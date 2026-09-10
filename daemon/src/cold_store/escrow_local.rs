//! cold_store::escrow_local — `P7.20-f` : L'EXÉCUTANT DU PLAN D'ESCROW FROID, DANS LE DÉMON.
//!
//! Le plan (`backup.rs`, `cold_backup_plan`) existait avec sa sous-commande `cold-backup-plan`, et AUCUNE unité
//! ni composition de ce dépôt ne le jouait : la sauvegarde native ne prenait que la base, `plume-backup.timer`
//! aussi. Un exploitant qui allumait le tier froid déplaçait donc des jours vers des fichiers qu'aucun mode ne
//! mettait à l'abri — et dont rien ne revient vers le chaud. Ce module joue le plan LÀ OÙ la sauvegarde est
//! déjà écrite : la destination de sauvegarde (`PLUME_BACKUP_DEST` pour le planificateur natif, le répertoire
//! que `plume-backup.timer` passe à `cold-escrow` en mode hôte). Un jour-file scellé est copié VERBATIM (il
//! est déjà zstd + age, immuable) sous `<destination>/cold/<tenant>/<env>/<AAAA-MM-JJ>-<NNNN>.parquet` — la
//! clé objet du plan devient un chemin relatif à la destination, de sorte que ce qui expédie la destination
//! (volume monté, dépôt objet, rsync) expédie aussi les jours froids sans rien savoir d'eux.
//!
//! CE QUI EST TENU : incrémental — les clés déjà présentes sous `<destination>/cold` SONT le `remote_keys` du
//! plan, la destination est la mémoire, il n'y a aucun état à part ; atomique par fichier (copie vers un
//! temporaire caché, taille vérifiée, renommage) ; JAMAIS de suppression sous la destination (l'immutabilité
//! et la rétention de l'archive sont du ressort de la destination, pas de ce module) ; chaque échec et chaque
//! entrée illisible sont COMPTÉS et nommés, jamais avalés.
//! CE QUI N'EST PAS TENU, dit ici : la destination OBJET (`s3://`, fonctionnalité `s3_backup`) — les jours
//! froids sont mis à l'abri dans la zone de préparation locale et n'y sont PAS déposés (`P7.20-m`).
use super::*;
use std::collections::HashSet;
use std::path::Path;

/// Sous-répertoire de la destination de sauvegarde sous lequel les jours froids sont mis à l'abri : le premier
/// segment de la clé objet du plan (`cold/<tenant>/<env>/…`), donc la clé EST le chemin relatif.
pub(crate) const RACINE_DE_L_ESCROW: &str = "cold";

/// Ce qu'une mise à l'abri a fait, compté : ce qui était déjà là, ce qu'il y avait à copier, ce qui l'a été,
/// et ce qui a échoué ou n'a pas pu être lu — chaque échec avec sa clé et sa cause.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct EscrowFroidRendu {
    pub(crate) deja_a_l_abri: usize,
    pub(crate) a_copier: usize,
    pub(crate) copies: usize,
    pub(crate) octets_copies: u64,
    pub(crate) entrees_illisibles: usize,
    pub(crate) echecs: Vec<String>,
}

impl EscrowFroidRendu {
    /// Un cycle sans jour froid neuf et sans incident n'a rien à dire au journal.
    pub(crate) fn a_quelque_chose_a_dire(&self) -> bool {
        self.a_copier > 0 || !self.echecs.is_empty() || self.entrees_illisibles > 0
    }

    pub(crate) fn phrase(&self) -> String {
        let mut s = format!(
            "{} jour(s) froid(s) déjà à l'abri, {} à copier, {} copié(s) ({} octets)",
            self.deja_a_l_abri, self.a_copier, self.copies, self.octets_copies
        );
        if self.entrees_illisibles > 0 {
            s.push_str(&format!(", {} entrée(s) de la destination illisible(s) — ignorée(s), et dite(s)", self.entrees_illisibles));
        }
        if !self.echecs.is_empty() {
            s.push_str(&format!(", {} ÉCHEC(S) : {}", self.echecs.len(), self.echecs.join(" ; ")));
        }
        s
    }
}

/// Les clés DÉJÀ à l'abri sous `<destination>/cold` : chaque fichier régulier, en chemin relatif à la destination
/// avec `/`, et le COMPTE des entrées qu'on n'a pas pu lire. Les entrées cachées (`.…`) sont les temporaires
/// d'une copie interrompue : jamais une clé, la copie est rejouée. Une racine `cold` absente rend un relevé vide
/// et zéro illisible : c'est le premier cycle.
pub(crate) fn cles_deja_a_l_abri(destination: &Path) -> (HashSet<String>, usize) {
    let mut cles = HashSet::new();
    let mut illisibles = 0usize;
    let racine = destination.join(RACINE_DE_L_ESCROW);
    if !racine.exists() {
        return (cles, 0);
    }
    let mut pile = vec![racine];
    while let Some(dir) = pile.pop() {
        let entrees = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => { illisibles += 1; continue; }
        };
        for entree in entrees {
            let e = match entree {
                Ok(e) => e,
                Err(_) => { illisibles += 1; continue; }
            };
            if e.file_name().to_string_lossy().starts_with('.') {
                continue; // temporaire d'une copie interrompue : pas une clé
            }
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => pile.push(p),
                Ok(t) if t.is_file() => match p.strip_prefix(destination) {
                    Ok(rel) => {
                        let segments: Vec<String> = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
                        cles.insert(segments.join("/"));
                    }
                    Err(_) => illisibles += 1,
                },
                Ok(_) => {}
                Err(_) => illisibles += 1,
            }
        }
    }
    (cles, illisibles)
}

/// Joue le plan d'escrow contre la destination : relevé de ce qui y est déjà, plan incrémental, copie verbatim
/// atomique de chaque jour-file à copier. Ne supprime jamais rien. Rend le compte, jamais un simple booléen.
pub(crate) fn mettre_a_l_abri_les_jours_froids(
    conn: &Connection,
    cold_dir: &Path,
    tenant_prefix: &str,
    destination: &Path,
) -> EscrowFroidRendu {
    let (deja, entrees_illisibles) = cles_deja_a_l_abri(destination);
    let plan = cold_backup_plan(conn, cold_dir, tenant_prefix, &deja);
    let mut rendu = EscrowFroidRendu {
        deja_a_l_abri: deja.len(),
        a_copier: plan.len(),
        entrees_illisibles,
        ..Default::default()
    };
    for item in &plan {
        match copier_verbatim(&item.local, &destination.join(&item.key)) {
            Ok(n) => {
                rendu.copies += 1;
                rendu.octets_copies += n;
            }
            Err(cause) => rendu.echecs.push(format!("{} : {cause}", item.key)),
        }
    }
    rendu
}

/// Copie atomique : temporaire CACHÉ dans le répertoire cible, taille vérifiée contre la source, renommage.
/// Un temporaire laissé par une copie interrompue n'est jamais une clé (`cles_deja_a_l_abri`) : la copie est
/// rejouée au cycle suivant et le renommage l'écrase.
fn copier_verbatim(source: &Path, cible: &Path) -> Result<u64, String> {
    let parent = cible.parent().ok_or_else(|| "cible sans répertoire".to_string())?;
    std::fs::create_dir_all(parent).map_err(|e| format!("création de {} : {e}", parent.display()))?;
    let nom = cible.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = parent.join(format!(".{nom}.tmp.{}", std::process::id()));
    let attendu = std::fs::metadata(source).map_err(|e| format!("source {} : {e}", source.display()))?.len();
    let copie = std::fs::copy(source, &tmp).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("copie vers {} : {e}", tmp.display())
    })?;
    if copie != attendu {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("taille copiée {copie} ≠ source {attendu}"));
    }
    std::fs::rename(&tmp, cible).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("renommage vers {} : {e}", cible.display())
    })?;
    Ok(copie)
}
