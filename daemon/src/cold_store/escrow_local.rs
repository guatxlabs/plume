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
//! plan, la destination est la mémoire, il n'y a aucun état à part ; atomique ET durable par fichier (copie vers
//! un temporaire caché, taille vérifiée, temporaire synchronisé, renommage, répertoire synchronisé) ; JAMAIS de
//! suppression sous la destination d'une copie qu'un tour précédent a publiée (l'immutabilité
//! et la rétention de l'archive sont du ressort de la destination, pas de ce module) ; chaque échec et chaque
//! entrée illisible sont COMPTÉS et nommés, jamais avalés ; ce que le plan n'a pas pu établir (index non lu,
//! rétention illisible) ou a écarté (jours au-delà de la rétention) est recopié dans le rendu et dit.
//! DESTINATION OBJET (`s3://`, fonctionnalité `s3_backup`, `P7.20-m`) : les copies faites à ce tour sont rendues
//! (`copies_faites`) pour que le planificateur les DÉPOSE une par une ; une copie dont le dépôt n'est pas
//! confirmé est retirée de la zone de préparation, si bien que « présente ici » veut dire « déposée là-bas »
//! et que le tour suivant la rejoue.
use super::*;
use super::backup::EtatDuPlan;
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
    /// Ce que le plan n'a pas pu établir ou a écarté (`backup::EtatDuPlan`), recopié tel quel.
    pub(crate) plan: EtatDuPlan,
    /// Les copies FAITES à ce tour, (clé, copie locale) : ce qu'un dépôt objet a encore à déposer (`P7.20-m`).
    pub(crate) copies_faites: Vec<(String, std::path::PathBuf)>,
}

impl EscrowFroidRendu {
    /// Un cycle sans jour froid neuf et sans incident n'a rien à dire au journal. Un aveu du plan est un incident.
    pub(crate) fn a_quelque_chose_a_dire(&self) -> bool {
        self.a_copier > 0 || !self.echecs.is_empty() || self.entrees_illisibles > 0 || self.plan != EtatDuPlan::default()
    }

    /// Code de sortie de la sous-commande `cold-escrow` : 1 si au moins une copie a échoué OU si l'index n'a pas
    /// été lu (rien n'a pu être planifié : ce n'est pas « rien à copier »), 0 sinon.
    pub(crate) fn code_de_sortie(&self) -> i32 {
        if !self.echecs.is_empty() || self.plan.index_non_lu.is_some() { 1 } else { 0 }
    }

    pub(crate) fn phrase(&self) -> String {
        let mut s = format!(
            "{} jour(s) froid(s) déjà à l'abri, {} à copier, {} copié(s) ({} octets)",
            self.deja_a_l_abri, self.a_copier, self.copies, self.octets_copies
        );
        if self.entrees_illisibles > 0 {
            s.push_str(&format!(", {} entrée(s) de la destination illisible(s) — ignorée(s), et dite(s)", self.entrees_illisibles));
        }
        for aveu in self.plan.aveux() {
            s.push_str(", ");
            s.push_str(&aveu);
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

/// Joue le plan d'escrow contre la destination : relevé de ce qui y est déjà, plan incrémental borné par la
/// rétention à l'instant `n` (`cold_backup_plan`), copie verbatim atomique et durable de chaque jour-file à copier.
/// Ne supprime jamais une copie publiée. Rend le compte, jamais un simple booléen.
pub(crate) fn mettre_a_l_abri_les_jours_froids(
    conn: &Connection,
    conf: &HashMap<String, String>,
    n: i64,
    cold_dir: &Path,
    tenant_prefix: &str,
    destination: &Path,
) -> EscrowFroidRendu {
    mettre_a_l_abri_avec(conn, conf, n, cold_dir, tenant_prefix, destination, &mut GestesDuDisque)
}

/// Le corps de `mettre_a_l_abri_les_jours_froids`, avec les gestes de durabilité injectés (le disque en
/// production ; un témoin qui les relève dans les tests).
pub(super) fn mettre_a_l_abri_avec(
    conn: &Connection,
    conf: &HashMap<String, String>,
    n: i64,
    cold_dir: &Path,
    tenant_prefix: &str,
    destination: &Path,
    gestes: &mut dyn GestesDeCopie,
) -> EscrowFroidRendu {
    let (deja, entrees_illisibles) = cles_deja_a_l_abri(destination);
    let plan = cold_backup_plan(conn, conf, n, cold_dir, tenant_prefix, &deja);
    let mut rendu = EscrowFroidRendu {
        deja_a_l_abri: deja.len(),
        a_copier: plan.items.len(),
        entrees_illisibles,
        plan: plan.etat,
        ..Default::default()
    };
    for item in &plan.items {
        match copier_verbatim(&item.local, &destination.join(&item.key), gestes) {
            Ok((n, durabilite_non_etablie)) => {
                rendu.copies += 1;
                rendu.octets_copies += n;
                rendu.copies_faites.push((item.key.clone(), destination.join(&item.key)));
                rendu.echecs.extend(durabilite_non_etablie.map(|cause| format!("{} : {cause}", item.key)));
            }
            Err(cause) => rendu.echecs.push(format!("{} : {cause}", item.key)),
        }
    }
    rendu
}

/// LES TROIS GESTES DE DURABILITÉ d'une copie, injectables : sans eux, une copie publiée par `rename` peut ne pas
/// survivre à une coupure (contenu encore en cache, entrée de répertoire non écrite), et `cles_deja_a_l_abri`, qui
/// tient tout fichier final pour « déjà à l'abri », ne la rejouerait jamais.
pub(super) trait GestesDeCopie {
    /// Le contenu du temporaire, écrit sur le disque.
    fn synchroniser_le_temporaire(&mut self, tmp: &Path) -> std::io::Result<()>;
    /// La publication sous le nom final.
    fn renommer(&mut self, de: &Path, vers: &Path) -> std::io::Result<()>;
    /// L'entrée de répertoire du nom final, écrite sur le disque.
    fn synchroniser_le_repertoire(&mut self, dir: &Path) -> std::io::Result<()>;
}

/// Les gestes de production, sur le disque.
pub(super) struct GestesDuDisque;

impl GestesDeCopie for GestesDuDisque {
    fn synchroniser_le_temporaire(&mut self, tmp: &Path) -> std::io::Result<()> {
        std::fs::OpenOptions::new().write(true).open(tmp)?.sync_all()
    }
    fn renommer(&mut self, de: &Path, vers: &Path) -> std::io::Result<()> {
        std::fs::rename(de, vers)
    }
    fn synchroniser_le_repertoire(&mut self, dir: &Path) -> std::io::Result<()> {
        std::fs::File::open(dir)?.sync_all()
    }
}

/// Copie atomique ET durable : temporaire CACHÉ dans le répertoire cible, taille vérifiée contre la source,
/// temporaire SYNCHRONISÉ, renommage, répertoire SYNCHRONISÉ — dans cet ordre (le renommage d'un temporaire non
/// synchronisé publierait un nom final dont le contenu peut se perdre à la coupure). Un temporaire laissé par une
/// copie interrompue n'est jamais une clé (`cles_deja_a_l_abri`) : la copie est rejouée au cycle suivant et le
/// renommage l'écrase. Un échec de synchronisation du temporaire est un échec de copie : le temporaire est retiré,
/// rien n'est publié, le cycle suivant rejoue. Un échec de synchronisation du RÉPERTOIRE, lui, survient APRÈS la
/// publication : le fichier est sous son nom final et n'est JAMAIS retiré (en-tête du module) — « absent au
/// relevé » ne veut pas dire « absent de la destination » : un répertoire qu'on ne peut pas lire (droits `-wx`)
/// cache au relevé une copie publiée à un tour précédent, que le renommage vient de remplacer, et la retirer
/// détruirait la seule copie. La copie est donc rendue FAITE (un dépôt objet doit encore la déposer) avec sa cause
/// (`Ok((octets, Some(cause)))`) : l'appelant la compte en échec, sortie 1, parce que sa durabilité n'est pas
/// établie — et le cycle suivant, qui la verra, la tiendra pour à l'abri (dit dans la cause).
fn copier_verbatim(source: &Path, cible: &Path, gestes: &mut dyn GestesDeCopie) -> Result<(u64, Option<String>), String> {
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
    gestes.synchroniser_le_temporaire(&tmp).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("synchronisation du temporaire : {e} — temporaire retiré, copie rejouée au cycle suivant")
    })?;
    gestes.renommer(&tmp, cible).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("renommage vers {} : {e}", cible.display())
    })?;
    let durabilite_non_etablie = gestes.synchroniser_le_repertoire(parent).err().map(|e| {
        format!(
            "synchronisation du répertoire : {e} — copie publiée laissée en place (jamais retirée), sa durabilité n'est pas établie ; le cycle suivant la tiendra pour à l'abri"
        )
    });
    Ok((copie, durabilite_non_etablie))
}
