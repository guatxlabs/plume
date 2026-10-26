//! cold_store::backup — TIER FROID 2-TIER BACKUP (#18) : PLANIFICATEUR d'escrow INCRÉMENTAL des jours-files SCELLÉS.
//!
//! MODÈLE : un jour-file cold est DÉJÀ zstd + chiffré age (AEAD) + IMMUABLE dès qu'il porte un seal. Le backup cold
//! n'est donc PAS un re-dump : c'est une COPIE VERBATIM INCRÉMENTALE (option a — escrow symétrique) des fichiers
//! NOUVELLEMENT scellés qui ne sont pas encore chez le remote. Le daemon ne PRODUIT QU'UN PLAN (sans état, SANS
//! credential S3) : il émet des paires `(chemin local, clé objet)` ; c'est le SIDECAR qui exécute le `mc cp` réel
//! (octets copiés TELS QUELS -> les fichiers restent chiffrés age-SYMÉTRIQUE ; aucun re-wrap, aucun déchiffrement).
//!
//! DR / RESTAURATION : le tier froid restauré depuis l'escrow EXIGE la CLÉ DU TENANT du domaine Vault (la même clé
//! SQLCipher dont dérive l'AEAD cold via HKDF) — l'escrow ASYMÉTRIQUE (`PLUME_BACKUP_AGE_RECIPIENT`, clé publique
//! hors-cluster) NE couvre QUE la fenêtre HOT récente (le backup `age(zstd(sqlite))`). C'est COHÉRENT avec le hot :
//! le tier froid partage la posture at-rest du hot (« ne pas faire confiance au disque »), pas une couche d'escrow
//! distincte. Le plan cold est donc EXEMPT de `PLUME_BACKUP_REQUIRE_ASYMMETRIC` (cold est symétrique PAR CONCEPTION,
//! pas un repli dégradé — cf. la sous-commande dans main.rs).
//!
//! LE DAEMON NE SUPPRIME JAMAIS d'objet cold distant : l'immutabilité de l'archive est du ressort du LIFECYCLE MinIO
//! (ILM), hors périmètre daemon. Le plan n'émet QUE des fichiers À COPIER, jamais des suppressions.

use super::*;
use std::path::{Path, PathBuf};

/// Un item du plan de backup cold : le CHEMIN LOCAL du jour-file scellé + la CLÉ OBJET stable où le sidecar le copie
/// VERBATIM. `pub` (dans un type `pub(crate)`) -> lisible par la sous-commande `cold-backup-plan` (main.rs).
pub(crate) struct ColdBackupItem {
    pub local: PathBuf,
    pub key: String,
}

/// CE QUE LE PLAN N'A PAS PU ÉTABLIR, OU A ÉCARTÉ, COMPTÉ. Un plan vide n'est « rien à copier » que si cet état
/// est vide : sinon il dit pourquoi. Partagé par la sous-commande `cold-backup-plan` (main.rs) et l'escrow local
/// (`escrow_local.rs`), qui le recopie dans son rendu.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct EtatDuPlan {
    /// Index `cold_seal` présent mais NON LU (nature : le code SQLite, jamais le message) : aucun jour n'a pu être
    /// planifié, ce qui n'est PAS « rien à copier ».
    pub(crate) index_non_lu: Option<String>,
    /// Réglage de rétention illisible : le plan est COMPLET, non borné — aucune borne n'est fabriquée sur une
    /// valeur que l'admin n'a pas écrite, et une sauvegarde manquante est la panne qu'on veut le moins.
    pub(crate) retention_non_lue: bool,
    /// Fichiers scellés d'un jour EXPIRÉ (`Bande::dernier_jour_expire`) dont la ligne `cold_seal` est restée :
    /// écartés du plan, jamais copiés.
    pub(crate) expires_ecartes: usize,
    /// Lignes `cold_seal` présentes dont une colonne ne se décode pas : leur fichier n'est pas planifié.
    pub(crate) lignes_illisibles: usize,
}

impl EtatDuPlan {
    /// Chaque fait du plan qui n'est pas « tout lu, rien écarté », une phrase par fait, dans un ordre fixe.
    pub(crate) fn aveux(&self) -> Vec<String> {
        let mut aveux = Vec::new();
        if let Some(nature) = &self.index_non_lu {
            aveux.push(format!(
                "index cold_seal NON LU ({nature}) : aucun jour froid planifié — ce n'est pas « rien à copier », retenté au cycle suivant"
            ));
        }
        if self.retention_non_lue {
            aveux.push(
                "réglage de rétention `retention_days` illisible : plan COMPLET, aucune borne fabriquée — des jours au-delà de la rétention peuvent y figurer"
                    .to_string(),
            );
        }
        if self.expires_ecartes > 0 {
            aveux.push(format!(
                "{} fichier(s) froid(s) au-delà de la rétention écarté(s) du plan (ligne cold_seal gardée, fichier non retiré)",
                self.expires_ecartes
            ));
        }
        if self.lignes_illisibles > 0 {
            aveux.push(format!("{} ligne(s) cold_seal illisible(s) : leur(s) fichier(s) non planifié(s)", self.lignes_illisibles));
        }
        aveux
    }
}

/// Le plan ET ce qu'il n'a pas pu établir.
#[derive(Default)]
pub(crate) struct PlanFroid {
    pub(crate) items: Vec<ColdBackupItem>,
    pub(crate) etat: EtatDuPlan,
}

impl PlanFroid {
    /// Code de sortie de la sous-commande `cold-backup-plan` : 1 quand l'index n'a pas été lu (un plan vide y
    /// serait pris pour « rien à copier » par qui lit la sortie standard), 0 sinon — rétention illisible
    /// comprise, le plan étant alors complet.
    pub(crate) fn code_de_sortie(&self) -> i32 {
        if self.etat.index_non_lu.is_some() { 1 } else { 0 }
    }
}

/// PLAN de backup cold INCRÉMENTAL (fonction PURE, testable) : pour CHAQUE fichier scellé de `cold_seal`, dérive la
/// clé objet stable `cold/<tenant_prefix>/<env_id>/<YYYY-MM-DD>-<NNNN>.parquet` (le segment `<YYYY-MM-DD>-<NNNN>`
/// EST le basename on-disk de `file_path` : `ymd_from_day(day)` + `seq` zéro-paddé sur 4) et le chemin local
/// `file_path(cold_dir, env, day, seq)`.
///  - SKIP si `remote_keys` contient déjà la clé (déjà escrowé -> COPIE INCRÉMENTALE, jamais de re-upload) ;
///  - SKIP si le fichier local est ABSENT (garde une course « seal encore présent mais fichier VENANT d'expirer »
///    entre `expire_cold_days` et ce plan -> jamais d'émission fantôme d'un chemin inexistant) ;
///  - env_id non valide (anti-traversée, parité `expire_cold_days`) -> ignoré (un tel seal ne peut cartographier
///    aucun fichier légitime) ;
///  - JOUR EXPIRÉ -> écarté et COMPTÉ. L'expiration garde la ligne `cold_seal` d'un fichier qu'elle n'a pas pu
///    retirer ; sans borne ici, ce jour était planifié puis copié vers la destination de sauvegarde au-delà de sa
///    rétention. La borne est celle du vieillissement et du lecteur froid : rétention lue par
///    `retention_effective_lue`, `Bande::calculer` (politiques par index, rétention froide étendue),
///    `Bande::dernier_jour_expire` à l'instant `n` (l'appelant passe l'heure courante, comme la passe).
/// Rétention illisible : plan COMPLET et c'est dit (`EtatDuPlan::retention_non_lue`), jamais une borne fabriquée.
/// Index non lu : plan vide et c'est dit (`index_non_lu`) — sauf table `cold_seal` ABSENTE (tier froid jamais
/// allumé sur cette base : « rien à copier » y est un fait, établi par le schéma).
/// Ordre DÉTERMINISTE `(env_id, day, seq)` (l'ordre SQL n'est pas garanti -> tri explicite). N'émet QUE des
/// fichiers À COPIER, JAMAIS de suppression (immutabilité = ILM MinIO, hors daemon). AUCUN accès S3/mc/disque
/// distant ni credential : le sidecar exécute le `mc cp` verbatim. Idempotent (invariant GFS) : rejouer le plan
/// avec les clés qu'il vient d'émettre AJOUTÉES à `remote_keys` -> plan VIDE.
pub(crate) fn cold_backup_plan(
    conn: &Connection,
    conf: &HashMap<String, String>,
    n: i64,
    cold_dir: &Path,
    tenant_prefix: &str,
    remote_keys: &std::collections::HashSet<String>,
) -> PlanFroid {
    let mut etat = EtatDuPlan::default();
    let lus = match all_sealed_files(conn) {
        Ok(lus) => lus,
        Err(nature) => {
            if table_cold_seal_absente(conn) {
                return PlanFroid::default(); // tier froid jamais allumé : aucun fichier scellé, c'est un fait.
            }
            etat.index_non_lu = Some(nature);
            return PlanFroid { items: Vec::new(), etat };
        }
    };
    etat.lignes_illisibles = lus.illisibles;
    let mut seals = lus.seals;
    let bande = match retention_effective_lue(conn, conf, "retention_days") {
        Ok(rd) => Some(Bande::calculer(conn, conf, n, rd)),
        Err(_) => {
            etat.retention_non_lue = true;
            None
        }
    };
    let expire = |env_id: &str, day: i64| bande.as_ref().is_some_and(|b| day <= b.dernier_jour_expire(env_id, n));
    // Ordre DÉTERMINISTE (env_id, day, seq) — l'ordre de retour SQL n'est pas spécifié.
    seals.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    let mut out = Vec::new();
    for (env_id, day, seq) in seals {
        if !env_id_ok(&env_id) {
            continue; // anti-traversée (parité expire_cold_days) : ne cartographie aucun fichier légitime.
        }
        if expire(&env_id, day) {
            etat.expires_ecartes += 1;
            continue; // au-delà de la rétention de son index : ni planifié ni copié.
        }
        // Le segment day-seq de la clé == basename on-disk EXACT (`file_path` : `<ymd>-<NNNN>.parquet`, seq %04).
        let key = format!("cold/{tenant_prefix}/{env_id}/{}-{:04}.parquet", ymd_from_day(day), seq);
        if remote_keys.contains(&key) {
            continue; // déjà escrowé -> copie INCRÉMENTALE (skip).
        }
        let local = file_path(cold_dir, &env_id, day, seq);
        if !local.exists() {
            continue; // course « fichier venant d'expirer » -> pas d'émission fantôme.
        }
        out.push(ColdBackupItem { local, key });
    }
    PlanFroid { items: out, etat }
}

/// Ce que l'index `cold_seal` dit de l'histoire froide SOUS une frontière chaud/froid, bornée par la rétention.
/// Consommé par la couverture déclarée de la barre de recherche (`handlers/search.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HistoireFroideSousLaFrontiere {
    /// Aucun jour froid à déclarer : table `cold_seal` absente (tier froid jamais allumé), aucune ligne sous la
    /// frontière, ou seulement des lignes de jours EXPIRÉS (gardées par un retrait de fichier refusé).
    Aucune,
    /// Au moins un jour sous la frontière ET dans la rétention de son index.
    Presente,
    /// Des jours sous la frontière, réglage de rétention illisible : NON bornés (aucune borne fabriquée), et
    /// l'appelant le dit.
    PresenteRetentionNonLue,
    /// Index présent mais NON LU (nature : le code SQLite, jamais le message).
    IndexNonLu(String),
    /// Aucun jour retenu parmi les lignes lues, mais des lignes dont une colonne ne se décode pas : leur jour
    /// n'est pas établi, « aucune histoire » ne l'est donc pas non plus.
    LignesIllisibles(usize),
}

/// L'HISTOIRE FROIDE SOUS LA FRONTIÈRE `boundary` (ts), BORNÉE COMME LE VIEILLISSEMENT. Même lecture que le plan
/// d'escrow (`all_sealed_files`), même borne : rétention lue par `retention_effective_lue`, `Bande::calculer`
/// (politiques par index, rétention froide étendue), un jour n'est retenu que s'il est STRICTEMENT après
/// `Bande::dernier_jour_expire` de son index à l'instant `n` (l'appelant passe l'instant de sa frontière). Un jour
/// expiré dont la ligne `cold_seal` est restée n'est donc pas « de l'histoire plus ancienne » : le lecteur froid ne
/// le sert pas et l'expiration le retirera.
/// Rétention illisible : les jours sous la frontière comptent tous (côté prudent), et c'est rendu
/// (`PresenteRetentionNonLue`). Index non lu : `IndexNonLu`, sauf table ABSENTE (`Aucune`, établi par le schéma).
/// Aucune écriture, aucun énoncé neuf : la lecture est celle de `all_sealed_files`.
pub(crate) fn histoire_froide_sous_la_frontiere(
    conn: &Connection,
    conf: &HashMap<String, String>,
    n: i64,
    boundary: i64,
) -> HistoireFroideSousLaFrontiere {
    let lus = match all_sealed_files(conn) {
        Ok(lus) => lus,
        Err(nature) => {
            if table_cold_seal_absente(conn) {
                return HistoireFroideSousLaFrontiere::Aucune; // tier froid jamais allumé : aucun jour scellé.
            }
            return HistoireFroideSousLaFrontiere::IndexNonLu(nature);
        }
    };
    let jour_frontiere = boundary.div_euclid(SECS_PER_DAY);
    let sous: Vec<(String, i64)> = lus.seals.into_iter().filter(|(_, day, _)| *day < jour_frontiere).map(|(env, day, _)| (env, day)).collect();
    if !sous.is_empty() {
        match retention_effective_lue(conn, conf, "retention_days") {
            Ok(rd) => {
                let bande = Bande::calculer(conn, conf, n, rd);
                if sous.iter().any(|(env, day)| *day > bande.dernier_jour_expire(env, n)) {
                    return HistoireFroideSousLaFrontiere::Presente;
                }
            }
            Err(_) => return HistoireFroideSousLaFrontiere::PresenteRetentionNonLue,
        }
    }
    if lus.illisibles > 0 {
        return HistoireFroideSousLaFrontiere::LignesIllisibles(lus.illisibles);
    }
    HistoireFroideSousLaFrontiere::Aucune
}

/// LA TABLE `cold_seal` EST-ELLE ABSENTE ? Lu sur le SCHÉMA (`PRAGMA table_info`, aucune donnée du tenant), et
/// seulement après une lecture ratée de l'index : absente, le tier froid n'a jamais tourné sur cette base et
/// « rien à copier » est vrai ; présente, ou schéma lui-même illisible, la lecture ratée reste un aveu.
fn table_cold_seal_absente(conn: &Connection) -> bool {
    let mut colonnes = 0usize;
    let lu = conn.pragma(None, "table_info", "cold_seal", |_| {
        colonnes += 1;
        Ok(())
    });
    lu.is_ok() && colonnes == 0
}
