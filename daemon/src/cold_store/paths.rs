//! cold_store::paths — dérivation de chemins on-disk : jour UTC <-> `YYYY-MM-DD`, layout `<env>/<day>-<NNNN>.parquet`,
//! et la RACINE COLD PAR-TENANT.
//!
//! LAYOUT FICHIER (#18 P2b) : `<racine cold>/<env_id>/<YYYY-MM-DD>-<NNNN>.parquet`. `seq` zéro-paddé sur 4
//! chiffres -> tri lexicographique == tri `seq`. `env_id` est VALIDÉ (env_id_ok) par l'appelant AVANT d'atteindre
//! ici -> aucun composant de chemin arbitraire (anti-traversée).
//!
//! RACINE COLD PAR-TENANT (FIX #2) : dérivée du `db_path` DU TENANT (jamais du `PLUME_COLD_DIR` global partagé)
//! -> tenants disjoints même à `env_id='prod'` commun. Mode 0 / tenant default = `<parent PLUME_DB>/cold` (ou
//! `PLUME_COLD_DIR`), inchangé.

use super::*;
use std::path::{Path, PathBuf};

/// `YYYY-MM-DD` (UTC) depuis un INDEX de jour (jours depuis l'epoch). Algorithme civil-from-days de Howard
/// Hinnant (pas de dépendance date/chrono) — exact pour toute la plage utile.
pub(super) fn ymd_from_day(day: i64) -> String {
    // z = jours depuis 1970-01-01 ; on décale l'ère pour que le 1er mars soit le début d'année.
    let z = day + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}")
}

/// Répertoire des fichiers cold d'un env_id sous la racine cold. `env_id` est VALIDÉ (env_id_ok) par l'appelant
/// AVANT d'atteindre ici -> aucun composant de chemin arbitraire (anti-traversée).
pub(super) fn day_dir(cold_dir: &Path, env_id: &str) -> PathBuf {
    cold_dir.join(env_id)
}

/// Chemin d'UN FICHIER cold `<env_id>/<YYYY-MM-DD>-<NNNN>.parquet` (#18 P2b : jour splitté en fichiers séquencés).
/// `seq` zéro-paddé sur 4 chiffres (0000..) -> tri lexicographique == tri `seq` (jusqu'à 9999 fichiers/jour, très
/// au-delà de tout jour réaliste : à `COLD_FILE_MAX_ROWS`~256K lignes/fichier c'est >2,5 G lignes/jour). `env_id`
/// est VALIDÉ par l'appelant (anti-traversée). Le `seq` est un entier interne (jamais d'entrée utilisateur).
pub(super) fn file_path(cold_dir: &Path, env_id: &str, day: i64, seq: i64) -> PathBuf {
    day_dir(cold_dir, env_id).join(format!("{}-{:04}.parquet", ymd_from_day(day), seq))
}

/// RACINE COLD PAR-TENANT (FIX #2) — DÉRIVÉE du `db_path` du tenant, JAMAIS du `PLUME_COLD_DIR` global (qui
/// est un config PROCESS partagé -> tous les tenants, `env_id='prod'` par défaut, écriraient le MÊME fichier).
///  - TENANT DEFAULT / MODE 0 (`db_path` vide OU == PLUME_DB) : comportement HISTORIQUE EXACT — `PLUME_COLD_DIR`
///    si posé, sinon `<parent de PLUME_DB>/cold`. (mode 0 byte-identique + fixtures de test inchangées.)
///  - AUTRE TENANT : `<db_path>.cold` — sibling du fichier base du tenant, CLÉ PAR LE CHEMIN COMPLET unique du
///    tenant. Deux tenants ont des `db_path` DISTINCTS (garantie control-plane : le db_path EST le stockage du
///    tenant) -> racines cold DISJOINTES par construction, quelle que soit la valeur d'`env_id`. On IGNORE
///    délibérément `PLUME_COLD_DIR` ici (jamais de racine partagée -> jamais de collision inter-tenant).
// `pub(crate)` : consommé par la sous-commande `cold-backup-plan` (main.rs) pour résoudre la racine cold à
// scanner — MÊME dérivation que l'aging (source unique, jamais de divergence de chemin entre écriture et backup).
pub(crate) fn cold_root(conf: &HashMap<String, String>, db_path: &str) -> PathBuf {
    let default_db = cfg(conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
    let is_default = db_path.trim().is_empty() || db_path == default_db;
    if is_default {
        let dir = cfg(conf, "PLUME_COLD_DIR", "");
        if !dir.trim().is_empty() {
            PathBuf::from(dir.trim())
        } else {
            Path::new(&default_db).parent().unwrap_or_else(|| Path::new(".")).join("cold")
        }
    } else {
        PathBuf::from(format!("{db_path}.cold"))
    }
}
