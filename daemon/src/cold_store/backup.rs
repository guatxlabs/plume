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

/// PLAN de backup cold INCRÉMENTAL (fonction PURE, testable) : pour CHAQUE fichier scellé de `cold_seal`, dérive la
/// clé objet stable `cold/<tenant_prefix>/<env_id>/<YYYY-MM-DD>-<NNNN>.parquet` (le segment `<YYYY-MM-DD>-<NNNN>`
/// EST le basename on-disk de `file_path` : `ymd_from_day(day)` + `seq` zéro-paddé sur 4) et le chemin local
/// `file_path(cold_dir, env, day, seq)`.
///  - SKIP si `remote_keys` contient déjà la clé (déjà escrowé -> COPIE INCRÉMENTALE, jamais de re-upload) ;
///  - SKIP si le fichier local est ABSENT (garde une course « seal encore présent mais fichier VENANT d'expirer »
///    entre `expire_cold_days` et ce plan -> jamais d'émission fantôme d'un chemin inexistant) ;
///  - env_id non valide (anti-traversée, parité `expire_cold_days`) -> ignoré (un tel seal ne peut cartographier
///    aucun fichier légitime).
/// Ordre DÉTERMINISTE `(env_id, day, seq)` (l'ordre SQL n'est pas garanti -> tri explicite). N'émet QUE des
/// fichiers À COPIER, JAMAIS de suppression (immutabilité = ILM MinIO, hors daemon). AUCUN accès S3/mc/disque
/// distant ni credential : le sidecar exécute le `mc cp` verbatim. Idempotent (invariant GFS) : rejouer le plan
/// avec les clés qu'il vient d'émettre AJOUTÉES à `remote_keys` -> plan VIDE.
pub(crate) fn cold_backup_plan(
    conn: &Connection,
    cold_dir: &Path,
    tenant_prefix: &str,
    remote_keys: &std::collections::HashSet<String>,
) -> Vec<ColdBackupItem> {
    let mut seals = all_sealed_files(conn);
    // Ordre DÉTERMINISTE (env_id, day, seq) — l'ordre de retour SQL n'est pas spécifié.
    seals.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    let mut out = Vec::new();
    for (env_id, day, seq) in seals {
        if !env_id_ok(&env_id) {
            continue; // anti-traversée (parité expire_cold_days) : ne cartographie aucun fichier légitime.
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
    out
}
