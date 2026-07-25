//! #40 (item 2) — FEDERATED SEARCH / SEARCH-WITHOUT-INGEST — DESIGN NOTE + minimal seam (STUB).
//!
//! ── PROBLÈME ─────────────────────────────────────────────────────────────────────────────────────
//! Le processeur d'ingest (item 1, `crate::processors`) réduit le volume CHAUD en décidant ce qu'on
//! n'INDEXE PAS. Le pendant est : pouvoir REGARDER les données FROIDES (archivées en object-storage,
//! MinIO/S3) SANS les ré-ingérer dans le store chaud (SQLCipher). C'est le pattern « search-without-
//! ingest » / federated search : une requête (fenêtre + prédicat) balaye les objets froids à la demande
//! (investigation, chasse rétrospective) et renvoie des lignes, sans coût de rétention permanent.
//!
//! ── OÙ ÇA S'INSÈRE ───────────────────────────────────────────────────────────────────────────────
//! Le store SPI (`crate::ingest::store`) possède DÉJÀ l'émission SOQL -> SQL (`soql_to_sql`) et la vue de
//! lecture typée `guatx_core::store::Rows` (miroir DTO de la forme `{columns, rows, stats}` de
//! `run_query_ex`). La federated search est une SECONDE SOURCE de `Rows`, PARALLÈLE au store chaud :
//!   - le CHAUD répond via `store().query_soql(...)` (SQLite, indexé) ;
//!   - le FROID répond via `ColdSearch::search(...)` (scan d'objets MinIO, borné par fenêtre/predicat).
//! Une requête « fédérée » = UNION des deux (chaud pour la fenêtre récente, froid pour l'historique
//! au-delà de la rétention chaude), fusionnée sur le MÊME schéma de colonnes -> l'UI ne voit qu'un
//! résultat. La COUTURE est le trait `ColdSearch` ci-dessous (une seule méthode). Le tier froid est
//! CONFIG-GATED (comme DuckDB/ClickHouse) : par défaut `NoColdTier` -> aucune dépendance, mode 0 inchangé.
//!
//! ── FORMAT FROID (décision d'archive) ───────────────────────────────────────────────────────────
//! Les events élagués par la rétention (ou routés par une règle ROUTE vers une classe « cold ») sont
//! écrits en object-storage sous un layout PARTITIONNÉ par temps + tenant + env :
//!     s3://<bucket>/plume/<tenant>/<env>/dt=YYYY-MM-DD/hh/events-*.ndjson.zst  (age-chiffré, cf. backup)
//! Le partitionnement par `dt/hh` permet le PARTITION PRUNING : une requête [from,to] ne LIT que les
//! préfixes couvrant la fenêtre (jamais un full-scan du bucket). Le prédicat SOQL est poussé au scan
//! (filtre ligne-à-ligne après décompression), le tri/agrégation restant à la charge de l'appelant.
//!
//! ── COÛT / BORNES ────────────────────────────────────────────────────────────────────────────────
//! Une federated query est INTRINSÈQUEMENT plus lente (I/O réseau + décompression) : elle est donc
//! (a) OPT-IN explicite (l'utilisateur demande « inclure l'archive »), (b) BORNÉE (budget octets scannés
//! + timeout, comme le watchdog `run_query_ex`), (c) JAMAIS sur le chemin d'ingest ou de détection chaude.
//!
//! ── ÉTAT ─────────────────────────────────────────────────────────────────────────────────────────
//! STUB : la couture (`trait ColdSearch` + `NoColdTier` + `cold_search()`) est posée et COMPILE ; aucune
//! route/handler ne l'appelle encore (l'impl MinIO réelle — client S3, pruning, scan — est un follow-up).
//! Objectif de ce fichier : figer le contrat pour que l'impl future se branche SANS toucher au data-plane.
#![allow(dead_code)]
use guatx_core::store::Rows;

/// Erreur d'une recherche fédérée (froid). `NotConfigured` = aucun tier froid monté (défaut mode 0).
#[derive(Debug)]
pub(crate) enum ColdSearchError {
    NotConfigured,
    Backend(String),
}

impl std::fmt::Display for ColdSearchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ColdSearchError::NotConfigured => write!(f, "tier froid non configuré (federated search désactivée)"),
            ColdSearchError::Backend(e) => write!(f, "erreur tier froid: {e}"),
        }
    }
}

/// COUTURE federated search : interroge les données FROIDES (object-storage) pour une fenêtre + un SOQL,
/// SANS ré-ingérer. Renvoie la MÊME vue typée (`Rows`) que le store chaud -> fusion transparente côté
/// appelant. `budget_bytes`/`timeout_ms` bornent le scan (jamais illimité). Backend-neutre (MinIO/S3/…).
pub(crate) trait ColdSearch {
    fn search(
        &self,
        tenant: &str,
        soql: &str,
        from: i64,
        to: i64,
        env: Option<&str>,
        budget_bytes: u64,
        timeout_ms: u64,
    ) -> Result<Rows, ColdSearchError>;
}

/// Impl PAR DÉFAUT : aucun tier froid. Toute recherche renvoie `NotConfigured` -> mode 0 strictement
/// inchangé (aucune dépendance object-storage tirée). Remplaçable par un `MinioColdSearch` (follow-up).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NoColdTier;

impl ColdSearch for NoColdTier {
    fn search(&self, _t: &str, _s: &str, _f: i64, _to: i64, _e: Option<&str>, _b: u64, _tm: u64) -> Result<Rows, ColdSearchError> {
        Err(ColdSearchError::NotConfigured)
    }
}

/// Accesseur du tier froid actif. Aujourd'hui toujours `NoColdTier` (federated search non montée) ->
/// contrepartie de `store()` pour le chemin FROID. Un futur `PLUME_COLD_STORE=minio` sélectionnerait ici.
pub(crate) fn cold_search() -> NoColdTier {
    NoColdTier
}
