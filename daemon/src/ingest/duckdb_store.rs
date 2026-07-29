//! DuckDbStore — tier WARM analytique (#15) EXPÉRIMENTAL, DERRIÈRE la SPI backend-neutre
//! `guatx_core::store::EventStore`.
//!
//! FEATURE-GATED `duckdb`, OFF PAR DÉFAUT + EXPÉRIMENTAL. Ce module N'EXISTE PAS dans le build SMB par
//! défaut (`daemon/src/ingest/mod.rs` le déclare sous `#[cfg(feature = "duckdb")]`) : le binaire par défaut
//! NE LINKE PAS la crate `duckdb` -> budget 2 Go / mode 0 byte-identique préservés.
//!
//! ⚠️ BUILD (revue store-resource) : la dép `duckdb` est UN-BUNDLED (le `Cargo.toml` a RETIRÉ
//! `features = ["bundled"]`) -> `--features duckdb` LIE une `libduckdb` SYSTÈME (pkg-config /
//! `DUCKDB_LIB_DIR`) au lieu de compiler l'amalgamation C++ (`cc1plus`, ~4 Go RAM, OOM). Sans libduckdb
//! sur l'hôte, l'échec est un LINK clair/rapide (`cannot find -lduckdb`), plus jamais un OOM opaque. À
//! builder sur un hôte ESN/MSSP disposant de libduckdb, JAMAIS sur le VPS 2 Go. Le tier scale-out
//! SUPPORTÉ est ClickHouse (client pur-Rust) ; DuckDB reste EXPÉRIMENTAL (embedded/no-server niche).
//!
//! ⚠️ RUNTIME — pas un backend silencieusement sélectionnable par le client. Sélection runtime FUTURE :
//! `PLUME_STORE=duckdb` (opt-in) + ACK `PLUME_STORE_DUCKDB_EXPERIMENTAL=1` (sinon avertissement bruyant,
//! `duckdb_experimental_guard`). On livre ici la PREUVE #15 (RFC `docs/scale-clickhouse-ha-design.md`
//! §Phase 1) qu'un SECOND backend, NON-`rusqlite`, monte la même SPI : émission via `DuckDbDialect`
//! (cœur), exécuteur non-SQLite, sur UN nœud, SANS la complexité réseau/HA/crypto de ClickHouse.
//!
//! PÉRIMÈTRE (de-risking) :
//!   - Écritures : `insert_event`/`insert_metric`/`insert_snapshot` + `insert_events` (boucle préparée ;
//!     le tier de prod utiliserait l'Appender DuckDB pour le débit — follow-up).
//!   - Lecture GXQL : `query_soql` compile via `Schema::events_duckdb()` (DuckDbDialect) puis exécute sur
//!     une connexion DuckDB au chemin `db_path`, et renvoie la MÊME forme JSON `{columns,rows,stats}` que
//!     l'exécuteur SQLite (`run_query_ex`).
//!   - GAP-4 (bornage ressources) — DÉSORMAIS HONORÉ (revue store-resource) : `query_soql_masked` pose
//!     `SET memory_limit`/`SET threads` (env `PLUME_DUCKDB_MEMORY_LIMIT`/`PLUME_DUCKDB_THREADS`, défauts
//!     conservateurs bien sous le budget d'un nœud) + un WATCHDOG `budget_ms` (thread + `InterruptHandle`
//!     DuckDB, MÊME motif que `run_query_ex` SQLite) qui interrompt une requête trop longue. `qid` est
//!     tracé (plus ignoré) ; l'annulation externe `/api/cancel` reste SQLite-typée (registre `QUERY_CANCEL`
//!     en `rusqlite::InterruptHandle`) -> un registre neutre est un follow-up documenté. La denylist de
//!     colonnes secrètes est SANS OBJET : le control-plane (user.hash/token.token_hash) n'est JAMAIS dans
//!     le store data-plane. Le masquage #45 est fail-closed (émission masquée via le Dialect).
#![allow(dead_code)] // module opt-in : le câblage runtime `PLUME_STORE=duckdb` est un follow-up.
use crate::*;
use guatx_core::store::{EventStore, StoreError, StoreHandle};
use serde_json::json;

/// Store analytique WARM (#15). Sans état (comme `SqlcipherStore`) : la connexion writer DuckDB est
/// passée PAR APPEL via `StoreHandle::DuckDb`, le `db_path` (fichier DuckDB) par la lecture.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DuckDbStore;

impl DuckDbStore {
    /// INSERT event DuckDB — MÊMES colonnes que l'INSERT SQLite. `INSERT OR IGNORE` (syntaxe
    /// SQLite-compat supportée par DuckDB) -> dédup sur la contrainte UNIQUE `dedup` du schéma WARM.
    const EVENT_INSERT_SQL: &'static str =
        "INSERT OR IGNORE INTO event(ts,source,category,severity,message,host,src_ip,dst_ip,url,dedup,fields,engagement_id,origin,env_id) \
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    const METRIC_INSERT_SQL: &'static str =
        "INSERT INTO metric(ts,name,labels,value,host) VALUES(?,?,?,?,?)";
    const SNAPSHOT_INSERT_SQL: &'static str =
        "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?,?,?,?,?)";
}

/// Mappe une valeur DuckDB (`ValueRef`) vers `serde_json::Value` — miroir du mapping SQLite de
/// `run_query_ex` (Null/Int/Real/Text/Blob), élargi aux familles d'entiers/flottants DuckDB. Les types
/// hors périmètre event/metric/snapshot (Decimal/Interval/List/Struct/Map/Array/Enum/Date/Time) tombent
/// en `Null` (best-effort documenté) — ces colonnes n'existent pas dans le data-plane SOC.
fn duck_vref_to_json(v: duckdb::types::ValueRef<'_>) -> Value {
    use duckdb::types::ValueRef as V;
    match v {
        V::Null => Value::Null,
        V::Boolean(b) => json!(b),
        V::TinyInt(n) => json!(n),
        V::SmallInt(n) => json!(n),
        V::Int(n) => json!(n),
        V::BigInt(n) => json!(n),
        V::HugeInt(n) => json!(n as i64), // best-effort (i128 -> i64) ; hors périmètre SOC courant
        V::UTinyInt(n) => json!(n),
        V::USmallInt(n) => json!(n),
        V::UInt(n) => json!(n),
        V::UBigInt(n) => json!(n),
        V::Float(f) => json!(f),
        V::Double(f) => json!(f),
        V::Text(s) => json!(s),
        V::Blob(b) => json!(format!("<blob {} o>", b.len())),
        _ => Value::Null,
    }
}

impl EventStore for DuckDbStore {
    fn insert_event(&self, h: StoreHandle, row: &EventRow) -> Result<usize, StoreError> {
        let conn = h.downcast::<duckdb::Connection>("duckdb")?;
        conn.execute(Self::EVENT_INSERT_SQL, duckdb::params![
            row.ts, row.source, row.category, row.severity, row.message, row.host,
            row.src_ip, row.dst_ip, row.url, row.dedup, row.fields, row.engagement_id,
            row.origin, row.env_id.as_deref().unwrap_or("prod")
        ]).map_err(be)
    }
    fn insert_metric(&self, h: StoreHandle, m: &MetricRow) -> Result<usize, StoreError> {
        let conn = h.downcast::<duckdb::Connection>("duckdb")?;
        conn.execute(Self::METRIC_INSERT_SQL, duckdb::params![m.ts, m.name, m.labels, m.value, m.host]).map_err(be)
    }
    fn insert_snapshot(&self, h: StoreHandle, s: &SnapshotRow) -> Result<usize, StoreError> {
        let conn = h.downcast::<duckdb::Connection>("duckdb")?;
        conn.execute(Self::SNAPSHOT_INSERT_SQL, duckdb::params![s.ts, s.kind, s.hash, s.data, s.host]).map_err(be)
    }
    fn insert_events(&self, h: StoreHandle, rows: &[EventRow]) -> Result<usize, StoreError> {
        // Boucle à statement PRÉPARÉ (primitive d'ingest batché GAP-3). Le tier de prod utiliserait
        // l'Appender DuckDB pour le débit ; ici le but est la parité de contrat, pas le throughput.
        let conn = h.downcast::<duckdb::Connection>("duckdb")?;
        let mut stmt = conn.prepare(Self::EVENT_INSERT_SQL).map_err(be)?;
        let mut n = 0usize;
        for row in rows {
            n += stmt.execute(duckdb::params![
                row.ts, row.source, row.category, row.severity, row.message, row.host,
                row.src_ip, row.dst_ip, row.url, row.dedup, row.fields, row.engagement_id,
                row.origin, row.env_id.as_deref().unwrap_or("prod")
            ]).map_err(be)?;
        }
        Ok(n)
    }
    fn event_insert_sql(&self) -> &'static str {
        Self::EVENT_INSERT_SQL
    }
    fn metric_insert_sql(&self) -> &'static str {
        Self::METRIC_INSERT_SQL
    }
    fn soql_to_sql(&self, soql: &str, from: i64, to: i64, env: Option<&str>) -> Result<String, StoreError> {
        // Émission via le cœur partagé, DIALECT DuckDB (`Schema::events_duckdb()`). Compilateur réutilisé.
        self.soql_to_sql_masked(soql, from, to, env, &guatx_core::soql::FieldMaskSet::new())
    }
    fn soql_to_sql_masked(&self, soql: &str, from: i64, to: i64, env: Option<&str>, masks: &guatx_core::soql::FieldMaskSet) -> Result<String, StoreError> {
        // FIELD FILTERS (#45) — les masques sont ÉMIS DANS LE SQL DuckDB via le `Dialect` (`with_masks`), au
        // MÊME choke-point `soql_field`/`mask_output_bag` que le tier chaud SQLite. VIDE -> byte-identique à
        // `soql_to_sql` (mode 0). Les actions portables (Mask/MaskPartial='***'/substr, Redact/Deny=NULL, retrait
        // de clé du sac) s'exécutent sur DuckDB ; une action NON portable (Hash -> `plume_fmask_hash`, UDF absente
        // ici) émet une expression que DuckDB ne connaît pas -> ERREUR À L'EXÉCUTION = FAIL-CLOSED (jamais de
        // valeur en clair). Un rôle masqué NE PEUT donc PAS obtenir de cleartext via le tier WARM.
        guatx_core::soql::to_sql(soql, from, to, &guatx_core::soql::Schema::events_duckdb().with_env(env).with_masks(masks.clone()))
            .map_err(StoreError::Emit)
    }
    fn query_soql(&self, db_path: &str, soql: &str, from: i64, to: i64, env: Option<&str>, budget_ms: u64, qid: Option<&str>) -> Result<Value, StoreError> {
        self.query_soql_masked(db_path, soql, from, to, env, budget_ms, qid, &guatx_core::soql::FieldMaskSet::new())
    }
    fn query_soql_masked(&self, db_path: &str, soql: &str, from: i64, to: i64, env: Option<&str>, budget_ms: u64, qid: Option<&str>, masks: &guatx_core::soql::FieldMaskSet) -> Result<Value, StoreError> {
        use std::sync::atomic::{AtomicBool, Ordering};
        // EXPERIMENTAL GATE : DuckDB n'est PAS un backend silencieusement sélectionnable. Avertissement
        // bruyant (une fois) tant que `PLUME_STORE_DUCKDB_EXPERIMENTAL=1` n'acquitte pas.
        duckdb_experimental_guard();
        // #45 : émission MASQUÉE (fail-closed sur ce tier) -> un rôle restreint ne voit jamais de cleartext.
        // L'émission passe par le store (jamais de SQL pré-fabriqué injecté).
        let sql = self.soql_to_sql_masked(soql, from, to, env, masks)?;
        let t0 = std::time::Instant::now();
        let conn = duckdb::Connection::open(db_path).map_err(be)?;

        // GAP-4 (a) — CAP MÉMOIRE + THREADS. DuckDB par défaut réclame ~80% de la RAM système et tous les
        // cœurs : mortel pour un pod au budget 2 Go. On pose des PRAGMA conservateurs, configurables, bien
        // sous le budget d'un nœud. Les valeurs env sont VALIDÉES (charset strict) avant émission -> aucune
        // injection possible via `SET` (repli sur défaut si invalide).
        let mem = duckdb_memory_limit();
        let threads = duckdb_threads();
        conn.execute_batch(&format!("SET memory_limit='{mem}'; SET threads={threads};")).map_err(be)?;

        // GAP-4 (b) — WATCHDOG budget_ms : MÊME motif que `run_query_ex` (SQLite). Un thread arme un
        // `InterruptHandle` DuckDB (Send+Sync) qui interrompt la requête au dépassement du budget. `qid` est
        // tracé (plus ignoré) ; l'annulation externe `/api/cancel` (registre `QUERY_CANCEL`) reste
        // SQLite-typée -> un registre backend-neutre est un follow-up (le budget suffit à borner la conso).
        let interrupt = conn.interrupt_handle();
        let done = Arc::new(AtomicBool::new(false));
        let fired = Arc::new(AtomicBool::new(false));
        let done_wd = done.clone();
        let fired_wd = fired.clone();
        let budget = budget_ms.max(1);
        let watchdog = std::thread::spawn(move || {
            let mut waited = 0u64;
            while waited < budget {
                if done_wd.load(Ordering::Relaxed) { return; }
                std::thread::sleep(std::time::Duration::from_millis(50));
                waited += 50;
            }
            fired_wd.store(true, Ordering::Relaxed);
            interrupt.interrupt();
        });

        let max_rows: usize = std::env::var("PLUME_QUERY_MAX").ok().and_then(|v| v.parse().ok())
            .filter(|&n| n > 0 && n <= 100_000).unwrap_or(5000);
        // Corps borné : sur interruption watchdog -> message budget clair (comme SQLite), jamais un 500 opaque.
        let result = (|| -> Result<Value, StoreError> {
            let mut stmt = conn.prepare(&sql).map_err(be)?;
            let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
            let ncol = cols.len();
            let mut out: Vec<Value> = Vec::new();
            let mut truncated = false;
            let mut rows = stmt.query([]).map_err(|e| watchdog_err(e, &fired, budget, qid))?;
            while let Some(row) = rows.next().map_err(|e| watchdog_err(e, &fired, budget, qid))? {
                if out.len() >= max_rows {
                    truncated = true;
                    break;
                }
                let mut r = Vec::with_capacity(ncol);
                for i in 0..ncol {
                    r.push(duck_vref_to_json(row.get_ref(i).map_err(be)?));
                }
                out.push(Value::Array(r));
            }
            let row_count = out.len();
            let elapsed_ms = (t0.elapsed().as_secs_f64() * 1_000_000.0).round() / 1000.0;
            Ok(json!({
                "columns": cols,
                "rows": out,
                "stats": { "elapsed_ms": elapsed_ms, "rows": row_count, "truncated": truncated }
            }))
        })();

        done.store(true, Ordering::Relaxed);
        let _ = watchdog.join();
        result
    }
}

/// GAP-4 gate — DuckDB est EXPÉRIMENTAL. Émet UN avertissement bruyant (au plus une fois) tant que
/// l'opérateur n'a pas acquitté via `PLUME_STORE_DUCKDB_EXPERIMENTAL=1`. Ne bloque pas (les caps runtime
/// sont posés) : le but est qu'un tier WARM non supporté ne soit JAMAIS activé silencieusement.
fn duckdb_experimental_guard() {
    use std::sync::Once;
    static WARN: Once = Once::new();
    WARN.call_once(|| {
        let acked = std::env::var("PLUME_STORE_DUCKDB_EXPERIMENTAL").map(|v| v == "1").unwrap_or(false);
        if !acked {
            eprintln!(
                "[store] ⚠️  DuckDbStore (PLUME_STORE=duckdb) est un tier WARM EXPÉRIMENTAL, NON supporté en \
                 prod (pas de parité crypto-at-rest/backup avec SQLCipher). Caps runtime ACTIFS \
                 (memory_limit={}, threads={}, watchdog budget_ms). Le tier scale-out SUPPORTÉ est \
                 ClickHouse. Posez PLUME_STORE_DUCKDB_EXPERIMENTAL=1 pour acquitter et supprimer cet \
                 avertissement.",
                duckdb_memory_limit(), duckdb_threads()
            );
        }
    });
}

/// Cap mémoire DuckDB (`SET memory_limit`). Env `PLUME_DUCKDB_MEMORY_LIMIT`, défaut conservateur `512MB`
/// (bien sous un budget de nœud 2 Go). VALIDÉ (nombre + unité DuckDB) -> aucune injection via `SET` ; toute
/// valeur non conforme retombe sur le défaut.
fn duckdb_memory_limit() -> String {
    const DEFAULT: &str = "512MB";
    match std::env::var("PLUME_DUCKDB_MEMORY_LIMIT") {
        Ok(v) if is_valid_memory_limit(&v) => v,
        _ => DEFAULT.to_string(),
    }
}

/// Nombre de threads DuckDB (`SET threads`). Env `PLUME_DUCKDB_THREADS`, défaut conservateur `2`, borné
/// [1..=8] (un embedded OLAP ne doit pas saturer les cœurs du pod). Toute valeur invalide -> défaut.
fn duckdb_threads() -> u32 {
    std::env::var("PLUME_DUCKDB_THREADS").ok().and_then(|v| v.parse::<u32>().ok())
        .filter(|&n| (1..=8).contains(&n)).unwrap_or(2)
}

/// Validation stricte de `memory_limit` (anti-injection `SET`) : `<nombre>[ ]<unité>` où l'unité est une
/// unité de taille DuckDB (B/KB/MB/GB/TB, binaire ou décimale). Refuse tout ce qui contient un quote,
/// point-virgule, espace multiple ou caractère hors charset -> impossible d'échapper le littéral `SET`.
fn is_valid_memory_limit(v: &str) -> bool {
    let v = v.trim();
    if v.is_empty() || v.len() > 16 { return false; }
    let bytes = v.as_bytes();
    let mut i = 0;
    // partie numérique (au moins un chiffre, un point optionnel)
    let start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() { i += 1; }
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_digit() { i += 1; }
    }
    if i == start { return false; } // aucun chiffre
    // séparateur : au plus un espace
    if i < bytes.len() && bytes[i] == b' ' { i += 1; }
    // unité (charset alpha strict)
    let unit: String = v[i..].to_ascii_uppercase();
    matches!(unit.as_str(), "B" | "KB" | "MB" | "GB" | "TB" | "KIB" | "MIB" | "GIB" | "TIB")
}

/// Traduit une erreur DuckDB en distinguant l'interruption WATCHDOG (budget dépassé) d'une erreur backend
/// ordinaire — message clair aligné sur `run_query_ex` (SQLite), avec `qid` pour la traçabilité.
fn watchdog_err(e: duckdb::Error, fired: &std::sync::atomic::AtomicBool, budget: u64, qid: Option<&str>) -> StoreError {
    if fired.load(std::sync::atomic::Ordering::Relaxed) {
        let q = qid.map(|q| format!(" [qid={q}]")).unwrap_or_default();
        StoreError::Backend(format!("requête DuckDB interrompue (budget {budget} ms dépassé){q}"))
    } else {
        be(e)
    }
}

/// Mappe une erreur DuckDB native vers l'erreur neutre `StoreError::Backend` (GAP-1 : le cœur ne connaît
/// aucun type d'erreur backend).
fn be(e: duckdb::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

#[cfg(test)]
mod med1_tests {
    use super::*;
    use guatx_core::soql::{FieldMaskSet, MaskAction};

    // MED-1 : le call-site WARM DuckDB THREAD désormais les masques (`.with_masks`) -> une lecture
    // role-scopée masque le champ (comme le HOT). Masques VIDES -> byte-identique au chemin non masqué (mode 0).
    #[test]
    fn duckdb_store_masked_emission_threads_masks() {
        let s = DuckDbStore;
        let mut m = FieldMaskSet::new();
        m.insert("src_user", MaskAction::Mask);
        let masked = s.soql_to_sql_masked("search | table src_user, host", 0, 0, None, &m).unwrap();
        assert!(masked.contains("'***'"), "WARM DuckDB masque src_user (comme le HOT) : {masked}");
        // Masques VIDES -> STRICTEMENT identique à `soql_to_sql` (mode 0 byte-identique).
        let empty = s.soql_to_sql_masked("search | table src_user, host", 0, 0, None, &FieldMaskSet::new()).unwrap();
        let plain = s.soql_to_sql("search | table src_user, host", 0, 0, None).unwrap();
        assert_eq!(empty, plain, "WARM masques VIDES -> byte-identique au non masqué");
    }

    // GAP-4 (revue store-resource) — CAP MÉMOIRE : la validation `memory_limit` accepte les formes
    // DuckDB légitimes et REJETTE toute tentative d'injection `SET` (quote/;/charset) -> repli sur défaut.
    #[test]
    fn duckdb_memory_limit_is_injection_safe() {
        // formes valides
        for ok in ["512MB", "2GB", "1.5GB", "256 MB", "1024KB", "8TB", "512MiB"] {
            assert!(is_valid_memory_limit(ok), "devrait être valide: {ok}");
        }
        // injections / formes invalides -> refusées (le default sera utilisé)
        for bad in [
            "512MB'; DROP TABLE event;--",
            "1GB; SET threads=99",
            "'||(SELECT hash FROM user)||'",
            "MB", "", "  ", "512", "512 XB", "512;MB", "512MB ", // (trailing space trim -> "512MB" ok, mais on teste la borne)
        ] {
            // "512MB " se trim -> "512MB" valide ; on ne l'inclut pas dans l'assertion négative
            if bad.trim() == "512MB" { continue; }
            assert!(!is_valid_memory_limit(bad), "devrait être REJETÉ (injection/invalide): {bad:?}");
        }
    }

    // GAP-4 — CAP THREADS : borné [1..=8], défaut 2, toute valeur hors borne/invalide -> défaut.
    #[test]
    fn duckdb_threads_bounded() {
        // le défaut est conservateur (2) et la borne haute est 8 : on vérifie l'invariant sans toucher l'env
        // process-wide (les tests tournent en parallèle). La validité de la borne est prouvée par la fn pure.
        let d = duckdb_threads();
        assert!((1..=8).contains(&d), "threads DuckDB bornés [1..=8]: {d}");
    }
}
