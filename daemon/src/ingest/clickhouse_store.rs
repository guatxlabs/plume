//! ClickHouseStore — tier COLD/scale (#18, Phase 2 de `docs/scale-clickhouse-ha-design.md`), DERRIÈRE la
//! SPI backend-neutre `guatx_core::store::EventStore`.
//!
//! FEATURE-GATED `clickhouse`, OFF PAR DÉFAUT. Ce module N'EXISTE PAS dans le build SMB par défaut
//! (`daemon/src/ingest/mod.rs` le déclare sous `#[cfg(feature = "clickhouse")]`) : le binaire par défaut
//! NE LINKE PAS la crate `clickhouse` (client HTTP async hyper/tokio) ni `serde` derive -> budget 2 Go /
//! mode 0 byte-identique préservés. Sélection runtime FUTURE : `PLUME_STORE=clickhouse` (opt-in, comme
//! `PLUME_STORE=duckdb`). On livre ici la PREUVE #18 Phase 2 (RFC §1) qu'un TROISIÈME backend — réseau,
//! async, NON-`rusqlite`/NON-`duckdb` — monte la MÊME SPI : émission via `ClickHouseDialect` (cœur) +
//! exécuteur ClickHouse, sans toucher au compilateur SOQL ni au chemin SQLite (parité mode 0 intacte).
//!
//! CHOIX SPI (documenté, RFC §1.3) :
//!   - GAP-2 (SPI SYNCHRONE ; ClickHouse est ASYNC/HTTP) : on prend l'OPTION A du RFC — bloquer sur un
//!     runtime tokio `current_thread` DÉDIÉ (`self.rt.block_on(...)`), destiné à tourner À L'INTÉRIEUR du
//!     `spawn_blocking` qui enveloppe déjà les lectures data-plane (`query_exec`/`run_query_ex`). Blast
//!     radius minimal : `SqlcipherStore` reste byte-identique, le chemin de lecture sync est inchangé.
//!     L'option B (jumeau `async fn query_soql_async` routé directement sur le runtime tokio) est un
//!     follow-up de la phase distribution (pooling de connexions au cluster).
//!   - GAP-3 (ClickHouse HAIT les INSERT ligne-à-ligne) : `insert_events` ouvre UN `Insert<ChEventRow>`
//!     (format `RowBinary`) et y écrit toutes les lignes du lot avant `end()` — c'est l'INSERT BATCHÉ
//!     natif du client. `insert_event` = lot d'une ligne. (Le tier de prod ajouterait un `Inserter`
//!     bufferisé N lignes / T ms — feature `inserter` — follow-up.)
//!   - GAP-4 (bornage/annulation) : la lecture pose `max_execution_time` (depuis `budget_ms`) + `query_id`
//!     (depuis `qid`) en SETTINGS ClickHouse via `Query::with_option` -> watchdog + `KILL QUERY` côté
//!     serveur. La denylist de colonnes secrètes est SANS OBJET ici : le control-plane (user.hash /
//!     token.token_hash …) n'est JAMAIS dans ClickHouse (seuls event/metric/snapshot y vivent, RFC §0.1).
//!   - GAP-5 (`db_path` = clé de tenant fichier) : ClickHouse n'a pas de chemin fichier ; le tenant mappe
//!     à une `database`/`cluster` + credentials portés par le `Client`. Ici le `db_path` de `query_soql`
//!     est IGNORÉ (le `Client` porte déjà la database) — la résolution par-tenant d'un `StoreLocator`
//!     opaque est un follow-up (RFC §1.3 GAP-5), comme le câblage runtime `PLUME_STORE=clickhouse`.
#![allow(dead_code)] // module opt-in : le câblage runtime `PLUME_STORE=clickhouse` est un follow-up.
use crate::*;
use guatx_core::store::{EventStore, StoreError, StoreHandle};
use serde_json::json;

/// Ligne d'INSERT ClickHouse typée (dérive `clickhouse::Row` + `serde::Serialize` -> sérialisée en
/// `RowBinary`). MÊMES colonnes/ordre que l'`event` SQLite. `env_id=None` -> 'prod' (comme le chemin
/// SQLite : la colonne est NOT NULL DEFAULT 'prod').
#[derive(clickhouse::Row, serde::Serialize)]
struct ChEventRow {
    ts: i64,
    source: String,
    category: String,
    severity: i64,
    message: String,
    host: Option<String>,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    url: Option<String>,
    dedup: Option<String>,
    fields: Option<String>,
    engagement_id: String,
    origin: String,
    env_id: String,
}

impl ChEventRow {
    fn from_row(r: &EventRow) -> Self {
        ChEventRow {
            ts: r.ts,
            source: r.source.clone(),
            category: r.category.clone(),
            severity: r.severity,
            message: r.message.clone(),
            host: r.host.clone(),
            src_ip: r.src_ip.clone(),
            dst_ip: r.dst_ip.clone(),
            url: r.url.clone(),
            dedup: r.dedup.clone(),
            fields: r.fields.clone(),
            engagement_id: r.engagement_id.clone(),
            origin: r.origin.clone(),
            env_id: r.env_id.clone().unwrap_or_else(|| "prod".to_string()),
        }
    }
}

#[derive(clickhouse::Row, serde::Serialize)]
struct ChMetricRow {
    ts: i64,
    name: String,
    labels: Option<String>,
    value: f64,
    host: Option<String>,
}

#[derive(clickhouse::Row, serde::Serialize)]
struct ChSnapshotRow {
    ts: i64,
    kind: String,
    hash: String,
    data: String,
    host: Option<String>,
}

/// Store COLD/scale ClickHouse (#18). Contrairement aux stores SQLite/DuckDB (sans état, connexion passée
/// par appel), il PORTE son `Client` (le client HTTP ClickHouse est déjà multiplexé/pooling) + un runtime
/// `current_thread` pour le pont sync->async (GAP-2 option A). La sélection par-tenant (GAP-5) reste un
/// follow-up ; ici le `Client` cible une database fixe.
pub(crate) struct ClickHouseStore {
    client: clickhouse::Client,
    /// Runtime DÉDIÉ pour bloquer sur l'I/O async du client (GAP-2 option A). Doit être appelé depuis un
    /// contexte BLOQUANT (`spawn_blocking`), jamais depuis le thread d'un runtime tokio actif.
    rt: tokio::runtime::Runtime,
}

impl ClickHouseStore {
    const EVENT_INSERT_SQL: &'static str =
        "INSERT INTO event(ts,source,category,severity,message,host,src_ip,dst_ip,url,dedup,fields,engagement_id,origin,env_id) VALUES";
    const METRIC_INSERT_SQL: &'static str =
        "INSERT INTO metric(ts,name,labels,value,host) VALUES";

    // ------------------------------------------------------------------------------------------------
    // DDL data-plane ClickHouse (`event`/`metric`/`snapshot`) — MIROIR du schéma SQLite `db/schema.sql`,
    // mais en moteur COLONNAIRE `MergeTree` (RFC §3.2, Phase 2 « cluster de un »). Idempotent (`IF NOT
    // EXISTS`). Émis par `ensure_schema()` au PROVISIONING d'un déploiement scale (opt-in) ; JAMAIS sur le
    // chemin SMB / mode 0. Les NOMS de colonnes sont IDENTIQUES aux `Ch*Row` (l'INSERT `RowBinary` du
    // client cible les colonnes PAR NOM) et à l'`event` SQLite -> MÊME surface SOQL, aucune réécriture.
    //
    // CHOIX MergeTree (RFC §3.1/§3.2) :
    //   - `PARTITION BY toYYYYMM(toDateTime(ts))` : partitionnement mensuel -> la purge de rétention
    //     devient un `DROP PARTITION` (bon marché à l'échelle multi-To) plutôt qu'un DELETE massif.
    //   - `event.ORDER BY (env_id, source, ts)` : miroir des index SQLite (`idx_event_src`/`idx_event_ts`)
    //     + scoping environnement (#2a) ; la clé de tri est aussi la clé du sparse-index MergeTree.
    //   - DEDUP : ClickHouse n'a PAS de contrainte `UNIQUE` -> l'`INSERT OR IGNORE` exactly-once du SQLite
    //     n'a pas d'équivalent (RFC §3.3, question OPEN). Le tier de PROD scale utiliserait
    //     `ReplacingMergeTree(ts)` clé sur `dedup` pour un dédup ÉVENTUEL (au merge). Le cut single-node de
    //     CORRECTION (#18 Phase 2) reste `MergeTree` nu : le dédup éventuel est un durcissement documenté,
    //     pas un prérequis de correction (cf. `docs/CLICKHOUSE-STORE.md`).
    const EVENT_DDL: &'static str = "CREATE TABLE IF NOT EXISTS event (\
        ts Int64, source String, category String, severity Int64, message String, \
        host Nullable(String), src_ip Nullable(String), dst_ip Nullable(String), url Nullable(String), \
        dedup Nullable(String), fields Nullable(String), \
        engagement_id String DEFAULT '', origin String DEFAULT '', env_id String DEFAULT 'prod'\
        ) ENGINE = MergeTree PARTITION BY toYYYYMM(toDateTime(ts)) ORDER BY (env_id, source, ts)";
    const METRIC_DDL: &'static str = "CREATE TABLE IF NOT EXISTS metric (\
        ts Int64, name String, labels Nullable(String), value Float64, host Nullable(String)\
        ) ENGINE = MergeTree PARTITION BY toYYYYMM(toDateTime(ts)) ORDER BY (name, ts)";
    const SNAPSHOT_DDL: &'static str = "CREATE TABLE IF NOT EXISTS snapshot (\
        ts Int64, kind String, hash String, data String, host Nullable(String)\
        ) ENGINE = MergeTree PARTITION BY toYYYYMM(toDateTime(ts)) ORDER BY (kind, ts)";
    /// Ordre canonique des DDL (event d'abord). Source UNIQUE du texte de schéma (diagnostic + tests).
    const SCHEMA_DDL: [&'static str; 3] = [Self::EVENT_DDL, Self::METRIC_DDL, Self::SNAPSHOT_DDL];

    /// Accesseur des DDL de schéma — TESTABLE sans serveur ClickHouse (assertions de texte : moteur
    /// MergeTree, parité de colonnes event <-> INSERT). Miroir de l'esprit `metric_insert_sql()`.
    pub(crate) fn schema_ddl() -> &'static [&'static str] {
        &Self::SCHEMA_DDL
    }

    /// Provisionne (idempotent) le schéma data-plane sur le serveur ClickHouse cible. Appelé UNE fois au
    /// démarrage d'un déploiement scale (opt-in `PLUME_STORE=clickhouse`) — JAMAIS en mode 0. Bloque sur le
    /// runtime dédié (GAP-2 option A) -> à invoquer depuis un contexte BLOQUANT (`spawn_blocking`). Nécessite
    /// un serveur CH joignable (couvert par le test d'intégration `#[ignore]`, pas la CI par défaut).
    pub(crate) fn ensure_schema(&self) -> Result<(), StoreError> {
        self.rt.block_on(async {
            for ddl in Self::SCHEMA_DDL {
                self.client.query(ddl).execute().await.map_err(be)?;
            }
            Ok(())
        })
    }

    /// Construit le store depuis l'environnement (`PLUME_CLICKHOUSE_URL`/`_USER`/`_PASSWORD`/`_DATABASE`).
    /// NON câblé à la sélection runtime (follow-up) — instancié explicitement par un déploiement scale.
    pub(crate) fn from_env() -> Result<Self, StoreError> {
        let url = std::env::var("PLUME_CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".into());
        let mut client = clickhouse::Client::default().with_url(url);
        if let Ok(u) = std::env::var("PLUME_CLICKHOUSE_USER") {
            client = client.with_user(u);
        }
        if let Ok(p) = std::env::var("PLUME_CLICKHOUSE_PASSWORD") {
            client = client.with_password(p);
        }
        if let Ok(db) = std::env::var("PLUME_CLICKHOUSE_DATABASE") {
            client = client.with_database(db);
        }
        Self::with_client(client)
    }

    /// Construit le store autour d'un `Client` déjà configuré (utile pour les tests d'intégration / le
    /// routing par-tenant futur qui résoudra un `Client` par database).
    pub(crate) fn with_client(client: clickhouse::Client) -> Result<Self, StoreError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| StoreError::Backend(format!("clickhouse runtime: {e}")))?;
        Ok(ClickHouseStore { client, rt })
    }
}

/// Mappe une erreur native `clickhouse` vers l'erreur neutre `StoreError::Backend` (GAP-1).
fn be(e: clickhouse::error::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

impl EventStore for ClickHouseStore {
    fn insert_event(&self, h: StoreHandle, row: &EventRow) -> Result<usize, StoreError> {
        self.insert_events(h, std::slice::from_ref(row))
    }

    fn insert_metric(&self, _h: StoreHandle, m: &MetricRow) -> Result<usize, StoreError> {
        let cm = ChMetricRow {
            ts: m.ts,
            name: m.name.clone(),
            labels: m.labels.clone(),
            value: m.value,
            host: m.host.clone(),
        };
        self.rt.block_on(async {
            let mut ins = self.client.insert::<ChMetricRow>("metric").await.map_err(be)?;
            ins.write(&cm).await.map_err(be)?;
            ins.end().await.map_err(be)?;
            Ok(1)
        })
    }

    fn insert_snapshot(&self, _h: StoreHandle, s: &SnapshotRow) -> Result<usize, StoreError> {
        let cs = ChSnapshotRow {
            ts: s.ts,
            kind: s.kind.clone(),
            hash: s.hash.clone(),
            data: s.data.clone(),
            host: s.host.clone(),
        };
        self.rt.block_on(async {
            let mut ins = self.client.insert::<ChSnapshotRow>("snapshot").await.map_err(be)?;
            ins.write(&cs).await.map_err(be)?;
            ins.end().await.map_err(be)?;
            Ok(1)
        })
    }

    fn insert_events(&self, _h: StoreHandle, rows: &[EventRow]) -> Result<usize, StoreError> {
        // GAP-3 : INSERT BATCHÉ natif — UN `Insert<ChEventRow>` (RowBinary) pour tout le lot, `end()`
        // valide. ClickHouse s'effondre sous les INSERT ligne-à-ligne ; ici une seule requête HTTP porte
        // N lignes (`insert_event` = lot d'une ligne, cf. supra).
        self.rt.block_on(async {
            let mut ins = self.client.insert::<ChEventRow>("event").await.map_err(be)?;
            for r in rows {
                ins.write(&ChEventRow::from_row(r)).await.map_err(be)?;
            }
            ins.end().await.map_err(be)?;
            Ok(rows.len())
        })
    }

    fn event_insert_sql(&self) -> &'static str {
        // Texte canonique (diagnostic/symétrie) — l'INSERT RÉEL passe par le `RowBinary` typé ci-dessus.
        Self::EVENT_INSERT_SQL
    }
    fn metric_insert_sql(&self) -> &'static str {
        Self::METRIC_INSERT_SQL
    }

    fn soql_to_sql(&self, soql: &str, from: i64, to: i64, env: Option<&str>) -> Result<String, StoreError> {
        // Émission via le cœur partagé, DIALECT ClickHouse (`Schema::events_clickhouse()`). Compilateur
        // réutilisé VERBATIM -> seuls les fragments SQL diffèrent (parité SQLite intacte par ailleurs).
        self.soql_to_sql_masked(soql, from, to, env, &guatx_core::soql::FieldMaskSet::new())
    }

    fn soql_to_sql_masked(&self, soql: &str, from: i64, to: i64, env: Option<&str>, masks: &guatx_core::soql::FieldMaskSet) -> Result<String, StoreError> {
        // FIELD FILTERS (#45) — masques ÉMIS DANS LE SQL ClickHouse via le `Dialect` (`with_masks`), au MÊME
        // choke-point que le tier chaud. VIDE -> byte-identique à `soql_to_sql` (mode 0). Actions portables
        // (Mask/MaskPartial/Redact/Deny) exécutées côté CH ; action NON portable (Hash -> `plume_fmask_hash`
        // absente) -> ERREUR À L'EXÉCUTION = FAIL-CLOSED (jamais de cleartext servi à un rôle restreint).
        guatx_core::soql::to_sql(soql, from, to, &guatx_core::soql::Schema::events_clickhouse().with_env(env).with_masks(masks.clone()))
            .map_err(StoreError::Emit)
    }

    fn query_soql(&self, db_path: &str, soql: &str, from: i64, to: i64, env: Option<&str>, budget_ms: u64, qid: Option<&str>) -> Result<Value, StoreError> {
        self.query_soql_masked(db_path, soql, from, to, env, budget_ms, qid, &guatx_core::soql::FieldMaskSet::new())
    }

    fn query_soql_masked(&self, _db_path: &str, soql: &str, from: i64, to: i64, env: Option<&str>, budget_ms: u64, qid: Option<&str>, masks: &guatx_core::soql::FieldMaskSet) -> Result<Value, StoreError> {
        // GAP-5 : `_db_path` ignoré (le `Client` porte déjà la database ; résolution par-tenant = follow-up).
        // L'émission passe par le store (jamais de SQL pré-fabriqué injecté). #45 : émission MASQUÉE (fail-closed).
        let sql = self.soql_to_sql_masked(soql, from, to, env, masks)?;
        let max_rows: usize = std::env::var("PLUME_QUERY_MAX").ok().and_then(|v| v.parse().ok())
            .filter(|&n| n > 0 && n <= 100_000).unwrap_or(5000);
        let t0 = std::time::Instant::now();
        self.rt.block_on(async {
            // GAP-4 : watchdog + annulation server-side via SETTINGS ClickHouse.
            let mut q = self.client.query(&sql);
            if budget_ms > 0 {
                // `max_execution_time` est en SECONDES (arrondi au plafond, min 1s).
                let secs = std::cmp::max(1, budget_ms.div_ceil(1000));
                q = q.with_option("max_execution_time", secs.to_string());
            }
            if let Some(id) = qid {
                q = q.with_option("query_id", id.to_string());
            }
            // `JSONCompact` -> `{ "meta":[{name,type},...], "data":[[...],...], ... }` : `data` est
            // DÉJÀ un tableau de tableaux, identique à la forme `rows` des exécuteurs SQLite/DuckDB.
            let mut cursor = q.fetch_bytes("JSONCompact").map_err(be)?;
            let mut buf: Vec<u8> = Vec::new();
            while let Some(chunk) = cursor.next().await.map_err(be)? {
                buf.extend_from_slice(&chunk);
            }
            let parsed: Value = serde_json::from_slice(&buf)
                .map_err(|e| StoreError::Backend(format!("clickhouse JSONCompact parse: {e}")))?;
            let cols: Vec<Value> = parsed.get("meta").and_then(|m| m.as_array()).map(|m| {
                m.iter().map(|c| c.get("name").cloned().unwrap_or(Value::Null)).collect()
            }).unwrap_or_default();
            let all: Vec<Value> = parsed.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default();
            let truncated = all.len() > max_rows;
            let out: Vec<Value> = all.into_iter().take(max_rows).collect();
            let row_count = out.len();
            let elapsed_ms = (t0.elapsed().as_secs_f64() * 1_000_000.0).round() / 1000.0;
            Ok(json!({
                "columns": cols,
                "rows": out,
                "stats": { "elapsed_ms": elapsed_ms, "rows": row_count, "truncated": truncated }
            }))
        })
    }
}

// ====================================================================================================
// TESTS UNITAIRES — compilés UNIQUEMENT sous `--features clickhouse` (le module l'est). Ils prouvent, SANS
// serveur ClickHouse, les deux propriétés vérifiables offline (RFC §1.2 / §3.2) :
//   1. l'ADAPTATEUR compile le SOQL VIA le `ClickHouseDialect` du cœur (jamais de SQL pré-fabriqué) — le
//      délta d'émission CH apparaît (l'émission elle-même est déjà prouvée dans `core/src/soql.rs`) ;
//   2. la DDL est bien `MergeTree` et MIROIR des colonnes `event` de l'INSERT (parité de schéma).
// L'INSERT batché + la lecture round-trip exigent un serveur CH -> test `#[ignore]` (cf. plus bas), hors CI.
#[cfg(test)]
mod tests {
    use super::*;

    /// Compile un SOQL VIA la méthode du store (`EventStore::soql_to_sql`) — n'ouvre AUCUNE connexion
    /// réseau (le `Client` ne se connecte qu'à l'envoi d'une requête ; ici on ne fait que compiler).
    fn compile(soql: &str) -> String {
        let store = ClickHouseStore::with_client(clickhouse::Client::default()).expect("store");
        store.soql_to_sql(soql, 0, i64::MAX, None).expect("compile")
    }

    #[test]
    fn store_soql_compiles_via_clickhouse_dialect() {
        // MÊME requête que la preuve d'émission du cœur : `values(user)` -> extraction JSON + group_concat.
        // On prouve que le chemin ADAPTATEUR (store.soql_to_sql) porte bien le dialect CH.
        let sql = compile("search source=sshd | stats values(user) by src_ip");
        assert!(sql.contains("JSONExtractString(fields,'user')"), "json_extract CH attendu: {sql}");
        assert!(sql.contains("arrayStringConcat(groupUniqArray("), "group_concat CH attendu: {sql}");
        // Anti-régression : aucun fragment SQLite ne fuit dans l'émission CH.
        assert!(!sql.contains("json_extract("), "fragment SQLite json_extract interdit: {sql}");
        assert!(!sql.contains("GROUP_CONCAT("), "fragment SQLite GROUP_CONCAT interdit: {sql}");
    }

    #[test]
    fn store_soql_time_bucket_is_clickhouse_intdiv() {
        // `timechart span=1h` -> time_bucket -> `intDiv(ts,3600)*3600` (grain IDENTIQUE au `(ts/3600)*3600`
        // SQLite : la clé du rollup doit correspondre, RFC §1.2).
        let sql = compile("search source=sshd | timechart span=1h count");
        assert!(sql.contains("intDiv(ts,3600)*3600"), "time_bucket CH attendu: {sql}");
    }

    #[test]
    fn store_soql_literal_is_escaped() {
        // INJECTION-SAFETY : le littéral traverse le MÊME compilateur (choke-point `soql_esc` du cœur) ;
        // l'apostrophe est DOUBLÉE dans l'émission CH comme en SQLite -> pas d'échappement du quoting.
        let sql = compile("search source=sshd message=\"a'b\"");
        assert!(sql.contains("'a''b'"), "littéral échappé attendu (quote doublée): {sql}");
    }

    #[test]
    fn schema_ddl_is_mergetree() {
        let ddls = ClickHouseStore::schema_ddl();
        assert_eq!(ddls.len(), 3, "event/metric/snapshot");
        for ddl in ddls {
            assert!(ddl.contains("ENGINE = MergeTree"), "moteur MergeTree attendu: {ddl}");
            assert!(ddl.contains("IF NOT EXISTS"), "idempotence attendue: {ddl}");
            assert!(ddl.contains("PARTITION BY toYYYYMM"), "partition mensuelle attendue: {ddl}");
        }
    }

    #[test]
    fn event_ddl_mirrors_insert_columns() {
        // Parité de schéma : CHAQUE colonne de l'INSERT event (source unique `EVENT_INSERT_SQL`) DOIT
        // exister dans la DDL MergeTree -> l'INSERT `RowBinary` (ciblage par NOM) ne peut pas dériver.
        let ddl = ClickHouseStore::EVENT_DDL;
        let insert = ClickHouseStore::EVENT_INSERT_SQL;
        let cols = insert
            .split_once('(').unwrap().1
            .split_once(')').unwrap().0;
        for col in cols.split(',') {
            let col = col.trim();
            assert!(ddl.contains(col), "colonne `{col}` de l'INSERT absente de la DDL: {ddl}");
        }
        // Les colonnes NOT-NULL par défaut du SQLite -> `String DEFAULT` côté CH (jamais NULL, parité valeur).
        assert!(ddl.contains("env_id String DEFAULT 'prod'"), "env_id DEFAULT 'prod' attendu: {ddl}");
        assert!(ddl.contains("origin String DEFAULT ''"), "origin DEFAULT '' attendu: {ddl}");
    }

    /// Round-trip RÉEL contre un serveur ClickHouse joignable (`PLUME_CLICKHOUSE_URL`). `#[ignore]` : hors
    /// CI (pas de serveur) — lancer `cargo test --features clickhouse -- --ignored` avec un CH up. Prouve
    /// `ensure_schema` + `insert_events` (batch RowBinary) + `query_soql` (émission + exécution + parse).
    #[test]
    #[ignore = "nécessite un serveur ClickHouse joignable (PLUME_CLICKHOUSE_URL)"]
    fn live_roundtrip_ensure_insert_query() {
        let store = ClickHouseStore::from_env().expect("from_env");
        store.ensure_schema().expect("ensure_schema");
        let rows = vec![EventRow {
            ts: 1_700_000_000,
            source: "sshd".into(),
            category: "auth".into(),
            severity: 2,
            message: "failed password".into(),
            host: Some("h1".into()),
            src_ip: Some("10.0.0.1".into()),
            dst_ip: None,
            url: None,
            dedup: Some("k1".into()),
            fields: Some("{\"user\":\"root\"}".into()),
            engagement_id: String::new(),
            origin: String::new(),
            env_id: None,
        }];
        // `StoreHandle::ClickHouse` porte un &dyn Any inutile ici (le store porte son Client) — on passe un
        // marqueur unit ; l'impl ignore le handle pour ClickHouse.
        let unit = ();
        let n = store.insert_events(StoreHandle::ClickHouse(&unit), &rows).expect("insert_events");
        assert_eq!(n, 1);
        let v = store
            .query_soql("", "search source=sshd | stats count", 0, i64::MAX, None, 5_000, None)
            .expect("query_soql");
        assert!(v.get("rows").is_some(), "réponse structurée attendue: {v}");
    }
}
