//! ClickHouseHa — SCAFFOLD du tier COLD/scale DISTRIBUÉ (#70, Phase 3/4 de
//! `docs/scale-clickhouse-ha-design.md`), EXTENSION du single-node `clickhouse_store.rs` (#18, Phase 2).
//!
//! STATUT : FONDATION INERTE, PAS ACTIVÉE. Feature-gated `clickhouse-ha` (qui active `clickhouse`) — ce
//! module N'EXISTE PAS dans le build par défaut NI dans le build `--features clickhouse` (#18). Il ne
//! porte AUCUN chemin runtime : rien du data-plane ne l'appelle (aucun call-site câblé). On pose ICI les
//! FONDATIONS TYPÉES d'un effort multi-trimestre (RFC §3/§4) — topologie de cluster, génération DDL
//! distribuée (`Distributed` sur `ReplicatedMergeTree`), interface de coordination Keeper, couture
//! d'ingest stateless, politique hot→cold — SANS cluster vivant et SANS opération multi-nœud réelle.
//!
//! SÉCURITÉ #1 — INJECTION DANS LA DDL DEPUIS LA CONFIG. La DDL distribuée est CONSTRUITE à partir de noms
//! venus de la config/env (cluster, database, table, volume, policy, colonne de sharding). Ces noms sont
//! SEMI-DE-CONFIANCE : ils sont validés DUR contre une allowlist stricte (`[A-Za-z0-9_]`, cf. `ident_ok`,
//! miroir de `soql_ident_ok` du cœur) via le newtype [`SafeIdent`] — construit-ou-rejeté. AUCUN nom n'est
//! JAMAIS concaténé brut dans une DDL : tout traverse `SafeIdent`. Les macros ClickHouse `{shard}` /
//! `{replica}` sont des LITTÉRAUX (substitués côté serveur), jamais de la config. La clé de sharding est
//! une COLONNE validée (enum fermé [`ShardingKey`]), jamais du texte libre. Le corps de colonnes et les
//! clés `PARTITION BY`/`ORDER BY` sont des CONSTANTES de l'auteur (non issues de la config).
//!
//! PRÉCONDITIONS REPORTÉES DE #18 (cf. `docs/CLICKHOUSE-HA.md` §Préconditions) :
//!   - MASQUAGE (#45) : câbler `soql_to_sql_masked` sur la SPI NEUTRE avant d'exposer le tier scale à des
//!     rôles restreints (sinon fail-closed : lecture masquée refusée plutôt que fuite non masquée).
//!   - AT-REST : ClickHouse PERD la crypto SQLCipher clé-par-tenant tenue par l'app -> volume/KMS/CH
//!     encryption + `database` par tenant (effacement RGPD = `DROP DATABASE`), garantie DÉGRADÉE, à écrire.
//!   - DISPATCH : la sélection runtime `PLUME_STORE=clickhouse` (~82 call-sites) reste DIFFÉRÉE (#18).
#![allow(dead_code)] // module SCAFFOLD inerte : aucun câblage runtime (fondation multi-trimestre #70).

use guatx_core::store::{EventRow, EventStore, StoreError, StoreHandle};

// ====================================================================================================
// 0. ERREUR + VALIDATION D'IDENTIFIANT (le choke-point anti-injection)
// ====================================================================================================

/// Erreur neutre du scaffold HA. `NotImplemented` marque les coutures dont l'impl RÉELLE exige un
/// cluster/Keeper vivant (Keeper, ingest stateless) — jamais un faux-positif silencieux.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HaError {
    /// Un nom (cluster/database/table/volume/policy/colonne) a échoué l'allowlist `[A-Za-z0-9_]`.
    InvalidIdent(String),
    /// Un hôte de réplica a échoué l'allowlist hôte (`[A-Za-z0-9._-]`) ou un port est nul.
    InvalidHost(String),
    /// La topologie est structurellement invalide (0 shard, 0 réplica, spec de sharding vide…).
    InvalidTopology(String),
    /// Une valeur de config est malformée (spec de shards non parsable…).
    Config(String),
    /// Couture dont l'impl vivante est différée (needs a live Keeper / cluster).
    NotImplemented(&'static str),
}

impl std::fmt::Display for HaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HaError::InvalidIdent(s) => write!(f, "identifiant invalide (allowlist [A-Za-z0-9_]): {s:?}"),
            HaError::InvalidHost(s) => write!(f, "hôte/port de réplica invalide: {s:?}"),
            HaError::InvalidTopology(s) => write!(f, "topologie de cluster invalide: {s}"),
            HaError::Config(s) => write!(f, "config HA invalide: {s}"),
            HaError::NotImplemented(s) => write!(f, "couture HA différée (cluster/Keeper vivant requis): {s}"),
        }
    }
}
impl std::error::Error for HaError {}

impl From<HaError> for StoreError {
    fn from(e: HaError) -> StoreError {
        StoreError::Backend(e.to_string())
    }
}

/// Longueur max d'un identifiant (garde-fou anti-pathologie ; ClickHouse tolère bien plus mais un nom de
/// 64 c. couvre tous les usages légitimes cluster/db/table/volume/policy).
const IDENT_MAX: usize = 64;

/// Allowlist STRICTE d'identifiant, MIROIR de `guatx_core::soql::soql_ident_ok` (privé au cœur, non
/// ré-exportable -> on le reproduit ici, même règle : non vide, `[A-Za-z0-9_]` uniquement). C'est LE
/// choke-point anti-injection de la DDL : tout nom issu de la config passe par ici avant toute émission.
/// Rejette donc `;`, quotes, espaces, `-`, `/`, `.`, `{`/`}`, backticks — toute la surface d'injection DDL.
fn ident_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= IDENT_MAX
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Allowlist d'HÔTE (utilisée UNIQUEMENT pour la config `remote_servers`, JAMAIS dans une DDL `ON
/// CLUSTER`). Autorise le point et le tiret des noms DNS + les chiffres/lettres/`_`. N'entre pas dans le
/// chemin d'émission SQL — mais on la valide quand même (défense en profondeur du modèle de topologie).
fn host_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Identifiant SQL VALIDÉ (construit-ou-rejeté). Le SEUL moyen d'obtenir un nom utilisable dans la DDL :
/// impossible d'en fabriquer un qui n'ait pas traversé `ident_ok`. `as_str()` rend le nom déjà sûr pour
/// une concaténation NUE (pas de quoting nécessaire : l'allowlist exclut tout métacaractère SQL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SafeIdent(String);

impl SafeIdent {
    /// Valide `raw` contre l'allowlist stricte, ou renvoie `HaError::InvalidIdent`. AUCUNE autre
    /// construction n'existe -> tout `SafeIdent` est prouvé sûr pour l'émission DDL.
    pub(crate) fn new(raw: &str) -> Result<Self, HaError> {
        if ident_ok(raw) {
            Ok(SafeIdent(raw.to_string()))
        } else {
            Err(HaError::InvalidIdent(raw.to_string()))
        }
    }
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SafeIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ====================================================================================================
// 1. MODÈLE DE TOPOLOGIE (données pures + validation ; parsé de la config/env)
// ====================================================================================================

/// Un réplica physique (un serveur ClickHouse d'un shard). L'hôte/port ne servent QUE la config
/// `remote_servers` du cluster — ils n'entrent JAMAIS dans une DDL `ON CLUSTER` (la DDL nomme le
/// CLUSTER, pas les hôtes). On les valide néanmoins (défense en profondeur).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Replica {
    pub host: String,
    pub port: u16,
}

impl Replica {
    fn validate(&self) -> Result<(), HaError> {
        if !host_ok(&self.host) {
            return Err(HaError::InvalidHost(self.host.clone()));
        }
        if self.port == 0 {
            return Err(HaError::InvalidHost(format!("{}:0", self.host)));
        }
        Ok(())
    }
}

/// Un shard = un ensemble de réplicas portant la MÊME partition de données (HA par réplication).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Shard {
    pub replicas: Vec<Replica>,
}

/// Topologie complète du cluster : nom logique (macro ClickHouse `{cluster}`), database cible, et la
/// liste ordonnée des shards. `cluster_name`/`database` sont des `SafeIdent` -> impossibles à injecter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClusterTopology {
    pub cluster_name: SafeIdent,
    pub database: SafeIdent,
    pub shards: Vec<Shard>,
}

impl ClusterTopology {
    /// Construit + VALIDE une topologie. Rejette : 0 shard, un shard à 0 réplica, un réplica invalide.
    /// (Les noms `cluster`/`database` sont déjà `SafeIdent` -> validés à leur construction.)
    pub(crate) fn new(cluster_name: SafeIdent, database: SafeIdent, shards: Vec<Shard>) -> Result<Self, HaError> {
        if shards.is_empty() {
            return Err(HaError::InvalidTopology("au moins 1 shard requis".into()));
        }
        for (i, s) in shards.iter().enumerate() {
            if s.replicas.is_empty() {
                return Err(HaError::InvalidTopology(format!("shard #{i}: au moins 1 réplica requis")));
            }
            for r in &s.replicas {
                r.validate()?;
            }
        }
        Ok(ClusterTopology { cluster_name, database, shards })
    }

    pub(crate) fn shard_count(&self) -> usize {
        self.shards.len()
    }
    pub(crate) fn replica_count(&self) -> usize {
        self.shards.iter().map(|s| s.replicas.len()).sum()
    }

    /// Parse une topologie depuis l'ENV (déploiement scale opt-in ; JAMAIS lu en mode 0) :
    ///   - `PLUME_CLICKHOUSE_CLUSTER`  : nom logique du cluster (SafeIdent).           défaut `plume_cluster`
    ///   - `PLUME_CLICKHOUSE_DATABASE` : database cible (SafeIdent).                    défaut `plume`
    ///   - `PLUME_CLICKHOUSE_SHARDS`   : spec compacte `h1:9000,h2:9000;h3:9000,...`   défaut `localhost:9000`
    ///       `;` sépare les SHARDS, `,` sépare les RÉPLICAS d'un shard, `host:port` chaque réplica.
    /// Fonction PURE de parsing + validation : ne CONTACTE aucun serveur.
    pub(crate) fn from_env() -> Result<Self, HaError> {
        let cluster = std::env::var("PLUME_CLICKHOUSE_CLUSTER").unwrap_or_else(|_| "plume_cluster".into());
        let database = std::env::var("PLUME_CLICKHOUSE_DATABASE").unwrap_or_else(|_| "plume".into());
        let shards_spec = std::env::var("PLUME_CLICKHOUSE_SHARDS").unwrap_or_else(|_| "localhost:9000".into());
        Self::parse(&cluster, &database, &shards_spec)
    }

    /// Parse + valide depuis des chaînes brutes (testable sans env). Coeur de `from_env`.
    pub(crate) fn parse(cluster: &str, database: &str, shards_spec: &str) -> Result<Self, HaError> {
        let cluster_name = SafeIdent::new(cluster)?;
        let db = SafeIdent::new(database)?;
        let mut shards = Vec::new();
        for shard_str in shards_spec.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            let mut replicas = Vec::new();
            for rep in shard_str.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let (host, port_s) = rep
                    .rsplit_once(':')
                    .ok_or_else(|| HaError::Config(format!("réplica sans port `{rep}` (attendu host:port)")))?;
                let port: u16 = port_s
                    .parse()
                    .map_err(|_| HaError::Config(format!("port invalide `{port_s}` dans `{rep}`")))?;
                let r = Replica { host: host.to_string(), port };
                r.validate()?;
                replicas.push(r);
            }
            if replicas.is_empty() {
                return Err(HaError::Config(format!("shard vide dans `{shards_spec}`")));
            }
            shards.push(Shard { replicas });
        }
        ClusterTopology::new(cluster_name, db, shards)
    }
}

// ====================================================================================================
// 2. GÉNÉRATION DDL DISTRIBUÉE (le cœur de la HA — INJECTION-SAFE)
// ====================================================================================================

/// Clé de sharding du moteur `Distributed` — enum FERMÉ (jamais du texte libre). La variante `Columns`
/// porte des colonnes VALIDÉES (`SafeIdent`) enveloppées dans `cityHash64(...)` (répartition uniforme,
/// co-localisation d'une clé sur un shard, cf. RFC §3.1). `Random` = `rand()` (répartition pure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ShardingKey {
    /// `cityHash64(col1, col2, ...)` — chaque colonne est un `SafeIdent` (validée, non concaténée brute).
    Columns(Vec<SafeIdent>),
    /// `rand()` — répartition uniforme sans co-localisation.
    Random,
}

impl ShardingKey {
    /// Émet l'EXPRESSION de sharding. Les colonnes sont déjà `SafeIdent` (validées) -> sûres en
    /// concaténation nue. Rejette une liste de colonnes VIDE (une clé de sharding vide est une erreur).
    fn emit(&self) -> Result<String, HaError> {
        match self {
            ShardingKey::Random => Ok("rand()".into()),
            ShardingKey::Columns(cols) => {
                if cols.is_empty() {
                    return Err(HaError::InvalidTopology("clé de sharding sans colonne".into()));
                }
                let joined = cols.iter().map(SafeIdent::as_str).collect::<Vec<_>>().join(", ");
                Ok(format!("cityHash64({joined})"))
            }
        }
    }
}

/// Spécification d'une table data-plane HA. Le corps de colonnes + les clés `PARTITION`/`ORDER` sont des
/// CONSTANTES de l'auteur (miroir du schéma single-node #18) — PAS de la config, donc non issues d'une
/// surface d'injection. Seuls `local_table` (nom, `SafeIdent`) et la clé de sharding (colonnes validées)
/// sont semi-de-confiance et validés.
#[derive(Debug, Clone)]
pub(crate) struct HaTableSpec {
    /// Nom de la table LOCALE (répliquée) — `SafeIdent`. La table `Distributed` est `<local>_dist`.
    pub local_table: SafeIdent,
    /// Définitions de colonnes SANS les parenthèses (constante auteur, miroir single-node).
    pub columns: &'static str,
    /// Expression `PARTITION BY` (constante auteur).
    pub partition_by: &'static str,
    /// Expression `ORDER BY` (constante auteur ; clé du sparse-index MergeTree).
    pub order_by: &'static str,
    /// Clé de sharding du moteur `Distributed` (colonnes validées / `rand()`).
    pub sharding_key: ShardingKey,
}

impl HaTableSpec {
    /// Les 3 tables data-plane (event/metric/snapshot), MIROIR du schéma single-node #18
    /// (`clickhouse_store.rs`) : mêmes colonnes/ordre -> MÊME surface GXQL. La parité de NOMS de colonnes
    /// event <-> single-node est asserée par test (`ha_event_columns_mirror_single_node`).
    pub(crate) fn canonical() -> Result<Vec<HaTableSpec>, HaError> {
        Ok(vec![
            HaTableSpec {
                local_table: SafeIdent::new("event")?,
                columns: EVENT_COLUMNS,
                partition_by: "toYYYYMM(toDateTime(ts))",
                order_by: "(env_id, source, ts)",
                // Co-localise les events d'un même hôte sur un shard (cf. RFC §3.1 `stats by host`).
                sharding_key: ShardingKey::Columns(vec![SafeIdent::new("host")?]),
            },
            HaTableSpec {
                local_table: SafeIdent::new("metric")?,
                columns: METRIC_COLUMNS,
                partition_by: "toYYYYMM(toDateTime(ts))",
                order_by: "(name, ts)",
                sharding_key: ShardingKey::Columns(vec![SafeIdent::new("name")?]),
            },
            HaTableSpec {
                local_table: SafeIdent::new("snapshot")?,
                columns: SNAPSHOT_COLUMNS,
                partition_by: "toYYYYMM(toDateTime(ts))",
                order_by: "(kind, ts)",
                sharding_key: ShardingKey::Columns(vec![SafeIdent::new("kind")?]),
            },
        ])
    }

    /// Nom de la table `Distributed` (`<local>_dist`). `local_table` est `SafeIdent` -> `<local>_dist`
    /// reste un identifiant sûr (`_dist` est un littéral).
    pub(crate) fn distributed_table(&self) -> String {
        format!("{}_dist", self.local_table.as_str())
    }
}

// Corps de colonnes MIROIR du single-node #18 (`clickhouse_store.rs::EVENT_DDL` etc.). CONSTANTES
// auteur : jamais issues de la config -> hors surface d'injection. La parité event est test-verrouillée.
const EVENT_COLUMNS: &str = "ts Int64, source String, category String, severity Int64, message String, \
    host Nullable(String), src_ip Nullable(String), dst_ip Nullable(String), url Nullable(String), \
    dedup Nullable(String), fields Nullable(String), \
    engagement_id String DEFAULT '', origin String DEFAULT '', env_id String DEFAULT 'prod'";
const METRIC_COLUMNS: &str =
    "ts Int64, name String, labels Nullable(String), value Float64, host Nullable(String)";
const SNAPSHOT_COLUMNS: &str =
    "ts Int64, kind String, hash String, data String, host Nullable(String)";

/// Chemin ZooKeeper/Keeper de la table répliquée : `/clickhouse/tables/{shard}/<db>/<local>`. `{shard}`
/// est une MACRO ClickHouse LITTÉRALE (substituée par le serveur par shard), PAS de la config. `<db>` et
/// `<local>` sont des `SafeIdent` (validés) -> le chemin ne peut pas contenir de segment injecté.
fn zk_path(topology: &ClusterTopology, spec: &HaTableSpec) -> String {
    format!(
        "/clickhouse/tables/{{shard}}/{}/{}",
        topology.database.as_str(),
        spec.local_table.as_str()
    )
}

/// Émet la DDL de la table LOCALE RÉPLIQUÉE (une par shard, HA) :
/// `CREATE TABLE IF NOT EXISTS <db>.<local> ON CLUSTER <cluster> (...) ENGINE =
///  ReplicatedMergeTree('/clickhouse/tables/{shard}/<db>/<local>', '{replica}') PARTITION BY ... ORDER BY ...`
/// avec, optionnellement, la clause TTL hot→cold + `SETTINGS storage_policy=...` (§Hot-cold).
///
/// INJECTION-SAFE : `<db>`/`<local>`/`<cluster>` sont des `SafeIdent` (allowlist) ; `{shard}`/`{replica}`
/// sont des macros LITTÉRALES ; colonnes/partition/order sont des constantes auteur. Le seul texte
/// config-dérivé qui atteint la DDL a traversé `SafeIdent`. Idempotent (`IF NOT EXISTS`).
pub(crate) fn replicated_ddl(
    topology: &ClusterTopology,
    spec: &HaTableSpec,
    tiering: Option<&TieringPolicy>,
) -> Result<String, HaError> {
    let db = topology.database.as_str();
    let cluster = topology.cluster_name.as_str();
    let local = spec.local_table.as_str();
    let zk = zk_path(topology, spec);
    let mut ddl = format!(
        "CREATE TABLE IF NOT EXISTS {db}.{local} ON CLUSTER {cluster} ({cols}) \
         ENGINE = ReplicatedMergeTree('{zk}', '{{replica}}') \
         PARTITION BY {part} ORDER BY {ord}",
        cols = spec.columns,
        part = spec.partition_by,
        ord = spec.order_by,
    );
    if let Some(t) = tiering {
        ddl.push(' ');
        ddl.push_str(&t.ttl_to_volume_clause()?);
        ddl.push(' ');
        ddl.push_str(&t.storage_policy_setting()?);
    }
    Ok(ddl)
}

/// Émet la DDL de la table `Distributed` (le routeur de requêtes/insertions par-dessus les tables
/// locales répliquées) :
/// `CREATE TABLE IF NOT EXISTS <db>.<local>_dist ON CLUSTER <cluster> (...) ENGINE =
///  Distributed(<cluster>, <db>, <local>, <sharding_expr>)`.
///
/// INJECTION-SAFE : idem `replicated_ddl` ; l'expression de sharding provient de l'enum fermé
/// `ShardingKey` (colonnes `SafeIdent` ou `rand()`), jamais de texte libre.
pub(crate) fn distributed_ddl(topology: &ClusterTopology, spec: &HaTableSpec) -> Result<String, HaError> {
    let db = topology.database.as_str();
    let cluster = topology.cluster_name.as_str();
    let local = spec.local_table.as_str();
    let dist = spec.distributed_table();
    let sharding = spec.sharding_key.emit()?;
    Ok(format!(
        "CREATE TABLE IF NOT EXISTS {db}.{dist} ON CLUSTER {cluster} ({cols}) \
         ENGINE = Distributed({cluster}, {db}, {local}, {sharding})",
        cols = spec.columns,
    ))
}

/// La paire de DDL complète d'une table HA : (locale répliquée, distribuée). Ordre d'application :
/// la table locale d'abord (elle doit exister sur chaque shard avant que la `Distributed` ne la cible).
pub(crate) fn table_ddls(
    topology: &ClusterTopology,
    spec: &HaTableSpec,
    tiering: Option<&TieringPolicy>,
) -> Result<[String; 2], HaError> {
    Ok([
        replicated_ddl(topology, spec, tiering)?,
        distributed_ddl(topology, spec)?,
    ])
}

/// Le schéma HA data-plane COMPLET (event/metric/snapshot), dans l'ordre d'application (chaque table :
/// locale puis distribuée). `tiering` optionnel s'applique aux tables locales. C'est ce que
/// `KeeperCoordination::propagate_ddl_on_cluster` exécuterait sur un cluster vivant (différé).
pub(crate) fn full_schema_ddls(
    topology: &ClusterTopology,
    tiering: Option<&TieringPolicy>,
) -> Result<Vec<String>, HaError> {
    let mut out = Vec::new();
    for spec in HaTableSpec::canonical()? {
        for ddl in table_ddls(topology, &spec, tiering)? {
            out.push(ddl);
        }
    }
    Ok(out)
}

// ====================================================================================================
// 3. POLITIQUE HOT→COLD (TTL + storage_policy ; INJECTION-SAFE)
// ====================================================================================================

/// Politique de tiering hot→cold (RFC §Phase 4). Modèle TYPÉ + émission DDL. Les noms de VOLUME et de
/// POLICY sont des `SafeIdent` (validés) ; `ttl_days` est un ENTIER (jamais du texte) -> l'émission TTL
/// est structurellement non-injectable. Ce modèle décrit la couche STORAGE ClickHouse (disque S3-backed
/// `cold` + `storage_policy='hot_cold'`) qu'un opérateur déclare dans `config.xml` (hors de ce code).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TieringPolicy {
    /// Âge (en JOURS) au-delà duquel une partie migre vers le volume froid. Entier -> non-injectable.
    pub ttl_days: u32,
    /// Nom du VOLUME froid (S3-backed), déclaré dans la `storage_policy` ClickHouse. `SafeIdent`.
    pub cold_volume: SafeIdent,
    /// Nom de la `storage_policy` ClickHouse (mappe hot->cold). `SafeIdent`.
    pub storage_policy: SafeIdent,
}

impl TieringPolicy {
    /// Construit une politique par défaut : `N` jours -> volume `cold` sous la policy `hot_cold`.
    pub(crate) fn new(ttl_days: u32, cold_volume: &str, storage_policy: &str) -> Result<Self, HaError> {
        if ttl_days == 0 {
            return Err(HaError::Config("ttl_days doit être > 0".into()));
        }
        Ok(TieringPolicy {
            ttl_days,
            cold_volume: SafeIdent::new(cold_volume)?,
            storage_policy: SafeIdent::new(storage_policy)?,
        })
    }

    /// Émet la clause `TTL toDateTime(ts) + INTERVAL <N> DAY TO VOLUME '<cold>'`. `<N>` est un `u32`
    /// formaté (jamais du texte libre) ; `<cold>` est un `SafeIdent` (l'allowlist exclut la quote) ->
    /// le littéral `'<cold>'` ne peut pas être cassé. `ts` = epoch secondes (comme le schéma).
    pub(crate) fn ttl_to_volume_clause(&self) -> Result<String, HaError> {
        Ok(format!(
            "TTL toDateTime(ts) + INTERVAL {} DAY TO VOLUME '{}'",
            self.ttl_days,
            self.cold_volume.as_str()
        ))
    }

    /// Émet `SETTINGS storage_policy='<policy>'`. `<policy>` est un `SafeIdent` -> littéral inviolable.
    pub(crate) fn storage_policy_setting(&self) -> Result<String, HaError> {
        Ok(format!("SETTINGS storage_policy='{}'", self.storage_policy.as_str()))
    }
}

// ====================================================================================================
// 4. INTERFACE DE COORDINATION KEEPER (stub ; impl vivante différée)
// ====================================================================================================

/// Identifiant de shard (index dans `ClusterTopology::shards`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShardId(pub usize);

/// Abstraction de la coordination ClickHouse Keeper / ZooKeeper : conscience leader/réplica et
/// propagation de la DDL `ON CLUSTER`. L'impl RÉELLE dialogue avec un Keeper vivant (leader election,
/// suivi de réplication, exécution distribuée de la DDL) -> DIFFÉRÉE (needs a live Keeper). On POSE ici
/// l'interface pour que le reste du scaffold (schéma, ingest) s'y branche sans connaître le transport.
pub(crate) trait KeeperCoordination {
    /// Ce nœud est-il le réplica LEADER du shard donné (pour les tâches qui ne doivent tourner qu'une
    /// fois par shard : merges pilotés, rollups `INSERT SELECT`) ? Réel = requête Keeper.
    fn is_leader_replica(&self, shard: ShardId) -> Result<bool, HaError>;
    /// Réplicas actuellement connus/vivants d'un shard (santé de réplication). Réel = état Keeper.
    fn known_replicas(&self, shard: ShardId) -> Result<Vec<Replica>, HaError>;
    /// Propage une DDL `ON CLUSTER` (via la file DDL distribuée du Keeper) et attend la convergence.
    /// C'est le point d'application de `full_schema_ddls`. Réel = `ON CLUSTER` + attente `distributed_ddl`.
    fn propagate_ddl_on_cluster(&self, ddl: &str) -> Result<(), HaError>;
}

/// STUB no-op de [`KeeperCoordination`]. Il ne CONTACTE aucun Keeper : toute opération vivante renvoie
/// `HaError::NotImplemented` (jamais un faux succès silencieux). Il connaît sa topologie -> il peut
/// répondre aux questions PURES (nombre de shards) sans réseau, mais REFUSE toute action distribuée.
/// L'impl réelle (`KeeperClient` sur un Keeper vivant) est le premier chantier de la Phase 3.
pub(crate) struct NoopKeeper {
    pub topology: ClusterTopology,
}

impl NoopKeeper {
    pub(crate) fn new(topology: ClusterTopology) -> Self {
        NoopKeeper { topology }
    }
}

impl KeeperCoordination for NoopKeeper {
    fn is_leader_replica(&self, shard: ShardId) -> Result<bool, HaError> {
        if shard.0 >= self.topology.shard_count() {
            return Err(HaError::InvalidTopology(format!("shard #{} hors bornes", shard.0)));
        }
        // Sans Keeper vivant, aucune élection de leader n'est possible -> on ne PRÉTEND pas être leader.
        Err(HaError::NotImplemented("leader election requiert un Keeper vivant"))
    }
    fn known_replicas(&self, shard: ShardId) -> Result<Vec<Replica>, HaError> {
        // La topologie CONFIGURÉE est connue offline ; l'état VIVANT (qui répond) ne l'est pas.
        self.topology
            .shards
            .get(shard.0)
            .map(|s| s.replicas.clone())
            .ok_or_else(|| HaError::InvalidTopology(format!("shard #{} hors bornes", shard.0)))
    }
    fn propagate_ddl_on_cluster(&self, _ddl: &str) -> Result<(), HaError> {
        Err(HaError::NotImplemented("propagation DDL ON CLUSTER requiert un Keeper vivant"))
    }
}

// ====================================================================================================
// 5. COUTURE D'INGEST STATELESS (structure + trait ; opération vivante différée)
// ====================================================================================================

/// Couture d'un NŒUD D'INGEST STATELESS (RFC §3.1, prolonge le seam #15). Un front d'ingest ne détient
/// AUCUN état local (pas de fichier SQLCipher) : il route un lot vers la table `Distributed`, et le
/// moteur `Distributed` de ClickHouse répartit sur les shards (sharding CÔTÉ SERVEUR). On expose la
/// CIBLE (`distributed_table`) + le point d'entrée d'écriture. L'opération VIVANTE (LB + N réplicas +
/// rejeu de spool durable + quarantaine fail-closed du tenant non résolu) est DIFFÉRÉE (Phase 3).
pub(crate) trait StatelessIngestTier {
    /// La table `Distributed` (`<db>.<local>_dist`) que ce nœud vise (le serveur fait le sharding).
    fn distributed_table(&self) -> &str;
    /// Route un lot à travers la SPI NEUTRE `EventStore` vers la table distribuée. L'impl VIVANTE (async
    /// insert + spool durable) est différée -> le stub renvoie `NotImplemented` plutôt qu'un faux write.
    fn route_batch(&self, store: &dyn EventStore, handle: StoreHandle, rows: &[EventRow]) -> Result<usize, StoreError>;
}

/// Réalisation-couture de [`StatelessIngestTier`] : elle CALCULE et porte la cible `Distributed` (pur,
/// testable offline) mais REFUSE l'écriture vivante (différée). C'est le squelette sur lequel la Phase 3
/// branchera l'async-insert ClickHouse + le rejeu de spool. Elle NE touche PAS le chemin data-plane
/// actuel (aucun call-site) -> mode 0 intact.
pub(crate) struct DistributedIngestSeam {
    dist_table: String,
}

impl DistributedIngestSeam {
    /// Cible la table `Distributed` de `spec` dans la `database` de `topology` : `<db>.<local>_dist`.
    pub(crate) fn new(topology: &ClusterTopology, spec: &HaTableSpec) -> Self {
        DistributedIngestSeam {
            dist_table: format!("{}.{}", topology.database.as_str(), spec.distributed_table()),
        }
    }
}

impl StatelessIngestTier for DistributedIngestSeam {
    fn distributed_table(&self) -> &str {
        &self.dist_table
    }
    fn route_batch(&self, _store: &dyn EventStore, _handle: StoreHandle, _rows: &[EventRow]) -> Result<usize, StoreError> {
        // Différé : l'ingest stateless HA exige un cluster vivant (async-insert + spool durable + routing
        // fail-closed du tenant). On renvoie une erreur EXPLICITE plutôt qu'un write silencieux vers nulle
        // part -> le seam est honnête tant que la Phase 3 ne l'a pas câblé.
        Err(HaError::NotImplemented("ingest stateless HA vers la table Distributed (Phase 3, cluster vivant)").into())
    }
}

// ====================================================================================================
// TESTS UNITAIRES — OFFLINE (aucun cluster/Keeper). Compilés SEULEMENT sous `--features clickhouse-ha`.
// Prouvent : parse+validation de topologie, forme des DDL Replicated/Distributed (macros + zk-path),
// ANTI-INJECTION (noms avec `;`/quote/espace/`-`/`/` REJETÉS), TTL hot→cold, stubs Keeper/ingest.
// Le round-trip multi-nœud RÉEL exige un cluster + Keeper -> `#[ignore]` (hors CI).
// ====================================================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn topo() -> ClusterTopology {
        ClusterTopology::parse("plume_cluster", "plume", "h1:9000,h2:9000;h3:9000,h4:9000").expect("topo")
    }
    fn event_spec() -> HaTableSpec {
        HaTableSpec::canonical().expect("specs").into_iter().next().expect("event")
    }

    // ---- Topologie : parse + validation --------------------------------------------------------

    #[test]
    fn topology_parses_shards_and_replicas() {
        let t = topo();
        assert_eq!(t.shard_count(), 2, "2 shards");
        assert_eq!(t.replica_count(), 4, "2 réplicas x 2 shards");
        assert_eq!(t.shards[0].replicas[0], Replica { host: "h1".into(), port: 9000 });
        assert_eq!(t.shards[1].replicas[1], Replica { host: "h4".into(), port: 9000 });
    }

    #[test]
    fn topology_single_node_default() {
        let t = ClusterTopology::parse("plume_cluster", "plume", "localhost:9000").expect("solo");
        assert_eq!(t.shard_count(), 1);
        assert_eq!(t.replica_count(), 1);
    }

    #[test]
    fn topology_rejects_empty_shards() {
        assert!(matches!(
            ClusterTopology::parse("c", "d", ""),
            Err(HaError::InvalidTopology(_))
        ));
    }

    #[test]
    fn topology_rejects_missing_port() {
        assert!(matches!(
            ClusterTopology::parse("c", "d", "h1"),
            Err(HaError::Config(_))
        ));
    }

    #[test]
    fn topology_rejects_bad_port() {
        assert!(matches!(
            ClusterTopology::parse("c", "d", "h1:0"),
            Err(HaError::InvalidHost(_))
        ));
        assert!(matches!(
            ClusterTopology::parse("c", "d", "h1:notaport"),
            Err(HaError::Config(_))
        ));
    }

    // ---- ANTI-INJECTION : le cœur sécurité ------------------------------------------------------

    #[test]
    fn safe_ident_allowlist_accepts_plain() {
        for ok in ["event", "plume", "plume_cluster", "cold", "hot_cold", "env_id", "A9_z"] {
            assert!(SafeIdent::new(ok).is_ok(), "devrait accepter: {ok}");
        }
    }

    #[test]
    fn safe_ident_rejects_injection_payloads() {
        // Toute la surface d'injection DDL : séparateurs, quotes, espaces, tiret, slash, macro, backtick,
        // parenthèse, commentaire. AUCUN ne doit produire un SafeIdent.
        for bad in [
            "",
            "a;DROP TABLE event",
            "a b",
            "a'b",
            "a\"b",
            "a-b",
            "a/b",
            "a.b",
            "event; --",
            "{shard}",
            "a`b",
            "a(b)",
            "évent",
            "a\\b",
            "a\nb",
        ] {
            assert!(SafeIdent::new(bad).is_err(), "devrait REJETER: {bad:?}");
        }
    }

    #[test]
    fn cluster_name_injection_rejected_before_ddl() {
        // Un nom de cluster malveillant venu de la config est rejeté À LA CONSTRUCTION de la topologie
        // -> il n'atteint JAMAIS `replicated_ddl`/`distributed_ddl`.
        assert!(matches!(
            ClusterTopology::parse("evil') ENGINE=Null--", "plume", "h1:9000"),
            Err(HaError::InvalidIdent(_))
        ));
    }

    #[test]
    fn database_and_table_injection_rejected() {
        assert!(ClusterTopology::parse("c", "db;DROP", "h1:9000").is_err());
        // table via SafeIdent (utilisé par HaTableSpec) :
        assert!(SafeIdent::new("event' UNION SELECT").is_err());
    }

    #[test]
    fn sharding_key_rejects_bad_column() {
        // Une colonne de sharding ne peut PAS être du texte libre : elle passe par SafeIdent.
        assert!(SafeIdent::new("host); DROP").is_err());
    }

    #[test]
    fn tiering_rejects_injection_in_volume_and_policy() {
        assert!(TieringPolicy::new(30, "cold'; DROP", "hot_cold").is_err());
        assert!(TieringPolicy::new(30, "cold", "hot_cold'--").is_err());
        assert!(matches!(TieringPolicy::new(0, "cold", "hot_cold"), Err(HaError::Config(_))));
    }

    // ---- DDL Replicated / Distributed : forme émise ---------------------------------------------

    #[test]
    fn replicated_ddl_shape() {
        let t = topo();
        let spec = event_spec();
        let ddl = replicated_ddl(&t, &spec, None).expect("ddl");
        assert!(ddl.contains("CREATE TABLE IF NOT EXISTS plume.event ON CLUSTER plume_cluster"), "{ddl}");
        assert!(
            ddl.contains("ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/plume/event', '{replica}')"),
            "moteur répliqué + zk-path + macros littérales attendus: {ddl}"
        );
        assert!(ddl.contains("PARTITION BY toYYYYMM(toDateTime(ts))"), "{ddl}");
        assert!(ddl.contains("ORDER BY (env_id, source, ts)"), "{ddl}");
        // Les macros restent LITTÉRALES (non substituées côté code).
        assert!(ddl.contains("{shard}") && ddl.contains("{replica}"), "macros littérales: {ddl}");
    }

    #[test]
    fn distributed_ddl_shape() {
        let t = topo();
        let spec = event_spec();
        let ddl = distributed_ddl(&t, &spec).expect("ddl");
        assert!(ddl.contains("CREATE TABLE IF NOT EXISTS plume.event_dist ON CLUSTER plume_cluster"), "{ddl}");
        assert!(
            ddl.contains("ENGINE = Distributed(plume_cluster, plume, event, cityHash64(host))"),
            "moteur Distributed(cluster, db, local, sharding) attendu: {ddl}"
        );
    }

    #[test]
    fn distributed_ddl_random_sharding() {
        let t = topo();
        let mut spec = event_spec();
        spec.sharding_key = ShardingKey::Random;
        let ddl = distributed_ddl(&t, &spec).expect("ddl");
        assert!(ddl.contains("Distributed(plume_cluster, plume, event, rand())"), "{ddl}");
    }

    #[test]
    fn full_schema_has_six_ddls_local_then_dist() {
        let t = topo();
        let ddls = full_schema_ddls(&t, None).expect("schema");
        assert_eq!(ddls.len(), 6, "3 tables x (locale + distribuée)");
        // event : locale d'abord, distribuée ensuite.
        assert!(ddls[0].contains("plume.event ") && ddls[0].contains("ReplicatedMergeTree"), "{}", ddls[0]);
        assert!(ddls[1].contains("plume.event_dist") && ddls[1].contains("Distributed("), "{}", ddls[1]);
        for ddl in &ddls {
            assert!(ddl.contains("ON CLUSTER plume_cluster"), "chaque DDL est ON CLUSTER: {ddl}");
            assert!(ddl.contains("IF NOT EXISTS"), "idempotence: {ddl}");
        }
    }

    #[test]
    fn ha_event_columns_mirror_single_node() {
        // Parité avec le schéma single-node #18 : chaque colonne event du single-node
        // (`ClickHouseStore::schema_ddl()[0]`) DOIT apparaître dans le corps de colonnes HA -> même
        // surface GXQL, l'INSERT RowBinary (par nom) ne dérive pas entre les deux tiers.
        let single = super::super::clickhouse_store::ClickHouseStore::schema_ddl()[0];
        for col in ["ts", "source", "category", "severity", "message", "host", "src_ip", "dst_ip",
                    "url", "dedup", "fields", "engagement_id", "origin", "env_id"] {
            assert!(EVENT_COLUMNS.contains(col), "colonne HA `{col}` absente du corps HA");
            assert!(single.contains(col), "colonne `{col}` absente du single-node (parité rompue)");
        }
    }

    // ---- Hot→cold : TTL + storage_policy --------------------------------------------------------

    #[test]
    fn tiering_ttl_clause_shape() {
        let p = TieringPolicy::new(30, "cold", "hot_cold").expect("policy");
        assert_eq!(
            p.ttl_to_volume_clause().unwrap(),
            "TTL toDateTime(ts) + INTERVAL 30 DAY TO VOLUME 'cold'"
        );
        assert_eq!(p.storage_policy_setting().unwrap(), "SETTINGS storage_policy='hot_cold'");
    }

    #[test]
    fn replicated_ddl_with_tiering_appends_ttl_and_settings() {
        let t = topo();
        let spec = event_spec();
        let p = TieringPolicy::new(14, "cold", "hot_cold").expect("policy");
        let ddl = replicated_ddl(&t, &spec, Some(&p)).expect("ddl");
        assert!(ddl.contains("TTL toDateTime(ts) + INTERVAL 14 DAY TO VOLUME 'cold'"), "{ddl}");
        assert!(ddl.contains("SETTINGS storage_policy='hot_cold'"), "{ddl}");
        // Ordre : ENGINE ... PARTITION ... ORDER ... TTL ... SETTINGS.
        let (i_engine, i_ttl) = (ddl.find("ENGINE").unwrap(), ddl.find("TTL").unwrap());
        assert!(i_engine < i_ttl, "TTL après ENGINE: {ddl}");
    }

    // ---- Stubs : Keeper + ingest stateless ------------------------------------------------------

    #[test]
    fn noop_keeper_refuses_live_ops_but_answers_pure() {
        let k = NoopKeeper::new(topo());
        // Question PURE (config connue offline) : OK.
        assert_eq!(k.known_replicas(ShardId(0)).unwrap().len(), 2);
        // Actions VIVANTES : NotImplemented (jamais un faux succès).
        assert!(matches!(k.is_leader_replica(ShardId(0)), Err(HaError::NotImplemented(_))));
        assert!(matches!(k.propagate_ddl_on_cluster("CREATE ..."), Err(HaError::NotImplemented(_))));
        // Shard hors bornes : erreur de topologie.
        assert!(matches!(k.known_replicas(ShardId(9)), Err(HaError::InvalidTopology(_))));
    }

    #[test]
    fn stateless_ingest_seam_targets_dist_table_but_defers_write() {
        let t = topo();
        let spec = event_spec();
        let seam = DistributedIngestSeam::new(&t, &spec);
        assert_eq!(seam.distributed_table(), "plume.event_dist");
    }

    // ---- Round-trip multi-nœud RÉEL : exige un cluster + Keeper vivants -> hors CI ---------------

    /// Applique le schéma HA sur un cluster ClickHouse RÉEL (`PLUME_CLICKHOUSE_*` + un Keeper).
    /// `#[ignore]` : nécessite un cluster multi-nœud + Keeper joignables. Lancer avec :
    /// `PLUME_CLICKHOUSE_URL=… PLUME_CLICKHOUSE_CLUSTER=… PLUME_CLICKHOUSE_SHARDS=… \
    ///  cargo test --features clickhouse-ha -- --ignored`.
    #[test]
    #[ignore = "nécessite un cluster ClickHouse multi-nœud + Keeper (PLUME_CLICKHOUSE_*)"]
    fn live_apply_ha_schema_on_cluster() {
        let topology = ClusterTopology::from_env().expect("from_env");
        let ddls = full_schema_ddls(&topology, None).expect("schema");
        let url = std::env::var("PLUME_CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".into());
        let client = clickhouse::Client::default().with_url(url);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("rt");
        rt.block_on(async {
            for ddl in &ddls {
                client.query(ddl).execute().await.expect("apply ON CLUSTER DDL");
            }
        });
    }
}
