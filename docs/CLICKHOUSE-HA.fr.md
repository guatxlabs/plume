# ClickHouse HA — échafaudage distribué multi-nœud (#70)

[English](CLICKHOUSE-HA.md) | [Français](CLICKHOUSE-HA.fr.md)

Statut : **ÉCHAFAUDAGE / FONDATIONS SEULEMENT — INERTE, NON ACTIVÉ.** Cloisonné par une sous-feature
dédiée, `clickhouse-ha` (qui active `clickhouse`). Absent du build par défaut **et** du build
`--features clickhouse` (#18 mono-nœud). Il ne porte **aucun chemin d'exécution** — rien dans le plan de
données ne l'appelle (aucun site d'appel n'est câblé). **Le défaut reste `SqlcipherStore` (SQLite/SQLCipher),
byte-identique à aujourd'hui.**

Ce document prolonge [`CLICKHOUSE-STORE.md`](./CLICKHOUSE-STORE.fr.md) (l'adaptateur mono-nœud, #18,
Phase 2) vers le **tier distribué HA multi-nœud** que celui-ci désignait comme roadmap future. Il transforme
la RFC de conception (§3/§4, Phases 3–4) en **fondations** typées et testées hors ligne pour un chantier de
plusieurs trimestres — pas en un store distribué en service. Il se construit **sur** l'adaptateur
mono-nœud, il ne le réécrit pas.

---

## 1. Ce que c'est (et ce que ce n'est pas)

| | Mono-nœud (#18, **construit**) | Échafaudage HA (#70, **ce document — fondations, inerte**) | HA en service (Phase 3, **non construit**) |
|---|---|---|---|
| Topologie | un serveur (`Client`) | `ClusterTopology` typée (shards × réplicas), analysée+validée | cluster en service + Keeper |
| Moteur | `MergeTree` | **génération de DDL** pour `ReplicatedMergeTree` + `Distributed` | tables créées sur le cluster |
| Coordination | s.o. | `trait KeeperCoordination` + bouchon `NoopKeeper` | client Keeper en service |
| Ingestion | le démon écrit des lots | point d'extension `trait StatelessIngestTier` (cible = `_dist`) | N réplicas sans état + rejeu du spool |
| Chaud→froid | s.o. | `TieringPolicy` + génération de DDL TTL/`storage_policy` | volume froid adossé à S3 en service |
| Exécution | `PLUME_STORE=clickhouse` (différé) | **câblé à aucun chemin d'exécution** | aiguillage + chemin de lecture asynchrone |

L'échafaudage prouve les **formes** — modèle de topologie, génération de DDL sûre face à l'injection,
points d'extension de coordination / d'ingestion / d'étagement — hors ligne, avant qu'on y ajoute les modes
de défaillance d'un cluster en service. C'est le jalon qui pose les fondations, pas le plafond de montée en
charge. Tout ici est **additif et byte-identique en mode 0** : le module ne compile **que** sous
`--features clickhouse-ha`, rien ne le sélectionne à l'exécution, et le déploiement PME/prod n'est pas
touché.

Module : `daemon/src/ingest/clickhouse_ha.rs` (un seul module cohérent ; le `clickhouse_store.rs`
mono-nœud reste lisible et inchangé).

---

## 2. Modèle de topologie du cluster

`ClusterTopology { cluster_name: SafeIdent, database: SafeIdent, shards: Vec<Shard{ replicas:
Vec<Replica{host,port}> }> }` — **données pures + validation**, analysées depuis la config/l'environnement,
sans rien contacter.

Analysée depuis l'environnement sur un déploiement à l'échelle (jamais lue en mode 0) :

```bash
export PLUME_CLICKHOUSE_CLUSTER=plume_cluster                 # nom logique du cluster (SafeIdent)
export PLUME_CLICKHOUSE_DATABASE=plume                        # base cible (SafeIdent)
export PLUME_CLICKHOUSE_SHARDS="h1:9000,h2:9000;h3:9000,h4:9000"
#   ';' sépare les SHARDS, ',' sépare les RÉPLICAS d'un shard, chaque réplica est host:port
```

`ClusterTopology::from_env()` / `::parse(cluster, database, shards_spec)` valident durement : ≥1 shard,
chaque shard ≥1 réplica, chaque hôte de réplica dans la liste d'autorisation des hôtes (`[A-Za-z0-9._-]`) et
port ≠ 0. Les noms de cluster et de base sont des `SafeIdent` (voir §4) — **une charge d'injection en guise
de nom de cluster/de base est refusée à la construction de la topologie, avant de pouvoir atteindre le
moindre DDL.**

`Replica{host,port}` n'alimente que la config ClickHouse `remote_servers` (déclarée par l'exploitant dans
`config.xml`, hors du périmètre de ce code). Les hôtes n'entrent **jamais** dans un DDL — une instruction
`ON CLUSTER` nomme le **cluster**, pas les hôtes.

---

## 3. DDL distribué : `Distributed` au-dessus de `ReplicatedMergeTree`

Le cœur de la HA. Pour chaque table du plan de données (`event`/`metric`/`snapshot`, reflet du schéma
mono-nœud #18), l'échafaudage émet **deux** DDL, dans l'ordre d'application :

1. **Table locale répliquée** (une table physique par shard, HA par réplication) :

   ```sql
   CREATE TABLE IF NOT EXISTS plume.event ON CLUSTER plume_cluster (
     ts Int64, source String, category String, severity Int64, message String,
     host Nullable(String), src_ip Nullable(String), dst_ip Nullable(String), url Nullable(String),
     dedup Nullable(String), fields Nullable(String),
     engagement_id String DEFAULT '', origin String DEFAULT '', env_id String DEFAULT 'prod'
   ) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/plume/event', '{replica}')
   PARTITION BY toYYYYMM(toDateTime(ts)) ORDER BY (env_id, source, ts)
   ```

2. **Table distribuée** (le routeur de requêtes/d'insertions au-dessus des shards locaux) :

   ```sql
   CREATE TABLE IF NOT EXISTS plume.event_dist ON CLUSTER plume_cluster ( …same columns… )
   ENGINE = Distributed(plume_cluster, plume, event, cityHash64(host))
   ```

- `{shard}` / `{replica}` sont des **macros ClickHouse littérales** (substituées côté serveur, par réplica,
  depuis `<macros>` dans `config.xml`) — ce **n'est pas** de la config, elles restent littérales dans la
  chaîne émise.
- Le **chemin ZooKeeper/Keeper** `/clickhouse/tables/{shard}/<db>/<local>` se construit à partir des noms
  validés `database` et `local_table` plus la macro littérale `{shard}` — aucun segment injecté n'est
  possible.
- La **clé de sharding** est une énumération fermée `ShardingKey` — `Columns(Vec<SafeIdent>)` →
  `cityHash64(col, …)` ou `Random` → `rand()`. C'est une **colonne validée, jamais du texte libre.** La
  spécification canonique de `event` répartit sur `cityHash64(host)` (regrouper les données d'un hôte pour
  que `stats by host` reste surtout local au shard, RFC §3.1) ; `metric` sur `name`, `snapshot` sur `kind`.
- Colonnes, `PARTITION BY`, `ORDER BY` sont des **constantes d'auteur** (reflet du mono-nœud #18) — pas de
  la config, donc pas une surface d'injection. Un test (`ha_event_columns_mirror_single_node`) verrouille
  l'ensemble des colonnes d'événement sur `ClickHouseStore::schema_ddl()` pour que les deux tiers ne puissent
  pas dériver (l'insertion `RowBinary` vise les colonnes par leur nom — même surface GXQL d'un tier à
  l'autre).

`full_schema_ddls(topology, tiering)` rend les six instructions (3 tables × {local, distributed}) dans
l'ordre d'application (local avant distribué — le moteur `Distributed` référence une table qui doit déjà
exister sur chaque shard). C'est exactement ce que `KeeperCoordination::propagate_ddl_on_cluster`
exécuterait sur un cluster en service (différé).

### 3.1 Sûreté face à l'injection — la cible de la revue

Le DDL est **construit à partir de noms de config** (cluster, base, table, colonne de sharding, volume
froid, politique de stockage). Ces noms sont **semi-fiables** et validés **durement** :

- **`SafeIdent`** est un newtype dont le **seul** constructeur valide contre une liste d'autorisation
  stricte `[A-Za-z0-9_]`, non vide, ≤64 caractères (`ident_ok`, reflet du `soql_ident_ok` privé du core).
  Il n'existe **aucun autre moyen** d'obtenir un `SafeIdent` — tout nom qui atteint une chaîne de DDL est
  donc **prouvé** exempt de métacaractère SQL (`;`, guillemets, espaces, `-`, `/`, `.`, `{`/`}`, accents
  graves, parenthèses, commentaires sont tous refusés). Les noms sont donc sûrs en concaténation **nue**
  (aucune mise entre guillemets n'est nécessaire puisque la classe des métacaractères est vide).
- **Aucune chaîne de config brute n'est jamais concaténée dans un DDL.** Cluster/base passent par
  `SafeIdent` à la construction de la topologie ; noms de table et colonnes de sharding par `SafeIdent` ;
  volume/politique par `SafeIdent` ; le nombre de jours du TTL est un `u32` (jamais du texte). Les macros
  `{shard}`/`{replica}` sont des littéraux.
- **Refus sur invalide, fail-closed.** Chaque constructeur rend `Result<_, HaError::InvalidIdent|…>` ; un
  nom invalide ne se dégrade jamais en DDL « au mieux » — il échoue.

Les tests anti-injection affirment qu'un nom de cluster/base/table/volume/politique/colonne contenant `;`,
des guillemets, des espaces, `-`, `/`, `.`, des accolades de macro, des accents graves, des parenthèses ou un
commentaire est **refusé** avant qu'aucun DDL ne soit émis (`safe_ident_rejects_injection_payloads`,
`cluster_name_injection_rejected_before_ddl`, `database_and_table_injection_rejected`,
`tiering_rejects_injection_in_volume_and_policy`).

---

## 4. Interface de coordination Keeper (bouchon)

`trait KeeperCoordination` abstrait ClickHouse Keeper / ZooKeeper : connaissance du leader et des réplicas,
et propagation des DDL `ON CLUSTER`.

```rust
trait KeeperCoordination {
    fn is_leader_replica(&self, shard: ShardId) -> Result<bool, HaError>;   // tâches une fois par shard
    fn known_replicas(&self, shard: ShardId) -> Result<Vec<Replica>, HaError>;
    fn propagate_ddl_on_cluster(&self, ddl: &str) -> Result<(), HaError>;   // applique full_schema_ddls
}
```

`NoopKeeper` est le **bouchon** livré : il répond à la question **pure** (`known_replicas` = la topologie
*configurée*, connue hors ligne) mais **refuse toute opération en service** — `is_leader_replica` et
`propagate_ddl_on_cluster` rendent `HaError::NotImplemented` plutôt qu'un faux succès silencieux.
**Implémentation réelle différée (il faut un Keeper en service) :** un `KeeperClient` qui assure l'élection
du leader, la connaissance du retard de réplication et l'exécution de la file de DDL distribués est le
premier chantier de la Phase 3.

---

## 5. Point d'extension du tier d'ingestion sans état

`trait StatelessIngestTier` est le point d'extension d'un nœud d'ingestion **sans état** (il prolonge le
concept d'ingestion sans état de #15) : un nœud frontal ne détient **aucun état local** (pas de fichier
SQLCipher) ; il route un lot vers la table `Distributed`, et le moteur `Distributed` de ClickHouse répartit
**côté serveur**.

```rust
trait StatelessIngestTier {
    fn distributed_table(&self) -> &str;   // "<db>.<local>_dist" — la cible de la répartition
    fn route_batch(&self, store: &dyn EventStore, handle: StoreHandle, rows: &[EventRow])
        -> Result<usize, StoreError>;
}
```

`DistributedIngestSeam` calcule et porte la cible `_dist` (pur, testable hors ligne) mais **diffère
l'écriture en service** (`route_batch` rend `NotImplemented`) — la structure honnête sur laquelle la Phase 3
câble l'insertion asynchrone + le rejeu d'un spool durable + la quarantaine fail-closed des tenants non
résolus (RFC §3.1). Elle ne touche aucun site d'appel existant du plan de données → mode 0 intact.

---

## 6. Politique d'étagement chaud→froid

`TieringPolicy { ttl_days: u32, cold_volume: SafeIdent, storage_policy: SafeIdent }` — modèle typé +
génération de DDL/TTL sûre face à l'injection (RFC Phase 4) :

- `ttl_to_volume_clause()` → `TTL toDateTime(ts) + INTERVAL <N> DAY TO VOLUME '<cold>'` — `<N>` est un
  `u32` (jamais du texte), `<cold>` un `SafeIdent` (la liste d'autorisation exclut l'apostrophe, donc le
  littéral `'<cold>'` ne peut pas être rompu).
- `storage_policy_setting()` → `SETTINGS storage_policy='<policy>'` — `<policy>` est un `SafeIdent`.
- `replicated_ddl(topology, spec, Some(&policy))` ajoute les clauses TTL + SETTINGS au DDL de la table
  locale (ordre : `ENGINE … PARTITION … ORDER … TTL … SETTINGS`).

La couche de stockage elle-même (un volume `cold` adossé à S3 + une `storage_policy` `hot_cold`) est
déclarée par l'exploitant dans `config.xml` ; ce code n'émet que la politique au niveau de la table, qui la
référence par son nom (validé).

---

## 7. Roadmap de déploiement sur plusieurs trimestres

Prolonge le découpage en phases de la RFC §5. Chaque étape se livre indépendamment, inerte en mode 0,
prouvée byte-identique.

- **#18 Phase 2 (faite) :** adaptateur mono-nœud (`ClickHouseStore`, `ClickHouseDialect`) — émission +
  exécuteur + schéma + ingestion par lots sur un vrai ClickHouse unique.
- **#70 (cet échafaudage) :** fondations typées — modèle de topologie, génération de DDL distribué sûre face
  à l'injection, points d'extension Keeper / ingestion sans état / chaud→froid — testées hors ligne,
  **inertes, non activées**.
- **Phase 3 — distribution + HA (suivante, il faut un cluster en service) :** vrai `KeeperClient` (élection
  du leader, propagation de `full_schema_ddls` par la file de DDL) ; créer les tables `ReplicatedMergeTree`
  + `Distributed` sur le cluster ; tier d'ingestion sans état (N réplicas derrière un répartiteur de charge,
  rejeu d'un spool durable, quarantaine fail-closed des tenants non résolus) ; chemin de lecture asynchrone
  + pool de connexions au cluster ; décisions de cohérence arrêtées (stratégie de déduplication §3.3 —
  `ReplacingMergeTree` à terme contre `FINAL` à la lecture ; RFC question ouverte #2).
- **Phase 4 — étagement chaud→froid (optionnel, plus tard) :** brancher `TieringPolicy` sur une politique de
  stockage en service ; un `MergeStore` qui compose chaud (SQLCipher/DuckDB) + froid (ClickHouse) derrière un
  seul `EventStore` ; répartition + fusion GXQL sur les larges plages, ou froid en rollups seulement (RFC
  §2.2b/c).
- **Différé, transverse :** aiguillage de sélection du store à l'exécution (`PLUME_STORE=clickhouse`, ~82
  sites d'appel, RFC §6.1) — tout le tier d'échelle reste exercé par sa propre API + ses tests, et non en
  basculant une variable d'environnement en prod, tant que cela n'est pas livré.

---

## 8. Compromis — reportés de #18, inchangés et honnêtes

Le tier HA n'est **pas** un remplacement à l'identique qui aurait les garanties du tier chaud PME (RFC
§3.4/§4, `CLICKHOUSE-STORE.md` §5). Rappelés parce qu'ils portent la charge pour quiconque construit la
Phase 3 :

- **Le chiffrement au repos est DÉGRADÉ.** SQLCipher = AES sur le fichier entier avec une **clé par tenant
  détenue par l'application** (voler le fichier ⇒ inutile ; effacement RGPD = jeter la clé). ClickHouse n'a
  **aucun équivalent** — son chiffrement au repos passe par le **chiffrement du disque/du volume (LUKS/KMS du
  cloud)** ou des codecs par colonne. **Recommandé : une `database` par tenant + chiffrement volume/KMS +
  `DROP DATABASE` comme primitive RGPD** — niveau exploitant/KMS, **pas** le niveau SQLCipher à clé détenue
  par l'application. Le dire clairement au client ; ne pas le maquiller.
- **Pas de déduplication exactement-une-fois.** `event.dedup UNIQUE` + `INSERT OR IGNORE` de SQLite donne
  l'exactement-une-fois. `ReplicatedMergeTree` n'a pas de contrainte d'unicité ; `ReplacingMergeTree(ts)`
  indexé sur `dedup` déduplique *à terme* (à la fusion). Une détection sur une fenêtre tout juste ingérée
  peut voir des doublons transitoires — décision OUVERTE (RFC §3.3 / question ouverte #2).
- **Rayon d'impact plus large sur les données brutes.** Un démon compromis détient les identifiants du
  cluster pour chaque tenant qu'il sert (contre une clé SQLCipher par tenant déverrouillée une à une). Le
  dire ; l'« isolation par construction » n'est pas revendiquée (une RCE dans le mono-processus atteint tous
  les tenants — règle inchangée).
- **Le ledger ne bouge jamais.** Le `ledger` / `control_ledger` d'audit relève du plan de contrôle, est
  critique pour l'intégrité, et reste sur le plan de contrôle chiffré / SQLCipher — **pas** une table
  ClickHouse (il n'a jamais été dans la frontière données/contrôle du store).
- **Coût d'exploitation.** Cluster + Keeper + shards/réplicas + supervision représentent une vraie charge
  d'exploitation — une fonctionnalité pour ESN/MSSP dotée d'une équipe plateforme, l'inverse du récit PME du
  « conteneur unique de 2 Go ».
- **La sauvegarde/restauration diffère.** La sauvegarde par fichier `age(zstd(plain))` est une primitive de
  *fichier* ; la sauvegarde ClickHouse passe par `BACKUP`/`clickhouse-backup` vers un stockage objet — non
  câblée ici.

### Préalables à câbler avant d'exposer le tier d'échelle (reportés de #18)

1. **Masquage sur le SPI neutre (#45).** Les masques par champ/rôle/tenant/environnement sont émis au point
   de passage unique `soql_field` et ne sont câblés aujourd'hui que sur
   `SqlcipherEventStore::soql_to_sql_masked` ; le `EventStore::soql_to_sql` **neutre vis-à-vis du backend**
   ne porte aucun argument `masks`. Le dialecte sait masquer (`Schema::…with_masks(...)`), donc le masquage
   ClickHouse est *prêt à l'émission*, mais le SPI neutre a besoin d'une entrée de lecture masquée avant qu'un
   rôle restreint n'interroge le tier d'échelle. D'ici là, le défaut du trait neutre est **fail-closed** (un
   store qui ne sait pas masquer refuse une compilation masquée plutôt que de laisser fuir une requête non
   masquée). **Câbler `soql_to_sql_masked` sur le SPI neutre avant d'exposer le tier d'échelle à des rôles
   restreints.**
2. **Au repos (ci-dessus).** Configurer le chiffrement côté ClickHouse (disque chiffré / KMS) + une
   `database` par tenant ; documenter explicitement le changement de garantie. Sans cela, `event`/`metric`/
   `snapshot` du tier d'échelle ne sont pas chiffrés au niveau applicatif (une vraie régression par rapport à
   SQLCipher).
3. **Aiguillage de sélection du store à l'exécution.** L'aiguillage `PLUME_STORE=clickhouse` qui remplace
   `store()` par un store ClickHouse sur les ~82 sites d'appel du démon est différé (RFC §6.1) — le SPI neutre
   est monté et prouvé neutre vis-à-vis du backend, mais la migration des sites d'appel est volontairement
   étagée pour protéger la parité du mode 0.

---

## 9. Couverture de tests (hors ligne contre en service)

Tests unitaires **hors ligne** (`cargo test --features clickhouse-ha`, **sans cluster ni Keeper**) :

- **Topologie** — `topology_parses_shards_and_replicas`, `topology_single_node_default`,
  `topology_rejects_empty_shards`/`_missing_port`/`_bad_port`.
- **Anti-injection (le cœur sécurité)** — `safe_ident_allowlist_accepts_plain`,
  `safe_ident_rejects_injection_payloads` (`;`, guillemets, espace, `-`, `/`, `.`, `{}`, accent grave,
  parenthèses, non-ASCII, saut de ligne), `cluster_name_injection_rejected_before_ddl`,
  `database_and_table_injection_rejected`, `sharding_key_rejects_bad_column`,
  `tiering_rejects_injection_in_volume_and_policy`.
- **Forme des DDL Distributed / Replicated** — `replicated_ddl_shape` (`ON CLUSTER`, chemin zk de
  `ReplicatedMergeTree` + macros littérales `{shard}`/`{replica}`, partition/ordre), `distributed_ddl_shape`
  (`Distributed(cluster, db, local, cityHash64(host))`), `distributed_ddl_random_sharding`,
  `full_schema_has_six_ddls_local_then_dist`, `ha_event_columns_mirror_single_node` (parité avec #18).
- **TTL chaud→froid** — `tiering_ttl_clause_shape`, `replicated_ddl_with_tiering_appends_ttl_and_settings`.
- **Bouchons** — `noop_keeper_refuses_live_ops_but_answers_pure`,
  `stateless_ingest_seam_targets_dist_table_but_defers_write`.

Il faut un **cluster multi-nœud en service + Keeper** (différé, `#[ignore]`) :

- `live_apply_ha_schema_on_cluster` — applique `full_schema_ddls` `ON CLUSTER` à un vrai cluster. Se lance
  avec un cluster joignable : `PLUME_CLICKHOUSE_URL=… PLUME_CLICKHOUSE_CLUSTER=… PLUME_CLICKHOUSE_SHARDS=…
  cargo test --features clickhouse-ha -- --ignored`.

Le `cargo test` **par défaut** (SqlcipherStore seul) et le build `--features clickhouse` (#18 mono-nœud)
sont inchangés et verts — le module HA et ses tests ne compilent **que** sous `--features clickhouse-ha`.
