# Store ClickHouse — adaptateur mono-nœud (#18, Phase 2)

[English](CLICKHOUSE-STORE.md) | [Français](CLICKHOUSE-STORE.fr.md)

Statut : **OPT-IN, INERTE PAR DÉFAUT.** Cloisonné par feature (`--features clickhouse`). La sélection à
l'exécution (`PLUME_STORE=clickhouse`) est conçue mais **non câblée** : la variable n'est lue nulle part dans
le démon, qui sert toujours `SqlcipherStore` (voir la note à la fin du §2.1 et `docs/CLICKHOUSE-HA.md`).
Absent du build PME/prod et du déploiement de prod. **Le défaut reste
`SqlcipherStore` (SQLite/SQLCipher), byte-identique à aujourd'hui.**

Ce document couvre l'adaptateur ClickHouse **mono-nœud** livré derrière le point d'extension : un serveur
ClickHouse (un « cluster d'un seul »), la correspondance CIM/schéma, et les compromis de sécurité. Le **tier
distribué HA multi-nœud** (sharding, `ReplicatedMergeTree`, Keeper, ingestion sans état, isolation par
`database` de tenant, étagement chaud→froid) est une **roadmap sur plusieurs trimestres — NON construite**
(voir la RFC de conception, §3 et Phases 3–4).

---

## 1. Ce que c'est (et ce que ce n'est pas)

| | Adaptateur mono-nœud (**ce document, construit**) | HA multi-nœud (RFC §3, **non construit**) |
|---|---|---|
| Topologie | un serveur ClickHouse (cluster d'un seul) | shards + réplicas + Keeper |
| Moteur | `MergeTree` | `ReplicatedMergeTree` + `Distributed` |
| Ingestion | le démon écrit les lots directement | tier d'ingestion sans état, N réplicas + spool durable |
| Clé de tenant | une `database` par `Client` | `database`/cluster par tenant, `StoreLocator` |
| Déduplication | aucune (`MergeTree`), voir §5 | `ReplacingMergeTree` à terme (OUVERT) |
| Lecture asynchrone | runtime bloquant dans `spawn_blocking` (GAP-2 option A) | asynchrone natif + pool (GAP-2 option B) |

La découpe mono-nœud prouve **émission + exécuteur + schéma + ingestion par lots** sur un vrai ClickHouse
avant qu'on y ajoute les modes de défaillance de la distribution. C'est le jalon de justesse, pas le plafond
de montée en charge.

---

## 2. Fonctionnement de l'adaptateur

Deux pièces maison derrière les deux points d'extension déjà découpés (rien de neuf n'est inventé — voir
RFC §0) :

- **`ClickHouseDialect : Dialect`** (`core/src/soql/dialect.rs`) — le compilateur GXQL est **inchangé** ;
  seuls les ~8 fragments d'émission sont transposés en SQL ClickHouse (`JSONExtractString`,
  `toFloat64OrNull`, `intDiv(ts,span)*span`, `arrayStringConcat(groupUniqArray(...))`, fonctions de chaîne
  CH pour `mitre_parent`, `positionCaseInsensitive`, identifiants entre accents graves, échappement des
  littéraux). Porté par `Schema::events_clickhouse()`. **Du texte pur, aucune dépendance à la crate
  `clickhouse`** — les schémas par défaut restent sur `SqliteDialect`, parité du mode 0 intacte. L'émission
  est déjà couverte par des tests unitaires dans le core (`clickhouse_dialect_emits_clickhouse_fragments`,
  `events_clickhouse_compiles_via_clickhouse_dialect`).

- **`ClickHouseStore : guatx_core::store::EventStore`** (`daemon/src/ingest/clickhouse_store.rs`,
  `#[cfg(feature = "clickhouse")]`) — l'implémentation d'écriture + de lecture GXQL :
  - **Ingestion (par lots).** `insert_events` ouvre un seul `Insert<ChEventRow>` (`RowBinary`) et écrit le
    lot entier avant `end()` — l'insertion par lots native (ClickHouse s'effondre sous des insertions rangée
    par rangée). `insert_event` = un lot d'un seul. Les `Ch{Event,Metric,Snapshot}Row` typés reflètent les
    colonnes SQLite ; l'insertion `RowBinary` vise les colonnes **par leur nom**, donc les noms de colonnes du
    DDL doivent correspondre aux structures de rangée (affirmé par le test `event_ddl_mirrors_insert_columns`).
  - **Requête.** `soql_to_sql` compile via `Schema::events_clickhouse()` (le store **possède** l'émission —
    jamais une chaîne SQL préfabriquée qu'on lui remettrait). `query_soql` exécute avec
    `fetch_bytes("JSONCompact")` et rend la **même** forme JSON `{columns, rows, stats}` que les exécuteurs
    SQLite/DuckDB, si bien que les handlers sont indépendants du backend.
  - **Pont synchrone↔asynchrone (GAP-2 option A).** Le SPI est synchrone ; ClickHouse est asynchrone/HTTP.
    Le store porte un runtime tokio `current_thread` dédié et fait des `block_on` à l'intérieur de
    l'enveloppe de lecture `spawn_blocking` existante du démon — le plus petit rayon d'impact,
    `SqlcipherStore` reste byte-identique.
  - **Chien de garde + annulation (GAP-4).** `budget_ms → max_execution_time`, `qid → query_id` posés en
    SETTINGS de requête ClickHouse (`KILL QUERY` côté serveur).

### 2.1 L'activer

Construire avec la feature (le build PME par défaut ne lie **pas** la crate `clickhouse`) :

```bash
cargo build --release --features clickhouse
```

Pointer vers un serveur ClickHouse et sélectionner le store à l'exécution :

```bash
export PLUME_STORE=clickhouse            # DESIGN ONLY — cette variable n'est lue par AUCUN chemin runtime
                                         # (cf. docs/CLICKHOUSE-HA.md) : la poser n'a AUCUN effet aujourd'hui.
export PLUME_CLICKHOUSE_URL=http://ch-host:8123
export PLUME_CLICKHOUSE_USER=plume       # optionnel
export PLUME_CLICKHOUSE_PASSWORD=…       # optionnel
export PLUME_CLICKHOUSE_DATABASE=plume   # optionnel ; le Client porte la base (= clé de tenant aujourd'hui)
```

`ClickHouseStore::from_env()` les lit ; `ensure_schema()` provisionne les tables de façon idempotente
(`CREATE TABLE IF NOT EXISTS`). À exécuter une fois au démarrage sur un déploiement à l'échelle.

> **Note — le câblage de la sélection à l'exécution est un chantier ultérieur.** Le store, le dialecte, le
> DDL et l'exécuteur sont construits et testés. L'*aiguillage* `PLUME_STORE=clickhouse` qui remplace
> `store()` par un `ClickHouseStore` sur les ~82 sites d'appel du démon est le chantier différé qui achève la
> Phase 0 (RFC §6.1 : le SPI neutre est monté et prouvé neutre vis-à-vis du backend, mais la migration des
> sites d'appel est volontairement étagée pour protéger la parité du mode 0). Tant que ce n'est pas livré,
> l'adaptateur est exercé par sa propre API + ses tests, et non en basculant la variable d'environnement en
> prod.

---

## 3. Correspondance schéma / CIM (DDL)

`ClickHouseStore::schema_ddl()` rend trois instructions `CREATE TABLE IF NOT EXISTS … ENGINE = MergeTree`
qui reflètent `db/schema.sql`. Les **noms** de colonnes **sont identiques** à ceux des tables SQLite et des
structures `Ch*Row`, si bien que chaque requête / règle / panneau GXQL résout les mêmes champs.

```sql
CREATE TABLE IF NOT EXISTS event (
  ts Int64, source String, category String, severity Int64, message String,
  host Nullable(String), src_ip Nullable(String), dst_ip Nullable(String), url Nullable(String),
  dedup Nullable(String), fields Nullable(String),
  engagement_id String DEFAULT '', origin String DEFAULT '', env_id String DEFAULT 'prod'
) ENGINE = MergeTree PARTITION BY toYYYYMM(toDateTime(ts)) ORDER BY (env_id, source, ts);

CREATE TABLE IF NOT EXISTS metric (
  ts Int64, name String, labels Nullable(String), value Float64, host Nullable(String)
) ENGINE = MergeTree PARTITION BY toYYYYMM(toDateTime(ts)) ORDER BY (name, ts);

CREATE TABLE IF NOT EXISTS snapshot (
  ts Int64, kind String, hash String, data String, host Nullable(String)
) ENGINE = MergeTree PARTITION BY toYYYYMM(toDateTime(ts)) ORDER BY (kind, ts);
```

Notes de correspondance :
- **Types.** SQLite `INTEGER→Int64`, `REAL→Float64`, `TEXT→String`. Les colonnes `NOT NULL` dans SQLite
  (`env_id`, `origin`, `engagement_id`) deviennent `String DEFAULT …` — jamais NULL, conformes à la valeur que
  stocke le chemin SQLite (l'insertion lie `'prod'` pour `env_id=None`, `''` pour `origin`/`engagement_id`).
  Les colonnes optionnelles (`host`, `src_ip`, …, `dedup`, `fields`) deviennent `Nullable(String)`.
- **`ORDER BY`** est l'index creux / la clé de tri de MergeTree : `event` reflète les index SQLite
  (`idx_event_src`, `idx_event_ts`) plus le cloisonnement par environnement (`ORDER BY (env_id, source, ts)`).
- **`PARTITION BY toYYYYMM(toDateTime(ts))`** (`ts` = secondes epoch) — des partitions mensuelles, pour que la
  purge de rétention soit un `DROP PARTITION` peu coûteux à l'échelle de plusieurs To, et non un `DELETE`
  massif.
- **`fields`** reste une `String` JSON ; `ClickHouseDialect.json_extract` émet
  `JSONExtractString(fields,'X')`. (L'optimisation SQLite par index d'expression sur les champs chauds n'a
  pas d'équivalent MergeTree — voir RFC §4 ; l'équivalent serait des colonnes `MATERIALIZED` / des index de
  saut, différés.)
- **`metric`/`snapshot`** portent exactement les colonnes que lie l'`INSERT` SQLite (pas de colonne
  `env_id` — les insertions SQLite de metric/snapshot l'omettent aussi), ce qui garde les données stockées à
  parité avec les structures de rangée.

---

## 4. Sûreté face à l'injection

**Les lectures passent par le même compilateur GXQL.** `ClickHouseStore::soql_to_sql` appelle
`guatx_core::soql::to_sql(…, Schema::events_clickhouse())` — le même compilateur en pipeline que pour
SQLite, seuls les fragments d'émission diffèrent. Chaque garde revue s'applique toujours :
- le **compilateur fermé** (GXQL n'est pas du SQL brut ; commandes/fonctions forment une énumération fermée),
- le **point de passage unique du masquage** (`soql_field`) et les points d'injection des filtres de champ,
- l'échappement des littéraux et des identifiants `soql_esc` / `quote_ident` (variante ClickHouse) — prouvé
  par le test `store_soql_literal_is_escaped` (`a'b` → `'a''b'`).

Aucune chaîne SQL n'est jamais remise toute faite au store ; le store **possède** l'émission.

**Liste de refus des colonnes secrètes — signalée, propre à SQLite aujourd'hui.** La liste de refus du
chemin chaud qui refuse `user.hash` / `token.token_hash` *même à l'admin* vit dans l'**autorizer de colonnes
du pool de lecture SQLite** (`main.rs`, `run_query_ex`). C'est un mécanisme `rusqlite`-`Authorizer` et il ne
se transpose **pas** à ClickHouse. C'est **acceptable et voulu**, parce que ces colonnes secrètes relèvent du
**plan de contrôle** et ne sont **jamais** dans ClickHouse — seulement `event`/`metric`/`snapshot` (la
frontière données/contrôle, RFC §0.1). Il n'y a donc aucune colonne secrète qu'une requête ClickHouse
pourrait atteindre. Si des tables du plan de contrôle devaient un jour passer dans ClickHouse (elles ne sont
**pas** dans le périmètre, jamais), l'application équivalente devrait être réimplémentée comme liste de refus
dans le `ClickHouseDialect`/l'exécuteur (ne jamais émettre de colonne secrète) plus des
`GRANT`/row-policies ClickHouse — c'est explicitement hors du périmètre de #18.

**Masquage par filtres de champ (#45) — lacune signalée.** Les masques de champ par rôle/tenant/environnement
sont émis au point de passage unique `soql_field` et ne sont câblés aujourd'hui que sur le
`SqlcipherEventStore::soql_to_sql_masked` interne ; le `EventStore::soql_to_sql` **neutre vis-à-vis du
backend** ne porte aucun argument `masks`. Le dialecte du core sait masquer (`Schema::…with_masks(...)`),
donc le masquage ClickHouse est *prêt à l'émission*, mais le SPI neutre aurait besoin d'une entrée de lecture
masquée avant qu'un rôle restreint n'interroge le tier d'échelle. D'ici là, le défaut du trait neutre est
**fail-closed** (un store qui ne sait pas masquer refuse une compilation masquée plutôt que de laisser fuir
une requête non masquée). Câbler `soql_to_sql_masked` sur le SPI neutre avant d'exposer le tier d'échelle à
des rôles restreints.

---

## 5. Compromis de sécurité — à lire avant d'activer

Le tier d'échelle n'est **pas** un remplacement à l'identique qui aurait les mêmes garanties que le tier
chaud PME. Les coûts honnêtes (inventaire complet en RFC §3.4 / §4) :

- **Le chiffrement au repos est DÉGRADÉ.** SQLCipher donne un **AES sur le fichier entier avec une clé par
  tenant détenue par l'application** : voler le fichier/la sauvegarde ⇒ inutile sans la clé ; effacement
  RGPD = jeter la clé. ClickHouse n'a **aucun équivalent** — son chiffrement au repos passe par le
  **chiffrement du disque/du volume (LUKS/KMS du cloud)** ou des codecs par colonne. L'adaptateur mono-nœud,
  tel que construit, stocke `event`/`metric`/`snapshot` **non chiffrés au niveau applicatif** à moins de
  configurer le chiffrement côté ClickHouse (disque chiffré / KMS). **C'est une vraie régression de la
  garantie au repos.** Les clients PME qui ont choisi plume *pour* le chiffrement à clé détenue par
  l'application doivent rester sur le tier chaud. Le schéma multi-nœud recommandé (une `database` par tenant
  + chiffrement volume/KMS, effacement RGPD = `DROP DATABASE`) est de niveau exploitant/KMS, **pas** du niveau
  SQLCipher à clé détenue par l'application — et il n'est **pas construit** ici.
- **Pas de déduplication exactement-une-fois.** `event.dedup UNIQUE` + `INSERT OR IGNORE` de SQLite donne
  l'exactement-une-fois **pour les surfaces dont l'émetteur fournit une clé `dedup`** (lots d'agent,
  `__CURSOR` de journald, …). Une surface dont le protocole ne porte **aucun identifiant par entrée** — le
  point d'entrée **Loki push** — laisse `dedup` à NULL et est donc **au-moins-une-fois même sur SQLite** ;
  dériver une clé du *contenu* écarterait en silence des lignes identiques légitimement répétées, c'est-à-dire
  changerait un doublon visible en une perte invisible. Le DDL
  `MergeTree` d'ici n'a **aucune contrainte d'unicité** — des doublons sont possibles. Une déduplication à
  terme via `ReplacingMergeTree(ts)` indexé sur `dedup` est l'option de prod documentée (OUVERTE), différée.
- **Rayon d'impact plus large sur les données brutes.** Un démon compromis détient les identifiants du
  cluster pour les données qu'il sert (contre une clé SQLCipher par tenant qu'il faut déverrouiller une à
  une). Le dire clairement.
- **La sauvegarde/restauration diffère.** La sauvegarde par fichier `age(zstd(plain))` est une primitive de
  *fichier* ; la sauvegarde ClickHouse passe par `BACKUP`/`clickhouse-backup` vers un stockage objet — un
  autre mécanisme, non câblé ici.

**En résumé :** activer le tier ClickHouse pour l'échelle et l'analytique (plusieurs To/jour, des mois de
rétention, la vitesse du colonnaire) sur un déploiement ESN/MSSP doté d'une équipe plateforme et d'un
chiffrement KMS/volume configuré — explicitement, comme `PLUME_MULTI_TENANT=1`. Jamais comme défaut PME.

---

## 6. Couverture de tests (ce qui est prouvé, ce qui exige un serveur en service)

Tests unitaires hors ligne (`cargo test --features clickhouse`, sans serveur ClickHouse) :
- `store_soql_compiles_via_clickhouse_dialect` — l'adaptateur compile le GXQL par le dialecte CH
  (`JSONExtractString`, `arrayStringConcat(groupUniqArray(...))`), aucun fragment SQLite ne fuit.
- `store_soql_time_bucket_is_clickhouse_intdiv` — `timechart span=1h` → `intDiv(ts,3600)*3600` (parité de
  granularité avec SQLite).
- `store_soql_literal_is_escaped` — sûreté face à l'injection : `a'b` → `'a''b'` par le point de passage
  unique partagé.
- `schema_ddl_is_mergetree` — les trois DDL sont `MergeTree`, idempotents, partitionnés par mois.
- `event_ddl_mirrors_insert_columns` — chaque colonne de `EVENT_INSERT_SQL` existe dans le DDL (parité par
  nom de RowBinary) ; les défauts de `env_id`/`origin` sont présents.
- L'émission du core est prouvée à part dans `core/src/soql/`
  (`clickhouse_dialect_emits_clickhouse_fragments`, `events_clickhouse_compiles_via_clickhouse_dialect`).

Exige un ClickHouse en service (différé, `#[ignore]`) :
- `live_roundtrip_ensure_insert_query` — aller-retour `ensure_schema` + `insert_events` par lots
  (`RowBinary`) + `query_soql`. Se lance avec un serveur joignable :
  `PLUME_CLICKHOUSE_URL=… cargo test --features clickhouse -- --ignored`.

Le `cargo test` **par défaut** (SqlcipherStore seul) est inchangé et vert — le module ClickHouse et ses
tests ne sont pas compilés sans `--features clickhouse`.
