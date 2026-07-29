# ClickHouse HA — distributed multi-node scaffold (#70)

Status: **SCAFFOLD / FOUNDATIONS ONLY — INERT, NOT ACTIVATED.** Feature-gated behind a dedicated
`clickhouse-ha` sub-feature (which enables `clickhouse`). Absent from the default build **and** from the
`--features clickhouse` build (#18 single-node). It carries **no runtime path** — nothing in the
data-plane calls it (no call-site is wired). **The default remains `SqlcipherStore` (SQLite/SQLCipher),
byte-identical to today.**

This document continues [`CLICKHOUSE-STORE.md`](./CLICKHOUSE-STORE.md) (the single-node adapter, #18,
Phase 2) into the **multi-node HA distributed tier** it named as future roadmap. It turns the
design RFC (§3/§4, Phases 3–4) into typed,
tested-offline **foundations** for a multi-quarter effort — not a live distributed store. It builds
**on** the single-node adapter, it does not rewrite it.

---

## 1. What this is (and is not)

| | Single-node (#18, **built**) | HA scaffold (#70, **this doc — foundations, inert**) | HA live (Phase 3, **not built**) |
|---|---|---|---|
| Topology | one server (`Client`) | typed `ClusterTopology` (shards × replicas), parsed+validated | live cluster + Keeper |
| Engine | `MergeTree` | **DDL-gen** for `ReplicatedMergeTree` + `Distributed` | tables created on cluster |
| Coordination | n/a | `trait KeeperCoordination` + `NoopKeeper` stub | live Keeper client |
| Ingest | daemon writes batches | `trait StatelessIngestTier` seam (target = `_dist`) | N stateless replicas + spool replay |
| Hot→cold | n/a | `TieringPolicy` + TTL/`storage_policy` DDL-gen | S3-backed cold volume live |
| Runtime | `PLUME_STORE=clickhouse` (deferred) | **not wired to any runtime path** | dispatch + async read path |

The scaffold proves the **shapes** — topology model, injection-safe DDL generation, the coordination /
ingest / tiering seams — offline, before a live cluster's failure modes are added. It is the
foundation-laying milestone, not the scale ceiling. Everything here is **additive and mode-0
byte-identical**: the module compiles **only** under `--features clickhouse-ha`, is selected by nothing at
runtime, and the SMB/prod deployment is untouched.

Module: `daemon/src/ingest/clickhouse_ha.rs` (single cohesive module; the single-node
`clickhouse_store.rs` stays navigable and unchanged).

---

## 2. Cluster topology model

`ClusterTopology { cluster_name: SafeIdent, database: SafeIdent, shards: Vec<Shard{ replicas:
Vec<Replica{host,port}> }> }` — **pure data + validation**, parsed from config/env, contacting nothing.

Parsed from env on a scale deployment (never read in mode 0):

```bash
export PLUME_CLICKHOUSE_CLUSTER=plume_cluster                 # logical cluster name (SafeIdent)
export PLUME_CLICKHOUSE_DATABASE=plume                        # target database (SafeIdent)
export PLUME_CLICKHOUSE_SHARDS="h1:9000,h2:9000;h3:9000,h4:9000"
#   ';' separates SHARDS, ',' separates REPLICAS within a shard, each replica is host:port
```

`ClusterTopology::from_env()` / `::parse(cluster, database, shards_spec)` validate hard: ≥1 shard, each
shard ≥1 replica, each replica host on the host allowlist (`[A-Za-z0-9._-]`) and port ≠ 0. Cluster and
database names are `SafeIdent` (see §4) — **an injection payload as a cluster/db name is rejected at
topology construction, before it can reach any DDL.**

`Replica{host,port}` feeds only the ClickHouse `remote_servers` config (declared by the operator in
`config.xml`, out of this code's scope). Hosts **never** enter a DDL — an `ON CLUSTER` statement names the
**cluster**, not the hosts.

---

## 3. Distributed DDL: `Distributed` over `ReplicatedMergeTree`

The core of HA. For each data-plane table (`event`/`metric`/`snapshot`, mirroring the single-node #18
schema) the scaffold emits **two** DDLs, in apply order:

1. **Local replicated table** (one physical table per shard, HA by replication):

   ```sql
   CREATE TABLE IF NOT EXISTS plume.event ON CLUSTER plume_cluster (
     ts Int64, source String, category String, severity Int64, message String,
     host Nullable(String), src_ip Nullable(String), dst_ip Nullable(String), url Nullable(String),
     dedup Nullable(String), fields Nullable(String),
     engagement_id String DEFAULT '', origin String DEFAULT '', env_id String DEFAULT 'prod'
   ) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/plume/event', '{replica}')
   PARTITION BY toYYYYMM(toDateTime(ts)) ORDER BY (env_id, source, ts)
   ```

2. **Distributed table** (the query/insert router over the local shards):

   ```sql
   CREATE TABLE IF NOT EXISTS plume.event_dist ON CLUSTER plume_cluster ( …same columns… )
   ENGINE = Distributed(plume_cluster, plume, event, cityHash64(host))
   ```

- `{shard}` / `{replica}` are **literal ClickHouse macros** (substituted server-side per replica from
  `<macros>` in `config.xml`) — they are **not** config, they stay literal in the emitted string.
- The **ZooKeeper/Keeper path** `/clickhouse/tables/{shard}/<db>/<local>` is built from the validated
  `database` and `local_table` names plus the literal `{shard}` macro — no injected segment is possible.
- **Sharding key** is a closed enum `ShardingKey` — `Columns(Vec<SafeIdent>)` → `cityHash64(col, …)` or
  `Random` → `rand()`. It is a **validated column, never free text.** The canonical `event` spec shards on
  `cityHash64(host)` (co-locate a host's data so `stats by host` stays mostly shard-local, RFC §3.1);
  `metric` on `name`, `snapshot` on `kind`.
- Columns, `PARTITION BY`, `ORDER BY` are **author constants** (mirror of single-node #18) — not config,
  so not an injection surface. A test (`ha_event_columns_mirror_single_node`) locks the event column set
  to `ClickHouseStore::schema_ddl()` so the two tiers cannot drift (the `RowBinary` insert targets columns
  by name — same GXQL surface across tiers).

`full_schema_ddls(topology, tiering)` returns the six statements (3 tables × {local, distributed}) in
apply order (local before distributed — the `Distributed` engine references a table that must already
exist on each shard). This is exactly what `KeeperCoordination::propagate_ddl_on_cluster` would run on a
live cluster (deferred).

### 3.1 Injection safety — the review target

DDL is **built from config names** (cluster, database, table, sharding column, cold volume, storage
policy). Those names are **semi-trusted** and validated **hard**:

- **`SafeIdent`** is a newtype whose **only** constructor validates against a strict allowlist
  `[A-Za-z0-9_]`, non-empty, ≤64 chars (`ident_ok`, a mirror of the core's private `soql_ident_ok`).
  There is **no other way** to obtain a `SafeIdent` — so any name that reaches a DDL string is
  **proven** to contain no SQL metacharacter (`;`, quotes, spaces, `-`, `/`, `.`, `{`/`}`, backticks,
  parens, comments are all rejected). Names are therefore safe in **bare** concatenation (no quoting
  needed because the metacharacter class is empty).
- **No raw config string is ever concatenated into a DDL.** Cluster/database go through `SafeIdent` at
  topology construction; table names and sharding columns through `SafeIdent`; volume/policy through
  `SafeIdent`; the TTL day count is a `u32` (never text). The macros `{shard}`/`{replica}` are literals.
- **Reject-on-invalid, fail-closed.** Every constructor returns `Result<_, HaError::InvalidIdent|…>`; an
  invalid name never degrades to a "best effort" DDL — it errors.

Anti-injection tests assert a cluster/database/table/volume/policy/column name containing `;`, quotes,
spaces, `-`, `/`, `.`, macro braces, backticks, parens or a comment is **rejected** before any DDL is
emitted (`safe_ident_rejects_injection_payloads`, `cluster_name_injection_rejected_before_ddl`,
`database_and_table_injection_rejected`, `tiering_rejects_injection_in_volume_and_policy`).

---

## 4. Keeper coordination interface (stub)

`trait KeeperCoordination` abstracts ClickHouse Keeper / ZooKeeper: leader/replica awareness and
`ON CLUSTER` DDL propagation.

```rust
trait KeeperCoordination {
    fn is_leader_replica(&self, shard: ShardId) -> Result<bool, HaError>;   // once-per-shard jobs
    fn known_replicas(&self, shard: ShardId) -> Result<Vec<Replica>, HaError>;
    fn propagate_ddl_on_cluster(&self, ddl: &str) -> Result<(), HaError>;   // apply full_schema_ddls
}
```

`NoopKeeper` is the shipped **stub**: it answers the **pure** question (`known_replicas` = the *configured*
topology, known offline) but **refuses every live operation** — `is_leader_replica` and
`propagate_ddl_on_cluster` return `HaError::NotImplemented` rather than a silent false success. **Real impl
deferred (needs a live Keeper):** a `KeeperClient` doing leader election, replication-lag awareness and
distributed DDL-queue execution is the first Phase-3 work item.

---

## 5. Stateless ingest tier seam

`trait StatelessIngestTier` is the seam for a **stateless** ingest node (extends the #15 stateless-ingest
concept): a front node holds **no local state** (no SQLCipher file); it routes a batch to the
`Distributed` table and ClickHouse's `Distributed` engine shards **server-side**.

```rust
trait StatelessIngestTier {
    fn distributed_table(&self) -> &str;   // "<db>.<local>_dist" — the fan-out target
    fn route_batch(&self, store: &dyn EventStore, handle: StoreHandle, rows: &[EventRow])
        -> Result<usize, StoreError>;
}
```

`DistributedIngestSeam` computes and carries the `_dist` target (pure, offline-testable) but **defers the
live write** (`route_batch` returns `NotImplemented`) — the honest structure on which Phase 3 wires
async-insert + durable-spool replay + fail-closed unresolved-tenant quarantine (RFC §3.1). It touches no
existing data-plane call-site → mode 0 intact.

---

## 6. Hot→cold tiering policy

`TieringPolicy { ttl_days: u32, cold_volume: SafeIdent, storage_policy: SafeIdent }` — typed model +
injection-safe DDL/TTL generation (RFC Phase 4):

- `ttl_to_volume_clause()` → `TTL toDateTime(ts) + INTERVAL <N> DAY TO VOLUME '<cold>'` — `<N>` is a `u32`
  (never text), `<cold>` a `SafeIdent` (the allowlist excludes the quote, so the `'<cold>'` literal can't
  be broken).
- `storage_policy_setting()` → `SETTINGS storage_policy='<policy>'` — `<policy>` a `SafeIdent`.
- `replicated_ddl(topology, spec, Some(&policy))` appends the TTL + SETTINGS clauses to the local table
  DDL (order: `ENGINE … PARTITION … ORDER … TTL … SETTINGS`).

The storage layer itself (an S3-backed `cold` volume + a `hot_cold` `storage_policy`) is declared by the
operator in `config.xml`; this code emits only the table-level policy that references it by (validated)
name.

---

## 7. Multi-quarter deployment roadmap

Continues the RFC §5 phasing. Each step independently shippable, mode-0-inert, proven byte-identical.

- **#18 Phase 2 (done):** single-node adapter (`ClickHouseStore`, `ClickHouseDialect`) — emission +
  executor + schema + batched ingest on a real single ClickHouse.
- **#70 (this scaffold):** typed foundations — topology model, injection-safe distributed DDL-gen, Keeper
  / stateless-ingest / hot→cold seams — offline-tested, **inert, not activated**.
- **Phase 3 — distribution + HA (next, needs a live cluster):** real `KeeperClient` (leader election,
  DDL-queue propagation of `full_schema_ddls`); create `ReplicatedMergeTree` + `Distributed` tables on the
  cluster; stateless ingest tier (N replicas behind an LB, durable spool replay, fail-closed
  unresolved-tenant quarantine); async read path + cluster connection pooling; consistency decisions
  locked (dedup strategy §3.3 — `ReplacingMergeTree` eventual vs `FINAL`-on-read; RFC Open-Q #2).
- **Phase 4 — hot→cold tiering (optional, later):** wire `TieringPolicy` into a live storage policy;
  `MergeStore` composing hot (SQLCipher/DuckDB) + cold (ClickHouse) behind one `EventStore`; wide-range
  GXQL fan-out + merge, or rollup-only cold (RFC §2.2b/c).
- **Cross-cutting deferred:** runtime store-selection dispatch (`PLUME_STORE=clickhouse`, ~82 call-sites,
  RFC §6.1) — the whole scale tier stays exercised by its own API + tests, not by flipping an env var in
  prod, until that lands.

---

## 8. Tradeoffs — carried forward from #18, unchanged and honest

The HA tier is **not** a drop-in with the SMB hot tier's guarantees (RFC §3.4/§4, `CLICKHOUSE-STORE.md`
§5). Restated because they are load-bearing for anyone who builds Phase 3:

- **At-rest encryption is DOWNGRADED.** SQLCipher = whole-file AES with a **per-tenant key held by the
  app** (steal the file ⇒ useless; RGPD erasure = throw the key). ClickHouse has **no equivalent** — its
  at-rest story is **disk/volume encryption (LUKS/cloud KMS)** or per-column codecs. **Recommended:
  per-tenant `database` + volume/KMS encryption + `DROP DATABASE` as the RGPD primitive** — operator/KMS-
  grade, **not** SQLCipher app-held-key-grade. Say it plainly to the customer; do not paper over it.
- **No exactly-once dedup.** SQLite's `event.dedup UNIQUE` + `INSERT OR IGNORE` gives exactly-once.
  `ReplicatedMergeTree` has no unique constraint; `ReplacingMergeTree(ts)` keyed on `dedup` dedups
  *eventually* (at merge). Detection over a just-ingested window may see transient duplicates — decision
  OPEN (RFC §3.3 / Open-Q #2).
- **Wider raw-data blast radius.** A compromised daemon holds cluster credentials for every tenant it
  serves (vs. a per-tenant SQLCipher key unlocked individually). State it; "isolation by construction" is
  not claimed (an RCE in the mono-process reaches all tenants — unchanged rule).
- **Ledger never moves.** The audit `ledger` / `control_ledger` is control-plane, integrity-critical, and
  stays on the encrypted control-plane / SQLCipher — **not** a ClickHouse table (it was never in the
  store's data/control frontier).
- **Operational cost.** Cluster + Keeper + shards/replicas + monitoring is a real ops burden — an
  ESN/MSSP-with-a-platform-team feature, the opposite of the "single 2 Go container" SMB story.
- **Backup/restore differs.** `age(zstd(plain))` per-file backup is a *file* primitive; ClickHouse backup
  is `BACKUP`/`clickhouse-backup` to object storage — not wired here.

### Preconditions to wire before exposing the scale tier (carried from #18)

1. **Masking on the neutral SPI (#45).** Field/role/tenant/env masks are emitted at the `soql_field`
   chokepoint and wired today only on `SqlcipherEventStore::soql_to_sql_masked`; the **backend-neutral**
   `EventStore::soql_to_sql` carries no `masks` argument. The dialect is mask-capable
   (`Schema::…with_masks(...)`), so ClickHouse masking is *emission-ready*, but the neutral SPI needs a
   masked read entry before a restricted role queries the scale tier. Until then the neutral trait's
   default is **fail-closed** (a store that cannot mask refuses a masked compilation rather than leak an
   unmasked query). **Wire `soql_to_sql_masked` onto the neutral SPI before exposing the scale tier to
   restricted roles.**
2. **At-rest (above).** Configure ClickHouse-side encryption (encrypted disk / KMS) + per-tenant
   `database`; document the guarantee change explicitly. Absent it, scale-tier `event`/`metric`/`snapshot`
   is unencrypted at the application layer (a genuine reduction vs. SQLCipher).
3. **Runtime store-selection dispatch.** The `PLUME_STORE=clickhouse` dispatch that swaps `store()` for a
   ClickHouse store across the ~82 daemon call-sites is deferred (RFC §6.1) — the neutral SPI is mounted
   and proven backend-neutral, but the call-site migration is intentionally staged to protect mode-0
   parity.

---

## 9. Test coverage (offline vs. live)

Unit-tested **offline** (`cargo test --features clickhouse-ha`, **no cluster/Keeper**):

- **Topology** — `topology_parses_shards_and_replicas`, `topology_single_node_default`,
  `topology_rejects_empty_shards`/`_missing_port`/`_bad_port`.
- **Anti-injection (the security core)** — `safe_ident_allowlist_accepts_plain`,
  `safe_ident_rejects_injection_payloads` (`;`, quotes, space, `-`, `/`, `.`, `{}`, backtick, parens,
  non-ASCII, newline), `cluster_name_injection_rejected_before_ddl`, `database_and_table_injection_rejected`,
  `sharding_key_rejects_bad_column`, `tiering_rejects_injection_in_volume_and_policy`.
- **Distributed / Replicated DDL shape** — `replicated_ddl_shape` (`ON CLUSTER`, `ReplicatedMergeTree`
  zk-path + literal `{shard}`/`{replica}` macros, partition/order), `distributed_ddl_shape`
  (`Distributed(cluster, db, local, cityHash64(host))`), `distributed_ddl_random_sharding`,
  `full_schema_has_six_ddls_local_then_dist`, `ha_event_columns_mirror_single_node` (parity with #18).
- **Hot→cold TTL** — `tiering_ttl_clause_shape`, `replicated_ddl_with_tiering_appends_ttl_and_settings`.
- **Stubs** — `noop_keeper_refuses_live_ops_but_answers_pure`,
  `stateless_ingest_seam_targets_dist_table_but_defers_write`.

Needs a **live multi-node cluster + Keeper** (deferred, `#[ignore]`):

- `live_apply_ha_schema_on_cluster` — applies `full_schema_ddls` `ON CLUSTER` against a real cluster. Run
  with a reachable cluster: `PLUME_CLICKHOUSE_URL=… PLUME_CLICKHOUSE_CLUSTER=… PLUME_CLICKHOUSE_SHARDS=…
  cargo test --features clickhouse-ha -- --ignored`.

The **default** `cargo test` (SqlcipherStore only) and the `--features clickhouse` (#18 single-node) build
are unchanged and green — the HA module and its tests compile **only** under `--features clickhouse-ha`.
