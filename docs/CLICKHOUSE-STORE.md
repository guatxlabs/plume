# ClickHouse store — single-node adapter (#18, Phase 2)

Status: **OPT-IN, INERT BY DEFAULT.** Feature-gated (`--features clickhouse`), selected at runtime by
`PLUME_STORE=clickhouse`. Absent from the SMB/prod build and prod deployment. **The default remains
`SqlcipherStore` (SQLite/SQLCipher), byte-identical to today.**

This document covers the **single-node** ClickHouse adapter that ships behind the seam: one ClickHouse
server (a "cluster of one"), the CIM/schema mapping, and the security tradeoffs. The **multi-node HA
distributed tier** (sharding, `ReplicatedMergeTree`, Keeper, stateless ingest, per-tenant `database`
isolation, hot→cold tiering) is a **multi-quarter roadmap — NOT built** (see the design RFC, §3 and Phases 3–4).

---

## 1. What this is (and is not)

| | Single-node adapter (**this doc, built**) | Multi-node HA (RFC §3, **not built**) |
|---|---|---|
| Topology | one ClickHouse server (cluster of one) | shards + replicas + Keeper |
| Engine | `MergeTree` | `ReplicatedMergeTree` + `Distributed` |
| Ingest | daemon writes batches directly | stateless ingest tier, N replicas + durable spool |
| Tenant key | one `database` per `Client` | per-tenant `database`/cluster, `StoreLocator` |
| Dedup | none (`MergeTree`), see §5 | `ReplacingMergeTree` eventual (OPEN) |
| Async read | blocking runtime in `spawn_blocking` (GAP-2 opt A) | native async + pooling (GAP-2 opt B) |

The single-node cut proves **emission + executor + schema + batched ingest** on a real ClickHouse
before distribution's failure modes are added. It is the correctness milestone, not the scale ceiling.

---

## 2. How the adapter works

Two first-party pieces behind the two already-cut seams (nothing new invented — see RFC §0):

- **`ClickHouseDialect : Dialect`** (`core/src/soql.rs`) — the GXQL compiler is **unchanged**; only the
  ~8 emission fragments are re-mapped to ClickHouse SQL (`JSONExtractString`, `toFloat64OrNull`,
  `intDiv(ts,span)*span`, `arrayStringConcat(groupUniqArray(...))`, CH string fns for `mitre_parent`,
  `positionCaseInsensitive`, identifier backticking, literal escaping). Carried by
  `Schema::events_clickhouse()`. **Pure text, zero `clickhouse` crate dependency** — default schemas
  stay on `SqliteDialect`, mode-0 parity intact. Emission is already unit-tested in core
  (`clickhouse_dialect_emits_clickhouse_fragments`, `events_clickhouse_compiles_via_clickhouse_dialect`).

- **`ClickHouseStore : guatx_core::store::EventStore`** (`daemon/src/ingest/clickhouse_store.rs`,
  `#[cfg(feature = "clickhouse")]`) — the write + GXQL-read impl:
  - **Ingest (batched).** `insert_events` opens one `Insert<ChEventRow>` (`RowBinary`) and writes the
    whole batch before `end()` — the native batched insert (ClickHouse collapses under row-at-a-time
    inserts). `insert_event` = a batch of one. Typed `Ch{Event,Metric,Snapshot}Row` mirror the SQLite
    columns; the `RowBinary` insert targets columns **by name**, so DDL column names must match the row
    structs (asserted by the `event_ddl_mirrors_insert_columns` test).
  - **Query.** `soql_to_sql` compiles via `Schema::events_clickhouse()` (the store **owns** emission —
    never a pre-fabricated SQL string handed in). `query_soql` executes with `fetch_bytes("JSONCompact")`
    and returns the **same** `{columns, rows, stats}` JSON shape as the SQLite/DuckDB executors, so
    handlers are backend-agnostic.
  - **Sync↔async bridge (GAP-2 option A).** The SPI is synchronous; ClickHouse is async/HTTP. The store
    carries a dedicated `current_thread` tokio runtime and `block_on`s inside the daemon's existing
    `spawn_blocking` read wrapper — smallest blast radius, `SqlcipherStore` stays byte-identical.
  - **Watchdog + cancel (GAP-4).** `budget_ms → max_execution_time`, `qid → query_id` set as ClickHouse
    query SETTINGS (server-side `KILL QUERY`).

### 2.1 Enabling it

Build with the feature (the default SMB build does **not** link the `clickhouse` crate):

```bash
cargo build --release --features clickhouse
```

Point at a ClickHouse server and select the store at runtime:

```bash
export PLUME_STORE=clickhouse            # opt-in; unset ⇒ SqlcipherStore (default, untouched)
export PLUME_CLICKHOUSE_URL=http://ch-host:8123
export PLUME_CLICKHOUSE_USER=plume       # optional
export PLUME_CLICKHOUSE_PASSWORD=…       # optional
export PLUME_CLICKHOUSE_DATABASE=plume   # optional; the Client carries the database (= tenant key today)
```

`ClickHouseStore::from_env()` reads these; `ensure_schema()` provisions the tables idempotently
(`CREATE TABLE IF NOT EXISTS`). Run once at startup on a scale deployment.

> **Note — runtime selection wiring is a follow-up.** The store, dialect, DDL and executor are built and
> tested. The `PLUME_STORE=clickhouse` *dispatch* that swaps `store()` for a `ClickHouseStore` across the
> ~82 daemon call-sites is the deferred Phase-0-completion follow-up (RFC §6.1: the neutral SPI is
> mounted and proven backend-neutral, but the call-site migration is intentionally staged to protect
> mode-0 parity). Until that lands, the adapter is exercised via its own API + tests, not by flipping the
> env var in prod.

---

## 3. Schema / CIM mapping (DDL)

`ClickHouseStore::schema_ddl()` returns three `CREATE TABLE IF NOT EXISTS … ENGINE = MergeTree`
statements mirroring `db/schema.sql`. Column **names are identical** to the SQLite tables and the
`Ch*Row` structs, so every GXQL query / rule / panel resolves the same fields.

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

Mapping notes:
- **Types.** SQLite `INTEGER→Int64`, `REAL→Float64`, `TEXT→String`. Columns that are `NOT NULL` in SQLite
  (`env_id`, `origin`, `engagement_id`) become `String DEFAULT …` — never NULL, matching the value the
  SQLite path stores (the insert binds `'prod'` for `env_id=None`, `''` for `origin`/`engagement_id`).
  Optional columns (`host`, `src_ip`, …, `dedup`, `fields`) become `Nullable(String)`.
- **`ORDER BY`** is the MergeTree sparse-index / sort key: `event` mirrors the SQLite indexes
  (`idx_event_src`, `idx_event_ts`) plus env scoping (`ORDER BY (env_id, source, ts)`).
- **`PARTITION BY toYYYYMM(toDateTime(ts))`** (`ts` = epoch seconds) — monthly partitions so retention
  purge is a cheap `DROP PARTITION` at multi-TB scale, not a mass `DELETE`.
- **`fields`** stays a JSON `String`; `ClickHouseDialect.json_extract` emits `JSONExtractString(fields,'X')`.
  (The SQLite hot-field expression-index optimization has no MergeTree equivalent — see RFC §4; the
  equivalent would be `MATERIALIZED` columns / skip-indexes, deferred.)
- **`metric`/`snapshot`** carry exactly the columns the SQLite `INSERT` binds (no `env_id` column — the
  SQLite metric/snapshot inserts omit it too), keeping stored data at parity with the row structs.

---

## 4. Injection safety

**Reads go through the same GXQL compiler.** `ClickHouseStore::soql_to_sql` calls
`guatx_core::soql::to_sql(…, Schema::events_clickhouse())` — the identical pipeline compiler as SQLite,
only the emission fragments differ. Every reviewed guard still applies:
- the **closed compiler** (GXQL is not raw SQL; commands/functions are a closed enum),
- the **masking chokepoint** (`soql_field`) and field-filter injection points,
- `soql_esc` / `quote_ident` literal + identifier escaping (ClickHouse variant) — proven by the
  `store_soql_literal_is_escaped` test (`a'b` → `'a''b'`).

No SQL string is ever handed to the store pre-fabricated; the store **owns** emission.

**Secret-column denylist — flagged, SQLite-specific today.** The hot-path denylist that refuses
`user.hash` / `token.token_hash` *even for admin* lives in the **SQLite read-pool column authorizer**
(`main.rs`, `run_query_ex`). It is a `rusqlite`-`Authorizer` mechanism and does **not** transfer to
ClickHouse. This is **acceptable and by design** because those secret columns are **control-plane** and
are **never** in ClickHouse — only `event`/`metric`/`snapshot` (the data/control frontier, RFC §0.1). So
there is no secret column for a ClickHouse query to reach. If control-plane tables were ever moved to
ClickHouse (they are **not** in scope, ever), the equivalent enforcement would have to be re-implemented
as a denylist in the `ClickHouseDialect`/executor (never emit secret columns) plus ClickHouse
`GRANT`/row-policy — that is explicitly out of scope for #18.

**Field-filter masking (#45) — flagged gap.** Role/tenant/env field masks are emitted at the `soql_field`
chokepoint and are wired today only on the internal `SqlcipherEventStore::soql_to_sql_masked`; the
**backend-neutral** `EventStore::soql_to_sql` carries no `masks` argument. The core dialect is
mask-capable (`Schema::…with_masks(...)`), so ClickHouse masking is *emission-ready*, but the neutral SPI
would need a masked read entry before a restricted role queries the scale tier. Until then the neutral
trait's default is **fail-closed** (a store that cannot mask refuses a masked compilation rather than
leak an unmasked query). Wire `soql_to_sql_masked` onto the neutral SPI before exposing the scale tier to
restricted roles.

---

## 5. Security tradeoffs — read before enabling

The scale tier is **not** a drop-in with the same guarantees as the SMB hot tier. The honest costs
(full inventory in RFC §3.4 / §4):

- **At-rest encryption is DOWNGRADED.** SQLCipher gives **whole-file AES with a per-tenant key held by
  the app**: steal the file/backup ⇒ useless without the key; RGPD erasure = throw the key. ClickHouse
  has **no equivalent** — its at-rest story is **disk/volume encryption (LUKS/cloud KMS)** or per-column
  codecs. The single-node adapter, as built, stores `event`/`metric`/`snapshot` **unencrypted at the
  application layer** unless you configure ClickHouse-side encryption (encrypted disk / KMS). **This is a
  genuine reduction of the at-rest guarantee.** SMB customers who chose plume *for* app-held-key crypto
  should stay on the hot tier. The recommended multi-node story (per-tenant `database` + volume/KMS
  encryption, RGPD erasure = `DROP DATABASE`) is operator/KMS-grade, **not** SQLCipher app-held-key-grade
  — and it is **not built** here.
- **No exactly-once dedup.** SQLite's `event.dedup UNIQUE` + `INSERT OR IGNORE` gives exactly-once. The
  `MergeTree` DDL here has **no unique constraint** — duplicates are possible. Eventual dedup via
  `ReplacingMergeTree(ts)` keyed on `dedup` is the documented (OPEN) prod option, deferred.
- **Wider raw-data blast radius.** A compromised daemon holds cluster credentials for the data it serves
  (vs. a per-tenant SQLCipher key that must be individually unlocked). State it plainly.
- **Backup/restore differs.** The `age(zstd(plain))` per-file backup is a *file* primitive; ClickHouse
  backup is `BACKUP`/`clickhouse-backup` to object storage — a different mechanism, not wired here.

**Bottom line:** enable the ClickHouse tier for scale/analytics (multi-TB/day, months of retention,
columnar speed) on an ESN/MSSP deployment with a platform team and KMS/volume encryption configured —
explicitly, like `PLUME_MULTI_TENANT=1`. Never as the SMB default.

---

## 6. Test coverage (what's proven vs. what needs a live server)

Unit-tested offline (`cargo test --features clickhouse`, no ClickHouse server):
- `store_soql_compiles_via_clickhouse_dialect` — the adapter compiles GXQL through the CH dialect
  (`JSONExtractString`, `arrayStringConcat(groupUniqArray(...))`), no SQLite fragment leaks.
- `store_soql_time_bucket_is_clickhouse_intdiv` — `timechart span=1h` → `intDiv(ts,3600)*3600` (grain
  parity with SQLite).
- `store_soql_literal_is_escaped` — injection-safety: `a'b` → `'a''b'` through the shared chokepoint.
- `schema_ddl_is_mergetree` — all three DDLs are `MergeTree`, idempotent, monthly-partitioned.
- `event_ddl_mirrors_insert_columns` — every `EVENT_INSERT_SQL` column exists in the DDL (RowBinary
  by-name parity); `env_id`/`origin` defaults present.
- Core emission is separately proven in `core/src/soql.rs`
  (`clickhouse_dialect_emits_clickhouse_fragments`, `events_clickhouse_compiles_via_clickhouse_dialect`).

Needs a live ClickHouse (deferred, `#[ignore]`):
- `live_roundtrip_ensure_insert_query` — `ensure_schema` + batched `insert_events` (`RowBinary`) +
  `query_soql` round-trip. Run with a reachable server:
  `PLUME_CLICKHOUSE_URL=… cargo test --features clickhouse -- --ignored`.

The **default** `cargo test` (SqlcipherStore only) is unchanged and green — the ClickHouse module and its
tests are not compiled without `--features clickhouse`.
