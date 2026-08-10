# Module map — a contributor's guide to the subsystems

This is the "which box do I open, and what can I safely touch" map for `plume-daemon`. It
complements — does not repeat — [`../ARCHITECTURE.md`](../ARCHITECTURE.md) (system design)
and [`CIM.md`](CIM.md) (event taxonomy). Read those for the *what/why*; read this for the
*where* and the *don't-break-this*.

Ownership verdicts ("safely ownable independently?") reflect a modularity review: the
codebase is modular with clean handler↔service↔store layering; the caveats below are the
few real cross-module tentacles.

---

## The `guatx-core` boundary

`guatx-core` (the shared crate published at [`guatxlabs/core`](https://github.com/guatxlabs/core), consumed by the daemon via a pinned public git-dep; a dev monorepo may override it with a local path) is the
shared ~70% between Plume (blue) and Forge (red). The daemon depends on it **one-directionally**;
the core never depends on the daemon and must never gain a `rusqlite`/SQLCipher dependency.

| Core module | Surface | Notes |
|-------------|---------|-------|
| `soql` | The closed GXQL compiler → read-only SQL; `Dialect` SPI, `FieldMaskSet`, `soql_field`/`soql_filter_field`, `SOQL_PIPE_COMMANDS` | The single query engine, shared with Forge. `soql_tests.rs` is its parity harness. Field-masking choke-point lives here. |
| `store` | Neutral **`EventStore` SPI** DTOs (`EventRow`/`MetricRow`/`SnapshotRow`, `Rows`/`QueryStats`) | Pure data contract — no rusqlite. The `EventStore` trait's only prod impl (`SqlcipherStore`) stays in the daemon. Enables pluggable backends (DuckDB/ClickHouse/Parquet). |
| `secret` | **`SecretProvider` SPI** (`SecretValue` over `secrecy`/`zeroize`) | Redacted Debug, zeroized on drop. |
| `cim`, `attack`, `ti` | Common information model, ATT&CK, threat-intel DTOs | Taxonomy shared blue/red. |

Core features: `forge` (Forge-only schema, OFF for Plume) and `cold_tier` (gates one additive
type-erased `StoreHandle::Parquet` variant — no `parquet` dep reaches the core).

---

## Daemon subsystems

`daemon/src/`. "Ownable independently?" = can a new contributor take this box without
tripping a cross-module invariant.

### Ingest (data-plane in)
| Path | Purpose | Boundary | Ownable? |
|------|---------|----------|----------|
| `ingest/mod.rs`, `ingest/store.rs` | Ingest pipeline + the `EventStore` SPI mount (`SqlcipherStore`) | `POST /api/ingest` → normalize → store | Yes |
| `ingest/{hec,minio,otlp,pubsub,firehose,obs,federated,endpoint}.rs` | Alternate receivers (Splunk HEC, S3/MinIO, OTLP traces, pub/sub, …) | Each gated by a `PLUME_*` runtime flag (mode 0 when off) — **except `federated.rs`, which is an inert scaffold: no route/handler calls it and no flag gates it** | Yes, per-receiver |
| `ingest/{duckdb,clickhouse}_store.rs`, `ingest/clickhouse_ha.rs` | Feature-gated alternate backends behind the `EventStore` SPI | `#[cfg(feature=…)]`; absent from default build | Yes (isolated by feature) |
| `parsers.rs`, `processors.rs`, `datamodels.rs`, `overlays*.rs` | Parse/normalize/enrich; config.d overlays | CIM contract (see `CIM.md`) | Mostly — respect CIM stamping |

### Handlers (HTTP surface) — `handlers/`
Handler↔service↔store layering is clean. `handlers/mod.rs` is the module registry (each entry
is annotated with its feature #). Large but flat: `query`, `search`, `soql_meta`, `cases`,
`caseops`, `incidents`, `alerting`, `alerts`, `detection`, `detection_advanced`, `dashboards`,
`datamodels`, `governance`, `compliance`, `idp`, `field_filters`, `rba`, `threat_intel`,
`tokens`, `engagement`, `freshness`, `fleet`, `system`, `destinations`, `notifiers`,
`scheduled_reports`, `saved_queries`, `knowledge`, `playbooks`, `actions`, `workflow_actions`,
`index_policies`, `prefs`, `users_lookups`, `admin_ui`, `overview`, `datasource`.

| Group | Purpose | Ownable? |
|-------|---------|----------|
| `handlers/connectors/` (`mod`, `defender`, `taxii`, `httppull`, `presets`) | External source connectors + SSRF-guarded egress choke-point | **Yes** — cleanest independently-ownable box (per audit). All egress funnels through `ssrf_guard`. |
| `handlers/detection.rs`, `handlers/detection_advanced.rs` | Detection rules, reparse/backfill | **Mostly** — one tentacle: `parser_reparse` clamps its lower bound to `hot_cutoff` via `cold_store::reparse_lower_bound` when the cold tier is on (immutable-cold invariant, H2). Touch reparse ⇒ understand cold aging. |
| `handlers/query.rs`, `handlers/soql_meta.rs`, `handlers/search.rs` | Query surface | Guarded — sits on the GXQL/masking choke-points (see invariants). |

### Query execution & aggregation
| Path | Purpose | Ownable? |
|------|---------|----------|
| `query_exec.rs` | Bounded read executor: per-`db_path` read pool (LRU, cross-DB cap 8), watchdog budgets, in-flight cancel registry, `stmt.readonly()` guard, DENY authorizer | Guarded — the enforcement point for read safety + budgets |
| `soql_glue.rs` | Wires the daemon into `guatx_core::soql` (schema/dialect/mask injection) | Guarded — masking injection lives here |
| `rollups.rs`, `rollup_route.rs`, `topn_cap.rs` | Precomputed aggregates + transparent rollup routing (the 2 GB strategy). `topn_cap` owns **a top-N cap is never declared without its magnitude**: `truncated` is a type, not a bool — the only way to declare a cap is `Cap::top_n(probe)`, which *requires* the query that quantifies it, and `apply_rollup_stats` takes the *measured* value, so declaring truncation without measuring it does not compile. | Mostly yes |

### Auth / identity / governance
| Path | Purpose | Ownable? |
|------|---------|----------|
| `auth.rs`, `session.rs`, `rbac.rs` | Password/session/RBAC. `rbac.rs::route_min_role` is a flat policy `match`; `rbac_gate` is fail-closed default-deny | Guarded — the RBAC allowlist is security-critical |
| `idp.rs`, `handlers/idp.rs`, `scim.rs` | Native IdP (OIDC/JWT/TOTP), SCIM provisioning; LDAP/SAML feature-gated | Mostly — pure fns un- gated, network bind gated |
| `governance.rs`, `handlers/governance.rs`, `compliance.rs` | Legal-hold, ledger export, composable roles, compliance mapping | Yes |
| `purge.rs`, `handlers/purge.rs` | Explicit **event purge** (beyond time-based retention): typed scope (mandatory time window + named identifiers, no free predicate), two-phase plan→token→apply, refusals (legal hold, cold tier, case-cited, FTS desync), mandatory hash-chained ledger inscription | **Guarded — the only non-retention DELETE on `event`.** See [PURGE.md](PURGE.md) |
| `tenants.rs` | Multi-tenant routing/key/RBAC (mode `PLUME_MULTI_TENANT`, default OFF) | Guarded — per-tenant isolation invariant |
| `field_filter.rs`, `handlers/field_filters.rs` | Field-level masking (#45); resolves caller → `FieldMaskSet`; arms SQLite authorizer for DENY on real columns | **Guarded — the masking choke-point.** |

### Storage / lifecycle
| Path | Purpose | Ownable? |
|------|---------|----------|
| `migrate.rs` | Append-only migration registry (exemplary; convergence with `db/schema.sql` guarded by tests) | Yes — append only, never edit history |
| `maintenance.rs`, `disk.rs` | Retention, disk-pressure guard (statvfs), housekeeping | Yes |
| `compactage_fts.rs` | **FTS5 segment compaction (P10.7-b)** — a retention purge makes the full-text index *grow* (an external-content FTS5 table cannot remove a posting; the `event_ad` trigger writes a *delete* posting that ADDs), and nothing in the daemon ever merged segments. Runs at the end of `retention_run` and from `plume-daemon fts-compact`, in bounded passes (`merge` with a **negative** budget — the positive one never reaches the floor) with the writer lock released between passes. The outcome is a TYPE: no variant other than `Rendue` can report reclaimed bytes | Yes — but keep the budget negative and the outcome typed |
| `backup.rs` | Compressed+encrypted backup `age(zstd(charge))` — charge is a streamed typed dump by default (no plaintext file on disk), or a full SQLite copy on the legacy path; symmetric (SQLCipher key) or asymmetric recipient; restore detects both by header marker | Guarded — scrypt lockstep with cold crypto |
| `cold_store/` | Opt-in cold Parquet tier — see submodule map below | Reader path **now yes** (post-split); writer/aging guarded |
| `vieillissement_serie.rs` | **What a cold aging pass cost (P10.5-a)** — one journal line *and* one series in `metric` per pass: days (candidate/aged/deferred/failed/skipped), rows written to Parquet, rows actually deleted from hot, files, on-disk bytes, duration, **thread** CPU, and a **window-scoped** RSS peak (`VmHWM` reset to the current RSS via `/proc/self/clear_refs`, then validated — the raw `VmHWM` is a since-boot maximum and would report an unrelated peak). A suspended pass publishes **no** work counters, only a named `..._ok{cause}=0`: a hole means "not measured", never zero. **Deliberately NOT feature-gated** (same reason as `cold_banniere.rs`): the publication logic and the measurement instrument must be testable in the DEFAULT build; only the caller (`cold_store/aging.rs`) is gated | Yes — pure functions + one bounded window per pass (179 µs measured 2026-08-10) |
| `cold_banniere.rs` | The `[cold]` startup line: which of three states this binary is in — capability **not compiled in**, compiled but runtime-disabled, or active (root dir, hot window, cold retention, day-file count + volume). **Deliberately NOT feature-gated**: the "not compiled in" case cannot be spoken by `cold_store/`, which does not exist in that build — and that is the case that left production believing in a cold tier the binary no longer carried. Only the state *harvest* has two `cfg` bodies. | Yes — pure phrases + a bounded `readdir`; no `event` scan |

### Server / state / entry
| Path | Purpose | Ownable? |
|------|---------|----------|
| `server.rs` | `run()` boot: config → open/migrate DB → seed_* → background jobs → router (**245 routes**, mesuré 2026-08-06 : `sed 's\|//.*\|\|' server.rs \| grep -c '\.route('` — chaque route peut porter plusieurs méthodes HTTP, le nombre de handlers est donc plus élevé) | Guarded — the boot god-function; changes here are deploy-gated |
| `state.rs` | `AppState` (config carrier + shared handles) | See caveat below |
| `main.rs` | CLI subcommands (backup/restore/…), glue | — |
| `metrics.rs`, `knowledge.rs`, `seeds.rs`, `ledger.rs`, `sigma.rs` | Metrics, knowledge objects, seed data, audit ledger, Sigma→GXQL importer | Mostly yes |

---

## The `cold_store/` submodule map (post-split)

Feature `cold_tier` (OFF by default) + runtime `PLUME_COLD_TIER`. `mod.rs` is a thin façade
(shared constants, the scrypt compile-assert, submodule decls, `pub(crate)` re-exports). Each
submodule owns exactly one invariant, stated at the top of its file:

| Submodule | Owns / invariant |
|-----------|------------------|
| `exactness` | **No derived value from a truncated set is ever rendered as a number.** Truncating a *materialisation* is legitimate (real rows, flagged incomplete); truncating an *aggregate* is a wrong number. Carried by types: a truncated `ColdAnswer` sequesters its `Value`, the only way out is `render(AnswerShape)`, and `AnswerShape` has no literal constructor — it is *derived* from the query, default-refusing every unknown pipeline stage. A future aggregate is covered without being named. |
| `crypto` | **At-rest encryption.** HKDF-SHA256 domain-separated key (`plume-cold-aead-v1`) from the tenant SQLCipher key; age STREAM AEAD (ChaCha20-Poly1305, random per-file nonce + chunk counter → no nonce reuse). Cold ON **requires** encryption → fail-closed if key unavailable. |
| `schema` | Columnar `ColdRow` + Parquet schema. Thin cols first, fat (`message`/`fields`) last; ZSTD; declared sorted on `ts`. |
| `identity` | **(env_id, day, seq) binding** stamped in the AEAD Parquet footer + **VERIFY** (full decode) before any hot DELETE. Closes intra-tenant day↔day / env↔env / seq swap. |
| `paths` | On-disk layout `<cold root>/<env_id>/<YYYY-MM-DD>-<nnnn>.parquet`; **per-tenant cold root** derived from the tenant `db_path` (FIX #2). |
| `seal` | Per-file `cold_seal` index (in the SQLCipher DB → confidential). Crash-safety commit marker (`last_file=1`), prune without decrypting. |
| `writer` | Streamed per-file writer + **Phase 1** of aging: size-bounded files, each durably sealed (fsync+VERIFY+rename+seal) **before** any hot DELETE. |
| `aging` | **Two-phase state machine + crash-safety (H1/H2).** Tail guard H1 (rowid-reuse), cold-immutability vs reparse H2, verify-before-delete, retention math. |
| `reader` | **Masking deferred to P3.** `hydrate_cold` produces raw unmasked rows in an ephemeral in-mem table — **never wired into a user query path**. Cold rows become user-reachable only through the *same* compiled GXQL + `FieldMaskSet` + authorizer as hot (a temp `event` view shadowing `main.event`). |
| `backup` | Incremental verbatim escrow of sealed day-files (plan only; sidecar runs `mc cp`). Symmetric by design; daemon never deletes remote objects. |

---

## Security invariants — MUST NOT break {#security-invariants}

| Invariant | Where it lives | How it's guarded |
|-----------|----------------|------------------|
| **Field-masking choke-point** — every user-visible field passes one masking point before aggregation/rename | `core/src/soql/mod.rs::soql_field`/`soql_filter_field`; injected via `field_filter.rs` → `FieldMaskSet` | Named fns + contiguous module; tests; non-GXQL surfaces reuse `mask_json_value` |
| **DENY authorizer** — DENY on a real column holds even for raw admin SQL | `query_exec.rs` SQLite authorizer, fed by `field_filter.rs` `PHYSICAL_EVENT_COLS` | Set at `prepare()`; secret denylist (`user.hash`/`token.token_hash`) |
| **Closed GXQL grammar** — reads are compiled, read-only; raw SQL is admin-only | `guatx_core::soql`; `stmt.readonly()` guard in `query_exec.rs` | Closed command enum; readonly assert |
| **Cold at-rest encryption + fail-closed** — cold never written in clear; no key ⇒ nothing aged/written/deleted | `cold_store/crypto.rs` | HKDF domain separation; fail-closed on missing key |
| **Per-tenant isolation** — tenants disjoint by key and cold root | per-tenant SQLCipher key; `cold_store/paths.rs` cold root from tenant `db_path` | Key + path derivation; `tenants.rs` |
| **Crash-safety: verify-before-delete** — hot rows deleted only after the cold file is proven decodable | `cold_store/{aging,identity,seal}.rs` | Two-phase machine; `last_file=1` commit; full-decode VERIFY |
| **scrypt lockstep** — cold AEAD work-factor fixed and matched to the backup/age crypto | `cold_store/crypto.rs` (`COLD_SCRYPT_LOG_N`), `backup.rs` | Compile-time assert in `cold_store/mod.rs`; fixed work factor |
| **No false number from the cold tier** — a value derived from a truncated read is never serialised | `cold_store/exactness.rs`; the three `cold_union_query` call sites in `handlers/query.rs` | `ColdAnswer::Truncated` sequesters its `Value`; `AnswerShape` is derivation-only and default-refuses unknown stages; hot-vs-cold parity test over the row cap |
| **Fail-closed RBAC** — unknown role/route ⇒ deny | `rbac.rs` (`rbac_gate` default-deny, `route_min_role`) | Flat policy `match`; ~200 fail-closed/rbac_gate test sites |

---

## The `AppState` caveat (no compile-time subsystem wall)

`AppState` (`state.rs`) is a **config/handle carrier**, not a god-object (the audit confirms
this) — but it *is* shared, so there is **no compile-time wall** stopping one subsystem from
reaching into another's concerns through it. Reaching across is *possible*; **don't**. Keep
subsystem interactions on their declared boundaries (SPIs, handler→service→store), and let the
per-module invariant headers, not `AppState` reach-through, be how subsystems compose.

---

## Boundaries worth clarifying (open questions for the maintainer)

- **`server.rs::run()`** is the one true god-function (config + DB open/migrate + ~40 `seed_*`
  + background spawns + ~340-route table). The audit proposes splitting into `boot_config` /
  `open_and_migrate_db` / `spawn_background_jobs` / `build_router`. Until then, ownership of
  "boot" is diffuse.
- **`detection` ↔ `cold_store` tentacle** (`reparse_lower_bound`): detection is otherwise
  independently ownable, but this coupling means a detection contributor must understand the
  cold immutability (H2) invariant. Worth an explicit interface if the team grows.
- **`main.rs`** still mixes CLI subcommands with glue — subsystem ownership of CLI vs runtime
  is not cleanly separated.
