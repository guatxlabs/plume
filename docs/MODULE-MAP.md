# Module map — a contributor's guide to the subsystems

This is the "which box do I open, and what can I safely touch" map for `plume-daemon`. It
complements — does not repeat — [`../ARCHITECTURE.md`](../ARCHITECTURE.md) (system design)
and [`CIM.md`](CIM.md) (event taxonomy). Read those for the *what/why*; read this for the
*where* and the *don't-break-this*.

Ownership verdicts ("safely ownable independently?") reflect a modularity review: the
codebase is modular with clean handler↔service↔store layering; the caveats below are the
few real cross-module tentacles.

Scope: `daemon/src/` (`*.rs`), `daemon/src/cold_store/` (`*.rs`), `web/` (`*.js`) — except `tests`.

The line above is read by a CI guard (`.github/scripts/check_module_map_matches_tree.py`). Each
scope entry names a directory and, in parentheses, the extension that makes a *module* there: what a
module is depends on the language of the tree, and a guard that assumed one language would only ever
hold half the product — the console went unread for exactly that reason. Every first-level module of
each directory — a `name.<ext>` file or a `name/` subdirectory, the excepted names aside — must have
a row in a table of a section whose heading names that directory, and every path a row's first cell
cites must exist in the tracked tree. The guard enumerates nothing: both lists are derived, from this
line and from `git ls-files`. A plan that nothing re-reads drifts; this one is re-read on every push.

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

## Daemon subsystems — `daemon/src/`

`daemon/src/`. "Ownable independently?" = can a new contributor take this box without
tripping a cross-module invariant.

### Ingest (data-plane in)
| Path | Purpose | Boundary | Ownable? |
|------|---------|----------|----------|
| `ingest/mod.rs`, `ingest/store.rs` | Ingest pipeline + the `EventStore` SPI mount (`SqlcipherStore`) | `POST /api/ingest` → normalize → store | Yes |
| `ingest/{hec,minio,otlp,pubsub,firehose,obs,federated,endpoint}.rs` | Alternate receivers (Splunk HEC, S3/MinIO, OTLP traces, pub/sub, …) | Each gated by a `PLUME_*` runtime flag (mode 0 when off) — **except `federated.rs`, which is an inert scaffold: no route/handler calls it and no flag gates it** | Yes, per-receiver |
| `ingest/{duckdb,clickhouse}_store.rs`, `ingest/clickhouse_ha.rs` | Feature-gated alternate backends behind the `EventStore` SPI | `#[cfg(feature=…)]`; absent from default build | Yes (isolated by feature) |
| `parsers.rs`, `processors.rs`, `datamodels.rs`, `overlays*.rs` | Parse/normalize/enrich; config.d overlays | CIM contract (see `CIM.md`) | Mostly — respect CIM stamping |
| `limite_corps.rs` | The ingest body-size cap, and **what it says when it bites**: the byte cap fires before the event-count cap, so the refusal names the limit, its unit and the lever (`P4.1-o`) | Wraps the router's body limit | Yes |

### Handlers (HTTP surface) — `handlers/`
Handler↔service↔store layering is clean. `handlers/mod.rs` is the module registry (each entry
is annotated with its feature #). Large but flat: `query`, `search`, `soql_meta`, `cases`,
`caseops`, `incidents`, `alerting`, `alerts`, `detection`, `detection_advanced`, `dashboards`,
`dash_ergonomics`, `panneau_resolu`, `panneau_avoue`, `datamodels`, `governance`, `compliance`, `idp`,
`field_filters`, `rba`, `threat_intel`, `tokens`, `engagement`, `freshness`, `fleet`, `system`,
`destinations`, `notifiers`, `scheduled_reports`, `saved_queries`, `knowledge`, `playbooks`,
`actions`, `workflow_actions`, `index_policies`, `prefs`, `users_lookups`, `admin_ui`, `overview`,
`datasource`, `sources`, `processors`, `purge`, `ai`. (This list is prose: the guard does not
re-read it, only the table rows below.)

| Group | Purpose | Ownable? |
|-------|---------|----------|
| `handlers/connectors/` (`mod`, `defender`, `taxii`, `httppull`, `presets`) | External source connectors + SSRF-guarded egress choke-point | **Yes** — cleanest independently-ownable box (per audit). All egress funnels through `ssrf_guard`. |
| `handlers/detection.rs`, `handlers/detection_advanced.rs` | Detection rules, reparse/backfill | **Mostly** — one tentacle: `parser_reparse` clamps its lower bound to `hot_cutoff` via `cold_store::reparse_lower_bound` when the cold tier is on (immutable-cold invariant, H2). Touch reparse ⇒ understand cold aging. |
| `handlers/query.rs`, `handlers/soql_meta.rs`, `handlers/search.rs` | Query surface | Guarded — sits on the GXQL/masking choke-points (see invariants). |
| `handlers/panneau_avoue.rs` | **How far back a panel could actually see, and where its number comes from (`P10.5-i`).** A dashboard panel never consults the cold band: its query runs over whatever retention (and cold aging) left behind, and the console drew the result as a *whole* curve. This vault owns the two mechanisms that decide it — compiling a panel (`PanneauCompile`, private fields, no production accessor) and the rendered-result cache table — so that **no** panel response leaves the daemon (served, cached, or frozen into a shareable snapshot) without `stats.coverage`: the horizon below which its window saw nothing, the window actually computed, and when that verdict was taken. Provenance has **three** states, not two: stamping `served_from:"raw", approx:false` on the opaque raw-SQL path would have *added* a lie to eleven shipped panels whose SQL reads a top-N-capped pre-aggregate — that branch publishes `provenance_non_derivee` instead, and never a figure it has not measured. The number itself is unchanged, byte for byte: this is "say it", not "fix it". Cost: one read-pool take plus one indexed `setting` read per panel response; zero added config disk reads (callers pass the `conf` they already load); no cold hydration. | Yes — one compile gate, one cache table, one horizon derivation |
| `imputation.rs` | **Which sources an alert is about, and where that name comes from (S7).** One author for the question, called by BOTH alert producers (`run_due_rules`, `check_heartbeats`) and read by per-source freshness. The answer comes from the **data** — the `source` column of the matched events, the typed probe descriptor for a mute sensor — never from the rule's prose: a deliberately generic rule (the ones the vendor-agnostic principle asks for) names no source in its text, so the old text scan imputed nothing and no source badge ever flipped. Preference order is written once, here: data, then the historical text fallback (the only path for opaque raw SQL), then a **named unknown** — never a silent nothing. The verdict is written onto the alert (`alert.sources`, v115) at raise time, so the read path (watchdog-bounded) guesses nothing. | Yes — pure encode/decode + one bounded read per firing rule |

### Detection evaluators & catalogue (background, not HTTP)
| Path | Purpose | Ownable? |
|------|---------|----------|
| `bilan_de_tick.rs` | **What a background tick renders (`P4.1-r`)**: the count of due items it ABANDONED, or the admission that it could not read its list — so the "detection" health cannot stay green while no rule is evaluated | Yes — one value type, written by every periodic evaluator |
| `controles_de_defense.rs` | **What a defence-control snapshot means, and what its alert renders (`P11.18-i`).** The shipped `control.catalog` alert announced a COUNT and nothing else — not which controls, not which machine, not since when — while all three answers were already stored: the control list in `alert.detail` (the collector payload copied at raise time, served and rendered nowhere), the machine in `alert.host` (bound by the INSERT, never selected), and the time bound in the `snapshot` series, which keeps one row per STATE because the heartbeat only touches the last one. This module reads those three and composes the sentence; it collects nothing new. It also carries the invariant: an EMPTY catalogue says so instead of rendering a green posture — the property is "zero control evaluated", never the REASON for the zero, so a catalogue removed or entirely disabled falls under it by construction. A payload that declares no list is a third case, not an empty one. | Yes — pure parsing/wording plus two bounded reads on the host-scoped snapshot series |
| `detection_aveugle.rs` | **A rule that cannot fire is an extinguished detection, and says so**: (`P3.9-a`) the cause of each abandon is kept (typed, not folded into `None`), and a rule abandoned tick after tick is surfaced as blind, not as calm; (`P9.5-a`) a rule whose query pins a `source` that **no shipped file emits and no shipped probe observes** is derived — never listed by name — so the seed can ship it dark instead of letting the ATT&CK matrix count its technique as covered — and because the seed only ever runs on a FRESH database, the same derivation is applied again at READ time (`lire_la_couverture_des_regles_activees`, the single point every coverage surface goes through, which returns THREE states rather than two: a rule that is enabled but that nothing on this base can feed is counted apart, WITH the sources it is missing — never folded back into "nobody ever wrote a rule"), where a source this base has actually RECEIVED events from also counts as a producer: an already-deployed install stops claiming a technique covered without anything being switched off | Yes |
| `collected.rs` | The **inertia oracle**: what the shipped collectors and agent really write into `fields.<X>` — deliberately separate from the Sigma field-alias table, because widening a translation must never silence an inertia warning | Yes — a table plus pure lookups |
| `attack_names.rs` | ATT&CK technique NAMES, served next to the identifier by the coverage matrix (`P11.6-a`); kept out of the shared core (a presentation datum) and held in lockstep with `guatx_core::attack::CATALOG` by a test | Yes |
| `maj_corroboree.rs` | **The SOC alerts on its own update (`P5.7-b`)**: the integrity collector watches the unit directory that `bootstrap.sh` writes into, so a deployment is told apart from a drop-in by corroboration, not by muting the rule | Yes — pure derivation over the shipped unit list |

### Feature-gated providers (absent from the default build)
| Path | Purpose | Ownable? |
|------|---------|----------|
| `ai/` (`mod`, `presets`) | Advisory AI layer (feature `ai`, OFF): feature gate (501 stub, mirror of the LDAP/SAML stub), cloud/local endpoint classification through the SSRF guard, call budget, and the HTTP provider impls; the daemon never executes generated text — the closed GXQL compiler disposes | Yes — behind `#[cfg(feature = "ai")]` |
| `sink_s3.rs` | S3-compatible object sink for the backup scheduler (feature `s3_backup`, OFF): SigV4 signing, streamed `PUT`, then `HEAD` read-back so "deposited" means "confirmed" — no SDK, no sidecar | Yes — behind `#[cfg(feature = "s3_backup")]` |

### Query execution & aggregation
| Path | Purpose | Ownable? |
|------|---------|----------|
| `query_exec.rs` | Bounded read executor: per-`db_path` read pool (LRU, cross-DB cap 8), watchdog budgets, in-flight cancel registry, `stmt.readonly()` guard, DENY authorizer | Guarded — the enforcement point for read safety + budgets |
| `soql_glue.rs` | Wires the daemon into `guatx_core::soql` (schema/dialect/mask injection) | Guarded — masking injection lives here |
| `rollup_coverage.rs` | **What the rollup covers, made undeclarable by a call site**: the right to serve a body from `event_rollup` is derived from what the job actually aggregated over the served range, not from the watermark alone (a late row written under the watermark was a permanent hole) | Yes — derivation only |
| `sqlite_plafond.rs` | **The memory ceiling of a single read**: what stops one query from taking the whole process. Three settings that do not play the same role — `temp_store` decides whether a sort can spill at all (shipped on `MEMORY`, a stated trade-off against plaintext temporaries), `cache_size` is the per-holder budget, `hard_heap_limit` is the ceiling that actually stops anything — and the per-holder value is DERIVED from the budget and the number of simultaneous holders, never written next to a constant it cannot see | Guarded — sits on the read path |
| `rollups.rs`, `rollup_route.rs`, `topn_cap.rs` | Precomputed aggregates + transparent rollup routing (the 2 GB strategy). `topn_cap` owns **a top-N cap is never declared without its magnitude**: `truncated` is a type, not a bool — the only way to declare a cap is `Cap::top_n(probe)`, which *requires* the query that quantifies it, and `apply_rollup_stats` takes the *measured* value, so declaring truncation without measuring it does not compile. | Mostly yes |

### Auth / identity / governance
| Path | Purpose | Ownable? |
|------|---------|----------|
| `auth.rs`, `session.rs`, `rbac.rs` | Password/session/RBAC. `rbac.rs::route_min_role` is a flat policy `match`; `rbac_gate` is fail-closed default-deny | Guarded — the RBAC allowlist is security-critical |
| `surface_publique_du_shell.rs` | **The only bytes an unauthenticated visitor receives.** FOUR EXACT, DERIVED lists that `auth_guard` lets through on GET/HEAD before any identity resolution: the entry document, what it and its stylesheet reference directly, and the closure of static ES imports from `/app.js`, and the font licence texts (SIL OFL 1.1 requires the licence to travel with the font files that are now served publicly). One predicate, `est_publique`, is the single door onto those lists, read by BOTH `auth_guard` and `budget_du_shell_public`. Behind a reverse proxy the root was already let through, so the defect only ever showed in the proxy-less modes (`host`, `docker`), where `GET /` answered `auth requise` in plain text and the module that paints the login overlay was never loaded | **Guarded — this is the public surface.** Never a prefix: a file dropped into `web/` tomorrow must not become public without a decision. `tests/fermeture_shell_spa.rs` recomputes the derivation and compares both ways, then proves it by SERVING |
| `budget_du_shell_public.rs` | **What the opened door costs, and its bound.** Serving the console to anonymous visitors moved the price of a credential-less request from 12 bytes / 0.21 ms of CPU to up to 1.9 MiB / ~6.5 ms of `gzip` (measured ON A BENCH — developer workstation, this tree's binary launched by hand, synthetic bursts; no installation is described — 2026-08-29) — while the two `rate_limit` ceilings that bounded that traffic had been sized when an anonymous request cost a 12-byte constant. Two sliding 10 s BYTE buckets, one per REAL client IP (`real_client_ip`, so per analyst and not per cluster behind a k3s Traefik) and one global, read by `rate_limit` on the SAME public-surface predicate the door uses | **Bound, not a cache.** A revalidation 304 carries no body, so it costs nothing: the bound weighs only on the client that omits the conditional header — i.e. on abuse. `0` disables a bucket |
| `acces_observe.rs` | **Who has access, and from where** — the account inventory used to be `SELECT … FROM user`, i.e. the accounts the product *creates*; an external-directory account (header SSO) has no row there and appeared nowhere while administering the console. Every identity resolved by the single auth choke-point is recorded with its provenance (derived from the auth method plus a lookup, never guessed), its effective role, where that role comes from, and when it was last seen. No secret ever enters the table; the write is debounced per identity and the table is capped | Yes — derivation + a bounded UPSERT |
| `idp/` (`mod`, `oidc`, `ldap`, `saml`, `totp`), `handlers/idp.rs`, `scim.rs` | Native IdP (OIDC/JWT/TOTP), SCIM provisioning; LDAP/SAML feature-gated | Mostly — pure fns un- gated, network bind gated |
| `governance.rs`, `handlers/governance.rs`, `handlers/compliance.rs` | Legal-hold, ledger export, composable roles, compliance mapping | Yes |
| `purge.rs`, `handlers/purge.rs` | Explicit **event purge** (beyond time-based retention): typed scope (mandatory time window + named identifiers, no free predicate), two-phase plan→token→apply, refusals (legal hold, cold tier, case-cited, FTS desync), mandatory hash-chained ledger inscription | **Guarded — the only non-retention DELETE on `event`.** See [PURGE.md](PURGE.md) |
| `tenants.rs` | Multi-tenant routing/key/RBAC (mode `PLUME_MULTI_TENANT`, default OFF) | Guarded — per-tenant isolation invariant |
| `field_filter.rs`, `handlers/field_filters.rs` | Field-level masking (#45); resolves caller → `FieldMaskSet`; arms SQLite authorizer for DENY on real columns | **Guarded — the masking choke-point.** |

### Storage / lifecycle
| Path | Purpose | Ownable? |
|------|---------|----------|
| `db_open.rs` | **THE door to a write connection on a plume database**: every production path that prepares a database goes through it (two shipped paths were outside and wrote to a base the daemon refused to serve) | Guarded — the single schema-convergence point |
| `crypto/` (`mod`) | SQLCipher open (`db_key`/`open_db`/`ensure_encrypted`), per-database key registry, Vault key resolution and TLS roots; the SQLCipher key is read by ONE path (`P8.7-b`) | Guarded — key handling |
| `migrate.rs` | Append-only migration registry (exemplary; convergence with `db/schema.sql` guarded by tests) | Yes — append only, never edit history |
| `maintenance.rs`, `disk.rs` | Retention, disk-pressure guard (statvfs), housekeeping | Yes |
| `db_ventilation.rs`, `ventilation_serie.rs` | **Where the bytes of the database go** (`P10.2-a`): the per-object breakdown (`db-stats --par-objet`), and the same breakdown as a SERIES over time, so a trend and a one-off relief are no longer mistaken for each other | Yes |
| `wal_empreinte.rs` | The write-ahead log's **residue** is bounded (what the file keeps after a burst); its **peak** is not, and the module says so rather than promising it | Yes |
| `tmp_possede.rs` | **The vault of the temporary directory**: the only holder of the system temp root; `build.rs` refuses to compile a direct call elsewhere, so fixtures own their container instead of enumerating what to delete | Yes — compile-time companion in `build.rs` |
| `compactage_fts.rs` | **FTS5 segment compaction (P10.7-b)** — a retention purge makes the full-text index *grow* (an external-content FTS5 table cannot remove a posting; the `event_ad` trigger writes a *delete* posting that ADDs), and nothing in the daemon ever merged segments. Runs at the end of `retention_run` and from `plume-daemon fts-compact`, in bounded passes (`merge` with a **negative** budget — the positive one never reaches the floor) with the writer lock released between passes. The outcome is a TYPE: no variant other than `Rendue` can report reclaimed bytes | Yes — but keep the budget negative and the outcome typed |
| `backup/` | Compressed+encrypted backup `age(zstd(charge))`, split into one façade and three submodules (below); callers keep the `crate::backup::X` paths through `pub(crate)` re-exports | Guarded — scrypt lockstep with cold crypto |
| `backup/mod.rs` | Façade: the envelope `age(zstd(charge))` — symmetric (SQLCipher key) or asymmetric recipient; fixed scrypt work factor; single configuration path for backup settings (`cfg()`, never bare `env::var`); plaintext-temp guard and orphan sweep; the legacy full-SQLite-copy path (`sqlcipher_export`); submodule decls and `pub(crate)` re-exports | Guarded — scrypt lockstep with cold crypto |
| `backup/dump_restauration.rs` | **The charge**: streamed typed dump B1 (`PLUMEDUMP1\n`, self-describing length-prefixed format, plan derived from `sqlite_master`, no plaintext file on disk), the `backup_compressed` dispatch (B1 by default, legacy fallback on a schema the dump cannot represent) and `restore_compressed`, which recognises the charge by its header marker (B1 dump or historical SQLite file), never by file name | Guarded — restore path |
| `backup/retention.rs` | **The only parser of archive names** (`classify_backup_name` → regular / premigrate / preschema / unparseable), GFS tiered prune plan (`backup_prune_plan`) and native keep-N plan (`backup_keep_recent_plan`): pure `names + now + params → names to delete`, no I/O, no credential; unparseable names are never deleted | Yes — pure, test-isolated |
| `backup/verification.rs` | Structural check of an `.age` header without decrypting (`inspect_age_header` → `BackupKind`), then **full verification re-opens the restored database and counts it** (`inventaire_restaure`, tables derived from `sqlite_master`, virtual/shadow tables excluded): an archive that decrypts and replays but yields **no row** is a failure, not a pass | Yes |
| `exercice_de_restauration.rs` | **Proof that a restore drill happened (P8.3-a)** — a backup nobody has ever restored is an unproven guarantee, and on the escrow mode the drill *must* stay offline (the private identity may not live next to the backups). A successful full verification emits a one-line **attestation** of facts only that drill produces; `plume-daemon restore-drill record` stores it in `meta`, `status` exits 3 when a drill is due. The derived state **ages** and is published as the `restauration` health component, `plume_restore_drill_overdue`/`_age_seconds`/`_last_success_timestamp_seconds`, and a non-purgeable SOC event emitted **from the backup path** (an install that never backs up has nothing to drill). A symmetric drill does not close the obligation of an install that escrows asymmetrically | Yes — pure state function + one `meta` row; never a scan |
| `cold_store/` | Opt-in cold Parquet tier — see submodule map below | Reader path **now yes** (post-split); writer/aging guarded |
| `vieillissement_serie.rs` | **What a cold aging pass cost (P10.5-a)** — one journal line *and* one series in `metric` per pass: days (candidate/aged/deferred/failed/skipped), rows written to Parquet, rows actually deleted from hot, files, on-disk bytes, duration, **thread** CPU, and a **window-scoped** RSS peak (`VmHWM` reset to the current RSS via `/proc/self/clear_refs`, then validated — the raw `VmHWM` is a since-boot maximum and would report an unrelated peak). A suspended pass publishes **no** work counters, only a named `..._ok{cause}=0`: a hole means "not measured", never zero. **Deliberately NOT feature-gated** (same reason as `cold_banniere.rs`): the publication logic and the measurement instrument must be testable in the DEFAULT build; only the caller (`cold_store/aging.rs`) is gated | Yes — pure functions + one bounded window per pass (179 µs measured 2026-08-10) |
| `cold_banniere.rs` | The `[cold]` startup line: which of three states this binary is in — capability **not compiled in**, compiled but runtime-disabled, or active (root dir, hot window, cold retention, day-file count + volume). **Deliberately NOT feature-gated**: the "not compiled in" case cannot be spoken by `cold_store/`, which does not exist in that build — and that is the case that left production believing in a cold tier the binary no longer carried. Only the state *harvest* has two `cfg` bodies. | Yes — pure phrases + a bounded `readdir`; no `event` scan |

### Server / state / entry
| Path | Purpose | Ownable? |
|------|---------|----------|
| `server/` | The HTTP server and its boot, split into one façade and its submodules (below); callers keep the `crate::server::X` paths through `pub(crate)` re-exports | Guarded — the boot god-function; changes here are deploy-gated |
| `server/mod.rs` | Façade: the HTTP layers (security headers + HSTS, per-IP/global rate limit, `Cache-Control` policy, panic→JSON), the opening PRAGMAs (`tune`), and the boot itself — `boot_config` → `open_and_migrate_db` → `seed_*` → background jobs → `run()` (control plane, TLS, bind); submodule decls and `pub(crate)` re-exports | Guarded — deploy-gated |
| `server/groupes_de_routes.rs` | **The routing table**: the cohesive per-domain sub-routers merged by `build_router` (**245 routes**, mesuré 2026-08-23 : `cat daemon/src/server/*.rs \| sed 's\|//.*\|\|' \| grep -c '\.route('` — chaque route peut porter plusieurs méthodes HTTP, le nombre de handlers est donc plus élevé), plus the six global layers, the fallback file service and the state injection, in the exact order the `router_*` sweeps interrogate. Read **as source** by the derived guards (`declared_route_table`), which resolve it by directory prefix, never by file name | Guarded — the composition is what the `router_*` sweeps defend |
| `server/sauvegarde_planifiee.rs` | **The native backup scheduler** (`OPS NATIVE #1`) — what makes `docker run` and the host binary self-backup with no sidecar and no init-container: the `PLUME_BACKUP_*` settings (interval 0 ⇒ no thread at all), the **fail-closed** resolution of an `s3://…` object destination under the `s3_backup` feature (a misconfigured remote never silently degrades to a local write under a remote name), the testable cycle `scheduled_backup_cycle` (compressed B1 backup → temp file → atomic rename → keep-N retention) and the posture signal a published archive must emit | Guarded — a silent scheduler is an unproven guarantee |
| `server/travaux_sur_la_base.rs` | **The background work that acts on the primary database itself**, as opposed to the per-tenant service loops: the incremental auto-vacuum (`OPS NATIVE #2` — bounded page batches, never a blocking full `VACUUM`, and an honest warning instead of silence when the base is not `auto_vacuum=INCREMENTAL`), the startup `ANALYZE`, the expression-index reconciliation and the index families created or dropped at bind, the FTS backfill, and the boot **read prewarm** that pays the cold SQLCipher decryption outside the first click. Every one of them waits on the `bound` flag or a post-bind grace, so none touches the writer lock before the port listens | Guarded — it holds the writer lock; keep every pass bounded |
| `server/boucles_de_fond.rs` | **The service loops and their launch**: ingest, the detection-rule scheduler, native-ban store maintenance, the connector and destination ticks, retention, scheduled reports, custom-role refresh, rollups and panel refresh. Each is a **dedicated thread** — a slow or dead network sink never delays local ingest — and iterates **per tenant** (mode 0 = a single pass over the primary base). The invariant of this file is the thread-creation order, the cadences, and cloning **at the call site**; `spawn_background_jobs` also starts, in that same order, the backup scheduler and the primary-database work | Guarded — order and cadence are the contract |
| `state.rs` | `AppState` (config carrier + shared handles) | See caveat below |
| `main.rs` | CLI subcommands (backup/restore/…), glue | — |
| `util/` (`mod`, `hexcrypto`, `http_client`) | Pure primitives with no `AppState` dependency: hex/sha256/hmac/constant-time compare, and the minimal HTTP/1.1 client (raw TCP + rustls) used by Vault, the Defender connector and the notifiers | Yes |
| `sondes.rs`, `sonde_de_flotte.rs` | **Freshness probes**: what a probe OBSERVES is typed, its query is DERIVED, and what bounds its cost is stated where the probe is born (`P3.7-a`); the fleet probe answers "is the PARK talking?" as a count, separate from the per-sensor probes (`P3.2-a`) | Yes |
| `sonde_du_magasin_de_secrets.rs` | **A secret store that can no longer serve is an extinguished key rotation, and says so (`P9.8-a`)**: the signal is about the STORE, never its consumers — one alert, not twenty-seven; it needs the whole window to be unanimous before raising, resolves on the first sample that saw at least one DECLARED store ready — "zero not-ready out of zero declared" is an absence, not health, so erasing the stores mid-incident no longer resolves the alert — and concludes NOTHING when nothing was reported (a silent collector never means "supply is back") | Yes |
| `mesure_environnement.rs` | **A measurement that fails does not render the most reassuring value (`S32`)**: process CPU/RSS and ingest-queue depth are `Mesure<T>` — read, or unreadable with a cause — never a zero | Yes |
| `tas_du_fil.rs` | Deterministic per-thread live-heap peak — a test-only allocator instrument (`#[cfg(test)]`, absent from the shipped binary) so memory properties are proven without the process RSS | Yes — test only |
| `metrics.rs`, `knowledge.rs`, `seeds.rs`, `ledger.rs`, `sigma.rs` | Metrics, knowledge objects, seed data, audit ledger, Sigma→GXQL importer | Mostly yes |
| `index_usage.rs` | **Which indexes actually serve, and whom (P10.9-a).** Owns the single plan reader (the closed-corpus replay in `tests/index_usage_event.rs` uses *this* one — a reading rule written twice diverges, and then the usage table lies) and the runtime observatory: at the single read passage point (`run_on_conn`, shared by the hot path and the hot∪cold union) it samples one `EXPLAIN QUERY PLAN` every N statements and counts, **per index × consumer class**, who named it. Label is an index name, never a query, and the registry is capped, so `/metrics` cardinality cannot grow with traffic or with the schema. It also publishes the **statistics regime** it read under (`none` / aggregated `sqlite_stat1` / **detailed** `sqlite_stat1+sqlite_stat4`), because a plan chosen without detailed index statistics is not representative for an index whose leading column is only probed by range — the named hole this key exists for. OFF by default (`PLUME_INDEX_USAGE_SAMPLE_N=0`, read through `cfg()`), and off means the exposition is the **empty string**, so `/metrics` is byte-identical. What the series does *not* prove travels in its `# HELP`, not only in a source comment | Yes — atomics + a capped registry; one extra *prepare* per sampled statement, after the caller's own elapsed time has been stopped |
| `query_timing.rs`, `semaphore_interactif.rs` | **The interactive concurrency bound, and what it costs (P7.8-a).** `query_timing` is the single gate that hands out a `query_sem` permit and splits a request's time (`prepare`/`sem_wait`/`exec`/`db_lock_wait`); `semaphore_interactif` publishes, per **route template**, the *wait* for a permit and the *work* done holding it — two series, because one total confounds "slow route" with "queued route" and the two have opposite levers. Route labels come from a `route_layer` reading `MatchedPath` (never the URL), and the label registry is capped, so `/metrics` cardinality cannot grow with traffic. **The label's SYNTAX is the router's, and the router changed it** (axum 0.7 wrote `/api/cases/:id`, axum 0.8 writes `/api/cases/{id}`): a `route=` selector written for an earlier plume matches nothing, and a series that vanishes never fires — it goes quiet. That fact travels in the `# HELP` of all six labelled series, written once and rendered six times, because whoever scrapes this daemon does not read its source. Derived guards refuse an acquisition outside the gate and a naked permit outside the measuring module | Yes — atomics + a few dozen registry entries; no DB access |
| `attente_serie.rs` | **What an aging pass costs an analyst, over time (P10.11-a).** A request's wait was measured but rendered *in that request's response*, so nothing could correlate it with the cold aging pass that caused it. This module publishes it as a series, on the same time scale as the pass's own window (`vieillissement_serie::chevauchement_us`), so "was this query slow because a pass was running?" is two points sharing a timestamp. **The shape was chosen by measurement, not habit**: on a local bench the mean understates the worst sample by 73x, and even the 99th percentile is *blind* at the regime closest to operation — it reads zero where an analyst waited. So: fixed **buckets** plus a **window maximum**, the only two forms that survive the hourly `metric_rollup` (a quantile does not re-aggregate; a max does, exactly). The sample is the **sum** of both queues a request crosses — permit wait *plus* shared-lock wait — which are disjoint intervals by construction, and the permit term is the *larger* one once the interactive bound saturates behind the pass. Cardinality is a **closed enumeration** (eleven name/label pairs), never a capped registry: no label can come from a request. What the series does *not* prove travels in its `# HELP` — it stays a **lower bound** on analyst cost | Yes — six relaxed atomics per request, no allocation and no extra clock read (both durations are already measured for the response); one flush of at most eleven `INSERT`s per rollup tick |

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
| `enonces` | **The SQL statements of aging, written once**, with their bounds — and the FIRING decision (`tir_du_retard`): the one full-scan statement (the lateness dead-man's-switch) is left intact but fired once a day instead of every hour, because columnarisation can only happen once a day by construction; the pass and the read-only probe read the same cadence here (`P10.13-a`). |
| `sonde_vieillissement` | The instrument that was missing: the PLAN and the stopwatch of each aging statement, on the live database, read-only (`plume-daemon cold-aging-plan`). |
| `vectorized` | Vectorised query engine over typed column batches, streaming row-group by row-group, never through SQLite; reuses the SAME `FieldMaskSet` masking as hot. |
| `planner` | Router: a query that is pure-cold AND vectorisable runs on `vectorized`; anything else returns `None` and the caller falls back VERBATIM on `cold_union_query` — the fallback is never duplicated. |

---

## The console — `web/`

The operator console is a **dependency-free ES-module SPA** served read-only by the daemon
(`ServeDir` fallback): no bundler, no framework, no build step — what is tracked here is what the
browser loads. `index.html` is the document; `app.js` is the single module it imports. The bulk of
these files came out of a monolithic `app.js` by pure move: bodies unchanged, only imports and
exports added. The remaining `app.js` ↔ view cycles are benign because the imported functions are
called at *execution* time (a click, after an `await`), never while a module is being evaluated.

Every module here except the service worker is linked by the ESM harness
(`.github/scripts/web_esm_harnais.mjs`), whose list is **derived from the directory**, not
enumerated: an import of a symbol that moved is a link error, the cascade reaches `app.js`, and the
interface stays blank — no Rust test can see that.

The `Kind` column tells four shapes apart. **service** — no view of its own; other modules import
it. **render** — owns one panel or view and is reached through the router. **registry** — content
only, imports nothing, re-read by a guard. **entry / shell / asset** — the document, its boot, and
what the browser fetches alongside.

### Shell, entry and shared services
| Path | Kind | Owns / exposes | Imported by |
|------|------|----------------|-------------|
| `app.js` | entry | Wraps `window.fetch` once (CSRF token, tenant and environment headers, the global in-flight progress bar), boots the console in the order the monolith did, registers the service worker, and re-exports the symbols the seam modules still read. It also still holds the panels never extracted — Overview, the Explore query bar and its back/forward history, Settings, the retention/sources/ledger admin wiring — so it is the one box here that does **not** reduce to a single concern | `alerts`, `admin_users`, `attack`, `cases`, `freshness`, `multitenant`, `viz` (at execution time only) |
| `navigation.js` | service | The two-level model of spaces and their sub-tabs (`SPACES`), resolution of the current tab from the hash (historic aliases; a forbidden or unknown tab falls back **without** rewriting the deep link), rendering of both levels, and routing to each view's loader. `initNavigation()` installs the hash listener, the sidebar and sub-tab clicks, and the burger | `app.js` |
| `login.js` | service | The front door: login form, logout, and the `GET /api/me` that decides between the application and the overlay. `initAuthGate()` is called where the block used to live, before the `fetch` wrapper is installed | `app.js` |
| `state.js` | service | The single mutable UI-state namespace `S`. ES-module imports are read-only *bindings*, so a module cannot reassign an imported `let`; every variable the seams both read and write lives here and is mutated as a property. Pure leaf — imports nothing | every module that shares mutable state (`viz`, `cases`, `connectors`, `alerts`, `dashboards`, …) |
| `core.js` | service | Shared UI primitives, with no business state and no import of `app.js`: DOM helpers (`$`, `esc`, `ic`), date and locale formatting, modals and toasts, the shared `disclosure` and `confirmWithConsequence` chrome, CSV/JSON/PDF export, `api()`/`apiSend()`, pagination | nearly every module |
| `recherche_de_liste.js` | service | The shared list-search field: normalisation (case and accents), the multi-word AND predicate, the filter over rows already in memory, the wiring of an `<input type="search">` (shared `.field` chrome, Esc clears) and the summary a filtered list owes its reader — how many of how many. Knows no domain: the caller names the searchable text of a row and hands the two summary phrases in as text nodes, so each panel's wording stays judged by the i18n guard in its own module. No network, no debounce — the rows are already loaded | `detection_admin.js`, `threatintel.js` |
| `composer_depuis_lexistant.js` | service | **The inventory of what the product already carries, offered to whoever composes** (`P11.13-a`): shipped query templates, the analyst's saved queries, and the reusable query of each detection rule, in one searchable list. Measured before it was written, and two of the four announced gaps turned out to be false — the template palette already offers templates *and* saved queries to whoever composes a query, and the transport to a panel already worked end to end, indirectly (palette → search bar → panel field). What was missing was choosing from the inventory *where one composes*, and starting from a RULE. A rule's query is not rewritten here: the daemon derives it (`query_reutilisable`, terminal scalar `stats` stage stripped for GXQL, raw SQL left intact with its window markers). A stock that could not be read is NAMED, never silently dropped — “no rules” and “I could not read the rules” are different sentences. Knows nothing of a dashboard; it returns a choice, the caller composes | `dashboards.js` |
| `copie_et_selection.js` | service | The console's contract with text selection and the clipboard: a click that stands down when the user has just selected text inside it (the result-table row and the alert title both navigated on the mouse-up that ended a drag, taking the selection with them), and THE copy gesture — one button, one icon, one on-screen answer, a refused clipboard admitted rather than hidden. Knows no domain: the caller hands it the element and the value. Changes no existing `user-select`: a one-piece secret is right to select as a block; what was missing was an explicit way out where there was none | `viz.js`, `alerts.js`, `admin_users.js`, `dashboards.js`, `system.js` |
| `prefs.js` | service | Per-user UI preferences (column config, dashboard favourites, per-view settings, default range): synchronous reads from memory, a localStorage mirror as the offline fast path, and a debounced write to a self-scoped endpoint. Never holds a secret — only UI state | `app.js`, `dashboards.js`, `login.js` |
| `keys.js` | service | Keyboard-driven navigation (`/`, `g` then a key, `j`/`k`, `?`): one document-level handler that never fires while the user is typing, while a modifier is held, or while a modal is open. Decoupled from the router — it drives `location.hash`, so there is no import cycle | `app.js` |
| `sw.js` | service | The PWA service worker: **network-first** app shell (the cache is the offline fallback, never the first answer), the API never cached, older cache versions purged on activate. Registered by `app.js`; the only module the ESM harness does not link, because it runs in a worker scope and not in the document | registered by `app.js` |

### Internationalisation
| Path | Kind | Owns / exposes | Imported by |
|------|------|----------------|-------------|
| `i18n.js` | service | The fr→en lexicon and `i18nWalk`, the exact-match walk that translates text nodes and displayed attributes. A displayed string with no entry stays in French, silently — which is why a CI guard holds the lexicon against what each module renders | `i18n_observer.js` |
| `i18n_observer.js` | service | Puts the lexicon on the **live** document: the initial walk, then the observer that translates what arrives afterwards — added elements and text nodes, and the displayed attributes (`title`, `placeholder`, `aria-label`, `label`). The dictionary and the walk stay next door; this module only installs them. Does not import `app.js` | `app.js` |

### In-app help
| Path | Kind | Owns / exposes | Imported by |
|------|------|----------------|-------------|
| `help.js` | service | The **mechanism** of in-app help: the `openHelp` opener, the single modal chrome, the guide page (index, glossary, shortcuts) and the delegated help handler. It carries no help text of its own, and a key with no section renders an admission naming the key rather than silence | `app.js`, `navigation.js` |
| `help_registry.js` | registry | The **content**, and only the content: one section per console panel, keyed, in both languages, rendered as preformatted text. Imports nothing. Its keys are the corpus of the help-trigger guard, and it is the one module exempt from the lexicon guard — over the scope of that object alone | `help.js` |

### Search, visualisation and dashboards
| Path | Kind | Owns / exposes | Imported by |
|------|------|----------------|-------------|
| `viz.js` | render | Explore and the charts: drilldown, sliding window, the interactive query (single flight, cancel-previous), table and chart rendering shared with dashboards, the truncation badge, the ban action | `alerts.js`, `app.js`, `cases.js`, `dashboards.js`, `dataaccess.js`, `multitenant.js` |
| `soql_complete.js` | render | Native IDE-like completion of the query bar. The vocabulary comes from the schema endpoint — derived from the closed compiler's own constants — so a suggestion is a **strict subset** of what compiles; plus the template palette | `app.js` |
| `savedqueries.js` | service | Per-user query templates, backed by an owner-scoped endpoint (the client never sends a user id), and the recent-query history held in the browser alone. Loading fills the bar **without** executing; the stored text is inert until it is run through the guarded query path | `app.js`, `soql_complete.js`, `viz.js` |
| `dashboards.js` | render | Tiles, panel grids (lazy load, render, export), shareable snapshot, slideshow, views and favourites. `initDashboards()` does the wiring at the point where the block used to live; `renderDashboard` is exported for the harness. Does not import `app.js` | `app.js`, `navigation.js` |
| `dataaccess.js` | render | Read-access governance: five panels over **existing** query surfaces, an analysis-window selector, a scope note, and a card order persisted locally. Does not import `app.js` | `navigation.js` |

### Detection and response
| Path | Kind | Owns / exposes | Imported by |
|------|------|----------------|-------------|
| `alerts.js` | render | The alert queue: rendering, group triage, drill, export, MITRE and source filters, and the single action bar. `alertListModel` and `alertActionBarHtml` are exported so the harness judges the rendered form | `app.js`, `detection_admin.js`, `navigation.js` |
| `cases.js` | render | Case management: list, detail, CRUD, and attaching items from the other surfaces. `caseBtn` is a pure render, judged by the harness | `alerts.js`, `app.js`, `navigation.js` |
| `detection_admin.js` | render | Detection administration: coverage, rules, notification channels, parsers, actions, the global mode, and playbooks — with the DOM wiring and initial loads. Its row models are exported so the harness can compare them with the other producer surfaces. Owns the rule search (the shared field, composed with the sort) and the two doors the ATT&CK matrix opens into it — the rules of a technique, and the form that would cover one | `app.js`, `attack.js` (injected), `navigation.js` |
| `detadv.js` | render | Advanced detection: multi-event correlations (finding groups) and UEBA baselines, each with an author-time backtest | `app.js`, `navigation.js` |
| `attack.js` | render | The ATT&CK coverage matrix: tactics as columns, techniques as cells shaded by coverage, so the **blind spots** are what stands out. If the endpoint is absent it says coverage is unavailable instead of failing hard. Owns the display name of a technique and the token used when that name is unknown, and the **door** a technique opens — its rules, its detections and the gesture that would cover it. Builds no query of its own: the detection exit is the pre-existing technique pivot, and the two exits that leave the panel are injected by the rule panel rather than imported from it | `app.js`, `detection_admin.js`, `navigation.js` |
| `risk.js` | render | Risk by entity: the entity list and, for one entity, its timeline and contributions — served from the rollup, so no event scan. Read-only | `app.js`, `navigation.js` |
| `runbooks.js` | render | Runbook authoring: shipped versus custom templates, phased steps with their kind, clone of a shipped one, enable and disable, delete. A runbook only *references* a response action; execution stays on the actions path | `navigation.js` |
| `sigmaimport.js` | render | Bulk Sigma import: archive upload or multi-document paste, then the returned summary — the **coverage delta** first, and every reject with its reason. Imported rules arrive disabled, and the panel says so and links to the rule list | `app.js`, `attack.js`, `detection_admin.js` |
| `suppressions.js` | render | The active suppressions and whitelists panel, and the three administrator gestures on alert silences — create, edit, delete — each audited daemon-side | `navigation.js` |
| `alerting.js` | render | Notification policies (the routing tree) and timed silences. Policies reference channels **by id only**: a channel secret never transits through this surface | `navigation.js` |
| `producer_ui.js` | service | The shared render factory for *producers* (detection rule, playbook, runbook, correlation, baseline): one row shape, one switch that states its value as a word and names the consequence it arms — asking for confirmation when that consequence reaches the network or a process — and one sentence saying where the product will land, with the link | `detadv.js`, `detection_admin.js`, `runbooks.js`, `sigmaimport.js` |

### Data, sources and knowledge
| Path | Kind | Owns / exposes | Imported by |
|------|------|----------------|-------------|
| `datamodels.js` | render | The semantic layer (models → objects → fields), the Pivot report builder and datasets. Pivot never builds SQL: the endpoint compiles a query in the closed language and runs it through the **same masked path** as a hand-written one | `navigation.js` |
| `knowledge.js` | render | Search-time knowledge objects: field aliases, calculated fields, event types, tags. Readable by any role on purpose — these objects shape everyone's search | `navigation.js` |
| `lookups.js` | render | Enrichment lookup tables: list, row, JSON and CSV paste, delete. `lookupRow` and `parseCsvRows` are exported for the harness. Does not import `app.js` | `app.js` |
| `sources.js` | render | The source inventory and its display metadata, plus the audited metadata mutations. `renderSourcesInventory` is exported for the harness | `app.js`, `navigation.js` |
| `processors.js` | render | The ingest processor: ordered rules that filter, mask, route or sample an event **before** indexing, a dry-run, and the per-rule counters — what was not indexed stays visible rather than silently dropped | `app.js`, `navigation.js` |
| `connectors.js` | render | External pull connectors (Defender, TAXII, generic HTTP pull, presets): list, form, type switch, field and status mapping, preview, poll | `app.js`, `navigation.js` |
| `destinations.js` | render | Outputs: forwarding normalised events to an external sink. Data leaves the perimeter here, so the surface is admin-only and send-only; the sink credential is a password field, never redisplayed, and re-sent only if re-typed | `app.js`, `navigation.js` |
| `index_policies.js` | render | Named logical indexes — an index being the environment value of an event, the same axis the ingest processor routes on — with their own retention and caps. An index with no policy inherits the global retention | `app.js`, `navigation.js` |
| `retention.js` | render | Retention durations, editable, with a destructive preview: any **decrease** raises a modal naming what it deletes before the write | `navigation.js` |
| `threatintel.js` | render | Threat intel: indicator coverage by type and source, the indicator list, manual add and bundle import | `app.js`, `navigation.js` |

### Operations, identity and administration
| Path | Kind | Owns / exposes | Imported by |
|------|------|----------------|-------------|
| `system.js` | render | The day-2 operations console: self-metrics, per-component health, the administrator bulletin, and the non-secret diagnostic bundle. `rendreSysteme` and `lireMesure` are exported because this is where the harness proves a **verdict is rendered as a state** — never as a zero, never as an empty cell | `app.js`, `login.js`, `navigation.js` |
| `freshness.js` | render | The two Overview panels: freshness (health per source) and integrations (sensor and host coverage). `freshState` and `countStates` are exported for the harness. Its one edge into `app.js` is the pivot from a hot source to the filtered alert queue, called on a click | `app.js`, `navigation.js` |
| `fleet.js` | render | The agent fleet inventory — hosts and endpoints, read-only | `app.js`, `navigation.js` |
| `audit.js` | render | The hashed mutation ledger, newest first, read-only, admin | `app.js`, `navigation.js` |
| `admin_users.js` | render | Accounts and access, plus agent and collector token provisioning — a provisioned token is shown **once** and never again | `app.js`, `navigation.js` |
| `idp.js` | render | The native identity provider: federated providers and self-service second-factor enrolment. Additive — with no provider enabled and no factor enrolled, authentication is unchanged. The provider secret is a password field, never redisplayed; omitting it keeps the stored one | `navigation.js` |
| `fieldfilters.js` | render | The administration surface of field-level masking. Additive: with no rule, every read is unchanged. The real enforcement is server-side — the mask is emitted **inside** the compiled SQL — and this surface only configures it | `navigation.js` |
| `multitenant.js` | service | The tenant and environment switcher in the header, the tenants view, grants, and the operator-access audit. It also owns the two predicates the rest of the console asks before spending a request: whether multi-tenant mode is on, and whether the current identity is an administrator | `app.js` and most administration modules |
| `ai.js` | render | The advisory assistant, revealed only if the status endpoint reports the feature enabled. It **proposes** a query into the bar for the analyst to review and run — zero automatic execution | `login.js` |

### Served document and assets
| Path | Kind | Owns / exposes | Imported by |
|------|------|----------------|-------------|
| `index.html` | shell | The served document: the static skeleton of every space and panel, the role-driven style rules that hide write controls as defence in depth, and the single module script that starts the console | — |
| `style.css` | asset | The whole theme — dark by default, light through a root attribute — driven entirely by CSS variables. Every identifier and class it targets is held against `web/` by a CI guard, orphan ceiling zero | `index.html` |
| `fonts/` | asset | Self-hosted Inter and JetBrains Mono subsets with their licence texts: no font request ever leaves the browser for a third party | `style.css` |
| `manifest.webmanifest`, `{favicon,favicon-plume,quetzal}.svg` | asset | The installable-app manifest and the icons the document and the manifest point at | `index.html` |

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
| **scrypt lockstep** — cold AEAD work-factor fixed and matched to the backup/age crypto | `cold_store/crypto.rs` (`COLD_SCRYPT_LOG_N`), `backup/mod.rs` | Compile-time assert in `cold_store/mod.rs`; fixed work factor |
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

- **`server/mod.rs::run()`** was the one true god-function (config + DB open/migrate + ~40
  `seed_*` + background spawns + the whole route table), and the audit proposed splitting it into
  `boot_config` / `open_and_migrate_db` / `spawn_background_jobs` / `build_router`. That split is
  done (`P7.18-a`): the façade now keeps the HTTP layers, the boot sequence and `run()`, and the
  four autonomous blocks live in the submodules above. What is still diffuse is the *sequence*
  itself — `run()` remains long, because the ORDER of its steps is the contract (bind before any
  writer-lock work, control plane before the loops) and no boundary in it is free.
- **`detection` ↔ `cold_store` tentacle** (`reparse_lower_bound`): detection is otherwise
  independently ownable, but this coupling means a detection contributor must understand the
  cold immutability (H2) invariant. Worth an explicit interface if the team grows.
- **`main.rs`** still mixes CLI subcommands with glue — subsystem ownership of CLI vs runtime
  is not cleanly separated.
