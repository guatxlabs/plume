# Contributing to Plume

Thanks for your interest in Plume — the feather-light SOC/XDR. Plume is a single Rust binary
(`plume-daemon`) that ingests telemetry, stores it encrypted in SQLite/SQLCipher, and serves
the API + web UI + detection engine. Contributions are welcome, under a few rules that exist
because Plume is a **security-critical, resource-bounded** tool.

By contributing you agree that your contribution is licensed under **AGPL-3.0-or-later** (the
project license), and you certify the [Developer Certificate of Origin](https://developercertificate.org/)
by signing off your commits (`git commit -s` → adds `Signed-off-by:`).

For the *what* and *why* of the architecture, read these first — this guide does **not** repeat
them: [`ARCHITECTURE.md`](ARCHITECTURE.md), [`docs/MODULE-MAP.md`](docs/MODULE-MAP.md)
(subsystem map + security invariants), [`docs/CIM.md`](docs/CIM.md) (event taxonomy).

## Non-negotiable: the invariants

A pull request that weakens any of these will be **rejected**, no matter how useful the feature:

- **Mode-0 byte-identical.** Anything behind an OFF-by-default Cargo feature (or a runtime
  gate) **must leave the default build byte-identical** — the module *does not exist*, not
  merely "skipped". You prove it by a **constant test count**: the default suite passes the
  **same number** of tests before and after your gated change — **752** at the time of
  writing (`cd daemon && cargo test --locked`, default features). The invariant is the
  *constancy*; when you legitimately add tests, update the number here, in
  `daemon/.cargo/audit.toml`, in `daemon/src/tests/ingest.rs` and — the one that actually
  enforces it — in `EXPECTED_TESTS` in `.github/workflows/ci.yml`, from your own
  measurement. CI SUMS the `test result: ok. N passed` lines of the default run and FAILS
  the build on any mismatch, so a gated change that silently adds or drops a test in the
  default profile cannot merge (the agent crate is separate: `cd agent && cargo test
  --locked` → 95, not asserted by CI). **The counterpart of this invariant is that the default
  suite is BLIND to gated code by construction** — 752 stayed green with a deliberate type
  error in `cold_store`. So a constant default count is necessary, not sufficient: gated work
  must ALSO be green under its own feature (`cold-tier` job). A heavy new
  dependency is `optional = true` behind a feature, defaulted OFF, with a rationale comment in
  `daemon/Cargo.toml` (that file is the canonical rationale log — match its style).
- **Masking is applied at the `soql_field` choke-point — never re-implemented per caller.**
  User-facing reads go through the shared SOQL compiler; rows pass through
  `soql_field`/`soql_filter_field` (in guatx-core) **before** aggregation/rename. Do not add a
  read path that hydrates raw rows into a user query, and do not reimplement masking anywhere
  else. DENY rules also arm the SQLite authorizer so the denial holds even for admin raw SQL.
  Fail **closed**: unknown role → masked; unreadable rule at reload → treated as DENY.
- **The 2 GB RAM budget is non-negotiable — optimise, don't grow.** The reference deployment
  is bounded to **2 GiB** (the SMB profile). Keep the working set bounded: paginate (keyset),
  stream (bounded ~1 MiB buffers), or roll up. A query that scans an event per request is a
  bug — precompute rollups, use the rollup-route/SWR. If a change trades RAM for speed, it
  goes behind an OFF-by-default feature or it does not land.
- **A schema migration's DDL must not depend on the DATA, the config, or the filesystem.**
  Boot derives the expected shape of a database by replaying `db/schema.sql` + the whole
  migration chain into an **empty, in-memory, unconfigured** database, then refuses to serve
  a database that lacks anything that reference declares (objects *and* columns). So a step
  that creates/alters/drops **conditionally on content** — "create this table only if `event`
  is empty", an `ALTER` gated on a `SELECT` — makes a perfectly healthy production database
  produce a *different* shape, and the daemon refuses to start on it while telling the
  operator to restore a backup. That is the worst failure mode in this codebase: an outage for
  someone who broke nothing. Write DDL that is unconditional and idempotent (`IF NOT EXISTS`);
  put data work in `INSERT`/`UPDATE` inside the same step, where it belongs. Two tests hold
  this: `the_reference_holds_on_a_populated_database` (populated database, both upgrade
  directions) and `every_migration_path_lands_on_the_same_shape`.
- **You do not get a writable database connection without the schema contract.** `db_open` is
  the only module that may open a SQLite connection on a path. Take it from
  `PreparedDb::open*` (anti-downgrade guard + `prepare_schema`), or say
  `open_db_without_schema_contract` out loud and expect the reviewer to ask why. A production
  file that opens `rusqlite::Connection` itself fails `the_door_is_the_only_way_in`.
- **The SOQL compiler lives in `guatx-core` — fix it in place, never fork.** The closed
  grammar and its `SqliteDialect` are shared. Change the compiler *in the core crate*; do not
  copy it into the daemon or maintain a divergent parser. The dependency is one-directional:
  `plume-daemon` depends on `guatx-core`; the core never depends on the daemon and must never
  gain a `rusqlite`/SQLCipher dependency.

When in doubt, add a test that proves the invariant still holds.

## Building & testing

> **Note (open-source build):** the daemon depends on `guatx-core` as a **git dependency**
> (`github.com/guatxlabs/core`, tag `v0.2.1`). To develop against a local core checkout, place
> it as a sibling directory and add a git-ignored `.cargo/config.toml` at the repo root with a
> `[patch]` redirecting the git dep to the path:
> ```toml
> # .cargo/config.toml (local only, never committed)
> [patch."https://github.com/guatxlabs/core"]
> guatx-core = { path = "../../core" }
> ```

The crate lives in `daemon/`, so point cargo at it. The default build is the SMB profile
(`SqlcipherStore` only) and must stay **752 tests green** and **offline**:

```sh
cargo test --manifest-path daemon/Cargo.toml        # 752 tests, default features
```

The **`cold_tier` suite has its own count and its own CI job** (`cold-tier` in
`.github/workflows/ci.yml`, `EXPECTED_COLD_TESTS`). Run it too when you touch
`daemon/src/cold_store/` — or anything it depends on, notably the SOQL compiler:

```sh
TMPDIR=/path/on/disk cargo test --manifest-path daemon/Cargo.toml --features cold_tier
# 942 tests (= the 752 default tests + the cold_store tests the feature adds)
```

> **Why this matters more than it looks.** With a 7-day hot window and 365-day retention,
> `cold_store` is the read path for ~358 of the 365 retained days. It is also the module whose
> failure mode is *silent*: over-prune a Parquet file and a query spanning more than a week
> returns a wrong count **without erroring**. Until this job existed, nothing in CI even
> *compiled* the module — and it had gone red unnoticed: bumping guatx-core to v0.2.1
> tightened SOQL field-name validation and broke the cold extractor-parity tests, while the
> default suite stayed at 752 green.

**Two testing gotchas** (learned the hard way):

1. **Point `TMPDIR` at a real disk path.** `/tmp` is often RAM-backed (ZRAM tmpfs); tests
   that spill temp DBs/Parquet there eat the very RAM budget you're respecting and can OOM.
2. **Never run the default suite and a `--features cold_tier` suite concurrently.** They share
   fixed temp fixture paths → two cargo processes clobber each other → false failures. Run
   feature suites **sequentially, on a separate runner**:
   ```sh
   TMPDIR=/path/on/disk cargo test --manifest-path daemon/Cargo.toml
   TMPDIR=/path/on/disk cargo test --manifest-path daemon/Cargo.toml --features cold_tier
   ```

All optional backends are **OFF by default**. The full feature list, from `[features]` in
`daemon/Cargo.toml`: `cold_tier`, `clickhouse`, `clickhouse-ha`, `ldap`, `saml`, `duckdb`, `ai`.
The default binary carries none of them.

**What CI actually verifies about them** — do not over-read a green tick:

| feature | CI coverage |
|---|---|
| `cold_tier` | **compiled and tested** (`cold-tier` job, own asserted count) |
| `duckdb`, `clickhouse`, `clickhouse-ha`, `ldap`, `saml`, `ai` | **`cargo check` only** — type-checked, never executed |

A behaviour regression in SAML assertion validation, the LDAP bind, the AI advisory path or the
ClickHouse backend **will pass CI green**. Making those real requires suites that run without a
live IdP / directory / model endpoint / ClickHouse server; that work is not done. If you touch
one of them, say in the PR how you tested it by hand — CI will not do it for you.

The **shell collectors** (43 tracked scripts) get a `bash -n` parse gate (`shell` job) and a
*consultative* shellcheck. `bash -n` proves they parse; it proves nothing about behaviour.

## Code style

- **Self-documenting, component-explicit names.** No workflow markers in names (task/commit/
  branch/feature); state lives in status, not names.
- **Commit prefixes name the touched subsystem** (`storage:`, `soql:`, `ingest:`, `ui:`,
  `auth:`, `detection:`, `rollups:`, `cold:`, …). Scope commits (`git add <file>`); never
  blanket-add.
- **Comments carry the rationale.** Each module/invariant states its "why" at the top of the
  file (see the `cold_store/*.rs` headers and the `daemon/Cargo.toml` dependency blocks). The
  *why* is load-bearing here — keep the discipline.
- **Tests are co-located by domain** under `daemon/src/tests/{rollup,detection,rbac,soql,cases,
  governance,connectors,tokens,engagement,tenants,…}.rs`. Add tests next to the domain they
  exercise; do not grow a test monolith.

## Pull requests

1. Open an issue first for anything non-trivial, so we can agree on the approach.
2. One logical change per PR. Keep the diff focused.
3. Include tests. Preserve or improve coverage; keep the default count at **752** (CI asserts it).
   If you touch `cold_store`, the `cold_tier` count (**942**) is asserted too.
4. Run `cargo test` (default) and, for gated work, the feature suite separately; run
   `cargo clippy`. All must pass. "The default suite is green" is **not** evidence for gated
   code — see the mode-0 invariant above.
5. Sign off your commits (`-s`).
6. **Security issues do not go here** — see [`SECURITY.md`](SECURITY.md).

## A word on intent

Plume is for monitoring **infrastructure you own or are authorized to monitor**. Contributions
that make it easier to exfiltrate data, evade its masking/RBAC controls, or attack systems you
don't own are out of scope for this project.
