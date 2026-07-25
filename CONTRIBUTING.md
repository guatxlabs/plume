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
  **same 707** tests before and after your gated change. A heavy new dependency is
  `optional = true` behind a feature, defaulted OFF, with a rationale comment in
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
- **The SOQL compiler lives in `guatx-core` — fix it in place, never fork.** The closed
  grammar and its `SqliteDialect` are shared. Change the compiler *in the core crate*; do not
  copy it into the daemon or maintain a divergent parser. The dependency is one-directional:
  `plume-daemon` depends on `guatx-core`; the core never depends on the daemon and must never
  gain a `rusqlite`/SQLCipher dependency.

When in doubt, add a test that proves the invariant still holds.

## Building & testing

> **Note (open-source build):** the daemon depends on `guatx-core` as a **git dependency**
> (`github.com/guatxlabs/core`, tag `v0.2.0`). To develop against a local core checkout, place
> it as a sibling directory and add a git-ignored `.cargo/config.toml` at the repo root with a
> `[patch]` redirecting the git dep to the path:
> ```toml
> # .cargo/config.toml (local only, never committed)
> [patch."https://github.com/guatxlabs/core"]
> guatx-core = { path = "../../core" }
> ```

The crate lives in `daemon/`, so point cargo at it. The default build is the SMB profile
(`SqlcipherStore` only) and must stay **707 tests green** and **offline**:

```sh
cargo test --manifest-path daemon/Cargo.toml        # 707 tests, default features
```

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

All optional backends are **OFF by default** (each is an `optional` dep behind a feature):
`cold_tier`, `clickhouse`, `ldap`, `saml`, `duckdb`. The default binary carries none of them.

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
3. Include tests. Preserve or improve coverage; keep the default count at **707**.
4. Run `cargo test` (default) and, for gated work, the feature suite separately; run
   `cargo clippy`. All must pass.
5. Sign off your commits (`-s`).
6. **Security issues do not go here** — see [`SECURITY.md`](SECURITY.md).

## A word on intent

Plume is for monitoring **infrastructure you own or are authorized to monitor**. Contributions
that make it easier to exfiltrate data, evade its masking/RBAC controls, or attack systems you
don't own are out of scope for this project.
