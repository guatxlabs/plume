# Contributing to Plume

Thanks for your interest in Plume — the feather-light SOC/XDR. Plume is a single Rust binary
(`plume-daemon`) that ingests telemetry, stores it encrypted in SQLite/SQLCipher, and serves
the API + web UI + detection engine. Contributions are welcome, under a few rules that exist
because Plume is a **security-critical, resource-bounded** tool.

By contributing you agree that your contribution is licensed under **AGPL-3.0-or-later** (the
project license), and you certify the [Developer Certificate of Origin](https://developercertificate.org/)
by the act of contributing itself. **Do not add a `Signed-off-by:` trailer.** Measured 2026-08-26:
the trailer carries an address outside the project domain, the guards refuse it, and the platform
*carries it over* into a squash commit — so a signed-off commit cannot land here. The certification
stands; only the trailer is dropped. See *How a change actually lands here* below.

For the *what* and *why* of the architecture, read these first — this guide does **not** repeat
them: [`ARCHITECTURE.md`](ARCHITECTURE.md), [`docs/MODULE-MAP.md`](docs/MODULE-MAP.md)
(subsystem map + security invariants), [`docs/CIM.md`](docs/CIM.md) (event taxonomy).

## Non-negotiable: the invariants

A pull request that weakens any of these will be **rejected**, no matter how useful the feature:

- **Mode-0 byte-identical.** Anything behind an OFF-by-default Cargo feature (or a runtime
  gate) **must leave the default build byte-identical** — the module *does not exist*, not
  merely "skipped". You prove it by a **constant test count**: the default suite passes the
  **same number** of tests before and after your gated change (`cd daemon && cargo test
  --locked`, default features). **That number is written in exactly ONE place**:
  `EXPECTED_TESTS` in `.github/workflows/ci.yml` — the place CI actually enforces. Read it
  there; do not copy it into prose. This document used to name it, and so did three other
  files; all four rotted out of date while CI stayed correct, which is the only outcome a
  duplicated counter can have. A CI step now FAILS if the live value reappears as a bare
  "N tests" claim anywhere else in the tree, so the duplication cannot come back. When you
  legitimately add tests, update `EXPECTED_TESTS` from your own measurement — and nothing
  else. (Historical measurements *quoted with their date* are fine and are not counters:
  they record what was true then, and must NOT be "fixed" to today's value.)
  CI SUMS the `test result: ok. N passed` lines of the default run and FAILS
  the build on any mismatch, so a gated change that silently adds or drops a test in the
  default profile cannot merge (the agent crate is separate: `cd agent && cargo test
  --locked` → 96, not asserted by CI). **The counterpart of this invariant is that the default
  suite is BLIND to gated code by construction** — 752 stayed green with a deliberate type
  error in `cold_store`. So a constant default count is necessary, not sufficient: gated work
  must ALSO be green under its own feature (`cold-tier` job). A heavy new
  dependency is `optional = true` behind a feature, defaulted OFF, with a rationale comment in
  `daemon/Cargo.toml` (that file is the canonical rationale log — match its style).
- **Masking is applied at the `soql_field` choke-point — never re-implemented per caller.**
  User-facing reads go through the shared GXQL compiler; rows pass through
  `soql_field`/`soql_filter_field` (in guatx-core) **before** aggregation/rename. Do not add a
  read path that hydrates raw rows into a user query, and do not reimplement masking anywhere
  else. DENY rules also arm the SQLite authorizer so the denial holds even for admin raw SQL.
  Fail **closed**: unknown role → masked; unreadable rule at reload → treated as DENY.
- **A collector that cannot collect must SAY SO — a silent `exit 0` is a lie.** A sensor whose
  prerequisite is missing (binary, source file, credential, subsystem) used to exit **successfully**
  and emit nothing, so the SOC could not tell *"this sensor is blind"* from *"nothing happened"*.
  *Measured 2026-08-01 on a fresh Ubuntu 24.04 Server VM: `auditd.sh` did `[ -r "$LOG" ] || exit 0`,
  auditd is not installed by default, and `category=exec` was empty with nothing anywhere saying why —
  29 of the 37 shipped sensors carried the same shape — 50 silent exits.* Every early exit is exactly
  one of three cases, and each has a named primitive in `collectors/lib.sh` that carries its own
  `exit`: `plume_unavailable` (prerequisite missing → emits `category=config`,
  `collect_status=unavailable`, closed `reason` vocabulary), `plume_disabled` (operator switch off),
  `plume_exit_nodata` (nothing new — the only legitimate silence). **A bare `exit 0` in a collector
  fails CI** (`.github/scripts/check_collector_exit_is_classified.py`): the gate enumerates no sensor
  list, so a collector written tomorrow is covered by construction. Reporting is not enough to be
  *seen*: an extra `config` event makes a blind source look **fresh** (measured: `/api/sources` returned
  `status: "frais"` for a source that had just admitted it was blind), so the shipped rule
  `config.d/rules/catalog/de-collector-unavailable.json` raises an **alert** on the admission —
  verified end to end. *Known gap, stated rather than hidden:* that alert is **global**, it does not
  flip the guilty feed to `warn`, because the daemon attributes `active_alerts` by scanning the rule's
  **query text** for `source=` tokens (`daemon/src/handlers/freshness.rs`, "limite assumée") and a
  deliberately generic rule carries none. Closing it means attributing an alert to the source of the
  **matched events** instead of to the rule text.
- **The 2 GB RAM budget is non-negotiable — optimise, don't grow.** The reference deployment
  measures **~310 MiB RSS** (9,844,503 events, 2 vCPU, field masking off) and is **capped at
  runtime** to **2 GiB** (`limits.memory: 2Gi` in k3s, `MemoryMax=2G` in systemd) — **no CI job
  asserts that ceiling**, so treat it as a budget you must re-measure, not a guarantee the
  pipeline defends. Keep the working set bounded: paginate (keyset),
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
- **The GXQL compiler lives in `guatx-core` — fix it in place, never fork.** The closed
  grammar and its `SqliteDialect` are shared. Change the compiler *in the core crate*; do not
  copy it into the daemon or maintain a divergent parser. The dependency is one-directional:
  `plume-daemon` depends on `guatx-core`; the core never depends on the daemon and must never
  gain a `rusqlite`/SQLCipher dependency.

When in doubt, add a test that proves the invariant still holds.

## Building & testing

> **Note (open-source build):** the daemon depends on `guatx-core` as a **git dependency**
> (`github.com/guatxlabs/core`), pinned to a tag **in `daemon/Cargo.toml` and nowhere else** —
> read it with `grep -n 'guatx-core' daemon/Cargo.toml`. To develop against a local core checkout, place
> it as a sibling directory and add a git-ignored `.cargo/config.toml` at the repo root with a
> `[patch]` redirecting the git dep to the path:
> ```toml
> # .cargo/config.toml (local only, never committed)
> [patch."https://github.com/guatxlabs/core"]
> guatx-core = { path = "../../core" }
> ```
>
> **This patch fails SILENTLY when your local core's version differs from the locked one —
> measured 2026-07-30, and it is a false-green trap, not a nuisance.** The committed
> `Cargo.lock` pins guatx-core to a git source **and rev**. If the sibling checkout carries a
> different `version =` (say you bumped it to 0.2.2 while the lock pins 0.2.1), cargo **declines
> the substitution** and builds against the *published* core, so your build is green and proves
> nothing about your local change. All you get is one line, easy to lose in cargo's output:
> ```
> warning: patch `guatx-core v0.2.2 (/path/to/core)` was not used in the crate graph
> ```
> Measured both ways: with the lock in place → resolved from
> the pinned `git+…?tag=…#<rev>` source of the lock; with the lock allowed to re-resolve → resolved from the local
> path. So **do not assume — verify which core you actually compiled**:
> ```sh
> cargo metadata --format-version 1 | python3 -c "import json,sys; \
>   print([ (p['version'], p.get('source') or 'LOCAL PATH') \
>           for p in json.load(sys.stdin)['packages'] if p['name']=='guatx-core' ])"
> ```
> It must print `LOCAL PATH`. If it prints a `git+…` source, let the lock re-resolve
> (`cargo update -p guatx-core`) — and never commit that lock change.

The crate lives in `daemon/`, so point cargo at it. The default build is the SMB profile
(`SqlcipherStore` only) and must stay **green at the count `EXPECTED_TESTS` asserts** (see
above — that variable is the single source of truth) and **offline**:

```sh
cargo test --manifest-path daemon/Cargo.toml        # default features
```

The **`cold_tier` suite has its own count and its own CI job** (`cold-tier` in
`.github/workflows/ci.yml`, `EXPECTED_COLD_TESTS`). Run it too when you touch
`daemon/src/cold_store/` — or anything it depends on, notably the GXQL compiler:

```sh
TMPDIR=/path/on/disk cargo test --manifest-path daemon/Cargo.toml --features cold_tier
# the count `EXPECTED_COLD_TESTS` asserts (= the default suite + what the feature adds)
```

> **Why this matters more than it looks.** With a 7-day hot window and 365-day retention,
> `cold_store` is the read path for ~358 of the 365 retained days. It is also the module whose
> failure mode is *silent*: over-prune a Parquet file and a query spanning more than a week
> returns a wrong count **without erroring**. Until this job existed, nothing in CI even
> *compiled* the module — and it had gone red unnoticed: bumping guatx-core to v0.2.1
> tightened GXQL field-name validation and broke the cold extractor-parity tests, while the
> default suite stayed green — **752 green on 2026-07-28**, the suite size on that date. That
> number is a dated measurement, not a counter: do **not** align it on today's value, or you
> destroy the evidence. The live counter is `EXPECTED_TESTS` and lives only in `ci.yml`.

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
- **Tests are co-located by domain** under `daemon/src/tests/{rollup,detection,rbac,soql_completion,cases,
  governance,connectors,tokens,engagement,tenants,…}.rs`. Add tests next to the domain they
  exercise; do not grow a test monolith.

## Pull requests

1. Open an issue first for anything non-trivial, so we can agree on the approach.
2. One logical change per PR. Keep the diff focused.
3. Include tests. Preserve or improve coverage; keep the default count CONSTANT — the value lives
   in `EXPECTED_TESTS` (`.github/workflows/ci.yml`) and nowhere else, so read it there.
   If you touch `cold_store`, `EXPECTED_COLD_TESTS` is asserted the same way.
   **Check it in 2 seconds instead of 47 minutes** with `.github/scripts/compter-les-tests.sh`: it
   asks the harness to *list* its tests (`cargo test -- --list`) rather than run them, and compares
   both counts against `ci.yml` itself — no second copy of the numbers. Install it as a pre-commit
   hook with `git config core.hooksPath .githooks` (it stays silent unless the commit touches
   `daemon/`). It does **not** tell you the tests pass — only CI, which actually runs them, does.
   *(Why a local check and not another CI trigger: `ci.yml` already runs on `push` to every branch,
   and has since the file was created. The 937 → 945 drift of 2026-08-07 was caught by CI on the
   push and simply not read. Measured 2026-08-09: listing both suites ≈ 2 s warm; running them = 187 s + 2627 s ≈ 47 min.)*
   <!-- Ces deux lignes ont porté « 758 » et « 949 » jusqu'au 2026-08-02, quand les compteurs vivants
        valaient 866 et 1061 : 108 et 112 de retard, dans le fichier même qui INTERDIT de recopier la
        valeur. La garde `check_no_duplicated_test_count.py` restait verte — c'est son résidu
        documenté (jambe A ne cherche que la valeur COURANTE ; jambe B n'attrape que la forme
        « nombre PUIS mot », or ici le nombre suivait le mot et était en gras markdown). Élargir la
        jambe B a été MESURÉ le 2026-08-02 : 162 candidats pour 2 vrais — donc NON élargie, et le
        remède est de ne plus écrire de nombre ici du tout. -->

4. Run `cargo test` (default) and, for gated work, the feature suite separately; run
   `cargo clippy`. All must pass. "The default suite is green" is **not** evidence for gated
   code — see the mode-0 invariant above.
5. **Do not sign off (`-s`).** The trailer carries a non-project address that both guards refuse —
   see *How a change actually lands here*. The DCO is certified by contributing, not by the trailer.
6. **Security issues do not go here** — see [`SECURITY.md`](SECURITY.md).

### How a change actually lands here

**The merge button cannot produce a commit this repository accepts.** Measured 2026-08-26 on
this repo's settings and on a real squash merge configured identically, the squash commit
carries three things the guards refuse, and no repository setting removes any of them: the
**sign-off trailers of the squashed commits are carried over** (bringing back a non-project
address), a **`Co-authored-by:` line per distinct author** is added, and the squash commit is
**committed by the platform account**, not the canonical identity. Proved by mutation: the same
body, stripped of those lines alone, passes.

So a pull request is **not** an entry path here — not even one written by the maintainer. The
only entry path is a **direct push** to the publication branch under the canonical identity. A
contribution is re-applied locally, replayed under that identity, and pushed; the commit message
cites the PR number so the discussion stays findable. The same goes for dependency-update PRs:
the bot is worth keeping for the **alert** — it says which version moved and why — and not for
merging.

That is why those pull requests stay red, and the red is **true**. It cannot be fixed branch by
branch: nobody can rewrite the message of a commit a bot just wrote. It must not be silenced
either — a guard that stopped judging those commits would not remove the cause, only the sight
of it, and the publication branch would lose its one redundancy: every commit would land there
without ever having been read.

## A word on intent

Plume is for monitoring **infrastructure you own or are authorized to monitor**. Contributions
that make it easier to exfiltrate data, evade its masking/RBAC controls, or attack systems you
don't own are out of scope for this project.

## Écrire pour le public

Ce dépôt est public. Tout ce qui y est écrit — messages de commit, documentation,
commentaires de code — s'adresse au **lecteur futur du code**, pas à une personne ni à une
conversation.

**Un message de commit dit CE QUI CHANGE et POURQUOI.** Il n'a pas à raconter le
déroulement du travail. À proscrire :

- nommer une personne, ou citer un échange privé ;
- le récit à la première personne (« j'ai essayé », « ma première version ») ;
- les repères de session (« hier », « ce matin », « la quatrième fois aujourd'hui ») ;
- un chemin machine (`/home/<compte>`), un pseudo personnel, une adresse tierce.

Ce qui a de la valeur et doit rester : la **mesure** (chiffres et date), ce qui a été
**réfuté**, et la **raison** d'un choix de conception. Le journal de travail, lui, a sa
place dans un dépôt interne — pas dans l'historique public.

**Identité.** Tous les commits sont signés `guatxlabs <noreply@guatx.com>`. À poser dans
chaque clone, car un clone frais hérite de la configuration globale de la machine :

```sh
git config user.name  "guatxlabs"
git config user.email "noreply@guatx.com"
git config core.hooksPath .githooks   # arme les gardes ci-dessous
```

**Deux gardes versionnées** appliquent le mécanisable : `pre-commit` refuse un commit dont
l'auteur n'est pas le canonique ; `commit-msg` refuse un message portant un chemin machine,
un pseudo personnel ou une adresse tierce. Les hooks sont une **boucle de retour**, pas une
frontière — la CI juge tout commit poussé, sur toute branche, et c'est elle qui lie. Le STYLE, lui, n'est pas mécanisé : une garde
qui prétendrait en juger produirait du bruit et finirait désarmée. Il se tient à la
relecture.
