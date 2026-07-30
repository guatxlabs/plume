# DuckDB store — WARM analytical tier (#15) — **EXPERIMENTAL**

Status: **OPT-IN, INERT BY DEFAULT, EXPERIMENTAL.** Feature-gated (`--features duckdb`), selected at
runtime by `PLUME_STORE=duckdb`. Absent from the SMB/prod build and prod deployment. **The default
remains `SqlcipherStore` (SQLite/SQLCipher), byte-identical to today.**

DuckDB is an **embedded, columnar, no-external-server** analytical engine. It fills a distinct niche
under the superset principle (single-box "bring-your-own-no-infra" analytics, air-gapped). But it is
**not the supported scale-out path** — **ClickHouse is** (see [`CLICKHOUSE-STORE.md`](./CLICKHOUSE-STORE.md)).
DuckDB stays as an experimental/scale-out tier: keep the capability, do **not** ship it as a
client-selectable backend on the 2 GB node.

> **Read this first.** Both the *build cost* and the *runtime footprint* of DuckDB are real. This tier is
> for an **ESN/MSSP build+run host**, never the 2 GB single-node VPS.

---

## 1. `PLUME_STORE` selector semantics

> ⚠️ **DESIGN, NOT YET WIRED.** `PLUME_STORE` is **read nowhere in the daemon** — `grep -rn '"PLUME_STORE"' daemon/src`
> returns nothing. Setting it has **no effect**: the daemon always uses `SqlcipherStore`. The only store
> variable actually read today is `PLUME_STORE_DUCKDB_EXPERIMENTAL` (`daemon/src/ingest/duckdb_store.rs`).
> The table below is the **intended** selector contract, kept as the design of record. Do not treat it as
> operator documentation until a runtime path reads the variable.

`PLUME_STORE` is designed to pick the data-plane store at runtime. **Unset ⇒ `SqlcipherStore` (default, untouched).**

| `PLUME_STORE` | Store | Build feature | Tier | Support |
|---|---|---|---|---|
| *(unset)* | `SqlcipherStore` (SQLite/SQLCipher) | *(none — default build)* | HOT, single-node, encrypted-at-rest | **★ Default / SMB / prod** |
| `duckdb` | `DuckDbStore` (embedded columnar) | `--features duckdb` | WARM, single-node analytics | **Experimental** |
| `clickhouse` | `ClickHouseStore` (external cluster) | `--features clickhouse` | COLD/scale, multi-node | Supported scale-out |

- The default build (no `--features`) links **neither** `duckdb` **nor** `clickhouse` — mode-0
  byte-identical. A `PLUME_STORE=duckdb` on a default binary has no `DuckDbStore` compiled in.
- Runtime selection dispatch (swapping `store()` across the ~82 daemon call-sites) is a **deferred
  follow-up** for all non-default stores; today the adapters are exercised via their own API + tests,
  not by flipping the env var in prod (same staging as ClickHouse — see `CLICKHOUSE-STORE.md` §2.1 note).

---

## 2. Build cost — why `--features duckdb` is heavy, and how it was de-fanged

### 2.1 The old footgun (bundled)

Previously the dep was `duckdb = { … features = ["bundled"] }`. `bundled` forces `libduckdb-sys` to
**compile the DuckDB C++ amalgamation from source** via the `cc` crate — a multi-MB single-translation-unit
C++ blob. `cc1plus` on that one TU needs **~4 GB build RAM** and **minutes of single-core CPU**. Concretely:

- On the **2 GB VPS** (no C++ toolchain — only a C compiler is present, for the vendored SQLCipher): it
  dies immediately with `cc-rs: failed to find tool "c++"`.
- On a **dev box with a C++ toolchain**: it OOMs / pins a core at ~90% for minutes.

This was a **build-time footgun by flag** (the *default* prod image never triggered it — it builds with
no `--features`), but a nasty one for whoever typed `--features duckdb`.

### 2.2 The fix (un-bundled → link a system libduckdb)

`features = ["bundled"]` has been **removed** (`daemon/Cargo.toml`). Without `bundled`, `libduckdb-sys`
uses **pre-generated bindings** (no `bindgen`/libclang) and looks for a **system/prebuilt `libduckdb`** via
`pkg-config` / `DUCKDB_LIB_DIR` (or a prebuilt download with `DUCKDB_DOWNLOAD_LIB`), then just **links**
`-lduckdb`. **No `cc1plus`, no amalgamation compile, no C++ toolchain requirement, no OOM.**

Trade-off / requirement:

- `--features duckdb` now **requires a `libduckdb` present on the build host**. Provide it via one of:
  - a system install (`libduckdb-dev` / a `duckdb.pc` on the `pkg-config` path), or
  - `export DUCKDB_LIB_DIR=/path/to/libduckdb` (and `DUCKDB_INCLUDE_DIR` if headers are needed), or
  - `export DUCKDB_DOWNLOAD_LIB=1` to let `libduckdb-sys` fetch a prebuilt binary.
- If **no** `libduckdb` is present, the build fails at the **link** step with a **clear, fast**
  `cannot find -lduckdb` — **not** the opaque cc1plus OOM/90%-CPU crawl of before. That is the intended,
  much-better failure mode on a host that shouldn't be building DuckDB anyway.
- The Rust `arrow` crate is **still compiled** (a pulled dependency of `duckdb`), so DuckDB roughly
  doubles the Rust build surface regardless. **Build DuckDB on a proper ESN/MSSP host, never the VPS.**

```bash
# On an ESN/MSSP build host WITH a system/prebuilt libduckdb:
export DUCKDB_LIB_DIR=/opt/duckdb/lib        # or install libduckdb-dev / set DUCKDB_DOWNLOAD_LIB=1
cargo build --release --features duckdb
```

---

## 3. Runtime footprint — caps (GAP-4)

DuckDB is **embedded**: its RAM lives **inside the plume pod**, competing directly with the 2 GB budget.
DuckDB's default `memory_limit` is ~**80 % of system RAM** and it grabs
**all cores** — a single large scan can OOM-evict the pod. `DuckDbStore` therefore enforces caps
(`daemon/src/ingest/duckdb_store.rs::query_soql_masked`):

| Concern | Enforcement | Env override | Default |
|---|---|---|---|
| Memory | `SET memory_limit='…'` PRAGMA on the connection | `PLUME_DUCKDB_MEMORY_LIMIT` | `512MB` |
| CPU | `SET threads=N` PRAGMA | `PLUME_DUCKDB_THREADS` (bounded 1–8) | `2` |
| Query time | watchdog thread + DuckDB `InterruptHandle` (mirrors the SQLite `run_query_ex` watchdog) | `budget_ms` (caller-supplied, same as the hot tier) | 5 s auto / 60 s interactive |
| Row cap | `max_rows` on result assembly | `PLUME_QUERY_MAX` | 5000 |

- **`budget_ms` is honored.** A watchdog interrupts a runaway query at the budget and returns a clear
  "budget dépassé" error (not an opaque 500) — the same pattern as the default SQLite store.
- **`memory_limit` env value is injection-validated** (`is_valid_memory_limit`): only `<number><unit>`
  (B/KB/MB/GB/TB, binary or decimal) is accepted before it is interpolated into `SET`; anything else falls
  back to the default. No `SET`-string escape is possible.
- **`qid`** is threaded/traced (no longer ignored). External `/api/cancel` cancellation is **not** wired
  to DuckDB yet — the in-flight cancel registry (`QUERY_CANCEL`) is typed on `rusqlite::InterruptHandle`;
  a backend-neutral registry is a documented follow-up. The `budget_ms` watchdog is sufficient to bound
  resource consumption in the meantime.

### 3.1 Experimental gate

`DuckDbStore` is **not silently client-selectable**. The first query logs a **loud warning** unless the
operator acknowledges with `PLUME_STORE_DUCKDB_EXPERIMENTAL=1`:

```
[store] ⚠️  DuckDbStore (PLUME_STORE=duckdb) est un tier WARM EXPÉRIMENTAL, NON supporté en prod …
        Posez PLUME_STORE_DUCKDB_EXPERIMENTAL=1 pour acquitter …
```

The gate does not hard-block (the runtime caps are already applied); its purpose is that an unsupported
tier is never enabled without a deliberate, logged acknowledgment.

---

## 4. Security parity notes

- **Masking (#45)** — fail-closed. `soql_to_sql_masked` emits masks through the `DuckDbDialect`
  chokepoint; a non-portable action (`Hash` → a UDF absent in DuckDB) raises an **execution error**
  (fail-closed) rather than leak cleartext to a restricted role.
- **Secret-column denylist** — N/A here: control-plane secrets (`user.hash`, `token.token_hash`) are
  **never** in the data-plane store; only `event`/`metric`/`snapshot` live in DuckDB.
- **At-rest encryption is DOWNGRADED** vs. the SQLCipher hot tier (no per-tenant app-held-key whole-file
  AES). Like ClickHouse, this is an operator/disk-encryption story, not SQLCipher-grade. SMB customers who
  chose plume *for* app-held-key crypto should stay on the hot tier.

---

## 5. Test coverage

Unit-tested offline (`cargo test --features duckdb`, no libduckdb needed for these pure paths — but note
the crate itself must link, so run on a host with `libduckdb`):

- `duckdb_store_masked_emission_threads_masks` — masked emission threads masks (fail-closed), empty masks
  byte-identical to the unmasked path.
- `duckdb_memory_limit_is_injection_safe` — `memory_limit` validation accepts DuckDB size forms and
  rejects `SET`-injection attempts.
- `duckdb_threads_bounded` — thread cap bounded [1..=8].

The **default** `cargo test` (SqlcipherStore only) is unchanged and green — the DuckDB module and its
tests are **not compiled** without `--features duckdb`.

---

## 6. Bottom line

Keep DuckDB as an **experimental embedded-analytics** option (superset principle), built on a proper
ESN/MSSP host with a system `libduckdb`, gated behind `PLUME_STORE_DUCKDB_EXPERIMENTAL=1`, with runtime
caps applied. **Never build it on the 2 GB VPS. Never make it the SMB default. For scale-out, use
ClickHouse** — the supported, light, pure-Rust, compute-externalizing path.
