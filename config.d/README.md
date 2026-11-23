# config.d — versioned overlays (Customization Phase 1)

[English](README.md) | [Français](README.fr.md)

**Git-versioned** source of truth for the custom **parsers**, **detection rules** and **playbooks**
of the Plume SOC. Any `*.json` file dropped here is loaded when the daemon starts
(`load_overlays`, right after the migrations and the seeds) and stored in the database with `managed = 1`.

> This overlay is one of Plume's extension *seams*. Overview (parser / connector / detection /
> threat-intel / enforcer) and *bring-your-own-vendor* model: **[`docs/SDK.md`](../docs/SDK.md)**.

## Why a baked overlay and not `/etc/plume`?

The daemon runs in a Kubernetes pod with `readOnlyRootFilesystem: true`: it has **no** writable host
path (no `/etc/plume`). This directory is therefore **baked into the image** (like the web assets
under `/usr/local/share/plume/web`) and mounted read-only. The daemon reads it through the
`PLUME_CONFIG_DIR` environment variable (default `/usr/local/share/plume/config.d`).

## Layout

```
config.d/
├── parsers/     *.json              → table `parser` (regex legacy) + `dparser` (DSL déclaratif, cf. docs/PARSER-DSL.md)
├── rules/       *.json              → table `rule`
├── playbooks/   *.json              → table `playbook`
├── sigma/       *.yml|*.yaml|*.json → table `rule` (règles Sigma traduites en GXQL, cf. docs/SIGMA-IMPORTER.md)
└── cim/         cim.v1.json         → SPEC (miroir machine du CIM, cf. docs/CIM.md ; IGNORÉ par le loader — zéro effet runtime)
```

One file = one entity (EXCEPT `sigma/`: a YAML file can carry **several** `---` documents). The
files are loaded in alphabetical order. Unknown JSON keys (e.g. `_comment`) are ignored —
handy for documenting each file (JSON has no comments).

> **`sigma/` (Slice #7, part 3).** [Sigma](https://github.com/SigmaHQ/sigma) rules (open detection
> standard, YAML) are **translated into Plume rules** there (GXQL `search … | stats count` + `title`/`level`/
> MITRE tags) at boot by `load_overlay_sigma`, `managed = 1`. The `logsource → category` mapping goes through
> the **CIM** (`docs/CIM.md`). A construct that cannot be expressed in GXQL (cross-field OR, `1 of them`, aggregation,
> `|base64`/`|cidr`…) is **reported + skipped** (never a silently wrong rule). See the coverage
> matrix in **`docs/SIGMA-IMPORTER.md`**. One-off/out-of-git import: `POST /api/sigma/import` (admin),
> or the subcommand on the central — `sudo env PLUME_CONFIG=/etc/plume/soc.conf /usr/local/bin/plume-daemon
> sigma-import <path> [--dry-run]` on a native host, `docker compose exec soc plume-daemon sigma-import <path>`
> under Docker, `kubectl -n soc exec deploy/soc -- plume-daemon sigma-import <path>` under k3s (`<path>` is
> then a path inside the container). Without `--dry-run`, it writes to the database: start the daemon once
> beforehand, otherwise it creates the database unencrypted
> ([`docs/INSTALLER-SANS-OUVRIR-DE-BRECHE.md` §1.1](../docs/INSTALLER-SANS-OUVRIR-DE-BRECHE.md#11-start-the-daemon-once-before-any-subcommand-that-writes-to-the-database)). `--dry-run`
> opens no database.

## Semantics of `managed`

The `managed` column (schema migration v60) distinguishes the origin of each parser/rule/playbook:

| value | origin                                                               |
|:------:|---------------------------------------------------------------------|
| `0`    | **builtin / seed** (shipped by the code, editable/can be disabled in the UI) |
| `1`    | **overlay-file** — THIS `config.d` directory (git source, durable)  |
| `2`    | **ad-hoc UI** — created through the interface's CRUD                 |

`load_overlays` performs an **UPSERT keyed by `name`**: an overlay **wins** over a builtin of the same name
(the builtin is overwritten, `managed` becomes `1`). It is **idempotent** — redeploying / restarting gives
the same state — and **durable**: the override survives the re-seeding of the builtins.

## Validation (at boot)

Each file is validated **before** insertion; an invalid file is **skipped** (warning in the
daemon logs), it **never crashes** the boot:

- **parser**: non-empty `pattern`, ≤ 1000 characters, a regex (Rust `regex` crate) that **compiles**.
- **rule / playbook**: the `query` must **compile** (GXQL or raw SQL, same path as eval/test).
- **rule**: `mitre` in `Txxxx` or `Txxxx.yyy` format (empty = unmapped).

## JSON schemas

### parser (`parsers/*.json`)

```json
{
  "name": "nginx — méthode + chemin + statut",   // required, UPSERT key
  "source": "nginx",                              // default "*" (all sources)
  "pattern": "...regex avec (?P<champ>...)...",    // required; named groups = extracted fields
  "enabled": true                                  // default true
}
```

### rule (`rules/*.json`)

```json
{
  "name": "...",            // required, UPSERT key
  "enabled": true,          // default true
  "query": "search ... | stats count",  // required; must compile
  "is_soql": true,          // default true. false = raw SQL (see security note below)
  "op": ">",                // > >= < <= == !=
  "threshold": 0,           // numeric threshold
  "severity": 3,            // 0 info … 4 critical
  "interval_s": 300,        // evaluation period
  "window_s": 3600,         // sliding window
  "mitre": "T1190"          // optional, Txxxx[.yyy]
}
```

### playbook (`playbooks/*.json`)

```json
{
  "name": "...",            // required, UPSERT key
  "enabled": false,         // default true
  "query": "search ... | table src_ip",  // required; 1st column = target of the action
  "is_soql": true,          // default true
  "action_kind": "ban_ip",  // ban_ip | unban_ip | stop_service | ...
  "interval_s": 300,
  "window_s": 3600
}
```

## Security notes

- **Raw SQL (`is_soql: false`)** reads the entire database. In the UI's CRUD, it is **reserved
  for the `admin` role** (hardening 3a); GXQL (a bounded, read-only language) remains allowed for the `editor`.
  The overlays in this directory are considered **trusted (git-reviewed)**, but the boundary **is not
  the same depending on the object** — this section used to assert a uniform "raw SQL is accepted there" that the code
  contradicted for half of the objects. Actual state, verified on 2026-08-03:

  | Overlay object | `is_soql: false` | Where |
  |---|---|---|
  | `rules/`, `playbooks/` | **REFUSED** at load (WARN + `config.overlay.reject` event) | `overlays.rs` |
  | `library-panels/`, `dashboards/` | **ACCEPTED**, and **traced** in the ledger (`config.overlay.raw_sql`) | `overlays_oac.rs` |

  The difference is deliberate: a rule runs **on its own, in a loop**, whereas a panel only renders
  what its reader is allowed to see. In both cases the query remains **validated** (must compile),
  and writing to this directory is an **operator** act (baked read-only image / ConfigMap,
  non-owner process) — never an action by an authenticated user.
- **Evaluation** of rules and playbooks runs on a **read-only connection**
  (`PRAGMA query_only=ON` + `SQLITE_OPEN_READ_ONLY` + `stmt.readonly()` guard): a rule/playbook
  can **only read**, never mutate the database (hardening 3b).

## Deployment (for reference — outside this directory)

- **Dockerfile**: `COPY plume/config.d /usr/local/share/plume/config.d`
- **Deployment**: expose `PLUME_CONFIG_DIR=/usr/local/share/plume/config.d` (or leave the default).

## Multi-deployment — the overlay is runtime-AGNOSTIC

The overlay is read from the **path** pointed to by the `PLUME_CONFIG_DIR` variable: Plume (and Forge) can
therefore be deployed **standalone**, not only on k3s. The baked `/usr/local/share/plume/config.d` remains
the **default fallback** in every mode (no variable -> that path).

| Mode | How to mount the overlay |
|:--|:--|
| **k3s** | a **ConfigMap** mounted on `PLUME_CONFIG_DIR` (declare it in your GitOps repository). |
| **docker-compose** | bind-mount `./config.d:/etc/plume/config.d` + `PLUME_CONFIG_DIR=/etc/plume/config.d`. |
| **host-native** | point `PLUME_CONFIG_DIR` at a directory on the host (e.g. `/etc/plume/config.d`). |

> The path baked into the image (`/usr/local/share/plume/config.d`) serves as the default if `PLUME_CONFIG_DIR`
> is not set — handy for a deployment without an external overlay.

## Config-driven per-dimension rollups (`PLUME_ROLLUP_DIMS`)

Independently of the files in this overlay, the **`PLUME_ROLLUP_DIMS`** environment variable adds
pre-aggregated dimensions (`event_dim_rollup`) **without recompiling**: a `search source=X | stats count by <dim>`
is then served from the rollup table (response in ms) instead of scanning the encrypted table.

- **Format**: `"source1:dim1,dim2;source2:dim3"` (sources separated by `;`, dims by `,`).
- **Semantics**: ADDITIVE (union with the compiled defaults) — never removes a built-in dim; creates the
  new sources. Cap of **6 dims/source**. Invalid identifiers silently ignored.
- ⚠️ **LOW cardinality ONLY** (`level`, `status`, `verb`, `ns`…). **NEVER** `msg`/`time`/`trace_id`:
  the top-N/bucket cap would truncate the figures AND these keys blow up the RAM (they are listed as HIGH-cardinality fields in `cim/cim.v1.json`, not to be considered for indexing).
- **Default**: `k8s-log` already includes `ns,pod,level` -> `search source=k8s-log | stats count by level` is instantaneous.
- A change to `PLUME_ROLLUP_DIMS` is taken into account on **restart** (value cached at boot).
