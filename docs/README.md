# Plume documentation — index

[English](README.md) | [Français](README.fr.md)

Entry point of `docs/`. The *what* and *why* of the architecture are in
[`../ARCHITECTURE.md`](../ARCHITECTURE.md); installation and the three deployment modes in
[`../README.md`](../README.md); the contribution rules in [`../CONTRIBUTING.md`](../CONTRIBUTING.md).

**Status** — every document carries one of these states. Read it before following a procedure: several
documents describe a **design** whose runtime wiring does not exist yet, and this is said
explicitly rather than left for the operator to discover.

| State | Meaning |
|---|---|
| ✅ **Shipped** | implemented in the shipped binary, usable as is |
| 🧪 **Opt-in / experimental** | implemented behind a compile-time feature or a flag, not enabled by default |
| 📐 **Design** | reference design; **not** (or not fully) wired at runtime |

## Using it (the lifecycle, for the operator)

These six pages describe the product **as it is**, for someone who operates it: install,
configure, use, uninstall — in all **three** deployment modes. Every claim there
carries the command that reproduces it, and what has not been executed is said next to the example.
The guard [`check_operator_surface_is_documented.py`](../.github/scripts/check_operator_surface_is_documented.py)
derives from the sources what an operator must be able to find — tabs, sensors, modes, levers — and
refuses an addition that goes in without being written down (`P9.7-b`).

| Document | State | What for |
|---|---|---|
| [INSTALLER-SANS-OUVRIR-DE-BRECHE.md](INSTALLER-SANS-OUVRIR-DE-BRECHE.md) | ✅ | **Installing it yourself without opening a breach, step by step** — what is open by default in each mode, TLS and authentication, where each token lives and what it allows, **a sensor-by-sensor table** (what it reads, its privileges, what it brings into the SIEM, its risk, the query that proves it reports), the transport, the accepted risks, and the sensor that feeds each seeded dashboard. |
| [TROIS-MODES.md](TROIS-MODES.md) | ✅ | **The same operation in all three modes** — native host, Docker, k3s. Where things live, how to change a setting, add a source, create a token, back up, update — and **the operations that do NOT exist** in a mode, named instead of smoothed over. |
| [CONSOLE.md](CONSOLE.md) | ✅ | **The console, space by space and tab by tab** — what each one does, which role sees it, what it does not do. Derived from the navigation structure, not copied. |
| [GXQL.md](GXQL.md) | ✅ | **The search language** — the twenty commands, the functions, the bounds, the read-only layers, and above all **what the grammar does not accept** (no `OR`, no grouping, no multi-field sort). |
| [AGENTS-PROTOCOLE.md](AGENTS-PROTOCOLE.md) | ✅ | **The agents and their protocol** — the wire contract, the tokens and what "bound to the host" really means, the disk buffer and **its lack of a bound on the shell side**, the watermarks, the return channel, TLS. |
| [CHIFFREMENT-COMPRESSION.md](CHIFFREMENT-COMPRESSION.md) | ✅ | **Encryption and compression, as they are** — what is encrypted, what is not, the `age(zstd(…))` order, and the measured defect: **without a database key, the backup scheduler produces nothing**. |

## Operating (operator)

| Document | State | What for |
|---|---|---|
| [DR-plume-restore.md](DR-plume-restore.md) | ✅ | **Disaster recovery** — the two backup formats the product produces, and how to restore each. Read it *before* you need it. |
| [COMPLIANCE.md](COMPLIANCE.md) | ✅ | Compliance posture and coverage (≠ certification). |
| [PURGE.md](PURGE.md) | ✅ CLI · 🧪 HTTP | **Purging named events** (beyond time-based retention): two phases with a token, reasoned refusals (legal hold, cold tier, chain of evidence), inscription in the ledger — and the explicit list of what is **not** covered, starting with backups. |
| [DETECTION-CATALOG.md](DETECTION-CATALOG.md) | ✅ | Curated detection catalogue shipped as a starting point. |
| [../deploy/CONFIDENTIALITE.md](../deploy/CONFIDENTIALITE.md) | ✅ | TLS, real scope of agent tokens, at-rest encryption, caveat on the plaintext export of the backup. |
| [../deploy/PROFILE.md](../deploy/PROFILE.md) | ✅ | Deploying on any infrastructure (`PLUME_*` variables, scripted inputs). |
| [../deploy/K8S.md](../deploy/K8S.md) | ✅ | Detailed Kubernetes deployment. |

## Ingesting and normalising

| Document | State | What for |
|---|---|---|
| [SDK.md](SDK.md) | ✅ | The **bring-your-own-vendor** model: where to plug in a source. |
| [CIM.md](CIM.md) | ✅ | The common information model — the event taxonomy rules are composed on. |
| [VALEURS-DES-CAPTEURS.md](VALEURS-DES-CAPTEURS.md) | 📐 | **What a sensor emits, and what its values mean.** The common model above declares **one** vocabulary per field; a sensor, however, writes only a subset, and two sensors write the same field name with unrelated meanings — so the key is the pair **(source, field)**. Says what the shipped producers already declare, what reaches neither the wire nor the screen, and why the gap is not closed by a hand-written table (`P11.19-a`). |
| [PARSER-DSL.md](PARSER-DSL.md) | ✅ | Declarative parser (CIM DSL): add a log format **without a rebuild**. |
| [CONNECTOR-PRESETS.md](CONNECTOR-PRESETS.md) | ✅ | Ready-to-use `http_pull` presets (AWS, M365/Entra, Okta, CrowdStrike, SentinelOne, GCP, Cloudflare, Google Workspace). Files in [`connector-presets/`](connector-presets/). |
| [SIGMA-IMPORTER.md](SIGMA-IMPORTER.md) | ✅ | Sigma rule import (single and bulk) + ATT&CK coverage delta. |
| [ENDPOINT-SECURITY.md](ENDPOINT-SECURITY.md) | ✅ | Endpoint security with a BYO agent. |
| [OTLP-TRACES.md](OTLP-TRACES.md) | ✅ | OpenTelemetry receiver (traces). |

## Collecting at the edges (workstations, devices, mailboxes)

Where events are BORN. Each of these paths ends on the same wire contract as the ingest —
which is what makes it possible to add one without touching the central server.

| Document | State | What for |
|---|---|---|
| [../agent/README.md](../agent/README.md) | ✅ | **Cross-OS endpoint agent**: reads the OS's native sources, buffers on disk (bounded spool, *at least once*), POSTs to the ingest. |
| [../agent/CI.md](../agent/CI.md) | ✅ | How this agent is **validated**: what CI actually executes per platform, and what it only compiles. |
| [../collectors/windows/README.md](../collectors/windows/README.md) | ✅ | **Windows collector** in PowerShell, a single file, with no agent and no spool: direct POST to `/api/ingest`. |
| [../deploy/SYSLOG.md](../deploy/SYSLOG.md) | ✅ | **Syslog receiver** (RFC 5424 + RFC 3164, UDP and TCP) and pluggable vendor parsers: a network device becomes one more collector. |
| [../deploy/MAIL.md](../deploy/MAIL.md) | ✅ | **Mail detection** read from the host's maildir: curated patterns (IOC, phishing, URL), minimal events. |
| [../deploy/EBPF-SIGMA.md](../deploy/EBPF-SIGMA.md) | ✅ | Plugging **eBPF** runtime detection (Falco JSON output) and **Sigma** rules into the ingest. |

## Interoperating

| Document | State | What for |
|---|---|---|
| [DATASOURCE.md](DATASOURCE.md) | ✅ | Serving queries **to** Grafana/Prometheus (Plume as a data source). |
| [OBSERVABILITY-AS-CODE.md](OBSERVABILITY-AS-CODE.md) | ✅ | Versioned dashboards and rules. |
| [NATIVE-IDP.md](NATIVE-IDP.md) | ✅ OIDC/LDAP/MFA · 🧪 SAML | Native IdP. **SAML requires `--features saml`** — absent from the shipped image (→ 501). |

## Storage — analytical tiers

| Document | State | What for |
|---|---|---|
| [DUCKDB-STORE.md](DUCKDB-STORE.md) | 🧪 | WARM analytical tier. The documented `PLUME_STORE` selector is **an unwired design** — only `PLUME_STORE_DUCKDB_EXPERIMENTAL` is read. |
| [CLICKHOUSE-STORE.md](CLICKHOUSE-STORE.md) | 📐 | Single-node adapter. `PLUME_STORE=clickhouse` **has no effect** today. |
| [CLICKHOUSE-HA.md](CLICKHOUSE-HA.md) | 📐 | Distributed multi-node scaffold — inert, not wired (and masking is not yet ported to the neutral SPI: read this before touching it). |

## Measuring performance

| Document | State | What for |
|---|---|---|
| [BENCHMARK.md](BENCHMARK.md) | ✅ | **The figures of reference, and the instrument to contradict them.** The matrix (query classes × windows × masking × FTS × cold tier × fleet size) on a synthetic database with a production profile, daemon under a cgroup `MemoryMax=2G` that is **enforced** — not observed. States what is **slow** as frankly as what is fast, publishes the remaining levers by measured gain, and NAMES the cells it has not measured. The harness (`../bench/`) re-runs the matrix with a single command and publishes its raw data, so that a third party can redo — or contradict — the measurement. **Read its qualifiers before quoting one of its figures**: no count is copied here (it would rot), the reference volume is not 10 M — the real ingest throughput and the MEASURED CAUSE of its degradation are published instead — and the database fit in the page cache, so the latencies are a CPU-bound **best case**. |
| [../bench/README.md](../bench/README.md) | ✅ | **THE INSTRUMENT** that produces the document above: what each pass measures, what each results file contains, and the reading traps named one by one. Read it before contradicting a figure — or quoting one. |

## Direction and internals

| Document | State | What for |
|---|---|---|
| [MODULE-MAP.md](MODULE-MAP.md) | ✅ | **Map of the subsystems + security invariants.** The document to read before a first contribution. |
| [AI-ML-DIRECTION.md](AI-ML-DIRECTION.md) | 📐 | AI/ML direction: optional, vendor-neutral, RAM-neutral, OFF by default. |
| [DESIGN-P10-echelle-2go.md](DESIGN-P10-echelle-2go.md) | 📐 | **Staying under 2 GiB at scale** — the map of the MEASURED ground (where the bytes go, where the sort RAM goes) and the order of levers that follows from it: hot/cold, columnar, bloom, compression. This is the document that carries the freshest state of this work; the `P10.*` keys of [ROADMAP.md](ROADMAP.md) point to it. A brainstorm anchored in measurement, **not** a frozen decision. |
| [ROADMAP-SUMMARY.md](ROADMAP-SUMMARY.md) | ✅ | **Where each workstream stands**, one section per phase — the English summary of [ROADMAP.md](ROADMAP.md), the public index of workstreams, which is kept in French. |

## Non-narrative resources

- [`img/`](img/) — screenshots and animated demo used by the README.
- [`connector-presets/`](connector-presets/) · [`ai-presets/`](ai-presets/) — shipped JSON presets.
- [`soql-templates/`](soql-templates/) — GXQL query library. **Historical directory name
  kept on purpose**: the file is embedded by `include_str!` from the daemon and copied by the
  `Dockerfile`; it is a build identifier, not a user-facing label (see the GXQL/`soql` naming
  boundary described in [`../README.md`](../README.md)).
