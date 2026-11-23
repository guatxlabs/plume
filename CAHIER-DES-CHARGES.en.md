# SOC — Requirements specification (complete, modular, multi-host vision)

[Français](CAHIER-DES-CHARGES.md) | [English](CAHIER-DES-CHARGES.en.md)

> Extends `ARCHITECTURE.md` (v1 design).
> Here = the **wish list / target spec**: everything that can be **built if needed**
> to make the SOC a **modular, scalable, offensive+defensive, multi-platform** tool, without
> ever shrinking the defensive surface. Inspired by **Splunk ES, Wazuh, Microsoft Defender XDR,
> CrowdSec, Elastic, Sigma/YARA, Atomic Red Team** — adapted to the constraints (Rust+SQLite+Svelte,
> host-native, <100 MB database, localhost least-priv, everything query-driven & replayable).

## 0. Guiding principles
1. **Modular**: each capability = a module (collector / detector / responder / viz) **that can be enabled
   per host** via `soc.conf`. Minimal core; only what is needed is enabled (a VPS ≠ a laptop).
2. **Observe ≠ enforce**: the SOC **detects + responds**, but the **existing enforcement stays** (golden
   rule, see §2). "Response" delegates to the blockers in place (CrowdSec/fail2ban/nft).
3. **Light by default, rich on demand.** 4. **Everything query-driven** (panels = queries).
5. **Everything replayable** (git + bootstrap). 6. **The SOC must not be a hole** (least-priv,
   integrity, RBAC, localhost/tunnel).

---

## 1. "Zero gap" GUARANTEE — the MECHANISM (direct answer)

> The roadmap **alone** guarantees nothing. What guarantees = **verifiable mechanisms**:

1. **Control Catalog (controls inventory)** — a declarative table of EVERYTHING that must exist
   (each defence: name, type `enforce|detect`, host, expected source, "proof of life"). The SOC
   **continuously checks** that each control is **present AND alive** → **alert if something is missing**
   (fail2ban jail down, bouncer absent, control nft rule gone, silent sensor). THAT is
   what proves that "no component is missing" — not a promise, an automatic check.
2. **MITRE ATT&CK mapping** — each detection mapped to a technique → **coverage
   dashboard** that shows the **techniques NOT covered** = the gaps are **visible**, measured.
3. **Parity go/no-go** (see §2) — a component is only **removed/replaced** after proof
   that the equivalent exists (data in the SOC + alert + enforcement unchanged).
4. **Baseline + diff everywhere** — any deviation (port, SUID, unit, nft rule, file hash) = alert →
   no silent drift.
5. **Self-monitoring** — heartbeat of each collector; integrity of the SOC's chain
   (hash-chain + Ed25519 checkpoints); "silent sensor" = alert.
6. **BAS (active proof)** — execute known ATT&CK techniques (sandbox) and **check that the
   SOC detects them** → *active* proof of no gap (not only declarative).

---

## 2. Coexisting with an existing stack: KEEP / REPLACE

Plume **never** arrives by replacing everything: it adds itself, proves parity, then you decide. The
classification rule, applicable to **any** stack in place:

| Class | What goes in it | Reason |
|---|---|---|
| **REPLACEABLE by Plume** | visualization / dashboards, log search, metric presets, redundant collection relays | Plume is a **superset** of these functions (SQL+FTS search, query-driven dashboards, single-pane) |
| **KEPT — NEVER touched (enforcement)** | everything that **blocks**: host firewall, bans/bouncers, IdP, NetworkPolicies, admission, secrets manager | **Plume observes, it does not replace enforcement** (see §0.2) |
| **KEPT (in parallel)** | operational alerting (availability, capacity) | infra alerting ≠ security detection: complementary |
| **DECOMMISSIONED (only after proven parity)** | a server whose function Plume now covers | parity go/no-go, see §1.3 — never before |

Method: **additive first** → run in parallel → parity check → removal. See
[`deploy/OBS.md`](deploy/OBS.md) for the concrete procedure on the metrics/logs side.

---

## 3. FUNCTIONAL REQUIREMENTS

### 3.1 Collection / ingestion (multi-source, multi-platform)
- **Linux/host**: journald, auditd, syslog, files (tail), nft, `ss`, `/proc`, systemd units, packages/CVE.
- **Containers/k8s**: docker events + API, **k8s audit log**, runtime, syscall (falco-style, optional), Trivy (images).
- **Windows**: ETW agent + **Sysmon** + Windows Event Log (EVTX) + Defender/ASR logs.
- **Network**: NetFlow/conntrack, Suricata/Zeek `eve.json` (optional), DNS logs.
- **Existing stack (ingestion, not re-collection)**: decisions from an IPS/CTI (e.g. CrowdSec), log aggregator already in place (bounded query), Prometheus metrics, nft snapshot.
- **Agents**: roles `standalone|agent|central` (ARCHITECTURE §13), **adaptive** (skip absent sources), config-gated, signed shipping (Ed25519) over WireGuard.
- **ECS-like normalization**: common schema `ts/host/source/category/severity/fields/mitre` (interop).

### 3.2 Storage & retention
- SQLite WAL+FTS5 (base); time partitioning; metrics **downsampling**; configurable retention;
  `VACUUM`; **disk cap + alert**. Scale option: columnar store (DuckDB/Parquet) for large volumes.

### 3.3 Search & query language ("an SPL in Rust, > PromQL")
- Engine = **validated read-only SQL** (ARCHITECTURE §7) + **FTS5**.
- **Unified pipe DSL "GXQL"** (SPL style) compiled to SQL: `search source=sshd "failed" | stats count by user | where count>5 | sort -count`. **ONE single language for logs + metrics + events** (vs PromQL=metrics only, LogQL=logs only) = the key advantage.
- Functions: `stats/agg` (count/sum/avg/percentile/rate), `group by`, **time bucket**, joins (FTS+relational), `eval`, **lookup** (IOC/CTI/geo/asn enrichment), regex extract, subsearch, `timechart`, `top`, `transaction` (correlation by session).
- **Autocompletion / helpers**: list available sources, fields, values (the "see the jobs/labels" need).
- **Cost per query** (requested): profile each query — **rows scanned, CPU, RAM, + timings
  parse→exec→fetch→render→network** — display the cost + **budget/timeout/kill** (anti-runaway-query).
- **Queries**: saved, **scheduled** (saved search → alert/panel), history, **real time** (SSE → "see the queries live").

### 3.4 Dashboards (easy creation/editing/saving, real time, examples)
- **Everything query-driven** (panel = query + viz; `dashboard`/`panel` tables already in the schema).
- **Viz**: table, stat (single value), **timechart**, bar, top, heatmap, gauge, **geo-map** (IP),
  **graph** (process/host/IP relations), Sankey (flows).
- **Easy editor**: add/reorder/resize panels; **global variables & filters**
  (time range, host); **drill-down** (click → filtered query); **edit & save** a dashboard.
- **Real time**: SSE/adjustable auto-refresh.
- **Shipped example dashboards** (built-in, all **editable**): Overview/posture · **ATT&CK coverage** ·
  Auth timeline · Firewall (+ control integrity) · CVE · Containers · Network/IDS · Resources ·
  Integrity/FIM · Persistence.
- **Export/import** of dashboards (JSON) → sharing & migration.

### 3.5 Detection (rules, correlation, MITRE, light ML)
- **Declarative TOML** rules: query+threshold · baseline diff · **sequence/correlation** (multi-event, window).
- **Sigma** import/conversion → engine (build-time, zero runtime cost).
- **YARA** file/memory scan (IOC/malware/samples).
- **MITRE ATT&CK** mapping per rule + coverage (see §1.2).
- **Risk-Based Alerting** (Splunk-style): cumulative risk score per host/user → alert at the threshold
  (reduces noise, prioritizes).
- **Light UEBA**: behavioural baselines (auth volume, usual processes/hours) + anomaly
  (z-score/IQR — no heavy ML).
- **CTI / threat intel**: feeds (CrowdSec CAPI, **MISP**, blocklists, AbuseIPDB, Tor exit) → automatic
  enrichment (IP → reputation/geo/ASN) + IOC match. De-dup, suppression/whitelist, tuning.

### 3.6 Response (SOAR-lite / XDR — "detection + response")
- **Declarative playbooks** (TOML): alert → **automatic or semi-automatic** actions (approval).
- **Actions**: ban IP (**delegates** to CrowdSec/fail2ban/nft = the existing enforcement) · isolate a host ·
  kill process · quarantine file (YARA) · disable account · forensic snapshot · notify (dunst/ntfy/webhook).
- **AIR** (automated investigation, Defender-style): on alert, collect the context (process tree,
  connections, files, user) → automatic **investigation file**.
- **Live response** (Defender-style): remote shell **bounded + audited + admin RBAC + allowlist** on an
  agent (forensics/remediation). ⚠️ opt-in, never arbitrary (otherwise = security hole).
- **Case management** (light TheHive-like): alerts → cases (assignment, status, timeline, notes, linked IOCs).
- SOC metrics: **MTTD / MTTR**, false positives, coverage.

### 3.7 Offensive (self-assessment of ONE'S OWN infra)
- **ASM (Attack Surface Management)**: scan of one's own infra (exposed ports, services, certs, DNS,
  subdomains) → exposure inventory + drift ("what does an attacker see").
- **Vuln**: arch-audit (host) · **Trivy** (images/containers) · light bounded network scan (nmap-like) · CVE→exploitability.
- Light **BAS (Breach & Attack Simulation)**, **Atomic Red Team-style**: replay sandboxed ATT&CK
  techniques → **check that the SOC detects** (= proof of coverage, §1.6).
- **Safeguard**: offensive **only on one's own infra**, opt-in, **never** external mass-scanning.

### 3.8 Posture / compliance
- **SCA/CIS** (Lynis + CIS benchmarks, Wazuh-style) → score + drift · hardening (sysctl/cmdline/lockdown)
  · **FIM/AIDE** · system inventory (packages/users/services/SUID) + diff · global posture score.

---

## 4. NON-FUNCTIONAL REQUIREMENTS

| Requirement | Target mechanism |
|---|---|
| **Modular** | everything = a module enabled through `soc.conf` (per host); core <100 MB; (future) module registry |
| **Scalable & HA** | standalone/agent/central roles → **cluster of centrals** (sharding by host); buffered ingestion queue (disk) + backpressure; failover |
| **Replicated** | DB replication (litestream/SQLite-replication → MinIO/S3); secondary central |
| **Built-in backup** | SQLite snapshot + WAL → MinIO/S3/local, **encrypted, scheduled**, the SOC **backs itself up + alerts on failure** |
| **Easy export** | events/dashboards/rules → JSON/CSV/Parquet; export API |
| **Migration** | dump+restore; **schema migrations** (`meta.schema_version`); upgrade `git pull→build→bootstrap` + rollback |
| **Easy install/deploy** | **1 static musl binary**; idempotent `bootstrap.sh`; deb/rpm/pacman(AUR) packages; **OCI container**; **Helm chart (k3s/k8s)**; signed one-liner; Windows MSI+service |
| **Easy replica** | clone + `soc.conf` (role) → new host in 1 command |
| **Multi-platform** | Linux(systemd) · Windows(service/ETW/Sysmon) · macOS(optional) · Docker(sidecar/socket) · **k3s/k8s (agent DaemonSet + /ingest)**; collectors auto-detect the platform |
| **Security of the SOC** | non-root web · read-only DB API · validated read-only SQL · loopback/tunnel bind · **RBAC** (viewer/editor/admin) · auth basic_auth→OIDC · **hash-chain integrity + Ed25519 checkpoints** · **every response action audited** · 0600 secrets outside the repo · signed agents |
| **Perf** | <100 MB database · systemd limits (`MemoryMax`/`CPUQuota`) · timers (no polling) · retention/downsampling · efficient FTS |
| **a11y / UX** | WCAG AA (ARCHITECTURE §8/§14) · dense/fast · severity = icon+text · keyboard · `prefers-*` |
| **Maintenance** | git · migrations · smoke tests · self-monitoring · single config · docs |

---

## 5. Inspiration → what we take (feature mapping)

| Tool | What we take |
|---|---|
| **Splunk ES** | SPL (→ GXQL DSL), correlation searches, **risk-based alerting**, UEBA, data models, **detection versioning/rollback**, dashboards, SOAR workflow |
| **Wazuh** | **FIM**, **SCA/CIS**, **vuln detection (CVE)**, **active response**, **MITRE mapping**, system inventory, multi-OS agent |
| **Defender XDR** | **EDR** (behavioural telemetry), **AIR** (automated investigation), **advanced hunting** (query language), **live response**, **attack disruption/containment** |
| **CrowdSec** | scenarios, **bouncers** (delegated enforcement), community **CAPI/CTI** |
| **Elastic SIEM** | detection rules, **timelines**, cases |
| **TheHive+Cortex** | case management, analyzers/responders |
| **MISP** | CTI / IOC platform |
| **Sigma / YARA / OSQuery / Velociraptor** | vendor-neutral rules / file scanning / endpoint query / remote DFIR |
| **Atomic Red Team / Caldera** | **BAS** (proof of coverage) |

---

## 6. Prioritization (MoSCoW) & phases

- **MUST (SOC core, one Linux host covered end to end)**: journald/auditd/nft collection + ingestion
  of the sources already in place (P5) · SQL+FTS search + GXQL DSL (P3) · query-driven dashboards + examples
  (P3) · rules+alerts+MITRE (P3/P4) · **Control Catalog self-audit (§1)** · built-in backup · remote
  agent (P7).
- **SHOULD**: YARA/AIDE/SUID-persistence (P4) · RBA + light UEBA · response playbooks (delegated) · case
  management · export/import · Sigma (P8) · Linux+Docker+k8s multi-platform.
- **COULD**: Windows/Sysmon · BAS/Atomic · ASM/exposure · live response · cluster of centrals/HA ·
  columnar store · macOS.
- **Phases**: the foundation (P0→P8) then **P9 Response/SOAR-lite**, **P10 Offensive/BAS/ASM**,
  **P11 Windows/multi-OS**. Each module respects §0 (modular, observe≠enforce) and §1 (anti-gap).

---

### Sources of inspiration (features studied)
- Splunk Enterprise Security (correlation searches, RBA, UEBA, SOAR, detection versioning).
- Wazuh (FIM, SCA/CIS, vuln detection, active response, MITRE mapping, inventory).
- Microsoft Defender XDR (EDR, automated investigation & response, advanced hunting KQL, live response, attack disruption).
