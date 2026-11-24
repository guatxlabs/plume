# Plume CIM — Common Information Model (v1.0)

[English](CIM.md) | [Français](CIM.fr.md)

> **Status: NORMATIVE, versioned contract.** This document formalises Plume's canonical
> information model — the NEUTRAL `category` vocabulary and the core field set — on
> which *every* detection already composes, in a **vendor-agnostic** way. It makes EXPLICIT
> a contract that was until now implicit in the code; **it changes no runtime behaviour**.

- **Version**: `1.3` (SemVer `majeur.mineur`; major = breaking change to the taxonomy/fields). v1.1 (#57) adds
  the `posture` (config-assessment / SCA-CIS) and `inventory` (endpoint inventory) categories; v1.2 (#41)
  adds the `trace` category (OpenTelemetry telemetry, correlatable by `trace_id`); v1.3 (Reorg Wave 2)
  adds **retroactive canonical homes** for categories ALREADY emitted by live collectors —
  `exec` (auditd execve), `secrets` (vault-audit), `account` (auditd), `recon` and the sub-stages of the
  mail collector (`postscreen`/`reject`/`mailflow`/`mail-phishing`/`mail-url`) — **plus a per-event version
  stamp** (`fields.cim`, §4f). Everything additive (no row rewritten, zero migrations).
- **Machine mirror**: [`config.d/cim/cim.v1.json`](../config.d/cim/cim.v1.json).
- **Code anchor**: `CIM_VERSION` / `CIM_CATEGORIES` / `CIM_CORE_FIELDS` / `CIM_ACTION_VOCAB`
  + the `cim_category_ok()` validator in `guatx_core::cim` (crate `guatx-core`, `src/cim.rs`).
- **Anti-drift guard**: two tests require that **the code const == the JSON** — `cim_contract_is_self_consistent`
  (`tests` module of `guatx_core::cim`, internal consistency of the contract) and
  `cim_const_mirror_matches_config_schema` (`daemon/src/tests/detection.rs`, const ↔ schema mirror).
  Doc, code and schema cannot diverge without breaking `cargo test`.

---

## 0. Guiding principle — ENRICH, never SUPPRESS

The CIM is a **PARSE / MAP / ENRICH** model. Recognising, mapping or enriching a
`category` **never suppresses** an event. An out-of-taxonomy `category` is
**accepted as is** (ingest is unchanged) and only **reported** (`warn`) — never
rejected. Any reduction of collection (drop/suppress) is a **filter**, which belongs to the
*whitelists* panel (#10) and to the `sev 3` audit (`/api/sources/settings`), **not to the CIM**.

This is the anti-blind-spot guarantee: the CIM enriches the data, it does not censor it.

> **Overview of extensions.** The CIM is the **pivot** of the *bring-your-own-vendor* model: see
> [`docs/SDK.md`](SDK.md) for the map of seams (parser, connector, detection, threat intel, enforcer) and
> the "describe, don't code" rule.

---

## 1. The canonical row — `EventRow`

Every ingest path (syslog, journal, shell collectors, native MinIO, agents) **converges**
on a single row, `EventRow` (`guatx_core::store`, crate `guatx-core`, `src/store.rs`), inserted by a single fixed SQL statement
(`EVENT_INSERT_SQL`, `INSERT OR IGNORE` on `dedup`). The columns below form the
**CORE field set** (first class: indexed / directly filterable).

| field           | type    | semantics |
|-----------------|---------|------------|
| `ts`            | integer | Event timestamp — **epoch seconds, UTC**. |
| `source`        | string  | Identity of the **PRODUCER / vendor** (`fortigate`, `suricata`, `web`…). **Never the semantics.** |
| `category`      | string  | **NEUTRAL semantic** class (§2) — the axis along which detections compose. |
| `severity`      | integer | **0..4** (§3). |
| `message`       | string  | Human-readable summary. |
| `host`          | string  | Observing/reporting host. **RESOLVED AT WRITE TIME, IN A SINGLE PLACE**: `HoteIngere::resoudre` (`daemon/src/ingest/store.rs`) returns the host **of the token** when that token is bound to a machine, and the **declared** host otherwise. A machine token can therefore only write under its own host, **on every ingestion surface** (`/api/ingest`, `/api/ingest/journal`, `/api/ingest/minio`, `/api/metrics/prom`, `/api/metrics/write`, `/loki/api/v1/push`, `/services/collector`, `/v1/traces`) — the resolution does not know the routes, so it cannot forget one. A **relay** token (`--relais`, multi-host forwarder) writes under the host it declares: that host is **not** attested. *Before: the binding was only consulted on the `/api/ingest` and `/loki/api/v1/push` paths. Measured on 2026‑08‑02 with a token bound to `WS22-LAB` — `/api/metrics/prom?host=HOTE-USURPE-PAR-METRICS` → HTTP 200 and the metric stored under the spoofed host; `/api/metrics/write` (label `instance`) → 204, likewise; `/services/collector` (HEC, `"host":"HEC-USURPE"`) → 200, likewise. Four surfaces, only one of which was documented as such.* |
| `src_ip`        | string  | Source IP — column **promoted** from `fields.src_ip` \| `fields.rhost` (§4). |
| `dst_ip`        | string  | Destination IP — column **promoted** from `fields.dst_ip`. |
| `url`           | string  | URL / host+path — column **promoted** from `fields.url`. |
| `dedup`         | string  | Anti-duplicate key (`INSERT OR IGNORE`). **PARTITIONED BY HOST AT WRITE TIME**: the STORED value is `dedup_scoped_by_host(host, dedup)` (`daemon/src/ingest/store.rs`), so the uniqueness scope is the row's HOST, not the database. A sender does **not** have to include the host in its key — and **cannot** produce one that collides across machines, whatever its language. It must, however, produce a **stable and deterministic** key for the same event; that key is what absorbs re-sends from the spool (at-least-once). *Before this partitioning, two machines silently stole each other's events: measured 45 Sysmon events lost on Windows (see `collectors/windows/README.md`) and 26 out of 78 on the Linux side (see the header of `ingest/store.rs`).* |
| `fields`        | object  | JSON bag of **EXTENDED** fields (vendor/parser-specific). |
| `engagement_id` | string  | Purple-team engagement correlation. |
| `origin`        | string  | Ingestion origin marker. |
| `env_id`        | string  | Environment binding (default `prod`). |

> The `EventRow` struct + `EVENT_INSERT_SQL` remain the **authoritative** definition;
> `CIM_CORE_FIELDS` is its tested contract mirror.

---

## 2. `category` taxonomy (v1.3 — 40 values, closed-ish)

`source` = **WHO** produces (vendor). `category` = **WHAT** semantically (neutral,
cross-vendor). Rules compose on **`category=…`, never by vendor** — this is what makes
a detection portable from FortiGate to Suricata to a future Defender connector without a rewrite.

Two **namespaces**. The split is **GUIDANCE** (the runtime treats all
categories identically):

- **security** — attack/security signal; the axis on which detection rules compose.
- **operational** — collector telemetry, configuration state, audit trail; **not** a primary attack
  signal — feeds health / coverage / whitelists.

### 2a. `security` namespace (27)

| category | meaning | example sources |
|----------|---------------|-------------------|
| `firewall`    | L3/L4 filtering, allow/deny, session/traffic.                              | `fortigate(traffic)`, `ufw`, `nft`, `origin-drop` |
| `ids`         | Intrusion detection/prevention, anomaly.                              | `suricata`, `fortigate(ips/anomaly)` |
| `alert`       | IDS signature alert.                                                     | `suricata` |
| `web`         | Web filtering / proxy / WAF / application HTTP access.                       | `web`, `fortigate(webfilter/waf)`, `cloudflare-http` |
| `malware`     | Antivirus / EDR / YARA detection.                                        | `clamav`, `yara`, `fortigate(virus)` |
| `auth`        | Authentication / authorisation (login, sudo, session).                   | `journal(sshd/sudo)`, `fortigate(user)` |
| `dns`         | DNS query / filtering.                                                   | `fortigate(dns)` |
| `mail`        | Email security / filtering.                                               | `mail`, `fortigate(emailfilter)` |
| `dlp`         | Data loss prevention.                                          | `fortigate(dlp)` |
| `vpn`         | VPN tunnel events.                                                | `fortigate(vpn)` |
| `application` | Application control (app-ctrl).                                          | `fortigate(app-ctrl)` |
| `endpoint`    | Endpoint / EMS / EDR.                                                     | `fortigate(endpoint/ems)` |
| `network`     | Network flows / telemetry; neutral bucket for unmapped FortiGate types. | `conntrack`, `crowdsec`, `fortigate(router/inconnu)` |
| `data`        | Data access / object storage / RBAC-to-data.                  | `minio`, `kube-rbac`, `dataaccess`, `dataacl` |
| `tamper`      | Tampering with an integrity-critical object (tripwire).                   | `auditd(sudoers.d/shadow)` |
| `vuln`        | Vulnerability finding.                                                | `vuln` |
| `utm`         | FortiGate UTM catch-all (unmapped subtype) — neutral bucket.          | `fortigate(utm)` |
| `posture`     | Configuration / compliance assessment (SCA-CIS): host × benchmark × check × pass\|fail × framework. | `wazuh(sca)`, `openscap`, `osquery(pack)` |
| `exec`        | **Process execution** (execve) — host execution monitoring. v1.3: canonical home of the **dominant** auditd flow (~30 % of events), compliant **retroactively**. | `auditd(execve)`, `osquery(process_events)` |
| `secrets`     | Access to the **secrets vault** (read / write / delete of a secret). v1.3. | `vault-audit` |
| `account`     | **Account management** (creation / modification / deletion of a user or group). v1.3. | `auditd(useradd/usermod/passwd)`, `journal` |
| `recon`       | **Reconnaissance** / enumeration / discovery activity. v1.3. | `nft(portscan corrélé)`, `moat-probe` |
| `postscreen`  | Postfix **postscreen** — pre-filtering of inbound SMTP connections (mail sub-stage). v1.3. | `mail(postscreen)` |
| `reject`      | **SMTP rejection** (relay / policy / RBL) — mail sub-stage. v1.3. | `mail(reject)` |
| `mailflow`    | **Mail flow** stage (delivery / queue / transport) — mail sub-stage. v1.3. | `mail(mailflow)` |
| `mail-phishing`| **Phishing** signal detected in the mail flow — mail sub-stage. v1.3. | `mail(phishing)` |
| `mail-url`    | **URL extracted** from a message (link analysis) — mail sub-stage. v1.3. | `mail(url)` |

> **v1.3 note — mail sub-stages.** `mail` remains the primary email security category; the five
> sub-stages above (`postscreen`/`reject`/`mailflow`/`mail-phishing`/`mail-url`) are the **labels that
> the mail collector ALREADY emits** as `category`. They are given a canonical home WITHOUT touching the collector
> (ADDITIVE, see §0): the goal is contract↔producer parity, not re-normalisation. A future
> evolution COULD fold these labels into `category=mail` + `fields.mail_stage=…`, but that would be a
> producer change (out of scope) and not backward-compatible.

### 2b. `operational` namespace (13)

| category | meaning | example sources |
|----------|---------------|-------------------|
| `health`    | Collector heartbeat / liveness (0 attacks = normal; distinguishes **silence** from **failure**). | all collectors (health beat) |
| `config`    | Collector self-report: transparency of filters (**whitelists #10**) **and AVAILABILITY** — `fields.collect_status` ∈ {`unavailable`, `disabled`, `fallback`, `partial`} + `fields.reason`: the first two say that a sensor CANNOT collect (missing dependency/source/setting), instead of silently exiting with success. See `plume_unavailable` / `plume_disabled` (`collectors/lib.sh`). A seventh `reason` word does NOT describe an inability: `collection-capped` says that the sensor collected and then CUT OFF by itself, at a bound THAT IS ITS OWN (line ceiling per pass, duration bound on an operator command) — the source was fine, the coverage is incomplete by construction, and the detail carries the number of lines discarded (or "nombre inconnu" when the bound does not allow it to be read). It is forbidden on primitives that EXIT (a crossed bound does not stop a pass); its gate is `plume_collecte_tronquee`. **THIRD STATE, DECLARED on 2026-09-09 (`P4.6-c`)**: `fallback` / `reason=unreadable-config` says that a SETTING could not be read and that a default applies in its place, the collection being COMPLETE — measured on 2026-08-27 on `collectors/custom.sh` (`MAX=deux` → 4 events published), which at the time used `unavailable / missing-config` and flipped the status badge of a healthy source. Its gate is `plume_reglage_illisible` (`collectors/lib.sh`), severity 1, forbidden on primitives that EXIT; the shipped rule `de-collector-unavailable` does not query it, and it can be queried: `search category=config collect_status=fallback`. **FOURTH STATE, DECLARED on 2026-09-29 (`P10.23-i`)**: `partial` / `reason=unreadable-address` says that the sensor READ the source and CLASSIFIED lines (authentication failure or success, block, rejection) that it did not emit, for lack of a valid source address (for example Postfix's `unknown[unknown]` client); the detail carries their number and their breakdown by category, the deduplication key does not carry the number. It is neither an inability (`unavailable` would make the shipped rule alert and flip the status badge of a healthy source), nor a sensor bound (`collection-capped`, which an operator raises), nor a complete collection (`fallback`). Its gate is `plume_adresse_illisible` (`collectors/lib.sh`), severity 2 (events are lost), it does not exit; the shipped rule `de-collector-unavailable` does not query it, and it can be queried: `search category=config collect_status=partial`. **`fields.hors_vocabulaire`** (decision of 2026-09-10, `P11.19-b`): when a Rust producer (agent, mail collector, syslog collector) emits for `reason` or `cause` a word outside the set it declares, the word goes out AS IS and this field names, separated by commas, the field(s) concerned — nothing is lost, the debt is visible and queryable: `search category=config hors_vocabulaire=*`. | `web`, `nft`, `portscan`, `auditd`, **any sensor that cannot collect** |
| `audit`     | Audit trail transport.                                              | `auditd(audit.sh)` |
| `system`    | System / host events.                                              | `fortigate(system/ha/config)` |
| `update`    | Image drift / packages & updates.                                | `imgdrift` |
| `container` | Container runtime events.                                        | `containerd` |
| `k8s`       | Kubernetes audit.                                                        | `kube-audit` |
| `ebpf`      | eBPF runtime security.                                                   | `falco` |
| `ban`       | Ban register (fail2ban / CAPI).                            | `bans` |
| `integrity` | File integrity monitoring (FIM).                             | `integrity`, `wazuh(syscheck)` |
| `syslog`    | Generic / unclassified syslog fallback ("not yet mapped" bucket).       | `collector-syslog` (parser `Generic`) |
| `inventory` | Endpoint inventory telemetry (syscollector): packages/ports/processes. | `wazuh(syscollector)`, `osquery` |
| `trace`     | OpenTelemetry telemetry: distributed trace spans (operation × service × duration × status), **correlatable with logs through `trace_id`** (#41). | `otlp(/v1/traces)`, `otel-collector`, `otel-sdk` |

> **Mapping guidance.** A vendor mapping SHOULD target an existing category. When in
> doubt: `network` (unknown L3/L4 flow), `system` (host state), or `syslog` (unclassified) are
> the neutral fallback buckets — **never** a drop. Adding a category = **bump
> `CIM_VERSION`** + update `docs/CIM.md` + `config.d/cim/cim.v1.json` (the test guards
> parity). An out-of-taxonomy value is accepted at ingest but **reported** (`warn`).

---

## 3. Severity scale (0..4)

| value | meaning  | syslog RFC5424 (mapped by `syslog_sev_to_plume`) | FortiGate (`level_to_sev`) |
|:------:|----------|--------------------------------------------------|----------------------------|
| `0`    | info     | info, debug                                      | information, debug |
| `1`    | notice   | notice                                           | notice |
| `2`    | warning  | warning                                          | warning |
| `3`    | error    | err                                              | error |
| `4`    | critical | emerg, alert, crit                               | emergency, alert, critical |

---

## 4. Extended fields (`fields`) — promotion, hot dimensions, outcome

Everything that is not a core column lives in `fields` (JSON object). Three sub-contracts:

### 4a. Fields PROMOTED to columns (by name)

The daemon promotes certain `fields` entries to the core columns (`fields_ip` /
`fields_dst` / `fields_url`). A parser/mapping MUST set these keys to populate the columns:

| target column | source `fields` keys |
|---------------|-----------------------|
| `src_ip`      | `fields.src_ip`, `fields.rhost` |
| `dst_ip`      | `fields.dst_ip` |
| `url`         | `fields.url` |

> `ip` (ambiguous source/destination) **is not** promoted — no false src/dst meaning.

### 4b. Hot EXTENDED dimensions (`HOT_FIELDS`) — the "extended core"

`fields` keys that are indexed / groupable (bounded cardinality = enumerations/identities of a bounded
fleet). This is the extended core of the CIM on which detections filter/group in addition to the
columns:

```
action  user  owner  kind  ns  role  scope  verb  resource  operation  dir  risk
```

> **`dir` and `risk` (2026‑08‑05) — added because SHIPPED content queries them, not by prediction.**
> These two keys were supposed to be served by an auto-indexing mechanism driven by usage
> heat. That mechanism **could no longer promote anything** — its counting hooks became dead
> code when the GXQL compiler migrated into `guatx-core` — and it was removed (P6.8‑b); its
> background purge dropped the `idx_ev_auto_dir` / `idx_ev_auto_risk` / `idx_ev_auto_vtype` indexes which,
> for their part, **really existed in production** (recorded with their size in `bench/profile-prod.json`,
> `provenance: measured`: a few MiB for `dir`, a few KiB for `risk`). The criterion for entry
> into this list has therefore become explicit
> and verifiable: **does a shipped rule filter on this field?** — `dir=outbound`: three rules in the
> catalogue (`ex-egress-fanout-external`, `lm-conntrack-internal-ssh`, `di-conntrack-internal-sweep`);
> `risk=public`: one (`cl-minio-public-bucket`). `vtype`, which no shipped content queries, was
> **not** restored. The list is **ordered** and duplicated in `guatx-core`; a compile-time
> assertion refuses any divergence between the two (`daemon/src/soql_glue.rs`).

### 4c. NEUTRAL vocabulary of `action` (normalised outcome — CIM v29)

`fields.action` carries the cross-source **normalised outcome** (produced by `journal_action`, the
FortiGate/web parsers, etc.). Mapping guidance (reuse these neutral verbs):

```
success  failure  allowed  blocked  ban  read  modify  delete  sudo  session_open  session_close
```

**`action` IS AN OUTCOME — so its absence is NOT uniform, and this document used to say it poorly.**
This paragraph listed a vocabulary without ever saying **where** `action` applies, nor what its
absence means. Two readings show that the question is not cosmetic:

- **Real database** (read-only extraction `bench/prod-profile.sql`, on the order of a million events):
  `fields.action` is present on **68.7 %** of rows, cardinality 18.
- **Linux host with the shipped collectors** (lab database populated by `collectors/*.sh` + real
  journald): absent on **12.6 %** of rows — and those rows are **exactly** the categories
  `health`, `config` and the `network` flows, that is, those that **have no outcome**.

The rule is therefore: **a category that describes an ACT carries its outcome; a category that describes a
STATE has none.** A heartbeat neither succeeds nor fails; nor does an availability self-report.
What remains **required**:

| family | expected `action` |
|---|---|
| `auth` (session opening/failure, Kerberos/NTLM, sudo, session) | **YES** — `success` / `failure` / `session_open` / `session_close` / `sudo` |
| `firewall`, `web`, `dns`, `mail`, `dlp`, `application` (filtering: there is a verdict) | **YES** — `allowed` / `blocked` |
| `ban` | **YES** — `ban` |
| `data`, `secrets`, `integrity`, `account` (access/mutation) | **YES** — `read` / `modify` / `delete` |
| `exec` | **YES** — `success` / `failure` (`auditd` returns `failure` on a refused `execve`; Windows only writes 4688 on success) |
| `health`, `config`, `inventory`, `posture`, `trace`, `network` (flows) | **NO** — no outcome to carry |

> This table is **NORMATIVE** (what is required of a sender), not a survey of what exists: compliance
> is only measured today on the paths cited in this document. A sender that carries
> the outcome under another name (`operation` for `vault-audit`, for example) remains out of reach of
> detections that compose on `action` — not measured elsewhere, so not asserted elsewhere.

> **Declared gap, `mail` (`P10.32-f`).** The SENDER authentication verdicts that
> `collectors/mail.sh` emits as `category=mail` (opendkim, opendmarc, policyd-spf) carry the result
> of the check (`pass`, `fail`, `none`, `softfail`, `neutral`, `temperror`, `permerror`; `signed` and
> `error` for opendkim), not `allowed`/`blocked`: such a verdict does not decide delivery, it maps
> to neither one nor the other. A detection that composes `category=mail action=blocked` does not see them.
> Outbound (`postfix/smtp`) and the queue (`postfix/qmgr`) are emitted as `mailflow` (delivery, queue).

> **What the absence cost, measured.** The two shipped brute-force rules compile
> `category=auth action=failure`, and **neither** of the two shipped Windows senders set `action`.
> Three Windows logon failures (4625) actually ingested: `search category=auth |
> stats count by source` returned `windows-security 2 · WinEventLog:Security 1` next to the `sudo` events, while
> `search category=auth action=failure | stats count by source` returned **only `sudo` and NOTHING for
> Windows**. An enabled T1110 detection was blind on the OS where brute force is most common.
> Closed on the sender side: the agent (`agent/src/source/windows.rs`) decides category, severity **and**
> outcome in **a single type variant with no optional field** — a branch that forgot the outcome would not
> compile; the PowerShell collector (`collectors/windows/plume-collector.ps1`) derives its list
> of identifiers from an **`identifiant → issue` table**, so collecting without declaring the outcome is no longer
> expressible (CI guard `check_windows_collector_is_honest.py`).

### 4d. HIGH-cardinality fields — do not expect them to be indexed

Mapping guidance, not a setting. These fields cost ~73 MB of expression index over 2.6 M rows on the auditd firehose bench (`daemon/src/soql_glue.rs`),
outside the RAM budget (2 GiB): **their aggregation goes through the rollups**, never through an index.

```
path  src_ip  uid  pid  url  message  dedup  remote_address
msg  time  logSource  request_id  trace_id  span_id  latency  duration  thread
```

> **What this section used to say, and why it was misleading.** It was titled "auto-index
> denylist" and cited an `AUTOINDEX_DENY` constant, which implied that there was an
> auto-indexing mechanism *from which these fields were excluded* — so that the **other** fields
> would eventually be indexed through use. That was false. This adaptive mechanism **never promoted a single
> index** and it was removed (P6.8-b). The only indexing of JSON fields that exists is the CLOSED list
> `HOT_FIELDS` (§4b); **every field that does not appear in it is scanned**, whether it is in the block above or
> not. The block above remains useful for a more modest and accurate reason: these are the fields that should not
> even be *considered* for addition to `HOT_FIELDS`.

### 4e. ENDPOINT SECURITY field families (#57 — BYO-agent)

Endpoint security telemetry **ingested** from the agent the customer already runs (Wazuh,
osquery, EDR) and normalised into `fields.*` by the `endpoint_normalize` preset (Wazuh schema) **or** by
a declarative parser (`docs/PARSER-DSL.md`) for any other vendor. See **`docs/ENDPOINT-SECURITY.md`**.
Plume **runs NO endpoint scan itself** (an acknowledged non-goal) — it is the analytics/response brain.

| category    | normalised `fields` families |
|-------------|---------------------------------|
| `posture`   | `posture_policy` `posture_policy_id` `posture_check_id` `posture_check_title` `posture_result`(pass\|fail\|na) `posture_remediation` `posture_framework` `posture_compliance` `posture_kind`(check\|summary) `posture_score` `posture_passed` `posture_failed` |
| `vuln`      | `cve` `vuln_severity`(critical..low) `vuln_package` `vuln_package_version` `vuln_status` `vuln_cvss` `vuln_title` |
| `integrity` | `fim_path` `fim_event`(added\|modified\|deleted) `fim_mode` `fim_sha256` `fim_md5` `fim_size` `fim_actor` (+ `action`=modify\|delete) |
| `inventory` | `inv_type`(package\|port\|process\|hotfix) `inv_name` `inv_version` `inv_vendor` `inv_port` `inv_protocol` `inv_process` `inv_pid` `inv_cmd` |

`agent_name` / `agent_id` / `agent_ip` (identity of the reported endpoint) are set for **all**
families: a central forwarder relays several hosts, so the `host` column may be the forwarder;
`agent_name` is the **real** endpoint on which views group.

### 4f. Per-event CIM version stamp (`fields.cim`) — drift detectable AT REST

Each event is stamped **at ingest** with `fields.cim = CIM_VERSION` (helper `cim_stamp`, applied on
BOTH insertion paths: generic events `ingest_events_batch_env` — which absorbs /api/ingest, spool,
HEC, MinIO, OTLP, Loki, connectors — and journald `ingest_journal_lines`). Goal: make **contract
drift detectable on frozen data**, without which nothing distinguishes a row written under an old convention
from a recent row.

- **Reading at rest**: a row **without** a `fields.cim` key was written **before** the stamp ("pre-stamp",
  unknown convention); an **old** value (`< CIM_VERSION`) signals an outdated contract. GXQL example:
  `search category=exec | where json_extract(fields,'$.cim')!="1.3"`.
- **Additive / idempotent / fail-safe**: `cim_stamp` never overwrites a `cim` key that is already set; an empty bag
  becomes `{"cim":"1.3"}`; an unexpected non-object JSON is left UNCHANGED (never any loss). The stamp does not
  take part in `dedup` (explicit or NULL, never derived from `fields`) → `INSERT OR IGNORE` idempotence
  preserved.
- **Minimal blast radius**: a field of the already-serialised `fields` bag — **not** a column, so **no
  schema migration**, no change to `EventRow`/`EVENT_INSERT_SQL` (no store parity to
  re-prove). **Pre-stamp** rows are not rewritten — they remain readable as such.

---

### 4.x Renaming a vendor field to an entity column — `P4.12-b` (2026-09-10)

Promotion (`promoted_fields`) only reads `fields.src_ip` / `fields.rhost`, `fields.dst_ip`, `fields.url`.
A producer that names its address differently — an OTLP attribute `otel.client.address`, a HEC key `src`,
a Loki label, a MinIO `remotehost` — leaves the `src_ip` column empty, and per-entity rules apply
to emptiness. Connector field→field renaming (`field_map`) only covered `http_pull`, Firehose and
Pub/Sub; the six other entry paths (`/api/ingest`, journald, MinIO, HEC, OTLP, Loki) had none.

The lever is the **processor engine** (`rename` action, `ingest_rule` table, admin API, hot
reloaded), which runs on ALL paths after promotion: `match_field=source`, `match_op=eq`,
`match_value=<source>`, `action=rename`, `action_arg=fields.otel.client.address->src_ip`. Allowed targets:
`src_ip`, `dst_ip`, `url`, `host`, `fields.<clé>`; the origin stays in `fields`; a column already set
by the producer WINS (precedence collector > parser) and the pre-emption is counted per key
(`ingest.fields_preempted`, `P4.12-f`).

What measures it: `ingest.events_without_src_ip_total` and `ingest.sources_without_src_ip{source}` in
`/api/metrics` (and `plume_ingest_events_without_src_ip_total` in Prometheus) count, since startup,
the events WRITTEN without a source address, per source, among those whose nature admits an address: the
health beats (`category=health`) and configuration admissions (`config`) of any source, local
execution (`exec`) from auditd, windows-security and the agent (`WinEventLog:Security`), account management
(`account`) from auditd and windows-security, writes to a monitored file (`tamper` from auditd), the
integrity hashes, the local `auth` of `sudo` and `su`, and the `data` category of local sources
(dataaccess, dataacl, kube-rbac, minio) are not counted (list `EVENEMENTS_SANS_ADRESSE_PAR_NATURE` in
`daemon/src/metrics.rs`), nor, judged on content (list `ADRESSE_ABSENTE_SELON_LE_CONTENU`), an auditd authentication
failure for which the kernel writes `addr=?` and the session open and close lines of
`sshd` and `sshd-session` (`action=session_open` / `session_close`), nor the account management that the Rust agent files under
`auth` with `WinEventLog:Security` (`event_id` 4720, 4722, 4724, 4725, 4726, 4728, 4732, 4735, 4738, 4740, see §5.5); the source inventory carries the same count
(`without_src_ip_since_start`). A `rename` rule that fills the column makes this count go down: that is
the proof of its effect. Known remainder: multi-tenant mode (control plane) does not bind a token to a
connector, and renaming per TOKEN would require carrying `connector_id` down to the core (the channel of the
Firehose `env_id`) — not built, the predicate on `source` covers the measured need.

## 5. Versioning policy

- `CIM_VERSION = "1.3"`. **Additive** (new category/new extended field) → **minor**
  bump (`1.1` added `posture`+`inventory`, #57; `1.2` added `trace`, #41; `1.3` added
  `exec`/`secrets`/`account`/`recon` + 5 mail sub-stages + the `fields.cim` stamp, Reorg Wave 2).
  **Breaking** (removal/renaming of a category or a core field) → **major** bump (`2.0`) + new
  file `config.d/cim/cim.v2.json`.
- The trio **doc (`docs/CIM.md`) ↔ code (`CIM_*` in `guatx_core::cim`) ↔ schema
  (`config.d/cim/cim.v1.json`)** is kept consistent by the parity test. Modifying one
  without the others **breaks `cargo test`** — that is intended: a single source of truth. A **COMPILE-time
  safeguard** (`daemon/build.rs`) goes further: it extracts the `version` of the embedded schema and
  const-asserts that it equals `CIM_VERSION` of the LINKED core — a build linked against a STALE core **fails to compile**.
- **BACKWARD COMPATIBILITY**: adding a name to the `CIM_CATEGORIES` allow-list rewrites **no** row. The
  events already stored under a newly canonised category (e.g. the whole `exec` history) become
  in-contract **immediately, without data migration** — `cim_category_ok()` is pure membership.

### 5.1 Out-of-taxonomy category at ingestion — accepted, never rejected

A `category` declared by a collector and **absent** from `CIM_CATEGORIES` is **stored as is**.
The CIM is a PARSE/MAP/ENRICH contract, **never a DROP**: refusing would make the SOC lose the
events of a misconfigured third-party collector, with no possible replay. Collection reduction has its own
explicit and audited path (whitelists, sev 3 audit) — the CIM does not decide it.

What changed (2026-07-28): the value was checked against the taxonomy **nowhere** on the ingest
path — not even a `warn` (the existing safeguards were upstream: loading of an overlay
parser, creation of a data model, HEC mapping). Now the **first** occurrence of each
out-of-taxonomy (`source`, `category`) pair is logged, naming the collector; **a single line per
pair and per process lifetime** (a warning that floods the log warns nobody). The stored row is
unchanged.

### 5.1bis **MISSING** category at ingestion — accepted, but never silent again

§5.1 only covered one case out of two. There are **three** possible states, not two:

| state | stored row | reported | seen by a `category=…` rule |
|---|---|---|---|
| **canonical** (in `CIM_CATEGORIES`) | as is | no | yes |
| **out of taxonomy** (non-empty, unknown) | as is | `warn`, once per (source, category) pair | no |
| **missing** (empty `category`) | as is, **empty** | `warn`, once per source | **no, permanently** |

The third state went out **before any check**, on this reasoning written in the code: "*Vide → rien
(le dparser tranchera côté serveur)*". **That was false, and it is measured** (2026‑08‑02): four
events in the exact form of the shipped agent (`WinEventLog:Security` 4768/4769,
`WinEventLog:Application` 1000, `macos-unified-log`) with `category:""` → HTTP 202, **4 stored as
is, zero log lines**; and of the **five** shipped declarative parsers, **none** targets
the agent's sources (they target `cloudflare`, `firewall`, `fim-agent`, `nginx`, `nft`). Nothing
decided, neither at ingestion nor later.

It was the state **most produced** by the shipped senders: the agent's Windows classification
returns "unclassified" for any identifier outside its table, and the macOS reader returns an empty
category for every benign line.

**No value is invented.** Setting an `unknown` by default would be worse than emptiness: it would be a
**fabricated** classification, and `search category=unknown` would look like a class when nothing
was recognised. The row therefore stays empty — which is honest. What is closed is the **silence**:

- resolution is a **type with a private field and a single constructor** (`CategorieIngeree::resoudre`,
  `daemon/src/ingest/store.rs`), and its sum is **exhaustive**: the value cannot be built outside
  this module, and a state added tomorrow does not compile until it is handled. *Exact limit: the
  type does NOT FORCE a future write point to go through it — the `category` column of `EventRow` remains
  a `String`. The guarantee is "a single place resolves, and ingest goes through it", not "nothing else
  can write".*
- **measurable at rest**, on the data and not on a process counter (which restarts from zero on
  every restart): `GET /api/system/diag` publishes `counts.events_without_category` and the
  `unclassified_by_source` breakdown. In GXQL: `search category="" | stats count by source`.

### 5.2 Migration debt — read alias `exec` ⊃ `process` (expiry **2027-07-23**)

The two Windows collectors (`collectors/windows/plume-collector.ps1`, `agent/src/source/windows.rs`)
declared `category='process'` for **process creation** (EventID 4688) until **2026-07-23**.
`process` **does not belong** to `CIM_CATEGORIES`; the canonical v1.3 name is **`exec`**. The collectors
have emitted `exec` since that date.

The history **is not migrated**: 365-day retention, **sealed** cold tier (encrypted Parquet, never
rewritten) ⇒ immutable by construction. Reconciliation happens at **READ time**:

- a `category=exec` query compiles to `category IN ('exec','process')` — placed at the point that
  100 % of read emission passes through (`SqlcipherStore::soql_to_sql*`, see `soql_glue::cim_read_alias_exec`),
  plus the `/api/search` bar, which builds its SQL by hand;
- **this is not a rewrite engine**: a single hardcoded equivalence, no table, no
  config, no ENV, unreachable for any other value. It only applies to the **equality** of a
  filter (`table_conds` / `where`) — `!=`, glob and regex are **not** aliased;
- **scope**: base filter, `where` stage, subsearches. **Out of scope**: macro bodies and
  `eventtype` filters (expanded in the core, after this pre-pass).

Measured consequences (reading of core v0.2.1): the `in (…)` list is emitted `COLLATE NOCASE` (case
over-match, **never** an under-match); `idx_event_category` (BINARY) no longer serves this filter; the cold tier
does not prune on `category` for an aliased query (`extract_cold_dim_preds` refuses the `IN` form) and the
columnar engine **declines** to vectorise these queries — the SQL oracle serves them, so only one possible answer
whatever the route.

**Removal.** Last known `process` event (schema switch) on 2026-07-23; 365-day retention ⇒ the last Parquet file
carrying it leaves retention on **2027-07-23**. After that date (purge done), remove the
`cim_read_alias_exec` block from `soql_glue.rs`, its 4 call sites (`ingest/store.rs` ×3, `handlers/search.rs`),
the `carries_cim_read_alias` guard of the cold planner, and the `cim_read_alias_*` / `cim_aliased_*` tests.

### 5.3 Downstream consequence — the Sigma import reconciled on `exec`

Setting `exec` as the canonical home left a **non-reconciled** surface: the Sigma importer mapped the
`process_creation` logsource to `endpoint`. Every imported Sigma process-creation rule therefore filtered
on `category=endpoint` while **the 4688 of the shipped collectors arrives as `exec`** — it was
blind to the telemetry it targets. Fixed: `process_creation` → **`exec`**
(`SIGMA_LOGSOURCE_CATEGORY`, `daemon/src/sigma.rs`), with a **derived** guard that READS the shipped
collectors and requires the table to agree with them
(`sigma_process_creation_targets_the_category_the_shipped_4688_path_emits`).

**The history is covered, and it is proven.** The importer **recompiles** the translated query through
`rule_sql` → `soql_to_sql_x` → `SqlcipherStore::soql_to_sql`, so it goes through
`cim_read_alias_exec`: a `process_creation` Sigma rule imported today sees today's `exec` telemetry
**and** the sealed `process` history. Verified end to end by
`sigma_process_creation_rule_fires_on_real_4688_event` (real 4688 fixture) — structure (`IN
('exec','process')` present in the emitted SQL) **and** count; neutralising the alias drops the count
from 2 to 1.

**Remaining blind spot, measured.** `classer` (`agent/src/source/windows.rs`) files **Sysmon ID 1**
(process creation) under `endpoint`, not `exec` — it is the default branch "Sysmon other than 3/22".
Process creation is therefore **split between two emitted categories**: `exec` (4688 + auditd
`execve`) and `endpoint` (Sysmon ID 1). A `process_creation` rule cannot see both; the importer
**reports** it (warning) and a test **pins** it. Closing it means changing the category
**emitted** by the agent: that is a data-plane change that reopens exactly the debt of §5.2
(the Sysmon history filed under `endpoint` would become unreachable through `category=exec`, and no alias can
disambiguate it since `endpoint` also carries image-load / registry / service installation).
**Conscious decision**: not done, written down.

**Measured under real conditions on 2026‑08‑02** (Windows 11 Enterprise 24H2 build 26100, Sysmon 15.21
installed in 18 s with a minimal `ProcessCreate` config, Rust agent cross-compiled and registered as an
SCM service): the blind spot is no longer inferred from the code, it is **observed**. Sysmon ID 1 does arrive as
`category=endpoint` (36 events), and on the **same** workstation, at the **same** moment, the query of the
`process_creation` Sigma rule imported as is —
`search category=exec CommandLine=~(?i)whoami | stats count` — counts **50**, while
`search category=endpoint CommandLine=~(?i)whoami | stats count` counts **20** more that it does not
see. These are the same executions, seen twice, filed under two categories.

Two practical consequences that reading the code did not give:
- **Sysmon populates `CommandLine` without ANY GPO** (it is in its event schema, not in Windows
  auditing). A fleet equipped with Sysmon therefore has the command line everywhere — including, measured, **the
  secrets passed in argv** (see the warning in `collectors/windows/README.md`) — even though the
  `process_creation` rule remains blind to these events.
- Switching from `endpoint` to `exec` would therefore pay off *more* than estimated (it would make visible
  telemetry that is already rich in `CommandLine`), and *also* cost more (the `endpoint` history is mixed).
  The decision remains unchanged; only its costing is now measured.

**Corollary for the taxonomy.** The `category` axis now has a **measured** emission oracle, which
`daemon/src/collected.rs` explicitly declared absent: `SIGMA_TARGET_CATEGORY_EMITTERS` cites, for
each category targeted by the Sigma import, **the shipped file and the fragment that emits it**; the guard
checks both directions. The scope remains that of the import's targets (16 categories), not the whole
taxonomy — **the rest is not measured, so it is not asserted**.

---

## 5.4 The other canonical row — the SNAPSHOT (`snapshot`), and its uniqueness scope

A sender does not produce only events: it can publish a **state snapshot**
(spool envelope `{"ts","host","kind","hash","data"}` — `collectors/firewall.sh`,
`collectors/controls.sh`, or `POST /api/ingest` with any `kind`). The daemon only
rewrites `data` if `hash` has **changed**; otherwise it advances the `ts` of the existing row
(*heartbeat*: a stable sensor must not be declared silent).

**THE SERIES IS `(kind, host)`, NEVER `kind` ALONE.** A snapshot captures what the sender
can OBSERVE, and a sender only observes its own machine. The whole snapshot path is therefore
partitioned by the row's host (`SnapshotSeries`, `daemon/src/ingest/store.rs`):
state comparison, heartbeat, state alert keys (`firewall.lockdown`, `control.catalog`,
`control.catalog.vide`), freshness probes and read surfaces.

**AN EMPTY SNAPSHOT IS AN ANSWER, NOT A SILENCE.** A sender that ran correctly and has
NOTHING to evaluate publishes a snapshot whose list is empty, rather than publishing nothing: the
series stays alive and the surface can say "nothing is measured here", instead of leaving an
indefinite "waiting for the sensor" to be read as a machine that is still silent. For the
control catalogue, the daemon derives the `control.catalog.vide` alert from it — the condition is
"zero controls evaluated", never the REASON for the zero.

Consequences for anyone writing a sender:

- **`host` is what identifies you.** Two machines that publish the same `kind` with the same
  `hash` are **two series**; neither can erase the other. *Before this partitioning, a homogeneous
  fleet of 3 machines yielded **only 1 row** — two thirds of the fleet silently discarded — and the
  heartbeat of one machine refreshed the row of another (measured: +3540 s on the row of a
  host dead for 3600 s).*
- **Omitting `host` is not a tolerated oversight, it is a DECLARATION**: the snapshot joins the
  `(kind, NULL)` series, the one for what describes **the deployment** and not a machine. That is how —
  and only how — a snapshot is legitimately global.
- **`hash` must be stable and deterministic for the same state**, and depend only on what
  the sender observes (`firewall.sh` removes the volatile counters from the ruleset before hashing).
- The **freshness of a fleet** is that of the machine **furthest behind** (`MIN` over the per-host `MAX(ts)`):
  a machine that is still alive can no longer make the whole fleet look fresh.

### 5.5 Two Windows senders, two categories for the SAME event — measured, not fixed

The two **shipped** Windows senders file account management (4720/4722/4724/4726/4732/4756)
under two different categories:

| sender | emitted `category` |
|---|---|
| `collectors/windows/plume-collector.ps1` | **`account`** (the canonical v1.3 home) |
| `agent/src/source/windows.rs` | **`auth`** |

Consequence: a `category=account` rule only sees the workstations equipped with the PowerShell collector,
and a `category=auth` rule picks up the account management of workstations equipped with the agent. Neither
sees the whole fleet — **it is the same kind of defect as in §5.3** (Sysmon ID 1 filed under
`endpoint` while 4688 goes to `exec`).

**Conscious decision, as in §5.3: not done, written down.** Switching the agent to `account` would reopen
exactly the debt of §5.2 — the agent history filed under `auth` would become unreachable through
`category=account`, and **no read alias can disambiguate it**, since `auth` also carries
session openings, Kerberos and sudo. The cost of an `account ⊃ auth` alias would be to
pull all authentication traffic into an account management query: the remedy
would be worse.

---

## 6. What the CIM is NOT (yet)

CIM v1 is **piece 1** of slice #7 (formalisation). It **introduces no** new
ingest path and does not modify the data plane. The pieces that build on it (outside the
scope of this document):

- **Piece 2 — declarative parser DSL**: map vendor fields → CIM fields in
  `config.d` without a Rust rebuild (PARSE/MAP/ENRICH, never DROP).
- **Piece 3 — Sigma importer**: translate Sigma rules → Plume rules (GXQL) through the
  logsource → `source`/`category` mapping of this contract.

These two pieces **reference** this taxonomy; they do not redefine it.
