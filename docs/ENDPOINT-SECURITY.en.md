# Plume — Endpoint security (BYO-agent) — #57

[Français](ENDPOINT-SECURITY.md) | [English](ENDPOINT-SECURITY.en.md)

> **Status: operator contract + product positioning.** This document describes how Plume ingests and
> normalizes **endpoint-security** telemetry (SCA/compliance, vulnerabilities, FIM, inventory) produced
> by the agent the client **already** runs (Wazuh, osquery, EDR), and surfaces it in **native views**.

---

## 0. Positioning — SUPERSET THROUGH INGESTION, not a new agent

**Strategic decision (deliberate).** Plume does **not** rebuild an endpoint agent: no native SCA
engine, no CVE scanner, no rootcheck. Rebuilding that engine would mean rebuilding OSSEC/Wazuh — against
the **sovereign / 2 GB RAM / vendor-agnostic** charter.

Instead, Plume adopts the **superset-through-ingestion** strategy: it becomes the analytics / detection /
response / ledger **brain** **on top of** the endpoint sensor the client
already owns. During a migration, **Wazuh / osquery / an EDR CAN BE the sensor**; Plume normalizes
its output into CIM and makes it queryable/correlatable/actionable like any other source.

- **What Plume DOES**: ingest + normalize (CIM) + index + detect (GXQL/Sigma/correlation/UEBA) +
  score risk (RBA) + respond (playbooks) + record (ledger) + surface (native views).
- **What Plume DOES NOT DO (honest non-goal)**: scan the endpoint itself (no native inotify FIM,
  no CVE feed, no embedded CIS assessment). The **sensor** remains the client's agent.

It is the same seam as the rest of the *bring-your-own-vendor* model (see `docs/SDK.md`, `docs/CIM.md`,
`docs/PARSER-DSL.md`, HEC `docs/…`): Plume is a **superset** of what exists, not a replacement that
makes you lose a capability.

---

## 1. Supported families & CIM mapping

The built-in preset `endpoint_normalize` (`daemon/src/ingest/endpoint.rs`) recognizes the **Wazuh JSON alert
schema** (the most widespread BYO format) and maps its families to the CIM (`docs/CIM.md`):

| Family (Wazuh source)                          | Detected JSON key        | → CIM category | Normalized fields (`fields.*`) |
|------------------------------------------------|--------------------------|----------------|--------------------------------|
| **SCA** (Security Configuration Assessment/CIS)| `data.sca.*`             | `posture`      | `posture_policy`, `posture_check_id`, `posture_check_title`, `posture_result` (pass\|fail\|na), `posture_remediation`, `posture_framework`, `posture_compliance`, `posture_kind`, `posture_score`/`posture_passed`/`posture_failed` (summary) |
| **Vulnerability-detector**                     | `data.vulnerability.*`   | `vuln`         | `cve`, `vuln_severity`, `vuln_package`, `vuln_package_version`, `vuln_status`, `vuln_cvss`, `vuln_title` |
| **FIM / syscheck**                             | `syscheck.*`             | `integrity`    | `fim_path`, `fim_event`, `fim_mode`, `fim_sha256`/`fim_md5`, `fim_size`, `fim_actor` (whodata), `action` |
| **syscollector** (inventory)                   | `data.{program,port,process,hotfix}` / `location=syscollector` | `inventory` | `inv_type`, `inv_name`, `inv_version`, `inv_vendor`, `inv_port`, `inv_protocol`, `inv_process`, `inv_pid`, `inv_cmd` |

All families also set `agent_name` / `agent_id` / `agent_ip` (identity of the **endpoint**). A
central forwarder relays several hosts → the `host` column may be the forwarder; **`agent_name` is the
real endpoint** on which the views group.

**Severity** (Plume scale 0..4, applied as **ENRICH-only** — the collector wins if it already set it):
SCA `failed`→2 / otherwise 0; CVE `critical`→4 `high`→3 `medium`→2 `low`→1; FIM `deleted`→3 `modified`→2
`added`→1; inventory→0.

**osquery**: recognized as `sourcetype osquery:results` on the HEC side (`docs`), and its FIM/SCA packs can be
mapped by declarative parser (below) to `integrity`/`posture`.

---

## 2. Accepted input formats (how to send the telemetry)

Plume **has no new agent**: the existing ingest paths are reused. The key point is that the
**source** of the event be in the opt-in list `PLUME_ENDPOINT_NORMALIZE` (default `"wazuh"`) and that the
**message** be the complete JSON alert.

- **HEC (Splunk-compatible, `POST /services/collector`)** — a Wazuh→Splunk-HEC forwarder, filebeat, or
  any HEC client: post the alert as `event` (object) with `"source":"wazuh"`. The message becomes the
  alert's JSON → normalized.
- **`POST /api/ingest`** (native agent/connector) — event `{ "source":"wazuh", "message":"<alerte JSON>" }`.
- **Pull connector** (`connectors.rs`) — a connector that pulls the Wazuh alerts and pushes them in batches.

> **Extend to another vendor WITHOUT a rebuild**: add the source to `PLUME_ENDPOINT_NORMALIZE` **if** its
> schema is Wazuh-like; otherwise write a **declarative parser** (`config.d/parsers/*.json`, see
> `config.d/parsers/example-endpoint-fim.json`) that targets the **same** CIM fields/categories. The native
> views then work identically (they compose on `category`, never on the vendor).

---

## 3. Native views (GXQL-backed)

Two seeded dashboards (idempotent), view **"Endpoint (BYO-agent)"**, **empty** as long as no telemetry
arrives:

- **Posture de configuration (SCA/CIS)** (configuration posture, the name the console serves) —
  pass/fail controls, failures per host, per benchmark, impacted compliance frameworks, detail of the
  failed controls. Composed on `category=posture`.
- **Vulnérabilités (CVE endpoint)** (endpoint vulnerabilities, the name the console serves) — CVE by
  severity, most vulnerable hosts, top CVE, most affected packages, critical/high in detail. Composed
  on `category=vuln`.

The panels are **GXQL** (masked path: automatically respects the field-filters #45 + RBAC). FIM
already feeds the `integrity` category (existing integrity views); the inventory (`category=inventory`)
is ingested and queryable — a dedicated dashboard is a **follow-on**.

---

## 4. Guarantees (invariants)

- **Mode 0 / byte-identical**: the normalizer is **gated per source**. As long as no event from an endpoint
  source flows, ingest is **byte-identical** (no JSON parse, no allocation) — a simple
  membership test. Proof: `endpoint_mode0_gate_ignores_non_endpoint_source`.
- **ENRICH / MAP, never DROP**: only absent `fields.*` are added (the collector wins);
  `category`/`severity` are only set as ENRICH-only. No event is deleted or filtered.
- **Injection-safe**: the normalized values travel through the `fields` bag → `EventRow`/INSERT path with
  bound parameters (no SQL built from strings). The panels go through GXQL.
- **Vendor-agnostic**: **thin** built-in preset for Wazuh; any other vendor is added by a `config.d`
  declarative parser **without recompiling**.

---

## 4bis. Cost of the `execve` rule (measured)

The **64-bit** `execve` rule **is active by default** in `systemd/plume-audit.rules`. Without it,
`category=exec` is **empty** on an amd64 host — a total blind spot on process execution. A
blind default is worse than a voluminous default. But it has a cost, and here is the **measured** cost, not
an estimate, so that you can project it onto YOUR fleet.

> **Measurement bench — 2026-08-01.** QEMU/KVM VM, official cloud image `noble-server-cloudimg-amd64`
> (Ubuntu 24.04 Server), **2 vCPU / 2 GiB**, `auditd` installed, shipped template loaded (**8/8 rules**,
> checked with `auditctl -l`), `auditd.sh` collector with default settings
> (`PLUME_AUDITD_EXEC_DROP` not set), local Plume central. Redo it on your own setup: the figures
> below describe THIS machine and THIS load, not yours.

### Primitive quantities (the only ones actually measured)

| quantity | measured value | how |
|---|---|---|
| **On-DISK size of an `exec` event** | **534 bytes** | 10,000 `exec` events ingested, database put through `wal_checkpoint(TRUNCATE)`: +5,349,376 bytes. Includes the row, the SQLite overhead and **the 8 indexes**. |
| *Logical* size (message + `fields`) | 270 bytes on average (198 min / 278 max) | `message` 75 B + `fields` blob 169 B. The gap with the 534 B on disk = **x1.97 amplification** (overhead + indexes) — the disk figure is the one that matters for sizing. |
| **At rest** (no login session) | **≈ 0 / hour** | Window of **900 s**. 9 `EXECVE` records observed, all attributable to the bench's own commands (9 session openings in the same window). Above all: **0** records with an undefined `auid`, even though `plume-ship.timer` (30 s) and `plume-resources.timer` (60 s) ran ~30 and ~15 times during the window. |
| **Under build load** | **533 events** for a build of 100 C compilation units + link (2 s) | that is **≈ 285 KiB** of database per build. |

### Why rest is so quiet — and what it implies

The template's `-F auid!=-1` filter only logs the execs that can be tied to a **login session**.
systemd timers, Plume collectors and daemons run with an undefined `auid`: **they
produce no `exec` event**. Volume therefore follows **human activity**, not machine churn.
That is what makes the "active" default sustainable on a server, and it is also why a **developer
desktop or a CI runner** is the costly case, not the production server.

### Projection at 30 days (the product's default retention)

> ⚠️ **These rows are ARITHMETIC on the quantities measured above, not measurements.** The
> number of builds/day is **your** parameter: replace it.

| host profile | `exec` events/day | per day | **at 30 days** |
|---|---|---|---|
| Server, nobody logs in | ≈ 0 *(measured)* | ≈ 0 | **≈ 0** |
| Dev desktop / CI runner, 20 builds/day | 20 × 533 = 10,660 | 5.7 MiB | **~171 MiB** |
| **Continuous build (upper bound)** | 266 ev/s → **23 M/day** | **12.3 GiB** | **~369 GiB** |

The "server with an administration session from time to time" regime is **not** tabulated: it depends
entirely on what your administrators type, and publishing an invented number for that row would be
exactly the kind of unmeasured figure this document refuses. Measure it on YOUR fleet, it is one
query:

```
search source=auditd category=exec | stats count by host
```

**The upper bound is the result that matters**: a host that compiles permanently saturates any
disk well before 30 days. On a build fleet, broad `execve` **must** be reduced (see below);
this is not an opinion, it is what the calculation says.

**At fleet scale.** An internal measurement on a fleet of a few dozen hosts gives a total volume
factor **slightly lower than the number of hosts** (the hosts are not identical; it is not
linear). With that factor, 50 dev desktops at 171 MiB/30 d give **≈ 7.3 GiB / 30 d** for the `exec`
stream alone. Compare with your current volume before generalizing.

**The 2 GiB RAM budget is not the limiting factor here, the DISK is.** The `exec` stream grows
the database, not the working set: reads remain paginated (keyset) and go through the rollups. What must be
watched is disk space and the retention window, not RSS.

### Reducing without going blind again — two levers, from the gentlest to the most radical

1. **Filter at the collector** (host forensics remain **complete**: `ausearch` sees everything; only
   Plume ingestion is reduced). In `/etc/plume/plume.conf`:
   ```sh
   PLUME_AUDITD_EXEC_DROP=1                   # unambiguous build/system noise (level 1)
   PLUME_AUDITD_EXEC_DROP_INCLUDE_RECON=1     # + discovery primitives (level 2, more aggressive)
   ```
   Level 2 is **deliberately separate**: it carries discovery and secret-hunting primitives
   (T1083/T1057/T1552.001) that remain **kept by default**, even with level 1 active. Measure the
   real share before enabling it: `search source=auditd category=exec | stats count by exe | sort -count`.
2. **Remove the 64-bit coverage** (comment out the template's `arch=b64` line). You then fall back
   into the measured blind spot: **`category=exec` becomes empty again**. Only do it knowingly.

The collector **publishes the state of these switches** as `category=config` on every pass — a
defender therefore sees the exact blind-spot surface whatever position the switches are in, without reading the code.

## 4ter. Loading the rules, and checking what is running

**A single loader**: `systemd/plume-audit-rules-load.sh`, installed as
`/usr/local/lib/plume/plume-audit-rules-load.sh`. `bootstrap.sh` (central) calls it;
`bootstrap-agent.sh` installs it without running it (loading an audit policy is an operator
decision) and displays the operation:

```sh
sudo sh /usr/local/lib/plume/plume-audit-rules-load.sh      # template: /usr/local/share/plume/plume-audit.rules
```

**Checking** — `auditctl -l` is the only proof of what is running. It renders a syscall rule with
`-F key=<clé>` and a watch with `-k <clé>`: counting only `key=plume_` misses the watches.

```sh
sudo auditctl -l | grep -cE -- '(-k |key=)plume_'                      # plume_* rules loaded
sudo auditctl -l | grep -oE -- '(-k |key=)[A-Za-z0-9_]+' | sort | uniq -c   # per key, exec_tracking included
```

The loader does this count itself, **per key**, against what the template declares, and returns:
`0` everything is loaded; `1` rules are missing (key, template line and `auditctl` message named);
`2` everything is loaded **now**, but only because it caught the rules up one by one:
`augenrules` stopped before them, and the next auditd start will stop at the same place.
`bootstrap.sh` then ends with code `3`, after setting up everything else, with a message specific to
each: code `1` « règles d'audit INCOMPLÈTES MAINTENANT » (fix the named line of the template),
code `2` « complètes maintenant, mais PAS au prochain démarrage » (fix the named line of a
file in `/etc/audit/rules.d`).

**Kernel state now, and at boot — it is not the same.** The catch-up loads into the
CURRENT kernel the rules that the assembly skipped; auditd, at startup, only replays
`augenrules --load`, which stops at the same place. Everything the loader announces as « chargée par le
rattrapage » (loaded by the catch-up) will therefore be lost at the next boot as long as the offending
line remains — with code `2` as with code `1`, where it says so with their number.

**A plume rule already declared by another file** in `/etc/audit/rules.d` (observed: a third-party file
already carried the b64 `execve` rule). `augenrules` concatenates the files in name order then
`auditctl -R`, which **stops** on "Error sending add rule data request (Rule exists)": without
a fix, no plume rule that followed was loaded, and the installer said nothing. Now:

- **identical** duplicate (up to whitespace): the line is commented out in `plume.rules`
  (`## plume-doublon : déjà déclarée par <fichier> …`) and the loader names the file. Nothing to do —
  except rerunning the loader if that third-party file changes or disappears (the rule then only lives
  in it);
- duplicate **written differently** (field order, `auid!=-1` versus `auid!=4294967295`): code `2`.
  Remove the rule from one of the two files — it is the same rule for the kernel — then rerun the
  loader. `sudo augenrules --load` displays "error in line N" of `/etc/audit/audit.rules`, the
  assembled file: `grep -n -- '<la règle>' /etc/audit/rules.d/*.rules` finds its origin;
- **real error** (missing path under `-F dir=`/`-F path=`, unknown field): code `1`, the line is
  named. The rules that follow it are loaded NOW by the catch-up, but LOST at the
  next boot (the assembly always stops on it). Fix it or comment it out, then
  rerun the loader.

## 5. Settings

| Variable                      | Default  | Effect |
|-------------------------------|----------|-------|
| `PLUME_ENDPOINT_NORMALIZE`    | `wazuh`  | CSV of the `source` values on which the endpoint preset activates (`*` forbidden). |

Code anchor: `daemon/src/ingest/endpoint.rs` (`endpoint_normalize`, `endpoint_sources`); hook-in in
`daemon/src/ingest/mod.rs` (`ingest_events_batch_env`, right after `dparsers_apply`). CIM categories:
`guatx_core::cim` (`posture`, `inventory`) + `config.d/cim/cim.v1.json` (v1.1). Dashboards: `seed_sca_dashboard`
/ `seed_vuln_dashboard` (`daemon/src/seeds.rs`).
