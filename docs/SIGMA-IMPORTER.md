# Plume — Sigma importer (Slice #7, part 3)

[English](SIGMA-IMPORTER.md) | [Français](SIGMA-IMPORTER.fr.md)

> **Status: operator contract.** Absorbs the **open-source** detection library:
> [Sigma](https://github.com/SigmaHQ/sigma) is the YAML standard for detection rules (logsource +
> `detection{selection/condition}` + MITRE tags). This importer **translates a Sigma rule into a Plume
> detection rule** — a **GXQL** query + the metadata (`title`, `level` → severity,
> `tags: attack.Txxxx` → MITRE). It is **ADDITIVE**: a Sigma rule = extra `rule` rows, **zero
> data-plane impact / mode 0**.

- **Code anchor**: `sigma_translate` / `sigma_field_tokens` / `sigma_parse_condition` /
  `sigma_yaml_to_docs` (`daemon/src/sigma.rs`), loader `load_overlay_sigma`, handler `sigma_import`,
  CLI subcommand `sigma-import`.
- **The pivot is the CIM** (`docs/CIM.md`): the `logsource → category` mapping and the core fields
  (`src_ip`/`dst_ip`/`url`/…) come from that contract. A Sigma rule composes on the NEUTRAL `category`,
  so it is **vendor-agnostic** (the same "firewall deny" fires on FortiGate, ufw, nft…).

---

## 0. Guiding principles

1. **NEVER a silently wrong rule.** A construct that cannot be expressed **faithfully** in GXQL is
   **flagged + skipped** with a clear reason (`skipped: [{title, reason}]`), **never** emitted as a
   rule that silently **under-matches** (= blind spot) or over-matches. A mistranslated Sigma rule that
   never fires would be worse than no rule. The coverage below is the **common subset**; the
   inexpressible is rejected (see §4).
2. **Injection impossible.** No Sigma value is interpolated "raw" into SQL. Every string value
   becomes a **REGEXP pattern** built by an encoder that emits **only characters that are inert**
   for the GXQL tokenizer (STRUCTURAL characters — space, `|`, `"`, `()`, `[]`, `,`, `'`, backtick —
   are hex-escaped `\xNN`; the regex engine decodes them, the GXQL/pipe/`in` splitting never sees them). The
   final query is **recompiled by the core GXQL compiler** (`soql_to_sql_x`) before anything is stored: a
   GXQL query that does not compile is **rejected** (the last line of defense).
3. **ENRICH / ADD, never reduce.** Importing a rule **adds** a detection; it neither removes nor
   filters any. An unmapped `logsource` is **not a drop**: the rule is imported (applied to
   all sources) with a **warning** about potential over-matching.

---

## 1. How to import — three paths

| path | use | `managed` | command |
|------|-----|:---------:|---------|
| **`config.d/sigma/`** | **GitOps** (durable, reviewed, baked into the image) | `1` | drop `*.yml`/`*.yaml`/`*.json`, loaded at boot |
| **CLI** | one-off import / **pre-flight** (`--dry-run`) | `2` | `plume-daemon sigma-import <fichier\|dossier> [--dry-run]` |
| **Admin API** | UI / automation | `2` | `POST /api/sigma/import` (**admin**) |

- **CLI** — `plume-daemon sigma-import ./rules/ --dry-run` prints a **JSON report**
  (`imported[]` / `skipped[{title,reason}]` / `summary`) **without writing**; without `--dry-run`, UPSERT by
  name into `PLUME_DB` (`managed=2`). That write **creates** the database if it is missing: on a fresh
  central, start the daemon first, otherwise the database is born in plaintext ([`INSTALLER-SANS-OUVRIR-DE-BRECHE.md`
  §1.1](INSTALLER-SANS-OUVRIR-DE-BRECHE.md#11-start-the-daemon-once-before-any-subcommand-that-writes-to-the-database)). `--dry-run` opens no database.
- **API** — body `{"content":"<yaml|json>","dry_run":false}` (Sigma text, multi-doc `---` OK) **or**
  `{"rules":[<sigma json>…]}`. Response `{imported:[…], skipped:[…]}`. RBAC gate: the `/api/sigma/*` route
  falls under **DEFAULT-DENY = admin** (bulk import of external detections is privileged).
- **UPSERT by `title`.** Re-importing is idempotent. The import **never replaces** a git overlay
  rule (`managed=1`) — that rule is `skipped` (remove it on the git side to replace it).

A multi-document Sigma file (`---`) is supported (one file can carry N rules).

---

## 2. The output model — a Plume rule

A "match" Sigma rule (fires as soon as an event matches) becomes:

```
query      = search <category?> <champs…> | stats count
is_soql    = 1
op / seuil = ">" / 0        # fires if at least 1 matching event exists in the window
window_s   = 3600           # sliding window
interval_s = 300            # evaluation cadence
severity   = level → 0..4   # see §3
mitre      = 1re tag attack.Txxxx[.yyy] → Txxxx[.yyy] (norm_mitre)
name       = title
```

`| stats count` returns **one** number (the count of matching events); `run_due_rules` compares `count
> 0` → alert, which **inherits** `severity` and `mitre` (MITRE coverage measurement, purple team).

### 3. `level` → severity (0..4, see `docs/CIM.md` §3)

| Sigma `level` | `informational` | `low` | `medium` (default) | `high` | `critical` |
|---------------|:---------------:|:-----:|:------------------:|:------:|:----------:|
| Plume `severity` | 0 | 1 | 2 | 3 | 4 |

---

## 4. Coverage matrix

### 4a. logsource → `category` (CIM)

Priority `category` > `service` > `product`. Table `SIGMA_LOGSOURCE_CATEGORY` — **40 entries, 16
distinct target categories** (counted in `daemon/src/sigma.rs`).

| Sigma logsource | CIM `category` | | Sigma logsource | CIM `category` |
|-----------------|:--------------:|-|-----------------|:--------------:|
| `firewall`, `firewall_traffic` | `firewall` | | **`process_creation`** | **`exec`** |
| `proxy`, `webserver`, `apache`, `nginx`, `modsecurity`, `web` | `web` | | `process_access`, `image_load`, `driver_load`, `create_remote_thread`, `file_event`/`_change`/`_delete`, `registry_event`/`_set`/`_add`/`_delete` | `endpoint` |
| `dns`, `dns_query` | `dns`          | | `network_connection`, `netflow` | `network` |
| `antivirus`, `av`, `clamav` | `malware` | | `kubernetes` | `k8s` |
| `authentication`, `auth`, `sshd`, `sudo` | `auth` | | `falco` | `ebpf` |
| `email`, `smtp` | `mail`         | | `container` | `container` |
| `vpn`, `dlp` | `vpn`, `dlp` | | `syslog`, `system` | `syslog`, `system` |

**Unmapped logsource** → rule imported **without** a `category=` filter (applies to all sources),
with a **warning** (possible over-matching). Never a drop.

#### The rule that governs this table: *a target with no emitter is worse than no mapping at all*

A mapping to a category that **nothing produces** manufactures **apparent** coverage: the rule
imports, gets categorized, shows up as "covered", and can **never** fire. Left unmapped, it is
**visibly** uncategorized. Every target in the table is therefore backed by a **mechanically verified
citation** — `(catégorie, fichier livré, fragment émetteur)` in `SIGMA_TARGET_CATEGORY_EMITTERS`,
guarded in both directions by `sigma_logsource_targets_are_emitted_by_a_shipped_collector`: no
phantom citation (the fragment must be present in the cited file), no target without a citation
(mapping to an unmeasured category turns CI **red**). Same contract as
`collected::COLLECTED_EXTENDED_FIELDS` for fields, applied here to the `category` axis.

Two entries were corrected against this criterion:

- **`process_creation` → `exec`** (no longer `endpoint`). Windows process creation
  (**EventID 4688**) is emitted as `exec` — the canonical CIM v1.3 name — by **both** shipped
  Windows collectors (`agent/src/source/windows.rs`: `4688 => ("exec"…)`; `plume-collector.ps1`:
  `-Ids @(4688) … -Category 'exec'`) **and** by the Linux stream `collectors/auditd.sh` (`execve`). As
  long as the table targeted `endpoint`, **every imported Sigma `process_creation` rule was blind to the
  telemetry it targets** — the largest rule family in SigmaHQ.
- **`ps_script`: removed** (hence unmapped). PowerShell Script Block Logging (EventID 4104, channel
  `Microsoft-Windows-PowerShell/Operational`) has **no** shipped emitter: the channel is neither among the
  agent's default channels (`d_win_channels`) nor among the PowerShell collector's `-LogName`, and
  `classer` would return an **empty** category for it anyway. To wire up this family, the telemetry must
  first be **produced** (declarative parser/source), then mapped.

#### What each category ACTUALLY requires from the operator

Measured by reading the shipped emitters (`collectors/`, `collectors/windows/`, `agent/src/`,
`collector-syslog/`, `collector-mail/`, `config.d/parsers/`, the daemon's ingest presets).

> **Essential framing, measured in `bootstrap.sh`: plume installs NO package.** It deploys the
> collectors + their systemd timers, and *arms* the auditd rules **if `augenrules` and `auditctl` are
> already present** (otherwise it says so: « auditd ABSENT (augenrules ou auditctl introuvable) : règles
> NON chargées », auditd absent, rules not loaded). Each row below therefore names
> what **the operator** must have on the host. Without it the category stays **empty** and the Sigma rules
> that target it are **inert** — this is flagged at import, never silent.

| CIM `category` | shipped emitter (example) | prerequisite on the host |
|----------------|---------------------------|--------------------------|
| `auth` | agent `source/linux.rs` (journald: sshd/sudo/su) | **journald** — present on every systemd distro, so the most common case |
| `firewall` | `collectors/ufw.sh`, `nft.sh`, `origin-drop.sh`, `portscan.sh`, `portprobe.sh` | **ufw** and/or **nftables** (read-only collectors, nothing is installed) |
| `exec` | `collectors/auditd.sh` (`execve`); EventID 4688 on the Windows side | **auditd installed** (the rules are armed by `bootstrap.sh`); on the Windows side, the "Audit Process Creation" audit policy |
| `network` | `collectors/conntrack.sh`, `crowdsec.sh` | **conntrack** (package `conntrack-tools`) |
| `web` | `collectors/web.sh`, `cloudflare.sh`, `cloudflare-http.sh` | a web front end whose access logs are readable (Traefik/nginx), or the Cloudflare feed |
| `syslog` | `collector-syslog/src/parser.rs` (Generic parser) | the `collector-syslog` syslog receiver deployed, and devices sending to it |
| `malware` | `clamav.sh`, `yara.sh`, `plume-collector.ps1` (Defender) | a scanner: **ClamAV** / **YARA** / **Defender** |
| `k8s` | `kube-audit.sh`, `kube-state.sh`, `pod-logs.sh` | a **Kubernetes cluster** (+ audit log enabled) |
| `container` | `collectors/containerd.sh` | **containerd** |
| `ebpf` | `collectors/falco.sh` | **Falco** |
| `mail` | `collector-mail/src/main.rs` | the `collector-mail` service wired to a mail stack |
| `dns` | agent Sysmon ID 22, `suricata.sh`, FortiGate `utm/dns` | **Sysmon** or **Suricata** or **FortiGate** |
| `endpoint` | agent `classer` (Sysmon except ID 1/3/22; Security 4697/1102; System 7045/7036/7040), FortiGate `event/endpoint`/`ems`/`connector` | **Sysmon** (+ plume agent on the Windows host) or **FortiGate EMS** |
| `system` | `plume-collector.ps1`, FortiGate `event/system` | the **Windows collector** or **FortiGate** |
| `vpn` | `collector-syslog/src/fortigate.rs` (`event/vpn`) | **FortiGate** |
| `dlp` | `collector-syslog/src/fortigate.rs` (`utm/dlp`) | **FortiGate** |

**In practice.** On a systemd Linux host with no third-party component added, the Sigma families that
can actually fire are those backed by `auth` (`authentication`, `auth`, `sshd`, `sudo`); adding the
`auditd`, `ufw`/`nftables` and `conntrack-tools` packages — which plume does not install — brings in
`process_creation` (via the auditd `execve`), `firewall` / `firewall_traffic` and
`network_connection` / `netflow`, plus the web family as soon as a front end is collected. **All Sysmon
families** (`process_access`, `image_load`, `driver_load`, `create_remote_thread`, `file_*`, `registry_*`)
require **Sysmon** running on the Windows hosts *and* the plume agent deployed there: without Sysmon,
they import and stay **inert**.

#### Two MEASURED blind spots, written down rather than hidden

1. **Process creation is split between two emitted categories.** 4688 (agent + PowerShell
   collector) and the auditd `execve` give `exec`; **Sysmon ID 1** (process creation) is filed under
   `endpoint` by `classer` (default branch "Sysmon except 3/22"). An imported `process_creation` rule
   therefore sees 4688 and auditd, **but not Sysmon ID 1**. Flagged by an **import
   warning** and pinned by a test. Closing this requires changing the category **emitted** by
   the agent (data plane) and reopens the same history debt as `process` → `exec` (`docs/CIM.md` §5.2).
2. **`CommandLine` does not exist in a default 4688.** The field only appears if the GPO *"Include
   command line in process creation events"* is enabled. The shipped showcase rule
   `config.d/sigma/process-whoami-discovery.yml` filters on `CommandLine`: it **stays inert on a
   default Windows, even after this reconciliation** (the importer flags it — inert extended field).
   A rule that filters on `NewProcessName` (always present) does fire: that is what
   `sigma_process_creation_rule_fires_on_real_4688_event` proves on a real 4688 fixture.

   **BOTH states have now been measured on a real Windows** *(2026‑08‑02, Windows 11
   Enterprise 24H2 build 26100, `Audit Process Creation` enabled, shipped PowerShell collector,
   rule imported as-is by `plume-daemon sigma-import`)*:

   | GPO state | `4688` carrying a non-empty `CommandLine` | `search category=exec CommandLine=~(?i)whoami \| stats count` |
   |---|---|---|
   | **disabled** (default) | **0 / 40** | **0** — inert |
   | **enabled** (`ProcessCreationIncludeCmdLine_Enabled=1`) | **12 / 25** | **15** — the rule **FIRES** |

   A useful diagnostic detail: without the GPO, the `<Data Name='CommandLine'>` element **is present but
   EMPTY** in the XML. The collector therefore does not set the key (`if ($d[$k])` discards the empty string) and
   `fields.CommandLine` is absent — the rule does not match, without leaving a misleading empty field behind.
   *Measured on the SOC side: 25 `category=exec` events carrying `fields.CommandLine` after enabling,
   0 before.*

   **Conclusion, and this is the difference that matters**: on Windows the rule is inert **by
   configuration** — one setting wakes it up, and it fits in a single registry value. On Linux it is
   inert **by nature** (below). The remedy is therefore not the same, and neither is the message to the operator:
   on Windows "enable the GPO", on Linux "take the twin rule that filters on `exe`".

   **On Linux, the same rule is inert for a STRONGER reason — structural, not a setting.**
   *Measured on 2026-08-01 (Ubuntu 24.04 Server amd64 VM, 2 vCPU/2 GiB, auditd rules loaded, load =
   build of 100 compilation units → 533 real `category=exec` events):*

   | filtered field | matching `exec` events | verdict |
   |----------------|------------------------|---------|
   | `CommandLine`  | **0 / 533**            | cannot match |
   | `exe`          | 407 / 533              | matches |
   | `comm`         | 305 / 533              | matches |

   The auditd `execve` path emits exactly `action · auid · cim · comm · exe · key · success ·
   syscall · uid`. `CommandLine` is not among them and **no option will make it appear**:
   on Windows a GPO is enough, on Linux there is nothing to enable. The two kinds of inertness therefore have
   different remedies, and confusing them would suggest that a setting is enough.
   The **Linux twin that fires** ships alongside:
   `config.d/sigma/process-whoami-discovery-linux.yml` (`exe|contains`). The pair is deliberate — it
   teaches the difference between a *translated field* (§4b, translation table) and a *populated field*.
   A rule that filters on a field that is never populated is not coverage: it is **apparent**
   coverage, more dangerous than no rule at all.

> **How much of a ruleset survives translation? NOT MEASURED HERE** — no SigmaHQ corpus is
> embedded in the repository, so no rate is published. Measure it **on your own ruleset**:
> `plume-daemon sigma-import <dossier> --dry-run` returns `imported[]` (with their `warnings`) and
> `skipped[{title,reason}]`. That is the only figure that concerns you.

### 4b. Sigma fields → Plume fields

**Two distinct questions, two distinct tables.** *Translating* a name ("how is this Sigma field written
in Plume?") and *knowing whether it is populated* ("does Plume collect this data?") are different
questions. Confusing them would mean that **adding an alias silences the inertness warning** without a
single new piece of data being collected — silence mistaken for coverage.

**Translation** (`SIGMA_FIELD_ALIAS`, `daemon/src/sigma.rs`):

- **Known aliases** → core columns: `SourceIp`/`src_ip`/`SourceAddress` → `src_ip`;
  `DestinationIp`/`dst_ip` → `dst_ip`; `DestinationPort`/`dst_port` → `dport`; `Url`/`Uri` → `url`;
  `User`/`TargetUserName`/`Account` → `user`; `Hostname`/`ComputerName` → `host`.
- **Otherwise**: the Sigma name is used **as-is** as an extended field → `fields.<Nom>` (via `json_extract`,
  **case preserved**).
- **Nested / dotted / hyphenated name** (`winlog.event_data.X`) → **not mappable** (`json_extract` 1 level) →
  the rule is **flagged** (skip).

**Inertness** (`COLLECTED_EXTENDED_FIELDS`, `daemon/src/collected.rs`): once the field is translated, the importer
**warns** if *no shipped collector, parser or agent writes that field*. The inventory is a table of
`(champ, fichier livré qui l'émet)` in which every entry is **cited**. A test guard
(`collected_inventory_is_backed_by_shipped_collectors`) checks both directions **with the same extractor**:

- **(A) no entry that nobody emits** — the field must be **extracted** from the cited file, hence appear there
  in **producer position** (literal `fields` object, insertion by literal key, awk `af(…)`, escaped JSON
  fragment, parser overlay). Any occurrence of the name **is not enough**: `web.sh` *reads* the
  Traefik key `RequestPath` without ever emitting it, so the entry `("RequestPath","web.sh")` is **rejected**;
- **(B) no emitted field missing from the inventory** — extraction covers the forms actually shipped:
  shell/awk escaped JSON, `jq` (unquoted keys), the agent's `serde_json::json!`, Python dictionary,
  PowerShell hashtable, `config.d/parsers/*.json` overlays;
- **(C) anti-rot per family** — each collector family has an **extraction floor**: losing an entire
  one (path moved, emission syntax changed) turns the guard red instead of going unnoticed.

Consequences:

- an **alias to an uncollected target** stays **flagged inert** — the alias translates, it does not collect;
- the warning **never rejects** the rule (the data may arrive later);
- **updates**: a collector that starts emitting `fields.<X>` (or stops) turns **the guard red**
  until the inventory is adjusted.

**What the inventory does not cover** (**open** surfaces, defined at deployment — hence not statically
inventoriable; their fields stay **flagged inert**, that is *over*-warned): the
verbatim copy of the Windows log's `EventData` keys, the fields of declarative `[[source]]` sources, and
the parser overlays the operator adds after deployment. `collected.rs` gives the exact list,
along with the **limit** of the citation check: it requires a producer position, it is not
tamper-proof.

### 4c. Field modifiers

| Sigma | → GXQL | note |
|-------|--------|------|
| *(none)* | `field=~(?i)^…$` (or `field=n` if integer) | **equality**; Sigma wildcards `*`/`?` **active** (→ `.*`/`.`) |
| `\|contains` | `field=~(?i)…` | substring (unanchored) |
| `\|startswith` | `field=~(?i)^…` | anchored at start |
| `\|endswith` | `field=~(?i)…$` | anchored at end |
| `\|re` (`\|re\|i`) | `field=~…` (`(?i)…`) | raw regex, **if** embeddable (no `\|`/`()`/`[]`/space → otherwise flag) |
| `\|all` (+ list) | several tokens **ANDed** | e.g. `contains\|all` |
| `\|lt \|lte \|gt \|gte` | `field< <= > >= n` | numeric |

> **Case.** String comparisons are **case-insensitive** (`(?i)`, matching the Sigma default — and
> safe: over-match rather than under-match). The OR list in `in(...)` **is no exception**: the core
> compiler (v0.2.2) emits this filter `COLLATE NOCASE` as long as it is **positive**, placed in the **base
> filter** of the `search` (not in a `| where` stage) and its list is **not entirely numeric**
> — a criterion carried by the **values**, never by the field's declared type. Since the importer's tokens
> all land in that base filter (§4e), this is indeed the form that applies: **no**
> silent under-match on members with varying case (`cmd.exe` vs `CMD.EXE`). The **negation**
> `not in (…)`, however, stays **BINARY** (case-sensitive): it **over-includes**, never a blind spot.

### 4d. Values

- **string** → hex/backslash-escaped regex pattern (injection-safe, see §0.2).
- **Sigma wildcards** `*` (→ `.*`), `?` (→ `.`), literal `\*`/`\?`/`\\` (equality only).
- **integer** in equality → exact numeric comparison `field=n`.
- **list** (OR of equalities, no wildcard) → `field in (a,b,c)`; **list + `\|all`** → **AND** of matches.
- **`null`** (field existence) → **not expressible** → flag.

### 4e. Condition

| supported | e.g. |
|-----------|------|
| single selection | `selection` |
| conjunction | `sel1 and sel2` |
| exclusion (negation of a **single equality / list of equalities**) | `selection and not filter` → `field!=v` / `field not in (…)` |
| `all of` quantifiers | `all of them`, `all of selection*` |
| parentheses (around a conjunction) | `(sel1 and sel2) and not filter` |

**Not supported (flag):** `or` / cross-field OR; `1 of them` / `any of` (OR); aggregations
`… | count() by X > N`; negation of a **multi-field** selection or one **with a modifier** (no
`NOT REGEXP` in GXQL); OR list of **substrings** (`contains` + list without `|all`); **modifiers**
`base64`/`base64offset`/`utf16`/`wide`/`cidr`/`windash`.

> **Why reject OR?** The GXQL `search` combines its filters with **AND**; the only OR available is
> `field in (…)` (OR of equalities on **one** field). A cross-field OR (`a or b`, `1 of them`) has no
> faithful GXQL form → translating it approximately would **under-match** (blind spot). We prefer to
> **flag** it honestly. (The field can still be imported manually, or through several rules.)

---

## 5. Shipped examples (`config.d/sigma/`)

| file | demonstrates | GXQL produced |
|------|--------------|---------------|
| `firewall-denied-nonstandard-port.yml` | `logsource.category`→`firewall`, equality, **list negation** | `search category=firewall action=~(?i)^deny$ dport not in (80,443) \| stats count` |
| `web-admin-path-blocked.yml` | `\|startswith` + equality **ANDed** | `search category=web action=~(?i)^blocked$ url=~(?i)^\/admin \| stats count` |
| `process-whoami-discovery.yml` | `process_creation`→`exec`, extended field `\|contains` | `search category=exec CommandLine=~(?i)whoami \| stats count` |

> ⚠️ **`process-whoami-discovery.yml` stays INERT on a default Windows**: it filters on
> `CommandLine`, a field **absent** from an EventID 4688 as long as the GPO *"Include command line in process
> creation events"* is not enabled (see §4a, blind spot #2). It demonstrates the **translation** of an
> extended field, not a detection that is active out of the box. Translating is not detecting.

Pre-flight: `plume-daemon sigma-import config.d/sigma --dry-run`.

---

## 6. What the importer is NOT

- Not a complete Sigma engine: it targets the **subset expressible in GXQL** (§4). The rest is
  **flagged**, never guessed.
- Not a **filter/suppression** path: an imported rule **adds** a detection (see principle #3).
- Not a **temporal correlation** backend (Sigma `timeframe`/aggregation): out of scope → flag.
