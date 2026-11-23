# Plume — Curated detection catalog (starter pack)

[English](DETECTION-CATALOG.md) | [Français](DETECTION-CATALOG.fr.md)

> **Status: additive content, vendor-agnostic, inert by default.** This catalog ships a
> LIBRARY of high-value detection rules, mapped to CIM + ATT&CK, under
> [`config.d/rules/catalog/*.json`](../config.d/rules/catalog). Loaded at boot by the overlay
> loader (`daemon/src/overlays.rs`) with `managed=1` (git source), with the SAME
> "compile-or-skip" validation as any overlay rule. They complement — without duplicating — the active
> SEEDED rules (`daemon/src/seeds.rs`) and the root overlays (`config.d/rules/*.json`).

## Principle & enabled/disabled policy

- **37 SHIPPED rules** (`git ls-files 'config.d/rules/catalog/*.json' | wc -l`, a count compared with the tree
  by `.github/scripts/check_a_published_rule_count_is_the_count_shipped.py`), of which **34 are described** in
  the tables below (all names distinct). Together, the shipped rules cite **26 distinct ATT&CK
  techniques** that fall under **13 tactics** (mapped via `guatx_core::attack::CATALOG`;
  no unmapped technique). The three shipped rules not described here, all in T1562.001, are
  `de-auditd-silent.json` ("Hôte: auditd muet (dead-man's-switch anti-forensics)"),
  `de-auditd-no-exec-rule.json` (auditd runs with no 64-bit execve rule) and
  `de-collector-unavailable.json` (a sensor declares that it cannot collect).
- **ALL `enabled=false` by default, except one**: `de-detection-content-mutated.json`, the self-detection
  of a change to the detection content, is active (exception held by
  `catalog_rules_all_compile_and_are_disabled_by_default`). It is a LIBRARY: the admin ENABLES each rule
  according to the telemetry actually wired in, through the UI toggle (no rule starts alerting
  on a fresh install ⇒ zero day-0 noise). The "universally present + low FP" base
  is ALREADY enabled by the seed layer; the catalog is the opt-in extension.
- **All in GXQL** (`is_soql=true`) ⇒ compiled by the CLOSED compiler (injection-safe by
  construction; never raw SQL). A rule that does not compile is DROPPED at boot ⇒ a test
  (`catalog_rules_all_compile_and_are_disabled_by_default`) requires all 37 to compile and load.
- **CIM-exact**: each rule references only `source`/`category`/`fields.*` values actually
  emitted by the collectors (see [`docs/CIM.md`](CIM.md)). NB the destination port of the
  native collectors (conntrack/ufw/portscan) is `dport` (string), not `dst_port`.
- **Every rule carries a `mitre` tag** ⇒ the ATT&CK coverage matrix lights up as soon as it is enabled.

### "Enable first" recommendations (low FP, high value)
- `Catalogue — Persistance: clé SSH ajoutée à authorized_keys` (T1098.004) — native telemetry
  (integrity), near-zero FP outside provisioning.
- `Catalogue — K8s: accès API anonyme / non-authentifié` (T1078) — if k8s audit is present, ~0 FP.
- `Catalogue — IDS: signature Suricata déclenchée (haute sévérité)` (T1190) — if Suricata is present.

### Signals that need telemetry that is NOT universally present (honest note)
- **Kubernetes** (`kube-audit`/`kube-rbac`): 6 rules — inert outside a k8s cluster with audit enabled.
- **Endpoint FIM BYO-agent** (`category=integrity fim_event=*`): 2 ransomware/wipe rules —
  they need a Wazuh/osquery agent wired in (distinct from the native host FIM `kind`/`change`).
- **MinIO audit relay** (`minio-audit`): 3 rules — they need the S3 audit relay.
- **Suricata / Falco**: do not emit structured fields (signal via `category`+`severity`).
- **Mail / Vault**: opt-in depending on the deployed stack.
- **Geo impossible-travel**: NOT shipped (no source provides geo/ASN to the CIM to date) —
  a documented gap, to be opened once a geo enrichment exists.

## Index — rule → tactic → technique → telemetry → enabled by default


### Reconnaissance (TA0043)

| Rule | ATT&CK | Sev | Required telemetry | Enabled |
|------|--------|:---:|--------------------|:-------:|
| Exploit web: motif d'injection/traversal dans l'URL (origine) | `T1190` | 3 | web (path) | no |
| Recon web: forced-browsing (403-breadth par IP) | `T1595.003` | 2 | web (action, status, path) | no |
| Recon: scanner web identifié par User-Agent (sqlmap/nikto/nuclei) | `T1595.002` | 2 | web (ua) | no |

### Credential Access (TA0006)

| Rule | ATT&CK | Sev | Required telemetry | Enabled |
|------|--------|:---:|--------------------|:-------:|
| Brute-force auth mail (SMTP/IMAP/POP) | `T1110` | 3 | mail (mail collector: category=auth action=failure, src_ip promoted) | no |
| Brute-force distribué (nombreuses IP sources sur l'auth) | `T1110` | 2 | any auth source (category=auth: journal/auditd/mail — neutral CIM) | no |
| Brute-force sur login web (401 par IP) | `T1110` | 3 | web (reverse proxy/app: category=web, status field) | no |
| Password spray (comptes distincts échoués depuis une IP) | `T1110.003` | 3 | auditd (PAM/auth audit: record family category=auth, acct field + addr promoted to src_ip) | no |
| Persistance: clé SSH ajoutée à authorized_keys (intégrité) | `T1098.004` | 4 | integrity (native host FIM: kind, change — default collector) | no |
| Vault: moisson de secrets (volume élevé par identité) | `T1552.001` | 3 | vault-audit (Vault audit device: operation, path, user) | no |

### Discovery (TA0007)

| Rule | ATT&CK | Sev | Required telemetry | Enabled |
|------|--------|:---:|--------------------|:-------:|
| Balayage réseau interne (une source touche de nombreux hôtes) | `T1046` | 3 | conntrack (flows: scope, dir, dst_ip — MULTI-HOST fleet) | no |
| K8s: rafale d'accès refusés (énumération API) | `T1069` | 3 | kube-audit (Kubernetes audit: action=forbidden, user) | no |
| K8s: énumération de secrets (list massif) | `T1552.007` | 3 | kube-audit (resource, verb) | no |
| Objet-store: rafale d'AccessDenied (recon de buckets) | `T1526` | 2 | minio-audit (S3 audit relay: status, accessKey) | no |

### Lateral Movement (TA0008)

| Rule | ATT&CK | Sev | Required telemetry | Enabled |
|------|--------|:---:|--------------------|:-------:|
| Latéralisation SSH interne (une source -> plusieurs hôtes en 22) | `T1021.004` | 3 | conntrack (scope, dir, dport, dst_ip) | no |

### Priv-Esc / Persistence (TA0004/TA0003)

| Rule | ATT&CK | Sev | Required telemetry | Enabled |
|------|--------|:---:|--------------------|:-------:|
| Hôte: compte local créé/modifié (useradd/usermod) | `T1136.001` | 3 | auditd (records category=account: useradd/usermod/passwd) | no |
| Hôte: nouveau binaire SUID déposé (intégrité) | `T1548.001` | 4 | integrity (native FIM: kind=suid, change=ajout) | no |
| K8s: (Cluster)RoleBinding créé (octroi de droits RBAC) | `T1098` | 3 | kube-audit (resource, verb) | no |
| K8s: ServiceAccount lié à cluster-admin (clés du royaume) | `T1098` | 4 | kube-rbac (RBAC snapshot: role, kind, subject) | no |

### Defense Evasion (TA0005)

| Rule | ATT&CK | Sev | Required telemetry | Enabled |
|------|--------|:---:|--------------------|:-------:|
| Hôte: tentative de désactivation de l'audit (auditctl) | `T1562.001` | 4 | auditd (records category=exec: exe) | no |
| SOC: modification du contenu de détection (règle créée/éditée/désactivée) | `T1562.001` | 2 | plume self (self-audit: source=plume-config, action=config.rule.*) | yes |

### Execution (TA0002)

| Rule | ATT&CK | Sev | Required telemetry | Enabled |
|------|--------|:---:|--------------------|:-------:|
| Hôte: exécution depuis un répertoire monde-inscriptible (/tmp, /dev/shm, /var/tmp, /run) | `T1059.004` | 3 | auditd (records category=exec: exe) | no |
| IDS: signature Suricata déclenchée (haute sévérité) | `T1190` | 3 | suricata (IDS: category=alert, severity) | no |
| Runtime: activité suspecte Falco (eBPF, sév≥3) | `T1059` | 3 | falco (eBPF: category=ebpf, severity) | no |
| Webshell probable (POST -> script .php renvoyant 200) | `T1505.003` | 3 | web (method, status, path) | no |

### Collection (TA0009)

| Rule | ATT&CK | Sev | Required telemetry | Enabled |
|------|--------|:---:|--------------------|:-------:|
| Hôte: accès répété aux secrets/identifiants (dataaccess) | `T1552.001` | 3 | dataaccess (watch on sensitive files: key, action, user) | no |

### Exfiltration (TA0010)

| Rule | ATT&CK | Sev | Required telemetry | Enabled |
|------|--------|:---:|--------------------|:-------:|
| Exfiltration/spam: envoi sortant de masse depuis une identité | `T1048` | 2 | mail (category=mailflow, sender) | no |
| Objet-store: lecture de masse (exfiltration probable) | `T1530` | 3 | minio-audit (api, accessKey) | no |
| Égress: éventail vers de nombreuses IP externes (hors infra) | `T1071` | 2 | conntrack (dir, scope, proc, dst_ip) | no |

### Impact (TA0040)

| Rule | ATT&CK | Sev | Required telemetry | Enabled |
|------|--------|:---:|--------------------|:-------:|
| Destruction: suppression de masse de fichiers (FIM endpoint) | `T1485` | 4 | endpoint FIM (category=integrity, fim_event, agent_name) | no |
| K8s: suppression de masse de ressources | `T1485` | 3 | kube-audit (verb, action, user) | no |
| Ransomware: modification de masse de fichiers (FIM endpoint) | `T1486` | 4 | endpoint FIM (BYO agent: category=integrity, fim_event, agent_name) | no |
| Vague d'attaques: rafale de bannissements (fail2ban/CrowdSec) | `T1595` | 2 | bans (fail2ban/crowdsec: category=ban, src_ip promoted) | no |

### Cloud / Container (TA0001/TA0004)

| Rule | ATT&CK | Sev | Required telemetry | Enabled |
|------|--------|:---:|--------------------|:-------:|
| K8s: accès API anonyme / non-authentifié | `T1078` | 3 | kube-audit (user) | no |
| Objet-store: bucket exposé publiquement | `T1530` | 3 | minio (policy snapshot: kind=bucket, risk=public) | no |

## ATT&CK coverage added

Techniques newly covered / reinforced by the catalog: `T1021.004`, `T1046`, `T1048`, `T1059`, `T1059.004`, `T1069`, `T1071`, `T1078`, `T1098`, `T1098.004`, `T1110`, `T1110.003`, `T1136.001`, `T1190`, `T1485`, `T1486`, `T1505.003`, `T1526`, `T1530`, `T1548.001`, `T1552.001`, `T1552.007`, `T1562.001`, `T1595`, `T1595.002`, `T1595.003`.

These tags join the coverage join (`/api/coverage/detections`): as soon as a catalog
rule is enabled, its technique moves from *missed* to *detected* in the matrix.

Two clarifications on what the matrix counts, on the consumer side (Forge's purple loop):

- **The tag's technique is the one that counts, sub-technique included.** Enabling a rule tagged with
  the **parent** technique (`T1110`) does NOT move a fired **sub-technique** (`T1110.001`) to
  *detected*: it is classified `detected-parent-approx` — a **named** blind spot, excluded from the detection
  rate and from the MTTD. A generic parent rule does not prove coverage of a particular
  vector: the three `T1110` rules in this catalog are bound to mail (`source=mail`), bound
  to web (`source=web status=401`), or require IP dispersion (`stats dc(src_ip)`) — none of those
  three catches a single-source SSH brute force. Other **seeded** `T1110` rules could,
  depending on the telemetry wired in: that is precisely what the join cannot know from a tag,
  and why it names the doubt instead of settling it. To turn a sub-technique green,
  tag a rule **with that sub-technique**.
- **A tag can carry SEVERAL techniques** (`"T1595.002 T1046"`, separated by space/comma/
  semicolon — the SigmaHQ convention). The endpoint **splits** them: one entry per technique, counts
  summed, `first_ts` = the first detection. The composite string is never served as-is.

## Seed rules (laid down at install) — the population each threshold was calibrated on

The rules in this catalog are **off** by default; these ones, on the contrary, are **laid down at
install** (`seeds.rs`), and enabled **only if a shipped producer emits the telemetry
they read** — a rule whose source nobody feeds is laid down disabled, and the audit says
which one and why (a lock that holds on a FRESH database: an installation already in service keeps what
its migration laid down). A threshold only makes sense for the population it was calibrated on.
This table says which one, and what a **new** population under the same rule changes (`P4.12-e`).

Since migration v122 (`P4.12-g`), this population is also **declared in the database**, readable by
the code: the `population` column of each shipped rule (single table `daemon/src/population_de_calibrage.rs`,
written by the seeders and replayed by the migration without overwriting an operator's declaration), and the
rule loop writes at fire time, into `population_vue`, the attributed sources that are not part of it — the
rule's row then carries "new population: <source>". This table remains the prose version of that
declaration; the code is its source of truth.

| Seed rule | Query shape | Threshold and window | Calibration population | A new population under this rule |
|-----------|-------------|----------------------|------------------------|----------------------------------|
| Brute-force auth par IP (5 min) | `category=auth action=failure \| stats count by src_ip \| where count > 15` | > 15 failures per IP, 5 min, evaluated every 60 s | the **sshd** `rhost`: exposed SSH, where 15 failures in 5 min from the same address is automated traffic | **Windows** failures (4625/4771/4776) carry `src_ip` since 2026-08-29: an RDS/Citrix gateway or a domain controller that concentrates the failures of a whole service under ONE address crosses this threshold on a Monday morning, with no attack. And an open alert is refreshed without re-notification (`P4.12-h`) |
| RBA : brute-force d'authentification (risque par IP source) | `category=auth action=failure \| stats count by src_ip \| where count > 5` | > 5 failures per IP, 1 h, 30 risk points per contribution, entity `ip` | the same sshd `rhost`; the score only crosses the alert threshold after several distinct hours | on a Windows fleet, every desktop whose mail client, mapped network drive or scheduled task holds an expired password contributes every hour: up to one risk alert **per desktop** (dedup key per entity) |
| Pic d'échecs d'authentification (1h) | `category=auth action=failure \| stats count` | > 100 failures across all sources, 1 h | the **global** spike of an exposed host (SSH + mail) — it is what sees a password spray spread over many addresses, which the per-IP rule does not see | an entire fleet counts its failures in the same place: the threshold is reached by the mere background noise of a large number of desktops |
| Port-scan détecté (nft PORTSCAN, 10 min) | `source=portscan dir=inbound \| stats count` | > 0 events, 10 min | the nftables `PORTSCAN` chain: an event only exists if the firewall has already classified it | none: the population is the one the firewall produces |
| RBA : reconnaissance / port-scan (risque par hôte ciblé) | `source=portscan dir=inbound \| stats count by host \| where count > 0` | > 0 per host, 1 h, 20 points, entity `host` | the same `PORTSCAN` chain | none |
| CPU > 90% (10 min) | `SELECT value FROM metric WHERE name='cpu_pct' … LIMIT 1` | last value > 90, 10 min | no population: a capacity threshold, not a behavior | a host loaded by design (builder, batch processing) raises the alert in every window |
| CF : scan/bot absorbé au edge (> 20 challenges managés/IP) · exploit WAF managé (> 3 blocages) · L7 flood (> 100 req/IP) · recon multi-vhost (> 3 vhosts/IP) · volume de challenges (> 20 IP distinctes) | `source=cloudflare …` | see `seeds.rs` | **not calibrated**: the code says so itself ("thresholds to be calibrated"), they describe the shape of the events that a Cloudflare plan without managed WAF emits | a plan with managed WAF, or a high-traffic site, changes the meaning of each threshold: to be recalibrated by the operator |

**What accidental coverage was hiding.** Before Windows failures carried `src_ip`
(`P4.12-a`), they all fell into a single empty bucket: a password spray from twenty addresses with ten
failures each made `count=200 > 15` and the "Brute-force auth par IP" rule fired — for the
wrong reason, but it fired. Since then, twenty buckets of ten, none above fifteen, **no
per-IP alert**: this case is only seen by the "Pic d'échecs (1h)" (threshold 100) and by the
catalog rule "Brute-force distribué (nombreuses IP sources sur l'auth)", which is **off by
default** like the whole catalog. An operator who wants to see the spray enables it; this document does not
claim it is covered otherwise.

**What nobody has measured.** The per-IP authentication failure rate of a Windows fleet **at
rest** — the figure that would decide whether the thresholds above produce false positives on this
population — has not been measured on any machine. Until it is, neither "false positive" nor
"true positive" can be asserted for Windows failures.
