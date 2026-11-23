# Infrastructure profile — deploying the SOC on ANY infrastructure (without touching the code)

[Français](PROFILE.md) | [English](PROFILE.en.md)

The SOC is **generic**: the engine (daemon), search (GXQL), the parsers and the collector
architecture contain **nothing specific to one infrastructure**. Everything that depends on YOUR
environment goes through **variables** (env / `EnvironmentFile` of the systemd units, or env of the
k8s Deployment). This file lists those variables — it is the **only** place to adapt.

Principle: *generic engine + infrastructure-specific in CONFIG, never hardcoded*; each collector is an
**auto-detected plugin** (switches itself off cleanly if the tool/log is absent), **OFF by default**.

> The default values below are **GuatX examples** (for compatibility). On another infrastructure,
> replace them with your own, or leave empty.

## 1. Agent → central (forwarder)
| Variable | Role | Default |
|---|---|---|
| `PLUME_CENTRAL` | URL of the central daemon (`https://central.example`; `http://` is only accepted by `ship.sh`, `respond.sh`, `prom-scrape.sh`, `engagement-adapter.sh` and the Windows collector towards the loopback, or with `PLUME_SHIP_ALLOW_PLAINTEXT=1` set in each unit's environment file) | — |
| `PLUME_TOKEN` | agent token (bound to a host, minted on the central by `plume-daemon token`, daemon started once beforehand ([`../docs/INSTALLER-SANS-OUVRIR-DE-BRECHE.md` §1.1](../docs/INSTALLER-SANS-OUVRIR-DE-BRECHE.en.md#11-start-the-daemon-once-before-any-subcommand-that-writes-to-the-database)): form per mode — `sudo env PLUME_CONFIG=/etc/plume/soc.conf …` on a native host, `exec` in the daemon's container in Docker and k3s — in [`../docs/TROIS-MODES.md` §3.5](../docs/TROIS-MODES.en.md#35-creating-an-agent-token)) | — |
| `PLUME_HOST_LABEL` | displayed host name (multi-host) | hostname |
| `PLUME_HOST_HEADER` | `Host:` header to send (if forward-auth/SNI) | — |
| `PLUME_TLS_*` | agent mTLS (cert/key/CA) if the central requires it | — |
| `PLUME_EXTRA_COLLECTORS` | plugins to enable (`conntrack auditd kube-state pod-logs …`) | (base only) |

## 2. k8s / k3s cluster (if applicable)
| Variable | Role | Default |
|---|---|---|
| `PLUME_KUBECTL` | kubectl command (`kubectl` / `k3s kubectl` / `microk8s kubectl`) | auto-detection |
| `PLUME_KUBECTL_TIMEOUT` | API timeout (anti-hang) | `8s` |
| `PLUME_K3S_STORAGE` | path of the local-path provisioner (PV% metric) | auto (k3s / local-path-provisioner) |
| **`PLUME_WATCH_STS`** | **critical apps to watch**: `ns/nom ns/nom …` → metric `kube_sts_ready_<nom>` + sev 4 alert "`<nom>` unavailable". Read by `kube-state.sh` (emission) **and** the daemon (rule seed). | **(empty)** — define your apps; the generic `kube_sts_notready` is still emitted without config |

> **Key rotation — no variable to set, but a timer to arm.** If the cluster uses
> `external-secrets`, `kube-state` also publishes `secretstore_notready` **and its denominator**
> `secretstore_total`: the daemon then raises **ONE** native alert (sev. 4, family
> `heartbeat.magasin-de-secrets`) when secret provisioning stops — not one per secret.
> Nothing to configure here; but the producer is `plume-kube-state.timer`, which `bootstrap.sh` leaves
> **off**, and as long as it is off this signal is **silent** — its silence does NOT mean "all is well".
> Details and arming operation: `deploy/K8S.md`.

## 3. Collectors (per-source settings)
| Variable | Role | Default |
|---|---|---|
| `PLUME_POD_LOG_SKIP` | pods excluded from `pod-logs` (already covered by a dedicated collector) — `\|` list | `mailserver` |
| `PLUME_POD_LOG_FILTER` | regex of the pod lines kept (errors + auth) | `error\|fail\|denied\|…\|authenticated\|…` |
| `PLUME_CROWDSEC_NS` / `PLUME_CROWDSEC_LAPI` | CrowdSec namespace / LAPI pod | `crowdsec` |
| `PLUME_CROWDSEC_WHITELIST_SHARE_MAX` | threshold, as a percentage of the lines parsed, from which the CrowdSec heartbeat says `surtout_liste_blanche` (severity 2); the cause follows the breakdown per whitelist (`cscli metrics show whitelists`): client address = a proxy's relay only if everything goes to `crowdsecurity/whitelists`, "vraies adresses" if another list discards, "répartition inconnue" if it is unreadable; integer from 1 to 100, any other value falls back to the default and says so (`unreadable-config`) | `90` |
| `PLUME_CROWDSEC_SANS_SCENARIO_MAX_HEURES` | duration, in hours, without any line reaching the scenarios (everything whitelisted) before the CrowdSec heartbeat refuses to conclude (`tout_en_liste_blanche`, severity 3, admission); below it: `en_liste_blanche_sous_le_seuil`, severity 1, no admission — except a missing or unreadable sensor timestamp that cannot be written (state not writable): refusal without waiting for the threshold, failure admitted (`etat/horodatage`). `0` = immediate refusal; integer from 0 to 9999, any other value falls back to the default and says so (`unreadable-config`) | `24` |
| `PLUME_WEB_MAX` | read bound of the `web` sensor: lines read at most per run. With `PLUME_WEB_SRC=file`, reading follows a byte offset, which serves as the watermark — beyond the bound, the rest of the log is read on the following runs, nothing is skipped, even in the middle of a second (only the first run reads the last `PLUME_WEB_MAX` lines and says so); a rotation resumes from `<journal>.1` (uncompressed), otherwise the loss is admitted (`missing-source`). With `k3s`, `kubectl logs --tail` only returns the last lines of the window: the oldest ones, never read, are counted by a second `kubectl logs` (explicit `--tail` of 10 × `PLUME_WEB_MAX` per pod: beyond that, the admitted number is a minimum, "au moins N") and admitted (`collection-capped`). Does NOT bound the ceiling of 9000 requests published per run, which is separate | `10000` |
| `PLUME_CONNTRACK_SCOPE` | conntrack scopes collected (`external internal loopback`) | all |
| `PLUME_LOCKDOWN_IFACE` / `PLUME_LOCKDOWN_PORTS` | docker-lan-lockdown check (laptop wifi) | `wlan0` (n/a if absent) |
| `PLUME_MAIL_F2B` / `PLUME_MAIL_SKIP_IP` | mail collector (docker-mailserver) | — |
| `PLUME_MAIL_SRC` / `PLUME_MAIL_DETECTION_DELAI` | log source of the mail collector (P10.33-x): `k3s`, `docker` or `file`, **set** = taken as is, without a probe (an unknown value is not guessed: the read failure is admitted). **Not set**: detected in the order k3s, Docker, readable file, each probe bounded by a `timeout` of `PLUME_MAIL_DETECTION_DELAI` seconds (integer ≥ 1 without a leading zero, otherwise admitted `unreadable-config` and 5); none: `missing-source`. Under a constrained unit (`CPUQuota`, cold `k3s kubectl` cache), **set** the source rather than have it detected. Details: `deploy/MAIL.md` | not set (detection), `5` |
| `PLUME_MAIL_CLAMAV_LOG` / `PLUME_MAIL_FRESHCLAM_LOG` | clamd and freshclam logs read by the mail collector (P10.32-f), in the same mode as `mail.log` (`PLUME_MAIL_SRC=k3s`: `kubectl exec`, `docker`: `docker exec`, `file`: local file). Set **empty**, reading is cut off; a file absent at the **default** path is reported `absent` in the config envelope; an unreadable **set** path is admitted | `/var/log/mail/clamav.log`, `/var/log/mail/freshclam.log` (k3s, docker); `/var/log/clamav/clamav.log`, `/var/log/clamav/freshclam.log` (file) |
| `PLUME_MAIL_DEMASQUER_DESTINATAIRE_LOCAL` / `PLUME_MAIL_DOMAINES_LOCAUX` | `1`: the `rcpt` field of a mail `malware` (INFECTED) or `banned` (BANNED) event comes out in plaintext if its domain appears **exactly** (case-insensitively) in the declared list of local domains (spaces or commas); everything else stays masked. Without a readable list, nothing is unmasked; an unreadable value or entry is admitted (`unreadable-config`). The config envelope states the state (`destinataire_local`) and the list retained (`domaines_locaux`). Risk and setting: `deploy/CONFIDENTIALITE.md` | empty (masked) |
| `PLUME_MAIL_CLAMAV_UTC_OFFSET` | UTC offset (`±hh:mm`) of the wall-clock time of the ClamAV log, which carries none | that of the last line of the run's `mail.log`, otherwise `+00:00` |

## 4. Central daemon
| Variable | Role | Default |
|---|---|---|
| `PLUME_RETENTION_DAYS` | event retention | `30` |
| `PLUME_QUERY_MAX` | ceiling of rows per query | `10000` |
| `PLUME_USER` / `PLUME_PASS_HASH` | native auth (argon2) — otherwise SETUP mode | — |
| `PLUME_SSO_HEADER_SECRET` + `PLUME_SSO_GROUP_*` | trusted-header SSO (Authentik/forward-auth) | — |
| `PLUME_GESTURE_SECRET_FILE` | file holding the argon2id **digest** (PHC) of the gesture secret — required, together with the permission, to create an account, promote an administrator, reset another account, mint a token or a delivery key, set an identity provider or a permission (header `x-plume-secret-des-gestes`). Generated by `plume-daemon secret-des-gestes --generer`. Reread on every operation (rotation = replace the file). See `docs/TROIS-MODES.md` §3.11 | **(empty)** — these operations are then **refused**, by name |
| `PLUME_HOST` | allowed host(s) (anti-DNS-rebinding) | — |
| `PLUME_SQLITE_BUDGET_MB` | total RAM budget granted to SQLite; automatically shared among the holders (pool connections + in-flight sorts), hence `cache_size` | `1088` (= 17 × 64 MiB, reproduces the historical sizing to the byte) |
| `PLUME_SQLITE_DEVERSEMENT` | **confidentiality ↔ memory trade-off.** At `0`, sorts stay in RAM: nothing of an event touches the disk in plaintext, but **a wide enough aggregation can exhaust memory** (SQLite has no spill mechanism in this mode). At `1`, large sorts spill to disk **in plaintext, outside the SQLCipher database** — only enable it if your threat model excludes theft of the volume, and then point `SQLITE_TMPDIR` to an encrypted medium (never a tmpfs: that would be RAM in the same cgroup). | `0` |
| `PLUME_SQLITE_DEVERSEMENT_QUOTA_MO` | **the bound on the volume written in plaintext**, in MiB, when `PLUME_SQLITE_DEVERSEMENT=1`. Beyond it, the current statement is STOPPED and **no result is returned** (a partial result would be wrong without saying so); the refusal names this lever. It bounds **what the PROCESS holds open** under the spill directory — not the offending query, not RAM, and nothing at all when spilling is `0` (no measurement is armed). `0` = no bound. If the system's measurement becomes unreadable along the way, the quota stops being enforceable and the cause is written once to standard error. | `1024` |

## Custom inputs (scripted inputs) — adding a source WITHOUT code
The generic collector `custom.sh` (OPT-IN, `PLUME_EXTRA_COLLECTORS="… custom"` + `plume-custom.timer`)
reads `/etc/plume/inputs.d/*.input`: you describe a command, its output becomes events. It is
the "inputs" equivalent of the parser registry — any source, any infrastructure, **zero code**.

```ini
# /etc/plume/inputs.d/nginx.input
SOURCE=nginx-app
CMD=journalctl -u nginx --since -90s --no-pager -o cat
SEVERITY=2
FILTER=error|warn|denied        # optional
# CATEGORY=web  MAX=100         # optional
```
Each line of the output of `CMD` → 1 event `source=nginx-app` (deduplicated on source+line/hour, bounded by `MAX`),
then **the registry's parsers enrich it** (groupable fields). See `deploy/example.input`.
Security: `CMD` runs as root → `/etc/plume/inputs.d` must be **root-only** (the operator already has root).

## Public demo (secured)
To expose a public demo **without risk**:
- **`PLUME_PUBLIC_DEMO=1`** → **anonymous read-only** access (*viewer* role forced): reading OK
  (overview, search, explore, dashboards, alerts…), **everything else blocked with 403** (create/update/delete,
  `/api/users`, `/api/actions`, `/api/ingest`, `/api/mail/body`). Reuses the viewer RBAC, PLUS a gate specific
  to the demo (`P10.28-i`): the *viewer* role writes for itself its saved queries, its preferences,
  its second factor and its password, and all anonymous visitors share the same identity — those writes
  are therefore refused too (named 403), reads remain.
- The demo **does not activate** if the name `demo` already belongs to someone (`P10.28-j`): a `demo` account,
  `PLUME_USER=demo`, rows held under that name or a directory identity that has carried it. The daemon starts without
  it (anonymous access refused): the startup log names the cause and the remedy, the ledger records the refusal
  (`demo.activation.refusee`) and the diagnostic bundle returns `public_demo_served` next to the configuration.
  The setup wizard does not set this name; with the demo active, a directory cannot present it (outside
  the demo, it takes it like any other name — and a demo requested afterwards will refuse to activate).
- **`PLUME_DEMO=1`** → only **fake data** (no real data).
- **ISOLATED instance**: a separate deployment, **never** the production SOC (its DB, its tokens, its network).
- Built-in rate limiting; put it behind a reverse proxy / Cloudflare. No real secret, no agent.

```sh
PLUME_PUBLIC_DEMO=1 PLUME_DEMO=1 docker compose up -d   # dedicated instance, read-only, demo data
```

## Deploying elsewhere (summary)
1. Central: `docker compose up` **or** `deploy/k3s.yaml` **or** `bootstrap.sh` (native host) — mode-aware.
2. Agent: `bootstrap-agent.sh` with `PLUME_CENTRAL`/`PLUME_TOKEN` + `PLUME_EXTRA_COLLECTORS`.
3. Adapt **this profile**: above all `PLUME_WATCH_STS` (your critical apps); the rest is auto-detected.
4. Absent collectors (no k8s, no crowdsec, …) disable themselves **on their own**.

Nothing else needs touching: no app name, namespace or IP is hardcoded in the logic.
