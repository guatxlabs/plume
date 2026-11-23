# Plume — Architecture

[Français](ARCHITECTURE.md) | [English](ARCHITECTURE.en.md)

Plume is a **feather-light SOC / XDR**: **a single Rust binary** (`plume-daemon`) that ingests
logs & metrics, stores them (SQLite/SQLCipher), and serves the **API + the web UI (PWA)** + the **detection
engine** on port **`:7000`**. Hosts/agents push their telemetry through `POST /api/ingest`.

The **same** binary deploys on **k3s/k8s** (behind a reverse proxy + SSO forward-auth), on
**Docker**, or on a **bare host** (systemd). The engine is **generic**: nothing infrastructure-specific is
hardcoded — everything goes through `PLUME_*` variables (see [`deploy/PROFILE.md`](deploy/PROFILE.md)).
The search compiler is **shared** with the public `guatx-core` crate.

> Reference documents (kept up to date): [`README.md`](README.md) · [`deploy/PROFILE.md`](deploy/PROFILE.md)
> (deploy on any infrastructure) · [`deploy/K8S.md`](deploy/K8S.md) · [`CAHIER-DES-CHARGES.md`](CAHIER-DES-CHARGES.md).

---

## 1. Goals & constraints

- **Unified visibility** in a **PWA** (installable, offline): posture, CVEs, firewall,
  hardening, auth, processes (XDR), file integrity, network, containers, k8s, resources.
- **Splunk-style search** over logs without Elastic: a **GXQL** language (search-like) compiled into
  read-only SQL.
- **Lightweight by design**: one `axum` + `rusqlite` binary (~4 MB), comfortable on little RAM.
  The reference profile **measures on the order of three hundred MiB of RSS** and is capped at **2 Gi** (host as well as k3s) — see §11
  for the measurement conditions and the caveat (no CI guard defends this ceiling).
- **Controlled exposure**: the daemon is **never** exposed to the Internet on its own — it lives behind a
  reverse-proxy chain (Cloudflare → Traefik → Authentik forward-auth), and agent ingest goes through
  a **dedicated mTLS** path. Standalone, it binds `127.0.0.1` by default + an anti-rebinding `Host` guard.
- **The SOC must not become a security hole** → privilege separation + hardening (see §10).

## 2. Design principles

1. **Lightweight pull, no heavy agents.** Sensors are small **shell** jobs (or 1 Rust binary
   for mail) triggered by **per-collector systemd timers** (`plume-*.timer`).
2. **Unprivileged daemon.** `plume-daemon` **never** runs as root (user `soc` / uid `10001`)
   and executes **no** privileged command on demand.
3. **Decoupled spool.** Collectors → JSON files in a **spool** → shipped by `ship.sh` →
   `/api/ingest` → SQLite tables. If the central goes down, the spool buffers → catch-up (zero loss).
4. **Everything auditable.** Sensors in readable shell (a professional must be able to review them).
5. **Diff & baseline.** Much of detection = comparing current state to a baseline (ports, SUID,
   units, hashes, image digests).
6. **Generic + config.** No app / namespace / IP name hardcoded in the logic: infrastructure specifics
   live in `PLUME_*` variables (env / `EnvironmentFile` / Deployment env). Each collector is
   an **auto-detected plugin** that switches itself off cleanly if the tool/log is absent, **OFF by default**.

## 3. Overview

```
  AGENTS host (sh + systemd, OFF par défaut)                    CENTRAL = 1 binaire `plume-daemon`
  ┌──────────────────────────────────────┐                     ┌─────────────────────────────────┐
  │ collecteurs bash  collectors/*.sh     │   mTLS + Bearer     │ axum (API + ServeDir PWA) :7000 │
  │  resources integrity firewall controls│  POST /api/ingest   │ rusqlite (SQLite/SQLCipher)     │
  │  conntrack auditd kube-state pod-logs …│ ─────────────────► │  event / metric / snapshot      │
  │  collector-mail (binaire Rust)        │                     │  + FTS5 + rollups (pré-agrégé)  │
  │  spool /var/lib/plume/spool           │                     │  parsers · règles · playbooks   │
  │  ship.sh  ·  respond.sh (pull)        │ ◄── /api/actions ── │  GXQL (compilo guatx-core)      │
  └──────────────────────────────────────┘   (responder pull)  └─────────────────────────────────┘
                                                                          ▲ :7000 (ClusterIP)
   Navigateur ──► Cloudflare (tunnel) ──► Traefik ──► Authentik forward-auth ──► daemon (UI)
   Agent      ──► ingest.example.com:443 (Traefik websecure, mTLS RequireAndVerifyClientCert) ──┘
```

The central **is also its own agent**: on the k3s host, host collectors (kube-state,
pod-logs, mail…) push into the same daemon. An **ingress NetworkPolicy** (to be placed in your
GitOps repository) restricts access to `:7000` to the reverse proxy **alone** (selector = the namespace and the
label of YOUR ingress controller) — no other pod can reach the daemon directly
(prevents forging of SSO headers).

## 4. Components

### 4.1 `plume-daemon` — the single binary (central)

- **Crate** `daemon/` (`plume-daemon`, `axum` 0.7 + `tokio` + `tower-http`). DB through `rusqlite` with
  the `bundled-sqlcipher-vendored-openssl` feature → **encrypted SQLite (SQLCipher) at rest**. A
  **new** database is born encrypted: under `PLUME_DB_KEY`/`PLUME_DB_KEY_FILE` if either is set, otherwise under a
  key the daemon generates on its first start (`0600`, next to the database). An **existing** plaintext
  database stays plaintext until the `plume-daemon chiffrer-au-repos` operation — including a database that a
  subcommand created before that first start
  ([`docs/INSTALLER-SANS-OUVRIR-DE-BRECHE.md` §1.1](docs/INSTALLER-SANS-OUVRIR-DE-BRECHE.md#11-démarrer-le-démon-une-fois-avant-toute-sous-commande-qui-écrit-dans-la-base)).
  WAL + FTS5.
- **Serves three things on the same port `:7000`**: the **API** (`/api/*`), the **web UI** (static assets
  via `tower_http::ServeDir` from `PLUME_WEB=/usr/local/share/plume/web`), and **ingestion**
  (`/api/ingest`, `/api/ingest/journal`, `/api/ingest/minio`, `/api/metrics/*`, `/loki/api/v1/push`).
- **GXQL compiler delegated to `guatx-core`**: `daemon/Cargo.toml` depends on `guatx-core` through a
  **pinned public git dependency** (see §4.1 "Image").
  The **`PLUME_SOQL_CORE`** toggle (read at boot) has 3 states: `off` (legacy Plume compiler), `shadow`
  (double compile Plume+core, logs the differences, **serves the old one**), `on` (serves the SQL from
  `guatx_core::soql::to_sql(...)`). **Recommended: `on`.**
- **CLI subcommands**: `hashpw '<mdp>'` (generates the argon2id hash), `token <nom> [hôte]` (mints an
  agent token bound to a host), `backup <fichier>` (`VACUUM INTO` — an **encrypted** copy since it is SQLCipher)
  and `backup --compress <fichier>` (`age(zstd(...))`, ~5-10x smaller, **but through a temporary plaintext
  export on disk** — see deploy/CONFIDENTIALITE.md).
- **Config**: **`PLUME_*` only** (the old `SOC_*` prefix no longer exists). In a container,
  `PLUME_CONFIG=/nonexistent` → configuration purely through env; on a host, the unit reads `PLUME_CONFIG=/etc/plume/soc.conf`.
  **A single read path**: `cfg()` → `env > fichier PLUME_CONFIG > défaut`. A setting read through
  `std::env::var` escapes the file and therefore only has an effect in a container — this is defect P8.7-a, which
  silently cancelled a backup escrow recipient on a host. The partition is kept closed by a
  source scanner (`tests/partition_config.rs`): it derives who reads the environment, including through an
  intermediate function, and refuses any new variable that is not entered in the debt register.
  That register is only allowed to shrink. `plume-daemon.service` **deliberately carries no**
  `EnvironmentFile`: it would export `PLUME_PASS_HASH`/`PLUME_DB_KEY` into `/proc/<pid>/environ`.
  **P8.7-b (2026-08-09)** fixed the worst case of this partition: `PLUME_DB_KEY` was read through
  BOTH paths, which did not agree — opening the database through `env::var` alone, the cold tier through
  `cfg()`. A key written in `soc.conf` therefore encrypted the COLD half and left the HOT half
  in plaintext, silently (reproduced on the bytes: `age-encryption.org/v1` on one side,
  `SQLite format 3\0` on the other). `crypto::db_key_depuis(conf)` is now the single path, and
  `cold_store` calls it instead of having its own.
- **Image**: multi-stage `Dockerfile`. **Build context = the root of this repository** (standalone
  clone): `guatx-core` is resolved through a public git dependency whose TAG is pinned in
  `daemon/Cargo.toml` (writing it here would make a second copy that ages — `grep -n 'guatx-core' daemon/Cargo.toml`),
  `../../db/schema.sql` is copied from `db/`, a sibling of `daemon/`. Runtime `debian:bookworm-slim`,
  **non-root** (uid `10001`), web assets as `a+rX`. Build: `docker build -t soc:latest .` from the root.

### 4.2 Host agents — bash collectors + per-collector timers

- **Collectors**: `collectors/*.sh` (one auto-detected script per source). Base always installed:
  `resources`, `integrity`, `ship`. Plugins **OFF by default**, opt-in through `PLUME_EXTRA_COLLECTORS`:
  `firewall controls conntrack nft ufw auditd containerd clamav suricata falco crowdsec bans
  kube-state kube-audit kube-rbac pod-logs prom-scrape vuln imgdrift mail dataaccess dataacl audit web
  custom` …
- **One systemd timer per collector**: `plume-<nom>.timer` → `plume-<nom>.service` (hardened root
  oneshot) writes into the **spool** `/var/lib/plume/spool`. Each source has its own cadence (e.g.
  `plume-auditd.timer` `OnUnitActiveSec=2min`, `plume-ship.timer` 30 s). **There is NO
  `fast/mid/daily` timer** — each collector has its own timer.
- **`ship.sh`**: pushes the spool to the central — `*.json` → `POST /api/ingest`, `*.ndjson`
  (raw journald sshd/sudo/su) → `POST /api/ingest/journal`. Auth = **Bearer `PLUME_TOKEN`**
  (recommended) or Basic; **mTLS** if `PLUME_TLS_CACERT/CERT/KEY` are set. An accepted file (HTTP 202)
  is deleted; otherwise it is kept for retry.
- **`collector-mail/`**: **Rust binary** `plume-collector-mail` (opt-in `PLUME_WITH_MAIL=1`),
  host-native mail detection (docker-mailserver / k3s), through `plume-collector-mail.timer`.
- **`respond.sh`** (responder, opt-in `PLUME_WITH_RESPONDER=1`): **pull** model (no inbound
  network on the agent) — `plume-respond-agent.timer` pulls `/api/actions/pending`, applies
  bans/unbans by **delegating** to CrowdSec → fail2ban → nft, **dry-run by default** (`PLUME_RESPONDER_APPLY=0`)
  + **exemption list** `PLUME_RESPONDER_ALLOW` (`/etc/plume/responder-ban-exempt.allow` — the value SET by
  `bootstrap-agent.sh` on a new agent installation, NOT the script's fallback: that fallback, used when the
  variable is not set, is `/etc/plume/responder.allow` and therefore shares its path with the daemon's list of
  services; both values are true, for two different objects). Token **bound to the host** (anti-IDOR).
  Ban duration (`P11.25-a`): the one the central serves (`ban_ttl_s`, per-line JSON form requested if the host
  has `jq` or `python3`), otherwise an announced fallback to `PLUME_BAN_DURATION`; a queue served with a non-200 is never
  executed (exit 3). Details: `docs/AGENTS-PROTOCOLE.md` §6.
  ⚠️ **Two policies, two files, two readers — and they do not overlap** (`P4.7-a`/`P4.7-b`):
  this file carries **addresses that must never be banned**, read by `is_ip` (shell); the daemon reads
  `PLUME_STOP_SERVICE_ALLOW` (same historical path `/etc/plume/responder.allow`) as **service
  names** allowed for `stop_service`. The two predicates **are not equal**: what holds,
  and is measured on both readers, is that the daemon recognises **strictly more** forms as an address
  than the agent does — so no line is silently accepted by both. See the box in the
  README and `collectors/predicat-adresse.corpus`.
  ⚠️ `P4.7-c`, **open**: the **central's** responder reads **no** exemption list.
- **`minio-audit-relay.py`** (opt-in): MinIO webhook receiver (object audit) → spool → `ship.sh`.
- **Installation**: `bootstrap.sh` (central host) / `bootstrap-agent.sh` (agent). Host layout:
  binary `/usr/local/bin/plume-daemon`, collectors `/usr/local/lib/plume/collectors/`, config
  `/etc/plume/` (`plume.conf`, `soc.conf`, `mail.conf`, `responder.conf`, `inputs.d/*.input`),
  data `/var/lib/plume/` (`spool/`, `state/`, `db/`). **Custom inputs** (scripted inputs):
  `custom.sh` reads `/etc/plume/inputs.d/*.input` → any source becomes events **without code**.

### 4.3 Exposure chain (k3s)

Below is a **reference recipe** (ingress controller + SSO forward-auth + internal PKI); the
ingress objects live in **your GitOps repository**, under names of your choosing. Any equivalent
chain works — the daemon depends on none.

- **Browser UI**: `plume.example.com` → (optional) **tunnel** → **ingress controller** (HTTP
  entrypoint) → middlewares *redirect + HTTPS headers*, ***SSO forward-auth***, *injection of the SSO
  header secret* → Service `plume:7000`. The PWA shell (`/sw.js`, `/manifest.webmanifest`) is served
  **without** forward-auth (otherwise the SW gets a 403).
- **Hardened agent ingest (mTLS)**: `ingest.example.com:443` → HTTPS entrypoint → a **TLS option**
  requiring **`RequireAndVerifyClientCert`** (internal PKI, e.g. cert-manager) → daemon,
  **only** the agent paths (`/api/ingest`, `/api/metrics`, `/api/actions/pending|result`,
  `/loki/`). The agent resolves `ingest.example.com` → `127.0.0.1` (`/etc/hosts`) and presents its client
  cert + Bearer. **Do not expose a plaintext Bearer-only agent route** on the UI host: the
  agent path must remain the dedicated mTLS path.
- **Ingress NetworkPolicy**: `ingress`-only, the ingress controller **alone** (its namespace + its
  label) → `:7000`. Effective mitigation of the trust placed in SSO headers
  (a compromised pod can no longer reach `:7000` to forge a header).

## 5. Sensors ("Complete / XDR" tier)

| Domain | Collector | Source / tool | Output |
|---|---|---|---|
| **CVE / vuln** | `vuln.sh` | package/image CVE scanner | snapshot + alert |
| **Firewall** | `firewall.sh` `nft.sh` `ufw.sh` | `nft -j list ruleset`, ufw | snapshot + counters; alert if the control rule disappears |
| **Hardening** | `controls.sh` | sysctl / `/proc/cmdline` / lockdown | score + drift |
| **Auth / identity** | `journal.sh` `audit.sh` | journald (sshd/sudo/su/faillock/polkit) | `.ndjson` events + FTS |
| **Execution (XDR)** | `auditd.sh` | **auditd** (execve, setuid, access to `/etc/shadow`,`~/.ssh`,`sudoers.d`) | events + alerts |
| **File integrity** | `integrity.sh` | **AIDE** on sensitive paths | alert on change |
| **Network** | `conntrack.sh` | conntrack (ext/int/loopback flows) | events + diff |
| **Containers** | `containerd.sh` `imgdrift.sh` | containerd / image digest drift | new ports / image drift |
| **Antimalware** | `clamav.sh` | ClamAV | matches |
| **IDS** | `suricata.sh` `falco.sh` | Suricata `eve.json` / Falco | events |
| **CTI / bans** | `crowdsec.sh` `bans.sh` | CrowdSec LAPI / fail2ban | decisions/alerts |
| **Kubernetes** | `kube-state.sh` `pod-logs.sh` `kube-audit.sh` `kube-rbac.sh` | `kubectl` (state, logs, audit, RBAC) | `kube_*` metrics + events |
| **Third-party metrics** | `prom-scrape.sh` | scrape of an exposed Prometheus endpoint | metrics |
| **Object storage** | `minio.sh` `minio-audit-relay.py` | MinIO + audit webhook | object access |
| **Data** | `dataaccess.sh` `dataacl.sh` | file access/ACLs | events |
| **Mail** | `collector-mail` (Rust) `mail.sh` | maildir / docker-mailserver | mail events |
| **Resources** | `resources.sh` | `/proc` (cpu/mem/PSI), disk, smart | metrics + alerts (OOM, disk, SSD) |
| **Custom** | `custom.sh` | `/etc/plume/inputs.d/*.input` | any source, without code |

Always **OFF by default** except the `resources`/`integrity` base; each plugin disables itself if
the tool or the log is absent.

## 6. Ingestion flow & storage (SQLite/SQLCipher, WAL + FTS5)

Schema: `db/schema.sql` (embedded through `include_str!`), versioned migrations (`meta.schema_version`,
**currently v51**) in `migrate()`. Tables:

```sql
event(id, ts, source, category, severity, host, message, fields/*json*/)   -- + event_fts (FTS5)
metric(ts, name, labels/*json*/, value)
snapshot(ts, kind, data/*json*/)        baseline(key, value/*json*/, updated)
alert(id, ts, rule, severity, title, detail, status, acked_at)
dashboard(...)  panel(...)  rule(...)   -- + users, tokens, playbooks, cases, notifiers, ledger…
```

- **Pipeline**: collector → JSON envelope in the spool → `ship.sh` → `POST /api/ingest` (response
  **202**) → normalisation (epoch timestamp, severity 0-4, source mapping) → idempotent INSERT (dedup).
  **Idempotence assumes the sender provides a `dedup` key** (the agent does; `__CURSOR` for
  journald). A surface whose protocol carries **no per-entry identifier** — this is the case of
  **Loki push** — is **at-least-once**: `dedup` is NULL there, so the partial unique index does not
  apply. This is deliberate: a key derived from the CONTENT would silently drop identical lines
  that are legitimately repeated, turning a visible duplicate into an invisible loss.
  Raw journald goes to `/api/ingest/journal` (parsing **on the daemon side**, no `jq` on the agent).
- **Parser registry**: after insertion, the **parsers** (managed in the UI) enrich the
  events with groupable fields (`fields`). Reparsing is possible (`/api/parsers/reparse`).
- **Rollups (pre-aggregation)**: to avoid rescanning the events table for every panel,
  `event_rollup` (caps `src_ip` to a top-N per bucket, the rest lumped then re-aggregated = never lost) and
  **`event_dim_rollup`** (caps **each dimension** to the top-N per bucket, `PLUME_ROLLUP_DIM_TOPN`).
  Refreshed periodically (`PLUME_ROLLUP_INTERVAL_S`) + incremental backfill.
  **Each one PUBLISHES what it covers**, and no route reads beyond that: `event_rollup` publishes its bound
  (`RollupCoverage`) and REbuilds the bands where a line arrived late; `event_dim_rollup`
  maintains a **band** that rises, extends downward (`PLUME_ROLLUP_DIM_BACKFILL` per tick, down to the oldest
  `ts` of `event`) and shrinks on a backdated write. Coverage not published → the route
  **declines** and the raw scan serves. See `daemon/src/rollup_coverage.rs` for the measurement that motivated
  both (a ×6,6 undercount served as exact; a coverage `0` served as a data `0`).
- **Retention**: `PLUME_RETENTION_DAYS` (events, default 30), `PLUME_METRIC_DAYS`, `PLUME_SNAPSHOT_DAYS`,
  `PLUME_ALERT_DAYS`, metric downsampling (`PLUME_METRIC_RAW_HOURS`), purge + `VACUUM`.

## 7. Query (GXQL) & detection engine

- **GXQL → read-only SQL**: `search source=sshd "failed" | stats count by user` is compiled into validated
  SQL (`guatx-core` when `PLUME_SOQL_CORE=on`). **Read-only** connection, **a single** `SELECT`/`WITH…SELECT`
  (rejection of `;`, `pragma/attach/insert/update/delete/drop`), forced `LIMIT` (`PLUME_QUERY_MAX`,
  `PLUME_SEARCH_LIMIT/MAX`).
- **Budget & cancellation**: each query has a time budget (`PLUME_QUERY_BUDGET_MS`, interactive
  variant) + an interruption **watchdog**; interactive queries carry a **`qid`** and
  `POST /api/cancel` interrupts them. Concurrency bounded by a semaphore (`PLUME_QUERY_CONCURRENCY`,
  default 3; shared by `/api/query` + `/api/search` + panel data).
- **Rollup route**: a GXQL query matching an **exact pattern** (`… | stats count by source`, `search source=X | stats
  count by <dim>`, `count by source,severity`) is rewritten onto the **pre-aggregated** counters
  of `event_rollup`/`event_dim_rollup` → an answer in a few milliseconds **because it does not read the
  raw events**: the 92 seeded panels answer in **a few milliseconds** by reading **a few tens of
  thousands of pre-aggregated rollup lines**, not the **million or more events** of a real database (reading of
  2026-08-05 by `plume-daemon db-stats --par-objet`). Each answer carries
  `served_from: rollup|raw` + `approx` +
  `truncated` — the analyst **always** sees whether the figure is exact or aggregated.
  **And when it is truncated, it carries BY HOW MUCH**: the per-dimension top-N cap discards from x1,0 to
  **x16,4** depending on the dimension (measured 2026-08-01, bench of 1 436 026 events, `daemon/src/topn_cap.rs`), which
  a simple flag did not say. The rollup job writes, in the same statement that truncates, one
  **remainder line** per (bucket, source, dim, env) — written **even at zero**, otherwise its absence
  would be indistinguishable from a zero remainder. The route reads it and publishes `topn_ecartes`/`topn_servis`/`topn_total`.
  Buckets without a remainder line (aggregated by an earlier binary) → the extent is **admitted as unknown**,
  never replaced by 0. **What is NOT routed
  is not routed on purpose**: a `count by source,severity,action` (or `host`, or `src_ip`) falls back to the
  **raw scan**, measured at **about thirty seconds** on a real database **no later than 2026-07-23** (date of commit
  `c784f75`, which records the measurement; the date of the measurement itself is not recorded) — on a topology
  that retention has since purged; **the number of lines the database held at that moment was never
  recorded**, and the latency has **not** been re-measured since (reading of the current volume: 2026-08-05). This is
  therefore not a current cost, it is a dated measurement. The refusal to route is about
  correctness, not latency: the rollup merges `NULL` and `''` on these
  dimensions and would return a **wrong** group-by under an "approximate" label. We refuse to serve
  an approximate answer as if it were exact: **tens of seconds (measurement ≤ 2026-07-23) that are exact rather
  than milliseconds that are wrong**. The route
  is never attempted when a **field mask** is active (`event_rollup` carries source/host/severity/
  action in plaintext) — all the figures above are measured **with masking inactive**.
- **SWR panel cache**: `panel_cache` + **adaptive LIVE/SWR classification by measured cost**
  (`panel_cost`, migration v46) — a fast panel is served LIVE, an expensive panel switches to
  **stale-while-revalidate** (TTL `PLUME_PANEL_CACHE_TTL`), with **anti-stampede** (a single async refresh
  in flight per key, on a dedicated semaphore `PLUME_PANEL_REFRESH_CONCURRENCY` — it never steals
  a permit from interactive queries). **Source freshness** card = COLLECTION state per source (fresh/quiet/down).
- **Detection rules**: seeded at boot (`seed_detection_rules`, reproducible on a new PVC) **and** placed
  on existing instances by the **migrations** (up to v51: CF rules, brute force,
  minio backup-delete, auditd tamper, SUID integrity/persistence, conntrack beaconing, vault
  secret-read, self-detection of brute force against Plume's own auth…). Two families: **query** (GXQL/SQL +
  threshold) and **diff** (snapshot vs baseline). A matching rule → INSERT `alert` (+ severity) →
  **notifiers** (ntfy through `PLUME_NOTIFY_NTFY_URL`, threshold `PLUME_NOTIFY_MIN_SEV`). **Playbooks**
  (SOAR-lite) + **cases** (incidents) for follow-up.

## 8. Frontend (PWA)

- **Vanilla JS, no build step**: static assets in `web/`, served by the daemon's `ServeDir`
  (`PLUME_WEB`). Installable PWA (manifest + service worker, offline shell). **Bilingual FR/EN** + all
  IANA time zones.
- **Dense page** (dark, a11y): alert banner → posture/score → panels (firewall, hardening,
  auth, process/auditd, integrity, network, containers, k8s, resources, freshness…), search
  bar (GXQL/FTS) + time ranges, **Explore**, saved **dashboards** & **panels**
  (query-driven), **rules**, **parsers**, **cases**, **actions/playbooks**, **users** (RBAC).
- The PWA shell is served **outside forward-auth**; the data stays gated (Authentik + Plume auth).

## 9. Deployment

Three targets, **same binary** (mode-aware):

- **Docker**: `docker-compose.yml` — build context = **the root of this repository** (`context: .`);
  `guatx-core` is resolved through a **public git dependency** (`guatxlabs/core`, tag pinned in
  `daemon/Cargo.toml`), no sibling crate
  required. `docker compose build soc` → `hashpw` → `.env` (`PLUME_PASS_HASH`, **between single
  quotes**: Compose interpolates the `$` in a `.env`, see `README.md` §A and `.env.example`) →
  `docker compose up -d --build`. `PLUME_DEMO=1` populates
  demo data. The compose file enables the **native ops** (backup every 6 h + daily auto-vacuum).
  **No image is published**: this mode compiles from source (stage `rust:1-bookworm`).
- **Bare host (systemd)**: `bootstrap.sh` (central) installs the binary + `plume-daemon.service`
  (`User=soc`, hardened: `NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet=`,
  `MemoryMax=2G`, `ReadWritePaths=/var/lib/plume/db /var/lib/plume/spool`, bind `127.0.0.1:7000`).
  `bootstrap-agent.sh` installs an **agent** (collectors + `ship`, no daemon/DB/web).
- **k3s**: generic manifest [`deploy/k3s.yaml`](deploy/k3s.yaml) (Namespace + Secret + PVC +
  Deployment + Service + **Ingress** + egress **NetworkPolicy** *default‑deny*), native backup enabled.
  The Ingress ships **TLS only** (Traefik `websecure` entrypoint, certificate from the `Secret` `soc-tls`, to be
  created before applying) and the NetworkPolicy only has an effect if your CNI enforces them. A typical **production** deployment (to be carried in **your GitOps
  repository**, driven by ArgoCD/Flux or equivalent) adds:
  - **Deployment** — `replicas: 1`, **`strategy: Recreate`** (RWO PVC +
    SQLite = a single writer, no rolling update). `securityContext` non-root uid `10001`,
    `readOnlyRootFilesystem`, `drop: [ALL]`, `seccomp RuntimeDefault`.
  - An optional **initContainer** that drops an object-storage client (`mc`, `aws`…) into a shared emptyDir.
  - **`plume`** container (image **pinned by digest/SHA** — bump after build) + **`backup`
    sidecar** (same image; `plume-daemon backup` = **encrypted** `VACUUM INTO` — the
    `--compress` variant, for its part, goes through a temporary plaintext export → copy to
    `<votre-bucket>/plume/`; replaces Litestream, which is incompatible with SQLCipher).
  - **`PLUME_*` env only**: `PLUME_ADDR=0.0.0.0:7000`,
    `PLUME_HOST=plume.example.com,ingest.example.com` (multi-host: browser + mTLS SNI),
    `PLUME_DB=/data/plume.db`, `PLUME_SPOOL=/data/spool`, `PLUME_LEDGER_KEY=/data/ledger.key`,
    `PLUME_SOQL_CORE=on`, `PLUME_WATCH_STS="<ns>/<sts> <ns>/<sts>"` (your critical apps; default
    **empty**, see [`deploy/PROFILE.md`](deploy/PROFILE.md)), + RAM tuning (see §11).
  - **Secrets** (ideally through a secrets manager → ExternalSecrets, `optional:true`),
    one per role: `<secret-auth>` (`PLUME_USER`/`PLUME_PASS_HASH` — absent ⇒ **SETUP mode**, install
    token in the logs), `<secret-db-key>` (`PLUME_DB_KEY`, SQLCipher encryption),
    `<secret-sso>` (`PLUME_SSO_HEADER_SECRET`), `<secret-notify>` (notifier token).
  - **PVC** (RWO), ClusterIP **Service** `:7000`, **TCP probes** on `:7000` (not
    httpGet: everything is gated by auth → 401 ⇒ never ready).

## 10. Security model of the SOC itself

> A SOC aggregates logs and runs a web server: it gets locked down.

- **Auth**: argon2id (bcrypt fallback) + **RBAC** (viewer / editor / admin). No hash → **SETUP mode**
  (single-use token printed, web wizard). **Delegated SSO**: behind the Authentik forward-auth, Traefik
  injects `X-authentik-username/groups` **+ a shared secret** `X-PLUME-SSO-Secret`; the daemon reads
  these headers **only** if `PLUME_SSO_HEADER_SECRET` matches exactly (group mapping →
  `PLUME_SSO_GROUP_ADMIN/EDITOR/SUPERADMIN`). Without the right secret, no forged header grants any
  privilege — and the NetworkPolicy prevents any pod from reaching `:7000` to attempt the forgery.
- **`Host` guard (anti-DNS-rebinding)**: `host_guard` only accepts `PLUME_HOST` (multi-host list) +
  loopback; otherwise **421 Misdirected Request**. `PLUME_HOST_STRICT=1` removes the loopback auto-allow
  (exposed standalone).
- **Anti-brute-force**: Basic failure counter per `(user, src_ip)` → exponential backoff + **lockout**
  (`PLUME_AUTH_LOCK_*`, 429 + `Retry-After`) **before** argon2 (saves CPU). Each failure/lockout is
  **self-ingested as a SIEM event** (`source=plume-auth`) → a **self-detection** rule (v51, T1110)
  alerts on a burst against Plume's auth. The src_ip does **not** use `X-Forwarded-For` (spoofable).
- **Rate limit**: per source IP (`PLUME_RL_IP_MAX`) + global ceiling (`PLUME_RL_GLOBAL_MAX`) + tighter
  cap on auth routes (`PLUME_RL_AUTH_MAX`) → 429.
- **Agent tokens**: Bearer, SHA-256 in the database. **The scope is DECLARED at creation**, never
  defaulted: `plume-daemon token <nom> <HOTE>` = **machine** token (the host is rewritten at write time
  on **all** ingestion surfaces — `HoteIngere::resoudre` — and it is what authorises the
  responder on that machine); `plume-daemon token <nom> --relais` = **multi-host forwarder**, whose
  declared host is **not** attested. The two-argument form is refused: it produced an unbound
  token with which `{"host":"CONTROLEUR-DE-DOMAINE-USURPE"}` was accepted and stored under that name
  (measured on 2026‑08‑02). Agent ingest hardened by **mTLS** (cert-manager, dedicated SNI).
- **The secret never goes through a command line**: sensors pass the auth to curl through
  standard input (`plume_curl_auth_stdin`, `collectors/lib.sh`), the agent reads its token with
  `--token-stdin`, and the Windows collector no longer has a `-Token` parameter. *A process argument is
  public: measured on 2026‑08‑02 as readable in `/proc/<pid>/cmdline` (101-byte argv, secret verbatim),
  copied by journald into `_CMDLINE`, and — on Windows — written into 4688/Sysmon ID 1, that is, into
  what Plume itself collects.* What this does **not** close: an operator who types a secret on their
  own command line is still captured by execution auditing (`sudo` logs it, and `MESSAGE` is
  stored) — hence the `tee` enrolment procedure in `README.md`.
- **Config-gated native TLS**: if `PLUME_TLS_CERT` + `PLUME_TLS_KEY` are set, the listener serves
  **HTTPS (rustls/ring)** + HSTS; otherwise HTTP (default, behind Traefik). `ring` provider (no
  aws-lc-rs: avoids cmake/nasm).
  **HTTP/2 is served correctly there — it was not, and that was serious.** *Measured on 2026‑08‑02 in this
  mode: ALPN advertised = `h2` (`openssl s_client -alpn h2,http/1.1` → "ALPN protocol: h2", so a
  browser negotiates h2 every time), and the same request on the same authority answered **421 "bad
  host" over HTTP/2** versus **401/404 with `--http1.1`** — on `/api/me`, `/api/search`, `/login` and `/`.
  Only `/healthz`, `/readyz` and `/metrics` answered, because they are exempt from the guard:
  **242 of the 245 declared routes, web interface included, were unreachable from a browser.***
  Cause: `host_guard` only read the `Host` header, which is **absent** in HTTP/2 (the authority there is the
  `:authority` pseudo-header, which hyper stores in the URI) → `unwrap_or(false)`. The senders (`.sh`
  collectors, `plume-collector.ps1`, `plume-agent`) all use HTTP/1.1, which hid the defect for
  the whole life of this mode. **Fix**: the authority comes from a single source (`AutoriteDemandee`,
  `daemon/src/auth.rs`) that reads both locations of the protocol; its field is private, so an authority
  cannot be built from only one of the two. The guard was not loosened: a request that
  names **no** authority is still refused, and an authority outside `PLUME_HOST` still gets 421 — over
  h2 as over HTTP/1.1 (re-measured). `sso_same_origin_ok`, the second and last reader of `Host`, consumes the
  same source.
- **DB**: **validated read-only** API queries + time budget; **SQLCipher** at rest (`PLUME_DB_KEY`).
- **Tamper-evident integrity**: **hash-chained log** (ledger, `PLUME_LEDGER_KEY`) +
  **Ed25519** checkpoints. A **partial** alteration (one modified/deleted line) breaks the chain and
  is detected by `plume-daemon verify`. **What is NOT covered by default**: verification
  recomputes the chain from the start, so an attacker who obtains **write access to the database AND the signing
  key** can **rewrite the whole log** and re-sign it in a self-consistent way. Closing this
  gap requires **pinning the public key outside the database** through **`PLUME_LEDGER_PUBKEY`** (escrow):
  `verify` then refuses a chain re-signed with another key. **This pin is OFF by default** — without it,
  the property that holds is "tamper-**evident** against a partial alteration", not "tamper-proof".
  AIDE for host file integrity.
- **Response**: actions **delegated** to existing enforcers (CrowdSec/fail2ban/nft), **dry-run by
  default** + **approval** + **allowlist** + trace in the ledger.
- **Hardened container**: non-root, read-only rootfs, `no-new-privileges`, capabilities `drop: ALL`.
- **Self-monitoring**: alert if a collector goes silent (freshness `down`) or if a control
  rule (firewall) disappears.

## 11. Resource budget

| Target | RAM | Swap |
|---|---|---|
| k3s (reference "SMB" profile, SQLCipher) | **on the order of three hundred MiB of RSS measured** · requests 256Mi-768Mi depending on load / **limit 2Gi** | disabled by the orchestrator |
| Container (`docker-compose.yml`) | `mem_limit` — **same figure, 2 GiB**, adjustable through `PLUME_MEM_LIMIT`; `/tmp` bounded (`PLUME_TMP_SIZE`) because a tmpfs is RAM charged to the same cgroup | `memswap_limit` **equal** to `mem_limit` → zero bytes |
| Bare host (systemd) | same binary, same budget: `MemoryMax=2G` / `MemoryHigh=1800M` (see `systemd/plume-daemon.service`). **256 MB and 200 MB OOM-kill the daemon at boot** — do not go below ~512 MB. | **unbounded**: no shipped unit sets `MemorySwapMax=`, so `MemoryMax=` there bounds the RESIDENT set and not the total |

The reference profile is **measured at a few hundred MiB of RSS** on a real installation
(**nearly ten million events in the database, 2 vCPU, memory ceiling 2 GiB, field masking inactive**), and the ceiling
of 2 GiB is **enforced at runtime** in all **three** modes (`limits.memory: 2Gi` on k3s,
`mem_limit` + `memswap_limit` in a container, `MemoryMax=2G` under systemd — the container did not set it,
`P4.14-a`) — but **the same figure is not the same bound in each** (the "Swap" column above), and
**no CI job checks this ceiling**: it is a measurement and a runtime bound, not a guarantee
re-proven at every commit. Consumption depends mostly on **query concurrency**, not on the
size of the database; measure your own footprint and **define your own thresholds**. Available levers:
`MALLOC_ARENA_MAX=2` (bounds glibc arenas) and `PLUME_QUERY_CONCURRENCY` (bounds simultaneous
queries — each one costs RAM). The strategy relies on **per-dimension
rollups** + the **SWR cache** — not on the index alone. CPU: 2 cores are enough.

**`PLUME_FTS_FIELDS` is not a lever of this budget, and yet this document listed it among
them.** *Corrected on 2026-08-30, after rereading the bench and the sources.* No comparable pair of the
bench measures a MEMORY overhead of the `event_fields_fts` vtable: the only pair that shares the
binary, the volume and the database shows a **lower** peak with the capability enabled, and the bench itself
says that this difference cannot be attributed to the flag (each configuration restarts from a fresh
daemon). What is measured is a **DISK** cost — on the order of a tenth of the database extra on
that same pair, on the repository's bench (`docs/BENCHMARK.md`, lever L6) — and what weighs the most cannot
be counted in bytes: **enabling this capability trades search performance for
confidentiality of the backup.** The vtable is declared *contentless* (`content=''`), a form
that the typed backup plan refuses (`collect_dump_plan` → `PlanErr::Unsupported`); the
compressed path then falls back to the historical export, which **rewrites the whole database IN PLAINTEXT** into the
staging directory for the duration of each cycle (`sqlcipher_export`). That — not RAM — is what
justifies the default of `0`, and it is the same explicit trade-off as that of
`PLUME_SQLITE_DEVERSEMENT`. Details: [`docs/CHIFFREMENT-COMPRESSION.md`](docs/CHIFFREMENT-COMPRESSION.md).

**Memory ceiling of a read — and why it is OPT-IN.** A `stats … by` or a `dc()` whose key
is not ordered by an index makes SQLite **sort**. Under `temp_store=MEMORY`, this sort has **no
spill mechanism** — not an overly generous setting, an absence of mechanism: in SQLite,
`sqlite3VdbeSorterInit` only sets `mxPmaSize` if `temp_store=FILE`, and `sqlite3VdbeSorterWrite`
encloses the whole spill computation in `if( mxPmaSize )`. The sorter therefore materialised one
record **per scanned line**. Switching to `temp_store=FILE` makes a ceiling exist. Measured on
3 648 003 events, process RSS peak (fresh daemon per cell, `interactive:true`, average of
2 runs):

| query | `MEMORY` (default) | `FILE` (opt-in) | spilled to disk |
|---|---:|---:|---:|
| `stats count by action,source \| sort -count \| head 50` | 1 134 MiB | **425 MiB** | 676 MiB |
| `stats dc(message)` | 1 106 MiB | **576 MiB** | 797 MiB |
| `stats count by severity` (served by an index) | 309 MiB | 311 MiB | 0 |

**And yet the shipped default remains `MEMORY`.** The 676 and 797 MiB of the last column are
**event values in plaintext**, outside the SQLCipher database: SQLCipher encrypts the *database file*, not
SQLite's temporary files (which is why it itself recommends `temp_store=MEMORY`).
Measured on 2026-08-04: **323 readable occurrences** of two needles from the test fixtures in 16 MiB of
spill file reread, negative control at 0. An encrypted database that leaks its values through the
sorter is not encrypted — **plume does not make this trade on your behalf**. `PLUME_SQLITE_DEVERSEMENT=1`
makes it explicitly, for a deployment whose threat model excludes theft of the volume.

**And once the trade is made, it is BOUNDED.** `PLUME_SQLITE_DEVERSEMENT_QUOTA_MO` (default `1024`,
`0` = no bound) caps the bytes that the **process** holds open under the spill
directory; beyond that, the current statement is stopped and no result is returned — the refusal
NAMES the lever, and [`deploy/PROFILE.md`](deploy/PROFILE.md) as well as the
[README](README.md#configuration--les-variables-plume_) describe what it bounds and what it does not
bound. It bounds neither RAM nor the offending query: the bound applies to what the process
holds, not to what a query writes.

**Consequence, written down so it can be held against us: at the default, a wide enough aggregation still kills the
process.** The path that closes this defect without giving up anything on confidentiality is "fewer bytes to
sort" — compression at rest and native bounded aggregation — not spilling.

What the default still provides: the budget is decided in **a single place**
(`daemon/src/sqlite_plafond.rs`) and **derived** from the existing bounds:
`cache_size = PLUME_SQLITE_BUDGET_MB / (READ_POOL_CAP + PLUME_QUERY_CONCURRENCY +
PLUME_PANEL_REFRESH_CONCURRENCY + 4)`.

> **The constant term is 4, not 2**, and the reason is written in the code: the two connections
> OUTSIDE the pool (the daemon's writer and the rollups' connection, `CONNEXIONS_HORS_POOL = 2`) EACH carry
> a page cache **and** can run a sort — they therefore count in **both** families
> of holders (`porteurs_pour`, `daemon/src/sqlite_plafond.rs`):
> `(READ_POOL_CAP + 2) + (interactif + refresh + 2)`. At the defaults: `(8+2) + (3+2+2) = 17`.
> This page published `+ 2` until 2026-08-06 — that is, 15 holders instead of 17 — while giving
> the right total ("17 holders") in the next sentence. Real consequence, and it is narrower
> than one might fear: the TOTAL budget is still respected since the daemon divides by the
> true count; it is the **per-holder** cache prediction that was wrong, the operator
> expecting ~13 % more than they receive. No additional exposure to OOM.

The default (1088 MiB = 17 holders × 64 MiB) **reproduces
exactly** the old `cache_size=-65536` ⇒ **no behaviour change is shipped**; doubling the read pool
now divides the cache on its own, instead of silently exceeding the budget.

**If you enable spilling, three operational points.** (1) A query that fits under the budget
pays **nothing** (no byte written); one that exceeds it pays in **time**, and that time is a
property of the **storage medium** — `dc(message)` measured at ×1,7 on tmpfs, ×3,4 on btrfs, ×8,6 on a
`fuse.gocryptfs` mount. **The answers are identical** in every configuration measured
(`dc(message)` = 2 234 123 everywhere). (2) The files live in `<répertoire de la base>/sqltmp` with
`0700` and SQLite **unlinks them as soon as they are opened** (so they have no name, and are deleted even if the process dies),
but the bytes do touch the device: point `SQLITE_TMPDIR` to an encrypted medium (it is
honoured if set). (3) Do **not** point it to a tmpfs (`/tmp` is one on most
systemd hosts): that would be RAM charged to the same cgroup, and the ceiling would no longer bound anything.

## 12. Configuration (`PLUME_*` only)

All infrastructure specifics go through `PLUME_*` variables (the old `SOC_*` prefix has been **removed**).
The complete list and the "deploy on any infrastructure" procedure are in
[`deploy/PROFILE.md`](deploy/PROFILE.md); k8s coverage in [`deploy/K8S.md`](deploy/K8S.md).
Essentials: `PLUME_ADDR`, `PLUME_HOST`, `PLUME_USER`/`PLUME_PASS_HASH`, `PLUME_DB`/`PLUME_SPOOL`,
`PLUME_DB_KEY`, `PLUME_CENTRAL`/`PLUME_TOKEN` (agent), `PLUME_SOQL_CORE`, `PLUME_WATCH_STS`,
`PLUME_TLS_CERT`/`PLUME_TLS_KEY`, `PLUME_SSO_HEADER_SECRET`, `PLUME_DEMO`/`PLUME_PUBLIC_DEMO`.

## 13. Portability & multi-host

- **Repository = single source**: `clone` → `bootstrap.sh` (central) / `bootstrap-agent.sh` (agent). Single
  binary, externalised config (`/etc/plume/`), self-adapting collectors (an absent tool is skipped).
- **Roles** (same binary, driven by config): `standalone` (collectors → local daemon → dashboard),
  `agent` (collectors → `ship` to the central, no local dashboard), `central` (receives the agents
  through authenticated `/api/ingest` + its own collectors; the `host` field aggregates all hosts).
- **Agent → central transport**: Bearer **token bound to the host** + **mTLS** (hardened path
  `ingest.example.com`). Internally (in-cluster), agents can push to the ClusterIP
  `<svc>.<ns>.svc:7000` — provided their pod is explicitly allowed in the ingress NetworkPolicy
  (by default it only lets the ingress controller through), and, since that ClusterIP is reached over
  `http://` outside the loopback, provided `PLUME_SHIP_ALLOW_PLAINTEXT=1` is set in the environment file of EACH unit that talks to the
  central: without it `ship.sh` refuses to ship in plaintext (exit 2, spool kept), `respond.sh` executes
  no action, `prom-scrape.sh` scrapes nothing and `engagement-adapter.sh` revokes its exemptions (exit 2).

## 14. Non-functional requirements (reminder)

- **Availability**: decoupled spool (zero loss if the central goes down), `Restart=on-failure`, crash-safe
  WAL, periodic encrypted backup → MinIO (sidecar).
- **Performance / do not overload**: systemd limits (host) / k8s requests-limits; collection by timers
  (no constant polling); query budget + rollups + SWR cache; retention + `VACUUM`.
- **UX / a11y**: dense responsive page, bilingual, semantics + ARIA, severity = icon + text,
  `prefers-reduced-motion` / `prefers-color-scheme`.
- **Maintenance**: collectors = small independent scripts; daemon in modules; versioned
  migrations (`meta.schema_version`); idempotent bootstrap (`git pull → build → bootstrap`); the SOC
  monitors itself.

## 15. Built-in detection engines (pluggable sources)

Plume remains the **brain / single pane**; the engines below are **optional,
config-gated sources**, never imposed:

- **Host EDR/XDR**: `auditd` (executions/accesses) + AIDE (integrity) + SUID/ports/units diff
  (persistence) = endpoint telemetry; our rules = the analytics.
- **CrowdSec**: IDS/IPS + community threat intel; we **ingest** its decisions and **delegate**
  enforcement (responder).
- **Falco / Suricata**: runtime/IDS, ingested as events.
- **Sigma**: vendor-neutral rule format → conversion to the GXQL/SQL engine (build time).
- **YARA / ClamAV**: on-demand file/IOC scan → events/alerts.

All can be **disabled** through config; when absent, they cost nothing.
