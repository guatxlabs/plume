# Plume — Architecture

Plume est un **SOC / XDR feather-light** : **un seul binaire Rust** (`plume-daemon`) qui ingère
logs & métriques, les stocke (SQLite/SQLCipher), et sert l'**API + l'UI web (PWA)** + le **moteur de
détection** sur le port **`:7000`**. Les hôtes/agents poussent leur télémétrie via `POST /api/ingest`.

Le **même** binaire se déploie en **k3s/k8s** (derrière un reverse-proxy + forward-auth SSO), en
**Docker**, ou sur **hôte nu** (systemd). Le moteur est **générique** : rien d'infra-spécifique n'est
codé en dur — tout passe par des variables `PLUME_*` (cf. [`deploy/PROFILE.md`](deploy/PROFILE.md)).
Le compilo de recherche est **partagé** avec le crate public `guatx-core`.

> Documents de référence (tenus à jour) : [`README.md`](README.md) · [`deploy/PROFILE.md`](deploy/PROFILE.md)
> (déployer sur n'importe quelle infra) · [`deploy/K8S.md`](deploy/K8S.md) · [`CAHIER-DES-CHARGES.md`](CAHIER-DES-CHARGES.md).

---

## 1. Objectifs & contraintes

- **Visibilité unifiée** dans une **PWA** (installable, offline) : posture, CVE, firewall,
  durcissement, auth, process (XDR), intégrité fichiers, réseau, conteneurs, k8s, ressources.
- **Recherche type Splunk** sur les logs sans Elastic : un langage **SOQL** (search-like) compilé en
  SQL read-only.
- **Léger par conception** : un binaire `axum` + `rusqlite` (~4 Mo), confortable en peu de RAM.
  Cible host < 128 Mo ; en k3s, l'instance de référence est bornée à 2 Gi (cf. §11).
- **Exposition maîtrisée** : le daemon ne s'expose **jamais** seul sur Internet — il vit derrière une
  chaîne reverse-proxy (Cloudflare → Traefik → Authentik forward-auth), et l'ingest agent passe par
  un chemin **mTLS dédié**. En standalone, bind `127.0.0.1` par défaut + garde `Host` anti-rebinding.
- **Le SOC ne doit pas devenir un trou de sécu** → séparation de privilèges + durcissement (cf. §10).

## 2. Principes de conception

1. **Pull léger, pas d'agents lourds.** Les capteurs sont de petits jobs **shell** (ou 1 binaire Rust
   pour le mail) déclenchés par des **timers systemd par-collecteur** (`plume-*.timer`).
2. **Daemon non privilégié.** `plume-daemon` ne tourne **jamais** en root (user `soc` / uid `10001`)
   et n'exécute **aucune** commande privilégiée à la demande.
3. **Spool découplé.** Collecteurs → fichiers JSON dans un **spool** → expédiés par `ship.sh` →
   `/api/ingest` → tables SQLite. Si le central tombe, le spool tampon → rattrapage (zéro perte).
4. **Tout auditable.** Capteurs en shell lisible (un pro doit pouvoir les relire).
5. **Diff & baseline.** Beaucoup de détection = comparer l'état courant à une baseline (ports, SUID,
   units, hashs, image digests).
6. **Générique + config.** Aucun nom d'app / namespace / IP en dur dans la logique : le spécifique-infra
   vit dans des variables `PLUME_*` (env / `EnvironmentFile` / env du Deployment). Chaque collecteur est
   un **plugin auto-détecté** qui s'éteint proprement si l'outil/log est absent, **OFF par défaut**.

## 3. Vue d'ensemble

```
  AGENTS host (sh + systemd, OFF par défaut)                    CENTRAL = 1 binaire `plume-daemon`
  ┌──────────────────────────────────────┐                     ┌─────────────────────────────────┐
  │ collecteurs bash  collectors/*.sh     │   mTLS + Bearer     │ axum (API + ServeDir PWA) :7000 │
  │  resources integrity firewall controls│  POST /api/ingest   │ rusqlite (SQLite/SQLCipher)     │
  │  conntrack auditd kube-state pod-logs …│ ─────────────────► │  event / metric / snapshot      │
  │  collector-mail (binaire Rust)        │                     │  + FTS5 + rollups (pré-agrégé)  │
  │  spool /var/lib/plume/spool           │                     │  parsers · règles · playbooks   │
  │  ship.sh  ·  respond.sh (pull)        │ ◄── /api/actions ── │  SOQL (compilo guatx-core)      │
  └──────────────────────────────────────┘   (responder pull)  └─────────────────────────────────┘
                                                                          ▲ :7000 (ClusterIP)
   Navigateur ──► Cloudflare (tunnel) ──► Traefik ──► Authentik forward-auth ──► daemon (UI)
   Agent      ──► ingest.example.com:443 (Traefik websecure, mTLS RequireAndVerifyClientCert) ──┘
```

Le central **est aussi son propre agent** : sur l'hôte k3s, des collecteurs host (kube-state,
pod-logs, mail…) poussent dans le même daemon. Une **NetworkPolicy d'ingress** (à poser dans votre
dépôt GitOps) restreint l'accès à `:7000` au **seul** reverse-proxy (sélecteur = le namespace et le
label de VOTRE ingress controller) — aucun autre pod ne peut atteindre le daemon en direct
(anti-forge des en-têtes SSO).

## 4. Composants

### 4.1 `plume-daemon` — le binaire unique (central)

- **Crate** `daemon/` (`plume-daemon`, `axum` 0.7 + `tokio` + `tower-http`). DB via `rusqlite` avec
  la feature `bundled-sqlcipher-vendored-openssl` → **SQLite chiffré (SQLCipher) at-rest** si
  `PLUME_DB_KEY` est posé (sinon base en clair). WAL + FTS5.
- **Sert trois choses sur le même port `:7000`** : l'**API** (`/api/*`), l'**UI web** (assets statiques
  via `tower_http::ServeDir` depuis `PLUME_WEB=/usr/local/share/plume/web`), et l'**ingestion**
  (`/api/ingest`, `/api/ingest/journal`, `/api/ingest/minio`, `/api/metrics/*`, `/loki/api/v1/push`).
- **Compilo SOQL délégué à `guatx-core`** : `daemon/Cargo.toml` dépend de `guatx-core` via une
  **git-dep publique épinglée** (cf. §4.1 « Image »).
  Le toggle **`PLUME_SOQL_CORE`** (lu au boot) a 3 états : `off` (compilo Plume historique), `shadow`
  (double-compile Plume+core, journalise les écarts, **sert l'ancien**), `on` (sert le SQL de
  `guatx_core::soql::to_sql(...)`). **Recommandé : `on`.**
- **Sous-commandes CLI** : `hashpw '<mdp>'` (génère le hash argon2id), `token <nom> [hôte]` (minte un
  token d'agent lié à un hôte), `backup <fichier>` (`VACUUM INTO` — copie **chiffrée** car SQLCipher).
- **Config** : **`PLUME_*` uniquement** (l'ancien préfixe `SOC_*` n'existe plus). En conteneur,
  `PLUME_CONFIG=/nonexistent` → config purement par env ; sur hôte, l'unit lit `PLUME_CONFIG=/etc/plume/soc.conf`.
- **Image** : `Dockerfile` multi-stage. **Contexte de build = la racine de ce dépôt** (clone
  standalone) : `guatx-core` est résolu via une git-dep publique (tag `v0.2.0`, récupérée au build),
  `../../db/schema.sql` est copié depuis `db/` sibling de `daemon/`. Runtime `debian:bookworm-slim`,
  **non-root** (uid `10001`), assets web en `a+rX`. Build : `docker build -t soc:latest .` depuis la racine.

### 4.2 Agents host — collecteurs bash + timers par-collecteur

- **Collecteurs** : `collectors/*.sh` (un script auto-détecté par source). Socle toujours installé :
  `resources`, `integrity`, `ship`. Plugins **OFF par défaut**, opt-in via `PLUME_EXTRA_COLLECTORS` :
  `firewall controls conntrack nft ufw auditd containerd clamav suricata falco crowdsec bans
  kube-state kube-audit kube-rbac pod-logs prom-scrape vuln imgdrift mail dataaccess dataacl audit web
  custom` …
- **Un timer systemd par collecteur** : `plume-<nom>.timer` → `plume-<nom>.service` (oneshot root
  durci) écrit dans le **spool** `/var/lib/plume/spool`. Cadences propres à chaque source (ex.
  `plume-auditd.timer` `OnUnitActiveSec=2min`, `plume-ship.timer` 30 s). **Il n'existe AUCUN timer
  `fast/mid/daily`** — chaque collecteur a son timer.
- **`ship.sh`** : pousse le spool vers le central — `*.json` → `POST /api/ingest`, `*.ndjson`
  (journald brut sshd/sudo/su) → `POST /api/ingest/journal`. Auth = **Bearer `PLUME_TOKEN`**
  (recommandé) ou Basic ; **mTLS** si `PLUME_TLS_CACERT/CERT/KEY` posés. Un fichier accepté (HTTP 202)
  est supprimé ; sinon conservé pour réessai.
- **`collector-mail/`** : **binaire Rust** `plume-collector-mail` (opt-in `PLUME_WITH_MAIL=1`),
  détection mail host-native (docker-mailserver / k3s), via `plume-collector-mail.timer`.
- **`respond.sh`** (responder, opt-in `PLUME_WITH_RESPONDER=1`) : modèle **pull** (aucune entrée
  réseau sur l'agent) — `plume-respond-agent.timer` tire `/api/actions/pending`, applique les
  bans/unbans en **déléguant** à CrowdSec → fail2ban → nft, **dry-run par défaut** (`PLUME_RESPONDER_APPLY=0`)
  + allowlist `/etc/plume/responder.allow`. Token **lié à l'hôte** (anti-IDOR).
- **`minio-audit-relay.py`** (opt-in) : récepteur webhook MinIO (audit objet) → spool → `ship.sh`.
- **Installation** : `bootstrap.sh` (central host) / `bootstrap-agent.sh` (agent). Arborescence host :
  binaire `/usr/local/bin/plume-daemon`, collecteurs `/usr/local/lib/plume/collectors/`, config
  `/etc/plume/` (`plume.conf`, `soc.conf`, `mail.conf`, `responder.conf`, `inputs.d/*.input`),
  données `/var/lib/plume/` (`spool/`, `state/`, `db/`). **Inputs custom** (scripted inputs) :
  `custom.sh` lit `/etc/plume/inputs.d/*.input` → toute source devient des events **sans code**.

### 4.3 Chaîne d'exposition (k3s)

Ci-dessous une **recette de référence** (ingress controller + forward-auth SSO + PKI interne) ; les
objets d'ingress vivent dans **votre dépôt GitOps**, sous les noms de votre choix. Toute chaîne
équivalente convient — le daemon ne dépend d'aucune.

- **UI navigateur** : `plume.example.com` → (optionnel) **tunnel** → **ingress controller** (entrypoint
  HTTP) → middlewares *redirection + en-têtes HTTPS*, ***forward-auth SSO***, *injection du secret
  d'en-tête SSO* → Service `plume:7000`. Le shell PWA (`/sw.js`, `/manifest.webmanifest`) est servi
  **sans** forward-auth (sinon le SW se fait 403).
- **Ingest agent durci (mTLS)** : `ingest.example.com:443` → entrypoint HTTPS → une **option TLS**
  exigeant **`RequireAndVerifyClientCert`** (PKI interne, p. ex. cert-manager) → daemon,
  **uniquement** les paths agent (`/api/ingest`, `/api/metrics`, `/api/actions/pending|result`,
  `/loki/`). L'agent résout `ingest.example.com` → `127.0.0.1` (`/etc/hosts`) et présente son cert
  client + Bearer. **N'exposez pas de route agent en clair Bearer-seul** sur l'hôte de l'UI : le
  chemin agent doit rester le chemin mTLS dédié.
- **NetworkPolicy d'ingress** : `ingress`-only, **seul** l'ingress controller (son namespace + son
  label) → `:7000`. Mitigation effective de la confiance aux en-têtes SSO
  (un pod compromis ne peut plus atteindre `:7000` pour forger un en-tête).

## 5. Capteurs (tier « Complet / XDR »)

| Domaine | Collecteur | Source / outil | Sortie |
|---|---|---|---|
| **CVE / vuln** | `vuln.sh` | scanner CVE paquets/images | snapshot + alerte |
| **Firewall** | `firewall.sh` `nft.sh` `ufw.sh` | `nft -j list ruleset`, ufw | snapshot + compteurs ; alerte si la règle de contrôle disparaît |
| **Durcissement** | `controls.sh` | sysctl / `/proc/cmdline` / lockdown | score + dérive |
| **Auth / identité** | `journal.sh` `audit.sh` | journald (sshd/sudo/su/faillock/polkit) | events `.ndjson` + FTS |
| **Exécution (XDR)** | `auditd.sh` | **auditd** (execve, setuid, accès `/etc/shadow`,`~/.ssh`,`sudoers.d`) | events + alertes |
| **Intégrité fichiers** | `integrity.sh` | **AIDE** sur chemins sensibles | alerte sur changement |
| **Réseau** | `conntrack.sh` | conntrack (flux ext/int/loopback) | events + diff |
| **Conteneurs** | `containerd.sh` `imgdrift.sh` | containerd / dérive de digests d'images | nouveaux ports / dérive image |
| **Antimalware** | `clamav.sh` | ClamAV | matches |
| **IDS** | `suricata.sh` `falco.sh` | Suricata `eve.json` / Falco | events |
| **CTI / bans** | `crowdsec.sh` `bans.sh` | CrowdSec LAPI / fail2ban | décisions/alertes |
| **Kubernetes** | `kube-state.sh` `pod-logs.sh` `kube-audit.sh` `kube-rbac.sh` | `kubectl` (state, logs, audit, RBAC) | metrics `kube_*` + events |
| **Métriques tierces** | `prom-scrape.sh` | scrape Prometheus exposé | metrics |
| **Stockage objet** | `minio.sh` `minio-audit-relay.py` | MinIO + audit webhook | accès objet |
| **Données** | `dataaccess.sh` `dataacl.sh` | accès/ACL fichiers | events |
| **Mail** | `collector-mail` (Rust) `mail.sh` | maildir / docker-mailserver | events mail |
| **Ressources** | `resources.sh` | `/proc` (cpu/mem/PSI), disque, smart | métriques + alertes (OOM, disque, SSD) |
| **Custom** | `custom.sh` | `/etc/plume/inputs.d/*.input` | toute source, sans code |

Toujours **OFF par défaut** sauf le socle `resources`/`integrity` ; chaque plugin se désactive seul si
l'outil ou le log est absent.

## 6. Flux d'ingestion & stockage (SQLite/SQLCipher, WAL + FTS5)

Schéma : `db/schema.sql` (embarqué via `include_str!`), migrations versionnées (`meta.schema_version`,
**actuellement v51**) dans `migrate()`. Tables :

```sql
event(id, ts, source, category, severity, host, message, fields/*json*/)   -- + event_fts (FTS5)
metric(ts, name, labels/*json*/, value)
snapshot(ts, kind, data/*json*/)        baseline(key, value/*json*/, updated)
alert(id, ts, rule, severity, title, detail, status, acked_at)
dashboard(...)  panel(...)  rule(...)   -- + users, tokens, playbooks, cases, notifiers, ledger…
```

- **Pipeline** : collecteur → enveloppe JSON dans le spool → `ship.sh` → `POST /api/ingest` (réponse
  **202**) → normalisation (timestamp epoch, sévérité 0-4, mapping source) → INSERT idempotent (dédup).
  Le journald brut va sur `/api/ingest/journal` (parsing **côté daemon**, sans `jq` côté agent).
- **Registre de parsers** : après insertion, les **parsers** (gérés dans l'UI) enrichissent les
  events en champs groupables (`fields`). Reparse possible (`/api/parsers/reparse`).
- **Rollups (pré-agrégation)** : pour éviter de re-balayer la table d'events à chaque panneau,
  `event_rollup` (cappe `src_ip` en top-N par bucket, le reste lumpé puis ré-agrégé = jamais perdu) et
  **`event_dim_rollup`** (cappe **chaque dimension** au top-N par bucket, `PLUME_ROLLUP_DIM_TOPN`).
  Rafraîchis périodiquement (`PLUME_ROLLUP_INTERVAL_S`) + backfill incrémental.
- **Rétention** : `PLUME_RETENTION_DAYS` (events, déf. 30), `PLUME_METRIC_DAYS`, `PLUME_SNAPSHOT_DAYS`,
  `PLUME_ALERT_DAYS`, downsample des métriques (`PLUME_METRIC_RAW_HOURS`), purge + `VACUUM`.

## 7. Requête (SOQL) & moteur de détection

- **SOQL → SQL read-only** : `search source=sshd "failed" | stats count by user` est compilé en SQL
  validé (`guatx-core` quand `PLUME_SOQL_CORE=on`). Connexion **read-only**, **un seul** `SELECT`/`WITH…SELECT`
  (rejet des `;`, `pragma/attach/insert/update/delete/drop`), `LIMIT` forcé (`PLUME_QUERY_MAX`,
  `PLUME_SEARCH_LIMIT/MAX`).
- **Budget & annulation** : chaque requête a un budget temps (`PLUME_QUERY_BUDGET_MS`, variante
  interactive) + **watchdog** d'interruption ; les requêtes interactives portent un **`qid`** et
  `POST /api/cancel` les interrompt. Concurrence bornée par un sémaphore (`PLUME_QUERY_CONCURRENCY`,
  déf. 3 ; partagé `/api/query` + `/api/search` + data de panneau).
- **Rollup-route** : un SOQL au **motif exact** (`… | stats count by source`, `search source=X | stats
  count by <dim>`) est réécrit vers `event_rollup`/`event_dim_rollup` → réponse en quelques ms.
- **Cache SWR des panneaux** : `panel_cache` + classification **adaptative LIVE/SWR par coût mesuré**
  (`panel_cost`, migration v46) — un panneau rapide est servi LIVE, un panneau coûteux passe en
  **stale-while-revalidate** (TTL `PLUME_PANEL_CACHE_TTL`), avec **anti-stampede** (un seul refresh
  async en vol par clé, sur un sémaphore dédié `PLUME_PANEL_REFRESH_CONCURRENCY` — il ne vole jamais
  un permis à l'interactif). Carte **Source freshness** = état de COLLECTE par source (fresh/quiet/down).
- **Règles de détection** : seedées au boot (`seed_detection_rules`, repro sur PVC neuf) **et** posées
  sur les instances existantes par les **migrations** (jusqu'à v51 : règles CF, brute-force,
  minio backup-delete, auditd tamper, intégrité SUID/persistance, conntrack beaconing, vault
  secret-read, self-detection brute-force de l'auth Plume…). Deux familles : **requête** (SOQL/SQL +
  seuil) et **diff** (snapshot vs baseline). Une règle qui matche → INSERT `alert` (+ sévérité) →
  **notifiers** (ntfy via `PLUME_NOTIFY_NTFY_URL`, seuil `PLUME_NOTIFY_MIN_SEV`). **Playbooks**
  (SOAR-lite) + **cases** (incidents) pour la suite.

## 8. Frontend (PWA)

- **Vanilla JS, sans étape de build** : assets statiques dans `web/`, servis par `ServeDir` du daemon
  (`PLUME_WEB`). PWA installable (manifest + service worker, shell offline). **Bilingue FR/EN** + tous
  les fuseaux IANA.
- **Page dense** (dark, a11y) : bandeau alertes → posture/score → panneaux (firewall, durcissement,
  auth, process/auditd, intégrité, réseau, conteneurs, k8s, ressources, freshness…), barre de
  recherche (SOQL/FTS) + plages de temps, **Explore**, **dashboards** & **panneaux** sauvegardés
  (query-driven), **règles**, **parsers**, **cases**, **actions/playbooks**, **users** (RBAC).
- Le shell PWA est servi **hors forward-auth** ; les données restent gatées (Authentik + auth Plume).

## 9. Déploiement

Trois cibles, **même binaire** (mode-aware) :

- **Docker** : `docker-compose.yml` (context parent `..`, dépend de `core/`). `hashpw` → `.env`
  (`PLUME_PASS_HASH`) → `docker compose up`. `PLUME_DEMO=1` peuple des données de démo.
- **Hôte nu (systemd)** : `bootstrap.sh` (central) installe le binaire + `plume-daemon.service`
  (`User=soc`, durci : `NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet=`,
  `MemoryMax=2G`, `ReadWritePaths=/var/lib/plume/db /var/lib/plume/spool`, bind `127.0.0.1:7000`).
  `bootstrap-agent.sh` installe un **agent** (collecteurs + `ship`, pas de daemon/DB/web).
- **k3s** : manifeste générique [`deploy/k3s.yaml`](deploy/k3s.yaml) (Namespace + Secret + PVC +
  Deployment + Service + Ingress). Un déploiement de **production** type (à porter dans **votre dépôt
  GitOps**, piloté par ArgoCD/Flux ou équivalent) ajoute :
  - **Deployment** — `replicas: 1`, **`strategy: Recreate`** (PVC RWO +
    SQLite = un seul writer, pas de rolling). `securityContext` non-root uid `10001`,
    `readOnlyRootFilesystem`, `drop: [ALL]`, `seccomp RuntimeDefault`.
  - **initContainer** optionnel qui dépose un client objet (`mc`, `aws`…) dans un emptyDir partagé.
  - Conteneur **`plume`** (image **pinnée par digest/SHA** — bump après build) + **sidecar
    `backup`** (même image ; `plume-daemon backup` = `VACUUM INTO` **chiffré** → copie vers
    `<votre-bucket>/plume/` ; remplace Litestream, incompatible SQLCipher).
  - **Env `PLUME_*` uniquement** : `PLUME_ADDR=0.0.0.0:7000`,
    `PLUME_HOST=plume.example.com,ingest.example.com` (multi-hôte : navigateur + SNI mTLS),
    `PLUME_DB=/data/plume.db`, `PLUME_SPOOL=/data/spool`, `PLUME_LEDGER_KEY=/data/ledger.key`,
    `PLUME_SOQL_CORE=on`, `PLUME_WATCH_STS="<ns>/<sts> <ns>/<sts>"` (vos apps critiques ; défaut
    **vide**, cf. [`deploy/PROFILE.md`](deploy/PROFILE.md)), + tuning RAM (cf. §11).
  - **Secrets** (idéalement via un gestionnaire de secrets → ExternalSecrets, `optional:true`),
    un par rôle : `<secret-auth>` (`PLUME_USER`/`PLUME_PASS_HASH` — absents ⇒ **mode SETUP**, token
    d'install dans les logs), `<secret-db-key>` (`PLUME_DB_KEY`, chiffrement SQLCipher),
    `<secret-sso>` (`PLUME_SSO_HEADER_SECRET`), `<secret-notify>` (token du notifier).
  - **PVC** (RWO), **Service** ClusterIP `:7000`, **sondes TCP** sur `:7000` (pas
    httpGet : tout est gaté par l'auth → 401 ⇒ jamais ready).

## 10. Modèle de sécurité du SOC lui-même

> Un SOC agrège des logs et tourne un web : on le verrouille.

- **Auth** : argon2id (repli bcrypt) + **RBAC** (viewer / editor / admin). Sans hash → **mode SETUP**
  (token unique imprimé, assistant web). **SSO délégué** : derrière le forward-auth Authentik, Traefik
  injecte `X-authentik-username/groups` **+ un secret partagé** `X-PLUME-SSO-Secret` ; le daemon ne lit
  ces en-têtes **que** si `PLUME_SSO_HEADER_SECRET` correspond exactement (mapping groupes →
  `PLUME_SSO_GROUP_ADMIN/EDITOR/SUPERADMIN`). Sans le bon secret, aucun en-tête forgé n'accorde de
  privilège — et la NetworkPolicy empêche tout pod d'atteindre `:7000` pour tenter la forge.
- **Garde `Host` (anti-DNS-rebinding)** : `host_guard` n'accepte que `PLUME_HOST` (liste multi-hôte) +
  loopback ; sinon **421 Misdirected Request**. `PLUME_HOST_STRICT=1` retire l'auto-allow loopback
  (standalone exposé).
- **Anti-brute-force** : compteur d'échecs Basic par `(user, src_ip)` → backoff exponentiel + **lockout**
  (`PLUME_AUTH_LOCK_*`, 429 + `Retry-After`) **avant** argon2 (économie CPU). Chaque échec/lockout est
  **auto-ingéré comme event SIEM** (`source=plume-auth`) → une règle de **self-detection** (v51, T1110)
  alerte sur une rafale contre l'auth de Plume. La src_ip n'utilise **pas** `X-Forwarded-For` (spoofable).
- **Rate-limit** : par IP source (`PLUME_RL_IP_MAX`) + plafond global (`PLUME_RL_GLOBAL_MAX`) + cap
  durci sur les routes d'auth (`PLUME_RL_AUTH_MAX`) → 429.
- **Tokens d'agent** : Bearer, SHA-256 en base, **liés à un hôte** → un agent ne peut agir (responder)
  que sur les actions de **son** hôte. Ingest agent durci par **mTLS** (cert-manager, SNI dédié).
- **TLS natif config-gated** : si `PLUME_TLS_CERT` + `PLUME_TLS_KEY` sont posés, le listener sert en
  **HTTPS (rustls/ring)** + HSTS ; sinon HTTP (défaut, derrière Traefik). Provider `ring` (pas
  d'aws-lc-rs : évite cmake/nasm).
- **DB** : requêtes API **read-only validées** + budget temps ; **SQLCipher** at-rest (`PLUME_DB_KEY`).
- **Intégrité tamper-evident** : **journal à chaîne de hash** (ledger, `PLUME_LEDGER_KEY`) +
  checkpoints **Ed25519** → toute altération casse la chaîne. AIDE pour l'intégrité fichiers hôte.
- **Réponse** : actions **déléguées** aux enforcers existants (CrowdSec/fail2ban/nft), **dry-run par
  défaut** + **approbation** + **allowlist** + trace au ledger.
- **Conteneur durci** : non-root, rootfs read-only, `no-new-privileges`, capabilities `drop: ALL`.
- **Auto-surveillance** : alerte si un collecteur se tait (freshness `down`) ou si une règle de
  contrôle (firewall) saute.

## 11. Budget ressources

| Cible | RAM |
|---|---|
| Daemon (Rust) host | ~15-30 Mo |
| Host (cible générale) | < 128 Mo |
| k3s / conteneur (profil de référence « SMB », SQLCipher) | requests 256Mi-768Mi selon la charge / **limit 2Gi** |

Le profil de référence est dimensionné pour **tenir dans 2 Gi** quel que soit le volume ingéré (la
consommation dépend surtout de la **concurrence de requêtes**, pas de la taille de la base) ; mesurez
votre propre empreinte et **définissez vos propres seuils**. Leviers disponibles :
`MALLOC_ARENA_MAX=2` (borne les arènes glibc), `PLUME_QUERY_CONCURRENCY` (borne les requêtes
simultanées — chacune coûte de la RAM), `PLUME_FTS_FIELDS=0` (défaut : pas de vtable
`event_fields_fts`, la plus grosse économie disponible). La stratégie tient aux **rollups
par-dimension** + au **cache SWR** — pas à l'index seul. CPU : 2 cœurs suffisent.

## 12. Configuration (`PLUME_*` uniquement)

Tout le spécifique-infra passe par des variables `PLUME_*` (l'ancien préfixe `SOC_*` a été **retiré**).
La liste complète et la procédure « déployer sur n'importe quelle infra » sont dans
[`deploy/PROFILE.md`](deploy/PROFILE.md) ; couverture k8s dans [`deploy/K8S.md`](deploy/K8S.md).
Essentiels : `PLUME_ADDR`, `PLUME_HOST`, `PLUME_USER`/`PLUME_PASS_HASH`, `PLUME_DB`/`PLUME_SPOOL`,
`PLUME_DB_KEY`, `PLUME_CENTRAL`/`PLUME_TOKEN` (agent), `PLUME_SOQL_CORE`, `PLUME_WATCH_STS`,
`PLUME_TLS_CERT`/`PLUME_TLS_KEY`, `PLUME_SSO_HEADER_SECRET`, `PLUME_DEMO`/`PLUME_PUBLIC_DEMO`.

## 13. Portabilité & multi-hôte

- **Repo = source unique** : `clone` → `bootstrap.sh` (central) / `bootstrap-agent.sh` (agent). Binaire
  unique, config externalisée (`/etc/plume/`), collecteurs auto-adaptatifs (un outil absent se skip).
- **Rôles** (même binaire, piloté par config) : `standalone` (collecteurs → daemon local → dashboard),
  `agent` (collecteurs → `ship` vers le central, pas de dashboard local), `central` (reçoit les agents
  via `/api/ingest` authentifié + ses propres collecteurs ; le champ `host` agrège tous les hôtes).
- **Transport agent → central** : Bearer **token lié à l'hôte** + **mTLS** (chemin durci
  `ingest.example.com`). En interne (in-cluster), les agents peuvent pousser au ClusterIP
  `<svc>.<ns>.svc:7000` — à condition d'ouvrir explicitement leur pod dans la NetworkPolicy d'ingress
  (par défaut elle ne laisse passer que l'ingress controller).

## 14. Exigences non-fonctionnelles (rappel)

- **Disponibilité** : spool découplé (zéro perte si le central tombe), `Restart=on-failure`, WAL
  crash-safe, backup chiffré périodique → MinIO (sidecar).
- **Perf / ne pas surcharger** : limites systemd (host) / requests-limits k8s ; collecte par timers
  (pas de polling constant) ; budget de requête + rollups + cache SWR ; rétention + `VACUUM`.
- **UX / a11y** : page dense responsive, bilingue, sémantique + ARIA, sévérité = icône + texte,
  `prefers-reduced-motion` / `prefers-color-scheme`.
- **Maintenance** : collecteurs = petits scripts indépendants ; daemon en modules ; migrations
  versionnées (`meta.schema_version`) ; bootstrap idempotent (`git pull → build → bootstrap`) ; le SOC
  s'auto-monitore.

## 15. Moteurs de détection intégrés (sources pluggables)

Plume reste le **cerveau / single-pane** ; les moteurs ci-dessous sont des **sources optionnelles,
config-gated**, jamais imposées :

- **EDR/XDR host** : `auditd` (exécutions/accès) + AIDE (intégrité) + diff SUID/ports/units
  (persistance) = télémétrie endpoint ; nos règles = l'analytique.
- **CrowdSec** : IDS/IPS + threat-intel communautaire ; on **ingère** ses décisions et on **délègue**
  l'enforcement (responder).
- **Falco / Suricata** : runtime/IDS, ingérés en events.
- **Sigma** : format de règles vendor-neutre → conversion vers le moteur SOQL/SQL (build-time).
- **YARA / ClamAV** : scan fichiers/IOC à la demande → events/alertes.

Tous **désactivables** par config ; absents, ils ne coûtent rien.
