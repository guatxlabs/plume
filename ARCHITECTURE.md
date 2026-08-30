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
- **Recherche type Splunk** sur les logs sans Elastic : un langage **GXQL** (search-like) compilé en
  SQL read-only.
- **Léger par conception** : un binaire `axum` + `rusqlite` (~4 Mo), confortable en peu de RAM.
  Le profil de référence **mesure de l'ordre de trois cents Mio de RSS** et est borné à **2 Gi** (host comme k3s) — cf. §11
  pour les conditions de mesure et la réserve (aucune garde CI ne défend ce plafond).
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
  │  ship.sh  ·  respond.sh (pull)        │ ◄── /api/actions ── │  GXQL (compilo guatx-core)      │
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
- **Compilo GXQL délégué à `guatx-core`** : `daemon/Cargo.toml` dépend de `guatx-core` via une
  **git-dep publique épinglée** (cf. §4.1 « Image »).
  Le toggle **`PLUME_SOQL_CORE`** (lu au boot) a 3 états : `off` (compilo Plume historique), `shadow`
  (double-compile Plume+core, journalise les écarts, **sert l'ancien**), `on` (sert le SQL de
  `guatx_core::soql::to_sql(...)`). **Recommandé : `on`.**
- **Sous-commandes CLI** : `hashpw '<mdp>'` (génère le hash argon2id), `token <nom> [hôte]` (minte un
  token d'agent lié à un hôte), `backup <fichier>` (`VACUUM INTO` — copie **chiffrée** car SQLCipher)
  et `backup --compress <fichier>` (`age(zstd(...))`, ~5-10x plus petit, **mais via un export en clair
  temporaire sur disque** — cf. deploy/CONFIDENTIALITE.md).
- **Config** : **`PLUME_*` uniquement** (l'ancien préfixe `SOC_*` n'existe plus). En conteneur,
  `PLUME_CONFIG=/nonexistent` → config purement par env ; sur hôte, l'unit lit `PLUME_CONFIG=/etc/plume/soc.conf`.
  **Une seule voie de lecture** : `cfg()` → `env > fichier PLUME_CONFIG > défaut`. Un réglage lu par
  `std::env::var` échappe au fichier et n'a donc d'effet qu'en conteneur — c'est le défaut P8.7-a, qui a
  annulé en silence un destinataire d'escrow de sauvegarde sur hôte. La partition est tenue fermée par un
  scanner de sources (`tests/partition_config.rs`) : il dérive qui lit l'environnement, y compris via une
  fonction intermédiaire, et refuse toute variable nouvelle qui ne soit pas inscrite au registre de dette.
  Ce registre n'a le droit que de rétrécir. `plume-daemon.service` **ne porte volontairement pas**
  d'`EnvironmentFile` : il exporterait `PLUME_PASS_HASH`/`PLUME_DB_KEY` dans `/proc/<pid>/environ`.
  **P8.7-b (2026-08-09)** a réglé le pire cas de cette partition : `PLUME_DB_KEY` était lue par les
  DEUX voies, qui ne s'accordaient pas — l'ouverture de la base par `env::var` seul, le tier froid par
  `cfg()`. Une clé écrite dans `soc.conf` chiffrait donc la moitié FROIDE et laissait la moitié CHAUDE
  en clair, en silence (reproduit sur les octets : `age-encryption.org/v1` d'un côté,
  `SQLite format 3\0` de l'autre). `crypto::db_key_depuis(conf)` est désormais la voie unique, et
  `cold_store` l'appelle au lieu d'avoir la sienne.
- **Image** : `Dockerfile` multi-stage. **Contexte de build = la racine de ce dépôt** (clone
  standalone) : `guatx-core` est résolu via une git-dep publique dont le TAG est épinglé dans
  `daemon/Cargo.toml` (l'écrire ici en ferait une seconde copie qui vieillit — `grep -n 'guatx-core' daemon/Cargo.toml`),
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
  + **liste d'épargne** `PLUME_RESPONDER_ALLOW` (défaut `/etc/plume/responder-ban-exempt.allow` sur une
  installation neuve). Token **lié à l'hôte** (anti-IDOR).
  ⚠️ **Deux politiques, deux fichiers, deux lecteurs — et ils ne se recouvrent pas** (`P4.7-a`/`P4.7-b`) :
  ce fichier-ci porte des **adresses à ne jamais bannir**, lues par `is_ip` (shell) ; le démon lit
  `PLUME_STOP_SERVICE_ALLOW` (même chemin historique `/etc/plume/responder.allow`) comme des **noms de
  service** autorisés pour `stop_service`. Les deux prédicats **ne sont pas égaux** : ce qui est tenu,
  et mesuré sur les deux lecteurs, est que le démon reconnaît comme adresse **strictement plus** de
  formes que l'agent — donc aucune ligne n'est acceptée en silence par les deux. Voir l'encadré du
  README et `collectors/predicat-adresse.corpus`.
  ⚠️ `P4.7-c`, **ouverte** : le responder du **central** ne lit **aucune** liste d'épargne.
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
  **L'idempotence suppose que l'émetteur fournisse une clé `dedup`** (l'agent le fait ; `__CURSOR` pour
  journald). Une surface dont le protocole ne porte **aucun identifiant par entrée** — c'est le cas du
  **push Loki** — est **at-least-once** : `dedup` y est NULL, donc l'index unique partiel ne s'applique
  pas. C'est délibéré : une clé dérivée du CONTENU ferait disparaître en silence des lignes identiques
  légitimement répétées, transformant un doublon visible en perte invisible.
  Le journald brut va sur `/api/ingest/journal` (parsing **côté daemon**, sans `jq` côté agent).
- **Registre de parsers** : après insertion, les **parsers** (gérés dans l'UI) enrichissent les
  events en champs groupables (`fields`). Reparse possible (`/api/parsers/reparse`).
- **Rollups (pré-agrégation)** : pour éviter de re-balayer la table d'events à chaque panneau,
  `event_rollup` (cappe `src_ip` en top-N par bucket, le reste lumpé puis ré-agrégé = jamais perdu) et
  **`event_dim_rollup`** (cappe **chaque dimension** au top-N par bucket, `PLUME_ROLLUP_DIM_TOPN`).
  Rafraîchis périodiquement (`PLUME_ROLLUP_INTERVAL_S`) + backfill incrémental.
  **Chacun PUBLIE ce qu'il couvre**, et aucune route ne lit au-delà : `event_rollup` publie sa borne
  (`RollupCoverage`) et REconstruit les bandes où une ligne est arrivée en retard ; `event_dim_rollup`
  entretient une **bande** qui monte, descend (`PLUME_ROLLUP_DIM_BACKFILL` par tick, jusqu'au plus vieux
  `ts` d'`event`) et se rétracte sur une écriture rétro-datée. Couverture non publiée → la route
  **décline** et le scan brut sert. Voir `daemon/src/rollup_coverage.rs` pour la mesure qui a motivé les
  deux (un sous-compte ×6,6 servi comme exact ; un `0` de couverture servi comme un `0` de données).
- **Rétention** : `PLUME_RETENTION_DAYS` (events, déf. 30), `PLUME_METRIC_DAYS`, `PLUME_SNAPSHOT_DAYS`,
  `PLUME_ALERT_DAYS`, downsample des métriques (`PLUME_METRIC_RAW_HOURS`), purge + `VACUUM`.

## 7. Requête (GXQL) & moteur de détection

- **GXQL → SQL read-only** : `search source=sshd "failed" | stats count by user` est compilé en SQL
  validé (`guatx-core` quand `PLUME_SOQL_CORE=on`). Connexion **read-only**, **un seul** `SELECT`/`WITH…SELECT`
  (rejet des `;`, `pragma/attach/insert/update/delete/drop`), `LIMIT` forcé (`PLUME_QUERY_MAX`,
  `PLUME_SEARCH_LIMIT/MAX`).
- **Budget & annulation** : chaque requête a un budget temps (`PLUME_QUERY_BUDGET_MS`, variante
  interactive) + **watchdog** d'interruption ; les requêtes interactives portent un **`qid`** et
  `POST /api/cancel` les interrompt. Concurrence bornée par un sémaphore (`PLUME_QUERY_CONCURRENCY`,
  déf. 3 ; partagé `/api/query` + `/api/search` + data de panneau).
- **Rollup-route** : un GXQL au **motif exact** (`… | stats count by source`, `search source=X | stats
  count by <dim>`, `count by source,severity`) est réécrit vers les compteurs **pré-agrégés**
  d'`event_rollup`/`event_dim_rollup` → réponse en quelques millisecondes **parce qu'elle ne lit pas les
  events brutes** : les 92 panneaux semés répondent en **quelques millisecondes** en lisant **quelques dizaines de
  milliers de lignes de rollup pré-agrégé**, pas le **million et plus d'événements** d'une base réelle (relevé du
  2026-08-05 par `plume-daemon db-stats --par-objet`). Chaque réponse porte
  `served_from: rollup|raw` + `approx` +
  `truncated` — l'analyste voit **toujours** si le chiffre est exact ou agrégé.
  **Et quand il est tronqué, il porte DE COMBIEN** : le plafond top-N par dimension écarte de x1,0 à
  **x16,4** selon la dimension (mesuré 2026-08-01, banc 1 436 026 events, `daemon/src/topn_cap.rs`), ce
  qu'un simple drapeau ne disait pas. Le job de rollup écrit, dans la même instruction qu'il tronque, une
  **ligne de reste** par (bucket, source, dim, env) — écrite **même à zéro**, faute de quoi son absence
  serait indiscernable d'un reste nul. La route la lit et publie `topn_ecartes`/`topn_servis`/`topn_total`.
  Buckets sans ligne de reste (agrégés par un binaire antérieur) → l'ampleur est **avouée inconnue**,
  jamais remplacée par 0. **Ce qui n'est PAS routé
  l'est délibérément** : un `count by source,severity,action` (ou `host`, ou `src_ip`) retombe sur le
  **scan brut**, mesuré à **une trentaine de secondes** sur une base réelle **au plus tard le 2026-07-23** (date du commit
  `c784f75` qui consigne la mesure ; la date de la mesure elle-même n'est pas consignée) — sur une topologie
  que la rétention a depuis purgée ; **le nombre de lignes que portait la base à cet instant n'a jamais été
  relevé**, et la latence n'a **pas** été re-mesurée depuis (relevé du volume courant : 2026-08-05). Ce n'est
  donc pas un coût courant, c'est une mesure datée. Le refus de router tient à la
  correction, pas à la latence : le rollup fusionne `NULL` et `''` sur ces
  dimensions et rendrait un group-by **faux** sous une étiquette « approximatif ». Nous refusons de servir
  une réponse approchée comme si elle était exacte : **des dizaines de secondes (mesure ≤ 2026-07-23) exactes plutôt
  que des millisecondes fausses**. La route
  n'est jamais tentée quand un **masque de champ** est actif (`event_rollup` porte source/host/severity/
  action en clair) — tous les chiffres ci-dessus sont mesurés **masquage inactif**.
- **Cache SWR des panneaux** : `panel_cache` + classification **adaptative LIVE/SWR par coût mesuré**
  (`panel_cost`, migration v46) — un panneau rapide est servi LIVE, un panneau coûteux passe en
  **stale-while-revalidate** (TTL `PLUME_PANEL_CACHE_TTL`), avec **anti-stampede** (un seul refresh
  async en vol par clé, sur un sémaphore dédié `PLUME_PANEL_REFRESH_CONCURRENCY` — il ne vole jamais
  un permis à l'interactif). Carte **Source freshness** = état de COLLECTE par source (fresh/quiet/down).
- **Règles de détection** : seedées au boot (`seed_detection_rules`, repro sur PVC neuf) **et** posées
  sur les instances existantes par les **migrations** (jusqu'à v51 : règles CF, brute-force,
  minio backup-delete, auditd tamper, intégrité SUID/persistance, conntrack beaconing, vault
  secret-read, self-detection brute-force de l'auth Plume…). Deux familles : **requête** (GXQL/SQL +
  seuil) et **diff** (snapshot vs baseline). Une règle qui matche → INSERT `alert` (+ sévérité) →
  **notifiers** (ntfy via `PLUME_NOTIFY_NTFY_URL`, seuil `PLUME_NOTIFY_MIN_SEV`). **Playbooks**
  (SOAR-lite) + **cases** (incidents) pour la suite.

## 8. Frontend (PWA)

- **Vanilla JS, sans étape de build** : assets statiques dans `web/`, servis par `ServeDir` du daemon
  (`PLUME_WEB`). PWA installable (manifest + service worker, shell offline). **Bilingue FR/EN** + tous
  les fuseaux IANA.
- **Page dense** (dark, a11y) : bandeau alertes → posture/score → panneaux (firewall, durcissement,
  auth, process/auditd, intégrité, réseau, conteneurs, k8s, ressources, freshness…), barre de
  recherche (GXQL/FTS) + plages de temps, **Explore**, **dashboards** & **panneaux** sauvegardés
  (query-driven), **règles**, **parsers**, **cases**, **actions/playbooks**, **users** (RBAC).
- Le shell PWA est servi **hors forward-auth** ; les données restent gatées (Authentik + auth Plume).

## 9. Déploiement

Trois cibles, **même binaire** (mode-aware) :

- **Docker** : `docker-compose.yml` — contexte de build = **la racine de ce dépôt** (`context: .`) ;
  `guatx-core` est résolu par une **git‑dep publique** (`guatxlabs/core`, tag épinglé dans
  `daemon/Cargo.toml`), aucun crate sibling
  requis. `docker compose build soc` → `hashpw` → `.env` (`PLUME_PASS_HASH`, **entre apostrophes
  simples** : Compose interpole les `$` d'un `.env`, cf. `README.md` §A et `.env.example`) →
  `docker compose up -d --build`. `PLUME_DEMO=1` peuple
  des données de démo. Le compose active les **ops natives** (backup 6 h + auto‑vacuum quotidien).
  **Aucune image n'est publiée** : ce mode compile depuis les sources (stage `rust:1-bookworm`).
- **Hôte nu (systemd)** : `bootstrap.sh` (central) installe le binaire + `plume-daemon.service`
  (`User=soc`, durci : `NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet=`,
  `MemoryMax=2G`, `ReadWritePaths=/var/lib/plume/db /var/lib/plume/spool`, bind `127.0.0.1:7000`).
  `bootstrap-agent.sh` installe un **agent** (collecteurs + `ship`, pas de daemon/DB/web).
- **k3s** : manifeste générique [`deploy/k3s.yaml`](deploy/k3s.yaml) (Namespace + Secret + PVC +
  Deployment + Service + **Ingress** + **NetworkPolicy** egress *default‑deny*), backup natif activé.
  L'Ingress est livré **sans TLS** (bloc à décommenter) et la NetworkPolicy n'a d'effet que si votre CNI
  les applique. Un déploiement de **production** type (à porter dans **votre dépôt
  GitOps**, piloté par ArgoCD/Flux ou équivalent) ajoute :
  - **Deployment** — `replicas: 1`, **`strategy: Recreate`** (PVC RWO +
    SQLite = un seul writer, pas de rolling). `securityContext` non-root uid `10001`,
    `readOnlyRootFilesystem`, `drop: [ALL]`, `seccomp RuntimeDefault`.
  - **initContainer** optionnel qui dépose un client objet (`mc`, `aws`…) dans un emptyDir partagé.
  - Conteneur **`plume`** (image **pinnée par digest/SHA** — bump après build) + **sidecar
    `backup`** (même image ; `plume-daemon backup` = `VACUUM INTO` **chiffré** — la variante
    `--compress` passe elle par un export en clair temporaire → copie vers
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
- **Tokens d'agent** : Bearer, SHA-256 en base. **La portée est DÉCLARÉE à la création**, jamais
  défaultée : `plume-daemon token <nom> <HOTE>` = jeton de **machine** (l'hôte est réécrit à l'écriture
  sur **toutes** les surfaces d'ingestion — `HoteIngere::resoudre` — et c'est lui qui autorise le
  responder sur cette machine) ; `plume-daemon token <nom> --relais` = **forwarder multi-hôtes**, dont
  l'hôte déclaré n'est **pas** attesté. La forme à deux arguments est refusée : elle produisait un jeton
  non lié avec lequel `{"host":"CONTROLEUR-DE-DOMAINE-USURPE"}` était accepté et stocké sous ce nom
  (mesuré le 2026‑08‑02). Ingest agent durci par **mTLS** (cert-manager, SNI dédié).
- **Le secret ne transite jamais par une ligne de commande** : les capteurs passent l'auth à curl par
  l'entrée standard (`plume_curl_auth_stdin`, `collectors/lib.sh`), l'agent lit son jeton avec
  `--token-stdin`, et le collecteur Windows n'a plus de paramètre `-Token`. *Un argument de processus est
  public : mesuré le 2026‑08‑02 lisible dans `/proc/<pid>/cmdline` (argv de 101 octets, secret verbatim),
  recopié par journald dans `_CMDLINE`, et — sous Windows — écrit dans 4688/Sysmon ID 1, c'est-à-dire dans
  ce que Plume collecte lui-même.* Ce que ça **ne** ferme pas : un opérateur qui tape un secret sur sa
  propre ligne de commande reste capté par l'audit d'exécution (`sudo` le journalise, et `MESSAGE` est
  stocké) — d'où la procédure d'enrôlement par `tee` du `README.md`.
- **TLS natif config-gated** : si `PLUME_TLS_CERT` + `PLUME_TLS_KEY` sont posés, le listener sert en
  **HTTPS (rustls/ring)** + HSTS ; sinon HTTP (défaut, derrière Traefik). Provider `ring` (pas
  d'aws-lc-rs : évite cmake/nasm).
  **HTTP/2 y est servi correctement — il ne l'était pas, et c'était grave.** *Mesuré le 2026‑08‑02 sur ce
  mode : ALPN annoncé = `h2` (`openssl s_client -alpn h2,http/1.1` → « ALPN protocol: h2 », donc un
  navigateur négocie h2 systématiquement), et la même requête sur la même autorité répondait **421 « bad
  host » en HTTP/2** contre **401/404 en `--http1.1`** — sur `/api/me`, `/api/search`, `/login` et `/`.
  Seules `/healthz`, `/readyz` et `/metrics` répondaient, parce qu'elles sont exemptées de la garde :
  **242 des 245 routes déclarées, interface web comprise, étaient injoignables depuis un navigateur.***
  Cause : `host_guard` ne lisait que l'en-tête `Host`, **absent** en HTTP/2 (l'autorité y est le
  pseudo-en-tête `:authority`, que hyper range dans l'URI) → `unwrap_or(false)`. Les émetteurs (collecteurs
  `.sh`, `plume-collector.ps1`, `plume-agent`) sont tous en HTTP/1.1, ce qui a masqué le défaut pendant
  toute la vie de ce mode. **Correctif** : l'autorité vient d'une source unique (`AutoriteDemandee`,
  `daemon/src/auth.rs`) qui lit les deux emplacements du protocole ; son champ est privé, donc on ne peut
  pas fabriquer une autorité à partir d'un seul des deux. La garde n'a pas été assouplie : une requête qui
  ne nomme **aucune** autorité reste refusée, et une autorité hors `PLUME_HOST` reçoit toujours 421 — en
  h2 comme en HTTP/1.1 (re-mesuré). `sso_same_origin_ok`, second et dernier lecteur de `Host`, consomme la
  même source.
- **DB** : requêtes API **read-only validées** + budget temps ; **SQLCipher** at-rest (`PLUME_DB_KEY`).
- **Intégrité tamper-evident** : **journal à chaîne de hash** (ledger, `PLUME_LEDGER_KEY`) +
  checkpoints **Ed25519**. Une altération **partielle** (une ligne modifiée/supprimée) casse la chaîne et
  est détectée par `plume-daemon verify`. **Ce qui n'est PAS couvert par défaut** : la vérification
  recalcule la chaîne depuis le début, donc un attaquant qui obtient **l'écriture en base ET la clé de
  signature** peut **réécrire tout le journal** et le re-signer de façon auto-cohérente. Fermer cette
  brèche exige d'**épingler la clé publique hors de la base** via **`PLUME_LEDGER_PUBKEY`** (escrow) :
  `verify` refuse alors une chaîne re-signée avec une autre clé. **Ce pin est OFF par défaut** — sans lui,
  la propriété tenue est « tamper-**evident** contre une altération partielle », pas « inviolable ».
  AIDE pour l'intégrité fichiers hôte.
- **Réponse** : actions **déléguées** aux enforcers existants (CrowdSec/fail2ban/nft), **dry-run par
  défaut** + **approbation** + **allowlist** + trace au ledger.
- **Conteneur durci** : non-root, rootfs read-only, `no-new-privileges`, capabilities `drop: ALL`.
- **Auto-surveillance** : alerte si un collecteur se tait (freshness `down`) ou si une règle de
  contrôle (firewall) saute.

## 11. Budget ressources

| Cible | RAM | Échange |
|---|---|---|
| k3s (profil de référence « SMB », SQLCipher) | **de l'ordre de trois cents Mio de RSS mesurés** · requests 256Mi-768Mi selon la charge / **limit 2Gi** | désactivé par l'orchestrateur |
| Conteneur (`docker-compose.yml`) | `mem_limit` — **même chiffre, 2 Gio**, réglable par `PLUME_MEM_LIMIT` ; `/tmp` borné (`PLUME_TMP_SIZE`) parce qu'un tmpfs est de la RAM comptée au même cgroup | `memswap_limit` **égal** à `mem_limit` → zéro octet |
| Hôte nu (systemd) | même binaire, même budget : `MemoryMax=2G` / `MemoryHigh=1800M` (cf. `systemd/plume-daemon.service`). **256 Mo et 200 Mo OOM-aient le daemon au boot** — ne descendez pas sous ~512 Mo. | **non borné** : aucune unité livrée ne pose `MemorySwapMax=`, donc `MemoryMax=` y borne le RÉSIDENT et pas le total |

Le profil de référence est **mesuré à quelques centaines de Mio de RSS** sur une installation réelle
(**près de dix millions d'événements en base, 2 vCPU, plafond mémoire 2 Gio, masquage de champs inactif**), et le plafond
de 2 Gio est **appliqué à l'exécution** dans les **trois** modes (`limits.memory: 2Gi` en k3s,
`mem_limit` + `memswap_limit` en conteneur, `MemoryMax=2G` en systemd — le conteneur ne le posait pas,
`P4.14-a`) — mais **le même chiffre n'y est pas la même borne** (colonne « Échange » ci-dessus), et
**aucun job de CI ne vérifie ce plafond** : c'est une mesure et une borne d'exécution, pas une garantie
re-prouvée à chaque commit. La consommation dépend surtout de la **concurrence de requêtes**, pas de la
taille de la base ; mesurez votre propre empreinte et **définissez vos propres seuils**. Leviers disponibles :
`MALLOC_ARENA_MAX=2` (borne les arènes glibc) et `PLUME_QUERY_CONCURRENCY` (borne les requêtes
simultanées — chacune coûte de la RAM). La stratégie tient aux **rollups
par-dimension** + au **cache SWR** — pas à l'index seul. CPU : 2 cœurs suffisent.

**`PLUME_FTS_FIELDS` n'est pas un levier de ce budget, et ce document le rangeait pourtant parmi
eux.** *Corrigé le 2026-08-30, après relecture du banc et des sources.* Aucune paire comparable du
banc ne mesure de surcoût MÉMOIRE de la vtable `event_fields_fts` : la seule paire qui partage le
binaire, le volume et la base rend une crête **plus basse** avec la capacité active, et le banc dit
lui-même que cet écart n'est pas attribuable au drapeau (chaque configuration repart d'un démon
neuf). Ce qui est mesuré, c'est un coût de **DISQUE** — de l'ordre d'un dixième de base en plus sur
cette même paire, au banc du dépôt (`docs/BENCHMARK.md`, levier L6) — et ce qui pèse le plus n'est
pas chiffrable en octets : **activer cette capacité échange de la performance de recherche contre de
la confidentialité sur la sauvegarde.** La vtable est déclarée *contentless* (`content=''`), forme
que le plan de sauvegarde typé refuse (`collect_dump_plan` → `PlanErr::Unsupported`) ; le chemin
compressé replie alors sur l'export historique, qui **réécrit la base entière EN CLAIR** dans le
répertoire de staging le temps de chaque cycle (`sqlcipher_export`). C'est cela — non la RAM — qui
justifie le défaut à `0`, et c'est le même arbitrage explicite que celui de
`PLUME_SQLITE_DEVERSEMENT`. Détail : [`docs/CHIFFREMENT-COMPRESSION.md`](docs/CHIFFREMENT-COMPRESSION.md).

**Plafond mémoire d'une lecture — et pourquoi il est OPT-IN.** Un `stats … by` ou un `dc()` dont la clé
n'est pas ordonnée par un index fait **trier** SQLite. Sous `temp_store=MEMORY`, ce tri n'a **aucun
mécanisme de déversement** — pas un réglage trop généreux, une absence de mécanisme : dans SQLite,
`sqlite3VdbeSorterInit` ne renseigne `mxPmaSize` que si `temp_store=FILE`, et `sqlite3VdbeSorterWrite`
enferme tout le calcul de déversement dans `if( mxPmaSize )`. Le trieur matérialisait donc un
enregistrement **par ligne balayée**. Basculer sur `temp_store=FILE` fait exister un plafond. Mesuré sur
3 648 003 événements, crête de RSS du processus (daemon neuf par cellule, `interactive:true`, moyenne de
2 tirs) :

| requête | `MEMORY` (défaut) | `FILE` (opt-in) | déversé sur disque |
|---|---:|---:|---:|
| `stats count by action,source \| sort -count \| head 50` | 1 134 Mio | **425 Mio** | 676 Mio |
| `stats dc(message)` | 1 106 Mio | **576 Mio** | 797 Mio |
| `stats count by severity` (servie par index) | 309 Mio | 311 Mio | 0 |

**Et pourtant le défaut livré reste `MEMORY`.** Les 676 et 797 Mio de la dernière colonne sont des
**valeurs d'événement en clair**, hors de la base SQLCipher : SQLCipher chiffre le *fichier de base*, pas
les temporaires de SQLite (c'est la raison pour laquelle il recommande lui-même `temp_store=MEMORY`).
Mesuré le 2026-08-04 : **323 occurrences lisibles** de deux aiguilles du jeu de test dans 16 Mio de
fichier de déversement relus, contrôle négatif à 0. Une base chiffrée qui laisse fuir ses valeurs par le
trieur n'est pas chiffrée — **plume ne fait pas cet échange à votre place**. `PLUME_SQLITE_DEVERSEMENT=1`
le prend explicitement, pour un déploiement dont le modèle de menace exclut le vol du volume.

**Et une fois l'échange pris, il est BORNÉ.** `PLUME_SQLITE_DEVERSEMENT_QUOTA_MO` (défaut `1024`,
`0` = aucune borne) plafonne les octets que le **processus** détient ouverts sous le répertoire de
déversement ; au-delà, l'instruction en cours est arrêtée et aucun résultat n'est rendu — le refus
NOMME le levier, et [`deploy/PROFILE.md`](deploy/PROFILE.md) comme le
[README](README.md#configuration--les-variables-plume_) décrivent ce qu'il borne et ce qu'il ne
borne pas. Il ne borne ni la RAM ni la requête fautive : la borne porte sur ce que le processus
détient, pas sur ce qu'une requête écrit.

**Conséquence, écrite pour être opposable : au défaut, une agrégation assez large tue toujours le
processus.** Le chemin qui ferme ce défaut sans rien céder sur la confidentialité est « moins d'octets à
trier » — compression au repos et agrégation bornée native — pas le déversement.

Ce que le défaut apporte quand même : le budget est décidé en **un seul endroit**
(`daemon/src/sqlite_plafond.rs`) et **dérivé** des bornes existantes :
`cache_size = PLUME_SQLITE_BUDGET_MB / (READ_POOL_CAP + PLUME_QUERY_CONCURRENCY +
PLUME_PANEL_REFRESH_CONCURRENCY + 4)`.

> **Le terme constant est 4, pas 2**, et la raison est écrite dans le code : les deux connexions
> HORS pool (l'écrivain du daemon et celle des rollups, `CONNEXIONS_HORS_POOL = 2`) portent CHACUNE
> un cache de pages **et** peuvent exécuter un tri — elles comptent donc dans les **deux** familles
> de porteurs (`porteurs_pour`, `daemon/src/sqlite_plafond.rs`) :
> `(READ_POOL_CAP + 2) + (interactif + refresh + 2)`. Aux défauts : `(8+2) + (3+2+2) = 17`.
> Cette page a publié `+ 2` jusqu'au 2026-08-06 — soit 15 porteurs au lieu de 17 — tout en donnant
> le bon total (« 17 porteurs ») à la phrase suivante. Conséquence réelle, et elle est plus étroite
> que ce qu'on pourrait craindre : le budget TOTAL reste respecté puisque le daemon divise par le
> vrai compte ; c'est la prédiction du cache **par porteur** qui était fausse, l'exploitant en
> attendant ~13 % de plus qu'il n'en reçoit. Aucune exposition supplémentaire à l'OOM.

Le défaut (1088 Mio = 17 porteurs × 64 Mio) **reproduit
exactement** l'ancien `cache_size=-65536` ⇒ **aucun écart de comportement n'est livré** ; doubler le pool
de lecture divise maintenant le cache tout seul, au lieu de dépasser le budget en silence.

**Si vous activez le déversement, trois points d'exploitation.** (1) Une requête qui tient sous le budget
ne paie **rien** (aucun octet écrit) ; celle qui le dépasse paie du **temps**, et ce temps est une
propriété du **support** — `dc(message)` mesuré à ×1,7 sur tmpfs, ×3,4 sur btrfs, ×8,6 sur un montage
`fuse.gocryptfs`. **Les réponses sont identiques** dans toutes les configurations mesurées
(`dc(message)` = 2 234 123 partout). (2) Les fichiers vivent dans `<répertoire de la base>/sqltmp` en
`0700` et SQLite les **délie dès l'ouverture** (donc sans nom, et effacés même si le processus meurt),
mais les octets touchent le périphérique : pointez `SQLITE_TMPDIR` sur un support chiffré (il est
respecté s'il est défini). (3) Ne le pointez **pas** sur un tmpfs (`/tmp` en est un sur la plupart des
hôtes systemd) : ce serait de la RAM comptée au même cgroup, et le plafond ne bornerait plus rien.

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
- **Sigma** : format de règles vendor-neutre → conversion vers le moteur GXQL/SQL (build-time).
- **YARA / ClamAV** : scan fichiers/IOC à la demande → events/alertes.

Tous **désactivables** par config ; absents, ils ne coûtent rien.
