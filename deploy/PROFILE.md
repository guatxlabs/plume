# Profil d'infra — déployer le SOC sur N'IMPORTE QUELLE infra (sans toucher au code)

Le SOC est **générique** : le moteur (daemon), la recherche (GXQL), les parsers et l'architecture
des collecteurs ne contiennent **rien de spécifique à une infra**. Tout ce qui dépend de TON
environnement passe par des **variables** (env / `EnvironmentFile` des units systemd, ou env du
Deployment k8s). Ce fichier liste ces variables — c'est le **seul** endroit à adapter.

Principe : *moteur générique + spécifique-infra en CONFIG, jamais en dur* ; chaque collecteur est un
**plugin auto-détecté** (s'éteint proprement si l'outil/log est absent), **OFF par défaut**.

> Les valeurs par défaut ci-dessous sont des **exemples GuatX** (pour compat). Sur une autre infra,
> remplace-les par les tiennes, ou laisse vide.

## 1. Agent → central (forwarder)
| Variable | Rôle | Défaut |
|---|---|---|
| `PLUME_CENTRAL` | URL du daemon central (`http://central:7000`) | — |
| `PLUME_TOKEN` | token d'agent (lié à un hôte, minté par `plume-daemon token`) | — |
| `PLUME_HOST_LABEL` | nom d'hôte affiché (multi-hôte) | hostname |
| `PLUME_HOST_HEADER` | en-tête `Host:` à envoyer (si forward-auth/SNI) | — |
| `PLUME_TLS_*` | mTLS agent (cert/clé/CA) si le central l'exige | — |
| `PLUME_EXTRA_COLLECTORS` | plugins à activer (`conntrack auditd kube-state pod-logs …`) | (socle seul) |

## 2. Cluster k8s / k3s (si applicable)
| Variable | Rôle | Défaut |
|---|---|---|
| `PLUME_KUBECTL` | commande kubectl (`kubectl` / `k3s kubectl` / `microk8s kubectl`) | auto-détection |
| `PLUME_KUBECTL_TIMEOUT` | timeout API (anti-hang) | `8s` |
| `PLUME_K3S_STORAGE` | chemin du provisioner local-path (métrique PV%) | auto (k3s / local-path-provisioner) |
| **`PLUME_WATCH_STS`** | **apps critiques à surveiller** : `ns/nom ns/nom …` → métrique `kube_sts_ready_<nom>` + alerte sév 4 « `<nom>` indisponible ». Lu par `kube-state.sh` (émission) **et** le daemon (seed de la règle). | **(vide)** — définis tes apps ; le générique `kube_sts_notready` reste émis sans config |

> **Rotation des clés — aucune variable à régler, mais un minuteur à armer.** Si le cluster utilise
> `external-secrets`, `kube-state` publie aussi `secretstore_notready` **et son dénominateur**
> `secretstore_total` : le daemon lève alors **UNE** alerte native (sév. 4, famille
> `heartbeat.magasin-de-secrets`) quand l'approvisionnement des secrets s'arrête — pas une par secret.
> Rien à configurer ici ; mais le producteur est `plume-kube-state.timer`, que `bootstrap.sh` laisse
> **éteint**, et tant qu'il l'est ce signal est **muet** — son silence ne vaut PAS « tout va bien ».
> Détail et geste d'armement : `deploy/K8S.md`.

## 3. Collecteurs (réglages par source)
| Variable | Rôle | Défaut |
|---|---|---|
| `PLUME_POD_LOG_SKIP` | pods exclus de `pod-logs` (déjà couverts par un collecteur dédié) — liste `\|` | `mailserver` |
| `PLUME_POD_LOG_FILTER` | regex des lignes pod retenues (erreurs + auth) | `error\|fail\|denied\|…\|authenticated\|…` |
| `PLUME_CROWDSEC_NS` / `PLUME_CROWDSEC_LAPI` | namespace / pod LAPI CrowdSec | `crowdsec` |
| `PLUME_CONNTRACK_SCOPE` | portées conntrack collectées (`external internal loopback`) | toutes |
| `PLUME_LOCKDOWN_IFACE` / `PLUME_LOCKDOWN_PORTS` | contrôle docker-lan-lockdown (laptop wifi) | `wlan0` (n/a si absent) |
| `PLUME_MAIL_F2B` / `PLUME_MAIL_SKIP_IP` | collecteur mail (docker-mailserver) | — |

## 4. Daemon central
| Variable | Rôle | Défaut |
|---|---|---|
| `PLUME_RETENTION_DAYS` | rétention des events | `30` |
| `PLUME_QUERY_MAX` | plafond de lignes par requête | `10000` |
| `PLUME_USER` / `PLUME_PASS_HASH` | auth native (argon2) — sinon mode SETUP | — |
| `PLUME_SSO_HEADER_SECRET` + `PLUME_SSO_GROUP_*` | SSO trusted-header (Authentik/forward-auth) | — |
| `PLUME_HOST` | hôte(s) autorisé(s) (anti-DNS-rebinding) | — |
| `PLUME_SQLITE_BUDGET_MB` | budget RAM total concédé à SQLite ; réparti automatiquement entre les porteurs (connexions du pool + tris en vol), d'où `cache_size` | `1088` (= 17 × 64 Mio, reproduit à l'octet le dimensionnement historique) |
| `PLUME_SQLITE_DEVERSEMENT` | **échange confidentialité ↔ mémoire.** À `0`, les tris restent en RAM : rien d'un événement ne touche le disque en clair, mais **une agrégation assez large peut épuiser la mémoire** (SQLite n'a aucun mécanisme de déversement dans ce mode). À `1`, les gros tris débordent sur disque **en clair, hors de la base SQLCipher** — n'activez que si votre modèle de menace exclut le vol du volume, et pointez alors `SQLITE_TMPDIR` sur un support chiffré (jamais un tmpfs : ce serait de la RAM au même cgroup). | `0` |
| `PLUME_SQLITE_DEVERSEMENT_QUOTA_MO` | **la borne du volume écrit en clair**, en Mio, quand `PLUME_SQLITE_DEVERSEMENT=1`. Au-delà, l'instruction en cours est ARRÊTÉE et **aucun résultat n'est rendu** (un résultat partiel serait faux sans le dire) ; le refus nomme ce levier. Il borne **ce que le PROCESSUS détient ouvert** sous le répertoire de déversement — pas la requête fautive, pas la RAM, et rien du tout quand le déversement vaut `0` (aucune mesure n'est armée). `0` = aucune borne. Si la mesure du système devient illisible en cours de route, le quota cesse d'être opposable et la cause est écrite une fois sur la sortie d'erreur. | `1024` |

## Inputs custom (scripted inputs) — ajouter une source SANS code
Le collecteur générique `custom.sh` (OPT-IN, `PLUME_EXTRA_COLLECTORS="… custom"` + `plume-custom.timer`)
lit `/etc/plume/inputs.d/*.input` : tu décris une commande, sa sortie devient des events. C'est
l'équivalent « inputs » du registre de parsers — toute source, toute infra, **zéro code**.

```ini
# /etc/plume/inputs.d/nginx.input
SOURCE=nginx-app
CMD=journalctl -u nginx --since -90s --no-pager -o cat
SEVERITY=2
FILTER=error|warn|denied        # optionnel
# CATEGORY=web  MAX=100         # optionnels
```
Chaque ligne de la sortie de `CMD` → 1 event `source=nginx-app` (dédupé source+ligne/heure, borné `MAX`),
puis **les parsers du registre l'enrichissent** (champs groupables). Voir `deploy/example.input`.
Sécurité : `CMD` tourne en root → `/etc/plume/inputs.d` doit être **root-only** (l'opérateur a déjà root).

## Démo publique (sécurisée)
Pour exposer une démo publique **sans risque** :
- **`PLUME_PUBLIC_DEMO=1`** → accès **anonyme en lecture seule** (rôle *viewer* forcé) : lecture OK
  (overview, search, explore, dashboards, alertes…), **tout le reste bloqué 403** (création/màj/suppression,
  `/api/users`, `/api/actions`, `/api/ingest`, `/api/mail/body`). Réutilise le RBAC viewer (testé).
- **`PLUME_DEMO=1`** → uniquement des **données factices** (aucune vraie donnée).
- **Instance ISOLÉE** : un déploiement séparé, **jamais** le SOC de prod (sa DB, ses tokens, son réseau).
- Rate-limit intégré ; mets-la derrière un reverse-proxy / Cloudflare. Pas de secret réel, pas d'agent.

```sh
PLUME_PUBLIC_DEMO=1 PLUME_DEMO=1 docker compose up -d   # instance dédiée, lecture seule, données démo
```

## Déployer ailleurs (résumé)
1. Central : `docker compose up` **ou** `deploy/k3s.yaml` **ou** `bootstrap.sh` (hôte natif) — mode-aware.
2. Agent : `bootstrap-agent.sh` avec `PLUME_CENTRAL`/`PLUME_TOKEN` + `PLUME_EXTRA_COLLECTORS`.
3. Adapter **ce profil** : surtout `PLUME_WATCH_STS` (tes apps critiques) ; le reste s'auto-détecte.
4. Les collecteurs absents (pas de k8s, pas de crowdsec, …) se désactivent **tout seuls**.

Rien d'autre n'est à toucher : aucun nom d'app, namespace ou IP n'est codé en dur dans la logique.
