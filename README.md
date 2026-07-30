<div align="center">

# 🪶 Plume

**Le SOC / XDR souverain, léger comme une plume** — des opérations de sécurité sans la pile lourde.
*Rust · SQLite · un seul petit binaire · tourne dans 2 Go · on‑premise, respectueux du RGPD, zéro dépendance externe.*

**·  open source  ·  par [GuatX](https://github.com/guatxlabs)  ·**

**Licence : [AGPL‑3.0](LICENSE)**  ·  Modules Enterprise → [`COMMUNITY_VS_ENTERPRISE.md`](COMMUNITY_VS_ENTERPRISE.md)

</div>

<p align="center">
  <img src="docs/img/plume-demo.gif" alt="Plume — GXQL search, alerts, and incident-case investigation" width="90%">
</p>

Plume est la **moitié bleue d'un SOC purple**. Il ingère **logs et métriques**, puis vous offre la **recherche
(GXQL)**, des **tableaux de bord**, un **moteur de détection** (règles · import Sigma · couverture ATT&CK · playbooks
SOAR‑lite), du **threat‑intel** (correspondance IOC/STIX/TAXII à l'ingestion), de l'**alerting basé sur le risque**, des **cases
d'incident** et une **réponse automatisée** — le tout dans **un seul petit binaire** que vous exécutez
sur **Docker**, un **hôte nu (systemd)** ou **Kubernetes/k3s**, dans **2 Go de RAM**.

> ### 🔴🔵 La boucle purple — un SOC qui s'entraîne face à son propre attaquant
> Plume fait équipe avec **[Forge](https://github.com/guatxlabs/forge)**, le moteur red‑team. **Forge lance** un
> engagement autorisé → **Plume détecte et corrèle** chaque action par sa technique ATT&CK → la **matrice de
> couverture** transforme chaque manqué en un angle mort visible à combler. Le **Mode Engagement** natif permet à un
> pentest autorisé de se dérouler à travers le SOC en production **sans reconfiguration** (le mode s'active et se désactive
> à chaud, mode‑off prouvé byte‑identique par les tests), puis
> nettoie automatiquement et produit un rapport signé.
>
> *La boucle attaque → SIEM → validation de détection **existe ailleurs** : [Splunk Attack Range](https://github.com/splunk/attack_range)
> (OSS, Splunk Threat Research Team) l'automatise jusqu'en CI/CD, [MITRE Caldera](https://github.com/mitre/caldera)
> l'outille côté adversaire, et le marché BAS/AEV (Cymulate, SafeBreach, Picus) la vend. Ce que **nous** n'avons trouvé
> chez personne, c'est cette boucle livrée **dans une suite souveraine, auto‑hébergée, dont la moitié bleue tient dans 2 Go** —
> rouge et bleu de la même suite (deux dépôts, [Plume](https://github.com/guatxlabs/plume) et
> [Forge](https://github.com/guatxlabs/forge)), corrélés par technique ATT&CK, sans SaaS ni cluster. Si vous connaissez un contre‑exemple,
> [ouvrez une issue](https://github.com/guatxlabs/plume/issues) : nous corrigerons cette phrase.*

### Pourquoi Plume
- 🪶 **Léger et souverain** — un seul binaire Rust (`axum` + `rusqlite`/SQLite, WAL+FTS5) + une PWA en JavaScript vanilla sans build. **Mesuré : ~310 Mio de RSS** sur l'instance de référence (**9 844 503 events, 2 vCPU, plafond 2 Gio, masquage inactif**) ; un `count` sur ces 9 844 503 events rend en **6,5 s** sous ce plafond. Le plafond de 2 Gio est **appliqué à l'exécution, pas vérifié par la CI** — mesurez votre propre empreinte. Pas de cloud américain, pas de cluster à opérer.
- 🧩 **Bring‑your‑own‑vendor** — *rien de spécifique à un éditeur n'est codé en dur.* Branchez **n'importe quelle** source : un **DSL de parsing** déclaratif (config.d, sans rebuild), un endpoint **compatible Splunk‑HEC** (pointez vos forwarders existants vers Plume), un **connecteur `http_pull` générique** (n'importe quelle API REST — CrowdStrike/SentinelOne/Defender par simple configuration), ou des flux **TAXII 2.1**. *Objectif de conception : ne pas vous faire perdre de capacité en migrant. Ce n'est pas une garantie mesurée — aucune matrice comparative n'existe dans `docs/` ; si une capacité vous manque, [ouvrez une issue](https://github.com/guatxlabs/plume/issues).*
- 🛡️ **Une détection qui grandit avec vous** — l'**import Sigma** (unitaire et en masse) projette le jeu de règles communautaire sur la **matrice de couverture ATT&CK** ; le **threat‑intel** enrichit à l'ingestion ; l'**alerting basé sur le risque** score les entités pour réduire la fatigue d'alertes. Normalisé CIM, pour que les règles se composent par *catégorie*, jamais par éditeur.
- 🔐 **Sécurisé et auditable par défaut** — argon2id + RBAC **fail‑closed** (une route non listée est refusée, pas autorisée), tokens d'agent liés à l'hôte, requêtes validées en lecture seule, un **ledger en chaîne de hachage** vérifiable (`plume-daemon verify`), conteneur durci (non‑root, rootfs en lecture seule, capabilities supprimées) et une **NetworkPolicy d'egress default‑deny** livrée dans [`deploy/k3s.yaml`](deploy/k3s.yaml). **Aucun secret dans le dépôt** — un code ouvert est une *fonctionnalité*, pas un risque.
  *Deux réserves explicites, parce qu'un défaut annoncé vaut mieux qu'un défaut découvert :* le **chiffrement at‑rest SQLCipher** (par tenant en mode MSSP) est **compilé mais OPT‑IN** — sans clé (`PLUME_DB_KEY_FILE`), **la base est en clair sur le disque** ; et la NetworkPolicy n'a d'effet que si votre CNI les applique (flannel seul ne le fait pas — [vérifiez‑le](deploy/k3s.yaml), ne le supposez pas).
- 🌍 **Interface bilingue** (FR / EN) + tous les fuseaux horaires IANA.

**Architecture** — *Central* : un seul binaire Rust qui ingère, stocke et sert l'API + la PWA sur `:7000`.
*Agents* : des collecteurs `sh` + `systemd` sans dépendances (plugins, désactivés par défaut) qui poussent vers le central
(`POST /api/ingest`, token bearer) ; un agent endpoint multi‑OS (Linux aujourd'hui, Windows/macOS en cours).
Le central est aussi son propre agent. Documentation approfondie : [`ARCHITECTURE.md`](ARCHITECTURE.md) ·
**[index de la documentation](docs/README.md)** (chaque document y porte son état : livré / opt-in /
conception) — dont [SDK](docs/SDK.md) · [CIM](docs/CIM.md) · [DSL de parsing](docs/PARSER-DSL.md) ·
[Importeur Sigma](docs/SIGMA-IMPORTER.md) · [reprise après sinistre](docs/DR-plume-restore.md).

## Au menu
| Domaine | Capacité |
|---|---|
| **Recherche** | GXQL (*GuatX Query Language*, **anciennement « SOQL »** — même langage, même syntaxe, seul le nom change) — un langage à pipes façon SPL compilé en SQL **lecture seule, à l'épreuve des injections** (champs en liste blanche, paramètres liés, un seul SELECT, budget temps). Aucune requête, aucun panneau, aucune règle n'est à réécrire ; les identifiants techniques (route `/api/soql/*`, clé JSON `soql`, colonne `is_soql`, module Rust `guatx_core::soql`) restent en `soql`. |
| **Détection** | Règles + playbooks SOAR‑lite · **import Sigma** (unitaire et en masse, avec delta de couverture ATT&CK) · **matrice de couverture ATT&CK** (**14 tactiques × 183 techniques** curées — le catalogue `guatx_core::attack::CATALOG`, angles morts mis en évidence). |
| **Threat‑intel** | Base d'IOC · import **STIX 2.1** · **correspondance à l'ingestion** (`ti_match`, enrichir sans supprimer) · connecteur de flux **TAXII 2.1** · appartenance basée sur des filtres de Bloom pour le passage à l'échelle. |
| **Risque (RBA)** | Scoring de risque par entité (modèle Splunk‑ES) · alerting sur incident de risque (cumul / tactiques distinctes / vélocité) · une seule alerte dédupliquée par entité. |
| **Ingestion** | Agents (sh/systemd) · endpoint compatible fil **Splunk HEC** · connecteur **`http_pull` générique** (bring‑your‑own‑vendor) · parser syslog + Fortinet · DSL de parsing déclaratif. |
| **Réponse** | **Vocabulaire d'actions fermé et à l'épreuve des injections** (ban_ip / unban_ip / kill_pid / stop_service) avec **exécuteurs par plateforme** (nft/fail2ban/netsh/pfctl/appliance) — dry‑run + approbation + liste blanche + ledger. |
| **Cases** | Cases d'incident, triage à l'échelle, export. |
| **Multi‑tenant** | Mode MSSP optionnel — chiffrement **SQLCipher par tenant**, groupes RBAC → tenant/rôle, super‑admin audité. *(Désactivé par défaut — le mono‑tenant est identique au bit près.)* |
| **Purple** | **Mode Engagement** (pentest autorisé à travers le SOC en production, sans angle mort, auto‑nettoyage, rapport signé) — la jonction avec [Forge](https://github.com/guatxlabs/forge). |

## Captures d'écran

<table>
<tr>
<td width="50%"><a href="docs/img/06-dashboard-light.png"><img src="docs/img/06-dashboard-light.png" alt="Overview"></a><br><sub><b>Vue d'ensemble</b> — firewall, contrôles, hôtes et fraîcheur des sources</sub></td>
<td width="50%"><a href="docs/img/03-explore-soql.png"><img src="docs/img/03-explore-soql.png" alt="GXQL"></a><br><sub><b>Explore / GXQL</b> — recherche façon SPL compilée en SQL sûr, en lecture seule</sub></td>
</tr>
<tr>
<td><a href="docs/img/08-case-detail.png"><img src="docs/img/08-case-detail.png" alt="Case"></a><br><sub><b>Cases d'incident</b> — timeline, événements/alertes liés, SLA</sub></td>
<td><a href="docs/img/04-attack-matrix.png"><img src="docs/img/04-attack-matrix.png" alt="ATT&CK"></a><br><sub><b>Couverture ATT&CK</b> — chaque manqué devient un angle mort visible</sub></td>
</tr>
<tr>
<td><a href="docs/img/10-inventaire-sources.png"><img src="docs/img/10-inventaire-sources.png" alt="Sources"></a><br><sub><b>Inventaire des sources</b> — flux déclarés, attendu vs réel, fraîcheur</sub></td>
<td><a href="docs/img/21-admin-audit.png"><img src="docs/img/21-admin-audit.png" alt="Audit"></a><br><sub><b>Administration</b> — ledger d'audit en chaîne de hachage, vérifiable</sub></td>
</tr>
</table>

## Installation

Le mot de passe admin n'est **jamais** stocké en clair : vous fournissez son **hash argon2id** via
`PLUME_PASS_HASH` (généré par la commande `hashpw`). En son absence, le central démarre en **mode SETUP**
(un token d'installation à usage unique affiché dans les logs → assistant web).

> ### ⚠️ À lire avant de choisir un mode : rien n'est encore pré‑construit
> **Aucune image de conteneur et aucun binaire ne sont publiés à ce jour** (pas de `ghcr.io/...`, pas
> d'artefact de release). Les trois modes **compilent le daemon depuis les sources**. Concrètement :
> - **Docker** ne demande **pas** de toolchain Rust sur votre machine : le `Dockerfile` compile dans un
>   stage `rust:1-bookworm`. Docker (avec BuildKit) suffit.
> - **Hôte nu** et **k3s** demandent, eux, **un Rust stable installé** (`cargo`) : le premier pour
>   produire le binaire, le second pour produire l'image à importer.
> - Le build tire crates.io **et** la git‑dep `guatxlabs/core@v0.2.1` → **un accès réseau est requis**
>   au premier build. *Durée et pic mémoire du build : non mesurés sur cette machine ; le `Dockerfile`
>   borne `CARGO_BUILD_JOBS=2` pour éviter l'OOM sur une petite machine.*
>
> Publier une image et des binaires signés est le **prérequis n°1** pour un démarrage « sans toolchain » ;
> c'est un manque assumé et connu, pas un oubli.

### A. Docker (le plus simple)
Depuis la racine de ce dépôt (le contexte de build est le dépôt lui‑même ; `guatx-core` est résolu
via une git‑dep publique, aucun crate sibling requis) :
```sh
docker compose run --rm soc hashpw 'my-password'     # -> copy the printed $argon2id$...
cp .env.example .env                                 # paste PLUME_PASS_HASH=...
docker compose up -d --build                         # -> http://soc.localhost:7000
```
Le `docker-compose.yml` livré active les **ops natives du binaire** : **backup toutes les 6 h** vers
`/data/backups` (rétention des 24 plus récents) + **auto‑vacuum quotidien**, sans sidecar ni cron hôte.
Réglez‑les — ou coupez‑les avec `PLUME_BACKUP_INTERVAL=0` — via `.env`.

> 🪶 **Démo (peuplée, sans agents)** — ajoutez `PLUME_DEMO=1` : des événements/métriques/alertes d'exemple sur 24 h pour voir Plume *vivant* immédiatement. *(Désactivé en production.)*

### B. Hôte nu (systemd) — mode de première classe, sans Docker
```sh
cd daemon && cargo build --release && cd ..          # single-file binary (Rust stable requis)
sudo bash bootstrap.sh                               # central: daemon + units, :7000 (idempotent)
```
`bootstrap.sh` **refuse de continuer** si `daemon/target/release/plume-daemon` est absent : compilez d'abord.
Il installe le daemon, les collecteurs et leurs units/timers — dont **`plume-backup.timer` (quotidien,
04:00)**, qui appelle `plume-daemon backup` (copie compacte `VACUUM INTO`, rotation à 7). *Ce chemin hôte
diffère de celui du mode Docker/k3s* : le timer produit une copie `.db` non compressée, le scheduler
in‑daemon produit une archive `age(zstd(...))` — voir [`docs/DR-plume-restore.md`](docs/DR-plume-restore.md).
Pour aligner l'hôte sur le scheduler natif, posez `PLUME_BACKUP_INTERVAL` dans `/etc/plume/soc.conf` et
désactivez le timer (`systemctl disable --now plume-backup.timer`).

Enrôlez une autre machine comme agent qui pousse vers le central :
```sh
sudo /usr/local/bin/plume-daemon token agent-$(hostname) $(hostname)   # on the central
sudo env PLUME_CENTRAL=https://central:7000 PLUME_TOKEN='<token>' bash bootstrap-agent.sh   # on the agent
```

### C. Kubernetes / k3s
**[`deploy/k3s.yaml`](deploy/k3s.yaml)** est complet et applicable tel quel : **Namespace + Secret + PVC +
Deployment + Service + Ingress + NetworkPolicy** (egress *default‑deny*, DNS seul autorisé) — avec le
backup natif activé. Remplacez les valeurs à compléter (`PLUME_PASS_HASH`, et `soc.tondomaine.tld` **aux
deux endroits** : `PLUME_HOST` et l'Ingress — un écart déclenche la garde anti‑DNS‑rebinding → 421),
construisez et importez l'image (multi‑stage `debian‑slim`, non‑root ; aucun registre requis), puis :
```sh
docker build -t soc:latest .
docker save soc:latest | sudo k3s ctr images import -
kubectl apply -f deploy/k3s.yaml
```
L'Ingress est livré **sans TLS** (bloc `tls:` à décommenter) : ne l'exposez pas sur Internet sans certificat.
Le PVC est à **1Gi**, une valeur de démarrage — dimensionnez‑le sur votre rétention réelle.

### Chiffrement de la base (at‑rest) — opt‑in, à décider AVANT le premier démarrage
Par défaut **la base est en clair sur le disque**. SQLCipher est compilé dans le binaire mais ne s'active
qu'avec une clé : `PLUME_DB_KEY_FILE=/chemin/vers/la/cle` (préféré — un fichier monté en lecture seule,
**fail‑closed** s'il est absent) ou `PLUME_DB_KEY=<passphrase>` (lisible via `/proc/<pid>/environ`).
Une base neuve est créée chiffrée d'office ; une base en clair existante est convertie au boot (idempotent).
**Perte de la clé = perte de la base** : conservez‑la hors de la machine.

### Désinstallation (hôte)
```sh
sudo bash uninstall.sh            # removes binary + collectors + units + config (KEEPS /var/lib/plume)
sudo bash uninstall.sh --purge    # ALSO removes data (DB, spool, ledger key) + the plume user
```

## Ajouter vos sources et collecteurs

Plume ingère **n'importe quelle source** sans rebuild ni intervention de notre part — trois leviers, du plus simple au plus fin.

**1. Une nouvelle source, sans code (« scripted input »).** Le collecteur générique `custom.sh` lit
`/etc/plume/inputs.d/<nom>.input` (`KEY=value`), exécute la commande et transforme chaque ligne de sa
sortie en événement `source=<SOURCE>`.

> ⚠️ **`custom` n'est PAS installé par défaut** — `bootstrap-agent.sh` n'installe que
> `resources integrity ship`. Deux étapes explicites (la « règle d'or » du projet : on installe sans
> activer, l'opérateur décide) :
> ```sh
> sudo env PLUME_EXTRA_COLLECTORS="custom" PLUME_CENTRAL=… PLUME_TOKEN=… bash bootstrap-agent.sh
> sudo install -d -o root -g root -m 0700 /etc/plume/inputs.d   # aucun script ne le crée
> sudo systemctl enable --now plume-custom.timer                # cadence : 60 s
> ```
> Le répertoire **doit** être root-only : `CMD` s'exécute **en root** (le collecteur n'a pas de
> `User=`), donc y déposer un fichier revient à exécuter du code privilégié.

```sh
# /etc/plume/inputs.d/monapp.input
SOURCE=monapp                          # nom cherchable (source=monapp) — obligatoire
CMD=tail -n0 -F /var/log/monapp.log    # toute commande ; 1 ligne stdout = 1 événement — obligatoire
CATEGORY=application                    # défaut: custom
SEVERITY=1                             # 0 info … 4 critique (défaut 1)
FILTER=ERROR|WARN                      # optionnel : ne garde que les lignes qui matchent
MAXLEN=4000                            # longueur max/ligne (monter pour du JSON verbeux)
```

Faites émettre à `CMD` uniquement le **nouveau** (`journalctl --since -1min`, `tail -n0 -F`, un appel d'API…) ; la déduplication horaire absorbe les doublons. Tout ce qui produit du texte se collecte ainsi : un log Linux, une API REST, une base — le collecteur tourne sur un hôte Linux mais la **cible** peut être n'importe quel système.

> **Linux** (serveur ou poste, toute distribution) est couvert nativement : les collecteurs (`collectors/*.sh`, POSIX-sh) s'installent via `bootstrap-agent.sh` et **s'auto-désactivent** si leur outil est absent (auditd, journald, conntrack, ufw/nftables, ClamAV, Falco, kube-state…). **Windows** (poste, entreprise, Windows Server) a un **collecteur natif PowerShell clé-en-main** — événements · pare-feu · réseau · Defender — dans **[`collectors/windows/`](collectors/windows/)** : copiez-le, planifiez-le (tâche toutes les 5 min), il POST directement au central. **macOS** : via un scripted input (`log show`).

**2. Extraire des champs d'un format inconnu (parser).** Déposez `config.d/parsers/<nom>.json` : une regex à groupes nommés `(?P<champ>…)` transforme le texte brut en champs structurés, cherchables et mappables au CIM — sans rebuild.

```json
{ "name": "monapp — erreurs", "source": "monapp",
  "pattern": "^(?P<ts>\\S+) (?P<level>\\w+) (?P<msg>.+)$", "enabled": true }
```

Un DSL déclaratif plus riche est documenté dans [`docs/PARSER-DSL.md`](docs/PARSER-DSL.md).

**Sigma.** Un **importeur** [Sigma](https://github.com/SigmaHQ/sigma) est livré (`plume-daemon sigma-import`, unitaire
ou en masse, avec `--dry-run`) ; **3 règles d'exemple** sont dans `config.d/sigma/`. Ce n'est **pas un moteur Sigma
complet** : il traduit le **sous-ensemble exprimable en GXQL**, et ce qu'il ne sait pas traduire fidèlement est
**flaggé**, jamais deviné — la matrice exacte des constructions supportées et refusées est dans
[`docs/SIGMA-IMPORTER.md`](docs/SIGMA-IMPORTER.md) §4 et §6. Le **taux d'acceptation sur le dépôt SigmaHQ complet
n'est pas mesuré** à ce jour : nous ne publierons ce chiffre qu'une fois le banc passé.

**3. Détecter et agir.** Ajoutez une **règle** (`config.d/rules/*.json` : requête GXQL + seuil) ou un **playbook** (`config.d/playbooks/*.json` : requête → action). Parsers, règles et playbooks sont aussi **créables/éditables dans l'interface** (rôle admin) ; le fichier reste la source durable, versionnée en git.

Les fichiers de `config.d/` sont chargés au démarrage de façon **idempotente** (un overlay l'emporte sur le builtin de même nom) ; un fichier invalide est **ignoré avec un avertissement**, jamais un crash. Vue d'ensemble des points d'extension (parser · connecteur · détection · threat-intel · enforcer) et modèle *bring-your-own-vendor* : **[`docs/SDK.md`](docs/SDK.md)**.

## Architecture (en bref)
```
  agents (sh + systemd, OFF by default)          central (1 Rust binary)
  ┌────────────────────────────────┐  POST /api/ingest  ┌──────────────────────────┐
  │ resources / integrity / journal│  ───── token ────► │ axum + rusqlite (SQLite) │
  │ conntrack / auditd / suricata  │                    │  ingest + retention      │
  │ kube-state / pod-logs / …      │  HEC / http_pull   │  GXQL + FTS5 · detection │
  │ (auto-disable if tool absent)  │  ◄── /api/actions ─│  TI · RBA · ATT&CK · PWA │
  └────────────────────────────────┘  (responder pull)  └──────────────────────────┘
                                  Forge findings ─► /api/ingest ─► correlate by ATT&CK (purple)
```

## Sécurité (intégrée)
- **Authentification** : argon2id (+bcrypt) + **RBAC** (viewer/editor/admin) ; tokens d'agent **liés à l'hôte** ; vérification du `Host` (anti‑rebinding) ; en‑têtes + rate‑limit par IP.
- **Base de données** : les requêtes de l'API sont **en lecture seule**, validées, à budget temps. Le SQL brut est réservé aux admins ; un autorisateur refuse les colonnes de mot de passe/token, même aux admins.
- **Réponse** : les actions sont **déléguées** aux exécuteurs, en **dry‑run par défaut** + approbation + liste blanche + **ledger en chaîne de hachage** (vérifiable par `plume-daemon verify` ; voir la réserve sur l'épinglage de clé dans ARCHITECTURE §14).
- **Au repos** : chiffrement optionnel **SQLCipher par tenant**. **Conteneur** : non‑root, rootfs en lecture seule, `no‑new‑privileges`, capabilities supprimées, NetworkPolicy d'egress.

## Licence et modèle
Le cœur de Plume est **ouvert et copyleft** sous **[AGPL‑3.0](LICENSE)** — auto‑hébergez‑le, étudiez‑le, modifiez‑le.
Sous l'AGPL, si vous distribuez une version modifiée *ou* l'exploitez comme service réseau, vous devez offrir aux
utilisateurs le **code source complet correspondant** de votre version sous l'AGPL. Son pendant offensif
**[Forge](https://github.com/guatxlabs/forge)** est lui aussi en **AGPL‑3.0** — le copyleft convient à un moteur de sécurité.

- **Open core — AGPL‑3.0** : le **SOC complet** — ingestion, GXQL, détection (règles · Sigma · couverture
  ATT&CK), threat‑intel, RBA, cases, réponse, connecteurs bring‑your‑own‑vendor, la boucle purple et le
  Mode Engagement. Tout le nécessaire pour exploiter Plume en solo, en équipe, ou dans vos propres opérations.
- **Licence commerciale (disponible séparément)** : pour les organisations qui ne peuvent pas satisfaire les
  obligations de copyleft réseau de l'AGPL — usage propriétaire ou embarqué sans divulgation du code source. À ses côtés,
  des modules Enterprise séparables pour l'**échelle / l'équipe / la conformité** (multi‑tenant/MSSP à l'échelle, SSO/SCIM,
  stockage distribué, packs de conformité, connecteurs premium), une offre **managée/hébergée** et du
  **support / SLA**.

**Principe** : l'ensemble du SOC reste ouvert et auditable sous l'AGPL — c'est là la crédibilité. Le
business, ce sont la **licence commerciale, les modules Enterprise, le service hébergé et le support** — pas une
restriction sur l'open core.
Détail : [`COMMUNITY_VS_ENTERPRISE.md`](COMMUNITY_VS_ENTERPRISE.md).

## Statut
Projet open‑source actif — **par [GuatX](https://github.com/guatxlabs)**. Détection, threat‑intel, RBA,
multi‑hôtes, boucle purple. Pas encore de release taguée ; à utiliser avec précaution. Contributions et issues bienvenues.
