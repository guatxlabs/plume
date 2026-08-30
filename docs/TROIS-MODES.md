# Le même geste dans les trois modes — hôte natif · Docker · k3s

Plume revendique **trois** modes de déploiement de première classe. Un document qui écrit un geste
sans dire à quel mode il s'applique n'en couvre qu'un — et laisse le lecteur des deux autres croire
qu'il a mal compris. Ce document existe pour cela : **chaque geste d'exploitation y porte sa forme
dans les trois modes, et là où il n'existe pas dans un mode, c'est ÉCRIT.**

Il complète, sans les répéter, l'installation ([`../README.md`](../README.md#installation)) et la
désinstallation ([`../README.md`](../README.md#désinstallation--les-trois-modes)).

> **Ce que ce document n'est pas.** Ce n'est pas un guide de dimensionnement, ni une procédure de
> reprise après sinistre — celle-ci est dans [`DR-plume-restore.md`](DR-plume-restore.md) — ni un
> tutoriel Kubernetes. Il répond à une seule question : *« j'ai lu un geste ; à quoi ressemble-t-il
> chez moi ? »*

---

## 1. Les trois modes, et d'où ce chiffre vient

Les trois modes ne sont pas une promesse marketing : ils sont **énumérés par le code qui les
retire**. `uninstall.sh` n'accepte que trois valeurs de `--mode`, et refuse tout le reste :

```sh
grep -nF 'case "${MODE}" in' uninstall.sh     # -F : le motif contient ${…}, à prendre littéralement
```

Le mode est aussi ce qui décide de la **forme** de chaque geste ci-dessous. Il n'y a pas de
quatrième mode caché : une installation montée à la main n'est décrite par aucun installateur du
dépôt, et aucun outil du dépôt ne prétend la connaître.

| Mode | Ce qui exécute le démon | Ce qui le redémarre | Immuable ? |
|---|---|---|---|
| `host` | une unité systemd (`systemd/plume-daemon.service`) | `systemctl` | non — le disque de l'hôte est modifiable |
| `docker` | un conteneur du service `soc` de `docker-compose.yml` | `docker compose` | **oui** — l'image est reconstruite, jamais éditée |
| `k3s` | un pod du `Deployment` de `deploy/k3s.yaml` | `kubectl` | **oui** — et le pod est remplacé à chaque déploiement |

**C'est de cette colonne « immuable » que découle presque tout le reste.** Un geste qui écrit sur le
disque de la machine a un sens sur un hôte ; sur un conteneur il est perdu au prochain déploiement,
et sur un cluster il l'est au prochain redémarrage du pod.

---

## 2. Où vivent les choses

Relevé **sur l'arbre suivi** le 2026-08-25, en lisant les installateurs et les manifestes — pas une
installation.

| Ce qui vit | `host` | `docker` | `k3s` |
|---|---|---|---|
| binaire | `/usr/local/bin/plume-daemon` (posé par `bootstrap.sh`) | image `soc:latest` | image `soc:latest`, importée dans `k3s ctr` |
| base | `/var/lib/plume/db/soc.db` | `/data/soc.db` sur le volume `soc-data` | `/data/soc.db` sur le PVC `soc-data` |
| spool | `/var/lib/plume/spool` | `/data/spool` | `/data/spool` |
| fichiers de la console | `/usr/local/share/plume/web` | dans l'image | dans l'image |
| overlays `config.d` | `/usr/local/share/plume/config.d` | dans l'image, **rootfs en lecture seule** | dans l'image, **rootfs en lecture seule** |
| fichier de configuration lu par le démon | `/etc/plume/soc.conf` | **aucun** | **aucun** |
| sauvegardes | `<dir(PLUME_DB)>/backups` | `/data/backups` | `/data/backups` |

Le **défaut compilé** diffère de ce que posent les installateurs, et il faut le savoir pour lire le
code : le démon cherche sa base en `/var/lib/plume/db/plume.db` et son fichier de configuration en
`/etc/plume/plume.conf` quand rien ne les surcharge (`daemon/src/main.rs`). Sur un hôte, c'est
l'unité systemd qui pose `PLUME_CONFIG=/etc/plume/soc.conf`, et `bootstrap.sh` qui écrit
`PLUME_DB=/var/lib/plume/db/soc.db` dans ce fichier. En conteneur, ce sont les `ENV` du `Dockerfile`.

### Le niveau « fichier de configuration » est VIDE en conteneur, et c'est délibéré

La précédence est la même partout — **`environnement` > fichier de configuration > défaut compilé**
(`cfg()`, `daemon/src/main.rs`) — mais en mode `docker` **et** en mode `k3s`, le chemin du fichier
est posé à `/nonexistent` (`docker-compose.yml`, `deploy/k3s.yaml`, `Dockerfile`). La lecture échoue,
la table est vide, et **le niveau du milieu n'existe pas** : tout arrive par l'environnement.

Corollaire à ne pas manquer : `.env` **n'est pas** ce fichier de configuration. C'est
`docker compose` qui le lit, pour interpoler des valeurs dans le bloc `environment:` du service —
donc **une variable de `.env` que le bloc `environment:` n'énumère pas n'atteint jamais le
conteneur**. Le réglage semble posé et ne mord pas.

---

## 3. Le même geste, dans les trois modes

### 3.1 Atteindre la console

| | commande | remarque |
|---|---|---|
| `host` | `http://soc.localhost:7000` | `bootstrap.sh` ajoute `127.0.0.1 soc.localhost` à `/etc/hosts`, et l'écoute est sur `127.0.0.1` |
| `docker` | `http://soc.localhost:7000` | le port n'est publié que sur `127.0.0.1` de l'hôte |
| `k3s` | l'hôte de l'`Ingress` | il **doit** être identique à `PLUME_HOST`, sinon la garde anti-DNS-rebinding rend `421` |

Dans les trois cas, `PLUME_HOST` et le nom réellement demandé doivent coïncider. C'est la même
garde, appliquée au même endroit ; seule la façon d'écrire le nom change.

### 3.2 Poser ou changer un réglage `PLUME_*`

**Aucun mode n'a de geste de rechargement.** L'unité du démon n'a pas d'`ExecReload=`, et le démon
n'installe pas de gestionnaire de `SIGHUP` : il n'existe nulle part une commande qui dise au démon
« relis ta configuration ». Les deux vérifications :

```sh
grep -c ExecReload systemd/plume-daemon.service          # 0 — l'unité du démon n'en a pas
grep -rn 'SIGHUP' daemon/src --include='*.rs'            # rien
```

*(Une autre unité livrée, `plume-portscan-nft.service`, porte bien un `ExecReload=` : il recharge
une table nftables, pas la configuration de plume.)*

#### Ce qui décide vraiment : le SUPPORT, pas le geste

Le geste de rechargement manque partout, mais ce n'est pas ce qui borne le sujet. Ce qui le borne,
c'est **le support depuis lequel une nouvelle valeur pourrait être lue**. La précédence est
`environnement > fichier de configuration > défaut compilé` (`cfg()`, `daemon/src/main.rs`), et
l'environnement d'un processus **déjà lancé ne change plus** : seul le niveau « fichier » peut porter
une valeur neuve pendant la vie du démon. Or ce niveau est coupé en conteneur (§2).

| | support d'une valeur neuve, démon en marche | conséquence |
|---|---|---|
| `host` | `/etc/plume/soc.conf`, relu à chaque lecture qui passe par `load_config()` | un rechargement à chaud est **possible**, et une partie existe déjà (voir §3.7) |
| `docker` | **aucun** — `PLUME_CONFIG=/nonexistent` (`docker-compose.yml`, `Dockerfile`) | rien à relire : le rechargement à chaud est **impossible par construction**, pas seulement non implémenté |
| `k3s` | **aucun** — `PLUME_CONFIG=/nonexistent` (`deploy/k3s.yaml`) | idem ; et le pod est de toute façon **remplacé** pour appliquer un `env:` modifié |

Autrement dit : **un rechargement à chaud ne pourrait servir qu'au mode `host`.** Dans les deux
autres, changer un réglage veut dire remplacer le conteneur — le redémarrage n'est pas le prix de la
reconfiguration, il *est* le mécanisme de déploiement. C'est une limite connue et portée par une clé
ouverte — voir `P9.4-a` et `P9.6-b` dans [`ROADMAP.md`](ROADMAP.md).

| | où on écrit | ce qui applique |
|---|---|---|
| `host` | `/etc/plume/soc.conf` (`0640`, `root:soc`) — ou l'environnement de l'unité | `sudo systemctl restart plume-daemon` |
| `docker` | `.env` **et** le bloc `environment:` du service `soc` (les deux, cf. §2) | `docker compose up -d` |
| `k3s` | le bloc `env:` du `Deployment`, ou le `Secret` `soc-auth` pour un secret | `kubectl apply -f deploy/k3s.yaml` puis `kubectl -n soc rollout restart deploy/soc` |

Un **secret** se pose de préférence par fichier plutôt que par variable : sur un hôte, le fichier de
configuration `0640` n'est pas lisible via `/proc/<pid>/environ`, contrairement à l'environnement ;
en k3s, `PLUME_DB_KEY_FILE` pointe un `Secret` monté en lecture seule (les lignes sont livrées
commentées dans `deploy/k3s.yaml`).

### 3.3 Ajouter une source de collecte

C'est ici que les modes divergent le plus, et le document doit le dire au lieu de le lisser.

| | geste | réalité |
|---|---|---|
| `host` | `PLUME_EXTRA_COLLECTORS="…"` puis `bootstrap-agent.sh`, puis `systemctl enable --now plume-<x>.timer` | le geste NATIF ; c'est la procédure du [`README`](../README.md#ajouter-vos-sources-et-collecteurs) |
| `docker` | **ce geste n'existe pas** | *(voir ci-dessous)* |
| `k3s` | **ce geste n'existe pas** | *(voir ci-dessous)* |

**Mesuré sur l'arbre suivi le 2026-08-25** : le `Dockerfile` ne copie **aucun** fichier de
`collectors/` dans l'image (`grep -n collectors Dockerfile` ne rend rien), et
`PLUME_EXTRA_COLLECTORS` n'est lu que par `bootstrap-agent.sh` — nulle part dans le démon :

```sh
grep -rn 'PLUME_EXTRA_COLLECTORS' daemon/src collectors bootstrap.sh bootstrap-agent.sh Dockerfile
```

Autrement dit : **le central en conteneur n'est pas son propre agent.** Les collecteurs shell sont
un artefact d'hôte. Ce que vous faites à la place, en conteneur et en cluster :

1. **Un agent sur une machine d'à côté** qui pousse vers le central (`POST /api/ingest`, jeton
   *Bearer*) — hôte Linux avec `bootstrap-agent.sh`, agent d'endpoint de [`../agent/`](../agent/README.md),
   ou collecteur Windows de [`../collectors/windows/`](../collectors/windows/README.md) ;
2. **une source en PULL** déclarée dans la console (onglet *Connecteurs*, admin) — le démon va
   chercher, rien n'est installé nulle part ;
3. **un récepteur** que le central expose déjà : Splunk HEC, OTLP, syslog
   ([`../deploy/SYSLOG.md`](../deploy/SYSLOG.md)).

Ces trois chemins existent dans les trois modes. C'est le **quatrième** — installer un script sur la
machine du central — qui n'existe qu'en mode hôte.

### 3.4 Ajouter un parseur, une règle, un playbook

| | par fichier | par la console |
|---|---|---|
| `host` | déposer sous `PLUME_CONFIG_DIR` (`/usr/local/share/plume/config.d`) puis redémarrer | oui, rôle admin ; la ligne est marquée « perso » |
| `docker` | **impossible sans reconstruire l'image ou monter un volume** — la racine du conteneur est en lecture seule | oui, même geste |
| `k3s` | par une `ConfigMap` montée sur `PLUME_CONFIG_DIR`, sinon impossible | oui, même geste |

Les deux chemins ne produisent pas la même chose, et c'est délibéré : un overlay de fichier est
marqué `managed=1` (source = le dépôt versionné), une création par la console est marquée
`managed=2` (perso). **Un homonyme perso fait IGNORER l'overlay de fichier**, avec un avertissement
au démarrage, plutôt que d'écraser silencieusement le travail de l'opérateur
(`daemon/src/overlays.rs`). En conteneur et en cluster, où le fichier est difficile, **la console
est le chemin normal** — et le fichier reste la source durable là où il est praticable.

### 3.5 Créer un jeton d'agent

La même sous-commande, atteinte de trois façons.

| | commande |
|---|---|
| `host` | `sudo /usr/local/bin/plume-daemon token <nom> <hôte-lié>` |
| `docker` | `docker compose exec soc plume-daemon token <nom> <hôte-lié>` |
| `k3s` | `kubectl -n soc exec deploy/soc -- plume-daemon token <nom> <hôte-lié>` |

*Non exécutées sur une installation réelle dans ce lot* — la forme à deux arguments et le drapeau
`--relais` sont ceux décrits dans le [`README`](../README.md#b-hôte-nu-systemd--mode-de-première-classe-sans-docker).
Le jeton s'affiche une fois ; il ne se relit pas.

> ⚠️ **Le jeton ne passe JAMAIS par la ligne de commande côté agent**, dans aucun mode : `sudo`
> journalise sa ligne complète et le collecteur `journal` la renvoie au SOC, qui la stocke en clair.
> La forme sûre — écriture par `tee` — est dans le [`README`](../README.md#-ne-passez-jamais-le-token-sur-la-ligne-de-commande).

### 3.6 Lire les journaux du démon

| | commande |
|---|---|
| `host` | `journalctl -u plume-daemon -f` |
| `docker` | `docker compose logs -f soc` |
| `k3s` | `kubectl -n soc logs -f deploy/soc` |

C'est là que se lit le **token d'installation** du mode SETUP quand aucun `PLUME_PASS_HASH` n'est
posé. En mode hôte il est aussi écrit à côté de la base
(`/var/lib/plume/db/setup-token.txt`, cf. `bootstrap.sh`).

### 3.7 Sauvegarder

**Les deux orchestrateurs de sauvegarde n'ont pas la même sortie**, et c'est le piège de ce
chapitre. Le détail — enveloppe, ordre des opérations, ce qui est chiffré et ce qui ne l'est pas —
est dans [`CHIFFREMENT-COMPRESSION.md`](CHIFFREMENT-COMPRESSION.md) ; la restauration est dans
[`DR-plume-restore.md`](DR-plume-restore.md).

| | ce qui déclenche | ce qui sort |
|---|---|---|
| `host` | `plume-backup.timer` (quotidien) → `plume-daemon backup` | une copie compacte, **non compressée**, rotation à 7 |
| `docker` | le planificateur interne au démon, si `PLUME_BACKUP_INTERVAL > 0` | l'enveloppe du planificateur |
| `k3s` | idem, `PLUME_BACKUP_INTERVAL` posé dans le manifeste livré | idem |

Pour **aligner un hôte sur le planificateur interne** : posez `PLUME_BACKUP_INTERVAL` dans
`/etc/plume/soc.conf` et coupez le timer (`systemctl disable --now plume-backup.timer`). Laisser les
deux en marche produit deux familles de sauvegardes dans le même répertoire, avec deux rotations
indépendantes.

#### Changer un réglage de sauvegarde : deux groupes, pas un

Les réglages `PLUME_BACKUP_*` **ne se rechargent pas tous de la même façon**, et la différence est
invisible depuis leur nom. Relevé sur l'arbre suivi le 2026-08-27 :

| Groupe | Clés | Quand la valeur est lue |
|---|---|---|
| chiffrement et séquestre | `AGE_RECIPIENT` · `REQUIRE_ASYMMETRIC` · `FORCE_PLAINTEXT_EXPORT` · `SCRYPT_LOG_N` · `STAGING_DIR` · `AGE_IDENTITY[_FILE]` | **à chaque cycle** (`reglage_sauvegarde`, `daemon/src/backup/mod.rs`) |
| activation, cadence, cible, rétention | `INTERVAL` · `DEST` · `KEEP` · `ON_START` | **une seule fois**, au lancement du fil (`spawn_backup_scheduler`, `daemon/src/server/sauvegarde_planifiee.rs`) |

Conséquence, **en mode `host` uniquement** (c'est le seul mode où le niveau « fichier » existe, §3.2) :
corriger un destinataire d'escrow dans `/etc/plume/soc.conf` mord **dès le cycle suivant, sans
redémarrage**. Corriger l'intervalle, la destination ou la rétention **exige** de redémarrer. En
`docker` et en `k3s`, les deux groupes exigent de remplacer le conteneur, faute de support à relire.

#### Ce que le redémarrage coûte, et qui n'est écrit nulle part ailleurs

> ⚠️ **Redémarrer le démon remet la cadence de sauvegarde à zéro.** Le planificateur ne garde aucune
> trace de sa dernière exécution : il attend 90 s (le temps du bind et de la *liveness*), puis dort un
> intervalle **entier** avant son premier cycle — `PLUME_BACKUP_ON_START` valant `0` par défaut et
> n'étant posé nulle part dans `deploy/k3s.yaml`. Avec l'intervalle livré (`21600` s, soit 6 h, dans
> `deploy/k3s.yaml`, `docker-compose.yml` et `.env.example`), **chaque redémarrage repousse la
> prochaine sauvegarde de 6 h 1 min 30 s**, et rien ne le dit.
>
> Le cas qui fait mal n'est pas la reconfiguration volontaire, c'est la **churn** : un pod qui
> redémarre plus souvent que son intervalle — déploiement, `rollout restart`, éviction, nœud
> `NotReady`, `OOMKill` — **ne produit jamais aucune archive**, pendant que la console annonce une
> rétention « 24 × 6 h » à côté d'un répertoire vide. Le signal SOC qui dénonce un cycle stérile
> (`P9.4-b`) n'aide pas ici : il n'est émis que par un cycle qui **s'exécute** et échoue, jamais par un
> cycle qui n'a pas encore eu lieu.
>
> Ce qu'on peut faire aujourd'hui : poser `PLUME_BACKUP_ON_START=1` — au prix d'une sauvegarde à
> chaque redémarrage, ce qui est une tempête si le processus boucle — ou **vérifier le répertoire
> plutôt que le réglage**, dans les trois modes :
> ```sh
> ls -la "$PLUME_BACKUP_DEST"     # host ; docker/k3s : la même commande via `exec` (§3.5)
> ```
> Un `PLUME_BACKUP_DEST` sans `plume-<TS>.db.age` est un déploiement **sans sauvegarde**, quelle que
> soit la rétention annoncée à côté.

### 3.8 Chiffrer la base au repos

Le geste est identique dans son principe — poser une clé **avant le premier démarrage** — et diffère
par le support. Par défaut, **dans les trois modes, la base est en clair sur le disque**.

| | comment |
|---|---|
| `host` | `PLUME_DB_KEY_FILE=/chemin/vers/la/cle` dans `/etc/plume/soc.conf` |
| `docker` | `PLUME_DB_KEY` via `.env` (déjà énuméré dans `environment:`), ou un fichier monté et `PLUME_DB_KEY_FILE` |
| `k3s` | le `Secret` `soc-auth`, monté en lecture seule ; les lignes sont livrées **commentées** dans `deploy/k3s.yaml` |

Le fichier est préférable à la variable dans les trois modes : l'environnement d'un processus est
lisible via `/proc/<pid>/environ`. **Perte de la clé = perte de la base.**

### 3.9 Mettre à jour

| | geste |
|---|---|
| `host` | recompiler (`cargo build --release` — **build nu : deux capacités en moins**, cf. sous la table), rejouer `bootstrap.sh` (idempotent) |
| `docker` | `docker compose up -d --build` |
| `k3s` | reconstruire l'image, la réimporter dans `k3s ctr`, puis `kubectl -n soc rollout restart deploy/soc` |

**Ces trois lignes ne reconstruisent pas le même binaire, et la table seule ne le montre pas.** Les deux
lignes qui passent par l'image héritent d'un jeu de features déclaré une fois pour
toutes — `ARG PLUME_FEATURES=ldap,cold_tier` dans le [`Dockerfile`](../Dockerfile), depuis `971de7a`
(2026‑08‑08). La ligne `host` est **nue** et n'en prend **aucune**. Un binaire hôte bâti ainsi n'a **ni le
tier froid colonnaire** — `PLUME_COLD_TIER` y est sans effet, et les fichiers‑jour Parquet écrits par un
autre binaire lui sont invisibles — **ni le bind LDAP/AD natif** : `POST /api/auth/ldap` répond **501**.
Les prendre : `cargo build --release --features cold_tier,ldap`. Le défaut nu est **assumé, pas
accidentel** (le coût de construction de `cold_tier` n'est borné par aucun chiffre mesuré ; l'en‑tête de
`bootstrap.sh` le dit), mais il ne doit pas être **subi** : c'est pourquoi `bootstrap.sh` **mesure** en fin
d'installation ce que le binaire posé porte — verdict `>> Capacités optionnelles`, obtenu en interrogeant
`plume-daemon --help` — et **refuse de conclure** plutôt que d'annoncer une capacité non prouvée. Ce
constat automatique ne couvre que le tier froid ; pour l'annuaire, la preuve est la réponse **501** de la
route de login.

**Aucune image et aucun binaire ne sont publiés à ce jour** : les trois chemins compilent depuis les
sources. C'est un manque assumé, écrit dans le [`README`](../README.md#installation).

Une mise à jour qui change le schéma de la base est une **porte à sens unique** : elle demande une
sauvegarde vérifiée avant, et un acquittement explicite. Voir [`DR-plume-restore.md`](DR-plume-restore.md).

### 3.10 Désinstaller

Un seul outil, trois modes, le mode se **désigne** :

```sh
bash uninstall.sh --dry-run                  # inventaire des trois modes, sans root, sans rien modifier
sudo bash uninstall.sh --mode host
sudo bash uninstall.sh --mode docker
bash uninstall.sh --mode k3s --apply
```

**La première ligne a été exécutée telle quelle sur cet arbre** : elle sonde les trois modes, ne
modifie rien, et sort en `0`. Sur une machine sans cluster joignable, elle ne conclut PAS « il n'y a
rien » — elle range k3s parmi les *sondages impossibles* et le dit. Les trois autres, qui écrivent,
**n'ont pas été jouées dans ce lot**.

La sémantique complète — ce que `--purge` détruit, les codes de sortie, ce qui résiste et pourquoi —
est dans le [`README`](../README.md#désinstallation--les-trois-modes). Le mode `k3s` **imprime** son
plan et n'exécute qu'avec `--apply`, parce qu'il touche un cluster partagé.

---

## 4. Les gestes qui n'existent pas, nommés

Un tableau d'équivalences est malhonnête s'il remplit toutes ses cases. Voici celles qui restent
vides, et pourquoi.

| Geste | Absent en | Raison mesurée |
|---|---|---|
| installer un collecteur shell sur la machine du central | `docker`, `k3s` | `collectors/` n'est pas copié dans l'image (`Dockerfile`) |
| déposer un overlay `config.d` par le système de fichiers | `docker` | racine du conteneur en lecture seule (`read_only: true`) |
| lire un réglage depuis un fichier de configuration | `docker`, `k3s` | `PLUME_CONFIG=/nonexistent` — délibéré, cf. §2 |
| éditer `/etc/hosts` pour la résolution locale | `k3s` | la résolution passe par l'`Ingress` et le DNS du cluster |
| appliquer une `NetworkPolicy` d'egress | `host`, `docker` | c'est un objet Kubernetes ; l'équivalent hôte est le pare-feu de la machine |
| recharger l'activation, la cadence, la cible ou la rétention de sauvegarde sans redémarrer | **les trois** | lues une seule fois au lancement du fil (`spawn_backup_scheduler`) — cf. §3.7 |
| recharger **quoi que ce soit** sans redémarrer | `docker`, `k3s` | aucun support à relire : environnement figé + `PLUME_CONFIG=/nonexistent` — cf. §3.2 |
| demander un rechargement par un signal ou une commande | **les trois** | pas d'`ExecReload=`, pas de `SIGHUP` — cf. §3.2 |

---

## 5. Pourquoi c'est ainsi

**Un seul binaire, trois enveloppes.** Un seul *programme* — mais pas forcément le même jeu de capacités
**compilées** : le build de l'image en prend deux que la recette hôte laisse (cf. §3.9). Le démon, lui, ne
sait pas dans quel mode il tourne, et c'est voulu : il lit des variables et des chemins, rien d'autre.
Tout ce qui distingue les *modes* vit **hors** du binaire — dans une unité systemd, dans un
`docker-compose.yml`, dans un manifeste. Le prix de ce choix est exactement ce document : les gestes
d'exploitation, eux, diffèrent.

**Le niveau « fichier » est coupé en conteneur pour une raison.** Laisser le démon lire
`/etc/plume/plume.conf` dans une image où ce fichier n'existe pas ferait dépendre le comportement
d'un fichier que personne ne versionne, et qu'un `docker cp` malheureux pourrait créer. `/nonexistent`
rend le niveau **explicitement** vide plutôt qu'accidentellement vide.

**On installe sans activer.** C'est la règle d'or du mode hôte : `bootstrap-agent.sh` pose des
capteurs sans armer leurs timers, et c'est l'opérateur qui décide. En conteneur, la règle prend une
autre forme — les récepteurs existent mais n'ingèrent que ce qu'on leur envoie, et les connecteurs
en PULL sont créés un par un dans la console.

**Le mode cluster dit quoi faire plutôt que de le faire.** Un cluster est partagé ; un outil qui y
applique un plan sans le montrer engage des ressources qui ne lui appartiennent pas. C'est pourquoi
`uninstall.sh --mode k3s` imprime et n'exécute que sur demande — et c'est le même principe qui fait
qu'aucun geste de ce document ne modifie un manifeste à votre place.

---

## 6. Ce qui n'a pas été exécuté

Honnêteté d'instrument : les faits de structure de ce document (chemins, variables, absence de
`collectors/` dans l'image, absence d'`ExecReload=`, valeur de `PLUME_CONFIG`) sont **lus dans
l'arbre suivi** et chacun porte la commande qui le redonne. En revanche, **aucune des séquences de
déploiement n'a été jouée sur une machine dans ce lot** : les commandes `docker compose`, `kubectl`
et `systemctl` sont reprises des manifestes et des installateurs livrés, pas d'un déploiement
observé. Un geste qui échouerait chez vous est un défaut à signaler, pas une faute de lecture de
votre part.
