# Chiffrement et compression, tels qu'ils sont

Ce document décrit **l'état du code**, pas une intention. Chaque affirmation vient d'une lecture des
sources, et la commande qui la redonne est écrite à côté. Là où le code ne prouve rien, c'est écrit
« **non établi** » plutôt que comblé par une vraisemblance : une propriété de sécurité annoncée et
non tenue est pire qu'une propriété absente.

Il ne remplace ni [`DR-plume-restore.md`](DR-plume-restore.md) — le runbook de restauration, qui
reste la référence pour *rétablir* — ni [`../deploy/CONFIDENTIALITE.md`](../deploy/CONFIDENTIALITE.md),
qui donne la posture. Il répond à : **qu'est-ce qui est chiffré, par quoi, dans quel ordre, et
qu'est-ce qui ne l'est pas.**

---

## 1. La base au repos : neuve → chiffrée ; existante → jamais touchée par un démarrage

**Une base neuve naît chiffrée. Une base existante n'est jamais convertie par un démarrage.** Ce sont
les deux moitiés de `P9.6-a`, et elles sont indépendantes. SQLCipher est compilé dans le binaire —
inconditionnellement, ce n'est pas une *feature* de compilation (`daemon/Cargo.toml`, `rusqlite` avec
`bundled-sqlcipher-vendored-openssl`).

```sh
grep -n 'bundled-sqlcipher' daemon/Cargo.toml
grep -n 'PRAGMA key' daemon/src/crypto/mod.rs daemon/src/db_open.rs
```

### Les trois leviers, et l'ordre entre eux

L'ordre de précédence est écrit **une fois**, dans le code, comme un tableau dont l'ordre EST la
règle (`daemon/src/crypto/mod.rs`) :

| Levier | Ce que c'est | Comportement |
|---|---|---|
| `PLUME_DB_KEY_FILE` | chemin d'un fichier-clé que **vous** fournissez | **préféré** ; s'il est posé mais illisible, vide ou non-UTF8 → message `[FATAL]` et **arrêt du processus**, sans repli sur les autres leviers |
| `PLUME_DB_KEY` | la passphrase elle-même | repli ; lisible via `/proc/<pid>/environ` si elle vient de l'environnement |
| `PLUME_DB_KEY_AUTO_PATH` | chemin où le démon **engendre** et relit sa propre clé | dernier recours ; vide → `<PLUME_DB>.key`. La clé n'est engendrée **que** sur une base absente ou vide, et **jamais** ailleurs |
| `PLUME_DB_KEY_ESCROWED` | acquittement de mise à l'abri (`1/true/yes/on`) | tant qu'il est absent, chaque ouverture de la base écrit un événement de posture **non purgeable** |

### La propriété qui décide « base neuve », et pourquoi elle ne peut pas se tromper dans le sens dangereux

Se tromper en disant *existante* d'une base neuve la laisse en clair : c'est le défaut d'avant, sans
aggravation. Se tromper dans l'autre sens engendrerait une clé pour une base qui n'en a pas — et le
démarrage suivant lui appliquerait un `PRAGMA key` qu'elle ne comprend pas. La fonction
`etat_du_fichier_de_base` est donc écrite pour que la seconde erreur n'existe pas :

* `Neuve` exige **deux absences indépendantes** : le fichier principal absent ou de longueur zéro,
  **et** aucun compagnon SQLite (`-wal`, `-shm`, `-journal`) portant des octets ;
* **toute** erreur de `metadata` autre que « absent » rend `Indecidable`, qui ne fait rien — c'est le
  correctif `S32` appliqué ici dès l'écriture, plutôt que le verdict le plus rassurant ;
* et même si le verdict était faux, la clé engendrée **ne peut pas atteindre** le chemin qui réécrit
  une base : `ensure_encrypted` décide sur `db_key_depuis` (clé explicite), la clé engendrée n'entre
  que par `db_key()` (clé d'ouverture). La conséquence d'une erreur serait un refus de démarrer, pas
  une conversion.

### Une nouvelle façon de tout perdre, et ce que le produit en dit

Avant `P9.6-a`, perdre un fichier de clé n'avait aucun effet sur un déploiement livré tel quel :
il n'y en avait pas. Désormais, **perdre la clé d'une base chiffrée, c'est perdre le SOC entier et
toutes ses archives, définitivement** — la sauvegarde compressée emploie la même clé comme passphrase.

Le produit le dit **deux fois**, et jamais par une simple ligne de journal :

1. **à l'engendrement** : un message qui nomme le fichier, dit contre quoi le chiffrement protège
   (vol de disque, image de volume, stockage mal décommissionné) et contre quoi il ne protège pas
   (machine compromise, où la clé est lisible à côté de la base) ;
2. **ensuite, tant que rien n'atteste la mise à l'abri** : un **événement de posture non purgeable**
   (`source=plume-config`, `category=health`, `origin=daemon`, sévérité 4, au plus un par heure),
   qu'un exploitant **ne peut pas effacer** — même mécanisme que « sauvegarde symétrique » et
   « cycle sans archive ». Il s'arrête quand `PLUME_DB_KEY_ESCROWED=1` est posé.

**Ce que cet acquittement vaut, écrit sans complaisance :** une *déclaration*. Le produit ne peut pas
vérifier qu'une copie de la clé existe ailleurs, et il ne le prétend pas — le message du signal le dit
lui-même.

```sh
# lire la clé engendrée pour la mettre à l'abri (Docker)
docker compose exec soc cat /data/plume-at-rest.key
# … puis poser PLUME_DB_KEY_ESCROWED=1 dans .env
```

Chacun se lit par `cfg()`, donc avec la précédence commune au produit — `environnement` > fichier de
configuration > défaut — ce qui veut dire que **sur un hôte, la clé peut vivre dans
`/etc/plume/soc.conf`** en `0640`, hors de l'environnement du processus. *Ce n'était pas vrai avant
le correctif `P8.7-b` : la base chaude ne lisait que l'environnement pendant que le tier froid lisait
aussi le fichier — une moitié chiffrée, l'autre en clair, sans que rien le dise.*

Le contenu du fichier est lu **verbatim** : le `\n` final n'est pas retiré, délibérément, pour que
`fichier` et `environnement` portant le même secret donnent le même octet-à-octet.

### Ce que le code vérifie, et ce qu'il ne vérifie pas

**Les permissions d'un fichier-clé que VOUS fournissez ne sont pas contrôlées.** La lecture de
`PLUME_DB_KEY_FILE` est un `read` nu ; aucun contrôle de mode, aucun contrôle de propriétaire. Un
fichier-clé lisible par tous sera accepté sans un mot. C'est à l'opérateur de poser les droits.

**La clé que le démon ENGENDRE, elle, est posée en `0600` et ses droits sont RELUS.** Le fichier est
créé avec `create_new(true)` — il n'écrase jamais un fichier existant, ce qui rend aussi inoffensive
la course entre deux démarrages simultanés — et le mode est demandé **à la création**, pas par un
`chmod` d'après coup qui laisserait une fenêtre. Si le système de fichiers n'honore pas les droits
POSIX (un montage `fat`, `9p`…), **la clé est retirée** et le démon refuse de démarrer plutôt que de
la laisser lisible. La pose est **fermée** : toute erreur d'écriture, de synchronisation ou de droits
donne un `[FATAL]` et un `exit 78`, jamais une base créée en clair en silence.

```sh
grep -rn '0o600' daemon/src --include='*.rs' --exclude-dir=tests
grep -n 'create_new' daemon/src/crypto/mod.rs
```

### Les paramètres du chiffrement ne sont pas choisis par ce dépôt

**Aucun réglage SQLCipher n'est surchargé** : ni `kdf_iter`, ni `cipher_page_size`, ni
`cipher_hmac_algorithm`, ni `page_size`. Les valeurs en vigueur sont donc **celles par défaut de la
version de SQLCipher vendorée** par `libsqlite3-sys`, pas des choix de plume.

```sh
grep -rn 'cipher_page_size\|kdf_iter\|cipher_hmac\|cipher_kdf' daemon/src   # rien
```

Conséquence à ne pas laisser dans l'ombre : **le KDF de SQLCipher n'est pas *memory-hard***. Le code
le dit lui-même, en tête du module de sauvegarde. Une passphrase faible protège donc mal une base
volée, quelle que soit la solidité du chiffrement lui-même.

La clé est toujours passée **en forme passphrase** (`PRAGMA key = '<chaîne>'`), jamais en forme clé
brute `x'<64 hexa>'` — y compris pour une clé de tenant, qui est pourtant 32 octets d'entropie
encodés en hexadécimal. SQLCipher lui applique donc son KDF. *Les conséquences exactes de ce choix
relèvent du comportement de SQLCipher et **ne sont pas établies** par lecture de ce dépôt.*

### Convertir une base existante : un geste explicite, irréversible, et ce qu'il exige avant de partir

**Aucun démarrage ne convertit une base existante.** Ni poser une clé, ni la changer, ni monter
d'image ne réécrit une base déjà en service. Si une clé est configurée et que la base est **en clair**,
le démon **refuse de démarrer** (`[FATAL]`, `exit 78`), ne touche à rien, et nomme le geste.

*C'est un changement de comportement par rapport à l'état antérieur, et il est délibéré : la
conversion se faisait alors au démarrage, sans sauvegarde, sans preuve d'équivalence et sans contrôle
de place. Franchir une porte à sens unique sur les données vivantes d'un SOC parce qu'une variable
d'environnement a changé n'est pas une commodité, c'est un risque.*

Le geste est `plume-daemon chiffrer-au-repos` (moteur : `convertir_la_base_au_repos`,
`daemon/src/crypto/mod.rs`). Il **refuse de partir** tant que les préconditions ne sont pas réunies :

| Précondition | Ce qu'elle établit |
|---|---|
| une clé **explicite** (`PLUME_DB_KEY_FILE` ou `PLUME_DB_KEY`) | la clé vient de vous ; le produit ne convertit jamais vers une clé qu'il se serait donnée lui-même |
| `PLUME_DB_KEY_ESCROWED=1` | vous **déclarez** que la clé est copiée hors de la machine |
| la base est bien **en clair** | `OpensWithKey` → rien à faire (le geste est idempotent) ; verrouillée → refus, arrêtez le démon d'abord |
| **la place** : `2,4 ×` la taille de la base | la copie chiffrée, l'archive de sécurité, et la base jetable de sa vérification. La mesure **indisponible** vaut refus, pas fail-open |

Puis, dans cet ordre — et **l'ordre est inhabituel pour une raison mesurée** :

1. point de contrôle du WAL sur l'original (un repli refusé = refus, sans rien toucher) ;
2. `sqlcipher_export` vers `<db>.conversion-en-cours`, **un nom que le démon n'ouvre jamais** ;
3. **équivalence prouvée**, quatre lectures toutes dérivées du schéma : `PRAGMA integrity_check` sur
   la copie ; l'empreinte `sqlite_master` objet par objet, dans les deux sens ; le compte de **chaque**
   table de données (pas un total — deux erreurs qui se compensent passeraient un total) ; et la
   **chaîne du journal inaltérable**, revérifiée sur la copie ;
4. **sauvegarde produite ET vérifiée** — voir ci-dessous ;
5. **bascule** : un lien dur sur l'original, puis **un seul `rename`**, atomique ;
6. la conversion **s'inscrit au journal inaltérable** (`at_rest.converted`) avec ce qui a été vérifié ;
7. la copie en clair est effacée (écrasement + `unlink`).

**Pourquoi la sauvegarde est prise depuis la COPIE et non depuis l'original.** *La séquence évidente —
sauvegarder, puis convertir — est réfutée par la mesure* : `backup_compressed` ouvre sa source **avec
la clé** (`PRAGMA key`), et une base en clair devient alors illisible (`SQLITE_NOTADB`) ; sans clé, il
refuse dès sa première instruction. **Le produit ne sait pas sauvegarder une base en clair** — c'est
exactement le cul-de-sac nommé par `P9.4-b`. La séquence tenable est donc : exporter → prouver
l'équivalence → sauvegarder et vérifier **depuis la copie** → basculer.

**Ce que cette précondition établit** : une archive existe à `PLUME_BACKUP_DEST` ; elle se déchiffre ;
elle se **rejoue** dans une base neuve ; et cette base restaurée rend le **même nombre de lignes** que
la copie qui va devenir la base vivante. Ce compte est confronté à celui produit par l'**autre**
dérivation du produit (`verify_backup` → `inventaire_restaure`) : si les deux lectures de « quelles
tables portent les données » divergeaient, la conversion refuserait.

**Ce qu'elle n'établit PAS** : que l'archive soit stockée **hors** de la machine (sans destinataire
`age`, elle est chiffrée par passphrase et la machine la déchiffre) ; qu'une restauration réussisse
ailleurs, sur un autre matériel ou un autre binaire ; que les lignes soient **sémantiquement** justes
— seul leur nombre est comparé ; ni que l'archive survive à la rétention *keep-N*.

**Le mode asymétrique sans identité privée est refusé**, et c'est le point le plus important :
`verify_backup` dégrade alors en contrôle **structurel**, qui dit « l'en-tête est bien formé », pas
« des lignes en reviennent ». Accepter ce verdict comme précondition d'une porte à sens unique serait
exactement ce que `P8.3-a` a nommé : un contrôle vert qui porte le mot « restore » sans avoir rien
restauré. Fournissez `PLUME_BACKUP_AGE_IDENTITY_FILE` le temps de la conversion, ou convertissez avec
une archive symétrique vérifiable sur place.

**Aucun état intermédiaire n'est démarrable**, et c'est structurel : la copie vit sous un nom que le
démon n'ouvre jamais, l'original garde le sien jusqu'au `rename`, et il n'existe **aucun instant** où
`PLUME_DB` désigne un fichier à moitié écrit. Le lien dur avant la bascule n'est pas un détail : deux
`rename` successifs ouvriraient une fenêtre où `PLUME_DB` n'existe pas — et un démarrage y créerait une
base **vide, chiffrée, d'apparence saine**.

**Ce qui est réversible, et ce qui ne l'est pas.** Avant la bascule : **tout**. Chaque échec laisse
l'original intact, et retirer la clé de la configuration remet le déploiement dans son état exact — la
base n'a pas bougé d'un octet. Après la bascule : **rien**. Il n'existe **aucun déchiffrement au
repos** dans ce produit, et la seule voie de reprise est l'archive vérifiée à l'étape 4.

### Multi-tenant

Une base **et une clé par tenant**, 32 octets d'entropie du système d'exploitation, sans repli sur
l'horloge si aucune source d'entropie n'est disponible. La référence de clé se résout **avant** toute
création (fail-closed), et l'oubli de la clé fait partie du geste de destruction d'un tenant
(`daemon/src/tenants.rs`).

---

## 2. Ce qui n'est PAS chiffré — la table

C'est la partie la plus utile de ce document, et la plus facile à oublier.

| Ce qui touche le disque | Chiffré ? | Établi par |
|---|---|---|
| base chaude | **oui, si et seulement si une clé est posée** | `daemon/src/crypto/mod.rs` |
| temporaires de tri SQLite | **rien n'est écrit par défaut** (`temp_store=MEMORY`) ; avec `PLUME_SQLITE_DEVERSEMENT=1` → `temp_store=FILE`, et **les valeurs partent en clair, hors de la base SQLCipher** | `daemon/src/sqlite_plafond.rs` |
| WAL de la base principale | **non établi** — rien dans ce dépôt ne le pose ni ne le vérifie ; c'est une propriété de SQLCipher | — |
| spool d'ingestion du démon | **non** — le corps HTTP est écrit tel quel, puis mis en `0600` | `daemon/src/ingest/mod.rs` |
| spool de l'agent | **non** — aucune caisse de chiffrement de fichier dans `agent/Cargo.toml`, seulement du TLS de transport | `agent/Cargo.toml` |
| tier froid Parquet | **oui**, et **fail-closed** : sans clé, aucun fichier n'est écrit | `daemon/src/cold_store/` |
| sauvegarde par le planificateur / `backup --compress` | **oui** (age) — voir §3 | `daemon/src/backup/` |
| sauvegarde par `plume-daemon backup` sans `--compress` | **hérite de l'état de la source** : le code n'applique aucune clé à la destination, il exécute `VACUUM INTO`. *Que la copie soit chiffrée est une propriété de `VACUUM INTO` sous SQLCipher — **non établie** par ce dépôt, aucun test ne la vérifie.* | `daemon/src/main.rs` |
| staging d'une sauvegarde compressée | **rien n'est écrit par défaut** (dump typé en flux) ; sur le chemin de repli — déclenché par `PLUME_FTS_FIELDS=1`, ou forcé par `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT` — **la base ENTIÈRE est réécrite en clair** le temps du cycle, puis effacée par écrasement. Voir §3.2 | `daemon/src/backup/mod.rs` |
| export du journal d'audit | **non** — JSONL servi en clair | `daemon/src/handlers/governance.rs` |
| réponses de l'API | en clair, sauf TLS (`PLUME_TLS_CERT`/`PLUME_TLS_KEY`) | — |

Le **déversement des tris** mérite une phrase de plus, parce que c'est un échange et non un défaut :
`temp_store=FILE` laisse SQLite trier sur disque au lieu d'échouer sous le budget mémoire, mais
SQLCipher **ne chiffre pas les temporaires**. C'est pourquoi le levier est **opt-in** et ne sera
jamais le défaut. Le répertoire est mis en `0700` ; **il n'est borné par aucun quota**.

---

## 3. L'enveloppe de sauvegarde

### 3.1 Deux orchestrateurs, deux sorties — et ils ne produisent pas la même chose

| | ce qui déclenche | ce qui sort | compression | chiffrement |
|---|---|---|---|---|
| timer d'hôte | `plume-backup.timer` → `collectors/backup.sh` → `plume-daemon backup <dest>` | `plume-<horodatage>.db`, rotation à 7 | **aucune** | hérité de la source |
| planificateur interne | `PLUME_BACKUP_INTERVAL > 0` | `plume-<horodatage>.db.age`, rétention *keep-N* | zstd | age |

Le script du timer appelle la sous-commande **sans** `--compress` ; c'est lui, et non le binaire, qui
forme le nom de fichier.

```sh
grep -n 'plume-daemon backup' collectors/backup.sh
grep -n 'db.age' daemon/src/server/sauvegarde_planifiee.rs
```

### 3.2 L'ordre : on compresse d'abord, on chiffre ensuite

La chaîne d'écriture, lue de l'extérieur vers l'intérieur, est sans ambiguïté dans le code : le
fichier reçoit **age**, qui enveloppe **zstd**, qui reçoit la charge.

```
charge  →  zstd  →  age  →  fichier          soit :  age( zstd( charge ) )
```

C'est l'ordre utile : compresser après avoir chiffré ne gagnerait rien, un texte chiffré étant
incompressible. La lecture est symétrique — déchiffrement age, puis décompression zstd.

La **charge**, elle, a deux formes, distinguées **par un marqueur en tête, jamais par le nom du
fichier** : un dump typé en flux (le défaut, qui n'écrit aucun clair transitoire) ou une copie SQLite
complète (chemin historique, atteint par repli automatique quand un schéma n'est pas représentable
en dump typé).

**CE QUI FAIT BASCULER SUR LE CHEMIN HISTORIQUE, ET CE QUE CE CHEMIN ÉCRIT.** *Établi par lecture des
sources le 2026-08-30.* Le repli n'est pas théorique : il est déclenché par une **table virtuelle FTS
sans table de contenu**. `collect_dump_plan` ne sait recréer une vtable FTS que lorsqu'elle s'adosse
à une table ordinaire — c'est le cas de `event_fts` (`content='event'`) — et rend
`PlanErr::Unsupported` pour toute autre forme. Or `PLUME_FTS_FIELDS=1` crée précisément une vtable
`content=''` (`event_fields_fts`). Le repli exécute alors `sqlcipher_export`, qui **réécrit la base
ENTIÈRE EN CLAIR** dans le répertoire de staging le temps du cycle, avant de la compresser et de la
chiffrer. Le fichier est effacé par écrasement (garde `Drop`) et un balayage réape les orphelins d'un
processus tué, mais **la fenêtre existe et elle revient à chaque cycle**. Trois conséquences :

- **activer l'indexation plein texte des CHAMPS est un échange performance ↔ confidentialité**, pas
  un arbitrage de mémoire — c'est la vraie raison pour laquelle `PLUME_FTS_FIELDS` vaut `0` par
  défaut, et le même genre d'échange explicite que `PLUME_SQLITE_DEVERSEMENT` (§2) ;
- la ligne de journal de chaque cycle **dit quel chemin a tourné** (`clair-sur-disque=OUI/non`) :
  c'est le seul moyen de savoir laquelle des deux formes votre installation produit ;
- `PLUME_BACKUP_STAGING_DIR` déplace ce clair transitoire — sur un volume éphémère, par exemple —
  et `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT` force le chemin historique sans recompiler.

```sh
grep -n "content=''" daemon/src/maintenance.rs
sed -n '/fn collect_dump_plan/,/Unsupported/p' daemon/src/backup/dump_restauration.rs | tail -5
grep -n 'sqlcipher_export' daemon/src/backup/mod.rs
```

| Constante | Valeur littérale | Où |
|---|---|---|
| niveau zstd de la sauvegarde | **7** | `daemon/src/backup/mod.rs` |
| tampon de flux | **1 Mio** | `daemon/src/backup/mod.rs` |
| caisse de compression | `zstd` | `daemon/Cargo.toml` |
| caisse de chiffrement | `age` | `daemon/Cargo.toml` |
| facteur scrypt écrit (mode passphrase) | **12**, borné à `[10, 20]` en lecture | `daemon/src/backup/mod.rs` |

*Le gain de compression consigné dans les commentaires du code, sur une base de test, est de l'ordre
de **×2,4** face au format historique, contre un surcoût de restauration.*

### 3.3 Symétrique ou asymétrique : ce qui change, ce n'est pas « chiffré »

| Mode | Condition | Qui peut déchiffrer |
|---|---|---|
| **asymétrique** | `PLUME_BACKUP_AGE_RECIPIENT` posé (clé **publique** `age1…`, non secrète) | le détenteur de l'identité privée, **qui n'a pas à être sur la machine** — c'est un séquestre |
| **symétrique** | aucun destinataire | **la machine elle-même** : la passphrase EST la clé SQLCipher, présente sur le nœud |

Le repli symétrique n'est pas silencieux. Trois choses se produisent, toutes portées par le code :

1. un avertissement bruyant à chaque archive — *« ce backup est DÉCHIFFRABLE PAR LE NŒUD : PAS
   d'escrow hors-cluster »* ;
2. un **événement SOC non purgeable** de posture (`category=health`, sévérité maximale, champs
   `backup_encryption=symmetric`, `node_decryptable=true`), dédupliqué à l'heure, émis **seulement
   quand une archive a réellement été publiée** ;
3. `PLUME_BACKUP_REQUIRE_ASYMMETRIC=1` **refuse** ce repli — et le refus tombe **avant toute
   écriture**, sur les deux chemins, pour ne pas produire un fichier qu'on rejetterait ensuite.
   Défaut : `0`.

### 3.4 La précondition du chemin compressé : une clé de base, et d'où elle vient

**ÉTABLI PAR LECTURE DE L'ARBRE SUIVI le 2026-08-30** — par les sources et leurs littéraux, aucun
cycle n'ayant été observé (§6). C'est le point le plus important de ce document pour un exploitant,
parce qu'il décide si une archive existe — et **la réponse dépend de l'âge de la base, pas du mode
de déploiement.**

Le chemin compressé **exige une passphrase, et cette passphrase est la clé SQLCipher**. La toute
première garde de `backup_compressed` refuse une clé absente ou vide, et son refus nomme la
variable attendue :

```rust
let pass = match key {
    Some(k) if !k.is_empty() => k.to_string(),
    _ => return Err("backup --compress : PLUME_DB_KEY requis (passphrase age)".into()),
};
```

**Ce qui remplit cet argument est `db_key()`, dans les DEUX chemins de production** :
l'ordonnanceur natif (`server::run_scheduled_backup`) et la sous-commande
`plume-daemon backup --compress` (`main.rs`) l'appellent l'un comme l'autre. Or `db_key()` a
**trois** provenances, et la troisième est la clé **auto-engendrée** de `P9.6-a` (§1) — celle que le
démon se donne à lui-même sur une base neuve. Le tableau des trois cas :

| État de la base au premier démarrage | Clé résolue par `db_key()` | Cycle compressé |
|---|---|---|
| **NEUVE** (volume, PVC ou `/var/lib/plume/db` vierge), aucune clé fournie | la clé **auto-engendrée** au démarrage — `0600`, à `PLUME_DB_KEY_AUTO_PATH` sinon `<PLUME_DB>.key` | **ABOUTIT** : une archive est écrite à chaque cycle |
| **ANTÉRIEURE à `P9.6-a`** et restée EN CLAIR, aucune clé fournie | **aucune** : un démarrage n'engendre JAMAIS de clé pour une base qui existe déjà (§1, c'est l'invariant du lot) | **REFUSE à chaque passage**, avec le message ci-dessus |
| n'importe laquelle, avec `PLUME_DB_KEY_FILE` ou `PLUME_DB_KEY` posée | la clé **explicite** (elle gagne sur l'auto) | ABOUTIT |

**Sur une installation faite aujourd'hui, en Docker comme en k3s, la sauvegarde compressée aboutit
donc sans qu'on ait rien à poser** : les deux manifestes livrent `PLUME_DB_KEY_AUTO_PATH`, la clé
naît au premier démarrage, et les cycles publient. C'est la garde de CI
`check_a_deployment_never_arms_a_task_it_cannot_run.py` qui tient cette conjonction — un manifeste
qui armerait l'ordonnanceur sans livrer aucune des trois provenances de clé fait rougir la CI.

**Le trou n'a pas disparu pour tout le monde, et c'est la ligne du milieu du tableau.** Une base
mise en service AVANT `P9.6-a` et laissée en clair n'a aucune clé et n'en recevra pas : son
ordonnanceur part toutes les 6 h, échoue, et le journal en est le seul témoin immédiat
(`[backup-sched] backup B1 échoué : … (best-effort -> on continue)`). Depuis `P9.4-b`, un cycle sans
archive émet aussi un **signal de posture non purgeable**, donc l'absence est visible ailleurs que
dans un journal — mais **rien ne convertit cette base à votre place** : il faut poser une clé
explicite, ou exécuter le geste de conversion décrit au §1 (« Convertir une base existante »).

Deux conséquences à tenir ensemble :

- **le mode hôte n'emprunte pas ce chemin du tout** : `plume-backup.timer` appelle `plume-daemon
  backup` sans `--compress`, c'est-à-dire `VACUUM INTO`, qui n'exige aucune clé. L'asymétrie entre
  les modes porte sur le FORMAT produit (copie `.db` contre archive `age(zstd(...))`), pas sur
  l'existence d'une sauvegarde ;
- **la clé auto est posée par le DÉMON, à son démarrage** (`server::mod.rs` appelle
  `ensure_encrypted`, la sous-commande non). Un `plume-daemon backup --compress` lancé à la main sur
  un volume où le démon n'a jamais tourné ne trouve donc rien à relire, et refuse.

Pour **prouver** qu'on est sauvegardé plutôt que de le supposer, la commande est
`plume-daemon backup-verify` (§3.5), et un répertoire de destination vide est un échec, pas un
silence. Les trois vérifications :

```sh
sed -n '/fn backup_compressed(/,/^}/p' daemon/src/backup/dump_restauration.rs | head -8
grep -n 'db_key().as_deref()' daemon/src/server/sauvegarde_planifiee.rs daemon/src/main.rs
grep -n 'PLUME_DB_KEY_AUTO_PATH\|PLUME_BACKUP_INTERVAL' docker-compose.yml deploy/k3s.yaml
```

*Ce que ce paragraphe corrige : jusqu'au 2026-08-30, cette section décrivait comme impossible ce que
le produit fait depuis `P9.6-a` (2026-08-25) — elle a été écrite avant que la clé auto-engendrée
existe et n'a pas suivi. Les décisions sur le chiffrement par défaut restent portées par `P9.6-a`
dans [`ROADMAP.md`](ROADMAP.md).*

### 3.5 Restaurer, et vérifier

- **`PLUME_DB_KEY` est toujours requise au moment de restaurer**, même pour une archive asymétrique :
  la base cible est **re-chiffrée en SQLCipher** avec cette clé. Une archive asymétrique demande en
  plus l'identité privée `AGE-SECRET-KEY-1…`.
- **Aucun hash, aucun manifeste, aucune somme de contrôle** n'accompagne l'archive. L'intégrité est
  celle du chiffrement authentifié d'age : une altération casse le déchiffrement. S'y ajoutent un
  **marqueur de format** en tête de la charge et une **sentinelle de fin** qui détecte une troncature.
- `backup-verify` lit l'en-tête age **sans déchiffrer** pour dire si l'archive est symétrique ou
  asymétrique, puis, si l'identité nécessaire est disponible, restaure vers une base jetable et en
  **inventorie le contenu** : **une restauration vide est un ÉCHEC**, pas un succès silencieux.

La procédure complète est dans [`DR-plume-restore.md`](DR-plume-restore.md).

---

## 4. La compression, partout où elle existe

| Où | Codec et niveau | Activée par défaut ? |
|---|---|---|
| sauvegarde compressée | `zstd`, niveau **7** (constante du dépôt) | oui, dès qu'on emprunte ce chemin |
| tier froid Parquet | `ZSTD` au **niveau par défaut de la caisse `parquet`** — ce n'est **pas** un choix écrit dans plume | **non** : double verrou, la *feature* `cold_tier` à la compilation **et** `PLUME_COLD_TIER=1` à l'exécution |
| réponses HTTP | **gzip seul** — `br`, `zstd` et `deflate` ne sont pas compilés | oui, la couche est inconditionnelle |
| ingestion OTLP et Pub/Sub | **dé**compression gzip, avec un plafond anti-bombe (`PLUME_OTLP_MAX_DECOMPRESS`) | oui, sur les corps compressés |
| ingestion Prometheus *remote-write* | **dé**compression snappy, plafonnée aussi | oui |
| base SQLite | **aucune compression** : `page_size` n'est jamais posé, aucune colonne n'est compressée | — |
| `VACUUM` | **jamais de `VACUUM` plein automatique** ; seul l'auto-vacuum **incrémental** existe, et il est inopérant si la base n'est pas en `auto_vacuum=INCREMENTAL` | **non** (`PLUME_AUTOVACUUM_INTERVAL=0`) |

```sh
grep -n 'BACKUP_ZSTD_LEVEL' daemon/src/backup/mod.rs
grep -n 'set_compression' daemon/src/cold_store/schema.rs
grep -n 'tower-http' daemon/Cargo.toml            # la liste des codecs HTTP compilés
```

**Ce qui réduit vraiment le volume n'est pas un codec.** Ce sont la **rétention**
(`PLUME_RETENTION_DAYS`), le **basculement vers le tier froid**
(`PLUME_COLD_HOT_WINDOW_DAYS`, qui retire les lignes de la base chaude après scellement) et les
**agrégats** (`event_rollup`, à cardinalité bornée par un plafond top-N). Aucun gain chiffré n'est
établi ici pour ces trois-là : voir [`DESIGN-P10-echelle-2go.md`](DESIGN-P10-echelle-2go.md), qui
porte l'état le plus frais de ces travaux.

---

## 5. Pourquoi c'est ainsi

**Un seul secret, deux usages.** La passphrase de la sauvegarde symétrique **est** la clé SQLCipher.
Ce choix évite un second secret à distribuer, à faire tourner et à perdre — au prix, dit franchement,
qu'un nœud compromis peut lire ses propres archives. Le destinataire age asymétrique existe
précisément pour rompre ce lien quand on veut un séquestre, et la clé publique n'est pas un secret :
elle peut vivre en clair dans un manifeste versionné.

**Le chiffrement de la base est opt-in parce que l'activer est une porte à sens unique.** Une base
chiffrée ne se relit plus sans sa clé ; un défaut qui aurait converti les installations existantes
au premier redémarrage aurait été pire que le trou. C'est la raison écrite — et c'est aussi ce que
`P9.6-a` remet en cause, avec un argument qui se retourne : le défaut actuel ne protège de rien, pas
même du vol d'un disque. **La décision n'est pas prise ; cette page décrit l'état, pas l'issue.**

**Le déversement des tris n'est pas un réglage de performance, c'est un échange de confidentialité.**
D'où le fait qu'il soit opt-in et qu'il le reste : la bonne voie n'est pas d'écrire les tris sur le
disque, c'est d'avoir moins d'octets à trier.

**On refuse avant d'écrire, jamais après.** Le fail-closed du séquestre, la sonde avant conversion,
le plafond scrypt, le refus de conclure d'un inventaire partiel : le même principe partout, parce
qu'un fichier produit puis rejeté a déjà touché le disque.

---

## 6. Ce qui n'a pas été vérifié, et pourquoi

- **Aucune sauvegarde n'a été produite ni restaurée dans ce lot.** Les faits ci-dessus sont établis
  par lecture des sources et par les constantes littérales qu'elles contiennent, pas par un cycle
  observé. La ligne de journal citée en §3.4 est celle qu'écrit le code ; elle n'a pas été relevée
  sur une installation.
- **Le chiffrement du WAL** reste **non établi** : rien dans ce dépôt ne le pose ni ne le teste.
- **Le contenu chiffré d'une copie `VACUUM INTO`** reste **non établi** par ce dépôt.
- Les **paramètres effectifs de SQLCipher** (itérations, taille de page, HMAC) dépendent de la
  version vendorée et ne sont écrits nulle part dans ces sources.
