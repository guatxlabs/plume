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

## 1. La base au repos : en clair par défaut

**Sans clé, la base est en clair sur le disque, dans les trois modes de déploiement.** SQLCipher est
compilé dans le binaire — inconditionnellement, ce n'est pas une *feature* de compilation
(`daemon/Cargo.toml`, `rusqlite` avec `bundled-sqlcipher-vendored-openssl`) — mais il ne s'arme
qu'à la présence d'une clé.

```sh
grep -n 'bundled-sqlcipher' daemon/Cargo.toml
grep -n 'PRAGMA key' daemon/src/crypto/mod.rs daemon/src/db_open.rs
```

### Les deux leviers, et l'ordre entre eux

L'ordre de précédence est écrit **une fois**, dans le code, comme un tableau dont l'ordre EST la
règle (`daemon/src/crypto/mod.rs`) :

| Levier | Ce que c'est | Comportement |
|---|---|---|
| `PLUME_DB_KEY_FILE` | chemin d'un fichier-clé | **préféré** ; s'il est posé mais illisible, vide ou non-UTF8 → message `[FATAL]` et **arrêt du processus**, sans repli sur l'autre levier |
| `PLUME_DB_KEY` | la passphrase elle-même | repli ; lisible via `/proc/<pid>/environ` si elle vient de l'environnement |

Chacun se lit par `cfg()`, donc avec la précédence commune au produit — `environnement` > fichier de
configuration > défaut — ce qui veut dire que **sur un hôte, la clé peut vivre dans
`/etc/plume/soc.conf`** en `0640`, hors de l'environnement du processus. *Ce n'était pas vrai avant
le correctif `P8.7-b` : la base chaude ne lisait que l'environnement pendant que le tier froid lisait
aussi le fichier — une moitié chiffrée, l'autre en clair, sans que rien le dise.*

Le contenu du fichier est lu **verbatim** : le `\n` final n'est pas retiré, délibérément, pour que
`fichier` et `environnement` portant le même secret donnent le même octet-à-octet.

### Ce que le code NE vérifie PAS

**Les permissions du fichier-clé ne sont pas contrôlées.** La lecture est un `read` nu ; il n'y a
aucun contrôle de mode `0600`, aucun contrôle de propriétaire. Un fichier-clé lisible par tous sera
accepté sans un mot.

```sh
grep -rn '0o600' daemon/src --include='*.rs' --exclude-dir=tests   # que des POSES, jamais une vérification
```

C'est à l'opérateur de poser les droits. Le dire ici vaut mieux que de laisser croire à un contrôle
qui n'existe pas.

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

### Convertir une base existante : ce qui se passe, et la fenêtre qui s'ouvre

Une base **neuve** est créée chiffrée d'office. Une base **en clair existante** est convertie au
démarrage, une seule fois, et l'opération est idempotente (`ensure_encrypted`,
`daemon/src/crypto/mod.rs`). La séquence, dans l'ordre :

1. un résidu `<db>.plaintext.bak` d'un essai interrompu est **effacé d'abord** ;
2. une **sonde non destructive** classe la base : fraîche, s'ouvre avec la clé, en clair, verrouillée,
   illisible, ou mauvaise clé ;
3. « mauvaise clé ou corrompue » → message `[FATAL]` et arrêt, **base non modifiée** — jamais une
   conversion à l'aveugle ;
4. « en clair » → point de contrôle du WAL, **copie en clair** vers `<db>.plaintext.bak`, export par
   `sqlcipher_export` vers `<db>.enc.tmp`, renommage atomique, suppression des `-wal`/`-shm`, puis
   effacement de la copie.

**La fenêtre est nommée** : entre l'étape 4 et son dernier geste, une **copie en clair de la base
existe sur le disque**. Une coupure à cet instant la laisse en place ; le démarrage suivant l'efface.
L'effacement écrase de zéros puis supprime — et le code écrit lui-même que **cela ne garantit rien
sur un SSD ou un système de fichiers à copie sur écriture**.

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

### 3.4 Le défaut mesuré : sans clé de base, le planificateur ne produit RIEN

**MESURÉ SUR L'ARBRE SUIVI le 2026-08-25.** C'est le point le plus important de ce document pour un
exploitant, et il ne figurait dans aucune page.

Le chemin compressé **exige une passphrase, et cette passphrase est la clé SQLCipher**. La toute
première garde de `backup_compressed` est :

```rust
let pass = match key {
    Some(k) if !k.is_empty() => k.to_string(),
    _ => return Err("backup --compress : PLUME_DB_KEY requis (passphrase age)".into()),
};
```

Or **la clé est vide par défaut dans les trois modes**, et les manifestes livrés arment pourtant le
planificateur. Sur une installation Docker ou k3s prise telle quelle, à chaque cycle :

```
[backup-sched] backup B1 échoué : backup --compress : PLUME_DB_KEY requis (passphrase age) (best-effort -> on continue)
```

**Aucune archive n'est produite.** Le planificateur ne s'arrête pas, ne dégrade aucun voyant, et rien
d'autre que cette ligne de journal ne le dit. Les deux vérifications :

```sh
sed -n '/fn backup_compressed(/,/^}/p' daemon/src/backup/dump_restauration.rs | head -20
grep -n 'PLUME_DB_KEY\|PLUME_BACKUP_INTERVAL' docker-compose.yml deploy/k3s.yaml
```

Trois conséquences à tenir ensemble :

- **le mode hôte n'a pas ce trou** : son timer emprunte le chemin `VACUUM INTO`, qui n'exige aucune
  clé — d'où une asymétrie entre les modes que rien n'annonce ;
- **poser une clé de base n'est donc pas seulement une décision de confidentialité** : en conteneur
  et en cluster, c'est la condition pour qu'une sauvegarde existe ;
- pour **prouver** qu'on est sauvegardé plutôt que de le supposer, la commande est
  `plume-daemon backup-verify` (§3.5), et un répertoire de destination vide est un échec, pas un
  silence.

*Cet écart entre ce que les manifestes arment et ce que le code peut produire n'a pas encore de clé
de roadmap au moment où cette page est écrite ; les décisions sur le chiffrement par défaut sont
portées par `P9.6-a` dans [`ROADMAP.md`](ROADMAP.md).*

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
