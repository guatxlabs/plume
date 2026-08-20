# DR — Restauration des backups Plume (SQLCipher)

Ce runbook couvre la restauration d'un backup Plume `plume-<TS>.db.age` (enveloppe
`age(zstd(…))`) depuis votre stockage objet (`<votre-bucket>/plume/`), et les **deux
modes** de chiffrement de backup proposés par le produit.

## D'abord : quel backup avez-vous ? Le produit en écrit DEUX formats différents

Ne suivez pas ce runbook avant d'avoir identifié le format entre vos mains — ils ne se restaurent pas
de la même façon.

| Produit par | Nom du fichier | Format | Restauration |
|---|---|---|---|
| **Scheduler natif in‑daemon** (`PLUME_BACKUP_INTERVAL` > 0 — activé par le `docker-compose.yml` et `deploy/k3s.yaml` livrés) | `plume-<TS>.db.age` | enveloppe `age(zstd(…))` — pour la CHARGE qu'elle contient, voir « quelle charge dans le `.age` ? » plus bas | **ce runbook** (`plume-daemon restore`) |
| **Timer hôte** `plume-backup.timer` (installé par `bootstrap.sh`, quotidien 04:00) | `plume-<TS>.db` | **copie SQLite compacte** (`VACUUM INTO`), *chiffrée SQLCipher si et seulement si la base l'était* — **jamais** d'enveloppe age | *voir ci‑dessous*, pas `restore` |

**Restaurer une copie du timer hôte** (`.db`, sans `.age`) : c'est un fichier SQLite ordinaire, donc
la restauration est une **copie de fichier**, daemon arrêté — n'utilisez pas `plume-daemon restore`,
qui attend une enveloppe age.

```sh
sudo systemctl stop plume-daemon
sudo install -o soc -g soc -m 0600 /var/lib/plume/backups/plume-<TS>.db /var/lib/plume/db/plume.db
sudo rm -f /var/lib/plume/db/plume.db-wal /var/lib/plume/db/plume.db-shm   # WAL de l'ancienne base
sudo systemctl start plume-daemon
```
La copie n'est lisible qu'avec la **même clé SQLCipher** que la base d'origine : si vous aviez posé
`PLUME_DB_KEY`/`PLUME_DB_KEY_FILE`, il faut la même valeur au redémarrage. Si la base était **en
clair**, cette copie est **en clair** — traitez-la comme la base elle‑même.

**Sink local vs stockage objet.** Le scheduler natif écrit par défaut dans un **répertoire local**
(`PLUME_BACKUP_DEST`, défaut `<dir(PLUME_DB)>/backups`) : les `mc cp` de ce runbook ne s'appliquent
qu'à un déploiement qui pousse ensuite vers un stockage objet. Le sink `s3://` natif **n'est pas
implémenté** — le daemon le **refuse explicitement** et se désactive plutôt que d'écrire un faux
backup local. **Un backup qui reste sur le même volume que la base ne protège que de la corruption
logique, pas de la perte du volume** : copiez-le hors de la machine.

## Ensuite : quelle CHARGE dans le `.age` ? (reconnue au marqueur, jamais au nom du fichier)

Distinction **indépendante** de la précédente : celle du dessus dit *quel outil* a produit l'artefact,
celle-ci dit *ce qu'il y a dedans*. Deux charges différentes voyagent sous la même enveloppe et sous le
**même nom de fichier** `plume-<TS>.db.age` — il n'existe **aucun suffixe, aucune convention de nom** qui
les distingue. C'est le **marqueur en tête de la charge décompressée** qui tranche, et
`plume-daemon restore` le lit tout seul : **vous n'avez ni à savoir lequel vous tenez, ni à passer
d'option.**

| Marqueur en tête de charge | Ce que c'est | D'où il vient |
|---|---|---|
| `PLUMEDUMP1\n` | **dump typé streaming** (DDL + lignes) — le **défaut** | sauvegarde qui n'écrit **aucun fichier en clair sur disque** |
| `SQLite format 3\0` | **copie SQLite complète en clair** | chemin **historique** : sauvegardes antérieures au streaming, schémas hors de son périmètre (FTS5 *contentless*), ou `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT=1` |

Pour lire le marqueur à la main, si vous voulez savoir avant de restaurer :

```sh
age -d -p < plume-<TS>.db.age | zstd -d | head -c 16 | xxd    # mode passphrase
# -> "PLUMEDUMP1."      = dump typé
# -> "SQLite format 3." = copie SQLite complète
```

Conséquences pratiques, à connaître **avant** un DR chronométré :

- **Les sauvegardes déjà en séquestre restent restaurables** — aucune migration, aucune conversion, le
  basculement du défaut ne périme rien.
- Le dump typé **n'emporte ni les index ni les tables shadow FTS5** : ils sont **reconstruits** à la
  restauration. Le `.age` est donc nettement plus petit (mesuré : **×2,4** sur une base de test au schéma
  réel ; l'écart grandit avec la masse d'index — index + FTS pesaient **43 %** du fichier de production
  le 2026-08-08).
- **En contrepartie, la restauration est plus longue** — et l'ampleur dépend de la charge de la machine,
  parce que reconstruire index et FTS est du **CPU pur**. Mesuré sur la même base : **+12 %** machine au
  repos, **+138 %** machine chargée. **Provisionnez dans le RTO un facteur pouvant approcher 2,5×**, et
  restaurez sur une machine peu chargée si le temps compte. L'ordre, lui, ne s'inverse jamais.

## Le tier froid : ce qu'une restauration du backup chaud ne rend PAS

Depuis l'aging Phase 2 (`daemon/src/cold_store/aging.rs`), une journée scellée en Parquet voit ses
lignes `event` **supprimées de la base chaude**. La base chaude ne porte donc plus que la fenêtre
`PLUME_COLD_HOT_WINDOW_DAYS` (**7 jours** en production au 2026-08-08) ; le reste de la rétention
(`PLUME_COLD_RETENTION_DAYS=365`) vit **uniquement** sous `PLUME_COLD_DIR=/data/cold`.

**Il n'y a pas de perte de données.** Les fichiers-jour froids sont séquestrés à chaque cycle du
sidecar `backup` par `plume-daemon cold-backup-plan`, en copie verbatim incrémentale vers
`<votre-bucket>/plume/cold/<tenant>/<env>/<AAAA-MM-JJ>-<NNNN>.parquet`. Ils sont déjà zstd+age-chiffrés
et immuables : aucun re-wrap, aucun clair.

**Ce qu'il faut en retenir pour un DR :**

1. Restaurer `plume-<TS>.db.age` seul rend un SOC **fonctionnel mais amputé** : la recherche répondra,
   et ne verra que les 7 derniers jours. Un incident daté d'il y a trois semaines sera **absent sans le
   moindre message d'erreur**.
2. Une restauration complète a **deux composants** : le `.db.age` chaud **et** l'arborescence `cold/` du
   même bucket, remise sous `PLUME_COLD_DIR` avant le démarrage du daemon.
3. **L'ordre compte** : déposer les fichiers-jour froids *avant* le premier boot. Le daemon lit
   `cold_seal` dans la base restaurée ; un jour scellé dont le fichier Parquet est absent est un trou
   silencieux, pas une erreur de boot.
4. **Le binaire doit porter la feature.** Un `plume-daemon` construit sans `--features cold_tier` ignore
   `/data/cold` et déclare quand même les variables `PLUME_COLD_*` — c'est le défaut P4.5-b, resté trois
   jours en production. Contrôle : la garde de capacités de `bootstrap/plume-deploy.sh`.
5. **Ce que le restore-test quotidien prouve, et ce qu'il ne prouve pas.** Il vérifie structurellement le
   **dernier backup chaud** et refuse de conclure s'il est plus vieux que 3× la cadence observée. Il
   **compte** les fichiers-jour froids de l'escrow et les nomme, mais **ne les vérifie pas** : quand il y
   en a, son verdict est `SUCCES PARTIEL — PORTEE : base CHAUDE seule`. La vérification des deux étages
   reste un **drill DR hors-cluster** avec l'identité age d'escrow.

**État mesuré le 2026-08-08** : 60 fichiers-jour sur le disque, **60 séquestrés** (témoin positif : 102
objets sous le préfixe `plume/` ; témoin négatif : 0 sous un préfixe inexistant), couvrant
2026-06-23 → 2026-07-31, ~163 Mio.

## Deux modes de chiffrement de backup

| Mode | En-tête age | Déchiffré avec | Où vit la clé de lecture | Vérif automatisée in-cluster |
|---|---|---|---|---|
| **Mode passphrase** (défaut) | stanza `scrypt` | passphrase = **clé SQLCipher** (`PLUME_DB_KEY`) | là où vit déjà `PLUME_DB_KEY` | **complète** (déchiffre + ouvre) |
| **Mode destinataire age** (`PLUME_BACKUP_AGE_RECIPIENT`) | stanza `X25519` | **identité age PRIVÉE** (`AGE-SECRET-KEY-1…`) | **escrow hors-cluster uniquement** (jamais un Secret k8s) | **structurelle seule** |

Le **mode destinataire** découple la lecture des backups de la clé de la base : la clé qui déchiffre
l'historique n'est plus présente là où tourne le daemon. C'est le mode recommandé dès que vous pouvez
tenir un escrow hors-ligne.

- `plume-daemon backup-verify <obj>` affiche `kind=Symmetric|Asymmetric` : c'est la façon fiable de
  savoir avec quel mode un objet donné a été produit (le mode peut changer au cours de la vie d'un
  déploiement).
- `plume-daemon restore` **auto-détecte** : il présente à age **les deux** identités (passphrase +
  identité privée si fournie) et age apparie selon le stanza de l'en-tête. Aucune option à choisir
  manuellement.

### Le facteur de travail scrypt du mode passphrase (à lire AVANT un DR sur une vieille archive)

Depuis le **2026-08-09** (P8.6-b) plume écrit un facteur **FIXE**, `log_n = 12` → **4 194 304 octets**
de tampon, et accepte à la lecture jusqu'à **`log_n = 20` → 1 073 741 824 octets**.

**Avant cette date, `age` choisissait ce facteur par un étalonnage au chronomètre à chaque
sauvegarde.** Mesuré le 2026-08-09 sur une machine 12 cœurs, trois appels de suite : `13, 14, 14` en
binaire *debug* mais **`19, 19, 20` en *release*** — soit **512 Mio à 1 Gio** de RAM réclamés par le
seul KDF, sous un budget de 2 Gio, et tirés au sort d'une sauvegarde à l'autre.

Ce que ça change pour un DR :

- **Vos archives symétriques d'avant le 2026-08-09 restent restaurables** — le plafond de 20 est
  précisément dimensionné pour elles — mais la restauration **allouera jusqu'à 1 Gio** le temps du
  KDF. Prévoyez la RAM sur la machine de restauration.
- Un `.age` exigeant **plus** de `log_n = 20` est **refusé**, et le refus le dit : facteur exigé,
  octets exigés, plafond, octets du plafond, et le fait que **la passphrase n'est pas en cause**.
  Recours : déchiffrer hors-ligne avec l'outil `age` sur une machine dotée de la RAM, puis
  re-sauvegarder avec la version courante.
- Le refus symétrique était auparavant **fonction de la machine de restauration** : `age` plafonnait
  à `target_scrypt_work_factor() + 4`, recalculé au chrono là où l'on déchiffre. Mesuré : une archive
  à `log_n = 19` était **REFUSÉE** (`Excessive work parameter for passphrase`) par un binaire debug et
  **ACCEPTÉE** par le même code avec le plafond fixe. La restaurabilité est désormais une propriété
  du **fichier**, plus de la machine.
- `PLUME_BACKUP_SCRYPT_LOG_N` (borné `[10, 20]`) permet de remonter ce facteur. **Ce n'est utile que
  si vous savez que votre `PLUME_DB_KEY` est une phrase tapée par un humain** : le même secret protège
  déjà le tier froid à `log_n = 12` (et ses jours-files partent à l'escrow **en copie verbatim**),
  donc monter le seul backup ne relève aucun plancher d'attaque.
- Le **mode destinataire age n'a aucun terme KDF** : c'est aussi pour ça qu'il reste le mode recommandé.

## Pré-requis d'escrow (HORS-cluster — responsabilité opérateur)

1. **Clé SQLCipher** (`PLUME_DB_KEY`) — à escrow. Requise pour **tout** restore (le restore
   re-chiffre la DB cible en SQLCipher avec cette clé), et pour déchiffrer les backups produits en
   **mode passphrase**.
2. **Identité age privée** — requise seulement en **mode destinataire** ; générée par l'opérateur,
   escrow **hors-ligne** (jamais en cluster) :
   ```sh
   age-keygen -o plume-backup-identity.key      # AGE-SECRET-KEY-1... (PRIVÉ, escrow hors-ligne)
   grep 'public key' plume-backup-identity.key   # age1...  (PUBLIC -> PLUME_BACKUP_AGE_RECIPIENT)
   ```
   La **clé publique** (`age1…`) va dans le déploiement (`PLUME_BACKUP_AGE_RECIPIENT`, non-secret). La
   **clé privée** ne quitte JAMAIS l'escrow ; elle n'est fournie qu'au moment d'un restore/drill.

## ⛔ GATE d'activation du mode destinataire (ORDRE IMPÉRATIF)

**NE PAS** poser `PLUME_BACKUP_AGE_RECIPIENT` **AVANT** d'avoir généré la paire ET escrow la clé
**privée** hors-ligne. Sinon les nouveaux backups deviennent **indéchiffrables** (aucune identité pour
les lire). Tant que `PLUME_BACKUP_AGE_RECIPIENT` est absent, les backups restent en **mode
passphrase** (comportement par défaut, byte-pour-byte inchangé). Séquence :

1. `age-keygen` → escrow la clé **privée** hors-ligne (+ copie de secours). Vérifier qu'elle est lisible.
2. Poser `PLUME_BACKUP_AGE_RECIPIENT: age1…` (clé **publique**) dans le déploiement (conteneur/sidecar
   qui exécute le backup) — ou, en **systemd host-natif**, dans `/etc/plume/soc.conf` : depuis le
   **2026-08-09** (P8.7-a) tous les réglages `PLUME_BACKUP_*` suivent la même précédence
   `env > PLUME_CONFIG > défaut`. *Avant cette date, ce destinataire écrit dans `soc.conf` était ignoré
   en silence et les archives repartaient en mode passphrase* : si vous exploitez un hôte configuré ainsi,
   vos archives antérieures sont **symétriques** — vérifiez-les avec `backup-verify` avant de compter
   dessus. Le démon nomme les clés concernées à son démarrage.
3. Appliquer (votre dépôt GitOps → redémarrage du pod). Le prochain backup est chiffré au destinataire
   (vérifier `backup-verify` → `Asymmetric`).
4. Faire un **DR drill** (ci-dessous) avec la clé privée escrow pour PROUVER que le nouveau backup se
   restaure. **Notez la date de bascule** dans votre propre documentation d'exploitation : les objets
   antérieurs restent en mode passphrase.

## Restaurer un backup (DR réel)

```sh
# 1) Récupérer l'objet depuis le stockage objet (ici avec le client MinIO `mc`)
mc cp <votre-bucket>/plume/plume-<TS>.db.age /restore/plume-<TS>.db.age

# 2a) Backup en MODE PASSPHRASE : seule la clé SQLCipher suffit
export PLUME_DB_KEY_FILE=/etc/plume/db/db.key            # ou PLUME_DB_KEY=<clé> (escrow)
plume-daemon restore /restore/plume-<TS>.db.age /data/plume.db --force

# 2b) Backup en MODE DESTINATAIRE : clé SQLCipher (cible) + identité age PRIVÉE (source)
export PLUME_DB_KEY_FILE=/etc/plume/db/db.key
export PLUME_BACKUP_AGE_IDENTITY_FILE=/escrow/plume-backup-identity.key   # depuis l'escrow, JAMAIS en cluster
plume-daemon restore /restore/plume-<TS>.db.age /data/plume.db --force
```

`restore` refuse d'écraser une DB existante sans `--force`. La DB restaurée est byte-rejouable
(round-trip prouvé par les tests).

## Vérification automatisée (restore-test) et sa dégradation assumée

Le restore-test **in-cluster** ne peut PAS détenir l'identité privée (la mettre en cluster ruinerait le
modèle du mode destinataire). Comportement de `plume-daemon backup-verify <obj>` :

- **Mode passphrase** : `PLUME_DB_KEY` est disponible → **vérif COMPLÈTE** : déchiffre, rejoue dans une
  base jetable, **la rouvre avec sa clé et en compte le contenu** (tables de données et lignes). Une
  archive qui se déchiffre et se rejoue mais ne rend **aucune ligne** est un **ÉCHEC** — c'est
  précisément le cas qu'un contrôle « pas d'erreur » laissait passer.
- **Mode destinataire** : identité privée **absente** → **vérif STRUCTURELLE** : valide l'en-tête
  age v1, le stanza destinataire (`X25519`), et une taille plausible — **sans déchiffrer**. Sortie 0 =
  structurellement sain ; le log indique clairement que la vérif complète exige l'identité escrow.

En mode destinataire, la **vérif complète** devient donc un **DRILL DR périodique** (mensuel
recommandé), exécuté hors-ligne / dans un pod jetable avec l'identité privée escrow :

```sh
export PLUME_DB_KEY=<clé-escrow>
export PLUME_BACKUP_AGE_IDENTITY_FILE=/escrow/plume-backup-identity.key
plume-daemon backup-verify /restore/plume-<TS>.db.age   # -> full_decrypt_verified=true attendu
```

**NE JAMAIS** stocker l'identité privée dans un Secret k8s pour automatiser ce drill : c'est
précisément l'exposition que le mode destinataire élimine.

## L'exercice de restauration : sa trace, et ce qui rend son absence visible

Une sauvegarde dont **aucune ligne n'a jamais été restaurée** est une garantie non éprouvée. Le drill
ci-dessus a lieu hors ligne, sur une machine que la production ne voit pas : sans trace, rien ne
distingue « exercice fait le mois dernier » de « jamais fait depuis l'installation ».

**Une vérification complète réussie émet une ATTESTATION** — une ligne sur la sortie standard, qui ne
porte que des faits produits par l'exercice (archive, taille, mode de chiffrement, tables et lignes
restaurées) et **aucun secret** :

```
PLUME-EXERCICE-RESTAURATION-1 {"ts":…,"archive":"plume-<TS>.db.age","archive_octets":…,
                               "chiffrement":"asymmetric","tables":…,"lignes":…}
```

Cette ligne se ramène sur le nœud — copier-coller, clé USB, `ssh` — **sans qu'aucune identité privée ne
fasse le voyage inverse** :

```sh
# sur la machine d'exercice (isolée, avec l'identité d'escrow)
plume-daemon backup-verify /restore/plume-<TS>.db.age > /media/attestation.txt

# sur le nœud (qui n'a jamais vu l'identité privée)
plume-daemon restore-drill record < /media/attestation.txt
plume-daemon restore-drill status     # sortie 0 = éprouvé récemment ; 3 = un exercice est DÛ
```

`record` **refuse** une attestation datée dans le futur (au-delà d'une heure de tolérance d'horloge),
une attestation plus ancienne que celle déjà enregistrée, et une attestation qui n'atteste rien
(zéro table ou zéro ligne).

**Ce que l'exploitant lit sans rien lancer**, une fois l'attestation posée :

| Où | Quoi |
|---|---|
| `/api/system/health`, panneau Système | composant `restauration` — `jamais` / `frais` / `perime` / `mode_non_eprouve`, avec l'âge |
| `/metrics` | `plume_restore_drill_overdue` (1 = un exercice est dû), `plume_restore_drill_age_seconds` et `plume_restore_drill_last_success_timestamp_seconds` — **absentes tant qu'aucun exercice n'a eu lieu**, parce qu'un âge de 0 se lirait « restauré à l'instant » |
| SOC | événement `health` **non purgeable** émis par le chemin de sauvegarde (dédup quotidienne) tant qu'un exercice est dû |

Deux règles portées par le mécanisme, et pas par une phrase :

1. **`PLUME_RESTORE_DRILL_MAX_AGE_DAYS`** (défaut **31**, `0` = suivi désactivé et affiché comme tel)
   fixe à partir de quand un exercice est périmé. L'état **vieillit** : il passe seul de `frais` à
   `perime`.
2. **Un exercice mené sur le chemin symétrique ne clôt pas l'obligation d'une installation qui
   séquestre en asymétrique** (`PLUME_BACKUP_AGE_RECIPIENT` posé) : l'état est alors
   `mode_non_eprouve`, parce que le chemin qui servira au sinistre — l'identité privée hors cluster —
   n'a pas été emprunté.

**Ce que cela ne prouve pas**, et c'est dit ici pour être opposable : l'attestation défend contre
l'**oubli**, pas contre une falsification délibérée — une ligne peut être recopiée à la main. Le
séquestre, lui, reste intact : aucune identité privée ne vit dans le dépôt, dans un test, ni dans
l'intégration continue.

## Rotation

- **Clé SQLCipher** : rotation = re-chiffrer la DB live ; les backups en mode passphrase restent
  lisibles avec l'**ancienne** clé (escrow historisé).
- **Identité age de backup** : générer une nouvelle paire, poser la nouvelle clé **publique**, escrow
  la nouvelle **privée** ; conserver l'ancienne privée tant que des backups chiffrés avec l'ancienne
  clé sont dans la rétention (fenêtre `PLUME_BACKUP_KEEP`). Découplé de la clé SQLCipher : les deux
  rotations sont indépendantes.
