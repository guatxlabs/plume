# DR — Restauration des backups Plume (SQLCipher)

Ce runbook couvre la restauration d'un backup Plume `plume-<TS>.db.age` (format
`age(zstd(SQLite en clair))`) depuis votre stockage objet (`<votre-bucket>/plume/`), et les **deux
modes** de chiffrement de backup proposés par le produit.

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
   qui exécute le backup).
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

- **Mode passphrase** : `PLUME_DB_KEY` est disponible → **vérif COMPLÈTE** (déchiffre + ouvre la DB).
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

## Rotation

- **Clé SQLCipher** : rotation = re-chiffrer la DB live ; les backups en mode passphrase restent
  lisibles avec l'**ancienne** clé (escrow historisé).
- **Identité age de backup** : générer une nouvelle paire, poser la nouvelle clé **publique**, escrow
  la nouvelle **privée** ; conserver l'ancienne privée tant que des backups chiffrés avec l'ancienne
  clé sont dans la rétention (fenêtre `PLUME_BACKUP_KEEP`). Découplé de la clé SQLCipher : les deux
  rotations sont indépendantes.
