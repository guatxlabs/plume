# P10 — Tenir sous 2 Go à l'échelle : chaud / froid / bloom / compression

> Brainstorm de conception, **ancré sur mesure** (2026-08-06). Ce document n'est PAS une décision
> figée : c'est la carte du terrain mesuré et l'ordre des leviers qui en découle. Chaque affirmation
> chiffrée porte sa source. Rien n'est construit sur la foi d'une intuition.

## 0. Ce qu'on cherche, et pourquoi c'est DEUX problèmes, pas un

Hugo, formulé plusieurs fois : « que la base tienne très peu de place, presque autant qu'un zstd,
tout en assurant fiabilité, confidentialité et sécurité **nativement** — sans dump clair puis zstd
puis age ». Et : tourner sous **2 Go de RAM** en host-natif / Docker / k3s, tout paramétrable, le
**défaut = ce qui est en prod**.

Deux problèmes distincts se cachent sous « P10 », et les confondre mène à construire le mauvais
levier :

- **TAILLE au repos** (le disque). C'est le « ×81 ». Levier : moins d'octets stockés.
- **RAM d'une requête** (l'OOM, P6.1-b). Le trieur SQLite matérialise **un enregistrement par ligne
  BALAYÉE** sur un `stats … by` (cf. P10.0). Levier : moins de lignes à balayer **et** un agrégateur
  à état borné. **La compression au repos ne réduit PAS la RAM de tri** — une page compressée est
  déchiffrée+décompressée en RAM avant d'être triée. Il faut les deux leviers.

## 1. LA MESURE — où partent les octets (2026-08-06)

**Production** (`db-stats`, pod live, lecture seule) : **1 276 MiB** pour **1 573 752 événements** ⇒
**~850 o/événement** sur disque · freelist **0,8 %** (VACUUM ne rendrait rien, base dense) ·
auto_vacuum=none. *La base est déjà bien plus petite qu'avant : les retraits d'index P10.2-d + P6.8
ont payé.*

**Ventilation par-objet** (banc 3,65 M év., `db-stats --par-objet`, comptabilité FERMÉE ✓ ; les
PROPORTIONS sont indépendantes de l'échelle) :

| poste | part | objets dominants |
|---|---:|---|
| **données (tables)** | **56,8 %** | `event` **51,0 %** · `event_rollup` 5,1 % |
| **index b-tree** | **32,8 %** | `dedup UNIQUE` 6,2 % · rollup-autoindex 5,3 % · `idx_event_host` 3,7 % · `src_srcip`/`sev_srcip`/`src_ts`/`srcip` 4×~2-3 % |
| **FTS5 (shadow)** | **8,1 %** | `event_fts_data` 6,9 % |
| freelist | 2,3 % | — |

**Trois faits qui commandent la conception :**

1. **La table `event` est la MOITIÉ de la base, et elle est stockée EN CLAIR-PAGE** (SQLCipher
   chiffre la page, mais ne la COMPRESSE pas). Les valeurs sont du log SIEM — `message`, `fields`
   JSON — qui compressent **×10 à ×40** au zstd. C'est le plus gros levier unique, et il est intact.
2. **Un TIERS de la base est de l'index b-tree.** La compression n'y peut presque rien (ce sont des
   clés déjà compactes). Mais un **tier froid colonnaire les ÉLIMINE** : le froid ne porte pas de
   b-tree, il prune par **bloom + zone-maps** (quelques bits par valeur vs une entrée d'index par
   ligne).
3. **FTS = 8 %**, entièrement **droppable au froid** (une requête froide scanne un row-group borné
   ou s'appuie sur le bloom ; pas besoin du shadow FTS sur des données rarement fouillées en plein
   texte).

## 2. CE QUI EST DÉJÀ CONSTRUIT (ne pas réinventer)

Le **tier froid Parquet** (`daemon/src/cold_store/`, feature `cold_tier`, 14 modules) EXISTE :
writer colonnaire **Parquet + ZSTD** (row-groups ~256K, RAM d'écriture bornée à un row-group),
branche d'**aging** hot→froid par jour, **lecteur hot∪cold masqué**, **bloom filters**
(`crypto.rs`/`reader.rs`/`planner.rs`/`vectorized.rs`), scellé crypto par jour, décodage
**vectorisé** (×2,7 mesuré, cf. horizon OLAP). **OPT-IN de bout en bout** : gate compile
`#[cfg(feature="cold_tier")]` + gate runtime `PLUME_COLD_TIER`. **OFF en production.**

Le **chaud** n'a **AUCUNE compression au repos** aujourd'hui : la table `event` est en pages b-tree
non compressées.

⇒ **La question centrale du brainstorm n'est donc PAS « comment construire le froid » — il est
construit. C'est : (a) qu'est-ce qui EMPÊCHE de l'activer par défaut, et (b) que reste-t-il pour le
chaud qui, lui, ne bouge pas.**

## 3. LES QUATRE LEVIERS, ordonnés par (impact mesuré ÷ code neuf)

### Levier A — ACTIVER l'aging froid (construit, OFF) · impact ÉNORME, code neuf ~0
Déplacer les jours anciens vers Parquet/ZSTD/bloom retire d'un coup **leurs lignes `event`** (part
du 51 %) **ET leur quote-part des 33 % d'index** (le froid n'en porte pas) **ET leur FTS**. Sur une
rétention de 30 j où ~90 % des événements ont plus de N jours, la base chaude fond.
**Ce que ça fait AUSSI pour l'OOM (P6.1-b) :** le `stats … by` sur la fenêtre chaude balaie **bien
moins de lignes** → le trieur matérialise bien moins. C'est le seul levier qui attaque les DEUX
problèmes avec du code **déjà écrit**.
**LA VRAIE TÂCHE EST DONC UNE MESURE, PAS UN BUILD :** *pourquoi est-ce OFF en prod ?* Hypothèses à
éprouver, une par une — (i) coût de décompression sur les requêtes froides jamais mesuré sous charge
réelle ; (ii) le lecteur hot∪cold a-t-il des angles morts (P51 « tronqué en silence » était un
symptôme, corrigé) ; (iii) crash-safety de l'aging multi-fichiers éprouvée mais jamais en prod ;
(iv) le scellé crypto par jour ajoute-t-il un coût de clé. **Aucune ne se tranche sans mesure.**

### Levier B — COMPRESSION AU REPOS du CHAUD (à construire) · impact GROS sur les 51 %
Ce qui reste chaud (la fenêtre récente, la seule indexée+FTS) garde ses grosses colonnes en clair-
page. **Compresser NATIVEMENT les colonnes volumineuses** (`fields` JSON, `message`) — pas la base,
les VALEURS — au zstd, transparent au moteur. Deux formes, à départager par mesure :
- **B1 — par-valeur** : chaque `fields`/`message` stocké zstd (dictionnaire partagé par source pour
  les petits blobs, sinon zstd simple). Simple, local, réversible ; le prix est un
  décompresse-à-la-lecture que **Hugo a explicitement pointé** (« la décompression peut se coûter si
  mal fait »). ⇒ mesurer le coût lecture AVANT de généraliser ; garder les colonnes filtrées/
  indexées (host, src_ip, severity, ts) EN CLAIR pour que l'index et le WHERE ne paient rien.
- **B2 — par-page** (VFS de compression sous SQLCipher, type `sqlite_zstd`/`cvfs`) : transparent
  total, mais touche la couche I/O et le chiffrement — **risque de confidentialité** (le temporaire,
  cf. P10.1-a) et de fiabilité élevé. **Écarté par défaut** sauf preuve qu'il n'ouvre aucun clair.
**Invariant non négociable (P10.1-a) :** aucune de ces formes ne doit produire un dump clair sur
disque. La compression se fait EN RAM sur la valeur, avant l'écriture chiffrée SQLCipher. Jamais un
fichier intermédiaire.

### Levier C — AGRÉGATION BORNÉE NATIVE (P10.3, à construire) · ferme l'OOM lui-même
Indépendant de la taille. Le trieur matérialise 1 ligne/événement balayé faute de mécanisme de
déversement en mémoire (P10.0). **Un agrégateur natif à état borné** — pour `count`, `dc`,
`count by` — maintient un accumulateur de taille bornée (HyperLogLog pour `dc`, top-N borné pour
`count by`, cf. `AnswerShape`/`TruncatedAggregate` DÉJÀ en place) au lieu de déléguer au trieur
SQLite. Rend un résultat **déclaré partiel** quand la cardinalité dépasse le budget — cohérent avec
l'existant, et **ne coûte AUCUNE confidentialité** (rien ne touche le disque). C'est la vraie
fermeture de P6.1-b, celle que P10.1-a a explicitement laissée ouverte.

### Levier D — RÉDUCTION D'INDEX (déjà entamé) · petit reste
P10.2-d a retiré 9 index inutiles, P6.8 l'auto-index. Reste, mesuré : `dedup UNIQUE` (6,2 %) est
**nécessaire** (exactly-once), les composites host/src_ip servent la détection active (P6.8-c l'a
prouvé douloureusement — ne PAS retoucher sans mesurer l'usage). Peu de gras restant ; **ne pas
sur-optimiser un poste déjà nettoyé**.

## 4. LA CIBLE, ET LA FRONTIÈRE CHAUD/FROID

Décodée des chiffres : **le chaud doit être petit et indexé ; le froid, minuscule et pruné.**
- **CHAUD** = fenêtre récente (à mesurer : combien de jours restent « souvent requêtés » ?), en
  SQLite/SQLCipher, indexé + FTS, **grosses colonnes compressées (levier B)**. C'est ce que le
  trieur balaie, donc **le plus petit possible sans casser l'interactivité**.
- **FROID** = le reste, en Parquet/ZSTD/bloom (levier A), **sans b-tree, sans FTS**. Requêtes rares,
  scan de row-group borné + prune bloom/zone-map.
- **BLOOM** : le mécanisme qui rend le froid interrogeable sans index — un filtre par colonne et par
  row-group (quelques Kio) répond « la valeur X n'est SÛREMENT pas ici » et écarte le bloc sans le
  lire. C'est ce qui remplace, à ~1 % du coût, les 33 % d'index b-tree pour les données froides.

## 5. ORDRE D'ATTAQUE RECOMMANDÉ (chacun se valide seul, aucun ne bloque le suivant)

1. **MESURER pourquoi le froid est OFF** (levier A) — banc réel : activer `PLUME_COLD_TIER` sur une
   copie, mesurer taille chaude après aging, coût des requêtes froides sous charge, crête RSS d'un
   `stats by` sur la fenêtre chaude réduite. **C'est la mesure fondatrice suivante.** Si le froid
   tient ses promesses, **l'activer par défaut ferme l'essentiel de la taille ET soulage l'OOM** —
   sans une ligne neuve.
2. **CONSTRUIRE l'agrégation bornée native** (levier C / P10.3) — ferme l'OOM par le haut, quelle
   que soit la taille de la fenêtre chaude. Indépendant, confidentialité-neutre.
3. **CONSTRUIRE la compression au repos du chaud** (levier B1 par-valeur) — attaque les 51 % qui
   restent chauds, en gardant les colonnes filtrées en clair. Mesurer le coût de lecture d'abord.
4. Ne PAS toucher les index restants (levier D) sans mesure d'usage (leçon P6.8-c).

## 6. INVARIANTS QUI NE PLIENT PAS (sinon on régresse ce qu'on a fermé)

- **Confidentialité (P10.1-a)** : aucun octet d'événement en clair sur disque hors SQLCipher/Parquet-
  scellé. La compression se fait en RAM sur la valeur. Le froid Parquet est scellé par jour.
- **Le DÉFAUT = la prod, et tout est paramétrable** (host/Docker/k3s). Un tiers doit obtenir nos
  chiffres. Chaque levier a son `PLUME_*`, défaut = ce qu'on décidera après mesure.
- **Générique** (P6.2-a) : les gains se mesurent sur PLUSIEURS profils, pas seulement le nôtre — nos
  événements de banc sont 4,4× plus gros que notre prod, donc un pire cas honnête.
- **Aucune perte silencieuse** : un résultat froid ou agrégé partiel se DÉCLARE (`AnswerShape`),
  jamais un total tronqué présenté comme exact.
- **Byte-identique en mode 0** : chaque levier OFF laisse le comportement actuel intact.

---
*Prochaine étape concrète : la mesure fondatrice du §5.1 (activer le froid sur copie de banc, mesurer
les 3 chiffres). Puis P10.3 (agrégation bornée). Ancré, pas supposé.*
