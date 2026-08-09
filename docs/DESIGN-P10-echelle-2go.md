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

## 1. LA MESURE — où partent les octets

> ⚠ **CE TABLEAU A DÉJÀ MENTI UNE FOIS, ET IL FAUT SAVOIR POURQUOI.** Sa première version venait du
> BANC (3,65 M év., base non chiffrée) et annonçait que « les PROPORTIONS sont indépendantes de
> l'échelle ». La production l'a contredit : **index 32,8 % → 25,4 %**, **FTS5 8,1 % → 18,9 %**. Une
> proportion de banc n'est pas une loi. **Et un relevé ne fait pas une série** : entre le 08-08
> (FTS 18,9 %) et le 08-09 (FTS 10,7 %) l'écart pourrait venir de la compaction `4ca6339`, de
> l'aging, ou d'un creux de trafic — **deux points ne le disent pas**. C'est ce trou qui est
> désormais fermé : la MÊME mesure est écrite chaque heure dans `metric` par `ventilation_serie`, et
> le tableau ci-dessous se **re-dérive sans relever quoi que ce soit** :
>
> ```
> metric plume_db_poste_bytes by poste | timechart span=1d avg(value) by poste
> ```
>
> Les parts se calculent depuis cette série SEULE (la somme des seaux EST le fichier — c'est ce que
> la comptabilité fermée garantit). Quand la mesure ne peut pas être prise, la série porte un TROU et
> `plume_db_ventilation_ok` passe à 0 avec sa cause — jamais un zéro d'octets.

**Production** (`plume-daemon db-stats --par-objet`, pod live, lecture seule, **2026-08-09**) :
**1 586,8 MiB** / 406 213 pages pour **1 715 910 événements** ⇒ **~970 o/événement** sur disque ·
freelist **7,3 %** · auto_vacuum=none · comptabilité FERMÉE ✓ · parcours **35,4 s** (22,9 s/Gio).

| poste | part | objets dominants |
|---|---:|---|
| **données (tables)** | **55,7 %** | `event` **53,4 %** |
| **index b-tree** | **26,3 %** | `sqlite_autoindex_event_1` 4,6 % · `idx_event_src_srcip` 3,1 % · `idx_event_src_ts` 2,6 % · `idx_event_host` 2,6 % · `idx_event_sev_srcip` 2,1 % · `idx_event_srcip` 2,0 % · `idx_event_ts` 1,6 % · `idx_event_category` 1,6 % |
| **FTS5 (shadow)** | **10,7 %** | `event_fts_data` 9,3 % |
| NON CLASSÉ | 0,0 % | — |
| pages libres | 7,3 % | — |

**Trois faits qui commandent la conception :**

1. **La table `event` est la MOITIÉ de la base, et elle est stockée EN CLAIR-PAGE** (SQLCipher
   chiffre la page, mais ne la COMPRESSE pas). Les valeurs sont du log SIEM — `message`, `fields`
   JSON — qui compressent **×10 à ×40** au zstd. C'est le plus gros levier unique, et il est intact.
2. **Un QUART de la base est de l'index b-tree** (26,3 % en production ; 32,8 % au banc — l'écart
   est réel, la part de banc était trop haute). La compression n'y peut presque rien (ce sont des
   clés déjà compactes). Mais un **tier froid colonnaire les ÉLIMINE** : le froid ne porte pas de
   b-tree, il prune par **bloom + zone-maps** (quelques bits par valeur vs une entrée d'index par
   ligne).
3. **FTS ≈ 11 % en production** (contre 8 % annoncés depuis le banc), entièrement **droppable au
   froid** (une requête froide scanne un row-group borné ou s'appuie sur le bloom ; pas besoin du
   shadow FTS sur des données rarement fouillées en plein texte). C'est le poste le plus VOLATIL des
   trois — d'où la série.

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

### Levier E — COMPACTER L'INDEX PLEIN-TEXTE (P10.7-b, construit le 2026-08-09) · le seul gratuit

**Ce levier manquait à la liste ci-dessus, et son absence était mesurable.** Les quatre leviers A–D
supposent tous que l'index plein-texte grossit avec les données. **C'est faux : il grossit AUSSI avec
les SUPPRESSIONS.** Une table FTS5 à contenu externe ne peut pas retirer un posting en place — le
déclencheur `event_ad` en écrit un de SUPPRESSION, qui s'AJOUTE — et l'espace n'est rendu qu'à la
FUSION DES SEGMENTS, que plume ne déclenchait **jamais**. C'est une part de l'écart entre les 8,1 %
du banc ci-dessus et les 17,9 % relevés en production : de la **trace d'aging**, pas de la croissance.

> **CE QUE LE RELEVÉ SUIVANT DIT — ET CE QU'IL NE DIT PAS.** Le 2026-08-09, au lendemain du
> déploiement de ce levier, la production mesure **FTS5 = 10,7 %** (`event_fts_data` 9,3 % sur
> 1 586,8 Mio). C'est cohérent avec un gain de compaction. **Ce n'est pas une preuve** : trois relevés
> manuels espacés de jours ne distinguent pas un gain de compaction d'un creux d'ingestion ou d'un
> aging moins actif. La preuve viendra de la série (`plume_db_poste_bytes{poste="fts"}`, un point par
> heure depuis ce lot) — c'est exactement la question qu'elle a été construite pour trancher.

Mesuré le 2026-08-09 sur la SQLite exacte du produit (SQLCipher 4.5.3 / SQLite 3.39.4 vendorée,
PRAGMA de `server::tune`), base au profil de `bench/profile-prod.json`, 1 200 000 événements puis un
`DELETE` réel de 58,4 % :

| grandeur | avant purge | après purge | après compaction |
|---|---|---|---|
| `event_fts_docsize` | 14,11 Mio | **5,88 Mio** (−58,3 %, il SUIT) | 5,88 Mio |
| `event_fts_data` | 135,27 Mio | **185,69 Mio** (+37,3 %, il GROSSIT) | **56,53 Mio** (−69,6 %) |

**Le comment compte autant que le combien.** `optimize` et `merge` atteignent le même plancher, mais
`optimize` le fait en **17,08 s d'un seul tenant sous le verrou d'écriture, avec 192,6 Mio de rafale
WAL**, et une interruption perd tout ; `merge` à budget **NÉGATIF** (`-500` pages/passe) le fait en
25 passes de **1,04 s au pire**, avec **13,4 Mio de WAL**, et chaque passe committée survit à un
`SIGKILL` — la reprise converge à l'octet près. Le budget POSITIF, lui, ne rend **rien du tout** sur
cet index (aucun niveau n'atteint `usermerge`) : c'est le piège du levier. Ces deux dépenses (verrou,
WAL) sont fixées par le budget de passe et **ne grandissent pas avec l'index** — vérifié au double du
volume. La RAM est celle du `cache_size` et rien d'autre (66,3 Mio, identique pour les deux bras).

Livré : `daemon/src/compactage_fts.rs`, appelé en fin de `retention_run` (là où le poids mort vient
d'être créé) et par `plume-daemon fts-compact`. Réglages `PLUME_FTS_COMPACT`(=1) /
`_PAGES`(=500) / `_PASSES`(=8) / `_REPOS_MS`(=200), tous par `cfg()`. **Ce que ce levier ne fait
pas** : rétrécir le fichier. Les pages vont à la freelist et sont réemployées par l'ingestion ;
`page_count` ne bouge pas.

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
