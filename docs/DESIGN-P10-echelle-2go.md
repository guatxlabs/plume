# P10 — Tenir sous 2 Go à l'échelle : chaud / froid / bloom / compression

> Brainstorm de conception, **ancré sur mesure** (2026-08-06). Ce document n'est PAS une décision
> figée : c'est la carte du terrain mesuré et l'ordre des leviers qui en découle. Chaque affirmation
> chiffrée porte sa source. Rien n'est construit sur la foi d'une intuition.

## 0. Ce qu'on cherche, et pourquoi c'est DEUX problèmes, pas un

L'exigence, formulée plusieurs fois par le mainteneur : « que la base tienne très peu de place, presque autant qu'un zstd,
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

**Base réelle** (`plume-daemon db-stats --par-objet`, pod live, lecture seule, **2026-08-09**) : une base
de l'ordre du Gio pour un peu moins de deux millions d'événements ⇒ **de l'ordre du Kio par événement**
sur disque · freelist **7,3 %** · auto_vacuum=none · comptabilité FERMÉE ✓ · parcours en **une vingtaine
de secondes par Gio**.

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
`#[cfg(feature="cold_tier")]` + gate runtime `PLUME_COLD_TIER`. ~~**OFF en production.**~~
**FAUX — corrigé le 2026-08-10 : il est ACTIF sur l'installation de référence** (`PLUME_COLD_TIER=1`,
des dizaines de fichiers-jour Parquet, des centaines de Mio, plus d'un mois de profondeur). Cette phrase
contredisait le §3 du MÊME fichier vingt lignes plus
bas, et elle a survécu à la correction du levier A faite le matin même : voir `P10.10-a`. Elle est
barrée et non effacée, parce que c'est elle qui a fait classer le levier A en tête pendant
quatre jours.

Le **chaud** n'a **AUCUNE compression au repos** aujourd'hui : la table `event` est en pages b-tree
non compressées.

⇒ **La question centrale du brainstorm n'est donc PAS « comment construire le froid » — il est
construit. C'est : (a) qu'est-ce qui EMPÊCHE de l'activer par défaut, et (b) que reste-t-il pour le
chaud qui, lui, ne bouge pas.**

## 2 bis. RE-DÉRIVATION DE L'ORDRE DEPUIS LES PARTS D'UNE BASE RÉELLE (second relevé du 2026-08-09)

Les leviers ci-dessous ont été ordonnés sur une ventilation de **banc** (3,65 M événements), publiée
avec l'affirmation « les proportions sont indépendantes de l'échelle ». **Une base réelle l'a
contredite.** Relevé pris par `db-stats --par-objet` (lecture seule vérifiée) sur le pod vivant :
une base de l'ordre du Gio, un peu moins de deux millions d'événements, comptabilité FERMÉE. *(Le premier appel a REFUSÉ de publier — « écart de 1 page » sous écriture concurrente. Le
fail-closed fonctionne, et il révèle que le chemin CLI n'a pas le `BEGIN DEFERRED` que
`ventilation_serie.rs` s'est donné.)*

| poste | part du fichier | part des octets **vivants** | ce que le texte des §3-§5 dit encore |
|---|---:|---:|---|
| données (tables) | **57,3 %** | 60,2 % | « 51 % » — **périmé** |
| — dont `event` | 55,0 % | 57,7 % | 5,8× l'objet suivant |
| **index b-tree** | **27,0 %** | 28,3 % | « 33 % » — **périmé** |
| FTS5 (shadow) | 10,9 % | 11,5 % | levier E, livré le 08-09 |
| pages libres | 4,8 % | — | — |

**LE PIÈGE DE LECTURE, à ne pas refaire.** Entre deux relevés du même jour à six heures d'écart,
`page_count` est **identique** alors que des dizaines de milliers d'événements sont entrés : la
croissance se paie sur la **freelist**
(7,3 % → 4,8 %), pas sur le fichier. Rapportée aux octets **vivants**, la composition est **plate**
(60,1/28,4/11,5 → 60,2/28,3/11,5). Qui comparerait les pourcentages **bruts** « découvrirait » que
données et index grossissent : ce serait un **artefact de la consommation de freelist**, pas un
mouvement structurel. Marge restante à ce rythme : moins d'une journée.

**Composition MARGINALE**, dérivée des deux relevés, comptabilité fermée à 0,1 % près (l'accroissement
des trois postes égale, au dixième de pour cent, la freelist consommée) : **~509 o / ~220 o / ~74 o ≈
802 o par événement net, réparti 63 / 27 / 9 %**. **Le marginal reproduit le stock.** Incertitude : ±3 % (données), ±7 % (index),
**±22 % (FTS)**.

**L'ORDRE RE-DÉRIVÉ, et ce qui change :**

| levier | poste visé, **re-mesuré** | ce qui change |
|---|---|---|
| **A** — activer le froid | 60,2 + 28,3 + 11,5 % de ce qu'il sort du chaud | **reste #1**, mais son arithmétique doit être réécrite (51/33 → 57,3/27,0). Sa tâche reste une **mesure** |
| **D** — index b-tree | **27,0 %** | **LE VRAI CHANGEMENT.** Second gisement, 27 % du stock **et** 27 % du marginal |
| **B** — compression du chaud | **57,3 %**, pas 51 % | vise **plus** que la carte ne le dit |
| **C** — agrégation bornée | orthogonal à la taille | inchangé : sa priorité tient à l'OOM, pas aux octets |
| **E** — compaction FTS | 10,9 % | livré (`4ca6339`) ; maintient le poste à son plancher |

**CE QUE LA MESURE IMPOSE, et c'est la conclusion de cette section.** Le §5.4 dit « ne PAS toucher
les index restants sans mesure d'usage » — et **personne ne l'a mesuré**. Or ce poste pèse
**27 % du fichier, plus que tout le FTS (10,9 %) + la freelist (4,8 %) réunis**. `sqlite_autoindex_event_1`
(un peu moins de 5 % du fichier) porte l'exactly-once de la dédup : hors de question. **Mais les 7 autres
pèsent 16,0 % du fichier**, derrière un panneau « ne pas toucher » sans mesure derrière.
À comparer : le levier E, un vrai effort d'ingénierie, gouverne 10,9 %.
⇒ **la mesure d'usage des index doit être promue à côté de l'étape 1**, pas rester une note de bas
de page en étape 4. Les deux sont des mesures, les deux sont bon marché, et le poste de D est 2,5×
celui de E.
Trois voies faisables, par fidélité croissante : (1) rejeu de `EXPLAIN QUERY PLAN` sur le corpus
**fermé** (panneaux de `seeds.rs`, table `rule`, `templates.json`, SQL du moteur de détection) —
énumérable, mais ne couvre pas l'ad hoc analyste ; (2) échantillonnage `1/N` des plans au point de
passage unique (`run_query_ex`/`soql_glue`), compté dans `metric` **par la machinerie de
`ventilation_serie` livrée le 08-09** — tick lent, borné, survit au redémarrage, aucune sonde neuve
dans le vide ; (3) *drop-and-watch*, que le dépôt fait déjà (`drop_redundant_event_indexes_background`),
mais dont **P6.8-c est la cicatrice** de l'avoir fait sans mesure.

**NON ÉTABLI, et le doc ne le revendique pas** : la chute FTS 18,9 % → 10,9 % est **cohérente** avec
la compaction et rien de plus. Trois relevés manuels ne distinguent pas un gain d'un creux
d'ingestion. C'est la série de ventilation (`c4c20f4`) qui tranchera.

## 3. LES QUATRE LEVIERS, ordonnés par (impact mesuré ÷ code neuf)

### ~~Levier A — ACTIVER l'aging froid (construit, OFF)~~ → **CLOS : IL N'A JAMAIS ÉTÉ « OFF » PAR DÉCISION, ET IL TOURNE** *(re-mesuré 2026-08-10)*

> **⚠ LA PRÉMISSE DE CE LEVIER ÉTAIT FAUSSE LE JOUR OÙ IL A ÉTÉ ÉCRIT — et la date le prouve.**
> Ce titre date de `5de5ccd`, **2026-08-06 00:54**. Le tier froid n'a cessé d'écrire que du
> **2026-08-05 au 2026-08-06** inclus, à cause d'un `Dockerfile` bâti `--features ldap` au lieu de
> `ldap,cold_tier`. Ces deux jours sont **le seul moment de toute l'histoire du dépôt** où
> l'observation « le froid ne produit rien » était vraie. **Un défaut de build de trois jours a été
> promu en état permanent de conception, et l'ORDRE DES QUATRE LEVIERS en a été dérivé.**
> La cause a été mesurée et écrite **le lendemain** (`6dac62e`, 2026-08-07 11:30) ; ni ce document
> ni la roadmap n'ont été rectifiés pendant quatre jours.
>
> **AUCUNE des quatre hypothèses listées ci-dessous n'a jamais eu à être éprouvée : aucune n'était
> la cause.** Elles sont conservées telles quelles, barrées, parce qu'effacer une hypothèse fausse
> effacerait la leçon.
>
> **ÉTAT MESURÉ SUR L'INSTALLATION DE RÉFÉRENCE LE 2026-08-10** (vérifié deux fois, indépendamment) :
> `PLUME_COLD_TIER=1` + 4 autres variables en `env:` du Deployment (aucun ConfigMap ne les porte) ·
> bannière `[cold] tier froid ACTIF — <n> fichier(s)-jour, <taille>` · symboles dans le binaire QUI
> TOURNE : `cold_store` **7**, `parquet` **32**, contre un témoin négatif à **0** · des dizaines de
> fichiers-jour Parquet, des centaines de Mio, plus d'un mois de profondeur.
> **La fenêtre d'amputation est lisible dans les dates d'écriture** — deux fichiers par jour avant la
> panne, **RIEN pendant ses deux jours**, puis un rattrapage le jour du correctif.
> C'est une preuve par mutation que l'histoire a jouée d'elle-même : feature retirée → 0 écrit ;
> feature rendue → rattrapage le jour même.
>
> **CE QUE LE LEVIER A RAPPORTE, MESURÉ ET NON PLUS ESPÉRÉ** (série de ventilation horaire, N=1
> vieillissement observé, 2026-08-10) : un jour vieilli rend **de l'ordre de la centaine de Mio** à la
> freelist — données, index et **FTS5** à parts inégales (environ 64 / 22 / 14 %) · fichier **inchangé**.
> Comptabilité fermée aux deux bornes. Le jour sorti pèse **quelques Mio** au froid. **Un jour vieilli =
> un ratio d'environ 30× entre octets rendus au chaud et octets écrits au froid** — et il emporte bien
> les trois postes, ce qui **confirme `P10.2-a`** (l'aging emporte la quote-part FTS) sur une base réelle.
>
> **ET VOICI LE VRAI PROBLÈME, QUE PERSONNE NE REGARDAIT** : la freelist se reconsomme à
> un rythme **supérieur de 10 à 25 %** à ce que l'aging rend par jour (deux fenêtres indépendantes) →
> **un déficit net, de l'ordre du dixième de ce que rend l'aging**. Au rythme du dernier point, les
> pages libres s'épuisent en **quelques jours**, après quoi le fichier recommence à croître. **L'aging freine la
> croissance, il ne l'annule pas.** Ce qui reste sur la table est donc ce qui réduit les octets PAR
> ÉVÉNEMENT CHAUD — le **levier B** — et non le levier A.
>
> **CE QUI RESTE NON MESURÉ, ET C'EST NOMMÉ** : la crête RAM *imputable* au vieillissement.
> `memory.peak` du cgroup vaut près des trois quarts de la limite et `VmHWM` environ le tiers, mais ce
> sont des maxima **cumulés et non horodatés** sur près d'une journée — rien ne dit s'ils tombent pendant l'aging ou
> pendant une requête. Idem pour la durée, le CPU et l'effet sur la latence chaude : **le
> vieillissement est totalement MUET** (une centaine de Mio libérés sans une ligne de journal), ce qui est
> exactement `P10.5-a`, toujours ouvert. **LA mesure qui débloque les quatre axes d'un coup** : une
> ligne de succès par `cold_age_run` portant jour, lignes, octets, durée et crête RSS. ~10 lignes,
> et trois des quatre axes deviennent observables sans banc ni copie de production.
>
> Bornes de conception, lues dans le code et confrontées au réel : écriture plafonnée à un seul
> row-group (`ROW_GROUP_ROWS = 262 144`) — un jour énorme fait PLUS de fichiers, pas de plus gros ;
> lecture = `degré × un fichier déchiffré`, soit quatre fichiers-jour de quelques Mio chacun en vol,
> négligeable devant 2 Gio.

### ~~Levier A (texte d'origine, conservé barré)~~ · impact ÉNORME, code neuf ~0
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
  décompresse-à-la-lecture que le besoin **pointe explicitement** (« la décompression peut se coûter si
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
du banc ci-dessus et les 17,9 % relevés sur une base réelle : de la **trace d'aging**, pas de la croissance.

> **CE QUE LE RELEVÉ SUIVANT DIT — ET CE QU'IL NE DIT PAS.** Le 2026-08-09, au lendemain du
> déploiement de ce levier, la base réelle mesure **FTS5 = 10,7 %** (`event_fts_data` 9,3 % du
> fichier). C'est cohérent avec un gain de compaction. **Ce n'est pas une preuve** : trois relevés
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

1. ~~**MESURER pourquoi le froid est OFF** (levier A)~~ → **FAIT, ET LE LEVIER EST CLOS**
   *(2026-08-10)*. Il n'était pas OFF : la ligne ci-dessus a été écrite **pendant** une panne de
   build de trois jours, la seule fenêtre où elle était vraie. Il tourne, il rend **de l'ordre de la
   centaine de Mio par jour** au chaud pour quelques Mio écrits au froid, et **ce gain est déjà DANS la
   ligne de base relevée** —
   ce n'est pas un gain à venir. **Ce qui prend sa place en tête n'est pas un des quatre leviers** :
   c'est **une ligne de succès sur `cold_age_run`** (`P10.5-a`), ~10 lignes, qui rend mesurables
   d'un coup la durée, le CPU, la crête RAM imputable et l'effet sur la latence — aujourd'hui tous
   les quatre inconnus parce que le vieillissement est MUET. **Puis le levier B**, seul à attaquer
   le déficit net de freelist que la mesure fait apparaître.
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
