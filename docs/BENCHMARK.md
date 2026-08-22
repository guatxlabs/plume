# Banc de mesure plume — requêtes à chaud sous 2 Gio

<!-- CE FICHIER EST GÉNÉRÉ par bench/report.py (voir la section « Reproduire » en bas).
     Ne pas l'éditer à la main : la prochaine passe l'écrase. Tout commentaire durable va dans
     bench/README.md. -->

Rendu le 2026-08-03 10:23:43+0200 depuis `results-smoke-200k.jsonl`, `results.jsonl`, `results-2026-07-31.jsonl`, `results-2026-07-31-corrige.jsonl`, `parity-avant-2026-07-31.jsonl`, `parity-apres-2026-07-31.jsonl`, `parity-couverture-2026-07-31.jsonl`, `concurrency-2026-08-01.jsonl`, `concurrency-reproduction-2026-08-01.jsonl`, `concurrency-attribution-2026-08-01.jsonl`, `concurrency-corrige-2026-08-01.jsonl`, `generique-2026-08-03.jsonl` — données brutes VERSIONNÉES dans [`bench/results/`](../bench/results/), pour que ce tableau puisse être contredit et pas seulement cru (cf. `bench/README.md`).

## Ce que ce document est, et ce qu'il n'est pas

C'est la **mesure de référence** de plume, prise avec un instrument publié et rejouable.
Chaque chiffre porte ses qualificatifs. Rien n'est extrapolé : une case vide est une case
**non mesurée**, pas une case implicitement bonne. Quand plusieurs passes coexistent au même
volume, elles sont TOUTES rendues : une passe n'est jamais remplacée par une plus flatteuse,
et la section « Écart mesuré entre deux passes » dit laquelle décrit le code actuel.

Ce n'est **pas** une comparaison à un autre produit, ni une mesure de production : c'est un
banc synthétique au **profil** de la production (voir `bench/profile-prod.json`).

## Verdict — ce que ces mesures autorisent à affirmer

Volume de référence : **1 440 007 événements** (`chaud-seul-v2@1.4M`), base **1434 Mio** chiffrée SQLCipher.

**Sur le budget de 2 Gio — soutenu.** RSS crête la plus haute mesurée sur l'ensemble des cellules : **1097 Mio**, soit **54 %** du budget. Et ce n'est pas une observation passive : le daemon tournait sous `MemoryMax=2G MemorySwapMax=0`, où un dépassement est un kill du noyau.

**Ce qui est RAPIDE** (p50, fenêtre indiquée, config de référence) :

- `C0-plancher` / all — **0.6 ms** (PLANCHER : seek sur une source inexistante (0 ligne)), servi par `raw`
- `C0-plancher` / au-dela-7d — **0.6 ms** (PLANCHER : seek sur une source inexistante (0 ligne)), servi par `raw`
- `C0-plancher` / 7d — **0.7 ms** (PLANCHER : seek sur une source inexistante (0 ligne)), servi par `raw`
- `C0-plancher` / 1h — **0.7 ms** (PLANCHER : seek sur une source inexistante (0 ligne)), servi par `raw`

**Ce qui est LENT** — et ce sont les cas que la promesse « sur tous les champs » met en avant :

- `C6b-groupby-host` / 7d — **22.2 s** (group-by sur host (autant de groupes que de machines)), servi par `raw`
- `C3c-groupby-json` / au-dela-7d — **21.8 s** (group-by sur champ ÉTENDU indexé (action) + colonne), servi par `raw`
- `C6b-groupby-host` / au-dela-7d — **20.9 s** (group-by sur host (autant de groupes que de machines)), servi par `raw`
- `C3-groupby-hi` / all — **14.2 s** (group-by 3 dims haute cardinalité (src_ip,host,source)), servi par `raw`

**Le disque n'a pas été sollicité — et c'est une limite, pas une bonne nouvelle.** Octets lus au bloc, maximum sur toutes les cellules : **0 Mio**. La base (1434 Mio) tient entièrement dans le cache de pages de la machine (6839 Mio de mémoire disponible au minimum pendant la mesure). Ces latences sont donc **bornées par le CPU, pas par le stockage**, et constituent un MEILLEUR CAS. À un volume où la base dépasse la RAM disponible, le stockage entre dans l'équation — et ce régime n'est pas mesuré ici.

**Ce que ces mesures n'autorisent PAS à affirmer** :

- rien au-delà de 1 440 007 événements. La cible de 10 M n'a pas été atteinte par le vrai chemin d'ingest — non pas faute de l'avoir cherché, mais parce que le débit d'ingest s'effondre avec le volume déjà en base, ce que la section « D'où vient l'effondrement » ATTRIBUE désormais (et non plus suppose) : le coût CPU par événement monte, le daemon écrit de plus en plus d'octets par ligne, et le chemin d'écriture est séquentiel. Le coût restant pour atteindre 10 M y est chiffré, en tant que PLANCHER arithmétique sur des débits mesurés. Toute latence annoncée à 10 M ou 100 M serait une extrapolation, pas une mesure.
- rien sur le multi-tenant (voir la section dédiée). Le tier froid, lui, EST mesuré ici — mais seulement dans `froid-actif@1.4M`, `froid-actif-v2@1.4M`, à une seule fenêtre chaude et un seul volume : les autres tableaux restent des tableaux SANS tier froid.
- la CONCURRENCE, elle, est mesurée : jusqu'à 10 analystes simultanés lançant de très grosses requêtes sous le même budget de 2 Gio appliqué, avec vérification que la réponse concurrente est IDENTIQUE à la réponse obtenue seul (section dédiée).
- rien sur un déploiement AVEC masquage à partir des chiffres masque-vide : l'écart mesuré le plus fort est **x287.3** sur `C3b-groupby-routable` / 24h (8.6 ms masque vide contre 2.5 s masque non vide).
  Et le masquage ne va pas TOUJOURS dans le sens du ralentissement : sur `C2-free-term` / 24h il est **x0.14**, donc plus RAPIDE (741 ms masque vide contre 101 ms masque non vide, même nombre de lignes rendues). **La cause n'est PAS établie par cette mesure**, et on ne va pas l'inventer. Deux mécanismes candidats, qui demandent chacun une expérience dédiée pour être départagés : (a) un masque posé sur une dimension à haute cardinalité l'effondre, il reste moins de groupes à agréger — la requête va plus vite **parce que la réponse a changé** ; (b) la passe masquée a tourné APRÈS la passe non masquée, donc sur un cache de pages plus chaud. Ce qui trancherait : rejouer les deux passes dans l'ordre inverse, et comparer les résultats ligne à ligne. En attendant, la règle est simple — **une latence qui baisse en présence d'un masque ne doit jamais être citée comme un gain**.

## Matériel et conditions

| | |
|---|---|
| Processeur | Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz (12 cœurs logiques) |
| RAM de la machine | 15.4 Gio |
| Noyau | 7.1.4-zen1-1-zen |
| Version de plume mesurée | `bin:72c367a16a91f06a construit:2026-08-03T06:02:47Z (HEAD au rendu: 77600da — indicatif, l'arbre bouge)` |
| Volumes mesurés | 200 003 événements, 335 255 événements, 600 003 événements, 1 440 003 événements, 1 440 007 événements |
| Taille de la base (SQLCipher, chiffrée) | 1039 Mio, 1263 Mio, 1401 Mio, 1434 Mio, 197 Mio, 336 Mio, 351 Mio, 377 Mio, 560 Mio, 634 Mio, 647 Mio, 649 Mio, 656 Mio |
| Budget mémoire | **appliqué** par un scope systemd `MemoryMax=2G MemorySwapMax=0` — la même contrainte que la limite de conteneur de production (`limits.memory: 2Gi`) |
| Concurrence de requêtes | `PLUME_QUERY_CONCURRENCY=3` (le défaut livré) |
| Passes de CONCURRENCE | 1, 2, 3, 4, 6, 8, 10 analystes simultanés, sémaphore 3 et 8 (section dédiée) |
| Budget par requête | interactif, 60 s (`interactive:true`) |

**Plusieurs binaires** figurent dans ce document : `10db2d2`, `bin:0642474ceedfaf15`, `bin:4bfcb9f76b4353a2`, `bin:72c367a16a91f06a`, `bin:b2d10fa90506682c`, `bin:bc481b69f4aca22c`, `ea1d072`. Chaque cellule porte le sien dans le JSONL brut, et chaque tableau de configuration l'affiche dans son sous-titre. Une comparaison entre deux tableaux de binaires différents mesure aussi l'écart entre les deux binaires — ce n'est légitime que dans la section « Écart mesuré entre deux passes », qui le dit.

**Honnêteté sur les conditions** : la machine de mesure n'était pas dédiée — d'autres travaux
tournaient en parallèle. Chaque cellule enregistre son `loadavg` et le swap consommé pendant
la mesure ; les cellules prises sous swap sont marquées et listées plus bas. Le daemon lui-même
ne pouvait pas swapper (`MemorySwapMax=0`), donc sa RSS crête est une vraie crête, mais les
latences absolues sont **pessimistes** sur une machine chargée.

## Débit d'ingest mesuré (chemin HTTP complet)

| Événements | Durée | Débit | Base après | `PLUME_FTS_FIELDS` | Binaire |
|---:|---:|---:|---:|:--:|---|
| 200 000 | 67 s | **2 985 ev/s** | 166 Mio | 0 | `10db2d2` |
| 1 400 000 | 816 s | **1 715 ev/s** | 1214 Mio | 0 | `bin:0642474ceedfaf15` |
| 600 000 | 212 s | **2 830 ev/s** | 545 Mio | 0 | `bin:bc481b69f4aca22c` |
| 600 000 | 131 s | **4 580 ev/s** | 321 Mio | 0 | `bin:bc481b69f4aca22c` |
| 600 000 | 128 s | **4 687 ev/s** | 337 Mio | 0 | `bin:bc481b69f4aca22c` |
| 600 000 | 309 s | **1 941 ev/s** | 623 Mio | 0 | `bin:72c367a16a91f06a` |
| 600 000 | 308 s | **1 948 ev/s** | 609 Mio | 0 | `bin:72c367a16a91f06a` |
| 600 000 | 155 s | **3 870 ev/s** | 356 Mio | 0 | `bin:72c367a16a91f06a` |
| 600 000 | 313 s | **1 916 ev/s** | 621 Mio | 0 | `bin:72c367a16a91f06a` |
| 600 000 | 326 s | **1 840 ev/s** | 619 Mio | 0 | `bin:72c367a16a91f06a` |
| 600 000 | 512 s | **1 171 ev/s** | 1012 Mio | 0 | `bin:72c367a16a91f06a` |
| 444 000 | 541 s | **820 ev/s** | 1217 Mio | 0 | `—` |
| 1 400 000 | 801 s | **1 747 ev/s** | 1214 Mio | 0 | `—` |

Chemin traversé : `POST /api/ingest -> spool -> ingest_events_batch (normalisation, promotion de colonnes, cim_stamp, déclencheurs FTS, index d'expression)`.

> Ligne de 444 000 événements : **reconstruit depuis l'échantillonneur (premier et dernier point mesurés), le remplissage ayant été borné en temps.**

> Ligne de 1 400 000 événements : **reconstruit depuis l'échantillonneur (premier et dernier point mesurés), le remplissage ayant été borné en temps.**

Débit **cumulé** relevé par le générateur lui-même pendant le remplissage (il est régulé sur la profondeur du spool : son débit de production est donc le débit d'ingest de bout en bout). Ces points couvrent le DÉBUT du remplissage :

| Événements produits | Volume produit | Débit cumulé mesuré |
|---:|---:|---:|
| 600 000 | 302 Mio | **7 190 ev/s** |
| 1 200 000 | 604 Mio | **3 018 ev/s** |

Le débit cumulé passe de **7 190 ev/s** à **3 018 ev/s** entre 600 000 et 1 200 000 événements produits, soit **x2.4**. Deux causes se superposent — le volume déjà en base (maintenance des index et de la FTS5) et la charge de la machine — et cette passe ne les sépare pas. À ce débit-là, atteindre 10 M depuis ce point aurait demandé plusieurs heures de plus : c'est ce qui a borné CETTE passe-ci, et cela ne dit rien des autres passes du document.

### Courbe de remplissage — `ingest_rate.csv`

#### Le débit d'ingest se dégrade avec le volume — mesuré, pas supposé

Un débit moyen seul cacherait cette dégradation. Chaque ligne est un intervalle
d'échantillonnage réel pendant le remplissage (la maintenance des index et de la
FTS coûte de plus en plus cher à mesure que les b-trees grossissent).

| Lignes en base | Taille base | RSS du daemon | Débit sur l'intervalle | `loadavg` |
|---:|---:|---:|---:|---:|
| 1 032 003 | 889 Mio | 484 Mio | 685 ev/s | 9.8 |
| 1 068 003 | 918 Mio | 599 Mio | 562 ev/s | 10.8 |
| 1 152 003 | 988 Mio | 599 Mio | 1 272 ev/s | 6.2 |
| 1 236 003 | 1058 Mio | 617 Mio | 1 105 ev/s | 6.6 |
| 1 272 003 | 1087 Mio | 639 Mio | 571 ev/s | 11.3 |
| 1 308 003 | 1117 Mio | 638 Mio | 571 ev/s | 14.0 |
| 1 368 003 | 1168 Mio | 685 Mio | 937 ev/s | 7.5 |
| 1 428 003 | 1217 Mio | 637 Mio | 800 ev/s | 9.5 |

Débit sur les intervalles échantillonnés : **min 562 ev/s, médiane 800 ev/s, max 1273 ev/s**, pour un `loadavg` allant de 6.2 à 14.0. L'écart d'un facteur 2.3 entre le plus lent et le plus rapide intervalle suit le `loadavg` : **cette passe ne sépare pas** le volume déjà en base de la charge de la machine — son CSV est antérieur à la sonde qui relève le CPU par processus. À lire comme un PLANCHER.

La colonne RSS est la mémoire réellement occupée par le daemon PENDANT l'ingest — crête échantillonnée ici : **685 Mio**, à confronter au budget de 2 Gio. C'est une mesure, pas une estimation.

> Portée de cette courbe : l'échantillonneur ne couvre que la fenêtre où il a tourné (1 032 003 à 1 428 003 lignes). Ce qui s'est passé avant n'est pas dans ce tableau, et n'est donc pas mesuré ici.

### Courbe de remplissage — `ingest_rate-quiet-2g.csv`

#### Le débit d'ingest se dégrade avec le volume — mesuré, pas supposé

Un débit moyen seul cacherait cette dégradation. Chaque ligne est un intervalle
d'échantillonnage réel pendant le remplissage (la maintenance des index et de la
FTS coûte de plus en plus cher à mesure que les b-trees grossissent).

| Lignes en base | Taille base | RSS du daemon | Débit sur l'intervalle | `loadavg` |
|---:|---:|---:|---:|---:|
| 144 003 | 118 Mio | 227 Mio | 4 500 ev/s | 1.8 |
| 372 003 | 363 Mio | 588 Mio | 3 076 ev/s | 2.4 |
| 528 003 | 493 Mio | 382 Mio | 1 935 ev/s | 2.1 |
| 648 003 | 592 Mio | 412 Mio | 1 875 ev/s | 2.8 |
| 768 003 | 691 Mio | 412 Mio | 1 818 ev/s | 3.2 |
| 852 003 | 761 Mio | 537 Mio | 1 411 ev/s | 3.3 |
| 948 003 | 840 Mio | 554 Mio | 1 548 ev/s | 3.5 |
| 1 032 003 | 909 Mio | 558 Mio | 1 200 ev/s | 3.3 |
| 1 116 003 | 979 Mio | 557 Mio | 1 161 ev/s | 3.0 |
| 1 212 003 | 1058 Mio | 508 Mio | 1 142 ev/s | 2.7 |
| 1 296 003 | 1128 Mio | 611 Mio | 1 297 ev/s | 3.3 |
| 1 368 003 | 1188 Mio | 505 Mio | 837 ev/s | 3.2 |

##### D'où vient l'effondrement — attribution mesurée, pas supposée

Un débit qui tombe ne dit pas POURQUOI il tombe. Trois grandeurs le disent, et
elles sont relevées à chaque tick par `bench/probe.py` :

- **CPU du daemon par événement** — s'il monte, le travail par ligne grandit
  vraiment (b-trees plus profonds, index et FTS à maintenir) : c'est le VOLUME.
- **CPU consommé par le reste de la machine** — c'est la CONTENTION. Elle inclut
  les fils noyau qui exécutent NOS propres écritures : ce n'est donc pas
  seulement « d'autres travaux », c'est « du CPU non facturé au daemon ».
- **Octets lus au bloc et stall mémoire du cgroup** — si le plafond de 2 Gio
  forçait la récupération du cache de pages, ils monteraient. Le budget est
  appliqué par ce même cgroup, et son cache de pages lui est facturé.

| Lignes en base | Débit | CPU daemon / événement | cœurs daemon | cœurs du reste | lu au bloc | écrit / 1 000 év. | stall mémoire | part de la sonde |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 144 003 | 4 500 ev/s | 0.142 ms | 0.64 | 1.50 | 0 Mio | 4.3 Mio | 0 ms | 7.3 % |
| 372 003 | 3 076 ev/s | 0.216 ms | 0.66 | 1.81 | 0 Mio | 9.2 Mio | 0 ms | 21.3 % |
| 528 003 | 1 935 ev/s | 0.203 ms | 0.39 | 1.85 | 0 Mio | 11.3 Mio | 0 ms | 1.3 % |
| 648 003 | 1 875 ev/s | 0.266 ms | 0.50 | 1.98 | 0 Mio | 13.1 Mio | 0 ms | 7.4 % |
| 768 003 | 1 818 ev/s | 0.257 ms | 0.47 | 2.00 | 0 Mio | 14.7 Mio | 0 ms | 9.8 % |
| 852 003 | 1 411 ev/s | 0.323 ms | 0.46 | 2.08 | 0 Mio | 15.9 Mio | 0 ms | 10.6 % |
| 948 003 | 1 548 ev/s | 0.303 ms | 0.47 | 2.14 | 0 Mio | 16.6 Mio | 0 ms | 4.7 % |
| 1 032 003 | 1 200 ev/s | 0.438 ms | 0.53 | 2.01 | 0 Mio | 18.5 Mio | 0 ms | 1.2 % |
| 1 116 003 | 1 161 ev/s | 0.371 ms | 0.43 | 2.02 | 0 Mio | 18.8 Mio | 0 ms | 4.4 % |
| 1 212 003 | 1 142 ev/s | 0.401 ms | 0.46 | 1.94 | 0 Mio | 20.0 Mio | 0 ms | 28.0 % |
| 1 296 003 | 1 297 ev/s | 0.288 ms | 0.37 | 2.21 | 0 Mio | 19.7 Mio | 0 ms | 17.6 % |
| 1 368 003 | 837 ev/s | 0.603 ms | 0.51 | 1.94 | 0 Mio | 21.8 Mio | 0 ms | 30.7 % |

« Part de la sonde » = ce que le COMPTAGE DES LIGNES de l'échantillonneur consomme de l'intervalle : **7.4 % en médiane**, **30.7 % au pire**. Ce comptage est un scan servi par le daemon : son coût est DANS les colonnes CPU et débit ci-dessus. La dégradation nette du produit est donc un peu plus faible que celle affichée — jamais plus forte.

Entre 144 003 et 1 400 003 lignes en base, le débit passe de **2 984 à 1 082 ev/s** (**÷2.76**) et le coût CPU du daemon par événement de **0.198 à 0.442 ms** (**×2.23**).

Cette chute se FACTORISE, sans reste, en deux facteurs mesurés — le débit est exactement `cœurs occupés / CPU par événement` :

> **÷2.76** (débit mesuré) = **×2.23** (CPU par événement : le travail par ligne grandit avec les b-trees) × **÷1.21** (cœurs occupés par le daemon : 0.56 au début contre 0.47 à la fin — il ATTEND davantage). Le produit vaut ÷2.70, soit 2 % d'écart avec la chute mesurée : l'écart est celui de la moyenne par quartile, l'identité `débit = cœurs / CPU par événement` étant exacte intervalle par intervalle.

Le travail par ligne grandit donc RÉELLEMENT avec le volume déjà en base : c'est le VOLUME, pas la machine. Et le daemon n'occupe jamais plus de 0.66 cœur sur les 12 disponibles : le chemin d'écriture est SÉQUENTIEL, ajouter des cœurs n'y changerait rien.

Le daemon occupe **0.47 cœur** en médiane pendant que le reste de la machine en occupe **2.01** (12 cœurs disponibles). La machine n'est donc pas saturée : la chute n'est pas une contention de CPU disponible.

**Ce que coûterait 10 000 000 événements** : au DERNIER débit mesuré (1 082 ev/s), il resterait 8 599 997 événements à ingérer, soit **2.2 h** — et c'est un PLANCHER, puisque le débit a déjà été divisé par 2.8 sur la plage mesurée et continue de baisser. Cette ligne est de l'arithmétique sur des débits mesurés, PAS une mesure à ce volume : aucune latence de ce document ne vaut au-delà du volume réellement rempli.

**Le stockage n'est pas en cause côté LECTURE** : 0 Mio lus au bloc sur tout le remplissage — la base tient dans le cache de pages. **Le plafond de 2 Gio ne freine pas non plus par récupération mémoire** : 0.0 s de stall mémoire cumulé sur le cgroup, mesuré.

Débit sur les intervalles échantillonnés : **min 837 ev/s, médiane 1455 ev/s, max 4500 ev/s**, pour un `loadavg` allant de 1.8 à 3.7. L'écart d'un facteur 5.4 entre le plus lent et le plus rapide intervalle n'est plus interprété depuis le `loadavg` : la sous-section d'attribution ci-dessus le décompose en CPU du daemon, CPU du reste de la machine et attente du stockage — trois grandeurs mesurées.

La colonne RSS est la mémoire réellement occupée par le daemon PENDANT l'ingest — crête échantillonnée ici : **611 Mio**, à confronter au budget de 2 Gio. C'est une mesure, pas une estimation.

> Portée de cette courbe : l'échantillonneur ne couvre que la fenêtre où il a tourné (144 003 à 1 400 003 lignes). Ce qui s'est passé avant n'est pas dans ce tableau, et n'est donc pas mesuré ici.

## Configurations mesurées

| Étiquette | Événements | Hôtes | `PLUME_FTS_FIELDS` | Masquage de champs | Tier froid | Classes mesurées |
|---|---:|---:|:--:|---|:--:|---|
| `fts0-masque-vide` | 200 003 | ? | 0 | vide | off | toutes (42 cellules) |
| `fts0-masque-non-vide` | 200 003 | ? | 0 | non-vide (src_ip=mask, fields.user=partial) | off | toutes (42 cellules) |
| `fts0-masque-vide@1.4M` | 1 440 003 | ? | 0 | vide | off | toutes (51 cellules) |
| `fts0-masque-non-vide@1.4M` | 1 440 003 | ? | 0 | non-vide (src_ip=mask, fields.user=partial) | off | toutes (51 cellules) |
| `fts1-masque-vide@1.4M` | 1 440 003 | ? | 1 | vide | off | **sous-ensemble** `C0-,C2,C5` (27 cellules) |
| `avant-leviers@1.4M` | 1 440 007 | ? | 0 | vide | off | toutes (54 cellules) |
| `apres-leviers@1.4M` | 1 440 007 | ? | 0 | vide | off | toutes (54 cellules) |
| `chaud-seul@1.4M` | 1 440 007 | 64 | 0 | vide | off | toutes (105 cellules) |
| `froid-actif@1.4M` | 335 255 | 64 | 0 | vide | actif (hot=7j) | toutes (105 cellules) |
| `flotte-1h@0.6M` | 600 003 | 1 | 0 | vide | off | **sous-ensemble** `C0-,C1-scan-agg,C3-groupby-hi,C6` (30 cellules) |
| `flotte-50h@0.6M` | 600 003 | 50 | 0 | vide | off | **sous-ensemble** `C0-,C1-scan-agg,C3-groupby-hi,C6` (30 cellules) |
| `flotte-200h@0.6M` | 600 003 | 200 | 0 | vide | off | **sous-ensemble** `C0-,C1-scan-agg,C3-groupby-hi,C6` (30 cellules) |
| `froid-actif-v2@1.4M` | 1 440 007 | 64 | 0 | vide | actif (hot=7j) | toutes (105 cellules) |
| `chaud-seul-v2@1.4M` | 1 440 007 | 64 | 0 | vide | off | toutes (105 cellules) |
| `temoin-64h@0.6M` | 600 003 | 64 | 0 | vide | off | toutes (105 cellules) |
| `flotte-1h-v2@0.6M` | 600 003 | 1 | 0 | vide | off | toutes (105 cellules) |
| `flotte-50h-v2@0.6M` | 600 003 | 50 | 0 | vide | off | toutes (105 cellules) |
| `card-haute@0.6M` | 600 003 | 64 | 0 | vide | off | toutes (105 cellules) |
| `sev-haute@0.6M` | 600 003 | 64 | 0 | vide | off | toutes (105 cellules) |
| `temoin-bis@0.6M` | 600 003 | 64 | 0 | vide | off | toutes (105 cellules) |
| `taille-grande@0.6M` | 600 003 | 64 | 0 | vide | off | toutes (105 cellules) |

Le masquage compte parce qu'il est **contre-intuitif** : un ensemble de masquage non vide
désarme la route de rollups *et* le moteur vectorisé (`handlers/query.rs:282`,
`cold_store/planner.rs:601`). Le rempart de confidentialité est un frein de performance, donc
des chiffres publiés sans cet axe ne vaudraient que pour un déploiement **sans** masquage.
Toutes les cellules sont tirées avec le **même rôle** (`viewer`) dans les deux états : une règle
de masque à `role:''` ne contraint pas un admin (`field_filter.rs:110-115`), le comparer en
admin ne mesurerait rien.

## Résultats — `fts0-masque-vide`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`ea1d072`, 200 003 événements, base 197 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**2 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 51 | 94 | 94 | 248 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 51 | 101 | 101 | 248 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 51 | 402 | 402 | 269 | 0 | 1 | raw | dispersion x7.9 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 51 | 59 | 59 | 269 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 51 | 51 | 51 | 269 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 577 | 652 | 351 | 270 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 62 | 62 | 62 | 270 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 101 | 252 | 252 | 270 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 652 | 652 | 602 | 270 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 52 | 60 | 60 | 270 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 101 | 151 | 151 | 270 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 502 | 502 | 502 | 270 | 0 | 1 | raw |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 51 | 51 | 51 | 270 | 0 | 1 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 51 | 51 | 51 | 270 | 0 | 6 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 51 | 52 | 51 | 270 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 51 | 51 | 51 | 270 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 51 | 101 | 101 | 270 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 870 | 902 | 902 | 270 | 0 | 50 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 51 | 51 | 51 | 270 | 0 | 28 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 51 | 51 | 51 | 270 | 0 | 45 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 151 | 251 | 251 | 270 | 0 | 61 | rollup |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 51 | 51 | 51 | 270 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 101 | 101 | 101 | 270 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 853 | 902 | 902 | 270 | 0 | 50 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 52 | 52 | 52 | 270 | 0 | 200 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 52 | 52 | 52 | 270 | 0 | 200 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 52 | 52 | 52 | 270 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 51 | 51 | 51 | 270 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 51 | 101 | 101 | 270 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 51 | 52 | 52 | 332 | 0 | 0 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 53 | 385 | 385 | 422 | 0 | 200 | raw | dispersion x7.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 53 | 53 | 53 | 422 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 54 | 54 | 54 | 422 | 0 | 200 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 51 | 52 | 51 | 422 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 51 | 51 | 51 | 422 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 552 | 553 | 502 | 422 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 51 | 51 | 51 | 422 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 101 | 151 | 151 | 422 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 652 | 671 | 602 | 422 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 51 | 51 | 51 | 422 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 51 | 51 | 51 | 422 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | 51 | 51 | 51 | 422 | 0 | 1 | raw |  |

## Résultats — `fts0-masque-non-vide`

*`PLUME_FTS_FIELDS`=0, masquage=non-vide (src_ip=mask, fields.user=partial), froid=off, version=`ea1d072`, 200 003 événements, base 197 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**Ce que `p95` vaut ici** : 3 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 51 | 61 | 61 | 423 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 51 | 51 | 51 | 423 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 352 | 352 | 352 | 423 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 51 | 51 | 51 | 423 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 51 | 51 | 51 | 423 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 302 | 302 | 302 | 423 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 51 | 51 | 51 | 423 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 52 | 102 | 102 | 423 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 502 | 502 | 502 | 423 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 52 | 52 | 52 | 423 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 51 | 51 | 51 | 423 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 502 | 502 | 451 | 423 | 0 | 1 | raw |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 52 | 53 | 52 | 423 | 0 | 1 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 51 | 51 | 51 | 423 | 0 | 6 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 52 | 52 | 52 | 423 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 52 | 54 | 54 | 423 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 52 | 103 | 103 | 423 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 702 | 702 | 702 | 423 | 0 | 50 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 51 | 51 | 51 | 423 | 0 | 28 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 51 | 51 | 51 | 423 | 0 | 45 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 1053 | 1053 | 1053 | 423 | 0 | 61 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 51 | 52 | 51 | 423 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 102 | 151 | 102 | 423 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 1203 | 1656 | 902 | 452 | 0 | 50 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 52 | 52 | 51 | 452 | 0 | 200 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 101 | 102 | 102 | 452 | 0 | 200 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 52 | 52 | 52 | 452 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 51 | 51 | 51 | 452 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 51 | 51 | 51 | 452 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 51 | 51 | 51 | 452 | 0 | 0 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 52 | 53 | 53 | 452 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 53 | 53 | 53 | 452 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 52 | 53 | 52 | 452 | 0 | 200 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 51 | 51 | 51 | 452 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 51 | 51 | 51 | 452 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 201 | 452 | 452 | 452 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 51 | 51 | 51 | 452 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 51 | 51 | 51 | 452 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 301 | 302 | 302 | 452 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | — | — | 0.7 | 452 | 0 | — | scan | ERREUR: {"error":"filtrage interdit sur le champ masqué « user » (field-filter / 0/3 tirs OK |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | — | — | 0.5 | 452 | 0 | — | scan | ERREUR: {"error":"filtrage interdit sur le champ masqué « user » (field-filter / 0/3 tirs OK |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | — | — | 0.5 | 452 | 0 | — | scan | ERREUR: {"error":"filtrage interdit sur le champ masqué « user » (field-filter / 0/3 tirs OK |

## Résultats — `fts0-masque-vide@1.4M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`bin:0642474ceedfaf15 construit:2026-07-30T11:08:02Z (HEAD au rendu: 3f9664b — indicatif, l'arbre bouge)`, 1 440 003 événements, base 1263 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**10 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 5 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 51 | 51 | 51 | 339 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 51 | 302 | 302 | 401 | 0 | 1 | raw | dispersion x5.9 (loadavg 12) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 2856 | 7863 | 2562 | 497 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 52 | 920 | 920 | 497 | 0 | 1 | raw | dispersion x17.7 (loadavg 12) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 201 | 302 | 302 | 522 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 5109 | 7843 | 5109 | 525 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 102 | 491 | 491 | 525 | 0 | 1 | raw | dispersion x4.8 (loadavg 11) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 1954 | 10.6 s | 2657 | 624 | 0 | 1 | raw | dispersion x5.4 (loadavg 11) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 5860 | 6061 | 6061 | 692 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 101 | 2385 | 2385 | 712 | 0 | 1 | raw | dispersion x23.5 (loadavg 11) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 1203 | 5525 | 1203 | 762 | 0 | 1 | raw | dispersion x4.6 (loadavg 11) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 3863 | 4012 | 3863 | 762 | 0 | 1 | raw |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 51 | 101 | 101 | 762 | 0 | 3 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 51 | 52 | 52 | 762 | 0 | 38 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 51 | 52 | 51 | 762 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 51 | 51 | 51 | 762 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 752 | 803 | 803 | 762 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 15.7 s | 17.5 s | 12.3 s | 762 | 0 | 50 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 101 | 151 | 151 | 712 | 0 | 37 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 102 | 201 | 201 | 553 | 0 | 48 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 152 | 302 | 302 | 553 | 0 | 63 | rollup |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 51 | 51 | 51 | 553 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 953 | 1253 | 1201 | 233 | 0 | 50 | raw | **pris sous swap — à rejouer** |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 12.6 s | 15.2 s | 11.1 s | 717 | 0 | 50 | raw | **pris sous swap — à rejouer** |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 66 | 253 | 253 | 793 | 0 | 200 | raw | dispersion x3.8 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 62 | 552 | 552 | 792 | 0 | 200 | raw | dispersion x8.8 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 52 | 53 | 52 | 792 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 52 | 52 | 51 | 792 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 1657 | 6415 | 2205 | 983 | 0 | 0 | raw | dispersion x3.9 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 1055 | 1206 | 1206 | 792 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 53 | 56 | 55 | 792 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 53 | 55 | 55 | 792 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 54 | 56 | 54 | 792 | 0 | 200 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 52 | 151 | 151 | 792 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 2402 | 3215 | 2402 | 717 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 6110 | 7166 | 7166 | 717 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 52 | 341 | 341 | 805 | 0 | 1 | raw | dispersion x6.6 (loadavg 11) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 2655 | 6603 | 6603 | 717 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 9616 | 10.3 s | 9616 | 745 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 52 | 102 | 102 | 1072 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 52 | 52 | 51 | 1072 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | 54 | 54 | 54 | 1072 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 51 | 101 | 101 | 335 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 51 | 51 | 51 | 335 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 51 | 51 | 51 | 335 | 0 | 1 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 51 | 52 | 51 | 762 | 0 | 3 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 902 | 911 | 752 | 762 | 0 | 38 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 3406 | 6611 | 3056 | 762 | 0 | 100 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 51 | 51 | 51 | 762 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 755 | 853 | 755 | 762 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | 2705 | 6599 | 2705 | 762 | 0 | 1 | raw |  |

## Résultats — `fts0-masque-non-vide@1.4M`

*`PLUME_FTS_FIELDS`=0, masquage=non-vide (src_ip=mask, fields.user=partial), froid=off, version=`bin:0642474ceedfaf15 construit:2026-07-30T11:08:02Z (HEAD au rendu: 3f9664b — indicatif, l'arbre bouge)`, 1 440 003 événements, base 1263 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**8 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 5 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 52 | 153 | 153 | 1073 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 552 | 603 | 603 | 1025 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 4666 | 5410 | 5410 | 1025 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 53 | 5160 | 5160 | 1025 | 0 | 1 | raw | dispersion x97.7 (loadavg 9) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 202 | 202 | 202 | 1025 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 9164 | 9916 | 9164 | 1065 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 103 | 2197 | 2197 | 956 | 0 | 1 | raw | dispersion x21.4 (loadavg 8) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 101 | 1052 | 1052 | 956 | 0 | 1 | raw | dispersion x10.4 (loadavg 8) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 3807 | 3906 | 3906 | 956 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 51 | 52 | 51 | 947 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 853 | 903 | 852 | 947 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 4508 | 6960 | 4508 | 974 | 0 | 1 | raw |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 51 | 60 | 60 | 974 | 0 | 3 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 51 | 52 | 52 | 942 | 0 | 38 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 52 | 52 | 51 | 942 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 52 | 59 | 52 | 1032 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 953 | 1003 | 1003 | 933 | 0 | 50 | raw | **pris sous swap — à rejouer** |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 7924 | 9572 | 7516 | 947 | 0 | 50 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 53 | 202 | 202 | 811 | 0 | 37 | raw | dispersion x3.8 (loadavg 10) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 2459 | 3008 | 3008 | 811 | 0 | 54 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 36.3 s | 37.5 s | 36.3 s | 1012 | 0 | 70 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 51 | 145 | 145 | 967 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 1154 | 1304 | 1304 | 965 | 0 | 50 | raw | **pris sous swap — à rejouer** |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 11.6 s | 15.1 s | 15.1 s | 1057 | 0 | 50 | raw | **pris sous swap — à rejouer** |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 53 | 103 | 103 | 1057 | 0 | 200 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 53 | 253 | 253 | 1057 | 0 | 200 | raw | dispersion x4.8 (loadavg 10) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 53 | 53 | 53 | 1057 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 51 | 52 | 51 | 1057 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 204 | 704 | 653 | 1057 | 0 | 0 | raw | **pris sous swap — à rejouer** / dispersion x3.4 (loadavg 10) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 54 | 555 | 555 | 1057 | 0 | 200 | raw | dispersion x10.2 (loadavg 10) — p95 dominé par la contention, pas par plume |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 55 | 56 | 55 | 1057 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 55 | 59 | 54 | 1057 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 56 | 60 | 60 | 1057 | 0 | 200 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 53 | 103 | 103 | 1057 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 354 | 1155 | 1155 | 1057 | 0 | 1 | raw | **pris sous swap — à rejouer** / dispersion x3.3 (loadavg 10) — p95 dominé par la contention, pas par plume |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 5963 | 13.3 s | 5963 | 1057 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 52 | 102 | 102 | 1007 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 1857 | 4215 | 1404 | 1007 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 7770 | 11.6 s | 11.6 s | 1004 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | — | — | 2.1 | 995 | 0 | — | scan | ERREUR: {"error":"filtrage interdit sur le champ masqué « user » (field-filter / 0/5 tirs OK |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | — | — | 0.9 | 995 | 0 | — | scan | ERREUR: {"error":"filtrage interdit sur le champ masqué « user » (field-filter / 0/5 tirs OK |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | — | — | 1.4 | 995 | 0 | — | scan | ERREUR: {"error":"filtrage interdit sur le champ masqué « user » (field-filter / 0/5 tirs OK |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 52 | 80 | 80 | 1073 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 51 | 52 | 51 | 1073 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 52 | 53 | 2.0 | 1073 | 0 | 1 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 101 | 109 | 101 | 942 | 0 | 3 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 903 | 1253 | 853 | 963 | 0 | 38 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 3557 | 6407 | 3557 | 1041 | 0 | 100 | raw | **pris sous swap — à rejouer** |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 102 | 104 | 104 | 1041 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 967 | 2626 | 1905 | 1041 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | 6514 | 7124 | 7124 | 1097 | 0 | 1 | raw | **pris sous swap — à rejouer** |

## Résultats — `fts1-masque-vide@1.4M`

*`PLUME_FTS_FIELDS`=1, masquage=vide, froid=off, version=`bin:0642474ceedfaf15 construit:2026-07-30T11:08:02Z (HEAD au rendu: 3f9664b — indicatif, l'arbre bouge)`, 1 440 003 événements, base 1401 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**3 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 5 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

> Cette configuration ne mesure que les classes `C0-,C2,C5`. Les classes absentes
> du tableau ci-dessous sont **non mesurées** dans cette configuration — pas
> implicitement inchangées.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 51 | 101 | 101 | 321 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 953 | 1104 | 853 | 435 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 6269 | 6937 | 5282 | 450 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 51 | 3145 | 3145 | 451 | 0 | 1 | raw | dispersion x61.3 (loadavg 9) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 1403 | 2305 | 2305 | 451 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 6366 | 7666 | 6366 | 628 | 0 | 1 | raw |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 51 | 53 | 51 | 628 | 0 | 3 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 51 | 53 | 52 | 628 | 0 | 38 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 53 | 103 | 52 | 628 | 0 | 100 | scan |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 51 | 51 | 51 | 690 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 952 | 953 | 803 | 690 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 8168 | 9183 | 6969 | 691 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 102 | 153 | 102 | 691 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 3659 | 8426 | 3608 | 691 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 6864 | 8515 | 8515 | 680 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 52 | 103 | 103 | 680 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 51 | 5278 | 5278 | 680 | 0 | 1 | raw | dispersion x103.1 (loadavg 11) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | 51 | 52 | 51 | 680 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 51 | 152 | 152 | 321 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 51 | 53 | 52 | 321 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 51 | 52 | 51 | 321 | 0 | 1 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 101 | 101 | 101 | 628 | 0 | 3 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 1103 | 1304 | 1053 | 669 | 0 | 38 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 3907 | 5523 | 3907 | 689 | 0 | 100 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 51 | 946 | 946 | 689 | 0 | 1 | raw | dispersion x18.5 (loadavg 9) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 952 | 1154 | 1154 | 690 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | 3207 | 3929 | 3929 | 690 | 0 | 1 | raw |  |

## Résultats — `avant-leviers@1.4M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`bin:b2d10fa90506682c`, 1 440 007 événements, base 1434 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**8 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 51 | 101 | 101 | 126 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 51 | 652 | 652 | 174 | 0 | 1 | raw | dispersion x12.8 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 2154 | 3806 | 3806 | 174 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 51 | 51 | 51 | 174 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 51 | 151 | 151 | 174 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 2004 | 19.3 s | 2004 | 367 | 0 | 1 | raw | dispersion x9.7 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 51 | 165 | 165 | 367 | 0 | 1 | raw | dispersion x3.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 1002 | 1653 | 1052 | 367 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 3406 | 3756 | 3756 | 368 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 51 | 51 | 51 | 368 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 802 | 954 | 802 | 368 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 3506 | 3806 | 3806 | 386 | 0 | 1 | raw |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 51 | 51 | 51 | 386 | 0 | 3 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 51 | 51 | 51 | 386 | 0 | 38 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 51 | 51 | 51 | 386 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 51 | 51 | 51 | 440 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 702 | 702 | 702 | 440 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 14.7 s | 15.2 s | 15.2 s | 588 | 0 | 50 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 101 | 152 | 152 | 588 | 0 | 37 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 51 | 101 | 101 | 588 | 0 | 48 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 201 | 351 | 351 | 588 | 0 | 63 | rollup |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 51 | 51 | 51 | 588 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 752 | 1803 | 1803 | 508 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 9214 | 9262 | 9214 | 747 | 0 | 50 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 51 | 52 | 51 | 747 | 0 | 200 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 51 | 152 | 152 | 747 | 0 | 200 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 51 | 52 | 52 | 747 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 51 | 51 | 51 | 747 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 752 | 1353 | 552 | 747 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 552 | 5234 | 752 | 747 | 0 | 200 | raw | dispersion x9.5 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 52 | 53 | 53 | 747 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 52 | 52 | 52 | 747 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 53 | 53 | 53 | 747 | 0 | 200 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 51 | 51 | 51 | 747 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 101 | 552 | 552 | 747 | 0 | 1 | raw | dispersion x5.5 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 4808 | 6629 | 6629 | 747 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 51 | 2546 | 2546 | 747 | 0 | 1 | raw | dispersion x49.9 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 201 | 852 | 852 | 747 | 0 | 1 | raw | dispersion x4.2 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 6063 | 7860 | 6063 | 747 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 71 | 3619 | 3619 | 747 | 0 | 1 | raw | dispersion x50.9 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 51 | 52 | 51 | 747 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | 51 | 51 | 51 | 747 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 51 | 95 | 95 | 122 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 51 | 51 | 51 | 122 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 51 | 51 | 51 | 122 | 0 | 1 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 51 | 51 | 51 | 386 | 0 | 3 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 702 | 802 | 752 | 386 | 0 | 38 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 2756 | 5496 | 2755 | 440 | 0 | 100 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 51 | 51 | 51 | 440 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 702 | 802 | 552 | 440 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | 3357 | 4789 | 3357 | 440 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 1h | 51 | 52 | 52 | 747 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 24h | 52 | 152 | 152 | 747 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | all | 52 | 62 | 52 | 747 | 0 | 200 | raw |  |

## Résultats — `apres-leviers@1.4M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`bin:bc481b69f4aca22c`, 1 440 007 événements, base 1434 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**23 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 1.4 | 30 | 30 | 152 | 0 | 1 | raw | dispersion x21.9 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 18 | 12.3 s | 661 | 273 | 0 | 1 | raw | dispersion x668.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 2036 | 2204 | 1961 | 341 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 1.0 | 7.4 | 7.4 | 341 | 0 | 1 | raw | dispersion x7.6 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 14 | 114 | 114 | 341 | 0 | 1 | raw | dispersion x8.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 4721 | 7072 | 2903 | 399 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 2.4 | 1503 | 1503 | 397 | 0 | 1 | raw | dispersion x626.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 59 | 1442 | 1442 | 397 | 0 | 1 | raw | dispersion x24.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 2568 | 4302 | 4302 | 397 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 3.2 | 27 | 27 | 397 | 0 | 1 | raw | dispersion x8.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 624 | 678 | 639 | 397 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 3156 | 5044 | 3156 | 397 | 0 | 1 | raw |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 1.7 | 19 | 19 | 397 | 0 | 3 | scan | dispersion x11.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 2.0 | 2.1 | 1.9 | 397 | 0 | 38 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 2.8 | 2.9 | 2.9 | 397 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 3.5 | 39 | 39 | 452 | 0 | 50 | raw | dispersion x11.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 624 | 649 | 649 | 397 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 13.9 s | 16.6 s | 12.8 s | 420 | 0 | 50 | raw | **pris sous swap — à rejouer** |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 2.8 | 40 | 40 | 420 | 0 | 37 | raw | dispersion x14.5 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 7.8 | 35 | 35 | 420 | 0 | 48 | rollup | dispersion x4.6 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 130 | 235 | 235 | 420 | 0 | 63 | rollup |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 5.7 | 6.6 | 6.2 | 420 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 721 | 778 | 778 | 420 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 8127 | 8418 | 8127 | 687 | 0 | 50 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 3.7 | 49 | 49 | 687 | 0 | 200 | raw | dispersion x13.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 12 | 190 | 190 | 687 | 0 | 200 | raw | dispersion x16.0 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 1.7 | 3.4 | 3.4 | 687 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 4.9 | 23 | 23 | 687 | 0 | 0 | raw | dispersion x4.6 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 447 | 579 | 579 | 687 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 31 | 534 | 534 | 687 | 0 | 200 | raw | dispersion x17.0 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 2.3 | 7.0 | 7.0 | 687 | 0 | 200 | raw | dispersion x3.0 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 2.6 | 3.7 | 2.3 | 687 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 3.5 | 4.0 | 2.9 | 687 | 0 | 200 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 3.6 | 22 | 22 | 687 | 0 | 1 | raw | dispersion x6.1 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 92 | 552 | 552 | 687 | 0 | 1 | raw | dispersion x6.0 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 5274 | 5282 | 5282 | 687 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 7.8 | 115 | 97 | 687 | 0 | 1 | raw | dispersion x14.7 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 834 | 1684 | 1684 | 687 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 5873 | 7878 | 5873 | 687 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 2.4 | 55 | 55 | 687 | 0 | 1 | raw | dispersion x23.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 2.3 | 2.5 | 2.5 | 687 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | 0.8 | 1.2 | 0.9 | 687 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 0.6 | 51 | 51 | 147 | 0 | 1 | raw | dispersion x86.6 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 0.7 | 0.8 | 0.6 | 147 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 0.7 | 0.8 | 0.8 | 148 | 0 | 1 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 5.1 | 29 | 29 | 397 | 0 | 3 | raw | dispersion x5.7 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 954 | 2565 | 630 | 527 | 0 | 38 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 2600 | 3980 | 3980 | 458 | 0 | 100 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 3.5 | 724 | 724 | 402 | 0 | 1 | raw | dispersion x204.6 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 597 | 896 | 896 | 414 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | 2696 | 8066 | 2550 | 452 | 0 | 1 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 1h | 1.6 | 2.1 | 2.1 | 687 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 24h | 1.4 | 2.0 | 1.4 | 687 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | all | 1.6 | 1.9 | 1.7 | 687 | 0 | 200 | raw |  |

## Résultats — `chaud-seul@1.4M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`bin:bc481b69f4aca22c construit:2026-07-30T13:25:38Z (HEAD au rendu: 09fc07f — indicatif, l'arbre bouge)`, 1 440 007 événements, base 1434 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**37 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 1.2 | 17 | 17 | 163 | 0 | 1 | raw | dispersion x13.6 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 16 | 302 | 302 | 226 | 0 | 1 | raw | dispersion x18.8 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 7d | 1316 | 1430 | 1354 | 292 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | au-dela-7d | 6809 | 9001 | 5155 | 463 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 4579 | 5128 | 3325 | 463 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 1.0 | 5.5 | 5.5 | 463 | 0 | 1 | raw | dispersion x5.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 11 | 145 | 145 | 463 | 0 | 1 | raw | dispersion x13.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 7d | 839 | 5737 | 1032 | 463 | 0 | 1 | raw | dispersion x6.8 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | au-dela-7d | 2422 | 4322 | 4322 | 463 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 3209 | 8768 | 3159 | 463 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 3.3 | 54 | 54 | 463 | 0 | 1 | raw | dispersion x16.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 565 | 838 | 838 | 463 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 7d | 7927 | 8834 | 7927 | 463 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | au-dela-7d | 3372 | 3922 | 3372 | 463 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 2813 | 9109 | 2815 | 463 | 0 | 1 | raw | dispersion x3.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 3.0 | 26 | 26 | 463 | 0 | 1 | raw | dispersion x8.6 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 635 | 4636 | 633 | 463 | 0 | 1 | raw | dispersion x7.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 7d | 5661 | 8286 | 4412 | 463 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | au-dela-7d | 3084 | 8541 | 8541 | 463 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 3364 | 4791 | 4791 | 463 | 0 | 1 | raw |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 3.1 | 34 | 34 | 463 | 0 | 3 | scan | dispersion x11.1 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 3.1 | 3.2 | 3.2 | 463 | 0 | 38 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 7d | 3.2 | 4.2 | 3.0 | 463 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | au-dela-7d | 4.4 | 4.5 | 4.4 | 463 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 4.3 | 4.6 | 4.5 | 463 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 8.4 | 48 | 48 | 475 | 0 | 50 | raw | dispersion x5.7 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 659 | 5922 | 987 | 475 | 0 | 50 | raw | dispersion x9.0 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 7d | 7265 | 7289 | 7289 | 475 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | au-dela-7d | 12.3 s | 12.9 s | 12.3 s | 475 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 13.0 s | 13.3 s | 13.3 s | 475 | 0 | 50 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 5.0 | 621 | 621 | 475 | 0 | 37 | raw | dispersion x124.9 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 16 | 105 | 105 | 475 | 0 | 48 | rollup | dispersion x6.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 7d | 97 | 205 | 205 | 475 | 0 | 53 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | au-dela-7d | 150 | 334 | 334 | 475 | 0 | 59 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 141 | 158 | 150 | 475 | 0 | 63 | rollup |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 5.8 | 28 | 28 | 475 | 0 | 50 | raw | dispersion x4.9 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 666 | 1508 | 1508 | 475 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 7d | 7676 | 11.0 s | 7676 | 475 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | au-dela-7d | 21.3 s | 22.0 s | 22.0 s | 625 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 7969 | 12.7 s | 12.7 s | 705 | 0 | 50 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 4.7 | 1640 | 1640 | 705 | 0 | 200 | raw | dispersion x345.9 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 16 | 437 | 407 | 705 | 0 | 200 | raw | dispersion x26.9 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 7d | 19 | 356 | 356 | 705 | 0 | 200 | raw | dispersion x18.7 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | au-dela-7d | 35 | 116 | 36 | 705 | 0 | 200 | raw | dispersion x3.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 2.9 | 4.5 | 4.5 | 705 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 5.8 | 87 | 87 | 705 | 0 | 0 | raw | dispersion x14.9 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 448 | 1430 | 1430 | 705 | 0 | 0 | raw | dispersion x3.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 7d | 2909 | 4390 | 4390 | 705 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | au-dela-7d | 434 | 665 | 665 | 705 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 366 | 1311 | 312 | 769 | 0 | 200 | raw | dispersion x3.6 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 2.5 | 6.6 | 6.6 | 769 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 2.3 | 2.8 | 2.8 | 769 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 7d | 2.3 | 2.6 | 2.6 | 769 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | au-dela-7d | 2.4 | 6.6 | 6.6 | 769 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 2.7 | 3.5 | 3.5 | 769 | 0 | 200 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 3.6 | 20 | 20 | 769 | 0 | 1 | raw | dispersion x5.6 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 635 | 1477 | 594 | 769 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 7d | 8636 | 9431 | 9431 | 712 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | au-dela-7d | 3471 | 4004 | 4004 | 712 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 3672 | 8916 | 3464 | 869 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 4.1 | 55 | 55 | 869 | 0 | 1 | raw | dispersion x13.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 666 | 737 | 737 | 821 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 7d | 8698 | 9576 | 8698 | 821 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | au-dela-7d | 6252 | 10.9 s | 6252 | 699 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 5727 | 6129 | 4511 | 699 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 2.7 | 104 | 104 | 699 | 0 | 1 | raw | dispersion x39.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 2.3 | 3.0 | 2.2 | 699 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 7d | 3.1 | 4.2 | 3.1 | 699 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | au-dela-7d | 3.0 | 4.7 | 3.0 | 699 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | 0.8 | 0.9 | 0.9 | 699 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 0.8 | 12.4 s | 12.4 s | 159 | 0 | 1 | raw | dispersion x14956.1 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 0.7 | 0.9 | 0.6 | 159 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 7d | 0.6 | 0.7 | 0.6 | 159 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | au-dela-7d | 0.6 | 0.7 | 0.7 | 159 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 0.6 | 0.7 | 0.7 | 159 | 0 | 1 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 7.4 | 1795 | 1795 | 463 | 0 | 3 | raw | dispersion x242.6 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 647 | 2953 | 1607 | 463 | 0 | 38 | raw | dispersion x4.6 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 7d | 4323 | 6448 | 6448 | 463 | 0 | 100 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | au-dela-7d | 3258 | 5725 | 5725 | 463 | 0 | 100 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 3288 | 3596 | 3288 | 516 | 0 | 100 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 3.6 | 23 | 23 | 435 | 0 | 1 | raw | dispersion x6.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 665 | 4346 | 552 | 462 | 0 | 1 | raw | dispersion x6.5 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 7d | 4286 | 4395 | 4395 | 462 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | au-dela-7d | 2750 | 6896 | 2550 | 460 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | 2924 | 9404 | 2630 | 486 | 0 | 1 | raw | dispersion x3.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 1h | 1.6 | 1.7 | 1.6 | 769 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 24h | 1.6 | 1.9 | 1.9 | 769 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 7d | 1.5 | 1.5 | 1.5 | 769 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | au-dela-7d | 2.9 | 3.6 | 1.6 | 769 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | all | 1.6 | 2.4 | 2.2 | 769 | 0 | 200 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 1h | 3.1 | 2820 | 2820 | 699 | 0 | 1 | raw | dispersion x912.7 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 24h | 604 | 1647 | 1537 | 699 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 7d | 275 | 638 | 638 | 699 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | au-dela-7d | 266 | 286 | 271 | 699 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | all | 1.6 | 2.7 | 2.7 | 699 | 0 | 1 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 1h | 2.8 | 24 | 24 | 699 | 0 | 50 | raw | dispersion x8.6 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 24h | 617 | 1796 | 638 | 699 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 7d | 20.7 s | 21.0 s | 19.2 s | 699 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | au-dela-7d | 20.7 s | 23.0 s | 23.0 s | 699 | 0 | 50 | raw | **pris sous swap — à rejouer** |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | all | 99 | 265 | 265 | 699 | 0 | 50 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 1h | 2.0 | 28 | 28 | 699 | 0 | 22 | raw | dispersion x13.9 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 24h | 12 | 148 | 148 | 699 | 0 | 200 | raw | dispersion x12.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 7d | 258 | 4978 | 258 | 699 | 0 | 200 | raw | dispersion x19.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | au-dela-7d | 22 | 33 | 22 | 699 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | all | 22 | 909 | 27 | 699 | 0 | 200 | raw | dispersion x41.9 (loadavg 3) — p95 dominé par la contention, pas par plume |

## Résultats — `froid-actif@1.4M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=actif (hot=7j), version=`bin:bc481b69f4aca22c construit:2026-07-30T13:25:38Z (HEAD au rendu: 09fc07f — indicatif, l'arbre bouge)`, 335 255 événements, base 1434 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**27 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 1.2 | 13 | 13 | 356 | 0 | 1 | raw | dispersion x10.2 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 18 | 224 | 224 | 356 | 0 | 1 | raw | dispersion x12.7 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 7d | 2024 | 3094 | 1676 | 405 | 0 | 1 | scan | tronqué |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | au-dela-7d | 1056 | 1435 | 1034 | 352 | 0 | 1 | scan | tronqué |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 2252 | 3524 | 1997 | 385 | 0 | 1 | scan | tronqué |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 1.0 | 10.0 | 10.0 | 330 | 0 | 1 | raw | dispersion x9.7 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 9.2 | 177 | 177 | 330 | 0 | 1 | raw | dispersion x19.1 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 7d | 1207 | 1380 | 1380 | 330 | 0 | 1 | scan | tronqué |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | au-dela-7d | 1069 | 1153 | 1069 | 330 | 0 | 1 | scan | tronqué |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 1725 | 2729 | 1894 | 341 | 0 | 1 | scan | tronqué |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 2.1 | 43 | 43 | 341 | 0 | 1 | raw | dispersion x20.5 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 494 | 860 | 860 | 341 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 7d | 3957 | 4312 | 4312 | 341 | 0 | 1 | scan | tronqué |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | au-dela-7d | 1084 | 1140 | 1071 | 341 | 0 | 1 | scan | tronqué |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 4898 | 6776 | 6776 | 341 | 0 | 1 | scan | tronqué |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 2.9 | 28 | 28 | 341 | 0 | 1 | raw | dispersion x9.7 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 540 | 552 | 550 | 341 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 7d | 3950 | 4185 | 3281 | 345 | 0 | 1 | scan | tronqué |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | au-dela-7d | 1084 | 1120 | 1056 | 393 | 0 | 1 | scan | tronqué |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 4532 | 4549 | 3832 | 372 | 0 | 1 | scan | tronqué |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 1.2 | 19 | 19 | 327 | 0 | 3 | scan | dispersion x15.8 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 1.5 | 1.6 | 1.4 | 327 | 0 | 38 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 7d | 2.2 | 2.3 | 2.3 | 327 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | au-dela-7d | 1.1 | 1.2 | 1.1 | 327 | 0 | 0 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 2.1 | 2.3 | 2.2 | 327 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 3.4 | 27 | 27 | 357 | 0 | 50 | raw | dispersion x7.9 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 547 | 568 | 557 | 357 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 7d | 4325 | 6087 | 3627 | 357 | 0 | 50 | scan | tronqué |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | au-dela-7d | 1067 | 1209 | 1209 | 357 | 0 | 50 | scan | tronqué |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 5126 | 7157 | 4893 | 467 | 0 | 50 | scan | tronqué |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 4.0 | 37 | 37 | 467 | 0 | 37 | raw | dispersion x9.0 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 7.8 | 45 | 45 | 467 | 0 | 48 | rollup | dispersion x5.8 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 7d | 43 | 98 | 98 | 467 | 0 | 54 | rollup | approx |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | au-dela-7d | 808 | 1793 | 1793 | 467 | 0 | 68 | rollup | approx |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 948 | 1346 | 1014 | 467 | 0 | 70 | rollup |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 6.5 | 72 | 72 | 467 | 0 | 50 | raw | dispersion x11.1 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 161 | 1160 | 1160 | 467 | 0 | 50 | raw | dispersion x7.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 7d | 6011 | 7193 | 7193 | 473 | 0 | 50 | scan | tronqué |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | au-dela-7d | 1083 | 1528 | 1091 | 515 | 0 | 50 | scan | tronqué |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 5314 | 5333 | 5309 | 517 | 0 | 50 | scan | tronqué |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 2.8 | 26 | 26 | 472 | 0 | 200 | raw | dispersion x9.1 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 9.5 | 125 | 125 | 472 | 0 | 200 | raw | dispersion x13.1 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 7d | 666 | 734 | 734 | 472 | 0 | 200 | scan | tronqué |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | au-dela-7d | 1110 | 1449 | 1449 | 477 | 0 | 200 | scan | tronqué |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 1195 | 1514 | 1174 | 479 | 0 | 200 | scan | tronqué |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 5.2 | 26 | 26 | 479 | 0 | 0 | raw | dispersion x5.0 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 342 | 464 | 464 | 479 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 7d | 2807 | 2925 | 1483 | 479 | 0 | 200 | scan | tronqué |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | au-dela-7d | 1075 | 1394 | 1032 | 506 | 0 | 0 | scan | tronqué |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 3513 | 4726 | 4726 | 506 | 0 | 200 | scan | tronqué |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 2.3 | 8.0 | 8.0 | 506 | 0 | 200 | raw | dispersion x3.5 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 2.3 | 2.6 | 2.5 | 506 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 7d | 549 | 680 | 557 | 506 | 0 | 200 | scan | tronqué |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | au-dela-7d | 1114 | 1398 | 1161 | 506 | 0 | 200 | scan | tronqué |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 1096 | 1443 | 1443 | 506 | 0 | 200 | scan | tronqué |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 3.1 | 35 | 35 | 506 | 0 | 1 | raw | dispersion x11.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 492 | 1233 | 1233 | 506 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 7d | 4097 | 4485 | 4485 | 506 | 0 | 1 | scan | tronqué |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | au-dela-7d | 1406 | 1485 | 1406 | 506 | 0 | 1 | scan | tronqué |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 5746 | 5753 | 4969 | 506 | 0 | 1 | scan | tronqué |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 3.9 | 29 | 29 | 506 | 0 | 1 | raw | dispersion x7.4 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 591 | 1147 | 608 | 506 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 7d | 4733 | 5797 | 4733 | 506 | 0 | 1 | scan | tronqué |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | au-dela-7d | 1090 | 1430 | 1021 | 506 | 0 | 1 | scan | tronqué |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 4934 | 5381 | 4763 | 506 | 0 | 1 | scan | tronqué |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 1.1 | 21 | 21 | 506 | 0 | 1 | raw | dispersion x18.7 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 1.2 | 1.3 | 1.3 | 506 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 7d | 540 | 614 | 530 | 506 | 0 | 1 | scan | tronqué |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | au-dela-7d | 1088 | 1113 | 1050 | 506 | 0 | 1 | scan | tronqué |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | 1071 | 1170 | 1060 | 506 | 0 | 1 | scan | tronqué |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 0.8 | 45 | 45 | 280 | 0 | 1 | raw | dispersion x52.9 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 0.7 | 0.8 | 0.8 | 280 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 7d | 516 | 546 | 508 | 280 | 0 | 1 | scan | tronqué |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | au-dela-7d | 1031 | 1093 | 1031 | 346 | 0 | 1 | scan | tronqué |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 1032 | 1156 | 1031 | 356 | 0 | 1 | scan | tronqué |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 4.2 | 26 | 26 | 327 | 0 | 3 | raw | dispersion x6.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 536 | 592 | 557 | 327 | 0 | 38 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 7d | 6035 | 7059 | 2771 | 354 | 0 | 100 | scan | tronqué |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | au-dela-7d | 1091 | 1468 | 1468 | 357 | 0 | 4 | scan | tronqué |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 5695 | 7298 | 5695 | 357 | 0 | 100 | scan | tronqué |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 2.4 | 33 | 33 | 357 | 0 | 1 | raw | dispersion x14.1 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 504 | 525 | 525 | 357 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 7d | 5331 | 6060 | 4427 | 357 | 0 | 1 | scan | tronqué |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | au-dela-7d | 1045 | 1402 | 1045 | 357 | 0 | 1 | scan | tronqué |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | 4478 | 4705 | 4705 | 357 | 0 | 1 | scan | tronqué |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 1h | 1.7 | 6.9 | 6.9 | 506 | 0 | 200 | raw | dispersion x4.1 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 24h | 1.6 | 1.8 | 1.5 | 506 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 7d | 544 | 571 | 544 | 506 | 0 | 200 | scan | tronqué |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | au-dela-7d | 1065 | 1376 | 1376 | 506 | 0 | 200 | scan | tronqué |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | all | 1122 | 1450 | 1127 | 506 | 0 | 200 | scan | tronqué |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 1h | 1.7 | 25 | 25 | 506 | 0 | 1 | raw | dispersion x14.7 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 24h | 503 | 1237 | 503 | 506 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 7d | 597 | 937 | 639 | 506 | 0 | 1 | scan | tronqué |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | au-dela-7d | 1071 | 1188 | 1042 | 506 | 0 | 1 | scan | tronqué |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | all | 1138 | 1499 | 1139 | 506 | 0 | 1 | scan | tronqué |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 1h | 2.9 | 26 | 26 | 506 | 0 | 50 | raw | dispersion x8.8 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 24h | 392 | 507 | 507 | 506 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 7d | 4227 | 5909 | 3078 | 506 | 0 | 50 | scan | tronqué |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | au-dela-7d | 1078 | 1089 | 1051 | 506 | 0 | 50 | scan | tronqué |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | all | 4606 | 4610 | 3123 | 506 | 0 | 50 | scan | tronqué |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 1h | 1.8 | 25 | 25 | 506 | 0 | 22 | raw | dispersion x13.8 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 24h | 11 | 130 | 130 | 506 | 0 | 200 | raw | dispersion x11.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 7d | 589 | 665 | 580 | 506 | 0 | 200 | scan | tronqué |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | au-dela-7d | 1068 | 1116 | 1032 | 506 | 0 | 80 | scan | tronqué |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | all | 1116 | 1485 | 1485 | 506 | 0 | 200 | scan | tronqué |

## Résultats — `flotte-1h@0.6M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`bin:bc481b69f4aca22c construit:2026-07-30T13:25:38Z (HEAD au rendu: 09fc07f — indicatif, l'arbre bouge)`, 600 003 événements, base 560 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**11 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

> Cette configuration ne mesure que les classes `C0-,C1-scan-agg,C3-groupby-hi,C6`. Les classes absentes
> du tableau ci-dessous sont **non mesurées** dans cette configuration — pas
> implicitement inchangées.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 0.7 | 17 | 17 | 117 | 0 | 1 | raw | dispersion x23.6 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 6.2 | 261 | 261 | 149 | 0 | 1 | raw | dispersion x42.1 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 7d | 404 | 1239 | 1239 | 176 | 0 | 1 | raw | dispersion x3.1 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | au-dela-7d | 1216 | 2094 | 2094 | 176 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 821 | 1011 | 753 | 200 | 0 | 1 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 2.5 | 4067 | 4067 | 528 | 0 | 50 | raw | dispersion x1607.4 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 47 | 828 | 440 | 549 | 0 | 50 | raw | dispersion x17.7 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 7d | 1581 | 3471 | 1792 | 315 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | au-dela-7d | 3812 | 5198 | 3812 | 531 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 3559 | 4474 | 3217 | 531 | 0 | 50 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 0.7 | 47 | 47 | 116 | 0 | 1 | raw | dispersion x66.0 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 0.8 | 0.8 | 0.7 | 116 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 7d | 0.9 | 0.9 | 0.9 | 116 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | au-dela-7d | 0.8 | 0.8 | 0.8 | 116 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 0.6 | 0.8 | 0.8 | 116 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 1h | 1.3 | 7.7 | 7.7 | 321 | 0 | 1 | raw | dispersion x6.0 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 24h | 203 | 207 | 203 | 321 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 7d | 1041 | 1523 | 1461 | 532 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | au-dela-7d | 898 | 1014 | 899 | 527 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | all | 25 | 210 | 210 | 527 | 0 | 1 | raw | dispersion x8.2 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 1h | 1.5 | 10 | 10 | 527 | 0 | 1 | raw | dispersion x6.8 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 24h | 211 | 232 | 219 | 527 | 0 | 1 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 7d | 962 | 992 | 962 | 531 | 0 | 1 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | au-dela-7d | 977 | 1795 | 1795 | 531 | 0 | 1 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | all | 40 | 93 | 93 | 320 | 0 | 2 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 1h | 1.6 | 5.3 | 5.3 | 320 | 0 | 200 | raw | dispersion x3.2 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 24h | 1.7 | 1.7 | 1.5 | 320 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 7d | 2.2 | 2.7 | 2.0 | 320 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | au-dela-7d | 1.7 | 5.1 | 5.1 | 320 | 0 | 200 | raw | dispersion x3.1 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | all | 1.6 | 1.8 | 1.7 | 320 | 0 | 200 | raw |  |

## Résultats — `flotte-50h@0.6M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`bin:bc481b69f4aca22c construit:2026-07-30T13:25:38Z (HEAD au rendu: 09fc07f — indicatif, l'arbre bouge)`, 600 003 événements, base 336 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**8 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

> Cette configuration ne mesure que les classes `C0-,C1-scan-agg,C3-groupby-hi,C6`. Les classes absentes
> du tableau ci-dessous sont **non mesurées** dans cette configuration — pas
> implicitement inchangées.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 0.8 | 19 | 19 | 123 | 0 | 1 | raw | dispersion x22.8 (loadavg 1) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 7.0 | 322 | 322 | 140 | 0 | 1 | raw | dispersion x45.9 (loadavg 1) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 7d | 50 | 814 | 814 | 165 | 0 | 1 | raw | dispersion x16.4 (loadavg 1) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | au-dela-7d | 500 | 723 | 723 | 165 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 465 | 473 | 259 | 165 | 0 | 1 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 1.9 | 5.5 | 5.5 | 165 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 36 | 95 | 95 | 167 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 7d | 552 | 592 | 592 | 177 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | au-dela-7d | 986 | 1351 | 934 | 493 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 1017 | 2075 | 1434 | 604 | 0 | 50 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 0.6 | 45 | 45 | 123 | 0 | 1 | raw | dispersion x75.3 (loadavg 1) — p95 dominé par la contention, pas par plume |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 0.6 | 0.7 | 0.7 | 123 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 7d | 0.6 | 0.7 | 0.6 | 123 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | au-dela-7d | 0.6 | 0.7 | 0.7 | 123 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 0.6 | 0.7 | 0.7 | 123 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 1h | 1.2 | 1.9 | 1.9 | 390 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 24h | 17 | 21 | 21 | 390 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 7d | 8.1 | 11 | 11 | 390 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | au-dela-7d | 7.6 | 8.0 | 8.0 | 390 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | all | 1.1 | 1.3 | 1.3 | 390 | 0 | 1 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 1h | 1.5 | 1.6 | 1.6 | 390 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 24h | 26 | 26 | 26 | 390 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 7d | 355 | 3412 | 483 | 391 | 0 | 50 | raw | dispersion x9.6 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | au-dela-7d | 4447 | 4650 | 4447 | 607 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | all | 44 | 102 | 102 | 601 | 0 | 50 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 1h | 1.3 | 7.5 | 7.5 | 601 | 0 | 14 | raw | dispersion x5.9 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 24h | 8.5 | 80 | 80 | 601 | 0 | 200 | raw | dispersion x9.4 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 7d | 9.5 | 95 | 95 | 601 | 0 | 200 | raw | dispersion x10.0 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | au-dela-7d | 10 | 10 | 10 | 601 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | all | 10 | 13 | 9.8 | 601 | 0 | 200 | raw |  |

## Résultats — `flotte-200h@0.6M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`bin:bc481b69f4aca22c construit:2026-07-30T13:25:38Z (HEAD au rendu: 09fc07f — indicatif, l'arbre bouge)`, 600 003 événements, base 351 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**7 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

> Cette configuration ne mesure que les classes `C0-,C1-scan-agg,C3-groupby-hi,C6`. Les classes absentes
> du tableau ci-dessous sont **non mesurées** dans cette configuration — pas
> implicitement inchangées.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 0.9 | 20 | 20 | 124 | 0 | 1 | raw | dispersion x22.7 (loadavg 1) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 7.4 | 306 | 306 | 158 | 0 | 1 | raw | dispersion x41.2 (loadavg 1) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 7d | 50 | 831 | 831 | 183 | 0 | 1 | raw | dispersion x16.5 (loadavg 1) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | au-dela-7d | 456 | 644 | 644 | 183 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 454 | 472 | 232 | 183 | 0 | 1 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 2.0 | 4.2 | 4.2 | 183 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 36 | 76 | 76 | 183 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 7d | 524 | 570 | 570 | 184 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | au-dela-7d | 1023 | 1082 | 921 | 276 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 891 | 2302 | 2302 | 595 | 0 | 50 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 0.7 | 44 | 44 | 122 | 0 | 1 | raw | dispersion x62.5 (loadavg 1) — p95 dominé par la contention, pas par plume |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 0.8 | 0.8 | 0.7 | 122 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 7d | 0.7 | 0.7 | 0.7 | 122 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | au-dela-7d | 0.8 | 0.8 | 0.7 | 122 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 0.7 | 0.7 | 0.6 | 122 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 1h | 1.2 | 1.9 | 1.9 | 595 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 24h | 2.2 | 3.3 | 3.3 | 595 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 7d | 2.7 | 3.0 | 2.7 | 595 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | au-dela-7d | 2.4 | 3.5 | 3.5 | 595 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | all | 0.9 | 1.2 | 0.9 | 595 | 0 | 1 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 1h | 1.5 | 1.9 | 1.9 | 595 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 24h | 27 | 30 | 30 | 595 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 7d | 599 | 4256 | 599 | 595 | 0 | 50 | raw | dispersion x7.1 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | au-dela-7d | 4192 | 4282 | 3021 | 548 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | all | 44 | 103 | 103 | 548 | 0 | 50 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 1h | 1.2 | 7.0 | 7.0 | 548 | 0 | 3 | raw | dispersion x5.9 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 24h | 2.8 | 28 | 28 | 548 | 0 | 86 | raw | dispersion x10.1 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 7d | 3.4 | 3.5 | 3.5 | 548 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | au-dela-7d | 4.5 | 5.2 | 4.5 | 548 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | all | 3.8 | 3.9 | 3.9 | 548 | 0 | 200 | raw |  |

## Résultats — `froid-actif-v2@1.4M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=actif (hot=7j), version=`bin:4bfcb9f76b4353a2 construit:2026-07-31T12:23:28Z (correctif troncature froide)`, 1 440 007 événements, base 1434 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**28 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 1.3 | 31 | 31 | 429 | 0 | 1 | raw | dispersion x22.9 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 14 | 540 | 540 | 429 | 0 | 1 | raw | dispersion x37.3 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 7d | 1851 | 2573 | 2573 | 429 | 0 | 1 | cold-vectorized-merge |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | au-dela-7d | 2884 | 3002 | 3002 | 429 | 0 | 1 | cold-vectorized |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 4118 | 4195 | 4110 | 429 | 0 | 1 | cold-vectorized-merge | **pris sous swap — à rejouer** |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 1.0 | 16 | 16 | 429 | 0 | 1 | raw | dispersion x16.0 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 9.6 | 167 | 167 | 429 | 0 | 1 | raw | dispersion x17.4 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 7d | — | — | 1390 | 429 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / **pris sous swap — à rejouer** / 0/7 tirs OK |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | au-dela-7d | — | — | 1096 | 429 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/7 tirs OK |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | — | — | 1759 | 429 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / **pris sous swap — à rejouer** / 0/7 tirs OK |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 2.4 | 35 | 35 | 429 | 0 | 1 | raw | dispersion x14.3 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 526 | 648 | 648 | 429 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 7d | — | — | 3506 | 429 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/3 tirs OK |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | au-dela-7d | — | — | 1083 | 429 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/7 tirs OK |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | — | — | 4603 | 429 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/3 tirs OK |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 2.7 | 35 | 35 | 429 | 0 | 1 | raw | dispersion x12.9 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 557 | 571 | 571 | 429 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 7d | 4201 | 4263 | 4263 | 429 | 0 | 1 | cold-vectorized-merge |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | au-dela-7d | 2820 | 3115 | 2817 | 429 | 0 | 1 | cold-vectorized |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 6284 | 6665 | 6284 | 429 | 0 | 1 | cold-vectorized-merge |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 1.8 | 25 | 25 | 429 | 0 | 3 | scan | dispersion x13.9 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 2.0 | 2.1 | 2.1 | 429 | 0 | 38 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 7d | 3.1 | 3.3 | 3.1 | 429 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | au-dela-7d | 1.4 | 1.6 | 1.6 | 429 | 0 | 0 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 2.2 | 2.6 | 2.6 | 429 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 4.5 | 28 | 28 | 468 | 0 | 50 | raw | dispersion x6.1 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 554 | 575 | 575 | 468 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 7d | — | — | 10.1 s | 468 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/3 tirs OK |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | au-dela-7d | 4145 | 4703 | 4145 | 471 | 0 | 50 | cold-vectorized |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | — | — | 14.9 s | 509 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/3 tirs OK |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 3.0 | 28 | 28 | 509 | 0 | 37 | raw | dispersion x9.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 8.4 | 58 | 58 | 509 | 0 | 48 | rollup | dispersion x7.0 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 7d | 46 | 163 | 163 | 509 | 0 | 54 | rollup | approx / dispersion x3.6 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | au-dela-7d | 858 | 3300 | 3300 | 509 | 0 | 68 | rollup | approx / dispersion x3.8 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 873 | 910 | 910 | 509 | 0 | 70 | rollup |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 6.0 | 29 | 29 | 509 | 0 | 50 | raw | dispersion x4.8 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 653 | 727 | 653 | 509 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 7d | — | — | 3954 | 509 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/3 tirs OK |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | au-dela-7d | — | — | 1183 | 509 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/7 tirs OK |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | — | — | 6766 | 509 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/3 tirs OK |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 3.5 | 27 | 27 | 509 | 0 | 200 | raw | dispersion x7.7 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 9.7 | 162 | 162 | 509 | 0 | 200 | raw | dispersion x16.7 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 7d | 680 | 720 | 674 | 509 | 0 | 200 | scan | tronqué |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | au-dela-7d | 1106 | 1303 | 1303 | 509 | 0 | 200 | scan | tronqué |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 1296 | 1398 | 1245 | 509 | 0 | 200 | scan | tronqué |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 3.8 | 26 | 26 | 509 | 0 | 0 | raw | dispersion x6.9 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 373 | 548 | 495 | 509 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 7d | 3078 | 4622 | 3023 | 509 | 0 | 200 | scan | tronqué |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | au-dela-7d | 1189 | 1362 | 1226 | 509 | 0 | 0 | scan | tronqué |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 3495 | 3499 | 3013 | 509 | 0 | 200 | scan | tronqué |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 3.6 | 10 | 10 | 509 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 3.6 | 5.1 | 3.5 | 509 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 7d | 3.9 | 4.5 | 3.8 | 509 | 0 | 0 | scan |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | au-dela-7d | 626 | 702 | 684 | 509 | 0 | 0 | scan |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 3.3 | 3.6 | 3.5 | 509 | 0 | 0 | scan |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 3.6 | 34 | 34 | 509 | 0 | 1 | raw | dispersion x9.3 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 446 | 593 | 593 | 509 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 7d | — | — | 2910 | 509 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/7 tirs OK |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | au-dela-7d | — | — | 1103 | 509 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/7 tirs OK |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | — | — | 4103 | 509 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/3 tirs OK |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 4.0 | 28 | 28 | 509 | 0 | 1 | raw | dispersion x7.0 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 595 | 668 | 619 | 509 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 7d | — | — | 4677 | 509 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/3 tirs OK |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | au-dela-7d | — | — | 1096 | 509 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/7 tirs OK |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | — | — | 4327 | 509 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/3 tirs OK |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 1.1 | 27 | 27 | 509 | 0 | 1 | raw | dispersion x24.0 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 1.0 | 1.1 | 1.1 | 509 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 7d | — | — | 571 | 509 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/7 tirs OK |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | au-dela-7d | — | — | 1421 | 509 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/7 tirs OK |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | — | — | 1227 | 509 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/7 tirs OK |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 0.8 | 49 | 49 | 428 | 0 | 1 | raw | dispersion x64.0 (loadavg 2) — p95 dominé par la contention, pas par plume |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 0.8 | 0.9 | 0.6 | 428 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 7d | 575 | 636 | 616 | 429 | 0 | 1 | cold-vectorized-merge |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | au-dela-7d | 2785 | 2953 | 2483 | 429 | 0 | 1 | cold-vectorized |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 3202 | 3279 | 3279 | 429 | 0 | 1 | cold-vectorized-merge |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 4.4 | 26 | 26 | 429 | 0 | 3 | raw | dispersion x5.9 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 577 | 1620 | 577 | 429 | 0 | 38 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 7d | 6558 | 7017 | 7017 | 468 | 0 | 100 | scan | tronqué |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | au-dela-7d | 1151 | 1454 | 1454 | 468 | 0 | 4 | scan | tronqué |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 5665 | 6744 | 6744 | 468 | 0 | 100 | scan | tronqué |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 2.5 | 27 | 27 | 468 | 0 | 1 | raw | dispersion x10.4 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 525 | 544 | 544 | 468 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 7d | — | — | 4067 | 468 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/3 tirs OK |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | au-dela-7d | — | — | 1101 | 468 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/7 tirs OK |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | — | — | 5113 | 468 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/3 tirs OK |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 1h | 1.9 | 2.2 | 2.2 | 509 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 24h | 1.9 | 2.4 | 2.0 | 509 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 7d | 2.3 | 2.5 | 2.2 | 509 | 0 | 0 | scan |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | au-dela-7d | 1164 | 1294 | 1110 | 509 | 0 | 200 | scan | tronqué |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | all | 3.1 | 7.3 | 7.3 | 509 | 0 | 0 | scan |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 1h | 1.8 | 26 | 26 | 509 | 0 | 1 | raw | dispersion x14.5 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 24h | 506 | 547 | 547 | 509 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 7d | 654 | 759 | 654 | 509 | 0 | 1 | cold-vectorized-merge |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | au-dela-7d | 2728 | 3138 | 2588 | 509 | 0 | 1 | cold-vectorized |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | all | 3041 | 3449 | 2934 | 509 | 0 | 1 | cold-vectorized-merge |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 1h | 2.9 | 26 | 26 | 509 | 0 | 50 | raw | dispersion x9.0 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 24h | 427 | 494 | 494 | 509 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 7d | — | — | 6637 | 509 | 0 | — | scan | ERREUR: {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendr / 0/3 tirs OK |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | au-dela-7d | 2755 | 2888 | 2764 | 509 | 0 | 50 | cold-vectorized |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | all | 7775 | 8012 | 8012 | 509 | 0 | 50 | cold-vectorized-merge |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 1h | 2.1 | 25 | 25 | 509 | 0 | 22 | raw | dispersion x12.1 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 24h | 11 | 129 | 129 | 509 | 0 | 200 | raw | dispersion x11.4 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 7d | 6.6 | 88 | 88 | 509 | 0 | 0 | scan | dispersion x13.3 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | au-dela-7d | 1181 | 1511 | 1058 | 509 | 0 | 80 | scan | tronqué |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | all | 7.2 | 192 | 192 | 509 | 0 | 0 | scan | dispersion x26.5 (loadavg 5) — p95 dominé par la contention, pas par plume |

## Résultats — `chaud-seul-v2@1.4M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`bin:4bfcb9f76b4353a2 construit:2026-07-31T12:23:28Z (correctif troncature froide)`, 1 440 007 événements, base 1434 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**32 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 1.4 | 22 | 22 | 716 | 0 | 1 | raw | dispersion x16.4 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 17 | 439 | 439 | 716 | 0 | 1 | raw | dispersion x25.5 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 7d | 1576 | 2531 | 2531 | 716 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | au-dela-7d | 4573 | 6895 | 4573 | 730 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 5134 | 6319 | 4100 | 730 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 77 | 3874 | 3874 | 730 | 0 | 1 | raw | dispersion x50.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 18 | 346 | 346 | 730 | 0 | 1 | raw | dispersion x19.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 7d | 851 | 1735 | 1735 | 756 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | au-dela-7d | 2671 | 3776 | 3776 | 756 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 4001 | 10.4 s | 3196 | 718 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 2.8 | 32 | 32 | 718 | 0 | 1 | raw | dispersion x11.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 741 | 1731 | 1091 | 718 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 7d | 7010 | 9125 | 7010 | 718 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | au-dela-7d | 3841 | 4121 | 4121 | 812 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 2878 | 4885 | 4885 | 812 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 3.5 | 39 | 39 | 717 | 0 | 1 | raw | dispersion x11.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 787 | 1747 | 787 | 717 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 7d | 8636 | 9212 | 9212 | 721 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | au-dela-7d | 4904 | 9113 | 4904 | 721 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 4028 | 4261 | 3265 | 721 | 0 | 1 | raw |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 2.3 | 43 | 43 | 722 | 0 | 3 | scan | dispersion x18.7 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 2.2 | 3.5 | 2.2 | 722 | 0 | 38 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 7d | 3.2 | 3.3 | 3.2 | 722 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | au-dela-7d | 3.9 | 4.5 | 4.5 | 722 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 3.7 | 4.1 | 3.8 | 722 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 3.9 | 27 | 27 | 801 | 0 | 50 | raw | dispersion x6.8 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 635 | 671 | 671 | 801 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 7d | 8494 | 8512 | 8494 | 801 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | au-dela-7d | 11.6 s | 11.9 s | 10.7 s | 801 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 14.2 s | 15.3 s | 14.2 s | 801 | 0 | 50 | raw | **pris sous swap — à rejouer** |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 3.1 | 47 | 47 | 801 | 0 | 37 | raw | dispersion x15.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 8.6 | 49 | 49 | 801 | 0 | 48 | rollup | dispersion x5.7 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 7d | 46 | 195 | 195 | 801 | 0 | 53 | rollup | dispersion x4.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | au-dela-7d | 132 | 319 | 319 | 801 | 0 | 59 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 141 | 300 | 300 | 801 | 0 | 63 | rollup |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 6.2 | 83 | 83 | 801 | 0 | 50 | raw | dispersion x13.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 698 | 1777 | 1777 | 801 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 7d | 5130 | 7020 | 7020 | 801 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | au-dela-7d | 21.8 s | 22.0 s | 22.0 s | 852 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 7002 | 8392 | 7002 | 972 | 0 | 50 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 4.8 | 2577 | 2577 | 972 | 0 | 200 | raw | dispersion x533.5 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 15 | 472 | 419 | 972 | 0 | 200 | raw | dispersion x30.8 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 7d | 20 | 588 | 375 | 972 | 0 | 200 | raw | dispersion x30.2 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | au-dela-7d | 3.0 | 40 | 40 | 972 | 0 | 200 | raw | dispersion x13.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 1.7 | 2.5 | 2.5 | 972 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 6.6 | 59 | 59 | 972 | 0 | 0 | raw | dispersion x9.0 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 450 | 1490 | 1490 | 972 | 0 | 0 | raw | dispersion x3.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 7d | 2729 | 4259 | 4259 | 972 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | au-dela-7d | 441 | 634 | 634 | 972 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 254 | 1289 | 338 | 972 | 0 | 200 | raw | dispersion x5.1 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 8.0 | 9.5 | 8.9 | 972 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 7.5 | 8.0 | 7.4 | 972 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 7d | 7.4 | 7.6 | 7.3 | 972 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | au-dela-7d | 9.1 | 9.9 | 9.9 | 972 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 8.4 | 11 | 9.0 | 972 | 0 | 200 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 38 | 43 | 41 | 972 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 601 | 1665 | 881 | 972 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 7d | 8702 | 9442 | 9442 | 972 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | au-dela-7d | 5000 | 5015 | 5000 | 972 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 5441 | 7876 | 7876 | 987 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 4.6 | 57 | 57 | 987 | 0 | 1 | raw | dispersion x12.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 688 | 6436 | 1168 | 987 | 0 | 1 | raw | dispersion x9.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 7d | 8501 | 9133 | 8075 | 987 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | au-dela-7d | 5616 | 6368 | 4977 | 987 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 6074 | 7261 | 6074 | 987 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 2.9 | 217 | 217 | 987 | 0 | 1 | raw | dispersion x75.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 2.9 | 3.6 | 3.2 | 987 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 7d | 3.0 | 3.9 | 2.6 | 987 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | au-dela-7d | 3.5 | 3.9 | 3.5 | 987 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | 1.1 | 1.4 | 1.2 | 987 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 0.7 | 53 | 53 | 716 | 0 | 1 | raw | dispersion x72.3 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 0.8 | 0.9 | 0.7 | 716 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 7d | 0.7 | 0.8 | 0.8 | 716 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | au-dela-7d | 0.6 | 0.7 | 0.6 | 716 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 0.6 | 0.6 | 0.6 | 716 | 0 | 1 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 5.4 | 29 | 29 | 722 | 0 | 3 | raw | dispersion x5.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 734 | 6184 | 718 | 809 | 0 | 38 | raw | dispersion x8.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 7d | 6841 | 7472 | 6841 | 809 | 0 | 100 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | au-dela-7d | 2618 | 6131 | 6131 | 801 | 0 | 100 | raw | **pris sous swap — à rejouer** |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 3108 | 4580 | 3108 | 801 | 0 | 100 | raw | **pris sous swap — à rejouer** |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 47 | 4243 | 4243 | 801 | 0 | 1 | raw | dispersion x89.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 602 | 1588 | 1588 | 801 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 7d | 8349 | 11.0 s | 8349 | 801 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | au-dela-7d | 3484 | 4323 | 3484 | 801 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | 3685 | 8071 | 3685 | 801 | 0 | 1 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 1h | 6.7 | 9.9 | 9.9 | 972 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 24h | 6.4 | 6.9 | 6.4 | 972 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 7d | 6.4 | 6.9 | 6.4 | 972 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | au-dela-7d | 6.5 | 7.7 | 7.7 | 972 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | all | 6.9 | 8.0 | 6.5 | 972 | 0 | 200 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 1h | 2.5 | 28 | 28 | 987 | 0 | 1 | raw | dispersion x11.3 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 24h | 600 | 1668 | 1389 | 987 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 7d | 259 | 661 | 661 | 987 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | au-dela-7d | 27 | 5772 | 272 | 987 | 0 | 1 | raw | dispersion x215.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | all | 3.3 | 3.7 | 3.7 | 987 | 0 | 1 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 1h | 3.8 | 51 | 51 | 987 | 0 | 50 | raw | dispersion x13.3 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 24h | 623 | 1696 | 1696 | 987 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 7d | 22.2 s | 22.6 s | 22.6 s | 987 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | au-dela-7d | 20.9 s | 21.0 s | 21.0 s | 987 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | all | 102 | 263 | 263 | 987 | 0 | 50 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 1h | 2.7 | 28 | 28 | 987 | 0 | 22 | raw | dispersion x10.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 24h | 13 | 148 | 148 | 987 | 0 | 200 | raw | dispersion x11.6 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 7d | 260 | 265 | 251 | 987 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | au-dela-7d | 21 | 812 | 515 | 987 | 0 | 200 | raw | dispersion x39.2 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | all | 21 | 21 | 20 | 987 | 0 | 200 | raw |  |

## Résultats — `temoin-64h@0.6M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`bin:72c367a16a91f06a construit:2026-08-03T06:02:47Z (HEAD au rendu: 77600da — indicatif, l'arbre bouge)`, 600 003 événements, base 647 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**35 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 1.3 | 21 | 21 | 117 | 0 | 1 | raw | dispersion x16.4 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 11 | 378 | 378 | 149 | 0 | 1 | raw | dispersion x33.7 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 7d | 611 | 1774 | 1774 | 176 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | au-dela-7d | 1869 | 3402 | 3402 | 176 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 1223 | 2181 | 1070 | 506 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 1.5 | 4.2 | 4.2 | 505 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 9.0 | 77 | 77 | 508 | 0 | 1 | raw | dispersion x8.6 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 7d | 97 | 496 | 496 | 511 | 0 | 1 | raw | dispersion x5.1 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | au-dela-7d | 1233 | 2829 | 1304 | 549 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 1534 | 3170 | 1679 | 328 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 1.3 | 9.6 | 9.6 | 328 | 0 | 1 | raw | dispersion x7.4 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 38 | 264 | 264 | 499 | 0 | 1 | raw | dispersion x6.9 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 7d | 1986 | 4763 | 1986 | 499 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | au-dela-7d | 1677 | 2180 | 1805 | 524 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 1471 | 2521 | 1419 | 607 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 2.2 | 12 | 12 | 607 | 0 | 1 | raw | dispersion x5.2 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 36 | 207 | 207 | 607 | 0 | 1 | raw | dispersion x5.7 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 7d | 2098 | 3529 | 2718 | 607 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | au-dela-7d | 1850 | 3096 | 2173 | 596 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 1871 | 2532 | 2532 | 596 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 115 | 233 | 233 | 387 | 0 | 3 | scan | **pris sous swap — à rejouer** |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 2.5 | 37 | 37 | 387 | 0 | 18 | scan | dispersion x14.8 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 7d | 3.7 | 3.9 | 3.5 | 387 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | au-dela-7d | 4.5 | 5.3 | 4.5 | 387 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 3.2 | 3.8 | 3.2 | 387 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 2.8 | 12 | 12 | 551 | 0 | 50 | raw | dispersion x4.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 291 | 319 | 303 | 551 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 7d | 3313 | 4315 | 2363 | 752 | 0 | 50 | raw | **pris sous swap — à rejouer** |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | au-dela-7d | 4292 | 5012 | 5012 | 768 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 6319 | 7174 | 7174 | 768 | 0 | 50 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 1.9 | 37 | 37 | 551 | 0 | 33 | raw | dispersion x19.1 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 15 | 35 | 35 | 551 | 0 | 50 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 7d | 106 | 233 | 233 | 551 | 0 | 59 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | au-dela-7d | 342 | 1422 | 1422 | 551 | 0 | 65 | rollup | dispersion x4.2 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 518 | 1218 | 454 | 551 | 0 | 68 | rollup | **pris sous swap — à rejouer** |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 3.3 | 4.0 | 3.3 | 550 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 357 | 925 | 925 | 565 | 0 | 50 | raw | **pris sous swap — à rejouer** |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 7d | 3386 | 5729 | 3386 | 749 | 0 | 50 | raw | **pris sous swap — à rejouer** |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | au-dela-7d | 10.9 s | 12.0 s | 10.9 s | 717 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 3219 | 3429 | 3429 | 732 | 0 | 50 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 2.4 | 20 | 20 | 732 | 0 | 200 | raw | dispersion x8.2 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 13 | 151 | 91 | 732 | 0 | 200 | raw | dispersion x11.6 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 7d | 201 | 310 | 169 | 732 | 0 | 200 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | au-dela-7d | 5.2 | 58 | 58 | 732 | 0 | 200 | raw | dispersion x11.1 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 2.6 | 3.8 | 3.8 | 732 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 2.9 | 13 | 13 | 732 | 0 | 0 | raw | dispersion x4.6 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 145 | 259 | 259 | 732 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 7d | 1099 | 1570 | 1570 | 732 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | au-dela-7d | 805 | 1230 | 614 | 754 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 415 | 749 | 749 | 755 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 3.5 | 25 | 25 | 547 | 0 | 200 | raw | dispersion x7.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 5.0 | 6.1 | 6.1 | 547 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 7d | 3.3 | 4.2 | 4.2 | 547 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | au-dela-7d | 3.0 | 12 | 12 | 547 | 0 | 200 | raw | dispersion x3.9 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 3.9 | 6.5 | 2.9 | 547 | 0 | 200 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 2.9 | 18 | 18 | 547 | 0 | 1 | raw | dispersion x6.1 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 42 | 536 | 536 | 547 | 0 | 1 | raw | dispersion x12.7 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 7d | 3158 | 3179 | 3179 | 547 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | au-dela-7d | 2121 | 3104 | 2486 | 762 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 2653 | 3406 | 2271 | 765 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 3.7 | 28 | 28 | 547 | 0 | 1 | raw | dispersion x7.6 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 345 | 361 | 359 | 547 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 7d | 2899 | 5296 | 2899 | 722 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | au-dela-7d | 3191 | 3947 | 3191 | 547 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 2443 | 3869 | 2249 | 762 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 4.6 | 20 | 20 | 546 | 0 | 1 | raw | dispersion x4.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 3.3 | 39 | 39 | 546 | 0 | 1 | raw | dispersion x11.8 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 7d | 1.8 | 3.7 | 3.7 | 546 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | au-dela-7d | 2.2 | 2.8 | 2.8 | 546 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | 1.0 | 1.2 | 1.2 | 546 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 0.8 | 57 | 57 | 115 | 0 | 1 | raw | dispersion x70.0 (loadavg 3) — p95 dominé par la contention, pas par plume |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 0.8 | 1.1 | 0.8 | 115 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 7d | 0.8 | 1.5 | 1.5 | 115 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | au-dela-7d | 0.9 | 1.3 | 0.9 | 115 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 1.0 | 2.0 | 2.0 | 115 | 0 | 1 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 3.0 | 30 | 30 | 387 | 0 | 3 | raw | dispersion x9.9 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 70 | 797 | 797 | 399 | 0 | 18 | raw | **pris sous swap — à rejouer** / dispersion x11.4 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 7d | 2069 | 3235 | 3235 | 736 | 0 | 100 | raw | **pris sous swap — à rejouer** |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | au-dela-7d | 1472 | 2684 | 1548 | 737 | 0 | 100 | raw | **pris sous swap — à rejouer** |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 1506 | 2410 | 1346 | 767 | 0 | 100 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 1.8 | 3.2 | 3.2 | 767 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 36 | 42 | 42 | 767 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 7d | 241 | 4163 | 267 | 767 | 0 | 1 | raw | dispersion x17.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | au-dela-7d | 1481 | 2602 | 2059 | 763 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | 1454 | 2432 | 1308 | 551 | 0 | 1 | raw | **pris sous swap — à rejouer** |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 1h | 2.2 | 3.8 | 2.8 | 547 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 24h | 2.1 | 3.7 | 1.9 | 547 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 7d | 2.4 | 3.5 | 2.6 | 547 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | au-dela-7d | 1.7 | 5.8 | 5.8 | 547 | 0 | 200 | raw | dispersion x3.4 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | all | 2.1 | 2.9 | 2.6 | 547 | 0 | 200 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 1h | 1.8 | 14 | 14 | 547 | 0 | 1 | raw | dispersion x7.9 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 24h | 9.9 | 147 | 147 | 547 | 0 | 1 | raw | dispersion x14.9 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 7d | 8.3 | 10 | 8.3 | 547 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | au-dela-7d | 8.4 | 9.8 | 9.8 | 547 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | all | 1.8 | 2.6 | 1.8 | 547 | 0 | 1 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 1h | 2.1 | 3.8 | 1.7 | 547 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 24h | 324 | 1044 | 720 | 547 | 0 | 50 | raw | **pris sous swap — à rejouer** / dispersion x3.2 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 7d | 7806 | 11.6 s | 7806 | 773 | 0 | 50 | raw | **pris sous swap — à rejouer** |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | au-dela-7d | 10.1 s | 10.4 s | 10.1 s | 773 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | all | 58 | 365 | 365 | 546 | 0 | 50 | raw | dispersion x6.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 1h | 2.5 | 24 | 24 | 546 | 0 | 5 | raw | dispersion x9.6 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 24h | 15 | 236 | 236 | 546 | 0 | 200 | raw | dispersion x15.6 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 7d | 12 | 247 | 247 | 546 | 0 | 200 | raw | dispersion x21.2 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | au-dela-7d | 11 | 12 | 11 | 546 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | all | 10 | 12 | 12 | 546 | 0 | 200 | raw |  |

## Résultats — `flotte-1h-v2@0.6M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`bin:72c367a16a91f06a construit:2026-08-03T06:02:47Z (HEAD au rendu: 77600da — indicatif, l'arbre bouge)`, 600 003 événements, base 634 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**37 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 1.3 | 17 | 17 | 115 | 0 | 1 | raw | dispersion x13.2 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 8.7 | 372 | 372 | 130 | 0 | 1 | raw | dispersion x42.6 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 7d | 590 | 1722 | 1722 | 157 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | au-dela-7d | 1847 | 3103 | 3103 | 157 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 1124 | 2151 | 950 | 457 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 1.2 | 15 | 15 | 459 | 0 | 1 | raw | dispersion x12.5 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 6.9 | 72 | 72 | 459 | 0 | 1 | raw | dispersion x10.4 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 7d | 228 | 430 | 403 | 533 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | au-dela-7d | 1376 | 3026 | 1425 | 575 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 1566 | 3564 | 1746 | 346 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 1.6 | 17 | 17 | 345 | 0 | 1 | raw | dispersion x10.7 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 39 | 677 | 376 | 556 | 0 | 1 | raw | dispersion x17.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 7d | 2078 | 4465 | 2204 | 556 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | au-dela-7d | 1445 | 1916 | 1916 | 543 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 1432 | 2644 | 1445 | 586 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 2.7 | 23 | 23 | 586 | 0 | 1 | raw | dispersion x8.8 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 45 | 874 | 874 | 586 | 0 | 1 | raw | dispersion x19.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 7d | 2299 | 4008 | 4008 | 573 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | au-dela-7d | 1756 | 2357 | 2357 | 573 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 1707 | 3076 | 2905 | 577 | 0 | 1 | raw |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 78 | 91 | 80 | 360 | 0 | 3 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 1.8 | 17 | 17 | 360 | 0 | 18 | scan | dispersion x9.6 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 7d | 2.8 | 3.1 | 3.0 | 360 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | au-dela-7d | 3.0 | 4.3 | 2.3 | 360 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 3.0 | 5.1 | 4.0 | 360 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 4.0 | 13 | 13 | 836 | 0 | 50 | raw | dispersion x3.2 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 41 | 249 | 249 | 836 | 0 | 50 | raw | dispersion x6.0 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 7d | 3041 | 4806 | 2066 | 836 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | au-dela-7d | 5494 | 6180 | 5494 | 831 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 5027 | 5605 | 5027 | 806 | 0 | 50 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 1.6 | 8.7 | 8.7 | 619 | 0 | 33 | raw | dispersion x5.3 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 14 | 28 | 28 | 619 | 0 | 50 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 7d | 88 | 158 | 158 | 619 | 0 | 59 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | au-dela-7d | 260 | 581 | 581 | 619 | 0 | 65 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 467 | 935 | 331 | 619 | 0 | 68 | rollup |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 3.9 | 4.9 | 4.9 | 619 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 282 | 866 | 866 | 822 | 0 | 50 | raw | dispersion x3.1 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 7d | 2528 | 4852 | 2894 | 822 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | au-dela-7d | 8875 | 10.3 s | 7763 | 831 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 3723 | 4014 | 3288 | 803 | 0 | 50 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 3.2 | 13 | 13 | 619 | 0 | 200 | raw | dispersion x4.0 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 12 | 152 | 152 | 619 | 0 | 200 | raw | dispersion x13.2 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 7d | 13 | 149 | 144 | 619 | 0 | 200 | raw | dispersion x11.3 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | au-dela-7d | 4.4 | 28 | 28 | 619 | 0 | 200 | raw | dispersion x6.4 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 2.1 | 3.7 | 3.7 | 619 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 2.6 | 3.0 | 2.7 | 619 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 37 | 227 | 227 | 619 | 0 | 0 | raw | dispersion x6.1 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 7d | 1786 | 3689 | 1506 | 845 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | au-dela-7d | 569 | 866 | 778 | 619 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 467 | 1104 | 1104 | 619 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 3.1 | 12 | 12 | 619 | 0 | 200 | raw | dispersion x3.8 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 3.4 | 4.7 | 4.7 | 619 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 7d | 2.7 | 3.4 | 3.2 | 619 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | au-dela-7d | 4.3 | 8.7 | 8.7 | 619 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 3.8 | 4.7 | 4.7 | 619 | 0 | 200 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 2.4 | 15 | 15 | 619 | 0 | 1 | raw | dispersion x6.5 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 44 | 584 | 584 | 619 | 0 | 1 | raw | dispersion x13.2 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 7d | 2537 | 4113 | 2537 | 831 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | au-dela-7d | 2485 | 2962 | 2962 | 834 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 1778 | 2765 | 1630 | 831 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 2.7 | 16 | 16 | 832 | 0 | 1 | raw | dispersion x5.9 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 56 | 270 | 270 | 832 | 0 | 1 | raw | dispersion x4.8 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 7d | 2246 | 3501 | 1619 | 832 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | au-dela-7d | 2553 | 3444 | 3444 | 834 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 2752 | 3462 | 2752 | 834 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 2.3 | 25 | 25 | 619 | 0 | 1 | raw | dispersion x11.2 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 1.6 | 46 | 46 | 619 | 0 | 1 | raw | dispersion x28.8 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 7d | 1.9 | 2.4 | 1.9 | 619 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | au-dela-7d | 1.9 | 2.4 | 1.4 | 619 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | 1.0 | 1.3 | 1.3 | 619 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 0.9 | 67 | 67 | 115 | 0 | 1 | raw | dispersion x76.0 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 0.7 | 0.8 | 0.7 | 115 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 7d | 0.8 | 0.9 | 0.6 | 115 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | au-dela-7d | 0.8 | 1.1 | 1.1 | 115 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 0.8 | 0.9 | 0.9 | 115 | 0 | 1 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 3.4 | 17 | 17 | 360 | 0 | 3 | raw | dispersion x5.1 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 308 | 470 | 470 | 360 | 0 | 18 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 7d | 1934 | 2849 | 2196 | 683 | 0 | 100 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | au-dela-7d | 1509 | 2608 | 1526 | 689 | 0 | 100 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 1655 | 2580 | 1303 | 833 | 0 | 100 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 2.1 | 6.9 | 6.9 | 619 | 0 | 1 | raw | dispersion x3.2 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 30 | 139 | 139 | 619 | 0 | 1 | raw | dispersion x4.7 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 7d | 1980 | 2793 | 911 | 626 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | au-dela-7d | 1428 | 2502 | 2113 | 833 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | 1491 | 2647 | 1461 | 836 | 0 | 1 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 1h | 1.8 | 3.2 | 1.8 | 619 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 24h | 2.2 | 2.5 | 2.3 | 619 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 7d | 1.9 | 2.8 | 2.2 | 619 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | au-dela-7d | 2.0 | 3.0 | 3.0 | 619 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | all | 1.9 | 2.6 | 2.6 | 619 | 0 | 200 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 1h | 1.4 | 23 | 23 | 834 | 0 | 1 | raw | dispersion x16.8 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 24h | 21 | 297 | 297 | 834 | 0 | 1 | raw | dispersion x14.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 7d | 1842 | 4922 | 1654 | 834 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | au-dela-7d | 1160 | 2269 | 2269 | 834 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | all | 42 | 376 | 163 | 834 | 0 | 1 | raw | dispersion x9.0 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 1h | 2.6 | 31 | 31 | 619 | 0 | 1 | raw | dispersion x12.0 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 24h | 260 | 945 | 439 | 619 | 0 | 1 | raw | dispersion x3.6 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 7d | 1311 | 2432 | 2432 | 837 | 0 | 1 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | au-dela-7d | 1307 | 1953 | 1323 | 837 | 0 | 1 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | all | 56 | 433 | 433 | 619 | 0 | 2 | raw | dispersion x7.7 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 1h | 2.1 | 28 | 28 | 619 | 0 | 200 | raw | dispersion x13.2 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 24h | 1.7 | 2.5 | 2.5 | 619 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 7d | 2.1 | 3.4 | 1.7 | 619 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | au-dela-7d | 2.4 | 13 | 13 | 619 | 0 | 200 | raw | dispersion x5.4 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | all | 1.6 | 2.4 | 2.4 | 619 | 0 | 200 | raw |  |

## Résultats — `flotte-50h-v2@0.6M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`bin:72c367a16a91f06a construit:2026-08-03T06:02:47Z (HEAD au rendu: 77600da — indicatif, l'arbre bouge)`, 600 003 événements, base 377 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**25 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 1.0 | 21 | 21 | 121 | 0 | 1 | raw | dispersion x19.9 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 9.3 | 416 | 416 | 138 | 0 | 1 | raw | dispersion x44.8 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 7d | 315 | 1322 | 1322 | 163 | 0 | 1 | raw | dispersion x4.2 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | au-dela-7d | 936 | 1302 | 1302 | 163 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 628 | 702 | 437 | 163 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 1.0 | 2.6 | 2.6 | 163 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 7.1 | 28 | 28 | 163 | 0 | 1 | raw | dispersion x3.9 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 7d | 38 | 166 | 166 | 163 | 0 | 1 | raw | dispersion x4.4 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | au-dela-7d | 568 | 764 | 543 | 352 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 1445 | 2657 | 668 | 468 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 11 | 13 | 13 | 270 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 251 | 718 | 683 | 270 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 7d | 1078 | 2174 | 2174 | 270 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | au-dela-7d | 867 | 1523 | 867 | 486 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 744 | 878 | 659 | 486 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 2.8 | 49 | 49 | 279 | 0 | 1 | raw | dispersion x17.7 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 339 | 894 | 767 | 280 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 7d | 1753 | 2826 | 2826 | 424 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | au-dela-7d | 1020 | 1075 | 738 | 424 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 1065 | 1096 | 1019 | 424 | 0 | 1 | raw |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 1.5 | 9.8 | 9.8 | 424 | 0 | 0 | scan | dispersion x6.5 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 2.5 | 3.4 | 2.3 | 424 | 0 | 25 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 7d | 4.3 | 7.6 | 4.3 | 424 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | au-dela-7d | 5.5 | 6.0 | 5.5 | 424 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 2.9 | 6.0 | 5.6 | 424 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 4.3 | 12 | 12 | 355 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 249 | 848 | 178 | 355 | 0 | 50 | raw | dispersion x3.4 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 7d | 1750 | 2861 | 2861 | 501 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | au-dela-7d | 1551 | 2211 | 1684 | 374 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 1769 | 2475 | 1760 | 594 | 0 | 50 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 2.5 | 9.8 | 9.8 | 384 | 0 | 26 | raw | dispersion x4.0 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 9.4 | 20 | 20 | 384 | 0 | 42 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 7d | 47 | 99 | 99 | 384 | 0 | 52 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | au-dela-7d | 166 | 353 | 353 | 384 | 0 | 53 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 189 | 207 | 205 | 384 | 0 | 57 | rollup |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 2.0 | 3.2 | 2.2 | 384 | 0 | 26 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 257 | 856 | 257 | 385 | 0 | 50 | raw | dispersion x3.3 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 7d | 1887 | 3456 | 2678 | 594 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | au-dela-7d | 5252 | 6081 | 5252 | 551 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 1485 | 2265 | 958 | 551 | 0 | 50 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 3.3 | 23 | 23 | 537 | 0 | 200 | raw | dispersion x6.9 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 420 | 477 | 447 | 578 | 0 | 200 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 7d | 14 | 373 | 373 | 384 | 0 | 200 | raw | dispersion x25.9 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | au-dela-7d | 5.8 | 30 | 30 | 384 | 0 | 200 | raw | dispersion x5.2 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 1.8 | 2.9 | 2.9 | 384 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 3.0 | 20 | 20 | 384 | 0 | 0 | raw | dispersion x6.4 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 41 | 250 | 250 | 384 | 0 | 0 | raw | dispersion x6.2 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 7d | 1020 | 2197 | 2197 | 594 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | au-dela-7d | 49 | 243 | 243 | 594 | 0 | 200 | raw | dispersion x5.0 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 30 | 33 | 33 | 594 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 2.6 | 3.7 | 2.6 | 594 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 2.8 | 3.4 | 2.8 | 594 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 7d | 2.2 | 3.3 | 2.1 | 594 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | au-dela-7d | 2.5 | 3.0 | 2.8 | 594 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 2.4 | 2.8 | 2.8 | 594 | 0 | 200 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 2.1 | 3.1 | 2.1 | 594 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 25 | 40 | 40 | 594 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 7d | 172 | 190 | 190 | 594 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | au-dela-7d | 202 | 211 | 211 | 594 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 777 | 1468 | 204 | 594 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 1.8 | 8.5 | 8.5 | 384 | 0 | 1 | raw | dispersion x4.7 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 194 | 198 | 197 | 384 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 7d | 1480 | 2564 | 1480 | 594 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | au-dela-7d | 737 | 865 | 462 | 594 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 774 | 1577 | 1577 | 384 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 0.7 | 1.9 | 1.9 | 571 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 0.7 | 1.2 | 0.7 | 571 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 7d | 0.8 | 1.2 | 1.2 | 571 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | au-dela-7d | 0.7 | 0.7 | 0.7 | 571 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | 0.7 | 1.0 | 0.7 | 571 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 0.8 | 52 | 52 | 121 | 0 | 1 | raw | dispersion x68.0 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 0.8 | 0.8 | 0.8 | 121 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 7d | 0.7 | 0.9 | 0.8 | 121 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | au-dela-7d | 0.8 | 1.1 | 0.9 | 121 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 0.8 | 1.0 | 1.0 | 121 | 0 | 1 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 2.9 | 13 | 13 | 424 | 0 | 0 | raw | dispersion x4.4 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 196 | 296 | 296 | 424 | 0 | 25 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 7d | 850 | 2683 | 1759 | 550 | 0 | 100 | raw | dispersion x3.2 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | au-dela-7d | 231 | 549 | 549 | 535 | 0 | 100 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 219 | 233 | 226 | 535 | 0 | 100 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 1.5 | 2.6 | 2.6 | 535 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 27 | 32 | 32 | 535 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 7d | 1595 | 2715 | 216 | 535 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | au-dela-7d | 908 | 1601 | 728 | 562 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | 781 | 801 | 749 | 355 | 0 | 1 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 1h | 1.7 | 2.6 | 2.6 | 594 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 24h | 1.8 | 3.0 | 3.0 | 594 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 7d | 1.8 | 3.8 | 3.8 | 594 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | au-dela-7d | 2.1 | 2.4 | 2.1 | 594 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | all | 1.9 | 2.9 | 1.7 | 594 | 0 | 200 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 1h | 1.5 | 10 | 10 | 384 | 0 | 1 | raw | dispersion x6.9 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 24h | 188 | 201 | 201 | 384 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 7d | 9.4 | 115 | 115 | 384 | 0 | 1 | raw | dispersion x12.2 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | au-dela-7d | 9.7 | 11 | 10 | 384 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | all | 1.9 | 2.2 | 2.2 | 384 | 0 | 1 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 1h | 1.7 | 2.3 | 1.7 | 384 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 24h | 222 | 232 | 210 | 384 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 7d | 2470 | 6407 | 6407 | 562 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | au-dela-7d | 6138 | 8233 | 2304 | 571 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | all | 58 | 144 | 144 | 571 | 0 | 50 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 1h | 1.9 | 14 | 14 | 571 | 0 | 14 | raw | dispersion x7.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 24h | 15 | 133 | 133 | 571 | 0 | 200 | raw | dispersion x8.9 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 7d | 13 | 174 | 161 | 571 | 0 | 200 | raw | dispersion x13.5 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | au-dela-7d | 12 | 25 | 13 | 571 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | all | 13 | 14 | 13 | 571 | 0 | 200 | raw |  |

## Résultats — `card-haute@0.6M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`bin:72c367a16a91f06a construit:2026-08-03T06:02:47Z (HEAD au rendu: 77600da — indicatif, l'arbre bouge)`, 600 003 événements, base 649 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**29 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 1.0 | 23 | 23 | 115 | 0 | 1 | raw | dispersion x22.2 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 9.1 | 376 | 376 | 130 | 0 | 1 | raw | dispersion x41.2 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 7d | 567 | 1670 | 1670 | 157 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | au-dela-7d | 1631 | 3106 | 3106 | 157 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 1117 | 1547 | 1048 | 306 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 1.2 | 20 | 20 | 317 | 0 | 1 | raw | dispersion x16.5 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 8.5 | 133 | 133 | 391 | 0 | 1 | raw | dispersion x15.6 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 7d | 45 | 605 | 605 | 490 | 0 | 1 | raw | dispersion x13.4 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | au-dela-7d | 1143 | 1450 | 1450 | 618 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 89 | 203 | 203 | 618 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 1.7 | 5.3 | 5.3 | 618 | 0 | 1 | raw | dispersion x3.1 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 344 | 1027 | 116 | 618 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 7d | 2010 | 3601 | 3601 | 394 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | au-dela-7d | 1426 | 2386 | 2301 | 613 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 1377 | 2440 | 1343 | 613 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 1.6 | 12 | 12 | 407 | 0 | 1 | raw | dispersion x7.2 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 273 | 288 | 251 | 407 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 7d | 1533 | 2158 | 2099 | 627 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | au-dela-7d | 2311 | 2919 | 1516 | 629 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 1699 | 2842 | 1699 | 627 | 0 | 1 | raw |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 79 | 82 | 77 | 410 | 0 | 3 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 1.8 | 12 | 12 | 410 | 0 | 18 | scan | dispersion x6.5 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 7d | 2.4 | 3.6 | 3.6 | 410 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | au-dela-7d | 2.9 | 3.7 | 3.7 | 410 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 2.4 | 3.2 | 2.1 | 410 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 2.8 | 13 | 13 | 582 | 0 | 50 | raw | dispersion x4.5 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 267 | 290 | 287 | 582 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 7d | 2871 | 3514 | 2951 | 754 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | au-dela-7d | 5123 | 6763 | 5123 | 798 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 7003 | 7324 | 7324 | 798 | 0 | 50 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 2.1 | 19 | 19 | 758 | 0 | 33 | raw | dispersion x8.8 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 17 | 27 | 27 | 758 | 0 | 50 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 7d | 102 | 198 | 198 | 758 | 0 | 59 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | au-dela-7d | 350 | 604 | 604 | 758 | 0 | 65 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 477 | 1170 | 486 | 758 | 0 | 68 | rollup |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 4.2 | 38 | 38 | 582 | 0 | 50 | raw | dispersion x9.1 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 69 | 901 | 901 | 582 | 0 | 50 | raw | dispersion x13.0 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 7d | 1885 | 3758 | 3758 | 582 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | au-dela-7d | 9089 | 9786 | 7873 | 790 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 3776 | 3780 | 3776 | 790 | 0 | 50 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 3.8 | 28 | 28 | 582 | 0 | 200 | raw | dispersion x7.5 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 15 | 154 | 154 | 582 | 0 | 200 | raw | dispersion x10.5 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 7d | 13 | 382 | 382 | 582 | 0 | 200 | raw | dispersion x29.2 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | au-dela-7d | 5.2 | 62 | 62 | 582 | 0 | 200 | raw | dispersion x12.0 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 1.7 | 3.8 | 3.8 | 582 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 2.3 | 9.1 | 9.1 | 582 | 0 | 0 | raw | dispersion x4.0 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 38 | 182 | 182 | 582 | 0 | 0 | raw | dispersion x4.7 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 7d | 2517 | 5044 | 2517 | 797 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | au-dela-7d | 898 | 1229 | 951 | 587 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 415 | 444 | 388 | 587 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 10 | 15 | 15 | 587 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 8.7 | 13 | 8.7 | 587 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 7d | 9.4 | 13 | 9.4 | 587 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | au-dela-7d | 11 | 15 | 15 | 587 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 9.8 | 11 | 9.8 | 587 | 0 | 200 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 20 | 27 | 27 | 587 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 527 | 916 | 916 | 794 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 7d | 2507 | 3984 | 3984 | 794 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | au-dela-7d | 1812 | 1989 | 1989 | 796 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 2108 | 3149 | 2108 | 798 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 21 | 23 | 22 | 586 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 593 | 1128 | 612 | 587 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 7d | 4459 | 4773 | 4773 | 801 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | au-dela-7d | 2570 | 3094 | 3094 | 587 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 3066 | 3396 | 3396 | 806 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 2.0 | 9.5 | 9.5 | 586 | 0 | 1 | raw | dispersion x4.8 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 1.6 | 12 | 12 | 586 | 0 | 1 | raw | dispersion x7.5 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 7d | 1.4 | 1.6 | 1.6 | 586 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | au-dela-7d | 1.2 | 1.3 | 1.1 | 586 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | 0.8 | 1.0 | 1.0 | 586 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 1.2 | 57 | 57 | 115 | 0 | 1 | raw | dispersion x47.7 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 1.1 | 1.1 | 1.1 | 115 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 7d | 0.9 | 1.1 | 0.9 | 115 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | au-dela-7d | 0.9 | 1.2 | 0.9 | 115 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 1.0 | 1.8 | 1.1 | 115 | 0 | 1 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 2.7 | 15 | 15 | 410 | 0 | 3 | raw | dispersion x5.5 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 275 | 295 | 289 | 410 | 0 | 18 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 7d | 1536 | 2923 | 1880 | 741 | 0 | 100 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | au-dela-7d | 1453 | 2176 | 1501 | 782 | 0 | 100 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 1392 | 1884 | 1349 | 799 | 0 | 100 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 2.0 | 4.2 | 4.2 | 799 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 28 | 76 | 76 | 799 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 7d | 196 | 453 | 453 | 799 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | au-dela-7d | 1419 | 2150 | 757 | 799 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | 1636 | 2548 | 1806 | 798 | 0 | 1 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 1h | 9.3 | 9.9 | 9.9 | 587 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 24h | 7.7 | 9.3 | 7.7 | 587 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 7d | 8.9 | 11 | 7.7 | 587 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | au-dela-7d | 8.9 | 12 | 9.6 | 587 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | all | 7.7 | 10.0 | 8.0 | 587 | 0 | 200 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 1h | 1.5 | 20 | 20 | 803 | 0 | 1 | raw | dispersion x13.4 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 24h | 7.7 | 138 | 138 | 803 | 0 | 1 | raw | dispersion x17.9 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 7d | 6.8 | 8.0 | 8.0 | 803 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | au-dela-7d | 7.7 | 8.1 | 8.1 | 803 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | all | 1.3 | 2.1 | 2.1 | 803 | 0 | 1 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 1h | 1.8 | 2.2 | 2.2 | 803 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 24h | 30 | 223 | 223 | 803 | 0 | 50 | raw | dispersion x7.5 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 7d | 7670 | 9507 | 7670 | 803 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | au-dela-7d | 8510 | 10.3 s | 8510 | 775 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | all | 69 | 306 | 306 | 586 | 0 | 50 | raw | dispersion x4.4 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 1h | 3.1 | 23 | 23 | 586 | 0 | 5 | raw | dispersion x7.6 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 24h | 17 | 217 | 217 | 586 | 0 | 200 | raw | dispersion x13.0 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 7d | 9.0 | 174 | 174 | 586 | 0 | 200 | raw | dispersion x19.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | au-dela-7d | 10 | 12 | 10 | 586 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | all | 10 | 13 | 10 | 586 | 0 | 200 | raw |  |

## Résultats — `sev-haute@0.6M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`bin:72c367a16a91f06a construit:2026-08-03T06:02:47Z (HEAD au rendu: 77600da — indicatif, l'arbre bouge)`, 600 003 événements, base 649 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**35 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 0.9 | 19 | 19 | 116 | 0 | 1 | raw | dispersion x20.4 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 7.9 | 417 | 417 | 131 | 0 | 1 | raw | dispersion x52.8 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 7d | 525 | 1630 | 1630 | 158 | 0 | 1 | raw | dispersion x3.1 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | au-dela-7d | 1716 | 3113 | 3113 | 158 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 1073 | 1669 | 1005 | 304 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 1.3 | 19 | 19 | 311 | 0 | 1 | raw | dispersion x14.3 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 7.1 | 111 | 111 | 362 | 0 | 1 | raw | dispersion x15.6 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 7d | 113 | 620 | 620 | 599 | 0 | 1 | raw | dispersion x5.5 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | au-dela-7d | 990 | 1350 | 1319 | 634 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 92 | 3791 | 208 | 634 | 0 | 1 | raw | dispersion x41.3 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 1.6 | 40 | 40 | 410 | 0 | 1 | raw | dispersion x25.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 281 | 430 | 430 | 410 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 7d | 1915 | 3815 | 2451 | 584 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | au-dela-7d | 1628 | 2359 | 1989 | 584 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 1334 | 2437 | 1334 | 627 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 1.7 | 11 | 11 | 410 | 0 | 1 | raw | dispersion x6.4 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 295 | 322 | 251 | 410 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 7d | 2460 | 3654 | 1994 | 720 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | au-dela-7d | 1759 | 2849 | 2584 | 496 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 1792 | 2984 | 1520 | 713 | 0 | 1 | raw |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 83 | 96 | 83 | 496 | 0 | 3 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 1.7 | 12 | 12 | 496 | 0 | 18 | scan | dispersion x7.1 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 7d | 2.5 | 3.4 | 2.5 | 496 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | au-dela-7d | 3.0 | 3.8 | 3.0 | 496 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 2.1 | 3.5 | 2.8 | 496 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 3.5 | 15 | 15 | 472 | 0 | 50 | raw | dispersion x4.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 322 | 847 | 268 | 472 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 7d | 2209 | 4075 | 4075 | 687 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | au-dela-7d | 4363 | 5106 | 5106 | 838 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 4765 | 5267 | 4765 | 838 | 0 | 50 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 3.3 | 23 | 23 | 614 | 0 | 41 | raw | dispersion x6.9 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 14 | 46 | 46 | 614 | 0 | 53 | rollup | dispersion x3.2 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 7d | 98 | 265 | 265 | 614 | 0 | 62 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | au-dela-7d | 332 | 795 | 795 | 614 | 0 | 65 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 396 | 523 | 362 | 614 | 0 | 69 | rollup |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 3.5 | 3.9 | 3.5 | 614 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 273 | 382 | 349 | 807 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 7d | 3272 | 3844 | 3844 | 807 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | au-dela-7d | 9710 | 10.6 s | 10.6 s | 792 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 4226 | 4815 | 4815 | 831 | 0 | 50 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 3.1 | 32 | 32 | 614 | 0 | 200 | raw | dispersion x10.4 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 19 | 167 | 167 | 614 | 0 | 200 | raw | dispersion x8.7 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 7d | 11 | 298 | 298 | 614 | 0 | 200 | raw | dispersion x26.8 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | au-dela-7d | 3.2 | 40 | 40 | 614 | 0 | 200 | raw | dispersion x12.6 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 1.5 | 2.4 | 2.4 | 614 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 3.0 | 11 | 11 | 614 | 0 | 0 | raw | dispersion x3.6 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 151 | 254 | 254 | 614 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 7d | 1313 | 2850 | 2478 | 809 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | au-dela-7d | 521 | 776 | 776 | 809 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 36 | 402 | 402 | 809 | 0 | 200 | raw | dispersion x11.1 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 5.1 | 7.6 | 7.6 | 809 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 4.0 | 5.4 | 5.4 | 809 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 7d | 2.6 | 4.5 | 2.5 | 809 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | au-dela-7d | 3.5 | 8.1 | 8.1 | 809 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 3.6 | 4.9 | 3.2 | 809 | 0 | 200 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 4.0 | 9.7 | 9.7 | 809 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 46 | 196 | 196 | 809 | 0 | 1 | raw | dispersion x4.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 7d | 2383 | 3487 | 3487 | 809 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | au-dela-7d | 2747 | 3149 | 2285 | 862 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 1946 | 3056 | 2080 | 850 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 3.2 | 10 | 10 | 849 | 0 | 1 | raw | dispersion x3.1 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 51 | 251 | 251 | 849 | 0 | 1 | raw | dispersion x4.9 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 7d | 2133 | 4861 | 1744 | 849 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | au-dela-7d | 2557 | 3306 | 3306 | 809 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 2105 | 3245 | 2171 | 851 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 3.5 | 12 | 12 | 867 | 0 | 1 | raw | dispersion x3.3 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 2.1 | 17 | 17 | 867 | 0 | 1 | raw | dispersion x8.3 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 7d | 2.1 | 3.0 | 1.5 | 867 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | au-dela-7d | 2.1 | 3.1 | 2.1 | 867 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | 1.4 | 1.8 | 1.7 | 867 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 0.8 | 58 | 58 | 116 | 0 | 1 | raw | dispersion x69.8 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 0.8 | 1.0 | 0.7 | 116 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 7d | 0.9 | 1.3 | 0.9 | 116 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | au-dela-7d | 0.7 | 0.8 | 0.8 | 116 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 1.0 | 1.2 | 1.2 | 116 | 0 | 1 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 3.3 | 18 | 18 | 496 | 0 | 3 | raw | dispersion x5.5 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 309 | 342 | 339 | 496 | 0 | 18 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 7d | 2554 | 3148 | 3148 | 496 | 0 | 100 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | au-dela-7d | 1625 | 2716 | 2281 | 713 | 0 | 100 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 1601 | 2489 | 1246 | 722 | 0 | 100 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 2.1 | 42 | 42 | 722 | 0 | 1 | raw | dispersion x20.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 25 | 294 | 294 | 722 | 0 | 1 | raw | dispersion x11.8 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 7d | 1792 | 2710 | 1291 | 722 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | au-dela-7d | 1487 | 2638 | 2638 | 673 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | 1512 | 2524 | 1979 | 673 | 0 | 1 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 1h | 2.2 | 2.8 | 2.2 | 809 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 24h | 2.2 | 3.0 | 1.4 | 809 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 7d | 2.1 | 3.2 | 1.5 | 809 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | au-dela-7d | 2.2 | 3.1 | 1.9 | 809 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | all | 1.9 | 2.8 | 1.8 | 809 | 0 | 200 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 1h | 1.2 | 9.6 | 9.6 | 851 | 0 | 1 | raw | dispersion x7.7 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 24h | 7.5 | 78 | 78 | 851 | 0 | 1 | raw | dispersion x10.3 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 7d | 7.8 | 8.3 | 7.7 | 851 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | au-dela-7d | 7.9 | 8.3 | 8.3 | 851 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | all | 1.5 | 1.7 | 1.6 | 851 | 0 | 1 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 1h | 2.2 | 2.5 | 1.9 | 851 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 24h | 327 | 1039 | 439 | 851 | 0 | 50 | raw | dispersion x3.2 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 7d | 10.9 s | 12.0 s | 12.0 s | 850 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | au-dela-7d | 8973 | 10.9 s | 8788 | 867 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | all | 54 | 172 | 172 | 867 | 0 | 50 | raw | dispersion x3.2 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 1h | 1.2 | 12 | 12 | 867 | 0 | 5 | raw | dispersion x10.0 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 24h | 12 | 150 | 150 | 867 | 0 | 200 | raw | dispersion x12.4 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 7d | 9.4 | 107 | 107 | 867 | 0 | 200 | raw | dispersion x11.3 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | au-dela-7d | 10.0 | 12 | 10.0 | 867 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | all | 12 | 13 | 12 | 867 | 0 | 200 | raw |  |

## Résultats — `temoin-bis@0.6M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`bin:72c367a16a91f06a construit:2026-08-03T06:02:47Z (HEAD au rendu: 77600da — indicatif, l'arbre bouge)`, 600 003 événements, base 656 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**33 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 1.0 | 6.6 | 6.6 | 357 | 0 | 1 | raw | dispersion x6.6 (loadavg 8) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 8.7 | 140 | 140 | 388 | 0 | 1 | raw | dispersion x16.2 (loadavg 8) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 7d | 548 | 662 | 662 | 415 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | au-dela-7d | 1751 | 1866 | 1866 | 463 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 1221 | 1446 | 1213 | 550 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 1.4 | 33 | 33 | 312 | 0 | 1 | raw | dispersion x24.1 (loadavg 8) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 5.9 | 269 | 213 | 312 | 0 | 1 | raw | dispersion x45.6 (loadavg 8) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 7d | 30 | 1018 | 1018 | 312 | 0 | 1 | raw | dispersion x34.0 (loadavg 8) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | au-dela-7d | 1116 | 2514 | 2514 | 312 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 1578 | 2382 | 1835 | 484 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 2.3 | 6.3 | 6.3 | 484 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 31 | 169 | 169 | 484 | 0 | 1 | raw | dispersion x5.5 (loadavg 8) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 7d | 2000 | 4366 | 1959 | 484 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | au-dela-7d | 1339 | 2280 | 2280 | 534 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 1539 | 2506 | 1217 | 580 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 2.9 | 16 | 16 | 537 | 0 | 1 | raw | dispersion x5.7 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 283 | 336 | 336 | 537 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 7d | 1894 | 3142 | 1603 | 537 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | au-dela-7d | 1932 | 3119 | 2524 | 535 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 1672 | 2982 | 2826 | 534 | 0 | 1 | raw |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 79 | 85 | 85 | 534 | 0 | 3 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 1.4 | 11 | 11 | 534 | 0 | 18 | scan | dispersion x8.0 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 7d | 2.1 | 2.7 | 2.7 | 534 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | au-dela-7d | 2.3 | 2.8 | 2.7 | 534 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 2.3 | 2.6 | 2.6 | 534 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 2.9 | 29 | 29 | 415 | 0 | 50 | raw | dispersion x9.8 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 273 | 345 | 345 | 415 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 7d | 3456 | 4090 | 3080 | 624 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | au-dela-7d | 5179 | 5378 | 5378 | 606 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 4706 | 6249 | 4706 | 621 | 0 | 50 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 3.3 | 7.6 | 7.6 | 621 | 0 | 33 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 17 | 51 | 26 | 621 | 0 | 50 | rollup | dispersion x3.0 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 7d | 157 | 393 | 252 | 621 | 0 | 59 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | au-dela-7d | 330 | 1531 | 1531 | 415 | 0 | 65 | rollup | dispersion x4.6 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 420 | 598 | 598 | 415 | 0 | 68 | rollup |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 7.9 | 36 | 36 | 415 | 0 | 50 | raw | dispersion x4.5 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 336 | 930 | 930 | 415 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 7d | 2253 | 5258 | 5258 | 590 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | au-dela-7d | 8737 | 8967 | 8192 | 697 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 3894 | 4345 | 3894 | 535 | 0 | 50 | raw |  |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 4.3 | 93 | 93 | 554 | 0 | 200 | raw | dispersion x21.5 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 16 | 357 | 357 | 554 | 0 | 200 | raw | dispersion x22.3 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 7d | 18 | 416 | 303 | 766 | 0 | 200 | raw | dispersion x23.5 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | au-dela-7d | 5.4 | 32 | 32 | 766 | 0 | 200 | raw | dispersion x6.0 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 2.4 | 3.9 | 3.9 | 766 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 3.8 | 21 | 21 | 767 | 0 | 0 | raw | dispersion x5.6 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 449 | 928 | 644 | 767 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 7d | 1117 | 3074 | 3074 | 584 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | au-dela-7d | 56 | 922 | 922 | 620 | 0 | 200 | raw | dispersion x16.4 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 34 | 61 | 34 | 620 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 3.2 | 4.0 | 3.7 | 620 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 4.3 | 4.9 | 4.1 | 620 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 7d | 3.9 | 4.9 | 4.9 | 620 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | au-dela-7d | 3.4 | 7.4 | 7.4 | 620 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 3.3 | 4.2 | 3.3 | 620 | 0 | 200 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 2.2 | 3.0 | 2.2 | 620 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 34 | 172 | 172 | 620 | 0 | 1 | raw | dispersion x5.1 (loadavg 7) — p95 dominé par la contention, pas par plume |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 7d | 2213 | 4272 | 734 | 755 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | au-dela-7d | 1870 | 3210 | 2149 | 755 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 1788 | 3061 | 1708 | 750 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 2.8 | 13 | 13 | 535 | 0 | 1 | raw | dispersion x4.7 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 316 | 344 | 344 | 535 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 7d | 2776 | 3727 | 3727 | 718 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | au-dela-7d | 2220 | 3307 | 2221 | 718 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 2194 | 3319 | 3319 | 744 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 2.7 | 22 | 22 | 744 | 0 | 1 | raw | dispersion x8.1 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 2.4 | 29 | 29 | 744 | 0 | 1 | raw | dispersion x12.4 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 7d | 2.0 | 2.8 | 2.8 | 744 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | au-dela-7d | 2.3 | 3.0 | 3.0 | 744 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | 1.1 | 1.5 | 1.5 | 744 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 0.8 | 52 | 52 | 357 | 0 | 1 | raw | dispersion x62.3 (loadavg 8) — p95 dominé par la contention, pas par plume |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 0.7 | 0.8 | 0.8 | 357 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 7d | 0.9 | 2.3 | 1.6 | 357 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | au-dela-7d | 0.6 | 0.7 | 0.7 | 357 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 0.9 | 1.1 | 0.9 | 357 | 0 | 1 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 2.6 | 16 | 16 | 534 | 0 | 3 | raw | dispersion x6.1 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 61 | 297 | 297 | 534 | 0 | 18 | raw | dispersion x4.9 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 7d | 1780 | 4234 | 1780 | 563 | 0 | 100 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | au-dela-7d | 1441 | 2403 | 1780 | 612 | 0 | 100 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 1373 | 2483 | 1317 | 425 | 0 | 100 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 1.9 | 6.2 | 6.2 | 415 | 0 | 1 | raw | dispersion x3.2 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 33 | 133 | 133 | 415 | 0 | 1 | raw | dispersion x4.1 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 7d | 857 | 1939 | 946 | 617 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | au-dela-7d | 1317 | 1747 | 1281 | 617 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | 1435 | 2456 | 2250 | 631 | 0 | 1 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 1h | 2.2 | 2.8 | 2.4 | 620 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 24h | 2.1 | 2.7 | 2.1 | 620 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 7d | 2.4 | 2.6 | 2.5 | 620 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | au-dela-7d | 2.1 | 2.7 | 2.1 | 620 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | all | 1.9 | 2.4 | 1.8 | 620 | 0 | 200 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 1h | 1.4 | 12 | 12 | 744 | 0 | 1 | raw | dispersion x8.2 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 24h | 8.7 | 88 | 88 | 744 | 0 | 1 | raw | dispersion x10.2 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 7d | 7.8 | 8.2 | 7.9 | 744 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | au-dela-7d | 6.9 | 7.6 | 7.3 | 744 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | all | 1.1 | 1.5 | 1.1 | 744 | 0 | 1 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 1h | 1.8 | 2.8 | 1.8 | 744 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 24h | 30 | 204 | 204 | 744 | 0 | 50 | raw | dispersion x6.8 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 7d | 8276 | 9588 | 7580 | 744 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | au-dela-7d | 9969 | 10.6 s | 10.6 s | 733 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | all | 52 | 285 | 285 | 534 | 0 | 50 | raw | dispersion x5.5 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 1h | 2.1 | 17 | 17 | 534 | 0 | 5 | raw | dispersion x8.2 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 24h | 451 | 640 | 244 | 717 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 7d | 15 | 540 | 248 | 744 | 0 | 200 | raw | dispersion x36.3 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | au-dela-7d | 15 | 17 | 16 | 744 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | all | 13 | 16 | 16 | 744 | 0 | 200 | raw |  |

## Résultats — `taille-grande@0.6M`

*`PLUME_FTS_FIELDS`=0, masquage=vide, froid=off, version=`bin:72c367a16a91f06a construit:2026-08-03T06:02:47Z (HEAD au rendu: 77600da — indicatif, l'arbre bouge)`, 600 003 événements, base 1039 Mio.*

Latences en millisecondes (mur, côté client), sauf mention `s`. `RSS` = crête réelle du
processus échantillonnée à 15 ms pendant la requête. `lu` = octets lus au bloc par le
processus (0 = servi depuis le cache de pages).


**29 cellules de ce tableau ont une dispersion `p95/p50` supérieure à 3.** Sur une machine partagée, cela ne décrit pas plume : cela décrit le fait que la mesure a été bousculée par les autres travaux. Ces cellules sont annotées ; leur `p50` reste utilisable, leur `p95` non.

**Ce que `p95` vaut ici** : 3, 7 répétitions par cellule (le harnais retombe à 3 quand le premier tir dépasse 3 s, pour que la matrice tienne). À ce nombre d'échantillons, `p95` par rang le plus proche **est le maximum observé** : c'est une borne haute sur un tout petit échantillon, pas une vraie queue de distribution. Le lire comme « le pire des N tirs », rien de plus.

| Classe | Fenêtre | p50 | p95 | 1er tir | RSS crête | lu | lignes | route | note |
|---|:--:|---:|---:|---:|---:|---:|---:|---|---|
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 1h | 1.5 | 24 | 24 | 116 | 0 | 1 | raw | dispersion x15.8 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 24h | 6.4 | 330 | 330 | 149 | 0 | 1 | raw | dispersion x51.4 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | 7d | 696 | 1984 | 1984 | 175 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | au-dela-7d | 2097 | 4468 | 4468 | 175 | 0 | 1 | raw |  |
| `C1-scan-agg` <br><sub>scan filtré + agrégat (source + severity)</sub> | all | 1962 | 2874 | 1468 | 572 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 1h | 1.1 | 25 | 25 | 397 | 0 | 1 | raw | dispersion x22.3 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 24h | 217 | 425 | 220 | 397 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | 7d | 417 | 1026 | 1026 | 344 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | au-dela-7d | 1298 | 3120 | 3120 | 344 | 0 | 1 | raw |  |
| `C1b-scan-agg-dc` <br><sub>scan filtré + dc() sur colonne réelle</sub> | all | 2912 | 3080 | 3080 | 344 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 1h | 2.2 | 9.6 | 9.6 | 344 | 0 | 1 | raw | dispersion x4.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 24h | 228 | 364 | 228 | 502 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | 7d | 2676 | 5410 | 5410 | 502 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | au-dela-7d | 4158 | 4649 | 4158 | 541 | 0 | 1 | raw |  |
| `C2-free-term` <br><sub>terme libre sur message (compile en LIKE '%…%')</sub> | all | 3021 | 4857 | 2651 | 658 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 1h | 39 | 58 | 58 | 455 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 24h | 358 | 995 | 995 | 455 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | 7d | 5194 | 5793 | 5194 | 609 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | au-dela-7d | 4137 | 4461 | 4137 | 612 | 0 | 1 | raw |  |
| `C2b-regex-msg` <br><sub>regex sur message (REGEXP, UDF Rust)</sub> | all | 3368 | 4938 | 2917 | 644 | 0 | 1 | raw |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 1h | 148 | 164 | 164 | 443 | 0 | 0 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 24h | 1.5 | 15 | 15 | 443 | 0 | 22 | scan | dispersion x10.0 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | 7d | 3.0 | 3.7 | 3.7 | 443 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | au-dela-7d | 3.1 | 3.9 | 3.0 | 443 | 0 | 100 | scan |  |
| `C2c-fts-bar` <br><sub>MÊME aiguille via /api/search (FTS5 event_fts, 100 lignes)</sub> | all | 3.3 | 3.9 | 3.6 | 443 | 0 | 100 | scan |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 1h | 2.7 | 15 | 15 | 825 | 0 | 50 | raw | dispersion x5.6 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 24h | 326 | 959 | 299 | 825 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | 7d | 6787 | 7645 | 6787 | 729 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | au-dela-7d | 8631 | 8728 | 8631 | 815 | 0 | 50 | raw |  |
| `C3-groupby-hi` <br><sub>group-by 3 dims haute cardinalité (src_ip,host,source)</sub> | all | 7618 | 9160 | 9160 | 815 | 0 | 50 | raw |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 1h | 2.0 | 11 | 11 | 627 | 0 | 32 | raw | dispersion x5.4 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 24h | 16 | 33 | 33 | 627 | 0 | 50 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | 7d | 108 | 239 | 239 | 627 | 0 | 59 | rollup |  |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | au-dela-7d | 349 | 1389 | 1389 | 627 | 0 | 69 | rollup | dispersion x4.0 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C3b-groupby-routable` <br><sub>group-by 2 dims ROUTABLE en rollup (source,severity)</sub> | all | 494 | 645 | 645 | 816 | 0 | 71 | rollup |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 1h | 5.6 | 7.1 | 5.5 | 816 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 24h | 1089 | 1235 | 1132 | 816 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | 7d | 6346 | 6535 | 6346 | 783 | 0 | 50 | raw | **pris sous swap — à rejouer** |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | au-dela-7d | 13.3 s | 13.6 s | 13.3 s | 784 | 0 | 50 | raw |  |
| `C3c-groupby-json` <br><sub>group-by sur champ ÉTENDU indexé (action) + colonne</sub> | all | 6608 | 6874 | 6874 | 827 | 0 | 50 | raw | **pris sous swap — à rejouer** |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 1h | 3.4 | 24 | 24 | 627 | 0 | 200 | raw | dispersion x6.9 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 24h | 13 | 174 | 174 | 627 | 0 | 200 | raw | dispersion x13.6 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | 7d | 13 | 193 | 193 | 627 | 0 | 200 | raw | dispersion x15.1 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | au-dela-7d | 6.1 | 91 | 91 | 627 | 0 | 200 | raw | dispersion x15.0 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4-raw-page1` <br><sub>RAW paginé page 1 (limit 200, offset 0)</sub> | all | 2.6 | 3.1 | 3.1 | 627 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 1h | 2.4 | 17 | 17 | 627 | 0 | 0 | raw | dispersion x7.0 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 24h | 174 | 323 | 323 | 627 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | 7d | 1823 | 3653 | 1986 | 913 | 0 | 0 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | au-dela-7d | 1058 | 2080 | 1513 | 972 | 0 | 200 | raw |  |
| `C4b-raw-deep` <br><sub>RAW paginé page profonde (offset 200 000)</sub> | all | 829 | 1570 | 829 | 1000 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 1h | 4.3 | 31 | 31 | 777 | 0 | 200 | raw | dispersion x7.3 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 24h | 3.2 | 4.4 | 3.2 | 777 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | 7d | 4.2 | 4.8 | 4.8 | 777 | 0 | 200 | raw |  |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | au-dela-7d | 4.3 | 16 | 16 | 777 | 0 | 200 | raw | dispersion x3.7 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C4c-raw-keyset` <br><sub>RAW paginé en keyset (curseur, sans offset)</sub> | all | 4.5 | 5.1 | 5.1 | 777 | 0 | 200 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 1h | 2.4 | 19 | 19 | 777 | 0 | 1 | raw | dispersion x8.1 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 24h | 367 | 771 | 771 | 777 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | 7d | 4666 | 5733 | 4666 | 978 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | au-dela-7d | 4351 | 4822 | 4351 | 946 | 0 | 1 | raw |  |
| `C5-regex-json-planted` <br><sub>regex sur champ ÉTENDU planté (fields.needle)</sub> | all | 3011 | 4867 | 2833 | 956 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 1h | 4.5 | 32 | 32 | 777 | 0 | 1 | raw | dispersion x7.2 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 24h | 346 | 392 | 328 | 837 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | 7d | 3190 | 6122 | 3190 | 976 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | au-dela-7d | 4791 | 5585 | 5585 | 971 | 0 | 1 | raw |  |
| `C5b-regex-json-cold` <br><sub>regex sur champ ÉTENDU NON indexé (fields.object)</sub> | all | 4455 | 5580 | 5580 | 777 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 1h | 2.8 | 13 | 13 | 776 | 0 | 1 | raw | dispersion x4.6 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 24h | 3.3 | 32 | 32 | 776 | 0 | 1 | raw | dispersion x9.8 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | 7d | 3.0 | 3.9 | 2.2 | 776 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | au-dela-7d | 3.6 | 4.3 | 4.3 | 776 | 0 | 1 | raw |  |
| `C5c-eq-json-hot` <br><sub>égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)</sub> | all | 0.9 | 1.1 | 0.9 | 776 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 1h | 1.3 | 68 | 68 | 114 | 0 | 1 | raw | dispersion x52.8 (loadavg 4) — p95 dominé par la contention, pas par plume |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 24h | 1.0 | 1.1 | 1.1 | 114 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | 7d | 0.8 | 0.9 | 0.9 | 114 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | au-dela-7d | 0.8 | 1.0 | 0.8 | 114 | 0 | 1 | raw |  |
| `C0-plancher` <br><sub>PLANCHER : seek sur une source inexistante (0 ligne)</sub> | all | 0.7 | 0.9 | 0.9 | 114 | 0 | 1 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 1h | 2.6 | 14 | 14 | 443 | 0 | 0 | raw | dispersion x5.5 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 24h | 355 | 1047 | 284 | 443 | 0 | 22 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | 7d | 2603 | 5015 | 5015 | 628 | 0 | 100 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | au-dela-7d | 3281 | 4418 | 4418 | 662 | 0 | 100 | raw |  |
| `C2d-free-term-rows` <br><sub>MÊME aiguille en GXQL rendant des LIGNES (comparable à /api/search)</sub> | all | 2915 | 4702 | 2558 | 870 | 0 | 100 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 1h | 2.2 | 14 | 14 | 870 | 0 | 1 | raw | dispersion x6.4 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 24h | 45 | 300 | 300 | 870 | 0 | 1 | raw | dispersion x6.6 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | 7d | 4785 | 5177 | 1842 | 827 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | au-dela-7d | 3199 | 4470 | 4470 | 627 | 0 | 1 | raw |  |
| `C2e-free-term-common` <br><sub>terme libre PEU sélectif (1 ligne sur 10) en LIKE</sub> | all | 2677 | 4887 | 4887 | 825 | 0 | 1 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 1h | 2.9 | 4.2 | 2.1 | 777 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 24h | 2.5 | 3.0 | 3.0 | 777 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | 7d | 2.9 | 3.7 | 2.0 | 777 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | au-dela-7d | 3.0 | 3.7 | 3.0 | 777 | 0 | 200 | raw |  |
| `C4d-keyset-projete` <br><sub>keyset DEMANDÉ sur un pipeline PROJETÉ (| table)</sub> | all | 2.5 | 2.8 | 2.8 | 777 | 0 | 200 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 1h | 1.9 | 21 | 21 | 776 | 0 | 1 | raw | dispersion x11.2 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 24h | 11 | 302 | 302 | 776 | 0 | 1 | raw | dispersion x27.7 (loadavg 6) — p95 dominé par la contention, pas par plume |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | 7d | 8.3 | 10 | 8.7 | 776 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | au-dela-7d | 7.3 | 11 | 7.3 | 776 | 0 | 1 | raw |  |
| `C6-filter-host` <br><sub>filtre sur UN hôte (idx_event_host, sélectivité 1/N)</sub> | all | 1.2 | 1.6 | 1.5 | 776 | 0 | 1 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 1h | 1.5 | 3.9 | 3.9 | 776 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 24h | 280 | 333 | 333 | 776 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | 7d | 10.5 s | 11.2 s | 10.5 s | 964 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | au-dela-7d | 11.6 s | 12.3 s | 6919 | 956 | 0 | 50 | raw |  |
| `C6b-groupby-host` <br><sub>group-by sur host (autant de groupes que de machines)</sub> | all | 51 | 239 | 239 | 776 | 0 | 50 | raw | dispersion x4.7 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 1h | 1.7 | 15 | 15 | 776 | 0 | 10 | raw | dispersion x8.7 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 24h | 16 | 170 | 170 | 776 | 0 | 200 | raw | dispersion x10.9 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | 7d | 12 | 190 | 190 | 776 | 0 | 200 | raw | dispersion x16.4 (loadavg 5) — p95 dominé par la contention, pas par plume |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | au-dela-7d | 13 | 16 | 13 | 776 | 0 | 200 | raw |  |
| `C6c-raw-one-host` <br><sub>RAW keyset d'UN hôte (« montre-moi cette machine »)</sub> | all | 13 | 14 | 14 | 776 | 0 | 200 | raw |  |

## Écart mesuré entre deux passes — `avant-leviers@1.4M` vs `apres-leviers@1.4M`

Comparaison `avant-leviers@1.4M` -> `apres-leviers@1.4M`, MÊME base, MÊME instrument, MÊME machine, passes consécutives. Les deux lignes sont des mesures ; le delta est leur soustraction, rien de plus.

**Ce qui a changé entre les deux passes** : deux correctifs du chemin de requête, mesurés ici. (1) La garde de budget attend désormais une CONDITION (condvar avec délai) au lieu de sonder un drapeau toutes les 50 ms : elle protège la même chose, au même seuil, avec la même interruption, mais elle ne QUANTIFIE plus la latence — auparavant toute lecture était arrondie au multiple de 50 ms supérieur, et la garde était jointe avant l'envoi de la réponse. Elle couvre les deux portes d'exécution : `run_on_conn` (/api/query) et `read_with_watchdog` (alertes, cases, fraîcheur, sources, /api/search). (2) L'applicabilité de la pagination par curseur est DÉRIVÉE des propriétés du wrap au lieu d'une liste de deux commandes, et un pipeline projeté (`| table`/`| fields`) est désormais servi par le curseur au lieu de retomber en silence sur l'OFFSET : c'est la cellule `C4d-keyset-projete`. Réserve de comparabilité : ces deux passes tournent sur la MÊME base, mais APRÈS le remplissage `event_fields_fts` de la phase 3 (base 1434 Mio contre 1263 Mio pour les tableaux `fts0-*@1.4M` ci-dessus) et sur une machine bien moins chargée. Elles sont comparables ENTRE ELLES ; elles ne sont pas comparables aux tableaux de la première référence. Cinq cellules vont dans l'autre sens (C1b/all +2.7 s, C5b/24h +632 ms, C5/all +467 ms, C2d/24h +252 ms) : sur ces quatre-là la colonne `SQL` bouge AUTANT que le mur, or les correctifs n'agissent QUE sur l'attente AUTOUR du SQL — ce sont donc des scans longs bousculés par la machine, et ils sont laissés tels quels.

Charge machine relevée : `loadavg` 2.9–5.5 pendant la passe AVANT, 2.8–3.5 pendant la passe APRÈS. Sur une machine partagée, un écart de quelques millisecondes ne prouve rien ; seuls les écarts francs sont exploitables, et les cellules dont la dispersion est annotée plus haut restent à lire avec la même réserve.

| Classe | Fenêtre | p50 avant | p50 après | delta | SQL avant | SQL après | route avant | route après |
|---|:--:|---:|---:|---:|---:|---:|---|---|
| `C0-plancher` | 1h | 51 ms | 0.6 ms | -50 ms | 0.1 ms | 0.1 ms | raw | raw |
| `C0-plancher` | 24h | 51 ms | 0.7 ms | -50 ms | 0.1 ms | 0.1 ms | raw | raw |
| `C0-plancher` | all | 51 ms | 0.7 ms | -50 ms | 0.1 ms | 0.0 ms | raw | raw |
| `C1-scan-agg` | 1h | 51 ms | 1.4 ms | -50 ms | 0.8 ms | 0.8 ms | raw | raw |
| `C1-scan-agg` | 24h | 51 ms | 18 ms | -33 ms | 20 ms | 17 ms | raw | raw |
| `C1-scan-agg` | all | 2.2 s | 2.0 s | -118 ms | 2.1 s | 2.0 s | raw | raw |
| `C1b-scan-agg-dc` | 1h | 51 ms | 1.0 ms | -50 ms | 0.5 ms | 0.3 ms | raw | raw |
| `C1b-scan-agg-dc` | 24h | 51 ms | 14 ms | -37 ms | 10 ms | 13 ms | raw | raw |
| `C1b-scan-agg-dc` | all | 2.0 s | 4.7 s | +2.7 s | 1959 ms | 4.7 s | raw | raw |
| `C2-free-term` | 1h | 51 ms | 2.4 ms | -49 ms | 2.4 ms | 1.7 ms | raw | raw |
| `C2-free-term` | 24h | 1002 ms | 59 ms | -943 ms | 660 ms | 58 ms | raw | raw |
| `C2-free-term` | all | 3.4 s | 2.6 s | -837 ms | 3.4 s | 2.6 s | raw | raw |
| `C2b-regex-msg` | 1h | 51 ms | 3.2 ms | -48 ms | 3.4 ms | 2.4 ms | raw | raw |
| `C2b-regex-msg` | 24h | 802 ms | 624 ms | -178 ms | 768 ms | 623 ms | raw | raw |
| `C2b-regex-msg` | all | 3.5 s | 3.2 s | -350 ms | 3.5 s | 3.1 s | raw | raw |
| `C2c-fts-bar` | 1h | 51 ms | 1.7 ms | -49 ms | — | — | — | — |
| `C2c-fts-bar` | 24h | 51 ms | 2.0 ms | -49 ms | — | — | — | — |
| `C2c-fts-bar` | all | 51 ms | 2.8 ms | -48 ms | — | — | — | — |
| `C2d-free-term-rows` | 1h | 51 ms | 5.1 ms | -46 ms | 5.1 ms | 4.3 ms | raw | raw |
| `C2d-free-term-rows` | 24h | 702 ms | 954 ms | +252 ms | 689 ms | 936 ms | raw | raw |
| `C2d-free-term-rows` | all | 2.8 s | 2.6 s | -156 ms | 216 ms | 204 ms | raw | raw |
| `C2e-free-term-common` | 1h | 51 ms | 3.5 ms | -47 ms | 2.3 ms | 2.7 ms | raw | raw |
| `C2e-free-term-common` | 24h | 702 ms | 597 ms | -105 ms | 682 ms | 596 ms | raw | raw |
| `C2e-free-term-common` | all | 3.4 s | 2.7 s | -661 ms | 2.8 s | 2.7 s | raw | raw |
| `C3-groupby-hi` | 1h | 51 ms | 3.5 ms | -48 ms | 3.5 ms | 2.7 ms | raw | raw |
| `C3-groupby-hi` | 24h | 702 ms | 624 ms | -78 ms | 664 ms | 623 ms | raw | raw |
| `C3-groupby-hi` | all | 14.7 s | 13.9 s | -776 ms | 14.7 s | 13.9 s | raw | raw |
| `C3b-groupby-routable` | 1h | 101 ms | 2.8 ms | -98 ms | 68 ms | 2.0 ms | raw | raw |
| `C3b-groupby-routable` | 24h | 51 ms | 7.8 ms | -43 ms | 13 ms | 7.0 ms | rollup | rollup |
| `C3b-groupby-routable` | all | 201 ms | 130 ms | -71 ms | 192 ms | 129 ms | rollup | rollup |
| `C3c-groupby-json` | 1h | 51 ms | 5.7 ms | -45 ms | 34 ms | 4.9 ms | raw | raw |
| `C3c-groupby-json` | 24h | 752 ms | 721 ms | -32 ms | 732 ms | 720 ms | raw | raw |
| `C3c-groupby-json` | all | 9.2 s | 8.1 s | -1087 ms | 6.4 s | 8.1 s | raw | raw |
| `C4-raw-page1` | 1h | 51 ms | 3.7 ms | -48 ms | 1.1 ms | 1.0 ms | raw | raw |
| `C4-raw-page1` | 24h | 51 ms | 12 ms | -40 ms | 1.2 ms | 1.2 ms | raw | raw |
| `C4-raw-page1` | all | 51 ms | 1.7 ms | -50 ms | 0.3 ms | 0.3 ms | raw | raw |
| `C4b-raw-deep` | 1h | 51 ms | 4.9 ms | -46 ms | 4.7 ms | 4.0 ms | raw | raw |
| `C4b-raw-deep` | 24h | 752 ms | 447 ms | -306 ms | 703 ms | 446 ms | raw | raw |
| `C4b-raw-deep` | all | 552 ms | 31 ms | -521 ms | 524 ms | 30 ms | raw | raw |
| `C4c-raw-keyset` | 1h | 52 ms | 2.3 ms | -50 ms | 0.9 ms | 0.6 ms | raw | raw |
| `C4c-raw-keyset` | 24h | 52 ms | 2.6 ms | -50 ms | 0.8 ms | 0.7 ms | raw | raw |
| `C4c-raw-keyset` | all | 53 ms | 3.5 ms | -49 ms | 1.0 ms | 0.8 ms | raw | raw |
| `C4d-keyset-projete` | 1h | 51 ms | 1.6 ms | -50 ms | 1.1 ms | 0.5 ms | raw | raw |
| `C4d-keyset-projete` | 24h | 52 ms | 1.4 ms | -50 ms | 1.3 ms | 0.4 ms | raw | raw |
| `C4d-keyset-projete` | all | 52 ms | 1.6 ms | -50 ms | 0.5 ms | 0.4 ms | raw | raw |
| `C5-regex-json-planted` | 1h | 51 ms | 3.6 ms | -47 ms | 5.1 ms | 2.9 ms | raw | raw |
| `C5-regex-json-planted` | 24h | 101 ms | 92 ms | -8.8 ms | 100 ms | 91 ms | raw | raw |
| `C5-regex-json-planted` | all | 4.8 s | 5.3 s | +467 ms | 4.8 s | 5.3 s | raw | raw |
| `C5b-regex-json-cold` | 1h | 51 ms | 7.8 ms | -43 ms | 5.9 ms | 6.6 ms | raw | raw |
| `C5b-regex-json-cold` | 24h | 201 ms | 834 ms | +632 ms | 173 ms | 833 ms | raw | raw |
| `C5b-regex-json-cold` | all | 6.1 s | 5.9 s | -190 ms | 6.1 s | 4.7 s | raw | raw |
| `C5c-eq-json-hot` | 1h | 71 ms | 2.4 ms | -69 ms | 41 ms | 1.7 ms | raw | raw |
| `C5c-eq-json-hot` | 24h | 51 ms | 2.3 ms | -49 ms | 2.9 ms | 1.6 ms | raw | raw |
| `C5c-eq-json-hot` | all | 51 ms | 0.8 ms | -50 ms | 0.3 ms | 0.2 ms | raw | raw |

54 cellules comparables. Une cellule non comparable n'est PAS un résultat neutre : elle est absente d'un côté.

## Écart mesuré entre deux passes — `chaud-seul@1.4M` vs `froid-actif@1.4M`

Comparaison `chaud-seul@1.4M` -> `froid-actif@1.4M`, MÊME base, MÊME instrument, MÊME machine, passes consécutives. Les deux lignes sont des mesures ; le delta est leur soustraction, rien de plus.

**Ce qui a changé entre les deux passes** : le tier froid, et rien d'autre. MÊME fichier de base, MÊME binaire, MÊME machine, passes consécutives : entre les deux, `plume-daemon retention` a columnarisé en Parquet les jours entièrement plus vieux que la fenêtre chaude (1 104 752 lignes sur 1 440 007, soit 76,7 %), et le daemon a été relancé avec `PLUME_COLD_TIER=1`. ATTENTION : 57 des 105 cellules froides rendent une réponse TRONQUÉE (le chemin d'union hydrate au plus `PLUME_QUERY_MAX`=5 000 lignes) — leur delta n'est PAS un écart de vitesse mais un écart de travail, et elles sont marquées comme telles dans le tableau. La sous-section « La réponse est-elle la MÊME ? » chiffre l'écart de contenu : jusqu'à x203 sur un simple `stats count`. CETTE PASSE DÉCRIT LE CODE D'AVANT LE CORRECTIF de troncature froide et elle est conservée pour cela : elle est la MESURE du défaut. La passe qui décrit le dépôt actuel est `chaud-seul-v2@1.4M` contre `froid-actif-v2@1.4M`, plus bas.

Charge machine relevée : `loadavg` 2.5–3.7 pendant la passe AVANT, 1.9–3.9 pendant la passe APRÈS. Sur une machine partagée, un écart de quelques millisecondes ne prouve rien ; seuls les écarts francs sont exploitables, et les cellules dont la dispersion est annotée plus haut restent à lire avec la même réserve.

| Classe | Fenêtre | p50 avant | p50 après | delta | SQL avant | SQL après | route avant | route après |
|---|:--:|---:|---:|---:|---:|---:|---|---|
| `C0-plancher` | 1h | 0.8 ms | 0.8 ms | +0.0 ms | 0.0 ms | 0.1 ms | raw | raw |
| `C0-plancher` | 24h | 0.7 ms | 0.7 ms | +0.0 ms | 0.1 ms | 0.1 ms | raw | raw |
| `C0-plancher` | 7d | 0.6 ms | 516 ms | +515 ms ⚠ **réponse tronquée d'un côté** | 0.1 ms | 0.8 ms | raw | — |
| `C0-plancher` | au-dela-7d | 0.6 ms | 1031 ms | +1031 ms ⚠ **réponse tronquée d'un côté** | 0.1 ms | 0.7 ms | raw | — |
| `C0-plancher` | all | 0.6 ms | 1032 ms | +1032 ms ⚠ **réponse tronquée d'un côté** | 0.0 ms | 0.6 ms | raw | — |
| `C1-scan-agg` | 1h | 1.2 ms | 1.2 ms | +0.0 ms | 0.5 ms | 0.5 ms | raw | raw |
| `C1-scan-agg` | 24h | 16 ms | 18 ms | +1.6 ms | 15 ms | 17 ms | raw | raw |
| `C1-scan-agg` | 7d | 1316 ms | 2.0 s | +708 ms ⚠ **réponse tronquée d'un côté** | 1315 ms | 1191 ms | raw | — |
| `C1-scan-agg` | au-dela-7d | 6.8 s | 1056 ms | -5.8 s ⚠ **réponse tronquée d'un côté** | 6.4 s | 0.7 ms | raw | — |
| `C1-scan-agg` | all | 4.6 s | 2.3 s | -2.3 s ⚠ **réponse tronquée d'un côté** | 4.6 s | 1187 ms | raw | — |
| `C1b-scan-agg-dc` | 1h | 1.0 ms | 1.0 ms | -0.0 ms | 0.3 ms | 0.3 ms | raw | raw |
| `C1b-scan-agg-dc` | 24h | 11 ms | 9.2 ms | -1.7 ms | 10 ms | 8.4 ms | raw | raw |
| `C1b-scan-agg-dc` | 7d | 839 ms | 1207 ms | +368 ms ⚠ **réponse tronquée d'un côté** | 838 ms | 677 ms | raw | — |
| `C1b-scan-agg-dc` | au-dela-7d | 2.4 s | 1069 ms | -1354 ms ⚠ **réponse tronquée d'un côté** | 2.4 s | 1.3 ms | raw | — |
| `C1b-scan-agg-dc` | all | 3.2 s | 1725 ms | -1484 ms ⚠ **réponse tronquée d'un côté** | 3.2 s | 664 ms | raw | — |
| `C2-free-term` | 1h | 3.3 ms | 2.1 ms | -1.2 ms | 2.2 ms | 1.4 ms | raw | raw |
| `C2-free-term` | 24h | 565 ms | 494 ms | -71 ms | 564 ms | 493 ms | raw | raw |
| `C2-free-term` | 7d | 7.9 s | 4.0 s | -4.0 s ⚠ **réponse tronquée d'un côté** | 7.5 s | 3.4 s | raw | — |
| `C2-free-term` | au-dela-7d | 3.4 s | 1084 ms | -2.3 s ⚠ **réponse tronquée d'un côté** | 3.4 s | 2.0 ms | raw | — |
| `C2-free-term` | all | 2.8 s | 4.9 s | +2.1 s ⚠ **réponse tronquée d'un côté** | 2.8 s | 3.8 s | raw | — |
| `C2b-regex-msg` | 1h | 3.0 ms | 2.9 ms | -0.1 ms | 2.2 ms | 2.0 ms | raw | raw |
| `C2b-regex-msg` | 24h | 635 ms | 540 ms | -96 ms | 634 ms | 538 ms | raw | raw |
| `C2b-regex-msg` | 7d | 5.7 s | 4.0 s | -1711 ms ⚠ **réponse tronquée d'un côté** | 5.7 s | 3.4 s | raw | — |
| `C2b-regex-msg` | au-dela-7d | 3.1 s | 1084 ms | -2.0 s ⚠ **réponse tronquée d'un côté** | 3.1 s | 3.9 ms | raw | — |
| `C2b-regex-msg` | all | 3.4 s | 4.5 s | +1168 ms ⚠ **réponse tronquée d'un côté** | 3.4 s | 3.5 s | raw | — |
| `C2c-fts-bar` | 1h | 3.1 ms | 1.2 ms | -1.9 ms | — | — | — | — |
| `C2c-fts-bar` | 24h | 3.1 ms | 1.5 ms | -1.6 ms | — | — | — | — |
| `C2c-fts-bar` | 7d | 3.2 ms | 2.2 ms | -0.9 ms | — | — | — | — |
| `C2c-fts-bar` | au-dela-7d | 4.4 ms | 1.1 ms | -3.3 ms | — | — | — | — |
| `C2c-fts-bar` | all | 4.3 ms | 2.1 ms | -2.2 ms | — | — | — | — |
| `C2d-free-term-rows` | 1h | 7.4 ms | 4.2 ms | -3.2 ms | 6.4 ms | 3.2 ms | raw | raw |
| `C2d-free-term-rows` | 24h | 647 ms | 536 ms | -111 ms | 643 ms | 532 ms | raw | raw |
| `C2d-free-term-rows` | 7d | 4.3 s | 6.0 s | +1713 ms ⚠ **réponse tronquée d'un côté** | 1464 ms | 1147 ms | raw | — |
| `C2d-free-term-rows` | au-dela-7d | 3.3 s | 1091 ms | -2.2 s ⚠ **réponse tronquée d'un côté** | 328 ms | 1.9 ms | raw | — |
| `C2d-free-term-rows` | all | 3.3 s | 5.7 s | +2.4 s ⚠ **réponse tronquée d'un côté** | 201 ms | 1077 ms | raw | — |
| `C2e-free-term-common` | 1h | 3.6 ms | 2.4 ms | -1.3 ms | 2.7 ms | 1.6 ms | raw | raw |
| `C2e-free-term-common` | 24h | 665 ms | 504 ms | -161 ms | 664 ms | 503 ms | raw | raw |
| `C2e-free-term-common` | 7d | 4.3 s | 5.3 s | +1045 ms ⚠ **réponse tronquée d'un côté** | 4.3 s | 4.8 s | raw | — |
| `C2e-free-term-common` | au-dela-7d | 2.7 s | 1045 ms | -1705 ms ⚠ **réponse tronquée d'un côté** | 2.7 s | 2.3 ms | raw | — |
| `C2e-free-term-common` | all | 2.9 s | 4.5 s | +1554 ms ⚠ **réponse tronquée d'un côté** | 2.9 s | 3.4 s | raw | — |
| `C3-groupby-hi` | 1h | 8.4 ms | 3.4 ms | -5.1 ms | 7.7 ms | 2.5 ms | raw | raw |
| `C3-groupby-hi` | 24h | 659 ms | 547 ms | -112 ms | 656 ms | 546 ms | raw | raw |
| `C3-groupby-hi` | 7d | 7.3 s | 4.3 s | -2.9 s ⚠ **réponse tronquée d'un côté** | 7.3 s | 3.8 s | raw | — |
| `C3-groupby-hi` | au-dela-7d | 12.3 s | 1067 ms | -11.3 s ⚠ **réponse tronquée d'un côté** | 10.9 s | 6.4 ms | raw | — |
| `C3-groupby-hi` | all | 13.0 s | 5.1 s | -7.9 s ⚠ **réponse tronquée d'un côté** | 13.0 s | 4.0 s | raw | — |
| `C3b-groupby-routable` | 1h | 5.0 ms | 4.0 ms | -0.9 ms | 4.1 ms | 2.8 ms | raw | raw |
| `C3b-groupby-routable` | 24h | 16 ms | 7.8 ms | -8.7 ms | 16 ms | 6.9 ms | rollup | rollup |
| `C3b-groupby-routable` | 7d | 97 ms | 43 ms | -54 ms | 96 ms | 42 ms | rollup | rollup |
| `C3b-groupby-routable` | au-dela-7d | 150 ms | 808 ms | +658 ms | 149 ms | 807 ms | rollup | rollup |
| `C3b-groupby-routable` | all | 141 ms | 948 ms | +807 ms | 139 ms | 648 ms | rollup | rollup |
| `C3c-groupby-json` | 1h | 5.8 ms | 6.5 ms | +0.7 ms | 5.1 ms | 5.4 ms | raw | raw |
| `C3c-groupby-json` | 24h | 666 ms | 161 ms | -505 ms | 664 ms | 160 ms | raw | raw |
| `C3c-groupby-json` | 7d | 7.7 s | 6.0 s | -1665 ms ⚠ **réponse tronquée d'un côté** | 7.7 s | 5.4 s | raw | — |
| `C3c-groupby-json` | au-dela-7d | 21.3 s | 1083 ms | -20.3 s ⚠ **réponse tronquée d'un côté** | 21.3 s | 12 ms | raw | — |
| `C3c-groupby-json` | all | 8.0 s | 5.3 s | -2.7 s ⚠ **réponse tronquée d'un côté** | 8.0 s | 4.2 s | raw | — |
| `C4-raw-page1` | 1h | 4.7 ms | 2.8 ms | -1.9 ms | 1.5 ms | 0.9 ms | raw | raw |
| `C4-raw-page1` | 24h | 16 ms | 9.5 ms | -6.7 ms | 1.7 ms | 1.0 ms | raw | raw |
| `C4-raw-page1` | 7d | 19 ms | 666 ms | +647 ms ⚠ **réponse tronquée d'un côté** | 1.5 ms | 4.8 ms | raw | — |
| `C4-raw-page1` | au-dela-7d | 35 ms | 1110 ms | +1076 ms ⚠ **réponse tronquée d'un côté** | 2.6 ms | 0.4 ms | raw | — |
| `C4-raw-page1` | all | 2.9 ms | 1195 ms | +1193 ms ⚠ **réponse tronquée d'un côté** | 0.6 ms | 4.8 ms | raw | — |
| `C4b-raw-deep` | 1h | 5.8 ms | 5.2 ms | -0.6 ms | 4.2 ms | 4.3 ms | raw | raw |
| `C4b-raw-deep` | 24h | 448 ms | 342 ms | -106 ms | 447 ms | 340 ms | raw | raw |
| `C4b-raw-deep` | 7d | 2.9 s | 2.8 s | -102 ms ⚠ **réponse tronquée d'un côté** | 2.9 s | 2.2 s | raw | — |
| `C4b-raw-deep` | au-dela-7d | 434 ms | 1075 ms | +641 ms ⚠ **réponse tronquée d'un côté** | 433 ms | 0.6 ms | raw | — |
| `C4b-raw-deep` | all | 366 ms | 3.5 s | +3.1 s ⚠ **réponse tronquée d'un côté** | 345 ms | 2.3 s | raw | — |
| `C4c-raw-keyset` | 1h | 2.5 ms | 2.3 ms | -0.2 ms | 0.7 ms | 0.6 ms | raw | raw |
| `C4c-raw-keyset` | 24h | 2.3 ms | 2.3 ms | 0.0 ms | 0.6 ms | 0.6 ms | raw | raw |
| `C4c-raw-keyset` | 7d | 2.3 ms | 549 ms | +547 ms ⚠ **réponse tronquée d'un côté** | 0.6 ms | 15 ms | raw | — |
| `C4c-raw-keyset` | au-dela-7d | 2.4 ms | 1114 ms | +1112 ms ⚠ **réponse tronquée d'un côté** | 0.6 ms | 12 ms | raw | — |
| `C4c-raw-keyset` | all | 2.7 ms | 1096 ms | +1093 ms ⚠ **réponse tronquée d'un côté** | 0.7 ms | 17 ms | raw | — |
| `C4d-keyset-projete` | 1h | 1.6 ms | 1.7 ms | +0.1 ms | 0.5 ms | 0.4 ms | raw | raw |
| `C4d-keyset-projete` | 24h | 1.6 ms | 1.6 ms | +0.1 ms | 0.5 ms | 0.4 ms | raw | raw |
| `C4d-keyset-projete` | 7d | 1.5 ms | 544 ms | +543 ms ⚠ **réponse tronquée d'un côté** | 0.4 ms | 12 ms | raw | — |
| `C4d-keyset-projete` | au-dela-7d | 2.9 ms | 1065 ms | +1062 ms ⚠ **réponse tronquée d'un côté** | 0.9 ms | 7.6 ms | raw | — |
| `C4d-keyset-projete` | all | 1.6 ms | 1122 ms | +1120 ms ⚠ **réponse tronquée d'un côté** | 0.5 ms | 12 ms | raw | — |
| `C5-regex-json-planted` | 1h | 3.6 ms | 3.1 ms | -0.5 ms | 2.9 ms | 2.4 ms | raw | raw |
| `C5-regex-json-planted` | 24h | 635 ms | 492 ms | -143 ms | 634 ms | 491 ms | raw | raw |
| `C5-regex-json-planted` | 7d | 8.6 s | 4.1 s | -4.5 s ⚠ **réponse tronquée d'un côté** | 8.6 s | 3.6 s | raw | — |
| `C5-regex-json-planted` | au-dela-7d | 3.5 s | 1406 ms | -2.1 s ⚠ **réponse tronquée d'un côté** | 3.5 s | 4.5 ms | raw | — |
| `C5-regex-json-planted` | all | 3.7 s | 5.7 s | +2.1 s ⚠ **réponse tronquée d'un côté** | 3.7 s | 4.3 s | raw | — |
| `C5b-regex-json-cold` | 1h | 4.1 ms | 3.9 ms | -0.2 ms | 3.3 ms | 3.1 ms | raw | raw |
| `C5b-regex-json-cold` | 24h | 666 ms | 591 ms | -76 ms | 665 ms | 589 ms | raw | raw |
| `C5b-regex-json-cold` | 7d | 8.7 s | 4.7 s | -4.0 s ⚠ **réponse tronquée d'un côté** | 8.7 s | 4.2 s | raw | — |
| `C5b-regex-json-cold` | au-dela-7d | 6.3 s | 1090 ms | -5.2 s ⚠ **réponse tronquée d'un côté** | 6.3 s | 7.7 ms | raw | — |
| `C5b-regex-json-cold` | all | 5.7 s | 4.9 s | -793 ms ⚠ **réponse tronquée d'un côté** | 5.7 s | 3.9 s | raw | — |
| `C6-filter-host` | 1h | 3.1 ms | 1.7 ms | -1.4 ms | 2.1 ms | 0.9 ms | raw | raw |
| `C6-filter-host` | 24h | 604 ms | 503 ms | -101 ms | 603 ms | 502 ms | raw | raw |
| `C6-filter-host` | 7d | 275 ms | 597 ms | +322 ms ⚠ **réponse tronquée d'un côté** | 274 ms | 66 ms | raw | — |
| `C6-filter-host` | au-dela-7d | 266 ms | 1071 ms | +805 ms ⚠ **réponse tronquée d'un côté** | 265 ms | 0.7 ms | raw | — |
| `C6-filter-host` | all | 1.6 ms | 1138 ms | +1136 ms ⚠ **réponse tronquée d'un côté** | 0.8 ms | 64 ms | raw | — |
| `C6b-groupby-host` | 1h | 2.8 ms | 2.9 ms | +0.1 ms | 2.0 ms | 2.0 ms | raw | raw |
| `C6b-groupby-host` | 24h | 617 ms | 392 ms | -224 ms | 616 ms | 391 ms | raw | raw |
| `C6b-groupby-host` | 7d | 20.7 s | 4.2 s | -16.5 s ⚠ **réponse tronquée d'un côté** | 20.7 s | 3.7 s | raw | — |
| `C6b-groupby-host` | au-dela-7d | 20.7 s | 1078 ms | -19.7 s ⚠ **réponse tronquée d'un côté** | 20.7 s | 4.0 ms | raw | — |
| `C6b-groupby-host` | all | 99 ms | 4.6 s | +4.5 s ⚠ **réponse tronquée d'un côté** | 98 ms | 3.5 s | raw | — |
| `C6c-raw-one-host` | 1h | 2.0 ms | 1.8 ms | -0.2 ms | 1.2 ms | 1.1 ms | raw | raw |
| `C6c-raw-one-host` | 24h | 12 ms | 11 ms | -0.6 ms | 11 ms | 9.9 ms | raw | raw |
| `C6c-raw-one-host` | 7d | 258 ms | 589 ms | +331 ms ⚠ **réponse tronquée d'un côté** | 257 ms | 66 ms | raw | — |
| `C6c-raw-one-host` | au-dela-7d | 22 ms | 1068 ms | +1046 ms ⚠ **réponse tronquée d'un côté** | 21 ms | 0.8 ms | raw | — |
| `C6c-raw-one-host` | all | 22 ms | 1116 ms | +1094 ms ⚠ **réponse tronquée d'un côté** | 20 ms | 65 ms | raw | — |
| `C5c-eq-json-hot` | 1h | 2.7 ms | 1.1 ms | -1.6 ms | 1.9 ms | 0.4 ms | raw | raw |
| `C5c-eq-json-hot` | 24h | 2.3 ms | 1.2 ms | -1.1 ms | 1.6 ms | 0.4 ms | raw | raw |
| `C5c-eq-json-hot` | 7d | 3.1 ms | 540 ms | +537 ms ⚠ **réponse tronquée d'un côté** | 2.3 ms | 15 ms | raw | — |
| `C5c-eq-json-hot` | au-dela-7d | 3.0 ms | 1088 ms | +1086 ms ⚠ **réponse tronquée d'un côté** | 2.2 ms | 15 ms | raw | — |
| `C5c-eq-json-hot` | all | 0.8 ms | 1071 ms | +1070 ms ⚠ **réponse tronquée d'un côté** | 0.2 ms | 15 ms | raw | — |

**57 de ces lignes opposent des réponses de contenu DIFFÉRENT** (un côté tronque) : leur delta mesure un écart de travail, pas un écart de vitesse. Elles sont marquées.

105 cellules comparables. Une cellule non comparable n'est PAS un résultat neutre : elle est absente d'un côté.

## Écart mesuré entre deux passes — `chaud-seul-v2@1.4M` vs `froid-actif-v2@1.4M`

Comparaison `chaud-seul-v2@1.4M` -> `froid-actif-v2@1.4M`, MÊME base, MÊME instrument, MÊME machine, passes consécutives. Les deux lignes sont des mesures ; le delta est leur soustraction, rien de plus.

**Ce qui a changé entre les deux passes** : le tier froid APRÈS le correctif de troncature, sur les MÊMES copies de base et la MÊME machine que la passe précédente, avec le binaire post-correctif. Ce qui a changé dans le produit : (1) le routeur colonnaire est ARMÉ PAR DÉFAUT dès que le tier froid est actif — son défaut DORMANT était la cause mesurée du défaut : aucune des 105 cellules froides n'atteignait les kernels ; (2) la garde « ne router que ce que le chemin d'union rendrait à l'identique » ne s'applique plus aux AGRÉGATS — au-delà du plafond d'hydratation, le chemin d'union agrège sur un ÉCHANTILLON, et la parité avec un nombre faux n'est pas une vertu ; (3) aucune valeur DÉRIVÉE d'un ensemble tronqué ne peut plus être sérialisée (`cold_store/exactness.rs`) : à défaut de pouvoir la calculer exactement, le daemon REFUSE en nommant sa cause et la voie exacte (HTTP 422). RÉSULTAT MESURÉ : les cellules TRONQUÉES passent de 57 à 11, et les 11 restantes sont TOUTES des matérialisations (`| table` / pages brutes) — c'est-à-dire le cas légitime : des lignes vraies, en nombre incomplet, signalé. 24 cellules répondent désormais 422 : ce sont les formes que le moteur colonnaire ne sait pas calculer exactement (dc(), terme libre, champ JSON, group-by chevauchant la frontière). Une cellule 422 n'a pas de latence comparable : elle mesure un refus, pas un travail. ATTENTION à la lecture des deltas : une cellule qui passe de « tronquée » à « exacte » fait PLUS de travail qu'avant — un ralentissement y est le prix de la justesse, pas une régression.

Charge machine relevée : `loadavg` 2.6–3.8 pendant la passe AVANT, 1.5–5.2 pendant la passe APRÈS. Sur une machine partagée, un écart de quelques millisecondes ne prouve rien ; seuls les écarts francs sont exploitables, et les cellules dont la dispersion est annotée plus haut restent à lire avec la même réserve.

| Classe | Fenêtre | p50 avant | p50 après | delta | SQL avant | SQL après | route avant | route après |
|---|:--:|---:|---:|---:|---:|---:|---|---|
| `C0-plancher` | 1h | 0.7 ms | 0.8 ms | +0.0 ms | 0.1 ms | 0.1 ms | raw | raw |
| `C0-plancher` | 24h | 0.8 ms | 0.8 ms | -0.1 ms | 0.1 ms | 0.1 ms | raw | raw |
| `C0-plancher` | 7d | 0.7 ms | 575 ms | +574 ms | 0.1 ms | 574 ms | raw | cold-vectorized-merge |
| `C0-plancher` | au-dela-7d | 0.6 ms | 2.8 s | +2.8 s | 0.0 ms | 2.8 s | raw | cold-vectorized |
| `C0-plancher` | all | 0.6 ms | 3.2 s | +3.2 s | 0.0 ms | 3.2 s | raw | cold-vectorized-merge |
| `C1-scan-agg` | 1h | 1.4 ms | 1.3 ms | -0.0 ms | 0.6 ms | 0.6 ms | raw | raw |
| `C1-scan-agg` | 24h | 17 ms | 14 ms | -2.7 ms | 16 ms | 14 ms | raw | raw |
| `C1-scan-agg` | 7d | 1576 ms | 1851 ms | +276 ms | 1575 ms | 1850 ms | raw | cold-vectorized-merge |
| `C1-scan-agg` | au-dela-7d | 4.6 s | 2.9 s | -1690 ms | 4.6 s | 2.9 s | raw | cold-vectorized |
| `C1-scan-agg` | all | 5.1 s | 4.1 s | -1015 ms | 5.1 s | 4.1 s | raw | cold-vectorized-merge |
| `C1b-scan-agg-dc` | 1h | 77 ms | 1.0 ms | -76 ms | 14 ms | 0.3 ms | raw | raw |
| `C1b-scan-agg-dc` | 24h | 18 ms | 9.6 ms | -8.2 ms | 17 ms | 8.6 ms | raw | raw |
| `C2-free-term` | 1h | 2.8 ms | 2.4 ms | -0.4 ms | 2.1 ms | 1.6 ms | raw | raw |
| `C2-free-term` | 24h | 741 ms | 526 ms | -215 ms | 740 ms | 525 ms | raw | raw |
| `C2b-regex-msg` | 1h | 3.5 ms | 2.7 ms | -0.8 ms | 2.7 ms | 2.0 ms | raw | raw |
| `C2b-regex-msg` | 24h | 787 ms | 557 ms | -231 ms | 786 ms | 555 ms | raw | raw |
| `C2b-regex-msg` | 7d | 8.6 s | 4.2 s | -4.4 s | 8.2 s | 4.2 s | raw | cold-vectorized-merge |
| `C2b-regex-msg` | au-dela-7d | 4.9 s | 2.8 s | -2.1 s | 4.9 s | 2.8 s | raw | cold-vectorized |
| `C2b-regex-msg` | all | 4.0 s | 6.3 s | +2.3 s | 4.0 s | 6.3 s | raw | cold-vectorized-merge |
| `C2c-fts-bar` | 1h | 2.3 ms | 1.8 ms | -0.5 ms | — | — | — | — |
| `C2c-fts-bar` | 24h | 2.2 ms | 2.0 ms | -0.3 ms | — | — | — | — |
| `C2c-fts-bar` | 7d | 3.2 ms | 3.1 ms | -0.1 ms | — | — | — | — |
| `C2c-fts-bar` | au-dela-7d | 3.9 ms | 1.4 ms | -2.5 ms | — | — | — | — |
| `C2c-fts-bar` | all | 3.7 ms | 2.2 ms | -1.5 ms | — | — | — | — |
| `C2d-free-term-rows` | 1h | 5.4 ms | 4.4 ms | -1.0 ms | 4.5 ms | 3.5 ms | raw | raw |
| `C2d-free-term-rows` | 24h | 734 ms | 577 ms | -157 ms | 721 ms | 576 ms | raw | raw |
| `C2d-free-term-rows` | 7d | 6.8 s | 6.6 s | -284 ms ⚠ **réponse tronquée d'un côté** | 2.2 s | 1948 ms | raw | — |
| `C2d-free-term-rows` | au-dela-7d | 2.6 s | 1151 ms | -1467 ms ⚠ **réponse tronquée d'un côté** | 293 ms | 2.1 ms | raw | — |
| `C2d-free-term-rows` | all | 3.1 s | 5.7 s | +2.6 s ⚠ **réponse tronquée d'un côté** | 307 ms | 1143 ms | raw | — |
| `C2e-free-term-common` | 1h | 47 ms | 2.5 ms | -45 ms | 47 ms | 1.6 ms | raw | raw |
| `C2e-free-term-common` | 24h | 602 ms | 525 ms | -77 ms | 601 ms | 524 ms | raw | raw |
| `C3-groupby-hi` | 1h | 3.9 ms | 4.5 ms | +0.6 ms | 3.0 ms | 3.4 ms | raw | raw |
| `C3-groupby-hi` | 24h | 635 ms | 554 ms | -81 ms | 634 ms | 553 ms | raw | raw |
| `C3-groupby-hi` | au-dela-7d | 11.6 s | 4.1 s | -7.5 s | 11.6 s | 4.1 s | raw | cold-vectorized |
| `C3b-groupby-routable` | 1h | 3.1 ms | 3.0 ms | -0.1 ms | 2.2 ms | 2.1 ms | raw | raw |
| `C3b-groupby-routable` | 24h | 8.6 ms | 8.4 ms | -0.2 ms | 7.6 ms | 7.4 ms | rollup | rollup |
| `C3b-groupby-routable` | 7d | 46 ms | 46 ms | -0.7 ms | 46 ms | 45 ms | rollup | rollup |
| `C3b-groupby-routable` | au-dela-7d | 132 ms | 858 ms | +726 ms | 131 ms | 857 ms | rollup | rollup |
| `C3b-groupby-routable` | all | 141 ms | 873 ms | +733 ms | 140 ms | 872 ms | rollup | rollup |
| `C3c-groupby-json` | 1h | 6.2 ms | 6.0 ms | -0.2 ms | 5.3 ms | 5.0 ms | raw | raw |
| `C3c-groupby-json` | 24h | 698 ms | 653 ms | -45 ms | 697 ms | 652 ms | raw | raw |
| `C4-raw-page1` | 1h | 4.8 ms | 3.5 ms | -1.3 ms | 1.4 ms | 1.0 ms | raw | raw |
| `C4-raw-page1` | 24h | 15 ms | 9.7 ms | -5.6 ms | 1.2 ms | 0.9 ms | raw | raw |
| `C4-raw-page1` | 7d | 20 ms | 680 ms | +660 ms ⚠ **réponse tronquée d'un côté** | 1.8 ms | 4.9 ms | raw | — |
| `C4-raw-page1` | au-dela-7d | 3.0 ms | 1106 ms | +1103 ms ⚠ **réponse tronquée d'un côté** | 0.3 ms | 0.5 ms | raw | — |
| `C4-raw-page1` | all | 1.7 ms | 1296 ms | +1294 ms ⚠ **réponse tronquée d'un côté** | 0.4 ms | 5.3 ms | raw | — |
| `C4b-raw-deep` | 1h | 6.6 ms | 3.8 ms | -2.8 ms | 5.5 ms | 2.9 ms | raw | raw |
| `C4b-raw-deep` | 24h | 450 ms | 373 ms | -77 ms | 449 ms | 372 ms | raw | raw |
| `C4b-raw-deep` | 7d | 2.7 s | 3.1 s | +349 ms ⚠ **réponse tronquée d'un côté** | 2.7 s | 2.4 s | raw | — |
| `C4b-raw-deep` | au-dela-7d | 441 ms | 1189 ms | +748 ms ⚠ **réponse tronquée d'un côté** | 440 ms | 0.8 ms | raw | — |
| `C4b-raw-deep` | all | 254 ms | 3.5 s | +3.2 s ⚠ **réponse tronquée d'un côté** | 252 ms | 2.3 s | raw | — |
| `C4c-raw-keyset` | 1h | 8.0 ms | 3.6 ms | -4.3 ms | 6.1 ms | 0.7 ms | raw | raw |
| `C4c-raw-keyset` | 24h | 7.5 ms | 3.6 ms | -3.8 ms | 5.6 ms | 0.7 ms | raw | raw |
| `C4c-raw-keyset` | 7d | 7.4 ms | 3.9 ms | -3.5 ms | 5.5 ms | — | raw | — |
| `C4c-raw-keyset` | au-dela-7d | 9.1 ms | 626 ms | +617 ms | 7.0 ms | — | raw | — |
| `C4c-raw-keyset` | all | 8.4 ms | 3.3 ms | -5.2 ms | 6.3 ms | — | raw | — |
| `C4d-keyset-projete` | 1h | 6.7 ms | 1.9 ms | -4.8 ms | 5.4 ms | 0.5 ms | raw | raw |
| `C4d-keyset-projete` | 24h | 6.4 ms | 1.9 ms | -4.6 ms | 5.2 ms | 0.4 ms | raw | raw |
| `C4d-keyset-projete` | 7d | 6.4 ms | 2.3 ms | -4.2 ms | 5.2 ms | — | raw | — |
| `C4d-keyset-projete` | au-dela-7d | 6.5 ms | 1164 ms | +1158 ms ⚠ **réponse tronquée d'un côté** | 5.2 ms | 7.9 ms | raw | — |
| `C4d-keyset-projete` | all | 6.9 ms | 3.1 ms | -3.8 ms | 5.5 ms | — | raw | — |
| `C5-regex-json-planted` | 1h | 38 ms | 3.6 ms | -34 ms | 37 ms | 2.7 ms | raw | raw |
| `C5-regex-json-planted` | 24h | 601 ms | 446 ms | -155 ms | 600 ms | 445 ms | raw | raw |
| `C5b-regex-json-cold` | 1h | 4.6 ms | 4.0 ms | -0.6 ms | 3.7 ms | 3.2 ms | raw | raw |
| `C5b-regex-json-cold` | 24h | 688 ms | 595 ms | -93 ms | 687 ms | 594 ms | raw | raw |
| `C6-filter-host` | 1h | 2.5 ms | 1.8 ms | -0.7 ms | 1.7 ms | 1.0 ms | raw | raw |
| `C6-filter-host` | 24h | 600 ms | 506 ms | -94 ms | 598 ms | 505 ms | raw | raw |
| `C6-filter-host` | 7d | 259 ms | 654 ms | +395 ms | 258 ms | 653 ms | raw | cold-vectorized-merge |
| `C6-filter-host` | au-dela-7d | 27 ms | 2.7 s | +2.7 s | 26 ms | 2.7 s | raw | cold-vectorized |
| `C6-filter-host` | all | 3.3 ms | 3.0 s | +3.0 s | 2.5 ms | 3.0 s | raw | cold-vectorized-merge |
| `C6b-groupby-host` | 1h | 3.8 ms | 2.9 ms | -0.9 ms | 3.0 ms | 2.1 ms | raw | raw |
| `C6b-groupby-host` | 24h | 623 ms | 427 ms | -196 ms | 622 ms | 425 ms | raw | raw |
| `C6b-groupby-host` | au-dela-7d | 20.9 s | 2.8 s | -18.2 s | 19.5 s | 2.8 s | raw | cold-vectorized |
| `C6b-groupby-host` | all | 102 ms | 7.8 s | +7.7 s | 101 ms | 7.8 s | raw | cold-vectorized-merge |
| `C6c-raw-one-host` | 1h | 2.7 ms | 2.1 ms | -0.6 ms | 1.7 ms | 1.2 ms | raw | raw |
| `C6c-raw-one-host` | 24h | 13 ms | 11 ms | -1.4 ms | 11 ms | 9.9 ms | raw | raw |
| `C6c-raw-one-host` | 7d | 260 ms | 6.6 ms | -254 ms | 259 ms | — | raw | — |
| `C6c-raw-one-host` | au-dela-7d | 21 ms | 1181 ms | +1161 ms ⚠ **réponse tronquée d'un côté** | 19 ms | 1.0 ms | raw | — |
| `C6c-raw-one-host` | all | 21 ms | 7.2 ms | -13 ms | 19 ms | — | raw | — |
| `C5c-eq-json-hot` | 1h | 2.9 ms | 1.1 ms | -1.8 ms | 2.1 ms | 0.5 ms | raw | raw |
| `C5c-eq-json-hot` | 24h | 2.9 ms | 1.0 ms | -1.9 ms | 2.1 ms | 0.3 ms | raw | raw |

**11 de ces lignes opposent des réponses de contenu DIFFÉRENT** (un côté tronque) : leur delta mesure un écart de travail, pas un écart de vitesse. Elles sont marquées.

81 cellules comparables. Une cellule non comparable n'est PAS un résultat neutre : elle est absente d'un côté.

## Les fenêtres mesurées, et celles qui ne le sont pas

Les fenêtres ne sont pas choisies : elles sont DÉRIVÉES de deux paramètres du produit — la
fenêtre chaude (`PLUME_COLD_HOT_WINDOW_DAYS`, défaut **7 j**, `cold_store/aging.rs`) et la
rétention (`PLUME_RETENTION_DAYS`) — puis filtrées par l'étendue réelle du jeu de données.

| Fenêtre | Ce qu'elle mesure |
|---|---|
| `1h` | dernière heure |
| `24h` | dernier jour |
| `7d` | fenêtre chaude du produit (7 j) |
| `au-dela-7d` | au-delà de la fenêtre chaude (de -28 j à -7 j) |
| `all` | tout |

**Fenêtres écartées par la garde de couverture — donc NON MESURÉES** :

- `30d` (toute la rétention (30 j)) — le jeu ne fait que 28 j : cette fenêtre serait `tout` sous une étiquette de 30 j

Une fenêtre plus large que le jeu ne mesure pas ce que dit son étiquette : elle mesure
`tout` sous un autre nom. Le harnais refuse de la tirer plutôt que de publier une cellule
dont le titre serait faux. Pour l'obtenir, il faut un jeu qui la couvre — c'est-à-dire
remplir sur une étendue plus longue (`BENCH_SPAN_DAYS`), pas rendre la garde plus permissive.

## Le tier froid — mesuré

Avec une fenêtre chaude de 7 jours et une rétention de 365, `daemon/src/cold_store/` est
le chemin de lecture de **358 des 365 jours** d'une production. Les tableaux ci-dessus
tournent tous à `PLUME_COLD_TIER=0` : ils ne disent rien de ce chemin. Cette section est
la seule qui en parle, et elle ne parle que de ce qui a été tiré.

**Columnarisation mesurée** (chemin réel : `plume-daemon retention` -> `retention_run`
-> `cold_age_run`, fenêtre chaude 7 j) :

| | Avant | Après |
|---|---:|---:|
| Lignes CHAUDES (SQLite) | 1 440 007 | 335 255 |
| Base chaude | 1434 Mio | 1434 Mio |
| Tier froid (Parquet chiffré) | 0 Mio | 101 Mio en 22 fichiers |

**1 104 752 lignes (76.7 %) ont quitté SQLite pour le Parquet**, en 22 fichiers (un par jour). Le froid pèse **96 octets par événement** là où le chaud en occupait 1044 (table, index et FTS compris), soit **11x plus compact**.

> Durée : 2597 s = intervalle MESURÉ entre l'horodatage du premier et du dernier fichier Parquet écrit (22 fichiers, un par jour). La passe a ensuite été INTERROMPUE par un kill EXTÉRIEUR au produit pendant la phase de suppression du chaud, puis REPRISE par un second `plume-daemon retention` qui a terminé en ~90 s et rendu « rétention OK » : l'aging est repartite sans perte, ce qui est son contrat (deux phases, idempotent). La durée totale n'est donc PAS un débit de columnarisation propre, et n'est pas publiée comme tel.

### La réponse est-elle la MÊME ? (parité mesurée)

Une latence n'est comparable que si les deux chemins rendent la même réponse : un
chemin qui TRONQUE est plus rapide parce qu'il en fait moins. Cette sous-section ne
compare donc pas des temps, elle compare **les valeurs rendues**.

Méthode : MÊME base, deux copies : l'une columnarisée (PLUME_COLD_TIER=1, 335 255 lignes chaudes + 1 104 752 en Parquet), l'autre intacte (PLUME_COLD_TIER=0, 1 440 007 lignes chaudes). MÊME binaire, MÊME machine, MÊMES requêtes, MÊMES fenêtres. On compare LES VALEURS RENDUES, pas les temps : une latence n'est comparable que si la réponse l'est.

| Requête | Fenêtre | Sans tier froid | Avec tier froid | Écart | Tronqué ? |
|---|:--:|---:|---:|---:|:--:|
| `search source=auditd severity>=2 \| stats count` | au-dela-7d | **58 747** | **289** | x203.3 | **oui** (5 000 lignes hydratées) |
| `search source=auditd severity>=2 \| stats count` | all | **78 314** | **18 325** | x4.3 | **oui** (5 000 lignes hydratées) |

Le chemin d'union chaud∪froid hydrate le froid dans une table temporaire SQLite bornée
à `PLUME_QUERY_MAX` lignes (défaut **5 000**, `cold_store/reader.rs:130`) puis agrège
SUR CET ÉCHANTILLON. Le compte rendu n'est donc pas « approché » : il est **faux d'un
facteur qui dépend du volume de la fenêtre**. Le daemon le SIGNALE
(`stats.truncated=true`), mais un lecteur qui ne regarde que le nombre voit un nombre
faux. Toute latence « froide » de cette passe doit donc être lue avec sa colonne
« tronqué » : quand elle dit oui, la cellule mesure le temps d'une réponse INCOMPLÈTE,
et ne peut pas être comparée à la cellule chaude.

> Réserve : Une TROISIÈME requête a été tirée (`search | stats count by source,severity`, fenêtre au-dela-7d) : les deux côtés l'ont servie par la ROUTE DE ROLLUPS, sans troncature, mais leurs valeurs divergent d'un facteur ~6,6 (la copie intacte rend ~160 k événements au total, la columnarisée ~1,05 M — cette dernière étant cohérente avec le volume attendu de la fenêtre). Cette divergence N'EST PAS EXPLIQUÉE par cette mesure. Mécanisme candidat, à départager par une expérience dédiée : la fraîcheur d'`event_rollup`, que la boucle de rollups (120 s) et `retention_run` alimentent — le daemon de la copie intacte venait de démarrer, celui de la copie columnarisée tournait depuis 20 minutes ET avait vu passer un `retention_run` complet. Tant que ce n'est pas tranché, aucune conclusion n'est tirée de cette troisième requête.

### La réponse est-elle la MÊME ? (parité mesurée)

Une latence n'est comparable que si les deux chemins rendent la même réponse : un
chemin qui TRONQUE est plus rapide parce qu'il en fait moins. Cette sous-section ne
compare donc pas des temps, elle compare **les valeurs rendues**.

Méthode : AVANT le correctif. MÊME base 1 440 007 événements, deux copies : l'une columnarisée (PLUME_COLD_TIER=1, 335 255 lignes chaudes + 1 104 752 en 22 Parquet), l'autre intacte (PLUME_COLD_TIER=0). MÊME binaire pré-correctif (bin:0642474ceedfaf15), MÊME machine, MÊMES requêtes, MÊMES fenêtres — la matrice de measure.py, en entier.

| Verdict | n | ce qu'il signifie |
|---|---:|---|
| `same` | 52 | les deux côtés rendent la MÊME réponse. |
| `differs` | 4 | ils divergent **sans le dire** — un nombre faux, lisible et copiable. C'est LE cas grave. |
| `declared` | 49 | ils divergent et le côté froid le DIT (`truncated`, ou note de couverture). L'incomplétude devient une information. |
| `refused` | 0 | un côté REFUSE, avec un motif nommé. Une erreur vaut mieux qu'un nombre faux : c'est la position de repli, pas l'échec. |

`declared` n'acquitte rien : un AGRÉGAT tronqué reste un nombre faux, déclaré ou non.
Les catégories ne s'additionnent jamais en un « tout va bien ».

**Le compte qui compte : 36 NOMBRE(S) FAUX.** C'est le nombre de contrôles dont la
réponse porte une valeur calculée SUR L'ENSEMBLE (`count`/`dc`/`stats … by …`) et dont
les deux côtés DIVERGENT — que le côté froid l'ait déclaré ou non. C'est exactement ce
que l'invariant de `cold_store/exactness.rs` interdit. Les autres catégories décrivent
des réponses partielles de LIGNES (vraies, incomplètes, signalées) ou des refus motivés :
elles ne sont pas du même ordre de gravité.

> Comptage : Verdicts et compte de NOMBRES FAUX RE-DÉRIVÉS avec le classifieur courant à partir des réponses `hot`/`cold` STOCKÉES, qui sont la mesure. Sans ce re-dérivage, les deux passes seraient comptées par deux règles différentes et leur comparaison ne voudrait rien dire. Aucune réponse n'a été re-mesurée.

Le détail de tout ce qui n'est pas `same` :

| Requête | Fenêtre | Verdict | Sans tier froid | Avec tier froid |
|---|:--:|:--:|---|---|
| `search source=auditd severity>=2 \| stats count` | 7d | declared | **19 567** | **18 324** |
| `search source=auditd severity>=2 \| stats count` | au-dela-7d | declared | **58 747** | **289** |
| `search source=auditd severity>=2 \| stats count` | all | declared | **78 314** | **18 325** |
| `search anomalieplumebench \| stats count` | 7d | declared | **349** | **327** |
| `search anomalieplumebench \| stats count` | au-dela-7d | declared | **1 091** | **4** |
| `search anomalieplumebench \| stats count` | all | declared | **1 440** | **329** |
| `search message=~anomalieplumebench \| stats count` | 7d | declared | **349** | **327** |
| `search message=~anomalieplumebench \| stats count` | au-dela-7d | declared | **1 091** | **4** |
| `search message=~anomalieplumebench \| stats count` | all | declared | **1 440** | **329** |
| `anomalieplumebench` | au-dela-7d | differs | 200 lignes `9c78ce2c33bf372c` | 0 lignes `e3b0c44298fc1c14` |
| `search anomalieplumebench \| table ts,host,source,message` | 7d | declared | 100 lignes `f72ae12b4bdf55c8` | 100 lignes `f52dbc1c103e7f85` (tronqué) |
| `search anomalieplumebench \| table ts,host,source,message` | au-dela-7d | declared | 100 lignes `d3c813e56493a55b` | **[1782992260, 'bench-node-005.plume.invalid', 'auditd', 'anom** |
| `search anomalieplumebench \| table ts,host,source,message` | all | declared | 100 lignes `4d04f605e5553863` | 100 lignes `f52dbc1c103e7f85` (tronqué) |
| `search sessionplumebench \| stats count` | 7d | declared | **35 876** | **33 453** |
| `search sessionplumebench \| stats count` | au-dela-7d | declared | **108 124** | **522** |
| `search sessionplumebench \| stats count` | all | declared | **144 000** | **33 483** |
| `search \| stats count by src_ip,host,source \| sort -count \| head 50` | 7d | declared | 50 lignes `6d735a44351b289e` | 50 lignes `4a73c821813dae02` (tronqué) |
| `search \| stats count by src_ip,host,source \| sort -count \| head 50` | au-dela-7d | declared | 50 lignes `2637cadfbf7608b4` | 50 lignes `d383b75cef3723bb` (tronqué) |
| `search \| stats count by src_ip,host,source \| sort -count \| head 50` | all | declared | 50 lignes `d2e9e2128c6a20cc` | 50 lignes `1a5464f34cb8cdf9` (tronqué) |
| `search \| stats count by source,severity` | 7d | differs | 53 lignes `b4fd67245376834f` | 54 lignes `5f5ce15873df856a` |
| `search \| stats count by source,severity` | au-dela-7d | differs | 59 lignes `95d5cd07721e2ccb` | 68 lignes `0a0a8af58152d7df` |
| `search \| stats count by source,severity` | all | differs | 63 lignes `e6c1b918e4b588e4` | 70 lignes `f506e60be6f1cbe5` |
| `search \| stats count by action,source \| sort -count \| head 50` | 7d | declared | 50 lignes `6708bbab4feb00cc` | 50 lignes `ee961c139b6f5785` (tronqué) |
| `search \| stats count by action,source \| sort -count \| head 50` | au-dela-7d | declared | 50 lignes `5c1a9b1495ee34ed` | 50 lignes `0f837dfd59cec58b` (tronqué) |
| `search \| stats count by action,source \| sort -count \| head 50` | all | declared | 50 lignes `1a3cfe0fe89e163e` | 50 lignes `edc885712c330f1c` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | 7d | declared | 200 lignes `7751d804f61177dc` | 200 lignes `0a3a70ce8ec66dda` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | au-dela-7d | declared | 200 lignes `cc2a01764c203c24` | 200 lignes `ddd0ec415bcf020e` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | all | declared | 200 lignes `d9d46972d13b2c93` | 200 lignes `0a3a70ce8ec66dda` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | 7d | declared | 200 lignes `d2089c14727c0ea2` | 200 lignes `f404c5baffd5865c` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | au-dela-7d | declared | 200 lignes `bd8755d9328aa11c` | 0 lignes `e3b0c44298fc1c14` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | all | declared | 200 lignes `9ca430786fb9a4e3` | 200 lignes `f404c5baffd5865c` (tronqué) |
| `search severity>=1` | au-dela-7d | declared | 200 lignes `409b636e003ac087` | 200 lignes `47f3aee8c673c46b` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | 7d | declared | 200 lignes `7751d804f61177dc` | 200 lignes `0a3a70ce8ec66dda` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | au-dela-7d | declared | 200 lignes `cc2a01764c203c24` | 200 lignes `ddd0ec415bcf020e` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | all | declared | 200 lignes `d9d46972d13b2c93` | 200 lignes `0a3a70ce8ec66dda` (tronqué) |
| `search needle=~objetplumebench \| stats count` | 7d | declared | **720** | **678** |
| `search needle=~objetplumebench \| stats count` | au-dela-7d | declared | **2 160** | **15** |
| `search needle=~objetplumebench \| stats count` | all | declared | **2 880** | **688** |
| `search object=~[0-9a-f]{6}c \| stats count` | 7d | declared | **10 528** | **9 754** |
| `search object=~[0-9a-f]{6}c \| stats count` | au-dela-7d | declared | **31 768** | **140** |
| `search object=~[0-9a-f]{6}c \| stats count` | all | declared | **42 296** | **9 740** |
| `search host=bench-node-000.plume.invalid \| stats count` | 7d | declared | **5 627** | **5 232** |
| `search host=bench-node-000.plume.invalid \| stats count` | au-dela-7d | declared | **16 975** | **80** |
| `search host=bench-node-000.plume.invalid \| stats count` | all | declared | **22 602** | **5 226** |
| `search \| stats count by host \| sort -count \| head 50` | 7d | declared | 50 lignes `4069e45a545b631b` | 50 lignes `a05ee0ac24a382e9` (tronqué) |
| `search \| stats count by host \| sort -count \| head 50` | au-dela-7d | declared | 50 lignes `d3ecb66df15075e4` | 50 lignes `4dae3d99a8922ff8` (tronqué) |
| `search \| stats count by host \| sort -count \| head 50` | all | declared | 50 lignes `2c6e066ee6dba227` | 50 lignes `29c979051d2efbfa` (tronqué) |
| `search host=bench-node-000.plume.invalid \| table ts,host,source,severity,message` | 7d | declared | 200 lignes `71cfd0ff9d877633` | 200 lignes `e97410f213384eff` (tronqué) |
| `search host=bench-node-000.plume.invalid \| table ts,host,source,severity,message` | au-dela-7d | declared | 200 lignes `c5864ed3c1cdc04d` | 80 lignes `0e4d979290ef6378` (tronqué) |
| `search host=bench-node-000.plume.invalid \| table ts,host,source,severity,message` | all | declared | 200 lignes `94d07562922eb9ba` | 200 lignes `e97410f213384eff` (tronqué) |
| `search user=bench-user-0007 \| stats count` | 7d | declared | **650** | **602** |
| `search user=bench-user-0007 \| stats count` | au-dela-7d | declared | **2 075** | **7** |
| `search user=bench-user-0007 \| stats count` | all | declared | **2 725** | **599** |

**Écart maximal mesuré sur un agrégat scalaire** : `search user=bench-user-0007 | stats count` sur la fenêtre `au-dela-7d` rend **2 075** sans tier froid et **7** avec — soit **x296.4**. Ce n'est pas une réponse approchée, c'est un mauvais nombre : le
chemin d'union hydrate le froid dans une table temporaire SQLite bornée à
`PLUME_QUERY_MAX` lignes (défaut **5 000**, `cold_store/reader.rs:130`) puis agrège
SUR CET ÉCHANTILLON.

### La réponse est-elle la MÊME ? (parité mesurée)

Une latence n'est comparable que si les deux chemins rendent la même réponse : un
chemin qui TRONQUE est plus rapide parce qu'il en fait moins. Cette sous-section ne
compare donc pas des temps, elle compare **les valeurs rendues**.

Méthode : APRÈS le correctif. MÊME base 1 440 007 événements, deux copies : l'une columnarisée (PLUME_COLD_TIER=1, 335 255 lignes chaudes + 1 104 752 en 22 Parquet), l'autre intacte (PLUME_COLD_TIER=0). MÊME binaire post-correctif (bin:4bfcb9f76b4353a2), MÊME machine, MÊMES requêtes, MÊMES fenêtres — la matrice de measure.py en entier, produite par bench/parity.py (rejouable).

| Verdict | n | ce qu'il signifie |
|---|---:|---|
| `same` | 61 | les deux côtés rendent la MÊME réponse. |
| `differs` | 8 | ils divergent **sans le dire** — un nombre faux, lisible et copiable. C'est LE cas grave. |
| `declared` | 12 | ils divergent et le côté froid le DIT (`truncated`, ou note de couverture). L'incomplétude devient une information. |
| `refused` | 24 | un côté REFUSE, avec un motif nommé. Une erreur vaut mieux qu'un nombre faux : c'est la position de repli, pas l'échec. |

`declared` n'acquitte rien : un AGRÉGAT tronqué reste un nombre faux, déclaré ou non.
Les catégories ne s'additionnent jamais en un « tout va bien ».

**Le compte qui compte : 3 NOMBRE(S) FAUX.** C'est le nombre de contrôles dont la
réponse porte une valeur calculée SUR L'ENSEMBLE (`count`/`dc`/`stats … by …`) et dont
les deux côtés DIVERGENT — que le côté froid l'ait déclaré ou non. C'est exactement ce
que l'invariant de `cold_store/exactness.rs` interdit. Les autres catégories décrivent
des réponses partielles de LIGNES (vraies, incomplètes, signalées) ou des refus motivés :
elles ne sont pas du même ordre de gravité.

> Comptage : Verdicts et compte de NOMBRES FAUX RE-DÉRIVÉS avec le classifieur courant à partir des réponses `hot`/`cold` STOCKÉES, qui sont la mesure. Sans ce re-dérivage, les deux passes seraient comptées par deux règles différentes et leur comparaison ne voudrait rien dire. Aucune réponse n'a été re-mesurée.

Le détail de tout ce qui n'est pas `same` :

| Requête | Fenêtre | Verdict | Sans tier froid | Avec tier froid |
|---|:--:|:--:|---|---|
| `search source=k8s-log \| stats dc(host)` | 7d | refused | **64** | refus 422 |
| `search source=k8s-log \| stats dc(host)` | au-dela-7d | refused | **64** | refus 422 |
| `search source=k8s-log \| stats dc(host)` | all | refused | **64** | refus 422 |
| `search anomalieplumebench \| stats count` | 7d | refused | **349** | refus 422 |
| `search anomalieplumebench \| stats count` | au-dela-7d | refused | **1 091** | refus 422 |
| `search anomalieplumebench \| stats count` | all | refused | **1 440** | refus 422 |
| `anomalieplumebench` | au-dela-7d | declared | 200 lignes `9c78ce2c33bf372c` | 0 lignes `e3b0c44298fc1c14` (couverture déclarée) |
| `search anomalieplumebench \| table ts,host,source,message` | 7d | declared | 100 lignes `f72ae12b4bdf55c8` | 100 lignes `f52dbc1c103e7f85` (tronqué) |
| `search anomalieplumebench \| table ts,host,source,message` | au-dela-7d | declared | 100 lignes `d3c813e56493a55b` | **[1782992260, 'bench-node-005.plume.invalid', 'auditd', 'anom** |
| `search anomalieplumebench \| table ts,host,source,message` | all | declared | 100 lignes `4d04f605e5553863` | 100 lignes `f52dbc1c103e7f85` (tronqué) |
| `search sessionplumebench \| stats count` | 7d | refused | **35 876** | refus 422 |
| `search sessionplumebench \| stats count` | au-dela-7d | refused | **108 124** | refus 422 |
| `search sessionplumebench \| stats count` | all | refused | **144 000** | refus 422 |
| `search \| stats count by src_ip,host,source \| sort -count \| head 50` | 7d | refused | 50 lignes `6d735a44351b289e` | refus 422 |
| `search \| stats count by src_ip,host,source \| sort -count \| head 50` | all | refused | 50 lignes `d2e9e2128c6a20cc` | refus 422 |
| `search \| stats count by source,severity` | 7d | differs | 53 lignes `b4fd67245376834f` | 54 lignes `5f5ce15873df856a` |
| `search \| stats count by source,severity` | au-dela-7d | differs | 59 lignes `95d5cd07721e2ccb` | 68 lignes `0a0a8af58152d7df` |
| `search \| stats count by source,severity` | all | differs | 63 lignes `e6c1b918e4b588e4` | 70 lignes `f506e60be6f1cbe5` |
| `search \| stats count by action,source \| sort -count \| head 50` | 7d | refused | 50 lignes `6708bbab4feb00cc` | refus 422 |
| `search \| stats count by action,source \| sort -count \| head 50` | au-dela-7d | refused | 50 lignes `5c1a9b1495ee34ed` | refus 422 |
| `search \| stats count by action,source \| sort -count \| head 50` | all | refused | 50 lignes `1a3cfe0fe89e163e` | refus 422 |
| `search severity>=1 \| table ts,host,source,severity,message` | 7d | declared | 200 lignes `7751d804f61177dc` | 200 lignes `0a3a70ce8ec66dda` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | au-dela-7d | declared | 200 lignes `cc2a01764c203c24` | 200 lignes `ddd0ec415bcf020e` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | all | declared | 200 lignes `d9d46972d13b2c93` | 200 lignes `0a3a70ce8ec66dda` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | 7d | declared | 200 lignes `d2089c14727c0ea2` | 200 lignes `f404c5baffd5865c` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | au-dela-7d | declared | 200 lignes `bd8755d9328aa11c` | 0 lignes `e3b0c44298fc1c14` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | all | declared | 200 lignes `9ca430786fb9a4e3` | 200 lignes `f404c5baffd5865c` (tronqué) |
| `search severity>=1` | au-dela-7d | differs | 200 lignes `409b636e003ac087` | 200 lignes `f86df08b66bb8913` |
| `search severity>=1 \| table ts,host,source,severity,message` | 7d | differs | 200 lignes `4d1842d2d07101ba` | 200 lignes `851189e3a3a3096d` |
| `search severity>=1 \| table ts,host,source,severity,message` | au-dela-7d | declared | 200 lignes `6210ef32fce88a29` | 200 lignes `b75c13c0060f6ba8` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | all | differs | 200 lignes `79c39c5f14e54169` | 200 lignes `cfc66de8daa83556` |
| `search needle=~objetplumebench \| stats count` | 7d | refused | **720** | refus 422 |
| `search needle=~objetplumebench \| stats count` | au-dela-7d | refused | **2 160** | refus 422 |
| `search needle=~objetplumebench \| stats count` | all | refused | **2 880** | refus 422 |
| `search object=~[0-9a-f]{6}c \| stats count` | 7d | refused | **10 528** | refus 422 |
| `search object=~[0-9a-f]{6}c \| stats count` | au-dela-7d | refused | **31 768** | refus 422 |
| `search object=~[0-9a-f]{6}c \| stats count` | all | refused | **42 296** | refus 422 |
| `search \| stats count by host \| sort -count \| head 50` | 7d | refused | 50 lignes `4069e45a545b631b` | refus 422 |
| `search host=bench-node-000.plume.invalid \| table ts,host,source,severity,message` | 7d | differs | 200 lignes `6e46072414e9dbf5` | 200 lignes `c674bdce229ced73` |
| `search host=bench-node-000.plume.invalid \| table ts,host,source,severity,message` | au-dela-7d | declared | 200 lignes `24f68972e58bd09b` | 80 lignes `0e4d979290ef6378` (tronqué) |
| `search host=bench-node-000.plume.invalid \| table ts,host,source,severity,message` | all | differs | 200 lignes `6e46072414e9dbf5` | 200 lignes `c674bdce229ced73` |
| `search user=bench-user-0007 \| stats count` | 7d | refused | **650** | refus 422 |
| `search user=bench-user-0007 \| stats count` | au-dela-7d | refused | **2 075** | refus 422 |
| `search user=bench-user-0007 \| stats count` | all | refused | **2 725** | refus 422 |

**Aucun agrégat scalaire ne diverge.** Les contrôles réductibles à un nombre rendent
la même valeur des deux côtés, ou bien le côté froid REFUSE de répondre en nommant sa
cause. C'est l'invariant de `cold_store/exactness.rs` : aucune valeur dérivée d'un
ensemble tronqué n'est rendue comme un nombre.

> Réserve : LES 3 NOMBRES FAUX QUI RESTENT NE SONT PAS CEUX DU TIER FROID. Ils sont tous portés par la MÊME classe, `C3b-groupby-routable` (`search | stats count by source,severity`), et les deux côtés la servent par la ROUTE DE ROLLUPS, pas par le chemin froid. Mesuré sur la fenêtre `au-dela-7d`, sur la MÊME donnée : la somme des counts vaut 164 165 côté SANS tier froid (`approx:false`, `truncated:false` — donc présentée comme EXACTE) et 1 082 346 côté AVEC (`approx:true`, avec sa note). Le compte BRUT de la même fenêtre, mesuré des deux côtés par `search | stats count`, vaut 1 080 321. C'est donc la route de rollups du côté SANS tier froid qui SOUS-COMPTE d'un facteur 6,6, en se déclarant exacte — un second défaut de la même famille (un nombre faux sans avertissement), DISTINCT de la troncature froide, NON corrigé ici, et reproductible : une base restaurée dont `event_rollup` ne couvre pas le passé profond sert des tableaux de bord sous-comptés. La réserve de la passe du 31/07 laissait ce mécanisme « non expliqué » ; il l'est maintenant, et il reste ouvert.

### La réponse est-elle la MÊME ? (parité mesurée)

Une latence n'est comparable que si les deux chemins rendent la même réponse : un
chemin qui TRONQUE est plus rapide parce qu'il en fait moins. Cette sous-section ne
compare donc pas des temps, elle compare **les valeurs rendues**.

Méthode : APRÈS les correctifs de COUVERTURE des rollups (event_rollup ET event_dim_rollup, cf. daemon/src/rollup_coverage.rs). MÊME base de banc 1440007 événements, deux copies FRAÎCHES du même fichier : l'une columnarisée (PLUME_COLD_TIER=1, 330255 lignes chaudes + 1109752 en 22 Parquet), l'autre intacte (PLUME_COLD_TIER=0). MÊME binaire de mesure (bin:80a19382ef3d30b8), MÊME machine, MÊMES requêtes, MÊMES fenêtres — la matrice de measure.py en entier, produite par bench/parity.py (rejouable). La columnarisation a été produite par un build release de l'arbre efd39e5 ; le code d'aging (cold_age_run) est identique dans le binaire de mesure. LES DEUX daemons ont TICKÉ avant la mesure et la publication de leur couverture (event_rollup_cov_id) a été VÉRIFIÉE des deux côtés — la passe précédente notait elle-même que l'un des daemons venait de démarrer quand l'autre tournait depuis vingt minutes, facteur non contrôlé qui est ici éliminé.

| Verdict | n | ce qu'il signifie |
|---|---:|---|
| `same` | 62 | les deux côtés rendent la MÊME réponse. |
| `differs` | 7 | ils divergent **sans le dire** — un nombre faux, lisible et copiable. C'est LE cas grave. |
| `declared` | 12 | ils divergent et le côté froid le DIT (`truncated`, ou note de couverture). L'incomplétude devient une information. |
| `refused` | 24 | un côté REFUSE, avec un motif nommé. Une erreur vaut mieux qu'un nombre faux : c'est la position de repli, pas l'échec. |

`declared` n'acquitte rien : un AGRÉGAT tronqué reste un nombre faux, déclaré ou non.
Les catégories ne s'additionnent jamais en un « tout va bien ».

**Le compte qui compte : 2 NOMBRE(S) FAUX.** C'est le nombre de contrôles dont la
réponse porte une valeur calculée SUR L'ENSEMBLE (`count`/`dc`/`stats … by …`) et dont
les deux côtés DIVERGENT — que le côté froid l'ait déclaré ou non. C'est exactement ce
que l'invariant de `cold_store/exactness.rs` interdit. Les autres catégories décrivent
des réponses partielles de LIGNES (vraies, incomplètes, signalées) ou des refus motivés :
elles ne sont pas du même ordre de gravité.

Le détail de tout ce qui n'est pas `same` :

| Requête | Fenêtre | Verdict | Sans tier froid | Avec tier froid |
|---|:--:|:--:|---|---|
| `search source=k8s-log \| stats dc(host)` | 7d | refused | **64** | refus 422 |
| `search source=k8s-log \| stats dc(host)` | au-dela-7d | refused | **64** | refus 422 |
| `search source=k8s-log \| stats dc(host)` | all | refused | **64** | refus 422 |
| `search anomalieplumebench \| stats count` | 7d | refused | **349** | refus 422 |
| `search anomalieplumebench \| stats count` | au-dela-7d | refused | **1 091** | refus 422 |
| `search anomalieplumebench \| stats count` | all | refused | **1 440** | refus 422 |
| `anomalieplumebench` | au-dela-7d | declared | 200 lignes `9c78ce2c33bf372c` | 0 lignes `e3b0c44298fc1c14` (couverture déclarée) |
| `search anomalieplumebench \| table ts,host,source,message` | 7d | declared | 100 lignes `f72ae12b4bdf55c8` | 100 lignes `f52dbc1c103e7f85` (tronqué) |
| `search anomalieplumebench \| table ts,host,source,message` | au-dela-7d | declared | 100 lignes `d3c813e56493a55b` | **[1782992260, 'bench-node-005.plume.invalid', 'auditd', 'anom** |
| `search anomalieplumebench \| table ts,host,source,message` | all | declared | 100 lignes `4d04f605e5553863` | 100 lignes `f52dbc1c103e7f85` (tronqué) |
| `search sessionplumebench \| stats count` | 7d | refused | **35 876** | refus 422 |
| `search sessionplumebench \| stats count` | au-dela-7d | refused | **108 124** | refus 422 |
| `search sessionplumebench \| stats count` | all | refused | **144 000** | refus 422 |
| `search \| stats count by src_ip,host,source \| sort -count \| head 50` | 7d | refused | 50 lignes `6d735a44351b289e` | refus 422 |
| `search \| stats count by src_ip,host,source \| sort -count \| head 50` | all | refused | 50 lignes `d2e9e2128c6a20cc` | refus 422 |
| `search \| stats count by source,severity` | 7d | differs | 63 lignes `a0ed57fa1c5d9bc4` | 63 lignes `90dac9300067cbde` |
| `search \| stats count by source,severity` | au-dela-7d | differs | 68 lignes `fbd1621013e0a038` | 68 lignes `0a0a8af58152d7df` |
| `search \| stats count by action,source \| sort -count \| head 50` | 7d | refused | 50 lignes `6708bbab4feb00cc` | refus 422 |
| `search \| stats count by action,source \| sort -count \| head 50` | au-dela-7d | refused | 50 lignes `5c1a9b1495ee34ed` | refus 422 |
| `search \| stats count by action,source \| sort -count \| head 50` | all | refused | 50 lignes `1a3cfe0fe89e163e` | refus 422 |
| `search severity>=1 \| table ts,host,source,severity,message` | 7d | declared | 200 lignes `7751d804f61177dc` | 200 lignes `0a3a70ce8ec66dda` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | au-dela-7d | declared | 200 lignes `cc2a01764c203c24` | 200 lignes `ddd0ec415bcf020e` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | all | declared | 200 lignes `d9d46972d13b2c93` | 200 lignes `0a3a70ce8ec66dda` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | 7d | declared | 200 lignes `d2089c14727c0ea2` | 200 lignes `f404c5baffd5865c` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | au-dela-7d | declared | 200 lignes `bd8755d9328aa11c` | 0 lignes `e3b0c44298fc1c14` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | all | declared | 200 lignes `9ca430786fb9a4e3` | 200 lignes `f404c5baffd5865c` (tronqué) |
| `search severity>=1` | au-dela-7d | differs | 200 lignes `409b636e003ac087` | 200 lignes `f86df08b66bb8913` |
| `search severity>=1 \| table ts,host,source,severity,message` | 7d | differs | 200 lignes `4d1842d2d07101ba` | 200 lignes `851189e3a3a3096d` |
| `search severity>=1 \| table ts,host,source,severity,message` | au-dela-7d | declared | 200 lignes `6210ef32fce88a29` | 200 lignes `b75c13c0060f6ba8` (tronqué) |
| `search severity>=1 \| table ts,host,source,severity,message` | all | differs | 200 lignes `79c39c5f14e54169` | 200 lignes `cfc66de8daa83556` |
| `search needle=~objetplumebench \| stats count` | 7d | refused | **720** | refus 422 |
| `search needle=~objetplumebench \| stats count` | au-dela-7d | refused | **2 160** | refus 422 |
| `search needle=~objetplumebench \| stats count` | all | refused | **2 880** | refus 422 |
| `search object=~[0-9a-f]{6}c \| stats count` | 7d | refused | **10 528** | refus 422 |
| `search object=~[0-9a-f]{6}c \| stats count` | au-dela-7d | refused | **31 768** | refus 422 |
| `search object=~[0-9a-f]{6}c \| stats count` | all | refused | **42 296** | refus 422 |
| `search \| stats count by host \| sort -count \| head 50` | 7d | refused | 50 lignes `4069e45a545b631b` | refus 422 |
| `search host=bench-node-000.plume.invalid \| table ts,host,source,severity,message` | 7d | differs | 200 lignes `6e46072414e9dbf5` | 200 lignes `c674bdce229ced73` |
| `search host=bench-node-000.plume.invalid \| table ts,host,source,severity,message` | au-dela-7d | declared | 200 lignes `24f68972e58bd09b` | 80 lignes `0e4d979290ef6378` (tronqué) |
| `search host=bench-node-000.plume.invalid \| table ts,host,source,severity,message` | all | differs | 200 lignes `6e46072414e9dbf5` | 200 lignes `c674bdce229ced73` |
| `search user=bench-user-0007 \| stats count` | 7d | refused | **650** | refus 422 |
| `search user=bench-user-0007 \| stats count` | au-dela-7d | refused | **2 075** | refus 422 |
| `search user=bench-user-0007 \| stats count` | all | refused | **2 725** | refus 422 |

**Aucun agrégat scalaire ne diverge.** Les contrôles réductibles à un nombre rendent
la même valeur des deux côtés, ou bien le côté froid REFUSE de répondre en nommant sa
cause. C'est l'invariant de `cold_store/exactness.rs` : aucune valeur dérivée d'un
ensemble tronqué n'est rendue comme un nombre.

> Réserve : LA DIVERGENCE ×6,6 DE LA PASSE PRÉCÉDENTE EST CORRIGÉE, ET C'EST CETTE PASSE QUI LE MESURE. La réserve de `parity-apres-2026-07-31` décrivait le binaire d'AVANT le correctif de couverture des rollups ; elle ne décrit plus le dépôt. Mesuré ici, sur la MÊME base et au MÊME instant que la matrice (le compte BRUT étant `search | stats count` sur le MÊME daemon) : côté SANS tier froid, `search | stats count by source,severity` rend 1 080 321 sur la fenêtre `au-dela-7d`, 359 679 sur `7d` et 1 440 007 sur `all` — soit EXACTEMENT le compte brut des trois fenêtres, là où la passe précédente rendait 164 165 sous `approx:false` pour 1 080 321 réels. Le nombre de groupes coïncide désormais des deux côtés (68/68, 63/63, 70/70 ; c'était 59 contre 68). CE QUI RESTE, ET DANS L'AUTRE SENS : 2 contrôles divergent encore, tous deux `C3b-groupby-routable`, et c'est le côté AVEC tier froid qui SUR-compte — 1 082 346 contre 1 080 321 (+2 025, soit +0,19 %) sur `au-dela-7d`, 360 020 contre 359 679 (+341, soit +0,09 %) sur `7d`. Ce côté-là se déclare `approx:true` et porte sa note ; le côté sans tier froid est `approx:false` et exact. La cause est le résidu DOCUMENTÉ de `plan_merge` : sous la frontière chaud/froid, `event` est agé en Parquet, donc un partiel de TÊTE sous-horaire ne peut pas être scanné en brut et est REPLIÉ dans le corps rollup, qui couvre l'heure entière — la fenêtre `au-dela-7d` du banc commence à 1782990828, non aligné à l'heure, et le repli ajoute la tranche [1782990000, 1782990828). Ce n'est donc pas un reste du défaut corrigé : c'est le grain horaire, borné à une sliver sub-horaire, et annoncé. POURQUOI CES 2 SONT QUAND MÊME COMPTÉS COMME NOMBRES FAUX : le classifieur ne rachète JAMAIS un agrégat qui diverge parce qu'il est déclaré (`declared n'acquitte rien`). La règle est conservée telle quelle — l'assouplir pour faire tomber le compte à zéro serait changer la règle après avoir vu le résultat.

### `froid-actif@1.4M`

Frontière chaud/froid CALCULÉE PAR LE DAEMON : `boundary_ts=1784851200`. Une fenêtre
dont la borne basse passe sous cette valeur lit du Parquet ; une fenêtre qui
l'enjambe lit les DEUX et paie l'union.

| Classe | Fenêtre | p50 | lignes | route | passé par le froid | tronqué |
|---|:--:|---:|---:|---|---|:--:|
| `C1-scan-agg` | 1h | 1.2 ms | 1 | raw | non | non |
| `C1-scan-agg` | 24h | 18 ms | 1 | raw | non | non |
| `C1-scan-agg` | 7d | 2.0 s | 1 | — | hot+cold | **oui** |
| `C1-scan-agg` | au-dela-7d | 1056 ms | 1 | — | hot+cold | **oui** |
| `C1-scan-agg` | all | 2.3 s | 1 | — | hot+cold | **oui** |
| `C1b-scan-agg-dc` | 1h | 1.0 ms | 1 | raw | non | non |
| `C1b-scan-agg-dc` | 24h | 9.2 ms | 1 | raw | non | non |
| `C1b-scan-agg-dc` | 7d | 1207 ms | 1 | — | hot+cold | **oui** |
| `C1b-scan-agg-dc` | au-dela-7d | 1069 ms | 1 | — | hot+cold | **oui** |
| `C1b-scan-agg-dc` | all | 1725 ms | 1 | — | hot+cold | **oui** |
| `C2-free-term` | 1h | 2.1 ms | 1 | raw | non | non |
| `C2-free-term` | 24h | 494 ms | 1 | raw | non | non |
| `C2-free-term` | 7d | 4.0 s | 1 | — | hot+cold | **oui** |
| `C2-free-term` | au-dela-7d | 1084 ms | 1 | — | hot+cold | **oui** |
| `C2-free-term` | all | 4.9 s | 1 | — | hot+cold | **oui** |
| `C2b-regex-msg` | 1h | 2.9 ms | 1 | raw | non | non |
| `C2b-regex-msg` | 24h | 540 ms | 1 | raw | non | non |
| `C2b-regex-msg` | 7d | 4.0 s | 1 | — | hot+cold | **oui** |
| `C2b-regex-msg` | au-dela-7d | 1084 ms | 1 | — | hot+cold | **oui** |
| `C2b-regex-msg` | all | 4.5 s | 1 | — | hot+cold | **oui** |
| `C2c-fts-bar` | 1h | 1.2 ms | 3 | — | non | non |
| `C2c-fts-bar` | 24h | 1.5 ms | 38 | — | non | non |
| `C2c-fts-bar` | 7d | 2.2 ms | 100 | — | non | non |
| `C2c-fts-bar` | au-dela-7d | 1.1 ms | 0 | — | non | non |
| `C2c-fts-bar` | all | 2.1 ms | 100 | — | non | non |
| `C3-groupby-hi` | 1h | 3.4 ms | 50 | raw | non | non |
| `C3-groupby-hi` | 24h | 547 ms | 50 | raw | non | non |
| `C3-groupby-hi` | 7d | 4.3 s | 50 | — | hot+cold | **oui** |
| `C3-groupby-hi` | au-dela-7d | 1067 ms | 50 | — | hot+cold | **oui** |
| `C3-groupby-hi` | all | 5.1 s | 50 | — | hot+cold | **oui** |
| `C3b-groupby-routable` | 1h | 4.0 ms | 37 | raw | non | non |
| `C3b-groupby-routable` | 24h | 7.8 ms | 48 | rollup | non | non |
| `C3b-groupby-routable` | 7d | 43 ms | 54 | rollup | non | non |
| `C3b-groupby-routable` | au-dela-7d | 808 ms | 68 | rollup | non | non |
| `C3b-groupby-routable` | all | 948 ms | 70 | rollup | non | non |
| `C3c-groupby-json` | 1h | 6.5 ms | 50 | raw | non | non |
| `C3c-groupby-json` | 24h | 161 ms | 50 | raw | non | non |
| `C3c-groupby-json` | 7d | 6.0 s | 50 | — | hot+cold | **oui** |
| `C3c-groupby-json` | au-dela-7d | 1083 ms | 50 | — | hot+cold | **oui** |
| `C3c-groupby-json` | all | 5.3 s | 50 | — | hot+cold | **oui** |
| `C4-raw-page1` | 1h | 2.8 ms | 200 | raw | non | non |
| `C4-raw-page1` | 24h | 9.5 ms | 200 | raw | non | non |
| `C4-raw-page1` | 7d | 666 ms | 200 | — | hot+cold | **oui** |
| `C4-raw-page1` | au-dela-7d | 1110 ms | 200 | — | hot+cold | **oui** |
| `C4-raw-page1` | all | 1195 ms | 200 | — | hot+cold | **oui** |
| `C4b-raw-deep` | 1h | 5.2 ms | 0 | raw | non | non |
| `C4b-raw-deep` | 24h | 342 ms | 0 | raw | non | non |
| `C4b-raw-deep` | 7d | 2.8 s | 200 | — | hot+cold | **oui** |
| `C4b-raw-deep` | au-dela-7d | 1075 ms | 0 | — | hot+cold | **oui** |
| `C4b-raw-deep` | all | 3.5 s | 200 | — | hot+cold | **oui** |
| `C4c-raw-keyset` | 1h | 2.3 ms | 200 | raw | non | non |
| `C4c-raw-keyset` | 24h | 2.3 ms | 200 | raw | non | non |
| `C4c-raw-keyset` | 7d | 549 ms | 200 | — | hot+cold | **oui** |
| `C4c-raw-keyset` | au-dela-7d | 1114 ms | 200 | — | hot+cold | **oui** |
| `C4c-raw-keyset` | all | 1096 ms | 200 | — | hot+cold | **oui** |
| `C5-regex-json-planted` | 1h | 3.1 ms | 1 | raw | non | non |
| `C5-regex-json-planted` | 24h | 492 ms | 1 | raw | non | non |
| `C5-regex-json-planted` | 7d | 4.1 s | 1 | — | hot+cold | **oui** |
| `C5-regex-json-planted` | au-dela-7d | 1406 ms | 1 | — | hot+cold | **oui** |
| `C5-regex-json-planted` | all | 5.7 s | 1 | — | hot+cold | **oui** |
| `C5b-regex-json-cold` | 1h | 3.9 ms | 1 | raw | non | non |
| `C5b-regex-json-cold` | 24h | 591 ms | 1 | raw | non | non |
| `C5b-regex-json-cold` | 7d | 4.7 s | 1 | — | hot+cold | **oui** |
| `C5b-regex-json-cold` | au-dela-7d | 1090 ms | 1 | — | hot+cold | **oui** |
| `C5b-regex-json-cold` | all | 4.9 s | 1 | — | hot+cold | **oui** |
| `C5c-eq-json-hot` | 1h | 1.1 ms | 1 | raw | non | non |
| `C5c-eq-json-hot` | 24h | 1.2 ms | 1 | raw | non | non |
| `C5c-eq-json-hot` | 7d | 540 ms | 1 | — | hot+cold | **oui** |
| `C5c-eq-json-hot` | au-dela-7d | 1088 ms | 1 | — | hot+cold | **oui** |
| `C5c-eq-json-hot` | all | 1071 ms | 1 | — | hot+cold | **oui** |
| `C0-plancher` | 1h | 0.8 ms | 1 | raw | non | non |
| `C0-plancher` | 24h | 0.7 ms | 1 | raw | non | non |
| `C0-plancher` | 7d | 516 ms | 1 | — | hot+cold | **oui** |
| `C0-plancher` | au-dela-7d | 1031 ms | 1 | — | hot+cold | **oui** |
| `C0-plancher` | all | 1032 ms | 1 | — | hot+cold | **oui** |
| `C2d-free-term-rows` | 1h | 4.2 ms | 3 | raw | non | non |
| `C2d-free-term-rows` | 24h | 536 ms | 38 | raw | non | non |
| `C2d-free-term-rows` | 7d | 6.0 s | 100 | — | hot+cold | **oui** |
| `C2d-free-term-rows` | au-dela-7d | 1091 ms | 4 | — | hot+cold | **oui** |
| `C2d-free-term-rows` | all | 5.7 s | 100 | — | hot+cold | **oui** |
| `C2e-free-term-common` | 1h | 2.4 ms | 1 | raw | non | non |
| `C2e-free-term-common` | 24h | 504 ms | 1 | raw | non | non |
| `C2e-free-term-common` | 7d | 5.3 s | 1 | — | hot+cold | **oui** |
| `C2e-free-term-common` | au-dela-7d | 1045 ms | 1 | — | hot+cold | **oui** |
| `C2e-free-term-common` | all | 4.5 s | 1 | — | hot+cold | **oui** |
| `C4d-keyset-projete` | 1h | 1.7 ms | 200 | raw | non | non |
| `C4d-keyset-projete` | 24h | 1.6 ms | 200 | raw | non | non |
| `C4d-keyset-projete` | 7d | 544 ms | 200 | — | hot+cold | **oui** |
| `C4d-keyset-projete` | au-dela-7d | 1065 ms | 200 | — | hot+cold | **oui** |
| `C4d-keyset-projete` | all | 1122 ms | 200 | — | hot+cold | **oui** |
| `C6-filter-host` | 1h | 1.7 ms | 1 | raw | non | non |
| `C6-filter-host` | 24h | 503 ms | 1 | raw | non | non |
| `C6-filter-host` | 7d | 597 ms | 1 | — | hot+cold | **oui** |
| `C6-filter-host` | au-dela-7d | 1071 ms | 1 | — | hot+cold | **oui** |
| `C6-filter-host` | all | 1138 ms | 1 | — | hot+cold | **oui** |
| `C6b-groupby-host` | 1h | 2.9 ms | 50 | raw | non | non |
| `C6b-groupby-host` | 24h | 392 ms | 50 | raw | non | non |
| `C6b-groupby-host` | 7d | 4.2 s | 50 | — | hot+cold | **oui** |
| `C6b-groupby-host` | au-dela-7d | 1078 ms | 50 | — | hot+cold | **oui** |
| `C6b-groupby-host` | all | 4.6 s | 50 | — | hot+cold | **oui** |
| `C6c-raw-one-host` | 1h | 1.8 ms | 22 | raw | non | non |
| `C6c-raw-one-host` | 24h | 11 ms | 200 | raw | non | non |
| `C6c-raw-one-host` | 7d | 589 ms | 200 | — | hot+cold | **oui** |
| `C6c-raw-one-host` | au-dela-7d | 1068 ms | 80 | — | hot+cold | **oui** |
| `C6c-raw-one-host` | all | 1116 ms | 200 | — | hot+cold | **oui** |

> Dans le tableau des configurations, la colonne « Événements » de `froid-actif@1.4M` vaut 335 255 : c'est le nombre de lignes CHAUDES, pas la taille du jeu. 1 440 007 événements sont interrogeables, dont 1 104 752 depuis le Parquet.

**57 cellules sur 105 ont réellement traversé le tier froid** (colonne
« passé par le froid » : elle vient de `stats.cold` renvoyé par le daemon, pas de
l'étiquette de configuration). **57 cellules sont TRONQUÉES** : le chemin d'union hydrate le froid dans SQLite avec un plafond de lignes (`PLUME_QUERY_MAX`, défaut 5 000, `cold_store/reader.rs:130`) — au-delà, la réponse est PARTIELLE et le daemon le dit. Un agrégat sur une fenêtre froide large n'est donc pas exact par défaut : c'est le résultat le plus important de cette section.

### `froid-actif-v2@1.4M`

Frontière chaud/froid CALCULÉE PAR LE DAEMON : `boundary_ts=1784851200`. Une fenêtre
dont la borne basse passe sous cette valeur lit du Parquet ; une fenêtre qui
l'enjambe lit les DEUX et paie l'union.

| Classe | Fenêtre | p50 | lignes | route | passé par le froid | tronqué |
|---|:--:|---:|---:|---|---|:--:|
| `C1-scan-agg` | 1h | 1.3 ms | 1 | raw | non | non |
| `C1-scan-agg` | 24h | 14 ms | 1 | raw | non | non |
| `C1-scan-agg` | 7d | 1851 ms | 1 | cold-vectorized-merge | cold-vectorized-merge | non |
| `C1-scan-agg` | au-dela-7d | 2.9 s | 1 | cold-vectorized | cold-vectorized | non |
| `C1-scan-agg` | all | 4.1 s | 1 | cold-vectorized-merge | cold-vectorized-merge | non |
| `C1b-scan-agg-dc` | 1h | 1.0 ms | 1 | raw | non | non |
| `C1b-scan-agg-dc` | 24h | 9.6 ms | 1 | raw | non | non |
| `C1b-scan-agg-dc` | 7d | — | — | — | non | non |
| `C1b-scan-agg-dc` | au-dela-7d | — | — | — | non | non |
| `C1b-scan-agg-dc` | all | — | — | — | non | non |
| `C2-free-term` | 1h | 2.4 ms | 1 | raw | non | non |
| `C2-free-term` | 24h | 526 ms | 1 | raw | non | non |
| `C2-free-term` | 7d | — | — | — | non | non |
| `C2-free-term` | au-dela-7d | — | — | — | non | non |
| `C2-free-term` | all | — | — | — | non | non |
| `C2b-regex-msg` | 1h | 2.7 ms | 1 | raw | non | non |
| `C2b-regex-msg` | 24h | 557 ms | 1 | raw | non | non |
| `C2b-regex-msg` | 7d | 4.2 s | 1 | cold-vectorized-merge | cold-vectorized-merge | non |
| `C2b-regex-msg` | au-dela-7d | 2.8 s | 1 | cold-vectorized | cold-vectorized | non |
| `C2b-regex-msg` | all | 6.3 s | 1 | cold-vectorized-merge | cold-vectorized-merge | non |
| `C2c-fts-bar` | 1h | 1.8 ms | 3 | — | non | non |
| `C2c-fts-bar` | 24h | 2.0 ms | 38 | — | non | non |
| `C2c-fts-bar` | 7d | 3.1 ms | 100 | — | non | non |
| `C2c-fts-bar` | au-dela-7d | 1.4 ms | 0 | — | non | non |
| `C2c-fts-bar` | all | 2.2 ms | 100 | — | non | non |
| `C3-groupby-hi` | 1h | 4.5 ms | 50 | raw | non | non |
| `C3-groupby-hi` | 24h | 554 ms | 50 | raw | non | non |
| `C3-groupby-hi` | 7d | — | — | — | non | non |
| `C3-groupby-hi` | au-dela-7d | 4.1 s | 50 | cold-vectorized | cold-vectorized | non |
| `C3-groupby-hi` | all | — | — | — | non | non |
| `C3b-groupby-routable` | 1h | 3.0 ms | 37 | raw | non | non |
| `C3b-groupby-routable` | 24h | 8.4 ms | 48 | rollup | non | non |
| `C3b-groupby-routable` | 7d | 46 ms | 54 | rollup | non | non |
| `C3b-groupby-routable` | au-dela-7d | 858 ms | 68 | rollup | non | non |
| `C3b-groupby-routable` | all | 873 ms | 70 | rollup | non | non |
| `C3c-groupby-json` | 1h | 6.0 ms | 50 | raw | non | non |
| `C3c-groupby-json` | 24h | 653 ms | 50 | raw | non | non |
| `C3c-groupby-json` | 7d | — | — | — | non | non |
| `C3c-groupby-json` | au-dela-7d | — | — | — | non | non |
| `C3c-groupby-json` | all | — | — | — | non | non |
| `C4-raw-page1` | 1h | 3.5 ms | 200 | raw | non | non |
| `C4-raw-page1` | 24h | 9.7 ms | 200 | raw | non | non |
| `C4-raw-page1` | 7d | 680 ms | 200 | — | hot+cold | **oui** |
| `C4-raw-page1` | au-dela-7d | 1106 ms | 200 | — | hot+cold | **oui** |
| `C4-raw-page1` | all | 1296 ms | 200 | — | hot+cold | **oui** |
| `C4b-raw-deep` | 1h | 3.8 ms | 0 | raw | non | non |
| `C4b-raw-deep` | 24h | 373 ms | 0 | raw | non | non |
| `C4b-raw-deep` | 7d | 3.1 s | 200 | — | hot+cold | **oui** |
| `C4b-raw-deep` | au-dela-7d | 1189 ms | 0 | — | hot+cold | **oui** |
| `C4b-raw-deep` | all | 3.5 s | 200 | — | hot+cold | **oui** |
| `C4c-raw-keyset` | 1h | 3.6 ms | 200 | raw | non | non |
| `C4c-raw-keyset` | 24h | 3.6 ms | 200 | raw | non | non |
| `C4c-raw-keyset` | 7d | 3.9 ms | 0 | — | hot+cold-vectorized-keyset | non |
| `C4c-raw-keyset` | au-dela-7d | 626 ms | 0 | — | hot+cold-vectorized-keyset | non |
| `C4c-raw-keyset` | all | 3.3 ms | 0 | — | hot+cold-vectorized-keyset | non |
| `C5-regex-json-planted` | 1h | 3.6 ms | 1 | raw | non | non |
| `C5-regex-json-planted` | 24h | 446 ms | 1 | raw | non | non |
| `C5-regex-json-planted` | 7d | — | — | — | non | non |
| `C5-regex-json-planted` | au-dela-7d | — | — | — | non | non |
| `C5-regex-json-planted` | all | — | — | — | non | non |
| `C5b-regex-json-cold` | 1h | 4.0 ms | 1 | raw | non | non |
| `C5b-regex-json-cold` | 24h | 595 ms | 1 | raw | non | non |
| `C5b-regex-json-cold` | 7d | — | — | — | non | non |
| `C5b-regex-json-cold` | au-dela-7d | — | — | — | non | non |
| `C5b-regex-json-cold` | all | — | — | — | non | non |
| `C5c-eq-json-hot` | 1h | 1.1 ms | 1 | raw | non | non |
| `C5c-eq-json-hot` | 24h | 1.0 ms | 1 | raw | non | non |
| `C5c-eq-json-hot` | 7d | — | — | — | non | non |
| `C5c-eq-json-hot` | au-dela-7d | — | — | — | non | non |
| `C5c-eq-json-hot` | all | — | — | — | non | non |
| `C0-plancher` | 1h | 0.8 ms | 1 | raw | non | non |
| `C0-plancher` | 24h | 0.8 ms | 1 | raw | non | non |
| `C0-plancher` | 7d | 575 ms | 1 | cold-vectorized-merge | cold-vectorized-merge | non |
| `C0-plancher` | au-dela-7d | 2.8 s | 1 | cold-vectorized | cold-vectorized | non |
| `C0-plancher` | all | 3.2 s | 1 | cold-vectorized-merge | cold-vectorized-merge | non |
| `C2d-free-term-rows` | 1h | 4.4 ms | 3 | raw | non | non |
| `C2d-free-term-rows` | 24h | 577 ms | 38 | raw | non | non |
| `C2d-free-term-rows` | 7d | 6.6 s | 100 | — | hot+cold | **oui** |
| `C2d-free-term-rows` | au-dela-7d | 1151 ms | 4 | — | hot+cold | **oui** |
| `C2d-free-term-rows` | all | 5.7 s | 100 | — | hot+cold | **oui** |
| `C2e-free-term-common` | 1h | 2.5 ms | 1 | raw | non | non |
| `C2e-free-term-common` | 24h | 525 ms | 1 | raw | non | non |
| `C2e-free-term-common` | 7d | — | — | — | non | non |
| `C2e-free-term-common` | au-dela-7d | — | — | — | non | non |
| `C2e-free-term-common` | all | — | — | — | non | non |
| `C4d-keyset-projete` | 1h | 1.9 ms | 200 | raw | non | non |
| `C4d-keyset-projete` | 24h | 1.9 ms | 200 | raw | non | non |
| `C4d-keyset-projete` | 7d | 2.3 ms | 0 | — | hot+cold-vectorized-keyset | non |
| `C4d-keyset-projete` | au-dela-7d | 1164 ms | 200 | — | hot+cold | **oui** |
| `C4d-keyset-projete` | all | 3.1 ms | 0 | — | hot+cold-vectorized-keyset | non |
| `C6-filter-host` | 1h | 1.8 ms | 1 | raw | non | non |
| `C6-filter-host` | 24h | 506 ms | 1 | raw | non | non |
| `C6-filter-host` | 7d | 654 ms | 1 | cold-vectorized-merge | cold-vectorized-merge | non |
| `C6-filter-host` | au-dela-7d | 2.7 s | 1 | cold-vectorized | cold-vectorized | non |
| `C6-filter-host` | all | 3.0 s | 1 | cold-vectorized-merge | cold-vectorized-merge | non |
| `C6b-groupby-host` | 1h | 2.9 ms | 50 | raw | non | non |
| `C6b-groupby-host` | 24h | 427 ms | 50 | raw | non | non |
| `C6b-groupby-host` | 7d | — | — | — | non | non |
| `C6b-groupby-host` | au-dela-7d | 2.8 s | 50 | cold-vectorized | cold-vectorized | non |
| `C6b-groupby-host` | all | 7.8 s | 50 | cold-vectorized-merge | cold-vectorized-merge | non |
| `C6c-raw-one-host` | 1h | 2.1 ms | 22 | raw | non | non |
| `C6c-raw-one-host` | 24h | 11 ms | 200 | raw | non | non |
| `C6c-raw-one-host` | 7d | 6.6 ms | 0 | — | hot+cold-vectorized-keyset | non |
| `C6c-raw-one-host` | au-dela-7d | 1181 ms | 80 | — | hot+cold | **oui** |
| `C6c-raw-one-host` | all | 7.2 ms | 0 | — | hot+cold-vectorized-keyset | non |

**33 cellules sur 105 ont réellement traversé le tier froid** (colonne
« passé par le froid » : elle vient de `stats.cold` renvoyé par le daemon, pas de
l'étiquette de configuration). **11 cellules sont TRONQUÉES** : le chemin d'union hydrate le froid dans SQLite avec un plafond de lignes (`PLUME_QUERY_MAX`, défaut 5 000, `cold_store/reader.rs:130`) — au-delà, la réponse est PARTIELLE et le daemon le dit. Un agrégat sur une fenêtre froide large n'est donc pas exact par défaut : c'est le résultat le plus important de cette section.

## Le nombre de machines — ce que le profil mono-hôte cachait

La base profilée est **mono-nœud** : toutes ses sources ont `distinct_hosts: 1`. `host`
étant l'une des six colonnes indexées, toute cellule qui filtre ou groupe par hôte y porte
sur un cas **dégénéré de cardinalité 1**. Les passes ci-dessous rejouent les mêmes classes
sur des profils FLOTTE dérivés (`bench/make_fleet_profile.py`), **à volume d'événements
égal**.

**Ce qui change exactement entre ces passes** — il faut le dire avant de lire le tableau :
**(1)** la cardinalité de `host` (1, puis N) ; **(2)** le MÉLANGE des sources, parce que
multiplier les sources host-locales par N change leur poids relatif (`auditd` passe de
38,5 % à 44,7 % du flux). Les deux viennent de la même dérivation. Une classe qui bouge
peut donc bouger pour l'une OU l'autre raison — sauf les classes `C6*`, qui nomment `host`
dans la requête : celles-là isolent la cardinalité, et ce sont elles qu'il faut lire pour
juger du trou de généricité.

**Ce que la taille de flotte change en VOLUME** — dérivé (`bench/make_fleet_profile.py`)
des distributions MESURÉES par source, sur la fenêtre de la base profilée :

| Hôtes | Sources host-locales | Événements mono-hôte (mesuré) | Événements flotte (dérivé) | Facteur |
|---:|---:|---:|---:|---:|
| 1 | 20 sur 32 | 1 395 968 | 1 395 968 | x1.0 |
| 50 | 20 sur 32 | 1 395 968 | 60 183 032 | x43.112 |
| 200 | 20 sur 32 | 1 395 968 | 240 143 432 | x172.026 |

La colonne « dérivé » n'est PAS une mesure : c'est la multiplication du poids des
sources déclarées host-locales par le nombre de machines. Ce qui est mesuré, ce sont
les distributions de chaque source ; ce qui est déclaré, c'est la liste des sources
host-locales (`bench/fleet-per-host.txt`, une ligne par source, avec sa raison).

| Classe | Fenêtre | 1 hôte | 50 hôtes | 200 hôtes |
|---|:--:|---:|---:|---:|
| `C1-scan-agg` | 1h | 0.7 ms | 0.8 ms | 0.9 ms |
| `C1-scan-agg` | 24h | 6.2 ms | 7.0 ms | 7.4 ms |
| `C1-scan-agg` | 7d | 404 ms | 50 ms | 50 ms |
| `C1-scan-agg` | au-dela-7d | 1216 ms | 500 ms | 456 ms |
| `C1-scan-agg` | all | 821 ms | 465 ms | 454 ms |
| `C3-groupby-hi` | 1h | 2.5 ms | 1.9 ms | 2.0 ms |
| `C3-groupby-hi` | 24h | 47 ms | 36 ms | 36 ms |
| `C3-groupby-hi` | 7d | 1581 ms | 552 ms | 524 ms |
| `C3-groupby-hi` | au-dela-7d | 3.8 s | 986 ms | 1023 ms |
| `C3-groupby-hi` | all | 3.6 s | 1017 ms | 891 ms |
| `C0-plancher` | 1h | 0.7 ms | 0.6 ms | 0.7 ms |
| `C0-plancher` | 24h | 0.8 ms | 0.6 ms | 0.8 ms |
| `C0-plancher` | 7d | 0.9 ms | 0.6 ms | 0.7 ms |
| `C0-plancher` | au-dela-7d | 0.8 ms | 0.6 ms | 0.8 ms |
| `C0-plancher` | all | 0.6 ms | 0.6 ms | 0.7 ms |
| `C6-filter-host` | 1h | 1.3 ms | 1.2 ms | 1.2 ms |
| `C6-filter-host` | 24h | 203 ms | 17 ms | 2.2 ms |
| `C6-filter-host` | 7d | 1041 ms | 8.1 ms | 2.7 ms |
| `C6-filter-host` | au-dela-7d | 898 ms | 7.6 ms | 2.4 ms |
| `C6-filter-host` | all | 25 ms | 1.1 ms | 0.9 ms |
| `C6b-groupby-host` | 1h | 1.5 ms | 1.5 ms | 1.5 ms |
| `C6b-groupby-host` | 24h | 211 ms | 26 ms | 27 ms |
| `C6b-groupby-host` | 7d | 962 ms | 355 ms | 599 ms |
| `C6b-groupby-host` | au-dela-7d | 977 ms | 4.4 s | 4.2 s |
| `C6b-groupby-host` | all | 40 ms | 44 ms | 44 ms |
| `C6c-raw-one-host` | 1h | 1.6 ms | 1.3 ms | 1.2 ms |
| `C6c-raw-one-host` | 24h | 1.7 ms | 8.5 ms | 2.8 ms |
| `C6c-raw-one-host` | 7d | 2.2 ms | 9.5 ms | 3.4 ms |
| `C6c-raw-one-host` | au-dela-7d | 1.7 ms | 10 ms | 4.5 ms |
| `C6c-raw-one-host` | all | 1.6 ms | 10 ms | 3.8 ms |

Une classe dont la latence ne bouge pas avec le nombre de machines ne dépend pas de la
cardinalité de `host`. Une classe qui bouge est une classe dont les chiffres publiés sur
un profil mono-hôte **ne valent pas** pour une flotte — et le sens de l'erreur n'est pas
toujours le même : là où `host` sert de FILTRE, le mono-hôte est PESSIMISTE (le filtre y
sélectionne tout, alors qu'il sélectionne 1/N sur une flotte) ; là où `host` sert de clé de
GROUPEMENT, il est OPTIMISTE (un seul groupe au lieu de N). Un profil mono-hôte ne
« flatte » donc pas le produit : il le décrit FAUX, dans les deux sens à la fois.

## La généricité — les mêmes requêtes sur d'AUTRES profils de données

Un chiffre mesuré sur notre profil prouve NOTRE cas, pas le cas général. Les passes ci-dessous
rejouent **la même matrice** sur des profils qui ne diffèrent du témoin que par **un seul**
paramètre du jeu de données, **à volume d'événements égal**, sur la même machine et le même
binaire. Chaque axe est DÉRIVÉ d'une décision du chemin d'exécution — pas choisi pour
l'occasion : ce qui décide index ou scan, route de rollups ou balayage, chaud ou froid.

| Passe | Axe | Valeur | Ce que le profil dit AVANT -> APRÈS | Événements | Base (Mio) |
|---|---|---|---|---:|---:|
| `temoin-64h@0.6M` | **témoin** | — | — | 600 003 | 647 |
| `flotte-1h-v2@0.6M` | hosts | 1 | cardinalité de `host` = 1 | 600 003 | 634 |
| `flotte-50h-v2@0.6M` | hosts | 50 | cardinalité de `host` = 50 | 600 003 | 377 |
| `card-haute@0.6M` | ext_card_scale | 25.0 | cardinalité médiane 4 -> 100 | 600 003 | 649 |
| `sev-haute@0.6M` | severity_shift | 0.6 | sévérité >= 3 0.064 -> 0.4768 | 600 003 | 649 |
| `temoin-bis@0.6M` | **témoin** | — | — | 600 003 | 656 |
| `taille-grande@0.6M` | event_size_scale | 3.0 | octets/événement 252.8 -> 758.2 | 600 003 | 1039 |

### Le bruit d'abord — sinon aucun écart n'est interprétable

Le témoin a été mesuré **deux fois**, sur la **même base**, avec le même binaire et la
même machine — `temoin-64h@0.6M` puis `temoin-bis@0.6M`. Rien n'y change : ni la donnée, ni le code,
ni le réglage. Les deux passes ENCADRENT la campagne (l'une au début, l'autre à la fin),
donc la bande contient aussi la dérive de la machine pendant la campagne. Le rapport
d'une passe à l'autre, cellule par cellule, est du BRUIT pur, et il vaut :

| Cellules | min | 5 % | médian | 95 % | max |
|---:|---:|---:|---:|---:|---:|
| 105 | x0.07 | x0.51 | x0.92 | x1.80 | x29.82 |

**C'est l'étalon.** Le critère retenu plus bas est l'ÉTENDUE COMPLÈTE `[x0.07,
x29.82]` — le plus conservateur des deux : un écart n'est déclaré attribuable au
profil que s'il sort de tout ce que la répétition a produit sans qu'on change quoi que ce
soit. Les quantiles sont publiés à côté pour que le lecteur voie si la bande est large
à cause d'UNE cellule ou de toutes.

Cette bande n'est pas un seuil choisi : c'est une mesure. Elle s'élargit d'elle-même si
la machine est plus chargée, et le document conclut alors MOINS. C'est le comportement
voulu — un banc doit perdre en conclusions quand il perd en conditions, jamais gagner en
confiance. **Réserve à connaître** : les cellules les plus rapides (proches du coût fixe
d'une requête, mesuré par `C0-plancher`) ont un bruit relatif élevé alors que leur enjeu
est nul ; elles élargissent la bande et rendent donc le test PLUS strict, jamais moins.

### L'écart, axe par axe

Rapport de la latence p50 de chaque passe à celle du témoin `temoin-64h@0.6M`. **Gras** = l'écart
sort de la bande de bruit ci-dessus, donc il est attribuable au PROFIL DE DONNÉES et pas à la
machine. Une cellule vide n'a pas été mesurée des deux côtés.

| Classe | Fenêtre | témoin | `flotte-1h-v2@0.6M` | `flotte-50h-v2@0.6M` | `card-haute@0.6M` | `sev-haute@0.6M` | `taille-grande@0.6M` |
|---|:--:|---:|---:|---:|---:|---:|---:|
| `C1-scan-agg` | 1h | 1.3 ms | x1.00 | x0.83 | x0.83 | x0.72 | x1.19 |
| `C1-scan-agg` | 24h | 11 ms | x0.78 | x0.83 | x0.81 | x0.70 | x0.57 |
| `C1-scan-agg` | 7d | 611 ms | x0.97 | x0.52 | x0.93 | x0.86 | x1.14 |
| `C1-scan-agg` | au-dela-7d | 1869 ms | x0.99 | x0.50 | x0.87 | x0.92 | x1.12 |
| `C1-scan-agg` | all | 1223 ms | x0.92 | x0.51 | x0.91 | x0.88 | x1.60 |
| `C1b-scan-agg-dc` | 1h | 1.5 ms | x0.77 | x0.67 | x0.81 | x0.87 | x0.75 |
| `C1b-scan-agg-dc` | 24h | 9.0 ms | x0.77 | x0.79 | x0.95 | x0.79 | x24.10 |
| `C1b-scan-agg-dc` | 7d | 97 ms | x2.35 | x0.39 | x0.47 | x1.16 | x4.30 |
| `C1b-scan-agg-dc` | au-dela-7d | 1233 ms | x1.12 | x0.46 | x0.93 | x0.80 | x1.05 |
| `C1b-scan-agg-dc` | all | 1534 ms | x1.02 | x0.94 | **x0.06** | **x0.06** | x1.90 |
| `C2-free-term` | 1h | 1.3 ms | x1.20 | x8.35 | x1.34 | x1.22 | x1.70 |
| `C2-free-term` | 24h | 38 ms | x1.02 | x6.53 | x8.96 | x7.34 | x5.95 |
| `C2-free-term` | 7d | 1986 ms | x1.05 | x0.54 | x1.01 | x0.96 | x1.35 |
| `C2-free-term` | au-dela-7d | 1677 ms | x0.86 | x0.52 | x0.85 | x0.97 | x2.48 |
| `C2-free-term` | all | 1471 ms | x0.97 | x0.51 | x0.94 | x0.91 | x2.05 |
| `C2b-regex-msg` | 1h | 2.2 ms | x1.20 | x1.25 | x0.74 | x0.76 | x17.35 |
| `C2b-regex-msg` | 24h | 36 ms | x1.24 | x9.30 | x7.49 | x8.09 | x9.81 |
| `C2b-regex-msg` | 7d | 2.1 s | x1.10 | x0.84 | x0.73 | x1.17 | x2.48 |
| `C2b-regex-msg` | au-dela-7d | 1850 ms | x0.95 | x0.55 | x1.25 | x0.95 | x2.24 |
| `C2b-regex-msg` | all | 1871 ms | x0.91 | x0.57 | x0.91 | x0.96 | x1.80 |
| `C2c-fts-bar` | 1h | 115 ms | x0.68 | **x0.01** | x0.69 | x0.72 | x1.29 |
| `C2c-fts-bar` | 24h | 2.5 ms | x0.69 | x1.00 | x0.71 | x0.67 | x0.58 |
| `C2c-fts-bar` | 7d | 3.7 ms | x0.75 | x1.16 | x0.63 | x0.66 | x0.80 |
| `C2c-fts-bar` | au-dela-7d | 4.5 ms | x0.66 | x1.22 | x0.65 | x0.66 | x0.68 |
| `C2c-fts-bar` | all | 3.2 ms | x0.94 | x0.91 | x0.75 | x0.67 | x1.03 |
| `C3-groupby-hi` | 1h | 2.8 ms | x1.45 | x1.53 | x1.02 | x1.24 | x0.96 |
| `C3-groupby-hi` | 24h | 291 ms | x0.14 | x0.86 | x0.92 | x1.11 | x1.12 |
| `C3-groupby-hi` | 7d | 3.3 s | x0.92 | x0.53 | x0.87 | x0.67 | x2.05 |
| `C3-groupby-hi` | au-dela-7d | 4.3 s | x1.28 | x0.36 | x1.19 | x1.02 | x2.01 |
| `C3-groupby-hi` | all | 6.3 s | x0.80 | x0.28 | x1.11 | x0.75 | x1.21 |
| `C3b-groupby-routable` | 1h | 1.9 ms | x0.85 | x1.29 | x1.10 | x1.74 | x1.04 |
| `C3b-groupby-routable` | 24h | 15 ms | x0.97 | x0.64 | x1.15 | x0.99 | x1.06 |
| `C3b-groupby-routable` | 7d | 106 ms | x0.83 | x0.44 | x0.96 | x0.92 | x1.02 |
| `C3b-groupby-routable` | au-dela-7d | 342 ms | x0.76 | x0.49 | x1.02 | x0.97 | x1.02 |
| `C3b-groupby-routable` | all | 518 ms | x0.90 | x0.36 | x0.92 | x0.76 | x0.95 |
| `C3c-groupby-json` | 1h | 3.3 ms | x1.18 | x0.60 | x1.27 | x1.07 | x1.69 |
| `C3c-groupby-json` | 24h | 357 ms | x0.79 | x0.72 | x0.19 | x0.77 | x3.05 |
| `C3c-groupby-json` | 7d | 3.4 s | x0.75 | x0.56 | x0.56 | x0.97 | x1.87 |
| `C3c-groupby-json` | au-dela-7d | 10.9 s | x0.81 | x0.48 | x0.83 | x0.89 | x1.22 |
| `C3c-groupby-json` | all | 3.2 s | x1.16 | x0.46 | x1.17 | x1.31 | x2.05 |
| `C4-raw-page1` | 1h | 2.4 ms | x1.30 | x1.35 | x1.55 | x1.26 | x1.42 |
| `C4-raw-page1` | 24h | 13 ms | x0.88 | **x32.22** | x1.12 | x1.48 | x0.98 |
| `C4-raw-page1` | 7d | 201 ms | **x0.07** | x0.07 | **x0.07** | **x0.06** | **x0.06** |
| `C4-raw-page1` | au-dela-7d | 5.2 ms | x0.84 | x1.10 | x0.98 | x0.60 | x1.16 |
| `C4-raw-page1` | all | 2.6 ms | x0.80 | x0.68 | x0.67 | x0.58 | x1.01 |
| `C4b-raw-deep` | 1h | 2.9 ms | x0.91 | x1.05 | x0.79 | x1.05 | x0.82 |
| `C4b-raw-deep` | 24h | 145 ms | x0.26 | x0.28 | x0.27 | x1.05 | x1.21 |
| `C4b-raw-deep` | 7d | 1099 ms | x1.63 | x0.93 | x2.29 | x1.20 | x1.66 |
| `C4b-raw-deep` | au-dela-7d | 805 ms | x0.71 | **x0.06** | x1.11 | x0.65 | x1.31 |
| `C4b-raw-deep` | all | 415 ms | x1.13 | x0.07 | x1.00 | x0.09 | x2.00 |
| `C4c-raw-keyset` | 1h | 3.5 ms | x0.88 | x0.75 | x2.99 | x1.45 | x1.22 |
| `C4c-raw-keyset` | 24h | 5.0 ms | x0.68 | x0.57 | x1.76 | x0.80 | x0.65 |
| `C4c-raw-keyset` | 7d | 3.3 ms | x0.82 | x0.67 | x2.84 | x0.80 | x1.26 |
| `C4c-raw-keyset` | au-dela-7d | 3.0 ms | x1.44 | x0.84 | x3.63 | x1.17 | x1.46 |
| `C4c-raw-keyset` | all | 3.9 ms | x0.96 | x0.61 | x2.52 | x0.93 | x1.15 |
| `C5-regex-json-planted` | 1h | 2.9 ms | x0.81 | x0.73 | x6.72 | x1.40 | x0.81 |
| `C5-regex-json-planted` | 24h | 42 ms | x1.05 | x0.60 | x12.50 | x1.09 | x8.70 |
| `C5-regex-json-planted` | 7d | 3.2 s | x0.80 | **x0.05** | x0.79 | x0.75 | x1.48 |
| `C5-regex-json-planted` | au-dela-7d | 2.1 s | x1.17 | x0.10 | x0.85 | x1.30 | x2.05 |
| `C5-regex-json-planted` | all | 2.7 s | x0.67 | x0.29 | x0.79 | x0.73 | x1.13 |
| `C5b-regex-json-cold` | 1h | 3.7 ms | x0.74 | x0.50 | x5.74 | x0.88 | x1.22 |
| `C5b-regex-json-cold` | 24h | 345 ms | x0.16 | x0.56 | x1.72 | x0.15 | x1.00 |
| `C5b-regex-json-cold` | 7d | 2.9 s | x0.77 | x0.51 | x1.54 | x0.74 | x1.10 |
| `C5b-regex-json-cold` | au-dela-7d | 3.2 s | x0.80 | x0.23 | x0.81 | x0.80 | x1.50 |
| `C5b-regex-json-cold` | all | 2.4 s | x1.13 | x0.32 | x1.25 | x0.86 | x1.82 |
| `C5c-eq-json-hot` | 1h | 4.6 ms | x0.49 | x0.16 | x0.43 | x0.76 | x0.61 |
| `C5c-eq-json-hot` | 24h | 3.3 ms | x0.48 | x0.22 | x0.49 | x0.62 | x0.99 |
| `C5c-eq-json-hot` | 7d | 1.8 ms | x1.06 | x0.44 | x0.78 | x1.16 | x1.70 |
| `C5c-eq-json-hot` | au-dela-7d | 2.2 ms | x0.88 | x0.31 | x0.56 | x0.95 | x1.65 |
| `C5c-eq-json-hot` | all | 1.0 ms | x1.06 | x0.77 | x0.83 | x1.43 | x0.98 |
| `C0-plancher` | 1h | 0.8 ms | x1.07 | x0.93 | x1.46 | x1.01 | x1.56 |
| `C0-plancher` | 24h | 0.8 ms | x0.92 | x0.96 | x1.36 | x1.08 | x1.24 |
| `C0-plancher` | 7d | 0.8 ms | x0.96 | x0.89 | x1.07 | x1.10 | x0.92 |
| `C0-plancher` | au-dela-7d | 0.9 ms | x0.85 | x0.92 | x1.06 | x0.76 | x0.94 |
| `C0-plancher` | all | 1.0 ms | x0.84 | x0.83 | x1.02 | x1.05 | x0.73 |
| `C2d-free-term-rows` | 1h | 3.0 ms | x1.11 | x0.95 | x0.90 | x1.08 | x0.85 |
| `C2d-free-term-rows` | 24h | 70 ms | x4.41 | x2.80 | x3.93 | x4.42 | x5.07 |
| `C2d-free-term-rows` | 7d | 2.1 s | x0.93 | x0.41 | x0.74 | x1.23 | x1.26 |
| `C2d-free-term-rows` | au-dela-7d | 1472 ms | x1.03 | x0.16 | x0.99 | x1.10 | x2.23 |
| `C2d-free-term-rows` | all | 1506 ms | x1.10 | x0.15 | x0.92 | x1.06 | x1.94 |
| `C2e-free-term-common` | 1h | 1.8 ms | x1.19 | x0.85 | x1.10 | x1.15 | x1.22 |
| `C2e-free-term-common` | 24h | 36 ms | x0.84 | x0.75 | x0.80 | x0.70 | x1.27 |
| `C2e-free-term-common` | 7d | 241 ms | x8.23 | x6.63 | x0.81 | x7.45 | x19.89 |
| `C2e-free-term-common` | au-dela-7d | 1481 ms | x0.96 | x0.61 | x0.96 | x1.00 | x2.16 |
| `C2e-free-term-common` | all | 1454 ms | x1.03 | x0.54 | x1.13 | x1.04 | x1.84 |
| `C4d-keyset-projete` | 1h | 2.2 ms | x0.82 | x0.78 | x4.22 | x1.00 | x1.30 |
| `C4d-keyset-projete` | 24h | 2.1 ms | x1.03 | x0.84 | x3.58 | x1.01 | x1.14 |
| `C4d-keyset-projete` | 7d | 2.4 ms | x0.80 | x0.78 | x3.81 | x0.88 | x1.22 |
| `C4d-keyset-projete` | au-dela-7d | 1.7 ms | x1.16 | x1.23 | x5.23 | x1.32 | x1.79 |
| `C4d-keyset-projete` | all | 2.1 ms | x0.88 | x0.86 | x3.57 | x0.89 | x1.14 |
| `C6-filter-host` | 1h | 1.8 ms | x0.78 | x0.83 | x0.85 | x0.70 | x1.09 |
| `C6-filter-host` | 24h | 9.9 ms | x2.11 | x19.03 | x0.78 | x0.76 | x1.10 |
| `C6-filter-host` | 7d | 8.3 ms | **x220.58** | x1.13 | x0.82 | x0.94 | x1.00 |
| `C6-filter-host` | au-dela-7d | 8.4 ms | **x138.72** | x1.15 | x0.92 | x0.95 | x0.87 |
| `C6-filter-host` | all | 1.8 ms | x23.29 | x1.03 | x0.72 | x0.83 | x0.66 |
| `C6b-groupby-host` | 1h | 2.1 ms | x1.25 | x0.82 | x0.86 | x1.09 | x0.74 |
| `C6b-groupby-host` | 24h | 324 ms | x0.80 | x0.68 | x0.09 | x1.01 | x0.86 |
| `C6b-groupby-host` | 7d | 7.8 s | x0.17 | x0.32 | x0.98 | x1.40 | x1.34 |
| `C6b-groupby-host` | au-dela-7d | 10.1 s | x0.13 | x0.61 | x0.84 | x0.89 | x1.15 |
| `C6b-groupby-host` | all | 58 ms | x0.97 | x1.01 | x1.20 | x0.94 | x0.88 |
| `C6c-raw-one-host` | 1h | 2.5 ms | x0.86 | x0.75 | x1.23 | x0.47 | x0.67 |
| `C6c-raw-one-host` | 24h | 15 ms | x0.11 | x0.99 | x1.10 | x0.80 | x1.03 |
| `C6c-raw-one-host` | 7d | 12 ms | x0.18 | x1.10 | x0.77 | x0.81 | x0.99 |
| `C6c-raw-one-host` | au-dela-7d | 11 ms | x0.21 | x1.06 | x0.92 | x0.91 | x1.22 |
| `C6c-raw-one-host` | all | 10 ms | x0.15 | x1.23 | x1.00 | x1.13 | x1.30 |

### Ce que ça donne, axe par axe

| Axe | Cellules comparables | Hors bande de bruit | Part |
|---|---:|---:|---:|
| `flotte-1h-v2@0.6M` (hosts) | 105 | 3 | 3 % |
| `flotte-50h-v2@0.6M` (hosts) | 105 | 4 | 4 % |
| `card-haute@0.6M` (ext_card_scale) | 105 | 2 | 2 % |
| `sev-haute@0.6M` (severity_shift) | 105 | 2 | 2 % |
| `taille-grande@0.6M` (event_size_scale) | 105 | 1 | 1 % |

Une part élevée veut dire : **sur cet axe, nos chiffres ne se transposent pas**. Un tiers dont
le jeu diffère de nous sur ce paramètre n'obtiendra pas nos latences, et l'écart n'est pas un
artefact de mesure puisqu'il sort de la bande mesurée sur une répétition à l'identique.

## Le budget de 2 Gio

RSS crête la plus haute observée, toutes cellules confondues : **1097 Mio** (53.5 % du budget de 2 Gio).

**Aucune cellule n'a dépassé 2 Gio**, et ce n'est pas une déduction : le daemon tournait
dans un scope `MemoryMax=2G MemorySwapMax=0`, où un dépassement se traduit par un kill du
noyau, pas par du swap. Il n'a pas été tué.

## La concurrence — ce que le nœud fait quand l'équipe travaille en même temps

Tout le reste de ce document est pris **une requête à la fois** : aucune requête n'y attend
son tour, et le document le disait lui-même. Cette section mesure l'autre condition, la
vraie : plusieurs analystes qui lancent de **très grosses** requêtes en même temps, sur la
même base et sous le **même budget appliqué** de 2 Gio.

**Un niveau** = *N* analystes indépendants (chacun sa connexion HTTP, chacun son compte
`viewer`), chacun parcourant le mélange plusieurs fois, en décalant son point de départ — deux
voisins ne tirent donc pas la même requête au même instant. Le niveau se termine quand tous ont
fini leur travail : le débit agrégé est du travail RÉELLEMENT servi, pas une extrapolation.

**L'ordre des questions est délibéré : la justesse d'abord.** Trois défauts de correction
viennent d'être trouvés dans les chemins d'agrégat de ce produit, et aucun n'était visible sur
un banc de latence. Chaque réponse concurrente est donc comparée **par sa valeur** à la réponse
obtenue seul — même base, même binaire, même fenêtre — avant qu'on ne regarde un seul temps.

### Le mélange, et pourquoi c'est celui-là

Le mélange n'est pas une liste de goûts : il est **dérivé de la passe solo qui le
précède**. Le PLANCHER est la requête la moins chère observée (`C0-plancher`,
0.7 ms) — c'est le coût FIXE d'une requête, pas du travail de base.
Chaque **famille** de la matrice (les classes `C1`…`C6` de ce document) entre par son
représentant le plus coûteux, et seulement s'il coûte au moins **10 ×**
le plancher. La famille du plancher échoue ainsi à son propre test et s'exclut d'elle-même.
Le plancher est ensuite ajouté **à part** : il ne charge rien, il mesure ce que devient le
clic instantané d'un tableau de bord pendant que les collègues lancent des monstres.

| Classe retenue | Famille | Ce que c'est | Coût SEUL (p50) |
|---|:--:|---|---:|
| `C1b-scan-agg-dc` | 1 | scan filtré + dc() sur colonne réelle | 7315 ms |
| `C2b-regex-msg` | 2 | regex sur message (REGEXP, UDF Rust) | 4053 ms |
| `C3-groupby-hi` | 3 | group-by 3 dims haute cardinalité (src_ip,host,source) | 9539 ms |
| `C4b-raw-deep` | 4 | RAW paginé page profonde (offset 200 000) | 348 ms |
| `C5-regex-json-planted` | 5 | regex sur champ ÉTENDU planté (fields.needle) | 4825 ms |
| `C6b-groupby-host` | 6 | group-by sur host (autant de groupes que de machines) | 332 ms |
| `C0-plancher` | 0 | PLANCHER : seek sur une source inexistante (0 ligne) | 0.7 ms |

Familles **écartées** du mélange lourd, avec leur motif mesuré :

- famille 0 (`C0-plancher`) : le plus coûteux de la famille 0 ne fait que 1.0 x le plancher (seuil 10).

**Mise au repos avant de mesurer** : un daemon qui vient de démarrer lance un `ANALYZE`
complet en arrière-plan, qui prend le verrou d'écriture et consomme disque et CPU —
mesurer tout de suite, c'est mesurer le démarrage.
Le harnais attend donc 3 tirs consécutifs dont l'attente avant moteur est
sous la milliseconde : **10.0 s** ici
(`quiescent=true`).

### La courbe — `conc-sem3@1.4M` (`PLUME_QUERY_CONCURRENCY=3`)

Sémaphore **3**, déclaré par le daemon (/api/system/diag). Fenêtre `all` (sans borne : le cas le plus coûteux). 3 passages par analyste sur 7 classes.

Mélange **DÉRIVÉ** par la passe solo de cette configuration (tableau plus haut).

| Analystes | file possible | requêtes | durée | débit | p50 | p95 | pire | p50 du pire analyste | attente PERMIT p50 | attente PERMIT p95 | RSS crête | plafond touché | OOM |
|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:--:|
| **1** | non | 21/21 | 72 s | 0.29 q/s (x1.00) | 2785 | 10.4 s | 12.9 s | 2785 | 0.1 | 1213 | 1026 Mio | 0 | non |
| **2** | non | 42/42 | 80 s | 0.53 q/s (x1.81) | 2930 | 13.7 s | 14.2 s | 2930 | 0.1 | 2.4 | 1114 Mio | 0 | non |
| **3** | non | 63/63 | 93 s | 0.68 q/s (x2.33) | 3751 | 14.7 s | 19.8 s | 3783 | 0.2 | 804 | 1069 Mio | 0 | non |
| **4** | oui | 84/84 | 126 s | 0.67 q/s (x2.29) | 4646 | 14.3 s | 19.8 s | 5417 | 542 | 5419 | 1161 Mio | 1 223 | non |
| **6** | oui | 126/126 | 170 s | 0.74 q/s (x2.55) | 7206 | 17.5 s | 24.5 s | 7587 | 3007 | 9474 | 1173 Mio | 3 341 | non |
| **8** | oui | 168/168 | 231 s | 0.73 q/s (x2.50) | 9763 | 19.5 s | 30.1 s | 12.3 s | 5985 | 12.0 s | 1186 Mio | 5 022 | non |
| **10** | oui | 210/210 | 300 s | 0.70 q/s (x2.40) | 13.3 s | 27.2 s | 34.0 s | 16.6 s | 9156 | 18.5 s | 1320 Mio | 30 250 | non |

Colonnes : *durée* = temps mur du niveau entier ; *débit* = requêtes servies par seconde
(entre parenthèses, le rapport au niveau 1 de la même passe) ; *p50/p95/pire* portent sur
**toutes** les requêtes du niveau ; *p50 du pire analyste* est le pire des médians
individuels — c'est lui qui dit si la charge est équitable ; *attente PERMIT* est le temps
passé à faire la queue au sémaphore, et RIEN d'autre (le temps passé à attendre le verrou
de la connexion partagée est publié séparément, plus bas) ; *plafond touché* est le
compteur `memory.events:max` du cgroup, c'est-à-dire le nombre de fois où le noyau a dû
récupérer de la mémoire pour rester sous 2 Gio pendant ce niveau.

*Charger le daemon, pas la machine* : l'instrument lui-même n'a jamais consommé plus de
**1.1 %** d'un cœur-seconde par seconde de mesure sur cette passe — la latence
mesurée n'est donc pas la sienne. Le daemon, lui, est enfermé dans son cgroup à 2 Gio
sans swap : les deux pressions sont relevées séparément (`pressure_*` dans le JSONL).

### La courbe — `conc-sem8@1.4M` (`PLUME_QUERY_CONCURRENCY=8`)

Sémaphore **8**, déclaré par le daemon (/api/system/diag). Fenêtre `all` (sans borne : le cas le plus coûteux). 3 passages par analyste sur 7 classes.

Mélange **IMPOSÉ** (celui de la passe de référence), pour que la comparaison entre sémaphores ne porte que sur le sémaphore. Sa propre passe solo aurait dérivé un mélange différent de 2 classe(s) : `C5-regex-json-planted`, `C5b-regex-json-cold` — c'est précisément ce que l'imposition neutralise.

| Analystes | file possible | requêtes | durée | débit | p50 | p95 | pire | p50 du pire analyste | attente PERMIT p50 | attente PERMIT p95 | RSS crête | plafond touché | OOM |
|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:--:|
| **1** | non | 21/21 | 82 s | 0.26 q/s (x1.00) | 3915 | 12.5 s | 12.6 s | 3915 | 0.1 | 0.4 | 1015 Mio | 0 | non |
| **2** | non | 42/42 | 89 s | 0.47 q/s (x1.84) | 4066 | 13.6 s | 16.7 s | 4153 | 0.2 | 0.9 | 1220 Mio | 8 283 | non |
| **3** | non | 63/63 | 102 s | 0.61 q/s (x2.41) | 4797 | 15.9 s | 18.4 s | 5048 | 0.2 | 2148 | 1430 Mio | 15 381 | non |
| **4** | non | 84/84 | 142 s | 0.59 q/s (x2.32) | 5555 | 20.2 s | 28.2 s | 5804 | 0.2 | 2057 | 1442 Mio | 94 243 | non |
| **6** | non | 126/126 | 183 s | 0.69 q/s (x2.70) | 7721 | 26.4 s | 27.2 s | 9026 | 0.2 | 6335 | 1589 Mio | 175 777 | non |
| **8** | non | 168/168 | 299 s | 0.56 q/s (x2.21) | 9039 | 46.7 s | 52.3 s | 10.1 s | 0.3 | 4705 | 2025 Mio | 244 846 | non |
| **10** | oui | 148/210 — **daemon TUÉ** | 460 s | 0.32 q/s (x1.26) | 15.5 s | 50.1 s | 89.5 s | 24.6 s | 2044 | 16.7 s | 2045 Mio | — (cgroup disparu) | non |

Requêtes qui n'ont pas abouti, par statut HTTP :

| Analystes | statuts | messages |
|---:|---|---|
| 10 | `0` x45, `200` x148, `400` x17 | `RemoteDisconnected: Remote end closed connection without response`<br>`URLError: <urlopen error [Errno 111] Connection refused>`<br>`{"error":"requête interrompue (budget 60 s dépassé)"}` |

`0` = pas de réponse HTTP du tout (connexion coupée / refusée) : c'est ce que voit un
client quand le processus n'est plus là. Un `4xx` avec une cause nommée est l'inverse :
le daemon a REFUSÉ proprement, en disant pourquoi.

Colonnes : *durée* = temps mur du niveau entier ; *débit* = requêtes servies par seconde
(entre parenthèses, le rapport au niveau 1 de la même passe) ; *p50/p95/pire* portent sur
**toutes** les requêtes du niveau ; *p50 du pire analyste* est le pire des médians
individuels — c'est lui qui dit si la charge est équitable ; *attente PERMIT* est le temps
passé à faire la queue au sémaphore, et RIEN d'autre (le temps passé à attendre le verrou
de la connexion partagée est publié séparément, plus bas) ; *plafond touché* est le
compteur `memory.events:max` du cgroup, c'est-à-dire le nombre de fois où le noyau a dû
récupérer de la mémoire pour rester sous 2 Gio pendant ce niveau.

*Charger le daemon, pas la machine* : l'instrument lui-même n'a jamais consommé plus de
**1.4 %** d'un cœur-seconde par seconde de mesure sur cette passe — la latence
mesurée n'est donc pas la sienne. Le daemon, lui, est enfermé dans son cgroup à 2 Gio
sans swap : les deux pressions sont relevées séparément (`pressure_*` dans le JSONL).

### La courbe — `conc-sem3-rouge@1.4M` (`PLUME_QUERY_CONCURRENCY=3`)

Sémaphore **3**, déclaré par le daemon (/api/system/diag). Fenêtre `all` (sans borne : le cas le plus coûteux). 1 passages par analyste sur 7 classes.

Mélange **DÉRIVÉ** par la passe solo de cette configuration (tableau plus haut).

| Analystes | file possible | requêtes | durée | débit | p50 | p95 | pire | p50 du pire analyste | attente PERMIT p50 | attente PERMIT p95 | RSS crête | plafond touché | OOM |
|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:--:|
| **1** | non | 7/7 | 23 s | 0.31 q/s (x1.00) | 1707 | 7754 | 7754 | 1707 | 0.2 | 3348 | 1195 Mio | 6 433 | non |
| **4** | oui | 28/28 | 39 s | 0.72 q/s (x2.35) | 4655 | 8880 | 9026 | 6515 | 437 | 5124 | 1196 Mio | 14 905 | non |

Colonnes : *durée* = temps mur du niveau entier ; *débit* = requêtes servies par seconde
(entre parenthèses, le rapport au niveau 1 de la même passe) ; *p50/p95/pire* portent sur
**toutes** les requêtes du niveau ; *p50 du pire analyste* est le pire des médians
individuels — c'est lui qui dit si la charge est équitable ; *attente PERMIT* est le temps
passé à faire la queue au sémaphore, et RIEN d'autre (le temps passé à attendre le verrou
de la connexion partagée est publié séparément, plus bas) ; *plafond touché* est le
compteur `memory.events:max` du cgroup, c'est-à-dire le nombre de fois où le noyau a dû
récupérer de la mémoire pour rester sous 2 Gio pendant ce niveau.

*Charger le daemon, pas la machine* : l'instrument lui-même n'a jamais consommé plus de
**1.1 %** d'un cœur-seconde par seconde de mesure sur cette passe — la latence
mesurée n'est donc pas la sienne. Le daemon, lui, est enfermé dans son cgroup à 2 Gio
sans swap : les deux pressions sont relevées séparément (`pressure_*` dans le JSONL).

### La courbe — `conc-sem3-attribue@1.4M` (`PLUME_QUERY_CONCURRENCY=3`)

Sémaphore **3**, déclaré par le daemon (/api/system/diag). Fenêtre `all` (sans borne : le cas le plus coûteux). 1 passages par analyste sur 7 classes.

Mélange **DÉRIVÉ** par la passe solo de cette configuration (tableau plus haut).

| Analystes | file possible | requêtes | durée | débit | p50 | p95 | pire | p50 du pire analyste | attente PERMIT p50 | attente PERMIT p95 | RSS crête | plafond touché | OOM |
|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:--:|
| **1** | non | 7/7 | 29 s | 0.24 q/s (x1.00) | 3347 | 9948 | 9948 | 3347 | 0.0 | 0.0 | 732 Mio | 0 | non |
| **4** | oui | 28/28 | 43 s | 0.66 q/s (x2.69) | 3721 | 13.9 s | 15.0 s | 5344 | 447 | 4513 | 819 Mio | 0 | non |

Colonnes : *durée* = temps mur du niveau entier ; *débit* = requêtes servies par seconde
(entre parenthèses, le rapport au niveau 1 de la même passe) ; *p50/p95/pire* portent sur
**toutes** les requêtes du niveau ; *p50 du pire analyste* est le pire des médians
individuels — c'est lui qui dit si la charge est équitable ; *attente PERMIT* est le temps
passé à faire la queue au sémaphore, et RIEN d'autre (le temps passé à attendre le verrou
de la connexion partagée est publié séparément, plus bas) ; *plafond touché* est le
compteur `memory.events:max` du cgroup, c'est-à-dire le nombre de fois où le noyau a dû
récupérer de la mémoire pour rester sous 2 Gio pendant ce niveau.

**2 niveau(x) pris pendant que la MACHINE swappait** (1, 4 analystes) : ces lignes mesurent le
stockage de l'hôte autant que plume, elles sont à rejouer.

*Charger le daemon, pas la machine* : l'instrument lui-même n'a jamais consommé plus de
**1.1 %** d'un cœur-seconde par seconde de mesure sur cette passe — la latence
mesurée n'est donc pas la sienne. Le daemon, lui, est enfermé dans son cgroup à 2 Gio
sans swap : les deux pressions sont relevées séparément (`pressure_*` dans le JSONL).

### La courbe — `conc-sem3-corrige@1.4M` (`PLUME_QUERY_CONCURRENCY=3`)

Sémaphore **3**, déclaré par le daemon (/api/system/diag). Fenêtre `all` (sans borne : le cas le plus coûteux). 3 passages par analyste sur 7 classes.

Mélange **IMPOSÉ** (celui de la passe de référence), pour que la comparaison entre sémaphores ne porte que sur le sémaphore. Sa propre passe solo aurait dérivé un mélange différent de 6 classe(s) : `C2b-regex-msg`, `C2d-free-term-rows`, `C5-regex-json-planted`, `C5b-regex-json-cold`, `C6b-groupby-host`, `C6c-raw-one-host` — c'est précisément ce que l'imposition neutralise.

| Analystes | file possible | requêtes | durée | débit | p50 | p95 | pire | p50 du pire analyste | attente PERMIT p50 | attente PERMIT p95 | RSS crête | plafond touché | OOM |
|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:--:|
| **1** | non | 21/21 | 81 s | 0.26 q/s (x1.00) | 3319 | 12.4 s | 13.3 s | 3319 | 0.0 | 0.0 | 826 Mio | 0 | non |
| **2** | non | 42/42 | 88 s | 0.48 q/s (x1.85) | 3931 | 12.4 s | 13.8 s | 3931 | 0.0 | 0.0 | 873 Mio | 0 | non |
| **3** | non | 63/63 | 93 s | 0.68 q/s (x2.61) | 3460 | 14.0 s | 15.0 s | 3641 | 0.0 | 0.0 | 858 Mio | 0 | non |
| **4** | oui | 84/84 | 120 s | 0.70 q/s (x2.71) | 4267 | 14.6 s | 19.8 s | 4452 | 459 | 4475 | 908 Mio | 0 | non |
| **6** | oui | 126/126 | 169 s | 0.75 q/s (x2.88) | 6860 | 17.2 s | 27.2 s | 7391 | 3391 | 9144 | 984 Mio | 1 580 | non |
| **8** | oui | 168/168 | 234 s | 0.72 q/s (x2.78) | 9518 | 20.8 s | 28.2 s | 11.0 s | 5940 | 12.8 s | 1039 Mio | 6 327 | non |
| **10** | oui | 210/210 | 362 s | 0.58 q/s (x2.24) | 16.2 s | 30.6 s | 37.1 s | 17.4 s | 12.1 s | 18.6 s | 1243 Mio | 170 949 | non |

Colonnes : *durée* = temps mur du niveau entier ; *débit* = requêtes servies par seconde
(entre parenthèses, le rapport au niveau 1 de la même passe) ; *p50/p95/pire* portent sur
**toutes** les requêtes du niveau ; *p50 du pire analyste* est le pire des médians
individuels — c'est lui qui dit si la charge est équitable ; *attente PERMIT* est le temps
passé à faire la queue au sémaphore, et RIEN d'autre (le temps passé à attendre le verrou
de la connexion partagée est publié séparément, plus bas) ; *plafond touché* est le
compteur `memory.events:max` du cgroup, c'est-à-dire le nombre de fois où le noyau a dû
récupérer de la mémoire pour rester sous 2 Gio pendant ce niveau.

*Charger le daemon, pas la machine* : l'instrument lui-même n'a jamais consommé plus de
**1.1 %** d'un cœur-seconde par seconde de mesure sur cette passe — la latence
mesurée n'est donc pas la sienne. Le daemon, lui, est enfermé dans son cgroup à 2 Gio
sans swap : les deux pressions sont relevées séparément (`pressure_*` dans le JSONL).

### La courbe — `conc-sem8-corrige@1.4M` (`PLUME_QUERY_CONCURRENCY=8`)

Sémaphore **8**, déclaré par le daemon (/api/system/diag). Fenêtre `all` (sans borne : le cas le plus coûteux). 3 passages par analyste sur 7 classes.

Mélange **IMPOSÉ** (celui de la passe de référence), pour que la comparaison entre sémaphores ne porte que sur le sémaphore. Sa propre passe solo aurait dérivé un mélange différent de 2 classe(s) : `C5-regex-json-planted`, `C5b-regex-json-cold` — c'est précisément ce que l'imposition neutralise.

| Analystes | file possible | requêtes | durée | débit | p50 | p95 | pire | p50 du pire analyste | attente PERMIT p50 | attente PERMIT p95 | RSS crête | plafond touché | OOM |
|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:--:|
| **1** | non | 21/21 | 87 s | 0.24 q/s (x1.00) | 3941 | 13.8 s | 14.2 s | 3941 | 0.0 | 0.0 | 992 Mio | 0 | non |
| **2** | non | 42/42 | 86 s | 0.49 q/s (x2.04) | 3574 | 12.6 s | 14.6 s | 3574 | 0.0 | 0.0 | 1217 Mio | 399 | non |
| **3** | non | 63/63 | 86 s | 0.73 q/s (x3.04) | 3620 | 14.1 s | 14.3 s | 3972 | 0.0 | 0.0 | 1198 Mio | 1 868 | non |
| **4** | non | 84/84 | 113 s | 0.75 q/s (x3.09) | 5143 | 16.8 s | 20.2 s | 5706 | 0.0 | 0.0 | 1318 Mio | 25 736 | non |
| **6** | non | 126/126 | 174 s | 0.72 q/s (x3.00) | 7480 | 27.9 s | 29.9 s | 8060 | 0.0 | 0.0 | 1615 Mio | 146 803 | non |
| **8** | non | 168/168 | 270 s | 0.62 q/s (x2.58) | 9906 | 41.7 s | 48.1 s | 11.3 s | 0.0 | 0.0 | 2035 Mio | 392 993 | non |
| **10** | oui | 210/210 | 351 s | 0.60 q/s (x2.48) | 12.4 s | 50.1 s | 56.9 s | 14.1 s | 1562 | 9331 | 2035 Mio | 892 090 | non |

Colonnes : *durée* = temps mur du niveau entier ; *débit* = requêtes servies par seconde
(entre parenthèses, le rapport au niveau 1 de la même passe) ; *p50/p95/pire* portent sur
**toutes** les requêtes du niveau ; *p50 du pire analyste* est le pire des médians
individuels — c'est lui qui dit si la charge est équitable ; *attente PERMIT* est le temps
passé à faire la queue au sémaphore, et RIEN d'autre (le temps passé à attendre le verrou
de la connexion partagée est publié séparément, plus bas) ; *plafond touché* est le
compteur `memory.events:max` du cgroup, c'est-à-dire le nombre de fois où le noyau a dû
récupérer de la mémoire pour rester sous 2 Gio pendant ce niveau.

*Charger le daemon, pas la machine* : l'instrument lui-même n'a jamais consommé plus de
**1.4 %** d'un cœur-seconde par seconde de mesure sur cette passe — la latence
mesurée n'est donc pas la sienne. Le daemon, lui, est enfermé dans son cgroup à 2 Gio
sans swap : les deux pressions sont relevées séparément (`pressure_*` dans le JSONL).

### La réponse est-elle la MÊME sous charge ?

| | |
|---|---:|
| Réponses comparées à leur référence solo | **2 864** |
| Identiques (empreinte ET total) | **2 859** |
| Divergentes | **5** |
| Dont NOMBRES FAUX (valeur dérivée d'un ensemble) | **5** |
| Hors verdict (voir ci-dessous) | 62 |

Les 62 réponses hors verdict sont EXACTEMENT les 62 requêtes qui n'ont pas abouti (connexion coupée après le kill, ou refus nommé) : une requête sans réponse n'a rien à comparer. Aucune n'est hors verdict pour cause d'instabilité — le compte le prouve, il n'est pas affirmé.

**Des réponses concurrentes diffèrent de la réponse obtenue seul.** Le détail est dans le
JSONL (`justesse.divergences` : empreinte et valeurs des deux côtés) :

| Passe | Analystes | Classe | Dérivée d'un ensemble | Solo | Sous charge |
|---|---:|---|:--:|---|---|
| `conc-sem3-attribue@1.4M` | 1 | `C2-free-term` | **OUI** | `[[1438]]` | `[[1437]]` |
| `conc-sem3-attribue@1.4M` | 4 | `C2-free-term` | **OUI** | `[[1438]]` | `[[1437]]` |
| `conc-sem3-attribue@1.4M` | 4 | `C2-free-term` | **OUI** | `[[1438]]` | `[[1437]]` |
| `conc-sem3-attribue@1.4M` | 4 | `C2-free-term` | **OUI** | `[[1438]]` | `[[1437]]` |
| `conc-sem3-attribue@1.4M` | 4 | `C2-free-term` | **OUI** | `[[1438]]` | `[[1437]]` |

**Aucune classe n'a été retirée du verdict** : chacune rend la même réponse à chacune de ses
répétitions SEUL, donc chacune est comparable sous charge. C'est vérifié, pas supposé.

### L'attente d'un permit, séparée de ce qui n'en est pas

C'est le champ `sem_wait_ms` que le daemon publie pour séparer « la requête est lente » de
« la requête attendait son tour ». La campagne précédente a montré **qu'il ne le faisait pas**,
et la démonstration ne demandait aucun seuil : tant qu'il y a **au moins autant de permis que
d'analystes**, aucune requête ne peut attendre son tour. À ces niveaux, l'attente d'un permit
est nulle *par construction* — toute valeur non nulle y est nécessairement autre chose.

| Passe | Analystes | Permis | File possible ? | découpage publié ? | attente PERMIT p95 | attente PERMIT max |
|---|---:|---:|:--:|:--:|---:|---:|
| `conc-sem3@1.4M` | 1 | 3 | **non** | **non** | 1213 | **2029** |
| `conc-sem3@1.4M` | 2 | 3 | **non** | **non** | 2.4 | **1491** |
| `conc-sem3@1.4M` | 3 | 3 | **non** | **non** | 804 | **3386** |
| `conc-sem8@1.4M` | 1 | 8 | **non** | **non** | 0.4 | **2287** |
| `conc-sem8@1.4M` | 2 | 8 | **non** | **non** | 0.9 | **4174** |
| `conc-sem8@1.4M` | 3 | 8 | **non** | **non** | 2148 | **3549** |
| `conc-sem8@1.4M` | 4 | 8 | **non** | **non** | 2057 | **8107** |
| `conc-sem8@1.4M` | 6 | 8 | **non** | **non** | 6335 | **10.1 s** |
| `conc-sem8@1.4M` | 8 | 8 | **non** | **non** | 4705 | **10.2 s** |
| `conc-sem3-rouge@1.4M` | 1 | 3 | **non** | **non** | 3348 | **3348** |
| `conc-sem3-attribue@1.4M` | 1 | 3 | **non** | oui | 0.0 | **0.0** |
| `conc-sem3-corrige@1.4M` | 1 | 3 | **non** | oui | 0.0 | **0.0** |
| `conc-sem3-corrige@1.4M` | 2 | 3 | **non** | oui | 0.0 | **0.0** |
| `conc-sem3-corrige@1.4M` | 3 | 3 | **non** | oui | 0.0 | **0.0** |
| `conc-sem8-corrige@1.4M` | 1 | 8 | **non** | oui | 0.0 | **0.0** |
| `conc-sem8-corrige@1.4M` | 2 | 8 | **non** | oui | 0.0 | **0.0** |
| `conc-sem8-corrige@1.4M` | 3 | 8 | **non** | oui | 0.0 | **0.0** |
| `conc-sem8-corrige@1.4M` | 4 | 8 | **non** | oui | 0.0 | **0.0** |
| `conc-sem8-corrige@1.4M` | 6 | 8 | **non** | oui | 0.0 | **0.0** |
| `conc-sem8-corrige@1.4M` | 8 | 8 | **non** | oui | 0.0 | **0.0** |

**Avant le découpage** : le maximum observé là où aucune file n'est possible est de
**10.2 s** en charge sous-critique, et de **16.5 s** pendant la
passe solo (un seul client, aucun autre en vol). Un sémaphore avec des permis libres ne
peut pas produire ça : le champ mesurait autre chose que son nom, et son nom envoie
l'exploitant AUGMENTER le sémaphore — la seule action que la section précédente mesure
comme nuisible (débit ×0,46, p95 27 s → 50 s, RSS +725 Mio, daemon tué à 10 analystes).

**Après : zéro partout.** Là où aucune file n'est possible, l'attente publiée est nulle —
pas « petite » : nulle, à la microseconde de résolution du champ. Ce n'est pas une mesure
qui a bien voulu tomber juste : quand un permit est libre il est pris sans jamais
suspendre la tâche, et la valeur publiée est le zéro CONSTANT
(`daemon/src/query_timing.rs`) — aucune horloge n'intervient sur ce chemin, donc rien ne
peut la contaminer. La propriété « autant de permis que de clients ⇒ aucune attente » a
cessé d'être une mesure à vérifier pour devenir la construction de la valeur, et le
harnais SORT EN ERREUR si elle est violée au lieu de publier le chiffre.

#### Où passe le temps, maintenant qu'il est découpé

Le champ ne pouvait pas être corrigé en le déplaçant : ce qu'il additionnait devait être
**séparé**, sinon la part cachée serait simplement retombée ailleurs. Le daemon publie donc
un découpage TOTAL — `prepare + sem_wait + exec == server` par construction, `exec` étant le
reste et jamais une troisième horloge :

| champ | ce qu'il mesure |
|---|---|
| `prepare_ms` | avant le permit : corps, masques, **couverture des rollups**, compilation |
| `sem_wait_ms` | l'attente du PERMIT, et rien d'autre |
| `db_lock_wait_ms` | le temps passé à **obtenir** le verrou de la connexion PARTAGÉE (pas celui passé à le tenir) |
| `exec_ms` | le reste : l'exécution |

| Passe | Analystes | file ? | avant moteur p50 | avant moteur p95 | **verrou partagé** p50 | **verrou partagé** max | permit p95 | mur p95 |
|---|---:|:--:|---:|---:|---:|---:|---:|---:|
| `conc-sem3-attribue@1.4M` | 1 | non | 0.1 | 2876 | **0.0** | **2876** | 0.0 | 9948 |
| `conc-sem3-attribue@1.4M` | 4 | oui | 654 | 4517 | **0.0** | **4142** | 4513 | 13.9 s |
| `conc-sem3-corrige@1.4M` | 1 | non | 0.2 | 20 | **0.0** | **0.0** | 0.0 | 12.4 s |
| `conc-sem3-corrige@1.4M` | 2 | non | 1.1 | 11 | **0.0** | **0.0** | 0.0 | 12.4 s |
| `conc-sem3-corrige@1.4M` | 3 | non | 0.3 | 20 | **0.0** | **0.0** | 0.0 | 14.0 s |
| `conc-sem3-corrige@1.4M` | 4 | oui | 459 | 4475 | **0.0** | **0.0** | 4475 | 14.6 s |
| `conc-sem3-corrige@1.4M` | 6 | oui | 3392 | 9144 | **0.0** | **0.0** | 9144 | 17.2 s |
| `conc-sem3-corrige@1.4M` | 8 | oui | 5961 | 12.8 s | **0.0** | **0.0** | 12.8 s | 20.8 s |
| `conc-sem3-corrige@1.4M` | 10 | oui | 12.1 s | 18.6 s | **0.0** | **0.0** | 18.6 s | 30.6 s |
| `conc-sem8-corrige@1.4M` | 1 | non | 0.4 | 19 | **0.0** | **0.0** | 0.0 | 13.8 s |
| `conc-sem8-corrige@1.4M` | 2 | non | 0.2 | 14 | **0.0** | **0.0** | 0.0 | 12.6 s |
| `conc-sem8-corrige@1.4M` | 3 | non | 0.2 | 17 | **0.0** | **0.0** | 0.0 | 14.1 s |
| `conc-sem8-corrige@1.4M` | 4 | non | 0.7 | 16 | **0.0** | **0.0** | 0.0 | 16.8 s |
| `conc-sem8-corrige@1.4M` | 6 | non | 1.1 | 28 | **0.0** | **0.0** | 0.0 | 27.9 s |
| `conc-sem8-corrige@1.4M` | 8 | non | 1.6 | 51 | **0.0** | **0.0** | 0.0 | 41.7 s |
| `conc-sem8-corrige@1.4M` | 10 | oui | 1562 | 9331 | **0.0** | **0.0** | 9331 | 50.1 s |

**La sérialisation que personne ne voyait.** Le chemin d'une requête interactive lit la
couverture des rollups. Tant que cette lecture prenait le verrou de la connexion
**partagée** — celui-là même que la boucle de rollups tient pendant tout un tick
(`spawn_rollup_loop`, 120 s) et que l'`ANALYZE` de démarrage tient plusieurs minutes —
**aucun sémaphore ne bornait cette attente** : elle avait lieu ailleurs que sur le
sémaphore, et augmenter le sémaphore n'y met que plus de monde.

MESURÉ, verrou en place (`conc-sem3-attribue@1.4M`) :
jusqu'à **4.1 s** sous charge et **3.4 s** en solo — sur le
chemin de CHAQUE requête GXQL, pendant que l'attente de permit, elle, était nulle.

MESURÉ après retrait (`conc-sem3-corrige@1.4M`, `conc-sem8-corrige@1.4M`) :
**zéro**. La lecture de couverture est passée au pool de lecture — mêmes lignes `meta`
commitées, même repli fail-closed vers « rien d'établi », donc le même corps de rollup
servi ou décliné ; seul le verrou disparaît. Le champ reste publié à zéro : une absence
de champ se lirait « je ne sais pas », un zéro se lit « j'ai regardé ».

C'est la lecture qui change une décision : un exploitant qui voit l'attente du permit à
zéro et le verrou partagé non nul sait que son sémaphore n'est pas le levier. Avant le
découpage, les deux étaient dans le même champ, sous le nom du sémaphore.

**Aucune route en angle mort** : toutes les classes tirées ici publient leur découpage, y
compris la barre `/api/search`, qui prend un permit sur le MÊME sémaphore et ne publiait
rien du tout jusqu'à la campagne précédente. Une route invisible à la mesure de concurrence
pèse pourtant dessus : elle consomme les mêmes permis.

### Le clic de tableau de bord, pendant que les autres travaillent

`C0-plancher` est la requête la moins chère de la matrice. Seule, elle est instantanée. Ce
tableau est ce que l'analyste RESSENT : aucune moyenne ne le montre, parce qu'elle est
noyée dans les monstres.

| Passe | Analystes | p50 | p95 | pire |
|---|---:|---:|---:|---:|
| `conc-sem3@1.4M` | 1 | 0.9 | 1.0 | 1.0 |
| `conc-sem3@1.4M` | 2 | 1.0 | 1.2 | 1.2 |
| `conc-sem3@1.4M` | 3 | 1.2 | 7.0 | 7.0 |
| `conc-sem3@1.4M` | 4 | 1610 | 5712 | 5712 |
| `conc-sem3@1.4M` | 6 | 1336 | 11.4 s | 11.4 s |
| `conc-sem3@1.4M` | 8 | 6250 | 13.3 s | 18.1 s |
| `conc-sem3@1.4M` | 10 | 12.8 s | 19.7 s | 20.2 s |
| `conc-sem8@1.4M` | 1 | 0.9 | 1.5 | 1.5 |
| `conc-sem8@1.4M` | 2 | 2.5 | 9.4 | 9.4 |
| `conc-sem8@1.4M` | 3 | 1.0 | 17 | 17 |
| `conc-sem8@1.4M` | 4 | 1.4 | 1571 | 1571 |
| `conc-sem8@1.4M` | 6 | 2.7 | 280 | 280 |
| `conc-sem8@1.4M` | 8 | 7.9 | 32 | 42 |
| `conc-sem8@1.4M` | 10 | 1310 | 19.6 s | 89.5 s |
| `conc-sem3-rouge@1.4M` | 1 | 9.1 | 9.1 | 9.1 |
| `conc-sem3-rouge@1.4M` | 4 | 90 | 5127 | 5127 |
| `conc-sem3-attribue@1.4M` | 1 | 0.9 | 0.9 | 0.9 |
| `conc-sem3-attribue@1.4M` | 4 | 1813 | 1975 | 1975 |
| `conc-sem3-corrige@1.4M` | 1 | 1.0 | 5.5 | 5.5 |
| `conc-sem3-corrige@1.4M` | 2 | 1.5 | 13 | 13 |
| `conc-sem3-corrige@1.4M` | 3 | 1.1 | 7.4 | 7.4 |
| `conc-sem3-corrige@1.4M` | 4 | 573 | 3934 | 3934 |
| `conc-sem3-corrige@1.4M` | 6 | 5231 | 10.7 s | 10.7 s |
| `conc-sem3-corrige@1.4M` | 8 | 6368 | 13.8 s | 13.9 s |
| `conc-sem3-corrige@1.4M` | 10 | 13.0 s | 19.2 s | 20.8 s |
| `conc-sem8-corrige@1.4M` | 1 | 0.9 | 4.2 | 4.2 |
| `conc-sem8-corrige@1.4M` | 2 | 0.9 | 1.3 | 1.3 |
| `conc-sem8-corrige@1.4M` | 3 | 1.1 | 39 | 39 |
| `conc-sem8-corrige@1.4M` | 4 | 1.1 | 20 | 20 |
| `conc-sem8-corrige@1.4M` | 6 | 1.4 | 75 | 75 |
| `conc-sem8-corrige@1.4M` | 8 | 6.6 | 33 | 92 |
| `conc-sem8-corrige@1.4M` | 10 | 2177 | 8417 | 9029 |

### Le budget de 2 Gio, à plusieurs

- **RSS crête du daemon, tous niveaux confondus : 2045 Mio** (100 % du budget).
- **Mémoire du cgroup crête : 2048 Mio** pour un plafond de 2048 Mio.
  Ce n'est pas la même grandeur que la RSS : le noyau compare au plafond la mémoire du CGROUP,
  cache de pages compris. Une base de 1,4 Gio lue en boucle le remplit — le cgroup vit donc
  **collé à son plafond**, et ce qui varie n'est pas son occupation mais son travail de
  récupération.
- **LE BUDGET A CÉDÉ** : `conc-sem8@1.4M`, **10 analystes** (sémaphore 8). RSS crête 2045 Mio contre un plafond de 2048 Mio, 62 requêtes sur 210 n'ont pas abouti, et le processus n'existait plus à la fin du niveau. Sous `MemoryMax` **sans swap**, cela ne peut pas être autre chose qu'un dépassement du budget : le noyau tue, il ne glisse pas en swap. Les niveaux au-delà ne sont **pas** mesurés — une absence, pas un zéro.
- La dégradation n'est pas binaire : AVANT le kill, le daemon a d'abord REFUSÉ proprement des requêtes en nommant sa cause (budget interactif de 60 s dépassé, `4xx`). Le refus nommé arrive donc en premier ; le kill est ce qui suit quand la mémoire, elle, ne négocie pas.
- **Tués par le noyau (`memory.events:oom_kill`) : 0** — compteur du cgroup, à lire avec la réserve ci-dessus : le cgroup d'un scope tué disparaît avec lui, et son compteur n'est alors plus lisible du tout.
- Le harnais a ARRÊTÉ le balayage après le niveau 10 (`conc-sem8@1.4M`) : le daemon n'existe plus après ce niveau : sous MemoryMax sans swap, cela signifie un DÉPASSEMENT DU BUDGET (kill du noyau). Les niveaux suivants ne sont PAS mesurés.

### Ce que coûte, et ce que rapporte, la taille du sémaphore

Le sémaphore de l'interactif est à 3 par défaut, après avoir été baissé depuis 8 **comme
levier de RAM**. Les passes comparées ici tournent sur la MÊME base, la MÊME machine, le
MÊME binaire **et le MÊME mélange de requêtes** : leur écart, à niveau d'analystes égal,
EST le taux de change entre concurrence et mémoire.

**Il est réglable sans recompiler** : `PLUME_QUERY_CONCURRENCY` est lu dans la
configuration au démarrage (`daemon/src/server.rs:254`, défaut 3) et le daemon publie la
valeur qu'il applique sur `/api/system/diag` — c'est de là que ce banc la lit, plutôt que
de la supposer. En revanche il est lu **une seule fois, au boot** : le changer demande un
redémarrage, et un redémarrage a son propre coût (voir la mise au repos plus haut).

**Écartée(s) de cette comparaison** : `conc-sem3@1.4M`, `conc-sem8@1.4M`, `conc-sem3-rouge@1.4M`, `conc-sem3-attribue@1.4M`
— leur mélange OU leur binaire n'est pas celui des autres passes, donc leur écart de
débit ne serait pas attribuable au sémaphore mais au travail ou au code. Leur courbe
reste publiée plus haut ; c'est cette comparaison-ci, et elle seule, qui exige que
tout le reste soit identique.

| Analystes | débit `conc-sem3-corrige@1.4M` | débit `conc-sem8-corrige@1.4M` | écart de débit | p95 `conc-sem3-corrige@1.4M` | p95 `conc-sem8-corrige@1.4M` | RSS `conc-sem3-corrige@1.4M` | RSS `conc-sem8-corrige@1.4M` |
|---:|---:|---:|---:|---:|---:|---:|---:|
| **1** | 0.26 q/s | 0.24 q/s | x0.93 | 12.4 s | 13.8 s | 826 Mio | 992 Mio |
| **2** | 0.48 q/s | 0.49 q/s | x1.03 | 12.4 s | 12.6 s | 873 Mio | 1217 Mio |
| **3** | 0.68 q/s | 0.73 q/s | x1.08 | 14.0 s | 14.1 s | 858 Mio | 1198 Mio |
| **4** | 0.70 q/s | 0.75 q/s | x1.06 | 14.6 s | 16.8 s | 908 Mio | 1318 Mio |
| **6** | 0.75 q/s | 0.72 q/s | x0.97 | 17.2 s | 27.9 s | 984 Mio | 1615 Mio |
| **8** | 0.72 q/s | 0.62 q/s | x0.86 | 20.8 s | 41.7 s | 1039 Mio | 2035 Mio |
| **10** | 0.58 q/s | 0.60 q/s | x1.03 | 30.6 s | 50.1 s | 1243 Mio | 2035 Mio |

**Au niveau le plus chargé mesuré des deux côtés (10 analystes)** : 0.60 contre 0.58 requête/s (**+3 %** de travail servi), p95 50.1 s contre 30.6 s, RSS crête 2035 contre 1243 Mio (**+792 Mio**, soit +38.6 % du budget). Ces six nombres SONT le taux de change entre un sémaphore à 3 et un sémaphore à 8 — celui que la baisse de 8 à 3, faite comme levier de RAM, avait acheté sans jamais être chiffré.

### L'écart avant / après le correctif de métrique

MÊME base, MÊME machine, MÊME sémaphore, MÊME mélange **imposé**, MÊMES niveaux : seul le
BINAIRE change. Ce n'est donc pas une comparaison de configurations, c'est la mesure de ce
qu'un correctif a fait — et les deux colonnes d'attente sont l'essentiel, parce que c'est
là que le défaut vivait.

**Sémaphore 3** — `conc-sem3@1.4M` (2026-08-01, `bin:80a19382ef3d30b8`) contre `conc-sem3-corrige@1.4M` (2026-08-01, `bin:4126d13c2e094bc5`)

| Analystes | file ? | débit avant | débit après | p95 avant | p95 après | attente PERMIT max avant | attente PERMIT max après | verrou partagé max après | RSS avant | RSS après |
|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **1** | non | 0.29 q/s | 0.26 q/s | 10.4 s | 12.4 s | 2029 | 0.0 | 0.0 | 1026 Mio | 826 Mio |
| **2** | non | 0.53 q/s | 0.48 q/s | 13.7 s | 12.4 s | 1491 | 0.0 | 0.0 | 1114 Mio | 873 Mio |
| **3** | non | 0.68 q/s | 0.68 q/s | 14.7 s | 14.0 s | 3386 | 0.0 | 0.0 | 1069 Mio | 858 Mio |
| **4** | oui | 0.67 q/s | 0.70 q/s | 14.3 s | 14.6 s | 5762 | 6020 | 0.0 | 1161 Mio | 908 Mio |
| **6** | oui | 0.74 q/s | 0.75 q/s | 17.5 s | 17.2 s | 12.7 s | 12.6 s | 0.0 | 1173 Mio | 984 Mio |
| **8** | oui | 0.73 q/s | 0.72 q/s | 19.5 s | 20.8 s | 18.1 s | 19.9 s | 0.0 | 1186 Mio | 1039 Mio |
| **10** | oui | 0.70 q/s | 0.58 q/s | 27.2 s | 30.6 s | 24.4 s | 23.0 s | 0.0 | 1320 Mio | 1243 Mio |

**Sémaphore 8** — `conc-sem8@1.4M` (2026-08-01, `bin:80a19382ef3d30b8`) contre `conc-sem8-corrige@1.4M` (2026-08-01, `bin:4126d13c2e094bc5`)

| Analystes | file ? | débit avant | débit après | p95 avant | p95 après | attente PERMIT max avant | attente PERMIT max après | verrou partagé max après | RSS avant | RSS après |
|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **1** | non | 0.26 q/s | 0.24 q/s | 12.5 s | 13.8 s | 2287 | 0.0 | 0.0 | 1015 Mio | 992 Mio |
| **2** | non | 0.47 q/s | 0.49 q/s | 13.6 s | 12.6 s | 4174 | 0.0 | 0.0 | 1220 Mio | 1217 Mio |
| **3** | non | 0.61 q/s | 0.73 q/s | 15.9 s | 14.1 s | 3549 | 0.0 | 0.0 | 1430 Mio | 1198 Mio |
| **4** | non | 0.59 q/s | 0.75 q/s | 20.2 s | 16.8 s | 8107 | 0.0 | 0.0 | 1442 Mio | 1318 Mio |
| **6** | non | 0.69 q/s | 0.72 q/s | 26.4 s | 27.9 s | 10.1 s | 0.0 | 0.0 | 1589 Mio | 1615 Mio |
| **8** | non | 0.56 q/s | 0.62 q/s | 46.7 s | 41.7 s | 10.2 s | 0.0 | 0.0 | 2025 Mio | 2035 Mio |
| **10** | oui | 0.32 q/s | 0.60 q/s | 50.1 s | 50.1 s | 87.5 s | 14.7 s | 0.0 | 2045 Mio | 2035 Mio |

Lire la colonne « file ? » AVANT les colonnes d'attente : là où elle dit **non**, aucune
requête ne PEUT attendre son tour, donc toute attente de permit publiée y est fausse.
La colonne « verrou partagé » est à zéro **parce que la sérialisation a été retirée**
(la lecture de couverture des rollups est passée au pool de lecture) — pas parce
qu'elle n'était pas là : c'est la passe d'ATTRIBUTION, plus haut, qui la mesure encore
en place, et le champ reste publié pour que la prochaine soit visible immédiatement.
Les colonnes de débit et de p95, elles, ne sont PAS un résultat de ce correctif : elles
portent la charge de la machine du jour autant que le code — on les publie pour qu'on
puisse les contredire, pas pour en tirer une conclusion.

## Cellules à ne pas croire telles quelles

- 33 cellules ont été **rejouées** (une mesure bousculée remplacée par une mesure propre) ; seule la dernière figure dans les tableaux, le JSONL brut garde les deux.
- **48 cellules prises pendant que la machine swappait** (apres-leviers@1.4M/C3-groupby-hi/all, apres-leviers@1.4M/C5b-regex-json-cold/24h, avant-leviers@1.4M/C2e-free-term-common/all, avant-leviers@1.4M/C5b-regex-json-cold/all, chaud-seul-v2@1.4M/C2d-free-term-rows/all, chaud-seul-v2@1.4M/C2d-free-term-rows/au-dela-7d, chaud-seul-v2@1.4M/C2e-free-term-common/24h, chaud-seul-v2@1.4M/C2e-free-term-common/7d, chaud-seul-v2@1.4M/C2e-free-term-common/au-dela-7d, chaud-seul-v2@1.4M/C3-groupby-hi/all, chaud-seul@1.4M/C6b-groupby-host/au-dela-7d, flotte-1h@0.6M/C6-filter-host/7d, froid-actif-v2@1.4M/C1-scan-agg/all, froid-actif-v2@1.4M/C1b-scan-agg-dc/7d, froid-actif-v2@1.4M/C1b-scan-agg-dc/all, fts0-masque-non-vide@1.4M/C2d-free-term-rows/all, fts0-masque-non-vide@1.4M/C2e-free-term-common/1h, fts0-masque-non-vide@1.4M/C2e-free-term-common/24h, fts0-masque-non-vide@1.4M/C2e-free-term-common/all, fts0-masque-non-vide@1.4M/C3-groupby-hi/24h, fts0-masque-non-vide@1.4M/C3c-groupby-json/24h, fts0-masque-non-vide@1.4M/C3c-groupby-json/all, fts0-masque-non-vide@1.4M/C4b-raw-deep/24h, fts0-masque-non-vide@1.4M/C5-regex-json-planted/24h, fts0-masque-non-vide@1.4M/C5-regex-json-planted/all, fts0-masque-vide@1.4M/C3c-groupby-json/24h, fts0-masque-vide@1.4M/C3c-groupby-json/all, fts0-masque-vide@1.4M/C5-regex-json-planted/24h, taille-grande@0.6M/C3c-groupby-json/7d, taille-grande@0.6M/C3c-groupby-json/all, temoin-64h@0.6M/C2-free-term/all, temoin-64h@0.6M/C2-free-term/au-dela-7d, temoin-64h@0.6M/C2b-regex-msg/all, temoin-64h@0.6M/C2c-fts-bar/1h, temoin-64h@0.6M/C2d-free-term-rows/24h, temoin-64h@0.6M/C2d-free-term-rows/7d, temoin-64h@0.6M/C2d-free-term-rows/au-dela-7d, temoin-64h@0.6M/C2e-free-term-common/all, temoin-64h@0.6M/C3-groupby-hi/7d, temoin-64h@0.6M/C3b-groupby-routable/all, temoin-64h@0.6M/C3c-groupby-json/24h, temoin-64h@0.6M/C3c-groupby-json/7d, temoin-64h@0.6M/C5-regex-json-planted/all, temoin-64h@0.6M/C5b-regex-json-cold/24h, temoin-64h@0.6M/C5b-regex-json-cold/7d, temoin-64h@0.6M/C5b-regex-json-cold/all, temoin-64h@0.6M/C6b-groupby-host/24h, temoin-64h@0.6M/C6b-groupby-host/7d). Un chiffre pris sous swap est faux. Un rejeu a été TENTÉ pour les cellules de la configuration de référence ; celles qui restent listées ici sont celles pour lesquelles la machine n'a pas offert de fenêtre sans swap. Leur `p50` est à prendre comme une borne haute, leur `p95` comme non exploitable.
- **30 cellules en échec ou en erreur** — elles restent dans le tableau avec leur message :
  - `fts0-masque-non-vide` / `C5c-eq-json-hot` / 1h : {"error":"filtrage interdit sur le champ masqué « user » (field-filter actif pour votre rôle : un champ que vous ne pouvez pas voir ne peut pas être filtré)"} (statuts [400])
  - `fts0-masque-non-vide` / `C5c-eq-json-hot` / 24h : {"error":"filtrage interdit sur le champ masqué « user » (field-filter actif pour votre rôle : un champ que vous ne pouvez pas voir ne peut pas être filtré)"} (statuts [400])
  - `fts0-masque-non-vide` / `C5c-eq-json-hot` / all : {"error":"filtrage interdit sur le champ masqué « user » (field-filter actif pour votre rôle : un champ que vous ne pouvez pas voir ne peut pas être filtré)"} (statuts [400])
  - `fts0-masque-non-vide@1.4M` / `C5c-eq-json-hot` / 1h : {"error":"filtrage interdit sur le champ masqué « user » (field-filter actif pour votre rôle : un champ que vous ne pouvez pas voir ne peut pas être filtré)"} (statuts [400])
  - `fts0-masque-non-vide@1.4M` / `C5c-eq-json-hot` / 24h : {"error":"filtrage interdit sur le champ masqué « user » (field-filter actif pour votre rôle : un champ que vous ne pouvez pas voir ne peut pas être filtré)"} (statuts [400])
  - `fts0-masque-non-vide@1.4M` / `C5c-eq-json-hot` / all : {"error":"filtrage interdit sur le champ masqué « user » (field-filter actif pour votre rôle : un champ que vous ne pouvez pas voir ne peut pas être filtré)"} (statuts [400])
  - `froid-actif-v2@1.4M` / `C1b-scan-agg-dc` / 7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C1b-scan-agg-dc` / au-dela-7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C1b-scan-agg-dc` / all : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C2-free-term` / 7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C2-free-term` / au-dela-7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C2-free-term` / all : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C2e-free-term-common` / 7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C2e-free-term-common` / au-dela-7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C2e-free-term-common` / all : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C3-groupby-hi` / 7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C3-groupby-hi` / all : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C3c-groupby-json` / 7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C3c-groupby-json` / au-dela-7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C3c-groupby-json` / all : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C5-regex-json-planted` / 7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C5-regex-json-planted` / au-dela-7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C5-regex-json-planted` / all : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C5b-regex-json-cold` / 7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C5b-regex-json-cold` / au-dela-7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C5b-regex-json-cold` / all : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C6b-groupby-host` / 7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C5c-eq-json-hot` / 7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C5c-eq-json-hot` / au-dela-7d : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
  - `froid-actif-v2@1.4M` / `C5c-eq-json-hot` / all : {"cold_row_cap":5000,"cold_rows_hydrated":5000,"error":"refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) sur l'historique froid, mais la lecture froide a dû s'arrêter à 5000 lignes (plafond RAM PLUME_QUERY_MAX=5000) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. Voies EXACTES : restreindre la fenêtre sous le plafon (statuts [422])
- **68 cellules tronquées** par le plafond de lignes (`PLUME_QUERY_MAX`, 5 000 par défaut) : leur latence est celle d'un résultat PARTIEL.

## Comment la latence monte avec le volume

Mesuré à plusieurs volumes sur la même machine, même binaire, masque vide, `PLUME_FTS_FIELDS=0`, fenêtre « tout ». C'est la pente qui répond à la question « des millions d'événements », pas un point isolé.

Réserve à connaître avant de citer ce tableau : les volumes viennent de **passes distinctes**, donc de bases distinctes et de nombres de répétitions possiblement différents (la colonne `reps` du JSONL brut le dit cellule par cellule). Les points sont comparables en ordre de grandeur, pas au pourcentage près. Une case vide = classe non mesurée à ce volume.

| Classe | 200 003 lignes | 335 255 lignes | 600 003 lignes | 600 003 lignes | 600 003 lignes | 600 003 lignes | 600 003 lignes | 1 440 003 lignes | 1 440 007 lignes | 1 440 007 lignes | 1 440 007 lignes | 1 440 007 lignes | 1 440 007 lignes | rapport |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `C1-scan-agg` | 51 | 2252 | 1223 | 1117 | 1073 | 1221 | 1962 | 2856 | 2154 | 2036 | 4579 | 4118 | 5134 | x100.5 pour x7.2 de lignes ⚠ base au plancher |
| `C1b-scan-agg-dc` | 577 | 1725 | 1534 | 89 | 92 | 1578 | 2912 | 5109 | 2004 | 4721 | 3209 | — | 4001 | x6.9 pour x7.2 de lignes |
| `C2-free-term` | 652 | 4898 | 1471 | 1377 | 1334 | 1539 | 3021 | 5860 | 3406 | 2568 | 2813 | — | 2878 | x4.4 pour x7.2 de lignes |
| `C2b-regex-msg` | 502 | 4532 | 1871 | 1699 | 1792 | 1672 | 3368 | 3863 | 3506 | 3156 | 3364 | 6284 | 4028 | x8.0 pour x7.2 de lignes |
| `C2c-fts-bar` | 51 | 2.1 | 3.2 | 2.4 | 2.1 | 2.3 | 3.3 | 51 | 51 | 2.8 | 4.3 | 2.2 | 3.7 | x0.1 pour x7.2 de lignes ⚠ base au plancher |
| `C3-groupby-hi` | 870 | 5126 | 6319 | 7003 | 4765 | 4706 | 7618 | 15.7 s | 14.7 s | 13.9 s | 13.0 s | — | 14.2 s | x16.4 pour x7.2 de lignes |
| `C3b-groupby-routable` | 151 | 948 | 518 | 477 | 396 | 420 | 494 | 152 | 201 | 130 | 141 | 873 | 141 | x0.9 pour x7.2 de lignes |
| `C3c-groupby-json` | 853 | 5314 | 3219 | 3776 | 4226 | 3894 | 6608 | 12.6 s | 9214 | 8127 | 7969 | — | 7002 | x8.2 pour x7.2 de lignes |
| `C4-raw-page1` | 52 | 1195 | 2.6 | 1.7 | 1.5 | 2.4 | 2.6 | 52 | 51 | 1.7 | 2.9 | 1296 | 1.7 | x0.0 pour x7.2 de lignes ⚠ base au plancher |
| `C4b-raw-deep` | 51 | 3513 | 415 | 415 | 36 | 34 | 829 | 1055 | 552 | 31 | 366 | 3495 | 254 | x4.9 pour x7.2 de lignes ⚠ base au plancher |
| `C4c-raw-keyset` | 54 | 1096 | 3.9 | 9.8 | 3.6 | 3.3 | 4.5 | 54 | 53 | 3.5 | 2.7 | 3.3 | 8.4 | x0.2 pour x7.2 de lignes ⚠ base au plancher |
| `C5-regex-json-planted` | 552 | 5746 | 2653 | 2108 | 1946 | 1788 | 3011 | 6110 | 4808 | 5274 | 3672 | — | 5441 | x9.9 pour x7.2 de lignes |
| `C5b-regex-json-cold` | 652 | 4934 | 2443 | 3066 | 2105 | 2194 | 4455 | 9616 | 6063 | 5873 | 5727 | — | 6074 | x9.3 pour x7.2 de lignes |
| `C5c-eq-json-hot` | 51 | 1071 | 1.0 | 0.8 | 1.4 | 1.1 | 0.9 | 54 | 51 | 0.8 | 0.8 | — | 1.1 | x0.0 pour x7.2 de lignes ⚠ base au plancher |
| `C0-plancher` | — | 1032 | 1.0 | 1.0 | 1.0 | 0.9 | 0.7 | 51 | 51 | 0.7 | 0.6 | 3202 | 0.6 | — |
| `C2d-free-term-rows` | — | 5695 | 1506 | 1392 | 1601 | 1373 | 2915 | 3406 | 2756 | 2600 | 3288 | 5665 | 3108 | — |
| `C2e-free-term-common` | — | 4478 | 1454 | 1636 | 1512 | 1435 | 2677 | 2705 | 3357 | 2696 | 2924 | — | 3685 | — |
| `C4d-keyset-projete` | — | 1122 | 2.1 | 7.7 | 1.9 | 1.9 | 2.5 | — | 52 | 1.6 | 1.6 | 3.1 | 6.9 | — |
| `C6-filter-host` | — | 1138 | 1.8 | 1.3 | 1.5 | 1.1 | 1.2 | — | — | — | 1.6 | 3041 | 3.3 | — |
| `C6b-groupby-host` | — | 4606 | 58 | 69 | 54 | 52 | 51 | — | — | — | 99 | 7775 | 102 | — |
| `C6c-raw-one-host` | — | 1116 | 10 | 10 | 12 | 13 | 13 | — | — | — | 22 | 7.2 | 21 | — |

Une classe dont le rapport de latence suit le rapport de lignes est un **scan** : son coût est linéaire en volume et rien ne l'indexe. Une classe dont le rapport reste plat est servie par un index ou par un rollup.

⚠ **base au plancher** : au petit volume, la cellule était déjà au plancher fixe (~51 ms, voir `C0-plancher`). Le rapport affiché mesure alors la distance à ce plancher, PAS la pente du scan — ne pas le citer comme un facteur d'échelle.

## Leviers désignés par la mesure

Aucun n'est implémenté ici : c'est le rôle de l'instrument de les **désigner** et de chiffrer
le gain qu'on aurait le droit d'en attendre. Classés par gain mesuré décroissant. « Coût RAM »
dit ce que le levier ajouterait au budget de 2 Gio ; quand il est nul, c'est écrit.

### L1. Rendre la route de rollups compatible avec le masquage

*Gain mesuré : **36.2 s** au p50 sur la cellule la plus parlante (C3b masqué vs non masqué). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*

le MÊME group-by, le MÊME rôle : **141 ms** masque vide (servi depuis `rollup`, 63 lignes) contre **36.3 s** masque non vide (servi depuis `raw`, 70 lignes — les comptes diffèrent parce que la route de rollups est APPROCHÉE, `stats.approx=true` : c'est le prix de sa vitesse), soit **257.8x plus lent**. Le rempart de confidentialité est donc aussi un frein de performance : un masque non vide désarme la route de rollups (`handlers/query.rs:282`) parce que `event_rollup` stocke `src_ip`/`host` en clair. Deux voies : masquer à la lecture du rollup, ou matérialiser un rollup par classe de masque. **Coût RAM : celui d'un jeu de rollups supplémentaire** (sur l'installation de référence, `event_rollup` pèse de l'ordre du Mio par million d'événements, donc marginal), plus le masquage au vol. **Réserve** : la passe masquée porte 1 440 003 événements contre 1 440 007 pour la passe non masquée — l'écart de volume est négligeable devant le facteur mesuré, mais les deux chiffres ne viennent pas de la MÊME passe.

### L2. Rendre l'index d'hôte utilisable AVEC une borne temporelle

*Gain mesuré : **22.1 s** au p50 sur la cellule la plus parlante (C6b 7d vs all). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*

le MÊME `stats count by host`, la MÊME base : **102 ms** sans borne de temps contre **22.2 s** borné à la fenêtre chaude du produit (`7d`), soit **217x plus lent**. Sans borne, le group-by est servi par un parcours d'index seul (`idx_event_host` couvre la requête). Dès qu'une borne `ts` entre, l'index d'hôte ne suffit plus — il faut ouvrir chaque ligne pour lire son `ts` — et la requête redevient un scan. Or la borne temporelle est le cas NORMAL : un tableau de bord regarde toujours une fenêtre. Voie : un index composite `(host, ts)`, qui rend le prédicat de temps satisfiable dans l'index. **Coût RAM : nul ; coût DISQUE : un index de plus** (sur l'installation de référence, `idx_event_host` pèse quelques dizaines de Mio par million d'événements). À noter : cette cellule est déjà à 64 hôtes ; sur une flotte, le nombre de groupes ne fait que grandir.

### L3. Étendre la route de rollups aux dimensions à haute cardinalité

*Gain mesuré : **14.1 s** au p50 sur la cellule la plus parlante (C3-groupby-hi / all). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*

`stats count by src_ip,host,source` sur tout l'historique : **14.2 s**, servi par `raw`. Seules les formes `by` dont TOUTES les dimensions tiennent dans `{source, severity}` sont routables (`rollup_route.rs:349-366`) ; dès qu'une dimension à haute cardinalité entre, on retombe sur le scan. **Coût RAM : celui du grain choisi** — un rollup à grain `src_ip` est borné à l'exécution par `PLUME_ROLLUP_SRCIP_TOPN` (50) précisément pour ne pas exploser, ce qui rend le résultat approché. Le compromis exactitude/mémoire doit être décidé, pas subi.

### L4. Le champ étendu non indexé n'a aucun chemin d'accès

*Gain mesuré : **6.1 s** au p50 sur la cellule la plus parlante (C5b vs C5c). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*

regex sur `fields.object` (aucun index) : **6.1 s** contre **1.1 ms** pour une égalité sur `fields.user`, qui a un index d'expression partiel. 12 champs seulement sont indexés (`HOT_FIELDS`, lu dans `daemon/src/soql_glue.rs` : action, user, owner, kind, ns, role, scope, verb, resource, operation, dir, risk) sur les **241 clés distinctes du profil mesuré**. Pour les 229 autres, toute recherche est un scan avec `json_extract` par ligne. C'est exactement la promesse « sur tous les champs » qui est en jeu. Voies : `event_fields_fts` (déjà écrit, voir le levier sur le coût de `PLUME_FTS_FIELDS`), ou des index d'expression sur demande, ou un stockage colonnaire des champs. **Coût RAM : un index d'expression par champ**, à arbitrer — et cet arbitrage n'a aujourd'hui aucun automate : le mécanisme qui promettait de le rendre à l'usage a été retiré (P6.8-b) sans avoir jamais promu un seul index.

### L5. Câbler FTS5 sur le chemin GXQL

*Gain mesuré : **3.1 s** au p50 sur la cellule la plus parlante (C2c vs C2d). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*

la même aiguille, le même nombre de lignes rendues : **3.1 s** par GXQL (`message LIKE '%…%'`, scan complet) contre **3.7 ms** par `/api/search` (index FTS5 `event_fts`). L'index EXISTE et est déjà payé — sur l'installation de référence il pèse environ six dixièmes du poids de la table — mais il n'est câblé que sur `/api/search`. Sur le chemin GXQL, un terme libre devient `col LIKE '%motif%'` (`core/src/soql/dialect.rs:65-67`, appelé depuis `soql/mod.rs:881-891`), donc un scan complet. **Coût RAM : nul** — l'index est déjà construit et déjà en base.

### L6. Le coût de `PLUME_FTS_FIELDS=1`, et à qui il profite

*Coût DISQUE mesuré : **+-33 Mio** (+-2 %) sur la base. Ce n'est pas un gain, c'est une dépense — et le document dit plus bas à qui elle profite.*

activer `PLUME_FTS_FIELDS=1` a fait passer la base de **1434 Mio à 1401 Mio** (+-33 Mio, +-2 %). RSS crête, sur les SEULES classes mesurées dans les deux configurations : **987 Mio** à `FTS_FIELDS=0` contre **691 Mio** à `FTS_FIELDS=1`. Attention : chaque configuration repart d'un daemon neuf, donc ces deux crêtes n'ont pas eu le même historique pour monter — l'écart n'est PAS attribuable au drapeau seul. Le chiffre solide de cette ligne est le coût DISQUE. Écart de latence observé sur le terme libre GXQL (tout l'historique) : **798 ms** en défaveur de FTS_FIELDS=1 — mais cet écart ne peut PAS venir du drapeau, puisque le chemin GXQL ne lit jamais `event_fields_fts` : c'est du bruit de mesure sur une machine partagée, et il est reporté comme tel. À retenir : `event_fields_fts` n'est lu que par `/api/search` (`handlers/search.rs:146-157`). Le chemin GXQL ne le consulte JAMAIS — donc son coût en disque et en ingest est payé sans que les requêtes GXQL en profitent. C'est le levier « Câbler FTS5 sur le chemin GXQL » qui rendrait ce coût déjà consenti utile aux requêtes GXQL.

## Ce qui n'est PAS mesuré ici

- **Le tier froid au-delà de ce qui est tiré** : 2 configuration(s) tournent
  `PLUME_COLD_TIER=1` (section dédiée plus haut), mais sur UNE seule taille de fenêtre
  chaude et UN seul volume. Le moteur vectorisé n'est pas mesuré séparément du chemin
  d'hydratation : le document ne dit pas lequel a servi chaque cellule au-delà de ce que
  `stats.cold` en rapporte.
- **La concurrence est mesurée** (section dédiée) : jusqu'à 10 analystes
  simultanés, sémaphore 3 et 8. Ce qui reste hors mesure :
  la concurrence PENDANT une ingestion (les deux charges sont mesurées séparément), la
  charge SOUTENUE sur des heures (chaque niveau dure des dizaines de secondes, pas une
  journée), et les fenêtres autres que `all` — le
  mélange est tiré sur la fenêtre la plus coûteuse, pas sur toutes.
- **Le multi-tenant** (`PLUME_MULTI_TENANT=1`) : tout est mesuré en mode 0.
- **Le cache de pages froid** : impossible de le vider sans privilège root sur la machine de
  mesure. La colonne `lu` dit ce qui a réellement atteint le disque ; elle ne dit pas ce que
  ferait un démarrage à froid complet.
- **La fidélité du texte** : le corps des messages est synthétique. Les chiffres FTS5, `LIKE`
  et `REGEXP` dépendent directement de ce vocabulaire ; c'est la limite la plus sérieuse du
  banc et elle est décrite dans `bench/gen_events.py` (`VOCAB`).
- **L'indexation des champs étendus** : `PLUME_EXPRINDEX=1` (le défaut livré) est le SEUL
  levier, et il n'indexe que les noms de `HOT_FIELDS`. Aucun mécanisme n'indexe plus un champ
  à l'usage — celui qui le promettait a été retiré (P6.8-b) sans avoir jamais promu un index.
  Ce tableau ne peut donc PAS montrer un champ étendu hors de cette liste servi par un index :
  ce n'est pas une case non mesurée, c'est une case qu'aucune configuration ne remplirait.

## Reproduire, et contredire

```sh
# 1. le profil de données (déjà versionné ; à re-extraire seulement pour une autre prod)
#    bench/prod-profile.sql, LECTURE SEULE, n'extrait aucune valeur de ligne
# 2. la matrice complète, de bout en bout :
CARGO_TARGET_DIR=../.bench-target cargo build --release --features cold_tier \
    --manifest-path daemon/Cargo.toml
bench/run.sh                       # 10 M d'événements
BENCH_EVENTS=1000000 bench/run.sh  # 1 M, pour itérer
# 2 bis. la CONCURRENCE, sur une base déjà remplie (redémarre le daemon par valeur de
#        sémaphore et lui REDEMANDE ce qu'il applique avant de mesurer) :
BENCH_PHASES=concurrency BENCH_SEM_SWEEP=3,8 BENCH_CONC_LEVELS=1,2,3,4,6,8,10 bench/run.sh
# 3. le rendu — LA COMMANDE EXACTE qui a produit CE document, reconstruite depuis ses propres
#    arguments et pointée sur les données VERSIONNÉES (donc rejouable par un tiers) :
python3 bench/report.py bench/results/results-smoke-200k.jsonl bench/results/results.jsonl bench/results/results-2026-07-31.jsonl bench/results/results-2026-07-31-corrige.jsonl bench/results/parity-avant-2026-07-31.jsonl bench/results/parity-apres-2026-07-31.jsonl bench/results/parity-couverture-2026-07-31.jsonl bench/results/concurrency-2026-08-01.jsonl bench/results/concurrency-reproduction-2026-08-01.jsonl bench/results/concurrency-attribution-2026-08-01.jsonl bench/results/concurrency-corrige-2026-08-01.jsonl bench/results/generique-2026-08-03.jsonl \
    --ingest-curve bench/results/ingest_rate.csv \
    --ingest-curve bench/results/ingest_rate-quiet-2g.csv \
    --ref chaud-seul-v2@1.4M \
    --compare avant-leviers@1.4M:apres-leviers@1.4M \
    --compare-note 'deux correctifs du chemin de requête, mesurés ici. (1) La garde de budget attend désormais une CONDITION (condvar avec délai) au lieu de sonder un drapeau toutes les 50 ms : elle protège la même chose, au même seuil, avec la même interruption, mais elle ne QUANTIFIE plus la latence — auparavant toute lecture était arrondie au multiple de 50 ms supérieur, et la garde était jointe avant l'"'"'envoi de la réponse. Elle couvre les deux portes d'"'"'exécution : `run_on_conn` (/api/query) et `read_with_watchdog` (alertes, cases, fraîcheur, sources, /api/search). (2) L'"'"'applicabilité de la pagination par curseur est DÉRIVÉE des propriétés du wrap au lieu d'"'"'une liste de deux commandes, et un pipeline projeté (`| table`/`| fields`) est désormais servi par le curseur au lieu de retomber en silence sur l'"'"'OFFSET : c'"'"'est la cellule `C4d-keyset-projete`. Réserve de comparabilité : ces deux passes tournent sur la MÊME base, mais APRÈS le remplissage `event_fields_fts` de la phase 3 (base 1434 Mio contre 1263 Mio pour les tableaux `fts0-*@1.4M` ci-dessus) et sur une machine bien moins chargée. Elles sont comparables ENTRE ELLES ; elles ne sont pas comparables aux tableaux de la première référence. Cinq cellules vont dans l'"'"'autre sens (C1b/all +2.7 s, C5b/24h +632 ms, C5/all +467 ms, C2d/24h +252 ms) : sur ces quatre-là la colonne `SQL` bouge AUTANT que le mur, or les correctifs n'"'"'agissent QUE sur l'"'"'attente AUTOUR du SQL — ce sont donc des scans longs bousculés par la machine, et ils sont laissés tels quels.' \
    --compare chaud-seul@1.4M:froid-actif@1.4M \
    --compare-note 'le tier froid, et rien d'"'"'autre. MÊME fichier de base, MÊME binaire, MÊME machine, passes consécutives : entre les deux, `plume-daemon retention` a columnarisé en Parquet les jours entièrement plus vieux que la fenêtre chaude (1 104 752 lignes sur 1 440 007, soit 76,7 %), et le daemon a été relancé avec `PLUME_COLD_TIER=1`. ATTENTION : 57 des 105 cellules froides rendent une réponse TRONQUÉE (le chemin d'"'"'union hydrate au plus `PLUME_QUERY_MAX`=5 000 lignes) — leur delta n'"'"'est PAS un écart de vitesse mais un écart de travail, et elles sont marquées comme telles dans le tableau. La sous-section « La réponse est-elle la MÊME ? » chiffre l'"'"'écart de contenu : jusqu'"'"'à x203 sur un simple `stats count`. CETTE PASSE DÉCRIT LE CODE D'"'"'AVANT LE CORRECTIF de troncature froide et elle est conservée pour cela : elle est la MESURE du défaut. La passe qui décrit le dépôt actuel est `chaud-seul-v2@1.4M` contre `froid-actif-v2@1.4M`, plus bas.' \
    --compare chaud-seul-v2@1.4M:froid-actif-v2@1.4M \
    --compare-note 'le tier froid APRÈS le correctif de troncature, sur les MÊMES copies de base et la MÊME machine que la passe précédente, avec le binaire post-correctif. Ce qui a changé dans le produit : (1) le routeur colonnaire est ARMÉ PAR DÉFAUT dès que le tier froid est actif — son défaut DORMANT était la cause mesurée du défaut : aucune des 105 cellules froides n'"'"'atteignait les kernels ; (2) la garde « ne router que ce que le chemin d'"'"'union rendrait à l'"'"'identique » ne s'"'"'applique plus aux AGRÉGATS — au-delà du plafond d'"'"'hydratation, le chemin d'"'"'union agrège sur un ÉCHANTILLON, et la parité avec un nombre faux n'"'"'est pas une vertu ; (3) aucune valeur DÉRIVÉE d'"'"'un ensemble tronqué ne peut plus être sérialisée (`cold_store/exactness.rs`) : à défaut de pouvoir la calculer exactement, le daemon REFUSE en nommant sa cause et la voie exacte (HTTP 422). RÉSULTAT MESURÉ : les cellules TRONQUÉES passent de 57 à 11, et les 11 restantes sont TOUTES des matérialisations (`| table` / pages brutes) — c'"'"'est-à-dire le cas légitime : des lignes vraies, en nombre incomplet, signalé. 24 cellules répondent désormais 422 : ce sont les formes que le moteur colonnaire ne sait pas calculer exactement (dc(), terme libre, champ JSON, group-by chevauchant la frontière). Une cellule 422 n'"'"'a pas de latence comparable : elle mesure un refus, pas un travail. ATTENTION à la lecture des deltas : une cellule qui passe de « tronquée » à « exacte » fait PLUS de travail qu'"'"'avant — un ralentissement y est le prix de la justesse, pas une régression.' \
    --fill-log bench/results/fill-progress-quiet-2g.txt \
    -o docs/BENCHMARK.md
```

Cette commande est **régénérée à chaque rendu** : elle ne peut pas se désynchroniser du
document. C'est délibéré — la version précédente publiait une commande incomplète qui, rejouée
telle quelle, AMPUTAIT le document de ses sections d'écart et de ses tableaux d'attribution.
Une commande de reproduction fausse est pire qu'absente : elle fait croire à une
reproduction réussie.

Le générateur est déterministe : `python3 bench/gen_events.py --count N --end-ts T --digest`
imprime le SHA-256 du flux. Deux exécutions avec les mêmes paramètres donnent la même
empreinte — c'est ce qui rend un désaccord sur les chiffres arbitrable.

