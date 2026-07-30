# Banc de mesure plume — requêtes à chaud sous 2 Gio

<!-- CE FICHIER EST GÉNÉRÉ par bench/report.py (voir la section « Reproduire » en bas).
     Ne pas l'éditer à la main : la prochaine passe l'écrase. Tout commentaire durable va dans
     bench/README.md. -->

Rendu le 2026-07-30 14:12:18+0200 depuis `results-smoke-200k.jsonl`, `results.jsonl` (données brutes conservées hors dépôt, cf. `bench/README.md`).

## Ce que ce document est, et ce qu'il n'est pas

C'est **la première mesure de référence** de plume, prise avec un instrument publié et
rejouable. Chaque chiffre porte ses qualificatifs. Rien n'est extrapolé : une case vide est
une case **non mesurée**, pas une case implicitement bonne.

Ce n'est **pas** une comparaison à un autre produit, ni une mesure de production : c'est un
banc synthétique au **profil** de la production (voir `bench/profile-prod.json`).

## Verdict — ce que ces mesures autorisent à affirmer

Volume de référence : **1 440 003 événements** (`fts0-masque-vide@1.4M`), base **1263 Mio** chiffrée SQLCipher.

**Sur le budget de 2 Gio — soutenu.** RSS crête la plus haute mesurée sur l'ensemble des cellules : **1097 Mio**, soit **54 %** du budget. Et ce n'est pas une observation passive : le daemon tournait sous `MemoryMax=2G MemorySwapMax=0`, où un dépassement est un kill du noyau.

**Ce qui est RAPIDE** (p50, fenêtre indiquée, config de référence) :

- `C0-plancher` / all — **51 ms** (PLANCHER : seek sur une source inexistante (0 ligne)), servi par `raw`
- `C0-plancher` / 24h — **51 ms** (PLANCHER : seek sur une source inexistante (0 ligne)), servi par `raw`
- `C1-scan-agg` / 1h — **51 ms** (scan filtré + agrégat (source + severity)), servi par `raw`
- `C2e-free-term-common` / 1h — **51 ms** (terme libre PEU sélectif (1 ligne sur 10) en LIKE), servi par `raw`

Toutes ces cellules sont AU PLANCHER. Une requête dont le SQL ne coûte rien revient en **51 ms** (`C0-plancher`, SQL mesuré à 0.1 ms) : c'est un coût FIXE, indépendant du volume, et aucune requête ne peut descendre en dessous aujourd'hui. Voir le levier « Le plancher fixe par requête ».

**Ce qui est LENT** — et ce sont les cas que la promesse « sur tous les champs » met en avant :

- `C3-groupby-hi` / all — **15.7 s** (group-by 3 dims haute cardinalité (src_ip,host,source)), servi par `raw`
- `C3c-groupby-json` / all — **12.6 s** (group-by sur champ ÉTENDU indexé (action) + colonne), servi par `raw`
- `C5b-regex-json-cold` / all — **9.6 s** (regex sur champ ÉTENDU NON indexé (fields.object)), servi par `raw`
- `C5-regex-json-planted` / all — **6.1 s** (regex sur champ ÉTENDU planté (fields.needle)), servi par `raw`

**Le disque n'a pas été sollicité — et c'est une limite, pas une bonne nouvelle.** Octets lus au bloc, maximum sur toutes les cellules : **0 Mio**. La base (1263 Mio) tient entièrement dans le cache de pages de la machine (6839 Mio de mémoire disponible au minimum pendant la mesure). Ces latences sont donc **bornées par le CPU, pas par le stockage**, et constituent un MEILLEUR CAS. À un volume où la base dépasse la RAM disponible, le stockage entre dans l'équation — et ce régime n'est pas mesuré ici.

**Ce que ces mesures n'autorisent PAS à affirmer** :

- rien au-delà de 1 440 003 événements. La cible de 10 M n'a pas été atteinte par le vrai chemin d'ingest dans le temps disponible (voir le débit mesuré ci-dessous). Toute phrase sur 10 M ou 100 M serait une extrapolation, pas une mesure.
- rien sur le tier froid, la concurrence, ni le multi-tenant (voir la section dédiée).
- rien sur un déploiement AVEC masquage à partir des chiffres masque-vide : l'écart mesuré le plus fort est **x239.5** sur `C3b-groupby-routable` / all (152 ms masque vide contre 36.3 s masque non vide).
  Et le masquage ne va pas TOUJOURS dans le sens du ralentissement : sur `C4b-raw-deep` / all il est **x0.05**, donc plus RAPIDE (1055 ms masque vide contre 54 ms masque non vide, même nombre de lignes rendues). **La cause n'est PAS établie par cette mesure**, et on ne va pas l'inventer. Deux mécanismes candidats, qui demandent chacun une expérience dédiée pour être départagés : (a) un masque posé sur une dimension à haute cardinalité l'effondre, il reste moins de groupes à agréger — la requête va plus vite **parce que la réponse a changé** ; (b) la passe masquée a tourné APRÈS la passe non masquée, donc sur un cache de pages plus chaud. Ce qui trancherait : rejouer les deux passes dans l'ordre inverse, et comparer les résultats ligne à ligne. En attendant, la règle est simple — **une latence qui baisse en présence d'un masque ne doit jamais être citée comme un gain**.

## Matériel et conditions

| | |
|---|---|
| Processeur | Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz (12 cœurs logiques) |
| RAM de la machine | 15.4 Gio |
| Noyau | 7.1.4-zen1-1-zen |
| Version de plume mesurée | `bin:0642474ceedfaf15 construit:2026-07-30T11:08:02Z (HEAD au rendu: 3f9664b — indicatif, l'arbre bouge)` |
| Volumes mesurés | 200 003 événements, 1 440 003 événements |
| Taille de la base (SQLCipher, chiffrée) | 1263 Mio, 1401 Mio, 197 Mio |
| Budget mémoire | **appliqué** par un scope systemd `MemoryMax=2G MemorySwapMax=0` — la même contrainte que la limite de conteneur de production (`limits.memory: 2Gi`) |
| Concurrence de requêtes | `PLUME_QUERY_CONCURRENCY=3` (le défaut livré) |
| Budget par requête | interactif, 60 s (`interactive:true`) |

**Honnêteté sur les conditions** : la machine de mesure n'était pas dédiée — d'autres travaux
tournaient en parallèle. Chaque cellule enregistre son `loadavg` et le swap consommé pendant
la mesure ; les cellules prises sous swap sont marquées et listées plus bas. Le daemon lui-même
ne pouvait pas swapper (`MemorySwapMax=0`), donc sa RSS crête est une vraie crête, mais les
latences absolues sont **pessimistes** sur une machine chargée.

## Débit d'ingest mesuré (chemin HTTP complet)

| Événements | Durée | Débit | Base après | `PLUME_FTS_FIELDS` |
|---:|---:|---:|---:|:--:|
| 200 000 | 67 s | **2 985 ev/s** | 166 Mio | 0 |
| 444 000 | 541 s | **820 ev/s** | 1217 Mio | 0 |

Chemin traversé : `POST /api/ingest -> spool -> ingest_events_batch (normalisation, promotion de colonnes, cim_stamp, déclencheurs FTS, index d'expression)`.

> Ligne de 444 000 événements : **reconstruit depuis l'échantillonneur (premier et dernier point mesurés), le remplissage ayant été borné en temps.**

Débit **cumulé** relevé par le générateur lui-même pendant le remplissage (il est régulé sur la profondeur du spool : son débit de production est donc le débit d'ingest de bout en bout). Ces points couvrent le DÉBUT du remplissage :

| Événements produits | Volume produit | Débit cumulé mesuré |
|---:|---:|---:|
| 600 000 | 302 Mio | **4 309 ev/s** |
| 1 200 000 | 604 Mio | **2 162 ev/s** |

Le débit cumulé passe de **4 309 ev/s** à **2 162 ev/s** entre 600 000 et 1 200 000 événements produits, soit **x2.0**. Deux causes se superposent — le volume déjà en base (maintenance des index et de la FTS5) et la charge de la machine — et cette passe ne les sépare pas. C'est pour ça que la cible de 10 M n'a pas été atteinte : à ce débit, il aurait fallu plusieurs heures de plus.

### Le débit d'ingest se dégrade avec le volume — mesuré, pas supposé

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

Débit sur les intervalles échantillonnés : **min 562 ev/s, médiane 800 ev/s, max 1273 ev/s**, pour un `loadavg` allant de 6.2 à 14.0. L'écart d'un facteur 2.3 entre le plus lent et le plus rapide intervalle suit le `loadavg` : **sur cette machine non dédiée, le débit d'ingest est dominé par la contention CPU**, pas seulement par le volume déjà en base. Il faut donc lire ces chiffres comme un PLANCHER, et refaire la mesure sur une machine au repos avant d'en publier un débit nominal.

La colonne RSS est la mémoire réellement occupée par le daemon PENDANT l'ingest — crête échantillonnée ici : **685 Mio**, à confronter au budget de 2 Gio. C'est une mesure, pas une estimation.

> Portée de cette courbe : l'échantillonneur ne couvre que la fenêtre où il a tourné (1 032 003 à 1 428 003 lignes). Ce qui s'est passé avant n'est pas dans ce tableau, et n'est donc pas mesuré ici.

## Configurations mesurées

| Étiquette | Événements | `PLUME_FTS_FIELDS` | Masquage de champs | Tier froid | Classes mesurées |
|---|---:|:--:|---|:--:|---|
| `fts0-masque-vide` | 200 003 | 0 | vide | off | toutes (42 cellules) |
| `fts0-masque-non-vide` | 200 003 | 0 | non-vide (src_ip=mask, fields.user=partial) | off | toutes (42 cellules) |
| `fts0-masque-vide@1.4M` | 1 440 003 | 0 | vide | off | toutes (51 cellules) |
| `fts0-masque-non-vide@1.4M` | 1 440 003 | 0 | non-vide (src_ip=mask, fields.user=partial) | off | toutes (51 cellules) |
| `fts1-masque-vide@1.4M` | 1 440 003 | 1 | vide | off | **sous-ensemble** `C0-,C2,C5` (27 cellules) |

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

## Le budget de 2 Gio

RSS crête la plus haute observée, toutes cellules confondues : **1097 Mio** (53.5 % du budget de 2 Gio).

**Aucune cellule n'a dépassé 2 Gio**, et ce n'est pas une déduction : le daemon tournait
dans un scope `MemoryMax=2G MemorySwapMax=0`, où un dépassement se traduit par un kill du
noyau, pas par du swap. Il n'a pas été tué.

## Cellules à ne pas croire telles quelles

- 33 cellules ont été **rejouées** (une mesure bousculée remplacée par une mesure propre) ; seule la dernière figure dans les tableaux, le JSONL brut garde les deux.
- **13 cellules prises pendant que la machine swappait** (fts0-masque-non-vide@1.4M/C2d-free-term-rows/all, fts0-masque-non-vide@1.4M/C2e-free-term-common/1h, fts0-masque-non-vide@1.4M/C2e-free-term-common/24h, fts0-masque-non-vide@1.4M/C2e-free-term-common/all, fts0-masque-non-vide@1.4M/C3-groupby-hi/24h, fts0-masque-non-vide@1.4M/C3c-groupby-json/24h, fts0-masque-non-vide@1.4M/C3c-groupby-json/all, fts0-masque-non-vide@1.4M/C4b-raw-deep/24h, fts0-masque-non-vide@1.4M/C5-regex-json-planted/24h, fts0-masque-non-vide@1.4M/C5-regex-json-planted/all, fts0-masque-vide@1.4M/C3c-groupby-json/24h, fts0-masque-vide@1.4M/C3c-groupby-json/all, fts0-masque-vide@1.4M/C5-regex-json-planted/24h). Un chiffre pris sous swap est faux. Un rejeu a été TENTÉ pour les cellules de la configuration de référence ; celles qui restent listées ici sont celles pour lesquelles la machine n'a pas offert de fenêtre sans swap. Leur `p50` est à prendre comme une borne haute, leur `p95` comme non exploitable.
- **6 cellules en échec ou en erreur** — elles restent dans le tableau avec leur message :
  - `fts0-masque-non-vide` / `C5c-eq-json-hot` / 1h : {"error":"filtrage interdit sur le champ masqué « user » (field-filter actif pour votre rôle : un champ que vous ne pouvez pas voir ne peut pas être filtré)"} (statuts [400])
  - `fts0-masque-non-vide` / `C5c-eq-json-hot` / 24h : {"error":"filtrage interdit sur le champ masqué « user » (field-filter actif pour votre rôle : un champ que vous ne pouvez pas voir ne peut pas être filtré)"} (statuts [400])
  - `fts0-masque-non-vide` / `C5c-eq-json-hot` / all : {"error":"filtrage interdit sur le champ masqué « user » (field-filter actif pour votre rôle : un champ que vous ne pouvez pas voir ne peut pas être filtré)"} (statuts [400])
  - `fts0-masque-non-vide@1.4M` / `C5c-eq-json-hot` / 1h : {"error":"filtrage interdit sur le champ masqué « user » (field-filter actif pour votre rôle : un champ que vous ne pouvez pas voir ne peut pas être filtré)"} (statuts [400])
  - `fts0-masque-non-vide@1.4M` / `C5c-eq-json-hot` / 24h : {"error":"filtrage interdit sur le champ masqué « user » (field-filter actif pour votre rôle : un champ que vous ne pouvez pas voir ne peut pas être filtré)"} (statuts [400])
  - `fts0-masque-non-vide@1.4M` / `C5c-eq-json-hot` / all : {"error":"filtrage interdit sur le champ masqué « user » (field-filter actif pour votre rôle : un champ que vous ne pouvez pas voir ne peut pas être filtré)"} (statuts [400])

## Comment la latence monte avec le volume

Mesuré à plusieurs volumes sur la même machine, même binaire, masque vide, `PLUME_FTS_FIELDS=0`, fenêtre « tout ». C'est la pente qui répond à la question « des millions d'événements », pas un point isolé.

Réserve à connaître avant de citer ce tableau : les volumes viennent de **passes distinctes**, donc de bases distinctes et de nombres de répétitions possiblement différents (la colonne `reps` du JSONL brut le dit cellule par cellule). Les points sont comparables en ordre de grandeur, pas au pourcentage près. Une case vide = classe non mesurée à ce volume.

| Classe | 200 003 lignes | 1 440 003 lignes | rapport |
|---|---|---|---|
| `C1-scan-agg` | 51 | 2856 | x55.9 pour x7.2 de lignes ⚠ base au plancher |
| `C1b-scan-agg-dc` | 577 | 5109 | x8.9 pour x7.2 de lignes |
| `C2-free-term` | 652 | 5860 | x9.0 pour x7.2 de lignes |
| `C2b-regex-msg` | 502 | 3863 | x7.7 pour x7.2 de lignes |
| `C2c-fts-bar` | 51 | 51 | x1.0 pour x7.2 de lignes ⚠ base au plancher |
| `C3-groupby-hi` | 870 | 15.7 s | x18.0 pour x7.2 de lignes |
| `C3b-groupby-routable` | 151 | 152 | x1.0 pour x7.2 de lignes |
| `C3c-groupby-json` | 853 | 12.6 s | x14.8 pour x7.2 de lignes |
| `C4-raw-page1` | 52 | 52 | x1.0 pour x7.2 de lignes ⚠ base au plancher |
| `C4b-raw-deep` | 51 | 1055 | x20.6 pour x7.2 de lignes ⚠ base au plancher |
| `C4c-raw-keyset` | 54 | 54 | x1.0 pour x7.2 de lignes ⚠ base au plancher |
| `C5-regex-json-planted` | 552 | 6110 | x11.1 pour x7.2 de lignes |
| `C5b-regex-json-cold` | 652 | 9616 | x14.8 pour x7.2 de lignes |
| `C5c-eq-json-hot` | 51 | 54 | x1.1 pour x7.2 de lignes ⚠ base au plancher |
| `C0-plancher` | — | 51 | — |
| `C2d-free-term-rows` | — | 3406 | — |
| `C2e-free-term-common` | — | 2705 | — |

Une classe dont le rapport de latence suit le rapport de lignes est un **scan** : son coût est linéaire en volume et rien ne l'indexe. Une classe dont le rapport reste plat est servie par un index ou par un rollup.

⚠ **base au plancher** : au petit volume, la cellule était déjà au plancher fixe (~51 ms, voir `C0-plancher`). Le rapport affiché mesure alors la distance à ce plancher, PAS la pente du scan — ne pas le citer comme un facteur d'échelle.

## Leviers désignés par la mesure

Aucun n'est implémenté ici : c'est le rôle de l'instrument de les **désigner** et de chiffrer
le gain qu'on aurait le droit d'en attendre. Classés par gain mesuré décroissant. « Coût RAM »
dit ce que le levier ajouterait au budget de 2 Gio ; quand il est nul, c'est écrit.

### L1. Rendre la route de rollups compatible avec le masquage

*Gain mesuré : **36.1 s** au p50 sur la cellule la plus parlante (C3b masqué vs non masqué). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*

le MÊME group-by, le MÊME rôle : **152 ms** masque vide (servi depuis `rollup`, 63 lignes) contre **36.3 s** masque non vide (servi depuis `raw`, 70 lignes — les comptes diffèrent parce que la route de rollups est APPROCHÉE, `stats.approx=true` : c'est le prix de sa vitesse), soit **239.5x plus lent**. Le rempart de confidentialité est donc aussi un frein de performance : un masque non vide désarme la route de rollups (`handlers/query.rs:282`) parce que `event_rollup` stocke `src_ip`/`host` en clair. Deux voies : masquer à la lecture du rollup, ou matérialiser un rollup par classe de masque. **Coût RAM : celui d'un jeu de rollups supplémentaire** (mesuré en production : `event_rollup` = 4,4 Mio pour 1,4 M d'événements, donc marginal), plus le masquage au vol.

### L2. Étendre la route de rollups aux dimensions à haute cardinalité

*Gain mesuré : **15.5 s** au p50 sur la cellule la plus parlante (C3-groupby-hi / all). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*

`stats count by src_ip,host,source` sur tout l'historique : **15.7 s**, servi par `raw`. Seules les formes `by` dont TOUTES les dimensions tiennent dans `{source, severity}` sont routables (`rollup_route.rs:349-366`) ; dès qu'une dimension à haute cardinalité entre, on retombe sur le scan. **Coût RAM : celui du grain choisi** — un rollup à grain `src_ip` est borné en production par `PLUME_ROLLUP_SRCIP_TOPN` (50) précisément pour ne pas exploser, ce qui rend le résultat approché. Le compromis exactitude/mémoire doit être décidé, pas subi.

### L3. Le champ étendu non indexé n'a aucun chemin d'accès

*Gain mesuré : **9.6 s** au p50 sur la cellule la plus parlante (C5b vs C5c). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*

regex sur `fields.object` (aucun index) : **9.6 s** contre **54 ms** pour une égalité sur `fields.user`, qui a un index d'expression partiel. Dix champs seulement sont indexés (`HOT_FIELDS` : action, user, owner, kind, ns, role, scope, verb, resource, operation) sur les **241 clés distinctes mesurées en production**. Pour les 231 autres, toute recherche est un scan avec `json_extract` par ligne. C'est exactement la promesse « sur tous les champs » qui est en jeu. Voies : `event_fields_fts` (déjà écrit, voir le levier sur le coût de `PLUME_FTS_FIELDS`), ou des index d'expression sur demande, ou un stockage colonnaire des champs. **Coût RAM : un index d'expression par champ**, à arbitrer — c'est pour ça que `PLUME_AUTOINDEX_MAX` existe.

### L4. Câbler FTS5 sur le chemin GXQL

*Gain mesuré : **3.4 s** au p50 sur la cellule la plus parlante (C2c vs C2d). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*

la même aiguille, le même nombre de lignes rendues : **3.4 s** par GXQL (`message LIKE '%…%'`, scan complet) contre **51 ms** par `/api/search` (index FTS5 `event_fts`). L'index EXISTE et est déjà payé — mesuré en production : 389 Mio, soit 0,61 fois le poids de la table — mais il n'est câblé que sur `/api/search`. Sur le chemin GXQL, un terme libre devient `col LIKE '%motif%'` (`core/src/soql/dialect.rs:65-67`, appelé depuis `soql/mod.rs:881-891`), donc un scan complet. **Coût RAM : nul** — l'index est déjà construit et déjà en base.

### L5. Faire du keyset le défaut de la pagination profonde

*Gain mesuré : **1001 ms** au p50 sur la cellule la plus parlante (C4b vs C4c). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*

page profonde en `OFFSET` : **1055 ms** ; la même profondeur en curseur keyset : **54 ms** — et ce, en rendant PLUS de données (le keyset porte toutes les colonnes, la page `OFFSET` n'en projette que cinq), ce qui rend l'écart conservateur. Le keyset existe déjà (`keyset:true`) mais il est **désactivé dès que le pipeline contient `| table` ou `| fields`** (`handlers/query.rs:198-205`) — c'est-à-dire dès qu'on projette des colonnes, ce que fait toute récupération RAW réelle. **Coût RAM : nul.**

### L6. Le plancher fixe par requête

*Gain mesuré : **51 ms** au p50 sur la cellule la plus parlante (toutes les cellules). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*

une requête dont le SQL coûte 0.1 ms revient en 51 ms : **51 ms de coût fixe**, indépendant du volume. Cause identifiée dans le code : le chien de garde de budget est un thread qui boucle sur `sleep(50 ms)` et il est **joint** avant que la réponse ne parte (`daemon/src/query_exec.rs:466-537`, `done.store(true)` puis `watchdog.join()`). Une attente à condition (condvar avec délai) ou un thread non joint rendrait ces millisecondes à **toutes** les requêtes. **Coût RAM : nul.** C'est le levier le moins cher du lot, et il domine toutes les requêtes rapides — donc toute l'expérience interactive.

### L7. Le coût de `PLUME_FTS_FIELDS=1`, et à qui il profite

*Coût DISQUE mesuré : **+138 Mio** (+11 %) sur la base. Ce n'est pas un gain, c'est une dépense — et le document dit plus bas à qui elle profite.*

activer `PLUME_FTS_FIELDS=1` a fait passer la base de **1263 Mio à 1401 Mio** (+138 Mio, +11 %). RSS crête, sur les SEULES classes mesurées dans les deux configurations : **1072 Mio** à `FTS_FIELDS=0` contre **691 Mio** à `FTS_FIELDS=1`. Attention : chaque configuration repart d'un daemon neuf, donc ces deux crêtes n'ont pas eu le même historique pour monter — l'écart n'est PAS attribuable au drapeau seul. Le chiffre solide de cette ligne est le coût DISQUE. Écart de latence observé sur le terme libre GXQL (tout l'historique) : **501 ms** en défaveur de FTS_FIELDS=1 — mais cet écart ne peut PAS venir du drapeau, puisque le chemin GXQL ne lit jamais `event_fields_fts` : c'est du bruit de mesure sur une machine partagée, et il est reporté comme tel. À retenir : `event_fields_fts` n'est lu que par `/api/search` (`handlers/search.rs:146-157`). Le chemin GXQL ne le consulte JAMAIS — donc son coût en disque et en ingest est payé sans que les requêtes GXQL en profitent. C'est le levier « Câbler FTS5 sur le chemin GXQL » qui rendrait ce coût déjà consenti utile aux requêtes GXQL.

## Ce qui n'est PAS mesuré ici

- **Le tier froid** (`--features cold_tier` + `PLUME_COLD_TIER=1`) : le binaire est compilé
  avec la feature, mais toutes les cellules tournent `PLUME_COLD_TIER=0`. Aucun chiffre de ce
  document ne dit quoi que ce soit du chemin Parquet ni du moteur vectorisé.
- **La concurrence** : une requête à la fois. `PLUME_QUERY_CONCURRENCY=3` est en place mais
  jamais saturé (`sem_wait_ms` reste nul). Le comportement à 10 utilisateurs simultanés n'est
  pas mesuré.
- **Le multi-tenant** (`PLUME_MULTI_TENANT=1`) : tout est mesuré en mode 0.
- **Le cache de pages froid** : impossible de le vider sans privilège root sur la machine de
  mesure. La colonne `lu` dit ce qui a réellement atteint le disque ; elle ne dit pas ce que
  ferait un démarrage à froid complet.
- **La fidélité du texte** : le corps des messages est synthétique. Les chiffres FTS5, `LIKE`
  et `REGEXP` dépendent directement de ce vocabulaire ; c'est la limite la plus sérieuse du
  banc et elle est décrite dans `bench/gen_events.py` (`VOCAB`).
- **`PLUME_AUTOINDEX`** est à 0 (le défaut livré) alors que notre production le met à 1 : les
  index d'expression auto-créés par l'usage ne sont donc pas dans le tableau.

## Reproduire, et contredire

```sh
# 1. le profil de données (déjà versionné ; à re-extraire seulement pour une autre prod)
#    bench/prod-profile.sql, LECTURE SEULE, n'extrait aucune valeur de ligne
# 2. la matrice complète, de bout en bout :
CARGO_TARGET_DIR=../.bench-target cargo build --release --features cold_tier \
    --manifest-path daemon/Cargo.toml
bench/run.sh                       # 10 M d'événements
BENCH_EVENTS=1000000 bench/run.sh  # 1 M, pour itérer
# 3. le rendu (les deux options portent des mesures, pas de la décoration :
#    --ingest-curve = débit/RSS échantillonnés pendant le remplissage,
#    --fill-log     = débit cumulé relevé par le générateur lui-même) :
python3 bench/report.py ../.bench/results.jsonl \
    --ingest-curve ../.bench/ingest_rate.csv \
    --fill-log ../.bench/matrix.log -o docs/BENCHMARK.md
```

Le générateur est déterministe : `python3 bench/gen_events.py --count N --end-ts T --digest`
imprime le SHA-256 du flux. Deux exécutions avec les mêmes paramètres donnent la même
empreinte — c'est ce qui rend un désaccord sur les chiffres arbitrable.

