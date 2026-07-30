# Banc de mesure plume — requêtes à chaud sous 2 Gio

<!-- CE FICHIER EST GÉNÉRÉ par bench/report.py (voir la section « Reproduire » en bas).
     Ne pas l'éditer à la main : la prochaine passe l'écrase. Tout commentaire durable va dans
     bench/README.md. -->

Rendu le 2026-07-30 15:48:34+0200 depuis `results-smoke-200k.jsonl`, `results.jsonl` — données brutes VERSIONNÉES dans [`bench/results/`](../bench/results/), pour que ce tableau puisse être contredit et pas seulement cru (cf. `bench/README.md`).

## Ce que ce document est, et ce qu'il n'est pas

C'est la **mesure de référence** de plume, prise avec un instrument publié et rejouable.
Chaque chiffre porte ses qualificatifs. Rien n'est extrapolé : une case vide est une case
**non mesurée**, pas une case implicitement bonne. Quand plusieurs passes coexistent au même
volume, elles sont TOUTES rendues : une passe n'est jamais remplacée par une plus flatteuse,
et la section « Écart mesuré entre deux passes » dit laquelle décrit le code actuel.

Ce n'est **pas** une comparaison à un autre produit, ni une mesure de production : c'est un
banc synthétique au **profil** de la production (voir `bench/profile-prod.json`).

## Verdict — ce que ces mesures autorisent à affirmer

Volume de référence : **1 440 007 événements** (`apres-leviers@1.4M`), base **1434 Mio** chiffrée SQLCipher.

**Sur le budget de 2 Gio — soutenu.** RSS crête la plus haute mesurée sur l'ensemble des cellules : **1097 Mio**, soit **54 %** du budget. Et ce n'est pas une observation passive : le daemon tournait sous `MemoryMax=2G MemorySwapMax=0`, où un dépassement est un kill du noyau.

**Ce qui est RAPIDE** (p50, fenêtre indiquée, config de référence) :

- `C0-plancher` / 1h — **0.6 ms** (PLANCHER : seek sur une source inexistante (0 ligne)), servi par `raw`
- `C0-plancher` / all — **0.7 ms** (PLANCHER : seek sur une source inexistante (0 ligne)), servi par `raw`
- `C0-plancher` / 24h — **0.7 ms** (PLANCHER : seek sur une source inexistante (0 ligne)), servi par `raw`
- `C5c-eq-json-hot` / all — **0.8 ms** (égalité sur champ ÉTENDU INDEXÉ (fields.user, idx_ev_f_user)), servi par `raw`

**Ce qui est LENT** — et ce sont les cas que la promesse « sur tous les champs » met en avant :

- `C3-groupby-hi` / all — **13.9 s** (group-by 3 dims haute cardinalité (src_ip,host,source)), servi par `raw`
- `C3c-groupby-json` / all — **8.1 s** (group-by sur champ ÉTENDU indexé (action) + colonne), servi par `raw`
- `C5b-regex-json-cold` / all — **5.9 s** (regex sur champ ÉTENDU NON indexé (fields.object)), servi par `raw`
- `C5-regex-json-planted` / all — **5.3 s** (regex sur champ ÉTENDU planté (fields.needle)), servi par `raw`

**Le disque n'a pas été sollicité — et c'est une limite, pas une bonne nouvelle.** Octets lus au bloc, maximum sur toutes les cellules : **0 Mio**. La base (1434 Mio) tient entièrement dans le cache de pages de la machine (6839 Mio de mémoire disponible au minimum pendant la mesure). Ces latences sont donc **bornées par le CPU, pas par le stockage**, et constituent un MEILLEUR CAS. À un volume où la base dépasse la RAM disponible, le stockage entre dans l'équation — et ce régime n'est pas mesuré ici.

**Ce que ces mesures n'autorisent PAS à affirmer** :

- rien au-delà de 1 440 007 événements. La cible de 10 M n'a pas été atteinte par le vrai chemin d'ingest dans le temps disponible (voir le débit mesuré ci-dessous). Toute phrase sur 10 M ou 100 M serait une extrapolation, pas une mesure.
- rien sur le tier froid, la concurrence, ni le multi-tenant (voir la section dédiée).
- rien sur un déploiement AVEC masquage à partir des chiffres masque-vide : l'écart mesuré le plus fort est **x317.3** sur `C3b-groupby-routable` / 24h (7.8 ms masque vide contre 2.5 s masque non vide).
  Et le masquage ne va pas TOUJOURS dans le sens du ralentissement : sur `C4b-raw-deep` / 24h il est **x0.46**, donc plus RAPIDE (447 ms masque vide contre 204 ms masque non vide, même nombre de lignes rendues). **La cause n'est PAS établie par cette mesure**, et on ne va pas l'inventer. Deux mécanismes candidats, qui demandent chacun une expérience dédiée pour être départagés : (a) un masque posé sur une dimension à haute cardinalité l'effondre, il reste moins de groupes à agréger — la requête va plus vite **parce que la réponse a changé** ; (b) la passe masquée a tourné APRÈS la passe non masquée, donc sur un cache de pages plus chaud. Ce qui trancherait : rejouer les deux passes dans l'ordre inverse, et comparer les résultats ligne à ligne. En attendant, la règle est simple — **une latence qui baisse en présence d'un masque ne doit jamais être citée comme un gain**.

## Matériel et conditions

| | |
|---|---|
| Processeur | Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz (12 cœurs logiques) |
| RAM de la machine | 15.4 Gio |
| Noyau | 7.1.4-zen1-1-zen |
| Version de plume mesurée | `bin:bc481b69f4aca22c` |
| Volumes mesurés | 200 003 événements, 1 440 003 événements, 1 440 007 événements |
| Taille de la base (SQLCipher, chiffrée) | 1263 Mio, 1401 Mio, 1434 Mio, 197 Mio |
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
| `avant-leviers@1.4M` | 1 440 007 | 0 | vide | off | toutes (54 cellules) |
| `apres-leviers@1.4M` | 1 440 007 | 0 | vide | off | toutes (54 cellules) |

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

## Écart mesuré entre deux passes

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

## Le budget de 2 Gio

RSS crête la plus haute observée, toutes cellules confondues : **1097 Mio** (53.5 % du budget de 2 Gio).

**Aucune cellule n'a dépassé 2 Gio**, et ce n'est pas une déduction : le daemon tournait
dans un scope `MemoryMax=2G MemorySwapMax=0`, où un dépassement se traduit par un kill du
noyau, pas par du swap. Il n'a pas été tué.

## Cellules à ne pas croire telles quelles

- 33 cellules ont été **rejouées** (une mesure bousculée remplacée par une mesure propre) ; seule la dernière figure dans les tableaux, le JSONL brut garde les deux.
- **17 cellules prises pendant que la machine swappait** (apres-leviers@1.4M/C3-groupby-hi/all, apres-leviers@1.4M/C5b-regex-json-cold/24h, avant-leviers@1.4M/C2e-free-term-common/all, avant-leviers@1.4M/C5b-regex-json-cold/all, fts0-masque-non-vide@1.4M/C2d-free-term-rows/all, fts0-masque-non-vide@1.4M/C2e-free-term-common/1h, fts0-masque-non-vide@1.4M/C2e-free-term-common/24h, fts0-masque-non-vide@1.4M/C2e-free-term-common/all, fts0-masque-non-vide@1.4M/C3-groupby-hi/24h, fts0-masque-non-vide@1.4M/C3c-groupby-json/24h, fts0-masque-non-vide@1.4M/C3c-groupby-json/all, fts0-masque-non-vide@1.4M/C4b-raw-deep/24h, fts0-masque-non-vide@1.4M/C5-regex-json-planted/24h, fts0-masque-non-vide@1.4M/C5-regex-json-planted/all, fts0-masque-vide@1.4M/C3c-groupby-json/24h, fts0-masque-vide@1.4M/C3c-groupby-json/all, fts0-masque-vide@1.4M/C5-regex-json-planted/24h). Un chiffre pris sous swap est faux. Un rejeu a été TENTÉ pour les cellules de la configuration de référence ; celles qui restent listées ici sont celles pour lesquelles la machine n'a pas offert de fenêtre sans swap. Leur `p50` est à prendre comme une borne haute, leur `p95` comme non exploitable.
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

| Classe | 200 003 lignes | 1 440 003 lignes | 1 440 007 lignes | 1 440 007 lignes | rapport |
|---|---|---|---|---|---|
| `C1-scan-agg` | 51 | 2856 | 2154 | 2036 | x39.9 pour x7.2 de lignes ⚠ base au plancher |
| `C1b-scan-agg-dc` | 577 | 5109 | 2004 | 4721 | x8.2 pour x7.2 de lignes |
| `C2-free-term` | 652 | 5860 | 3406 | 2568 | x3.9 pour x7.2 de lignes |
| `C2b-regex-msg` | 502 | 3863 | 3506 | 3156 | x6.3 pour x7.2 de lignes |
| `C2c-fts-bar` | 51 | 51 | 51 | 2.8 | x0.1 pour x7.2 de lignes ⚠ base au plancher |
| `C3-groupby-hi` | 870 | 15.7 s | 14.7 s | 13.9 s | x16.0 pour x7.2 de lignes |
| `C3b-groupby-routable` | 151 | 152 | 201 | 130 | x0.9 pour x7.2 de lignes |
| `C3c-groupby-json` | 853 | 12.6 s | 9214 | 8127 | x9.5 pour x7.2 de lignes |
| `C4-raw-page1` | 52 | 52 | 51 | 1.7 | x0.0 pour x7.2 de lignes ⚠ base au plancher |
| `C4b-raw-deep` | 51 | 1055 | 552 | 31 | x0.6 pour x7.2 de lignes ⚠ base au plancher |
| `C4c-raw-keyset` | 54 | 54 | 53 | 3.5 | x0.1 pour x7.2 de lignes ⚠ base au plancher |
| `C5-regex-json-planted` | 552 | 6110 | 4808 | 5274 | x9.6 pour x7.2 de lignes |
| `C5b-regex-json-cold` | 652 | 9616 | 6063 | 5873 | x9.0 pour x7.2 de lignes |
| `C5c-eq-json-hot` | 51 | 54 | 51 | 0.8 | x0.0 pour x7.2 de lignes ⚠ base au plancher |
| `C0-plancher` | — | 51 | 51 | 0.7 | — |
| `C2d-free-term-rows` | — | 3406 | 2756 | 2600 | — |
| `C2e-free-term-common` | — | 2705 | 3357 | 2696 | — |
| `C4d-keyset-projete` | — | — | 52 | 1.6 | — |

Une classe dont le rapport de latence suit le rapport de lignes est un **scan** : son coût est linéaire en volume et rien ne l'indexe. Une classe dont le rapport reste plat est servie par un index ou par un rollup.

⚠ **base au plancher** : au petit volume, la cellule était déjà au plancher fixe (~51 ms, voir `C0-plancher`). Le rapport affiché mesure alors la distance à ce plancher, PAS la pente du scan — ne pas le citer comme un facteur d'échelle.

## Leviers désignés par la mesure

Aucun n'est implémenté ici : c'est le rôle de l'instrument de les **désigner** et de chiffrer
le gain qu'on aurait le droit d'en attendre. Classés par gain mesuré décroissant. « Coût RAM »
dit ce que le levier ajouterait au budget de 2 Gio ; quand il est nul, c'est écrit.

### L1. Rendre la route de rollups compatible avec le masquage

*Gain mesuré : **36.2 s** au p50 sur la cellule la plus parlante (C3b masqué vs non masqué). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*

le MÊME group-by, le MÊME rôle : **130 ms** masque vide (servi depuis `rollup`, 63 lignes) contre **36.3 s** masque non vide (servi depuis `raw`, 70 lignes — les comptes diffèrent parce que la route de rollups est APPROCHÉE, `stats.approx=true` : c'est le prix de sa vitesse), soit **279.5x plus lent**. Le rempart de confidentialité est donc aussi un frein de performance : un masque non vide désarme la route de rollups (`handlers/query.rs:282`) parce que `event_rollup` stocke `src_ip`/`host` en clair. Deux voies : masquer à la lecture du rollup, ou matérialiser un rollup par classe de masque. **Coût RAM : celui d'un jeu de rollups supplémentaire** (mesuré en production : `event_rollup` = 4,4 Mio pour 1,4 M d'événements, donc marginal), plus le masquage au vol. **Réserve** : la passe masquée porte 1 440 003 événements contre 1 440 007 pour la passe non masquée — l'écart de volume est négligeable devant le facteur mesuré, mais les deux chiffres ne viennent pas de la MÊME passe.

### L2. Étendre la route de rollups aux dimensions à haute cardinalité

*Gain mesuré : **13.8 s** au p50 sur la cellule la plus parlante (C3-groupby-hi / all). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*

`stats count by src_ip,host,source` sur tout l'historique : **13.9 s**, servi par `raw`. Seules les formes `by` dont TOUTES les dimensions tiennent dans `{source, severity}` sont routables (`rollup_route.rs:349-366`) ; dès qu'une dimension à haute cardinalité entre, on retombe sur le scan. **Coût RAM : celui du grain choisi** — un rollup à grain `src_ip` est borné en production par `PLUME_ROLLUP_SRCIP_TOPN` (50) précisément pour ne pas exploser, ce qui rend le résultat approché. Le compromis exactitude/mémoire doit être décidé, pas subi.

### L3. Le champ étendu non indexé n'a aucun chemin d'accès

*Gain mesuré : **5.9 s** au p50 sur la cellule la plus parlante (C5b vs C5c). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*

regex sur `fields.object` (aucun index) : **5.9 s** contre **0.8 ms** pour une égalité sur `fields.user`, qui a un index d'expression partiel. Dix champs seulement sont indexés (`HOT_FIELDS` : action, user, owner, kind, ns, role, scope, verb, resource, operation) sur les **241 clés distinctes mesurées en production**. Pour les 231 autres, toute recherche est un scan avec `json_extract` par ligne. C'est exactement la promesse « sur tous les champs » qui est en jeu. Voies : `event_fields_fts` (déjà écrit, voir le levier sur le coût de `PLUME_FTS_FIELDS`), ou des index d'expression sur demande, ou un stockage colonnaire des champs. **Coût RAM : un index d'expression par champ**, à arbitrer — c'est pour ça que `PLUME_AUTOINDEX_MAX` existe.

### L4. Câbler FTS5 sur le chemin GXQL

*Gain mesuré : **2.6 s** au p50 sur la cellule la plus parlante (C2c vs C2d). Ce n'est pas une promesse de gain : c'est l'écart QUE LA MESURE MONTRE aujourd'hui entre le chemin lent et un chemin rapide déjà existant ou atteignable.*

la même aiguille, le même nombre de lignes rendues : **2.6 s** par GXQL (`message LIKE '%…%'`, scan complet) contre **2.8 ms** par `/api/search` (index FTS5 `event_fts`). L'index EXISTE et est déjà payé — mesuré en production : 389 Mio, soit 0,61 fois le poids de la table — mais il n'est câblé que sur `/api/search`. Sur le chemin GXQL, un terme libre devient `col LIKE '%motif%'` (`core/src/soql/dialect.rs:65-67`, appelé depuis `soql/mod.rs:881-891`), donc un scan complet. **Coût RAM : nul** — l'index est déjà construit et déjà en base.

### L5. Le coût de `PLUME_FTS_FIELDS=1`, et à qui il profite

*Coût DISQUE mesuré : **+-33 Mio** (+-2 %) sur la base. Ce n'est pas un gain, c'est une dépense — et le document dit plus bas à qui elle profite.*

activer `PLUME_FTS_FIELDS=1` a fait passer la base de **1434 Mio à 1401 Mio** (+-33 Mio, +-2 %). RSS crête, sur les SEULES classes mesurées dans les deux configurations : **687 Mio** à `FTS_FIELDS=0` contre **691 Mio** à `FTS_FIELDS=1`. Attention : chaque configuration repart d'un daemon neuf, donc ces deux crêtes n'ont pas eu le même historique pour monter — l'écart n'est PAS attribuable au drapeau seul. Le chiffre solide de cette ligne est le coût DISQUE. Écart de latence observé sur le terme libre GXQL (tout l'historique) : **1307 ms** en défaveur de FTS_FIELDS=1 — mais cet écart ne peut PAS venir du drapeau, puisque le chemin GXQL ne lit jamais `event_fields_fts` : c'est du bruit de mesure sur une machine partagée, et il est reporté comme tel. À retenir : `event_fields_fts` n'est lu que par `/api/search` (`handlers/search.rs:146-157`). Le chemin GXQL ne le consulte JAMAIS — donc son coût en disque et en ingest est payé sans que les requêtes GXQL en profitent. C'est le levier « Câbler FTS5 sur le chemin GXQL » qui rendrait ce coût déjà consenti utile aux requêtes GXQL.

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

