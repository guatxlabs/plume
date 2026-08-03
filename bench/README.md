# `bench/` — l'instrument de mesure

Ce répertoire n'optimise rien. Il rend les optimisations **prouvables**. « Mesurer d'abord,
optimiser ensuite » : sans instrument publié, une amélioration annoncée n'est pas vérifiable et un
chiffre annoncé n'est pas contestable.

## Les pièces

| Fichier | Rôle |
|---|---|
| `prod-profile.sql` | Extraction **lecture seule** du profil de données d'une production. N'extrait que des agrégats : comptes, cardinalités, longueurs, noms de clés. **Jamais** une valeur de ligne. |
| `distill_profile.py` | Transforme la sortie du SQL ci-dessus en `profile-prod.json`, en marquant chaque section `measured` ou `derived`. |
| `profile-prod.json` | Le profil versionné. C'est la **seule** entrée du générateur. |
| `make_fleet_profile.py` | **Dérive** un profil FLOTTE (`profile-fleet-N.json`) du profil mesuré : le nombre d'hôtes devient un paramètre explicite. Refuse de deviner quelles sources sont host-locales — voir ci-dessous. |
| `fleet-per-host.txt` | La **déclaration d'opérateur** que le script exige : quelles sources tournent sur chaque machine. Une ligne, une raison. |
| `make_axis_profile.py` | **DÉRIVE un profil qui ne diffère du mesuré que par UN axe** — cardinalité des clés étendues, taille d'événement, distribution de sévérité, nom des sources. Chaque axe vient d'une DÉCISION du chemin d'exécution (voir plus bas). Refuse d'en changer deux à la fois : un profil qui diffère sur deux paramètres ne mesure ni l'un ni l'autre. |
| `campagne-generique.sh` | La campagne **multi-profils** : la même matrice sur chaque profil, à volume égal, **témoin mesuré deux fois** pour donner la bande de bruit. |
| `probe_route_b.py` + `campagne-noms-sources.sh` | La sonde de la **ROUTE B** (`event_dim_rollup`), la seule forme que la matrice ne tire pas, et la seule dont la route dépend du **NOM** de la source. |
| `campagne-10m.sh` | Le remplissage à **10 M par le vrai chemin**, avec **preuve de survie du jeu** (recompte après matrice). |
| `gen_events.py` | Générateur **déterministe** (splitmix64, graine explicite, aucun appel à l'horloge) au profil ci-dessus. Zéro donnée réelle. |
| `measure.py` | La matrice : latence p50/p95, **RSS crête mesurée** (échantillonnage /proc à 15 ms), lecture disque, pression machine. Les fenêtres y sont **dérivées**, pas énumérées. |
| `probe.py` | L'échantillonneur d'ingest. Relève, à chaque tick, ce qui permet de dire POURQUOI le débit tombe : CPU du daemon, CPU du reste de la machine, octets lus/écrits au bloc, stall mémoire du cgroup. |
| `parity.py` | **La réponse est-elle la MÊME ?** Interroge DEUX daemons (avec et sans tier froid) sur la MÊME matrice et compare **les valeurs**, pas les temps. Le jeu de contrôles n'est pas écrit : c'est `query_classes` × `windows` de `measure.py`. |
| `concurrency.py` | **N analystes en même temps.** L'angle mort que `measure.py` déclare lui-même (une requête à la fois → personne n'attend son tour). Mesure, dans cet ordre : la JUSTESSE sous charge (chaque réponse concurrente comparée par sa VALEUR à la réponse obtenue seul), la RAM sous budget appliqué (RSS + cgroup + `memory.events`), la courbe de latence/débit, et le DÉCOUPAGE de l'attente (`sem_wait_ms` = le permit ; `db_lock_wait_ms` = le verrou de la connexion partagée ; `prepare_ms`/`exec_ms`). Le mélange de requêtes est **dérivé** de la passe solo qui le précède. |
| `report.py` | Rend `docs/BENCHMARK.md`. Ne masque aucune cellule. |
| `run.sh` | **La commande unique.** Enchaîne tout, budget de 2 Gio *appliqué* par cgroup. |
| `results/` | Les **données brutes** de la mesure publiée dans `docs/BENCHMARK.md`. Versionnées exprès — voir ci-dessous. |

## Les fenêtres sont DÉRIVÉES, et une fenêtre non couverte n'est pas mesurée

`measure.py` ne porte pas une liste de fenêtres choisies. Chacune vient d'un paramètre du **produit**
— ou de l'absence de bornes :

| Fenêtre | D'où elle vient |
|---|---|
| `1h`, `24h` | l'usage interactif (triage, tableau de bord). |
| `{N}d` | `PLUME_COLD_HOT_WINDOW_DAYS` (défaut **7**, `daemon/src/cold_store/aging.rs`) — **la frontière chaud/froid du produit**. Passer la fenêtre chaude à 14 j déplace la cellule mesurée : rien n'est à retoucher ici. |
| `au-dela-{N}d` | la bande entièrement plus vieille que la fenêtre chaude : le régime **pur-froid** quand le tier froid est actif. |
| `{R}d` | `PLUME_RETENTION_DAYS` — toute la rétention. |
| `all` | sans borne : traverse la frontière. Le cas le plus coûteux. |

**La garde** : une fenêtre bornée n'est tirée que si le jeu de données la **couvre**
(`portée <= span_days`). Sur un jeu de 28 jours, la fenêtre « 30 j » n'est donc PAS mesurée — elle
mesurerait `all` sous une étiquette qui ment. Elle est écrite dans le JSONL comme **non mesurée avec
son motif**, et `docs/BENCHMARK.md` la publie comme telle. La garde compare une portée à une
étendue : elle n'a aucune liste de fenêtres interdites, donc elle vaut aussi pour toute fenêtre
ajoutée plus tard. Vérifier sans rien mesurer :

```sh
python3 bench/measure.py --list-windows --end-ts 0 --span-days 28 --hot-window-days 7 \
    --retention-days 30 --user x --password x --pid 1 --config-id x
```

## La concurrence — les gardes sont DÉRIVÉES, y compris celle du balayage

`concurrency.py` n'a pas de liste de requêtes ni de liste de niveaux « autorisés ». Tout ce qui
pourrait être écrit à la main y est dérivé d'une mesure ou d'une déclaration du daemon :

| Ce qui pourrait être écrit à la main | Ce dont c'est dérivé |
|---|---|
| la taille du sémaphore mesurée | **demandée au daemon** (`/api/system/diag` publie `PLUME_QUERY_CONCURRENCY`). `--expect-sem` compare l'étiquette de la passe à ce que le daemon applique VRAIMENT, et refuse si les deux divergent : une passe dont l'étiquette ment ne mesure rien. |
| le mélange de requêtes | la passe SOLO qui le précède : chaque **famille** de la matrice (`C1`…`C6`) entre par son représentant le plus coûteux, s'il coûte au moins 10 × le **plancher mesuré** dans la même passe. La famille du plancher échoue à son propre test et s'exclut d'elle-même. Le plancher est ajouté à part — il mesure le clic de tableau de bord sous charge. |
| la fenêtre | la seule fenêtre **sans borne** que `measure.windows` retient (le cas le plus coûteux). Reconnue à cette propriété, pas à son nom. |
| « les deux passes sont comparables » | le mélange est **DÉRIVÉ par la première passe puis IMPOSÉ aux suivantes** (`--mix`, posé par `run.sh`). Deux passes qui dérivent chacune le leur peuvent différer — mesuré : `C5` 3,7 s contre `C5b` 6,0 s, deux classes de la même famille que la machine peut départager autrement d'une fois sur l'autre — et leur écart de débit ne serait alors plus attribuable au sémaphore. La dérivation propre de chaque passe reste calculée et publiée à côté du mélange imposé. `report.py` refuse en plus de publier la comparaison de deux passes dont le mélange diffère. |
| les niveaux du balayage | libres, mais **gardés** : le balayage doit contenir un point strictement en dessous du sémaphore ET un point strictement au-dessus. En dessous, aucune requête ne peut attendre ; la file ne commence qu'au-delà. Un balayage qui ne franchit pas ce point mesure un seul régime et l'appelle « la capacité ». |
| « la réponse a changé » | l'empreinte de `parity.py` (insensible à l'ordre) + le total de pagination, contre la référence SOLO de la MÊME passe. Une classe dont la réponse varie **déjà seule** est retirée du verdict, et le retrait est publié. |
| « le champ `sem_wait_ms` est faux » | la sémantique d'un sémaphore : à *N* analystes pour *S* ≥ *N* permis, **aucune** requête ne peut attendre son tour. Toute attente publiée à ces niveaux est donc autre chose. Aucun seuil n'intervient — la garde compare un compte de permis à un compte de clients, elle vaut donc pour toute taille de sémaphore. Elle a mordu (10,2 s publiées sous ce nom, 16,5 s en solo) ; depuis le correctif elle **fait échouer le harnais** (`rc=5`) au lieu de publier un chiffre qui enverrait l'exploitant augmenter le sémaphore. |
| « d'où vient l'attente, si ce n'est pas le sémaphore » | le daemon publie le découpage TOTAL (`prepare + sem_wait + exec == server`, `daemon/src/query_timing.rs`) et, à part, `db_lock_wait_ms` — le temps passé à OBTENIR le verrou de la connexion partagée. Le harnais ne le recalcule pas : il le relaie. |
| « le daemon est prêt » | trois tirs consécutifs dont l'attente avant moteur est **sous la milliseconde**. Cette attente est DÉRIVÉE (`server_ms - exec_ms` : tout ce que la requête subit avant d'exécuter), jamais `sem_wait_ms` seul — depuis que ce champ ne mesure plus que le permit, il est nul par construction dès qu'un permit est libre, et une sonde qui ne regarderait que lui déclarerait « au repos » un daemon qui tient encore le verrou d'écriture. Le temps qu'il a fallu est publié — c'est lui-même une mesure. |

```sh
BENCH_PHASES=concurrency BENCH_DIR=<copie d une base remplie> bench/run.sh
# variables : BENCH_SEM_SWEEP (défaut 3,8) · BENCH_CONC_LEVELS (défaut 1,2,3,4,6,8,10)
#             BENCH_CONC_ROUNDS (passages par analyste) · BENCH_CONC_PROBE_REPS
```

## Le profil FLOTTE — ce qui est mesuré, ce qui est dérivé

La production profilée est **mono-nœud** : ses 32 sources ont toutes `distinct_hosts: 1`. Comme
`host` est l'une des six colonnes indexées, tout chiffre publié sur un filtre ou un group-by par
hôte y porte sur un cas **dégénéré de cardinalité 1**. `make_fleet_profile.py` produit donc des
profils où la taille de flotte est un **paramètre explicite** :

```sh
python3 bench/make_fleet_profile.py --hosts 50 --per-host @bench/fleet-per-host.txt \
    -o bench/profile-fleet-50.json
BENCH_PROFILE=$PWD/bench/profile-fleet-50.json BENCH_EVENTS=600000 bench/run.sh
```

| | |
|---|---|
| **Mesuré**, repris tel quel | par source : severity, catégories, longueurs de message et de `fields`, clés étendues avec types/longueurs/cardinalités, taux de `src_ip` ; la courbe horaire ; les histogrammes. |
| **Dérivé**, marqué `provenance: "derived"` | le poids `n` des sources host-locales (multiplié par le nombre d'hôtes) et la cardinalité de `host`. Chaque source garde son `n_measured_mono_host`. |
| **Ni l'un ni l'autre — déclaré** | *quelles* sources sont host-locales. Le profil mono-nœud ne contient rien qui permette de le déduire : `--per-host` est **obligatoire**, et le script s'arrête plutôt que de deviner. La déclaration est versionnée dans `fleet-per-host.txt`, une ligne par source avec sa raison. |
| **Non multiplié**, délibérément | la cardinalité des `src_ip` (une flotte plus grande ne crée pas plus de clients sur Internet), le vocabulaire des messages, la densité par hôte. |

La répartition des événements sur les hôtes est **uniforme** : c'est le cas le plus dur pour un
group-by (tous les groupes sont peuplés) et le plus facile pour un filtre sur un hôte (sélectivité
exactement 1/N). C'est une hypothèse de banc, pas une mesure — une vraie flotte est déséquilibrée.

## La généricité — les axes sont DÉRIVÉS du chemin d'exécution, et ceux qu'on écarte le sont AUSSI

Un chiffre mesuré sur notre profil prouve NOTRE cas. Pour savoir s'il tient ailleurs, il faut le
remesurer sur des jeux qui diffèrent, et publier l'écart. Encore faut-il ne pas choisir les axes au
hasard : chacun de ceux ci-dessous correspond à une **décision** que le daemon prend en fonction de
la DONNÉE, pas de la requête.

| Axe mesuré | La décision qu'il déplace | Ancre dans le code |
|---|---|---|
| cardinalité de `host` | sélectivité de `idx_event_host` (filtre) et nombre de groupes (group-by) | `migrate.rs` (`idx_event_host`) |
| cardinalité des clés étendues | sélectivité du **seek d'index d'expression** sur les 10 clés de `HOT_FIELDS`, et nombre de groupes d'un `by <clé>` | `soql_glue.rs` (`HOT_FIELDS`), `maintenance.rs` (`idx_ev_f_*`) |
| taille d'événement | **aucun index** ne porte sur `message` ni `fields` ; en GXQL un terme libre compile en `LIKE '%…%'`. Le coût est proportionnel aux OCTETS lus | `db/schema.sql`, compilateur GXQL (`freetext_col`) |
| distribution de sévérité | `event_rollup.src_ip` n'est une DIMENSION que si `severity >= PLUME_ROLLUP_SRCIP_MIN_SEV` (défaut 3) — sinon la valeur est ramenée à `''` | `rollups.rs` |
| **nom** des sources | la ROUTE B (`event_dim_rollup`) n'est prise que si le couple (nom de source, dimension) figure dans `DIM_ROLLUP_SPECS`, une table **écrite en dur** | `rollups.rs` (`DIM_ROLLUP_SPECS`), `rollup_route.rs` |

**Et les axes ÉCARTÉS, avec leur raison** — un axe écarté sans motif est un angle mort déguisé :

| Axe écarté | Pourquoi |
|---|---|
| mélange de sources (uniforme) | **MESURÉ, pas supposé** : rendre le mélange uniforme fait passer la part de `severity >= 3` de 0,064 à 0,219 et la taille moyenne de 252,8 à 237,4 octets — parce que la sévérité est une propriété DE chaque source. L'écart ne serait attribuable ni au mélange ni à la sévérité. Le profil `profile-axe-mix-uniforme.json` est conservé : sa section `axis` PORTE cette preuve. |
| cardinalité de `src_ip` | déplacerait en même temps la colonne indexée (`idx_event_srcip`) ET le plafond top-N des rollups (`PLUME_ROLLUP_SRCIP_TOPN`). Même problème d'attribution. |
| cardinalité de `category` | `category` est indexée, mais **aucune classe de la matrice ne la filtre ni ne la groupe** : l'axe ne serait exercé par aucune requête. Écarté faute de sonde, pas faute d'importance. |
| `env_id`, `origin`, `engagement_id` | constants en mode 0 (multi-tenant off, hors engagement). |
| `dst_ip`, `url`, `xff` | non indexées ET non interrogées par la matrice. |
| profondeur de rétention | ce n'est pas une propriété du JEU mais un réglage du daemon ; les fenêtres en sont déjà dérivées, et la garde de couverture écarte déjà celles que le jeu ne porte pas. |

**Ce que ces profils ne prétendent pas être** : ils sont SYNTHÉTIQUES et DÉRIVÉS. Ils ne sont la
production de personne. Ils répondent à « le chiffre bouge-t-il quand ce paramètre bouge, et de
combien », qui est la seule question à laquelle un banc puisse répondre sans les données du tiers.
Ils ne répondent PAS à « voici ce que mesurera tel client » — cette phrase exigerait SON jeu.

### Le bruit avant l'écart

Un écart entre deux profils ne veut rien dire tant qu'on ne sait pas ce que la **même** mesure rend
deux fois de suite sur le **même** jeu. La campagne mesure donc le témoin **deux fois**, en
encadrant la campagne (une passe au début, une à la fin, donc dérive de la machine comprise), et la
bande de bruit qui en sort devient le critère : un écart n'est déclaré attribuable au profil que
s'il sort de l'**étendue complète** de cette bande. Aucun seuil n'est écrit — si la machine est plus
bruyante, la bande s'élargit et le document **conclut moins**. C'est voulu : un banc doit perdre en
conclusions quand il perd en conditions, jamais gagner en confiance.

`measure.py` publie pour cela les **échantillons par tir** (`wall_samples_ms`, `sql_samples_ms`) et
plus seulement leurs percentiles : une dispersion ne se recalcule pas depuis un p50.

## La garde de rétention — le piège qui a mordu, fermé pour de bon

Un jeu figé une fois pour toutes finit par sortir de la rétention du daemon : l'horloge avance, le
bord de rétention rattrape la queue du jeu, et la purge SUPPRIME des événements **pendant** la
campagne. Ce n'est pas théorique — mesuré le 2026-08-01 : 1 440 007 -> 1 436 516 événements en une
demi-heure, avec à la clef un verdict de justesse FAUX imputé à la concurrence alors qu'il venait de
l'horloge. Et la purge n'attend pas : `spawn_retention_loop` (`daemon/src/server.rs`) passe une
première fois **60 s après le démarrage**, puis toutes les heures.

`run.sh` REFUSE désormais de démarrer quand la marge est négative, et l'annonce quand elle ne l'est
pas. La garde est DÉRIVÉE — elle compare deux instants, `end_ts - span_days` contre
`now - retention_days`, et vaut donc pour toute rétention, toute étendue et tout `end_ts` :

```
marge de rétention : 48 h avant que la purge n'entame le jeu (échéance …)
STOP: LE JEU EST DÉJÀ DANS LA ZONE DE PURGE — il a 42 h de retard.
```

Une garde de DÉPART ne prouve toutefois rien sur ce qui s'est passé PENDANT : `campagne-10m.sh`
recompte donc les événements **après** la matrice et publie le avant/après.

## Pourquoi les données brutes sont versionnées

Un tableau de mesures sans ses données brutes ne peut être que **cru ou ignoré** ; il ne peut pas
être *contredit*. `results/` porte donc les fichiers dont `docs/BENCHMARK.md` est rendu :

| Fichier | Contenu |
|---|---|
| `results/results.jsonl` | Une ligne par cellule : p50/p95 mur et SQL, RSS crête, octets lus, pression mémoire avant/après, `swap_suspect`, la requête et son SQL compilé. |
| `results/results-smoke-200k.jsonl` | La passe de rodage à 200 k événements. |
| `results/results-2026-07-31.jsonl` | La passe du 31/07 : fenêtre chaude du produit, tier froid ACTIF (avec le bilan de columnarisation et la **parité de réponse** chaud/froid), et les trois profils de flotte. Porte aussi les fenêtres ÉCARTÉES par la garde de couverture — une absence y est une donnée. |
| `results/ingest_rate.csv` | La courbe de débit d'ingest de la passe du 30/07 (machine chargée, sans colonnes CPU). |
| `results/ingest_rate-quiet-2g.csv` | La courbe du 31/07, machine au repos et sonde complète : c'est elle qui permet d'ATTRIBUER l'effondrement du débit au lieu de le supposer. |
| `results/results-2026-07-31-corrige.jsonl` | La passe du 31/07 REJOUÉE après le correctif de troncature froide (témoin chaud `chaud-seul-v2@1.4M` + `froid-actif-v2@1.4M`, même machine, mêmes copies de base, binaire post-correctif). C'est elle qui décrit le code actuel. |
| `results/parity-avant-2026-07-31.jsonl` | La parité chaud/froid mesurée sur toute la matrice **AVANT** le correctif : 53 contrôles sur 105 divergent en silence. |
| `results/parity-apres-2026-07-31.jsonl` | La MÊME mesure **APRÈS** : plus aucun agrégat scalaire ne diverge en silence. |
| `results/parity-couverture-2026-07-31.jsonl` | La MÊME mesure, REJOUÉE avec le binaire post-correctifs de **couverture des rollups**, sur deux copies FRAÎCHES de la même base et avec une stabilisation VÉRIFIÉE (les deux daemons ont tické, leur couverture est publiée). C'est elle qui mesure que le sous-compte ×6,6 de la passe précédente est corrigé : le côté sans tier froid rend désormais EXACTEMENT le compte brut. Elle décrit le dépôt actuel ; les réserves des passes antérieures décrivent leurs binaires. |
| `results/fill-progress-quiet-2g.txt` | Les lignes de progression du générateur pour cette passe. Extension `.txt` et non `.log` : `.gitignore` exclut `*.log`, et une donnée publiée ne doit pas dépendre d'une exception d'ignore. |
| `results/concurrency-2026-08-01.jsonl` | **La CONCURRENCE** : une ligne par NIVEAU (N analystes simultanés), plus une ligne d'en-tête par valeur de sémaphore (référence solo classe par classe, dérivation du mélange, mise au repos, état du cgroup). C'est l'entrée de la section « La concurrence » du document. |
| `results/concurrency-requests-2026-08-01.jsonl` | La MÊME passe, **une ligne par requête** (analyste, tour, classe, instant relatif, mur/serveur/attente, empreinte de réponse, verdict de justesse). Donnée brute : c'est elle qui permet de recalculer n'importe quel percentile publié, ou de contredire un verdict de justesse requête par requête. `report.py` l'accepte sans s'en servir (il la reconnaît à sa forme). |
| `results/concurrency-reproduction-2026-08-01.jsonl` | **LA VALEUR IMPOSSIBLE, REPRODUITE** avant d'y toucher. Passe COURTE (niveaux 1 et 4, 1 tour) sur le binaire d'AVANT : `sem_wait_ms` y atteint **16 456 ms en passe SOLO** et 3 348 ms à 1 analyste pour 3 permis. Elle ne sert qu'à une chose, et c'est la plus importante : voir le défaut ROUGE sur cette machine-ci avant de le corriger. Son mélange est DÉRIVÉ (pas imposé) — elle n'entre donc dans aucune comparaison de débit, et `report.py` l'en écarte tout seul. |
| `results/concurrency-attribution-2026-08-01.jsonl` | **CE QUE `sem_wait_ms` MESURAIT.** Passe COURTE (2 niveaux, 1 tour) tirée sur le binaire qui découpe l'attente mais garde la lecture de couverture sur le verrou d'écriture partagé. C'est elle qui ATTRIBUE : à 1 analyste pour 3 permis, l'attente du permit tombe à **0,000 ms** et 2 876 ms réapparaissent en `db_lock_wait_ms`. Sans elle, la correction serait une affirmation ; avec elle, c'est une mesure. |
| `results/concurrency-corrige-2026-08-01.jsonl` | La campagne COMPLÈTE d'après correctif (mêmes niveaux, MÊME mélange imposé que la passe d'avant, deux sémaphores). C'est elle qui décrit le dépôt actuel. |
| `results/concurrency-requests-corrige-2026-08-01.jsonl` | Le détail par requête de la passe ci-dessus. |
| `results/generique-2026-08-03.jsonl` | **LA CAMPAGNE MULTI-PROFILS** : la même matrice sur 5 profils (témoin, flotte 1 et 50 hôtes, cardinalité x25, sévérité décalée, taille d'événement x3), à volume égal, **plus le témoin mesuré DEUX FOIS** — c'est cette répétition qui donne la bande de bruit sans laquelle aucun écart inter-profils n'est interprétable. Porte les **échantillons par tir** (`wall_samples_ms`), donc toute dispersion y est recalculable. Les étiquettes de flotte portent `-v2` : les passes du 31/07 s'appelaient pareil, et sans ce suffixe deux campagnes de binaires différents auraient fusionné en silence. |
| `results/routeb-noms-sources-2026-08-03.jsonl` | **LE NOM DE LA SOURCE DÉCIDE DE LA ROUTE.** Deux jeux identiques à un détail près — le nom des sources. `served_from` passe de `rollup` à `raw` : preuve DIRECTE, pas une inférence sur des latences. |
| `results/hotfields-2026-08-03.jsonl` | **CHAMP INDEXÉ CONTRE CHAMP NON INDEXÉ**, paire APPARIÉE dérivée du profil (même type, même cardinalité, même taux de présence), au défaut livré puis avec `PLUME_AUTOINDEX=1`. Porte le réglage EFFECTIF relu sur le daemon, pas celui supposé depuis le code. |

**Scannés avant publication** : chemins personnels, e-mails, jetons (`ghp_`/`AKIA`/`xox*-`/
`AGE-SECRET`/`hvs.`/JWT), IP hors plages de documentation, hexadécimal ≥ 32 — **zéro
correspondance**. Les seules requêtes qui y figurent sont celles du banc, synthétiques.
Une seule chaîne déclenche le motif « e-mail » et elle est publiée en connaissance de cause :
`user@1000.service`, un nom d'unité systemd dans le chemin du cgroup où le budget de 2 Gio a été
appliqué (`.../user-1000.slice/user@1000.service/app.slice/plume-bench-N.scope`). Ce n'est pas une
adresse ; c'est la PREUVE que le plafond était appliqué à un cgroup réel, et c'est pour ça qu'elle
reste.

**Ce qui est DÉLIBÉRÉMENT absent** : `matrix.log`, le journal d'exécution. Il porte des chemins de
build absolus de la machine qui a mesuré (3 occurrences de chemins personnels, vérifié) — le publier
serait une fuite pour zéro gain de vérifiabilité, puisqu'il ne contient aucun chiffre qui ne soit
déjà dans les JSONL. `report.py` l'accepte en `--fill-log` quand vous lancez le banc vous-même : il
est une sortie de VOTRE exécution, pas une entrée qu'il faut recevoir de nous.

**La commande de rendu est publiée PAR le document lui-même** (`docs/BENCHMARK.md`, section
« Reproduire ») : `report.py` la reconstruit depuis ses propres arguments et la repointe vers
`bench/results/`. Elle est un POINT FIXE — la relancer telle quelle redonne le document à l'octet
près, hors ligne d'horodatage (vérifié). La version précédente publiait une commande incomplète qui
amputait le document de ses sections d'écart : une commande de reproduction fausse est pire
qu'absente, elle fait croire à une reproduction réussie.

**Corollaire pour un contributeur** : si vous contestez un chiffre, rejouez `bench/run.sh` et
comparez vos JSONL aux nôtres. Le générateur étant déterministe (`--digest` imprime le SHA-256 du
flux), un désaccord se tranche sur des données identiques — ce qui est le seul cas où un désaccord
de performance est arbitrable.

## Lancer

```sh
CARGO_TARGET_DIR=../.bench-target cargo build --release --features cold_tier \
    --manifest-path daemon/Cargo.toml
bench/run.sh                          # 10 M d'événements, matrice complète
BENCH_EVENTS=1000000 bench/run.sh     # 1 M — itération rapide
BENCH_PHASES=matrix bench/run.sh      # rejouer la matrice sur une base déjà remplie
BENCH_PHASES=simple bench/run.sh      # UNE configuration (masque vide) — le mode des A/B où
                                      # seule LA DONNÉE change (mono-hôte contre flotte)
BENCH_PHASES=cold BENCH_COLD=1 bench/run.sh   # tier froid : témoin chaud, aging réel
                                      # (`plume-daemon retention`), bilan, puis matrice froide
BENCH_SKIP=1400000 BENCH_PHASES=ingest bench/run.sh   # PROLONGER une base sans changer de graine
# la PARITÉ (valeurs, pas latences) : deux daemons, l'un columnarisé, l'autre intact, MÊME binaire.
python3 bench/parity.py --hot-base http://127.0.0.1:7421 --cold-base http://127.0.0.1:7422 \
    --user <u> --password <p> --end-ts <ts> --span-days 28 --hot-window-days 7 \
    --retention-days 30 -o parity.jsonl
# le rendu : NE PAS l'écrire de mémoire. La commande EXACTE est publiée par le document
# lui-même (docs/BENCHMARK.md, section « Reproduire ») et elle en est un point fixe.
```

`report.py` accepte PLUSIEURS fichiers de résultats : passer les JSONL de deux volumes différents
active le tableau « comment la latence monte avec le volume », qui est ce qui répond vraiment à la
question « des millions d'événements ». Pour obtenir un second volume sans refaire tout le
remplissage, `gen_events.py --skip N` prolonge le MÊME flux déterministe (mêmes clés `dedup`, donc
pas de doublon) au lieu de changer de graine.

Sorties sous `$BENCH_DIR` (par défaut `../.bench`, **hors dépôt**) : `results.jsonl` (une ligne
JSON par cellule, c'est la donnée brute), `manifest.json` (aiguilles et taux), `daemon.log`,
`db/plume.db`. Compter **~1 Kio de base par événement** (mesuré en production : 1 053 o/événement,
index et FTS compris) : 10 M d'événements ≈ 10 Gio.

## Les règles qui rendent le banc publiable

1. **La RAM crête est mesurée, jamais estimée.** `measure.py` échantillonne `/proc/<pid>/statm`
   pendant la requête et relève `VmHWM`. Le daemon tourne sous `MemoryMax=2G MemorySwapMax=0` :
   un dépassement du budget est un *kill* du noyau, pas un glissement silencieux vers le swap.
2. **Une cellule qui dépasse le budget est un résultat**, pas un échec. `report.py` les liste.
3. **Une cellule prise sous swap est fausse.** Elle est marquée `swap_suspect` et signalée comme
   à rejouer.
4. **Les données entrent par le vrai chemin** (`POST /api/ingest`), pas par un `INSERT` qui
   contournerait la normalisation, la promotion de colonnes, `cim_stamp`, les déclencheurs FTS et
   les index d'expression.
5. **Le déterminisme est vérifiable** : `gen_events.py --digest` imprime le SHA-256 du flux.
6. **Zéro donnée réelle** : IPv4 uniquement dans les plages de documentation de la RFC 5737, IPv6
   dans `2001:db8::/32` (RFC 3849), noms d'hôte en `.plume.invalid`, utilisateurs `bench-user-NNNN`.

## Les axes de la matrice, et pourquoi

- **Classes de requêtes** : scan filtré + agrégat · plein-texte/regex sur `message` · group-by
  multi-dimensions à haute cardinalité · récupération RAW paginée · **regex sur un champ étendu
  (JSON)** · **la colonne `host`** (filtre, group-by, récupération d'UNE machine). L'avant-dernière
  est le cas le plus coûteux, et c'est précisément celui qu'on prétend servir quand on dit « sur
  tous les champs » ; la dernière est la seule qui distingue un laboratoire d'une flotte.
- **Fenêtres** : dérivées des paramètres du produit (voir plus haut), pas choisies.
- **Tier froid `PLUME_COLD_TIER` 0 et 1** : c'est le chemin de lecture de 358 des 365 jours d'une
  rétention d'un an. Mesuré sur la MÊME base, avant et après columnarisation — et avec une
  vérification de **parité de réponse**, parce qu'un chemin qui tronque est plus rapide sans être
  meilleur.
- **Nombre d'hôtes** : 1 (la production profilée), 50, 200. `host` est indexé ; à cardinalité 1
  toute mesure qui le touche est dégénérée.
- **`PLUME_FTS_FIELDS` 0 et 1** : il est à 0 par défaut. On mesure son **coût** (RAM, disque, ingest)
  autant que son gain en latence.
- **Masquage vide vs non vide** : décisif et contre-intuitif — un masque non vide désarme la route
  de rollups *et* le moteur vectorisé. Des chiffres publiés sans cet axe ne valent que pour un
  déploiement sans masquage.

## Re-profiler une autre production

```sh
DB=/chemin/plume.db
KEY=<PLUME_DB_KEY>
{ printf "PRAGMA key = '%s';\n" "$KEY"; cat bench/prod-profile.sql; } > /tmp/p.sql && chmod 600 /tmp/p.sql
sqlcipher "file:$DB?mode=ro" < /tmp/p.sql > dump.txt ; rm -f /tmp/p.sql
python3 bench/distill_profile.py dump.txt --measured-at "$(date -Is)" \
    --host "<matériel>" --image "<version>" -o bench/profile-prod.json
```

`mode=ro` interdit toute écriture. Mais un lecteur SQLite tient un instantané : tant qu'une passe
tourne, le WAL ne peut pas être checkpointé et il grossit. Sur une grosse base, lancer les sections
du SQL **une par une**.
