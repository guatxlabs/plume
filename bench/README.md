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
| `gen_events.py` | Générateur **déterministe** (splitmix64, graine explicite, aucun appel à l'horloge) au profil ci-dessus. Zéro donnée réelle. |
| `measure.py` | La matrice : latence p50/p95, **RSS crête mesurée** (échantillonnage /proc à 15 ms), lecture disque, pression machine. Les fenêtres y sont **dérivées**, pas énumérées. |
| `probe.py` | L'échantillonneur d'ingest. Relève, à chaque tick, ce qui permet de dire POURQUOI le débit tombe : CPU du daemon, CPU du reste de la machine, octets lus/écrits au bloc, stall mémoire du cgroup. |
| `parity.py` | **La réponse est-elle la MÊME ?** Interroge DEUX daemons (avec et sans tier froid) sur la MÊME matrice et compare **les valeurs**, pas les temps. Le jeu de contrôles n'est pas écrit : c'est `query_classes` × `windows` de `measure.py`. |
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

**Scannés avant publication** : chemins personnels, e-mails, jetons (`ghp_`/`AKIA`/`xox*-`/
`AGE-SECRET`/`hvs.`/JWT), IP hors plages de documentation, hexadécimal ≥ 32 — **zéro
correspondance**. Les seules requêtes qui y figurent sont celles du banc, synthétiques.

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
