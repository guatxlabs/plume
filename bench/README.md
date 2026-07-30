# `bench/` — l'instrument de mesure

Ce répertoire n'optimise rien. Il rend les optimisations **prouvables**. « Mesurer d'abord,
optimiser ensuite » : sans instrument publié, une amélioration annoncée n'est pas vérifiable et un
chiffre annoncé n'est pas contestable.

## Les quatre pièces

| Fichier | Rôle |
|---|---|
| `prod-profile.sql` | Extraction **lecture seule** du profil de données d'une production. N'extrait que des agrégats : comptes, cardinalités, longueurs, noms de clés. **Jamais** une valeur de ligne. |
| `distill_profile.py` | Transforme la sortie du SQL ci-dessus en `profile-prod.json`, en marquant chaque section `measured` ou `derived`. |
| `profile-prod.json` | Le profil versionné. C'est la **seule** entrée du générateur. |
| `gen_events.py` | Générateur **déterministe** (splitmix64, graine explicite, aucun appel à l'horloge) au profil ci-dessus. Zéro donnée réelle. |
| `measure.py` | La matrice : latence p50/p95, **RSS crête mesurée** (échantillonnage /proc à 15 ms), lecture disque, pression machine. |
| `report.py` | Rend `docs/BENCHMARK.md`. Ne masque aucune cellule. |
| `run.sh` | **La commande unique.** Enchaîne tout, budget de 2 Gio *appliqué* par cgroup. |

## Lancer

```sh
CARGO_TARGET_DIR=../.bench-target cargo build --release --features cold_tier \
    --manifest-path daemon/Cargo.toml
bench/run.sh                          # 10 M d'événements, matrice complète
BENCH_EVENTS=1000000 bench/run.sh     # 1 M — itération rapide
BENCH_PHASES=matrix bench/run.sh      # rejouer la matrice sur une base déjà remplie
python3 bench/report.py ../.bench/results.jsonl \
    --ingest-curve ../.bench/ingest_rate.csv \
    --fill-log ../.bench/matrix.log -o docs/BENCHMARK.md
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
  (JSON)**. La dernière est le cas le plus coûteux, et c'est précisément celui qu'on prétend servir
  quand on dit « sur tous les champs ».
- **Fenêtres** : dernière heure / dernier jour / tout.
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
