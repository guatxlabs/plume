#!/usr/bin/env bash
# bench/campagne-10m.sh — P6.1-a : 10 MILLIONS d'événements PAR LE VRAI CHEMIN.
#
# POURQUOI CE SCRIPT EXISTE : le banc publié porte sur 1 440 007 événements. L'objectif produit est
# « des millions, puis des milliards ». Une latence mesurée à 1,4 M ne dit rien à 10 M — le coût par
# ligne du chemin d'écriture GRANDIT avec le volume (mesuré : CPU par événement x2,23 entre 144 k et
# 1,4 M), et rien ne garantit que le chemin de LECTURE se comporte linéairement non plus.
#
# CE QU'IL NE FAIT PAS, ET C'EST LE POINT : il n'INSÈRE pas. Tout entre par `POST /api/ingest`, donc
# par la normalisation, la promotion de colonnes, `cim_stamp`, les déclencheurs FTS et les index
# d'expression. Un `INSERT` fabriqué mesurerait SQLite, pas plume — et il donnerait des chiffres
# flatteurs pour la seule raison qu'il sauterait le travail que le produit fait vraiment.
#
# LA PREUVE DE SURVIE DU JEU : la rétention du daemon supprime `ts < now - PLUME_RETENTION_DAYS`,
# toutes les heures, dès 60 s après le démarrage. Un remplissage de plusieurs heures suivi d'une
# matrice est exactement la situation où le jeu peut RÉTRÉCIR SOUS LA MESURE. `bench/run.sh` refuse
# désormais de démarrer si la marge est négative ; ce script mesure EN PLUS le compte avant et après
# la matrice, parce qu'une garde de départ ne prouve rien sur ce qui s'est passé pendant.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${TENM_DIR:-$(cd "$REPO/.." && pwd)/.bench-10m}"
EVENTS="${TENM_EVENTS:-10000000}"

mkdir -p "$DIR"
exec > >(tee -a "$DIR/campagne-10m.log") 2>&1

echo "=== P6.1-a — 10 M par le vrai chemin — $(date -Is) ==="
echo "cible : $EVENTS événements   répertoire : $DIR"
echo "espace libre : $(df -B1G --output=avail "$DIR" | tail -1 | tr -d ' ') Gio (compter ~1 Kio/événement)"
echo "charge au départ : loadavg=$(cut -d' ' -f1-3 /proc/loadavg)"

echo ""
echo "### REMPLISSAGE — $(date -Is)"
BENCH_DIR="$DIR" BENCH_EVENTS="$EVENTS" BENCH_PHASES=ingest "$REPO/bench/run.sh" \
  || { echo "!!! le remplissage a échoué"; exit 1; }

echo ""
echo "### MATRICE — $(date -Is)  charge=$(cut -d' ' -f1-3 /proc/loadavg)"
BENCH_DIR="$DIR" BENCH_EVENTS="$EVENTS" BENCH_PHASES=simple BENCH_CONFIG_ID="volume-10M" \
  "$REPO/bench/run.sh" || echo "!!! la matrice a rendu non-zéro (C'EST UN RÉSULTAT)"

# PREUVE DE SURVIE — une garde de DÉPART ne prouve rien sur ce qui s'est passé PENDANT.
# `config.events` est relevé UNE fois par passe, au démarrage du daemon de cette passe : deux passes
# successives donnent donc deux comptes pris à deux instants, et c'est exactement le avant/après
# qu'il faut. La passe témoin ci-dessous ne tire qu'UNE classe (le plancher) : elle coûte quelques
# secondes et son seul rôle est de RECOMPTER après la matrice.
echo ""
echo "### RECOMPTE APRÈS MATRICE — $(date -Is)"
BENCH_DIR="$DIR" BENCH_EVENTS="$EVENTS" BENCH_PHASES=simple BENCH_CONFIG_ID="survie-apres" \
  BENCH_CLASSES="C0-" "$REPO/bench/run.sh" || echo "!!! le recompte a rendu non-zéro"

python3 - "$DIR/results.jsonl" <<'EOF'
import json, sys
seen = {}
for ln in open(sys.argv[1], encoding="utf-8"):
    d = json.loads(ln)
    c, n = d.get("config_id"), (d.get("config") or {}).get("events")
    if c and n and c not in seen:
        seen[c] = n
a, b = seen.get("volume-10M"), seen.get("survie-apres")
print(f"PREUVE DE SURVIE — événements avant la matrice = {a} ; après = {b}")
if a and b:
    if a == b:
        print("  -> le jeu N'A PAS bougé pendant la matrice : toutes les cellules portent sur "
              "le MÊME jeu.")
    else:
        print(f"  -> LE JEU A BOUGÉ ({a - b} événements en moins). Les cellules ne portent pas "
              "toutes sur le même jeu : la passe est à rejouer avec une marge de rétention plus "
              "large. Ce n'est PAS un détail — c'est le défaut qui a déjà fait publier un verdict "
              "de justesse faux.")
EOF

echo ""
echo "=== terminé — $(date -Is) ==="
echo "résultats : $DIR/results.jsonl"
