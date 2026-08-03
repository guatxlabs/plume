#!/usr/bin/env bash
# bench/campagne-noms-sources.sh — L'AXE LE PLUS PUR, ET LE PLUS GÊNANT.
#
# Deux jeux identiques à UN détail près : le NOM des sources. Même volume, même graine, mêmes
# cardinalités, mêmes sévérités, mêmes longueurs — le profil republie ses propres statistiques
# avant/après, et elles sont inchangées (vérifié : 32 sources renommées, 0 autre champ modifié).
#
# La question : `search source=X | stats count by <dim>` n'est servie par le rollup par dimension
# que si le couple (X, dim) figure dans `DIM_ROLLUP_SPECS`, une table ÉCRITE EN DUR dans le daemon.
# Notre profil porte les noms de NOTRE production, qui sont exactement les clés de cette table.
# Un tiers dont les sources s'appellent autrement tombe hors de la table. Cette campagne le mesure.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="${NOMS_ROOT:-$(cd "$REPO/.." && pwd)/.bench-noms}"
EVENTS="${NOMS_EVENTS:-300000}"
OUT="$ROOT/routeb.jsonl"

mkdir -p "$ROOT"
exec > >(tee -a "$ROOT/campagne.log") 2>&1
echo "=== axe NOM DE SOURCE — $(date -Is) ==="
echo "volume par jeu : $EVENTS   charge : $(cut -d' ' -f1-3 /proc/loadavg)"

one() {  # $1 id  $2 profil
  local id="$1" prof="$2" dir="$ROOT/$1"
  echo ""
  echo "### $id — $(basename "$prof") — $(date -Is) — charge=$(cut -d' ' -f1-3 /proc/loadavg)"
  mkdir -p "$dir"
  BENCH_DIR="$dir" BENCH_PROFILE="$prof" BENCH_EVENTS="$EVENTS" BENCH_PHASES=ingest \
    "$REPO/bench/run.sh" || { echo "!!! ingest $id a échoué"; return 1; }
  BENCH_DIR="$dir" BENCH_PROFILE="$prof" BENCH_EVENTS="$EVENTS" BENCH_PHASES=routeb \
    BENCH_CONFIG_ID="$id" "$REPO/bench/run.sh" || echo "!!! sonde $id non-zéro"
  cat "$dir/routeb.jsonl" >> "$OUT" 2>/dev/null
}

one "noms-a-nous"   "$REPO/bench/profile-prod.json"
one "noms-de-tiers" "$REPO/bench/profile-axe-noms-tiers.json"

echo ""
echo "=== résultat ==="
python3 - "$OUT" <<'EOF'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8")]
for r in rows:
    print(f"{r['config_id']:16} source={r['source']:16} médiane={r['wall_median_ms']}ms "
          f"route={r['served_from']} approx={r['approx']} lignes={r['rows']} "
          f"| témoin sans source= : {r['control_wall_median_ms']}ms {r['control_served_from']}")
if len(rows) == 2:
    a, b = rows[0], rows[1]
    if a["wall_median_ms"] and b["wall_median_ms"]:
        print(f"\nRAPPORT (noms de tiers / nos noms) : x{b['wall_median_ms']/a['wall_median_ms']:.2f}")
    if a["served_from"] != b["served_from"]:
        print(f"LA ROUTE A CHANGÉ : {a['served_from']} -> {b['served_from']} — "
              "c'est une preuve directe, pas une inférence sur des latences.")
    else:
        print(f"La route est LA MÊME des deux côtés ({a['served_from']}) : le nom de la source "
              "n'a PAS dévié la route sur ce couple (source, dimension). Constat RÉFUTÉ.")
EOF
echo "brut : $OUT"
