#!/usr/bin/env bash
# bench/campagne-generique.sh — LA CAMPAGNE MULTI-PROFILS.
#
# LA QUESTION À LAQUELLE ELLE RÉPOND : un chiffre mesuré sur NOTRE profil de données décrit-il ce
# qu'obtiendra quelqu'un d'autre ? Un banc mono-profil ne peut pas y répondre — il mesure son cas.
# Cette campagne rejoue LA MÊME MATRICE sur plusieurs profils qui ne diffèrent du témoin QUE par un
# paramètre, à VOLUME D'ÉVÉNEMENTS ÉGAL, et publie l'écart.
#
# CE QUI REND LA COMPARAISON LÉGITIME, et sans quoi elle ne vaudrait rien :
#   * même binaire, même machine, passes consécutives ;
#   * même volume (BENCH_EVENTS), même graine, même end_ts par passe ;
#   * un seul paramètre change par profil (bench/make_axis_profile.py REFUSE d'en changer deux) ;
#   * le TÉMOIN est mesuré DEUX FOIS sur la MÊME base. C'est la pièce décisive : sans l'écart
#     INTRA-profil, un écart INTER-profils n'est pas interprétable — on ne saurait pas s'il vient du
#     profil ou de la machine. La seconde passe du témoin est donc une mesure du BRUIT, et c'est
#     l'étalon auquel tout le reste se compare.
#
# Détachée : `setsid nohup bench/campagne-generique.sh &`. Une mesure longue tuée par la fermeture
# d'un terminal est une ABSENCE de mesure, pas un résultat partiel.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="${CAMP_ROOT:-$(cd "$REPO/.." && pwd)/.bench-generique}"
EVENTS="${CAMP_EVENTS:-600000}"
OUT="${CAMP_OUT:-$ROOT/generique.jsonl}"
KEEP_DB="${CAMP_KEEP_DB:-0}"     # 1 = garder les bases (débogage) ; 0 = les effacer au fil de l'eau

mkdir -p "$ROOT"
: > "$ROOT/campagne.log"
exec > >(tee -a "$ROOT/campagne.log") 2>&1

echo "=== campagne généricité — $(date -Is) ==="
echo "volume par profil : $EVENTS   racine : $ROOT"
echo "espace libre : $(df -B1G --output=avail "$ROOT" | tail -1 | tr -d ' ') Gio"

# Un profil = une passe. `id` sert d'étiquette de configuration ET de nom de répertoire.
# L'ordre place le TÉMOIN en premier et sa RÉPÉTITION en dernier : le bruit de la machine est ainsi
# encadré par toute la campagne, et non mesuré deux fois de suite dans les mêmes conditions — ce qui
# le sous-estimerait précisément là où on s'en sert comme étalon.
run_profile() {  # $1 id  $2 chemin du profil
  local id="$1" prof="$2" dir="$ROOT/$1"
  echo ""
  echo "######################################################################"
  echo "### PROFIL $id — $(basename "$prof")  —  $(date -Is)"
  echo "### charge machine : loadavg=$(cut -d' ' -f1-3 /proc/loadavg)"
  echo "######################################################################"
  mkdir -p "$dir"
  BENCH_DIR="$dir" BENCH_PROFILE="$prof" BENCH_EVENTS="$EVENTS" \
    BENCH_PHASES=ingest "$REPO/bench/run.sh" || { echo "!!! ingest $id a échoué"; return 1; }
  BENCH_DIR="$dir" BENCH_PROFILE="$prof" BENCH_EVENTS="$EVENTS" \
    BENCH_PHASES=simple BENCH_CONFIG_ID="$id" "$REPO/bench/run.sh" || echo "!!! matrice $id a rendu non-zéro (C'EST UN RÉSULTAT)"
  cat "$dir/results.jsonl" >> "$OUT" 2>/dev/null
  echo "### $id terminé — $(wc -l < "$OUT") lignes cumulées dans $OUT"
}

# La RÉPÉTITION du témoin : même base, même profil, matrice rejouée. Aucune ingestion.
rerun_matrix() {  # $1 nouvel id  $2 répertoire existant  $3 profil
  local id="$1" dir="$2" prof="$3"
  echo ""
  echo "######################################################################"
  echo "### RÉPÉTITION $id (même base que $(basename "$dir")) — $(date -Is)"
  echo "### charge machine : loadavg=$(cut -d' ' -f1-3 /proc/loadavg)"
  echo "######################################################################"
  BENCH_DIR="$dir" BENCH_PROFILE="$prof" BENCH_EVENTS="$EVENTS" \
    BENCH_PHASES=simple BENCH_CONFIG_ID="$id" "$REPO/bench/run.sh" || echo "!!! matrice $id a rendu non-zéro"
  # `results.jsonl` du répertoire contient DÉJÀ la passe précédente : n'ajouter que le nouveau.
  grep -F "\"config_id\": \"$id\"" "$dir/results.jsonl" >> "$OUT" 2>/dev/null
  echo "### $id terminé — $(wc -l < "$OUT") lignes cumulées"
}

V="$(python3 -c "print(f'{$EVENTS/1e6:.1f}M')")"

run_profile "temoin-64h@$V"      "$REPO/bench/profile-prod.json"
run_profile "flotte-1h@$V"       "$REPO/bench/profile-fleet-1.json"
run_profile "flotte-50h@$V"      "$REPO/bench/profile-fleet-50.json"
run_profile "card-haute@$V"      "$REPO/bench/profile-axe-card-haute.json"
run_profile "taille-grande@$V"   "$REPO/bench/profile-axe-taille-grande.json"
run_profile "sev-haute@$V"       "$REPO/bench/profile-axe-sev-haute.json"
rerun_matrix "temoin-bis@$V"     "$ROOT/temoin-64h@$V" "$REPO/bench/profile-prod.json"

echo ""
echo "=== campagne terminée — $(date -Is) ==="
echo "résultats : $OUT ($(wc -l < "$OUT") lignes)"
if [ "$KEEP_DB" != "1" ]; then
  echo "effacement des bases (CAMP_KEEP_DB=1 pour les garder)"
  find "$ROOT" -name 'plume.db*' -delete
  echo "espace libre après : $(df -B1G --output=avail "$ROOT" | tail -1 | tr -d ' ') Gio"
fi
