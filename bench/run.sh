#!/usr/bin/env bash
# bench/run.sh — LA COMMANDE UNIQUE. Rejoue toute la matrice de bout en bout, pour qu'un tiers
# puisse CONTREDIRE les chiffres de docs/BENCHMARK.md. Sans ça un banc n'est pas publiable.
#
#   bench/run.sh                        # 10 M d'événements, matrice complète
#   BENCH_EVENTS=1000000 bench/run.sh   # 1 M — itération rapide
#   BENCH_EVENTS=100000000 bench/run.sh # 100 M — horizon (prévoir le disque : ~1 Kio/événement)
#   BENCH_PHASES=ingest bench/run.sh    # ingest seulement (mesure le débit, garde la base)
#   BENCH_PHASES=matrix bench/run.sh    # matrice seulement, sur une base déjà remplie
#
# LE BUDGET DE 2 Gio EST APPLIQUÉ, PAS SUPPOSÉ : le daemon tourne dans un scope systemd
# `MemoryMax=2G MemorySwapMax=0`, ce qui reproduit la limite de conteneur de la production
# (`limits.memory: 2Gi`, sans swap). Si le daemon se fait tuer par l'OOM, c'est UN RÉSULTAT à
# publier, pas un incident à masquer : le script le dit et continue.
#
# CE QUE LE SCRIPT NE FAIT PAS : il ne touche à rien dans le dépôt, il n'écrit que sous $BENCH_DIR.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_DIR="${BENCH_DIR:-$(cd "$REPO/.." && pwd)/.bench}"
TARGET_DIR="${CARGO_TARGET_DIR:-$(cd "$REPO/.." && pwd)/.bench-target}"
BIN="$TARGET_DIR/release/plume-daemon"

BENCH_EVENTS="${BENCH_EVENTS:-10000000}"
BENCH_SEED="${BENCH_SEED:-0x504C554D45}"
# PROLONGER une base déjà remplie sans la dupliquer : `gen_events.py --skip N` jette les N premiers
# événements du MÊME flux déterministe (mêmes clés `dedup`) et POSTe la suite. C'est le seul moyen
# d'ajouter du volume sans changer de graine — donc sans changer le profil de cardinalités.
BENCH_SKIP="${BENCH_SKIP:-0}"
BENCH_END_TS="${BENCH_END_TS:-}"          # vide -> figé au 1er run et RELU ensuite (déterminisme)
BENCH_SPAN_DAYS="${BENCH_SPAN_DAYS:-28}"
BENCH_PORT="${BENCH_PORT:-7411}"
BENCH_MEMMAX="${BENCH_MEMMAX:-2G}"
BENCH_PHASES="${BENCH_PHASES:-all}"
BENCH_REPS="${BENCH_REPS:-7}"
BENCH_MIN_FREE_GIB="${BENCH_MIN_FREE_GIB:-40}"
BENCH_PROBE_INTERVAL="${BENCH_PROBE_INTERVAL:-60}"
# Profil de données lu par le générateur. Défaut : le profil MESURÉ sur la production. Un profil
# DÉRIVÉ (bench/profile-fleet-*.json, une flotte de N hôtes) se passe ici — le générateur ne lit
# que ce fichier, donc changer de profil change le jeu de données et RIEN d'autre.
BENCH_PROFILE="${BENCH_PROFILE:-$REPO/bench/profile-prod.json}"
# Tier froid. `PLUME_COLD_HOT_WINDOW_DAYS` est le paramètre PRODUIT de la frontière chaud/froid
# (défaut 7 j, daemon/src/cold_store/aging.rs) : il est passé À LA FOIS au daemon et au harnais de
# mesure, pour que la fenêtre mesurée SOIT la frontière du produit et pas un nombre choisi ici.
BENCH_COLD="${BENCH_COLD:-0}"
BENCH_COLD_HOT_DAYS="${BENCH_COLD_HOT_DAYS:-7}"
# Rétention du daemon. SOURCE UNIQUE : la même valeur part dans PLUME_RETENTION_DAYS et dans le
# harnais de mesure, qui en dérive la fenêtre « toute la rétention ».
BENCH_RETENTION_DAYS="${BENCH_RETENTION_DAYS:-30}"
BENCH_ADMIN_PW="${BENCH_ADMIN_PW:-benchadmin-motdepasse}"
BENCH_VIEWER_PW="${BENCH_VIEWER_PW:-benchviewer-motdepasse}"
# Clé SQLCipher DU BANC. Ce n'est pas un secret : elle est publiée pour que le banc soit rejouable.
# Elle est là parce que la production est CHIFFRÉE : mesurer en clair donnerait des chiffres
# flatteurs (pas de déchiffrement AES par page lue).
BENCH_DB_KEY="${BENCH_DB_KEY:-plume-bench-cle-non-secrete-0000000000000000}"

DB_DIR="$BENCH_DIR/db"
SPOOL_DIR="$BENCH_DIR/spool"
RESULTS="$BENCH_DIR/results.jsonl"
LOG="$BENCH_DIR/daemon.log"
ENVSH="$BENCH_DIR/daemon-env.sh"
STATE="$BENCH_DIR/state.env"
SCOPE="plume-bench-$$"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31mSTOP: %s\033[0m\n' "$*" >&2; exit 1; }

free_gib() { df -B1G --output=avail / | tail -1 | tr -d ' '; }

guard_disk() {
  local f; f="$(free_gib)"
  [ "$f" -ge "$BENCH_MIN_FREE_GIB" ] || die "plus que ${f} Gio libres sur / (plancher ${BENCH_MIN_FREE_GIB} Gio) — on s'arrête net"
}

# ------------------------------------------------------------------ cycle de vie du daemon
DAEMON_PID=""

write_env() {   # $1 = PLUME_FTS_FIELDS
  # Le tier froid n'ajoute d'environnement QUE lorsqu'il est demandé : à `BENCH_COLD=0` le daemon
  # reçoit EXACTEMENT les mêmes variables que les passes déjà publiées — pas une de plus. (Le
  # fichier gagne une ligne vide ; le daemon, lui, ne voit aucune différence.)
  COLD_EXTRA_ENV=""
  if [ "$BENCH_COLD" = "1" ]; then
    COLD_EXTRA_ENV="export PLUME_COLD_DIR=$BENCH_DIR/cold
export PLUME_COLD_HOT_WINDOW_DAYS=$BENCH_COLD_HOT_DAYS"
  fi
  cat > "$ENVSH" <<EOF
#!/bin/sh
# Environnement du daemon pour le banc. Volontairement calé sur les DÉFAUTS DU PRODUIT (et non sur
# les réglages de notre production), sauf là où c'est noté : un banc doit mesurer ce qui est livré.
export PLUME_CONFIG=/nonexistent
export PLUME_DB=$DB_DIR/plume.db
export PLUME_SPOOL=$SPOOL_DIR
export PLUME_ADDR=127.0.0.1:$BENCH_PORT
export PLUME_HOST=localhost
export PLUME_WEB=$REPO/web
export PLUME_USER=benchadmin
export PLUME_PASS_HASH='$ADMIN_HASH'
export PLUME_DB_KEY='$BENCH_DB_KEY'
export PLUME_FTS_FIELDS=$1
export PLUME_FTS_FIELDS_BACKFILL=1
export PLUME_EXPRINDEX=1
export PLUME_AUTOINDEX=0
export PLUME_QUERY_CONCURRENCY=3
export PLUME_RETENTION_DAYS=$BENCH_RETENTION_DAYS
export PLUME_COLD_TIER=$BENCH_COLD
$COLD_EXTRA_ENV
export PLUME_INGEST_MIN_FREE_MB=0
export PLUME_BACKUP_INTERVAL=0
export PLUME_DEMO=0
export PLUME_RL_IP_MAX=200000
export PLUME_RL_GLOBAL_MAX=400000
export MALLOC_ARENA_MAX=2
exec "$BIN"
EOF
  chmod 700 "$ENVSH"
}

start_daemon() { # $1 = PLUME_FTS_FIELDS
  write_env "$1"
  : > "$LOG"
  systemd-run --user --scope --unit="$SCOPE-$1-$RANDOM" --quiet \
      -p MemoryMax="$BENCH_MEMMAX" -p MemorySwapMax=0 \
      /bin/sh "$ENVSH" >>"$LOG" 2>&1 &
  local i
  for i in $(seq 1 180); do
    DAEMON_PID="$(pgrep -u "$(id -u)" -f "^$BIN\$" | head -1)"
    [ -n "$DAEMON_PID" ] && break
    sleep 0.5
  done
  [ -n "$DAEMON_PID" ] || { tail -30 "$LOG"; die "le daemon n'a pas démarré"; }
  for i in $(seq 1 240); do
    if curl -sf -m 3 -H "Host: localhost" "http://127.0.0.1:$BENCH_PORT/healthz" >/dev/null; then
      say "daemon vivant pid=$DAEMON_PID (PLUME_FTS_FIELDS=$1, MemoryMax=$BENCH_MEMMAX, sans swap)"
      return 0
    fi
    kill -0 "$DAEMON_PID" 2>/dev/null || { tail -40 "$LOG"; die "le daemon est mort au démarrage (OOM ? voir $LOG)"; }
    sleep 1
  done
  tail -40 "$LOG"; die "/healthz ne répond pas"
}

stop_daemon() {
  [ -n "${DAEMON_PID:-}" ] || return 0
  kill -TERM "$DAEMON_PID" 2>/dev/null
  local i; for i in $(seq 1 60); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.5; done
  kill -KILL "$DAEMON_PID" 2>/dev/null
  DAEMON_PID=""
}
trap 'stop_daemon' EXIT INT TERM

api() { # api METHOD PATH [BODY] — en admin
  local m="$1" p="$2" b="${3:-}"
  if [ -n "$b" ]; then
    curl -s -m 60 -u "benchadmin:$BENCH_ADMIN_PW" -H "Host: localhost" -H 'Content-Type: application/json' \
      -X "$m" --data "$b" "http://127.0.0.1:$BENCH_PORT$p"
  else
    curl -s -m 60 -u "benchadmin:$BENCH_ADMIN_PW" -H "Host: localhost" -X "$m" "http://127.0.0.1:$BENCH_PORT$p"
  fi
}


drop_bench_filters() {
  local ids
  ids="$(api GET /api/field-filters | python3 -c 'import json,sys
try:
  d = json.load(sys.stdin)
  rows = d if isinstance(d, list) else (d.get("rules") or d.get("filters") or d.get("rows") or [])
  print(" ".join(str(r["id"]) for r in rows if str(r.get("name","")).startswith("bench-mask")))
except Exception:
  pass')"
  local id
  for id in $ids; do api DELETE "/api/field-filters/$id" >/dev/null; done
  # VÉRIFICATION, pas confiance : il ne doit plus rester AUCUNE règle de banc.
  local left
  left="$(api GET /api/field-filters | python3 -c 'import json,sys
try:
  d = json.load(sys.stdin)
  rows = d if isinstance(d, list) else (d.get("rules") or d.get("filters") or d.get("rows") or [])
  print(sum(1 for r in rows if str(r.get("name","")).startswith("bench-mask")))
except Exception:
  print(-1)')"
  [ "$left" = "0" ] || die "impossible de retirer les masques de banc (il en reste $left) — on refuse de mesurer une configuration dont l'étiquette serait FAUSSE"
}

count_events() {
  api POST /api/query '{"soql":"search | stats count","from":0,"to":0,"interactive":true}' \
    | python3 -c 'import json,sys
try: print(json.load(sys.stdin)["rows"][0][0])
except Exception: print(-1)'
}

oom_report() {
  if grep -qiE 'out of memory|oom' "$LOG" 2>/dev/null; then
    say "OOM DÉTECTÉ dans le journal du daemon — C'EST UN RÉSULTAT, il part dans le rapport"
    grep -iE 'out of memory|oom' "$LOG" | tail -5
  fi
  systemctl --user show "$SCOPE"* -p MemoryPeak 2>/dev/null | grep -v '^$' | tail -3
}

# ================================================================== PRÉAMBULE
say "préambule"
guard_disk
mkdir -p "$DB_DIR" "$SPOOL_DIR"
[ -x "$BIN" ] || die "binaire absent : $BIN (construire : CARGO_TARGET_DIR=$TARGET_DIR cargo build --release --features cold_tier --manifest-path daemon/Cargo.toml)"
command -v systemd-run >/dev/null || die "systemd-run absent : impossible d'APPLIQUER le budget de 2 Gio (on refuse de le SUPPOSER)"

# `end_ts` est figé au premier run et relu ensuite : le générateur n'appelle jamais l'horloge, mais
# le script si — une seule fois, et la valeur est PERSISTÉE pour que le rejeu soit identique.
if [ -f "$STATE" ]; then . "$STATE"; fi
if [ -z "${BENCH_END_TS:-}" ] || [ "$BENCH_END_TS" = "" ]; then
  BENCH_END_TS="${SAVED_END_TS:-$(date +%s)}"
fi
ADMIN_HASH="${SAVED_ADMIN_HASH:-}"
if [ -z "$ADMIN_HASH" ]; then
  ADMIN_HASH="$("$BIN" hashpw "$BENCH_ADMIN_PW")" || die "hashpw a échoué"
fi
cat > "$STATE" <<EOF
SAVED_END_TS=$BENCH_END_TS
SAVED_ADMIN_HASH='$ADMIN_HASH'
EOF
echo "fenêtre de données : end_ts=$BENCH_END_TS  span=${BENCH_SPAN_DAYS}j  cible=${BENCH_EVENTS} événements"
echo "matériel : $(nproc) cœurs, $(free -g | awk '/^Mem:/{print $2}') Gio RAM totale, $(free_gib) Gio libres sur /"
echo "pression au départ : loadavg=$(cut -d' ' -f1-3 /proc/loadavg)  swap utilisé=$(free -m | awk '/^Swap:/{print $3}') Mio"

# IDENTITÉ DE CE QUI EST MESURÉ. `git rev-parse HEAD` ne suffit PAS : l'arbre peut bouger entre la
# compilation et la mesure (travaux concurrents), et le chiffre publié décrirait alors un commit qui
# n'est pas celui du binaire tiré. On enregistre donc l'empreinte du BINAIRE — la seule chose qui a
# réellement été mesurée — et le HEAD à titre indicatif seulement.
BIN_SHA="$(sha256sum "$BIN" | cut -c1-16)"
BIN_MTIME="$(date -u -d "@$(stat -c%Y "$BIN")" +%Y-%m-%dT%H:%M:%SZ)"
GIT_HEAD="$(cd "$REPO" && git rev-parse --short HEAD 2>/dev/null || echo inconnu)"
VERSION="bin:$BIN_SHA construit:$BIN_MTIME (HEAD au rendu: $GIT_HEAD — indicatif, l'arbre bouge)"
echo "identité mesurée : $VERSION"
# Manifeste écrit AVANT toute mesure : il fige les aiguilles et leurs taux attendus, y compris en
# mode `matrix` seul (la base peut avoir été remplie par un run précédent).
python3 "$REPO/bench/gen_events.py" --count "$BENCH_EVENTS" --end-ts "$BENCH_END_TS" \
  --span-days "$BENCH_SPAN_DAYS" --seed "$BENCH_SEED" --manifest "$BENCH_DIR/manifest.json" \
  --digest >/dev/null 2>&1 &
MANIFEST_PID=$!; sleep 2; kill "$MANIFEST_PID" 2>/dev/null; wait "$MANIFEST_PID" 2>/dev/null

# ================================================================== INGEST
if [ "$BENCH_PHASES" = "all" ] || [ "$BENCH_PHASES" = "ingest" ]; then
  say "phase 1/3 — ingest de $BENCH_EVENTS événements PAR LE VRAI CHEMIN (POST /api/ingest)"
  start_daemon 0
  TOK="$(PLUME_DB="$DB_DIR/plume.db" PLUME_DB_KEY="$BENCH_DB_KEY" PLUME_CONFIG=/nonexistent \
        "$BIN" token bench-generator 2>/dev/null | tr -d '\r\n')"
  [ ${#TOK} -ge 32 ] || die "jeton d'ingest non miné (obtenu : ${#TOK} caractères)"
  api POST /api/users "{\"name\":\"benchviewer\",\"password\":\"$BENCH_VIEWER_PW\",\"role\":\"viewer\"}" >/dev/null

  N0="$(count_events)"; T0=$(date +%s)
  # Échantillonneur de débit (bench/probe.py) : le débit SEUL ne dit pas POURQUOI il tombe. La sonde
  # relève en plus, à chaque tick, le CPU du daemon, le CPU de la machine, le CPU du générateur, les
  # octets lus/écrits au bloc et le stall mémoire du cgroup — les grandeurs qui séparent le VOLUME
  # (coût CPU par événement qui monte) de la CONTENTION (CPU consommé par les AUTRES) et du
  # STOCKAGE. Les 5 premières colonnes restent celles de l'échantillonneur d'origine.
  RATE_CSV="$BENCH_DIR/ingest_rate.csv"
  python3 "$REPO/bench/gen_events.py" --count "$BENCH_EVENTS" --end-ts "$BENCH_END_TS" \
    --span-days "$BENCH_SPAN_DAYS" --seed "$BENCH_SEED" --profile "$BENCH_PROFILE" \
    --skip "$BENCH_SKIP" --manifest "$BENCH_DIR/manifest.json" \
    --post "http://127.0.0.1:$BENCH_PORT/api/ingest" --token "$TOK" \
    --spool-dir "$SPOOL_DIR" & GEN_PID=$!
  python3 "$REPO/bench/probe.py" --pid "$DAEMON_PID" --gen-pid "$GEN_PID" \
    --db "$DB_DIR/plume.db" --spool "$SPOOL_DIR" \
    --base "http://127.0.0.1:$BENCH_PORT" --host-header localhost \
    --user benchadmin --password "$BENCH_ADMIN_PW" \
    --interval "$BENCH_PROBE_INTERVAL" -o "$RATE_CSV" >/dev/null 2>&1 & SAMPLER=$!
  wait "$GEN_PID" || die "le générateur s'est arrêté"

  say "attente du drainage du spool (la boucle d'ingest du daemon repasse toutes les 5 s)"
  LAST=-1; STALL=0
  while :; do
    guard_disk
    PEND="$(ls "$SPOOL_DIR" 2>/dev/null | grep -c '^ingest-' || true)"
    N="$(count_events)"
    echo "  spool=$PEND  events=$N  rss=$(( $(awk '{print $2}' /proc/$DAEMON_PID/statm 2>/dev/null || echo 0) * 4096 / 1048576 ))Mio  db=$(du -m "$DB_DIR/plume.db" 2>/dev/null | cut -f1)Mio"
    kill -0 "$DAEMON_PID" 2>/dev/null || { oom_report; die "le daemon est mort pendant l'ingest (voir $LOG)"; }
    [ "$PEND" = "0" ] && [ "$N" = "$LAST" ] && break
    [ "$N" = "$LAST" ] && STALL=$((STALL+1)) || STALL=0
    [ "$STALL" -gt 40 ] && { echo "  (compteur figé — on arrête l'attente)"; break; }
    LAST="$N"; sleep 15
  done
  kill "$SAMPLER" 2>/dev/null
  T1=$(date +%s); NF="$(count_events)"
  INGESTED=$(( NF - (N0 < 0 ? 0 : N0) )); ELAPSED=$(( T1 - T0 ))
  say "DÉBIT D'INGEST MESURÉ : $INGESTED événements en ${ELAPSED}s = $(( INGESTED / (ELAPSED>0?ELAPSED:1) )) ev/s (chemin HTTP complet)"
  { echo "{\"phase\":\"ingest\",\"version\":\"$VERSION\",\"events\":$INGESTED,\"seconds\":$ELAPSED,"
    echo " \"events_per_second\":$(( INGESTED / (ELAPSED>0?ELAPSED:1) )),"
    echo " \"db_bytes\":$(stat -c%s "$DB_DIR/plume.db"),\"fts_fields\":0,"
    echo " \"path\":\"POST /api/ingest -> spool -> ingest_events_batch (normalisation, promotion de colonnes, cim_stamp, déclencheurs FTS, index d'expression)\"}"
  } | tr -d '\n' >> "$RESULTS"; echo >> "$RESULTS"

  say "stabilisation : rollups (boucle 120 s) + index d'arrière-plan"
  sleep 150
  api POST /api/query '{"soql":"search | stats count by source | head 3","from":0,"to":0,"interactive":true}' >/dev/null
  stop_daemon
fi

# ================================================================== MATRICE
PROFILE_HOSTS="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['bench_target']['hosts'])" "$BENCH_PROFILE" 2>/dev/null || echo '?')"
PROFILE_NAME="$(basename "$BENCH_PROFILE")"

run_matrix() { # $1 config_id  $2 meta-json  $3 classes (vide = toutes)
  # `--span-days` et `--hot-window-days` ne sont pas des réglages de banc : ce sont l'ÉTENDUE RÉELLE
  # du jeu et la FRONTIÈRE CHAUD/FROID DU PRODUIT. Le harnais en DÉRIVE les fenêtres à mesurer (et
  # refuse celles que le jeu ne couvre pas) au lieu d'une liste écrite à la main.
  python3 "$REPO/bench/measure.py" --base "http://127.0.0.1:$BENCH_PORT" --host-header localhost \
    --user benchviewer --password "$BENCH_VIEWER_PW" --pid "$DAEMON_PID" \
    --end-ts "$BENCH_END_TS" --span-days "$BENCH_SPAN_DAYS" \
    --hot-window-days "$BENCH_COLD_HOT_DAYS" --retention-days "$BENCH_RETENTION_DAYS" \
    --config-id "$1" --config-meta "$2" \
    --reps "$BENCH_REPS" --only "${3:-}" --windows "${BENCH_WINDOWS:-}" -o "$RESULTS"
}
# Sous-ensemble de la phase 3 : les classes que PLUME_FTS_FIELDS peut concerner (plein-texte, regex,
# champs étendus) plus le plancher, qui sert de témoin. Mesurer les 15 classes une 3e fois coûterait
# une heure pour redémontrer que le group-by ne dépend pas de la FTS. Ce qui est retiré est NOMMÉ,
# et docs/BENCHMARK.md le signale : les cellules absentes de la phase 3 sont NON MESURÉES.
FTS_CLASSES="${FTS_CLASSES:-C0-,C2,C5}"

if [ "$BENCH_PHASES" = "all" ] || [ "$BENCH_PHASES" = "matrix" ]; then
  NEV="$(count_events 2>/dev/null || echo 0)"

  say "phase 2/3 — matrice, PLUME_FTS_FIELDS=0"
  start_daemon 0
  NEV="$(count_events)"
  VOL="$(python3 -c "print(f'{$NEV/1e6:.1f}M')")"
  DB0="$(stat -c%s "$DB_DIR/plume.db")"
  echo "base : $NEV événements, $((DB0/1048576)) Mio"
  say "  2a — masque VIDE (route de rollups et moteur vectorisé ARMÉS)"
  drop_bench_filters
  run_matrix "fts0-masque-vide@$VOL" "{\"fts_fields\":0,\"mask\":\"vide\",\"cold\":\"off\",\"version\":\"$VERSION\",\"events\":$NEV,\"db_bytes\":$DB0,\"hosts\":$PROFILE_HOSTS,\"profile\":\"$PROFILE_NAME\"}" ""

  say "  2b — masque NON VIDE (le rempart de confidentialité DÉSARME les deux)"
  # `role:''` masque viewer+editor mais PAS admin (field_filter.rs:110-115) : c'est pour ça que
  # TOUTES les cellules sont tirées en `benchviewer`, dans les deux états. Sinon le masque serait
  # inerte et la comparaison ne mesurerait rien.
  api POST /api/field-filters '{"name":"bench-mask-srcip","field":"src_ip","action":"mask","role":"","enabled":1}' >/dev/null
  api POST /api/field-filters '{"name":"bench-mask-user","field":"user","action":"partial","role":"","enabled":1}' >/dev/null
  api GET /api/field-filters | head -c 400; echo
  run_matrix "fts0-masque-non-vide@$VOL" "{\"fts_fields\":0,\"mask\":\"non-vide (src_ip=mask, fields.user=partial)\",\"cold\":\"off\",\"version\":\"$VERSION\",\"events\":$NEV,\"db_bytes\":$DB0,\"hosts\":$PROFILE_HOSTS,\"profile\":\"$PROFILE_NAME\"}" ""
  drop_bench_filters
  oom_report
  stop_daemon

  say "phase 3/3 — matrice, PLUME_FTS_FIELDS=1 (on mesure son COÛT, pas seulement son gain)"
  guard_disk
  start_daemon 1
  say "  attente du backfill de event_fields_fts (lots de 5 000, 200 ms entre deux)"
  PREV=0
  for i in $(seq 1 400); do
    guard_disk
    CUR="$(stat -c%s "$DB_DIR/plume.db")"
    RSS=$(( $(awk '{print $2}' /proc/$DAEMON_PID/statm 2>/dev/null || echo 0) * 4096 / 1048576 ))
    echo "  db=$((CUR/1048576))Mio (+$(( (CUR-DB0)/1048576 ))Mio) rss=${RSS}Mio"
    kill -0 "$DAEMON_PID" 2>/dev/null || { oom_report; die "daemon mort pendant le backfill FTS (voir $LOG) — RÉSULTAT À PUBLIER"; }
    [ "$CUR" = "$PREV" ] && [ "$i" -gt 4 ] && break
    PREV="$CUR"; sleep 30
  done
  DB1="$(stat -c%s "$DB_DIR/plume.db")"
  say "  COÛT DISQUE MESURÉ de PLUME_FTS_FIELDS=1 : +$(( (DB1-DB0)/1048576 )) Mio ($((DB0/1048576)) -> $((DB1/1048576)) Mio)"
  run_matrix "fts1-masque-vide@$VOL" "{\"fts_fields\":1,\"mask\":\"vide\",\"cold\":\"off\",\"version\":\"$VERSION\",\"events\":$NEV,\"db_bytes\":$DB1,\"db_bytes_fts0\":$DB0,\"classes\":\"$FTS_CLASSES\",\"hosts\":$PROFILE_HOSTS,\"profile\":\"$PROFILE_NAME\"}" "$FTS_CLASSES"
  oom_report
  stop_daemon
fi

# ================================================================== MATRICE SIMPLE (une config)
# `BENCH_PHASES=simple` tire UNE configuration (masque vide, FTS off) sur la base déjà remplie.
# C'est le mode des comparaisons où seule LA DONNÉE change (profil mono-hôte contre profil flotte) :
# rejouer les passes masquage et FTS n'y apprendrait rien et coûterait trois fois le temps.
#   BENCH_PHASES=simple BENCH_CONFIG_ID=flotte-50@0.6M BENCH_DIR=<base remplie> bench/run.sh
if [ "$BENCH_PHASES" = "simple" ]; then
  say "matrice SIMPLE — une configuration, masque vide"
  start_daemon 0
  NEV="$(count_events)"
  DB0="$(stat -c%s "$DB_DIR/plume.db")"
  VOL="$(python3 -c "print(f'{$NEV/1e6:.1f}M')")"
  echo "base : $NEV événements, $((DB0/1048576)) Mio, profil $PROFILE_NAME ($PROFILE_HOSTS hôtes)"
  drop_bench_filters
  CLASSES_META=""
  [ -n "${BENCH_CLASSES:-}" ] && CLASSES_META=",\"classes\":\"$BENCH_CLASSES\""
  # L'étiquette « tier froid » est DÉRIVÉE de l'état réel du daemon, jamais écrite en dur : une
  # configuration dont l'étiquette mentirait sur son propre réglage n'aurait aucune valeur.
  COLD_LABEL="off"
  [ "$BENCH_COLD" = "1" ] && COLD_LABEL="actif (hot=${BENCH_COLD_HOT_DAYS}j)"
  run_matrix "${BENCH_CONFIG_ID:-simple@$VOL}" "{\"fts_fields\":0,\"mask\":\"vide\",\"cold\":\"$COLD_LABEL\",\"version\":\"$VERSION\",\"events\":$NEV,\"db_bytes\":$DB0,\"hosts\":$PROFILE_HOSTS,\"profile\":\"$PROFILE_NAME\"$CLASSES_META}" "${BENCH_CLASSES:-}"
  oom_report
  stop_daemon
fi

# ================================================================== TIER FROID
# `BENCH_PHASES=cold` mesure le tier froid SUR UNE BASE DÉJÀ REMPLIE. Quatre temps :
#   0. TÉMOIN CHAUD SEUL : la MÊME base, `PLUME_COLD_TIER=0`, matrice complète. Sans ce témoin, tout
#      écart mesuré ensuite mélangerait l'effet du froid et celui d'une autre base ou d'une autre
#      machine.
#   1. AGING : le daemon est ARRÊTÉ et `plume-daemon retention` est lancé une fois, avec le MÊME
#      environnement. C'est le vrai chemin (`retention_run` -> `cold_age_run`), pas un raccourci ;
#      le faire hors ligne évite de mesurer une columnarisation concurrente des requêtes.
#   2. BILAN MESURÉ de la columnarisation : lignes restées chaudes, taille du hot, taille du froid.
#   3. MATRICE avec `PLUME_COLD_TIER=1`. Les fenêtres au-delà de la fenêtre chaude lisent alors du
#      Parquet, et celles qui la traversent lisent les DEUX — c'est le cas réel et le plus coûteux.
#
#   BENCH_PHASES=cold BENCH_COLD=1 BENCH_DIR=<copie d une base remplie> bench/run.sh
if [ "$BENCH_PHASES" = "cold" ]; then
  # 0. LA MÊME BASE, TIER FROID ÉTEINT. Sans ce témoin, l'écart mesuré ensuite mélangerait l'effet du
  #    froid et celui d'une autre base ou d'une autre machine. Ici : même fichier, même machine,
  #    passes consécutives — le seul changement est `PLUME_COLD_TIER` et la columnarisation.
  say "phase froid 1/4 — témoin CHAUD SEUL sur la même base (PLUME_COLD_TIER=0)"
  BENCH_COLD=0
  start_daemon 0
  NEV_HOT0="$(count_events)"
  DBC0="$(stat -c%s "$DB_DIR/plume.db")"
  VOLC="$(python3 -c "print(f'{$NEV_HOT0/1e6:.1f}M')")"
  echo "avant : $NEV_HOT0 événements, hot $((DBC0/1048576)) Mio"
  drop_bench_filters
  run_matrix "chaud-seul@$VOLC" "{\"fts_fields\":0,\"mask\":\"vide\",\"cold\":\"off\",\"version\":\"$VERSION\",\"events\":$NEV_HOT0,\"db_bytes\":$DBC0,\"hosts\":$PROFILE_HOSTS,\"profile\":\"$PROFILE_NAME\"}" ""
  oom_report
  stop_daemon
  BENCH_COLD=1

  say "phase froid 2/4 — aging hot -> Parquet (plume-daemon retention, chemin réel)"
  mkdir -p "$BENCH_DIR/cold"
  TA0=$(date +%s)
  ( PLUME_CONFIG=/nonexistent PLUME_DB="$DB_DIR/plume.db" PLUME_DB_KEY="$BENCH_DB_KEY" \
    PLUME_SPOOL="$SPOOL_DIR" PLUME_COLD_TIER=1 PLUME_COLD_DIR="$BENCH_DIR/cold" \
    PLUME_COLD_HOT_WINDOW_DAYS="$BENCH_COLD_HOT_DAYS" PLUME_RETENTION_DAYS="$BENCH_RETENTION_DAYS" \
    "$BIN" retention ) >>"$BENCH_DIR/cold-aging.log" 2>&1 || die "l'aging a échoué (voir $BENCH_DIR/cold-aging.log)"
  TA1=$(date +%s)
  guard_disk

  say "phase froid 3/4 — bilan mesuré ; 4/4 — matrice avec PLUME_COLD_TIER=1"
  start_daemon 0
  NEV_HOT1="$(count_events)"
  DBC1="$(stat -c%s "$DB_DIR/plume.db")"
  COLD_BYTES="$(du -sb "$BENCH_DIR/cold" 2>/dev/null | cut -f1)"
  COLD_FILES="$(find "$BENCH_DIR/cold" -type f -name '*.parquet' 2>/dev/null | wc -l)"
  say "COLUMNARISÉ : $NEV_HOT0 -> $NEV_HOT1 lignes chaudes ; hot $((DBC0/1048576)) -> $((DBC1/1048576)) Mio ; froid $((COLD_BYTES/1048576)) Mio en $COLD_FILES fichiers, en $((TA1-TA0))s"
  { echo "{\"phase\":\"cold_age\",\"version\":\"$VERSION\",\"hot_rows_before\":$NEV_HOT0,"
    echo " \"hot_rows_after\":$NEV_HOT1,\"hot_bytes_before\":$DBC0,\"hot_bytes_after\":$DBC1,"
    echo " \"cold_bytes\":${COLD_BYTES:-0},\"cold_files\":${COLD_FILES:-0},\"seconds\":$((TA1-TA0)),"
    echo " \"hot_window_days\":$BENCH_COLD_HOT_DAYS,\"retention_days\":$BENCH_RETENTION_DAYS,"
    echo " \"path\":\"plume-daemon retention -> retention_run -> cold_age_run (écriture Parquet scellée, vérifiée, puis suppression du hot)\"}"
  } | tr -d '\n' >> "$RESULTS"; echo >> "$RESULTS"
  drop_bench_filters
  run_matrix "froid-actif@$VOLC" "{\"fts_fields\":0,\"mask\":\"vide\",\"cold\":\"actif (hot=${BENCH_COLD_HOT_DAYS}j)\",\"version\":\"$VERSION\",\"events\":$NEV_HOT0,\"db_bytes\":$DBC1,\"cold_bytes\":${COLD_BYTES:-0},\"hosts\":$PROFILE_HOSTS,\"profile\":\"$PROFILE_NAME\"}" ""
  oom_report
  stop_daemon
fi

say "terminé — résultats bruts : $RESULTS"
echo "rendu du tableau :"
echo "  python3 bench/report.py $RESULTS \\"
echo "      --ingest-curve $BENCH_DIR/ingest_rate.csv \\"
echo "      --fill-log $BENCH_DIR/matrix.log -o docs/BENCHMARK.md"
