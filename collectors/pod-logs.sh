#!/bin/sh
# Capteur Plume : logs des pods k8s (/var/log/pods) FILTRÉS (sécurité) -> events source=k8s-log.
# PAS du Loki exhaustif : ne ship que les lignes notables (filtre configurable), borné (anti-volume).
# Offset par fichier. ROOT / OPT-IN. Skip si /var/log/pods absent.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
DIR="${PLUME_POD_LOG_DIR:-/var/log/pods}"
FILTER="${PLUME_POD_LOG_FILTER:-error|fail|denied|unauthorized|panic|fatal|exception|segfault|authenticated|session opened|successful login|logged in|signed in}"
# DÉBRUITAGE — pods déjà couverts par un collecteur DÉDIÉ : les exclure ici évite une DOUBLE ingestion.
# Liste de sous-chaînes séparées par | (comparée au nom de pod). Défaut VIDE : rien n'est exclu.
# À vous de la remplir selon les collecteurs que vous activez (ex. SKIP='app-a|app-b').
SKIP="${PLUME_POD_LOG_SKIP:-}"
MAX="${PLUME_POD_LOG_MAX:-200}"
MIN_SEV="${PLUME_POD_LOG_MIN_SEV:-3}"   # DÉBRUITAGE : ne shippe que sev>=3 (denied/unauthorized/fatal/panic/segfault) ; coupe le bruit du grep error|fail (sev2) et les auth-ok (sev1)
[ -d "$DIR" ] || exit 0
mkdir -p "$STATE/podoff" 2>/dev/null || true

raw=$(mktemp)
fscan=0   # fichiers réellement scannés ce run (existants, nouveaux octets, hors pods SKIP) -> battement de santé
for f in "$DIR"/*/*/*.log; do
  [ -e "$f" ] || continue
  key=$(printf '%s' "$f" | cksum | cut -d' ' -f1)
  off="$STATE/podoff/$key"
  last=$(cat "$off" 2>/dev/null || echo 0)
  size=$(wc -c < "$f" 2>/dev/null || echo 0)
  [ "$size" -lt "$last" ] && last=0
  state_write "$off" "$size"
  [ "$size" -le "$last" ] && continue
  pod=$(printf '%s' "$f" | sed -E 's#.*/pods/([^/]+)/.*#\1#')
  # le conteneur = répertoire juste au-dessus du fichier .log (/pods/<ns_pod_uid>/<CONTENEUR>/N.log)
  # -> distingue les conteneurs d'un même pod (app vs sidecar/init) ; perdu auparavant.
  cont=${f%/*}; cont=${cont##*/}
  skip=0; for s in $(printf '%s' "$SKIP" | tr '|' ' '); do case "$pod" in *"$s"*) skip=1; break ;; esac; done
  [ "$skip" = 1 ] && continue   # pod listé dans SKIP (déjà couvert par un collecteur dédié) : pas de double collecte
  fscan=$((fscan + 1))   # ce fichier est effectivement scanné (compteur du battement de santé)
  tail -c "+$((last + 1))" "$f" 2>/dev/null | grep -iE "$FILTER" | head -n 80 | while IFS= read -r l; do
    printf '%s\t%s\t%s\n' "$pod" "$cont" "$l"
  done >> "$raw"
done

events=""
n=0
lscan=0   # lignes candidates (post-filtre FILTER) examinées ce run -> battement de santé
TAB=$(printf '\t')
while IFS="$TAB" read -r pod cont l; do
  [ -z "${l:-}" ] && continue
  lscan=$((lscan + 1))
  ns=${pod%%_*}                       # <ns>_<pod>_<uid> -> ns = le namespace k8s (souvent 1 par application) -> groupable
  pn=${pod#*_}; pn=${pn%_*}           # nom du pod (sans préfixe ns ni suffixe uid)
  msg=$(printf '%s' "$l" | sed -E 's/^[0-9TZ:.+-]+ (stdout|stderr) [FP] //')
  sev=2
  case "$l" in *denied*|*nauthorized*|*fatal*|*FATAL*|*panic*|*segfault*) sev=3 ;; esac
  case "$l" in *authenticated*|*"session opened"*|*"logged in"*|*"signed in"*|*"successful login"*) sev=1 ;; esac   # auth réussie = info
  [ "$sev" -lt "$MIN_SEV" ] && continue   # DÉBRUITAGE : sous le seuil de sévérité -> non shippé
  n=$((n + 1)); [ "$n" -gt "$MAX" ] && break
  em=$(json_escape "$(printf '%s: %s' "$pn" "$msg" | cut -c1-400)")
  nsj=$(json_escape "$ns"); pnj=$(json_escape "$pn")
  cj=$(json_escape "${cont:-}")
  fj="{\"ns\":\"$nsj\",\"pod\":\"$pnj\",\"container\":\"$cj\"}"
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"k8s-log\",\"category\":\"k8s\",\"severity\":$sev,\"message\":\"$em\",\"fields\":$fj}"
done < "$raw"
rm -f "$raw"

# DEAD-MAN'S-SWITCH (calque EXACT de crowdsec.sh) : à CHAQUE run on ship AUSSI un battement de SANTÉ
# (source=k8s-log category=health, sev 0) MÊME quand 0 ligne sev≥3 -> Plume distingue « collecteur calme
# (normal) » de « collecteur pod-logs mort/cassé ». Le SILENCE de ce battement (>~25 min) lève une alerte
# MUET (collecteur CONTINU k8s-log-health, cf. main.rs COLLECTORS). PAS de dedup (event.dedup est UNIQUE ->
# un dedup constant bloquerait l'INSERT OR IGNORE et figerait MAX(ts)) -> chaque battement S'INSÈRE -> MAX(ts)
# avance -> heartbeat vivant. On NE coupe PLUS avant ce point (l'ancien « [ -z "$events" ] && exit 0 » sautait
# le battement les runs sans sev≥3) : events contient au minimum ce battement -> le spool part toujours.
hmsg="pod-logs santé: $fscan fichiers, $lscan lignes scannées, $n lignes expédiées (seuil PLUME_POD_LOG_MIN_SEV)"
hfields="{\"files_scanned\":$fscan,\"lines_scanned\":$lscan,\"sev3_shipped\":$n}"
events="$events${events:+,}$(heartbeat k8s-log "$hmsg" "$hfields")"

spool_write "podlogs-$ts.json" "$(emit_event "$events")"

# --- CHANTIER whitelists->webui : AUTO-REPORT de config (source=k8s-log category=config) -----------
# Surface FILTER/SKIP/MIN_SEV dans le panneau read-only « Suppressions & whitelists actives » (VISIBILITE
# cote daemon, CONTROLE ici). Dedup par empreinte -> re-emet seulement si la config change. collection-reducing.
cfg_fields=$(printf '{"type":"collection-reducing","collector":"pod-logs","source":"k8s-log","filters":{"filter":"%s","skip":"%s","min_sev":"%s","max":"%s"},"note":"ne ship que les lignes matchant FILTER, hors pods SKIP (collecteurs dedies), au-dessus de MIN_SEV — collecte reduite"}' \
  "$(json_escape "$FILTER")" "$(json_escape "$SKIP")" "$(json_escape "$MIN_SEV")" "$(json_escape "$MAX")")
cfg_dd="cfg-k8s-log-$(printf '%s' "$cfg_fields" | cksum | cut -d' ' -f1)"
cfg_event=$(printf '{"ts":%s,"source":"k8s-log","category":"config","severity":0,"message":"config collecteur pod-logs (filtres de collecte)","dedup":"%s","fields":%s}' \
  "$ts" "$cfg_dd" "$cfg_fields")
spool_write "config-podlogs-$ts.json" "$(emit_event "$cfg_event")"
