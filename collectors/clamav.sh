#!/bin/sh
# Capteur SOC (PLUGIN) : antivirus ClamAV sur les fichiers NOUVEAUX de chemins surveilles
# (pieces jointes mail, uploads, /tmp...) -> events source=clamav. Plugin : si clamscan/clamdscan
# absent OU aucun chemin configure -> exit 0. Dependance = ClamAV uniquement (optionnel).
# Incremental : ne scanne que les fichiers modifies depuis le dernier passage (marqueur d'horodatage).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
PATHS="${PLUME_CLAMAV_PATHS:-}"                       # ex: "/opt/.../mail-data /var/www/uploads"
[ -n "$PATHS" ] || plume_unavailable clamav missing-config "PLUME_CLAMAV_PATHS non pose : aucun chemin a scanner"
if command -v clamdscan >/dev/null 2>&1; then SCAN="clamdscan --fdpass --no-summary -i"
elif command -v clamscan >/dev/null 2>&1; then SCAN="clamscan --no-summary -i"
else plume_unavailable clamav missing-dependency "ni clamdscan ni clamscan sur cet hote"; fi
STAMP="$STATE_DIR/clamav.stamp"
MAX="${PLUME_CLAMAV_MAX:-500}"                        # plafond de fichiers scannes par passage

# liste des fichiers NOUVEAUX (plus recents que le marqueur) ; 1er run = depuis le marqueur cree maintenant
list=$(mktemp)
if [ -f "$STAMP" ]; then findnew="-newer $STAMP"; else findnew=""; fi
# shellcheck disable=SC2086
for p in $PATHS; do
  [ -e "$p" ] || continue
  find "$p" -type f $findnew 2>/dev/null
done | head -n "$MAX" > "$list"
touch "$STAMP"

if [ ! -s "$list" ]; then rm -f "$list"; plume_exit_nodata; fi

# scan -> ClamAV imprime "<fichier>: <signature> FOUND" pour chaque infection
res=$(mktemp)
# xargs : passe les fichiers en arguments (gere les gros lots) ; on ne garde que les FOUND
xargs -d '\n' -r $SCAN < "$list" 2>/dev/null | grep ' FOUND$' > "$res" || true
rm -f "$list"

events=""
while IFS= read -r line; do
  [ -z "$line" ] && continue
  file=${line%%: *}
  sig=${line#*: }; sig=${sig% FOUND}
  m=$(json_escape "$(printf 'malware: %s dans %s' "$sig" "$file")")
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"clamav\",\"category\":\"malware\",\"severity\":4,\"message\":\"$m\",\"dedup\":\"clamav-$file-$sig\"}"
done < "$res"
rm -f "$res"
[ -z "$events" ] && plume_exit_nodata

spool_write "clamav-$ts.json" "$(emit_event "$events")"
