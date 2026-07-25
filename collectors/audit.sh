#!/bin/sh
# Capteur SOC : auditd (exec / élévation de privilège / accès fichiers sensibles) -> events.
# Lit les NOUVEAUX enregistrements via le checkpoint d'ausearch. ROOT. auditd OPTIONNEL (skip si absent).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
command -v ausearch >/dev/null 2>&1 || exit 0
CKPT="$STATE/audit.ckpt"

out="$(ausearch --checkpoint "$CKPT" --start checkpoint --format text 2>/dev/null || true)"
[ -z "$out" ] && exit 0

tmpf=$(mktemp)
printf '%s\n' "$out" > "$tmpf"
events=""
n=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  n=$((n + 1)); [ "$n" -gt 200 ] && break   # garde-fou : 200 events max / passe
  sev=2
  case "$line" in
    *shadow*|*sudoers*|*ld.so.preload*|*sudo*|*" su "*|*passwd*|*useradd*|*usermod*|*setuid*|*sshd_config*) sev=3 ;;
  esac
  em=$(json_escape "$(printf '%s' "$line" | cut -c1-400)")
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"auditd\",\"category\":\"audit\",\"severity\":$sev,\"message\":\"$em\"}"
done < "$tmpf"
rm -f "$tmpf"
[ -z "$events" ] && exit 0

spool_write "audit-$ts.json" "$(emit_event "$events")"
