#!/bin/sh
# Capteur SOC : ingère les détections eBPF de Falco (sortie JSON) -> events source=falco.
# Falco est externe (falco.org) ; configure json_output + file_output vers $PLUME_FALCO_LOG.
# Lecture incrémentale par offset. ROOT. Optionnel (skip si log absent).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
LOG="${PLUME_FALCO_LOG:-/var/log/falco/events.txt}"
[ -r "$LOG" ] || plume_unavailable falco missing-source "$LOG absent ou illisible : Falco non installe/non demarre"
OFF="$STATE/falco.offset"
last=$(cat "$OFF" 2>/dev/null || echo 0)
size=$(wc -c < "$LOG" 2>/dev/null || echo 0)
[ "$size" -lt "$last" ] && last=0   # rotation -> on repart du début
new=$(tail -c "+$((last + 1))" "$LOG" 2>/dev/null || true)
printf '%s' "$size" > "$OFF"
[ -z "$new" ] && plume_exit_nodata

tmpf=$(mktemp)
printf '%s\n' "$new" > "$tmpf"
events=""
n=0
while IFS= read -r line; do
  case "$line" in *'"priority"'*) : ;; *) continue ;; esac
  n=$((n + 1)); [ "$n" -gt 200 ] && break
  # 'output' est déjà une chaîne JSON échappée -> on la réinjecte telle quelle
  out=$(printf '%s' "$line" | grep -oP '"output":"\K(?:\\.|[^"\\])*' | head -1)
  [ -z "$out" ] && continue
  pri=$(printf '%s' "$line" | grep -oP '"priority":"\K[^"]+' | head -1)
  case "$pri" in Emergency|Alert|Critical) sev=4 ;; Error|Warning) sev=3 ;; Notice) sev=2 ;; *) sev=1 ;; esac
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"falco\",\"category\":\"ebpf\",\"severity\":$sev,\"message\":\"$out\"}"
done < "$tmpf"
rm -f "$tmpf"
[ -z "$events" ] && plume_exit_nodata

spool_write "falco-$ts.json" "$(emit_event "$events")"
