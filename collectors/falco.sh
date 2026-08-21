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
# S30 — l'offset est MIS EN ATTENTE ici et n'est ecrit qu'apres la publication (cf. lib.sh). Avant,
# il avancait des la lecture : une coupure avant le `spool_write` final perdait la tranche en silence.
# S34 — le rejeu que cet ordre produit est desormais ABSORBE : chaque event porte une cle d'identite
# (cf. le bloc `dedup` de la boucle ci-dessous), donc republier la meme tranche n'ajoute aucune ligne.
state_stage "$OFF" "$size"
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
  # S34 — CLE D'IDENTITE. Elle est prise DANS LE RECORD (`time`, horodatage nanoseconde pose par
  # Falco au moment de la detection), jamais dans le passage : ni `$ts`, ni l'offset, ni le PID n'y
  # entrent, sans quoi la meme detection republiee produirait une cle differente et ne serait pas
  # absorbee. Le rang `k` ne compte QUE les records partageant le MEME `time` (le journal est ecrit
  # dans l'ordre du temps, les egaux sont donc contigus) : il n'est PAS un rang global dans la
  # tranche. La difference compte — un rang global se decalerait si la tranche suivante commencait
  # ailleurs (le journal peut grossir entre la mesure de taille et la lecture), et le recouvrement
  # cesserait d'etre absorbe. Sans `time` exploitable, AUCUNE cle n'est posee : une cle inventee
  # confondrait deux detections distinctes, ce qui est pire qu'un doublon visible.
  ftime=$(printf '%s' "$line" | grep -oP '"time":"\K[^"]+' | head -1)
  dd=""
  if [ -n "$ftime" ]; then
    if [ "$ftime" = "${prev_ftime:-}" ]; then k=$((${k:-1} + 1)); else prev_ftime="$ftime"; k=1; fi
    dd=",\"dedup\":\"falco-$(json_escape "$ftime")-$k\""
  fi
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"falco\",\"category\":\"ebpf\",\"severity\":$sev,\"message\":\"$out\"$dd}"
done < "$tmpf"
rm -f "$tmpf"
[ -z "$events" ] && plume_exit_nodata

spool_write_then_ack "falco-$ts.json" "$(emit_event "$events")"
