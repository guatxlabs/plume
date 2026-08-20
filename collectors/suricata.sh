#!/bin/sh
# Capteur SOC (PLUGIN) : ingere le eve.json de Suricata -> events source=suricata.
# Donne la profondeur reseau "facon Fortigate" SANS MITM : alertes IDS, fichiers extraits
# (telechargements), metadonnees TLS (SNI) / DNS. Plugin : si eve.json absent -> exit 0.
# Dependance MINIMALE : lit seulement le JSON que Suricata ecrit (pas de jq). Incremental via offset.
# NB : DEPLOYER Suricata est le morceau "lourd" (choix operateur) ; ce collecteur est juste le pont.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
EVE="${PLUME_SURICATA_EVE:-/var/log/suricata/eve.json}"
[ -r "$EVE" ] || plume_unavailable suricata missing-source "$EVE absent ou illisible : Suricata non installe/non demarre, ou eve.json ailleurs"
OFF="$STATE_DIR/suricata.offset"
# types ingeres (defaut = haut signal ; tls/dns sont volumineux -> opt-in)
TYPES_RE=$(printf '%s' "${PLUME_SURICATA_TYPES:-alert fileinfo}" | tr ', ' '||' | sed 's/^|*//; s/|*$//')

size=$(wc -c < "$EVE" 2>/dev/null || echo 0)
prev=$(cat "$OFF" 2>/dev/null || echo 0)
case "$prev" in *[!0-9]*) prev=0 ;; esac
[ "$prev" -gt "$size" ] && prev=0
# S30 — l'offset est MIS EN ATTENTE (ecrit apres publication, ou par `plume_exit_nodata` quand rien
# n'a ete publie donc rien n'est acquitte). Les events suricata ne portent pas de cle de
# dedoublonnage : le rejeu apres coupure produit des doublons visibles, plus une perte muette.
if [ "$prev" -ge "$size" ]; then state_stage "$OFF" "$size"; plume_exit_nodata; fi

new=$(mktemp)
tail -c +"$((prev + 1))" "$EVE" 2>/dev/null > "$new" || true
state_stage "$OFF" "$size"

parsed=$(awk -v types="$TYPES_RE" '
  function sval(key){ if (match($0, "\"" key "\":\"[^\"]*\"")) return substr($0, RSTART+length(key)+4, RLENGTH-length(key)-5); return "" }
  function nval(key){ if (match($0, "\"" key "\":[0-9]+"))     return substr($0, RSTART+length(key)+3, RLENGTH-length(key)-3); return "" }
  {
    et=sval("event_type"); if (et=="" || et !~ ("^(" types ")$")) next;
    src=sval("src_ip"); dst=sval("dest_ip");
    if (et=="alert")        { s=nval("severity"); sev=(s=="1"?3:(s=="2"?2:1)); msg="IDS: " sval("signature") " (" src "->" dst ")" }
    else if (et=="fileinfo"){ sev=1; msg="file: " sval("filename") " (" src "->" dst ")" }
    else if (et=="tls")     { sev=0; msg="tls: SNI=" sval("sni") " (" dst ")" }
    else if (et=="dns")     { sev=0; msg="dns: " sval("rrname") }
    else next;
    gsub(/[\\"]/,"",msg); print sev "\t" et "\t" msg
  }
' "$new" | head -400)
rm -f "$new"
[ -z "$parsed" ] && plume_exit_nodata

events=""; TAB=$(printf '\t')
while IFS="$TAB" read -r sev cat msg; do
  [ -z "${msg:-}" ] && continue
  mj=$(json_escape "$msg")
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"suricata\",\"category\":\"$cat\",\"severity\":$sev,\"message\":\"$mj\"}"
done <<EOF
$parsed
EOF
[ -z "$events" ] && plume_exit_nodata

spool_write_then_ack "suricata-$ts.json" "$(emit_event "$events")"
