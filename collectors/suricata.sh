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
# n'a ete publie donc rien n'est acquitte). S34 — le rejeu que cet ordre produit est desormais
# ABSORBE : chaque event porte une cle prise dans le record lui-meme (cf. `dd` dans l'awk).
if [ "$prev" -ge "$size" ]; then state_stage "$OFF" "$size"; plume_exit_nodata; fi

new=$(mktemp)
tail -c +"$((prev + 1))" "$EVE" 2>/dev/null > "$new" || true
state_stage "$OFF" "$size"

# S34 — CLE D'IDENTITE. Elle est prise DANS LE RECORD : `timestamp` est l'horodatage microseconde
# que Suricata pose sur l'evenement, pas l'instant du passage. Ni `$ts`, ni l'offset, ni le PID n'y
# entrent — republier la meme tranche reproduit donc la MEME cle, et le central l'absorbe.
# `k` ne compte QUE les records partageant le meme `timestamp` (plusieurs signatures peuvent alerter
# sur le meme paquet, a la microseconde pres). C'est un rang PAR HORODATAGE et non un rang dans la
# tranche : un rang global se decalerait des que la tranche suivante recouvre la precedente (le
# journal peut grossir entre la mesure de taille et la lecture), et le recouvrement cesserait d'etre
# absorbe. Sans `timestamp` exploitable, AUCUNE cle n'est posee : une cle inventee confondrait deux
# alertes distinctes, ce qui est pire qu'un doublon visible.
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
    # S34 : cle prise DANS LE RECORD (voir le bandeau au-dessus). k = rang PAR HORODATAGE.
    tsv=sval("timestamp"); dd="";
    if (tsv!="") { k=++C[tsv]; dd="suricata-" tsv "-" k }
    gsub(/[\\"]/,"",msg); print sev "\t" et "\t" dd "\t" msg
  }
' "$new" | head -400)
rm -f "$new"
[ -z "$parsed" ] && plume_exit_nodata

events=""; TAB=$(printf '\t')
while IFS="$TAB" read -r sev cat dd msg; do
  [ -z "${msg:-}" ] && continue
  mj=$(json_escape "$msg")
  ddj=""; [ -n "${dd:-}" ] && ddj=",\"dedup\":\"$(json_escape "$dd")\""
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"suricata\",\"category\":\"$cat\",\"severity\":$sev,\"message\":\"$mj\"$ddj}"
done <<EOF
$parsed
EOF
[ -z "$events" ] && plume_exit_nodata

spool_write_then_ack "suricata-$ts.json" "$(emit_event "$events")"
