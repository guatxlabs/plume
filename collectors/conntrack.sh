#!/bin/sh
# Capteur Plume (PLUGIN) : FLUX reseau (egress/ingress) -> events source=conntrack.
# MODE FLUX : un snapshot unique `ss state established` etait AVEUGLE aux connexions
# COURTES (beacon C2, exfil breve ouvertes+fermees entre deux passages) et dedupait la frequence par dst
# (beaconing invisible). On ECHANTILLONNE desormais a HAUTE FREQUENCE pendant une fenetre (established +
# syn-sent -> on capte aussi l'INSTANT d'initiation d'une sortie), on COMPTE les connexions distinctes par
# (proc,dst:port) -> le compteur `count` EST le signal beaconing, et on N'ETOUFFE PAS les repetitions
# entre ticks (un event par flux PAR TICK -> serie temporelle => cadence beacon visible cote SOC).
# `conntrack -E` serait l'ideal (events noyau NEW/DESTROY) mais l'outil est absent ici -> fallback ss HF.
# CAPTURE par PORTEE (champ scope) : loopback | internal (10./192.168./172.16-31./pods k3s 10.42-43/ULA) |
# external (public). Defaut = external SEULEMENT (l'intra-cluster 10.42/10.43 = bruit enorme, exclu) :
# PLUME_CONNTRACK_SCOPE="external internal" pour re-elargir. ROOT (nom de process via ss -p).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
command -v ss >/dev/null 2>&1 || plume_unavailable conntrack missing-dependency "ss absent (paquet iproute2) : aucune socket/flux observable"
# rDNS (PTR) CACHÉ -> egress LISIBLE (ex deb.debian.org). INFORMATIF seulement (le PTR est controle par le
# proprietaire de l'IP -> ne jamais s'en servir pour decider ; dst_ip = verite).
RDNS_CACHE="$STATE_DIR/rdns.cache"; touch "$RDNS_CACHE" 2>/dev/null || true
rdns() {
  h=$(awk -F'\t' -v ip="$1" '$1==ip{print $2; exit}' "$RDNS_CACHE" 2>/dev/null)
  [ -n "$h" ] && { printf '%s' "$h"; return; }
  h=$(getent hosts "$1" 2>/dev/null | awk '{print $2; exit}'); [ -n "$h" ] || h="$1"
  printf '%s\t%s\n' "$1" "$h" >> "$RDNS_CACHE" 2>/dev/null || true
  printf '%s' "$h"
}
KEEP="${PLUME_CONNTRACK_SCOPE:-external}"
MAX="${PLUME_CONNTRACK_MAX:-400}"                # garde-fou de volume (flux conntrack = verbeux)
WINDOW="${PLUME_CONNTRACK_WINDOW:-12}"           # secondes d'echantillonnage HF par passage
IVAL="${PLUME_CONNTRACK_INTERVAL:-0.2}"          # intervalle entre echantillons (capte les flux brefs)

# ports en ECOUTE -> distingue ENTRANT (on se fait contacter) de SORTANT (on initie). Calcule une fois.
listen=" $(ss -Hltn 2>/dev/null | awk '{p=$4; sub(/.*:/,"",p); print p}' | sort -un | tr '\n' ' ') "

# --- ECHANTILLONNAGE FLUX : boucle bornee a WINDOW secondes (self-limit -> pas de chevauchement timer) ---
raw=$(mktemp)
end=$(( $(date +%s) + WINDOW ))
while [ "$(date +%s)" -lt "$end" ]; do
  # multi-state => la colonne State EST imprimee (6 champs : state recvq sendq local peer process)
  ss -Htanp state established state syn-sent 2>/dev/null >> "$raw" || true
  sleep "$IVAL" 2>/dev/null || sleep 1
done

# --- AGREGATION : 1 ligne TSV par (dir,scope,proc,dst,dport) avec count = nb de connexions DISTINCTES ---
TAB=$(printf '\t')
agg=$(awk -v keep="$KEEP" -v listen="$listen" '
  function scopeof(ip){
    if(ip ~ /^127\./ || ip=="::1" || ip ~ /^::ffff:127\./) return "loopback";
    if(ip ~ /^10\./ || ip ~ /^192\.168\./ || ip ~ /^169\.254\./ || ip ~ /^::ffff:10\./ || ip ~ /^::ffff:192\.168\./) return "internal";
    if(ip ~ /^172\.(1[6-9]|2[0-9]|3[0-1])\./ || ip ~ /^::ffff:172\.(1[6-9]|2[0-9]|3[0-1])\./) return "internal";
    if(ip ~ /^fc/ || ip ~ /^fd/ || ip ~ /^fe80/) return "internal";
    if(ip=="" || ip=="*" || ip ~ /^0\./ || ip ~ /^255\./) return "skip";
    return "external";
  }
  function ipof(a){ if(a ~ /^\[/){ s=a; sub(/^\[/,"",s); sub(/\].*/,"",s); return s } s=a; sub(/:[^:]*$/,"",s); return s }
  function portof(a){ if(a ~ /^\[/){ s=a; sub(/.*\]:/,"",s); return s } s=a; sub(/.*:/,"",s); return s }
  BEGIN{
    n=split(keep,kk," "); for(i=1;i<=n;i++) karr[kk[i]]=1;
    m=split(listen,ll," "); for(i=1;i<=m;i++) lset[ll[i]]=1;
  }
  {
    state=$1; local=$4; peer=$5;
    if(local=="" || peer=="") next;
    proc="?"; if(match($0,/\(\("[^"]+"/)){ proc=substr($0,RSTART+3,RLENGTH-4) }
    lip=ipof(local); lport=portof(local); pip=ipof(peer); pport=portof(peer);
    sc=scopeof(pip);
    if(sc=="skip" || !(sc in karr)) next;
    dir=(lport in lset)?"inbound":"outbound";
    if(dir=="outbound"){ sip=lip; dip=pip; dpt=pport } else { sip=pip; dip=lip; dpt=lport }
    key=dir SUBSEP sc SUBSEP proc SUBSEP dip SUBSEP dpt;
    conn=lip ":" lport "-" pip ":" pport;       # identite connexion (port local ephemere) -> compte beaconing
    ck=key SUBSEP conn;
    if(!(ck in seen)){ seen[ck]=1; conns[key]++ }
    sipa[key]=sip; dira[key]=dir; sca[key]=sc; proca[key]=proc; dipa[key]=dip; dpta[key]=dpt;
    if(states[key]=="") states[key]=state; else if(index(states[key],state)==0) states[key]=states[key] "," state;
  }
  END{ for(key in conns) printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n", dira[key], sca[key], proca[key], sipa[key], dipa[key], dpta[key], states[key], conns[key] }
' "$raw")
rm -f "$raw"
[ -z "$agg" ] && plume_exit_nodata

# tri par count DECROISSANT -> les flux les plus frequents (beaconing) survivent au plafond MAX
events=""; n=0
printf '%s\n' "$agg" | sort -t"$TAB" -k8 -nr | head -n "$MAX" | while IFS="$TAB" read -r dir sc proc sip dip dpt state conns; do
  [ -z "${dip:-}" ] && continue
  sev=1; [ "$dir" = inbound ] && [ "$sc" = external ] && sev=2
  dhost=""; [ "$dir" = outbound ] && [ "$sc" = external ] && dhost=$(rdns "$dip")
  if [ "$dir" = outbound ]; then m="net $sc out: $proc -> $dip:$dpt (x$conns)"; else m="net $sc in: $sip -> $proc:$dpt (x$conns)"; fi
  m=$(json_escape "$m")
  pj=$(json_escape "$proc")
  dh=$(json_escape "$dhost")
  st=$(json_escape "$state")
  fields="{\"proc\":\"$pj\",\"src_ip\":\"$sip\",\"dst_ip\":\"$dip\",\"dst_host\":\"$dh\",\"dport\":\"$dpt\",\"proto\":\"tcp\",\"dir\":\"$dir\",\"state\":\"$st\",\"scope\":\"$sc\",\"count\":$conns}"
  printf '%s\n' "{\"ts\":$ts,\"source\":\"conntrack\",\"category\":\"network\",\"severity\":$sev,\"message\":\"$m\",\"src_ip\":\"$sip\",\"dst_ip\":\"$dip\",\"dedup\":\"conntrack-$dir-$dip-$dpt-$pj-$ts\",\"fields\":$fields}"
done > "$STATE_DIR/.ct.events.$$" || true
# le while tourne dans un sous-shell (pipe) -> on relit le fichier pour assembler l'enveloppe
events=$(paste -sd, "$STATE_DIR/.ct.events.$$" 2>/dev/null || true)
rm -f "$STATE_DIR/.ct.events.$$"

# --- CHANTIER whitelists->webui : AUTO-REPORT de config (source=conntrack category=config) ---------
# AVANT l'early-exit (config surfacee meme sur un hote sans flux). Surface la PORTEE capturee
# (PLUME_CONNTRACK_SCOPE, defaut external) dans le panneau read-only. VISIBILITE cote daemon, CONTROLE ici.
# Dedup par empreinte. collection-reducing (drop des flux hors portee : internal/self).
cfg_scope="${PLUME_CONNTRACK_SCOPE:-external}"
cfg_fields=$(printf '{"type":"collection-reducing","collector":"conntrack","filters":{"scope_keep":"%s"},"note":"ne capture que les flux de la portee KEEP (defaut external) — drop internal/self, collecte reduite"}' \
  "$(json_escape "$cfg_scope")")
cfg_dd="cfg-conntrack-$(printf '%s' "$cfg_fields" | cksum | cut -d' ' -f1)"
cfg_event=$(printf '{"ts":%s,"source":"conntrack","category":"config","severity":0,"message":"config collecteur conntrack (portee capturee)","dedup":"%s","fields":%s}' \
  "$ts" "$cfg_dd" "$cfg_fields")
spool_write "config-conntrack-$ts.json" "$(emit_event "$cfg_event")"

[ -z "$events" ] && plume_exit_nodata

spool_write "conntrack-$ts.json" "$(emit_event "$events")"
