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
#
# S36, RANG « DU BRUIT AU LIEU DU SILENCE » — UNE LISTE VIDE FAISAIT DE TOUT FLUX UNE SORTIE.
# Le statut du tube etait celui de `tr`, jamais celui de `ss` : quand la lecture des sockets en ECOUTE
# echouait, `listen` valait la meme chose que sur un hote qui n'ecoute REELLEMENT rien — une liste
# vide. Or `dir` en derive par un seul test (`lport in lset`) : aucun port en ecoute connu, donc
# AUCUN flux entrant, donc TOUT devient `dir=outbound`. Les connexions que l'hote SUBIT etaient
# republiees comme des connexions qu'il INITIE, et trois regles livrees s'arment exactement de la :
# `di-conntrack-internal-sweep` (severite 3, `dc(dst_ip) by src_ip > 20`), `lm-conntrack-internal-ssh`
# (severite 3) et `ex-egress-fanout-external` (severite 2). Un balayage interne etait annonce a chaque
# passage ou `ss` ne repondait pas — l'alerte la plus couteuse a ignorer, parce qu'elle est vraie
# parfois.
# LA DISTINCTION EST FAITE SUR LE CODE DE RETOUR, pas sur le vide : `ss` qui REUSSIT et ne rend aucun
# port est un hote qui n'ecoute rien, et ce releve-la est publie comme avant. `ss` qui ECHOUE ne
# permet plus de dire le sens d'un seul flux : le capteur le DIT et rend la main, sans acquitter quoi
# que ce soit (il n'a pas de filigrane) — le passage suivant reechantillonnera.
_ss_listen=$(mktemp)
if ss -Hltn > "$_ss_listen" 2>/dev/null; then
  listen=" $(awk '{p=$4; sub(/.*:/,"",p); print p}' "$_ss_listen" | sort -un | tr '\n' ' ') "
  rm -f "$_ss_listen"
else
  rm -f "$_ss_listen"
  plume_lecture_echouee conntrack source_illisible \
    "les sockets en ECOUTE n'ont pas pu etre lues (ss -Hltn) : le SENS de chaque flux (entrant/sortant) en derive, et sans elles tout flux serait publie comme SORTANT. Aucun flux n'est publie ce passage plutot qu'un sens fabrique."
fi

# --- ECHANTILLONNAGE FLUX : boucle bornee a WINDOW secondes (self-limit -> pas de chevauchement timer) ---
#
# S36, RANG « DESARME UNE REGLE » — L'ECHANTILLONNAGE QUI ECHOUE RENDAIT « HOTE AU REPOS ».
# `|| true` ramenait chaque echec de `ss` au cas normal, et la boucle n'en gardait aucune trace. Quand
# la lecture des sockets echouait A TOUS LES ECHANTILLONS — refus de netlink dans un espace de noms
# reduit, `ss` present mais casse, table saturee — le fichier brut restait VIDE, l'agregat aussi, et
# le capteur sortait par la porte « rien a signaler ». Or c'est EXACTEMENT ce que rend un hote qui
# n'a aucun flux dans la portee capturee : l'aveuglement et le calme se disaient du meme mot.
# CE QUE CE SILENCE DESARME, nommement : `di-conntrack-internal-sweep` (severite 3, balayage interne),
# `lm-conntrack-internal-ssh` (severite 3, lateralisation SSH) et `ex-egress-fanout-external`
# (severite 2, eventail de sortie). Les trois comptent des flux ; sans flux elles ne peuvent plus
# tirer. Une regle dont l'entree est vide n'est pas en retard, elle est STRUCTURELLEMENT INERTE.
# LA GARDE D'EN-TETE NE COUVRE PAS CE CAS : `command -v ss` etablit que le binaire EXISTE, jamais
# qu'une lecture aboutit.
# DEUX PORTES, PARCE QU'IL Y A DEUX SITUATIONS : aucun echantillon obtenu -> toute la collecte du
# passage a echoue, on le dit et on sort (`plume_lecture_echouee`) ; une partie seulement -> ce qui a
# ete vu reste publie, mais l'echantillonnage est LACUNAIRE et le compteur de connexions distinctes
# (le signal de battement) le sous-estime — on le dit et on continue (`plume_lecture_partielle`).
raw=$(mktemp)
end=$(( $(date +%s) + WINDOW ))
_ct_ok=0
_ct_ko=0
while [ "$(date +%s)" -lt "$end" ]; do
  # multi-state => la colonne State EST imprimee (6 champs : state recvq sendq local peer process)
  if ss -Htanp state established state syn-sent 2>/dev/null >> "$raw"; then
    _ct_ok=$((_ct_ok + 1))
  else
    _ct_ko=$((_ct_ko + 1))
  fi
  sleep "$IVAL" 2>/dev/null || sleep 1
done
if [ "$_ct_ok" -eq 0 ]; then
  rm -f "$raw"
  plume_lecture_echouee conntrack source_illisible "aucun des $_ct_ko echantillons de sockets n'a abouti pendant la fenetre de ${WINDOW}s : AUCUN flux n'a ete observe ce passage. L'absence de balayage, de lateralisation ou d'eventail de sortie ne peut PAS en etre conclue."
fi
if [ "$_ct_ko" -gt 0 ]; then
  plume_lecture_partielle conntrack source_illisible "echantillonnage LACUNAIRE : $_ct_ko echantillon(s) sur $((_ct_ok + _ct_ko)) n'ont pas abouti. Les flux brefs de ces instants ne sont pas vus et le compteur de connexions distinctes les sous-estime."
fi

# --- AGREGATION : 1 ligne TSV par (dir,scope,proc,dst,dport) avec count = nb de connexions DISTINCTES ---
# S36, RANG « DU BRUIT AU LIEU DU SILENCE » — LE PROPRIETAIRE DE FLUX `?` FUSIONNAIT TOUT EN UN.
# `ss -Htanp` ne rend la colonne processus qu'avec les droits qu'il faut ; sans eux, AUCUNE ligne ne
# la porte. Le programme ci-dessous posait alors `?` — un mot du DOMAINE NORMAL du champ — sur tous
# les flux d'un coup. La regle livree `ex-egress-fanout-external` (severite 2) compte
# `dc(dst_ip) by proc | where dc > 50` : un hote qui parle a plus de cinquante destinations externes,
# ce qui est banal, franchissait le seuil au nom d'un SEUL « processus » qui n'existe pas. Le
# proprietaire non lu se dit desormais par la chaine VIDE, et le champ disparait de l'evenement.
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
    NONLU="__plume_proc_non_lu__";
    n=split(keep,kk," "); for(i=1;i<=n;i++) karr[kk[i]]=1;
    m=split(listen,ll," "); for(i=1;i<=m;i++) lset[ll[i]]=1;
  }
  {
    state=$1; local=$4; peer=$5;
    if(local=="" || peer=="") next;
    # S36 : un SENTINEL, jamais un nom fabrique (voir le bandeau au-dessus du programme awk). Il ne
    # peut pas etre la chaine vide : la ligne TSV est relue par `read` avec IFS=TABULATION, et une
    # TABULATION est un blanc IFS — deux consecutives se fondent en une seule et decalent TOUTES les
    # colonnes suivantes. Le sentinel est traduit en « champ absent » par le shell, plus bas.
    proc=NONLU; if(match($0,/\(\("[^"]+"/)){ proc=substr($0,RSTART+3,RLENGTH-4) }
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
  # LE CHAMP `proc` DISPARAIT QUAND LE PROPRIETAIRE N'A PAS ETE LU — il n'est pas remplace par un
  # mot. C'est ce qui rend le verdict EXACT plutot que muet : le flux est PUBLIE (il est reel, il
  # reste cherchable et compte dans les panneaux), mais une regle qui RAISONNE SUR LE PROCESSUS ne
  # peut plus conclure a partir de lui. Le compilateur GXQL emet `json_extract(fields,'$.proc')` sans
  # COALESCE : sur une cle absente le predicat `proc!=…` vaut NULL, donc la ligne sort du `WHERE` de
  # `ex-egress-fanout-external` au lieu d'y entrer sous un faux proprietaire commun. Le trou, lui,
  # est avoue une fois par passage, par le canal ou une regle livree alerte deja.
  # Le sentinel de l'agregation redevient ici ce qu'il decrit : un proprietaire NON LU.
  [ "$proc" = "__plume_proc_non_lu__" ] && proc=""
  _pl="processus non lu"; [ -n "$proc" ] && _pl="$proc"
  if [ "$dir" = outbound ]; then m="net $sc out: $_pl -> $dip:$dpt (x$conns)"; else m="net $sc in: $sip -> $_pl:$dpt (x$conns)"; fi
  m=$(json_escape "$m")
  pj=$(json_escape "$proc")
  dh=$(json_escape "$dhost")
  st=$(json_escape "$state")
  if [ -n "$proc" ]; then
    _pf="\"proc\":\"$pj\","
  else
    _pf="\"proc_verdict\":\"illisible\",\"cause\":\"source_refusee\","
  fi
  fields="{$_pf\"src_ip\":\"$sip\",\"dst_ip\":\"$dip\",\"dst_host\":\"$dh\",\"dport\":\"$dpt\",\"proto\":\"tcp\",\"dir\":\"$dir\",\"state\":\"$st\",\"scope\":\"$sc\",\"count\":$conns}"
  printf '%s\n' "{\"ts\":$ts,\"source\":\"conntrack\",\"category\":\"network\",\"severity\":$sev,\"message\":\"$m\",\"src_ip\":\"$sip\",\"dst_ip\":\"$dip\",\"dedup\":\"conntrack-$dir-$dip-$dpt-$pj-$ts\",\"fields\":$fields}"
done > "$STATE_DIR/.ct.events.$$" || true
# le while tourne dans un sous-shell (pipe) -> on relit le fichier pour assembler l'enveloppe
events=$(paste -sd, "$STATE_DIR/.ct.events.$$" 2>/dev/null || true)
# L'AVEU EST COMPTE SUR LE FICHIER, pas dans la boucle : celle-ci tourne dans un sous-shell.
_ct_sans_proc=$(grep -c '"proc_verdict":"illisible"' "$STATE_DIR/.ct.events.$$" 2>/dev/null || true)
rm -f "$STATE_DIR/.ct.events.$$"
case "${_ct_sans_proc:-0}" in ''|*[!0-9]*) _ct_sans_proc=0 ;; esac
if [ "$_ct_sans_proc" -gt 0 ]; then
  plume_lecture_partielle conntrack source_refusee \
    "$_ct_sans_proc flux publie(s) SANS proprietaire : la colonne processus de ss n'a pas ete lisible (droits insuffisants sur les sockets d'autrui). Les flux sont publies, mais aucune detection qui raisonne PAR PROCESSUS ne peut conclure sur eux — et aucun nom de processus n'est fabrique pour les faire tenir ensemble."
fi

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
