#!/bin/sh
# Capteur Plume (PLUGIN, OPT-IN) : logs MAILSERVER -> events source=mail.
# docker-mailserver logge dans un FICHIER du pod (/var/log/mail/mail.log), PAS dans journald hote
# -> invisible des autres capteurs (d'ou "je ne vois pas les logs mail dans le SOC"). Ce capteur le
# lit (k3s exec, ou fichier en natif/container) et emet les events SECURITE : connexions reussies,
# echecs d'auth, rejets, postscreen, + verdicts ANTIVIRUS ClamAV/amavis (virus detecte, piece
# jointe bannie, panne du scanner). Champs PARSES (qui=src_ip/user, quand=ts, ou=service,
# comment=action) -> groupables en GXQL ( | stats count by action / by src_ip / by user ).
# Mode-aware : PLUME_MAIL_SRC=k3s|file. OPT-IN (non actif par defaut). Lecture seule, aucune action.
#
# Horodatage : le log est en ISO avec offset (+02:00) ; l'epoch UTC = mktime(heure) - offset, avec
# TZ=UTC pour que mktime interprete l'heure en UTC quel que soit le fuseau de l'hote.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
MAILSRC="${PLUME_MAIL_SRC:-k3s}"                       # k3s (kubectl exec) | file (chemin local)
MAIL_NS="${PLUME_MAIL_NS:-mail}"
MAIL_SEL="${PLUME_MAIL_SELECTOR:-app=mailserver}"
MAIL_CONTAINER="${PLUME_MAIL_CONTAINER:-mailserver}"
MAIL_LOG="${PLUME_MAIL_LOG:-/var/log/mail/mail.log}"
MAX="${PLUME_MAIL_MAX:-3000}"                          # lignes lues par passage (garde-fou)
SKIPIP="${PLUME_MAIL_SKIP_IP:-}"                        # IP à ignorer (ex node/self : probes internes bruyantes)
WM="$STATE_DIR/mail.watermark"                       # dernier epoch traite (incremental)
last=$(cat "$WM" 2>/dev/null || echo 0)

read_log() {
  case "$MAILSRC" in
    k3s)
      KC="kubectl"; command -v kubectl >/dev/null 2>&1 || KC="k3s kubectl"
      command -v "${KC%% *}" >/dev/null 2>&1 || return 1
      pod=$($KC -n "$MAIL_NS" get pod -l "$MAIL_SEL" -o name 2>/dev/null | head -1)
      [ -n "$pod" ] || return 1
      $KC -n "$MAIL_NS" exec "$pod" -c "$MAIL_CONTAINER" -- tail -n "$MAX" "$MAIL_LOG" 2>/dev/null
      ;;
    file)
      [ -r "$MAIL_LOG" ] || return 1
      tail -n "$MAX" "$MAIL_LOG" 2>/dev/null
      ;;
    *) return 1 ;;
  esac
}

raw=$(read_log) || plume_unavailable mail missing-source "source de log mail illisible (PLUME_MAIL_SRC=$MAILSRC) : ni fichier lisible, ni pod joignable"
[ -n "$raw" ] || plume_exit_nodata

now=$(date +%s)
umask 027
tmp=$(mktemp "$SPOOL/.mail.XXXXXX")
newwm=$(printf '%s\n' "$raw" | TZ=UTC awk -v last="$last" -v host="$host" -v now="$now" -v out="$tmp" -v skipip="$SKIPIP" '
function jesc(s){ gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/\r/,"",s); gsub(/\t/," ",s); return s }
function emit(cat,act,sev,ip,usr,svc,extra,dk,   dd){
  # malware/banned/av_error/mailflow = signaux amavis/clamav : emis MEME sans src_ip (le verdict
  # amavis ne porte pas toujours une IP relais) ; les autres exigent une src_ip (respect de skipip).
  if(cat!="malware" && cat!="banned" && cat!="av_error" && cat!="mailflow" && (ip=="" || ip==skipip)) return
  dd=(dk!="")?dk:("mail-" et "-" ip "-" act)
  ev="{\"ts\":" et ",\"source\":\"mail\",\"category\":\"" cat "\",\"severity\":" sev ",\"src_ip\":\"" ip "\",\"message\":\"" jesc($0) "\",\"dedup\":\"" dd "\",\"fields\":{\"action\":\"" act "\",\"user\":\"" jesc(usr) "\",\"service\":\"" svc "\",\"src_ip\":\"" ip "\"" extra "}}"
  if(n>0) buf=buf ","; buf=buf ev; n++
}
BEGIN{ n=0; buf=""; maxts=last+0 }
{
  if (n>=3000) next                                             # garde-fou volume/passage
  if ($0 !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/) next
  d=substr($0,1,19); gsub(/[-T:]/," ",d); base=mktime(d); if(base<0) next
  off=0; if (match($0,/[+-][0-9][0-9]:[0-9][0-9]/)) { o=substr($0,RSTART,RLENGTH); s=(substr(o,1,1)=="-")?-1:1; off=s*(substr(o,2,2)*3600+substr(o,5,2)*60) }
  et=base-off
  if (et <= last) next
  if (et > maxts) maxts=et
  ip=""; if (match($0,/rip=[0-9.]+/)) ip=substr($0,RSTART+4,RLENGTH-4); else if (match($0,/\[[0-9]+(\.[0-9]+)+\]/)) ip=substr($0,RSTART+1,RLENGTH-2)  # exige des points -> exclut le PID [1457]
  usr=""; if (match($0,/user=<[^>]*>/)) usr=substr($0,RSTART+6,RLENGTH-7)
  svc="postfix"; if ($0 ~ /dovecot/) svc="dovecot"; else if ($0 ~ /postscreen/) svc="postscreen"
  if ($0 ~ /(imap|pop3|submission)-login: Login:/) emit("auth","success",1,ip,usr,svc)
  else if ($0 ~ /authentication failed|auth failed|Aborted login/) emit("auth","failure",2,ip,usr,svc)
  else if ($0 ~ /postscreen.*(PREGREET|DNSBL|BLACKLISTED|COMMAND (PIPELINING|TIME|COUNT)|BARE NEWLINE|NON-SMTP)/) emit("postscreen","blocked",2,ip,usr,"postscreen")  # HANGUP exclu = bruit (probes node)
  else if ($0 ~ /NOQUEUE: reject|reject: RCPT/) emit("reject","blocked",2,ip,usr,svc)
  else if ($0 ~ /amavis\[[0-9]+\]:.*(Passed|Blocked) [A-Z]/) {  # verdict amavis (IronPort-like : flux + verdicts)
    vd=""; if (match($0,/(Passed|Blocked) [A-Z][A-Z-]*/)) vd=substr($0,RSTART,RLENGTH)
    frm=""; if (match($0,/<[^>]*> ->/)) frm=substr($0,RSTART+1,RLENGTH-5)           # <sender> ->
    rcpt=""; if (match($0,/-> <[^>]*>/)) rcpt=substr($0,RSTART+4,RLENGTH-5)         # -> <rcpt>
    sco=""; if (match($0,/Hits: -?[0-9.]+/)) sco=substr($0,RSTART+6,RLENGTH-6)
    sz="";  if (match($0,/size: [0-9]+/)) sz=substr($0,RSTART+6,RLENGTH-6)
    mid=""; if (match($0,/mail_id: [A-Za-z0-9_+-]+/)) mid=substr($0,RSTART+9,RLENGTH-9)
    mcat="mailflow"; msev=1; mact="pass"
    if (vd ~ /INFECTED/) { mcat="malware"; msev=4; mact="infected" }
    else if (vd ~ /BANNED/) { mcat="banned"; msev=3; mact="banned" }
    else if (vd ~ /SPAM/) { msev=2; mact="spam" }
    else if (vd ~ /Blocked/) { msev=2; mact="blocked" }
    ext=",\"verdict\":\"" jesc(vd) "\",\"sender\":\"" jesc(frm) "\",\"rcpt\":\"" jesc(rcpt) "\",\"score\":\"" sco "\",\"size\":\"" sz "\""
    if (vd ~ /INFECTED/ && match($0,/INFECTED \([^)]+\)/)) ext=ext ",\"virus\":\"" jesc(substr($0,RSTART+10,RLENGTH-11)) "\""
    emit(mcat,mact,msev,ip,rcpt,"amavis",ext,(mid!=""?("mail-" mid):""))
  }
  else if ($0 ~ /amavis\[[0-9]+\].*(av-scanner.*FAILED|virus scanners? failed)/) {       # clamd injoignable -> mail NON scanne
    emit("av_error","error",3,ip,"","clamav","")
  }
}
END{
  if (n>0) printf "{\"ts\":%d,\"host\":\"%s\",\"kind\":\"events\",\"events\":[%s]}\n", now, host, buf > out
  print maxts
}')

# S30 — l'ordre etait DEJA le bon ; le filigrane est MIS EN ATTENTE et ecrit par la publication
# elle-meme. Quand il n'y a aucune ligne a publier, c'est l'enveloppe de config de fin — toujours
# emise — qui l'ecrit : un capteur n'a jamais le geste d'acquitter a sa disposition.
state_stage "$WM" "${newwm:-$last}"
if [ -s "$tmp" ]; then spool_publish_then_ack "$tmp" "mail-$now.json"; else rm -f "$tmp"; fi

# --- CHANTIER whitelists->webui : AUTO-REPORT de config (source=mail category=config) --------------
# Surface PLUME_MAIL_SKIP_IP dans le panneau read-only « Suppressions & whitelists actives ». VISIBILITE
# cote daemon, CONTROLE ici. Dedup par empreinte. collection-reducing (drop des events de l'IP skippee).
cfg_fields=$(printf '{"type":"collection-reducing","collector":"mail","filters":{"skip_ip":"%s","max":"%s"},"note":"ignore les events mail de SKIP_IP (probes internes/self) — postscreen HANGUP deja exclu. collecte reduite"}' \
  "$(json_escape "$SKIPIP")" "$(json_escape "$MAX")")
cfg_dd="cfg-mail-$(printf '%s' "$cfg_fields" | cksum | cut -d' ' -f1)"
spool_write_then_ack "config-mail-$now.json" "$(printf '{"ts":%s,"host":"%s","kind":"events","events":[{"ts":%s,"source":"mail","category":"config","severity":0,"message":"config collecteur mail (filtres de collecte)","dedup":"%s","fields":%s}]}' \
  "$now" "$host" "$now" "$cfg_dd" "$cfg_fields")"
