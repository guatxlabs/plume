#!/bin/sh
# plume-source: mail
# plume-emits: fields=rcpt,score,sender,service,size,verdict,virus
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

# S36 — meme distinction, dite avec le mot de la famille (cf. `web.sh`) : le routage etait deja le
# bon, la primitive y ajoute le rejet des marqueurs en attente.
raw=$(read_log) || plume_lecture_echouee mail source_illisible "source de log mail illisible (PLUME_MAIL_SRC=$MAILSRC) : ni fichier lisible, ni pod joignable"
[ -n "$raw" ] || plume_exit_nodata

now=$(date +%s)
umask 027
tmp=$(mktemp "$SPOOL/.mail.XXXXXX")
newwm=$(printf '%s\n' "$raw" | TZ=UTC awk -v last="$last" -v host="$host" -v now="$now" -v out="$tmp" -v skipip="$SKIPIP" "$_PLUME_AWK_ECHAPPEMENT_JSON"'
# jesc() : l’échappement JSON de collectors/lib.sh (_PLUME_AWK_ECHAPPEMENT_JSON, P10.23-e), placé en tête de ce programme.
# P10.22-s — UNE ADRESSE, ET RIEN D’AUTRE. IPv4 pointée ou IPv6 (témoin :
# collectors/mail-adresses-et-texte-du-client.corpus), validée ENTIÈRE : une valeur qui n’en est pas une
# rend "" et la ligne n’est pas émise, plutôt qu’un préfixe (`rip=2001:db8::5` rendait `2001`). La forme
# mappée `::ffff:a.b.c.d` est rendue en IPv4 : Postfix la replie déjà à la source
# (`sane_sockaddr_to_hostaddr`), le démon la replie pour ses bans et sa liste d’épargne
# (`ssrf_norm_ip`), et la veille compare du TEXTE — sans ce repli, une même machine porterait deux clés
# et ne rencontrerait jamais un indicateur IPv4. Aucun intervalle `{n,m}` dans ces motifs : mawk
# 1.3.4 20200120 les lit comme des caractères.
# CANONICALISATION HORS DÉMON (`P4.7-j`) — divergence avec `ssrf_norm_ip`, nommée : seule la forme
# mappée ÉCRITE PAR inet_ntop (`::ffff:a.b.c.d`) est repliée ; `::ffff:c000:228`, la forme non
# compressée et une IPv6 en majuscules ressortent telles qu’écrites, là où le démon les replie ou
# les récrit. Dovecot et Postfix n’écrivent aucune de ces trois formes. Comme le démon : zéro de tête
# d’un octet IPv4 refusé, zone `%…` refusée.
function est_ipv4(s,   o, i){
  if (s !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 0
  split(s, o, ".")
  for (i = 1; i <= 4; i++) if (length(o[i]) > 3 || o[i] + 0 > 255 || o[i] ~ /^0[0-9]/) return 0
  return 1
}
function est_ipv6(s,   t, doubles, g, n, i, groupes){
  if (s !~ /^[0-9A-Fa-f:.]+$/ || index(s, ":") == 0 || index(s, ":::") > 0) return 0
  if ((s ~ /^:/ && s !~ /^::/) || (s ~ /:$/ && s !~ /::$/)) return 0
  t = s; doubles = gsub(/::/, "", t); if (doubles > 1) return 0
  n = split(s, g, ":"); groupes = 0
  for (i = 1; i <= n; i++) {
    if (g[i] == "") continue
    if (i == n && index(g[i], ".") > 0) { if (!est_ipv4(g[i])) return 0; groupes += 2; continue }
    if (g[i] !~ /^[0-9A-Fa-f]+$/ || length(g[i]) > 4) return 0
    groupes++
  }
  return doubles ? (groupes <= 7) : (groupes == 8)
}
function adresse(s){
  if (est_ipv4(s)) return s
  if (!est_ipv6(s)) return ""
  if (s ~ /^::ffff:[0-9.]+$/) return substr(s, 8)
  return s
}
# Dovecot : le DERNIER champ `rip=` du message. Ceux qui le précèdent (`user=<…>`) sont fournis par le
# client ; ceux qui le suivent (`lip=`, `mpid=`, sécurité, `session=`) sont écrits par le serveur.
function rip_de_dovecot(m,   v){
  v = ""
  while (match(m, /[,:] rip=[^, ]*/)) { v = substr(m, RSTART + 6, RLENGTH - 6); m = substr(m, RSTART + RLENGTH) }
  return v
}
# Postfix, postscreen, amavis : le PREMIER crochet du message qui ressemble à une adresse — Postfix écrit
# le client `nom[adresse]` (ou `[adresse]:port`) AVANT tout texte venu du client (`helo=<…>`, texte de
# pré-salutation, commande non SMTP). S’il ne se valide pas, aucune adresse : on ne va JAMAIS chercher
# plus loin, là où le client écrit. Le PID (`smtpd[1457]`) n’a ni point ni deux-points, le port est
# hors du crochet ; `[IPv6:…]` n’est pas une forme de journal (Postfix la réserve aux en-têtes
# `Received:`) : c’est celle qu’un CLIENT écrit dans son HELO, elle ne se valide donc pas.
function crochet_du_client(m){
  if (!match(m, /\[[0-9A-Za-z:.%_-]*[.:][0-9A-Za-z:.%_-]*\]/)) return ""
  return substr(m, RSTART + 1, RLENGTH - 2)
}
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
  # P10.22-v — L’ÉTIQUETTE EST CELLE DE L’EN-TÊTE SYSLOG, PAS UN MOT DE LA LIGNE. Le journal est
  # `<horodatage> <hôte> <étiquette>: <message>` ; `dovecot:` (ou `postfix/…/smtpd[pid]:`) n’est lu
  # qu’en TROISIÈME champ. Cherchée partout, l’étiquette `dovecot:` se trouvait aussi dans un `helo=<…>`
  # ou un texte de pré-salutation Postfix : n’importe quel client fabriquait une connexion RÉUSSIE, à
  # l’utilisateur et à l’adresse de son choix. `user=<…>` n’est lu que dans un message Dovecot : dans
  # une ligne Postfix, il ne peut venir que du client.
  dvc=""; if (match($0,/^[^ ]+ [^ ]+ dovecot(\[[0-9]+\])?: /)) dvc=substr($0,RSTART+RLENGTH)
  psd=""; if (match($0,/^[^ ]+ [^ ]+ postfix(\/[A-Za-z0-9_.-]+)*\/smtpd\[[0-9]+\]: /)) psd=substr($0,RSTART+RLENGTH)
  pss=""; if (match($0,/^[^ ]+ [^ ]+ postfix(\/[A-Za-z0-9_.-]+)*\/postscreen\[[0-9]+\]: /)) pss=substr($0,RSTART+RLENGTH)
  msg=""; if (match($0,/^[^ ]+ [^ ]+ [^ ]+ /)) msg=substr($0,RSTART+RLENGTH)
  ip=""; if (dvc != "") ip=adresse(rip_de_dovecot(dvc)); else ip=adresse(crochet_du_client(msg))
  usr=""; if (dvc != "" && match(dvc,/user=<[^>]*>/)) usr=substr(dvc,RSTART+6,RLENGTH-7)
  svc="postfix"; if (dvc != "") svc="dovecot"; else if (pss != "") svc="postscreen"
  # P10.22-j — connexions Dovecot, 2.3 ET 2.4 (témoin : collectors/mail-connexions-dovecot.corpus).
  # Succès : 2.3 `Login:`, 2.4 `Logged in:` (émis par login-common, donc aussi par managesieve-login).
  # Lu en TÊTE du message Dovecot, et nulle part ailleurs : le `user=<…>` qui suit est fourni par le
  # client. Le deux-points fait partie du motif : 2.4 écrit `Login aborted:` pour une connexion qui
  # N A PAS abouti, et `Login` en est le préfixe.
  # Échec, ANCRÉ COMME LE SUCCÈS (P10.22-v) — trois formes et aucune autre :
  #   Dovecot, en tête du message et AVANT le premier champ (`[^<=]*` : ni `user=<` ni `rip=` encore) :
  #     `(auth failed, …)` (2.3 et 2.4) ; `Aborted login` (2.3 : `Disconnected: Aborted login by
  #     logging out`) ; `Login aborted: Logged out`, son pendant 2.4. Une fermeture sans tentative
  #     (`Login aborted: Connection closed (no auth attempts…)`) ne compte pas, comme en 2.3.
  #   Postfix, serveur smtpd seulement : `warning: nom[adresse]: SASL <mécanisme> authentication failed`.
  # Cherché partout, le bras comptait en échec d’authentification un `helo=<auth failed>`, un expéditeur,
  # une commande HTTP envoyée au port de soumission, un texte de pré-salutation — et l’échec de NOTRE
  # relais sortant, imputé à l’adresse du relais.
  if (dvc ~ /^(imap|pop3|submission|managesieve)-login: (Login|Logged in): /) emit("auth","success",1,ip,usr,svc)
  else if (dvc ~ /^(imap|pop3|submission|managesieve)-login: [^<=]*\(auth failed[,)]/ ||
           dvc ~ /^(imap|pop3|submission|managesieve)-login: (Disconnected: )?Aborted login[ (]/ ||
           dvc ~ /^(imap|pop3|submission|managesieve)-login: Login aborted: Logged out / ||
           psd ~ /^warning: [A-Za-z0-9._-]+\[[0-9A-Fa-f:.]+\](:[0-9]+)?: SASL [A-Za-z0-9_-]+ authentication failed/) emit("auth","failure",2,ip,usr,svc)
  # P10.23-f — POSTSCREEN ET REJET, ANCRÉS COMME L’AUTHENTIFICATION : lus en TÊTE du message, sous
  # l’étiquette du démon qui les écrit, et nulle part ailleurs. Cherchés partout, un `helo=<postscreen
  # PREGREET>` faisait d’un rejet smtpd un blocage postscreen (service compris), une sonde HTTP portant
  # `NOQUEUE: reject` au port de soumission devenait un rejet, un texte du client dans un message
  # Dovecot devenait un blocage — et le `helo` du rejet de postscreen lui-même en choisissait la
  # catégorie. Formes lues dans les sources Postfix (`postscreen.c`, `postscreen_early.c`,
  # `postscreen_smtpd.c`, `smtpd_check.c`) ; HANGUP, PASS, CONNECT et ALLOWLISTED restent hors des
  # blocages (bruit des sondes du nœud, parité avec l’ancien motif).
  # P10.23-g — la liste de refus s’écrit `BLACKLISTED` ou `DENYLISTED` selon `respectful_logging`, dont
  # le défaut vaut `yes` dès `compatibility_level` 3.6 : les deux formes sont lues.
  # Rejet : `NOQUEUE: reject: <étape> …` (smtpd et postscreen ; l’étape est écrite par le serveur, et
  # peut porter une espace : `DATA content`), `<file>: reject: RCPT from …` (smtpd, quand la file
  # existe), `…: milter-reject: RCPT from …` (smtpd) — les formes que l’ancien motif lisait, et elles
  # seules.
  else if (pss ~ /^(PREGREET [0-9]+ after |DNSBL rank [0-9]+ for |(BLACK|DENY)LISTED \[|COMMAND (PIPELINING|TIME LIMIT|COUNT LIMIT) from |BARE NEWLINE from |NON-SMTP COMMAND from )/) emit("postscreen","blocked",2,ip,usr,"postscreen")
  else if (pss ~ /^NOQUEUE: reject: / || psd ~ /^NOQUEUE: reject: / || psd ~ /^[0-9A-Za-z]+: (milter-)?reject: RCPT from /) emit("reject","blocked",2,ip,usr,svc)
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
