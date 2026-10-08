#!/bin/sh
# plume-source: dataaccess
# plume-emits: fields=action,alive,auid,comm,key,path,user
# Capteur Plume (PLUGIN, OPT-IN) : ACCES AUX DONNEES facon Varonis -> events source=dataaccess.
# QUI (auid -> user) a fait QUELLE action (open/write/delete/chmod/chown) sur QUEL fichier sensible,
# d'apres les watches auditd plume_data/plume_etc/plume_creds (cf systemd/plume-audit.rules, filtre auid>=1000
# = humain). Parse le RAW /var/log/audit/audit.log : ausearch --format text ne rend PAS les acces
# fichier et ausearch -k est casse sur certains hotes -> on lit le brut. ROOT. Lecture seule.
# FIREHOSE-IMMUNE : on grep d'abord les seules lignes SYSCALL porteuses d'une cle data (rares), puis
# on grep les event-ids correspondants pour recuperer leurs lignes PATH (le nom de fichier). La churn
# exec_tracking (des milliers/j) n'entre jamais dans le traitement.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
LOG="${PLUME_AUDIT_LOG:-/var/log/audit/audit.log}"
# Lit le log COURANT + le rotated .1 : avec le firehose exec_tracking, audit.log rote vite et des
# records soc_* peuvent basculer dans .1 avant notre passage. Le watermark (epoch) evite tout retraitement.
LOGS=""; for f in "$LOG.1" "$LOG"; do [ -r "$f" ] && LOGS="$LOGS $f"; done
[ -n "$LOGS" ] || plume_unavailable dataaccess missing-config "aucun log de donnees configure (PLUME_DATAACCESS_LOGS)"
plume_init
WM="$STATE_DIR/dataaccess.epoch"
last=$(cat "$WM" 2>/dev/null || echo 0)

# DEAD-MAN'S-SWITCH (battement de santé AUTONOME) : ce collecteur sort tôt (pas de log lisible, aucun record
# data nouveau) et n'écrit son enveloppe events que via awk quand $tmp est non vide -> son silence serait
# indistinguable d'un collecteur mort. On écrit donc un petit .json kind:events health À CHAQUE run, AVANT
# toute sortie précoce et INDÉPENDAMMENT du parsing. PAS de dedup -> chaque battement S'INSÈRE -> MAX(ts)
# avance -> heartbeat vivant. Silence > 25 min = alerte MUET (collecteur CONTINU dataaccess-health, main.rs).
spool_write "dataaccess-health-$ts.json" \
  "$(emit_event "$(heartbeat dataaccess 'dataaccess santé: collecteur actif' '{"alive":1}')")" nl

ids=$(mktemp); rec=$(mktemp); syscalls=$(mktemp)
trap 'rm -f "$ids" "$rec" "$syscalls"' EXIT

# Pass 1 : event-ids (token "audit(EPOCH.ms:SERIAL)") des SYSCALL data NOUVEAUX (epoch > watermark).
# S36 — LE VERDICT DU TUBE ETAIT CELUI DE `sort`, qui reussit sur une entree vide : des journaux
# d'audit devenus illisibles rendaient une liste vide, indiscernable de « aucun acces nouveau ».
# `grep` distingue les deux — 1 = aucune correspondance (cas normal), >=2 = erreur de lecture — a
# condition de lire SON code de retour, donc de le sortir du tube.
_ga_rc=0
# shellcheck disable=SC2086  ($LOGS = liste de chemins a eclater ; expansion voulue)
grep -h -E 'type=SYSCALL.*key="(plume_data|plume_etc|plume_creds)"' $LOGS > "$syscalls" 2>/dev/null || _ga_rc=$?
[ "$_ga_rc" -le 1 ] || plume_lecture_echouee dataaccess source_illisible "journaux d'audit illisibles ($LOGS) : aucun acces aux donnees n'a pu etre relu, le filigrane n'avance pas"
awk -v last="$last" '
{ if(!match($0,/audit\([0-9]+\.[0-9]+:[0-9]+\)/)) next; idt=substr($0,RSTART,RLENGTH);
  ep=idt; sub(/audit\(/,"",ep); sub(/\..*/,"",ep); if(ep+0<=last) next; print idt }' "$syscalls" | sort -u > "$ids"
[ -s "$ids" ] || plume_exit_nodata

# Pass 2 : toutes les lignes (SYSCALL + PATH) de ces events uniquement.
grep -h -F -f "$ids" $LOGS 2>/dev/null > "$rec"

umask 027
tmp=$(mktemp "$SPOOL/.da.XXXXXX")
newwm=$(awk -v host="$host" -v now="$ts" -v out="$tmp" -v last="$last" "$_PLUME_AWK_ECHAPPEMENT_JSON"'
# jesc() : l’échappement JSON de collectors/lib.sh (_PLUME_AWK_ECHAPPEMENT_JSON, P10.23-e), placé en tête de ce programme.
function fraw(line,name,   re,v){ re=name "=\"[^\"]*\"|" name "=[^ ]+"; if(match(line,re)){ v=substr(line,RSTART,RLENGTH); sub(/^[^=]*=/,"",v); return v } return "" }
function fv(line,name,   v){ v=fraw(line,name); gsub(/"/,"",v); return v }
# P10.23-z — auditd ecrit EN HEXADECIMAL, SANS guillemets, un nom (name=, comm=) qui porte un espace, un
# guillemet, un controle ou un octet hors ASCII : `name=2F6574632F612062` pour « /etc/a b ». Publie tel quel,
# ce chemin echappait a toute regle ou panneau ecrit sur le texte (evasion triviale : un espace dans le nom).
# jval() rend le FRAGMENT JSON d une valeur brute de fraw() : entre guillemets -> jesc() comme avant ; nue, de
# longueur paire et toute en [0-9A-F] -> decodee par jhex(). HYPOTHESE : le noyau met entre guillemets tout nom
# qu il n encode pas, donc une valeur NUE et hexadecimale est un encodage ; une autre valeur nue (`(null)`, longueur
# impaire) passe par jesc() inchangee.
# jhex() decode sans strtonum (absent de mawk) par la table HX, et n emet QUE de l ASCII : UTF-8 valide -> \uXXXX
# (paire de substitution au-dela de U+FFFF), octet non UTF-8 -> \ufffd, controle C0 et octet NUL -> espace (la
# regle de jesc), guillemet et antislash echappes. Aucun octet brut : l enveloppe reste du JSON/UTF-8 valide
# sous gawk (locale UTF-8 ou non) comme sous mawk.
function jval(v){ if(v ~ /^([0-9A-F][0-9A-F])+$/) return jhex(v); gsub(/"/,"",v); return jesc(v) }
function jhex(h,   n,i,k,b,c,d,o,need,cp,lo,hi,ok){
  n=0; for(i=1;i<length(h);i+=2) b[++n]=HX[substr(h,i,1)]*16+HX[substr(h,i+1,1)]
  o=""; i=1
  while(i<=n){ c=b[i]
    if(c<32){ o=o " "; i++; continue }
    if(c<128){ if(c==34) o=o "\\\""; else if(c==92) o=o "\\\\"; else o=o sprintf("%c",c); i++; continue }
    need=0
    if(c>=194&&c<=223){ need=1; cp=c-192; lo=128; hi=191 }
    else if(c>=224&&c<=239){ need=2; cp=c-224; lo=(c==224)?160:128; hi=(c==237)?159:191 }
    else if(c>=240&&c<=244){ need=3; cp=c-240; lo=(c==240)?144:128; hi=(c==244)?143:191 }
    ok=(need>0 && i+need<=n)
    for(k=1;ok&&k<=need;k++){ d=b[i+k]; if(d<((k==1)?lo:128)||d>((k==1)?hi:191)) ok=0; else cp=cp*64+d-128 }
    if(!ok){ o=o "\\ufffd"; i++; continue }
    if(cp>65535){ cp-=65536; o=o sprintf("\\u%04x\\u%04x",55296+int(cp/1024),56320+cp%1024) } else o=o sprintf("\\u%04x",cp)
    i+=need+1 }
  return o }
function eid(line,   v){ if(match(line,/:[0-9]+\)/)){ return substr(line,RSTART+1,RLENGTH-2) } return "" }
function eep(line,   v){ if(match(line,/audit\([0-9]+/)){ return substr(line,RSTART+6,RLENGTH-6) } return "" }
function uname(a,   u,cmd){ if(a in UC) return UC[a]; u=a; cmd="getent passwd " a " 2>/dev/null | cut -d: -f1"; cmd|getline u; close(cmd); if(u=="")u=a; UC[a]=u; return u }
function act_of(sc,nt){ if(nt=="CREATE")return "modify"; if(nt=="DELETE")return "delete";
  if(sc==90||sc==268)return "modify"; if(sc==92||sc==260||sc==94)return "modify";   # chmod/chown -> modify
  if(sc==82||sc==264||sc==316)return "modify"; if(sc==87||sc==263)return "delete";  # rename/unlink
  if(sc==257||sc==2)return "read"; if(sc==1)return "modify"; return "modify" }      # open->read, write->modify (CIM)
BEGIN{ n=0; buf=""; maxep=last+0; for(i=1;i<=16;i++) HX[substr("0123456789ABCDEF",i,1)]=i-1 }
/type=SYSCALL/ {
  id=eid($0); if(id=="")next
  SC[id]=1; SCs[id]=fv($0,"syscall"); SCa[id]=fv($0,"auid"); SCc[id]=jval(fraw($0,"comm"));   # fragment JSON (jval : P10.23-z)
  SCk[id]=fv($0,"key"); sub(/[\001-\037].*/,"",SCk[id]); SCe[id]=eep($0)   # cle = 1re seulement (le noyau joint les cles par 0x01, AUDIT_KEY_SEPARATOR)
  if(SCe[id]+0>maxep)maxep=SCe[id]+0
  next
}
/type=PATH/ {
  id=eid($0); if(!(id in SC)||(id in DONE))next
  nt=fv($0,"nametype"); if(nt=="PARENT")next
  name=fv($0,"name"); if(name==""||name=="(null)")next   # auditd rend name=(null) quand le champ name est absent du record PATH -> path non identifiable : skip sans poser DONE (une PATH ulterieure reelle peut encore servir le meme event)
  DONE[id]=1
  au=SCa[id]; if(au==""||au=="4294967295"||au=="-1")next
  if(n>=600)next   # plafond AVANT le decodage : un PATH ecarte ne paie pas la boucle octet par octet de jhex()
  jname=jval(fraw($0,"name"))   # fragment JSON, nom hexadecimal decode (P10.23-z)
  usr=uname(au); sc=SCs[id]+0; key=SCk[id]; act=act_of(sc,nt); sev=(key=="plume_creds")?3:2
  # message en fragments : jesc() agit caractere par caractere, donc jesc(a) jesc(b) = jesc(a b) octet pour octet.
  m=jesc("dataaccess: " usr " " act " ") jname jesc(" (key=" key ", via ") SCc[id] jesc(")")
  ev="{\"ts\":" now ",\"source\":\"dataaccess\",\"category\":\"data\",\"severity\":" sev ",\"message\":\"" m "\",\"dedup\":\"da-" SCe[id] "-" id "\",\"fields\":{\"user\":\"" jesc(usr) "\",\"auid\":\"" au "\",\"action\":\"" act "\",\"path\":\"" jname "\",\"key\":\"" key "\",\"comm\":\"" SCc[id] "\"}}"
  if(n>0)buf=buf","; buf=buf ev; n++
  next
}
END{ if(n>0) printf "{\"ts\":%d,\"host\":\"%s\",\"kind\":\"events\",\"events\":[%s]}\n", now, host, buf > out; print maxep }' "$rec")

# S30 — l'ordre etait DEJA le bon, mais l'ecriture du filigrane etait BRUTE (fenetre d'ecriture
# dechiree apres coupure, que S27 avait fermee ailleurs via `state_write`). Mise en attente : elle
# passe par la voie unique, apres la publication.
state_stage "$WM" "${newwm:-$last}"
if [ -s "$tmp" ]; then spool_publish_then_ack "$tmp" "dataaccess-$ts.json"; else rm -f "$tmp"; plume_exit_nodata; fi
