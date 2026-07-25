#!/bin/sh
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
[ -n "$LOGS" ] || exit 0
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

ids=$(mktemp); rec=$(mktemp)
trap 'rm -f "$ids" "$rec"' EXIT

# Pass 1 : event-ids (token "audit(EPOCH.ms:SERIAL)") des SYSCALL data NOUVEAUX (epoch > watermark).
grep -h -E 'type=SYSCALL.*key="(plume_data|plume_etc|plume_creds)"' $LOGS 2>/dev/null | awk -v last="$last" '
{ if(!match($0,/audit\([0-9]+\.[0-9]+:[0-9]+\)/)) next; idt=substr($0,RSTART,RLENGTH);
  ep=idt; sub(/audit\(/,"",ep); sub(/\..*/,"",ep); if(ep+0<=last) next; print idt }' | sort -u > "$ids"
[ -s "$ids" ] || exit 0

# Pass 2 : toutes les lignes (SYSCALL + PATH) de ces events uniquement.
grep -h -F -f "$ids" $LOGS 2>/dev/null > "$rec"

umask 027
tmp=$(mktemp "$SPOOL/.da.XXXXXX")
newwm=$(awk -v host="$host" -v now="$ts" -v out="$tmp" -v last="$last" '
function jesc(s){ gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/[\001-\037]/," ",s); return s }   # strip TOUT char de controle (auditd joint les cles multiples par \x1d -> JSON invalide sinon)
function fv(line,name,   re,v){ re=name "=\"[^\"]*\"|" name "=[^ ]+"; if(match(line,re)){ v=substr(line,RSTART,RLENGTH); sub(/^[^=]*=/,"",v); gsub(/"/,"",v); return v } return "" }
function eid(line,   v){ if(match(line,/:[0-9]+\)/)){ return substr(line,RSTART+1,RLENGTH-2) } return "" }
function eep(line,   v){ if(match(line,/audit\([0-9]+/)){ return substr(line,RSTART+6,RLENGTH-6) } return "" }
function uname(a,   u,cmd){ if(a in UC) return UC[a]; u=a; cmd="getent passwd " a " 2>/dev/null | cut -d: -f1"; cmd|getline u; close(cmd); if(u=="")u=a; UC[a]=u; return u }
function act_of(sc,nt){ if(nt=="CREATE")return "modify"; if(nt=="DELETE")return "delete";
  if(sc==90||sc==268)return "modify"; if(sc==92||sc==260||sc==94)return "modify";   # chmod/chown -> modify
  if(sc==82||sc==264||sc==316)return "modify"; if(sc==87||sc==263)return "delete";  # rename/unlink
  if(sc==257||sc==2)return "read"; if(sc==1)return "modify"; return "modify" }      # open->read, write->modify (CIM)
BEGIN{ n=0; buf=""; maxep=last+0 }
/type=SYSCALL/ {
  id=eid($0); if(id=="")next
  SC[id]=1; SCs[id]=fv($0,"syscall"); SCa[id]=fv($0,"auid"); SCc[id]=fv($0,"comm"); SCk[id]=fv($0,"key"); sub(/[\001-\037].*/,"",SCk[id]); SCe[id]=eep($0)   # cle = 1re seulement (auditd joint par \x1d)
  if(SCe[id]+0>maxep)maxep=SCe[id]+0
  next
}
/type=PATH/ {
  id=eid($0); if(!(id in SC)||(id in DONE))next
  nt=fv($0,"nametype"); if(nt=="PARENT")next
  name=fv($0,"name"); if(name==""||name=="(null)")next   # auditd rend name=(null) quand le champ name est absent du record PATH -> path non identifiable : skip sans poser DONE (une PATH ulterieure reelle peut encore servir le meme event)
  DONE[id]=1
  au=SCa[id]; if(au==""||au=="4294967295"||au=="-1")next
  usr=uname(au); sc=SCs[id]+0; key=SCk[id]; act=act_of(sc,nt); sev=(key=="plume_creds")?3:2
  m="dataaccess: " usr " " act " " name " (key=" key ", via " SCc[id] ")"
  if(n>=600)next
  ev="{\"ts\":" now ",\"source\":\"dataaccess\",\"category\":\"data\",\"severity\":" sev ",\"message\":\"" jesc(m) "\",\"dedup\":\"da-" SCe[id] "-" id "\",\"fields\":{\"user\":\"" jesc(usr) "\",\"auid\":\"" au "\",\"action\":\"" act "\",\"path\":\"" jesc(name) "\",\"key\":\"" key "\",\"comm\":\"" jesc(SCc[id]) "\"}}"
  if(n>0)buf=buf","; buf=buf ev; n++
  next
}
END{ if(n>0) printf "{\"ts\":%d,\"host\":\"%s\",\"kind\":\"events\",\"events\":[%s]}\n", now, host, buf > out; print maxep }' "$rec")

if [ -s "$tmp" ]; then chmod 0640 "$tmp"; mv -f "$tmp" "$SPOOL/dataaccess-$ts.json"; else rm -f "$tmp"; fi
printf '%s' "${newwm:-$last}" > "$WM"
