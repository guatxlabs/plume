#!/bin/sh
# Capteur Plume (PLUGIN, OPT-IN) : access-logs Traefik (JSON) -> events source=web.
# Vue "trafic web" facon FortiGate : qui (src_ip reelle via Cf-Connecting-Ip / forwarded) accede a
# quel host/chemin, methode, statut, octets, duree, routeur, User-Agent. Groupable en GXQL
# ( | stats count by status / by host / by src_ip / by path ). Pre-requis : Traefik en accesslog JSON
# (deja le cas ici : --accesslog=true --accesslog.format=json). Lecture seule, AUCUNE action.
# Mode-aware : PLUME_WEB_SRC=k3s (kubectl logs) | file (chemin local). OPT-IN (non actif par defaut).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
WEBSRC="${PLUME_WEB_SRC:-k3s}"
WEB_NS="${PLUME_WEB_NS:-kube-system}"
WEB_SEL="${PLUME_WEB_SELECTOR:-app.kubernetes.io/name=traefik}"
WEB_LOG="${PLUME_WEB_LOG:-/var/log/traefik/access.log}"     # mode file
SKIP_HOST="${PLUME_WEB_SKIP_HOST:-}"                          # hosts a ignorer si <500 (liste |). ex: ingest.example.com (self-ingest)
SKIP_PATH="${PLUME_WEB_SKIP_PATH:-}"                          # DEBRUIT: prefixes de path a ignorer si <500 (liste |). ex: /v1/sys/health|/v1/sys/seal-status (poll Vault)
SKIP_ROUTER="${PLUME_WEB_SKIP_ROUTER:-}"                      # DEBRUIT: routers a ignorer si <500 (sous-chaine, liste |). ex: -agent-mtls (self-traffic mTLS de l agent)
MAX="${PLUME_WEB_MAX:-10000}"                                 # lignes lues par passage
WM="$STATE_DIR/web.watermark"
last=$(cat "$WM" 2>/dev/null || echo 0)
now=$(date +%s)
since=$((now - last + 10)); [ "$last" -eq 0 ] && since=300       # 1re fois : 5 min en arriere
[ "$since" -gt 86400 ] && since=86400

read_log() {
  case "$WEBSRC" in
    k3s)
      KC="kubectl"; command -v kubectl >/dev/null 2>&1 || KC="k3s kubectl"
      command -v "${KC%% *}" >/dev/null 2>&1 || return 1
      $KC -n "$WEB_NS" logs -l "$WEB_SEL" --since="${since}s" --tail="$MAX" --max-log-requests=5 2>/dev/null
      ;;
    file) [ -r "$WEB_LOG" ] || return 1; tail -n "$MAX" "$WEB_LOG" 2>/dev/null ;;
    *) return 1 ;;
  esac
}

raw=$(read_log) || plume_unavailable web missing-source "source de log web illisible (PLUME_WEB_SRC=$WEBSRC) : ni fichier lisible, ni pod joignable"
[ -n "$raw" ] || plume_exit_nodata
umask 027
tmp=$(mktemp "$SPOOL/.web.XXXXXX")
newwm=$(printf '%s\n' "$raw" | TZ=UTC awk -v last="$last" -v host="$host" -v now="$now" -v out="$tmp" -v skiphost="$SKIP_HOST" -v skippath="$SKIP_PATH" -v skiprouter="$SKIP_ROUTER" '
function jesc(s){ gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/\r/,"",s); gsub(/\t/," ",s); return s }
function sval(name,   re,v){ re="\"" name "\":\"[^\"]*\""; if(match($0,re)){ v=substr($0,RSTART,RLENGTH); sub(/^"[^"]*":"/,"",v); sub(/"$/,"",v); return v } return "" }
function nval(name,   re,v){ re="\"" name "\":-?[0-9]+"; if(match($0,re)){ v=substr($0,RSTART,RLENGTH); sub(/^"[^"]*":/,"",v); return v } return "" }
BEGIN{ n=0; buf=""; maxts=last+0 }
{
  if ($0 !~ /"DownstreamStatus":/) next                          # garde uniquement les lignes access-log
  if (n>=9000) next
  su=sval("StartUTC"); if(su=="") next
  d=substr(su,1,19); gsub(/[-T:]/," ",d); et=mktime(d); if(et<0) next
  if (et <= last) next
  if (et > maxts) maxts=et
  hostr=sval("RequestHost")
  ip=sval("request_Cf-Connecting-Ip"); if(ip=="") ip=sval("ClientHost")
  sc="external"; if(ip ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|::1|fc|fd|fe80)/) sc="internal"
  path=sval("RequestPath"); method=sval("RequestMethod"); proto=sval("RequestProtocol")
  router=sval("RouterName"); sub(/@kubernetescrd$/,"",router); sub(/-[0-9a-f]+$/,"",router)
  ua=sval("request_User-Agent")
  status=nval("DownstreamStatus"); bytes=nval("DownstreamContentSize"); durns=nval("Duration")
  durms=0; if(durns!="") durms=int(durns/1000000)
  # DEBRUITAGE : self-traffic + polling infra ecartes UNIQUEMENT si <500 -> on GARDE tout 5xx
  # (vrai incident applicatif) et tout le trafic externe. host=exact, router=sous-chaine, path=prefixe.
  if(status+0<500){ skip=0
    if(skiphost!=""){ nH=split(skiphost,AH,"|"); for(iH=1;iH<=nH;iH++) if(AH[iH]!="" && hostr==AH[iH]) skip=1 }
    if(!skip && skiprouter!=""){ nR=split(skiprouter,AR,"|"); for(iR=1;iR<=nR;iR++) if(AR[iR]!="" && index(router,AR[iR])>0) skip=1 }
    if(!skip && skippath!=""){ nP=split(skippath,AP,"|"); for(iP=1;iP<=nP;iP++) if(AP[iP]!="" && index(path,AP[iP])==1) skip=1 }
    if(skip) next
  }
  sev=1; if(status+0>=400) sev=2; if(status+0>=500) sev=3
  s=status+0; act=(s<400)?"success":"failure"; if(s==401||s==403||s==429) act="blocked"   # action normalise (CIM)
  m="web " method " " hostr path " -> " status
  ev="{\"ts\":" et ",\"source\":\"web\",\"category\":\"web\",\"severity\":" sev ",\"src_ip\":\"" jesc(ip) "\",\"message\":\"" jesc(m) "\",\"dedup\":\"web-" jesc(su) "\",\"fields\":{\"src_ip\":\"" jesc(ip) "\",\"vhost\":\"" jesc(hostr) "\",\"scope\":\"" sc "\",\"path\":\"" jesc(path) "\",\"method\":\"" method "\",\"status\":\"" status "\",\"action\":\"" act "\",\"bytes\":\"" bytes "\",\"dur_ms\":\"" durms "\",\"proto\":\"" proto "\",\"router\":\"" jesc(router) "\",\"ua\":\"" jesc(ua) "\",\"dir\":\"inbound\"}}"
  if(n>0) buf=buf ","; buf=buf ev; n++
}
END{ if(n>0) printf "{\"ts\":%d,\"host\":\"%s\",\"kind\":\"events\",\"events\":[%s]}\n", now, host, buf > out; print maxts }')

if [ -s "$tmp" ]; then spool_publish_file "$tmp" "web-$now.json"; else rm -f "$tmp"; fi
state_write "$WM" "${newwm:-$last}"

# --- CHANTIER whitelists->webui : AUTO-REPORT de config (source=web category=config) --------------
# Surface les filtres de CE collecteur dans le panneau read-only « Suppressions & whitelists actives ».
# Le daemon garde la VISIBILITE ; le CONTROLE reste ICI (frontiere hote). Dedup par empreinte de config
# -> ne re-emet un event QUE si la config change (pas de spam). type=collection-reducing (drop <500).
cfg_fields=$(printf '{"type":"collection-reducing","collector":"web","filters":{"skip_host":"%s","skip_path":"%s","skip_router":"%s","max_lines":"%s","src":"%s"},"note":"drops <500 matching host/path/router — collecte reduite, controle a la frontiere hote"}' \
  "$(json_escape "$SKIP_HOST")" "$(json_escape "$SKIP_PATH")" "$(json_escape "$SKIP_ROUTER")" "$(json_escape "$MAX")" "$(json_escape "$WEBSRC")")
cfg_dd="cfg-web-$(printf '%s' "$cfg_fields" | cksum | cut -d' ' -f1)"
spool_write "config-web-$now.json" "$(printf '{"ts":%s,"host":"%s","kind":"events","events":[{"ts":%s,"source":"web","category":"config","severity":0,"message":"config collecteur web (filtres de collecte)","dedup":"%s","fields":%s}]}' \
  "$now" "$host" "$now" "$cfg_dd" "$cfg_fields")"
