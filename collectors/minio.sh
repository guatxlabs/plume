#!/bin/sh
# Capteur Plume (PLUGIN, OPT-IN) : gouvernance d'acces MinIO / S3 (Varonis brique c) -> source=minio.
# QUI a acces a QUEL stockage objet, et QUELS buckets sont exposes : map utilisateurs->policy +
# etat public/prive des buckets + flags risque (policy admin/rw, bucket PUBLIC). Dedup
# (utilisateur+policy / bucket+acces) -> ne re-emet que sur CHANGEMENT (= signal Varonis : un droit
# ou une exposition a change). LECTURE SEULE (mc admin/anonymous get). Mode k3s (kubectl exec dans
# le pod minio, alias 'local' preconfigure) ou natif (mc sur l'hote via $PLUME_MINIO_ALIAS).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
NS="${PLUME_MINIO_NS:-minio}"
ALIAS="${PLUME_MINIO_ALIAS:-}"        # natif : nom d'alias mc deja configure sur l'hote
plume_init

# --- Resoudre comment lancer `mc` : hote natif (alias fourni) sinon kubectl exec dans le pod ---
if [ -n "$ALIAS" ] && command -v mc >/dev/null 2>&1; then
  A="$ALIAS"; mc(){ command mc "$@"; }
else
  KC="kubectl"; command -v kubectl >/dev/null 2>&1 || KC="k3s kubectl"
  command -v "${KC%% *}" >/dev/null 2>&1 || plume_unavailable minio missing-dependency "ni kubectl ni k3s sur cet hote"
  POD=$($KC -n "$NS" get pod -l app.kubernetes.io/name=minio \
        -o jsonpath='{range .items[*]}{.metadata.name} {.status.phase}{"\n"}{end}' 2>/dev/null \
        | awk '$2=="Running"{print $1; exit}')
  [ -z "${POD:-}" ] && plume_exit_nodata
  A="local"; mc(){ $KC -n "$NS" exec "$POD" -- mc "$@"; }
fi

USERS=$(mc --json admin user list "$A" 2>/dev/null || true)
BKTS=$(mc --json ls "$A" 2>/dev/null || true)
INFO=$(mc --json admin info "$A" 2>/dev/null || true)
[ -z "$USERS$BKTS" ] && plume_exit_nodata

# Etat anonyme (public/prive) par bucket -> une ligne "<bucket>\t<texte mc anonymous>".
blist=$(printf '%s\n' "$BKTS" | grep -oE '"key":"[^"]+"' | sed 's/"key":"//; s/"//; s#/$##')
ANON=""
for b in $blist; do
  [ -z "$b" ] && continue
  a=$(mc anonymous get "$A/$b" 2>/dev/null || true)
  ANON="$ANON$b	$a
"
done

umask 027
tmp=$(mktemp "$SPOOL/.minio.XXXXXX")
{ printf '==USERS==\n%s\n==ANON==\n%s\n==INFO==\n%s\n' "$USERS" "$ANON" "$INFO"; } \
| awk -v ts="$ts" -v host="$host" -v out="$tmp" '
function jesc(s){ gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/[\001-\037]/," ",s); return s }
function jval(s,k,  r){ r=s
  if(match(r,"\""k"\":\"")){ r=substr(r,RSTART+length(k)+4); sub(/".*/,"",r); return r }
  if(match(r,"\""k"\":")){ r=substr(r,RSTART+length(k)+3); sub(/[,}].*/,"",r); return r }
  return "" }
function num(s,k,  r){ r=s; if(match(r,"\""k"\":\\{\"count\":[0-9]+")){ r=substr(r,RSTART,RLENGTH); sub(/.*"count":/,"",r); return r } return "" }
function add(ev){ if(n>=3000)return; if(n>0)buf=buf","; buf=buf ev; n++ }
BEGIN{ n=0; buf="" }
/^==USERS==/{sec="u";next} /^==ANON==/{sec="a";next} /^==INFO==/{sec="i";next}
sec=="u" && /"accessKey"/ {
  ak=jval($0,"accessKey"); pol=jval($0,"policyName"); st=jval($0,"userStatus")
  if(ak=="")next
  risk=""; sev=1
  if(pol=="consoleAdmin"){risk="admin"; sev=4}
  else if(pol ~ /readwrite|writeonly|[-_]rw$|rw$/){risk="rw"; sev=2}
  else if(pol=="diagnostics"){risk="diag"; sev=2}
  else if(pol ~ /readonly|[-_]ro$|ro$/){risk="ro"; sev=1}
  msg="minio user " ak " -> " (pol==""?"(aucune)":pol) (risk!=""?" ["risk"]":"")
  add("{\"ts\":" ts ",\"source\":\"minio\",\"category\":\"data\",\"severity\":" sev ",\"message\":\"" jesc(msg) "\",\"dedup\":\"minio-user-" jesc(ak) "-" jesc(pol) "\",\"fields\":{\"subject\":\"" jesc(ak) "\",\"kind\":\"user\",\"policy\":\"" jesc(pol) "\",\"status\":\"" jesc(st) "\",\"risk\":\"" jesc(risk) "\"}}")
  next
}
sec=="a" && NF>=1 {
  b=$1; access="unknown"
  if(match($0,/`[a-z]+`/)) access=substr($0,RSTART+1,RLENGTH-2)
  if(b=="")next
  risk=""; sev=1
  if(access!="private" && access!="none" && access!="unknown" && access!=""){risk="public"; sev=4}
  msg="minio bucket " b ": " access (risk!=""?" [PUBLIC]":"")
  add("{\"ts\":" ts ",\"source\":\"minio\",\"category\":\"data\",\"severity\":" sev ",\"message\":\"" jesc(msg) "\",\"dedup\":\"minio-bucket-" jesc(b) "-" jesc(access) "\",\"fields\":{\"subject\":\"" jesc(b) "\",\"kind\":\"bucket\",\"access\":\"" jesc(access) "\",\"risk\":\"" jesc(risk) "\"}}")
  next
}
sec=="i" && /"buckets"/ {
  bc=num($0,"buckets"); oc=num($0,"objects"); vc=num($0,"versions")
  if(bc==""&&oc=="")next
  msg="minio store: " bc " buckets / " oc " objets / " vc " versions"
  add("{\"ts\":" ts ",\"source\":\"minio\",\"category\":\"data\",\"severity\":1,\"message\":\"" jesc(msg) "\",\"dedup\":\"minio-store-" bc "-" oc "-" vc "\",\"fields\":{\"subject\":\"minio\",\"kind\":\"store\",\"buckets\":\"" bc "\",\"objects\":\"" oc "\",\"versions\":\"" vc "\"}}")
  next
}
END{ if(n>0) printf "{\"ts\":%d,\"host\":\"%s\",\"kind\":\"events\",\"events\":[%s]}\n", ts, host, buf > out }'
if [ -s "$tmp" ]; then spool_publish_file "$tmp" "minio-$ts.json"; else rm -f "$tmp"; fi
