#!/bin/sh
# Capteur Plume (PLUGIN, OPT-IN) : RBAC Kubernetes (Varonis brique c) -> events source=kube-rbac.
# QUI PEUT acceder a QUOI dans le cluster (les secrets k8s = donnees sensibles) : map des
# (Cluster)RoleBindings -> sujet -> role -> scope, + flags risque (cluster-admin, roles donnant
# l'acces aux SECRETS, admin/edit). Dedup (binding+role+sujet) -> ne re-emet que sur CHANGEMENT
# d'attribution (= signal Varonis : un droit a change). kubectl LECTURE SEULE. Mode k3s/natif.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
command -v kubectl >/dev/null 2>&1 || command -v k3s >/dev/null 2>&1 || plume_unavailable kube-rbac missing-dependency "ni kubectl ni k3s sur cet hote"
kctl version --request-timeout=5s >/dev/null 2>&1 || plume_unavailable kube-rbac unreachable "kubectl present mais l API du cluster ne repond pas (kubeconfig / reseau / RBAC)"
plume_init
# Roles (cluster + ns) qui DONNENT l'acces aux secrets (rules mentionnant secrets + un verbe de lecture).
SEC=$( { kctl get clusterroles -o jsonpath='{range .items[*]}{.metadata.name}={.rules}{"\n"}{end}' 2>/dev/null
         kctl get roles -A -o jsonpath='{range .items[*]}{.metadata.name}={.rules}{"\n"}{end}' 2>/dev/null; } \
      | awk -F= '$0 ~ /secrets/ && $0 ~ /get|list|watch|\*/{print $1}' | sort -u )
umask 027
tmp=$(mktemp "$SPOOL/.rbac.XXXXXX")
{
  kctl get clusterrolebindings -o jsonpath='{range .items[*]}C|{.metadata.name}|{.roleRef.name}|{range .subjects[*]}{.kind}={.name};{end}{"\n"}{end}' 2>/dev/null
  kctl get rolebindings -A -o jsonpath='{range .items[*]}{.metadata.namespace}|{.metadata.name}|{.roleRef.name}|{range .subjects[*]}{.kind}={.name};{end}{"\n"}{end}' 2>/dev/null
} | awk -v ts="$ts" -v host="$host" -v out="$tmp" -v sec="$SEC" '
function jesc(s){ gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/[\001-\037]/," ",s); return s }
BEGIN{ FS="|"; n=0; buf=""; m=split(sec,A,"\n"); for(i=1;i<=m;i++) if(A[i]!="") SECR[A[i]]=1 }
{
  scope=($1=="C")?"cluster":"ns"; ns=($1=="C")?"":$1; binding=$2; role=$3; subs=$4
  if(role=="")next
  risk=""; sev=1
  if(role=="cluster-admin"){risk="cluster-admin"; sev=4}
  else if(role in SECR){risk="secrets-access"; sev=3}
  else if(role=="admin"||role=="edit"){risk="rw"; sev=2}
  k=split(subs,S,";")
  for(j=1;j<=k;j++){
    s=S[j]; if(s=="")continue
    ei=index(s,"="); if(ei<1)continue
    kind=substr(s,1,ei-1); name=substr(s,ei+1); if(name=="")continue
    msg="rbac: " kind " " name " -> " role " (" scope (ns!=""?"/" ns:"") ")" (risk!=""?" ["risk"]":"")
    dd="rbac-" binding "-" role "-" s
    ev="{\"ts\":" ts ",\"source\":\"kube-rbac\",\"category\":\"data\",\"severity\":" sev ",\"message\":\"" jesc(msg) "\",\"dedup\":\"" jesc(dd) "\",\"fields\":{\"subject\":\"" jesc(name) "\",\"kind\":\"" jesc(kind) "\",\"role\":\"" jesc(role) "\",\"scope\":\"" scope "\",\"ns\":\"" jesc(ns) "\",\"binding\":\"" jesc(binding) "\",\"risk\":\"" jesc(risk) "\"}}"
    if(n>=3000)break
    if(n>0)buf=buf","; buf=buf ev; n++
  }
}
END{ if(n>0) printf "{\"ts\":%d,\"host\":\"%s\",\"kind\":\"events\",\"events\":[%s]}\n", ts, host, buf > out }'
if [ -s "$tmp" ]; then chmod 0640 "$tmp"; mv -f "$tmp" "$SPOOL/kube-rbac-$ts.json"; else rm -f "$tmp"; fi
