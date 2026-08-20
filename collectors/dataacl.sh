#!/bin/sh
# Capteur Plume (PLUGIN, OPT-IN) : CARTE D'ACCES aux donnees (Varonis brique b) -> events source=dataacl.
# QUI PEUT acceder a QUOI + PROPRIETAIRE : snapshot des permissions (owner/group/mode) des dossiers
# sensibles + flags risque (world-readable/writable, SUID/SGID). Dedup (chemin+mode+owner+group) ->
# ne RE-emet que sur CHANGEMENT de perm/owner (= signal Varonis). N'emet que les REPERTOIRES (la
# structure d'acces) + les fichiers RISQUES (pas chaque fichier 600 du maildir). ROOT, lecture seule.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
# Chemins sensibles a cartographier (joyaux). Glob autorise (PVC a UUID). Surchargeable via env.
PATHS="${PLUME_ACL_PATHS:-/etc/rancher/k3s /etc/ssl/private /var/lib/rancher/k3s/server/tls /opt/local-path-provisioner/*vault* /opt/local-path-provisioner/*plume-data* /opt/local-path-provisioner/*mail-data*}"
DEPTH="${PLUME_ACL_DEPTH:-4}"
MAX="${PLUME_ACL_MAX:-3000}"
plume_init
umask 027
tmp=$(mktemp "$SPOOL/.acl.XXXXXX")
# find -printf : 1 passe, pas de stat par fichier. %p chemin %u owner %g group %m mode-octal %y type.
# Les chemins DOIVENT précéder l'expression find -> on les met dans "$@" (pas via xargs, qui les
# appendrait APRÈS -maxdepth/-printf et casserait find). shellcheck disable=SC2086 (glob voulu).
set --
for p in $PATHS; do [ -e "$p" ] && set -- "$@" "$p"; done
[ "$#" -gt 0 ] || { rm -f "$tmp"; plume_exit_nodata; }
find "$@" -maxdepth "$DEPTH" \( -type f -o -type d \) -printf '%p\t%u\t%g\t%m\t%y\n' 2>/dev/null \
  | head -n "$MAX" \
  | awk -v ts="$ts" -v host="$host" -v out="$tmp" '
function jesc(s){ gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/[\001-\037]/," ",s); return s }
BEGIN{ FS="\t"; n=0; buf="" }
{
  path=$1; owner=$2; grp=$3; mode=$4; typ=$5
  if(path=="") next
  L=length(mode)
  oth=substr(mode,L,1)+0
  spec=(L>=4)?substr(mode,L-3,1)+0:0
  wr=(oth>=4)?1:0; ww=(int(oth/2)%2==1)?1:0
  suid=(int(spec/4)%2==1)?1:0; sgid=(int(spec/2)%2==1)?1:0
  risk=""
  if(ww) risk="world-writable"; else if(wr) risk="world-readable"
  if(suid) risk=(risk==""?"suid":risk" suid"); if(sgid) risk=(risk==""?"sgid":risk" sgid")
  if(typ!="d" && risk=="") next                       # garde les REPERTOIRES + les fichiers risques
  sev=1; if(wr)sev=3; if(ww||suid||sgid)sev=4
  flags=(wr?"o+r ":"") (ww?"o+w ":"") (suid?"suid ":"") (sgid?"sgid ":""); sub(/ $/,"",flags)
  msg="acl: " path " " owner ":" grp " " mode (risk!=""?" ["risk"]":"")
  dd="acl-" path "-" mode "-" owner "-" grp
  ev="{\"ts\":" ts ",\"source\":\"dataacl\",\"category\":\"data\",\"severity\":" sev ",\"message\":\"" jesc(msg) "\",\"dedup\":\"" jesc(dd) "\",\"fields\":{\"path\":\"" jesc(path) "\",\"owner\":\"" jesc(owner) "\",\"group\":\"" jesc(grp) "\",\"mode\":\"" mode "\",\"type\":\"" typ "\",\"flags\":\"" flags "\",\"risk\":\"" jesc(risk) "\"}}"
  if(n>=2000)next
  if(n>0)buf=buf","; buf=buf ev; n++
}
END{ if(n>0) printf "{\"ts\":%d,\"host\":\"%s\",\"kind\":\"events\",\"events\":[%s]}\n", ts, host, buf > out }'
if [ -s "$tmp" ]; then spool_publish_file "$tmp" "dataacl-$ts.json"; else rm -f "$tmp"; fi
