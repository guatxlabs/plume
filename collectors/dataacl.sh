#!/bin/sh
# plume-source: dataacl
# plume-emits: fields=flags,group,mode,owner,path,risk,type
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
#
# P10.32-k — UNE CARTE VIDE PARCE QUE RIEN N'EST REGARDÉ SE DIT. Avant, aucun chemin existant -> sortie
# muette : « aucune permission à signaler » et « je ne regarde rien » étaient le même silence. Désormais :
#   · AUCUN chemin existant -> aveu `unavailable/missing-source` qui nomme la cause, la liste lue et la
#     variable à poser (les défauts visent un nœud k3s : sur un hôte natif ou dans un conteneur, la variable
#     non posée ne trouve souvent rien) ;
#   · un chemin PRÉSENT mais que ce capteur ne peut pas parcourir (droits, `ProtectHome`, montage) -> aveu
#     `missing-source` qui le nomme, SANS sortir : son entrée de tête reste cartographiée comme avant, son
#     contenu ne l'est pas. La sonde est un vrai `find` (pas `test -r`, qui répond « oui » à root sans
#     regarder les capacités) et ne voit que la TÊTE du chemin : un sous-répertoire illisible plus bas n'est
#     pas avoué ;
#   · des chemins ABSENTS à côté d'au moins un chemin présent ne sont PAS avoués : la liste par défaut couvre
#     plusieurs volumes dont tous n'existent pas sur chaque nœud, l'avouer à chaque passage serait un bruit
#     permanent. La collecte des chemins présents est inchangée.
set --
_acl_illisibles=""
for p in $PATHS; do
  [ -e "$p" ] || continue
  set -- "$@" "$p"
  find "$p" -maxdepth 1 -printf '%m\n' >/dev/null 2>&1 || _acl_illisibles="$_acl_illisibles $p"
done
if [ "$#" -eq 0 ]; then
  rm -f "$tmp"
  plume_unavailable dataacl missing-source "aucun chemin de PLUME_ACL_PATHS n'existe sur cet hote ($PATHS ; non posee, ce sont les defauts d'un noeud k3s). Aucune permission n'est cartographiee : une carte vide ne dit PAS que les droits sont sains. Poser PLUME_ACL_PATHS (chemins sensibles separes par des espaces, glob admis)."
fi
if [ -n "$_acl_illisibles" ]; then
  plume_report_availability dataacl unavailable missing-source "chemin(s) de PLUME_ACL_PATHS presents mais illisibles par ce capteur (droits, ProtectHome, montage) :$_acl_illisibles. Seule leur entree de tete est cartographiee, pas leur contenu ; les autres chemins le sont." 2 2>/dev/null || true
fi
find "$@" -maxdepth "$DEPTH" \( -type f -o -type d \) -printf '%p\t%u\t%g\t%m\t%y\n' 2>/dev/null \
  | head -n "$MAX" \
  | awk -v ts="$ts" -v host="$host" -v out="$tmp" "$_PLUME_AWK_ECHAPPEMENT_JSON"'
# jesc() : l’échappement JSON de collectors/lib.sh (_PLUME_AWK_ECHAPPEMENT_JSON, P10.23-e), placé en tête de ce programme.
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
