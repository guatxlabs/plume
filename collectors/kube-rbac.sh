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
# =================================================================================================
# S36 — QUATRE LECTURES DONT LE STATUT PARTAIT DANS LE TUBE, ET UNE REGLE DE SEVERITE 4 QUI EN
# DEPENDAIT ENTIEREMENT. Chaque `kctl get` etait branche directement sur un `awk` : le statut rendu
# etait celui de l'`awk`, jamais celui de la lecture. Une API qui REFUSE la lecture — RBAC du compte
# de service, jeton expire, coupure reseau — rendait alors EXACTEMENT ce que rend un cluster sans
# aucune liaison : rien. L'enveloppe restait vide, `spool_publish_file` n'etait pas appele, et le
# capteur se taisait.
# CE QUE LA SONDE D'EN-TETE N'ATTRAPE PAS : `kctl version` repond sans toucher au RBAC des
# (cluster)rolebindings. Un compte de service autorise a lire la version et rien d'autre passait donc
# les deux gardes du haut, puis lisait zero liaison.
# CE QUE CE SILENCE COUTE : `config.d/rules/catalog/pe-kube-sa-clusteradmin.json` (severite 4, « les
# cles du royaume ») compte les liaisons `role=cluster-admin kind=ServiceAccount`. Son entree tombe
# a zero, la regle ne peut plus tirer, et rien ne le dit. La regle n'est pas en retard : elle est
# STRUCTURELLEMENT INERTE.
# CE QUI EST TENU MAINTENANT : chaque lecture est faite DANS un fichier, son code de retour est lu la
# ou il est encore le sien, et le capteur DIT ce qu'il n'a pas pu lire.
#   les DEUX lectures de liaisons echouent -> il n'y a plus rien a publier : `plume_lecture_echouee`.
#   une seule echoue                        -> il publie l'autre et AVOUE la moitie manquante.
#   la lecture des ROLES echoue             -> les liaisons restent publiees, mais le drapeau de
#                                              risque `secrets-access` ne peut plus etre calcule : un
#                                              role donnant l'acces aux secrets serait publie avec un
#                                              risque VIDE, c'est-a-dire rassurant. On l'avoue.
# La cause se dit dans le vocabulaire ferme de `S32`/`S33` : ici la source repond mais la lecture a
# lache — `source_illisible`. Rien n'est invente pour l'occasion.
# =================================================================================================
umask 027
_rbac_roles=$(mktemp "$STATE/.rbac.roles.XXXXXX")
_rbac_liens=$(mktemp "$STATE/.rbac.liens.XXXXXX")
_rbac_roles_ko=0
_rbac_liens_ko=""
_rbac_liens_n=0
# Roles (cluster + ns) qui DONNENT l'acces aux secrets (rules mentionnant secrets + un verbe de lecture).
kctl get clusterroles -o jsonpath='{range .items[*]}{.metadata.name}={.rules}{"\n"}{end}' \
  >> "$_rbac_roles" 2>/dev/null || _rbac_roles_ko=$((_rbac_roles_ko + 1))
kctl get roles -A -o jsonpath='{range .items[*]}{.metadata.name}={.rules}{"\n"}{end}' \
  >> "$_rbac_roles" 2>/dev/null || _rbac_roles_ko=$((_rbac_roles_ko + 1))
SEC=$(awk -F= '$0 ~ /secrets/ && $0 ~ /get|list|watch|\*/{print $1}' "$_rbac_roles" | sort -u)
rm -f "$_rbac_roles"
kctl get clusterrolebindings -o jsonpath='{range .items[*]}C|{.metadata.name}|{.roleRef.name}|{range .subjects[*]}{.kind}={.name};{end}{"\n"}{end}' \
  >> "$_rbac_liens" 2>/dev/null || { _rbac_liens_ko="$_rbac_liens_ko clusterrolebindings"; _rbac_liens_n=$((_rbac_liens_n + 1)); }
kctl get rolebindings -A -o jsonpath='{range .items[*]}{.metadata.namespace}|{.metadata.name}|{.roleRef.name}|{range .subjects[*]}{.kind}={.name};{end}{"\n"}{end}' \
  >> "$_rbac_liens" 2>/dev/null || { _rbac_liens_ko="$_rbac_liens_ko rolebindings"; _rbac_liens_n=$((_rbac_liens_n + 1)); }
if [ "$_rbac_liens_n" -eq 2 ]; then
  rm -f "$_rbac_liens"
  plume_lecture_echouee kube-rbac source_illisible "aucune liaison RBAC n'a pu etre lue (clusterrolebindings ET rolebindings) : l'API repond a \`version\` mais refuse ou perd ces lectures. AUCUNE attribution de droits n'est observee ce passage — l'absence de liaison cluster-admin ne peut PAS en etre conclue."
fi
# UN SEUL AVEU PAR PASSAGE, ET C'EST UNE CONTRAINTE MESUREE, PAS UN GOUT : `plume_report_availability`
# nomme son enveloppe `config-availability-<source>-<ts>.json`. Deux aveux emis dans la MEME seconde
# pour la MEME source ecrivent donc le MEME fichier, et le second efface le premier. Les motifs sont
# accumules puis dits en une fois.
_rbac_manque=""
[ -n "$_rbac_liens_ko" ] && _rbac_manque="liaisons non lues :$_rbac_liens_ko (les attributions de cette portee ne sont pas observees ce passage)"
if [ "$_rbac_roles_ko" -gt 0 ]; then
  _rbac_manque="$_rbac_manque${_rbac_manque:+ ; }$_rbac_roles_ko lecture(s) de roles en echec : le drapeau de risque secrets-access ne peut PAS etre calcule ce passage, un role donnant l'acces aux secrets serait publie avec un risque VIDE"
fi
if [ -n "$_rbac_manque" ]; then
  plume_lecture_partielle kube-rbac source_illisible "lecture RBAC PARTIELLE — $_rbac_manque"
fi
tmp=$(mktemp "$SPOOL/.rbac.XXXXXX")
awk -v ts="$ts" -v host="$host" -v out="$tmp" -v sec="$SEC" '
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
END{ if(n>0) printf "{\"ts\":%d,\"host\":\"%s\",\"kind\":\"events\",\"events\":[%s]}\n", ts, host, buf > out }' "$_rbac_liens"
rm -f "$_rbac_liens"
if [ -s "$tmp" ]; then spool_publish_file "$tmp" "kube-rbac-$ts.json"; else rm -f "$tmp"; fi
