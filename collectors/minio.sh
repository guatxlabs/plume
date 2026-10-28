#!/bin/sh
# plume-source: minio
# plume-emits: fields=access,buckets,kind,objects,policy,risk,status,subject,versions
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
# P10.32-k — UN ALIAS POSE SANS `mc` NE BASCULE PLUS EN SILENCE VERS kubectl. PLUME_MINIO_ALIAS dit le mode
# hote natif ; `mc` absent, le capteur cherchait un pod MinIO a la place et, sans lui, conseillait de poser
# l'alias deja pose. La cause est la dependance manquante, et elle se dit.
if [ -n "$ALIAS" ]; then
  command -v mc >/dev/null 2>&1 || plume_unavailable minio missing-dependency "PLUME_MINIO_ALIAS=$ALIAS est pose (mode hote natif) mais \`mc\` est introuvable dans le PATH du capteur : ni utilisateur ni bucket ne peuvent etre lus"
  A="$ALIAS"; mc(){ command mc "$@"; }
else
  KC="kubectl"; command -v kubectl >/dev/null 2>&1 || KC="k3s kubectl"
  command -v "${KC%% *}" >/dev/null 2>&1 || plume_unavailable minio missing-dependency "ni kubectl ni k3s sur cet hote"
  # P10.32-k — « PAS DE POD MINIO » N'EST PAS « RIEN DE NEUF ». Le capteur sortait en silence quand la
  # cible manquait ; deux causes distinctes se disent maintenant, chacune par son mot : l'API ne répond pas
  # (`unreachable`), ou elle répond sans pod MinIO en marche dans l'espace de noms (`subsystem-absent`).
  if ! pods=$($KC -n "$NS" get pod -l app.kubernetes.io/name=minio \
        -o jsonpath='{range .items[*]}{.metadata.name} {.status.phase}{"\n"}{end}' 2>/dev/null); then
    plume_unavailable minio unreachable "lecture des pods MinIO impossible ($KC -n $NS get pod) : API Kubernetes injoignable ou droits insuffisants"
  fi
  POD=$(printf '%s\n' "$pods" | awk '$2=="Running"{print $1; exit}')
  [ -n "${POD:-}" ] || plume_unavailable minio subsystem-absent "aucun pod MinIO en marche dans l'espace de noms $NS (selecteur app.kubernetes.io/name=minio) : ni utilisateur ni bucket ne peuvent etre lus. En hote natif, posez PLUME_MINIO_ALIAS."
  A="local"; mc(){ $KC -n "$NS" exec "$POD" -- mc "$@"; }
fi

# P10.32-k — UNE LECTURE `mc` QUI ECHOUE N'EST PAS UN STOCKAGE VIDE. `|| true` remplacait le code de retour par
# un succes : alias faux, identifiants revoques, serveur arrete ou `exec` refuse rendaient trois sorties vides, et
# `plume_exit_nodata` les rangeait en « rien de neuf ». Les trois echecs se disent `unreachable` ; un echec
# partiel part par `plume_lecture_partielle` et le capteur publie ce qu'il a lu (inventaire seul compris). Ce capteur ne tient aucun
# marqueur : rien n'avance, la lecture est simplement refaite au passage suivant.
_mko=""
USERS=$(mc --json admin user list "$A" 2>/dev/null) || { USERS=""; _mko="$_mko utilisateurs(admin user list)"; }
BKTS=$(mc --json ls "$A" 2>/dev/null) || { BKTS=""; _mko="$_mko buckets(ls)"; }
INFO=$(mc --json admin info "$A" 2>/dev/null) || { INFO=""; _mko="$_mko inventaire(admin info)"; }
# Etat anonyme (public/prive) par bucket -> une ligne "<bucket>\t<texte mc anonymous>". P10.32-k — une politique
# ILLISIBLE n'est pas « inconnue » : publiee `access: unknown`, elle changeait la cle de deduplication du bucket sans
# rien dire. Le bucket est alors tu ce passage, et le compte des politiques non lues part dans l'aveu partiel.
blist=$(printf '%s\n' "$BKTS" | grep -oE '"key":"[^"]+"' | sed 's/"key":"//; s/"//; s#/$##')
ANON=""; _anon_ko=0
for b in $blist; do
  [ -z "$b" ] && continue
  if a=$(mc anonymous get "$A/$b" 2>/dev/null); then
    ANON="$ANON$b	$a
"
  else
    _anon_ko=$((_anon_ko + 1))
  fi
done
[ "$_anon_ko" -gt 0 ] && _mko="$_mko politique_anonyme(anonymous get : $_anon_ko bucket(s))"
case "$_mko" in
  *utilisateurs*buckets*inventaire*)
    plume_unavailable minio unreachable "les trois lectures \`mc\` ont echoue sur l'alias $A (alias ou identifiants faux, droits insuffisants, serveur MinIO arrete) : ni utilisateur ni bucket ne sont lus, l'absence de changement ne peut PAS en etre conclue" ;;
  ?*)
    plume_lecture_partielle minio source_illisible "lecture(s) \`mc\` en echec sur l'alias $A :$_mko. Ce qu'elles portent n'est PAS observe ce passage." ;;
esac
# Rien a publier seulement si TOUT a ete lu et rien rendu : une lecture partielle publie ce qu'elle a lu, l'inventaire
# (`admin info`) compris quand utilisateurs et buckets ont echoue.
[ -z "$USERS$BKTS" ] && [ -z "$_mko" ] && plume_exit_nodata

umask 027
tmp=$(mktemp "$SPOOL/.minio.XXXXXX")
{ printf '==USERS==\n%s\n==ANON==\n%s\n==INFO==\n%s\n' "$USERS" "$ANON" "$INFO"; } \
| awk -v ts="$ts" -v host="$host" -v out="$tmp" "$_PLUME_AWK_ECHAPPEMENT_JSON""$_PLUME_AWK_DECODAGE_JSON"'
# jesc() : l’échappement JSON de collectors/lib.sh (_PLUME_AWK_ECHAPPEMENT_JSON, P10.23-e), placé en tête de ce programme.
# jval() : une chaine est rendue DECODEE par jstr() de collectors/lib.sh (P10.23-x : elle etait coupee a son premier
# guillemet echappe et gardee encodee) ; un nombre ou un booleen, tel quel.
function jval(s,k,  r){ r=s
  if(index(r,"\""k"\":\"")) return jstr(r,k)
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
