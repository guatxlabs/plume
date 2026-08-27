#!/bin/sh
# Capteur Plume : état du cluster k8s/k3s via kubectl -> metrics + events (couvre l'angle mort Prometheus).
# pods down/crashloop/OOMKilled, nodes NotReady, deployments dégradés. SANS jq (awk sur --no-headers).
# Requiert kubectl + accès cluster (KUBECONFIG). ROOT / OPT-IN. Skip si kubectl absent.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
# kubectl standalone, sinon `k3s kubectl` (cas k3s : pas de kubectl dans le PATH root), sinon skip.
# PLUME_KUBECTL force la commande (ex: "k3s kubectl" ou "microk8s kubectl").
# --request-timeout : anti-hang si l'API k8s est lente/injoignable (ex: kubectl résiduel hors cluster).
KTMO="${PLUME_KUBECTL_TIMEOUT:-8s}"
if [ -n "${PLUME_KUBECTL:-}" ]; then kc() { $PLUME_KUBECTL --request-timeout="$KTMO" "$@"; }
elif command -v kubectl >/dev/null 2>&1; then kc() { kubectl --request-timeout="$KTMO" "$@"; }
elif command -v k3s >/dev/null 2>&1; then kc() { k3s kubectl --request-timeout="$KTMO" "$@"; }
else plume_unavailable k8s missing-dependency "ni kubectl ni k3s sur cet hote"; fi
plume_init

# S36 — LE CODE DE RETOUR DE `kubectl` N'ETAIT PAS LU. `pods=$(kc get pods … || true)` rend la MEME
# chaine vide qu'un cluster reellement sans pod, et les blocs `END{print c+0}` en tiraient des zeros :
# huit metriques a 0 — dont `kube_nodes_ready`, `kube_nodes_notready` et `kube_deploy_unavailable` —
# publiees precisement quand l'API n'avait RIEN repondu. Un cluster injoignable (kubeconfig perime,
# RBAC retire, API en panne) se lisait donc « aucun noeud NotReady, aucun deploiement degrade », et
# la regle a seuil qui consomme ces series ne pouvait plus lever : elle n'etait pas en retard, elle
# etait STRUCTURELLEMENT INERTE, et rien ne le disait.
# LA FORME EST CELLE DE `S33`, REPRISE ET NON DOUBLEE : la lecture est SEPAREE du decodage pour que
# son statut soit encore lisible (un tube ou un `|| true` interpose y substitue le sien), la serie
# dont la source n'a pas repondu DISPARAIT de l'enveloppe au lieu d'y valoir zero, et l'aveu part par
# le canal d'indisponibilite existant — celui sur lequel une regle livree alerte deja. Les causes
# sont les mots du vocabulaire ferme (`plume_cause_fermee`, memes mots que le demon).
# LE SECOND CAS EST TENU AUSSI, et c'est lui qui compte : un cluster JOIGNABLE et reellement vide
# rend zero, et ce zero est PUBLIE. Sans lui, une version qui n'emettrait plus jamais rien passerait
# le premier temoin sans rien prouver.
lire_kube() {  # <fichier> <detail> <cle...> -- <commande...> : lit, ou declare absentes les cles nommees
  _lk_f=$1; _lk_det=$2; shift 2
  _lk_cles=""
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do _lk_cles="$_lk_cles $1"; shift; done
  [ "${1:-}" = "--" ] && shift
  if "$@" > "$_lk_f" 2>/dev/null; then return 0; fi
  : > "$_lk_f"
  for _lk_c in $_lk_cles; do plume_mesure_absente "$_lk_c" source_illisible "$_lk_det"; done
  return 1
}

f_pods=$(mktemp); f_nodes=$(mktemp); f_deps=$(mktemp)
# `api_joignable` sert plus bas aux ressources OPTIONNELLES (cert-manager, Velero) : un `kubectl get`
# sur une CRD ABSENTE et un `kubectl get` sur une API EN PANNE rendent le meme code de retour, et
# declarer une mesure absente a chaque passage sur un cluster qui n'a simplement pas Velero ferait de
# l'aveu un bruit permanent — donc, a terme, une alerte desarmee. Ce qui les separe est le SUCCES des
# lectures de base : si `get pods` a repondu, l'API est joignable et l'echec dit « pas installe » ;
# sinon, l'incapacite est DEJA avouee ici, une seule fois, pour un seul et meme fait.
api_joignable=1
lire_kube "$f_pods" "kubectl get pods -A : l'API du cluster n'a pas repondu — l'etat des pods (dont CrashLoop/OOMKilled) n'est pas observable ce passage" \
  kube_pods_running kube_pods_pending kube_pods_total kube_restarts_total -- kc get pods -A --no-headers || api_joignable=0
lire_kube "$f_nodes" "kubectl get nodes : l'API du cluster n'a pas repondu — la regle « noeud NotReady » est INERTE tant que c'est le cas" \
  kube_nodes_ready kube_nodes_total kube_nodes_notready -- kc get nodes --no-headers || true
lire_kube "$f_deps" "kubectl get deployments -A : l'API du cluster n'a pas repondu — la regle « deploiement degrade » est INERTE tant que c'est le cas" \
  kube_deploy_unavailable -- kc get deployments -A --no-headers || true

c_running=$(awk '$4=="Running"{c++} END{print c+0}' "$f_pods")
c_pending=$(awk '$4=="Pending"{c++} END{print c+0}' "$f_pods")
c_total=$(awk 'NF{c++} END{print c+0}' "$f_pods")
c_restarts=$(awk '{s+=$5} END{print s+0}' "$f_pods")
n_ready=$(awk '$2=="Ready"{c++} END{print c+0}' "$f_nodes")
n_total=$(awk 'NF{c++} END{print c+0}' "$f_nodes")
d_unavail=$(awk '{split($3,a,"/"); if(NF && a[1]+0 < a[2]+0) c++} END{print c+0}' "$f_deps")

m() { printf '{"name":"%s","value":%s}' "$1" "$2"; }
metrics=""
add_m() {  # ajoute la metrique <nom>=<valeur> SAUF si sa source n'a pas ete lue
  plume_mesure_est_absente "$1" && return 0
  metrics="$metrics${metrics:+,}$(m "$1" "$2")"
}
add_m kube_pods_running "$c_running"
add_m kube_pods_pending "$c_pending"
add_m kube_pods_total "$c_total"
add_m kube_restarts_total "$c_restarts"
add_m kube_nodes_ready "$n_ready"
add_m kube_nodes_total "$n_total"
add_m kube_nodes_notready "$((n_total - n_ready))"
add_m kube_deploy_unavailable "$d_unavail"

ev=$(mktemp)
awk '$4 ~ /CrashLoopBackOff|OOMKilled|Error|Failed|ImagePullBackOff|ErrImagePull|Evicted/ {print "3\t"$1"/"$2" : "$4" (restarts="$5")"}' "$f_pods" >> "$ev"
awk 'NF && $2!="Ready" {print "4\t"$1" : node "$2}' "$f_nodes" >> "$ev"
awk '{split($3,a,"/"); if(NF && a[1]+0 < a[2]+0) print "3\t"$1"/"$2" : deployment dégradé "$3}' "$f_deps" >> "$ev"
rm -f "$f_pods" "$f_nodes" "$f_deps"

# --- compléments (optionnels, skip si absent) : stockage PV%, certs cert-manager, backups Velero ---
# Auto-détection du root local-path : k3s, GuatX (/opt/local-path-provisioner), k8s natif. Override PLUME_K3S_STORAGE.
STORAGE="${PLUME_K3S_STORAGE:-}"
if [ -z "$STORAGE" ]; then
  for c in /var/lib/rancher/k3s/storage /opt/local-path-provisioner /var/lib/kubernetes/storage; do
    [ -d "$c" ] && { STORAGE="$c"; break; }
  done
fi
if [ -n "$STORAGE" ] && [ -d "$STORAGE" ]; then
  # S36 — LE MEME DEFAUT QUE `resources.sh` PORTAIT (S33), RECOPIE ICI : `df … | awk` rend le statut
  # d'`awk`, jamais celui de `df`, et le bloc `END` imprime `0` meme sans une seule ligne d'entree —
  # « 0 % » etait donc publie quand `df` echouait. Le tube est coupe en deux.
  f_df=$(mktemp)
  if df -P "$STORAGE" > "$f_df" 2>/dev/null; then
    sp=$(awk 'END{gsub("%","",$5); if ($5 ~ /^[0-9]+$/) print $5+0}' "$f_df")
    if [ -n "${sp:-}" ]; then add_m kube_storage_pct "$sp"
    else plume_mesure_absente kube_storage_pct forme_inconnue "df -P $STORAGE : aucune occupation exploitable dans la sortie"; fi
  else
    plume_mesure_absente kube_storage_pct "$(plume_cause_lecture "$STORAGE")" "df -P $STORAGE : l'occupation du stockage local-path n'a pas pu etre lue"
  fi
  rm -f "$f_df"
fi
tc=$(mktemp)
if kc get certificates.cert-manager.io -A --no-headers -o custom-columns=N:.metadata.namespace,M:.metadata.name,E:.status.notAfter > "$tc" 2>/dev/null; then
  mind=""
  while read -r cns cnm cexp; do
    [ -z "${cexp:-}" ] && continue
    es=$(date -d "$cexp" +%s 2>/dev/null || echo "")
    [ -z "$es" ] && continue
    d=$(( (es - ts) / 86400 ))
    if [ -z "$mind" ] || [ "$d" -lt "$mind" ]; then mind=$d; fi
    [ "$d" -lt 14 ] && printf '3\t%s/%s : certificat expire dans %sj\n' "$cns" "$cnm" "$d" >> "$ev"
  done < "$tc"
  [ -n "$mind" ] && add_m cert_days_min "$mind"
elif [ "$api_joignable" = 1 ]; then
  : # cert-manager n'est pas installe sur ce cluster : ce n'est pas une lecture ratee (cf. `api_joignable`)
fi
rm -f "$tc"
# --- §A readiness des StatefulSets (couvre mailserver down, Vault down/scellé, sts générique) ---
# `kubectl get statefulset -A` : $1=ns $2=nom $3=ready/desired (ex 1/1). ready<desired => pas prêt.
# S36 — `[ -n "$sts" ]` confondait DEUX faits : « ce cluster n'a aucun statefulset » (un zero REEL,
# qui doit etre publie) et « la lecture a echoue » (aucune mesure, et il faut le dire). La metrique
# disparaissait donc dans les deux cas, et la regle « sts pas pret » etait inerte sans qu'on sache
# lequel des deux etait vrai.
f_sts=$(mktemp)
if kc get statefulset -A --no-headers > "$f_sts" 2>/dev/null; then
  s_notready=$(awk '{split($3,a,"/"); if(NF && a[1]+0 < a[2]+0) c++} END{print c+0}' "$f_sts")
  add_m kube_sts_notready "$s_notready"
  # répliques prêtes d'un sts précis (0 si absent -> déclenche aussi la règle <1)
  sts_ready() { awk -v ns="$1" -v nm="$2" '$1==ns && $2==nm {split($3,a,"/"); print a[1]+0; f=1} END{if(!f) print 0}' "$f_sts"; }
  # INFRA-EN-CONFIG (générique) : apps critiques surveillées nommément via PLUME_WATCH_STS="ns/nom ns/nom".
  # -> métrique kube_sts_ready_<nom> (0 si absent) + event sévérité 4. DÉFAUT VIDE (aucune app en dur) ;
  # chaque déploiement met sa liste (cf deploy/PROFILE.md). Le générique kube_sts_notready reste émis.
  WATCH="${PLUME_WATCH_STS:-}"
  crit=" "
  for w in $WATCH; do
    wns=${w%%/*}; wnm=${w##*/}; [ -n "$wnm" ] || continue
    san=$(printf '%s' "$wnm" | tr -c 'A-Za-z0-9_' '_')
    add_m "kube_sts_ready_$san" "$(sts_ready "$wns" "$wnm")"
    crit="$crit$wns/$wnm "
  done
  # events : chaque sts pas prêt ; les apps de PLUME_WATCH_STS = sévérité 4 (critique), les autres = 3
  awk -v crit="$crit" '{split($3,a,"/"); if(NF && a[1]+0 < a[2]+0){sev=(index(crit," "$1"/"$2" ")>0)?4:3; print sev"\t"$1"/"$2" : statefulset pas pret ("$3")"}}' "$f_sts" >> "$ev"
else
  # `statefulset` est une ressource du CŒUR de l'API (apps/v1), pas une CRD : son echec ne peut pas
  # vouloir dire « pas installe ». C'est donc TOUJOURS une lecture ratee, et elle se dit.
  plume_mesure_absente kube_sts_notready source_illisible "kubectl get statefulset -A : lecture impossible — la regle « statefulset pas pret » est INERTE tant que c'est le cas"
fi
rm -f "$f_sts"

# --- §B LE MAGASIN DE SECRETS LUI-MEME (P9.8-a) ------------------------------------------------
# CE QUI A ETE PAYE EN VRAI : un coffre scelle plusieurs jours a empeche le rafraichissement de
# VINGT-SEPT secrets externes de tous les espaces d'un cluster — emetteur de certificats, fournisseur
# d'identite, tunnel d'entree, pare-feu applicatif — et RIEN ne l'a dit. Deux certificats ont expire.
# L'etat n'a ete decouvert qu'en tapant une commande d'inspection.
# CE QUE CE BLOC OBSERVE, ET POURQUOI CE N'EST PAS `kube_sts_notready`. Ce dernier parle du POD du
# coffre ; il ne dit rien d'un magasin dont le pod tourne mais qui a perdu son jeton, et sa regle est
# semee DESACTIVEE. Ici l'objet est le MAGASIN : la ressource qui declare pouvoir approvisionner.
# UNE SEULE SERIE POUR UNE SEULE CAUSE. Compter les SECRETS bloques rendrait vingt-sept fois le meme
# fait ; ce sont les MAGASINS qui sont comptes. Le demon leve UNE alerte dessus, sans qu'aucune regle
# ait a etre activee (cf. `daemon/src/sonde_du_magasin_de_secrets.rs`, qui cite ces deux noms de serie).
# CE QUI EST PRET, ET CE QUI NE L'EST PAS : la condition `Ready` a la valeur `True`, et RIEN D'AUTRE.
# Un magasin sans condition `Ready` n'est PAS pret — il n'a rien affirme, et convertir ce silence en
# sante est exactement le defaut poursuivi. Le regime transitoire (un magasin cree a l'instant) est
# absorbe cote demon, qui exige l'unanimite des releves d'une heure avant de lever.
# LE CRD EST OPTIONNEL — meme forme que cert-manager et Velero plus haut : un `get` qui echoue sur une
# API JOIGNABLE veut dire « pas installe » (rien n'est dit), sur une API MUETTE il veut dire « je n'ai
# pas pu regarder » (et la mesure est declaree absente). Les deux genres sont lus, un cluster peut
# n'avoir que l'un des deux.
f_ms=$(mktemp)
ms_lus=0
for _ms_kind in clustersecretstores.external-secrets.io secretstores.external-secrets.io; do
  if kc get "$_ms_kind" -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' >> "$f_ms" 2>/dev/null; then
    ms_lus=$((ms_lus + 1))
  fi
done
if [ "$ms_lus" -gt 0 ]; then
  # `NF` garde les lignes vides hors du compte ; une ligne dont le second champ MANQUE (aucune
  # condition `Ready`) a bien NF>=1 et compte comme NON prete. Un cluster reellement sans magasin
  # publie donc un VRAI zero — sans ce cas, une version qui n'emettrait plus jamais rien passerait
  # le temoin d'echec sans rien prouver.
  ms_total=$(awk 'NF{c++} END{print c+0}' "$f_ms")
  ms_nr=$(awk 'NF && $2!="True"{c++} END{print c+0}' "$f_ms")
  add_m secretstore_total "$ms_total"
  add_m secretstore_notready "$ms_nr"
  # L'EVENEMENT NOMME chaque magasin et l'etat qu'il a REELLEMENT publie (ou son absence) : le compte
  # dit qu'il faut agir, le nom dit ou. Severite 4 — une rotation de cles eteinte a l'echelle du
  # cluster est du meme rang qu'un noeud NotReady.
  # `sub(/^\//)` : un magasin de PORTEE CLUSTER n'a pas d'espace de noms, le champ arrive donc vide et
  # le nom se lirait « /vault-backend ». Ce qui est retire est un separateur sans objet, jamais un nom.
  awk 'NF && $2!="True"{n=$1; sub(/^\//,"",n); e=$2; if(e=="") e="(aucune condition Ready)"; print "4\t"n" : magasin de secrets pas pret (Ready="e") — les secrets approvisionnes par ce magasin ne se renouvellent plus"}' "$f_ms" >> "$ev"
elif [ "$api_joignable" = 0 ]; then
  plume_mesure_absente secretstore_notready source_illisible "kubectl get clustersecretstores/secretstores : l'API du cluster n'a pas repondu — impossible de distinguer « aucun magasin de secrets deploye » de « le magasin ne repond plus » ; la rotation des cles n'est PAS observee tant que c'est le cas"
fi
rm -f "$f_ms"

f_vel=$(mktemp)
if kc get backups.velero.io -A --no-headers -o custom-columns=N:.metadata.name,P:.status.phase > "$f_vel" 2>/dev/null; then
  vf=$(awk '$2 ~ /Failed/{c++} END{print c+0}' "$f_vel")
  add_m velero_failed "$vf"
  awk '$2 ~ /Failed/ {print "3\t"$1" : backup Velero "$2}' "$f_vel" >> "$ev"
elif [ "$api_joignable" = 0 ]; then
  # API injoignable : on ne peut pas conclure « Velero n'est pas installe » — c'est exactement la
  # conversion qu'on chasse. La serie rejoint donc l'aveu DEJA en cours (un seul evenement pour un
  # seul fait), au lieu de disparaitre sans un mot. Si l'API repond et que seule cette CRD manque,
  # rien n'est dit : Velero n'est simplement pas deploye ici.
  plume_mesure_absente velero_failed source_illisible "kubectl get backups.velero.io : l'API du cluster n'a pas repondu — impossible de distinguer « Velero absent » de « Velero muet »"
fi
rm -f "$f_vel"

events=""
TAB=$(printf '\t')
while IFS="$TAB" read -r sev msg; do
  [ -z "${msg:-}" ] && continue
  em=$(json_escape "$(printf '%s' "$msg" | cut -c1-300)")
  dd="k8s-$(printf '%s' "$msg" | cksum | cut -d' ' -f1)-$((ts / 3600))"
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"k8s\",\"category\":\"k8s\",\"severity\":$sev,\"message\":\"$em\",\"dedup\":\"$dd\"}"
done < "$ev"
rm -f "$ev"

# S36 — L'AVEU PART EN UNE FOIS, PAR LE CANAL D'INDISPONIBILITE EXISTANT, et il NOMME chaque serie
# non publiee (`plume_mesures_avouer`, cf. lib.sh) : une regle livree alerte deja dessus, donc une
# mesure de cluster perdue leve une alerte au lieu de se lire comme du calme. Aucune metrique nouvelle
# n'est inventee pour porter l'indicateur — ce serait une serie de plus par mesure.
plume_mesures_avouer k8s
# Une enveloppe de metriques VIDE n'a rien a dire : quand l'API n'a rien repondu, ce qui part est
# l'aveu ci-dessus, pas un tableau vide qu'un tableau de bord lirait comme un releve.
if [ -n "$metrics" ]; then
  spool_write "kubestate-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"metrics","data":{"metrics":[%s]}}' "$ts" "$host" "$metrics")"
fi
if [ -n "$events" ]; then
  spool_write "kubeevents-$ts.json" "$(emit_event "$events")"
fi
