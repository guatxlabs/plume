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
else exit 0; fi
plume_init

pods=$(kc get pods -A --no-headers 2>/dev/null || true)
nodes=$(kc get nodes --no-headers 2>/dev/null || true)
deps=$(kc get deployments -A --no-headers 2>/dev/null || true)

c_running=$(printf '%s\n' "$pods" | awk '$4=="Running"{c++} END{print c+0}')
c_pending=$(printf '%s\n' "$pods" | awk '$4=="Pending"{c++} END{print c+0}')
c_total=$(printf '%s\n' "$pods" | awk 'NF{c++} END{print c+0}')
c_restarts=$(printf '%s\n' "$pods" | awk '{s+=$5} END{print s+0}')
n_ready=$(printf '%s\n' "$nodes" | awk '$2=="Ready"{c++} END{print c+0}')
n_total=$(printf '%s\n' "$nodes" | awk 'NF{c++} END{print c+0}')
d_unavail=$(printf '%s\n' "$deps" | awk '{split($3,a,"/"); if(NF && a[1]+0 < a[2]+0) c++} END{print c+0}')

m() { printf '{"name":"%s","value":%s}' "$1" "$2"; }
metrics="$(m kube_pods_running "$c_running"),$(m kube_pods_pending "$c_pending"),$(m kube_pods_total "$c_total"),$(m kube_restarts_total "$c_restarts"),$(m kube_nodes_ready "$n_ready"),$(m kube_nodes_total "$n_total"),$(m kube_nodes_notready "$((n_total - n_ready))"),$(m kube_deploy_unavailable "$d_unavail")"

ev=$(mktemp)
printf '%s\n' "$pods"  | awk '$4 ~ /CrashLoopBackOff|OOMKilled|Error|Failed|ImagePullBackOff|ErrImagePull|Evicted/ {print "3\t"$1"/"$2" : "$4" (restarts="$5")"}' >> "$ev"
printf '%s\n' "$nodes" | awk 'NF && $2!="Ready" {print "4\t"$1" : node "$2}' >> "$ev"
printf '%s\n' "$deps"  | awk '{split($3,a,"/"); if(NF && a[1]+0 < a[2]+0) print "3\t"$1"/"$2" : deployment dégradé "$3}' >> "$ev"

# --- compléments (optionnels, skip si absent) : stockage PV%, certs cert-manager, backups Velero ---
# Auto-détection du root local-path : k3s, GuatX (/opt/local-path-provisioner), k8s natif. Override PLUME_K3S_STORAGE.
STORAGE="${PLUME_K3S_STORAGE:-}"
if [ -z "$STORAGE" ]; then
  for c in /var/lib/rancher/k3s/storage /opt/local-path-provisioner /var/lib/kubernetes/storage; do
    [ -d "$c" ] && { STORAGE="$c"; break; }
  done
fi
if [ -n "$STORAGE" ] && [ -d "$STORAGE" ]; then
  sp=$(df -P "$STORAGE" 2>/dev/null | awk 'END{gsub("%","",$5); print $5+0}')
  [ -n "${sp:-}" ] && metrics="$metrics,$(m kube_storage_pct "$sp")"
fi
certs=$(kc get certificates.cert-manager.io -A --no-headers -o custom-columns=N:.metadata.namespace,M:.metadata.name,E:.status.notAfter 2>/dev/null || true)
if [ -n "$certs" ]; then
  tc=$(mktemp); printf '%s\n' "$certs" > "$tc"; mind=""
  while read -r cns cnm cexp; do
    [ -z "${cexp:-}" ] && continue
    es=$(date -d "$cexp" +%s 2>/dev/null || echo "")
    [ -z "$es" ] && continue
    d=$(( (es - ts) / 86400 ))
    if [ -z "$mind" ] || [ "$d" -lt "$mind" ]; then mind=$d; fi
    [ "$d" -lt 14 ] && printf '3\t%s/%s : certificat expire dans %sj\n' "$cns" "$cnm" "$d" >> "$ev"
  done < "$tc"; rm -f "$tc"
  [ -n "$mind" ] && metrics="$metrics,$(m cert_days_min "$mind")"
fi
# --- §A readiness des StatefulSets (couvre mailserver down, Vault down/scellé, sts générique) ---
# `kubectl get statefulset -A` : $1=ns $2=nom $3=ready/desired (ex 1/1). ready<desired => pas prêt.
sts=$(kc get statefulset -A --no-headers 2>/dev/null || true)
if [ -n "$sts" ]; then
  s_notready=$(printf '%s\n' "$sts" | awk '{split($3,a,"/"); if(NF && a[1]+0 < a[2]+0) c++} END{print c+0}')
  metrics="$metrics,$(m kube_sts_notready "$s_notready")"
  # répliques prêtes d'un sts précis (0 si absent -> déclenche aussi la règle <1)
  sts_ready() { printf '%s\n' "$sts" | awk -v ns="$1" -v nm="$2" '$1==ns && $2==nm {split($3,a,"/"); print a[1]+0; f=1} END{if(!f) print 0}'; }
  # INFRA-EN-CONFIG (générique) : apps critiques surveillées nommément via PLUME_WATCH_STS="ns/nom ns/nom".
  # -> métrique kube_sts_ready_<nom> (0 si absent) + event sévérité 4. DÉFAUT VIDE (aucune app en dur) ;
  # chaque déploiement met sa liste (cf deploy/PROFILE.md). Le générique kube_sts_notready reste émis.
  WATCH="${PLUME_WATCH_STS:-}"
  crit=" "
  for w in $WATCH; do
    wns=${w%%/*}; wnm=${w##*/}; [ -n "$wnm" ] || continue
    san=$(printf '%s' "$wnm" | tr -c 'A-Za-z0-9_' '_')
    metrics="$metrics,$(m "kube_sts_ready_$san" "$(sts_ready "$wns" "$wnm")")"
    crit="$crit$wns/$wnm "
  done
  # events : chaque sts pas prêt ; les apps de PLUME_WATCH_STS = sévérité 4 (critique), les autres = 3
  printf '%s\n' "$sts" | awk -v crit="$crit" '{split($3,a,"/"); if(NF && a[1]+0 < a[2]+0){sev=(index(crit," "$1"/"$2" ")>0)?4:3; print sev"\t"$1"/"$2" : statefulset pas pret ("$3")"}}' >> "$ev"
fi

vel=$(kc get backups.velero.io -A --no-headers -o custom-columns=N:.metadata.name,P:.status.phase 2>/dev/null || true)
if [ -n "$vel" ]; then
  vf=$(printf '%s\n' "$vel" | awk '$2 ~ /Failed/{c++} END{print c+0}')
  metrics="$metrics,$(m velero_failed "$vf")"
  printf '%s\n' "$vel" | awk '$2 ~ /Failed/ {print "3\t"$1" : backup Velero "$2}' >> "$ev"
fi

events=""
TAB=$(printf '\t')
while IFS="$TAB" read -r sev msg; do
  [ -z "${msg:-}" ] && continue
  em=$(json_escape "$(printf '%s' "$msg" | cut -c1-300)")
  dd="k8s-$(printf '%s' "$msg" | cksum | cut -d' ' -f1)-$((ts / 3600))"
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"k8s\",\"category\":\"k8s\",\"severity\":$sev,\"message\":\"$em\",\"dedup\":\"$dd\"}"
done < "$ev"
rm -f "$ev"

spool_write "kubestate-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"metrics","data":{"metrics":[%s]}}' "$ts" "$host" "$metrics")"
if [ -n "$events" ]; then
  spool_write "kubeevents-$ts.json" "$(emit_event "$events")"
fi
