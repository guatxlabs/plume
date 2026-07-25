#!/bin/sh
# Capteur Plume : INGÈRE les alertes CrowdSec (cscli) -> events source=crowdsec.
# On NE refait PAS la détection/le ban : CrowdSec reste l'IPS, le SOC corrèle/notifie/investigue.
# Requiert cscli + jq. ROOT. Optionnel (skip si absents). Dédup par id d'alerte (idempotent).
#
# DEAD-MAN'S-SWITCH : à CHAQUE run (timer 5 min) on ship AUSSI un battement de SANTÉ
# (source=crowdsec category=health) MÊME quand 0 alerte -> Plume distingue « 0 attaque (normal) » de
# « moteur CrowdSec mort/cassé ». Le SILENCE de ce battement (>~25 min) lève une alerte MUET (collecteur
# CONTINU crowdsec-health, cf. main.rs) ; scenarios_broken>0 lève une alerte de détection (T1562.001).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
NS="${PLUME_CROWDSEC_NS:-crowdsec}"; LAPI="${PLUME_CROWDSEC_LAPI:-crowdsec-lapi}"
AGENT="${PLUME_CROWDSEC_AGENT:-crowdsec-agent}"   # le HUB (scénarios) vit sur l'AGENT, pas la LAPI
# Commande cscli selon le MODE de déploiement : PLUME_CSCLI explicite > cscli sur l'hôte > k3s (exec dans
# le pod LAPI : en k3s CrowdSec tourne en pod, pas de cscli sur l'hôte) > skip. # shellcheck disable=SC2086
if [ -n "${PLUME_CSCLI:-}" ]; then cscli_cmd() { $PLUME_CSCLI "$@"; }
elif command -v cscli >/dev/null 2>&1; then cscli_cmd() { cscli "$@"; }
elif command -v k3s >/dev/null 2>&1 && k3s kubectl -n "$NS" get deploy "$LAPI" >/dev/null 2>&1; then cscli_cmd() { k3s kubectl -n "$NS" exec "deploy/$LAPI" -- cscli "$@"; }
elif command -v kubectl >/dev/null 2>&1 && kubectl -n "$NS" get deploy "$LAPI" >/dev/null 2>&1; then cscli_cmd() { kubectl -n "$NS" exec "deploy/$LAPI" -- cscli "$@"; }
else exit 0; fi
# Résolution de l'AGENT (hub/scénarios + LOG) pour le battement de SANTÉ. L'agent CrowdSec est un DaemonSet
# (ds/) — PAS un Deployment — donc on sonde ds/ puis deploy/ (jamais un nom de pod figé). host/explicite
# (cscli local) voient le hub local ; sinon on exec/log dans la ressource agent kube. # shellcheck disable=SC2086
KUBE=""
if command -v k3s >/dev/null 2>&1; then KUBE="k3s kubectl"
elif command -v kubectl >/dev/null 2>&1; then KUBE="kubectl"; fi
AGENT_REF=""
if [ -n "$KUBE" ]; then
  if $KUBE -n "$NS" get ds "$AGENT" >/dev/null 2>&1; then AGENT_REF="ds/$AGENT"
  elif $KUBE -n "$NS" get deploy "$AGENT" >/dev/null 2>&1; then AGENT_REF="deploy/$AGENT"; fi
fi
ALOG_C="${PLUME_CROWDSEC_AGENT_CONTAINER:-crowdsec-agent}"   # conteneur agent (exec/logs ciblés)
if [ -n "${PLUME_CSCLI:-}" ]; then cscli_agent() { $PLUME_CSCLI "$@"; }
elif command -v cscli >/dev/null 2>&1; then cscli_agent() { cscli "$@"; }
elif [ -n "$AGENT_REF" ]; then cscli_agent() { $KUBE -n "$NS" exec "$AGENT_REF" -c "$ALOG_C" -- cscli "$@"; }
else cscli_agent() { cscli_cmd "$@"; }   # repli : pas d'agent kube distinct -> la LAPI porte le hub
fi
# Logs de l'AGENT pour DÉTECTER le deadlock moteur. DÉCISIF (validé crowdsec v1.7.8) : un scénario qui ÉCHOUE
# à charger ses data-files reste status:"enabled" / tainted:null dans `hub list` -> le hub NE voit PAS la
# panne. Seul signal fiable = le LOG agent ('not found in expr library' / 'unable to init data for file').
# Lisible seulement en k3s/kubectl (ds|deploy/$AGENT) ; sinon false -> scenarios_broken=-1 (inconnu, la règle
# la regle de sante ne fire pas sur transitoire). NB FENÊTRE --since=15m : capte les erreurs de (re)chargement récentes
# (startup/SIGHUP/évaluation) ; backstop pour une cécité durable = l'alerte MUET du capteur CONTINU
# crowdsec-health (silence du battement) si l'agent meurt vraiment.
if [ -n "$AGENT_REF" ]; then agent_logs() { $KUBE -n "$NS" logs "$AGENT_REF" -c "$ALOG_C" --since=15m; }
else agent_logs() { false; }   # host/explicite : pas de chemin log pod -> scenarios_broken=-1 (inconnu)
fi
command -v jq >/dev/null 2>&1 || exit 0
plume_init

# ── 1) ALERTES (chemin existant) : ne SORT PLUS si vide -> le battement de santé ci-dessous part TOUJOURS.
raw=$(cscli_cmd alerts list --limit 0 -o json 2>/dev/null || echo '')
lapi_ok=0; [ -n "$raw" ] && lapi_ok=1     # `alerts list` a répondu -> LAPI joignable
[ -z "$raw" ] && raw='[]'
events=""
n=0
tmpf=$(mktemp)
if printf '%s' "$raw" | jq -r '.[] | [ (.id|tostring), (.source.value // "-"), (.scenario // "-") ] | @tsv' > "$tmpf" 2>/dev/null; then
  TAB=$(printf '\t')
  while IFS="$TAB" read -r id ip scen; do
    [ -z "$id" ] && continue
    n=$((n + 1)); [ "$n" -gt 200 ] && break
    m=$(json_escape "$(printf 'CrowdSec: %s (src %s)' "$scen" "$ip")")
    ipf=""
    case "$ip" in *.*|*:*) ipf=",\"src_ip\":\"$ip\"" ;; esac
    events="$events${events:+,}{\"ts\":$ts,\"source\":\"crowdsec\",\"category\":\"network\",\"severity\":3,\"message\":\"$m\",\"dedup\":\"crowdsec-$id\"$ipf,\"fields\":{\"action\":\"blocked\"}}"
  done < "$tmpf"
fi
rm -f "$tmpf"

# ── 2) SANTÉ (dead-man's-switch) : interroge l'AGENT (hub + LOG) + la LAPI, ship UN battement à CHAQUE run
# (même 0 alerte). scenarios_loaded = `cscli hub list -o json | .scenarios | length` (INFORMATIF, ~59 sain ;
# PAS un signal de panne : le hub reste « enabled » même scénario cassé). scenarios_broken = ERREURS DE
# CHARGEMENT lues dans le LOG agent (seul signal fiable, cf. ci-dessus). agent_ready = hub interrogeable ;
# lapi_ok = `alerts list` a répondu ci-dessus ; last_alert_age_s informatif.
agent_ready=0; scen_loaded=-1; scen_broken=-1
hub=$(cscli_agent hub list -o json 2>/dev/null || echo '')
if [ -n "$hub" ]; then
  agent_ready=1
  scen_loaded=$(printf '%s' "$hub" | jq -r '(.scenarios // []) | length' 2>/dev/null || echo -1)
fi
# scenarios_broken = nb de lignes d'erreur de chargement dans le log agent (15 min). -1 si log inaccessible
# (modes host/explicite, RBAC, réseau) -> inconnu -> la règle de santé (CAST(-1)>0 faux) ne fire pas sur transitoire.
if logs=$(agent_logs 2>/dev/null); then
  scen_broken=$(printf '%s\n' "$logs" | grep -cE 'not found in expr library|unable to init data' || true)
  [ -z "$scen_broken" ] && scen_broken=0
fi
# âge de la dernière alerte (informatif, -1 si indéterminable / pas de `date -d`).
last_age=-1
last_created=$(printf '%s' "$raw" | jq -r '[ .[].created_at // empty ] | max // empty' 2>/dev/null || echo '')
if [ -n "$last_created" ]; then
  le=$(date -d "$last_created" +%s 2>/dev/null || echo '')
  [ -n "$le" ] && last_age=$((ts - le))
fi
ar=false; [ "$agent_ready" -eq 1 ] && ar=true
lo=false; [ "$lapi_ok" -eq 1 ] && lo=true
# sévérité : 0 (info) si sain ; 4 si scénarios cassés ; 3 si agent injoignable (transitoire possible -> le
# vrai « moteur mort » est attrapé par l'alerte MUET du collecteur CONTINU crowdsec-health).
if [ "$agent_ready" -eq 0 ]; then
  hsev=3; hmsg="CrowdSec INJOIGNABLE: agent non interrogeable"
elif [ "$scen_broken" -gt 0 ] 2>/dev/null; then
  hsev=4; hmsg="CrowdSec DÉGRADÉ: $scen_broken erreur(s) de chargement / $scen_loaded scénarios"
elif [ "$scen_broken" -lt 0 ] 2>/dev/null; then
  hsev=0; hmsg="CrowdSec santé: $scen_loaded scénarios (chargement inconnu — log agent inaccessible)"
else
  hsev=0; hmsg="CrowdSec santé: $scen_loaded scénarios, 0 erreur de chargement"
fi
hfields="{\"scenarios_loaded\":$scen_loaded,\"scenarios_broken\":$scen_broken,\"agent_ready\":$ar,\"lapi_ok\":$lo,\"last_alert_age_s\":$last_age}"
# PAS de dedup (event.dedup est UNIQUE) -> chaque battement S'INSÈRE -> MAX(ts) avance -> heartbeat vivant.
events="$events${events:+,}$(heartbeat crowdsec "$hmsg" "$hfields" "$hsev")"

# ── 3) SHIP : un seul spool par run (alertes éventuelles + battement de santé TOUJOURS présent).
[ -z "$events" ] && exit 0
spool_write "crowdsec-$ts.json" "$(emit_event "$events")"
