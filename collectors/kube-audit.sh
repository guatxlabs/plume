#!/bin/sh
# Capteur Plume : log d'audit de l'API Kubernetes (kube-apiserver --audit-log-path) -> events.
# Couvre "qui a fait quoi sur l'API du cluster" (create/update/delete/patch + accès refusés 403/401).
# ROOT (le log est sous /var/lib/rancher/k3s/server, 0600 root). OPT-IN. SANS jq (grep -oP, sûr).
# Le log brut sur disque reste la trace forensique complète ; le SOC en est la vue indexée/alertée.
#
# Variables (toutes optionnelles, défauts k3s) :
#   PLUME_KUBE_AUDIT_LOG   chemin du audit.log         (def: /var/lib/rancher/k3s/server/logs/audit.log)
#   PLUME_KUBE_AUDIT_MAX   max lignes traitées / run   (def: 4000 — borne le flood du 1er run)
#   PLUME_SPOOL / PLUME_STATE  comme les autres capteurs
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
# Auto-détection du audit.log : k3s puis k8s natif (override explicite via PLUME_KUBE_AUDIT_LOG).
LOG="${PLUME_KUBE_AUDIT_LOG:-}"
if [ -z "$LOG" ]; then
  for c in /var/lib/rancher/k3s/server/logs/audit.log /var/log/kubernetes/audit.log /var/log/kube-apiserver/audit.log; do
    [ -r "$c" ] && { LOG="$c"; break; }
  done
  LOG="${LOG:-/var/lib/rancher/k3s/server/logs/audit.log}"   # rien trouvé -> défaut k3s -> skip propre L+1
fi
MAX="${PLUME_KUBE_AUDIT_MAX:-4000}"
plume_init
[ -r "$LOG" ] || exit 0                      # audit pas activé / pas root -> skip propre

OFFF="$STATE/kube-audit.offset"
SIZE=$(wc -c < "$LOG" 2>/dev/null || echo 0)
OFF=$(cat "$OFFF" 2>/dev/null || echo 0)
case "$OFF" in ''|*[!0-9]*) OFF=0 ;; esac
[ "$SIZE" -lt "$OFF" ] && OFF=0              # rotation/troncature -> reprise au début
[ "$SIZE" -eq "$OFF" ] && exit 0            # rien de neuf

# Nouveau chunk (depuis l'offset), borné aux MAX dernières lignes (anti-flood 1er run).
chunk=$(mktemp); tail -c +$((OFF + 1)) "$LOG" 2>/dev/null | tail -n "$MAX" > "$chunk" || true
echo "$SIZE" > "$OFFF"                       # avance l'offset (le brut reste la trace complète)

events=""
while IFS= read -r line; do
  [ -z "$line" ] && continue
  # n'ingère QUE les events porteurs d'une RÉPONSE : le stage RequestReceived (émis À la réception de la
  # requête, AVANT traitement) n'a ni responseStatus.code ni décision d'autorisation -> code=0/verb-decision
  # NULL = bruit non requêtable. On ne garde donc que ResponseComplete/ResponseStarted (qui portent code +
  # décision -> le fix forbidden/403 reste intact). La policy k3s omet déjà RequestReceived : garde-fou
  # collecteur contre toute dérive de politique d'audit (ou un autre hôte sans omitStages).
  case "$line" in *'"stage":"RequestReceived"'*) continue ;; esac
  verb=$(printf '%s' "$line"  | grep -oP '"verb":"\K[^"]+' | head -1 || true)
  [ -z "$verb" ] && continue                 # pas une entrée d'audit -> skip
  user=$(printf '%s' "$line"  | grep -oP '"user":\{[^}]*"username":"\K[^"]+' | head -1 || true)
  oref=$(printf '%s' "$line"  | grep -oP '"objectRef":\{[^}]*\}' | head -1 || true)
  res=$(printf '%s'  "$oref"  | grep -oP '"resource":"\K[^"]+' | head -1 || true)
  ns=$(printf '%s'   "$oref"  | grep -oP '"namespace":"\K[^"]+' | head -1 || true)
  name=$(printf '%s' "$oref"  | grep -oP '"name":"\K[^"]+' | head -1 || true)
  # code HTTP : responseStatus contient un objet imbriqué "metadata":{} (et "details":{} sur refus) ;
  # le [^}]*' d'origine butait sur le 1er '}' -> code toujours vide -> 0 -> "allowed" (jamais de 403).
  # (?:[^{}]|\{[^}]*\})*? saute les sous-objets de 1 niveau et s'arrête au 1er "code" -> code RÉEL.
  code=$(printf '%s' "$line"  | grep -oP '"responseStatus":\{(?:[^{}]|\{[^}]*\})*?"code":\s*\K[0-9]+' | head -1 || true)
  sip=$(printf '%s'  "$line"  | grep -oP '"sourceIPs":\["\K[^"]+' | head -1 || true)
  # décision d'autorisation canonique (TOUJOURS émise par l'audit k8s, indépendante du code) : allow|forbid
  decision=$(printf '%s' "$line" | grep -oP 'authorization\.k8s\.io/decision":"\K[^"]+' | head -1 || true)
  [ -z "$user" ] && user="?"; [ -z "$res" ] && res="?"
  # NE JAMAIS fabriquer un code : si la source ne le porte pas, on le laisse VIDE (pas 0 -> pas de faux allowed).

  # action canonique (CIM) : la DÉCISION RBAC prime (forbid=refus) ; le code HTTP complète (erreurs serveur).
  act=allowed
  [ "$decision" = forbid ] && act=forbidden
  case "$code" in 401|403) act=forbidden ;; 4??|5??) [ "$act" = allowed ] && act=error ;; esac

  # sévérité : refus d'autorisation (forbid) / auth (401/403) / erreurs serveur (5xx) / suppressions = 3 ; reste = 2
  sev=2
  [ "$decision" = forbid ] && sev=3
  case "$code" in 401|403) sev=3 ;; 5??) sev=3 ;; esac
  [ "$verb" = "delete" ] && sev=3
  [ "$verb" = "deletecollection" ] && sev=3

  tgt="$res"; [ -n "$ns" ] && tgt="$ns/$res"; [ -n "$name" ] && tgt="$tgt/$name"
  msg="$user $verb $tgt -> ${code:-$decision}"
  em=$(json_escape "$(printf '%s' "$msg" | cut -c1-300)")
  esc(){ json_escape "$1"; }
  # fields = OBJET JSON (cohérent avec les autres sources -> cherchable verb=/user=/action=/decision=)
  fields="{\"verb\":\"$(esc "$verb")\",\"user\":\"$(esc "$user")\",\"resource\":\"$(esc "$res")\",\"ns\":\"$(esc "${ns:-}")\",\"name\":\"$(esc "${name:-}")\",\"code\":\"$code\",\"decision\":\"$(esc "${decision:-}")\",\"action\":\"$act\"}"
  # dedup : collapse les reconciles identiques sur fenêtre 10min, garde les actions distinctes
  dd="kaudit-$(printf '%s|%s|%s|%s' "$user" "$verb" "$tgt" "$code" | cksum | cut -d' ' -f1)-$((ts / 600))"
  ev="{\"ts\":$ts,\"source\":\"kube-audit\",\"category\":\"k8s\",\"severity\":$sev,\"message\":\"$em\",\"fields\":$fields,\"dedup\":\"$dd\""
  [ -n "$sip" ] && ev="$ev,\"src_ip\":\"$sip\""
  ev="$ev}"
  events="$events${events:+,}$ev"
done < "$chunk"
rm -f "$chunk"

[ -z "$events" ] && exit 0
spool_write "kubeaudit-$ts.json" "$(emit_event "$events")"
