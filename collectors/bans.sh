#!/bin/sh
# Capteur Plume : agrège les BANS ACTIFS de tous les backends -> events category=ban (cherchables :
#   category:ban ip:1.2.3.4   -> cette IP est-elle bannie, et par quoi ?
#   source:fail2ban category:ban   -> tous les bans fail2ban
# Backends : fail2ban (hôte, fail2ban-client) + CrowdSec (cscli decisions, mode-aware host/k3s).
# ROOT. OPT-IN. Dédup HORAIRE : un ban actif réapparaît chaque heure (récent = courant) ; une IP
# unban cesse de réapparaître -> vieillit via la rétention. cf respond.sh pour l'UNBAN.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
bucket=$((ts / 3600))
events=""
nb=0   # nb de bans actifs EMIS ce run (fail2ban + crowdsec) -> {active_bans} du battement de santé
emit() { # $1=source $2=ip $3=label
  case "$2" in *.*|*:*) : ;; *) return ;; esac    # IPv4/IPv6 seulement
  m=$(json_escape "$(printf 'BAN actif %s (%s)' "$2" "$3" | cut -c1-200)")
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"$1\",\"category\":\"ban\",\"severity\":3,\"message\":\"$m\",\"src_ip\":\"$2\",\"dedup\":\"ban-$1-$2-$bucket\",\"fields\":{\"action\":\"ban\"}}"
  nb=$((nb + 1))
}

# --- fail2ban (hôte) : chaque jail -> liste des IP bannies ---
if command -v fail2ban-client >/dev/null 2>&1; then
  jails=$(fail2ban-client status 2>/dev/null | grep -i "Jail list" | sed 's/.*://' | tr ',' ' ')
  for j in $jails; do
    [ -n "$j" ] || continue
    for ip in $(fail2ban-client status "$j" 2>/dev/null | grep -i "Banned IP list" | sed 's/.*Banned IP list:[[:space:]]*//'); do
      emit fail2ban "$ip" "$j"
    done
  done
fi

# --- fail2ban INTERNE du mailserver (docker-mailserver : jails postfix/dovecot/custom) ---
# Il tourne DANS le pod mail -> INVISIBLE du fail2ban hôte ci-dessus = angle mort (un ban mail
# n'apparaissait nulle part dans le SOC). Mode k3s : exec dans le pod, label "mail/<jail>".
# OPT-IN (PLUME_MAIL_F2B=1) : spécifique à un déploiement type docker-mailserver-en-k3s -> DÉSACTIVÉ
# par défaut (le SOC est générique : on ne suppose ni mailserver, ni k3s). Skip propre si pas de pod.
if [ "${PLUME_MAIL_F2B:-0}" = "1" ]; then
  MNS="${PLUME_MAIL_F2B_NS:-mail}"; MCT="${PLUME_MAIL_F2B_CONTAINER:-mailserver}"; mpod="${PLUME_MAIL_F2B_POD:-}"
  if [ -z "$mpod" ]; then
    if command -v k3s >/dev/null 2>&1; then mpod=$(k3s kubectl -n "$MNS" get pods --no-headers 2>/dev/null | awk '/mailserver/{print $1; exit}')
    elif command -v kubectl >/dev/null 2>&1; then mpod=$(kubectl -n "$MNS" get pods --no-headers 2>/dev/null | awk '/mailserver/{print $1; exit}'); fi
  fi
  if [ -n "$mpod" ]; then
    mkx() { if command -v k3s >/dev/null 2>&1; then k3s kubectl -n "$MNS" exec "$mpod" -c "$MCT" -- "$@"; else kubectl -n "$MNS" exec "$mpod" -c "$MCT" -- "$@"; fi; }
    for mj in $(mkx fail2ban-client status 2>/dev/null | grep -i "Jail list" | sed 's/.*://' | tr ',' ' '); do
      [ -n "$mj" ] || continue
      for ip in $(mkx fail2ban-client status "$mj" 2>/dev/null | grep -i "Banned IP list" | sed 's/.*Banned IP list:[[:space:]]*//'); do
        emit fail2ban "$ip" "mail/$mj"
      done
    done
  fi
fi

# --- CrowdSec (décisions actives) : mode-aware (PLUME_CSCLI > cscli hôte > k3s exec pod LAPI > kubectl) ---
NS="${PLUME_CROWDSEC_NS:-crowdsec}"; LAPI="${PLUME_CROWDSEC_LAPI:-crowdsec-lapi}"
# shellcheck disable=SC2086
if [ -n "${PLUME_CSCLI:-}" ]; then cscli_cmd() { $PLUME_CSCLI "$@"; }
elif command -v cscli >/dev/null 2>&1; then cscli_cmd() { cscli "$@"; }
elif command -v k3s >/dev/null 2>&1 && k3s kubectl -n "$NS" get deploy "$LAPI" >/dev/null 2>&1; then cscli_cmd() { k3s kubectl -n "$NS" exec "deploy/$LAPI" -- cscli "$@"; }
elif command -v kubectl >/dev/null 2>&1 && kubectl -n "$NS" get deploy "$LAPI" >/dev/null 2>&1; then cscli_cmd() { kubectl -n "$NS" exec "deploy/$LAPI" -- cscli "$@"; }
else cscli_cmd() { return 1; }; fi
if command -v jq >/dev/null 2>&1; then
  tmpf=$(mktemp)
  cscli_cmd decisions list -o json 2>/dev/null | jq -r '(.[]?|.decisions[]?) | [(.value//"-"),(.scenario//.origin//"crowdsec")] | @tsv' > "$tmpf" 2>/dev/null || true
  TAB=$(printf '\t')
  while IFS="$TAB" read -r ip scen; do [ -n "$ip" ] && emit crowdsec "$ip" "$scen"; done < "$tmpf"
  rm -f "$tmpf"
fi

# DEAD-MAN'S-SWITCH (calque crowdsec.sh/pod-logs.sh) : battement de SANTÉ à CHAQUE run MÊME quand 0 ban actif.
# La liveness de bans.sh est rattachée à source=fail2ban (id COLLECTORS existant) : le dead-man's-switch du
# MOTEUR crowdsec est DÉJÀ porté par crowdsec.sh, on n'en refait pas un ici. PAS de dedup (event.dedup est
# UNIQUE -> un dedup constant bloquerait l'INSERT OR IGNORE et figerait MAX(ts)) -> chaque battement S'INSÈRE
# -> MAX(ts) avance -> heartbeat vivant. Le SILENCE de ce battement (>~25 min) lève l'alerte MUET (collecteur
# CONTINU fail2ban-health, cf. main.rs). On NE coupe PLUS avant (l'ancien « [ -z "$events" ] && exit 0 »
# sautait le battement les runs sans ban) : events porte toujours ce battement -> le spool part toujours.
events="$events${events:+,}$(heartbeat fail2ban "bans santé: $nb ban(s) actif(s)" "{\"active_bans\":$nb}")"
spool_write "bans-$ts.json" "$(emit_event "$events")"
