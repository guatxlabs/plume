#!/bin/sh
# Capteur Plume : firewall (nftables) — snapshot d'INTÉGRITÉ du ruleset + (si applicable) le contrôle
# docker-lan-lockdown. Exécuté en ROOT par plume-firewall.service. Lecture seule, aucune action.
#
# Mode-aware (cf project deployment-modes : k3s / hôte-natif / container) :
#  - le hash du ruleset nft est émis PARTOUT où nft est présent (détection de changement) ; skip si pas de nft.
#  - le contrôle docker-lan-lockdown (DROP LAN->docker sur une interface wifi) est SPÉCIFIQUE à un hôte
#    type laptop : il n'est évalué QUE si l'interface $PLUME_LOCKDOWN_IFACE (def wlan0) existe + iptables dispo.
#    Sinon (VPS/k3s/container, pas de wlan0) on l'OMET -> le daemon défaut ok=true -> PAS de faux "ABSENT".
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
PORTS="${PLUME_LOCKDOWN_PORTS:-5900,6080,8080,8081,8090,5173}"
IFACE="${PLUME_LOCKDOWN_IFACE:-wlan0}"
plume_init
command -v nft >/dev/null 2>&1 || plume_unavailable firewall missing-dependency "nft absent (conteneur / non-linux) : aucun ruleset a instantaner"          # pas de nft (container/non-linux) -> rien à snapshot -> skip
nft list ruleset >/dev/null 2>&1 || plume_unavailable firewall subsystem-absent "nft present mais ruleset illisible (droits root/CAP_NET_ADMIN insuffisants)"        # nft présent mais non lisible (pas root/cap) -> skip
# hash sur la STRUCTURE des règles : on retire les compteurs volatils (packets/bytes) -> un snapshot
# n'est stocké que si les règles changent vraiment (pas toutes les 2 min).
rs_hash=$(nft list ruleset 2>/dev/null | sed -E 's/packets [0-9]+ bytes [0-9]+//g' | sha256sum | cut -d' ' -f1)

# Contrôle docker-lan-lockdown : UNIQUEMENT si l'interface visée existe + iptables dispo (hôte type laptop).
lockdown=""
if command -v iptables >/dev/null 2>&1 && ip link show "$IFACE" >/dev/null 2>&1; then
  chk() { if "$@" >/dev/null 2>&1; then printf true; else printf false; fi; }   # true/false selon présence règle
  du_v4=$(chk iptables  -C DOCKER-USER -i "$IFACE" -d 172.16.0.0/12 -m conntrack --ctstate NEW -j DROP)
  in_v4=$(chk iptables  -C INPUT -i "$IFACE" -p tcp -m multiport --dports "$PORTS" -m conntrack --ctstate NEW -j DROP)
  in_v6=$(chk ip6tables -C INPUT -i "$IFACE" -p tcp -m multiport --dports "$PORTS" -m conntrack --ctstate NEW -j DROP)
  if [ "$du_v4" = true ] && [ "$in_v4" = true ] && [ "$in_v6" = true ]; then ok=true; else ok=false; fi
  lockdown=",\"control_docker_lockdown\":{\"iface\":\"$IFACE\",\"docker_user_v4\":$du_v4,\"input_v4\":$in_v4,\"input_v6\":$in_v6,\"ok\":$ok}"
fi

# atomic publish 0640 (lisible par le groupe 'soc', le daemon ingester) via lib.sh
spool_write "firewall-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"firewall","hash":"%s","data":{"ruleset_sha256":"%s"%s}}' \
  "$ts" "$host" "$rs_hash" "$rs_hash" "$lockdown")"
