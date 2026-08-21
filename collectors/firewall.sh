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
  # S36, RANG « DU BRUIT AU LIEU DU SILENCE » — « JE N'AI PAS PU VERIFIER » N'EST PAS « LA REGLE EST
  # ABSENTE ». `iptables -C` rend 1 quand la regle n'existe pas (le verdict recherche) mais AUSSI un
  # code >=2 quand la verification elle-meme n'a pas pu avoir lieu : verrou xtables tenu par un autre
  # processus, module noyau absent, droits insuffisants, binaire incompatible. Tous tombaient du cote
  # `false`, c'est-a-dire du cote « controle de defense MANQUANT » — et le daemon leve alors l'alerte
  # livree `firewall.lockdown` (severite 3, une par jour et par machine, cf. daemon/src/ingest/mod.rs).
  # Une machine dont le verrou iptables est simplement occupe annoncait donc chaque jour un durcissement
  # disparu. LE VERDICT DEVIENT EXACT, PAS MUET : `null` dit « non etabli », le daemon le distingue deja
  # d'un `false` (`as_bool()` -> None -> pas d'alerte, comme pour le controle OMIS sur un hote sans
  # wlan0), et l'aveu part par le canal ou une regle livree alerte deja.
  chk() { if "$@" >/dev/null 2>&1; then printf true; else case $? in 1) printf false ;; *) printf null ;; esac; fi; }
  du_v4=$(chk iptables  -C DOCKER-USER -i "$IFACE" -d 172.16.0.0/12 -m conntrack --ctstate NEW -j DROP)
  in_v4=$(chk iptables  -C INPUT -i "$IFACE" -p tcp -m multiport --dports "$PORTS" -m conntrack --ctstate NEW -j DROP)
  in_v6=$(chk ip6tables -C INPUT -i "$IFACE" -p tcp -m multiport --dports "$PORTS" -m conntrack --ctstate NEW -j DROP)
  if [ "$du_v4" = true ] && [ "$in_v4" = true ] && [ "$in_v6" = true ]; then
    ok=true
  elif [ "$du_v4" = null ] || [ "$in_v4" = null ] || [ "$in_v6" = null ]; then
    # AU MOINS UNE JAMBE N'A PAS PU ETRE VERIFIEE : le controle n'est ni tenu ni absent, il est
    # INDETERMINE. Le declarer absent serait une alerte fabriquee ; le declarer tenu serait un faux
    # calme. On ne dit ni l'un ni l'autre, et on le DIT.
    ok=null
    plume_lecture_partielle firewall source_illisible \
      "controle docker-lan-lockdown NON VERIFIABLE sur $IFACE (iptables/ip6tables -C n'a pas pu conclure : verrou xtables, module absent ou droits insuffisants) : docker_user_v4=$du_v4 input_v4=$in_v4 input_v6=$in_v6. Ni tenu, ni absent — le SOC ne recoit AUCUN verdict sur ce controle ce passage."
  else
    ok=false
  fi
  lockdown=",\"control_docker_lockdown\":{\"iface\":\"$IFACE\",\"docker_user_v4\":$du_v4,\"input_v4\":$in_v4,\"input_v6\":$in_v6,\"ok\":$ok}"
fi

# atomic publish 0640 (lisible par le groupe 'soc', le daemon ingester) via lib.sh
spool_write "firewall-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"firewall","hash":"%s","data":{"ruleset_sha256":"%s"%s}}' \
  "$ts" "$host" "$rs_hash" "$rs_hash" "$lockdown")"
