#!/bin/sh
# Capteur Plume (PLUGIN, OPT-IN) : PORT-PROBE low-and-slow via la table nft 'plume-portscan'.
# Complement de portscan.sh : celui-la lit le LOG kernel PORTSCAN (scanner RAPIDE, seuil de DEBIT). Ici on lit
# l'APPARTENANCE au set dynamique ps_rate_v4/ps_rate_v6 (timeout 60s) = "a sonde un port NON ouvert",
# INDEPENDAMMENT du debit -> capte le prober LENT (low-and-slow, T1046) qu'un seuil de DEBIT laisse passer.
# LECTURE SEULE : `nft -j list ruleset` (REQUETE, PAS un log) -> AUCUN bruit journald, AUCUN seuil noyau
# abaisse. Chaque run reinsere les membres courants (dedup au bucket-minute) -> la RECURRENCE se compte
# sur la fenetre (regle "Port-probe low-and-slow (recurrence)" : count>12/src_ip/heure).
# INVARIANT : AUCUNE IP whitelistee ; un poste d'administration legitime est exclu par NATURE (il ne
# sonde pas de port ferme). source=portprobe (PAS 'portscan' : la regle de scan rapide lit source=portscan).
# OPT-IN / mode-aware : skip propre si nft ou la table plume-portscan est absente. Requiert nft + jq.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
command -v nft >/dev/null 2>&1 || plume_unavailable portprobe missing-dependency "nft absent"                       # pas de nft -> skip propre
command -v jq  >/dev/null 2>&1 || plume_unavailable portprobe missing-dependency "jq absent"
nft list table inet plume-portscan >/dev/null 2>&1 || plume_unavailable portprobe subsystem-absent "table nft plume-portscan absente : le detecteur de scan n est pas pose (systemd/plume-portscan.nft)"   # detecteur absent -> rien a faire
umask 027

# Membres courants des sets ps_rate_v4/v6 (val = IP source ayant sonde un port ferme). `nft -j` = requete
# read-only du ruleset (pas de journald). status/severite : chaque membre = 1 event source=portprobe.
# PAS de heartbeat sous source=portprobe : un battement sans src_ip formerait un groupe src_ip vide dont
# le count franchirait le seuil recurrence -> FAUX POSITIF. On n'emet donc QUE des events par-membre.
envj=$(nft -j list ruleset 2>/dev/null | jq -c --arg host "$host" --argjson ts "$ts" '
  [ .nftables[]
    | (.set // empty) as $s
    | select(($s|type)=="object" and ($s.table=="plume-portscan")
             and ($s.name=="ps_rate_v4" or $s.name=="ps_rate_v6"))
    | ($s.name) as $set
    | ($s.elem // [])[]
    | ( if type=="object" then (.elem.val // .val // "") else . end ) as $ip
    | select(($ip|type)=="string" and $ip != "")
    | {
        ts:$ts, source:"portprobe", category:"firewall", severity:1,
        src_ip:$ip, dir:"inbound",
        message:("PORTPROBE " + $ip + " (sonde port ferme, set " + $set + ")"),
        dedup:("portprobe-" + $ip + "-" + (($ts/60)|floor|tostring)),
        fields:{ src_ip:$ip, set:$set, action:"probed", detector:"nft", dir:"inbound", scope:"external" }
      }
  ] as $events
  | { ts:$ts, host:$host, kind:"events", events:$events }' 2>/dev/null || true)

n=$(printf '%s' "$envj" | jq -r '.events | length' 2>/dev/null || echo 0)
if [ "${n:-0}" -gt 0 ]; then
  spool_write "portprobe-$ts.json" "$envj" nl
fi
