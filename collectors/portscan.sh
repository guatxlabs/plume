#!/bin/sh
# Capteur Plume (PLUGIN, OPT-IN) : PORT-SCAN détecté par la table nft 'plume-portscan'.
# La journalisation d'un pare-feu généraliste est en général rate-limitée et étouffe les scans lents
# (peu ou pas de signal). Ici le SIGNAL EST DEJA "un scan détecté" :
# nft émet AU PLUS 1 ligne 'PORTSCAN4:/PORTSCAN6:' par source par minute (low-volume, propre).
# On parse ce préfixe -> event (qui=SRC, où=DST:DPT, comment=PROTO, dir=inbound). Lecture seule.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
MAX="${PLUME_PORTSCAN_MAX:-300}"
command -v nft >/dev/null 2>&1 || plume_unavailable portscan missing-dependency "nft absent"                       # pas de nft -> skip propre
nft list table inet plume-portscan >/dev/null 2>&1 || plume_unavailable portscan subsystem-absent "table nft plume-portscan absente : le detecteur de scan n est pas pose (systemd/plume-portscan.nft)"   # détecteur absent -> rien à faire
umask 027

WM="$STATE_DIR/portscan.watermark"
last=$(cat "$WM" 2>/dev/null || echo $((ts - 3600)))
tmpf=$(mktemp)
journalctl -k --since "@$last" --no-pager -o short-unix 2>/dev/null | grep 'PORTSCAN' > "$tmpf" 2>/dev/null || true
events=""; n=0; seen=" "
while IFS= read -r line; do
  [ -n "$line" ] || continue
  src=$(printf '%s' "$line" | sed -n 's/.*SRC=\([0-9A-Fa-f.:]*\).*/\1/p'); [ -n "$src" ] || continue
  dst=$(printf '%s' "$line"  | sed -n 's/.*DST=\([0-9A-Fa-f.:]*\).*/\1/p')
  dpt=$(printf '%s' "$line"  | sed -n 's/.*DPT=\([0-9]*\).*/\1/p')
  proto=$(printf '%s' "$line"| sed -n 's/.*PROTO=\([A-Za-z0-9]*\).*/\1/p')
  case "$line" in *PORTSCAN6:*) fam=ipv6 ;; *) fam=ipv4 ;; esac
  key="$src"
  case "$seen" in *" $key "*) continue ;; esac                 # dédup par source dans ce passage
  seen="$seen$key "
  n=$((n + 1)); [ "$n" -le "$MAX" ] || break
  m="PORTSCAN [$fam] $src -> $host (sonde :${dpt:-?}/${proto:-?})"
  fields="{\"src_ip\":\"$src\",\"dst_ip\":\"$dst\",\"dport\":\"${dpt:-}\",\"proto\":\"${proto:-}\",\"family\":\"$fam\",\"dir\":\"inbound\",\"action\":\"detected\",\"detector\":\"nft\"}"
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"portscan\",\"category\":\"firewall\",\"severity\":3,\"message\":\"$m\",\"src_ip\":\"$src\",\"dir\":\"inbound\",\"dport\":\"${dpt:-}\",\"dedup\":\"portscan-$src-$((ts / 300))\",\"fields\":$fields}"
  # BRING-YOUR-OWN / vendor-agnostic path (chantier #5) : forward the RAW kernel PORTSCAN line ALSO
  # under source=nft so the declarative parser `nft-scan-detect` (config.d) normalises it to CIM
  # firewall (category=firewall action=deny dst_port=.. signal=portscan) -> feeds the inter-vendor
  # low-and-slow rules (dc(dst_port)>8 / dc(dst_ip)>5). NO category here -> the parser sets firewall
  # (ENRICH-only, collector-wins). Coexists with the native source=portscan event above (2 paths, #5).
  nftmsg=$(json_escape "$line")
  events="$events,{\"ts\":$ts,\"source\":\"nft\",\"message\":\"$nftmsg\",\"dedup\":\"nftscan-$src-$((ts / 300))\"}"
done < "$tmpf"
rm -f "$tmpf"
# S30 — filigrane MIS EN ATTENTE (ecrit apres la publication de l'enveloppe d'events, cf. lib.sh).
# Cle `portscan-<src>-<seau 5 min>` -> un rejeu tombant dans le meme seau est absorbe.
state_stage "$WM" "$ts"

# DEAD-MAN'S-SWITCH (calque crowdsec.sh/pod-logs.sh) : battement de SANTÉ à CHAQUE run MÊME quand 0 scan
# détecté -> Plume distingue « aucun scan (normal, event_based) » de « collecteur portscan mort ». PAS de
# dedup (event.dedup est UNIQUE -> un dedup constant bloquerait l'INSERT OR IGNORE et figerait MAX(ts)) ->
# chaque battement S'INSÈRE -> MAX(ts) avance -> heartbeat vivant. Le SILENCE de ce battement (>~25 min) lève
# l'alerte MUET (collecteur CONTINU portscan-health, cf. main.rs). Le ship de l'enveloppe events est rendu
# INCONDITIONNEL (events porte toujours ce battement) ; la métrique portscans_seen reste inchangée.
events="$events${events:+,}$(heartbeat portscan "portscan santé: $n scan(s) ce passage" "{\"scans_seen\":$n}")"
spool_write_then_ack "portscan-$ts.json" "$(emit_event "$events")" nl
spool_write "portscanm-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"metrics","data":{"metrics":[{"name":"portscans_seen","value":%s}]}}' "$ts" "$host" "$n")" nl

# --- CHANTIER whitelists->webui : AUTO-REPORT de config (source=portscan category=config) ----------
# ETAT HOTE (type=host) : detecteur nft 'plume-portscan' (le SIGNAL est deja « un scan detecte »).
# Surface l'etat du detecteur dans le panneau read-only. VISIBILITE cote daemon, CONTROLE a la frontiere
# hote (table nft) — read-only, jamais pilotable d'ici. Dedup stable (etat du detecteur, pas le volume).
cfg_fields=$(printf '{"type":"host","collector":"portscan","detector":"nft inet plume-portscan","max":"%s","note":"detecteur nft de port-scan (1 ligne max/source/min) — controle a la frontiere hote, read-only"}' "${MAX}")
cfg_dd="cfg-portscan-$(printf '%s' "$cfg_fields" | cksum | cut -d' ' -f1)"
cfg_event=$(printf '{"ts":%s,"source":"portscan","category":"config","severity":0,"message":"config etat detecteur portscan (nft plume-portscan)","dedup":"%s","fields":%s}' \
  "$ts" "$cfg_dd" "$cfg_fields")
spool_write "config-portscan-$ts.json" "$(emit_event "$cfg_event")" nl
