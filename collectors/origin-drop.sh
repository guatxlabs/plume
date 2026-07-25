#!/bin/sh
# Capteur Plume (PLUGIN) : rend VISIBLES les paquets rejetes par votre pare-feu d'origine.
# Un pare-feu qui DROP silencieusement ne produit aucun evenement : vous ne savez pas qui frappe le
# service en direct, en contournant votre CDN ou votre ingress. Le remede est cote pare-feu : placer une
# regle de LOG juste AVANT le DROP, avec un prefixe reconnaissable et un rate-limit (pour ne pas se faire
# inonder). Ce capteur parse ce prefixe (defaut 'ORIGIN-DROP:') dans le journal kernel et en fait des
# evenements source=origin-drop / category=firewall.
#
# A DEFINIR PAR VOUS : la table/chaine, les ports proteges, le prefixe et le rate-limit. Exemple nft :
#   log prefix "ORIGIN-DROP: " flags all limit rate <N>/minute
# Le signal utile est "un contournement a ete tente", pas le volume : un rate-limit bas suffit.
# LECTURE SEULE (journalctl -k).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
MAX="${PLUME_ORIGINDROP_MAX:-300}"
command -v nft >/dev/null 2>&1 || exit 0                          # pas de nft -> skip propre
nft list table inet "${PLUME_ORIGINDROP_TABLE:-plume-origin-fw}" >/dev/null 2>&1 || exit 0   # table absente -> rien a faire
plume_init; umask 027

WM="$STATE_DIR/origin-drop.watermark"
last=$(cat "$WM" 2>/dev/null || echo $((ts - 3600)))
tmpf=$(mktemp)
journalctl -k --since "@$last" --no-pager -o short-unix 2>/dev/null | grep 'ORIGIN-DROP:' > "$tmpf" 2>/dev/null || true
events=""; n=0; seen=" "
while IFS= read -r line; do
  [ -n "$line" ] || continue
  src=$(printf '%s' "$line" | sed -n 's/.*SRC=\([0-9A-Fa-f.:]*\).*/\1/p'); [ -n "$src" ] || continue
  dst=$(printf '%s' "$line"  | sed -n 's/.*DST=\([0-9A-Fa-f.:]*\).*/\1/p')
  dpt=$(printf '%s' "$line"  | sed -n 's/.*DPT=\([0-9]*\).*/\1/p')
  spt=$(printf '%s' "$line"  | sed -n 's/.*SPT=\([0-9]*\).*/\1/p')
  proto=$(printf '%s' "$line"| sed -n 's/.*PROTO=\([A-Za-z0-9]*\).*/\1/p')
  case "$src" in *:*) fam=ipv6 ;; *) fam=ipv4 ;; esac
  key="$src"
  case "$seen" in *" $key "*) continue ;; esac                    # dedup par source dans ce passage (calque portscan)
  seen="$seen$key "
  n=$((n + 1)); [ "$n" -le "$MAX" ] || break
  m="ORIGIN-DROP [$fam] $src -> $host:${dpt:-?}/${proto:-?} (acces direct origine = bypass Cloudflare, DROP)"
  fields="{\"src_ip\":\"$src\",\"dst_ip\":\"${dst:-}\",\"dport\":\"${dpt:-}\",\"sport\":\"${spt:-}\",\"proto\":\"${proto:-}\",\"family\":\"$fam\",\"dir\":\"inbound\",\"action\":\"dropped\",\"detector\":\"nft-origin-fw\"}"
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"origin-drop\",\"category\":\"firewall\",\"severity\":2,\"message\":\"$m\",\"src_ip\":\"$src\",\"dst_ip\":\"${dst:-}\",\"dir\":\"inbound\",\"dport\":\"${dpt:-}\",\"dedup\":\"origindrop-$src-$((ts / 60))\",\"fields\":$fields}"
done < "$tmpf"
rm -f "$tmpf"
state_write "$WM" "$ts"

# DEAD-MAN'S-SWITCH (calque portscan.sh/crowdsec.sh) : battement de SANTE a CHAQUE run MEME a 0 hit ->
# Plume distingue « aucun acces direct (normal, event_based) » de « collecteur origin-drop mort ». PAS de
# dedup (event.dedup est UNIQUE -> un dedup constant bloquerait l'INSERT OR IGNORE et figerait MAX(ts)) ->
# chaque battement S'INSERE -> MAX(ts) avance -> heartbeat vivant.
events="$events${events:+,}$(heartbeat origin-drop "origin-drop sante: $n hit(s) ce passage" "{\"hits_seen\":$n}")"
spool_write "origin-drop-$ts.json" "$(emit_event "$events")" nl
spool_write "origin-dropm-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"metrics","data":{"metrics":[{"name":"origin_drops_seen","value":%s}]}}' "$ts" "$host" "$n")" nl
