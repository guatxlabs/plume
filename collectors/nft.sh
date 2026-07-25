#!/bin/sh
# Capteur Plume (PLUGIN) : COMPTEURS des sets nft (blocklists CAPI/crowdsec/fail2ban) -> metrics.
# Le SOC "voit" l'enforcement au niveau PAQUET sans ingerer les milliers d'IP : on emet juste les
# COMPTES par set (+ total) = volume mini, zero bruit. OPT-IN, lecture seule.
#
# Mode-aware (cf project deployment-modes : k3s / hote-natif / container) : nft est lu sur l'HOTE
# (en host-natif comme en k3s, l'agent tourne sur l'hote ou nft vit) ; SKIP PROPRE si nft est
# absent ou non lisible (container sans acces nft, ou OS sans nftables). Requiert jq pour le detail
# par set (sinon emet juste un total best-effort). Aucune dependance dure.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
command -v nft >/dev/null 2>&1 || exit 0            # pas de nft (container/non-linux) -> skip propre
nft list ruleset >/dev/null 2>&1 || exit 0          # nft present mais non lisible (pas root/cap) -> skip
m() { printf '{"name":"%s","value":%s}' "$1" "$2"; }
metrics=""; total=0
if command -v jq >/dev/null 2>&1; then
  tmpf=$(mktemp)
  # 1 ligne "<set>\t<nb elements>" par set possedant des elements (CAPI, crowdsec, f2b-*, ...)
  nft -j list ruleset 2>/dev/null | jq -r '.nftables[]?.set | select(.elem) | "\(.name)\t\(.elem|length)"' > "$tmpf" 2>/dev/null || true
  TAB=$(printf '\t')
  while IFS="$TAB" read -r name cnt; do
    [ -n "${name:-}" ] || continue
    case "$cnt" in ''|*[!0-9]*) continue ;; esac          # garde-fou numerique
    sane=$(printf 'nft_set_%s' "$name" | tr -c 'A-Za-z0-9_' '_')   # nom de metric sur
    metrics="$metrics${metrics:+,}$(m "$sane" "$cnt")"
    total=$((total + cnt))
  done < "$tmpf"
  rm -f "$tmpf"
fi
metrics="$metrics${metrics:+,}$(m nft_blocked_total "$total")"
spool_write "nft-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"metrics","data":{"metrics":[%s]}}' "$ts" "$host" "$metrics")"

# --- CHANTIER whitelists->webui : AUTO-REPORT de config (source=nft category=config) --------------
# ETAT HOTE (type=host) : le SOC voit l'enforcement au niveau paquet SANS ingerer les milliers d'IP.
# Surface le TOTAL de l'enforcement nft dans le panneau read-only. VISIBILITE cote daemon, CONTROLE a la
# frontiere hote (nft/systemd) — JAMAIS pilotable d'ici (invariant sandbox #3).
cfg_fields=$(printf '{"type":"host","collector":"nft","enforcement":{"nft_blocked_total":%s},"note":"compteurs des sets nft (CAPI/crowdsec/fail2ban) — enforcement paquet ; controle a la frontiere hote, read-only"}' "$total")
cfg_dd="cfg-nft-$(printf '%s' "$cfg_fields" | cksum | cut -d' ' -f1)"
cfg_event=$(printf '{"ts":%s,"source":"nft","category":"config","severity":0,"message":"config etat firewall nft (enforcement paquet)","dedup":"%s","fields":%s}' \
  "$ts" "$cfg_dd" "$cfg_fields")
spool_write "config-nft-$ts.json" "$(emit_event "$cfg_event")"
