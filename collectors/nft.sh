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
command -v nft >/dev/null 2>&1 || plume_unavailable nft missing-dependency "nft absent (conteneur / non-linux)"            # pas de nft (container/non-linux) -> skip propre
nft list ruleset >/dev/null 2>&1 || plume_unavailable nft subsystem-absent "nft present mais ruleset illisible (droits root/CAP_NET_ADMIN insuffisants)"          # nft present mais non lisible (pas root/cap) -> skip
m() { printf '{"name":"%s","value":%s}' "$1" "$2"; }
metrics=""; total=0
# S36 — TROIS ECHECS RENDAIENT LE MEME `0` QU'UN ENFORCEMENT REELLEMENT VIDE, et ce zero partait dans
# la metrique `nft_blocked_total` ET dans l'etat d'hote du panneau : `jq` absent (le bloc entier etait
# saute sans un mot), `nft -j` refuse (un nft trop ancien n'a PAS la sortie JSON, alors que le `nft
# list ruleset` du garde-fou d'entree, lui, passe : c'est le piege de l'OPTION absente), et le statut
# du tube qui est celui de `jq`, jamais celui de `nft`. « Aucune IP bloquee » et « je ne sais pas
# combien d'IP sont bloquees » sont deux phrases differentes ; une seule etait dite.
# La lecture est donc separee du decodage, et une source non lue ne produit PAS de nombre : la serie
# disparait, et l'aveu part par le canal d'indisponibilite existant (S33, meme voie, memes mots).
nft_lu=1
if ! command -v jq >/dev/null 2>&1; then
  nft_lu=0
  plume_mesure_absente nft_blocked_total source_absente "jq absent : le detail des sets nft n'est pas decodable sur cet hote — le compte d'enforcement paquet ne peut PAS etre etabli"
else
  brut=$(mktemp); tmpf=$(mktemp)
  if ! nft -j list ruleset > "$brut" 2>/dev/null; then
    nft_lu=0
    plume_mesure_absente nft_blocked_total source_illisible "nft -j list ruleset : sortie JSON indisponible (nft trop ancien, ou droits insuffisants) alors que le ruleset texte est lisible"
  # 1 ligne "<set>\t<nb elements>" par set possedant des elements (CAPI, crowdsec, f2b-*, ...)
  elif ! jq -r '.nftables[]?.set | select(.elem) | "\(.name)\t\(.elem|length)"' < "$brut" > "$tmpf" 2>/dev/null; then
    nft_lu=0
    plume_mesure_absente nft_blocked_total forme_inconnue "nft -j list ruleset : la sortie JSON n'a pas la forme attendue (.nftables[].set) — le compte des sets n'est pas etablissable"
  else
    TAB=$(printf '\t')
    while IFS="$TAB" read -r name cnt; do
      [ -n "${name:-}" ] || continue
      case "$cnt" in ''|*[!0-9]*) continue ;; esac          # garde-fou numerique
      sane=$(printf 'nft_set_%s' "$name" | tr -c 'A-Za-z0-9_' '_')   # nom de metric sur
      metrics="$metrics${metrics:+,}$(m "$sane" "$cnt")"
      total=$((total + cnt))
    done < "$tmpf"
  fi
  rm -f "$brut" "$tmpf"
fi
# UN RULESET REELLEMENT SANS AUCUNE IP BLOQUEE RESTE PUBLIE A 0 : c'est un releve, pas une panne.
[ "$nft_lu" = 1 ] && metrics="$metrics${metrics:+,}$(m nft_blocked_total "$total")"
plume_mesures_avouer nft
if [ -n "$metrics" ]; then
  spool_write "nft-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"metrics","data":{"metrics":[%s]}}' "$ts" "$host" "$metrics")"
fi

# --- CHANTIER whitelists->webui : AUTO-REPORT de config (source=nft category=config) --------------
# ETAT HOTE (type=host) : le SOC voit l'enforcement au niveau paquet SANS ingerer les milliers d'IP.
# Surface le TOTAL de l'enforcement nft dans le panneau read-only. VISIBILITE cote daemon, CONTROLE a la
# frontiere hote (nft/systemd) — JAMAIS pilotable d'ici (invariant sandbox #3).
# L'ETAT D'HOTE NE PUBLIE PAS UN COMPTE QU'IL N'A PAS PU ETABLIR : le panneau read-only afficherait
# « 0 IP bloquee » — la lecture la plus rassurante possible — la ou le capteur n'a rien pu lire.
if [ "$nft_lu" = 1 ]; then
  cfg_enf=$(printf '{"nft_blocked_total":%s}' "$total")
else
  cfg_enf='{"nft_blocked_total":null}'
fi
cfg_fields=$(printf '{"type":"host","collector":"nft","enforcement":%s,"note":"compteurs des sets nft (CAPI/crowdsec/fail2ban) — enforcement paquet ; controle a la frontiere hote, read-only ; enforcement null = compte NON ETABLI ce passage (cf. aveu collector-availability)"}' "$cfg_enf")
cfg_dd="cfg-nft-$(printf '%s' "$cfg_fields" | cksum | cut -d' ' -f1)"
cfg_event=$(printf '{"ts":%s,"source":"nft","category":"config","severity":0,"message":"config etat firewall nft (enforcement paquet)","dedup":"%s","fields":%s}' \
  "$ts" "$cfg_dd" "$cfg_fields")
spool_write "config-nft-$ts.json" "$(emit_event "$cfg_event")"
