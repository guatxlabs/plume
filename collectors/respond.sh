#!/bin/sh
# Agent Plume — responder : applique SUR CET HOTE les actions (ban/unban IP) decidees par le central.
# Modele pull (pas d'entree reseau sur l'agent) : GET /api/actions/pending?host=... -> applique -> POST result.
# OPT-IN (PLUME_RESPONDER=1). DRY-RUN par defaut (PLUME_RESPONDER_APPLY=1 pour appliquer reellement).
# Delegue l'enforcement a l'IPS existant : CrowdSec (cscli) > fail2ban > nft (fallback). Portable (sh + curl).
set -eu

# P5.5-a — L'AUTH NE PASSE PAS PAR argv. Un argument de processus est public : mesure du 2026-08-02,
# le jeton etait lisible verbatim dans /proc/<pid>/cmdline (argv de 101 octets) et recopie par journald
# dans `_CMDLINE`, que Plume collecte lui-meme. On emet donc les options PORTEUSES DE SECRET sur
# l'ENTREE STANDARD de curl (`curl -K -`, format de ses fichiers de config) ; l'URL et les timeouts
# restent en argv, ou il n'y a rien a cacher.
# POURQUOI CETTE FONCTION EST DEFINIE ICI plutot que reprise de la bibliotheque des capteurs : ce
# script est un ENFORCER, pas un capteur. Une garde de CI
# (.github/scripts/check_collector_exit_is_classified.py) VERIFIE qu'il ne depend PAS de cette
# bibliotheque — c'est cette exclusion qui garde le code privilegie a surface de dependance minimale,
# et elle est AUTO-INVALIDANTE (elle se declenche des qu'on l'enfreint, y compris par une simple
# mention). On paie donc quelques lignes de duplication plutot que d'affaiblir une garde.
# Meme raison, meme forme, dans engagement-adapter.sh.
resp_curl_auth_stdin() {
  if [ -n "${PLUME_TOKEN:-}" ]; then
    printf 'header = "Authorization: Bearer %s"\n' "$(printf '%s' "$PLUME_TOKEN" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  elif [ -n "${PLUME_USER:-}" ] && [ -n "${PLUME_PASS:-}" ]; then
    printf 'user = "%s:%s"\n' \
      "$(printf '%s' "$PLUME_USER" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
      "$(printf '%s' "$PLUME_PASS" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  fi
}

[ "${PLUME_RESPONDER:-0}" = "1" ] || exit 0            # desactive tant que non explicitement active
CENTRAL="${PLUME_CENTRAL:?PLUME_CENTRAL requis}"
HOSTN="${PLUME_HOST_LABEL:-$(hostname)}"
APPLY="${PLUME_RESPONDER_APPLY:-0}"                     # 0 = dry-run meme pour une action 'reelle' (securite)
BACKEND="${PLUME_BAN_BACKEND:-auto}"
JAIL="${PLUME_FAIL2BAN_JAIL:-sshd}"
DUR="${PLUME_BAN_DURATION:-4h}"
ALLOWFILE="${PLUME_RESPONDER_ALLOW:-/etc/plume/responder.allow}"   # IP a NE JAMAIS bannir (1/ligne)
# PLUME_HOST_HEADER : override Host (central in-cluster atteint par ClusterIP). Sans espace -> split sh-safe.
HH=""; [ -n "${PLUME_HOST_HEADER:-}" ] && HH="-H Host:$PLUME_HOST_HEADER"
# mTLS optionnel (cert client agent) vers le central : mêmes variables PLUME_TLS_* que ship.sh.
TLS=""; [ -n "${PLUME_TLS_CACERT:-}" ] && TLS="$TLS --cacert $PLUME_TLS_CACERT"; [ -n "${PLUME_TLS_CERT:-}" ] && TLS="$TLS --cert $PLUME_TLS_CERT"; [ -n "${PLUME_TLS_KEY:-}" ] && TLS="$TLS --key $PLUME_TLS_KEY"

# hote du central (pour ne jamais le bannir) : retire schema + port de PLUME_CENTRAL
CENTRAL_HOST=$(printf '%s' "$CENTRAL" | sed -e 's#^[a-z]*://##' -e 's#[:/].*$##')

esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n\r\t' '   '; }

is_ip() { printf '%s' "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*$'; }
protected() {            # 0 = IP protegee (ne pas bannir) : loopback/RFC1918/lien-local/central/allowlist
  ip="$1"
  case "$ip" in
    127.*|10.*|192.168.*|169.254.*|0.*|255.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    ::1|fe80:*|fc[0-9a-fA-F]*:*|fd[0-9a-fA-F]*:*) return 0 ;;
  esac
  [ -n "$CENTRAL_HOST" ] && [ "$ip" = "$CENTRAL_HOST" ] && return 0
  [ -r "$ALLOWFILE" ] && grep -qxF "$ip" "$ALLOWFILE" 2>/dev/null && return 0
  return 1
}

backend="$BACKEND"
if [ "$backend" = auto ]; then
  if command -v cscli >/dev/null 2>&1; then backend=crowdsec
  elif command -v fail2ban-client >/dev/null 2>&1; then backend=fail2ban
  else backend=nft; fi
fi
# cscli mode-aware (host OU k3s exec pod LAPI) pour l'UNBAN CrowdSec en k3s. # shellcheck disable=SC2086
NS="${PLUME_CROWDSEC_NS:-crowdsec}"; LAPI="${PLUME_CROWDSEC_LAPI:-crowdsec-lapi}"
if [ -n "${PLUME_CSCLI:-}" ]; then cscli_cmd() { $PLUME_CSCLI "$@"; }; CSCLI_OK=1
elif command -v cscli >/dev/null 2>&1; then cscli_cmd() { cscli "$@"; }; CSCLI_OK=1
elif command -v k3s >/dev/null 2>&1 && k3s kubectl -n "$NS" get deploy "$LAPI" >/dev/null 2>&1; then cscli_cmd() { k3s kubectl -n "$NS" exec "deploy/$LAPI" -- cscli "$@"; }; CSCLI_OK=1
elif command -v kubectl >/dev/null 2>&1 && kubectl -n "$NS" get deploy "$LAPI" >/dev/null 2>&1; then cscli_cmd() { kubectl -n "$NS" exec "deploy/$LAPI" -- cscli "$@"; }; CSCLI_OK=1
else cscli_cmd() { return 1; }; CSCLI_OK=0; fi
# UNBAN = best-effort sur TOUS les backends (une IP peut être bannie n'importe où : fail2ban/crowdsec/nft).
unban_all() {
  OUT=""
  if command -v fail2ban-client >/dev/null 2>&1; then OUT="$OUT [f2b]$(fail2ban-client unban "$1" 2>&1 || true)"; fi
  if [ "$CSCLI_OK" = 1 ]; then OUT="$OUT [cs]$(cscli_cmd decisions delete -i "$1" 2>&1 || true)"; fi
  if nft list table inet plume >/dev/null 2>&1; then r=$(nft delete element inet plume blocklist "{ $1 }" 2>&1 || true); OUT="$OUT [nft]$r"; fi
  [ -n "$OUT" ] || { OUT='aucun backend de ban disponible'; return 1; }
  return 0
}
ensure_nft() {           # cree (idempotent) la table/set nft dediee Plume (fallback uniquement)
  nft list table inet plume >/dev/null 2>&1 && return 0
  nft add table inet plume 2>/dev/null || true
  nft add set inet plume blocklist '{ type ipv4_addr; flags interval; }' 2>/dev/null || true
  nft add chain inet plume input '{ type filter hook input priority -150; policy accept; }' 2>/dev/null || true
  nft add rule inet plume input ip saddr @blocklist drop 2>/dev/null || true
}
plan() {                 # kind target -> imprime la commande qui SERAIT executee (pour dry-run + trace)
  [ "$1" = unban_ip ] && { printf 'unban %s (best-effort: fail2ban tous jails + cscli + nft plume)' "$2"; return; }
  case "$backend:$1" in
    crowdsec:ban_ip)   printf 'cscli decisions add -i %s -d %s -t ban -R plume-playbook' "$2" "$DUR" ;;
    crowdsec:unban_ip) printf 'cscli decisions delete -i %s' "$2" ;;
    fail2ban:ban_ip)   printf 'fail2ban-client set %s banip %s' "$JAIL" "$2" ;;
    fail2ban:unban_ip) printf 'fail2ban-client set %s unbanip %s' "$JAIL" "$2" ;;
    nft:ban_ip)        printf 'nft add element inet plume blocklist { %s }' "$2" ;;
    nft:unban_ip)      printf 'nft delete element inet plume blocklist { %s }' "$2" ;;
    *)                 printf 'NON-SUPPORTE %s/%s' "$backend" "$1" ;;
  esac
}
enforce() {              # kind target -> applique ; renvoie 0/!=0, sortie dans $OUT
  k="$1"; t="$2"
  [ "$k" = unban_ip ] && { unban_all "$t"; return $?; }   # unban = tous backends (k3s-aware)
  case "$backend:$k" in
    crowdsec:ban_ip)   OUT=$(cscli_cmd decisions add -i "$t" -d "$DUR" -t ban -R plume-playbook 2>&1) ;;
    crowdsec:unban_ip) OUT=$(cscli decisions delete -i "$t" 2>&1) ;;
    fail2ban:ban_ip)   OUT=$(fail2ban-client set "$JAIL" banip "$t" 2>&1) ;;
    fail2ban:unban_ip) OUT=$(fail2ban-client set "$JAIL" unbanip "$t" 2>&1) ;;
    nft:ban_ip)        ensure_nft; OUT=$(nft add element inet plume blocklist "{ $t }" 2>&1) ;;
    nft:unban_ip)      OUT=$(nft delete element inet plume blocklist "{ $t }" 2>&1) ;;
    *)                 OUT="backend/kind non supporte: $backend/$k"; return 1 ;;
  esac
}

# --- recupere la liste (TSV: id  kind  target  dry_run), 1 action/ligne ---
# P5.5-a : auth par l'ENTRÉE STANDARD (`-K -`), jamais en argument -> rien dans /proc/<pid>/cmdline.
if [ -z "${PLUME_TOKEN:-}" ]; then : "${PLUME_USER:?}" "${PLUME_PASS:?}"; fi
# shellcheck disable=SC2086  ($HH = 0 ou 2 tokens, expansion voulue)
list=$(resp_curl_auth_stdin | curl -K - $HH $TLS -sS --max-time 15 "$CENTRAL/api/actions/pending?host=$HOSTN" 2>/dev/null) || exit 0
[ -n "$list" ] || exit 0

post_result() {          # id status result (auth par stdin, jamais en argv)
  body="{\"id\":$1,\"status\":\"$2\",\"result\":\"$(esc "$3")\"}"
  # shellcheck disable=SC2086  ($HH = 0 ou 2 tokens, expansion voulue)
  resp_curl_auth_stdin | curl -K - $HH $TLS -sS --max-time 15 -o /dev/null \
    -H 'Content-Type: application/json' --data-binary "$body" "$CENTRAL/api/actions/result" 2>/dev/null || true
}

printf '%s\n' "$list" | while IFS='	' read -r id kind target dry; do
  [ -n "${id:-}" ] || continue
  case "$id" in *[!0-9]*) continue ;; esac          # id doit etre numerique
  if ! is_ip "$target"; then post_result "$id" failed "cible non-IP: $target"; continue; fi
  if protected "$target"; then post_result "$id" failed "IP protegee (allowlist/RFC1918/central): $target"; continue; fi
  cmd=$(plan "$kind" "$target")
  if [ "$APPLY" != "1" ] || [ "${dry:-1}" = "1" ]; then
    post_result "$id" dryrun "[dry-run] $cmd"
    echo "respond: [dry-run] #$id $cmd" >&2
    continue
  fi
  if enforce "$kind" "$target"; then
    post_result "$id" done "$cmd | $OUT"
    echo "respond: #$id applique ($cmd)" >&2
  else
    post_result "$id" failed "$cmd | $OUT"
    echo "respond: #$id ECHEC ($cmd): $OUT" >&2
  fi
done
