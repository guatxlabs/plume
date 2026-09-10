#!/bin/sh
# plume-source: ship
# Agent SOC — shipper : pousse les fichiers du spool vers le SOC CENTRAL.
#   *.json   (enveloppes events/metrics/firewall/controls) -> POST /api/ingest
#   *.ndjson (journald brut : sshd/sshd-session/sudo/su)    -> POST /api/ingest/journal
#            (le parsing reste cote daemon, sans jq cote agent ; sinon ces logs ne partaient PAS)
# Auth : PLUME_TOKEN (Bearer, recommandé) OU PLUME_USER+PLUME_PASS (basic). Portable (sh + curl).
# P5.5-a : le secret n'est PLUS un argument de curl (il était lisible dans /proc/<pid>/cmdline —
# mesuré) ; il transite par `curl -K -`, cf. `plume_curl_auth_stdin` dans lib.sh.
set -eu
# lib.sh est sourcé pour `plume_curl_auth_stdin` et, depuis `P9.7-c`, pour l'aveu `plume_report_availability` :
# `plume_init` pose SPOOL/STATE/host/ts (le même SPOOL que ce fichier résolvait seul ; STATE porte les compteurs).
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
SPOOL="${PLUME_SPOOL:-/var/lib/plume/spool}"
# `P9.7-c` (4) — LE TAMPON DE L'HÔTE EST BORNÉ, ET LA PERTE EST COMPTÉE ET DITE. Trois familles de tampon
# existaient et deux étaient bornées ; celle-ci — le spool qu'un hôte reçoit par défaut — n'avait ni plafond,
# ni éviction, ni purge : une erreur PERMANENTE du central le faisait croître sans fin. Tranché : sur un agent
# en échec permanent, la perte la moins mauvaise est celle des PLUS ANCIENS fichiers — l'agent Rust évince déjà
# ainsi, et ce que le SOC perd alors est du passé déjà hors de sa fenêtre de détection, pas le signal courant ;
# refuser le plus récent (la doctrine du récepteur syslog, un RÉSEAU sans état durable) perdrait l'attaque en
# cours au profit d'un historique jamais expédié. Et la perte n'est jamais silencieuse : chaque éviction est
# COMPTÉE et AVOUÉE au central par une enveloppe de disponibilité (`spool-full`), qui porte le compte.
SPOOL_MAX_FILES="${PLUME_SPOOL_MAX_FILES:-5000}"
borner_le_spool() {
  n=$(find "$SPOOL" -maxdepth 1 -type f \( -name '*.json' -o -name '*.ndjson' \) 2>/dev/null | wc -l | tr -d ' ')
  [ "$n" -gt "$SPOOL_MAX_FILES" ] || return 0
  surplus=$((n - SPOOL_MAX_FILES)); evinces=0
  # shellcheck disable=SC2012  (les noms du spool sont posés par les capteurs : sans blanc ni saut de ligne)
  for f in $(ls -tr "$SPOOL"/*.json "$SPOOL"/*.ndjson 2>/dev/null | head -n "$surplus"); do
    rm -f "$f" && evinces=$((evinces + 1))
  done
  # Le COMPTE vit dans l'aveu expédié au central (qui le garde durablement), pas dans $STATE : l'état de
  # l'hôte n'a qu'une voie d'écriture, celle des marqueurs de progression, et un compte n'en est pas un.
  echo "ship: spool plein ($n fichiers, plafond $SPOOL_MAX_FILES) : $evinces plus ancien(s) évincé(s)" >&2
  plume_report_availability ship unavailable spool-full \
    "SPOOL PLEIN : $evinces fichier(s) les plus anciens évincés à ce passage (plafond PLUME_SPOOL_MAX_FILES=$SPOOL_MAX_FILES, $n fichiers présents) — le central ne répond pas ou refuse depuis trop longtemps ; les événements les plus anciens sont PERDUS, le signal courant est gardé." 2 \
    2>/dev/null || true
}
# Un refus PERMANENT du central (un corps qu'il n'acceptera jamais : 400, 413, 415, 422) ne se réessaie pas
# éternellement : le fichier est mis à l'écart dans $STATE/refuses/, compté, et dit. Un 401/403 (identité),
# un 429/408, un 5xx ou un 000 (réseau) restent des CONSERVÉS POUR RÉESSAI, comme avant.
refuses=0
ecarter_un_refus_permanent() { # $1 = fichier, $2 = code
  # HORS du spool : le spool n'est publié que par sa voie unique (`spool_write`), et une pièce refusée n'est
  # plus une publication — c'est une pièce à LIRE, rangée avec l'état de l'hôte ($STATE/refuses/).
  mkdir -p "$STATE/refuses" 2>/dev/null || return 1
  mv -f "$1" "$STATE/refuses/" 2>/dev/null || return 1
  refuses=$((refuses + 1))
  echo "ship: $1 -> HTTP $2 (REFUS PERMANENT : mis à l'écart dans $STATE/refuses/)" >&2
}
# PLUME_HOST_HEADER : override l'en-tete Host (cas central in-cluster atteint par IP/ClusterIP alors que
# le daemon valide Host=soc.example.com). Valeur SANS espace -> "Host:soc.example.com" (split sh-safe).
HH=""; [ -n "${PLUME_HOST_HEADER:-}" ] && HH="-H Host:$PLUME_HOST_HEADER"
# mTLS optionnel : si PLUME_TLS_* fournis, curl présente un cert client + valide la CA interne.
# (exposez au central une route dédiée à l'agent, avec mTLS obligatoire, depuis votre dépôt GitOps.)
TLS=""
[ -n "${PLUME_TLS_CACERT:-}" ] && TLS="$TLS --cacert $PLUME_TLS_CACERT"
[ -n "${PLUME_TLS_CERT:-}" ]   && TLS="$TLS --cert $PLUME_TLS_CERT"
[ -n "${PLUME_TLS_KEY:-}" ]    && TLS="$TLS --key $PLUME_TLS_KEY"

post_file() { # $1 = fichier, $2 = endpoint -> imprime le code HTTP
  # Ni token ni user/pass -> échec explicite, comme avant (`${PLUME_USER:?}` sortait en erreur).
  if [ -z "${PLUME_TOKEN:-}" ]; then : "${PLUME_USER:?}" "${PLUME_PASS:?}"; fi
  # L'AUTH passe par l'entrée standard (`-K -`) : elle n'apparaît dans AUCUN argument -> rien à lire
  # dans /proc/<pid>/cmdline, rien à recopier dans `_CMDLINE` journald. Le corps vient du FICHIER
  # (`--data-binary @…`), donc l'usage de stdin par `-K` n'entre en conflit avec rien.
  # shellcheck disable=SC2086  ($HH/$TLS = tokens à éclater, expansion voulue)
  plume_curl_auth_stdin | curl -K - $HH $TLS -sS --max-time 15 -o /dev/null -w '%{http_code}' \
    -H 'Content-Type: application/json' --data-binary @"$1" "$PLUME_CENTRAL$2" 2>/dev/null || echo 000
}

sent=0
ship_glob() { # $1 = glob (non quote a l'expansion), $2 = endpoint
  for f in $1; do
    [ -e "$f" ] || continue
    case "${f##*/}" in .*) continue ;; esac
    code=$(post_file "$f" "$2")
    case "$code" in
      202) rm -f "$f"; sent=$((sent + 1)) ;;
      400|413|415|422) ecarter_un_refus_permanent "$f" "$code" || echo "ship: $f -> HTTP $code (refus permanent, mise à l'écart impossible : conservé)" >&2 ;;
      *) echo "ship: $f -> HTTP $code (conservé pour réessai)" >&2 ;;
    esac
  done
}

borner_le_spool
# shellcheck disable=SC2086  (on VEUT l'expansion du glob)
ship_glob "$SPOOL/*.json"   /api/ingest
ship_glob "$SPOOL/*.ndjson" /api/ingest/journal
[ "$sent" -gt 0 ] && echo "ship: $sent fichier(s) -> $PLUME_CENTRAL" || true
[ "$refuses" -gt 0 ] && plume_report_availability ship unavailable ingest-refused \
  "REFUS PERMANENT : $refuses fichier(s) refusés par le central (4xx hors identité et cadence), mis à l'écart dans $STATE/refuses/ — leur contenu n'entrera JAMAIS tel quel ; à lire, pas à réessayer." 2 2>/dev/null || true
