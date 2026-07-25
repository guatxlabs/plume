#!/bin/sh
# Agent SOC — shipper : pousse les fichiers du spool vers le SOC CENTRAL.
#   *.json   (enveloppes events/metrics/firewall/controls) -> POST /api/ingest
#   *.ndjson (journald brut : sshd/sshd-session/sudo/su)    -> POST /api/ingest/journal
#            (le parsing reste cote daemon, sans jq cote agent ; sinon ces logs ne partaient PAS)
# Auth : PLUME_TOKEN (Bearer, recommandé) OU PLUME_USER+PLUME_PASS (basic). Portable (sh + curl).
set -eu
SPOOL="${PLUME_SPOOL:-/var/lib/plume/spool}"
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
  # shellcheck disable=SC2086  ($HH/$TLS = tokens à éclater, expansion voulue)
  if [ -n "${PLUME_TOKEN:-}" ]; then
    curl $HH $TLS -sS --max-time 15 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $PLUME_TOKEN" \
      -H 'Content-Type: application/json' --data-binary @"$1" "$PLUME_CENTRAL$2" 2>/dev/null || echo 000
  else
    curl $HH $TLS -sS --max-time 15 -o /dev/null -w '%{http_code}' -u "${PLUME_USER:?}:${PLUME_PASS:?}" \
      -H 'Content-Type: application/json' --data-binary @"$1" "$PLUME_CENTRAL$2" 2>/dev/null || echo 000
  fi
}

sent=0
ship_glob() { # $1 = glob (non quote a l'expansion), $2 = endpoint
  for f in $1; do
    [ -e "$f" ] || continue
    case "${f##*/}" in .*) continue ;; esac
    code=$(post_file "$f" "$2")
    if [ "$code" = "202" ]; then
      rm -f "$f"; sent=$((sent + 1))
    else
      echo "ship: $f -> HTTP $code (conservé pour réessai)" >&2
    fi
  done
}

# shellcheck disable=SC2086  (on VEUT l'expansion du glob)
ship_glob "$SPOOL/*.json"   /api/ingest
ship_glob "$SPOOL/*.ndjson" /api/ingest/journal
[ "$sent" -gt 0 ] && echo "ship: $sent fichier(s) -> $PLUME_CENTRAL" || true
