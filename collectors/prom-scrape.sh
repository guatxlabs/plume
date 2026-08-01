#!/bin/sh
# Agent SOC - scrape Prometheus (OBS-1, remplacement de Prometheus) : curl les /metrics d'une
# liste de cibles -> POST /api/metrics/prom (format texte d'exposition, parse cote daemon).
# OPT-IN. Cibles : /etc/plume/prom-targets (1 URL/ligne, # = commentaire) ou $PLUME_PROM_TARGETS.
# Auth : PLUME_TOKEN (Bearer, recommande) OU PLUME_USER+PLUME_PASS (basic). Portable (sh + curl).
set -eu
# lib.sh est sourcé UNIQUEMENT pour les primitives de sortie classée (plume_unavailable & co) : ce
# collecteur POSTe directement au central et n'utilise ni le spool ni les helpers d'événement. Sourcer
# ne fait que DÉFINIR des fonctions — aucun effet de bord, `plume_init` n'est pas appelé ici.
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
SOC="${PLUME_CENTRAL:-http://127.0.0.1:7000}"
HOSTN="${PLUME_HOST_LABEL:-$(hostname)}"
TFILE="${PLUME_PROM_TARGETS_FILE:-/etc/plume/prom-targets}"
targets="${PLUME_PROM_TARGETS:-}"
[ -z "$targets" ] && [ -r "$TFILE" ] && targets=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$TFILE" | tr '\n' ' ')
# « aucune cible » n'est PAS un silence légitime : c'est un capteur NON CONFIGURÉ, donc structurellement
# incapable de scraper quoi que ce soit. Il le dit (missing-config) au lieu de sortir 0 sans un mot.
[ -z "$targets" ] && plume_unavailable prom-scrape missing-config "aucune cible de scrape ($TFILE absent/vide et PLUME_PROM_TARGETS non pose)"
# PLUME_HOST_HEADER : override Host (central in-cluster atteint par ClusterIP). Sans espace -> split sh-safe.
HH=""; [ -n "${PLUME_HOST_HEADER:-}" ] && HH="-H Host:$PLUME_HOST_HEADER"
# mTLS optionnel (cert client agent) vers le central : mêmes variables PLUME_TLS_* que ship.sh.
TLS=""; [ -n "${PLUME_TLS_CACERT:-}" ] && TLS="$TLS --cacert $PLUME_TLS_CACERT"; [ -n "${PLUME_TLS_CERT:-}" ] && TLS="$TLS --cert $PLUME_TLS_CERT"; [ -n "${PLUME_TLS_KEY:-}" ] && TLS="$TLS --key $PLUME_TLS_KEY"

post() { # $1 = corps texte
  # shellcheck disable=SC2086  ($HH = 0 ou 2 tokens, expansion voulue)
  if [ -n "${PLUME_TOKEN:-}" ]; then
    printf '%s' "$1" | curl $HH $TLS -sS --max-time 15 -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer $PLUME_TOKEN" -H 'Content-Type: text/plain' \
      --data-binary @- "$SOC/api/metrics/prom?host=$HOSTN" 2>/dev/null || echo 000
  else
    printf '%s' "$1" | curl $HH $TLS -sS --max-time 15 -o /dev/null -w '%{http_code}' \
      -u "${PLUME_USER:?}:${PLUME_PASS:?}" -H 'Content-Type: text/plain' \
      --data-binary @- "$SOC/api/metrics/prom?host=$HOSTN" 2>/dev/null || echo 000
  fi
}

ok=0; total=0
for t in $targets; do
  total=$((total + 1))
  body=$(curl -sS --max-time 10 "$t" 2>/dev/null) || { echo "prom-scrape: $t injoignable" >&2; continue; }
  [ -n "$body" ] || { echo "prom-scrape: $t vide" >&2; continue; }
  code=$(post "$body")
  if [ "$code" = "200" ]; then ok=$((ok + 1)); else echo "prom-scrape: $t -> HTTP $code" >&2; fi
done
echo "prom-scrape: $ok/$total cible(s) -> $SOC"
