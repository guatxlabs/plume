#!/bin/sh
# plume-source: prom-scrape
# plume-emits: fields=
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
# P10.33-a — LE JETON ET LES MESURES NE PARTENT PAS EN CLAIR VERS UN CENTRAL DISTANT. Meme porte que
# `ship.sh` (lib.sh, `plume_verifier_le_transport`) : `https://` et la boucle locale (le defaut ci-dessus)
# passent, tout autre `http://` est REFUSE, code 2, AVANT de scraper ou d'expedier quoi que ce soit, sauf
# `PLUME_SHIP_ALLOW_PLAINTEXT=1`.
# LES CIBLES SCRAPEES NE SONT PAS SOUMISES A CETTE PORTE, ET C'EST UN CHOIX : aucun jeton ne leur est
# envoye (leur `curl` ne recoit ni `-K` ni en-tete d'authentification) ; ce qui circule en clair est la
# mesure ENTRANTE, qu'un tiers sur le chemin peut lire ou falsifier. Un exporteur `/metrics` se sert en
# `http://` dans l'usage courant : le refuser couperait le capteur sans proteger aucun secret. Une cible
# `https://` reste possible. Une cible n'est imprimee que par schema et hote (elle peut porter une identite).
plume_verifier_le_transport prom-scrape "$SOC" "Aucune cible n'est scrapee, rien n'est expedie." || exit 2
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
  # P5.5-a : l'auth passe par l'ENTRÉE STANDARD (`-K -`), jamais par argv (mesuré lisible dans
  # /proc/<pid>/cmdline). Stdin étant pris par la config, le CORPS passe par un fichier temporaire —
  # c'est du texte d'exposition Prometheus, il ne contient aucun secret. 0600 + effacé aussitôt.
  if [ -z "${PLUME_TOKEN:-}" ]; then : "${PLUME_USER:?}" "${PLUME_PASS:?}"; fi
  _pb=$(umask 077; mktemp)
  printf '%s' "$1" > "$_pb"
  # shellcheck disable=SC2086  ($HH = 0 ou 2 tokens, expansion voulue)
  plume_curl_auth_stdin | curl -K - $HH $TLS -sS --max-time 15 -o /dev/null -w '%{http_code}' \
    -H 'Content-Type: text/plain' \
    --data-binary @"$_pb" "$SOC/api/metrics/prom?host=$HOSTN" 2>/dev/null || echo 000
  rm -f "$_pb"
}

ok=0; total=0
for t in $targets; do
  total=$((total + 1))
  ta=$(plume_url_affichee "$t")
  body=$(curl -sS --max-time 10 "$t" 2>/dev/null) || { echo "prom-scrape: $ta injoignable" >&2; continue; }
  [ -n "$body" ] || { echo "prom-scrape: $ta vide" >&2; continue; }
  code=$(post "$body")
  if [ "$code" = "200" ]; then ok=$((ok + 1)); else echo "prom-scrape: $ta -> HTTP $code" >&2; fi
done
echo "prom-scrape: $ok/$total cible(s) -> $_PLUME_CENTRAL_AFFICHE"
