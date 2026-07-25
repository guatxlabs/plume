#!/bin/sh
# Capteur Plume (PLUGIN, OPT-IN) : firewall events Cloudflare (edge WAF / Bot / RateLimit)
# -> events source=cloudflare. Ferme l'angle mort des attaques web stoppees AU EDGE par CF
# (challenge/block) que l'origine (Traefik) ne voit jamais. Lecture seule : GraphQL
# firewallEventsAdaptive (pull-only ; aucune action/mutation CF). Dedup cf-<rayName> (idempotent).
# OPT-IN : skip propre si PLUME_CF_TOKEN / PLUME_CF_ZONE absents. Requiert curl -4 + jq.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
TOKEN="${PLUME_CF_TOKEN:-}"
ZONE="${PLUME_CF_ZONE:-}"                       # ZONE TAG 32-hex de example.com (PAS le nom de zone)
LIMIT="${PLUME_CF_LIMIT:-1000}"
API="${PLUME_CF_API:-https://api.cloudflare.com/client/v4/graphql}"

# OPT-IN : pas de creds -> skip silencieux (comme les autres collecteurs)
[ -n "$TOKEN" ] && [ -n "$ZONE" ] || exit 0
command -v curl -4 >/dev/null 2>&1 || exit 0
command -v jq   >/dev/null 2>&1 || exit 0

plume_init
WM="$STATE_DIR/cloudflare.watermark"

# watermark = dernier datetime RFC3339 ingere ; 1re passe (ou invalide) = now-10min
since=$(cat "$WM" 2>/dev/null || true)
case "$since" in
  ????-??-??T??:??:??Z) : ;;                    # RFC3339 'Z' valide
  *) since=$(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%SZ) ;;
esac

read_query() {
cat <<'GQL'
query($zone:String!,$since:Time!,$lim:Int!){ viewer { zones(filter:{zoneTag:$zone}){
  firewallEventsAdaptive(filter:{datetime_gt:$since}, limit:$lim, orderBy:[datetime_ASC]){
    datetime action source clientIP clientAsn clientCountryName
    clientRequestHTTPHost clientRequestPath clientRequestHTTPMethodName
    userAgent ruleId rayName }}}}
GQL
}

body=$(jq -n --arg q "$(read_query)" --arg zone "$ZONE" --arg since "$since" --argjson lim "$LIMIT" \
  '{query:$q,variables:{zone:$zone,since:$since,lim:$lim}}')

resp=$(curl -4 -s -m 30 -w '\n%{http_code}' "$API" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' --data "$body" 2>/dev/null || true)
code=$(printf '%s' "$resp" | tail -n1)
json=$(printf '%s' "$resp" | sed '$d')

# Echec API (scope token / plan CF / reseau) : ne PAS avancer le watermark, ne PAS spooler.
if [ "$code" != "200" ]; then
  echo "cloudflare: GraphQL HTTP ${code:-000} (token scope/plan ? rien spoole)" >&2
  exit 0
fi
errs=$(printf '%s' "$json" | jq -c '.errors // empty' 2>/dev/null || true)
if [ -n "$errs" ] && [ "$errs" != "null" ] && [ "$errs" != "[]" ]; then
  echo "cloudflare: GraphQL errors=$errs (rien spoole)" >&2
  exit 0
fi

# Map CF -> enveloppe Plume kind:events (source=cloudflare, category=web). Severite :
#   block/connectionClose -> 3 ; *challenge* -> 2 ; sinon 1 ; +1 si source=waf (ruleset manage) ; cap 4.
# action CIM (aligne web.sh) : blocked / challenged / allowed. cf_action/cf_source = brut.
envj=$(printf '%s' "$json" | jq -c --arg host "$host" --argjson ts "$ts" '
  ( .data.viewer.zones[0].firewallEventsAdaptive // [] ) as $ev
  | { ts:$ts, host:$host, kind:"events",
      events: ( $ev | map(
        (.action // "") as $a | (.source // "") as $s |
        ( if ($a=="block" or $a=="connectionClose" or $a=="force_connection_close") then 3
          elif ($a|test("challenge")) then 2 else 1 end ) as $base |
        ( [ (if $s=="waf" then ($base+1) else $base end), 4 ] | min ) as $sev |
        ( if ($a=="block" or $a=="connectionClose" or $a=="force_connection_close") then "blocked"
          elif ($a|test("challenge")) then "challenged" else "allowed" end ) as $cim |
        {
          ts: ( (.datetime // "") | sub("\\.[0-9]+Z$";"Z") | fromdateiso8601 ),
          source: "cloudflare",
          category: "web",
          severity: $sev,
          src_ip: (.clientIP // ""),
          message: ( "CF " + $a + " " + $s + " " + (.clientRequestHTTPHost // "") + (.clientRequestPath // "") + " from " + (.clientIP // "") ),
          dedup: ( "cf-" + (.rayName // "") ),
          fields: {
            action: $cim,
            cf_action: $a,
            cf_source: $s,
            ruleId: ((.ruleId // "") | tostring),
            vhost: (.clientRequestHTTPHost // ""),
            path: (.clientRequestPath // ""),
            method: (.clientRequestHTTPMethodName // ""),
            ua: (.userAgent // ""),
            country: (.clientCountryName // ""),
            asn: ((.clientAsn // "") | tostring),
            ray: (.rayName // ""),
            src_ip: (.clientIP // ""),
            dir: "inbound",
            scope: "external"
          }
        } ) )
    }')

n=$(printf '%s' "$envj" | jq -r '.events | length' 2>/dev/null || echo 0)
if [ "${n:-0}" -gt 0 ]; then
  spool_write "cloudflare-$ts.json" "$envj" nl
  # avance le watermark au max(datetime) ingere (datetime_gt strict ; dedup cf-<rayName> couvre tout chevauchement)
  maxdt=$(printf '%s' "$json" | jq -r '[ .data.viewer.zones[0].firewallEventsAdaptive[]?.datetime ] | max // empty' 2>/dev/null || true)
  [ -n "${maxdt:-}" ] && state_write "$WM" "$maxdt"
fi
