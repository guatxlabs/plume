#!/bin/sh
# Capteur Plume (PLUGIN, OPT-IN) : requetes HTTP 4xx/5xx vues AU EDGE Cloudflare (httpRequestsAdaptiveGroups)
# -> events source=cloudflare-http, category=web. Ferme l'angle mort du SCAN WEB (T1595.002) absorbe/servi
# au edge que l'origine (Traefik/web.sh) ne voit pas forcement (404 sur des chemins qui n'atteignent jamais
# l'origine, ou trafic filtre CF). Alimente la regle "404-breadth (Cloudflare)" (dc(path)>30 par IP).
# LECTURE SEULE : GraphQL Analytics (pull-only ; AUCUNE action/mutation CF). Cardinalite BORNEE pour le
# pod 2Go : limit<=200 groupes + filtre edgeResponseStatus_geq:400 uniquement (les 200 legit n'entrent PAS).
# INVARIANT anti-angle-mort : AUCUNE IP whitelistee ; le signal est la NATURE 404-en-masse, pas une IP.
# OPT-IN : skip propre si PLUME_CF_TOKEN / PLUME_CF_ZONE absents. Requiert curl + jq.
# GOTCHA egress IPv4 : le token CF whiteliste des IPv4 mais le VPS sort en IPv6 -> curl -4 IMPERATIF.
# Le TOKEN n'est JAMAIS imprime/loggue (ni en clair, ni tronque) NI passe en argument de curl (P5.5-a :
# un argument est lisible dans /proc/<pid>/cmdline par tout utilisateur local — il transite par stdin).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
TOKEN="${PLUME_CF_TOKEN:-}"
ZONE="${PLUME_CF_ZONE:-}"                       # ZONE TAG 32-hex de example.com (PAS le nom de zone)
LIMIT="${PLUME_CF_HTTP_LIMIT:-200}"            # cardinalite bornee (pod 2Go) ; groupes 4xx/5xx par fenetre
LAG="${PLUME_CF_HTTP_LAG:-90}"                 # buffer (s) contre le lag adaptive-sampling CF ; recouvre, jamais de trou
API="${PLUME_CF_API:-https://api.cloudflare.com/client/v4/graphql}"

# OPT-IN : pas de creds -> skip silencieux (comme les autres collecteurs)
[ -n "$TOKEN" ] && [ -n "$ZONE" ] || plume_unavailable cloudflare-http missing-config "PLUME_CF_TOKEN et/ou PLUME_CF_ZONE non poses"
command -v curl >/dev/null 2>&1 || plume_unavailable cloudflare-http missing-dependency "curl absent"
command -v jq   >/dev/null 2>&1 || plume_unavailable cloudflare-http missing-dependency "jq absent"

plume_init
nowiso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
WM="$STATE_DIR/cloudflare-http.watermark"

# watermark = borne basse datetime_geq de la fenetre ; 1re passe (ou invalide) = now-10min
since=$(cat "$WM" 2>/dev/null || true)
case "$since" in
  ????-??-??T??:??:??Z) : ;;                    # RFC3339 'Z' valide
  *) since=$(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%SZ) ;;
esac

read_query() {
cat <<'GQL'
query($zone:String!,$since:Time!,$lim:Int!){ viewer { zones(filter:{zoneTag:$zone}){
  httpRequestsAdaptiveGroups(limit:$lim, filter:{datetime_geq:$since, edgeResponseStatus_geq:400}, orderBy:[count_DESC]){
    count
    dimensions { clientIP clientRequestHTTPHost clientRequestPath edgeResponseStatus clientRequestHTTPMethodName }
  }}}}
GQL
}

body=$(jq -n --arg q "$(read_query)" --arg zone "$ZONE" --arg since "$since" --argjson lim "$LIMIT" \
  '{query:$q,variables:{zone:$zone,since:$since,lim:$lim}}')

# curl -4 IMPERATIF (token CF whiteliste IPv4 ; sortie IPv6 par defaut serait rejetee).
# P5.5-a : le jeton CF passe par l'ENTREE STANDARD (`-K -`), jamais en argument de curl. L'en-tete
# du fichier promettait « JAMAIS imprime/loggue » : c'etait faux tant qu'il etait en argv, ou tout
# utilisateur local le lisait dans /proc/<pid>/cmdline (mesure 2026-08-02, argv de 101 octets).
resp=$(plume_curlcfg_header_auth "$TOKEN" | curl -K - -4 -s -m 30 -w '\n%{http_code}' "$API" \
  -H 'Content-Type: application/json' --data "$body" 2>/dev/null || true)
code=$(printf '%s' "$resp" | tail -n1)
json=$(printf '%s' "$resp" | sed '$d')

# Echec API (scope token / plan CF / reseau) : ne PAS avancer le watermark, ne PAS spooler. Token JAMAIS logge.
if [ "$code" != "200" ]; then
  echo "cloudflare-http: GraphQL HTTP ${code:-000} (token scope/plan ? rien spoole)" >&2
  plume_unavailable cloudflare-http unreachable "API GraphQL Cloudflare HTTP ${code:-000} (scope du token / plan CF / reseau) : rien spoole, watermark non avance"
fi
errs=$(printf '%s' "$json" | jq -c '.errors // empty' 2>/dev/null || true)
if [ -n "$errs" ] && [ "$errs" != "null" ] && [ "$errs" != "[]" ]; then
  echo "cloudflare-http: GraphQL errors=$errs (rien spoole)" >&2
  plume_unavailable cloudflare-http unreachable "API GraphQL Cloudflare a repondu des erreurs : rien spoole, watermark non avance"
fi

# Map CF -> enveloppe Plume kind:events. status/path/method/vhost = STRING (calque web.sh -> la regle
# 'status=404 | stats dc(path)' s'applique a l'identique). severity 1 (telemetrie ; la DETECTION = regle).
# S34 — CLE D'IDENTITE, ANCREE SUR LA FENETRE INTERROGEE ET NON SUR L'INSTANT DU PASSAGE.
# CE QUI ETAIT FAUX, ET COMMENT LE DECOMPTE S'EN EST TROUVE FAUSSE : la cle valait
# `cfhttp-<ip>-<path>-<status>-<$ts/60>`, ou `$ts` est l'INSTANT DE COLLECTE. Un capteur cadence a la
# minute change donc de seau a presque chaque passage : une tranche republiee apres coupure portait
# des cles NEUVES et n'etait absorbee par rien. Ce capteur figurait pourtant parmi ceux annonces
# « absorbes par identite de contenu » — le classement venait du prefixe de la cle, pas de ce qui la
# compose. Une cle qui contient l'instant de publication ne dedoublonne rien : c'est le piege meme.
# CE QUI EST STABLE ICI : `since`, la borne basse de la fenetre GraphQL. Elle est lue dans le
# filigrane AVANT le passage, et le filigrane n'avance qu'APRES la publication (S30) — republier
# apres coupure reinterroge donc la MEME fenetre et reproduit les MEMES cles. Elle avance d'un
# passage a l'autre, donc deux passages distincts ne se confondent pas. Les dimensions du groupe
# (ip, chemin, statut, methode) completent l'identite : deux groupes distincts d'une meme fenetre
# ont des cles distinctes. Le groupe n'ayant PAS de dimension temporelle, il n'existe rien de plus
# fin a mettre dans la cle — le recouvrement volontaire (LAG) reinsere donc toujours, et la regle
# `dc(path)` reste INSENSIBLE a ces doublons-la, comme avant.
envj=$(printf '%s' "$json" | jq -c --arg host "$host" --argjson ts "$ts" --arg since "$since" '
  ( .data.viewer.zones[0].httpRequestsAdaptiveGroups // [] ) as $g
  | { ts:$ts, host:$host, kind:"events",
      events: ( $g | map(
        (.dimensions // {}) as $d |
        ($d.clientIP // "")                       as $ip |
        ($d.clientRequestHTTPHost // "")          as $vh |
        ($d.clientRequestPath // "")              as $pa |
        (($d.edgeResponseStatus // 0) | tostring) as $st |
        ($d.clientRequestHTTPMethodName // "")    as $me |
        (.count // 0)                             as $c  |
        {
          ts: $ts,
          source: "cloudflare-http",
          category: "web",
          severity: 1,
          src_ip: $ip,
          message: ( "CF-HTTP " + $me + " " + $vh + $pa + " -> " + $st + " (x" + ($c|tostring) + ")" ),
          dedup: ( "cfhttp-" + $since + "-" + $ip + "-" + $pa + "-" + $st + "-" + $me ),
          fields: {
            src_ip: $ip,
            vhost:  $vh,
            path:   $pa,
            status: $st,
            method: $me,
            count:  $c,
            dir:    "inbound",
            scope:  "external"
          }
        } ) )
    }')

# avance le watermark a now-LAG (recouvrement borne : jamais de trou face au lag CF ; dedup+dc absorbent).
# S30 — l'ordre etait DEJA le bon ; le filigrane est desormais MIS EN ATTENTE et ecrit par la
# publication elle-meme. Quand la fenetre ne rend aucun evenement, il n'y a rien a publier et donc
# rien a acquitter : `plume_exit_nodata` ecrit le filigrane et sort. Ne PAS l'ecrire dans ce cas
# ferait grandir la fenetre interrogee sans fin.
adv=$(date -u -d "@$((ts - LAG))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "$nowiso")

# S36 — LE FILIGRANE NE DOIT RIEN A LA REPONSE : il vaut « maintenant moins le lag », donc il avance
# meme quand rien n'a ete compris de ce qui a ete recu. Il etait mis en attente ICI, avant que la
# reponse ne soit exploitee, et `|| echo 0` rendait 0 aussi bien pour une fenetre reellement calme
# que pour une reponse illisible : la sortie « rien a signaler » avancait alors la fenetre PAR-DESSUS
# des requetes en erreur qui ne seraient plus jamais interrogees. Le code de retour de `jq` est
# desormais lu, et la mise en attente ne vient qu'apres.
if ! n=$(printf '%s' "$envj" | jq -r '.events | length' 2>/dev/null); then
  plume_lecture_echouee cloudflare-http forme_inconnue "reponse GraphQL recue mais non exploitable : la fenetre depuis $since n'a pas ete lue, le filigrane N'AVANCE PAS"
fi
state_stage "$WM" "$adv"

if [ "${n:-0}" -gt 0 ]; then
  spool_write_then_ack "cloudflare-http-$ts.json" "$envj" nl
else
  plume_exit_nodata
fi
