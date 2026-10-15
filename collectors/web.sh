#!/bin/sh
# plume-source: web
# plume-emits: fields=action,bytes,collector,dir,dur_ms,filters,method,note,path,proto,router,scope,status,type,ua,vhost
# Capteur Plume (PLUGIN, OPT-IN) : access-logs Traefik (JSON) -> events source=web.
# Vue "trafic web" facon FortiGate : qui (src_ip reelle via Cf-Connecting-Ip / forwarded) accede a
# quel host/chemin, methode, statut, octets, duree, routeur, User-Agent. Groupable en GXQL
# ( | stats count by status / by host / by src_ip / by path ). Pre-requis : Traefik en accesslog JSON
# (deja le cas ici : --accesslog=true --accesslog.format=json). Lecture seule, AUCUNE action.
# Mode-aware : PLUME_WEB_SRC=k3s (kubectl logs) | file (chemin local). OPT-IN (non actif par defaut).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
WEBSRC="${PLUME_WEB_SRC:-k3s}"
WEB_NS="${PLUME_WEB_NS:-kube-system}"
WEB_SEL="${PLUME_WEB_SELECTOR:-app.kubernetes.io/name=traefik}"
WEB_LOG="${PLUME_WEB_LOG:-/var/log/traefik/access.log}"     # mode file
SKIP_HOST="${PLUME_WEB_SKIP_HOST:-}"                          # hosts a ignorer si <500 (liste |). ex: ingest.example.com (self-ingest)
SKIP_PATH="${PLUME_WEB_SKIP_PATH:-}"                          # DEBRUIT: prefixes de path a ignorer si <500 (liste |). ex: /v1/sys/health|/v1/sys/seal-status (poll Vault)
SKIP_ROUTER="${PLUME_WEB_SKIP_ROUTER:-}"                      # DEBRUIT: routers a ignorer si <500 (sous-chaine, liste |). ex: -agent-mtls (self-traffic mTLS de l agent)
MAX="${PLUME_WEB_MAX:-10000}"                                 # lignes lues par passage
WM="$STATE_DIR/web.watermark"
last=$(cat "$WM" 2>/dev/null || echo 0)
now=$(date +%s)
since=$((now - last + 10)); [ "$last" -eq 0 ] && since=300       # 1re fois : 5 min en arriere
[ "$since" -gt 86400 ] && since=86400

read_log() {
  case "$WEBSRC" in
    k3s)
      KC="kubectl"; command -v kubectl >/dev/null 2>&1 || KC="k3s kubectl"
      command -v "${KC%% *}" >/dev/null 2>&1 || return 1
      $KC -n "$WEB_NS" logs -l "$WEB_SEL" --since="${since}s" --tail="$MAX" --max-log-requests=5 2>/dev/null
      ;;
    file) [ -r "$WEB_LOG" ] || return 1; tail -n "$MAX" "$WEB_LOG" 2>/dev/null ;;
    *) return 1 ;;
  esac
}

# S36 — meme distinction, dite avec le mot de la famille : une lecture qui echoue n'est pas une
# source vide. Le routage etait deja le bon ; `plume_lecture_echouee` y ajoute la seule garantie qui
# manquait a la forme generique — JETER ce qui serait en attente, pour qu'aucune sortie ne puisse
# acquitter ce qu'elle n'a pas publie.
raw=$(read_log) || plume_lecture_echouee web source_illisible "source de log web illisible (PLUME_WEB_SRC=$WEBSRC) : ni fichier lisible, ni pod joignable"

# P10.32-k — BATTEMENT DE SANTE, A CHAQUE PASSAGE QUI A VU AU MOINS UNE REQUETE NEUVE, gardee ou non. La sonde
# `web` est CONTINUE (elle lit le MAX(ts) de `source=web`) et ce capteur ecarte une partie du trafic par
# construction (filtres PLUME_WEB_SKIP_*) : un passage dont tout le trafic neuf etait filtre ne publiait RIEN, et
# un site servi se lisait « capteur mort ». Le battement part donc des qu'une ligne d'acces POSTERIEURE au
# filigrane a ete lue — publiee, filtree ou coupee par le plafond. Il NE part PAS quand rien de neuf n'a ete vu :
# lecture vide (`kubectl logs` d'un selecteur sans pod rend une sortie vide et le code 0) ou journal FIGE (toutes
# ses lignes deja vues : Traefik arrete, journal d'acces coupe). Ce silence-la est le signal de la sonde, comme
# celui d'auditd sur un journal qui ne grossit plus ; un battement l'aurait couvert. LE PRIX, DIT : un site sans
# AUCUNE requete pendant un intervalle de sonde se lit muet. Pas de cle de dedoublonnage : chaque battement
# s'insere. Une lecture qui ECHOUE n'en emet pas — elle s'avoue au-dessus. Les comptes sont dans le MESSAGE : un
# champ neuf doit entrer dans l'inventaire de collecte du demon (`daemon/src/collected.rs`), que ce changement
# ne touche pas — `type` et `collector` y sont deja.
#
# P10.32-k — CE QU'UN FLOT DE REQUETES FAIT PERDRE, ET CE QUI EN EST AVOUE. Deux bornes, de natures differentes :
#  · le PLAFOND de 9000 requetes PUBLIEES par passage. Les lignes filtrees (PLUME_WEB_SKIP_*) n'y comptent pas.
#    Au-dela, une ligne est coupee : d'une seconde POSTERIEURE au filigrane, elle est relue au passage suivant ;
#    de la MEME seconde que la derniere publiee (ou d'une seconde anterieure, pods entrelaces), elle est PERDUE,
#    comptee et avouee (`collection-capped`). Ni une ligne filtree ni une ligne coupee ne fait avancer le
#    filigrane apres le plafond. Un flot NON filtre (scan, attaque volumetrique) peut donc pousser des requetes
#    reelles au-dela du plafond : celles de sa derniere seconde publiee sont perdues et avouees en nombre ; le
#    reste est reporte, et sous un flot SOUTENU le report court derriere le journal (voir la borne suivante) ;
#  · la BORNE DE LECTURE PLUME_WEB_MAX (`tail -n`, `kubectl logs --tail`) : seules les MAX dernieres lignes sont
#    lues, sans egard au filigrane. Entre deux passages, un flot plus long que MAX — filtre ou non : un sondage
#    de sante consomme cette borne comme une requete — fait sortir de la fenetre des lignes jamais lues. Elles
#    sont perdues SANS etre comptees (le capteur ne les voit pas) ; seul le battement le dit, en une phrase
#    (« borne de lecture PLUME_WEB_MAX atteinte »), quand toutes les lignes lues ont rempli la borne. C'est
#    l'angle mort : un flot filtre assez dense efface des requetes reelles et l'aveu n'en donne pas le nombre.
web_battement() {
  _wb_msg="web santé : $1 ligne(s) lue(s), $2 gardée(s), $3 filtrée(s) par PLUME_WEB_SKIP_*, $4 déjà vue(s), $5 hors journal d'accès, $6 reportée(s) au passage suivant et $7 perdue(s) au-delà du plafond de 9000 par passage"
  [ "$1" -ge "$MAX" ] 2>/dev/null && _wb_msg="$_wb_msg ; borne de lecture PLUME_WEB_MAX=$MAX atteinte, des lignes plus anciennes ont pu ne pas être lues"
  spool_write "web-health-$now.json" "$(emit_event "$(heartbeat web "$_wb_msg" '{"type":"collector-health","collector":"web"}' 0 "$now")")" nl
}
[ -n "$raw" ] || plume_exit_nodata
umask 027
tmp=$(mktemp "$SPOOL/.web.XXXXXX")
newwm=$(printf '%s\n' "$raw" | TZ=UTC awk -v last="$last" -v host="$host" -v now="$now" -v out="$tmp" -v skiphost="$SKIP_HOST" -v skippath="$SKIP_PATH" -v skiprouter="$SKIP_ROUTER" "$_PLUME_AWK_ECHAPPEMENT_JSON"'
# jesc() : l’échappement JSON de collectors/lib.sh (_PLUME_AWK_ECHAPPEMENT_JSON, P10.23-e), placé en tête de ce programme.
function sval(name,   re,v){ re="\"" name "\":\"[^\"]*\""; if(match($0,re)){ v=substr($0,RSTART,RLENGTH); sub(/^"[^"]*":"/,"",v); sub(/"$/,"",v); return v } return "" }
function nval(name,   re,v){ re="\"" name "\":-?[0-9]+"; if(match($0,re)){ v=substr($0,RSTART,RLENGTH); sub(/^"[^"]*":/,"",v); return v } return "" }
BEGIN{ n=0; buf=""; maxts=last+0; nfil=0; nvu=0; nautre=0; nreport=0; nperdu=0 }
{
  if ($0 !~ /"DownstreamStatus":/) { nautre++; next }            # garde uniquement les lignes access-log
  su=sval("StartUTC"); if(su=="") { nautre++; next }
  d=substr(su,1,19); gsub(/[-T:]/," ",d); et=mktime(d); if(et<0) { nautre++; next }
  if (et <= last) { nvu++; next }
  hostr=sval("RequestHost")
  ip=sval("request_Cf-Connecting-Ip"); if(ip=="") ip=sval("ClientHost")
  sc="external"; if(ip ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|::1|fc|fd|fe80)/) sc="internal"
  path=sval("RequestPath"); method=sval("RequestMethod"); proto=sval("RequestProtocol")
  router=sval("RouterName"); sub(/@kubernetescrd$/,"",router); sub(/-[0-9a-f]+$/,"",router)
  ua=sval("request_User-Agent")
  status=nval("DownstreamStatus"); bytes=nval("DownstreamContentSize"); durns=nval("Duration")
  durms=0; if(durns!="") durms=int(durns/1000000)
  # DEBRUITAGE : self-traffic + polling infra ecartes UNIQUEMENT si <500 -> on GARDE tout 5xx
  # (vrai incident applicatif) et tout le trafic externe. host=exact, router=sous-chaine, path=prefixe.
  if(status+0<500){ skip=0
    if(skiphost!=""){ nH=split(skiphost,AH,"|"); for(iH=1;iH<=nH;iH++) if(AH[iH]!="" && hostr==AH[iH]) skip=1 }
    if(!skip && skiprouter!=""){ nR=split(skiprouter,AR,"|"); for(iR=1;iR<=nR;iR++) if(AR[iR]!="" && index(router,AR[iR])>0) skip=1 }
    if(!skip && skippath!=""){ nP=split(skippath,AP,"|"); for(iP=1;iP<=nP;iP++) if(AP[iP]!="" && index(path,AP[iP])==1) skip=1 }
    # Une ligne filtree ne fait avancer le filigrane que SOUS le plafond : apres lui, des lignes coupees d une
    # seconde anterieure attendent d etre relues, et un filigrane pousse au-dela les perdrait sans aveu.
    if(skip) { nfil++; if (n<9000 && et > maxts) maxts=et; next }
  }
  # P10.32-k — au-dela du plafond, la ligne est COMPTEE par seconde : le filigrane ne la passe pas toujours.
  if (n>=9000) { PLAF[et]++; next }
  if (et > maxts) maxts=et
  sev=1; if(status+0>=400) sev=2; if(status+0>=500) sev=3
  s=status+0; act=(s<400)?"success":"failure"; if(s==401||s==403||s==429) act="blocked"   # action normalise (CIM)
  m="web " method " " hostr path " -> " status
  ev="{\"ts\":" et ",\"source\":\"web\",\"category\":\"web\",\"severity\":" sev ",\"src_ip\":\"" jesc(ip) "\",\"message\":\"" jesc(m) "\",\"dedup\":\"web-" jesc(su) "\",\"fields\":{\"src_ip\":\"" jesc(ip) "\",\"vhost\":\"" jesc(hostr) "\",\"scope\":\"" sc "\",\"path\":\"" jesc(path) "\",\"method\":\"" method "\",\"status\":\"" status "\",\"action\":\"" act "\",\"bytes\":\"" bytes "\",\"dur_ms\":\"" durms "\",\"proto\":\"" proto "\",\"router\":\"" jesc(router) "\",\"ua\":\"" jesc(ua) "\",\"dir\":\"inbound\"}}"
  if(n>0) buf=buf ","; buf=buf ev; n++
}
END{ if(n>0) printf "{\"ts\":%d,\"host\":\"%s\",\"kind\":\"events\",\"events\":[%s]}\n", now, host, buf > out
  # Une ligne coupee dont la seconde est POSTERIEURE au filigrane sera relue au passage suivant ; une ligne de la
  # meme seconde que lui (ou d une seconde anterieure, journaux de plusieurs pods entrelaces) ne le sera jamais.
  for (e in PLAF) { if (e+0 > maxts) nreport += PLAF[e]; else nperdu += PLAF[e] }
  print maxts, NR, n, nfil, nvu, nautre, nreport, nperdu }')
# Le filigrane, puis les comptes du passage (lignes lues, gardees, filtrees, deja vues, hors journal, coupees par le
# plafond et reportees, coupees et perdues).
w_lus=0; w_gardes=0; w_filtres=0; w_vus=0; w_autres=0; w_report=0; w_perdu=0
read -r newwm w_lus w_gardes w_filtres w_vus w_autres w_report w_perdu <<EOF
$newwm
EOF
# Une requete neuve vue (publiee ou filtree ; une ligne n'est coupee par le plafond qu'apres 9000 publiees) : la
# source vit, le battement part. Sinon, rien.
if [ $(( ${w_gardes:-0} + ${w_filtres:-0} )) -gt 0 ]; then
  web_battement "${w_lus:-0}" "${w_gardes:-0}" "${w_filtres:-0}" "${w_vus:-0}" "${w_autres:-0}" "${w_report:-0}" "${w_perdu:-0}"
fi
if [ "${w_perdu:-0}" -gt 0 ]; then
  plume_collecte_tronquee web plafond-de-lignes "$w_perdu" \
    "9000 requetes publiees par passage ; les lignes coupees de la meme seconde que la derniere publiee (ou d'une seconde anterieure) ne seront pas relues, le filigrane les a passees. Les lignes coupees d'une seconde posterieure sont relues au passage suivant."
fi

# S30 — l'ordre etait DEJA le bon ; le filigrane est MIS EN ATTENTE et ecrit par la publication
# elle-meme. Quand il n'y a aucune ligne a publier, c'est l'enveloppe de config de fin — toujours
# emise — qui l'ecrit : un capteur n'a jamais le geste d'acquitter a sa disposition.
state_stage "$WM" "${newwm:-$last}"
if [ -s "$tmp" ]; then spool_publish_then_ack "$tmp" "web-$now.json"; else rm -f "$tmp"; fi

# --- CHANTIER whitelists->webui : AUTO-REPORT de config (source=web category=config) --------------
# Surface les filtres de CE collecteur dans le panneau read-only « Suppressions & whitelists actives ».
# Le daemon garde la VISIBILITE ; le CONTROLE reste ICI (frontiere hote). Dedup par empreinte de config
# -> ne re-emet un event QUE si la config change (pas de spam). type=collection-reducing (drop <500).
cfg_fields=$(printf '{"type":"collection-reducing","collector":"web","filters":{"skip_host":"%s","skip_path":"%s","skip_router":"%s","max_lines":"%s","src":"%s"},"note":"drops <500 matching host/path/router — collecte reduite, controle a la frontiere hote"}' \
  "$(json_escape "$SKIP_HOST")" "$(json_escape "$SKIP_PATH")" "$(json_escape "$SKIP_ROUTER")" "$(json_escape "$MAX")" "$(json_escape "$WEBSRC")")
cfg_dd="cfg-web-$(printf '%s' "$cfg_fields" | cksum | cut -d' ' -f1)"
spool_write_then_ack "config-web-$now.json" "$(printf '{"ts":%s,"host":"%s","kind":"events","events":[{"ts":%s,"source":"web","category":"config","severity":0,"message":"config collecteur web (filtres de collecte)","dedup":"%s","fields":%s}]}' \
  "$now" "$host" "$now" "$cfg_dd" "$cfg_fields")"
