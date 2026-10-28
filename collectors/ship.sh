#!/bin/sh
# plume-source: ship
# plume-emits: fields=
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

# P10.32-i — LE CLAIR NE PART PAS VERS UN HOTE DISTANT SANS QU'ON L'AIT CHOISI. La porte (https://
# inchange, `http://` admis vers la boucle locale seule, sinon REFUS nomme sauf `PLUME_SHIP_ALLOW_PLAINTEXT=1`)
# vit dans lib.sh (`plume_verifier_le_transport`, P10.33-a) : `prom-scrape.sh` juge par le meme texte.
# Ici, le refus sort en code 2 AVANT de toucher au spool (rien n'est evince, rien n'est expedie : tout
# est conserve pour le passage qui suivra la correction).
if [ -n "${PLUME_CENTRAL:-}" ]; then
  plume_verifier_le_transport ship "$PLUME_CENTRAL" "Rien n'est expedie ni evince : le spool est conserve." || exit 2
fi

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
  # P10.32-i — LE PARCOURS NE FAIT PLUS CONFIANCE AUX NOMS. Il etait `for f in $(ls -tr …)` : un nom a
  # espace (`a /chemin/x.json`) eclatait en deux mots, dont un CHEMIN ABSOLU que `rm -f` supprimait HORS
  # du spool. Desormais : `ls` liste le REPERTOIRE (des noms nus, jamais un `/`, du plus ancien au plus
  # recent ; `-q` rend `?` pour un caractere non imprimable, donc un nom a saut de ligne ne designe plus
  # rien), une ligne = un nom, et seul un fichier REGULIER qui n'est pas un lien symbolique est evince —
  # le meme ensemble que celui que `find -type f` a compte ci-dessus.
  # shellcheck disable=SC2012  (lecture ligne a ligne d'un listage par date : `find` n'en a pas de POSIX)
  # Le tube fait tourner la boucle dans un sous-shell : c'est elle qui IMPRIME son compte.
  evinces=$( { ls -1qtr "$SPOOL" 2>/dev/null || :; } | {
    _c=0
    while [ "$_c" -lt "$surplus" ] && IFS= read -r _nom; do
      case "$_nom" in .*|*/*) continue ;; *.json|*.ndjson) : ;; *) continue ;; esac
      _f="$SPOOL/$_nom"
      [ -f "$_f" ] && [ ! -L "$_f" ] || continue
      rm -f "$_f" && _c=$((_c + 1))
    done
    echo "$_c"
  } )
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
# P10.32-i — LE FICHIER EXPEDIE EST CELUI QUI A ETE JUGE, PAS CELUI QUI PORTE SON NOM AU MOMENT DE LIRE.
# Le parcours jugeait le nom (`[ -f ] && [ ! -L ]`) puis curl ouvrait ce nom un instant plus tard. Le
# spool est inscriptible par le groupe `soc` (2770 root:soc : le relais MinIO y ecrit sous `User=soc`),
# et ce script tourne en root : entre le jugement et la lecture, un membre du groupe pouvait remplacer
# le fichier par un lien symbolique (ou un lien dur, ou un tube) et faire POSTER au central, en root, le
# contenu de n'importe quel fichier de l'hote. Desormais le fichier est d'abord RENOMME dans
# `$STATE/envoi/` (racine seule : `state` est 0750 root:root), puis juge LA, ou plus personne ne peut le
# substituer : un fichier regulier a un seul lien part ; tout autre chose (substitue pendant la
# fenetre) est mis a l'ecart dans `$STATE/refuses/`, compte et avoue, jamais ouvert. Un fichier
# conserve pour reessai retourne au spool. Un renommage interrompu (coupure entre `mv` et l'envoi) est
# repris au passage suivant : un fichier juge resté dans `envoi/` revient d'abord au spool (voie durable),
# tout autre objet y est mis a l'ecart sans etre ni lu ni `chmod` (un `chmod` suivrait un lien).
ENVOI="$STATE/envoi"
substitues=0
# un fichier REGULIER a un seul lien ; `find` sans -L ne suit pas un lien : `-type f` ecarte lien, tube,
# repertoire ; `-links 1` un lien dur — quand spool et etat sont sur le MEME volume (entre deux volumes,
# `mv` recopie : le lien dur devient un fichier a un lien, que seul `fs.protected_hardlinks` borne).
# Ne se juge QUE dans `$ENVOI`, ou personne d'autre n'ecrit.
est_un_fichier_juge() { [ -n "$(find "$1" -prune -type f -links 1 -print 2>/dev/null)" ]; }
ecarter_un_substitue() { # $1 = objet dans $ENVOI qui n'est pas un fichier juge : jamais lu, jamais chmod
  mkdir -p "$STATE/refuses" 2>/dev/null && mv -f "$1" "$STATE/refuses/" 2>/dev/null || rm -f "$1"
  substitues=$((substitues + 1))
  echo "ship: ${1##*/} -> REMPLACE pendant le passage (lien, lien dur ou tube) : jamais lu, mis à l'écart dans $STATE/refuses/" >&2
}
# Le nom rendu est LIBRE dans le spool pendant tout l'envoi : un membre de `soc` peut y poser un lien vers
# un repertoire. `spool_publish_file` renomme par `mv -T` : le lien est remplace, jamais suivi.
# Un VRAI repertoire a ce nom fait echouer la remise : le fichier reste dans l'abri (jamais supprime,
# jamais depose ailleurs) jusqu'au passage ou le nom est libre.
remettre_au_spool() { # $1 = fichier JUGE dans $ENVOI -> republie au spool par la voie durable
  spool_publish_file "$1" "${1##*/}" 2>/dev/null || :
  if [ -e "$1" ]; then
    echo "ship: ${1##*/} -> remise au spool impossible : reste dans $ENVOI, repris au prochain passage" >&2
  fi
  return 0
}
reprendre_un_envoi_interrompu() {
  for _r in "$ENVOI"/* "$ENVOI"/.[!.]*; do
    [ -e "$_r" ] || [ -L "$_r" ] || continue
    if est_un_fichier_juge "$_r"; then remettre_au_spool "$_r"; else ecarter_un_substitue "$_r"; fi
  done
}
prendre_pour_envoi() { # $1 = chemin dans le spool -> 0 et `_pe` = chemin prive juge, 1 sinon
  # Appelee DIRECTEMENT (jamais dans `$(…)`) : le compte `substitues` doit survivre a l'appel.
  _pe="$ENVOI/${1##*/}"
  mv -f "$1" "$_pe" 2>/dev/null || return 1
  est_un_fichier_juge "$_pe" && return 0
  ecarter_un_substitue "$_pe"
  return 1
}
ship_glob() { # $1 = extension (json, ndjson), $2 = endpoint
  # P10.32-i — seul le motif est hors guillemets : un chemin de spool a espace ne s'eclate plus. Un lien
  # symbolique n'est JAMAIS expedie (il ferait poster au central le contenu de sa cible, n'importe ou
  # sur l'hote) ni supprime ; un nom qui n'est pas un fichier regulier (repertoire, tube) est ignore.
  for f in "$SPOOL"/*."$1"; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    case "${f##*/}" in .*) continue ;; esac
    prendre_pour_envoi "$f" || continue
    p=$_pe
    code=$(post_file "$p" "$2")
    case "$code" in
      202) rm -f "$p"; sent=$((sent + 1)) ;;
      400|413|415|422) ecarter_un_refus_permanent "$p" "$code" || { echo "ship: $f -> HTTP $code (refus permanent, mise à l'écart impossible : conservé)" >&2; remettre_au_spool "$p"; } ;;
      *) echo "ship: $f -> HTTP $code (conservé pour réessai)" >&2; remettre_au_spool "$p" ;;
    esac
  done
}

# Sans repertoire prive, aucun fichier ne peut etre juge a l'abri : REFUS nomme, code 2, spool conserve
# (jamais un repli silencieux sur la lecture en place, qui rouvrirait la substitution).
if ! { mkdir -p "$ENVOI" 2>/dev/null && chmod 700 "$ENVOI" 2>/dev/null; }; then
  echo "ship: REFUS : répertoire privé d'envoi $ENVOI impossible à créer (PLUME_STATE inscriptible attendu) — rien n'est expédié, le spool est conservé." >&2
  exit 2
fi
# Le lien dur n'est ecarte (`-links 1`) que si spool et abri partagent un volume : entre deux volumes, `mv`
# RECOPIE, et le lien dur arrive dans l'abri en fichier a un lien. Il ne reste alors que
# `fs.protected_hardlinks=1` (le noyau refuse de lier un fichier que son auteur ne peut lire ET ecrire : rien
# qu'il ne puisse deja poser lui-meme au spool). Les deux conditions reunies, la defense est OUVERTE : on le
# dit a chaque passage. Un volume illisible (`stat` absent ou en echec) ne se juge pas et ne dit rien.
# `stat -L` : un spool qui est un lien symbolique se juge sur le volume de sa CIBLE, pas sur celui du lien.
# Le sysctl se lit par `cat`, pas par `read` : sous dash, `read` sur /proc rend 1 alors qu'il a lu la valeur
# (lecture octet par octet), et le sysctl a 1 se disait « inconnu » a chaque passage. Une lecture vide ou
# en echec reste « inconnu », donc l'avertissement est dit.
dire_si_le_lien_dur_passe() {
  _vs=$(stat -L -c %d "$SPOOL" 2>/dev/null) && _ve=$(stat -L -c %d "$ENVOI" 2>/dev/null) || return 0
  [ -n "$_vs" ] && [ -n "$_ve" ] && [ "$_vs" != "$_ve" ] || return 0
  _ph=$(cat "${PLUME_PROC_ROOT:-/proc}/sys/fs/protected_hardlinks" 2>/dev/null) || _ph=inconnu
  [ -n "$_ph" ] || _ph=inconnu
  [ "$_ph" = 1 ] && return 0
  echo "ship: ATTENTION : spool et $ENVOI sur deux volumes ET fs.protected_hardlinks=$_ph — un lien dur posé au spool vers un fichier de l'hôte serait recopié dans l'abri et EXPÉDIÉ ; remède : même volume, ou sysctl fs.protected_hardlinks=1" >&2
}
dire_si_le_lien_dur_passe
reprendre_un_envoi_interrompu
borner_le_spool
ship_glob json   /api/ingest
ship_glob ndjson /api/ingest/journal
# P10.32-i — l'URL n'est pas imprimee telle quelle : elle peut porter identifiant et mot de passe.
[ "$sent" -gt 0 ] && echo "ship: $sent fichier(s) -> $_PLUME_CENTRAL_AFFICHE" || true
[ "$substitues" -gt 0 ] && plume_report_availability ship unavailable spool-substitue \
  "SPOOL ALTÉRÉ : $substitues fichier(s) du spool remplacés entre leur examen et leur envoi (lien symbolique, lien dur ou tube) — aucun n'a été lu ni expédié, ils sont mis à l'écart dans $STATE/refuses/. Quelqu'un qui écrit dans le spool tente de faire lire au central un fichier de l'hôte." 2 2>/dev/null || true
[ "$refuses" -gt 0 ] && plume_report_availability ship unavailable ingest-refused \
  "REFUS PERMANENT : $refuses fichier(s) refusés par le central (4xx hors identité et cadence), mis à l'écart dans $STATE/refuses/ — leur contenu n'entrera JAMAIS tel quel ; à lire, pas à réessayer." 2 2>/dev/null || true
