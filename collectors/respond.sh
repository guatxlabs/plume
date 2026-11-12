#!/bin/sh
# plume-source: aucune
# plume-emits: fields=
# Agent Plume — responder : applique SUR CET HOTE les actions (ban/unban IP) decidees par le central.
# Modele pull (pas d'entree reseau sur l'agent) : GET /api/actions/pending?host=... -> applique -> POST result.
# OPT-IN (PLUME_RESPONDER=1). DRY-RUN par defaut (PLUME_RESPONDER_APPLY=1 pour appliquer reellement).
# Delegue l'enforcement a l'IPS existant : CrowdSec (cscli) > fail2ban > nft (fallback). Portable (sh + curl).
# LISTE D EPARGNE, FAIL-CLOSED SUR LE BAN : les IP a NE JAMAIS bannir sont une PROTECTION. Quand
# cette liste n est pas lisible, aucun ban n est applique et le refus est NOMME au central (cause
# dans l ensemble ferme source_absente / source_refusee / source_illisible). Un `unban_ip` n y est
# PAS soumis : il ne baisse aucune defense, et le refuser verrouillerait l operateur.
# `P11.25-a` — LA DUREE DU BAN EST CELLE QUE SERT LE CENTRAL. Si l hote sait lire du JSON (jq, sinon
# python3 -I), la file est demandee en JSON par ligne (`Accept: application/x-ndjson`) et chaque `ban_ip`
# porte `ban_ttl_s` (entier de secondes, 1..31536000) : CrowdSec la recoit en `-d <n>s`, nft en timeout
# d element dans le set `inet plume blocklist_ttl`, fail2ban ne la porte pas (bantime de la jail) et le
# resultat remis le DIT. Sur nft, un ban plus court ne raccourcit JAMAIS un ban en cours : il est conserve,
# ou allonge, et le resultat remis dit lequel (`nft_poser_sans_raccourcir`). Une valeur hors contrat sur un
# `ban_ip` => `failed` avec la cause, rien applique.
# Repli sur PLUME_BAN_DURATION SEULEMENT si la duree n est pas servie (central en TSV, ou aucun lecteur
# JSON sur l hote), et le resultat remis le dit avec sa cause. Une reponse non-200 (ou curl en echec)
# n est JAMAIS lue comme une file : journal stderr nomme, code de sortie 3, rien execute. Detail plus bas.
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

# ================================================================================================
# `P10.33-a` — LES ORDRES NE SE LISENT PAS EN CLAIR SUR LE RESEAU.
# ------------------------------------------------------------------------------------------------
# CE QUI SE PASSAIT. `ship.sh` refusait deja `http://` vers un hote distant (`P10.32-i`), mais ce script
# lisait la liste des actions en attente, puis les EXECUTAIT EN ROOT (cscli, fail2ban, nft), sur le meme
# `PLUME_CENTRAL` en `http://` distant, sans un mot : le jeton partait en clair, et un intermediaire
# pouvait REPONDRE A LA PLACE du central — un ban sur l adresse de son choix, applique par cet hote.
# CE QUI EST FAIT, AVANT TOUT APPEL AU CENTRAL (rejeu, liste, remise) : la MEME porte que `ship.sh` —
# `https://` accepte, `http://` vers 127.0.0.0/8, ::1 ou localhost accepte, tout autre `http://` (ou
# une adresse sans schema) REFUSE sur stderr, code 2, AUCUNE action recuperee ni executee, sauf
# l opt-in EXPLICITE `PLUME_SHIP_ALLOW_PLAINTEXT=1` (la meme variable : un seul choix a apprendre ; il
# se pose par fichier d environnement, donc par unite), qui passe avec un avertissement.
# UNE COPIE, PAS UN EMPRUNT : cet enforcer ne source pas la bibliotheque des capteurs (cf. plus haut) ;
# la garde `check_a_collector_escapes_its_json_and_never_ships_or_listens_open.py` joue le MEME corpus
# d URL sur cette copie et sur la porte partagee des capteurs : c est elle qui tient leur egalite.
resp_hote_en_boucle_locale() { # $1 = hote (sans crochets) -> 0 si boucle locale
  case "$1" in
    localhost|::1) return 0 ;;
    127.*) : ;;
    *) return 1 ;;
  esac
  case "$1" in *[!0-9.]*|*..*|*.) return 1 ;; esac
  _bl_points=$(printf '%s' "$1" | tr -cd . | wc -c | tr -d ' ')
  [ "$_bl_points" = 3 ]
}
# resp_verifier_le_transport <url> — 0 si admis, 1 (refus ecrit sur stderr) sinon. Seuls le schema et
# l hote sont imprimes : une URL peut porter identifiant et mot de passe.
resp_verifier_le_transport() {
  case "$1" in
    *://*) _vt_schema=${1%%://*}; _vt_reste=${1#*://} ;;
    *) _vt_schema=""; _vt_reste=$1 ;;
  esac
  _vt_aut=${_vt_reste%%/*}; _vt_aut=${_vt_aut%%\?*}; _vt_aut=${_vt_aut%%#*}; _vt_aut=${_vt_aut##*@}
  case "$_vt_schema" in
    [Hh][Tt][Tt][Pp][Ss]) return 0 ;;
    [Hh][Tt][Tt][Pp]|"") : ;;
    *[!A-Za-z0-9+.-]*) echo "respond: REFUS : PLUME_CENTRAL — schema illisible (https:// attendu)" >&2; return 1 ;;
    *) echo "respond: REFUS : PLUME_CENTRAL — schema $_vt_schema:// non pris en charge (https:// attendu)" >&2; return 1 ;;
  esac
  case "$_vt_aut" in
    \[*\]*) _vt_hote=${_vt_aut#\[}; _vt_hote=${_vt_hote%%\]*} ;;
    *) _vt_hote=${_vt_aut%%:*} ;;
  esac
  _vt_hote=$(printf '%s' "$_vt_hote" | tr 'A-Z' 'a-z')
  resp_hote_en_boucle_locale "$_vt_hote" && return 0
  if [ "${PLUME_SHIP_ALLOW_PLAINTEXT:-0}" = 1 ]; then
    echo "respond: AVERTISSEMENT : ordres lus EN CLAIR depuis $_vt_hote (PLUME_SHIP_ALLOW_PLAINTEXT=1) — jeton lisible et actions falsifiables sur le reseau" >&2
    return 0
  fi
  echo "respond: REFUS : PLUME_CENTRAL parle EN CLAIR a l hote distant '$_vt_hote' (jeton lisible, et un intermediaire peut injecter des actions executees en root). Utilisez https://, ou posez PLUME_SHIP_ALLOW_PLAINTEXT=1 pour l accepter en connaissance de cause. Aucune action n est recuperee ni executee, aucun verdict n est remis." >&2
  return 1
}

[ "${PLUME_RESPONDER:-0}" = "1" ] || exit 0            # desactive tant que non explicitement active
CENTRAL="${PLUME_CENTRAL:?PLUME_CENTRAL requis}"
resp_verifier_le_transport "$CENTRAL" || exit 2
HOSTN="${PLUME_HOST_LABEL:-$(hostname)}"
APPLY="${PLUME_RESPONDER_APPLY:-0}"                     # 0 = dry-run meme pour une action 'reelle' (securite)
BACKEND="${PLUME_BAN_BACKEND:-auto}"
JAIL="${PLUME_FAIL2BAN_JAIL:-sshd}"
DUR="${PLUME_BAN_DURATION:-4h}"
ALLOWFILE="${PLUME_RESPONDER_ALLOW:-/etc/plume/responder.allow}"   # IP a NE JAMAIS bannir (1/ligne)
# Un chemin POSE par l operateur et un chemin par DEFAUT ne portent pas la meme promesse : le
# premier absent est une liste promise qui manque, le second absent est un hote qui ne tient
# simplement pas de liste. `verdict_liste_epargne` en tire deux verdicts differents.
ALLOW_CONFIGUREE=0; [ -n "${PLUME_RESPONDER_ALLOW:-}" ] && ALLOW_CONFIGUREE=1
# PLUME_HOST_HEADER : override Host (central in-cluster atteint par ClusterIP). Sans espace -> split sh-safe.
HH=""; [ -n "${PLUME_HOST_HEADER:-}" ] && HH="-H Host:$PLUME_HOST_HEADER"
# mTLS optionnel (cert client agent) vers le central : mêmes variables PLUME_TLS_* que ship.sh.
TLS=""; [ -n "${PLUME_TLS_CACERT:-}" ] && TLS="$TLS --cacert $PLUME_TLS_CACERT"; [ -n "${PLUME_TLS_CERT:-}" ] && TLS="$TLS --cert $PLUME_TLS_CERT"; [ -n "${PLUME_TLS_KEY:-}" ] && TLS="$TLS --key $PLUME_TLS_KEY"

# hote du central (pour ne jamais le bannir) : retire schema + port de PLUME_CENTRAL
CENTRAL_HOST=$(printf '%s' "$CENTRAL" | sed -e 's#^[a-z]*://##' -e 's#[:/].*$##')

esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n\r\t' '   '; }

is_ip() { printf '%s' "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*$'; }
protected() {            # 0 = IP reservee/centrale (ne pas bannir) : loopback/RFC1918/lien-local/central
  ip="$1"                # la LISTE D EPARGNE, elle, se lit par `verdict_liste_epargne` (trois cas)
  case "$ip" in
    127.*|10.*|192.168.*|169.254.*|0.*|255.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    ::1|fe80:*|fc[0-9a-fA-F]*:*|fd[0-9a-fA-F]*:*) return 0 ;;
  esac
  [ -n "$CENTRAL_HOST" ] && [ "$ip" = "$CENTRAL_HOST" ] && return 0
  return 1
}

# ================================================================================================
# LA LISTE D EPARGNE EST UNE PROTECTION : SA LECTURE NE PEUT PAS ECHOUER EN SILENCE.
# ------------------------------------------------------------------------------------------------
# FORME PRECEDENTE : `[ -r "$F" ] && grep -qxF "$ip" "$F" 2>/dev/null && return 0`, puis `return 1`.
# QUATRE faits distincts y tombaient sur la MEME branche — celle qui autorise le ban : (a) la liste
# a ete lue et l IP n y est pas, (b) le fichier n existe pas, (c) il existe mais l acces est refuse,
# (d) la recherche elle-meme a echoue (un REPERTOIRE a la place du fichier, une erreur d E/S : `-r`
# les passe, et sous root il passe meme un mode 000). Seul (a) est un fait ; les trois autres sont
# des NON-REPONSES, et elles rendaient la reponse la plus permissive — le ban partait, et son
# resultat remontait au central comme un succes ordinaire. La protection disparaissait donc
# exactement au moment ou quelque chose n allait deja pas.
#
# VOCABULAIRE FERME DES CAUSES, LES MEMES MOTS QUE LE RESTE DU PRODUIT (cote demon comme cote
# capteurs). Il est REECRIT ici et non emprunte : cet enforcer ne depend d AUCUNE bibliotheque
# (cf. l en-tete), et une garde de CI verifie qu il n en depend toujours pas. Trois lignes de
# duplication coutent moins qu une garde affaiblie.
RESP_CAUSES="source_absente source_refusee source_illisible forme_inconnue"

# _resp_illisible <cause> — LA CARDINALITE EST BORNEE ICI : une cause hors de l ensemble ferme est
# ramenee a `source_illisible` plutot que de devenir une surface libre. Le detail non borne (chemin
# tente, message du systeme) ne vit que dans le texte du refus, lu par un humain.
_resp_illisible() {
  case " $RESP_CAUSES " in
    *" $1 "*) printf 'illisible:%s' "$1" ;;
    *)        printf 'illisible:source_illisible' ;;
  esac
}

# verdict_liste_epargne <fichier> <configuree:0|1> <ip> — rend UN mot d un ensemble a TROIS cas, sur
# la sortie standard, SANS valeur par defaut :
#   epargnee           l IP figure dans la liste                     -> ne pas bannir
#   hors-liste         la liste a ete LUE et ne contient pas l IP    -> le ban peut suivre son cours
#                      (liste vide, et hote sans liste, sont ce cas : ce sont de VRAIS faits)
#   illisible:<cause>  la liste n a PAS pu etre lue                  -> l appelant DOIT trancher
# PARAMETREE sur son fichier : exercable contre une arborescence fabriquee, sans /etc ni privilege.
verdict_liste_epargne() {
  _vle_f="$1"; _vle_cfg="$2"; _vle_ip="$3"
  [ -n "$_vle_f" ] || { printf 'hors-liste'; return 0; }
  if [ ! -e "$_vle_f" ]; then
    [ "$_vle_cfg" = 1 ] && { _resp_illisible source_absente; return 0; }
    printf 'hors-liste'; return 0
  fi
  [ -r "$_vle_f" ] || { _resp_illisible source_refusee; return 0; }
  # ========================================================================================
  # UNE LISTE BIEN FORMEE POUR QUELQU UN D AUTRE N EST PAS UNE LISTE VIDE (P4.7-a)
  # ----------------------------------------------------------------------------------------
  # LE DEFAUT, MESURE SUR L ARBRE le 2026-08-27. `/etc/plume/responder.allow` est ecrit par les
  # DEUX installateurs et lu par DEUX composants, avec deux politiques qui ne se recouvrent pas :
  # cote CENTRAL il porte des NOMS DE SERVICE autorises pour `stop_service` (bootstrap.sh, et
  # `daemon/src/handlers/actions.rs` le lit ainsi) ; cote AGENT il porte des ADRESSES a NE JAMAIS
  # bannir (bootstrap-agent.sh, et ce script le lit ainsi). Les deux installateurs ne creent le
  # fichier que s il est ABSENT : sur une machine qui est a la fois centrale et agent — que rien
  # n interdit — le second herite du contenu du premier.
  # LA DIRECTION DANGEREUSE EST CELLE-CI, ET C EST POURQUOI LE CONTROLE EST ICI. Un exploitant qui
  # suit la consigne du central y ecrit `nginx.service` ; ce script cherchait alors une IP par
  # egalite de ligne, n en trouvait aucune, et concluait `hors-liste` — c est-a-dire LA BRANCHE QUI
  # BANNIT. Sa liste d IP epargnees etait vide sans qu il l ait jamais dite vide, et le premier
  # bannissement pouvait l enfermer dehors depuis sa propre console. Aucun des deux composants ne
  # se plaignait : chacun lisait un fichier bien forme POUR LUI.
  # CE QU ON FAIT : une ligne retenue qui n est pas une ADRESSE rend la liste NON LUE, avec sa
  # cause (`forme_inconnue`), donc le refus fail-closed deja ecrit plus bas. Rejeter, jamais
  # ignorer. Le predicat employe ici est `is_ip` — CELUI QUE CE SCRIPT EMPLOIE DEJA sur la cible des
  # actions, donc une seule definition DANS CE FICHIER.
  # `P4.7-b` — MAIS PAS UNE SEULE DANS LE PRODUIT, ET CETTE LIGNE A PROMIS LE CONTRAIRE. Elle
  # disait « une seule definition de qu est-ce qu une adresse, pas deux qui divergeront » : il y en
  # a DEUX (ici en ERE POSIX, la-bas en Rust), elles ne peuvent pas partager de litteral, et elles
  # DIVERGEAIENT. Ce qui est promis, mesure et tenu depuis est ecrit plus bas, au paragraphe
  # `P4.7-b` : la CONTENANCE, pas l egalite.
  # CE QUE CE CONTROLE CASSE, ET CHEZ QUI (dit, pas sous-entendu) :
  #   * une ligne CIDR (`203.0.113.0/24`) est desormais REFUSEE. Elle n a JAMAIS epargne personne —
  #     la recherche est une egalite de ligne (`grep -qxF`), donc une IP ne l a jamais appariee — et
  #     elle laissait le ban PARTIR en silence. Le refus est la meme absence de protection, mais
  #     DITE. Remede : une ligne par adresse, ou `PLUME_PROTECTED_IPS`.
  #   * un commentaire commencant EN COLONNE ZERO (`#`) et une ligne STRICTEMENT vide restent
  #     ignores. Les deux listes par defaut ne contiennent QUE cela — VERIFIE, pas suppose : les
  #     temoins `liste-par-defaut-du-central` et `liste-par-defaut-de-l-agent` de
  #     `check_enforcer_lists_fail_closed.py` EXTRAIENT le contenu des DEUX installateurs et exigent
  #     que le ban suive son cours (mesure du 2026-08-27 : 5 lignes et 8 lignes, toutes en
  #     commentaire de colonne zero, verdict `hors-liste` des deux cotes). Une ligne non commentee
  #     ajoutee demain a l un des deux defauts fait ROUGIR ce temoin.
  #   * LES ESPACES EN TETE NE SONT PAS ROGNES, ET IL FAUT LIRE CE QUE CELA COUTE : un commentaire
  #     INDENTE (`  # ...`) et une ligne de BLANCS (`   `) ne sont donc PAS ignores — ils sont
  #     REFUSES, et un seul d entre eux desarme TOUT le bannissement de cet hote (MESURE le
  #     2026-08-27, les deux cas). C est deliberement le MEME critere que la recherche : celle-ci est
  #     une egalite de ligne (`grep -qxF`), donc une ligne indentee n aurait JAMAIS epargne
  #     personne, et la refuser DIT une protection absente au lieu de la laisser croire. Le refus va
  #     dans la direction protectrice — aucun ban ne part —, et c est pour cela qu il est acceptable ;
  #     la direction inverse (rogner, puis chercher sur la ligne brute) rendrait une ligne `epargnee`
  #     que la recherche n apparie pas, c est-a-dire un ban qui part sur une IP declaree intouchable.
  #     Idem pour un fichier a fins de ligne CRLF — le retour chariot restait dans la ligne, la
  #     recherche ne l appariait jamais, et le ban partait. Le refus dit ce que le silence cachait.
  #   * LES DEUX LECTEURS NE NORMALISENT PAS PAREIL, ET C EST JUSTE : le versant demon
  #     (`allowlist_stop_service`) fait `trim()` avant de tester, parce que SA recherche porte sur la
  #     valeur ROGNEE — rogner y est donc sans effet de bord. Ici, la recherche porte sur la ligne
  #     BRUTE ; rogner y creerait l ecart decrit ci-dessus.
  #   * `P4.7-b` — ET LE PREDICAT D ADRESSE N EST PAS COMMUN NON PLUS. Cette ligne promettait « ce qui
  #     est COMMUN aux deux lecteurs est le PREDICAT D ADRESSE », et c etait FAUX : il y a DEUX textes,
  #     `is_ip` ici (ERE POSIX) et `ressemble_a_une_adresse` la-bas (Rust). Aucun littéral ne peut etre
  #     partage entre les deux, et ils ne rendaient pas le meme verdict — MESURE le 2026-08-28 : le
  #     lecteur du demon exigeait un POINT, donc `2001:db8::1` et `::1`, que CE lecteur-ci accepte
  #     parfaitement, tombaient chez lui dans la liste des NOMS DE SERVICE autorises, sans un mot.
  #     CE QUI EST PROMIS DEPUIS, ET C EST PLUS ETROIT : le classificateur du demon reconnait
  #     strictement PLUS de formes que `is_ip`, si bien qu AUCUNE ligne n est retenue par LES DEUX
  #     lecteurs. Une meme ligne peut etre refusee des deux cotes (`::ffff:...`, `%zone`, un masque) :
  #     ici cela desarme tout ban de l hote, la-bas cela refuse la liste — les deux le DISENT.
  #     LA PROMESSE N EST PLUS TENUE PAR UN COMMENTAIRE, ELLE EST MESUREE. Le corpus commun est
  #     `collectors/predicat-adresse.corpus` ; il est rejoue sur LES DEUX lecteurs, la colonne shell
  #     par `.github/scripts/check_enforcer_lists_fail_closed.py` (qui EXTRAIT `is_ip` de CE fichier
  #     et l EXECUTE), la colonne Rust par `daemon/src/tests/allowlist_du_responder.rs`. Ni l un ni
  #     l autre ne prouve seul : c est le fichier partage qui les relie.
  #   * dans TOUS ces cas, la protection etait DEJA absente : le changement ne retire rien, il rend
  #     l absence VISIBLE et bloquante. Et il ne touche pas `unban_ip`, qui ne baisse aucune defense
  #     et continue de passer (le refuser transformerait une panne de lecture en verrouillage).
  # ========================================================================================
  # `|| [ -n "$_vle_l" ]` — LA DERNIERE LIGNE SANS SAUT DE LIGNE FINAL EST LUE, ELLE AUSSI.
  # MESURE LE 2026-08-27, sur ce script tel qu il est livre : une liste dont le contenu est
  # exactement `nginx.service` SANS `\n` terminal ne faisait PAS entrer la boucle (`read` rend un
  # code non nul sur une derniere ligne non terminee, et son corps n est alors jamais execute). La
  # liste passait donc pour bien formee, `grep -qxF` rendait 1, le verdict tombait sur `hors-liste`
  # — LA BRANCHE QUI BANNIT — et `nft add element inet plume blocklist { 203.0.113.7 }` PARTAIT,
  # remonte au central en `{"status":"done"}`. LE MEME CONTENU AVEC son `\n` etait refuse.
  # Un fichier sans saut de ligne final n est pas une curiosite : `printf '%s' ...`, un editeur
  # regle ainsi, un `echo -n` d installeur en produisent un. Le versant DEMON n avait pas ce trou
  # (`str::lines()` rend la derniere ligne partielle), si bien que les deux lecteurs divergeaient
  # SUR LA LECTURE DE LA DERNIERE LIGNE. `P4.7-b` : cette phrase disait « LA OU le lot promet un
  # critere unique » — le lot ne promet PAS de critere unique, et il ne l a jamais tenu ; ce qui
  # est promis est la CONTENANCE (paragraphe `P4.7-b` ci-dessus). La divergence de saut final,
  # elle, etait bien un ecart sur la MEME question, et elle est fermee. Le temoin qui le tient est
  # `check_enforcer_lists_fail_closed.py`, scenario `liste-de-l-autre-politique-SANS-SAUT-FINAL`.
  _vle_l=""
  # `${_vle_l:-}` et non `$_vle_l` : sur un REPERTOIRE, `read` echoue SANS affecter la variable,
  # et `set -u` transformerait alors la lecture impossible en ARRET du script — c est-a-dire en
  # panne d unit la ou la partition promet un refus NOMME. Mesure : `read error: Is a directory`
  # suivi de `_vle_l: unbound variable`, code 1, aucun resultat remonte au central.
  while IFS= read -r _vle_l || [ -n "${_vle_l:-}" ]; do
    case "$_vle_l" in ''|'#'*) continue ;; esac
    is_ip "$_vle_l" || { _resp_illisible forme_inconnue; return 0; }
  done < "$_vle_f"
  # `-r` ne suffit pas : root le voit vrai sur un mode 000, et un repertoire le passe. Seul le CODE
  # DE RETOUR de la recherche separe « lue, absente » (1) d une erreur de lecture (>1).
  if grep -qxF "$_vle_ip" "$_vle_f" 2>/dev/null; then _vle_rc=0; else _vle_rc=$?; fi
  case "$_vle_rc" in
    0) printf 'epargnee' ;;
    1) printf 'hors-liste' ;;
    *) _resp_illisible source_illisible ;;
  esac
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
# `P11.25-a` — UN RETRAIT nft EST CLASSE COMME LE DEMON LE CLASSE (daemon/src/handlers/actions.rs,
# `MESSAGE_NFT_D_ABSENCE`, `classer_le_retrait_nft`). `nft delete element` rend le meme code (1) pour une adresse
# absente et pour tout autre refus : seule sa SORTIE D ERREUR les distingue, lue sous `LC_ALL=C LANG=C` (le texte de
# `strerror` est traduit hors locale C, et un message traduit n est PAS reconnu : il reste un refus).
#   code 0                                              -> `retiree`  (l adresse etait dans le set, elle n y est plus) ;
#   code 1 a 125 ET la sortie d erreur porte le message  -> `absente`  (l adresse, ou le set, n y etait pas) ;
#   tout le reste                                       -> `refus`    (autre message, message sur la sortie STANDARD
#     seulement, code 126/127 d une commande qui ne part pas, code > 128 d un nft tue par un signal meme apres avoir
#     ecrit le message) : l adresse peut rester bannie dans ce set.
# La sortie standard de nft (vide pour `delete element` sans `--echo`) part au journal de l unite, jamais dans la
# decision ni dans le resultat. Un refus est remis avec le set, le code et ce que nft a ecrit, borne a
# NFT_PART_DE_RETRAIT_OCTETS octets par set (coupe sur un caractere, `[...]` dit la coupe) : quand nft est le seul
# backend, le plan, la part du premier set et l etiquette du second (set et code) tiennent sous la borne de 500
# caracteres que le central applique au resultat, si bien qu un premier set bavard ne masque pas le second. Les
# sorties de fail2ban et de CrowdSec, qui les precedent, ne sont pas bornees ici.
NFT_MESSAGE_D_ABSENCE="No such file or directory"
NFT_PART_DE_RETRAIT_OCTETS=120
# Tout caractere de controle (pas seulement le saut de ligne) devient une espace : le resultat part en JSON, et `esc`
# n echappe que le saut de ligne, le retour chariot et la tabulation ; un autre caractere de controle brut (sequence
# de couleur, cloche) ferait refuser le corps par le central, et le verdict ne serait jamais remis.
# <code> <sortie d erreur de nft> -> 0 si c est l absence, sinon 1 et NFT_REFUS_TEXTE = « (cause) : ecrit borne »
nft_lire_l_echec() {
  _cr_code=$1
  case "$2" in
    *"$NFT_MESSAGE_D_ABSENCE"*) if [ "$_cr_code" -lt 126 ]; then return 0; fi ;;
  esac
  _cr_cause="code $_cr_code"
  if [ "$_cr_code" -gt 128 ]; then _cr_cause="$_cr_cause, nft interrompu par le signal $((_cr_code - 128))"; fi
  _cr_entier=$(printf '%s' "$2" | tr '\000-\037' ' ')
  _cr_coupe=$(printf '%s\n' "$_cr_entier" | coupe_sur_caractere "$NFT_PART_DE_RETRAIT_OCTETS")
  if [ "$_cr_coupe" != "$_cr_entier" ]; then _cr_coupe="$_cr_coupe [...]"; fi
  NFT_REFUS_TEXTE="($_cr_cause) : $_cr_coupe"
  return 1
}
# <set> <adresse> -> NFT_RETRAIT (`retiree` | `absente` | `refus`) et NFT_RETRAIT_TEXTE (texte remis pour ce set)
nft_classer_le_retrait() {
  if NFT_RETRAIT_TEXTE=$(LC_ALL=C LANG=C nft delete element inet plume "$1" "{ $2 }" 3>&2 2>&1 1>&3 3>&-); then
    NFT_RETRAIT=retiree; return 0
  else
    _cr_retour=$?
  fi
  if nft_lire_l_echec "$_cr_retour" "$NFT_RETRAIT_TEXTE"; then NFT_RETRAIT=absente; return 0; fi
  NFT_RETRAIT=refus
  NFT_RETRAIT_TEXTE="REFUS du retrait dans $1 $NFT_REFUS_TEXTE"
}
# `P11.25-a` — UNE SONDE (`nft list table|set ...`) EST LUE COMME UN RETRAIT : seule l absence MESUREE (code 1 a 125 et
# le message, sous `LC_ALL=C LANG=C`) dit que l objet n existe pas, et seulement alors le retrait n est pas tente. Une
# sonde REFUSEE (autre message, signal, commande qui ne part pas) ne dit rien de l objet : le retrait est TENTE et son
# classement tranche, comme le demon qui ne sonde pas ; la sonde refusee est dite au journal de l unite. Sa sortie
# standard (la table listee) est jetee.
# <libelle de l objet> <arguments de `nft list`> -> NFT_SONDE (`present` | `absent` | `refus`)
nft_sonder() {
  _so_objet=$1; shift
  if _so_ecrit=$(LC_ALL=C LANG=C nft list "$@" 2>&1 >/dev/null); then NFT_SONDE=present; return 0; else _so_retour=$?; fi
  if nft_lire_l_echec "$_so_retour" "$_so_ecrit"; then NFT_SONDE=absent; return 0; fi
  NFT_SONDE=refus
  echo "respond: SONDE nft REFUSEE sur $_so_objet $NFT_REFUS_TEXTE ; le retrait est tente, son classement tranche" >&2
}
# UNBAN = best-effort sur TOUS les backends (une IP peut être bannie n'importe où : fail2ban/crowdsec/nft).
# `P11.25-a` — LE VERDICT, backends dans l ordre d avant, chacun tente :
#   - un retrait nft `refus` (sur `blocklist` ou sur `blocklist_ttl`) -> `failed`, QUOI QU AIENT RENDU les autres
#     backends : l adresse peut rester bannie sur cet hote, un `done` dirait le contraire au central ;
#   - nft seul backend present, aucun retrait `retiree` (deux absences, ou une absence et le set a duree inexistant)
#     -> `failed`, `LEVEE NON FAITE` : rien n a ete leve (regle du demon, `verdict_des_deux_retraits_nft`) ;
#   - DECISION : nft n a rien retire MAIS fail2ban ou CrowdSec etaient presents -> `done`, comme avant. Leurs
#     retraits gardent leur `|| true` : leur code de sortie n est pas mesure, ils ont pu lever l adresse, et un
#     `failed` affirmerait un echec que rien n a lu. Ce `done` dit « tente partout, aucun refus lu », pas « leve » ;
#   - nft absent de l hote : rien n est sonde ni tente ; table `inet plume` absente : nft n est pas tente ; set a duree
#     absent : son retrait n est pas tente (rien n existe a retirer, ce n est pas un refus) ; une sonde REFUSEE n est
#     pas une absence, le retrait est tente et classe (cf. `nft_sonder`) ; aucun backend du tout -> `failed`, comme avant.
# Le texte d un retrait `retiree` ou `absente` est celui d avant, a l octet.
unban_all() {
  OUT=""; _ua_autres=0; _ua_refus=0; _ua_retrait=0
  # `P10.21-n` : « rien retire, rien refuse, nft seul » est lu par la REPRISE d une levee interrompue (traiter_action).
  UA_RIEN_RETIRE=0; UA_OUT_AVANT_VERDICT=""
  if command -v fail2ban-client >/dev/null 2>&1; then _ua_autres=1; OUT="$OUT [f2b]$(fail2ban-client unban "$1" 2>&1 || true)"; fi
  if [ "$CSCLI_OK" = 1 ]; then _ua_autres=1; OUT="$OUT [cs]$(cscli_cmd decisions delete -i "$1" 2>&1 || true)"; fi
  if command -v nft >/dev/null 2>&1; then nft_sonder "la table inet plume" table inet plume; else NFT_SONDE=absent; fi
  if [ "$NFT_SONDE" != absent ]; then
    nft_classer_le_retrait blocklist "$1"; OUT="$OUT [nft]$NFT_RETRAIT_TEXTE"
    case "$NFT_RETRAIT" in refus) _ua_refus=1 ;; retiree) _ua_retrait=1 ;; esac
    # Les bans a duree vivent dans le second set (cf. `ensure_nft`) : son retrait est classe de meme.
    nft_sonder "le set blocklist_ttl" set inet plume blocklist_ttl
    if [ "$NFT_SONDE" != absent ]; then
      nft_classer_le_retrait blocklist_ttl "$1"; OUT="$OUT [nft-ttl]$NFT_RETRAIT_TEXTE"
      case "$NFT_RETRAIT" in refus) _ua_refus=1 ;; retiree) _ua_retrait=1 ;; esac
    fi
  fi
  [ -n "$OUT" ] || { OUT='aucun backend de ban disponible'; return 1; }
  if [ "$_ua_refus" = 1 ]; then return 1; fi
  # Ici OUT n est pas vide : sans fail2ban ni CrowdSec, c est que nft a ete tente.
  if [ "$_ua_retrait" = 0 ] && [ "$_ua_autres" = 0 ]; then
    UA_RIEN_RETIRE=1; UA_OUT_AVANT_VERDICT="$OUT"
    OUT="$OUT ; LEVEE NON FAITE : adresse absente de chaque set nft tente, rien n a ete retire"; return 1
  fi
  return 0
}
# ================================================================================================
# `P11.25-a` — NFT : UN BAN A DUREE VA DANS UN SET QUI PORTE LE TIMEOUT, L ANCIEN SET N EST PAS TOUCHE.
# ------------------------------------------------------------------------------------------------
# Le set historique `inet plume blocklist` est cree `flags interval` SANS `timeout` : un element y est
# PERMANENT, et nft ne sait pas ajouter un drapeau a un set existant. Le migrer en place voudrait dire
# le DETRUIRE (regle comprise) puis le recreer — c est-a-dire lever en silence tous les bans qu il porte.
# DECISION : le set historique reste tel quel (ses elements deja poses restent, `unban_ip` les retire
# toujours) ; un second set `inet plume blocklist_ttl` (`flags timeout`) recoit desormais chaque ban, avec
# le timeout de la duree effective (servie, ou PLUME_BAN_DURATION en repli dit), et sa propre regle `drop`
# dans la meme chaine. `ensure_nft` le cree aussi sur une table DEJA existante (hote deja equipe).
# Plus aucun ban nft n est donc pose sans duree. Une duree de repli illisible pour nft (autre chose que
# `<n>s/m/h/d`) OU NULLE (`0s`, `00h0m` : nft n emet pas de timeout nul, l element serait sans fin)
# => le ban est `failed` avec la cause, jamais pose permanent.
# La MEME regle vaut pour cscli : une duree de repli illisible ou nulle n y part jamais (`0s`, `-1h`, `abc`
# etaient passes tels quels), le ban est `failed` avec la cause, le dry-run dit NON-APPLIQUE.
# CE QUI N EST PAS TENU : un noyau ou un nft qui refuse le timeout demande rend son erreur dans le
# resultat (`failed`), il n est pas contourne.
NFT_SET_TTL=blocklist_ttl
ensure_nft() {           # cree (idempotent) la table/sets nft dedies Plume (fallback uniquement)
  if ! nft list table inet plume >/dev/null 2>&1; then
    nft add table inet plume 2>/dev/null || true
    nft add set inet plume blocklist '{ type ipv4_addr; flags interval; }' 2>/dev/null || true
    nft add chain inet plume input '{ type filter hook input priority -150; policy accept; }' 2>/dev/null || true
    nft add rule inet plume input ip saddr @blocklist drop 2>/dev/null || true
  fi
  nft list set inet plume "$NFT_SET_TTL" >/dev/null 2>&1 && return 0
  nft add set inet plume "$NFT_SET_TTL" '{ type ipv4_addr; flags timeout; }' 2>/dev/null || true
  nft add rule inet plume input ip saddr "@$NFT_SET_TTL" drop 2>/dev/null || true
}
# Une duree de ban posee par nft OU par cscli : lisible ET non nulle. D abord RIEN d autre que [0-9dhms] dans
# la valeur ENTIERE : grep juge ligne par ligne, et un PLUME_BAN_DURATION multiligne (`4h`, `}`, `add table ...`)
# passait l ERE sur sa premiere ligne puis partait a nft comme commandes. Ensuite une suite de `<n>` + unite.
# POUR NFT SEULEMENT (second argument `nft`) : `<n>d`, `<n>h`, `<n>m`, `<n>s` DANS CET ORDRE, chacun une fois au
# plus — la forme exacte que l analyseur de nft accepte : une unite repetee (`1h1h`) ou desordonnee (`30s1d`)
# passait ce controle puis echouait chez nft en erreur de syntaxe ; elle est refusee ICI, avec sa cause. cscli
# garde la regle d avant (`1h1h` lui part tel quel, comme avant ce controle : son analyseur n est pas celui de
# nft). Enfin au moins un chiffre non nul (`0h30m` passe, `0s` non). Une duree servie (`<n>s`, 1 a 31536000)
# passe toujours. La cause du refus est posee dans DUREE_CAUSE, citee par l appelant.
duree_de_ban_lisible() {   # <duree> <outil : nft | cscli>
  DUREE_CAUSE=""
  case "$1" in ''|*[!0-9dhms]*) DUREE_CAUSE="illisible (attendu <n>s, m, h ou d)"; return 1 ;; esac
  if ! printf '%s' "$1" | grep -qE '^([0-9]+[dhms])+$'; then
    DUREE_CAUSE="illisible (attendu <n>s, m, h ou d)"; return 1
  fi
  if [ "$2" = nft ] && ! printf '%s' "$1" | grep -qE '^([0-9]+d)?([0-9]+h)?([0-9]+m)?([0-9]+s)?$'; then
    DUREE_CAUSE="unite repetee ou desordonnee (nft n admet d, h, m, s que dans cet ordre, chacune une fois au plus)"
    return 1
  fi
  printf '%s' "$1" | grep -q '[1-9]' || { DUREE_CAUSE="nulle"; return 1; }
}

# ================================================================================================
# `P11.25-a` — UN BAN PLUS COURT NE RACCOURCIT JAMAIS UN BAN EN COURS (voie nft).
# ------------------------------------------------------------------------------------------------
# MESURE (nft 1.1.7, noyau 7.2, espace de noms reseau sans privilege) : `nft add element` sur une adresse
# DEJA presente dans `blocklist_ttl` REMPLACE son delai (60 s, puis 600 s, puis 10 s : le dernier gagne,
# code 0), et le resultat remis disait `done` : un ban court pose apres un ban long le raccourcissait.
# CE QUI EST FAIT, sans dependre de ce remplacement (un autre noyau peut garder l ancien delai) :
#   1. pose EXCLUSIVE (`nft create element`) : elle ne reussit que si l adresse est absente -> BAN POSE ;
#   2. adresse presente (« File exists ») : son reste est LU (`nft get element`, champ `expires` sous
#      toutes ses formes, jours a millisecondes) et compare a la duree demandee :
#      reste >= demandee -> rien n est recrit, DEJA BANNI POUR PLUS LONGTEMPS, DUREE CONSERVEE ;
#      reste <  demandee -> retrait PUIS pose dans UNE transaction (`nft -f -`) : nft l applique entiere
#      ou pas du tout, l adresse ne passe par aucun etat non banni -> BAN ALLONGE ;
#   3. l element expire entre la pose refusee et la lecture (ou avant la transaction) : UNE nouvelle
#      pose exclusive, une seule ;
#   4. element SANS FIN (ni `timeout` ni `expires` : pose sans delai, a la main) : son reste est infini, donc
#      au moins egal a toute duree demandee -> rien n est recrit, DEJA BANNI SANS FIN, DUREE CONSERVEE (`done`) ;
#   5. reste ILLISIBLE (sortie inconnue, `timeout` sans `expires`, `expires` sans valeur ou de forme inconnue,
#      lecture refusee) : rien n est recrit, l adresse reste bannie telle quelle, et le verdict est `failed` avec DUREE NON
#      APPLIQUEE — la duree demandee n est pas appliquee, un `done` le laisserait croire. Le central ecrit ce
#      verdict tel quel (riposte close, texte au registre) : rien n est re-servi ni reexecute.
# Les valeurs passees a nft (adresse, duree) ont deja passe `is_ip` et `duree_de_ban_lisible` : chiffres,
# points, deux-points, hexadecimal, unites d/h/m/s — ni espace, ni accolade, ni point-virgule, ni saut de
# ligne ne peuvent entrer dans la transaction. Le set historique permanent `blocklist` n est ni lu ni
# touche : une adresse qui y figure recoit son element a duree comme avant.
# `awk` (POSIX, mawk compris : aucune intervalle `{n}`, aucune extension gawk) lit le reste et compare en
# millisecondes, en virgule flottante : aucun depassement d entier sur un hote 32 bits.
PHRASE_BAN_POSE="BAN POSE"
PHRASE_BAN_ALLONGE="BAN ALLONGE"
PHRASE_BAN_CONSERVE="DEJA BANNI POUR PLUS LONGTEMPS, DUREE CONSERVEE"
PHRASE_BAN_CONSERVE_SANS_FIN="DEJA BANNI SANS FIN, DUREE CONSERVEE"
PHRASE_DUREE_NON_APPLIQUEE="DUREE NON APPLIQUEE, ban en cours conserve tel quel"
# <sortie de nft get element> <adresse> <duree demandee>
#   -> `conserver <reste>` | `conserver_sans_fin` | `allonger <reste>` | `illisible <cause>`
nft_juger_le_reste() {
  printf '%s\n' "$1" | awk -v ip="$2" -v dem="$3" '
    function en_ms(s,   tot, prec, num, u, r, f) {
      if (s == "") return -1
      tot = 0; prec = 0
      while (s != "") {
        num = ""
        while (s != "" && index("0123456789", substr(s, 1, 1)) > 0) { num = num substr(s, 1, 1); s = substr(s, 2) }
        if (num == "") return -1
        if (substr(s, 1, 2) == "ms") { u = "ms"; s = substr(s, 3) } else { u = substr(s, 1, 1); s = substr(s, 2) }
        if (u == "d") { r = 1; f = 86400000 }
        else if (u == "h") { r = 2; f = 3600000 }
        else if (u == "m") { r = 3; f = 60000 }
        else if (u == "s") { r = 4; f = 1000 }
        else if (u == "ms") { r = 5; f = 1 }
        else return -1
        if (r <= prec) return -1
        prec = r
        tot = tot + num * f
      }
      return tot
    }
    {
      for (i = 1; i <= NF; i++) {
        c = $i; v = (c ~ /,$/); sub(/,$/, "", c)
        if (c != ip) continue
        trouve++
        if (v) continue
        for (j = i + 1; j <= NF; j++) {
          g = $j
          if (g == "}") break
          if (g == "timeout" || g == "timeout," || g == "expires" || g == "expires,") nattr++
          if (g == "expires" && j < NF) {
            e = $(j + 1); ve = (e ~ /,$/); sub(/,$/, "", e); reste = e; nexp++
            if (ve) break
            j++; continue
          }
          if (g ~ /,$/) break
        }
      }
    }
    END {
      if (trouve == 0) { print "illisible adresse_absente_de_la_sortie"; exit }
      if (trouve > 1) { print "illisible adresse_en_double"; exit }
      # Ni `timeout` ni `expires` sur l element : pose sans delai, il ne finit jamais (forme mesuree sur nft 1.1.7).
      if (nattr == 0) { print "conserver_sans_fin"; exit }
      if (nexp != 1) { print "illisible expires_absent"; exit }
      r = en_ms(reste); d = en_ms(dem)
      if (r < 0) { print "illisible expires_de_forme_inconnue"; exit }
      # `dem` a passe `duree_de_ban_lisible` dans `enforce`, avant tout appel : d > 0.
      if (r >= d) print "conserver " reste; else print "allonger " reste
    }'
}
# <adresse> <duree> -> OUT ; 0 = applique (pose, allonge ou conserve), 1 = duree non appliquee
nft_poser_sans_raccourcir() {
  _np_ip=$1; _np_dur=$2; _np_reprise=0
  while :; do
    if _np_sortie=$(LC_ALL=C nft create element inet plume "$NFT_SET_TTL" "{ $_np_ip timeout $_np_dur }" 2>&1); then
      OUT="$PHRASE_BAN_POSE (absente de $NFT_SET_TTL, timeout $_np_dur)${_np_sortie:+ $_np_sortie}"; return 0
    fi
    case "$_np_sortie" in *'File exists'*) ;; *) OUT="$_np_sortie"; return 1 ;; esac
    _np_detail=""
    if _np_lu=$(LC_ALL=C nft get element inet plume "$NFT_SET_TTL" "{ $_np_ip }" 2>&1); then
      _np_verdict=$(nft_juger_le_reste "$_np_lu" "$_np_ip" "$_np_dur") || _np_verdict="illisible lecteur_en_echec"
    else
      case "$_np_lu" in
        *'No such file or directory'*)
          if [ "$_np_reprise" = 0 ]; then _np_reprise=1; continue; fi   # expire avant la lecture
          _np_verdict="illisible element_disparu_apres_la_reprise" ;;
        *) _np_verdict="illisible lecture_refusee"; _np_detail=" : $_np_lu" ;;
      esac
    fi
    case "$_np_verdict" in
      "conserver "*)
        OUT="$PHRASE_BAN_CONSERVE (reste ${_np_verdict#conserver } >= $_np_dur demandes), rien n est recrit"; return 0 ;;
      conserver_sans_fin)
        OUT="$PHRASE_BAN_CONSERVE_SANS_FIN (element sans expiration dans $NFT_SET_TTL, $_np_dur demandes), rien n est recrit"; return 0 ;;
      "allonger "*)
        if _np_tx=$(printf 'delete element inet plume %s { %s }\nadd element inet plume %s { %s timeout %s }\n' \
            "$NFT_SET_TTL" "$_np_ip" "$NFT_SET_TTL" "$_np_ip" "$_np_dur" | LC_ALL=C nft -f - 2>&1); then
          OUT="$PHRASE_BAN_ALLONGE (reste ${_np_verdict#allonger } < $_np_dur demandes), remplace en une seule transaction nft"; return 0
        fi
        case "$_np_tx" in
          *'No such file or directory'*)
            if [ "$_np_reprise" = 0 ]; then _np_reprise=1; continue; fi ;;   # expire avant la transaction
        esac
        OUT="DUREE NON APPLIQUEE : allongement refuse par nft, transaction annulee entiere (le ban en cours, s il n a pas expire, reste tel quel) : $_np_tx"
        return 1 ;;
      *)
        OUT="$PHRASE_DUREE_NON_APPLIQUEE : son reste n a pas pu etre lu (cause=${_np_verdict#illisible }), rien n est recrit$_np_detail"
        return 1 ;;
    esac
  done
}
# La duree EFFECTIVE du ban en cours et sa PROVENANCE, posees par `traiter_action` avant plan/enforce.
EFF_DUR="$DUR"; DUR_PROV="PLUME_BAN_DURATION de l hote"
UA_RIEN_RETIRE=0; UA_OUT_AVANT_VERDICT=""
plan() {                 # kind target -> imprime la commande qui SERAIT executee (pour dry-run + trace)
  [ "$1" = unban_ip ] && { printf 'unban %s (best-effort: fail2ban tous jails + cscli + nft plume)' "$2"; return; }
  case "$backend:$1" in
    crowdsec:ban_ip)
      if duree_de_ban_lisible "$EFF_DUR" cscli; then
        printf 'cscli decisions add -i %s -d %s -t ban -R plume-playbook [duree %s : %s]' "$2" "$EFF_DUR" "$EFF_DUR" "$DUR_PROV"
      else
        printf 'NON-APPLIQUE crowdsec : duree %s (%s) illisible ou nulle (cause : %s) — aucun ban pose' "$EFF_DUR" "$DUR_PROV" "$DUREE_CAUSE"
      fi ;;
    crowdsec:unban_ip) printf 'cscli decisions delete -i %s' "$2" ;;
    fail2ban:ban_ip)   printf 'fail2ban-client set %s banip %s [duree %s (%s) NON portee par fail2ban : le ban dure le bantime de la jail %s]' "$JAIL" "$2" "$EFF_DUR" "$DUR_PROV" "$JAIL" ;;
    fail2ban:unban_ip) printf 'fail2ban-client set %s unbanip %s' "$JAIL" "$2" ;;
    nft:ban_ip)
      if duree_de_ban_lisible "$EFF_DUR" nft; then
        printf 'nft create element inet plume %s { %s timeout %s } [duree %s : %s] ; deja banni : duree appliquee seulement si elle allonge, jamais raccourci' "$NFT_SET_TTL" "$2" "$EFF_DUR" "$EFF_DUR" "$DUR_PROV"
      else
        printf 'NON-APPLIQUE nft : duree %s (%s) illisible ou nulle comme timeout nft (cause : %s) — aucun ban permanent pose a la place' "$EFF_DUR" "$DUR_PROV" "$DUREE_CAUSE"
      fi ;;
    nft:unban_ip)      printf 'nft delete element inet plume blocklist { %s } puis blocklist_ttl' "$2" ;;  # inatteignable : unban_ip sort plus haut
    *)                 printf 'NON-SUPPORTE %s/%s' "$backend" "$1" ;;
  esac
}
enforce() {              # kind target -> applique ; renvoie 0/!=0, sortie dans $OUT
  k="$1"; t="$2"
  [ "$k" = unban_ip ] && { unban_all "$t"; return $?; }   # unban = tous backends (k3s-aware)
  case "$backend:$k" in
    crowdsec:ban_ip)
      duree_de_ban_lisible "$EFF_DUR" cscli || { OUT="duree $EFF_DUR illisible ou nulle pour cscli, rien pose (cause : $DUREE_CAUSE)"; return 1; }
      OUT=$(cscli_cmd decisions add -i "$t" -d "$EFF_DUR" -t ban -R plume-playbook 2>&1) ;;
    crowdsec:unban_ip) OUT=$(cscli decisions delete -i "$t" 2>&1) ;;
    fail2ban:ban_ip)   OUT=$(fail2ban-client set "$JAIL" banip "$t" 2>&1) ;;
    fail2ban:unban_ip) OUT=$(fail2ban-client set "$JAIL" unbanip "$t" 2>&1) ;;
    nft:ban_ip)
      duree_de_ban_lisible "$EFF_DUR" nft || { OUT="duree $EFF_DUR illisible ou nulle comme timeout nft, rien pose (cause : $DUREE_CAUSE)"; return 1; }
      ensure_nft; nft_poser_sans_raccourcir "$t" "$EFF_DUR"; return $? ;;
    nft:unban_ip)      unban_all "$t"; return $? ;;  # inatteignable : unban_ip sort plus haut ; les deux sets
    *)                 OUT="backend/kind non supporte: $backend/$k"; return 1 ;;
  esac
}

# P5.5-a : auth par l'ENTRÉE STANDARD (`-K -`), jamais en argument -> rien dans /proc/<pid>/cmdline.
# La meme authentification sert la liste, la remise et le rejeu : elle est exigee ici, une fois.
if [ -z "${PLUME_TOKEN:-}" ]; then : "${PLUME_USER:?}" "${PLUME_PASS:?}"; fi

# ================================================================================================
# `P10.21-d` — LA REMISE DU VERDICT EST LUE : UN REFUS DU CENTRAL N EST PLUS UN SUCCES MUET.
# ------------------------------------------------------------------------------------------------
# FORME PRECEDENTE : `curl ... -o /dev/null ... || true`. La reponse etait jetee et le code de sortie
# avale : quoi que le central reponde, l agent passait a la riposte suivante. Or `action_result`
# (daemon/src/handlers/actions.rs) distingue desormais l ecriture ratee (cinq cent trois nomme,
# `CAUSE_RESULTAT_NON_ENREGISTRE` : la riposte reste OUVERTE, l agent doit revenir) de l absence
# (deux cents `{"ok":false}` : riposte deja close ou d un autre hote, passer a la suivante). Jeter la
# reponse confondait les deux, et laissait des ripostes ouvertes sans que personne sache pourquoi.
# CE QUI EST FAIT, PAR STATUT HTTP (lu par `-w`, jamais devine du corps) :
#   2xx                  remis ; un `"ok":false` est dit sur la sortie d erreur, sans reessai.
#   503, 502, 504, 000   passager (ecriture ratee, passerelle, central injoignable) : reessaye
#                        RESULTAT_ESSAIS fois au plus, attente doublee a chaque fois, puis AVOUE et
#                        RETENU pour le rejeu du tour suivant (`P10.21-j`, plus bas).
#                        Reessayer est sur : la route ne clot qu une riposte encore `approved`, une
#                        seconde remise d un verdict deja pris rend l absence, jamais une double cloture.
#   tout autre code      refus definitif (400, 401, 403, 404...) : AVOUE aussitot, sans reessai ni rejeu.
#   aucun code lu        AVOUE comme illisible, sans reessai, et RETENU pour le rejeu.
# L AVEU PART SUR LA SORTIE D ERREUR, qui est le journal de l unite (systemd, `plume-respond-agent`) :
# identifiant de riposte, statut, nombre d essais et reponse du central bornee et privee de ses
# caracteres de controle. JAMAIS l en-tete d authentification ni le jeton : ils ne passent que par
# l entree standard de curl et ne sont ecrits nulle part. La boucle CONTINUE dans tous les cas : une
# riposte dont le verdict n a pas ete remis ne doit pas bloquer l application des suivantes.
RESULTAT_ESSAIS=3
RESULTAT_ATTENTE=2

# ================================================================================================
# `P10.21-j` — LA REPONSE DU CENTRAL EST LUE BORNEE, ET COUPEE SUR UNE FRONTIERE DE CARACTERE.
# ------------------------------------------------------------------------------------------------
# FORME PRECEDENTE : `_pr_rep=$(curl ... -w '\n%{http_code}')` — le corps ENTIER dans une variable,
# sans borne, puis `sed 's/^\(.\{300\}\).*/…/'`. Sous la locale C (celle d une unite systemd sans
# `LANG`), `.` est un OCTET : la coupe tombait au milieu d un caractere multi-octet (« É », « — »), et
# le journal recevait une sequence UTF-8 invalide. Sous une locale UTF-8, la meme ligne coupait a 300
# CARACTERES, jusqu a 1 200 octets : la borne dependait de l environnement.
# CE QUI EST FAIT : le corps va dans un fichier temporaire (curl l abandonne au-dela de
# RESULTAT_CORPS_FICHIER octets), seuls RESULTAT_CORPS_LU octets en sont lus, et toute coupe passe par
# `sans_caractere_entame`, qui retire une sequence UTF-8 laissee incomplete EN FIN de texte — jamais
# un caractere complet. La locale est forcee a C pour la coupe : la borne est en OCTETS, partout.
# CE QUE CECI NE TIENT PAS : `--max-filesize` n arrete un corps sans longueur annoncee qu a partir de
# curl 8.4 ; avant, seul `--max-time` borne ce qui atterrit dans le fichier (la variable, elle, reste
# bornee par la lecture).
RESULTAT_CORPS_FICHIER=65536
RESULTAT_CORPS_LU=4096
RESULTAT_CORPS_JOURNAL=300

# Octets de tete d une sequence UTF-8 (2, 3, 4 octets) et octets de suite, ecrits une fois en octal.
UTF8_SUITE=$(printf '\200-\277'); UTF8_TETE2=$(printf '\302-\337'); UTF8_TETE3=$(printf '\340-\357'); UTF8_TETE4=$(printf '\360-\364')
# stdin -> stdout : retire une sequence incomplete EN FIN de ligne (une tete seule, une tete de trois
# octets suivie d au plus un octet de suite, une tete de quatre suivie d au plus deux). Un caractere
# complet n est jamais touche : sa tete n est pas a la place que ces motifs exigent.
sans_caractere_entame() {
  LC_ALL=C sed -e "s/[$UTF8_TETE2]\$//" -e "s/[$UTF8_TETE3][$UTF8_SUITE]\{0,1\}\$//" -e "s/[$UTF8_TETE4][$UTF8_SUITE]\{0,2\}\$//"
}
# <octets> : stdin (une ligne) -> au plus N octets, jamais un caractere coupe.
coupe_sur_caractere() { LC_ALL=C cut -b "1-$1" | sans_caractere_entame; }

# Reponse du central rendue lisible au journal : une ligne, sans caractere de controle, bornee en octets.
reponse_bornee() {
  _rb_entier=$(printf '%s' "$1" | tr '\000-\037' ' ')
  _rb_coupe=$(printf '%s\n' "$_rb_entier" | coupe_sur_caractere "$RESULTAT_CORPS_JOURNAL")
  if [ "$_rb_coupe" = "$_rb_entier" ]; then printf '%s' "$_rb_coupe"; else printf '%s [...]' "$_rb_coupe"; fi
}

# Corps en ligne — le corps part en `--data-raw`, jamais en `-d`/`--data`/`--data-binary` : ces trois-la lisent un
# corps qui COMMENCE par « @ » comme un FICHIER LOCAL et l envoient (ici en root, au central).
# Le corps livre commence par « { », mais la remise ne doit pas dependre de cette forme.
# remettre_une_fois <corps-json> — UNE remise, rend `_rv_code` (statut HTTP lu, vide si aucun),
# `_rv_corps` (au plus RESULTAT_CORPS_LU octets, une ligne) et `_rv_tronque` (1 si le corps depassait).
remettre_une_fois() {
  _rv_code=""; _rv_corps=""; _rv_tronque=0
  _rv_fichier=$(mktemp 2>/dev/null) || _rv_fichier=""
  if [ -z "$_rv_fichier" ]; then
    # Sans fichier temporaire, le statut est lu et la reponse ne l est pas — c est dit, pas devine.
    echo "respond: remise du verdict sans fichier temporaire (mktemp refuse) : la reponse du central n est pas lue, son statut l est" >&2
    # shellcheck disable=SC2086  ($HH = 0 ou 2 tokens, expansion voulue)
    _rv_code=$(resp_curl_auth_stdin | curl -K - $HH $TLS -sS --max-time 15 -o /dev/null -w '%{http_code}' \
      -H 'Content-Type: application/json' --data-raw "$1" "$CENTRAL/api/actions/result" 2>/dev/null) || :
    return 0
  fi
  # shellcheck disable=SC2086  ($HH = 0 ou 2 tokens, expansion voulue)
  _rv_code=$(resp_curl_auth_stdin | curl -K - $HH $TLS -sS --max-time 15 --max-filesize "$RESULTAT_CORPS_FICHIER" \
    -o "$_rv_fichier" -w '%{http_code}' \
    -H 'Content-Type: application/json' --data-raw "$1" "$CENTRAL/api/actions/result" 2>/dev/null) || :
  _rv_corps=$(dd if="$_rv_fichier" bs="$RESULTAT_CORPS_LU" count=1 2>/dev/null | tr '\000-\037' ' ' | sans_caractere_entame) || _rv_corps=""
  _rv_suite=$(dd if="$_rv_fichier" bs="$RESULTAT_CORPS_LU" skip=1 count=1 2>/dev/null | tr '\000-\037' ' ') || _rv_suite=""
  [ -n "$_rv_suite" ] && _rv_tronque=1
  rm -f "$_rv_fichier"
  return 0
}

# ================================================================================================
# `P10.21-j` — UN VERDICT QUE LE CENTRAL N A PAS ENREGISTRE EST REJOUE, BORNE, AU TOUR SUIVANT.
# ------------------------------------------------------------------------------------------------
# CE QUI SE PASSAIT, MESURE DANS L ARBRE DU DEMON. Apres l aveu de `P10.21-d`, la riposte restait
# `approved` au central. `actions_pending` (daemon/src/handlers/actions.rs) la RE-SERT une fois sa
# reclamation perimee (`RECLAMATION_PERIMEE_S`, trois cents secondes) : l agent ne rejouait pas le
# VERDICT, il REEXECUTAIT la riposte — un second ban pose, et un second verdict qui peut differer du
# premier. Rien ne rejouait le verdict d origine, celui de l action reellement appliquee.
# CE QUI EST FAIT. Un verdict non remis (passager epuise, ou statut illisible) est RETENU dans un
# fichier d etat LOCAL de l agent, une ligne par riposte : `<id> TAB <tours> TAB <corps json>`. Le corps
# ne contient que l identifiant, le statut et le resultat — JAMAIS le jeton, l en-tete ni l hote :
# l authentification ne passe que par l entree standard de curl. Repertoire 0700, fichier 0600.
# Au debut de CHAQUE tour, avant la liste, chaque verdict retenu est remis UNE fois :
#   2xx                 remis (ou absence dite), la ligne part ;
#   passager / illisible  garde avec un tour de plus ; au REJEU_TOURS-ieme, ABANDONNE et avoue — la
#                       riposte sera alors re-servie par le central ; l aveu dit si le registre
#                       d execution (`P10.21-n`, plus bas) la porte `faite` (verdict re-remis, pas
#                       d execution) ou non (elle sera reexecutee) ;
#   tout autre code     refus definitif, avoue, la ligne part.
# Le premier echec passager ARRETE le rejeu de ce tour (le central ne repond pas : essayer les
# suivants coute quinze secondes chacun pour rien) ; les lignes non tentees gardent leur compte.
# Une riposte dont le verdict attend sa remise n est PAS reexecutee si le central la re-sert.
# Chaque aveu de verdict non retenu (etat non inscriptible, file pleine, ecriture refusee) finit de meme
# par ce que deviendra la riposte re-servie, lu dans le registre d execution.
# BORNES : REJEU_LIGNES lignes au plus (au-dela, le verdict n est PAS retenu, et c est avoue), un
# resultat de REJEU_RESULTAT_OCTETS octets au plus par ligne (coupe sur un caractere).
# Le repertoire suit le levier d etat DEJA documente des collecteurs (`PLUME_STATE`, README) : un
# sous-repertoire a lui, 0700, que l unite (`ProtectSystem=full`) laisse inscriptible.
REJEU_DIR="${PLUME_STATE:-/var/lib/plume/state}/responder"
REJEU_FICHIER="$REJEU_DIR/verdicts-a-remettre"
REJEU_TOURS=5
REJEU_LIGNES=64
REJEU_RESULTAT_OCTETS=400

etat_de_rejeu_pret() {
  [ -d "$REJEU_DIR" ] || (umask 077 && mkdir -p "$REJEU_DIR") 2>/dev/null || return 1
  chmod 700 "$REJEU_DIR" 2>/dev/null || return 1
  [ -w "$REJEU_DIR" ] || return 1
  return 0
}

# ================================================================================================
# `P10.21-n` — UNE RIPOSTE RE-SERVIE N EST JAMAIS EXECUTEE UNE SECONDE FOIS A L AVEUGLE.
# ------------------------------------------------------------------------------------------------
# Par CET agent. Sur un hote a la fois central et agent, le responder local du demon n est pas tenu par ce
# registre : voir le reste nomme sous "UN TOUR PLUS LONG QUE LA FENETRE DE RECLAMATION", plus bas.
# CE QUI SE PASSAIT. `enforce` partait sans qu aucune trace ne soit ecrite AVANT ; le seul souvenir etait
# `verdicts-a-remettre`, ecrit APRES, et seulement sur un echec passager de la remise. Le central re-sert une
# riposte reclamee sans verdict apres sa fenetre de reclamation (`RECLAMATION_PERIMEE_S`, cote demon) : elle
# etait REEXECUTEE quand l agent s etait arrete entre l execution et la retenue du verdict, quand la retenue
# renoncait (etat non inscriptible, file pleine, ecriture refusee), apres un refus definitif de la remise et
# apres un rejeu abandonne. Une levee reexecutee sur nft seul rendait alors `failed` LEVEE NON FAITE : le
# second verdict contredisait le premier.
# CE QUI EST FAIT : un REGISTRE D EXECUTION (`REGISTRE_FICHIER`, dans le repertoire 0700 du rejeu, fichier
# 0600), une ligne par riposte, champs separes par une tabulation :
#   <id> commencee <genre> <cible>                     ecrite AVANT `enforce` ;
#   <id> faite <genre> <cible> <statut> <resultat>     ecrite APRES, a la place de la precedente.
# Genre et cible sont ramenes a l ASCII imprimable sans espace et bornes ; le resultat est prive de ses
# caracteres de controle et coupe sur un caractere entier a REGISTRE_RESULTAT_OCTETS octets, comme le rejeu ;
# un identifiant de plus de REGISTRE_ID_CHIFFRES chiffres n est pas inscrit. Toute ligne est donc bornee en
# octets. Ni jeton, ni en-tete, ni hote n y entrent. Le simulacre et les refus d avant execution (duree hors
# contrat, cible non IP ou protegee, liste d epargne) n y ecrivent rien.
# A LA RE-PRESENTATION d un identifiant inscrit pour la MEME riposte (meme genre, meme cible) :
#   faite      -> AUCUNE execution : le verdict ENREGISTRE est remis de nouveau (sa forme bornee : celle
#                 que porte le registre), et le journal dit la re-remise ;
#   commencee  -> l issue de la premiere execution est inconnue : la riposte est REPRISE par le meme
#                 `enforce`, et son resultat le DIT (`PHRASE_REPRISE`). Un ban repris ne raccourcit rien
#                 (`nft_poser_sans_raccourcir`). Une levee reprise qui ne trouve l adresse nulle part (nft
#                 seul, rien retire, rien refuse) est rendue `done` : constatee absente, retrait non observe ;
#                 un REFUS de retrait reste `failed`.
# Un identifiant inscrit pour une AUTRE riposte (base du central recreee, identifiants repartis de zero) n est
# pas une re-presentation : l entree perimee est remplacee, c est dit, et la riposte suit son cours.
# UNE ENTREE PART quand le central a pris son verdict (2xx sans `"ok":false`) ou a repondu que la riposte est
# close (`"ok":false`), a la remise, au rejeu ou a la re-remise. Sinon elle reste.
# BORNE : REGISTRE_LIGNES lignes. Au-dela, la plus ancienne `faite` sort, et c est AVOUE (re-servie ensuite,
# elle serait reexecutee) ; une `commencee` ne sort JAMAIS par eviction : son issue est inconnue, l oublier
# rendrait une reprise aveugle en execution aveugle. La borne couvre les ripostes que le central peut encore
# re-servir pendant qu il ne prend aucun verdict : le tour en cours et le precedent (cent actions au plus
# chacun, re-servies passee la fenetre de reclamation) plus la file de rejeu entiere (REJEU_LIGNES).
# CE QUI N EST PAS TENU : une `commencee` ne part que lorsque le central re-sert sa riposte (elle devient `faite`) ou
# prend son verdict. Celle d une riposte que le central ne re-servira JAMAIS (annulee ou close au central apres un
# arret brutal de l agent) reste donc a vie. Apres REGISTRE_LIGNES arrets de ce genre, le registre est plein de
# `commencee` : chaque riposte suivante est executee SANS protection contre la reexecution, avouee a chaque fois
# (« registre plein de ripostes commencees »), et rien ne le repare seul — retirer le fichier rend la protection.
# REGISTRE INDISPONIBLE (etat non inscriptible, illisible, plein de `commencee`, ecriture refusee, identifiant
# trop long) : la
# riposte est EXECUTEE quand meme — un ban est une defense, il ne se suspend pas pour un etat local — et
# l aveu dit que la protection contre la reexecution est ABSENTE pour cette riposte.
# Les lectures du registre se font sous `LC_ALL=C` (la forme est jugee octet par octet), et toujours a travers
# `registre_texte`, qui retire les octets nuls : une coupure de courant peut laisser la fin d un fichier remplie de
# zeros, et `grep` tient alors le fichier entier pour binaire et n en rend plus aucune ligne.
REGISTRE_FICHIER="$REJEU_DIR/ripostes-executees"
REGISTRE_LIGNES=264
REGISTRE_ID_CHIFFRES=19
REGISTRE_GENRE_OCTETS=32
REGISTRE_CIBLE_OCTETS=64
REGISTRE_RESULTAT_OCTETS=400
PHRASE_REPRISE="REPRISE d une execution interrompue (issue de la premiere inconnue)"
PHRASE_ABSENTE_APRES_INTERRUPTION="ADRESSE CONSTATEE ABSENTE apres une execution interrompue : retrait non observe (la premiere execution a pu la lever)"
# Forme d une ligne lisible (ERE) ; toute autre ligne est ecartee au debut du tour, et ignoree a la lecture. Le
# resultat n a pas d intervalle dans l ERE (certains moteurs refusent un intervalle au-dela de 255) : sa borne est
# tenue a l ecriture.
REGISTRE_FORME=$(printf '^[0-9]{1,%s}\t(commencee\t[!-~]{1,%s}\t[!-~]{1,%s}|faite\t[!-~]{1,%s}\t[!-~]{1,%s}\t(done|failed)\t[^\t]*)$' \
  "$REGISTRE_ID_CHIFFRES" "$REGISTRE_GENRE_OCTETS" "$REGISTRE_CIBLE_OCTETS" "$REGISTRE_GENRE_OCTETS" "$REGISTRE_CIBLE_OCTETS")

registre_texte() { tr -d '\000' < "$REGISTRE_FICHIER"; }

# <octets> <valeur> -> la valeur en ASCII imprimable sans espace (tout autre octet devient `_`), bornee ; `-` si vide.
registre_jeton() {
  _rt=$(printf '%s' "$2" | LC_ALL=C tr -c '!-~' '_' | LC_ALL=C cut -b "1-$1")
  printf '%s' "${_rt:--}"
}

# registre_publier — le fichier voisin `.nouveau`, deja ecrit et ferme, remplace le registre (renommage : jamais
# un registre a moitie ecrit). 1 si refuse.
registre_publier() {
  if chmod 600 "$REGISTRE_FICHIER.nouveau" 2>/dev/null && mv -f "$REGISTRE_FICHIER.nouveau" "$REGISTRE_FICHIER" 2>/dev/null; then
    return 0
  fi
  rm -f "$REGISTRE_FICHIER.nouveau" 2>/dev/null || :
  return 1
}

# registre_reecrire <id> [ligne] — republie le registre sans les lignes de <id>, puis avec [ligne] si elle est
# donnee. 1 si l ecriture est refusee (le registre reste tel quel).
registre_reecrire() {
  _rw_texte=""
  if [ -e "$REGISTRE_FICHIER" ]; then
    [ -f "$REGISTRE_FICHIER" ] || return 1
    _rw_texte=$(registre_texte 2>/dev/null) || return 1
  fi
  if ! (umask 077 && {
      { [ -z "$_rw_texte" ] || printf '%s\n' "$_rw_texte" | LC_ALL=C grep -v "^$1	" || [ $? = 1 ]; } &&
      { [ -z "${2:-}" ] || printf '%s\n' "$2"; }
    } > "$REGISTRE_FICHIER.nouveau") 2>/dev/null; then
    rm -f "$REGISTRE_FICHIER.nouveau" 2>/dev/null || :
    return 1
  fi
  registre_publier
}

# Au debut du tour : les lignes illisibles (forme inconnue, ligne coupee par un arret brutal) sont ecartees et
# dites. Un registre qui ne se lit pas du tout n est pas repare ici : chaque riposte l avoue a sa lecture.
registre_assainir() {
  [ -e "$REGISTRE_FICHIER" ] || return 0
  if [ ! -f "$REGISTRE_FICHIER" ]; then
    echo "respond: registre d execution $REGISTRE_FICHIER illisible (pas un fichier ordinaire) : ni lu ni repare ce tour-ci" >&2
    return 0
  fi
  _ra_texte=$(registre_texte 2>/dev/null) || return 0
  [ -n "$_ra_texte" ] || return 0
  _ra_total=$(printf '%s\n' "$_ra_texte" | LC_ALL=C grep -c '') || :
  _ra_bonnes=$(printf '%s\n' "$_ra_texte" | LC_ALL=C grep -cE "$REGISTRE_FORME") || :
  [ "$_ra_total" -gt "$_ra_bonnes" ] || return 0
  _ra_ecartees=$((_ra_total - _ra_bonnes))
  if (umask 077 && { printf '%s\n' "$_ra_texte" | LC_ALL=C grep -E "$REGISTRE_FORME" || [ $? = 1 ]; } > "$REGISTRE_FICHIER.nouveau") 2>/dev/null \
      && registre_publier; then
    echo "respond: registre d execution : $_ra_ecartees ligne(s) illisible(s) ecartee(s) de $REGISTRE_FICHIER" >&2
    return 0
  fi
  rm -f "$REGISTRE_FICHIER.nouveau" 2>/dev/null || :
  echo "respond: registre d execution : $_ra_ecartees ligne(s) illisible(s) dans $REGISTRE_FICHIER, NON retiree(s) (ecriture refusee) : elles sont ignorees a la lecture" >&2
}

# registre_lire <id> <genre> <cible> -> REG_ETAT : absente | commencee | faite | autre (meme id, autre riposte)
# | illisible ; pour `faite`, REG_STATUT et REG_RESULTAT. Seule la DERNIERE ligne LISIBLE de <id> compte.
registre_lire() {
  REG_ETAT=absente; REG_STATUT=""; REG_RESULTAT=""
  [ -e "$REGISTRE_FICHIER" ] || return 0
  [ -f "$REGISTRE_FICHIER" ] || { REG_ETAT=illisible; return 0; }
  if _rl=$(registre_texte 2>/dev/null); then :; else REG_ETAT=illisible; return 0; fi
  _rl=$(printf '%s\n' "$_rl" | LC_ALL=C grep "^$1	" | LC_ALL=C grep -E "$REGISTRE_FORME" | sed -n '$p')
  [ -n "$_rl" ] || return 0
  _rl=${_rl#*	}; _rl_etat=${_rl%%	*}; _rl=${_rl#*	}; _rl_genre=${_rl%%	*}; _rl=${_rl#*	}; _rl_cible=${_rl%%	*}
  if [ "$_rl_genre" != "$2" ] || [ "$_rl_cible" != "$3" ]; then REG_ETAT=autre; return 0; fi
  if [ "$_rl_etat" = faite ]; then
    _rl=${_rl#*	}; REG_STATUT=${_rl%%	*}; REG_RESULTAT=${_rl#*	}; REG_ETAT=faite
  else
    REG_ETAT=commencee
  fi
}

# Fait de la place pour une ligne : a partir de REGISTRE_LIGNES lignes, les plus anciennes `faite` sortent, chacune
# dite. Tout ou rien : s il n y a pas assez de `faite`, rien ne sort et REG_CAUSE le dit.
registre_faire_place() {
  [ -f "$REGISTRE_FICHIER" ] || return 0
  # HORS D ATTEINTE depuis `traiter_action` sauf course : `registre_lire` vient de lire ce fichier, et un registre
  # illisible n y est jamais inscrit (`_ta_protege=0`). Garde par principe : ne jamais republier un texte non lu. Sa
  # cause est DISTINCTE de celle de `registre_lire` : un registre illisible lu comme absent se verrait au journal.
  _fp_texte=$(registre_texte 2>/dev/null) || { REG_CAUSE="registre d execution illisible au moment d y faire de la place ($REGISTRE_FICHIER)"; return 1; }
  [ -n "$_fp_texte" ] || return 0
  _fp_n=$(printf '%s\n' "$_fp_texte" | LC_ALL=C grep -c '') || :
  [ "$_fp_n" -ge "$REGISTRE_LIGNES" ] || return 0
  _fp_trop=$((_fp_n - REGISTRE_LIGNES + 1))
  _fp_faites=$(printf '%s\n' "$_fp_texte" | LC_ALL=C grep -n "^[0-9]*	faite	" | sed -n "1,${_fp_trop}p") || :
  _fp_k=0; _fp_sed=""; _fp_ids=""
  while IFS= read -r _fp_l; do
    [ -n "$_fp_l" ] || continue
    _fp_k=$((_fp_k + 1)); _fp_e=${_fp_l#*:}; _fp_ids="$_fp_ids ${_fp_e%%	*}"
    _fp_sed="$_fp_sed${_fp_l%%:*}d
"
  done <<EOF
$_fp_faites
EOF
  if [ "$_fp_k" -lt "$_fp_trop" ]; then
    REG_CAUSE="registre plein de ripostes commencees ($_fp_n lignes pour $REGISTRE_LIGNES, une commencee ne sort jamais par eviction)"
    return 1
  fi
  if ! (umask 077 && printf '%s\n' "$_fp_texte" | LC_ALL=C sed "$_fp_sed" > "$REGISTRE_FICHIER.nouveau") 2>/dev/null || ! registre_publier; then
    rm -f "$REGISTRE_FICHIER.nouveau" 2>/dev/null || :
    REG_CAUSE="ecriture refusee dans $REGISTRE_FICHIER"; return 1
  fi
  for _fp_id in $_fp_ids; do
    echo "respond: registre d execution PLEIN ($REGISTRE_LIGNES lignes) : #$_fp_id (faite, verdict jamais pris par le central) EVINCEE : si le central la re-sert, elle sera REEXECUTEE" >&2
  done
}

# registre_inscrire <id> <genre> <cible> -> 0 si la ligne `commencee` est ecrite ; sinon 1 et REG_CAUSE. Elle est
# AJOUTEE : une entree perimee du meme id (autre riposte) la precede, et `registre_lire` ne lit que la derniere
# ligne de l id ; `registre_marquer_faite` les remplace toutes par la ligne `faite`.
registre_inscrire() {
  if [ "${#1}" -gt "$REGISTRE_ID_CHIFFRES" ]; then REG_CAUSE="identifiant de plus de $REGISTRE_ID_CHIFFRES chiffres"; return 1; fi
  etat_de_rejeu_pret || { REG_CAUSE="etat local $REJEU_DIR non inscriptible"; return 1; }
  registre_faire_place || return 1
  if ! (umask 077 && printf '%s\tcommencee\t%s\t%s\n' "$1" "$2" "$3" >> "$REGISTRE_FICHIER") 2>/dev/null; then
    REG_CAUSE="ecriture refusee dans $REGISTRE_FICHIER"; return 1
  fi
  chmod 600 "$REGISTRE_FICHIER" 2>/dev/null || :
}

# registre_marquer_faite <id> <genre> <cible> <statut> <resultat> — la ligne `commencee` devient `faite`.
registre_marquer_faite() {
  _mf_res=$(printf '%s' "$5" | tr '\000-\037' ' ' | coupe_sur_caractere "$REGISTRE_RESULTAT_OCTETS")
  registre_reecrire "$1" "$(printf '%s\tfaite\t%s\t%s\t%s\t%s' "$1" "$2" "$3" "$4" "$_mf_res")"
}

# Le central a pris le verdict de <id>, ou l a dite close : son entree part.
registre_retirer() {
  [ -f "$REGISTRE_FICHIER" ] || return 0
  registre_texte 2>/dev/null | LC_ALL=C grep -q "^$1	" || return 0
  registre_reecrire "$1" && return 0
  echo "respond: #$1 verdict pris par le central, mais son entree du registre d execution n est PAS retiree (ecriture refusee) : si le central la re-servait, son verdict enregistre serait remis de nouveau" >&2
}

# Ce que deviendra la riposte <id> si le central la re-sert : la fin de chaque aveu de verdict non remis.
consequence_de_la_re_presentation() {
  if [ -f "$REGISTRE_FICHIER" ] && registre_texte 2>/dev/null | LC_ALL=C grep -E "$REGISTRE_FORME" | LC_ALL=C grep "^$1	" | sed -n '$p' | LC_ALL=C grep -q "^$1	faite	"; then
    printf 'elle ne sera PAS reexecutee : le registre d execution la porte faite, son verdict enregistre sera remis de nouveau'
  else
    printf 'elle sera REEXECUTEE (le registre d execution ne la porte pas faite)'
  fi
}

# ================================================================================================
# `P10.21-n` — UNE SEULE EXECUTION DE L AGENT A LA FOIS PAR REPERTOIRE D ETAT.
# ------------------------------------------------------------------------------------------------
# Un lancement a la main pendant le tour du minuteur traitait la meme file : deux `enforce` de la meme riposte,
# deux verdicts. Le verrou est pris avant le rejeu et la liste, et tenu jusqu a la sortie :
#   - `flock` present : verrou du noyau sur VERROU_FICHIER, rendu par le noyau quand le processus meurt, quelle
#     qu en soit la cause — un arret brutal ne laisse rien derriere lui (un enfant encore vivant, curl par
#     exemple, le tient jusqu a sa propre fin, bornee par son delai) ;
#   - sinon : un repertoire VERROU_REPERTOIRE cree par `mkdir` (atomique), qui porte l identite du porteur : pid
#     et instant de demarrage lu dans /proc quand il existe (un pid recycle n est pas le porteur). Un porteur
#     mort, recycle, ou jamais ecrit (relu apres une seconde) rend le verrou ORPHELIN : repris, et dit ; le
#     verrou est rendu a la sortie.
# Une seconde execution sort SANS RIEN TRAITER (ni rejeu, ni liste, ni remise), le dit, code 0 : le tour en cours
# fait le travail. Etat local non inscriptible, ou verrou impossible a poser : le tour continue SANS verrou, et
# c est dit — un ban est une defense, il ne se suspend pas pour un etat local.
# CE QUI N EST PAS TENU (repli `mkdir` seulement) : deux executions qui reprennent le MEME verrou orphelin au meme
# instant peuvent tourner ensemble, la reprise n etant pas atomique ; un porteur qui ne peut pas etre ecrit
# (disque plein) laisse le verrou reprenable par la suivante. `flock` n a aucun de ces deux trous.
# UN TOUR PLUS LONG QUE LA FENETRE DE RECLAMATION (`RECLAMATION_PERIMEE_S`, trois cents secondes, cote demon ; rien ne
# borne la duree d un tour en dessous : cent actions, chacune avec ses remises et leurs delais) : ses dernieres
# ripostes redeviennent reclamables avant d etre closes. Ce qui en suit depend de l hote :
#   - hote SEULEMENT agent : la re-presentation est sans effet. Seul cet hote peut les reclamer de nouveau (la
#     condition de reclamation d un agent lit `host`, qu une reclamation pose), et jamais pendant le tour : systemd
#     ne lance pas une seconde instance de l unite `oneshot` encore en cours (le minuteur, `OnUnitActiveSec=60s`,
#     n y change rien) et un lancement a la main sort au verrou. Re-servies au tour suivant, elles sont lues au
#     registre ci-dessus.
#   - hote a la fois CENTRAL et agent, sous la meme identite : le responder local du demon (`plume-daemon respond`,
#     sur son propre minuteur) prend aussi une action approuvee dont la reclamation d agent a passe la fenetre et dont
#     `host` est sa propre identite (`ACTIONS_A_RECLAMER_ICI`, daemon/src/handlers/actions.rs), et il l EXECUTE sans
#     lire ni ce verrou ni ce registre. Une riposte que l agent tient encore, ou dont le verdict n est pas encore pris
#     par le central, peut donc etre executee une seconde fois par le demon. RESTE NOMME, NON FERME : ni ce script,
#     ni sa garde ne le tiennent.
# Aucune garde ne lie la fenetre au rythme du minuteur.
VERROU_FICHIER="$REJEU_DIR/verrou"
VERROU_REPERTOIRE="$REJEU_DIR/verrou.d"
VERROU_REPERTOIRE_PRIS=0
PHRASE_VERROU_DEJA_PRIS="une autre execution de l agent tient deja le verrou : ce tour-ci ne traite RIEN (ni rejeu, ni liste, ni remise)"
# <pid> -> « pid instant » (instant de demarrage, champ 22 de /proc/<pid>/stat, lu apres le nom entre
# parentheses qui peut porter des espaces ; `-` sans /proc).
identite_du_processus() {
  _ip_debut=""
  if [ -r "/proc/$1/stat" ]; then _ip_debut=$(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f20) || _ip_debut=""; fi
  printf '%s %s' "$1" "${_ip_debut:--}"
}
# <identite lue> -> 0 si ce processus vit encore et n a pas ete remplace par un autre sous le meme pid.
porteur_vivant() {
  _pv_pid=${1%% *}; _pv_debut=${1#* }
  case "$_pv_pid" in ''|*[!0-9]*) return 1 ;; esac
  kill -0 "$_pv_pid" 2>/dev/null || return 1
  [ "$_pv_debut" = - ] && return 0
  [ "$(identite_du_processus "$_pv_pid")" = "$1" ]
}
rendre_le_verrou() {
  if [ "$VERROU_REPERTOIRE_PRIS" = 1 ]; then rm -rf "$VERROU_REPERTOIRE" 2>/dev/null || :; fi
}
prendre_le_verrou() {
  if ! etat_de_rejeu_pret; then
    echo "respond: VERROU NON PRIS (etat local $REJEU_DIR non inscriptible) : ce tour-ci continue sans verrou, une execution simultanee de l agent n est pas empechee" >&2
    return 0
  fi
  if command -v flock >/dev/null 2>&1; then
    if ! (umask 077 && : >> "$VERROU_FICHIER") 2>/dev/null; then
      echo "respond: VERROU NON PRIS ($VERROU_FICHIER non inscriptible) : ce tour-ci continue sans verrou, une execution simultanee de l agent n est pas empechee" >&2
      return 0
    fi
    exec 9>>"$VERROU_FICHIER"
    if flock -n 9; then return 0; else _pl_rc=$?; fi
    if [ "$_pl_rc" = 1 ]; then echo "respond: $PHRASE_VERROU_DEJA_PRIS ($VERROU_FICHIER)" >&2; exit 0; fi
    echo "respond: VERROU NON PRIS (flock en echec (code $_pl_rc) sur $VERROU_FICHIER) : ce tour-ci continue sans verrou, une execution simultanee de l agent n est pas empechee" >&2
    return 0
  fi
  _pl_moi=$(identite_du_processus $$)
  for _pl_essai in 1 2; do
    if (umask 077 && mkdir "$VERROU_REPERTOIRE") 2>/dev/null; then
      VERROU_REPERTOIRE_PRIS=1
      trap 'rendre_le_verrou' EXIT
      (umask 077 && printf '%s\n' "$_pl_moi" > "$VERROU_REPERTOIRE/porteur") 2>/dev/null || :
      return 0
    fi
    _pl_lu=$(cat "$VERROU_REPERTOIRE/porteur" 2>/dev/null) || _pl_lu=""
    if [ -z "$_pl_lu" ]; then
      sleep 1 2>/dev/null || :
      _pl_lu=$(cat "$VERROU_REPERTOIRE/porteur" 2>/dev/null) || _pl_lu=""
    fi
    if porteur_vivant "$_pl_lu"; then echo "respond: $PHRASE_VERROU_DEJA_PRIS ($VERROU_REPERTOIRE)" >&2; exit 0; fi
    if [ -n "$_pl_lu" ]; then _pl_qui="pid ${_pl_lu%% *}"; else _pl_qui="jamais ecrit"; fi
    echo "respond: verrou ORPHELIN repris ($VERROU_REPERTOIRE, porteur $_pl_qui disparu) : une execution precedente s est arretee sans le rendre" >&2
    rm -rf "$VERROU_REPERTOIRE" 2>/dev/null || :
  done
  echo "respond: VERROU NON PRIS ($VERROU_REPERTOIRE ni cree ni repris) : ce tour-ci continue sans verrou, une execution simultanee de l agent n est pas empechee" >&2
}

verdict_en_attente_de_remise() {   # <id> -> 0 si un verdict de cette riposte attend sa remise
  [ -f "$REJEU_FICHIER" ] || return 1
  grep -q "^$1	" "$REJEU_FICHIER" 2>/dev/null
}

retenir_pour_rejeu() {   # <id> <status> <result>
  if ! etat_de_rejeu_pret; then
    echo "respond: #$1 verdict NON RETENU pour rejeu : etat local $REJEU_DIR non inscriptible — le central re-servira la riposte apres sa fenetre de reclamation, et $(consequence_de_la_re_presentation "$1")" >&2
    return 0
  fi
  verdict_en_attente_de_remise "$1" && return 0
  _rr_n=0; [ -f "$REJEU_FICHIER" ] && _rr_n=$(grep -c '' "$REJEU_FICHIER" 2>/dev/null || :)
  if [ "${_rr_n:-0}" -ge "$REJEU_LIGNES" ]; then
    echo "respond: #$1 verdict NON RETENU pour rejeu : la file de rejeu est PLEINE ($REJEU_LIGNES verdicts en attente dans $REJEU_FICHIER) — le central re-servira la riposte, et $(consequence_de_la_re_presentation "$1")" >&2
    return 0
  fi
  _rr_resultat=$(printf '%s' "$3" | tr '\000-\037' ' ' | coupe_sur_caractere "$REJEU_RESULTAT_OCTETS")
  if ! (umask 077 && printf '%s\t0\t{"id":%s,"status":"%s","result":"%s"}\n' "$1" "$1" "$2" "$(esc "$_rr_resultat")" >> "$REJEU_FICHIER") 2>/dev/null; then
    echo "respond: #$1 verdict NON RETENU pour rejeu : ecriture refusee dans $REJEU_FICHIER — le central re-servira la riposte, et $(consequence_de_la_re_presentation "$1")" >&2
    return 0
  fi
  chmod 600 "$REJEU_FICHIER" 2>/dev/null || :
  echo "respond: #$1 verdict RETENU pour rejeu au tour suivant ($REJEU_FICHIER, $REJEU_TOURS tours au plus)" >&2
}

rejouer_les_verdicts_retenus() {
  [ -s "$REJEU_FICHIER" ] || return 0
  if ! etat_de_rejeu_pret; then
    echo "respond: rejeu IMPOSSIBLE : etat local $REJEU_DIR non inscriptible, les verdicts retenus restent en attente" >&2
    return 0
  fi
  _rj_nouveau="$REJEU_FICHIER.nouveau"
  if ! (umask 077 && : > "$_rj_nouveau") 2>/dev/null; then
    echo "respond: rejeu IMPOSSIBLE : $_rj_nouveau non inscriptible, les verdicts retenus restent en attente" >&2
    return 0
  fi
  _rj_muet=0
  while IFS='	' read -r _rj_id _rj_tours _rj_corps || [ -n "${_rj_id:-}" ]; do
    case "$_rj_id" in ''|*[!0-9]*) echo "respond: rejeu : ligne illisible ecartee de $REJEU_FICHIER" >&2; continue ;; esac
    case "$_rj_tours" in ''|*[!0-9]*) echo "respond: #$_rj_id rejeu : compte de tours illisible, ligne ecartee" >&2; continue ;; esac
    case "$_rj_corps" in "{\"id\":$_rj_id,"*) ;; *) echo "respond: #$_rj_id rejeu : corps illisible, ligne ecartee" >&2; continue ;; esac
    if [ "$_rj_muet" = 1 ]; then printf '%s\t%s\t%s\n' "$_rj_id" "$_rj_tours" "$_rj_corps" >> "$_rj_nouveau"; continue; fi
    _rj_tours=$((_rj_tours + 1))
    remettre_une_fois "$_rj_corps"
    case "$_rv_code" in
      2[0-9][0-9])
        case "$_rv_corps" in
          *'"ok":false'*) echo "respond: #$_rj_id verdict REJOUE mais NON RETENU par le central (riposte deja close, ou d un autre hote) : $(reponse_bornee "$_rv_corps")" >&2 ;;
          *) echo "respond: #$_rj_id verdict REJOUE et remis au tour $_rj_tours" >&2 ;;
        esac
        registre_retirer "$_rj_id" ;;
      503|502|504|000|'')
        _rj_muet=1
        if [ "$_rj_tours" -ge "$REJEU_TOURS" ]; then
          echo "respond: #$_rj_id verdict ABANDONNE apres $_rj_tours tours de rejeu (dernier HTTP ${_rv_code:-illisible}) : la riposte reste OUVERTE au central, qui la re-servira, et $(consequence_de_la_re_presentation "$_rj_id") : $(reponse_bornee "$_rv_corps")" >&2
        else
          printf '%s\t%s\t%s\n' "$_rj_id" "$_rj_tours" "$_rj_corps" >> "$_rj_nouveau"
          echo "respond: #$_rj_id verdict toujours NON REMIS au tour $_rj_tours/$REJEU_TOURS (HTTP ${_rv_code:-illisible}), garde pour le tour suivant" >&2
        fi ;;
      *) echo "respond: #$_rj_id verdict REJOUE et REFUSE par le central (HTTP $_rv_code), abandonne : $(reponse_bornee "$_rv_corps")" >&2 ;;
    esac
  done < "$REJEU_FICHIER"
  mv "$_rj_nouveau" "$REJEU_FICHIER" 2>/dev/null || echo "respond: rejeu : $REJEU_FICHIER non remplace, les verdicts deja remis seront rejoues (le central rendra leur absence)" >&2
}

post_result() {          # id status result (auth par stdin, jamais en argv)
  body="{\"id\":$1,\"status\":\"$2\",\"result\":\"$(esc "$3")\"}"
  _pr_essai=1; _pr_attente=$RESULTAT_ATTENTE
  while :; do
    remettre_une_fois "$body"
    case "$_rv_code" in
      2[0-9][0-9])
        [ "$_rv_tronque" = 1 ] && echo "respond: #$1 reponse du central de plus de $RESULTAT_CORPS_LU octets : seuls les $RESULTAT_CORPS_LU premiers sont lus" >&2
        case "$_rv_corps" in
          *'"ok":false'*) echo "respond: #$1 verdict NON RETENU par le central (riposte deja close, ou d un autre hote) : $(reponse_bornee "$_rv_corps")" >&2 ;;
        esac
        registre_retirer "$1"
        return 0 ;;
      503|502|504|000) ;;
      '') echo "respond: #$1 remise du verdict ILLISIBLE : aucun statut HTTP lu, la riposte peut rester ouverte au central" >&2
          retenir_pour_rejeu "$1" "$2" "$3"; return 0 ;;
      *) echo "respond: #$1 verdict REFUSE par le central (HTTP $_rv_code), non reessaye : $(reponse_bornee "$_rv_corps")" >&2; return 0 ;;
    esac
    if [ "$_pr_essai" -ge "$RESULTAT_ESSAIS" ]; then
      echo "respond: #$1 verdict NON REMIS apres $_pr_essai essais (dernier HTTP $_rv_code) : la riposte reste OUVERTE au central : $(reponse_bornee "$_rv_corps")" >&2
      retenir_pour_rejeu "$1" "$2" "$3"
      return 0
    fi
    echo "respond: #$1 remise du verdict en HTTP $_rv_code, essai $_pr_essai/$RESULTAT_ESSAIS, nouvel essai dans ${_pr_attente} s" >&2
    sleep "$_pr_attente" 2>/dev/null || :
    _pr_essai=$((_pr_essai + 1)); _pr_attente=$((_pr_attente * 2))
  done
}

# ================================================================================================
# `P11.25-a` — LA FILE EST DEMANDEE EN JSON PAR LIGNE SI CET HOTE SAIT LA LIRE, ET LE STATUT EST JUGE.
# ------------------------------------------------------------------------------------------------
# CONTRAT DU CENTRAL (docs/AGENTS-PROTOCOLE.md §6, `actions_pending` dans daemon/src/handlers/actions.rs) :
# sans `Accept` (ou `*/*`), le TSV a quatre champs `id kind target dry_run`, inchange ; sous
# `Accept: application/x-ndjson`, un objet JSON par ligne, servi avec ce type de contenu, ou `ban_ttl_s`
# (entier, secondes, jamais nul) est present sur chaque `ban_ip` et absent des autres genres ; cent
# actions au plus par tour ; 503 quand rien n a pu etre reclame.
# CE QUI SE PASSAIT : `list=$(curl -sS ...) || exit 0`, sans `-f` ni lecture du statut. Le CORPS d un 503
# (ou de tout non-200) etait parse comme une liste : une ligne qui y aurait commence par un chiffre
# serait devenue une action. Et la duree du ban etait celle de l hote (`-d $PLUME_BAN_DURATION`),
# jamais celle du playbook.
# CE QUI EST FAIT :
#   1. LECTEUR : `jq`, sinon `python3 -I` (isole : ni le repertoire courant ni l environnement Python ne
#      chargent de code), sinon AUCUN — et sans lecteur, l en-tete `Accept` n est PAS envoye : le central
#      sert le TSV, la duree n est pas servie, le repli est dit.
#   2. STATUT : le corps va dans un fichier borne, le statut et le type de contenu sont lus par `-w`.
#      curl en echec, ou tout statut autre que 200 => journal stderr nomme (statut, reponse bornee),
#      CODE DE SORTIE 3 (l unite passe `failed`, visible), AUCUNE action executee ni verdict remis.
#   3. FORME : JSON par ligne SEULEMENT si le type servi est `application/x-ndjson` ; tout autre type
#      (un central anterieur qui ignore l en-tete) => chemin TSV inchange, duree non servie, repli dit.
#   4. CHAQUE LIGNE JSON est jugee par le lecteur, qui ne rend que des enregistrements tabules a
#      champs ASCII imprimables : une ligne illisible (JSON invalide, pas un objet, `id` illisible) est
#      IGNOREE ET DITE sur stderr (numero de ligne, cause), les autres sont servies ; un `id` lisible
#      dont `kind`/`target`/`dry_run` ne sont pas du contrat => `failed` avec la cause ; champs inconnus
#      ignores. AUCUNE valeur servie n est evaluee par le shell (pas d eval) ; la cible passe toujours
#      par `is_ip`, `protected` et la liste d epargne, comme en TSV.
#   5. DUREE (ban_ip) : un entier de 1 a 31536000 => appliquee (`<n>s`) ; nulle, absente, non
#      numerique, non entiere ou hors borne => `failed` avec la cause, RIEN applique. La valeur entiere
#      est jugee sur sa VALEUR (`5400.0` est 5400 pour jq comme pour python3).
#   6. REPLI : PLUME_BAN_DURATION seulement quand la duree n est pas servie (TSV), et le resultat remis
#      (dry-run compris) porte la duree effective, sa provenance et la cause du repli.
FILE_OCTETS_MAX=262144
TYPE_FILE_JSON="application/x-ndjson"
LECTEUR_JSON=""
if command -v jq >/dev/null 2>&1; then LECTEUR_JSON=jq
elif command -v python3 >/dev/null 2>&1; then LECTEUR_JSON=python3; fi

# Une ligne servie -> UN enregistrement tabule : `B` (ligne blanche), `X<TAB>cause` (illisible, sans id),
# `F<TAB>id<TAB>cause` (id lisible, champ hors contrat), `A<TAB>id<TAB>kind<TAB>target<TAB>dry(0|1)<TAB>duree`
# ou duree = chiffres (servie, dans la borne) | `-` (pas un ban_ip) | `!cause` (hors contrat). `kind` et
# `target` sont non vides et en ASCII imprimable sans espace : aucun separateur ne peut y passer.
# Un `id` -0 est rendu `0` par les deux lecteurs (jq l ecrirait `-0`, que la boucle ne lit pas comme un
# id : la ligne serait perdue sans verdict ni journal).
# Les deux lecteurs portent la MEME table de decision ; la garde
# `check_responder_applies_the_ban_duration_served_by_the_central.py` les joue sur le meme corpus.
JQ_FILE_JSON='
def blanc: (explode | all(. == 32 or . == 9 or . == 13));
def hors_ascii: (explode | any(. < 33 or . > 126));
def entier: (type == "number" and . == floor);
if blanc then "B"
else ((try fromjson catch null) as $o
  | if ($o | type) != "object" then "X\tjson_illisible"
    elif ((($o.id | entier) and $o.id >= 0 and $o.id <= 9007199254740991) | not) then "X\tid_illisible"
    else (($o.id | floor) + 0 | tostring) as $id
      | if ($o.kind | type) != "string" or $o.kind == "" or ($o.kind | hors_ascii) then "F\t\($id)\tkind_illisible"
        elif ($o.target | type) != "string" or $o.target == "" or ($o.target | hors_ascii) then "F\t\($id)\ttarget_illisible"
        elif ($o.dry_run | type) != "boolean" then "F\t\($id)\tdry_run_illisible"
        else
          (if $o.kind != "ban_ip" then "-"
           elif ($o | has("ban_ttl_s")) | not then "!absente"
           elif $o.ban_ttl_s == null then "!nulle"
           elif ($o.ban_ttl_s | type) != "number" then "!non_numerique"
           elif ($o.ban_ttl_s | entier | not) then "!non_entiere"
           elif $o.ban_ttl_s < 1 or $o.ban_ttl_s > 31536000 then "!hors_borne"
           else ($o.ban_ttl_s | floor | tostring) end) as $duree
          | "A\t\($id)\t\($o.kind)\t\($o.target)\t\(if $o.dry_run then 1 else 0 end)\t\($duree)"
        end
    end)
end'
PY_FILE_JSON='
import json, sys
BORNE_ID = 9007199254740991
BORNE_DUREE = 31536000
def hors_ascii(s):
    return any(ord(c) < 33 or ord(c) > 126 for c in s)
def nombre(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)
def entier(v):
    return nombre(v) and (isinstance(v, int) or v.is_integer())
def refuser(nom):
    raise ValueError(nom)
def ligne(brut):
    if brut.strip(" \t\r") == "":
        return "B"
    try:
        o = json.loads(brut, parse_constant=refuser)
    except Exception:
        return "X\tjson_illisible"
    if not isinstance(o, dict):
        return "X\tjson_illisible"
    i = o.get("id")
    if not entier(i) or i < 0 or i > BORNE_ID:
        return "X\tid_illisible"
    i = str(int(i))
    k, t, d = o.get("kind"), o.get("target"), o.get("dry_run")
    if not isinstance(k, str) or k == "" or hors_ascii(k):
        return "F\t" + i + "\tkind_illisible"
    if not isinstance(t, str) or t == "" or hors_ascii(t):
        return "F\t" + i + "\ttarget_illisible"
    if not isinstance(d, bool):
        return "F\t" + i + "\tdry_run_illisible"
    if k != "ban_ip":
        duree = "-"
    elif "ban_ttl_s" not in o:
        duree = "!absente"
    elif o["ban_ttl_s"] is None:
        duree = "!nulle"
    elif not nombre(o["ban_ttl_s"]):
        duree = "!non_numerique"
    elif not entier(o["ban_ttl_s"]):
        duree = "!non_entiere"
    elif o["ban_ttl_s"] < 1 or o["ban_ttl_s"] > BORNE_DUREE:
        duree = "!hors_borne"
    else:
        duree = str(int(o["ban_ttl_s"]))
    return "\t".join(["A", i, k, t, "1" if d else "0", duree])
morceaux = sys.stdin.buffer.read().decode("utf-8", "replace").split("\n")
if morceaux and morceaux[-1] == "":
    morceaux.pop()
sys.stdout.write("".join(ligne(m) + "\n" for m in morceaux))
'
convertir_la_file_json() {   # <corps> <enregistrements> -> 0 si le lecteur a lu tout le corps
  case "$LECTEUR_JSON" in
    jq)      jq -R -r "$JQ_FILE_JSON" < "$1" > "$2" ;;
    python3) python3 -I -c "$PY_FILE_JSON" < "$1" > "$2" ;;
    *)       return 1 ;;
  esac
}
# lire_la_file <fichier-corps> [en-tetes curl...] -> imprime `<statut> <type de contenu>` ; code = celui de curl.
lire_la_file() {
  _lf_corps=$1; shift
  # shellcheck disable=SC2086  ($HH = 0 ou 2 tokens, expansion voulue)
  resp_curl_auth_stdin | curl -K - $HH $TLS -sS --max-time 15 --max-filesize "$FILE_OCTETS_MAX" "$@" \
    -o "$_lf_corps" -w '%{http_code} %{content_type}' "$CENTRAL/api/actions/pending?host=$HOSTN" 2>/dev/null
}

# traiter_action <id> <kind> <target> <dry> <duree> — duree : chiffres (servie) | `?` (non servie, TSV)
# | `!cause` (servie hors contrat) | `-` (pas un ban). Le corps est celui de l ancienne boucle TSV.
traiter_action() {
  id=$1; kind=$2; target=$3; dry=$4; _ta_duree=$5
  [ -n "${id:-}" ] || return 0
  case "$id" in *[!0-9]*) return 0 ;; esac          # id doit etre numerique
  # `P10.21-j` — l action a deja ete appliquee, seul son verdict manque au central : la reexecuter
  # poserait un second ban et remonterait un second verdict. Le rejeu la remettra.
  if verdict_en_attente_de_remise "$id"; then
    echo "respond: #$id NON reexecutee : son verdict attend deja sa remise ($REJEU_FICHIER)" >&2
    return 0
  fi
  # `P10.21-n` — deja FAITE (registre d execution) : son verdict est un fait, il est remis de nouveau AVANT tout
  # controle d avant execution (une liste d epargne changee depuis ne le contredit pas) ; rien n est execute.
  _ta_genre=$(registre_jeton "$REGISTRE_GENRE_OCTETS" "$kind"); _ta_cible=$(registre_jeton "$REGISTRE_CIBLE_OCTETS" "$target")
  registre_lire "$id" "$_ta_genre" "$_ta_cible"
  if [ "$REG_ETAT" = faite ]; then
    echo "respond: #$id NON reexecutee : deja FAITE (registre d execution), verdict enregistre RE-REMIS ($REG_STATUT)" >&2
    post_result "$id" "$REG_STATUT" "$REG_RESULTAT"
    return 0
  fi
  if [ "$kind" = ban_ip ]; then
    case "$_ta_duree" in
      '?') EFF_DUR="$DUR"; DUR_PROV="PLUME_BAN_DURATION de l hote, duree NON servie : $DUREE_NON_SERVIE" ;;
      !*)
        post_result "$id" failed "duree du ban servie HORS CONTRAT (cause=${_ta_duree#!}) : RIEN n est applique (ban_ttl_s attendu : entier de secondes, 1 a 31536000)"
        echo "respond: #$id duree du ban servie hors contrat (${_ta_duree#!}), rien applique" >&2
        return 0 ;;
      ''|*[!0-9]*)
        post_result "$id" failed "duree du ban illisible : RIEN n est applique"
        echo "respond: #$id duree du ban illisible, rien applique" >&2
        return 0 ;;
      *) EFF_DUR="${_ta_duree}s"; DUR_PROV="servie par le central" ;;
    esac
  fi
  if ! is_ip "$target"; then post_result "$id" failed "cible non-IP: $target"; return 0; fi
  if protected "$target"; then post_result "$id" failed "IP protegee (reservee/centrale): $target"; return 0; fi
  verdict=$(verdict_liste_epargne "$ALLOWFILE" "$ALLOW_CONFIGUREE" "$target")
  case "$verdict" in
    epargnee) post_result "$id" failed "IP protegee (liste d epargne): $target"; return 0 ;;
    illisible:*)
      # FAIL-CLOSED, ET L ARBITRAGE EST ECRIT. Refuser coute une action de reponse non appliquee :
      # elle reste visible au central en `failed` avec sa cause, et se rejoue des la liste relue.
      # Laisser passer coute un ban pose sur une IP que l operateur avait declaree a NE JAMAIS
      # bannir — typiquement sa propre sortie, un rebond d administration, un partenaire — c est
      # a dire une panne qu il s inflige et qui peut lui retirer l acces par lequel il la leverait.
      # Le cout du refus est BORNE : les plages reservees et l hote central restent protegees par
      # `protected`, donc seul le ban d une IP PUBLIQUE est suspendu le temps de la panne.
      if [ "$kind" != unban_ip ]; then
        post_result "$id" failed "REFUS (fail-closed): liste d epargne non lue (cause=${verdict#illisible:}) sur $ALLOWFILE — aucun ban applique tant que la liste des IP a NE JAMAIS bannir n est pas lisible"
        echo "respond: #$id REFUS fail-closed (liste d epargne ${verdict#illisible:}: $ALLOWFILE)" >&2
        return 0
      fi
      # `unban_ip` ne BAISSE aucune defense : il en leve une. Lui appliquer le refus transformerait
      # une panne de lecture en ban qu on ne peut plus lever, c est a dire en verrouillage.
      echo "respond: #$id liste d epargne ${verdict#illisible:} ($ALLOWFILE) — unban poursuivi (ne baisse aucune defense)" >&2
      ;;
  esac
  cmd=$(plan "$kind" "$target")
  if [ "$APPLY" != "1" ] || [ "${dry:-1}" = "1" ]; then
    post_result "$id" dryrun "[dry-run] $cmd"
    echo "respond: [dry-run] #$id $cmd" >&2
    return 0
  fi
  # `P10.21-n` — la trace est ecrite AVANT `enforce` ; sans elle (registre indisponible), la riposte part quand meme.
  _ta_reprise=0; _ta_protege=1
  case "$REG_ETAT" in
    commencee)
      _ta_reprise=1
      echo "respond: #$id REPRISE : une execution precedente a ete interrompue avant son issue (registre d execution), la riposte est rejouee" >&2 ;;
    illisible) _ta_protege=0; REG_CAUSE="registre d execution illisible ($REGISTRE_FICHIER)" ;;
    autre)
      echo "respond: #$id identifiant deja inscrit au registre d execution pour une AUTRE riposte (genre ou cible differents) : entree perimee remplacee" >&2
      registre_inscrire "$id" "$_ta_genre" "$_ta_cible" || _ta_protege=0 ;;
    *) registre_inscrire "$id" "$_ta_genre" "$_ta_cible" || _ta_protege=0 ;;
  esac
  if [ "$_ta_protege" = 0 ]; then
    echo "respond: #$id protection contre la REEXECUTION ABSENTE pour cette riposte ($REG_CAUSE) : elle est executee quand meme (un ban est une defense, il ne se suspend pas pour un etat local)" >&2
  fi
  if enforce "$kind" "$target"; then _ta_statut=done; else _ta_statut=failed; fi
  # Levee reprise qui ne trouve l adresse nulle part (nft seul, rien retire, AUCUN refus) : la premiere execution a
  # pu la lever, l issue n est pas un echec — elle est dite telle quelle. Un refus de retrait reste `failed`.
  if [ "$_ta_reprise" = 1 ] && [ "$_ta_statut" = failed ] && [ "$kind" = unban_ip ] && [ "$UA_RIEN_RETIRE" = 1 ]; then
    _ta_statut=done; OUT="$UA_OUT_AVANT_VERDICT ; $PHRASE_ABSENTE_APRES_INTERRUPTION"
  fi
  _ta_resultat="$cmd | $OUT"
  if [ "$_ta_reprise" = 1 ]; then _ta_resultat="$PHRASE_REPRISE : $_ta_resultat"; fi
  if [ "$_ta_protege" = 1 ] && ! registre_marquer_faite "$id" "$_ta_genre" "$_ta_cible" "$_ta_statut" "$_ta_resultat"; then
    echo "respond: #$id issue NON enregistree au registre d execution (ecriture refusee) : la riposte y reste commencee ; si le central la re-sert, elle sera REPRISE" >&2
  fi
  post_result "$id" "$_ta_statut" "$_ta_resultat"
  if [ "$_ta_statut" = done ]; then
    echo "respond: #$id applique ($cmd)" >&2
  else
    echo "respond: #$id ECHEC ($cmd): $OUT" >&2
  fi
}

# --- `P10.21-n` : une seule execution a la fois ; les lignes illisibles du registre sont ecartees et dites ---
prendre_le_verrou
registre_assainir

# --- le rejeu passe AVANT la liste : une liste vide ou injoignable n empeche pas de remettre ---
rejouer_les_verdicts_retenus

# --- recupere la file dans un fichier borne ; statut et type de contenu lus par `-w` ---
_file_corps=$(mktemp 2>/dev/null) || { echo "respond: file d actions NON LUE : fichier temporaire refuse (mktemp) — aucune action recuperee ni executee" >&2; exit 3; }
_file_enreg=$(mktemp 2>/dev/null) || { rm -f "$_file_corps"; echo "respond: file d actions NON LUE : fichier temporaire refuse (mktemp) — aucune action recuperee ni executee" >&2; exit 3; }
trap 'rm -f "$_file_corps" "$_file_enreg"; rendre_le_verrou' EXIT
if [ -n "$LECTEUR_JSON" ]; then
  if _file_w=$(lire_la_file "$_file_corps" -H "Accept: $TYPE_FILE_JSON"); then _file_rc=0; else _file_rc=$?; fi
else
  if _file_w=$(lire_la_file "$_file_corps"); then _file_rc=0; else _file_rc=$?; fi
fi
_file_code=${_file_w%% *}
case "$_file_w" in *" "*) _file_type=${_file_w#* } ;; *) _file_type="" ;; esac
if [ "$_file_rc" != 0 ] || [ "$_file_code" != 200 ]; then
  _file_lu=$(dd if="$_file_corps" bs="$RESULTAT_CORPS_LU" count=1 2>/dev/null | tr '\000-\037' ' ' | sans_caractere_entame) || _file_lu=""
  echo "respond: file d actions NON LUE (HTTP ${_file_code:-illisible}, curl code $_file_rc) : AUCUNE action executee ni verdict remis ce tour-ci — ce n est pas une file vide : $(reponse_bornee "$_file_lu")" >&2
  exit 3
fi
[ -s "$_file_corps" ] || exit 0                        # 200 et corps vide : rien a faire (silence honnete)

_file_type_nu=$(printf '%s' "$_file_type" | tr 'A-Z' 'a-z' | sed -e 's/;.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
if [ "$_file_type_nu" = "$TYPE_FILE_JSON" ]; then
  if [ -z "$LECTEUR_JSON" ]; then
    echo "respond: file d actions servie en $TYPE_FILE_JSON SANS avoir ete demandee, et aucun lecteur JSON sur cet hote : AUCUNE action executee" >&2
    exit 3
  fi
  if ! convertir_la_file_json "$_file_corps" "$_file_enreg"; then
    echo "respond: lecture de la file JSON par $LECTEUR_JSON en ECHEC : AUCUNE action executee ce tour-ci" >&2
    exit 3
  fi
  _n=0
  while IFS='	' read -r _r_typ _r_2 _r_3 _r_4 _r_5 _r_6 <&7 || [ -n "${_r_typ:-}" ]; do
    _n=$((_n + 1))
    case "$_r_typ" in
      B) continue ;;
      X) echo "respond: file JSON : ligne $_n ILLISIBLE (cause=${_r_2:-inconnue}), ignoree — les autres actions sont servies" >&2 ;;
      F)
        case "${_r_2:-}" in ''|*[!0-9]*) echo "respond: file JSON : ligne $_n ILLISIBLE, ignoree" >&2; continue ;; esac
        if verdict_en_attente_de_remise "$_r_2"; then
          echo "respond: #$_r_2 NON reexecutee : son verdict attend deja sa remise ($REJEU_FICHIER)" >&2; continue
        fi
        post_result "$_r_2" failed "action servie HORS CONTRAT (cause=${_r_3:-inconnue}) : rien n est applique"
        echo "respond: #$_r_2 action servie hors contrat (${_r_3:-inconnue}), rien applique" >&2 ;;
      A) traiter_action "${_r_2:-}" "${_r_3:-}" "${_r_4:-}" "${_r_5:-}" "${_r_6:-}" ;;
      *) echo "respond: file JSON : ligne $_n non comprise du lecteur, ignoree" >&2 ;;
    esac
  done 7< "$_file_enreg"
  exit 0
fi

# --- chemin TSV (id  kind  target  dry_run), 1 action/ligne : la duree n est pas servie ---
if [ -n "$LECTEUR_JSON" ]; then
  DUREE_NON_SERVIE="le central a servi du TSV malgre la demande de JSON par ligne (central anterieur a la duree servie)"
else
  DUREE_NON_SERVIE="aucun lecteur JSON sur cet hote (ni jq ni python3), file demandee en TSV"
fi
while IFS='	' read -r id kind target dry <&7 || [ -n "${id:-}" ]; do
  traiter_action "${id:-}" "${kind:-}" "${target:-}" "${dry:-}" '?'
done 7< "$_file_corps"
