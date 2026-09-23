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
      -H 'Content-Type: application/json' --data-binary "$1" "$CENTRAL/api/actions/result" 2>/dev/null) || :
    return 0
  fi
  # shellcheck disable=SC2086  ($HH = 0 ou 2 tokens, expansion voulue)
  _rv_code=$(resp_curl_auth_stdin | curl -K - $HH $TLS -sS --max-time 15 --max-filesize "$RESULTAT_CORPS_FICHIER" \
    -o "$_rv_fichier" -w '%{http_code}' \
    -H 'Content-Type: application/json' --data-binary "$1" "$CENTRAL/api/actions/result" 2>/dev/null) || :
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
#                       riposte sera alors re-servie par le central, et reexecutee ;
#   tout autre code     refus definitif, avoue, la ligne part.
# Le premier echec passager ARRETE le rejeu de ce tour (le central ne repond pas : essayer les
# suivants coute quinze secondes chacun pour rien) ; les lignes non tentees gardent leur compte.
# Une riposte dont le verdict attend sa remise n est PAS reexecutee si le central la re-sert.
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

verdict_en_attente_de_remise() {   # <id> -> 0 si un verdict de cette riposte attend sa remise
  [ -f "$REJEU_FICHIER" ] || return 1
  grep -q "^$1	" "$REJEU_FICHIER" 2>/dev/null
}

retenir_pour_rejeu() {   # <id> <status> <result>
  if ! etat_de_rejeu_pret; then
    echo "respond: #$1 verdict NON RETENU pour rejeu : etat local $REJEU_DIR non inscriptible — le central re-servira la riposte apres sa fenetre de reclamation, et elle sera REEXECUTEE" >&2
    return 0
  fi
  verdict_en_attente_de_remise "$1" && return 0
  _rr_n=0; [ -f "$REJEU_FICHIER" ] && _rr_n=$(grep -c '' "$REJEU_FICHIER" 2>/dev/null || :)
  if [ "${_rr_n:-0}" -ge "$REJEU_LIGNES" ]; then
    echo "respond: #$1 verdict NON RETENU pour rejeu : la file de rejeu est PLEINE ($REJEU_LIGNES verdicts en attente dans $REJEU_FICHIER) — le central re-servira la riposte, et elle sera REEXECUTEE" >&2
    return 0
  fi
  _rr_resultat=$(printf '%s' "$3" | tr '\000-\037' ' ' | coupe_sur_caractere "$REJEU_RESULTAT_OCTETS")
  if ! (umask 077 && printf '%s\t0\t{"id":%s,"status":"%s","result":"%s"}\n' "$1" "$1" "$2" "$(esc "$_rr_resultat")" >> "$REJEU_FICHIER") 2>/dev/null; then
    echo "respond: #$1 verdict NON RETENU pour rejeu : ecriture refusee dans $REJEU_FICHIER" >&2
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
        esac ;;
      503|502|504|000|'')
        _rj_muet=1
        if [ "$_rj_tours" -ge "$REJEU_TOURS" ]; then
          echo "respond: #$_rj_id verdict ABANDONNE apres $_rj_tours tours de rejeu (dernier HTTP ${_rv_code:-illisible}) : la riposte reste OUVERTE au central, qui la re-servira et elle sera REEXECUTEE : $(reponse_bornee "$_rv_corps")" >&2
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

# --- le rejeu passe AVANT la liste : une liste vide ou injoignable n empeche pas de remettre ---
rejouer_les_verdicts_retenus

# --- recupere la liste (TSV: id  kind  target  dry_run), 1 action/ligne ---
# shellcheck disable=SC2086  ($HH = 0 ou 2 tokens, expansion voulue)
list=$(resp_curl_auth_stdin | curl -K - $HH $TLS -sS --max-time 15 "$CENTRAL/api/actions/pending?host=$HOSTN" 2>/dev/null) || exit 0
[ -n "$list" ] || exit 0

printf '%s\n' "$list" | while IFS='	' read -r id kind target dry; do
  [ -n "${id:-}" ] || continue
  case "$id" in *[!0-9]*) continue ;; esac          # id doit etre numerique
  # `P10.21-j` — l action a deja ete appliquee, seul son verdict manque au central : la reexecuter
  # poserait un second ban et remonterait un second verdict. Le rejeu la remettra.
  if verdict_en_attente_de_remise "$id"; then
    echo "respond: #$id NON reexecutee : son verdict attend deja sa remise ($REJEU_FICHIER)" >&2
    continue
  fi
  if ! is_ip "$target"; then post_result "$id" failed "cible non-IP: $target"; continue; fi
  if protected "$target"; then post_result "$id" failed "IP protegee (reservee/centrale): $target"; continue; fi
  verdict=$(verdict_liste_epargne "$ALLOWFILE" "$ALLOW_CONFIGUREE" "$target")
  case "$verdict" in
    epargnee) post_result "$id" failed "IP protegee (liste d epargne): $target"; continue ;;
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
        continue
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
