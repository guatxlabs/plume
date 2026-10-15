#!/bin/sh
# plume-source: mail
# plume-emits: fields=action,collector,domain,dsn,filters,method,note,nrcpt,rcpt,rcpt_domain,relay,score,sender,service,size,truncated,type,user,verdict,virus
# Capteur Plume (PLUGIN, OPT-IN) : logs MAILSERVER -> events source=mail.
# docker-mailserver logge dans un FICHIER du pod (/var/log/mail/mail.log), PAS dans journald hote
# -> invisible des autres capteurs (d'ou "je ne vois pas les logs mail dans le SOC"). Ce capteur le
# lit (k3s exec, docker exec, ou fichier en natif) et emet les events SECURITE : connexions reussies,
# echecs d'auth, rejets, postscreen, + verdicts ANTIVIRUS ClamAV/amavis (virus detecte, piece
# jointe bannie, panne du scanner). Champs PARSES (qui=src_ip/user, quand=ts, ou=service,
# comment=action) -> groupables en GXQL ( | stats count by action / by src_ip / by user ).
# Mode-aware : PLUME_MAIL_SRC=k3s|docker|file. OPT-IN (non actif par defaut). Lecture seule, aucune action.
#
# P10.32-f — LA SURFACE QUE LE CAPTEUR NE LISAIT PAS, constatee sur un journal docker-mailserver reel :
# seuls dovecot, smtpd, postscreen et amavis etaient lus. Rien n'etait emis pour les
# verdicts d'authentification de l'EXPEDITEUR (opendkim, opendmarc, policyd-spf), le courrier SORTANT
# (`postfix/smtp`), la file (`postfix/qmgr`), l'envoi AUTHENTIFIE REUSSI (`client=…, sasl_method=…`),
# ni le journal propre de ClamAV (clamd, freshclam) : une usurpation, un compte vole qui envoie, une
# base antivirale perimee etaient invisibles. Ces familles sont lues ici, sous leur etiquette et en
# tete de leur message, comme les quatre autres (corpus `collectors/mail-*.corpus`, temoin
# `.github/scripts/check_mail_sensor_reads_sender_checks_outbound_queue_and_clamav.py`).
# Categories, toutes du CIM : `mail` (verdicts DKIM/DMARC/SPF), `mailflow` (sortant, file : la
# livraison, la file et le transport, docs/CIM.md), `auth` (envoi authentifie reussi),
# `malware`/`av_error`/`update` (journal ClamAV). La SEVERITE distingue l'echec
# du succes : 1 pour un succes ou une absence de verdict, 2 pour un echec temporaire ou un report, 3
# pour un echec (signature fausse, DMARC/SPF `fail`, rebond sortant), 4 pour un virus trouve.
# CONFIDENTIALITE DU SORTANT : seul le DOMAINE du destinataire est un champ, et le message emis est
# la ligne dont chaque partie locale d'adresse est remplacee par `*` (`masquer_adresses`).
# P10.32-l — CONFIDENTIALITE PARTOUT, plus seulement sur le sortant : le message emis de TOUTE ligne est
# masque (`masquer_ligne`), et les champs qui portent une adresse ou un compte (`user`, `sender`, `rcpt`)
# sortent sous la forme `*@<domaine>` (`*` sans domaine). Une exception, ecrite : l'expediteur d'une
# entree amavis ORIGINAIRE de ce serveur (`LOCAL`, client de mynetworks ou authentifie) reste en clair,
# parce que la regle livree `ex-mail-mass-outbound` compte `sender` par expediteur — masque, il se
# confondrait avec tous les envois du domaine. Les dangers mesures : un `viewer` qui lisait les
# correspondants de chaque boite, une base volee qui portait l'annuaire des echanges.
# P10.33-f — une seconde exception, OPT-IN et masquee par defaut : `PLUME_MAIL_DEMASQUER_DESTINATAIRE_LOCAL=1`
# rend en clair le champ `rcpt` d'un verdict INFECTED ou BANNED dont le domaine est dans
# `PLUME_MAIL_DOMAINES_LOCAUX` (voir sa lecture, plus bas).
#
# Horodatage : le log est en ISO avec offset (+02:00) ; l'epoch UTC = mktime(heure) - offset, avec
# TZ=UTC pour que mktime interprete l'heure en UTC quel que soit le fuseau de l'hote.
# Le journal ClamAV (`LogTime yes`) porte une heure MURALE sans decalage (`Wed Oct 14 00:00:02 2026 ->`) :
# son decalage est PLUME_MAIL_CLAMAV_UTC_OFFSET, sinon celui de la derniere ligne de mail.log lue au meme
# passage (meme conteneur, meme fuseau), sinon +00:00. Son filigrane est `<heure murale> <lignes deja vues
# a cette seconde>` : l'heure n'a que la seconde, et sept lignes de freshclam partagent la meme.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
MAILSRC="${PLUME_MAIL_SRC:-k3s}"                       # k3s (kubectl exec) | docker (docker exec) | file (chemin local)
MAIL_NS="${PLUME_MAIL_NS:-mail}"
MAIL_SEL="${PLUME_MAIL_SELECTOR:-app=mailserver}"
MAIL_CONTAINER="${PLUME_MAIL_CONTAINER:-mailserver}"   # conteneur du pod (k3s) ou nom du conteneur (docker)
MAIL_LOG="${PLUME_MAIL_LOG:-/var/log/mail/mail.log}"
# VOLUME, PAR FLUX ET NON AU TOTAL (P10.32-f) : `PLUME_MAIL_MAX` borne les lignes lues de CHAQUE journal, et
# le programme n'émet pas plus de 3000 événements par flux et par passage. Les flux sont jusqu'à trois
# (mail.log, clamd, freshclam) : un passage peut donc publier jusqu'à trois fois le plafond.
MAX="${PLUME_MAIL_MAX:-3000}"                          # lignes lues par journal et par passage (garde-fou)
SKIPIP="${PLUME_MAIL_SKIP_IP:-}"                        # IP à ignorer (ex node/self : probes internes bruyantes)
WM="$STATE_DIR/mail.watermark"                       # dernier epoch traite (incremental)
last=$(cat "$WM" 2>/dev/null || echo 0)
# P10.32-f — LE JOURNAL CLAMAV, une source par demon. Defaut par mode : docker-mailserver (k3s, docker)
# l'ecrit sous /var/log/mail/, un hote natif Debian/Ubuntu sous /var/log/clamav/. Une variable posee VIDE
# coupe la lecture ; un fichier ABSENT au chemin par defaut est un hote sans ClamAV (dit dans l'enveloppe
# de config, pas avoue) ; un chemin POSE que la lecture ne rend pas est avoue (`plume_lecture_partielle`).
case "$MAILSRC" in file) _clam_rep=/var/log/clamav ;; *) _clam_rep=/var/log/mail ;; esac
CLAMD_LOG="${PLUME_MAIL_CLAMAV_LOG-$_clam_rep/clamav.log}"
FRESHCLAM_LOG="${PLUME_MAIL_FRESHCLAM_LOG-$_clam_rep/freshclam.log}"
CLAMD_POSE="${PLUME_MAIL_CLAMAV_LOG+1}"
FRESHCLAM_POSE="${PLUME_MAIL_FRESHCLAM_LOG+1}"
CLAM_DECALAGE="${PLUME_MAIL_CLAMAV_UTC_OFFSET:-}"      # ex. +02:00 ; vide = celui de mail.log
# Un decalage pose mais illisible (`Europe/Paris`) est avoue, et c'est le repli ordinaire qui s'applique.
case "$CLAM_DECALAGE" in
  ''|[+-][0-2][0-9]:[0-5][0-9]) ;;
  *) plume_reglage_illisible mail PLUME_MAIL_CLAMAV_UTC_OFFSET "$CLAM_DECALAGE" "le decalage de mail.log (sinon +00:00)" "la forme +hh:mm ou -hh:mm"
     CLAM_DECALAGE="" ;;
esac

# P10.33-f — LE DESTINATAIRE LOCAL D'UN VIRUS OU D'UNE PIECE BANNIE, DEMASQUABLE PAR UN REGLAGE NOMME.
# Masque, le champ `rcpt` d'un verdict amavis INFECTED ou BANNED rend `*@<domaine>` : l'analyste ne sait plus
# quelle boite de ce serveur a ete visee. `PLUME_MAIL_DEMASQUER_DESTINATAIRE_LOCAL=1` le rend en clair, et
# RIEN D'AUTRE : seulement le champ `rcpt`, seulement sur les categories `malware` (INFECTED) et `banned`
# (BANNED), seulement si son domaine figure dans `PLUME_MAIL_DOMAINES_LOCAUX`. Le message, `user`, `sender`,
# les domaines externes et tout autre evenement restent masques. Toute autre valeur que `1` laisse le
# masquage (defaut) ; une valeur ni vide, ni `0`, ni `1` est avouee (`plume_reglage_illisible`).
# CE QUI EST « LOCAL », DIT : la liste EXPLICITE `PLUME_MAIL_DOMAINES_LOCAUX` (domaines separes par des
# espaces ou des virgules, compares sans casse et EXACTEMENT : `sous.example.org` n'est pas `example.org`).
# Rien n'est devine : ni `mydestination` ni `virtual_mailbox_domains` ne sont lus (le capteur ne lit que des
# journaux, dans trois modes). Sans liste lisible, rien n'est demasque, et c'est avoue. L'etat est dit dans
# l'enveloppe de config (`destinataire_local` : `masque`, `demasque`, `masque-sans-liste`).
# LE RISQUE, DIT (deploy/CONFIDENTIALITE.md) : des adresses de boites reelles entrent dans le SIEM.
DEMASQUER_RCPT_LOCAL="${PLUME_MAIL_DEMASQUER_DESTINATAIRE_LOCAL:-}"
demasquer_rcpt_local=0; domaines_locaux=" "; etat_rcpt_local=masque
case "$DEMASQUER_RCPT_LOCAL" in
  ''|0) ;;
  1)
    _dl_illisibles=""
    set -f
    for _dl in $(printf '%s' "${PLUME_MAIL_DOMAINES_LOCAUX:-}" | tr ',;' '  ' | tr 'A-Z' 'a-z'); do
      case "$_dl" in
        .*|*.|*..*|*[!a-z0-9.-]*) _dl_illisibles="$_dl_illisibles $_dl" ;;
        *) case "$domaines_locaux" in *" $_dl "*) ;; *) domaines_locaux="$domaines_locaux$_dl " ;; esac ;;
      esac
    done
    set +f
    if [ "$domaines_locaux" = " " ]; then
      etat_rcpt_local=masque-sans-liste
      plume_reglage_illisible mail PLUME_MAIL_DOMAINES_LOCAUX "${PLUME_MAIL_DOMAINES_LOCAUX:-}" \
        "le masquage de TOUT destinataire (aucun domaine local lisible : rien n'est demasque)" \
        "la liste des domaines locaux, requise par PLUME_MAIL_DEMASQUER_DESTINATAIRE_LOCAL=1"
    else
      demasquer_rcpt_local=1; etat_rcpt_local=demasque
      [ -z "$_dl_illisibles" ] || plume_reglage_illisible mail PLUME_MAIL_DOMAINES_LOCAUX "${_dl_illisibles# }" \
        "le masquage des destinataires de ces entrees (seuls les domaines lisibles sont locaux)" \
        "la liste des domaines locaux (un domaine : lettres, chiffres, points et tirets)"
    fi
    ;;
  *) plume_reglage_illisible mail PLUME_MAIL_DEMASQUER_DESTINATAIRE_LOCAL "$DEMASQUER_RCPT_LOCAL" \
       "le masquage de tout destinataire (defaut)" "la valeur 1 (demasque le destinataire local) ou 0 (masque)" ;;
esac

# lire_journal <chemin> — les MAX dernieres lignes d'un journal du serveur mail, dans le mode choisi.
# Code 3 : le fichier n'existe pas (dit par la source elle-meme, `[ -e ]` joue LA OU le journal vit) ;
# tout autre echec : source injoignable ou illisible. Le code de la commande distante est celui que
# `kubectl exec` et `docker exec` rendent.
_LIRE_JOURNAL='[ -e "$1" ] || exit 3; tail -n "$2" "$1"'
_pod=""
if [ "$MAILSRC" = k3s ]; then
  KC="kubectl"; command -v kubectl >/dev/null 2>&1 || KC="k3s kubectl"
  if command -v "${KC%% *}" >/dev/null 2>&1; then
    _pod=$($KC -n "$MAIL_NS" get pod -l "$MAIL_SEL" -o name 2>/dev/null | head -1) || _pod=""
  fi
fi
lire_journal() {
  case "$MAILSRC" in
    k3s)
      [ -n "$_pod" ] || return 1
      $KC -n "$MAIL_NS" exec "$_pod" -c "$MAIL_CONTAINER" -- sh -c "$_LIRE_JOURNAL" lire "$1" "$MAX" 2>/dev/null
      ;;
    docker)
      command -v docker >/dev/null 2>&1 || return 1
      docker exec "$MAIL_CONTAINER" sh -c "$_LIRE_JOURNAL" lire "$1" "$MAX" 2>/dev/null
      ;;
    file)
      sh -c "$_LIRE_JOURNAL" lire "$1" "$MAX" 2>/dev/null
      ;;
    *) return 1 ;;
  esac
}


# S36 — meme distinction, dite avec le mot de la famille (cf. `web.sh`) : le routage etait deja le
# bon, la primitive y ajoute le rejet des marqueurs en attente.
raw=$(lire_journal "$MAIL_LOG") || plume_lecture_echouee mail source_illisible "source de log mail illisible (PLUME_MAIL_SRC=$MAILSRC) : ni fichier lisible, ni conteneur joignable"

now=$(date +%s)
umask 027
# LE PROGRAMME, ÉCRIT UNE FOIS ET JOUÉ SUR TROIS FLUX (P10.32-f) : `flux=mail` (mail.log, filigrane epoch),
# `flux=clamd` et `flux=freshclam` (journal ClamAV, filigrane `<heure murale> <lignes vues à cette seconde>`).
# LC_ALL=C : l’empreinte (P10.24-h) lit des OCTETS ; gawk en locale UTF-8 lirait des caractères. Les motifs
# du programme sont en ASCII, et mawk (awk par défaut de Debian et d’Ubuntu) lit déjà des octets.
PROGRAMME_MAIL='
# jesc() : l’échappement JSON de collectors/lib.sh (_PLUME_AWK_ECHAPPEMENT_JSON, P10.23-e), placé en tête de ce programme à chaque appel (`"$_PLUME_AWK_ECHAPPEMENT_JSON""$PROGRAMME_MAIL"`).
# P10.22-s — UNE ADRESSE, ET RIEN D’AUTRE. IPv4 pointée ou IPv6 (témoin :
# collectors/mail-adresses-et-texte-du-client.corpus), validée ENTIÈRE : une valeur qui n’en est pas une
# rend "" et la ligne n’est pas émise, plutôt qu’un préfixe (`rip=2001:db8::5` rendait `2001`). La forme
# mappée `::ffff:a.b.c.d` est rendue en IPv4 : Postfix la replie déjà à la source
# (`sane_sockaddr_to_hostaddr`), le démon la replie pour ses bans et sa liste d’épargne
# (`ssrf_norm_ip`), et la veille compare du TEXTE — sans ce repli, une même machine porterait deux clés
# et ne rencontrerait jamais un indicateur IPv4. Aucun intervalle `{n,m}` dans ces motifs : mawk
# 1.3.4 20200120 les lit comme des caractères.
# CANONICALISATION HORS DÉMON (`P4.7-j`) — divergence avec `ssrf_norm_ip`, nommée : seule la forme
# mappée ÉCRITE PAR inet_ntop (`::ffff:a.b.c.d`) est repliée ; `::ffff:c000:228`, la forme non
# compressée et une IPv6 en majuscules ressortent telles qu’écrites, là où le démon les replie ou
# les récrit. Dovecot et Postfix n’écrivent aucune de ces trois formes. Comme le démon : zéro de tête
# d’un octet IPv4 refusé, zone `%…` refusée.
function est_ipv4(s,   o, i){
  if (s !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 0
  split(s, o, ".")
  for (i = 1; i <= 4; i++) if (length(o[i]) > 3 || o[i] + 0 > 255 || o[i] ~ /^0[0-9]/) return 0
  return 1
}
function est_ipv6(s,   t, doubles, g, n, i, groupes){
  if (s !~ /^[0-9A-Fa-f:.]+$/ || index(s, ":") == 0 || index(s, ":::") > 0) return 0
  if ((s ~ /^:/ && s !~ /^::/) || (s ~ /:$/ && s !~ /::$/)) return 0
  t = s; doubles = gsub(/::/, "", t); if (doubles > 1) return 0
  n = split(s, g, ":"); groupes = 0
  for (i = 1; i <= n; i++) {
    if (g[i] == "") continue
    if (i == n && index(g[i], ".") > 0) { if (!est_ipv4(g[i])) return 0; groupes += 2; continue }
    if (g[i] !~ /^[0-9A-Fa-f]+$/ || length(g[i]) > 4) return 0
    groupes++
  }
  return doubles ? (groupes <= 7) : (groupes == 8)
}
function adresse(s){
  if (est_ipv4(s)) return s
  if (!est_ipv6(s)) return ""
  if (s ~ /^::ffff:[0-9.]+$/) return substr(s, 8)
  return s
}
# Dovecot : le DERNIER champ `rip=` du message. Ceux qui le précèdent (`user=<…>`) sont fournis par le
# client ; ceux qui le suivent (`lip=`, `mpid=`, sécurité, `session=`) sont écrits par le serveur.
function rip_de_dovecot(m,   v){
  v = ""
  while (match(m, /[,:] rip=[^, ]*/)) { v = substr(m, RSTART + 6, RLENGTH - 6); m = substr(m, RSTART + RLENGTH) }
  return v
}
# Postfix, postscreen : le PREMIER crochet du message — Postfix écrit le client `nom[adresse]` (ou
# `[adresse]:port`) AVANT tout texte venu du client (`helo=<…>`, texte de pré-salutation, commande non
# SMTP). S’il ne se valide pas, aucune adresse : on ne va JAMAIS chercher plus loin, là où le client
# écrit. Le message commence après l’étiquette : le PID (`smtpd[1457]`) n’y est pas, le port est hors du
# crochet ; `[IPv6:…]` n’est pas une forme de journal (Postfix la réserve aux en-têtes `Received:`) :
# c’est celle qu’un CLIENT écrit dans son HELO, elle ne se valide donc pas.
# P10.23-i — le motif lisait « le premier crochet QUI RESSEMBLE À UNE ADRESSE » (un point ou deux-points
# dedans) : derrière un client `unknown[unknown]` (`smtpd_peer.c` : `CLIENT_ADDR_UNKNOWN`, pair parti avant
# le réveil du serveur, ou `XCLIENT ADDR=[UNAVAILABLE]` d’un mandataire autorisé), il allait chercher plus
# loin, et un `helo=<[a.b.c.d]>` écrit par le client devenait l’adresse source. Lu par `index`, sans motif.
function crochet_du_client(m,   o, f){
  o = index(m, "["); if (o == 0) return ""
  m = substr(m, o + 1); f = index(m, "]"); if (f == 0) return ""
  return substr(m, 1, f - 1)
}
# P10.23-w — combien de fois un motif figure dans s. Un champ qu’amavis écrit UNE fois, et qu’un texte du
# client peut recopier, n’est lu que s’il n’y figure qu’une fois : la copie ne peut alors que le taire.
function occurrences(s, motif,   n){
  n = 0
  while (match(s, motif)) { n++; s = substr(s, RSTART + RLENGTH) }
  return n
}
# P10.23-h — L’UTILISATEUR D’UN ÉCHEC SASL DE SMTPD, ET SEULEMENT LÀ. `smtpd_sasl_glue.c` (Postfix 3.9.0,
# reporté dans 3.8.3, 3.7.8, 3.6.12 et 3.5.23 ; absent de 3.8.2, 3.7.7, 3.6.11) écrit
#   `warning: <nom>[<adresse>]: SASL <mécanisme> authentication failed: <raison>, sasl_username=<nom SASL>`
# — raison `(reason unavailable)` quand le moteur SASL n’en donne pas, nom `(unavailable)` quand il n’en
# rend pas, nom coupé à 100 octets. `reste` est ce qui suit `authentication failed` (tout ce qui précède
# est écrit par smtpd et ancré, le mécanisme étant un jeton sans espace). Le nom SASL est celui que le
# client a TENTÉ (comme le `user=<…>` d’un échec Dovecot) ; il est lu à la place où smtpd l’écrit, en FIN
# de ligne — espaces et virgules compris —, et seulement si `, sasl_username=` n’y figure qu’UNE fois :
# la raison le précède, et un nom qui recopie le repère ne peut alors que se TAIRE. Jamais lu dans une
# autre ligne Postfix, où un `sasl_username=` ne peut venir que d’un texte du client (`helo=<…>`).
function utilisateur_sasl(reste,   p, v){
  if (occurrences(reste, ", sasl_username=") != 1) return ""
  p = index(reste, ", sasl_username="); v = substr(reste, p + 16)
  return (v == "(unavailable)") ? "" : v
}
# P10.24-h — L’EMPREINTE DE LA LIGNE BRUTE, horodatage à la microseconde compris : somme polynomiale
# modulaire (base 257, module 2147483629, premier sous 2^31), exacte en double puisque h*257+255 < 2^40.
# Chaque octet est lu dans OCTET, table associative octet -> rang (1 à 255) bâtie une fois (BEGIN) : un
# accès par octet, là où `index` dans une chaîne de 255 octets la balayait (gawk ×3,4 sur 3000 rejets de
# ~1000 octets). Le programme tourne sous LC_ALL=C, sans quoi gawk en locale UTF-8 lirait des caractères et
# `sprintf("%c")` rendrait plusieurs octets. Ni opérateur binaire (mawk n’en a pas), ni processus par
# ligne. Fonction de la SEULE ligne : le rejeu d’une tranche rend la même clé, deux lignes distinctes deux clés.
function empreinte(s,   i, n, h){
  h = 0; n = length(s)
  for (i = 1; i <= n; i++) h = (h * 257 + OCTET[substr(s, i, 1)]) % 2147483629
  return h
}
# P10.23-w — L’ENTRÉE PRINCIPALE D’AMAVIS, LUE DANS SA FORME ET NULLE PART AILLEURS (témoin :
# collectors/mail-amavis.corpus). Gabarit `$log_short_templ` (amavis, `lib/Amavis.pm`, section __DATA__) :
#   (<id>) <Passed|Blocked> <catégorie>[ (<détail>)] {<actions>}, [<banque> ][LOCAL ][<a>]:<port>[ [<e>]] <exp> -> <dest>[,<dest>…], …, mail_id: <id>, Hits: <score>, size: <taille>, …, <n> ms
# `$log_verbose_templ` insère `<proto>/<proto> ` avant l’expéditeur et `, b: <empreinte>` après mail_id.
# Ce que le CLIENT écrit dans cette ligne : le détail de BANNED (nom de la pièce jointe), l’expéditeur, un
# destinataire (`+extension`, partie locale entre guillemets), le Message-ID (espaces et virgules admis par
# `parse_message_id`), `[<e>]` (plus ancienne adresse publique des en-têtes `Received:`). D’où :
#   * catégorie, verdict : la TÊTE du message, que rien du client ne précède ;
#   * adresse relais : `[<a>]:<port>` (XFORWARD ADDR/PORT de Postfix), JUSTE après `{<actions>}, ` et la
#     banque éventuelle — jamais `[<e>]` (sans port), jamais un crochet du détail. Derrière BANNED, le
#     détail précède ce délimiteur et peut le recopier : il doit être UNIQUE, sinon pas d’adresse ;
#   * expéditeur, destinataire, score, taille, identifiant : sur une entrée COMPLÈTE seulement (qui finit
#     par `, <n> ms` — amavis coupe une entrée de plus de 980 octets et termine le morceau par `...`, et
#     le vrai champ peut alors tomber dans la suite), et seulement si leur repère (` -> `, la suite
#     `, Hits: …, size: …`) n’y figure qu’UNE fois ; l’identifiant est celui qui la précède immédiatement.
# Un champ copié par le client n’est ainsi jamais PRIS : il est TU. Lu partout, le nom d’une pièce jointe
# bannie choisissait l’adresse et le destinataire, un Message-ID choisissait l’identifiant (donc la clé
# de dédoublonnage : un événement malware portant la clé d’un passage propre antérieur est écarté à
# l’ingestion), le score et la taille.
# P10.24-i — une entrée COUPÉE le dit : `coupee` vaut 1 quand elle ne finit pas par `, <n> ms`, posé AVANT
# tout retour anticipé (derrière BANNED, le délimiteur `) {…}, ` peut lui-même tomber dans la suite, ou un
# faux délimiteur du nom de la pièce jointe rester dans le premier morceau). `coupee` est une GLOBALE : posé
# après un retour, il garderait la valeur de l’entrée précédente. Témoin : dans le corpus, chaque entrée
# coupée suit une entrée complète lue jusqu’au bout, et une entrée complète suit une entrée coupée — la
# garde exige ce voisinage. La suite `(<id>) ...` n’est pas recollée : elle porte du texte du client
# (famille de P10.23-w).
function lire_amavis(m,   reste, apres, avant, p, s, detail, unique, complete){
  vd = ""; vir = ""; aip = ""; frm = ""; rcpt = ""; sco = ""; sz = ""; mid = ""; orig = 0
  coupee = (m !~ /, [0-9]+ ms$/)
  sub(/^\([^ ()]+\) /, "", m)
  match(m, /^(Passed|Blocked) [A-Z][A-Z0-9-]*/); vd = substr(m, 1, RLENGTH); reste = substr(m, RLENGTH + 1)
  unique = 1; detail = ""
  if (reste ~ /^ \(/) {
    if (!match(reste, /[)] [{][A-Za-z,]*[}], /)) return
    detail = substr(reste, 3, RSTART - 3); apres = substr(reste, RSTART + RLENGTH)
    if (vd ~ /BANNED$/ && match(apres, /[)] [{][A-Za-z,]*[}], /)) unique = 0
  } else {
    if (!match(reste, /^ [{][A-Za-z,]*[}], /)) return
    apres = substr(reste, RLENGTH + 1)
  }
  if (vd ~ /INFECTED$/) vir = detail
  complete = !coupee
  if (vd ~ /BANNED$/ && !(complete && unique)) return
  if (match(apres, /^([A-Za-z0-9_.\/-]+ )?(LOCAL )?\[[0-9A-Fa-f:.]+\]:[0-9]+ /)) {
    s = substr(apres, RSTART, RLENGTH); match(s, /\[[0-9A-Fa-f:.]+\]/); aip = adresse(substr(s, RSTART + 1, RLENGTH - 2))
    # P10.32-l — `LOCAL` (`%l` de `$log_short_templ`) : le message est ORIGINAIRE de ce serveur.
    if (s ~ /(^| )LOCAL \[/) orig = 1
  }
  if (!complete) return
  if (occurrences(apres, " -> ") == 1) {
    p = index(apres, " -> "); avant = substr(apres, 1, p - 1); s = substr(apres, p + 4)
    if (match(avant, /(^| )<[^<>]*>$/)) { frm = substr(avant, RSTART, RLENGTH); sub(/^ /, "", frm); frm = substr(frm, 2, length(frm) - 2) }
    if (match(s, /^<[^<>]*>,/)) rcpt = substr(s, 2, RLENGTH - 3)
  }
  if (occurrences(m, SUITE_HITS_SIZE) == 1) {
    match(m, SUITE_HITS_SIZE); avant = substr(m, 1, RSTART - 1); s = substr(m, RSTART, RLENGTH)
    match(s, /Hits: [^,]*/); sco = substr(s, RSTART + 6, RLENGTH - 6); if (sco == "-") sco = ""
    match(s, /size: [0-9]+/); sz = substr(s, RSTART + 6, RLENGTH - 6)
    if (match(avant, /, mail_id: [A-Za-z0-9_-]+(, b: [A-Za-z0-9_-]+)?$/)) { mid = substr(avant, RSTART + 11, RLENGTH - 11); sub(/,.*/, "", mid) }
  }
}
# P10.32-f — CONFIDENTIALITÉ DU SORTANT : chaque PARTIE LOCALE d’adresse de la ligne est remplacée par `*`
# (`to=<*@example.org>`, et la même adresse recopiée par le serveur distant dans sa réponse). La forme
# entre guillemets d’abord, guillemet échappé compris (`"a b"@d`, `"a\"b"@d`), puis TOUT ce qui précède le
# `@` jusqu’à une espace, un `<`, un autre `@` ou le début de la ligne. L’ancien motif s’arrêtait au
# premier délimiteur d’adresse et laissait fuir un morceau : `<jean:dupont@d>` rendait `<jean:*@d>`,
# `"a \"b c"@d` rendait `"a *@d`, `<jean[1]@d>` rendait `<jean[*@d>`.
# CE QUI N’EST PAS MASQUÉ, DIT : un `@` sans partie locale devant lui, le domaine, qui est le champ, et ce
# qui précède l’espace d’une forme entre guillemets NON REFERMÉE (`"a b@d` rend `"a *@d`) : Postfix
# referme les siennes, seul un texte du serveur distant peut l’écrire ainsi. De même, une partie locale à
# espace recopiée SANS ses guillemets par le serveur distant : `<jean dupont@d>` rend `<jean *@d>`, et
# `<a\ b@d>` rend `<a\ *@d>` — aucune borne lisible ne sépare alors la partie locale du texte qui la précède.
# CE QUE LE MASQUAGE MANGE EN TROP, DIT : la ponctuation collée devant une partie locale (`(a@d` rend
# `*@d`), et le domaine d’une adresse collée à la suivante sans espace (`a@x,b@y` rend `*@*@y`).
# P10.32-l — UNE ÉTIQUETTE DE CHAMP `clé=` COLLÉE À LA PARTIE LOCALE N’EST PAS MANGÉE : `sasl_username=jean@d`
# rend `sasl_username=*@d`, `envelope-from=jean@d;` rend `envelope-from=*@d;`. Une ÉTIQUETTE, et rien d’autre :
# le préfixe `nom=` (`[A-Za-z_-]+=`, jusqu’au PREMIER `=`) au DÉBUT du morceau ou juste après un `,` ou un `;`
# du morceau, et SEULEMENT si le morceau ne suit ni un `<` ni un autre `@`. Après un `<`, tout jusqu’au `@` est
# la partie locale, masquée ENTIÈRE : `to=<jean_dupont=x@d>` rend `to=<*@d>` (l’ancienne règle gardait tout
# préfixe `nom=` du morceau, chevron compris, et rendait `to=<jean_dupont=*@d>` : la partie locale fuyait).
# `(` n’est pas une borne d’étiquette : Dovecot écrit le compte juste après (`imap(jean@d)`), et `imap(a_b=c@d)`
# garderait `a_b=`. BATV HORS CHEVRONS (`envelope-from=prvs=0123abcd=jean@d`) : seule l’étiquette du champ sort,
# l’étiquette `prvs=`, la signature et la partie locale sont masquées ensemble (`envelope-from=*@d`) ; sans
# étiquette de champ devant (` prvs=0123abcd=jean@d`), `prvs=` est pris pour une étiquette et le reste masqué.
# CE QUI FUIT ENCORE, DIT : une partie locale qui contient `=`, écrite HORS chevrons et SANS étiquette devant
# (` jean_dupont=x@d` rend ` jean_dupont=*@d`) — aucune borne lisible ne la sépare d’une étiquette.
function masquer_adresses(s,   r, t, e, p, q, c){
  gsub(/"([^"\\]|\\.)*"@/, "*@", s)
  r = ""
  while (match(s, /[^ <@]+@/)) {
    p = RSTART; q = RLENGTH; t = substr(s, p, q - 1); e = ""
    # Le caractère qui précède le morceau : celui de la ligne, ou le `@` du morceau précédent.
    if (p > 1) c = substr(s, p - 1, 1); else if (r != "") c = "@"; else c = ""
    if (c != "<" && c != "@") {
      if (match(t, /^[A-Za-z_-]+=/)) e = substr(t, 1, RLENGTH)
      else if (match(t, /[,;][A-Za-z_-]+=/)) e = substr(t, 1, RSTART + RLENGTH - 1)
    }
    r = r substr(s, 1, p - 1) e "*@"
    s = substr(s, p + q)
  }
  return r s
}
# P10.32-l — un compte ou une adresse LUS, tels qu’ils sortent dans un champ : `*@<domaine>` (le domaine est
# ce qui suit le DERNIER `@`), `*` sans `@`, rien pour rien.
function masquer_compte(v,   d){
  if (v == "") return ""
  if (index(v, "@") == 0) return "*"
  d = v; sub(/^.*@/, "", d)
  return "*@" d
}
# P10.33-f — le champ `rcpt` d’une entrée amavis : en clair SEULEMENT si le réglage est actif
# (`demasquer_local`), la catégorie `malware` ou `banned`, et le domaine (après le DERNIER `@`, sans casse,
# sans espace) un domaine local déclaré (`domaines_locaux`, ` a b ` : bornés d’espaces). Masqué sinon.
function destinataire_emis(v, cat,   d){
  if (demasquer_local == 1 && (cat == "malware" || cat == "banned") && index(v, "@") > 0) {
    d = v; sub(/^.*@/, "", d); d = tolower(d)
    if (d ~ /^[a-z0-9.-]+$/ && index(domaines_locaux, " " d " ") > 0) return v
  }
  return masquer_compte(v)
}
# Chaque occurrence LITTÉRALE de `de` (aucun motif : une valeur lue peut porter `.`, `[`, `\`…).
function remplacer_partout(s, de, vers,   r, p){
  if (de == "" || de == vers) return s
  r = ""
  while ((p = index(s, de)) > 0) { r = r substr(s, 1, p - 1) vers; s = substr(s, p + length(de)) }
  return r s
}
# P10.32-l — LE MESSAGE ÉMIS DE TOUTE LIGNE. Les valeurs que le programme a LUES (le compte `usr`, l’expéditeur
# et le destinataire `lu_exp`/`lu_dest`) sont d’abord remplacées à leur place exacte, sous leur repère
# (`user=<…>`, `sasl_username=`, `<…>`) — ce qui masque aussi une valeur sans `@` (`user=<sales>`) et une partie
# locale à espace NON guillemetée (`<jean dupont@d>`, la limite dite de P10.32-f), pour la valeur lue et ses
# recopies. Puis `masquer_adresses` sur le reste. CE QUI RESTE, DIT : une partie locale à espace que le
# programme n’a pas lue (texte libre du serveur distant), et un nom SASL sans `@` recopié hors de son repère.
function masquer_ligne(s, usr){
  if (usr != "") {
    s = remplacer_partout(s, "user=<" usr ">", "user=<" masquer_compte(usr) ">")
    s = remplacer_partout(s, "sasl_username=" usr, "sasl_username=" masquer_compte(usr))
  }
  if (lu_exp != "") s = remplacer_partout(s, "<" lu_exp ">", "<" masquer_compte(lu_exp) ">")
  if (lu_dest != "") s = remplacer_partout(s, "<" lu_dest ">", "<" masquer_compte(lu_dest) ">")
  return masquer_adresses(s)
}
# P10.32-f — LE COURRIER SORTANT, `postfix/smtp[pid]:` (le client SMTP de Postfix sous son nom par défaut ;
# `postfix/smtp-amavis/smtp` et `postfix/lmtp` sont des SAUTS INTERNES, d’autres étiquettes). Gabarit de
# `log_adhoc.c` : `<file>: to=<…>, [orig_to=<…>, ]relay=<hôte>[<adresse>]:<port>|none, [conn_use=<n>, ]
# delay=…, delays=a/b/c/d, dsn=x.y.z, status=<sent|deferred|bounced> (<texte>)`. Ce que le CLIENT écrit :
# l’adresse du destinataire (partie locale entre guillemets admise) ; ce que le SERVEUR DISTANT écrit : le
# texte entre parenthèses. La suite `relay=… status=… (` n’est lue que si elle n’y figure qu’UNE fois —
# copiée par l’un ou l’autre, elle ne peut que se TAIRE : l’événement part alors en `ambiguous`, sans champ,
# plutôt que sous un statut choisi par le texte. Un relais en boucle locale (`127.x`, `::1`) est un filtre
# de contenu posé sous le nom par défaut : un saut interne, rien.
function lire_sortant(m,   n, s, avant, a, rl, ds, st, rd, sev){
  n = occurrences(m, SUITE_SORTANT)
  if (n == 0) return
  # P10.32-l — le destinataire lu (`to=<…>`, en tête du message) est masqué à sa place, ses recopies aussi.
  if (match(m, /^[0-9A-Za-z]+: to=<[^<>]*>/)) { lu_dest = substr(m, RSTART, RLENGTH - 1); sub(/^[^<]*</, "", lu_dest) }
  if (n > 1) { emit("mailflow","ambiguous",2,"","","smtp",""); return }
  match(m, SUITE_SORTANT); avant = substr(m, 1, RSTART - 1); s = substr(m, RSTART, RLENGTH)
  match(s, /relay=[^ ,]+/); rl = substr(s, RSTART + 6, RLENGTH - 6)
  if (rl ~ /\[(127[.][0-9.]+|::1)\]/) return
  match(s, /dsn=[0-9.]+/); ds = substr(s, RSTART + 4, RLENGTH - 4)
  match(s, /status=[a-z]+/); st = substr(s, RSTART + 7, RLENGTH - 7)
  rd = ""
  if (avant ~ /^[0-9A-Za-z]+: to=<[^<>]*>(, orig_to=<[^<>]*>)?$/) {
    a = avant; sub(/^[^<]*</, "", a); sub(/>.*/, "", a)
    if (index(a, "@") > 0) { sub(/^.*@/, "", a); if (a ~ /^[A-Za-z0-9_.-]+$/) rd = tolower(a) }
  }
  sev = (st == "sent") ? 1 : (st == "deferred") ? 2 : 3
  emit("mailflow",st,sev,"","","smtp",",\"rcpt_domain\":\"" rd "\",\"relay\":\"" jesc(rl) "\",\"dsn\":\"" ds "\"")
}
# P10.32-f — LE JOURNAL DE CLAMAV (`LogTime yes`) : `<Jour> <Mois> <jj> <hh:mm:ss> <aaaa> -> <message>`,
# jour du mois complété par une ESPACE sous dix (`ctime`). L’heure est MURALE, sans décalage : `mur` (lue
# sous TZ=UTC) sert au filigrane, `mur - decal` à l’horodatage. Le filigrane est le couple
# `<mur> <vues>` : une ligne d’une seconde antérieure est déjà vue ; à la seconde du filigrane, les `vues`
# premières le sont ; toute autre est neuve. Un passage qui coupe au plafond ne compte que ce qu’il a lu.
# UN MÊME VIRUS COMPTE DEUX FOIS, DIT : amavis le signale (service `amavis`, adresse relais) et clamd, qui
# a fait l’analyse pour lui, aussi (service `clamd`, sans adresse) — deux événements `malware` de sévérité
# 4. Aucun champ ne les relie (clamd ne connaît ni le mail_id ni le client) : un compte de virus compte des
# verdicts, pas des messages.
# CE QUE CE FILIGRANE NE TIENT PAS, DIT : le retour d’heure d’hiver (l’heure murale rejoue une heure :
# ses lignes sont tenues pour vues), et une fenêtre `tail` qui ne contiendrait plus toutes les lignes de
# la seconde du filigrane.
function ligne_clamav(   d, mur, m, cat, act, sev, vir){
  if (n >= 3000) return
  if ($0 !~ /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-6][0-9] [0-9][0-9][0-9][0-9] -> /) return
  d = substr($0, 21, 4) " " MOIS[substr($0, 5, 3)] " " (substr($0, 9, 2) + 0) " " substr($0, 12, 2) " " substr($0, 15, 2) " " substr($0, 18, 2)
  mur = mktime(d); if (mur < 0) return
  if (mur > maxmur) { maxmur = mur; vues_max = 0 }
  if (mur == maxmur) vues_max++
  if (mur < last) return
  if (mur == last) { deja++; if (deja <= vues) return }
  et = mur - decal
  m = substr($0, 29); cat = ""; vir = ""
  if (m ~ /virus database is older than/) { cat = "update"; act = "database_stale"; sev = 3 }
  else if (flux == "clamd") {
    if (match(m, /: [^ ]+ FOUND$/)) { cat = "malware"; act = "infected"; sev = 4; vir = substr(m, RSTART + 2, RLENGTH - 8) }
    else if (m ~ /^(ERROR|LibClamAV Error): /) {
      cat = "av_error"; sev = 3; act = "error"
      if (m ~ /SelfCheck/) act = "selfcheck_failed"
      else if (m ~ /[Rr]eload|[Dd]atabase load/) act = "reload_failed"
    }
    else if (m ~ /: .* ERROR$/) { cat = "av_error"; act = "scan_error"; sev = 3 }
    else if (m ~ /^Database correctly reloaded \(/) { cat = "update"; act = "reloaded"; sev = 1 }
  } else {
    if (m ~ /^WARNING: Your ClamAV installation is OUTDATED/) { cat = "update"; act = "outdated"; sev = 2 }
    else if (m ~ /^ERROR: /) { cat = "update"; act = "update_failed"; sev = 3 }
    else if (m ~ /^[A-Za-z0-9_-]+[.]c[lv]d updated [(]version: /) { cat = "update"; act = "updated"; sev = 1 }
  }
  if (cat == "") return
  emit(cat, act, sev, "", "", flux, (vir != "") ? (",\"virus\":\"" jesc(vir) "\"") : "")
}
# P10.32-f — OPENDKIM : les VERDICTS de vérification, `<file>: <verdict>`, et la signature posée sur un
# message sortant. `not internal` et `not authenticated` sont des INFORMATIONS (le message n’est ni local ni
# authentifié, donc vérifié plutôt que signé) : rien. `key retrieval failed` est un échec de la RÉSOLUTION de
# clé (DNS), pas une signature fausse : sévérité 2, comme un report.
function lire_opendkim(m,   d){
  d = ""
  if (match(m, /^[0-9A-Za-z]+: (key retrieval failed|DKIM-Signature field added) \(s=[^ ,()]*, d=[A-Za-z0-9_.-]*\)/)) {
    d = substr(m, RSTART, RLENGTH - 1); sub(/^.*, d=/, "", d); d = tolower(d)
  }
  if (m ~ /^[0-9A-Za-z]+: DKIM verification successful$/) emit("mail","pass",1,"","","opendkim",",\"domain\":\"\"")
  else if (m ~ /^[0-9A-Za-z]+: bad signature data$/) emit("mail","fail",3,"","","opendkim",",\"domain\":\"\"")
  else if (m ~ /^[0-9A-Za-z]+: no signature data$/) emit("mail","none",1,"","","opendkim",",\"domain\":\"\"")
  else if (m ~ /^[0-9A-Za-z]+: key retrieval failed \(/ && d != "") emit("mail","error",2,"","","opendkim",",\"domain\":\"" d "\"")
  else if (m ~ /^[0-9A-Za-z]+: DKIM-Signature field added \(.*\)$/ && d != "") emit("mail","signed",1,"","","opendkim",",\"domain\":\"" d "\"")
}
# P10.32-f — OPENDMARC : `<file>: <domaine de From:> <résultat>`, le résultat en FIN de ligne et le domaine
# sans espace, ou rien.
function lire_opendmarc(m,   r, d){
  if (m !~ /^[0-9A-Za-z]+: [A-Za-z0-9_.-]+ (pass|fail|none|bestguesspass|temperror|permerror)$/) return
  r = m; sub(/^.* /, "", r); d = m; sub(/^[^ ]+ /, "", d); sub(/ .*$/, "", d)
  emit("mail", r, (r == "fail") ? 3 : (r ~ /error$/) ? 2 : 1, "", "", "opendmarc", ",\"domain\":\"" tolower(d) "\"")
}
# P10.32-f — POLICYD-SPF : `: prepend Received-SPF: <Résultat> (<commentaire>) identity=<…>; client-ip=<a>;
# helo=<…>; envelope-from=<…>; receiver=<…>`. Le résultat est la TÊTE du message. Le CLIENT écrit le HELO et
# l’expéditeur : `client-ip=` n’est lu que derrière `identity=…; ` et s’il n’y figure qu’une fois,
# l’expéditeur que si `; envelope-from=` n’y figure qu’une fois — copiés, ils se TAISENT. Du second, le
# DOMAINE seul est un champ. Un refus de policyd-spf lui-même (`550 5.7.23 …`) n’est pas lu ici : smtpd
# l’écrit en `NOQUEUE: reject:`, déjà émis.
function lire_policyd_spf(m,   r, s, sip, d){
  if (!match(m, /^: prepend Received-SPF: (Pass|Fail|Softfail|Neutral|None|Temperror|Permerror) /)) return
  r = tolower(substr(m, 25, RLENGTH - 25))
  sip = ""
  if (occurrences(m, " identity=[a-z]+; client-ip=") == 1) {
    match(m, / identity=[a-z]+; client-ip=[^; ]*;/); s = substr(m, RSTART, RLENGTH - 1); sub(/^.*client-ip=/, "", s); sip = adresse(s)
  }
  d = ""
  if (occurrences(m, "; envelope-from=") == 1) {
    s = substr(m, index(m, "; envelope-from=") + 16); sub(/[; ].*$/, "", s)
    if (index(s, "@") > 0) sub(/^.*@/, "", s)
    if (s ~ /^[A-Za-z0-9_.-]+$/) d = tolower(s)
  }
  emit("mail", r, (r == "fail") ? 3 : (r == "softfail" || r ~ /error$/) ? 2 : 1, sip, "", "policyd-spf", ",\"domain\":\"" d "\"")
}
# P10.32-f — LA FILE, `postfix/qmgr` : `<file>: from=<expéditeur>, size=<octets>, nrcpt=<n> (queue active)`
# à l’entrée en file active, `<file>: from=<…>, status=expired, returned to sender` à l’expiration. La suite
# est ANCRÉE en fin de ligne : l’expéditeur (écrit par le client) est tout ce qui la précède, et ne peut
# pas la recopier.
function lire_qmgr(m,   s, f, sz, nr){
  if (match(m, /^[0-9A-Za-z]+: from=<.*>, size=[0-9]+, nrcpt=[0-9]+ \(queue active\)$/)) {
    s = m; sub(/^[0-9A-Za-z]+: from=</, "", s)
    match(s, />, size=[0-9]+, nrcpt=[0-9]+ \(queue active\)$/); f = substr(s, 1, RSTART - 1); s = substr(s, RSTART)
    match(s, /size=[0-9]+/); sz = substr(s, RSTART + 5, RLENGTH - 5)
    match(s, /nrcpt=[0-9]+/); nr = substr(s, RSTART + 6, RLENGTH - 6)
    lu_exp = f
    emit("mailflow","queued",1,"","","qmgr",",\"sender\":\"" jesc(masquer_compte(f)) "\",\"size\":\"" sz "\",\"nrcpt\":\"" nr "\"")
  } else if (m ~ /^[0-9A-Za-z]+: from=<.*>, status=expired, returned to sender$/) {
    f = m; sub(/^[0-9A-Za-z]+: from=</, "", f); sub(/>, status=expired, returned to sender$/, "", f)
    lu_exp = f
    emit("mailflow","expired",2,"","","qmgr",",\"sender\":\"" jesc(masquer_compte(f)) "\"")
  }
}
function emit(cat,act,sev,ip,usr,svc,extra,dk,   dd){
  # malware/banned/av_error/mailflow = signaux amavis/clamav : emis MEME sans src_ip (le verdict
  # amavis ne porte pas toujours une IP relais) ; les autres exigent une src_ip (respect de skipip).
  # P10.23-i — une ligne CLASSÉE (auth, postscreen, rejet) dont l’adresse ne se valide pas n’est pas
  # émise, mais elle est COMPTÉE, par catégorie, et le compte est avoué en fin de passage
  # (`plume_adresse_illisible`). L’adresse SKIP_IP, déclarée par l’enveloppe `collection-reducing`,
  # reste hors du compte.
  # P10.32-f — `mail` (verdicts DKIM/DMARC/SPF), `mailflow` (sortant, file) et `update` (journal ClamAV) n’ont pas de
  # client à attribuer : émis sans adresse, comme amavis. Un verdict SPF porte l’adresse du client
  # (`client-ip=`) : l’adresse SKIP_IP y est écartée comme ailleurs.
  if(cat!="malware" && cat!="banned" && cat!="av_error" && cat!="mailflow" && cat!="mail" && cat!="update") {
    if (ip=="") { sans_adresse++; sans_adresse_par[cat]++; return }
    if (ip==skipip) return
  } else if (cat=="mail" && ip!="" && ip==skipip) return
  # P10.24-h — la clé de repli était `mail-<seconde>-<adresse>-<action>` pour TOUT événement sans clé
  # propre (auth, postscreen, rejet, entrée amavis sans identifiant, panne) : deux échecs de la même
  # adresse dans la même seconde, même sur deux comptes, portaient la même clé, et l’ingestion
  # (`INSERT OR IGNORE`) écartait le second. L’empreinte de la ligne s’y ajoute.
  # P10.32-f — l’empreinte est celle du MESSAGE ÉMIS : pour le sortant, la ligne masquée. Prise sur la ligne
  # brute, la clé (requêtable) laissait retrouver une partie locale masquée en essayant des candidats. CE QUE
  # CELA COÛTE, DIT : deux lignes sortantes qui ne diffèrent QUE par la partie locale, à la microseconde près,
  # portent la même clé et l’ingestion en écarte une.
  # P10.32-l — et le message émis est masqué pour TOUTE ligne (`masquer_ligne`), le compte aussi.
  message_emis = masquer_ligne($0, usr)
  dd=(dk!="")?dk:("mail-" et "-" ip "-" act "-" empreinte(message_emis))
  ev="{\"ts\":" et ",\"source\":\"mail\",\"category\":\"" cat "\",\"severity\":" sev ",\"src_ip\":\"" ip "\",\"message\":\"" jesc(message_emis) "\",\"dedup\":\"" dd "\",\"fields\":{\"action\":\"" act "\",\"user\":\"" jesc(masquer_compte(usr)) "\",\"service\":\"" svc "\",\"src_ip\":\"" ip "\"" extra "}}"
  if(n>0) buf=buf ","; buf=buf ev; n++
}
BEGIN{ n=0; buf=""; maxts=last+0; sans_adresse=0
  # `Hits: <score>, size: <taille>` : les deux champs qu’amavis écrit TOUJOURS, côte à côte, dans ses deux
  # gabarits ; score `-`, `-1.1`, `3` ou `2.1..5.3` (`macro_score`).
  SUITE_HITS_SIZE = ", Hits: (-|-?[0-9]+([.][0-9]+)?([.][.]-?[0-9]+([.][0-9]+)?)?), size: [0-9]+"
  for (i = 1; i < 256; i++) OCTET[sprintf("%c", i)] = i
  # P10.32-f — la suite que `postfix/smtp` écrit après le destinataire (`lire_sortant`).
  SUITE_SORTANT = ", relay=[^ ,]+, (conn_use=[0-9]+, )?delay=[0-9.]+, delays=[0-9.]+/[0-9.]+/[0-9.]+/[0-9.]+, dsn=[0-9][.][0-9]+[.][0-9]+, status=(sent|deferred|bounced) [(]"
  split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", noms, " ")
  for (i = 1; i <= 12; i++) MOIS[noms[i]] = i
  # Journal ClamAV : filigrane `<mur> <vues>`, décalage `±hh:mm` (vide ou illisible : +00:00).
  maxmur = last + 0; vues_max = 0; deja = 0; vues += 0; decal = 0
  if (decalage ~ /^[+-][0-2][0-9]:[0-5][0-9]$/) decal = (substr(decalage, 1, 1) == "-" ? -1 : 1) * (substr(decalage, 2, 2) * 3600 + substr(decalage, 5, 2) * 60)
  dernier_decalage = "" }
{
  message_emis = ""; lu_exp = ""; lu_dest = ""
  if (flux != "mail") { ligne_clamav(); next }
  if (n>=3000) next                                             # garde-fou volume/passage
  if ($0 !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/) next
  d=substr($0,1,19); gsub(/[-T:]/," ",d); base=mktime(d); if(base<0) next
  off=0; if (match($0,/[+-][0-9][0-9]:[0-9][0-9]/)) { o=substr($0,RSTART,RLENGTH); s=(substr(o,1,1)=="-")?-1:1; off=s*(substr(o,2,2)*3600+substr(o,5,2)*60); dernier_decalage=o }
  et=base-off
  if (et <= last) next
  if (et > maxts) maxts=et
  # P10.22-v — L’ÉTIQUETTE EST CELLE DE L’EN-TÊTE SYSLOG, PAS UN MOT DE LA LIGNE. Le journal est
  # `<horodatage> <hôte> <étiquette>: <message>` ; `dovecot:` (ou `postfix/…/smtpd[pid]:`) n’est lu
  # qu’en TROISIÈME champ. Cherchée partout, l’étiquette `dovecot:` se trouvait aussi dans un `helo=<…>`
  # ou un texte de pré-salutation Postfix : n’importe quel client fabriquait une connexion RÉUSSIE, à
  # l’utilisateur et à l’adresse de son choix. `user=<…>` n’est lu que dans un message Dovecot : dans
  # une ligne Postfix, il ne peut venir que du client.
  dvc=""; if (match($0,/^[^ ]+ [^ ]+ dovecot(\[[0-9]+\])?: /)) dvc=substr($0,RSTART+RLENGTH)
  psd=""; if (match($0,/^[^ ]+ [^ ]+ postfix(\/[A-Za-z0-9_.-]+)*\/smtpd\[[0-9]+\]: /)) psd=substr($0,RSTART+RLENGTH)
  pss=""; if (match($0,/^[^ ]+ [^ ]+ postfix(\/[A-Za-z0-9_.-]+)*\/postscreen\[[0-9]+\]: /)) pss=substr($0,RSTART+RLENGTH)
  amv=""; if (match($0,/^[^ ]+ [^ ]+ amavis\[[0-9]+\]: /)) amv=substr($0,RSTART+RLENGTH)
  dkm=""; if (match($0,/^[^ ]+ [^ ]+ opendkim\[[0-9]+\]: /)) dkm=substr($0,RSTART+RLENGTH)
  dmc=""; if (match($0,/^[^ ]+ [^ ]+ opendmarc\[[0-9]+\]: /)) dmc=substr($0,RSTART+RLENGTH)
  spf=""; if (match($0,/^[^ ]+ [^ ]+ policyd-spf\[[0-9]+\]: /)) spf=substr($0,RSTART+RLENGTH)
  smt=""; if (match($0,/^[^ ]+ [^ ]+ postfix\/smtp\[[0-9]+\]: /)) smt=substr($0,RSTART+RLENGTH)
  qmg=""; if (match($0,/^[^ ]+ [^ ]+ postfix(\/[A-Za-z0-9_.-]+)*\/qmgr\[[0-9]+\]: /)) qmg=substr($0,RSTART+RLENGTH)
  msg=""; if (match($0,/^[^ ]+ [^ ]+ [^ ]+ /)) msg=substr($0,RSTART+RLENGTH)
  ip=""; if (dvc != "") ip=adresse(rip_de_dovecot(dvc)); else ip=adresse(crochet_du_client(msg))
  usr=""; if (dvc != "" && match(dvc,/user=<[^>]*>/)) usr=substr(dvc,RSTART+6,RLENGTH-7)
  svc="postfix"; if (dvc != "") svc="dovecot"; else if (pss != "") svc="postscreen"
  # P10.22-j — connexions Dovecot, 2.3 ET 2.4 (témoin : collectors/mail-connexions-dovecot.corpus).
  # Succès : 2.3 `Login:`, 2.4 `Logged in:` (émis par login-common, donc aussi par managesieve-login).
  # Lu en TÊTE du message Dovecot, et nulle part ailleurs : le `user=<…>` qui suit est fourni par le
  # client. Le deux-points fait partie du motif : 2.4 écrit `Login aborted:` pour une connexion qui
  # N A PAS abouti, et `Login` en est le préfixe.
  # Échec, ANCRÉ COMME LE SUCCÈS (P10.22-v) — trois formes et aucune autre :
  #   Dovecot, en tête du message et AVANT le premier champ (`[^<=]*` : ni `user=<` ni `rip=` encore) :
  #     `(auth failed, …)` (2.3 et 2.4) ; `Aborted login` (2.3 : `Disconnected: Aborted login by
  #     logging out`) ; `Login aborted: Logged out`, son pendant 2.4. Une fermeture sans tentative
  #     (`Login aborted: Connection closed (no auth attempts…)`) ne compte pas, comme en 2.3.
  #   Postfix, serveur smtpd seulement : `warning: nom[adresse]: SASL <mécanisme> authentication failed`.
  # Cherché partout, le bras comptait en échec d’authentification un `helo=<auth failed>`, un expéditeur,
  # une commande HTTP envoyée au port de soumission, un texte de pré-salutation — et l’échec de NOTRE
  # relais sortant, imputé à l’adresse du relais.
  if (dvc ~ /^(imap|pop3|submission|managesieve)-login: (Login|Logged in): /) emit("auth","success",1,ip,usr,svc)
  else if (dvc ~ /^(imap|pop3|submission|managesieve)-login: [^<=]*\(auth failed[,)]/ ||
           dvc ~ /^(imap|pop3|submission|managesieve)-login: (Disconnected: )?Aborted login[ (]/ ||
           dvc ~ /^(imap|pop3|submission|managesieve)-login: Login aborted: Logged out /) emit("auth","failure",2,ip,usr,svc)
  # P10.23-h — l’échec SASL de smtpd porte son utilisateur (`utilisateur_sasl`), lu après la forme ancrée.
  else if (match(psd, /^warning: [A-Za-z0-9._-]+\[[0-9A-Fa-f:.]+\](:[0-9]+)?: SASL [A-Za-z0-9_-]+ authentication failed/)) emit("auth","failure",2,ip,utilisateur_sasl(substr(psd,RSTART+RLENGTH)),svc)
  # P10.23-f — POSTSCREEN ET REJET, ANCRÉS COMME L’AUTHENTIFICATION : lus en TÊTE du message, sous
  # l’étiquette du démon qui les écrit, et nulle part ailleurs. Cherchés partout, un `helo=<postscreen
  # PREGREET>` faisait d’un rejet smtpd un blocage postscreen (service compris), une sonde HTTP portant
  # `NOQUEUE: reject` au port de soumission devenait un rejet, un texte du client dans un message
  # Dovecot devenait un blocage — et le `helo` du rejet de postscreen lui-même en choisissait la
  # catégorie. Formes lues dans les sources Postfix (`postscreen.c`, `postscreen_early.c`,
  # `postscreen_smtpd.c`, `smtpd_check.c`) ; HANGUP, PASS, CONNECT et ALLOWLISTED restent hors des
  # blocages (bruit des sondes du nœud, parité avec l’ancien motif).
  # P10.23-g — la liste de refus s’écrit `BLACKLISTED` ou `DENYLISTED` selon `respectful_logging`, dont
  # le défaut vaut `yes` dès `compatibility_level` 3.6 : les deux formes sont lues.
  # P10.23-y — postscreen coupe aussi une session pour `COMMAND LENGTH LIMIT` (`line_length_limit`
  # dépassé) et pour `DATA`/`BDAT without valid RCPT` (postscreen refuse tout destinataire et n’annonce
  # pas PIPELINING : un client légitime n’envoie jamais DATA ni BDAT) — `postscreen_smtpd.c`.
  # Rejet : `NOQUEUE: reject: <étape> …` (smtpd et postscreen ; l’étape est écrite par le serveur, et
  # peut porter une espace : `DATA content`) ; `<file|NOQUEUE>: (milter-)reject: <étape> from …` (smtpd,
  # `log_whatsup` de `smtpd_check.c` et `milter-reject` de `smtpd.c`), l’étape étant l’une de celles que
  # smtpd écrit (`smtpd.h`) — P10.23-y : sous identifiant de file, le rejet après le premier destinataire
  # accepté (`DATA`, `END-OF-MESSAGE`, `bare <LF> received`…) et le rejet d’un milter à la fin du message
  # n’étaient pas lus ; seule l’étape RCPT l’était.
  else if (pss ~ /^(PREGREET [0-9]+ after |DNSBL rank [0-9]+ for |(BLACK|DENY)LISTED \[|COMMAND (PIPELINING|TIME LIMIT|COUNT LIMIT|LENGTH LIMIT) from |BARE NEWLINE from |NON-SMTP COMMAND from |(DATA|BDAT) without valid RCPT from )/) emit("postscreen","blocked",2,ip,usr,"postscreen")
  else if (pss ~ /^NOQUEUE: reject: / || psd ~ /^NOQUEUE: reject: / || psd ~ /^[0-9A-Za-z]+: (milter-)?reject: (CONNECT|HELO|EHLO|STARTTLS|AUTH|MAIL|RCPT|DATA|DATA content|BDAT|BDAT content|END-OF-MESSAGE|RSET|NOOP|VRFY|ETRN|QUIT|XCLIENT|XFORWARD|UNKNOWN|HELP) from /) emit("reject","blocked",2,ip,usr,svc)
  # P10.23-w — AMAVIS, SOUS SON ÉTIQUETTE `amavis[pid]:` ET EN TÊTE DE SON MESSAGE. Cherché partout, le
  # verdict se lisait dans une commande HTTP envoyée au port de soumission (`GET /amavis[1]: Blocked
  # INFECTED (…)` : alerte malware de sévérité quatre, virus au choix, à l’adresse du client), dans un
  # `ID` IMAP, dans le nom d’une pièce jointe recopié par amavis lui-même (`p.path`, niveau 1). Verdict :
  # l’entrée principale `(<id>) Passed|Blocked <catégorie>` (catégories de `$log_short_templ`), champs
  # lus par `lire_amavis`. Panne du scanner : `(<id>) (!)<scanner> av-scanner FAILED: …` et `(<id>)
  # (!)WARN: all primary virus scanners failed…` (`lib/Amavis/AV.pm`, niveau -1) ; `(!!)AV: ALL VIRUS
  # SCANNERS FAILED` suit toujours ce WARN (même passage) et n’est pas lu. La panne n’a pas de client :
  # aucune adresse (l’ancien bras prenait celle du démon clamd, `[::1]:3310`, pour une adresse source).
  else if (amv ~ /^\([^ ()]+\) (Passed|Blocked) ((CLEAN|OTHER|MTA-BLOCKED|OVERSIZED|BAD-HEADER-[0-9]+|SPAMMY|SPAM|UNCHECKED|UNCHECKED-ENCRYPTED) [{]|(INFECTED|BANNED) \()/) {
    lire_amavis(amv)
    mcat="mailflow"; msev=1; mact="pass"
    if (vd ~ /INFECTED$/) { mcat="malware"; msev=4; mact="infected" }
    else if (vd ~ /BANNED$/) { mcat="banned"; msev=3; mact="banned" }
    else if (vd ~ /SPAM/) { msev=2; mact="spam" }
    else if (vd ~ /^Blocked/) { msev=2; mact="blocked" }
    # P10.33-f — sauf, sur INFECTED et BANNED, le destinataire LOCAL si l’exploitant l’a demandé (`destinataire_emis`).
    # P10.32-l — destinataire masqué ; expéditeur masqué SAUF sur une entrée ORIGINAIRE (`LOCAL`) : c’est le
    # compte de ce serveur, que `ex-mail-mass-outbound` compte (`stats count by sender`).
    lu_exp = frm; lu_dest = rcpt
    ext=",\"verdict\":\"" jesc(vd) "\",\"sender\":\"" jesc(orig ? frm : masquer_compte(frm)) "\",\"rcpt\":\"" jesc(destinataire_emis(rcpt, mcat)) "\",\"score\":\"" jesc(sco) "\",\"size\":\"" sz "\""
    if (vd ~ /INFECTED$/) ext=ext ",\"virus\":\"" jesc(vir) "\""
    if (coupee) ext=ext ",\"truncated\":\"1\""
    # P10.24-j — `$log_short_templ` a DEUX blocs, `Passed …` (destinataires livrés, `%#D`) et `Blocked …`
    # (destinataires bloqués, `%#O`), développés ensemble par message : un message au sort partagé écrit
    # deux entrées au MÊME mail_id (amavis, `lib/Amavis.pm`, section __DATA__, commit 7d473b22). La clé
    # `mail-<id>` les confondait ; elle porte désormais le verdict et la catégorie (`vd` : `Passed CLEAN`).
    # EFFET SUR UNE RÈGLE, DIT : un message au sort partagé dont la catégorie est de flux (SPAM, CLEAN…)
    # donne DEUX événements `mailflow` au même expéditeur, là où l’ingestion en écartait un. La règle de
    # catalogue `ex-mail-mass-outbound` (`stats count by sender`, désactivée par défaut) le compte deux fois :
    # elle compte des entrées, pas des messages (le mail_id n’est pas un champ de l’événement).
    # P10.32-f — la file (`qmgr`) et le sortant (`smtp`) sont aussi `mailflow` : la règle se borne à
    # `service=amavis`, sans quoi chaque message compterait deux fois et le sortant, sans `sender`, ferait un
    # groupe vide de tous les envois.
    emit(mcat,mact,msev,aip,rcpt,"amavis",ext,(mid!=""?("mail-" mid "-" substr(vd,1,index(vd," ")-1) "-" substr(vd,index(vd," ")+1)):""))
  }
  else if (amv ~ /^\([^ ()]+\) \(!!?\)([^:]* av-scanner FAILED: |WARN: all primary virus scanners failed)/) emit("av_error","error",3,"","","clamav","")
  # P10.32-f — L’ENVOI AUTHENTIFIÉ RÉUSSI, sous l’étiquette de smtpd et en tête de son message : smtpd écrit
  # `<file>: client=<nom>[<adresse>], sasl_method=<mécanisme>, sasl_username=<nom>` (`smtpd.c`) quand un
  # client AUTHENTIFIÉ ouvre un message — seule ligne de succès SASL de Postfix. Le nom est celui que le
  # serveur SASL a ACCEPTÉ ; il court jusqu’à `, sasl_sender=` ou `, orig_` (champs que smtpd écrit après).
  # Témoin : collectors/mail-soumission-authentifiee.corpus. Un client `unknown[unknown]` (P10.23-i) est
  # lu : sans adresse valide, la ligne n’est pas émise mais COMPTÉE (`plume_adresse_illisible`, `auth=`).
  else if (match(psd, /^[0-9A-Za-z]+: client=[A-Za-z0-9._-]+\[([0-9A-Fa-f:.]+|unknown)\](:[0-9]+)?, sasl_method=[A-Za-z0-9_-]+, sasl_username=/)) {
    su = substr(psd, RSTART + RLENGTH); mth = psd; sub(/^[^,]*, sasl_method=/, "", mth); sub(/,.*$/, "", mth)
    p = index(su, ", sasl_sender="); if (p > 0) su = substr(su, 1, p - 1)
    p = index(su, ", orig_"); if (p > 0) su = substr(su, 1, p - 1)
    emit("auth","success",1,ip,su,svc,",\"method\":\"" jesc(mth) "\"")
  }
  # P10.32-f — verdicts de l’EXPÉDITEUR (opendkim, opendmarc, policyd-spf), sortant et file, chacun sous
  # SON étiquette (témoins : collectors/mail-opendkim.corpus, mail-opendmarc.corpus, mail-policyd-spf.corpus,
  # mail-sortant-postfix-smtp.corpus, mail-file-qmgr.corpus).
  else if (dkm != "") lire_opendkim(dkm)
  else if (dmc != "") lire_opendmarc(dmc)
  else if (spf != "") lire_policyd_spf(spf)
  else if (smt != "") lire_sortant(smt)
  else if (qmg != "") lire_qmgr(qmg)
}
END{
  if (n>0) printf "{\"ts\":%d,\"host\":\"%s\",\"kind\":\"events\",\"events\":[%s]}\n", now, host, buf > out
  # Journal ClamAV : une ligne, le filigrane `<mur> <vues>`. Aucune ligne lue à la seconde du filigrane ni
  # après (journal remplacé par un plus ancien) : il reste tel quel, sans quoi `<mur> 0` rejouerait les lignes
  # de cette seconde. Des lignes lues à cette seconde, mais moins que `vues` (journal tourné dans la seconde) :
  # c’est leur nombre qui compte, pour que les suivantes ne soient pas tenues pour vues.
  if (flux != "mail") { if (maxmur == last + 0 && vues_max == 0) vues_max = vues; print maxmur " " vues_max; exit }
  # Une ligne : le filigrane, puis le compte P10.23-i et sa ventilation (un mot, sans espace).
  # P10.32-f — en quatrième mot, le décalage de la dernière ligne lue : celui du journal ClamAV par défaut.
  print maxts " " sans_adresse " auth=" (sans_adresse_par["auth"]+0) ",postscreen=" (sans_adresse_par["postscreen"]+0) ",reject=" (sans_adresse_par["reject"]+0) " " dernier_decalage
}'
# P10.32-f — UN JOURNAL VIDE N'ARRÊTE PLUS LE PASSAGE : le journal ClamAV se lit quand même. Le filigrane
# de mail.log n'est mis en attente que sur une lecture qui a rendu des lignes (inchangé sinon).
decalage_mail=""
if [ -n "$raw" ]; then
tmp=$(mktemp "$SPOOL/.mail.XXXXXX")
sortie=$(printf '%s\n' "$raw" | LC_ALL=C TZ=UTC awk -v flux=mail -v last="$last" -v host="$host" -v now="$now" -v out="$tmp" -v skipip="$SKIPIP" -v demasquer_local="$demasquer_rcpt_local" -v domaines_locaux="$domaines_locaux" "$_PLUME_AWK_ECHAPPEMENT_JSON""$PROGRAMME_MAIL")
read -r newwm sans_adresse ventilation_sans_adresse decalage_mail <<EOF
$sortie
EOF

# S30 — l'ordre etait DEJA le bon ; le filigrane est MIS EN ATTENTE et ecrit par la publication
# elle-meme. Quand il n'y a aucune ligne a publier, c'est l'enveloppe de config de fin — toujours
# emise — qui l'ecrit : un capteur n'a jamais le geste d'acquitter a sa disposition.
state_stage "$WM" "${newwm:-$last}"
if [ -s "$tmp" ]; then spool_publish_then_ack "$tmp" "mail-$now.json"; else rm -f "$tmp"; fi
# P10.23-i — les lignes classées mais non émises faute d'adresse valide, COMPTÉES et avouées.
case "${sans_adresse:-}" in
  ''|*[!0-9]*|0) ;;
  *) plume_adresse_illisible mail "$sans_adresse" "Ventilation : $ventilation_sans_adresse. Lignes auth, postscreen et rejet seulement ; les verdicts amavis sont émis sans adresse à dessein, et l'adresse SKIP_IP est déclarée à part." ;;
esac
fi

# P10.32-f — LE JOURNAL CLAMAV, un passage par démon (`clamd`, `freshclam`), chacun son filigrane
# `<heure murale> <lignes vues à cette seconde>`. `etat_clamav` dit ce qui en a été lu, dans l'enveloppe
# de config : `lu`, `absent` (chemin par défaut sans fichier), `coupe` (variable posée vide), `illisible`
# (avoué par `plume_lecture_partielle`, filigrane non avancé).
etat_clamav=""
lire_clamav() {  # <flux> <chemin> <posé : 1 ou vide>
  _cf=$1; _cp=$2; _cpose=$3; _cw="$STATE_DIR/mail-$1.watermark"
  if [ -z "$_cp" ]; then etat_clamav="$etat_clamav $_cf=coupe"; return 0; fi
  _crc=0; _craw=$(lire_journal "$_cp") || _crc=$?
  if [ "$_crc" = 3 ] && [ -z "$_cpose" ]; then etat_clamav="$etat_clamav $_cf=absent"; return 0; fi
  if [ "$_crc" != 0 ]; then
    if [ "$_crc" = 3 ]; then _ccause=source_absente; else _ccause=source_illisible; fi
    plume_lecture_partielle mail "$_ccause" "journal $_cf de ClamAV illisible (PLUME_MAIL_SRC=$MAILSRC) : son filigrane n'avance pas, le reste du passage est publie"
    etat_clamav="$etat_clamav $_cf=illisible"; return 0
  fi
  etat_clamav="$etat_clamav $_cf=lu"
  [ -n "$_craw" ] || return 0
  _cmur=0; _cvues=0
  # Le filigrane est écrit SANS fin de ligne : `read` rend alors 1 après avoir lu ; seul le contenu juge.
  if [ -r "$_cw" ]; then read -r _cmur _cvues < "$_cw" || true; fi
  case "${_cmur:-}" in ''|*[!0-9]*) _cmur=0; _cvues=0 ;; esac
  case "${_cvues:-}" in ''|*[!0-9]*) _cvues=0 ;; esac
  _ctmp=$(mktemp "$SPOOL/.mail-$_cf.XXXXXX")
  _csortie=$(printf '%s\n' "$_craw" | LC_ALL=C TZ=UTC awk -v flux="$_cf" -v last="$_cmur" -v vues="$_cvues" -v decalage="${CLAM_DECALAGE:-${decalage_mail:-+00:00}}" -v host="$host" -v now="$now" -v out="$_ctmp" -v skipip="" "$_PLUME_AWK_ECHAPPEMENT_JSON""$PROGRAMME_MAIL")
  state_stage "$_cw" "$_csortie"
  if [ -s "$_ctmp" ]; then spool_publish_then_ack "$_ctmp" "mail-$_cf-$now.json"; else rm -f "$_ctmp"; fi
}
lire_clamav clamd "$CLAMD_LOG" "$CLAMD_POSE"
lire_clamav freshclam "$FRESHCLAM_LOG" "$FRESHCLAM_POSE"

# --- CHANTIER whitelists->webui : AUTO-REPORT de config (source=mail category=config) --------------
# Surface PLUME_MAIL_SKIP_IP dans le panneau read-only « Suppressions & whitelists actives ». VISIBILITE
# cote daemon, CONTROLE ici. Dedup par empreinte. collection-reducing (drop des events de l'IP skippee).
cfg_fields=$(printf '{"type":"collection-reducing","collector":"mail","filters":{"skip_ip":"%s","max":"%s","clamav":"%s","destinataire_local":"%s","domaines_locaux":"%s"},"note":"ignore les events mail de SKIP_IP (probes internes/self) — postscreen HANGUP deja exclu. collecte reduite"}' \
  "$(json_escape "$SKIPIP")" "$(json_escape "$MAX")" "$(json_escape "${etat_clamav# }")" "$etat_rcpt_local" \
  "$(json_escape "$(printf '%s' "$domaines_locaux" | sed 's/^ //; s/ $//; s/ /,/g')")")
cfg_dd="cfg-mail-$(printf '%s' "$cfg_fields" | cksum | cut -d' ' -f1)"
spool_write_then_ack "config-mail-$now.json" "$(printf '{"ts":%s,"host":"%s","kind":"events","events":[{"ts":%s,"source":"mail","category":"config","severity":0,"message":"config collecteur mail (filtres de collecte)","dedup":"%s","fields":%s}]}' \
  "$now" "$host" "$now" "$cfg_dd" "$cfg_fields")"
