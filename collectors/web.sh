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
MAX="${PLUME_WEB_MAX:-10000}"                                 # lignes lues par passage (borne de lecture, P10.33-e)
WM="$STATE_DIR/web.watermark"
OFFS="$STATE_DIR/web.offset"                                  # mode file : « empreinte octet » du journal lu (P10.33-e)
WREP="$STATE_DIR/web.lecture"                                 # mode file : repere DATE du debut de la derniere lecture (P10.33-e)
last=$(cat "$WM" 2>/dev/null || echo 0)
now=$(date +%s)
since=$((now - last + 10)); [ "$last" -eq 0 ] && since=300       # 1re fois : 5 min en arriere
[ "$since" -gt 86400 ] && since=86400

# P10.33-e — LA BORNE DE LECTURE NE FAIT PLUS PERDRE EN SILENCE. Elle lisait les MAX DERNIERES lignes
# (`tail -n`, `kubectl logs --tail`) sans egard au filigrane : entre deux passages, un flot plus long que MAX
# — filtre ou non, un sondage de sante la consomme comme une requete — faisait sortir de la fenetre des
# lignes reelles jamais lues ni comptees ; seul le battement le disait, sans nombre ni reprise. Un attaquant
# pouvait noyer ses requetes sous un flot. Desormais (le battement dit « borne de lecture PLUME_WEB_MAX=$MAX
# atteinte », suivi de « restent à lire, repris au passage suivant » en mode file, de « jamais lue(s),
# comptée(s) et avouée(s) » en k3s) :
#  · MODE file — LECTURE PAR OFFSET D'OCTETS, comme auditd.sh : au plus MAX lignes COMPLETES a partir de
#    l'octet ou le passage precedent s'est arrete ; le reste est lu aux passages suivants, rien n'est saute. Ce
#    qui suit l'offset n'est plus filtre par le filigrane horaire (voir l'appel awk) : une seconde coupee en deux
#    par la borne n'en perd pas sa fin.
#    L'offset ne passe jamais une ligne coupee par le plafond de 9000 (il s'arrete devant la premiere), ni une
#    derniere ligne incomplete (ecriture en cours). Le fichier lu est reconnu a l'EMPREINTE de sa premiere
#    ligne (`cksum`), pas a son inode, que le systeme peut redonner a un journal neuf apres une rotation
#    compressee. ROTATION (empreinte changee ou fichier plus court que l'offset) : le reste non lu est cherche
#    dans `$PLUME_WEB_LOG.1` (renomme, ou copie de `copytruncate`), lu jusqu'au bout, puis le journal neuf
#    depuis son debut ; apres DEUX rotations, dans `.2` (ou `.2.gz` si gzip est la), puis `.1`, puis le courant
#    (voir web_lire_fichier) ; s'il est introuvable (rotation compressee sans `delaycompress`), les journaux tournes
#    modifies depuis le passage precedent sont lus, et la perte est AVOUEE (`missing-source`, nombre inconnu).
#    Premier passage (ou etat de lecture illisible) : les MAX dernieres lignes, comme avant, filtrees par le
#    filigrane ; ce qui les precede n'est pas lu, et le battement le DIT ;
#  · MODE k3s — `kubectl logs` ne sait rendre que les DERNIERES lignes d'une fenetre (`--tail`) : la perte n'est
#    pas evitable a cout borne, elle est COMPTEE. Quand la borne est atteinte, un second `kubectl logs` sur la
#    meme fenetre passe dans un awk qui ne garde rien en memoire : il compte les requetes posterieures au
#    filigrane ecrites (horodatage du runtime, `--timestamps`) au plus tard a la plus RECENTE ligne lue (le MAX
#    des horodatages : `kubectl` met les pods bout a bout, la derniere ligne est celle du dernier pod) ; la
#    difference avec celles lues est le nombre de lignes sautees, avoue par `collection-capped`. Ce second appel
#    porte un `--tail` EXPLICITE (et PAS de `--since` : compte exact par pod, voir plus bas) : sans lui, `kubectl logs -l` rend 10 lignes par pod (`kubectl logs --help` :
#    « Defaults to -1 with no selector, showing all log lines otherwise 10, if a selector is provided »), et le
#    compte, plafonne a 10, se lisait « 0 ligne sautee ». Ce `--tail` vaut 10 x PLUME_WEB_MAX par pod : le compte
#    ne garde rien en memoire, mais chaque ligne relue traverse l'API ; un pod dont la plus ancienne ligne rendue
#    ne precede pas la fenetre est avoue « au moins N », par son nom (`--prefix`), les autres en nombre exact. Si ce comptage echoue, ou rend moins de requetes que celles lues (journal du pod tourne
#    entre les deux appels, horodatages illisibles), l'aveu part quand meme, « nombre inconnu ».
read_log() {
  case "$WEBSRC" in
    k3s)
      KC="kubectl"; command -v kubectl >/dev/null 2>&1 || KC="k3s kubectl"
      command -v "${KC%% *}" >/dev/null 2>&1 || return 1
      $KC -n "$WEB_NS" logs -l "$WEB_SEL" --since="${since}s" --tail="$MAX" --timestamps --prefix --max-log-requests=5 2>/dev/null
      ;;
    file) web_lire_fichier ;;
    *) return 1 ;;
  esac
}

# web_flux <chemin> — le contenu du journal, decompresse au fil de l'eau s'il est un `.gz` (gzip -dc ne garde en
# memoire qu'un tampon, pas le fichier : P10.33-e). Un `.gz` n'est jamais pris sans gzip (voir web_tourne_lu).
web_flux() { case "$1" in *.gz) gzip -dc "$1" 2>/dev/null ;; *) cat "$1" ;; esac; }
# web_empreinte <chemin> — empreinte de la PREMIERE ligne COMPLETE du fichier (identite du journal, P10.33-e). Une
# premiere ligne sans fin de ligne (ecriture en cours) ne l'identifie pas encore : empreinte du vide, comme un
# journal vide (W_EMP_VIDE), sans quoi son achevement se lirait comme une rotation.
web_empreinte() { case "$1" in *.gz) web_flux "$1" | head -n 1 ;; *) head -n 1 "$1" 2>/dev/null ;; esac \
  | { IFS= read -r _we_l && printf '%s\n' "$_we_l"; } | cksum | cut -d' ' -f1; }
W_EMP_VIDE=$(printf '' | cksum | cut -d' ' -f1)
web_taille() { case "$1" in *.gz) web_flux "$1" | wc -c ;; *) wc -c < "$1" ;; esac; }
# web_tourne_lu <chemin> — vrai si <chemin> est le journal lu au passage precedent (meme empreinte, assez long pour
# l'offset) ; pose alors w_src, w_emp_src, w_taille_src, w_debut.
web_tourne_lu() {
  [ -f "$1" ] && [ -r "$1" ] || return 1
  case "$1" in *.gz) command -v gzip >/dev/null 2>&1 || return 1 ;; esac
  [ "$(web_empreinte "$1")" = "$_p_emp" ] || return 1
  _wt=$(web_taille "$1") || return 1
  [ "$_p_off" -le "$_wt" ] || return 1
  w_src=$1; w_emp_src=$_p_emp; w_taille_src=$_wt; w_debut=$_p_off
}

# web_posterieur <chemin> — vrai si <chemin> a ete modifie APRES le debut de la lecture du passage precedent. Le repere
# WREP est cree AVANT toute lecture (`mktemp`) et n'est ecrit qu'avec l'etat de lecture, en le renommant (sa date est
# conservee) : un journal ainsi date porte des lignes que ce passage-la n'a pas pu lire. `find -newer` compare a la
# precision du systeme de fichiers et de `find` (la nanoseconde avec GNU find, la seconde ailleurs) : un journal ecrit
# PUIS tourne dans la meme seconde que le repere n'est pas reconnu posterieur. Un journal comprime prend la date de sa
# compression : posterieur, il peut ne faire que recomprimer des lignes deja lues.
web_posterieur() { [ -f "$1" ] && [ -f "$WREP" ] && [ -n "$(find "$1" -newer "$WREP" 2>/dev/null)" ]; }

# web_reprendre_posterieurs — le journal pointe au passage precedent n'est ni le courant ni un tourne reconnu (ou il
# etait VIDE, donc sans identite). Les journaux tournes POSTERIEURS a ce passage (web_posterieur) n'ont jamais ete lus :
# le plus ancien qui se lit (`.2`, ou `.2.gz` si `.2` est absent et `gzip` la ; puis `.1`) devient la source, depuis 0,
# et la suite (`.1`, puis le courant) se lit par les memes etats. Les posterieurs qui ne se liront pas (`.3`, `.3.gz`,
# `.2.gz` sans gzip, `.1.gz`, illisibles, ou plus anciens que la source) sont nommes dans w_perdus, et avoues.
web_reprendre_posterieurs() {
  _wr2=""; if [ -e "$WEB_LOG.2" ]; then _wr2=$WEB_LOG.2; elif command -v gzip >/dev/null 2>&1; then _wr2=$WEB_LOG.2.gz; fi
  _wrs=""
  for _wrf in "$WEB_LOG.3" "$WEB_LOG.3.gz" "$WEB_LOG.2.gz" "$WEB_LOG.2" "$WEB_LOG.1.gz" "$WEB_LOG.1"; do
    web_posterieur "$_wrf" || continue
    if [ -z "$_wrs" ] && { [ "$_wrf" = "$_wr2" ] || [ "$_wrf" = "$WEB_LOG.1" ]; } && [ -r "$_wrf" ]; then
      _wrs=$_wrf; continue
    fi
    [ -n "$_wrs" ] && [ "$_wrf" = "$WEB_LOG.1" ] && continue      # `.1` apres `.2` : lu par la suite (ou avoue par elle)
    w_perdus="$w_perdus $_wrf"
  done
  [ -n "$_wrs" ] || return 0
  w_src=$_wrs; w_debut=0
  w_emp_src=$(web_empreinte "$w_src") || return 1
  w_taille_src=$(web_taille "$w_src") || return 1
}

# web_lire_fichier — choisit le fichier et l'octet de depart, ecrit sur la sortie au plus MAX lignes a partir
# de lui. Pose w_src, w_debut, w_taille_src, w_emp_src, w_emp_cour, w_emp_suiv, w_perte_rotation, w_fini_*.
# P10.33-e — DEUX ROTATIONS ENTRE DEUX PASSAGES : le journal lu au passage precedent est devenu `.2` (`.1` est un
# journal posterieur). Il etait avoue perdu ; il est desormais cherche dans `.2`, puis dans `.2.gz` si `gzip` est la
# (`logrotate delaycompress` comprime le second), reconnu a la MEME empreinte que pour `.1`, et lu depuis l'offset.
# Un passage lit UNE source (comme pour `.1`) : arrive au bout d'un journal tourne, l'etat pointe le SUIVANT depuis
# 0 (`.2` -> `.1` -> courant, empreinte du suivant). Un journal tourne deja lu jusqu'au bout n'est pas relu : on
# passe au suivant dans le meme passage. Chaque ligne est donc lue une fois, dans la borne. Un etat d'offset 0 dont
# l'empreinte est celle de `.1` (journal pointe mais pas encore lu, tourne depuis) fait lire `.1` depuis 0, au lieu
# de sauter au courant.
# UN JOURNAL VIDE N'A PAS D'IDENTITE (son empreinte est W_EMP_VIDE, celle de tout journal vide) : pointe tel quel, il
# ne se reconnaitrait plus une fois rempli puis tourne, et ses lignes seraient sautees sans aveu. L'etat ne le pointe
# donc jamais quand un journal tourne vient d'etre fini : il pointe la FIN de ce tourne (empreinte et taille), que la
# rotation suivante deplace en `.2` sans le changer — `.2` fini, `.1` (l'ancien vide, rempli) est lu depuis 0 (voir
# web_offset_suivant). Seuls un premier passage, une premiere ligne en cours d'ecriture ou un `.2` fini sans `.1`
# pointent encore un journal vide : pour eux, comme pour un journal pointe introuvable dans `.1`, `.2` et `.2.gz`, les
# journaux tournes modifies depuis le passage precedent sont lus (web_reprendre_posterieurs), ceux qui ne se lisent
# pas sont avoues PERDUS, et sans repere de lecture la perte est avouee, nombre inconnu. Un journal pointe non vide
# introuvable est avoue perdu, comme avant — y compris a l'offset 0 (pointe apres avoir fini `.1` ou `.2`, puis tourne
# hors de portee). Et `.2` fini sans `.1` lisible (le journal d'entre les deux rotations a disparu) : le courant est
# lu, la perte de `.1` avouee (w_perte_intermediaire), au debut du passage comme a sa fin.
w_src=""; w_debut=0; w_taille_src=0; w_emp_src=""; w_emp_cour=""; w_emp_suiv=""; w_perte_rotation=""; w_par_offset=0
w_perte_intermediaire=""; w_fini_emp=""; w_fini_taille=0; w_perdus=""; w_vide_inconnu=""; w_repere=""
web_lire_fichier() {
  [ -r "$WEB_LOG" ] || return 1
  w_repere=$(mktemp "$STATE_DIR/.web.lecture.XXXXXX") || return 1   # date du debut de CETTE lecture (web_posterieur)
  w_taille_cour=$(wc -c < "$WEB_LOG") || return 1
  w_emp_cour=$(web_empreinte "$WEB_LOG") || return 1
  w_src=$WEB_LOG; w_emp_src=$w_emp_cour; w_taille_src=$w_taille_cour
  _p_emp=""; _p_off=""
  if [ -r "$OFFS" ]; then read -r _p_emp _p_off < "$OFFS" || true; fi
  case "$_p_off" in ''|*[!0-9]*) _p_emp="" ;; esac
  if [ -z "$_p_emp" ]; then
    # premier passage (ou etat illisible) : les MAX dernieres lignes, comme avant.
    _t=$(tail -n "$MAX" "$WEB_LOG" | wc -c) || return 1
    w_debut=$((w_taille_src - _t)); [ "$w_debut" -ge 0 ] || w_debut=0
  elif [ "$_p_emp" = "$w_emp_cour" ] && [ "$_p_off" -le "$w_taille_src" ]; then
    w_debut=$_p_off
  elif web_tourne_lu "$WEB_LOG.1"; then
    :
  elif web_tourne_lu "$WEB_LOG.2"; then
    :
  elif [ ! -e "$WEB_LOG.2" ] && web_tourne_lu "$WEB_LOG.2.gz"; then
    :
  else
    if [ "$_p_off" -eq 0 ] && [ "$_p_emp" = "$W_EMP_VIDE" ]; then
      # pointe VIDE : rempli puis tourne, il est posterieur (lu ou avoue ci-dessous) ; sinon le courant l'est.
      [ -f "$WREP" ] || [ ! -e "$WEB_LOG.1" ] || w_vide_inconnu=1
    else
      w_perte_rotation=$_p_off
    fi
    w_debut=0
    web_reprendre_posterieurs || return 1
  fi
  # Un journal tourne lu jusqu'au bout : le suivant, depuis 0 (`.2` -> `.1` -> courant).
  while [ "$w_src" != "$WEB_LOG" ] && [ "$w_debut" -ge "$w_taille_src" ]; do
    if [ "$w_emp_src" != "$W_EMP_VIDE" ]; then                 # le dernier tourne fini NON VIDE : identite de repli
      w_fini_emp=$w_emp_src; w_fini_taille=$w_taille_src         # (web_offset_suivant)
    fi
    if [ "$w_src" = "$WEB_LOG.1" ]; then
      w_src=$WEB_LOG; w_emp_src=$w_emp_cour; w_taille_src=$w_taille_cour
    elif [ ! -f "$WEB_LOG.1" ] || [ ! -r "$WEB_LOG.1" ]; then
      w_perte_intermediaire=1                                   # `.2` fini, `.1` absent ou illisible : perdu, avoue
      w_src=$WEB_LOG; w_emp_src=$w_emp_cour; w_taille_src=$w_taille_cour
    else
      w_src=$WEB_LOG.1; w_emp_src=$(web_empreinte "$w_src"); w_taille_src=$(wc -c < "$w_src") || return 1
    fi
    w_debut=0
  done
  w_emp_suiv=$w_emp_cour
  if [ "$w_src" = "$WEB_LOG.2" ] || [ "$w_src" = "$WEB_LOG.2.gz" ]; then
    if [ -f "$WEB_LOG.1" ] && [ -r "$WEB_LOG.1" ]; then w_emp_suiv=$(web_empreinte "$WEB_LOG.1"); fi
  fi
  [ -z "$_p_emp" ] || w_par_offset=1
  case "$w_src" in
    *.gz) web_flux "$w_src" | tail -c +"$((w_debut + 1))" | head -n "$MAX" ;;
    *) tail -c +"$((w_debut + 1))" "$w_src" 2>/dev/null | head -n "$MAX" ;;
  esac
}

# S36 — meme distinction, dite avec le mot de la famille : une lecture qui echoue n'est pas une
# source vide. Le routage etait deja le bon ; `plume_lecture_echouee` y ajoute la seule garantie qui
# manquait a la forme generique — JETER ce qui serait en attente, pour qu'aucune sortie ne puisse
# acquitter ce qu'elle n'a pas publie.
w_brut=$(mktemp)
trap 'rm -f "$w_brut" "$w_brut.c" "$w_brut.p" ${w_repere:+"$w_repere"}' EXIT
read_log > "$w_brut" || plume_lecture_echouee web source_illisible "source de log web illisible (PLUME_WEB_SRC=$WEBSRC) : ni fichier lisible, ni pod joignable"
# Une derniere ligne sans fin de ligne dans le journal COURANT est une ecriture en cours : ni lue, ni comptee dans
# l'offset. Dans un journal tourne, plus personne n'ecrit : elle est lue, sans quoi l'offset n'en sortirait jamais.
w_lignes=$(wc -l < "$w_brut")
if [ "$WEBSRC" = file ] && [ "$w_src" = "$WEB_LOG" ] && [ -s "$w_brut" ] && [ "$(tail -c 1 "$w_brut" | wc -l)" -eq 0 ]; then
  head -n "$w_lignes" "$w_brut" > "$w_brut.c"; mv -f "$w_brut.c" "$w_brut"
fi
# web_offset_suivant <lignes consommees> — l'etat de lecture a mettre en attente (mode file). Un journal tourne lu
# jusqu'au bout : le suivant depuis 0 — sauf si le suivant est VIDE (sans identite) : l'etat pointe alors la FIN du
# tourne (voir web_lire_fichier), et de meme quand le courant atteint apres un tourne fini est vide. Apres un `.2` fini
# sans `.1` lisible (perte avouee dans ce passage), le courant depuis 0, meme vide : la fin de `.2` ferait avouer
# la meme perte au passage suivant.
web_offset_suivant() {
  [ "$WEBSRC" = file ] || return 0
  _wo=$((w_debut + $(head -n "$1" "$w_brut" | wc -c)))
  if [ "$w_src" != "$WEB_LOG" ] && [ "$_wo" -ge "$w_taille_src" ]; then
    if [ "$w_emp_suiv" = "$W_EMP_VIDE" ] && [ -z "$w_perte_intermediaire" ]; then
      printf '%s %s' "$w_emp_src" "$w_taille_src"               # suivant vide : la fin du tourne, identite sure
    else
      printf '%s 0' "$w_emp_suiv"                              # journal tourne lu jusqu'au bout : le suivant, depuis 0
    fi
  elif [ "$w_emp_src" = "$W_EMP_VIDE" ] && [ -n "$w_fini_emp" ] && [ -z "$w_perte_intermediaire" ]; then
    printf '%s %s' "$w_fini_emp" "$w_fini_taille"              # courant vide apres un tourne fini : la fin du tourne
  else
    printf '%s %s' "$w_emp_src" "$_wo"
  fi
}
# web_avouer_rotation — UN aveu par passage (`missing-source`) pour tout ce qu'une rotation a fait perdre : le journal
# pointe introuvable, les journaux modifies depuis le passage precedent qui ne se lisent pas, le `.1` absent ou
# illisible entre `.2` et le courant. Cle propre au passage ET a son contenu : le central ecarte un aveu dont la cle
# (et l'heure) est deja vue, et une cle fixe faisait taire la seconde perte distincte d'une meme heure.
web_avouer_rotation() {
  _w_msg=""
  if [ -n "$w_perte_rotation" ]; then
    _w_lu="lu jusqu'a l'octet $w_perte_rotation"
    [ "$w_perte_rotation" -eq 0 ] && _w_lu="pointe mais pas encore lu, non vide"
    _w_msg=" Le journal lu au passage precedent ($_w_lu) est introuvable sous $WEB_LOG.1, $WEB_LOG.2 et $WEB_LOG.2.gz (ce dernier n'est lu que si gzip est present) — ce qui y a ete ecrit apres ce passage n'a pas ete lu et est PERDU, nombre inconnu (peut-etre nul)."
  elif [ -n "$w_vide_inconnu" ]; then
    _w_msg=" Le journal pointe au passage precedent etait vide, et aucun repere de lecture ($WREP) ne dit s'il a ete rempli puis tourne — ce qui y aurait ete ecrit n'a pas ete lu et est PERDU, nombre inconnu (peut-etre nul)."
  fi
  if [ -n "$w_perdus" ]; then
    _w_msg="$_w_msg Journal(aux) tourne(s) modifie(s) depuis le passage precedent et non lu(s) (hors de portee, compresse sans gzip, illisible) :$w_perdus — ce qui y a ete ecrit depuis est PERDU : perte certaine pour un journal non compresse (un journal compresse peut ne recomprimer que des lignes deja lues), nombre inconnu."
  fi
  if [ -n "$w_perte_intermediaire" ]; then
    _w_qte="nombre inconnu (peut-etre nul)"
    [ -s "$WEB_LOG.1" ] && _w_qte="perte certaine ($WEB_LOG.1 n'est pas vide), nombre inconnu"
    _w_msg="$_w_msg Deux rotations depuis le passage precedent : le journal lu ($WEB_LOG.2 ou $WEB_LOG.2.gz) l'est jusqu'au bout, mais le journal d'entre les deux, $WEB_LOG.1, est absent ou illisible — ce qui y a ete ecrit n'a pas ete lu et est PERDU, $_w_qte."
  fi
  [ -n "$_w_msg" ] || return 0
  plume_report_availability web unavailable missing-source \
    "ROTATION DU JOURNAL D'ACCES :$_w_msg Les journaux suivants sont lus depuis leur debut. Gardez le journal tourne non compresse un cycle (logrotate delaycompress)." \
    2 "web-rotation-introuvable-$now-$_w_msg" 2>/dev/null || true
}

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
#    Au-dela, une ligne est coupee. En mode file, elle est TOUJOURS relue au passage suivant (l'offset s'arrete
#    devant la premiere, P10.33-e). En k3s : d'une seconde POSTERIEURE au filigrane, elle est relue au passage
#    suivant ; de la MEME seconde que la derniere publiee (ou d'une seconde anterieure, pods entrelaces), elle est
#    PERDUE, comptee et avouee (`collection-capped`). Ni une ligne filtree ni une ligne coupee ne fait avancer le
#    filigrane apres le plafond. Un flot NON filtre (scan, attaque volumetrique) peut donc pousser des requetes
#    reelles au-dela du plafond : celles de sa derniere seconde publiee sont perdues et avouees en nombre ; le
#    reste est reporte, et sous un flot SOUTENU le report court derriere le journal (voir la borne suivante) ;
#  · la BORNE DE LECTURE PLUME_WEB_MAX : elle ne fait plus perdre en silence (P10.33-e, voir read_log). En mode
#    file, les lignes au-dela de la borne sont lues aux passages suivants (offset d'octets) ; en k3s, celles
#    qu'un flot plus long que la borne a fait sortir de la fenetre `--tail` sont comptees et avouees
#    (`collection-capped`, dans le MEME aveu que le plafond). Le battement le dit dans les deux cas.
web_battement() {
  _wb_msg="web santé : $1 ligne(s) lue(s), $2 gardée(s), $3 filtrée(s) par PLUME_WEB_SKIP_*, $4 déjà vue(s), $5 hors journal d'accès, $6 reportée(s) au passage suivant et $7 perdue(s) au-delà du plafond de 9000 par passage"
  [ -n "$w_note_borne" ] && _wb_msg="$_wb_msg ; $w_note_borne"
  [ -n "$w_note_debut" ] && _wb_msg="$_wb_msg ; $w_note_debut"
  spool_write "web-health-$now.json" "$(emit_event "$(heartbeat web "$_wb_msg" '{"type":"collector-health","collector":"web"}' 0 "$now")")" nl
}
if [ ! -s "$w_brut" ]; then
  if [ "$WEBSRC" = file ]; then
    web_avouer_rotation
    state_stage "$OFFS" "$(web_offset_suivant 0)"; state_stage_file "$w_repere" "$WREP"
  fi
  plume_exit_nodata
fi
umask 027
tmp=$(mktemp "$SPOOL/.web.XXXXXX")
# P10.33-e — EN MODE file, L'OFFSET TIENT LIEU DE FILIGRANE. Ce qui est lu a partir de l'offset n'a jamais ete lu :
# le filtrer encore par seconde (`et <= last`) perdait, sans aveu, les lignes d'une seconde coupee en deux par la
# borne PLUME_WEB_MAX (la fin de la seconde dite « deja vue » au passage suivant), et celles d'une requete longue
# que Traefik ecrit a sa fin avec un StartUTC anterieur au filigrane. Le filigrane horaire ne s'applique plus
# qu'au PREMIER passage (aucun offset connu : `tail -n MAX`, qui peut relire ce qu'une version sans offset a deja
# publie) et en k3s. Et une ligne coupee par le plafond est toujours relue en mode file (l'offset s'arrete devant
# la premiere) : elle est dite reportee, jamais perdue. LE PRIX : apres une rotation perdue, le journal relu depuis
# 0 sans filigrane peut republier des requetes deja publiees ; leur cle `web-<StartUTC>` les fait ecarter par le
# magasin (`INSERT OR IGNORE`). Un doublon ecarte vaut mieux qu'une requete perdue.
w_par_wm=1; w_relu=0
if [ "$WEBSRC" = file ]; then w_relu=1; [ "$w_par_offset" -eq 1 ] && w_par_wm=0; fi
w_k3s=0; [ "$WEBSRC" = k3s ] && w_k3s=1
newwm=$(TZ=UTC awk -v last="$last" -v parwm="$w_par_wm" -v relu="$w_relu" -v k3s="$w_k3s" -v podsout="$w_brut.p" -v host="$host" -v now="$now" -v out="$tmp" -v skiphost="$SKIP_HOST" -v skippath="$SKIP_PATH" -v skiprouter="$SKIP_ROUTER" "$_PLUME_AWK_ECHAPPEMENT_JSON"'
# jesc() : l’échappement JSON de collectors/lib.sh (_PLUME_AWK_ECHAPPEMENT_JSON, P10.23-e), placé en tête de ce programme.
function sval(name,   re,v){ re="\"" name "\":\"[^\"]*\""; if(match($0,re)){ v=substr($0,RSTART,RLENGTH); sub(/^"[^"]*":"/,"",v); sub(/"$/,"",v); return v } return "" }
function nval(name,   re,v){ re="\"" name "\":-?[0-9]+"; if(match($0,re)){ v=substr($0,RSTART,RLENGTH); sub(/^"[^"]*":/,"",v); return v } return "" }
# rt() : horodatage du runtime que `kubectl logs --timestamps` met en tete de ligne, `Z` retire : RFC3339Nano retire
# les zeros de queue de la fraction, et `10.5Z` se classerait APRES `10.50001Z` (Z apres 0) ; sans lui, l ordre des
# chaines est celui du temps. Vide en mode file.
function rt(   t){ t=$1; if (t !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T.*Z$/) return ""; sub(/Z$/,"",t); return t }
BEGIN{ n=0; buf=""; maxts=last+0; nfil=0; nvu=0; nautre=0; nreport=0; nperdu=0; coupe=0; nneuf=0; borne="" }
{
  # P10.33-e — `--prefix` (k3s) : `[pod/<pod>/<conteneur>] ` en tete de ligne, avant l horodatage ; retire, il
  # nomme le pod dont la ligne vient (les requetes neuves lues sont comptees PAR POD, pour le comptage des sautees).
  pod="-"; if (k3s && $1 ~ /^\[pod\/.*\]$/) { split(substr($1,2,length($1)-2),PA,"/"); pod=PA[2]; $0=substr($0,length($1)+2) }
  VUPOD[pod]=1
  r=rt(); if (r > borne) borne=r
  if ($0 !~ /"DownstreamStatus":/) { nautre++; next }            # garde uniquement les lignes access-log
  su=sval("StartUTC"); if(su=="") { nautre++; next }
  d=substr(su,1,19); gsub(/[-T:]/," ",d); et=mktime(d); if(et<0) { nautre++; next }
  if (parwm && et <= last) { nvu++; next }
  nneuf++; NPOD[pod]++
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
  # P10.33-e — l offset du mode file s arrete devant la PREMIERE ligne coupee : tout ce qui la suit est relu.
  if (n>=9000) { if (!coupe) coupe=NR; PLAF[et]++; next }
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
  # En mode file (relu), l offset s arrete devant la premiere ligne coupee : toutes sont relues, aucune n est perdue.
  for (e in PLAF) { if (relu || e+0 > maxts) nreport += PLAF[e]; else nperdu += PLAF[e] }
  if (k3s) { for (p in VUPOD) print p, NPOD[p]+0 > podsout; close(podsout) }
  print maxts, NR, n, nfil, nvu, nautre, nreport, nperdu, (coupe ? coupe-1 : NR), nneuf, (borne=="" ? "-" : borne) }' "$w_brut")
# Le filigrane, puis les comptes du passage (lignes lues, gardees, filtrees, deja vues, hors journal, coupees par le
# plafond et reportees, coupees et perdues).
w_lus=0; w_gardes=0; w_filtres=0; w_vus=0; w_autres=0; w_report=0; w_perdu=0; w_cons=0; w_neufs=0; w_borne=-
read -r newwm w_lus w_gardes w_filtres w_vus w_autres w_report w_perdu w_cons w_neufs w_borne <<EOF
$newwm
EOF
# P10.33-e — la borne de lecture atteinte : en mode file, le reste est lu au passage suivant ; en k3s, les lignes
# sautees sont COMPTEES par un second `kubectl logs` de la meme fenetre, a --tail explicite (voir read_log).
w_saute=0; w_saute_dit=""; w_saute_note=""; w_note_borne=""; w_note_debut=""
if [ "$WEBSRC" = file ] && [ "$w_par_offset" -eq 0 ] && [ "$w_debut" -gt 0 ]; then
  w_note_debut="premier passage (aucun état de lecture, ou illisible) : les $w_debut premier(s) octet(s) du journal, antérieurs aux $MAX dernières lignes, ne sont pas lus"
fi
if [ "${w_lus:-0}" -ge "$MAX" ] 2>/dev/null; then
  if [ "$WEBSRC" = file ]; then
    _wr=$(( w_taille_src - w_debut - $(head -n "${w_cons:-0}" "$w_brut" | wc -c) )); [ "$_wr" -ge 0 ] || _wr=0
    _ws=" — rien n'est sauté"; [ -z "$w_note_debut" ] || _ws=""   # premier passage : le debut du journal l'est, dit a part
    if [ "$_wr" -eq 0 ] && [ "$w_src" = "$WEB_LOG" ]; then
      w_note_borne="borne de lecture PLUME_WEB_MAX=$MAX atteinte pile : le journal est lu jusqu'à sa dernière ligne complète$_ws"
    elif [ "$_wr" -eq 0 ]; then
      w_note_borne="borne de lecture PLUME_WEB_MAX=$MAX atteinte pile : le journal tourné ${w_src} est lu jusqu'au bout, le suivant est lu au passage suivant$_ws"
    else
      w_note_borne="borne de lecture PLUME_WEB_MAX=$MAX atteinte : au moins $_wr octet(s) du journal ${w_src} restent à lire, repris au passage suivant$_ws"
    fi
  else
    # P10.33-e — LE COMPTE PAR POD. `--tail` borne CHAQUE pod : un compte global ne savait pas quel pod depassait,
    # et disait « au moins N » pour tous des que le total atteignait la borne. Le comptage nomme les pods
    # (`--prefix`), ne porte PAS de `--since` et rend jusqu'a 10 x PLUME_WEB_MAX lignes par pod : un pod dont la plus
    # ANCIENNE ligne rendue precede la fenetre de lecture (`_wlo`, une seconde avant elle) a ete vu en entier depuis
    # le debut de la fenetre — son nombre est EXACT ; sinon (flot plus long que la borne, journal du pod tourne ou
    # conteneur redemarre) il est un MINIMUM, « au moins N ». Un pod dont le comptage voit moins de requetes que la
    # lecture n'en a lu, ou qui manque au comptage, est « nombre inconnu ». Le total est exact si tous le sont, un
    # minimum si l'un l'est, inconnu si l'un l'est ; chaque pod est dit par son NOM (jamais une adresse).
    _wlo=$(( now - since - 1 ))
    _wcap=$(( MAX * 10 ))
    [ -f "$w_brut.p" ] || : > "$w_brut.p"
    w_comptage=$( { $KC -n "$WEB_NS" logs -l "$WEB_SEL" --tail="$_wcap" --timestamps --prefix --max-log-requests=5 2>/dev/null \
                 || printf 'plume-comptage-en-echec\n'; } | TZ=UTC awk -v last="$last" -v borne="$w_borne" -v lo="$_wlo" -v lusf="$w_brut.p" '
      function rt(   t){ t=$1; if (t !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T.*Z$/) return ""; sub(/Z$/,"",t); return t }
      function ep(t,   d){ d=substr(t,1,19); gsub(/[-T:]/," ",d); return mktime(d) }
      function nommer(p){ if (!(p in K)) { K[p]=1; NOMS[++np]=p } }
      BEGIN { np=0; while ((getline l < lusf) > 0) { split(l, F, " "); nommer(F[1]); L[F[1]]=F[2]+0 } close(lusf) }
      $0 == "plume-comptage-en-echec" { ko=1; next }
      { pod="-"; if ($1 ~ /^\[pod\/.*\]$/) { split(substr($1,2,length($1)-2),PA,"/"); pod=PA[2]; $0=substr($0,length($1)+2) }
        nommer(pod); r=rt()
        if (!(pod in PREM)) PREM[pod]=r                    # kubectl rend chaque pod dans l ordre : sa plus ancienne ligne
        if (r=="" || r > borne || ep(r) < lo+0) next
        if (!match($0,/"StartUTC":"[^"]*"/)) next; su=substr($0,RSTART+12,19); if ($0 !~ /"DownstreamStatus":/) next
        gsub(/[-T:]/," ",su); et=mktime(su); if (et > last+0) C[pod]++ }
      END { if (ko || borne=="-") { print "inconnu"; print ""; exit }
        for (i=2;i<=np;i++) { v=NOMS[i]; j=i-1; while (j>0 && NOMS[j] > v) { NOMS[j+1]=NOMS[j]; j-- } NOMS[j+1]=v }
        tot=0; inc=0; mini=0; det=""
        for (i=1;i<=np;i++) { p=NOMS[i]; c=C[p]+0; l=L[p]+0
          if (!(p in PREM) || c < l) { inc=1; d="nombre inconnu" }
          else if (PREM[p] != "" && ep(PREM[p]) < lo+0) { d=c-l; tot+=c-l }
          else { mini=1; d="au moins " (c-l); tot+=c-l }
          det=det (det=="" ? "" : ", ") p " : " d }
        if (inc) print "inconnu"; else if (mini) print "au-moins", tot; else print "exact", tot
        print det }')
    w_pods_dit=$(printf '%s\n' "$w_comptage" | sed -n 2p); w_comptage=$(printf '%s\n' "$w_comptage" | sed -n 1p)
    w_pods_note=""; [ -z "$w_pods_dit" ] || w_pods_note=" — par pod : $w_pods_dit"
    w_saute=""; w_saute_dit="nombre inconnu de"
    case "$w_comptage" in
      "exact "*) w_saute=${w_comptage#exact }; w_saute_dit=$w_saute ;;
      "au-moins "*) w_saute_dit="au moins ${w_comptage#au-moins }"
                    w_saute_note=" (comptage borné à $_wcap lignes par pod, 10 x PLUME_WEB_MAX : la plus ancienne ligne rendue d'un pod au moins ne précède pas la fenêtre)" ;;
    esac
    w_saute_note="$w_saute_note$w_pods_note"
    w_note_borne="borne de lecture PLUME_WEB_MAX=$MAX atteinte : $w_saute_dit ligne(s) plus ancienne(s) de la fenêtre jamais lue(s), comptée(s) et avouée(s)$w_saute_note"
  fi
fi
# Une requete neuve vue (publiee ou filtree ; une ligne n'est coupee par le plafond qu'apres 9000 publiees) : la
# source vit, le battement part. Sinon, rien.
if [ $(( ${w_gardes:-0} + ${w_filtres:-0} )) -gt 0 ]; then
  web_battement "${w_lus:-0}" "${w_gardes:-0}" "${w_filtres:-0}" "${w_vus:-0}" "${w_autres:-0}" "${w_report:-0}" "${w_perdu:-0}"
fi
# Un SEUL aveu pour les deux bornes : `plume_collecte_tronquee` cle par (source, borne), et les deux pertes sont
# des `plafond-de-lignes` — deux aveux du meme passage prendraient le meme fichier, le second effacerait le premier.
case "$w_saute" in ''|*[!0-9]*) _wt="" ;; *) _wt=$(( ${w_perdu:-0} + w_saute )) ;; esac
if [ "$_wt" != 0 ]; then
  _wd="plafond de 9000 requetes publiees par passage : ${w_perdu:-0} ligne(s) coupee(s) de la meme seconde que la derniere publiee (ou d'une seconde anterieure), que le filigrane a passees, ne seront pas relues ; les lignes coupees d'une seconde posterieure sont relues au passage suivant."
  [ -n "$w_note_borne" ] && [ "$WEBSRC" != file ] && _wd="$_wd Borne de lecture PLUME_WEB_MAX=$MAX (kubectl logs --tail) : $w_saute_dit ligne(s) plus ancienne(s) de la fenetre jamais lue(s)$w_saute_note."
  plume_collecte_tronquee web plafond-de-lignes "$_wt" "$_wd"
fi

# S30 — l'ordre etait DEJA le bon ; le filigrane est MIS EN ATTENTE et ecrit par la publication
# elle-meme. Quand il n'y a aucune ligne a publier, c'est l'enveloppe de config de fin — toujours
# emise — qui l'ecrit : un capteur n'a jamais le geste d'acquitter a sa disposition.
state_stage "$WM" "${newwm:-$last}"
if [ "$WEBSRC" = file ]; then
  # `.2` lu jusqu'au bout EN FIN de passage, `.1` absent ou illisible : sa perte est avouee dans CE passage — au
  # suivant, l'etat pointe le courant depuis 0 et ne la verrait plus (logrotate `compress` sans `delaycompress`).
  if { [ "$w_src" = "$WEB_LOG.2" ] || [ "$w_src" = "$WEB_LOG.2.gz" ]; } && { [ ! -f "$WEB_LOG.1" ] || [ ! -r "$WEB_LOG.1" ]; } \
     && [ $((w_debut + $(head -n "${w_cons:-0}" "$w_brut" | wc -c))) -ge "$w_taille_src" ]; then
    w_perte_intermediaire=1
  fi
  web_avouer_rotation
  state_stage "$OFFS" "$(web_offset_suivant "${w_cons:-0}")"; state_stage_file "$w_repere" "$WREP"
fi
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
