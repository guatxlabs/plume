#!/bin/sh
# Capteur Plume GÉNÉRIQUE — "scripted inputs" : sources définies par l'OPÉRATEUR, SANS CODE.
# Lit /etc/plume/inputs.d/*.input (KEY=value), exécute CMD, expédie chaque ligne stdout (filtrée +
# bornée + dédupée) en event source=<SOURCE>. Les parsers du registre s'appliquent ensuite -> input
# custom + parser custom = pipeline 100% extensible (l'équivalent "inputs" du registre de parsers).
#
# Format d'un fichier .input (lignes KEY=value) :
#   SOURCE=nom-source         (obligatoire ; le source= cherchable)
#   CMD=commande shell        (obligatoire ; sa sortie stdout = les events, 1 ligne = 1 event)
#   SEVERITY=0..4             (défaut 1)
#   CATEGORY=texte            (défaut custom)
#   FILTER=regex              (optionnel ; ne garde que les lignes qui matchent)
#   MAX=nombre                (défaut 100 ; plafond de lignes/passage, anti-flood — le surplus est
#                              PERDU, et le capteur le DIT avec son compte : voir plus bas)
#   MAXLEN=nombre             (défaut 1000 ; longueur max d'une ligne — monter pour du JSON verbeux
#                              type audit Vault, sinon les champs en fin de ligne sont tronqués)
#   TIMEOUT=secondes          (défaut PLUME_CUSTOM_TIMEOUT, sinon 45 ; 0 = AUCUNE borne, à vos
#                              risques — voir « DEUX BORNES » ci-dessous)
# Astuce : faire émettre à CMD uniquement le NOUVEAU (ex `journalctl -u x --since -1min`) ; sinon la
# déduplication horaire (source+ligne) évite les doublons d'un `tail` répété.
#
# ==================================================================================================
# DEUX BORNES, ET AUCUNE DES DEUX NE COUPE EN SILENCE (P4.6-a, P4.6-b)
# --------------------------------------------------------------------------------------------------
# CE QUI ÉTAIT MESURÉ SUR L'ARBRE, ET REJOUABLE (2026-08-27, ce fichier, ce harnais) :
#   (a) SANS BORNE DE DURÉE. `CMD` était exécuté par `sh -c` et le capteur ATTENDAIT sa sortie, sans
#       minuterie ; `systemd/plume-custom.service` est un `Type=oneshot` qui ne pose pas de délai
#       propre. Mesuré avec `CMD=sh -c 'echo debut; sleep 300'` : le capteur ne rend PAS la main
#       (tué au bout de 8 s par le harnais), et le spool reste VIDE — la ligne « debut », pourtant
#       lue, n'est jamais publiée. Pendant ce temps le timer réarme à la minute. Un capteur qui se
#       tait parce qu'il attend est un capteur aveugle.
#   (b) PLAFOND MUET. Avec `CMD=seq 1 10` et `MAX=3` : 3 événements publiés, 7 lignes jetées, AUCUN
#       aveu, code de sortie 0. Rien ne distinguait cette source tronquée d'une source qui n'aurait
#       produit que 3 lignes.
#   (c) UNE BORNE MAL ÉCRITE PERDAIT TOUT. `MAX=deux` : `head -n deux` échouait, et comme seul le
#       DERNIER maillon d'un tube décide du code de retour, le capteur sortait en 0 avec un spool
#       VIDE — l'entrée entière disparaissait, la seule trace partant sur la sortie d'erreur, qui va
#       au journal de l'hôte et non au SOC. Mesuré le même jour, même harnais.
# UNE DOCUMENTATION N'EST PAS UNE BORNE : les deux faits étaient écrits dans le README, et la
# déclaration mal choisie suivante y retombait quand même. Ce qui suit sont des bornes ARMÉES.
#
# CE QUI EST ARMÉ MAINTENANT :
#   * DURÉE — `timeout` borne CHAQUE commande. Au dépassement (code 124), le capteur publie ce que la
#     commande avait déjà émis et AVOUE la coupure (`plume_collecte_tronquee`, borne-de-duree).
#     `TIMEOUT=0` retire la borne : c'est un choix EXPLICITE de l'exploitant, plus un défaut subi.
#   * VOLUME — le plafond COMPTE ce qu'il écarte, et l'aveu porte le nombre.
#   * L'ABSENCE DE L'OUTIL SE DIT AUSSI. Sur un hôte sans `timeout` (busybox minimal), la borne
#     demandée n'est PAS armée : le capteur l'avoue (`missing-dependency`) au lieu de laisser croire
#     à une protection qu'il n'a pas. Une borne qu'on croit posée est pire que pas de borne.
#
# CE QUE CE CHANGEMENT COÛTE, DIT PLUTÔT QUE TU. Le plafond n'est plus un `head` : `head` FERMAIT le
# tube et tuait la commande dès la MAX-ième ligne, ce qui rendait la main tout de suite mais rendait
# aussi le surplus inconnaissable. Compter exige de LIRE le surplus. La lecture du surplus est donc
# désormais bornée par la DURÉE (et par `CPUQuota=40%` / `MemoryMax=192M` de l'unit), non plus par le
# plafond : une commande qui déverse sans fin occupe le capteur jusqu'à `TIMEOUT` au lieu de quelques
# millisecondes. C'est l'échange assumé — du temps de capteur borné contre une perte qui cesse d'être
# invisible. Le surplus n'est jamais MÉMORISÉ (awk n'en garde que le compte) : la RAM ne suit pas le
# débit.
#
# ORDRE DE GRANDEUR MESURÉ (2026-08-27, ce poste, une entrée `CMD=yes`, `MAX=3`) :
#   AVANT — 42 ms, 0 aveu. Le nombre de lignes perdues n'est pas seulement inconnu de l'exploitant :
#           il est inconnaissable, parce que personne ne les a lues.
#   APRÈS, `TIMEOUT=3` — 3 143 ms, les 3 mêmes événements publiés, DEUX aveux (plafond ET durée), et
#           le plafond nomme sa perte : 32 767 998 lignes écartées.
#   CRÊTE RSS du capteur et de ses enfants sous ce déluge : 25 Mo, soit le huitième du `MemoryMax`
#           de l'unit. La mémoire ne suit PAS le débit — c'est ce que la mesure devait établir, parce
#           que « compter » aurait pu vouloir dire « garder ».
# ==================================================================================================
#
# OPT-IN, ROOT (comme tout collecteur). /etc/plume/inputs.d doit être root-only (l'opérateur a déjà root).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
DIR="${PLUME_INPUTS_DIR:-/etc/plume/inputs.d}"
[ -d "$DIR" ] || plume_unavailable custom missing-config "$DIR absent : aucune entree scriptee declaree (voir README, scripted input)"
plume_init
esc() { json_escape "$1"; }

# Borne de durée par DÉFAUT. 45 s tient sous la cadence de l'unit (`OnUnitActiveSec=60s`) : au-delà,
# un passage chevaucherait le suivant, ce qui est déjà une panne d'ordonnancement.
TIMEOUT_DEFAUT="${PLUME_CUSTOM_TIMEOUT:-45}"

# borne_entiere <clé> <valeur> <défaut> — rend <valeur> si c'est un entier, sinon le <défaut> ET
# AVOUE le repli. UNE BORNE MAL ÉCRITE ÉTAIT UNE PERTE TOTALE ET MUETTE : `head -n "$MAX"` avec un
# `MAX` non numérique échouait, et comme seul le DERNIER maillon d'un tube décide du code de retour,
# l'entrée entière disparaissait sans un mot. Un réglage qu'on ne sait pas lire ne se devine pas.
borne_entiere() {
  case "$2" in
    ''|*[!0-9]*)
      plume_report_availability "$SOURCE" unavailable missing-config \
        "$1=\"$2\" n'est pas un entier dans $f — repli sur $3. La borne demandee n'est PAS celle qui s'applique." \
        2 2>/dev/null || true
      printf '%s' "$3" ;;
    *) printf '%s' "$2" ;;
  esac
}

raw=$(mktemp)
for f in "$DIR"/*.input; do
  [ -r "$f" ] || continue
  SOURCE=""; CMD=""; SEVERITY=1; CATEGORY=custom; FILTER=""; MAX=100; MAXLEN=1000
  TIMEOUT="$TIMEOUT_DEFAUT"
  # `|| [ -n "$k$v" ]` — LA DERNIERE LIGNE SANS SAUT DE LIGNE FINAL EST LUE (meme famille que
  # `collectors/respond.sh`, MESUREE ICI le 2026-08-27 sur ce capteur tel qu il est livre) : une
  # declaration dont le contenu est `SOURCE=t\nCMD=seq 1 3` SANS `\n` terminal perdait sa DERNIERE
  # ligne. `CMD` restait vide, le `continue` ci-dessous ecartait l entree ENTIERE, et le capteur
  # sortait en 0 avec un spool VIDE : une source declaree par l exploitant ne collectait rien et ne
  # le disait pas. Temoin AVEC le saut de ligne : 3 evenements publies. C est la perte silencieuse
  # que tout ce fichier poursuit, a l entree du fichier de declaration.
  k=""; v=""
  while IFS='=' read -r k v || [ -n "${k:-}${v:-}" ]; do
    case "$k" in
      SOURCE) SOURCE=$v ;; CMD) CMD=$v ;; SEVERITY) SEVERITY=$v ;;
      CATEGORY) CATEGORY=$v ;; FILTER) FILTER=$v ;; MAX) MAX=$v ;; MAXLEN) MAXLEN=$v ;;
      TIMEOUT) TIMEOUT=$v ;;
    esac
  done < "$f"
  [ -n "$SOURCE" ] && [ -n "$CMD" ] || continue
  MAX=$(borne_entiere MAX "$MAX" 100)
  MAXLEN=$(borne_entiere MAXLEN "$MAXLEN" 1000)
  TIMEOUT=$(borne_entiere TIMEOUT "$TIMEOUT" "$TIMEOUT_DEFAUT")
  sj=$(esc "$SOURCE"); cj=$(esc "$CATEGORY")
  # BORNE DE DURÉE — même forme que `collectors/yara.sh`, qui la tenait déjà pour son scan : on ne
  # l'invente pas ici, on la met à l'endroit qui en manquait.
  TO=""
  if [ "$TIMEOUT" != 0 ]; then
    if command -v timeout >/dev/null 2>&1; then
      TO="timeout $TIMEOUT"
    else
      plume_report_availability "$SOURCE" unavailable missing-dependency \
        "borne de duree demandee (TIMEOUT=$TIMEOUT s) mais l'utilitaire \`timeout\` est ABSENT de cet hote : la commande de $f tourne SANS borne de DUREE. Le plafond de lignes reste structurel (le capteur cesse de lire des la MAX+1-eme ligne et la commande recoit SIGPIPE), mais le NOMBRE de lignes ecartees ne peut pas etre connu dans ce mode." \
        2 2>/dev/null || true
    fi
  fi
  # =================================================================================================
  # QUI BORNE L EXECUTION, ET DONC QUI PEUT COMPTER (regression MESUREE le 2026-08-27, corrigee ici)
  # -------------------------------------------------------------------------------------------------
  # CE QUE LE PREMIER JET DE `P4.6-a` AVAIT CASSE. `head -n "$MAX"` FERMAIT le tube a la MAX-ieme
  # ligne : la commande recevait SIGPIPE et mourait, si bien que le PLAFOND bornait aussi la DUREE.
  # Le remplacer par un `awk` qui COMPTE le surplus a supprime cette borne-la. MESURE, meme lib, meme
  # bac, PATH fabrique SANS `timeout`, entree `SOURCE=t / CMD=yes / MAX=3` :
  #     AVANT (HEAD, `head -n MAX`)  -> rc=0 en 37 ms, 3 evenements publies.
  #     APRES (premier jet, `awk`)   -> le capteur NE REND JAMAIS LA MAIN (tue a 8 s, rc=124), spool
  #                                     ne portant QUE l aveu `missing-dependency`, ZERO evenement.
  # Sur cette population, le correctif produisait exactement ce que la cle condamne — « un capteur qui
  # se tait parce qu il attend est un capteur aveugle » — en PIRE qu avant. Et l unit n a pas de
  # garde-fou : `grep -rn TimeoutStartSec systemd/` rend 0.
  # CE QU ON FAIT, ET C EST UN CHOIX ENTRE DEUX GRANDEURS, PAS UNE ASTUCE :
  #   * BORNE DE DUREE ARMEE  -> on peut lire le surplus sans risque, donc on le COMPTE : l aveu porte
  #     le NOMBRE EXACT de lignes ecartees.
  #   * BORNE DE DUREE NON ARMEE (`timeout` absent, ou `TIMEOUT=0` voulu par l exploitant) -> plus rien
  #     ne borne la lecture, donc on ne lit PAS le surplus : `awk` s arrete a la MAX+1-eme ligne, exactement
  #     comme `head` le faisait, et la commande recoit SIGPIPE. LA MAX+1-eme LIGNE EST LUE, ET C EST
  #     ELLE QUI PORTE LE FAIT : sa seule existence prouve la troncature sans qu on ait a supposer
  #     quoi que ce soit d une entree qui aurait produit exactement MAX lignes. Le NOMBRE, lui, reste
  #     inconnu — et l aveu le dit (« nombre inconnu »), au lieu d ecrire un zero rassurant.
  # AUCUNE CONSTANTE N EST INVENTEE : ni plafond de surplus, ni delai de repli. La lecture s arrete a
  # MAX+1, qui est le plus petit nombre de lignes qui permette de distinguer « tronque » de « pile MAX ».
  # =================================================================================================
  COMPTE_SURPLUS=0
  [ -n "$TO" ] && COMPTE_SURPLUS=1
  rcf=$(mktemp); dropf=$(mktemp)
  # LE CODE DE RETOUR DE LA COMMANDE NE SURVIT PAS AU TUBE (c'est le dernier maillon qui décide) : il
  # est écrit dans un fichier À L'ENDROIT EXACT où il est encore lisible. `|| _rc=$?` le TESTE, sans
  # quoi `set -e` tuerait le sous-shell avant l'écriture et la coupure redeviendrait indiscernable.
  # awk remplace `head` : il IMPRIME les MAX premières lignes (octet pour octet ce que `head -n MAX`
  # rendait) et COMPTE le reste sans le garder.
  # shellcheck disable=SC2086  ($TO = 0 ou 2 tokens, expansion voulue)
  { _rc=0; $TO sh -c "$CMD" 2>/dev/null || _rc=$?; printf '%s' "$_rc" > "$rcf"; } \
    | { if [ -n "$FILTER" ]; then grep -iE "$FILTER" || true; else cat; fi; } \
    | awk -v max="$MAX" -v df="$dropf" -v compte="$COMPTE_SURPLUS" '
         { n++
           if (n <= max) { print; next }
           if (!compte) { printf("?") > df; exit }   # MAX+1-eme ligne : le FAIT est etabli, on cesse de lire
         }
         END { if (compte && n > max) printf("%d", n - max) > df }' \
    | while IFS= read -r line; do
    [ -n "$line" ] || continue
    em=$(printf '%s' "$line" | cut -c1-"${MAXLEN:-1000}" | tr -d '\000-\037'); em=$(esc "$em")
    dd=$(printf '%s' "$SOURCE$line" | cksum | cut -d' ' -f1)   # dédup source+ligne dans l'heure
    printf '{"ts":%s,"source":"%s","category":"%s","severity":%s,"message":"%s","dedup":"custom-%s-%s"}\n' \
      "$ts" "$sj" "$cj" "${SEVERITY:-1}" "$em" "$dd" "$((ts / 3600))"
  done >> "$raw"
  cmd_rc=$(cat "$rcf" 2>/dev/null || printf '')
  ecartees=$(cat "$dropf" 2>/dev/null || printf '')
  rm -f "$rcf" "$dropf"
  # LES DEUX AVEUX SONT DISTINCTS ET CUMULABLES : une commande peut dépasser le plafond ET la durée,
  # et les deux faits n'appellent pas le même geste d'exploitant (relever MAX / resserrer FILTER
  # d'un côté, borner ou accélérer la commande de l'autre).
  case "${ecartees:-}" in
    ''|0) : ;;
    *) plume_collecte_tronquee "$SOURCE" plafond-de-lignes "$ecartees" \
         "plafond MAX=$MAX atteint pour $f. Relevez MAX, resserrez FILTER, ou faites emettre moins a CMD." ;;
  esac
  # UN AVEU NE S ECRIT QUE SUR CE QUI A ETE MESURE (corrige le 2026-08-27).
  # CE QUI ETAIT FAUX : le test portait sur le SEUL code de retour, sans regarder si la borne avait
  # ete ARMEE. MESURE sur le capteur livre, entree `SOURCE=cap124 / CMD=sh -c "echo une-ligne; exit
  # 124" / TIMEOUT=0` : aucune borne posee, RIEN de tronque, et pourtant l aveu partait — « COLLECTE
  # TRONQUEE (borne-de-duree) : nombre inconnu ecartee(s) … coupee a TIMEOUT=0s (code 124) », une
  # phrase qui se contredit elle-meme. Il levait l alerte livree `de-collector-unavailable` et
  # faisait basculer la pastille d une source SAINE. 124 et 137 sont des codes de sortie ordinaires
  # pour une commande d exploitant.
  # CE QUI EST AFFIRME MAINTENANT, ET RIEN DE PLUS : la borne etait armee (`$TO` non vide) ET le code
  # est 124, qui est le code que `timeout` reserve au depassement. C est le seul cas ou l attribution
  # est CERTAINE.
  # CE QUI N EST PLUS AFFIRME, ET POURQUOI C EST DIT : 137 (SIGKILL) n est plus impute a cette borne.
  # `timeout` est invoque SANS `-k`, il n envoie donc jamais SIGKILL ; un 137 vient d ailleurs — le
  # `MemoryMax` de l unit, un kill exterieur, ou la commande elle-meme — et ce capteur ne sait pas
  # lequel. Nommer une cause qu on n a pas mesuree etait precisement le defaut corrige ici. La perte
  # eventuelle n est pas muette pour autant : si elle a franchi le plafond, l aveu de VOLUME la dit.
  if [ -n "$TO" ] && [ "${cmd_rc:-0}" = 124 ]; then
    plume_collecte_tronquee "$SOURCE" borne-de-duree "" \
      "CMD de $f coupee a TIMEOUT=${TIMEOUT}s (code 124) : ce qu'elle avait deja emis est publie, la suite est perdue. Une commande qui SUIT un flux (tail -F, journalctl -f) ne se termine jamais : faites-lui emettre le nouveau, puis sortir."
  fi
done
if [ ! -s "$raw" ]; then rm -f "$raw"; plume_exit_nodata; fi
events=$(paste -sd, "$raw"); rm -f "$raw"
spool_write "custom-$ts.json" "$(emit_event "$events")"
