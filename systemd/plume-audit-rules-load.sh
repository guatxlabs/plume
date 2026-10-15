#!/bin/sh
# =================================================================================================
# Plume — chargement VÉRIFIÉ des règles auditd. Un chargement PARTIEL est un ÉCHEC, et il est NOMMÉ.
# C'est le SEUL chargeur : bootstrap.sh (central) l'appelle, bootstrap-agent.sh le pose et en affiche
# le geste. Aucun installeur ne lance `augenrules --load` lui-même.
# -------------------------------------------------------------------------------------------------
# LE DÉFAUT D'ORIGINE (mesuré le 2026-08-01, VM Ubuntu 24.04 Server fraîche, amd64) :
# `augenrules --load` S'ARRÊTE À LA PREMIÈRE RÈGLE EN ÉCHEC, ne revient PAS en arrière, et laisse la
# machine à moitié armée. Sur le gabarit d'alors : **12 règles déclarées, 6 chargées**. Le code de
# retour (rc=1, « error in line 12 ») ne dit NI combien de règles manquent, NI lesquelles : on ne
# fait donc PAS confiance à l'outil pour se juger lui-même, on COMPTE ce qui est chargé.
#
# `P10.33-c` — LE MÊME ARRÊT, CAUSÉ PAR UN AUTRE FICHIER. Constaté sur un hôte réel : un fichier
# tiers de /etc/audit/rules.d déclarait déjà, à l'identique, la règle execve b64 de ce gabarit.
# augenrules CONCATÈNE les fichiers (ordre du nom) puis `auditctl -R` : la seconde occurrence rend
# « Error sending add rule data request (Rule exists) », auditctl s'arrête, et AUCUNE règle plume qui
# suit n'est chargée. Rien n'était faux dans plume.rules — et un rechargement à la main ne guérit
# rien : au prochain démarrage d'auditd, le même assemblage s'arrête au même endroit.
#
# LA VOIE CHOISIE, ET POURQUOI CELLE-LÀ :
#   1. DÉDOUBLONNER AVANT D'ASSEMBLER. Une ligne du gabarit déjà déclarée À L'IDENTIQUE (espaces
#      normalisés) par un autre `*.rules` du même répertoire est COMMENTÉE dans la copie posée — une
#      ligne pour une ligne, les numéros restent ceux du gabarit — et le chargeur le DIT, fichier
#      nommé. C'est la seule voie qui répare le fichier ASSEMBLÉ : donc le chargement au démarrage
#      aussi, et les règles du fichier tiers quand c'est lui qui vient après plume. Un `-i`/`-c`
#      d'auditctl, lui, est GLOBAL à l'assemblage (il ferait taire les erreurs des autres fichiers,
#      et une vraie erreur de syntaxe avec) ; ignorer « Rule exists » ligne par ligne ne vaut que pour
#      CE chargement-ci, pas pour celui du démarrage.
#   2. COMPTER (`auditctl -l`, seule source de vérité) PAR CLÉ, contre l'attendu DÉRIVÉ du gabarit
#      (`exec_tracking` × 2, `plume_sensitive` × 4, … — jamais un nombre écrit en dur). Les clés
#      survivent à l'aller-retour sous deux formes : `-k <clé>` (watches), `-F key=<clé>` (syscall).
#   3. S'IL MANQUE QUELQUE CHOSE : RATTRAPER règle par règle (`auditctl <règle>`). « Rule exists » est
#      IGNORÉ (la règle tourne déjà) ; TOUTE AUTRE ERREUR est nommée — numéro de ligne, règle, message
#      d'auditctl. Puis on RECOMPTE. C'est ce qui couvre le doublon que l'étape 1 ne reconnaît pas
#      (écrit autrement, chargé à la main) et l'arrêt sur une erreur d'un AUTRE fichier placé avant.
#      Le rattrapage lit le GABARIT, pas la copie dédoublonnée : une règle retirée de plume.rules parce
#      qu'un fichier tiers la porte n'est chargée que si ce fichier va jusqu'à elle — s'il s'arrête
#      avant (erreur plus haut dans CE fichier), seul le gabarit la rend.
#   CODES : 0 tout est chargé, et par l'assemblage lui-même ;
#           1 il MANQUE des règles plume (clés et lignes nommées) — refusé. Ce que le rattrapage a
#             chargé APRÈS la ligne en échec ne vit que dans le noyau COURANT : au démarrage, auditd
#             rejoue l'assemblage, qui s'arrête au même endroit — ces règles-là seront PERDUES, et le
#             chargeur le dit, avec leur nombre ;
#           2 tout est chargé MAINTENANT, mais seulement par le rattrapage : le prochain
#             `augenrules --load` (démarrage d'auditd) s'arrêtera au même endroit. Refusé aussi.
#
# CE QUE ÇA COÛTE, DIT :
#   · une règle plume retirée parce qu'un autre fichier la porte DÉPEND de ce fichier : s'il est
#     supprimé, la règle disparaît au prochain rechargement — relancez ce chargeur après tout
#     changement de /etc/audit/rules.d (il la rendra à plume.rules) ;
#   · seule l'égalité TEXTUELLE est reconnue à l'étape 1 : un doublon écrit autrement (ordre des
#     champs, `auid!=-1` contre `auid!=4294967295`) passe à l'étape 3 et finit en code 2 ;
#   · le rattrapage ajoute les règles EN FIN de politique, pas à leur place dans l'assemblage ;
#   · sur une configuration sans `-D` en tête, une règle restée dans le noyau d'un passage précédent
#     arrête aussi l'assemblage : code 2 jusqu'au prochain redémarrage, alors qu'il serait complet ;
#   · le compte est PAR CLÉ : une règle tierce qui porte une clé plume masquerait une règle plume
#     absente de la même clé.
#
# NOTE : `-e 2` (configuration immuable) n'est pas posé — il interdirait tout rechargement jusqu'au
# reboot, y compris celui-ci. Si vous le posez, faites-le en DERNIER, après cette vérification.
#
# USAGE : sudo sh plume-audit-rules-load.sh [gabarit]
#   gabarit par défaut : `plume-audit.rules` à côté de ce script (dépôt), sinon ../../share/plume/
#   (installé : /usr/local/lib/plume/ → /usr/local/share/plume/plume-audit.rules).
#   PLUME_AUDIT_RULES_DEST : fichier posé (défaut /etc/audit/rules.d/plume.rules).
# VÉRIFIER À LA MAIN : sudo auditctl -l | grep -cE -- '(-k |key=)plume_'
# =================================================================================================
set -eu

ICI=$(dirname "$0")
if [ $# -ge 1 ]; then
  SRC=$1
elif [ -r "$ICI/plume-audit.rules" ]; then
  SRC=$ICI/plume-audit.rules
else
  SRC=$ICI/../../share/plume/plume-audit.rules
fi
DEST="${PLUME_AUDIT_RULES_DEST:-/etc/audit/rules.d/plume.rules}"
RULES_D=$(dirname "$DEST")
GESTE="sudo sh $0 $SRC"

[ -r "$SRC" ] || { echo "!! gabarit introuvable : $SRC" >&2; exit 1; }
command -v auditctl >/dev/null 2>&1 || {
  echo "!! auditctl absent — auditd n'est pas installé." >&2
  echo "   Ubuntu/Debian : sudo apt install auditd" >&2
  exit 1
}
command -v augenrules >/dev/null 2>&1 || { echo "!! augenrules absent (paquet auditd incomplet)" >&2; exit 1; }
[ -d "$RULES_D" ] && [ -w "$RULES_D" ] || { echo "!! $RULES_D absent ou non inscriptible : ce script doit tourner en root" >&2; exit 1; }

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

# Clés d'un flux de règles (gabarit ou `auditctl -l`), avec leur multiplicité : « <n> <clé> ».
cles() {
  awk '/^[ \t]*-/ { for (i = 1; i <= NF; i++) {
         if ($i == "-k" && i < NF) { print $(i + 1); next }
         if ($i ~ /^key=/) { print substr($i, 5); next } } }' | sort | uniq -c
}
compter_charge() { auditctl -l 2>/dev/null | cles > "$T/charge" || true; }
# « <clé> <chargées> <déclarées> » pour chaque clé du gabarit sous son compte.
manquantes() {
  awk 'FILENAME == ARGV[1] { got[$2] = $1; next }
       { g = ($2 in got) ? got[$2] : 0; if (g + 0 < $1 + 0) print $2, g, $1 }' "$T/charge" "$T/attendu"
}

# --- 1. ATTENDU : les clés déclarées par le gabarit ------------------------------------------------
cles < "$SRC" > "$T/attendu"
[ -s "$T/attendu" ] || { echo "!! aucune règle avec clé (-k) trouvée dans $SRC — rien à vérifier, on refuse de conclure." >&2; exit 1; }
echo ">> gabarit  : $SRC"
echo ">> attendu  (clé × nombre de règles déclarées) :"
sed 's/^/     /' "$T/attendu"

# --- 2. DÉDOUBLONNAGE contre les autres fichiers de rules.d, puis pose ------------------------------
set --
for f in "$RULES_D"/*.rules; do
  [ -f "$f" ] && [ "$f" != "$DEST" ] && set -- "$@" "$f"
done
PLUME_GABARIT="$SRC" PLUME_DOUBLONS="$T/doublons" awk '
  function norm(l) { gsub(/[ \t]+/, " ", l); sub(/^ /, "", l); sub(/ $/, "", l); return l }
  FILENAME != ENVIRON["PLUME_GABARIT"] {
    if ($0 ~ /^[ \t]*-[aAw]/) { n = norm($0); if (!(n in vu)) vu[n] = FILENAME }
    next
  }
  $0 ~ /^[ \t]*-[aAw]/ {
    n = norm($0)
    if (n in vu) {
      print "## plume-doublon : déjà déclarée par " vu[n] " (retirée ici, sinon « Rule exists » arrête augenrules) : " n
      print FNR "\t" vu[n] > ENVIRON["PLUME_DOUBLONS"]
      next
    }
  }
  { print }' "$@" "$SRC" > "$T/plume.rules"
if [ -s "$T/doublons" ]; then
  while IFS='	' read -r num fichier; do
    echo ">> doublon  : ligne $num du gabarit déjà déclarée, à l'identique, par $fichier"
    echo "              -> commentée dans $DEST (sinon augenrules s'arrêterait sur « Rule exists »)."
  done < "$T/doublons"
  echo "              Si l'un de ces fichiers change ou disparaît, relancez : $GESTE"
fi
install -m0640 "$T/plume.rules" "$DEST"

# --- 3. CHARGEMENT de l'assemblage ------------------------------------------------------------------
echo ">> chargement (augenrules --load) …"
augrc=0
augout=$(augenrules --load 2>&1) || augrc=$?
compter_charge
if [ -z "$(manquantes)" ]; then
  if [ "$augrc" -ne 0 ]; then
    echo "   (augenrules a rendu rc=$augrc APRÈS les règles plume, dans un autre fichier :"
    printf '%s\n' "$augout" | sed 's/^/      /'
    echo "    — hors de plume, mais les règles qui suivent cette ligne-là ne sont pas chargées.)"
  fi
  echo ">> chargé   (clé × nombre de règles vues par auditctl -l) :"
  sed 's/^/     /' "$T/charge"
  echo ">> OK — toutes les règles déclarées sont chargées."
  echo "   Vérifiez quand même de vos yeux : sudo auditctl -l | grep -cE -- '(-k |key=)plume_'"
  exit 0
fi

echo "!! après augenrules --load (rc=$augrc), il manque des règles plume :" >&2
manquantes | while read -r k g n; do echo "   clé '$k' : $g chargée(s) sur $n déclarée(s)" >&2; done
echo "   sortie d'augenrules :" >&2
printf '%s\n' "${augout:-(rien)}" | sed 's/^/      /' >&2

# --- 4. RATTRAPAGE règle par règle -------------------------------------------------------------------
echo ">> rattrapage : chaque règle du gabarit, une par une (« Rule exists » = déjà chargée, ignorée)"
num=0; rattrapees=0; refusees=0
while IFS= read -r ligne || [ -n "$ligne" ]; do
  num=$((num + 1))
  regle=${ligne#"${ligne%%[! 	]*}"}
  case $regle in -a*|-A*|-w*) ;; *) continue ;; esac
  set -f
  rc=0; sortie=$(auditctl $regle 2>&1) || rc=$?
  set +f
  if [ "$rc" -eq 0 ]; then
    rattrapees=$((rattrapees + 1))
    echo "   + ligne $num chargée par le rattrapage : $regle"
  elif printf '%s\n' "$sortie" | grep -q -e 'Rule exists' -e 'File exists'; then
    :
  else
    refusees=$((refusees + 1))
    echo "!! ligne $num de $SRC REFUSÉE par auditctl : $regle" >&2
    printf '%s\n' "$sortie" | sed 's/^/      auditctl : /' >&2
  fi
done < "$SRC"

compter_charge
echo ">> chargé   (clé × nombre de règles vues par auditctl -l) :"
sed 's/^/     /' "$T/charge"
if [ -n "$(manquantes)" ]; then
  manquantes | while read -r k g n; do echo "!! CLÉ '$k' : $g règle(s) chargée(s) sur $n déclarée(s)" >&2; done
  if [ "$refusees" -gt 0 ]; then
    cat >&2 <<EOF

!! CHARGEMENT PARTIEL — REFUSÉ ($refusees ligne(s) du gabarit refusée(s) par auditctl, nommées ci-dessus).
   Cause la plus fréquente : une règle \`-F dir=\` ou \`-F path=\` qui pointe un chemin ABSENT.
   Corrigez ou commentez la ligne nommée dans le gabarit ($SRC), puis relancez :
     $GESTE
EOF
  else
    cat >&2 <<EOF

!! CHARGEMENT PARTIEL — REFUSÉ. Aucune ligne du gabarit n'est refusée par auditctl : chacune est
   chargée ou « Rule exists ». La cause n'est donc PAS une ligne refusée à corriger : le gabarit
   déclare deux fois, sous la même clé, une règle que le noyau tient pour une seule (à l'identique ou
   écrite autrement) — il n'en garde qu'une. Retirez le doublon du gabarit ($SRC), puis relancez :
     $GESTE
EOF
  fi
  if [ "$rattrapees" -gt 0 ]; then
    cat >&2 <<EOF
   MAINTENANT : $rattrapees règle(s) que l'assemblage n'a pas chargées tournent par le seul rattrapage
   (« + ligne N » ci-dessus) ; il ne manque au noyau que ce que nomment les « CLÉ » ci-dessus.
   AU PROCHAIN DÉMARRAGE d'auditd, \`augenrules --load\` rejoue l'assemblage et s'arrête au même endroit :
   ces $rattrapees règle(s) rattrapée(s) seront PERDUES au prochain démarrage, en plus de ce qui manque déjà.
EOF
  fi
  echo "   Vérifier :  sudo auditctl -l | grep -cE -- '(-k |key=)plume_'     (la SEULE preuve de ce qui tourne)" >&2
  exit 1
fi
if [ "$rattrapees" -gt 0 ]; then
  cat >&2 <<EOF

!! RÈGLES PLUME COMPLÈTES MAINTENANT, MAIS PAR LE SEUL RATTRAPAGE ($rattrapees règle(s)) — REFUSÉ.
   augenrules s'est arrêté AVANT elles (sa sortie est ci-dessus : « error in line N » désigne
   /etc/audit/audit.rules, le fichier ASSEMBLÉ). Le prochain \`augenrules --load\` — au démarrage
   d'auditd — s'arrêtera au même endroit, et la machine redémarrera à moitié armée.
   Geste : retrouvez dans $RULES_D le fichier qui porte cette ligne ; si c'est une règle plume écrite
   autrement, retirez-la de ce fichier (ou de plume.rules) ; si c'est une erreur, corrigez-la. Puis :
     $GESTE
EOF
  exit 2
fi
echo ">> OK — toutes les règles déclarées sont chargées (le rattrapage n'a rien eu à faire)."
echo "   Vérifiez quand même de vos yeux : sudo auditctl -l | grep -cE -- '(-k |key=)plume_'"
