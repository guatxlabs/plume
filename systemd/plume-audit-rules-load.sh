#!/bin/sh
# =================================================================================================
# Plume — chargement VÉRIFIÉ des règles auditd. Un chargement PARTIEL est un ÉCHEC.
# -------------------------------------------------------------------------------------------------
# LE DÉFAUT QUE CE SCRIPT FERME (mesuré le 2026-08-01, VM Ubuntu 24.04 Server fraîche, amd64) :
# `augenrules --load` S'ARRÊTE À LA PREMIÈRE RÈGLE EN ÉCHEC, ne revient PAS en arrière, et laisse la
# machine à moitié armée. Sur le gabarit d'alors : **12 règles déclarées, 6 chargées**. L'opérateur
# n'a rien vu passer d'explicite, et surtout : rien ne lui disait COMBIEN il en manquait.
#
# POURQUOI ON NE REGARDE PAS `$?` — mesure contre l'idée reçue : sur cette image `augenrules --load` a
# rendu **rc=1** et affiché « error in line 12 ». Le code de retour n'est donc pas toujours 0. Mais il
# ne dit NI combien de règles manquent, NI lesquelles, et il ne défait pas le chargement partiel : un
# script qui se contenterait de `augenrules --load && echo ok` resterait aveugle au fait que la moitié
# de la politique d'audit est absente. On ne fait donc PAS confiance à un outil tiers pour se juger
# lui-même. On COMPTE ce qui est réellement chargé.
#
# LA VÉRIFICATION EST DÉRIVÉE, PAS ÉCRITE EN DUR — on ne code nulle part « attends-toi à 12 » (un
# nombre en dur pourrit dès qu'on édite le fichier, et pourrit vers le dangereux : il finit par valider
# un fichier qu'il ne décrit plus). On dérive l'attendu DU FICHIER LUI-MÊME :
#   1. ATTENDU  : chaque ligne de règle non commentée du fichier porte un `-k <clé>`. On compte les
#                 règles PAR CLÉ (`exec_tracking` × 2, `plume_sensitive` × 4, …).
#   2. RÉEL     : `auditctl -l` est la SEULE source de vérité sur ce qui tourne dans le noyau. Les clés
#                 y survivent au aller-retour, sous deux formes selon le type de règle — `-k <clé>`
#                 pour les watches, `-F key=<clé>` pour les règles syscall. On extrait les deux.
#   3. VERDICT  : pour CHAQUE clé déclarée, réel >= attendu. Sinon on ÉCHOUE en nommant la clé et
#                 l'écart. Comparer PAR CLÉ (et non un total) rend la garde insensible aux autres
#                 fichiers de `rules.d` — qui ajoutent leurs propres règles sans fausser le compte.
# Ajouter, retirer ou réécrire une règle dans le gabarit ne demande donc AUCUNE mise à jour ici.
#
# NOTE : `-e 2` (configuration immuable) n'est pas posé — il interdirait tout rechargement jusqu'au
# reboot, y compris celui-ci. Si vous le posez, faites-le en DERNIER, après cette vérification.
# =================================================================================================
set -eu

SRC="${1:-$(dirname "$0")/plume-audit.rules}"
DEST="${PLUME_AUDIT_RULES_DEST:-/etc/audit/rules.d/plume.rules}"

[ "$(id -u)" = 0 ] || { echo "!! ce script doit tourner en root (il écrit dans /etc/audit/rules.d)" >&2; exit 1; }
[ -r "$SRC" ] || { echo "!! gabarit introuvable : $SRC" >&2; exit 1; }
command -v auditctl >/dev/null 2>&1 || {
  echo "!! auditctl absent — auditd n'est pas installé." >&2
  echo "   Ubuntu/Debian : sudo apt install auditd" >&2
  exit 1
}
command -v augenrules >/dev/null 2>&1 || { echo "!! augenrules absent (paquet auditd incomplet)" >&2; exit 1; }

# --- 1. ATTENDU : les clés déclarées par le gabarit, avec leur multiplicité --------------------------
# Une ligne de règle = commence par `-` (les commentaires commencent par `#`). On ne retient que les
# lignes qui portent une clé : ce sont exactement les règles que ce gabarit prétend poser.
expected=$(grep -E '^[[:space:]]*-' "$SRC" | sed -n 's/.*-k[[:space:]]\+\([^[:space:]]\+\).*/\1/p' | sort | uniq -c)
[ -n "$expected" ] || { echo "!! aucune règle avec clé (-k) trouvée dans $SRC — rien à vérifier, on refuse de conclure." >&2; exit 1; }

echo ">> gabarit  : $SRC"
echo ">> attendu  (clé × nombre de règles déclarées) :"
printf '%s\n' "$expected" | sed 's/^/     /'

# --- 2. CHARGEMENT ---------------------------------------------------------------------------------
install -m0640 "$SRC" "$DEST"
echo ">> chargement (augenrules --load) …"
# `|| true` DÉLIBÉRÉ : le code de retour de augenrules n'est pas notre critère (cf. en-tête). C'est le
# comptage ci-dessous qui décide. On garde quand même le code pour le journaliser honnêtement.
augrc=0
augenrules --load >/dev/null 2>&1 || augrc=$?
[ "$augrc" -eq 0 ] || echo "   (augenrules a rendu rc=$augrc — informatif ; le verdict vient du comptage)"

# --- 3. RÉEL : ce que le NOYAU rapporte -------------------------------------------------------------
loaded=$(auditctl -l 2>/dev/null | sed -n -e 's/.*-k[[:space:]]\+\([^[:space:]]\+\).*/\1/p' -e 's/.*-F[[:space:]]\+key=\([^[:space:]]\+\).*/\1/p' | sort | uniq -c)
echo ">> chargé   (clé × nombre de règles vues par auditctl -l) :"
printf '%s\n' "${loaded:-     (aucune)}" | sed 's/^/     /'

# --- 4. VERDICT ------------------------------------------------------------------------------------
missing=0
echo "$expected" | while read -r n key; do
  [ -n "${key:-}" ] || continue
  got=$(printf '%s\n' "$loaded" | awk -v k="$key" '$2==k {print $1; found=1} END{if(!found) print 0}' | head -1)
  if [ "${got:-0}" -lt "$n" ]; then
    echo "!! CLÉ '$key' : $got règle(s) chargée(s) sur $n déclarée(s)" >&2
    echo x >> /tmp/.plume-audit-missing.$$
  fi
done
[ -f "/tmp/.plume-audit-missing.$$" ] && missing=$(wc -l < "/tmp/.plume-audit-missing.$$")
rm -f "/tmp/.plume-audit-missing.$$"

if [ "${missing:-0}" -gt 0 ]; then
  cat >&2 <<'EOF'

!! CHARGEMENT PARTIEL — REFUSÉ.
   auditd a chargé MOINS de règles que le fichier n'en déclare. `augenrules` s'arrête à la première
   règle en échec : tout ce qui SUIT la ligne fautive est absent, et la machine est à moitié armée.
   Cause la plus fréquente : une règle `-F dir=` ou `-F path=` qui pointe un chemin ABSENT.
   Diagnostic :
     sudo augenrules --load          # relisez le message « error in line N »
     sudo auditctl -l                # la SEULE preuve de ce qui tourne réellement
   Corrigez ou commentez la règle fautive dans le gabarit, puis relancez ce script.
EOF
  exit 1
fi

echo ">> OK — toutes les règles déclarées sont chargées."
echo "   Vérifiez quand même de vos yeux : sudo auditctl -l"
