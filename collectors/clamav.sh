#!/bin/sh
# Capteur SOC (PLUGIN) : antivirus ClamAV sur les fichiers NOUVEAUX de chemins surveilles
# (pieces jointes mail, uploads, /tmp...) -> events source=clamav. Plugin : si clamscan/clamdscan
# absent OU aucun chemin configure -> exit 0. Dependance = ClamAV uniquement (optionnel).
# Incremental : ne scanne que les fichiers modifies depuis le dernier passage (marqueur d'horodatage).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
PATHS="${PLUME_CLAMAV_PATHS:-}"                       # ex: "/opt/.../mail-data /var/www/uploads"
[ -n "$PATHS" ] || plume_unavailable clamav missing-config "PLUME_CLAMAV_PATHS non pose : aucun chemin a scanner"
if command -v clamdscan >/dev/null 2>&1; then SCAN="clamdscan --fdpass --no-summary -i"
elif command -v clamscan >/dev/null 2>&1; then SCAN="clamscan --no-summary -i"
else plume_unavailable clamav missing-dependency "ni clamdscan ni clamscan sur cet hote"; fi
STAMP="$STATE_DIR/clamav.stamp"
MAX="${PLUME_CLAMAV_MAX:-500}"                        # plafond de fichiers scannes par passage

# liste des fichiers NOUVEAUX (plus recents que le marqueur) ; 1er run = depuis le marqueur cree maintenant
list=$(mktemp)
brut=$(mktemp)
if [ -f "$STAMP" ]; then findnew="-newer $STAMP"; else findnew=""; fi
# S36 — LE LISTAGE EST LA LECTURE DE CE CAPTEUR, et c'est lui que le repere acquitte : ce que
# `find -newer` a rendu ne sera plus jamais represente. Le `for` etait la source d'un TUBE, donc
# tournait dans un sous-shell : le verdict de chaque `find` s'y perdait, et un chemin devenu
# illisible rendait une liste vide, indiscernable de « aucun fichier nouveau ». Le repere etait
# avance sur cette lecture ratee, et les fichiers modifies dans l'intervalle n'etaient jamais
# scannes — un verdict `malware` pouvait disparaitre sans trace. Plus de tube : le code de retour
# reste lisible, et les chemins fautifs sont NOMMES.
_liste_ko=""
# shellcheck disable=SC2086
for p in $PATHS; do
  [ -e "$p" ] || continue
  find "$p" -type f $findnew >> "$brut" 2>/dev/null || _liste_ko="$_liste_ko $p"
done
head -n "$MAX" "$brut" > "$list"
rm -f "$brut"
# S30 — le repere incremental est cree sur un TEMPORAIRE et ne remplace `$STAMP` qu'APRES publication
# (c'est sa DATE qui fait office de filigrane pour `find -newer`, et le renommage la preserve). Avant,
# il avancait avant meme le scan : une coupure entre l'avance et la publication rendait les fichiers
# deja listes invisibles au passage suivant, et un verdict `malware` pouvait disparaitre sans trace.
# La cle `clamav-<fichier>-<signature>` est une identite de contenu -> le rejeu est absorbe au central.
# S36 — le repere n'est mis en attente QUE si le listage a abouti partout. Sinon le capteur avoue et
# CONTINUE de scanner ce qu'il a pu lister : ne rien avancer coute une relecture bornee au passage
# suivant, avancer couterait le scan lui-meme.
if [ -z "$_liste_ko" ]; then
  _stamp_tmp=$(mktemp "$STATE_DIR/.clamav.stamp.XXXXXX")
  state_stage_file "$_stamp_tmp" "$STAMP"
else
  plume_lecture_partielle clamav source_illisible "listage des fichiers nouveaux incomplet sous :$_liste_ko"
fi

if [ ! -s "$list" ]; then rm -f "$list"; plume_exit_nodata; fi

# scan -> ClamAV imprime "<fichier>: <signature> FOUND" pour chaque infection
res=$(mktemp); sortie=$(mktemp)
# xargs : passe les fichiers en arguments (gere les gros lots) ; on ne garde que les FOUND
# S36 — LE SCAN AUSSI EST UNE LECTURE, et son echec etait avale par `|| true` : `res` sortait vide,
# `events` aussi, et la sortie « rien a signaler » acquittait le repere alors que les fichiers
# listes n'avaient jamais ete examines. Le filtre `grep` est SORTI du tube : sans quoi c'est SON
# verdict (rien trouve = 1, cas normal) qui aurait ete lu a la place de celui du scanner.
# CE QUE LE CODE DE RETOUR PERMET DE CONCLURE, ET CE QU'IL NE PERMET PAS : `clamscan` rend 1 quand
# il TROUVE et 2 sur erreur, mais `xargs` ramene les deux a 123. Le seul verdict sur : un echec sans
# la moindre ligne `FOUND` ne peut pas etre une detection, donc c'est une erreur. Un lot qui melange
# une detection et une erreur reste indiscernable — la limite est ecrite plutot que tue.
_scan_rc=0
xargs -d '\n' -r $SCAN < "$list" > "$sortie" 2>/dev/null || _scan_rc=$?
grep ' FOUND$' "$sortie" > "$res" || true
rm -f "$list" "$sortie"
if [ "$_scan_rc" != 0 ] && [ ! -s "$res" ]; then
  plume_lecture_echouee clamav source_illisible "le scan antivirus s'est termine en erreur (code $_scan_rc) sans rendre le moindre verdict : les fichiers listes n'ont PAS ete examines"
fi

events=""
while IFS= read -r line; do
  [ -z "$line" ] && continue
  file=${line%%: *}
  sig=${line#*: }; sig=${sig% FOUND}
  m=$(json_escape "$(printf 'malware: %s dans %s' "$sig" "$file")")
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"clamav\",\"category\":\"malware\",\"severity\":4,\"message\":\"$m\",\"dedup\":\"clamav-$file-$sig\"}"
done < "$res"
rm -f "$res"
[ -z "$events" ] && plume_exit_nodata

spool_write_then_ack "clamav-$ts.json" "$(emit_event "$events")"
