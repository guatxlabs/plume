#!/bin/sh
# Capteur Plume (PLUGIN, OFF PAR DEFAUT) : scan YARA des chemins surveilles -> events source=yara
# category=malware. Un match de regle YARA = malware/IOC sur l'hote (severity 4).
#
# GARDE-FOU « OFF par defaut » (double) — le script est INERTE tant qu'il n'est pas configure :
#   1. `yara` absent (command -v yara)               -> exit 0, rien emis.
#   2. repertoire de regles vide/absent (aucune *.yar/*.yara dans PLUME_YARA_RULES) -> exit 0, rien emis.
# Donc : tant que l'operateur n'a pas `apt install yara` + depose des regles dans /etc/plume/yara.d, ce
# collecteur ne produit STRICTEMENT rien (et le timer plume-yara n'est de toute facon pas active : cf.
# bootstrap-agent.sh PLUME_WITH_YARA + systemd/plume-yara.timer NON enable par defaut).
#
# Quand ACTIVE : construit une liste de fichiers BORNEE via find (PRUNE des stores conteneur comme
# integrity.sh, skip des gros fichiers, INCREMENTAL via watermark, plafond MAX) puis lance yara une seule
# fois (--scan-list, timeout borne, -g pour les tags). Parse les MATCHES (regle, tags, fichier), DEDUP par
# (rule,file,mtime) sur l'etat, plafonne le nombre d'events, emet {rule,file,tags,sha256} severity 4.
# Lecture seule (hash sha256 des seuls fichiers matches, peu nombreux). Sans jq.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
RULES_DIR="${PLUME_YARA_RULES:-/etc/plume/yara.d}"
PATHS="${PLUME_YARA_PATHS:-/home /tmp /var/tmp /dev/shm}"

# (1) garde-fou : binaire yara absent -> inerte.
command -v yara >/dev/null 2>&1 || plume_unavailable yara missing-dependency "yara absent"
# (2) garde-fou : aucune regle deposee -> inerte. On collecte les fichiers de regles (multiples acceptes
#     par yara 4.x en positionnels). Repertoire absent/vide = OFF.
[ -d "$RULES_DIR" ] || plume_unavailable yara missing-config "$RULES_DIR absent : aucun repertoire de regles YARA"
RULES=$(find "$RULES_DIR" -type f \( -name '*.yar' -o -name '*.yara' \) 2>/dev/null | sort)
[ -n "$RULES" ] || plume_unavailable yara missing-config "aucune regle *.yar/*.yara dans $RULES_DIR"

STAMP="$STATE_DIR/yara.stamp"           # watermark incremental (ne re-scanne que le nouveau, cf. clamav)
SEEN="$STATE_DIR/yara.seen"                 # dedup persistant par (rule|file|mtime) ; cree par
                                            # l'ajout DIFFERE (S30), sa lecture tolere son absence
MAX="${PLUME_YARA_MAX:-5000}"           # plafond de fichiers listes par passage
MAXE="${PLUME_YARA_MAX_EVENTS:-200}"    # plafond d'events emis par passage (anti-flood)
TIMEOUT="${PLUME_YARA_TIMEOUT:-120}"    # borne le temps de scan (s)
MAXSZ="${PLUME_YARA_MAX_FILE_SIZE:-100M}"  # skip des fichiers trop gros (find -size -N)
# PRUNE des stores conteneur (anti-bruit snapshots buildkit/rancher/containerd), aligne sur integrity.sh.
PRUNE="${PLUME_YARA_PRUNE:-/var/lib/buildkit /var/lib/rancher /var/lib/containerd /var/lib/docker /var/lib/kubelet}"
prune_expr=""; for _d in $PRUNE; do prune_expr="$prune_expr -path $_d -prune -o"; done

# --- liste BORNEE de fichiers a scanner : incremental (>= watermark), pruned, < MAXSZ, plafonnee. ---
list=$(mktemp)
if [ -f "$STAMP" ]; then findnew="-newer $STAMP"; else findnew=""; fi
# shellcheck disable=SC2086  ($prune_expr/$findnew = tokens a eclater ; expansion voulue)
for p in $PATHS; do
  [ -e "$p" ] || continue
  find "$p" -xdev $prune_expr -type f $findnew ! -size +"$MAXSZ" -print 2>/dev/null
done | head -n "$MAX" > "$list"
# S30 — meme forme que clamav : le repere incremental (`find -newer`) est cree sur un temporaire et ne
# remplace `$STAMP` qu'APRES publication. Une coupure entre l'ancienne avance et la publication rendait
# les fichiers deja listes invisibles au passage suivant — un match YARA pouvait disparaitre sans trace.
_stamp_tmp=$(mktemp "$STATE_DIR/.yara.stamp.XXXXXX")
state_stage_file "$_stamp_tmp" "$STAMP"
if [ ! -s "$list" ]; then rm -f "$list"; plume_exit_nodata; fi

# --- scan : yara une fois (--scan-list lit la liste ; -g imprime les tags). timeout borne le run. ---
# Format de sortie yara -g : "<rule> [<tags>] <fichier>" (1 ligne par match).
TO=""; if command -v timeout >/dev/null 2>&1; then TO="timeout $TIMEOUT"; fi
res=$(mktemp)
# shellcheck disable=SC2086  ($TO/$RULES = listes de tokens ; "$list" = cible (dernier positionnel)).
$TO yara -g --scan-list $RULES "$list" 2>/dev/null > "$res" || true
rm -f "$list"
if [ ! -s "$res" ]; then rm -f "$res"; plume_exit_nodata; fi

# parse -> TSV "rule \t tags \t file" (file = reste de la ligne ; tags = contenu des [] s'il y en a).
TAB=$(printf '\t')
parsed=$(awk '
  /^[[:space:]]/ { next }          # lignes de strings (-s) eventuelles : indentees -> ignorees
  /^0x/          { next }
  NF>=2 {
    rule=$1; tags=""; fstart=2;
    if ($2 ~ /^\[.*\]$/) { tags=substr($2,2,length($2)-2); fstart=3 }
    file=$fstart; for(i=fstart+1;i<=NF;i++) file=file" "$i;   # le chemin peut contenir des espaces
    if (file=="") next;
    print rule "\t" tags "\t" file;
  }
' "$res")
rm -f "$res"
[ -z "$parsed" ] && plume_exit_nodata

# here-doc (PAS un pipe) -> la boucle tourne dans le shell COURANT : $events/$ne persistent (cf. auditd.sh).
events=""; ne=0
while IFS="$TAB" read -r rule tags file; do
  [ -z "${rule:-}" ] && continue
  [ -z "${file:-}" ] && continue
  [ "$ne" -ge "$MAXE" ] && break
  mtime=$(stat -c %Y "$file" 2>/dev/null || echo 0)
  key="$rule|$file|$mtime"
  # S30 — le registre « deja signale » est un ACQUITTEMENT : l'ajout est donc MIS EN ATTENTE et n'est
  # ecrit qu'apres publication. `state_marker_seen` interroge le fichier ET les lignes en attente, sans
  # quoi un meme constat serait signale deux fois dans le MEME passage.
  state_marker_seen "$SEEN" "$key" && continue               # deja signale (meme rule/file/mtime) -> skip
  state_stage_append "$SEEN" "$key"
  ne=$((ne + 1))
  sha=$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1); [ -n "$sha" ] || sha="?"
  rj=$(json_escape "$rule")
  fj=$(json_escape "$file")
  tj=$(json_escape "$tags")
  m=$(json_escape "$(printf 'YARA: regle %s sur %s' "$rule" "$file")")
  fields="{\"rule\":\"$rj\",\"file\":\"$fj\",\"tags\":\"$tj\",\"sha256\":\"$sha\"}"
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"yara\",\"category\":\"malware\",\"severity\":4,\"message\":\"$m\",\"dedup\":\"yara-$key\",\"fields\":$fields}"
done <<EOF
$parsed
EOF
[ -z "$events" ] && plume_exit_nodata

spool_write_then_ack "yara-$ts.json" "$(emit_event "$events")"
