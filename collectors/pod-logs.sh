#!/bin/sh
# Capteur Plume : logs des pods k8s (/var/log/pods) FILTRÉS (sécurité) -> events source=k8s-log.
# PAS du Loki exhaustif : ne ship que les lignes notables (filtre configurable), borné (anti-volume).
# Offset par fichier. ROOT / OPT-IN. Skip si /var/log/pods absent.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
DIR="${PLUME_POD_LOG_DIR:-/var/log/pods}"
FILTER="${PLUME_POD_LOG_FILTER:-error|fail|denied|unauthorized|panic|fatal|exception|segfault|authenticated|session opened|successful login|logged in|signed in}"
# DÉBRUITAGE — pods déjà couverts par un collecteur DÉDIÉ : les exclure ici évite une DOUBLE ingestion.
# Liste de sous-chaînes séparées par | (comparée au nom de pod). Défaut VIDE : rien n'est exclu.
# À vous de la remplir selon les collecteurs que vous activez (ex. SKIP='app-a|app-b').
SKIP="${PLUME_POD_LOG_SKIP:-}"
MAX="${PLUME_POD_LOG_MAX:-200}"
MIN_SEV="${PLUME_POD_LOG_MIN_SEV:-3}"   # DÉBRUITAGE : ne shippe que sev>=3 (denied/unauthorized/fatal/panic/segfault) ; coupe le bruit du grep error|fail (sev2) et les auth-ok (sev1)
[ -d "$DIR" ] || plume_unavailable k8s-log missing-source "$DIR absent : aucun log de pod a lire sur cet hote"
mkdir -p "$STATE/podoff" 2>/dev/null || true

raw=$(mktemp)
fscan=0   # fichiers réellement scannés ce run (existants, nouveaux octets, hors pods SKIP) -> battement de santé
_pl_ko=""  # journaux dont la LECTURE a échoué ce passage -> leur offset ne bouge pas, et on le DIT (S36)
for f in "$DIR"/*/*/*.log; do
  [ -e "$f" ] || continue
  key=$(printf '%s' "$f" | cksum | cut -d' ' -f1)
  off="$STATE/podoff/$key"
  last=$(cat "$off" 2>/dev/null || echo 0)
  size=$(wc -c < "$f" 2>/dev/null || echo 0)
  [ "$size" -lt "$last" ] && last=0
  # S30 — offset MIS EN ATTENTE, PAR FICHIER, ecrit seulement apres la publication de l'unique
  # enveloppe de fin. C'est le site qui rejoue le plus : le lot porte TOUS les fichiers du passage,
  # pas une enveloppe. S34 — ce rejeu est desormais ABSORBE : chaque ligne expediee porte une cle
  # batie sur son propre horodatage CRI (cf. plus bas), donc republier le lot n'ajoute aucune ligne.
  # S36 — L'OFFSET N'EST MIS EN ATTENTE QU'UNE FOIS LA TRANCHE LUE. Il l'etait avant meme d'essayer,
  # et sa valeur (la TAILLE du fichier) ne doit rien a la lecture : un `tail` qui echouait sur un
  # journal supprime sous le lecteur, ou dont les droits venaient de changer, ne rendait aucune ligne
  # — indiscernable d'un journal calme — et l'unique publication de fin (le battement de sante part a
  # CHAQUE passage) acquittait cet offset. La tranche etait perdue, pour ce fichier seulement, donc
  # sans que rien ne le montre. Un echec ne fait plus avancer QUE le fichier concerne, et il est dit.
  # Les deux sorties de boucle ci-dessous acquittent, elles, une lecture qui n'avait pas lieu d'etre :
  # aucun octet neuf, ou pod couvert par un collecteur dedie.
  if [ "$size" -le "$last" ]; then state_stage "$off" "$size"; continue; fi
  pod=$(printf '%s' "$f" | sed -E 's#.*/pods/([^/]+)/.*#\1#')
  # le conteneur = répertoire juste au-dessus du fichier .log (/pods/<ns_pod_uid>/<CONTENEUR>/N.log)
  # -> distingue les conteneurs d'un même pod (app vs sidecar/init) ; perdu auparavant.
  cont=${f%/*}; cont=${cont##*/}
  skip=0; for s in $(printf '%s' "$SKIP" | tr '|' ' '); do case "$pod" in *"$s"*) skip=1; break ;; esac; done
  if [ "$skip" = 1 ]; then state_stage "$off" "$size"; continue; fi   # pod listé dans SKIP (déjà couvert par un collecteur dédié) : pas de double collecte
  fscan=$((fscan + 1))   # ce fichier est effectivement scanné (compteur du battement de santé)
  # Le `tail` est SORTI du tube : son code de retour y etait remplace par celui du `grep` final, pour
  # qui « aucune ligne notable » vaut 1 — c'est-a-dire le cas normal d'un pod tranquille.
  tranche=$(mktemp)
  if tail -c "+$((last + 1))" "$f" > "$tranche" 2>/dev/null; then
    state_stage "$off" "$size"
    grep -iE "$FILTER" "$tranche" 2>/dev/null | head -n 80 | while IFS= read -r l; do
      printf '%s\t%s\t%s\n' "$pod" "$cont" "$l"
    done >> "$raw"
  else
    _pl_ko="$_pl_ko $f"
  fi
  rm -f "$tranche"
done
# Un journal illisible ne rend pas le capteur incapable — les autres pods sont collectes. Il est donc
# AVOUE et le passage continue ; ce qui protege la tranche est que son offset n'a pas ete mis en attente.
[ -n "$_pl_ko" ] && plume_lecture_partielle k8s-log source_illisible "journaux de pod non lus ce passage (leur offset n'avance pas, ils seront relus) :$_pl_ko"

events=""
n=0
lscan=0   # lignes candidates (post-filtre FILTER) examinées ce run -> battement de santé
TAB=$(printf '\t')
# S34 — CLE D'IDENTITE, PRISE DANS LA LIGNE. Le format de journal CRI prefixe chaque ligne de son
# horodatage RFC3339 a la nanoseconde, pose par le runtime au moment de l'ecriture : c'est
# l'identite de la ligne, et elle est INDEPENDANTE du passage qui la lit. La cle joint le pod, le
# conteneur et cet horodatage — le pod seul ne suffirait pas (un pod a plusieurs conteneurs, dont
# les flux sont independants et peuvent partager une nanoseconde). Ni `$ts`, ni l'offset, ni le PID
# n'y entrent : republier le lot reproduit donc les MEMES cles. `k` ne departage que des lignes
# CONSECUTIVES du meme flux portant le meme horodatage, cas que le format autorise sans le garantir
# unique. Une ligne dont le premier jeton n'est pas un horodatage ne recoit AUCUNE cle : mieux vaut
# un doublon visible qu'une cle qui confondrait deux lignes distinctes.
# Le battement de sante de fin reste DELIBEREMENT sans cle (voir son propre commentaire).
while IFS="$TAB" read -r pod cont l; do
  [ -z "${l:-}" ] && continue
  lscan=$((lscan + 1))
  ns=${pod%%_*}                       # <ns>_<pod>_<uid> -> ns = le namespace k8s (souvent 1 par application) -> groupable
  pn=${pod#*_}; pn=${pn%_*}           # nom du pod (sans préfixe ns ni suffixe uid)
  msg=$(printf '%s' "$l" | sed -E 's/^[0-9TZ:.+-]+ (stdout|stderr) [FP] //')
  sev=2
  case "$l" in *denied*|*nauthorized*|*fatal*|*FATAL*|*panic*|*segfault*) sev=3 ;; esac
  case "$l" in *authenticated*|*"session opened"*|*"logged in"*|*"signed in"*|*"successful login"*) sev=1 ;; esac   # auth réussie = info
  [ "$sev" -lt "$MIN_SEV" ] && continue   # DÉBRUITAGE : sous le seuil de sévérité -> non shippé
  n=$((n + 1)); [ "$n" -gt "$MAX" ] && break
  em=$(json_escape "$(printf '%s: %s' "$pn" "$msg" | cut -c1-400)")
  nsj=$(json_escape "$ns"); pnj=$(json_escape "$pn")
  cj=$(json_escape "${cont:-}")
  fj="{\"ns\":\"$nsj\",\"pod\":\"$pnj\",\"container\":\"$cj\"}"
  lts=${l%% *}
  case "$lts" in [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T*) : ;; *) lts="" ;; esac
  ddj=""
  if [ -n "$lts" ]; then
    dk="$pod|$cont|$lts"
    if [ "$dk" = "${prev_dk:-}" ]; then dkn=$((${dkn:-1} + 1)); else prev_dk="$dk"; dkn=1; fi
    ddj=",\"dedup\":\"k8slog-$(json_escape "$dk")-$dkn\""
  fi
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"k8s-log\",\"category\":\"k8s\",\"severity\":$sev,\"message\":\"$em\"$ddj,\"fields\":$fj}"
done < "$raw"
rm -f "$raw"

# DEAD-MAN'S-SWITCH (calque EXACT de crowdsec.sh) : à CHAQUE run on ship AUSSI un battement de SANTÉ
# (source=k8s-log category=health, sev 0) MÊME quand 0 ligne sev≥3 -> Plume distingue « collecteur calme
# (normal) » de « collecteur pod-logs mort/cassé ». Le SILENCE de ce battement (>~25 min) lève une alerte
# MUET (collecteur CONTINU k8s-log-health, cf. main.rs COLLECTORS). PAS de dedup (event.dedup est UNIQUE ->
# un dedup constant bloquerait l'INSERT OR IGNORE et figerait MAX(ts)) -> chaque battement S'INSÈRE -> MAX(ts)
# avance -> heartbeat vivant. On NE coupe PLUS avant ce point (l'ancien « [ -z "$events" ] && exit 0 » sautait
# le battement les runs sans sev≥3) : events contient au minimum ce battement -> le spool part toujours.
hmsg="pod-logs santé: $fscan fichiers, $lscan lignes scannées, $n lignes expédiées (seuil PLUME_POD_LOG_MIN_SEV)"
hfields="{\"files_scanned\":$fscan,\"lines_scanned\":$lscan,\"sev3_shipped\":$n}"
events="$events${events:+,}$(heartbeat k8s-log "$hmsg" "$hfields")"

spool_write_then_ack "podlogs-$ts.json" "$(emit_event "$events")"

# --- CHANTIER whitelists->webui : AUTO-REPORT de config (source=k8s-log category=config) -----------
# Surface FILTER/SKIP/MIN_SEV dans le panneau read-only « Suppressions & whitelists actives » (VISIBILITE
# cote daemon, CONTROLE ici). Dedup par empreinte -> re-emet seulement si la config change. collection-reducing.
cfg_fields=$(printf '{"type":"collection-reducing","collector":"pod-logs","source":"k8s-log","filters":{"filter":"%s","skip":"%s","min_sev":"%s","max":"%s"},"note":"ne ship que les lignes matchant FILTER, hors pods SKIP (collecteurs dedies), au-dessus de MIN_SEV — collecte reduite"}' \
  "$(json_escape "$FILTER")" "$(json_escape "$SKIP")" "$(json_escape "$MIN_SEV")" "$(json_escape "$MAX")")
cfg_dd="cfg-k8s-log-$(printf '%s' "$cfg_fields" | cksum | cut -d' ' -f1)"
cfg_event=$(printf '{"ts":%s,"source":"k8s-log","category":"config","severity":0,"message":"config collecteur pod-logs (filtres de collecte)","dedup":"%s","fields":%s}' \
  "$ts" "$cfg_dd" "$cfg_fields")
spool_write "config-podlogs-$ts.json" "$(emit_event "$cfg_event")"
