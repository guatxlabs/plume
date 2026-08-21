# shellcheck shell=sh
# Plume collectors — shared POSIX-sh library (sourced, NEVER executed directly).
# Sourced at the top of a collector, right after `set -eu`, via:
#     . "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
#
# GOAL : factor the byte-for-byte-identical boilerplate that ~35 host collectors
# duplicate (spool preamble, atomic spool write, JSON escaping, health heartbeat,
# events envelope, kubectl/k3s resolution). Sourcing this file MUST NOT change the
# emitted spool JSON for any collector : every helper reproduces the exact bytes
# the hand-written inline code produced. The ONLY intentional behaviour change is
# in json_escape (invalid-UTF-8 scrub + control-char strip), which only alters
# INVALID input — valid input is passed through byte-identical.
#
# Defines functions + (via plume_init) sets SPOOL / STATE / STATE_DIR / host / ts.
# Pure sh, no bashisms, no external deps beyond coreutils + iconv (best-effort).

# plume_init — spool/state paths, hostname, timestamp, ensure state dir.
# Sets: SPOOL, STATE, STATE_DIR (alias of STATE for the collectors that use it),
#       host, ts. mkdir of STATE is best-effort (never aborts under `set -eu`).
plume_init() {
  SPOOL="${PLUME_SPOOL:-/var/lib/plume/spool}"
  STATE="${PLUME_STATE:-/var/lib/plume/state}"
  STATE_DIR="$STATE"
  host="$(cat /proc/sys/kernel/hostname 2>/dev/null || echo unknown)"
  ts=$(date +%s)
  mkdir -p "$STATE" 2>/dev/null || true
}

# =================================================================================================
# PUBLIER, C'EST AUSSI SURVIVRE À UNE COUPURE (S27)
# -------------------------------------------------------------------------------------------------
# DEUX PROPRIÉTÉS QU'ON CONFOND, ET DONT UNE SEULE ÉTAIT TENUE.
#   ATOMICITÉ DU CONTENU — après `mv`, un lecteur voit l'ANCIEN fichier ou le NOUVEAU, jamais un
#   fichier à moitié écrit. Le renommage la donne, seul. C'est ce que ce fichier faisait déjà.
#   DURABILITÉ — après une coupure d'alimentation ou du noyau, la publication SURVIT. Le renommage
#   ne la donne PAS : il faut que le CONTENU du temporaire soit sur le disque AVANT (sinon on
#   publie un nom qui désigne des octets jamais écrits, donc un fichier vide au redémarrage) et que
#   le RÉPERTOIRE le soit APRÈS (sinon l'entrée de répertoire peut manquer alors que le fichier
#   existe : les octets sont là, leur NOM n'y est pas, et `ship.sh` parcourt le spool PAR NOM).
# La promesse de livraison au moins une fois tenait donc par convention, pas par mécanisme.
#
# L'ASYMÉTRIE EST DÉLIBÉRÉE — `spool_write` est DURABLE, `state_write` ne l'est PAS.
# Un filigrane perdu fait RELIRE une tranche déjà collectée : le central dédoublonne (`event.dedup`,
# `INSERT OR IGNORE`), donc au pire des doublons. Un filigrane qui SURVIVRAIT à des événements
# perdus fait, lui, disparaître ces événements DÉFINITIVEMENT, sans que rien ne les compte. Rendre
# le filigrane durable AVANT l'événement transformerait une perte improbable en perte garantie :
# c'est exactement la direction interdite. Le seul sens sûr est « l'événement d'abord ».
#
# CE QUE CETTE ASYMÉTRIE NE FERMAIT PAS, ET QUI EST FERMÉ DEPUIS (S30) : des capteurs livrés
# avançaient leur filigrane AVANT de publier leurs événements — le filigrane écrit dans la boucle de
# lecture, l'enveloppe composée seulement ensuite. Une coupure entre les deux perdait la tranche, et
# aucune synchronisation ne pouvait y remédier : c'était l'ORDRE, pas la durabilité. LE COMPTE ANNONCÉ
# ICI ÉTAIT FAUX — cinq, dérivés d'un `grep state_write` ; le motif en dénombre DIX-SEPT (les douze
# autres marquaient par redirection brute, `touch` d'un repère daté, ajout dans un registre,
# renommage d'une base de référence, ou point de reprise avancé par un outil externe). L'ordre est
# désormais tenu par construction : voir le bandeau S30 plus bas. Ne PAS rendre `state_write` durable
# reste la bonne décision, et pour la même raison qu'avant.
#
# COÛT — MESURÉ le 2026-08-20 (NVMe, btrfs sur LVM, 100 publications par variante, sh POSIX) :
# publication sans synchronisation 8,5 ms ; avec les deux synchronisations 21,2 ms — soit +12,7 ms.
# Un capteur publie une à trois enveloppes par passage et les unités tournent à la minute : le prix
# se paie en dizaines de millisecondes par minute et par hôte. Il ne serait PAS le même arbitrage
# sur une surface appelée à chaque requête, et ce fichier ne prétend rien pour celles-là.
# =================================================================================================

# plume_sync_path <chemin> — force l'écriture SUR DISQUE d'un fichier ou d'un répertoire.
#
# VALIDATION DE L'INSTRUMENT, AVANT DE S'EN SERVIR. `sync <chemin>` (fsync ciblé) n'existe pas
# partout : GNU coreutils l'accepte depuis 8.24, busybox depuis 1.28, et certains `sync` plus
# anciens ACCEPTENT l'opérande en l'IGNORANT — ils rendent 0 sans rien synchroniser du chemin
# demandé. Croire ce 0 serait croire un instrument non validé, et publier « durablement » ce qui ne
# l'est pas. On tranche donc par DEUX témoins :
#   NÉGATIF : `sync` sur un chemin qui N'EXISTE PAS doit ÉCHOUER. S'il rend 0, il n'a pas ouvert le
#             chemin — il ignore son opérande, et son succès ne prouve rien.
#   POSITIF : `sync` sur le chemin RÉEL doit rendre 0.
# Le verdict est mémoïsé pour le processus (un capteur publie peu, mais il publie plusieurs fois).
#
# REPLI HONNÊTE PLUTÔT QUE SILENCE : si la forme ciblée n'est pas utilisable, on exécute `sync` NU,
# qui est POSIX et présent partout. Il vide TOUS les systèmes de fichiers — plus cher, parfois
# beaucoup — mais il DONNE la propriété demandée. On ne rend jamais la main en laissant croire à
# une durabilité qu'on n'a pas obtenue.
plume_sync_path() {
  if [ -z "${_plume_sync_cible:-}" ]; then
    if sync "$1.plume-sonde-absente-$$" 2>/dev/null; then
      _plume_sync_cible=non          # a rendu 0 sur un chemin ABSENT -> il ignore l'opérande
    elif sync "$1" 2>/dev/null; then
      _plume_sync_cible=oui          # échoue sur l'absent, réussit sur le réel -> il synchronise
      return 0
    else
      _plume_sync_cible=non
    fi
  fi
  if [ "$_plume_sync_cible" = oui ] && sync "$1" 2>/dev/null; then
    return 0
  fi
  sync
}

# spool_write <basename> <content> [nl]
# DURABLE, group-readable (0640) publish into $SPOOL — the exact umask/mktemp/chmod/mv
# sequence ~35 collectors inline today, plus the two syncs the header above explains.
# Content is written VERBATIM (printf '%s');
# pass a third arg "nl" to append exactly one trailing newline (for the collectors
# whose hand-written printf format ended in \n). The transient temp name is a hidden
# dotfile (ship.sh globs *.json and skips dotfiles) so a single generic template is
# safe for all callers — the observable output is only the final $SPOOL/<basename>.
spool_write() {
  umask 027
  _sw_tmp=$(mktemp "$SPOOL/.xx.XXXXXX")
  if [ "${3:-}" = nl ]; then
    printf '%s\n' "$2" > "$_sw_tmp"
  else
    printf '%s' "$2" > "$_sw_tmp"
  fi
  spool_publish_file "$_sw_tmp" "$1"
}

# spool_publish_file <tempfile> <basename>
# Same DURABLE publication, for the collectors that build their temp file themselves (streaming
# into it line by line, then publishing only if it is non-empty) instead of passing a string to
# spool_write. It exists so those callers have somewhere to go: before it, seven of them inlined
# `chmod 0640 "$tmp"; mv -f "$tmp" "$SPOOL/<name>"` and therefore re-invented the write-temp-then-
# rename motif — each one a site where the missing syncs had to be noticed separately.
# The temp file MUST already live in $SPOOL (same filesystem — a rename across filesystems is a
# copy, hence no longer atomic) and MUST be a dotfile (ship.sh must not pick it up mid-write).
# `.github/scripts/check_publication_is_durable.py` refuses any new inline publication.
spool_publish_file() {
  chmod 0640 "$1"
  plume_sync_path "$1"       # le CONTENU est sur le disque AVANT que le nom n'existe
  mv -f "$1" "$SPOOL/$2"
  plume_sync_path "$SPOOL"   # l'ENTRÉE DE RÉPERTOIRE l'est APRÈS le renommage
}

# state_write <file> <content>
# Atomic watermark/cursor write : temp-in-same-dir + rename, replacing the
# non-atomic `printf '%s' "$x" > "$WM"` the collectors do today (fixes a torn-write
# window on crash). State files are NEVER shipped, so this changes no spool bytes;
# the file content is byte-identical, only the write is now crash-safe.
# DELIBERATELY NOT DURABLE — see the asymmetry paragraph in the header above: a watermark that
# outlives the events it acknowledges is how events vanish, whereas a watermark that is lost only
# costs a replay the central deduplicates. Do not "fix" this by adding a sync here.
state_write() {
  umask 077
  _st_dir=$(dirname "$1")
  _st_tmp=$(mktemp "$_st_dir/.st.XXXXXX")
  printf '%s' "$2" > "$_st_tmp"
  mv -f "$_st_tmp" "$1"
}

# =================================================================================================
# ACQUITTER APRÈS AVOIR PUBLIÉ, JAMAIS AVANT (S30)
# -------------------------------------------------------------------------------------------------
# S27 a rendu la PUBLICATION durable et laissé le FILIGRANE volatil, en notant au passage que cinq
# capteurs avançaient tout de même leur filigrane AVANT de publier. LE COMPTE ÉTAIT FAUX, et pour la
# raison exacte que S27 avait elle-même nommée à propos du sien : il avait été dérivé du SYMBOLE
# `state_write`, pas du MOTIF. Recherche refaite sur le motif « un site qui marque la progression et
# un site qui publie, dans le même flot » : DIX-SEPT capteurs, pas cinq. Les douze manquants marquent
# leur progression autrement — redirection brute (`printf '%s' "$size" > "$OFF"`), `touch` d'un
# fichier-repère relu ensuite en `find -newer`, ajout d'une ligne dans un registre « déjà signalé »,
# renommage d'une base de référence. Aucune de ces quatre formes n'apparaît dans un `grep state_write`.
#
# L'ORDRE EST LE SUJET, ET IL NE PENCHE QUE D'UN CÔTÉ.
#   MARQUER PUIS PUBLIER — une coupure entre les deux PERD les événements, et rien ne le signale :
#   le marqueur affirme qu'ils sont acquittés, donc personne ne les relira jamais. Aucune
#   synchronisation ne répare ça ; rendre le marqueur DURABLE ne ferait qu'en garantir la perte.
#   PUBLIER PUIS MARQUER — la même coupure produit un REJEU : le passage suivant relit la même
#   tranche et la republie. Un rejeu se voit, se compte et se corrige ; une perte est silencieuse.
#
# CE QUE LE REJEU DEVIENT AU CENTRAL — S34, ET LE DÉCOMPTE PRÉCÉDENT ÉTAIT FAUX DEUX FOIS.
# LE MÉCANISME, D'ABORD, parce que c'est de lui que la partition se dérive : `event.dedup` porte un
# index UNIQUE au niveau de la base et toute écriture est un `INSERT OR IGNORE` ; le daemon
# CLOISONNE la clé par l'hôte de la ligne au point d'écriture (`dedup_scoped_by_host`). Une clé
# ABSENTE vaut NULL, et SQLite tient deux NULL pour DISTINCTS : sans clé, il n'y a pas de dédup du
# tout. La question n'est donc pas « quel capteur a été converti » mais « qu'est-ce que l'événement
# PORTE, et cette valeur est-elle la même quand on le republie ».
# LA POPULATION EXACTE est celle des capteurs qui peuvent REJOUER — ceux qui publient puis
# acquittent, soit les VINGT-DEUX qui appellent `spool_write_then_ack` / `spool_publish_then_ack`.
# Le décompte annoncé la portait à dix-sept parce qu'il avait hérité de la liste `S30`, qui recensait
# les capteurs dont l'ORDRE était fautif ; `web`, `mail` et `dataaccess` avaient déjà le bon ordre et
# rejouent tout autant, `resources` aussi. C'est la même faute qu'avant, d'un cran plus haut : une
# liste reprise au lieu d'une propriété redérivée.
#   ABSORBÉ INTÉGRALEMENT — la clé est une IDENTITÉ DE CONTENU, indépendante du passage qui la lit,
#     et le rejeu n'ajoute aucune ligne. NEUF, et non six : `journal` (le daemon prend `__CURSOR`),
#     `imgdrift` (`update-<image>-<digest>`), `vuln`, `clamav`, `yara` (`<règle|fichier|mtime>`),
#     `cloudflare` (`cf-<rayName>`), plus les trois oubliés — `web` (`web-<StartUTC>` de la requête),
#     `mail` (horodatage de la ligne de journal, IP, action) et `dataaccess` (identifiant de
#     l'enregistrement auditd). Depuis `S34` s'y ajoutent les huit corrigés ci-dessous.
#   ABSORBÉ SEULEMENT DANS LE MÊME SEAU DE TEMPS — la clé porte un SEAU DE L'INSTANT DE COLLECTE, pas
#     une identité : `ufw` (seau horaire), `portscan` (5 min), `origin-drop` (1 min), `kube-audit`
#     (empreinte + 10 min). Ces quatre seaux sont une AGRÉGATION VOULUE (un même scanneur ne remplit
#     pas un tableau de bord), et ils ne sont pas touchés — mais il faut voir ce qu'ils coûtent : une
#     coupure qui enjambe la frontière du seau n'est PAS absorbée, et c'est le régime le plus subtil
#     des trois, parce qu'il marche jusqu'à ce qu'il ne marche plus.
#   PAS ABSORBÉ DU TOUT — c'était le cas de SEPT capteurs dont les événements ne portaient aucune
#     clé (`falco`, `suricata`, `auditd`, `audit`, `pod-logs`, `integrity`, `containerd`), et d'un
#     HUITIÈME que le décompte précédent rangeait à tort dans l'identité de contenu : `cloudflare-http`
#     bâtissait sa clé sur `<instant de collecte>/60`, donc sur le moment de la PUBLICATION. Une clé
#     qui contient l'instant de publication ne dédoublonne rien.
# CE QUE `S34` A POSÉ : chacun de ces huit porte désormais une clé prise dans ce qu'il OBSERVE —
# l'horodatage nanoseconde du record (`falco`, `pod-logs`), l'horodatage microseconde (`suricata`),
# le serial du noyau (`auditd`), l'identifiant d'image ou de conteneur (`containerd`), le triplet
# (chemin, empreinte, date) du constat (`integrity`), ou, quand le record lui-même n'offre aucune
# identité, la BORNE BASSE DE LA TRANCHE, qui n'avance qu'après la publication (`audit`,
# `cloudflare-http`). Ce qui reste SANS clé est nommé plutôt que bricolé : les ports en écoute
# d'`integrity` (leur seule composante stable se répète légitimement), et tout record privé de son
# horodatage. Le détail et la raison sont écrits dans chaque capteur, au point d'émission.
#
# COMBIEN AU PIRE. Le rejeu porte sur UN passage de collecte, borné par le plafond du capteur (limites
# de conception, pas d'exploitation) : `PLUME_AUDIT_MAX`/`PLUME_KUBE_AUDIT_MAX` 4000 lignes,
# `PLUME_SURICATA_*` 400, `PLUME_POD_LOG_MAX` 200 lignes, `falco` 200, `portscan`/`origin-drop` 300,
# `imgdrift` 80 images. Deux capteurs rejouent un LOT et non une enveloppe : `pod-logs` marque un
# offset PAR FICHIER de pod dans sa boucle de lecture et ne publie qu'ensuite (le rejeu porte sur tous
# les fichiers du passage), et les registres « déjà signalé » (`vuln`, `yara`, `containerd`) accumulent
# une ligne par constat avant la publication unique de fin.
#
# COMMENT L'ORDRE EST TENU — PAR CONSTRUCTION, PAS PAR CONVENTION. Un capteur n'a PAS les deux gestes
# à sa disposition : il MET EN ATTENTE (`state_stage`, `state_stage_append`, `state_stage_file`), il
# n'écrit pas. Les SEULS points d'écriture sont `spool_write_then_ack` / `spool_publish_then_ack`
# (publient PUIS écrivent) et `plume_exit_nodata`. L'ordre est INTERNE à ces fonctions, donc un
# appelant ne peut pas s'y tromper.
# LA JUSTIFICATION DONNÉE ICI POUR `plume_exit_nodata` — « rien n'a été publié, donc rien n'est
# acquitté, donc les marqueurs en attente sont sans danger » — ÉTAIT FAUSSE POUR UNE MOITIÉ DES
# MARQUEURS, et `S36` l'a refermée : elle ne vaut que pour un marqueur calculé À PARTIR de ce qui a
# été lu. Un marqueur qui ne doit rien à la lecture (offset pris sur la taille, repère daté, instant
# du passage) est en attente AVANT elle, et cette sortie l'écrit alors même que la lecture a échoué.
# Le raisonnement complet, et la porte de sortie qui manquait, sont à `plume_exit_nodata`. C'est la forme déjà retenue côté Windows (`Stage-Watermark` / `Complete-Run`)
# et côté binaire d'agent (`CursorStore::save`, appelé seulement après ship+ack).
# `.github/scripts/check_watermark_follows_publication.py` refuse toute écriture directe d'un marqueur
# hors de cette bibliothèque, et NOMME le capteur fautif.
# =================================================================================================

# Marqueurs MIS EN ATTENTE pendant le passage. Trois formes, parce que les capteurs marquent leur
# progression de trois façons — une VALEUR (offset, curseur, horodatage), une LIGNE ajoutée à un
# registre, un FICHIER entier (base de référence, ou repère daté relu en `find -newer`).
# Séparateur : tabulation + fin de ligne. Une valeur de marqueur n'en contient jamais (offsets,
# curseurs journald, dates ISO, sommes) ; le commit ignore les enregistrements malformés plutôt que
# d'écrire n'importe où.
_plume_ack_valeurs=""
_plume_ack_lignes=""
_plume_ack_fichiers=""
_PLUME_TAB=$(printf '\t')

# state_stage <fichier> <valeur> — met en attente une VALEUR de marqueur. N'écrit rien.
state_stage() {
  _plume_ack_valeurs="$_plume_ack_valeurs$1$_PLUME_TAB$2
"
}

# state_stage_append <registre> <ligne> — met en attente l'AJOUT d'une ligne à un registre. N'écrit rien.
state_stage_append() {
  _plume_ack_lignes="$_plume_ack_lignes$1$_PLUME_TAB$2
"
}

# state_stage_file <temporaire> <fichier-d-état> — met en attente le REMPLACEMENT d'un fichier d'état
# par un temporaire DÉJÀ constitué (base de référence, repère `touch`é dont c'est la DATE qui compte —
# le renommage la préserve). Le temporaire doit être sur le même système de fichiers que la cible.
state_stage_file() {
  _plume_ack_fichiers="$_plume_ack_fichiers$1$_PLUME_TAB$2
"
}

# state_marker_seen <registre> <ligne> — vrai si la ligne est DÉJÀ dans le registre sur disque, OU
# déjà mise en attente ce passage. Remplace le `grep -qxF <registre>` que faisaient les capteurs à
# registre : depuis que l'ajout est DIFFÉRÉ, interroger le seul fichier ferait re-signaler deux fois
# le même constat DANS LE MÊME passage.
state_marker_seen() {
  grep -qxF "$2" "$1" 2>/dev/null && return 0
  case "$_plume_ack_lignes" in *"$1$_PLUME_TAB$2
"*) return 0 ;; esac
  return 1
}

# plume_registre_illisible <registre> — vrai quand le registre « déjà signalé » EXISTE mais ne peut
# pas être interrogé.
#
# S36, RANG « DU BRUIT AU LIEU DU SILENCE ». `state_marker_seen` ne peut pas distinguer ses deux
# échecs : `grep` rend 1 quand la ligne n'y est pas (le cas normal) et >=2 quand le fichier n'a pas pu
# être lu — les deux se lisent « jamais signalé ». Un registre devenu illisible fait donc RE-SIGNALER
# tout ce qu'il contenait : pour `yara` c'est un événement `severity 4` par correspondance déjà vue,
# pour `vuln` une CVE `CRITICAL` par ligne. L'exploitant reçoit une vague d'alertes maximales qui ne
# décrivent AUCUN fait nouveau, et c'est ainsi qu'une famille d'alertes cesse d'être lue.
#
# CE QUI N'EST SURTOUT PAS FAIT : se taire. Ne rien émettre quand le registre est illisible
# transformerait ce faux positif en angle mort — une correspondance RÉELLEMENT nouvelle disparaîtrait
# avec les re-signalements. Le lot part donc en entier, et ce qui change est qu'il est ACCOMPAGNÉ :
# l'appelant avoue que son registre n'était pas interrogeable, de sorte qu'un lot volumineux se lise
# pour ce qu'il est. Un registre ABSENT n'est PAS ce cas : c'est le premier passage, et il est normal.
# Le test est en O(1) — un octet — et non un balayage : il est fait une fois par passage, et un
# registre de plusieurs milliers de lignes ne doit pas se payer deux fois.
plume_registre_illisible() {
  [ -e "$1" ] || return 1          # absent = premier passage, cas nominal
  head -c 1 "$1" >/dev/null 2>&1 && return 1
  return 0
}

# Écrit les marqueurs en attente. PRIVÉE : les seuls appelants sont les publications qui acquittent
# et `plume_exit_nodata`. L'appeler ailleurs, c'est réintroduire le défaut.
_plume_ack_commit() {
  while IFS="$_PLUME_TAB" read -r _ac_f _ac_v; do
    [ -n "${_ac_f:-}" ] || continue
    state_write "$_ac_f" "$_ac_v"
  done <<EOF
$_plume_ack_valeurs
EOF
  while IFS="$_PLUME_TAB" read -r _ac_f _ac_l; do
    [ -n "${_ac_f:-}" ] || continue
    printf '%s\n' "$_ac_l" >> "$_ac_f"
  done <<EOF
$_plume_ack_lignes
EOF
  while IFS="$_PLUME_TAB" read -r _ac_t _ac_f; do
    [ -n "${_ac_t:-}" ] || continue
    [ -n "${_ac_f:-}" ] || continue
    mv -f "$_ac_t" "$_ac_f"
  done <<EOF
$_plume_ack_fichiers
EOF
  _plume_ack_valeurs=""
  _plume_ack_lignes=""
  _plume_ack_fichiers=""
}

# spool_write_then_ack <basename> <content> [nl] — PUBLIE l'enveloppe (voie durable de S27), PUIS
# écrit les marqueurs mis en attente. L'ordre est ici, et nulle part ailleurs.
spool_write_then_ack() {
  spool_write "$1" "$2" "${3:-}"
  _plume_ack_commit
}

# spool_publish_then_ack <tempfile> <basename> — idem pour un temporaire déjà rempli par l'appelant.
spool_publish_then_ack() {
  spool_publish_file "$1" "$2"
  _plume_ack_commit
}

# json_escape <str> — escape a string for embedding inside a JSON "..." literal.
# Reproduces the sed the collectors use now (backslash then double-quote), and
# ADDS two hardening passes that only affect INVALID input :
#   1. iconv -c utf-8->utf-8 drops invalid UTF-8 bytes (best-effort : if iconv is
#      absent the `|| cat` fallback passes the bytes through untouched) so a single
#      bad byte can't corrupt the whole batch's JSON.
#   2. tr -d '\000-\037' strips C0 control chars (raw controls are invalid inside a
#      JSON string) — the collectors that already stripped controls are unchanged;
#      those that did not had a latent invalid-JSON bug this closes.
# For valid, control-free input the output is byte-identical to the old sed-only form.
json_escape() {
  printf '%s' "$1" \
    | { iconv -c -f utf-8 -t utf-8 2>/dev/null || cat; } \
    | tr -d '\000-\037' \
    | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# emit_event <events-fragment>
# Build the standard kind:events envelope around one-or-more already-built event
# object(s). ts/host come from plume_init (ts is numeric — quoted-numeric guard :
# the fragment supplies its own inner ts). No trailing newline (matches the
# `printf '{...}' > tmp` form) — pass the result through `spool_write ... nl` for
# the few collectors whose envelope printf ended in \n.
emit_event() {
  printf '{"ts":%s,"host":"%s","kind":"events","events":[%s]}' "$ts" "$host" "$1"
}

# heartbeat <source> <message> <fields-json> [severity] [ts]
# Print (to stdout) the shared health event OBJECT :
#   {"ts":<ts>,"source":"<source>","category":"health","severity":<sev>,"message":"<msg>","fields":<fields>}
# byte-identical to the hand-written dead-man's-switch heartbeats. Default severity
# 0, default ts=$ts. The message is json_escaped (identity for the fixed literals
# the collectors pass). Callers that ship a standalone health file wrap this with
# `spool_write "<source>-health-$ts.json" "$(emit_event "$(heartbeat ...)")" nl` ;
# accumulator collectors append it to their $events string.
heartbeat() {
  _hb_sev="${4:-0}"
  _hb_ts="${5:-$ts}"
  printf '{"ts":%s,"source":"%s","category":"health","severity":%s,"message":"%s","fields":%s}' \
    "$_hb_ts" "$1" "$_hb_sev" "$(json_escape "$2")" "$3"
}

# kctl [args...] — resolve kubectl-vs-`k3s kubectl` once and run it.
# Matches the `KC="kubectl"; command -v kubectl || KC="k3s kubectl"` idiom the
# collectors use (prefer a standalone kubectl, else k3s' embedded one). Honours
# PLUME_KUBECTL as an explicit override (e.g. "microk8s kubectl").
kctl() {
  if [ -n "${PLUME_KUBECTL:-}" ]; then
    $PLUME_KUBECTL "$@"
  elif command -v kubectl >/dev/null 2>&1; then
    kubectl "$@"
  else
    k3s kubectl "$@"
  fi
}

# =================================================================================================
# DISPONIBILITÉ DU CAPTEUR — « un capteur qui ne peut pas collecter doit le DIRE »
# -------------------------------------------------------------------------------------------------
# LE DÉFAUT QUE CECI FERME (mesuré le 2026-08-01, VM Ubuntu 24.04 Server fraîche, 2 vCPU / 2 Gio) :
# `auditd.sh` faisait `[ -r "$LOG" ] || exit 0`. Sur une Ubuntu Server, auditd n'est PAS installé, donc
# `/var/log/audit/audit.log` n'existe pas, donc le capteur sortait en SUCCÈS sans rien émettre. Vu du
# SOC, RIEN ne distingue « ce capteur ne PEUT PAS fonctionner » de « il ne s'est rien passé ». C'est la
# même famille que les défauts de requête corrigés cette semaine : un composant CONNAÎT son incapacité
# et ne la dit pas. Le silence est ici la pire réponse possible, parce qu'il est indiscernable du calme.
#
# LA PARTITION (fermée) — tout arrêt anticipé d'un collecteur est EXACTEMENT l'un de ces trois cas :
#   (I)   INCAPACITÉ  : un PRÉREQUIS de la collecte est absent sur cet hôte (binaire, fichier/répertoire
#                       source, identifiant/réglage obligatoire, sous-système ou objet absent, endpoint
#                       injoignable). Le capteur ne produira RIEN tant qu'un opérateur n'agit pas.
#                       -> `plume_unavailable` : DOIT le dire. C'est le défaut ci-dessus.
#   (II)  DÉSACTIVÉ   : un opérateur l'a délibérément coupé (interrupteur `PLUME_*`). État connu, mais
#                       une unit ACTIVE dont le capteur est coupé reste une surprise pour l'analyste.
#                       -> `plume_disabled` : DOIT le dire, à sévérité plus basse.
#   (III) RIEN DE NEUF: le capteur a tourné NORMALEMENT, le curseur n'a pas bougé / le résultat est vide.
#                       -> `plume_exit_nodata` : silence LÉGITIME (le battement de santé le couvre déjà,
#                       et l'IHM sait déjà dire « calme »). Aucun event, aucun octet en plus.
# Seuls (I) et (II) sont des MENSONGES. (III) est honnête. La partition est fermée : il n'existe pas de
# quatrième raison de s'arrêter tôt, donc classer est TOUJOURS possible.
#
# POURQUOI UN CAPTEUR ÉCRIT DEMAIN EST COUVERT PAR CONSTRUCTION — ce n'est PAS une énumération de
# capteurs (une liste pourrit ; le prochain capteur n'y serait pas). Deux jambes :
#   1. La SEULE façon de sortir tôt d'un collecteur est l'une de ces trois FONCTIONS, qui portent chacune
#      leur `exit 0`. Un auteur qui veut sortir doit en CHOISIR une, donc CLASSER.
#   2. `.github/scripts/check_collector_exit_is_classified.py` interdit tout `exit 0` NU dans un
#      collecteur suivi. Le défaut d'origine (`|| exit 0`) n'est plus une chose qu'on PEUT écrire : elle
#      ne franchit pas la CI. Le mauvais défaut — le silence — n'est plus disponible.
#
# ON RÉUTILISE L'EXISTANT, ON N'INVENTE RIEN : la catégorie CIM `config` est déjà l'auto-report de
# configuration du collecteur (docs/CIM.md §2b, « transparence des filtres ») — `web`, `nft`, `portscan`,
# `auditd`, `conntrack`, `mail`, `pod-logs` en émettent déjà. La disponibilité EST de la configuration
# observée. Aucune nouvelle catégorie, aucun champ cœur, aucun changement de daemon.
#
# VISIBILITÉ — ce qui est MESURÉ, et ce qui ne l'est PAS (lisez les deux, la nuance compte).
# Émettre ne suffit pas à VOIR : un event `config` de plus rend même la source « fraîche » dans l'IHM.
# MESURÉ le 2026-08-01 sur l'instance de test, après ingestion d'un aveu d'indisponibilité `auditd` :
# `/api/sources` rendait bien `status: "frais"` pour auditd. Émettre SANS alerter masquerait donc le
# problème. La règle livrée `config.d/rules/catalog/de-collector-unavailable.json` lève donc une ALERTE
# sur ces events — VÉRIFIÉ de bout en bout : l'alerte se lève (« capteur indisponible : 1 > 0 », sév. 2).
#
# CE QUI N'EST PAS COUVERT, et il faut le dire : cette alerte est GLOBALE, elle ne fait PAS basculer la
# source fautive en « dégradé ». `web/freshness.js:80` bascule bien un feed en `warn` dès
# `active_alerts > 0`, MAIS le daemon calcule `active_alerts` en cherchant des jetons `source=<nom>`
# DANS LE TEXTE DE LA REQUÊTE de la règle (`daemon/src/handlers/freshness.rs:270`, « limite assumée »).
# Une règle générique — qui est précisément ce qu'on veut, pour ne pas énumérer les capteurs — ne porte
# aucun jeton `source=`, donc ne s'impute à aucun feed : mesuré `active_alerts: 0` sur auditd malgré
# l'alerte levée. Fermer cet écart demande d'imputer l'alerte à la source des ÉVÉNEMENTS MATCHÉS plutôt
# qu'au texte de la règle — un changement côté daemon, hors du périmètre de ce correctif.
# En l'état, l'opérateur voit l'angle mort par l'ALERTE et par la requête ci-dessous, pas par la pastille :
#   search category=config collect_status=unavailable | table host, source, reason, detail
#
# DÉDUP : clé = source + empreinte du contenu + BUCKET HORAIRE. Le daemon fait `INSERT OR IGNORE` sur
# `dedup` (cf. config.d/cim/cim.v1.json). Un capteur cadencé à 60 s qui reste incapable écrit donc
# ~24 lignes/jour au lieu de 1440, tout en RÉ-AFFIRMANT son incapacité chaque heure — sans quoi une
# dédup purement de contenu ferait vieillir l'aveu jusqu'à le rendre invisible.
#
# VOCABULAIRE FERMÉ de `reason` (requêtable, pas de la prose) :
#   missing-dependency · missing-source · missing-config · subsystem-absent · unreachable · disabled
#
# ROBUSTESSE : ces fonctions ne doivent JAMAIS transformer un skip en échec d'unit. `plume_init` est
# rappelé si besoin (certains collecteurs sortent AVANT de l'avoir appelé), et l'écriture du spool est
# best-effort (`|| true`) : si le spool est absent/non inscriptible, on sort quand même 0.
# =================================================================================================

# plume_report_availability <source> <status> <reason> <detail> <severity> — n'exite PAS (usage interne).
# CE QUE CETTE CLÉ N'A PAS BESOIN DE PORTER, ET POURQUOI (2026-08-02). `_av_dd` ne contient AUCUN
# élément propre à la machine : deux hôtes auxquels il manque le MÊME prérequis produisent la MÊME clé.
# C'était une perte SILENCIEUSE — `event.dedup` était UNIQUE au niveau de la BASE du central et
# l'ingestion fait `INSERT OR IGNORE` : le 2e hôte était jeté sans un mot, et c'est l'aveu « capteur
# aveugle » lui-même qui disparaissait. MESURÉ en faisant tourner les 36 capteurs livrés sur deux hôtes :
# 36 clés chacun, dont 26 IDENTIQUES ; 78 événements envoyés, 52 stockés, 26 perdus (39 lignes pour le
# 1er hôte, 13 pour le 2e). Le correctif N'EST PAS ici : le central CLOISONNE `event.dedup` par l'hôte de
# la ligne à l'écriture (`dedup_scoped_by_host`, daemon/src/ingest/store.rs), là où l'hôte est déjà connu
# et ATTESTÉ (jeton lié). Corriger les >=29 formes de clé des 30 fichiers émetteurs, en 6 langages, aurait laissé le
# prochain capteur — y compris celui d'un client, via `custom.sh` — refaire la même faute.
# CE QUI RESTE EXIGÉ D'UNE CLÉ ÉMETTEUR : être STABLE et DÉTERMINISTE pour un même événement — c'est elle
# qui absorbe les réémissions du spool (at-least-once). Le bucket horaire ci-dessous joue ce rôle.
plume_report_availability() {
  [ -n "${SPOOL:-}" ] || plume_init
  _av_fields=$(printf '{"type":"collector-availability","collector":"%s","collect_status":"%s","reason":"%s","detail":"%s"}' \
    "$(json_escape "$1")" "$(json_escape "$2")" "$(json_escape "$3")" "$(json_escape "${4:-}")")
  _av_dd="avail-$1-$(printf '%s' "$_av_fields" | cksum | cut -d' ' -f1)-$((ts / 3600))"
  _av_ev=$(printf '{"ts":%s,"source":"%s","category":"config","severity":%s,"message":"%s","dedup":"%s","fields":%s}' \
    "$ts" "$(json_escape "$1")" "$5" "$(json_escape "capteur $1 $2 : $3 — ${4:-}")" "$_av_dd" "$_av_fields")
  # S36 — LE NOM DE L'ENVELOPPE PORTE L'EMPREINTE DU CONTENU, ET PAS SEULEMENT LA SECONDE. Il valait
  # `config-availability-<source>-<ts>.json` : deux aveux DISTINCTS emis par la meme source pendant le
  # meme passage ecrivaient le MEME fichier, et le second EFFACAIT le premier. Mesure sur un capteur
  # d'integrite exerce contre des bouchons : deux aveux emis, UN SEUL fichier dans le spool. Le
  # dedoublonnage du central n'y pouvait rien — il ne voit que ce qui lui est expedie, et l'un des deux
  # n'a jamais quitte l'hote. C'etait un aveu perdu par un aveu, c'est-a-dire le defaut meme que ce
  # canal existe pour empecher. `_av_dd` porte deja l'empreinte du contenu et le seau horaire : un
  # aveu REPETE a l'identique garde donc le meme nom (aucun fichier de plus), deux aveux DIFFERENTS en
  # prennent deux.
  spool_write "config-availability-$1-$ts-${_av_dd#avail-$1-}.json" "$(emit_event "$_av_ev")"
}

# plume_unavailable <source> <reason> <detail> — cas (I) : PRÉREQUIS ABSENT. Émet puis sort 0.
# sévérité 2 (warning) : ce n'est pas une attaque, c'est un TROU DE COUVERTURE — il doit se voir.
plume_unavailable() {
  plume_report_availability "$1" unavailable "$2" "${3:-}" 2 2>/dev/null || true
  exit 0
}

# plume_disabled <source> <detail> — cas (II) : coupé par un interrupteur opérateur. Émet puis sort 0.
# sévérité 1 (notice) : c'est un CHOIX, pas une panne ; mais il reste dit, jamais deviné.
# ZÉRO APPELANT AUJOURD'HUI, et c'est mesuré : le 2026-08-01, aucun des 37 capteurs livrés n'a
# d'interrupteur on/off — les deux seuls composants qui en portent un (`respond.sh`,
# `engagement-adapter.sh`) sont des ENFORCERS, hors partition. Cette fonction n'est donc pas du code
# mort par négligence : sans elle, l'auteur du premier capteur à interrupteur n'aurait AUCUNE primitive
# correcte à appeler, et la garde de CI lui refuserait le `exit 0` nu — on l'aurait poussé à mentir en
# rangeant son cas en « rien de neuf ». Une partition à laquelle il manque un cas ne partitionne rien.
plume_disabled() {
  plume_report_availability "$1" disabled disabled "${2:-}" 1 2>/dev/null || true
  exit 0
}

# plume_exit_nodata — cas (III) : rien de neuf à remonter. Sortie 0 NUE, volontairement sans event :
# zéro octet de plus, comportement inchangé. La fonction n'existe QUE pour porter un NOM : c'est ce nom
# qui prouve à la relecture (et à la CI) que le silence est ici un CHOIX et non un oubli.
#
# ELLE ÉCRIT LES MARQUEURS EN ATTENTE, ET C'EST LE SEUL AUTRE ENDROIT QUI LE FASSE (S30). Sans ce
# commit, un capteur incrémental qui ne trouve rien à signaler ne mémoriserait jamais sa progression
# et re-scannerait la même tranche indéfiniment (`clamav`/`yara` relisent leur liste par
# `find -newer`).
#
# L'HYPOTHÈSE QUE `S30` AVAIT ÉCRITE ICI ÉTAIT VRAIE SUR UNE MOITIÉ DU DOMAINE SEULEMENT, ET C'EST
# ELLE QUI A ROUVERT LE DÉFAUT QUE `S30` FERMAIT (S36). Elle disait : « sortir par ici veut dire
# qu'AUCUNE enveloppe n'a été publiée, donc les marqueurs en attente n'acquittent RIEN ».
#   VRAI pour un marqueur CALCULÉ À PARTIR DE CE QUI A ÉTÉ LU. Un curseur journald tiré de la
#   dernière ligne obtenue n'existe pas tant que la lecture n'a pas abouti : il n'y a rien à mettre
#   en attente, donc rien à écrire, donc rien à perdre.
#   FAUX pour un marqueur dont la valeur ne doit RIEN à la lecture — un offset pris sur la TAILLE du
#   fichier, un repère daté, l'instant du passage. Celui-là est en attente AVANT que la lecture
#   n'aboutisse. Si elle échoue, le capteur n'a effectivement rien à signaler, il sort par ici, et
#   cette sortie ACQUITTE une tranche qui n'a jamais été publiée. C'est mot pour mot la perte
#   SILENCIEUSE que `S30` existait pour empêcher, réintroduite par la porte de sortie.
#
# CE QUI EST VRAI, ET C'EST LA SEULE FORMULATION À REPRENDRE : cette fonction ACQUITTE, et elle n'a
# le droit d'être atteinte que lorsque la source a été LUE et s'est révélée vide. « La lecture n'a
# pas abouti » n'est pas une sortie propre : c'est un ÉCHEC, il se dit, et il n'acquitte rien. C'est
# `plume_lecture_echouee`, juste en dessous.
plume_exit_nodata() { _plume_ack_commit; exit 0; }

# =================================================================================================
# « LA SOURCE ÉTAIT VIDE » N'EST PAS « JE N'AI PAS PU LA LIRE » (S36)
# -------------------------------------------------------------------------------------------------
# LE DÉFAUT. Un capteur incrémental met son marqueur en attente, tente sa lecture, et route l'échec
# vers la même branche que le vide : `tail … 2>/dev/null || true`, puis « si c'est vide, rien à
# signaler ». Les deux mots d'un tube qui a échoué et d'une source réellement calme sont le même mot
# — la chaîne vide — et la sortie propre acquitte alors un offset que rien n'a jamais publié. Le
# passage suivant repart APRÈS la tranche perdue : les événements ne reviendront jamais, et rien ne
# les compte, puisque rien ne compte ce qui manque.
#
# CE N'EST PAS UN QUATRIÈME CAS DE LA PARTITION. C'est le cas (I) — INCAPACITÉ — survenu APRÈS la
# mise en attente de marqueurs : même vocabulaire de `reason`, même sévérité, même canal d'aveu, et
# donc la même alerte livrée. Ce qu'il y a EN PLUS est une seule garantie : JETER ce qui est en
# attente, pour que la sortie ne puisse pas acquitter ce qu'elle n'a pas publié. La partition reste
# fermée à trois cas.
#
# LA CAUSE SE DIT DANS LE VOCABULAIRE FERMÉ DÉJÀ POSÉ (`PLUME_CAUSES_MESURE`, S32/S33) et non en
# prose : `source_absente`, `source_refusee`, `source_illisible`, `forme_inconnue`. Un capteur qui
# lit un CHEMIN n'a pas à choisir — `plume_cause_lecture` dérive la cause de l'état du fichier.
#
# DEUX PORTES, PARCE QU'IL Y A DEUX SITUATIONS ET QU'UNE SEULE N'AURAIT PAS COUVERT LES DEUX :
#   `plume_lecture_echouee`  — la lecture ratée était TOUTE la collecte du passage : on jette, on
#                              avoue, on sort. Elle porte son propre `exit`, comme les trois autres.
#   `plume_lecture_partielle`— le capteur a autre chose à publier (une autre source, un battement de
#                              santé dont le silence lèverait une alerte MUET). Il avoue et
#                              CONTINUE ; ce qui protège la tranche est qu'il n'a PAS mis en attente
#                              le marqueur de la lecture ratée. C'est la forme d'`integrity`.
# =================================================================================================

# _plume_ack_abandonner — JETTE les marqueurs mis en attente, et les temporaires qu'ils désignaient.
# PRIVÉE. Le seul appelant qui sort le fait juste après, si bien que remettre les variables à vide
# pourrait passer pour superflu : c'est écrit quand même, parce qu'une garde peut alors MESURER la
# propriété (« après un échec de lecture, plus rien n'est en attente ») au lieu de la supposer.
_plume_ack_abandonner() {
  while IFS="$_PLUME_TAB" read -r _ab_t _ab_f; do
    [ -n "${_ab_t:-}" ] || continue
    rm -f "$_ab_t"
  done <<EOF
$_plume_ack_fichiers
EOF
  _plume_ack_valeurs=""
  _plume_ack_lignes=""
  _plume_ack_fichiers=""
}

# plume_lecture_echouee <capteur> <cause> <détail> — cas (I) survenu pendant la collecte. Jette les
# marqueurs en attente, avoue, sort 0. À appeler à l'endroit exact où le code de retour de la
# lecture est encore lisible : un `| grep` ou un `|| true` interposé le remplace par le sien, et
# c'est précisément ainsi que l'échec s'était déguisé en source vide.
plume_lecture_echouee() {
  _plume_ack_abandonner
  plume_report_availability "$1" unavailable missing-source \
    "LECTURE DE LA SOURCE IMPOSSIBLE ($(plume_cause_fermee "$2")) : aucun marqueur acquitté, la tranche sera relue au passage suivant. ${3:-}" \
    2 2>/dev/null || true
  exit 0
}

# plume_lecture_partielle <capteur> <cause> <détail> — même distinction, capteur PARTIELLEMENT
# aveugle : il publie ce qu'il a et rend la main. Elle n'écrit ni ne jette rien — c'est l'appelant
# qui, en s'abstenant de mettre le marqueur en attente, garantit que la tranche sera relue.
plume_lecture_partielle() {
  plume_report_availability "$1" unavailable missing-source \
    "LECTURE PARTIELLE ($(plume_cause_fermee "$2")) : le marqueur correspondant N'AVANCE PAS, la tranche sera relue au passage suivant. ${3:-}" \
    2 2>/dev/null || true
}

# ====================================================================================================
# LE SECRET NE PASSE PAS PAR argv (P5.5-a).
#
# CE QUI ÉTAIT CASSÉ. Chaque expédition posait le jeton en ARGUMENT de curl :
# `curl -H "Authorization: Bearer $PLUME_TOKEN" …` (idem `-u user:pass`). Un argument de processus est
# PUBLIC : le noyau l'expose dans /proc/<pid>/cmdline, lisible par tout utilisateur local tant que /proc
# n'est pas monté `hidepid`. MESURÉ le 2026-08-02 (instrument validé — on vérifie d'abord que
# /proc/<pid>/cmdline EXISTE, sinon un « 0 » n'est pas une absence de fuite mais une absence de mesure) :
#   forme actuelle  -> argv de 101 octets : `curl -sS --max-time 8 -H Authorization: Bearer <JETON> …`
#                      le jeton y figure VERBATIM.
#   `curl -K -`     -> argv : `curl -K -`. Le jeton n'y figure PAS.
# La même argv part aussi dans journald (`_CMDLINE`) dès que le processus émet une ligne de log, et,
# sous Windows, dans les événements 4688 / Sysmon ID 1 — c'est-à-dire dans ce que Plume COLLECTE
# lui-même (cf. `collectors/windows/README.md`, mesuré le même jour).
#
# LA FORME DÉRIVÉE. On ne « masque » pas un argument : on ne l'écrit pas. Les options PORTEUSES DE
# SECRET sont émises sur l'ENTRÉE STANDARD de curl, au format de ses fichiers de configuration ; le
# reste (URL, timeouts, corps) reste en argv, où il n'y a rien à cacher. Un appelant ne peut donc plus
# « oublier » d'appliquer la protection au bon endroit : il n'y a plus qu'un seul endroit où l'auth
# s'écrit, et il n'est pas argv.
#
# LIMITE DÉCLARÉE : un secret contenant un SAUT DE LIGNE ne survivrait pas à ce format (une option par
# ligne). Aucun jeton Plume n'en contient (hex de 32 octets) et un `EnvironmentFile` systemd ne sait
# déjà pas en porter — la contrainte n'est donc pas nouvelle, elle est seulement dite.
# ====================================================================================================

# plume_curl_auth_stdin — écrit sur STDOUT la configuration curl portant l'authentification, à donner à
# `curl -K -`. PLUME_TOKEN (Bearer) prioritaire, sinon PLUME_USER+PLUME_PASS (basic), sinon RIEN (config
# vide : curl se comporte comme sans `-K`). Les valeurs sont échappées pour le format de config curl
# (`\` et `"` dans une chaîne entre guillemets).
plume_curl_auth_stdin() {
  if [ -n "${PLUME_TOKEN:-}" ]; then
    printf 'header = "Authorization: Bearer %s"\n' "$(plume_curlcfg_escape "$PLUME_TOKEN")"
  elif [ -n "${PLUME_USER:-}" ] && [ -n "${PLUME_PASS:-}" ]; then
    printf 'user = "%s:%s"\n' "$(plume_curlcfg_escape "$PLUME_USER")" "$(plume_curlcfg_escape "$PLUME_PASS")"
  fi
}

# plume_curlcfg_escape <valeur> — échappe `\` puis `"` pour une chaîne entre guillemets d'un fichier de
# config curl. L'ordre importe : les antislashs D'ABORD, sinon on ré-échapperait ceux qu'on vient de poser.
plume_curlcfg_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# plume_curlcfg_header_auth <secret> — config curl portant un Bearer ARBITRAIRE (API TIERCE : Cloudflare
# & co, dont le secret n'est pas PLUME_TOKEN). Même règle, même raison : un secret ne s'écrit pas en argv.
plume_curlcfg_header_auth() {
  printf 'header = "Authorization: Bearer %s"\n' "$(plume_curlcfg_escape "$1")"
}

# ====================================================================================================
# UNE MESURE D'HÔTE QUI ÉCHOUE N'EST PAS PUBLIÉE COMME UN ZÉRO (S33)
# ----------------------------------------------------------------------------------------------------
# LE DÉFAUT. Un capteur qui n'arrive pas à lire une source d'environnement publiait quand même un
# nombre — et ce nombre était le plus CALME de sa série. `mem_pct` valait 0 quand `/proc/meminfo` ne
# portait plus la clé cherchée, `disk_root_pct` valait 0 quand `df` échouait (son code de retour était
# avalé par le tube vers `awk`), `mem_slab_mb` valait 0 sur tout noyau qui n'expose pas `SUnreclaim`, et
# le débit réseau valait 0 dès que le nom de l'interface sortait du motif codé en dur.
#
# CE QUE CE ZÉRO COÛTE, ET POURQUOI IL EST PIRE QU'UNE ABSENCE. Ces séries ARMENT des règles à seuil
# (« mémoire > 90 % », « disque / > 90 % », « fuite slab > 2,5 Go », « CPU > 90 % »). Une règle dont
# l'entrée vaut 0 n'est pas en retard : elle est STRUCTURELLEMENT INERTE, et rien ne le dit. Un tableau
# de bord y lit « rien à signaler » précisément là où il n'y a plus aucune mesure.
#
# LA RÈGLE, ET ELLE N'EST PAS NOUVELLE : `resources.sh` la tenait DÉJÀ pour la température — « pas de
# sonde thermique -> on NE l'émet PAS (sinon faux 0 °C trompeur) ». Ces fonctions ne font que la rendre
# disponible aux autres mesures, et exigible par une garde plutôt que par la relecture.
#   1. la mesure DISPARAÎT de l'enveloppe (jamais un nombre inventé) ;
#   2. un AVEU l'accompagne, nommant la clé et la CAUSE. L'absence seule ne distingue pas « la lecture a
#      échoué » d'un relevé manqué ; l'aveu seul laisserait le zéro en place. Il faut les deux.
#
# ON RÉUTILISE LE CANAL D'AVEU EXISTANT, ON N'EN CRÉE PAS UN SECOND. `plume_report_availability` porte
# déjà le vocabulaire fermé de `reason`, la clé de dédoublonnage horaire, et — c'est le point — la règle
# livrée `config.d/rules/catalog/de-collector-unavailable.json` ALERTE déjà dessus. Une mesure d'hôte
# perdue lève donc une alerte au lieu de se lire comme du calme. Aucune métrique nouvelle n'est inventée
# pour porter l'indicateur : ce serait une série de plus par mesure, et le SOC a déjà où regarder.
# C'est la forme que `integrity.sh` emploie pour sa couverture partielle — aveu, puis on continue.
#
# LES CAUSES SONT LES MÊMES MOTS QUE CÔTÉ DÉMON (`daemon/src/mesure_environnement.rs`, S32). Un
# vocabulaire par langage aurait fait diverger deux moitiés du même produit ; ces quatre clés sont
# celles-là, moins `aucune` qui ne décrit pas une absence.
PLUME_CAUSES_MESURE="source_absente source_refusee source_illisible forme_inconnue"

# plume_cause_source <chemin> — traduit l'état d'une source de fichier en une clé de l'ensemble fermé,
# ou la chaîne VIDE quand le fichier est là et lisible (l'échec vient alors de son CONTENU, pas de son
# accès : c'est `forme_inconnue`, et c'est `plume_cause_mesure` qui le conclut).
plume_cause_source() {
  if [ ! -e "$1" ]; then
    printf 'source_absente'
  elif [ ! -r "$1" ]; then
    printf 'source_refusee'
  fi
}

# plume_cause_mesure <chemin> — la cause à retenir quand une mesure tirée de <chemin> n'a pas pu être
# établie : l'état du FICHIER s'il explique l'échec, `forme_inconnue` sinon. `S28` a montré que ce
# dernier cas est celui qui se perd le plus facilement — un fichier présent dont le format a changé
# était ignoré en silence, et l'appelant concluait comme si de rien n'était.
plume_cause_mesure() {
  _pcm=$(plume_cause_source "$1")
  if [ -n "$_pcm" ]; then printf '%s' "$_pcm"; else printf 'forme_inconnue'; fi
}

# plume_cause_fermee <mot> — ramène <mot> dans l'ensemble fermé, `forme_inconnue` sinon. La borne de
# cardinalité était écrite en ligne dans `plume_mesure_absente` ; elle est ici parce que `S36` lui a
# donné un second appelant, et que deux endroits qui contraignent le même vocabulaire divergent.
plume_cause_fermee() {
  case " $PLUME_CAUSES_MESURE " in
    *" $1 "*) printf '%s' "$1" ;;
    *) printf 'forme_inconnue' ;;
  esac
}

# plume_cause_lecture <chemin> — la cause à retenir quand la LECTURE de <chemin> a échoué : l'état du
# fichier s'il l'explique, `source_illisible` sinon — la source est là, elle est ouvrable, et la
# lecture a tout de même lâché (tube coupé, entrée/sortie, fichier remplacé sous le lecteur).
# `plume_cause_mesure` conclut `forme_inconnue` dans ce dernier cas parce qu'elle parle du CONTENU
# d'une mesure ; ici c'est l'ACCÈS qui a lâché, et le vocabulaire fermé portait déjà le mot.
plume_cause_lecture() {
  _pcl=$(plume_cause_source "$1")
  if [ -n "$_pcl" ]; then printf '%s' "$_pcl"; else printf 'source_illisible'; fi
}

# plume_mesure_absente <clé> <cause> <détail> — enregistre qu'une mesure NE SERA PAS publiée, et
# pourquoi. N'émet rien : l'aveu part en UNE fois (cf. `plume_mesures_avouer`), sans quoi un hôte dont
# `/proc` est masqué produirait sept événements par passage pour un seul et même fait.
#
# LA CARDINALITÉ EST BORNÉE ICI. `cause` est CONTRAINTE à l'ensemble fermé — une clé inventée est
# ramenée à `forme_inconnue` plutôt que de devenir une surface libre. Le `détail` (chemin tenté,
# message du système) n'a lui AUCUNE borne : il ne vit que dans le texte de l'aveu, lu par un humain.
plume_mesure_absente() {
  _pma_cause=$(plume_cause_fermee "$2")
  _plume_mesures_absentes="${_plume_mesures_absentes:-}${_plume_mesures_absentes:+ }$1=$_pma_cause"
  _plume_mesures_details="${_plume_mesures_details:-}${_plume_mesures_details:+ ; }$1 ($_pma_cause) : $3"
}

# plume_mesure_est_absente <clé> — vrai si <clé> a été déclarée absente ce passage. Sert aux mesures
# DÉRIVÉES d'une autre (un débit dérive d'un compteur) : dériver d'une mesure manquante ne produit pas
# une valeur, cela propage l'absence.
plume_mesure_est_absente() {
  case " ${_plume_mesures_absentes:-} " in *" $1="*) return 0 ;; esac
  return 1
}

# plume_mesures_resume — le récapitulatif des mesures manquantes (clés=causes, puis détails), pour un
# appelant qui doit composer son propre message — typiquement `plume_unavailable` quand AUCUNE mesure
# n'a pu être prise. Existe pour qu'un capteur n'ait pas à lire les variables internes de cette
# bibliothèque : le jour où leur forme change, un seul endroit bouge.
plume_mesures_resume() {
  printf '%s' "${_plume_mesures_absentes:-aucune} — ${_plume_mesures_details:-}"
}

# plume_mesures_avouer <capteur> — émet l'aveu s'il y a au moins une mesure manquante, et rend la main
# (le capteur n'est pas incapable, il est PARTIELLEMENT aveugle et publie le reste). Sans appelant,
# rien n'est émis : c'est la raison pour laquelle une garde de CI vérifie que le capteur l'appelle.
# Sévérité 2 : ce n'est pas une attaque, c'est un TROU DE COUVERTURE — il doit se voir.
plume_mesures_avouer() {
  [ -n "${_plume_mesures_absentes:-}" ] || return 0
  plume_report_availability "$1" unavailable missing-source \
    "mesures d'hôte NON PUBLIÉES faute de source exploitable ($_plume_mesures_absentes) — une règle à seuil qui les consomme est INERTE tant que c'est le cas. Détail : $_plume_mesures_details" \
    2 2>/dev/null || true
}
