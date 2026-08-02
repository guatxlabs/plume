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

# spool_write <basename> <content> [nl]
# Atomic, group-readable (0640) publish into $SPOOL — the exact umask/mktemp/chmod/mv
# sequence ~35 collectors inline today. Content is written VERBATIM (printf '%s');
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
  chmod 0640 "$_sw_tmp"
  mv -f "$_sw_tmp" "$SPOOL/$1"
}

# state_write <file> <content>
# Atomic watermark/cursor write : temp-in-same-dir + rename, replacing the
# non-atomic `printf '%s' "$x" > "$WM"` the collectors do today (fixes a torn-write
# window on crash). State files are NEVER shipped, so this changes no spool bytes;
# the file content is byte-identical, only the write is now crash-safe.
state_write() {
  umask 077
  _st_dir=$(dirname "$1")
  _st_tmp=$(mktemp "$_st_dir/.st.XXXXXX")
  printf '%s' "$2" > "$_st_tmp"
  mv -f "$_st_tmp" "$1"
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
  spool_write "config-availability-$1-$ts.json" "$(emit_event "$_av_ev")"
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
plume_exit_nodata() { exit 0; }

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
