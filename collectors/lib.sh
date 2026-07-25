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
