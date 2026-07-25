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
#   MAX=nombre                (défaut 100 ; plafond de lignes/passage, anti-flood)
#   MAXLEN=nombre             (défaut 1000 ; longueur max d'une ligne — monter pour du JSON verbeux
#                              type audit Vault, sinon les champs en fin de ligne sont tronqués)
# Astuce : faire émettre à CMD uniquement le NOUVEAU (ex `journalctl -u x --since -1min`) ; sinon la
# déduplication horaire (source+ligne) évite les doublons d'un `tail` répété.
#
# OPT-IN, ROOT (comme tout collecteur). /etc/plume/inputs.d doit être root-only (l'opérateur a déjà root).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
DIR="${PLUME_INPUTS_DIR:-/etc/plume/inputs.d}"
[ -d "$DIR" ] || exit 0
plume_init
esc() { json_escape "$1"; }
raw=$(mktemp)
for f in "$DIR"/*.input; do
  [ -r "$f" ] || continue
  SOURCE=""; CMD=""; SEVERITY=1; CATEGORY=custom; FILTER=""; MAX=100; MAXLEN=1000
  while IFS='=' read -r k v; do
    case "$k" in
      SOURCE) SOURCE=$v ;; CMD) CMD=$v ;; SEVERITY) SEVERITY=$v ;;
      CATEGORY) CATEGORY=$v ;; FILTER) FILTER=$v ;; MAX) MAX=$v ;; MAXLEN) MAXLEN=$v ;;
    esac
  done < "$f"
  [ -n "$SOURCE" ] && [ -n "$CMD" ] || continue
  sj=$(esc "$SOURCE"); cj=$(esc "$CATEGORY")
  sh -c "$CMD" 2>/dev/null | { if [ -n "$FILTER" ]; then grep -iE "$FILTER" || true; else cat; fi; } | head -n "$MAX" | while IFS= read -r line; do
    [ -n "$line" ] || continue
    em=$(printf '%s' "$line" | cut -c1-"${MAXLEN:-1000}" | tr -d '\000-\037'); em=$(esc "$em")
    dd=$(printf '%s' "$SOURCE$line" | cksum | cut -d' ' -f1)   # dédup source+ligne dans l'heure
    printf '{"ts":%s,"source":"%s","category":"%s","severity":%s,"message":"%s","dedup":"custom-%s-%s"}\n' \
      "$ts" "$sj" "$cj" "${SEVERITY:-1}" "$em" "$dd" "$((ts / 3600))"
  done >> "$raw"
done
if [ ! -s "$raw" ]; then rm -f "$raw"; exit 0; fi
events=$(paste -sd, "$raw"); rm -f "$raw"
spool_write "custom-$ts.json" "$(emit_event "$events")"
