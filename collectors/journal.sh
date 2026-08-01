#!/bin/sh
# Capteur Plume : journald -> events auth (sshd/sudo/su). ROOT (via plume-journal.service).
# Dump NDJSON brut (journalctl -o json, 1 objet JSON valide/ligne) dans le spool ;
# la transformation -> table `event` est faite par le daemon (Rust, sûr, sans jq).
# Suivi par curseur journald -> pas de doublon.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
CUR="$STATE/journal.cursor"
if [ -s "$CUR" ]; then
  SEL="--after-cursor=$(cat "$CUR")"
else
  SEL="--since=-15min"
fi
umask 027
tmp=$(mktemp "$SPOOL/.jrnl.XXXXXX")
# shellcheck disable=SC2086  ($SEL = un seul token ; le ';' du curseur reste littéral)
journalctl $SEL -o json --no-pager _COMM=sshd _COMM=sshd-session _COMM=sudo _COMM=su 2>/dev/null > "$tmp" || true
# DEAD-MAN'S-SWITCH — CAS SPÉCIAL : journal.sh shippe du NDJSON BRUT (journal-*.ndjson) routé vers
# /api/ingest/journal, où le daemon FORCE category='auth' en dur -> un battement category=health NE PEUT PAS
# transiter par le .ndjson. On écrit donc une enveloppe kind:events .json SÉPARÉE (journal-health-*.json),
# ramassée par le glob *.json de ship.sh -> /api/ingest (chemin events, où le category est PRÉSERVÉ — le même
# qui fait marcher crowdsec-health). Émis À CHAQUE run, AVANT le garde « aucune ligne auth » -> distingue
# « pas de login (normal) » de « shipper journald mort ». source='journal' est un id COLLECTORS -> connu
# (source_is_known) -> zéro faux « inattendu ». Silence > 25 min = alerte MUET (journal-health, cf. main.rs).
spool_write "journal-health-$ts.json" \
  "$(emit_event "$(heartbeat journal 'journal santé: shipper auth actif' '{"alive":1}')")" nl
if [ ! -s "$tmp" ]; then rm -f "$tmp"; plume_exit_nodata; fi
# nouveau curseur = __CURSOR de la dernière entrée (sans jq)
newcur=$(tail -n1 "$tmp" | grep -oP '"__CURSOR"\s*:\s*"\K[^"]+' || true)
[ -n "$newcur" ] && state_write "$CUR" "$newcur"
chmod 0640 "$tmp"
mv -f "$tmp" "$SPOOL/journal-$(date +%s).ndjson"
