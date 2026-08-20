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
# ----------------------------------------------------------------------------------------------------
# MINIMISATION DE CE QU'ON EXPÉDIE (P5.5-b).
#
# `journalctl -o json` rend TOUT ce que journald a stocké sur chaque entrée. Le daemon, lui, n'en lit
# que NEUF champs (`ingest_journal_lines` : __REALTIME_TIMESTAMP, __CURSOR, _COMM, MESSAGE, PRIORITY,
# _PID, _UID, _SYSTEMD_UNIT, _HOSTNAME). MESURÉ le 2026-08-02 sur 200 entrées réelles `_COMM=sudo|su|
# sshd|sshd-session` : 32 champs distincts émis, 31-32 par entrée, 285 223 octets — dont 23 champs
# JAMAIS lus, expédiés sur le réseau et écrits dans le spool pour rien.
#
# CE N'EST PAS QU'UN VOLUME. `_CMDLINE` fait partie des champs jamais lus : c'est l'ARGV COMPLÈTE du
# processus émetteur. Pour `_COMM=sudo`, c'est la ligne de commande sudo, secrets compris. MESURÉ le
# même jour : un leurre passé via `sudo env PLUME_TOKEN=<leurre> …` ressort dans DEUX champs —
# `_CMDLINE` (expédié + spoolé, jamais lu) et `MESSAGE` (lu, donc STOCKÉ en base). La restriction
# ci-dessous ferme le premier ; le second est fermé en amont, en ne mettant plus jamais un secret sur
# une ligne de commande (P5.5-a : `plume_curl_auth_stdin`, et la doc d'installation qui ne le montre plus).
#
# APRÈS restriction, MÊME protocole : 13 champs distincts, 121 476 octets — **-57,4 % de volume**, les
# 9 champs consommés TOUS présents, `_CMDLINE` absent. Les 4 champs qui restent en trop
# (`_BOOT_ID`, `__MONOTONIC_TIMESTAMP`, `__SEQNUM`, `__SEQNUM_ID`) sont les champs d'ADRESSE que
# journald ajoute toujours : ils ne sont pas supprimables, et ils ne portent rien de sensible.
#
# COMPATIBILITÉ — ET POURQUOI L'ÉCHEC N'EST PAS SILENCIEUX. `--output-fields` date de systemd v236.
# Sur plus vieux, journalctl SORT EN ERREUR et n'écrit RIEN : la collecte auth disparaîtrait sans un
# mot, exactement le genre de trou que ce dépôt chasse. On SONDE donc le support (sonde validée : elle
# rend 0 sur une option supportée et 1 sur une option inconnue), et l'absence de support DÉGRADE vers
# la forme complète EN LE DISANT sur stderr — donc dans le journal, donc dans le SOC.
# ----------------------------------------------------------------------------------------------------
JRNL_FIELDS='MESSAGE,PRIORITY,_COMM,_PID,_UID,_SYSTEMD_UNIT,_HOSTNAME'
if journalctl -o json --output-fields="$JRNL_FIELDS" -n0 >/dev/null 2>&1; then
  OF="--output-fields=$JRNL_FIELDS"
else
  OF=""
  echo "journal: journalctl sans --output-fields (systemd < 236) -> expedition NON minimisee (_CMDLINE inclus)" >&2
fi
# shellcheck disable=SC2086  ($SEL/$OF = un seul token chacun ; le ';' du curseur reste littéral)
journalctl $SEL $OF -o json --no-pager _COMM=sshd _COMM=sshd-session _COMM=sudo _COMM=su 2>/dev/null > "$tmp" || true
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
# S30 — PUBLIER D'ABORD, ACQUITTER ENSUITE. Le curseur etait ecrit AVANT la publication du NDJSON :
# une coupure entre les deux perdait la tranche pour toujours (journald ne rend que ce qui suit le
# curseur). Le rejeu que l'inversion produit est absorbe INTEGRALEMENT au central — le daemon prend
# `__CURSOR` comme cle de dedoublonnage, soit l'identite exacte de la ligne.
[ -n "$newcur" ] && state_stage "$CUR" "$newcur"
spool_publish_then_ack "$tmp" "journal-$(date +%s).ndjson"
