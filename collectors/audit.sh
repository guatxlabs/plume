#!/bin/sh
# Capteur SOC : auditd (exec / élévation de privilège / accès fichiers sensibles) -> events.
# Lit les NOUVEAUX enregistrements via le checkpoint d'ausearch. ROOT. auditd OPTIONNEL (skip si absent).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
command -v ausearch >/dev/null 2>&1 || plume_unavailable auditd missing-dependency "ausearch absent (paquet auditd non installe) : la piste d'audit ne peut pas etre relue"
CKPT="$STATE/audit.ckpt"
# S30 — PUBLIER D'ABORD, ACQUITTER ENSUITE, y compris quand c'est un OUTIL EXTERNE qui acquitte.
# `ausearch --checkpoint` avance son point de reprise au moment ou il LIT, donc bien avant que
# l'enveloppe ne soit publiee : une coupure entre les deux perdait la tranche definitivement, et les
# events `audit` ne portent aucune cle de dedoublonnage, donc rien ne l'aurait rattrapee. Le point de
# reprise est donc tenu sur une COPIE DE TRAVAIL, qui ne remplace le fichier d'etat qu'APRES la
# publication. Quand aucun point de reprise n'existe encore, la copie n'existe pas non plus : ausearch
# voit exactement ce qu'il voyait avant. LIMITE : l'ecriture du point de reprise par ausearch reste la
# sienne — ce qui est tenu ici est le MOMENT ou elle devient visible, pas son atomicite.
CKPT_WORK=$(mktemp "$STATE/.audit.ckpt.XXXXXX")
if [ -s "$CKPT" ]; then cp "$CKPT" "$CKPT_WORK"; else rm -f "$CKPT_WORK"; fi

out="$(ausearch --checkpoint "$CKPT_WORK" --start checkpoint --format text 2>/dev/null || true)"
if [ -s "$CKPT_WORK" ]; then state_stage_file "$CKPT_WORK" "$CKPT"; else rm -f "$CKPT_WORK"; fi
[ -z "$out" ] && plume_exit_nodata

tmpf=$(mktemp)
printf '%s\n' "$out" > "$tmpf"
events=""
n=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  n=$((n + 1)); [ "$n" -gt 200 ] && break   # garde-fou : 200 events max / passe
  sev=2
  case "$line" in
    *shadow*|*sudoers*|*ld.so.preload*|*sudo*|*" su "*|*passwd*|*useradd*|*usermod*|*setuid*|*sshd_config*) sev=3 ;;
  esac
  em=$(json_escape "$(printf '%s' "$line" | cut -c1-400)")
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"auditd\",\"category\":\"audit\",\"severity\":$sev,\"message\":\"$em\"}"
done < "$tmpf"
rm -f "$tmpf"
[ -z "$events" ] && plume_exit_nodata

spool_write_then_ack "audit-$ts.json" "$(emit_event "$events")"
