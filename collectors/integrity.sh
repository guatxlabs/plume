#!/bin/sh
# Capteur Plume : intégrité/persistance — FIM NATIF (aucune dépendance type AIDE/auditd).
# Baseline + diff. DURCISSEMENT :
#   (a) SHA256 des binaires SUID/SGID -> detecte la MODIF IN-PLACE (binaire systeme trojanise au MEME
#       chemin : 0 event avant car on ne suivait que le CHEMIN). suid modifie in-place = severity 4.
#   (b) FIM ETENDU sur les vecteurs de persistance : /etc/sudoers.d, /etc/cron.d, authorized_keys,
#       units systemd (/etc/systemd/system), /etc/pam.d, /etc/ld.so.preload, /etc/rc.local (hash + ajout/modif).
#   (c) champs STRUCTURES {kind, path, sha256, scope:host|container, change:ajout|modif}.
# Garde le PRUNE conteneur (anti-bruit snapshots buildkit/rancher/containerd). Borne le volume : baseline
# + DELTA (comm), pas de re-scan complet emis. ROOT (CAP_DAC_READ_SEARCH) ; ProtectHome=read-only requis
# pour lire authorized_keys. Lecture seule.
#   (d) COUVERTURE ANNONCEE vs COUVERTURE ATTEINTE : le bac a sable de l'unit peut RETIRER une famille
#       annoncee sans un mot (un glob qui ne matche rien ne previent personne). Ce capteur VERIFIE donc
#       la portee des racines dont depend la famille `authkeys` et AVOUE quand elles sont masquees.
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
FILES="${PLUME_FIM_FILES:-/etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers /etc/crontab /etc/hosts /etc/ssh/sshd_config}"
plume_init
BASE="$STATE/integrity.base"
# S30 — le temporaire de la nouvelle base de reference vit dans `$STATE` (meme systeme de fichiers que
# la cible) : le remplacement differe reste alors un renommage, pas une copie.
cur="$(mktemp "$STATE/.integrity.base.XXXXXX")"

# scope d'un chemin : container si sous un store conteneur (normalement PRUNE -> host en pratique).
scope_of() {
  case "$1" in
    /var/lib/buildkit/*|/var/lib/rancher/*|/var/lib/containerd/*|/var/lib/docker/*|/var/lib/kubelet/*|*/overlay2/*|/run/containerd/*) echo container ;;
    *) echo host ;;
  esac
}
# emet une ligne baseline "kind|path|sha256|scope" pour un FICHIER (hash sha256).
emit_hash() {  # $1=kind $2=path
  [ -f "$2" ] || return 0
  _h=$(sha256sum "$2" 2>/dev/null | cut -d' ' -f1); [ -n "$_h" ] || _h="?"
  printf '%s|%s|%s|%s\n' "$1" "$2" "$_h" "$(scope_of "$2")" >> "$cur"
}

# (a) binaires SUID/SGID + SHA256 (modif in-place detectee par changement de hash). PRUNE conteneurs.
PRUNE="${PLUME_FIM_PRUNE:-/var/lib/buildkit /var/lib/rancher /var/lib/containerd /var/lib/docker /var/lib/kubelet}"
prune_expr=""; for _d in $PRUNE; do prune_expr="$prune_expr -path $_d -prune -o"; done
# shellcheck disable=SC2086
find / -xdev $prune_expr -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | while IFS= read -r b; do
  emit_hash suid "$b"
done
# fichiers critiques (identite/comptes/sshd)
for f in $FILES; do emit_hash crit "$f"; done
# (b) FIM ETENDU — vecteurs de persistance (hash + ajout/modif via le diff baseline)
emit_hash preload /etc/ld.so.preload
emit_hash rclocal /etc/rc.local
for f in /etc/sudoers.d/*;            do emit_hash sudoersd "$f"; done
for f in /etc/cron.d/*;               do emit_hash crond "$f"; done
for f in /etc/pam.d/*;                do emit_hash pamd "$f"; done
for f in /etc/systemd/system/*.service /etc/systemd/system/*.timer; do emit_hash unit "$f"; done
# --- (d) la famille `authkeys` est ANNONCEE : si ses racines sont hors de portee, on le DIT ----------
# systemd `ProtectHome=` ne rend pas /home et /root illisibles : il REMPLACE le point de montage par un
# repertoire vide (`/systemd/inaccessible/dir`, ou un tmpfs neuf pour `ProtectHome=tmpfs`). Le glob
# ci-dessous ne matche alors RIEN, et une baseline amputee est indiscernable d'un hote sans cle SSH.
# MESURE le 2026-08-20 (systemd 261, sonde differentielle a une seule variable, ce script execute TEL
# QUEL) : sous `ProtectHome=yes` la baseline perd EXACTEMENT une famille -- 86 lignes au lieu de 87,
# 0 entree `authkeys` au lieu de 1 ; tout le reste est identique.
# ON LE LIT DANS LE NOYAU, ON NE LE DEVINE PAS d'un repertoire vide (un /root vide est plausible) : le
# montage qui COUVRE un chemin est celui de mountpoint le plus long, et le DERNIER a ce mountpoint (un
# BindReadOnlyPaths= plus profond re-expose par dessus). Sonde validee le meme jour avec ses temoins
# POSITIF et NEGATIF : `yes` et `tmpfs` -> /home et /root masques ; `read-only` et absence de directive
# -> visibles ; /etc visible dans les quatre cas (temoin de non-degenerescence).
# LIMITE DECLAREE : un tmpfs monte par l'exploitant lui-meme sur /home serait signale de la meme facon
# -- ce qui reste vrai, le FIM n'y verrait pas davantage les vraies cles.
# awk REND UN MOT, il ne rend pas un code de sortie : `exit` dans le programme awk se lit comme une
# sortie du CAPTEUR pour la garde de CI qui interdit les sorties non classees (et un lecteur pourrait
# faire la meme confusion). Le verdict est donc une chaine, comparee ici.
fim_chemin_masque() {  # vrai = le montage qui COUVRE $1 est un masque de bac a sable
  [ "$(awk -v P="$1" '
    { i = index($0, " - "); if (i == 0) next
      split(substr($0, 1, i - 1), g, " "); split(substr($0, i + 3), d, " ")
      m = g[5]
      if (m == P || m == "/" || index(P, m "/") == 1) {
        if (length(m) >= length(mm)) { mm = m; racine = g[4]; type = d[1]; src = d[2] } } }
    END { if (type == "tmpfs" && (racine ~ /^\/systemd\/inaccessible/ || (racine == "/" && src == "tmpfs")))
            print "masque" }' /proc/self/mountinfo 2>/dev/null)" = masque ]
}
fim_hors_portee=""
for _racine in /root/.ssh /home; do
  if fim_chemin_masque "$_racine"; then fim_hors_portee="$fim_hors_portee $_racine"; fi
done
if [ -n "$fim_hors_portee" ]; then
  # PAS `plume_unavailable` : le capteur n'est pas incapable, il est PARTIELLEMENT aveugle et continue
  # de rendre les neuf autres familles. On emet l'aveu et on poursuit. `missing-source` est le
  # vocabulaire ferme existant (cf. collectors/lib.sh) : la source annoncee n'est pas la.
  plume_report_availability integrity unavailable missing-source \
    "famille authkeys ANNONCEE mais hors de portee : le bac a sable de l'unit remplace$fim_hors_portee (ProtectHome=). Les cles SSH autorisees ne sont PAS surveillees sur cet hote ; les autres familles du FIM le restent." \
    2 2>/dev/null || true
fi
for f in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 /home/*/.ssh/authorized_keys /home/*/.ssh/authorized_keys2; do emit_hash authkeys "$f"; done
# ports TCP en écoute (kind=port, pas de hash)
if command -v ss >/dev/null 2>&1; then
  ss -H -tln 2>/dev/null | awk '{print $4}' | sed 's/.*://' | grep -E '^[0-9]+$' | sort -un | sed 's/^/port|/; s/$/||host/' >> "$cur" || true
fi
sort -o "$cur" "$cur"

events=""
add_ev() {  # $1=severity $2=message $3=fields-json
  em=$(json_escape "$2")
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"integrity\",\"category\":\"integrity\",\"severity\":$1,\"message\":\"$em\",\"fields\":$3}"
}
if [ -f "$BASE" ]; then
  comm -13 "$BASE" "$cur" > "$STATE/.int.added" 2>/dev/null || true
  while IFS='|' read -r kind path sha scope; do
    [ -z "${kind:-}" ] && continue
    # ajout vs modif : le chemin existait-il deja dans la baseline (hash different) ?
    if grep -qF "$kind|$path|" "$BASE" 2>/dev/null; then change=modif; else change=ajout; fi
    pj=$(json_escape "$path")
    fields="{\"kind\":\"$kind\",\"path\":\"$pj\",\"sha256\":\"$sha\",\"scope\":\"${scope:-host}\",\"change\":\"$change\"}"
    case "$kind" in
      suid)     [ "$change" = modif ] && add_ev 4 "SUID/SGID MODIFIE in-place (hash) : $path" "$fields" || add_ev 3 "nouveau binaire SUID/SGID : $path" "$fields" ;;
      preload)  add_ev 4 "/etc/ld.so.preload $change (persistance LD) : $path" "$fields" ;;
      sudoersd) add_ev 4 "sudoers.d $change (privilege) : $path" "$fields" ;;
      authkeys) add_ev 4 "authorized_keys $change (acces SSH) : $path" "$fields" ;;
      pamd)     add_ev 4 "pam.d $change (auth) : $path" "$fields" ;;
      rclocal)  add_ev 4 "rc.local $change (boot persistance) : $path" "$fields" ;;
      unit)     add_ev 3 "unit systemd $change (persistance) : $path" "$fields" ;;
      crond)    add_ev 3 "cron.d $change : $path" "$fields" ;;
      crit)     case "$path" in *shadow*) add_ev 4 "fichier critique $change : $path" "$fields" ;; *) add_ev 3 "fichier critique $change : $path" "$fields" ;; esac ;;
      port)     add_ev 2 "nouveau port en écoute : $path" "$fields" ;;
      *)        add_ev 1 "$kind $change : $path" "$fields" ;;
    esac
  done < "$STATE/.int.added"
  rm -f "$STATE/.int.added"
fi
# S30 — PUBLIER D'ABORD, ACQUITTER ENSUITE. La base de reference EST l'acquittement de ce capteur :
# ce qu'elle contient ne sera plus jamais signale. Ecrite avant la publication, une coupure entre les
# deux faisait disparaitre DEFINITIVEMENT le constat — un binaire SUID nouveau ou modifie in-place
# entrait dans la reference sans avoir jamais ete emis. Elle est donc MISE EN ATTENTE et n'est posee
# qu'apres la publication de l'enveloppe d'events (ou par `plume_exit_nodata` au 1er run et aux runs
# sans changement, ou elle n'acquitte rien). Ces events ne portent pas de cle de dedoublonnage : le
# rejeu apres coupure produit des doublons VISIBLES, la ou il y avait une perte muette.
state_stage_file "$cur" "$BASE"

# DEAD-MAN'S-SWITCH (battement de santé AUTONOME) : ce FIM sort tôt au 1er run (baseline) et aux runs sans
# changement -> son silence serait indistinguable d'un collecteur mort. On écrit donc un petit .json kind:events
# health À CHAQUE run, AVANT le garde « aucun changement » et INDÉPENDAMMENT du diff. PAS de dedup -> chaque
# battement S'INSÈRE -> MAX(ts) avance -> heartbeat vivant. Silence > 25 min = alerte MUET (collecteur CONTINU
# integrity-health, cf. main.rs). Le flux d'events RÉEL (category=integrity) tolère le calme (event_based).
spool_write "integrity-health-$ts.json" \
  "$(emit_event "$(heartbeat integrity 'integrity santé: FIM actif' '{"alive":1}')")" nl

[ -z "$events" ] && plume_exit_nodata   # 1er run (baseline) ou aucun changement -> rien à signaler
spool_write_then_ack "integrity-$ts.json" "$(emit_event "$events")"
