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
# S33 — LA SONDE D'AVEUGLEMENT S'AVEUGLAIT ELLE-MEME. Elle rendait DEUX verdicts (masque / pas
# masque), et l'echec de lecture de `/proc/self/mountinfo` tombait du cote « pas masque » — c'est-a-dire
# du cote « couvert ». Le capteur se declarait alors integralement couvert precisement quand il n'avait
# RIEN pu etablir, et l'aveu ci-dessous n'etait jamais emis. Le remede est celui de tout ce lot : un
# TROISIEME verdict, `indetermine`, distinct des deux autres et avoue a son tour.
# `visible` est imprime EXPLICITEMENT plutot que deduit d'une sortie vide : sans lui, un awk qui
# echoue et un awk qui conclut « ce chemin n'est pas masque » rendraient la meme chose — rien — et on
# aurait reconstruit le defaut d'un cran plus bas.
# PARAMETRE SUR SA SOURCE : une garde peut lui presenter un `mountinfo` fabrique et obtenir le meme
# verdict sur n'importe quelle machine, y compris une machine dont le bac a sable est reel.
FIM_MOUNTINFO="${PLUME_MOUNTINFO:-/proc/self/mountinfo}"
fim_verdict_portee() {  # imprime : masque | visible | indetermine
  if [ ! -r "$FIM_MOUNTINFO" ]; then printf 'indetermine'; return 0; fi
  _fv=$(awk -v P="$1" '
    { i = index($0, " - "); if (i == 0) next
      split(substr($0, 1, i - 1), g, " "); split(substr($0, i + 3), d, " ")
      m = g[5]
      if (m == P || m == "/" || index(P, m "/") == 1) {
        if (length(m) >= length(mm)) { mm = m; racine = g[4]; type = d[1]; src = d[2] } } }
    END { if (mm == "") print "indetermine"
          else if (type == "tmpfs" && (racine ~ /^\/systemd\/inaccessible/ || (racine == "/" && src == "tmpfs")))
            print "masque"
          else print "visible" }' "$FIM_MOUNTINFO" 2>/dev/null || true)
  case "$_fv" in
    masque|visible) printf '%s' "$_fv" ;;
    *) printf 'indetermine' ;;
  esac
}
fim_hors_portee=""
fim_portee_inconnue=""
for _racine in /root/.ssh /home; do
  case "$(fim_verdict_portee "$_racine")" in
    masque)      fim_hors_portee="$fim_hors_portee $_racine" ;;
    indetermine) fim_portee_inconnue="$fim_portee_inconnue $_racine" ;;
  esac
done
if [ -n "$fim_portee_inconnue" ]; then
  # NI couvert NI aveugle : INDETERMINE. La couverture annoncee de la famille `authkeys` n'a pas pu
  # etre verifiee sur$fim_portee_inconnue, et se taire reviendrait a affirmer qu'elle est atteinte.
  plume_report_availability integrity unavailable missing-source \
    "portee de la famille authkeys NON VERIFIABLE sur$fim_portee_inconnue : $FIM_MOUNTINFO n'est pas lisible. Le FIM ne peut PAS affirmer que les cles SSH autorisees sont surveillees sur cet hote — ni qu'elles ne le sont pas." \
    2 2>/dev/null || true
fi
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
add_ev() {  # $1=severity $2=message $3=fields-json $4=cle d'identite (vide = aucune)
  em=$(json_escape "$2")
  _dd=""; [ -n "${4:-}" ] && _dd=",\"dedup\":\"$(json_escape "$4")\""
  events="$events${events:+,}{\"ts\":$ts,\"source\":\"integrity\",\"category\":\"integrity\",\"severity\":$1,\"message\":\"$em\"$_dd,\"fields\":$3}"
}
# S36 — LE DIFF EST LA LECTURE DE CE CAPTEUR, et c'est lui que la promotion de la reference
# acquitte : ce qui entre dans la reference ne sera plus jamais signale. Son code de retour etait
# avale par `|| true`, si bien qu'un `comm` en echec (une reference ecrite avec un autre ordre de
# tri suffit : il refuse une entree non triee) rendait un diff VIDE — indiscernable d'un hote sans
# changement. La sortie « rien a signaler » promouvait alors la reference, et les modifications
# constatees ce passage y entraient sans avoir jamais ete emises : un binaire SUID modifie in-place
# devenait « connu ». C'est exactement la perte que `S30` fermait, par la porte de sortie.
_diff_ok=1
if [ -f "$BASE" ]; then
  comm -13 "$BASE" "$cur" > "$STATE/.int.added" 2>/dev/null || _diff_ok=0
  while IFS='|' read -r kind path sha scope; do
    [ -z "${kind:-}" ] && continue
    # ajout vs modif : le chemin existait-il deja dans la baseline (hash different) ?
    if grep -qF "$kind|$path|" "$BASE" 2>/dev/null; then change=modif; else change=ajout; fi
    pj=$(json_escape "$path")
    fields="{\"kind\":\"$kind\",\"path\":\"$pj\",\"sha256\":\"$sha\",\"scope\":\"${scope:-host}\",\"change\":\"$change\"}"
    # S34 — CLE D'IDENTITE : (genre, chemin, empreinte, date de derniere modification). Les trois
    # premieres composantes decrivent le CONSTAT, la quatrieme le rend RE-SIGNALABLE. Sans elle, un
    # fichier retire de la reference puis remis a l'identique — une cle SSH replacee apres avoir ete
    # nettoyee, par exemple — porterait la cle deja vue, et le second constat, pourtant REEL, serait
    # efface. C'est la forme deja retenue par le capteur `yara`, pour cette raison exacte.
    # Ni `$ts`, ni le PID n'y entrent : une reference non promue (coupure apres publication) fait
    # relire le MEME diff, avec les MEMES empreintes et les MEMES dates, donc les MEMES cles.
    # LES PORTS EN ECOUTE N'EN RECOIVENT AUCUNE, et c'est dit plutot que bricole : un port n'est ni
    # un fichier ni un contenu, il n'a ni empreinte ni date, et sa seule composante stable — le
    # numero — se repete legitimement quand un service est arrete puis relance. Une cle batie
    # dessus effacerait cette reapparition, qui est precisement le constat a voir.
    dd=""
    if [ "$kind" != port ] && [ -f "$path" ]; then
      mt=$(stat -c %Y "$path" 2>/dev/null || echo "")
      [ -n "$mt" ] && dd="integrity-$kind-$path-$sha-$mt"
    fi
    case "$kind" in
      suid)     [ "$change" = modif ] && add_ev 4 "SUID/SGID MODIFIE in-place (hash) : $path" "$fields" "$dd" || add_ev 3 "nouveau binaire SUID/SGID : $path" "$fields" "$dd" ;;
      preload)  add_ev 4 "/etc/ld.so.preload $change (persistance LD) : $path" "$fields" "$dd" ;;
      sudoersd) add_ev 4 "sudoers.d $change (privilege) : $path" "$fields" "$dd" ;;
      authkeys) add_ev 4 "authorized_keys $change (acces SSH) : $path" "$fields" "$dd" ;;
      pamd)     add_ev 4 "pam.d $change (auth) : $path" "$fields" "$dd" ;;
      rclocal)  add_ev 4 "rc.local $change (boot persistance) : $path" "$fields" "$dd" ;;
      unit)     add_ev 3 "unit systemd $change (persistance) : $path" "$fields" "$dd" ;;
      crond)    add_ev 3 "cron.d $change : $path" "$fields" "$dd" ;;
      crit)     case "$path" in *shadow*) add_ev 4 "fichier critique $change : $path" "$fields" "$dd" ;; *) add_ev 3 "fichier critique $change : $path" "$fields" "$dd" ;; esac ;;
      port)     add_ev 2 "nouveau port en écoute : $path" "$fields" "$dd" ;;
      *)        add_ev 1 "$kind $change : $path" "$fields" "$dd" ;;
    esac
  done < "$STATE/.int.added"
  rm -f "$STATE/.int.added"
fi
# S30 — PUBLIER D'ABORD, ACQUITTER ENSUITE. La base de reference EST l'acquittement de ce capteur :
# ce qu'elle contient ne sera plus jamais signale. Ecrite avant la publication, une coupure entre les
# deux faisait disparaitre DEFINITIVEMENT le constat — un binaire SUID nouveau ou modifie in-place
# entrait dans la reference sans avoir jamais ete emis. Elle est donc MISE EN ATTENTE et n'est posee
# qu'apres la publication de l'enveloppe d'events, ou par `plume_exit_nodata` au 1er run et aux runs
# sans changement — ou elle acquitte bel et bien la reference, et c'est LEGITIME parce que le diff a
# abouti et n'a rien trouve. S36 : quand ce diff ECHOUE, la reference n'est plus mise en attente du
# tout, sans quoi cette sortie ferait entrer dans le connu des constats jamais emis. S34 — le rejeu que cet ordre produit est desormais
# ABSORBE pour les constats portant sur un FICHIER (cle (genre, chemin, empreinte, mtime)) ; les
# ports en ecoute n'en portent pas, faute d'identite sure, et leur rejeu reste visible.
# S36 — la reference n'est mise en attente QUE si le diff a abouti. Sinon elle est jetee : le
# capteur publie ce qu'il a (rien, ou les constats deja bâtis) et la comparaison sera refaite au
# passage suivant contre la MEME reference — une relecture, jamais un oubli.
if [ "$_diff_ok" = 1 ]; then
  state_stage_file "$cur" "$BASE"
else
  rm -f "$cur"
  plume_lecture_partielle integrity forme_inconnue "comparaison a la reference d'integrite en echec : la reference N'EST PAS promue, aucun constat n'entre en silence dans le connu"
fi

# DEAD-MAN'S-SWITCH (battement de santé AUTONOME) : ce FIM sort tôt au 1er run (baseline) et aux runs sans
# changement -> son silence serait indistinguable d'un collecteur mort. On écrit donc un petit .json kind:events
# health À CHAQUE run, AVANT le garde « aucun changement » et INDÉPENDAMMENT du diff. PAS de dedup -> chaque
# battement S'INSÈRE -> MAX(ts) avance -> heartbeat vivant. Silence > 25 min = alerte MUET (collecteur CONTINU
# integrity-health, cf. main.rs). Le flux d'events RÉEL (category=integrity) tolère le calme (event_based).
spool_write "integrity-health-$ts.json" \
  "$(emit_event "$(heartbeat integrity 'integrity santé: FIM actif' '{"alive":1}')")" nl

[ -z "$events" ] && plume_exit_nodata   # 1er run (baseline) ou aucun changement -> rien à signaler
spool_write_then_ack "integrity-$ts.json" "$(emit_event "$events")"
