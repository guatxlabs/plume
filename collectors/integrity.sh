#!/bin/sh
# Capteur Plume : intégrité/persistance — FIM NATIF (aucune dépendance type AIDE/auditd).
# Baseline + diff. DURCISSEMENT :
#   (a) SHA256 des binaires SUID/SGID -> detecte la MODIF IN-PLACE (binaire systeme trojanise au MEME
#       chemin : 0 event avant car on ne suivait que le CHEMIN). suid modifie in-place = severity 4.
#   (b) FIM ETENDU sur les vecteurs de persistance : /etc/sudoers.d, /etc/cron.d, authorized_keys,
#       unites systemd (tout le chemin de recherche, cf. (e)), /etc/pam.d, /etc/ld.so.preload, /etc/rc.local
#       (hash + ajout/modif).
#   (c) champs STRUCTURES {kind, path, sha256, scope:host|container, change:ajout|modif}.
# Garde le PRUNE conteneur (anti-bruit snapshots buildkit/rancher/containerd). Borne le volume : baseline
# + DELTA (comm), pas de re-scan complet emis. ROOT (CAP_DAC_READ_SEARCH) ; ProtectHome=read-only requis
# pour lire authorized_keys. Lecture seule.
#   (d) COUVERTURE ANNONCEE vs COUVERTURE ATTEINTE : le bac a sable de l'unit peut RETIRER une famille
#       annoncee sans un mot (un glob qui ne matche rien ne previent personne). Ce capteur VERIFIE donc
#       la portee des racines dont depend la famille `authkeys` et AVOUE quand elles sont masquees.
#   (e) P3.8-a — LA FAMILLE `unit` COUVRAIT UNE LIGNE : `/etc/systemd/system/*.service` et `*.timer`.
#       Ni `/run/systemd/system`, ni `/usr/local/lib/systemd/system`, ni les drop-ins `*.d/*.conf`, ni les
#       `.socket`/`.path`. Un drop-in qui ajoute un `ExecStartPre=` a une unite existante est une persistance
#       ORDINAIRE et ne produisait AUCUN evenement : la regle livree « vecteur de persistance ajoute » (T1543)
#       tournait sur une liste qui ne contenait pas le fichier. Silence complet, pas allegation fausse.
#       La liste des repertoires est desormais DERIVEE du chemin de recherche de systemd (`systemd-analyze
#       unit-paths`), avec un repli sur la table de `systemd.unit(5)` ecrite UNE fois ; l'evenement dit quelle
#       voie a servi (`unit_dirs_from`). Types couverts : ceux qui executent ou declenchent quelque chose
#       (`service timer socket path mount automount`) et les drop-ins, avec le nom de l'unite parente (`unit`).
#       Un repertoire ABSENT n'est rien (un hote sans `/usr/local/lib/systemd/system` est ordinaire) ; un
#       repertoire ILLISIBLE est un aveu et interdit la promotion de la reference, comme une famille non
#       enumeree. `PLUME_UNIT_ROOT` prefixe chaque repertoire derive : les temoins posent un drop-in sous un
#       repertoire temporaire sans toucher l'hote. NON COUVERT, et dit : les liens d'activation
#       `*.wants/` / `*.requires/` (activer une unite deja presente), et les `.scope`/`.slice`/`.target`.
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
# nom de l'unite que designe un chemin de la famille `unit` : le fichier lui-meme, ou, pour un drop-in
# `<unite>.d/<fragment>.conf`, l'UNITE PARENTE (`service.d/` type-wide rend `service`).
fim_unit_name() {  # $1=path
  _fun_dir=${1%/*}
  case "$_fun_dir" in
    *.d) _fun_parent=${_fun_dir##*/}; printf '%s' "${_fun_parent%.d}" ;;
    *)   printf '%s' "${1##*/}" ;;
  esac
}
# emet une ligne baseline "kind|path|sha256|scope" pour un FICHIER (hash sha256).
#
# S36, RANG « DU BRUIT AU LIEU DU SILENCE » — L'EMPREINTE `?` ETAIT UN VERDICT FABRIQUE.
# `sha256sum … | cut` rend le statut de `cut`, jamais celui de `sha256sum` : un fichier present mais
# NON LISIBLE (droits retires, capacite DAC droppee, entree/sortie) donnait une empreinte vide, et la
# ligne partait quand meme avec `?` a la place. `?` appartient au DOMAINE NORMAL du champ : le `comm`
# la voyait differente de la reference, `grep` retrouvait le chemin, et le capteur concluait `modif` —
# c'est-a-dire `add_ev 4` pour `authkeys`, `preload`, `sudoersd`, `pamd`, `rclocal`, `crit`+shadow et
# un SUID modifie in-place. Les regles livrees `ca-ssh-authkeys-persistence` et `pe-new-suid-added`
# (severite 4 toutes deux) s'arment de ces constats. Le cout ne s'arretait pas la : `?` entrait dans la
# reference promue, si bien que la lecture REUSSIE suivante ressortait une SECONDE fois en `modif`.
# Une seule panne de droits produisait donc deux vagues d'alertes de severite 4 qui ne decrivaient
# rien. C'est l'usure du capteur : l'exploitant apprend a ignorer la famille entiere.
#
# CE QUI EST FAIT A LA PLACE, ET POURQUOI CE N'EST PAS SE TAIRE. Le code de retour de `sha256sum` est
# lu (plus de tube), et une lecture ratee ne produit AUCUNE empreinte. Omettre la ligne ne suffirait
# pas : la reference promue perdrait le chemin, et le passage suivant le ressortirait en `ajout` — le
# meme faux constat, decale d'un cran. La ligne de la REFERENCE est donc REPORTEE telle quelle, de
# sorte que la comparaison de ce passage ne dit rien de ce chemin et que celle du passage suivant se
# fera contre l'etat qui a REELLEMENT ete constate la derniere fois. Un vrai changement survenu
# pendant l'aveuglement n'est donc pas perdu : il ressort des que le fichier redevient lisible.
# Et le trou est DIT — les chemins collectes dans `$_fim_ko` sont avoues plus bas par le canal deja livre.
emit_hash() {  # $1=kind $2=path
  [ -f "$2" ] || return 0
  if _hs=$(sha256sum "$2" 2>/dev/null); then
    _h=$(printf '%s' "$_hs" | cut -d' ' -f1)
  else
    _h=""
  fi
  if [ -z "$_h" ]; then
    # UN FICHIER, PAS UNE VARIABLE : la boucle des binaires SUID est alimentee par un TUBE, donc elle
    # tourne dans un SOUS-SHELL — une variable qu'on y poserait serait perdue au retour, et le trou
    # ne serait jamais avoue. C'est la meme forme de piege que celle que `S36` a fermee ailleurs.
    printf '%s\n' "$2" >> "$_fim_ko"
    # Report de la ligne de reference, s'il y en a une. Sinon RIEN : un chemin jamais empreinte ne
    # doit pas entrer dans la reference sur une lecture qui a echoue.
    _ref=$(grep -F "$1|$2|" "$BASE" 2>/dev/null | head -1)
    [ -n "$_ref" ] && printf '%s\n' "$_ref" >> "$cur"
    return 0
  fi
  printf '%s|%s|%s|%s\n' "$1" "$2" "$_h" "$(scope_of "$2")" >> "$cur"
}
_fim_ko="$STATE/.int.ko.$$"
: > "$_fim_ko"

# (a) binaires SUID/SGID + SHA256 (modif in-place detectee par changement de hash). PRUNE conteneurs.
PRUNE="${PLUME_FIM_PRUNE:-/var/lib/buildkit /var/lib/rancher /var/lib/containerd /var/lib/docker /var/lib/kubelet}"
prune_expr=""; for _d in $PRUNE; do prune_expr="$prune_expr -path $_d -prune -o"; done
# S36 — L'ENUMERATION DES SUID ETAIT BRANCHEE SUR UN TUBE, DONC SON STATUT ETAIT CELUI DU `while`.
# Un `find` qui ne demarre pas — binaire absent, racine refusee, systeme de fichiers en erreur —
# rendait alors EXACTEMENT ce que rend un hote sans aucun binaire SUID : rien. La famille `suid`
# disparaissait de la nouvelle reference, la reference etait promue quand meme, et ce qui n'avait
# jamais ete lu entrait dans le CONNU. La regle livree `pe-new-suid-added` (severite 4,
# `kind=suid change=ajout`) perdait son entree, et le passage suivant la noyait sous une
# re-declaration de TOUS les binaires SUID en « ajout ».
# CE QUI EST TENU, ET CE QUI NE L'EST PAS — la distinction tient a une propriete de `find` qu'il faut
# dire plutot que supposer : son code de retour vaut 1 AUSSI BIEN pour « un sous-arbre etait
# illisible » — banal sur un hote reel, et le reste de l'enumeration est valable — que pour « la
# lecture n'a pas eu lieu ». S'en servir seul ferait avouer une indisponibilite a chaque passage.
# CE QUI EST CONCLU ICI est donc la seule conjonction qui ne soit pas ambigue : code de retour non
# nul ET AUCUNE ligne rendue. Le cas PARTIEL — des lignes rendues et un code non nul — reste NON
# COUVERT, et il est nomme : y conclure demanderait un second signal (la liste des racines refusees),
# que `find` n'expose pas separement.
_suid_liste=$(mktemp "$STATE/.integrity.suid.XXXXXX")
_fim_famille_ko=""
_fim_famille_cause=""
# shellcheck disable=SC2086
find / -xdev $prune_expr -type f \( -perm -4000 -o -perm -2000 \) -print > "$_suid_liste" 2>/dev/null \
  || { [ -s "$_suid_liste" ] || { _fim_famille_ko=" suid"; _fim_famille_cause="source_illisible"; }; }
while IFS= read -r b; do
  emit_hash suid "$b"
done < "$_suid_liste"
rm -f "$_suid_liste"
# fichiers critiques (identite/comptes/sshd)
for f in $FILES; do emit_hash crit "$f"; done
# (b) FIM ETENDU — vecteurs de persistance (hash + ajout/modif via le diff baseline)
emit_hash preload /etc/ld.so.preload
emit_hash rclocal /etc/rc.local
for f in /etc/sudoers.d/*;            do emit_hash sudoersd "$f"; done
for f in /etc/cron.d/*;               do emit_hash crond "$f"; done
for f in /etc/pam.d/*;                do emit_hash pamd "$f"; done
# (e) UNITES SYSTEMD — LE CHEMIN DE RECHERCHE EST DERIVE, PAS ECRIT (P3.8-a).
# Types retenus : ceux qui EXECUTENT ou DECLENCHENT quelque chose. Un `.target` ou un `.slice` n'a pas
# de `Exec*=` et ne peut rien lancer par lui-meme.
UNIT_TYPES="service timer socket path mount automount"
# REPLI, ecrit UNE fois, avec sa source : systemd.unit(5), table « Load path when running in system mode
# (--system) », relue le 2026-08-22 sur un systemd 261 — et `/lib/systemd/system`, que la meme page reserve
# aux systemes dont `/usr` n'est pas fusionne ; sur les autres il designe le meme repertoire que
# `/usr/lib/systemd/system` et la deduplication par chemin canonique ci-dessous l'ecarte.
UNIT_DIRS_DOC="/etc/systemd/system.control /run/systemd/system.control /run/systemd/transient /run/systemd/generator.early /etc/systemd/system /etc/systemd/system.attached /run/systemd/system /run/systemd/system.attached /run/systemd/generator /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system /run/systemd/generator.late"
# LA VOIE QUI A SERVI EST DITE DANS L'EVENEMENT. Deux valeurs, et elles sont les deux seules :
#   `systemd-analyze` — la liste vient du gestionnaire de cet hote (son chemin compile, ses generateurs) ;
#   `systemd.unit(5)`  — la table documentee, parce que l'outil est absent (un hote sans systemd n'a
#                        rien a deriver : ce n'est pas un defaut), ou parce qu'il a ECHOUE ou rendu une
#                        sortie sans chemin — et ces deux derniers cas sont AVOUES : l'outil est la, donc
#                        systemd est la, et la derivation n'a pas eu lieu.
UNIT_DIRS_FROM="systemd.unit(5)"
_ud_liste=""
_ud_anomalie=""
if command -v systemd-analyze >/dev/null 2>&1; then
  if _ud_sortie=$(systemd-analyze unit-paths 2>/dev/null); then
    # Seules les lignes qui designent un chemin absolu comptent ; le reste n'est pas un repertoire.
    while IFS= read -r _ud; do
      case "$_ud" in /*) _ud_liste="$_ud_liste$_ud
" ;; esac
    done <<EOF
$_ud_sortie
EOF
    if [ -n "$_ud_liste" ]; then UNIT_DIRS_FROM="systemd-analyze"; else _ud_anomalie="forme_inconnue"; fi
  else
    _ud_anomalie="source_illisible"
  fi
fi
if [ -n "$_ud_anomalie" ]; then
  plume_report_availability integrity unavailable missing-dependency \
    "chemin de recherche des unites systemd NON DERIVE ($_ud_anomalie : systemd-analyze unit-paths present mais sans chemin rendu) : repli sur la table de systemd.unit(5). Les unites d'un repertoire propre a cet hote, hors de cette table, ne sont PAS surveillees ce passage." \
    2 2>/dev/null || true
fi
[ -n "$_ud_liste" ] || _ud_liste=$(printf '%s\n' $UNIT_DIRS_DOC)
# `PLUME_UNIT_ROOT` : prefixe de chaque repertoire derive. Vide en production ; un temoin y met un
# repertoire temporaire et le capteur ne lit alors RIEN de l'hote.
UNIT_ROOT="${PLUME_UNIT_ROOT:-}"
# Deduplication par chemin CANONIQUE (`cd -P` + `pwd -P`, deux primitives du shell) : `/lib/systemd/system`
# et `/usr/lib/systemd/system` sont le meme repertoire sur un `/usr` fusionne, et le hacher deux fois
# produirait deux constats pour un seul fichier.
_ud_vus=" "
while IFS= read -r _ud; do
  [ -n "$_ud" ] || continue
  _ud="$UNIT_ROOT$_ud"
  [ -d "$_ud" ] || continue
  _ud_canon=$(cd -P "$_ud" 2>/dev/null && pwd -P) || _ud_canon="$_ud"
  case "$_ud_vus" in *" $_ud_canon "*) continue ;; esac
  _ud_vus="$_ud_vus$_ud_canon "
  if [ ! -r "$_ud" ] || [ ! -x "$_ud" ]; then
    # PRESENT MAIS ILLISIBLE : ce n'est pas « rien a hacher », c'est « pas pu lire ». Meme traitement
    # qu'une famille non enumeree (S36) : aveu, et la reference n'est pas promue — sans quoi ce que
    # personne n'a lu entrerait dans le connu, et ressortirait en « ajout » une fois le droit rendu.
    _fim_famille_ko="$_fim_famille_ko unit:$_ud"
    _fim_famille_cause="${_fim_famille_cause:-$(plume_cause_lecture "$_ud")}"
    continue
  fi
  for _ut in $UNIT_TYPES; do for f in "$_ud"/*."$_ut"; do emit_hash unit "$f"; done; done
  for f in "$_ud"/*.d/*.conf; do emit_hash unit "$f"; done
done <<EOF
$_ud_liste
EOF
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

# S36 — LE TROU EST DIT, PAR LE CANAL DEJA LIVRE. Un fichier annonce surveille dont l'empreinte n'a
# pas pu etre prise n'est PAS surveille ce passage : aucune modification de son contenu n'y sera vue.
# `plume_lecture_partielle` : le capteur n'est pas incapable — les autres familles restent rendues —
# et la regle livree `de-collector-unavailable` alerte deja sur ce canal. AUCUN marqueur n'est jete
# ici : la reference reportee EST l'etat constate la derniere fois, elle reste promouvable.
if [ -s "$_fim_ko" ]; then
  _fim_n=$(wc -l < "$_fim_ko" | tr -d ' ')
  _fim_liste=$(head -n 20 "$_fim_ko" | tr '\n' ' ')
  plume_lecture_partielle integrity "$(plume_cause_lecture "$(head -1 "$_fim_ko")")" \
    "$_fim_n fichier(s) annonce(s) surveille(s) N'ONT PAS pu etre empreintes ce passage : aucune empreinte fabriquee, aucun constat de modification n'en est deduit, et la ligne de reference de chacun est reportee telle quelle. Chemins (20 max) : $_fim_liste"
fi
rm -f "$_fim_ko"

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
    # P3.8-a — UN DROP-IN PORTE LE NOM DE SON UNITE PARENTE. `x.service.d/zz.conf` configure `x.service` :
    # c'est ce nom que l'analyste cherche, pas celui du fragment. Une unite ordinaire porte le sien.
    # `unit_dirs_from` dit par quelle voie la liste des repertoires a ete obtenue ce passage.
    _usur=""
    if [ "$kind" = unit ]; then
      _un=$(fim_unit_name "$path")
      case "$path" in *.d/*.conf) _uform="drop-in"; _usur=" sur $_un (drop-in)" ;; *) _uform="unit" ;; esac
      fields="${fields%?},\"unit\":\"$(json_escape "$_un")\",\"unit_form\":\"$_uform\",\"unit_dirs_from\":\"$UNIT_DIRS_FROM\"}"
    fi
    case "$kind" in
      suid)     [ "$change" = modif ] && add_ev 4 "SUID/SGID MODIFIE in-place (hash) : $path" "$fields" "$dd" || add_ev 3 "nouveau binaire SUID/SGID : $path" "$fields" "$dd" ;;
      preload)  add_ev 4 "/etc/ld.so.preload $change (persistance LD) : $path" "$fields" "$dd" ;;
      sudoersd) add_ev 4 "sudoers.d $change (privilege) : $path" "$fields" "$dd" ;;
      authkeys) add_ev 4 "authorized_keys $change (acces SSH) : $path" "$fields" "$dd" ;;
      pamd)     add_ev 4 "pam.d $change (auth) : $path" "$fields" "$dd" ;;
      rclocal)  add_ev 4 "rc.local $change (boot persistance) : $path" "$fields" "$dd" ;;
      unit)     add_ev 3 "unit systemd $change (persistance)$_usur : $path" "$fields" "$dd" ;;
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
# S36 — UNE FAMILLE QUI N'A PAS PU ETRE ENUMEREE INTERDIT LA PROMOTION AU MEME TITRE QU'UN DIFF
# RATE, et pour la meme raison : promouvoir une reference amputee fait entrer dans le connu ce que
# personne n'a lu. Un seul aveu part par passage — `plume_report_availability` nomme son enveloppe
# d'apres la source et la seconde, donc deux aveux de la meme source dans le meme passage
# s'ecraseraient. Les deux causes sont donc exclusives et la plus grave est dite en premier.
if [ "$_diff_ok" != 1 ]; then
  rm -f "$cur"
  plume_lecture_partielle integrity forme_inconnue "comparaison a la reference d'integrite en echec : la reference N'EST PAS promue, aucun constat n'entre en silence dans le connu"
elif [ -n "$_fim_famille_ko" ]; then
  rm -f "$cur"
  plume_lecture_partielle integrity "${_fim_famille_cause:-source_illisible}" "famille(s)$_fim_famille_ko NON ENUMEREE(S) ce passage (lecture en echec et aucune entree rendue, ou repertoire present mais illisible) : la reference N'EST PAS promue. L'absence de constat nouveau dans ces familles ne peut PAS en etre conclue."
else
  state_stage_file "$cur" "$BASE"
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
