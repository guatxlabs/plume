#!/bin/sh
# Capteur Plume : Control Catalog (« zéro-trou ») MODE-AWARE. Vérifie que les contrôles de défense
# ATTENDUS sont présents et vivants -> snapshot 'controls' (failed>0 = alerte). ROOT, lecture seule.
#
# Mode-aware (cf project deployment-modes : k3s / hôte-natif / container) : chaque contrôle n'est
# inclus QUE s'il S'APPLIQUE dans cet environnement (auto-détection sur l'outil présent) -> pas de
# faux "manquant" hors-contexte (ex : ne PAS exiger `auditd` actif là où auditd n'est pas installé).
# Extensible sans toucher au script : /etc/plume/controls.d/*.check (lignes "id|commande", rc 0 = OK).
#
# CE QUE CE CATALOGUE NE SAIT PAS ENCORE FAIRE, ET C'EST DIT ICI PARCE QUE C'EST LA PREMIÈRE CHOSE QU'UN
# EXPLOITANT DEMANDE (P11.18-i) : on ne peut qu'AJOUTER des contrôles, et seulement depuis le système de
# fichiers de l'hôte. Aucun mécanisme ne permet d'en RETIRER ni d'en MODIFIER un depuis la console — les
# règles de détection, elles, se désactivent avec une trace au journal inaltérable. Tant que ce n'est pas
# fait, la seule prise sur une alerte jugée envahissante est ce fichier-ci. Un catalogue VIDE, lui, ne
# rend plus une posture verte : il se DIT (voir la publication en fin de script).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
# S36, RANG « DU BRUIT AU LIEU DU SILENCE » — « JE N'AI PAS PU LIRE » N'EST PAS « LE CONTROLE EST
# MANQUANT ». Chaque sonde de ce capteur rendait DEUX verdicts, et l'echec de la sonde elle-meme
# tombait du cote `false` : `sysctl -n` dont la sortie est vide (`/proc` masque, conteneur, cle
# renommee), `systemctl is-active` quand il n'y a pas de gestionnaire de services joignable,
# une verification externe dont le code de retour ne separe pas « pas la » de « pas verifiable ». Le
# daemon compte `failed > 0` et leve l'alerte livree `control.catalog` (severite 3, dedupliquee sur
# l'ETAT et le jour) : une sonde qui echoue de facon intermittente CHANGE l'empreinte d'etat, donc
# refait une alerte a chaque bascule. C'est l'usure — l'exploitant finit par ne plus ouvrir une alerte
# qui n'annonce qu'un COMPTE, et le jour ou c'est vrai il ne le lira pas. Depuis `P11.18-i` cette alerte
# NOMME les controles manquants, la machine et depuis quand : elle reste dedupliquee de la meme facon,
# mais elle se lit sans ouvrir quoi que ce soit.
#
# LE TROISIEME VERDICT S'APPELLE `indetermine`, il vaut `null` sur le fil, il ne compte PAS dans
# `failed`, et il est AVOUE. Ce n'est pas se taire : le controle reste dans la liste, avec sa cause,
# et l'aveu passe par le canal ou la regle livree `de-collector-unavailable` alerte deja.
sx(){ # <cle sysctl> <valeur attendue> -> true | false | indetermine
  if _sxv=$(sysctl -n "$1" 2>/dev/null) && [ -n "$_sxv" ]; then
    [ "$_sxv" = "$2" ] && echo true || echo false
  else
    echo indetermine
  fi
}
svc_actif(){ # <unite> -> true | false | indetermine  (pas de gestionnaire joignable = pas un verdict)
  _sav=$(systemctl is-active "$1" 2>/dev/null || true)
  case "$_sav" in
    active) echo true ;;
    inactive|failed|deactivating|activating|reloading) echo false ;;
    *) echo indetermine ;;
  esac
}
items=""; failed=0; hash=""; indetermines=""
add(){ # id verdict detail  (modifie les globals items/failed/hash/indetermines)
  case "$2" in
    true|false)
      items="$items${items:+,}$(printf '{"id":"%s","ok":%s,"detail":"%s"}' "$1" "$2" "$3")"
      [ "$2" = false ] && failed=$((failed+1)) || true
      ;;
    *)
      # `ok:null` — NI tenu, NI manquant. Le champ garde son nom (les consommateurs le lisent deja)
      # et porte en plus le VERDICT et la CAUSE, dans le vocabulaire ferme partage avec le demon.
      items="$items${items:+,}$(printf '{"id":"%s","ok":null,"verdict":"indetermine","cause":"%s","detail":"%s"}' \
        "$1" "$(plume_cause_fermee source_illisible)" "$3")"
      indetermines="$indetermines $1"
      ;;
  esac
  hash="$hash$2"
}

# --- Universels : s'appliquent partout où l'outil existe ---
if command -v sysctl >/dev/null 2>&1; then
  # kptr_restrict : 1 (cache aux non-root) OU 2 (cache à tous, plus strict) -> les deux OK (>=1).
  # `${kpr:-0}` transformait une lecture RATEE en « 0 », c'est-a-dire en « protection desactivee ».
  kpr=$(sysctl -n kernel.kptr_restrict 2>/dev/null || true)
  case "${kpr:-}" in
    ''|*[!0-9]*) add sysctl_kptr_restrict indetermine 'kptr_restrict>=1' ;;
    *) [ "$kpr" -ge 1 ] && add sysctl_kptr_restrict true 'kptr_restrict>=1' \
                        || add sysctl_kptr_restrict false 'kptr_restrict>=1' ;;
  esac
  add sysctl_suid_dumpable "$(sx fs.suid_dumpable 0)" 'suid_dumpable=0'
fi
command -v auditctl       >/dev/null 2>&1 && add auditd_active   "$(svc_actif auditd)"   'auditd actif'
command -v fail2ban-client >/dev/null 2>&1 && add fail2ban_active "$(svc_actif fail2ban)" 'fail2ban actif'
# aide_db : la base peut être dans un répertoire _aide 0700 illisible par le capteur durci (caps DAC
# droppées) -> on accepte aussi aide.db.new.gz OU un timer aide planifié (systemctl, sans accès fichier).
# S36 — la jambe « planifiee » de ce controle passe par `systemctl` ; sans gestionnaire de services
# joignable elle rend TOUJOURS faux, et l'absence de fichier lisible (le repertoire _aide peut etre
# 0700, c'est ecrit ci-dessus) ne prouve alors rien. Sans signal positif ET sans moyen d'interroger
# le gestionnaire, le controle n'est pas manquant : il n'est pas etabli.
aide_verdict(){
  if [ -f /var/lib/aide/aide.db ] || [ -f /var/lib/aide/aide.db.gz ] || [ -f /var/lib/aide/aide.db.new.gz ] \
     || systemctl is-enabled dailyaidecheck.timer >/dev/null 2>&1 \
     || systemctl is-enabled aidecheck.timer >/dev/null 2>&1 \
     || systemctl is-enabled aidecheck.service >/dev/null 2>&1; then
    echo true
  # `show --property=Version` est un aller-retour vers le GESTIONNAIRE : il repond 0 des qu'il est
  # joignable, y compris sur un systeme « degraded » — contrairement a `is-system-running`, dont
  # l'echec dirait « degrade » et non « injoignable », et rendrait indetermine un vrai manquant.
  elif command -v systemctl >/dev/null 2>&1 && systemctl show --property=Version >/dev/null 2>&1; then
    echo false
  else
    echo indetermine
  fi
}
command -v aide           >/dev/null 2>&1 && add aide_db         "$(aide_verdict)" 'base AIDE présente/planifiée'

# --- CE QUE CE CATALOGUE N'ATTEND PLUS, ET POURQUOI (P11.18-i, mesuré le 2026-08-25) ---
# Deux entrées — `docker_lockdown_v4` et `docker_lockdown_v6` — vérifiaient deux des trois jambes d'un
# verrou iptables posé sur une interface wifi et une liste de ports. Elles sont RETIRÉES, pas
# désactivées : un contrôle qui n'a plus lieu d'être ne se désactive pas, il se retire.
#   (a) LE MÊME CONTRÔLE EST DÉJÀ PORTÉ PAR LA VOIE `firewall`. `collectors/firewall.sh` évalue les
#       TROIS jambes sous la MÊME condition d'applicabilité (iptables présent ET interface présente),
#       rend `indetermine` quand `-C` ne conclut pas, et le daemon en lève l'alerte DÉDIÉE
#       `firewall.lockdown` — une par machine et par jour. Un hôte concerné recevait donc DEUX alertes
#       par jour pour UN SEUL fait. Et les deux ne s'accordaient pas : ce catalogue omettait la jambe
#       `INPUT (v4)`, si bien qu'un verrou v4 disparu se comptait « 1 manquant » ici pendant que la
#       voie `firewall` disait « ABSENT ».
#   (b) LE PRODUIT N'INSTALLE RIEN DE CE QU'ELLES EXIGENT. Aucun artefact livré — unité systemd,
#       manifeste de déploiement, bootstrap — ne CRÉE cette règle : les seules occurrences de la chaîne
#       dans l'arbre étaient les vérifications elles-mêmes. Les ports visés (bureau distant, serveur de
#       développement front) ne sont ceux d'AUCUN service de ce produit, dont le seul port publié est
#       7000. Un catalogue qui exige une règle que rien ne pose est MANQUANT pour toujours sur toute
#       machine qui porte l'interface visée : c'est l'alerte que l'exploitant ne peut ni comprendre,
#       ni clore, ni retirer.
# CE QUI EST PERDU, ET C'EST DIT : sur un hôte qui a iptables et l'interface mais dont le ruleset nft
# est absent ou illisible, `firewall.sh` sort par `plume_unavailable` et ne rend AUCUN verdict sur ce
# verrou. Le trou n'est pas silencieux — cette sortie lève déjà l'alerte de capteur indisponible — mais
# il n'est plus comblé par ce catalogue.

# --- Contrôles propres au déploiement (k3s : crowdsec pod, etc.) sans toucher au script générique ---
for f in /etc/plume/controls.d/*.check; do
  [ -r "$f" ] || continue
  while IFS='|' read -r cid ccmd; do
    [ -n "${cid:-}" ] || continue
    case "$cid" in \#*) continue ;; esac
    if sh -c "$ccmd" >/dev/null 2>&1; then add "$cid" true "$cid"; else add "$cid" false "$cid"; fi
  done < "$f"
done

# LE TROU EST DIT. Un controle `indetermine` ne compte pas dans `failed` — il ne DOIT donc pas
# disparaitre pour autant : sans cet aveu, un capteur qui ne saurait plus rien lire publierait
# « 0 manquant », c'est-a-dire la valeur la plus rassurante de la serie. La regle livree
# `de-collector-unavailable` alerte sur ce canal.
if [ -n "$indetermines" ]; then
  plume_lecture_partielle controls source_illisible \
    "controle(s) NON ETABLI(S) ce passage (ni tenu(s), ni manquant(s)) :$indetermines. Ils ne comptent PAS dans failed — le compte de controles manquants publie est donc un MINORANT tant que c'est le cas."
fi

# UN CATALOGUE VIDE SE DIT — IL NE SE TAIT PAS (P11.18-i). Ce capteur sortait ici par « rien de neuf »
# quand AUCUN contrôle ne s'appliquait : aucun instantané n'était jamais publié, la sonde de fraîcheur
# restait « inconnu » (jamais « muet » : elle n'a rien vu du tout), et le panneau affichait « en attente
# du capteur » indéfiniment. Une machine où RIEN n'est mesuré se lisait donc comme une machine dont le
# capteur n'a pas encore parlé. On publie désormais l'instantané VIDE : il porte `failed:0` et une liste
# `controls` vide, et c'est le daemon qui en tire l'alerte `control.catalog.vide` — la propriété est
# « zéro contrôle évalué », jamais la RAISON du zéro, de sorte qu'un catalogue retiré ou entièrement
# désactivé s'y dira de la même façon. Rien n'est acquitté au passage : ce capteur ne met aucun marqueur
# de progression en attente (c'est ce que `plume_exit_nodata` faisait ici, et il n'avait rien à écrire).
hash=$(printf '%s' "$hash" | sha256sum | cut -d' ' -f1)
spool_write "controls-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"controls","hash":"%s","data":{"failed":%s,"controls":[%s]}}' "$ts" "$host" "$hash" "$failed" "$items")"
