#!/bin/sh
# Capteur Plume : Control Catalog (« zéro-trou ») MODE-AWARE. Vérifie que les contrôles de défense
# ATTENDUS sont présents et vivants -> snapshot 'controls' (failed>0 = alerte). ROOT, lecture seule.
#
# Mode-aware (cf project deployment-modes : k3s / hôte-natif / container) : chaque contrôle n'est
# inclus QUE s'il S'APPLIQUE dans cet environnement (auto-détection sur l'outil présent) -> pas de
# faux "manquant" hors-contexte (ex : ne PAS exiger sshd inactif sur un serveur, ni wlan0 sur un VPS).
# Extensible sans toucher au script : /etc/plume/controls.d/*.check (lignes "id|commande", rc 0 = OK).
set -eu
. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"
plume_init
# S36, RANG « DU BRUIT AU LIEU DU SILENCE » — « JE N'AI PAS PU LIRE » N'EST PAS « LE CONTROLE EST
# MANQUANT ». Chaque sonde de ce capteur rendait DEUX verdicts, et l'echec de la sonde elle-meme
# tombait du cote `false` : `sysctl -n` dont la sortie est vide (`/proc` masque, conteneur, cle
# renommee), `systemctl is-active` quand il n'y a pas de gestionnaire de services joignable,
# `iptables -C` dont le code de retour vaut 2 ou plus (verrou xtables, module absent, droits). Le
# daemon compte `failed > 0` et leve l'alerte livree `control.catalog` (severite 3, dedupliquee sur
# l'ETAT et le jour) : une sonde qui echoue de facon intermittente CHANGE l'empreinte d'etat, donc
# refait une alerte a chaque bascule. C'est l'usure — l'exploitant finit par ne plus ouvrir « n
# controle(s) de defense MANQUANT(S) », et le jour ou c'est vrai il ne le lira pas.
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

# --- Spécifique hôte type laptop : docker-lan-lockdown UNIQUEMENT si l'interface wifi existe ---
IFACE="${PLUME_LOCKDOWN_IFACE:-wlan0}"
if command -v iptables >/dev/null 2>&1 && ip link show "$IFACE" >/dev/null 2>&1; then
  PORTS="${PLUME_LOCKDOWN_PORTS:-5900,6080,8080,8081,8090,5173}"
  # Meme distinction que dans `firewall.sh` : `iptables -C` rend 1 quand la regle n'est PAS la (un
  # verdict) et >=2 quand la verification n'a pas pu avoir lieu (verrou xtables, module, droits).
  chk(){ if "$@" >/dev/null 2>&1; then echo true; else case $? in 1) echo false ;; *) echo indetermine ;; esac; fi; }
  add docker_lockdown_v4 "$(chk iptables  -C DOCKER-USER -i "$IFACE" -d 172.16.0.0/12 -m conntrack --ctstate NEW -j DROP)" 'DROP LAN->docker (v4)'
  add docker_lockdown_v6 "$(chk ip6tables -C INPUT -i "$IFACE" -p tcp -m multiport --dports "$PORTS" -m conntrack --ctstate NEW -j DROP)" 'lockdown INPUT (v6)'
fi

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

[ -z "$items" ] && plume_exit_nodata
hash=$(printf '%s' "$hash" | sha256sum | cut -d' ' -f1)
spool_write "controls-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"controls","hash":"%s","data":{"failed":%s,"controls":[%s]}}' "$ts" "$host" "$hash" "$failed" "$items")"
