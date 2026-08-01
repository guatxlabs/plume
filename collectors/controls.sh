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
sx(){ [ "$(sysctl -n "$1" 2>/dev/null)" = "$2" ] && echo true || echo false; }
items=""; failed=0; hash=""
add(){ # id ok detail  (modifie les globals items/failed/hash)
  items="$items${items:+,}$(printf '{"id":"%s","ok":%s,"detail":"%s"}' "$1" "$2" "$3")"
  [ "$2" = false ] && failed=$((failed+1)) || true
  hash="$hash$2"
}

# --- Universels : s'appliquent partout où l'outil existe ---
if command -v sysctl >/dev/null 2>&1; then
  # kptr_restrict : 1 (cache aux non-root) OU 2 (cache à tous, plus strict) -> les deux OK (>=1).
  kpr=$(sysctl -n kernel.kptr_restrict 2>/dev/null)
  add sysctl_kptr_restrict "$([ "${kpr:-0}" -ge 1 ] 2>/dev/null && echo true || echo false)" 'kptr_restrict>=1'
  add sysctl_suid_dumpable "$(sx fs.suid_dumpable 0)" 'suid_dumpable=0'
fi
command -v auditctl       >/dev/null 2>&1 && add auditd_active   "$([ "$(systemctl is-active auditd 2>/dev/null)" = active ] && echo true || echo false)" 'auditd actif'
command -v fail2ban-client >/dev/null 2>&1 && add fail2ban_active "$([ "$(systemctl is-active fail2ban 2>/dev/null)" = active ] && echo true || echo false)" 'fail2ban actif'
# aide_db : la base peut être dans un répertoire _aide 0700 illisible par le capteur durci (caps DAC
# droppées) -> on accepte aussi aide.db.new.gz OU un timer aide planifié (systemctl, sans accès fichier).
command -v aide           >/dev/null 2>&1 && add aide_db         "$( { [ -f /var/lib/aide/aide.db ] || [ -f /var/lib/aide/aide.db.gz ] || [ -f /var/lib/aide/aide.db.new.gz ] || systemctl is-enabled dailyaidecheck.timer >/dev/null 2>&1 || systemctl is-enabled aidecheck.timer >/dev/null 2>&1 || systemctl is-enabled aidecheck.service >/dev/null 2>&1; } && echo true || echo false)" 'base AIDE présente/planifiée'

# --- Spécifique hôte type laptop : docker-lan-lockdown UNIQUEMENT si l'interface wifi existe ---
IFACE="${PLUME_LOCKDOWN_IFACE:-wlan0}"
if command -v iptables >/dev/null 2>&1 && ip link show "$IFACE" >/dev/null 2>&1; then
  PORTS="${PLUME_LOCKDOWN_PORTS:-5900,6080,8080,8081,8090,5173}"
  chk(){ if "$@" >/dev/null 2>&1; then echo true; else echo false; fi; }
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

[ -z "$items" ] && plume_exit_nodata
hash=$(printf '%s' "$hash" | sha256sum | cut -d' ' -f1)
spool_write "controls-$ts.json" "$(printf '{"ts":%s,"host":"%s","kind":"controls","hash":"%s","data":{"failed":%s,"controls":[%s]}}' "$ts" "$host" "$hash" "$failed" "$items")"
