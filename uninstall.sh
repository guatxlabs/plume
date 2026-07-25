#!/usr/bin/env bash
# Desinstalle le SOC (central ET/OU agent) installe par bootstrap.sh / bootstrap-agent.sh.
# Par defaut : retire binaire + collecteurs + units systemd + config, GARDE les donnees (/var/lib/plume).
#   sudo bash uninstall.sh            # retrait, donnees conservees
#   sudo bash uninstall.sh --purge    # retire AUSSI /var/lib/plume (DB, spool, cle ledger) + user soc
#   sudo bash uninstall.sh --purge -y # idem sans confirmation
# NB : ne touche PAS au depot source ~/plume (supprime-le a la main si voulu).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "!! lance en root : sudo bash uninstall.sh [--purge] [-y]"; exit 1; }

PURGE=0; YES=0
for a in "${@:-}"; do case "$a" in
  --purge) PURGE=1 ;;
  -y|--yes) YES=1 ;;
  "") ;;
  *) echo "option inconnue: $a"; exit 1 ;;
esac; done

echo ">> Desinstallation du SOC"
units=$(systemctl list-unit-files 'plume-*' --no-legend 2>/dev/null | awk '{print $1}' || true)
[ -n "$units" ] && echo "   units a retirer : $(echo "$units" | tr '\n' ' ')"
if [ "$PURGE" = 1 ]; then
  echo "   !! MODE PURGE : /var/lib/plume (DB, spool, cle ledger) ET le user 'soc' seront SUPPRIMES."
else
  echo "   donnees /var/lib/plume CONSERVEES (utilise --purge pour tout supprimer)."
fi
if [ "$YES" != 1 ]; then
  printf "   Continuer ? [y/N] "; read -r r; case "$r" in y|Y) ;; *) echo "annule."; exit 0 ;; esac
fi

# 1. Stop + disable tous les timers/services plume-* (collecteurs) + le daemon central.
for u in $units plume-daemon.service; do systemctl disable --now "$u" 2>/dev/null || true; done

# 2. Tue un eventuel tunnel reverse-ssh agent->central (ssh -fN -R 7000:...).
pkill -f 'ssh .*-R .*7000' 2>/dev/null || true

# 3. Retire les unit files systemd.
rm -f /etc/systemd/system/plume-*.service /etc/systemd/system/plume-*.timer
systemctl daemon-reload 2>/dev/null || true

# 4. Binaire + collecteurs + config (la config peut contenir des tokens).
rm -f  /usr/local/bin/plume-daemon
rm -rf /usr/local/lib/plume
rm -rf /etc/plume

# 5. Regles auditd posees par le SOC (si presentes) + reload.
if [ -f /etc/audit/rules.d/plume.rules ]; then
  rm -f /etc/audit/rules.d/plume.rules
  command -v augenrules >/dev/null 2>&1 && augenrules --load 2>/dev/null || true
fi

# 6. Donnees + user (uniquement en --purge).
if [ "$PURGE" = 1 ]; then
  rm -rf /var/lib/plume
  userdel soc 2>/dev/null || true
  groupdel soc 2>/dev/null || true
  echo ">> Purge complete : donnees + user 'soc' supprimes."
else
  echo ">> Donnees conservees dans /var/lib/plume. Pour tout supprimer : sudo bash uninstall.sh --purge"
fi
echo ">> SOC desinstalle. (Le depot source $(cd "$(dirname "$0")" && pwd) n'est pas touche.)"
