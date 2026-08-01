#!/usr/bin/env bash
# Installe le SOC en mode AGENT : capteurs génériques + shipper -> central. PAS de daemon/DB/web.
# Auth recommandée par TOKEN (créé sur le central : plume-daemon token <nom>) :
#   sudo env PLUME_CENTRAL=https://soc.central:7000 PLUME_TOKEN='...' bash bootstrap-agent.sh
# (ou basic : PLUME_USER=admin PLUME_PASS='motdepasse')
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"

getent group  soc >/dev/null || groupadd -r soc
getent passwd soc >/dev/null || useradd -r -g soc -s /usr/sbin/nologin -d /var/lib/plume soc
install -d -o root -g soc  -m 2750 /var/lib/plume
install -d -o root -g soc  -m 2770 /var/lib/plume/spool
install -d -o root -g root -m 0750 /var/lib/plume/state
install -d -m0755 /usr/local/lib/plume/collectors
install -d -o root -g soc  -m 0750 /etc/plume

# Librairie POSIX-sh partagee sourcee par les collecteurs (spool/heartbeat/json_escape/kctl...).
# Doit etre en place AVANT tout collecteur (chaque collectors/*.sh fait `. .../lib.sh`).
install -m0644 "$SRC/collectors/lib.sh" /usr/local/lib/plume/collectors/lib.sh

# install_collector <nom> [binaire] — pose le collecteur (script $SRC/collectors/<nom>.sh, OU le
# binaire prebuild fourni en $2 sous le nom plume-<nom>), son unit .service/.timer si presents, et le
# drop-in de durcissement commun (SystemCallFilter=@system-service + Protect* alignes sur le daemon).
# Remplace le bloc `install -m0755 collecteur; install unit; install timer` duplique ~40 fois. NON active.
COMMON_HARDENING="$SRC/systemd/plume-collector-common.conf"
install_collector() {
  _ic_name="$1"; _ic_bin="${2:-}"
  if [ -n "$_ic_bin" ]; then
    install -m0755 "$_ic_bin" "/usr/local/lib/plume/collectors/plume-$_ic_name"
  elif [ -f "$SRC/collectors/$_ic_name.sh" ]; then
    install -m0755 "$SRC/collectors/$_ic_name.sh" /usr/local/lib/plume/collectors/
  else
    echo "!! collecteur inconnu (pas de collectors/$_ic_name.sh) : $_ic_name"; return 0
  fi
  _ic_unit="plume-$_ic_name"
  [ -f "$SRC/systemd/$_ic_unit.service" ] && install -m0644 "$SRC/systemd/$_ic_unit.service" /etc/systemd/system/
  [ -f "$SRC/systemd/$_ic_unit.timer" ]   && install -m0644 "$SRC/systemd/$_ic_unit.timer"   /etc/systemd/system/
  if [ -f "$SRC/systemd/$_ic_unit.service" ] && [ -f "$COMMON_HARDENING" ]; then
    install -d -m0755 "/etc/systemd/system/$_ic_unit.service.d"
    install -m0644 "$COMMON_HARDENING" "/etc/systemd/system/$_ic_unit.service.d/50-plume-hardening.conf"
  fi
}

# Config : 1er install -> exige PLUME_CENTRAL (+ PLUME_TOKEN ou USER/PASS) et l'ecrit. Re-run -> conf
# existante CONSERVEE (maj des collecteurs SANS repasser les secrets) -> 'git pull && sudo bash ...' est sur.
if [ -f /etc/plume/plume.conf ]; then
  echo ">> /etc/plume/plume.conf present -> conserve (re-run : mise a jour des collecteurs)."
  # shellcheck disable=SC1091
  . /etc/plume/plume.conf
else
  : "${PLUME_CENTRAL:?PLUME_CENTRAL requis (1er install)}"
  if [ -z "${PLUME_TOKEN:-}" ] && { [ -z "${PLUME_USER:-}" ] || [ -z "${PLUME_PASS:-}" ]; }; then
    echo "!! fournis PLUME_TOKEN (recommande) OU PLUME_USER+PLUME_PASS"; exit 1
  fi
  umask 027
  {
    echo "PLUME_CENTRAL=$PLUME_CENTRAL"
    [ -n "${PLUME_TOKEN:-}" ] && echo "PLUME_TOKEN=$PLUME_TOKEN"
    [ -n "${PLUME_USER:-}" ] && echo "PLUME_USER=$PLUME_USER"
    [ -n "${PLUME_PASS:-}" ] && echo "PLUME_PASS=$PLUME_PASS"
    echo "PLUME_SPOOL=/var/lib/plume/spool"
    echo "PLUME_STATE=/var/lib/plume/state"
    # --- options collecteurs (lues par les units via EnvironmentFile=/etc/plume/plume.conf) ---
    # PLUME_MAIL_F2B=1 -> bans.sh lit le fail2ban INTERNE du mailserver (docker-mailserver/k3s) =
    #   bans mail (postfix/dovecot) visibles dans le SOC. Défaut 0 (générique : aucun mailserver supposé).
    # PAS de commentaire en fin de ligne de valeur (systemd EnvironmentFile ne les retire pas).
    echo "PLUME_MAIL_F2B=${PLUME_MAIL_F2B:-0}"
  } > /etc/plume/plume.conf
  chgrp soc /etc/plume/plume.conf && chmod 0640 /etc/plume/plume.conf
fi
echo ">> Agent SOC depuis $SRC -> central $PLUME_CENTRAL"

for c in resources integrity ship; do
  install_collector "$c"
done

# --- collecteurs OPT-IN host-safe : PLUME_EXTRA_COLLECTORS="conntrack nft ufw mail crowdsec falco ..." ---
# Installes (NON actives = regle d'or) ; l'operateur active ce qu'il veut.
for c in ${PLUME_EXTRA_COLLECTORS:-}; do
  if [ -f "$SRC/collectors/$c.sh" ]; then
    install_collector "$c"
    echo ">> collecteur opt-in installe (NON active) : $c  ->  systemctl enable --now plume-$c.timer"
  else
    echo "!! collecteur inconnu (pas de collectors/$c.sh) : $c"
  fi
done

# --- gabarit de regles auditd + chargeur VERIFIE ---------------------------------------------------
# DEFAUT MESURE le 2026-08-01 (VM Ubuntu 24.04 Server fraiche) : le gabarit `plume-audit.rules` n'etait
# pose que par bootstrap.sh (le CENTRAL). Sur un AGENT, le chemin que le gabarit documentait lui-meme
# (/usr/local/share/plume/) N'EXISTAIT PAS -> l'operateur qui suivait la doc ne trouvait rien, et
# `auditd.sh` tournait sans aucune regle, donc sans remonter le moindre execve. On pose donc les deux
# fichiers ICI AUSSI, au chemin que la doc annonce.
# REGLE D'OR RESPECTEE : on POSE, on n'ACTIVE PAS. Charger des regles d'audit modifie la politique de
# journalisation du noyau et a un cout en volume : c'est une decision d'exploitant, pas un effet de bord
# d'une installation d'agent. Le chargeur est fourni pret a l'emploi, et il REFUSE un chargement partiel.
install -d -m0755 /usr/local/share/plume
install -m0644 "$SRC/systemd/plume-audit.rules" /usr/local/share/plume/plume-audit.rules
install -m0755 "$SRC/systemd/plume-audit-rules-load.sh" /usr/local/lib/plume/plume-audit-rules-load.sh
echo ">> gabarit auditd pose (NON charge) : /usr/local/share/plume/plume-audit.rules"
echo "   pour l'armer :  sudo apt install auditd  &&  sudo bash /usr/local/lib/plume/plume-audit-rules-load.sh"

# --- collector-mail (OPT-IN : PLUME_WITH_MAIL=1) : detection mail host-native (cf. deploy/MAIL.md, ADR-0008) ---
if [ "${PLUME_WITH_MAIL:-0}" = "1" ]; then
  MAILBIN="$SRC/collector-mail/target/release/plume-collector-mail"
  if [ ! -x "$MAILBIN" ] && command -v cargo >/dev/null 2>&1; then
    echo ">> build collector-mail (cargo release)..."
    ( cd "$SRC/collector-mail" && cargo build --release )
  fi
  if [ -x "$MAILBIN" ]; then
    install -m0755 "$MAILBIN" /usr/local/lib/plume/collectors/plume-collector-mail
    install -m0644 "$SRC/systemd/plume-collector-mail.service" /etc/systemd/system/
    install -m0644 "$SRC/systemd/plume-collector-mail.timer"   /etc/systemd/system/
    if [ ! -f /etc/plume/mail.conf ]; then
      umask 027
      {
        echo "# collector-mail (ADR-0008). Renseigne la racine maildir host PUIS :"
        echo "#   sudo systemctl enable --now plume-collector-mail.timer"
        echo "PLUME_MAIL_ROOT=${PLUME_MAIL_ROOT:-/opt/local-path-provisioner/CHANGEME_mail_mail-data-mailserver-0}"
        echo "PLUME_MAIL_DOMAIN=${PLUME_MAIL_DOMAIN:-localhost}"
        echo "PLUME_SPOOL=/var/lib/plume/spool"
      } > /etc/plume/mail.conf
      chgrp soc /etc/plume/mail.conf && chmod 0640 /etc/plume/mail.conf
    fi
    echo ">> collector-mail installe (OPT-IN, NON active). Edite /etc/plume/mail.conf puis: systemctl enable --now plume-collector-mail.timer"
  else
    echo "!! collector-mail non installe (binaire absent + cargo indisponible) -> build sur une machine Rust, copie collector-mail/target/release/plume-collector-mail"
  fi
fi

# --- collector-syslog (OPT-IN : PLUME_WITH_SYSLOG=1) : recepteur syslog RFC5424/RFC3164 :514 + parser ---
# FortiGate (cf. deploy/SYSLOG.md). SERVICE long-running (pas un timer) ; ship.sh expedie le spool.
if [ "${PLUME_WITH_SYSLOG:-0}" = "1" ]; then
  SYSLOGBIN="$SRC/collector-syslog/target/release/plume-collector-syslog"
  if [ ! -x "$SYSLOGBIN" ] && command -v cargo >/dev/null 2>&1; then
    echo ">> build collector-syslog (cargo release)..."
    ( cd "$SRC/collector-syslog" && cargo build --release )
  fi
  if [ -x "$SYSLOGBIN" ]; then
    install -m0755 "$SYSLOGBIN" /usr/local/lib/plume/collectors/plume-collector-syslog
    install -m0644 "$SRC/systemd/plume-collector-syslog.service" /etc/systemd/system/
    if [ ! -f /etc/plume/syslog.conf ]; then
      umask 027
      {
        echo "# collector-syslog : recepteur syslog (FortiGate + appareils reseau generiques)."
        echo "#   Pointe ton FortiGate/switch/routeur vers CE host, port 514 (UDP ET/OU TCP)."
        echo "#   TCP recommande pour les feeds volumineux (pas de troncature UDP au MTU). Puis :"
        echo "#     sudo systemctl enable --now plume-collector-syslog.service"
        echo "PLUME_SPOOL=/var/lib/plume/spool"
        echo "PLUME_SYSLOG_PARSER=${PLUME_SYSLOG_PARSER:-fortigate}   # fortigate | auto | generic"
        echo "PLUME_SYSLOG_SOURCE=${PLUME_SYSLOG_SOURCE:-fortigate}"
        echo "PLUME_SYSLOG_UDP=${PLUME_SYSLOG_UDP:-0.0.0.0:514}       # vider = desactiver l'UDP"
        echo "PLUME_SYSLOG_TCP=${PLUME_SYSLOG_TCP:-0.0.0.0:514}       # vider = desactiver le TCP"
        echo "# DURCISSEMENT (syslog = NON authentifie) : restreins :514 a tes appareils. 2 couches :"
        echo "#  1) allowlist applicative (CIDR/IP separes par virgule) — vide = TOUT accepte (deconseille) :"
        echo "PLUME_SYSLOG_ALLOW=${PLUME_SYSLOG_ALLOW:-}          # ex: 203.0.113.10/32,10.0.0.0/8"
        echo "#  2) pare-feu hote (default-deny) — a poser MANUELLEMENT vers le/les CIDR FortiGate, ex :"
        echo "#     sudo ufw allow from <CIDR-FortiGate> to any port 514   # (puis 'ufw deny 514' hors liste)"
        echo "# PLUME_SYSLOG_TZ=+0100          # tz du device si ses logs n'ont PAS de champ tz (sinon UTC)"
        echo "PLUME_SYSLOG_BATCH_MAX=${PLUME_SYSLOG_BATCH_MAX:-500}"
        echo "PLUME_SYSLOG_FLUSH_MS=${PLUME_SYSLOG_FLUSH_MS:-2000}"
      } > /etc/plume/syslog.conf
      chgrp soc /etc/plume/syslog.conf && chmod 0640 /etc/plume/syslog.conf
    fi
    echo ">> collector-syslog installe (OPT-IN, NON active). Edite /etc/plume/syslog.conf puis: systemctl enable --now plume-collector-syslog.service"
    echo "   SECURITE : :514 est NON authentifie. AVANT d'activer, restreins la source — PLUME_SYSLOG_ALLOW=<CIDR> ET une regle pare-feu (ufw/nft) default-deny vers le :514 (cf. deploy/SYSLOG.md, section Durcissement)."
  else
    echo "!! collector-syslog non installe (binaire absent + cargo indisponible) -> build sur une machine Rust, copie collector-syslog/target/release/plume-collector-syslog"
  fi
fi

# --- responder agent (OPT-IN : PLUME_WITH_RESPONDER=1) : applique les bans/unbans decides par le central ---
# Modele pull (aucune entree reseau sur l'agent). Double securite : timer NON active + DRY-RUN par defaut.
if [ "${PLUME_WITH_RESPONDER:-0}" = "1" ]; then
  install -m0755 "$SRC/collectors/respond.sh" /usr/local/lib/plume/collectors/respond.sh
  install -m0644 "$SRC/systemd/plume-respond-agent.service" /etc/systemd/system/
  install -m0644 "$SRC/systemd/plume-respond-agent.timer"   /etc/systemd/system/
  if [ ! -f /etc/plume/responder.conf ]; then
    umask 027
    {
      echo "# responder agent. Enforcement delegue a CrowdSec (cscli) > fail2ban > nft."
      echo "# !! PLUME_TOKEN doit etre un token LIE A CET HOTE (anti-IDOR). Sur le central :"
      echo "#      plume-daemon token agent-$(hostname) $(hostname)   # le 2e arg = hostname vu dans les events"
      echo "#    et reporte-le ci-dessous (et dans plume.conf pour l'ingest). Un token non-lie est refuse ici."
      echo "# Pour PASSER EN REEL : PLUME_RESPONDER_APPLY=1 puis: sudo systemctl enable --now plume-respond-agent.timer"
      echo "PLUME_CENTRAL=$PLUME_CENTRAL"
      # Host override (central atteint par ClusterIP) + SNI dedie mTLS : ex soc-ingest.example.com
      [ -n "${PLUME_HOST_HEADER:-}" ] && echo "PLUME_HOST_HEADER=$PLUME_HOST_HEADER"
      [ -n "${PLUME_TOKEN:-}" ] && echo "PLUME_TOKEN=$PLUME_TOKEN"
      [ -z "${PLUME_TOKEN:-}" ] && [ -n "${PLUME_USER:-}" ] && echo "PLUME_USER=$PLUME_USER"
      [ -z "${PLUME_TOKEN:-}" ] && [ -n "${PLUME_PASS:-}" ] && echo "PLUME_PASS=$PLUME_PASS"
      echo "PLUME_HOST_LABEL=${PLUME_HOST_LABEL:-$(hostname)}"
      echo "PLUME_RESPONDER=1"
      echo "PLUME_RESPONDER_APPLY=0          # 0 = dry-run (remonte ce qui SERAIT fait). Mettre 1 pour appliquer."
      echo "PLUME_BAN_BACKEND=auto           # auto|crowdsec|fail2ban|nft"
      echo "PLUME_BAN_DURATION=4h"
      echo "PLUME_FAIL2BAN_JAIL=sshd"
      # mTLS : si le central exige un cert client (ex soc-ingest.example.com), memes certs que l'ingest.
      [ -n "${PLUME_TLS_CACERT:-}" ] && echo "PLUME_TLS_CACERT=$PLUME_TLS_CACERT"
      [ -n "${PLUME_TLS_CERT:-}" ] && echo "PLUME_TLS_CERT=$PLUME_TLS_CERT"
      [ -n "${PLUME_TLS_KEY:-}" ] && echo "PLUME_TLS_KEY=$PLUME_TLS_KEY"
      # CrowdSec en mode k3s (unban via \`kubectl exec\` du pod LAPI) : ns/deploy configurables.
      echo "PLUME_CROWDSEC_NS=${PLUME_CROWDSEC_NS:-crowdsec}"
      echo "PLUME_CROWDSEC_LAPI=${PLUME_CROWDSEC_LAPI:-crowdsec-lapi}"
      echo "PLUME_RESPONDER_ALLOW=/etc/plume/responder.allow"
    } > /etc/plume/responder.conf
    chgrp soc /etc/plume/responder.conf && chmod 0640 /etc/plume/responder.conf
  fi
  if [ ! -f /etc/plume/responder.allow ]; then
    {
      echo "# IP a NE JAMAIS bannir (1 par ligne). RFC1918/loopback/lien-local + le central sont DEJA exclus."
      echo "# Ajoute ici tes IP d'admin / sauts SSH de confiance."
    } > /etc/plume/responder.allow
    chgrp soc /etc/plume/responder.allow && chmod 0640 /etc/plume/responder.allow
  fi
  echo ">> responder agent installe (OPT-IN, NON active, DRY-RUN). Edite /etc/plume/responder.{conf,allow} puis: systemctl enable --now plume-respond-agent.timer"
fi

# --- relais audit MinIO (OPT-IN : PLUME_WITH_MINIO_AUDIT=1) : telemetrie d'acces objet -> source=minio-audit ---
# Recepteur webhook MinIO (long-running, User=soc, bind cni0). Reformate {bucket,object,api,accessKey,src_ip,
# status,request_id} -> spool -> ship.sh (mTLS). La conf MinIO (audit_webhook) est posee par
# votre runbook de provisionnement d'acces au cluster. cf. collectors/minio-audit-relay.py.
if [ "${PLUME_WITH_MINIO_AUDIT:-0}" = "1" ]; then
  install -m0755 "$SRC/collectors/minio-audit-relay.py" /usr/local/lib/plume/collectors/minio-audit-relay.py
  install -m0644 "$SRC/systemd/plume-minio-audit.service" /etc/systemd/system/
  # Token partage MinIO<->relais : genere une fois, root:soc 0640 (relais le lit en soc, jamais en argv).
  if [ ! -s /etc/plume/minio-audit.token ]; then
    umask 077
    (head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n') > /etc/plume/minio-audit.token
    chgrp soc /etc/plume/minio-audit.token && chmod 0640 /etc/plume/minio-audit.token
  fi
  if [ ! -f /etc/plume/minio-audit.conf ]; then
    umask 027
    {
      echo "# relais audit MinIO. cni0 = bridge pod->hote (jamais public). Buckets scope = backups."
      echo "PLUME_SPOOL=/var/lib/plume/spool"
      echo "PLUME_MINIO_AUDIT_BIND=${PLUME_MINIO_AUDIT_BIND:-10.42.0.1}"
      echo "PLUME_MINIO_AUDIT_PORT=${PLUME_MINIO_AUDIT_PORT:-9099}"
      echo "PLUME_MINIO_AUDIT_BUCKETS=${PLUME_MINIO_AUDIT_BUCKETS:-example-backups,velero-backups}"
      echo "PLUME_MINIO_AUDIT_TOKEN_FILE=/etc/plume/minio-audit.token"
    } > /etc/plume/minio-audit.conf
    chgrp soc /etc/plume/minio-audit.conf && chmod 0640 /etc/plume/minio-audit.conf
  fi
  echo ">> relais minio-audit installe (OPT-IN, NON active). Active (apres conf MinIO) : systemctl enable --now plume-minio-audit"
fi

# --- collecteur YARA (OPT-IN : PLUME_WITH_YARA=1) : scan malware/IOC host-natif -> source=yara. OFF PAR
# DEFAUT et DOUBLEMENT INERTE : (1) le timer N'EST PAS active ici (regle d'or : l'operateur active ce qu'il
# veut) ; (2) le collecteur lui-meme no-op (exit 0, rien emis) tant que `yara` est ABSENT *ou* qu'AUCUNE
# regle n'est deposee dans /etc/plume/yara.d. On ne fait qu'installer le collecteur + l'unit + le squelette
# (conf + repertoire de regles vide). Activation = etape MANUELLE documentee ci-dessous.
if [ "${PLUME_WITH_YARA:-0}" = "1" ]; then
  install -m0755 "$SRC/collectors/yara.sh" /usr/local/lib/plume/collectors/yara.sh
  install -m0644 "$SRC/systemd/plume-yara.service" /etc/systemd/system/
  install -m0644 "$SRC/systemd/plume-yara.timer"   /etc/systemd/system/
  # repertoire de regles : VIDE = collecteur inerte (garde-fou OFF). root:soc 0750 ; l'operateur y depose ses *.yar.
  install -d -o root -g soc -m 0750 /etc/plume/yara.d
  if [ ! -f /etc/plume/yara.conf ]; then
    umask 027
    # PAS de commentaire en fin de ligne de VALEUR (systemd EnvironmentFile ne les retire pas).
    {
      echo "# collecteur YARA (OFF par defaut, inerte tant que yara/regles absents). Pour ACTIVER :"
      echo "#   sudo apt install yara"
      echo "#   deposer des regles *.yar dans /etc/plume/yara.d/"
      echo "#   sudo systemctl enable --now plume-yara.timer"
      echo "PLUME_YARA_RULES=/etc/plume/yara.d"
      echo "PLUME_YARA_PATHS=/home /tmp /var/tmp /dev/shm"
      echo "PLUME_YARA_TIMEOUT=120"
      echo "PLUME_YARA_MAX=5000"
      echo "PLUME_YARA_MAX_EVENTS=200"
      echo "PLUME_YARA_MAX_FILE_SIZE=100M"
      echo "PLUME_SPOOL=/var/lib/plume/spool"
      echo "PLUME_STATE=/var/lib/plume/state"
    } > /etc/plume/yara.conf
    chgrp soc /etc/plume/yara.conf && chmod 0640 /etc/plume/yara.conf
  fi
  echo ">> collecteur YARA installe (OPT-IN, NON active, INERTE tant que yara+regles absents)."
  echo "   ACTIVER : sudo apt install yara ; deposer des regles *.yar dans /etc/plume/yara.d/ ; sudo systemctl enable --now plume-yara.timer"
fi

# --- port-scan nft (OPT-IN : PLUME_WITH_PORTSCAN=1) : detection low-volume via la table nft plume-portscan ->
# source=portscan. Le collecteur seul (via PLUME_EXTRA_COLLECTORS) N'INSTALLE PAS le detecteur nft ni sa table
# -> ce bloc dedie pose AUSSI la table + son loader (plume-portscan-nft.service). Regle d'or : installe NON
# active (ni le loader nft, ni le timer). Le battement de sante (source=portscan category=health) part a chaque
# run une fois active -> dead-man's-switch portscan-health (cf. main.rs).
if [ "${PLUME_WITH_PORTSCAN:-0}" = "1" ]; then
  install -m0755 "$SRC/collectors/portscan.sh" /usr/local/lib/plume/collectors/portscan.sh
  install -m0644 "$SRC/systemd/plume-portscan.service"     /etc/systemd/system/
  install -m0644 "$SRC/systemd/plume-portscan.timer"       /etc/systemd/system/
  install -m0644 "$SRC/systemd/plume-portscan-nft.service" /etc/systemd/system/
  install -m0644 "$SRC/systemd/plume-portscan.nft"         /etc/plume/plume-portscan.nft
  echo ">> collecteur port-scan installe (OPT-IN, NON active). La table nft + son loader sont poses mais NON charges."
  echo "   ACTIVER : sudo systemctl enable --now plume-portscan-nft.service plume-portscan.timer"
fi

# --- port-probe low-and-slow (OPT-IN : PLUME_WITH_PORTPROBE=1) : lit l'APPARTENANCE aux sets dynamiques
# ps_rate_v4/v6 de la table nft 'plume-portscan' (posee par PLUME_WITH_PORTSCAN) -> source=portprobe. Complement
# de portscan.sh (le log kernel = scan RAPIDE ; ici on capte le prober LENT que le seuil 10/s laisse passer).
# LECTURE SEULE (`nft -j list ruleset`, pas un log). Requiert nft + jq. Regle d'or : installe NON active ;
# skip propre a l'execution si la table plume-portscan est absente. DEPEND de PLUME_WITH_PORTSCAN=1.
if [ "${PLUME_WITH_PORTPROBE:-0}" = "1" ]; then
  install -m0755 "$SRC/collectors/portprobe.sh" /usr/local/lib/plume/collectors/portprobe.sh
  install -m0644 "$SRC/systemd/plume-portprobe.service" /etc/systemd/system/
  install -m0644 "$SRC/systemd/plume-portprobe.timer"   /etc/systemd/system/
  echo ">> collecteur port-probe installe (OPT-IN, NON active). Requiert la table nft plume-portscan (PLUME_WITH_PORTSCAN=1)."
  echo "   ACTIVER : sudo systemctl enable --now plume-portprobe.timer"
fi

# --- origin-drop (OPT-IN : PLUME_WITH_ORIGIN_DROP=1) : rend VISIBLE le DROP direct-a-l-origine (bypass
# Cloudflare/cluster) en parsant le prefixe de log kernel 'ORIGIN-DROP:' que vous emettez depuis une regle de LOG (placee
# juste AVANT le DROP dans votre pare-feu ; table, ports, prefixe et rate-limit sont a definir par vous)
# -> source=origin-drop, category=firewall. LECTURE SEULE (journalctl -k). Regle d'or : installe
# NON active ; skip propre a l'execution si la table est absente.
if [ "${PLUME_WITH_ORIGIN_DROP:-0}" = "1" ]; then
  install -m0755 "$SRC/collectors/origin-drop.sh" /usr/local/lib/plume/collectors/origin-drop.sh
  install -m0644 "$SRC/systemd/plume-origin-drop.service" /etc/systemd/system/
  install -m0644 "$SRC/systemd/plume-origin-drop.timer"   /etc/systemd/system/
  echo ">> collecteur origin-drop installe (OPT-IN, NON active). Requiert une regle de LOG 'ORIGIN-DROP:' dans votre pare-feu, placee avant le DROP."
  echo "   ACTIVER : sudo systemctl enable --now plume-origin-drop.timer"
fi

# --- collecteur Cloudflare HTTP edge (OPT-IN : PLUME_WITH_CLOUDFLARE_HTTP=1) : requetes 4xx/5xx vues AU EDGE
# Cloudflare (httpRequestsAdaptiveGroups, GraphQL Analytics, LECTURE SEULE / pull-only) -> source=cloudflare-http,
# category=web. Ferme l'angle mort du web-scan absorbe/servi au edge (T1595.002) que l'origine ne voit pas.
# Requiert curl + jq. Skip propre a l'execution si PLUME_CF_TOKEN / PLUME_CF_ZONE absents (jamais imprimes/loggues).
if [ "${PLUME_WITH_CLOUDFLARE_HTTP:-0}" = "1" ]; then
  install -m0755 "$SRC/collectors/cloudflare-http.sh" /usr/local/lib/plume/collectors/cloudflare-http.sh
  install -m0644 "$SRC/systemd/plume-cloudflare-http.service" /etc/systemd/system/
  install -m0644 "$SRC/systemd/plume-cloudflare-http.timer"   /etc/systemd/system/
  if [ ! -f /etc/plume/cloudflare.conf ]; then
    umask 077
    {
      echo "# collecteur Cloudflare HTTP edge (source=cloudflare-http). Renseigne un API token READ-ONLY"
      echo "# (permission Analytics:Read sur la zone) + le ZONE TAG 32-hex de la zone (PAS le nom), PUIS :"
      echo "#   sudo systemctl enable --now plume-cloudflare-http.timer"
      echo "# Le token n'est JAMAIS imprime/loggue. GOTCHA egress : curl -4 impose (le VPS sort en IPv6, le"
      echo "# token whiteliste des IPv4) -- deja gere par le collecteur."
      echo "PLUME_CF_TOKEN=${PLUME_CF_TOKEN:-}"
      echo "PLUME_CF_ZONE=${PLUME_CF_ZONE:-}"
      echo "PLUME_CF_ACCOUNT=${PLUME_CF_ACCOUNT:-}"
    } > /etc/plume/cloudflare.conf
    chmod 0600 /etc/plume/cloudflare.conf
  fi
  echo ">> collecteur cloudflare-http installe (OPT-IN, NON active). Edite /etc/plume/cloudflare.conf puis: systemctl enable --now plume-cloudflare-http.timer"
fi

# --- collecteur Cloudflare firewall-events LEGACY (OPT-IN : PLUME_WITH_CLOUDFLARE=1) : evenements firewall
# (edge WAF / Bot / RateLimit) vus AU EDGE Cloudflare via GraphQL firewallEventsAdaptive (LECTURE SEULE /
# pull-only) -> source=cloudflare, category=web. Ferme l'angle mort des attaques web STOPPEES au edge
# (challenge/block) que l'origine (Traefik) ne voit jamais. SUPERSEDE par cloudflare-http.sh (httpRequests-
# AdaptiveGroups, couverture plus large) mais TOUJOURS LIVE sur l'hote de prod GuatX (l'opérateur pourra le retirer
# plus tard). PARTAGE /etc/plume/cloudflare.conf avec cloudflare-http (memes PLUME_CF_TOKEN/PLUME_CF_ZONE) :
# le skeleton est genere par le bloc PLUME_WITH_CLOUDFLARE_HTTP ci-dessus ; on ne le (re)genere ici QUE s'il
# est absent (filet de securite si ce collecteur est active seul). Requiert curl -4 + jq. Skip propre a
# l'execution si PLUME_CF_TOKEN/PLUME_CF_ZONE absents (jamais imprimes/loggues). Regle d'or : installe NON active.
if [ "${PLUME_WITH_CLOUDFLARE:-0}" = "1" ]; then
  install -m0755 "$SRC/collectors/cloudflare.sh" /usr/local/lib/plume/collectors/cloudflare.sh
  install -m0644 "$SRC/systemd/plume-cloudflare.service" /etc/systemd/system/
  install -m0644 "$SRC/systemd/plume-cloudflare.timer"   /etc/systemd/system/
  if [ ! -f /etc/plume/cloudflare.conf ]; then
    umask 077
    {
      echo "# collecteur Cloudflare (source=cloudflare / cloudflare-http). Renseigne un API token READ-ONLY"
      echo "# (permission Analytics:Read sur la zone) + le ZONE TAG 32-hex de la zone (PAS le nom), PUIS :"
      echo "#   sudo systemctl enable --now plume-cloudflare.timer"
      echo "# Le token n'est JAMAIS imprime/loggue. GOTCHA egress : curl -4 impose (le VPS sort en IPv6, le"
      echo "# token whiteliste des IPv4) -- deja gere par le collecteur."
      echo "PLUME_CF_TOKEN=${PLUME_CF_TOKEN:-}"
      echo "PLUME_CF_ZONE=${PLUME_CF_ZONE:-}"
      echo "PLUME_CF_ACCOUNT=${PLUME_CF_ACCOUNT:-}"
    } > /etc/plume/cloudflare.conf
    chmod 0600 /etc/plume/cloudflare.conf
  fi
  echo ">> collecteur cloudflare (firewall-events LEGACY) installe (OPT-IN, NON active). Edite /etc/plume/cloudflare.conf puis: systemctl enable --now plume-cloudflare.timer"
fi

# --- adaptateur Mode Engagement (OPT-IN : PLUME_WITH_ENGAGEMENT=1) : enforcer-exemption HOST-SIDE (PULL). Le
# daemon DECLARE (GET /api/engagements/active) ; cet adaptateur APPLIQUE/REVOQUE sur CET HOTE les exemptions
# d'auto-block des engagements autorises (CrowdSec allowlist / fail2ban ignoreip / nft accept). SACRED : ne
# touche JAMAIS detection/collecte/logging ; NO-OP sur PLUME_ENGAGEMENT_MODE=0 cote daemon (/active -> []).
# Fail-CLOSED (revert apres N echecs) + dead-man revert (unit separee, expiry nft/f2b sans TTL natif). Reutilise
# le socle responder (token agent host-bound + mTLS). Installe 2 paires d'units (adapter + revert), NON activees.
if [ "${PLUME_WITH_ENGAGEMENT:-0}" = "1" ]; then
  install -m0755 "$SRC/collectors/engagement-adapter.sh" /usr/local/lib/plume/collectors/engagement-adapter.sh
  install -m0644 "$SRC/systemd/plume-engagement-adapter.service" /etc/systemd/system/
  install -m0644 "$SRC/systemd/plume-engagement-adapter.timer"   /etc/systemd/system/
  install -m0644 "$SRC/systemd/plume-engagement-revert.service"  /etc/systemd/system/
  install -m0644 "$SRC/systemd/plume-engagement-revert.timer"    /etc/systemd/system/
  if [ ! -f /etc/plume/engagement-adapter.conf ]; then
    umask 077
    {
      echo "# Plume — enforcer-exemption adapter (host-side PULL). Reutilise le socle responder :"
      echo "# token agent host-bound + mTLS + Host-header + wrapper cscli k3s-aware. OPT-IN."
      echo "# !! PLUME_TOKEN DOIT etre un token agent LIE A CET HOTE (anti-IDOR). Renseigne-le PUIS active"
      echo "#    les 2 timers (l'adaptateur + le dead-man revert) :"
      echo "#      sudo systemctl enable --now plume-engagement-adapter.timer plume-engagement-revert.timer"
      echo "PLUME_ENGAGEMENT_ADAPTER=1"
      echo "PLUME_ENGAGEMENT_FAILCLOSED_N=${PLUME_ENGAGEMENT_FAILCLOSED_N:-2}"
      echo "PLUME_CENTRAL=$PLUME_CENTRAL"
      [ -n "${PLUME_HOST_HEADER:-}" ] && echo "PLUME_HOST_HEADER=$PLUME_HOST_HEADER"
      [ -n "${PLUME_TOKEN:-}" ] && echo "PLUME_TOKEN=$PLUME_TOKEN"
      echo "PLUME_HOST_LABEL=${PLUME_HOST_LABEL:-$(hostname)}"
      echo "PLUME_TLS_CACERT=${PLUME_TLS_CACERT:-/etc/plume/ca.crt}"
      echo "PLUME_TLS_CERT=${PLUME_TLS_CERT:-/etc/plume/agent.crt}"
      echo "PLUME_TLS_KEY=${PLUME_TLS_KEY:-/etc/plume/agent.key}"
      echo "PLUME_CROWDSEC_NS=${PLUME_CROWDSEC_NS:-crowdsec}"
      echo "PLUME_CROWDSEC_LAPI=${PLUME_CROWDSEC_LAPI:-crowdsec-lapi}"
    } > /etc/plume/engagement-adapter.conf
    chmod 0600 /etc/plume/engagement-adapter.conf
  fi
  echo ">> adaptateur engagement installe (OPT-IN, NON active). Edite /etc/plume/engagement-adapter.conf (PLUME_TOKEN host-bound) puis:"
  echo "   sudo systemctl enable --now plume-engagement-adapter.timer plume-engagement-revert.timer"
fi

systemctl daemon-reload
for t in plume-resources plume-integrity plume-ship; do systemctl enable --now "$t.timer"; done
systemctl start plume-resources.service plume-integrity.service || true
echo ">> Agent installé (capteurs resources+integrity, ship 30s) -> $PLUME_CENTRAL/api/ingest"
