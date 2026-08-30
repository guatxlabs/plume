#!/usr/bin/env bash
# Bootstrap plume central — binaire unique tout-en-un (PAS de Caddy). Idempotent.
#   cd ~/plume/daemon && cargo build --release
#   HASH=$(~/plume/daemon/target/release/plume-daemon hashpw 'tonmotdepasse')
#   sudo env PLUME_PASS_HASH="$HASH" bash ~/plume/bootstrap.sh
#
# `P7.20-e` — CE QUE CETTE RECETTE COMPILE, ET CE QU'ELLE NE COMPILE PAS. CE SCRIPT NE COMPILE RIEN :
# il refuse de continuer si le binaire est absent (plus bas) et vous renvoie à `cargo`. La ligne de
# compilation ci-dessus est donc ce qui DÉCIDE des capacités du mode natif — et jusqu'ici elle ne
# décidait rien, elle se taisait. `cargo build --release` NU est le défaut, et il est désormais ASSUMÉ
# ICI : le démon complet, SANS les features optionnelles. L'image conteneur, elle, est bâtie
# `ldap,cold_tier` (`ARG PLUME_FEATURES` du Dockerfile) — l'écart entre les deux modes était réel et
# n'était écrit NULLE PART ; il l'est ici, et l'installation le MESURE sur le binaire qu'elle pose
# (verdict `>> Capacités optionnelles` en fin de course) plutôt que de vous laisser le découvrir.
#
# LES DEUX CAPACITÉS QUE LE DÉFAUT NU N'A PAS :
#   • `cold_tier` — tier froid colonnaire Parquet (#18). Sans elle, `PLUME_COLD_TIER` est SANS EFFET
#     et des fichiers-jour écrits par un AUTRE binaire seraient INVISIBLES à celui-ci. Avec elle,
#     RIEN NE CHANGE tant que `PLUME_COLD_TIER=1` n'est pas posé (double porte : compilation PUIS
#     exécution) — la compiler ne l'allume pas. CE QU'ELLE COÛTE À LA CONSTRUCTION N'EST PAS MESURÉ
#     ICI, et c'est la raison pour laquelle le défaut reste nu plutôt qu'aligné sur l'image : elle
#     tire `parquet` (codecs zstd/snap, sans arrow) plus `hkdf`/`sha2`/`bytes` — davantage de caisses
#     à compiler sur une machine qui n'a pas forcément de quoi, sans un chiffre pour le borner.
#     Ce qu'elle vaut ALLUMÉE, et ce qu'elle prend, est écrit à côté du réglage lui-même (plus bas,
#     dans /etc/plume/soc.conf) — dont le fait qu'AUCUN chemin ne ramène un jour froid vers le chaud.
#   • `ldap` — bind LDAP/AD natif (#44). Sans elle, le login annuaire répond 501. Elle est DÉFAUT-ON
#     dans l'image conteneur : c'est le second écart entre les deux modes, et il n'est pas silencieux.
# CE QUE CE FICHIER NE PEUT PAS TENIR SEUL : le README prescrit AUSSI la ligne de compilation, et il
# la donne nue. Deux endroits à tenir d'accord = une occasion de diverger (le Dockerfile a rencontré
# exactement ça, `P4.5-a`) ; c'est le contrôle de fin de course qui rattrape l'écart, pas la prose.
# Les prendre :  cd ~/plume/daemon && cargo build --release --features cold_tier,ldap
# Sur une machine modeste, bornez le parallélisme comme le fait l'image :  CARGO_BUILD_JOBS=2 cargo …
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
echo ">> Source repo : $SRC"

# users / arborescence
getent group  soc >/dev/null || groupadd -r soc
getent passwd soc >/dev/null || useradd -r -g soc -s /usr/sbin/nologin -d /var/lib/plume soc
install -d -o root -g soc -m 2750 /var/lib/plume
install -d -o root -g soc -m 2770 /var/lib/plume/spool
install -d -o soc  -g soc -m 0750 /var/lib/plume/db
install -d -o root -g root -m 0750 /var/lib/plume/state
install -d -o soc  -g soc  -m 2750 /var/lib/plume/backups
install -d -m0755 /usr/local/lib/plume/collectors
install -d -m0755 /usr/local/share/plume/web

# capteurs + timers
install -m0755 "$SRC/collectors/firewall.sh"       /usr/local/lib/plume/collectors/firewall.sh
install -m0755 "$SRC/collectors/journal.sh"        /usr/local/lib/plume/collectors/journal.sh
install -m0755 "$SRC/collectors/controls.sh"       /usr/local/lib/plume/collectors/controls.sh
install -m0755 "$SRC/collectors/resources.sh"      /usr/local/lib/plume/collectors/resources.sh
install -m0755 "$SRC/collectors/integrity.sh"      /usr/local/lib/plume/collectors/integrity.sh
install -m0755 "$SRC/collectors/auditd.sh"         /usr/local/lib/plume/collectors/auditd.sh
install -m0755 "$SRC/collectors/backup.sh"         /usr/local/lib/plume/collectors/backup.sh
install -m0755 "$SRC/collectors/falco.sh"          /usr/local/lib/plume/collectors/falco.sh
install -m0755 "$SRC/collectors/crowdsec.sh"       /usr/local/lib/plume/collectors/crowdsec.sh
install -m0755 "$SRC/collectors/kube-state.sh"     /usr/local/lib/plume/collectors/kube-state.sh
install -m0755 "$SRC/collectors/pod-logs.sh"       /usr/local/lib/plume/collectors/pod-logs.sh
install -m0755 "$SRC/collectors/prom-scrape.sh"    /usr/local/lib/plume/collectors/prom-scrape.sh
install -m0644 "$SRC/systemd/plume-audit.rules"      /usr/local/share/plume/plume-audit.rules
install -m0644 "$SRC/systemd/plume-firewall.service" /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-firewall.timer"   /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-journal.service"  /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-journal.timer"    /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-controls.service" /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-controls.timer"   /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-resources.service" /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-resources.timer"  /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-integrity.service" /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-integrity.timer"  /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-respond.service"  /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-respond.timer"    /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-auditd.service"   /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-auditd.timer"     /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-backup.service"   /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-backup.timer"     /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-falco.service"    /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-falco.timer"      /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-crowdsec.service" /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-crowdsec.timer"   /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-kube-state.service" /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-kube-state.timer" /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-pod-logs.service" /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-pod-logs.timer"   /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-prom-scrape.service" /etc/systemd/system/
install -m0644 "$SRC/systemd/plume-prom-scrape.timer"   /etc/systemd/system/

# daemon (binaire requis)
if [ ! -x "$SRC/daemon/target/release/plume-daemon" ]; then
  echo "!! binaire absent — fais d'abord :"
  echo "     cd $SRC/daemon && cargo build --release"
  echo "   ou, pour les capacités optionnelles que l'image conteneur porte (tier froid, LDAP/AD) :"
  echo "     cd $SRC/daemon && cargo build --release --features cold_tier,ldap"
  echo "   (les deux formes sont légitimes ; la nue est le défaut assumé — cf. l'en-tête de ce script)"
  exit 1
fi
install -m0755 "$SRC/daemon/target/release/plume-daemon" /usr/local/bin/plume-daemon
install -m0644 "$SRC/systemd/plume-daemon.service" /etc/systemd/system/

# PWA statique (+ polices auto-hébergées dans web/fonts/)
install -m0644 "$SRC"/web/* /usr/local/share/plume/web/ 2>/dev/null || true
install -d -m0755 /usr/local/share/plume/web/fonts
install -m0644 "$SRC"/web/fonts/*.woff2 /usr/local/share/plume/web/fonts/ 2>/dev/null || true

# config /etc/plume/soc.conf  (contient le hash -> 0640 root:soc)
install -d -o root -g soc -m 0750 /etc/plume
if [ -n "${PLUME_PASS_HASH:-}" ] || [ ! -f /etc/plume/soc.conf ]; then
  umask 027
  cat > /etc/plume/soc.conf <<EOF
PLUME_USER=${PLUME_USER:-admin}
PLUME_PASS_HASH=${PLUME_PASS_HASH:-}
PLUME_ADDR=127.0.0.1:7000
PLUME_HOST=soc.localhost
PLUME_WEB=/usr/local/share/plume/web
PLUME_DB=/var/lib/plume/db/soc.db
PLUME_SPOOL=/var/lib/plume/spool
# TIER FROID COLONNAIRE (#18) — ÉTEINT, ET C'EST UNE DÉCISION (P7.20-e). Ligne COMMENTÉE : le démon
# saute les lignes qui commencent par un dièse, elle n'arme donc rien. Décommentée, elle ne mord que
# si ce binaire a été bâti avec la feature (double porte : compilation PUIS exécution) ; le démon dit
# lequel des trois états est le sien au démarrage — journalctl -u plume-daemon | grep -i 'tier froid'
# CE QU'ALLUMER FAIT, ET QUI NE SE DÉFAIT PAS : un jour révolu au-delà de la fenêtre chaude QUITTE la
# table event pour un fichier Parquet chiffré sous /var/lib/plume/db/cold. AUCUN chemin ne ramène un
# jour froid vers le chaud : le fichier devient la SEULE copie de ces événements.
# ET CE FICHIER N'EST PAS SAUVEGARDÉ ICI : plume-backup.timer copie la BASE (VACUUM INTO) et rien
# d'autre ; le répertoire cold n'entre dans aucune archive de ce mode. Le démon sait produire un plan
# de copie (plume-daemon cold-backup-plan), mais aucune unité de ce dépôt ne l'exécute.
# CE QUI N'EST PAS MESURÉ, ET QUI DÉCIDE DU DÉFAUT : la crête mémoire imputable à la passe de
# vieillissement sous le budget de 2 Gio (MemoryMax de plume-daemon.service). Cf.
# docs/DESIGN-P10-echelle-2go.md, levier A. Seule la valeur 1 allume ; toute autre valeur = éteint.
#PLUME_COLD_TIER=1
EOF
  chgrp soc /etc/plume/soc.conf && chmod 0640 /etc/plume/soc.conf
  [ -n "${PLUME_PASS_HASH:-}" ] && echo ">> /etc/plume/soc.conf écrit (hash posé)." \
                              || echo ">> Aucun hash -> SETUP MODE : token d'installation dans 'journalctl -u plume-daemon' ou /var/lib/plume/db/setup-token.txt -> ⚙️ Réglages."
else
  echo ">> /etc/plume/soc.conf déjà présent (inchangé)."
fi

# résolution locale
grep -q 'soc.localhost' /etc/hosts || echo '127.0.0.1 soc.localhost' >> /etc/hosts

# allowlist du responder (vide par défaut -> stop_service entièrement bloqué tant qu'on n'ajoute pas un service)
# P4.7-a — CE CHEMIN A PORTÉ DEUX POLITIQUES, ET IL N'EN PORTE PLUS QU'UNE. `bootstrap-agent.sh`
# semait ICI, sous le MÊME nom, la liste des ADRESSES à ne jamais bannir ; les deux installateurs ne
# créant le fichier que s'il est ABSENT, sur une machine à la fois centrale et agent le second
# héritait du contenu du premier et le relisait de travers — et la direction dangereuse a été
# MESURÉE le 2026-08-27 : avec des noms de service dans ce fichier, le responder d'agent n'y trouvait
# AUCUNE adresse épargnée et POSAIT le ban.
# TROIS choses ont changé, et il en faut trois : (1) une installation d'agent NEUVE sème sa liste
# dans `/etc/plume/responder-ban-exempt.allow`, donc les deux politiques ont deux fichiers ;
# (2) une installation EXISTANTE n'est pas touchée — son `responder.conf` garde son chemin, qui peut
# rester celui-ci ; (3) c'est pourquoi les DEUX lecteurs REFUSENT désormais un contenu qui n'est pas
# de leur politique au lieu de le lire de travers (le démon : `blocked` en nommant l'autre politique ;
# l'agent : refus fail-closed `forme_inconnue`, aucun ban appliqué). Le chemin de CETTE liste-ci se
# pose par `PLUME_STOP_SERVICE_ALLOW`.
# `P4.7-b` — CE QUE (3) NE DISAIT PAS, ET QUI ÉTAIT FAUX : les deux lecteurs n'ont pas le MÊME
# critère d'adresse, ils en ont deux (Rust ici, shell là-bas, aucun littéral partagé possible).
# MESURÉ le 2026-08-28 : le lecteur du démon exigeait un POINT, donc une liste d'épargne IPv6
# hexadécimale pure (`2001:db8::1`, `::1`) tombait chez lui dans la liste des NOMS DE SERVICE — sans
# un mot, pendant que ce fichier-ci promettait le contraire à l'exploitant. La promesse EST tenable,
# mais elle est plus ÉTROITE que « le même critère » : le classificateur du démon reconnaît
# strictement PLUS de formes que `is_ip`, donc aucune ligne n'est acceptée en silence par les deux.
# C'est cette propriété-là qui est écrite dans le fichier ci-dessous, et elle est MESURÉE ligne par
# ligne sur LES DEUX lecteurs par `collectors/predicat-adresse.corpus`, et par un BALAYAGE dont
# l'alphabet est dérivé de la ligne `is_ip` livrée (un corpus de 30 lignes reste un échantillon).
# `P4.7-c`, OUVERTE et dite ici plutôt que tue : le responder du CENTRAL ne lit AUCUNE liste
# d'épargne. Ce fichier-ci ne gouverne QUE `stop_service` ; rien, de ce côté, n'empêche un
# `ban_ip` de partir sur une adresse que l'agent aurait épargnée.
if [ ! -f /etc/plume/responder.allow ]; then
  printf '# POLITIQUE DE CE FICHIER : services systemd autorises pour l action stop_service (lu par le DEMON).\n# 1 nom de service par ligne (ex: nginx.service). vide = aucun stop_service autorise.\n# N Y METTEZ PAS D ADRESSES IP : ce chemin est aussi celui de la liste des IP a ne jamais bannir de\n# l agent (bootstrap-agent.sh). Une ligne qui a la FORME d une adresse -- IPv4 ou IPv6, avec ou sans\n# masque, avec ou sans zone -- fait REFUSER ce fichier EN ENTIER en nommant l autre politique : plus\n# aucun stop_service ne passe tant qu elle y est.\n# CE QUI EST GARANTI ENTRE LES DEUX LECTEURS, ET RIEN DE PLUS : leurs deux criteres ne sont PAS\n# identiques. Ce lecteur-ci reconnait comme adresse strictement PLUS de formes que celui de l agent,\n# si bien qu AUCUNE ligne n est acceptee EN SILENCE par les deux -- mais une forme peut etre refusee\n# des deux cotes (l agent refuse alors TOUT ban sur son hote, fail-closed). Ce qui le mesure : un\n# CORPUS ligne a ligne sur les deux lecteurs, ET un BALAYAGE sur chacun (un corpus de 30 lignes\n# reste un echantillon) -- collectors/predicat-adresse.corpus.\n# CE FICHIER NE PROTEGE AUCUNE IP (P4.7-c) : il n autorise que des ARRETS DE SERVICE. Le\n# responder du central ne lit AUCUNE liste d epargne -- la liste des IP a ne jamais bannir est\n# celle de l AGENT (PLUME_RESPONDER_ALLOW), et le demon ne la consulte pas.\n' > /etc/plume/responder.allow
  chgrp soc /etc/plume/responder.allow && chmod 0640 /etc/plume/responder.allow
fi

# OBS-1 : cibles de scrape Prometheus + conf (opt-in, le timer reste désactivé tant que non configuré)
if [ ! -f /etc/plume/prom-targets ]; then
  cat > /etc/plume/prom-targets <<'PT'
# 1 URL /metrics par ligne (# = commentaire). Exemples :
# http://127.0.0.1:9100/metrics    # node_exporter
# http://127.0.0.1:8080/metrics    # kube-state-metrics (via port-forward)
PT
  chgrp soc /etc/plume/prom-targets && chmod 0640 /etc/plume/prom-targets
fi
if [ ! -f /etc/plume/prom.conf ]; then
  cat > /etc/plume/prom.conf <<'PC'
# plume-prom-scrape : PLUME_CENTRAL = ou pousser (def http://127.0.0.1:7000).
# Auth : PLUME_TOKEN (Bearer, via 'plume-daemon token prom') OU PLUME_USER+PLUME_PASS (basic).
#PLUME_CENTRAL=http://127.0.0.1:7000
#PLUME_TOKEN=
PC
  chgrp soc /etc/plume/prom.conf && chmod 0640 /etc/plume/prom.conf
fi

# règles auditd (Varonis-like + anti-blindspot #8 svc_exec) : persistées dans /etc/audit/rules.d
# (survivent au reboot) PUIS chargées via augenrules — c'est CE qui arme le collecteur auditd.sh
# (sans les règles, dataaccess/svc_exec sont vides). Le staging /usr/local/share/plume ci-dessus reste
# la copie de référence (méthode manuelle documentée en en-tête du fichier). Le collecteur mappe -k
# svc_exec en severity 3 et le shippe MEME sous PLUME_AUDIT_REAL_USER_ONLY=1 (l'exec service-account
# n'est JAMAIS droppé = angle-mort #8 fermé).
# CAVEAT DURABILITE : les watch svc_exec figent des realpaths ; les binaires versionnés (ruby3.3/
# tclsh8.6) exigent un re-resolve (readlink -f) sur upgrade majeur (cf. en-tête de plume-audit.rules).
if command -v augenrules >/dev/null 2>&1; then
  install -m0640 -o root -g root "$SRC/systemd/plume-audit.rules" /etc/audit/rules.d/plume.rules
  augenrules --load >/dev/null 2>&1 || true
  echo ">> règles auditd chargées dans /etc/audit/rules.d/plume.rules (svc_exec: $(auditctl -l 2>/dev/null | grep -c 'key=svc_exec'))"
else
  echo ">> auditd absent (augenrules introuvable) — installe auditd puis relance, sinon auditd.sh reste inerte (dataaccess/svc_exec vides)."
fi

# activation
systemctl daemon-reload
systemctl enable --now plume-firewall.timer
systemctl start  plume-firewall.service
systemctl enable --now plume-journal.timer
systemctl start  plume-journal.service
systemctl enable --now plume-controls.timer
systemctl start  plume-controls.service
systemctl enable --now plume-resources.timer
systemctl start  plume-resources.service
systemctl enable --now plume-integrity.timer
systemctl start  plume-integrity.service
# retire l'ancien wiring plume-audit (collecteur audit.sh) supersede par auditd.sh/plume-auditd : au cas ou
# un ancien bootstrap l'aurait laisse actif -> on ne laisse JAMAIS les deux collecteurs auditd tourner.
systemctl disable --now plume-audit.timer 2>/dev/null || true
systemctl enable --now plume-auditd.timer
systemctl start  plume-auditd.service || true
systemctl enable --now plume-backup.timer
# OPTIONNELS (réponse root / dépendances externes) = OFF par défaut. On les désactive
# explicitement (au cas où un ancien bootstrap les aurait activés) -> opt-in conscient.
systemctl disable --now plume-respond.timer plume-falco.timer plume-crowdsec.timer plume-kube-state.timer plume-pod-logs.timer plume-prom-scrape.timer 2>/dev/null || true
systemctl enable plume-daemon.service
systemctl restart plume-daemon.service   # (re)charge la config

echo ">> OK. Page : http://soc.localhost:7000   (user $(grep -m1 '^PLUME_USER' /etc/plume/soc.conf | cut -d= -f2))"
echo ">> Modules OPTIONNELS désactivés par défaut — active à la demande :"
echo "   • Réponse (root, exécute les actions)  : sudo systemctl enable --now plume-respond.timer"
echo "       garde-fous : mode 'observe' + dry-run + approbation + allowlist + délégation CrowdSec/fail2ban + limites systemd"
echo "   • Falco eBPF (si Falco installé)       : sudo systemctl enable --now plume-falco.timer"
echo "   • Ingestion CrowdSec (si CrowdSec)     : sudo systemctl enable --now plume-crowdsec.timer"
echo "   • Couverture k8s (si k3s)              : sudo systemctl enable --now plume-kube-state.timer plume-pod-logs.timer"
echo "       ce que leur extinction ÉTEINT : sans kube-state, l'alerte native « magasin de secrets pas prêt » ne peut pas se lever —"
echo "       un coffre scellé arrête la rotation des clés de TOUT le cluster (épisode fondateur du 2026-08-26 : vingt-sept secrets externes)."
echo "       Tant que le timer est éteint ce signal est MUET, et ce silence ne vaut PAS « tout va bien ». Détail : deploy/K8S.md"
echo "   • Scrape Prometheus (OBS-1, remplace Prom) : remplis /etc/plume/prom-targets + /etc/plume/prom.conf puis sudo systemctl enable --now plume-prom-scrape.timer"

# `P7.20-e` — CAPACITÉS OPTIONNELLES DU BINAIRE RÉELLEMENT POSÉ, MESURÉES ET NON SUPPOSÉES.
# CE QUE ÇA FERME : l'image conteneur est bâtie `ldap,cold_tier`, la recette native ne l'est pas, et
# rien ne le disait — l'exploitant natif perdait une capacité EN SILENCE. On ne devine donc pas depuis
# la ligne de compilation (personne ne sait ce que l'exploitant a tapé) : on DEMANDE AU BINAIRE.
# L'ANCRE EST LE NOM DE LA SOUS-COMMANDE, pas une phrase : `cold-backup-plan` existe dans les DEUX
# builds (main.rs la liste des deux côtés), et c'est le binaire lui-même qui la dit indisponible quand
# la feature manque. `--help` n'ouvre aucune base, ne lit aucune conf et sort immédiatement.
# TROISIÈME ÉTAT, DÉLIBÉRÉ, ET C'EST LUI QUI DÉCIDE DE LA FORME. LE SENS OPTIMISTE EST LE SEUL QUI
# COÛTE CHER ICI — croire le tier froid présent, poser PLUME_COLD_TIER=1, et n'obtenir RIEN. Le verdict
# « PRÉSENT » exige donc une PREUVE POSITIVE (la ligne d'aide du build QUI PORTE la feature), jamais
# l'absence d'un mot : si les deux formes connues manquent — binaire muet, aide remaniée, phrase
# renommée dans main.rs — ce contrôle REFUSE DE CONCLURE. Une dérive des libellés du démon dégrade
# donc ce constat vers le silence, jamais vers une capacité annoncée à tort. Aucun code de sortie n'en
# dépend : l'installation est finie, ceci n'est qu'un constat.
AIDE_DAEMON="$(/usr/local/bin/plume-daemon --help 2>&1 || true)"
LIGNE_COLD="$(printf '%s\n' "$AIDE_DAEMON" | grep -m1 -- 'cold-backup-plan' || true)"
if [ -n "$LIGNE_COLD" ] && printf '%s' "$LIGNE_COLD" | grep -q 'plan de sauvegarde du tier froid'; then
  echo ">> Capacités optionnelles — tier froid colonnaire (#18) : PRÉSENT dans ce binaire, et ÉTEINT."
  echo "   La compilation ne l'allume pas : il faut AUSSI PLUME_COLD_TIER=1 dans /etc/plume/soc.conf"
  echo "   (la ligne y est écrite, commentée, avec ce qu'elle coûte). Allumé, il déplace des jours"
  echo "   entiers vers /var/lib/plume/db/cold — SANS retour possible vers le chaud, et HORS de ce que"
  echo "   plume-backup.timer sauvegarde."
elif printf '%s' "$LIGNE_COLD" | grep -q 'INDISPONIBLE'; then
  echo ">> Capacités optionnelles — tier froid colonnaire (#18) : ABSENT de ce binaire (bâti sans"
  echo "   --features cold_tier). PLUME_COLD_TIER y est SANS EFFET, et des fichiers-jour Parquet"
  echo "   écrits par un autre binaire seraient INVISIBLES à celui-ci. C'est le défaut ASSUMÉ du mode"
  echo "   natif ; l'image conteneur, elle, le compile. Le prendre : cd $SRC/daemon &&"
  echo "   cargo build --release --features cold_tier,ldap  puis rejouer ce script (idempotent)."
else
  echo ">> Capacités optionnelles : NON MESURÉES — le binaire n'a pas répondu à --help, ou son aide ne"
  echo "   porte aucune des deux formes attendues pour 'cold-backup-plan'. Ceci n'est PAS « aucune"
  echo "   capacité » : c'est un contrôle qui REFUSE DE CONCLURE plutôt que d'en annoncer une."
  echo "   Vérifie à la main : /usr/local/bin/plume-daemon --help"
fi
systemctl is-active plume-daemon.service
