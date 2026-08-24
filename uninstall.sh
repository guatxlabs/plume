#!/usr/bin/env bash
# Désinstallation de plume — LES TROIS MODES DE DÉPLOIEMENT (hôte systemd · Docker · k3s).
#
# CE QUE CE SCRIPT PROMET, ET CE QU'IL REFUSE DE PROMETTRE
# --------------------------------------------------------
# 1. LE GESTE PAR DÉFAUT NE DÉTRUIT RIEN D'IRRÉVERSIBLE. Il retire le logiciel — binaire,
#    collecteurs, unités, image, conteneurs — et LAISSE les données (base, spool, sauvegardes,
#    clé du ledger, volume, PVC). La destruction est `--purge`, elle ÉNUMÈRE ce qu'elle va
#    détruire AVANT de le faire, et elle demande confirmation.
# 2. IL REFUSE PLUTÔT QUE DE DEVINER. Sans `--mode`, il SONDE les trois modes et n'agit que si
#    UN SEUL porte des traces. Zéro trace, ou deux modes à la fois -> il le dit et s'arrête
#    (code 2). Il ne conclut jamais « c'est sûrement du Docker » à partir de la présence d'un
#    outil : `docker` installé n'est pas un déploiement plume, et un outil ABSENT n'est pas la
#    preuve qu'il n'y a rien — c'est un sondage IMPOSSIBLE, et il est rapporté comme tel.
# 3. IL REND COMPTE DE CE QU'IL N'A PAS PU RETIRER. Un service qui résiste, un fichier partagé
#    qu'il refuse d'éditer, une ressource interdite par RBAC, un volume encore référencé : tout
#    reste est NOMMÉ dans le résumé final et le code de sortie devient 3. Une désinstallation
#    qui rendrait 0 en laissant des restes serait exactement le défaut que ce projet poursuit
#    partout ailleurs.
# 4. LE MODE k3s DIT QUOI FAIRE PLUTÔT QUE DE LE FAIRE. Il touche un cluster partagé, dont le
#    contexte, les droits et la politique de récupération des volumes appartiennent à
#    l'exploitant. Par défaut il IMPRIME le plan dérivé du manifeste livré ; il n'exécute qu'avec
#    `--apply`, et jamais le namespace ni le PVC sans `--purge`.
#
# USAGE
#   sudo bash uninstall.sh --mode host              # retrait, données conservées
#   sudo bash uninstall.sh --mode host --purge      # + données + utilisateur système
#   sudo bash uninstall.sh --mode docker            # conteneurs + réseau, volume conservé
#   sudo bash uninstall.sh --mode docker --purge    # + volume nommé + image construite
#        bash uninstall.sh --mode k3s               # IMPRIME le plan, ne touche à rien
#        bash uninstall.sh --mode k3s --apply       # exécute, garde Namespace + PVC
#        bash uninstall.sh --mode k3s --apply --purge   # + PVC + Namespace (destructif)
#        bash uninstall.sh --dry-run                # inventaire seul, sans root, sans rien toucher
#
# OPTIONS
#   --mode host|docker|k3s   mode visé. Omis -> sondage ; refus si le mode n'est pas déterminable.
#   --purge                  DÉTRUIT les données du mode visé. Énumère puis demande confirmation.
#   -y | --yes               répond oui à la confirmation (scripts, SSH non interactif).
#   --dry-run                n'exécute AUCUNE modification : inventaire + commandes qui seraient
#                            lancées. Ne demande pas root.
#   --apply                  mode k3s uniquement : exécute réellement le plan imprimé.
#   --project <nom>          mode docker : nom du projet compose (défaut : `COMPOSE_PROJECT_NAME`,
#                            sinon le nom du répertoire de ce dépôt — c'est la règle de compose).
#   --namespace <ns>         mode k3s : namespace visé (défaut DÉRIVÉ de deploy/k3s.yaml).
#
# CODES DE SORTIE
#   0  terminé, aucun reste connu de ce script
#   1  erreur d'usage, droits insuffisants, ou confirmation impossible
#   2  mode non déterminable, ou outil/cluster hors de portée -> RIEN n'a été fait
#   3  terminé, mais des RESTES subsistent : ils sont nommés dans le résumé
#
# CE QUE CE SCRIPT NE FAIT PAS
#   Il ne touche pas au dépôt source (supprimez-le à la main si vous le voulez). Il n'édite
#   JAMAIS /etc/hosts ni aucun fichier partagé qu'il n'a pas créé seul : il imprime la ligne et
#   la commande, et vous décidez. Il ne connaît pas les déploiements faits à la main hors de
#   `bootstrap.sh`, `docker-compose.yml` et `deploy/k3s.yaml`.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"

MODE=""
PURGE=0
YES=0
DRYRUN=0
APPLY=0
PROJET="${COMPOSE_PROJECT_NAME:-$(basename "$SRC")}"
NS=""
RESTES=()
RETIRES=()
CONSERVES=()
PLAN_SEUL=0

dire()    { printf '>> %s\n' "$*"; }
detail()  { printf '   %s\n' "$*"; }
alerte()  { printf '!! %s\n' "$*" >&2; }
reste()   { RESTES+=("$*"); }
retire()  { RETIRES+=("$*"); }
conserve(){ CONSERVES+=("$*"); }

# --- options ---------------------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --mode)      MODE="${2:-}"; shift 2 || true ;;
    --mode=*)    MODE="${1#*=}"; shift ;;
    --purge)     PURGE=1; shift ;;
    -y|--yes)    YES=1; shift ;;
    --dry-run)   DRYRUN=1; shift ;;
    --apply)     APPLY=1; shift ;;
    --project)   PROJET="${2:-}"; shift 2 || true ;;
    --project=*) PROJET="${1#*=}"; shift ;;
    --namespace) NS="${2:-}"; shift 2 || true ;;
    --namespace=*) NS="${1#*=}"; shift ;;
    -h|--help)   sed -n '2,70p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)           alerte "option inconnue : $1  (--help pour l'usage)"; exit 1 ;;
  esac
done
case "${MODE}" in ""|host|docker|k3s) ;; *) alerte "mode inconnu : $MODE (host|docker|k3s)"; exit 1 ;; esac

# Namespace k3s : DÉRIVÉ du manifeste livré, jamais recopié. Si le manifeste est absent (script
# copié hors du dépôt) on le DIT au lieu de supposer un nom.
if [ -z "$NS" ]; then
  if [ -r "$SRC/deploy/k3s.yaml" ]; then
    NS="$(awk '
      /^[[:space:]]*#/ { next }
      /^kind:[[:space:]]*Namespace/ { dansns = 1; next }
      dansns && /name:[[:space:]]/ {
        ligne = $0; sub(/.*name:[[:space:]]*/, "", ligne); sub(/[,}].*/, "", ligne)
        gsub(/[[:space:]]/, "", ligne); print ligne; exit
      }' "$SRC/deploy/k3s.yaml")"
  fi
fi

confirmer() {
  [ "$YES" = 1 ] && return 0
  if [ ! -t 0 ]; then
    alerte "entrée standard non interactive et --yes absent : RIEN n'a été détruit."
    alerte "relancez avec --yes pour confirmer sans terminal."
    exit 1
  fi
  printf '   Continuer ? [o/N] '
  read -r reponse
  case "$reponse" in o|O|y|Y) return 0 ;; *) dire "annulé — rien n'a été touché."; exit 0 ;; esac
}

exiger_root() {
  [ "$DRYRUN" = 1 ] && return 0
  [ "$(id -u)" = 0 ] && return 0
  alerte "ce mode modifie le système : relancez en root (sudo bash uninstall.sh ...)."
  alerte "pour un inventaire sans droits ni modification : bash uninstall.sh --dry-run"
  exit 1
}

# `faire <commande...>` — exécute, ou imprime seulement en --dry-run. Le code de retour est celui
# de la commande ; en simulation il vaut 0 (rien n'a été tenté, rien ne peut avoir échoué).
faire() {
  if [ "$DRYRUN" = 1 ]; then printf '   [simulation] %s\n' "$*"; return 0; fi
  "$@"
}

# =================================================================================================
# SONDAGE — trois questions indépendantes, chacune répondant « trouvé », « rien », ou « impossible »
# =================================================================================================
TRACES_HOTE=0; TRACES_DOCKER=0; TRACES_K3S=0
SONDAGE_IMPOSSIBLE=()

sonder_hote() {
  local trouve=0
  for p in /usr/local/bin/plume-daemon /etc/plume /usr/local/lib/plume /usr/local/share/plume /var/lib/plume; do
    [ -e "$p" ] && { detail "hôte   : $p"; trouve=1; }
  done
  if command -v systemctl >/dev/null 2>&1; then
    local u
    u="$(systemctl list-unit-files 'plume-*' --no-legend 2>/dev/null | awk '{print $1}' || true)"
    [ -n "$u" ] && { detail "hôte   : unités systemd — $(echo "$u" | tr '\n' ' ')"; trouve=1; }
  else
    SONDAGE_IMPOSSIBLE+=("hôte : systemctl introuvable — les unités n'ont pas pu être sondées")
  fi
  TRACES_HOTE=$trouve
}

sonder_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    SONDAGE_IMPOSSIBLE+=("docker : commande introuvable — ce mode n'a pas pu être sondé")
    return 0
  fi
  if ! docker info >/dev/null 2>&1; then
    SONDAGE_IMPOSSIBLE+=("docker : démon injoignable — ce mode n'a pas pu être sondé")
    return 0
  fi
  local trouve=0 c v
  c="$(docker ps -a -q --filter "label=com.docker.compose.project=$PROJET" 2>/dev/null || true)"
  [ -n "$c" ] && { detail "docker : $(printf '%s\n' "$c" | wc -l) conteneur(s) du projet « $PROJET »"; trouve=1; }
  v="$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJET" 2>/dev/null || true)"
  [ -n "$v" ] && { detail "docker : volume(s) — $(echo "$v" | tr '\n' ' ')"; trouve=1; }
  # L'IMAGE SEULE N'EST PAS UNE PREUVE : `soc:latest` est un nom générique qui peut appartenir à
  # quelqu'un d'autre. On la signale, on ne s'en sert pas pour conclure — c'est la différence
  # entre observer et deviner.
  if docker image inspect soc:latest >/dev/null 2>&1; then
    detail "docker : image soc:latest présente (signalée, PAS retenue comme preuve du mode)"
  fi
  [ "$trouve" = 0 ] && detail "docker : aucune trace pour le projet « $PROJET » (autre nom ? --project <nom>)"
  TRACES_DOCKER=$trouve
}

sonder_k3s() {
  if ! command -v kubectl >/dev/null 2>&1; then
    SONDAGE_IMPOSSIBLE+=("k3s : kubectl introuvable — ce mode n'a pas pu être sondé")
    return 0
  fi
  if [ -z "$NS" ]; then
    SONDAGE_IMPOSSIBLE+=("k3s : namespace indéterminé (deploy/k3s.yaml illisible) — utilisez --namespace <ns>")
    return 0
  fi
  if ! kubectl get namespace "$NS" >/dev/null 2>&1; then
    if ! kubectl version >/dev/null 2>&1; then
      SONDAGE_IMPOSSIBLE+=("k3s : aucun cluster joignable dans le contexte courant — ce mode n'a pas pu être sondé")
    else
      detail "k3s   : namespace « $NS » absent"
    fi
    return 0
  fi
  detail "k3s   : namespace « $NS » présent"
  if kubectl -n "$NS" get deployment soc >/dev/null 2>&1; then
    detail "k3s   : Deployment soc présent dans « $NS »"
    TRACES_K3S=1
  else
    detail "k3s   : pas de Deployment « soc » dans « $NS » — namespace non attribué à plume"
  fi
}

inventaire() {
  dire "Sondage des trois modes de déploiement"
  sonder_hote
  sonder_docker
  sonder_k3s
  if [ "${#SONDAGE_IMPOSSIBLE[@]}" -gt 0 ]; then
    echo
    dire "Sondages IMPOSSIBLES (absence de trace non prouvée) :"
    for s in "${SONDAGE_IMPOSSIBLE[@]}"; do detail "· $s"; done
  fi
}

determiner_mode() {
  [ -n "$MODE" ] && return 0
  inventaire
  local n=$((TRACES_HOTE + TRACES_DOCKER + TRACES_K3S))
  echo
  if [ "$n" = 1 ]; then
    [ "$TRACES_HOTE"   = 1 ] && MODE=host
    [ "$TRACES_DOCKER" = 1 ] && MODE=docker
    [ "$TRACES_K3S"    = 1 ] && MODE=k3s
    dire "Un seul mode porte des traces : « $MODE »."
    return 0
  fi
  if [ "$n" = 0 ]; then
    alerte "AUCUN mode ne porte de trace de plume. Rien n'a été fait."
    alerte "Si l'installation existe ailleurs, désignez-la : --mode host|docker|k3s"
  else
    alerte "$n modes portent des traces à la fois. Ce script REFUSE de choisir à votre place."
    alerte "Désignez celui que vous voulez retirer : --mode host|docker|k3s  (un mode à la fois)"
  fi
  exit 2
}

# =================================================================================================
# MODE HÔTE (systemd, sans Docker)
# =================================================================================================
desinstaller_hote() {
  exiger_root
  dire "Mode HÔTE (systemd) — retrait depuis $SRC"

  local units
  units="$(systemctl list-unit-files 'plume-*' --no-legend 2>/dev/null | awk '{print $1}' || true)"
  [ -n "$units" ] && detail "unités à retirer : $(echo "$units" | tr '\n' ' ')"

  if [ "$PURGE" = 1 ]; then
    echo
    dire "!! --purge : CE QUI VA ÊTRE DÉTRUIT, ÉNUMÉRÉ AVANT DE L'ÊTRE"
    for p in /var/lib/plume/db /var/lib/plume/spool /var/lib/plume/state /var/lib/plume/backups; do
      if [ -e "$p" ]; then
        detail "· $p  ($(du -sh "$p" 2>/dev/null | cut -f1 || echo 'taille illisible'))"
      fi
    done
    [ -e /var/lib/plume ] && detail "· /var/lib/plume (l'arborescence entière, dont la clé du ledger)"
    getent passwd soc >/dev/null 2>&1 && detail "· l'utilisateur système « soc » et son groupe"
    detail "PERTE DE LA BASE ET DE LA CLÉ DU LEDGER : aucune récupération n'est possible ensuite."
    detail "Sauvegardez d'abord si besoin :  plume-daemon backup --out <fichier>"
    confirmer
  else
    detail "données /var/lib/plume CONSERVÉES (--purge pour les détruire aussi)."
  fi

  # 1. Arrêt + désactivation des unités, puis VÉRIFICATION : une unité qui reste active est un reste.
  for u in $units plume-daemon.service; do
    faire systemctl disable --now "$u" >/dev/null 2>&1 || true
  done
  if [ "$DRYRUN" = 0 ]; then
    for u in $units plume-daemon.service; do
      if systemctl is-active --quiet "$u" 2>/dev/null; then
        reste "unité systemd TOUJOURS ACTIVE : $u  (systemctl status $u)"
      fi
    done
  fi

  # 2. Tunnel reverse-ssh agent -> central, s'il en existe un.
  faire pkill -f 'ssh .*-R .*7000' >/dev/null 2>&1 || true

  # 3. Unités + DROP-INS. Les drop-ins de durcissement sont posés par `install_collector`
  #    (bootstrap-agent.sh) dans `<unité>.service.d/` : l'ancienne désinstallation retirait les
  #    unités et LAISSAIT ces répertoires derrière elle.
  faire rm -f /etc/systemd/system/plume-*.service /etc/systemd/system/plume-*.timer
  for d in /etc/systemd/system/plume-*.service.d; do
    [ -d "$d" ] || continue
    faire rm -f "$d/50-plume-hardening.conf"
    if [ "$DRYRUN" = 0 ]; then
      if rmdir "$d" 2>/dev/null; then retire "$d"; else reste "répertoire de drop-in NON VIDE, conservé : $d (contenu étranger à plume)"; fi
    else
      detail "[simulation] rmdir $d (si vide)"
    fi
  done
  faire systemctl daemon-reload >/dev/null 2>&1 || true

  # 4. Binaire, collecteurs, ressources partagées, configuration.
  #    /usr/local/share/plume (PWA + gabarit auditd) est posé par bootstrap.sh:19,34,70-72 et
  #    bootstrap-agent.sh:115-117 ; l'ancienne désinstallation ne le retirait pas.
  for p in /usr/local/bin/plume-daemon /usr/local/lib/plume /usr/local/share/plume /etc/plume; do
    if [ -e "$p" ]; then
      faire rm -rf "$p"
      if [ "$DRYRUN" = 0 ]; then
        [ -e "$p" ] && reste "n'a PAS pu être retiré : $p" || retire "$p"
      fi
    fi
  done

  # 5. Règles auditd posées par plume, et rechargement.
  if [ -f /etc/audit/rules.d/plume.rules ]; then
    faire rm -f /etc/audit/rules.d/plume.rules
    [ "$DRYRUN" = 0 ] && retire "/etc/audit/rules.d/plume.rules"
    if command -v augenrules >/dev/null 2>&1; then
      faire augenrules --load >/dev/null 2>&1 || reste "règles auditd non rechargées (augenrules a échoué) — la politique du noyau peut encore porter les règles plume jusqu'au prochain chargement"
    else
      reste "augenrules introuvable : les règles plume déjà CHARGÉES dans le noyau y restent jusqu'au redémarrage (auditctl -D pour les vider)"
    fi
  fi

  # 6. /etc/hosts — FICHIER PARTAGÉ, JAMAIS ÉDITÉ PAR CE SCRIPT.
  #    bootstrap.sh:95 y ajoute `127.0.0.1 soc.localhost`. L'éditer d'autorité reviendrait à
  #    modifier un fichier dont d'autres lignes ne nous appartiennent pas.
  if [ -f /etc/hosts ] && grep -q 'soc.localhost' /etc/hosts 2>/dev/null; then
    reste "/etc/hosts porte encore la ligne « soc.localhost » posée à l'installation — retrait manuel : sudo sed -i '/soc\\.localhost/d' /etc/hosts"
  fi

  # 7. Données + utilisateur système : UNIQUEMENT en --purge.
  if [ "$PURGE" = 1 ]; then
    faire rm -rf /var/lib/plume
    if [ "$DRYRUN" = 0 ]; then
      [ -e /var/lib/plume ] && reste "n'a PAS pu être retiré : /var/lib/plume" || retire "/var/lib/plume (données)"
    fi
    faire userdel soc >/dev/null 2>&1 || true
    faire groupdel soc >/dev/null 2>&1 || true
    if [ "$DRYRUN" = 0 ] && getent passwd soc >/dev/null 2>&1; then
      reste "l'utilisateur « soc » existe encore (processus survivant, ou compte non créé par plume) — userdel -f soc"
    fi
  else
    [ -e /var/lib/plume ] && conserve "/var/lib/plume — base, spool, sauvegardes, clé du ledger (choix par défaut)"
  fi

  # 8. Processus survivants.
  if [ "$DRYRUN" = 0 ] && command -v pgrep >/dev/null 2>&1; then
    if pgrep -x plume-daemon >/dev/null 2>&1; then
      reste "un processus plume-daemon tourne encore (binaire supprimé mais processus vivant) — pkill -x plume-daemon"
    fi
  fi
  return 0
}

# =================================================================================================
# MODE DOCKER
# =================================================================================================
desinstaller_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    alerte "docker introuvable : ce mode ne peut pas être désinstallé depuis cette machine. Rien n'a été fait."
    exit 2
  fi
  if ! docker info >/dev/null 2>&1; then
    alerte "démon Docker injoignable (droits ? service arrêté ?). Rien n'a été fait."
    exit 2
  fi
  local compose=(docker compose -p "$PROJET")
  [ -r "$SRC/docker-compose.yml" ] && compose=(docker compose -p "$PROJET" -f "$SRC/docker-compose.yml")

  dire "Mode DOCKER — projet compose « $PROJET »"
  local conteneurs volumes
  conteneurs="$(docker ps -a -q --filter "label=com.docker.compose.project=$PROJET" 2>/dev/null || true)"
  volumes="$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJET" 2>/dev/null || true)"
  [ -n "$conteneurs" ] && detail "conteneurs : $(printf '%s\n' "$conteneurs" | wc -l)"
  [ -n "$volumes" ]    && detail "volumes    : $(echo $volumes)"
  if [ -z "$conteneurs" ] && [ -z "$volumes" ]; then
    alerte "aucune ressource compose pour le projet « $PROJET »."
    alerte "compose nomme le projet d'après le RÉPERTOIRE : si vous avez lancé depuis un autre"
    alerte "chemin ou avec -p, redonnez ce nom (--project <nom>). Rien n'a été fait."
    exit 2
  fi

  if [ "$PURGE" = 1 ]; then
    echo
    dire "!! --purge : CE QUI VA ÊTRE DÉTRUIT, ÉNUMÉRÉ AVANT DE L'ÊTRE"
    for v in $volumes; do
      detail "· volume $v — il porte /data : la base, les sauvegardes locales et la clé du ledger"
    done
    docker image inspect soc:latest >/dev/null 2>&1 && detail "· image soc:latest (reconstructible : docker compose build)"
    detail "UN VOLUME DOCKER SUPPRIMÉ NE SE RÉCUPÈRE PAS."
    detail "Sauvegardez d'abord si besoin :  docker compose -p $PROJET exec soc plume-daemon backup --out /data/avant-purge.age"
    confirmer
  else
    detail "volume(s) de données CONSERVÉ(S) (--purge pour les détruire aussi)."
  fi

  # `down` retire conteneurs + réseaux du projet, et LAISSE les volumes nommés.
  if [ "$PURGE" = 1 ]; then
    faire "${compose[@]}" down --volumes --remove-orphans || reste "« docker compose down --volumes » a échoué — relancez-le et lisez son message"
  else
    faire "${compose[@]}" down --remove-orphans || reste "« docker compose down » a échoué — relancez-le et lisez son message"
  fi

  if [ "$DRYRUN" = 0 ]; then
    local restants
    restants="$(docker ps -a -q --filter "label=com.docker.compose.project=$PROJET" 2>/dev/null || true)"
    if [ -n "$restants" ]; then
      reste "conteneur(s) du projet toujours présents : $(printf '%s\n' "$restants" | tr '\n' ' ') — docker rm -f <id>"
    else
      retire "conteneurs et réseaux du projet « $PROJET »"
    fi
  fi

  if [ "$PURGE" = 1 ]; then
    for v in $volumes; do
      if [ "$DRYRUN" = 0 ]; then
        if docker volume inspect "$v" >/dev/null 2>&1; then
          if docker volume rm "$v" >/dev/null 2>&1; then
            retire "volume $v"
          else
            reste "volume NON supprimé : $v (encore référencé par un conteneur ?) — docker volume rm $v"
          fi
        else
          retire "volume $v"
        fi
      else
        detail "[simulation] docker volume rm $v"
      fi
    done
    if docker image inspect soc:latest >/dev/null 2>&1; then
      if [ "$DRYRUN" = 0 ]; then
        if docker image rm soc:latest >/dev/null 2>&1; then
          retire "image soc:latest"
        else
          reste "image soc:latest NON supprimée (utilisée par un autre conteneur) — docker image rm -f soc:latest"
        fi
      else
        detail "[simulation] docker image rm soc:latest"
      fi
    fi
  else
    for v in $volumes; do conserve "volume Docker $v — /data : base, sauvegardes, clé du ledger (choix par défaut)"; done
    if docker image inspect soc:latest >/dev/null 2>&1; then
      conserve "image soc:latest (choix par défaut ; --purge la retire)"
    fi
  fi
  return 0
}

# =================================================================================================
# MODE k3s / KUBERNETES — DIRE PLUTÔT QUE FAIRE
# =================================================================================================
desinstaller_k3s() {
  if [ -z "$NS" ]; then
    alerte "namespace indéterminé : deploy/k3s.yaml illisible depuis $SRC. Donnez-le : --namespace <ns>."
    alerte "Rien n'a été fait — ce script ne suppose pas un nom de namespace."
    exit 2
  fi
  # LE PLAN EST DÉRIVÉ DU MANIFESTE, PAS DU CLUSTER : il reste imprimable là où aucun cluster n'est
  # joignable — c'est précisément le cas où « dire quoi faire » a le plus de valeur. Seuls les
  # renseignements qui n'existent QUE dans le cluster (contexte, politique de récupération du
  # volume) manquent alors, et leur absence est DITE plutôt que comblée par une supposition.
  local ctx="<non consulté>" cluster=0
  if command -v kubectl >/dev/null 2>&1; then
    ctx="$(kubectl config current-context 2>/dev/null || echo '<aucun contexte>')"
    if kubectl get namespace "$NS" >/dev/null 2>&1; then
      cluster=1
    fi
  fi
  if [ "$cluster" = 0 ]; then
    if [ "$DRYRUN" != 1 ] && [ "$APPLY" = 1 ]; then
      alerte "namespace « $NS » injoignable ou absent (contexte « $ctx ») : --apply REFUSÉ, rien n'a été fait."
      alerte "Vérifiez le contexte (kubectl config get-contexts) ou le namespace (--namespace <ns>)."
      exit 2
    fi
    alerte "cluster non consulté (kubectl absent, sans contexte, ou namespace « $NS » introuvable)."
    alerte "Le plan ci-dessous est DÉRIVÉ DU MANIFESTE LIVRÉ, pas de l'état réel du cluster."
  fi

  dire "Mode k3s / Kubernetes"
  detail "contexte  : $ctx      <- LISEZ-LE : c'est le cluster qui sera touché"
  detail "namespace : $NS"
  echo

  # Le plan est DÉRIVÉ du manifeste livré, pas énuméré ici : un manifeste qui gagne une ressource
  # la voit apparaître dans ce plan sans qu'on y pense.
  local logiciel=() donnees=()
  if [ -r "$SRC/deploy/k3s.yaml" ]; then
    while IFS=$'\t' read -r kind nom; do
      [ -z "$kind" ] && continue
      case "$kind" in
        Namespace|PersistentVolumeClaim) donnees+=("$kind/$nom") ;;
        *) logiciel+=("$kind/$nom") ;;
      esac
    done < <(awk '
      /^[[:space:]]*#/ { next }
      /^---[[:space:]]*$/ { if (k != "") print k "\t" n; k = ""; n = ""; next }
      /^kind:[[:space:]]/ { k = $2; next }
      /name:[[:space:]]/ {
        if (n == "") { l = $0; sub(/.*name:[[:space:]]*/, "", l); sub(/[,}].*/, "", l); gsub(/[[:space:]]/, "", l); n = l }
      }
      END { if (k != "") print k "\t" n }' "$SRC/deploy/k3s.yaml")
  else
    alerte "deploy/k3s.yaml illisible : le plan ne peut pas être dérivé. Rien n'a été fait."
    exit 2
  fi

  dire "PLAN — ressources du LOGICIEL (retirées ; aucune donnée dedans) :"
  for r in "${logiciel[@]}"; do detail "· $r"; done
  echo
  dire "PLAN — ressources de DONNÉES (conservées SAUF --purge) :"
  for r in "${donnees[@]}"; do detail "· $r"; done

  # LA POLITIQUE DE RÉCUPÉRATION DU VOLUME EST UNE PROPRIÉTÉ DU CLUSTER, PAS DE CE SCRIPT.
  # `Delete` : supprimer le PVC détruit les octets. `Retain` : ils survivent, et le PV reste
  # « Released » — un reste que ce script ne peut pas nettoyer et qu'il doit donc nommer.
  local pv=""
  [ "$cluster" = 1 ] && pv="$(kubectl -n "$NS" get pvc soc-data -o jsonpath='{.spec.volumeName}' 2>/dev/null || true)"
  if [ -z "$pv" ]; then
    echo
    detail "Politique de récupération du volume : NON LUE (le cluster n'a pas répondu)."
    detail "  Lisez-la AVANT de purger — c'est elle qui décide si les octets partent avec le PVC :"
    detail "  kubectl -n $NS get pvc soc-data -o jsonpath='{.spec.volumeName}'"
    detail "  kubectl get pv <nom> -o jsonpath='{.spec.persistentVolumeReclaimPolicy}'"
  fi
  if [ -n "$pv" ]; then
    local politique
    politique="$(kubectl get pv "$pv" -o jsonpath='{.spec.persistentVolumeReclaimPolicy}' 2>/dev/null || echo inconnue)"
    echo
    detail "PVC soc-data -> PersistentVolume « $pv », politique de récupération : $politique"
    case "$politique" in
      Delete) detail "  « Delete » : supprimer le PVC DÉTRUIT les octets. Sauvegardez avant." ;;
      Retain) detail "  « Retain » : les octets SURVIVENT au PVC et le PV restera « Released ». Ce script ne le nettoie pas." ;;
      *)      detail "  politique non lue : traitez la suppression du PVC comme DESTRUCTRICE." ;;
    esac
  fi

  if [ "$APPLY" != 1 ] || [ "$DRYRUN" = 1 ]; then
    echo
    dire "RIEN N'A ÉTÉ EXÉCUTÉ. Ce mode touche un cluster : il imprime, vous exécutez."
    dire "Les commandes, dans l'ordre :"
    for r in "${logiciel[@]}"; do detail "kubectl -n $NS delete $(printf '%s' "${r%%/*}" | tr 'A-Z' 'a-z') ${r##*/} --ignore-not-found"; done
    if [ "$PURGE" = 1 ]; then
      detail "kubectl -n $NS delete persistentvolumeclaim soc-data      # DESTRUCTEUR (cf. politique ci-dessus)"
      detail "kubectl delete namespace $NS                              # supprime TOUT ce qui reste dedans"
    else
      detail "# PVC et Namespace conservés. Ajoutez --purge pour les inclure au plan."
    fi
    detail "# pour que ce script les exécute lui-même : --apply"
    PLAN_SEUL=1
    return 0
  fi

  if [ "$PURGE" = 1 ]; then
    echo
    dire "!! --apply --purge : le PVC et le namespace « $NS » vont être SUPPRIMÉS."
    detail "Tout ce que d'autres auraient déposé dans ce namespace partira avec lui."
    confirmer
  fi

  for r in "${logiciel[@]}"; do
    local kind nom
    kind="$(printf '%s' "${r%%/*}" | tr 'A-Z' 'a-z')"; nom="${r##*/}"
    if kubectl -n "$NS" delete "$kind" "$nom" --ignore-not-found >/dev/null 2>&1; then
      retire "$NS/$r"
    else
      reste "NON supprimé (droits RBAC ? finalizer ?) : $NS/$r — kubectl -n $NS delete $kind $nom"
    fi
  done

  if [ "$PURGE" = 1 ]; then
    if kubectl -n "$NS" delete persistentvolumeclaim soc-data --ignore-not-found >/dev/null 2>&1; then
      retire "$NS/PersistentVolumeClaim/soc-data"
    else
      reste "PVC soc-data NON supprimé — kubectl -n $NS delete pvc soc-data"
    fi
    if kubectl delete namespace "$NS" --ignore-not-found >/dev/null 2>&1; then
      retire "Namespace/$NS"
    else
      reste "namespace « $NS » NON supprimé (finalizer bloquant ?) — kubectl get namespace $NS -o yaml"
    fi
    if [ -n "$pv" ] && kubectl get pv "$pv" >/dev/null 2>&1; then
      reste "PersistentVolume « $pv » subsiste (politique Retain, ou libération en cours) — kubectl delete pv $pv, après avoir vérifié qu'il ne sert plus"
    fi
  else
    conserve "$NS/PersistentVolumeClaim/soc-data et Namespace/$NS (choix par défaut)"
  fi
  return 0
}

# =================================================================================================
# RÉSUMÉ — ce qui est parti, ce qui reste, et pourquoi
# =================================================================================================
resumer() {
  echo
  if [ "$PLAN_SEUL" = 1 ]; then
    dire "PLAN IMPRIMÉ — rien n'a été exécuté, donc rien n'est terminé."
    return 0
  fi
  if [ "$DRYRUN" = 1 ]; then
    dire "SIMULATION terminée : aucune modification n'a été faite."
    return 0
  fi
  if [ "${#RETIRES[@]}" -gt 0 ]; then
    dire "RETIRÉ :"
    for r in "${RETIRES[@]}"; do detail "· $r"; done
  fi
  if [ "${#CONSERVES[@]}" -gt 0 ]; then
    dire "CONSERVÉ DÉLIBÉRÉMENT (le geste par défaut ne détruit pas de données) :"
    for r in "${CONSERVES[@]}"; do detail "· $r"; done
  fi
  if [ "${#RESTES[@]}" -gt 0 ]; then
    echo
    alerte "RESTES — ce script n'a PAS pu tout retirer. ${#RESTES[@]} point(s) :"
    for r in "${RESTES[@]}"; do printf '   · %s\n' "$r" >&2; done
    alerte "code de sortie 3 : la désinstallation est INCOMPLÈTE et le dit."
    exit 3
  fi
  dire "Désinstallation terminée. Aucun reste connu de ce script."
  dire "Le dépôt source ($SRC) n'est pas touché."
}

# =================================================================================================
main() {
  if [ "$DRYRUN" = 1 ] && [ -z "$MODE" ]; then
    inventaire
    echo
    dire "Inventaire seul : aucun mode désigné, aucune modification. Désignez un mode pour voir son plan :"
    detail "bash uninstall.sh --dry-run --mode host|docker|k3s"
    exit 0
  fi
  determiner_mode
  echo
  case "$MODE" in
    host)   desinstaller_hote ;;
    docker) desinstaller_docker ;;
    k3s)    desinstaller_k3s ;;
  esac
  resumer
}
main
