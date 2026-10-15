#!/usr/bin/env python3
"""Une installation est fonctionnelle et durcie dans les trois modes — garde de CI (`P10.32-j`).

LES DÉFAUTS QUE CETTE GARDE REND NON-ÉCRIVABLES
-----------------------------------------------
Hôte natif. (a) `bootstrap.sh` installait les capteurs sans `collectors/lib.sh`, que chacun charge
(`. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"`) : une installation centrale par ce script seul livrait des
capteurs qui échouaient tous. (b) Il ne posait pas le drop-in `plume-collector-common.conf` que
`bootstrap-agent.sh` pose. (c) Sans auditd, il ne disait pas pourquoi le capteur ne collecte rien (les règles, elles, étaient
déjà conditionnées à `augenrules`, et le capteur avoue au SOC sa source absente) ; elles exigent
désormais `augenrules` ET `auditctl`. Posé tel quel, le drop-in commun aurait aussi donné AF_INET et
AF_INET6 à sept capteurs du central sans usage du réseau : le central le posait sans sa ligne
`RestrictAddressFamilies=` — ligne retirée du drop-in lui-même depuis `P10.33-d` (ci-dessous).
(d) `/etc/plume/plume.conf` (le jeton de l'agent) était 0640 root:soc alors qu'aucun processus lancé
sous `soc` ne le lit — et `responder.conf`, qui recopie le même jeton, aussi. Une conf déjà posée était
gardée en silence, commentaires de fin de valeur compris. README.md prescrivait encore `chgrp soc` sur
plume.conf ; deploy/SYSLOG.md présentait comme conf par défaut l'écoute 0.0.0.0, les commentaires en fin
de valeur et « vider = désactiver » (VRAI depuis `P10.32-l` : une écoute posée vide coupe son transport, une
écoute ABSENTE vaut 0.0.0.0:514). (e) `systemd/plume-pod-logs.service` forçait une liste de pods d'un parc
particulier et un seuil de sévérité que ni le script ni la sonde ne disent. (h) La conf syslog
engendrée écrivait ses commentaires EN FIN DE VALEUR — systemd les garde dans la valeur, si bien que
la liste d'autorisation valait `# ex: …` (le récepteur s'arrête) — et écoutait 0.0.0.0 avec une liste
vide. La même faute de commentaire rendait `PLUME_RESPONDER_APPLY=1   # …` différent de `1`.
k3s. (f) Ingress sans TLS et servi aussi en HTTP, pas de profil seccomp, jeton de compte de service
monté sans usage, entrée réseau ouverte depuis tout namespace.
Docker. (g) Aucun `cap_drop`, et PLUME_TLS_CERT/PLUME_TLS_KEY jamais transmis au conteneur ;
PLUME_TLS_TERMINATED_UPSTREAM pareil (`P10.32-t`), et absent du Deployment k3s derrière un Ingress HTTPS seul.

CE QUE LA GARDE FAIT
--------------------
Elle JOUE les deux installeurs LIVRÉS, dans un bac : le texte du script est exécuté tel quel, seules
ses racines absolues (`/etc`, `/usr/local`, `/var/lib/plume`) sont réacheminées sous un répertoire
temporaire, et les outils qui exigent root ou une machine réelle (`install` avec `-o/-g`, `chgrp`,
`chown`, `systemctl`, `getent`, `groupadd`, `useradd`, `hostname`, `augenrules`, `auditctl`) sont des
exécutables factices du PATH qui JOURNALISENT chaque geste, dans l'ordre. Le PATH ne contient que ces
factices et des liens vers les outils réels de la machine, MOINS `auditctl`, `augenrules` et `cargo` :
leur absence est ainsi un scénario, pas un accident de l'exécuteur. Puis elle juge :
  · chaque fichier installé sous `collectors/` qui charge `lib.sh` trouve `lib.sh` installé AVANT lui,
    dans le même répertoire, pour CHAQUE installeur et chaque scénario (central, agent avec tous les
    capteurs en supplément, agent avec tous les modules optionnels) ;
  · chaque unité de capteur (ExecStart sous /usr/local/lib/plume/collectors/) posée par le central
    ou par `install_collector` a son drop-in, `systemd/plume-collector-common.conf` octet pour octet,
    posé avant le premier `systemctl daemon-reload` ;
  · `P10.33-d` — sur le central ET sur l'agent, aucune unité de capteur ne reçoit du drop-in une
    famille d'adresses qu'elle ne déclare pas, chacune déclare la sienne, et le drop-in n'en porte
    AUCUNE (une liste de drop-in s'UNIT : sur l'agent, il donnait AF_UNIX AF_NETLINK AF_INET AF_INET6 à
    tous). Et la famille de chaque unité livrée est DÉRIVÉE de ce que son ExecStart appelle — le script,
    les fonctions qu'il définit, celles de `lib.sh` (`kctl`), la seule branche d'un mode d'argument
    (`revert-expired`) — par une table outil → famille (`FAMILLES_DES_OUTILS` : curl, kubectl, cscli,
    skopeo, trivy → AF_INET/AF_INET6 ; nft, auditctl, ss, ip → AF_NETLINK ; iptables, ufw → les deux ;
    docker, crictl, systemctl → AF_UNIX) : une famille MANQUANTE (le script l'ouvre, `socket()`
    échouerait) et une famille EN TROP (rien ne l'ouvre) sont des fautes. Un script qui exécute du CODE
    D'EXPLOITANT (`sh -c "$V"`/`eval "$V"`, V jamais affectée d'un littéral : `controls` et ses
    catalogues `/etc/plume/controls.d/*.check`, `custom` et ses déclarations) exige TOUTES les familles.
    L'instrument est éprouvé : un appel direct, par variable, par fonction, une ligne de catalogue lue
    par `read` sont vus ; un message, un `command -v`, un commentaire, un chemin, l'argument d'un
    `plume_unavailable`, un programme écrit dans le script (`_LIRE_JOURNAL` de mail.sh) ne le sont pas ;
  · sans `augenrules`, sans `auditctl`, ou sans les deux : aucune règle posée, l'installeur le dit, et
    `plume-auditd.timer` reste ACTIVÉ — c'est lui qui porte au SOC l'aveu `missing-source` du
    capteur ; avec les deux : règles posées (le témoin positif de la même mesure) ;
  · `plume.conf` et `responder.conf` (le même jeton) finissent 0600, jamais confiés au groupe `soc`,
    et ne sont JAMAIS plus ouverts que 0600 au premier geste qui les touche après leur création (les
    faux chown/chgrp journalisent le mode qu'ils trouvent) — à la création comme au re-passage d'une
    conf 0640 existante — et AUCUN processus lancé sous `soc` ne lit plume.conf (unités `User=soc` qui
    lancent le démon : `PLUME_CONFIG` posé ailleurs ; sources des autres : aucune mention) ;
  · au re-passage, une conf existante est gardée OCTET POUR OCTET, mais chaque clé dont la valeur
    porte un commentaire est NOMMÉE — elles seules, jamais leur valeur (un jeton commenté ne sort pas) —,
    ainsi que chaque écoute syslog hors boucle locale à liste vide — par sa CLÉ, jamais sa valeur —, avec
    « REFUSERA DE DEMARRER » (`P10.32-l` : le récepteur sort en code 2) ; la conf syslog posée est l'ANCIENNE
    CONF ENGENDRÉE octet pour octet (`PLUME_SYSLOG_ALLOW=          # ex: …`, valeur qui COMMENCE par
    `#`). Les trois fonctions de signalement livrées sont aussi jouées seules sur des confs syslog, la
    sémantique de `env_ecoute` (collector-syslog) : adresse ABSENTE = 0.0.0.0:514, posée VIDE ou blanche =
    transport coupé (UDP, TCP, chacune seule), adresse sans port ou à port hors bornes = hors boucle
    locale, liste `""`, `''` ou faite de seuls séparateurs = vide, ligne `;` = commentaire, et les témoins
    négatifs (liste posée, nue ou entre guillemets ; boucle locale v4, `[::1]`, `localhost` ; deux
    écoutes coupées). Aucune sortie, aucun texte de l'installeur, de l'unité ni de deploy/SYSLOG.md ne
    redit « absente ou vide = 0.0.0.0:514 », « vider ne désactive pas » ni « toute source est acceptée ».
    Un second passage sur les confs que l'installeur vient d'engendrer se tait (le témoin négatif) ;
  · toute conf engendrée sous /etc/plume qu'une unité charge par `EnvironmentFile=` est lue SELON
    systemd (un commentaire de fin de ligne reste dans la valeur) : aucune valeur n'en porte ; la
    conf syslog écoute 127.0.0.1:514 en UDP et TCP, liste vide, et son commentaire nomme la liste
    d'autorisation ET le pare-feu ;
  · l'unité pod-logs ne pose aucune valeur PLUME_POD_LOG_* qui diffère du défaut du script ;
  · `deploy/k3s.yaml` et `docker-compose.yml` sont LUS PAR UN ANALYSEUR YAML (PyYAML), et leurs
    propriétés jugées sur l'objet, pas sur le texte : TLS de l'Ingress posé (secretName non vide,
    hôtes = hôtes des règles), entrée Traefik `websecure` SEULE, seccomp RuntimeDefault,
    `automountServiceAccountToken: false` — adossé à l'absence de tout client de l'API Kubernetes
    dans `daemon/src` —, entrée réseau limitée à `kube-system` et au namespace ; `cap_drop: [ALL]`,
    `no-new-privileges:true`, PLUME_TLS_CERT, PLUME_TLS_KEY et PLUME_TLS_TERMINATED_UPSTREAM transmis depuis
    `.env` ; PLUME_TLS_TERMINATED_UPSTREAM=1 dans le Deployment k3s, dont l'Ingress ne sert que du HTTPS ;
  · la documentation suit — consigne affichée par bootstrap-agent.sh comprise (`sudo chmod 0600`, en
    en-tête ET au 1er passage sans secret) : aucun `chgrp soc`/`chmod 0640` prescrit sur plume.conf ou responder.conf,
    et la conf syslog de deploy/SYSLOG.md, lue selon systemd, est celle de l'installeur (127.0.0.1,
    liste vide, aucun commentaire dans une valeur, pas de « vider ne désactive pas »).
  · `P10.33-c` — les règles d'audit passent par UN SEUL chargeur (`systemd/plume-audit-rules-load.sh`) :
    aucun installeur ne lance `augenrules --load`/`auditctl -R` lui-même ; le central l'appelle, l'agent
    le pose et l'affiche, et le chargeur INSTALLÉ, joué sans argument, trouve son gabarit. Le chargeur est
    joué SEUL, sous CHAQUE awk présent (gawk, mawk), contre des faux `auditctl`/`augenrules` qui imitent
    le réel (un noyau en fichier ; « Rule exists » ; `auditctl -R` s'arrête à la première règle en échec
    sans annuler les précédentes) : nominal et re-passage (le plume.rules précédent n'est pas un doublon)
    → code 0, tout chargé, au redémarrage simulé aussi ; doublon
    textuel d'un fichier tiers AVANT ou APRÈS plume.rules → tout chargé, au redémarrage aussi, doublon
    nommé (fichier, ligne), règles tierces intactes ; doublon écrit autrement → code 2 avoué, tout chargé
    maintenant ; erreur réelle dans le gabarit → code 1, nommée (ligne, règle, message), sans décapiter
    les règles qui la suivent. Le central, joué avec ces faux : nominal, doublon tiers (dit, tout chargé,
    code 0) et fichier tiers fautif avant plume (code 3, avoué en fin de course). La doc dit le geste de
    vérification (`-k` ET `key=`) et quoi faire d'un doublon ; rien ne fait compter `key=plume_` seul.
CE QU'ELLE NE TIENT PAS : la table outil → famille est lue du CODE des outils, pas MESURÉE sous
systemd (aucune unité n'a été jouée avec sa nouvelle liste) ; un outil qui ouvrirait une famille
inattendue (un `getaddrinfo` qui sonde les interfaces par netlink) n'est vu que par cette table.
Le code d'exploitant n'est reconnu que sous la forme `sh|bash|dash -c "$V"` / `eval "$V"` : un script
qui exécuterait un fichier d'exploitant autrement (`. "$f"`, `"$f"` nu, `xargs sh`) ne serait pas vu, et
sa liste resserrée ferait mourir les commandes de l'exploitant. Les capacités (`CapabilityBoundingSet=`)
ne sont pas jugées par cette dérivation.
Ses propres instruments sont éprouvés à chaque exécution : le lecteur systemd sur des lignes connues,
le juge d'ordre sur un journal où `lib.sh` arrive trop tard, le réacheminement sur l'absence de toute
racine non réacheminée.

Codes de sortie : 0 conforme · 1 propriété violée · 2 l'instrument REFUSE DE CONCLURE.
Le chargeur d'audit exécute awk : il est joué sous chaque awk présent ; aucun → REFUSE DE CONCLURE.
"""
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

RACINE_DEPOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DOSSIER_CAPTEURS = "/usr/local/lib/plume/collectors"
DROPIN = "50-plume-hardening.conf"
fautes = []
refus = []


def faute(msg):
    fautes.append(msg)
    print(f"::error::{msg}")


def refuser(msg):
    refus.append(msg)
    print(f"::error::REFUSE DE CONCLURE : {msg}")


def lire(chemin):
    with open(chemin, encoding="utf-8", errors="replace") as f:
        return f.read()


# --------------------------------------------------------------------------------------------------
# Lecteur d'EnvironmentFile SELON systemd : une ligne qui commence par `#` ou `;` est un commentaire ;
# sinon la valeur est tout ce qui suit `=`, espaces de tête et de fin retirés, guillemets de bord
# retirés — un `#` en milieu de ligne N'EST PAS un commentaire (mesuré, systemd 262 :
# `A=x       # c` arrive `x       # c`).
# --------------------------------------------------------------------------------------------------
def lire_env_systemd(texte):
    valeurs = {}
    for ligne in texte.splitlines():
        brut = ligne.strip()
        if not brut or brut[0] in "#;":
            continue
        if "=" not in brut:
            continue
        cle, val = brut.split("=", 1)
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
            val = val[1:-1]
        valeurs[cle.strip()] = val
    return valeurs


def eprouver_lecteur_systemd():
    v = lire_env_systemd("A=x       # c\nB=          # ex: 203.0.113.10/32\n# C=1\n ; D=2\nE=\"q r\"\n")
    attendu = {"A": "x       # c", "B": "# ex: 203.0.113.10/32", "E": "q r"}
    if v != attendu:
        refuser(f"le lecteur systemd de la garde ne rend pas ce que systemd rend : {v!r} au lieu de {attendu!r}")


# --------------------------------------------------------------------------------------------------
# Réacheminement des racines absolues du script LIVRÉ vers le bac.
# --------------------------------------------------------------------------------------------------
RACINES = re.compile(r"(?<![\w.$/{}-])/(etc|usr/local|var/lib/plume)(?=/|\b)")


def reacheminer(texte):
    return RACINES.sub(lambda m: "${PLUME_BAC_RACINE}/" + m.group(1), texte)


def eprouver_reacheminement(texte_reachemine, nom):
    # Une racine réacheminée est précédée de `}` (exclu par le regard arrière) : ce qui reste n'en est pas une.
    reste = [m.group(0) for m in RACINES.finditer(texte_reachemine)]
    if reste:
        refuser(f"{nom} : racines non réacheminées dans le bac : {sorted(set(reste))}")
    if "${PLUME_BAC_RACINE}/etc/plume" not in texte_reachemine:
        refuser(f"{nom} : le réacheminement n'a rien trouvé à réacheminer — le script a changé de forme")


# --------------------------------------------------------------------------------------------------
# Le bac
# --------------------------------------------------------------------------------------------------
EXCLUS_DU_PATH = {"install", "chgrp", "chown", "systemctl", "getent", "groupadd", "useradd", "hostname",
                  "augenrules", "auditctl", "cargo", "sudo"}

# Un `python3 -I` par appel coûtait ~40 ms sur l'exécuteur, pour ~400 appels : le faux est en bash.
FAUX_INSTALL = r'''#!{bash}
garde=(); pos=(); rep=0
while [ $# -gt 0 ]; do
  x=$1
  case "$x" in
    -o|-g) shift 2; continue ;;
    -m) garde+=("$x" "$2"); shift 2; continue ;;
  esac
  if [ ${#x} -gt 2 ]; then case "$x" in -o*|-g*) shift; continue ;; esac; fi
  [ "$x" = -d ] && rep=1
  case "$x" in -*) ;; *) pos+=("$x") ;; esac
  garde+=("$x"); shift
done
{reel} "${garde[@]}"; rc=$?
n=${#pos[@]}
{
if [ $rep = 1 ]; then
  for p in "${pos[@]}"; do printf 'install\t%s\t-\t%d\n' "$(realpath -ms -- "$p")" "$rc"; done
elif [ "$n" -ge 2 ]; then
  cible=${pos[$((n-1))]}
  if [ -d "$cible" ]; then
    for src in "${pos[@]:0:$((n-1))}"; do
      printf 'install\t%s\t%s\t%d\n' "$(realpath -ms -- "$cible/${src##*/}")" "$src" "$rc"
    done
  else
    printf 'install\t%s\t%s\t%d\n' "$(realpath -ms -- "$cible")" "${pos[0]}" "$rc"
  fi
fi
} >> "$PLUME_BAC_JOURNAL"
exit $rc
'''

FAUX_JOURNALISANT = r'''#!/bin/sh
printf '%s\t%s\n' "{nom}" "$*" >> "$PLUME_BAC_JOURNAL"
{suite}
exit 0
'''

# chown/chgrp journalisent EN PLUS le mode de chaque fichier qu'ils touchent, AU MOMENT du geste : c'est
# le mode de création (umask), que le chmod qui suit efface et qu'aucun état final ne montre.
SUITE_MODE = 'for a in "$@"; do [ -f "$a" ] && printf \'mode\\t%s\\t%s\\n\' "$a" "$(stat -c %a "$a")" >> "$PLUME_BAC_JOURNAL"; done'


# `P10.33-c` — FAUX auditctl / augenrules QUI IMITENT LE COMPORTEMENT RÉEL, noyau compris (un fichier
# d'état, une règle canonique par ligne) : une règle déjà présente rend « Error sending add rule data
# request (Rule exists) » ; `-F dir=`/`-F path=` sur un chemin absent rend « (No such file or
# directory) » ; `auditctl -R` S'ARRÊTE à la première règle en échec (« There was an error in line N »)
# SANS annuler les précédentes ; `augenrules --load` concatène les `*.rules` dans l'ordre du nom puis
# `auditctl -R`. `auditctl -l` rend la forme du noyau : `-F key=` pour une règle syscall, `-k` pour une
# watch, `auid!=4294967295`/`unset` rendus `auid!=-1` (même valeur pour le noyau).
FAUX_AUDITCTL = r"""#!/bin/bash
etat=${PLUME_BAC_AUDIT_ETAT:?}
printf 'auditctl\t%s\n' "$*" >> "${PLUME_BAC_JOURNAL:-/dev/null}"
touch "$etat"
canon() {
  local a=("$@") out=() k= i=0 w
  while [ $i -lt ${#a[@]} ]; do
    w=${a[$i]}
    if [ "$w" = -k ]; then k=${a[$((i+1))]}; i=$((i+2)); continue; fi
    case $w in 'auid!=4294967295'|'auid!=unset') w='auid!=-1' ;; esac
    out+=("$w"); i=$((i+1))
  done
  if [ -n "$k" ]; then if [ "${a[0]}" = -w ]; then out+=(-k "$k"); else out+=(-F "key=$k"); fi; fi
  printf '%s\n' "${out[*]}"
}
ajouter() {
  local a=("$@") i f c
  case ${a[0]} in -a|-A|-w) ;; *) echo "auditctl: option inconnue ${a[0]}" >&2; return 1 ;; esac
  for ((i = 0; i < ${#a[@]}; i++)); do
    [ "${a[$i]}" = -F ] || continue
    f=${a[$((i+1))]}
    case $f in dir=*|path=*) [ -e "${f#*=}" ] || { echo "Error sending add rule data request (No such file or directory)" >&2; return 1; } ;; esac
  done
  c=$(canon "$@")
  if grep -qxF -- "$c" "$etat"; then echo "Error sending add rule data request (Rule exists)" >&2; return 1; fi
  printf '%s\n' "$c" >> "$etat"
}
case ${1:-} in
  -l) if [ -s "$etat" ]; then cat "$etat"; else echo "No rules"; fi; exit 0 ;;
  -D) : > "$etat"; exit 0 ;;
  -R)
    n=0
    while IFS= read -r l || [ -n "$l" ]; do
      n=$((n+1))
      read -ra w <<< "$l"
      [ ${#w[@]} -eq 0 ] && continue
      case ${w[0]} in '#'*) continue ;; -D) : > "$etat"; continue ;; -b|-f|-e|-r|--backlog_wait_time) continue ;; esac
      ajouter "${w[@]}" || { echo "There was an error in line $n of $2" >&2; exit 1; }
    done < "$2"
    exit 0 ;;
  *) ajouter "$@" || exit 1; exit 0 ;;
esac
"""

FAUX_AUGENRULES = r"""#!/bin/bash
printf 'augenrules\t%s\n' "$*" >> "${PLUME_BAC_JOURNAL:-/dev/null}"
d=${PLUME_BAC_RULES_D:?}; out=${PLUME_BAC_AUDIT_RULES:?}
echo "## This file is automatically generated from $d" > "$out"
for f in $(ls "$d" | LC_ALL=C sort); do
  case $f in *.rules) cat "$d/$f" >> "$out" ;; esac
done
[ "${1:-}" = --load ] && exec auditctl -R "$out"
exit 0
"""

# Base d'un /etc/audit/rules.d d'Ubuntu : `audit.rules` vient AVANT `plume.rules` et commence par -D.
BASE_RULES_D = "-D\n-b 8192\n-f 1\n--backlog_wait_time 60000\n"
CHARGEUR = "systemd/plume-audit-rules-load.sh"
GABARIT = "systemd/plume-audit.rules"
AWK_EXERCES = ("gawk", "mawk")
VERIFIER_AUDIT = "sudo auditctl -l | grep -cE -- '(-k |key=)plume_'"


def canon_regle(mots):
    """Forme du noyau d'une règle (celle de FAUX_AUDITCTL), recalculée ICI de façon indépendante."""
    out, k, i = [], None, 0
    while i < len(mots):
        w = mots[i]
        if w == "-k":
            k = mots[i + 1]
            i += 2
            continue
        out.append({"auid!=4294967295": "auid!=-1", "auid!=unset": "auid!=-1"}.get(w, w))
        i += 1
    if k:
        out += ["-k", k] if mots[0] == "-w" else ["-F", "key=" + k]
    return " ".join(out)


def regles_du_gabarit(texte):
    """(numéro de ligne, forme canonique) de chaque règle ACTIVE du gabarit."""
    return [(n, canon_regle(l.split())) for n, l in enumerate(texte.splitlines(), 1)
            if re.match(r"\s*-[aAw]\b", l)]


class Bac:
    def __init__(self, nom, outils_audit=(), gabarit=None):
        base = os.environ.get("TMPDIR") or None
        self.d = tempfile.mkdtemp(prefix=f"plume-installation-{nom}-", dir=base)
        self.racine = os.path.join(self.d, "racine")
        self.src = os.path.join(self.d, "src")
        self.bin = os.path.join(self.d, "bin")
        self.sys = os.path.join(self.d, "sys")
        self.journal = os.path.join(self.d, "journal")
        for r in ("etc/systemd/system", "usr/local/bin", "etc/audit/rules.d"):
            os.makedirs(os.path.join(self.racine, r), exist_ok=True)
        open(os.path.join(self.racine, "etc/hosts"), "w").close()
        open(self.journal, "w").close()
        os.makedirs(self.src)
        for lien in ("collectors", "systemd", "web"):
            if lien == "systemd" and gabarit is not None:
                # `P10.33-c` — un gabarit d'audit VARIANTE, le reste de systemd/ lié au dépôt.
                os.makedirs(os.path.join(self.src, lien))
                for f in os.listdir(os.path.join(RACINE_DEPOT, lien)):
                    if f != os.path.basename(GABARIT):
                        os.symlink(os.path.join(RACINE_DEPOT, lien, f), os.path.join(self.src, lien, f))
                with open(os.path.join(self.src, GABARIT), "w") as f:
                    f.write(gabarit)
                continue
            os.symlink(os.path.join(RACINE_DEPOT, lien), os.path.join(self.src, lien))
        self._binaire("daemon/target/release/plume-daemon",
                      "#!/bin/sh\necho '  cold-backup-plan   plan de sauvegarde du tier froid : INDISPONIBLE'\n")
        self._binaire("collector-syslog/target/release/plume-collector-syslog", "#!/bin/sh\nexit 0\n")
        self._binaire("collector-mail/target/release/plume-collector-mail", "#!/bin/sh\nexit 0\n")
        os.makedirs(self.bin)
        os.makedirs(self.sys)
        vus = set()
        for rep in ("/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"):
            if not os.path.isdir(rep):
                continue
            for n in os.listdir(rep):
                if n in vus or n in EXCLUS_DU_PATH:
                    continue
                p = os.path.join(rep, n)
                if os.path.isfile(p) and os.access(p, os.X_OK):
                    vus.add(n)
                    os.symlink(p, os.path.join(self.sys, n))
        reel = shutil.which("install", path="/usr/bin:/bin")
        if not reel:
            refuser("aucun `install` réel sur cet exécuteur")
            reel = "/usr/bin/install"
        bash = shutil.which("bash") or "/bin/bash"
        self._outil("install", FAUX_INSTALL.replace("{bash}", bash).replace("{reel}", shlex.quote(reel)))
        for n, suite in (("chgrp", SUITE_MODE), ("chown", SUITE_MODE), ("getent", ""), ("groupadd", ""),
                         ("useradd", ""), ("systemctl", '[ "$1" = is-active ] && echo active'),
                         ("hostname", "echo hote-bac")):
            self._outil(n, FAUX_JOURNALISANT.replace("{nom}", n).replace("{suite}", suite))
        # Chaque outil d'audit est un scénario À LUI SEUL : l'installeur exige les DEUX.
        if "augenrules" in outils_audit:
            self._outil("augenrules", FAUX_AUGENRULES)
        if "auditctl" in outils_audit:
            self._outil("auditctl", FAUX_AUDITCTL)
        self.etat_audit = os.path.join(self.d, "noyau-audit")
        with open(os.path.join(self.racine, "etc/audit/rules.d/audit.rules"), "w") as f:
            f.write(BASE_RULES_D)

    def _binaire(self, rel, contenu):
        p = os.path.join(self.src, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(contenu)
        os.chmod(p, 0o755)

    def _outil(self, nom, contenu):
        p = os.path.join(self.bin, nom)
        with open(p, "w") as f:
            f.write(contenu)
        os.chmod(p, 0o755)

    def poser(self, rel, contenu, mode):
        p = os.path.join(self.racine, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(contenu)
        os.chmod(p, mode)

    def jouer(self, script, env_sup):
        texte = reacheminer(lire(os.path.join(RACINE_DEPOT, script)))
        eprouver_reacheminement(texte, script)
        cible = os.path.join(self.src, script)
        with open(cible, "w") as f:
            f.write(texte)
        env = {"PATH": f"{self.bin}:{self.sys}", "HOME": self.d, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
               "PLUME_BAC_RACINE": self.racine, "PLUME_BAC_JOURNAL": self.journal,
               "TMPDIR": self.d, "PLUME_BAC_AUDIT_ETAT": self.etat_audit,
               "PLUME_BAC_RULES_D": self.r("/etc/audit/rules.d"), "PLUME_BAC_AUDIT_RULES": self.r("/etc/audit/audit.rules")}
        env.update(env_sup)
        r = subprocess.run(["bash", cible], env=env, cwd=self.d, capture_output=True, text=True, timeout=300)
        self.sortie = r.stdout + r.stderr
        self.rc = r.returncode
        return self

    def gestes(self):
        return [l.rstrip("\n").split("\t") for l in open(self.journal, encoding="utf-8") if l.strip()]

    def r(self, chemin_absolu):
        return os.path.join(self.racine, chemin_absolu.lstrip("/"))

    def nettoyer(self):
        shutil.rmtree(self.d, ignore_errors=True)


# --------------------------------------------------------------------------------------------------
# Juges
# --------------------------------------------------------------------------------------------------
CHARGE_LIB = re.compile(r'^\s*\.\s+"?\$\{PLUME_LIB:-\$\(dirname "\$0"\)/lib\.sh\}"?', re.M)


def juger_lib_avant_capteurs(gestes, racine, lire_installe, nom):
    """Rend la liste des fautes : capteur installé (chargeant lib.sh) sans lib.sh posé AVANT lui."""
    out = []
    lib = os.path.normpath(os.path.join(racine, DOSSIER_CAPTEURS.lstrip("/"), "lib.sh"))
    dossier = os.path.dirname(lib)
    rang_lib = None
    capteurs = 0
    for i, g in enumerate(gestes):
        if g[0] != "install" or g[2] == "-":
            continue
        dest = g[1]
        if dest == lib:
            if rang_lib is None:
                rang_lib = i
            continue
        if os.path.dirname(dest) != dossier:
            continue
        contenu = lire_installe(dest)
        if contenu is None or not CHARGE_LIB.search(contenu):
            continue
        capteurs += 1
        if rang_lib is None:
            out.append(f"{nom} : `{os.path.basename(dest)}` est installé (geste {i}) AVANT `lib.sh`, qu'il charge")
    if capteurs == 0:
        out.append(f"{nom} : aucun capteur chargeant lib.sh n'a été vu installé — le juge ne mesure rien")
    if rang_lib is not None and not os.path.isfile(lib):
        out.append(f"{nom} : lib.sh journalisé mais absent du bac")
    return out


def eprouver_juge_lib():
    r = "/bac"
    lib = f"{r}{DOSSIER_CAPTEURS}/lib.sh"
    cap = f"{r}{DOSSIER_CAPTEURS}/journal.sh"
    contenus = {cap: '. "${PLUME_LIB:-$(dirname "$0")/lib.sh}"\n'}
    tard = [["install", cap, "s", "0"], ["install", lib, "s", "0"]]
    tot = [["install", lib, "s", "0"], ["install", cap, "s", "0"]]
    f_tard = juger_lib_avant_capteurs(tard, r, contenus.get, "épreuve")
    f_tot = [x for x in juger_lib_avant_capteurs(tot, r, contenus.get, "épreuve") if "absent du bac" not in x]
    if not any("AVANT `lib.sh`" in x for x in f_tard) or f_tot:
        refuser(f"le juge d'ordre de lib.sh ne distingue pas un journal fautif d'un journal sain ({f_tard!r} / {f_tot!r})")


def juger_dropins(bac, nom, commun):
    gestes = bac.gestes()
    reload = next((i for i, g in enumerate(gestes) if g[0] == "systemctl" and g[1].startswith("daemon-reload")), None)
    if reload is None:
        faute(f"{nom} : aucun `systemctl daemon-reload` journalisé — le juge du drop-in ne mesure rien")
        return
    rang = {g[1]: i for i, g in enumerate(gestes) if g[0] == "install"}
    unites = 0
    sysd = bac.r("/etc/systemd/system")
    for n in sorted(os.listdir(sysd)):
        if not n.endswith(".service"):
            continue
        exe = re.search(r"^ExecStart=(\S+)", lire(os.path.join(sysd, n)), re.M)
        if not exe or not exe.group(1).startswith(DOSSIER_CAPTEURS + "/"):
            continue
        unites += 1
        d = os.path.normpath(os.path.join(sysd, n + ".d", DROPIN))
        if not os.path.isfile(d):
            faute(f"{nom} : l'unité de capteur `{n}` est posée SANS le drop-in de durcissement commun")
            continue
        if lire(d) != commun:
            faute(f"{nom} : le drop-in de `{n}` n'est pas celui attendu (systemd/plume-collector-common.conf, "
                  f"octet pour octet, sur le central comme sur l'agent)")
        if rang.get(d, 10 ** 9) > reload:
            faute(f"{nom} : le drop-in de `{n}` est posé APRÈS le premier daemon-reload")
    if unites == 0:
        faute(f"{nom} : aucune unité de capteur vue — le juge du drop-in ne mesure rien")



def familles(texte):
    out = set()
    for m in re.finditer(r"^RestrictAddressFamilies=(.*)$", texte, re.M):
        v = m.group(1).split()
        if not v:
            out = set()   # une affectation vide REMET la liste à zéro (systemd)
        out |= set(v)
    return out


def juger_familles_installees(bac, nom):
    """Central ET agent (`P10.33-d`) : le drop-in commun ne donne AUCUNE famille d'adresses, et chaque unité
    de capteur qui le reçoit déclare la sienne. `RestrictAddressFamilies=` est une LISTE : posée dans le
    drop-in, elle s'UNIRAIT à celle de chaque unité et donnerait à toutes la même union."""
    sysd = bac.r("/etc/systemd/system")
    vues = 0
    for n in sorted(os.listdir(sysd)):
        d = os.path.join(sysd, n + ".d", DROPIN)
        if not n.endswith(".service") or not os.path.isfile(d):
            continue
        vues += 1
        unite = lire(os.path.join(sysd, n))
        propres = familles(unite)
        if not re.search(r"^RestrictAddressFamilies=", unite, re.M):
            faute(f"{nom} : `{n}` ne déclare aucune RestrictAddressFamilies= : elle tournerait SANS restriction "
                  f"de familles d'adresses (le drop-in commun n'en pose aucune)")
            continue
        ajout = familles(lire(d)) - propres
        if ajout:
            faute(f"{nom} : le drop-in donne à `{n}` des familles qu'elle ne déclare pas : {sorted(ajout)} "
                  f"(une LISTE de drop-in s'UNIT à celle de l'unité)")
    if vues == 0:
        faute(f"{nom} : aucune unité à drop-in vue — le juge des familles ne mesure rien")


# --------------------------------------------------------------------------------------------------
# `P10.33-d` — LA FAMILLE D'ADRESSES D'UNE UNITÉ EST DÉRIVÉE DE CE QUE SON SCRIPT APPELLE.
#
# `RestrictAddressFamilies=` fait échouer `socket()` (EAFNOSUPPORT) pour toute famille non nommée. Une
# famille MANQUANTE tue donc l'appel qui en a besoin — souvent en silence, l'erreur étant avalée par un
# `2>/dev/null || true` (cas mesuré dans le dépôt : `auditd.sh` lit `auditctl -l`, qui ouvre un socket
# AF_NETLINK ; l'unité ne déclarait qu'AF_UNIX, le capteur publiait « 0 règle chargée » sur le central).
# Une famille EN TROP est une surface que rien n'emploie. La garde dérive donc, pour chaque unité, les
# familles que son ExecStart appelle RÉELLEMENT — le script et les fonctions de `lib.sh` qu'il invoque —
# et exige l'ÉGALITÉ avec ce que l'unité déclare. Le tableau ci-dessous dit, outil par outil, la famille
# que son socket ouvre (source : le code de l'outil, pas une mesure sous systemd — cf. « ne tient pas »).
# AF_UNIX est le plancher de toute unité : résolution des comptes par NSS (systemd-userdb, nscd),
# journald, D-Bus.
# --------------------------------------------------------------------------------------------------
F_UNIX = frozenset({"AF_UNIX"})
F_NETLINK = frozenset({"AF_NETLINK"})
F_INET = frozenset({"AF_INET", "AF_INET6"})
FAMILLES_DES_OUTILS = {
    # client HTTP/TCP vers le central, une API ou un registre
    "curl": F_INET, "wget": F_INET, "kubectl": F_INET, "skopeo": F_INET, "trivy": F_INET, "mc": F_INET,
    "cscli": F_INET,                      # LAPI CrowdSec en HTTP (127.0.0.1:8080 par défaut)
    "clamdscan": F_UNIX | F_INET,         # clamd par LocalSocket OU par TCPSocket (clamd.conf)
    # noyau par netlink
    "nft": F_NETLINK, "auditctl": F_NETLINK, "conntrack": F_NETLINK,
    "ss": F_NETLINK,                      # sock_diag
    "ip": F_NETLINK,                      # rtnetlink
    # iptables : nf_tables par netlink, OU (backend legacy) socket brut AF_INET/AF_INET6
    "iptables": F_NETLINK | F_INET, "ip6tables": F_NETLINK | F_INET,
    "iptables-save": F_NETLINK | F_INET, "ip6tables-save": F_NETLINK | F_INET,
    "ufw": F_NETLINK | F_INET,            # appelle iptables/ip6tables
    # sockets locaux
    "docker": F_UNIX, "crictl": F_UNIX, "ctr": F_UNIX, "systemctl": F_UNIX, "fail2ban-client": F_UNIX,
    "journalctl": F_UNIX, "getent": F_UNIX,
}
# `getent hosts <ip>` est une résolution DNS (module NSS `dns` : UDP vers le résolveur) : réseau.
GETENT_DNS = re.compile(r"(?<![\w/.$-])getent\s+a?hosts\b")
# `ip` et `ss` sont aussi des noms de variables (`$ip`, `for ip in`) : on n'y compte que l'APPEL.
APPEL_SPECIAL = {"ip": r"(?=\s+(?:-[46a-z]+\s+)*(?:link|addr|address|route|neigh|rule|netns|monitor|-br|-j)\b)",
                 "ss": r"(?=\s+-)"}
# Python embarqué ou exécuté : une bibliothèque réseau ouvre AF_INET/AF_INET6.
PYTHON_RESEAU = re.compile(r"^\s*(?:import|from)\s+(?:socket|socketserver|http|urllib|requests|ssl)\b", re.M)
# ExecStart qui n'est pas un script du dépôt : binaire bâti (démon, collector-*) — son code n'est pas un
# texte que cette garde sait lire. Ses familles restent celles que l'unité DÉCLARE, déclaration exigée.
BINAIRES_HORS_DERIVATION = {"plume-daemon", "plume-collector-mail", "plume-collector-syslog"}
# Familles déclarées au-delà de la dérivation, ADMISES avec leur raison — et seulement celles-là. Vide : le
# seul cas qui y figurait (`custom`) est désormais DÉRIVÉ par la règle du code d'exploitant ci-dessous.
EXCES_ADMIS = {}
# CODE D'EXPLOITANT. Un script qui exécute une commande qu'il ne contient pas — `sh -c "$ccmd"` sur une
# ligne lue d'un catalogue de /etc/plume/controls.d, `sh -c "$CMD"` d'une déclaration de /etc/plume/custom.d
# — ouvre ce que CETTE commande ouvre : la garde ne peut pas le lire, l'unité doit donc garder TOUTES les
# familles (un contrôle `kubectl get pods`, `nft list ruleset` ou `ss -ltn` mourrait en EAFNOSUPPORT, serait
# compté `false` et lèverait une fausse alerte). Critère : `sh|bash|dash -c "$V"` ou `eval "$V"` dont la
# variable V n'est JAMAIS affectée d'un littéral non vide dans le script (lue par `read`, copiée d'une
# autre variable). Un programme que le script écrit lui-même (`_LIRE_JOURNAL='tail …'` de mail.sh) n'en
# est pas : son texte est dans le dépôt.
F_TOUTES = F_UNIX | F_NETLINK | F_INET
EXEC_DE_VARIABLE = re.compile(r'(?<![\w/.-])(?:(?:ba|da)?sh\s+-c|eval)\s+"?\$\{?([A-Za-z_]\w*)\}?"?')


def code_d_exploitant(texte):
    """[(ligne, extrait)] des exécutions de code que le script ne contient pas (cf. CODE D'EXPLOITANT)."""
    out = []
    # les commentaires citent volontiers une affectation d'exemple (`CMD=sh -c '…'` dans custom.sh) : ni
    # l'exécution ni l'affectation littérale n'y comptent.
    code = "\n".join("" if l.lstrip().startswith("#") else l for l in texte.splitlines())
    for k, ligne in enumerate(code.splitlines(), 1):
        for m in EXEC_DE_VARIABLE.finditer(ligne):
            v = m.group(1)
            litteral = re.search(r"(?<![\w$])" + re.escape(v) + r"""=(?:'[^']+'|"[^"$]+"|[^\s'"$;][^\s;]*)""", code)
            if not litteral:
                out.append((k, m.group(0)))
    return out


def code_shell(texte):
    """Le code exécutable d'un script, lu en FLUX (une chaîne entre apostrophes peut couvrir plusieurs
    lignes : un programme awk) : commentaires retirés, chaînes retirées SAUF celles qui sont une valeur
    d'affectation (`KC="k3s kubectl"`, `SCAN="clamdscan …"`) ou qui portent une substitution `$(…)`. Un
    message (`plume_unavailable … "kubectl absent"`) ne compte donc pas comme un appel. Les sauts de ligne
    sont conservés : un numéro de ligne du code est celui du fichier."""
    out, i, n = [], 0, len(texte)
    while i < n:
        c = texte[i]
        if c == "\\" and i + 1 < n:
            out.append(texte[i:i + 2])
            i += 2
            continue
        if c in "'\"":
            j = i + 1
            while j < n and texte[j] != c:
                j += 2 if (c == '"' and texte[j] == "\\") else 1
            corps = texte[i + 1:j]
            garder = (i > 0 and texte[i - 1] == "=") or (c == '"' and "$(" in corps)
            out.append(" " + corps + " " if garder else " " + "\n" * corps.count("\n") + " ")
            i = j + 1
            continue
        if c == "#" and (i == 0 or texte[i - 1] in " \t\n;"):
            j = texte.find("\n", i)
            i = n if j < 0 else j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def appelle(code, nom):
    """Première ligne (1-based) où `nom` est APPELÉ dans `code`, ou 0 — jamais `command -v nom`, jamais un
    chemin ni un nom composé (`docker-lan`, `first_ctr`, `/var/lib/docker`, `$ip`)."""
    motif = re.compile(r"(?<![\w/.$:-])(?<!-v )" + re.escape(nom) + r"(?![\w/.:=-])" + APPEL_SPECIAL.get(nom, ""))
    for k, ligne in enumerate(code.splitlines(), 1):
        for m in motif.finditer(ligne):
            # Le mot est-il l'ARGUMENT d'une commande qui n'exécute rien (`plume_unavailable conntrack …`,
            # `heartbeat ufw …`, `echo nft`) ? On isole la commande courante (après le dernier séparateur).
            segment = re.split(r"[;|&(`{]|\$\(|\b(?:then|do|else|elif)\b", ligne[:m.start()])[-1]
            if re.match(r"\s*(?:plume_\w+|heartbeat|emit_event|spool_\w+|state_\w+|echo|printf|log)\s", segment):
                continue
            return k
    return 0


def fonctions_du_code(code):
    """{nom: corps} des fonctions shell définies dans `code` (deux définitions du même nom — un enrobage
    choisi selon l'hôte, `cscli_cmd` — sont réunies : l'une ou l'autre peut tourner)."""
    out = {}
    lignes = code.splitlines()
    for k, l in enumerate(lignes):
        m = re.match(r"^(\s*)(?:function\s+)?([A-Za-z_][\w]*)\s*\(\)\s*\{(.*)$", l)
        if not m:
            continue
        if "}" in m.group(3):
            corps = m.group(3)[:m.group(3).rindex("}")]
        else:
            fin = re.compile(r"^" + re.escape(m.group(1)) + r"\}")
            corps_l = []
            for l2 in lignes[k + 1:]:
                if fin.match(l2):
                    break
                corps_l.append(l2)
            corps = "\n".join(corps_l)
        out[m.group(2)] = out.get(m.group(2), "") + "\n" + corps
    return out


def familles_du_fragment(fragment, fonctions, lib):
    """(familles, preuves) de ce que `fragment` appelle : outils, fonctions du script (transitivement) et
    fonctions de lib.sh. AF_UNIX est le plancher."""
    fam, preuves = set(F_UNIX), []
    vues, a_voir = set(), [("", fragment)]
    while a_voir:
        ou, code = a_voir.pop()
        for outil, ff in FAMILLES_DES_OUTILS.items():
            k = appelle(code, outil)
            if k:
                fam |= ff
                preuves.append(f"{outil} ({ou or 'l.' + str(k)}) → {' '.join(sorted(ff))}")
        if GETENT_DNS.search(code):
            fam |= F_INET
            preuves.append(f"getent hosts ({ou or 'script'}) → AF_INET AF_INET6")
        for f, ff in lib.items():
            if appelle(code, f):
                fam |= ff
                preuves.append(f"{f} (lib.sh) → {' '.join(sorted(ff))}")
        for f, corps in fonctions.items():
            if f not in vues and appelle(code, f):
                vues.add(f)
                a_voir.append((f + "()", corps))
    return frozenset(fam), sorted(set(preuves))


def fonctions_de_lib(texte):
    """{fonction de lib.sh: familles de son corps}. Un capteur qui l'appelle hérite de ces familles."""
    out = {}
    fonctions = fonctions_du_code(code_shell(texte))
    for nom, corps in fonctions.items():
        fam, _ = familles_du_fragment(corps, fonctions, {})
        if fam - F_UNIX:
            out[nom] = fam
    return out


def familles_derivees(chemin_script, lib, argument=None):
    """(familles, preuves) que l'ExecStart appelle. Avec un argument de mode (`revert-expired`) que le script
    traite dans une branche `if [ "${1:-}" = "<mode>" ]; then … fi`, seule cette branche (et ce qu'elle
    appelle) est retenue : c'est elle qui tourne sous l'unité."""
    texte = lire(chemin_script)
    if chemin_script.endswith(".py"):
        if PYTHON_RESEAU.search(texte):
            return F_UNIX | F_INET, ["python réseau → AF_INET AF_INET6"]
        return F_UNIX, []
    code = code_shell(texte)
    fragment = code
    if argument:
        m = re.search(r'^if \[ "\$\{1:-\}" = "?' + re.escape(argument) + r'"? \]; then\n(.*?)^fi\b', texte, re.M | re.S)
        if not m:
            return None, [f"aucune branche `if [ \"${{1:-}}\" = \"{argument}\" ]` dans {chemin_script}"]
        debut = texte.count("\n", 0, m.start(1))
        fragment = "\n".join(code.splitlines()[debut:debut + m.group(1).count("\n")])
    fam, preuves = familles_du_fragment(fragment, fonctions_du_code(code), lib)
    brut = m.group(1) if argument else texte
    for k, extrait in code_d_exploitant(brut):
        fam |= F_TOUTES
        preuves.append(f"code d'exploitant `{extrait}` (l.{k}) → toutes familles")
    if PYTHON_RESEAU.search(fragment if argument else texte):
        fam |= F_INET
        preuves.append("python réseau embarqué → AF_INET AF_INET6")
    return frozenset(fam), preuves


def execstart_de_l_unite(texte):
    """(script du dépôt ou None, argument de mode ou None, binaire ou None) de l'ExecStart d'une unité."""
    m = re.search(r"^ExecStart=(.*)$", texte, re.M)
    if not m:
        return None, None, None
    mots = m.group(1).split()
    for k, mot in enumerate(mots):
        base = os.path.basename(mot)
        if mot.startswith(DOSSIER_CAPTEURS + "/") and os.path.isfile(os.path.join(RACINE_DEPOT, "collectors", base)):
            arg = mots[k + 1] if len(mots) > k + 1 and not mots[k + 1].startswith("-") else None
            return os.path.join(RACINE_DEPOT, "collectors", base), arg, None
    return None, None, (os.path.basename(mots[0]) if mots else None)


def juger_familles_derivees():
    """Chaque unité livrée déclare SA RestrictAddressFamilies=, ÉGALE à ce que son ExecStart appelle."""
    lib = fonctions_de_lib(lire(os.path.join(RACINE_DEPOT, "collectors/lib.sh")))
    if "kctl" not in lib or not F_INET <= lib["kctl"]:
        refuser("la dérivation des familles ne voit plus `kctl` (lib.sh) appeler kubectl : l'instrument est cassé")
        return
    eprouver_derivation(lib)
    unites = sorted(f for f in os.listdir(os.path.join(RACINE_DEPOT, "systemd")) if f.endswith(".service"))
    jugees = reseau = 0
    for n in unites:
        texte = lire(os.path.join(RACINE_DEPOT, "systemd", n))
        if not re.search(r"^RestrictAddressFamilies=", texte, re.M):
            faute(f"systemd/{n} : aucune RestrictAddressFamilies= — chaque unité déclare la sienne (le drop-in "
                  f"commun n'en pose plus, `P10.33-d`)")
            continue
        declarees = familles(texte)
        script, argument, binaire = execstart_de_l_unite(texte)
        if script is None:
            if binaire in BINAIRES_HORS_DERIVATION:
                continue
            if binaire not in FAMILLES_DES_OUTILS:
                refuser(f"systemd/{n} : ExecStart `{binaire}` n'est ni un script de collectors/, ni un outil de "
                        f"FAMILLES_DES_OUTILS, ni un binaire déclaré : la famille ne peut pas être dérivée")
                continue
            requises, preuves = F_UNIX | FAMILLES_DES_OUTILS[binaire], [f"ExecStart {binaire}"]
        else:
            requises, preuves = familles_derivees(script, lib, argument)
            if requises is None:
                refuser(f"systemd/{n} : {preuves[0]} — le mode de l'ExecStart n'est pas dérivable")
                continue
        jugees += 1
        reseau += bool(F_INET & requises)
        manque = requises - declarees
        if manque:
            faute(f"systemd/{n} : il MANQUE {sorted(manque)} — son ExecStart les ouvre ({'; '.join(preuves)}) ; "
                  f"sans elles `socket()` échoue (EAFNOSUPPORT) et la collecte meurt")
        trop = declarees - requises - EXCES_ADMIS.get(n, frozenset())
        if trop:
            faute(f"systemd/{n} : familles déclarées que rien n'appelle : {sorted(trop)} (appels vus : "
                  f"{'; '.join(preuves) or 'aucun outil à socket'}) — retirez-les, ou dites pourquoi dans EXCES_ADMIS")
    if jugees < 30 or reseau < 10:
        refuser(f"dérivation des familles : {jugees} unité(s) jugée(s) dont {reseau} réseau — trop peu, la "
                f"découverte est cassée")


def eprouver_derivation(lib):
    """Témoins de l'instrument : un appel réel est vu (directement, par une variable, par une fonction du
    script ou de lib.sh) ; un message, un `command -v`, un commentaire, un chemin, une variable ne le sont pas."""
    cas = [
        ('out=$(curl -sS "$U")\n', F_UNIX | F_INET),
        ('KC="k3s kubectl"\n$KC get pods\n', F_UNIX | F_INET),
        ('kctl get ns\n', F_UNIX | F_INET),
        ('_ar=$(auditctl -l 2>/dev/null || true)\n', F_UNIX | F_NETLINK),
        ('chk iptables -C INPUT -j DROP\n', F_UNIX | F_NETLINK | F_INET),
        ('h=$(getent hosts "$1")\n', F_UNIX | F_INET),
        ('f() {\n  cscli decisions list\n}\nf\n', F_UNIX | F_INET),
        ('command -v kubectl >/dev/null || plume_unavailable x y "kubectl absent"\n', F_UNIX),
        ('command -v ss >/dev/null || plume_unavailable conntrack missing-dependency "ss absent"\n', F_UNIX),
        ("# curl https://example.org\nP=/var/lib/docker\nfirst_ctr=0\nfor ip in $L; do echo \"$ip\"; done\n"
         "awk '\n  { if ($1 ~ /curl|wget/) print }\n' f\n", F_UNIX),
        # code d'exploitant : une ligne lue d'un catalogue, une valeur copiée d'une déclaration → toutes ;
        # un programme écrit dans le script, une mention en commentaire → rien de plus.
        ('cid=""; ccmd=""\nwhile IFS="|" read -r cid ccmd; do\n  sh -c "$ccmd" >/dev/null\ndone < "$f"\n', F_TOUTES),
        ('CMD=""\nCMD=$v\n$TO sh -c "$CMD"\n', F_TOUTES),
        ('eval "$LIGNE"\n', F_TOUTES),
        ("P='[ -e \"$1\" ] || exit 3; tail -n \"$2\" \"$1\"'\nsh -c \"$P\" lire \"$f\" 10\n", F_UNIX),
        ('# `CMD` était exécuté par `sh -c "$CMD"`\n', F_UNIX),
    ]
    for src, attendu in cas:
        code = code_shell(src)
        obtenu, _ = familles_du_fragment(code, fonctions_du_code(code), lib)
        if code_d_exploitant(src):
            obtenu |= F_TOUTES
        if obtenu != attendu:
            refuser(f"dérivation des familles : {src!r} rend {sorted(obtenu)}, attendu {sorted(attendu)}")


def lecteurs_soc_de_plume_conf():
    """Unités `User=soc` : le démon doit lire une AUTRE conf ; tout autre exécutable ne doit pas la citer."""
    sysd = os.path.join(RACINE_DEPOT, "systemd")
    vus = 0
    for n in sorted(os.listdir(sysd)):
        if not n.endswith(".service"):
            continue
        t = lire(os.path.join(sysd, n))
        u = re.search(r"^User=(\S+)", t, re.M)
        if not u or u.group(1) == "root":
            continue
        vus += 1
        exe = re.search(r"^ExecStart=(.+)$", t, re.M)
        jetons = exe.group(1).split() if exe else []
        conf = re.search(r"^Environment=\"?PLUME_CONFIG=([^\"\s]+)", t, re.M)
        conf_ailleurs = bool(conf) and conf.group(1) != "/etc/plume/plume.conf"
        sources = []
        lance_le_demon = False
        for j in jetons:
            base = os.path.basename(j)
            if base == "plume-daemon":
                lance_le_demon = True
            elif base.startswith("plume-collector-"):
                d = os.path.join(RACINE_DEPOT, base[len("plume-"):], "src")
                if os.path.isdir(d):
                    sources += [os.path.join(d, f) for f in sorted(os.listdir(d))]
            elif os.path.isfile(os.path.join(RACINE_DEPOT, "collectors", base)):
                sources.append(os.path.join(RACINE_DEPOT, "collectors", base))
        if not lance_le_demon and not sources:
            refuser(f"systemd/{n} tourne sous `{u.group(1)}` et sa source ({' '.join(jetons)}) est introuvable : lecteur non jugé")
            continue
        for s in sources:
            texte = lire(s)
            if "plume.conf" in texte:
                faute(f"{os.path.relpath(s, RACINE_DEPOT)} tourne sous `{u.group(1)}` ({n}) et cite plume.conf : "
                      f"le jeton y serait lu par `soc`")
            if re.search(r"(^|[\s/])plume-daemon\s", texte, re.M):
                lance_le_demon = True
        # Le démon lit PLUME_CONFIG, défaut /etc/plume/plume.conf : lancé sous `soc` sans elle, il lirait le jeton.
        if lance_le_demon and not conf_ailleurs:
            faute(f"systemd/{n} lance plume-daemon sous `{u.group(1)}` sans PLUME_CONFIG hors de plume.conf : "
                  f"le démon y lit alors /etc/plume/plume.conf (son défaut), c'est-à-dire le jeton de l'agent")
    if vus == 0:
        refuser("aucune unité non-root trouvée : le relevé des lecteurs de plume.conf ne mesure rien")


def fichiers_environnement():
    out = set()
    for n in os.listdir(os.path.join(RACINE_DEPOT, "systemd")):
        if n.endswith(".service"):
            for m in re.finditer(r"^EnvironmentFile=-?(\S+)", lire(os.path.join(RACINE_DEPOT, "systemd", n)), re.M):
                out.add(m.group(1))
    return out


def juger_confs_engendrees(bac, nom, env_files):
    """Aucune valeur d'une conf chargée par EnvironmentFile ne porte un commentaire de fin de ligne."""
    for chemin in sorted(env_files):
        p = bac.r(chemin)
        if not os.path.isfile(p):
            continue
        for cle, val in lire_env_systemd(lire(p)).items():
            if re.search(r"(^|\s)#", val):
                faute(f"{nom} : {chemin} — systemd lit {cle}={val!r} : le commentaire est DANS la valeur")


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


# --------------------------------------------------------------------------------------------------
# Scénarios d'installation
# --------------------------------------------------------------------------------------------------
def scenario_central(commun, env_files):
    for outils in ((), ("augenrules",), ("auditctl",), ("augenrules", "auditctl")):
        auditd = len(outils) == 2
        nom = f"bootstrap.sh (outils d'audit : {' + '.join(outils) or 'aucun'})"
        bac = Bac("central", outils_audit=outils).jouer("bootstrap.sh", {"PLUME_PASS_HASH": ""})
        try:
            if bac.rc != 0:
                refuser(f"{nom} a échoué dans le bac (code {bac.rc}) :\n{bac.sortie[-3000:]}")
                continue
            gestes = bac.gestes()
            for f in juger_lib_avant_capteurs(gestes, bac.racine, lambda d: lire(d) if os.path.isfile(d) else None, nom):
                faute(f)
            juger_dropins(bac, nom, commun)
            juger_familles_installees(bac, nom)
            regles = os.path.isfile(bac.r("/etc/audit/rules.d/plume.rules"))
            active = any(g[0] == "systemctl" and re.match(r"enable\b", g[1]) and "plume-auditd.timer" in g[1]
                         for g in gestes)
            # Le timer reste activé SANS auditd : c'est lui qui porte au SOC l'aveu `missing-source` du
            # capteur. L'éteindre ferait d'une absence NOMMÉE un silence — la garde le refuse aussi.
            if not active:
                faute(f"{nom} : plume-auditd.timer non activé — l'aveu « source absente » n'atteindrait plus le SOC")
            if auditd and not regles:
                faute(f"{nom} : auditd présent et règles NON posées — le témoin positif ne tient pas")
            if auditd:
                noyau = set(lire(bac.etat_audit).splitlines()) if os.path.isfile(bac.etat_audit) else set()
                manque = [n for n, c in regles_du_gabarit(lire(os.path.join(RACINE_DEPOT, GABARIT))) if c not in noyau]
                if manque or "OK —" not in bac.sortie:
                    faute(f"{nom} : règles du gabarit absentes du noyau après installation (lignes {manque})")
            if not auditd:
                if regles:
                    faute(f"{nom} : règles d'audit posées alors que l'installeur n'a pas les deux outils")
                if "auditd ABSENT" not in bac.sortie:
                    faute(f"{nom} : l'installeur ne dit pas que auditd est absent")
            juger_confs_engendrees(bac, nom, env_files)
        finally:
            bac.nettoyer()


# --------------------------------------------------------------------------------------------------
# `P10.33-c` — le chargeur des règles d'audit, joué SEUL contre les faux réalistes
# --------------------------------------------------------------------------------------------------
def awks_presents():
    awks, vus = [], set()
    for nom in AWK_EXERCES:
        p = shutil.which(nom)
        if p and os.path.realpath(p) not in vus:
            vus.add(os.path.realpath(p))
            awks.append((nom, p))
    return awks


def jouer_chargeur(awk, tiers=None, gabarit=None, script=None, sans_argument=False, pose=None):
    """Joue le chargeur dans un hôte factice : rules.d = audit.rules (base Ubuntu, -D en tête) + les
    fichiers `tiers` ; rend (code, sortie, noyau après chargement, noyau après un REDÉMARRAGE simulé —
    noyau vidé puis `augenrules --load` seul, comme auditd au boot). `pose` (dict), s'il est donné, reçoit
    le plume.rules posé sous la clé "plume.rules"."""
    d = tempfile.mkdtemp(prefix="plume-chargeur-audit-", dir=os.environ.get("TMPDIR") or None)
    try:
        b, rd = os.path.join(d, "bin"), os.path.join(d, "rules.d")
        os.makedirs(b)
        os.makedirs(rd)
        for nom, contenu in (("auditctl", FAUX_AUDITCTL), ("augenrules", FAUX_AUGENRULES)):
            with open(os.path.join(b, nom), "w") as f:
                f.write(contenu)
            os.chmod(os.path.join(b, nom), 0o755)
        os.symlink(awk, os.path.join(b, "awk"))
        with open(os.path.join(rd, "audit.rules"), "w") as f:
            f.write(BASE_RULES_D)
        for nom, contenu in (tiers or {}).items():
            with open(os.path.join(rd, nom), "w") as f:
                f.write(contenu)
        gab = os.path.join(d, "plume-audit.rules")
        with open(gab, "w") as f:
            f.write(gabarit if gabarit is not None else lire(os.path.join(RACINE_DEPOT, GABARIT)))
        etat = os.path.join(d, "noyau")
        env = {"PATH": f"{b}:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TMPDIR": d, "HOME": d,
               "PLUME_BAC_AUDIT_ETAT": etat, "PLUME_BAC_RULES_D": rd,
               "PLUME_BAC_AUDIT_RULES": os.path.join(d, "audit.rules"),
               "PLUME_AUDIT_RULES_DEST": os.path.join(rd, "plume.rules"), "PLUME_BAC_JOURNAL": os.path.join(d, "j")}
        cmd = ["sh", script or os.path.join(RACINE_DEPOT, CHARGEUR)] + ([] if sans_argument else [gab])
        r = subprocess.run(cmd, env=env, cwd=d, capture_output=True, text=True, timeout=120)
        noyau = set(lire(etat).splitlines()) if os.path.isfile(etat) else set()
        if pose is not None and os.path.isfile(os.path.join(rd, "plume.rules")):
            pose["plume.rules"] = lire(os.path.join(rd, "plume.rules"))
        open(etat, "w").close()
        subprocess.run([os.path.join(b, "augenrules"), "--load"], env=env, capture_output=True, timeout=60)
        boot = set(lire(etat).splitlines())
        return r.returncode, r.stdout + r.stderr, noyau, boot
    finally:
        shutil.rmtree(d, ignore_errors=True)


def juger_chargeur_audit():
    gab = lire(os.path.join(RACINE_DEPOT, GABARIT))
    regles = regles_du_gabarit(gab)
    lignes = gab.splitlines()
    b64 = [(n, l) for n, l in enumerate(lignes, 1) if re.match(r"-a always,exit -F arch=b64 -S execve .*-k exec_tracking$", l)]
    if len(regles) < 3 or len(b64) != 1:
        refuser(f"{GABARIT} : gabarit méconnaissable ({len(regles)} règles actives, {len(b64)} règle execve b64)")
        return
    n64, l64 = b64[0]
    if n64 == regles[-1][0]:
        refuser(f"{GABARIT} : la règle execve b64 est la DERNIÈRE — un doublon ne décapiterait rien, le témoin est vacant")
        return
    awks = awks_presents()
    if not awks:
        refuser(f"aucun awk parmi {AWK_EXERCES} : le chargeur n'est pas jouable")
        return

    def absentes(noyau):
        return [n for n, c in regles if c not in noyau]

    for awk_nom, awk in awks:
        t = f"{CHARGEUR} [{awk_nom}]"
        # A — nominal : inchangé (code 0, OK, rien à dédoublonner, tout chargé, et au redémarrage aussi).
        rc, out, noyau, boot = jouer_chargeur(awk)
        if rc != 0 or absentes(noyau) or absentes(boot) or "OK —" not in out or "doublon" in out:
            faute(f"{t} nominal : code {rc}, absentes {absentes(noyau)}, au boot {absentes(boot)}\n{out[-1500:]}")
        # A2 — re-passage : le plume.rules d'une installation précédente est DANS rules.d. Il n'est pas un
        #      « autre fichier » : rien n'est dédoublonné contre lui, la pose reste nominale.
        rc, out, noyau, boot = jouer_chargeur(awk, {"plume.rules": gab})
        if rc != 0 or absentes(noyau) or absentes(boot) or "doublon" in out:
            faute(f"{t} re-passage : code {rc}, absentes {absentes(noyau)}, au boot {absentes(boot)}\n{out[-1500:]}")
        # B — un fichier tiers placé AVANT plume.rules déclare la règle b64 à l'identique (espaces
        #     différents) : le cas constaté. Toutes les règles plume chargées, au boot aussi ; le
        #     doublon est NOMMÉ (fichier et ligne du gabarit) ; la règle tierce qui suit reste chargée.
        tiers = "  " + l64.replace(" ", "   ", 3) + "\n-w /etc/passwd -p wa -k tiers_passwd\n"
        pose = {}
        rc, out, noyau, boot = jouer_chargeur(awk, {"exec-tiers.rules": tiers}, pose=pose)
        # La copie posée garde les NUMÉROS du gabarit (une ligne commentée pour une ligne retirée) : les
        # « ligne N » des messages et de la doc désignent la même ligne dans plume.rules et le gabarit.
        posees = pose.get("plume.rules", "").splitlines()
        autres = [n for n, (a, b) in enumerate(zip(lignes, posees), 1) if n != n64 and a != b]
        if (len(posees) != len(lignes) or autres
                or not (len(posees) >= n64 and posees[n64 - 1].startswith("## plume-doublon") and "exec-tiers.rules" in posees[n64 - 1])):
            faute(f"{t} doublon tiers AVANT plume : plume.rules posé ne commente pas la ligne {n64} À SA PLACE "
                  f"({len(posees)} lignes posées pour {len(lignes)}, autres lignes changées {autres[:5]})")
        if rc != 0 or absentes(noyau) or absentes(boot):
            faute(f"{t} doublon tiers AVANT plume : code {rc}, absentes {absentes(noyau)}, au boot {absentes(boot)}\n{out[-1500:]}")
        if "exec-tiers.rules" not in out or f"ligne {n64} " not in out:
            faute(f"{t} doublon tiers AVANT plume : le doublon n'est pas nommé (fichier + ligne {n64})\n{out[-1500:]}")
        if "-w /etc/passwd -p wa -k tiers_passwd" not in noyau:
            faute(f"{t} doublon tiers AVANT plume : la règle propre au fichier tiers n'est plus chargée")
        # B2 — le doublon tiers est une WATCH (`-w`), pas la règle syscall : cinq règles du gabarit sur huit
        #      sont des watches. Placée avant les autres watches, elle décapiterait toutes celles qui suivent
        #      au démarrage si le dédoublonnage ne reconnaissait que `-a`/`-A`.
        watches = [(n, l) for n, l in enumerate(lignes, 1) if re.match(r"-w\s", l)]
        if len(watches) < 2:
            refuser(f"{GABARIT} : moins de deux watches — le témoin du doublon de watch est vacant")
        else:
            nw, lw = watches[0]
            rc, out, noyau, boot = jouer_chargeur(awk, {"exec-tiers.rules": " ".join(lw.split()) + "\n"})
            if rc != 0 or absentes(noyau) or absentes(boot) or f"ligne {nw} " not in out or "exec-tiers.rules" not in out:
                faute(f"{t} watch doublée par un tiers AVANT plume : code {rc} (attendu 0), absentes {absentes(noyau)}, "
                      f"au boot {absentes(boot)}, doublon ligne {nw} nommé {f'ligne {nw} ' in out}\n{out[-1500:]}")
        # B3 — le fichier tiers qui porte le doublon s'arrête AVANT lui (erreur plus haut dans CE fichier) :
        #      la copie retirée de plume.rules n'est chargée par personne. Le rattrapage la rend depuis le
        #      gabarit (code 2 : complet maintenant, le démarrage s'arrêtera), au lieu d'un code 1 qui
        #      renverrait à une ligne du gabarit sans en nommer aucune.
        casse = "-a always,exit -F dir=/chemin/absent/plume-temoin -k tiers_casse\n" + l64 + "\n"
        rc, out, noyau, boot = jouer_chargeur(awk, {"exec-tiers.rules": casse})
        if rc != 2 or absentes(noyau) or "RATTRAPAGE" not in out or f"ligne {n64} chargée par le rattrapage" not in out:
            faute(f"{t} tiers fautif AVANT son doublon : code {rc} (attendu 2), absentes {absentes(noyau)}, "
                  f"ligne {n64} rattrapée {f'ligne {n64} chargée par le rattrapage' in out}\n{out[-1500:]}")
        # C — le même doublon, fichier tiers APRÈS plume.rules : c'est le TIERS qui serait décapité.
        rc, out, noyau, boot = jouer_chargeur(awk, {"zz-tiers.rules": l64 + "\n-w /etc/group -p wa -k tiers_group\n"})
        tg = "-w /etc/group -p wa -k tiers_group"
        if rc != 0 or absentes(noyau) or absentes(boot) or tg not in noyau or tg not in boot:
            faute(f"{t} doublon tiers APRÈS plume : code {rc}, absentes {absentes(noyau)}, au boot {absentes(boot)}, "
                  f"règle tierce chargée {tg in noyau}/{tg in boot}\n{out[-1500:]}")
        # C2 — fichier tiers APRÈS plume.rules, avec une vraie erreur à lui : toutes les règles plume sont
        #      chargées (code 0, au boot aussi), mais augenrules a rendu un échec — la note le DIT, avec la
        #      sortie d'augenrules, au lieu d'un « OK » qui tairait que la règle tierce suivante manque.
        casse_apres = "-a always,exit -F dir=/chemin/absent/plume-temoin -k tiers_casse\n" + tg + "\n"
        rc, out, noyau, boot = jouer_chargeur(awk, {"zz-tiers.rules": casse_apres})
        if (rc != 0 or absentes(noyau) or absentes(boot) or tg in noyau
                or "augenrules a rendu rc=1 APRÈS les règles plume" not in out or "There was an error in line" not in out):
            faute(f"{t} tiers fautif APRÈS plume : code {rc} (attendu 0), absentes {absentes(noyau)}, règle tierce "
                  f"chargée {tg in noyau}, note « rc APRÈS les règles plume » {'dite' if 'APRÈS les règles plume' in out else 'TUE'}\n{out[-1500:]}")
        # D — doublon ÉCRIT AUTREMENT (même valeur pour le noyau) : le dédoublonnage textuel ne le voit pas,
        #     augenrules s'arrête ; le rattrapage charge tout MAINTENANT et le chargeur AVOUE (code 2) que le
        #     prochain démarrage s'arrêtera — sortie d'augenrules montrée.
        autre = l64.replace("auid!=-1", "auid!=4294967295")
        if autre == l64:
            refuser(f"{GABARIT} : la règle b64 ne porte plus `auid!=-1` — le témoin du doublon écrit autrement est vacant")
        else:
            rc, out, noyau, boot = jouer_chargeur(awk, {"exec-tiers.rules": autre + "\n"})
            if rc != 2 or absentes(noyau) or "Rule exists" not in out or "RATTRAPAGE" not in out:
                faute(f"{t} doublon écrit autrement : code {rc} (attendu 2), absentes {absentes(noyau)}\n{out[-1500:]}")
        # D2 — EXACTEMENT UNE règle rattrapée : l'avant-dernière règle du gabarit, déclarée par un tiers placé
        #      AVANT plume avec `-k` déplacé (même règle pour le noyau, texte différent). augenrules s'arrête
        #      sur elle, seule la dernière règle manque, le rattrapage la rend : code 2, « 1 règle(s) », et
        #      au démarrage simulé elle MANQUE bien. Un seuil « plus d'une » dirait OK.
        na, la = regles[-2][0], lignes[regles[-2][0] - 1]
        mots = la.split()
        if "-k" not in mots or mots.index("-k") <= 2:
            refuser(f"{GABARIT} : l'avant-dernière règle n'a pas de `-k` après ses champs — le témoin d'une seule règle rattrapée est vacant")
        else:
            ik = mots.index("-k")
            deplace = " ".join(mots[:2] + mots[ik:ik + 2] + mots[2:ik] + mots[ik + 2:])
            rc, out, noyau, boot = jouer_chargeur(awk, {"exec-tiers.rules": deplace + "\n"})
            nd = regles[-1][0]
            if (deplace == " ".join(mots) or rc != 2 or absentes(noyau) or absentes(boot) != [nd]
                    or "PAR LE SEUL RATTRAPAGE (1 règle(s))" not in out or f"ligne {nd} chargée par le rattrapage" not in out
                    or "OK —" in out):
                faute(f"{t} une seule règle rattrapée (ligne {na} doublée par « {deplace} ») : code {rc} (attendu 2), "
                      f"absentes {absentes(noyau)}, au boot {absentes(boot)} (attendu [{nd}])\n{out[-1500:]}")
        # E — une VRAIE erreur dans le gabarit, avant sa dernière règle : nommée (ligne, règle, message
        #     d'auditctl, sortie d'augenrules), code 1, et elle ne décapite plus les règles qui la suivent.
        fausse = "-a always,exit -F dir=/chemin/absent/plume-temoin -F perm=wa -k plume_temoin_erreur"
        i = regles[-1][0] - 1
        variante = "\n".join(lignes[:i] + [fausse] + lignes[i:]) + "\n"
        rc, out, noyau, boot = jouer_chargeur(awk, gabarit=variante)
        nommee = f"ligne {i + 1} de" in out and fausse in out and "No such file or directory" in out
        if rc != 1 or not nommee or "plume_temoin_erreur" not in out or "There was an error in line" not in out:
            faute(f"{t} erreur de syntaxe : code {rc} (attendu 1), nommée {nommee}\n{out[-1500:]}")
        if absentes(noyau):
            faute(f"{t} erreur de syntaxe : elle décapite encore les règles qui la suivent : {absentes(noyau)}")
        # Le message FINAL renvoie à la ligne refusée, pas à un « doublon du gabarit » qui n'existe pas.
        if ("CHARGEMENT PARTIEL — REFUSÉ (1 ligne(s) du gabarit refusée(s) par auditctl" not in out
                or "Corrigez ou commentez la ligne nommée" not in out or "Aucune ligne du gabarit n'est refusée" in out):
            faute(f"{t} erreur de syntaxe : le message final ne renvoie pas à la ligne refusée (ou parle d'un doublon)\n{out[-1500:]}")
        # MAINTENANT la dernière règle tourne (rattrapée) ; AU DÉMARRAGE simulé elle manque — et le chargeur le dit.
        if absentes(boot) != [regles[-1][0]]:
            faute(f"{t} erreur de syntaxe : au démarrage simulé, absentes {absentes(boot)} (attendu [{regles[-1][0]}]) — témoin vacant")
        if "ces 1 règle(s) rattrapée(s) seront PERDUES au prochain démarrage" not in out:
            faute(f"{t} erreur de syntaxe : le code 1 tait que la règle rattrapée sera PERDUE au prochain démarrage\n{out[-1500:]}")
        # E2 — la même erreur sous une clé DÉJÀ portée par le gabarit : les autres règles de la clé sont
        #      chargées, seul le COMPTE par clé voit qu'il en manque une. Un simple test de présence de la
        #      clé dirait « OK », code 0.
        cle = regles[-1][1].split()[-1].split("=", 1)[-1]
        avant = sum(1 for _, c in regles if c.split()[-1].split("=", 1)[-1] == cle)
        fausse2 = f"-a always,exit -F dir=/chemin/absent/plume-temoin -F perm=wa -k {cle}"
        rc, out, noyau, _ = jouer_chargeur(awk, gabarit="\n".join(lignes[:i] + [fausse2] + lignes[i:]) + "\n")
        compte = f"CLÉ '{cle}' : {avant} règle(s) chargée(s) sur {avant + 1} déclarée(s)"
        if rc != 1 or compte not in out or "OK —" in out or absentes(noyau):
            faute(f"{t} erreur sous la clé existante {cle} : code {rc} (attendu 1), « {compte} » "
                  f"{'dit' if compte in out else 'TU'}, absentes {absentes(noyau)}\n{out[-1500:]}")
        # G — le gabarit déclare DEUX FOIS la même règle : rien n'est refusé par auditctl (« Rule exists »),
        #     il manque une règle à la clé. Code 1, et le message ne renvoie pas à une « ligne nommée »
        #     qu'il n'a pas nommée.
        rc, out, noyau, _ = jouer_chargeur(awk, gabarit="\n".join(lignes[:n64] + [l64] + lignes[n64:]) + "\n")
        if (rc != 1 or "Aucune ligne du gabarit n'est refusée" not in out or "la ligne nommée" in out
                or "REFUSÉE par auditctl" in out):
            faute(f"{t} règle doublée DANS le gabarit : code {rc} (attendu 1), aveu sans ligne refusée "
                  f"{'dit' if 'Aucune ligne du gabarit' in out else 'TU'}\n{out[-1500:]}")


def juger_chargeur_sans_cle():
    """Un gabarit sans aucune `-k` n'a rien de vérifiable : le chargeur REFUSE DE CONCLURE (code 1), il ne
    dit pas « OK » sur un attendu vide."""
    sans_cle = "\n".join(re.sub(r"\s+-k\s+\S+\s*$", "", l) for l in lire(os.path.join(RACINE_DEPOT, GABARIT)).splitlines()) + "\n"
    if re.search(r"(^|\s)-k\s", sans_cle, re.M):
        refuser(f"{GABARIT} : une `-k` n'est pas en fin de ligne — le témoin du gabarit sans clé est vacant")
        return
    for awk_nom, awk in awks_presents():
        rc, out, _, _ = jouer_chargeur(awk, gabarit=sans_cle)
        if rc != 1 or "aucune règle avec clé" not in out or "OK —" in out:
            faute(f"{CHARGEUR} [{awk_nom}] gabarit sans clé : code {rc} (attendu 1), refus de conclure "
                  f"{'dit' if 'aucune règle avec clé' in out else 'TU'}\n{out[-800:]}")


def juger_un_seul_chargeur():
    for rel in ("bootstrap.sh", "bootstrap-agent.sh"):
        for i, ligne in enumerate(lire(os.path.join(RACINE_DEPOT, rel)).splitlines(), 1):
            code = ligne.split("#", 1)[0]
            if re.search(r"(^|[;&|(]\s*|\s)(augenrules\s+--load|auditctl\s+-R)\b", code) and not re.match(r"\s*echo\b", code):
                faute(f"{rel}:{i} charge les règles d'audit lui-même au lieu de passer par {CHARGEUR} : {ligne.strip()}")


def juger_chargeur_installe(bac, nom):
    """Le geste que l'agent affiche — le chargeur INSTALLÉ, sans argument — trouve le gabarit installé."""
    script = bac.r("/usr/local/lib/plume/plume-audit-rules-load.sh")
    if not os.path.isfile(script) or not os.path.isfile(bac.r("/usr/local/share/plume/plume-audit.rules")):
        faute(f"{nom} : chargeur ou gabarit d'audit non posé")
        return
    if "plume-audit-rules-load.sh" not in bac.sortie:
        faute(f"{nom} : l'installeur n'affiche pas le geste du chargeur d'audit")
    # L'agent ne charge rien : l'exploitant arme à la main, et c'est l'agent qui lui donne la SEULE preuve
    # de ce qui tourne (watches comprises), la même que la doc.
    if VERIFIER_AUDIT not in bac.sortie:
        faute(f"{nom} : l'installeur n'affiche pas le geste de vérification « {VERIFIER_AUDIT} »")
    awks = awks_presents()
    if not awks:
        return
    rc, out, noyau, _ = jouer_chargeur(awks[0][1], script=script, sans_argument=True)
    manque = [n for n, c in regles_du_gabarit(lire(os.path.join(RACINE_DEPOT, GABARIT))) if c not in noyau]
    if rc != 0 or manque:
        faute(f"{nom} : le chargeur INSTALLÉ, joué sans argument comme la doc le dit, rend {rc} (absentes {manque})\n{out[-1200:]}")


def scenario_central_audit():
    """bootstrap.sh passe par le chargeur : un doublon tiers est dédoublonné, et un arrêt d'augenrules
    AVANT plume (fichier tiers fautif) finit l'installation en code 3, avoué en fin de course."""
    regles = regles_du_gabarit(lire(os.path.join(RACINE_DEPOT, GABARIT)))
    b64 = next((l for l in lire(os.path.join(RACINE_DEPOT, GABARIT)).splitlines()
                if re.match(r"-a always,exit -F arch=b64 -S execve", l)), None)
    lignes = lire(os.path.join(RACINE_DEPOT, GABARIT)).splitlines()
    i = regles[-1][0] - 1 if regles else 0
    fausse = "-a always,exit -F dir=/chemin/absent/plume-temoin -F perm=wa -k plume_temoin_erreur"
    avec_erreur = "\n".join(lignes[:i] + [fausse] + lignes[i:]) + "\n"
    m1, m2 = "RÈGLES D'AUDIT INCOMPLÈTES MAINTENANT", "RÈGLES D'AUDIT COMPLÈTES MAINTENANT, MAIS PAS AU PROCHAIN DÉMARRAGE"
    # (libellé, fichiers posés, gabarit variante, code attendu, marque dite, marque TUE)
    cas = (("doublon tiers", {"etc/audit/rules.d/exec-tiers.rules": (b64 or "") + "\n"}, None, 0, "doublon", "INSTALLATION POSÉE"),
           # chargeur en code 2 : tout tourne maintenant, le démarrage s'arrêtera sur le fichier tiers.
           ("fichier tiers fautif avant plume",
            {"etc/audit/rules.d/00-casse.rules": "-a always,exit -F dir=/chemin/absent/plume-temoin -k tiers_casse\n"},
            None, 3, m2, m1),
           # chargeur en code 1 : une ligne du gabarit est refusée, il manque une règle MAINTENANT.
           ("ligne du gabarit refusée", {}, avec_erreur, 3, m1, m2))
    for libelle, poses, gabarit, rc_attendu, marque, tue in cas:
        nom = f"bootstrap.sh (auditd, {libelle})"
        bac = Bac("central", outils_audit=("augenrules", "auditctl"), gabarit=gabarit)
        try:
            for rel, contenu in poses.items():
                bac.poser(rel, contenu, 0o640)
            bac.jouer("bootstrap.sh", {"PLUME_PASS_HASH": ""})
            noyau = set(lire(bac.etat_audit).splitlines()) if os.path.isfile(bac.etat_audit) else set()
            manque = [n for n, c in regles if c not in noyau]
            charge = any(g[0] == "augenrules" and g[1] == "--load" for g in bac.gestes())
            if bac.rc != rc_attendu or marque not in bac.sortie or tue in bac.sortie or manque or not charge:
                faute(f"{nom} : code {bac.rc} (attendu {rc_attendu}), « {marque} » {'dit' if marque in bac.sortie else 'TU'}, "
                      f"« {tue} » {'DIT' if tue in bac.sortie else 'tu'}, absentes {manque}, augenrules --load joué {charge}\n{bac.sortie[-2000:]}")
        finally:
            bac.nettoyer()


def scenario_agent(commun, env_files):
    capteurs = sorted(f[:-3] for f in os.listdir(os.path.join(RACINE_DEPOT, "collectors"))
                      if f.endswith(".sh") and f != "lib.sh")
    base_env = {"PLUME_CENTRAL": "https://soc.example.test", "PLUME_TOKEN": "leurre-du-bac"}
    # 1) neuf, tous les capteurs en supplément (install_collector)
    nom = "bootstrap-agent.sh (neuf, tous les capteurs en supplément)"
    bac = Bac("agent").jouer("bootstrap-agent.sh", dict(base_env, PLUME_EXTRA_COLLECTORS=" ".join(capteurs)))
    try:
        if bac.rc != 0:
            refuser(f"{nom} a échoué dans le bac (code {bac.rc}) :\n{bac.sortie[-3000:]}")
        else:
            gestes = bac.gestes()
            for f in juger_lib_avant_capteurs(gestes, bac.racine, lambda d: lire(d) if os.path.isfile(d) else None, nom):
                faute(f)
            juger_dropins(bac, nom, commun)
            juger_familles_installees(bac, nom)
            juger_jeton(bac, nom, "/etc/plume/plume.conf", creee=True)
            juger_chargeur_installe(bac, nom)
    finally:
        bac.nettoyer()
    # 2) re-passage sur des confs 0640 existantes, écrites par une version qui commentait en fin de valeur :
    #    a) la conf syslog est l'ANCIENNE CONF ENGENDRÉE, octet pour octet — le cas qui motive le lot :
    #       `PLUME_SYSLOG_ALLOW=          # ex: …` vaut pour systemd une valeur qui COMMENCE par `#` ;
    #       un jeton porte aussi un commentaire, et sa valeur ne doit JAMAIS sortir ;
    #    b) une conf syslog sans adresse et à liste vide : le récepteur écouterait 0.0.0.0:514 deux fois,
    #       donc REFUSERA DE DEMARRER (`P10.32-l`) — les deux clés sont nommées, absentes.
    repasser_agent("a", {
        "/etc/plume/plume.conf": "PLUME_CENTRAL=https://soc.example.test\n"
                                 f"PLUME_TOKEN={JETON_COMMENTE}   # pose a la main\n"
                                 "PLUME_MAIL_F2B=0   # ancien commentaire\n",
        "/etc/plume/responder.conf": "PLUME_CENTRAL=https://soc.example.test\nPLUME_TOKEN=leurre-du-bac\n"
                                     "PLUME_RESPONDER=1\nPLUME_RESPONDER_APPLY=1   # 1 = appliquer\n"
                                     "PLUME_RESPONDER_ALLOW={allow}\n",
        "/etc/plume/syslog.conf": ANCIENNE_CONF_SYSLOG,
    }, {("/etc/plume/plume.conf", "PLUME_TOKEN"), ("/etc/plume/plume.conf", "PLUME_MAIL_F2B"),
        ("/etc/plume/responder.conf", "PLUME_RESPONDER_APPLY"),
        ("/etc/plume/syslog.conf", "PLUME_SYSLOG_PARSER"), ("/etc/plume/syslog.conf", "PLUME_SYSLOG_UDP"),
        ("/etc/plume/syslog.conf", "PLUME_SYSLOG_TCP"), ("/etc/plume/syslog.conf", "PLUME_SYSLOG_ALLOW")},
        None)
    repasser_agent("b", {
        "/etc/plume/plume.conf": "PLUME_CENTRAL=https://soc.example.test\nPLUME_TOKEN=leurre-du-bac\n",
        "/etc/plume/responder.conf": "PLUME_CENTRAL=https://soc.example.test\nPLUME_TOKEN=leurre-du-bac\n"
                                     "PLUME_RESPONDER=1\nPLUME_RESPONDER_ALLOW={allow}\n",
        "/etc/plume/syslog.conf": "PLUME_SYSLOG_PARSER=fortigate\nPLUME_SYSLOG_ALLOW=\n",
    }, set(), [ABSENTE_UDP, ABSENTE_TCP])
    # 3) tous les modules optionnels
    nom = "bootstrap-agent.sh (tous les modules optionnels)"
    modules = sorted(set(re.findall(r'"\$\{(PLUME_WITH_[A-Z_]+):-0\}"', lire(os.path.join(RACINE_DEPOT, "bootstrap-agent.sh")))))
    if "PLUME_WITH_SYSLOG" not in modules:
        refuser("bootstrap-agent.sh n'a plus de module PLUME_WITH_SYSLOG : la conf syslog n'est plus jugée")
    bac = Bac("agent-modules").jouer("bootstrap-agent.sh", dict(base_env, **{m: "1" for m in modules}))
    try:
        if bac.rc != 0:
            refuser(f"{nom} a échoué dans le bac (code {bac.rc}) :\n{bac.sortie[-3000:]}")
            return
        gestes = bac.gestes()
        for f in juger_lib_avant_capteurs(gestes, bac.racine, lambda d: lire(d) if os.path.isfile(d) else None, nom):
            faute(f)
        juger_confs_engendrees(bac, nom, env_files)
        juger_jeton(bac, nom, "/etc/plume/responder.conf", creee=True)
        # Le témoin négatif : un second passage relit les confs que l'installeur VIENT d'engendrer. Il doit
        # les garder octet pour octet, et se taire — sinon le signal ne distingue rien.
        confs = ("/etc/plume/plume.conf", "/etc/plume/responder.conf", "/etc/plume/syslog.conf")
        avant = {c: lire(bac.r(c)) for c in confs if os.path.isfile(bac.r(c))}
        if len(avant) != len(confs):
            faute(f"{nom} : confs engendrées manquantes : {sorted(set(confs) - set(avant))}")
        bac.jouer("bootstrap-agent.sh", dict(base_env, **{m: "1" for m in modules}))
        if bac.rc != 0:
            refuser(f"{nom} : le second passage a échoué (code {bac.rc}) :\n{bac.sortie[-3000:]}")
            return
        for marque in ("COMMENTAIRE DANS UNE VALEUR", MARQUE_SYSLOG, "SYSLOG OUVERT SANS LISTE"):
            if marque in bac.sortie:
                faute(f"{nom} : au second passage, une conf que l'installeur vient d'engendrer est signalée « {marque} »")
        for c, contenu in avant.items():
            if lire(bac.r(c)) != contenu:
                faute(f"{nom} : au second passage, {c} a été réécrite")
        for c in ("/etc/plume/plume.conf", "/etc/plume/responder.conf"):
            if os.path.isfile(bac.r(c)) and mode(bac.r(c)) != 0o600:
                faute(f"{nom} : au second passage, {c} finit en {mode(bac.r(c)):04o}")
        p = bac.r("/etc/plume/syslog.conf")
        if not os.path.isfile(p):
            faute(f"{nom} : /etc/plume/syslog.conf n'a pas été engendrée")
            return
        texte = lire(p)
        v = lire_env_systemd(texte)
        for cle in ("PLUME_SYSLOG_UDP", "PLUME_SYSLOG_TCP"):
            if v.get(cle) != "127.0.0.1:514":
                faute(f"{nom} : syslog.conf écoute {cle}={v.get(cle)!r} (lu selon systemd) au lieu de 127.0.0.1:514")
        if v.get("PLUME_SYSLOG_ALLOW", None) != "":
            faute(f"{nom} : PLUME_SYSLOG_ALLOW={v.get('PLUME_SYSLOG_ALLOW')!r} (lu selon systemd) : attendu vide")
        comm = "\n".join(l for l in texte.splitlines() if l.lstrip().startswith("#"))
        if "PLUME_SYSLOG_ALLOW" not in comm or "pare-feu" not in comm or "0.0.0.0:514" not in comm:
            faute(f"{nom} : le commentaire de syslog.conf ne dit pas comment ouvrir (liste d'autorisation + pare-feu + 0.0.0.0:514)")
    finally:
        bac.nettoyer()


# L'ancienne conf syslog, telle que bootstrap-agent.sh l'engendrait avant `P10.32-j` (octet pour octet).
ANCIENNE_CONF_SYSLOG = (
    "PLUME_SPOOL=/var/lib/plume/spool\n"
    "PLUME_SYSLOG_PARSER=fortigate   # fortigate | auto | generic\n"
    "PLUME_SYSLOG_SOURCE=fortigate\n"
    "PLUME_SYSLOG_UDP=0.0.0.0:514       # vider = desactiver l'UDP\n"
    "PLUME_SYSLOG_TCP=0.0.0.0:514       # vider = desactiver le TCP\n"
    "PLUME_SYSLOG_ALLOW=          # ex: 203.0.113.10/32,10.0.0.0/8\n")
JETON_COMMENTE = "leurre-jeton-qui-ne-sort-jamais"
# P10.32-l — le récepteur REFUSE DE DÉMARRER (code 2) une écoute hors boucle locale à liste vide : le
# signalement le dit, et nomme les CLÉS (une écoute absente vaut 0.0.0.0:514, c'est le défaut du binaire,
# pas une valeur lue). Une ligne sans « REFUSERA DE DEMARRER » ne compte pas comme signalement.
MARQUE_SYSLOG = "SYSLOG HORS BOUCLE LOCALE SANS LISTE"
OUVERT = re.compile(MARQUE_SYSLOG + r" : (\S+) : ecoute hors boucle locale par (.*?), PLUME_SYSLOG_ALLOW vide : "
                    r"collector-syslog REFUSERA DE DEMARRER")
ABSENTE_UDP, ABSENTE_TCP = "PLUME_SYSLOG_UDP(absente=0.0.0.0:514)", "PLUME_SYSLOG_TCP(absente=0.0.0.0:514)"
# L'ANCIENNE sémantique, fausse depuis `P10.32-l` : vide = 0.0.0.0:514, vider ne désactive pas, liste vide
# = toute source acceptée. Interdite dans la sortie de l'installeur ET dans les textes qui la décrivent.
ANCIENNE_SEMANTIQUE = re.compile(
    r"(absente?|non\s+pos[ée]e)\s+ou\s+vide|vider?\s+ne\s+d[ée]sactive\s+pas|ne\s+d[ée]sactive\s+pas\s+un\s+transport"
    r"|toute\s+source\s+(est\s+)?accept[ée]e|SYSLOG OUVERT SANS LISTE", re.I)
NOMMEE = re.compile(r"COMMENTAIRE DANS UNE VALEUR : (\S+) : (\S+)")


def juger_signalements(nom, sortie, racine, confs, attendues, ouvert_attendu, conf_syslog):
    """Compare ce que l'installeur NOMME à ce qu'il doit nommer — dans les deux sens — et exige qu'aucune
    valeur d'une clé nommée ne sorte (elle peut être un secret)."""
    nommees = {(c.replace(racine, ""), k) for c, k in NOMMEE.findall(sortie)}
    for chemin, cle in sorted(attendues - nommees):
        faute(f"{nom} : {chemin} garde {cle}=« … # … » (lu selon systemd) et l'installeur ne le NOMME pas")
    for chemin, cle in sorted(nommees - attendues):
        faute(f"{nom} : {chemin} : {cle} est nommée alors que sa valeur ne porte aucun commentaire")
    for chemin, contenu in confs.items():
        for cle, val in lire_env_systemd(contenu).items():
            if (chemin, cle) in attendues and val.strip() and val in sortie:
                faute(f"{nom} : la VALEUR de {cle} ({chemin}) sort de l'installeur — elle peut être un secret")
    if JETON_COMMENTE in sortie:
        faute(f"{nom} : le jeton d'une ligne commentée sort de l'installeur")
    ouverts = [(c.replace(racine, ""), a.split()) for c, a in OUVERT.findall(sortie)]
    ouverts = [a for c, a in ouverts if c == conf_syslog]
    if ouvert_attendu is None and ouverts:
        faute(f"{nom} : {conf_syslog} signalée « {MARQUE_SYSLOG} » ({ouverts[0]}) à tort")
    elif ouvert_attendu is not None and ouverts != [ouvert_attendu]:
        faute(f"{nom} : {conf_syslog} écoute hors boucle locale par {' '.join(ouvert_attendu)} à liste vide "
              f"(absente = 0.0.0.0:514, posée vide = coupée) : le récepteur refusera de démarrer ; l'installeur "
              f"dit {ouverts or 'rien'}")
    m = ANCIENNE_SEMANTIQUE.search(sortie)
    if m:
        faute(f"{nom} : l'installeur redit l'ancienne sémantique syslog (« {m.group(0)} ») — fausse depuis P10.32-l")


def repasser_agent(lettre, posees, attendues, ouvert_attendu):
    nom = f"bootstrap-agent.sh (re-passage {lettre}, confs 0640 existantes)"
    bac = Bac(f"agent-repassage-{lettre}")
    posees = {c: v.replace("{allow}", bac.r("/etc/plume/responder-ban-exempt.allow")) for c, v in posees.items()}
    for chemin, contenu in posees.items():
        bac.poser(chemin.lstrip("/"), contenu, 0o640)
    bac.jouer("bootstrap-agent.sh", {"PLUME_WITH_RESPONDER": "1", "PLUME_WITH_SYSLOG": "1"})
    try:
        if bac.rc != 0:
            refuser(f"{nom} a échoué dans le bac (code {bac.rc}) :\n{bac.sortie[-3000:]}")
            return
        juger_jeton(bac, nom, "/etc/plume/plume.conf", creee=False)
        juger_jeton(bac, nom, "/etc/plume/responder.conf", creee=False)
        for chemin, contenu in posees.items():
            if lire(bac.r(chemin)) != contenu:
                faute(f"{nom} : {chemin} existante a été RÉÉCRITE — une conf d'exploitant se garde telle quelle")
        juger_signalements(nom, bac.sortie, bac.racine, posees, attendues, ouvert_attendu, "/etc/plume/syslog.conf")
    finally:
        bac.nettoyer()


# Les fonctions de signalement LIVRÉES, jouées seules sur des confs que le re-passage complet ne peut pas
# toutes porter (une seule syslog.conf par passage). Le texte est celui du script, extrait tel quel.
FONCTIONS_SIGNALEMENT = ("lire_conf_systemd", "signaler_conf_conservee", "signaler_syslog_ouvert")
CONFS_SYSLOG = {
    # nom : (conf, clés nommées attendues, adresses ouvertes attendues ou None)
    "ancienne-conf-engendree": (ANCIENNE_CONF_SYSLOG,
                                {"PLUME_SYSLOG_PARSER", "PLUME_SYSLOG_UDP", "PLUME_SYSLOG_TCP", "PLUME_SYSLOG_ALLOW"}, None),
    "transports-absents-liste-vide": ("PLUME_SYSLOG_PARSER=fortigate\nPLUME_SYSLOG_ALLOW=\n", set(),
                                      [ABSENTE_UDP, ABSENTE_TCP]),
    # P10.32-l — posée VIDE, une écoute est COUPÉE : deux écoutes coupées n'ouvrent rien
    "transports-vides-liste-vide": ("PLUME_SYSLOG_UDP=\nPLUME_SYSLOG_TCP=\nPLUME_SYSLOG_ALLOW=\n", set(), None),
    "tcp-absent": ("PLUME_SYSLOG_UDP=127.0.0.1:514\nPLUME_SYSLOG_ALLOW=\n", set(), [ABSENTE_TCP]),
    "udp-absent": ("PLUME_SYSLOG_TCP=127.0.0.1:514\nPLUME_SYSLOG_ALLOW=\n", set(), [ABSENTE_UDP]),
    "udp-vide": ("PLUME_SYSLOG_UDP=\nPLUME_SYSLOG_TCP=127.0.0.1:514\nPLUME_SYSLOG_ALLOW=\n", set(), None),
    "tcp-vide": ("PLUME_SYSLOG_UDP=127.0.0.1:514\nPLUME_SYSLOG_TCP=\nPLUME_SYSLOG_ALLOW=\n", set(), None),
    "udp-vide-tcp-reseau": ("PLUME_SYSLOG_UDP=\nPLUME_SYSLOG_TCP=0.0.0.0:514\nPLUME_SYSLOG_ALLOW=\n", set(),
                            ["PLUME_SYSLOG_TCP"]),
    "udp-blanc-entre-guillemets": ("PLUME_SYSLOG_UDP=\"   \"\nPLUME_SYSLOG_TCP=127.0.0.1:514\nPLUME_SYSLOG_ALLOW=\n",
                                   set(), None),
    "toutes-interfaces-v6": ("PLUME_SYSLOG_UDP=[::]:514\nPLUME_SYSLOG_TCP=\nPLUME_SYSLOG_ALLOW=\n", set(),
                             ["PLUME_SYSLOG_UDP"]),
    # sans port, ou port hors bornes : le récepteur ne la prouve pas locale, il la compte dehors
    "boucle-locale-sans-port": ("PLUME_SYSLOG_UDP=127.0.0.1\nPLUME_SYSLOG_TCP=127.0.0.1:514\nPLUME_SYSLOG_ALLOW=\n",
                                set(), ["PLUME_SYSLOG_UDP"]),
    "boucle-locale-port-hors-bornes": ("PLUME_SYSLOG_UDP=127.0.0.1:514\nPLUME_SYSLOG_TCP=127.0.0.1:70000\n"
                                       "PLUME_SYSLOG_ALLOW=\n", set(), ["PLUME_SYSLOG_TCP"]),
    "liste-entre-guillemets-doubles": ("PLUME_SYSLOG_UDP=127.0.0.1:514\nPLUME_SYSLOG_TCP=0.0.0.0:514\n"
                                       "PLUME_SYSLOG_ALLOW=\"\"\n", set(), ["PLUME_SYSLOG_TCP"]),
    "liste-entre-guillemets-simples": ("PLUME_SYSLOG_UDP=0.0.0.0:514\nPLUME_SYSLOG_TCP=127.0.0.1:514\n"
                                       "PLUME_SYSLOG_ALLOW=''\n", set(), ["PLUME_SYSLOG_UDP"]),
    # une liste faite de seuls séparateurs est VIDE pour le récepteur (parse_allowlist : aucun jeton)
    "liste-de-separateurs": ("PLUME_SYSLOG_UDP=0.0.0.0:514\nPLUME_SYSLOG_TCP=127.0.0.1:514\nPLUME_SYSLOG_ALLOW=, ,\n",
                             set(), ["PLUME_SYSLOG_UDP"]),
    "ligne-point-virgule": ("; PLUME_SYSLOG_PARSER=auto   # ancien essai\nPLUME_SYSLOG_UDP=127.0.0.1:514\n"
                            "PLUME_SYSLOG_TCP=127.0.0.1:514\nPLUME_SYSLOG_ALLOW=\n", set(), None),
    # témoins négatifs : une liste non vide (nue ou entre guillemets) fait taire le signalement
    "liste-posee": ("PLUME_SYSLOG_UDP=0.0.0.0:514\nPLUME_SYSLOG_ALLOW=203.0.113.10/32\n", set(), None),
    "liste-posee-entre-guillemets": ("PLUME_SYSLOG_TCP=0.0.0.0:514\nPLUME_SYSLOG_ALLOW=\"203.0.113.10/32\"\n",
                                     set(), None),
    "boucle-locale": ("PLUME_SYSLOG_UDP=127.0.0.1:514\nPLUME_SYSLOG_TCP=127.0.0.1:514\nPLUME_SYSLOG_ALLOW=\n",
                      set(), None),
    "boucle-locale-v6-et-nom": ("PLUME_SYSLOG_UDP=[::1]:514\nPLUME_SYSLOG_TCP=localhost:5514\nPLUME_SYSLOG_ALLOW=\n",
                                set(), None),
}


def juger_fonctions_de_signalement():
    texte = lire(os.path.join(RACINE_DEPOT, "bootstrap-agent.sh"))
    corps = []
    for f in FONCTIONS_SIGNALEMENT:
        m = re.search(r"^" + f + r"\(\) \{\n.*?^\}\n", texte, re.M | re.S)
        if not m:
            refuser(f"bootstrap-agent.sh ne définit plus `{f}()` à la forme attendue : les signalements ne sont plus jugés")
            return
        corps.append(m.group(0))
    d = tempfile.mkdtemp(prefix="plume-installation-signalements-", dir=os.environ.get("TMPDIR") or None)
    try:
        fichiers = []
        for nom, (conf, _, _) in CONFS_SYSLOG.items():
            p = os.path.join(d, nom)
            with open(p, "w") as h:
                h.write(conf)
            fichiers.append(p)
        prog = "set -euo pipefail\n" + "".join(corps) + (
            'for f in "$@"; do signaler_conf_conservee "$f"; signaler_syslog_ouvert "$f"; done\n')
        r = subprocess.run(["bash", "-c", prog, "signalements"] + fichiers, capture_output=True, text=True,
                           timeout=60, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"})
        if r.returncode != 0:
            refuser(f"les fonctions de signalement de bootstrap-agent.sh échouent seules (code {r.returncode}) : "
                    f"{(r.stdout + r.stderr)[-1500:]}")
            return
        for nom, (conf, cles, ouvert) in CONFS_SYSLOG.items():
            p = os.path.join(d, nom)
            lignes = "\n".join(l for l in r.stdout.splitlines() if f" {p} " in l + " ")
            juger_signalements(f"bootstrap-agent.sh (signalements, conf « {nom} »)", lignes, d,
                               {"/" + nom: conf}, {("/" + nom, k) for k in cles}, ouvert, "/" + nom)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def juger_jeton(bac, nom, chemin, creee):
    """Fichier porteur du jeton : 0600 à la fin, jamais confié à soc ; créé, il n'a jamais été plus ouvert."""
    p = os.path.normpath(bac.r(chemin))
    court = os.path.basename(chemin)
    if not os.path.isfile(p):
        faute(f"{nom} : {court} absent du bac")
        return
    m = mode(p)
    if m != 0o600:
        faute(f"{nom} : {court} finit en {m:04o} au lieu de 0600")
    gestes = bac.gestes()
    for g in gestes:
        if g[0] in ("chgrp", "chown") and p in g[1] and re.search(r"(^|[\s:])soc(\s|$)", g[1]):
            faute(f"{nom} : {court} confié au groupe soc ({g[0]} {g[1].replace(bac.racine, '')})")
    if creee:
        modes = [g[2] for g in gestes if g[0] == "mode" and os.path.normpath(g[1]) == p]
        if not modes:
            faute(f"{nom} : aucun chown/chgrp n'a touché {court} — le mode de création n'est pas mesuré")
        elif modes[0] != "600":
            faute(f"{nom} : {court} est CRÉÉ en {modes[0]} (umask) avant d'être resserré : le jeton est plus "
                  f"ouvert que 0600 jusqu'au chmod, et le reste si ce chmod échoue")


# --------------------------------------------------------------------------------------------------
# Propriétés statiques : unité pod-logs, k3s, compose
# --------------------------------------------------------------------------------------------------
def juger_pod_logs():
    unite = lire(os.path.join(RACINE_DEPOT, "systemd/plume-pod-logs.service"))
    script = lire(os.path.join(RACINE_DEPOT, "collectors/pod-logs.sh"))
    defauts = dict(re.findall(r'"\$\{(PLUME_POD_LOG_[A-Z_]+):-([^}]*)\}"', script))
    if "PLUME_POD_LOG_SKIP" not in defauts or "PLUME_POD_LOG_MIN_SEV" not in defauts:
        refuser("collectors/pod-logs.sh ne déclare plus ses défauts PLUME_POD_LOG_SKIP / MIN_SEV sous la forme ${X:-d}")
        return
    if defauts["PLUME_POD_LOG_SKIP"] != "":
        faute(f"collectors/pod-logs.sh : défaut de PLUME_POD_LOG_SKIP non vide ({defauts['PLUME_POD_LOG_SKIP']!r})")
    for m in re.finditer(r'^Environment="?(PLUME_POD_LOG_[A-Z_]+)=([^"\n]*)', unite, re.M):
        cle, val = m.group(1), m.group(2).strip()
        if cle in defauts and val != defauts[cle]:
            faute(f"systemd/plume-pod-logs.service force {cle}={val!r} alors que le script vaut {defauts[cle]!r}")


def charger_yaml():
    try:
        import yaml  # noqa: PLC0415
    except ImportError:
        refuser("PyYAML absent : k3s.yaml et docker-compose.yml ne sont pas jugés par un analyseur")
        return None
    return yaml


def juger_k3s(yaml):
    try:
        docs = [d for d in yaml.safe_load_all(lire(os.path.join(RACINE_DEPOT, "deploy/k3s.yaml"))) if d]
    except yaml.YAMLError as e:
        faute(f"deploy/k3s.yaml n'est pas du YAML valide : {e}")
        return
    par = {}
    for d in docs:
        par.setdefault(d.get("kind"), []).append(d)
    for k in ("Deployment", "Ingress", "NetworkPolicy"):
        if len(par.get(k, [])) != 1:
            refuser(f"deploy/k3s.yaml : {len(par.get(k, []))} objet(s) {k} au lieu d'un")
            return
    pod = par["Deployment"][0]["spec"]["template"]["spec"]
    if pod.get("automountServiceAccountToken") is not False:
        faute("deploy/k3s.yaml : le pod monte le jeton de compte de service (automountServiceAccountToken != false)")
    psc = pod.get("securityContext") or {}
    for c in pod.get("containers", []):
        csc = c.get("securityContext") or {}
        sec = (csc.get("seccompProfile") or psc.get("seccompProfile") or {}).get("type")
        if sec != "RuntimeDefault":
            faute(f"deploy/k3s.yaml : conteneur {c.get('name')} sans seccompProfile RuntimeDefault ({sec!r})")
        if csc.get("allowPrivilegeEscalation") is not False or (csc.get("capabilities") or {}).get("drop") != ["ALL"]:
            faute(f"deploy/k3s.yaml : conteneur {c.get('name')} sans allowPrivilegeEscalation:false + drop [ALL]")
    ing = par["Ingress"][0]
    hotes = {r.get("host") for r in ing["spec"].get("rules", [])}
    tls = ing["spec"].get("tls") or []
    hotes_tls = {h for t in tls for h in (t.get("hosts") or [])}
    if not tls or not all(t.get("secretName") for t in tls):
        faute("deploy/k3s.yaml : Ingress sans bloc tls (ou sans secretName)")
    elif not hotes <= hotes_tls:
        faute(f"deploy/k3s.yaml : hôtes servis sans TLS : {sorted(hotes - hotes_tls)}")
    ann = (ing.get("metadata") or {}).get("annotations") or {}
    entrees = [e.strip() for e in str(ann.get("traefik.ingress.kubernetes.io/router.entrypoints", "")).split(",") if e.strip()]
    if entrees != ["websecure"]:
        faute(f"deploy/k3s.yaml : entrées Traefik {entrees!r} — attendu `websecure` seule (sinon servi aussi en HTTP)")
    if str(ann.get("traefik.ingress.kubernetes.io/router.tls", "")).lower() != "true":
        faute("deploy/k3s.yaml : annotation traefik router.tls absente ou différente de \"true\"")
    # `P10.32-t` — l'Ingress ne sert que du HTTPS et parle au pod en clair : sans le réglage, le démon
    # pose ses cookies sans `Secure` et ne pose pas HSTS alors que le navigateur ne voit que du HTTPS.
    env_plume = {e.get("name"): e.get("value") for c in pod.get("containers", []) for e in (c.get("env") or [])}
    if str(env_plume.get("PLUME_TLS_TERMINATED_UPSTREAM")) != "1":
        faute("deploy/k3s.yaml : Ingress HTTPS seul mais PLUME_TLS_TERMINATED_UPSTREAM != \"1\" "
              f"({env_plume.get('PLUME_TLS_TERMINATED_UPSTREAM')!r}) — cookies sans Secure, pas de HSTS")
    np_ = par["NetworkPolicy"][0]["spec"]
    if "Ingress" not in (np_.get("policyTypes") or []):
        faute("deploy/k3s.yaml : la NetworkPolicy ne filtre pas l'entrée")
    for regle in np_.get("ingress") or []:
        pairs = regle.get("from")
        if not pairs:
            faute("deploy/k3s.yaml : une règle d'entrée sans `from` accepte TOUTE source")
            continue
        for p in pairs:
            ns = p.get("namespaceSelector")
            if ns is not None:
                if (ns.get("matchLabels") or {}) != {"kubernetes.io/metadata.name": "kube-system"} or ns.get("matchExpressions"):
                    faute(f"deploy/k3s.yaml : entrée depuis un namespace autre que kube-system : {p!r}")
            elif "ipBlock" in p:
                faute(f"deploy/k3s.yaml : entrée par ipBlock : {p!r}")
            elif "podSelector" not in p:
                faute(f"deploy/k3s.yaml : pair d'entrée inconnu : {p!r}")
    # Le jeton non monté est ADOSSÉ à un fait du code : le démon n'a aucun client de l'API du cluster.
    motifs = re.compile(r"KUBERNETES_SERVICE_HOST|/var/run/secrets/kubernetes\.io|kube::|k8s_openapi")
    for rac, _, fs in os.walk(os.path.join(RACINE_DEPOT, "daemon/src")):
        for f in fs:
            if f.endswith(".rs") and motifs.search(lire(os.path.join(rac, f))):
                faute(f"daemon/src/{os.path.relpath(os.path.join(rac, f), os.path.join(RACINE_DEPOT, 'daemon/src'))} "
                      f"parle à l'API Kubernetes : `automountServiceAccountToken: false` le priverait de son jeton")


def juger_compose(yaml):
    try:
        d = yaml.safe_load(lire(os.path.join(RACINE_DEPOT, "docker-compose.yml")))
    except yaml.YAMLError as e:
        faute(f"docker-compose.yml n'est pas du YAML valide : {e}")
        return
    s = (d.get("services") or {}).get("soc")
    if not s:
        refuser("docker-compose.yml : service `soc` introuvable")
        return
    if "ALL" not in (s.get("cap_drop") or []):
        faute("docker-compose.yml : pas de cap_drop: [ALL]")
    if "no-new-privileges:true" not in (s.get("security_opt") or []):
        faute("docker-compose.yml : pas de security_opt no-new-privileges:true")
    env = s.get("environment") or {}
    if isinstance(env, list):
        env = dict(e.split("=", 1) if "=" in e else (e, None) for e in env)
    for cle in ("PLUME_TLS_CERT", "PLUME_TLS_KEY", "PLUME_TLS_TERMINATED_UPSTREAM"):
        if not re.fullmatch(r"\$\{" + cle + r"(:?-[^}]*)?\}", str(env.get(cle, ""))):
            faute(f"docker-compose.yml : {cle} n'est pas transmis depuis `.env` au conteneur ({env.get(cle)!r})")
    # `P10.32-t` — VIDE par défaut, comme le `.env` copié depuis `.env.example` : un `:-1` poserait Secure et HSTS
    # sur un déploiement qui ne l'a pas demandé (accès direct en http privé de son cookie).
    if str(env.get("PLUME_TLS_TERMINATED_UPSTREAM", "")) != "${PLUME_TLS_TERMINATED_UPSTREAM:-}":
        faute(f"docker-compose.yml : PLUME_TLS_TERMINATED_UPSTREAM n'est pas vide par défaut ({env.get('PLUME_TLS_TERMINATED_UPSTREAM')!r})")


def juger_docs_audit():
    """`P10.33-c` — la doc dit comment VÉRIFIER (watches comprises : `-k`, pas seulement `key=`) et quoi
    faire d'un doublon d'un autre fichier ; aucune doc ni installeur ne fait compter `key=plume_` seul."""
    doc = lire(os.path.join(RACINE_DEPOT, "docs/ENDPOINT-SECURITY.md"))
    if "auditctl -l | grep -cE -- '(-k |key=)plume_'" not in doc:
        faute("docs/ENDPOINT-SECURITY.md : le geste de vérification `sudo auditctl -l | grep -cE -- '(-k |key=)plume_'` manque")
    if not re.search(r"doublon", doc) or "/etc/audit/rules.d" not in doc or "Rule exists" not in doc:
        faute("docs/ENDPOINT-SECURITY.md : rien ne dit quoi faire d'une règle plume déjà déclarée par un autre fichier de /etc/audit/rules.d")
    # Le code que la doc annonce pour bootstrap.sh est celui du bloc AUDIT_RC de bootstrap.sh, lu ici.
    bloc = re.search(r'if \[ "\$\{AUDIT_RC:-0\}" -ne 0 \]; then\n(.*?)\nfi\n', lire(os.path.join(RACINE_DEPOT, "bootstrap.sh")), re.S)
    codes = re.findall(r"^\s*exit (\d+)\s*$", bloc.group(1), re.M) if bloc else []
    if len(codes) != 1:
        refuser(f"bootstrap.sh : bloc AUDIT_RC méconnaissable ({len(codes)} `exit` lus) — le code annoncé par la doc n'est pas jugeable")
    elif f"`bootstrap.sh` finit alors en code `{codes[0]}`" not in doc:
        faute(f"docs/ENDPOINT-SECURITY.md : n'annonce pas le code `{codes[0]}` que bootstrap.sh rend sur un chargement d'audit refusé")
    vraie = re.search(r"^- \*\*vraie erreur\*\*.*?(?=^\S|^- |\Z)", doc, re.S | re.M)
    if not vraie or "PERDUES au prochain démarrage" not in " ".join(vraie.group(0).split()):
        faute("docs/ENDPOINT-SECURITY.md : le cas « vraie erreur » (code 1) ne dit pas que les règles rattrapées seront PERDUES au prochain démarrage")
    seul = re.compile(r"grep\s+-c\s+['\"]?key=plume_")
    fichiers = ["README.md", "bootstrap.sh", "bootstrap-agent.sh", CHARGEUR, GABARIT]
    for rep in ("deploy", "docs"):
        fichiers += [os.path.relpath(os.path.join(r, f), RACINE_DEPOT) for r, _, fs in os.walk(os.path.join(RACINE_DEPOT, rep))
                     for f in fs if f.endswith(".md") and f != "ROADMAP.md"]
    for rel in sorted(fichiers):
        for i, ligne in enumerate(lire(os.path.join(RACINE_DEPOT, rel)).splitlines(), 1):
            if seul.search(ligne):
                faute(f"{rel}:{i} fait compter `key=plume_` seul — `auditctl -l` rend les watches en `-k`, qui y échappent")


def juger_docs():
    prescrit = re.compile(r"chgrp\s+soc\s+/etc/plume/(plume|responder)\.conf|chmod\s+0?640\s+/etc/plume/(plume|responder)\.conf")
    docs = [os.path.join(RACINE_DEPOT, "README.md")]
    for rep in ("deploy", "docs"):
        for rac, _, fs in os.walk(os.path.join(RACINE_DEPOT, rep)):
            docs += [os.path.join(rac, f) for f in fs if f.endswith(".md") and f != "ROADMAP.md"]
    # La consigne que bootstrap-agent.sh AFFICHE (en-tête et message d'échec du 1er passage) est une doc aussi.
    docs.append(os.path.join(RACINE_DEPOT, "bootstrap-agent.sh"))
    for d in sorted(docs):
        for i, ligne in enumerate(lire(d).splitlines(), 1):
            if prescrit.search(ligne):
                faute(f"{os.path.relpath(d, RACINE_DEPOT)}:{i} prescrit d'ouvrir le jeton au groupe soc : {ligne.strip()}")
    consigne = r"sudo chmod 0600 /etc/plume/plume\.conf"
    agent = lire(os.path.join(RACINE_DEPOT, "bootstrap-agent.sh")).splitlines()
    if not any(re.match(r"\s*#.*" + consigne, l) for l in agent):
        faute("bootstrap-agent.sh : l'en-tête ne prescrit plus `sudo chmod 0600 /etc/plume/plume.conf` après la pose par STDIN")
    if not any(re.match(r"\s*echo .*" + consigne, l) for l in agent):
        faute("bootstrap-agent.sh : la consigne affichée au 1er passage sans secret ne prescrit plus "
              "`sudo chmod 0600 /etc/plume/plume.conf`")
    texte = lire(os.path.join(RACINE_DEPOT, "deploy/SYSLOG.md"))
    m = re.search(r"^### 2\. Config `/etc/plume/syslog\.conf`\n.*?^```sh\n(.*?)^```", texte, re.M | re.S)
    if not m:
        refuser("deploy/SYSLOG.md : bloc de conf de la section « 2. Config /etc/plume/syslog.conf » introuvable")
        return
    v = lire_env_systemd(m.group(1))
    for cle, val in v.items():
        if re.search(r"(^|\s)#", val):
            faute(f"deploy/SYSLOG.md : la conf documentée fait lire à systemd {cle}={val!r} — commentaire DANS la valeur")
    for cle in ("PLUME_SYSLOG_UDP", "PLUME_SYSLOG_TCP"):
        if v.get(cle) != "127.0.0.1:514":
            faute(f"deploy/SYSLOG.md : la conf documentée écoute {cle}={v.get(cle)!r} — l'installeur pose 127.0.0.1:514")
    if v.get("PLUME_SYSLOG_ALLOW") != "":
        faute(f"deploy/SYSLOG.md : PLUME_SYSLOG_ALLOW={v.get('PLUME_SYSLOG_ALLOW')!r} dans la conf documentée")
    # P10.32-l — l'ancienne sémantique (vide = 0.0.0.0:514, « toute source acceptée ») est fausse : ni la
    # doc, ni l'unité, ni l'installeur (commentaires, conf engendrée, messages) ne la redisent.
    for rel in ("deploy/SYSLOG.md", "systemd/plume-collector-syslog.service", "bootstrap-agent.sh"):
        for i, ligne in enumerate(lire(os.path.join(RACINE_DEPOT, rel)).splitlines(), 1):
            m = ANCIENNE_SEMANTIQUE.search(ligne)
            if m:
                faute(f"{rel}:{i} redit l'ancienne sémantique syslog (« {m.group(0)} ») : une écoute posée vide "
                      f"coupe son transport, et une liste vide hors boucle locale fait REFUSER le démarrage")


def main():
    if os.geteuid() == 0:
        refuser("cette garde ne se joue pas en root : un chemin non réacheminé toucherait la machine")
        return 2
    if not shutil.which("bash"):
        refuser("bash absent")
        return 2
    eprouver_lecteur_systemd()
    eprouver_juge_lib()
    commun = lire(os.path.join(RACINE_DEPOT, "systemd/plume-collector-common.conf"))
    env_files = fichiers_environnement()
    if not refus:
        scenario_central(commun, env_files)
        scenario_central_audit()
        scenario_agent(commun, env_files)
        juger_chargeur_audit()
        juger_chargeur_sans_cle()
        juger_fonctions_de_signalement()
    if re.search(r"^\s*RestrictAddressFamilies\s*=", commun, re.M):
        faute("systemd/plume-collector-common.conf : `RestrictAddressFamilies=` est de retour dans le drop-in "
              "COMMUN. C'est une LISTE : elle s'UNIT à celle de chaque unité, et ÉLARGIT toutes celles qui en "
              "déclarent moins. Chaque unité porte la sienne (`P10.33-d`).")
    juger_familles_derivees()
    lecteurs_soc_de_plume_conf()
    juger_un_seul_chargeur()
    juger_pod_logs()
    juger_docs()
    juger_docs_audit()
    yaml = charger_yaml()
    if yaml:
        juger_k3s(yaml)
        juger_compose(yaml)
    if fautes:
        print(f"{len(fautes)} propriété(s) violée(s).")
        return 1
    if refus:
        return 2
    print("installation fonctionnelle et durcie : central, agent, k3s, compose — conforme.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
