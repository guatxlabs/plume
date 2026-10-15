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
AF_INET6 à sept capteurs du central sans usage du réseau : le central le pose sans sa ligne
`RestrictAddressFamilies=`.
(d) `/etc/plume/plume.conf` (le jeton de l'agent) était 0640 root:soc alors qu'aucun processus lancé
sous `soc` ne le lit — et `responder.conf`, qui recopie le même jeton, aussi. Une conf déjà posée était
gardée en silence, commentaires de fin de valeur compris. README.md prescrivait encore `chgrp soc` sur
plume.conf ; deploy/SYSLOG.md présentait comme conf par défaut l'écoute 0.0.0.0, les commentaires en fin
de valeur et « vider = désactiver », faux (une valeur vide rend le défaut du récepteur, 0.0.0.0:514). (e) `systemd/plume-pod-logs.service` forçait une liste de pods d'un parc
particulier et un seuil de sévérité que ni le script ni la sonde ne disent. (h) La conf syslog
engendrée écrivait ses commentaires EN FIN DE VALEUR — systemd les garde dans la valeur, si bien que
la liste d'autorisation valait `# ex: …` (le récepteur s'arrête) — et écoutait 0.0.0.0 avec une liste
vide. La même faute de commentaire rendait `PLUME_RESPONDER_APPLY=1   # …` différent de `1`.
k3s. (f) Ingress sans TLS et servi aussi en HTTP, pas de profil seccomp, jeton de compte de service
monté sans usage, entrée réseau ouverte depuis tout namespace.
Docker. (g) Aucun `cap_drop`, et PLUME_TLS_CERT/PLUME_TLS_KEY jamais transmis au conteneur.

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
    ou par `install_collector` a son drop-in, identique à `systemd/plume-collector-common.conf`,
    posé avant le premier `systemctl daemon-reload` ;
  · sur le central, aucune unité de capteur ne reçoit du drop-in une famille d'adresses qu'elle ne
    déclare pas, et chacune déclare la sienne (sur l'agent, l'union est antérieure : NON jugée) ;
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
    ainsi qu'une écoute syslog hors boucle locale à liste vide ; la conf syslog posée est l'ANCIENNE
    CONF ENGENDRÉE octet pour octet (`PLUME_SYSLOG_ALLOW=          # ex: …`, valeur qui COMMENCE par
    `#`). Les trois fonctions de signalement livrées sont aussi jouées seules sur treize confs syslog :
    adresse absente ou vide = 0.0.0.0:514 (UDP, TCP, chacune seule), liste `""` ou `''` = vide, ligne
    `;` = commentaire, et les témoins négatifs (liste posée, nue ou entre guillemets ; boucle locale).
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
    `no-new-privileges:true`, PLUME_TLS_CERT et PLUME_TLS_KEY transmis depuis `.env` ;
  · la documentation suit — consigne affichée par bootstrap-agent.sh comprise (`sudo chmod 0600`, en
    en-tête ET au 1er passage sans secret) : aucun `chgrp soc`/`chmod 0640` prescrit sur plume.conf ou responder.conf,
    et la conf syslog de deploy/SYSLOG.md, lue selon systemd, est celle de l'installeur (127.0.0.1,
    liste vide, aucun commentaire dans une valeur, pas de « vider = désactiver »).
CE QU'ELLE NE TIENT PAS : l'union des familles d'adresses sur l'AGENT (une trentaine d'unités, à
mesurer capteur par capteur sous systemd avant de la resserrer).
Ses propres instruments sont éprouvés à chaque exécution : le lecteur systemd sur des lignes connues,
le juge d'ordre sur un journal où `lib.sh` arrive trop tard, le réacheminement sur l'absence de toute
racine non réacheminée.

Codes de sortie : 0 conforme · 1 propriété violée · 2 l'instrument REFUSE DE CONCLURE.
Aucun awk n'est exécuté par les installeurs jugés ici : la garde n'a pas à se jouer sous gawk et mawk.
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


class Bac:
    def __init__(self, nom, outils_audit=()):
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
            self._outil("augenrules", FAUX_JOURNALISANT.replace("{nom}", "augenrules").replace("{suite}", ""))
        if "auditctl" in outils_audit:
            self._outil("auditctl", FAUX_JOURNALISANT.replace("{nom}", "auditctl")
                        .replace("{suite}", "echo '-w /usr/bin/x -p x -k svc_exec'"))

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
               "TMPDIR": self.d}
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
            faute(f"{nom} : le drop-in de `{n}` n'est pas celui attendu (systemd/plume-collector-common.conf"
                  f"{', sans RestrictAddressFamilies=' if commun != COMMUN_ENTIER[0] else ''})")
        if rang.get(d, 10 ** 9) > reload:
            faute(f"{nom} : le drop-in de `{n}` est posé APRÈS le premier daemon-reload")
    if unites == 0:
        faute(f"{nom} : aucune unité de capteur vue — le juge du drop-in ne mesure rien")


COMMUN_ENTIER = [None]


def sans_familles(commun):
    return "".join(l for l in commun.splitlines(keepends=True) if not l.startswith("RestrictAddressFamilies="))


def familles(texte):
    out = set()
    for m in re.finditer(r"^RestrictAddressFamilies=(.*)$", texte, re.M):
        v = m.group(1).split()
        if not v:
            out = set()   # une affectation vide REMET la liste à zéro (systemd)
        out |= set(v)
    return out


def juger_familles_central(bac, nom):
    """Central : aucune unité de capteur ne reçoit du drop-in une famille qu'elle ne déclare pas."""
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
            faute(f"{nom} : `{n}` ne déclare aucune RestrictAddressFamilies= : sans la ligne du drop-in, "
                  f"elle n'aurait AUCUNE restriction de familles d'adresses")
            continue
        ajout = familles(lire(d)) - propres
        if ajout:
            faute(f"{nom} : le drop-in donne à `{n}` des familles qu'elle ne déclare pas : {sorted(ajout)}")
    if vues == 0:
        faute(f"{nom} : aucune unité à drop-in vue — le juge des familles ne mesure rien")


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
            juger_dropins(bac, nom, sans_familles(commun))
            juger_familles_central(bac, nom)
            regles = os.path.isfile(bac.r("/etc/audit/rules.d/plume.rules"))
            active = any(g[0] == "systemctl" and re.match(r"enable\b", g[1]) and "plume-auditd.timer" in g[1]
                         for g in gestes)
            # Le timer reste activé SANS auditd : c'est lui qui porte au SOC l'aveu `missing-source` du
            # capteur. L'éteindre ferait d'une absence NOMMÉE un silence — la garde le refuse aussi.
            if not active:
                faute(f"{nom} : plume-auditd.timer non activé — l'aveu « source absente » n'atteindrait plus le SOC")
            if auditd and not regles:
                faute(f"{nom} : auditd présent et règles NON posées — le témoin positif ne tient pas")
            if not auditd:
                if regles:
                    faute(f"{nom} : règles d'audit posées alors que l'installeur n'a pas les deux outils")
                if "auditd ABSENT" not in bac.sortie:
                    faute(f"{nom} : l'installeur ne dit pas que auditd est absent")
            juger_confs_engendrees(bac, nom, env_files)
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
            juger_jeton(bac, nom, "/etc/plume/plume.conf", creee=True)
    finally:
        bac.nettoyer()
    # 2) re-passage sur des confs 0640 existantes, écrites par une version qui commentait en fin de valeur :
    #    a) la conf syslog est l'ANCIENNE CONF ENGENDRÉE, octet pour octet — le cas qui motive le lot :
    #       `PLUME_SYSLOG_ALLOW=          # ex: …` vaut pour systemd une valeur qui COMMENCE par `#` ;
    #       un jeton porte aussi un commentaire, et sa valeur ne doit JAMAIS sortir ;
    #    b) une conf syslog sans adresse et à liste vide : le récepteur écoute alors 0.0.0.0:514 deux fois.
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
    }, set(), ["0.0.0.0:514", "0.0.0.0:514"])
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
        for marque in ("COMMENTAIRE DANS UNE VALEUR", "SYSLOG OUVERT SANS LISTE"):
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
OUVERT = re.compile(r"SYSLOG OUVERT SANS LISTE : (\S+) ecoute(.*?) avec PLUME_SYSLOG_ALLOW vide")
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
        faute(f"{nom} : {conf_syslog} signalée « SYSLOG OUVERT SANS LISTE » ({ouverts[0]}) à tort")
    elif ouvert_attendu is not None and ouverts != [ouvert_attendu]:
        faute(f"{nom} : {conf_syslog} écoute {' '.join(ouvert_attendu)} à liste vide (adresse absente ou vide = "
              f"0.0.0.0:514) ; l'installeur dit {ouverts or 'rien'}")


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
                                      ["0.0.0.0:514", "0.0.0.0:514"]),
    "transports-vides-liste-vide": ("PLUME_SYSLOG_UDP=\nPLUME_SYSLOG_TCP=\nPLUME_SYSLOG_ALLOW=\n", set(),
                                    ["0.0.0.0:514", "0.0.0.0:514"]),
    "tcp-absent": ("PLUME_SYSLOG_UDP=127.0.0.1:514\nPLUME_SYSLOG_ALLOW=\n", set(), ["0.0.0.0:514"]),
    "udp-absent": ("PLUME_SYSLOG_TCP=127.0.0.1:514\nPLUME_SYSLOG_ALLOW=\n", set(), ["0.0.0.0:514"]),
    "udp-vide": ("PLUME_SYSLOG_UDP=\nPLUME_SYSLOG_TCP=127.0.0.1:514\nPLUME_SYSLOG_ALLOW=\n", set(), ["0.0.0.0:514"]),
    "tcp-vide": ("PLUME_SYSLOG_UDP=127.0.0.1:514\nPLUME_SYSLOG_TCP=\nPLUME_SYSLOG_ALLOW=\n", set(), ["0.0.0.0:514"]),
    "liste-entre-guillemets-doubles": ("PLUME_SYSLOG_UDP=127.0.0.1:514\nPLUME_SYSLOG_TCP=0.0.0.0:514\n"
                                       "PLUME_SYSLOG_ALLOW=\"\"\n", set(), ["0.0.0.0:514"]),
    "liste-entre-guillemets-simples": ("PLUME_SYSLOG_UDP=0.0.0.0:514\nPLUME_SYSLOG_TCP=127.0.0.1:514\n"
                                       "PLUME_SYSLOG_ALLOW=''\n", set(), ["0.0.0.0:514"]),
    "ligne-point-virgule": ("; PLUME_SYSLOG_PARSER=auto   # ancien essai\nPLUME_SYSLOG_UDP=127.0.0.1:514\n"
                            "PLUME_SYSLOG_TCP=127.0.0.1:514\nPLUME_SYSLOG_ALLOW=\n", set(), None),
    # témoins négatifs : une liste non vide (nue ou entre guillemets) fait taire le signalement
    "liste-posee": ("PLUME_SYSLOG_UDP=0.0.0.0:514\nPLUME_SYSLOG_ALLOW=203.0.113.10/32\n", set(), None),
    "liste-posee-entre-guillemets": ("PLUME_SYSLOG_TCP=0.0.0.0:514\nPLUME_SYSLOG_ALLOW=\"203.0.113.10/32\"\n",
                                     set(), None),
    "boucle-locale": ("PLUME_SYSLOG_UDP=127.0.0.1:514\nPLUME_SYSLOG_TCP=127.0.0.1:514\nPLUME_SYSLOG_ALLOW=\n",
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
    for cle in ("PLUME_TLS_CERT", "PLUME_TLS_KEY"):
        if not re.fullmatch(r"\$\{" + cle + r"(:?-[^}]*)?\}", str(env.get(cle, ""))):
            faute(f"docker-compose.yml : {cle} n'est pas transmis depuis `.env` au conteneur ({env.get(cle)!r})")


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
    if re.search(r"vider[^\n]{0,30}=\s*d[ée]sactiver", texte, re.I):
        faute("deploy/SYSLOG.md dit encore « vider = désactiver » : une valeur vide rend le défaut du récepteur, 0.0.0.0:514")


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
    COMMUN_ENTIER[0] = commun
    env_files = fichiers_environnement()
    if not refus:
        scenario_central(commun, env_files)
        scenario_agent(commun, env_files)
        juger_fonctions_de_signalement()
    lecteurs_soc_de_plume_conf()
    juger_pod_logs()
    juger_docs()
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
