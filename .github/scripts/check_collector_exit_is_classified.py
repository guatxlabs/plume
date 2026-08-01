#!/usr/bin/env python3
"""Un capteur qui ne peut pas collecter doit le DIRE — garde de CI.

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Mesuré le 2026-08-01 sur une VM Ubuntu 24.04 Server fraîche (2 vCPU / 2 Gio, image cloud
officielle) : `collectors/auditd.sh` faisait `[ -r "$LOG" ] || exit 0`. auditd n'étant PAS
installé sur une Ubuntu Server, le fichier n'existe pas, et le capteur sortait en SUCCÈS sans
rien émettre. Vu du SOC, RIEN ne distingue « ce capteur ne PEUT PAS fonctionner » de « il ne
s'est rien passé ». Le silence est indiscernable du calme, et c'est le pire des deux mondes :
l'opérateur croit être couvert.

CE N'EST PAS UNE LISTE DE CAPTEURS — c'est une PARTITION FERMÉE
---------------------------------------------------------------
Énumérer les capteurs fautifs corrigerait le passé et raterait le prochain. On raisonne donc sur
la seule chose qui soit close : les RAISONS de s'arrêter tôt. Il y en a exactement trois —
(I) incapacité (un prérequis manque), (II) désactivé (interrupteur opérateur), (III) rien de neuf.
Seuls (I) et (II) sont des mensonges quand ils sont muets ; (III) est un silence honnête.
`collectors/lib.sh` porte une fonction par cas — `plume_unavailable`, `plume_disabled`,
`plume_exit_nodata` — et CHACUNE porte son propre `exit`.

D'où la règle, qui est la contraposée : **si toute sortie anticipée légitime passe par l'une des
trois fonctions, alors un `exit 0` NU dans un capteur est nécessairement une sortie NON CLASSÉE.**
Cette garde interdit donc le `exit 0` nu. Un capteur écrit demain est couvert par CONSTRUCTION :
son auteur ne peut pas sortir sans choisir un cas, et le mauvais défaut — le silence — n'est plus
une chose que la CI laisse passer.

POURQUOI SEULEMENT `exit 0`
---------------------------
Un `exit` non-nul est déjà BRUYANT : systemd marque l'unit `failed`, et c'est visible. Le défaut
traité ici est précisément la sortie en SUCCÈS alors que la collecte est impossible.

PÉRIMÈTRE, ET POURQUOI L'EXCLUSION NE PEUT PAS POURRIR
-------------------------------------------------------
La partition porte sur les CAPTEURS. `respond.sh` et `engagement-adapter.sh` sont des ENFORCERS
(ils appliquent des actions décidées ailleurs ; ils ne collectent pas) : mesuré, ils ne sourcent
pas `lib.sh`. Cette exclusion est AUTO-INVALIDANTE : la garde VÉRIFIE qu'ils ne le sourcent
toujours pas. Le jour où l'un d'eux devient un capteur (donc source `lib.sh`), son exclusion
tombe d'elle-même et il repasse sous la règle. Une exclusion qu'on ne peut pas oublier de retirer.
"""
import re
import subprocess
import sys

# Fonctions de lib.sh qui PORTENT un exit — la partition fermée, une fonction par cas.
PRIMITIVES = ("plume_unavailable", "plume_disabled", "plume_exit_nodata")

# Vocabulaire FERMÉ de `reason`. Il existe pour que l'incapacité soit REQUÊTABLE
# (`search category=config reason=missing-dependency`) plutôt que de la prose libre qui dérive.
REASONS = {
    "missing-dependency",   # un binaire requis est absent
    "missing-source",       # le fichier/répertoire à lire est absent ou illisible
    "missing-config",       # un réglage/identifiant obligatoire n'est pas posé
    "subsystem-absent",     # le sous-système est là mais l'objet nécessaire n'y est pas
    "unreachable",          # l'endpoint distant n'a pas répondu / a répondu une erreur
    "disabled",             # coupé par un interrupteur opérateur (posé par plume_disabled)
}

# ENFORCERS, pas capteurs. Le critère est OBJECTIF et re-vérifié plus bas, pas déclaratif.
ENFORCERS = ("collectors/respond.sh", "collectors/engagement-adapter.sh")

# lib.sh DÉFINIT les trois primitives : c'est le seul fichier où un `exit` nu est le sujet.
LIB = "collectors/lib.sh"

# PLANCHER, pas un compte exact : ajouter un capteur est une opération de routine et ne doit pas
# obliger à toucher ce fichier. Le plancher ferme le seul mode de panne réel de l'énumération —
# un glob cassé qui ne scanne RIEN et rapporte un vert joyeux.
# MESURÉ le 2026-08-01 : `git ls-files 'collectors/*.sh'` = 40 fichiers, moins lib.sh et les
# 2 enforcers = 37 capteurs. (Le premier jet de cette garde portait un 38 SUPPOSÉ ; elle a échoué
# sur son propre chiffre non mesuré, ce qui est exactement ce qu'on lui demande de faire.)
MIN_COLLECTORS = 37


def strip_comment(line: str) -> str:
    """Retire le commentaire `#` en respectant les quotes (un `#` dans "..." n'en ouvre pas un)."""
    out, quote, i = [], None, 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\" and quote == '"':
                out.append(c)
                i += 1
                if i < len(line):
                    out.append(line[i])
                i += 1
                continue
            if c == quote:
                quote = None
            out.append(c)
        elif c in "'\"":
            quote = c
            out.append(c)
        elif c == "#" and (not out or out[-1].isspace()):
            break
        else:
            out.append(c)
        i += 1
    return "".join(out)


def function_body(src: str, name: str):
    """Corps de `name() { ... }` par APPARIEMENT D'ACCOLADES. Renvoie None si introuvable.

    Un premier jet utilisait une regex attendant un `}` en début de ligne. Elle ne matchait
    donc PAS une définition sur UNE ligne (`f() { exit 0; }`) et, `body` valant None, le test
    se contentait de NE RIEN VÉRIFIER : la mutation « la primitive ne termine plus le capteur »
    passait au VERT. Un contrôle qui, quand il ne sait pas, se tait — c'est précisément le
    défaut que ce fichier existe pour interdire. D'où : appariement d'accolades, et l'appelant
    ÉCHOUE quand le corps est introuvable au lieu de sauter le test.
    """
    m = re.search(rf"^{re.escape(name)}\(\)\s*\{{", src, re.M)
    if not m:
        return None
    depth, i = 0, m.end() - 1
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[m.end():i]
        i += 1
    return None


def main() -> int:
    tracked = subprocess.run(
        ["git", "ls-files", "collectors/*.sh"], capture_output=True, text=True, check=True
    ).stdout.split()
    errs, scanned = [], 0

    lib_src = open(LIB, encoding="utf-8").read()
    # Les trois primitives DOIVENT exister ET porter un `exit`, sinon la règle ci-dessous ne
    # prouve plus rien : un capteur « classé » poursuivrait son exécution au lieu de s'arrêter.
    for fn in PRIMITIVES:
        body = function_body(lib_src, fn)
        if body is None:
            errs.append(
                f"{LIB}: primitive `{fn}` introuvable (supprimée, renommée, ou forme non "
                f"reconnue). La partition n'est plus fermée — ce test refuse de conclure."
            )
        elif not re.search(r"(?<![\w-])exit\s+0\b", body):
            errs.append(f"{LIB}: `{fn}` ne porte plus `exit 0` — elle ne termine plus le capteur.")

    for path in tracked:
        if path == LIB:
            continue
        src = open(path, encoding="utf-8").read()
        if path in ENFORCERS:
            # Exclusion AUTO-INVALIDANTE : elle ne tient que tant que le critère tient.
            if re.search(r"PLUME_LIB|/lib\.sh", src):
                errs.append(
                    f"{path}: source désormais lib.sh — ce n'est plus un enforcer mais un capteur. "
                    f"Retirez-le de ENFORCERS ici et classez ses sorties."
                )
            continue
        scanned += 1
        # COUPLAGE : appeler une primitive sans avoir sourcé lib.sh donne « command not found »
        # (rc=127) et fait ÉCHOUER l'unit systemd — on remplacerait un capteur muet par un capteur
        # cassé. Attrapé en vrai pendant la remédiation : `prom-scrape.sh` n'était pas lib-based, la
        # réécriture mécanique y avait posé un `plume_exit_nodata` qui ne pouvait pas exister.
        if re.search(r"\bplume_(unavailable|disabled|exit_nodata)\b", src) and not re.search(
            r"PLUME_LIB|/lib\.sh", src
        ):
            errs.append(
                f"{path}: appelle une primitive de sortie classée SANS sourcer lib.sh — la fonction "
                f"n'existe pas à l'exécution (rc=127, unit systemd en échec). Ajoutez : "
                f'. "${{PLUME_LIB:-$(dirname "$0")/lib.sh}}"'
            )
        for i, line in enumerate(src.split("\n"), 1):
            code = strip_comment(line)
            if re.search(r"(?<![\w-])exit\s+0\b", code):
                errs.append(
                    f"{path}:{i}: `exit 0` NU dans un capteur — sortie NON CLASSÉE.\n"
                    f"      {line.strip()}\n"
                    f"      Un capteur qui s'arrête doit DIRE POURQUOI. Choisissez le cas :\n"
                    f"        prérequis absent .......... plume_unavailable <source> <reason> \"<détail>\"\n"
                    f"        coupé par l'opérateur ..... plume_disabled <source> \"<détail>\"\n"
                    f"        rien de neuf (silence OK) . plume_exit_nodata"
                )
            for m in re.finditer(r"plume_unavailable\s+\S+\s+(\S+)", code):
                if m.group(1) not in REASONS:
                    errs.append(
                        f"{path}:{i}: reason `{m.group(1)}` hors vocabulaire fermé "
                        f"({', '.join(sorted(REASONS))})."
                    )

    if scanned < MIN_COLLECTORS:
        errs.append(
            f"seulement {scanned} capteurs scannés, plancher {MIN_COLLECTORS} : soit la découverte "
            f"est cassée (cette garde ne vérifierait alors RIEN), soit des capteurs ont "
            f"légitimement disparu — dans ce cas baissez MIN_COLLECTORS depuis votre propre compte."
        )

    if errs:
        for e in errs:
            print(f"::error::{e}")
        print(f"\n{len(errs)} sortie(s) non classée(s) sur {scanned} capteurs.")
        return 1
    print(f"{scanned} capteurs : toute sortie anticipée est classée (incapacité / désactivé / rien de neuf).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
