#!/usr/bin/env python3
"""Prendre le jeton de travail lourd ne rend jamais muet le shell qui l'a pris — garde de CI.

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`sonde_jeton_prendre` (`.github/scripts/sonde-construction-ou-suite-en-cours.sh`) ouvrait le jeton par
`exec {fd}>"$jeton" 2>/dev/null`. Un `exec` sans commande applique TOUTES ses redirections au shell
courant, et pour toujours : le `2>/dev/null` restait posé sur le shell qui avait sourcé la sonde. Les
trois appelants (`verifier-le-binaire-de-production-compile.sh`, `compter-les-tests.sh`,
`jouer-la-batterie-de-gardes.sh`) perdaient leur sortie d'erreur à partir de la prise du jeton : un échec
ultérieur sortait rouge SANS TEXTE, et le refus « un autre travail lourd a pris le jeton » se taisait
lui aussi. Rien ne le voyait : chaque appelant rendait toujours le bon code.

CE QUI EST JUGÉ
---------------
La sonde du dépôt est SOURCÉE par `bash` dans un processus à part, avec un `TMPDIR` privé et un jeton
JETABLE (jamais le vrai jeton du dépôt). Trois cas :
  - jeton libre : `sonde_jeton_prendre` rend 0, le descripteur est posé, le verrou est TENU (un second
    `flock -n` sur le fichier échoue), et une ligne écrite ENSUITE sur la sortie d'erreur arrive ;
  - jeton tenu par un autre (cette garde le tient) : code 1, et la sortie d'erreur arrive ;
  - jeton impossible à ouvrir (répertoire absent) : code 2, et la sortie d'erreur arrive.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
--------------------------------------------------
Les mêmes cas sont joués d'abord sur deux sondes fabriquées : l'une porte la forme fautive (elle doit
être vue rouge dans les cas 1 et 2), l'autre une forme juste (elle doit être vue verte partout). Une
lecture qui ne rend pas le verdict attendu fait refuser la garde.

CODES DE SORTIE
---------------
`0` la sonde du dépôt tient les trois cas ; `1` un cas est faux ; `2` rien de probant (`bash` ou
`flock` absent, sonde introuvable, instrument faux).

CE QU'ELLE NE TIENT PAS
-----------------------
Elle ne juge que `sonde_jeton_prendre`. Un autre `exec` sans commande, ailleurs, qui redirige la sortie
d'erreur du shell courant, n'est pas vu ici.
"""
import fcntl
import os
import shutil
import subprocess
import sys
import tempfile

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
SONDE = os.path.join(RACINE, ".github", "scripts", "sonde-construction-ou-suite-en-cours.sh")
ETIQUETTE = "[jeton-et-sortie-d-erreur]"
MARQUE = "marque-ecrite-apres-la-prise-du-jeton"

# Le scénario : source la sonde, désigne le jeton jetable, prend le jeton, rend le code, le descripteur
# et l'état du verrou sur la sortie standard, puis écrit la MARQUE sur la sortie d'erreur.
SCENARIO = r'''
source "$1" || exit 90
sonde_jeton="$2"
sonde_jeton_prendre essai; rc=$?
etat=sans-objet
if [ "$rc" = 0 ]; then
    if flock -n "$sonde_jeton" true 2>/dev/null; then etat=libre; else etat=tenu; fi
fi
printf 'rc=%s fd=%s verrou=%s\n' "$rc" "${_sonde_jeton_fd:-}" "$etat"
printf '%s\n' "$3" >&2
'''

# Sondes fabriquées pour éprouver la lecture : la forme fautive, et une forme juste.
FABRIQUEE = r'''
sonde_jeton_a_moi=0
_sonde_jeton_fd=
sonde_jeton_prendre() {
    [ "$sonde_jeton_a_moi" -eq 0 ] || return 0
    OUVERTURE || return 2
    if ! flock -n "$_sonde_jeton_fd" 2>/dev/null; then
        exec {_sonde_jeton_fd}>&-
        _sonde_jeton_fd=
        return 1
    fi
    sonde_jeton_a_moi=1
    return 0
}
'''
FAUTIVE = 'exec {_sonde_jeton_fd}>"$sonde_jeton" 2>/dev/null'
JUSTE = '{ exec {_sonde_jeton_fd}>"$sonde_jeton"; } 2>/dev/null'


def jouer(sonde, jeton, tmp):
    """(code bash, sortie standard, sortie d'erreur) du scénario sur `sonde` et `jeton`."""
    env = dict(os.environ, TMPDIR=tmp, LC_ALL="C")
    p = subprocess.run(
        ["bash", "-c", SCENARIO, "scenario", sonde, jeton, MARQUE],
        cwd=RACINE, env=env, capture_output=True, text=True, timeout=60,
    )
    return p.returncode, p.stdout, p.stderr


def lire(stdout):
    """Le dictionnaire `rc`/`fd`/`verrou` de la dernière ligne de la sortie standard, ou None."""
    lignes = [l for l in stdout.splitlines() if l.startswith("rc=")]
    if not lignes:
        return None
    return dict(c.split("=", 1) for c in lignes[-1].split())


def juger(sonde, tmp):
    """La liste des fautes de `sonde` sur les trois cas ; une liste vide si elle les tient tous."""
    fautes = []

    # 1. Jeton libre.
    jeton = os.path.join(tmp, "jeton-libre")
    code, out, err = jouer(sonde, jeton, tmp)
    vu = lire(out)
    if code != 0 or vu is None:
        fautes.append(f"jeton libre : le scénario n'a pas abouti (code {code}) : {err.strip()[-200:]}")
    else:
        if vu.get("rc") != "0":
            fautes.append(f"jeton libre : code {vu.get('rc')}, attendu 0")
        if not vu.get("fd"):
            fautes.append("jeton libre : le descripteur du jeton n'est pas posé")
        if vu.get("verrou") != "tenu":
            fautes.append(f"jeton libre : après la prise, le verrou est vu {vu.get('verrou')}, attendu tenu")
        if MARQUE not in err:
            fautes.append("jeton libre : une ligne écrite sur la sortie d'erreur APRÈS la prise est PERDUE")

    # 2. Jeton tenu par un autre : cette garde le tient pendant le scénario.
    jeton = os.path.join(tmp, "jeton-tenu")
    with open(jeton, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        code, out, err = jouer(sonde, jeton, tmp)
    vu = lire(out)
    if code != 0 or vu is None:
        fautes.append(f"jeton tenu : le scénario n'a pas abouti (code {code}) : {err.strip()[-200:]}")
    else:
        if vu.get("rc") != "1":
            fautes.append(f"jeton tenu par un autre : code {vu.get('rc')}, attendu 1")
        if MARQUE not in err:
            fautes.append("jeton tenu par un autre : la sortie d'erreur est PERDUE après le refus")

    # 3. Jeton impossible à ouvrir : son répertoire n'existe pas.
    jeton = os.path.join(tmp, "repertoire-absent", "jeton")
    code, out, err = jouer(sonde, jeton, tmp)
    vu = lire(out)
    if code != 0 or vu is None:
        fautes.append(f"jeton inouvrable : le scénario n'a pas abouti (code {code}) : {err.strip()[-200:]}")
    else:
        if vu.get("rc") != "2":
            fautes.append(f"jeton impossible à ouvrir : code {vu.get('rc')}, attendu 2")
        if MARQUE not in err:
            fautes.append("jeton impossible à ouvrir : la sortie d'erreur est PERDUE")
    return fautes


def epreuve_de_l_instrument(tmp):
    """None si la lecture voit la forme fautive rouge et la forme juste verte ; sinon le motif."""
    for nom, ouverture, attendu_rouge in (("fautive", FAUTIVE, True), ("juste", JUSTE, False)):
        chemin = os.path.join(tmp, f"sonde-{nom}.sh")
        with open(chemin, "w", encoding="utf-8") as f:
            f.write(FABRIQUEE.replace("OUVERTURE", ouverture))
        d = tempfile.mkdtemp(prefix=f"epreuve-{nom}.", dir=tmp)
        fautes = juger(chemin, d)
        if attendu_rouge:
            perdues = [x for x in fautes if "PERDUE" in x]
            if len(perdues) != 2:
                return f"la sonde fabriquée FAUTIVE n'est pas vue rouge dans les cas 1 et 2 : {fautes}"
        elif fautes:
            return f"la sonde fabriquée JUSTE est vue rouge : {fautes}"
    return None


def main():
    for outil in ("bash", "flock"):
        if shutil.which(outil) is None:
            print(f"{ETIQUETTE} REFUS DE CONCLURE : « {outil} » est absent, rien n'a été joué.")
            return 2
    if not os.path.isfile(SONDE):
        print(f"{ETIQUETTE} REFUS DE CONCLURE : la sonde est introuvable ({SONDE}).")
        return 2
    tmp = tempfile.mkdtemp(prefix="garde-jeton.")
    try:
        motif = epreuve_de_l_instrument(tmp)
        if motif:
            print(f"{ETIQUETTE} REFUS DE CONCLURE : instrument faux — {motif}")
            return 2
        d = tempfile.mkdtemp(prefix="sonde-du-depot.", dir=tmp)
        fautes = juger(SONDE, d)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if fautes:
        print(f"{ETIQUETTE} ÉCHEC : `sonde_jeton_prendre` rend muet ou trompe le shell qui la source :")
        for x in fautes:
            print(f"  - {x}")
        return 1
    print(f"{ETIQUETTE} OK : jeton libre, tenu ou impossible à ouvrir, le shell appelant garde sa sortie "
          "d'erreur, et le verrou est tenu après la prise.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
