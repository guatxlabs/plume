#!/usr/bin/env python3
"""Une garde écrite mais non câblée ne refuse rien, et son verdict se lit comme si elle tenait.

Le défaut a été mesuré le 2026-08-26 : deux gardes neuves vivaient dans `.github/scripts/` sans
qu'aucun pas de la CI ne les exécute. Elles rendaient pourtant un verdict — « OK, N ensembles
déclarés » — que leurs auteurs et leurs relecteurs ont lu comme une garantie. Le mécanisme qu'elles
gardaient pouvait être retiré le lendemain sans qu'aucun vert ne bouge.

Le corpus est le RÉPERTOIRE, pas l'index du dépôt : une garde neuve existe sur le disque avant d'être
suivie, et c'est précisément à ce moment-là qu'on oublie de la câbler. La lire depuis l'index la
rendrait invisible tant qu'elle n'est pas commitée — verte en local, rouge en intégration, ce qui est
le piège inverse.
"""
import os, re, sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
FLUX = os.path.join(RACINE, ".github", "workflows")
NOM = re.compile(r"^check_[a-z0-9_]+\.py$")
CITE = re.compile(r"\b(check_[a-z0-9_]+\.py)\b")


def gardes_sur_le_disque(rep):
    try:
        return sorted(f for f in os.listdir(rep) if NOM.match(f))
    except OSError:
        return None


def gardes_citees(rep_flux):
    """Toute garde citée par n'importe quel flux de travail, avec le fichier qui la cite."""
    citees = {}
    try:
        fichiers = sorted(f for f in os.listdir(rep_flux) if f.endswith((".yml", ".yaml")))
    except OSError:
        return None
    if not fichiers:
        return None
    for f in fichiers:
        try:
            texte = open(os.path.join(rep_flux, f), encoding="utf-8").read()
        except OSError:
            return None
        for m in CITE.findall(texte):
            citees.setdefault(m, set()).add(f)
    return citees


def epreuves():
    """Témoins positifs ET négatifs sur l'appariement, hors du disque."""
    cas = [
        ("toutes câblées", ["check_a.py", "check_b.py"], {"check_a.py": {"ci.yml"}, "check_b.py": {"ci.yml"}}, 0, 0),
        ("une non câblée", ["check_a.py", "check_b.py"], {"check_a.py": {"ci.yml"}}, 1, 0),
        ("une citée qui n'existe pas", ["check_a.py"], {"check_a.py": {"ci.yml"}, "check_z.py": {"ci.yml"}}, 0, 1),
        ("aucune citée", ["check_a.py"], {}, 1, 0),
        ("citée par un autre flux", ["check_a.py"], {"check_a.py": {"agent-ci.yml"}}, 0, 0),
    ]
    for nom, disque, citees, att_orphelines, att_fantomes in cas:
        orph = [g for g in disque if g not in citees]
        fant = [g for g in citees if g not in disque]
        if len(orph) != att_orphelines or len(fant) != att_fantomes:
            return f"témoin « {nom} » : {len(orph)} orpheline(s) / {len(fant)} fantôme(s), attendu {att_orphelines} / {att_fantomes}"
    if NOM.match("check_.py") or NOM.match("checker_a.py") or not NOM.match("check_a_b.py"):
        return "témoin de nom : le motif de nom de garde ne discrimine pas"
    return None


def main():
    faute = epreuves()
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return 2

    disque = gardes_sur_le_disque(ICI)
    if not disque:
        print("::error::aucune garde lisible dans .github/scripts : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2
    citees = gardes_citees(FLUX)
    if citees is None:
        print("::error::flux de travail illisibles : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2

    orphelines = [g for g in disque if g not in citees]
    fantomes = sorted(g for g in citees if g not in disque)

    for g in orphelines:
        print(f"::error file=.github/scripts/{g}::cette garde existe mais aucun flux de travail ne "
              "l'exécute — son verdict ne refuse rien", file=sys.stderr)
    for g in fantomes:
        ou = ", ".join(sorted(citees[g]))
        print(f"::error file=.github/workflows/{sorted(citees[g])[0]}::`{g}` est citée ({ou}) mais "
              "n'existe pas dans .github/scripts", file=sys.stderr)

    if orphelines or fantomes:
        print(f"\n{len(orphelines)} garde(s) écrite(s) sans être câblée(s), {len(fantomes)} citée(s) "
              "sans exister. Une garde qui ne s'exécute pas ne refuse rien, et son verdict se lit "
              "pourtant comme une garantie : le mécanisme qu'elle protège peut disparaître sans "
              "qu'aucun vert ne bouge.", file=sys.stderr)
        return 1

    print(f"check_every_guard_written_is_a_guard_wired : {len(disque)} garde(s) dans .github/scripts, "
          f"chacune exécutée par au moins un des flux de travail, et aucun flux ne cite une garde "
          "absente. Le corpus est le RÉPERTOIRE et non l'index du dépôt : une garde neuve est vue dès "
          "qu'elle existe sur le disque, avant même d'être suivie.\n"
          "CE QU'ELLE NE TIENT PAS : qu'un pas soit atteint (un `if:` peut le sauter, un job peut être "
          "conditionné), que le flux qui l'exécute se déclenche sur les événements utiles, qu'un échec "
          "soit BLOQUANT (`continue-on-error` n'est pas lu ici), ni que la garde tienne ce qu'elle "
          "annonce — cela se juge ailleurs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
