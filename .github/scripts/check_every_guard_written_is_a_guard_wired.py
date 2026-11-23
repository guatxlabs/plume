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
# CITÉE N'EST PAS EXÉCUTÉE. Une version antérieure tenait pour câblée toute garde citée n'importe où dans
# un flux : le `echo "::error::check_x.py : …"` de la ligne d'agrégat suffisait, et retirer le pas qui
# exécute la garde restait vert (mesuré : `run:` de deux gardes remplacé par `run: true`, code 0). Une garde
# est désormais câblée si une ligne NON COMMENTÉE l'appelle par l'interpréteur, sous son chemin
# `.github/scripts/` (relatif, `./`, ou `$GITHUB_WORKSPACE/`, entre guillemets ou non). Les CITATIONS
# servent encore à détecter une garde citée qui n'existe pas.
EXECUTE = re.compile(
    r"\bpython3?\s+(?:-\S+\s+)*[\"']?(?:\$\{?GITHUB_WORKSPACE\}?/|\./)?\.github/scripts/(check_[a-z0-9_]+\.py)\b"
)


def gardes_sur_le_disque(rep):
    try:
        return sorted(f for f in os.listdir(rep) if NOM.match(f))
    except OSError:
        return None


def gardes_executees_dans(texte):
    """Les gardes qu'une ligne non commentée du flux exécute."""
    executees = set()
    for ligne in texte.splitlines():
        # Un commentaire, en tête de ligne ou après un blanc (`run: true  # python3 …`), n'exécute rien.
        executees.update(EXECUTE.findall(re.split(r"(?:^|\s)#", ligne, maxsplit=1)[0]))
    return executees


def gardes_citees(rep_flux):
    """(gardes citées, gardes exécutées) par n'importe quel flux de travail, avec le fichier qui les porte."""
    citees, executees = {}, {}
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
        for m in gardes_executees_dans(texte):
            executees.setdefault(m, set()).add(f)
    return citees, executees


def apparier(disque, executees, citees):
    """(orphelines : sur le disque sans être exécutées, fantômes : citées sans exister). Pur."""
    orphelines = [g for g in disque if g not in executees]
    fantomes = sorted(g for g in citees if g not in disque)
    return orphelines, fantomes


def epreuves():
    """Témoins positifs ET négatifs sur l'appariement, hors du disque."""
    cas = [
        ("toutes câblées", ["check_a.py", "check_b.py"], {"check_a.py": {"ci.yml"}, "check_b.py": {"ci.yml"}}, None, 0, 0),
        ("une non câblée", ["check_a.py", "check_b.py"], {"check_a.py": {"ci.yml"}}, None, 1, 0),
        ("une citée qui n'existe pas", ["check_a.py"], {"check_a.py": {"ci.yml"}, "check_z.py": {"ci.yml"}}, None, 0, 1),
        ("aucune citée", ["check_a.py"], {}, None, 1, 0),
        ("citée par un autre flux", ["check_a.py"], {"check_a.py": {"agent-ci.yml"}}, None, 0, 0),
        ("citée mais jamais exécutée", ["check_a.py"], {}, {"check_a.py": {"ci.yml"}}, 1, 0),
    ]
    for nom, disque, executees, citees, att_orphelines, att_fantomes in cas:
        orph, fant = apparier(disque, executees, executees if citees is None else citees)
        if len(orph) != att_orphelines or len(fant) != att_fantomes:
            return f"témoin « {nom} » : {len(orph)} orpheline(s) / {len(fant)} fantôme(s), attendu {att_orphelines} / {att_fantomes}"
    if NOM.match("check_.py") or NOM.match("checker_a.py") or not NOM.match("check_a_b.py"):
        return "témoin de nom : le motif de nom de garde ne discrimine pas"
    flux = (
        "      - id: garde_1\n"
        "        run: python3 .github/scripts/check_a.py\n"
        "      - run: python3 \"$GITHUB_WORKSPACE/.github/scripts/check_b.py\" --x\n"
        "      - run: true\n"
        "      # python3 .github/scripts/check_c.py\n"
        "          echo \"::error::check_d.py : $o\"\n"
        "      - run: python3 ./.github/scripts/check_e.py\n"
        "      - run: true  # python3 .github/scripts/check_f.py\n"
        "      - run: wc -l .github/scripts/check_g.py\n"
    )
    vues = gardes_executees_dans(flux)
    if vues != {"check_a.py", "check_b.py", "check_e.py"}:
        return (f"témoin d'exécution : {sorted(vues)} vues exécutées, attendu check_a, check_b, check_e "
                "(une ligne commentée, un `echo` d'agrégat ou une simple lecture du fichier ne câble pas une garde)")
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
    lues = gardes_citees(FLUX)
    if lues is None:
        print("::error::flux de travail illisibles : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2
    citees, executees = lues

    orphelines, fantomes = apparier(disque, executees, citees)

    for g in orphelines:
        print(f"::error file=.github/scripts/{g}::cette garde existe mais aucun flux de travail ne "
              "l'exécute (une citation en commentaire ou dans un `echo` ne l'exécute pas) — son verdict ne refuse rien",
              file=sys.stderr)
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
          "CE QU'ELLE NE TIENT PAS : une ligne d'appel placée dans une chaîne (`echo \"python3 …\"`) compte "
          "comme un appel ; qu'un pas soit atteint (un `if:` peut le sauter, un job peut être "
          "conditionné), que le flux qui l'exécute se déclenche sur les événements utiles, qu'un échec "
          "soit BLOQUANT (`continue-on-error` n'est pas lu ici), ni que la garde tienne ce qu'elle "
          "annonce — cela se juge ailleurs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
