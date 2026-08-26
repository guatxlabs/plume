#!/usr/bin/env python3
"""Une clé de feuille de route se lit sous le titre de sa phase, ou elle ne se lit pas.

La règle est DÉRIVÉE de la clé elle-même : `P<phase>.<chantier>-<constat>` doit se
trouver sous le titre `## P<phase> — …`. Aucune liste de phases n'est écrite ici ;
ajouter une phase P13 n'oblige à rien toucher.

Le défaut que cette garde attrape a été mesuré le 2026-08-26 : vingt clés sur deux
cent quatre-vingts vivaient sous le titre de la console, dont neuf d'une phase qui
n'avait PAS de section, parce qu'une clé neuve s'ajoute à la fin du document et que
la fin du document n'est pas la fin de sa phase.
"""
import re, subprocess, sys

TITRE = re.compile(r"^## +P(\d+) +— ")
AUTRE_TITRE = re.compile(r"^## +")
CLE = re.compile(r"^\| +\*\*P(\d+)\.(\d+)-([a-z])\*\*")
CODE = re.compile(r"^\s*(```|~~~)")


def sections_et_cles(texte):
    """Rend (clés_hors_section, nombre_total, phases_sans_section).

    Une clé citée dans un bloc de code est un ÉCHANTILLON, pas une entrée d'index.
    """
    phase = None
    dans_code = False
    hors, total, vues, titrees = [], 0, set(), set()
    for n, ligne in enumerate(texte.split("\n"), 1):
        if CODE.match(ligne):
            dans_code = not dans_code
            continue
        if dans_code:
            continue
        t = TITRE.match(ligne)
        if t:
            phase = t.group(1)
            titrees.add(phase)
            continue
        if AUTRE_TITRE.match(ligne):
            phase = None
            continue
        k = CLE.match(ligne)
        if k:
            total += 1
            vues.add(k.group(1))
            if k.group(1) != phase:
                hors.append((n, f"P{k.group(1)}.{k.group(2)}-{k.group(3)}", phase))
    return hors, total, sorted(vues - titrees, key=int)


def epreuves():
    """Témoins positifs ET négatifs. Une garde qu'on n'a pas vue rougir ne prouve rien."""
    bon = "## P3 — a\n\n| Clé |\n|---|\n| **P3.1-a** | x |\n\n## P4 — b\n\n| **P4.1-a** | y |\n"
    cas = [
        ("clé sous sa phase", bon, 0, 0),
        ("clé sous une AUTRE phase", "## P3 — a\n| **P4.1-a** | y |\n", 1, 1),
        ("clé sans aucune section", "| **P1.1-a** | y |\n", 1, 1),  # phase NON titrée : convention des témoins
        ("clé sous un titre qui n'est pas une phase", "## Limites\n| **P3.1-a** | y |\n", 1, 1),
        ("clé montrée dans un bloc de code", "## P3 — a\n```\n| **P4.1-a** | y |\n```\n", 0, 0),
        ("phase à deux chiffres", "## P10 — a\n| **P10.5-a** | y |\n", 0, 0),
        ("P1 ne préfixe pas P10", "## P1 — a\n| **P10.5-a** | y |\n", 1, 1),
    ]
    for nom, texte, attendu_hors, attendu_sans in cas:
        hors, _, sans = sections_et_cles(texte)
        if len(hors) != attendu_hors or len(sans) != attendu_sans:
            return f"témoin « {nom} » : {len(hors)} hors / {len(sans)} sans, attendu {attendu_hors} / {attendu_sans}"
    return None


def main():
    faute = epreuves()
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return 2
    try:
        sortie = subprocess.run(["git", "ls-files", "*.md"], capture_output=True, text=True, check=True).stdout
    except Exception as e:  # pas de dépôt, pas de corpus, pas de verdict
        print(f"::error::corpus illisible ({e}) : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2
    fichiers = [f for f in sortie.split("\n") if f.strip()]
    if not fichiers:
        print("::error::aucun document Markdown SUIVI : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2

    hors_tout, total, docs_avec_cles = [], 0, 0
    for f in fichiers:
        try:
            texte = open(f, encoding="utf-8").read()
        except OSError:
            continue
        hors, n, sans = sections_et_cles(texte)
        total += n
        if n:
            docs_avec_cles += 1
        for ligne, cle, phase in hors:
            ou = f"la phase P{phase}" if phase else "aucune section de phase"
            hors_tout.append((f, ligne, cle, ou))
        for ph in sans:
            hors_tout.append((f, 0, f"P{ph}.*", f"le document n'a pas de titre « ## P{ph} — »"))

    for f, ligne, cle, ou in hors_tout:
        emplacement = f"file={f},line={ligne}" if ligne else f"file={f}"
        print(f"::error {emplacement}::`{cle}` se lit sous {ou}", file=sys.stderr)

    if hors_tout:
        print(
            f"\n{len(hors_tout)} clé(s) ne se lisent pas sous le titre de leur phase. Une clé neuve "
            "s'ajoute à la FIN du document, qui n'est pas la fin de sa phase : la ranger sous "
            "« ## P<phase> — », en créant la section si elle manque.",
            file=sys.stderr,
        )
        return 1

    print(
        f"check_every_key_sits_under_the_section_of_its_phase : {total} clés dans {docs_avec_cles} "
        f"document(s) sur {len(fichiers)} suivis ; chacune se lit sous le titre « ## P<phase> — » que "
        "SA PROPRE clé désigne, et toute phase citée a une section. La phase attendue est DÉRIVÉE de la "
        "clé : ajouter une phase n'oblige à rien toucher ici.\n"
        "CE QU'ELLE NE TIENT PAS : un document Markdown NON SUIVI par le dépôt n'est pas lu (le corpus "
        "vient de `git ls-files`) ; l'ORDRE des sections entre elles n'est pas jugé, ni la place d'une "
        "clé DANS sa section, ni la cohérence entre le titre d'une phase et le sujet de ses clés ; et "
        "elle ne dit rien de l'ÉTAT d'une clé, qui est tenu ailleurs."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
