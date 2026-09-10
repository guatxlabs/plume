#!/usr/bin/env python3
"""Une clé ouverte que rien ne peut prendre À CET INSTANT le dit, et l'index publie une lecture DÉRIVÉE
du travail prenable (`P8.29-b`).

Mesuré le 2026-08-29 : sur cent dix-sept clés ouvertes, quarante-trois n'étaient pas du travail
disponible — décision de l'exploitant, mesure que le poste ne peut pas prendre, porte à sens unique,
autre dépôt, clé sans objet propre — et toutes portaient le MÊME état que les autres. Un lecteur qui
comptait les clés ouvertes surestimait le travail disponible de plus d'un tiers.

LA FORME TRANCHÉE : le blocage est une propriété du MOMENT, pas de la clé — une décision, une machine
ou une clé voisine le lèvent sans que le constat change. Il n'est donc PAS un état : c'est une MARQUE
en tête de cellule, `**⏸ <cause>**`, prise dans un vocabulaire FERMÉ, posée sur une clé ⬜ ou 🔵 et
révisée par qui lève le blocage. L'index publie une lecture dérivée (« Lecture dérivée du travail
prenable ») que cette garde recompte à chaque exécution : un chiffre publié qui ne serait plus celui
de la dérivation rougit, et la garde imprime la ligne juste. Une marque sur une clé close, ou une
cause hors vocabulaire, rougit aussi : la marque ne peut ni survivre à la fermeture ni inventer une
cause.
"""
import re, sys, collections

CAUSES = (
    "décision de l'exploitant",
    "mesure hors du poste",
    "porte à sens unique",
    "hors de ce dépôt",
    "dépend d'une autre clé",
)
OUVERTS = ("⬜", "🔵")
MARQUE = re.compile(r"^\*\*⏸ ([^*]+)\*\*")
PREFIXE_LECTURE = "Lecture dérivée du travail prenable"
CODE = re.compile(r"^\s*(```|~~~)")


def cellules(ligne):
    brut = ligne.strip()
    if not (brut.startswith("|") and brut.endswith("|")):
        return None
    return [c.strip() for c in re.split(r"(?<!\\)\|", brut[1:-1])]


def cles(texte):
    dans_code = False
    for n, l in enumerate(texte.split("\n"), 1):
        if CODE.match(l):
            dans_code = not dans_code
            continue
        if dans_code:
            continue
        c = cellules(l)
        if not c or len(c) != 4:
            continue
        m = re.match(r"\*\*(P[\d.]+-[a-z0-9]+)\*\*", c[0])
        if m:
            yield n, m.group(1), c[2], c[3]


def deriver(texte):
    """(prenables par état, retenues par cause, fautes[(ligne, message)])."""
    prenables = collections.Counter()
    retenues = collections.Counter()
    fautes = []
    for n, cle, etat, cellule in cles(texte):
        m = MARQUE.match(cellule)
        if m:
            cause = m.group(1).strip()
            if cause not in CAUSES:
                fautes.append((n, f"`{cle}` porte la marque « ⏸ {cause} », hors du vocabulaire fermé {list(CAUSES)}"))
                continue
            if etat not in OUVERTS:
                fautes.append((n, f"`{cle}` est {etat} et porte encore une marque ⏸ : une clé close ou gatée n'est pas « retenue », la marque doit tomber avec le blocage"))
                continue
            retenues[cause] += 1
        elif etat in OUVERTS:
            prenables[etat] += 1
    return prenables, retenues, fautes


def ligne_publiee(prenables, retenues):
    total_p = sum(prenables.values())
    total_r = sum(retenues.values())
    causes = " ; ".join(f"{c} {retenues[c]}" for c in CAUSES if retenues[c])
    return (f"{PREFIXE_LECTURE} : {total_p} clé(s) prenable(s) (⬜ {prenables['⬜']}, 🔵 {prenables['🔵']}) ; "
            f"{total_r} retenue(s) par une cause du moment ({causes if causes else 'aucune'}).")


def lecture_du_document(texte):
    for n, l in enumerate(texte.split("\n"), 1):
        if PREFIXE_LECTURE in l:
            return n, l.strip().lstrip("*> ").rstrip("*")
    return None, None


def epreuves():
    base = "| Clé | Titre | État | Constat |\n|---|---|---|---|\n"
    def doc(lignes, lecture=None):
        t = base + "".join(lignes)
        return t + ("\n" + lecture + "\n" if lecture else "")
    cas = [
        ("deux prenables, une retenue, lecture juste",
         doc(["| **P1.1-a** | x | ⬜ | ouvert |\n", "| **P1.1-b** | x | 🔵 | décidé |\n", "| **P1.1-c** | x | ⬜ | **⏸ mesure hors du poste** — il faut une machine |\n"],
             "**Lecture dérivée du travail prenable : 2 clé(s) prenable(s) (⬜ 1, 🔵 1) ; 1 retenue(s) par une cause du moment (mesure hors du poste 1).**"), 0),
        ("lecture périmée", doc(["| **P1.1-a** | x | ⬜ | ouvert |\n"], "Lecture dérivée du travail prenable : 2 clé(s) prenable(s) (⬜ 2, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune)."), 1),
        ("lecture absente", doc(["| **P1.1-a** | x | ⬜ | ouvert |\n"]), 1),
        ("cause hors vocabulaire", doc(["| **P1.1-a** | x | ⬜ | **⏸ fatigue** — non |\n"], "Lecture dérivée du travail prenable : 0 clé(s) prenable(s) (⬜ 0, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune)."), 1),
        ("marque sur une clé close", doc(["| **P1.1-a** | x | ✅ | **⏸ hors de ce dépôt** — fait |\n"], "Lecture dérivée du travail prenable : 0 clé(s) prenable(s) (⬜ 0, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune)."), 1),
        ("marque ailleurs qu'en tête n'est pas une marque", doc(["| **P1.1-a** | x | ⬜ | ouvert, et plus loin **⏸ hors de ce dépôt** cité |\n"], "Lecture dérivée du travail prenable : 1 clé(s) prenable(s) (⬜ 1, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune)."), 0),
    ]
    for nom, texte, attendu in cas:
        rc = juger(texte, "<fabriqué>", silencieux=True)
        if rc != attendu:
            return f"épreuve « {nom} » : rc={rc}, attendu {attendu}"
    return None


def juger(texte, fichier, silencieux=False):
    prenables, retenues, fautes = deriver(texte)
    rc = 0
    for n, msg in fautes:
        rc = 1
        if not silencieux:
            print(f"::error file={fichier},line={n}::{msg}", file=sys.stderr)
    attendue = ligne_publiee(prenables, retenues)
    n, lue = lecture_du_document(texte)
    if lue is None:
        rc = 1
        if not silencieux:
            print(f"::error file={fichier}::l'index ne publie AUCUNE lecture dérivée du travail prenable ; ligne à poser (en gras, sous la légende des états) :\n{attendue}", file=sys.stderr)
    elif lue != attendue:
        rc = 1
        if not silencieux:
            print(f"::error file={fichier},line={n}::la lecture publiée n'est plus celle que la dérivation rend.\n  publiée : {lue}\n  dérivée : {attendue}", file=sys.stderr)
    if not silencieux and rc == 0:
        print(f"{sum(prenables.values())} clé(s) prenable(s), {sum(retenues.values())} retenue(s) par une cause du moment ; la lecture publiée est celle de la dérivation.")
    return rc


def main():
    faute = epreuves()
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return 2
    fichier = "docs/ROADMAP.md"
    try:
        texte = open(fichier, encoding="utf-8").read()
    except OSError as e:
        print(f"::error::corpus illisible ({e}) : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2
    return juger(texte, fichier)


if __name__ == "__main__":
    sys.exit(main())
