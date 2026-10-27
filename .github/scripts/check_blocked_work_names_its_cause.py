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

LE PÉRIMÈTRE 1.0 (décision de l'exploitant du 2026-10-26) : le périmètre est gelé pour la 1.0. Une
clé hors de ce périmètre porte la marque `**⏸ après 1.0**`, du même vocabulaire fermé, mais ce n'est
PAS une cause du moment : la clé n'est ni prenable ni retenue, elle est HORS PÉRIMÈTRE. La lecture
dérivée publie en plus l'avancement du périmètre 1.0 : X clé(s) fermée(s) (✅) sur Y, où Y compte les
✅ et les clés non closes (⬜, 🔵, 🔒) qui ne portent pas « après 1.0 » ; une clé ❓ (numéro réservé,
sans constat) n'entre jamais dans Y. Z est arrondi au dixième (moitié vers le haut), virgule
décimale. La marque « après 1.0 » sur une clé ✅ ou ❓ rougit : une clé close n'a plus de périmètre à
quitter, un numéro réservé n'en a jamais eu.
"""
import re, sys, collections
from decimal import Decimal, ROUND_HALF_UP

CAUSES = (
    "décision de l'exploitant",
    "mesure hors du poste",
    "porte à sens unique",
    "hors de ce dépôt",
    "dépend d'une autre clé",
)
HORS_PERIMETRE = "après 1.0"
VOCABULAIRE = CAUSES + (HORS_PERIMETRE,)
OUVERTS = ("⬜", "🔵")
FERME = "✅"
RESERVE = "❓"
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
    """(prenables par état, retenues par cause, périmètre {fermees, total, hors}, fautes[(ligne, message)])."""
    prenables = collections.Counter()
    retenues = collections.Counter()
    perimetre = {"fermees": 0, "total": 0, "hors": 0}
    fautes = []
    for n, cle, etat, cellule in cles(texte):
        m = MARQUE.match(cellule)
        cause = m.group(1).strip() if m else None
        if cause is not None and cause not in VOCABULAIRE:
            fautes.append((n, f"`{cle}` porte la marque « ⏸ {cause} », hors du vocabulaire fermé {list(VOCABULAIRE)}"))
            continue
        if cause == HORS_PERIMETRE:
            if etat in (FERME, RESERVE):
                fautes.append((n, f"`{cle}` est {etat} et porte la marque « ⏸ {HORS_PERIMETRE} » : une clé close n'a plus de périmètre à quitter, un numéro réservé n'en a jamais eu"))
                continue
            perimetre["hors"] += 1
            continue
        if etat != RESERVE:
            perimetre["total"] += 1
            if etat == FERME:
                perimetre["fermees"] += 1
        if cause is not None:
            if etat not in OUVERTS:
                fautes.append((n, f"`{cle}` est {etat} et porte encore une marque ⏸ : une clé close ou gatée n'est pas « retenue », la marque doit tomber avec le blocage"))
                continue
            retenues[cause] += 1
        elif etat in OUVERTS:
            prenables[etat] += 1
    return prenables, retenues, perimetre, fautes


def pourcentage(fermees, total):
    """Z au dixième, moitié vers le haut, virgule décimale ; None si le périmètre est vide."""
    if total == 0:
        return None
    z = (Decimal(100) * fermees / total).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    return f"{z}".replace(".", ",")


def ligne_publiee(prenables, retenues, perimetre):
    total_p = sum(prenables.values())
    total_r = sum(retenues.values())
    causes = " ; ".join(f"{c} {retenues[c]}" for c in CAUSES if retenues[c])
    z = pourcentage(perimetre["fermees"], perimetre["total"])
    avancement = (f"{perimetre['fermees']} clé(s) fermée(s) sur {perimetre['total']}, soit {z} %"
                  if z is not None else "aucune clé")
    return (f"{PREFIXE_LECTURE} : {total_p} clé(s) prenable(s) (⬜ {prenables['⬜']}, 🔵 {prenables['🔵']}) ; "
            f"{total_r} retenue(s) par une cause du moment ({causes if causes else 'aucune'}) ; "
            f"{perimetre['hors']} hors périmètre ({HORS_PERIMETRE}) ; périmètre 1.0 : {avancement}.")


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
    vide = " ; 0 hors périmètre (après 1.0) ; périmètre 1.0 : aucune clé."
    p = ["| **P2.1-a** | x | ✅ | fait |\n", "| **P2.1-b** | x | ✅ | fait |\n", "| **P2.1-c** | x | ✅ | fait |\n",
         "| **P2.1-d** | x | ✅ | fait |\n", "| **P2.1-e** | x | ⬜ | ouvert |\n", "| **P2.1-f** | x | 🔒 | geste de l'exploitant |\n",
         "| **P2.1-g** | x | 🔵 | **⏸ après 1.0** — hors du périmètre gelé |\n", "| **P2.1-h** | — | ❓ | numéro réservé |\n"]
    cas = [
        ("deux prenables, une retenue, lecture juste",
         doc(["| **P1.1-a** | x | ⬜ | ouvert |\n", "| **P1.1-b** | x | 🔵 | décidé |\n", "| **P1.1-c** | x | ⬜ | **⏸ mesure hors du poste** — il faut une machine |\n"],
             "**Lecture dérivée du travail prenable : 2 clé(s) prenable(s) (⬜ 1, 🔵 1) ; 1 retenue(s) par une cause du moment (mesure hors du poste 1) ; 0 hors périmètre (après 1.0) ; périmètre 1.0 : 0 clé(s) fermée(s) sur 3, soit 0,0 %.**"), 0, 0),
        ("lecture périmée", doc(["| **P1.1-a** | x | ⬜ | ouvert |\n"], "Lecture dérivée du travail prenable : 2 clé(s) prenable(s) (⬜ 2, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune) ; 0 hors périmètre (après 1.0) ; périmètre 1.0 : 0 clé(s) fermée(s) sur 1, soit 0,0 %."), 1, 0),
        ("lecture absente", doc(["| **P1.1-a** | x | ⬜ | ouvert |\n"]), 1, 0),
        # La lecture publiée est celle qu'une garde au vocabulaire OUVERT dériverait : seule la faute peut rougir.
        ("cause hors vocabulaire", doc(["| **P1.1-a** | x | ⬜ | **⏸ fatigue** — non |\n"], "Lecture dérivée du travail prenable : 0 clé(s) prenable(s) (⬜ 0, 🔵 0) ; 1 retenue(s) par une cause du moment (aucune) ; 0 hors périmètre (après 1.0) ; périmètre 1.0 : 0 clé(s) fermée(s) sur 1, soit 0,0 %."), 1, 1),
        # Même principe : la lecture est celle d'une garde qui avalerait la faute et compterait la clé retenue.
        ("marque sur une clé close", doc(["| **P1.1-a** | x | ✅ | **⏸ hors de ce dépôt** — fait |\n"], "Lecture dérivée du travail prenable : 0 clé(s) prenable(s) (⬜ 0, 🔵 0) ; 1 retenue(s) par une cause du moment (hors de ce dépôt 1) ; 0 hors périmètre (après 1.0) ; périmètre 1.0 : 1 clé(s) fermée(s) sur 1, soit 100,0 %."), 1, 1),
        ("marque ailleurs qu'en tête n'est pas une marque", doc(["| **P1.1-a** | x | ⬜ | ouvert, et plus loin **⏸ hors de ce dépôt** cité |\n"], "Lecture dérivée du travail prenable : 1 clé(s) prenable(s) (⬜ 1, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune) ; 0 hors périmètre (après 1.0) ; périmètre 1.0 : 0 clé(s) fermée(s) sur 1, soit 0,0 %."), 0, 0),
        ("après 1.0 hors périmètre, 🔒 dans Y, ❓ hors de Y, arrondi au dixième : lecture juste",
         doc(p, "Lecture dérivée du travail prenable : 1 clé(s) prenable(s) (⬜ 1, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune) ; 1 hors périmètre (après 1.0) ; périmètre 1.0 : 4 clé(s) fermée(s) sur 6, soit 66,7 %."), 0, 0),
        ("clé après 1.0 comptée prenable",
         doc(p, "Lecture dérivée du travail prenable : 2 clé(s) prenable(s) (⬜ 1, 🔵 1) ; 0 retenue(s) par une cause du moment (aucune) ; 0 hors périmètre (après 1.0) ; périmètre 1.0 : 4 clé(s) fermée(s) sur 7, soit 57,1 %."), 1, 0),
        ("clé après 1.0 comptée retenue",
         doc(p, "Lecture dérivée du travail prenable : 1 clé(s) prenable(s) (⬜ 1, 🔵 0) ; 1 retenue(s) par une cause du moment (après 1.0 1) ; 0 hors périmètre (après 1.0) ; périmètre 1.0 : 4 clé(s) fermée(s) sur 7, soit 57,1 %."), 1, 0),
        ("pourcentage faux : tronqué au lieu d'arrondi",
         doc(p, "Lecture dérivée du travail prenable : 1 clé(s) prenable(s) (⬜ 1, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune) ; 1 hors périmètre (après 1.0) ; périmètre 1.0 : 4 clé(s) fermée(s) sur 6, soit 66,6 %."), 1, 0),
        ("pourcentage faux : point décimal",
         doc(p, "Lecture dérivée du travail prenable : 1 clé(s) prenable(s) (⬜ 1, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune) ; 1 hors périmètre (après 1.0) ; périmètre 1.0 : 4 clé(s) fermée(s) sur 6, soit 66.7 %."), 1, 0),
        ("❓ comptée dans le périmètre",
         doc(p, "Lecture dérivée du travail prenable : 1 clé(s) prenable(s) (⬜ 1, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune) ; 1 hors périmètre (après 1.0) ; périmètre 1.0 : 4 clé(s) fermée(s) sur 7, soit 57,1 %."), 1, 0),
        ("🔒 oubliée du périmètre",
         doc(p, "Lecture dérivée du travail prenable : 1 clé(s) prenable(s) (⬜ 1, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune) ; 1 hors périmètre (après 1.0) ; périmètre 1.0 : 4 clé(s) fermée(s) sur 5, soit 80,0 %."), 1, 0),
        ("après 1.0 sur une clé ✅",
         doc(["| **P1.1-a** | x | ✅ | **⏸ après 1.0** — fait |\n"], "Lecture dérivée du travail prenable : 0 clé(s) prenable(s) (⬜ 0, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune) ; 1 hors périmètre (après 1.0) ; périmètre 1.0 : aucune clé."), 1, 1),
        ("après 1.0 sur une clé ❓",
         doc(["| **P1.1-a** | — | ❓ | **⏸ après 1.0** — réservé |\n"], "Lecture dérivée du travail prenable : 0 clé(s) prenable(s) (⬜ 0, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune) ; 1 hors périmètre (après 1.0) ; périmètre 1.0 : aucune clé."), 1, 1),
        # 1 sur 16 = 6,25 exactement : l'égalité départage la moitié vers le haut (6,3) de l'arrondi
        # au pair et du round() flottant (6,2 tous deux).
        ("égalité au centième : moitié vers le haut",
         doc(["| **P3.1-a** | x | ✅ | fait |\n"] + [f"| **P3.1-{chr(98 + i)}** | x | ⬜ | ouvert |\n" for i in range(15)],
             "Lecture dérivée du travail prenable : 15 clé(s) prenable(s) (⬜ 15, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune) ; 0 hors périmètre (après 1.0) ; périmètre 1.0 : 1 clé(s) fermée(s) sur 16, soit 6,3 %."), 0, 0),
        ("égalité au centième : arrondi au pair refusé",
         doc(["| **P3.1-a** | x | ✅ | fait |\n"] + [f"| **P3.1-{chr(98 + i)}** | x | ⬜ | ouvert |\n" for i in range(15)],
             "Lecture dérivée du travail prenable : 15 clé(s) prenable(s) (⬜ 15, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune) ; 0 hors périmètre (après 1.0) ; périmètre 1.0 : 1 clé(s) fermée(s) sur 16, soit 6,2 %."), 1, 0),
        ("périmètre vide, sans faute : aucune clé",
         doc(["| **P1.1-a** | x | ⬜ | **⏸ après 1.0** — hors du périmètre gelé |\n"], "Lecture dérivée du travail prenable : 0 clé(s) prenable(s) (⬜ 0, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune)" + vide.replace("0 hors", "1 hors")), 0, 0),
        ("après 1.0 admis sur une clé 🔒",
         doc(["| **P1.1-a** | x | ✅ | fait |\n", "| **P1.1-b** | x | 🔒 | **⏸ après 1.0** — geste de l'exploitant |\n"], "Lecture dérivée du travail prenable : 0 clé(s) prenable(s) (⬜ 0, 🔵 0) ; 0 retenue(s) par une cause du moment (aucune) ; 1 hors périmètre (après 1.0) ; périmètre 1.0 : 1 clé(s) fermée(s) sur 1, soit 100,0 %."), 0, 0),
    ]
    # Chaque cas dit son code ET son nombre de fautes : un rc=1 venu d'une lecture qui ne concorde
    # plus ne peut pas masquer une faute avalée.
    for nom, texte, attendu, fautes_attendues in cas:
        rc = juger(texte, "<fabriqué>", silencieux=True)
        if rc != attendu:
            return f"épreuve « {nom} » : rc={rc}, attendu {attendu}"
        fautes = len(deriver(texte)[3])
        if fautes != fautes_attendues:
            return f"épreuve « {nom} » : {fautes} faute(s), attendu {fautes_attendues}"
    return None


def juger(texte, fichier, silencieux=False):
    prenables, retenues, perimetre, fautes = deriver(texte)
    rc = 0
    for n, msg in fautes:
        rc = 1
        if not silencieux:
            print(f"::error file={fichier},line={n}::{msg}", file=sys.stderr)
    attendue = ligne_publiee(prenables, retenues, perimetre)
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
