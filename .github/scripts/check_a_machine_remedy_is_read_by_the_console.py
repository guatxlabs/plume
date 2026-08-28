#!/usr/bin/env python3
"""Tout REMÈDE MACHINE que le démon publie dans un refus est LU par la console (`P10.5-g`).

LE DÉFAUT QUE CETTE GARDE ATTRAPE. Un refus peut porter deux choses : une PHRASE pour l'humain et
une CONDUITE pour le programme. La conduite est un booléen nu — `"restart_without_cursor": true` —
qui dit au client ce qu'il doit FAIRE. Mesuré le 2026-08-28 : le démon en publiait un sur ses trois
sites de refus de curseur froid et AUCUN module de `web/` ne le lisait. Le message s'affichait, la
table des curseurs gardait le curseur mort, et « Suivant » le rejouait indéfiniment. Un remède posé
et non armé est pire qu'un remède absent : il fait croire que le cas est traité.

LA POPULATION EST DÉRIVÉE, JAMAIS ÉNUMÉRÉE. Un corps de refus se reconnaît à ce qu'il PORTE une
clé `"reason"` — c'est la forme que le démon s'est donnée pour nommer une cause machine. Dans un tel
corps, tout champ dont la valeur littérale est `true` est un fait ou une conduite que le démon a jugé
utile de publier À CÔTÉ de la phrase ; s'il ne sert à personne, il n'avait pas à être écrit. La règle
est donc à PLAFOND ZÉRO et sans exception déclarée : chacun de ces noms doit apparaître dans au moins
un module de `web/`. Ajouter un champ neuf sans le brancher fait rougir cette garde sans qu'aucune
liste soit tenue à côté du code.

CE QU'ELLE NE TIENT PAS, ET C'EST ÉCRIT PLUTÔT QUE PROMIS. Elle vérifie que le nom est LU, pas qu'il
est OBÉI : un module qui lirait `restart_without_cursor` pour l'ignorer la satisferait. Elle ne voit
pas un remède publié sous une autre forme (une chaîne, un entier, un objet), ni un corps de refus
qui ne porterait pas de `"reason"`. Et elle ne lit que `web/` : un client tiers reste hors de portée.
Le plancher de non-dégénérescence protège de la vacuité TOTALE (une réécriture qui ferait disparaître
la forme), pas de la vacuité PARTIELLE.
"""
import re
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
DEMON = RACINE / "daemon" / "src" / "handlers"
CONSOLE = RACINE / "web"
PLANCHER_REMEDES = 2  # non-dégénérescence : sous ce compte, la forme a changé -> refuser de conclure

CLE_TRUE = re.compile(r'"([a-z][a-z0-9_]*)"\s*:\s*true\b')
CLE_REASON = re.compile(r'"reason"\s*:')


def corps_de_refus(texte: str):
    """Rend les tranches de texte qui portent une clé `"reason"`, bornées par accolades équilibrées."""
    for m in CLE_REASON.finditer(texte):
        # remonter jusqu'à l'accolade ouvrante du littéral qui contient cette clé
        profondeur, debut = 0, None
        for i in range(m.start(), -1, -1):
            c = texte[i]
            if c == "}":
                profondeur += 1
            elif c == "{":
                if profondeur == 0:
                    debut = i
                    break
                profondeur -= 1
        if debut is None:
            continue
        profondeur, fin = 0, None
        for i in range(debut, len(texte)):
            c = texte[i]
            if c == "{":
                profondeur += 1
            elif c == "}":
                profondeur -= 1
                if profondeur == 0:
                    fin = i + 1
                    break
        if fin is not None:
            yield texte[debut:fin]


def main() -> int:
    if not DEMON.is_dir() or not CONSOLE.is_dir():
        print(f"::error::arborescence inattendue ({DEMON} / {CONSOLE}) : REFUS DE CONCLURE.")
        return 2

    remedes: dict[str, list[str]] = {}
    for src in sorted(DEMON.rglob("*.rs")):
        texte = src.read_text(encoding="utf-8")
        for corps in corps_de_refus(texte):
            for nom in CLE_TRUE.findall(corps):
                remedes.setdefault(nom, [])
                rel = str(src.relative_to(RACINE))
                if rel not in remedes[nom]:
                    remedes[nom].append(rel)

    if len(remedes) < PLANCHER_REMEDES:
        print(
            f"::error::{len(remedes)} champ(s) booléen(s) trouvé(s) dans un corps de refus, "
            f"plancher {PLANCHER_REMEDES} : la FORME a changé (plus de `\"reason\"`, ou plus de "
            f"booléen nu) et cette garde ne mesure plus rien. REFUS DE CONCLURE."
        )
        return 2

    lus = " ".join(p.read_text(encoding="utf-8") for p in sorted(CONSOLE.glob("*.js")))
    muets = {n: s for n, s in remedes.items() if n not in lus}
    if muets:
        for nom, sites in sorted(muets.items()):
            print(
                f"::error::`{nom}` est publié par le démon ({', '.join(sites)}) et AUCUN module de "
                f"web/ ne le lit — un remède posé et non armé fait croire que le cas est traité."
            )
        return 1

    print(
        f"check_a_machine_remedy_is_read_by_the_console : {len(remedes)} champ(s) de conduite "
        f"publié(s) dans un corps de refus ({', '.join(sorted(remedes))}), chacun lu par au moins un "
        f"module de web/. Population DÉRIVÉE de la forme `\"reason\"` + booléen nu, plafond ZÉRO."
    )
    print(
        "CE QU'ELLE NE TIENT PAS : que le remède soit OBÉI (le lire suffit à la satisfaire) ; un "
        "remède publié sous une autre forme qu'un booléen nu ; un corps de refus sans `\"reason\"` ; "
        "et tout client hors de web/."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
