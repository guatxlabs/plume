#!/usr/bin/env python3
"""Le résumé anglais de la feuille de route a une section par phase de l'index, ni plus ni moins.

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`docs/ROADMAP.md` reste en français et n'est pas traduite ; le lecteur anglophone reçoit
`docs/ROADMAP-SUMMARY.md`, une section par phase. Rien ne liait les deux : une phase ouverte dans
l'index (un titre `## P14 — …`) laissait le résumé muet sur elle, et une phase retirée ou renumérotée
laissait dans le résumé une section qui ne désigne plus rien. Les deux pages restaient lisibles, et
aucun vert ne bougeait.

CE QUI EST JUGÉ, ET RIEN D'AUTRE
--------------------------------
L'ENSEMBLE des phases titrées de l'index (`## P<n> — `, hors blocs de code — la forme même que
`check_every_key_sits_under_the_section_of_its_phase.py` lit) et l'ensemble des sections de phase du
résumé (même forme) sont ÉGAUX, jugés dans les deux sens :
  - une phase de l'index sans section dans le résumé rougit ;
  - une section du résumé sans phase dans l'index rougit ;
  - une phase titrée deux fois dans le résumé rougit aussi (deux sections pour une phase, l'une est
    périmée).

CE QU'ELLE NE TIENT PAS
-----------------------
Ni l'ORDRE des sections, ni le texte d'une section : qu'une phrase du résumé soit encore exacte
repose sur la relecture. Ni les titres de niveau trois (sous-sections de l'index, comme P4.4), ni les
sections de l'index qui ne sont pas des phases (limites connues, constats sans clé).

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
--------------------------------------------------
Avant de lire l'arbre, la garde joue sa décision sur des textes fabriqués : égalité (vert), phase
neuve sans section (rouge), section sans phase (rouge), section dupliquée (rouge), titre dans un
bloc de code (ignoré), P1 qui ne préfixe pas P10, et un index sans phase (refus). Un témoin qui ne
rend pas son code fait refuser la garde.

CODES DE SORTIE
---------------
`0` ensembles égaux ; `1` un écart nommé ; `2` rien de probant (instrument faux, fichier illisible,
index sans aucune phase titrée).
"""
import os
import re
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
INDEX = os.path.join("docs", "ROADMAP.md")
RESUME = os.path.join("docs", "ROADMAP-SUMMARY.md")
ETIQUETTE = "[resume-de-la-feuille-de-route]"

TITRE = re.compile(r"^## +P(\d+) +— ")
CODE = re.compile(r"^\s*(```|~~~)")


def phases(texte):
    """Liste des numéros de phase titrés (`## P<n> — `) hors blocs de code, dans l'ordre, doublons compris."""
    vues, dans_code = [], False
    for ligne in texte.split("\n"):
        if CODE.match(ligne):
            dans_code = not dans_code
            continue
        if dans_code:
            continue
        t = TITRE.match(ligne)
        if t:
            vues.append(int(t.group(1)))
    return vues


def juger(texte_index, texte_resume):
    """(code, lignes). Toute la décision est ici ; les témoins la jouent telle quelle."""
    de_l_index = phases(texte_index)
    du_resume = phases(texte_resume)
    if not de_l_index:
        return 2, [f"{ETIQUETTE} REFUSE DE CONCLURE — l'index ne titre aucune phase `## P<n> — ` : "
                   f"la forme a changé ou le fichier est vide, rien n'est comparé."]
    lignes = []
    for p in sorted(set(de_l_index) - set(du_resume)):
        lignes.append(f"::error file={RESUME}::la phase P{p} est titrée dans {INDEX} et n'a aucune section "
                      f"`## P{p} — ` dans {RESUME}")
    for p in sorted(set(du_resume) - set(de_l_index)):
        lignes.append(f"::error file={RESUME}::la section P{p} de {RESUME} ne désigne aucune phase titrée "
                      f"dans {INDEX}")
    for p in sorted({p for p in du_resume if du_resume.count(p) > 1}):
        lignes.append(f"::error file={RESUME}::la phase P{p} a {du_resume.count(p)} sections dans {RESUME}")
    if lignes:
        return 1, lignes + [f"{ETIQUETTE} ÉCHEC — {len(lignes)} écart(s) entre les phases de l'index et les "
                            f"sections du résumé : une phase ouverte, retirée ou renumérotée dans l'index "
                            f"se reporte dans le résumé dans le même commit."]
    return 0, [f"{ETIQUETTE} OK — {len(set(de_l_index))} phase(s) titrée(s) dans l'index, autant de sections "
               f"dans le résumé, dans les deux sens. Ni l'ordre ni le texte des sections ne sont jugés."]


def valider_instrument():
    """TÉMOINS : rend la liste des échecs. Chacun exige son code ET la faute qui le fonde."""
    index = "# I\n\n## P3 — a\n\n| x |\n\n## P10 — b\n\n## Limites\n"
    resume = "# S\n\n## How to read\n\n## P3 — a\n\n## P10 — b\n\n## Other\n"
    cas = [
        ("ensembles égaux", index, resume, 0, "OK", 0),
        ("phase neuve sans section", index + "\n## P14 — c\n", resume, 1, "la phase P14 est titrée", 1),
        ("section sans phase", index, resume + "\n## P9 — z\n", 1, "la section P9", 1),
        ("section dupliquée", index, resume + "\n## P3 — encore\n", 1, "la phase P3 a 2 sections", 1),
        ("titre dans un bloc de code", index + "\n```\n## P14 — c\n```\n", resume, 0, "OK", 0),
        ("P1 ne préfixe pas P10", index, resume.replace("## P10 — b", "## P1 — b"), 1,
         "la phase P10 est titrée", 2),
        ("titre de niveau trois ignoré", index + "\n### P4.4 — d\n", resume, 0, "OK", 0),
        ("index sans phase", "# I\n\n## Limites\n", resume, 2, "REFUSE DE CONCLURE", 0),
    ]
    echecs = []
    for nom, ti, tr, attendu, faute, fautes in cas:
        code, lignes = juger(ti, tr)
        if code != attendu or not any(faute in l for l in lignes):
            echecs.append(f"témoin « {nom} » : code {code}, attendu {attendu} avec « {faute} »")
        elif sum(1 for l in lignes if l.startswith("::error")) != fautes:
            echecs.append(f"témoin « {nom} » : {sum(1 for l in lignes if l.startswith('::error'))} faute(s), "
                          f"{fautes} attendue(s)")
    return echecs


def lire(rel):
    with open(os.path.join(RACINE, rel), encoding="utf-8") as f:
        return f.read()


def main():
    echecs = valider_instrument()
    if echecs:
        print(f"{ETIQUETTE} REFUSE DE CONCLURE — l'INSTRUMENT est faux, aucun verdict sur l'arbre :")
        for e in echecs:
            print(f"    - {e}")
        return 2
    try:
        texte_index, texte_resume = lire(INDEX), lire(RESUME)
    except (OSError, UnicodeDecodeError) as e:
        print(f"{ETIQUETTE} REFUSE DE CONCLURE — lecture impossible ({e}) : rien n'est comparé.")
        return 2
    code, lignes = juger(texte_index, texte_resume)
    for ligne in lignes:
        print(ligne)
    return code


if __name__ == "__main__":
    sys.exit(main())
