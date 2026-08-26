#!/usr/bin/env python3
"""La colonne d'état d'une clé ne vaut que ce que la légende du document déclare.

Les états admis sont DÉRIVÉS de la table de légende du document lui-même — la
première table à deux colonnes dont l'en-tête porte « État ». Rien n'est énuméré
ici : ajouter un état à la légende suffit à le rendre licite, en retirer un le
rend illicite, sans toucher à ce fichier.

Le défaut attrapé a été mesuré le 2026-08-26 : une cellule portait DEUX marqueurs
collés, une valeur que la légende ne déclare pas. Elle échappait à tout relevé qui
lit la colonne, et l'un des deux marqueurs contredisait le texte de sa propre
cellule.
"""
import re, subprocess, sys

LIGNE_CLE = re.compile(r"^\| +\*\*(P[\d.]+-[a-z])\*\* *[^|]*\| *[^|]*\| *([^|]*?) *\|")
CODE = re.compile(r"^\s*(```|~~~)")
SEP = re.compile(r"^\|[ :\-|]+\|$")


def legende(texte):
    """Les états déclarés, lus dans la table dont l'en-tête porte « État »."""
    lignes = texte.split("\n")
    for i, l in enumerate(lignes):
        cellules = [c.strip() for c in l.strip().strip("|").split("|")]
        if len(cellules) == 2 and cellules[0].lower() == "état" and i + 1 < len(lignes) and SEP.match(lignes[i + 1]):
            admis = set()
            for suite in lignes[i + 2:]:
                if not suite.startswith("|"):
                    break
                c = [x.strip() for x in suite.strip().strip("|").split("|")]
                if len(c) == 2 and c[0]:
                    admis.add(c[0])
            return admis
    return set()


def etats_utilises(texte):
    dans_code = False
    for n, l in enumerate(texte.split("\n"), 1):
        if CODE.match(l):
            dans_code = not dans_code
            continue
        if dans_code:
            continue
        m = LIGNE_CLE.match(l)
        if m:
            yield n, m.group(1), m.group(2)


def epreuves():
    base = "| État | Signification |\n|---|---|\n| ✅ | fait |\n| ⬜ | ouvert |\n"
    cas = [
        ("état déclaré", base + "| **P1.1-a** | x | ✅ | y |\n", 0),
        ("état composite", base + "| **P1.1-a** | x | ✅⬜ | y |\n", 1),
        ("état inconnu", base + "| **P1.1-a** | x | 🟥 | y |\n", 1),
        ("colonne vide", base + "| **P1.1-a** | x |  | y |\n", 1),
        ("clé dans un bloc de code", base + "```\n| **P1.1-a** | x | 🟥 | y |\n```\n", 0),
    ]
    for nom, texte, attendu in cas:
        admis = legende(texte)
        if admis != {"✅", "⬜"}:
            return f"témoin « {nom} » : légende lue = {sorted(admis)}, attendu ✅ ⬜"
        faux = [1 for _, _, e in etats_utilises(texte) if e not in admis]
        if len(faux) != attendu:
            return f"témoin « {nom} » : {len(faux)} état(s) hors légende, attendu {attendu}"
    if legende("| Clé | Périmètre |\n|---|---|\n| a | b |\n"):
        return "témoin « pas de légende » : une table sans colonne « État » a été prise pour une légende"
    return None


def main():
    faute = epreuves()
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return 2
    try:
        sortie = subprocess.run(["git", "ls-files", "*.md"], capture_output=True, text=True, check=True).stdout
    except Exception as e:
        print(f"::error::corpus illisible ({e}) : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2

    fautes, total, docs = [], 0, 0
    for f in [x for x in sortie.split("\n") if x.strip()]:
        try:
            texte = open(f, encoding="utf-8").read()
        except OSError:
            continue
        utilises = list(etats_utilises(texte))
        if not utilises:
            continue
        docs += 1
        admis = legende(texte)
        if not admis:
            print(f"::error file={f}::ce document porte des clés mais AUCUNE table de légende « État » : "
                  "la garde REFUSE DE CONCLURE sur lui", file=sys.stderr)
            return 2
        for n, cle, etat in utilises:
            total += 1
            if etat not in admis:
                fautes.append((f, n, cle, etat, sorted(admis)))

    for f, n, cle, etat, admis in fautes:
        vu = etat if etat else "(vide)"
        print(f"::error file={f},line={n}::`{cle}` porte l'état « {vu} », que la légende ne déclare pas "
              f"(déclarés : {' '.join(admis)})", file=sys.stderr)

    if fautes:
        print(f"\n{len(fautes)} clé(s) portent un état hors légende. Un état composite ou inconnu échappe à "
              "TOUT relevé qui lit la colonne, et il peut contredire le texte de sa propre cellule. Choisir "
              "l'état qui tient, ou déclarer le nouvel état dans la légende.", file=sys.stderr)
        return 1

    print(f"check_a_key_state_is_one_the_legend_declares : {total} clés dans {docs} document(s) ; chacune "
          "porte un état que la légende de SON PROPRE document déclare. Les états admis sont DÉRIVÉS de "
          "cette légende — en ajouter un n'oblige à rien toucher ici — et un document qui porte des clés "
          "sans légende fait REFUSER DE CONCLURE.\n"
          "CE QU'ELLE NE TIENT PAS : la VÉRITÉ de l'état, qui est tenue ailleurs ; la cohérence entre "
          "l'état et le texte de la cellule ; et un document Markdown non suivi par le dépôt n'est pas lu.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
