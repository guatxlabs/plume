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

SECOND DÉFAUT, mesuré le 2026-09-15 (`P11.24-x`, puis `P11.24-y`) : une clé a porté
douze jours l'état dont la légende dit « sans constat attesté » alors que sa cellule
s'ouvrait par « MESURÉ le 2026-09-03 ». Le symbole appartenait à la légende, donc la
première règle ne voyait rien ; et cet état est INVISIBLE au compte dérivé du
travail prenable comme à la garde des résidus, si bien qu'un constat réel dormait
hors de tout relevé. La règle ajoutée est DÉRIVÉE de la légende, comme la première :
tout état dont le SENS déclaré contient « sans constat » interdit à sa cellule une
DÉCLARATION DATÉE — la forme « MOT-EN-MAJUSCULES le AAAA-MM-JJ » par laquelle ce
document atteste lui-même un constat (la forme que la garde de concordance
index/commit dérive pour son lexique de fermeture, élargie aux mots de deux lettres
pour lire « VU le … »). Un ❓ dont la cellule dit « MESURÉ le … » ou « VU le … »
contredit sa propre légende : la garde le refuse et nomme la PREMIÈRE déclaration
de la cellule.
"""
import re, subprocess, sys

LIGNE_CLE = re.compile(r"^\| +\*\*(P[\d.]+-[a-z])\*\* *[^|]*\| *[^|]*\| *([^|]*?) *\|(.*)$")
CODE = re.compile(r"^\s*(```|~~~)")
SEP = re.compile(r"^\|[ :\-|]+\|$")
# La forme par laquelle l'index atteste un constat : un mot en MAJUSCULES (accents compris)
# suivi de « le » et d'une date ISO. C'est la forme que `check_the_index_agrees_with_what_a_commit_closes.py`
# dérive pour son lexique de fermeture (DECLARATION_DATEE), à une différence PRÈS, voulue : elle
# exige quatre lettres parce qu'elle cherche des participes (FERMÉE, CORRIGÉE) ; ici deux suffisent,
# parce que la déclaration la plus courante de cet index est « VU le AAAA-MM-JJ » — mesuré le
# 2026-09-16 : avec quatre lettres, la mutation « P10.7-e remise en ❓ » n'était nommée que par
# son « FERMÉE le … », pas par le « VU le … » qui ouvre sa cellule.
DECLARATION_DATEE = re.compile(r"\b([A-ZÀ-ÖØ-Þ]{2,})\s+le\s+\d{4}-\d{2}-\d{2}")
SENS_SANS_CONSTAT = re.compile(r"sans\s+constat", re.IGNORECASE)


def legende(texte):
    """Les états déclarés, lus dans la table dont l'en-tête porte « État » : état -> sens."""
    lignes = texte.split("\n")
    for i, l in enumerate(lignes):
        cellules = [c.strip() for c in l.strip().strip("|").split("|")]
        if len(cellules) == 2 and cellules[0].lower() == "état" and i + 1 < len(lignes) and SEP.match(lignes[i + 1]):
            admis = {}
            for suite in lignes[i + 2:]:
                if not suite.startswith("|"):
                    break
                c = [x.strip() for x in suite.strip().strip("|").split("|")]
                if len(c) == 2 and c[0]:
                    admis[c[0]] = c[1]
            return admis
    return {}


def etats_sans_constat(admis):
    """Les états dont la légende elle-même dit qu'ils ne portent AUCUN constat."""
    return {e for e, sens in admis.items() if SENS_SANS_CONSTAT.search(sens)}


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
            yield n, m.group(1), m.group(2), m.group(3)


def declaration_contredisant(etat, cellule, sans_constat):
    """La déclaration datée qu'une cellule porte alors que son état la lui interdit, sinon None."""
    if etat not in sans_constat:
        return None
    m = DECLARATION_DATEE.search(cellule)
    return m.group(0) if m else None


def epreuves():
    base = ("| État | Signification |\n|---|---|\n| ✅ | fait |\n| ⬜ | ouvert |\n"
            "| ❓ | numéro réservé, sans constat attesté |\n")
    attendu_legende = {"✅", "⬜", "❓"}
    cas = [
        # (nom, texte, états hors légende attendus, contradictions état/cellule attendues)
        ("état déclaré", base + "| **P1.1-a** | x | ✅ | y |\n", 0, 0),
        ("état composite", base + "| **P1.1-a** | x | ✅⬜ | y |\n", 1, 0),
        ("état inconnu", base + "| **P1.1-a** | x | 🟥 | y |\n", 1, 0),
        ("colonne vide", base + "| **P1.1-a** | x |  | y |\n", 1, 0),
        ("clé dans un bloc de code", base + "```\n| **P1.1-a** | x | 🟥 | y |\n```\n", 0, 0),
        ("sans constat, cellule vierge", base + "| **P1.1-a** | x | ❓ | Numéro réservé : aucun constat ne le porte. |\n", 0, 0),
        ("sans constat, cellule qui atteste", base + "| **P1.1-a** | x | ❓ | MESURÉ le 2026-09-03 EN PASSANT : deux assertions tombent. |\n", 0, 1),
        ("sans constat, date sans mot attestant", base + "| **P1.1-a** | x | ❓ | réservé ; voir le 2026-09-03 la discussion. |\n", 0, 0),
        ("constat daté sous un état qui l'admet", base + "| **P1.1-a** | x | ⬜ | MESURÉ le 2026-09-03 : ouvert. |\n", 0, 0),
        ("mot accentué attestant", base + "| **P1.1-a** | x | ❓ | TROUVÉE le 2026-09-03 en fermant une voisine. |\n", 0, 1),
        ("la forme la plus courte de l'index, « VU le »", base + "| **P1.1-a** | x | ❓ | VU le 2026-08-28 : le corps est nu. |\n", 0, 1),
        ("mot d'une lettre, pas une attestation", base + "| **P1.1-a** | x | ❓ | réservé ; A le 2026-09-03 rien. |\n", 0, 0),
    ]
    for nom, texte, attendu_faux, attendu_contra in cas:
        admis = legende(texte)
        if set(admis) != attendu_legende:
            return f"témoin « {nom} » : légende lue = {sorted(admis)}, attendu ✅ ⬜ ❓"
        sans_constat = etats_sans_constat(admis)
        if sans_constat != {"❓"}:
            return f"témoin « {nom} » : états « sans constat » dérivés = {sorted(sans_constat)}, attendu ❓ seul"
        utilises = list(etats_utilises(texte))
        faux = [1 for _, _, e, _ in utilises if e not in admis]
        if len(faux) != attendu_faux:
            return f"témoin « {nom} » : {len(faux)} état(s) hors légende, attendu {attendu_faux}"
        contra = [1 for _, _, e, c in utilises if declaration_contredisant(e, c, sans_constat)]
        if len(contra) != attendu_contra:
            return f"témoin « {nom} » : {len(contra)} contradiction(s) état/cellule, attendu {attendu_contra}"
    if legende("| Clé | Périmètre |\n|---|---|\n| a | b |\n"):
        return "témoin « pas de légende » : une table sans colonne « État » a été prise pour une légende"
    if etats_sans_constat({"✅": "fait", "⬜": "ouvert"}):
        return "témoin « légende sans état réservé » : un état « sans constat » a été dérivé d'une légende qui n'en déclare pas"
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

    fautes, contradictions, total, docs = [], [], 0, 0
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
        sans_constat = etats_sans_constat(admis)
        for n, cle, etat, cellule in utilises:
            total += 1
            if etat not in admis:
                fautes.append((f, n, cle, etat, sorted(admis)))
                continue
            decl = declaration_contredisant(etat, cellule, sans_constat)
            if decl:
                contradictions.append((f, n, cle, etat, admis[etat], decl))

    for f, n, cle, etat, admis in fautes:
        vu = etat if etat else "(vide)"
        print(f"::error file={f},line={n}::`{cle}` porte l'état « {vu} », que la légende ne déclare pas "
              f"(déclarés : {' '.join(admis)})", file=sys.stderr)
    for f, n, cle, etat, sens, decl in contradictions:
        print(f"::error file={f},line={n}::`{cle}` porte l'état {etat} — « {sens} » selon la légende — et sa "
              f"cellule ATTESTE un constat : « {decl} ». L'état contredit la cellule, et cet état est invisible "
              "au compte du travail prenable comme à la garde des résidus : choisir l'état qui tient (🔵 si "
              "mesuré et décidé, ⬜ si ouvert, ✅ si tenu) ou retirer la déclaration.", file=sys.stderr)

    if fautes or contradictions:
        if fautes:
            print(f"\n{len(fautes)} clé(s) portent un état hors légende. Un état composite ou inconnu échappe à "
                  "TOUT relevé qui lit la colonne, et il peut contredire le texte de sa propre cellule. Choisir "
                  "l'état qui tient, ou déclarer le nouvel état dans la légende.", file=sys.stderr)
        if contradictions:
            print(f"\n{len(contradictions)} clé(s) portent un état « sans constat » sur une cellule qui en atteste "
                  "un. Mesuré le 2026-09-15 : une telle clé a dormi douze jours hors de tout relevé.", file=sys.stderr)
        return 1

    print(f"check_a_key_state_is_one_the_legend_declares : {total} clés dans {docs} document(s) ; chacune "
          "porte un état que la légende de SON PROPRE document déclare, et aucune clé d'un état « sans "
          "constat » ne porte de déclaration datée dans sa cellule. Les états admis, comme les états « sans "
          "constat », sont DÉRIVÉS de cette légende — en ajouter un n'oblige à rien toucher ici — et un "
          "document qui porte des clés sans légende fait REFUSER DE CONCLURE.\n"
          "CE QU'ELLE NE TIENT PAS : la VÉRITÉ de l'état, qui est tenue ailleurs ; la cohérence entre "
          "l'état et le texte de la cellule pour les AUTRES états (un ✅ dont la cellule dit « reste ouvert » "
          "est jugé par la garde des résidus, pas ici) ; une clé sans lettre de constat (`P5.6`, "
          "`P7.2 · P7.6`) n'est pas lue par la forme de ligne ; et un document Markdown non suivi par le "
          "dépôt n'est pas lu.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
