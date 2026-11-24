#!/usr/bin/env python3
"""Les outils des deux langues passent leurs propres épreuves — garde de CI.

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Deux outils portent les deux langues des documents : `parite_des_langues.py`, que la garde
`check_every_document_is_paired_and_in_parity.py` appelle pour juger l'arbre, et `bench/report.py`, qui
rend `docs/BENCHMARK.md` et `docs/BENCHMARK.fr.md`. Chacun a ses épreuves
(`.github/scripts/test_parite_des_langues.py`, `bench/test_report_langues.py`), et rien ne les lançait.
Une jointure coupée dans l'outil de parité rend ses épreuves rouges, et la garde qui l'emploie reste
verte sur un arbre où la jointure n'a rien à joindre ; une traduction perdue par le générateur ne se
voit qu'au prochain rendu. Les épreuves écrites sans être jouées ne refusaient rien.

CE QUI EST JUGÉ
---------------
Chaque suite de `SUITES` est jouée par l'interpréteur courant, depuis la racine du dépôt. Elle passe
si elle se termine sans échec ni erreur, après au moins son PLANCHER d'épreuves : une suite qui
n'en joue plus, ou presque plus, ne prouve rien et ne passe pas pour une suite verte.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
--------------------------------------------------
La lecture du résultat d'une suite est jouée d'abord sur des suites fabriquées : une qui passe, une
qui échoue, une qui ne s'importe pas, une sous son plancher, une sans épreuve. Une lecture qui ne rend
pas le code attendu fait refuser la garde.

CODES DE SORTIE
---------------
`0` toutes les suites passent ; `1` une suite échoue ou ne se joue pas (erreur d'import, plantage) ;
`2` rien de probant : instrument faux, suite absente, aucune épreuve jouée, ou moins que son plancher.

CE QU'ELLE NE TIENT PAS
-----------------------
Elle ne juge pas ce que les épreuves couvrent : une règle de l'outil sans épreuve reste sans témoin
ici. Elle ne lance que les suites nommées dans `SUITES`.
"""
import os
import re
import subprocess
import sys
import tempfile

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
ETIQUETTE = "[epreuves-des-langues]"

# (suite, plancher d'épreuves jouées, ce qu'elle éprouve). Planchers relevés à l'écriture de la garde :
# 104 épreuves pour l'outil de parité, 13 pour le générateur du banc.
SUITES = (
    (".github/scripts/test_parite_des_langues.py", 95, "l'outil de parité des langues"),
    ("bench/test_report_langues.py", 12, "les deux langues du générateur du banc"),
)

JOUEES = re.compile(r"^Ran (\d+) tests? in ", re.M)


def lire_le_resultat(code, sortie, plancher):
    """(code de la garde, motif) pour une suite unittest qui a rendu `code` et écrit `sortie`."""
    m = JOUEES.search(sortie)
    jouees = int(m.group(1)) if m else None
    if jouees == 0:
        return 2, "aucune épreuve jouée"
    if code != 0:
        if jouees is None:
            return 1, f"la suite ne s'est pas jouée (code {code}) : {dernieres_lignes(sortie)}"
        return 1, f"{jouees} épreuve(s) jouée(s), en échec (code {code}) : {dernieres_lignes(sortie)}"
    if jouees is None:
        return 2, "aucun compte d'épreuves lu dans la sortie"
    if jouees < plancher:
        return 2, f"{jouees} épreuve(s) jouée(s), plancher {plancher} : la suite a maigri ou n'est plus découverte"
    return 0, f"{jouees} épreuve(s), toutes passées"


def dernieres_lignes(sortie, n=4):
    return " | ".join(l.strip() for l in sortie.strip().splitlines()[-n:])


def jouer(chemin, racine):
    """(code, sortie) de la suite `chemin`, jouée depuis `racine` ; None si elle n'existe pas."""
    complet = os.path.join(racine, chemin)
    if not os.path.isfile(complet):
        return None
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    r = subprocess.run([sys.executable, complet], cwd=racine, capture_output=True, text=True, env=env,
                       timeout=900)
    return r.returncode, r.stdout + r.stderr


def juger(suites, racine):
    """(code, lignes) pour les `suites` sous `racine`. Un échec quelque part rend 1, même si une autre
    suite n'a rien prouvé."""
    codes, lignes = [], []
    for chemin, plancher, quoi in suites:
        resultat = jouer(chemin, racine)
        if resultat is None:
            code, motif = 2, "suite absente"
        else:
            code, motif = lire_le_resultat(*resultat, plancher)
        codes.append(code)
        prefixe = "::error::" if code else ""
        lignes.append(f"{prefixe}{ETIQUETTE} {chemin} ({quoi}) : {motif}")
    if 1 in codes:
        return 1, lignes + [f"{ETIQUETTE} ÉCHEC — une suite au moins échoue : l'outil ne tient plus ce que "
                            f"ses épreuves disent."]
    if 2 in codes:
        return 2, lignes + [f"{ETIQUETTE} REFUSE DE CONCLURE — une suite au moins n'a rien prouvé."]
    return 0, lignes + [f"{ETIQUETTE} OK — {len(suites)} suite(s), toutes passées au-dessus de leur plancher."]


ENTETE = "import unittest\n"
PIED = "\nif __name__ == '__main__':\n    unittest.main()\n"
FABRIQUEES = {
    "passe.py": ENTETE + "class T(unittest.TestCase):\n    def test_a(self): pass\n    def test_b(self): pass\n" + PIED,
    "echoue.py": ENTETE + "class T(unittest.TestCase):\n    def test_a(self): pass\n    def test_b(self): self.fail('x')\n" + PIED,
    "import_casse.py": "import module_qui_n_existe_pas\n" + ENTETE + PIED,
    "vide.py": ENTETE + PIED,
}


def valider_instrument():
    """TÉMOINS de la lecture d'une suite, sur des suites fabriquées."""
    cas = [
        ("suite qui passe", [("passe.py", 2, "t")], 0),
        ("suite qui échoue", [("echoue.py", 1, "t")], 1),
        ("suite qui ne s'importe pas", [("import_casse.py", 1, "t")], 1),
        ("suite sous son plancher", [("passe.py", 3, "t")], 2),
        ("suite sans épreuve", [("vide.py", 1, "t")], 2),
        ("suite absente", [("absente.py", 1, "t")], 2),
        ("un échec l'emporte sur un refus", [("vide.py", 1, "t"), ("echoue.py", 1, "t")], 1),
    ]
    echecs = []
    with tempfile.TemporaryDirectory() as racine:
        for nom, texte in FABRIQUEES.items():
            with open(os.path.join(racine, nom), "w", encoding="utf-8") as f:
                f.write(texte)
        for nom, suites, attendu in cas:
            code, lignes = juger(suites, racine)
            if code != attendu:
                echecs.append(f"témoin « {nom} » : code {code}, attendu {attendu} — {lignes[0]}")
    return echecs


def main():
    echecs = valider_instrument()
    if echecs:
        print(f"{ETIQUETTE} REFUSE DE CONCLURE — l'INSTRUMENT est faux, aucun verdict :")
        for e in echecs:
            print(f"    - {e}")
        return 2
    code, lignes = juger(SUITES, RACINE)
    for ligne in lignes:
        print(ligne)
    return code


if __name__ == "__main__":
    sys.exit(main())
