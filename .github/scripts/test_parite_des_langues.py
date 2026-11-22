#!/usr/bin/env python3
"""Épreuves de `parite_des_langues.py` sur de petites paires fabriquées.

Une paire juste doit rendre vert, et chaque défaut qu'une traduction peut introduire sans que sa
relecture le voie doit rendre rouge, nommé par sa famille et par `fichier:ligne`. Les paires vivent
dans un répertoire temporaire ; l'arbre du dépôt n'est jamais lu.

    python3 .github/scripts/test_parite_des_langues.py
"""
import os
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import parite_des_langues as pdl  # noqa: E402

ORIGINAL = """\
# Guide

Le budget est de 2,7 Gio, mesuré sur 4 812 337 lignes.

## Installer

```sh
# commentaire libre
cargo test --locked   # suite par défaut
```

Voir [la carte](carte.md#sous-systemes) et [le schéma](schema.md).

| clé | valeur |
|---|---|
| `EXPECTED_TESTS` | ci.yml |

### Détail

Lire `daemon/Cargo.toml` d'abord.
"""

TRADUCTION = """\
# Guide

The budget is 2.7 GiB, measured on 4,812,337 lines.

## Install

```sh
# free comment, translated
cargo test --locked   # default suite
```

See [the map](carte.en.md#subsystems) and [the schema](schema.md).

| key | value |
|---|---|
| `EXPECTED_TESTS` | ci.yml |

### Detail

Read `daemon/Cargo.toml` first.
"""


class Paire(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.racine = self._tmp.name
        # carte.md a sa traduction, schema.md n'en a pas : un lien bascule, l'autre non.
        for nom in ("carte.md", "carte.en.md", "schema.md"):
            self.ecrire(nom, "# x\n")

    def tearDown(self):
        self._tmp.cleanup()

    def ecrire(self, nom, texte):
        chemin = os.path.join(self.racine, nom)
        os.makedirs(os.path.dirname(chemin), exist_ok=True)
        with open(chemin, "w", encoding="utf-8") as f:
            f.write(texte)

    def ecarts(self, traduction, original=ORIGINAL, convention=None):
        convention = convention or pdl.Convention()
        o = "guide" + convention.original + ".md"
        t = "guide" + convention.traduction + ".md"
        self.ecrire(o, original)
        self.ecrire(t, traduction)
        return pdl.comparer_fichiers(self.racine, o, t, convention)

    def familles(self, ecarts):
        return sorted({e.famille for e in ecarts})

    def test_paire_juste_verte(self):
        self.assertEqual(self.ecarts(TRADUCTION), [])

    def test_titre_manquant_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("### Detail\n", ""))
        self.assertEqual(self.familles(ecarts), ["titres"])
        self.assertEqual(str(ecarts[0]).split(" [")[0], "guide.md:18:")

    def test_niveau_de_titre_change_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("### Detail", "## Detail"))
        self.assertEqual(self.familles(ecarts), ["titres"])
        self.assertIn("guide.en.md:18", ecarts[0].message)

    def test_commande_modifiee_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("cargo test --locked", "cargo test"))
        self.assertEqual(self.familles(ecarts), ["blocs"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.md", 9))

    def test_commande_ajoutee_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("cargo test --locked   # default suite\n",
                                                "cargo test --locked\ncargo clippy\n"))
        self.assertEqual(self.familles(ecarts), ["blocs"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.en.md", 10))

    def test_bloc_de_code_retire_rouge(self):
        sans_bloc = TRADUCTION.replace("```sh\n# free comment, translated\n"
                                       "cargo test --locked   # default suite\n```\n", "")
        self.assertIn("blocs", self.familles(self.ecarts(sans_bloc)))

    def test_nombre_change_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("4,812,337", "4,812,373"))
        self.assertEqual(self.familles(ecarts), ["nombres"])
        lieux = {(e.fichier, e.ligne) for e in ecarts}
        self.assertEqual(lieux, {("guide.md", 3), ("guide.en.md", 3)})

    def test_lien_non_bascule_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("carte.en.md#subsystems", "carte.md#subsystems"))
        self.assertEqual(self.familles(ecarts), ["liens"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.en.md", 12))
        self.assertIn("non basculé", ecarts[0].message)

    def test_lien_bascule_sans_traduction_existante_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("schema.md", "schema.en.md"))
        self.assertEqual(self.familles(ecarts), ["liens"])

    def test_ligne_de_tableau_retiree_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("| `EXPECTED_TESTS` | ci.yml |\n", ""))
        self.assertIn("tableaux", self.familles(ecarts))
        self.assertIn("identifiants", self.familles(ecarts))

    def test_identifiant_change_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("`daemon/Cargo.toml`", "`daemon/Cargo.lock`"))
        self.assertEqual(self.familles(ecarts), ["identifiants"])

    def test_commentaire_html_et_url_ne_comptent_pas(self):
        original = ORIGINAL + "\n<!-- note 42 -->\nSource : https://example.org/v7\n"
        traduction = TRADUCTION + "\nSource: https://example.org/v7\n"
        self.assertEqual(self.ecarts(traduction, original), [])

    def test_convention_basculee(self):
        convention = pdl.Convention(".fr", "")
        # carte.fr.md a sa traduction carte.md ; annexe.fr.md n'en a pas.
        for nom in ("carte.fr.md", "annexe.fr.md"):
            self.ecrire(nom, "# x\n")
        original = ORIGINAL.replace("carte.md", "carte.fr.md").replace("schema.md", "annexe.fr.md")
        juste = TRADUCTION.replace("carte.en.md", "carte.md").replace("schema.md", "annexe.fr.md")
        self.assertEqual(self.ecarts(juste, original, convention), [])
        ecarts = self.ecarts(juste.replace("(carte.md", "(carte.fr.md"), original, convention)
        self.assertIn("non basculé", ecarts[0].message)


class Convention(unittest.TestCase):
    def test_suffixes(self):
        c = pdl.Convention()
        self.assertTrue(c.est_original("docs/X.md"))
        self.assertFalse(c.est_original("docs/X.en.md"))
        self.assertTrue(c.est_traduction("docs/X.en.md"))
        self.assertEqual(c.traduction_de("docs/X.md"), "docs/X.en.md")
        b = pdl.Convention(".fr", "")
        self.assertTrue(b.est_original("X.fr.md"))
        self.assertFalse(b.est_original("X.md"))
        self.assertTrue(b.est_traduction("X.md"))
        self.assertFalse(b.est_traduction("X.fr.md"))
        self.assertEqual(b.traduction_de("X.fr.md"), "X.md")

    def test_suffixes_identiques_refuses(self):
        with self.assertRaises(ValueError):
            pdl.Convention(".en", ".en")


class Inventaire(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.racine = self._tmp.name
        for nom in ("A.md", "A.en.md", "B.md", "docs/C.md", "D.en.md"):
            chemin = os.path.join(self.racine, nom)
            os.makedirs(os.path.dirname(chemin), exist_ok=True)
            with open(chemin, "w", encoding="utf-8") as f:
                f.write("# x\n")
        subprocess.run(["git", "init", "-q", self.racine], check=True)
        subprocess.run(["git", "-C", self.racine, "add", "--", "A.md", "A.en.md", "B.md",
                        "docs/C.md", "D.en.md"], check=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_liste_sans_rougir_puis_rougit_en_strict(self):
        documents = pdl.documents_suivis(self.racine)
        sans, orphelines = pdl.inventaire(documents, pdl.Convention())
        self.assertEqual(sans, ["B.md", "docs/C.md"])
        self.assertEqual(orphelines, ["D.en.md"])
        with open(os.devnull, "w") as nul:
            sortie, sys.stdout = sys.stdout, nul
            try:
                self.assertEqual(pdl.main(["--racine", self.racine, "--inventaire"]), 0)
                self.assertEqual(pdl.main(["--racine", self.racine, "--inventaire", "--strict"]), 1)
                self.assertEqual(pdl.main(["--racine", self.racine]), 0)
            finally:
                sys.stdout = sortie

    def test_aucune_paire_ne_rend_pas_vert(self):
        os.remove(os.path.join(self.racine, "A.en.md"))
        subprocess.run(["git", "-C", self.racine, "rm", "-q", "--cached", "A.en.md"], check=True)
        with open(os.devnull, "w") as nul:
            erreur, sys.stderr = sys.stderr, nul
            try:
                self.assertEqual(pdl.main(["--racine", self.racine]), 2)
            finally:
                sys.stderr = erreur


if __name__ == "__main__":
    unittest.main()
