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
        # Les nombres 42, 83 et 91 n'existent nulle part ailleurs : seule leur exclusion les tait.
        # L'URL diffère d'un côté à l'autre (page localisée) sans que ce soit un écart de nombre ;
        # le lien porte la même cible des deux côtés, donc aucun écart de lien non plus.
        original = ORIGINAL + "\n<!-- note 42 -->\nSource : https://example.org/fr/v83\n"
        traduction = TRADUCTION + "\nSource: https://example.org/en/v91\n"
        self.assertEqual(self.ecarts(traduction, original), [])

    def test_titre_en_trop_rouge(self):
        ecarts = self.ecarts(TRADUCTION + "\n## Extra\n")
        self.assertEqual(self.familles(ecarts), ["titres"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.en.md", 22))

    def test_commande_retiree_d_un_bloc_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("cargo test --locked   # default suite\n", ""))
        self.assertEqual(self.familles(ecarts), ["blocs"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.md", 9))
        self.assertIn("absente", ecarts[0].message)

    def test_tableau_retire_entier_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("| key | value |\n|---|---|\n"
                                                "| `EXPECTED_TESTS` | ci.yml |\n", ""))
        self.assertIn("tableaux", self.familles(ecarts))
        tableaux = [e for e in ecarts if e.famille == "tableaux"]
        self.assertEqual((tableaux[0].fichier, tableaux[0].ligne), ("guide.md", 14))

    def test_lien_retire_de_la_traduction_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("[the schema](schema.md)", "the schema"))
        self.assertEqual(self.familles(ecarts), ["liens"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.md", 12))
        self.assertIn("absent de la traduction", ecarts[0].message)

    def test_definition_de_lien_comparee(self):
        original = ORIGINAL + "\nVoir [la carte][r].\n\n[r]: carte.md\n"
        juste = TRADUCTION + "\nSee [the map][r].\n\n[r]: carte.en.md\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("[r]: carte.en.md", "[r]: carte.md"), original)
        self.assertEqual(self.familles(ecarts), ["liens"])
        self.assertIn("non basculé", ecarts[0].message)

    def test_lien_dans_un_segment_de_code_n_est_pas_un_lien(self):
        # Un exemple de syntaxe cité entre accents graves ne se bascule pas : il reste identique.
        original = ORIGINAL + "\nÉcrire `[x](carte.md)` tel quel.\n"
        traduction = TRADUCTION + "\nWrite `[x](carte.md)` as is.\n"
        self.assertEqual(self.ecarts(traduction, original), [])

    def test_citation_lue_comme_le_texte(self):
        original = ORIGINAL + "\n> ## Note\n>\n> ```sh\n> make check\n> ```\n"
        juste = TRADUCTION + "\n> ## Note\n>\n> ```sh\n> make check\n> ```\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("> make check", "> make"), original)
        self.assertEqual(self.familles(ecarts), ["blocs"])
        ecarts = self.ecarts(juste.replace("> ## Note", "> ### Note"), original)
        self.assertEqual(self.familles(ecarts), ["titres"])

    def test_cloture_plus_courte_ne_ferme_pas_le_bloc(self):
        # Un bloc ouvert par quatre accents graves cite un bloc de trois sans se fermer.
        bloc = "\n````md\n```sh\nmake a\n```\nmake b\n````\n"
        original = ORIGINAL + bloc
        self.assertEqual(self.ecarts(TRADUCTION + bloc, original), [])
        ecarts = self.ecarts(TRADUCTION + bloc.replace("make b", "make c"), original)
        self.assertEqual(self.familles(ecarts), ["blocs"])
        self.assertIn("make b", ecarts[0].message)

    def test_diese_de_code_n_est_pas_un_commentaire(self):
        bloc = "\n```rust\n#[derive(Debug)]\nstruct S;\n```\n"
        original = ORIGINAL + bloc
        self.assertEqual(self.ecarts(TRADUCTION + bloc, original), [])
        ecarts = self.ecarts(TRADUCTION + bloc.replace("Debug", "Clone"), original)
        self.assertEqual(self.familles(ecarts), ["blocs"])

    def test_point_barre_ne_change_pas_la_cible(self):
        juste = TRADUCTION.replace("(carte.en.md#", "(./carte.en.md#").replace("(schema.md)",
                                                                              "(./schema.md)")
        self.assertEqual(self.ecarts(juste), [])

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

    def test_suffixe_mal_forme_refuse(self):
        for mauvais in ("en", ".", ".e n", "../x", ".en.md"):
            with self.assertRaises(ValueError, msg=mauvais):
                pdl.Convention("", mauvais)
        self.assertEqual(muet(pdl.main, ["--suffixe-traduction", "en"])[0], 2)


def muet(fonction, *args):
    """Appelle `fonction` sorties standard et d'erreur détournées ; rend (résultat, sortie)."""
    import io
    sortie, erreur = io.StringIO(), io.StringIO()
    anciens = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = sortie, erreur
    try:
        return fonction(*args), sortie.getvalue() + erreur.getvalue()
    finally:
        sys.stdout, sys.stderr = anciens


class CodeDeSortie(unittest.TestCase):
    """main() : 0 sans écart, 1 au premier écart nommé, 2 quand rien n'a pu être comparé."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.racine = self._tmp.name
        for nom, texte in (("carte.md", "# x\n"), ("carte.en.md", "# x\n"), ("schema.md", "# x\n"),
                           ("guide.md", ORIGINAL), ("guide.en.md", TRADUCTION)):
            with open(os.path.join(self.racine, nom), "w", encoding="utf-8") as f:
                f.write(texte)

    def tearDown(self):
        self._tmp.cleanup()

    def main(self, *args):
        return muet(pdl.main, ["--racine", self.racine, *args])

    def test_paire_juste_rend_0(self):
        rc, _ = self.main("--paire", "guide.md", "guide.en.md")
        self.assertEqual(rc, 0)

    def test_paire_avec_ecart_rend_1_et_le_nomme(self):
        with open(os.path.join(self.racine, "guide.en.md"), "w", encoding="utf-8") as f:
            f.write(TRADUCTION.replace("### Detail\n", ""))
        rc, sortie = self.main("--paire", "guide.md", "guide.en.md")
        self.assertEqual(rc, 1)
        self.assertIn("guide.md:18: [titres]", sortie)

    def test_fichier_absent_rend_2(self):
        rc, sortie = self.main("--paire", "guide.md", "absent.en.md")
        self.assertEqual(rc, 2)
        self.assertIn("rien comparé", sortie)

    def test_fichier_absent_apres_une_paire_juste_rend_2(self):
        # La première paire est juste : un fichier sauté rendrait 0, l'arrêt rend 2.
        rc, _ = self.main("--paire", "absent.md", "guide.en.md")
        self.assertEqual(rc, 2)

    def test_fichier_hors_utf8_rend_2(self):
        with open(os.path.join(self.racine, "guide.en.md"), "wb") as f:
            f.write("# Guide évalué\n".encode("latin-1"))
        rc, sortie = self.main("--paire", "guide.md", "guide.en.md")
        self.assertEqual(rc, 2)
        self.assertIn("rien comparé", sortie)

    def test_depot_illisible_rend_2_meme_en_inventaire(self):
        # `racine` n'est pas un dépôt git : ls-files échoue, ce n'est pas une liste vide.
        self.assertIsNone(pdl.documents_suivis(self.racine))
        for args in ((), ("--inventaire",), ("--inventaire", "--strict")):
            rc, _ = self.main(*args)
            self.assertEqual(rc, 2, args)

    def test_inventaire_sur_zero_document_rend_2(self):
        subprocess.run(["git", "init", "-q", self.racine], check=True)
        for args in (("--inventaire",), ("--inventaire", "--strict")):
            rc, sortie = self.main(*args)
            self.assertEqual(rc, 2, args)
            self.assertIn("aucun document suivi", sortie)


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
