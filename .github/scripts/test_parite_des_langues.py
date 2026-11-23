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

SELECTEUR = "[Français](guide.md) | [English](guide.en.md)"
SELECTEUR_BASCULE = "[Français](guide.fr.md) | [English](guide.md)"

ORIGINAL = """\
# Guide

[Français](guide.md) | [English](guide.en.md)

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

[Français](guide.md) | [English](guide.en.md)

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


CARTE = "# Sous-systèmes\n"
CARTE_EN = "# Subsystems\n"


class Paire(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.racine = self._tmp.name
        # carte.md a sa traduction, schema.md n'en a pas : un lien bascule, l'autre non. Le titre de
        # carte.en.md porte l'ancre `#subsystems` que la traduction vise.
        for nom, texte in (("carte.md", CARTE), ("carte.en.md", CARTE_EN), ("schema.md", "# x\n")):
            self.ecrire(nom, texte)

    def tearDown(self):
        self._tmp.cleanup()

    def ecrire(self, nom, texte):
        chemin = os.path.join(self.racine, nom)
        os.makedirs(os.path.dirname(chemin), exist_ok=True)
        with open(chemin, "w", encoding="utf-8") as f:
            f.write(texte)

    def ecarts(self, traduction, original=ORIGINAL, convention=None, dossier=""):
        convention = convention or pdl.Convention()
        o = os.path.join(dossier, "guide" + convention.original + ".md")
        t = os.path.join(dossier, "guide" + convention.traduction + ".md")
        self.ecrire(o, original)
        self.ecrire(t, traduction)
        return pdl.comparer_fichiers(self.racine, o, t, convention)

    def peupler_docs(self):
        """Sous docs/, les cibles relatives de la paire de base : carte bascule, schema non."""
        for nom, texte in (("docs/carte.md", CARTE), ("docs/carte.en.md", CARTE_EN),
                           ("docs/schema.md", "# x\n")):
            self.ecrire(nom, texte)

    def familles(self, ecarts):
        return sorted({e.famille for e in ecarts})

    def test_paire_juste_verte(self):
        self.assertEqual(self.ecarts(TRADUCTION), [])

    def test_titre_manquant_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("### Detail\n", ""))
        self.assertEqual(self.familles(ecarts), ["titres"])
        self.assertEqual(str(ecarts[0]).split(" [")[0], "guide.md:20:")

    def test_niveau_de_titre_change_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("### Detail", "## Detail"))
        self.assertEqual(self.familles(ecarts), ["titres"])
        self.assertIn("guide.en.md:20", ecarts[0].message)

    def test_commande_modifiee_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("cargo test --locked", "cargo test"))
        self.assertEqual(self.familles(ecarts), ["blocs"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.md", 11))

    def test_commande_ajoutee_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("cargo test --locked   # default suite\n",
                                                "cargo test --locked\ncargo clippy\n"))
        self.assertEqual(self.familles(ecarts), ["blocs"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.en.md", 12))

    def test_bloc_de_code_retire_rouge(self):
        sans_bloc = TRADUCTION.replace("```sh\n# free comment, translated\n"
                                       "cargo test --locked   # default suite\n```\n", "")
        self.assertIn("blocs", self.familles(self.ecarts(sans_bloc)))

    def test_nombre_change_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("4,812,337", "4,812,373"))
        self.assertEqual(self.familles(ecarts), ["nombres"])
        lieux = {(e.fichier, e.ligne) for e in ecarts}
        self.assertEqual(lieux, {("guide.md", 5), ("guide.en.md", 5)})

    def test_lien_non_bascule_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("carte.en.md#subsystems", "carte.md#subsystems"))
        # L'ancre est jugée contre le fichier réellement visé, carte.md, qui n'a pas ce titre.
        self.assertEqual(self.familles(ecarts), ["ancres", "liens"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.en.md", 14))
        self.assertIn("non basculé", ecarts[0].message)

    def test_lien_bascule_sans_traduction_existante_rouge(self):
        # Les deux sens sont nommés : la cible attendue manque, la cible portée est en trop.
        ecarts = self.ecarts(TRADUCTION.replace("schema.md", "schema.en.md"))
        self.assertEqual(self.familles(ecarts), ["liens"])
        lus = sorted((e.fichier, e.ligne, e.message) for e in ecarts)
        self.assertEqual(lus, [
            ("guide.en.md", 14, "lien vers « schema.en.md » absent de l'original"),
            ("guide.md", 14, "lien vers « schema.md » absent de la traduction"),
        ])

    def test_lien_en_trop_dans_la_traduction_rouge(self):
        ecarts = self.ecarts(TRADUCTION + "\nSee [the annex](annexe.md).\n")
        self.assertEqual([(e.fichier, e.ligne, e.message) for e in ecarts],
                         [("guide.en.md", 24, "lien vers « annexe.md » absent de l'original")])

    def test_bloc_en_trop_dans_la_traduction_rouge(self):
        ecarts = self.ecarts(TRADUCTION + "\n```sh\nmake extra\n```\n")
        self.assertEqual(self.familles(ecarts), ["blocs"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.en.md", 24))
        self.assertIn("2 blocs de code contre 1 dans guide.md", ecarts[0].message)

    def test_tableau_en_trop_dans_la_traduction_rouge(self):
        ecarts = self.ecarts(TRADUCTION + "\n| a | b |\n|---|---|\n")
        self.assertEqual(self.familles(ecarts), ["tableaux"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.en.md", 24))
        self.assertIn("2 tableaux contre 1 dans guide.md", ecarts[0].message)

    def test_lien_relatif_resolu_depuis_le_dossier_du_document(self):
        # docs/plan.md a sa traduction ; à la racine, plan.en.md n'existe pas. Résolu depuis la
        # racine, le lien ne basculerait pas, et la traduction juste serait accusée.
        self.peupler_docs()
        for nom in ("docs/plan.md", "docs/plan.en.md"):
            self.ecrire(nom, "# x\n")
        original = ORIGINAL + "\nVoir [le plan](plan.md).\n"
        juste = TRADUCTION + "\nSee [the plan](plan.en.md).\n"
        self.assertEqual(self.ecarts(juste, original, dossier="docs"), [])
        ecarts = self.ecarts(juste.replace("plan.en.md", "plan.md"), original, dossier="docs")
        self.assertEqual(self.familles(ecarts), ["liens"])
        self.assertIn("non basculé", ecarts[0].message)
        self.assertEqual(ecarts[0].fichier, os.path.join("docs", "guide.en.md"))

    def test_lien_absolu_resolu_depuis_la_racine(self):
        # annexe.en.md existe à la racine, pas sous docs/ : `/annexe.md` bascule depuis docs/.
        self.peupler_docs()
        for nom in ("annexe.md", "annexe.en.md", "docs/annexe.md"):
            self.ecrire(nom, "# x\n")
        original = ORIGINAL + "\nVoir [l'annexe](/annexe.md).\n"
        juste = TRADUCTION + "\nSee [the annex](/annexe.en.md).\n"
        self.assertEqual(self.ecarts(juste, original, dossier="docs"), [])
        ecarts = self.ecarts(juste.replace("/annexe.en.md", "/annexe.md"), original, dossier="docs")
        self.assertEqual(self.familles(ecarts), ["liens"])
        self.assertIn("non basculé", ecarts[0].message)

    def test_selecteur_de_langue_identique_des_deux_cotes(self):
        # Le sélecteur vise le document lui-même et sa traduction : il est le même des deux côtés,
        # et ses liens ne basculent pas (la paire de base le porte et rend vert).
        self.assertIn(SELECTEUR, ORIGINAL)
        self.assertEqual(self.ecarts(TRADUCTION), [])
        # Depuis un sous-dossier, la cible relative désigne la même paire.
        self.peupler_docs()
        self.assertEqual(self.ecarts(TRADUCTION, dossier="docs"), [])
        # Un lien vers un AUTRE document non basculé reste accusé, sélecteur présent.
        ecarts = self.ecarts(TRADUCTION.replace("carte.en.md#", "carte.md#"))
        self.assertIn("liens", self.familles(ecarts))
        self.assertIn("non basculé", next(e for e in ecarts if e.famille == "liens").message)

    def test_selecteur_de_langue_convention_basculee(self):
        convention = pdl.Convention(".fr", "")
        for nom in ("carte.fr.md", "annexe.fr.md"):
            self.ecrire(nom, "# x\n")
        self.ecrire("carte.md", CARTE_EN)
        original = ORIGINAL.replace(SELECTEUR, SELECTEUR_BASCULE).replace(
            "carte.md", "carte.fr.md").replace("schema.md", "annexe.fr.md")
        juste = TRADUCTION.replace(SELECTEUR, SELECTEUR_BASCULE).replace(
            "carte.en.md", "carte.md").replace("schema.md", "annexe.fr.md")
        self.assertEqual(self.ecarts(juste, original, convention), [])
        # Le sélecteur de l'ancienne convention vise un fichier qui n'est plus de la paire.
        # Ses deux liens diffèrent de ceux de l'original : la famille des liens le dit aussi.
        ecarts = self.ecarts(juste.replace(SELECTEUR_BASCULE, SELECTEUR), original, convention)
        selecteur = [e for e in ecarts if e.famille == "sélecteur"]
        self.assertEqual([(e.fichier, e.ligne) for e in selecteur], [("guide.md", 3)])
        self.assertIn("attendu « guide.fr.md » puis « guide.md »", selecteur[0].message)
        self.assertEqual(self.familles(ecarts), ["liens", "sélecteur"])

    def test_selecteur_original_anglais_nomme_l_original_d_abord(self):
        # Original anglais `X.md`, traduction `X.fr.md` : l'anglais vient en premier.
        convention = pdl.Convention("", ".fr")
        self.ecrire("carte.fr.md", CARTE_EN)
        selecteur = "[English](guide.md) | [Français](guide.fr.md)"
        original = ORIGINAL.replace(SELECTEUR, selecteur).replace("carte.md#sous-systemes",
                                                                   "carte.md#x")
        juste = TRADUCTION.replace(SELECTEUR, selecteur).replace("carte.en.md", "carte.fr.md")
        self.assertEqual(self.ecarts(juste, original, convention), [])
        inverse = "[Français](guide.fr.md) | [English](guide.md)"
        ecarts = self.ecarts(juste.replace(selecteur, inverse), original, convention)
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.fr.md", 3, "sélecteur")])
        self.assertIn("inversé", ecarts[0].message)

    def test_selecteur_absent_des_deux_cotes_rouge(self):
        sans = SELECTEUR + "\n\n"
        ecarts = self.ecarts(TRADUCTION.replace(sans, ""), ORIGINAL.replace(sans, ""))
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.md", 3, "sélecteur"), ("guide.en.md", 3, "sélecteur")])
        self.assertIn("absent sous le titre de niveau 1 (ligne 1)", ecarts[0].message)
        self.assertIn("« guide.md » puis « guide.en.md »", ecarts[0].message)

    def test_selecteur_absent_d_un_cote_rouge(self):
        # Ses deux liens manquent d'un côté : la famille des liens le dit aussi.
        for traduction, original, fautif in (
                (TRADUCTION.replace(SELECTEUR + "\n\n", ""), ORIGINAL, "guide.en.md"),
                (TRADUCTION, ORIGINAL.replace(SELECTEUR + "\n\n", ""), "guide.md")):
            ecarts = self.ecarts(traduction, original)
            self.assertEqual([(e.fichier, e.ligne) for e in ecarts if e.famille == "sélecteur"],
                             [(fautif, 3)])
            self.assertEqual(self.familles(ecarts), ["liens", "sélecteur"])

    def test_selecteur_inverse_dans_la_traduction_rouge(self):
        # Mêmes cibles, donc aucun écart de lien : seul l'ordre trahit l'inversion.
        inverse = "[English](guide.en.md) | [Français](guide.md)"
        ecarts = self.ecarts(TRADUCTION.replace(SELECTEUR, inverse))
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.en.md", 3, "sélecteur")])
        self.assertIn("inversé", ecarts[0].message)

    def test_selecteur_qui_vise_un_autre_fichier_rouge(self):
        autre = "[Français](carte.md) | [English](carte.en.md)"
        ecarts = self.ecarts(TRADUCTION.replace(SELECTEUR, autre), ORIGINAL.replace(SELECTEUR, autre))
        selecteur = [e for e in ecarts if e.famille == "sélecteur"]
        self.assertEqual([(e.fichier, e.ligne) for e in selecteur],
                         [("guide.md", 3), ("guide.en.md", 3)])
        self.assertIn("vise carte.md, carte.en.md", selecteur[0].message)
        # Un seul lien, vers l'original : la traduction manque au sélecteur.
        seul = "[Français](guide.md)"
        ecarts = self.ecarts(TRADUCTION.replace(SELECTEUR, seul), ORIGINAL.replace(SELECTEUR, seul))
        self.assertEqual(self.familles(ecarts), ["sélecteur"])
        self.assertEqual(len(ecarts), 2)

    def test_selecteur_different_d_un_cote_a_l_autre_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("[Français]", "[French]", 1))
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.en.md", 3, "sélecteur")])
        self.assertIn("différent de celui de l'original (guide.md:3)", ecarts[0].message)

    def test_selecteur_pas_juste_sous_le_titre_rouge(self):
        # Une phrase s'intercale : la ligne sous le titre n'est pas un sélecteur.
        intercale = "Lire en : " + SELECTEUR
        ecarts = self.ecarts(TRADUCTION.replace(SELECTEUR, intercale),
                             ORIGINAL.replace(SELECTEUR, intercale))
        self.assertEqual(self.familles(ecarts), ["sélecteur"])
        self.assertEqual(len(ecarts), 2)
        ecarts = self.ecarts(TRADUCTION.replace("# Guide\n\n", "# Guide\n\nIntro.\n\n", 1),
                             ORIGINAL.replace("# Guide\n\n", "# Guide\n\nIntro.\n\n", 1))
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.md", 3, "sélecteur"), ("guide.en.md", 3, "sélecteur")])

    def test_segment_de_code_replie_lu_comme_un_seul(self):
        # CommonMark : dans un paragraphe, la fin de ligne d'un segment de code vaut une espace.
        original = ORIGINAL + "\nLancer `cargo test\n--locked` puis lire.\n"
        juste = TRADUCTION + "\nRun `cargo test --locked` then read.\n"
        self.assertEqual(self.ecarts(juste, original), [])
        # Replié ailleurs dans la traduction : toujours le même segment.
        self.assertEqual(self.ecarts(TRADUCTION + "\nRun `cargo\ntest --locked` then read.\n",
                                     original), [])
        ecarts = self.ecarts(juste.replace("cargo test --locked` then", "cargo test` then"), original)
        self.assertEqual(self.familles(ecarts), ["identifiants"])
        self.assertIn(("guide.md", 24, "identifiant « cargo test --locked » absent de la traduction"),
                      [(e.fichier, e.ligne, e.message) for e in ecarts])

    def test_segment_de_code_replie_dans_une_citation(self):
        # La forme de docs/CIM.md : le mot qui suit le segment replié n'est pas un identifiant.
        original = ORIGINAL + "\n> Ingérés : `search a |\n> stats b` rendait `x 2`.\n"
        juste = TRADUCTION + "\n> Ingested: `search a |\n> stats b` returned `x 2`.\n"
        self.assertEqual(self.ecarts(juste, original), [])
        self.assertEqual(self.ecarts(TRADUCTION + "\n> Ingested: `search a | stats b` returned "
                                     "`x 2`.\n", original), [])

    def test_accent_grave_seul_ne_traverse_pas_le_paragraphe(self):
        # Un accent grave que rien ne ferme dans son paragraphe est du texte : la ligne vide, le
        # titre et la puce de liste arrêtent la recherche de sa fermeture.
        for coupure in ("\n", "## Suite\n", "- puce\n"):
            original = ORIGINAL + f"\nUn accent ` seul.\n{coupure}Puis `x` et ` y.\n"
            juste = TRADUCTION + f"\nA lone ` accent.\n{coupure}Then `x` and ` y.\n"
            self.assertEqual(self.ecarts(juste, original), [], coupure)
            ecarts = self.ecarts(juste.replace("`x`", "`z`"), original)
            self.assertEqual(self.familles(ecarts), ["identifiants"], coupure)

    def test_ancre_vers_un_titre_traduit_verte(self):
        # La paire de base vise `carte.en.md#subsystems`, titre réel de carte.en.md.
        self.assertIn("carte.en.md#subsystems", TRADUCTION)
        self.assertEqual(self.ecarts(TRADUCTION), [])

    def test_ancre_changee_d_une_lettre_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("#subsystems", "#subsystem"))
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.en.md", 14, "ancres")])
        self.assertIn("ancre « #subsystem » : aucun titre de carte.en.md", ecarts[0].message)

    def test_ancre_restee_sur_le_titre_francais_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("#subsystems", "#sous-systèmes"))
        self.assertEqual(self.familles(ecarts), ["ancres"])
        self.assertIn("titre de l'original carte.md : viser le titre traduit", ecarts[0].message)
        # Encodée en pourcent, l'ancre désigne le même titre.
        ecarts = self.ecarts(TRADUCTION.replace("#subsystems", "#sous-syst%C3%A8mes"))
        self.assertIn("titre de l'original carte.md", ecarts[0].message)

    def test_ancre_dans_le_document_lui_meme(self):
        juste = TRADUCTION + "\nBack to [the detail](#detail).\n"
        original = ORIGINAL + "\nRetour au [détail](#détail).\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("(#detail)", "(#détail)"), original)
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.en.md", 24, "ancres")])
        self.assertIn("l'original guide.md", ecarts[0].message)

    def test_slug_github(self):
        # Minuscules, ponctuation retirée, espaces en tirets, accents conservés, contenu des
        # segments de code gardé, emoji retiré, `_` gardé, séquence de clôture ôtée.
        cas = {
            "Étape 2 : l'installation (rapide)": "étape-2--linstallation-rapide",
            "⚠️ `PLUME_*` — variables": "-plume_--variables",
            "3. L'authentification, et ce que « lié à l'hôte » veut dire":
                "3-lauthentification-et-ce-que--lié-à-lhôte--veut-dire",
            "Voir [la carte](carte.md) **vite** ##": "voir-la-carte-vite",
            "1.1 `a.b` <br> fin": "11-ab--fin",
        }
        for titre, attendu in cas.items():
            self.assertEqual(pdl.slug(titre), attendu, titre)

    def test_ancre_de_titre_en_double(self):
        self.ecrire("carte.en.md", "# Subsystems\n\n## Usage\n\n## Usage\n")
        self.ecrire("carte.md", "# Sous-systèmes\n\n## Usage\n\n## Usage\n")
        original = ORIGINAL + "\nVoir [le second](carte.md#usage-1).\n"
        juste = TRADUCTION + "\nSee [the second](carte.en.md#usage-1).\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("#usage-1", "#usage-2"), original)
        self.assertEqual(self.familles(ecarts), ["ancres"])

    def test_ancre_html_et_titre_souligne_existent(self):
        self.ecrire("carte.en.md", CARTE_EN + "\n<a id=\"pin\"></a>\n\nUnderlined\n----------\n")
        for ancre in ("pin", "underlined"):
            original = ORIGINAL + f"\nVoir [ici](carte.md#{ancre}).\n"
            juste = TRADUCTION + f"\nSee [here](carte.en.md#{ancre}).\n"
            self.assertEqual(self.ecarts(juste, original), [], ancre)

    def test_ancres_non_jugees(self):
        # L'original n'est pas jugé ; ni une cible qui n'est pas un document Markdown de l'arbre ;
        # ni une ancre en majuscules (la casse n'est pas tranchée).
        original = ORIGINAL.replace("#sous-systemes", "#nulle-part") + (
            "\nVoir [s](script.sh#L3), [a](absent.md#x) et [e](https://example.org/a.md#z).\n")
        juste = TRADUCTION.replace("#subsystems", "#Subsystems") + (
            "\nSee [s](script.sh#L3), [a](absent.md#x) and [e](https://example.org/a.md#z).\n")
        self.assertEqual(self.ecarts(juste, original), [])

    def test_ancre_dans_une_definition_de_lien(self):
        original = ORIGINAL + "\nVoir [la carte][r].\n\n[r]: carte.md#sous-systemes\n"
        juste = TRADUCTION + "\nSee [the map][r].\n\n[r]: carte.en.md#subsystems\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("[r]: carte.en.md#subsystems", "[r]: carte.en.md#maps"),
                             original)
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.en.md", 26, "ancres")])

    def test_note_de_bas_de_page_n_est_pas_une_definition_de_lien(self):
        original = ORIGINAL + "\nVoir la note[^1].\n\n[^1]: Voir le manuel, page 12.\n"
        juste = TRADUCTION + "\nSee the note[^1].\n\n[^1]: See the manual, page 12.\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("page 12", "page 13"), original)
        self.assertEqual(self.familles(ecarts), ["nombres"])

    def test_bom_ne_masque_pas_le_premier_titre(self):
        self.assertEqual(self.ecarts(TRADUCTION, "\ufeff" + ORIGINAL), [])
        ecarts = self.ecarts(TRADUCTION.replace("# Guide\n", "Guide\n", 1), "\ufeff" + ORIGINAL)
        # Sans titre de niveau 1, le sélecteur n'a plus de place : les deux écarts sont nommés.
        self.assertEqual(self.familles(ecarts), ["sélecteur", "titres"])

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
        # une URL nue n'est pas comparée comme cible de lien, donc aucun écart de lien non plus.
        original = ORIGINAL + "\n<!-- note 42 -->\nSource : https://example.org/fr/v83\n"
        traduction = TRADUCTION + "\nSource: https://example.org/en/v91\n"
        self.assertEqual(self.ecarts(traduction, original), [])

    def test_titre_en_trop_rouge(self):
        ecarts = self.ecarts(TRADUCTION + "\n## Extra\n")
        self.assertEqual(self.familles(ecarts), ["titres"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.en.md", 24))

    def test_commande_retiree_d_un_bloc_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("cargo test --locked   # default suite\n", ""))
        self.assertEqual(self.familles(ecarts), ["blocs"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.md", 11))
        self.assertIn("absente", ecarts[0].message)

    def test_tableau_retire_entier_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("| key | value |\n|---|---|\n"
                                                "| `EXPECTED_TESTS` | ci.yml |\n", ""))
        self.assertIn("tableaux", self.familles(ecarts))
        tableaux = [e for e in ecarts if e.famille == "tableaux"]
        self.assertEqual((tableaux[0].fichier, tableaux[0].ligne), ("guide.md", 16))

    def test_lien_retire_de_la_traduction_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("[the schema](schema.md)", "the schema"))
        self.assertEqual(self.familles(ecarts), ["liens"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.md", 14))
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
        self.ecrire("carte.md", CARTE_EN)
        original = ORIGINAL.replace(SELECTEUR, SELECTEUR_BASCULE).replace(
            "carte.md", "carte.fr.md").replace("schema.md", "annexe.fr.md")
        juste = TRADUCTION.replace(SELECTEUR, SELECTEUR_BASCULE).replace(
            "carte.en.md", "carte.md").replace("schema.md", "annexe.fr.md")
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
    """main() : 0 sans écart, 1 dès qu'un écart est nommé, 2 sans écart quand quelque chose n'a pas été lu."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.racine = self._tmp.name
        for nom, texte in (("carte.md", CARTE), ("carte.en.md", CARTE_EN), ("schema.md", "# x\n"),
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
        self.assertIn("guide.md:20: [titres]", sortie)

    def test_fichier_absent_rend_2(self):
        rc, sortie = self.main("--paire", "guide.md", "absent.en.md")
        self.assertEqual(rc, 2)
        self.assertIn("rien comparé", sortie)

    def suivre(self, *fichiers):
        subprocess.run(["git", "init", "-q", self.racine], check=True)
        subprocess.run(["git", "-C", self.racine, "add", "--", *fichiers], check=True)

    def ecrire(self, nom, contenu):
        mode = "wb" if isinstance(contenu, bytes) else "w"
        with open(os.path.join(self.racine, nom), mode,
                  **({} if isinstance(contenu, bytes) else {"encoding": "utf-8"})) as f:
            f.write(contenu)

    def test_illisible_puis_ecart_rend_1_et_nomme_les_deux(self):
        # `autre` se lit avant `guide` : la paire illisible n'arrête pas la comparaison, et l'écart
        # trouvé ensuite est imprimé ; une violation ne se lit pas comme « rien mesuré ».
        self.ecrire("autre.md", "# Autre\n")
        self.ecrire("autre.en.md", "# Autre évalué\n".encode("latin-1"))
        self.ecrire("guide.en.md", TRADUCTION.replace("### Detail\n", ""))
        self.suivre("autre.md", "autre.en.md", "guide.md", "guide.en.md")
        rc, sortie = self.main()
        self.assertEqual(rc, 1)
        self.assertIn("guide.md:20: [titres]", sortie)
        self.assertIn("autre.en.md", sortie)
        self.assertIn("illisible", sortie)

    def test_illisible_sans_ecart_rend_2_et_le_nomme(self):
        self.ecrire("autre.md", "# Autre\n")
        self.ecrire("autre.en.md", "# Autre évalué\n".encode("latin-1"))
        self.suivre("autre.md", "autre.en.md", "guide.md", "guide.en.md")
        rc, sortie = self.main()
        self.assertEqual(rc, 2)
        self.assertIn("autre.en.md", sortie)
        self.assertIn("illisible", sortie)
        self.assertIn("1 paire(s) comparée(s), 0 écart(s)", sortie)

    def test_fichier_hors_utf8_rend_2(self):
        with open(os.path.join(self.racine, "guide.en.md"), "wb") as f:
            f.write("# Guide évalué\n".encode("latin-1"))
        rc, sortie = self.main("--paire", "guide.md", "guide.en.md")
        self.assertEqual(rc, 2)
        self.assertIn("rien comparé", sortie)

    def test_selecteur_absent_rend_1_et_le_nomme(self):
        self.ecrire("guide.en.md", TRADUCTION.replace(SELECTEUR + "\n\n", ""))
        rc, sortie = self.main("--paire", "guide.md", "guide.en.md")
        self.assertEqual(rc, 1)
        self.assertIn("guide.en.md:3: [sélecteur] sélecteur de langue absent", sortie)

    def test_ancre_fausse_rend_1_et_la_nomme(self):
        self.ecrire("guide.en.md", TRADUCTION.replace("#subsystems", "#subsystem"))
        rc, sortie = self.main("--paire", "guide.md", "guide.en.md")
        self.assertEqual(rc, 1)
        self.assertIn("guide.en.md:14: [ancres] ancre « #subsystem »", sortie)

    def test_fichier_vise_par_une_ancre_illisible_rend_2(self):
        # Une ancre qu'on n'a pas pu chercher n'est ni juste ni fausse : rien ne prouve la parité.
        self.ecrire("latin.md", "# Évalué\n".encode("latin-1"))
        self.ecrire("guide.md", ORIGINAL + "\nVoir [l](latin.md#x).\n")
        self.ecrire("guide.en.md", TRADUCTION + "\nSee [l](latin.md#x).\n")
        rc, sortie = self.main("--paire", "guide.md", "guide.en.md")
        self.assertEqual(rc, 2)
        self.assertIn("latin.md", sortie)
        self.assertIn("illisible", sortie)

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
        selecteur = "# x\n\n[Français](A.md) | [English](A.en.md)\n"
        for nom in ("A.md", "A.en.md", "B.md", "docs/C.md", "D.en.md"):
            chemin = os.path.join(self.racine, nom)
            os.makedirs(os.path.dirname(chemin), exist_ok=True)
            with open(chemin, "w", encoding="utf-8") as f:
                f.write(selecteur if nom.startswith("A.") else "# x\n")
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
        attendu = ("B.md: sans traduction (attendue : B.en.md)\n"
                   "docs/C.md: sans traduction (attendue : docs/C.en.md)\n"
                   "D.en.md: traduction sans original (attendu : D.md)\n"
                   "2 document(s) sans traduction, 1 traduction(s) sans original, "
                   "sur 5 documents suivis\n")
        rc, sortie = muet(pdl.main, ["--racine", self.racine, "--inventaire"])
        self.assertEqual((rc, sortie), (0, attendu))
        rc, sortie = muet(pdl.main, ["--racine", self.racine, "--inventaire", "--strict"])
        self.assertEqual((rc, sortie), (1, attendu))
        self.assertEqual(muet(pdl.main, ["--racine", self.racine])[0], 0)

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
