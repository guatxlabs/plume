#!/usr/bin/env python3
"""Épreuves des deux langues de `bench/report.py`.

Le document de mesure est rendu en anglais (`docs/BENCHMARK.md`) et en français
(`docs/BENCHMARK.fr.md`) par la MÊME logique : chaque texte passe par `tr()`, dont la clé est le
texte français, et `TEXTES_EN` porte l'anglais. Deux défauts restent invisibles à la relecture
d'un seul rendu, et ce fichier les rend rouges :

- une clé `tr("…")` posée dans le code sans traduction (le rendu anglais refuserait de tourner),
  ou une traduction qui ne correspond plus à aucune clé (un texte retouché d'un côté seulement),
  ou une traduction qui perd un champ de format ;
- un rendu anglais dont les NOMBRES ou les IDENTIFIANTS diffèrent du rendu français sur les
  mêmes mesures. La comparaison est celle de `.github/scripts/parite_des_langues.py`, importée
  et non recopiée.

Les mesures du second essai sont INVENTÉES (aucune ne vient d'un relevé) et vivent dans un
répertoire temporaire.

    python3 bench/test_report_langues.py
"""
import ast
import collections
import json
import os
import string
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
BANC = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.dirname(BANC)
sys.path.insert(0, BANC)
sys.path.insert(0, os.path.join(RACINE, ".github", "scripts"))
import report  # noqa: E402
import parite_des_langues as pdl  # noqa: E402

GENERATEUR = os.path.join(BANC, "report.py")
MATERIEL_INVENTE = '{"cpu": "cpu-invente", "cores": 3, "mem_gib": 7.5, "kernel": "noyau-invente"}'


def cles_du_code(chemin=GENERATEUR):
    """Les clés françaises : le premier argument littéral de chaque appel `tr(...)`."""
    arbre = ast.parse(lire(chemin))
    cles, non_litterales = set(), []
    for n in ast.walk(arbre):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "tr":
            a = n.args[0] if n.args else None
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                cles.add(a.value)
            else:
                non_litterales.append(n.lineno)
    return cles, non_litterales


def lire(chemin):
    with open(chemin, encoding="utf-8") as fh:
        return fh.read()


def champs(gabarit):
    return sorted((nom, spec, conv) for _, nom, spec, conv in string.Formatter().parse(gabarit)
                  if nom is not None)


def comptes(texte):
    """Nombres et identifiants du texte courant, COMPTÉS (hors blocs de code et commentaires HTML),
    lus avec les motifs de l'outil de parité. L'outil compare des ENSEMBLES, et un ensemble ne voit
    pas une occurrence perdue quand la même valeur figure ailleurs : sur un rendu des mêmes mesures,
    chaque occurrence doit avoir son pendant."""
    nombres, identifiants = collections.Counter(), collections.Counter()
    dans_bloc = dans_commentaire = False
    for ligne in texte.split("\n"):
        if pdl.ouvre_un_bloc(ligne):
            dans_bloc = not dans_bloc
            continue
        if dans_bloc:
            continue
        visible, dans_commentaire = pdl.retirer_commentaires_html(ligne, dans_commentaire)
        for seg in pdl.SEGMENT_DE_CODE.finditer(visible):
            identifiants[seg.group(2).strip()] += 1
        for n in pdl.NOMBRE.findall(pdl.SEGMENT_DE_CODE.sub(" ", visible)):
            nombres[str(int(n))] += 1
    return nombres, identifiants


def mesures_inventees():
    lignes = []
    for cfg, ev, db in (("alpha@0.3M", 314159, 271828183), ("beta@0.9M", 926535, 897932384)):
        for cid, label in (("C0-plancher", "PLANCHER : seek sur une source inexistante (0 ligne)"),
                           ("C2-free-term", "terme libre sur message (compile en LIKE '%…%')")):
            for w, wl in (("1h", "dernière heure"), ("all", "tout")):
                lignes.append(dict(
                    config_id=cfg, class_id=cid, label=label, kind="gxql", window=w, window_label=wl,
                    config=dict(events=ev, db_bytes=db, version="bin:0123456789abcdef", mask="vide",
                                fts_fields=0, cold="off", hosts=7, profile="profile-prod.json"),
                    reps=5, reps_ok=5, wall_p50_ms=12.5 if cid == "C0-plancher" else 4321.0,
                    wall_p95_ms=17.25, sql_p50_ms=3.5, peak_rss_bytes=123456789, read_bytes_first=0,
                    rows=42, served_from="raw", loadavg=[1.25, 1.5, 1.75], swap_delta_bytes=0,
                    measured_at="2026-01-02T03:04:05+0000"))
    return lignes


class LesClesExistentDansLesDeuxLangues(unittest.TestCase):

    def test_chaque_cle_du_code_a_sa_traduction_et_reciproquement(self):
        cles, non_litterales = cles_du_code()
        self.assertEqual(non_litterales, [],
                         "tr() appelé sans littéral : sa clé échappe à l'inventaire (lignes ci-dessus)")
        self.assertGreater(len(cles), 300, "inventaire des clés dégénéré : l'extraction ne voit plus rien")
        sans_anglais = sorted(cles - set(report.TEXTES_EN))
        orphelines = sorted(set(report.TEXTES_EN) - cles)
        self.assertEqual(sans_anglais, [], "clé française sans traduction anglaise")
        self.assertEqual(orphelines, [], "traduction anglaise dont la clé n'existe plus dans le code")

    def test_chaque_traduction_garde_les_champs_de_format(self):
        perdus = [(fr, champs(fr), champs(en)) for fr, en in report.TEXTES_EN.items()
                  if champs(fr) != champs(en)]
        self.assertEqual(perdus, [])

    def test_l_inventaire_voit_une_cle_ajoutee_sans_traduction(self):
        """L'épreuve d'abord : une clé neuve dans une copie du code doit être vue."""
        src = lire(GENERATEUR)
        with tempfile.TemporaryDirectory() as d:
            copie = os.path.join(d, "report.py")
            with open(copie, "w", encoding="utf-8") as fh:
                fh.write(src + '\n\ntr("une clé inventée pour l\'épreuve")\n')
            cles, _ = cles_du_code(copie)
        self.assertIn("une clé inventée pour l'épreuve", cles - set(report.TEXTES_EN))


class LesDeuxRendusPortentLesMemesFaits(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dossier = tempfile.TemporaryDirectory()
        d = cls.dossier.name
        entree = os.path.join(d, "mesures-inventees.jsonl")
        with open(entree, "w", encoding="utf-8") as fh:
            for ligne in mesures_inventees():
                fh.write(json.dumps(ligne, ensure_ascii=False) + "\n")
        cls.rendus = {}
        for langue in ("fr", "en"):
            sortie = os.path.join(d, f"rendu.{langue}.md")
            subprocess.run([sys.executable, GENERATEUR, entree, "--rendu-le", "2026-01-02 03:04:05+0000",
                            "--materiel", MATERIEL_INVENTE, "--langue", langue, "-o", sortie],
                           cwd=RACINE, check=True, capture_output=True, text=True)
            cls.rendus[langue] = (sortie, lire(sortie))

    @classmethod
    def tearDownClass(cls):
        cls.dossier.cleanup()

    def doc(self, langue):
        chemin, texte = self.rendus[langue]
        return pdl.analyser(texte, chemin)

    def test_les_deux_rendus_different_par_la_langue(self):
        self.assertNotEqual(self.rendus["fr"][1], self.rendus["en"][1])
        self.assertIn("Rendered on 2026-01-02", self.rendus["en"][1])
        self.assertIn("Rendu le 2026-01-02", self.rendus["fr"][1])

    def test_memes_nombres(self):
        fr, en = self.doc("fr"), self.doc("en")
        self.assertGreater(len(fr.nombres), 20, "rendu dégénéré : presque aucun nombre lu")
        self.assertEqual(sorted(en.nombres), sorted(fr.nombres))
        n_fr, n_en = comptes(self.rendus["fr"][1])[0], comptes(self.rendus["en"][1])[0]
        self.assertEqual((n_fr - n_en, n_en - n_fr), (collections.Counter(), collections.Counter()))

    def test_memes_identifiants(self):
        fr, en = self.doc("fr"), self.doc("en")
        self.assertIn("C2-free-term", fr.identifiants)
        self.assertEqual(sorted(en.identifiants), sorted(fr.identifiants))
        i_fr, i_en = comptes(self.rendus["fr"][1])[1], comptes(self.rendus["en"][1])[1]
        self.assertEqual((i_fr - i_en, i_en - i_fr), (collections.Counter(), collections.Counter()))

    def test_memes_titres_et_tableaux(self):
        fr, en = self.doc("fr"), self.doc("en")
        self.assertEqual([n for _, n in en.titres], [n for _, n in fr.titres])
        self.assertEqual([n for _, n in en.tableaux], [n for _, n in fr.tableaux])


if __name__ == "__main__":
    unittest.main()
