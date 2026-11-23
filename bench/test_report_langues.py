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
import re
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
    """Les champs de format DANS L'ORDRE : deux champs permutés dans une traduction rendraient une
    valeur à la place de l'autre, et un tri le cacherait."""
    return [(nom, spec, conv) for _, nom, spec, conv in string.Formatter().parse(gabarit)
            if nom is not None]


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


SEPARATEUR_DE_CELLULES = re.compile(r"(?<!\\)\|")


def faits(cellule):
    """Ce qu'une langue ne change pas dans un fragment : ses nombres et ses identifiants, DANS
    L'ORDRE."""
    return ([str(int(n)) for n in pdl.NOMBRE.findall(pdl.SEGMENT_DE_CODE.sub(" ", cellule))],
            [m.group(2).strip() for m in pdl.SEGMENT_DE_CODE.finditer(cellule)])


def tableaux(texte):
    """Chaque tableau : la liste de ses lignes, chaque ligne la liste de ses cellules."""
    tous, courant, dans_bloc = [], None, False
    for ligne in texte.split("\n"):
        if pdl.ouvre_un_bloc(ligne):
            dans_bloc = not dans_bloc
        if not dans_bloc and pdl.LIGNE_DE_TABLEAU.match(ligne):
            if courant is None:
                courant = []
                tous.append(courant)
            courant.append(SEPARATEUR_DE_CELLULES.split(ligne.strip().strip("|")))
        else:
            courant = None
    return tous


def ecarts_ligne_a_ligne(fr, en):
    """Les deux rendus ont la MÊME suite de lignes (une clé = une ligne ou un fragment de ligne) :
    chaque ligne doit porter les mêmes nombres et les mêmes identifiants (comptés), et chaque ligne
    de commande d'un bloc doit être identique. Rend la liste des lignes en écart."""
    lf, le = fr.split("\n"), en.split("\n")
    if len(lf) != len(le):
        return [("nombre de lignes", len(lf), len(le))]
    ecarts, dans_bloc, com_f, com_e = [], False, False, False
    for i, (a, b) in enumerate(zip(lf, le), 1):
        if pdl.ouvre_un_bloc(a) or pdl.ouvre_un_bloc(b):
            dans_bloc = not dans_bloc
            if a != b:
                ecarts.append((i, a, b))
            continue
        if dans_bloc:
            if pdl.commande(a) != pdl.commande(b):
                ecarts.append((i, a, b))
            continue
        va, com_f = pdl.retirer_commentaires_html(a, com_f)
        vb, com_e = pdl.retirer_commentaires_html(b, com_e)
        fa, fb = faits(va), faits(vb)
        if collections.Counter(fa[0]) != collections.Counter(fb[0]) or \
                collections.Counter(fa[1]) != collections.Counter(fb[1]):
            ecarts.append((i, a[:120], b[:120]))
    return ecarts


def ecarts_de_tableaux(fr, en):
    """Forme (nombre de tableaux, de lignes, de cellules par ligne) puis contenu cellule par
    cellule, position comprise : nombres et identifiants dans l'ordre."""
    tf, te = tableaux(fr), tableaux(en)
    if [[len(r) for r in t] for t in tf] != [[len(r) for r in t] for t in te]:
        return ["forme des tableaux différente"] + [
            (k, i, ra, rb) for k, (a, b) in enumerate(zip(tf, te)) for i, (ra, rb) in enumerate(zip(a, b))
            if len(ra) != len(rb)][:5]
    return [(k, i, j, ca, cb) for k, (a, b) in enumerate(zip(tf, te))
            for i, (ra, rb) in enumerate(zip(a, b))
            for j, (ca, cb) in enumerate(zip(ra, rb)) if faits(ca) != faits(cb)]


def mesures_inventees():
    lignes = []
    # Valeurs INVENTÉES et choisies pour n'exister nulle part ailleurs : `grep -rF` de chacune des
    # valeurs à quatre chiffres ou plus ne trouve rien dans `bench/results/` ni dans les documents.
    for cfg, ev, db in (("alpha@0.3M", 314159, 271828183), ("beta@0.9M", 926535, 897932384)):
        for cid, label in (("C0-plancher", "PLANCHER : seek sur une source inexistante (0 ligne)"),
                           ("C2-free-term", "terme libre sur message (compile en LIKE '%…%')")):
            for w, wl in (("1h", "dernière heure"), ("all", "tout")):
                lignes.append(dict(
                    config_id=cfg, class_id=cid, label=label, kind="gxql", window=w, window_label=wl,
                    config=dict(events=ev, db_bytes=db, version="bin:0123456789abcdef", mask="vide",
                                fts_fields=0, cold="off", hosts=7, profile="profile-prod.json"),
                    reps=5, reps_ok=5, wall_p50_ms=24680.0 if cid == "C0-plancher" else 86420.0,
                    wall_p95_ms=97531.0, sql_p50_ms=11223.0, peak_rss_bytes=123456789,
                    read_bytes_first=0, rows=35791, served_from="raw", loadavg=[1, 2, 3],
                    swap_delta_bytes=0,
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


def rendre(entree, sortie, langue, *options):
    return subprocess.run([sys.executable, GENERATEUR, entree, "--rendu-le", "2026-01-02 03:04:05+0000",
                           "--materiel", MATERIEL_INVENTE, "--langue", langue, "-o", sortie, *options],
                          cwd=RACINE, capture_output=True, text=True)


def ecrire_mesures(chemin, lignes):
    with open(chemin, "w", encoding="utf-8") as fh:
        for ligne in lignes:
            fh.write(json.dumps(ligne, ensure_ascii=False) + "\n")


class ComparaisonDesDeuxLangues:
    """Les comparaisons, jouées sur une paire (français, anglais) fournie par la sous-classe."""

    def paire(self):
        raise NotImplementedError

    def test_memes_nombres_et_identifiants_ligne_a_ligne(self):
        fr, en = self.paire()
        self.assertGreater(sum(len(faits(x)[0]) for x in fr.split("\n")), 20,
                           "rendu dégénéré : presque aucun nombre lu")
        self.assertEqual(ecarts_ligne_a_ligne(fr, en), [])

    def test_memes_tableaux_cellule_par_cellule(self):
        fr, en = self.paire()
        self.assertTrue(tableaux(fr), "aucun tableau lu : l'extraction est cassée")
        self.assertEqual(ecarts_de_tableaux(fr, en), [])

    def test_memes_ensembles_pour_l_outil_de_parite(self):
        fr, en = self.paire()
        a, b = pdl.analyser(fr, "fr.md"), pdl.analyser(en, "en.md")
        self.assertEqual(sorted(a.nombres), sorted(b.nombres))
        self.assertEqual(sorted(a.identifiants), sorted(b.identifiants))
        self.assertEqual([n for _, n in a.titres], [n for _, n in b.titres])


class LeJeuInventeRenduDansLesDeuxLangues(ComparaisonDesDeuxLangues, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dossier = tempfile.TemporaryDirectory()
        d = cls.dossier.name
        entree = os.path.join(d, "mesures-inventees.jsonl")
        ecrire_mesures(entree, mesures_inventees())
        cls.rendus = {}
        for langue in ("fr", "en"):
            sortie = os.path.join(d, f"rendu.{langue}.md")
            r = rendre(entree, sortie, langue)
            assert r.returncode == 0, r.stderr
            cls.rendus[langue] = lire(sortie)

    @classmethod
    def tearDownClass(cls):
        cls.dossier.cleanup()

    def paire(self):
        return self.rendus["fr"], self.rendus["en"]

    def test_les_deux_rendus_different_par_la_langue(self):
        self.assertNotEqual(self.rendus["fr"], self.rendus["en"])
        self.assertIn("Rendered on 2026-01-02", self.rendus["en"])
        self.assertIn("Rendu le 2026-01-02", self.rendus["fr"])


class LesDeuxDocumentsSuivis(ComparaisonDesDeuxLangues, unittest.TestCase):
    """Les documents publiés : toutes les clés réellement rendues y passent, y compris celles que
    le jeu inventé n'exerce pas."""

    def paire(self):
        return (lire(os.path.join(RACINE, "docs", "BENCHMARK.fr.md")),
                lire(os.path.join(RACINE, "docs", "BENCHMARK.md")))


class UnLibelleDeDonneesInconnu(unittest.TestCase):

    def test_le_rendu_anglais_refuse_en_nommant_le_libelle(self):
        lignes = mesures_inventees()
        for ligne in lignes:
            ligne["label"] = "un libellé inventé que personne n'a traduit"
        with tempfile.TemporaryDirectory() as d:
            entree = os.path.join(d, "m.jsonl")
            ecrire_mesures(entree, lignes)
            en = rendre(entree, os.path.join(d, "en.md"), "en")
            fr = rendre(entree, os.path.join(d, "fr.md"), "fr")
        self.assertNotEqual(en.returncode, 0)
        self.assertIn("un libellé inventé que personne n'a traduit", en.stderr)
        self.assertNotIn("Traceback", en.stderr)
        self.assertEqual(fr.returncode, 0, fr.stderr)

    def test_un_libelle_qui_porte_une_valeur_se_traduit_par_gabarit(self):
        report.LANGUE = "en"
        try:
            self.assertEqual(
                report.tr_donnee("le plus coûteux de la famille 9 ne fait que 3.7 x le plancher (seuil 10)"),
                "the most expensive of family 9 is only 3.7 x the floor (threshold 10)")
            self.assertEqual(report.tr_donnee("fenêtre chaude du produit (13 j)"),
                             "the product's hot window (13 d)")
        finally:
            report.LANGUE = "en"


class DesOptionsMalFormeesSontRefusees(unittest.TestCase):

    CAS = {
        "JSON illisible": ["--materiel", "{cpu"],
        "pas un objet": ["--materiel", "[1, 2]"],
        "clé manquante": ["--materiel", '{"cpu": "c", "cores": 3, "mem_gib": 6.5}'],
        "clé inconnue": ["--materiel", '{"cpu": "c", "cores": 3, "mem_gib": 6.5, "kernel": "k", "gpu": 1}'],
        "mauvais type": ["--materiel", '{"cpu": "c", "cores": "trois", "mem_gib": 6.5, "kernel": "k"}'],
        "booléen pour un nombre": ["--materiel", '{"cpu": "c", "cores": true, "mem_gib": 6.5, "kernel": "k"}'],
        "valeur nulle": ["--materiel", '{"cpu": "c", "cores": 0, "mem_gib": 6.5, "kernel": "k"}'],
        "horodatage sans fuseau": ["--rendu-le", "2026-01-02 03:04:05"],
        "horodatage au format ISO": ["--rendu-le", "2026-01-02T03:04:05+0000"],
    }

    def test_chaque_cas_est_refuse_par_un_message_clair(self):
        with tempfile.TemporaryDirectory() as d:
            entree = os.path.join(d, "m.jsonl")
            ecrire_mesures(entree, mesures_inventees())
            for nom, options in self.CAS.items():
                with self.subTest(cas=nom):
                    r = rendre(entree, os.path.join(d, "x.md"), "en", *options)
                    self.assertEqual(r.returncode, 2, r.stderr)
                    self.assertIn(options[0], r.stderr)
                    self.assertNotIn("Traceback", r.stderr)
                    self.assertFalse(os.path.exists(os.path.join(d, "x.md")))


if __name__ == "__main__":
    unittest.main()
