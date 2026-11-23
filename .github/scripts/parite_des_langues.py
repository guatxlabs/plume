#!/usr/bin/env python3
"""Parité entre un document et sa traduction : ce que la langue ne doit pas changer.

LE DÉFAUT VISÉ
--------------
Une traduction se relit pour son style ; ce qu'elle perd en route ne se voit pas à la relecture. Un
titre sauté, une commande recopiée avec une option en moins, un chiffre retouché, un lien qui vise
encore le document français alors que sa version anglaise existe : chacun laisse un texte lisible,
fluide, et faux. Ce sont des faits que la langue ne change pas, donc des faits qu'une machine peut
comparer sans juger la traduction elle-même.

CE QUI EST COMPARÉ, PAIRE PAR PAIRE
-----------------------------------
- les TITRES : leur nombre et la suite de leurs niveaux ;
- les BLOCS DE CODE : leur nombre, et dans chacun les lignes de commande hors commentaires (une ligne
  qui commence par `#` ou `//` est un commentaire, comme la fin de ligne qui suit ` # ` ou ` // ` :
  c'est la part qu'une traduction a le droit de réécrire) ;
- les TABLEAUX : leur nombre et le nombre de lignes de chacun ;
- les CIBLES DE LIENS : un lien vers `Y.md` doit viser `Y.en.md` côté traduction quand ce fichier
  existe, et rester tel quel sinon ; l'ancre (`#…`) est retirée avant comparaison, car elle dérive
  d'un titre, et un titre traduit change d'ancre ;
- l'ENSEMBLE DES NOMBRES du texte courant, lus comme des suites de chiffres : `2,7` et `2.7`, ou
  `4 812 337` et `4,812,337`, donnent les mêmes suites, si bien que la typographie de chaque langue
  n'accuse rien ;
- l'ENSEMBLE DES IDENTIFIANTS ENTRE ACCENTS GRAVES.

Chaque écart est nommé par `fichier:ligne`, côté original quand il manque quelque chose à la
traduction, côté traduction quand elle porte quelque chose en trop.

LA CONVENTION DE SUFFIXE EST UN PARAMÈTRE
-----------------------------------------
Aujourd'hui l'original est `X.md` (français) et la traduction `X.en.md`. La convention basculera en
`X.fr.md` / `X.md` ; l'outil ne la code pas en dur : `--suffixe-original ""` et
`--suffixe-traduction .en` sont les défauts, `--suffixe-original .fr --suffixe-traduction ""` est la
bascule.

DEUX MODES
----------
- comparaison (défaut) : toutes les paires suivies par git, ou une seule avec `--paire ORIGINAL
  TRADUCTION`. Code 1 au premier écart nommé, 0 sinon, 2 quand rien n'a été comparé (aucune paire,
  dépôt illisible, fichier absent ou qui n'est pas de l'UTF-8) : un vert sur zéro paire ne
  prouverait rien.
- `--inventaire` : liste les documents suivis sans traduction, et les traductions sans original. Il
  rend 0 tant que `--strict` n'est pas passé ; avec `--strict`, un document sans traduction rend 1.
  Sur zéro document suivi, ou sur un dépôt illisible, il rend 2 dans les deux cas.

L'outil n'est câblé dans aucun flux d'intégration : son nom ne porte pas le préfixe des gardes, et
c'est délibéré tant que le corpus n'a pas de paires.

CE QU'IL NE VOIT PAS
--------------------
Les titres soulignés (`===` / `---` sous une ligne) ne sont pas lus, seulement les titres `#`. Un
bloc de code indenté de quatre espaces n'est pas un bloc pour lui, seulement les blocs clôturés
(trois accents graves ou trois tildes). Les commentaires HTML ne sont pas rendus, donc pas comparés.
Un nombre écrit en toutes lettres échappe à la comparaison des nombres. L'ensemble est un ENSEMBLE :
un nombre cité deux fois d'un côté et une fois de l'autre ne fait pas d'écart.
Un tableau n'est vu que si ses lignes commencent par une barre verticale : `a | b` suivi de `---|---`
n'est pas un tableau pour lui. Dans un bloc, ` # ` ou ` // ` coupe la ligne même entre guillemets :
`grep ' # a'` et `grep ' # b'` donnent la même commande. Une ligne de bloc qui commence par `#` est un
commentaire, sauf `#[`, `#!` et les directives du préprocesseur C (`#include`, `#define`…), qui sont
du code.
"""
import argparse
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field

CLOTURE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")
CITATION = re.compile(r"^\s{0,3}(?:>\s?)+")
TITRE = re.compile(r"^\s{0,3}(#{1,6})(?:\s+(.*))?$")
LIGNE_DE_TABLEAU = re.compile(r"^\s*\|")
SEGMENT_DE_CODE = re.compile(r"(`+)(.+?)\1")
LIEN_EN_LIGNE = re.compile(
    r"!?\[((?:[^\[\]\\]|\\.|\[[^\]]*\])*)\]\(\s*<?([^)\s>]*)>?(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)"
)
DEFINITION_DE_LIEN = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+.*)?$")
URL_NUE = re.compile(r"<?\b[a-zA-Z][a-zA-Z0-9+.-]*://\S+")
NOMBRE = re.compile(r"\d+")
SCHEMA = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
COMMENTAIRE_FINAL = re.compile(r"\s+(?:#|//)(?:\s.*)?$")
# Lignes qui commencent par `#` sans être des commentaires : attribut Rust, shebang, préprocesseur C.
DIESE_DE_CODE = re.compile(
    r"^#(?:\[|!|(?:include|define|undef|if|ifdef|ifndef|elif|else|endif|pragma|error)\b)")


@dataclass
class Document:
    chemin: str
    titres: list = field(default_factory=list)       # (ligne, niveau)
    blocs: list = field(default_factory=list)        # (ligne d'ouverture, [(ligne, commande)])
    tableaux: list = field(default_factory=list)     # (première ligne, nombre de lignes)
    liens: list = field(default_factory=list)        # (ligne, cible brute)
    nombres: dict = field(default_factory=dict)      # nombre -> première ligne
    identifiants: dict = field(default_factory=dict)  # contenu entre accents graves -> première ligne


@dataclass(frozen=True)
class Ecart:
    fichier: str
    ligne: int
    famille: str
    message: str

    def __str__(self):
        return f"{self.fichier}:{self.ligne}: [{self.famille}] {self.message}"


def commande(ligne):
    """La part d'une ligne de bloc qu'une traduction ne doit pas toucher ; None pour un commentaire."""
    s = ligne.strip()
    if not s or s.startswith("//") or (s.startswith("#") and not DIESE_DE_CODE.match(s)):
        return None
    s = COMMENTAIRE_FINAL.sub("", s)
    return " ".join(s.split()) or None


def retirer_commentaires_html(ligne, dans_commentaire):
    visible = []
    i = 0
    while i < len(ligne):
        if dans_commentaire:
            fin = ligne.find("-->", i)
            if fin < 0:
                return "".join(visible), True
            i = fin + 3
            dans_commentaire = False
        else:
            debut = ligne.find("<!--", i)
            if debut < 0:
                visible.append(ligne[i:])
                break
            visible.append(ligne[i:debut])
            i = debut + 4
            dans_commentaire = True
    return "".join(visible), dans_commentaire


def analyser(texte, chemin):
    doc = Document(chemin)
    cloture = None  # (caractère, longueur, ligne d'ouverture, commandes)
    dans_commentaire = False
    tableau = None  # [première ligne, nombre]

    def fermer_tableau():
        nonlocal tableau
        if tableau:
            doc.tableaux.append(tuple(tableau))
        tableau = None

    for n, brute in enumerate(texte.splitlines(), 1):
        ligne = CITATION.sub("", brute, count=1)
        if cloture:
            m = CLOTURE.match(ligne)
            if (m and m.group(1)[0] == cloture[0] and len(m.group(1)) >= cloture[1]
                    and not m.group(2).strip()):
                doc.blocs.append((cloture[2], cloture[3]))
                cloture = None
            else:
                c = commande(ligne)
                if c:
                    cloture[3].append((n, c))
            continue
        m = CLOTURE.match(ligne)
        if m and not dans_commentaire and not (m.group(1)[0] == "`" and "`" in m.group(2)):
            fermer_tableau()
            cloture = (m.group(1)[0], len(m.group(1)), n, [])
            continue

        visible, dans_commentaire = retirer_commentaires_html(ligne, dans_commentaire)
        if LIGNE_DE_TABLEAU.match(visible):
            if tableau is None:
                tableau = [n, 0]
            tableau[1] += 1
        else:
            fermer_tableau()

        t = TITRE.match(visible)
        if t:
            doc.titres.append((n, len(t.group(1))))

        d = DEFINITION_DE_LIEN.match(visible)
        if d:
            doc.liens.append((n, d.group(1)))
            continue

        for s in SEGMENT_DE_CODE.finditer(visible):
            doc.identifiants.setdefault(s.group(2).strip(), n)
        sans_code = SEGMENT_DE_CODE.sub(" ", visible)
        for lien in LIEN_EN_LIGNE.finditer(sans_code):
            doc.liens.append((n, lien.group(2)))
        texte_courant = LIEN_EN_LIGNE.sub(lambda x: f" {x.group(1)} ", sans_code)
        texte_courant = URL_NUE.sub(" ", texte_courant)
        for nombre in NOMBRE.findall(texte_courant):
            doc.nombres.setdefault(str(int(nombre)), n)

    fermer_tableau()
    if cloture:
        doc.blocs.append((cloture[2], cloture[3]))
    return doc


class Convention:
    """`X<original>.md` ↔ `X<traduction>.md` ; l'un des deux suffixes peut être vide, pas les deux."""

    def __init__(self, original="", traduction=".en"):
        for s in (original, traduction):
            if s and not re.fullmatch(r"\.[A-Za-z][A-Za-z_-]*", s):
                raise ValueError(f"suffixe « {s} » : attendu vide ou de la forme .xx")
        if original == traduction:
            raise ValueError("les deux suffixes sont identiques : aucune paire ne peut se former")
        self.original = original
        self.traduction = traduction

    def _tige(self, chemin, suffixe):
        fin = suffixe + ".md"
        return chemin[: -len(fin)] if chemin.endswith(fin) else None

    def est_original(self, chemin):
        if self._tige(chemin, self.original) is None:
            return False
        # Avec un suffixe d'original vide, `X.en.md` finit aussi par `.md` : c'est une traduction.
        return bool(self.original) or self._tige(chemin, self.traduction) is None

    def est_traduction(self, chemin):
        if self._tige(chemin, self.traduction) is None:
            return False
        return bool(self.traduction) or self._tige(chemin, self.original) is None

    def traduction_de(self, chemin):
        return self._tige(chemin, self.original) + self.traduction + ".md"

    def original_de(self, chemin):
        return self._tige(chemin, self.traduction) + self.original + ".md"


def cible_sans_ancre(cible):
    """La cible sans ancre ; `./y.md` et `y.md` désignent le même fichier, donc la même cible."""
    chemin = cible.split("#", 1)[0]
    while chemin.startswith("./"):
        chemin = chemin[2:]
    return chemin


def basculer(cible, dossier, convention, existe):
    """La cible qu'un lien de l'original doit porter dans la traduction."""
    chemin = cible_sans_ancre(cible)
    if not chemin or SCHEMA.match(chemin) or chemin.startswith("//"):
        return chemin
    if not convention.est_original(chemin):
        return chemin
    traduit = convention.traduction_de(chemin)
    base = "" if traduit.startswith("/") else dossier
    if existe(os.path.normpath(os.path.join(base, traduit.lstrip("/")))):
        return traduit
    return chemin


def comparer_titres(o, t):
    for (lo, no), (lt, nt) in zip(o.titres, t.titres):
        if no != nt:
            return [Ecart(o.chemin, lo, "titres",
                          f"titre de niveau {no}, la traduction porte un niveau {nt} ({t.chemin}:{lt})")]
    if len(o.titres) > len(t.titres):
        lo, no = o.titres[len(t.titres)]
        return [Ecart(o.chemin, lo, "titres",
                      f"titre de niveau {no} sans pendant ({len(o.titres)} titres contre {len(t.titres)})")]
    if len(t.titres) > len(o.titres):
        lt, nt = t.titres[len(o.titres)]
        return [Ecart(t.chemin, lt, "titres",
                      f"titre de niveau {nt} en trop ({len(t.titres)} titres contre {len(o.titres)})")]
    return []


def comparer_blocs(o, t):
    ecarts = []
    if len(o.blocs) != len(t.blocs):
        court, long_ = (o, t) if len(o.blocs) < len(t.blocs) else (t, o)
        ligne = long_.blocs[len(court.blocs)][0]
        ecarts.append(Ecart(long_.chemin, ligne, "blocs",
                            f"{len(long_.blocs)} blocs de code contre {len(court.blocs)} dans {court.chemin}"))
    for (lo, co), (lt, ct) in zip(o.blocs, t.blocs):
        for (ko, xo), (kt, xt) in zip(co, ct):
            if xo != xt:
                ecarts.append(Ecart(o.chemin, ko, "blocs",
                                    f"commande « {xo} », la traduction porte « {xt} » ({t.chemin}:{kt})"))
                break
        else:
            if len(co) > len(ct):
                ko, xo = co[len(ct)]
                ecarts.append(Ecart(o.chemin, ko, "blocs",
                                    f"commande « {xo} » absente du bloc ouvert en {t.chemin}:{lt}"))
            elif len(ct) > len(co):
                kt, xt = ct[len(co)]
                ecarts.append(Ecart(t.chemin, kt, "blocs",
                                    f"commande « {xt} » en trop, absente du bloc ouvert en {o.chemin}:{lo}"))
    return ecarts


def comparer_tableaux(o, t):
    ecarts = []
    if len(o.tableaux) != len(t.tableaux):
        court, long_ = (o, t) if len(o.tableaux) < len(t.tableaux) else (t, o)
        ligne = long_.tableaux[len(court.tableaux)][0]
        ecarts.append(Ecart(long_.chemin, ligne, "tableaux",
                            f"{len(long_.tableaux)} tableaux contre {len(court.tableaux)} dans {court.chemin}"))
    for (lo, no), (lt, nt) in zip(o.tableaux, t.tableaux):
        if no != nt:
            ecarts.append(Ecart(o.chemin, lo, "tableaux",
                                f"tableau de {no} lignes, la traduction en porte {nt} ({t.chemin}:{lt})"))
    return ecarts


def comparer_liens(o, t, convention, existe):
    dossier = os.path.dirname(o.chemin)
    attendus, origine, forme_brute = Counter(), {}, {}
    for ligne, cible in o.liens:
        b = basculer(cible, dossier, convention, existe)
        if not b:
            continue
        attendus[b] += 1
        origine.setdefault(b, ligne)
        forme_brute.setdefault(cible_sans_ancre(cible), b)
    portes, position = Counter(), {}
    for ligne, cible in t.liens:
        c = cible_sans_ancre(cible)
        if not c:
            continue
        portes[c] += 1
        position.setdefault(c, ligne)

    manquants = attendus - portes
    en_trop = portes - attendus
    ecarts = []
    for c in sorted(en_trop):
        visee = forme_brute.get(c)
        if visee and visee != c and visee in manquants:
            ecarts.append(Ecart(t.chemin, position[c], "liens",
                                f"lien non basculé : « {c} » doit viser « {visee} », qui existe"))
            del manquants[visee]
        else:
            ecarts.append(Ecart(t.chemin, position[c], "liens", f"lien vers « {c} » absent de l'original"))
    for c in sorted(manquants):
        ecarts.append(Ecart(o.chemin, origine[c], "liens", f"lien vers « {c} » absent de la traduction"))
    return ecarts


def comparer_ensembles(o_valeurs, t_valeurs, o, t, famille, nom):
    ecarts = []
    for v in sorted(set(o_valeurs) - set(t_valeurs)):
        ecarts.append(Ecart(o.chemin, o_valeurs[v], famille, f"{nom} « {v} » absent de la traduction"))
    for v in sorted(set(t_valeurs) - set(o_valeurs)):
        ecarts.append(Ecart(t.chemin, t_valeurs[v], famille, f"{nom} « {v} » absent de l'original"))
    return ecarts


def comparer_nombres(o, t):
    return comparer_ensembles(o.nombres, t.nombres, o, t, "nombres", "nombre")


def comparer_identifiants(o, t):
    return comparer_ensembles(o.identifiants, t.identifiants, o, t, "identifiants", "identifiant")


def comparer(original, traduction, convention, existe):
    """Tous les écarts entre deux documents déjà analysés, famille par famille."""
    ecarts = []
    ecarts += comparer_titres(original, traduction)
    ecarts += comparer_blocs(original, traduction)
    ecarts += comparer_tableaux(original, traduction)
    ecarts += comparer_liens(original, traduction, convention, existe)
    ecarts += comparer_nombres(original, traduction)
    ecarts += comparer_identifiants(original, traduction)
    return ecarts


def comparer_fichiers(racine, original, traduction, convention):
    def lire(rel):
        try:
            with open(os.path.join(racine, rel), encoding="utf-8") as f:
                texte = f.read()
        except (OSError, UnicodeDecodeError) as e:
            raise Illisible(f"{rel} : {e}") from e
        return analyser(texte, rel)

    def existe(rel):
        return os.path.isfile(os.path.join(racine, rel))

    return comparer(lire(original), lire(traduction), convention, existe)


class Illisible(Exception):
    """Un fichier de la paire n'a pas pu être lu : rien n'a été comparé."""


def documents_suivis(racine):
    try:
        sortie = subprocess.run(["git", "-C", racine, "ls-files", "-z", "--", "*.md"],
                                capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return sorted(p for p in sortie.decode("utf-8").split("\0") if p)


def inventaire(documents, convention):
    """(originaux sans traduction, traductions sans original), en chemins relatifs."""
    present = set(documents)
    sans_traduction = [d for d in documents
                       if convention.est_original(d) and convention.traduction_de(d) not in present]
    orphelines = [d for d in documents
                  if convention.est_traduction(d) and convention.original_de(d) not in present]
    return sans_traduction, orphelines


def paires(documents, convention):
    present = set(documents)
    return [(d, convention.traduction_de(d)) for d in documents
            if convention.est_original(d) and convention.traduction_de(d) in present]


def racine_par_defaut():
    ici = os.path.dirname(os.path.abspath(__file__))
    return os.path.realpath(os.path.join(ici, "..", ".."))


def main(argv=None):
    p = argparse.ArgumentParser(description="Parité entre un document et sa traduction.")
    p.add_argument("--racine", default=racine_par_defaut())
    p.add_argument("--suffixe-original", default="")
    p.add_argument("--suffixe-traduction", default=".en")
    p.add_argument("--paire", nargs=2, metavar=("ORIGINAL", "TRADUCTION"))
    p.add_argument("--inventaire", action="store_true")
    p.add_argument("--strict", action="store_true")
    a = p.parse_args(argv)

    try:
        convention = Convention(a.suffixe_original, a.suffixe_traduction)
    except ValueError as e:
        print(f"convention invalide : {e}", file=sys.stderr)
        return 2

    if a.paire:
        a_comparer = [tuple(a.paire)]
    else:
        documents = documents_suivis(a.racine)
        if documents is None:
            print(f"aucun document lisible sous {a.racine} (git ls-files a échoué) : rien comparé",
                  file=sys.stderr)
            return 2
        if a.inventaire:
            sans_traduction, orphelines = inventaire(documents, convention)
            for d in sans_traduction:
                print(f"{d}: sans traduction (attendue : {convention.traduction_de(d)})")
            for d in orphelines:
                print(f"{d}: traduction sans original (attendu : {convention.original_de(d)})")
            print(f"{len(sans_traduction)} document(s) sans traduction, {len(orphelines)} traduction(s) "
                  f"sans original, sur {len(documents)} documents suivis")
            if not documents:
                print("aucun document suivi : rien inventorié", file=sys.stderr)
                return 2
            return 1 if a.strict and sans_traduction else 0
        a_comparer = paires(documents, convention)
        if not a_comparer:
            print("aucune paire de documents suivis : rien comparé (voir --inventaire)", file=sys.stderr)
            return 2

    total = []
    for original, traduction in a_comparer:
        try:
            total += comparer_fichiers(a.racine, original, traduction, convention)
        except Illisible as e:
            print(f"{original} / {traduction} illisible, rien comparé : {e}", file=sys.stderr)
            return 2
    for e in total:
        print(e)
    print(f"{len(a_comparer)} paire(s) comparée(s), {len(total)} écart(s)")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
