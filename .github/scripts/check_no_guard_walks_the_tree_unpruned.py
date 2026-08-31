#!/usr/bin/env python3
"""Aucun instrument ne parcourt RÉCURSIVEMENT une racine DOMINANTE sans élaguer les artefacts (`P11.8-n`).

LE DÉFAUT. `P11.8-m` a payé la divergence : le geste d'élagage a été écrit UNE fois
(`NOMS_HORS_ARBRE`, `parcours_des_sources`, dans `check_every_style_selector_has_a_target.py`) et trois
gardes l'importent. Mais RIEN ne rougissait sur un parcours écrit à la main sans élagage : le trou
restait refermable en silence par quiconque en écrirait un nouveau. C'est ce que cette garde refuse.

LE RECENSEMENT, RE-MESURÉ PAR L'ARBRE SYNTAXIQUE LE 2026-08-31 sur les 53 instruments Python :
27 passent par l'arbre SUIVI (`git ls-files`), 19 énumèrent le disque À PLAT, 4 passent par le geste
partagé, 5 n'énumèrent rien, et **ONZE portent un parcours RÉCURSIF écrit à la main** — un fichier peut
tomber dans plusieurs colonnes. Des onze, le premier est le CORPS du geste partagé lui-même (il élague,
par construction), un part de la racine du dépôt, et les NEUF autres partent d'un répertoire de sources.

CE QU'ELLE ACCUSE, ET POURQUOI PAS PLUS — LA MESURE A TRANCHÉ LA FORME (2026-08-31)
-----------------------------------------------------------------------------------
Trois formes étaient possibles, et le compte les départage :

  (1) TOUT parcours récursif écrit à la main. Mesuré : **10 sites dans 10 fichiers**, hors le corps du
      geste partagé. Neuf d'entre eux partent d'un répertoire de SOURCES (`daemon/src`,
      `daemon/src/handlers`, `<caisse>/src`) et sont sains — non par accident, mais par une propriété
      des OUTILS : cargo écrit `target/` À CÔTÉ de `src/`, jamais dedans, et Python écrit `__pycache__`
      à côté des `.py`, dont il n'y en a aucun là. Les accuser
      poserait un cliquet à neuf que personne ne fera baisser aujourd'hui : une RANÇON. Refusé.

  (2) Les parcours dont la racine PEUT recevoir un artefact. Refusé par une mesure, pas par goût :
      les artefacts (`daemon/target`, `.github/scripts/__pycache__`, mesurés le 2026-08-31) n'existent
      qu'APRÈS une construction. Sur une copie de travail neuve — celle de l'intégration continue — ils
      n'existent pas : la garde y serait **VERTE PAR CONSTRUCTION**, et rouge sur le poste de l'auteur.
      Un instrument dont le verdict dépend d'un `cargo build` ne mesure pas le code.

  (3) Les parcours récursifs qui n'élaguent pas, RESTREINTS AUX RACINES DOMINANTES. Retenu.
      Une racine est DOMINANTE quand elle est dérivée de la position du fichier SANS DESCENDRE — la racine
      du dépôt, ou un ancêtre du répertoire des instruments — ou quand c'est une racine DÉSIGNÉE
      (`racine_designee()`, `sys.argv[1]`, `git rev-parse --show-toplevel`). Une telle racine CONTIENT tout
      artefact qui existe ou existera, quel que soit l'outil qui l'écrit : le danger y est une propriété
      de la RACINE, pas du contenu de l'arbre du jour. Mesuré le 2026-08-31 : **zéro violation**.

DEUX CANAUX DISTINCTS, ET LE SECOND PORTE UN PLAFOND DATÉ
---------------------------------------------------------
  · VIOLATION NUE — un parcours dominant qui n'exclut AUCUN nom d'artefact pendant la descente. Zéro
    admis, aujourd'hui et demain : c'est le trou que `P11.8-n` nomme.
  · COPIE DIVERGENTE — un parcours dominant qui élague une PART des artefacts et en oublie d'autres,
    c'est-à-dire qui porte sa propre liste au lieu du geste partagé. Une liste écrite à la main qui
    tient TOUT ce que `NOMS_HORS_ARBRE` tient est verte : c'est l'OUBLI qui est jugé, pas la recopie.
    C'est la famille que `P11.8-m` a nommée : « le défaut n'est pas l'ABSENCE, c'est la DIVERGENCE ».
    Mesuré le 2026-08-31 : **une** — `check_i18n_lexicon_covers_displayed_strings.py`,
    dont la liste tient `.git`, `target`, `node_modules`, `.github` et **manque neuf noms** que le geste
    partagé tient (`vendor`, `__pycache__`, `.venv`, `venv`, `site-packages`, `.tox`, `.mypy_cache`,
    `.pytest_cache`, `.ruff_cache`) — un `cargo vendor` ou un environnement virtuel posé sous l'arbre
    entrerait dans son corpus. Le remède est de DEUX LIGNES (importer `parcours_des_sources`) ; le
    plafond est à UN, daté, et il n'attend que ce geste pour tomber à zéro. Une copie divergente de plus
    rougit.

L'ÉLAGAGE SE LIT DANS LA DESCENTE, JAMAIS APRÈS. Un `dossiers[:] = […]` posé DANS le corps de la boucle
empêche `os.walk` de descendre ; un filtrage fait à la sortie a déjà LU le répertoire — c'est exactement
la nuance que le geste partagé documente, et le témoin `élagage après la boucle` la tient.

UN PARCOURS PLAT N'EST JAMAIS ACCUSÉ. `os.listdir`, `os.scandir`, un `glob` sans `**` ne DESCENDENT
rien : ils ne peuvent pas rencontrer l'artefact. Mesuré le 2026-08-31 : QUATRE instruments posent un
`os.listdir` sur une racine dominante et sont sains par cette platitude-là. Les accuser serait une
fausse accusation — les témoins `parcours PLAT`, `scandir PLAT` et `glob PLAT depuis la racine` la
refusent.

LA RACINE SE PROPAGE. Un parcours nu caché derrière un paramètre (`def f(r): os.walk(r)` appelé `f(RACINE)`)
est accusé comme s'il était écrit sur place : la dominance des arguments se propage aux paramètres, par
point fixe, à l'intérieur du module. Sans cela l'échappatoire serait d'une ligne.

CE QUE CETTE GARDE NE TIENT PAS — DIT FRANCHEMENT
-------------------------------------------------
  · Un parcours récursif nu depuis une racine DESCENDUE n'est pas accusé, et `daemon/` en porte un
    (`daemon/target`, mesuré le 2026-08-31) : `os.walk(os.path.join(RACINE, "daemon"))` passerait au vert.
    Le juger demanderait de savoir quels répertoires un outil peut peupler — c'est le point (2) ci-dessus,
    et il est réfuté. Ce reste appartient à `P11.8-n`, ouverte.
  · Les neuf parcours bruts à racine de sources restent bruts : sains par une propriété des outils, non par
    une règle. Le jour où l'un d'eux élargit sa racine jusqu'à devenir dominante, CETTE garde le voit.
  · Elle ne juge que du Python de son propre répertoire, et par l'ARBRE SYNTAXIQUE : un parcours construit
    par `eval`, par un sous-processus (`find`), ou écrit dans un `.sh` lui échappe.
  · Elle ne dit rien de la JUSTESSE d'une exclusion (élaguer `tests` peut être exactement ce qu'il faut),
    seulement de la présence d'un élagage d'artefact sur une racine dominante.
"""
import ast, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_style_selector_has_a_target import (  # noqa: E402  (GESTE PARTAGÉ, source unique — `P11.8-m`)
    NOMS_HORS_ARBRE, parcours_des_sources)

ICI = os.path.dirname(os.path.abspath(__file__))
# PLANCHER DE POPULATION. Une garde à corpus validée sur un corpus VIDE est verte et se croit juste ;
# ce dépôt a déjà payé cette faute. Le compte d'instruments ne fait que croître : relevé à 53 le
# 2026-08-31, le plancher est posé bien en dessous pour ne jamais devenir une rançon.
PLANCHER_INSTRUMENTS = 40
# PLAFOND DE COPIES DIVERGENTES. Relevé le 2026-08-31 : UNE (le lexique i18n, neuf noms manquants).
# L'abaisser à zéro est le seul sens admis, et il coûte deux lignes.
PLAFOND_COPIES_DIVERGENTES = 1

SEGMENTS_QUI_NE_DESCENDENT_PAS = ("..", ".", "")
MARQUE_TOPLEVEL = "--show-toplevel"


# ────────────────────────── CE QUI FAIT D'UNE EXPRESSION UNE RACINE DOMINANTE ──────────────────────────

def _sans_descente(n):
    """L'expression ne pose aucun segment de chemin LITTÉRAL qui descende sous sa base."""
    for x in ast.walk(n):
        if isinstance(x, ast.Constant) and isinstance(x.value, str):
            if x.value not in SEGMENTS_QUI_NE_DESCENDENT_PAS:
                return False
    return True


def expression_dominante(n):
    """Cette expression désigne-t-elle la racine du dépôt, un de ses ancêtres, ou une racine DÉSIGNÉE ?

    Quatre formes, toutes dérivées de ce que le dépôt écrit pour se situer — jamais un chemin écrit :
      · elle part de `__file__` et ne descend pas   (la racine du dépôt, ou le répertoire des instruments) ;
      · elle appelle le geste partagé `racine_designee` ;
      · elle prend `sys.argv[…]`                     (une racine désignée par l'appelant) ;
      · elle lit `git rev-parse --show-toplevel`.
    Un `X if … else Y` est dominant dès qu'une de ses branches l'est : le verdict porterait alors sur
    une racine dominante au moins une fois sur deux, ce qui suffit à exiger l'élagage.
    """
    for x in ast.walk(n):
        if isinstance(x, ast.Constant) and x.value == MARQUE_TOPLEVEL:
            return True
        if isinstance(x, ast.Call):
            f = x.func
            nom = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else None)
            if nom == "racine_designee":
                return True
    if not _sans_descente(n):
        return False
    for x in ast.walk(n):
        if isinstance(x, ast.Name) and x.id == "__file__":
            return True
        if isinstance(x, ast.Subscript) and isinstance(x.value, ast.Attribute) and x.value.attr == "argv":
            return True
    return False


# ──────────────────────────────── LES PORTÉES, ET LA PROPAGATION DE LA RACINE ────────────────────────────

def _visible(nom, portee, dominants, parente):
    """Ce nom est-il dominant dans cette portée, ou dans une portée qui l'englobe ?"""
    ou, vues = portee, set()
    while ou not in vues:
        vues.add(ou)
        if nom in dominants.get(ou, set()):
            return True
        if ou is None:
            return False
        ou = parente.get(ou)
    return False


def noms_dominants(arbre):
    """({portée: {noms dominants}}, {id(nœud): portée}, {portée: portée parente}) — portée `None` = module.

    La dominance se propage aux PARAMÈTRES par les sites d'appel du module, par point fixe : un parcours
    nu caché derrière un paramètre est le même défaut écrit une indirection plus loin.
    """
    portee = {}          # id(nœud) -> nom de la fonction englobante (ou None)
    parente = {None: None}   # portée -> portée englobante : un nom du module reste visible dans une fonction
    fonctions = {}       # nom -> ast.FunctionDef

    def marquer(n, ou):
        for enfant in ast.iter_child_nodes(n):
            if isinstance(enfant, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fonctions[enfant.name] = enfant
                portee[id(enfant)] = ou
                parente[enfant.name] = ou
                marquer(enfant, enfant.name)
            else:
                portee[id(enfant)] = ou
                marquer(enfant, ou)
    marquer(arbre, None)

    dominants = {}
    for n in ast.walk(arbre):
        if isinstance(n, ast.Assign) and expression_dominante(n.value):
            for cible in n.targets:
                if isinstance(cible, ast.Name):
                    dominants.setdefault(portee.get(id(n)), set()).add(cible.id)

    for _ in range(8):  # point fixe borné : les chaînes d'indirection de ce dépôt tiennent en deux sauts
        avant = {k: set(v) for k, v in dominants.items()}
        for n in ast.walk(arbre):
            if not isinstance(n, ast.Call) or not isinstance(n.func, ast.Name):
                continue
            cible = fonctions.get(n.func.id)
            if cible is None:
                continue
            params = [a.arg for a in cible.args.args]
            for i, arg in enumerate(n.args):
                if i >= len(params):
                    break
                ici = portee.get(id(n))
                nu = isinstance(arg, ast.Name) and _visible(arg.id, ici, dominants, parente)
                if nu or expression_dominante(arg):
                    dominants.setdefault(cible.name, set()).add(params[i])
        if dominants == avant:
            break
    return dominants, portee, parente


def racine_est_dominante(expr, portee_du_site, dominants, parente):
    """Un nom est dominant s'il l'est dans la portée du site OU dans une portée qui l'englobe."""
    if expression_dominante(expr):
        return True
    return isinstance(expr, ast.Name) and _visible(expr.id, portee_du_site, dominants, parente)


# ─────────────────────────────── LES PARCOURS RÉCURSIFS, ET LEUR ÉLAGAGE ────────────────────────────────

def liaisons_de_noms(arbre, portee, parente):
    """{(portée, nom): expression} pour chaque affectation simple — l'ensemble d'exclusions se lit là.

    Le geste partagé compose le sien (`interdits = set(NOMS_HORS_ARBRE) | set(hors)`) : un lecteur qui
    ne saurait pas suivre cette composition accuserait de NUDITÉ le geste même qu'il recommande.
    """
    out = {}
    for n in ast.walk(arbre):
        if isinstance(n, ast.Assign):
            for cible in n.targets:
                if isinstance(cible, ast.Name):
                    out[(portee.get(id(n)), cible.id)] = n.value
    return out


def _lie(nom, ou, liaisons, parente):
    vues = set()
    while ou not in vues:
        vues.add(ou)
        if (ou, nom) in liaisons:
            return liaisons[(ou, nom)]
        if ou is None:
            return None
        ou = parente.get(ou)
    return None


ENVELOPPES = ("set", "frozenset", "tuple", "list", "sorted")


def chaines_de(n, ou, liaisons, parente, profondeur=0):
    """Les noms de chaîne qu'une expression désigne, en suivant les noms, les enveloppes et les unions."""
    if n is None or profondeur > 5:
        return set()
    suivant = lambda x: chaines_de(x, ou, liaisons, parente, profondeur + 1)  # noqa: E731
    if isinstance(n, ast.Constant):
        return {n.value} if isinstance(n.value, str) else set()
    if isinstance(n, ast.Name):
        if n.id == "NOMS_HORS_ARBRE" and _lie(n.id, ou, liaisons, parente) is None:
            return set(NOMS_HORS_ARBRE)   # importé du geste partagé, jamais recopié
        return suivant(_lie(n.id, ou, liaisons, parente))
    if isinstance(n, (ast.Tuple, ast.List, ast.Set)):
        return set().union(*(suivant(e) for e in n.elts)) if n.elts else set()
    if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.BitOr, ast.Add)):
        return suivant(n.left) | suivant(n.right)
    if isinstance(n, ast.Call):
        f = n.func
        nom = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else None)
        if nom in ENVELOPPES and n.args:
            return suivant(n.args[0])
    return set()


def elagage_de_la_boucle(boucle, ou, liaisons, parente):
    """Les noms EXCLUS DANS LA DESCENTE d'un `for … in os.walk(…)`.

    Seule une affectation de TRANCHE (`dossiers[:] = …`) sur la variable des sous-répertoires empêche
    `os.walk` de descendre. Une réaffectation nue (`dossiers = …`) ou un filtrage fait après la boucle
    a déjà LU le répertoire : l'artefact a coûté sa lecture, et c'est précisément le défaut que le geste
    partagé documente. Elle n'est donc PAS comptée comme un élagage.
    """
    if not isinstance(boucle.target, ast.Tuple) or len(boucle.target.elts) != 3:
        return set()
    var = boucle.target.elts[1]
    if not isinstance(var, ast.Name):
        return set()
    exclus = set()
    for n in ast.walk(boucle):
        if not isinstance(n, ast.Assign):
            continue
        for cible in n.targets:
            if (isinstance(cible, ast.Subscript) and isinstance(cible.value, ast.Name)
                    and cible.value.id == var.id and isinstance(cible.slice, ast.Slice)):
                for cmp_ in ast.walk(n.value):
                    if isinstance(cmp_, ast.Compare):
                        for c in cmp_.comparators:
                            exclus |= chaines_de(c, ou, liaisons, parente)
    return exclus


def parcours_recursifs(arbre, portee, liaisons, parente):
    """[(ligne, forme, expression de racine, noms exclus)] pour chaque parcours RÉCURSIF écrit à la main.

    `parcours_des_sources` — le geste partagé — n'en est pas un à son APPEL : il EST l'élagage.
    Un parcours PLAT (`os.listdir`, `os.scandir`, un `glob` sans `**`) n'en est pas un non plus : il ne
    descend rien, donc il ne peut pas rencontrer l'artefact.
    """
    boucles = {}
    for n in ast.walk(arbre):
        if isinstance(n, ast.For) and isinstance(n.iter, ast.Call):
            boucles[id(n.iter)] = n
    out = []
    for n in ast.walk(arbre):
        if not isinstance(n, ast.Call) or not n.args:
            continue
        f, ou = n.func, portee.get(id(n))
        if isinstance(f, ast.Attribute) and f.attr == "walk" and isinstance(f.value, ast.Name) and f.value.id == "os":
            boucle = boucles.get(id(n))
            exclus = elagage_de_la_boucle(boucle, ou, liaisons, parente) if boucle is not None else set()
            out.append((n.lineno, "os.walk", n.args[0], exclus))
        elif isinstance(f, ast.Attribute) and f.attr == "rglob":
            out.append((n.lineno, "rglob", f.value, set()))
        elif isinstance(f, ast.Attribute) and f.attr == "glob":
            motif = n.args[0]
            if isinstance(motif, ast.Constant) and isinstance(motif.value, str) and "**" in motif.value:
                out.append((n.lineno, "glob **", f.value, set()))
    return out


def juger(source, nom="<témoin>"):
    """(violations nues, copies divergentes) — chacune : [(ligne, forme, noms exclus)]."""
    arbre = ast.parse(source, filename=nom)
    dominants, portee, parente = noms_dominants(arbre)
    liaisons = liaisons_de_noms(arbre, portee, parente)
    nues, divergentes = [], []
    for ligne, forme, racine, exclus in parcours_recursifs(arbre, portee, liaisons, parente):
        if not racine_est_dominante(racine, portee.get(id(racine)), dominants, parente):
            continue
        manquants = sorted(set(NOMS_HORS_ARBRE) - exclus)
        if not manquants:
            continue                      # il tient TOUT ce que le geste partagé tient
        if exclus & set(NOMS_HORS_ARBRE):
            divergentes.append((ligne, forme, manquants))   # il en tient une part, et en oublie
        else:
            nues.append((ligne, forme, sorted(exclus)))     # il n'en tient aucune
    return nues, divergentes


# ───────────────────────────── AUTO-VALIDATION SUR DES ENTRÉES FABRIQUÉES ICI ────────────────────────────

CLIMB = 'RACINE = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))'

TEMOINS = (
    # (nom, source fabriquée, violations nues attendues, copies divergentes attendues)
    ("parcours nu depuis la racine", f"""
import os
{CLIMB}
def f():
    for b, d, n in os.walk(RACINE):
        yield b
""", 1, 0),
    ("parcours par le geste partagé", f"""
import os
from check_every_style_selector_has_a_target import parcours_des_sources
{CLIMB}
def f():
    for b, n in parcours_des_sources(RACINE):
        yield b
""", 0, 0),
    ("élagage par le nom partagé", f"""
import os
from check_every_style_selector_has_a_target import NOMS_HORS_ARBRE
{CLIMB}
def f():
    for b, d, n in os.walk(RACINE):
        d[:] = [x for x in d if x not in NOMS_HORS_ARBRE]
        yield b
""", 0, 0),
    ("copie divergente incomplète", f"""
import os
HORS = (".git", "target")
{CLIMB}
def f():
    for b, d, n in os.walk(RACINE):
        d[:] = [x for x in d if x not in HORS]
        yield b
""", 0, 1),
    ("élagage qui ne touche aucun artefact", f"""
import os
{CLIMB}
def f():
    for b, d, n in os.walk(RACINE):
        d[:] = [x for x in d if x != "tests"]
        yield b
""", 1, 0),
    ("élagage APRÈS la descente", f"""
import os
from check_every_style_selector_has_a_target import NOMS_HORS_ARBRE
{CLIMB}
def f():
    for b, d, n in os.walk(RACINE):
        d = [x for x in d if x not in NOMS_HORS_ARBRE]
        yield b, d
""", 1, 0),
    ("parcours PLAT depuis la racine", f"""
import os
{CLIMB}
def f():
    return sorted(os.listdir(RACINE))
""", 0, 0),
    ("scandir PLAT depuis la racine", f"""
import os
{CLIMB}
def f():
    return [e.name for e in os.scandir(RACINE)]
""", 0, 0),
    ("glob PLAT depuis la racine", f"""
import os
from pathlib import Path
{CLIMB}
def f():
    return sorted(Path(RACINE).glob("*.py"))
""", 0, 0),
    ("parcours nu depuis une racine DESCENDUE", f"""
import os
{CLIMB}
SRC = os.path.join(RACINE, "daemon", "src")
def f():
    for b, d, n in os.walk(SRC):
        yield b
""", 0, 0),
    ("indirection : racine dominante passée en paramètre", f"""
import os
{CLIMB}
def parcourir(rep):
    for b, d, n in os.walk(rep):
        yield b
def f():
    return parcourir(RACINE)
""", 1, 0),
    ("indirection : racine DESCENDUE passée en paramètre", f"""
import os
{CLIMB}
def parcourir(rep):
    for b, d, n in os.walk(rep):
        yield b
def f():
    return parcourir(os.path.join(RACINE, "web"))
""", 0, 0),
    ("rglob depuis la racine", f"""
from pathlib import Path
RACINE = Path(__file__).resolve().parents[2]
def f():
    return sorted(RACINE.rglob("*.rs"))
""", 1, 0),
    ("glob ** depuis la racine", f"""
from pathlib import Path
RACINE = Path(__file__).resolve().parents[2]
def f():
    return sorted(RACINE.glob("**/*.rs"))
""", 1, 0),
    ("rglob depuis une racine DESCENDUE", f"""
from pathlib import Path
RACINE = Path(__file__).resolve().parents[2]
SRC = RACINE / "daemon" / "src"
def f():
    return sorted(SRC.rglob("*.rs"))
""", 0, 0),
    ("racine DÉSIGNÉE par le geste partagé", """
import os
from check_every_style_selector_has_a_target import racine_designee
RACINE = racine_designee()
def f():
    for b, d, n in os.walk(RACINE):
        yield b
""", 1, 0),
    ("racine DÉSIGNÉE par l'appelant", f"""
import os, sys
RACINE = (sys.argv[1] if len(sys.argv) > 1
          else os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))
def f():
    for b, d, n in os.walk(RACINE):
        yield b
""", 1, 0),
    ("racine lue par git rev-parse", """
import os, subprocess
RACINE = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True).stdout.strip()
def f():
    for b, d, n in os.walk(RACINE):
        yield b
""", 1, 0),
    ("le répertoire des instruments est DOMINANT lui aussi", """
import os
ICI = os.path.dirname(os.path.abspath(__file__))
def f():
    for b, d, n in os.walk(ICI):
        yield b
""", 1, 0),
    ("le geste partagé lui-même, défini ET appelé sur la racine", f"""
import os
from check_every_style_selector_has_a_target import NOMS_HORS_ARBRE
{CLIMB}
def parcours_des_sources(racine, hors=()):
    interdits = set(NOMS_HORS_ARBRE) | set(hors)
    for base, dossiers, fichiers in os.walk(racine):
        dossiers[:] = [d for d in dossiers if d not in interdits]
        yield base, sorted(f for f in fichiers if f not in interdits)
def f():
    return list(parcours_des_sources(RACINE, hors=("tests",)))
""", 0, 0),
    ("élagage COMPOSÉ mais incomplet", f"""
import os
HORS = (".git", "target")
{CLIMB}
def f():
    interdits = set(HORS) | {{"tests"}}
    for b, d, n in os.walk(RACINE):
        d[:] = [x for x in d if x not in interdits]
        yield b
""", 0, 1),
    ("aucun parcours du tout", """
import os
def f():
    return open("x").read()
""", 0, 0),
)


def epreuves():
    """Témoins POSITIFS et NÉGATIFS, fabriqués ici, joués sur la fonction que la garde appelle."""
    for nom, source, att_nues, att_div in TEMOINS:
        try:
            nues, div = juger(source, nom)
        except SyntaxError as e:
            return f"témoin « {nom} » : la source fabriquée ne se lit pas ({e})"
        if len(nues) != att_nues or len(div) != att_div:
            return (f"témoin « {nom} » : {len(nues)} violation(s) nue(s) / {len(div)} copie(s) divergente(s), "
                    f"attendu {att_nues} / {att_div}")
    if not expression_dominante(ast.parse(CLIMB).body[0].value):
        return "témoin de racine : une remontée depuis __file__ n'est pas reconnue dominante"
    if expression_dominante(ast.parse('X = os.path.join(R, "web")').body[0].value):
        return "témoin de racine : un chemin DESCENDU est pris pour une racine dominante"
    if not set(NOMS_HORS_ARBRE) >= {".git", "target", "node_modules", "__pycache__"}:
        return "témoin du geste partagé : NOMS_HORS_ARBRE ne tient plus les artefacts qu'il nommait"
    return None


# ───────────────────────────────────────────── LE VERDICT ───────────────────────────────────────────────

def main():
    faute = epreuves()
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return 2

    corpus = []
    for dossier, fichiers in parcours_des_sources(ICI):
        for f in fichiers:
            if f.endswith(".py"):
                corpus.append(os.path.join(dossier, f))
    corpus.sort()
    if len(corpus) < PLANCHER_INSTRUMENTS:
        print(f"::error::{len(corpus)} instrument(s) Python lus sous {ICI}, plancher {PLANCHER_INSTRUMENTS} : "
              "un corpus amputé rendrait un vert qui n'atteste rien — la garde REFUSE DE CONCLURE",
              file=sys.stderr)
        return 2

    nues, divergentes, parcourus = [], [], 0
    for chemin in corpus:
        rel = os.path.relpath(chemin, os.path.realpath(os.path.join(ICI, "..", "..")))
        try:
            source = open(chemin, encoding="utf-8").read()
        except OSError as e:
            print(f"::error::{rel} illisible ({e}) : la garde REFUSE DE CONCLURE", file=sys.stderr)
            return 2
        try:
            a, b = juger(source, rel)
        except SyntaxError as e:
            print(f"::error file={rel}::ne se lit pas comme du Python ({e}) : la garde REFUSE DE CONCLURE",
                  file=sys.stderr)
            return 2
        parcourus += len(a) + len(b)
        nues += [(rel, *x) for x in a]
        divergentes += [(rel, *x) for x in b]

    for rel, ligne, forme, exclus in nues:
        quoi = f"il n'exclut que {', '.join(exclus)}" if exclus else "il n'exclut rien"
        print(f"::error file={rel},line={ligne}::parcours RÉCURSIF ({forme}) depuis une racine DOMINANTE "
              f"sans élaguer les artefacts — {quoi}. Une racine dominante contient tout artefact d'outil "
              "qui existe ou existera. Le geste tient en deux lignes : importer `parcours_des_sources` "
              "de `check_every_style_selector_has_a_target`.", file=sys.stderr)
    for rel, ligne, forme, manquants in divergentes:
        print(f"::warning file={rel},line={ligne}::COPIE DIVERGENTE du geste d'élagage ({forme}) — il manque "
              f"{', '.join(manquants)}. Le remède est d'importer `parcours_des_sources` (`P11.8-m`).",
              file=sys.stderr)

    if nues:
        print(f"\n{len(nues)} parcours récursif(s) nu(s) depuis une racine dominante. Un tel parcours "
              "descend dans le répertoire de construction, l'environnement virtuel ou les dépendances "
              "tierces : il gonfle le corpus en silence, et aucun plancher ne rougit — un plancher ne "
              "garde que la BAISSE.", file=sys.stderr)
        return 1
    if len(divergentes) > PLAFOND_COPIES_DIVERGENTES:
        print(f"\n{len(divergentes)} copie(s) divergente(s) du geste d'élagage, plafond {PLAFOND_COPIES_DIVERGENTES} "
              f"(relevé le 2026-08-31). Le défaut n'est pas l'ABSENCE d'élagage, c'est la DIVERGENCE : "
              "chaque copie oublie un nom que les autres tiennent.", file=sys.stderr)
        return 1

    detail = ""
    if divergentes:
        detail = (" " + ", ".join(f"{rel}:{l}" for rel, l, _, _ in divergentes)
                  + f" élague(nt) à la main (plafond {PLAFOND_COPIES_DIVERGENTES}, relevé le 2026-08-31) ;"
                  " le remède est d'importer `parcours_des_sources`.")
    print(f"check_no_guard_walks_the_tree_unpruned : {len(corpus)} instrument(s) Python lus, "
          f"{parcourus} parcours récursif(s) partant d'une racine DOMINANTE, "
          f"0 sans élagage, {len(divergentes)} copie(s) divergente(s).{detail}\n"
          "La racine est DÉRIVÉE de la position du fichier (remontée depuis `__file__`, "
          "`racine_designee()`, `sys.argv`, `git rev-parse --show-toplevel`), jamais d'un chemin écrit, "
          "et la dominance se propage aux paramètres par les sites d'appel.\n"
          "CE QU'ELLE NE TIENT PAS : un parcours nu depuis une racine DESCENDUE (`daemon/` porte "
          "`daemon/target`) n'est pas accusé — le juger demanderait de savoir quels répertoires un outil "
          "peut peupler, et ces répertoires n'existent pas sur une copie neuve, ce qui rendrait la garde "
          "verte par construction en intégration ; les neuf parcours bruts à racine de SOURCES restent "
          "bruts, sains par une propriété des outils et non par une règle ; un parcours écrit en shell, "
          "par sous-processus ou par `eval` lui échappe.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
