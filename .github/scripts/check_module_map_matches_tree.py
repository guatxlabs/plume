#!/usr/bin/env python3
"""Le plan des modules (`docs/MODULE-MAP.md`) dit VRAI sur l'arbre suivi — garde de CI (`P7.18-a`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Le plan des modules est le document qu'un arrivant ouvre pour savoir quelle boîte toucher. Rien ne
le relisait contre l'arbre : un renommage (`backup.rs` devenu le répertoire `backup/`) l'a laissé
faux pendant des heures, et `idp.rs` y figurait encore alors que le module était un répertoire
depuis son découpage. Mesuré le 2026-08-22 par cette garde, avant correction : 2 chemins cités
inexistants (`idp.rs`, `compliance.rs` — la relecture à l'œil qui a précédé n'en avait vu qu'un),
22 modules de premier niveau de `daemon/src/` sans aucune entrée sur 64 (un tiers), 4 sous-modules
de `cold_store/` sur 15 absents d'une carte qui se présentait comme complète. Un plan que rien ne
relit dérive ; celui-ci est relu à chaque poussée, dans les DEUX sens.

CE QU'EST UNE ENTRÉE — LE CRITÈRE, ÉCRIT
---------------------------------------
Le plan DÉCLARE son périmètre sur une ligne `Scope: \\`dir/\\` (\\`*.ext\\`), … — except \\`nom\\`.` ; la
garde n'énumère aucun répertoire. L'EXTENSION EST DÉCLARÉE, JAMAIS DEVINÉE : ce qu'est un « module »
dépend du langage de l'arbre (`.rs` pour le démon, `.js` pour la console), et une garde qui le
supposerait ne tiendrait que la moitié du produit — la console est restée hors de toute relecture
tant que cette garde savait lire du Rust et rien d'autre. Une SECTION est dans le périmètre quand son
titre (`##`/`###`) cite,
entre accents graves, un répertoire du périmètre ou un sous-répertoire suivi de celui-ci ; un
titre `###` sans répertoire hérite de son `##`. Une ENTRÉE est la PREMIÈRE CELLULE d'une ligne de
tableau d'une section dans le périmètre ; chaque token entre accents graves y est un chemin
revendiqué, résolu d'abord contre le dernier répertoire cité dans la cellule (`\\`b/\\` (\\`mod\\`,
\\`x\\`)`), puis contre le répertoire de la section, puis contre chaque répertoire du périmètre.
Un nom nu (`exactness`) vaut `exactness` suivi de l'extension DÉCLARÉE pour ce répertoire, ou
`exactness/` ; `{a,b}` se développe ; `*` est un motif sur l'arbre suivi ; un token finissant par `/`
est un répertoire et doit contenir au moins un fichier suivi. Un répertoire cité dans un titre est
lui-même une revendication. Les bases d'essai d'un token sont le répertoire de la cellule, celui de la
section, puis les répertoires du périmètre APPARENTÉS à celle-ci (l'un contient l'autre) : sans cette
borne, un chemin absent d'une caisse serait blanchi par un homonyme d'une autre caisse.

CE QUE LA GARDE NE LIT PAS — DIT FRANCHEMENT
-------------------------------------------
La prose (la liste des handlers « large but flat », les invariants de sécurité, la section du
cœur partagé qui décrit une AUTRE caisse) et les cellules autres que la première ne sont pas des
entrées : un chemin qui n'y existe plus n'est pas vu. Une ligne de tableau du périmètre dont la
première cellule ne porte AUCUN token entre accents graves est refusée : une entrée en clair
échapperait sinon à la relecture. La garde s'exclut elle-même : le plan cite ce script dans sa
prose, et la prose n'est pas une entrée. Les deux jambes :
  (a) tout chemin revendiqué existe dans l'arbre SUIVI (`git ls-files`, pas le disque : un fichier
      oublié d'un `git add` n'existe pas pour le lecteur du dépôt) ;
  (b) tout module de premier niveau d'un répertoire du périmètre — `nom` suivi de l'extension
      déclarée, ou `nom/` ; `mod<ext>` est le répertoire lui-même, pas un sous-module (convention
      Rust, inerte là où elle n'existe pas) — a une entrée, sauf les noms exceptés. Un fichier dont
      l'extension n'est pas celle déclarée n'est pas un module : `style.css` n'est pas une caisse de
      la console, et exiger une entrée pour chaque octet servi ferait du plan un inventaire.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
-------------------------------------------------
Une garde d'extraction rend vert de deux façons : tout va bien, ou son motif ne reconnaît plus
rien. Avant tout verdict, elle exécute un plan et un arbre de contrôle portant ses témoins : des
formes qu'elle DOIT résoudre (nom nu, accolades, motif, répertoire, nom relatif au répertoire de
la cellule, titre de section), des citations qu'elle NE DOIT PAS compter (prose, seconde cellule,
section hors périmètre), un chemin absent qu'elle DOIT nommer, un module sans entrée qu'elle DOIT
nommer, et les exceptions qu'elle DOIT respecter. Puis un PLANCHER d'entrées et de fichiers sur
l'arbre réel. Si `git ls-files` échoue, elle ne conclut pas (code 2, « instrument muet »).

Usage :  python3 .github/scripts/check_module_map_matches_tree.py [--mesure] [--plan CHEMIN]
Sortie :  0 = plan et arbre concordent ; 1 = écart au-dessus d'un plafond ; 2 = instrument muet ou
          faux. `--mesure` imprime les comptes sans verdict ; `--plan` relit une copie du plan
          (témoins sur copie), l'arbre restant celui du dépôt.
"""
from __future__ import annotations

import fnmatch
import itertools
import os
import re
import subprocess
import sys

RACINE = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
PLAN = "docs/MODULE-MAP.md"

# PLAFONDS, relevés le 2026-08-22 après correction du plan : zéro chemin cité absent, zéro module
# sans entrée dans chaque répertoire du périmètre. Relever un plafond exige une raison écrite à côté.
PLAFOND_CHEMINS_ABSENTS = 0
PLAFOND_MODULES_SANS_ENTREE = 0

# Planchers sur l'arbre réel : en dessous, c'est la lecture qui est cassée, pas l'arbre qui a maigri.
# Relevés SUR L'ARBRE SUIVI du dépôt le 2026-08-23, périmètre étendu à `web/` : 123 entrées dans le
# périmètre, 287 fichiers suivis sous les répertoires déclarés.
MIN_ENTREES = 60
MIN_FICHIERS = 200

TOKEN = re.compile(r"`([^`]+)`")
SCOPE = re.compile(r"^Scope:\s*(.+?)\s*$")
# Un poste du périmètre : le répertoire, puis l'extension qui y fait un module — `` `web/` (`*.js`) ``.
POSTE = re.compile(r"`([^`]+/)`\s*\(\s*`\*(\.[A-Za-z0-9_]+)`\s*\)")
TITRE = re.compile(r"^(#{2,3})\s+(.*)$")
SEPARATEUR = re.compile(r"^\|?\s*:?-{3,}")
CELLULE = re.compile(r"(?<!\\)\|")
ACCOLADES = re.compile(r"\{([^{}]+)\}")


class InstrumentMuet(Exception):
    """Le périmètre n'est pas lisible ou l'arbre n'est pas lisible : aucun verdict."""


def lire_arbre() -> set[str] | None:
    """Les chemins SUIVIS, par git. `None` si git ne répond pas : l'instrument est muet."""
    try:
        sortie = subprocess.run(["git", "ls-files", "-z"], cwd=RACINE, capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return {p.decode("utf-8", "surrogateescape") for p in sortie.stdout.split(b"\0") if p}


def lire_perimetre(texte: str) -> tuple[list[str], dict[str, str], set[str]]:
    """La ligne `Scope:` du plan : les répertoires déclarés, L'EXTENSION QUI Y FAIT UN MODULE, et les noms
    exceptés. L'extension n'est pas devinée : `daemon/src/` est du Rust, `web/` est de l'ES module, et une
    garde qui supposerait `.rs` laisserait la console hors de toute relecture."""
    lignes = [m for m in (SCOPE.match(l) for l in texte.splitlines()) if m]
    if len(lignes) != 1:
        raise InstrumentMuet(f"{len(lignes)} ligne(s) `Scope:` dans le plan, il en faut exactement une — "
                             f"le périmètre n'est pas déclaré, la garde n'a rien à relire.")
    corps = lignes[0].group(1)
    if "except" in corps:
        part_dirs, part_exc = corps.split("except", 1)
    else:
        part_dirs, part_exc = corps, ""
    postes = POSTE.findall(part_dirs)
    dirs = [d for d, _ in postes]
    exts = {d: e for d, e in postes}
    exceptions = {t.strip("/") for t in TOKEN.findall(part_exc)}
    if not dirs or 2 * len(postes) != len(TOKEN.findall(part_dirs)) or len(exts) != len(dirs):
        raise InstrumentMuet("la ligne `Scope:` déclare chaque poste comme un répertoire entre accents "
                             "graves terminé par `/`, SUIVI entre parenthèses de l'extension qui y fait un "
                             "module — `` `daemon/src/` (`*.rs`), `web/` (`*.js`) ``. Sans elle la garde "
                             "devrait DEVINER ce qu'est un module, et elle ne devine pas.")
    return dirs, exts, exceptions


def ext_pour(base: str, exts: dict[str, str]) -> str:
    """L'extension déclarée pour le répertoire du périmètre le plus spécifique qui contient `base`. Vide
    si `base` n'est sous aucun d'eux : un nom nu n'y désigne alors qu'un répertoire."""
    candidats = [d for d in exts if base.startswith(d)]
    return exts[max(candidats, key=len)] if candidats else ""


def est_repertoire(chemin: str, arbre: set[str]) -> bool:
    return any(p.startswith(chemin) for p in arbre)


def developper(token: str) -> list[str]:
    """`ingest/{a,b}_store.rs` -> [`ingest/a_store.rs`, `ingest/b_store.rs`] (accolades imbriquées exclues)."""
    groupes = ACCOLADES.findall(token)
    if not groupes:
        return [token]
    gabarit = ACCOLADES.sub("{}", token)
    return [gabarit.format(*choix) for choix in itertools.product(*[g.split(",") for g in groupes])]


def resoudre(token: str, bases: list[str], arbre: set[str], exts: dict[str, str]) -> set[str]:
    """Ce qu'un token REVENDIQUE : des fichiers suivis, ou un répertoire suivi EN TANT QUE TEL (chemin
    terminé par `/`) — jamais le contenu du répertoire, sinon citer `cold_store/` couvrirait chacun de
    ses sous-modules. Ensemble vide si le token ne désigne rien."""
    token = token.split("::", 1)[0].strip()
    if token.startswith("./"):
        token = token[2:]
    if not token:
        return set()
    trouves: set[str] = set()
    for forme in developper(token):
        pour_forme: set[str] = set()
        for base in bases:
            candidat = forme if forme.startswith(base) else base + forme
            if "*" in candidat:
                pour_forme = {p for p in arbre if fnmatch.fnmatchcase(p, candidat)}
            elif candidat.endswith("/"):
                pour_forme = {candidat} if est_repertoire(candidat, arbre) else set()
            elif "/" not in forme and "." not in forme:
                # Nom nu : un fichier de l'extension DÉCLARÉE pour ce répertoire, ou un répertoire.
                ext = ext_pour(base, exts)
                if ext and candidat + ext in arbre:
                    pour_forme = {candidat + ext}
                elif est_repertoire(candidat + "/", arbre):
                    pour_forme = {candidat + "/"}
            elif candidat in arbre:
                pour_forme = {candidat}
            elif est_repertoire(candidat + "/", arbre):
                pour_forme = {candidat + "/"}
            if pour_forme:
                break
        if not pour_forme:
            return set()
        trouves |= pour_forme
    return trouves


def base_du_titre(titre: str, dirs: list[str], arbre: set[str]) -> tuple[str | None, list[str]]:
    """Le répertoire qu'un titre de section cite ; et ceux qu'il cite sans qu'ils existent."""
    base, absents = None, []
    for t in TOKEN.findall(titre):
        if not t.endswith("/"):
            continue
        for d in dirs:
            candidat = t if t.startswith(d) else d + t
            if candidat == d or (candidat.startswith(d) and est_repertoire(candidat, arbre)):
                base = candidat
                break
        else:
            absents.append(t)
    return base, absents


def relire(texte: str, arbre: set[str]) -> dict:
    """Lit le plan contre l'arbre. Rend entrées, chemins absents, modules sans entrée, lignes sans chemin."""
    dirs, exts, exceptions = lire_perimetre(texte)
    revendiques: set[str] = set()  # fichiers, ou répertoires en tant que tels (terminés par `/`)
    absents: list[tuple[int, str]] = []
    sans_chemin: list[int] = []
    entrees = 0
    base_h2: str | None = None
    base: str | None = None
    lignes = texte.splitlines()
    for i, ligne in enumerate(lignes, 1):
        m = TITRE.match(ligne)
        if m:
            b, manquants = base_du_titre(m.group(2), dirs, arbre)
            for t in manquants:
                absents.append((i, t))
            if m.group(1) == "##":
                base_h2 = base = b
            else:
                base = b if b is not None else base_h2
            if b is not None:
                # Un titre revendique le MODULE qu'il nomme (`cold_store/` couvre `cold_store` dans
                # `daemon/src/`), jamais le contenu de ce module : sinon toute section couvrirait tout.
                revendiques.add(b)
            continue
        if base is None or not ligne.lstrip().startswith("|") or SEPARATEUR.match(ligne.lstrip()):
            continue
        suivante = lignes[i] if i < len(lignes) else ""
        if SEPARATEUR.match(suivante.lstrip()):
            continue  # ligne d'en-tête du tableau
        cellules = CELLULE.split(ligne.strip().strip("|"))
        premiere = cellules[0] if cellules else ""
        tokens = TOKEN.findall(premiere)
        if not tokens:
            sans_chemin.append(i)
            continue
        entrees += 1
        base_cellule: str | None = None
        for t in tokens:
            # Les répertoires du périmètre APPARENTÉS à la section seulement (l'un contient l'autre) :
            # un chemin absent d'une caisse ne doit pas être blanchi par un homonyme d'une autre caisse.
            apparentes = [x for x in dirs if x.startswith(base) or base.startswith(x)]
            bases = [b for b in [base_cellule, base, *apparentes] if b]
            trouves = resoudre(t, bases, arbre, exts)
            if not trouves:
                absents.append((i, t))
                continue
            revendiques |= trouves
            if t.endswith("/"):
                # Le répertoire réel désigné, pas le texte : `b/` résolu sous la section.
                base_cellule = next(iter(trouves))
    modules_sans_entree: dict[str, list[str]] = {}
    modules_total = 0
    for d in dirs:
        ext = exts[d]
        facade = "mod" + ext  # `d/mod.rs` EST `d` (convention Rust) ; inerte là où elle n'existe pas.
        noms = set()
        for p in arbre:
            if not p.startswith(d):
                continue
            reste = p[len(d):]
            nom = reste.split("/", 1)[0]
            if "/" not in reste:
                # Un fichier dont l'extension n'est pas celle déclarée n'est pas un module de ce
                # répertoire (`style.css`, une police) : il peut être cité, il n'est pas exigé.
                if not nom.endswith(ext) or nom == facade:
                    continue
                nom = nom[: -len(ext)]
            if nom in exceptions:
                continue
            noms.add(nom)
        modules_total += len(noms)
        # Couvert par le fichier `n.rs`, par le répertoire `n/` en tant que tel, ou par un chemin
        # revendiqué À L'INTÉRIEUR de `n/` (`ingest/mod.rs` couvre `ingest`). Le répertoire PARENT
        # revendiqué en tant que tel ne couvre pas ses enfants.
        manquants = [n for n in sorted(noms)
                     if d + n + ext not in revendiques
                     and not any(p.startswith(d + n + "/") for p in revendiques)]
        modules_sans_entree[d] = manquants
    fichiers = sum(1 for p in arbre if any(p.startswith(d) for d in dirs))
    return {"dirs": dirs, "exceptions": exceptions, "entrees": entrees, "revendiques": revendiques,
            "absents": absents, "sans_chemin": sans_chemin, "modules_sans_entree": modules_sans_entree,
            "modules_total": modules_total, "fichiers": fichiers}


def valider_instrument() -> list[str]:
    """TÉMOIN POSITIF ET TÉMOIN NÉGATIF sur un plan et un arbre de contrôle — avant tout verdict.

    L'arbre de contrôle porte DEUX langages (`d/src/` en `.rs`, `w/` en `.js`) : c'est la seule façon de
    prouver que l'extension est DÉRIVÉE du périmètre déclaré et non codée en dur. Le témoin de
    NON-FUITE (`index.html` cité depuis la section Rust) prouve qu'un chemin absent d'une caisse n'est
    pas blanchi par un homonyme de l'autre.
    """
    arbre = {"d/src/a.rs", "d/src/b/mod.rs", "d/src/b/x.rs", "d/src/c/mod.rs", "d/src/c/one.rs",
             "d/src/c/two.rs", "d/src/c/tests.rs", "d/src/over_a.rs", "d/src/over_b.rs", "d/src/main.rs",
             "d/src/tests/t.rs", "d/src/e.rs", "d/src/h/mod.rs", "d/src/h/k.rs", "other/z.rs",
             "w/a.js", "w/b.js", "w/index.html", "w/sub/f.bin"}
    plan = "\n".join([
        "# Plan de contrôle",
        "Scope: `d/src/` (`*.rs`), `d/src/c/` (`*.rs`), `w/` (`*.js`) — except `tests`.",
        "Prose citing `ghost.rs` and `z` is ignored.",
        "## Other crate — `other-core`",
        "| Core module | Surface |", "|---|---|",
        "| `z` | lives in another tree |",
        "## Subsystems — `d/src/`",
        "### First",
        "| Path | Purpose |", "|---|---|",
        "| `a.rs`, `over*.rs` | see `absent_in_prose.rs` \\| `also_absent.rs` |",
        "| `b/` (`mod`, `x`) | … |",
        "| `main.rs`, `fantome.rs`, `index.html` | the third lives only in the other scope tree |",
        "| bare text, no token | … |",
        "### Nested — `h/`",
        "| Path | Purpose |", "|---|---|",
        "| `k` | relative to the section directory |",
        "## The `c/` submodule map",
        "| Submodule | Owns |", "|---|---|",
        "| `one` | … |",
        "## Invariants",
        "| Invariant | Where |", "|---|---|",
        "| no path here | `ghost2.rs` |",
        "## Console — `w/`",
        "| Path | Kind | Purpose |", "|---|---|---|",
        "| `a` | render | bare name resolved with the extension DECLARED for this directory |",
        "| `sub/`, `index.html` | asset | a directory, and a file whose extension is not the module one |",
    ])
    try:
        r = relire(plan, arbre)
    except InstrumentMuet as e:
        return [f"témoin en échec : le plan de contrôle n'est pas lu ({e})"]
    errs = []
    attendus = {"d/src/a.rs", "d/src/over_a.rs", "d/src/over_b.rs", "d/src/b/", "d/src/b/mod.rs",
                "d/src/b/x.rs", "d/src/main.rs", "d/src/c/", "d/src/c/one.rs", "d/src/h/", "d/src/h/k.rs",
                "w/", "w/a.js", "w/sub/", "w/index.html"}
    if not attendus <= r["revendiques"]:
        errs.append(f"témoin POSITIF en échec : non résolus {sorted(attendus - r['revendiques'])} — "
                    "une forme d'entrée que la garde DOIT reconnaître ne l'est plus (dont le nom nu résolu "
                    "avec l'extension déclarée du répertoire, `.js` comme `.rs`).")
    if r["absents"] != [(14, "fantome.rs"), (14, "index.html")]:
        errs.append(f"témoin en échec : chemins absents attendus [(14, 'fantome.rs'), (14, 'index.html')], "
                    f"obtenus {r['absents']} — soit un chemin absent n'est plus nommé, soit une mention en "
                    "prose / seconde cellule / section hors périmètre est comptée comme une entrée, soit un "
                    "chemin d'une AUTRE caisse du périmètre blanchit une citation de celle-ci.")
    if r["sans_chemin"] != [15]:
        errs.append(f"témoin en échec : lignes sans chemin attendues [15], obtenues {r['sans_chemin']}.")
    if r["modules_sans_entree"] != {"d/src/": ["e"], "d/src/c/": ["two"], "w/": ["b"]}:
        errs.append(f"témoin en échec : modules sans entrée attendus {{d/src/: [e], d/src/c/: [two], "
                    f"w/: [b]}}, obtenus {r['modules_sans_entree']} — `tests` est excepté, `mod.rs` est le "
                    "répertoire lui-même, `h/` est couvert par son titre de section, `c/` aussi mais pas ses "
                    "sous-modules, `w/index.html` n'est pas un module (extension déclarée `.js`) et "
                    "`w/sub/` en est un, couvert par son entrée.")
    if r["entrees"] != 7:
        errs.append(f"témoin en échec : 7 entrées attendues dans le périmètre, {r['entrees']} comptées.")
    try:
        lire_perimetre("pas de périmètre ici\n")
        errs.append("témoin en échec : un plan sans ligne `Scope:` doit rendre l'instrument muet.")
    except InstrumentMuet:
        pass
    try:
        lire_perimetre("Scope: `d/src/`, `w/` — except `tests`.\n")
        errs.append("témoin en échec : un périmètre qui ne DÉCLARE pas l'extension de module d'un répertoire "
                    "doit rendre l'instrument muet — sinon la garde devine ce qu'est un module.")
    except InstrumentMuet:
        pass
    return errs


def main(argv: list[str]) -> int:
    mesure = "--mesure" in argv
    plan = PLAN
    if "--plan" in argv:
        plan = argv[argv.index("--plan") + 1]

    errs = valider_instrument()
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print("\nL'instrument ne reconnaît pas son propre corpus : la garde refuse de conclure.")
        return 2

    arbre = lire_arbre()
    if arbre is None:
        print("::error::`git ls-files` ne répond pas : instrument muet, aucun verdict (un vert ici serait aveugle).")
        return 2
    chemin_plan = plan if os.path.isabs(plan) else os.path.join(RACINE, plan)
    try:
        with open(chemin_plan, encoding="utf-8") as fh:
            texte = fh.read()
    except OSError as e:
        print(f"::error::le plan `{plan}` n'est pas lisible ({e}) : instrument muet.")
        return 2
    try:
        r = relire(texte, arbre)
    except InstrumentMuet as e:
        print(f"::error file={PLAN}::{e}")
        return 2

    if r["fichiers"] < MIN_FICHIERS:
        print(f"::error::{r['fichiers']} fichiers suivis sous {r['dirs']}, plancher {MIN_FICHIERS} : soit la "
              f"lecture de l'arbre est cassée, soit le périmètre ne désigne plus l'arbre.")
        return 2
    if r["entrees"] < MIN_ENTREES:
        print(f"::error file={PLAN}::{r['entrees']} entrées lues dans le périmètre, plancher {MIN_ENTREES} : "
              f"les témoins passent mais le plan réel n'est plus reconnu (reformatage, titres sans répertoire).")
        return 2

    print(f"périmètre {', '.join(r['dirs'])} (exceptés : {', '.join(sorted(r['exceptions'])) or '—'}) ; "
          f"{r['entrees']} entrées, {len(r['revendiques'])} chemins revendiqués, {r['fichiers']} fichiers suivis ; "
          f"{len(r['absents'])} chemin(s) cité(s) absent(s) ; "
          f"{sum(len(v) for v in r['modules_sans_entree'].values())} module(s) sans entrée sur {r['modules_total']}.")
    for d, manquants in r["modules_sans_entree"].items():
        print(f"  {d}: {len(manquants)} sans entrée" + (f" — {', '.join(manquants)}" if manquants else ""))
    for i, t in r["absents"]:
        print(f"  absent : ligne {i} `{t}`")
    if mesure:
        return 0

    verdicts = []
    for i in r["sans_chemin"]:
        verdicts.append(f"file={PLAN},line={i}::entrée sans chemin : la première cellule d'une ligne de tableau du "
                        f"périmètre cite au moins un chemin entre accents graves, sinon rien ne la relit.")
    if len(r["absents"]) > PLAFOND_CHEMINS_ABSENTS:
        for i, t in r["absents"]:
            verdicts.append(f"file={PLAN},line={i}::`{t}` n'existe pas dans l'arbre suivi (plafond "
                            f"{PLAFOND_CHEMINS_ABSENTS}) : le plan nomme un chemin que le lecteur ne trouvera pas — "
                            f"renommez l'entrée ou retirez-la.")
    for d, manquants in r["modules_sans_entree"].items():
        if len(manquants) > PLAFOND_MODULES_SANS_ENTREE:
            for n in manquants:
                verdicts.append(f"file={PLAN}::module `{d}{n}` sans entrée (plafond {PLAFOND_MODULES_SANS_ENTREE}) : "
                                f"ajoutez une ligne de tableau, lue depuis le fichier, dans une section dont le titre "
                                f"nomme `{d}`.")
    if verdicts:
        for v in verdicts:
            print(f"::error {v}")
        print(f"\n{len(verdicts)} écart(s) entre le plan des modules et l'arbre suivi.")
        return 1
    print("Le plan des modules et l'arbre suivi concordent, dans les deux sens.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
