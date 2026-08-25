#!/usr/bin/env python3
"""Ce qu'un exploitant doit pouvoir TROUVER est documenté — garde de CI (`P9.7-b`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Le corpus dérive parce que RIEN ne le lie au code. Un levier de configuration ajouté, un capteur
livré, un onglet de console posé, un mode de déploiement reconnu : aucun de ces gestes ne fait
rougir un instrument s'il n'est écrit nulle part. Une campagne de documentation sans cliquet est
donc à refaire à chaque fois — et c'est exactement ce que la roadmap de ce dépôt a mesuré deux fois.

MESURÉ SUR L'ARBRE SUIVI le 2026-08-25, avant la campagne qui accompagne cette garde : sur les
37 onglets que la console DÉCLARE, **3** avaient une entrée dans le corpus. Les 34 autres n'étaient
décrits nulle part — ni leur rôle, ni ce qu'on y fait, ni ce qu'ils ne font pas. Dans le même temps,
39 des 39 capteurs livrés en avaient une : le critère n'est donc pas hors d'atteinte, c'est une
partie de la surface qui n'avait jamais été relue.

CE QU'EST UNE « ENTRÉE » — LE CRITÈRE, ÉCRIT UNE FOIS
-----------------------------------------------------
Une ENTRÉE est un jeton entre accents graves dans la PREMIÈRE CELLULE d'une ligne de tableau
Markdown, dans un document SUIVI. Ce n'est pas « être cité » : une mention en prose ne compte pas.
Le choix est délibéré et il est le même que celui de `check_every_doc_is_reachable.py` — un lecteur
suit une structure, pas une occurrence. Une première cellule de tableau est la forme minimale d'un
engagement : elle dit « voici la chose, et voici ce qu'on en sait », alors qu'une mention en prose
peut n'être qu'un mot de passage.

LES QUATRE INVENTAIRES SONT DÉRIVÉS, JAMAIS ÉNUMÉRÉS ICI
---------------------------------------------------------
  (A) ONGLETS DE LA CONSOLE. Le module qui porte la structure de navigation est lui-même DÉRIVÉ :
      c'est l'unique fichier suivi sous `web/` qui contient la définition `const SPACES = [`.
      Zéro ou plusieurs porteurs -> la dérivation ne conclut pas (code 2). ANCRAGE SUR LA PROPRIÉTÉ,
      PAS SUR LE NOM : ce dépôt a déjà payé une garde aveugle parce qu'elle nommait un fichier qu'on
      a déplacé. Le module peut être renommé ou scindé sans que cette garde perde son objet.
  (B) CAPTEURS LIVRÉS. Les scripts suivis de `collectors/`, MOINS ceux qu'un autre script de ce
      répertoire SOURCE (`. <chemin>`) : une bibliothèque partagée n'est pas un capteur, et c'est le
      fait d'être sourcée — non son nom — qui en fait une bibliothèque.
  (C) MODES DE DÉPLOIEMENT. Les alternatives que le script de désinstallation ACCEPTE dans son
      `case` sur le mode. Là encore le script est dérivé par son contenu, pas nommé.
  (D) LEVIERS `PLUME_*`. Les identifiants lus par le code de PRODUCTION : `daemon/src` hors tests
      (formes `env::var("PLUME_…")` et `cfg…("PLUME_…")`), plus `collectors/` et les deux
      installateurs (formes `$PLUME_…` et `${PLUME_…`). C'est le MÊME critère que les commandes
      publiées dans `README.md` — une règle écrite deux fois finit par diverger, celle-ci est donc
      écrite ici et republiée là-bas à l'identique.

DEUX RÉGIMES DE VERDICT, ET POURQUOI ILS DIFFÈRENT
---------------------------------------------------
(A), (B), (C) sont des inventaires COURTS et STABLES : chaque élément doit avoir son entrée, plafond
à ZÉRO. Ajouter un onglet ou un capteur sans l'écrire fait rougir, et c'est l'objet.
(D) est un inventaire de plusieurs centaines d'entrées dont la majorité n'a, à ce jour, d'autre
documentation que le code qui la lit. Exiger zéro serait exiger l'impossible et la garde finirait
désarmée. On pose donc un CLIQUET : le nombre de leviers qu'AUCUN document ne cite est PUBLIÉ à
chaque exécution et ne doit jamais AUGMENTER. Un levier ajouté sans un mot le fait franchir ; en
documenter un autorise à abaisser le plafond, ce qui est le seul sens admis. C'est le patron des
gardes sœurs de ce dépôt : ce qui n'est pas couvert est DIT, avec un cliquet dessus, plutôt que tu.

CE QUE CETTE GARDE NE VOIT PAS — dit pour qu'on ne s'en réclame pas trop
------------------------------------------------------------------------
Elle ne juge PAS la qualité d'une entrée : une ligne de tableau qui nommerait un onglet sans rien en
dire la satisfait. Elle ne SCOPE PAS le document : un identifiant court qui apparaîtrait en première
cellule d'un tableau sans rapport serait compté (mesuré avant campagne : 3 sur 37 seulement, donc
l'effet est marginal — mais il existe). Elle ne lit QUE des documents suivis : un document non
ajouté à l'index git n'existe pas pour elle, comme il n'existe pas pour le lecteur du dépôt. Elle ne
regarde pas les fichiers autres que Markdown : `Dockerfile` et `docker-compose.yml` portent eux
aussi des constantes citées, et ils sont hors de ce périmètre. Enfin elle juge des FORMES, pas du
sens : la relecture reste nécessaire, comme le dit `AGENTS.md`.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
--------------------------------------------------
Une garde d'extraction rend vert de deux façons : parce que tout va bien, ou parce que son motif ne
reconnaît plus rien. Avant tout verdict elle exécute un corpus de contrôle portant ses DEUX témoins
— des formes qu'elle DOIT reconnaître (première cellule, plusieurs jetons, accents graves contenant
une barre verticale, ligne sans barre de tête) et des formes qu'elle NE DOIT PAS compter (seconde
cellule, prose, ligne de séparation, bloc de code) — puis la dérivation des quatre inventaires sur
un arbre de contrôle, puis des PLANCHERS sur l'arbre réel. Un dépouillement qui ne trouverait plus
rien ÉCHOUE au lieu de se taire.

Usage :  python3 .github/scripts/check_operator_surface_is_documented.py [--mesure] [RACINE]
Sortie :  0 = la surface d'exploitation est documentée · 1 = un écart au-dessus d'un plafond ·
          2 = instrument muet ou faux (aucun verdict rendu). `--mesure` imprime les comptes sans
          verdict.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_style_selector_has_a_target import racine_designee  # noqa: E402  (source unique)

# --- PLAFONDS ------------------------------------------------------------------------------------
# Inventaires courts : ZÉRO manquant. Relevés sur l'arbre suivi le 2026-08-25 après la campagne
# `P9.7-a` : 37 onglets, 39 capteurs, 3 modes, tous avec une entrée.
PLAFOND_ONGLETS_SANS_ENTREE = 0
PLAFOND_CAPTEURS_SANS_ENTREE = 0
PLAFOND_MODES_SANS_ENTREE = 0
# CLIQUET des leviers. Relevé sur l'arbre suivi le 2026-08-25, campagne `P9.7-a` comprise :
# 299 leviers lus par le code de production, 131 cités par au moins un document ou `.env.example`,
# 168 cités nulle part. Le relevé de la veille était 130/169 ; la campagne en a documenté un de plus
# (`PLUME_QUERY_BUDGET_INTERACTIVE_MS`) et le plafond a été abaissé d'autant — c'est le seul sens
# admis. Il ne MONTE jamais sans une raison écrite ici même.
PLAFOND_LEVIERS_SANS_DOC = 168

# --- PLANCHERS DE NON-DÉGÉNÉRESCENCE -------------------------------------------------------------
# En dessous, c'est la LECTURE qui est cassée, pas l'arbre qui a maigri — et une garde qui ne
# trouverait plus rien rendrait vert en ne vérifiant rien. Relevés sur l'arbre suivi le 2026-08-25 :
# 37 onglets, 39 capteurs, 3 modes, 299 leviers, 612 jetons en première cellule, 50 documents.
MIN_ONGLETS = 25
MIN_CAPTEURS = 30
MIN_MODES = 2
MIN_LEVIERS = 200
MIN_ENTREES = 200
MIN_DOCS = 40

# --- MOTIFS --------------------------------------------------------------------------------------
# La DÉFINITION de la structure de navigation. Même ancre pour localiser le module et pour en lire
# les onglets : le fichier n'est jamais nommé.
DEFINITION_NAVIGATION = re.compile(r"\bconst\s+SPACES\s*=\s*\[")
# Un onglet : `{ id: 'x', label: … }` — c'est la présence de `label` qui distingue un onglet d'un
# espace (un espace porte `tabs:`), donc la forme, pas la position.
ONGLET = re.compile(r"\{\s*id:\s*['\"]([A-Za-z0-9_-]+)['\"]\s*,\s*label\s*:")
# Le `case` qui VALIDE le mode de déploiement, et la liste de ses alternatives.
CASE_DU_MODE = re.compile(r'case\s+"\$\{MODE\}"\s+in\s+([^)]*)\)')
# Sourcing POSIX en tête de ligne : `. <chemin>` ou `source <chemin>`.
SOURCING = re.compile(r"^\s*(?:\.|source)\s+\S")
NOM_SH = re.compile(r"([A-Za-z0-9_.-]+\.sh)")
# Leviers, MÊME critère que les commandes publiées dans `README.md`.
LEVIER_RUST = re.compile(r'(?:env::var|cfg[a-z_]*)\([^)]*"(PLUME_[A-Z0-9_]+)"')
LEVIER_SHELL = re.compile(r"\$\{?(PLUME_[A-Z0-9_]+)")
LEVIER_NU = re.compile(r"\b(PLUME_[A-Z0-9_]+)")
# Tableaux Markdown.
SEPARATEUR = re.compile(r"^\|?\s*:?-{3,}")
CODE_SPAN = re.compile(r"`[^`\n]*`")
CLOTURE_DE_BLOC = re.compile(r"^\s*(```|~~~)")


class InstrumentMuet(Exception):
    """Une dérivation n'a pas pu conclure : aucun verdict n'est rendu."""


# --- Extraction ----------------------------------------------------------------------------------

def entrees_de_tableau(texte: str) -> set[str]:
    """Les jetons entre accents graves de la PREMIÈRE CELLULE de chaque ligne de tableau.

    Les blocs de code sont sautés (une ligne de shell commence souvent par autre chose qu'une barre,
    mais un tableau collé dans un bloc n'est pas un engagement du document). Les barres verticales
    situées DANS un accent grave ne découpent pas de cellule : `` `a|b` `` reste une cellule.
    """
    out: set[str] = set()
    dans_bloc = False
    for ligne in texte.splitlines():
        if CLOTURE_DE_BLOC.match(ligne):
            dans_bloc = not dans_bloc
            continue
        if dans_bloc:
            continue
        s = ligne.strip()
        if "|" not in s:
            continue
        if SEPARATEUR.match(s.lstrip("|")):
            continue
        # Protéger les accents graves avant de découper.
        spans: list[str] = []

        def _garde(m: re.Match) -> str:
            spans.append(m.group(0))
            return f"\x00{len(spans) - 1}\x00"

        masque = CODE_SPAN.sub(_garde, s)
        cellules = re.split(r"(?<!\\)\|", masque)
        if s.startswith("|"):
            cellules = cellules[1:]
        if not cellules:
            continue
        premiere = re.sub(r"\x00(\d+)\x00", lambda m: spans[int(m.group(1))], cellules[0])
        out |= {t.strip() for t in re.findall(r"`([^`]+)`", premiere) if t.strip()}
    return out


# Les INSTRUMENTS ne sont pas des sources. Une garde cite forcément les motifs qu'elle cherche —
# celle-ci porte le `case` des modes dans son propre corpus témoin — et se compterait elle-même
# comme porteuse de la définition, rendant la dérivation ambiguë donc MUETTE. L'exclusion porte sur
# le répertoire des gardes, pas sur un nom de fichier : elle survit à un renommage de ce script.
INSTRUMENTS = ".github/scripts/"


def porteur_unique(racine: str, suivis: list[str], sous: str, motif: re.Pattern, quoi: str) -> str:
    """L'unique fichier suivi sous `sous/` qui contient `motif`. Zéro ou plusieurs -> muet."""
    porteurs = []
    for chemin in suivis:
        if sous and not chemin.startswith(sous):
            continue
        if chemin.startswith(INSTRUMENTS):
            continue
        try:
            with open(os.path.join(racine, chemin), encoding="utf-8", errors="replace") as fh:
                if motif.search(fh.read()):
                    porteurs.append(chemin)
        except OSError:
            continue
    if len(porteurs) != 1:
        raise InstrumentMuet(
            f"{quoi} : {len(porteurs)} porteur(s) de la définition ({porteurs or 'aucun'}). "
            f"Cette garde DÉRIVE le fichier de son contenu, jamais de son nom — s'il a été scindé, "
            f"la définition doit rester en UN seul endroit, sinon l'inventaire n'a plus de source.")
    return porteurs[0]


def onglets_declares(racine: str, suivis: list[str]) -> tuple[str, list[str]]:
    module = porteur_unique(racine, suivis, "web/", DEFINITION_NAVIGATION, "onglets de la console")
    with open(os.path.join(racine, module), encoding="utf-8", errors="replace") as fh:
        texte = fh.read()
    debut = DEFINITION_NAVIGATION.search(texte).start()
    fin = texte.find("\n];", debut)
    bloc = texte[debut:fin if fin > 0 else len(texte)]
    return module, sorted({m.group(1) for m in ONGLET.finditer(bloc)})


def modes_declares(racine: str, suivis: list[str]) -> tuple[str, list[str]]:
    script = porteur_unique(racine, suivis, "", CASE_DU_MODE, "modes de déploiement")
    with open(os.path.join(racine, script), encoding="utf-8", errors="replace") as fh:
        m = CASE_DU_MODE.search(fh.read())
    alternatives = [a.strip().strip('"').strip("'") for a in m.group(1).split("|")]
    return script, sorted({a for a in alternatives if a})


def capteurs_livres(racine: str, suivis: list[str]) -> list[str]:
    """Les scripts de `collectors/`, moins ceux qu'un autre script du même répertoire SOURCE."""
    scripts = [c for c in suivis if c.startswith("collectors/") and c.endswith(".sh")
               and "/" not in c[len("collectors/"):]]
    sources: set[str] = set()
    for c in scripts:
        try:
            with open(os.path.join(racine, c), encoding="utf-8", errors="replace") as fh:
                for ligne in fh:
                    if SOURCING.match(ligne):
                        sources |= set(NOM_SH.findall(ligne))
        except OSError:
            continue
    return sorted({os.path.basename(c)[:-3] for c in scripts if os.path.basename(c) not in sources})


def leviers_lus(racine: str, suivis: list[str]) -> set[str]:
    """Les `PLUME_*` que lit le code de PRODUCTION (tests exclus par le CHEMIN, critère écrit)."""
    out: set[str] = set()
    for chemin in suivis:
        parties = chemin.split("/")
        if chemin.startswith("daemon/src/") and chemin.endswith(".rs"):
            if "tests" in parties or parties[-1] in ("tests.rs", "test.rs"):
                continue
            motif = LEVIER_RUST
        elif chemin.startswith("collectors/") or chemin in ("bootstrap.sh", "bootstrap-agent.sh"):
            motif = LEVIER_SHELL
        else:
            continue
        try:
            with open(os.path.join(racine, chemin), encoding="utf-8", errors="replace") as fh:
                out |= set(motif.findall(fh.read()))
        except OSError:
            continue
    return out


def leviers_cites(racine: str, suivis: list[str]) -> set[str]:
    """Les `PLUME_*` que cite le corpus : documents suivis + `.env.example` (une documentation)."""
    out: set[str] = set()
    corpus = [d for d in suivis if d.endswith(".md")]
    if ".env.example" in suivis:
        corpus.append(".env.example")
    for d in corpus:
        try:
            with open(os.path.join(racine, d), encoding="utf-8", errors="replace") as fh:
                out |= set(LEVIER_NU.findall(fh.read()))
        except OSError:
            continue
    return out


# --- Validation de l'instrument ------------------------------------------------------------------

CORPUS_TABLEAU = """
Un texte de prose qui cite `onglet-en-prose` sans tableau.

| `alpha` | `pas-compte-seconde-cellule` |
|---|---|
| `beta` / `gamma` | description |
| `a|b` | une barre DANS un accent grave ne coupe pas la cellule |
`delta` en tête de ligne | mais la ligne porte une barre | et pas de barre de tête

```
| `dans-un-bloc-de-code` | ne compte pas |
```
"""

CORPUS_NAVIGATION = """
const SPACES = [
  { id: 'espace1', tabs: [
    { id: 'onglet-a', label: 'A', sections: ['s'] },
    { id: 'onglet-b', label: "B", sections: ['s'], admin: true },
  ] },
];
const AUTRE = { id: 'pas-un-onglet', tabs: [] };
"""


def valider_instrument() -> list[str]:
    """TÉMOIN POSITIF ET TÉMOIN NÉGATIF, sur un corpus de contrôle — avant tout verdict."""
    errs: list[str] = []

    vu = entrees_de_tableau(CORPUS_TABLEAU)
    doit = {"alpha", "beta", "gamma", "a|b", "delta"}
    if not doit <= vu:
        errs.append(f"témoin POSITIF (entrées) en échec : manquent {sorted(doit - vu)} — "
                    f"le motif de première cellule ne reconnaît plus les formes qu'il doit voir.")
    interdit = {"pas-compte-seconde-cellule", "onglet-en-prose", "dans-un-bloc-de-code"}
    if vu & interdit:
        errs.append(f"témoin NÉGATIF (entrées) en échec : {sorted(vu & interdit)} compté(s) alors "
                    f"qu'une seconde cellule, une MENTION en prose et un bloc de code ne sont pas "
                    f"des entrées — c'est exactement le laxisme que cette garde refuse.")

    onglets = {m.group(1) for m in ONGLET.finditer(CORPUS_NAVIGATION)}
    if onglets != {"onglet-a", "onglet-b"}:
        errs.append(f"témoin (onglets) en échec : attendu ['onglet-a', 'onglet-b'], obtenu "
                    f"{sorted(onglets)} — la forme `id`+`label` ne discrimine plus un onglet d'un "
                    f"espace, ou les guillemets doubles ne sont plus reconnus.")

    m = CASE_DU_MODE.search('case "${MODE}" in ""|host|docker|k3s) ;; *) exit 1 ;; esac')
    modes = sorted({a.strip().strip('"') for a in m.group(1).split("|")} - {""}) if m else []
    if modes != ["docker", "host", "k3s"]:
        errs.append(f"témoin (modes) en échec : obtenu {modes} — le `case` qui valide le mode n'est "
                    f"plus reconnu, l'inventaire des modes serait vide et la garde muette.")

    if LEVIER_RUST.findall('let x = cfg(&c, "PLUME_ALPHA", "0"); env::var("PLUME_BETA")') \
            != ["PLUME_ALPHA", "PLUME_BETA"]:
        errs.append("témoin (leviers Rust) en échec : les deux formes de lecture ne sont plus vues.")
    if LEVIER_RUST.findall('eprintln!("PLUME_GAMMA est ignoré")'):
        errs.append("témoin NÉGATIF (leviers Rust) en échec : un nom cité dans un message n'est pas "
                    "une lecture ; le compter gonflerait l'inventaire d'un levier qui n'existe pas.")
    if LEVIER_SHELL.findall('a="${PLUME_DELTA:-1}"; b=$PLUME_EPSILON') != ["PLUME_DELTA", "PLUME_EPSILON"]:
        errs.append("témoin (leviers shell) en échec : les deux formes d'expansion ne sont plus vues.")
    return errs


# --- Verdict -------------------------------------------------------------------------------------

def manquants(inventaire, entrees) -> list[str]:
    return sorted(x for x in inventaire if x not in entrees)


def main() -> int:
    argv = [a for a in sys.argv if a != "--mesure"]
    mesure = "--mesure" in sys.argv
    racine = racine_designee(argv)

    errs = valider_instrument()
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print("\nl'INSTRUMENT est faux : aucun verdict n'est rendu (un vert l'aurait été pour de "
              "mauvaises raisons).")
        return 2

    fait = subprocess.run(["git", "ls-files"], cwd=racine, capture_output=True, text=True)
    if fait.returncode:
        print("::error::`git ls-files` ne répond pas : l'arbre suivi n'est pas lisible, aucun "
              "verdict n'est rendu.")
        return 2
    suivis = [p for p in fait.stdout.split("\n") if p]

    docs = [d for d in suivis if d.endswith(".md")]
    if len(docs) < MIN_DOCS:
        print(f"::error::{len(docs)} documents suivis découverts, plancher {MIN_DOCS} : la "
              f"découverte est cassée, ou des documents ont légitimement disparu — dans ce cas "
              f"baissez MIN_DOCS depuis votre propre compte.")
        return 2

    entrees: set[str] = set()
    for d in docs:
        try:
            with open(os.path.join(racine, d), encoding="utf-8", errors="replace") as fh:
                entrees |= entrees_de_tableau(fh.read())
        except OSError:
            continue

    try:
        module_nav, onglets = onglets_declares(racine, suivis)
        script_modes, modes = modes_declares(racine, suivis)
    except InstrumentMuet as e:
        print(f"::error::{e}")
        return 2
    capteurs = capteurs_livres(racine, suivis)
    lus = leviers_lus(racine, suivis)
    cites = leviers_cites(racine, suivis)
    sans_doc = sorted(lus - cites)

    planchers = [
        (len(onglets), MIN_ONGLETS, f"onglets déclarés par `{module_nav}`"),
        (len(capteurs), MIN_CAPTEURS, "capteurs livrés sous `collectors/`"),
        (len(modes), MIN_MODES, f"modes de déploiement acceptés par `{script_modes}`"),
        (len(lus), MIN_LEVIERS, "leviers `PLUME_*` lus par le code de production"),
        (len(entrees), MIN_ENTREES, "jetons en première cellule de tableau dans le corpus"),
    ]
    sous_plancher = [(n, p, q) for n, p, q in planchers if n < p]
    if sous_plancher:
        for n, p, q in sous_plancher:
            print(f"::error::{n} {q}, plancher {p} : les témoins passent mais l'arbre réel n'est "
                  f"plus reconnu. Corrigez l'extraction — ne baissez ce plancher que sur votre "
                  f"propre compte.")
        return 2

    if mesure:
        print(f"onglets      {len(onglets):4d}  sans entrée {len(manquants(onglets, entrees)):4d}  "
              f"(source : {module_nav})")
        print(f"capteurs     {len(capteurs):4d}  sans entrée {len(manquants(capteurs, entrees)):4d}")
        print(f"modes        {len(modes):4d}  sans entrée {len(manquants(modes, entrees)):4d}  "
              f"(source : {script_modes})")
        print(f"leviers lus  {len(lus):4d}  cités {len(lus & cites):4d}  sans doc {len(sans_doc):4d}")
        print(f"entrées      {len(entrees):4d}  documents {len(docs):4d}")
        return 0

    verdicts: list[str] = []
    for inventaire, plafond, quoi, remede in (
        (onglets, PLAFOND_ONGLETS_SANS_ENTREE, "onglet de la console",
         f"décrivez-le dans une ligne de tableau (il est déclaré par `{module_nav}`)"),
        (capteurs, PLAFOND_CAPTEURS_SANS_ENTREE, "capteur livré",
         "ajoutez-lui une ligne au tableau des capteurs"),
        (modes, PLAFOND_MODES_SANS_ENTREE, "mode de déploiement",
         f"décrivez-le pour les gestes d'exploitation (il est accepté par `{script_modes}`)"),
    ):
        absents = manquants(inventaire, entrees)
        if len(absents) > plafond:
            for a in absents:
                verdicts.append(
                    f"`{a}` : {quoi} DÉCLARÉ par le code et sans aucune entrée dans le corpus "
                    f"(plafond {plafond}). Un exploitant ne peut pas le trouver — {remede}. "
                    f"Une MENTION en prose ne compte pas : la première cellule d'une ligne de "
                    f"tableau est ce qui engage le document.")

    if len(sans_doc) > PLAFOND_LEVIERS_SANS_DOC:
        surplus = len(sans_doc) - PLAFOND_LEVIERS_SANS_DOC
        verdicts.append(
            f"{len(sans_doc)} leviers `PLUME_*` ne sont cités par AUCUN document ni par "
            f"`.env.example` — le cliquet est à {PLAFOND_LEVIERS_SANS_DOC}, dépassé de {surplus}. "
            f"Ce qui n'est pas documenté ne doit jamais AUGMENTER en silence : documentez le ou les "
            f"leviers ajoutés, ou déclarez-les hors périmètre en écrivant pourquoi. "
            f"CETTE GARDE COMPTE, ELLE NE TIENT PAS LA LISTE D'HIER : elle ne peut donc pas NOMMER "
            f"ceux qui viennent d'apparaître. Pour les isoler, comparez la sortie de la commande 3 "
            f"de la section « Configuration » de `README.md` entre votre branche et la base. "
            f"Extrait de la liste complète, par ordre alphabétique : {', '.join(sans_doc[:12])}…")

    if verdicts:
        for v in verdicts:
            print(f"::error::{v}")
        print(f"\nsurface d'exploitation : {len(onglets)} onglets, {len(capteurs)} capteurs, "
              f"{len(modes)} modes, {len(lus)} leviers — et ce qui précède n'est trouvable nulle part.")
        return 1

    print(f"surface d'exploitation documentée — {len(onglets)} onglets (source : {module_nav}), "
          f"{len(capteurs)} capteurs, {len(modes)} modes ({script_modes}) : tous ont une entrée. "
          f"Leviers `PLUME_*` : {len(lus)} lus, {len(lus & cites)} cités, {len(sans_doc)} sans "
          f"aucune documentation (cliquet {PLAFOND_LEVIERS_SANS_DOC}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
