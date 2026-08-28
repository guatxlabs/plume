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
  (D) LEVIERS `PLUME_*`. Les identifiants lus par le code de PRODUCTION : `daemon/src` hors tests,
      plus `collectors/` et les deux installateurs (formes `$PLUME_…` et `${PLUME_…`).
      LA LECTURE RUST EST POSITIONNELLE ET SUIT LES CONSTANTES — corrigé le 2026-08-28, et la
      correction a révélé une dette qui a été PAYÉE le même jour. L'ancien motif cherchait un
      littéral `"PLUME_…"` n'importe où avant la première parenthèse fermante de l'appel. Il
      manquait DEUX familles, MESURÉES sur l'arbre suivi : (a) un levier NOMMÉ PAR UNE CONSTANTE
      (`cfg(&conf, LEVIER_QUOTA_DEVERSEMENT, …)`) — 22 constantes `PLUME_*` déclarées dans le code
      de production, dont UNE SEULE était vue ; (b) un appel dont un argument antérieur porte une
      parenthèse (`cfg(&load_config(), "PLUME_ROLLUP_DIMS", …)`), coupé net par le `[^)]*`.
      Bilan de la correction : **164 -> 180 leviers Rust, et l'ancien ensemble est INCLUS dans le
      nouveau** (aucun levier perdu — c'est le témoin qui autorise à remplacer le motif). Un seul
      des seize nouveaux n'était cité par aucun document (`PLUME_RETENTION_PURGE_BATCH`) : il a été
      documenté, donc le cliquet ci-dessous NE MONTE PAS.
      CE QUE CETTE LECTURE NE RÉSOUT PAS EST PUBLIÉ, PAS TU : une clé qui est une VARIABLE
      D'EXÉCUTION (`cfg(&conf, k, …)` dans une boucle) n'a pas de nom statique. Leur nombre est
      imprimé à chaque exécution. Ce ne sont pas des leviers documentables, mais un compte qui
      grimperait dirait qu'une famille entière est passée derrière une indirection.
      ET CE COMPTE PORTAIT UN PLANCHER DE 3 (mesuré le 2026-08-28, corrigé) : les EN-TÊTES de
      `fn cfg`/`fn cfg_secret`/`fn cfg_secret_optional` étaient lus comme des appels, avec pour
      « clé » le fragment `String>` d'un `HashMap<String, String>` coupé par le découpage à la
      virgule. Une DÉCLARATION n'est pas une lecture ; elle est écartée par sa PROPRIÉTÉ (le mot-clé
      `fn` qui la précède), pas par son nom — cf. `est_une_declaration`. 22 -> 19.
      Les blocs `#[cfg(test)]` sont RETIRÉS du texte avant lecture : le critère annonçait déjà
      « code de PRODUCTION », mais il n'excluait les tests que par le CHEMIN — un `mod tests` en
      ligne dans un fichier de production y échappait (mesuré : `PLUME_REFERENCE_BUILD_CHILD`,
      marqueur de sous-processus d'un test de `migrate.rs`, comptait comme un levier d'exploitant).
  (E) LEVIERS DU MODULE QUI DÉCIDE LE BUDGET MÉMOIRE (`P10.1-c`). Même dérivation que (D), mais
      restreinte à UN module et sous plafond ZÉRO. Le module est DÉRIVÉ, jamais nommé : c'est
      l'unique fichier suivi de `daemon/src` hors tests qui COMPOSE le lot de pragmas du budget —
      celui qui porte à la fois `PRAGMA temp_store=`, `PRAGMA cache_size=` et `PRAGMA mmap_size=`.
      C'est la propriété que le module revendique lui-même (« le budget mémoire est décidé ici et
      NULLE PART ailleurs ») ; il peut donc être renommé ou déplacé sans que la garde perde son
      objet. POURQUOI ZÉRO ICI ALORS QUE (D) EST UN CLIQUET : le cliquet tolère 168 leviers muets,
      donc un levier ajouté À CE MODULE peut s'y glisser dès qu'un autre est documenté ailleurs.
      C'est exactement ce qui est arrivé — MESURÉ le 2026-08-28, avant correctif : sur les six
      leviers de ce module, DEUX n'avaient d'entrée nulle part
      (`PLUME_SQLITE_DEVERSEMENT_QUOTA_MO`, qui n'était cité par AUCUN document, et
      `PLUME_PANEL_REFRESH_CONCURRENCY`, cité en PROSE dans `ARCHITECTURE.md` et donc invisible au
      critère d'entrée). Un instrument qui ne saurait pas résoudre une clé de ce module REFUSE DE
      CONCLURE : un verdict à tolérance zéro rendu sur un inventaire partiel serait faux.

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
# LES AIDES DE LECTURE RUST SONT EMPRUNTÉES, PAS RECOPIÉES. Blanchiment des commentaires et des
# littéraux, et intervalles couverts par un attribut : trois règles déjà écrites, éprouvées par les
# témoins de leur propre garde. Une quatrième copie de « où commence un `#[cfg(test)]` » divergerait
# comme ont divergé les quatre `temp_store` que `daemon/src/sqlite_plafond.rs` a dû réunir.
from check_a_producer_declares_the_values_it_emits import (  # noqa: E402  (source unique)
    _code,
    _dans,
    _hors_commentaire,
    _spans_attribut,
    _zones,
)

# --- PLAFONDS ------------------------------------------------------------------------------------
# Inventaires courts : ZÉRO manquant. Relevés sur l'arbre suivi le 2026-08-25 après la campagne
# `P9.7-a` : 37 onglets, 39 capteurs, 3 modes, tous avec une entrée.
PLAFOND_ONGLETS_SANS_ENTREE = 0
PLAFOND_CAPTEURS_SANS_ENTREE = 0
PLAFOND_MODES_SANS_ENTREE = 0
# (E) LEVIERS DU MODULE DU BUDGET MÉMOIRE : plafond ZÉRO, et il le reste. Relevé sur l'arbre suivi
# le 2026-08-28, APRÈS la campagne qui accompagne cette extension : 6 leviers, 6 entrées.
PLAFOND_LEVIERS_DU_BUDGET_SANS_ENTREE = 0
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
# Le module du budget mémoire lit 6 leviers le 2026-08-28. En dessous de 4, c'est la lecture qui est
# cassée : un plafond ZÉRO rendu sur un inventaire vide serait le plus confortable des faux verts.
MIN_LEVIERS_DU_BUDGET = 4
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
# LA CLÉ EST LUE À SA PLACE, pas « quelque part dans l'appel » : 1er argument de `env::var`,
# 2e argument d'un `cfg…`. Un motif qui cherchait le littéral n'importe où avant la première
# parenthèse fermante manquait deux familles entières (cf. l'en-tête, mesure du 2026-08-28).
# LE SITE EST TROUVÉ PAR UN MOTIF, LES ARGUMENTS SONT DÉCOUPÉS PAR ÉQUILIBRAGE — parce qu'un motif
# ne sait pas compter les parenthèses. La première version de cette correction découpait à l'expression
# régulière : une clé qui était un APPEL (`cfg(&conf, cle_calculee(), "1")`) ne matchait alors
# AUCUNE alternative, et la garde la laissait tomber EN SILENCE — l'inventaire rétrécissait sans que
# rien ne rougisse, c'est-à-dire le défaut même que cette campagne poursuit. Mesuré par mutation le
# 2026-08-28 : 6 leviers -> 5, verdict VERT. Désormais tout site est découpé, et tout ce qui n'est
# ni un littéral ni un identifiant résoluble est RENDU comme non résolu.
APPEL_DE_CONFIG = re.compile(r"\b(env::var|cfg[a-z_]*)\s*\(")
# Rang de l'argument qui porte la CLÉ, par forme d'appel.
RANG_DE_LA_CLE = {"env::var": 0}  # tout `cfg…` -> 1 (cf. `rang_de_la_cle`)
CLE_LITTERALE = re.compile(r'^"([^"]*)"$')
CLE_IDENTIFIANT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$")
# Un ATTRIBUT Rust (`#[cfg(test)]`, `#[cfg_attr(not(feature=\"x\"), allow(…))]`) n'est PAS une lecture
# de configuration, et il porte le même mot. Ses intervalles sont retirés des sites — mesuré : deux
# `cfg_attr` de `daemon/src/handlers/query.rs` rendaient `allow(unused_mut, unused_variables)` comme
# une clé non résolue, ce qui aurait rendu l'instrument muet sur un arbre parfaitement sain.
# Une constante ou une statique de type `&str` — c'est par là que passe un levier NOMMÉ. Toutes les
# visibilités : `const`, `pub const`, `pub(crate) const`, `static`. La forme, pas le nom.
CONSTANTE_TEXTE = re.compile(
    r"\b(?:const|static)\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*&(?:'static\s+)?str\s*=\s*\"([^\"]*)\""
)
# LA COMPOSITION DU LOT DE PRAGMAS DU BUDGET — la propriété qui DÉSIGNE le module de `P10.1-c`.
# Trois motifs, tous requis : c'est le fait de décider les trois ensemble qui fait le module, et
# aucun d'eux ne suffit seul (une suite de tests pose `PRAGMA temp_store=FILE` sans rien décider).
BUDGET_MEMOIRE = (
    re.compile(r"PRAGMA temp_store="),
    re.compile(r"PRAGMA cache_size="),
    re.compile(r"PRAGMA mmap_size="),
)
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


def porteur_unique(racine, suivis, sous, motifs, quoi, exclure=lambda _c: False) -> str:
    """L'unique fichier suivi sous `sous/` qui contient TOUS les `motifs`. Zéro ou plusieurs -> muet.

    `motifs` accepte un motif seul ou un n-uplet : une propriété peut demander plusieurs marques à
    la fois, et c'est leur CONJONCTION qui désigne alors le porteur (aucune ne suffit isolément).
    `exclure` écarte des chemins par une PROPRIÉTÉ du chemin — jamais par un nom de fichier.
    """
    if isinstance(motifs, re.Pattern):
        motifs = (motifs,)
    porteurs = []
    for chemin in suivis:
        if sous and not chemin.startswith(sous):
            continue
        if chemin.startswith(INSTRUMENTS) or exclure(chemin):
            continue
        try:
            with open(os.path.join(racine, chemin), encoding="utf-8", errors="replace") as fh:
                texte = fh.read()
        except OSError:
            continue
        if all(m.search(texte) for m in motifs):
            porteurs.append(chemin)
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


def est_source_rust_de_production(chemin: str) -> bool:
    """Un `.rs` de `daemon/src` qui n'est pas une suite. Tests écartés par le CHEMIN, comme avant —
    ce que le chemin ne dit pas, `#[cfg(test)]` le dit (cf. `leviers_dun_texte_rust`)."""
    parties = chemin.split("/")
    return (chemin.startswith("daemon/src/") and chemin.endswith(".rs")
            and "tests" not in parties and parties[-1] not in ("tests.rs", "test.rs"))


def constantes_texte(textes) -> dict[str, str]:
    """Le nom -> la valeur de chaque constante/statique `&str`, hors commentaire."""
    out: dict[str, str] = {}
    for texte in textes:
        com, _ = _zones(texte, ".rs")
        for m in CONSTANTE_TEXTE.finditer(_hors_commentaire(texte, com)):
            out[m.group(1)] = m.group(2)
    return out


def spans_dattribut(code: str) -> list[tuple[int, int]]:
    """Les intervalles `#[ … ]` — équilibrés, donc `#[cfg_attr(not(a), allow(b, c))]` est couvert."""
    spans = []
    i = code.find("#[")
    while i >= 0:
        prof, j = 0, i + 1
        while j < len(code):
            if code[j] == "[":
                prof += 1
            elif code[j] == "]":
                prof -= 1
                if prof == 0:
                    break
            j += 1
        spans.append((i, j + 1))
        i = code.find("#[", j + 1)
    return spans


def arguments_de_lappel(code: str, lisible: str, ouvrante: int) -> list[str] | None:
    """Les arguments d'un appel, découpés par ÉQUILIBRAGE et lus dans le texte LISIBLE.

    Le découpage se fait sur `code` — commentaires ET littéraux blanchis — donc ni une virgule dans
    une chaîne ni une parenthèse dans un commentaire ne peut déplacer une frontière. Les tranches
    sont ensuite relues dans `lisible`, où les littéraux sont intacts. Appel non refermé -> `None`.
    """
    prof, coupes, debut = 0, [], ouvrante + 1
    for j in range(ouvrante, len(code)):
        c = code[j]
        if c in "([{":
            prof += 1
        elif c in ")]}":
            prof -= 1
            if prof == 0:
                coupes.append((debut, j))
                return [lisible[a:b].strip() for a, b in coupes]
        elif c == "," and prof == 1:
            coupes.append((debut, j))
            debut = j + 1
    return None


def rang_de_la_cle(forme: str) -> int:
    """`env::var(CLÉ)` -> 0 ; toute forme `cfg…(source, CLÉ, défaut)` -> 1."""
    return RANG_DE_LA_CLE.get(forme, 1)


def est_une_declaration(code: str, debut: int) -> bool:
    """Le site est-il la DÉCLARATION de la fonction plutôt qu'un APPEL ?

    LE DÉFAUT MESURÉ (2026-08-28). Le compte de « clés d'exécution » publié par cette garde en portait
    TROIS qui ne sont pas des lectures : les en-têtes `fn cfg(m: &HashMap<String, String>, key: &str, …)`,
    `fn cfg_secret(…)` et `fn cfg_secret_optional(…)`. Le découpage par virgules coupe le type générique
    en deux, si bien que l'argument de rang 1 y vaut le fragment `String>`. La phrase publiée — « N clés
    de configuration sont des variables d'exécution » — était donc FAUSSE ligne à ligne pour trois de ses
    N, et le compteur portait un PLANCHER permanent de 3 qui brouille exactement le signal qu'il prétend
    donner (« un compte qui grimperait dirait qu'une famille est passée derrière une indirection »).

    LA PROPRIÉTÉ, PAS LA LISTE : ce qui distingue une déclaration d'un appel, c'est le mot-clé `fn` qui
    la précède immédiatement. Aucun des trois n'est nommé ici ; une quatrième enveloppe écrite demain est
    couverte le jour même. ET CE N'ÉTAIT PAS QUE COSMÉTIQUE : `leviers_du_budget_memoire` rend
    l'instrument MUET (code 2) dès QU'UNE clé de son module ne se résout pas — le jour où le module du
    budget mémoire se donne sa propre enveloppe `fn cfg`, l'inventaire à tolérance ZÉRO se serait tu pour
    une non-raison.
    """
    return code[:debut].rstrip().endswith("fn")


def leviers_dun_texte_rust(texte: str, consts: dict[str, str]) -> tuple[set[str], list[str]]:
    """Les `PLUME_*` qu'UN fichier Rust LIT, et les clés qu'on n'a pas su résoudre.

    Une clé littérale vaut pour elle-même ; une clé IDENTIFIANT est résolue par `consts` ; TOUT LE
    RESTE est rendu comme non résolu, jamais écarté. Une valeur qui se termine par `_` est un
    PRÉFIXE (le code s'en sert avec `starts_with`), pas un nom de levier : la compter inventerait
    une variable que personne ne peut poser. Les blocs `#[cfg(test)]` sont hors du champ — le
    critère annonce « code de production » — et les ATTRIBUTS aussi : ils portent le même mot sans
    lire quoi que ce soit.
    """
    com, cha = _zones(texte, ".rs")
    code = _code(texte, com, cha)
    lisible = _hors_commentaire(texte, com)
    hors_portee = _spans_attribut(code, "#[cfg(test)]") + spans_dattribut(code)
    leviers: set[str] = set()
    non_resolues: list[str] = []
    for m in APPEL_DE_CONFIG.finditer(code):
        if _dans(hors_portee, m.start()) or est_une_declaration(code, m.start()):
            continue
        args = arguments_de_lappel(code, lisible, m.end() - 1)
        rang = rang_de_la_cle(m.group(1))
        if args is None or len(args) <= rang:
            # `cfg(x)` à un seul argument n'est pas une lecture de configuration de ce dépôt ; un
            # appel non refermé est un fichier tronqué. Ni l'un ni l'autre ne porte de clé.
            continue
        cle = args[rang]
        litteral = CLE_LITTERALE.match(cle)
        if litteral:
            valeur = litteral.group(1)
        elif CLE_IDENTIFIANT.match(cle):
            valeur = consts.get(cle.split("::")[-1])
            if valeur is None:
                non_resolues.append(cle)
                continue
        else:
            non_resolues.append(cle)
            continue
        if valeur.startswith("PLUME_") and not valeur.endswith("_"):
            leviers.add(valeur)
    return leviers, non_resolues


def leviers_lus(racine: str, suivis: list[str]) -> tuple[set[str], list[str]]:
    """Les `PLUME_*` que lit le code de PRODUCTION, et les clés d'exécution non résolues."""
    sources = [c for c in suivis if est_source_rust_de_production(c)]
    textes: dict[str, str] = {}
    for chemin in sources:
        try:
            with open(os.path.join(racine, chemin), encoding="utf-8", errors="replace") as fh:
                textes[chemin] = fh.read()
        except OSError:
            continue
    consts = constantes_texte(textes.values())
    out: set[str] = set()
    non_resolues: list[str] = []
    for texte in textes.values():
        vus, inconnus = leviers_dun_texte_rust(texte, consts)
        out |= vus
        non_resolues += inconnus
    for chemin in suivis:
        if not (chemin.startswith("collectors/") or chemin in ("bootstrap.sh", "bootstrap-agent.sh")):
            continue
        try:
            with open(os.path.join(racine, chemin), encoding="utf-8", errors="replace") as fh:
                out |= set(LEVIER_SHELL.findall(fh.read()))
        except OSError:
            continue
    return out, non_resolues


def leviers_du_budget_memoire(racine: str, suivis: list[str]) -> tuple[str, list[str]]:
    """(E) Le module qui décide le budget mémoire, et TOUS les leviers qu'il lit.

    Une clé non résolue ici rend l'instrument MUET : le verdict de cet inventaire est à tolérance
    ZÉRO, et un zéro rendu sur une lecture incomplète serait exactement le défaut poursuivi.
    """
    module = porteur_unique(
        racine, suivis, "daemon/src/", BUDGET_MEMOIRE,
        "module qui décide le budget mémoire (`P10.1-c`)",
        exclure=lambda c: not est_source_rust_de_production(c),
    )
    with open(os.path.join(racine, module), encoding="utf-8", errors="replace") as fh:
        texte = fh.read()
    leviers, non_resolues = leviers_dun_texte_rust(texte, constantes_texte([texte]))
    if non_resolues:
        raise InstrumentMuet(
            f"leviers du budget mémoire : {len(non_resolues)} clé(s) de `{module}` ne se résolvent "
            f"pas en un nom ({sorted(set(non_resolues))}). La clé est peut-être devenue une variable "
            f"d'exécution, ou sa constante vit désormais dans un AUTRE fichier — dans les deux cas "
            f"l'inventaire est PARTIEL, et un plafond ZÉRO rendu dessus serait faux.")
    return module, sorted(leviers)


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


# LE CORPUS RUST DE CONTRÔLE — cinq formes à VOIR, cinq à NE PAS voir, une à DIRE. Il porte
# `#[cfg(test)]` dans son propre texte : c'est pour cela que le répertoire des instruments est
# exclu de toute dérivation de porteur (cf. `INSTRUMENTS`).
CORPUS_RUST = """
const CLE_NOMMEE: &str = "PLUME_DELTA";
pub(crate) const PREFIXE: &str = "PLUME_PREFIXE_";
static AUTRE: &'static str = "pas_un_levier";
fn cfg(m: &HashMap<String, String>, key: &str, default: &str) -> String { String::new() }
fn lire(conf: &Conf) -> String {
    let _ = cfg(&conf, "PLUME_ALPHA", "0");
    let _ = cfg(&load_config(), "PLUME_BETA", "PLUME_UN_DEFAUT_PAS_UNE_CLE");
    let _ = std::env::var("PLUME_GAMMA");
    let _ = cfg(&conf, CLE_NOMMEE, "0");
    let _ = cfg(&conf, autre_module::CLE_QUALIFIEE, "0");
    let _ = cfg(&conf, PREFIXE, "0");
    let _ = cfg(&conf, AUTRE, "0");
    for k in noms { let _ = cfg(&conf, cle_dexecution, "0"); }
    let _ = cfg(&conf, cle_calculee(), "0");
    let _ = cfg(&conf, "PLUME_ZETA", "un defaut, avec une virgule");
    eprintln!("PLUME_CITE_DANS_UN_MESSAGE est ignoré");
}
#[cfg_attr(not(feature = "froid"), allow(unused_mut, unused_variables))]
fn attribut_pas_une_lecture() {}
#[cfg(test)]
mod tests {
    fn t() { let _ = cfg(&conf, "PLUME_SEULEMENT_EN_TEST", "0"); }
}
"""
# La constante QUALIFIÉE du corpus vit « ailleurs » : la résolution passe par le dictionnaire global,
# donc le témoin la fournit comme le ferait un autre fichier de production.
CORPUS_RUST_CONSTANTES_EXTERNES = {"CLE_QUALIFIEE": "PLUME_EPSILON"}


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

    consts = constantes_texte([CORPUS_RUST])
    consts.update(CORPUS_RUST_CONSTANTES_EXTERNES)
    if consts.get("CLE_NOMMEE") != "PLUME_DELTA" or consts.get("PREFIXE") != "PLUME_PREFIXE_":
        errs.append(f"témoin (constantes) en échec : {sorted(consts)} — les visibilités `const`, "
                    f"`pub(crate) const` et `static` ne sont plus toutes reconnues, donc un levier "
                    f"NOMMÉ par une constante redeviendrait invisible.")
    vus, inconnus = leviers_dun_texte_rust(CORPUS_RUST, consts)
    doit = {"PLUME_ALPHA", "PLUME_BETA", "PLUME_GAMMA", "PLUME_DELTA", "PLUME_EPSILON", "PLUME_ZETA"}
    if vus != doit:
        manque, en_trop = sorted(doit - vus), sorted(vus - doit)
        if manque:
            errs.append(f"témoin POSITIF (leviers Rust) en échec : manquent {manque} — littéral, "
                        f"appel dont un argument antérieur porte une parenthèse, `env::var`, clé "
                        f"nommée par une constante, clé QUALIFIÉE : les cinq formes doivent être vues.")
        if en_trop:
            errs.append(f"témoin NÉGATIF (leviers Rust) en échec : {en_trop} compté(s). Un nom cité "
                        f"dans un MESSAGE, un levier lu seulement sous `#[cfg(test)]`, une valeur de "
                        f"DÉFAUT et un PRÉFIXE ne sont pas des leviers lus par la production.")
    if sorted(inconnus) != ["cle_calculee()", "cle_dexecution"]:
        errs.append(f"témoin (clés non résolues) en échec : {sorted(inconnus)} — une clé qui est une "
                    f"variable d'exécution OU UN APPEL doit être RENDUE, pas silencieusement écartée : "
                    f"c'est le seul endroit où cette garde sait qu'elle ne sait pas, et une mutation "
                    f"a mesuré le 2026-08-28 que l'écarter faisait passer l'inventaire de 6 à 5 en "
                    f"restant VERT. `allow(unused_mut, unused_variables)` d'un `cfg_attr` ne doit PAS "
                    f"y figurer : un attribut ne lit rien. Et `String>` NON PLUS : le corpus porte la "
                    f"DÉCLARATION `fn cfg(m: &HashMap<String, String>, key: &str, …)`, dont l'en-tête "
                    f"n'est pas une lecture — c'est le plancher de 3 mesuré le 2026-08-28.")
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
        module_budget, leviers_budget = leviers_du_budget_memoire(racine, suivis)
    except InstrumentMuet as e:
        print(f"::error::{e}")
        return 2
    capteurs = capteurs_livres(racine, suivis)
    lus, cles_dexecution = leviers_lus(racine, suivis)
    cites = leviers_cites(racine, suivis)
    sans_doc = sorted(lus - cites)

    planchers = [
        (len(onglets), MIN_ONGLETS, f"onglets déclarés par `{module_nav}`"),
        (len(capteurs), MIN_CAPTEURS, "capteurs livrés sous `collectors/`"),
        (len(modes), MIN_MODES, f"modes de déploiement acceptés par `{script_modes}`"),
        (len(lus), MIN_LEVIERS, "leviers `PLUME_*` lus par le code de production"),
        (len(leviers_budget), MIN_LEVIERS_DU_BUDGET,
         f"leviers lus par `{module_budget}` (module du budget mémoire)"),
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
        print(f"leviers lus  {len(lus):4d}  cités {len(lus & cites):4d}  sans doc {len(sans_doc):4d}"
              f"  (clés d'exécution non résolues : {len(cles_dexecution)})")
        print(f"budget mém.  {len(leviers_budget):4d}  sans entrée "
              f"{len(manquants(leviers_budget, entrees)):4d}  (source : {module_budget})")
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
        (leviers_budget, PLAFOND_LEVIERS_DU_BUDGET_SANS_ENTREE,
         "levier du module qui décide le budget mémoire",
         f"documentez-le là où vivent ses sœurs — `README.md`, `deploy/PROFILE.md` — avec sa valeur "
         f"par défaut, ce qu'il borne EXACTEMENT et ce qu'il NE borne PAS (il est lu par "
         f"`{module_budget}`). Le cliquet des leviers ne suffit pas ici : il tolère un levier muet "
         f"de plus dès qu'un autre est documenté ailleurs, et c'est par ce trou que "
         f"`P10.1-c` est passé"),
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
          f"{len(capteurs)} capteurs, {len(modes)} modes ({script_modes}), "
          f"{len(leviers_budget)} leviers de budget mémoire ({module_budget}) : tous ont une entrée. "
          f"Leviers `PLUME_*` : {len(lus)} lus, {len(lus & cites)} cités, {len(sans_doc)} sans "
          f"aucune documentation (cliquet {PLAFOND_LEVIERS_SANS_DOC}). "
          f"NON COUVERT, et c'est dit : {len(cles_dexecution)} clé(s) de configuration sont des "
          f"variables d'exécution, sans nom statique à documenter.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
