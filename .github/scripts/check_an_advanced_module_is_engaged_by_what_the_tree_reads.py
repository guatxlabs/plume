#!/usr/bin/env python3
"""Un module avancé s'engage par ce que l'arbre lit réellement, pas par un geste qui n'a aucun effet.

LE DÉFAUT, CONSTATÉ SUR L'ARBRE. `ADVANCED_MODULES.md` disait d'engager les magasins ClickHouse et DuckDB
par `PLUME_STORE=clickhouse` et `PLUME_STORE=duckdb`. Aucun code du démon ne lit `PLUME_STORE` : la
sélection du magasin à l'exécution est conçue mais pas câblée, et le démon sert toujours SQLCipher. La
phrase avait été recopiée d'une page de conception. Un exploitant qui la suivait posait une variable sans
effet et croyait servir un autre magasin.

LA GARDE. Dans `ADVANCED_MODULES.md` :
  - chaque `PLUME_…` entre accents graves (forme `PLUME_X`, `PLUME_X=valeur` ou préfixe `PLUME_X_*`) doit
    être lu par le code de production du démon : le littéral `"PLUME_X"` (ou `"PLUME_X_` pour un préfixe)
    dans `daemon/src`, hors fichiers de test ;
  - chaque « fonctionnalité `x` » doit être une clé de `[features]` de `daemon/Cargo.toml` ;
  - chaque ligne du tableau des modules cite, dans sa colonne « Comment l'engager », SOIT une
    « fonctionnalité `x` », SOIT les mots « compilé par défaut » — jamais les deux, jamais aucun. La page
    disait que CHAQUE module s'engage par une fonctionnalité Cargo, alors que le multi-tenant n'en a pas :
    son code est dans le build par défaut, seul `PLUME_MULTI_TENANT` l'engage. Un module sans
    fonctionnalité doit le dire sur sa ligne.

La page renvoie à `CONTRIBUTING.md` pour ce que la CI vérifie de chaque fonctionnalité. Dans ce fichier,
la liste « The full feature list, from `[features]` » et la première colonne du tableau « feature | CI
coverage » doivent porter EXACTEMENT les clés de `[features]` (hors `default`). Le tableau omettait
`s3_backup`, compilée et testée par le job `features` : le renvoi menait à un tableau qui n'en disait rien.

CODES DE SORTIE. `0` tout ce que la page cite existe ; `1` un levier ou une fonctionnalité citée n'existe
pas dans l'arbre, une ligne du tableau ne dit pas comment son module est compilé, ou `CONTRIBUTING.md` ne
couvre pas exactement les fonctionnalités déclarées ; `2` rien n'a été mesuré : épreuve interne en échec, fichier illisible, ou page qui ne
cite plus aucun levier ni aucune fonctionnalité (une page reformulée doit être relue ici, pas passer).

CE QU'ELLE NE TIENT PAS. Elle vérifie qu'un levier est LU, pas qu'il fait ce que la page en dit. Un
littéral présent dans un module `#[cfg(test)]` d'un fichier de production compte comme lu. Elle ne vérifie
pas qu'une ligne « compilé par défaut » l'est vraiment, ni que la couverture décrite dans `CONTRIBUTING.md`
est celle de la CI. Les autres documents ne sont pas lus ici.
"""
from __future__ import annotations

import os
import re
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
PAGE = "ADVANCED_MODULES.md"
CONTRIBUTING = "CONTRIBUTING.md"
COMPILE_PAR_DEFAUT = "compilé par défaut"
CARGO = "daemon/Cargo.toml"
SOURCES = "daemon/src"

LEVIER = re.compile(r"`(PLUME_[A-Z0-9_]*[A-Z0-9])(_\*)?(?:=[^`]*)?`")
FONCTIONNALITE = re.compile(r"fonctionnalités? `([a-z0-9_-]+)`")


def cites(page: str) -> tuple[set[tuple[str, bool]], set[str]]:
    """(leviers cités avec « est un préfixe », fonctionnalités citées)."""
    leviers = {(m.group(1), m.group(2) is not None) for m in LEVIER.finditer(page)}
    return leviers, set(FONCTIONNALITE.findall(page))


def fonctionnalites_declarees(cargo: str) -> set[str]:
    m = re.search(r"^\[features\]\s*$(.*?)(?=^\[|\Z)", cargo, re.M | re.S)
    if not m:
        return set()
    return set(re.findall(r"^([A-Za-z0-9_-]+)\s*=", m.group(1), re.M))


def lignes_du_tableau_des_modules(page: str) -> list[tuple[str, str]]:
    """(module, colonne « Comment l'engager ») de chaque ligne du tableau dont l'en-tête est `| Module |`."""
    lignes, dedans = [], False
    for ligne in page.splitlines():
        if ligne.startswith("| Module |"):
            dedans = True
            continue
        if dedans and not ligne.startswith("|"):
            break
        if dedans and not re.fullmatch(r"\|[-| :]+\|", ligne):
            cellules = [c.strip() for c in ligne.strip().strip("|").split("|")]
            if len(cellules) >= 2:
                lignes.append((cellules[0], cellules[1]))
    return lignes


def fautes_du_tableau(page: str) -> list[str]:
    fautes = []
    for module, engager in lignes_du_tableau_des_modules(page):
        a_une_fonctionnalite = bool(FONCTIONNALITE.search(engager))
        dit_compile = COMPILE_PAR_DEFAUT in engager
        if a_une_fonctionnalite == dit_compile:
            fautes.append(f"la ligne « {module[:60]} » de {PAGE} doit citer SOIT une « fonctionnalité `x` », SOIT "
                          f"« {COMPILE_PAR_DEFAUT} » (elle cite : fonctionnalité={a_une_fonctionnalite}, "
                          f"compilé par défaut={dit_compile})")
    return fautes


def couverture_contributing(contributing: str) -> tuple[set[str] | None, set[str] | None]:
    """(clés de la liste « The full feature list », clés de la 1re colonne du tableau « feature | CI coverage »)."""
    m = re.search(r"The full feature list, from `\[features\]` in\s+`daemon/Cargo\.toml`:(.*?)\.\s*$",
                  contributing, re.M | re.S)
    liste = set(re.findall(r"`([a-z0-9_-]+)`", m.group(1))) if m else None
    tableau, dedans = set(), False
    for ligne in contributing.splitlines():
        if re.match(r"\|\s*feature\s*\|\s*CI coverage\s*\|", ligne):
            dedans = True
            continue
        if dedans and not ligne.startswith("|"):
            break
        if dedans:
            tableau |= set(re.findall(r"`([a-z0-9_-]+)`", ligne.split("|")[1]))
    return liste, (tableau if dedans else None)


def est_un_fichier_de_test(chemin: str) -> bool:
    parties = chemin.replace(os.sep, "/").split("/")
    return "tests" in parties or parties[-1] in ("tests.rs", "test.rs") or parties[-1].endswith("_tests.rs")


def trancher(page: str, cargo: str, sources: dict[str, str], contributing: str | None = None) -> tuple[int, list[str]]:
    """Le code de sortie et les lignes à imprimer. Pur : rien n'est lu du disque ici."""
    leviers, fonctionnalites = cites(page)
    if not leviers or not fonctionnalites:
        return 2, [f"[modules-avances] REFUSE DE CONCLURE — {PAGE} ne cite plus de levier `PLUME_…` "
                   f"({len(leviers)}) ou de « fonctionnalité `x` » ({len(fonctionnalites)}) : relire ce que "
                   "la page engage et mettre cette garde à jour."]
    declarees = fonctionnalites_declarees(cargo)
    if not declarees:
        return 2, [f"[modules-avances] REFUSE DE CONCLURE — aucune clé lue dans `[features]` de {CARGO}."]
    production = "\n".join(t for c, t in sources.items() if not est_un_fichier_de_test(c))
    fautes = []
    for nom, prefixe in sorted(leviers):
        # Un levier exact se cherche avec ses DEUX guillemets : `"PLUME_STORE` est un préfixe du levier
        # `"PLUME_STORE_DUCKDB_EXPERIMENTAL"`, réellement lu, et le laisserait passer pour lu.
        if (f'"{nom}_' if prefixe else f'"{nom}"') not in production:
            forme = f"{nom}_*" if prefixe else nom
            fautes.append(f"`{forme}` est cité par {PAGE} mais aucun code de production de {SOURCES} ne le lit")
    for f in sorted(fonctionnalites - declarees):
        fautes.append(f"la fonctionnalité `{f}` est citée par {PAGE} mais n'est pas déclarée dans {CARGO}")
    fautes += fautes_du_tableau(page)
    if contributing is not None:
        liste, tableau = couverture_contributing(contributing)
        if liste is None or tableau is None:
            return 2, [f"[modules-avances] REFUSE DE CONCLURE — {CONTRIBUTING} : liste « The full feature list » "
                       f"ou tableau « feature | CI coverage » introuvable ; mettre cette garde à jour."]
        attendues = declarees - {"default"}
        for nom, vues in (("la liste « The full feature list »", liste), ("le tableau « feature | CI coverage »", tableau)):
            for f in sorted(attendues - vues):
                fautes.append(f"{CONTRIBUTING} : {nom} ne cite pas la fonctionnalité `{f}`, déclarée dans {CARGO}")
            for f in sorted(vues - attendues):
                fautes.append(f"{CONTRIBUTING} : {nom} cite `{f}`, qui n'est pas une fonctionnalité de {CARGO}")
    if fautes:
        return 1, ["[modules-avances] ÉCHEC — la page dit d'engager un module par un geste que l'arbre ne lit pas :"] \
            + [f"    - {f}" for f in fautes]
    return 0, [f"[modules-avances] OK — {len(leviers)} levier(s) et {len(fonctionnalites)} fonctionnalité(s) "
               f"cités par {PAGE}, tous lus par l'arbre ; {len(lignes_du_tableau_des_modules(page))} ligne(s) du tableau "
               f"disent comment leur module est compilé"
               + ("" if contributing is None else f" ; {CONTRIBUTING} couvre les {len(declarees - {'default'})} "
                  "fonctionnalités déclarées")]


def epreuves() -> list[str]:
    """Témoins positifs et négatifs, hors du disque."""
    cargo = '[package]\nname = "x"\n\n[features]\ndefault = []\nclickhouse = ["dep:c"]\ncold_tier = []\n\n[dependencies]\nserde = "1"\n'
    sources = {
        "daemon/src/main.rs": 'cfg("PLUME_COLD_TIER"); var("PLUME_AI_URL"); var("PLUME_STORE_DUCKDB_EXPERIMENTAL");',
        "daemon/src/tests/store.rs": 'set_var("PLUME_STORE", "clickhouse");',
    }
    cas = [
        ("tout est lu", "fonctionnalité `cold_tier` + `PLUME_COLD_TIER=1`", 0),
        ("préfixe lu", "fonctionnalité `cold_tier` + `PLUME_AI_*`", 0),
        ("levier lu seulement par un test", "fonctionnalité `clickhouse` + `PLUME_STORE=clickhouse`", 1),
        ("levier lu nulle part", "fonctionnalité `cold_tier` + `PLUME_JAMAIS=1`", 1),
        ("levier préfixe d'un levier lu", "fonctionnalité `cold_tier` + `PLUME_STORE=duckdb`", 1),
        ("fonctionnalité non déclarée", "fonctionnalité `duckdb` + `PLUME_COLD_TIER=1`", 1),
        ("dépendance prise pour une fonctionnalité", "fonctionnalité `serde` + `PLUME_COLD_TIER=1`", 1),
        ("page sans levier", "fonctionnalité `cold_tier`", 2),
        ("page sans fonctionnalité", "`PLUME_COLD_TIER=1`", 2),
    ]
    echecs = []
    for nom, page, attendu in cas:
        code, _ = trancher(page, cargo, sources)
        if code != attendu:
            echecs.append(f"épreuve « {nom} » : code {code}, attendu {attendu}")
    tableau = ("| Module | Comment l'engager | Doc |\n|---|---|---|\n"
               "| **Froid** | fonctionnalité `cold_tier` + `PLUME_COLD_TIER=1` | x |\n"
               "| **MT** | {mt} | x |\n")
    contrib = ("The full feature list, from `[features]` in\n`daemon/Cargo.toml`: {liste}.\n\n"
               "| feature | CI coverage |\n|---|---|\n{lignes}\n\nsuite\n")
    contrib_ok = contrib.format(liste="`clickhouse`, `cold_tier`", lignes="| `cold_tier` | t |\n| `clickhouse` | c |")
    cas_tableau = [
        ("module sans fonctionnalité dit compilé", tableau.format(mt="compilé par défaut ; `PLUME_COLD_TIER=1`"), contrib_ok, 0),
        ("module sans fonctionnalité muet", tableau.format(mt="`PLUME_COLD_TIER=1`"), contrib_ok, 1),
        ("fonctionnalité ET compilé par défaut", tableau.format(mt="compilé par défaut, fonctionnalité `clickhouse`"), contrib_ok, 1),
        ("fonctionnalité absente du tableau CI", tableau.format(mt="fonctionnalité `clickhouse`"),
         contrib.format(liste="`clickhouse`, `cold_tier`", lignes="| `cold_tier` | t |"), 1),
        ("fonctionnalité absente de la liste", tableau.format(mt="fonctionnalité `clickhouse`"),
         contrib.format(liste="`cold_tier`", lignes="| `cold_tier` | t |\n| `clickhouse` | c |"), 1),
        ("fonctionnalité inconnue au tableau CI", tableau.format(mt="fonctionnalité `clickhouse`"),
         contrib.format(liste="`clickhouse`, `cold_tier`", lignes="| `cold_tier` | t |\n| `clickhouse`, `ldap` | c |"), 1),
        ("tableau CI introuvable", tableau.format(mt="fonctionnalité `clickhouse`"), "rien", 2),
    ]
    for nom, page, contributing, attendu in cas_tableau:
        code, _ = trancher(page, cargo, sources, contributing)
        if code != attendu:
            echecs.append(f"épreuve « {nom} » : code {code}, attendu {attendu}")
    code, _ = trancher("fonctionnalité `cold_tier` + `PLUME_COLD_TIER=1`", '[package]\nname = "x"\n', sources)
    if code != 2:
        echecs.append(f"épreuve « Cargo.toml sans [features] » : code {code}, attendu 2")
    return echecs


def main() -> int:
    echecs = epreuves()
    if echecs:
        print("[modules-avances] REFUSE DE CONCLURE — épreuve interne en échec :")
        for e in echecs:
            print(f"    - {e}")
        return 2
    try:
        with open(os.path.join(RACINE, PAGE), encoding="utf-8") as fh:
            page = fh.read()
        with open(os.path.join(RACINE, CARGO), encoding="utf-8") as fh:
            cargo = fh.read()
        with open(os.path.join(RACINE, CONTRIBUTING), encoding="utf-8") as fh:
            contributing = fh.read()
        sources = {}
        for rep, _, noms in os.walk(os.path.join(RACINE, SOURCES)):
            for n in noms:
                if n.endswith(".rs"):
                    chemin = os.path.join(rep, n)
                    with open(chemin, encoding="utf-8") as fh:
                        sources[os.path.relpath(chemin, RACINE)] = fh.read()
    except (OSError, UnicodeDecodeError) as e:
        print(f"[modules-avances] REFUSE DE CONCLURE — lecture impossible : {e}")
        return 2
    if not sources:
        print(f"[modules-avances] REFUSE DE CONCLURE — aucun fichier Rust lu sous {SOURCES}.")
        return 2
    code, lignes = trancher(page, cargo, sources, contributing)
    for ligne in lignes:
        print(ligne)
    return code


if __name__ == "__main__":
    sys.exit(main())
