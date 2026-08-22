#!/usr/bin/env python3
"""Toute fonctionnalité cargo DÉCLARÉE est COMPILÉE par au moins une commande BLOQUANTE de la CI (`P8.24-a`).

LA FAMILLE : DU CODE LIVRÉ QU'AUCUN JOB NE COMPILE
---------------------------------------------------
Une fonctionnalité cargo (`[features]`) éteinte par défaut met du code derrière un `#[cfg(feature)]`.
Ce code n'existe pour le compilateur que lorsqu'une commande l'active. Si aucune commande de la CI ne
le fait, une régression de compilation y passe au VERT : la CI ne dit pas « ce code est cassé », elle
dit « je n'ai pas regardé », et les deux se lisent pareil. Même famille que `S36` (les suites des deux
collecteurs compilés ne tournaient nulle part) : le remède n'est pas d'ajouter un nom à une liste,
mais de DÉRIVER les deux ensembles et de refuser l'écart.

LA MESURE QUI A OUVERT CETTE CLÉ, ET CE QU'ELLE A CONFIRMÉ (2026-08-21, ce critère, ce dépôt)
------------------------------------------------------------------------------------------
Population déclarée : 9 fonctionnalités sur 4 manifestes — `daemon` 8 (`ai`, `clickhouse`,
`clickhouse-ha`, `cold_tier`, `duckdb`, `ldap`, `s3_backup`, `saml`), `agent` 1 (`fim_windows_native`),
`collector-syslog` 0, `collector-mail` 0. Aucune fonctionnalité implicite (toutes les dépendances
optionnelles du démon sont rattachées par `dep:`), aucun `default`. Contre-mesuré par
`cargo metadata --no-deps` sur chaque crate : mêmes ensembles.
Population activée : 8 — les 8 du démon (un `cargo test` pour `cold_tier`, un `cargo check` séparé
pour chacune des 7 autres). ÉCART : 1, `fim_windows_native`, exactement le cas connu. Le constat
tient donc pour ce qu'il annonce, et il ne cache pas un écart plus large.
Le SENS, tranché par la lecture : ce n'est PAS du code mort. Le backend est une implémentation FFI
réelle (`CreateFileW`/port de complétion/`ReadDirectoryChangesW`, ~250 lignes, `Drop` qui annule et
ferme), dont la moitié pure (mapping `FILE_ACTION_*`, découpage `FILE_NOTIFY_INFORMATION`) est
compilée et testée sur toutes les cibles. Il est documenté au lecteur (`agent/README.md`) et son
manifeste dit pourquoi il est éteint : la validation à l'EXÉCUTION exige un hôte Windows. C'est une
fonctionnalité opt-in de compilation, comme `ldap` ou `saml` côté démon — et celles-là sont
compilées en CI. Preuve par mutation, `cargo xwin check --target x86_64-pc-windows-msvc` : une
erreur de type sous le `cfg` de la fonctionnalité rend rc=101 AVEC `--features fim_windows_native`
et rc=0 SANS — c'est l'aveuglement que cette garde ferme.

LE CRITÈRE, ÉCRIT ET REJOUABLE (c'est lui qui définit les populations, jamais une liste)
----------------------------------------------------------------------------------------
  DÉCLARÉE — une fonctionnalité d'un manifeste `Cargo.toml` suivi par git qui porte un `[package]` :
    une clé de `[features]`, OU une dépendance `optional = true` (de toute table de dépendances, y
    compris `[target.*.dependencies]`) qu'aucune valeur `dep:` ne rattache — cargo lui crée une
    fonctionnalité implicite du même nom. Le manifeste est lu par un parseur TOML : un `# [features]`
    commenté ne déclare rien.
  ACTIVÉE — une fonctionnalité que le `cfg` voit VRAI dans au moins une commande cargo de compilation
    (`build`/`check`/`test`/`clippy`/`run`/`doc`/`bench`/`rustc`, directement ou derrière `cargo xwin`
    / `cargo zigbuild`) écrite dans un bloc `run:` d'un workflow suivi, ou dans la recette d'une
    cible `make` que ce bloc invoque (les prérequis de la cible sont suivis ; `$(CARGO)` vaut `cargo`).
    Est activé : `--features`/`-F` (virgules et espaces, forme `=` comprise), `--all-features`, et la
    fonctionnalité `default` sauf `--no-default-features` — puis la FERMETURE (une fonctionnalité qui
    en nomme une autre l'active). Le crate visé est celui du `--manifest-path`, sinon du
    `working-directory` de l'étape ou du job.
    NE COMPTE PAS : une étape ou un job `continue-on-error: true` (une compilation qui peut échouer
    sans rougir ne garde rien), une étape ou un job sous `if:` (sauf `always()`), un `# commentaire`
    dans le script, le `name:` d'une étape, et toute prose hors `run:`.
  L'ÉCART = DÉCLARÉE − ACTIVÉE, par manifeste, et il doit être VIDE.

EXCEPTIONS — une fonctionnalité peut être légitimement hors CI (outillage absent du runner, licence,
coût). Elle se déclare dans `EXCEPTIONS` avec son manifeste, sa RAISON et la CONDITION qui lèvera
l'exception ; une exception dont la fonctionnalité n'existe plus, ou qui est désormais compilée,
est elle-même refusée (une allowlist pourrit dans les deux sens). Aujourd'hui : aucune.

PLANCHER DE NON-DÉGÉNÉRESCENCE — la façon la plus simple de rendre vert serait un parseur qui ne
trouve rien : zéro déclaré, zéro écart. La garde REFUSE DE CONCLURE sous un plancher de manifestes,
de fonctionnalités déclarées et de commandes cargo bloquantes (mesurés, pas devinés), et quand un
argument de `--features` contient une expression qu'elle ne sait pas résoudre (`${{ }}`, `$VAR`).
Elle valide son instrument sur des témoins POSITIFS et NÉGATIFS avant de croire un seul verdict.

CE QUE CETTE GARDE NE PROUVE PAS
-------------------------------
1. « Compilée » = le `cfg` est vrai dans une commande qui RÉUSSIT ou rougit. Un `cargo check` ne lie
   pas et n'exécute rien : pour `fim_windows_native`, le lien et l'exécution sur un hôte Windows
   restent non prouvés — c'est écrit dans le manifeste, et c'est la condition de son allumage par
   défaut, pas l'objet de cette garde.
2. Elle compte une activation TRANSITIVE (via `default` ou une sur-fonctionnalité) comme une
   activation : le code est bien compilé. Elle ne garantit pas qu'une fonctionnalité a été compilée
   SEULE — la doctrine « un check par fonctionnalité » de `ci.yml` reste une discipline d'écriture.
   Les fonctionnalités atteintes seulement par transitivité sont NOMMÉES dans la sortie.
3. Elle ne modélise pas `needs:` ni les filtres `paths:` — un job bloquant d'un workflow qui ne se
   déclenche que sur certains chemins compte, parce qu'il rougit le commit qui touche ces chemins.
4. Elle lit une cible `make` par ses lignes de recette ; une indirection plus profonde (script
   appelé par la recette, `$(MAKE)` récursif, `cargo` derrière une variable autre que `CARGO`) n'est
   pas suivie et la commande est alors INVISIBLE — donc l'écart se verrait, jamais l'inverse.

Usage :  python3 .github/scripts/check_every_feature_is_compiled_somewhere.py [--repo CHEMIN]
Sortie :  0 = sain ; 1 = écart, exception pourrie, ou instrument qui refuse de conclure.
"""
from __future__ import annotations

import argparse
import itertools
import os
import re
import shlex
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import yaml

WORKFLOWS = ".github/workflows"
COMPILE = {"build", "check", "test", "clippy", "run", "doc", "bench", "rustc", "rustdoc"}
WRAPPERS = {"xwin", "zigbuild"}  # `cargo xwin <sous-commande>`, `cargo zigbuild` (= build)
SEPARATEURS = {";", "&&", "||", "|", "&", "(", ")", "{", "}", ";;"}
PREFIXES_INERTES = {"sudo", "time", "nice", "env", "exec", "command"}

# PLANCHERS, pas des comptes exacts : ajouter un crate, une fonctionnalité ou une étape est de la
# routine. Ils ferment le seul mode de panne réel de la dérivation — un parseur cassé qui ne trouve
# RIEN et rend un vert joyeux. MESURÉS le 2026-08-21 : 4 manifestes, 9 fonctionnalités déclarées,
# 19 commandes cargo de compilation bloquantes.
PLANCHER_MANIFESTES = 3
PLANCHER_DECLAREES = 6
PLANCHER_COMMANDES = 8

# EXCEPTIONS JUSTIFIÉES — (manifeste, fonctionnalité) -> (raison, condition de levée).
# Chaque entrée dit POURQUOI cette fonctionnalité n'est compilée par aucun job ET ce qui lèvera
# l'exception. Une entrée dont la fonctionnalité n'existe plus, ou qui est compilée, est REFUSÉE.
EXCEPTIONS: dict[tuple[str, str], tuple[str, str]] = {}


# ==================================================================================================
# DÉCLARÉE — lecture des manifestes
# ==================================================================================================
def features_declarees(texte_toml: str) -> dict[str, list[str]] | None:
    """-> {fonctionnalité: [ce qu'elle active]} ; None si le manifeste n'est pas un crate ([workspace] nu)."""
    m = tomllib.loads(texte_toml)
    if "package" not in m:
        return None
    feats: dict[str, list[str]] = {k: list(v) for k, v in (m.get("features") or {}).items()}
    optionnelles: set[str] = set()

    def ramasse(table):
        for nom, spec in (table or {}).items():
            if isinstance(spec, dict) and spec.get("optional") is True:
                optionnelles.add(nom)  # la fonctionnalité implicite porte le nom de la CLÉ, même renommée

    tables = ("dependencies", "dev-dependencies", "build-dependencies")
    for t in tables:
        ramasse(m.get(t))
    for _, cible in (m.get("target") or {}).items():
        for t in tables:
            ramasse(cible.get(t))
    rattachees = {v[4:] for vals in feats.values() for v in vals if v.startswith("dep:")}
    for d in sorted(optionnelles - rattachees):
        feats.setdefault(d, ["dep:" + d])
    return feats


def fermeture(feats: dict[str, list[str]], actives: set[str]) -> set[str]:
    """Fonctionnalités de CE crate vraies quand `actives` le sont (`dep:` et `crate/feat` ignorés)."""
    vues: set[str] = set()
    pile = [a for a in actives if a in feats]
    while pile:
        f = pile.pop()
        if f in vues:
            continue
        vues.add(f)
        for v in feats[f]:
            if v.startswith("dep:") or "/" in v:
                continue
            if v in feats:
                pile.append(v)
    return vues


# ==================================================================================================
# ACTIVÉE — lecture des workflows, des scripts `run:` et des recettes `make`
# ==================================================================================================
@dataclass
class Commande:
    origine: str          # "ci.yml › job › étape" (+ " › make cible")
    cwd: str              # répertoire courant, relatif au dépôt
    argv: list[str]


@dataclass
class Refus:
    ou: str
    pourquoi: str


def lignes_logiques(script: str) -> list[str]:
    """Joint les continuations `\\`, saute les heredocs `<<MOT … MOT`."""
    out: list[str] = []
    courante = ""
    heredoc: str | None = None
    for brut in script.splitlines():
        if heredoc is not None:
            if brut.strip() == heredoc:
                heredoc = None
            continue
        if courante:
            brut = courante + " " + brut.strip()
            courante = ""
        if brut.rstrip().endswith("\\"):
            courante = brut.rstrip()[:-1]
            continue
        m = re.search(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", brut)
        if m:
            heredoc = m.group(1)
            brut = brut[: m.start()]
        out.append(brut)
    if courante:
        out.append(courante)
    return out


def commandes_du_script(script: str) -> list[list[str]]:
    """-> liste d'argv, une par commande simple (séparateurs shell coupés, commentaires retirés)."""
    script = re.sub(r"\$[({]CARGO[)}]", "cargo", script)
    resultat: list[list[str]] = []
    for ligne in lignes_logiques(script):
        try:
            lex = shlex.shlex(ligne, posix=True, punctuation_chars=True)
            lex.whitespace_split = True
            lex.commenters = "#"
            jetons = list(lex)
        except ValueError:
            # une ligne que le shell lui-même ne découperait pas (guillemet ouvert) : on la garde
            # telle quelle pour que `cargo` y soit au moins VU par la détection de refus
            jetons = ligne.split()
        argv: list[str] = []
        for j in jetons:
            if j in SEPARATEURS:
                if argv:
                    resultat.append(argv)
                argv = []
            else:
                argv.append(j)
        if argv:
            resultat.append(argv)
    return resultat


def depouille(argv: list[str]) -> list[str]:
    """Retire `K=V`, `sudo`, `@`/`-` de make… jusqu'au vrai programme."""
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in PREFIXES_INERTES or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", a) or a in ("@", "-", "@-", "-@"):
            i += 1
            continue
        break
    reste = argv[i:]
    if reste and not reste[0].startswith("--"):
        reste[0] = reste[0].lstrip("@-")  # préfixes de recette make : `@cargo`, `-cargo`
        if not reste[0]:
            reste = reste[1:]
    return reste


def cibles_makefile(texte: str) -> dict[str, tuple[list[str], list[str]]]:
    """-> {cible: (prérequis, lignes de recette)} — règles explicites seulement."""
    regles: dict[str, tuple[list[str], list[str]]] = {}
    courantes: list[str] = []
    for ligne in lignes_logiques(texte):
        if ligne.startswith("\t"):
            for c in courantes:
                regles[c][1].append(ligne.strip())
            continue
        sans = ligne.split("#", 1)[0].rstrip()
        if not sans or sans.startswith("."):
            courantes = []
            continue
        m = re.match(r"^([A-Za-z0-9_./%-]+(?:\s+[A-Za-z0-9_./%-]+)*)\s*:(?![=])\s*(.*)$", sans)
        if not m:
            courantes = []
            continue
        courantes = m.group(1).split()
        prereqs = m.group(2).split()
        for c in courantes:
            regles.setdefault(c, (prereqs, []))
    return regles


def recettes_de(cible: str, regles, vues: set[str] | None = None) -> list[str]:
    vues = vues if vues is not None else set()
    if cible in vues or cible not in regles:
        return []
    vues.add(cible)
    prereqs, recette = regles[cible]
    out: list[str] = []
    for p in prereqs:
        out += recettes_de(p, regles, vues)
    return out + recette


def expansions_matrice(script: str, matrice) -> list[str] | None:
    """Remplace `${{ matrix.k }}` par chaque valeur scalaire ; None si une expression reste opaque."""
    cles = sorted(set(re.findall(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}", script)))
    if not cles:
        return [script]
    if not isinstance(matrice, dict):
        return None
    valeurs = []
    for k in cles:
        v = matrice.get(k)
        if not isinstance(v, list) or not all(isinstance(x, (str, int, float)) for x in v):
            return None
        valeurs.append([str(x) for x in v])
    out = []
    for combo in itertools.product(*valeurs):
        s = script
        for k, val in zip(cles, combo):
            s = re.sub(r"\$\{\{\s*matrix\." + re.escape(k) + r"\s*\}\}", val, s)
        out.append(s)
    return out


def condition_inerte(cond) -> bool:
    return cond is None or str(cond).strip() in ("", "always()")


def commandes_des_workflows(repo: Path, fichiers: list[str]) -> tuple[list[Commande], list[Refus], list[str]]:
    commandes: list[Commande] = []
    refus: list[Refus] = []
    ignorees: list[str] = []
    for rel in fichiers:
        doc = yaml.safe_load((repo / rel).read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
            continue
        for jnom, job in doc["jobs"].items():
            if not isinstance(job, dict):
                continue
            ou_job = f"{Path(rel).name} › {jnom}"
            if job.get("continue-on-error") is True or not condition_inerte(job.get("if")):
                ignorees.append(ou_job + " (job consultatif ou conditionnel)")
                continue
            cwd_job = ((job.get("defaults") or {}).get("run") or {}).get("working-directory") or "."
            matrice = (job.get("strategy") or {}).get("matrix")
            for idx, step in enumerate(job.get("steps") or [], 1):
                if not isinstance(step, dict) or "run" not in step:
                    continue
                ou = f"{ou_job} › étape {idx} « {step.get('name', '')} »"
                if step.get("continue-on-error") is True or not condition_inerte(step.get("if")):
                    ignorees.append(ou + " (étape consultative ou conditionnelle)")
                    continue
                cwd = step.get("working-directory") or cwd_job
                variantes = expansions_matrice(str(step["run"]), matrice)
                if variantes is None:
                    refus.append(Refus(ou, "expression `${{ }}` de matrice non résoluble dans un bloc run:"))
                    continue
                for script in variantes:
                    for argv in commandes_du_script(script):
                        argv = depouille(argv)
                        if not argv:
                            continue
                        prog = os.path.basename(argv[0])
                        if prog == "cargo":
                            commandes.append(Commande(ou, cwd, argv))
                        elif prog == "make":
                            commandes += commandes_de_make(repo, ou, cwd, argv, refus)
    return commandes, refus, ignorees


def commandes_de_make(repo: Path, ou: str, cwd: str, argv: list[str], refus: list[Refus]) -> list[Commande]:
    cibles: list[str] = []
    mk = None
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in ("-f", "--file", "--makefile") and i + 1 < len(argv):
            mk = argv[i + 1]
            i += 1
        elif a in ("-C", "--directory") and i + 1 < len(argv):
            cwd = os.path.normpath(os.path.join(cwd, argv[i + 1]))
            i += 1
        elif not a.startswith("-") and "=" not in a:
            cibles.append(a)
        i += 1
    chemin = repo / cwd / (mk or "Makefile")
    if not chemin.is_file():
        refus.append(Refus(ou, f"`make` sans Makefile lisible sous `{cwd}`"))
        return []
    regles = cibles_makefile(chemin.read_text(encoding="utf-8"))
    out: list[Commande] = []
    for c in cibles or ["all"]:
        if c not in regles:
            refus.append(Refus(ou, f"cible make `{c}` introuvable dans {chemin.relative_to(repo)}"))
            continue
        for ligne in recettes_de(c, regles):
            for sous in commandes_du_script(ligne):
                sous = depouille(sous)
                if sous and os.path.basename(sous[0]) == "cargo":
                    out.append(Commande(f"{ou} › make {c}", cwd, sous))
    return out


@dataclass
class Activation:
    manifeste: str
    explicites: set[str] = field(default_factory=set)
    toutes: bool = False
    sans_default: bool = False
    origine: str = ""


def lire_activation(cmd: Commande, manifestes: dict[str, dict], refus: list[Refus]) -> Activation | None:
    """-> ce que la commande active et sur quel manifeste ; None si ce n'est pas une compilation."""
    a = cmd.argv[1:]
    if not a:
        return None
    sous = a[0]
    if sous in WRAPPERS:
        a = a[1:]
        if sous == "zigbuild":
            sous = "build"
        elif not a:
            return None
        else:
            sous = a[0]
            a = a[1:]
    if sous not in COMPILE:
        return None
    act = Activation(manifeste="", origine=cmd.origine)
    manifest_path = None
    i = 0
    while i < len(a):
        t = a[i]
        val = None
        if t == "--":
            break  # ce qui suit est passé au binaire, pas à cargo
        if t in ("--features", "-F"):
            val = a[i + 1] if i + 1 < len(a) else ""
            i += 1
        elif t.startswith("--features=") or t.startswith("-F="):
            val = t.split("=", 1)[1]
        elif t == "--all-features":
            act.toutes = True
        elif t == "--no-default-features":
            act.sans_default = True
        elif t == "--manifest-path":
            manifest_path = a[i + 1] if i + 1 < len(a) else None
            i += 1
        elif t.startswith("--manifest-path="):
            manifest_path = t.split("=", 1)[1]
        if val is not None:
            if "$" in val or "{{" in val:
                refus.append(Refus(cmd.origine, f"argument de --features non résoluble : `{val}`"))
                return None
            act.explicites |= {f for f in re.split(r"[,\s]+", val) if f}
        i += 1
    chemin = os.path.normpath(os.path.join(cmd.cwd, manifest_path or "Cargo.toml"))
    if chemin not in manifestes:
        refus.append(Refus(cmd.origine, f"commande `cargo {sous}` dont le manifeste `{chemin}` n'est pas suivi"))
        return None
    act.manifeste = chemin
    return act


def activees(feats: dict[str, list[str]], act: Activation) -> set[str]:
    base = set(feats) if act.toutes else set(act.explicites)
    if not act.sans_default and "default" in feats:
        base.add("default")
    return fermeture(feats, base)


# ==================================================================================================
# VALIDATION DE L'INSTRUMENT — témoins POSITIFS et NÉGATIFS, avant de croire un seul verdict
# ==================================================================================================
MANIFESTE_TEMOIN = """
[package]
name = "temoin"
version = "0.1.0"
# [features]
# fantome = []
[features]
reelle = []
englobante = ["reelle"]
x = ["dep:rattachee"]
[dependencies]
serde = { version = "1", optional = true }
rattachee = { version = "1", optional = true }
[target.'cfg(windows)'.dependencies]
winonly = { version = "1", optional = true }
"""
# Attendu : `reelle`, `englobante`, `x` (déclarées), `serde` et `winonly` (optionnelles SANS `dep:`,
# donc implicites — `winonly` depuis une table par-cible) ; PAS `fantome` (commentée), PAS `rattachee`
# (rattachée par `dep:`, donc pas de fonctionnalité implicite).

WORKFLOW_TEMOIN = """
name: temoin
on: push
jobs:
  bloquant:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        f: [reelle, englobante]
    steps:
      - name: prose qui parle de --features fantome sans rien lancer
        run: |
          # cargo check --features commentee
          echo "--features dans_un_echo"
          TMPDIR=/tmp cargo check --features ${{ matrix.f }} --locked
      - name: via make
        working-directory: sous
        run: make cible
  consultatif:
    runs-on: ubuntu-latest
    steps:
      - name: ne garde rien
        continue-on-error: true
        run: cargo check --features consultative
  conditionnel:
    runs-on: ubuntu-latest
    steps:
      - name: ne garde rien non plus
        if: github.event_name == 'push'
        run: cargo check --features conditionnelle
"""
MAKEFILE_TEMOIN = """
CARGO ?= cargo
.PHONY: cible prereq
prereq:
\t$(CARGO) xwin check --target x86_64-pc-windows-msvc -F "par_make,seconde"
cible: prereq
\t@echo "rien"
"""


def valider_l_instrument(errs: list[str]) -> None:
    f = features_declarees(MANIFESTE_TEMOIN)
    attendu = {"reelle", "englobante", "x", "serde", "winonly"}
    if f is None or set(f) != attendu:
        errs.append("INSTRUMENT (manifeste) : attendu %s, lu %s — un `# [features]` commenté, une dépendance "
                    "optionnelle (par-cible comprise) ou un rattachement `dep:` est mal compté."
                    % (sorted(attendu), sorted(f or [])))
    if f and fermeture(f, {"englobante"}) != {"englobante", "reelle"}:
        errs.append("INSTRUMENT (fermeture) : `englobante = [\"reelle\"]` devrait activer `reelle`.")
    if features_declarees("[workspace]\nmembers = []\n") is not None:
        errs.append("INSTRUMENT (manifeste) : un `[workspace]` nu est pris pour un crate.")

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        (repo / ".github/workflows").mkdir(parents=True)
        (repo / ".github/workflows/temoin.yml").write_text(WORKFLOW_TEMOIN)
        (repo / "sous").mkdir()
        (repo / "sous/Makefile").write_text(MAKEFILE_TEMOIN)
        cmds, refus, ignorees = commandes_des_workflows(repo, [".github/workflows/temoin.yml"])
        manifestes = {"Cargo.toml": {}, "sous/Cargo.toml": {}}
        vues: set[str] = set()
        for c in cmds:
            act = lire_activation(c, manifestes, refus)
            if act:
                vues |= act.explicites
        attendu_act = {"reelle", "englobante", "par_make", "seconde"}
        if vues != attendu_act:
            errs.append("INSTRUMENT (workflow) : attendu %s activées, vu %s — la matrice, la recette make "
                        "(via prérequis), le commentaire, le `echo` ou l'étape consultative/conditionnelle "
                        "est mal lu." % (sorted(attendu_act), sorted(vues)))
        if refus:
            errs.append("INSTRUMENT (workflow) : refus inattendu sur le témoin — %s"
                        % "; ".join(f"{r.ou}: {r.pourquoi}" for r in refus))
        if len(ignorees) != 2:
            errs.append("INSTRUMENT (workflow) : %d étape(s) ignorée(s) sur le témoin, 2 attendues "
                        "(consultative + conditionnelle)." % len(ignorees))
        # Témoin de REFUS : une expression opaque dans --features ne doit pas passer en silence.
        (repo / ".github/workflows/opaque.yml").write_text(
            "name: o\non: push\njobs:\n  j:\n    runs-on: x\n    steps:\n"
            "      - run: cargo check --features $PLUME_FEATURES\n")
        cmds, refus, _ = commandes_des_workflows(repo, [".github/workflows/opaque.yml"])
        for c in cmds:
            lire_activation(c, manifestes, refus)
        if not refus:
            errs.append("INSTRUMENT (refus) : `--features $PLUME_FEATURES` a été accepté au lieu d'être refusé.")


# ==================================================================================================
def suivis(repo: Path, motif: str) -> list[str]:
    out = subprocess.run(["git", "-C", str(repo), "ls-files", "-z", motif],
                         capture_output=True, check=True).stdout
    return sorted(p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=".")
    args = ap.parse_args()
    repo = Path(args.repo).resolve()
    errs: list[str] = []

    valider_l_instrument(errs)
    if errs:
        for e in errs:
            print("::error::%s" % e)
        print("\nL'instrument ne mesure pas ce qu'il annonce : aucun verdict ne vaut.")
        return 1

    # --- DÉCLARÉE ---------------------------------------------------------------------------------
    manifestes: dict[str, dict[str, list[str]]] = {}
    for rel in suivis(repo, "*Cargo.toml"):
        if "/target/" in rel:
            continue
        try:
            f = features_declarees((repo / rel).read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as e:
            errs.append("%s : TOML illisible (%s) — la garde ne peut pas dériver sa population." % (rel, e))
            continue
        if f is not None:
            manifestes[rel] = f

    # --- ACTIVÉE ----------------------------------------------------------------------------------
    wf = [p for p in suivis(repo, WORKFLOWS + "/*") if p.endswith((".yml", ".yaml"))]
    commandes, refus, ignorees = commandes_des_workflows(repo, wf)
    activation: dict[str, set[str]] = {m: set() for m in manifestes}
    explicites: dict[str, set[str]] = {m: set() for m in manifestes}
    origines: dict[tuple[str, str], list[str]] = {}
    n_compil = 0
    for c in commandes:
        act = lire_activation(c, manifestes, refus)
        if act is None:
            continue
        n_compil += 1
        feats = manifestes[act.manifeste]
        vraies = activees(feats, act)
        activation[act.manifeste] |= vraies
        explicites[act.manifeste] |= (set(feats) if act.toutes else act.explicites) & set(feats)
        for f in vraies:
            origines.setdefault((act.manifeste, f), []).append(act.origine)

    for r in refus:
        errs.append("REFUS DE CONCLURE — %s : %s" % (r.ou, r.pourquoi))

    # --- PLANCHERS --------------------------------------------------------------------------------
    n_decl = sum(len(f) for f in manifestes.values())
    if len(manifestes) < PLANCHER_MANIFESTES or n_decl < PLANCHER_DECLAREES or n_compil < PLANCHER_COMMANDES:
        errs.append(
            "population trouvée : %d manifeste(s) (plancher %d), %d fonctionnalité(s) déclarée(s) "
            "(plancher %d), %d commande(s) cargo de compilation bloquante(s) (plancher %d). Sous le "
            "plancher, soit la dérivation est cassée — cette garde ne vérifierait alors RIEN —, soit "
            "le dépôt a légitimement rétréci : dans ce cas baissez le plancher DEPUIS VOTRE PROPRE "
            "MESURE." % (len(manifestes), PLANCHER_MANIFESTES, n_decl, PLANCHER_DECLAREES,
                         n_compil, PLANCHER_COMMANDES))

    # --- ÉCART ------------------------------------------------------------------------------------
    for m, feats in sorted(manifestes.items()):
        for f in sorted(feats):
            if f in activation[m]:
                continue
            exc = EXCEPTIONS.get((m, f))
            if exc:
                continue
            errs.append(
                "%s déclare la fonctionnalité `%s` et AUCUNE commande cargo bloquante d'un workflow "
                "ne l'active : le code derrière son `cfg` n'est compilé nulle part en CI, une "
                "régression y passerait au vert.\n"
                "      Deux issues : l'activer dans le job qui compile déjà ce crate (`cargo check "
                "--features %s` suffit à prouver la compilation, sur le même répertoire cible), ou "
                "l'inscrire dans `EXCEPTIONS` de cette garde AVEC sa raison et la condition "
                "qui lèvera l'exception. La retirer du manifeste est la troisième, si c'est du code mort "
                "— et alors le code part avec elle." % (m, f, f))
    for (m, f), (raison, levee) in sorted(EXCEPTIONS.items()):
        if m not in manifestes or f not in manifestes[m]:
            errs.append("EXCEPTION POURRIE — `%s` n'est plus déclarée dans %s : retirez l'entrée." % (f, m))
        elif f in activation[m]:
            errs.append("EXCEPTION POURRIE — `%s` de %s est désormais compilée (%s) : retirez l'entrée "
                        "(raison consignée : %s ; levée prévue : %s)."
                        % (f, m, origines[(m, f)][0], raison, levee))

    # LA MESURE D'ABORD, le verdict ensuite : la population se lit même quand la garde rougit.
    for m, feats in sorted(manifestes.items()):
        manquantes = sorted(set(feats) - activation[m])
        trans = sorted(activation[m] - explicites[m])
        print("%s : %d déclarée(s) %s — %s%s" % (
            m, len(feats), sorted(feats) if feats else "",
            ("NON compilée(s) : %s" % manquantes) if manquantes else "toutes compilées",
            (" (par transitivité seulement : %s)" % trans) if trans else ""))
    print("%d commande(s) cargo de compilation bloquante(s) lues dans %d workflow(s) ; %d étape(s)/job(s) "
          "ignoré(s) car consultatif(s) ou conditionnel(s)." % (n_compil, len(wf), len(ignorees)))
    for i in ignorees:
        print("    ignoré : " + i)

    if errs:
        for e in errs:
            print("::error::%s" % e)
        print("\n%d défaut(s) : une fonctionnalité déclarée qu'aucun job ne compile, une exception "
              "pourrie, ou un instrument qui refuse de conclure." % len(errs))
        return 1

    print("Témoins de l'instrument : `# [features]` commenté, dépendance optionnelle implicite (par-cible "
          "comprise) et rattachée par `dep:`, fermeture, workspace nu, matrice, recette make via "
          "prérequis, commentaire et echo dans run:, étape consultative, étape conditionnelle, "
          "argument de --features opaque (refus).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
