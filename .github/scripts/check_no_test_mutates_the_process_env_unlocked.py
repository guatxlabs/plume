#!/usr/bin/env python3
"""Aucun test ne MUTE l'environnement du processus sans prendre LE verrou d'environnement (`P11.18-w`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`cfg()` (daemon/src/main.rs) résout toute clé dans l'ordre `env > conf > défaut`. Un test qui écrit
`std::env::set_var("PLUME_COLD_TIER", "1")` ne règle donc pas SON tier froid : il règle celui de tous
les tests qui tournent au même instant dans le même processus, y compris ceux qui croyaient contrôler
cette clé par leur propre `conf` — puisque l'environnement passe DEVANT la conf.

Ce n'est pas une hypothèse. Mesuré le 2026-08-25 sur cet arbre : le test froid
`search_declares_what_it_did_not_search_only_when_cold_history_exists` a échoué une fois sur deux
exécutions complètes de la suite froide, sur l'assertion « tier froid OFF -> aucune note, aucun coût ».
Sa `conf` portait bien `PLUME_COLD_TIER=0` ; un test de plafonds voisin posait `PLUME_COLD_TIER=1` dans
l'environnement. Le message accusait le tier d'être éteint alors qu'il était allumé — c'est-à-dire qu'une
intégration continue rouge ne se distinguait plus d'une régression réelle.

LA CAUSE N'ÉTAIT PAS L'ABSENCE DE VERROU : IL Y EN AVAIT NEUF
------------------------------------------------------------
Relevé du 2026-08-25, par la dérivation ci-dessous : 72 tests du démon mutent l'environnement. Ils se
répartissaient entre NEUF verrous distincts — un par « famille » de variables — et douze n'en prenaient
aucun. DEUX VERROUS POUR UNE RESSOURCE, C'EST ZÉRO VERROU : chaque famille obtenait la sérialisation
qu'elle croyait avoir vis-à-vis d'elle-même, et aucune vis-à-vis des autres. Le compilateur ne pouvait
pas le voir : les verrous n'avaient pas le même type.

La ressource n'est pas « PLUME_COLD_TIER », ni « PLUME_ROLLUP_MULTIDIM », ni « les réglages de
sauvegarde » : c'est L'ENVIRONNEMENT, un seul objet global au processus. Il a donc UN verrou,
`VERROU_ENV_PROCESSUS` (daemon/src/tests/common.rs), lecteurs/écrivain : `.write()` pour qui MUTE,
`.read()` pour qui LIT. LE MODE FAIT PARTIE DE LA RÈGLE — muter sous `.read()` n'exclut personne, les
lecteurs étant parallèles entre eux, et cette garde exige donc le mode ÉCRITURE de tout mutateur.

LA PROPRIÉTÉ, ET POURQUOI C'EST UNE PROPRIÉTÉ ET PAS UNE LISTE
--------------------------------------------------------------
    Tout `#[test]` du démon dont le corps MUTE une variable d'environnement — directement, ou à travers
    un utilitaire écrit CÔTÉ TEST qui la mute — doit tenir `VERROU_ENV_PROCESSUS` EN ÉCRITURE.

Rien n'est énuméré : ni les noms de tests, ni les noms de fichiers, ni les clés d'environnement.
  · La POPULATION est découverte en parcourant `daemon/src` (le système de fichiers, PAS `git ls-files` :
    une garde à corpus `git ls-files` valide un arbre où un fichier NEUF n'est pas encore suivi, puis
    rougit en CI — le dépôt s'est déjà fait mordre par là, `P11.13-d`).
  · Les MUTATEURS sont DÉRIVÉS des sources en DEUX temps. (a) Toute fonction côté test dont le corps
    écrit `env::set_var` / `env::remove_var` — fonctions LIBRES comme fonctions ASSOCIÉES d'un `impl`.
    C'est ce terme-là qui fait apparaître `cold_env_on` (par lequel quatre tests de plafonds posent
    `PLUME_COLD_TIER` sans jamais écrire `set_var`) et `ReglageBackupPose::neuf` (une fonction associée,
    donc invisible à un parseur qui ne lirait que les fonctions libres) : chercher `set_var` dans les
    corps de `#[test]` les aurait tous laissés passer. (b) La FERMETURE sur les appels : une fonction
    qui appelle un mutateur en est un. Elle n'ajoute AUCUN nom sur l'arbre d'aujourd'hui — la chaîne
    d'appels y est courte — et c'est un témoin synthétique, pas l'arbre, qui la valide ; sans quoi
    « elle n'a rien ajouté » et « elle est cassée » se liraient pareil.
  · Les PORTEURS du verrou EN ÉCRITURE sont dérivés de la même façon : un test qui prend le verrou à
    travers `p4a_lock_env_mute()` ou `rba_env_lock()` le prend bel et bien.

CÔTÉ TEST vs CÔTÉ PRODUCTION — LA FRONTIÈRE EST DÉRIVÉE, PAS DÉCRÉTÉE
---------------------------------------------------------------------
Le code de PRODUCTION mute lui aussi l'environnement (`sqlite_plafond.rs` pose `SQLITE_TMPDIR` en
ouvrant la base) : c'est le comportement du produit, pas le levier d'un test, et l'exiger sous verrou
sérialiserait toute la suite pour rien. La frontière est donc lue dans les sources : est « côté test »
tout fichier atteint par un `mod` déclaré `#[cfg(test)]` (et les fichiers qu'il `include!`), plus tout
bloc `#[cfg(test)] mod … { … }` écrit dans un fichier de production. Un fichier de test créé demain
entre par construction ; aucun nom n'est écrit ici.

CE QUE CETTE GARDE NE PROUVE PAS
--------------------------------
1. Elle tient le côté MUTATEUR. Le côté LECTEUR — « ce test dépend de l'environnement, il doit prendre
   `.read()` » — n'est pas une propriété syntaxique : tout appel à `cfg()` lit l'environnement. Cette
   part-là tient à la relecture, et aux gardes de famille qui existent déjà (celle des sauvegardes,
   `aucune_sauvegarde_de_test_ne_lit_les_reglages_sans_le_verrou`, DÉDUIT qui déclenche une sauvegarde).
2. Elle voit qu'un verrou est PRIS, pas qu'il est TENU ASSEZ LONGTEMPS. Un test qui prendrait le verrou
   puis le relâcherait avant de muter passerait. Le patron du dépôt — `let _env = …write();` en tête de
   corps — rend ce cas visible à la relecture.
3. Elle ne suit pas une indirection à travers un pointeur de fonction, une macro ou un trait objet.
   L'appel doit être écrit avec le nom (`nom(` ou `Type::nom(`). Une indirection plus profonde est
   INVISIBLE — donc elle produit un faux NÉGATIF, jamais une accusation à tort.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
-------------------------------------------------
Témoin POSITIF (un corps synthétique qui mute sans verrou doit être accusé), témoin NÉGATIF (le même
corps avec le verrou doit être acquitté, et un corps qui ne mute rien aussi), témoin de MODE (un corps
qui mute sous `.read()` ne doit PAS être acquitté), témoin de la FERMETURE dans les deux sens, témoin du
corps d'UNE SEULE LIGNE (`fn nom(&self) -> &str { "x" }` : la lecture doit s'arrêter là, sinon l'unité
avale la suite du fichier — mesuré le 2026-08-25, cette faute-là faisait entrer trois méthodes d'un
double de test à la fois dans les mutateurs et dans les porteurs), CONTRÔLE POSITIF sur l'arbre réel (la
dérivation doit retrouver `cold_env_on` ET `ReglageBackupPose::neuf` — une fonction libre et une fonction
associée ; sans elles, elle ne voit plus les mutations indirectes et son « aucune infraction » ne dit
rien), et PLANCHERS de non-dégénérescence. Sous un plancher, la garde REFUSE DE CONCLURE (sortie 2) au
lieu de rendre vert en étant aveugle.

Usage :  python3 .github/scripts/check_no_test_mutates_the_process_env_unlocked.py [--repo CHEMIN]
Sortie :  0 = sain ; 1 = violation (chaque test nommé) ; 2 = la garde refuse de conclure.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

ETIQUETTE = "verrou-env-processus"
VERROU = "VERROU_ENV_PROCESSUS"
ECRITURE = f"{VERROU}.write()"
SRC = Path("daemon") / "src"

# La MUTATION, telle qu'elle s'écrit : `std::env::set_var(…)`, `env::remove_var(…)`, ou l'un des deux
# importé. Le `(` est exigé : une mention en prose ou en identifiant plus long ne mute rien.
MUTATION = re.compile(r"(?<![\w:])(?:(?:std\s*::\s*)?env\s*::\s*)?(set_var|remove_var)\s*\(")
# En-tête de fonction, à N'IMPORTE QUELLE indentation (les fonctions associées d'un `impl` vivent plus
# profond que les fonctions libres, et ce sont précisément elles que le défaut a utilisées pour passer).
EN_TETE_FN = re.compile(r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z0-9_]+)")
EN_TETE_IMPL = re.compile(r"^(\s*)(?:unsafe\s+)?impl(?:\s*<[^>]*>)?\s+(.+?)\s*\{\s*$")
MOD_FICHIER = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;")
INCLUDE = re.compile(r'include!\s*\(\s*"([^"]+)"\s*\)')


def sans_commentaire(ligne: str) -> str:
    """Retire un `//…` de fin de ligne. Une mutation citée en commentaire ne mute rien, et un nom de
    test cité dans un message d'assertion ne doit pas compter pour un appel."""
    i = ligne.find("//")
    return ligne if i < 0 else ligne[:i]


def appelle(corps: str, nom: str) -> bool:
    """APPEL de `nom`, pas simple occurrence : le caractère qui précède ne doit pas être un caractère de
    nom (sinon `domain(` compterait pour un appel à `main`), et les commentaires sont retirés."""
    motif = nom + "("
    for ligne in corps.splitlines():
        l = sans_commentaire(ligne)
        i = 0
        while True:
            i = l.find(motif, i)
            if i < 0:
                break
            avant = l[i - 1] if i else ""
            if not (avant.isalnum() or avant == "_"):
                return True
            i += 1
    return False


class Unite:
    """Une fonction : son nom nu, son nom QUALIFIÉ (`Type::nom` dans un `impl`), s'il porte `#[test]`,
    son corps, et où il commence."""

    __slots__ = ("fichier", "ligne", "nom", "qualifie", "test", "corps")

    def __init__(self, fichier, ligne, nom, qualifie, test, corps):
        self.fichier, self.ligne, self.nom, self.qualifie = fichier, ligne, nom, qualifie
        self.test, self.corps = test, corps

    def __repr__(self):
        return f"{self.fichier}::{self.qualifie or self.nom}"


def depouiller_rust(src: str) -> str:
    """Le texte à LIRE : commentaires (ligne et bloc, imbriqués) et CONTENU des littéraux (chaînes,
    chaînes brutes, littéraux d'octets, caractères) remplacés par des espaces, hauteur et longueur
    CONSERVÉES. Sans cela, une accolade écrite dans un gabarit (`format!("… {} …")`) déplacerait la fin
    de chaque corps de fonction, et un mot cité dans un message d'assertion compterait pour du code.
    Une apostrophe qui n'ouvre pas un caractère (`'static`) reste une durée de vie, pas un littéral."""
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            prof = 0
            while i < n:
                if src.startswith("/*", i):
                    prof += 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    continue
                if src.startswith("*/", i):
                    prof -= 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    if prof == 0:
                        break
                    continue
                if src[i] != "\n":
                    out[i] = " "
                i += 1
        elif c in "rb" and (m := re.match(r'(?:b?r|rb)(#*)"', src[i:])):
            diese = m.group(1)
            j = src.find('"' + diese, i + m.end() - 1 + 1)
            fin = (j + 1 + len(diese)) if j >= 0 else n
            for k in range(i, min(fin, n)):
                if src[k] != "\n":
                    out[k] = " "
            i = fin
        elif c == '"' or (c == "b" and i + 1 < n and src[i + 1] == '"'):
            j = i + (2 if c == "b" else 1)
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                if src[k] != "\n":
                    out[k] = " "
            i = j
        elif c == "'":
            # caractère (`'a'`, `'\n'`) vs durée de vie (`'static`) : seule la forme fermée est un littéral
            if i + 1 < n and src[i + 1] == "\\":
                j = i + 2
                while j < n and src[j] != "'":
                    j += 1
                j += 1
            elif i + 2 < n and src[i + 2] == "'":
                j = i + 3
            else:
                out[i] = " " if src[i] != "\n" else out[i]
                i += 1
                continue
            for k in range(i, min(j, n)):
                if src[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def unites(chemin_relatif: str, src: str) -> list[Unite]:
    """Découpe un fichier en fonctions. Le corps d'une fonction va de son en-tête à l'accolade qui
    REFERME celle de son corps, comptée sur le texte DÉPOUILLÉ — pas à la première ligne qui ressemble à
    une fermeture. La différence n'est pas cosmétique : un corps d'une seule ligne
    (`fn kind_name(&self) -> &'static str { "all-true" }`) faisait, avec la règle d'indentation, avaler
    tout le fichier jusqu'à la prochaine fermeture de même profondeur — et cette unité-là contenait
    alors des mutations et des prises de verrou qui ne lui appartenaient pas. Une fonction IMBRIQUÉE est
    une unité de plus, ET reste incluse dans le corps de celle qui la contient : une mutation écrite
    dans une fonction imbriquée ne peut pas échapper au test qui la porte."""
    nu = depouiller_rust(src)
    lignes = src.split("\n")
    lignes_nues = nu.split("\n")
    debut_de_ligne = []
    pos = 0
    for l in lignes_nues:
        debut_de_ligne.append(pos)
        pos += len(l) + 1

    def fin_du_corps(i: int) -> int:
        """Numéro (exclusif) de la dernière ligne du corps ouvert sur la ligne `i`."""
        prof, vu = 0, False
        for j in range(i, len(lignes_nues)):
            for c in lignes_nues[j]:
                if c == "{":
                    prof += 1
                    vu = True
                elif c == "}":
                    prof -= 1
                    if vu and prof <= 0:
                        return j + 1
            if vu and prof <= 0:
                return j + 1
        return len(lignes_nues)

    impls: list[tuple[int, str, int]] = []   # (indentation, type, fin de bloc)
    out: list[Unite] = []
    marque_test = False
    for i, l in enumerate(lignes_nues):
        t = l.strip()
        m_impl = EN_TETE_IMPL.match(l)
        if m_impl:
            ind = len(m_impl.group(1))
            cible = m_impl.group(2)
            if " for " in cible:                       # `impl Trait for Type`
                cible = cible.split(" for ", 1)[1]
            impls.append((ind, cible.split("<")[0].strip(), fin_du_corps(i)))
        m = EN_TETE_FN.match(l)
        if m:
            ind = len(m.group(1))
            nom = m.group(2)
            porteur = next((b for (a, b, f) in reversed(impls) if a < ind and i < f), None)
            fin = fin_du_corps(i)
            # LE CORPS RETENU EST LE TEXTE DÉPOUILLÉ : une mutation citée en commentaire ne mute
            # rien, et un `VERROU_ENV_PROCESSUS` cité en commentaire ne tient aucun verrou. Juger le
            # texte brut acquitterait le second cas — c'est-à-dire rendrait vert un test NU.
            out.append(Unite(chemin_relatif, i + 1, nom, f"{porteur}::{nom}" if porteur else None,
                             marque_test, "\n".join(lignes_nues[i:fin])))
            marque_test = False
        elif t.startswith("#["):
            # `#[test]` ET `#[tokio::test]` ; `#[cfg(test)]` finit par `test)]` -> exclu.
            marque_test = marque_test or t.rstrip().endswith("test]")
        elif t and not t.startswith("//"):
            marque_test = False
    return out


def fichiers_rs(racine: Path) -> list[Path]:
    out = []
    for d, _, fs in os.walk(racine):
        for f in fs:
            if f.endswith(".rs"):
                out.append(Path(d) / f)
    return sorted(out)


def cote_test(repo: Path, chemins: list[Path]) -> set[Path]:
    """LA FRONTIÈRE, LUE DANS LES SOURCES. Un `mod X;` précédé de `#[cfg(test)]` rend `X.rs` (ou
    `X/mod.rs`) test-only, et les fichiers qu'il `include!` avec lui. Aucun nom n'est écrit ici."""
    test_only: set[Path] = set()
    a_voir: list[Path] = []
    for p in chemins:
        lignes = p.read_text(encoding="utf-8", errors="replace").split("\n")
        precede_cfg_test = False
        for l in lignes:
            t = l.strip()
            m = MOD_FICHIER.match(l)
            if m and precede_cfg_test:
                for cand in (p.parent / f"{m.group(1)}.rs", p.parent / m.group(1) / "mod.rs"):
                    if cand.exists():
                        a_voir.append(cand)
            if t.startswith("#["):
                precede_cfg_test = precede_cfg_test or t.replace(" ", "") == "#[cfg(test)]"
            elif t and not t.startswith("//"):
                precede_cfg_test = False
    while a_voir:
        p = a_voir.pop()
        if p in test_only:
            continue
        test_only.add(p)
        src = p.read_text(encoding="utf-8", errors="replace")
        for rel in INCLUDE.findall(src):
            cand = (p.parent / rel).resolve()
            if cand.exists():
                a_voir.append(cand)
    return test_only


def blocs_mod_test(src: str) -> list[tuple[int, int]]:
    """Les plages `#[cfg(test)] mod … { … }` écrites DANS un fichier de production : leurs fonctions
    sont, elles aussi, du code de test."""
    lignes = src.split("\n")
    plages = []
    precede = False
    for i, l in enumerate(lignes):
        t = l.strip()
        if precede and re.match(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z0-9_]+\s*\{", l):
            ind = len(l) - len(l.lstrip())
            fermeture = " " * ind + "}"
            fin = len(lignes)
            for j in range(i + 1, len(lignes)):
                if lignes[j].rstrip() == fermeture:
                    fin = j + 1
                    break
            plages.append((i + 1, fin))
        if t.startswith("#["):
            precede = precede or t.replace(" ", "") == "#[cfg(test)]"
        elif t and not t.startswith("//"):
            precede = False
    return plages


def fermeture(depart: set[str], candidats: list[Unite], tours: int = 6) -> set[str]:
    """Ferme un ensemble de NOMS sur les unités candidates : une unité qui APPELLE un nom de l'ensemble
    entre à son tour. Les fonctions associées n'entrent que par leur nom QUALIFIÉ (`Type::nom`) — un nom
    de constructeur comme `neuf` ou `build` est trop commun pour être suivi nu."""
    vus = set(depart)
    for _ in range(tours):
        neuf = set()
        for u in candidats:
            cle = u.qualifie or u.nom
            if cle in vus or u.test:
                continue
            if any(appelle(u.corps, n) for n in vus):
                neuf.add(cle)
        if not neuf:
            break
        vus |= neuf
    return vus


def temoins():
    """L'INSTRUMENT DANS LES DEUX SENS, avant tout verdict sur l'arbre."""
    doit_accuser = [
        '    #[test]\n    fn t() {\n        std::env::set_var("PLUME_X", "1");\n    }\n',
        '    #[test]\n    fn t() {\n        env::remove_var("PLUME_X");\n    }\n',
    ]
    doit_acquitter = [
        '    #[test]\n    fn t() {\n        let _e = VERROU_ENV_PROCESSUS.write();\n'
        '        std::env::set_var("PLUME_X", "1");\n    }\n',
        '    #[test]\n    fn t() {\n        let v = std::env::var("PLUME_X");\n    }\n',
        '    #[test]\n    fn t() {\n        // std::env::set_var("PLUME_X", "1");\n    }\n',
    ]
    for src in doit_accuser:
        us = unites("t.rs", src)
        assert us and MUTATION.search(us[0].corps) and VERROU not in us[0].corps, \
            f"témoin POSITIF : un corps qui mute sans verrou n'est pas accusé — {src!r}"
    for src in doit_acquitter:
        us = unites("t.rs", src)
        assert us, f"témoin : corps illisible — {src!r}"
        mute = bool(MUTATION.search(us[0].corps))
        assert (not mute) or ECRITURE in us[0].corps, \
            f"témoin NÉGATIF : un corps sain est accusé — {src!r}"
    # LE MODE : `.read()` ne suffit PAS pour muter — les lecteurs sont parallèles entre eux.
    lecteur_qui_mute = ('    #[test]\n    fn t() {\n        let _e = VERROU_ENV_PROCESSUS.read();\n'
                        '        std::env::set_var("PLUME_X", "1");\n    }\n')
    us = unites("t.rs", lecteur_qui_mute)
    assert MUTATION.search(us[0].corps) and ECRITURE not in us[0].corps, \
        "témoin : un test qui MUTE sous `.read()` serait acquitté — le mode n'est pas lu"
    # borne de mot : `domain(` n'est pas un appel à `main`
    assert not appelle("    let d = domain(x);", "main"), \
        "témoin : la borne de mot ne tient pas — un nom court accuserait tout"
    assert appelle("    let d = main(x);", "main"), "témoin INVERSE : un vrai appel n'est plus vu"
    # une fonction associée doit être vue, et son nom nu ne doit pas suffire
    us = unites("t.rs", "impl R {\n    fn neuf() {\n        std::env::set_var(\"A\", \"b\");\n    }\n}\n")
    assert any(u.qualifie == "R::neuf" for u in us), \
        "témoin : les fonctions associées d'un `impl` ne sont pas lues — c'est par là que le défaut passait"
    # un corps d'UNE SEULE LIGNE ne doit pas avaler ce qui suit : c'est la faute qui, mesurée le
    # 2026-08-25, faisait entrer trois méthodes d'un double de test dans la liste des mutateurs ET dans
    # celle des porteurs du verrou — le même corps, avalé, contenait les deux.
    us = unites("t.rs", 'impl R {\n    fn nom(&self) -> &str { "x" }\n}\n'
                        'fn ailleurs() {\n    std::env::set_var("A", "b");\n}\n')
    court = next(u for u in us if u.nom == "nom")
    assert "set_var" not in court.corps, \
        "témoin : un corps d'une seule ligne avale la suite du fichier — toute la lecture devient fausse"
    # LA FERMETURE : un utilitaire qui appelle un mutateur EST un mutateur. Sans ce témoin, la fermeture
    # n'est vérifiée par rien sur cet arbre (elle n'y ajoute aujourd'hui aucun nom).
    us = unites("t.rs", 'fn pose() {\n    std::env::set_var("A", "b");\n}\n'
                        'fn prepare() {\n    pose();\n}\n'
                        'fn prepare_plus() {\n    prepare();\n}\n')
    ferme = fermeture({"pose"}, us)
    assert ferme == {"pose", "prepare", "prepare_plus"}, \
        f"témoin : la fermeture ne remonte pas la chaîne d'appels — {sorted(ferme)}"
    assert fermeture({"pose"}, [u for u in us if u.nom == "prepare_plus"]) == {"pose"}, \
        "témoin INVERSE : la fermeture ajoute un nom qu'aucun corps n'appelle"


def refuser(msg: str) -> int:
    print(f"::error::[{ETIQUETTE}] {msg}")
    return 2


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=".")
    args = ap.parse_args()
    repo = Path(args.repo).resolve()
    racine = repo / SRC

    temoins()

    if not racine.is_dir():
        return refuser(f"{racine} : dossier introuvable — la découverte est cassée.")
    chemins = fichiers_rs(racine)
    # PLANCHERS, mesurés le 2026-08-25 sur cet arbre : 1615 attributs `#[test]`/`#[tokio::test]` dans
    # les sources (la suite EXÉCUTÉE en compte moins — beaucoup sont derrière une fonctionnalité cargo
    # éteinte — et c'est bien la SOURCE que cette garde lit), 72 tests mutateurs. Ils ferment le seul
    # mode de panne réel de la découverte : un parseur qui ne trouve RIEN et rapporte un vert joyeux.
    if len(chemins) < 100:
        return refuser(f"{len(chemins)} fichier(s) .rs découverts sous {SRC}, plancher 100.")

    test_only = cote_test(repo, chemins)
    if len(test_only) < 40:
        return refuser(f"{len(test_only)} fichier(s) côté test dérivés des `mod` sous `#[cfg(test)]`, "
                       f"plancher 40 : la frontière test/production est cassée.")

    toutes: list[Unite] = []
    unites_test_side: list[Unite] = []
    tests: list[Unite] = []
    for p in chemins:
        rel = os.path.relpath(p, repo)
        src = p.read_text(encoding="utf-8", errors="replace")
        us = unites(rel, src)
        toutes.extend(us)
        if p in test_only:
            unites_test_side.extend(us)
        else:
            plages = blocs_mod_test(src)
            unites_test_side.extend(u for u in us if any(a <= u.ligne <= b for a, b in plages))
        tests.extend(u for u in us if u.test)
    if len(tests) < 900:
        return refuser(f"{len(tests)} `#[test]` découverts, plancher 900 : la lecture des corps est cassée.")

    # --- (1) LES MUTATEURS, DÉRIVÉS DES SOURCES CÔTÉ TEST -------------------------------------------
    directs = {(u.qualifie or u.nom) for u in unites_test_side
               if not u.test and MUTATION.search(u.corps)}
    mutateurs = fermeture(directs, unites_test_side)
    indirects = sorted(mutateurs - directs)
    print(f"[{ETIQUETTE}] mutateurs directs dérivés (utilitaires de test) : {sorted(directs)}")
    print(f"[{ETIQUETTE}] mutateurs ajoutés par la FERMETURE sur les appels : {indirects}")
    # CONTRÔLE POSITIF de la dérivation : sans ces deux-là, elle est inerte, et « aucune infraction »
    # ne dirait rien. `cold_env_on` est une fonction LIBRE (quatre tests de plafonds mutent par elle) ;
    # `ReglageBackupPose::neuf` est une fonction ASSOCIÉE (invisible à un parseur de fonctions libres).
    for controle in ("cold_env_on", "ReglageBackupPose::neuf"):
        if controle not in mutateurs:
            return refuser(f"la dérivation n'a pas retrouvé `{controle}` : elle ne voit plus les "
                           f"mutations INDIRECTES, et son verdict ne vaudrait rien.")

    # --- (2) LES PORTEURS DU VERROU EN ÉCRITURE, DÉRIVÉS DE LA MÊME FAÇON ---------------------------
    # LE MODE COMPTE. Un test qui MUTE sous `.read()` n'exclut personne : les lecteurs sont parallèles
    # entre eux, donc sa mutation s'applique pendant qu'un voisin lit. Exiger `VERROU` sans regarder le
    # mode acquitterait exactement le cas que la clé ferme.
    porteurs = fermeture({u.qualifie or u.nom for u in unites_test_side
                          if not u.test and ECRITURE in u.corps}, unites_test_side)
    print(f"[{ETIQUETTE}] utilitaires qui prennent le verrou EN ÉCRITURE : {sorted(porteurs)}")

    def tient_le_verrou(u: Unite) -> bool:
        return ECRITURE in u.corps or any(appelle(u.corps, n) for n in porteurs)

    def mute(u: Unite) -> bool:
        return bool(MUTATION.search(u.corps)) or \
            any(appelle(u.corps, n) for n in mutateurs)

    mutants = [u for u in tests if mute(u)]
    nus = [u for u in mutants if not tient_le_verrou(u)]
    print(f"[{ETIQUETTE}] {len(tests)} `#[test]` lus, {len(mutants)} mutent l'environnement, "
          f"{len(mutants) - len(nus)} tiennent le verrou.")
    if len(mutants) < 40:
        return refuser(f"{len(mutants)} test(s) mutateur(s) trouvés, plancher 40 (mesuré le 2026-08-25 : "
                       f"72) : la lecture est cassée, la garde refuse de conclure.")

    for u in nus:
        print(f"::error file={u.fichier},line={u.ligne}::le test `{u.nom}` MUTE une variable "
              f"d'environnement du processus sans tenir `{VERROU}`. L'environnement est UNE ressource "
              f"pour tout le binaire de test : ce que ce test pose, il le pose pour tous ceux qui "
              f"tournent au même instant — et `cfg()` fait passer l'environnement DEVANT la `conf`, donc "
              f"il écrase même la conf d'un voisin qui croyait décider seul. Prendre le verrou UNIQUE en "
              f"tête de corps : `let _env = {ECRITURE};`. `.read()` NE SUFFIT PAS pour muter : les "
              f"lecteurs sont parallèles entre eux, donc la mutation s'appliquerait pendant qu'un voisin "
              f"lit (`.read()` est le mode de qui DÉPEND de l'environnement sans y toucher). Ne pas "
              f"ajouter un verrou de plus : deux verrous pour une "
              f"ressource, c'est zéro verrou.")
    if nus:
        print(f"[{ETIQUETTE}] {len(nus)} test(s) mutent l'environnement sans le verrou.")
        return 1

    print(f"[{ETIQUETTE}] OK — les {len(mutants)} tests qui mutent l'environnement du processus tiennent "
          f"tous `{ECRITURE}`, le verrou UNIQUE de cette ressource, dans le mode qui exclut. Ce que cette "
          f"garde NE tient PAS : le côté LECTEUR (« ce test dépend de l'environnement »), qui n'est pas une "
          f"propriété syntaxique, et la DURÉE de tenue du verrou.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
