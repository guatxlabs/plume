#!/usr/bin/env python3
"""« Je n'ai pas pu mesurer » sort par un CANAL DISTINCT de « la propriété est violée » (`P7.19-b`).

CE QUI ÉTAIT POSÉ, ET CE QUI NE L'ÉTAIT PAS — MESURÉ LE 2026-08-27
------------------------------------------------------------------
`daemon/src/tests/query_verify.rs` fabrique un banc dont la mesure n'est valide que dans une
fenêtre, et refuse de conclure hors d'elle par `qb_refuser_de_conclure`, dont le message porte une
MARQUE en tête. Le texte du module affirmait : « la CI trie sur cette marque et rend le code 2 — je
refuse de conclure — là où une propriété violée rend 1 ». Trois mesures, le même jour :
  * `grep -rn "INSTRUMENT NON" .github/` -> ZÉRO. Rien ne lisait la marque.
  * l'étape qui exécute la suite sommait les `test result: ok.` et sortait `1` sur écart : aucun
    chemin de sortie 2 n'existait dans les jobs Rust.
  * `qb_refuser_de_conclure` se termine par `panic!` : l'intégration voyait EXACTEMENT ce qu'elle
    voit pour une assertion violée — même canal, même code.
Et l'exemplaire cité en modèle rendait 1, pas 2 : `python3 check_windows_collector_is_honest.py`
sans `pwsh` -> **1**. Un mécanisme POSÉ, présenté comme ARMÉ.

CE QUE CE FICHIER FAIT, ET C'EST DEUX CHOSES
--------------------------------------------
(A) IL EST LE TRI LUI-MÊME. `--trier <journal> <code-cargo>` est appelé par `ci.yml` après chaque
    `cargo test`, et rend :
        2  la marque figure dans le journal            -> « JE N'AI PAS PU MESURER »
        c  aucune marque, cargo a rendu c != 0         -> une propriété est violée (le code de cargo)
        0  aucune marque, cargo a rendu 0              -> rien à dire
        2  la marque figure ALORS QUE cargo a rendu 0  -> l'instrument se contredit : dans le doute,
                                                          on refuse de conclure.
(B) IL GARDE CE TRI. Exécuté sans argument (le pas de CI), il exerce ses propres témoins POSITIF et
    NÉGATIF sur la fonction ci-dessus — celle-là même que la CI appelle, pas une copie — puis vérifie
    deux propriétés DÉRIVÉES de l'arbre :
      1. la marque existe dans `daemon/src/tests/query_verify.rs` et la fonction de refus l'emploie ;
      2. TOUT pas d'un flux de travail qui lance `cargo test` SUR LE CRATE OÙ VIT LE BANC appelle ce
         tri. La population est DÉRIVÉE, jamais énumérée : le crate est celui qui contient
         `query_verify.rs` (on remonte jusqu'au `Cargo.toml`), et les pas retenus sont ceux dont le
         `working-directory` est ce crate. Un pas neuf qui lance `cargo test` là fait rougir cette
         garde ; et si le banc DÉMÉNAGE, la population le suit sans qu'on y pense.
         BORNE DITE : les pas qui lancent `cargo test` sur un AUTRE crate (`agent`,
         `collector-syslog`, `collector-mail`) ne sont pas couverts — la marque ne peut pas y
         apparaître, le banc n'y est pas compilé. Le jour où un second banc à refus naîtrait
         ailleurs, cette borne devrait bouger, et elle est écrite pour qu'on la voie.

CE QUE LE CODE 2 N'ACHÈTE PAS, ÉCRIT PLUTÔT QUE SOUS-ENTENDU
------------------------------------------------------------
Le job reste ROUGE dans les deux cas, et c'est délibéré : un banc qui sait ne pas avoir mesuré n'a
pas le droit d'être vert. Ce que le code 2 achète est un tri MÉCANIQUE — le code de sortie de
l'étape, plus une annotation distincte — au lieu d'une lecture d'humain sur un `panic!` que rien ne
distingue d'une assertion. Ce fichier ne prétend pas plus.

BORNE DE LA PROPRIÉTÉ 2, DITE : elle regarde le TEXTE des flux de travail. Elle établit que le tri
est CÂBLÉ après chaque `cargo test`, pas qu'un runner l'a exécuté — cette seconde chose, seule
l'exécution la montre, et c'est le rôle du pas de CI lui-même.
"""

import os
import re
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
FLUX = os.path.join(RACINE, ".github", "workflows")
BANC = os.path.join(RACINE, "daemon", "src", "tests", "query_verify.rs")

# La marque est LUE dans la source du banc, jamais recopiée : deux copies divergent, et c'est
# exactement le défaut que ce fichier existe pour empêcher.
MARQUE_DECL = re.compile(r'const\s+QB_MARQUE_REFUS\s*:\s*&str\s*=\s*"([^"]+)"\s*;')
MOI = os.path.basename(__file__)

CODE_REFUS = 2          # « je n'ai pas pu mesurer » — le canal distinct
CODE_INSTRUMENT = 2     # la garde elle-même, quand elle ne peut pas conclure


def marque_du_banc():
    """La marque, LUE dans `query_verify.rs`. `None` si elle n'y est plus."""
    try:
        source = open(BANC, encoding="utf-8").read()
    except OSError:
        return None, None
    m = MARQUE_DECL.search(source)
    if not m:
        return None, source
    return m.group(1), source


# =================================================================================================
# (A) LE TRI — la fonction que `ci.yml` appelle, et que les témoins ci-dessous exercent.
# =================================================================================================
def trier(journal_texte, code_cargo, marque):
    """Rend (code, explication). Voir l'en-tête pour la table complète."""
    porte_la_marque = marque in journal_texte
    if porte_la_marque and code_cargo == 0:
        return (CODE_REFUS,
                "le journal porte la marque du refus de conclure ALORS QUE cargo a rendu 0 : "
                "l'instrument se contredit, et dans le doute on ne conclut pas.")
    if porte_la_marque:
        return (CODE_REFUS,
                "JE N'AI PAS PU MESURER — un banc a REFUSÉ DE CONCLURE (marque « "
                f"{marque} » dans le journal). Ce n'est PAS une propriété violée : le témoin n'a "
                "pas pu être amené dans sa fenêtre de validité. Lire les paliers d'étalonnage "
                "rendus juste après la marque.")
    if code_cargo != 0:
        return (code_cargo,
                f"cargo a rendu {code_cargo} et AUCUN banc n'a refusé de conclure : "
                "une propriété est violée, ou la suite n'a pas compilé.")
    return (0, "cargo vert, aucune marque de refus.")


def epreuves(marque):
    """TÉMOINS POSITIF **ET** NÉGATIF, sur la fonction que la CI appelle — pas sur une copie.

    Le témoin NÉGATIF est celui qui interdit la fausse correction : un tri qui rendrait 2 pour
    TOUTE défaillance ne distinguerait rien et passerait le témoin positif brillamment.
    """
    panique_ordinaire = (
        "running 3 tests\n"
        "test qb_la_garde_de_budget_mord_toujours ... FAILED\n"
        "thread 'qb_la_garde…' panicked at daemon/src/tests/query_verify.rs:401:\n"
        "assertion failed: surcout_ms < QB_TICK_MS\n"
        "test result: FAILED. 2 passed; 1 failed\n"
    )
    refus = (
        "running 3 tests\n"
        "test qb_le_surcout_de_la_garde_ne_paie_plus_le_tick ... FAILED\n"
        f"{marque} — porte A : je n'ai pas pu MESURER. …\n"
        "  paliers d'étalonnage : n=2000 -> SQL 0.053 ms | n=11321 -> SQL 2.041 ms\n"
        "test result: FAILED. 2 passed; 1 failed\n"
    )
    vert = "running 3 tests\ntest result: ok. 3 passed; 0 failed\n"
    cas = [
        ("POSITIF   — refus de conclure, cargo 101", refus, 101, CODE_REFUS),
        ("NÉGATIF   — assertion violée, cargo 101", panique_ordinaire, 101, 101),
        ("NÉGATIF   — suite verte", vert, 0, 0),
        ("NÉGATIF   — échec de compilation, journal sans marque", "error[E0308]: mismatched types\n", 101, 101),
        ("DOUTE     — marque ET cargo vert", refus, 0, CODE_REFUS),
    ]
    for nom, journal, rc, attendu in cas:
        obtenu, _ = trier(journal, rc, marque)
        if obtenu != attendu:
            return f"témoin « {nom} » : le tri rend {obtenu}, attendu {attendu}"
    # ÉPREUVE DE L'INSTRUMENT LUI-MÊME : une marque vide apparierait TOUT texte et rendrait 2
    # partout ; le tri cesserait de trier sans qu'aucun témoin ne bouge.
    if not marque.strip():
        return "la marque lue est vide : elle apparierait n'importe quel journal"
    return None


# =================================================================================================
# (B) LES PROPRIÉTÉS DÉRIVÉES DE L'ARBRE
# =================================================================================================
LANCE_CARGO_TEST = re.compile(r"^\s*(?!#).*\bcargo\s+test\b", re.MULTILINE)


def blocs_run(texte):
    """Les blocs `run: |` d'un flux, rendus (indice de ligne, corps).

    DÉCOUPE PAR L'INDENTATION, la seule structure que YAML garantit ici : le corps d'un `run: |`
    est tout ce qui suit, plus indenté que la clé. Aucune bibliothèque YAML n'est requise (elle
    n'est pas garantie sur le runner qui exécute ces gardes)."""
    lignes = texte.splitlines()
    blocs = []
    i = 0
    while i < len(lignes):
        # `run: <commande>` sur UNE ligne est un pas comme un autre : l'oublier laisserait la
        # forme la plus courte hors de la population, c'est-à-dire une exception non écrite.
        plat = re.match(r"^\s*run:\s*(?![|>])(\S.*)$", lignes[i])
        if plat:
            blocs.append((i + 1, plat.group(1)))
            i += 1
            continue
        m = re.match(r"^(\s*)run:\s*[|>]", lignes[i])
        if not m:
            i += 1
            continue
        creux = len(m.group(1))
        depart = i
        corps = []
        i += 1
        while i < len(lignes):
            l = lignes[i]
            if l.strip() and (len(l) - len(l.lstrip())) <= creux:
                break
            corps.append(l)
            i += 1
        blocs.append((depart + 1, "\n".join(corps)))
    return blocs


def propriete_marque_armee(source, marque, erreurs):
    """La fonction de refus emploie la marque : sans cela, la marque est un commentaire."""
    corps = re.search(r"fn qb_refuser_de_conclure\b.*?\n    \}", source, re.S)
    if not corps:
        erreurs.append("`qb_refuser_de_conclure` INTROUVABLE dans le banc : cette garde ne peut "
                       "pas établir que la marque est émise, elle REFUSE DE CONCLURE.")
        return
    if "QB_MARQUE_REFUS" not in corps.group(0):
        erreurs.append("la fonction de refus du banc n'emploie PAS `QB_MARQUE_REFUS` : la marque "
                       f"« {marque} » ne serait jamais imprimée, et le tri de la CI ne trierait rien.")


def crate_du_banc():
    """Le répertoire du crate qui COMPILE le banc — remonté depuis `query_verify.rs` jusqu'au
    `Cargo.toml`, rendu relatif à la racine. C'est LUI qui définit la population des pas à tri
    obligatoire ; il n'est écrit nulle part à la main."""
    d = os.path.dirname(BANC)
    while d.startswith(RACINE) and len(d) > len(RACINE):
        if os.path.exists(os.path.join(d, "Cargo.toml")):
            return os.path.relpath(d, RACINE)
        d = os.path.dirname(d)
    return None


REP_DE_TRAVAIL = re.compile(r"^\s*working-directory:\s*(\S+)\s*$")
DEBUT_DE_PAS = re.compile(r"^\s*-\s+(name|uses|run):")


def repertoires_par_ligne(texte):
    """Pour chaque ligne, le `working-directory` du pas qui la contient (ou None).

    Un pas commence à `- name:`/`- uses:`/`- run:` ; le répertoire y est remis à zéro, puis pris
    au premier `working-directory:` rencontré dans le pas. C'est la structure que GitHub garantit,
    et elle se lit sans bibliothèque YAML (pas garantie sur le runner des gardes)."""
    courant = None
    par_ligne = []
    for l in texte.splitlines():
        if DEBUT_DE_PAS.match(l):
            courant = None
        m = REP_DE_TRAVAIL.match(l)
        if m:
            courant = m.group(1).strip("\"'")
        par_ligne.append(courant)
    return par_ligne


def propriete_tri_cable(erreurs):
    """DÉRIVÉE, JAMAIS ÉNUMÉRÉE : tout pas qui lance `cargo test` DANS LE CRATE DU BANC trie."""
    crate = crate_du_banc()
    if crate is None:
        erreurs.append("le crate du banc n'a pas pu être dérivé (aucun `Cargo.toml` au-dessus de "
                       f"{os.path.relpath(BANC, RACINE)}) : la garde REFUSE DE CONCLURE.")
        return None
    try:
        fichiers = sorted(f for f in os.listdir(FLUX) if f.endswith((".yml", ".yaml")))
    except OSError:
        erreurs.append(f"répertoire des flux illisible ({FLUX}) : la garde REFUSE DE CONCLURE.")
        return None
    if not fichiers:
        erreurs.append("aucun flux de travail lisible : la garde REFUSE DE CONCLURE.")
        return None
    vus = 0
    hors_population = 0
    for nom in fichiers:
        try:
            texte = open(os.path.join(FLUX, nom), encoding="utf-8").read()
        except OSError:
            erreurs.append(f"flux `{nom}` illisible : la garde REFUSE DE CONCLURE.")
            return None
        repertoires = repertoires_par_ligne(texte)
        for ligne, corps in blocs_run(texte):
            if not LANCE_CARGO_TEST.search(corps):
                continue
            rep = repertoires[ligne - 1] if ligne - 1 < len(repertoires) else None
            if rep != crate:
                hors_population += 1
                continue
            vus += 1
            if MOI not in corps or "--trier" not in corps:
                erreurs.append(
                    f"{nom}:{ligne} — ce pas lance `cargo test` dans `{crate}` (le crate du banc) "
                    f"sans passer son journal au tri (`{MOI} --trier <journal> <code>`). Un banc "
                    f"qui REFUSE DE CONCLURE y sortirait par le même canal et le même code qu'une "
                    f"propriété violée : c'est le défaut que `P7.19-b` ferme.")
    if vus == 0:
        erreurs.append(f"AUCUN pas de CI ne lance `cargo test` dans `{crate}` ({hors_population} "
                       f"pas le lancent ailleurs) : l'instrument de cette garde ne mesure rien, "
                       f"elle REFUSE DE CONCLURE.")
        return None
    return vus


def main():
    marque, source = marque_du_banc()
    if marque is None:
        print(f"::error::`QB_MARQUE_REFUS` INTROUVABLE dans {os.path.relpath(BANC, RACINE)} — la "
              f"marque du refus de conclure n'existe plus, ou sa forme a changé. Cette garde "
              f"trierait sur une chaîne inventée : elle REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT

    # --- (A) mode TRI, appelé par ci.yml -------------------------------------------------------
    if len(sys.argv) > 1 and sys.argv[1] == "--trier":
        if len(sys.argv) != 4:
            print(f"::error::usage : {MOI} --trier <journal> <code-cargo>", file=sys.stderr)
            return CODE_INSTRUMENT
        chemin, brut = sys.argv[2], sys.argv[3]
        try:
            code_cargo = int(brut)
        except ValueError:
            print(f"::error::code de cargo illisible (« {brut} ») : le tri REFUSE DE CONCLURE.",
                  file=sys.stderr)
            return CODE_INSTRUMENT
        try:
            journal = open(chemin, encoding="utf-8", errors="replace").read()
        except OSError as e:
            print(f"::error::journal de test illisible ({chemin} : {e}) : le tri ne peut pas "
                  f"distinguer un refus de conclure d'une propriété violée, il REFUSE DE CONCLURE.",
                  file=sys.stderr)
            return CODE_INSTRUMENT
        faute = epreuves(marque)
        if faute:
            print(f"::error::le tri est INVALIDE ({faute}) : il REFUSE DE CONCLURE.", file=sys.stderr)
            return CODE_INSTRUMENT
        code, pourquoi = trier(journal, code_cargo, marque)
        if code == CODE_REFUS:
            print(f"::error::[BANC] {pourquoi}")
        elif code != 0:
            print(f"::error::{pourquoi}")
        else:
            print(f"tri du journal : {pourquoi}")
        return code

    # --- (B) mode GARDE, appelé par le job des gardes -------------------------------------------
    faute = epreuves(marque)
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return CODE_INSTRUMENT

    erreurs = []
    propriete_marque_armee(source, marque, erreurs)
    vus = propriete_tri_cable(erreurs)
    if erreurs:
        for e in erreurs:
            print(f"::error::{e}")
        return 1
    print(f"canal distinct ARMÉ : marque « {marque} » lue dans le banc, tri câblé sur les {vus} pas "
          f"de CI qui lancent `cargo test` dans `{crate_du_banc()}` (marque -> code {CODE_REFUS} ; "
          f"propriété violée -> code de cargo).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
