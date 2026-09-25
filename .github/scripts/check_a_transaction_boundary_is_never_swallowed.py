#!/usr/bin/env python3
"""Une BORNE DE TRANSACTION (`BEGIN`, `COMMIT`) n'est jamais AVALÉE — garde de CI (`P10.25-g`, `P10.27-m`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Un geste d'écriture ouvre sa transaction (`BEGIN`), écrit, puis la valide (`COMMIT`). Les deux bornes rendent
un `Result`, et l'idiome qui le jette — `let _ = conn.execute_batch("COMMIT")`, `let _ = tx.commit()`,
`….execute_batch("BEGIN IMMEDIATE").ok()`, `if let Ok(tx) = Txn::begin(..) { … }` sans `else` — efface
l'échec. MESURÉ le 2026-09-24 sur les quarante-huit sites que `P10.25-g` et `P10.26-x` ont fermés (mutation :
la forme d'avant réintroduite site par site, témoins `cjds_`) : un `COMMIT` refusé puis avalé rendait 200 ou
204 sur un geste que la base n'avait pas pris, et laissait la transaction OUVERTE sur l'écrivain partagé ;
tout ce qui lit par cet écrivain voyait l'état pendant (un parseur jamais écrit était chargé par
l'ingestion) ; le garde `Txn` fermait la sienne, mais rendait quand même le succès.

Depuis `P10.26-s`, une transaction laissée ouverte n'est plus validée par accident par le geste suivant :
elle BLOQUE l'ingestion (503, lots gardés au spool), le pli des hôtes, le reparse et l'envoi des puits
jusqu'au redémarrage (`P10.27-g`). Un `COMMIT` avalé est donc devenu un risque de DISPONIBILITÉ, et un
`BEGIN` avalé (`P10.26-s`, zéro site depuis le lot 197) un risque d'INTÉGRITÉ : les écritures du geste
entrent dans la transaction d'un autre, que son `COMMIT` valide et son `ROLLBACK` annule.

LA POPULATION, ÉCRITE
---------------------
Une BORNE est, dans `daemon/src/` (sous-répertoires compris, `tests/`, `tests.rs` et les modules
`#[cfg(test)]` élagués, commentaires dépouillés, littéraux exclus) :
  * `.execute_batch("…")` ou `.execute("…", …)` dont le littéral COMMENCE par `COMMIT`, `END` ou `RELEASE`
    (genre `COMMIT`), `BEGIN` ou `SAVEPOINT` (genre `BEGIN`) ;
  * `.commit()` sans argument (garde `Txn`, transaction rusqlite) — genre `COMMIT` ;
  * `Txn::begin(`, `.transaction()`, `.unchecked_transaction()`, `.transaction_with_behavior(`,
    `.savepoint()` — genre `BEGIN` ;
  * les JUGES du dépôt, `valider_la_transaction(` et `ouvrir_sa_transaction(` : jeter LEUR `Result`
    serait la même faute écrite une ligne plus loin — et, depuis `P10.28-d`, les deux formes d'une ROUTE qui
    ouvre sa transaction, `ouvrir_la_transaction_du_geste(` et `ouvrir_le_garde_du_geste(` (genre `BEGIN`) : le lot
    y a déplacé quatre-vingt-quinze `BEGIN` littéraux ; sans elles, cette garde aurait cessé de lire ces bornes
    (MESURÉ : 88 bornes lues sur 25 fichiers, sous son plancher de 121/27) et leur `Result` jeté passerait.
`ROLLBACK` n'en fait PAS partie : son échec, après un refus, n'est pas une information (`valider_la_transaction`
le dit), et c'est `is_autocommit()` qu'on relit ensuite.

LES FORMES QUI AVALENT, ÉCRITES
-------------------------------
  * `let _` — la liaison sourde (`let _ = <receveur>.<borne>`), receveur-appel compris (lecteur `liaison_sourde`
    de la garde `P10.20-w`) ;
  * `.ok`, `.unwrap_or`, `.unwrap_or_default`, `.unwrap_or_else`, `.map_or`, `.map_or_else` — une chaîne qui
    ABSORBE l'échec (lecteur `verdict_de_la_chaine`, même vocabulaire) ; un `?` n'importe où la fait SORTIR ;
  * `instruction nue` — la borne seule, suivie de `;` ;
  * `drop` — `drop(<borne>)` ;
  * `if let Ok sans else` — `if let Ok(..) = <borne> { … }` sans branche `else` (lecteur `if_let_sans_branche`) ;
  * `Err muet` — `if let Err(..) = <borne> {}`, `if <borne>.is_err() {}`, ou un bras `Err(..) => {}` / `()` d'un
    `match` dont la borne est le scrutateur (lecteur `bras_du_match`) ;
  * `.is_ok sans else` — `if <borne>.is_ok() { … }` sans `else`, sur une borne BRUTE (les juges disent eux-mêmes
    leur refus au journal : `if … && ouvrir_sa_transaction(..).is_ok()` n'est pas accusé) ;
  * `let _.is_ok`, `let _.is_err` et leurs formes d'instruction nue — le test jeté.

POURQUOI UN ENSEMBLE NOMMÉ, JUGÉ DANS LES DEUX SENS
---------------------------------------------------
Un compte se laisse compenser : un site corrigé et un site neuf le même jour laissent le total immobile.
`SITES_TOLERES` est donc un ensemble de SITES — fichier, fonction, et la forme (genre + façon d'avaler) —, et
jamais un compte ni un numéro de ligne. Un site hors ensemble est une FORME NEUVE (rouge) ; une entrée qui n'est
plus accusée est une EXEMPTION SANS OBJET (rouge : corrigé sans retirer l'entrée, ou la garde a cessé de le voir —
dans les deux cas l'entrée se retire à la main EN DISANT LEQUEL).

CE QUE CE VERT NE DIRA PAS : voir `ce_qui_n_est_pas_tenu()`.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

RACINE = (os.path.abspath(sys.argv[1]) if len(sys.argv) > 1
          else os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))

# LES LECTEURS SONT IMPORTÉS, JAMAIS RECOPIÉS : ceux de la famille des gardes de forme Rust (`P10.20-w` les
# ré-importe déjà depuis `P10.7-f`, qui les tient de `P10.20-c`). Les modules évaluent leur `RACINE` À L'IMPORT,
# par `sys.argv` : on leur passe la racine DÉJÀ calculée ici, pour qu'aucun ne juge un autre arbre.
_ARGV = sys.argv
sys.argv = [_ARGV[0], RACINE]
try:
    from check_a_swallowed_write_is_never_affirmed_as_a_fact import (  # noqa: E402
        ABSORBANTS, ARBRE_FABRIQUE, SOURCES_ATTENDUES, apparier, chaine_detaillee, coupe_tests,
        dans_une_chaine_rust, debut_instruction, fonctions, liaison_sourde, parcours_des_sources,
        portee_englobante, positions_de_coupe, refuser_sur_aveu, sans_commentaires_rust,
        spans_de_chaines_rust, temoins_des_lecteurs_de_forme, temoins_du_lecteur, verdict_de_la_chaine)
    from check_a_read_that_did_not_happen_is_never_served_as_a_fact import (  # noqa: E402
        bras_du_match, if_let_est_le_scrutateur, if_let_sans_branche)
finally:
    sys.argv = _ARGV

DEMON = os.path.join(RACINE, "daemon", "src")
ETIQUETTE = "borne-de-transaction-avalee"

# --- LA POPULATION : LES BORNES -------------------------------------------------------------------
APPEL_SQL = re.compile(r"\.\s*(?:execute_batch|execute)\s*\(")
# Le premier argument est un LITTÉRAL (simple ou brut) ; son premier mot décide du genre.
LITTERAL_DE_TETE = re.compile(r'\s*r?#*"\s*([A-Za-z]+)')
MOTS_DE_BORNE = {"COMMIT": "COMMIT", "END": "COMMIT", "RELEASE": "COMMIT", "BEGIN": "BEGIN", "SAVEPOINT": "BEGIN"}
APPEL_COMMIT_DE_GARDE = re.compile(r"\.\s*commit\s*\(\s*\)")
APPEL_BEGIN_DE_GARDE = re.compile(
    r"\bTxn\s*::\s*begin\s*\(|\.\s*(?:transaction|unchecked_transaction|savepoint)\s*\(\s*\)"
    r"|\.\s*transaction_with_behavior\s*\(")
# Appel nu ou par chemin (`crate::handlers::transaction_validee::valider_la_transaction(`) : seul un identifiant qui
# PROLONGE le nom (`pre_valider_…`) est écarté.
APPEL_DE_JUGE = re.compile(
    r"(?<![\w])(valider_la_transaction|ouvrir_sa_transaction|ouvrir_la_transaction_du_geste|ouvrir_le_garde_du_geste)\s*\(")
GENRE_DU_JUGE = {"valider_la_transaction": "COMMIT", "ouvrir_sa_transaction": "BEGIN",
                 "ouvrir_la_transaction_du_geste": "BEGIN", "ouvrir_le_garde_du_geste": "BEGIN"}

TETE_SOURDE_NUE = re.compile(r"\A\s*let\s+_\s*(?::\s*[^=]*?)?=\s*\Z")
ENVELOPPE_DROP = re.compile(r"\bdrop\s*\(\s*\Z")
MOTIF_ERR = re.compile(r"^Err\s*\(.*\)$", re.S)
CHEMIN_EN_QUEUE = re.compile(r"(?:[A-Za-z_]\w*\s*::\s*)+\Z")

# --- PLANCHER DE NON-DÉGÉNÉRESCENCE (première écriture, 2026-09-24) -------------------------------------
# Il ne réclame pas un volume de code : il constate qu'une LECTURE est cassée. Relevé du jour sur l'arbre :
# 182 bornes sur 41 fichiers (jugées et avalées confondues) ; règle des deux tiers, arrondie en dessous : 121 et 27.
# Il ne monte jamais ; il se re-dérive, date écrite ici, si un lot retire assez de bornes pour le franchir.
PLANCHER_BORNES = 121
PLANCHER_FICHIERS = 27

# ================================================================================================
# L'ENSEMBLE NOMMÉ — LES SITES ENCORE TOLÉRÉS, AVEC LEUR RAISON
# ================================================================================================
# `(fichier, fonction) -> (forme, …)` ; une forme par site (les doublons comptent). Une forme s'écrit
# `<genre> <façon d'avaler>`.
# VIDE depuis le 2026-09-25 (`P10.27-w`). Les deux dernières entrées — `scheduled_reports.rs::report_create` et
# `workflow_actions.rs::workflow_action_create`, `COMMIT let _` — sont RETIRÉES parce que les deux sites sont CORRIGÉS :
# le `COMMIT` passe par `rendre_apres_validation` (503 nommé, transaction fermée, rien d'annoncé avant) et l'identifiant
# servi est celui que la fermeture a lu au pied de l'`INSERT`. Elles étaient tolérées pour une raison qui tenait à un
# AUTRE instrument (l'ensemble de `check_a_swallowed_write_is_never_affirmed_as_a_fact.py`, à son plancher exact) : le
# même geste a retiré leurs entrées là-bas et re-dérivé son plancher. Zéro borne avalée tolérée : toute borne avalée est
# désormais une forme neuve.
SITES_TOLERES = {}


# ================================================================================================
# LA LECTURE
# ================================================================================================
def bornes_du_texte(code, spans):
    """[(genre, debut, ouvrante, juge)] — chaque borne du texte, avec l'index de la parenthèse de son appel.
    `juge` est vrai pour `valider_la_transaction` / `ouvrir_sa_transaction`."""
    out = []
    for m in APPEL_SQL.finditer(code):
        if dans_une_chaine_rust(spans, m.start()):
            continue
        tete = LITTERAL_DE_TETE.match(code, m.end())
        if not tete:
            continue
        genre = MOTS_DE_BORNE.get(tete.group(1).upper())
        if genre:
            out.append((genre, m.start(), m.end() - 1, False))
    for m in APPEL_COMMIT_DE_GARDE.finditer(code):
        if not dans_une_chaine_rust(spans, m.start()):
            out.append(("COMMIT", m.start(), code.index("(", m.start()), False))
    for m in APPEL_BEGIN_DE_GARDE.finditer(code):
        if not dans_une_chaine_rust(spans, m.start()):
            out.append(("BEGIN", m.start(), code.index("(", m.start()), False))
    for m in APPEL_DE_JUGE.finditer(code):
        if dans_une_chaine_rust(spans, m.start()):
            continue
        avant = code[max(0, m.start() - 12):m.start()]
        if re.search(r"\bfn\s+\Z", avant):
            continue  # la définition du juge n'est pas un appel
        out.append((GENRE_DU_JUGE[m.group(1)], m.start(), m.end() - 1, True))
    return sorted(out, key=lambda b: b[1])


def bloc_suivant(code, i):
    """(ouvrante, fermante) du bloc `{…}` qui commence au premier caractère non blanc à partir de `i`, ou None."""
    while i < len(code) and code[i] in " \t\n":
        i += 1
    if i >= len(code) or code[i] != "{":
        return None
    f = apparier(code, i)
    return (i, f) if f > 0 else None


def sans_else(code, fermante):
    return not re.match(r"\s*else\b", code[fermante + 1:fermante + 16])


def recepteur_seul(texte):
    """Vrai quand `texte` (ce qui précède la borne dans l'instruction) n'est qu'un receveur : vide, ou un
    chemin suivi de champs et d'appels fermés — le lecteur `liaison_sourde` le décide, sous une tête fabriquée."""
    return not texte.strip() or liaison_sourde("let _ = " + texte.strip())


def forme_avalee(code, coupes, genre, debut, ouvrante, juge):
    """La façon dont la borne est avalée, ou None quand son `Result` est jugé, propagé ou lié."""
    fin = apparier(code, ouvrante)
    if fin < 0:
        return "PARENTHESE"
    jetons, apres = chaine_detaillee(code, fin)
    verdict, chaine = verdict_de_la_chaine(jetons)
    deb_instr = debut_instruction(coupes, debut)
    # Un appel par CHEMIN (`crate::…::valider_la_transaction(`, `crate::Txn::begin(`) : le chemin fait partie de
    # l'appel, pas du préfixe qui décide de la forme.
    prefixe = CHEMIN_EN_QUEUE.sub("", code[deb_instr:debut])
    sourde = liaison_sourde(prefixe) or bool(TETE_SOURDE_NUE.match(prefixe))
    nue = recepteur_seul(prefixe) and code[apres:apres + 1] == ";"
    derniers = [j[0] for j in jetons]
    if verdict == "absorbe":
        return ("let _." if sourde else ".") + chaine
    if verdict == "scrute":
        dernier = derniers[-1] if derniers else ""
        if sourde:
            return f"let _.{dernier}"
        if nue:
            return f"instruction nue .{dernier}"
        # `if <borne>.is_err() {}` / `if <borne>.is_ok() { … }` sans `else`
        if re.search(r"\bif\b[^;{}]*\Z", prefixe):
            bloc = bloc_suivant(code, apres)
            if bloc and dernier == "is_err" and not code[bloc[0] + 1:bloc[1]].strip():
                return "Err muet"
            if bloc and dernier == "is_ok" and not juge and sans_else(code, bloc[1]):
                return ".is_ok sans else"
        return None
    if verdict != "nu":
        return None
    if sourde:
        return "let _"
    if nue:
        return "instruction nue"
    i_drop = prefixe.rfind("drop(")
    if i_drop >= 0 and ENVELOPPE_DROP.search(prefixe[:i_drop + 5]) and recepteur_seul(prefixe[i_drop + 5:]) \
            and code[apres:apres + 1] == ")":
        return "drop"
    if if_let_sans_branche(code, ouvrante, apres):
        return "if let Ok sans else"
    if if_let_est_le_scrutateur(code, ouvrante, MOTIF_ERR):
        bloc = bloc_suivant(code, apres)
        if bloc and not code[bloc[0] + 1:bloc[1]].strip():
            return "Err muet"
    if re.search(r"\bmatch\b[^;{}]*\Z", prefixe):
        bloc = bloc_suivant(code, apres)
        if bloc:
            for motif, corps in bras_du_match(code, bloc[0]):
                if MOTIF_ERR.match(motif.strip()) and corps.strip().rstrip(",").strip() in ("{}", "()", "{ }"):
                    return "Err muet"
    return None


def analyser(chemin_relatif, texte, journal, aveux_du_lecteur=None):
    """(sites, population) pour UN fichier : sites = [(chemin, ligne, fonction, forme, extrait)], population =
    le nombre de bornes lues (avalées ou non) — c'est elle que le plancher juge."""
    journal_du_lecteur = []
    brut = sans_commentaires_rust(texte, journal_du_lecteur)
    if journal_du_lecteur and aveux_du_lecteur is not None:
        aveux_du_lecteur[chemin_relatif] = [f"ligne {texte.count(chr(10), 0, o) + 1} : {m}"
                                            for m, o in journal_du_lecteur]
    code = coupe_tests(brut)
    fns = fonctions(code)
    coupes = positions_de_coupe(code)
    spans = spans_de_chaines_rust(code)
    sites, population = [], 0
    for genre, debut, ouvrante, juge in bornes_du_texte(code, spans):
        population += 1
        forme = forme_avalee(code, coupes, genre, debut, ouvrante, juge)
        ligne = code.count("\n", 0, debut) + 1
        if forme == "PARENTHESE":
            journal.append(f"{chemin_relatif}:{ligne} — parenthèse d'appel non appariée sur une borne de "
                           "transaction : le lecteur a perdu la fin de l'expression")
            continue
        if forme is None:
            continue
        englobante = portee_englobante(fns, debut)
        if not englobante:
            journal.append(f"{chemin_relatif}:{ligne} — borne avalée HORS de toute fonction : un site sans "
                           "fonction ne peut pas entrer dans l'ensemble")
            continue
        deb = debut_instruction(coupes, debut)
        extrait = " ".join(code[deb:min(len(code), debut + 90)].split())[:140]
        sites.append((chemin_relatif, ligne, englobante[0], f"{genre} {forme}", extrait))
    return sites, population


def fichiers_du_corpus(racine=None):
    """Tous les `.rs` de `daemon/src/`, SOUS-RÉPERTOIRES COMPRIS, artefacts, `tests/` et `tests.rs` ÉLAGUÉS par le
    geste partagé (`parcours_des_sources`, `P11.8-m`). `racine` ne sert qu'aux épreuves sur un arbre FABRIQUÉ."""
    racine = DEMON if racine is None else racine
    if not os.path.isdir(racine):
        return []
    trouves = []
    for dossier, fichiers in parcours_des_sources(racine, hors=("tests", "tests.rs")):
        trouves += [os.path.join(dossier, n) for n in fichiers
                    if n.endswith(".rs") and os.path.isfile(os.path.join(dossier, n))]
    return sorted(trouves)


def decouvrir():
    sites, journal, aveux_du_lecteur, population, fichiers = [], [], {}, 0, set()
    for chemin in fichiers_du_corpus():
        with open(chemin, encoding="utf-8", errors="replace") as fh:
            texte = fh.read()
        rel = os.path.relpath(chemin, RACINE).replace(os.sep, "/")
        s, n = analyser(rel, texte, journal, aveux_du_lecteur)
        sites += s
        population += n
        if n:
            fichiers.add(rel)
    return sites, journal, aveux_du_lecteur, population, fichiers


# ================================================================================================
# LE JUGEMENT CONTRE L'ENSEMBLE NOMMÉ — DANS LES DEUX SENS
# ================================================================================================
def juger_contre_l_ensemble(sites, toleres):
    """[(genre d'écart, fichier, phrase)] — `forme neuve` quand une forme accusée dépasse ce qui est toléré,
    `exemption sans objet` quand une forme tolérée n'est plus accusée autant qu'elle le déclare."""
    vus = {}
    for chemin, ligne, fn, forme, _x in sites:
        vus.setdefault((chemin, fn), {}).setdefault(forme, []).append(ligne)
    ecarts = []
    for cle in sorted(set(vus) | set(toleres)):
        chemin, fn = cle
        admises = {}
        for forme in toleres.get(cle, ()):
            admises[forme] = admises.get(forme, 0) + 1
        vues = vus.get(cle, {})
        for forme in sorted(set(vues) | set(admises)):
            n_vu, n_admis = len(vues.get(forme, [])), admises.get(forme, 0)
            if n_vu > n_admis:
                lignes = ", ".join(str(x) for x in sorted(vues[forme])[n_admis:])
                ecarts.append(("forme neuve", chemin,
                               f"FORME NEUVE — `{fn}` ({chemin}) avale une borne de transaction sous la forme "
                               f"`{forme}` {n_vu} fois pour {n_admis} tolérée(s) ; ligne(s) : {lignes}. Un `COMMIT` "
                               "se juge (`valider_la_transaction`, `rendre_apres_validation`, 503 nommé, rien "
                               "d'annoncé ni de rechargé avant) ; un `BEGIN` se prend ou le geste n'écrit rien "
                               "(`ouvrir_sa_transaction`). Sinon le site entre dans SITES_TOLERES AVEC sa raison."))
            if n_vu < n_admis:
                ecarts.append(("exemption sans objet", chemin,
                               f"EXEMPTION SANS OBJET — `{fn}` ({chemin}) est toléré {n_admis} fois sous la forme "
                               f"`{forme}` et n'est accusé que {n_vu} fois : le site est corrigé, ou il n'existe "
                               "plus, ou cette garde a cessé de le voir. L'entrée se retire à la main EN DISANT "
                               "LEQUEL — un reste qui rétrécit sans le dire passerait pour un défaut fermé."))
    return ecarts


# ================================================================================================
# LES ÉPREUVES — JOUÉES AVANT TOUTE LECTURE DU DÉPÔT, DANS LES DEUX SENS
# ================================================================================================
# Sources FABRIQUÉES, jamais prises sur l'arbre : un témoin adossé à un site réel rougirait le jour où il est corrigé.
def _f(corps):
    return "fn f(conn: &Connection) -> Response {\n" + corps + "\n}\n"


EPREUVES = [
    # --- CE QUI DOIT ÊTRE VU (témoins POSITIFS).
    ("p1 `let _ = conn.execute_batch(\"COMMIT\")`", _f('    let _ = conn.execute_batch("COMMIT");\n    ok()'),
     {"COMMIT let _"}),
    ("p2 `.ok()` sur un BEGIN", _f('    conn.execute_batch("BEGIN IMMEDIATE").ok();\n    ok()'), {"BEGIN .ok"}),
    ("p3 `let _ = tx.commit()`", _f('    let tx = Txn::begin(conn)?;\n    let _ = tx.commit();\n    ok()'),
     {"COMMIT let _"}),
    ("p4 `if let Ok(tx) = Txn::begin(..)` sans else",
     _f('    if let Ok(tx) = Txn::begin(conn) {\n        ecrire(conn)?;\n        tx.commit()?;\n    }\n    ok()'),
     {"BEGIN if let Ok sans else"}),
    ("p5 `if let Err(_) = … COMMIT {}`", _f('    if let Err(_) = conn.execute_batch("COMMIT") {}\n    ok()'),
     {"COMMIT Err muet"}),
    ("p6 instruction nue", _f('    conn.execute_batch("COMMIT");\n    ok()'), {"COMMIT instruction nue"}),
    ("p7 le juge jeté", _f('    let _ = valider_la_transaction(conn);\n    ok()'), {"COMMIT let _"}),
    ("p8 `drop(…)`", _f('    drop(conn.execute_batch("END"));\n    ok()'), {"COMMIT drop"}),
    ("p9 `execute(\"COMMIT\", []).unwrap_or(0)`", _f('    let n = conn.execute("COMMIT", []).unwrap_or(0);\n    ok()'),
     {"COMMIT .unwrap_or"}),
    ("p10 receveur coupé par rustfmt", _f('    let _ = conn\n        .execute_batch("COMMIT");\n    ok()'),
     {"COMMIT let _"}),
    ("p11 bras `Err(_) => {}` d'un match",
     _f('    match conn.execute_batch("COMMIT") {\n        Ok(()) => {}\n        Err(_) => {}\n    }\n    ok()'),
     {"COMMIT Err muet"}),
    ("p12 `let _ = … .is_err()`", _f('    let _ = conn.execute_batch("COMMIT").is_err();\n    ok()'),
     {"COMMIT let _.is_err"}),
    ("p13 `if … .is_ok() { … }` sans else", _f('    if conn.execute_batch("COMMIT").is_ok() {\n        recharger(conn);\n    }\n    ok()'),
     {"COMMIT .is_ok sans else"}),
    ("p14 receveur-appel", _f('    let _ = st.db.lock().execute_batch("COMMIT");\n    ok()'), {"COMMIT let _"}),
    ("p15 littéral brut", _f('    let _ = conn.execute_batch(r"BEGIN IMMEDIATE");\n    ok()'), {"BEGIN let _"}),
    ("p16 juge appelé par son chemin", _f('    let _ = crate::handlers::transaction_validee::valider_la_transaction(conn);\n    ok()'),
     {"COMMIT let _"}),
    ("p17 la forme commune d'une route jetée (`P10.28-d`)",
     _f('    let _ = ouvrir_la_transaction_du_geste(&conn, "j", "g", CAUSE);\n    ecrire(conn)?;\n    ok()'), {"BEGIN let _"}),
    ("p18 le garde de la forme commune jeté (`P10.28-d`)",
     _f('    drop(ouvrir_le_garde_du_geste(&conn, "j", "g", CAUSE));\n    ok()'), {"BEGIN drop"}),
    # --- CE QUI NE DOIT PAS L'ÊTRE (témoins NÉGATIFS).
    ("n1 juge propagé", _f('    valider_la_transaction(conn)?;\n    ok()'), set()),
    ("n2 BEGIN scruté qui refuse", _f('    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {\n        return refus();\n    }\n    ok()'),
     set()),
    ("n3 ROLLBACK hors population", _f('    let _ = conn.execute_batch("ROLLBACK");\n    ok()'), set()),
    ("n4 map_err propagé", _f('    conn.execute_batch("COMMIT").map_err(|e| e.to_string())?;\n    ok()'), set()),
    ("n5 `if let Err(e)` qui parle",
     _f('    if let Err(e) = conn.execute_batch("COMMIT") {\n        let _ = conn.execute_batch("ROLLBACK");\n        return refus(e);\n    }\n    ok()'),
     set()),
    ("n6 cité dans un littéral échappé", _f('    eprintln!("let _ = conn.execute_batch(\\"COMMIT\\")");\n    ok()'), set()),
    ("n6b cité dans un littéral BRUT (les guillemets n'y sont pas échappés)",
     _f('    let doc = r#"let _ = conn.execute_batch("COMMIT");"#;\n    rendre(doc)'), set()),
    ("n7 module de test coupé",
     _f('    ok()') + '#[cfg(test)]\nmod tests {\n    fn t(c: &Connection) { let _ = c.execute_batch("COMMIT"); }\n}\n', set()),
    ("n8 test lié à un nom", _f('    let valide = tx.commit().is_ok();\n    rendre(valide)'), set()),
    ("n9 mot COMMIT hors tête du littéral", _f('    let _ = conn.execute_batch("INSERT INTO t VALUES(\'COMMIT\')");\n    ok()'),
     set()),
    ("n10 test dans une expression", _f('    Some(ok && tx.commit().is_ok())'), set()),
    ("n11 match dont le bras d'erreur refuse",
     _f('    match conn.execute_batch("COMMIT") {\n        Ok(()) => ok(),\n        Err(e) => refus(e),\n    }'), set()),
    ("n12 juge sous `if … is_ok()` (il dit lui-même son refus)",
     _f('    if a < b && ouvrir_sa_transaction(conn, "j", "g").is_ok() {\n        ecrire(conn);\n    }\n    ok()'), set()),
    ("n13 `if let Ok` AVEC else",
     _f('    if let Ok(tx) = Txn::begin(conn) {\n        tx.commit()?;\n    } else {\n        dire();\n    }\n    ok()'), set()),
    ("n14 garde Txn jugé", _f('    match tx.commit() {\n        Ok(()) => ok(),\n        Err(e) => refus(e),\n    }'), set()),
    ("n15 définition du juge", 'fn valider_la_transaction(conn: &Connection) -> rusqlite::Result<()> {\n'
                               '    conn.execute_batch("COMMIT").map_err(|e| e)\n}\n', set()),
    ("n16 la forme commune qui refuse (`P10.28-d`)",
     _f('    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "j", "g", CAUSE) {\n        return refus;\n    }\n    ok()'), set()),
    ("n17 le garde de la forme commune jugé (`P10.28-d`)",
     _f('    let tx = match ouvrir_le_garde_du_geste(&conn, "j", "g", CAUSE) { Ok(t) => t, Err(refus) => return refus };\n    ok()'),
     set()),
]


def epreuve_de_la_descente():
    """Le corpus descend dans les sous-répertoires et élague `tests/` et les artefacts — dans les deux sens, et un
    fichier LISTÉ est aussi ANALYSÉ (sinon la descente ne prouve rien)."""
    errs = []
    source = _f('    let _ = conn.execute_batch("COMMIT");\n    ok()')
    with tempfile.TemporaryDirectory(prefix="plume-borne-avalee-") as racine:
        for rel in ARBRE_FABRIQUE + (("tests", "suite_fabriquee.rs"),):
            chemin = os.path.join(racine, *rel)
            os.makedirs(os.path.dirname(chemin), exist_ok=True)
            with open(chemin, "w", encoding="utf-8") as fh:
                fh.write(source)
        vus = {os.path.relpath(c, racine).replace(os.sep, "/") for c in fichiers_du_corpus(racine)}
        if SOURCES_ATTENDUES - vus:
            errs.append(f"épreuve de la DESCENTE (positif) : {sorted(SOURCES_ATTENDUES - vus)} hors du corpus — la "
                        "découverte est redevenue PLATE")
        if vus - SOURCES_ATTENDUES:
            errs.append(f"épreuve de la DESCENTE (élagage) : {sorted(vus - SOURCES_ATTENDUES)} est entré dans le "
                        "corpus — `tests/` ou un artefact n'est plus élagué par le geste partagé")
    sites, _n = analyser("sous_repertoire_fabrique/mod.rs", source, [])
    if {f for _c, _l, _fn, f, _x in sites} != {"COMMIT let _"}:
        errs.append("épreuve de la DESCENTE (analyse) : un fichier LISTÉ n'est pas ACCUSÉ")
    return errs


def valider_instrument():
    """L'instrument s'éprouve AVANT de rendre un verdict. MUTATIONS JOUÉES le 2026-09-24 sur cette garde, et ce
    qu'elles ont fait tomber (sortie 2 à chaque fois, sauf la dernière) : ignorer les chaînes qui absorbent (p2,
    p9) ; une tête `let _ =` jamais reconnue (p7, p16) ; plus d'`instruction nue` (p6) ; plus de `drop` (p8) ; plus
    d'`if let Ok sans else` (p4) ; plus de bras `Err` muet (p11) ; plus d'`if let Err` muet (p5) ; `.commit()` non lu
    (p3) ; `Txn::begin` non lu (p4) ; `ROLLBACK` accusé (n3, n5) ; les modules de test lus (n7) ; un juge accusé sous
    `is_ok` (n12) ; le jugement de l'ensemble débranché (les trois épreuves d'ensemble) ; le chemin d'appel gardé dans
    le préfixe (p16) ; les juges hors population (p7, p16). CE QUE LES ÉPREUVES NE TIENNENT PAS, MESURÉ : débrancher
    l'exclusion des littéraux ne fait tomber ni n6 ni n6b — le lecteur de bornes d'instruction partagé
    (`positions_de_coupe`), qui ne connaît pas la chaîne BRUTE, désynchronise aussi le préfixe d'une borne citée dans
    un littéral brut, et elle n'est plus lue comme une liaison sourde. L'exclusion est gardée comme défense
    redondante ; aucune épreuve ne prouve qu'elle est nécessaire."""
    errs = []
    try:
        temoins_du_lecteur()
    except AssertionError as e:
        errs.append(f"lecteur partagé (`sans_commentaires_rust`) : {e}")
    try:
        temoins_des_lecteurs_de_forme()
    except AssertionError as e:
        errs.append(f"lecteurs de forme Rust (`apparier`, `fonctions`, `bras_du_match`, …) : {e}")
    if "ok" not in ABSORBANTS or "unwrap_or" not in ABSORBANTS:
        errs.append("vocabulaire des ABSORBANTS importé amputé : `.ok()` / `.unwrap_or(..)` ne seraient plus vus")
    for nom, src, attendues in EPREUVES:
        journal = []
        sites, population = analyser("/epreuve.rs", src, journal)
        vues = {f for _c, _l, _fn, f, _x in sites}
        if journal:
            errs.append(f"épreuve « {nom} » : le lecteur avoue avoir perdu quelque chose ({journal[0]})")
        if vues != attendues:
            errs.append(f"épreuve « {nom} » : formes vues {sorted(vues) or 'aucune'}, attendu {sorted(attendues) or 'aucune'}"
                        + (" — la garde ne voit plus une forme qu'elle nomme" if attendues else
                           " — la garde accuse une forme qui juge, propage, ou n'est pas une borne"))
        if attendues and population < 1:
            errs.append(f"épreuve « {nom} » : aucune borne comptée dans la population")
    errs += epreuve_de_la_descente()
    # --- L'ENSEMBLE NOMMÉ, À SON PROPRE NIVEAU ET DANS LES DEUX SENS.
    faux = [("daemon/src/fabrique.rs", 3, "f", "COMMIT let _", "let _ = conn.execute_batch(..)")]
    if {g for g, _f2, _p in juger_contre_l_ensemble(faux, {})} != {"forme neuve"}:
        errs.append("épreuve de l'ENSEMBLE (site neuf) : un site hors ensemble ne rougit plus")
    if {g for g, _f2, _p in juger_contre_l_ensemble([], {("daemon/src/fabrique.rs", "f"): ("COMMIT let _",)})} \
            != {"exemption sans objet"}:
        errs.append("épreuve de l'ENSEMBLE (site corrigé encore listé) : une entrée sans objet ne rougit plus")
    if juger_contre_l_ensemble(faux, {("daemon/src/fabrique.rs", "f"): ("COMMIT let _",)}):
        errs.append("épreuve de l'ENSEMBLE (accord) : un site exactement toléré produit un écart")
    change = [("daemon/src/fabrique.rs", 3, "f", "BEGIN let _", "…")]
    if {g for g, _f2, _p in juger_contre_l_ensemble(change, {("daemon/src/fabrique.rs", "f"): ("COMMIT let _",)})} \
            != {"forme neuve", "exemption sans objet"}:
        errs.append("épreuve de l'ENSEMBLE (forme changée) : un site toléré sous une forme, réécrit sous une autre, "
                    "passe sans un mot")
    return errs


# ================================================================================================
# LE VERDICT
# ================================================================================================
def ce_qui_n_est_pas_tenu():
    print(f"\n[{ETIQUETTE}] CE QU'ELLE NE TIENT PAS :\n"
          "  * un `Result` de borne LIÉ à un nom puis jeté plus bas (`let r = conn.execute_batch(\"COMMIT\");` et `r` "
          "jamais lu), ou rendu à un appelant qui le jette : la garde lit la forme au SITE, pas le devenir d'un nom.\n"
          "  * un bras `Err` qui PARLE sans fermer la transaction (`Err(e) => eprintln!(..)` après un `COMMIT` refusé, "
          "sans `ROLLBACK`) : elle ne juge que le bras VIDE. La transaction peut alors rester ouverte — c'est la sonde "
          "de `P10.27-g` (tick de détection) qui le voit à l'exécution, pas cette garde.\n"
          "  * `ROLLBACK` : hors population par décision (son échec après un refus n'est pas une information) ; un "
          "`ROLLBACK` avalé qui LAISSE la transaction ouverte n'est vu ici que si le geste relit `is_autocommit()`.\n"
          "  * une borne dont le SQL n'est pas un LITTÉRAL en tête d'appel (constante, `format!`) : elle n'entre pas "
          "dans la population.\n"
          "  * les modules `#[cfg(test)]` en ligne sont coupés à partir du premier (lecteur partagé `coupe_tests`) : du "
          "code de production écrit APRÈS un module de test du même fichier ne serait pas lu.\n"
          "  * elle ne prouve rien à l'exécution : elle constate qu'une forme est absente, jamais qu'un `COMMIT` refusé "
          "rend bien un 503 (ce sont les témoins `cjds_`, `cjcg_`, `cjgi_`, `rncc_`, `brev_` qui le jouent).")


def main():
    errs = valider_instrument()
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print(f"\n[{ETIQUETTE}] l'INSTRUMENT est faux : aucun verdict n'est rendu.")
        ce_qui_n_est_pas_tenu()
        return 2
    cargo = os.path.join(RACINE, "daemon", "Cargo.toml")
    manifeste = open(cargo, encoding="utf-8", errors="replace").read() if os.path.isfile(cargo) else ""
    if not re.search(r"^\s*rusqlite\s*=", manifeste, re.M):
        print("::error::aucun `rusqlite` dans daemon/Cargo.toml : les bornes que cette garde lit n'ont plus "
              "d'ancrage. Elle REFUSE DE CONCLURE.")
        ce_qui_n_est_pas_tenu()
        return 2

    sites, journal, aveux_du_lecteur, population, fichiers = decouvrir()
    if aveux_du_lecteur and refuser_sur_aveu(ETIQUETTE, aveux_du_lecteur, "Rust"):
        ce_qui_n_est_pas_tenu()
        return 2
    if journal:
        for a in journal:
            print(f"::error::{a}")
        print(f"\n[{ETIQUETTE}] REFUS DE CONCLURE — le lecteur avoue avoir perdu une expression.")
        ce_qui_n_est_pas_tenu()
        return 2
    if population < PLANCHER_BORNES or len(fichiers) < PLANCHER_FICHIERS:
        print(f"::error::{population} borne(s) lue(s) sur {len(fichiers)} fichier(s), planchers "
              f"{PLANCHER_BORNES}/{PLANCHER_FICHIERS} (dérivés le 2026-09-24 : 182 bornes sur 41 fichiers, règle des "
              "deux tiers). La lecture est cassée, ou un lot a retiré assez de bornes pour que les planchers doivent "
              "être RE-DÉRIVÉS, date écrite. La garde REFUSE DE CONCLURE plutôt que de rendre vert en étant aveugle.")
        ce_qui_n_est_pas_tenu()
        return 2

    for chemin, ligne, fn, forme, extrait in sorted(sites):
        print(f"::notice file={chemin},line={ligne}::`{fn}` avale une borne de transaction (`{forme}`) — `{extrait}`")
    ecarts = juger_contre_l_ensemble(sites, SITES_TOLERES)
    print(f"\n[{ETIQUETTE}] POPULATION du jour : {population} borne(s) de transaction sur {len(fichiers)} fichier(s) de "
          f"daemon/src (`tests/` élagué) ; {len(sites)} avalée(s), {sum(len(v) for v in SITES_TOLERES.values())} "
          "tolérée(s) par l'ensemble nommé.")
    if ecarts:
        for _g, chemin, phrase in ecarts:
            print(f"::error file={chemin}::{phrase}")
        print(f"::error::{len(ecarts)} écart(s) entre l'arbre et l'ensemble nommé ; il se corrige à la main, AVEC la "
              "raison. Zéro reste atteignable.")
        ce_qui_n_est_pas_tenu()
        return 1
    print(f"[{ETIQUETTE}] l'ensemble nommé est EXACTEMENT ce que l'arbre porte — ni forme neuve, ni exemption sans "
          "objet. CE QUE CE VERT NE DIT PAS : les sites tolérés sont des DÉFAUTS CONNUS (un `COMMIT` avalé peut laisser "
          "l'écrivain bloqué) ; le vert dit seulement qu'AUCUNE borne avalée neuve n'est entrée.")
    ce_qui_n_est_pas_tenu()
    return 0


if __name__ == "__main__":
    sys.exit(main())
