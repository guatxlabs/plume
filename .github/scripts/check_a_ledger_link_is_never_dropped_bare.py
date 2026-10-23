#!/usr/bin/env python3
"""Un maillon du registre n'est jamais jeté par un appel nu — garde de CI (`P10.31-u`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`ledger_append` (daemon/src/ledger.rs) rend un `MaillonDeRegistre` : `Inscrit`, ou `NonInscrit(cause)` quand la
ligne n'est pas entrée au registre tamper-evident. Écrit comme une instruction seule — `ledger_append(conn, …);` —
l'issue est jetée, et ce qui suit (réponse servie, bilan de tick, corps de courriel rendu) affirme une trace qui
peut manquer. Le type n'est pas `#[must_use]` (une cinquantaine d'appels de test le jettent à dessein) : le
compilateur ne dit rien.

MESURÉ le 2026-10-23 sur 1011ec9f : onze appels nus de production — `ingest/minio.rs` (`mail_body` lisait le corps
d'un courriel AVANT sa trace, et le servait même quand le registre la refusait), `handlers/caseops.rs`
(`case.unlink`), `handlers/incidents.rs` (`case.runbook_attach`), quatre dans `handlers/playbooks.rs`, quatre traces
de démarrage dans `server/mod.rs`. Le lot qui écrit cette garde les consomme tous.

LA RÈGLE, ÉCRITE
----------------
Population : chaque appel de `ledger_append(` ou `control_ledger_append(` (chemin `crate::ledger::` admis) de
`daemon/src/`, sous-répertoires compris, `tests/`, `tests.rs` et les modules `#[cfg(test)]` en fin de fichier élagués,
commentaires dépouillés, littéraux exclus, déclarations (`fn ledger_append(`) exclues. Un appel est NU quand :
  * il ouvre son instruction (rien entre la borne d'instruction précédente — `;`, `{`, `}` — et lui), ou n'est
    précédé que d'une liaison muette `let _ =` / `let _nom =` ;
  * ET l'instruction se termine par `;` juste après l'appel et sa chaîne de méthodes ;
  * ET cette chaîne n'est pas exactement `.laisser_a_l_aveu_de_la_primitive()` — le geste NOMMÉ, cherchable, par
    lequel un site sans surface laisse la perte à l'aveu que la primitive écrit déjà sur la sortie d'erreur.
Correction vague AG : sont NUS aussi l'affectation au joker `_ = …;`, `drop(…)` / `mem::drop(…)` /
`std::mem::drop(…)` en instruction, et l'appel qui est la valeur d'un bras de `match` ou d'une branche d'`if … else`
quand ce `match` ou cet `if` est lui-même une instruction jetée (`;`, à vide ou sous liaison muette) — la remontée
traverse les bras imbriqués.
Tout le reste est CONSOMMÉ : `let maillon = …`, `match …`, `if let … = …`, argument (`Ok(…)`), valeur de queue
d'un bloc ou d'un bras.

POURQUOI UN ENSEMBLE NOMMÉ, JUGÉ DANS LES DEUX SENS, ET POURQUOI IL EST VIDE
---------------------------------------------------------------------------
`SITES_ADMIS` est un ensemble de sites `(fichier, fonction) -> nombre d'appels nus admis`, jamais un compte global :
un site corrigé et un site neuf le même jour ne se compensent pas. VIDE le jour de l'écriture. Un appel nu neuf
rougit ; une entrée qui n'est plus accusée rougit aussi (exemption sans objet).

CE QUE CE VERT NE DIRA PAS : voir `ce_qui_n_est_pas_tenu()`.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

RACINE = (os.path.abspath(sys.argv[1]) if len(sys.argv) > 1
          else os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))

# LES LECTEURS SONT IMPORTÉS, JAMAIS RECOPIÉS (même geste que `check_an_inserted_id_is_read_at_the_foot_of_its_insert.py`).
# Les modules évaluent leur `RACINE` À L'IMPORT, par `sys.argv` : on leur passe la racine DÉJÀ calculée ici.
_ARGV = sys.argv
sys.argv = [_ARGV[0], RACINE]
try:
    from check_a_transaction_boundary_is_never_swallowed import (  # noqa: E402
        ARBRE_FABRIQUE, SOURCES_ATTENDUES, apparier, coupe_tests, dans_une_chaine_rust, fichiers_du_corpus,
        fonctions, portee_englobante, refuser_sur_aveu, sans_commentaires_rust, spans_de_chaines_rust,
        temoins_des_lecteurs_de_forme, temoins_du_lecteur)
    from check_a_swallowed_write_is_never_affirmed_as_a_fact import (  # noqa: E402
        chaine_detaillee, debut_instruction, positions_de_coupe)
finally:
    sys.argv = _ARGV

DEMON = os.path.join(RACINE, "daemon", "src")
ETIQUETTE = "maillon-du-registre-jamais-jete"

# --- LA POPULATION : LES APPELS DES PRIMITIVES QUI RENDENT UN MAILLON -----------------------------------------
# Un APPEL : le nom n'est prolongé ni à gauche (`fn `, un identifiant plus long) ni à droite. Le chemin `a::b::` qui
# le précède est rattaché à l'appel (l'instruction commence au chemin).
APPEL = re.compile(r"(?<![\w])((?:[A-Za-z_]\w*\s*::\s*)*)(control_ledger_append|ledger_append)\s*\(")
DECLARATION = re.compile(r"\bfn\s+\Z")
# `let _ =`, `let _nom =`, `let _: T =`, et l'affectation au joker `_ =` (correction vague AG : le même geste que
# `let _ =`, écrit sans `let`).
LIAISON_MUETTE = re.compile(r"\A\s*(?:let\s+_\w*\s*(?::\s*[^=]*?)?|_\s*)=\s*\Z")
# `drop(…)`, `mem::drop(…)`, `std::mem::drop(…)`, `core::mem::drop(…)` — sous une liaison muette ou non.
JET_PAR_DROP = re.compile(r"\A\s*(?:(?:let\s+_\w*\s*(?::\s*[^=]*?)?|_\s*)=\s*)?"
                          r"(?:(?:std|core)\s*::\s*)?(?:mem\s*::\s*)?drop\s*\(\s*\Z")
MOT_MATCH = re.compile(r"(?<![\w])match\b")
MOT_IF = re.compile(r"(?<![\w])if\b")
MOT_ELSE_EN_TETE = re.compile(r"\A\s*else\b")
PROFONDEUR_DE_REMONTEE = 12
GESTE_NOMME = "laisser_a_l_aveu_de_la_primitive"

# --- PLANCHER DE NON-DÉGÉNÉRESCENCE (première écriture, 2026-10-23) -------------------------------------------
# Il ne réclame pas un volume de code : il constate qu'une LECTURE est cassée. Relevé du jour sur l'arbre corrigé :
# 78 appels sur 20 fichiers ; règle des deux tiers des gardes sœurs, arrondie en dessous : 52 et 13. Il ne monte
# jamais ; il se re-dérive, date écrite ici, si un lot retire assez d'appels pour le franchir.
PLANCHER_APPELS = 52
PLANCHER_FICHIERS = 13

# ================================================================================================
# L'ENSEMBLE NOMMÉ — LES APPELS NUS ENCORE ADMIS, AVEC LEUR RAISON
# ================================================================================================
# `(fichier, fonction) -> nombre d'appels nus admis`. VIDE le jour de l'écriture : les onze appels nus de l'arbre
# d'avant sont consommés ou laissés nommément à l'aveu de la primitive par le lot qui écrit cette garde.
SITES_ADMIS = {}


# ================================================================================================
# LA LECTURE
# ================================================================================================
def _apres_espaces(code, k):
    while k < len(code) and code[k] in " \t\r\n":
        k += 1
    return k


def _accolade_englobante(code, coupes, i):
    """Index de la `{` (hors chaîne) qui contient `i` au plus près, -1 s'il n'y en a pas."""
    profondeur = 0
    for c in reversed([x for x in coupes if x < i]):
        if code[c] == "}":
            profondeur += 1
        elif code[c] == "{":
            if profondeur == 0:
                return c
            profondeur -= 1
    return -1


def _jete_par_l_instruction(code, coupes, debut, fermante, profondeur):
    """L'expression qui commence en `debut` et dont le dernier caractère est en `fermante` (un appel, un `match`, une
    chaîne `if … else …`) rend un maillon : 'nu' si elle est jetée — instruction terminée par `;` ouverte à vide ou
    par une liaison muette, sans le geste nommé —, ou si elle est la valeur d'un bras (ou d'une branche) d'un `match`
    (ou d'un `if`) lui-même jeté ; None si la valeur voyage."""
    if profondeur > PROFONDEUR_DE_REMONTEE:
        return ("PERDU", "remontée des bras trop profonde")
    jetons, fin = chaine_detaillee(code, fermante)
    k = _apres_espaces(code, fin)
    noms = [nom for nom, _j, _a1, _a2 in jetons]
    prefixe = code[debut_instruction(coupes, debut):debut]
    if k < len(code) and code[k] == ";":
        if prefixe.strip() and not LIAISON_MUETTE.match(prefixe):
            return None
        if noms == [GESTE_NOMME] and not LIAISON_MUETTE.match(prefixe):
            a1, a2 = jetons[0][2], jetons[0][3]
            if a1 >= 0 and not code[a1:a2].strip():
                return None
        return "nu"
    if k < len(code) and code[k] == ")" and not jetons and JET_PAR_DROP.match(prefixe):
        k2 = _apres_espaces(code, k + 1)
        return "nu" if k2 < len(code) and code[k2] == ";" else None
    if jetons or k >= len(code) or code[k] not in ",}":
        return None  # argument, opérande, valeur liée : la valeur voyage
    if prefixe.strip() and not prefixe.rstrip().endswith("=>"):
        return None  # pas une valeur de queue ni un bras
    return _remonter_d_une_queue(code, coupes, debut, profondeur + 1)


def _remonter_d_une_queue(code, coupes, debut, profondeur):
    """`debut` ouvre la valeur de queue d'un bloc ou la valeur d'un bras : qui la reçoit ?"""
    ouvrante = _accolade_englobante(code, coupes, debut)
    if ouvrante < 0:
        return None
    fermante = apparier(code, ouvrante)
    if fermante < 0:
        return ("PERDU", "accolade non appariée")
    tete_debut = debut_instruction(coupes, ouvrante)
    tete = code[tete_debut:ouvrante]
    if tete.rstrip().endswith("=>"):
        # bloc-bras : le bloc entier est la valeur du bras (aucune virgule n'est exigée après un bloc-bras).
        return _remonter_d_une_queue(code, coupes, ouvrante, profondeur + 1)
    m = MOT_MATCH.search(tete)
    if m:
        return _jete_par_l_instruction(code, coupes, tete_debut + m.start(), fermante, profondeur)
    # chaîne `if … { } else if … { } else { }` : remonter à son `if`, descendre à son dernier bloc.
    o = ouvrante
    for _ in range(64):
        t0 = debut_instruction(coupes, o)
        t = code[t0:o]
        if MOT_ELSE_EN_TETE.match(t):
            precedente = t0 - 1
            if precedente < 0 or code[precedente] != "}":
                return None
            o = _accolade_englobante(code, coupes, precedente)
            if o < 0:
                return ("PERDU", "accolade non appariée")
            continue
        mi = MOT_IF.search(t)
        if not mi:
            return None  # corps de fonction, fermeture, boucle, bloc nu : la valeur voyage ou n'est pas lue ici
        debut_if = t0 + mi.start()
        break
    else:
        return ("PERDU", "chaîne if/else trop longue")
    c = fermante
    for _ in range(64):
        k = _apres_espaces(code, c + 1)
        if not re.match(r"else\b", code[k:k + 5]):
            break
        suivante = next((x for x in coupes if x > k and code[x] == "{"), -1)
        if suivante < 0:
            return ("PERDU", "branche else sans bloc")
        c = apparier(code, suivante)
        if c < 0:
            return ("PERDU", "accolade non appariée")
    return _jete_par_l_instruction(code, coupes, debut_if, c, profondeur)


def forme_de_l_appel(code, coupes, debut_appel, ouvrante):
    """'nu' quand l'appel dont le chemin commence en `debut_appel` et la parenthèse s'ouvre en `ouvrante` jette son
    maillon, None quand il est consommé ; ('PERDU', raison) quand le lecteur ne peut pas conclure."""
    fermante = apparier(code, ouvrante)
    if fermante < 0:
        return ("PERDU", "parenthèse d'appel non appariée")
    return _jete_par_l_instruction(code, coupes, debut_appel, fermante, 0)


def analyser(chemin_relatif, texte, journal, aveux_du_lecteur=None):
    """(sites, population) pour UN fichier : sites = [(chemin, ligne, fonction, extrait)]."""
    journal_du_lecteur = []
    brut = sans_commentaires_rust(texte, journal_du_lecteur)
    if journal_du_lecteur and aveux_du_lecteur is not None:
        aveux_du_lecteur[chemin_relatif] = [f"ligne {texte.count(chr(10), 0, o) + 1} : {m}"
                                            for m, o in journal_du_lecteur]
    code = coupe_tests(brut)
    spans = spans_de_chaines_rust(code)
    coupes = positions_de_coupe(code)
    fns = fonctions(code)
    sites, population = [], 0
    for m in APPEL.finditer(code):
        if dans_une_chaine_rust(spans, m.start()):
            continue
        if DECLARATION.search(code, max(0, m.start() - 8), m.start()):
            continue
        population += 1
        ligne = code.count("\n", 0, m.start(2)) + 1
        forme = forme_de_l_appel(code, coupes, m.start(), m.end() - 1)
        if isinstance(forme, tuple):
            journal.append(f"{chemin_relatif}:{ligne} — {forme[1]} : le lecteur ne peut pas conclure sur cet appel")
            continue
        if forme is None:
            continue
        englobante = portee_englobante(fns, m.start())
        debut_ligne = code.rfind("\n", 0, m.start()) + 1
        fin_ligne = code.find("\n", m.end())
        extrait = " ".join(code[debut_ligne:fin_ligne if fin_ligne >= 0 else len(code)].split())[:140]
        sites.append((chemin_relatif, ligne, englobante[0] if englobante else "?", extrait))
    return sites, population


def decouvrir():
    sites, journal, aveux_du_lecteur, population, fichiers = [], [], {}, 0, set()
    for chemin in fichiers_du_corpus(DEMON):
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
def juger_contre_l_ensemble(sites, admis):
    """[(genre d'écart, fichier, phrase)] — `appel nu neuf` quand un site porte plus d'appels nus qu'admis,
    `exemption sans objet` quand un site admis en porte moins qu'il ne le déclare."""
    vus = {}
    for chemin, ligne, fn, _x in sites:
        vus.setdefault((chemin, fn), []).append(ligne)
    ecarts = []
    for cle in sorted(set(vus) | set(admis)):
        chemin, fn = cle
        n_vu, n_admis = len(vus.get(cle, [])), admis.get(cle, 0)
        if n_vu > n_admis:
            lignes = ", ".join(str(x) for x in sorted(vus[cle])[n_admis:])
            ecarts.append(("appel nu neuf", chemin,
                           f"APPEL NU — `{fn}` ({chemin}) jette le maillon de registre de {n_vu} appel(s) pour {n_admis} "
                           f"admis ; ligne(s) : {lignes}. La trace peut manquer pendant que la suite l'affirme : lire "
                           "l'issue (`cause_de_non_inscription`, `match`), ou, sur un site sans aucune surface, la "
                           "laisser NOMMÉMENT par `.laisser_a_l_aveu_de_la_primitive()`. Sinon le site entre dans "
                           "SITES_ADMIS AVEC sa raison."))
        if n_vu < n_admis:
            ecarts.append(("exemption sans objet", chemin,
                           f"EXEMPTION SANS OBJET — `{fn}` ({chemin}) est admis pour {n_admis} appel(s) nu(s) et n'en "
                           f"porte que {n_vu} : le site est corrigé, ou il n'existe plus, ou cette garde a cessé de le "
                           "voir. L'entrée se retire à la main EN DISANT LEQUEL."))
    return ecarts


# ================================================================================================
# LES ÉPREUVES — JOUÉES AVANT TOUTE LECTURE DU DÉPÔT, DANS LES DEUX SENS
# ================================================================================================
# Sources FABRIQUÉES, jamais prises sur l'arbre : un témoin adossé à un site réel rougirait le jour où il est corrigé.
def _f(corps):
    return "fn f(conn: &Connection) -> Response {\n" + corps + "\n}\n"


EPREUVES = [
    # --- CE QUI DOIT ÊTRE VU (témoins POSITIFS) : nombre d'appels nus attendus.
    ("p1 instruction seule (la forme mesurée)", _f('    ledger_append(conn, "k", "d");\n    ok()'), 1),
    ("p2 sur plusieurs lignes", _f('    ledger_append(&conn, "k",\n        &format!("a {b}"));\n    ok()'), 1),
    ("p3 liaison muette `let _ =`", _f('    let _ = ledger_append(conn, "k", "d");\n    ok()'), 1),
    ("p4 liaison muette nommée `let _m =`", _f('    let _m = ledger_append(conn, "k", "d");\n    ok()'), 1),
    ("p5 chemin `crate::ledger::`", _f('    crate::ledger::ledger_append(conn, "k", "d");\n    ok()'), 1),
    ("p6 primitive du plan de contrôle", _f('    control_ledger_append(&st, "k", "a", "", "d");\n    ok()'), 1),
    ("p7 après un bloc fermé", _f('    if x { y(); }\n    ledger_append(conn, "k", "d");\n    ok()'), 1),
    ("p8 issue lue puis jetée", _f('    ledger_append(conn, "k", "d").cause_de_non_inscription();\n    ok()'), 1),
    ("p9 geste nommé sous une liaison muette", _f('    let _ = ledger_append(conn, "k", "d").laisser_a_l_aveu_de_la_primitive();\n    ok()'), 1),
    ("p10 geste nommé suivi d'un autre jeton", _f('    ledger_append(conn, "k", "d").laisser_a_l_aveu_de_la_primitive().clone();\n    ok()'), 1),
    ("p11 deux appels nus dans un bras de bloc", _f('    match x {\n        A => {\n            ledger_append(conn, "a", "d");\n'
                                                      '            ledger_append(conn, "b", "d");\n        }\n        _ => {}\n    }\n    ok()'), 2),
    ("p12 parenthèse dans un littéral de l'appel", _f('    ledger_append(conn, "k", "a ) b");\n    ok()'), 1),
    # Correction vague AG (formes relevées par la vérification : vues 0 avant cette correction).
    ("p13 affectation au joker `_ =`", _f('    _ = ledger_append(conn, "k", "d");\n    ok()'), 1),
    ("p14 `drop(…)`", _f('    drop(ledger_append(conn, "k", "d"));\n    ok()'), 1),
    ("p15 `std::mem::drop(…)`", _f('    std::mem::drop(crate::ledger::ledger_append(conn, "k", "d"));\n    ok()'), 1),
    ("p16 `match` en instruction, bras nus", _f('    match r {\n        Ok(_) => ledger_append(conn, "a", "d"),\n'
                                                '        Err(_) => ledger_append(conn, "b", "d"),\n    };\n    ok()'), 2),
    ("p17 `if`/`else` en instruction", _f('    if x {\n        ledger_append(conn, "a", "d")\n    } else if y {\n'
                                           '        ledger_append(conn, "b", "d")\n    } else {\n        ledger_append(conn, "c", "d")\n    };\n    ok()'), 3),
    ("p18 bloc-bras d'un `match` en instruction", _f('    match r {\n        Ok(_) => {\n            x();\n            ledger_append(conn, "a", "d")\n'
                                                     '        }\n        Err(_) => M::Inscrit,\n    };\n    ok()'), 1),
    ("p19 `let _ = match`", _f('    let _ = match r {\n        Ok(_) => ledger_append(conn, "a", "d"),\n        Err(_) => M::Inscrit,\n    };\n    ok()'), 1),
    ("p20 `match` imbriqué dans un `if` en instruction", _f('    if x {\n        match r {\n            A => ledger_append(conn, "a", "d"),\n'
                                                            '            _ => M::Inscrit,\n        }\n    } else {\n        M::Inscrit\n    };\n    ok()'), 1),
    # --- CE QUI NE DOIT PAS ÊTRE VU (témoins NÉGATIFS) : aucun appel nu.
    ("n1 liaison nommée", _f('    let maillon = ledger_append(conn, "k", "d");\n    servir(maillon)'), 0),
    ("n2 sujet d'un match", _f('    match ledger_append(conn, "k", "d") {\n        M::Inscrit => a(),\n        M::NonInscrit(c) => b(c),\n    }'), 0),
    ("n3 argument", _f('    Ok(ledger_append(conn, "k", "d"))'), 0),
    ("n4 valeur de queue", _f('    x();\n    ledger_append(conn, "k", "d")'), 0),
    ("n5 bras de match", _f('    let m = match r {\n        Ok(n) => ledger_append(conn, "a", "d"),\n        Err(e) => ledger_append(conn, "b", "d"),\n    };\n    m'), 0),
    ("n6 geste nommé", _f('    ledger_append(conn, "k", "d").laisser_a_l_aveu_de_la_primitive();\n    ok()'), 0),
    ("n7 geste nommé sur plusieurs lignes", _f('    ledger_append(conn, "k",\n        &format!("{a}"))\n        .laisser_a_l_aveu_de_la_primitive();\n    ok()'), 0),
    ("n8 `if let` sur l'issue", _f('    if let Some(c) = ledger_append(conn, "k", "d").cause_de_non_inscription() {\n        dire(c);\n    }'), 0),
    ("n9 compteur entier", _f('    abandonnes += u32::from(ledger_append(conn, "k", "d").cause_de_non_inscription().is_some());'), 0),
    ("n10 déclaration de la primitive", 'pub(crate) fn ledger_append(conn: &Connection, kind: &str, detail: &str) -> MaillonDeRegistre {\n    MaillonDeRegistre::Inscrit\n}\n', 0),
    ("n11 nom dans un littéral", _f('    dire("ledger_append(conn, x);");\n    ok()'), 0),
    ("n12 nom dans un commentaire", _f('    // ledger_append(conn, "k", "d");\n    ok()'), 0),
    ("n13 module de test en fin de fichier", _f('    ok()') + '#[cfg(test)]\nmod tests {\n    fn t() {\n        ledger_append(&c, "k", "d");\n    }\n}\n', 0),
    ("n14 nom prolongé", _f('    mon_ledger_append(conn, "k", "d");\n    ledger_append_bis(conn);\n    ok()'), 0),
    ("n15 `match` lié par un nom", _f('    let m = match r {\n        Ok(_) => ledger_append(conn, "a", "d"),\n        Err(_) => M::Inscrit,\n    };\n    servir(m)'), 0),
    ("n16 `if`/`else` en valeur de queue", _f('    if x {\n        ledger_append(conn, "a", "d")\n    } else {\n        ledger_append(conn, "b", "d")\n    }'), 0),
    ("n17 `match` en argument", _f('    servir(match r {\n        A => ledger_append(conn, "a", "d"),\n        _ => M::Inscrit,\n    });\n    ok()'), 0),
    ("n18 affectation à un nom", _f('    maillon = ledger_append(conn, "k", "d");\n    servir(maillon)'), 0),
    ("n19 `drop` d'autre chose", _f('    drop(garde);\n    let m = ledger_append(conn, "k", "d");\n    servir(m)'), 0),
    ("n20 `match` en instruction dont les bras lisent l'issue", _f('    match r {\n        Ok(_) => dire(ledger_append(conn, "a", "d")),\n'
                                                                   '        Err(_) => {}\n    };\n    ok()'), 0),
    ("n21 fermeture qui rend le maillon", _f('    let f = || {\n        ledger_append(conn, "a", "d")\n    };\n    servir(f())'), 0),
]


def epreuve_de_la_descente():
    """Le corpus descend dans les sous-répertoires et élague `tests/` et les artefacts — dans les deux sens, et un
    fichier LISTÉ est aussi ANALYSÉ (sinon la descente ne prouve rien)."""
    errs = []
    source = _f('    ledger_append(conn, "k", "d");\n    ok()')
    with tempfile.TemporaryDirectory(prefix="plume-maillon-nu-") as racine:
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
    if len(sites) != 1:
        errs.append("épreuve de la DESCENTE (analyse) : un fichier LISTÉ n'est pas ACCUSÉ")
    return errs


def valider_instrument():
    """L'instrument s'éprouve AVANT de rendre un verdict, dans les deux sens (positifs `p*`, négatifs `n*`). HUIT
    MUTATIONS JOUÉES le 2026-10-23 sur cette garde, chacune seule, et ce qu'elles ont fait tomber (sortie 2 à chaque
    fois) : la liaison muette plus reconnue (p3) ; toute chaîne de méthodes admise (p8) ; les littéraux lus (n11) ; les
    modules de test lus (n13) ; la déclaration comptée (n10) ; la valeur de queue tenue pour nue (n4) ; le jugement de
    l'ensemble débranché (épreuve d'ensemble « site neuf ») ; le chemin `a::b::` plus rattaché à l'appel (p5). Correction
    vague AG : p13 à p20 étaient vues 0 par la version d'avant (sondes du vérificateur E1 à E5) ; sept mutations
    jouées, chacune sortie 2 : joker `_ =` oublié (p13), `drop` oublié (p14, p15), remontée coupée (p16 à p18),
    bloc-bras qui exige une virgule (p18), `if` ignoré (p17, p20), tête liée ignorée (n1, n5, n15), `else` non remonté
    (p17) ; et trois formes neuves posées sur un site réel (`_ =`, `std::mem::drop`, `match` en instruction) : code 1,
    site nommé. Et onze
    mutants de l'ARBRE, un par site corrigé (le correctif retiré, l'appel redevenu nu) : code 1, le site nommé seul."""
    errs = []
    try:
        temoins_du_lecteur()
    except AssertionError as e:
        errs.append(f"lecteur partagé (`sans_commentaires_rust`) : {e}")
    try:
        temoins_des_lecteurs_de_forme()
    except AssertionError as e:
        errs.append(f"lecteurs de forme Rust (`apparier`, `fonctions`, …) : {e}")
    for nom, src, attendus in EPREUVES:
        journal = []
        sites, population = analyser("/epreuve.rs", src, journal)
        if journal:
            errs.append(f"épreuve « {nom} » : le lecteur avoue avoir perdu quelque chose ({journal[0]})")
        if len(sites) != attendus:
            errs.append(f"épreuve « {nom} » : {len(sites)} appel(s) nu(s) vu(s), attendu {attendus}"
                        + (" — la garde ne voit plus une forme qu'elle nomme" if attendus else
                           " — la garde accuse un maillon consommé, ou ce qui n'est pas un appel"))
        if nom.startswith(("n10", "n11", "n12", "n13", "n14")) and population:
            errs.append(f"épreuve « {nom} » : {population} appel(s) compté(s) là où il n'y en a aucun")
        if nom.startswith(("p", "n1 ", "n2", "n3", "n4", "n5", "n6", "n7", "n8", "n9 ")) and population < 1:
            errs.append(f"épreuve « {nom} » : aucun appel compté dans la population")
    errs += epreuve_de_la_descente()
    # --- L'ENSEMBLE NOMMÉ, À SON PROPRE NIVEAU ET DANS LES DEUX SENS.
    faux = [("daemon/src/fabrique.rs", 3, "f", "…")]
    if {g for g, _f2, _p in juger_contre_l_ensemble(faux, {})} != {"appel nu neuf"}:
        errs.append("épreuve de l'ENSEMBLE (site neuf) : un appel nu hors ensemble ne rougit plus")
    if {g for g, _f2, _p in juger_contre_l_ensemble([], {("daemon/src/fabrique.rs", "f"): 1})} != {"exemption sans objet"}:
        errs.append("épreuve de l'ENSEMBLE (site corrigé encore listé) : une entrée sans objet ne rougit plus")
    if juger_contre_l_ensemble(faux, {("daemon/src/fabrique.rs", "f"): 1}):
        errs.append("épreuve de l'ENSEMBLE (accord) : un site exactement admis produit un écart")
    return errs


# ================================================================================================
# LE VERDICT
# ================================================================================================
def ce_qui_n_est_pas_tenu():
    print(f"\n[{ETIQUETTE}] CE QU'ELLE NE TIENT PAS :\n"
          "  * un maillon CONSOMMÉ n'est pas un maillon BIEN consommé : `let maillon = …` suivi d'aucune lecture, un "
          "`match` dont les deux bras rendent la même chose, une valeur de queue jetée par l'appelant de la fonction ne "
          "sont pas départagés. Ce sont les témoins de chaque site qui le tiennent.\n"
          "  * le geste nommé `.laisser_a_l_aveu_de_la_primitive()` est ADMIS partout : la garde ne juge pas que le site "
          "n'a vraiment aucune surface où porter l'aveu (relecture, et les commentaires du site).\n"
          "  * les appels de test (`tests/`, `tests.rs`, module `#[cfg(test)]` en fin de fichier) ne sont pas lus ; une "
          "fonction `#[cfg(test)]` posée au MILIEU d'un fichier de production l'est.\n"
          "  * un appel par un ALIAS (`use crate::ledger::ledger_append as trace;`) ou par un pointeur de fonction n'est "
          "pas vu.\n"
          "  * un maillon rendu par un BLOC NU (`{ …; ledger_append(…) };`), une BOUCLE (`break ledger_append(…)`), une "
          "FERMETURE ou une FONCTION dont l'appelant jette la valeur n'est pas suivi : la remontée ne traverse que les "
          "bras de `match` et les branches d'`if … else`.\n"
          "  * elle ne prouve rien à l'exécution, ni que la console lit `registre_sans_maillon`.")


def main():
    errs = valider_instrument()
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print(f"\n[{ETIQUETTE}] l'INSTRUMENT est faux : aucun verdict n'est rendu.")
        ce_qui_n_est_pas_tenu()
        return 2
    primitive = os.path.join(DEMON, "ledger.rs")
    texte_primitive = open(primitive, encoding="utf-8", errors="replace").read() if os.path.isfile(primitive) else ""
    if not re.search(r"\bfn\s+ledger_append\s*\([^)]*\)\s*->\s*MaillonDeRegistre\b", texte_primitive):
        print("::error::daemon/src/ledger.rs ne déclare plus `fn ledger_append(…) -> MaillonDeRegistre` : la primitive "
              "que cette garde croit lire a changé de forme. Elle REFUSE DE CONCLURE.")
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
    if population < PLANCHER_APPELS or len(fichiers) < PLANCHER_FICHIERS:
        print(f"::error::{population} appel(s) des primitives du registre sur {len(fichiers)} fichier(s), planchers "
              f"{PLANCHER_APPELS}/{PLANCHER_FICHIERS} (dérivés le 2026-10-23, règle des deux tiers). La lecture est "
              "cassée, ou un lot a retiré assez d'appels pour que les planchers doivent être RE-DÉRIVÉS, date écrite. "
              "La garde REFUSE DE CONCLURE plutôt que de rendre vert en étant aveugle.")
        ce_qui_n_est_pas_tenu()
        return 2

    for chemin, ligne, fn, extrait in sorted(sites):
        print(f"::notice file={chemin},line={ligne}::`{fn}` jette son maillon de registre — `{extrait}`")
    ecarts = juger_contre_l_ensemble(sites, SITES_ADMIS)
    print(f"\n[{ETIQUETTE}] POPULATION du jour : {population} appel(s) de `ledger_append`/`control_ledger_append` sur "
          f"{len(fichiers)} fichier(s) de daemon/src (`tests/` élagué) ; {len(sites)} nu(s), "
          f"{sum(SITES_ADMIS.values())} admis par l'ensemble nommé.")
    if ecarts:
        for _g, chemin, phrase in ecarts:
            print(f"::error file={chemin}::{phrase}")
        print(f"::error::{len(ecarts)} écart(s) entre l'arbre et l'ensemble nommé ; il se corrige à la main, AVEC la "
              "raison.")
        ce_qui_n_est_pas_tenu()
        return 1
    print(f"[{ETIQUETTE}] aucun maillon de registre n'est jeté par un appel nu, et l'ensemble nommé est exactement ce "
          "que l'arbre porte. CE QUE CE VERT NE DIT PAS : que chaque maillon consommé est bien lu (témoins des sites).")
    ce_qui_n_est_pas_tenu()
    return 0


if __name__ == "__main__":
    sys.exit(main())
