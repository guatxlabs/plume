#!/usr/bin/env python3
"""Un `match` sur une lecture de ligne unique à chaîne NUE ne sert jamais son échec comme un FAIT — garde de CI
(`P10.20-l`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`query_row` rend un `Result` à trois états dans un seul canal : ligne lue, AUCUNE ligne (`QueryReturnedNoRows`),
lecture NON FAITE (verrou, schéma périmé, conversion). La garde sœur (`check_a_single_row_read_that_failed_is_never_
served_as_a_fact.py`, `P10.20-b`) juge les CHAÎNES qui absorbent l'échec (`.ok()`, `.unwrap_or(..)`, …). La même
faute s'écrit SANS chaîne :

    match conn.query_row(..) { Ok(v) => …, Err(_) => return not_found("…") }

Le bras d'échec rend 404 (ou 403, 400, `false`, `None`, un défaut) quand la base n'a PAS répondu : « absent » et
« pas lu » sont servis pareil. La garde sœur ne le voit pas (sa chaîne est vide : verdict `nu`), et un site neuf
s'écrivait ainsi sans rougir.

LA POPULATION, ÉCRITE
---------------------
Dans `daemon/src/handlers/` (sous-répertoires compris, `#[cfg(test)]` coupé, commentaires dépouillés, littéraux
exclus — lecteurs IMPORTÉS de la garde sœur et de `check_a_read_that_did_not_happen_is_never_served_as_a_fact.py`) :
un `.query_row(` qui est le SCRUTATEUR d'un `match` (lecteur `scrutateur_est_la_lecture`) et dont la chaîne est NUE
— vide, ou faite de seuls TRAVERSANTS (`map`, `map_err`, `and_then`, …) sans `?` ni `.optional()`. `.optional()` fait
SORTIR de la population : l'absence y devient `Ok(None)`, le bras `Err` n'y porte plus que l'échec (trois issues).

LE BRAS D'ÉCHEC, LU
-------------------
Un bras d'échec est un bras `Err(..)`, un fourre-tout `_` ou un nom nu (`autre =>`) ; un motif à ALTERNATIVES
(`Err(QueryReturnedNoRows) | Err(_)`) l'est dès qu'une alternative l'est. N'en sont PAS : le bras qui NOMME
l'absence (`Err(rusqlite::Error::QueryReturnedNoRows)`), et le bras CIBLÉ par une garde (`Err(e) if <cond> =>`, la garde
portant sur tout le motif) — ils ne prennent pas l'échec quelconque ; le bras suivant le prend, et c'est lui qui est
jugé. Puis, dans l'ordre :
  1. son corps distingue lui-même l'absence (`QueryReturnedNoRows` dans le corps) : il n'est pas accusé (limite) ;
  2. il rend un STATUT de client — tout `StatusCode::<NOM>` qui n'est PAS un 5xx (4xx, mais aussi 2xx et 3xx :
     `ACCEPTED`, `NOT_MODIFIED`), ou `not_found(`, `forbidden(`, `bad_req(`, `bad_request(`, `conflict(`,
     `unauthorized(` : il FABRIQUE — forme `Err => <code>` (le nom du statut quand il n'est pas dans la table) ;
  3. il PROPAGE ou AVOUE au sens de la garde sœur (`bras_derreur_garde`, importé : cause portée, `Err(..)`/`return
     Err`, statut d'échec, abandon compté, constructeur d'aveu dérivé), une fois les macros de JOURNAL et les JETS de
     la cause (`drop(e)`, `let _ = e;`) retirés de son corps (`eprintln!(…{e}…)` ne rend rien au client : un bras qui
     journalise, ou jette `e`, puis rend `None` FABRIQUE) ;
  4. sinon il FABRIQUE une valeur — forme `Err => valeur`.

POURQUOI UN ENSEMBLE NOMMÉ, JUGÉ DANS LES DEUX SENS
---------------------------------------------------
Un compte se compense. `SITES_ADMIS` est un ensemble de SITES (fichier, fonction) portant leurs FORMES : une
accusation hors ensemble est une FORME NEUVE (rouge), une entrée qui n'est plus accusée une EXEMPTION SANS OBJET
(rouge). Zéro rançon : aucune épreuve ne s'adosse à un site réel.

DÉCISIONS DU LOT (2026-10-23) : instrument pur, aucun fichier de `daemon/src/` modifié, aucun site corrigé ;
lecteurs importés, jamais recopiés ; seule la jambe `match` DIRECTE est jugée (voir `ce_qui_n_est_pas_tenu()`).

LA SECONDE JAMBE — `map_err` QUI JETTE LA CAUSE (`P10.20-l`, vague AP, 2026-10-25)
---------------------------------------------------------------------------------
La même faute s'écrit aussi SANS `match` et SANS absorbant : `conn.query_row(..).map_err(|_| "objet introuvable")?`.
La garde sœur lit `map_err` comme traversant et `?` comme propagateur (verdict `propage`) ; la jambe `match` ne la voit
pas (la chaîne n'est pas nue). Pourtant la fermeture JETTE l'erreur (`|_|`, `|_e|`) : « aucune ligne » et « lecture
non faite » repartent sous la même phrase d'absence. POPULATION : un `.query_row(` du même corpus dont la chaîne porte
un `map_err` précédé de seuls traversants sans `.optional()`, et suivi d'un `?` (traversants seuls entre les deux).
ACCUSÉ : la fermeture jette sa cause ET rend un LITTÉRAL (chaîne, `String::from`/`format!` d'une chaîne seule, une
constante `MAJUSCULE`, suffixes `.to_string()`/`.to_owned()`/`.into()`, bloc d'une seule expression) — forme
`map_err(|_|)? => littéral` — ou un statut de client (même lecteur que la jambe `match`) — forme
`map_err(|_|)? => <code>`. Les deux jambes s'excluent (une chaîne qui porte `?` n'est jamais nue) : un site n'est
compté qu'une fois. MESURÉ le 2026-10-25 sur `ac1f43b8` par ce lecteur : 4 lectures dans la population
(`library_panel_delete`, `object_constraint_chain`, `resolve_step_search`, `cloner_le_runbook`), 2 accusées
(`object_constraint_chain`, `resolve_step_search`), corrigées par le même lot — aucune entrée dans `SITES_ADMIS`.
VARIANTE D'UN LITTÉRAL (relevée par la vérification du même lot) : une fois la fonction passée à un type de refus, le
retour le plus probable à la forme d'avant s'écrit `.map_err(|_| Refus::Refusee("étape introuvable".to_string()))?` —
la phrase d'absence sous un constructeur nommé. Un constructeur en `CamelCase` (chemin toléré) dont l'UNIQUE champ est
un littéral au sens ci-dessus (ou une telle variante) est accusé, forme `map_err(|_|)? => variante(littéral)`, quel que
soit son nom : la garde ne lit pas le sens d'une variante. Remesuré sur l'arbre du lot : population de la jambe 2,
aucune accusée, aucun faux positif.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

RACINE = (os.path.abspath(sys.argv[1]) if len(sys.argv) > 1
          else os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))

# LES LECTEURS SONT IMPORTÉS, JAMAIS RECOPIÉS (leçon `P10.21-k`). Les modules évaluent leur `RACINE` à l'import par
# `sys.argv` : on leur passe celle d'ici.
_ARGV = sys.argv
sys.argv = [_ARGV[0], RACINE]
try:
    from check_a_single_row_read_that_failed_is_never_served_as_a_fact import (  # noqa: E402
        ARBRE_FABRIQUE, LECTURE_UNE_LIGNE, SOURCES_ATTENDUES, TRAVERSANTS, apparier, chaine_detaillee, coupe_tests,
        dans_une_chaine_rust, debut_instruction, fichiers_du_corpus, fonctions, portee_englobante, positions_de_coupe,
        refuser_sur_aveu, sans_commentaires_rust, spans_de_chaines_rust, temoins_des_lecteurs_de_forme,
        temoins_du_lecteur)
    from check_a_read_that_did_not_happen_is_never_served_as_a_fact import (  # noqa: E402
        bras_derreur_garde, bras_du_match, constructeurs_d_aveu, definitions, scrutateur_est_la_lecture, sources)
finally:
    sys.argv = _ARGV

DEMON = os.path.join(RACINE, "daemon", "src")
ETIQUETTE = "match-nu-servi"

# Les traversants qui gardent le `Result` À DEUX ÉTATS : `optional` en est retiré (il fait les trois issues).
TRAVERSANTS_NUS = tuple(t for t in TRAVERSANTS if t != "optional")
# Un STATUT DE CLIENT est tout `StatusCode::<NOM>` qui n'est PAS un 5xx (succès, redirection, 4xx : « absent »,
# « interdit », « déjà fait » sont des faits sur la demande), ou un constructeur de refus de client du dépôt. Lu par
# EXCLUSION des 5xx et non par liste des 4xx : un `StatusCode::ACCEPTED` ou un `NOT_MODIFIED` servi sur une lecture
# ratée fabrique autant qu'un 404, et le lecteur sœur (`STATUT_ECHEC`) prend tout `StatusCode` pour un aveu.
STATUT_NOMME = re.compile(r"\bStatusCode\s*::\s*([A-Z][A-Z0-9_]*)\b")
CONSTRUCTEUR_DE_CLIENT = re.compile(r"(?<![\w.])(not_found|forbidden|bad_req|bad_request|conflict|unauthorized)\s*\(")
STATUTS_D_ECHEC_SERVEUR = frozenset((
    "INTERNAL_SERVER_ERROR", "NOT_IMPLEMENTED", "BAD_GATEWAY", "SERVICE_UNAVAILABLE", "GATEWAY_TIMEOUT",
    "HTTP_VERSION_NOT_SUPPORTED", "VARIANT_ALSO_NEGOTIATES", "INSUFFICIENT_STORAGE", "LOOP_DETECTED", "NOT_EXTENDED",
    "NETWORK_AUTHENTICATION_REQUIRED"))
CODE_DU_STATUT = {"NOT_FOUND": "404", "FORBIDDEN": "403", "BAD_REQUEST": "400", "UNAUTHORIZED": "401",
                  "CONFLICT": "409", "GONE": "410", "UNPROCESSABLE_ENTITY": "422", "OK": "200", "NO_CONTENT": "204",
                  "CREATED": "201", "ACCEPTED": "202", "NOT_MODIFIED": "304", "FOUND": "302", "SEE_OTHER": "303",
                  "MOVED_PERMANENTLY": "301", "TEMPORARY_REDIRECT": "307", "PERMANENT_REDIRECT": "308",
                  "TOO_MANY_REQUESTS": "429", "PAYLOAD_TOO_LARGE": "413", "PRECONDITION_FAILED": "412",
                  "not_found": "404", "forbidden": "403", "bad_req": "400", "bad_request": "400", "conflict": "409",
                  "unauthorized": "401"}
# Ce qui CONSOMME l'erreur sans la porter : `drop(e)`, `std::mem::drop(e)`, `let _ = e;`. Retiré du corps jugé comme
# le journal : un bras qui jette sa cause puis rend une valeur FABRIQUE.
JET_DE_LA_CAUSE = re.compile(r"(?<![\w.])(?:std\s*::\s*mem\s*::\s*)?drop\s*\(\s*[a-z_]\w*\s*\)\s*;?"
                             r"|\blet\s+_\s*=\s*[a-z_]\w*\s*;")
MACRO_DE_JOURNAL = re.compile(r"(?<![\w])(?:eprintln|println|eprint|print|log::\w+|tracing::\w+)\s*!\s*\(")
# La SECONDE JAMBE (`map_err` qui jette la cause). Une fermeture qui JETTE son argument : `|_|`, `|_e|`, typée ou non,
# `move` toléré. Ce qu'elle rend est lu par `corps_litteral` / `statut_de_client`.
FERMETURE_QUI_JETTE = re.compile(r"\s*(?:move\s+)?\|\s*_\w*\s*(?::[^|]*)?\|", re.S)
SUFFIXE_DE_CONVERSION = re.compile(r"\s*\.\s*(?:to_string|to_owned|into)\s*\(\s*\)\s*$")
ENVELOPPE_D_UNE_CHAINE = re.compile(r"(?:String\s*::\s*from|format\s*!)\s*\((.*)\)", re.S)
LITTERAL_SEUL = re.compile(r'"(?:[^"\\]|\\.)*"|r(#*)".*?"\1|(?:[a-z_]\w*\s*::\s*)*[A-Z][A-Z0-9_]*', re.S)
JAMBE_MAP_ERR = "map_err(|_|)? => "
# Un constructeur en `CamelCase` (variante d'énumération ou struct-tuple, chemin `a::B::` toléré) à UN champ :
# `Refus::Refusee("…".to_string())`. Le champ est relu par `corps_litteral` (ou, récursivement, par cette même forme).
# Une fonction (`bad_req(..)`, `String::from(..)`, `Box::new(..)`) n'a pas de dernier segment en `CamelCase`.
VARIANTE_D_UN_CHAMP = re.compile(r"(?:[A-Za-z_]\w*\s*::\s*)*[A-Z]\w*[a-z]\w*\s*\((.*)\)", re.S)
FORME_VARIANTE_D_UN_LITTERAL = JAMBE_MAP_ERR + "variante(littéral)"

# --- PLANCHERS DE NON-DÉGÉNÉRESCENCE (première écriture, 2026-10-23) --------------------------------------------
# Relevé de l'arbre ce jour-là (base `1287fb98`), MESURÉ par cette garde : 76 `match` directs sur un `query_row` sous
# `handlers/`, dont 34 en `.optional()` (hors population) et 42 à chaîne nue sur 18 fichiers. Règle des deux tiers
# de la garde sœur (69 % et 65 %, arrondis en dessous) : 42 -> 28 (28,98), 18 -> 11 (11,7). Ils ne montent jamais ;
# ils se re-dérivent, date écrite, quand un lot passe assez de sites en `.optional()` pour les franchir.
RELEVE_SITES = 42
RELEVE_FICHIERS = 18
PLANCHER_SITES = 28
PLANCHER_FICHIERS = 11

# ================================================================================================
# L'ENSEMBLE NOMMÉ — LES BRAS QUI FABRIQUENT, ENCORE ADMIS, AVEC LEUR RAISON
# ================================================================================================
# `(fichier, fonction) -> (forme, …)`. Défauts CONNUS de `P10.20-l` (clé ouverte), non corrigés par ce lot
# (instrument pur). Chaque correction retire son entrée.
# NE SONT PAS ICI, PAR DÉCISION : `incidents.rs::runbook_delete` et `incidents.rs::runbook_set_enabled`
# (`Err => 404`), que le lot AH1 de la même vague corrige ; sur un arbre où AH1 n'est pas intégré, la garde les
# accuse en FORME NEUVE, et c'est voulu (une exemption pour un site qu'un lot voisin ferme serait sans objet le jour
# de l'intégration).
SITES_ADMIS = {
    # FAUX POSITIF ÉCRIT : le compte non lu rend `null` (jamais 0) ET pousse son nom dans `non_lus`, que le corps
    # du diagnostic sert. L'aveu passe par une liste que le lecteur importé ne reconnaît pas.
    ("daemon/src/handlers/system.rs", "diag_bundle_json"): ("Err => valeur",),
}


# ================================================================================================
# LA LECTURE
# ================================================================================================
def chaine_nue(jetons):
    """La chaîne laisse-t-elle le `Result` à DEUX états (vide, ou seuls traversants hors `optional`, sans `?`) ?"""
    return all(nom in TRAVERSANTS_NUS for nom, _i, _a1, _a2 in jetons)


def depouiller(corps):
    """Le corps sans son bloc d'une seule expression ni ses suffixes de conversion."""
    c = corps.strip()
    if c.startswith("{") and c.endswith("}"):
        c = c[1:-1].strip()
    while SUFFIXE_DE_CONVERSION.search(c):
        c = SUFFIXE_DE_CONVERSION.sub("", c).strip()
    return c


def corps_litteral(corps):
    """Le corps d'une fermeture n'est-il qu'un LITTÉRAL (chaîne, constante), éventuellement converti ou enveloppé ?"""
    c = depouiller(corps)
    m = ENVELOPPE_D_UNE_CHAINE.fullmatch(c)
    if m:
        c = m.group(1).strip()
    return bool(LITTERAL_SEUL.fullmatch(c))


def variante_d_un_litteral(corps):
    """Le corps n'est-il qu'un constructeur en `CamelCase` dont l'unique champ est un littéral (ou une telle variante) ?
    `Refus::Refusee("étape introuvable".to_string())` : la phrase d'absence sous un type nommé."""
    m = VARIANTE_D_UN_CHAMP.fullmatch(depouiller(corps))
    return bool(m) and (corps_litteral(m.group(1)) or variante_d_un_litteral(m.group(1)))


def jambe_map_err(code, jetons):
    """`(dans_la_population, forme_accusée_ou_None)` pour la chaîne d'une lecture : un `map_err` précédé de seuls
    traversants sans `optional`, suivi d'un `?` (traversants seuls entre les deux) ; accusé quand sa fermeture jette la
    cause et rend un littéral ou un statut de client."""
    for k, (nom, _i, a1, a2) in enumerate(jetons):
        if nom != "map_err":
            if nom not in TRAVERSANTS_NUS:
                return False, None
            continue
        suite = [n for n, _j, _b1, _b2 in jetons[k + 1:]]
        if "?" not in suite or not all(n in TRAVERSANTS_NUS for n in suite[:suite.index("?")]):
            return False, None
        if a1 < 0:
            return True, None
        argument = code[a1:a2]
        f = FERMETURE_QUI_JETTE.match(argument)
        if not f:
            return True, None
        corps = argument[f.end():]
        if corps_litteral(corps):
            return True, JAMBE_MAP_ERR + "littéral"
        if variante_d_un_litteral(corps):
            return True, FORME_VARIANTE_D_UN_LITTERAL
        statut = statut_de_client(corps)
        return True, (JAMBE_MAP_ERR + statut) if statut else None
    return False, None


def sans_macros_de_journal(corps):
    """Le corps privé de ses macros de journal : ce qui part au journal n'est pas rendu à l'appelant."""
    out, i = [], 0
    for m in MACRO_DE_JOURNAL.finditer(corps):
        if m.start() < i:
            continue
        f = apparier(corps, m.end() - 1)
        if f < 0:
            continue
        out.append(corps[i:m.start()])
        i = f + 1
    return "".join(out) + corps[i:]


def statut_de_client(corps):
    """L'étiquette (`404`, `202`, …) du premier statut de client du corps, ou None."""
    for m in STATUT_NOMME.finditer(corps):
        if m.group(1) not in STATUTS_D_ECHEC_SERVEUR:
            return CODE_DU_STATUT.get(m.group(1), m.group(1))
    c = CONSTRUCTEUR_DE_CLIENT.search(corps)
    return CODE_DU_STATUT[c.group(1)] if c else None


def alternatives_du_motif(motif):
    """Les alternatives de tête d'un motif (`A | B`), coupées hors parenthèses."""
    out, prof, deb = [], 0, 0
    for j, c in enumerate(motif):
        if c in "([{":
            prof += 1
        elif c in ")]}":
            prof -= 1
        elif c == "|" and prof == 0:
            out.append(motif[deb:j])
            deb = j + 1
    out.append(motif[deb:])
    return out


def est_un_bras_d_echec(motif):
    """Le bras prend-il l'échec QUELCONQUE ? `Err(..)`, `_`, nom nu — sauf l'absence nommée et le bras gardé. Un motif
    à ALTERNATIVES (`Err(QueryReturnedNoRows) | Err(_)`) l'est dès qu'UNE alternative l'est ; la garde (`if …`) qui
    suit la dernière alternative porte sur tout le motif."""
    m = " ".join(motif.split())
    alternatives = alternatives_du_motif(m)
    if len(alternatives) > 1:
        derniere = alternatives[-1].strip()
        garde = re.search(r"\)\s+if\b|^\s*[a-z_]\w*\s+if\b", derniere)
        if garde:
            return False  # bras CIBLÉ
        return any(est_un_bras_d_echec(a) for a in alternatives)
    if re.fullmatch(r"&?[a-z_]\w*", m):  # `_`, `&_`, ou un nom nu : le fourre-tout prend l'échec
        return True
    if not re.match(r"Err\s*\(", m):
        return False
    f = apparier(m, m.index("("))
    if f < 0 or m[f + 1:].strip():
        return False  # `Err(e) if <cond>` : bras CIBLÉ, il ne prend pas l'échec quelconque
    return "QueryReturnedNoRows" not in m


def verdict_du_bras(motif, corps, constructeurs, portee):
    """La forme accusée (`Err => 404`, `Err => valeur`), ou None quand le bras propage, avoue ou distingue."""
    if "QueryReturnedNoRows" in corps:
        return None
    statut = statut_de_client(corps)
    if statut:
        return "Err => " + statut
    if bras_derreur_garde(motif, JET_DE_LA_CAUSE.sub("", sans_macros_de_journal(corps)), constructeurs, portee):
        return None
    return "Err => valeur"


def analyser(chemin_relatif, texte, journal, constructeurs, aveux_du_lecteur=None, compteurs=None):
    """(sites, population) pour UN fichier : sites = [(chemin, ligne, fonction, forme, extrait)], population = le
    nombre de `match` à chaîne nue lus (accusés ou non). `compteurs["map_err"]` reçoit la population de la seconde
    jambe (lectures `… .map_err(..)?` sans `.optional()`, accusées ou non)."""
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
    for m in LECTURE_UNE_LIGNE.finditer(code):
        if dans_une_chaine_rust(spans, m.start()):
            continue
        ligne = code.count("\n", 0, m.start()) + 1
        fin = apparier(code, m.end() - 1)
        if fin < 0:
            journal.append(f"{chemin_relatif}:{ligne} — parenthèse d'appel non appariée sur une lecture de ligne "
                           "unique : le lecteur a perdu la fin de l'expression")
            continue
        jetons, apres = chaine_detaillee(code, fin)
        dans_la_jambe, forme_map_err = jambe_map_err(code, jetons)
        if dans_la_jambe:
            if compteurs is not None:
                compteurs["map_err"] = compteurs.get("map_err", 0) + 1
            if forme_map_err:
                englobante = portee_englobante(fns, m.start())
                if not englobante:
                    journal.append(f"{chemin_relatif}:{ligne} — `map_err` qui jette la cause HORS de toute fonction : "
                                   "un site sans fonction ne peut pas entrer dans l'ensemble")
                else:
                    extrait = " ".join(code[debut_instruction(coupes, m.start()):apres].split())[:140]
                    sites.append((chemin_relatif, ligne, englobante[0], forme_map_err, extrait))
            continue  # une chaîne qui porte `?` n'est jamais nue : la jambe `match` ne la reverrait pas
        if not chaine_nue(jetons) or not scrutateur_est_la_lecture(code, m.start()):
            continue
        i = apres
        while i < len(code) and code[i] in " \t\n":
            i += 1
        if code[i:i + 1] != "{":
            continue
        population += 1
        englobante = portee_englobante(fns, m.start())
        if not englobante:
            journal.append(f"{chemin_relatif}:{ligne} — `match` HORS de toute fonction : un site sans fonction ne "
                           "peut pas entrer dans l'ensemble")
            continue
        portee = code[englobante[2]:englobante[3]]
        for motif, corps in bras_du_match(code, i):
            if not est_un_bras_d_echec(motif):
                continue
            forme = verdict_du_bras(motif, corps, constructeurs, portee)
            if forme:
                extrait = " ".join((motif.strip() + " => " + corps.strip()).split())[:140]
                sites.append((chemin_relatif, ligne, englobante[0], forme, extrait))
    return sites, population


def constructeurs_du_demon(racine_demon=None):
    """Les constructeurs d'aveu dérivés sur tout `daemon/src` (geste de la garde sœur, importé)."""
    src = list(sources(DEMON if racine_demon is None else racine_demon))
    return constructeurs_d_aveu(definitions(src), src)


def decouvrir(racine=None, compteurs=None):
    sites, journal, aveux_du_lecteur, population, fichiers = [], [], {}, 0, set()
    constructeurs = constructeurs_du_demon(None if racine is None else racine)
    for chemin in fichiers_du_corpus(racine):
        with open(chemin, encoding="utf-8", errors="replace") as fh:
            texte = fh.read()
        rel = os.path.relpath(chemin, RACINE).replace(os.sep, "/")
        s, n = analyser(rel, texte, journal, constructeurs, aveux_du_lecteur, compteurs)
        sites += s
        population += n
        if n:
            fichiers.add(rel)
    return sites, journal, aveux_du_lecteur, population, fichiers


# ================================================================================================
# LE JUGEMENT CONTRE L'ENSEMBLE NOMMÉ — DANS LES DEUX SENS
# ================================================================================================
def juger_contre_l_ensemble(sites, admis):
    vus = {}
    for chemin, ligne, fn, forme, _x in sites:
        vus.setdefault((chemin, fn), {}).setdefault(forme, []).append(ligne)
    ecarts = []
    for cle in sorted(set(vus) | set(admis)):
        chemin, fn = cle
        admises = {}
        for forme in admis.get(cle, ()):
            admises[forme] = admises.get(forme, 0) + 1
        vues = vus.get(cle, {})
        for forme in sorted(set(vues) | set(admises)):
            n_vu, n_admis = len(vues.get(forme, [])), admises.get(forme, 0)
            if n_vu > n_admis:
                lignes = ", ".join(str(x) for x in sorted(vues[forme])[n_admis:])
                ecarts.append(("forme neuve", chemin,
                               f"FORME NEUVE — `{fn}` ({chemin}) sert l'échec d'une lecture de ligne unique à chaîne "
                               f"nue sous la forme `{forme}` {n_vu} fois pour {n_admis} admise(s) ; ligne(s) : {lignes}. "
                               "La lecture se fait en trois issues (`.optional()` : absent = la réponse d'avant, "
                               "lecture ratée = 503 nommé), ou le bras d'échec propage — sinon le site entre dans "
                               "SITES_ADMIS AVEC sa raison."))
            if n_vu < n_admis:
                ecarts.append(("exemption sans objet", chemin,
                               f"EXEMPTION SANS OBJET — `{fn}` ({chemin}) est admis {n_admis} fois sous la forme "
                               f"`{forme}` et n'est accusé que {n_vu} fois : le site est corrigé, a changé de forme, "
                               "n'existe plus, ou cette garde a cessé de le voir. L'entrée se retire à la main EN "
                               "DISANT LEQUEL."))
    return ecarts


# ================================================================================================
# LES ÉPREUVES — JOUÉES AVANT TOUTE LECTURE DU DÉPÔT, DANS LES DEUX SENS
# ================================================================================================
# Sources FABRIQUÉES, jamais prises sur l'arbre (zéro rançon).
def _f(corps):
    return "fn f(conn: &Connection, id: i64) -> Response {\n" + corps + "\n}\n"


def _m(bras, chaine=""):
    return _f('    match conn.query_row("SELECT 1 FROM t WHERE id=?1", [id], |r| r.get::<_, i64>(0))' + chaine
              + ' {\n        Ok(v) => ok(v),\n' + bras + '\n    }')


AVEU = '/// AVEU — la lecture n\'a pas eu lieu.\nfn refus_avoue() -> Response {\n    err_json(StatusCode::SERVICE_UNAVAILABLE, "x")\n}\n'

EPREUVES = [
    # --- CE QUI DOIT ÊTRE VU.
    ("p1 `Err(_) => not_found(..)`", _m('        Err(_) => return not_found("absent"),'), {"Err => 404"}, 1),
    ("p2 `Err(_) => (false, Value::Null)`", _m('        Err(_) => (false, Value::Null),'), {"Err => valeur"}, 1),
    ("p3 `Err(_) => err_json(StatusCode::CONFLICT, ..)`",
     _m('        Err(_) => return err_json(StatusCode::CONFLICT, "aucun"),'), {"Err => 409"}, 1),
    ("p4 fourre-tout `_ => StatusCode::FORBIDDEN`", _m('        _ => StatusCode::FORBIDDEN.into_response(),'),
     {"Err => 403"}, 1),
    ("p5 le bras qui journalise puis rend `None`", _m('        Err(e) => {\n            eprintln!("non lu : {e}");\n'
                                                      '            None\n        }'), {"Err => valeur"}, 1),
    ("p6 chaîne de traversants seuls", _m('        Err(_) => return bad_req("x"),', '.map(|v| v + 1)'), {"Err => 400"}, 1),
    ("p7 absence nommée puis bras quelconque qui fabrique",
     _m('        Err(rusqlite::Error::QueryReturnedNoRows) => not_found("absent"),\n        Err(_) => forbidden("non"),'),
     {"Err => 403"}, 1),
    ("p8 receveur coupé par rustfmt",
     _f('    match conn\n        .query_row("SELECT 1", [], |r| r.get::<_, i64>(0))\n    {\n        Ok(v) => ok(v),\n'
        '        Err(_) => not_found("x"),\n    }'), {"Err => 404"}, 1),
    ("p9 nom nu fourre-tout", _m('        autre => Vec::new(),'), {"Err => valeur"}, 1),
    # --- CE QUI NE DOIT PAS L'ÊTRE.
    ("n1 trois issues par `.optional()` (hors population)", _m('        Err(_) => not_found("x"),', '.optional()'),
     set(), 0),
    ("n2 `Err(e) => return Err(e)`", _m('        Err(e) => return Err(e),'), set(), 1),
    ("n3 503 nommé", _m('        Err(e) => return err_json(StatusCode::SERVICE_UNAVAILABLE, format!("{CAUSE} ({e})")),'),
     set(), 1),
    ("n4 absence nommée en 404, échec en 503",
     _m('        Err(rusqlite::Error::QueryReturnedNoRows) => not_found("absent"),\n'
        '        Err(e) => err_json(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),'), set(), 1),
    ("n5 bras ciblé par une garde, puis 503",
     _m('        Err(e) if forme_inconnue(&e) => false,\n        Err(_) => err_json(StatusCode::SERVICE_UNAVAILABLE, "x"),'),
     set(), 1),
    ("n6 abandon compté", _m('        Err(_) => {\n            abandons += 1;\n            continue;\n        }'), set(), 1),
    ("n7 `Result` lié puis `match` (hors jambe : limite écrite)",
     _f('    let r = conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0));\n    match r {\n        Ok(v) => ok(v),\n'
        '        Err(_) => not_found("x"),\n    }'), set(), 0),
    ("n8 cité dans un littéral",
     _f('    let doc = "match conn.query_row(q, [], f) { Ok(v) => v, Err(_) => not_found(x) }";\n    rendre(doc)'), set(), 0),
    ("n9 module de test coupé", _f('    ok()') + '#[cfg(test)]\nmod tests {\n' + _m('        Err(_) => not_found("x"),')
     + '}\n', set(), 0),
    ("n10 le corps distingue lui-même l'absence",
     _m('        Err(e) => match e {\n            rusqlite::Error::QueryReturnedNoRows => not_found("absent"),\n'
        '            autre => err_json(StatusCode::SERVICE_UNAVAILABLE, autre.to_string()),\n        },'), set(), 1),
    ("n11 constructeur d'aveu dérivé (doc `/// AVEU`)", AVEU + _m('        Err(_) => return refus_avoue(),'), set(), 1),
    ("n12 propagé par `?` (hors population)", _m('        Err(_) => not_found("x"),', '?'), set(), 0),
    ("n13 la lecture n'est pas le scrutateur",
     _f('    match id {\n        0 => conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0)).map_err(|_| 0),\n'
        '        _ => Err(1),\n    }'), set(), 0),
    ("n14 `if let Ok(..)` suivi d'un bloc (hors jambe : limite écrite)",
     _f('    if let Ok(v) = conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0)) {\n        ok(v)\n    } else {\n'
        '        not_found("x")\n    }'), set(), 0),
    ("n15 la lecture comparée sous un `match` (pas de bloc après la chaîne)",
     _f('    match conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0)) == Ok(1) {\n        true => ok(),\n'
        '        false => not_found("x"),\n    }'), set(), 0),
    # --- `P10.20-l`, correction : les contournements relevés par la vérification indépendante.
    ("p10 motif à alternatives `Err(QueryReturnedNoRows) | Err(_)`",
     _m('        Err(rusqlite::Error::QueryReturnedNoRows) | Err(_) => return not_found("x"),'), {"Err => 404"}, 1),
    ("p11 `drop(e)` puis une valeur", _m('        Err(e) => {\n            drop(e);\n            Value::Null\n        }'),
     {"Err => valeur"}, 1),
    ("p12 `let _ = e;` puis une valeur", _m('        Err(e) => {\n            let _ = e;\n            Value::Null\n        }'),
     {"Err => valeur"}, 1),
    ("p13 statut hors table (nom servi tel quel)", _m('        Err(_) => StatusCode::IM_A_TEAPOT.into_response(),'),
     {"Err => IM_A_TEAPOT"}, 1),
    ("n16 motif à alternatives CIBLÉ par une garde, puis 503",
     _m('        Err(rusqlite::Error::QueryReturnedNoRows) | Err(_) if rare() => false,\n'
        '        Err(e) => err_json(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),'), set(), 1),
    ("n18 motif à alternatives d'échec CIBLÉ par une garde (elle porte sur tout le motif), puis 503",
     _m('        Err(rusqlite::Error::InvalidQuery) | Err(_) if rare() => false,\n'
        '        Err(e) => err_json(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),'), set(), 1),
    ("n17 `drop` d'AUTRE CHOSE, cause portée", _m('        Err(e) => {\n            drop(verrou);\n            return Err(e);\n'
                                                  '        }'), set(), 1),
]


# --- `P10.20-l` (vague AP) : LA SECONDE JAMBE, `map_err` qui jette la cause. Le cinquième terme est la population de
# la jambe (0 par défaut pour les épreuves de la jambe `match` : aucune n'y entre).
def _e(chaine, suite="    ok(v)"):
    return _f('    let v = conn.query_row("SELECT 1 FROM t WHERE id=?1", [id], |r| r.get::<_, i64>(0))' + chaine
              + ';\n' + suite)


LITTERAL_ACCUSE = {JAMBE_MAP_ERR + "littéral"}
EPREUVES += [
    ("p14 `.map_err(|_| \"…\".to_string())?`", _e('.map_err(|_| "objet introuvable".to_string())?'), LITTERAL_ACCUSE, 0, 1),
    ("p15 constante rendue `.map_err(|_| ABSENT)?`", _e('.map_err(|_| ABSENT)?'), LITTERAL_ACCUSE, 0, 1),
    ("p16 statut de client `.map_err(|_| not_found(..))?`", _e('.map_err(|_| not_found("x"))?'),
     {JAMBE_MAP_ERR + "404"}, 0, 1),
    ("p17 `|_e|` et `String::from(..)`", _e('.map_err(|_e| String::from("x"))?'), LITTERAL_ACCUSE, 0, 1),
    ("p18 coupé par rustfmt, bloc d'une expression, `.into()`",
     _f('    let v = conn\n        .query_row("SELECT 1", [], |r| r.get::<_, i64>(0))\n        .map_err(|_| {\n'
        '            "x".into()\n        })?;\n    ok(v)'), LITTERAL_ACCUSE, 0, 1),
    ("p19 traversant avant `map_err`", _e('.map(|v| v + 1).map_err(|_| "x")?'), LITTERAL_ACCUSE, 0, 1),
    ("p20 `format!` d'une chaîne seule", _e('.map_err(|_| format!("x"))?'), LITTERAL_ACCUSE, 0, 1),
    ("p21 fermeture typée `|_: rusqlite::Error|`", _e('.map_err(|_: rusqlite::Error| "x")?'), LITTERAL_ACCUSE, 0, 1),
    ("p22 statut nommé `(StatusCode::BAD_REQUEST, ..)`", _e('.map_err(|_| (StatusCode::BAD_REQUEST, "x".to_string()))?'),
     {JAMBE_MAP_ERR + "400"}, 0, 1),
    ("p23 constante d'un module, `.to_owned()`", _e('.map_err(|_| erreurs::ABSENT.to_owned())?'), LITTERAL_ACCUSE, 0, 1),
    ("n19 trois issues `.optional().map_err(|_| ..)?` (hors jambe)", _e('.optional().map_err(|_| "x")?'), set(), 0, 0),
    ("n20 cause portée `.map_err(|e| format!(\"… {e}\"))?`", _e('.map_err(|e| format!("x : {e}"))?'), set(), 0, 1),
    ("n21 sans `?` (le `Result` est rendu : hors jambe, limite écrite)", _e('.map_err(|_| "x")', '    v'), set(), 0, 0),
    ("n22 variante UNITAIRE, aucun littéral (non jugée : limite écrite)", _e('.map_err(|_| Refus::NonLu)?'), set(), 0, 1),
    ("n23 échec serveur `.map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, ..))?`",
     _e('.map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, CAUSE))?'), set(), 0, 1),
    ("n24 `format!` qui porte un argument", _e('.map_err(|_| format!("x {}", id))?'), set(), 0, 1),
    ("n25 cité dans un littéral",
     _f('    let doc = "conn.query_row(q, [], f).map_err(|_| \\"x\\")?";\n    rendre(doc)'), set(), 0, 0),
    ("n26 module de test coupé", _f('    ok()') + '#[cfg(test)]\nmod tests {\n' + _e('.map_err(|_| "x")?') + '}\n',
     set(), 0, 0),
    ("n27 `?` séparé par un absorbant (hors jambe)", _e('.map_err(|_| "x").ok()?'), set(), 0, 0),
]
# La VARIANTE D'UN LITTÉRAL (vérification du lot) : le retour probable à la forme d'avant sous un type de refus.
VARIANTE_ACCUSEE = {FORME_VARIANTE_D_UN_LITTERAL}
EPREUVES += [
    ("p24 variante d'un littéral `|_| Refus::Refusee(\"…\".to_string())`",
     _e('.map_err(|_| Refus::Refusee("étape introuvable".to_string()))?'), VARIANTE_ACCUSEE, 0, 1),
    ("p25 chemin de module et `String::from` dans la variante",
     _e('.map_err(|_| crate::erreurs::Refus::Absent(String::from("x")))?'), VARIANTE_ACCUSEE, 0, 1),
    ("p26 bloc rustfmt, constante convertie, `.into()` sur la variante",
     _f('    let v = conn\n        .query_row("SELECT 1", [], |r| r.get::<_, i64>(0))\n        .map_err(|_| {\n'
        '            Refus::Refusee(ABSENT.into()).into()\n        })?;\n    ok(v)'), VARIANTE_ACCUSEE, 0, 1),
    ("p27 variante dans une variante", _e('.map_err(|_| Refus::Client(Motif::Absent("x")))?'), VARIANTE_ACCUSEE, 0, 1),
    ("n28 variante d'un `format!` qui porte un argument", _e('.map_err(|_| Refus::Refusee(format!("x {}", id)))?'),
     set(), 0, 1),
    ("n29 variante à deux champs (limite écrite)", _e('.map_err(|_| Refus::Refusee("x", id))?'), set(), 0, 1),
    ("n30 fonction en minuscules (pas un constructeur)", _e('.map_err(|_| refuser("x"))?'), set(), 0, 1),
]
# Chaque statut de client de la table, et chaque 5xx exclu, a son épreuve : perdre une entrée (ou un 5xx de
# l'exclusion) fait rougir la sienne. Le lecteur sœur prend tout `StatusCode` pour un aveu : sans ces épreuves, perdre
# `NOT_FOUND` laissait passer `Err(_) => StatusCode::NOT_FOUND.into_response()`. L'étiquette attendue est ÉCRITE ici,
# jamais relue de `CODE_DU_STATUT` : une entrée retirée de la table doit faire rougir son épreuve, pas la faire disparaître.
STATUTS_EPROUVES = (
    ("NOT_FOUND", "404"), ("FORBIDDEN", "403"), ("BAD_REQUEST", "400"), ("UNAUTHORIZED", "401"), ("CONFLICT", "409"),
    ("GONE", "410"), ("UNPROCESSABLE_ENTITY", "422"), ("OK", "200"), ("NO_CONTENT", "204"), ("CREATED", "201"),
    ("ACCEPTED", "202"), ("NOT_MODIFIED", "304"), ("FOUND", "302"), ("SEE_OTHER", "303"), ("MOVED_PERMANENTLY", "301"),
    ("TEMPORARY_REDIRECT", "307"), ("PERMANENT_REDIRECT", "308"), ("TOO_MANY_REQUESTS", "429"),
    ("PAYLOAD_TOO_LARGE", "413"), ("PRECONDITION_FAILED", "412"), ("not_found", "404"), ("forbidden", "403"),
    ("bad_req", "400"), ("bad_request", "400"), ("conflict", "409"), ("unauthorized", "401"))
for _nom, _code in STATUTS_EPROUVES:
    _bras = (f'        Err(_) => StatusCode::{_nom}.into_response(),' if _nom.isupper()
             else f'        Err(_) => return {_nom}("x"),')
    EPREUVES.append((f"s-{_nom} statut de client servi sur l'échec", _m(_bras), {"Err => " + _code}, 1))
for _nom in sorted(STATUTS_D_ECHEC_SERVEUR):
    EPREUVES.append((f"s-{_nom} échec serveur qui porte la cause",
                     _m(f'        Err(e) => err_json(StatusCode::{_nom}, e.to_string()),'), set(), 1))


def epreuve_de_la_descente():
    """Le corpus descend dans les sous-répertoires et élague `tests/` et les artefacts — un fichier LISTÉ est ANALYSÉ."""
    errs = []
    source = _m('        Err(_) => not_found("x"),')
    with tempfile.TemporaryDirectory(prefix="plume-match-nu-") as racine:
        for rel in ARBRE_FABRIQUE:
            chemin = os.path.join(racine, *rel)
            os.makedirs(os.path.dirname(chemin), exist_ok=True)
            with open(chemin, "w", encoding="utf-8") as fh:
                fh.write(source)
        vus = {os.path.relpath(c, racine).replace(os.sep, "/") for c in fichiers_du_corpus(racine)}
        if SOURCES_ATTENDUES - vus:
            errs.append(f"épreuve de la DESCENTE : {sorted(SOURCES_ATTENDUES - vus)} hors du corpus")
        if vus - SOURCES_ATTENDUES:
            errs.append(f"épreuve de la DESCENTE (élagage) : {sorted(vus - SOURCES_ATTENDUES)} est entré dans le corpus")
        sites = decouvrir(racine)[0]
        if {f for _c, _l, _fn, f, _x in sites} != {"Err => 404"} or len(sites) != len(SOURCES_ATTENDUES):
            errs.append("épreuve de la DESCENTE (analyse) : un fichier LISTÉ n'est pas ACCUSÉ")
    return errs


def epreuve_du_constructeur_d_un_autre_fichier():
    """Les constructeurs d'aveu se dérivent sur tout le démon, pas sur le seul fichier lu — dans les deux sens."""
    errs = []
    appelant = _m('        Err(_) => return refus_avoue(),')
    for avec in (True, False):
        with tempfile.TemporaryDirectory(prefix="plume-match-nu-aveu-") as racine:
            with open(os.path.join(racine, "appelant.rs"), "w", encoding="utf-8") as fh:
                fh.write(appelant)
            with open(os.path.join(racine, "aveu.rs"), "w", encoding="utf-8") as fh:
                fh.write(AVEU if avec else "fn rien() {}\n")
            formes = {f for _c, _l, _fn, f, _x in decouvrir(racine)[0]}
        if avec and formes:
            errs.append("épreuve du CONSTRUCTEUR d'un autre fichier : le bras qui avoue est accusé — les constructeurs "
                        "ne sont plus dérivés sur tout le démon")
        if not avec and formes != {"Err => valeur"}:
            errs.append("épreuve du CONSTRUCTEUR d'un autre fichier (sans lui) : le bras qui fabrique n'est plus accusé")
    return errs


def valider_instrument():
    """L'instrument s'éprouve AVANT de rendre un verdict. MUTATIONS JOUÉES le 2026-10-23, toutes en sortie 2 : chaîne
    toujours nue (n1) ; `optional` compté nu (vocabulaire, n1) ; scrutateur non exigé (n14) ; bloc non exigé (n15) ;
    fourre-tout et nom nu oubliés (p4, p9) ; bras gardé pris (n5) ; absence nommée prise (n4, p7) ; corps qui distingue
    ignoré (n10) ; statut de client ignoré (p1, p3) ; journal laissé dans le corps jugé (p5) ; aveu ignoré (n2, n3) ;
    constructeurs non dérivés sur tout le démon (épreuve du constructeur) ; jugement d'ensemble muet dans chaque sens ;
    littéraux lus (n8) ; tests lus (n9) ; population non comptée (p1) ; bras non filtrés (p1, p3). Un premier essai
    avait un fourre-tout `_` lu deux fois (règle `_` et règle du nom nu) : la mutation de l'une restait verte, les deux
    sont fondues en une.

    CORRECTION (2026-10-23) — une vérification indépendante a trouvé verts les mutants qui retiraient `NOT_FOUND`, `OK`
    ou `BAD_REQUEST` de la liste des statuts (aucune épreuve ne les fixait, et le lecteur sœur prend tout `StatusCode`
    pour un aveu), et trois contournements : `Err(QueryReturnedNoRows) | Err(_)`, un statut 2xx/3xx, `drop(e)`. Le statut
    se lit désormais par EXCLUSION des 5xx, chaque entrée de la table et chaque 5xx exclu a son épreuve (`s-…`, table
    attendue écrite à part et accordée à la table lue). MUTATIONS JOUÉES, toutes en sortie 2 : un 5xx retiré de
    l'exclusion (n3, n4) ; `NOT_FOUND`, `OK`, `BAD_REQUEST` comptés 5xx un par un (s-NOT_FOUND, s-OK, s-BAD_REQUEST) ;
    étiquette 404 retirée de la table (s-NOT_FOUND, accord) ; entrée de table sans épreuve (accord) ; statut lu par la
    seule table (p13) ; constructeurs de client ignorés (p1, p6) ; alternatives ignorées (p10) ; « une » alternative lue
    « toutes » (p10) ; garde d'un motif à alternatives ignorée (n18) ; jet non retiré (p11, p12), `drop` puis `let _ = e`
    oubliés un par un (p11, p12). Sur une copie mutée du démon (`incidents.rs::case_step_set`) : `StatusCode::NOT_FOUND`,
    `(StatusCode::OK, …)`, `StatusCode::ACCEPTED`, `Err(QueryReturnedNoRows) | Err(_)` et `drop(e)` puis valeur sont
    accusés. Population et accusations de l'arbre inchangées (avec et sans le lot voisin qui corrige `runbook_*`).

    SECONDE JAMBE (`P10.20-l`, vague AP, 2026-10-25) — épreuves `p14`-`p23` et `n19`-`n27`, population de la jambe
    jugée sur chacune (cinquième terme), doublon d'accusation refusé. Mutants joués sur une copie de cette garde, chacun
    en sortie 2 : la jambe retirée ; `optional` accepté avant `map_err` (n19) ; `?` non exigé (n21) ; un absorbant
    accepté entre `map_err` et `?` (n27) ; `|_e|` non reconnu (p17) ; fermeture typée non reconnue (p21) ; suffixes de
    conversion ignorés (p14) ; bloc non dépouillé (p18) ; enveloppe `String::from`/`format!` ignorée (p17, p20) ;
    constante non reconnue (p15) ; statut de client ignoré (p16, p22) ; population non comptée (p14). Le `continue` qui
    suit la jambe est une ceinture (une chaîne qui porte `?` n'est jamais nue) : son retrait est un mutant équivalent.
    Sur une copie de l'arbre `ac1f43b8` (les deux sites d'avant le correctif) :
    sortie 1, `object_constraint_chain` et `resolve_step_search` accusés en FORME NEUVE ; sur l'arbre corrigé : 0.
    VARIANTE D'UN LITTÉRAL (vérification du lot) — épreuves `p24`-`p27` et `n28`-`n30` ; mutants joués sur une copie,
    chacun en sortie 2 : la branche retirée de `jambe_map_err` (p24) ; dernier segment en `CamelCase` non exigé (n30) ;
    récursion retirée (p27) ; dépouillement retiré (p26) ; chemin de module non toléré (p25). Sur une copie de l'arbre
    du lot où `resolve_step_search` est remis en `.map_err(|_| RefusDeLaRechercheDEtape::Refusee("étape
    introuvable".to_string()))?` : sortie 1, FORME NEUVE `variante(littéral)` ; arbre du lot : 0, population inchangée."""
    errs = []
    try:
        temoins_du_lecteur()
    except AssertionError as e:
        errs.append(f"lecteur partagé (`sans_commentaires_rust`) : {e}")
    try:
        temoins_des_lecteurs_de_forme()
    except AssertionError as e:
        errs.append(f"lecteurs de forme Rust (`apparier`, `fonctions`, `bras_du_match`, …) : {e}")
    if set(CODE_DU_STATUT) != {n for n, _c in STATUTS_EPROUVES}:
        errs.append("table des statuts et épreuves désaccordées : "
                    f"{sorted(set(CODE_DU_STATUT) ^ {n for n, _c in STATUTS_EPROUVES})} sans son épreuve ou sans entrée")
    if "optional" in TRAVERSANTS_NUS or "map" not in TRAVERSANTS_NUS:
        errs.append("vocabulaire des traversants importé faux : `.optional()` compté nu, ou `.map(..)` hors chaîne nue")
    for nom, src, attendues, pop_attendue, *jambe in EPREUVES:
        journal, compteurs = [], {}
        constructeurs = constructeurs_d_aveu(definitions([("/epreuve.rs", src)]), [("/epreuve.rs", src)])
        sites, population = analyser("/epreuve.rs", src, journal, constructeurs, compteurs=compteurs)
        if len(sites) != len({(c, l, fn) for c, l, fn, _f2, _x in sites}):
            errs.append(f"épreuve « {nom} » : une même lecture accusée deux fois")
        if compteurs.get("map_err", 0) != (jambe[0] if jambe else 0):
            errs.append(f"épreuve « {nom} » : population de la jambe `map_err` {compteurs.get('map_err', 0)}, attendu "
                        f"{jambe[0] if jambe else 0}")
        vues = {f for _c, _l, _fn, f, _x in sites}
        if journal:
            errs.append(f"épreuve « {nom} » : le lecteur avoue avoir perdu quelque chose ({journal[0]})")
        if vues != attendues:
            errs.append(f"épreuve « {nom} » : formes vues {sorted(vues) or 'aucune'}, attendu {sorted(attendues) or 'aucune'}"
                        + (" — la garde ne voit plus une forme qu'elle nomme" if attendues else
                           " — la garde accuse un bras qui propage, avoue, ou n'est pas dans la population"))
        if population != pop_attendue:
            errs.append(f"épreuve « {nom} » : population {population}, attendu {pop_attendue}")
    errs += epreuve_de_la_descente()
    errs += epreuve_du_constructeur_d_un_autre_fichier()
    faux = [("daemon/src/handlers/fabrique.rs", 3, "f", "Err => 404", "…")]
    if {g for g, _f2, _p in juger_contre_l_ensemble(faux, {})} != {"forme neuve"}:
        errs.append("épreuve de l'ENSEMBLE (site neuf) : un site hors ensemble ne rougit plus")
    if {g for g, _f2, _p in juger_contre_l_ensemble([], {("daemon/src/handlers/fabrique.rs", "f"): ("Err => 404",)})} \
            != {"exemption sans objet"}:
        errs.append("épreuve de l'ENSEMBLE (site corrigé encore listé) : une entrée sans objet ne rougit plus")
    if juger_contre_l_ensemble(faux, {("daemon/src/handlers/fabrique.rs", "f"): ("Err => 404",)}):
        errs.append("épreuve de l'ENSEMBLE (accord) : un site exactement admis produit un écart")
    change = [("daemon/src/handlers/fabrique.rs", 3, "f", "Err => valeur", "…")]
    if {g for g, _f2, _p in juger_contre_l_ensemble(change, {("daemon/src/handlers/fabrique.rs", "f"): ("Err => 404",)})} \
            != {"forme neuve", "exemption sans objet"}:
        errs.append("épreuve de l'ENSEMBLE (forme changée) : un site admis sous une forme, réécrit sous une autre, passe")
    return errs


# ================================================================================================
# LE VERDICT
# ================================================================================================
def ce_qui_n_est_pas_tenu():
    print(f"\n[{ETIQUETTE}] CE QU'ELLE NE TIENT PAS (mesuré le 2026-10-23 sur `1287fb98`) :\n"
          "  * seule la jambe `match` DIRECTE est jugée (42 lectures sous `handlers/`). Restent hors garde, à chaîne nue "
          "sous `handlers/` : 24 `Result` LIÉS à un nom (`let r = conn.query_row(..); match r {..}`, `if let`, rendus "
          "plus bas) et 6 rendus ou passés en argument — c'est la suite de `P10.20-l`. Hors `handlers/` (dont "
          "l'authentification, `state.rs`, `scim.rs`), ni cette garde ni sa sœur ne lisent : 27 `match` directs, 26 "
          "liés, 7 `if let` directs, 15 autres, à chaîne nue.\n"
          "  * seconde jambe (`map_err` qui jette la cause, vague AP) : seule la fermeture `|_|`/`|_e|` suivie d'un `?` est "
          "jugée, et seul un corps LITTÉRAL, une variante d'UN littéral ou un statut de client y est accusé ; la variante est "
          "accusée quel que soit son nom (une variante « non lu » qui porterait un littéral le serait aussi : elle entre "
          "alors dans SITES_ADMIS avec sa raison). Une variante unitaire (`|_| Refus::NonLu`) ou à plusieurs champs, "
          "un 5xx (`|_| (StatusCode::SERVICE_UNAVAILABLE, ..)`, l'absence servie en lecture ratée), un `format!` qui porte "
          "un argument, une fermeture `|e|` qui ne se sert pas de `e`, ou un `Result` rendu sans `?` passent sans "
          "jugement ; aucun plancher : la population de l'arbre est petite et sa santé est zéro accusation.\n"
          "  * un `match` en trois issues (`.optional()`) sort de la population : son bras `Err` porte l'échec seul, et "
          "un bras qui y fabrique (journal puis `None`) n'est pas jugé ici.\n"
          "  * un bras dont le corps NOMME `QueryReturnedNoRows` est cru : il distingue l'absence lui-même ; un corps qui "
          "la nomme mais rend quand même 404 sur l'échec quelconque passerait.\n"
          "  * l'aveu est celui de la garde sœur (`bras_derreur_garde`) : cause portée HORS journal, statut d'échec, "
          "abandon compté, constructeur `/// AVEU`. Une cause portée dans une valeur servie mais fausse (le nom de "
          "l'erreur glissé dans un 200) est lue comme un aveu ; une liste d'aveux maison (`non_lus.push(..)`) ne l'est "
          "pas (faux positif écrit dans SITES_ADMIS).\n"
          "  * les modules `#[cfg(test)]` en ligne sont coupés à partir du premier (lecteur partagé `coupe_tests`).\n"
          "  * le statut se lit par son NOM (`StatusCode::NOT_FOUND`) ou par un constructeur du dépôt : un statut "
          "numérique (`StatusCode::from_u16(404)`), une redirection (`Redirect::to`, lue « valeur ») ou un constructeur "
          "de refus d'un autre nom passent par le lecteur sœur. Un jet de la cause n'est vu que sous `drop(e)`, "
          "`std::mem::drop(e)` et `let _ = e;` : la cause glissée dans une variable jamais servie est lue comme portée.\n"
          "  * elle ne prouve rien à l'exécution : un bras jugé honnête n'est pas un 503 servi — ce sont les témoins des "
          "vagues `ad_` à `ag_` qui le jouent.")


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
        print("::error::aucun `rusqlite` dans daemon/Cargo.toml : `query_row` n'a plus d'ancrage. La garde REFUSE DE "
              "CONCLURE.")
        ce_qui_n_est_pas_tenu()
        return 2
    compteurs = {}
    sites, journal, aveux_du_lecteur, population, fichiers = decouvrir(compteurs=compteurs)
    if aveux_du_lecteur and refuser_sur_aveu(ETIQUETTE, aveux_du_lecteur, "Rust"):
        ce_qui_n_est_pas_tenu()
        return 2
    if journal:
        for a in journal:
            print(f"::error::{a}")
        print(f"\n[{ETIQUETTE}] REFUS DE CONCLURE — le lecteur avoue avoir perdu une expression.")
        ce_qui_n_est_pas_tenu()
        return 2
    if population < PLANCHER_SITES or len(fichiers) < PLANCHER_FICHIERS:
        print(f"::error::{population} `match` à chaîne nue sur {len(fichiers)} fichier(s), planchers "
              f"{PLANCHER_SITES}/{PLANCHER_FICHIERS} (dérivés le 2026-10-23 : {RELEVE_SITES} sur {RELEVE_FICHIERS}, règle "
              "des deux tiers). La lecture est cassée, ou un lot a passé assez de sites en trois issues pour que les "
              "planchers doivent être RE-DÉRIVÉS, date écrite. La garde REFUSE DE CONCLURE.")
        ce_qui_n_est_pas_tenu()
        return 2
    for chemin, ligne, fn, forme, extrait in sorted(sites):
        print(f"::notice file={chemin},line={ligne}::`{fn}` sert l'échec d'une lecture à chaîne nue (`{forme}`) — "
              f"`{extrait}`")
    ecarts = juger_contre_l_ensemble(sites, SITES_ADMIS)
    print(f"\n[{ETIQUETTE}] POPULATION du jour : {population} `match` à chaîne nue sur {len(fichiers)} fichier(s) de "
          f"daemon/src/handlers, et {compteurs.get('map_err', 0)} lecture(s) `… .map_err(..)?` sans `.optional()` "
          f"(seconde jambe) ; {len(sites)} site(s) qui fabriquent, "
          f"{sum(len(v) for v in SITES_ADMIS.values())} admis par l'ensemble nommé.")
    if ecarts:
        for _g, chemin, phrase in ecarts:
            print(f"::error file={chemin}::{phrase}")
        print(f"::error::{len(ecarts)} écart(s) entre l'arbre et l'ensemble nommé ; il se corrige à la main, AVEC la "
              "raison.")
        ce_qui_n_est_pas_tenu()
        return 1
    print(f"[{ETIQUETTE}] l'ensemble nommé est EXACTEMENT ce que l'arbre porte. CE QUE CE VERT NE DIT PAS : les sites "
          "admis sont des DÉFAUTS CONNUS ; le vert dit seulement qu'aucun bras qui fabrique n'est entré.")
    ce_qui_n_est_pas_tenu()
    return 0


if __name__ == "__main__":
    sys.exit(main())
