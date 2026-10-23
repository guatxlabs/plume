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
  * `let _.is_ok`, `let _.is_err` et leurs formes d'instruction nue — le test jeté ;
  * `let nom jamais lu`, `let nom jeté` (`P10.28-b`, 2026-10-23) — le `Result` LIÉ à un nom (`let r = <borne>;`) que
    la fonction ne lit jamais ensuite, ou ne touche que pour le jeter (`let _ = r;`, `drop(r)`, `r;`), ou re-lie
    avant toute lecture (lecteur `devenir_du_nom`) ;
  * `Err sans ROLLBACK` (`P10.28-b`) — la branche d'échec d'un `COMMIT` LITTÉRAL (`COMMIT`, `END`, `RELEASE`) qui
    PARLE sans fermer la transaction : bras `Err(..)`, `_` ou nom nu (`autre =>`) d'un `match`, bloc d'un
    `if let Err(..)`, bloc d'un `if … .is_err()`, bloc `else` d'un `let Ok(..) = … else`, dont le corps n'exécute pas
    de `ROLLBACK` (littéral en premier argument d'un `execute_batch`/`execute`, un message qui contient le mot ne
    compte pas) et n'appelle aucun FERMEUR (fonction LIBRE du corpus, hors `#[cfg(test)]`, dont le corps exécute ce
    `ROLLBACK`, dérivée un niveau ; une méthode n'en est pas une). Le garde `Txn`, la transaction rusqlite et les
    juges ne sont pas accusés : ils se ferment à leur destruction, ou ferment eux-mêmes ;
  * `juge sans ROLLBACK` (`P10.28-b`) — un juge de genre `COMMIT` (`valider_la_transaction`) DÉFINI sans exécuter
    de `ROLLBACK` : c'est sa fermeture qui le sort de la forme précédente.
Les deux formes de `P10.28-b` lisent À TRAVERS une chaîne de seuls TRAVERSANTS (`.map_err(..)`, `.inspect_err(..)`,
…) sans `?` : elle rend encore le `Result`. La fermeture d'un traversant d'ÉCHEC (`map_err`, `or_else`,
`inspect_err`) qui exécute le `ROLLBACK` ferme la branche ; celle d'un traversant de succès (`map`) non.

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
        ABSORBANTS, ARBRE_FABRIQUE, SOURCES_ATTENDUES, TRAVERSANTS, apparier, chaine_detaillee, coupe_tests,
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
# `P10.28-b`, forme (a) : la tête d'une liaison NOMMÉE (`let r =`, `let mut r: T =`). `let _ =` n'y entre pas : `_`
# n'est pas un nom (c'est la liaison sourde, lue plus haut) ; `let _r =` y entre, et son nom est suivi comme un autre.
TETE_LIEE = re.compile(r"\A\s*let\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::\s*[^=]*?)?=\s*")
# `P10.28-b`, forme (b) : ce qui FERME une transaction après un `COMMIT` refusé — un littéral `ROLLBACK` (simple ou
# brut, `ROLLBACK TO` compris), ou l'appel d'un FERMEUR : une fonction dont le corps porte lui-même ce littéral
# (`end_failed_write_tx`, `annuler_le_tableau_oac`, `valider_la_transaction`). L'ensemble des fermeurs est DÉRIVÉ du
# corpus, un niveau, jamais une liste écrite à la main.
# Le littéral n'est lu qu'en PREMIER ARGUMENT d'un `execute_batch`/`execute` (ou de son `&format!(..)`) : un message
# qui contient le mot (`eprintln!("ROLLBACK impossible")`) ne ferme rien.
LITTERAL_ROLLBACK = re.compile(r'\.\s*(?:execute_batch|execute)\s*\(\s*(?:&\s*format!\s*\(\s*)?r?#*"\s*ROLLBACK\b',
                               re.I)
# Les traversants dont la fermeture ne s'exécute QUE sur l'échec : elle est une branche d'échec de la borne.
TRAVERSANTS_D_ECHEC = ("map_err", "or_else", "inspect_err")
# Un motif de bras qui LIE tout ce qui reste : `_`, ou un nom nu (`autre =>`), éventuellement `ref`/`mut`.
MOTIF_FOURRE_TOUT = re.compile(r"(?:ref\s+)?(?:mut\s+)?[a-z_]\w*")
# `let Ok(..) = <borne> else { … };` — le let-else dont le bloc `else` est la branche d'échec.
TETE_LET_ELSE_OK = re.compile(r"\A\s*let\s+Ok\s*\([^=]*\)\s*=\s*", re.S)

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


def fermeurs_du_texte(code):
    """Les noms des FONCTIONS LIBRES du texte dont le corps exécute un `ROLLBACK` (littéral en premier argument d'un
    `execute_batch`/`execute`) : appeler l'une d'elles ferme la transaction (`P10.28-b`, forme (b)). Une MÉTHODE
    (`self` dans sa signature, `impl Drop … fn drop(&mut self)`) n'en est pas une : elle ne s'appelle qu'en `.nom(`, que
    `ferme_la_transaction` ne lit pas, et son nom nu désignerait une autre fonction (`drop(e)` est celle du prélude)."""
    return {nom for nom, sig, b, f in fonctions(code)
            if not re.search(r"\bself\b", sig) and LITTERAL_ROLLBACK.search(code[b:f + 1])}


def ferme_la_transaction(corps, fermeurs):
    """Le corps d'une branche d'échec ferme-t-il la transaction ? Littéral `ROLLBACK`, ou appel LIBRE d'un fermeur."""
    if LITTERAL_ROLLBACK.search(corps):
        return True
    return any(re.search(r"(?<![\w.])" + re.escape(n) + r"\s*\(", corps) for n in fermeurs)


def _fin_d_expression(code, i, fin):
    """L'index où s'arrête l'expression qui commence en `i` : première `,`, `;` ou fermante non appariée, à
    profondeur nulle (corps d'une fermeture sans accolade, corps d'un bras sans accolade)."""
    prof, j = 0, i
    while j < fin:
        c = code[j]
        if c in "([{":
            prof += 1
        elif c in ")]}":
            if prof == 0:
                return j
            prof -= 1
        elif c in ",;" and prof == 0:
            return j
        j += 1
    return fin


def _bloc_ou_expression(code, i, fin):
    """(début, fin) de ce qui suit `i` : le bloc `{…}` s'il en ouvre un, sinon l'expression."""
    while i < fin and code[i] in " \t\n":
        i += 1
    if code[i:i + 1] == "{":
        f = apparier(code, i)
        return (i, f if f > 0 else fin)
    return (i, _fin_d_expression(code, i, fin))


def _premier_bloc(code, i, fin):
    """(début, fin) du premier bloc `{…}` à profondeur nulle après `i` (corps d'un `for`, d'un `if let`)."""
    prof, j = 0, i
    while j < fin:
        c = code[j]
        if c in "([":
            prof += 1
        elif c in ")]":
            prof -= 1
        elif c == "{" and prof == 0:
            f = apparier(code, j)
            return (j, f if f > 0 else fin)
        elif c == ";" and prof == 0:
            return None
        j += 1
    return None


def _fin_du_bloc_interieur(code, depuis, i, fin, spans):
    """Si `i` est dans un bloc OUVERT après `depuis` (profondeur d'accolades positive, littéraux sautés), l'index de la
    fermante de ce bloc ; sinon None (même bloc que la liaison suivie)."""
    prof = 0
    for j in range(depuis, i):
        if code[j] in "{}" and not dans_une_chaine_rust(spans, j):
            prof += 1 if code[j] == "{" else -1
    if prof <= 0:
        return None
    prof = 0
    for j in range(i, fin):
        if code[j] in "{}" and not dans_une_chaine_rust(spans, j):
            if code[j] == "}":
                if prof == 0:
                    return j
                prof -= 1
            else:
                prof += 1
    return fin


def portees_d_homonymes(code, nom, depuis, fin):
    """`P10.28-b` (a) : les plages `[(a, b)]` où `nom` désigne une AUTRE liaison que le `Result` suivi — paramètre de
    fermeture (`|nom| …`), `for nom in … { … }`, motif d'un `if let`/`while let`, `Ok(nom)`/`Err(nom)`/`Some(nom)` d'un
    bras de `match`. Le nom LIANT et ses usages dans la plage ne lisent pas le `Result`. Une liaison par motif de TUPLE
    dans un bras (`(a, nom) =>`) n'est pas lue : son usage compte comme une lecture (limite écrite, jamais une fausse
    accusation)."""
    mot = re.compile(r"(?<![\w.])" + re.escape(nom) + r"\b")
    out = []
    for m in re.finditer(r"\|([^|;{}]*)\|", code[depuis:fin]):
        a = depuis + m.start()
        k = a - 1
        while k >= 0 and code[k] in " \t\n":
            k -= 1
        avant = code[max(0, k - 4):k + 1]
        if not (code[k:k + 1] in "(,={;" or avant.endswith("move")) or not mot.search(m.group(1)):
            continue
        out.append((a, _bloc_ou_expression(code, depuis + m.end(), fin)[1]))
    for m in re.finditer(r"\bfor\s+([^;{}]*?)\s+in\b", code[depuis:fin]):
        if mot.search(m.group(1)):
            bloc = _premier_bloc(code, depuis + m.end(), fin)
            if bloc:
                out.append((depuis + m.start(), bloc[1]))
    for m in re.finditer(r"\b(?:if|while)\s+let\s+([^=;{}]*?)\s*=(?![=>])", code[depuis:fin]):
        if mot.search(m.group(1)):
            bloc = _premier_bloc(code, depuis + m.end(), fin)
            if bloc:
                # La plage saute le scrutateur : `if let Err(e) = nom {` LIT `nom`.
                out.append((depuis + m.start(1), depuis + m.end(1)))
                out.append(bloc)
    motif_bras = re.compile(r"\b(?:Ok|Err|Some)\s*\(\s*(?:ref\s+)?(?:mut\s+)?" + re.escape(nom)
                            + r"\s*\)\s*(?:if\b[^{};]*?)?=>")
    for m in motif_bras.finditer(code[depuis:fin]):
        out.append((depuis + m.start(), _bloc_ou_expression(code, depuis + m.end(), fin)[1]))
    return out


def devenir_du_nom(code, nom, depuis, fin, spans):
    """`P10.28-b`, forme (a) : ce que devient le `Result` lié à `nom` entre `depuis` (après le `;` de sa liaison) et
    `fin` (fin de la FONCTION englobante). Rend `jamais lu`, `jeté` (seuls usages : `let _ = nom;`, `drop(nom)`,
    `nom;`), ou None quand le nom est LU — son devenir ensuite n'est pas suivi (limite écrite). Un HOMONYME (paramètre de
    fermeture, `for`, motif d'`if let` ou de bras) n'est pas une lecture (`portees_d_homonymes`). Une RE-LIAISON du même
    nom (`let nom = …`, `let (a, nom) = …`) ferme la portée — l'ancien `Result` n'est plus nommable — SAUF si son membre
    droit le lit (`let nom = nom.map_err(..)`) : c'est alors une lecture. Dans un bloc INTÉRIEUR, la re-liaison n'ombre
    le nom que jusqu'à la fin de ce bloc."""
    corps = code[depuis:fin]
    homonymes = portees_d_homonymes(code, nom, depuis, fin)

    def masque(i):
        return dans_une_chaine_rust(spans, i) or any(a <= i < b for a, b in homonymes)
    # Un argument de format en ligne (`"{r:?}"`) LIT le nom depuis un littéral : c'est une lecture.
    if re.search(r"\{" + re.escape(nom) + r"[:}]", corps):
        return None
    usages = 0
    for m in re.finditer(r"(?<![\w.])" + re.escape(nom) + r"\b", corps):
        i = depuis + m.start()
        if masque(i):
            continue
        # `avant` remonte AU-DELÀ de `depuis` : le `;` de la liaison elle-même borne un `r;` qui la suit.
        avant, apres = code[max(0, i - 40):i], code[i + len(nom):i + len(nom) + 40]
        if re.search(r"\blet\s+[^=;{}]*\Z", avant) and not re.search(r"\b(?:if|while)\s+let\s+[^=;{}]*\Z", avant):
            # re-liaison : la portée du `Result` s'arrête là, sauf si le membre droit le lit
            eg = re.search(r"=(?![=>])", code[i:fin])
            if eg:
                droit_deb = i + eg.end()
                droit_fin = _fin_d_expression(code, droit_deb, fin)
                for r in re.finditer(r"(?<![\w.])" + re.escape(nom) + r"\b", code[droit_deb:droit_fin]):
                    if not masque(droit_deb + r.start()):
                        return None
            fin_interieure = _fin_du_bloc_interieur(code, depuis, i, fin, spans)
            if fin_interieure is None:
                break
            # re-liaison dans un bloc INTÉRIEUR : elle n'ombre le nom que jusqu'à la fin de ce bloc.
            homonymes.append((i, fin_interieure))
            continue
        if re.match(r"\s*[;)]", apres) and (re.search(r"\blet\s+_\s*=\s*&?\s*\Z", avant)
                                            or re.search(r"\bdrop\s*\(\s*\Z", avant)
                                            or re.search(r"[;{}]\s*\Z", avant)):
            usages += 1
            continue
        return None
    return "jeté" if usages else "jamais lu"


def branche_d_echec_sans_fermeture(code, debut, ouvrante, apres, prefixe, dernier, fermeurs, close_par_la_chaine=False):
    """`P10.28-b`, forme (b) : la branche d'ÉCHEC d'un `COMMIT` littéral qui PARLE (corps non vide) sans fermer la
    transaction. Écritures lues : bras `Err(..)`, `_` ou nom nu (`autre =>`) d'un `match` dont la borne est le
    scrutateur, bloc d'un `if let Err(..) = <borne>`, bloc d'un `if <borne>.is_err()`, bloc `else` d'un
    `let Ok(..) = <borne> else { … };`. La borne peut porter une chaîne de TRAVERSANTS (`.map_err(..)`, …) : quand la
    fermeture d'un traversant d'échec (`map_err`, `or_else`, `inspect_err`) ferme elle-même la transaction
    (`close_par_la_chaine`), la branche l'est. Rend la forme, ou None."""
    # Un corps VIDE est déjà rendu `Err muet` plus haut, avant cet appel : il n'arrive jamais ici.
    def parle_sans_fermer(corps):
        return not close_par_la_chaine and not ferme_la_transaction(corps, fermeurs)
    bloc = bloc_suivant(code, apres)
    if dernier == "is_err":
        if re.search(r"\bif\b[^;{}]*\Z", prefixe) and bloc and parle_sans_fermer(code[bloc[0] + 1:bloc[1]]):
            return "Err sans ROLLBACK"
        return None
    if dernier:
        return None
    if if_let_est_le_scrutateur(code, ouvrante, MOTIF_ERR):
        if bloc and parle_sans_fermer(code[bloc[0] + 1:bloc[1]]):
            return "Err sans ROLLBACK"
        return None
    tete_let_else = TETE_LET_ELSE_OK.match(prefixe)
    if tete_let_else and recepteur_seul(prefixe[tete_let_else.end():]):
        sinon = re.match(r"\s*else\b", code[apres:apres + 16])
        bloc_sinon = bloc_suivant(code, apres + sinon.end()) if sinon else None
        if bloc_sinon and parle_sans_fermer(code[bloc_sinon[0] + 1:bloc_sinon[1]]):
            return "Err sans ROLLBACK"
        return None
    if re.search(r"\bmatch\b[^;{}]*\Z", prefixe) and bloc:
        for motif, corps in bras_du_match(code, bloc[0]):
            m = " ".join(motif.split())
            if (MOTIF_ERR.match(m) or MOTIF_FOURRE_TOUT.fullmatch(m)) and parle_sans_fermer(corps):
                return "Err sans ROLLBACK"
    return None


def formes_du_result_lie_ou_parlant(code, prefixe, apres, debut, ouvrante, fns, spans, fermeurs, commit_litteral,
                                    jetons):
    """Les deux formes de `P10.28-b`, sur une borne à chaîne NUE ou faite de seuls TRAVERSANTS (sans `?`) : la chaîne
    de traversants rend encore le `Result`, elle n'est pas une propagation tant qu'aucun `?` ni `return` ne suit."""
    lie = TETE_LIEE.match(prefixe)
    if lie and fns is not None and code[apres:apres + 1] == ";" and recepteur_seul(prefixe[lie.end():]):
        englobante = portee_englobante(fns, debut)
        if englobante:
            devenir = devenir_du_nom(code, lie.group(1), apres + 1, englobante[3], spans or [])
            if devenir:
                return f"let nom {devenir}"
    if commit_litteral:
        return branche_d_echec_sans_fermeture(code, debut, ouvrante, apres, prefixe, "", fermeurs,
                                              chaine_qui_ferme(code, jetons, fermeurs))
    return None


def chaine_qui_ferme(code, jetons, fermeurs):
    """La fermeture d'un traversant d'ÉCHEC de la chaîne (`map_err`, `or_else`, `inspect_err`) ferme-t-elle la
    transaction ? Elle ne s'exécute que sur l'échec : elle EST alors la branche d'échec qui ferme."""
    return any(nom in TRAVERSANTS_D_ECHEC and a1 >= 0 and ferme_la_transaction(code[a1:a2], fermeurs)
               for nom, _i, a1, a2 in jetons)


def forme_avalee(code, coupes, genre, debut, ouvrante, juge, fns=None, spans=None, fermeurs=frozenset()):
    """La façon dont la borne est avalée, ou None quand son `Result` est jugé, propagé ou lié puis LU.
    `fns`, `spans` et `fermeurs` servent aux deux formes de `P10.28-b` ; absents, elles ne sont pas lues."""
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
    # `P10.28-b` (b) : seul un `COMMIT` LITTÉRAL laisse la transaction ouverte quand il est refusé. Le garde `Txn` et la
    # transaction rusqlite se ferment à leur destruction ; les juges (`valider_la_transaction`) ferment eux-mêmes.
    commit_litteral = genre == "COMMIT" and not juge and bool(APPEL_SQL.match(code, debut))
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
        if commit_litteral:
            return branche_d_echec_sans_fermeture(code, debut, ouvrante, apres, prefixe, dernier, fermeurs,
                                                  chaine_qui_ferme(code, jetons, fermeurs))
        return None
    # `P10.28-b` : une chaîne de seuls TRAVERSANTS (`.map_err(..)`, `.inspect_err(..)`, …) sans `?` rend encore le
    # `Result` ; `verdict_de_la_chaine` (partagé) la dit « propage », et les formes d'AVANT `P10.28-b` gardent ce
    # verdict (limite écrite). Les deux formes neuves, elles, la lisent comme une chaîne nue.
    if verdict == "propage" and jetons and all(j[0] in TRAVERSANTS for j in jetons):
        return formes_du_result_lie_ou_parlant(code, prefixe, apres, debut, ouvrante, fns, spans, fermeurs,
                                               commit_litteral, jetons)
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
    return formes_du_result_lie_ou_parlant(code, prefixe, apres, debut, ouvrante, fns, spans, fermeurs,
                                           commit_litteral, jetons)


def analyser(chemin_relatif, texte, journal, aveux_du_lecteur=None, fermeurs_du_corpus=frozenset()):
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
    fermeurs = set(fermeurs_du_corpus) | fermeurs_du_texte(code)
    for genre, debut, ouvrante, juge in bornes_du_texte(code, spans):
        population += 1
        forme = forme_avalee(code, coupes, genre, debut, ouvrante, juge, fns, spans, fermeurs)
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
    # `P10.28-b` (b) : un JUGE de genre `COMMIT` sort de la forme (b) parce qu'il FERME lui-même la transaction qu'un
    # `COMMIT` refusé laisse ouverte. Défini ici, son corps exécute donc un `ROLLBACK` (littéral lu comme ci-dessus) ;
    # sans lui, chacun de ses appelants serait une branche d'échec qui ne ferme rien.
    for nom, _sig, b, f in fns:
        if GENRE_DU_JUGE.get(nom) == "COMMIT" and not LITTERAL_ROLLBACK.search(code[b:f + 1]):
            sites.append((chemin_relatif, code.count("\n", 0, b) + 1, nom, "COMMIT juge sans ROLLBACK",
                          " ".join(code[b:b + 120].split())[:140]))
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


def decouvrir(racine=None):
    """`racine` ne sert qu'aux épreuves sur un arbre FABRIQUÉ (le fermeur défini dans un autre fichier)."""
    sites, journal, aveux_du_lecteur, population, fichiers = [], [], {}, 0, set()
    textes = []
    for chemin in fichiers_du_corpus(racine):
        with open(chemin, encoding="utf-8", errors="replace") as fh:
            textes.append((chemin, fh.read()))
    # Les FERMEURS (`P10.28-b`, forme (b)) se dérivent sur tout le corpus d'abord : un bras d'échec peut appeler une
    # fonction d'annulation définie dans un autre fichier.
    fermeurs = set()
    for _chemin, texte in textes:
        fermeurs |= fermeurs_du_texte(coupe_tests(sans_commentaires_rust(texte, [])))
    for chemin, texte in textes:
        rel = os.path.relpath(chemin, RACINE).replace(os.sep, "/")
        s, n = analyser(rel, texte, journal, aveux_du_lecteur, fermeurs)
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
    # --- `P10.28-b` (a) : le `Result` LIÉ à un nom puis jeté.
    ("p19 `let r = … COMMIT` jamais lu", _f('    let r = conn.execute_batch("COMMIT");\n    ok()'),
     {"COMMIT let nom jamais lu"}),
    ("p20 le juge lié puis `drop(r)`", _f('    let r = valider_la_transaction(conn);\n    drop(r);\n    ok()'),
     {"COMMIT let nom jeté"}),
    ("p21 lié puis re-lié avant toute lecture",
     _f('    let r = conn.execute_batch("BEGIN IMMEDIATE");\n    let r = ecrire(conn);\n    rendre(r)'),
     {"BEGIN let nom jamais lu"}),
    ("p22 lié puis `let _ = r;`", _f('    let mut fin = tx.commit();\n    let _ = fin;\n    ok()'), {"COMMIT let nom jeté"}),
    ("p28 lié puis `r;` (instruction nue)", _f('    let r = conn.execute_batch("COMMIT");\n    r;\n    ok()'),
     {"COMMIT let nom jeté"}),
    ("p27 le nom cité dans un littéral n'est pas une lecture",
     _f('    let r = conn.execute_batch("COMMIT");\n    eprintln!("r validé");\n    ok()'), {"COMMIT let nom jamais lu"}),
    # --- `P10.28-b` (b) : la branche d'échec d'un `COMMIT` LITTÉRAL qui parle sans fermer la transaction.
    ("p23 bras `Err(e)` qui refuse sans ROLLBACK",
     _f('    match conn.execute_batch("COMMIT") {\n        Ok(()) => ok(),\n        Err(e) => refus(e),\n    }'),
     {"COMMIT Err sans ROLLBACK"}),
    ("p24 `if let Err(e)` qui parle sans ROLLBACK",
     _f('    if let Err(e) = conn.execute_batch("COMMIT") {\n        eprintln!("{e}");\n        return refus();\n    }\n    ok()'),
     {"COMMIT Err sans ROLLBACK"}),
    ("p25 `if … .is_err()` qui parle sans ROLLBACK",
     _f('    if conn.execute_batch("COMMIT").is_err() {\n        return refus();\n    }\n    ok()'),
     {"COMMIT Err sans ROLLBACK"}),
    ("p26 bras fourre-tout `_` d'un `END`",
     _f('    match conn.execute("END", []) {\n        Ok(_) => ok(),\n        _ => refus(),\n    }'),
     {"COMMIT Err sans ROLLBACK"}),
    # --- `P10.28-b`, correction : à travers une chaîne de TRAVERSANTS, les homonymes, la portée, les autres bras.
    ("p29 lié à travers `.map_err(..)` jamais lu",
     _f('    let validation = conn.execute_batch("COMMIT").map_err(|e| e.to_string());\n    ok()'),
     {"COMMIT let nom jamais lu"}),
    ("p30 lié à travers `.inspect_err(..)` jamais lu",
     _f('    let r = conn.execute_batch("COMMIT").inspect_err(|e| eprintln!("{e}"));\n    ok()'), {"COMMIT let nom jamais lu"}),
    ("p31 `if let Err` à travers `.map_err(..)` qui parle sans ROLLBACK",
     _f('    if let Err(e) = conn.execute_batch("COMMIT").map_err(|e| e.to_string()) {\n        return refus(e);\n    }\n'
        '    ok()'), {"COMMIT Err sans ROLLBACK"}),
    ("p32 `match` à travers `.map_err(..)` dont le bras parle sans ROLLBACK",
     _f('    match conn.execute_batch("COMMIT").map_err(|e| e.to_string()) {\n        Ok(()) => ok(),\n'
        '        Err(e) => refus(e),\n    }'), {"COMMIT Err sans ROLLBACK"}),
    ("p33 un paramètre de fermeture homonyme n'est pas une lecture",
     _f('    let r = conn.execute_batch("COMMIT");\n    let n: Vec<i64> = v.into_iter().map(|r| r + 1).collect();\n    ok()'),
     {"COMMIT let nom jamais lu"}),
    ("p34 un bras `Ok(r)` homonyme n'est pas une lecture",
     _f('    let r = conn.execute_batch("COMMIT");\n    match lire(conn) {\n        Ok(r) => rendre(r),\n'
        '        Err(_) => refus(),\n    }'), {"COMMIT let nom jamais lu"}),
    ("p35 un `for r in` homonyme n'est pas une lecture",
     _f('    let r = conn.execute_batch("COMMIT");\n    for r in lignes {\n        ecrire(r);\n    }\n    ok()'),
     {"COMMIT let nom jamais lu"}),
    ("p36 un motif d'`if let` homonyme n'est pas une lecture",
     _f('    let r = conn.execute_batch("COMMIT");\n    if let Some(r) = lire(conn) {\n        ecrire(r);\n    }\n    ok()'),
     {"COMMIT let nom jamais lu"}),
    ("p37 la portée du nom est la FONCTION : un homonyme lu plus bas, ailleurs, ne compte pas",
     _f('    let r = conn.execute_batch("COMMIT");\n    ok()') + 'fn g(r: R) -> R {\n    rendre(r)\n}\n',
     {"COMMIT let nom jamais lu"}),
    ("p38 fourre-tout NOMMÉ (`autre =>`) qui parle sans ROLLBACK",
     _f('    match conn.execute_batch("COMMIT") {\n        Ok(()) => ok(),\n        autre => refus(autre),\n    }'),
     {"COMMIT Err sans ROLLBACK"}),
    ("p39 let-else dont le `else` parle sans ROLLBACK",
     _f('    let Ok(()) = conn.execute_batch("COMMIT") else {\n        return refus();\n    };\n    ok()'),
     {"COMMIT Err sans ROLLBACK"}),
    ("p40 le mot ROLLBACK dans un MESSAGE ne ferme rien",
     _f('    if let Err(e) = conn.execute_batch("COMMIT") {\n        eprintln!("ROLLBACK impossible {e}");\n'
        '        return refus();\n    }\n    ok()'), {"COMMIT Err sans ROLLBACK"}),
    ("p41 un fermeur appelé en MÉTHODE (`.annuler(`) est une autre fonction",
     'fn annuler(c: &Connection) {\n    let _ = c.execute_batch("ROLLBACK");\n}\n'
     + _f('    if let Err(e) = conn.execute_batch("COMMIT") {\n        tx.annuler();\n        return refus(e);\n    }\n'
          '    ok()'), {"COMMIT Err sans ROLLBACK"}),
    ("p42 `drop(e)` n'est pas un fermeur (la méthode `Drop::drop` qui annule ne lui donne pas son nom)",
     'impl Drop for Garde {\n    fn drop(&mut self) {\n        let _ = self.c.execute_batch("ROLLBACK");\n    }\n}\n'
     + _f('    if let Err(e) = conn.execute_batch("COMMIT") {\n        drop(e);\n        return refus();\n    }\n    ok()'),
     {"COMMIT Err sans ROLLBACK"}),
    ("p44 lié puis `let _ = &r;`", _f('    let r = conn.execute_batch("COMMIT");\n    let _ = &r;\n    ok()'),
     {"COMMIT let nom jeté"}),
    ("p45 la fermeture d'un traversant de SUCCÈS (`.map(..)`) n'est pas une branche d'échec",
     _f('    if let Err(e) = conn.execute_batch("COMMIT").map(|()| {\n        let _ = conn.execute_batch("ROLLBACK");\n'
        '    }) {\n        return refus(e);\n    }\n    ok()'), {"COMMIT Err sans ROLLBACK"}),
    ("p46 re-lié dans un bloc INTÉRIEUR, jamais lu", _f('    let r = conn.execute_batch("COMMIT");\n    {\n'
                                                        '        let r = 1;\n        ecrire(r);\n    }\n    ok()'),
     {"COMMIT let nom jamais lu"}),
    ("p43 le JUGE défini sans ROLLBACK",
     'fn valider_la_transaction(conn: &Connection) -> R {\n    conn.execute_batch("COMMIT").map_err(|refus| refus)\n}\n',
     {"COMMIT juge sans ROLLBACK"}),
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
    ("n11 match dont le bras d'erreur ferme puis refuse",
     _f('    match conn.execute_batch("COMMIT") {\n        Ok(()) => ok(),\n        Err(e) => {\n'
        '            let _ = conn.execute_batch("ROLLBACK");\n            refus(e)\n        }\n    }'), set()),
    ("n12 juge sous `if … is_ok()` (il dit lui-même son refus)",
     _f('    if a < b && ouvrir_sa_transaction(conn, "j", "g").is_ok() {\n        ecrire(conn);\n    }\n    ok()'), set()),
    ("n13 `if let Ok` AVEC else",
     _f('    if let Ok(tx) = Txn::begin(conn) {\n        tx.commit()?;\n    } else {\n        dire();\n    }\n    ok()'), set()),
    ("n14 garde Txn jugé", _f('    match tx.commit() {\n        Ok(()) => ok(),\n        Err(e) => refus(e),\n    }'), set()),
    # n15 porte le `ROLLBACK` du juge réel depuis `P10.28-b` (correction) : un juge défini SANS lui est accusé (p43).
    ("n15 définition du juge (qui ferme)", 'fn valider_la_transaction(conn: &Connection) -> rusqlite::Result<()> {\n'
                                           '    conn.execute_batch("COMMIT").map_err(|e| {\n'
                                           '        let _ = conn.execute_batch("ROLLBACK");\n        e\n    })\n}\n', set()),
    ("n16 la forme commune qui refuse (`P10.28-d`)",
     _f('    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "j", "g", CAUSE) {\n        return refus;\n    }\n    ok()'), set()),
    ("n18 lié puis LU (son devenir n'est pas suivi : limite écrite)",
     _f('    let r = conn.execute_batch("COMMIT");\n    rendre(r)'), set()),
    ("n19 lié puis lu par un argument de format en ligne",
     _f('    let r = conn.execute_batch("COMMIT");\n    eprintln!("{r:?}");\n    ok()'), set()),
    ("n20 lié puis propagé", _f('    let r = tx.commit();\n    r?;\n    ok()'), set()),
    ("n21 bras d'échec qui appelle un FERMEUR dérivé",
     'fn annuler(c: &Connection) {\n    let _ = c.execute_batch("ROLLBACK TO s");\n}\n'
     + _f('    if let Err(e) = conn.execute_batch("RELEASE s") {\n        annuler(conn);\n        return refus(e);\n    }\n    ok()'),
     set()),
    ("n22 garde `Txn` dont le bras parle (il se ferme à sa destruction)",
     _f('    match tx.commit() {\n        Ok(()) => ok(),\n        Err(e) => { eprintln!("{e}"); refus(e) }\n    }'), set()),
    ("n23 juge dont le bras parle (il ferme lui-même)",
     _f('    if let Err(refus) = valider_la_transaction(conn) {\n        return refus;\n    }\n    ok()'), set()),
    ("n24 BEGIN dont le bras parle (aucune transaction n'est ouverte)",
     _f('    match conn.execute_batch("BEGIN IMMEDIATE") {\n        Ok(()) => ok(),\n        Err(e) => refus(e),\n    }'), set()),
    ("n25 `is_err` d'un COMMIT qui ferme", _f('    if conn.execute_batch("COMMIT").is_err() {\n'
                                            '        let _ = conn.execute_batch("ROLLBACK");\n        return refus();\n    }\n    ok()'), set()),
    ("n26 le traversant d'échec FERME lui-même",
     _f('    if let Err(e) = conn.execute_batch("COMMIT").map_err(|e| {\n        let _ = conn.execute_batch("ROLLBACK");\n'
        '        e\n    }) {\n        return refus(e);\n    }\n    ok()'), set()),
    ("n27 une re-liaison qui LIT le nom (`let r = r.map_err(..)`)",
     _f('    let r = conn.execute_batch("COMMIT");\n    let r = r.map_err(|e| e.to_string());\n    rendre(r)'), set()),
    ("n28 lié à travers `.map_err(..)` puis lu", _f('    let r = conn.execute_batch("COMMIT").map_err(|e| e);\n    rendre(r)'),
     set()),
    ("n30 let-else qui ferme",
     _f('    let Ok(()) = conn.execute_batch("COMMIT") else {\n        let _ = conn.execute_batch("ROLLBACK");\n'
        '        return refus();\n    };\n    ok()'), set()),
    ("n31 la portée d'un homonyme s'arrête à sa fermeture : la lecture d'après compte",
     _f('    let r = conn.execute_batch("COMMIT");\n    let n = v.map(|r| r + 1);\n    rendre(r)'), set()),
    ("n32 `if let` qui LIT le nom en scrutateur, motif homonyme",
     _f('    let r = conn.execute_batch("COMMIT");\n    if let Err(r) = r {\n        let _ = conn.execute_batch("ROLLBACK");\n'
        '        return refus(r);\n    }\n    ok()'), set()),
    ("n35 re-lié dans un bloc INTÉRIEUR, puis LU après lui",
     _f('    let r = conn.execute_batch("COMMIT");\n    {\n        let r = 1;\n        ecrire(r);\n    }\n    rendre(r)'),
     set()),
    ("n33 le bras ferme par un `ROLLBACK TO` formaté",
     _f('    if let Err(e) = conn.execute_batch("RELEASE p") {\n        let _ = conn.execute_batch(&format!("ROLLBACK TO {P}"));\n'
        '        return refus(e);\n    }\n    ok()'), set()),
    ("n34 `.map_err(..)` qui ferme puis `.is_err()`",
     _f('    if conn.execute_batch("COMMIT").map_err(|e| {\n        let _ = conn.execute_batch("ROLLBACK");\n        e\n'
        '    }).is_err() {\n        return refus();\n    }\n    ok()'), set()),
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


def epreuve_du_fermeur_d_un_autre_fichier():
    """`P10.28-b` (b) : un bras d'échec qui appelle un fermeur DÉFINI DANS UN AUTRE FICHIER ferme la transaction — les
    fermeurs se dérivent sur tout le corpus avant l'analyse. Dans les deux sens : sans le fermeur, le même bras rougit."""
    errs = []
    appelant = _f('    if let Err(e) = conn.execute_batch("COMMIT") {\n        annuler_ailleurs(conn);\n'
                  '        return refus(e);\n    }\n    ok()')
    fermeur = 'fn annuler_ailleurs(c: &Connection) {\n    let _ = c.execute_batch("ROLLBACK");\n}\n'
    # Troisième cas (`P10.28-b`, correction) : le même fermeur, défini dans un module `#[cfg(test)]` seulement — il
    # n'existe pas dans le démon livré, le bras qui l'appelle ne ferme rien.
    en_test = 'fn rien() {}\n#[cfg(test)]\nmod tests {\n    use super::*;\n' + fermeur + '}\n'
    for cas, src_fermeur in (("avec", fermeur), ("sans", "fn rien() {}\n"), ("en test", en_test)):
        with tempfile.TemporaryDirectory(prefix="plume-fermeur-") as racine:
            for nom, src in (("appelant.rs", appelant), ("fermeur.rs", src_fermeur)):
                with open(os.path.join(racine, nom), "w", encoding="utf-8") as fh:
                    fh.write(src)
            sites = decouvrir(racine)[0]
        formes = {f for _c, _l, _fn, f, _x in sites}
        if cas == "avec" and formes:
            errs.append(f"épreuve du FERMEUR d'un autre fichier : {sorted(formes)} accusé — les fermeurs ne sont plus "
                        "dérivés sur tout le corpus")
        if cas == "sans" and formes != {"COMMIT Err sans ROLLBACK"}:
            errs.append("épreuve du FERMEUR d'un autre fichier (sans lui) : le bras qui parle sans fermer n'est plus "
                        "accusé")
        if cas == "en test" and formes != {"COMMIT Err sans ROLLBACK"}:
            errs.append("épreuve du FERMEUR d'un autre fichier (défini sous `#[cfg(test)]`) : un fermeur des modules de "
                        "test est compté comme fermant le démon livré")
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
    redondante ; aucune épreuve ne prouve qu'elle est nécessaire.

    MUTATIONS JOUÉES le 2026-10-23 (`P10.28-b`), toutes en sortie 2 : `devenir_du_nom` muet (p19-p22) ; la re-liaison qui
    ne ferme plus la portée (p21) ; `jeté` lu comme une lecture (p20, p22) ; `let _ = r;`, `drop(r)` et `r;` oubliés un
    par un (p22, p20, p28) ; l'argument de format en ligne ignoré (n19) ; un nom cité dans un littéral lu (p27) ; la
    liaison nommée débranchée (p19) ; le littéral `ROLLBACK` ignoré (n5, n11) ; les fermeurs ignorés (n21, épreuve du
    fermeur) ; les fermeurs du FICHIER ou du CORPUS non dérivés (n21 ; épreuve du fermeur d'un autre fichier) ; le garde
    `Txn`/les juges accusés (n14, n22) ; le `BEGIN` accusé (n2, n24) ; chacune des trois écritures de branche d'échec
    débranchée (p23, p24, p25) et le fourre-tout `_` oublié (p26). Le premier essai de p28 a ROUGI SANS MUTATION : le
    contexte d'un `r;` était coupé au `;` de sa propre liaison ; corrigé avant ce relevé. Sur l'arbre du jour, les deux
    lecteurs n'accusent RIEN : zéro `Result` de borne lié à un nom, dix `COMMIT` littéraux dont toutes les branches
    d'échec ferment (`ROLLBACK`, `end_failed_write_tx`, `annuler_le_tableau_oac`).

    `P10.28-b`, CORRECTION (2026-10-23) — une vérification indépendante a trouvé les deux formes aveugles derrière un
    traversant (`if let Err(e) = conn.execute_batch("COMMIT").map_err(..)` sans `ROLLBACK`, `let validation = ….map_err(..);`
    jamais lu : verts sur une copie mutée du démon), trois mutants verts (portée au fichier, fermeur appelé en méthode,
    fermeurs des modules de test), un juge privé de son `ROLLBACK` vert, et des lectures fausses (homonyme pris pour une
    lecture, re-liaison qui lit accusée, fourre-tout nommé et let-else non jugés, `drop` et un message comptés fermants).
    MUTATIONS JOUÉES après correction, toutes en sortie 2 : traversants non lus (p29, p30) ; fermeture de chaîne ignorée
    (n26, n34) ; traversant de succès compté d'échec (p45) ; homonyme de fermeture, de `for`, d'`if let`, de bras ignoré un
    par un (p33, p35, p36, p34) ; portée d'une fermeture jusqu'à la fin (n31) ; scrutateur d'`if let` masqué (n32) ;
    re-liaison qui lit ignorée (n27) ; re-liaison qui ne ferme plus (p21) ; re-liaison intérieure (n35) ; fourre-tout nommé
    oublié (p38) ; let-else ignoré (p39) ; `ROLLBACK` lu dans un message (p40) ; `ROLLBACK TO` formaté oublié (n33) ;
    fermeur appelé en méthode (p41) ; méthodes fermeuses (p42) ; juge non jugé (p43) ; fermeurs des modules de test
    (épreuve du fermeur, cas « en test ») ; portée au fichier (p37) ; `let _ = &r;` lu (p44). Sur une copie mutée du démon
    (`purge.rs::purge_apply`, `transaction_validee.rs`) : `.map_err` puis `if let Err` sans `ROLLBACK`, `let validation =
    ….map_err(..)` jamais lu, fermeture homonyme `|validation|`, juge sans `ROLLBACK`, `autre =>` et let-else sans
    `ROLLBACK` sont accusés ; `let validation = validation.map_err(..)` puis lu ne l'est plus. Sur l'arbre (et sur l'arbre
    avec le lot voisin qui corrige `runbook_*`), toujours zéro accusation. `n11` (bras d'erreur d'un `COMMIT` qui refuse
    SANS `ROLLBACK`, négatif jusque-là) est devenu le positif `p23` ; `n15` porte désormais le `ROLLBACK` du juge réel."""
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
    errs += epreuve_du_fermeur_d_un_autre_fichier()
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
          "  * un `Result` de borne LIÉ à un nom (`P10.28-b`) n'est suivi que jusqu'à sa PREMIÈRE lecture : jamais lu, "
          "jeté ou re-lié avant lecture est accusé ; lu (`if let Err(e) = r`, `rendre(r)`, `r.is_ok()`, `let r = "
          "r.map_err(..)`), son devenir ensuite n'est pas suivi — un `r` lu puis avalé par une forme plus bas, ou rendu à "
          "un appelant qui le jette, passe. Le nom n'est pas suivi d'une fonction à l'autre. Un HOMONYME n'est reconnu "
          "que sous quatre écritures (paramètre de fermeture `|r|`, `for r in`, motif d'un `if let`/`while let`, bras "
          "`Ok(r)`/`Err(r)`/`Some(r)`) ; une re-liaison `let r` dans un bloc INTÉRIEUR n'ombre le nom que jusqu'à la fin "
          "de ce bloc. Un homonyme lié par un motif de TUPLE dans un bras (`(a, r) =>`) compte comme une lecture et fait "
          "taire l'accusation (jamais l'inverse).\n"
          "  * une branche d'échec de `COMMIT` qui parle (`P10.28-b`) n'est jugée que sur un `COMMIT` LITTÉRAL scruté "
          "AU SITE (`match`, `if let Err`, `if … .is_err()`, `let Ok(..) = … else`), chaîne nue ou de seuls traversants : "
          "la même branche sur un `Result` lié, l'`else` d'un `if let Ok(..)` ou d'un `if … .is_ok()`, et la chaîne "
          "PROPAGÉE (`….map_err(..)?`, ou rendue en expression finale) dont la fermeture d'échec ne fait pas de "
          "`ROLLBACK` — deux sites le 2026-10-23, `backup/dump_restauration.rs::restore_stream` et "
          "`cold_store/writer.rs::write_day_files`, hors gestionnaires, sur une connexion qui leur est propre — ne le "
          "sont pas ; seul le juge `valider_la_transaction` est tenu d'y fermer. Les formes d'AVANT `P10.28-b` (`let _`, "
          "instruction nue, `drop`, `if let Ok sans else`, `Err muet`) gardent le verdict partagé : derrière une chaîne "
          "de traversants (`let _ = conn.execute_batch(\"COMMIT\").map_err(..);`), elles ne sont pas lues. Un FERMEUR "
          "est une fonction LIBRE dont le corps exécute un `ROLLBACK`, OÙ QU'IL SOIT dans ce corps : une fonction qui "
          "annule une AUTRE transaction (un gestionnaire entier qui porte un `ROLLBACK` sur un autre chemin — le "
          "2026-10-23, 89 fermeurs dérivés, dont les gestionnaires d'écriture), un fermeur qui en appelle un autre, ou "
          "dont le `ROLLBACK` est sur une autre connexion, se lit comme fermant. Une méthode (`self`) n'est jamais un "
          "fermeur, même quand elle annule (`Txn::drop`) : un bras qui l'appelle en `.nom(` est accusé. C'est la sonde de "
          "`P10.27-g` (tick de détection) qui voit à l'exécution une transaction restée ouverte, pas cette garde.\n"
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
