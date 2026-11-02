#!/usr/bin/env python3
r"""Un `match` sur une lecture de ligne unique à chaîne NUE ne sert jamais son échec comme un FAIT — garde de CI
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

VAGUE BD (2026-10-29) — TROIS RESTES DE LA SECONDE JAMBE, ET UNE TROISIÈME JAMBE
--------------------------------------------------------------------------------
  * Une variante (ou une constante) dont le NOM avoue la lecture ratée (`Refus::NonLu("…")`, `CAUSE_X_NON_LUE`,
    `Illisible`) n'est plus accusée : elle sert l'absence en lecture ratée, fail-closed, la décision déjà prise pour le
    5xx (`n23`). Avant, elle aurait dû entrer dans `SITES_ADMIS`.
  * Une variante UNITAIRE (`|_| Refus::Absent`) et une variante à PLUSIEURS champs (`|_| Refus::Refusee("x", id)`)
    sont accusées — formes `variante unitaire` et `variante(plusieurs champs)`.
  * LE `Result` LIÉ PUIS `match` : `let r = conn.query_row(..); match r { .. Err(_) => not_found(..) }` est jugé par
    les mêmes bras que la jambe directe (forme préfixée `lié puis match : `), quand la liaison est l'instruction entière
    et que le `match` est la première apparition du nom dans la fonction. Population de l'arbre `fa44af5a` : 8, aucune
    accusée une fois l'aveu PAR LE NOM lu dans les bras (`(None, CAUSE_…_NON_RELU)`, quatre sites honnêtes qu'il aurait
    sinon fallu admettre : `case_create`, `connector_poll`, `destination_flush`, `playbooks_list`).

VAGUE BE (2026-10-29) — LA JAMBE LIÉE LIT L'OMBRE ET ENJAMBE LES FERMETURES ; L'AVEU PAR LE NOM EST RENDU À SA JAMBE
-----------------------------------------------------------------------------------------------------------------
  * `let r = conn.query_row(..); let r = match r { .. }` — la forme la plus écrite en Rust — passait : la règle de
    première apparition s'arrêtait sur le `r` du nouveau `let`, qui ne consomme rien. L'ombre `let <nom> = match
    <nom>` (type et `mut` tolérés) est enjambée, de même qu'un PARAMÈTRE de fermeture (`|r| r + 1`, `move |a, r| {..}`)
    et son corps, qui ombrent le nom. Une capture (`|| r.clone()`), un ou binaire (`a | r | b`), une re-liaison par
    autre chose (`let r = autre(r);`) arrêtent toujours la jambe. Site vivant entré : `cases.rs`
    (`rattraper_les_echeances_multi_niveau`), dont le bras d'échec rend « ÉCHÉANCES MULTI-NIVEAU NON RELUES » avec la
    cause : honnête, non accusé, aucune entrée (épreuves `p50` et `n57`).
  * L'aveu par le NOM ne vaut plus que dans la jambe LIÉE (les quatre sites qui en avaient besoin). La jambe `match`
    directe juge comme sur `fa44af5a` (`Err(_) => (0, CAUSE_X_NON_LU)`, `Json(json!({.., "etat": Etat::NonLu}))`,
    `{ let _c = CAUSE_X_NON_LU; Value::Null }` y sont accusés) ; dans la jambe liée, un nom rangé dans une liaison
    jetée (`let _c = …;`) n'avoue rien. Dans la seconde jambe, seul le nom de TÊTE avoue :
    `.map_err(|_| ApiError::NotFound(CAUSE_X_NON_LU))?` reste accusé, comme sur `fa44af5a`.
  * `let _ =` n'est jamais pris pour un nom lié (le refus est écrit, plus seulement supposé de Rust).

VAGUE BF (2026-11-02) — CHAQUE ÉLÉMENT ÉCRIT EST TENU, OU RETIRÉ
----------------------------------------------------------------
La vérification de la vague BE a posé un mutant par élément (79) : 26 restaient verts. Chacun est maintenant tenu par une
épreuve qui rougit sous son retrait (`p66`-`p87`, `n66`-`n76`), ou l'élément est retiré avec sa raison :
  * jambe liée : le receveur n'est plus filtré que par la barre d'une fermeture, lue hors chaîne (mots-clés et classe
    `[^;{}=]` retirés : l'instruction est déjà bornée par `debut_instruction`) ; la RÉAFFECTATION `r = match r` est
    jugée comme l'ombre ; le `\b`, le `.` et le `\w` de la recherche du nom ont leur épreuve, comme chaque début (`(`
    `,` `=` `{` `;` `move`) et chaque fin (`)` `]` `}` `,` `;`) d'une fermeture enjambée ;
  * seconde jambe : une constante ASSOCIÉE (`|_| Refus::ABSENT`) est un littéral ; les champs d'une variante se coupent à
    chaque virgule hors chaîne, par le lecteur importé (chaînes brutes comprises) — le compte de profondeur et les refus
    d'appariement sont retirés, preuve d'équivalence dans `champs_de_tete` ;
  * aveu par le nom : `NOM_QUI_AVOUE_LA_LECTURE` réécrit en quatre alternatives dont chaque suffixe, pluriel et
    lookahead a son épreuve ; la liaison jetée typée, le lookbehind et la casse de `IDENTIFIANT_NOMME`, la tête prise au
    DERNIER segment ont la leur.
Population de l'arbre `b29051c4` inchangée par la réécriture : 37 directs sur 17 fichiers, 3 `map_err`, 10 liés, un seul
site accusé (`diag_bundle_json`, admis).

CORRECTION DE LA VAGUE BF (vérification BF1, 2026-11-02)
--------------------------------------------------------
  * la RÉPÉTITION de l'accès de champ d'une valeur simple (`req.a.b`, `p89`) et chaque côté de la parenthèse exclue
    d'un paramètre de fermeture (`|(a, b), r|` `n79`, `|r: (i64, i64)|` `n80`) ont leur épreuve, pris séparément ;
  * une liaison HORS de toute fonction est dite au journal (refus de conclure), comme la jambe directe ;
  * les boucles de saut de blancs après la chaîne (jambe directe et jambe liée) sont retirées : mortes, la fin rendue
    par `chaine_detaillee` est déjà sur un non-blanc (`p90` fixe ce contrat) ;
  * les lectures à chaîne nue qu'aucune jambe ne lit sont COMPTÉES et classées dans `ce_qui_n_est_pas_tenu()`, sous
    `handlers/` et hors de lui ; un défaut lu hors `handlers/` (`rollups.rs` 811 puis 880) y est nommé et rattaché à
    `P10.20-b`.
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
# Vague BF : le chemin d'une constante admet un segment en `CamelCase` — une constante ASSOCIÉE (`Refus::ABSENT`)
# est un littéral comme `erreurs::ABSENT` (épreuve `p66`).
LITTERAL_SEUL = re.compile(r'"(?:[^"\\]|\\.)*"|r(#*)".*?"\1|(?:[A-Za-z_]\w*\s*::\s*)*[A-Z][A-Z0-9_]*', re.S)
JAMBE_MAP_ERR = "map_err(|_|)? => "
# Un constructeur en `CamelCase` (variante d'énumération ou struct-tuple, chemin `a::B::` toléré) à UN champ :
# `Refus::Refusee("…".to_string())`. Le champ est relu par `corps_litteral` (ou, récursivement, par cette même forme).
# Une fonction (`bad_req(..)`, `String::from(..)`, `Box::new(..)`) n'a pas de dernier segment en `CamelCase`.
VARIANTE_D_UN_CHAMP = re.compile(r"(?:[A-Za-z_]\w*\s*::\s*)*[A-Z]\w*[a-z]\w*\s*\((.*)\)", re.S)
FORME_VARIANTE_D_UN_LITTERAL = JAMBE_MAP_ERR + "variante(littéral)"
# `P10.20-l` (vague BD) — trois formes de la seconde jambe qui passaient, ou accusaient à tort :
#  * une variante UNITAIRE (`|_| Refus::Absent`, `|_| Value::Null`) : même faute qu'un littéral, sans champ ;
#  * une variante à PLUSIEURS champs dont l'un au moins est un littéral et les autres des valeurs simples
#    (`|_| Refus::Refusee("x", id)`) : la phrase d'absence avec un identifiant à côté ;
#  * une variante ou une constante qui AVOUE la lecture ratée par son NOM (`Refus::NonLu("…")`, `CAUSE_X_NON_LUE`,
#    `Illisible`) n'est PAS accusée : elle sert l'absence comme une lecture ratée (fail-closed), la même décision que
#    pour le 5xx (`n23`). La garde lit ce NOM, pas le sens du littéral ; la limite est écrite.
# Vague BF : la minuscule exigée d'avant (`[A-Z]\w*[a-z]\w*`) est retirée — un dernier segment sans minuscule est une
# constante, prise par `corps_litteral` (jugé AVANT) sous le même chemin : les deux ensembles se recouvraient à l'octet.
VARIANTE_UNITAIRE = re.compile(r"(?:[A-Za-z_]\w*\s*::\s*)*[A-Z]\w*")
FORME_VARIANTE_UNITAIRE = JAMBE_MAP_ERR + "variante unitaire"
FORME_VARIANTE_A_PLUSIEURS_CHAMPS = JAMBE_MAP_ERR + "variante(plusieurs champs)"
# Vague BF : quatre alternatives, chaque élément tenu par une épreuve (`valider_instrument`, mutants `M_NOM*`) :
# `Non` + `Re` facultatif + `l` OU `L` + `u` + `e` facultatif + `s` facultatif, jamais suivi d'une minuscule
# (`NonLu`, `NonLue`, `NonLus`, `NonLues`, `NonRelu(e)(s)`) ; `Illisible(s)` ; `NON_` + `RE_`… en capitales ;
# `ILLISIBLE(S)`. L'écriture d'avant (`Non(?:Re)?lu…|NonLu…`) laissait non tenus les suffixes de `NonLu`.
NOM_QUI_AVOUE_LA_LECTURE = re.compile(r"Non(?:Re)?[lL]ue?s?(?![a-z])|Illisibles?(?![a-z])"
                                      r"|NON_(?:RE)?LUE?S?(?![A-Z])|ILLISIBLES?(?![A-Z])")
IDENTIFIANT_NOMME = re.compile(r"(?<![\w.])[A-Z]\w*")
TETE_DE_CONSTRUCTEUR = re.compile(r"((?:[A-Za-z_]\w*\s*::\s*)*([A-Za-z_]\w*))\s*(?:\((.*)\))?", re.S)
VALEUR_SIMPLE = re.compile(r"&?\s*[a-z_]\w*(?:\s*\.\s*[a-z_]\w*)*(?:\s*\.\s*(?:clone|to_string|to_owned)\s*\(\s*\))?")
# LA TROISIÈME JAMBE — `Result` LIÉ puis `match` (vague BD) : `let r = conn.query_row(..); match r { .. }`. Mêmes bras,
# même verdict que la jambe directe ; la forme porte ce préfixe pour que l'ensemble nommé dise laquelle des deux.
FORME_LIEE = "lié puis match : "
# Vague BE : une liaison à un nom JETÉ (`let _c = CAUSE_X_NON_LU;`) ne sert rien ; l'aveu par le nom ne la lit pas.
LIAISON_JETEE = re.compile(r"\blet\s+_\w*\s*(?::[^=;]*)?=[^;]*;")
# Vague BF : le receveur est tout ce qui suit le `=` jusqu'à la lecture. La fenêtre est l'instruction (`debut_instruction`
# coupe aux `;`, `{`, `}` hors chaîne) : l'exclusion d'avant (`[^;{}=]`) ne coupait plus que des chaînes du receveur
# (`st.pool("a{b;c=d").query_row(..)`, épreuve `p67`), un angle mort et rien d'autre.
LIAISON_EN_TETE = re.compile(r"\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;]*)?=\s*(.*)$", re.S)

# --- PLANCHERS DE NON-DÉGÉNÉRESCENCE (première écriture, 2026-10-23) --------------------------------------------
# Relevé de l'arbre ce jour-là (base `1287fb98`), MESURÉ par cette garde : 76 `match` directs sur un `query_row` sous
# `handlers/`, dont 34 en `.optional()` (hors population) et 42 à chaîne nue sur 18 fichiers. Règle des deux tiers
# de la garde sœur (69 % et 65 %, arrondis en dessous) : 42 -> 28 (28,98), 18 -> 11 (11,7). Ils ne montent jamais ;
# ils se re-dérivent, date écrite, quand un lot passe assez de sites en `.optional()` pour les franchir.
RELEVE_SITES = 42
RELEVE_FICHIERS = 18
PLANCHER_SITES = 28
PLANCHER_FICHIERS = 11
# TROISIÈME JAMBE (`Result` lié puis `match`, vague BD) : relevé du 2026-10-29 sur `fa44af5a`, MESURÉ par cette garde,
# 8 liaisons consommées par un `match` sous `handlers/`, aucune accusée. Règle des deux tiers : 8 -> 5.
# RE-DÉRIVÉ le 2026-10-29 (vague BE) sur `d68c32e5` : l'ombre `let r = match r` est lue, `cases.rs`
# (`rattraper_les_echeances_multi_niveau`) entre — 9 liaisons, aucune accusée. Deux tiers : 9 -> 6.
# RE-MESURÉ le 2026-11-02 (vague BF) sur `b29051c4` : 10 liaisons, aucune accusée. Deux tiers : 10 -> 6, inchangé.
RELEVE_LIE = 10
PLANCHER_LIE = 6

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


def champs_de_tete(texte):
    """Les champs d'une liste d'arguments, coupés à CHAQUE virgule hors chaîne (lecteur importé
    `spans_de_chaines_rust` : chaînes brutes et échappements compris, `p32`, `p77`, `p78`), virgule finale retirée.

    Vague BF — POURQUOI NI PROFONDEUR NI APPARIEMENT (l'écriture d'avant comptait `([{`/`)]}` et rendait None sur un
    texte non apparié ; le vérificateur de BE2 a trouvé ses deux refus d'appariement, M_CT4 et M_CT5, sans effet) : le
    seul appelant (`variante_a_plusieurs_champs`) n'accuse que si CHAQUE champ est accepté — littéral, valeur simple
    ou variante d'un littéral. Aucune de ces formes ne porte de virgule hors chaîne, et chacune est appariée sans
    jamais descendre sous zéro (un littéral n'a pas de parenthèse hors chaîne ; `String::from(..)`, `format!(..)`,
    `{ .. }`, `.to_string()`, `.clone()` et `Tete(..)` ouvrent avant de fermer, récursivement). Donc : si les champs
    coupés à toutes les virgules sont tous acceptés, aucune virgule n'était sous une parenthèse et la coupe est celle
    qu'aurait faite le compte de profondeur ; si une virgule était sous une parenthèse, le morceau qui la précède
    porte une ouvrante non fermée et il est refusé — le verdict est le même. Un texte non apparié laisse de même au
    moins un champ refusé."""
    chaines = spans_de_chaines_rust(texte)
    out, deb = [], 0
    for j, c in enumerate(texte):
        if c == "," and not dans_une_chaine_rust(chaines, j):
            out.append(texte[deb:j])
            deb = j + 1
    out.append(texte[deb:])
    if len(out) > 1 and not out[-1].strip():
        out.pop()  # virgule finale
    return [x.strip() for x in out]


def avoue_la_lecture(corps):
    """Le corps est-il une constante ou un constructeur dont le NOM DE TÊTE avoue la lecture ratée (`NonLu`,
    `NON_LUE`, `Illisible`) ?"""
    c = depouiller(corps)
    m = TETE_DE_CONSTRUCTEUR.fullmatch(c)
    if not m:
        return False
    # Vague BE : seul le NOM DE TÊTE (ce qui est servi) compte. Un champ qui avoue sous une tête qui n'avoue pas
    # (`ApiError::NotFound(CAUSE_X_NON_LU)`, accusé sur `fa44af5a`) sert la tête : il reste accusé.
    return bool(NOM_QUI_AVOUE_LA_LECTURE.search(m.group(2)))


def variante_unitaire(corps):
    """Le corps n'est-il qu'une variante SANS champ (`Refus::Absent`, `Value::Null`) ?"""
    return bool(VARIANTE_UNITAIRE.fullmatch(depouiller(corps)))


def variante_a_plusieurs_champs(corps):
    """Un constructeur en `CamelCase` à DEUX champs ou plus, dont l'un au moins est un littéral (ou une variante d'un
    littéral) et chacun des autres un littéral ou une valeur simple (`id`, `&nom`, `x.clone()`)."""
    m = VARIANTE_D_UN_CHAMP.fullmatch(depouiller(corps))
    if not m:
        return False
    champs = champs_de_tete(m.group(1))  # jamais vide : au moins un champ, même sans virgule
    # Un champ UNIQUE littéral est déjà pris par `variante_d_un_litteral`, jugée avant ; non littéral, `any` le rejette.
    litteraux = [corps_litteral(x) or variante_d_un_litteral(x) for x in champs]
    return any(litteraux) and all(lit or bool(VALEUR_SIMPLE.fullmatch(x)) for lit, x in zip(litteraux, champs))


def liaison_puis_match(code, coupes, spans, deb, apres, fns, hors_de_toute_fonction=None):
    """La TROISIÈME JAMBE. L'index de l'accolade du `match <nom>` (ou `match &<nom>`) qui CONSOMME le `Result` lié par
    `let <nom> = <receveur>.query_row(..)<chaîne nue>;`, ou None. La liaison doit être l'instruction entière (rien
    après la chaîne que le `;`), le receveur sans fermeture (aucune barre `|`), et le `match` la PREMIÈRE apparition
    CONSOMMANTE du nom dans la fonction englobante : toute autre consommation (passé en argument, `?`, `if let`,
    re-liaison par autre chose, capture) sort de la jambe, sans deviner.

    Vague BF — CE QUI A CHANGÉ, ET POURQUOI : la liste de mots-clés refusés dans le receveur (`if`, `while`, `let`,
    `for`, `match`, `else`, `move`, `return`) est retirée. Tous sauf `return` exigent une accolade, qui coupe
    l'instruction (`debut_instruction`) avant que la liaison soit lue ; `move` n'existe que devant une fermeture
    (`|`, refusée) ou un bloc ; reste `let r = return conn.query_row(..);`, qui lie `!` — lu désormais, sans effet sur un
    `match` qui compile. Le refus d'un receveur vide est retiré aussi : `LECTURE_UNE_LIGNE` exige le `.` d'un receveur."""
    # Une lecture DANS des parenthèses (`f(conn.query_row(..))`) n'est jamais suivie du `;` exigé plus bas : l'appariement
    # du receveur est tenu par lui. `let _ =` ne lie rien : `match _` n'existe pas, la boucle ne trouve aucun nom.
    ml = LIAISON_EN_TETE.search(code[debut_instruction(coupes, deb):deb])
    if not ml:
        return None
    receveur = ml.group(2)
    chaines_du_receveur = spans_de_chaines_rust(receveur)
    if any(c == "|" and not dans_une_chaine_rust(chaines_du_receveur, k) for k, c in enumerate(receveur)):
        return None  # une fermeture liée (`let r = move || ..;`, `n52`, `n66`) n'est pas un `Result` ; une barre DANS
        # une chaîne du receveur (`p67`) n'est pas une fermeture
    # `apres` (rendu par `chaine_detaillee`, importé) est déjà sur un caractère non blanc : le lecteur saute " \t\n"
    # avant de rendre la fin de chaîne. La boucle de saut écrite ici avant la vague BF (correction) était morte.
    j = apres
    if code[j:j + 1] != ";":
        return None
    nom = ml.group(1)
    if nom == "_":
        return None  # `let _ =` ne lie rien (vague BE : `n44` porte un `match _` pour le prouver)
    englobante = portee_englobante(fns, deb)
    if not englobante:
        # Une liaison HORS de toute fonction (fermeture dans un `static`) : la recherche du `match` n'a pas de borne.
        # Comme la jambe directe, la garde le DIT et refuse de conclure (journal ; `epreuve_hors_de_toute_fonction`).
        if hors_de_toute_fonction is not None:
            hors_de_toute_fonction.append(nom)
        return None
    # Vague BE — deux occurrences du nom ne CONSOMMENT pas le `Result` lié, et la recherche les enjambe :
    #  * l'OMBRE `let <nom> = match <nom> {` (le nom du nouveau `let`) : le `match` qui suit est la consommation ;
    #  * un PARAMÈTRE de fermeture (`|r| r + 1`, `move |a, r| { .. }`) : il ombre le nom dans son corps, enjambé aussi.
    # Toute autre apparition (argument, `?`, champ, capture par une fermeture, re-liaison par autre chose) arrête la jambe.
    # Vague BF — la RÉAFFECTATION `r = match r { .. }` (nom lié `mut`) est enjambée comme l'ombre : le `let` exigé
    # d'avant est retiré (`p68`). Aucun contexte n'est exigé devant le nom : sur du Rust qui compile, `<nom> = match
    # <nom>` n'est qu'une liaison, une réaffectation ou un argument nommé de macro (`format!("{r}", r = match r ..)`,
    # où le `match` est bien la consommation) ; `==`, `+=`, `<=` ne passent pas la forme (le `=` doit suivre le nom, puis
    # `match`), un champ `x.r` est exclu par le lookbehind de `occurrence`.
    ombre = re.compile(r"\s*(?::[^=;]*)?=\s*match\s+(?:&\s*)?" + re.escape(nom) + r"\b")
    # Chaque élément a son épreuve : le lookbehind `\w` (`err` ne contient pas `r`, `p69`), le `.` (`cfg.r` est un
    # champ, `p70`), le `\b` final (`return`, `rows` ne sont pas `r`, `p71`).
    occurrence = re.compile(r"(?<![\w.])" + re.escape(nom) + r"\b")
    pos_de_recherche, fin = j + 1, englobante[3]
    while True:
        o = occurrence.search(code, pos_de_recherche, fin)
        if not o:
            return None
        pos = o.start()
        pos_de_recherche = o.end()
        if dans_une_chaine_rust(spans, pos):
            continue
        if ombre.match(code, o.end()):
            continue
        fin_de_fermeture = fin_du_parametre_de_fermeture(code, pos, o.end())
        if fin_de_fermeture is not None:
            pos_de_recherche = fin_de_fermeture
            continue
        if not re.search(r"\bmatch\s+(?:&\s*)?$", code[max(0, pos - 40):pos]):
            return None
        k = pos + len(nom)
        while k < len(code) and code[k] in " \t\n":
            k += 1
        return k if code[k:k + 1] == "{" else None


def fin_du_parametre_de_fermeture(code, deb, fin):
    """Si `code[deb:fin]` est un PARAMÈTRE de fermeture (`|r|`, `|a, r: T|`, `move |r|`), l'index de la fin du CORPS de
    cette fermeture ; sinon None. La barre ouvrante doit suivre un début d'argument (`(`, `,`, `=`, `{`, `;`, `move`) : un `a | r`
    (ou binaire) n'est pas une fermeture. Chaque début a son épreuve (vague BF) : `(` `p48`, `,` `p72`
    (`stmt.query_map(params![id], |r| ..)`), `=` `p65`, `{` `p73`, `;` `p74`, `move` `p49`. Une fermeture après `=>`,
    `[`, `&`, `:`, `||` ou `return` n'est PAS reconnue : le nom y est lu comme une consommation et la jambe sort (limite
    écrite, du côté qui ne juge pas). De même une parenthèse dans les paramètres, AVANT le nom (`|(a, b), r|`, `n79`)
    ou APRÈS lui (`|r: (i64, i64)|`, `n80`) : les deux classes `[^|;{}()]` l'excluent, chacune tenue par son épreuve.

    Le corps court jusqu'à la `,`, au `;` ou à la fermante `)`, `]`, `}` de profondeur nulle ; `(`, `[`, `{` ouvrent une
    profondeur. Épreuves (vague BF) : `)` `n67`, `]` `n68`, `}` `n69` en fin ; `(` `p75`, `[` `p76`, `{` `p64` en
    ouverture ; `,` `n64`, `;` `n65`."""
    avant = re.search(r"(?:[(,={;]|\bmove)\s*\|[^|;{}()]*$", code[max(0, deb - 80):deb])
    if not avant:
        return None
    apres = re.match(r"[^|;{}()]*\|", code[fin:fin + 80])
    if not apres:
        return None
    # Le corps, bloc compris (`{ .. }` ouvre puis ferme une profondeur), court jusqu'à la virgule, la parenthèse,
    # l'accolade ou le `;` de profondeur nulle.
    k, prof = fin + apres.end(), 0
    while k < len(code):
        c = code[k]
        if c in "([{":
            prof += 1
        elif c in ")]}":
            if prof == 0:
                return k
            prof -= 1
        elif c in ",;" and prof == 0:
            return k
        k += 1
    return None


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
        # Le statut de client l'emporte sur le nom qui avoue (`not_found(CAUSE_X_NON_LU)` sert un 404), comme dans la
        # jambe `match` (p39) : il se juge AVANT l'aveu par le nom.
        statut = statut_de_client(corps)
        if statut:
            return True, JAMBE_MAP_ERR + statut
        if avoue_la_lecture(corps):
            return True, None
        if corps_litteral(corps):
            return True, JAMBE_MAP_ERR + "littéral"
        if variante_d_un_litteral(corps):
            return True, FORME_VARIANTE_D_UN_LITTERAL
        if variante_unitaire(corps):
            return True, FORME_VARIANTE_UNITAIRE
        if variante_a_plusieurs_champs(corps):
            return True, FORME_VARIANTE_A_PLUSIEURS_CHAMPS
        return True, None
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


def verdict_du_bras(motif, corps, constructeurs, portee, aveu_par_le_nom=False):
    """La forme accusée (`Err => 404`, `Err => valeur`), ou None quand le bras propage, avoue ou distingue.
    `aveu_par_le_nom` : vrai pour la seule jambe LIÉE (vague BE). La jambe `match` directe juge comme sur `fa44af5a`
    (`Err(_) => (0, CAUSE_X_NON_LU)` y reste accusé) : aucun de ses sites n'avait besoin de l'aveu par le nom."""
    if "QueryReturnedNoRows" in corps:
        return None
    statut = statut_de_client(corps)
    if statut:
        return "Err => " + statut
    servi = JET_DE_LA_CAUSE.sub("", sans_macros_de_journal(corps))
    if bras_derreur_garde(motif, servi, constructeurs, portee):
        return None
    if not aveu_par_le_nom:
        return "Err => valeur"
    # `P10.20-l` (vague BD) — une constante ou une variante qui AVOUE la lecture ratée par son nom, HORS journal
    # (`corps["sla_due_non_lu"] = json!(CAUSE_…_NON_RELUE)`, `(None, CAUSE_…_NON_RELU)`) : l'échec est dit, pas fabriqué.
    # Vague BE : un nom rangé dans une liaison jetée (`let _c = CAUSE_X_NON_LU;`) n'est pas servi : retiré d'abord.
    servi = LIAISON_JETEE.sub("", servi)
    chaines = spans_de_chaines_rust(servi)
    if any(NOM_QUI_AVOUE_LA_LECTURE.search(x.group(0)) for x in IDENTIFIANT_NOMME.finditer(servi)
           if not dans_une_chaine_rust(chaines, x.start())):
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
        if not chaine_nue(jetons):
            continue
        prefixe_de_forme = ""
        if scrutateur_est_la_lecture(code, m.start()):
            i = apres  # déjà sur un non-blanc (`chaine_detaillee`) : la boucle de saut d'avant était morte
            if code[i:i + 1] != "{":
                continue
            population += 1
        else:
            hors_de_toute_fonction = []
            i = liaison_puis_match(code, coupes, spans, m.start(), apres, fns, hors_de_toute_fonction)
            for nom_lie in hors_de_toute_fonction:
                journal.append(f"{chemin_relatif}:{ligne} — `let {nom_lie} = ….query_row(..);` HORS de toute fonction : "
                               "le `match` qui le consomme ne peut être cherché, ni le site entrer dans l'ensemble")
            if i is None:
                continue
            if compteurs is not None:
                compteurs["lie"] = compteurs.get("lie", 0) + 1
            prefixe_de_forme = FORME_LIEE
        englobante = portee_englobante(fns, m.start())
        if not englobante:
            journal.append(f"{chemin_relatif}:{ligne} — `match` HORS de toute fonction : un site sans fonction ne "
                           "peut pas entrer dans l'ensemble")
            continue
        portee = code[englobante[2]:englobante[3]]
        for motif, corps in bras_du_match(code, i):
            if not est_un_bras_d_echec(motif):
                continue
            forme = verdict_du_bras(motif, corps, constructeurs, portee, prefixe_de_forme == FORME_LIEE)
            if forme:
                extrait = " ".join((motif.strip() + " => " + corps.strip()).split())[:140]
                sites.append((chemin_relatif, ligne, englobante[0], prefixe_de_forme + forme, extrait))
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
    # `n7` d'avant (« `Result` lié puis `match`, hors jambe ») est devenue `p28` (troisième jambe, vague BD).
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
    ("n22 variante UNITAIRE qui AVOUE la lecture par son nom (vague BD)", _e('.map_err(|_| Refus::NonLu)?'), set(), 0, 1),
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
    # `n29` d'avant (« variante à deux champs, limite écrite ») est devenue `p31` (vague BD).
    ("n30 fonction en minuscules (pas un constructeur)", _e('.map_err(|_| refuser("x"))?'), set(), 0, 1),
]
# `P10.20-l` (vague BD) — VARIANTES UNITAIRE, À PLUSIEURS CHAMPS, ET QUI AVOUENT ; TROISIÈME JAMBE (`Result` lié).
# Sixième terme : la population de la jambe liée.
def _l(liaison, entre="", bras='        Err(_) => not_found("x"),', scrutateur="r"):
    return _f('    let r = ' + liaison + ';\n' + entre + '    match ' + scrutateur + ' {\n        Ok(v) => ok(v),\n' + bras
              + '\n    }')


_Q = 'conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))'
LIE_404 = {FORME_LIEE + "Err => 404"}
# Vague BE — l'OMBRE `let r = match r`, le PARAMÈTRE de fermeture avant le `match`, le site vivant de `cases.rs`
# (`rattraper_les_echeances_multi_niveau`), la variante unitaire SANS chemin, et les quatre formes que `fa44af5a`
# accusait et que l'aveu par le nom avait désarmées (jambes directe et `map_err`).
_OMBRE = '    let r = match r {\n        Ok(v) => v,\n'
_CAS = ('    let relu: Result<(i64, String), _> = conn.query_row("SELECT a, b FROM t WHERE id=?1", params![id], |r| '
        'Ok((r.get(0)?, r.get(1)?)));\n    let pause_due = |statut: &str, en_pause: Option<i64>| statut != "w" || '
        'en_pause.is_some();\n    let relu = match relu {\n')
EPREUVES_VAGUE_BE = [
    ("p46 jambe liée : OMBRE `let r = match r { .. Err(_) => return not_found(..) }`",
     _f('    let r = ' + _Q + ';\n' + _OMBRE + '        Err(_) => return not_found("x"),\n    };\n    ok(r)'), LIE_404, 0, 0, 1),
    ("p47 jambe liée : ombre typée et `mut` (`let mut r: i64 = match &r`)",
     _f('    let r = ' + _Q + ';\n    let mut r: i64 = match &r {\n        Ok(v) => *v,\n        _ => return forbidden("x"),\n'
        '    };\n    ok(r)'), {FORME_LIEE + "Err => 403"}, 0, 0, 1),
    ("p48 jambe liée : une fermeture `|r|` AVANT le `match` ne l'arrête pas",
     _l(_Q, entre='    let w = autre(|r| r + 1);\n'), LIE_404, 0, 0, 1),
    ("p49 jambe liée : fermeture `move |a, r: i64| { .. }` à bloc, puis l'ombre",
     _f('    let r = ' + _Q + ';\n    let w = f(1, move |a, r: i64| { r + a });\n' + _OMBRE
        + '        Err(_) => return bad_req("x"),\n    };\n    ok(r)'), {FORME_LIEE + "Err => 400"}, 0, 0, 1),
    ("p50 jambe liée : forme du site vivant de `cases.rs` qui FABRIQUERAIT (`Err(_) => return String::new()`)",
     _f(_CAS + '        Err(_) => return String::new(),\n        Ok(v) => v,\n    };\n    rendre(relu)'),
     {FORME_LIEE + "Err => valeur"}, 0, 0, 1),
    ("p51 variante unitaire SANS chemin `|_| Absent`", _e('.map_err(|_| Absent)?'), {FORME_VARIANTE_UNITAIRE}, 0, 1),
    ("p52 jambe directe : `Err(_) => (0, CAUSE_X_NON_LU)` (accusé sur `fa44af5a`)",
     _m('        Err(_) => (0, CAUSE_X_NON_LU),'), {"Err => valeur"}, 1),
    ("p53 jambe directe : `Json(json!({\"trouve\": false, \"etat\": Etat::NonLu}))`",
     _m('        Err(_) => Json(json!({"trouve": false, "etat": Etat::NonLu})),'), {"Err => valeur"}, 1),
    ("p54 jambe directe : `{ let _c = CAUSE_X_NON_LU; Value::Null }`",
     _m('        Err(_) => {\n            let _c = CAUSE_X_NON_LU;\n            Value::Null\n        }'), {"Err => valeur"}, 1),
    ("p55 seconde jambe : `ApiError::NotFound(CAUSE_X_NON_LU)` (la tête n'avoue pas)",
     _e('.map_err(|_| ApiError::NotFound(CAUSE_X_NON_LU))?'), {FORME_VARIANTE_D_UN_LITTERAL}, 0, 1),
    ("p56 jambe liée : le nom qui avoue rangé dans une liaison JETÉE (`let _c = CAUSE_X_NON_LU;`)",
     _l(_Q, bras='        Err(_) => {\n            let _c = CAUSE_X_NON_LU;\n            Value::Null\n        }'),
     {FORME_LIEE + "Err => valeur"}, 0, 0, 1),
    ("p57 seconde jambe : seul le champ avoue (`Refus::Refusee(CAUSE_X_NON_LU)`)",
     _e('.map_err(|_| Refus::Refusee(CAUSE_X_NON_LU))?'), {FORME_VARIANTE_D_UN_LITTERAL}, 0, 1),
    ("n57 jambe liée : forme HONNÊTE du site vivant de `cases.rs` (phrase « NON RELUES » qui porte la cause)",
     _f(_CAS + '        Err(e) => return format!(" ; ÉCHÉANCES NON RELUES ({e}){suite}"),\n        Ok(v) => v,\n    };\n'
        '    rendre(relu)'), set(), 0, 0, 1),
    ("n58 jambe liée : nom CAPTURÉ par une fermeture avant le `match` (consommé autrement)",
     _l(_Q, entre='    let w = autre(|| r.clone());\n'), set(), 0, 0, 0),
    ("n59 jambe liée : `a | r | b` (ou binaire, pas une fermeture) avant le `match`",
     _l(_Q, entre='    let w = a | r | b;\n'), set(), 0, 0, 0),
    ("n60 jambe liée : re-liaison par AUTRE CHOSE qu'un `match` du nom (`let r = autre(r);`)",
     _l(_Q, entre='    let r = autre(r);\n'), set(), 0, 0, 0),
    ("n61 jambe liée : `let _ =` puis un `match` d'autre chose qui fabrique", _l(_Q, scrutateur='autre').replace(
        'let r = ', 'let _ = ', 1), set(), 0, 0, 0),
    ("n63 jambe liée : paramètre de fermeture typé par un TUPLE (lu comme une consommation : limite écrite)",
     _l(_Q, entre='    let w = f(|(a, r): (i64, i64)| a + r);\n'), set(), 0, 0, 0),
    ("n62 jambe directe : `Err(_) => err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_X_NON_LU)` (5xx, aveu)",
     _m('        Err(_) => err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_X_NON_LU),'), set(), 1),
    # Les règles de l'aveu PAR LE NOM ne se lisent plus que dans la jambe liée : `p38`-`p41` (jambe directe) passent
    # quelle que soit leur écriture. Leurs jumelles liées les fixent là où elles agissent.
    ("p58 jambe liée : la constante qui avoue N'EST QUE dans le journal : fabrique",
     _l(_Q, bras='        Err(e) => {\n            eprintln!("{} {e}", CAUSE_X_NON_LU);\n            None\n        }'),
     {FORME_LIEE + "Err => valeur"}, 0, 0, 1),
    ("p59 jambe liée : la constante qui avoue sous un statut de client : le 404 l'emporte",
     _l(_Q, bras='        Err(_) => (StatusCode::NOT_FOUND, CAUSE_X_NON_LU).into_response(),'), LIE_404, 0, 0, 1),
    ("p60 jambe liée : « NON_LU » dans un LITTÉRAL de chaîne n'avoue rien",
     _l(_Q, bras='        Err(_) => json!("CAUSE_X_NON_LU"),'), {FORME_LIEE + "Err => valeur"}, 0, 0, 1),
    ("p61 jambe liée : nom voisin qui n'avoue pas (`CAUSE_X_NON_LUMINEUX`)",
     _l(_Q, bras='        Err(_) => json!(CAUSE_X_NON_LUMINEUX),'), {FORME_LIEE + "Err => valeur"}, 0, 0, 1),
    ("p62 seconde jambe : nom de tête voisin qui n'avoue pas (`|_| CAUSE_X_NON_LUMINEUX`)",
     _e('.map_err(|_| CAUSE_X_NON_LUMINEUX)?'), LITTERAL_ACCUSE, 0, 1),
    # Seule forme où la tête AVOUE et porte un statut de client : elle fixe l'ordre « statut avant aveu » de la
    # seconde jambe (les têtes de `p42`-`p45` n'avouent pas).
    ("p63 seconde jambe : tête qui avoue sur un statut de client (`Refus::NonLu(StatusCode::NOT_FOUND)`) : le 404 "
     "l'emporte", _e('.map_err(|_| Refus::NonLu(StatusCode::NOT_FOUND))?'), {JAMBE_MAP_ERR + "404"}, 0, 1),
    # La FIN du corps d'une fermeture enjambée : un bloc `{ .. ; .. }` ouvre une profondeur (son `;` ne la termine pas),
    # le `;` et la `,` de profondeur nulle la terminent (le nom qui suit est une consommation).
    ("p64 jambe liée : fermeture à bloc qui contient un `;` (`autre(|r| { foo(); r })`)",
     _l(_Q, entre='    let w = autre(|r| { foo(); r });\n'), LIE_404, 0, 0, 1),
    ("p65 jambe liée : fermeture finie par le `;` de l'instruction (`let f = |r| r + 1;`)",
     _l(_Q, entre='    let f = |r| r + 1;\n'), LIE_404, 0, 0, 1),
    ("n64 jambe liée : la `,` termine le corps de la fermeture, le nom passé ensuite en argument consomme",
     _l(_Q, entre='    let w = f(|r| r + 1, r);\n'), set(), 0, 0, 0),
    ("n65 jambe liée : le `;` termine le corps de la fermeture, le nom consommé ensuite par `?`",
     _l(_Q, entre='    let f = |r| r + 1; let w = r?;\n'), set(), 0, 0, 0),
]
# Vague BF — chaque élément que le vérificateur de BE2 a trouvé non tenu (mutants verts) a son épreuve, et chaque
# élément écrit par ce lot aussi. Les numéros sont cités au site de chaque règle.
_LIE_VALEUR = {FORME_LIEE + "Err => valeur"}
EPREUVES_VAGUE_BF = [
    # --- seconde jambe
    ("p66 constante ASSOCIÉE sous un chemin `CamelCase` (`|_| Refus::ABSENT`) : un littéral",
     _e('.map_err(|_| Refus::ABSENT)?'), LITTERAL_ACCUSE, 0, 1),
    ("p77 champ littéral qui porte un guillemet échappé et une virgule (`\"a \\\", b\"`)",
     _e('.map_err(|_| Refus::Refusee("a \\", b", id))?'), {FORME_VARIANTE_A_PLUSIEURS_CHAMPS}, 0, 1),
    ("p78 champ en chaîne BRUTE qui porte guillemets et virgule (`r#\"absent, \"ou\" pas\"#`)",
     _e('.map_err(|_| Refus::Refusee(r#"absent, "ou" pas"#, id))?'), {FORME_VARIANTE_A_PLUSIEURS_CHAMPS}, 0, 1),
    ("p79 valeur simple : accès de champ (`req.id`)", _e('.map_err(|_| Refus::Refusee("x", req.id))?'),
     {FORME_VARIANTE_A_PLUSIEURS_CHAMPS}, 0, 1),
    ("p80 valeur simple : `id.to_string()`", _e('.map_err(|_| Refus::Refusee("x", id.to_string()))?'),
     {FORME_VARIANTE_A_PLUSIEURS_CHAMPS}, 0, 1),
    ("p81 valeur simple : `nom.to_owned()`", _e('.map_err(|_| Refus::Refusee("x", nom.to_owned()))?'),
     {FORME_VARIANTE_A_PLUSIEURS_CHAMPS}, 0, 1),
    ("p82 la tête est le DERNIER segment : `RefusNonLu::Introuvable` n'avoue pas",
     _e('.map_err(|_| RefusNonLu::Introuvable)?'), {FORME_VARIANTE_UNITAIRE}, 0, 1),
    ("p83 `Illisible` suivi d'une minuscule (`Refus::Illisiblement`) n'avoue pas",
     _e('.map_err(|_| Refus::Illisiblement)?'), {FORME_VARIANTE_UNITAIRE}, 0, 1),
    ("p84 `ILLISIBLE` suivi d'une capitale (`CAUSE_ILLISIBLEMENT`) n'avoue pas",
     _e('.map_err(|_| CAUSE_ILLISIBLEMENT)?'), LITTERAL_ACCUSE, 0, 1),
    ("n71 `Refus::NonLue` avoue", _e('.map_err(|_| Refus::NonLue)?'), set(), 0, 1),
    ("n72 `Refus::NonLus` avoue", _e('.map_err(|_| Refus::NonLus)?'), set(), 0, 1),
    ("n73 `Refus::NonLues` avoue", _e('.map_err(|_| Refus::NonLues)?'), set(), 0, 1),
    ("n74 `Refus::Illisibles` avoue", _e('.map_err(|_| Refus::Illisibles)?'), set(), 0, 1),
    ("n75 `CAUSE_X_ILLISIBLES` avoue", _e('.map_err(|_| CAUSE_X_ILLISIBLES)?'), set(), 0, 1),
    ("n76 `CAUSE_X_NON_LUS` avoue", _e('.map_err(|_| CAUSE_X_NON_LUS)?'), set(), 0, 1),
    # --- jambe liée : receveur, ombre, occurrence
    ("p67 jambe liée : receveur qui porte `{`, `}`, `;`, `=` et `|` DANS une chaîne",
     _l('st.pool("a{b}c;d=e|f").query_row("SELECT 1", [], |r| r.get::<_, i64>(0))'), LIE_404, 0, 0, 1),
    ("n66 jambe liée : fermeture liée sans `move` (`let r = || conn.query_row(..);`)", _l('|| ' + _Q), set(), 0, 0, 0),
    ("p68 jambe liée : RÉAFFECTATION `r = match r { .. Err(_) => Ok(0) }`",
     _f('    let mut r = ' + _Q + ';\n    r = match r {\n        Ok(v) => Ok(v),\n        Err(_) => Ok(0),\n    };\n'
        '    rendre(r)'), _LIE_VALEUR, 0, 0, 1),
    ("p69 jambe liée : `err` ne contient pas le nom `r` (lookbehind `\\w`)", _l(_Q, entre='    let e = err;\n'),
     LIE_404, 0, 0, 1),
    ("p70 jambe liée : `cfg.r` est un champ, pas le nom (lookbehind `.`)", _l(_Q, entre='    let n = cfg.r;\n'),
     LIE_404, 0, 0, 1),
    ("p71 jambe liée : `return`, `rows` commencent par le nom sans l'être (`\\b` final)",
     _l(_Q, entre='    if id < 0 { return ok(0); }\n    let w = rows;\n'), LIE_404, 0, 0, 1),
    ("n70 jambe liée : `let r = match rows { .. }` n'est pas l'ombre (`\\b` après le nom du `match`)",
     _l(_Q, entre='    let r = match rows { _ => 1 };\n'), set(), 0, 0, 0),
    # --- jambe liée : début et fin d'une fermeture enjambée
    ("p72 jambe liée : fermeture après `,` (`stmt.query_map(params![id], |r| ..)`)",
     _l(_Q, entre='    let v = stmt.query_map(params![id], |r| r.get(0));\n'), LIE_404, 0, 0, 1),
    ("p73 jambe liée : fermeture après `{` (`{ |r: i64| r + 1 }`)", _l(_Q, entre='    let f = { |r: i64| r + 1 };\n'),
     LIE_404, 0, 0, 1),
    ("p74 jambe liée : fermeture après `;`", _l(_Q, entre='    foo(); |r| r + 1;\n'), LIE_404, 0, 0, 1),
    ("p75 jambe liée : `(` ouvre une profondeur dans le corps (`|r| f(1, r)`)",
     _l(_Q, entre='    let w = autre(|r| f(1, r));\n'), LIE_404, 0, 0, 1),
    ("p76 jambe liée : `[` ouvre une profondeur dans le corps (`|r| [1, r]`)",
     _l(_Q, entre='    let w = autre(|r| [1, r]);\n'), LIE_404, 0, 0, 1),
    ("n67 jambe liée : `)` de profondeur nulle termine le corps, `g(&r)` consomme ensuite",
     _l(_Q, entre='    let w = f(|r| r + 1) + g(&r);\n'), set(), 0, 0, 0),
    ("n68 jambe liée : `]` de profondeur nulle termine le corps, `+ r` consomme ensuite",
     _l(_Q, entre='    let w = [0, |r| r + 1].len() + r;\n'), set(), 0, 0, 0),
    ("n69 jambe liée : `}` de profondeur nulle termine le corps, `+ r` consomme ensuite",
     _l(_Q, entre='    let w = { |r| r + 1 } + r;\n'), set(), 0, 0, 0),
    # --- jambe liée : aveu par le nom
    ("p85 jambe liée : liaison jetée TYPÉE (`let _c: &str = CAUSE_X_NON_LU;`) n'avoue rien",
     _l(_Q, bras='        Err(_) => {\n            let _c: &str = CAUSE_X_NON_LU;\n            Value::Null\n        }'),
     _LIE_VALEUR, 0, 0, 1),
    ("p86 jambe liée : `etat_NonLu` (identifiant en minuscule) n'avoue rien", _l(_Q, bras='        Err(_) => etat_NonLu,'),
     _LIE_VALEUR, 0, 0, 1),
    ("p87 jambe liée : `cfg.CAUSE_X_NON_LU` (champ) n'avoue rien", _l(_Q, bras='        Err(_) => cfg.CAUSE_X_NON_LU,'),
     _LIE_VALEUR, 0, 0, 1),
    # --- les limites écrites par ce lot dans `ce_qui_n_est_pas_tenu()`, fixées dans le sens où elles sont dites
    ("p88 jambe liée : receveur qui porte `return` (lu, limite écrite)", _l('return ' + _Q), LIE_404, 0, 0, 1),
    ("n77 seconde jambe : un champ variante UNITAIRE (`Motif::Absent`) n'est ni littéral ni valeur simple (limite écrite)",
     _e('.map_err(|_| Refus::Refusee("x", Motif::Absent))?'), set(), 0, 1),
    ("n78 jambe liée : fermeture après `=>` non reconnue, le nom y est une consommation (limite écrite)",
     _l(_Q, entre='    let w = match a { _ => |r| r + 1 };\n'), set(), 0, 0, 0),
    # Correction de la vague BF (vérification BF1) : la RÉPÉTITION de l'accès de champ d'une valeur simple, et chaque
    # côté de la parenthèse exclue d'un paramètre de fermeture, pris SÉPARÉMENT (`n63` ne tient que leur conjonction).
    ("p89 valeur simple : accès de champ à DEUX niveaux (`req.a.b`)", _e('.map_err(|_| Refus::Refusee("x", req.a.b))?'),
     {FORME_VARIANTE_A_PLUSIEURS_CHAMPS}, 0, 1),
    ("n79 jambe liée : parenthèse AVANT le nom dans les paramètres (`|(a, b), r|`, consommation : limite écrite)",
     _l(_Q, entre='    let w = f(|(a, b), r| a + r);\n'), set(), 0, 0, 0),
    ("n80 jambe liée : parenthèse APRÈS le nom dans les paramètres (`|r: (i64, i64)|`, consommation : limite écrite)",
     _l(_Q, entre='    let w = f(|r: (i64, i64)| r.0);\n'), set(), 0, 0, 0),
    # La fin de chaîne rendue par `chaine_detaillee` (importé) est déjà sur un non-blanc : la jambe liée s'y fie depuis
    # que sa boucle de saut, morte, est retirée. Cette épreuve fixe ce contrat (blancs et saut de ligne avant le `;`).
    ("p90 jambe liée : blancs et saut de ligne entre la chaîne et le `;`", _l(_Q + '  \n    '), LIE_404, 0, 0, 1),
]
EPREUVES += [
    ("p28 `let r = conn.query_row(..); match r { Err(_) => not_found(..) }`", _l(_Q), LIE_404, 0, 0, 1),
    ("p29 variante UNITAIRE `|_| Refus::Absent`", _e('.map_err(|_| Refus::Absent)?'), {FORME_VARIANTE_UNITAIRE}, 0, 1),
    ("p30 variante unitaire `Value::Null`, bloc rustfmt", _e('.map_err(|_| { Value::Null })?'),
     {FORME_VARIANTE_UNITAIRE}, 0, 1),
    ("p31 variante à deux champs `Refus::Refusee(\"x\", id)`", _e('.map_err(|_| Refus::Refusee("x", id))?'),
     {FORME_VARIANTE_A_PLUSIEURS_CHAMPS}, 0, 1),
    ("p32 trois champs, virgule DANS le littéral, champ `&nom` et `x.clone()`",
     _e('.map_err(|_| Refus::Refusee("absent, ou pas", &nom, x.clone(),))?'), {FORME_VARIANTE_A_PLUSIEURS_CHAMPS}, 0, 1),
    ("p33 deux champs littéraux dont une variante d'un littéral",
     _e('.map_err(|_| Refus::Double(Motif::Absent("x"), ABSENT))?'), {FORME_VARIANTE_A_PLUSIEURS_CHAMPS}, 0, 1),
    ("p34 jambe liée : `match &r`, receveur coupé par rustfmt, instruction entre les deux, chaîne `.map(..)`",
     _f('    let mut r: Result<i64, rusqlite::Error> = conn\n        .query_row("SELECT 1", [], |r| r.get::<_, i64>(0))'
        '\n        .map(|v| v + 1);\n    let autre = 2;\n    match &r {\n        Ok(v) => ok(v),\n'
        '        _ => StatusCode::FORBIDDEN.into_response(),\n    }'), {FORME_LIEE + "Err => 403"}, 0, 0, 1),
    ("p35 jambe liée : bras qui journalise puis rend `None`",
     _l(_Q, bras='        Err(e) => {\n            eprintln!("{e}");\n            None\n        }'),
     {FORME_LIEE + "Err => valeur"}, 0, 0, 1),
    ("p36 jambe liée : le nom cité dans un littéral avant le `match` ne l'arrête pas",
     _l(_Q, entre='    let t = "r";\n'), LIE_404, 0, 0, 1),
    ("p37 jambe liée : receveur `db.lock()`", _l('db.lock().query_row("SELECT 1", [], |r| r.get::<_, i64>(0))'),
     LIE_404, 0, 0, 1),
    ("n31 variante d'un littéral qui AVOUE `Refus::NonLu(\"…\")`", _e('.map_err(|_| Refus::NonLu("x".to_string()))?'),
     set(), 0, 1),
    ("n32 constante qui avoue `CAUSE_X_NON_LUE`", _e('.map_err(|_| CAUSE_X_NON_LUE.to_string())?'), set(), 0, 1),
    # `n33` d'avant (« variante dont le champ avoue », non accusée) est devenue `p57` (vague BE : seule la tête compte).
    ("n34 deux champs dont la variante avoue `Refus::Illisible(\"x\", id)`",
     _e('.map_err(|_| Refus::Illisible("x", id))?'), set(), 0, 1),
    ("n35 deux champs dont l'un est un appel (limite écrite)", _e('.map_err(|_| Refus::Refusee("x", nom(id)))?'),
     set(), 0, 1),
    ("n36 un seul champ, non littéral (pas une variante à plusieurs champs)", _e('.map_err(|_| Refus::Refusee(id))?'),
     set(), 0, 1),
    ("n37 variante dont le nom CONTIENT `NonLu` sans l'être (`NonLuxe`) : toujours accusée",
     _e('.map_err(|_| Refus::NonLuxe)?'), {FORME_VARIANTE_UNITAIRE}, 0, 1),
    ("n48 jambe liée : bras qui AVOUE par une constante servie (`(None, CAUSE_X_NON_RELU)`, forme de `destination_flush`)",
     _l(_Q, bras='        Err(e) => {\n            eprintln!("{e}");\n            (None, CAUSE_X_NON_RELU)\n        }'),
     set(), 0, 0, 1),
    ("n49 jambe liée : bras qui avoue dans le corps servi (`corps[..] = json!(CAUSE_X_NON_RELUE)`, forme de "
     "`case_create`)", _l(_Q, bras='        Err(_) => corps["x_non_lu"] = json!(CAUSE_X_NON_RELUE),'), set(), 0, 0, 1),
    ("n50 jambe liée : bras qui avoue par une variante (`Refus::NonLu`)", _l(_Q, bras='        Err(_) => Refus::NonLu,'),
     set(), 0, 0, 1),
    ("p38 la constante qui avoue N'EST QUE dans le journal : fabrique",
     _m('        Err(e) => {\n            eprintln!("{} {e}", CAUSE_X_NON_LU);\n            None\n        }'), {"Err => valeur"}, 1),
    ("p39 la constante qui avoue sous un statut de client : le 404 l'emporte",
     _m('        Err(_) => (StatusCode::NOT_FOUND, CAUSE_X_NON_LU).into_response(),'), {"Err => 404"}, 1),
    ("p40 « NON_LU » dans un LITTÉRAL de chaîne n'avoue rien", _m('        Err(_) => json!("CAUSE_X_NON_LU"),'),
     {"Err => valeur"}, 1),
    ("p41 nom voisin qui n'avoue pas (`CAUSE_X_NON_LUMINEUX`)", _m('        Err(_) => json!(CAUSE_X_NON_LUMINEUX),'),
     {"Err => valeur"}, 1),
    ("p42 seconde jambe : la constante qui avoue sous un statut de client `not_found(CAUSE_X_NON_LU)` : le 404 "
     "l'emporte", _e('.map_err(|_| not_found(CAUSE_X_NON_LU))?'), {JAMBE_MAP_ERR + "404"}, 0, 1),
    ("p43 seconde jambe : `err_json(StatusCode::NOT_FOUND, CAUSE_X_NON_LU)`",
     _e('.map_err(|_| err_json(StatusCode::NOT_FOUND, CAUSE_X_NON_LU))?'), {JAMBE_MAP_ERR + "404"}, 0, 1),
    ("p44 seconde jambe : `bad_req(CAUSE_X_NON_LU)`", _e('.map_err(|_| bad_req(CAUSE_X_NON_LU))?'),
     {JAMBE_MAP_ERR + "400"}, 0, 1),
    ("p45 seconde jambe : la variante qui avoue sous un refus `forbidden(Refus::NonLu)`",
     _e('.map_err(|_| forbidden(Refus::NonLu))?'), {JAMBE_MAP_ERR + "403"}, 0, 1),
    ("n51 deux champs SANS littéral (`Refus::Refusee(id, nom)`)", _e('.map_err(|_| Refus::Refusee(id, nom))?'), set(), 0, 1),
    ("n52 jambe liée : une FERMETURE liée (`let r = move || conn.query_row(..);`)", _l('move || ' + _Q), set(), 0, 0, 0),
    ("n53 jambe liée : la lecture en ARGUMENT (`let r = f(conn.query_row(..));`)", _l('f(' + _Q + ')'), set(), 0, 0, 0),
    ("n54 variante unitaire `Refus::NonRelue` (relecture avouée)", _e('.map_err(|_| Refus::NonRelue)?'), set(), 0, 1),
    ("n55 jambe liée : bras qui avoue par une constante `…_ILLISIBLE`",
     _l(_Q, bras='        Err(_) => (None, CAUSE_X_ILLISIBLE),'), set(), 0, 0, 1),
    ("n56 variante `Refus::Illisible` (sans champ)", _e('.map_err(|_| Refus::Illisible)?'), set(), 0, 1),
] + EPREUVES_VAGUE_BE + EPREUVES_VAGUE_BF + [
    ("n38 jambe liée en trois issues (`.optional()`)", _l(_Q + '.optional()'), set(), 0, 0, 0),
    ("n39 jambe liée : bras qui propage", _l(_Q, bras='        Err(e) => return Err(e),'), set(), 0, 0, 1),
    ("n40 jambe liée : première consommation hors `match` (`?`)", _l(_Q, entre='    let w = r?;\n', scrutateur='w'),
     set(), 0, 0, 0),
    ("n41 jambe liée : nom RE-LIÉ avant le `match`", _l(_Q, entre='    let r = autre();\n'), set(), 0, 0, 0),
    ("n42 jambe liée : quelque chose APRÈS la chaîne dans l'instruction", _l(_Q + ' == Ok(1)'), set(), 0, 0, 0),
    ("n43 jambe liée : la lecture dans une fermeture (receveur non apparié)",
     _l('spawn(move || ' + _Q + ')'), set(), 0, 0, 0),
    # `n44` (vague BE) porte un `match` : sans lui, elle passait quelle que soit l'implémentation. `match _` ne compile pas
    # en Rust, et c'est voulu : l'épreuve fixe que `_` n'est jamais pris pour un nom lié.
    ("n44 jambe liée : `let _ =` puis `match _`", _l(_Q, scrutateur='_').replace('let r = ', 'let _ = ', 1), set(), 0, 0, 0),
    ("n45 jambe liée : liaison absorbée `.ok()`", _l(_Q + '.ok()'), set(), 0, 0, 0),
    ("n46 jambe liée : module de test coupé", _f('    ok()') + '#[cfg(test)]\nmod tests {\n' + _l(_Q) + '}\n',
     set(), 0, 0, 0),
    ("n47 jambe liée : le `match` porte sur un champ du nom (`r.0`)", _l(_Q, scrutateur='r.0'), set(), 0, 0, 0),
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


def epreuve_hors_de_toute_fonction():
    """Une lecture HORS de toute fonction (fermeture dans un `static`) est DITE au journal, dans la jambe directe comme
    dans la jambe liée (correction de la vague BF : la jambe liée sortait en silence) ; `let _ =` ne lie rien et ne
    l'est pas."""
    errs = []
    def statique(corps):
        return 'static X: Lazy<i64> = Lazy::new(|| {\n    ' + corps + '\n});\n'
    bras = ' {\n        Ok(v) => v,\n        Err(_) => 0,\n    }'
    cas = [("directe", statique('match ' + _Q + bras), "`match` HORS de toute fonction"),
           ("liée", statique('let r = ' + _Q + ';\n    match r' + bras), "`let r = ….query_row(..);` HORS"),
           ("`let _ =`", statique('let _ = ' + _Q + ';\n    0'), None)]
    for jambe, src, attendu in cas:
        journal = []
        analyser("/hors.rs", src, journal, constructeurs_d_aveu(definitions([("/hors.rs", src)]), [("/hors.rs", src)]))
        if attendu is None and journal:
            errs.append(f"épreuve HORS de toute fonction ({jambe}) : journal inattendu ({journal[0]})")
        if attendu is not None and (len(journal) != 1 or attendu not in journal[0]):
            errs.append(f"épreuve HORS de toute fonction (jambe {jambe}) : journal {journal or 'vide'}, attendu une "
                        f"entrée qui dise « {attendu} » — un site hors fonction sortirait en silence")
    return errs


def valider_instrument():
    r"""L'instrument s'éprouve AVANT de rendre un verdict. MUTATIONS JOUÉES le 2026-10-23, toutes en sortie 2 : chaîne
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
    introuvable".to_string()))?` : sortie 1, FORME NEUVE `variante(littéral)` ; arbre du lot : 0, population inchangée.

    VAGUE BD (2026-10-29) — épreuves `p28`-`p45`, `n22`, `n31`-`n56`, population de la jambe liée jugée (sixième terme).
    MUTANTS JOUÉS, chacun en sortie 2 : aveu par le nom ignoré dans la seconde jambe (n22) ; `NON_RELU` non reconnu
    (n48) ; garde de nom voisin retirée (p41, sur l'arbre de la vague BD ; depuis la vague BE : p61, p62) ; variante unitaire non jugée (p29) ; plusieurs champs non jugés (p31) ;
    `any(littéraux)` retiré (n36) ; `all(..)` retiré (n35) ; chaînes ignorées au découpage des champs (p32) ; virgule
    finale gardée (p32) ; valeur simple sans `&` ou sans `.clone()` (p32) ; liaison sans type (p34) ; `Illisible` et
    `ILLISIBLE` retirés un par un (n34, n55) ; `Non(Re)lu` retiré (n54) ; jambe liée retirée (p28) ; mot-clé ou fermeture
    du receveur non refusé (n52) ; `;` non exigé (n53) ; première apparition non exigée (n41) ; `match &` refusé (p34) ;
    littéraux non sautés (p36) ; accolade non exigée (n47) ; préfixe de forme perdu (p28) ; population liée non comptée
    (p28) ; aveu par le nom des bras retiré (n48), lu dans les littéraux (p40), lu dans le journal (p5), jugé avant le
    statut (p1) — ces trois-là sur l'arbre de la vague BD, où l'aveu par le nom valait dans la jambe directe ; depuis la
    vague BE ils se fixent dans la jambe liée (p60, p58, p59) ; plancher lié trop haut (sortie 2 sur l'arbre). Correction : aveu jugé avant le statut dans la seconde
    jambe (p42-p45 sur l'arbre de la vague BD ; depuis la vague BE, où seule la tête avoue, p63), constante d'aveu lue
    dans le journal (p38 ; depuis la vague BE p58), statut retiré (p16, p22, p42-p45).

    VAGUE BE (2026-10-29) — épreuves `p46`-`p57`, `n57`-`n62` ; `n33` devenue `p57`, `n48`-`n50` et `n55` passées dans la
    jambe liée, `n44` porte un `match`. MUTANTS JOUÉS, chacun en sortie 2 : ombre non enjambée (p46, p47, p49, p50) ;
    ombre prise pour tout `let <nom>` (n41, n60) ; ombre sans type ni `mut` (p47) ; ombre sans `match &` (p47) ;
    paramètre de fermeture non enjambé (p48, p49) ; fermeture reconnue sans début d'argument (n59) ; `_` pris pour un
    nom (n44) ; aveu par le nom rendu à la jambe directe (p52, p53 ; p54 tient aussi par la liaison jetée) ; aveu par le nom retiré de la jambe liée (n48-n50,
    n55) ; liaison jetée lue (p56) ; aveu d'un champ remis dans la seconde jambe (p55, p57) ; variante unitaire exigeant
    un chemin, `(..::)*` -> `(..::)+` (p51) ; plancher lié remis trop haut (sortie 2 sur l'arbre). Sur une copie de
    l'arbre où le bras d'échec de `rattraper_les_echeances_multi_niveau` rend `String::new()` : sortie 1, FORME NEUVE
    `lié puis match : Err => valeur` (la garde de la vague BD rendait 0).

    CORRECTION DE LA VAGUE BE — l'aveu par le nom rendu à la seule jambe liée laissait `p38`-`p41` (jambe directe)
    passer quelle que soit l'écriture des règles qu'elles nomment, et les têtes de `p42`-`p45` n'avouent pas : épreuves
    `p58`-`p65`, `n64`, `n65`. MUTANTS JOUÉS, chacun en sortie 2 : noms d'un littéral lus comme aveu (p60) ; journal lu
    comme aveu (p58) ; aveu par le nom jugé avant le statut dans la jambe liée (p59) ; aveu jugé avant le statut dans
    la seconde jambe (p63) ; garde de nom voisin `(?![A-Z])` retirée (p61, p62) ; `{` sans profondeur dans le corps
    d'une fermeture (p64) ; `,` et `;` qui ne terminent plus ce corps (p65, n64) ; la seule `,` (n64).

    VAGUE BF (2026-11-02) — LES 79 MUTANTS DE LA VÉRIFICATION DE BE2, ET CEUX DE CE LOT. Chaque mutant est UNE
    substitution dans une copie de cette garde, jouée sur l'arbre `b29051c4` ; chacun rend la sortie 2 (91 joués, aucun
    vert). Nom du vérificateur -> nom joué ici (épreuve qui rougit la première) :
      aveu par le nom (les deux premières alternatives d'avant sont fondues en une) — M_NOM1/M_NOM2 -> N0 alternative
      `NonLu` retirée (n22) ; M_NOM3 -> N8 (n34) ; M_NOM4 -> N11 (n32) ; M_NOM5 -> N12 `RE_` retiré (n48) ; M_NOM6 -> N17
      (n55) ; M_NOM7 -> N7 lookahead de `NonLu` (n37) ; M_NOM8 -> N16 lookahead de `NON_LU` (p61) ; M_NOM9 -> N10 (p83) ;
      M_NOM10 -> N19 (p84) ; M_NOM11 et M_NOM14 -> N5 `e` retiré (n54) et N6 `s` retiré (n72) ; M_NOM12 -> N14 `E` retiré
      (n32) et N15 `S` retiré (n76) ; M_NOM13 -> N1 `Re` retiré (n54) ; M_NOM15 -> N9 (n74) ; M_NOM16 -> N18 (n75).
      Propres à la réécriture : N2 `Re` exigé (n22), N3 `l` seul (n22), N4 `L` seul (n54), N13 `RE_` exigé (n32) ;
      identifiant — M_IDN1 -> I1 (p86), M_IDN2 -> I2 (p86), et I3 le seul `.` (p87), I4 le seul `\w` (p86) ;
      liaison jetée — M_LJ1 -> J1 (p56), M_LJ2 -> J2 (p56), M_LJ3 -> J3 (p85) ;
      liaison en tête — M_LT1 -> T1 (p34), M_LT2 -> T2 (p34) ; M_LT3/M_LT4 : la classe `[^;{}=]` est RETIRÉE (vague BF),
      sa remise caractère par caractère est T3a `{`, T3b `}`, T3c `;`, T3d `=` (p67) ;
      receveur — M_RC1/M_RC2 : la liste de mots-clés est RETIRÉE (raison dans `liaison_puis_match`) ; R1 barre non
      refusée (n52), R2 barre lue dans une chaîne (p67) ; M_PV1 -> PV1 (n53) ; M_US1 -> US1 (n44) ;
      ombre — M_OM1 -> O1 (p46), M_OM2 -> O2 (p47), M_OM3 -> O3 (p47), M_OM6 -> O5 (n70) ; M_OM4/M_OM5 : le contexte `let`
      est RETIRÉ (la réaffectation est jugée), sa remise est O6 (p68) ; O4 `\b` après le nom du `match` (n70) ;
      occurrence — M_OC1 -> C1 (p70), M_OC2 -> C2 (p71), C3 le seul `\w` (p69) ; M_STR1 -> STR1 (p36), M_CL1 -> CL1
      (p48), M_MA1 -> MA1 (p34), M_MA2 -> MA2 (n47) ;
      début de fermeture — M_FP1 -> F1 (p49), M_FP2 -> F2 (p48), M_FP3 -> F3 (p72), M_FP4 -> F4 (p65), M_FP5 -> F5
      (p73), M_FP6 -> F6 (p74) ;
      corps de fermeture — M_FP9 -> F9 (p64), M_FP10 -> F10 (p65), M_FP11 -> F11 (n64), M_FP12 -> F12 (n67) ; F7 `(`
      n'ouvre plus (p64, p75), F8 `[` n'ouvre plus (p76), F13 `]` ne finit plus (n68), F14 `}` ne finit plus (n69) ;
      valeur simple — M_VS1 -> V1 (p32), M_VS2 -> V2 (p79), M_VS3 -> V3 (p32), M_VS4 -> V5 (p80) ; V4 `clone` retiré
      (p32), V6 `to_owned` retiré (p81) ;
      champs — M_CT1 -> CT1, chaînes non sautées (p32) ; M_CT2 : le saut d'échappement est celui du lecteur importé
      (`p77` le fixe) ; M_CT3 -> CT3 (p32) ; M_CT4/M_CT5 : le compte de profondeur et les deux refus d'appariement sont
      RETIRÉS — ils étaient ÉQUIVALENTS (preuve dans `champs_de_tete` : un champ accepté n'a ni virgule hors chaîne ni
      fermante sans ouvrante ; un texte non apparié laisse donc un champ refusé, verdict identique) ;
      plusieurs champs — M_MC1 -> MC1 (n36), M_MC2 -> MC2 (n35), M_MC3 -> MC3 (p33) ;
      tête — M_TETE1 -> TETE1 (p55), M_TETE2 -> TETE2 (p82) ; variante unitaire — M_VU1 -> VU1 (p51) ; M_VU2 : la
      minuscule exigée est RETIRÉE, l'ensemble sans minuscule étant pris AVANT par `corps_litteral` sous le même chemin
      (équivalence écrite à `VARIANTE_UNITAIRE`) ; L1 constante associée refusée (p66) ;
      jambe `map_err` — M_JM1 -> JM1 (p63), M_JM2 -> JM2 (n22), M_JM3 -> JM3 (p29), M_JM4 -> JM4 (p31) ;
      bras — M_VB1 -> VB1 (p52), M_VB2 -> VB2 (n48), M_VB3 -> VB3 (p60), M_VB4 -> VB4 (p58), M_VB5 -> VB5 (p56) ;
      analyse — M_AN1 -> AN1 (p28), M_AN2 -> AN2 (p28), M_MN2 -> MN2 (plancher lié 11 > relevé 10 : sortie 2 sur
      l'arbre).
    Sur une copie de l'arbre où le bras d'échec de `rattraper_les_echeances_multi_niveau` (`cases.rs`, liaison `relu`)
    rend `String::new()` : sortie 1, FORME NEUVE `lié puis match : Err => valeur` ; arbre du lot : 0.

    CORRECTION DE LA VAGUE BF — les trois mutants restés verts à la vérification de BF1, rejoués sur la garde corrigée,
    chacun en sortie 2 : V14 répétition de l'accès de champ -> `?` (p89) ; V16 parenthèse admise AVANT le nom (n79) ;
    V17 parenthèse admise APRÈS le nom (n80). Et ceux de la correction : liaison hors fonction tue dans
    `liaison_puis_match` ou dans `analyser` (épreuve HORS de toute fonction, jambe liée) ; `let _ =` hors fonction
    journalisé (même épreuve). V01 (boucle de saut retirée) était ÉQUIVALENT : la boucle est retirée, `p90` fixe le
    contrat du lecteur importé. Compilation stricte (`-W error::SyntaxWarning`) : les docstrings sont brutes."""
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
        if compteurs.get("lie", 0) != (jambe[1] if len(jambe) > 1 else 0):
            errs.append(f"épreuve « {nom} » : population de la jambe liée {compteurs.get('lie', 0)}, attendu "
                        f"{jambe[1] if len(jambe) > 1 else 0}")
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
    errs += epreuve_hors_de_toute_fonction()
    faux = [("daemon/src/handlers/fabrique.rs", 3, "f", "Err => 404", "…")]
    if {g for g, _f2, _p in juger_contre_l_ensemble(faux, {})} != {"forme neuve"}:
        errs.append("épreuve de l'ENSEMBLE (site neuf) : un site hors ensemble ne rougit plus")
    if {g for g, _f2, _p in juger_contre_l_ensemble([], {("daemon/src/handlers/fabrique.rs", "f"): ("Err => 404",)})} \
            != {"exemption sans objet"}:
        errs.append("épreuve de l'ENSEMBLE (site corrigé encore listé) : une entrée sans objet ne rougit plus")
    if juger_contre_l_ensemble(faux, {("daemon/src/handlers/fabrique.rs", "f"): ("Err => 404",)}):
        errs.append("épreuve de l'ENSEMBLE (accord) : un site exactement admis produit un écart")
    lie = [("daemon/src/handlers/fabrique.rs", 3, "f", FORME_LIEE + "Err => 404", "…")]
    if {g for g, _f2, _p in juger_contre_l_ensemble(lie, {("daemon/src/handlers/fabrique.rs", "f"): ("Err => 404",)})} \
            != {"forme neuve", "exemption sans objet"}:
        errs.append("épreuve de l'ENSEMBLE (jambe liée) : un site admis en `match` direct, réécrit en `Result` lié, passe")
    change = [("daemon/src/handlers/fabrique.rs", 3, "f", "Err => valeur", "…")]
    if {g for g, _f2, _p in juger_contre_l_ensemble(change, {("daemon/src/handlers/fabrique.rs", "f"): ("Err => 404",)})} \
            != {"forme neuve", "exemption sans objet"}:
        errs.append("épreuve de l'ENSEMBLE (forme changée) : un site admis sous une forme, réécrit sous une autre, passe")
    return errs


# ================================================================================================
# LE VERDICT
# ================================================================================================
def ce_qui_n_est_pas_tenu():
    print(f"\n[{ETIQUETTE}] CE QU'ELLE NE TIENT PAS (remesuré le 2026-11-02 sur `b29051c4`, vague BF) :\n"
          "  * trois jambes sont jugées sous `handlers/` : le `match` DIRECT (37 lectures), le `map_err` qui jette la "
          "cause (3), le `Result` LIÉ puis `match` (10 : `let r = <receveur>.query_row(..);` dont la première apparition "
          "CONSOMMANTE de `r` est `match r` ou `match &r` — l'ombre `let r = match r`, la réaffectation `r = match r` et "
          "un paramètre de fermeture `|r|` sont enjambés). Restent hors garde, du côté qui NE JUGE PAS : un `if let`/"
          "`let … else` sur la lecture ou sur le nom lié, un nom lié consommé autrement d'abord (argument, `?`, champ, "
          "capture par une fermeture), un `Result` rendu ou passé en argument, un paramètre de fermeture dont la liste "
          "porte une parenthèse avant ou après le nom (`|(a, b), r|`, `|r: (i64, i64)|`, `|(a, r): (i64, i64)|`) ou "
          "placé après `=>`, `[`, `&`, `:`, `||`, `return` (lu comme une consommation : la jambe sort). Un receveur qui "
          "porte `return` (`let r = return conn.query_row(..);`, lie `!`) est lu. Une liaison HORS de toute fonction "
          "(fermeture d'un `static`) est dite au journal et la garde refuse de conclure, comme la jambe directe. "
          "MESURÉ le 2026-11-02 (correction de la vague BF, mêmes lecteurs), les lectures à chaîne nue sous `handlers/` "
          "qu'aucune jambe ne lit : 0 `if let`, 0 `let … else` ; 3 noms liés consommés autrement, honnêtes "
          "(`caseops.rs` 579, fermeture `lire` puis `match lire(..)` qui nomme `QueryReturnedNoRows` ; `caseops.rs` 1209 "
          "et `cases.rs` 929, `match (total, lues)` qui porte l'échec) ; 18 en argument ou en retour — 4 `Result` rendus "
          "à l'appelant (`freshness.rs` 105, `incidents.rs` 1317, `panneau_resolu.rs` 361, `saved_queries.rs` 69), 10 "
          "passés à un compteur qui avoue par `non_etablis` servi (`caseops.rs` 1055 à 1065, `overview.rs` 61 à 70), 3 à "
          "`TotalBorne::depuis_un_comptage_borne` (`actions.rs` 468, `engagement.rs` 737, `threat_intel.rs` 551), 1 en "
          "tuple puis `match lu` qui le dit (`admin_ui.rs` 242, `deleted_non_lu`).\n"
          "  * hors `handlers/` (corpus NON JUGÉ par cette garde ; MESURÉ par les mêmes lecteurs sur `daemon/src` hors "
          "tests, `cold_store/tests.rs` exclu) : 27 `match` directs à chaîne nue sur 16 fichiers, 11 liés, 13 "
          "`map_err(..)?`. 14 bras que ces lecteurs accuseraient, LUS UN PAR UN, aucun ne fabrique : 4 avouent par un "
          "drapeau compté (`rollups.rs` 607/627/652/846), 2 replis conservateurs dits au journal (`rollups.rs` 827, "
          "`acces_observe.rs` 163), 4 variantes qui avouent sous un nom que la garde ne lit pas (`NonMesure` "
          "`cold_store/aging.rs` 584/683, `NonEtabli` `crypto/mod.rs` 897, `NonEtablie` `topn_cap.rs` 88), 2 propagations "
          "`autre => autre` (`ledger.rs` 36, `rbac.rs` 623), 2 sondes de classement qui retombent fail-closed "
          "(`crypto/mod.rs` 345/354). 63 chaînes absorbantes au sens de la garde sœur (`P10.20-b`) : 22 dans `migrate.rs` "
          "(repli du moteur de migration dit par `P10.20-f`/`P10.20-i`), 3 dans `seeds.rs` (démonstration), 1 dans "
          "`auth.rs` 1466 (`None` renvoie au lecteur de l'écrivain, en trois issues), 6 confusions FAIL-CLOSED à cause "
          "fausse (`state.rs` 509 `catalog_route`, 1430/1434/1443 `resolve_user_tenant` servie en « aucun grant », 403 ; "
          "`tenants.rs` 773 `tenant_delete` 404 « tenant inconnu » ; `tenants.rs` 134 `tenant_provision`, existence lue par "
          "`is_ok` dans la transaction, l'INSERT qui suit échoue et tout est annulé sous sa cause). Les 31 autres, RELUES "
          "UNE PAR UNE le 2026-11-02 : 12 replis qui DÉCLENCHENT ou REFUSENT (`cold_store/aging.rs` 520 tir ; "
          "`exercice_de_restauration.rs` 284 « jamais » ; `maj_corroboree.rs` 231 et 259, aucune fenêtre ; "
          "`rollup_coverage.rs` 96 et 245 `unproven` ; `rollups.rs` 566 reconstruction ; `server/mod.rs` 868 "
          "ré-annonce ; `server/travaux_sur_la_base.rs` 49 et 51 aucun vacuum ; `compactage_fts.rs` 286 aucune fusion ; "
          "`wal_empreinte.rs` 286 taille de page par défaut, jamais une borne nulle) ; 8 AVEUX portés (`compactage_fts.rs` "
          "304 `Echec` et 312 « non mesurés » ; `index_usage.rs` 291 non publié ; `sonde_du_magasin_de_secrets.rs` 195, 226 "
          "et 232, `None` porté au bilan ; `soql_glue.rs` 303 aucun oracle, dit ; `tri_des_connexions.rs` 66 "
          "`Tri::Illisible`) ; 2 sentinelles `-1` dites (`main.rs` 2135 et 2155, sous-commande `db-stats`, première "
          "lecture fail-closed) ; 3 OMISSIONS (`backup/verification.rs` 142, version de schéma tue au rapport ; "
          "`controles_de_defense.rs` 108 et 121, « même état depuis » tu au titre, l'alerte écrite) ; 6 DIAGNOSTICS À "
          "CAUSE FAUSSE, sans décision ni sécurité en jeu (`index_usage.rs` 213 et 224, régime « aucune statistique » "
          "publié sur une lecture ratée, et 311 « non compilé » ; `ventilation_serie.rs` 272, tailles nulles passées à la "
          "mesure ; `server/travaux_sur_la_base.rs` 33, « auto_vacuum=-1 … INOPÉRANT » au journal ; "
          "`sonde_du_magasin_de_secrets.rs` 250, « dénominateur non publié par le capteur » dit aussi d'une lecture "
          "ratée). Les lectures à chaîne nue qu'aucune jambe ne lit (MESURÉ le 2026-11-02, correction de la vague BF ; "
          "le relevé du 2026-10-23 disait « 7 `if let` directs, 15 autres ») : 9 `if let` — 4 sur `Err(e)` qui classent ou "
          "refusent (`integrity_check.rs` 303 ; `main.rs` 1956, 2007, 2141, sortie 1), 3 graines de migration sautées sur "
          "une lecture ratée (`migrate.rs` 2939/2940 `migrate_v10`, 3939 `migrate_v58`, repli du moteur dit par "
          "`P10.20-f`/`P10.20-i`), `rbac.rs` 1506 (`ensure_platform_user_conn` : la lecture ratée tente l'INSERT, refusé "
          "par `name UNIQUE`, `None` fail-closed sans cause), et `rollups.rs` 811 (`rollup_events`), DÉFAUT LU, NON JOUÉ : "
          "`if let Ok(Some(t))` sur le `MIN(ts)` des lignes tardives ; sur une erreur, `band_hi` n'est pas rétracté, sans "
          "journal ni drapeau, puis `DimRollupCoverage::publish(.., dim_at_id)` (880) déclare couvertes, sous une borne "
          "d'identifiant qui les dépasse, des lignes tardives jamais agrégées — une lecture ratée servie comme "
          "couverture ; rattaché à `P10.20-b` (famille ouverte des lectures de ligne unique hors `handlers/`, qui porte "
          "déjà `rollups.rs`), non corrigé par cette garde. 3 noms liés consommés autrement : `governance.rs` 88 "
          "(`lu.map(..)` rendu), `server/mod.rs` 711 (`comptes` porté avec sa cause), `server/travaux_sur_la_base.rs` 177 "
          "(`let _ =`, préchauffage). 16 en argument ou en retour : 8 `Result` rendus (`cold_store/seal.rs` 204 et 215, "
          "`crypto/mod.rs` 1263, `maintenance.rs` 1191, `migrate.rs` 173, `purge.rs` 678, `sondes.rs` 328, `soql_glue.rs` "
          "328), 3 à `compte_lu_ou_avoue` (`metrics.rs` 798, 1062, 1067), `detection_aveugle.rs` 220 sous `optional(..)` "
          "(trois issues), 2 liées par un `if`/`else` puis `match lu` qui dit `NonLue` (`purge.rs` 959/961), un bloc puis "
          "`match existence` en trois issues (`tenants.rs` 690), et `soql_glue.rs` 359 (`retrieves` : `false` sur une "
          "lecture ratée, le terme est alors cité en phrase, repli conservateur).\n"
          "  * seconde jambe (`map_err` qui jette la cause) : seule la fermeture `|_|`/`|_e|` suivie d'un `?` est jugée ; y "
          "sont accusés un corps LITTÉRAL, une variante d'UN littéral, une variante UNITAIRE, une variante à PLUSIEURS "
          "champs (un littéral au moins, les autres littéraux ou valeurs simples) et un statut de client. Une variante "
          "ou une constante dont le NOM DE TÊTE avoue la lecture (`NonLu`, `NonRelu`, `Illisible`, `…_NON_LU(E)`, "
          "`…_NON_RELU(E)`) n'est pas accusée : elle sert l'absence en lecture ratée (fail-closed), comme un 5xx — sauf "
          "sous un statut de client (`not_found(CAUSE_X_NON_LU)` reste accusé 404, comme dans la jambe `match`). La "
          "garde CROIT ce nom (une constante `CAUSE_X_NON_LU` dont le texte dirait « introuvable » passerait). Une "
          "constante associée (`Refus::ABSENT`) est lue comme un littéral (vague BF). Passent aussi : une variante à "
          "champs nommés (`Refus::Absent { .. }`), un champ qui est un appel ou une variante unitaire "
          "(`Refus::Refusee(\"x\", Motif::Absent)`), un `format!` qui porte un argument, une fermeture `|e|` qui ne se "
          "sert pas de `e`, un `Result` rendu sans `?`.\n"
          "  * dans un bras de la jambe LIÉE seule, un identifiant hors journal, hors littéral et hors liaison jetée "
          "(`let _c = …;`) dont le NOM avoue la lecture (`CAUSE_…_NON_RELU`, `Refus::NonLu`) vaut aveu, après le statut de "
          "client ; la garde ne vérifie pas que cet identifiant est SERVI (`(0, CAUSE_X_NON_LU)` y passe, accusé dans la "
          "jambe directe). Dans la seconde jambe, seul le nom de TÊTE avoue (`ApiError::NotFound(CAUSE_X_NON_LU)` "
          "accusé).\n"
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
    if compteurs.get("lie", 0) < PLANCHER_LIE:
        print(f"::error::{compteurs.get('lie', 0)} `Result` lié(s) puis `match`, plancher {PLANCHER_LIE} (re-mesuré le "
              f"2026-11-02 : {RELEVE_LIE}, règle des deux tiers). La lecture de la troisième jambe est cassée, ou les "
              "sites sont passés en trois issues et le plancher doit être RE-DÉRIVÉ, date écrite. La garde REFUSE DE "
              "CONCLURE.")
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
          f"daemon/src/handlers, {compteurs.get('map_err', 0)} lecture(s) `… .map_err(..)?` sans `.optional()` "
          f"(seconde jambe) et {compteurs.get('lie', 0)} `Result` lié(s) puis `match` (troisième jambe) ; "
          f"{len(sites)} site(s) qui fabriquent, "
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
