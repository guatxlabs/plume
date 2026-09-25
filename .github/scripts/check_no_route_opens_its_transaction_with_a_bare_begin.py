#!/usr/bin/env python3
"""Aucune route n'ouvre sa transaction par un `BEGIN` NU — garde de CI (`P10.28-d`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Une route qui ouvre sa transaction écrivait `if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return
server_err("verrou base indisponible"); }` (ou le même `match Txn::begin(&conn) { …, Err(_) => … }`). La forme
n'écrivait rien sur un refus — aucun défaut d'intégrité —, mais elle rendait une réponse GÉNÉRIQUE et taisait le
journal. MESURÉ le 2026-09-25 sur l'arbre d'avant (témoins `bdrn_`, `BEGIN` refusé par un autorisateur SQLite) :
quatre-vingt-neuf routes (et leurs aides) rendaient un 500 JSON « verrou base indisponible » (soixante-dix-neuf),
un 500 TEXTE (trois), un `Err` d'aide rendu en 500 (quatre, dont `purge_apply`), un 500 SANS CORPS (deux canaux),
un deux cents `{error}` (la création d'un canal) ; cinq routes des runbooks, ouvertes par le garde `Txn`, rendaient
le même 500 ; la désactivation du second facteur rendait la phrase d'une SUPPRESSION refusée. Aucune ne disait au
journal si le refus venait d'un verrou passager ou de la transaction d'un AUTRE geste restée ouverte, qui bloque
l'écrivain — deux causes qui n'appellent pas la même suite.

LA FORME COMMUNE (daemon/src/handlers/transaction_validee.rs) : `ouvrir_la_transaction_du_geste` (une route qui
ouvre par un `BEGIN`), `ouvrir_le_garde_du_geste` (une route qui ouvre par le garde `Txn`), `ouvrir_sa_transaction`
(le juge sous-jacent, pour une aide qui rend son propre `Err`). Toutes disent le refus au journal
(`dire_la_transaction_non_ouverte`) ; les deux premières rendent le 503 qui porte la CAUSE NOMMÉE du geste.

LA POPULATION, ÉCRITE
---------------------
Une OUVERTURE NUE est, dans `daemon/src/` (sous-répertoires compris, `tests/`, `tests.rs` et les modules
`#[cfg(test)]` élagués, commentaires dépouillés, littéraux exclus), HORS de `handlers/transaction_validee.rs` (où la
forme commune est définie) :
  * `BEGIN littéral` — `.execute_batch("…")` ou `.execute("…", …)` dont le littéral COMMENCE par `BEGIN` ou
    `SAVEPOINT` ;
  * `Txn::begin` — un appel `Txn::begin(` (chemin compris) ;
  * `transaction rusqlite` — `.transaction()`, `.unchecked_transaction()`, `.transaction_with_behavior(`,
    `.savepoint()`.
Les appels aux trois formes communes sont COMPTÉS (ouvertures jugées) : c'est sur la somme des deux — ouvertures
nues et jugées — que porte le plancher de non-dégénérescence.

POURQUOI « DANS UNE ROUTE », ET COMMENT C'EST LU
------------------------------------------------
Toute ouverture nue est un site ; l'ensemble nommé en tolère deux classes, chacune avec sa raison au site :
  * `SITES_HORS_ROUTE` — ce qui n'est pas une route (le garde `Txn` lui-même, les migrations, la sauvegarde, le
    tier froid, les semis, le spool, les balayages de fond) : leur refus a son propre chemin, et ce n'est pas une
    réponse HTTP. La garde VÉRIFIE qu'aucune de ces fonctions n'est une route du routeur (`server/groupes_de_routes.rs`,
    `get(f)`/`post(f)`/…) : une route rangée « hors route » rougit ;
  * `SITES_DE_ROUTE_TOLERES` — les RESTES : des routes (ou aides de route) qui ouvrent encore nu. Chacun porte la clé
    qui le reprend. Zéro reste est atteignable.
Un site neuf, où qu'il soit, rougit : il se range dans l'un des deux ensembles, avec sa raison, ou il prend la forme
commune.

POURQUOI UN ENSEMBLE NOMMÉ, JUGÉ DANS LES DEUX SENS
---------------------------------------------------
Un compte se laisse compenser. L'ensemble est fait de (fichier, fonction) -> formes (une par site, les doublons
comptent) : un site hors ensemble est une FORME NEUVE (rouge) ; une entrée qui n'est plus accusée est une EXEMPTION
SANS OBJET (rouge : corrigé sans retirer l'entrée, ou la garde a cessé de le voir — l'entrée se retire à la main EN
DISANT LEQUEL).

CE QUE CE VERT NE DIRA PAS : voir `ce_qui_n_est_pas_tenu()`.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

RACINE = (os.path.abspath(sys.argv[1]) if len(sys.argv) > 1
          else os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))

# LES LECTEURS SONT IMPORTÉS, JAMAIS RECOPIÉS (famille des gardes de forme Rust, par `P10.20-w`). Les modules évaluent
# leur `RACINE` À L'IMPORT, par `sys.argv` : on leur passe la racine déjà calculée ici.
_ARGV = sys.argv
sys.argv = [_ARGV[0], RACINE]
try:
    from check_a_swallowed_write_is_never_affirmed_as_a_fact import (  # noqa: E402
        ARBRE_FABRIQUE, SOURCES_ATTENDUES, coupe_tests, dans_une_chaine_rust, fonctions, parcours_des_sources,
        portee_englobante, refuser_sur_aveu, sans_commentaires_rust, spans_de_chaines_rust, temoins_des_lecteurs_de_forme,
        temoins_du_lecteur)
finally:
    sys.argv = _ARGV

DEMON = os.path.join(RACINE, "daemon", "src")
ETIQUETTE = "begin-nu-de-route"
FICHIER_DE_LA_FORME_COMMUNE = "daemon/src/handlers/transaction_validee.rs"
ROUTEUR = os.path.join(DEMON, "server", "groupes_de_routes.rs")

APPEL_SQL = re.compile(r"\.\s*(?:execute_batch|execute)\s*\(")
LITTERAL_DE_TETE = re.compile(r'\s*r?#*"\s*([A-Za-z]+)')
MOTS_D_OUVERTURE = {"BEGIN", "SAVEPOINT"}
APPEL_TXN_BEGIN = re.compile(r"\bTxn\s*::\s*begin\s*\(")
APPEL_TRANSACTION_RUSQLITE = re.compile(
    r"\.\s*(?:transaction|unchecked_transaction|savepoint)\s*\(\s*\)|\.\s*transaction_with_behavior\s*\(")
# Appel nu ou par chemin ; un identifiant qui PROLONGE le nom est écarté, et la définition (`fn …(`) aussi.
APPEL_DE_LA_FORME_COMMUNE = re.compile(
    r"(?<![\w])(ouvrir_la_transaction_du_geste|ouvrir_le_garde_du_geste|ouvrir_sa_transaction)\s*\(")
HANDLER_DU_ROUTEUR = re.compile(r"\b(?:get|post|put|delete|patch)\s*\(\s*([A-Za-z_][\w:]*)\s*\)")

# --- PLANCHER DE NON-DÉGÉNÉRESCENCE (première écriture, 2026-09-25) -------------------------------------
# Il constate qu'une LECTURE est cassée, il ne réclame pas un volume de code. Relevé du jour sur l'arbre (après le lot) :
# 126 ouvertures (109 jugées, 17 nues) sur 42 fichiers ; règle des deux tiers des gardes sœurs, arrondie en dessous :
# 84 et 28. Il ne monte jamais ; il se re-dérive, date écrite ici, si un lot retire assez d'ouvertures pour le franchir.
PLANCHER_OUVERTURES = 84
PLANCHER_FICHIERS = 28

# ================================================================================================
# L'ENSEMBLE NOMMÉ — (fichier, fonction) -> (forme, …), une forme par site
# ================================================================================================
# --- CE QUI N'EST PAS UNE ROUTE : le refus a son propre chemin, et ce n'est pas une réponse HTTP.
SITES_HORS_ROUTE = {
    # Le garde `Txn` lui-même : `Txn::begin` EST l'ouverture (propagée par `?`), la forme commune s'appuie sur lui.
    ("daemon/src/main.rs", "begin"): ("BEGIN littéral",),
    # Une étape de migration au démarrage : refus dit et étape abandonnée par `abort_step` (rien n'est servi).
    ("daemon/src/migrate.rs", "migrate_step"): ("BEGIN littéral",),
    # La sauvegarde en flux et la restauration : instantané de lecture et restauration sur une connexion PRIVÉE
    # (CLI, conteneur de sauvegarde), refus propagé par `?` jusqu'à la commande.
    ("daemon/src/backup/dump_restauration.rs", "backup_compressed_stream"): ("BEGIN littéral",),
    ("daemon/src/backup/dump_restauration.rs", "restore_stream"): ("BEGIN littéral",),
    # Le tier froid (feature `cold_tier`) : l'écriture d'un jour-fichier par la boucle de vieillissement, refus propagé.
    ("daemon/src/cold_store/writer.rs", "write_day_files"): ("BEGIN littéral",),
    # La ventilation de la base : un instantané de lecture (`BEGIN DEFERRED`), jugé et dit par son propre `match`.
    ("daemon/src/ventilation_serie.rs", "mesurer_une_fois"): ("BEGIN littéral",),
    # Les balayages de fond des engagements (expiration, activation) : chaque refus dit par
    # `dire_un_geste_du_cycle_non_pris`, l'engagement est repris au tour suivant.
    ("daemon/src/handlers/engagement.rs", "expire_due_engagements_conn"): ("BEGIN littéral",),
    ("daemon/src/handlers/engagement.rs", "activate_due_engagements_conn"): ("BEGIN littéral", "BEGIN littéral"),
    # Les semis au démarrage (démonstration, tableaux de bord) : refus dit, semis rejoué au démarrage suivant.
    ("daemon/src/seeds.rs", "semer_la_demonstration"): ("Txn::begin",),
    ("daemon/src/seeds.rs", "semer_sous_son_drapeau"): ("Txn::begin",),
    # Le spool de métriques et d'instantanés : refus dit par `dire_la_transaction_non_ouverte`, lot laissé au spool.
    ("daemon/src/ingest/mod.rs", "ingest_once"): ("Txn::begin", "Txn::begin"),
}

# --- LES RESTES : des routes, ou des aides de route, qui ouvrent encore nu. Chacun porte la clé qui le reprend.
SITES_DE_ROUTE_TOLERES = {
    # `purge_apply` (aide de `/api/purge/apply`, partagée avec la CLI) : son refus est une variante de `PurgeRefusal`
    # (`db`, 500 `{ok:false, refusal, message}`), un contrat propre que la forme commune ne rend pas. Le reprendre
    # demande une variante neuve et sa face console — clé proposée par le lot `P10.28-d`.
    ("daemon/src/purge.rs", "purge_apply"): ("BEGIN littéral",),
    # `scim_group_patch` (`PATCH /scim/v2/Groups/{id}`) : le refus est NOMMÉ (503, `scim_refuser_a_rejouer`, au format
    # d'erreur SCIM — RFC 7644 —, que `err_json` ne sert pas) ; le journal ne sépare pas les deux causes d'un `BEGIN`
    # refusé. Reste de la même clé.
    ("daemon/src/scim.rs", "scim_group_patch"): ("Txn::begin",),
    # `attach_runbook` (aide de `POST /api/cases/{id}/runbook`) : refus rendu en 503 par son appelant
    # (`RefusDAttache::EtapesNonEcrites`), sans la phrase d'une transaction non prise ni le journal des deux causes.
    ("daemon/src/handlers/incidents.rs", "attach_runbook"): ("Txn::begin",),
    # `poser_l_administrateur` (aide de `/api/setup` et du changement du mot de passe administrateur) : ouvre par
    # `unchecked_transaction()` (un `BEGIN` DIFFÉRÉ), et son refus remonte en 500 « mot de passe NON changé (rien n'a été
    # écrit) : transaction : … » — nommé, mais sans le 503 ni le journal des deux causes. Vu par cette garde à sa première
    # exécution (l'énoncé de `P10.28-d` ne comptait que les `BEGIN IMMEDIATE`) ; reste de la même clé.
    ("daemon/src/session.rs", "poser_l_administrateur"): ("transaction rusqlite",),
}


# ================================================================================================
# LA LECTURE
# ================================================================================================
def ouvertures_du_texte(code, spans):
    """[(forme, début)] des ouvertures NUES, et le nombre d'appels aux formes communes (hors leur définition)."""
    nues, jugees = [], 0
    for m in APPEL_SQL.finditer(code):
        if dans_une_chaine_rust(spans, m.start()):
            continue
        tete = LITTERAL_DE_TETE.match(code, m.end())
        if tete and tete.group(1).upper() in MOTS_D_OUVERTURE:
            nues.append(("BEGIN littéral", m.start()))
    for m in APPEL_TXN_BEGIN.finditer(code):
        if not dans_une_chaine_rust(spans, m.start()):
            nues.append(("Txn::begin", m.start()))
    for m in APPEL_TRANSACTION_RUSQLITE.finditer(code):
        if not dans_une_chaine_rust(spans, m.start()):
            nues.append(("transaction rusqlite", m.start()))
    for m in APPEL_DE_LA_FORME_COMMUNE.finditer(code):
        if dans_une_chaine_rust(spans, m.start()):
            continue
        if re.search(r"\bfn\s+\Z", code[max(0, m.start() - 12):m.start()]):
            continue
        jugees += 1
    return sorted(nues, key=lambda o: o[1]), jugees


def analyser(chemin_relatif, texte, journal, aveux_du_lecteur=None):
    """(sites, ouvertures lues) pour UN fichier : sites = [(chemin, ligne, fonction, forme, extrait)]."""
    journal_du_lecteur = []
    brut = sans_commentaires_rust(texte, journal_du_lecteur)
    if journal_du_lecteur and aveux_du_lecteur is not None:
        aveux_du_lecteur[chemin_relatif] = [f"ligne {texte.count(chr(10), 0, o) + 1} : {m}" for m, o in journal_du_lecteur]
    code = coupe_tests(brut)
    spans = spans_de_chaines_rust(code)
    fns = fonctions(code)
    nues, jugees = ouvertures_du_texte(code, spans)
    if chemin_relatif == FICHIER_DE_LA_FORME_COMMUNE:
        return [], jugees + len(nues)
    sites = []
    for forme, debut in nues:
        ligne = code.count("\n", 0, debut) + 1
        englobante = portee_englobante(fns, debut)
        if not englobante:
            journal.append(f"{chemin_relatif}:{ligne} — ouverture nue HORS de toute fonction : un site sans fonction ne "
                           "peut pas entrer dans l'ensemble")
            continue
        extrait = " ".join(code[max(0, debut - 40):debut + 70].split())[:140]
        sites.append((chemin_relatif, ligne, englobante[0], forme, extrait))
    return sites, jugees + len(nues)


def fichiers_du_corpus(racine=None):
    """Tous les `.rs` de `daemon/src/`, sous-répertoires compris, `tests/`, `tests.rs` et artefacts élagués par le geste
    partagé (`parcours_des_sources`). `racine` ne sert qu'aux épreuves sur un arbre FABRIQUÉ."""
    racine = DEMON if racine is None else racine
    if not os.path.isdir(racine):
        return []
    trouves = []
    for dossier, fichiers in parcours_des_sources(racine, hors=("tests", "tests.rs")):
        trouves += [os.path.join(dossier, n) for n in fichiers if n.endswith(".rs") and os.path.isfile(os.path.join(dossier, n))]
    return sorted(trouves)


def decouvrir():
    sites, journal, aveux, population, fichiers = [], [], {}, 0, set()
    for chemin in fichiers_du_corpus():
        with open(chemin, encoding="utf-8", errors="replace") as fh:
            texte = fh.read()
        rel = os.path.relpath(chemin, RACINE).replace(os.sep, "/")
        s, n = analyser(rel, texte, journal, aveux)
        sites += s
        population += n
        if n:
            fichiers.add(rel)
    return sites, journal, aveux, population, fichiers


def routes_du_routeur(texte):
    """Les noms des fonctions que le routeur sert (dernier segment d'un chemin)."""
    code = sans_commentaires_rust(texte, [])
    return {m.group(1).split("::")[-1] for m in HANDLER_DU_ROUTEUR.finditer(code)}


# ================================================================================================
# LE JUGEMENT — DANS LES DEUX SENS, ET LA CLASSE « HORS ROUTE » VÉRIFIÉE CONTRE LE ROUTEUR
# ================================================================================================
def juger_contre_l_ensemble(sites, toleres, routes):
    """[(genre d'écart, fichier, phrase)]."""
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
                dans = "dans une ROUTE du routeur" if fn in routes else "hors des routes du routeur (aide ou boucle ?)"
                ecarts.append(("forme neuve", chemin,
                               f"FORME NEUVE — `{fn}` ({chemin}, {dans}) ouvre sa transaction par `{forme}` {n_vu} fois pour "
                               f"{n_admis} tolérée(s) ; ligne(s) : {lignes}. Une route ouvre par `ouvrir_la_transaction_du_geste` "
                               "(ou `ouvrir_le_garde_du_geste`) : un refus est dit au journal et rendu en 503 NOMMÉ. Sinon le "
                               "site entre dans SITES_HORS_ROUTE ou SITES_DE_ROUTE_TOLERES AVEC sa raison."))
            if n_vu < n_admis:
                ecarts.append(("exemption sans objet", chemin,
                               f"EXEMPTION SANS OBJET — `{fn}` ({chemin}) est toléré {n_admis} fois sous `{forme}` et n'est "
                               f"accusé que {n_vu} fois : corrigé, disparu, ou la garde a cessé de le voir. L'entrée se "
                               "retire à la main EN DISANT LEQUEL."))
    return ecarts


def juger_la_classe_hors_route(hors_route, routes):
    """Une fonction rangée « hors route » que le routeur sert est une route : rouge."""
    return [("route rangée hors route", chemin,
             f"ROUTE RANGÉE HORS ROUTE — `{fn}` ({chemin}) est servie par le routeur : son ouverture nue n'est pas « hors "
             "route ». Elle prend la forme commune, ou elle entre dans SITES_DE_ROUTE_TOLERES avec sa clé.")
            for (chemin, fn) in sorted(hors_route) if fn in routes]


# ================================================================================================
# LES ÉPREUVES — JOUÉES AVANT TOUTE LECTURE DU DÉPÔT, DANS LES DEUX SENS
# ================================================================================================
def _f(corps, nom="f"):
    return f"fn {nom}(conn: &Connection) -> Response {{\n" + corps + "\n}\n"


EPREUVES = [
    # --- CE QUI DOIT ÊTRE VU (témoins POSITIFS).
    ("p1 la forme d'avant", _f('    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {\n        return server_err("verrou base indisponible");\n    }\n    ok()'),
     {"BEGIN littéral"}),
    ("p2 BEGIN propagé", _f('    conn.execute_batch("BEGIN")?;\n    ok()'), {"BEGIN littéral"}),
    ("p3 `match Txn::begin`", _f('    let tx = match Txn::begin(&conn) { Ok(t) => t, Err(_) => return server_err("x") };\n    ok()'),
     {"Txn::begin"}),
    ("p4 `Txn::begin` par son chemin", _f('    let tx = crate::Txn::begin(conn)?;\n    ok()'), {"Txn::begin"}),
    ("p5 SAVEPOINT par `execute`", _f('    conn.execute("SAVEPOINT s", [])?;\n    ok()'), {"BEGIN littéral"}),
    ("p6 littéral brut", _f('    conn.execute_batch(r"BEGIN DEFERRED")?;\n    ok()'), {"BEGIN littéral"}),
    ("p7 transaction rusqlite", _f('    let tx = conn.unchecked_transaction()?;\n    ok()'), {"transaction rusqlite"}),
    ("p8 receveur coupé par rustfmt", _f('    if conn\n        .execute_batch("BEGIN IMMEDIATE")\n        .is_err() {\n        return x();\n    }\n    ok()'),
     {"BEGIN littéral"}),
    ("p9 casse du mot", _f('    conn.execute_batch("begin immediate")?;\n    ok()'), {"BEGIN littéral"}),
    # --- CE QUI NE DOIT PAS L'ÊTRE (témoins NÉGATIFS).
    ("n1 la forme commune", _f('    if let Err(r) = ouvrir_la_transaction_du_geste(&conn, "j", "g", CAUSE) {\n        return r;\n    }\n    ok()'), set()),
    ("n2 le garde de la forme commune", _f('    let tx = match ouvrir_le_garde_du_geste(&conn, "j", "g", CAUSE) { Ok(t) => t, Err(r) => return r };\n    ok()'),
     set()),
    ("n3 le juge sous-jacent", _f('    if ouvrir_sa_transaction(conn, "j", "g").is_err() {\n        return Err(x());\n    }\n    ok()'), set()),
    ("n4 cité dans un littéral échappé", _f('    eprintln!("forme d\'avant : conn.execute_batch(\\"BEGIN IMMEDIATE\\")");\n    ok()'), set()),
    ("n5 cité dans un littéral brut", _f('    let doc = r#"conn.execute_batch("BEGIN");"#;\n    rendre(doc)'), set()),
    ("n6 COMMIT et ROLLBACK", _f('    conn.execute_batch("COMMIT")?;\n    let _ = conn.execute_batch("ROLLBACK");\n    ok()'), set()),
    ("n7 module de test coupé", _f('    ok()') + '#[cfg(test)]\nmod tests {\n    fn t(c: &Connection) { c.execute_batch("BEGIN").unwrap(); }\n}\n', set()),
    ("n8 mot BEGIN hors tête du littéral", _f('    conn.execute("INSERT INTO t VALUES(\'BEGIN\')", [])?;\n    ok()'), set()),
    ("n9 commentaire", _f('    // conn.execute_batch("BEGIN IMMEDIATE") : la forme d\'avant\n    ok()'), set()),
    ("n10 un identifiant qui prolonge `transaction`", _f('    let n = conn.transactions_ouvertes();\n    ok()'), set()),
]


def epreuve_de_la_descente():
    errs = []
    source = _f('    conn.execute_batch("BEGIN")?;\n    ok()')
    with tempfile.TemporaryDirectory(prefix="plume-begin-nu-") as racine:
        for rel in ARBRE_FABRIQUE + (("tests", "suite_fabriquee.rs"),):
            chemin = os.path.join(racine, *rel)
            os.makedirs(os.path.dirname(chemin), exist_ok=True)
            with open(chemin, "w", encoding="utf-8") as fh:
                fh.write(source)
        vus = {os.path.relpath(c, racine).replace(os.sep, "/") for c in fichiers_du_corpus(racine)}
        if SOURCES_ATTENDUES - vus:
            errs.append(f"épreuve de la DESCENTE (positif) : {sorted(SOURCES_ATTENDUES - vus)} hors du corpus")
        if vus - SOURCES_ATTENDUES:
            errs.append(f"épreuve de la DESCENTE (élagage) : {sorted(vus - SOURCES_ATTENDUES)} est entré dans le corpus")
    sites, _n = analyser("sous_repertoire_fabrique/mod.rs", source, [])
    if {f for _c, _l, _fn, f, _x in sites} != {"BEGIN littéral"}:
        errs.append("épreuve de la DESCENTE (analyse) : un fichier LISTÉ n'est pas ACCUSÉ")
    return errs


def valider_instrument():
    """L'instrument s'éprouve AVANT de rendre un verdict (mutations jouées : voir le rapport du lot `P10.28-d`)."""
    errs = []
    try:
        temoins_du_lecteur()
    except AssertionError as e:
        errs.append(f"lecteur partagé (`sans_commentaires_rust`) : {e}")
    try:
        temoins_des_lecteurs_de_forme()
    except AssertionError as e:
        errs.append(f"lecteurs de forme Rust partagés : {e}")
    for nom, src, attendues in EPREUVES:
        journal = []
        sites, population = analyser("daemon/src/epreuve.rs", src, journal)
        vues = {f for _c, _l, _fn, f, _x in sites}
        if journal:
            errs.append(f"épreuve « {nom} » : le lecteur avoue avoir perdu quelque chose ({journal[0]})")
        if vues != attendues:
            errs.append(f"épreuve « {nom} » : formes vues {sorted(vues) or 'aucune'}, attendu {sorted(attendues) or 'aucune'}")
        if (attendues or nom.startswith(("n1 ", "n2 ", "n3 "))) and population < 1:
            errs.append(f"épreuve « {nom} » : aucune ouverture comptée dans la population")
    # La forme commune n'est jamais accusée dans son propre fichier (elle y est définie) — mais elle y est comptée.
    sites, population = analyser(FICHIER_DE_LA_FORME_COMMUNE, _f('    conn.execute_batch("BEGIN IMMEDIATE")?;\n    ok()', "ouvrir_sa_transaction"), [])
    if sites or population != 1:
        errs.append("épreuve du fichier de la forme commune : accusé, ou non compté")
    errs += epreuve_de_la_descente()
    # --- L'ENSEMBLE NOMMÉ, DANS LES DEUX SENS, ET LA CLASSE « HORS ROUTE » CONTRE LE ROUTEUR.
    faux = [("daemon/src/fabrique.rs", 3, "f", "BEGIN littéral", "…")]
    if {g for g, _c, _p in juger_contre_l_ensemble(faux, {}, set())} != {"forme neuve"}:
        errs.append("épreuve de l'ENSEMBLE (site neuf) : un site hors ensemble ne rougit plus")
    if {g for g, _c, _p in juger_contre_l_ensemble([], {("daemon/src/fabrique.rs", "f"): ("BEGIN littéral",)}, set())} != {"exemption sans objet"}:
        errs.append("épreuve de l'ENSEMBLE (site corrigé encore listé) : une entrée sans objet ne rougit plus")
    if juger_contre_l_ensemble(faux, {("daemon/src/fabrique.rs", "f"): ("BEGIN littéral",)}, set()):
        errs.append("épreuve de l'ENSEMBLE (accord) : un site exactement toléré produit un écart")
    change = [("daemon/src/fabrique.rs", 3, "f", "Txn::begin", "…")]
    if {g for g, _c, _p in juger_contre_l_ensemble(change, {("daemon/src/fabrique.rs", "f"): ("BEGIN littéral",)}, set())} \
            != {"forme neuve", "exemption sans objet"}:
        errs.append("épreuve de l'ENSEMBLE (forme changée) : un site toléré sous une forme, réécrit sous une autre, passe")
    routeur = '        .route("/api/x", get(liste).post(creer))\n        .route("/api/x/{id}", delete(crate::handlers::x::retirer))\n'
    routes = routes_du_routeur(routeur)
    if routes != {"liste", "creer", "retirer"}:
        errs.append(f"épreuve du ROUTEUR : routes lues {sorted(routes)}, attendu creer, liste, retirer")
    if not juger_la_classe_hors_route({("daemon/src/fabrique.rs", "creer")}, routes):
        errs.append("épreuve de la CLASSE : une route rangée « hors route » ne rougit plus")
    if juger_la_classe_hors_route({("daemon/src/fabrique.rs", "boucle")}, routes):
        errs.append("épreuve de la CLASSE : une fonction hors du routeur est accusée d'être une route")
    return errs


# ================================================================================================
# LE VERDICT
# ================================================================================================
def ce_qui_n_est_pas_tenu():
    print(f"\n[{ETIQUETTE}] CE QU'ELLE NE TIENT PAS :\n"
          "  * elle ne sait pas si une AIDE est appelée par une route : la classe « hors route » est vérifiée contre le seul "
          "routeur (une aide de route rangée « hors route » passerait) — chaque entrée porte sa raison, lue à la main.\n"
          "  * elle ne juge pas CE QUE rend l'appelant d'`ouvrir_sa_transaction` : une aide peut prendre le juge commun puis "
          "rendre un 500 générique ; ce sont les témoins `bdrn_` qui jouent les réponses.\n"
          "  * une ouverture dont le SQL n'est pas un LITTÉRAL en tête d'appel (constante, `format!`) n'entre pas dans la "
          "population.\n"
          "  * les modules `#[cfg(test)]` en ligne sont coupés à partir du premier (lecteur partagé `coupe_tests`).\n"
          "  * elle ne prouve rien à l'exécution : elle constate qu'une forme est absente, jamais qu'un `BEGIN` refusé rend "
          "bien son 503 nommé (témoins `bdrn_`, `isdl_`).")


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
    if not re.search(r"^\s*rusqlite\s*=", manifeste, re.M) or not os.path.isfile(ROUTEUR):
        print("::error::aucun `rusqlite` dans daemon/Cargo.toml, ou routeur introuvable : la garde REFUSE DE CONCLURE.")
        ce_qui_n_est_pas_tenu()
        return 2
    with open(ROUTEUR, encoding="utf-8", errors="replace") as fh:
        routes = routes_du_routeur(fh.read())
    if len(routes) < 100:
        print(f"::error::{len(routes)} route(s) lue(s) dans le routeur (plancher 100) : la lecture du routeur est cassée. "
              "La garde REFUSE DE CONCLURE.")
        ce_qui_n_est_pas_tenu()
        return 2
    sites, journal, aveux, population, fichiers = decouvrir()
    if aveux and refuser_sur_aveu(ETIQUETTE, aveux, "Rust"):
        ce_qui_n_est_pas_tenu()
        return 2
    if journal:
        for a in journal:
            print(f"::error::{a}")
        print(f"\n[{ETIQUETTE}] REFUS DE CONCLURE — le lecteur avoue avoir perdu une expression.")
        ce_qui_n_est_pas_tenu()
        return 2
    if population < PLANCHER_OUVERTURES or len(fichiers) < PLANCHER_FICHIERS:
        print(f"::error::{population} ouverture(s) lue(s) sur {len(fichiers)} fichier(s), planchers {PLANCHER_OUVERTURES}/"
              f"{PLANCHER_FICHIERS} (dérivés le 2026-09-25 : 126 sur 42, règle des deux tiers). La lecture est cassée, ou "
              "un lot a retiré assez d'ouvertures pour que les planchers doivent être RE-DÉRIVÉS, date écrite.")
        ce_qui_n_est_pas_tenu()
        return 2
    for chemin, ligne, fn, forme, extrait in sorted(sites):
        print(f"::notice file={chemin},line={ligne}::`{fn}` ouvre sa transaction par `{forme}` — `{extrait}`")
    toleres = {}
    for classe in (SITES_HORS_ROUTE, SITES_DE_ROUTE_TOLERES):
        for cle, formes in classe.items():
            toleres[cle] = tuple(toleres.get(cle, ())) + tuple(formes)
    ecarts = juger_contre_l_ensemble(sites, toleres, routes) + juger_la_classe_hors_route(SITES_HORS_ROUTE, routes)
    restes = sum(len(v) for v in SITES_DE_ROUTE_TOLERES.values())
    print(f"\n[{ETIQUETTE}] POPULATION du jour : {population} ouverture(s) de transaction sur {len(fichiers)} fichier(s) de "
          f"daemon/src ({population - len(sites)} par la forme commune, {len(sites)} nue(s)) ; {len(routes)} route(s) lue(s) "
          f"dans le routeur ; tolérées : {sum(len(v) for v in SITES_HORS_ROUTE.values())} hors route, {restes} reste(s) de route.")
    if ecarts:
        for _g, chemin, phrase in ecarts:
            print(f"::error file={chemin}::{phrase}")
        print(f"::error::{len(ecarts)} écart(s) entre l'arbre et l'ensemble nommé ; il se corrige à la main, AVEC la raison.")
        ce_qui_n_est_pas_tenu()
        return 1
    print(f"[{ETIQUETTE}] l'ensemble nommé est EXACTEMENT ce que l'arbre porte. CE QUE CE VERT NE DIT PAS : les {restes} "
          "reste(s) de route sont des DÉFAUTS CONNUS (réponse sans la forme commune) ; le vert dit seulement qu'aucune "
          "ouverture nue neuve n'est entrée.")
    ce_qui_n_est_pas_tenu()
    return 0


if __name__ == "__main__":
    sys.exit(main())
