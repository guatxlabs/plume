#!/usr/bin/env python3
"""Un identifiant inséré se lit AU PIED de son insertion — garde de CI (`P10.27-x`, `P10.27-w`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`last_insert_rowid()` rend le dernier identifiant inséré sur LA CONNEXION, toutes tables confondues. Lu
juste après l'`INSERT` d'un objet, c'est l'identifiant de cet objet. Lu après une AUTRE insertion sur la
même connexion — l'audit (`audit_config_change` insère une ligne de registre PUIS un événement de
configuration), une trace, une ligne liée —, c'est l'identifiant de cette autre ligne, et rien ne le
distingue du bon : c'est un entier.

MESURÉ le 2026-09-25 sur la forme d'avant (témoins `isdl_`, un événement déjà ingéré dans la base) :
douze créations relisaient `conn.last_insert_rowid()` APRÈS l'audit — les quatre des modèles de données,
les six des objets de savoir, `report_create` et `workflow_action_create` — et servaient le numéro de
l'ÉVÉNEMENT d'audit comme identifiant de l'objet. Le modèle d'Alice était servi avec l'identifiant du
modèle de Bob ; l'objet qu'Alice rattachait à « son » modèle entrait dans celui de Bob (200) ; la
suppression de « son » modèle, de « son » alias, de « son » rapport par l'identifiant servi retirait
celui de Bob (200). Sur une base dont les numéros d'événement ont pris de l'avance, l'identifiant servi
ne désigne plus rien (404) ; sur une table `event` vide, il COÏNCIDE avec le bon et masque le défaut.

LA RÈGLE, ÉCRITE
----------------
Pour chaque lecture `<receveur>.last_insert_rowid()` de `daemon/src/` (sous-répertoires compris, `tests/`,
`tests.rs` et les modules `#[cfg(test)]` élagués, commentaires dépouillés, littéraux exclus), le DERNIER
USAGE de ce receveur qui la précède dans la fonction englobante doit être l'appel
`<receveur>.execute("INSERT …" | "REPLACE …", …)` lui-même — ses arguments comptent comme lui. Tout autre
dernier usage est accusé, sous une forme qui dit lequel :
  * `sans insertion sur son receveur` — aucune insertion sur ce receveur avant la lecture dans la fonction
    (receveur lié, reçu en paramètre, ou insertion faite sur un AUTRE nom) ;
  * `après une écriture qui n'est pas son insertion` — un `execute`/`execute_batch` dont l'énoncé n'est pas
    un littéral `INSERT`/`REPLACE` en tête (`COMMIT`, `UPDATE`, énoncé non littéral) ; un énoncé NOMMÉ par une
    constante `&str` du même fichier est lu à sa définition (`mettre_une_riposte_en_file`) ;
  * `après un appel qui reçoit la connexion` — le receveur passé à une fonction (`audit_config_change(&conn,
    …)`, `ledger_append(conn, …)`) : la garde ne lit pas ce que fait l'appelé, elle constate qu'il PEUT
    insérer ;
  * `après un autre usage de la connexion` — une autre méthode du receveur (`query_row`, `prepare`…) :
    elle ne change pas l'identifiant, mais la lecture n'est plus au pied de l'insertion, et la règle ne se
    négocie pas à la méthode près ;
  * `receveur non nommé` — la lecture porte sur une expression (`st.db.lock().last_insert_rowid()`) : la
    garde ne sait pas suivre son dernier usage.
Le remède est toujours le même : lire l'identifiant juste après l'insertion (ou `RETURNING`), et faire
voyager la VALEUR, jamais la relire.

POURQUOI UNE GARDE NEUVE ET NON L'EXTENSION D'UNE AUTRE
-------------------------------------------------------
`check_a_swallowed_write_is_never_affirmed_as_a_fact.py` (`garde_69`) juge une CONJONCTION : une écriture
AVALÉE suivie d'un fait qui l'affirme, dont `last_insert_rowid()`. Le défaut d'ici n'avale RIEN — l'`INSERT`
et l'audit sont propagés par `?` — : c'est l'ORDRE qui est faux. Sa population (toutes les lectures
d'identifiant) n'est pas la sienne (les écritures avalées), son plancher non plus ; l'y greffer aurait
mêlé deux comptes et deux raisons dans un seul ensemble nommé. Les deux gardes se complètent : celle-là
tient que l'insertion n'est pas avalée avant la lecture, celle-ci que la lecture est au pied de
l'insertion. `check_a_transaction_boundary_is_never_swallowed.py` (`garde_72`) juge les bornes de
transaction, autre objet encore. Les LECTEURS, eux, sont importés de la famille, jamais recopiés.

POURQUOI UN ENSEMBLE NOMMÉ, JUGÉ DANS LES DEUX SENS, ET POURQUOI IL EST VIDE
---------------------------------------------------------------------------
`SITES_TOLERES` est un ensemble de sites (fichier, fonction, forme), jamais un compte : un site corrigé et un
site neuf le même jour ne se compensent pas. Il est VIDE le jour de l'écriture : les douze lectures
accusées sur l'arbre d'avant sont corrigées par le même lot. Un site neuf rougit ; une entrée qui n'est
plus accusée rougit aussi (exemption sans objet).

CE QUE CE VERT NE DIRA PAS : voir `ce_qui_n_est_pas_tenu()`.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

RACINE = (os.path.abspath(sys.argv[1]) if len(sys.argv) > 1
          else os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))

# LES LECTEURS SONT IMPORTÉS, JAMAIS RECOPIÉS (même geste que `garde_72`, qui les tient de `garde_69`). Les modules
# évaluent leur `RACINE` À L'IMPORT, par `sys.argv` : on leur passe la racine DÉJÀ calculée ici.
_ARGV = sys.argv
sys.argv = [_ARGV[0], RACINE]
try:
    from check_a_transaction_boundary_is_never_swallowed import (  # noqa: E402
        ARBRE_FABRIQUE, LITTERAL_DE_TETE, SOURCES_ATTENDUES, apparier, coupe_tests, dans_une_chaine_rust,
        fichiers_du_corpus, fonctions, portee_englobante, refuser_sur_aveu, sans_commentaires_rust,
        spans_de_chaines_rust, temoins_des_lecteurs_de_forme, temoins_du_lecteur)
finally:
    sys.argv = _ARGV

DEMON = os.path.join(RACINE, "daemon", "src")
ETIQUETTE = "identifiant-lu-au-pied-de-son-insertion"

# --- LA POPULATION : LES LECTURES D'IDENTIFIANT -----------------------------------------------------------------
# Un APPEL de méthode : `::last_insert_rowid(` (une implémentation de trait) et `fn last_insert_rowid(` (sa
# déclaration) n'en sont pas.
LECTURE_D_IDENTIFIANT = re.compile(r"\.\s*last_insert_rowid\s*\(\s*\)")
# Le receveur : un chemin de champs qui finit juste avant le point (`conn`, `c`, `self.conn`).
RECEVEUR_EN_QUEUE = re.compile(r"(?<![\w.])([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*\Z")
APPEL_D_ECRITURE = re.compile(r"\s*\.\s*(execute_batch|execute)\s*\(")
AUTRE_METHODE = re.compile(r"\s*\.\s*[A-Za-z_]\w*\s*\(")
MOTS_D_INSERTION = {"INSERT", "REPLACE"}
# Un énoncé NOMMÉ par une constante du MÊME fichier (`conn.execute(SQL_METTRE_UNE_RIPOSTE_EN_FILE, …)`) est lu à sa
# définition. Une constante d'un autre fichier n'est pas suivie : l'énoncé reste « non littéral », donc accusé.
CONSTANTE_EN_TETE = re.compile(r"\s*([A-Z_][A-Z0-9_]*)\s*[,)]")
DEFINITION_DE_CONSTANTE = re.compile(r"\bconst\s+([A-Z_][A-Z0-9_]*)\s*:\s*&\s*(?:'static\s+)?str\s*=\s*r?#*\"\s*([A-Za-z]+)")

FORMES = ("sans insertion sur son receveur", "après une écriture qui n'est pas son insertion",
          "après un appel qui reçoit la connexion", "après un autre usage de la connexion", "receveur non nommé")

# --- PLANCHER DE NON-DÉGÉNÉRESCENCE (première écriture, 2026-09-25) -------------------------------------------------
# Il ne réclame pas un volume de code : il constate qu'une LECTURE est cassée. Relevé du jour sur l'arbre corrigé :
# 53 lectures d'identifiant sur 29 fichiers ; règle des deux tiers des gardes sœurs, arrondie en dessous : 35 et 19.
# Il ne monte jamais ; il se re-dérive, date écrite ici, si un lot retire assez de lectures pour le franchir.
PLANCHER_LECTURES = 35
PLANCHER_FICHIERS = 19

# ================================================================================================
# L'ENSEMBLE NOMMÉ — LES SITES ENCORE TOLÉRÉS, AVEC LEUR RAISON
# ================================================================================================
# `(fichier, fonction) -> (forme, …)`, une forme par site. VIDE le jour de l'écriture : les douze lectures accusées sur
# l'arbre d'avant (`datamodels.rs` ×4, `knowledge.rs` ×6, `scheduled_reports.rs::report_create`,
# `workflow_actions.rs::workflow_action_create`) sont corrigées par le lot qui écrit cette garde.
SITES_TOLERES = {}


# ================================================================================================
# LA LECTURE
# ================================================================================================
def motif_du_receveur(chemin):
    """Le receveur `a.b` cherché comme un TOUT (ni prolongé à gauche par un champ, ni à droite par un identifiant)."""
    parties = [re.escape(p) for p in re.split(r"\s*\.\s*", chemin)]
    return re.compile(r"(?<![\w.])" + r"\s*\.\s*".join(parties) + r"(?!\w)")


def usages_du_receveur(code, spans, motif, debut, fin):
    """[(position, fin du nom)] des usages du receveur dans `[debut, fin)`, hors littéraux."""
    return [(m.start(), m.end()) for m in motif.finditer(code, debut, fin) if not dans_une_chaine_rust(spans, m.start())]


def appel_sur(code, fin_du_nom, constantes):
    """(méthode, ouvrante, fermante, mot de tête de l'énoncé) quand l'usage est le receveur d'un `execute`, sinon None.
    L'énoncé est un littéral en tête d'appel, ou une constante de ce fichier (`constantes` : nom -> mot de tête)."""
    m = APPEL_D_ECRITURE.match(code, fin_du_nom)
    if not m:
        return None
    ouvrante = m.end() - 1
    tete = LITTERAL_DE_TETE.match(code, m.end())
    if tete:
        mot = tete.group(1).upper()
    else:
        nommee = CONSTANTE_EN_TETE.match(code, m.end())
        mot = constantes.get(nommee.group(1)) if nommee else None
    return m.group(1), ouvrante, apparier(code, ouvrante), mot


def forme_de_la_lecture(code, spans, fns, constantes, i):
    """La forme accusée pour la lecture dont le point est en `i`, ou None quand elle est au pied de son insertion.
    Rend aussi ('PERDU', raison) quand le lecteur ne peut pas conclure."""
    rec = RECEVEUR_EN_QUEUE.search(code, max(0, i - 200), i)  # le receveur colle au point : une fenêtre courte suffit
    if not rec:
        return "receveur non nommé"
    englobante = portee_englobante(fns, i)
    if not englobante:
        return ("PERDU", "lecture d'identifiant HORS de toute fonction")
    motif = motif_du_receveur(rec.group(1))
    usages = usages_du_receveur(code, spans, motif, englobante[2], rec.start(1))
    # Les insertions sur ce receveur : leurs ARGUMENTS comptent comme elles (un `params![…]` peut nommer le receveur).
    insertions = []
    for debut_u, fin_u in usages:
        appel = appel_sur(code, fin_u, constantes)
        if appel and appel[0] == "execute" and appel[3] in MOTS_D_INSERTION:
            if appel[2] < 0:
                return ("PERDU", "parenthèse d'appel non appariée sur une insertion")
            insertions.append((debut_u, appel[1], appel[2]))
    restants = [(d, f) for d, f in usages if not any(o < d < fe for _q, o, fe in insertions)]
    if not restants:
        return "sans insertion sur son receveur"
    dernier, fin_dernier = restants[-1]
    if any(q == dernier and fe < i for q, _o, fe in insertions):
        return None
    appel = appel_sur(code, fin_dernier, constantes)
    if appel:
        return "après une écriture qui n'est pas son insertion"
    if re.search(r"\blet\s+(?:mut\s+)?\Z", code[max(0, dernier - 12):dernier]):
        return "sans insertion sur son receveur"
    if AUTRE_METHODE.match(code, fin_dernier):
        return "après un autre usage de la connexion"
    return "après un appel qui reçoit la connexion"


def analyser(chemin_relatif, texte, journal, aveux_du_lecteur=None):
    """(sites, population) pour UN fichier : sites = [(chemin, ligne, fonction, forme, extrait)]."""
    journal_du_lecteur = []
    brut = sans_commentaires_rust(texte, journal_du_lecteur)
    if journal_du_lecteur and aveux_du_lecteur is not None:
        aveux_du_lecteur[chemin_relatif] = [f"ligne {texte.count(chr(10), 0, o) + 1} : {m}"
                                            for m, o in journal_du_lecteur]
    code = coupe_tests(brut)
    fns = fonctions(code)
    spans = spans_de_chaines_rust(code)
    constantes = {m.group(1): m.group(2).upper() for m in DEFINITION_DE_CONSTANTE.finditer(code)}
    sites, population = [], 0
    for m in LECTURE_D_IDENTIFIANT.finditer(code):
        if dans_une_chaine_rust(spans, m.start()):
            continue
        population += 1
        ligne = code.count("\n", 0, m.start()) + 1
        forme = forme_de_la_lecture(code, spans, fns, constantes, m.start())
        if isinstance(forme, tuple):
            journal.append(f"{chemin_relatif}:{ligne} — {forme[1]} : le lecteur ne peut pas conclure sur cette lecture")
            continue
        if forme is None:
            continue
        englobante = portee_englobante(fns, m.start())
        debut_ligne = code.rfind("\n", 0, m.start()) + 1
        extrait = " ".join(code[debut_ligne:m.end()].split())[:140]
        sites.append((chemin_relatif, ligne, englobante[0] if englobante else "?", forme, extrait))
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
                               f"FORME NEUVE — `{fn}` ({chemin}) lit `last_insert_rowid()` {forme} ({n_vu} fois pour "
                               f"{n_admis} tolérée(s)) ; ligne(s) : {lignes}. L'identifiant rendu est alors celui de la "
                               "DERNIÈRE ligne insérée sur la connexion, pas forcément celle de l'objet : le lire juste "
                               "après son `INSERT` (ou `RETURNING`) et faire voyager la VALEUR. Sinon le site entre "
                               "dans SITES_TOLERES AVEC sa raison."))
            if n_vu < n_admis:
                ecarts.append(("exemption sans objet", chemin,
                               f"EXEMPTION SANS OBJET — `{fn}` ({chemin}) est toléré {n_admis} fois sous la forme "
                               f"`{forme}` et n'est accusé que {n_vu} fois : le site est corrigé, ou il n'existe plus, "
                               "ou cette garde a cessé de le voir. L'entrée se retire à la main EN DISANT LEQUEL."))
    return ecarts


# ================================================================================================
# LES ÉPREUVES — JOUÉES AVANT TOUTE LECTURE DU DÉPÔT, DANS LES DEUX SENS
# ================================================================================================
# Sources FABRIQUÉES, jamais prises sur l'arbre : un témoin adossé à un site réel rougirait le jour où il est corrigé.
def _f(corps):
    return "fn f(conn: &Connection) -> Response {\n" + corps + "\n}\n"


EPREUVES = [
    # --- CE QUI DOIT ÊTRE VU (témoins POSITIFS).
    ("p1 lue après l'audit (la forme mesurée)",
     _f('    conn.execute("INSERT INTO t(a) VALUES(1)", [])?;\n'
        '    audit_config_change(&conn, "k", "d", 2, "m", "{}")?;\n'
        '    let id = conn.last_insert_rowid();\n    ok(id)'),
     {"après un appel qui reçoit la connexion"}),
    ("p2 relue après la fermeture qui audite (lecture intérieure au pied, lecture extérieure accusée)",
     _f('    let r: rusqlite::Result<i64> = (|| {\n'
        '        conn.execute("INSERT INTO t(a) VALUES(1)", [])?;\n'
        '        let id = conn.last_insert_rowid();\n'
        '        audit_config_change(&conn, "k", "d", 2, "m", "{}")?;\n'
        '        Ok(id)\n    })();\n'
        '    let id = conn.last_insert_rowid();\n    ok(id)'),
     {"après un appel qui reçoit la connexion"}),
    ("p3 lue après le COMMIT (la forme de `report_create`)",
     _f('    conn.execute("INSERT INTO t(a) VALUES(1)", [])?;\n'
        '    let _ = conn.execute_batch("COMMIT");\n'
        '    Json(json!({ "id": conn.last_insert_rowid() }))'),
     {"après une écriture qui n'est pas son insertion"}),
    ("p4 aucune insertion dans la fonction", _f('    let id = conn.last_insert_rowid();\n    ok(id)'),
     {"sans insertion sur son receveur"}),
    ("p5 insertion sur un AUTRE nom", _f('    tx.execute("INSERT INTO t(a) VALUES(1)", [])?;\n    ok(conn.last_insert_rowid())'),
     {"sans insertion sur son receveur"}),
    ("p6 lue après un UPDATE", _f('    conn.execute("INSERT INTO t(a) VALUES(1)", [])?;\n'
                                  '    conn.execute("UPDATE u SET b=1", [])?;\n    ok(conn.last_insert_rowid())'),
     {"après une écriture qui n'est pas son insertion"}),
    ("p7 lue après une autre méthode", _f('    conn.execute("INSERT INTO t(a) VALUES(1)", [])?;\n'
                                           '    let n: i64 = conn.query_row("SELECT 1", [], |r| r.get(0))?;\n'
                                           '    ok(conn.last_insert_rowid() + n)'),
     {"après un autre usage de la connexion"}),
    ("p8 receveur non nommé", _f('    st.db.lock().execute("INSERT INTO t(a) VALUES(1)", [])?;\n'
                                 '    ok(st.db.lock().last_insert_rowid())'),
     {"receveur non nommé"}),
    ("p9 connexion liée puis lue sans insertion", _f('    let conn = st.db.lock();\n    ok(conn.last_insert_rowid())'),
     {"sans insertion sur son receveur"}),
    ("p10 énoncé nommé par une constante d'AILLEURS", _f('    conn.execute(SQL_INSERT, [])?;\n    ok(conn.last_insert_rowid())'),
     {"après une écriture qui n'est pas son insertion"}),
    ("p11 énoncé nommé par une constante du fichier qui n'insère pas",
     'const SQL_MAJ: &str = "UPDATE t SET a=1";\n' + _f('    conn.execute(SQL_MAJ, [])?;\n    ok(conn.last_insert_rowid())'),
     {"après une écriture qui n'est pas son insertion"}),
    # --- CE QUI NE DOIT PAS L'ÊTRE (témoins NÉGATIFS).
    ("n1 lue au pied de l'insertion", _f('    conn.execute("INSERT INTO t(a) VALUES(1)", [])?;\n'
                                         '    let id = conn.last_insert_rowid();\n'
                                         '    audit_config_change(&conn, "k", "d", 2, "m", "{}")?;\n    ok(id)'), set()),
    ("n2 bras d'un match sur l'insertion", _f('    let id = match conn.execute(\n        "INSERT INTO t(a) VALUES(?1)",\n'
                                               '        params![a],\n    ) {\n        Ok(1) => conn.last_insert_rowid(),\n'
                                               '        _ => return refus(),\n    };\n    ok(id)'), set()),
    ("n3 après un test d'échec", _f('    if conn.execute("INSERT INTO t(a) VALUES(1)", []).is_err() {\n        return refus();\n    }\n'
                                     '    ok(conn.last_insert_rowid())'), set()),
    ("n4 le receveur nommé dans les arguments de l'insertion",
     _f('    conn.execute("INSERT INTO t(a) VALUES(?1)", params![conn.is_autocommit()])?;\n    ok(conn.last_insert_rowid())'),
     set()),
    ("n5 littéral brut et OR REPLACE", _f('    conn.execute(r#"INSERT OR REPLACE INTO t(a) VALUES(1)"#, [])?;\n'
                                           '    ok(conn.last_insert_rowid())'), set()),
    ("n6 cité dans un littéral", _f('    eprintln!("conn.last_insert_rowid()");\n    ok(0)'), set()),
    ("n7 module de test coupé",
     _f('    ok(0)') + '#[cfg(test)]\nmod tests {\n    fn t(c: &Connection) -> i64 { c.last_insert_rowid() }\n}\n', set()),
    ("n8 implémentation par chemin et déclaration de trait",
     'trait SqlExec { fn last_insert_rowid(&self) -> i64; }\n'
     'impl SqlExec for Connection {\n    fn last_insert_rowid(&self) -> i64 {\n'
     '        rusqlite::Connection::last_insert_rowid(self)\n    }\n}\n', set()),
    ("n10 énoncé nommé par une constante du fichier qui insère (`mettre_une_riposte_en_file`)",
     'pub(crate) const SQL_POSER: &str =\n    "INSERT INTO action(ts) VALUES(?1)";\n'
     + _f('    match conn.execute(\n        SQL_POSER,\n        params![ts],\n    ) {\n'
          '        Ok(1) => Posee(conn.last_insert_rowid()),\n        _ => NonEcrite,\n    }'), set()),
    ("n9 champ receveur `self.conn`", 'impl S {\n    fn f(&self) -> i64 {\n'
                                      '        self.conn.execute("INSERT INTO t(a) VALUES(1)", []).unwrap();\n'
                                      '        self.conn.last_insert_rowid()\n    }\n}\n', set()),
]


def epreuve_de_la_descente():
    """Le corpus descend dans les sous-répertoires et élague `tests/` et les artefacts — dans les deux sens, et un
    fichier LISTÉ est aussi ANALYSÉ (sinon la descente ne prouve rien)."""
    errs = []
    source = _f('    let id = conn.last_insert_rowid();\n    ok(id)')
    with tempfile.TemporaryDirectory(prefix="plume-id-au-pied-") as racine:
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
    if {f for _c, _l, _fn, f, _x in sites} != {"sans insertion sur son receveur"}:
        errs.append("épreuve de la DESCENTE (analyse) : un fichier LISTÉ n'est pas ACCUSÉ")
    return errs


def valider_instrument():
    """L'instrument s'éprouve AVANT de rendre un verdict. HUIT MUTATIONS JOUÉES le 2026-09-25 sur cette garde, chacune
    seule, et ce qu'elles ont fait tomber (sortie 2 à chaque fois) : toute écriture tenue pour insertion (p3, p6, p10,
    p11) ; les arguments de l'insertion plus comptés comme elle (n4) ; les littéraux plus exclus (n6) ; les modules de
    test lus (n7) ; un appel par chemin `::` et à arguments accepté comme lecture (n8) ; le receveur réduit à son
    dernier segment (n9 — `self.conn` n'est plus trouvé sous `conn`) ; le jugement de l'ensemble débranché (les deux
    épreuves d'ensemble qui attendent un écart) ; les constantes du fichier plus lues (n10)."""
    errs = []
    try:
        temoins_du_lecteur()
    except AssertionError as e:
        errs.append(f"lecteur partagé (`sans_commentaires_rust`) : {e}")
    try:
        temoins_des_lecteurs_de_forme()
    except AssertionError as e:
        errs.append(f"lecteurs de forme Rust (`apparier`, `fonctions`, …) : {e}")
    for nom, src, attendues in EPREUVES:
        journal = []
        sites, population = analyser("/epreuve.rs", src, journal)
        vues = {f for _c, _l, _fn, f, _x in sites}
        if journal:
            errs.append(f"épreuve « {nom} » : le lecteur avoue avoir perdu quelque chose ({journal[0]})")
        if vues != attendues:
            errs.append(f"épreuve « {nom} » : formes vues {sorted(vues) or 'aucune'}, attendu {sorted(attendues) or 'aucune'}"
                        + (" — la garde ne voit plus une forme qu'elle nomme" if attendues else
                           " — la garde accuse une lecture au pied de son insertion, ou ce qui n'est pas une lecture"))
        if attendues and population < 1:
            errs.append(f"épreuve « {nom} » : aucune lecture comptée dans la population")
        if nom.startswith(("n6", "n7", "n8")) and population:
            errs.append(f"épreuve « {nom} » : {population} lecture(s) comptée(s) là où il n'y en a aucune")
    errs += epreuve_de_la_descente()
    # --- L'ENSEMBLE NOMMÉ, À SON PROPRE NIVEAU ET DANS LES DEUX SENS.
    forme = FORMES[2]
    faux = [("daemon/src/fabrique.rs", 3, "f", forme, "…")]
    if {g for g, _f2, _p in juger_contre_l_ensemble(faux, {})} != {"forme neuve"}:
        errs.append("épreuve de l'ENSEMBLE (site neuf) : un site hors ensemble ne rougit plus")
    if {g for g, _f2, _p in juger_contre_l_ensemble([], {("daemon/src/fabrique.rs", "f"): (forme,)})} \
            != {"exemption sans objet"}:
        errs.append("épreuve de l'ENSEMBLE (site corrigé encore listé) : une entrée sans objet ne rougit plus")
    if juger_contre_l_ensemble(faux, {("daemon/src/fabrique.rs", "f"): (forme,)}):
        errs.append("épreuve de l'ENSEMBLE (accord) : un site exactement toléré produit un écart")
    return errs


# ================================================================================================
# LE VERDICT
# ================================================================================================
def ce_qui_n_est_pas_tenu():
    print(f"\n[{ETIQUETTE}] CE QU'ELLE NE TIENT PAS :\n"
          "  * l'ordre qu'elle lit est TEXTUEL : une insertion écrite dans un bras frère d'un `match`, une boucle dont "
          "le tour suivant insère après la lecture, une fermeture appelée plus tard ne sont pas départagées de l'ordre "
          "d'exécution.\n"
          "  * un ALIAS du receveur (`let c = &conn;` puis `c.execute(…)`) n'est pas suivi : l'insertion faite sous "
          "l'autre nom rend la lecture accusée (`sans insertion`), jamais l'inverse.\n"
          "  * une insertion qui peut NE RIEN insérer (`INSERT OR IGNORE`, `ON CONFLICT … DO NOTHING/UPDATE`) laisse "
          "l'identifiant de la ligne PRÉCÉDENTE ; la garde l'accepte comme insertion — c'est au site de lire le compte "
          "de lignes (`Ok(1)`) avant l'identifiant.\n"
          "  * une insertion AVALÉE (`let _ = conn.execute(\"INSERT…\")` puis la lecture) est au pied de son insertion "
          "pour cette garde : c'est `check_a_swallowed_write_is_never_affirmed_as_a_fact.py` qui l'accuse.\n"
          "  * un identifiant lu au bon endroit puis REMPLACÉ plus bas, ou rendu par une autre voie qu'un "
          "`last_insert_rowid()` (compteur, `MAX(id)`) : la garde lit le site de la lecture, pas le devenir de la "
          "valeur.\n"
          "  * elle ne prouve rien à l'exécution : ce sont les témoins `isdl_` qui jouent les créations et le geste "
          "suivant par l'identifiant servi.")


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
        print("::error::aucun `rusqlite` dans daemon/Cargo.toml : `last_insert_rowid()` n'est plus la méthode que "
              "cette garde croit lire. Elle REFUSE DE CONCLURE.")
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
    if population < PLANCHER_LECTURES or len(fichiers) < PLANCHER_FICHIERS:
        print(f"::error::{population} lecture(s) d'identifiant sur {len(fichiers)} fichier(s), planchers "
              f"{PLANCHER_LECTURES}/{PLANCHER_FICHIERS} (dérivés le 2026-09-25 : 53 lectures sur 29 fichiers, règle "
              "des deux tiers). La lecture est cassée, ou un lot a retiré assez de lectures pour que les planchers "
              "doivent être RE-DÉRIVÉS, date écrite. La garde REFUSE DE CONCLURE plutôt que de rendre vert en étant aveugle.")
        ce_qui_n_est_pas_tenu()
        return 2

    for chemin, ligne, fn, forme, extrait in sorted(sites):
        print(f"::notice file={chemin},line={ligne}::`{fn}` lit `last_insert_rowid()` {forme} — `{extrait}`")
    ecarts = juger_contre_l_ensemble(sites, SITES_TOLERES)
    print(f"\n[{ETIQUETTE}] POPULATION du jour : {population} lecture(s) d'identifiant sur {len(fichiers)} fichier(s) "
          f"de daemon/src (`tests/` élagué) ; {len(sites)} hors du pied de leur insertion, "
          f"{sum(len(v) for v in SITES_TOLERES.values())} tolérée(s) par l'ensemble nommé.")
    if ecarts:
        for _g, chemin, phrase in ecarts:
            print(f"::error file={chemin}::{phrase}")
        print(f"::error::{len(ecarts)} écart(s) entre l'arbre et l'ensemble nommé ; il se corrige à la main, AVEC la "
              "raison.")
        ce_qui_n_est_pas_tenu()
        return 1
    print(f"[{ETIQUETTE}] chaque lecture d'identifiant est au pied de son insertion, et l'ensemble nommé est exactement "
          "ce que l'arbre porte. CE QUE CE VERT NE DIT PAS : que l'insertion n'a pas été avalée (autre garde), ni que "
          "l'ordre textuel est l'ordre d'exécution.")
    ce_qui_n_est_pas_tenu()
    return 0


if __name__ == "__main__":
    sys.exit(main())
