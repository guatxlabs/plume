//! KNOWLEDGE OBJECTS (#46) — objets de savoir SEARCH-TIME PERSISTÉS, auto-appliqués à la compilation GXQL
//! (parité Splunk : ce qui rend un contenu SOC PORTABLE). QUATRE types, tenant-wide (comme les règles de
//! détection ; ils façonnent la recherche de TOUT LE MONDE, donc CRUD = editor+), chargés depuis les tables
//! `knowledge_alias`/`knowledge_calc`/`knowledge_eventtype`/`knowledge_tag` (migration v94) en un
//! `guatx_core::soql::KnowledgeSet` INJECTÉ DANS LE SCHÉMA de compilation via `Schema::with_knowledge` :
//!   1. ALIAS de champ   : `canonical -> source` (recherche sur le canonique -> résout la source) ;
//!   2. CHAMPS CALCULÉS  : `name = <expr eval>` (eval implicite au-dessus de la base, ORDONNÉ) ;
//!   3. EVENT TYPES      : `name` + filtre GXQL (`eventtype=name` compile le filtre) ;
//!   4. TAGS             : `label` sur `field=value` (`tag=label` = OR des paires).
//!
//! MODE 0 : aucun KO -> `KnowledgeSet` VIDE -> le compilateur émet le SQL legacy À L'IDENTIQUE (invariant
//! absolu, prouvé côté cœur par `tests/plume_parity.rs`). Le KO se COMPOSE avec les FIELD FILTERS (#45) : il
//! passe par `soql_field`/`soql_filter_field` -> HÉRITE du masquage (un calc/eventtype/alias sur un champ
//! masqué ne peut PAS récupérer la valeur — alias résolu AVANT le masque, filtre sur champ masqué REJETÉ).
//!
//! SÛRETÉ : noms d'alias/calc/eventtype/tag + champs allowlistés (`soql_ident_ok`, mêmes idents que les
//! champs CIM) ; expressions de calc compilées par le chemin `eval` (déjà injection-safe), filtres d'eventtype
//! compilés par le chemin GXQL normal ; les valeurs de tag sont échappées (`soql_esc`). Jamais de SQL brut.
use crate::*;
use guatx_core::soql::{KnowledgeSet, Schema};

// Registre ACTIF par db_path (comme FIELD_FILTERS). VIDE/absent -> mode 0 (aucun KO).
static KNOWLEDGE: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, Arc<RegistreDeSavoir>>>> =
    std::sync::OnceLock::new();
fn knowledge_cell() -> &'static parking_lot::RwLock<HashMap<String, Arc<RegistreDeSavoir>>> {
    KNOWLEDGE.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}

/// Ce qui est publié pour un db_path : le jeu compilé ET les lignes brutes dont il est fait. Les lignes
/// sont gardées parce que le `KnowledgeSet` du cœur ne rend pas ses alias, types, tags ni macros
/// énumérables : sans elles, une table dont la lecture rate ne pourrait pas garder SA part du jeu en place
/// pendant que les autres tables, lues, font foi (`P10.20-b`, `knowledge_reload`).
struct RegistreDeSavoir {
    jeu: KnowledgeSet,
    lignes: LignesDeSavoir,
}

/// Les lignes décodées des six tables, chacune dans l'ordre de son SQL.
#[derive(Clone, Default)]
struct LignesDeSavoir {
    alias: Vec<(String, String)>,
    calc: Vec<(String, String)>,
    eventtype: Vec<(String, String)>,
    tag: Vec<(String, String, String)>,
    macros: Vec<(String, String, String)>,
    auto_lookup: Vec<(String, String, String)>,
}

impl LignesDeSavoir {
    /// Construit le jeu dans l'ordre d'avant : alias, calculs, types, tags, macros, auto-lookups, chaque
    /// table dans l'ordre de ses lignes. Le cœur revalide chaque identifiant (fail-closed : une ligne
    /// hostile est ignorée, comme avant).
    fn construire(&self) -> KnowledgeSet {
        let mut ks = KnowledgeSet::new();
        for (c, s) in &self.alias {
            ks.add_alias(c.clone(), s.clone());
        }
        for (n, e) in &self.calc {
            ks.add_calc(n.clone(), e.clone());
        }
        for (n, f) in &self.eventtype {
            ks.add_eventtype(n.clone(), f.clone());
        }
        for (l, f, v) in &self.tag {
            ks.add_tag(l.clone(), f.clone(), v.clone());
        }
        for (n, p, b) in &self.macros {
            let params: Vec<String> = p.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            ks.add_macro(n.clone(), params, b.clone());
        }
        for (n, k, o) in &self.auto_lookup {
            let out: Vec<String> = o.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            ks.add_auto_lookup(n.clone(), k.clone(), out);
        }
        ks
    }
}

/// Lectures ratées du registre de savoir PAR db_path depuis le démarrage (une par échec : préparation,
/// pas du moteur, ligne indécodable). Chaque échec est dit sur stderr (`ligne_de_lecture_de_savoir_ratee`)
/// ET compté ici ; le compte est servi par `GET /api/knowledge` sous `CLE_LECTURES_DE_SAVOIR_RATEES`
/// (`avouer_les_lectures_de_savoir_ratees`, `P10.20-b`), sur le précédent de `reload_read_failures` des
/// processeurs. Ni `/metrics` ni la console ne le lisent.
static KNOWLEDGE_LECTURES_RATEES: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, u64>>> =
    std::sync::OnceLock::new();

fn compter_une_lecture_de_savoir_ratee(db_path: &str) {
    *KNOWLEDGE_LECTURES_RATEES
        .get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
        .write()
        .entry(db_path.to_string())
        .or_insert(0) += 1;
}

/// Lectures ratées du registre de savoir de `db_path` depuis le démarrage (cf. `KNOWLEDGE_LECTURES_RATEES`) :
/// le compte de CETTE base seule — une base (un tenant) ne voit pas les échecs d'une autre.
pub(crate) fn knowledge_lectures_ratees_de(db_path: &str) -> u64 {
    KNOWLEDGE_LECTURES_RATEES
        .get()
        .and_then(|m| m.read().get(db_path).copied())
        .unwrap_or(0)
}

/// Clé du corps de `GET /api/knowledge` qui porte `knowledge_lectures_ratees_de(db_path)`. ABSENTE quand le
/// compte est nul : le corps nominal reste octet pour octet celui d'avant (convention de `S32`).
pub(crate) const CLE_LECTURES_DE_SAVOIR_RATEES: &str = "reload_read_failures";

/// Pose dans `corps` le compte des lectures ratées du registre de savoir, s'il n'est pas nul. Ce compte dit
/// que les objets APPLIQUÉS à la compilation peuvent différer des objets LISTÉS : tant qu'une table rate, sa
/// part en place est gardée (`knowledge_reload`).
pub(crate) fn avouer_les_lectures_de_savoir_ratees(mut corps: Value, lectures_ratees: u64) -> Value {
    if lectures_ratees > 0 {
        corps[CLE_LECTURES_DE_SAVOIR_RATEES] = json!(lectures_ratees);
    }
    corps
}

/// La ligne de stderr d'UN échec de lecture : la table, la base, la cause rendue par le moteur, et ce qui est
/// publié à sa place. Aucune valeur de cellule : la cause du moteur nomme le type et la colonne, pas le
/// contenu.
pub(crate) fn ligne_de_lecture_de_savoir_ratee(table: &str, db_path: &str, cause: &str, part_en_place: bool) -> String {
    let suite = if part_en_place {
        "la part en place de cette table est GARDÉE"
    } else {
        "aucun registre en place : seul ce qui a été décodé est publié"
    };
    format!("[knowledge] lecture ratée de `{table}` (registre de savoir de {db_path}) : {cause} — {suite}")
}

/// Ce qu'une table a rendu : ses lignes décodées et, s'il y en a, ses échecs (avec la cause du moteur).
struct LectureDeTable<T> {
    lignes: Vec<T>,
    echecs: Vec<String>,
}

/// Lit une table du registre SANS rien avaler : préparation, pas du moteur et ligne indécodable sont
/// chacun un échec nommé ; un pas raté arrête le parcours (la suite n'est pas lue, elle n'est pas « vide »).
fn lire_une_table_de_savoir<T>(
    conn: &Connection,
    sql: &str,
    decoder: impl Fn(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> LectureDeTable<T> {
    let mut lu = LectureDeTable { lignes: Vec::new(), echecs: Vec::new() };
    let mut st = match conn.prepare(sql) {
        Ok(st) => st,
        Err(e) => {
            lu.echecs.push(format!("préparation : {e}"));
            return lu;
        }
    };
    let mut rows = match st.query([]) {
        Ok(rows) => rows,
        Err(e) => {
            lu.echecs.push(format!("parcours : {e}"));
            return lu;
        }
    };
    loop {
        match rows.next() {
            Ok(Some(r)) => match decoder(r) {
                Ok(t) => lu.lignes.push(t),
                Err(e) => lu.echecs.push(format!("ligne : {e}")),
            },
            Ok(None) => break,
            Err(e) => {
                lu.echecs.push(format!("parcours : {e}"));
                break;
            }
        }
    }
    lu
}

/// Ce qui est publié pour UNE table : lue sans échec -> ses lignes (zéro ligne comprise : c'est le vide
/// posé par l'exploitant) ; échec et part en place -> la part EN PLACE, entière ; échec et rien en place
/// -> ce qui a été décodé. Les échecs sont versés, nommés par table, dans `echecs`.
fn retenir_une_table<T: Clone>(
    table: &'static str,
    lu: LectureDeTable<T>,
    en_place: Option<&Vec<T>>,
    echecs: &mut Vec<(&'static str, String)>,
) -> Vec<T> {
    let LectureDeTable { lignes, echecs: ratees } = lu;
    let retenu = match (ratees.is_empty(), en_place) {
        (true, _) | (false, None) => lignes,
        (false, Some(p)) => p.clone(),
    };
    echecs.extend(ratees.into_iter().map(|e| (table, e)));
    retenu
}

// db_path de COMPILATION (le tenant primaire, mode 0). Posé par `knowledge_reload` au bind/CRUD ; lu par
// `active_knowledge` sur le chemin d'émission GXQL (qui n'a pas de db_path — l'émission est db-agnostique).
static KNOWLEDGE_DB: std::sync::OnceLock<parking_lot::RwLock<String>> = std::sync::OnceLock::new();
fn knowledge_db_cell() -> &'static parking_lot::RwLock<String> {
    KNOWLEDGE_DB.get_or_init(|| parking_lot::RwLock::new(String::new()))
}

/// Valide un NOM d'objet / champ KO : identifiant GXQL sûr (alphanumérique + '_'), non vide, hors denylist
/// structurelle. Empêche toute interpolation SQL de nom (les valeurs, elles, sont échappées à la compilation).
pub(crate) fn validate_ko_ident(raw: &str) -> Result<String, String> {
    let f = raw.trim();
    if f.is_empty() {
        return Err("identifiant requis".into());
    }
    if !f.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
        return Err(format!("identifiant invalide (alphanumérique + '_' seulement) : {raw}"));
    }
    if crate::field_filter::STRUCTURAL_DENY.contains(&f) {
        return Err(format!("champ structurel non utilisable comme objet de savoir : {f}"));
    }
    Ok(f.to_string())
}

/// Valide une EXPRESSION de champ calculé en la COMPILANT via le chemin `eval` (déjà injection-safe) : on
/// construit un `KnowledgeSet` d'UN calc et on compile un `search` -> l'eval implicite s'exécute. Erreur eval
/// (fonction/mot-clé interdit, SELECT, identifiant invalide…) -> rejet. Ne persiste RIEN, ne touche pas la DB.
pub(crate) fn validate_calc_expr(name: &str, expr: &str) -> Result<(), String> {
    let mut ko = KnowledgeSet::new();
    ko.add_calc(name, expr);
    guatx_core::soql::to_sql("search", 0, 0, &Schema::events().with_knowledge(ko)).map(|_| ())
}

/// Valide un FILTRE d'event type en le compilant via `eventtype=<name>` -> le chemin GXQL normal (filtres
/// allowlistés, échappement). Erreur de filtre (champ/opérateur invalide) -> rejet. Ne persiste rien.
pub(crate) fn validate_eventtype_filter(name: &str, filter: &str) -> Result<(), String> {
    let mut ko = KnowledgeSet::new();
    ko.add_eventtype(name, filter);
    guatx_core::soql::to_sql(&format!("search eventtype={name}"), 0, 0, &Schema::events().with_knowledge(ko)).map(|_| ())
}

/// Valide une MACRO (#60) à la CRÉATION (fail-closed) : nom + params idents (validate_ko_ident), corps
/// non vide, puis DRY-EXPANSION avec des arguments factices sûrs -> le texte détendu doit COMPILER par le
/// compilateur fermé (soit tel quel, soit préfixé `search `, pour couvrir corps=pipeline ET corps=fragment).
/// Un placeholder `$x$` non déclaré (ou tout `$` résiduel) échoue la substitution -> rejet. Ne persiste rien.
pub(crate) fn validate_macro(name: &str, params: &[String], body: &str) -> Result<(), String> {
    if body.trim().is_empty() {
        return Err("macro : corps requis".into());
    }
    // 1) enregistre la macro dans un KnowledgeSet jetable (le cœur revalide nom/params ; fail-closed).
    let mut ko = KnowledgeSet::new();
    ko.add_macro(name, params.to_vec(), body);
    if !ko.has_macros() {
        return Err("macro : nom ou paramètre invalide (alphanumérique + '_' ; pas de doublon)".into());
    }
    // 2) DRY-EXPANSION : appelle la macro avec des arguments factices sûrs (charset autorisé) -> vérifie la
    //    substitution (arité, placeholders résolus, pas de `$` résiduel) SANS toucher la DB.
    let args = params.iter().map(|_| "x1".to_string()).collect::<Vec<_>>().join(",");
    let call = if params.is_empty() { format!("`{name}`") } else { format!("`{name}({args})`") };
    let expanded = guatx_core::soql::expand_macros(&call, &ko)?;
    // 3) COMPILE-CHECK du texte détendu (fermé) : accepte s'il compile TEL QUEL ou préfixé `search `.
    let sch = Schema::events();
    if guatx_core::soql::to_sql(&expanded, 0, 0, &sch).is_ok() {
        return Ok(());
    }
    guatx_core::soql::to_sql(&format!("search {expanded}"), 0, 0, &sch)
        .map(|_| ())
        .map_err(|e| format!("corps de macro non compilable : {e}"))
}

/// Valide un AUTO-LOOKUP (#60) à la création : nom de table + champ-clé + colonnes de sortie idents. On
/// COMPILE-VÉRIFIE en construisant un auto-lookup jetable et en compilant un `search` nu -> l'injection
/// `compile_lookup` (mask-aware) doit réussir. Ne persiste rien, ne touche pas la DB.
pub(crate) fn validate_auto_lookup(name: &str, key_field: &str, out_cols: &[String]) -> Result<(), String> {
    let mut ko = KnowledgeSet::new();
    ko.add_auto_lookup(name, key_field, out_cols.to_vec());
    if ko.auto_lookups().is_empty() {
        return Err("auto-lookup : nom/champ-clé/colonne invalide (alphanumérique + '_')".into());
    }
    guatx_core::soql::to_sql("search", 0, 0, &Schema::events().with_knowledge(ko)).map(|_| ())
}

/// (Re)charge le registre KO de CE db_path depuis les six tables (`knowledge_alias`/`knowledge_calc`/
/// `knowledge_eventtype`/`knowledge_tag`, v94 ; `macro_def`/`auto_lookup`, v97 ; `enabled=1`), en un
/// `KnowledgeSet` injecté à la compilation. Idempotent, appelé au bind (comme `field_filters_reload`), par
/// l'hydratation d'une base tenant et après chaque écriture CRUD. VIDE -> mode 0. NE POSE PAS le db_path de
/// compilation : l'activation (chemin d'émission db-agnostique) est SÉPARÉE (`knowledge_activate`) pour que le
/// simple chargement du cache (tests unitaires, DB non-primaire) ne CONTAMINE pas la compilation globale.
///
/// UNE LECTURE RATÉE NE RETIRE PAS UN OBJET QU'ELLE N'A PAS RELU (`P10.20-b`, sur le précédent de
/// `processors_reload`). Avant, chaque table était lue sous `if let Ok(..)` (préparation, parcours) puis
/// `rows.flatten()`, et le jeu lu REMPLAÇAIT le jeu en place : une table illisible retirait tous ses objets,
/// une ligne indécodable (cellule blob dans une colonne TEXT) retirait le sien — alias ou macros non résolus,
/// types et tags qui ne compilent plus, calculs et auto-lookups absents —, sans un mot ni un compte.
/// Désormais le jugement est PAR TABLE (le `KnowledgeSet` est indexé par nom, pas par identifiant : pas
/// d'union ligne à ligne) : une table lue sans échec fait foi, zéro ligne comprise (le vide posé par
/// l'exploitant, mode 0) ; une table dont la préparation, un pas du moteur ou une ligne a raté garde SA
/// part du jeu en place, entière, et ce qu'elle a décodé n'est pas publié ; s'il n'y avait rien en place
/// (registre jamais chargé), ce qui a été décodé est publié. Prix assumé, borné à la table en échec : tant
/// qu'elle rate, un objet supprimé ou éteint dans CETTE table reste appliqué, un objet posé depuis dans
/// cette table ne l'est pas encore. Chaque échec est dit sur stderr avec la table et la cause du moteur
/// (hors du verrou du registre) et compté, un par échec, dans `knowledge_lectures_ratees_de(db_path)`,
/// compte servi par `GET /api/knowledge` (`CLE_LECTURES_DE_SAVOIR_RATEES`, absente à zéro).
///
/// Table absente = lecture ratée : les chargements du bind et de `PreparedWriter::open` passent par la
/// porte de schéma (`prepare_schema` : chaîne de migrations jusqu'à `CODE_SCHEMA_MAX`, puis `schema_gaps`
/// qui refuse une table déclarée absente), donc les six tables existent sur une base servie — leur absence
/// y est une anomalie, pas une base ancienne. Chemin nominal (aucun échec) : jeu remplacé comme avant,
/// construit dans le même ordre.
pub(crate) fn knowledge_reload(conn: &Connection, db_path: &str) {
    for ligne in recharger_le_savoir(conn, db_path) {
        eprintln!("{ligne}");
    }
}

/// Le corps de `knowledge_reload` : recharge, compte, et rend les lignes de stderr de ses échecs (une par
/// échec, `ligne_de_lecture_de_savoir_ratee`) — rendues plutôt qu'écrites pour que les témoins les lisent.
pub(crate) fn recharger_le_savoir(conn: &Connection, db_path: &str) -> Vec<String> {
    let deux = |r: &rusqlite::Row<'_>| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?));
    let trois = |r: &rusqlite::Row<'_>| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?));
    // 1) ALIAS canonical -> source
    let alias = lire_une_table_de_savoir(conn, "SELECT canonical, source FROM knowledge_alias WHERE enabled=1 ORDER BY id", deux);
    // 2) CHAMPS CALCULÉS name = expr (ordre : ord puis id -> un calc peut réutiliser un précédent)
    let calc = lire_une_table_de_savoir(conn, "SELECT name, expr FROM knowledge_calc WHERE enabled=1 ORDER BY ord, id", deux);
    // 3) EVENT TYPES name -> filter
    let eventtype = lire_une_table_de_savoir(conn, "SELECT name, filter FROM knowledge_eventtype WHERE enabled=1 ORDER BY id", deux);
    // 4) TAGS label -> (field, value)*
    let tag = lire_une_table_de_savoir(conn, "SELECT label, field, value FROM knowledge_tag WHERE enabled=1 ORDER BY id", trois);
    // 5) MACROS (#60) name(params) -> body (le cœur revalide nom/params : add_macro fail-closed).
    let macros = lire_une_table_de_savoir(conn, "SELECT name, params, body FROM macro_def WHERE enabled=1 ORDER BY id", trois);
    // 6) AUTO-LOOKUPS (#60) name + key_field + out_cols (add_auto_lookup fail-closed).
    let auto_lookup = lire_une_table_de_savoir(conn, "SELECT name, key_field, out_cols FROM auto_lookup WHERE enabled=1 ORDER BY id", trois);
    let mut echecs: Vec<(&'static str, String)> = Vec::new();
    let mut w = knowledge_cell().write();
    let en_place = w.get(db_path).cloned();
    let p = en_place.as_deref().map(|r| &r.lignes);
    let lignes = LignesDeSavoir {
        alias: retenir_une_table("knowledge_alias", alias, p.map(|l| &l.alias), &mut echecs),
        calc: retenir_une_table("knowledge_calc", calc, p.map(|l| &l.calc), &mut echecs),
        eventtype: retenir_une_table("knowledge_eventtype", eventtype, p.map(|l| &l.eventtype), &mut echecs),
        tag: retenir_une_table("knowledge_tag", tag, p.map(|l| &l.tag), &mut echecs),
        macros: retenir_une_table("macro_def", macros, p.map(|l| &l.macros), &mut echecs),
        auto_lookup: retenir_une_table("auto_lookup", auto_lookup, p.map(|l| &l.auto_lookup), &mut echecs),
    };
    let jeu = lignes.construire();
    w.insert(db_path.to_string(), Arc::new(RegistreDeSavoir { jeu, lignes }));
    drop(w);
    echecs
        .iter()
        .map(|(table, e)| {
            compter_une_lecture_de_savoir_ratee(db_path);
            ligne_de_lecture_de_savoir_ratee(table, db_path, e, en_place.is_some())
        })
        .collect()
}

/// ACTIVE le db_path de COMPILATION (mode 0 : tenant primaire) lu par `active_knowledge` sur le chemin
/// d'émission GXQL db-agnostique. Appelé UNIQUEMENT au bind du serveur primaire et après un CRUD KO — JAMAIS
/// par un simple `knowledge_reload` (tests unitaires / DB non-primaire) -> le chargement d'un cache ne peut
/// pas détourner la compilation globale. `knowledge_reload(db_path)` DOIT précéder pour peupler le cache.
pub(crate) fn knowledge_activate(db_path: &str) {
    { let mut w = knowledge_db_cell().write();
        *w = db_path.to_string();
    }
}

/// Jeu de KO EFFECTIF pour un db_path (clone). VIDE si absent -> compilation byte-identique (mode 0).
pub(crate) fn effective_knowledge(db_path: &str) -> KnowledgeSet {
    knowledge_cell()
        .read()
        .get(db_path)
        .map(|a| a.jeu.clone())
        .unwrap_or_default()
}

/// Jeu de KO ACTIF pour la COMPILATION GXQL (chemin d'émission db-agnostique). Renvoie le KO du db_path de
/// compilation posé par `knowledge_reload`. VIDE (aucun reload / pas de KO) -> SQL byte-identique au legacy.
pub(crate) fn active_knowledge() -> KnowledgeSet {
    let db = knowledge_db_cell().read().clone();
    if db.is_empty() {
        return KnowledgeSet::new();
    }
    effective_knowledge(&db)
}

/// `P10.32-u` — LE TEXTE QUE LES JUGES D'ÉTAGES DU DÉMON DOIVENT LIRE. Le compilateur détend les macros
/// (`expand_macros`) AVANT de découper la requête en étages : une macro dont le corps est un pipeline
/// (`| stats count`) ajoute donc des étages que le texte brut ne montre pas. `keyset_applicable`,
/// `keyset_projection_augment` et `AnswerShape::of_gxql` jugent CE texte détendu, avec la MÊME fonction
/// publique du cœur et le jeu de savoir que la compilation lira. Sans backtick : texte inchangé, sans
/// cloner le jeu (même chemin rapide que le cœur). Détente en échec -> `None`, que chaque juge lit comme un
/// REFUS (le compilateur refusera la requête de toute façon ; jamais un texte brut jugé à la place).
pub(crate) fn soql_detendu_pour_juger(
    soql: &str,
    savoir: impl FnOnce() -> KnowledgeSet,
) -> Option<std::borrow::Cow<'_, str>> {
    if !soql.contains('`') {
        return Some(std::borrow::Cow::Borrowed(soql));
    }
    guatx_core::soql::expand_macros(soql, &savoir()).ok().map(std::borrow::Cow::Owned)
}
