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
static KNOWLEDGE: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, Arc<KnowledgeSet>>>> =
    std::sync::OnceLock::new();
fn knowledge_cell() -> &'static parking_lot::RwLock<HashMap<String, Arc<KnowledgeSet>>> {
    KNOWLEDGE.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}
// db_path de COMPILATION (le tenant primaire, mode 0). Posé par `knowledge_reload` au bind/CRUD ; lu par
// `active_knowledge` sur le chemin d'émission GXQL (qui n'a pas de db_path — l'émission est db-agnostique).
static KNOWLEDGE_DB: std::sync::OnceLock<parking_lot::RwLock<String>> = std::sync::OnceLock::new();
fn knowledge_db_cell() -> &'static parking_lot::RwLock<String> {
    KNOWLEDGE_DB.get_or_init(|| parking_lot::RwLock::new(String::new()))
}

/// Champs STRUCTURELS jamais aliasables/tagables (casseraient pagination/temps/anti-doublon/routage) : un
/// alias/calc/eventtype/tag ne doit pas RÉÉCRIRE ces noms. (`fields` = sac brut ; masqué séparément par #45.)
const STRUCTURAL_DENY: &[&str] = &["id", "ts", "env_id", "dedup", "origin", "engagement_id", "fields"];

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
    if STRUCTURAL_DENY.contains(&f) {
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

/// (Re)charge le registre KO de CE db_path depuis les 4 tables `knowledge_*` (enabled=1), en un `KnowledgeSet`
/// injecté à la compilation. Idempotent, appelé au bind (comme `field_filters_reload`) et après chaque écriture
/// CRUD. VIDE -> mode 0. FAIL-SAFE : table absente (base pré-v94) -> registre vide. NE POSE PAS le db_path de
/// compilation : l'activation (chemin d'émission db-agnostique) est SÉPARÉE (`knowledge_activate`) pour que le
/// simple chargement du cache (tests unitaires, DB non-primaire) ne CONTAMINE pas la compilation globale.
pub(crate) fn knowledge_reload(conn: &Connection, db_path: &str) {
    let mut ks = KnowledgeSet::new();
    // 1) ALIAS canonical -> source
    if let Ok(mut st) = conn.prepare("SELECT canonical, source FROM knowledge_alias WHERE enabled=1 ORDER BY id") {
        if let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
            for (c, s) in rows.flatten() {
                ks.add_alias(c, s); // le cœur revalide l'ident (fail-closed : une paire hostile est ignorée)
            }
        }
    }
    // 2) CHAMPS CALCULÉS name = expr (ordre : ord puis id -> un calc peut réutiliser un précédent)
    if let Ok(mut st) = conn.prepare("SELECT name, expr FROM knowledge_calc WHERE enabled=1 ORDER BY ord, id") {
        if let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
            for (n, e) in rows.flatten() {
                ks.add_calc(n, e);
            }
        }
    }
    // 3) EVENT TYPES name -> filter
    if let Ok(mut st) = conn.prepare("SELECT name, filter FROM knowledge_eventtype WHERE enabled=1 ORDER BY id") {
        if let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
            for (n, f) in rows.flatten() {
                ks.add_eventtype(n, f);
            }
        }
    }
    // 4) TAGS label -> (field, value)*
    if let Ok(mut st) = conn.prepare("SELECT label, field, value FROM knowledge_tag WHERE enabled=1 ORDER BY id") {
        if let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))) {
            for (l, f, v) in rows.flatten() {
                ks.add_tag(l, f, v);
            }
        }
    }
    // 5) MACROS (#60) name(params) -> body. FAIL-SAFE : table absente (base pré-v97) -> ignoré. Le cœur
    // revalide nom/params (add_macro fail-closed : une macro malformée n'est pas installée).
    if let Ok(mut st) = conn.prepare("SELECT name, params, body FROM macro_def WHERE enabled=1 ORDER BY id") {
        if let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))) {
            for (n, p, b) in rows.flatten() {
                let params: Vec<String> = p.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                ks.add_macro(n, params, b);
            }
        }
    }
    // 6) AUTO-LOOKUPS (#60) name + key_field + out_cols. FAIL-SAFE : table absente -> ignoré. Le cœur
    // revalide les idents (add_auto_lookup fail-closed).
    if let Ok(mut st) = conn.prepare("SELECT name, key_field, out_cols FROM auto_lookup WHERE enabled=1 ORDER BY id") {
        if let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))) {
            for (n, k, o) in rows.flatten() {
                let out: Vec<String> = o.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                ks.add_auto_lookup(n, k, out);
            }
        }
    }
    { let mut w = knowledge_cell().write();
        w.insert(db_path.to_string(), Arc::new(ks));
    }
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
        .map(|a| (**a).clone())
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
