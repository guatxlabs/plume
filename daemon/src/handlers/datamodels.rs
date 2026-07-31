//! #47 — CRUD des DATA MODELS (data_model / data_model_object / data_model_field), exécution de PIVOT
//! (report-builder SANS SPL) et DATASETS (résultats sauvegardés réutilisables).
//!
//! RBAC : le CRUD des modèles/objets/champs/datasets = editor+ (ils façonnent une couche sémantique
//! PARTAGÉE, comme les knowledge objects #46 ; `route_min_role` gate `/api/datamodels` et `/api/datasets` en
//! Write). L'EXÉCUTION d'un Pivot / dataset = viewer+ (lecture, `readonly_post`) — soumise au masquage de
//! champ #45 du rôle de l'appelant, car elle passe par le MÊME `soql_to_sql_masked_x` que /api/query.
//!
//! Un Pivot ne fabrique JAMAIS de SQL : `pivot_to_soql` (module `datamodels`) produit du GXQL, compilé par le
//! chemin masqué normal -> masquage jamais contourné, denylist de secrets intacte, enum de commandes fermée.
use crate::*;


/// Squelette transactionnel commun aux mutations (create/delete) auditées.
fn dm_commit(conn: &Connection, outcome: rusqlite::Result<i64>, ok_val: Value) -> Response {
    match outcome {
        Ok(_) => {
            let _ = conn.execute_batch("COMMIT");
            Json(ok_val).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            if e.to_string().contains("UNIQUE") {
                return bad_req("un objet porte déjà ce nom");
            }
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

// =================================================================================================
// GET /api/datamodels — arbre complet (modèles -> objets -> champs). viewer+ (transparence).
// =================================================================================================
pub(crate) async fn datamodels_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    crate::req_conn!(st, au, conn);
    let models: Vec<Value> = conn
        .prepare("SELECT id,name,title,description,category,enabled,managed,created,updated FROM data_model ORDER BY id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "name": r.get::<_,String>(1)?, "title": r.get::<_,String>(2)?,
                    "description": r.get::<_,String>(3)?, "category": r.get::<_,String>(4)?, "enabled": r.get::<_,i64>(5)? != 0,
                    "managed": r.get::<_,i64>(6)?, "created": r.get::<_,i64>(7)?, "updated": r.get::<_,i64>(8)? }))
            })
            .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    let objects: Vec<Value> = conn
        .prepare("SELECT id,model_id,name,parent_id,constraint_soql,enabled,created,updated FROM data_model_object ORDER BY model_id, id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "model_id": r.get::<_,i64>(1)?, "name": r.get::<_,String>(2)?,
                    "parent_id": r.get::<_,Option<i64>>(3)?, "constraint": r.get::<_,String>(4)?, "enabled": r.get::<_,i64>(5)? != 0,
                    "created": r.get::<_,i64>(6)?, "updated": r.get::<_,i64>(7)? }))
            })
            .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    let fields: Vec<Value> = conn
        .prepare("SELECT id,object_id,name,ftype,expr,created FROM data_model_field ORDER BY object_id, id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "object_id": r.get::<_,i64>(1)?, "name": r.get::<_,String>(2)?,
                    "type": r.get::<_,String>(3)?, "expr": r.get::<_,String>(4)?, "created": r.get::<_,i64>(5)? }))
            })
            .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    Json(json!({ "models": models, "objects": objects, "fields": fields,
        "field_types": DM_FIELD_TYPES, "stat_funcs": DM_STAT_FUNCS, "filter_ops": DM_FILTER_OPS })).into_response()
}

// =================================================================================================
// MODÈLES
// =================================================================================================
pub(crate) async fn model_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let name = match validate_dm_ident(b.str_field("name")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let title = b.str_field("title").trim().to_string();
    let description = b.str_field("description").trim().to_string();
    // category optionnelle : si fournie, doit être une catégorie CIM connue (couche sémantique = sur le CIM).
    let category = b.str_field("category").trim().to_string();
    if !category.is_empty() && !cim_category_ok(&category) {
        return bad_req(format!("catégorie CIM inconnue : {category}"));
    }
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO data_model(name,title,description,category,enabled,created,updated) VALUES(?1,?2,?3,?4,?5,?6,?6)",
            params![name, title, description, category, enabled, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.datamodel.create",
            &format!("data model '{name}' (#{id}) par {}", au.name), 2,
            &format!("data model '{name}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"data_model", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    let id = conn.last_insert_rowid();
    dm_commit(&conn, outcome, json!({ "id": id }))
}

pub(crate) async fn model_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM data_model WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("data model introuvable"),
    };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        // Cascade manuelle : champs des objets du modèle, puis objets, puis modèle.
        conn.execute("DELETE FROM data_model_field WHERE object_id IN (SELECT id FROM data_model_object WHERE model_id=?1)", params![id])?;
        conn.execute("DELETE FROM data_model_object WHERE model_id=?1", params![id])?;
        conn.execute("DELETE FROM data_model WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.datamodel.delete",
            &format!("data model '{name}' (#{id}) supprimé par {}", au.name), 2,
            &format!("data model '{name}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"data_model", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    dm_commit(&conn, outcome, json!({ "ok": true }))
}

// =================================================================================================
// OBJETS (hiérarchiques : parent_id ; constraint = fragment de filtre GXQL compile-vérifié)
// =================================================================================================
pub(crate) async fn object_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(model_id): Path<i64>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let name = match validate_dm_ident(b.str_field("name")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let constraint = b.str_field("constraint").trim().to_string();
    // COMPILE-CHECK de la contrainte (fragment GXQL) AVANT persistance (fail-closed, enum fermée).
    if let Err(e) = validate_dm_constraint(&constraint) { return bad_req(e); }
    let parent_id = b.get("parent_id").and_then(|v| v.as_i64());
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    // Vérifie l'existence du modèle et (si fourni) du parent DANS LE MÊME MODÈLE (pas de hiérarchie cross-modèle).
    if conn.query_row("SELECT 1 FROM data_model WHERE id=?1", params![model_id], |_| Ok(())).is_err() {
        return not_found("data model introuvable");
    }
    if let Some(pid) = parent_id {
        match conn.query_row("SELECT model_id FROM data_model_object WHERE id=?1", params![pid], |r| r.get::<_,i64>(0)) {
            Ok(m) if m == model_id => {}
            Ok(_) => return bad_req("objet parent d'un autre modèle"),
            Err(_) => return bad_req("objet parent introuvable"),
        }
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO data_model_object(model_id,name,parent_id,constraint_soql,enabled,created,updated) VALUES(?1,?2,?3,?4,?5,?6,?6)",
            params![model_id, name, parent_id, constraint, enabled, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.datamodel.object.create",
            &format!("objet '{name}' (#{id}) du modèle #{model_id} par {}", au.name), 2,
            &format!("objet de data model '{name}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"data_model_object", "id":id, "model_id":model_id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    let id = conn.last_insert_rowid();
    dm_commit(&conn, outcome, json!({ "id": id }))
}

pub(crate) async fn object_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM data_model_object WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("objet introuvable"),
    };
    // Refus si l'objet a des enfants (évite d'orpheliner une hiérarchie ; l'éditeur supprime feuille-à-racine).
    let has_children: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM data_model_object WHERE parent_id=?1)", params![id], |r| r.get::<_,i64>(0)).map(|n| n != 0).unwrap_or(false);
    if has_children { return bad_req("objet parent d'autres objets : supprimez d'abord les enfants"); }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM data_model_field WHERE object_id=?1", params![id])?;
        conn.execute("DELETE FROM data_model_object WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.datamodel.object.delete",
            &format!("objet '{name}' (#{id}) supprimé par {}", au.name), 2,
            &format!("objet de data model '{name}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"data_model_object", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    dm_commit(&conn, outcome, json!({ "ok": true }))
}

// =================================================================================================
// CHAMPS TYPÉS (allowlist du Pivot ; expr optionnelle -> peut référencer un alias/calc #46)
// =================================================================================================
pub(crate) async fn field_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(object_id): Path<i64>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let name = match validate_dm_ident(b.str_field("name")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let ftype = match validate_dm_ftype(b.str_field("type")) { Ok(t) => t, Err(e) => return bad_req(e) };
    // expr optionnelle : si fournie, doit être un identifiant GXQL sûr (nom de champ SOURCE, alias/calc #46).
    // On NE persiste PAS d'expression arbitraire : un champ de data model expose un CHAMP existant (renommage
    // sémantique), pas un calcul (les calculs vivent dans les knowledge objects #46, réutilisables via l'alias).
    let expr = b.str_field("expr").trim().to_string();
    if !expr.is_empty() {
        if let Err(e) = validate_dm_ident(&expr) { return bad_req(format!("expr : {e}")); }
    }
    crate::req_conn!(st, au, conn);
    if conn.query_row("SELECT 1 FROM data_model_object WHERE id=?1", params![object_id], |_| Ok(())).is_err() {
        return not_found("objet introuvable");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO data_model_field(object_id,name,ftype,expr,created) VALUES(?1,?2,?3,?4,?5)",
            params![object_id, name, ftype, expr, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.datamodel.field.create",
            &format!("champ '{name}' ({ftype}) sur objet #{object_id} par {}", au.name), 2,
            &format!("champ de data model '{name}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"data_model_field", "id":id, "object_id":object_id, "name":name, "type":ftype, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    let id = conn.last_insert_rowid();
    dm_commit(&conn, outcome, json!({ "id": id }))
}

pub(crate) async fn field_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM data_model_field WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("champ introuvable"),
    };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM data_model_field WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.datamodel.field.delete",
            &format!("champ '{name}' (#{id}) supprimé par {}", au.name), 2,
            &format!("champ de data model '{name}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"data_model_field", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    dm_commit(&conn, outcome, json!({ "ok": true }))
}

// =================================================================================================
// RÉSOLUTION objet -> (chaîne de contraintes héritées, allowlist de champs source)
// =================================================================================================
/// Chaîne de contraintes de la RACINE vers l'objet (parent d'abord -> l'enfant hérite). Bornée (cap 16) contre
/// un cycle accidentel de `parent_id`. Chaque fragment a été compile-vérifié à la création.
fn object_constraint_chain(conn: &Connection, object_id: i64) -> Result<Vec<String>, String> {
    let mut chain_rev: Vec<String> = Vec::new();
    let mut cur = Some(object_id);
    let mut guard = 0;
    while let Some(oid) = cur {
        if guard > 16 { return Err("hiérarchie d'objets trop profonde (cycle ?)".into()); }
        guard += 1;
        let (constraint, parent): (String, Option<i64>) = conn
            .query_row("SELECT constraint_soql, parent_id FROM data_model_object WHERE id=?1 AND enabled=1", params![oid],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?)))
            .map_err(|_| "objet introuvable ou désactivé".to_string())?;
        chain_rev.push(constraint);
        cur = parent;
    }
    chain_rev.reverse(); // racine -> feuille
    Ok(chain_rev)
}

/// Allowlist des champs déclarés de l'objet : le NOM SOURCE (expr si fournie, sinon name). C'est ce que le
/// Pivot injecte réellement dans le GXQL (le `name` public peut renommer via `expr`). Un objet SANS champ
/// déclaré -> allowlist vide -> Pivot ne peut rien split-by/agréger (fail-closed, force la déclaration).
fn object_field_allow(conn: &Connection, object_id: i64) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    if let Ok(mut s) = conn.prepare("SELECT name, expr FROM data_model_field WHERE object_id=?1") {
        if let Ok(rows) = s.query_map(params![object_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
            for (name, expr) in rows.flatten() {
                let src = if expr.trim().is_empty() { name } else { expr };
                set.insert(src);
            }
        }
    }
    set
}

/// Parse une `PivotSpec` depuis le corps JSON (report-builder ; aucune saisie GXQL/SPL libre).
fn parse_pivot_spec(b: &Value) -> PivotSpec {
    let splitby: Vec<String> = b.get("splitby").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
    let stats: Vec<PivotStat> = b.get("stats").and_then(|v| v.as_array())
        .map(|a| a.iter().map(|x| PivotStat {
            func: x.get("func").and_then(|f| f.as_str()).unwrap_or("").to_string(),
            field: x.get("field").and_then(|f| f.as_str()).map(|s| s.to_string()),
        }).collect()).unwrap_or_default();
    let filters: Vec<PivotFilter> = b.get("filters").and_then(|v| v.as_array())
        .map(|a| a.iter().map(|x| PivotFilter {
            field: x.get("field").and_then(|f| f.as_str()).unwrap_or("").to_string(),
            op: x.get("op").and_then(|f| f.as_str()).unwrap_or("=").to_string(),
            value: x.get("value").and_then(|f| f.as_str()).unwrap_or("").to_string(),
        }).collect()).unwrap_or_default();
    let span = b.get("span").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let limit = b.get("limit").and_then(|v| v.as_i64());
    PivotSpec { splitby, stats, filters, span, limit }
}

/// Génère le GXQL d'un Pivot depuis le corps de requête (résout objet -> contraintes + allowlist).
fn pivot_soql_from_body(conn: &Connection, b: &Value) -> Result<String, String> {
    let object_id = b.get("object_id").and_then(|v| v.as_i64()).ok_or("object_id requis")?;
    let constraints = object_constraint_chain(conn, object_id)?;
    let allowed = object_field_allow(conn, object_id);
    let spec = parse_pivot_spec(b);
    pivot_to_soql(&constraints, &allowed, &spec)
}

// =================================================================================================
// PIVOT — compile (retourne le GXQL) et run (exécute via le chemin GXQL MASQUÉ, comme /api/query)
// =================================================================================================
/// POST /api/pivot/compile — retourne le GXQL généré (transparence report-builder ; pas d'exécution). viewer+.
pub(crate) async fn pivot_compile(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let __rc = req_db(&st, &au);
    let soql = {
        let conn = __rc.lock();
        match pivot_soql_from_body(&conn, &b) { Ok(s) => s, Err(e) => return bad_req(e) }
    };
    Json(json!({ "soql": soql })).into_response()
}

/// EXÉCUTION d'un GXQL généré via le MÊME chemin de LECTURE MASQUÉ que /api/query (choke-point unique de
/// redaction/RBAC). Masques EFFECTIFS du rôle -> un champ masqué reste masqué (projection) et un filtre sur
/// champ masqué échoue-fermé. run_query_ex applique l'authorizer read-pool (denylist de secrets) + budget +
/// plafond de lignes. AUCUNE surface SQL brute n'est ouverte.
async fn run_generated_soql(st: &AppState, au: &AuthUser, soql: &str, from: i64, to: i64, limit: i64) -> Response {
    let env = au.env_filter();
    let masks = effective_masks(req_db_path(st, au).as_str(), &au.role, &au.tenant, env);
    // Masque non vide -> rollup-route DÉSACTIVÉ (les tables event_rollup portent src_ip/host en clair) ; sinon
    // on peut router (identique à /api/query). Le Pivot ne produit que du stats/timechart/search -> compatible.
    let compiled = if masks.is_empty() {
        // COUVERTURE du rollup (cf. rollup_coverage) : ÉTABLIE depuis la base, jamais affirmée ici — elle borne
        // le corps du MERGE multi-dim au réellement-agrégé. Non établie -> aucun corps -> tout raw (exact).
        let rollup_cov = { let rc = req_db(st, au); let c = rc.lock(); RollupCoverage::of(&c) };
        match try_rollup_route(soql, from, to, env, rollup_cov) {
            Some(rr) => rr.sql,
            None => match soql_to_sql_masked_x(soql, from, to, env, &masks) { Ok(s) => s, Err(e) => return bad_req(e) },
        }
    } else {
        match soql_to_sql_masked_x(soql, from, to, env, &masks) { Ok(s) => s, Err(e) => return bad_req(e) }
    };
    if compiled.is_empty() { return bad_req("requête vide"); }
    let _permit = match st.query_sem.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => return Json(json!({ "columns": [], "rows": [] })).into_response(),
    };
    let db_path = req_db_path(st, au);
    let lim = limit.clamp(1, 10_000);
    let page_sql = format!("SELECT * FROM ({compiled}) LIMIT {lim}");
    let budget = query_budget_interactive_ms();
    let soql_echo = compiled.clone();
    let res = tokio::task::spawn_blocking(move || run_query_ex(&db_path, &page_sql, budget, None)).await;
    match res {
        Ok(Ok(mut v)) => {
            v["compiled_sql"] = json!(soql_echo);
            v["soql"] = json!(soql);
            Json(v).into_response()
        }
        Ok(Err(e)) => bad_req(e),
        Err(_) => server_err("exécution échouée"),
    }
}

/// POST /api/pivot/run — génère le GXQL du Pivot puis l'exécute (masqué). viewer+ (readonly_post).
pub(crate) async fn pivot_run(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let __rc = req_db(&st, &au);
    let soql = {
        let conn = __rc.lock();
        match pivot_soql_from_body(&conn, &b) { Ok(s) => s, Err(e) => return bad_req(e) }
    };
    let from = b.i64_field("from", 0);
    let to = b.i64_field("to", 0);
    let limit = b.get("limit").and_then(|v| v.as_i64()).unwrap_or(1000);
    run_generated_soql(&st, &au, &soql, from, to, limit).await
}

// =================================================================================================
// DATASETS — résultats sauvegardés réutilisables (pivot enregistré / search enregistré)
// =================================================================================================
pub(crate) async fn datasets_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    crate::req_conn!(st, au, conn);
    let items: Vec<Value> = conn
        .prepare("SELECT id,name,kind,soql,object_id,spec,enabled,managed,created,updated FROM dataset ORDER BY id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "name": r.get::<_,String>(1)?, "kind": r.get::<_,String>(2)?,
                    "soql": r.get::<_,String>(3)?, "object_id": r.get::<_,Option<i64>>(4)?, "spec": r.get::<_,String>(5)?,
                    "enabled": r.get::<_,i64>(6)? != 0, "managed": r.get::<_,i64>(7)?, "created": r.get::<_,i64>(8)?, "updated": r.get::<_,i64>(9)? }))
            })
            .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    Json(json!({ "datasets": items })).into_response()
}

/// POST /api/datasets — enregistre un dataset. editor+.
///  - kind='search' : `soql` figé (compile-vérifié via le chemin GXQL normal AVANT persistance) ;
///  - kind='pivot'  : `object_id` + `spec` (PivotSpec) -> on GÉNÈRE puis compile-vérifie le GXQL avant d'enregistrer.
/// Dans les deux cas on STOCKE le GXQL résolu (jamais du SQL) -> le run recompile par le chemin masqué normal.
pub(crate) async fn dataset_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let name = match validate_dm_ident(b.str_field("name")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let kind = b.str_field("kind").trim().to_string();
    crate::req_conn!(st, au, conn);
    // Résout le GXQL selon le type + compile-check (fail-closed).
    let (soql, object_id, spec): (String, Option<i64>, String) = match kind.as_str() {
        "search" => {
            let soql = b.str_field("soql").trim().to_string();
            if soql.is_empty() { return bad_req("dataset search : soql requis"); }
            if let Err(e) = guatx_core::soql::to_sql(&soql, 0, 0, &guatx_core::soql::Schema::events()) {
                return bad_req(format!("dataset search : GXQL invalide : {e}"));
            }
            (soql, None, String::new())
        }
        "pivot" => {
            let soql = match pivot_soql_from_body(&conn, &b) { Ok(s) => s, Err(e) => return bad_req(e) };
            let object_id = b.get("object_id").and_then(|v| v.as_i64());
            let spec = b.get("spec").cloned().or_else(|| Some(json!({
                "splitby": b.get("splitby"), "stats": b.get("stats"), "filters": b.get("filters"),
                "span": b.get("span"), "limit": b.get("limit"),
            }))).map(|v| v.to_string()).unwrap_or_default();
            (soql, object_id, spec)
        }
        _ => return bad_req("kind invalide (search|pivot)"),
    };
    let enabled = b.bool_field("enabled", true) as i64;
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO dataset(name,kind,soql,object_id,spec,enabled,created,updated) VALUES(?1,?2,?3,?4,?5,?6,?7,?7)",
            params![name, kind, soql, object_id, spec, enabled, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.dataset.create",
            &format!("dataset '{name}' ({kind}, #{id}) par {}", au.name), 2,
            &format!("dataset '{name}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"dataset", "id":id, "name":name, "dataset_kind":kind, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    let id = conn.last_insert_rowid();
    dm_commit(&conn, outcome, json!({ "id": id }))
}

pub(crate) async fn dataset_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM dataset WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("dataset introuvable"),
    };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM dataset WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.dataset.delete",
            &format!("dataset '{name}' (#{id}) supprimé par {}", au.name), 2,
            &format!("dataset '{name}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"dataset", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    dm_commit(&conn, outcome, json!({ "ok": true }))
}

/// POST /api/datasets/:id/run — exécute le GXQL stocké du dataset via le chemin MASQUÉ. viewer+ (readonly_post).
pub(crate) async fn dataset_run(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    let __rc = req_db(&st, &au);
    let soql = {
        let conn = __rc.lock();
        match conn.query_row("SELECT soql FROM dataset WHERE id=?1 AND enabled=1", params![id], |r| r.get::<_, String>(0)) {
            Ok(s) => s, Err(_) => return not_found("dataset introuvable ou désactivé"),
        }
    };
    let from = b.i64_field("from", 0);
    let to = b.i64_field("to", 0);
    let limit = b.get("limit").and_then(|v| v.as_i64()).unwrap_or(1000);
    run_generated_soql(&st, &au, &soql, from, to, limit).await
}
