//! #46 — CRUD des KNOWLEDGE OBJECTS (tables `knowledge_alias`/`knowledge_calc`/`knowledge_eventtype`/
//! `knowledge_tag`). CRUD = editor+ (route_min_role : `/api/knowledge` -> Write ; ils façonnent la recherche
//! de TOUT LE MONDE, comme les règles de détection). GET (liste) = viewer+ (transparence de la politique).
//! Chaque mutation VALIDE l'objet (idents allowlistés ; expr de calc compilée via `eval` ; filtre d'eventtype
//! compilé via SOQL) AVANT écriture (fail-closed : objet invalide REFUSÉ en 400, jamais persisté), écrit sous
//! transaction auditée, puis `knowledge_reload` recompile le `KnowledgeSet` de CE db_path -> auto-appliqué à
//! la compilation SOQL suivante (Explore, panels, règles, export en héritent).
use crate::*;


/// GET /api/knowledge — les 4 familles d'objets de savoir (viewer+). Rend la politique LISIBLE.
pub(crate) async fn knowledge_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    crate::req_conn!(st, au, conn);
    let aliases: Vec<Value> = conn
        .prepare("SELECT id,canonical,source,enabled,managed,created,updated FROM knowledge_alias ORDER BY id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "canonical": r.get::<_,String>(1)?, "source": r.get::<_,String>(2)?,
                    "enabled": r.get::<_,i64>(3)? != 0, "managed": r.get::<_,i64>(4)?, "created": r.get::<_,i64>(5)?, "updated": r.get::<_,i64>(6)? }))
            })
            .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    let calcs: Vec<Value> = conn
        .prepare("SELECT id,name,expr,enabled,ord,managed,created,updated FROM knowledge_calc ORDER BY ord, id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "name": r.get::<_,String>(1)?, "expr": r.get::<_,String>(2)?,
                    "enabled": r.get::<_,i64>(3)? != 0, "ord": r.get::<_,i64>(4)?, "managed": r.get::<_,i64>(5)?, "created": r.get::<_,i64>(6)?, "updated": r.get::<_,i64>(7)? }))
            })
            .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    let eventtypes: Vec<Value> = conn
        .prepare("SELECT id,name,filter,enabled,managed,created,updated FROM knowledge_eventtype ORDER BY id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "name": r.get::<_,String>(1)?, "filter": r.get::<_,String>(2)?,
                    "enabled": r.get::<_,i64>(3)? != 0, "managed": r.get::<_,i64>(4)?, "created": r.get::<_,i64>(5)?, "updated": r.get::<_,i64>(6)? }))
            })
            .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    let tags: Vec<Value> = conn
        .prepare("SELECT id,label,field,value,enabled,managed,created,updated FROM knowledge_tag ORDER BY label, id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "label": r.get::<_,String>(1)?, "field": r.get::<_,String>(2)?, "value": r.get::<_,String>(3)?,
                    "enabled": r.get::<_,i64>(4)? != 0, "managed": r.get::<_,i64>(5)?, "created": r.get::<_,i64>(6)?, "updated": r.get::<_,i64>(7)? }))
            })
            .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    // #60 — MACROS + AUTO-LOOKUPS (FAIL-SAFE : tables absentes sur base pré-v97 -> listes vides).
    let macros: Vec<Value> = conn
        .prepare("SELECT id,name,params,body,enabled,managed,created,updated FROM macro_def ORDER BY name")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "name": r.get::<_,String>(1)?, "params": r.get::<_,String>(2)?, "body": r.get::<_,String>(3)?,
                    "enabled": r.get::<_,i64>(4)? != 0, "managed": r.get::<_,i64>(5)?, "created": r.get::<_,i64>(6)?, "updated": r.get::<_,i64>(7)? }))
            })
            .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    let auto_lookups: Vec<Value> = conn
        .prepare("SELECT id,name,key_field,out_cols,kind,enabled,managed,created,updated FROM auto_lookup ORDER BY id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "name": r.get::<_,String>(1)?, "key_field": r.get::<_,String>(2)?, "out_cols": r.get::<_,String>(3)?,
                    "kind": r.get::<_,String>(4)?, "enabled": r.get::<_,i64>(5)? != 0, "managed": r.get::<_,i64>(6)?, "created": r.get::<_,i64>(7)?, "updated": r.get::<_,i64>(8)? }))
            })
            .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    Json(json!({ "aliases": aliases, "calcs": calcs, "eventtypes": eventtypes, "tags": tags,
        "macros": macros, "auto_lookups": auto_lookups })).into_response()
}

/// Émet la réponse d'un create/delete audité + `knowledge_reload`. Factorise le squelette transactionnel.
fn ko_commit(st: &AppState, au: &AuthUser, conn: &Connection, outcome: rusqlite::Result<i64>, ok_val: Value) -> Response {
    match outcome {
        Ok(_) => {
            let _ = conn.execute_batch("COMMIT");
            let dbp = req_db_path(st, au);
            knowledge_reload(conn, dbp.as_str());
            knowledge_activate(dbp.as_str()); // CRUD sur le tenant courant -> réactive la compilation
            Json(ok_val).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            if e.to_string().contains("UNIQUE") {
                return bad_req("un objet de savoir porte déjà ce nom");
            }
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 1) ALIAS de champ : canonical -> source
// ---------------------------------------------------------------------------------------------
pub(crate) async fn alias_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let canonical = match validate_ko_ident(b.str_field("canonical")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let source = match validate_ko_ident(b.str_field("source")) { Ok(f) => f, Err(e) => return bad_req(e) };
    if canonical == source { return bad_req("alias : canonical et source doivent différer"); }
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO knowledge_alias(canonical,source,enabled,created,updated) VALUES(?1,?2,?3,?4,?4)",
            params![canonical, source, enabled, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.knowledge.alias.create",
            &format!("alias '{canonical}' -> '{source}' (#{id}) par {}", au.name), 2,
            &format!("alias '{canonical}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"knowledge_alias", "id":id, "canonical":canonical, "source":source, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    let id = conn.last_insert_rowid();
    ko_commit(&st, &au, &conn, outcome, json!({ "id": id }))
}

pub(crate) async fn alias_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let canonical = match conn.query_row("SELECT canonical FROM knowledge_alias WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("alias introuvable"),
    };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM knowledge_alias WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.knowledge.alias.delete",
            &format!("alias '{canonical}' (#{id}) supprimé par {}", au.name), 2,
            &format!("alias '{canonical}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"knowledge_alias", "id":id, "canonical":canonical, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, json!({ "ok": true }))
}

// ---------------------------------------------------------------------------------------------
// 2) CHAMPS CALCULÉS : name = <expr eval>
// ---------------------------------------------------------------------------------------------
pub(crate) async fn calc_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let name = match validate_ko_ident(b.str_field("name")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let expr = b.str_field("expr").trim().to_string();
    if expr.is_empty() { return bad_req("calc : expression requise"); }
    // Compile-check via le chemin `eval` (injection-safe) AVANT persistance (fail-closed).
    if let Err(e) = validate_calc_expr(&name, &expr) { return bad_req(format!("expression de calc invalide : {e}")); }
    let ord = b.get("ord").and_then(|v| v.as_i64()).unwrap_or(0);
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO knowledge_calc(name,expr,enabled,ord,created,updated) VALUES(?1,?2,?3,?4,?5,?5)",
            params![name, expr, enabled, ord, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.knowledge.calc.create",
            &format!("champ calculé '{name}' (#{id}) par {}", au.name), 2,
            &format!("champ calculé '{name}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"knowledge_calc", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    let id = conn.last_insert_rowid();
    ko_commit(&st, &au, &conn, outcome, json!({ "id": id }))
}

pub(crate) async fn calc_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM knowledge_calc WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("champ calculé introuvable"),
    };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM knowledge_calc WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.knowledge.calc.delete",
            &format!("champ calculé '{name}' (#{id}) supprimé par {}", au.name), 2,
            &format!("champ calculé '{name}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"knowledge_calc", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, json!({ "ok": true }))
}

// ---------------------------------------------------------------------------------------------
// 3) EVENT TYPES : name + filtre SOQL
// ---------------------------------------------------------------------------------------------
pub(crate) async fn eventtype_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let name = match validate_ko_ident(b.str_field("name")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let filter = b.str_field("filter").trim().to_string();
    if filter.is_empty() { return bad_req("eventtype : filtre requis"); }
    // Compile-check du filtre via `eventtype=<name>` -> chemin SOQL normal (allowlist/échappement) AVANT persistance.
    if let Err(e) = validate_eventtype_filter(&name, &filter) { return bad_req(format!("filtre d'eventtype invalide : {e}")); }
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO knowledge_eventtype(name,filter,enabled,created,updated) VALUES(?1,?2,?3,?4,?4)",
            params![name, filter, enabled, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.knowledge.eventtype.create",
            &format!("eventtype '{name}' (#{id}) par {}", au.name), 2,
            &format!("eventtype '{name}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"knowledge_eventtype", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    let id = conn.last_insert_rowid();
    ko_commit(&st, &au, &conn, outcome, json!({ "id": id }))
}

pub(crate) async fn eventtype_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM knowledge_eventtype WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("eventtype introuvable"),
    };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM knowledge_eventtype WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.knowledge.eventtype.delete",
            &format!("eventtype '{name}' (#{id}) supprimé par {}", au.name), 2,
            &format!("eventtype '{name}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"knowledge_eventtype", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, json!({ "ok": true }))
}

// ---------------------------------------------------------------------------------------------
// 4) TAGS : label sur field=value
// ---------------------------------------------------------------------------------------------
pub(crate) async fn tag_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let label = match validate_ko_ident(b.str_field("label")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let field = match validate_ko_ident(b.str_field("field")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let value = b.str_field("value").to_string(); // valeur libre -> échappée à la compilation (soql_esc)
    if value.is_empty() { return bad_req("tag : valeur requise"); }
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO knowledge_tag(label,field,value,enabled,created,updated) VALUES(?1,?2,?3,?4,?5,?5)",
            params![label, field, value, enabled, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.knowledge.tag.create",
            &format!("tag '{label}' sur {field}={value} (#{id}) par {}", au.name), 2,
            &format!("tag '{label}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"knowledge_tag", "id":id, "label":label, "field":field, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    let id = conn.last_insert_rowid();
    ko_commit(&st, &au, &conn, outcome, json!({ "id": id }))
}

pub(crate) async fn tag_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let label = match conn.query_row("SELECT label FROM knowledge_tag WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("tag introuvable"),
    };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM knowledge_tag WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.knowledge.tag.delete",
            &format!("tag '{label}' (#{id}) supprimé par {}", au.name), 2,
            &format!("tag '{label}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"knowledge_tag", "id":id, "label":label, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, json!({ "ok": true }))
}

// ---------------------------------------------------------------------------------------------
// 5) MACROS (#60) : fragment SOQL nommé + paramétré, détendu À LA COMPILATION par le compilateur FERMÉ.
//    Corps + params compile-vérifiés (validate_macro : dry-expansion + compile-check) AVANT persistance.
// ---------------------------------------------------------------------------------------------
pub(crate) async fn macro_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let name = match validate_ko_ident(b.str_field("name")) { Ok(f) => f, Err(e) => return bad_req(e) };
    // params : liste (JSON array) OU chaîne "a,b" ; chaque param = ident SOQL sûr (validate_ko_ident).
    let params: Vec<String> = match b.get("params") {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
        _ => Vec::new(),
    };
    for p in &params {
        if let Err(e) = validate_ko_ident(p) { return bad_req(format!("paramètre de macro invalide : {e}")); }
    }
    let body = b.str_field("body").trim().to_string();
    // COMPILE-CHECK (fail-closed) : dry-expansion + compilation par le compilateur fermé.
    if let Err(e) = validate_macro(&name, &params, &body) { return bad_req(e); }
    let params_str = params.join(",");
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO macro_def(name,params,body,enabled,created,updated) VALUES(?1,?2,?3,?4,?5,?5)",
            params![name, params_str, body, enabled, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.knowledge.macro.create",
            &format!("macro '{name}'({params_str}) (#{id}) par {}", au.name), 2,
            &format!("macro '{name}' créée par {}", au.name),
            &json!({ "op":"create", "kind":"macro", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    let id = conn.last_insert_rowid();
    ko_commit(&st, &au, &conn, outcome, json!({ "id": id }))
}

pub(crate) async fn macro_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM macro_def WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("macro introuvable"),
    };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM macro_def WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.knowledge.macro.delete",
            &format!("macro '{name}' (#{id}) supprimée par {}", au.name), 2,
            &format!("macro '{name}' supprimée par {}", au.name),
            &json!({ "op":"delete", "kind":"macro", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, json!({ "ok": true }))
}

// ---------------------------------------------------------------------------------------------
// 6) AUTO-LOOKUPS (#60) : enrichissement auto-appliqué au-dessus de la base (mask-aware, réutilise
//    compile_lookup). GeoIP = un auto-lookup dont la table lookup_kv est peuplée depuis une base BYO.
// ---------------------------------------------------------------------------------------------
pub(crate) async fn auto_lookup_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let name = match validate_ko_ident(b.str_field("name")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let key_field = match validate_ko_ident(b.str_field("key_field")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let out_cols: Vec<String> = match b.get("out_cols") {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
        _ => Vec::new(),
    };
    for c in &out_cols {
        if let Err(e) = validate_ko_ident(c) { return bad_req(format!("colonne de sortie invalide : {e}")); }
    }
    // kind : label 'lookup' (défaut) ou 'geoip' (mécanique identique ; GeoIP = table BYO peuplée hors-ligne).
    let kind = match b.str_field("kind").trim() { "" | "lookup" => "lookup", "geoip" => "geoip", k => return bad_req(format!("kind invalide (lookup|geoip) : {k}")) }.to_string();
    if let Err(e) = validate_auto_lookup(&name, &key_field, &out_cols) { return bad_req(e); }
    let out_str = out_cols.join(",");
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO auto_lookup(name,key_field,out_cols,kind,enabled,created,updated) VALUES(?1,?2,?3,?4,?5,?6,?6)",
            params![name, key_field, out_str, kind, enabled, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.knowledge.autolookup.create",
            &format!("auto-lookup '{name}' sur {key_field} ({kind}, #{id}) par {}", au.name), 2,
            &format!("auto-lookup '{name}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"auto_lookup", "id":id, "name":name, "key_field":key_field, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    let id = conn.last_insert_rowid();
    ko_commit(&st, &au, &conn, outcome, json!({ "id": id }))
}

pub(crate) async fn auto_lookup_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM auto_lookup WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("auto-lookup introuvable"),
    };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM auto_lookup WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.knowledge.autolookup.delete",
            &format!("auto-lookup '{name}' (#{id}) supprimé par {}", au.name), 2,
            &format!("auto-lookup '{name}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"auto_lookup", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, json!({ "ok": true }))
}
