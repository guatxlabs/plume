//! #45 — CRUD des FIELD FILTERS (table `field_filter`). Règles ADMIN-ONLY (route_min_role :
//! `/api/field-filters` -> Admin, GET compris — la config CONTRAINT viewer/editor, elle est sensible).
//! Chaque mutation VALIDE la règle (nom de champ allowlisté, action/rôle connus) AVANT écriture (fail-closed :
//! règle invalide REFUSÉE en 400, jamais persistée), écrit sous transaction auditée, puis `field_filters_reload`
//! recompile le registre de CE db_path (+ set DENY de l'authorizer + sel). La LISTE renvoie les règles + une
//! MATRICE « quels champs sont masqués pour quel rôle » (transparence de la politique PII).
use crate::*;

/// Actions valides à la CRÉATION (rejet explicite d'une action inconnue -> 400 ; au reload, une action
/// corrompue tombe en DENY = fail-closed, mais on ne LAISSE PAS créer une action illisible).
const VALID_ACTIONS: &[&str] = &["mask", "partial", "hash", "redact", "deny"];
/// Rôles de scope valides ('' = seuil défaut viewer+editor ; sinon seuil = rank du rôle ; DENY = tous).
const VALID_ROLES: &[&str] = &["", "viewer", "editor", "admin"];

fn validate_role(r: &str) -> Result<(), Response> {
    if VALID_ROLES.contains(&r) {
        Ok(())
    } else {
        Err(bad_req("role invalide (''|viewer|editor|admin)"))
    }
}
fn validate_action(a: &str) -> Result<(), Response> {
    if VALID_ACTIONS.contains(&a) {
        Ok(())
    } else {
        Err(bad_req("action invalide (mask|partial|hash|redact|deny)"))
    }
}

/// GET /api/field-filters — règles ordonnées + matrice champ×rôle des masques effectifs (admin-only).
pub(crate) async fn field_filters_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if let Err(r) = require_admin(&au) {
        return r;
    }
    let db_path = req_db_path(&st, &au);
    crate::req_conn!(st, au, conn);
    let rules: Vec<Value> = match conn.prepare(
        "SELECT id,name,field,action,role,tenant,env,enabled,ord,created,updated FROM field_filter ORDER BY ord, id",
    ) {
        Ok(mut stmt) => stmt
            .query_map([], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "field": r.get::<_, String>(2)?,
                    "action": r.get::<_, String>(3)?, "role": r.get::<_, String>(4)?, "tenant": r.get::<_, String>(5)?,
                    "env": r.get::<_, String>(6)?, "enabled": r.get::<_, i64>(7)? != 0, "ord": r.get::<_, i64>(8)?,
                    "created": r.get::<_, i64>(9)?, "updated": r.get::<_, i64>(10)?
                }))
            })
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    // MATRICE : pour chaque rôle, le jeu EFFECTIF de champs masqués (champ -> action). Rend la politique
    // LISIBLE (« src_user est HASH pour viewer, en clair pour admin »). Tenant/env = ceux de l'admin courant.
    let mut matrix = serde_json::Map::new();
    for role in ["viewer", "editor", "admin"] {
        let eff = effective_masks(&db_path, role, &au.tenant, au.env_filter());
        let mut m = serde_json::Map::new();
        for rr in rules.iter() {
            if let Some(f) = rr.get("field").and_then(|x| x.as_str()) {
                let key = normalize_field(f);
                if let Some(a) = eff.get(&key) {
                    m.insert(key, json!(action_str(a)));
                }
            }
        }
        matrix.insert(role.to_string(), Value::Object(m));
    }
    Json(json!({ "rules": rules, "matrix": matrix, "actions": VALID_ACTIONS, "roles": VALID_ROLES })).into_response()
}

/// POST /api/field-filters — crée une règle (admin-only). Valide champ/action/rôle AVANT insert (fail-closed).
pub(crate) async fn field_filter_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_admin(&au) {
        return r;
    }
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Field filter").trim().to_string();
    if name.is_empty() {
        return bad_req("name requis");
    }
    let field = match validate_field(b.str_field("field")) {
        Ok(f) => f,
        Err(e) => return bad_req(e),
    };
    let action = b.get("action").and_then(|v| v.as_str()).unwrap_or("mask").trim().to_ascii_lowercase();
    if let Err(r) = validate_action(&action) {
        return r;
    }
    let role = b.str_field("role").trim().to_string();
    if let Err(r) = validate_role(&role) {
        return r;
    }
    let tenant = b.str_field("tenant").trim().to_string();
    let env = b.str_field("env").trim().to_string();
    let ord = b.get("ord").and_then(|v| v.as_i64()).unwrap_or(0);
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO field_filter(name,field,action,role,tenant,env,enabled,ord,created,updated) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)",
            params![name, field, action, role, tenant, env, enabled, ord, now()],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.field_filter.create",
            &format!("field-filter '{name}' (#{id}) champ={field} action={action} rôle='{role}' par {}", au.name), 2,
            &format!("field-filter '{name}' créé par {}", au.name),
            &json!({ "op": "create", "kind": "field_filter", "id": id, "field": field, "action": action, "role": role, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => {
            let _ = conn.execute_batch("COMMIT");
            field_filters_reload(&conn, req_db_path(&st, &au).as_str());
            Json(json!({ "id": id })).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            // UNIQUE(name) violé -> message clair.
            if e.to_string().contains("UNIQUE") {
                return bad_req("un field-filter porte déjà ce nom");
            }
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

/// POST /api/field-filters/:id — met à jour une règle (admin-only). Re-valide la règle FUSIONNÉE.
pub(crate) async fn field_filter_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_admin(&au) {
        return r;
    }
    crate::req_conn!(st, au, conn);
    let cur = conn.query_row(
        "SELECT field,action,role FROM field_filter WHERE id=?1",
        params![id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
    );
    let (field0, act0, role0) = match cur {
        Ok(t) => t,
        Err(_) => return not_found("field-filter introuvable"),
    };
    // Valeurs FUSIONNÉES (un update partiel ne doit pas produire un état invalide).
    let field = match b.get("field").and_then(|v| v.as_str()) {
        Some(f) => match validate_field(f) {
            Ok(f) => f,
            Err(e) => return bad_req(e),
        },
        None => field0,
    };
    let action = b.get("action").and_then(|v| v.as_str()).unwrap_or(&act0).trim().to_ascii_lowercase();
    if let Err(r) = validate_action(&action) {
        return r;
    }
    let role = b.get("role").and_then(|v| v.as_str()).unwrap_or(&role0).trim().to_string();
    if let Err(r) = validate_role(&role) {
        return r;
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(v) = b.get("name").and_then(|x| x.as_str()) { conn.execute("UPDATE field_filter SET name=?1 WHERE id=?2", params![v.trim(), id])?; }
        if let Some(v) = b.get("tenant").and_then(|x| x.as_str()) { conn.execute("UPDATE field_filter SET tenant=?1 WHERE id=?2", params![v.trim(), id])?; }
        if let Some(v) = b.get("env").and_then(|x| x.as_str()) { conn.execute("UPDATE field_filter SET env=?1 WHERE id=?2", params![v.trim(), id])?; }
        if let Some(v) = b.get("ord").and_then(|x| x.as_i64()) { conn.execute("UPDATE field_filter SET ord=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) { conn.execute("UPDATE field_filter SET enabled=?1 WHERE id=?2", params![v as i64, id])?; }
        conn.execute("UPDATE field_filter SET field=?1,action=?2,role=?3,updated=?4 WHERE id=?5", params![field, action, role, now(), id])?;
        audit_config_change(
            &conn, "config.field_filter.update",
            &format!("field-filter #{id} modifié par {}", au.name), 2,
            &format!("field-filter #{id} modifié par {}", au.name),
            &json!({ "op": "update", "kind": "field_filter", "id": id, "field": field, "action": action, "role": role, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            field_filters_reload(&conn, req_db_path(&st, &au).as_str());
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            if e.to_string().contains("UNIQUE") {
                return bad_req("un field-filter porte déjà ce nom");
            }
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

/// DELETE /api/field-filters/:id — supprime une règle (admin-only).
pub(crate) async fn field_filter_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_admin(&au) {
        return r;
    }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM field_filter WHERE id=?1", params![id], |r| r.get::<_, String>(0)) {
        Ok(n) => n,
        Err(_) => return not_found("field-filter introuvable"),
    };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM field_filter WHERE id=?1", params![id])?;
        audit_config_change(
            &conn, "config.field_filter.delete",
            &format!("field-filter '{name}' (#{id}) supprimé par {}", au.name), 2,
            &format!("field-filter '{name}' supprimé par {}", au.name),
            &json!({ "op": "delete", "kind": "field_filter", "id": id, "name": name, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            field_filters_reload(&conn, req_db_path(&st, &au).as_str());
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}
