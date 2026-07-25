//! Comptes utilisateurs (réservé admin) et tables de correspondance (lookups) : CRUD utilisateurs
//! (`users_list`/`user_create`/`user_delete`/`user_update`) et lookups (`value_to_lookup_str`/
//! `build_lookup_kv`, `lookups_list`/`lookup_upload`/`lookup_delete`).
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// ---------- comptes utilisateurs (réservé admin via auth_guard) ----------
pub(crate) async fn users_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    let mut stmt = conn.prepare("SELECT id,name,role,created FROM user ORDER BY id").unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?,
                "role": r.get::<_, String>(2)?, "created": r.get::<_, i64>(3)?
            }))
        })
        .unwrap();
    Json(json!({ "users": rows.flatten().collect::<Vec<_>>(), "me": au.name }))
}

pub(crate) async fn user_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.trimmed("name");
    let pw = b.str_field("password");
    let role = match b.get("role").and_then(|v| v.as_str()) {
        Some("admin") => "admin",
        Some("viewer") => "viewer",
        _ => "editor",
    };
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return (StatusCode::BAD_REQUEST, "nom invalide (alphanumérique, . _ - uniquement)").into_response();
    }
    // MODE ENGAGEMENT : le préfixe `eng-cred-` est RÉSERVÉ aux credentials mintés par le provisioning
    // d'engagement (compte scopé + hard-expiry). L'interdire à la création interactive garantit qu'aucun
    // compte durable ne peut usurper ce discriminant du chemin d'auth (hard-expiry + no-cache).
    if name.starts_with(ENG_CRED_PREFIX) {
        return (StatusCode::BAD_REQUEST, "préfixe 'eng-cred-' réservé aux credentials d'engagement").into_response();
    }
    // POLITIQUE MDP ≥ 12 (item 3) — à la CRÉATION du compte uniquement (les comptes existants intacts).
    if pw.chars().count() < 12 {
        return (StatusCode::BAD_REQUEST, "mot de passe trop court (≥ 12 caractères)").into_response();
    }
    let hash = hash_pw(pw);
    crate::req_conn!(st, au, conn);
    // AUDIT D'IDENTITÉ : création de compte = mutation d'IDENTITÉ -> AUDIT fail-closed DANS la transaction (patron
    // audit_config_change des lookups/notifiers). Sans trace, un admin compromis plante une persistance
    // (nouvel admin) invisible. Le hash n'est JAMAIS mis dans l'audit — seuls actor/target/rôle. Créer un
    // ADMIN = sévérité 4 (HIGH, alertable) ; editor/viewer = 3.
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let sev = if role == "admin" { 4 } else { 3 };
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![name, hash, role])?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.user.create",
            &format!("compte '{name}' (rôle {role}) créé par {}", au.name), sev,
            &format!("compte utilisateur '{name}' créé (rôle {role}) par {}", au.name),
            &json!({ "action": "config.user.create", "kind": "user", "target": name, "role": role, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "id": id })).into_response() }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : rien de persisté sans audit
            // distinguer un conflit de nom (UNIQUE) d'un vrai échec d'audit — même sémantique 409 qu'avant.
            let es = e.to_string();
            if es.contains("UNIQUE") || es.contains("constraint") {
                (StatusCode::CONFLICT, "ce nom de compte existe déjà").into_response()
            } else {
                server_err(format!("échec transaction audit (aucune modification): {e}"))
            }
        }
    }
}

pub(crate) async fn user_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    let target: Option<(String, String)> = conn
        .query_row("SELECT name,role FROM user WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
        .ok();
    let Some((tname, trole)) = target else {
        return (StatusCode::NOT_FOUND, "compte introuvable").into_response();
    };
    if tname == au.name {
        return (StatusCode::BAD_REQUEST, "impossible de supprimer son propre compte").into_response();
    }
    if trole == "admin" {
        let admins: i64 = conn.query_row("SELECT COUNT(*) FROM user WHERE role='admin'", [], |r| r.get(0)).unwrap_or(0);
        if admins <= 1 {
            return (StatusCode::BAD_REQUEST, "dernier administrateur — suppression refusée").into_response();
        }
    }
    // AUDIT D'IDENTITÉ : suppression de compte = mutation d'identité -> AUDIT fail-closed transactionnel. Supprimer un
    // ADMIN = sévérité 4. Rien n'est purgé sans trace (source=plume-config, non-purgeable).
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let sev = if trole == "admin" { 4 } else { 3 };
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM user WHERE id=?1", params![id])?;
        audit_config_change(
            &conn, "config.user.delete",
            &format!("compte '{tname}' (rôle {trole}) supprimé par {}", au.name), sev,
            &format!("compte utilisateur '{tname}' supprimé (rôle {trole}) par {}", au.name),
            &json!({ "action": "config.user.delete", "kind": "user", "target": tname, "role": trole, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            st.auth_cache.lock().clear(); // invalide les creds en cache du compte supprimé
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

// MAJ d'un compte (admin only via auth_guard) : rôle et/ou reset du mot de passe.
pub(crate) async fn user_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    let new_pw = b.get("password").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty());
    let new_role = b.get("role").and_then(|v| v.as_str());
    crate::req_conn!(st, au, conn);
    let target: Option<(String, String)> = conn
        .query_row("SELECT name,role FROM user WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
        .ok();
    let Some((tname, trole)) = target else { return (StatusCode::NOT_FOUND, "compte introuvable").into_response(); };
    // VALIDATION AVANT toute écriture (rôle valide, anti-lockout, longueur mdp) — inchangé, mais hors transaction.
    let role_change: Option<&str> = if let Some(nr) = new_role {
        let role = match nr { "admin" => "admin", "editor" => "editor", "viewer" => "viewer", _ => return (StatusCode::BAD_REQUEST, "rôle invalide (admin|editor|viewer)").into_response() };
        // anti-lockout : ne pas rétrograder le DERNIER admin
        if trole == "admin" && role != "admin" {
            let admins: i64 = conn.query_row("SELECT COUNT(*) FROM user WHERE role='admin'", [], |r| r.get(0)).unwrap_or(0);
            if admins <= 1 { return (StatusCode::BAD_REQUEST, "dernier administrateur — rétrogradation refusée").into_response(); }
        }
        Some(role)
    } else { None };
    if let Some(pw) = new_pw {
        if pw.chars().count() < 12 { return (StatusCode::BAD_REQUEST, "mot de passe trop court (≥ 12 caractères)").into_response(); } // POLITIQUE MDP ≥ 12 (item 3) — reset admin uniquement
    }
    // AUDIT D'IDENTITÉ : changement de rôle ET/OU reset mdp = mutations d'identité -> AUDIT fail-closed transactionnel
    // (un audit PAR type de changement : role_change / password_reset). Un reset mdp ou une escalade vers admin
    // = sévérité 4 (HIGH, alertable). Le nouveau hash n'est JAMAIS mis dans l'audit.
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(role) = role_change {
            conn.execute("UPDATE user SET role=?1 WHERE id=?2", params![role, id])?;
            let sev = if role == "admin" || trole == "admin" { 4 } else { 3 };
            audit_config_change(
                &conn, "config.user.role_change",
                &format!("compte '{tname}' : rôle {trole} -> {role} par {}", au.name), sev,
                &format!("rôle du compte '{tname}' modifié ({trole} -> {role}) par {}", au.name),
                &json!({ "action": "config.user.role_change", "kind": "user", "target": tname, "from": trole, "to": role, "actor": au.name }).to_string(),
            )?;
        }
        if let Some(pw) = new_pw {
            conn.execute("UPDATE user SET hash=?1 WHERE id=?2", params![hash_pw(pw), id])?;
            audit_config_change(
                &conn, "config.user.password_reset",
                &format!("mot de passe du compte '{tname}' réinitialisé par {}", au.name), 4,
                &format!("mot de passe du compte '{tname}' (rôle {trole}) réinitialisé par {}", au.name),
                &json!({ "action": "config.user.password_reset", "kind": "user", "target": tname, "actor": au.name }).to_string(),
            )?;
        }
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            st.auth_cache.lock().clear(); // invalide le cache d'auth (rôle/mdp changés)
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

// ---------- LOOKUP : tables d'enrichissement (admin only via auth_guard) ----------
// NOYAU FONCTIONNEL : table + endpoint admin minimal + op SOQL `lookup`. L'UI de GESTION (formulaire
// d'upload CSV/JSON, édition, aperçu) est un SUIVI ULTÉRIEUR — ici seul l'endpoint REST est exposé.

/// Convertit une valeur JSON scalaire en chaîne exploitable comme clé/valeur de lookup. String -> telle
/// quelle ; nombre/bool -> représentation textuelle ; null/objet/array -> None (clé inexploitable).
pub(crate) fn value_to_lookup_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Transforme les lignes d'upload `[{...}]` en paires (key, val_json) + l'ensemble ordonné des colonnes
/// de sortie. PURE (testable sans DB). Pour chaque ligne : la valeur de `key_field` devient la CLÉ ;
/// les AUTRES paires (clé passant `soql_ident_ok`, donc requêtable via json_extract) sont sérialisées
/// dans `val`. Lignes sans clé exploitable -> ignorées. `val` est TOUJOURS du JSON valide par
/// construction (un `val` malformé ne peut donc pas naître de l'API ; le compilo garde de toute façon
/// `json_valid` en lecture).
pub(crate) fn build_lookup_kv(key_field: &str, rows: &[Value]) -> (Vec<(String, String)>, Vec<String>) {
    let mut out_cols: Vec<String> = Vec::new();
    let mut kv: Vec<(String, String)> = Vec::new();
    for row in rows {
        let Some(obj) = row.as_object() else { continue };
        let key = match obj.get(key_field).and_then(value_to_lookup_str) {
            Some(k) if !k.is_empty() => k,
            _ => continue,
        };
        let mut val = serde_json::Map::new();
        for (k, v) in obj {
            if k == key_field || !soql_ident_ok(k) {
                continue;
            }
            if !out_cols.iter().any(|c| c == k) {
                out_cols.push(k.clone());
            }
            val.insert(k.clone(), v.clone());
        }
        kv.push((key, Value::Object(val).to_string()));
    }
    (kv, out_cols)
}

/// GET /api/lookups -> liste des lookups déclarés (depuis lookup_meta) + nombre de lignes par lookup.
pub(crate) async fn lookups_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    let mut stmt = conn
        .prepare(
            "SELECT m.name, m.key_field, m.cols, m.updated, \
             (SELECT COUNT(*) FROM lookup_kv k WHERE k.name=m.name) \
             FROM lookup_meta m ORDER BY m.name",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(json!({
                "name": r.get::<_, String>(0)?,
                "key_field": r.get::<_, Option<String>>(1)?,
                "cols": r.get::<_, Option<String>>(2)?,
                "updated": r.get::<_, Option<i64>>(3)?,
                "rows": r.get::<_, i64>(4)?,
                // D12 — origine du contenu (badge managed, cohérent avec rule/parser/playbook). Les lookups
                // n'ont ni seed builtin ni overlay config.d : tout lookup est créé via l'UI/API => 2 (perso).
                "managed": 2,
            }))
        })
        .unwrap();
    Json(json!({ "lookups": rows.flatten().collect::<Vec<_>>() }))
}

/// POST /api/lookups {name, key_field, rows:[{...}]} -> REMPLACE intégralement le contenu du lookup
/// `name` (UPSERT, val = JSON des colonnes hors `key_field`). Valide name/key_field via soql_ident_ok.
pub(crate) async fn lookup_upload(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.trimmed("name");
    let key_field = b.trimmed("key_field");
    // #1c garde-fou #1 (lookup) : nom + champ-clé au format identifiant SOQL (soql_ident_ok), rows = tableau.
    if !soql_ident_ok(&name) {
        return bad_req("nom de lookup invalide (alphanumérique + _)");
    }
    if !soql_ident_ok(&key_field) {
        return bad_req("champ-clé invalide (alphanumérique + _)");
    }
    let Some(rows) = b.get("rows").and_then(|v| v.as_array()) else {
        return bad_req("champ 'rows' (tableau d'objets) requis");
    };
    let (kv, out_cols) = build_lookup_kv(&key_field, rows);
    crate::req_conn!(st, au, conn);
    // #1c garde-fou #6 : remplacement ATOMIQUE fail-closed + audit #1b (ledger + event plume-config). Si un
    // write ou l'audit échoue -> ROLLBACK (aucun remplacement partiel, aucune mutation sans trace).
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM lookup_kv WHERE name=?1", params![name])?;
        {
            let mut ins = conn.prepare("INSERT OR REPLACE INTO lookup_kv(name,\"key\",val) VALUES(?1,?2,?3)")?;
            for (k, v) in &kv {
                ins.execute(params![name, k, v])?;
            }
        }
        conn.execute(
            "INSERT OR REPLACE INTO lookup_meta(name,key_field,cols,updated) VALUES(?1,?2,?3,?4)",
            params![name, key_field, out_cols.join(","), now()],
        )?;
        audit_config_change(
            &conn, "config.lookup.upload",
            &format!("lookup '{name}' ({} lignes) chargé par {}", kv.len(), au.name), 2,
            &format!("table d'enrichissement '{name}' remplacée ({} lignes) par {}", kv.len(), au.name),
            &json!({ "op": "upload", "kind": "lookup", "name": name, "rows": kv.len(), "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "name": name, "rows": kv.len(), "cols": out_cols })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

/// DELETE /api/lookups/:name -> supprime le lookup (lignes kv + métadonnées). #1c : audit fail-closed.
pub(crate) async fn lookup_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(name): Path<String>) -> Response {
    if !soql_ident_ok(&name) {
        return bad_req("nom de lookup invalide");
    }
    crate::req_conn!(st, au, conn);
    // existe ? (pour renvoyer 404 sans ouvrir de transaction inutile)
    if conn.query_row("SELECT 1 FROM lookup_meta WHERE name=?1", params![name], |_| Ok(())).is_err() {
        return not_found("lookup introuvable");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM lookup_kv WHERE name=?1", params![name])?;
        conn.execute("DELETE FROM lookup_meta WHERE name=?1", params![name])?;
        audit_config_change(
            &conn, "config.lookup.delete",
            &format!("lookup '{name}' supprimé par {}", au.name), 3,
            &format!("table d'enrichissement '{name}' supprimée par {}", au.name),
            &json!({ "op": "delete", "kind": "lookup", "name": name, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "ok": true, "deleted": true })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}
