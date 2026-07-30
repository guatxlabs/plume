//! Handlers HTTP de la couche IA CONSEIL (#16, Phase 1 : NL→GXQL). Feature `ai` OFF par défaut ->
//! CHAQUE endpoint appelle `require_feature()` en tête ; sans la feature -> 501 (miroir strict du stub
//! LDAP/SAML « non compilé »). Runtime-inert de plus : sans `PLUME_AI_ENABLE` + provider `enabled=1`,
//! aucun endpoint n'agit (mode 0 byte-identique).
//!
//! CRUD des providers + presets + politique de redaction = ADMIN-ONLY (route_min_role Admin + re-check
//! in-handler + secret redigé). NL→GXQL + status = analyste (viewer+). Mode 0 UNIQUEMENT (comme l'IdP :
//! pas de chemin IA cross-tenant à moitié câblé -> 501 en multi-tenant).
//!
//! INVARIANT CARDINAL : NL→GXQL passe le TEXTE du LLM au compilo FERMÉ `soql_to_sql_x` (le MÊME que
//! /api/query) et renvoie GXQL+SQL validés (ou l'erreur) à l'analyste. ZÉRO exécution : ce handler
//! n'appelle jamais /api/query, ne touche jamais la base avec le texte généré.
use crate::*;

/// Nom de provider valide : alphanumérique + `. _ -`, non vide, <= 64 (miroir idp_name_ok).
fn ai_name_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn ai_api_shape_ok(s: &str) -> bool {
    matches!(s, "openai" | "ollama-native" | "anthropic")
}

/// Refus mode-1 homogène (IA = mono-tenant en Phase 1, comme IdP).
fn ai_deny_multitenant() -> Response {
    err_json(StatusCode::NOT_IMPLEMENTED, "IA via l'UI réservée au mode mono-tenant (control-plane : roadmap #2)")
}

/// Traduit une erreur worker en réponse : « non compilé » -> 501 (stub feature-off), sinon 500.
pub(crate) fn ai_worker_err(e: String) -> Response {
    if e.contains("non compilé") {
        err_json(StatusCode::NOT_IMPLEMENTED, e)
    } else {
        server_err(e)
    }
}

/// Construit le DÉTAIL de l'entrée de ledger `ai.call`. NE CONTIENT QUE : purpose, provider, formes,
/// compteurs de tokens, version de politique de redaction, HASH du prompt rédigé, verdicts. JAMAIS la
/// matière du prompt, JAMAIS la clé, JAMAIS le GXQL/SQL généré. Fonction pure -> testable (invariant no-leak).
#[allow(clippy::too_many_arguments)]
pub(crate) fn ai_call_ledger_detail(
    provider_id: i64, api_shape: &str, cloud: bool, prompt_tokens: u32, completion_tokens: u32,
    redaction_policy_version: i64, prompt_sha256: &str, valid: bool, retried: bool, actor: &str,
) -> String {
    json!({
        "purpose": guatx_core::ai::AiPurpose::NlToSoql.as_str(),
        "provider_id": provider_id,
        "api_shape": api_shape,
        "cloud": cloud,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "redaction_policy_version": redaction_policy_version,
        "prompt_sha256": prompt_sha256,
        "valid": valid,
        "retried": retried,
        "actor": actor,
    })
    .to_string()
}

macro_rules! ai_gate {
    ($au:expr) => {
        if let Err(e) = crate::ai::require_feature() {
            return err_json(StatusCode::NOT_IMPLEMENTED, e);
        }
    };
}

// ============================ POLITIQUE DE REDACTION (meta-backed, versionnée) ============================

/// Politique de redaction ACTIVE : lue depuis `meta['ai_redaction_policy']`, sinon défaut v1 (core).
/// Conservatrice : la version est estampillée dans chaque entrée de ledger `ai.call`.
fn active_redaction_policy(conn: &rusqlite::Connection) -> guatx_core::ai::RedactionPolicy {
    let mut p = guatx_core::ai::default_redaction_policy();
    if let Ok(raw) = conn.query_row("SELECT value FROM meta WHERE key='ai_redaction_policy'", [], |r| r.get::<_, String>(0)) {
        if let Ok(v) = serde_json::from_str::<Value>(&raw) {
            if let Some(ver) = v.get("version").and_then(|x| x.as_i64()) {
                p.version = ver;
            }
            if let Some(extra) = v.get("deny_substr").and_then(|x| x.as_array()) {
                p.deny_substr = extra.iter().filter_map(|x| x.as_str()).map(|s| s.to_ascii_lowercase()).collect();
            }
            if let Some(allow) = v.get("pii_allow").and_then(|x| x.as_array()) {
                p.pii_allow = allow.iter().filter_map(|x| x.as_str()).map(|s| s.to_string()).collect();
            }
        }
    }
    p
}

pub(crate) async fn ai_redaction_policy_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    ai_gate!(au);
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    let conn = st.db.lock();
    let p = active_redaction_policy(&conn);
    Json(json!({ "version": p.version, "deny_substr": p.deny_substr, "pii_allow": p.pii_allow })).into_response()
}

pub(crate) async fn ai_redaction_policy_put(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    ai_gate!(au);
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return ai_deny_multitenant();
    }
    // version obligatoire (versionnage explicite, estampillé au ledger). deny_substr/pii_allow optionnels.
    let version = match b.get("version").and_then(|x| x.as_i64()) {
        Some(v) if v > 0 => v,
        _ => return bad_req("version (entier > 0) requise"),
    };
    let deny = b.get("deny_substr").cloned().unwrap_or_else(|| {
        Value::Array(guatx_core::ai::default_redaction_policy().deny_substr.into_iter().map(Value::String).collect())
    });
    let allow = b.get("pii_allow").cloned().unwrap_or_else(|| json!([]));
    let stored = json!({ "version": version, "deny_substr": deny, "pii_allow": allow }).to_string();
    let conn = st.db.lock();
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("INSERT INTO meta(key,value) VALUES('ai_redaction_policy',?1) ON CONFLICT(key) DO UPDATE SET value=?1", params![stored])?;
        audit_config_change(
            &conn, "config.ai.redaction_policy",
            &format!("politique de redaction IA -> v{version} par {}", au.name), 3,
            &format!("politique de redaction IA mise à jour (v{version}) par {}", au.name),
            &json!({ "version": version, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "ok": true, "version": version })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit: {e}")) }
    }
}

// ================================ CRUD PROVIDERS (admin-only, mode 0) ================================

pub(crate) async fn ai_providers_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    ai_gate!(au);
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return ai_deny_multitenant();
    }
    let conn = st.db.lock();
    // Le secret n'est JAMAIS projeté : seul le booléen (secret != '') sort (miroir idp).
    let list: Vec<Value> = match conn.prepare(
        "SELECT id,name,vendor,api_shape,endpoint,enabled,config_json,created,updated,(secret != '') FROM ai_provider ORDER BY id",
    ) {
        Ok(mut stmt) => stmt
            .query_map([], |r| {
                let cfg_json: String = r.get(6)?;
                let endpoint: String = r.get(4)?;
                let cfg: Value = serde_json::from_str(&cfg_json).unwrap_or_else(|_| json!({}));
                let requires_cloud = cfg.get("requires_cloud").and_then(|x| x.as_bool()).unwrap_or(false);
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "name": r.get::<_, String>(1)?,
                    "vendor": r.get::<_, String>(2)?,
                    "api_shape": r.get::<_, String>(3)?,
                    "endpoint": endpoint,
                    "enabled": r.get::<_, i64>(5)? != 0,
                    "config": cfg,
                    "cloud": crate::ai::provider_is_cloud(&r.get::<_, String>(4)?, requires_cloud),
                    "created": r.get::<_, i64>(7)?,
                    "updated": r.get::<_, i64>(8)?,
                    "has_secret": r.get::<_, i64>(9)? != 0,
                }))
            })
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    Json(Value::Array(list)).into_response()
}

pub(crate) async fn ai_provider_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    ai_gate!(au);
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return ai_deny_multitenant();
    }
    let name = b.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    if !ai_name_ok(&name) {
        return bad_req("nom de provider invalide (alphanumérique, . _ - ; <= 64)");
    }
    let api_shape = b.get("api_shape").and_then(|x| x.as_str()).unwrap_or("openai").to_string();
    if !ai_api_shape_ok(&api_shape) {
        return bad_req("api_shape non supporté (openai | ollama-native | anthropic)");
    }
    let endpoint = b.get("endpoint").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        return bad_req("endpoint doit être une URL absolue http(s)");
    }
    let vendor = b.get("vendor").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let config = b.get("config").cloned().unwrap_or_else(|| json!({}));
    let requires_cloud = config.get("requires_cloud").and_then(|x| x.as_bool()).unwrap_or(false);
    // GARDE CLOUD À LA CRÉATION (defense in depth : re-vérifiée à l'appel).
    if let Err(e) = crate::ai::cloud_gate(&endpoint, requires_cloud) {
        return err_json(StatusCode::FORBIDDEN, e);
    }
    let enabled = b.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false) as i64;
    let secret = b.get("secret").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let conn = st.db.lock();
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO ai_provider(name,vendor,api_shape,endpoint,secret,enabled,config_json,created,updated) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8)",
            params![name, vendor, api_shape, endpoint, secret, enabled, config.to_string(), now()],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.ai.provider.create",
            &format!("provider IA '{name}' ({api_shape}) créé par {}", au.name), 3,
            &format!("provider IA '{name}' ({api_shape}, endpoint={endpoint}, enabled={}) créé par {}", enabled != 0, au.name),
            &json!({ "id": id, "api_shape": api_shape, "enabled": enabled != 0, "cloud": crate::ai::provider_is_cloud(&endpoint, requires_cloud), "has_secret": !secret.is_empty(), "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "id": id, "enabled": enabled != 0 })).into_response() }
        Err(_) => { let _ = conn.execute_batch("ROLLBACK"); (StatusCode::CONFLICT, "échec de création (nom déjà pris ou audit) — réessayez").into_response() }
    }
}

pub(crate) async fn ai_provider_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    ai_gate!(au);
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return ai_deny_multitenant();
    }
    let conn = st.db.lock();
    let row: Option<(String, i64)> = conn
        .query_row("SELECT endpoint, (config_json LIKE '%\"requires_cloud\":true%') FROM ai_provider WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
        .ok();
    let Some((cur_endpoint, cur_req_cloud)) = row else { return not_found("provider introuvable") };
    // Si on (ré)active OU on change l'endpoint, re-vérifier la garde cloud sur l'endpoint EFFECTIF.
    let new_endpoint = b.get("endpoint").and_then(|x| x.as_str()).map(|s| s.trim().to_string());
    let eff_endpoint = new_endpoint.clone().unwrap_or(cur_endpoint);
    if let Some(ep) = &new_endpoint {
        if !ep.starts_with("http://") && !ep.starts_with("https://") {
            return bad_req("endpoint doit être une URL absolue http(s)");
        }
    }
    let will_enable = b.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false);
    let req_cloud = b.get("config").and_then(|c| c.get("requires_cloud")).and_then(|x| x.as_bool()).unwrap_or(cur_req_cloud != 0);
    if will_enable || new_endpoint.is_some() {
        if let Err(e) = crate::ai::cloud_gate(&eff_endpoint, req_cloud) {
            return err_json(StatusCode::FORBIDDEN, e);
        }
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) {
            conn.execute("UPDATE ai_provider SET enabled=?1 WHERE id=?2", params![v as i64, id])?;
        }
        if let Some(ep) = &new_endpoint {
            conn.execute("UPDATE ai_provider SET endpoint=?1 WHERE id=?2", params![ep, id])?;
        }
        if let Some(v) = b.get("config") {
            conn.execute("UPDATE ai_provider SET config_json=?1 WHERE id=?2", params![v.to_string(), id])?;
        }
        if let Some(v) = b.get("vendor").and_then(|x| x.as_str()) {
            conn.execute("UPDATE ai_provider SET vendor=?1 WHERE id=?2", params![v, id])?;
        }
        if let Some(v) = b.get("api_shape").and_then(|x| x.as_str()) {
            if !ai_api_shape_ok(v) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            conn.execute("UPDATE ai_provider SET api_shape=?1 WHERE id=?2", params![v, id])?;
        }
        // SECRET : mis à jour UNIQUEMENT si fourni ET non vide (jamais d'écrasement par vide, jamais renvoyé).
        let mut secret_rotated = false;
        if let Some(s) = b.get("secret").and_then(|x| x.as_str()) {
            if !s.is_empty() {
                conn.execute("UPDATE ai_provider SET secret=?1 WHERE id=?2", params![s, id])?;
                secret_rotated = true;
            }
        }
        conn.execute("UPDATE ai_provider SET updated=?1 WHERE id=?2", params![now(), id])?;
        audit_config_change(
            &conn, "config.ai.provider.update",
            &format!("provider IA #{id} modifié par {}", au.name), 3,
            &format!("provider IA #{id} modifié (secret_rotated={secret_rotated}) par {}", au.name),
            &json!({ "id": id, "secret_rotated": secret_rotated, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "ok": true })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction (aucune modification): {e}")) }
    }
}

pub(crate) async fn ai_provider_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    ai_gate!(au);
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return ai_deny_multitenant();
    }
    let conn = st.db.lock();
    let name: Option<String> = conn.query_row("SELECT name FROM ai_provider WHERE id=?1", params![id], |r| r.get(0)).ok();
    let Some(name) = name else { return not_found("provider introuvable") };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM ai_provider WHERE id=?1", params![id])?;
        audit_config_change(
            &conn, "config.ai.provider.delete",
            &format!("provider IA '{name}' (#{id}) supprimé par {}", au.name), 3,
            &format!("provider IA '{name}' supprimé par {}", au.name),
            &json!({ "id": id, "name": name, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); StatusCode::NO_CONTENT.into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit: {e}")) }
    }
}

// ================================ PRESETS (admin-only) ================================

pub(crate) async fn ai_presets_list(Extension(au): Extension<AuthUser>) -> Response {
    ai_gate!(au);
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    let list: Vec<Value> = crate::ai::AI_PRESETS.iter().map(crate::ai::ai_preset_public).collect();
    Json(json!({ "presets": list })).into_response()
}

/// POST /api/ai/from-preset — instancie un provider À PARTIR d'un preset. Délègue à `ai_provider_create`
/// (même validation, colonne secret, audit). `enabled:false` FORCÉ, garde cloud appliquée (create + preset).
pub(crate) async fn ai_from_preset(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    ai_gate!(au);
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    let preset_id = b.get("preset_id").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    let preset = match crate::ai::ai_preset_by_id(&preset_id) {
        Some(p) => p,
        None => return bad_req("preset_id inconnu"),
    };
    let raw: Value = serde_json::from_str(preset.raw).unwrap_or_else(|_| json!({}));
    let values = b.get("values").and_then(|x| x.as_object()).cloned().unwrap_or_default();
    // Substitution des placeholders {ident} dans endpoint/model (jamais dans du JSON sérialisé).
    let subst = |s: &str| -> String {
        let mut out = s.to_string();
        for (k, v) in &values {
            if let Some(vv) = v.as_str() {
                out = out.replace(&format!("{{{k}}}"), vv);
            }
        }
        out
    };
    let endpoint = subst(b.get("endpoint").and_then(|x| x.as_str()).unwrap_or_else(|| raw.get("endpoint").and_then(|x| x.as_str()).unwrap_or("")));
    let model = subst(b.get("model").and_then(|x| x.as_str()).unwrap_or_else(|| raw.get("model").and_then(|x| x.as_str()).unwrap_or("")));
    if endpoint.contains('{') || model.contains('{') || endpoint.is_empty() || model.is_empty() {
        return bad_req("endpoint/model non renseignés (placeholders {…} restants)");
    }
    let mut config = raw.get("config").cloned().unwrap_or_else(|| json!({}));
    if let Some(o) = config.as_object_mut() {
        o.insert("model".into(), json!(model));
        o.insert("requires_cloud".into(), json!(preset.requires_cloud));
    }
    let name = b.get("name").and_then(|x| x.as_str()).filter(|s| !s.trim().is_empty()).map(|s| s.to_string()).unwrap_or_else(|| preset.id.to_string());
    let body = json!({
        "name": name,
        "vendor": preset.vendor,
        "api_shape": preset.api_shape,
        "endpoint": endpoint,
        "config": config,
        "enabled": false, // FORCÉ : l'admin teste puis active
        "secret": b.get("secret").cloned().unwrap_or_else(|| json!("")),
    });
    // DÉLÉGATION — la garde cloud + l'audit + la colonne secret sont assurés par ai_provider_create.
    ai_provider_create(State(st), Extension(au), Json(body)).await
}

// ================================ STATUS + NL→GXQL (analyste, viewer+) ================================

/// GET /api/ai/status — l'UI l'utilise pour afficher/masquer l'assistant. Feature+runtime+provider inertness.
pub(crate) async fn ai_status(State(st): State<AppState>, Extension(_au): Extension<AuthUser>) -> Response {
    if crate::ai::require_feature().is_err() {
        return Json(json!({ "enabled": false, "reason": "feature_off" })).into_response();
    }
    if st.multi_tenant {
        return Json(json!({ "enabled": false, "reason": "multitenant" })).into_response();
    }
    let runtime = crate::ai::runtime_enabled();
    let (has_provider, provider) = {
        let conn = st.db.lock();
        match conn.query_row("SELECT name,api_shape FROM ai_provider WHERE enabled=1 ORDER BY id LIMIT 1", [], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
            Ok((n, s)) => (true, json!({ "name": n, "api_shape": s })),
            Err(_) => (false, Value::Null),
        }
    };
    Json(json!({
        "enabled": runtime && has_provider,
        "runtime": runtime,
        "has_provider": has_provider,
        "provider": provider,
        "cloud_allowed": crate::ai::cloud_allowed(),
    }))
    .into_response()
}

/// POST /api/ai/nl2soql — assemble un prompt RÉDIGÉ (noms de champ CIM + question), interroge le provider
/// actif, passe le GXQL au compilo FERMÉ `soql_to_sql_x`, renvoie GXQL+SQL (ou l'erreur). ZÉRO exécution.
/// Un appel = une question (jamais par-event). Audité au ledger SANS matière de prompt ni clé.
pub(crate) async fn ai_nl2soql(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    ai_gate!(au);
    if st.multi_tenant {
        return ai_deny_multitenant();
    }
    if !crate::ai::runtime_enabled() {
        return err_json(StatusCode::CONFLICT, "couche IA désactivée (poser PLUME_AI_ENABLE=1 et builder --features ai)");
    }
    let nl = b.get("nl").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    if nl.is_empty() || nl.len() > 2000 {
        return bad_req("question vide ou trop longue (<= 2000)");
    }
    // Provider ACTIF (premier enabled=1). Inerte si aucun.
    let (pid, api_shape, endpoint, secret_ref, config): (i64, String, String, String, Value) = {
        let conn = st.db.lock();
        match conn.query_row(
            "SELECT id,api_shape,endpoint,secret,config_json FROM ai_provider WHERE enabled=1 ORDER BY id LIMIT 1",
            [],
            |r| {
                let cfg: String = r.get(4)?;
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, serde_json::from_str::<Value>(&cfg).unwrap_or_else(|_| json!({}))))
            },
        ) {
            Ok(v) => v,
            Err(_) => return err_json(StatusCode::CONFLICT, "aucun provider IA actif — configurez-en un (admin)"),
        }
    };
    let requires_cloud = config.get("requires_cloud").and_then(|x| x.as_bool()).unwrap_or(false);
    // GARDE CLOUD À L'APPEL (defense in depth).
    if let Err(e) = crate::ai::cloud_gate(&endpoint, requires_cloud) {
        return err_json(StatusCode::FORBIDDEN, e);
    }
    // BUDGET (fenêtre glissante, mode 0 -> tenant "default").
    if let Err(e) = crate::ai::budget_take("default") {
        return err_json(StatusCode::TOO_MANY_REQUESTS, e);
    }

    let model = config.get("model").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if model.is_empty() {
        return err_json(StatusCode::CONFLICT, "provider IA sans 'model' configuré");
    }
    let temperature = config.get("temperature").and_then(|x| x.as_f64()).unwrap_or(0.0);
    let num_ctx = config.get("num_ctx").and_then(|x| x.as_u64()).unwrap_or(4096) as u32;
    let max_tokens = config
        .get("max_tokens")
        .and_then(|x| x.as_u64())
        .map(|v| (v as u32).min(crate::ai::max_tokens_cap()))
        .unwrap_or_else(crate::ai::max_tokens_cap);

    // Résolution du secret (SecretRef grammar v126) — au call time, jamais stocké en clair, jamais loggé.
    let key = if secret_ref.is_empty() { String::new() } else { crate::resolve_ref_setup_safe("PLUME_AI_PROVIDER_SECRET", &secret_ref) };

    // Schéma RÉDIGÉ = champs CIM cœur + champs chauds, filtrés par la politique active.
    let policy = {
        let conn = st.db.lock();
        active_redaction_policy(&conn)
    };
    let mut raw_fields: Vec<String> = guatx_core::cim::CIM_CORE_FIELDS.iter().map(|s| s.to_string()).collect();
    raw_fields.extend(guatx_core::soql::HOT_FIELDS.iter().map(|s| s.to_string()));
    let fields = guatx_core::ai::redact_fields(&raw_fields, &policy);
    let categories = guatx_core::cim::CIM_CATEGORIES;

    // Hash du PROMPT RÉDIGÉ pour le ledger (jamais la matière). Reconstruit à l'identique du pipeline.
    let (sys_p, usr_p) = guatx_core::ai::build_nl2soql_prompt(&fields, categories, &nl);
    let prompt_sha = sha256_hex(format!("{sys_p}\n{usr_p}").as_bytes());

    // COUTURE COMPILO FERMÉ = /api/query. Aucune borne temporelle (l'analyste choisit sa fenêtre en Explore).
    // #45 : c'est le MÊME compilo que /api/query, donc le MÊME jeu de masques que /api/query — le GXQL
    // rendu à l'analyste ne peut pas référencer un champ masqué pour son rôle (sinon la couche IA serait un
    // générateur de requêtes que la surface d'exécution refuserait, ou pire un contournement). Masque VIDE
    // (mode 0 / admin sans règle) -> STRICTEMENT identique à `soql_to_sql_x`.
    let ai_masks = effective_masks(&req_db_path(&st, &au), &au.role, &au.tenant, au.env_filter());
    let compile = |s: &str| -> Result<String, String> { soql_to_sql_masked_x(s, 0, 0, None, &ai_masks) };

    let outcome = crate::ai::run_nl2soql(
        &endpoint, &api_shape, &model, &key, temperature, num_ctx, &nl, &fields, categories, &policy, max_tokens, &compile,
    );

    match outcome {
        Ok(o) => {
            // LEDGER : purpose, provider, tokens, version de politique, HASH du prompt rédigé. JAMAIS la
            // matière du prompt, JAMAIS la clé, JAMAIS le GXQL/SQL généré (le hash suffit à l'audit).
            {
                let conn = st.db.lock();
                let detail = ai_call_ledger_detail(
                    pid, &api_shape, crate::ai::provider_is_cloud(&endpoint, requires_cloud),
                    o.prompt_tokens, o.completion_tokens, policy.version, &prompt_sha, o.valid, o.retried, &au.name,
                );
                ledger_append(&conn, "ai.call", &detail);
            }
            Json(json!({
                "soql": o.soql,
                "sql": o.sql,
                "valid": o.valid,
                "error": o.error,
                "retried": o.retried,
                "prompt_tokens": o.prompt_tokens,
                "completion_tokens": o.completion_tokens,
            }))
            .into_response()
        }
        Err(e) => ai_worker_err(e),
    }
}
