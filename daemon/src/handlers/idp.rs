//! Handlers HTTP de l'IdP natif (#44) : CRUD admin des fournisseurs fédérés (OIDC/LDAP/SAML seam,
//! secret write-only + redaction, miroir de `connectors.rs`), flux de login OIDC (Authorization-Code +
//! PKCE), login LDAP (bind), et MFA TOTP (enrôlement/vérif/désactivation + challenge à la connexion).
//!
//! MODE 0 UNIQUEMENT (comme le provisioning de jetons UI) : en multi-tenant, IdP/MFA vivent au control-plane
//! (hors périmètre de cet incrément) -> ces routes renvoient 501, JAMAIS un chemin fédéré cross-tenant à
//! moitié câblé. FAIL-CLOSED partout ; le cœur logique (validation JWT, bind, TOTP) est dans `idp.rs`.
use crate::*;

// ---------- utilitaires locaux ----------

/// Nom de provider valide (segment d'URL sûr) : alphanumérique + `. _ -`, non vide, <= 64.
fn idp_name_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Nom réservé au compte admin de CONFIG (PLUME_USER + PLUME_PASS_HASH) — repli de `authenticate()`, JAMAIS
/// dans la table `user`. Un login fédéré portant ce nom est refusé (anti lockout/hijack de l'admin statique).
/// None si aucun admin de config n'est posé (pass_hash vide) -> pas de nom à réserver.
fn reserved_static_admin(st: &AppState) -> Option<&str> {
    (!st.pass_hash.is_empty()).then(|| st.user.as_str())
}

/// Refus mode-1 homogène (IdP/MFA = mono-tenant dans cet incrément).
fn deny_multitenant() -> Response {
    err_json(StatusCode::NOT_IMPLEMENTED, "IdP/MFA via l'UI réservé au mode mono-tenant (control-plane : voir la roadmap #2)")
}

/// GET JSON via le client HTTP interne (rustls/ring). Corps jamais mis dans une erreur.
fn fetch_json(url: &str) -> Result<Value, String> {
    ssrf_guard(url)?; // discovery OIDC + jwks_uri sont pilotés par la config IdP -> garde SSRF (anti 169.254/interne/rebind)
    let resp = http_call("GET", url, &[("Accept", "application/json")], None)?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("HTTP {} (discovery/jwks)", resp.status));
    }
    serde_json::from_slice(&resp.body).map_err(|_| "réponse non-JSON".to_string())
}

/// Pose les cookies de session (plume_session HttpOnly + plume_csrf) sur une réponse — MÊME construction
/// que `login_post` (jeton HMAC lié à l'epoch, TTL, Secure si TLS). Chemin de sortie commun OIDC/LDAP/MFA.
fn attach_session_cookies(st: &AppState, resp: &mut Response, name: &str, role: &str) {
    let epoch = st.session_epoch.load(std::sync::atomic::Ordering::Relaxed);
    let token = mint_session(st.session_secret.as_slice(), name, role, st.session_ttl_s, epoch);
    let csrf = csrf_for(st.session_secret.as_slice(), &token);
    let secure = cookie_secure_suffix();
    let ttl = st.session_ttl_s.max(1);
    let c_sess = format!("plume_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}{secure}");
    let c_csrf = format!("plume_csrf={csrf}; SameSite=Strict; Path=/; Max-Age={ttl}{secure}");
    if let Ok(v) = c_sess.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    if let Ok(v) = c_csrf.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
}

/// Ticket MFA signé (2e facteur en attente) : `mfa|user|role|exp`, HMAC-SHA256 (session_secret). Émis par
/// `login_post` quand le 1er facteur réussit ET que l'utilisateur a une MFA active ; consommé par
/// `login_mfa_post`. Stateless, non forgeable, borné dans le temps. Le préfixe de domaine `mfa` empêche
/// toute confusion avec un jeton de session/state OIDC.
fn mfa_ticket_sign(secret: &[u8], user: &str, role: &str, ttl_s: i64) -> String {
    let exp = now() + ttl_s.max(1);
    let payload = format!("mfa|{user}|{role}|{exp}");
    let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let sig = hmac_sha256(secret, p_b64.as_bytes());
    format!("{p_b64}.{}", hex_encode(&sig))
}

fn mfa_ticket_verify(secret: &[u8], blob: &str) -> Option<(String, String)> {
    let (p_b64, sig_hex) = blob.split_once('.')?;
    let expect = hmac_sha256(secret, p_b64.as_bytes());
    if !ct_eq(&hex_decode(sig_hex)?, &expect) {
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p_b64).ok()?;
    let s = String::from_utf8(raw).ok()?;
    let mut it = s.split('|');
    if it.next()? != "mfa" {
        return None;
    }
    let user = it.next()?.to_string();
    let role = it.next()?.to_string();
    let exp: i64 = it.next()?.parse().ok()?;
    if now() >= exp {
        return None;
    }
    Some((user, role))
}

// ================================================================================================
// CRUD des fournisseurs (admin-only, mode 0). Secret write-only + redaction (miroir connectors.rs).
// ================================================================================================

pub(crate) async fn idp_providers_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return deny_multitenant();
    }
    let conn = st.db.lock();
    // Le secret n'est JAMAIS projeté : seul le booléen (secret != '') sort.
    let list: Vec<Value> = match conn.prepare(
        "SELECT id,name,kind,enabled,config_json,created,updated,(secret != '') FROM idp_provider ORDER BY id",
    ) {
        Ok(mut stmt) => stmt
            .query_map([], |r| {
                let cfg_json: String = r.get(4)?;
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "name": r.get::<_, String>(1)?,
                    "kind": r.get::<_, String>(2)?,
                    "enabled": r.get::<_, i64>(3)? != 0,
                    "config": serde_json::from_str::<Value>(&cfg_json).unwrap_or_else(|_| json!({})),
                    "created": r.get::<_, i64>(5)?,
                    "updated": r.get::<_, i64>(6)?,
                    "has_secret": r.get::<_, i64>(7)? != 0,
                }))
            })
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    Json(Value::Array(list)).into_response()
}

pub(crate) async fn idp_provider_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return deny_multitenant();
    }
    let name = b.trimmed("name");
    if !idp_name_ok(&name) {
        return bad_req("nom de provider invalide (alphanumérique, . _ - ; <= 64)");
    }
    let kind = match b.get("kind").and_then(|x| x.as_str()) {
        Some("oidc") => "oidc",
        Some("ldap") => "ldap",
        Some("saml") => "saml",
        _ => return bad_req("kind non supporté (oidc | ldap | saml)"),
    };
    let config = b.get("config").cloned().unwrap_or_else(|| json!({}));
    // Validation minimale par type (fail-closed : refuse une config inexploitable).
    match kind {
        "oidc" => {
            let c = OidcCfg::from_json(&config);
            if !c.is_usable() {
                return bad_req("config OIDC : issuer, client_id et redirect_uri requis");
            }
            if !c.redirect_uri.starts_with("https://") && !c.redirect_uri.starts_with("http://") {
                return bad_req("redirect_uri doit être une URL absolue http(s)");
            }
        }
        "ldap" => {
            let c = LdapCfg::from_json(&config);
            if c.url.is_empty() {
                return bad_req("config LDAP : url requise (ldap:// ou ldaps://)");
            }
        }
        "saml" => {
            // DURCISSEMENT #7 : want_assertions_signed=false est un footgun réel (assertions acceptées non
            // signées). GARDÉ configurable (IdP legacy signant seulement la Response) mais JAMAIS silencieux :
            // avertissement BRUYANT au moment de la config (le use-time est aussi averti dans saml_verify_and_extract).
            let c = SamlCfg::from_json(&config);
            if !c.want_assertions_signed {
                eprintln!(
                    "AVERTISSEMENT SÉCURITÉ SAML — provider '{name}' créé avec want_assertions_signed=false : assertions acceptées NON SIGNÉES (INSÉCURE, réservé à un IdP legacy). Cf. docs/NATIVE-IDP.md §5."
                );
            }
        }
        _ => {}
    }
    let enabled = b.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false) as i64;
    let secret = b.get("secret").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let conn = st.db.lock();
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO idp_provider(name,kind,enabled,config_json,secret,created,updated) VALUES(?1,?2,?3,?4,?5,?6,?6)",
            params![name, kind, enabled, config.to_string(), secret, now()],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.idp.create",
            &format!("provider IdP '{name}' ({kind}) créé par {}", au.name), 3,
            &format!("fournisseur d'identité '{name}' ({kind}, enabled={}) créé par {}", enabled != 0, au.name),
            &json!({ "id": id, "kind": kind, "enabled": enabled != 0, "has_secret": !secret.is_empty(), "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "id": id, "enabled": enabled != 0 })).into_response() }
        Err(_) => { let _ = conn.execute_batch("ROLLBACK"); (StatusCode::CONFLICT, "échec de création (nom déjà pris ou audit) — réessayez").into_response() }
    }
}

pub(crate) async fn idp_provider_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return deny_multitenant();
    }
    let conn = st.db.lock();
    if conn.query_row("SELECT 1 FROM idp_provider WHERE id=?1", params![id], |_| Ok(())).is_err() {
        return not_found("provider introuvable");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) {
            conn.execute("UPDATE idp_provider SET enabled=?1 WHERE id=?2", params![v as i64, id])?;
        }
        if let Some(v) = b.get("config") {
            conn.execute("UPDATE idp_provider SET config_json=?1 WHERE id=?2", params![v.to_string(), id])?;
        }
        // SECRET : mis à jour UNIQUEMENT si fourni ET non vide -> omis/vide = conserver l'existant (jamais
        // d'écrasement par vide ; jamais renvoyé ni loggé).
        let mut secret_rotated = false;
        if let Some(s) = b.get("secret").and_then(|x| x.as_str()) {
            if !s.is_empty() {
                conn.execute("UPDATE idp_provider SET secret=?1 WHERE id=?2", params![s, id])?;
                secret_rotated = true;
            }
        }
        conn.execute("UPDATE idp_provider SET updated=?1 WHERE id=?2", params![now(), id])?;
        let changed: Vec<&str> = ["enabled", "config"].iter().copied().filter(|k| b.get(*k).is_some()).collect();
        audit_config_change(
            &conn, "config.idp.update",
            &format!("provider IdP #{id} modifié ({}{}) par {}", changed.join(","), if secret_rotated { ",secret" } else { "" }, au.name), 3,
            &format!("fournisseur d'identité #{id} modifié (champs: {}{}) par {}", changed.join(","), if secret_rotated { ", secret rotaté" } else { "" }, au.name),
            &json!({ "id": id, "changed": changed, "secret_rotated": secret_rotated, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "ok": true })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

pub(crate) async fn idp_provider_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return deny_multitenant();
    }
    let conn = st.db.lock();
    let name: Option<String> = conn.query_row("SELECT name FROM idp_provider WHERE id=?1", params![id], |r| r.get(0)).ok();
    let Some(name) = name else { return not_found("provider introuvable") };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM idp_provider WHERE id=?1", params![id])?;
        audit_config_change(
            &conn, "config.idp.delete",
            &format!("provider IdP '{name}' (#{id}) supprimé par {}", au.name), 3,
            &format!("fournisseur d'identité '{name}' supprimé par {}", au.name),
            &json!({ "id": id, "name": name, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); StatusCode::NO_CONTENT.into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit: {e}")) }
    }
}

// ================================================================================================
// OIDC login (Authorization-Code + PKCE). Routes PUBLIQUES (auth_guard allowlist).
// ================================================================================================

/// Charge une ligne provider (config_json, secret) par nom + kind + enabled=1. None si absent/désactivé.
fn load_provider(st: &AppState, name: &str, kind: &str) -> Option<(Value, String)> {
    let conn = st.db.lock();
    conn.query_row(
        "SELECT config_json,secret FROM idp_provider WHERE name=?1 AND kind=?2 AND enabled=1",
        params![name, kind],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )
    .ok()
    .map(|(cj, sec)| (serde_json::from_str(&cj).unwrap_or_else(|_| json!({})), sec))
}

/// Résout les endpoints OIDC : discovery si nécessaire (endpoints non tous overridés). Blocking (rare).
fn oidc_endpoints_for(cfg: &OidcCfg) -> Result<OidcEndpoints, String> {
    let need_discovery = cfg.authorization_endpoint.is_empty() || cfg.token_endpoint.is_empty() || cfg.jwks_uri.is_empty();
    let discovery = if need_discovery { Some(fetch_json(&cfg.discovery_url())?) } else { None };
    oidc_resolve_endpoints(cfg, discovery.as_ref())
}

/// GET /api/auth/oidc/:name/start — démarre le login OIDC : pose un cookie de state signé (Lax, court) et
/// redirige (302) vers l'authorize endpoint. PUBLIC. Fail-closed : provider inconnu/désactivé/misconfig -> 4xx.
pub(crate) async fn oidc_start(State(st): State<AppState>, Path(name): Path<String>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    if !idp_name_ok(&name) {
        return bad_req("nom de provider invalide");
    }
    let Some((cfg_json, _secret)) = load_provider(&st, &name, "oidc") else {
        return not_found("provider OIDC inconnu ou désactivé");
    };
    let cfg = OidcCfg::from_json(&cfg_json);
    if !cfg.is_usable() {
        return server_err("configuration OIDC incomplète");
    }
    // Réseau (discovery) -> spawn_blocking : ne bloque PAS l'exécuteur async (route publique pré-auth ;
    // http_call = std::net bloquant jusqu'à 10 s -> sinon famine du pool de workers = DoS). Cf. connectors.rs.
    let cfg_disc = cfg.clone();
    let ep = match tokio::task::spawn_blocking(move || oidc_endpoints_for(&cfg_disc)).await {
        Ok(Ok(e)) => e,
        Ok(Err(e)) => return err_json(StatusCode::BAD_GATEWAY, format!("découverte OIDC échouée: {e}")),
        Err(_) => return server_err("échec interne (discovery)"),
    };
    let (Some(state), Some(nonce), Some(verifier)) = (rand_url_token(), rand_url_token(), rand_url_token()) else {
        return server_err("entropie noyau indisponible");
    };
    let challenge = pkce_challenge_s256(&verifier);
    let blob = oidc_state_sign(st.session_secret.as_slice(), &name, &state, &nonce, &verifier, 600);
    let secure = cookie_secure_suffix();
    // SameSite=Lax : le cookie DOIT survivre à la navigation top-level de retour depuis l'IdP (Strict le
    // droperait). HttpOnly ; Max-Age court (10 min) borné à la durée du flux.
    let cookie = format!("plume_oidc={blob}; HttpOnly; SameSite=Lax; Path=/api/auth/oidc; Max-Age=600{secure}");
    let url = oidc_authorize_url(&cfg, &ep, &state, &nonce, &challenge);
    let mut resp = (StatusCode::FOUND, [(header::LOCATION, url)]).into_response();
    if let Ok(v) = cookie.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

/// GET /api/auth/oidc/callback?code=&state= — valide le retour IdP, échange le code, valide l'id_token,
/// mappe groupe->rôle, provisionne le compte JIT, pose la session et redirige vers `/`. PUBLIC. Fail-closed.
pub(crate) async fn oidc_callback(State(st): State<AppState>, headers: axum::http::HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    // erreur renvoyée par l'IdP (ex access_denied) -> 401, jamais de session.
    if let Some(e) = q.get("error") {
        return err_json(StatusCode::UNAUTHORIZED, format!("l'IdP a refusé l'authentification: {e}"));
    }
    // 1) State cookie signé -> provider/state/nonce/verifier attendus.
    let cookie_hdr = headers.get(header::COOKIE).and_then(|h| h.to_str().ok()).unwrap_or("");
    let Some(blob) = cookie_value(cookie_hdr, "plume_oidc") else {
        return bad_req("state de login OIDC absent (cookie manquant ou expiré)");
    };
    let Some((provider, exp_state, nonce, verifier)) = oidc_state_verify(st.session_secret.as_slice(), &blob) else {
        return bad_req("state de login OIDC invalide ou expiré");
    };
    // 2) CSRF : le state renvoyé par l'IdP DOIT == celui du cookie (temps constant).
    let got_state = q.get("state").map(String::as_str).unwrap_or("");
    if !ct_eq(got_state.as_bytes(), exp_state.as_bytes()) {
        return bad_req("state OIDC ne correspond pas (anti-CSRF)");
    }
    let Some(code) = q.get("code").filter(|c| !c.is_empty()) else {
        return bad_req("code d'autorisation absent");
    };
    // 3) Provider (re-chargé côté serveur, jamais depuis la requête).
    let Some((cfg_json, secret)) = load_provider(&st, &provider, "oidc") else {
        return not_found("provider OIDC inconnu ou désactivé");
    };
    let cfg = OidcCfg::from_json(&cfg_json);
    // Réseau -> spawn_blocking (route publique pré-auth ; jusqu'à 3 appels réseau bloquants = ~30 s -> sinon
    // famine du pool de workers async = DoS pré-auth). Miroir strict de connectors.rs.
    let cfg_disc = cfg.clone();
    let ep = match tokio::task::spawn_blocking(move || oidc_endpoints_for(&cfg_disc)).await {
        Ok(Ok(e)) => e,
        Ok(Err(e)) => return err_json(StatusCode::BAD_GATEWAY, format!("découverte OIDC échouée: {e}")),
        Err(_) => return server_err("échec interne (discovery)"),
    };
    // 4) Échange du code -> id_token (le secret ne transite QUE dans ce corps POST). Réseau -> spawn_blocking.
    let body = oidc_token_body(&cfg, code, &verifier, &secret);
    let token_url = ep.token_endpoint.clone();
    let tok_resp = match tokio::task::spawn_blocking(move || {
        ssrf_guard(&token_url)?; // le token_endpoint (config/discovery) est un égress -> garde SSRF
        http_call("POST", &token_url, &[("Content-Type", "application/x-www-form-urlencoded"), ("Accept", "application/json")], Some(body.as_bytes()))
    }).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return err_json(StatusCode::BAD_GATEWAY, format!("échange de code échoué: {e}")),
        Err(_) => return server_err("échec interne (token)"),
    };
    if !(200..300).contains(&tok_resp.status) {
        return err_json(StatusCode::UNAUTHORIZED, format!("échange de code refusé (HTTP {})", tok_resp.status));
    }
    let tok_json: Value = match serde_json::from_slice(&tok_resp.body) {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::BAD_GATEWAY, "réponse token non-JSON"),
    };
    let Some(id_token) = tok_json.get("id_token").and_then(|v| v.as_str()) else {
        return err_json(StatusCode::UNAUTHORIZED, "id_token absent de la réponse token");
    };
    // 5) JWKS + validation signature/iss/aud/exp/nonce (fail-closed). Réseau -> spawn_blocking.
    let jwks_url = ep.jwks_uri.clone();
    let jwks = match tokio::task::spawn_blocking(move || fetch_json(&jwks_url)).await {
        Ok(Ok(j)) => j,
        Ok(Err(e)) => return err_json(StatusCode::BAD_GATEWAY, format!("JWKS indisponible: {e}")),
        Err(_) => return server_err("échec interne (jwks)"),
    };
    let claims = match oidc_validate_id_token(id_token, &jwks, &cfg.issuer, &cfg.client_id, &nonce) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::UNAUTHORIZED, format!("id_token invalide: {e}")),
    };
    // 6) Identité + rôle (mapping groupe->rôle réutilisé ; fail-closed si aucun groupe mappé).
    let username = oidc_username(&claims);
    if !idp_name_ok(&username) {
        return err_json(StatusCode::UNAUTHORIZED, "nom d'utilisateur OIDC absent ou invalide");
    }
    let groups = oidc_groups_str(&claims, &cfg.group_claim);
    let Some(role) = oidc_role_mode0(&st, &groups, cfg.require_group_match) else {
        return forbidden("aucun groupe OIDC mappé à un rôle Plume (accès refusé)");
    };
    // 7) Provisioning JIT (anti-collision compte local + réservation admin bootstrap) + session.
    {
        let conn = st.db.lock();
        if let Err(e) = idp_provision_user(&conn, &username, &role, reserved_static_admin(&st)) {
            return (StatusCode::CONFLICT, e).into_response();
        }
        ledger_append(&conn, "login", &format!("login OIDC : '{username}' (rôle {role}) via provider '{provider}'"));
    }
    // 8) Redirige vers `/` (jamais une URL contrôlée par l'utilisateur -> pas d'open redirect) + efface le state.
    let mut resp = (StatusCode::FOUND, [(header::LOCATION, "/")]).into_response();
    attach_session_cookies(&st, &mut resp, &username, &role);
    let secure = cookie_secure_suffix();
    if let Ok(v) = format!("plume_oidc=; HttpOnly; SameSite=Lax; Path=/api/auth/oidc; Max-Age=0{secure}").parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

// ================================================================================================
// SAML 2.0 SP login (SP-initié, HTTP-POST ACS). Routes PUBLIQUES (auth_guard allowlist). La vérification
// XML-DSig/XSW est feature-gated (`saml`) dans idp.rs -> sans la feature, ces handlers renvoient 501.
// ================================================================================================

/// GET /api/auth/saml/:name/start — construit l'AuthnRequest (HTTP-Redirect), pose le RelayState signé +
/// un cookie de flux (Lax, best-effort) et redirige (302) vers l'IdP. PUBLIC. Fail-closed.
pub(crate) async fn saml_start(State(st): State<AppState>, Path(name): Path<String>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    if !idp_name_ok(&name) {
        return bad_req("nom de provider invalide");
    }
    let Some((cfg_json, secret)) = load_provider(&st, &name, "saml") else {
        return not_found("provider SAML inconnu ou désactivé");
    };
    let cfg = SamlCfg::from_json(&cfg_json);
    if !cfg.is_usable() {
        return server_err("configuration SAML incomplète (idp_sso_url/idp_entity_id/sp_entity_id/acs_url/idp_x509_cert requis)");
    }
    // Génération PURE (XML + deflate + éventuelle signature RSA) — CPU ms-scale, aucun réseau : inline.
    let (url, blob) = match saml_build_authn_redirect(&cfg, &name, &secret, st.session_secret.as_slice()) {
        Ok(v) => v,
        Err(e) if e.contains("non compilé") => return err_json(StatusCode::NOT_IMPLEMENTED, e),
        Err(e) => return server_err(format!("échec de l'AuthnRequest SAML: {e}")),
    };
    let secure = cookie_secure_suffix();
    // Cookie de flux Lax = défense en profondeur : peut NE PAS survivre au POST cross-site vers l'ACS
    // (SameSite=Lax exclut les POST cross-site) -> le RelayState signé (echo IdP) reste la SOURCE DE VÉRITÉ.
    let cookie = format!("plume_saml={blob}; HttpOnly; SameSite=Lax; Path=/api/auth/saml; Max-Age=600{secure}");
    let mut resp = (StatusCode::FOUND, [(header::LOCATION, url)]).into_response();
    if let Ok(v) = cookie.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

/// POST /api/auth/saml/acs — Assertion Consumer Service (SÉCURITÉ-CRITIQUE). Consomme SAMLResponse+RelayState,
/// valide (checklist complète dans `saml_verify_and_extract`), mappe groupe->rôle, provisionne JIT, pose la
/// session, 302 vers `/`. PUBLIC. Fail-closed : toute anomalie -> 4xx, aucune session.
pub(crate) async fn saml_acs(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Form(form): axum::extract::Form<HashMap<String, String>>,
) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    let Some(saml_response) = form.get("SAMLResponse").filter(|s| !s.is_empty()) else {
        return bad_req("SAMLResponse absente");
    };
    // 1) RelayState signé (#12) -> (provider, request_id). JAMAIS de RelayState brut fiable.
    let relay = form.get("RelayState").map(String::as_str).unwrap_or("");
    let Some((provider, request_id)) = saml_relaystate_verify(st.session_secret.as_slice(), relay) else {
        return bad_req("RelayState SAML invalide ou expiré (recommencez la connexion)");
    };
    // 2) Liaison de flux best-effort via le cookie plume_saml (si présent : DOIT concorder ; s'il a été
    //    droppé par SameSite=Lax sur le POST cross-site, on s'appuie sur le RelayState signé, autoritatif).
    let cookie_hdr = headers.get(header::COOKIE).and_then(|h| h.to_str().ok()).unwrap_or("");
    if let Some(cval) = cookie_value(cookie_hdr, "plume_saml") {
        match saml_relaystate_verify(st.session_secret.as_slice(), &cval) {
            Some((_, cookie_req_id)) if ct_eq(cookie_req_id.as_bytes(), request_id.as_bytes()) => {}
            _ => return bad_req("liaison de flux SAML invalide (cookie/RelayState divergents)"),
        }
    }
    // 3) Provider re-chargé côté serveur (jamais depuis la requête).
    let Some((cfg_json, _secret)) = load_provider(&st, &provider, "saml") else {
        return not_found("provider SAML inconnu ou désactivé");
    };
    let cfg = SamlCfg::from_json(&cfg_json);
    // 4) VÉRIFICATION + EXTRACTION (feature-gated ; anti-rejeu via le set global borné). Le verrou est tenu
    //    pendant finish_sso (l'adaptateur de rejeu l'utilise) — login peu fréquent, coût négligeable.
    let now_unix = now();
    let res = {
        let mut store = saml_replay_store().lock();
        saml_verify_and_extract(&cfg, saml_response, &request_id, now_unix, &mut *store)
    };
    let (username, groups) = match res {
        Ok(v) => v,
        Err(e) if e.contains("non compilé") => return err_json(StatusCode::NOT_IMPLEMENTED, e),
        Err(_) => return err_json(StatusCode::UNAUTHORIZED, "assertion SAML invalide"),
    };
    // 5) Identité contrainte (même politique qu'OIDC : segment sûr, pas de '|' qui casserait le token de session).
    if !idp_name_ok(&username) {
        return err_json(StatusCode::UNAUTHORIZED, "nom d'utilisateur SAML absent ou invalide (attr_username/NameID)");
    }
    // 6) Rôle (mapping groupe->rôle RÉUTILISÉ ; fail-closed si aucun groupe mappé, #13).
    let Some(role) = oidc_role_mode0(&st, &saml_groups_str(&groups), cfg.require_group_match) else {
        return forbidden("aucun groupe SAML mappé à un rôle Plume (accès refusé)");
    };
    // 7) Provisioning JIT (anti-collision compte local + réservation admin bootstrap) + session.
    {
        let conn = st.db.lock();
        if let Err(e) = idp_provision_user(&conn, &username, &role, reserved_static_admin(&st)) {
            return (StatusCode::CONFLICT, e).into_response();
        }
        ledger_append(&conn, "login", &format!("login SAML : '{username}' (rôle {role}) via provider '{provider}'"));
    }
    // 8) Redirige vers `/` (jamais une URL contrôlée par l'utilisateur) + efface le cookie de flux.
    let mut resp = (StatusCode::FOUND, [(header::LOCATION, "/")]).into_response();
    attach_session_cookies(&st, &mut resp, &username, &role);
    let secure = cookie_secure_suffix();
    if let Ok(v) = format!("plume_saml=; HttpOnly; SameSite=Lax; Path=/api/auth/saml; Max-Age=0{secure}").parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

/// GET /api/auth/saml/:name/metadata — métadonnée SP (XML public, à fournir à l'IdP). PUBLIC.
pub(crate) async fn saml_metadata(State(st): State<AppState>, Path(name): Path<String>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    if !idp_name_ok(&name) {
        return bad_req("nom de provider invalide");
    }
    let Some((cfg_json, _)) = load_provider(&st, &name, "saml") else {
        return not_found("provider SAML inconnu ou désactivé");
    };
    let cfg = SamlCfg::from_json(&cfg_json);
    match saml_sp_metadata_xml(&cfg) {
        Ok(xml) => ([(header::CONTENT_TYPE, "application/samlmetadata+xml")], xml).into_response(),
        Err(e) if e.contains("non compilé") => err_json(StatusCode::NOT_IMPLEMENTED, e),
        Err(e) => server_err(format!("génération métadonnée SP échouée: {e}")),
    }
}

// ================================================================================================
// LDAP login (bind). Route PUBLIQUE. Le bind réseau est feature-gated (`ldap`) dans idp.rs.
// ================================================================================================

/// POST /api/auth/ldap {provider?, user, pass} — bind LDAP/AD, mappe l'appartenance aux groupes -> rôle,
/// provisionne JIT, pose la session. PUBLIC. Anti-brute-force réutilisé (lockout (user,ip)). Fail-closed.
pub(crate) async fn ldap_login_post(State(st): State<AppState>, ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>, Json(b): Json<Value>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    let user = b.trimmed("user");
    let pass = b.str_field("pass").to_string();
    let ip = peer.ip().to_string();
    if user.is_empty() || pass.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "user et pass requis");
    }
    if let Some(retry) = auth_lock_check(&st, &user, &ip) {
        return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, retry.to_string())], Json(json!({ "error": "trop d'échecs — réessayez plus tard" }))).into_response();
    }
    // provider : nommé, sinon le 1er provider LDAP activé.
    let prov_name = b.trimmed("provider");
    let row: Option<(Value, String)> = if !prov_name.is_empty() {
        load_provider(&st, &prov_name, "ldap")
    } else {
        let conn = st.db.lock();
        conn.query_row(
            "SELECT config_json,secret FROM idp_provider WHERE kind='ldap' AND enabled=1 ORDER BY id LIMIT 1",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .ok()
        .map(|(cj, sec)| (serde_json::from_str(&cj).unwrap_or_else(|_| json!({})), sec))
    };
    let Some((cfg_json, bind_pw)) = row else {
        return not_found("aucun provider LDAP activé");
    };
    let cfg = LdapCfg::from_json(&cfg_json);
    // Bind bloquant (feature-gated) -> spawn_blocking : route publique pré-auth, ne bloque PAS l'exécuteur
    // async (sinon famine du pool de workers = DoS). Erreur -> échec d'auth (lockout), jamais de détail sensible.
    let (cfg_b, bind_b, user_b, pass_b) = (cfg.clone(), bind_pw.clone(), user.clone(), pass.clone());
    let auth_res = tokio::task::spawn_blocking(move || ldap_authenticate(&cfg_b, &bind_b, &user_b, &pass_b))
        .await
        .unwrap_or_else(|_| Err("échec interne LDAP".to_string()));
    match auth_res {
        Ok(role) => {
            auth_record_success(&st, &user, &ip);
            {
                let conn = st.db.lock();
                if let Err(e) = idp_provision_user(&conn, &user, &role, reserved_static_admin(&st)) {
                    return (StatusCode::CONFLICT, e).into_response();
                }
                ledger_append(&conn, "login", &format!("login LDAP : '{user}' (rôle {role})"));
            }
            let mut resp = Json(json!({ "ok": true, "user": user, "role": role })).into_response();
            attach_session_cookies(&st, &mut resp, &user, &role);
            resp
        }
        Err(e) => {
            let _ = auth_record_failure(&st, &user, &ip);
            // ldap non compilé -> 501 explicite ; sinon 401 générique (pas de fuite : user existe/n'existe pas).
            if e.contains("non compilé") {
                err_json(StatusCode::NOT_IMPLEMENTED, e)
            } else {
                err_json(StatusCode::UNAUTHORIZED, "identifiants LDAP invalides")
            }
        }
    }
}

// ================================================================================================
// MFA TOTP : enrôlement / vérif / désactivation (self-service authentifié) + challenge au login.
// ================================================================================================

/// True si `user` a une MFA ACTIVE (enabled=1). Mode 0 uniquement (table `user_mfa` dans st.db).
pub(crate) fn mfa_enabled_for(st: &AppState, user: &str) -> bool {
    let conn = st.db.lock();
    conn.query_row("SELECT enabled FROM user_mfa WHERE user=?1", params![user], |r| r.get::<_, i64>(0))
        .map(|v| v != 0)
        .unwrap_or(false)
}

pub(crate) async fn mfa_status(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    let conn = st.db.lock();
    let row: Option<i64> = conn.query_row("SELECT enabled FROM user_mfa WHERE user=?1", params![au.name], |r| r.get(0)).ok();
    Json(json!({ "enrolled": row.is_some(), "enabled": row.map(|v| v != 0).unwrap_or(false) })).into_response()
}

/// POST /api/mfa/enroll — génère une graine TOTP (base32) + l'URI otpauth (show-once) ; enregistre en
/// `enabled=0` (en attente de vérification). Ne PEUT PAS écraser une MFA déjà active (409 : désactiver d'abord).
pub(crate) async fn mfa_enroll(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    {
        let conn = st.db.lock();
        let en: Option<i64> = conn.query_row("SELECT enabled FROM user_mfa WHERE user=?1", params![au.name], |r| r.get(0)).ok();
        if en == Some(1) {
            return err_json(StatusCode::CONFLICT, "MFA déjà active (désactivez-la d'abord)");
        }
    }
    let Some(seed) = rand_bytes(20) else {
        return server_err("entropie noyau indisponible");
    };
    let secret_b32 = base32_encode(&seed);
    {
        let conn = st.db.lock();
        if conn.execute(
            // last_step=-1 : un ré-enrôlement repart d'une graine neuve -> compteur anti-rejeu réinitialisé.
            "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES(?1,?2,0,'[]',-1,?3,?3) \
             ON CONFLICT(user) DO UPDATE SET secret=excluded.secret, enabled=0, recovery='[]', last_step=-1, updated=excluded.updated",
            params![au.name, secret_b32, now()],
        ).is_err() {
            return server_err("enregistrement de l'enrôlement échoué");
        }
    }
    let uri = totp_uri("Plume", &au.name, &secret_b32);
    Json(json!({ "secret": secret_b32, "otpauth_uri": uri })).into_response()
}

/// POST /api/mfa/verify {code} — vérifie le 1er code TOTP -> ACTIVE la MFA + renvoie les codes de secours
/// (show-once). Un code invalide -> 401 (l'enrôlement reste en attente). Fail-closed.
pub(crate) async fn mfa_verify(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    let code = b.trimmed("code");
    let row: Option<(String, i64)> = {
        let conn = st.db.lock();
        conn.query_row("SELECT secret,last_step FROM user_mfa WHERE user=?1", params![au.name], |r| Ok((r.get(0)?, r.get(1)?))).ok()
    };
    let Some((secret, last_step)) = row.filter(|(s, _)| !s.is_empty()) else {
        return bad_req("aucun enrôlement en cours (appelez /api/mfa/enroll d'abord)");
    };
    // ANTI-REJEU : le pas TOTP matché doit être STRICTEMENT postérieur au dernier pas consommé (last_step=-1
    // à l'enrôlement -> tout pas réel passe ; un code déjà utilisé serait <= last_step -> refusé).
    let Some(step) = totp_verify_step(&secret, &code, now(), 30, 6, 1) else {
        return err_json(StatusCode::UNAUTHORIZED, "code TOTP invalide");
    };
    if step <= last_step {
        return err_json(StatusCode::UNAUTHORIZED, "code TOTP déjà utilisé (anti-rejeu)");
    }
    let Some((clear, hashes)) = gen_recovery_codes(10) else {
        return server_err("entropie noyau indisponible");
    };
    {
        let conn = st.db.lock();
        if conn.execute(
            "UPDATE user_mfa SET enabled=1, recovery=?1, last_step=?2, updated=?3 WHERE user=?4",
            params![json!(hashes).to_string(), step, now(), au.name],
        ).is_err() {
            return server_err("activation MFA échouée");
        }
        ledger_append(&conn, "mfa", &format!("MFA TOTP activée pour '{}'", au.name));
    }
    // SHOW-ONCE : les codes de secours CLAIRS ne sont renvoyés QU'ICI (seuls leurs SHA-256 sont persistés).
    Json(json!({ "ok": true, "recovery_codes": clear })).into_response()
}

/// POST /api/mfa/disable {code} — désactive la MFA de l'appelant. Exige un code TOTP (ou de secours) VALIDE
/// -> une session détournée sans le 2e facteur ne peut pas retirer la MFA. Fail-closed.
pub(crate) async fn mfa_disable(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    let code = b.trimmed("code");
    let row: Option<(String, i64, String)> = {
        let conn = st.db.lock();
        conn.query_row("SELECT secret,enabled,recovery FROM user_mfa WHERE user=?1", params![au.name], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).ok()
    };
    let Some((secret, enabled, recovery)) = row else {
        return not_found("aucune MFA enrôlée");
    };
    if enabled == 1 {
        // exige un facteur valide pour désactiver (TOTP ou code de secours).
        let totp_ok = totp_verify(&secret, &code, now(), 30, 6, 1);
        let rec_ok = !code.is_empty() && recovery_contains(&recovery, &code);
        if !totp_ok && !rec_ok {
            return err_json(StatusCode::UNAUTHORIZED, "code MFA requis pour désactiver");
        }
    }
    {
        let conn = st.db.lock();
        let _ = conn.execute("DELETE FROM user_mfa WHERE user=?1", params![au.name]);
        ledger_append(&conn, "mfa", &format!("MFA TOTP désactivée pour '{}'", au.name));
    }
    Json(json!({ "ok": true })).into_response()
}

/// Un code de secours (clair) figure-t-il dans la liste des SHA-256 persistés ? (comparaison des hash.)
fn recovery_contains(recovery_json: &str, code: &str) -> bool {
    let want = sha256_hex(code.as_bytes());
    serde_json::from_str::<Vec<String>>(recovery_json)
        .map(|v| v.iter().any(|h| ct_eq(h.as_bytes(), want.as_bytes())))
        .unwrap_or(false)
}

/// Consomme (usage unique) un code de secours : le retire de la liste persistée s'il matche. True si consommé.
fn recovery_consume(st: &AppState, user: &str, code: &str) -> bool {
    let want = sha256_hex(code.as_bytes());
    let conn = st.db.lock();
    let Ok(rec): rusqlite::Result<String> = conn.query_row("SELECT recovery FROM user_mfa WHERE user=?1", params![user], |r| r.get(0)) else {
        return false;
    };
    let mut list: Vec<String> = serde_json::from_str(&rec).unwrap_or_default();
    let before = list.len();
    list.retain(|h| !ct_eq(h.as_bytes(), want.as_bytes()));
    if list.len() == before {
        return false; // aucun code consommé
    }
    let _ = conn.execute("UPDATE user_mfa SET recovery=?1, updated=?2 WHERE user=?3", params![json!(list).to_string(), now(), user]);
    true
}

/// POST /api/login/mfa {ticket, code} — 2e facteur du login local : consomme le ticket signé émis par
/// `login_post`, vérifie le TOTP (ou un code de secours à usage unique), pose la session. PUBLIC. Fail-closed.
pub(crate) async fn login_mfa_post(State(st): State<AppState>, ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>, Json(b): Json<Value>) -> Response {
    let ticket = b.trimmed("ticket");
    let code = b.trimmed("code");
    let ip = peer.ip().to_string();
    let Some((user, role)) = mfa_ticket_verify(st.session_secret.as_slice(), &ticket) else {
        return err_json(StatusCode::UNAUTHORIZED, "ticket MFA invalide ou expiré (recommencez la connexion)");
    };
    if let Some(retry) = auth_lock_check(&st, &user, &ip) {
        return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, retry.to_string())], Json(json!({ "error": "trop d'échecs — réessayez plus tard" }))).into_response();
    }
    // Rôle re-résolu LIVE (le ticket n'est qu'un plancher : un changement de rôle entre les 2 facteurs est pris en compte).
    let live_role = live_role_for(&st, &user).unwrap_or(role);
    let row: Option<(String, i64)> = {
        let conn = st.db.lock();
        conn.query_row("SELECT secret,last_step FROM user_mfa WHERE user=?1 AND enabled=1", params![user], |r| Ok((r.get(0)?, r.get(1)?))).ok()
    };
    let Some((secret, last_step)) = row else {
        return err_json(StatusCode::UNAUTHORIZED, "aucune MFA active pour ce compte");
    };
    // ANTI-REJEU TOTP : un pas matché est « frais » seulement s'il est > last_step (un code capté et rejoué
    // dans sa fenêtre de ~90 s a un pas <= last_step -> refusé). Un code déjà consommé n'est PAS traité comme
    // un code de secours (matched.is_some()) -> pas de repli recovery sur un TOTP rejoué.
    let matched = totp_verify_step(&secret, &code, now(), 30, 6, 1);
    let totp_fresh = matched.map_or(false, |s| s > last_step);
    let rec_ok = matched.is_none() && !code.is_empty() && recovery_consume(&st, &user, &code);
    if !totp_fresh && !rec_ok {
        let _ = auth_record_failure(&st, &user, &ip);
        return err_json(StatusCode::UNAUTHORIZED, "code MFA invalide");
    }
    if let Some(step) = matched.filter(|_| totp_fresh) {
        // consomme le pas TOTP (anti-rejeu) AVANT de poser la session.
        let conn = st.db.lock();
        let _ = conn.execute("UPDATE user_mfa SET last_step=?1, updated=?2 WHERE user=?3", params![step, now(), user]);
    }
    auth_record_success(&st, &user, &ip);
    {
        let conn = st.db.lock();
        ledger_append(&conn, "login", &format!("login local MFA validé pour '{user}'{}", if rec_ok { " (code de secours)" } else { "" }));
    }
    let mut resp = Json(json!({ "ok": true, "user": user, "role": live_role })).into_response();
    attach_session_cookies(&st, &mut resp, &user, &live_role);
    resp
}

/// Émet un ticket MFA (2e facteur en attente) — appelé par `login_post` (session.rs) quand le 1er facteur
/// réussit et que le compte a une MFA active. TTL court (5 min).
pub(crate) fn mfa_challenge_response(st: &AppState, user: &str, role: &str) -> Response {
    let ticket = mfa_ticket_sign(st.session_secret.as_slice(), user, role, 300);
    Json(json!({ "mfa_required": true, "ticket": ticket })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mfa_ticket_roundtrip_and_tamper() {
        let s = b"ticket-secret";
        let t = mfa_ticket_sign(s, "bob", "editor", 300);
        assert_eq!(mfa_ticket_verify(s, &t), Some(("bob".into(), "editor".into())));
        assert!(mfa_ticket_verify(b"autre", &t).is_none());
        // ticket déjà expiré forgé à la main (sign clampe le TTL >= 1s) -> rejeté.
        let past = now() - 100;
        let payload = format!("mfa|bob|editor|{past}");
        let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let expired = format!("{p_b64}.{}", hex_encode(&hmac_sha256(s, p_b64.as_bytes())));
        assert!(mfa_ticket_verify(s, &expired).is_none());
        // un ticket de session (préfixe différent) ne doit pas passer pour un ticket MFA.
        let sess = mint_session(s, "bob", "editor", 300, 0);
        assert!(mfa_ticket_verify(s, &sess).is_none());
    }

    #[test]
    fn recovery_contains_matches_hash_only() {
        let (clear, hashes) = gen_recovery_codes(3).unwrap();
        let rec = json!(hashes).to_string();
        assert!(recovery_contains(&rec, &clear[0]));
        assert!(!recovery_contains(&rec, "0000-0000"));
        // la liste persistée ne contient QUE des hash (jamais le clair).
        assert!(!rec.contains(&clear[0]));
    }

    #[test]
    fn idp_name_validation() {
        assert!(idp_name_ok("google"));
        assert!(idp_name_ok("azure-ad.corp_1"));
        assert!(!idp_name_ok(""));
        assert!(!idp_name_ok("bad/slash"));
        assert!(!idp_name_ok("space bar"));
    }
}
