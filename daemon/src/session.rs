//! Sessions form-login (cookie HMAC) & endpoints d'identité : émission/vérif du jeton signé
//! (`mint_session`/`verify_session`) mêlé à l'epoch de révocation (`load_session_epoch`/`bump_session_epoch`),
//! rôle live (`live_role_for`), CSRF (`csrf_for`), cookies (`cookie_value`/`cookie_secure_suffix`), secret de
//! session (`load_session_secret`), hash/pose du mot de passe admin (`hash_pw`/`set_admin`) et les handlers
//! `setup_status`/`setup_post`/`password_post`/`login_post`/`logout_post`/`me`. Extrait de main.rs
//! (refactor split #25 — byte-identique).
use crate::*;

/// Forge un jeton de session signé : payload = `user|role|exp` (b64url), signé HMAC-SHA256.
/// Format : `<b64url(payload)>.<hex(hmac)>`. exp = now + ttl. Stateless (vérifié par HMAC).
/// L2 (RÉVOCATION) : l'`epoch` de session est MÉLANGÉ à la matière signée -> un bump d'epoch (logout /
/// changement de mdp) invalide TOUS les jetons antérieurs (leur signature recalculée avec le nouvel epoch
/// ne correspond plus). L'epoch n'est PAS exposé dans le payload lisible : la vérif le re-injecte côté
/// serveur (source de vérité = AppState.session_epoch), donc il n'est ni forgeable ni rejouable.
pub(crate) fn mint_session(secret: &[u8], user: &str, role: &str, ttl_s: i64, epoch: i64) -> String {
    let exp = now() + ttl_s.max(1);
    let payload = format!("{user}|{role}|{exp}");
    let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let sig = hmac_sha256(secret, format!("{p_b64}|{epoch}").as_bytes());
    format!("{p_b64}.{}", hex_encode(&sig))
}

/// Vérifie un jeton de session : HMAC valide (temps constant, LIÉ à l'epoch courant) + non expiré ->
/// Some((user, role)). L2 : `epoch` = compteur de révocation LIVE ; un jeton signé avec un epoch antérieur
/// échoue à la comparaison de signature -> None (révocation serveur). Le TTL est conservé (double borne).
pub(crate) fn verify_session(secret: &[u8], token: &str, epoch: i64) -> Option<(String, String)> {
    let (p_b64, sig_hex) = token.split_once('.')?;
    let expect = hmac_sha256(secret, format!("{p_b64}|{epoch}").as_bytes());
    let got = hex_decode(sig_hex)?;
    if !ct_eq(&got, &expect) {
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p_b64).ok()?;
    let s = String::from_utf8(raw).ok()?;
    // payload = user|role|exp ; user peut contenir '|' -> on découpe par la DROITE (exp, role, reste).
    let mut it = s.rsplitn(3, '|');
    let exp: i64 = it.next()?.parse().ok()?;
    let role = it.next()?.to_string();
    let user = it.next()?.to_string();
    if now() >= exp {
        return None;
    }
    Some((user, role))
}

/// L2 (RE-CHECK LIVE DU RÔLE, mode 0) — rôle COURANT d'un utilisateur authentifié par COOKIE, RE-RÉSOLU à
/// chaque requête depuis la source de vérité (table `user` -> admin du wizard -> compte config statique),
/// AU LIEU du rôle FIGÉ dans le cookie. `None` = l'utilisateur N'EXISTE PLUS (compte supprimé) -> le cookie
/// est refusé (401). MÊME ordre de résolution que `authenticate`, SANS vérif de mot de passe (le HMAC du
/// cookie a DÉJÀ prouvé l'identité). Effet : un editor rétrogradé viewer / supprimé perd ses droits AVANT
/// l'expiration du TTL (12h). Mode 1 : NON appelé (le rôle PER-TENANT est déjà relu LIVE via les grants).
pub(crate) fn live_role_for(st: &AppState, user: &str) -> Option<String> {
    // 1) compte applicatif (table `user`) — fait autorité, comme dans authenticate().
    //    #23 F4 — la session cookie est DÉJÀ prouvée par HMAC : ce chemin n'a besoin QUE du RÔLE, jamais du
    //    hash. On le lit donc `SELECT role FROM user WHERE name=?` via le READ POOL (WAL, hors mutex WRITER),
    //    au lieu de lookup_basic_ident (qui SELECTe `hash` et prend le writer -> chaque requête UI cookie se
    //    sérialisait contre l'ingest). `role` n'est PAS une colonne DÉNIÉE par l'authorizer read-pool (seuls
    //    user.hash/token.token_hash le sont) et reste servie FRAÎCHE (snapshot WAL committé) -> la révocation/
    //    rétrogradation LIVE est préservée à l'identique (rôle relu à CHAQUE requête, juste sur une autre
    //    connexion). N'AFFECTE QUE le mode 0 hors eng-cred : les eng-creds (fenêtre horaire d'engagement,
    //    JAMAIS mis en cache) RESTENT sur lookup_basic_ident (writer) -> leur sémantique de fenêtre est
    //    inchangée ; le Basic-auth (qui a réellement besoin du hash) n'est PAS touché non plus. Une panne de
    //    connexion du pool (rare) retombe sur lookup_basic_ident (writer) -> aucun refus de rôle à tort.
    if !st.multi_tenant && !user.starts_with(ENG_CRED_PREFIX) {
        match role_only_via_read_pool(st, user) {
            RolePoolLookup::Found(role) => return Some(role),
            RolePoolLookup::Absent => {} // absent de `user` -> repli admin-wizard / config statique (idem historique).
            RolePoolLookup::PoolUnavailable => {
                // pool indisponible : on reproduit EXACTEMENT le chemin d'origine (writer) pour ne rien changer.
                if let Some((_, role)) = lookup_basic_ident(st, user) {
                    return Some(role);
                }
            }
        }
    } else if let Some((_, role)) = lookup_basic_ident(st, user) {
        return Some(role);
    }
    // 2) admin défini par le wizard (meta) -> admin.
    if let Some((au, _)) = st.admin.lock().clone() {
        if user == au {
            return Some("admin".to_string());
        }
    }
    // 3) compte config statique (bootstrap) -> admin.
    if !st.pass_hash.is_empty() && user == st.user.as_str() {
        return Some("admin".to_string());
    }
    None
}

/// #23 F4 — résultat TRI-ÉTAT d'une résolution de rôle par le READ POOL : distingue « trouvé » de « absent »
/// (compte disparu -> le cookie ne vaut plus rien) de « pool indisponible » (repli writer, jamais un refus à tort).
enum RolePoolLookup {
    Found(String),
    Absent,
    PoolUnavailable,
}

/// #23 F4 — lit `SELECT role FROM user WHERE name=?` sur le READ POOL (mode 0). `role` n'est pas une colonne
/// déniée par l'authorizer read-pool ; le SELECT est index-couvert (PK `name`? -> `user` est minuscule de
/// toute façon) et sert un snapshot WAL FRAIS (révocation live préservée). Aucune prise du mutex writer.
fn role_only_via_read_pool(st: &AppState, user: &str) -> RolePoolLookup {
    read_with(st.db_path.as_str(), RolePoolLookup::PoolUnavailable, |conn| {
        match conn.query_row("SELECT role FROM user WHERE name=?1", params![user], |r| r.get::<_, String>(0)) {
            Ok(role) => RolePoolLookup::Found(role),
            Err(rusqlite::Error::QueryReturnedNoRows) => RolePoolLookup::Absent,
            // erreur inattendue (verrou, corruption transitoire...) -> repli writer plutôt qu'un faux « absent ».
            Err(_) => RolePoolLookup::PoolUnavailable,
        }
    })
}

/// L2 — lit le compteur de révocation de session persistant (meta `session_epoch`, défaut 0). Chargé au
/// boot dans AppState.session_epoch (source de vérité mémoire consultée par mint/verify_session).
pub(crate) fn load_session_epoch(conn: &Connection) -> i64 {
    conn.query_row("SELECT value FROM meta WHERE key='session_epoch'", [], |r| r.get::<_, String>(0))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// L2 — INCRÉMENTE l'epoch de session (révocation serveur) : met à jour le compteur EN MÉMOIRE (effet
/// IMMÉDIAT sur mint/verify) ET le persiste dans meta (survit au redémarrage). Appelé par /api/logout et
/// par tout changement de mot de passe -> tous les jetons antérieurs deviennent invalides.
pub(crate) fn bump_session_epoch(st: &AppState) {
    let e = st.session_epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    let c = st.db.lock();
    let _ = c.execute(
        "INSERT INTO meta(key,value) VALUES('session_epoch',?1) ON CONFLICT(key) DO UPDATE SET value=?1",
        params![e.to_string()],
    );
}

/// Token CSRF DÉRIVÉ du jeton de session (stateless) : le serveur le recalcule à chaque requête à
/// partir du cookie de session -> aucun stockage. Le SPA le renvoie en header `X-CSRF-Token`.
pub(crate) fn csrf_for(secret: &[u8], session_token: &str) -> String {
    hex_encode(&hmac_sha256(secret, format!("csrf|{session_token}").as_bytes()))
}

/// Extrait la valeur d'un cookie nommé depuis un en-tête `Cookie:` (None si absent).
pub(crate) fn cookie_value(header: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    header.split(';').map(|p| p.trim()).find_map(|p| p.strip_prefix(&prefix).map(|v| v.to_string()))
}

/// Attribut `Secure` des cookies UNIQUEMENT quand le TLS natif est actif (sinon le cookie ne serait
/// jamais émis en HTTP — k3s derrière Traefik termine le TLS au proxy, l'origine est en clair).
pub(crate) fn cookie_secure_suffix() -> &'static str {
    if TLS_ON.load(std::sync::atomic::Ordering::Relaxed) {
        "; Secure"
    } else {
        ""
    }
}

/// Secret de signature des sessions : env/conf PLUME_SESSION_SECRET (matière à clé brute) -> sinon
/// clé persistée 0600 (générée au 1er boot, comme la clé du ledger). JAMAIS de secret en dur.
pub(crate) fn load_session_secret(conf: &HashMap<String, String>) -> Vec<u8> {
    let env_secret = cfg(conf, "PLUME_SESSION_SECRET", "");
    if !env_secret.trim().is_empty() {
        return env_secret.trim().as_bytes().to_vec();
    }
    use std::os::unix::fs::PermissionsExt;
    let path = cfg(conf, "PLUME_SESSION_KEY", "/var/lib/plume/db/session.key");
    if let Ok(hex) = std::fs::read_to_string(&path) {
        if let Some(b) = hex_decode(hex.trim()) {
            if b.len() >= 32 {
                return b;
            }
        }
    }
    use std::io::Read;
    let mut b = [0u8; 32];
    if std::fs::File::open("/dev/urandom").ok().and_then(|mut f| f.read_exact(&mut b).ok()).is_some() {
        let _ = std::fs::write(&path, hex_encode(&b));
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        return b.to_vec();
    }
    // dernier recours (jamais attendu sous Linux) : dérive non vide -> les sessions restent signées.
    sha256_hex(format!("plume-session-fallback-{}", now()).as_bytes()).into_bytes()
}

// ---------- wizard / admin (auth modifiable depuis l'UI) ----------
pub(crate) fn hash_pw(pw: &str) -> Option<String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut OsRng);
    argon2::Argon2::default().hash_password(pw.as_bytes(), &salt).ok().map(|h| h.to_string())
}

pub(crate) fn set_admin(st: &AppState, user: &str, hash: &str) {
    {
        let c = st.db.lock();
        let _ = c.execute("INSERT INTO meta(key,value) VALUES('admin_user',?1) ON CONFLICT(key) DO UPDATE SET value=?1", params![user]);
        // ANTI-FUITE PAR EXPORT — on NE STOCKE PLUS le hash admin en CLAIR dans meta : il y était
        // exfiltrable via /api/export ou /api/query en SQL brut admin (`SELECT value FROM meta WHERE
        // key='admin_hash'`), l'authorizer read-pool ne pouvant pas filtrer meta PAR CLÉ (déni de meta.value
        // casserait schema_version/plume_mode). La SOURCE DE VÉRITÉ du hash = user.hash (déjà DÉNIÉ par
        // l'authorizer, écrit juste dessous). On purge toute copie héritée (bases pré-fix) — idempotent.
        let _ = c.execute("DELETE FROM meta WHERE key='admin_hash'", []);
        // l'admin est aussi un compte de la table user (rôle admin)
        let _ = c.execute(
            "INSERT INTO user(name,hash,role) VALUES(?1,?2,'admin') ON CONFLICT(name) DO UPDATE SET hash=?2, role='admin'",
            params![user, hash],
        );
    }
    *st.admin.lock() = Some((user.to_string(), hash.to_string()));
    st.auth_cache.lock().clear(); // invalide les creds en cache (l'ancien défaut ne marche plus)
}

pub(crate) async fn setup_status(State(st): State<AppState>) -> Json<Value> {
    let configured = st.admin.lock().is_some() || !st.pass_hash.is_empty();
    Json(json!({ "configured": configured }))
}

pub(crate) async fn setup_post(State(st): State<AppState>, Json(b): Json<Value>) -> Response {
    if st.admin.lock().is_some() || !st.pass_hash.is_empty() {
        return err_json(StatusCode::CONFLICT, "déjà configuré (utilise Réglages > changer le mot de passe)");
    }
    let token = b.str_field("token");
    if st.setup_token.is_empty() || token != st.setup_token.as_str() {
        return forbidden("token d'installation invalide (voir le log du daemon ou /var/lib/plume/db/setup-token.txt)");
    }
    let user = b.trimmed("user");
    let pw = b.str_field("password");
    // POLITIQUE MDP ≥ 12 (item 3) — n'affecte QUE la DÉFINITION ; les mdp existants continuent de marcher.
    if user.is_empty() || pw.chars().count() < 12 {
        return bad_req("utilisateur requis + mot de passe ≥ 12 caractères");
    }
    match hash_pw(pw) {
        Some(h) => {
            set_admin(&st, &user, &h);
            let _ = std::fs::remove_file(std::path::Path::new(st.db_path.as_str()).with_file_name("setup-token.txt"));
            ledger_append(&st.db.lock(), "setup", &format!("admin défini : {user}"));
            (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
        }
        None => server_err("hash échoué"),
    }
}

pub(crate) async fn password_post(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    // DURCISSEMENT : ce handler écrit `set_admin` (mot de passe de l'admin). SANS ce garde,
    // un editor pouvait reset le mdp admin = takeover/lockout. Le gate `rbac_gate` classe déjà /api/password
    // ADMIN ; ce re-check DOUBLE la garde (défense en profondeur : les deux doivent bloquer un non-admin).
    if let Err(r) = require_admin(&au) { return r; }
    // l'appelant est déjà authentifié (auth_guard) ; on garde le même nom d'admin
    let new = b.str_field("new");
    // POLITIQUE MDP ≥ 12 (item 3) — ne valide qu'au CHANGEMENT ; l'ancien mdp reste valide tant qu'inchangé.
    if new.chars().count() < 12 {
        return bad_req("mot de passe ≥ 12 caractères");
    }
    let user = st.admin.lock().clone().map(|(u, _)| u).unwrap_or_else(|| st.user.as_ref().clone());
    match hash_pw(new) {
        Some(h) => {
            set_admin(&st, &user, &h);
            // L2 : un changement de mot de passe INVALIDE toutes les sessions antérieures (bump d'epoch) —
            // un attaquant tenant un ancien cookie/mdp est déconnecté par le reset, pas seulement au TTL.
            bump_session_epoch(&st);
            ledger_append(&st.db.lock(), "password", "mot de passe admin changé");
            (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
        }
        None => server_err("hash échoué"),
    }
}

// ---------- form-login : /api/login, /api/logout, /api/me (cookie de session signé + CSRF) ----------
// POST /api/login {user,pass} -> vérifie via la MÊME résolution de compte que Basic (table user ->
// admin -> config) puis pose `plume_session` (HttpOnly, SameSite=Strict, Path=/, Secure si TLS) +
// `plume_csrf` (lisible JS). Échec -> 401 + lockout brute-force Phase 3 (compteur (user,ip) + SIEM).
pub(crate) async fn login_post(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Json(b): Json<Value>,
) -> Response {
    let user = b.trimmed("user");
    let pass = b.str_field("pass").to_string();
    let ip = peer.ip().to_string();
    // Lockout AVANT toute vérif coûteuse (réutilise le compteur (user,ip) de la Phase 3, comme Basic).
    if let Some(retry) = auth_lock_check(&st, &user, &ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry.to_string())],
            Json(json!({ "error": "trop d'échecs d'authentification — réessayez plus tard" })),
        )
            .into_response();
    }
    // Réutilise EXACTEMENT la résolution de compte de Basic via un en-tête Basic synthétique -> aucun
    // chemin d'auth divergent (mêmes hash argon2/bcrypt, même priorité table/admin/config, même cache).
    let synth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
    );
    let Some((name, role)) = authenticate(&st, &synth) else {
        // ÉCHEC -> lockout brute-force existant (incrémente (user,ip) + AUTO-INGEST SIEM, 429 au seuil).
        let _ = auth_record_failure(&st, &user, &ip);
        return err_json(StatusCode::UNAUTHORIZED, "identifiants invalides");
    };
    auth_record_success(&st, &user, &ip); // réarme le compteur (comme un succès Basic)
    // MFA (#44) — 2e FACTEUR : si le compte a une MFA TOTP ACTIVE (mode 0), le 1er facteur (mot de passe)
    // NE pose PAS de session : on renvoie un ticket signé court, à échanger contre un code sur /api/login/mfa.
    // INVARIANT MODE 0 : `user_mfa` VIDE (défaut) -> `mfa_enabled_for` renvoie false -> flux STRICTEMENT
    // inchangé (aucune session tant qu'aucun compte n'a volontairement activé la MFA). Mode 1 : sauté.
    if !st.multi_tenant && mfa_enabled_for(&st, &name) {
        return mfa_challenge_response(&st, &name, &role);
    }
    // L2 : le jeton est frappé avec l'epoch de session COURANT -> il reste valide après un logout/reset
    // ANTÉRIEUR (seuls les jetons émis avant le dernier bump sont révoqués).
    let epoch = st.session_epoch.load(std::sync::atomic::Ordering::Relaxed);
    let token = mint_session(st.session_secret.as_slice(), &name, &role, st.session_ttl_s, epoch);
    let csrf = csrf_for(st.session_secret.as_slice(), &token);
    let secure = cookie_secure_suffix();
    let ttl = st.session_ttl_s.max(1);
    // plume_session : HttpOnly (invisible au JS) ; plume_csrf : lisible JS (le SPA le renvoie en header).
    let c_sess = format!("plume_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}{secure}");
    let c_csrf = format!("plume_csrf={csrf}; SameSite=Strict; Path=/; Max-Age={ttl}{secure}");
    let mut resp = (StatusCode::OK, Json(json!({ "ok": true, "user": name, "role": role }))).into_response();
    if let Ok(v) = c_sess.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    if let Ok(v) = c_csrf.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

// POST /api/logout -> efface les cookies (Set-Cookie expiré) ET révoque côté SERVEUR (L2). Public (pas
// besoin d'identité valide). L2 : incrémente l'epoch de session -> TOUS les cookies antérieurs (y compris
// un cookie EXFILTRÉ, qui survivait jusqu'ici jusqu'au TTL) deviennent immédiatement invalides côté serveur.
// GARDE ANTI-DoS (L2-fix) : le bump d'epoch (révocation GLOBALE) n'est déclenché QUE si l'appelant présente
// un cookie de session ACTUELLEMENT VALIDE. Sans cette garde, un tiers NON authentifié pourrait marteler
// /api/logout (route publique, budget per-IP standard 1200/10s) pour bumper l'epoch en boucle et déconnecter
// EN PERMANENCE tous les utilisateurs (DoS d'authentification) + amplification d'écritures DB. Le but sécu
// est préservé : un logout LÉGITIME (cookie valide) révoque bien les jetons antérieurs, y compris une COPIE
// EXFILTRÉE du même cookie. L'effacement des cookies côté navigateur, lui, reste INCONDITIONNEL.
pub(crate) async fn logout_post(State(st): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    let cookie_hdr = headers.get(header::COOKIE).and_then(|h| h.to_str().ok()).unwrap_or("");
    let epoch = st.session_epoch.load(std::sync::atomic::Ordering::Relaxed);
    let has_valid_session = cookie_value(cookie_hdr, "plume_session")
        .and_then(|tok| verify_session(st.session_secret.as_slice(), &tok, epoch))
        .is_some();
    if has_valid_session {
        bump_session_epoch(&st);
    }
    let secure = cookie_secure_suffix();
    let exp = "Max-Age=0; expires=Thu, 01 Jan 1970 00:00:00 GMT";
    let c_sess = format!("plume_session=; HttpOnly; SameSite=Strict; Path=/; {exp}{secure}");
    let c_csrf = format!("plume_csrf=; SameSite=Strict; Path=/; {exp}{secure}");
    let mut resp = (StatusCode::OK, Json(json!({ "ok": true }))).into_response();
    if let Ok(v) = c_sess.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    if let Ok(v) = c_csrf.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

// GET /api/me -> état d'auth pour le SPA : {user, role, auth_method, csrf_token}. csrf_token non vide
// UNIQUEMENT en auth par cookie (le SPA le pose en header X-CSRF-Token sur les mutations). M2M : "".
pub(crate) async fn me(Extension(au): Extension<AuthUser>) -> Json<Value> {
    Json(json!({
        "user": au.name,
        "role": au.role,            // rôle PER-TENANT (mode 1) ou rôle global (mode 0)
        "tenant": au.tenant,        // tenant courant (#2b) ; "default" en mode 0
        "is_superadmin": au.is_superadmin, // super-admin plateforme (#2b/D3) : bandeau opérateur côté SPA
        "auth_method": au.method,
        "csrf_token": au.csrf,
    }))
}
