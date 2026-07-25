use super::*;

// ===================== entropie / encodages =====================

/// N octets CSPRNG (/dev/urandom). None si l'entropie noyau est indisponible -> l'appelant ÉCHOUE
/// (jamais de state/nonce/verifier/secret faible ou prévisible). Même source que le mint de jetons.
pub(crate) fn rand_bytes(n: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut b = vec![0u8; n];
    std::fs::File::open("/dev/urandom").ok()?.read_exact(&mut b).ok()?;
    Some(b)
}

/// Jeton aléatoire base64url-sans-padding (state / nonce / code_verifier PKCE). 32 octets -> 43 caractères
/// (>= le plancher RFC 7636 de 43 pour un verifier). None si entropie indisponible.
pub(crate) fn rand_url_token() -> Option<String> {
    rand_bytes(32).map(|b| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))
}

// ===================== PKCE (RFC 7636) =====================

/// Challenge PKCE `S256` : base64url(SHA-256(verifier)). Le serveur d'autorisation le compare au verifier
/// renvoyé à l'échange -> une interception du code sans le verifier est inexploitable.
pub(crate) fn pkce_challenge_s256(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
}

// ===================== state signé (login OIDC en cours) =====================

/// Blob de state de login OIDC : `provider|state|nonce|verifier|exp`, signé HMAC-SHA256 (session_secret).
/// Stateless (aucun stockage serveur) — posé en cookie court (`plume_oidc`) à `oidc_start`, vérifié au
/// callback. Format : `<b64url(payload)>.<hex(hmac)>`. Miroir EXACT de `mint_session`.
pub(crate) fn oidc_state_sign(secret: &[u8], provider: &str, state: &str, nonce: &str, verifier: &str, ttl_s: i64) -> String {
    let exp = now() + ttl_s.max(1);
    // provider/state/nonce/verifier sont tous alnum/base64url (aucun '|') -> séparateur non ambigu.
    let payload = format!("{provider}|{state}|{nonce}|{verifier}|{exp}");
    let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let sig = hmac_sha256(secret, p_b64.as_bytes());
    format!("{p_b64}.{}", hex_encode(&sig))
}

/// Vérifie + décode un blob de state OIDC : HMAC valide (temps constant) + non expiré. Retourne
/// (provider, state, nonce, verifier). None = signature invalide / expiré / malformé -> le callback REFUSE.
pub(crate) fn oidc_state_verify(secret: &[u8], blob: &str) -> Option<(String, String, String, String)> {
    let (p_b64, sig_hex) = blob.split_once('.')?;
    let expect = hmac_sha256(secret, p_b64.as_bytes());
    let got = hex_decode(sig_hex)?;
    if !ct_eq(&got, &expect) {
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p_b64).ok()?;
    let s = String::from_utf8(raw).ok()?;
    let mut it = s.split('|');
    let provider = it.next()?.to_string();
    let state = it.next()?.to_string();
    let nonce = it.next()?.to_string();
    let verifier = it.next()?.to_string();
    let exp: i64 = it.next()?.parse().ok()?;
    if now() >= exp {
        return None;
    }
    Some((provider, state, nonce, verifier))
}

// ===================== config OIDC =====================

/// Config OIDC décodée depuis `idp_provider.config_json` (paramètres NON-secrets). Le `client_secret` est
/// dans la colonne dédiée `idp_provider.secret`, jamais ici.
#[derive(Debug, Clone, Default)]
pub(crate) struct OidcCfg {
    pub(crate) issuer: String,        // ex https://accounts.google.com — sert de préfixe discovery ET d'`iss` attendu
    pub(crate) client_id: String,
    pub(crate) redirect_uri: String,  // URL de callback EXACTE (allowlistée : re-servie telle quelle -> anti open-redirect)
    pub(crate) scopes: String,        // défaut "openid profile email groups"
    pub(crate) group_claim: String,   // claim portant les groupes (défaut "groups")
    pub(crate) require_group_match: bool, // fail-closed : un user ne matchant AUCUN groupe connu -> DENY (défaut true)
    // endpoints explicites (optionnels) — si vides, résolus par discovery `.well-known/openid-configuration`.
    pub(crate) authorization_endpoint: String,
    pub(crate) token_endpoint: String,
    pub(crate) jwks_uri: String,
}

impl OidcCfg {
    pub(crate) fn from_json(v: &Value) -> OidcCfg {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let scopes = { let x = s("scopes"); if x.is_empty() { "openid profile email groups".to_string() } else { x } };
        let group_claim = { let x = s("group_claim"); if x.is_empty() { "groups".to_string() } else { x } };
        OidcCfg {
            issuer: s("issuer").trim_end_matches('/').to_string(),
            client_id: s("client_id"),
            redirect_uri: s("redirect_uri"),
            scopes,
            group_claim,
            // require_group_match : true SAUF si explicitement mis à false (fail-closed par défaut).
            require_group_match: v.get("require_group_match").and_then(|x| x.as_bool()).unwrap_or(true),
            authorization_endpoint: s("authorization_endpoint"),
            token_endpoint: s("token_endpoint"),
            jwks_uri: s("jwks_uri"),
        }
    }
    /// URL de discovery OIDC (issuer sans slash final + suffixe standard).
    pub(crate) fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.issuer)
    }
    /// Config minimale présente ? (fail-closed : refuse tôt une config incomplète.)
    pub(crate) fn is_usable(&self) -> bool {
        !self.issuer.is_empty() && !self.client_id.is_empty() && !self.redirect_uri.is_empty()
    }
}

/// Endpoints résolus (discovery OU overrides explicites). `iss` = l'issuer de la config (ce qu'on EXIGERA
/// dans l'id_token), JAMAIS un champ arbitraire renvoyé par un tiers.
#[derive(Debug, Clone, Default)]
pub(crate) struct OidcEndpoints {
    pub(crate) authorization_endpoint: String,
    pub(crate) token_endpoint: String,
    pub(crate) jwks_uri: String,
}

/// Résout les endpoints : parse un document de discovery (JSON) et applique les overrides explicites de la
/// config (priorité à l'override). PUR (le fetch réseau est injecté par l'appelant). Fail-closed si un
/// endpoint requis manque.
pub(crate) fn oidc_resolve_endpoints(cfg: &OidcCfg, discovery: Option<&Value>) -> Result<OidcEndpoints, String> {
    let disc = |k: &str| discovery.and_then(|d| d.get(k)).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let pick = |ov: &str, k: &str| if !ov.is_empty() { ov.to_string() } else { disc(k) };
    let ep = OidcEndpoints {
        authorization_endpoint: pick(&cfg.authorization_endpoint, "authorization_endpoint"),
        token_endpoint: pick(&cfg.token_endpoint, "token_endpoint"),
        jwks_uri: pick(&cfg.jwks_uri, "jwks_uri"),
    };
    if ep.authorization_endpoint.is_empty() || ep.token_endpoint.is_empty() || ep.jwks_uri.is_empty() {
        return Err("endpoints OIDC incomplets (discovery indisponible et pas d'override)".into());
    }
    // Anti-SSRF minimal : les endpoints DOIVENT être https (le token/JWKS transitent le secret/la clé).
    for u in [&ep.authorization_endpoint, &ep.token_endpoint, &ep.jwks_uri] {
        if !u.starts_with("https://") {
            return Err("endpoint OIDC non-https refusé".into());
        }
    }
    Ok(ep)
}

/// URL d'autorisation complète (redirection navigateur) : response_type=code + PKCE S256 + state + nonce +
/// scope. Tous les paramètres user-influençables sont percent-encodés.
pub(crate) fn oidc_authorize_url(cfg: &OidcCfg, ep: &OidcEndpoints, state: &str, nonce: &str, challenge: &str) -> String {
    let sep = if ep.authorization_endpoint.contains('?') { '&' } else { '?' };
    format!(
        "{}{sep}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        ep.authorization_endpoint,
        url_encode(&cfg.client_id),
        url_encode(&cfg.redirect_uri),
        url_encode(&cfg.scopes),
        url_encode(state),
        url_encode(nonce),
        url_encode(challenge),
    )
}

/// Corps form-urlencoded de l'échange de code (Authorization-Code + PKCE). Le `client_secret` ne transite
/// QUE dans ce corps POST (mémoire, jamais loggé). code_verifier prouve la possession (PKCE).
pub(crate) fn oidc_token_body(cfg: &OidcCfg, code: &str, verifier: &str, client_secret: &str) -> String {
    let mut body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        url_encode(code), url_encode(&cfg.redirect_uri), url_encode(&cfg.client_id), url_encode(verifier),
    );
    if !client_secret.is_empty() {
        body.push_str(&format!("&client_secret={}", url_encode(client_secret)));
    }
    body
}

// ===================== validation JWT id_token =====================

/// Valide un id_token OIDC (signature RS256/ES256 via JWKS + iss/aud/exp/nonce). Retourne les claims
/// (JSON) sur succès. FAIL-CLOSED : toute anomalie -> Err (jamais de claims « best-effort »).
///  - la clé est choisie dans le JWKS par `kid` (header) ; l'algo est RESTREINT à l'asymétrique (RS*/ES*)
///    -> pas de confusion d'algorithme (HS256 forgé avec la clé publique) ;
///  - iss DOIT == l'issuer CONFIGURÉ (pas un champ arbitraire), aud DOIT contenir client_id, exp valide
///    (leeway 60 s), nonce DOIT == le nonce du state (anti-rejeu).
pub(crate) fn oidc_validate_id_token(
    id_token: &str,
    jwks: &Value,
    issuer: &str,
    client_id: &str,
    nonce: &str,
) -> Result<Value, String> {
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
    let header = decode_header(id_token).map_err(|e| format!("en-tête JWT invalide: {e}"))?;
    // Algo RESTREINT à l'asymétrique (anti alg-confusion). HS*/none -> refus immédiat.
    if !matches!(header.alg, Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 | Algorithm::ES256 | Algorithm::ES384) {
        return Err(format!("algorithme JWT non autorisé: {:?}", header.alg));
    }
    let keys = jwks.get("keys").and_then(|k| k.as_array()).ok_or("JWKS sans 'keys'")?;
    let want_kid = header.kid.as_deref();
    // Si le token porte un kid, on EXIGE la clé correspondante ; sinon (kid absent) on essaie chaque clé.
    let jwk = keys
        .iter()
        .find(|k| match want_kid {
            Some(w) => k.get("kid").and_then(|v| v.as_str()) == Some(w),
            None => true,
        })
        .ok_or("aucune clé JWKS ne correspond au kid du token")?;
    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
    let key = match kty {
        "RSA" => {
            let n = jwk.get("n").and_then(|v| v.as_str()).ok_or("JWK RSA sans 'n'")?;
            let e = jwk.get("e").and_then(|v| v.as_str()).ok_or("JWK RSA sans 'e'")?;
            DecodingKey::from_rsa_components(n, e).map_err(|e| format!("clé RSA JWK invalide: {e}"))?
        }
        "EC" => {
            let x = jwk.get("x").and_then(|v| v.as_str()).ok_or("JWK EC sans 'x'")?;
            let y = jwk.get("y").and_then(|v| v.as_str()).ok_or("JWK EC sans 'y'")?;
            DecodingKey::from_ec_components(x, y).map_err(|e| format!("clé EC JWK invalide: {e}"))?
        }
        other => return Err(format!("type de clé JWK non supporté: {other}")),
    };
    let mut v = Validation::new(header.alg);
    v.set_issuer(&[issuer]);
    v.set_audience(&[client_id]);
    v.set_required_spec_claims(&["exp", "iss", "aud"]);
    // validate_exp=true + leeway 60 s par défaut (dérive d'horloge tolérée, bornée).
    let data = decode::<Value>(id_token, &key, &v).map_err(|e| format!("validation JWT échouée: {e}"))?;
    let claims = data.claims;
    // NONCE (claim non-registered) : vérifié À LA MAIN, temps constant. Anti-rejeu / anti-injection de token.
    let got_nonce = claims.get("nonce").and_then(|x| x.as_str()).unwrap_or("");
    if nonce.is_empty() || !ct_eq(got_nonce.as_bytes(), nonce.as_bytes()) {
        return Err("nonce du id_token absent ou ne correspond pas".into());
    }
    Ok(claims)
}

/// Nom d'utilisateur canonique depuis les claims : preferred_username -> email -> sub. Le nom retenu est
/// contraint (voir provisioning) ; ici on choisit la source la plus lisible disponible.
pub(crate) fn oidc_username(claims: &Value) -> String {
    for k in ["preferred_username", "email", "sub"] {
        if let Some(s) = claims.get(k).and_then(|v| v.as_str()) {
            let s = s.trim();
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    String::new()
}

/// Extrait les groupes du claim configuré et les NORMALISE en chaîne `a|b|c` — le format EXACT attendu par
/// `sso_role`/`sso_grants` (réutilisation stricte de la sémantique groupe->rôle du SSO trusted-header). Le
/// claim peut être un tableau de chaînes OU une chaîne (séparée par ' '/','/'|').
pub(crate) fn oidc_groups_str(claims: &Value, group_claim: &str) -> String {
    match claims.get(group_claim) {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join("|"),
        Some(Value::String(s)) => s.split(|c| c == ' ' || c == ',' || c == '|')
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
            .join("|"),
        _ => String::new(),
    }
}

/// Un des groupes matche-t-il un groupe PLUME connu (admin/editor/viewer/superadmin configurés) ? Sert la
/// politique fail-closed `require_group_match` : aucun groupe connu -> DENY (pas de rôle viewer par défaut).
pub(crate) fn sso_any_group_match(st: &AppState, groups: &str) -> bool {
    let known = [
        st.sso_group_admin.as_str(),
        st.sso_group_editor.as_str(),
        st.sso_group_superadmin.as_str(),
        "plume-admin",
        "plume-editor",
        "plume-viewer",
        "plume-superadmin",
    ];
    groups.split(|c| c == '|' || c == ',').map(|g| g.trim()).any(|g| !g.is_empty() && known.contains(&g))
}

/// Mapping FINAL groupes->rôle pour un login OIDC en MODE 0 (réutilise `sso_role`, la table exacte du SSO
/// header). `require_group_match` : si vrai et qu'AUCUN groupe connu ne matche -> None (DENY, fail-closed) ;
/// sinon rôle `sso_role` (viewer par défaut, cohérent avec le chemin Authentik).
pub(crate) fn oidc_role_mode0(st: &AppState, groups: &str, require_group_match: bool) -> Option<String> {
    if require_group_match && !sso_any_group_match(st, groups) {
        return None;
    }
    Some(sso_role(st, groups))
}

// ===================== provisioning JIT d'un compte fédéré (mode 0) =====================

/// Sentinel de hash pour un compte provisionné par un IdP fédéré (OIDC/LDAP) : PAS un hash valide ->
/// `verify_pw(_, HASH)` renvoie TOUJOURS false -> impossible de se connecter en Basic à ce compte (l'auth
/// se fait UNIQUEMENT via l'IdP). Reconnaissable pour distinguer un compte fédéré d'un compte local.
pub(crate) const IDP_HASH_SENTINEL: &str = "!external-idp";

/// PROVISIONING JIT (mode 0) d'un compte fédéré dans la table `user`, pour que la ré-résolution LIVE du
/// rôle par cookie (`live_role_for`/`lookup_basic_ident`) fonctionne sur les requêtes suivantes.
///  - RÉSERVATION ADMIN BOOTSTRAP : `reserved_static_admin` = le compte admin de CONFIG (PLUME_USER +
///    PLUME_PASS_HASH) — il n'est JAMAIS dans la table `user` (repli de `authenticate()`), donc la garde de
///    collision ci-dessous ne le voit pas. Sans cette réservation, un login fédéré nommé "admin" créerait
///    `user(name='admin', hash=sentinel)` qui deviendrait AUTORITAIRE -> lockout silencieux du vrai admin
///    statique (ou hijack si l'IdP le mappe admin). On REFUSE donc de fédérer sur ce nom réservé (fail-closed).
///  - COLLISION : si un compte LOCAL (hash réel, ni vide ni sentinel) porte déjà ce nom -> Err (on REFUSE
///    de fédérer sur un nom déjà pris par un compte à mot de passe : un utilisateur IdP ne peut PAS
///    détourner ni piloter le rôle d'un compte local — fail-closed anti-usurpation) ;
///  - sinon UPSERT (nom, hash=sentinel, rôle mappé) : à chaque login le rôle est resynchronisé depuis l'IdP.
/// Retourne Ok(()) si le compte est utilisable pour une session. NB : le sentinel neutralise Basic.
pub(crate) fn idp_provision_user(conn: &Connection, name: &str, role: &str, reserved_static_admin: Option<&str>) -> Result<(), String> {
    if let Some(reserved) = reserved_static_admin {
        if name == reserved {
            return Err("ce nom d'utilisateur est réservé au compte administrateur de configuration (fédération refusée)".into());
        }
    }
    let existing: Option<String> = conn
        .query_row("SELECT hash FROM user WHERE name=?1", params![name], |r| r.get::<_, String>(0))
        .ok();
    if let Some(h) = existing.as_deref() {
        if !h.is_empty() && h != IDP_HASH_SENTINEL {
            return Err("le nom d'utilisateur correspond à un compte local existant (fédération refusée)".into());
        }
    }
    conn.execute(
        "INSERT INTO user(name,hash,role) VALUES(?1,?2,?3) \
         ON CONFLICT(name) DO UPDATE SET role=excluded.role",
        params![name, IDP_HASH_SENTINEL, role],
    )
    .map_err(|e| format!("provisioning du compte fédéré échoué: {e}"))?;
    Ok(())
}
