use super::*;
use rusqlite::OptionalExtension;

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
///
/// `P10.25-t` — LES DEUX REFUS NE SONT PLUS JUGÉS ICI : ils le sont par `auth::juger_le_nom_pris_par_un_annuaire`, la
/// règle unique du chemin SSO d'en-têtes et de la fédération, sur la lecture du hachage que CETTE connexion d'écriture
/// fait (celle de l'`UPSERT` qui suit : aucune autre écriture ne s'intercale, l'appelant tient le verrou). Deux
/// différences avec la forme d'avant, décidées et mesurées (voir le bandeau de la règle) : l'administrateur de
/// l'assistant sans ligne est refusé (il était pris, et son mot de passe d'installation ne connectait plus) ; une
/// lecture du hachage qui échoue refuse (elle était avalée, et l'`UPSERT` donnait à un compte à mot de passe le rôle
/// de l'annuaire). `noms` : `NomsTenusHorsDeLaTable::de(&st)` sur tout chemin servi (`federer_le_nom`).
///
/// `P10.24-t` — TÉMOINS SEULEMENT : les trois portes servies passent par `federer_le_nom`, qui compose la même règle
/// (`juger_le_nom_a_federer`), la lecture de ce que le nom tient sans compte, puis la même écriture
/// (`poser_la_ligne_federee`). Cette forme-ci, sans la lecture neuve, reste aux témoins d'avant qui l'éprouvent.
#[cfg(test)]
pub(crate) fn idp_provision_user<'a>(
    conn: &Connection,
    name: &str,
    role: &str,
    noms: impl Into<crate::auth::NomsTenusHorsDeLaTable<'a>>,
) -> Result<(), RefusDeLaFederation> {
    juger_le_nom_a_federer(conn, name, &noms.into())?;
    poser_la_ligne_federee(conn, name, role)
}

/// `P10.25-t` — la règle unique des annuaires, sur la lecture du hachage que fait la connexion d'écriture de la
/// fédération. `P10.24-t` : extraite telle quelle de `idp_provision_user` pour que `federer_le_nom` intercale sa lecture
/// de ce que le nom tient entre la règle et l'écriture.
fn juger_le_nom_a_federer(conn: &Connection, name: &str, noms: &crate::auth::NomsTenusHorsDeLaTable<'_>) -> Result<(), RefusDeLaFederation> {
    crate::auth::juger_le_nom_pris_par_un_annuaire(name, noms, || {
        conn.query_row("SELECT hash FROM user WHERE name=?1", params![name], |r| r.get::<_, String>(0)).optional()
    })
    .map_err(RefusDeLaFederation::Nom)
}

/// L'`UPSERT` de la ligne fédérée (extrait tel quel de `idp_provision_user`, `P10.24-t`).
fn poser_la_ligne_federee(conn: &Connection, name: &str, role: &str) -> Result<(), RefusDeLaFederation> {
    conn.execute(
        "INSERT INTO user(name,hash,role) VALUES(?1,?2,?3) \
         ON CONFLICT(name) DO UPDATE SET role=excluded.role",
        params![name, IDP_HASH_SENTINEL, role],
    )
    .map_err(|e| RefusDeLaFederation::Ecriture(format!("provisioning du compte fédéré échoué: {e}")))?;
    Ok(())
}

/// `P10.24-t` — CE QUE LE NOM TIENT SANS COMPTE, LU PAR LA FÉDÉRATION COMME PAR LA CRÉATION.
///
/// LE DÉFAUT, MESURÉ LE 2026-09-25 SUR LA FORME D'AVANT (témoins `mpra_`). `zed-mpra` tient, sans ligne `user` et sans
/// avoir jamais été présenté par l'annuaire, une requête privée, un tableau de bord privé et un instantané capturé au
/// rôle `admin` — les restes d'un compte supprimé avant que la suppression n'emporte ses objets (lots 190 et 192). La
/// création d'un compte local de ce nom rend 409 (`P10.24-u`) ; sa FÉDÉRATION rendait `Ok`, posait la ligne, et le
/// compte fédéré listait la requête privée de l'ancien titulaire.
///
/// LA DÉCISION : même lecture que la création (`ce_que_le_nom_tient_sans_compte`), et REFUS NOMMÉ (409, le détail des
/// lignes) quand le nom tient des lignes sans compte ET que l'annuaire ne l'a jamais présenté par les en-têtes ; une
/// lecture ratée refuse (503). Un nom VU par l'annuaire (inventaire des accès, méthode `sso`) reste fédérable : ses
/// lignes sont celles de l'identité de l'annuaire elle-même, que les en-têtes lui servent déjà — c'est la voie que
/// `P10.24-u` a nommée. POURQUOI UN REFUS ET NON UNE PURGE OU UNE RÉATTRIBUTION : la fédération n'a pas d'auteur à qui
/// réattribuer (la suppression réattribue à l'administrateur qui supprime, `P10.24-p`), et purger à la connexion d'un
/// tiers détruirait des objets communs sans décision humaine. Le nettoyage des lignes orphelines existantes est une
/// porte à sens unique, décrite et non exécutée (clé proposée par ce lot).
///
/// CE QUI N'EST PAS TOUCHÉ, ET C'EST DÉLIBÉRÉ : le chemin d'en-têtes SSO. Une identité d'en-têtes n'a JAMAIS de ligne
/// `user` et tient ses objets par son nom — la même forme que des restes orphelins, sans colonne de provenance pour
/// les séparer ; y appliquer ce refus refuserait l'identité SSO réelle de l'exploitant dès que l'inventaire des accès
/// l'aurait oubliée (plafonné), et une identité neuve au nom d'un compte supprimé ne pourrait jamais entrer.
fn juger_ce_que_le_nom_tient_a_la_federation(conn: &Connection, name: &str) -> Result<(), RefusDeLaFederation> {
    match crate::handlers::users_lookups::ce_que_le_nom_tient_sans_compte(conn, name) {
        Ok(None) => Ok(()),
        Ok(Some(tenue)) if tenue["vu_par_l_annuaire"].as_bool() == Some(true) => Ok(()),
        Ok(Some(tenue)) => Err(RefusDeLaFederation::NomTenuSansCompte(name.to_string(), tenue)),
        Err(e) => Err(RefusDeLaFederation::TenueNonVerifiee(name.to_string(), e.to_string())),
    }
}

/// `P10.25-t` — LA FÉDÉRATION D'UN NOM, TELLE QUE LES TROIS PORTES SERVIES L'APPELLENT (OIDC, SAML, LDAP) : les noms tenus
/// hors de la table sont lus sur l'état du démon, les DEUX (configuration et assistant). `conn` est la connexion
/// d'écriture que l'appelant tient. `P10.24-t` : entre la règle et l'écriture, ce que le nom tient sans compte.
pub(crate) fn federer_le_nom(st: &AppState, conn: &Connection, name: &str, role: &str) -> Result<(), RefusDeLaFederation> {
    juger_le_nom_a_federer(conn, name, &crate::auth::NomsTenusHorsDeLaTable::de(st))?;
    juger_ce_que_le_nom_tient_a_la_federation(conn, name)?;
    poser_la_ligne_federee(conn, name, role)
}

/// `P10.25-t` — POURQUOI UNE FÉDÉRATION N'A PAS POSÉ SA LIGNE.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RefusDeLaFederation {
    /// La règle unique des annuaires refuse le nom (`auth::RefusDeLAnnuaire`).
    Nom(crate::auth::RefusDeLAnnuaire),
    /// `P10.24-t` — le nom tient des lignes sans compte et l'annuaire ne l'a jamais présenté : (nom, détail).
    NomTenuSansCompte(String, Value),
    /// `P10.24-t` — ce que le nom tient n'a pas pu être lu : (nom, cause du moteur).
    TenueNonVerifiee(String, String),
    /// L'écriture de la ligne fédérée a échoué.
    Ecriture(String),
}

/// `P10.24-t` — la fédération refusée : le nom tient des lignes sans compte, et l'annuaire ne l'a jamais présenté.
pub(crate) const CAUSE_FEDERATION_NOM_TENU_SANS_COMPTE: &str = "FÉDÉRATION REFUSÉE, CE NOM TIENT DES LIGNES SANS \
     COMPTE : sans ligne dans la table des comptes, ce nom tient encore des objets, une graine du second facteur ou des \
     préférences (détail dans `ce_que_le_nom_tient`) — les restes d'un compte supprimé avant que la suppression ne les \
     emporte —, et l'annuaire ne l'a jamais présenté. Le compte fédéré en hériterait. Aucune ligne n'est posée, aucune \
     session n'est ouverte. Ces lignes ne se retirent pas toutes par la console (requêtes, instantanés, graine et \
     préférences d'un nom sans compte) : leur nettoyage est un geste d'exploitation à décider ; d'ici là, l'annuaire \
     peut présenter l'identité sous un autre nom.";

/// `P10.24-t` — la fédération refusée : ce que le nom tient n'a pas pu être lu.
pub(crate) const CAUSE_FEDERATION_CE_QUE_LE_NOM_TIENT_NON_VERIFIE: &str = "FÉDÉRATION REFUSÉE, NOM NON VÉRIFIÉ : la \
     base n'a pas pu dire si ce nom tient des lignes sans compte (lecture refusée ou table illisible), et le démon ne \
     fédère pas un nom qu'il n'a pas pu vérifier — aucune ligne n'est posée ni modifiée, aucune session n'est ouverte. \
     Réessayez.";

/// `P10.25-t` — la fédération refusée parce que le nom n'a pas pu être vérifié (lecture du hachage non faite).
pub(crate) const CAUSE_FEDERATION_NOM_NON_VERIFIE: &str = "FÉDÉRATION REFUSÉE, NOM NON VÉRIFIÉ : la base n'a pas pu \
     dire si ce nom est celui d'un compte local à mot de passe (lecture refusée ou table illisible), et le démon ne \
     fédère pas un nom qu'il n'a pas pu vérifier — aucune ligne n'est posée ni modifiée, aucune session n'est ouverte. \
     Réessayez.";

impl RefusDeLaFederation {
    /// `P10.28-v` — LE REFUS D'UNE FÉDÉRATION EST TRACÉ COMME CELUI DU CHEMIN D'EN-TÊTES : un refus de NOM (la règle unique
    /// des annuaires) inscrit un maillon `auth.annuaire.refuse` et un événement `plume-auth` de sévérité quatre, une fois
    /// par fenêtre et par (base, nom, cause, porte) — `auth::tracer_le_refus_de_l_annuaire`, la trace même des en-têtes.
    /// Le nom n'entre PAS à l'inventaire des accès (il n'a pas accédé). Une écriture de la ligne fédérée qui échoue n'est
    /// pas un refus de nom : elle n'est pas tracée ici. L'appelant ne tient PAS la connexion d'écriture (la trace la prend).
    pub(crate) fn servir(&self, st: &AppState, porte: crate::auth::PorteDeLAnnuaire, ip: &str) -> Response {
        match self {
            Self::Nom(refus) => crate::auth::tracer_le_refus_de_l_annuaire(st, refus, ip, porte),
            // `P10.24-t` — les deux refus neufs sont tracés par la MÊME trace, sous leur propre code.
            Self::NomTenuSansCompte(nom, _) => crate::auth::tracer_un_refus_de_l_annuaire(st, nom, "nom_tenu_sans_compte", ip, porte),
            Self::TenueNonVerifiee(nom, _) => crate::auth::tracer_un_refus_de_l_annuaire(st, nom, "tenue_non_verifiee", ip, porte),
            Self::Ecriture(_) => {}
        }
        self.reponse()
    }

    /// La réponse des trois portes. Les deux refus d'avant gardent leur statut et leur texte (409) ; le nom non
    /// vérifié, neuf, rend 503 et sa cause.
    pub(crate) fn reponse(&self) -> Response {
        use crate::auth::RefusDeLAnnuaire as R;
        match self {
            Self::Nom(R::AdministrateurDeConfiguration(_)) => (
                StatusCode::CONFLICT,
                "ce nom d'utilisateur est réservé au compte administrateur de configuration (fédération refusée)",
            )
                .into_response(),
            Self::Nom(R::CompteAMotDePasse(_)) => {
                (StatusCode::CONFLICT, "le nom d'utilisateur correspond à un compte local existant (fédération refusée)").into_response()
            }
            Self::Nom(R::NonVerifie(nom, cause)) => {
                eprintln!("[idp] WARN fédération de '{nom}' refusée, nom non vérifié : {cause}");
                err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_FEDERATION_NOM_NON_VERIFIE)
            }
            Self::NomTenuSansCompte(_, tenue) => (
                StatusCode::CONFLICT,
                Json(json!({ "error": CAUSE_FEDERATION_NOM_TENU_SANS_COMPTE, "ce_que_le_nom_tient": tenue })),
            )
                .into_response(),
            Self::TenueNonVerifiee(nom, cause) => {
                eprintln!("[idp] WARN fédération de '{nom}' refusée, ce que le nom tient non lu : {cause}");
                err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_FEDERATION_CE_QUE_LE_NOM_TIENT_NON_VERIFIE)
            }
            Self::Ecriture(e) => (StatusCode::CONFLICT, e.clone()).into_response(),
        }
    }
}
