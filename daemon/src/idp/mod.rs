//! IdP NATIF (#44) — cœur logique de l'authentification fédérée + MFA, sans dépendance sur les handlers
//! HTTP (testable en pur). Trois protocoles :
//!   1. OIDC (Authorization-Code + PKCE) : découverte `.well-known`, échange de code, validation JWT
//!      id_token (RS256/ES256 via JWKS), contrôle iss/aud/exp/nonce, mapping claims->rôle (RÉUTILISE
//!      `sso_role`/`sso_grants`, la MÊME sémantique groupe->rôle que le SSO trusted-header Authentik).
//!   2. LDAP / Active Directory (bind + appartenance aux groupes) — échappement de filtre RFC 4515 +
//!      mapping PURS et testés ici ; le bind réseau est feature-gated (`ldap`, cf. `ldap_bind`).
//!   3. TOTP MFA (RFC 6238, HMAC-SHA1) : base32, génération/vérification à fenêtre de dérive, codes de secours.
//!
//! INVARIANT MODE 0 : tant qu'aucun provider n'est configuré (table `idp_provider` vide) et qu'aucune
//! inscription MFA n'existe (`user_mfa` vide), rien ici n'est appelé sur le chemin d'auth existant ->
//! Basic/session/agent-token/HEC/header-SSO STRICTEMENT inchangés. FAIL-CLOSED partout : toute erreur
//! (signature, expiration, nonce, groupe non mappé, misconfig) -> DENY, jamais de session accordée.
//!
//! ORGANISATION (split mécanique — comportement identique) : ce module est un répertoire ; chaque protocole
//! vit dans un sous-module dédié, ré-exporté ici pour que TOUT symbole reste joignable à l'identique en
//! `crate::idp::X` (et via le glob `pub(crate) use idp::*` de `main.rs`).
//!   - `oidc` : entropie/encodages, PKCE, state signé, config OIDC, validation JWT, provisioning JIT.
//!   - `ldap` : LDAP / Active Directory (bind réseau feature-gated `ldap`).
//!   - `totp` : TOTP MFA (RFC 6238) + codes de secours.
//!   - `saml` : SAML 2.0 SP (vérification/extraction feature-gated `saml`).
use crate::*;

mod oidc;
mod ldap;
mod totp;
mod saml;

pub(crate) use oidc::*;
pub(crate) use ldap::*;
pub(crate) use totp::*;
pub(crate) use saml::*;

#[cfg(test)]
mod tests {
    use super::*;

    // ---- clé RSA de test (générée hors-ligne) : PEM PKCS8 + composants JWK (n,e base64url) ----
    // THROWAWAY test key — générée hors-ligne, JAMAIS déployée, JAMAIS un secret de production ;
    // compilée UNIQUEMENT sous #[cfg(test)] (ce module `tests`) pour signer des jetons de test.
    const TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQC8WhQXOyDBHGA0\n/AclkrwY7wE8j9/6m3wp3wedUwxmShTHI/dLAEWUIpLYo4qRLXPNiY1cgATDlIqD\nb6KS/wxyOjSp0rD+uLRB7shDRDmgPus44kh9A6jiscxcxqjTLh+GtI0a6EoTi5jE\nTqbAnMSoayA7DY9OQi2tCwmPrx3HkX4CT+Dwx4lZsqOjQOnzXVSUn7W48Rz19HCp\n8DRS0MBm2leAtsy7V6nY/fOxKiIN/NXABzu2ytlsMIstM1kzyBBd5J0g/vm6zsm8\n8VR51BBH0KbFnuxwdUaYWD7i/LE325F1f6copxz0WXMdhDUn1gV0AC1mcRQijAJz\nqe6psjP/AgMBAAECgf8P7+HcFVphslNpYhtqP+NPtKdiALn/VVH2i5odd8yQqZtB\nwoMdyR3Hd2eB3Kc7204/lfR9BFgIAvDONocLCh5JrQ59YJyp2CiiQkOfK2ScFeAb\nqeChmpDEW6oUQBXPEvLaA439euxFiY5v9Q5xVpBmEtv1wBtTsUXRSd/b8dAjxCu9\ntDO3hhrPxipbSTGHe89HdAbGCMeqZeQQ+ypCUvuu/lFi+HbLbDfbAgJkdr4zCNER\nbOQZqfbbW9NYqjFHZclK23CFwMTwPTzOm0Mh8D/BmxeH7kRSr962SRTXYJTrEyr7\n7SFKkBAfxYb7Q23y2uqxQPWJQyTjrb05MXHHwy0CgYEA5mYVokFFAENEnf7MEbGc\nhioO5QcGGRfwsI0vGrIyg6zWqWI4p5uO9v2NvY0k+zzRNlMU1zLnfcURbqoSU4AG\nn6gSMYLEBhyXUomEr3kc5WJogKF/oqWDGjWEbbhd0zX3vro/wo4mRWueiKQfozbe\nJaGVe3ke0CJOb4Gg/KmIlKsCgYEA0Uft6IJVLgK0Dydp9bMssZPfXDc0V6n4N6uD\n2HTnPZalToMpLc73P60djj2wcSK3iaCabe8g7Wuk3am/WRh7GB1Y7JBTtwbD9+Si\n6gpaNfAUvKMv+TZtgphFAczxjVB66wFtb6lhZZ+nNXIlMXXlcy3+uuQIdnAhjyWK\nG0wP1f0CgYBAvvVbaH4sibrRr5XHbyMubMlMwUGMcbbY1oQjO2qIqFyWsxx6tXNi\no3RejTiURc4BNy3HH+3/4Q56C98kifjSixe5xCa0FPrNXgnkieN97r6xTzEgEuUZ\ny2pQrxvmy+a4OXzLfsjwf0LI4V5mrneVGah5T1tCYDGskkAcYMQaCwKBgBuoStug\nZctn1g3uooUzAaQSK8GPFh7Duqb4xrrTcD/macA/ezCvmmNS6IYExw2cje7lR6Nh\np9NYl3gn177ZimL8deUFidq1TS60i4csiRF5wfPQCSYBOGW649vCDuYjDauDC8hm\n9RUuDTX1+M5Zi1I2cOSYADpOxVCaoG7NFYatAoGBAMFrsV23xD7Ec4UWrRmkMySI\nE/PZNHY+t32FmLNvSVCr7vZyjXLZe1Dwer7IJDCqX4HwsTplo8s1SXuvi+WkYY/5\naS0x5Z1a8vsPovQjVuxmNbVv75Wa0rMUAS3qg2YDL4rI6nBvfzveVGlsCYY6I+KV\nCqORZTvxlptOc0ptlLjI\n-----END PRIVATE KEY-----\n";
    const TEST_N: &str = "vFoUFzsgwRxgNPwHJZK8GO8BPI_f-pt8Kd8HnVMMZkoUxyP3SwBFlCKS2KOKkS1zzYmNXIAEw5SKg2-ikv8Mcjo0qdKw_ri0Qe7IQ0Q5oD7rOOJIfQOo4rHMXMao0y4fhrSNGuhKE4uYxE6mwJzEqGsgOw2PTkItrQsJj68dx5F-Ak_g8MeJWbKjo0Dp811UlJ-1uPEc9fRwqfA0UtDAZtpXgLbMu1ep2P3zsSoiDfzVwAc7tsrZbDCLLTNZM8gQXeSdIP75us7JvPFUedQQR9CmxZ7scHVGmFg-4vyxN9uRdX-nKKcc9FlzHYQ1J9YFdAAtZnEUIowCc6nuqbIz_w";
    const TEST_E: &str = "AQAB";

    fn test_jwks() -> Value {
        json!({ "keys": [ { "kty": "RSA", "kid": "test-key-1", "alg": "RS256", "use": "sig", "n": TEST_N, "e": TEST_E } ] })
    }

    fn mint_id_token(claims: Value) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some("test-key-1".to_string());
        let key = EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).expect("encoding key");
        encode(&h, &claims, &key).expect("sign")
    }

    fn base_claims(exp: i64) -> Value {
        json!({
            "iss": "https://idp.example.com",
            "aud": "plume-client",
            "sub": "u-123",
            "preferred_username": "alice",
            "nonce": "nonce-abc",
            "exp": exp,
            "iat": now() - 10,
            "groups": ["plume-editor"],
        })
    }

    #[test]
    fn oidc_jwt_accept_valid() {
        let tok = mint_id_token(base_claims(now() + 300));
        let c = oidc_validate_id_token(&tok, &test_jwks(), "https://idp.example.com", "plume-client", "nonce-abc");
        assert!(c.is_ok(), "un id_token bien formé/signé/non expiré est accepté: {:?}", c.err());
        assert_eq!(oidc_username(&c.unwrap()), "alice");
    }

    #[test]
    fn oidc_jwt_reject_bad_signature() {
        let tok = mint_id_token(base_claims(now() + 300));
        // Corrompt le PREMIER caractère de la signature (bits de poids fort de l'octet 0 -> impact garanti ;
        // le DERNIER caractère base64url porte des bits « don't care » et pouvait décoder aux MÊMES octets).
        let parts: Vec<&str> = tok.split('.').collect();
        let sig = parts[2];
        let first = sig.chars().next().unwrap();
        let newfirst = if first == 'A' { 'B' } else { 'A' }; // 'A'=0, 'B'=1 -> valeur toujours différente
        let bad_sig: String = std::iter::once(newfirst).chain(sig.chars().skip(1)).collect();
        let bad = format!("{}.{}.{}", parts[0], parts[1], bad_sig);
        assert!(oidc_validate_id_token(&bad, &test_jwks(), "https://idp.example.com", "plume-client", "nonce-abc").is_err());
    }

    #[test]
    fn oidc_jwt_reject_wrong_aud() {
        let tok = mint_id_token(base_claims(now() + 300));
        assert!(oidc_validate_id_token(&tok, &test_jwks(), "https://idp.example.com", "AUTRE-client", "nonce-abc").is_err());
    }

    #[test]
    fn oidc_jwt_reject_wrong_iss() {
        let tok = mint_id_token(base_claims(now() + 300));
        assert!(oidc_validate_id_token(&tok, &test_jwks(), "https://evil.example.com", "plume-client", "nonce-abc").is_err());
    }

    #[test]
    fn oidc_jwt_reject_bad_nonce() {
        let tok = mint_id_token(base_claims(now() + 300));
        assert!(oidc_validate_id_token(&tok, &test_jwks(), "https://idp.example.com", "plume-client", "MAUVAIS-nonce").is_err());
    }

    #[test]
    fn oidc_jwt_reject_expired() {
        let tok = mint_id_token(base_claims(now() - 3600));
        assert!(oidc_validate_id_token(&tok, &test_jwks(), "https://idp.example.com", "plume-client", "nonce-abc").is_err());
    }

    #[test]
    fn oidc_jwt_reject_wrong_kid() {
        let tok = mint_id_token(base_claims(now() + 300));
        let jwks = json!({ "keys": [ { "kty": "RSA", "kid": "AUTRE-kid", "n": TEST_N, "e": TEST_E } ] });
        assert!(oidc_validate_id_token(&tok, &jwks, "https://idp.example.com", "plume-client", "nonce-abc").is_err());
    }

    #[test]
    fn oidc_groups_extraction_array_and_string() {
        let c = json!({ "groups": ["a", "b", "c"] });
        assert_eq!(oidc_groups_str(&c, "groups"), "a|b|c");
        let c2 = json!({ "roles": "x y z" });
        assert_eq!(oidc_groups_str(&c2, "roles"), "x|y|z");
        let c3 = json!({ "groups": ["only"] });
        assert_eq!(oidc_groups_str(&c3, "missing"), "");
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_vector() {
        // vecteur de test RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(pkce_challenge_s256(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn oidc_state_roundtrip_and_tamper() {
        let secret = b"unit-test-secret";
        let blob = oidc_state_sign(secret, "google", "st-1", "nc-1", "vf-1", 300);
        let got = oidc_state_verify(secret, &blob).expect("valide");
        assert_eq!(got, ("google".into(), "st-1".into(), "nc-1".into(), "vf-1".into()));
        // signature d'un AUTRE secret -> rejet.
        assert!(oidc_state_verify(b"autre-secret", &blob).is_none());
        // altération du payload -> rejet.
        let mut bad = blob.clone();
        bad.insert(0, 'x');
        assert!(oidc_state_verify(secret, &bad).is_none());
    }

    #[test]
    fn oidc_state_expired_rejected() {
        // `sign` clampe le TTL à >= 1s (jamais un token déjà expiré) : on forge à la main un blob dont exp
        // est dans le PASSÉ, correctement signé, et on vérifie que `verify` le REJETTE (borne temporelle).
        let secret = b"s";
        let past = now() - 100;
        let payload = format!("g|s|n|v|{past}");
        let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let sig = hmac_sha256(secret, p_b64.as_bytes());
        let blob = format!("{p_b64}.{}", hex_encode(&sig));
        assert!(oidc_state_verify(secret, &blob).is_none());
    }

    #[test]
    fn oidc_endpoints_require_https_and_completeness() {
        let mut cfg = OidcCfg { issuer: "https://i".into(), client_id: "c".into(), redirect_uri: "https://r".into(), ..Default::default() };
        let disc = json!({ "authorization_endpoint": "https://a", "token_endpoint": "https://t", "jwks_uri": "https://j" });
        assert!(oidc_resolve_endpoints(&cfg, Some(&disc)).is_ok());
        // discovery avec un endpoint http:// -> refus (anti fuite de secret en clair).
        let bad = json!({ "authorization_endpoint": "http://a", "token_endpoint": "https://t", "jwks_uri": "https://j" });
        assert!(oidc_resolve_endpoints(&cfg, Some(&bad)).is_err());
        // pas de discovery + pas d'override -> incomplet -> Err.
        cfg.authorization_endpoint.clear();
        assert!(oidc_resolve_endpoints(&cfg, None).is_err());
    }

    #[test]
    fn ldap_filter_escaping_blocks_injection() {
        // un login d'injection ne peut pas altérer la structure du filtre.
        assert_eq!(ldap_escape_filter("*)(uid=*"), "\\2a\\29\\28uid=\\2a");
        assert_eq!(ldap_escape_filter("a\\b"), "a\\5cb");
        assert_eq!(ldap_escape_filter("normal.user"), "normal.user");
        let cfg = LdapCfg { user_filter: "(uid={user})".into(), ..Default::default() };
        assert_eq!(cfg.build_user_filter("*)(cn=*"), "(uid=\\2a\\29\\28cn=\\2a)");
    }

    #[test]
    fn ldap_group_role_mapping_and_failclosed() {
        let cfg = LdapCfg {
            admin_group: "cn=admins,ou=g,dc=x".into(),
            editor_group: "cn=editors,ou=g,dc=x".into(),
            viewer_group: "cn=viewers,ou=g,dc=x".into(),
            require_group_match: true,
            ..Default::default()
        };
        assert_eq!(ldap_role_from_groups(&cfg, &["cn=editors,ou=g,dc=x".into()]), Some("editor".into()));
        // admin l'emporte sur editor.
        assert_eq!(ldap_role_from_groups(&cfg, &["cn=editors,ou=g,dc=x".into(), "cn=admins,ou=g,dc=x".into()]), Some("admin".into()));
        // aucun groupe mappé + require_group_match -> DENY.
        assert_eq!(ldap_role_from_groups(&cfg, &["cn=autre,ou=g,dc=x".into()]), None);
        // require_group_match=false -> viewer par défaut.
        let cfg2 = LdapCfg { require_group_match: false, ..cfg.clone() };
        assert_eq!(ldap_role_from_groups(&cfg2, &["cn=autre".into()]), Some("viewer".into()));
    }

    #[test]
    fn base32_roundtrip() {
        let data = b"Hello!\x00\xff";
        let enc = base32_encode(data);
        assert_eq!(base32_decode(&enc).unwrap(), data);
        // RFC 4648 vecteur "foobar".
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert!(base32_decode("MZXW6YTBOI!").is_none()); // caractère invalide -> None
    }

    #[test]
    fn totp_rfc6238_and_replay_window() {
        // graine "12345678901234567890" (RFC 6238 test) en base32.
        let secret_b32 = base32_encode(b"12345678901234567890");
        // à T=59s, step=30 -> code RFC = 94287082 (8 chiffres). On teste 6 chiffres (usage réel) par cohérence interne.
        let t = 59i64;
        let code = hotp(&base32_decode(&secret_b32).unwrap(), (t / 30) as u64, 6);
        assert!(totp_verify(&secret_b32, &code, t, 30, 6, 1), "le code courant est accepté");
        // un code faux est rejeté.
        assert!(!totp_verify(&secret_b32, "000000", t, 30, 6, 1) || code == "000000");
        // fenêtre de dérive : le code du pas précédent est accepté avec skew=1.
        let prev = hotp(&base32_decode(&secret_b32).unwrap(), (t / 30 - 1) as u64, 6);
        assert!(totp_verify(&secret_b32, &prev, t, 30, 6, 1));
        // hors fenêtre (skew=0) -> refus du pas précédent.
        assert!(!totp_verify(&secret_b32, &prev, t, 30, 6, 0) || prev == code);
        // format invalide -> refus.
        assert!(!totp_verify(&secret_b32, "abcd", t, 30, 6, 1));
        assert!(!totp_verify(&secret_b32, "12345", t, 30, 6, 1)); // mauvaise longueur
    }

    #[test]
    fn provision_refuses_static_admin_and_local_collision() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE user(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'editor', created INTEGER NOT NULL DEFAULT 0);",
        ).unwrap();
        // compte LOCAL à mot de passe réel -> une fédération sur ce nom est REFUSÉE (anti-usurpation).
        conn.execute("INSERT INTO user(name,hash,role) VALUES('alice','$argon2id$vrai-hash','admin')", []).unwrap();
        assert!(idp_provision_user(&conn, "alice", "viewer", None).is_err(), "collision avec un compte local refusée");
        // ADMIN BOOTSTRAP réservé (PLUME_USER='admin'), ABSENT de la table `user` -> refus MÊME si pas de
        // collision visible (sinon lockout/hijack silencieux de l'admin statique). C'est le cœur de FIX 3.
        assert!(idp_provision_user(&conn, "admin", "admin", Some("admin")).is_err(), "admin de config réservé -> fédération refusée");
        // un nouveau nom fédéré -> OK : crée un compte sentinel (Basic impossible), rôle mappé.
        assert!(idp_provision_user(&conn, "bob", "editor", Some("admin")).is_ok());
        let (h, r): (String, String) = conn.query_row("SELECT hash,role FROM user WHERE name='bob'", [], |x| Ok((x.get(0)?, x.get(1)?))).unwrap();
        assert_eq!(h, IDP_HASH_SENTINEL, "hash sentinel -> verify_pw toujours false (pas de login Basic)");
        assert_eq!(r, "editor");
        // re-login fédéré resynchronise le rôle (upsert) sans jamais toucher un compte réservé/local.
        assert!(idp_provision_user(&conn, "bob", "viewer", Some("admin")).is_ok());
        let r2: String = conn.query_row("SELECT role FROM user WHERE name='bob'", [], |x| x.get(0)).unwrap();
        assert_eq!(r2, "viewer", "le rôle est resynchronisé depuis l'IdP au re-login");
        // reserved=None (aucun admin de config posé) -> pas de réservation.
        assert!(idp_provision_user(&conn, "carol", "viewer", None).is_ok());
    }

    #[test]
    fn totp_step_returned_and_replay_rejected() {
        let secret = base32_encode(b"12345678901234567890");
        let sbytes = base32_decode(&secret).unwrap();
        let t = 59i64;
        let ctr = t / 30; // = 1
        let code = hotp(&sbytes, ctr as u64, 6);
        // le pas matché est renvoyé (support de l'anti-rejeu).
        assert_eq!(totp_verify_step(&secret, &code, t, 30, 6, 1), Some(ctr), "le compteur matché est renvoyé");
        // ANTI-REJEU : un code déjà consommé a un pas <= last_step -> rejeté par le prédicat des handlers.
        let last_step = ctr;
        assert!(totp_verify_step(&secret, &code, t, 30, 6, 1).unwrap() <= last_step, "code déjà utilisé (step<=last_step) = rejeu");
        // le pas SUIVANT est > last_step -> accepté (le TOTP continue d'avancer).
        let next_code = hotp(&sbytes, (ctr + 1) as u64, 6);
        let next_step = totp_verify_step(&secret, &next_code, t + 30, 30, 6, 1).unwrap();
        assert!(next_step > last_step, "un nouveau pas est accepté");
        // format invalide -> None (jamais un pas matché).
        assert!(totp_verify_step(&secret, "abcd", t, 30, 6, 1).is_none());
        assert!(totp_verify_step(&secret, "1234567", t, 30, 6, 1).is_none());
    }

    #[test]
    fn recovery_codes_hashed_not_clear() {
        let (clear, hashes) = gen_recovery_codes(8).expect("entropie");
        assert_eq!(clear.len(), 8);
        assert_eq!(hashes.len(), 8);
        // chaque hash = SHA-256 du code clair (usage unique, jamais le clair persisté).
        for (c, h) in clear.iter().zip(hashes.iter()) {
            assert_eq!(&sha256_hex(c.as_bytes()), h);
            assert!(c.contains('-'));
        }
    }
}
