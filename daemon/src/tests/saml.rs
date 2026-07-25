// Tests SAML 2.0 SP (#44). TOUS gated `#[cfg(feature = "saml")]` -> le build/test DÉFAUT reste à 600 tests
// (byte-identique, samlify non linké). Sous `--features saml` : tests PURS (RelayState, mapping, garde
// d'algorithme, cache anti-rejeu, parsing config) + tests ADVERSAIRES de l'ACS (fixtures signées générées
// via le round-trip samlify IdP, puis mutées : non signé, signature altérée, mauvaise audience/recipient/
// issuer, expiré, pas-encore-valide, InResponseTo divergent, rejeu, mauvais cert, SHA-1, XSW, statut != Success).
//
// Inclus dans le module `tests` (voir mod.rs) -> les items de la racine du crate (SamlCfg, saml_*,
// oidc_role_mode0, sso_test_state, now, base64…) sont en portée.

// ---- clé + cert de test (vecteurs samlify, réutilisés hors-ligne ; JAMAIS de prod) ----
// THROWAWAY test key — vecteur de test hors-ligne, JAMAIS déployée, JAMAIS un secret de production ;
// compilée UNIQUEMENT sous #[cfg(test)] (module `tests`) + `--features saml`.
#[cfg(feature = "saml")]
const SAML_TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEwgIBADANBgkqhkiG9w0BAQEFAASCBKwwggSoAgEAAoIBAgC6Jl6iPARyB13z\nJEJ12SEuGgpJwhMmXVVxStswVrvrKD/0oWM6CJjbtjhzMvvVcrLcvnYZBdyvJeE5\neu3613wCuwNX4BNWYu38TDVVOYbmMpuwlB7e1iC6W92XqswTvK0LW+TjQsYC0HTx\n8/gdtVQs5LocSwVa3C0rEjbChWB8JTfuck4LP1JVawzFHCOY2fWXI6ct3MdnzvJT\nojIgZELPAuE3T2NWhgrfpco+X5cXaZN44MBcnlsYfMF9LU8uGL3Mbtzy3TAsxVtL\nvoLPpOkr+hMmdMEybPBnqwuWtsrdfLuB5FXuuFZ8SZj3tZeQYtRreMp+rktMB/re\nvPlmPOB5nwIDAQABAoIBAgCwsQD8n1lc3y9HPjCzafE7sE35qvTAYrFag0JAxONE\nmAT08Eeea1CkpHc6qbcu6Ntr+oFgyRarTZpWFCBWDDnS4a6Pt8rDIc5hv/iTt7Ib\nSQhM+JvAyqFwIwjYEK/7QAlFEenV6ajIPRP0Ia5ujJKktksN1gv0La/WBUjjJPTr\ngdKDgP4SgEHwhDF3rgzk/284Dbmr4pOxvi290AnHrVER+oPlxy/WS4mOEBYVU2Rq\nTbP07ej+ifYO/w9ZjJAc5l9UK2NDsv3JCUgui0PBgZ27z3dZ2TD2VbZXqSS4jahG\nUUhwCT0sOzIWVsZypv4PvTHJl/uvgS1Be01n/FAtcJGAKQKBgQ49glSkdtfJtjQm\nblqbacabkox+EM8EGkc9iveveD81E0gUYTL7AjVawowVYKQnYSZfsCdU7feLPQH2\nbwjzAgbiY+QbbFcTT9FJu5D31qM4jqk24Bu2vjecHpEy8sJKkvoqv0CdWTUKhk98\n7enh63LWo4Hjs6FVMAh8QKwsHjeMfQKBgQ0Sc4eO4ZSFuwCx8L4gG7MlvIeqVbHC\n8kwDzJY3qECxDaDD1ogbGuDVa9p8bnZNmhHE6+nyep7AGvXKzWUzWqYYz2nqxwuC\n/MAQHN6ruKFDaWzrDCfBMfwLsif4SgpcKkJj+1Y+LjPe1tgBw45cco9cWxZLPvVL\nyxEAVTbFWXFlSwKBgQu7F/ZqVYyGGpbzYc06YfS+jAc4gthG5O7y/9vyrPhE3NFw\nGHJK3RLe5Y1Ivwf7eMiH4zFDgZV/Go7XV7jjlzPco7Vx8dn5irM6Lk3KHQLwwHUd\nQ5kQ/boJ3hR3CAyOKm3zcQHlnWtYdDRfEg6tkaxUrPV/gqbQ6nTTBuPOpEXWcQKB\ngQnqSvMxr21mmleGoOK1nA0gvIXy75ksE3kREKeIg/i902Zz5U/Lr3GGsI5C/86A\nQjLkOUV0hQnRESIKuAzhDQsbmofuaxgSPQC5uAw2GI9JgLf6+XdWFUHm5TVoIVEG\nY4+EIuphs83oYvHpNJnRCZwwI28fmBubZ+X3aKtoudVHTQKBgQCKN34ZGQUgs3OY\n0VNlrlM5BMqO4uJD/kv5BgepqfbVEud2Mwmu+W1nPKv0rdWyIZunL2xVGD/9yRk0\nruC2q4dCQvFV2TsxN7Pkf+bvm9Ep9XokQE79g7EVty3mf8vYVv5KXDXEH808YxqU\ngFQYnB76DUsI08o13SQtjDCm/oLxSA==\n-----END PRIVATE KEY-----\n";
#[cfg(feature = "saml")]
const SAML_TEST_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIID0TCCArigAwIBAgIBADANBgkqhkiG9w0BAQsFADCBgTELMAkGA1UEBhMCaGsx\nEjAQBgNVBAgMCUhvbmcgS29uZzETMBEGA1UECgwKbm9kZS1zYW1sMjEXMBUGA1UE\nAwwOc2FtbGlmeS5qcy5vcmcxCzAJBgNVBAcMAkhLMSMwIQYJKoZIhvcNAQkBFhRu\nb2RlLnNhbWwyQGdtYWlsLmNvbTAeFw0yMzAxMDUyMjQ3NTBaFw0zMzAxMDIyMjQ3\nNTBaMIGBMQswCQYDVQQGEwJoazESMBAGA1UECAwJSG9uZyBLb25nMRMwEQYDVQQK\nDApub2RlLXNhbWwyMRcwFQYDVQQDDA5zYW1saWZ5LmpzLm9yZzELMAkGA1UEBwwC\nSEsxIzAhBgkqhkiG9w0BCQEWFG5vZGUuc2FtbDJAZ21haWwuY29tMIIBIzANBgkq\nhkiG9w0BAQEFAAOCARAAMIIBCwKCAQIAuiZeojwEcgdd8yRCddkhLhoKScITJl1V\ncUrbMFa76yg/9KFjOgiY27Y4czL71XKy3L52GQXcryXhOXrt+td8ArsDV+ATVmLt\n/Ew1VTmG5jKbsJQe3tYgulvdl6rME7ytC1vk40LGAtB08fP4HbVULOS6HEsFWtwt\nKxI2woVgfCU37nJOCz9SVWsMxRwjmNn1lyOnLdzHZ87yU6IyIGRCzwLhN09jVoYK\n36XKPl+XF2mTeODAXJ5bGHzBfS1PLhi9zG7c8t0wLMVbS76Cz6TpK/oTJnTBMmzw\nZ6sLlrbK3Xy7geRV7rhWfEmY97WXkGLUa3jKfq5LTAf63rz5ZjzgeZ8CAwEAAaNQ\nME4wHQYDVR0OBBYEFIW8z2CmYsUvTbX8IFHE+IdbkcsHMB8GA1UdIwQYMBaAFIW8\nz2CmYsUvTbX8IFHE+IdbkcsHMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQAD\nggECAAvSnm6IQYmPPVpoUvwC3K3jh28HQ/8S5QMgRGw+RcqgJbo5wIAn0OOUJLfR\nrLtcx2UfaFPn3QKvGOrX71ekb6FF0hzEq+U3Mbv2KEWBEwbu5D+N93uvf3ryeM7o\nX4t6Qi5gKe486PrOBu2CyUtveFBqECWCGRG5yN+/4bd2zh/hug3lD28hicA7rsnA\nFOrEmnhnDhzWzoG+ih1uCzjui21gFGeKRspWkXf+4Vgc7lL+tYCI0sVfe1huRwFh\nSkTC5yT/7mYw4aLlRAKOxAEMHQjj5bFyr8NZa296YIcdBbdRm8oqGDqWcK4wcu/I\nyFtbTMIWwNL9n/lLh695eNwDmg28\n-----END CERTIFICATE-----\n";

#[cfg(feature = "saml")]
const SAML_SP_ENTITY: &str = "https://plume.example.com/saml/metadata";
#[cfg(feature = "saml")]
const SAML_IDP_ENTITY: &str = "https://idp.example.com/metadata";
#[cfg(feature = "saml")]
const SAML_ACS: &str = "https://plume.example.com/api/auth/saml/acs";
#[cfg(feature = "saml")]
const SAML_IDP_SSO: &str = "https://idp.example.com/sso";

// ================================ tests PURS (logique plume) ================================

#[cfg(feature = "saml")]
#[test]
fn saml_relaystate_roundtrip_tamper_expire_domain() {
    let secret = b"unit-test-secret";
    let blob = saml_relaystate_sign(secret, "okta", "_req-123", 300);
    assert_eq!(saml_relaystate_verify(secret, &blob), Some(("okta".into(), "_req-123".into())));
    // mauvais secret -> rejet.
    assert!(saml_relaystate_verify(b"autre", &blob).is_none());
    // altération -> rejet.
    let mut bad = blob.clone();
    bad.insert(0, 'x');
    assert!(saml_relaystate_verify(secret, &bad).is_none());
    // expiré (forgé à la main, correctement signé) -> rejet.
    let past = now() - 100;
    let payload = format!("saml|okta|_req-123|{past}");
    let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let expired = format!("{p_b64}.{}", hex_encode(&hmac_sha256(secret, p_b64.as_bytes())));
    assert!(saml_relaystate_verify(secret, &expired).is_none());
    // CONFUSION DE DOMAINE : un blob OIDC (préfixe provider|state|nonce|verifier) ne doit PAS passer pour un
    // RelayState SAML (préfixe de domaine `saml` exigé).
    let oidc_blob = oidc_state_sign(secret, "okta", "st", "nc", "vf", 300);
    assert!(saml_relaystate_verify(secret, &oidc_blob).is_none());
}

#[cfg(feature = "saml")]
#[test]
fn saml_groups_str_normalizes() {
    assert_eq!(saml_groups_str(&["a".into(), " b ".into(), "".into(), "c".into()]), "a|b|c");
    assert_eq!(saml_groups_str(&[]), "");
}

#[cfg(feature = "saml")]
#[test]
fn saml_group_role_mapping_reuses_sso_and_fails_closed() {
    // MÊME mapping groupe->rôle qu'OIDC/SSO header (réutilise oidc_role_mode0). Fail-closed #13.
    let st = sso_test_state("plume-admins", "plume-editors", "plume-supers");
    // un groupe editor connu -> editor.
    assert_eq!(oidc_role_mode0(&st, &saml_groups_str(&["plume-editors".into()]), true), Some("editor".into()));
    // admin l'emporte.
    assert_eq!(
        oidc_role_mode0(&st, &saml_groups_str(&["plume-editors".into(), "plume-admins".into()]), true),
        Some("admin".into())
    );
    // AUCUN groupe connu + require_group_match=true -> DENY (pas de viewer par défaut).
    assert_eq!(oidc_role_mode0(&st, &saml_groups_str(&["random".into()]), true), None);
    // groupes vides + require -> DENY.
    assert_eq!(oidc_role_mode0(&st, "", true), None);
    // require=false -> viewer par défaut.
    assert_eq!(oidc_role_mode0(&st, "random", false), Some("viewer".into()));
}

/// Construit un `<ds:Signature>` minimal bien formé portant `sig_alg`/`dig_alg` — pour tester la garde #11
/// via le VRAI parseur DOM de saml-rs (attributs char-ref-décodés), comme en production.
#[cfg(feature = "saml")]
fn sig_xml(sig_alg: &str, dig_alg: &str) -> String {
    format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:SignatureMethod Algorithm="{sig_alg}"/><ds:Reference><ds:DigestMethod Algorithm="{dig_alg}"/><ds:DigestValue>x</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>x</ds:SignatureValue></ds:Signature>"#
    )
}

#[cfg(feature = "saml")]
#[test]
fn saml_reject_weak_sig_alg_guard() {
    let rsa256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    let sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    // --- ALGOS FORTS -> ACCEPTÉS (pas de faux rejet de l'allowlist) ---
    assert!(saml_reject_weak_sig_alg(&sig_xml(rsa256, sha256)));
    assert!(saml_reject_weak_sig_alg(&sig_xml("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "http://www.w3.org/2001/04/xmldsig-more#sha384")));
    assert!(saml_reject_weak_sig_alg(&sig_xml("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "http://www.w3.org/2001/04/xmlenc#sha512")));
    assert!(saml_reject_weak_sig_alg(&sig_xml("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", sha256)));
    assert!(saml_reject_weak_sig_alg(&sig_xml("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", sha256)));
    // RSA-PSS (xmldsig-more 2007/05 ; casse d'origine `MGF1`) -> accepté (frag comparé en minuscules).
    assert!(saml_reject_weak_sig_alg(&sig_xml("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1", sha256)));
    // --- ALGOS FAIBLES/INCONNUS -> REFUSÉS ---
    assert!(!saml_reject_weak_sig_alg(&sig_xml("http://www.w3.org/2000/09/xmldsig#rsa-sha1", sha256)));
    assert!(!saml_reject_weak_sig_alg(&sig_xml("http://www.w3.org/2000/09/xmldsig#dsa-sha1", sha256)));
    assert!(!saml_reject_weak_sig_alg(&sig_xml("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1", sha256)));
    assert!(!saml_reject_weak_sig_alg(&sig_xml("http://www.w3.org/2001/04/xmldsig-more#rsa-md5", sha256)));
    assert!(!saml_reject_weak_sig_alg(&sig_xml("http://www.w3.org/2000/09/xmldsig#hmac-sha1", sha256)));
    // DigestMethod faible (signature forte) -> refusé (on vérifie AUSSI les digests).
    assert!(!saml_reject_weak_sig_alg(&sig_xml(rsa256, "http://www.w3.org/2000/09/xmldsig#sha1")));
    // --- CONTOURNEMENT PAR RÉFÉRENCE DE CARACTÈRE (le cœur du fix #11) ---
    // `...#rsa-sha&#49;` / `&#x31;` ne contiennent AUCUNE sous-chaîne `#rsa-sha1` (l'ancien denylist PASSAIT)
    // mais le parseur DOM décode `&#49;`/`&#x31;` -> `1` -> frag `rsa-sha1` -> REFUSÉ.
    assert!(!saml_reject_weak_sig_alg(&sig_xml("http://www.w3.org/2000/09/xmldsig#rsa-sha&#49;", sha256)));
    assert!(!saml_reject_weak_sig_alg(&sig_xml("http://www.w3.org/2000/09/xmldsig#rsa-sha&#x31;", sha256)));
    // --- FAIL-CLOSED ---
    // aucune SignatureMethod -> refusé (une réponse signée en porte toujours une).
    assert!(!saml_reject_weak_sig_alg(r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>"#));
    // XML illisible -> refusé.
    assert!(!saml_reject_weak_sig_alg("<not-closed"));
    // Algorithm absent -> refusé.
    assert!(!saml_reject_weak_sig_alg(r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:SignatureMethod/></ds:SignedInfo></ds:Signature>"#));
}

#[cfg(feature = "saml")]
#[test]
fn saml_groups_str_neutralizes_embedded_separators_no_priv_esc() {
    // DURCISSEMENT #4 : une valeur de groupe UNIQUE assertée par l'IdP contenant un séparateur ('|' ou ',')
    // ne doit PAS se ré-éclater en plusieurs groupes -> pas de groupe admin synthétique.
    let st = sso_test_state("plume-admins", "plume-editors", "plume-supers");
    // '|' interne neutralisé : "x|plume-admins" -> "xplume-admins" (une seule valeur, pas admin).
    let joined = saml_groups_str(&["x|plume-admins".into()]);
    assert!(!joined.contains('|'), "séparateur '|' interne neutralisé: {joined}");
    assert_eq!(oidc_role_mode0(&st, &joined, false), Some("viewer".into()), "pas d'élévation via '|'");
    // ',' interne neutralisé de même.
    let joined2 = saml_groups_str(&["y,plume-admins".into()]);
    assert_eq!(oidc_role_mode0(&st, &joined2, false), Some("viewer".into()), "pas d'élévation via ','");
    // fail-closed : require_group_match=true -> aucun groupe connu -> DENY.
    assert_eq!(oidc_role_mode0(&st, &joined, true), None);
    // les séparateurs LÉGITIMES entre valeurs distinctes (posés par nous) restent, eux, fonctionnels.
    assert_eq!(oidc_role_mode0(&st, &saml_groups_str(&["z".into(), "plume-admins".into()]), true), Some("admin".into()));
}

#[cfg(feature = "saml")]
#[test]
fn saml_bounded_replay_store() {
    let mut s = BoundedReplayStore::new(2);
    let t = 1000i64;
    // 1er vu -> OK ; rejeu -> refusé.
    assert!(s.check_and_store("_a", t, t + 300));
    assert!(!s.check_and_store("_a", t, t + 300));
    // ID vide -> refusé (fail-closed).
    assert!(!s.check_and_store("", t, t + 300));
    // purge des expirés : à t+400, _a a expiré (t+300) -> _b réinsérable, _a aussi de nouveau.
    assert!(s.check_and_store("_b", t + 400, t + 700));
    assert!(s.check_and_store("_a", t + 400, t + 700));
    // borne dure : cap=2, on insère un 3e non-expiré -> éviction du plus proche de l'expiration, jamais un refus.
    assert!(s.check_and_store("_c", t + 400, t + 800));
}

#[cfg(feature = "saml")]
#[test]
fn saml_cfg_from_json_defaults_and_usable() {
    // défauts fail-closed : want_assertions_signed=true, sign_authn_requests=false, skew=60, require_group_match=true.
    let cfg = SamlCfg::from_json(&json!({
        "idp_sso_url": "https://idp/sso", "idp_entity_id": "https://idp", "sp_entity_id": "https://sp",
        "acs_url": "https://sp/acs", "idp_x509_cert": "PEM"
    }));
    assert!(cfg.want_assertions_signed);
    assert!(!cfg.sign_authn_requests);
    assert_eq!(cfg.allowed_clock_skew_s, 60);
    assert!(cfg.require_group_match);
    assert_eq!(cfg.attr_groups, "groups");
    assert!(cfg.is_usable());
    // skew borné [0..3600].
    let c2 = SamlCfg::from_json(&json!({"idp_sso_url":"x","idp_entity_id":"x","sp_entity_id":"x","acs_url":"x","idp_x509_cert":"x","allowed_clock_skew_s": 999999}));
    assert_eq!(c2.allowed_clock_skew_s, 3600);
    // config incomplète -> non utilisable.
    assert!(!SamlCfg::from_json(&json!({"idp_sso_url":"x"})).is_usable());
}

// ================================ harnais de fixtures signées (round-trip samlify) ================================

/// Génère un couple (SAMLResponse base64 signé, request_id) via le round-trip IdP samlify : SP émet
/// l'AuthnRequest, l'IdP le reçoit et répond avec une assertion SIGNÉE (clé/cert de test). `now_offset_s`
/// décale l'horloge de génération (0 = maintenant).
#[cfg(feature = "saml")]
fn saml_gen_signed_response() -> (String, String) {
    use samlify::{
        AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, IdpConfig,
        IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, NameId, PrivateKeyPem, ReplayPolicy,
        RespondSso, Saml, SamlValidationContext, SpConfig, SpDescriptor, SpValidationPolicy,
        SsoEndpoint, StartSso, Subject,
    };
    use std::time::SystemTime;

    let creds = Credentials {
        signing_key: Some(PrivateKeyPem::new(SAML_TEST_KEY)),
        signing_certificate: Some(CertificatePem::new(SAML_TEST_CERT)),
        ..Default::default()
    };
    // SP : signe son AuthnRequest (strict) pour que l'IdP strict l'accepte.
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SAML_SP_ENTITY).unwrap())
            .acs_endpoint(AcsEndpoint::post(SAML_ACS).unwrap().mark_default())
            .credentials(creds.clone())
            .validation(SpValidationPolicy::strict())
            .build()
            .unwrap(),
    )
    .unwrap();
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(SAML_IDP_ENTITY).unwrap())
            .sso_endpoint(SsoEndpoint::post(SAML_IDP_SSO).unwrap())
            .credentials(creds)
            .validation(IdpValidationPolicy::strict())
            .build()
            .unwrap(),
    )
    .unwrap();
    let sp_desc = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SAML_SP_ENTITY).unwrap(),
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
    .unwrap();
    let idp_desc = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SAML_IDP_ENTITY).unwrap(),
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
    .unwrap();
    let started = sp.start_sso(&idp_desc, StartSso::post()).unwrap();
    let request_id = started.pending.snapshot().id;
    let req_input = BrowserInput::<AuthnRequest>::post(started.outbound.post_form().unwrap().fields().to_vec());
    let received = idp
        .receive_sso(&sp_desc, req_input, SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility))
        .unwrap();
    // NameID sans '@' pour rester conforme à idp_name_ok côté handler.
    let subject = Subject::new(NameId::new("alice", None), Vec::new());
    let resp = idp.respond_sso(&sp_desc, &received, subject, RespondSso::post()).unwrap();
    let b64 = resp
        .post_form()
        .unwrap()
        .fields()
        .iter()
        .find(|f| f.name() == "SAMLResponse")
        .unwrap()
        .value()
        .to_string();
    (b64, request_id)
}

#[cfg(feature = "saml")]
fn saml_base_cfg() -> SamlCfg {
    SamlCfg {
        idp_sso_url: SAML_IDP_SSO.into(),
        idp_entity_id: SAML_IDP_ENTITY.into(),
        sp_entity_id: SAML_SP_ENTITY.into(),
        acs_url: SAML_ACS.into(),
        idp_x509_cert: SAML_TEST_CERT.into(),
        attr_username: String::new(),
        attr_groups: "groups".into(),
        want_assertions_signed: true,
        sign_authn_requests: false,
        allowed_clock_skew_s: 60,
        require_group_match: true,
    }
}

/// Décode base64 STANDARD -> XML, applique une mutation, ré-encode.
#[cfg(feature = "saml")]
fn saml_mutate(b64: &str, f: impl FnOnce(String) -> String) -> String {
    let xml = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(b64.trim()).unwrap()).unwrap();
    base64::engine::general_purpose::STANDARD.encode(f(xml).as_bytes())
}

// ================================ tests ADVERSAIRES de l'ACS ================================

#[cfg(feature = "saml")]
#[test]
fn saml_acs_valid_assertion_accepted() {
    let (b64, req) = saml_gen_signed_response();
    let mut store = BoundedReplayStore::new(16);
    let r = saml_verify_and_extract(&saml_base_cfg(), &b64, &req, now(), &mut store);
    let (user, _groups) = r.expect("une assertion valide et signée doit être acceptée");
    assert_eq!(user, "alice");
}

#[cfg(feature = "saml")]
#[test]
fn saml_acs_unsigned_assertion_rejected() {
    let (b64, req) = saml_gen_signed_response();
    // retire la Signature enveloppée -> l'assertion n'est plus signée -> RequireSigned rejette (#1).
    let stripped = saml_mutate(&b64, |xml| {
        let start = xml.find("<ds:Signature").expect("signature ds: présente");
        let end = xml.find("</ds:Signature>").expect("fin signature") + "</ds:Signature>".len();
        let mut out = xml.clone();
        out.replace_range(start..end, "");
        out
    });
    let mut store = BoundedReplayStore::new(16);
    assert!(saml_verify_and_extract(&saml_base_cfg(), &stripped, &req, now(), &mut store).is_err());
}

#[cfg(feature = "saml")]
#[test]
fn saml_acs_tampered_signature_rejected() {
    let (b64, req) = saml_gen_signed_response();
    let tampered = saml_mutate(&b64, |xml| {
        let s = xml.find("<ds:SignatureValue>").unwrap() + "<ds:SignatureValue>".len();
        let mut out = xml.clone();
        let ch = out.as_bytes()[s];
        let repl = if ch == b'A' { b'B' } else { b'A' };
        unsafe { out.as_bytes_mut()[s] = repl; }
        out
    });
    let mut store = BoundedReplayStore::new(16);
    assert!(saml_verify_and_extract(&saml_base_cfg(), &tampered, &req, now(), &mut store).is_err());
}

#[cfg(feature = "saml")]
#[test]
fn saml_acs_wrong_audience_rejected() {
    let (b64, req) = saml_gen_signed_response();
    let mut cfg = saml_base_cfg();
    cfg.sp_entity_id = "https://attacker.example.com/metadata".into(); // Audience != sp_entity_id (#5)
    let mut store = BoundedReplayStore::new(16);
    assert!(saml_verify_and_extract(&cfg, &b64, &req, now(), &mut store).is_err());
}

#[cfg(feature = "saml")]
#[test]
fn saml_acs_wrong_recipient_rejected() {
    let (b64, req) = saml_gen_signed_response();
    let mut cfg = saml_base_cfg();
    cfg.acs_url = "https://attacker.example.com/acs".into(); // Recipient/Destination != acs_url (#6)
    let mut store = BoundedReplayStore::new(16);
    assert!(saml_verify_and_extract(&cfg, &b64, &req, now(), &mut store).is_err());
}

#[cfg(feature = "saml")]
#[test]
fn saml_acs_wrong_issuer_rejected() {
    let (b64, req) = saml_gen_signed_response();
    let mut cfg = saml_base_cfg();
    cfg.idp_entity_id = "https://evil-idp.example.com/metadata".into(); // Issuer != idp_entity_id (#9)
    let mut store = BoundedReplayStore::new(16);
    assert!(saml_verify_and_extract(&cfg, &b64, &req, now(), &mut store).is_err());
}

#[cfg(feature = "saml")]
#[test]
fn saml_acs_expired_rejected() {
    let (b64, req) = saml_gen_signed_response();
    let mut store = BoundedReplayStore::new(16);
    // horloge 1h dans le FUTUR -> NotOnOrAfter dépassé (#7).
    assert!(saml_verify_and_extract(&saml_base_cfg(), &b64, &req, now() + 3600, &mut store).is_err());
}

#[cfg(feature = "saml")]
#[test]
fn saml_acs_not_yet_valid_rejected() {
    let (b64, req) = saml_gen_signed_response();
    let mut store = BoundedReplayStore::new(16);
    // horloge 1h dans le PASSÉ -> NotBefore pas atteint (#7).
    assert!(saml_verify_and_extract(&saml_base_cfg(), &b64, &req, now() - 3600, &mut store).is_err());
}

#[cfg(feature = "saml")]
#[test]
fn saml_acs_inresponseto_mismatch_rejected() {
    let (b64, _req) = saml_gen_signed_response();
    let mut store = BoundedReplayStore::new(16);
    // request_id attendu != InResponseTo de la réponse (#8a).
    assert!(saml_verify_and_extract(&saml_base_cfg(), &b64, "_unexpected-request-id", now(), &mut store).is_err());
}

#[cfg(feature = "saml")]
#[test]
fn saml_acs_replayed_assertion_rejected() {
    let (b64, req) = saml_gen_signed_response();
    let mut store = BoundedReplayStore::new(16);
    // 1er passage OK, 2e (MÊME assertion) -> rejeu détecté (#8b).
    assert!(saml_verify_and_extract(&saml_base_cfg(), &b64, &req, now(), &mut store).is_ok());
    assert!(saml_verify_and_extract(&saml_base_cfg(), &b64, &req, now(), &mut store).is_err());
}

#[cfg(feature = "saml")]
#[test]
fn saml_acs_wrong_certificate_rejected() {
    let (b64, req) = saml_gen_signed_response();
    let mut cfg = saml_base_cfg();
    // cert IdP ne correspondant PAS à la clé de signature (#1) : self-signed d'un autre émetteur.
    cfg.idp_x509_cert = SAML_OTHER_CERT.into();
    let mut store = BoundedReplayStore::new(16);
    assert!(saml_verify_and_extract(&cfg, &b64, &req, now(), &mut store).is_err());
}

#[cfg(feature = "saml")]
#[test]
fn saml_acs_sha1_algorithm_rejected() {
    // Une réponse annonçant RSA-SHA1 est refusée AVANT toute vérif crypto (#11).
    let xml = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/></ds:SignedInfo></ds:Signature></samlp:Response>"#
    );
    let b64 = base64::engine::general_purpose::STANDARD.encode(xml.as_bytes());
    let mut store = BoundedReplayStore::new(16);
    let e = saml_verify_and_extract(&saml_base_cfg(), &b64, "_r", now(), &mut store).unwrap_err();
    assert!(e.contains("SHA-1") || e.to_lowercase().contains("faible"), "erreur d'algorithme attendue: {e}");
}

#[cfg(feature = "saml")]
#[test]
fn saml_acs_charref_obfuscated_sha1_rejected() {
    // RÉGRESSION PERMANENTE (#11) : une garde par SOUS-CHAÎNES est ÉVADABLE via
    // références de caractères XML. On réécrit la SignatureMethod d'une VRAIE réponse valide en la forme
    // obfusquée `...#rsa-sha&#49;` / `&#x31;` : aucune sous-chaîne `#rsa-sha1` dans le texte brut (l'ancien
    // denylist PASSAIT), mais bergshamra décode `&#49;`/`&#x31;` -> `1` au moment de la vérif -> SHA-1 validé.
    // La garde par ALLOWLIST sur DOM décodé (MÊME parseur que le vérifieur) l'attrape AVANT toute vérif crypto.
    for obf in ["rsa-sha&#49;", "rsa-sha&#x31;"] {
        let (b64, req) = saml_gen_signed_response();
        // Seule la SignatureMethod porte `rsa-sha256` (le digest est `#sha256`) -> réécriture ciblée.
        let evil = saml_mutate(&b64, |xml| xml.replace("rsa-sha256", obf));
        let mut store = BoundedReplayStore::new(16);
        let e = saml_verify_and_extract(&saml_base_cfg(), &evil, &req, now(), &mut store)
            .expect_err("SHA-1 obfusqué par char-ref DOIT être rejeté par la garde #11");
        assert!(
            e.to_lowercase().contains("faible") || e.contains("SHA-1") || e.contains("allowlist"),
            "rejet attendu par la garde d'algorithme (obf={obf}): {e}"
        );
    }
    // NON-RÉGRESSION : une réponse rsa-sha256 LÉGITIME (non mutée) reste ACCEPTÉE (l'allowlist ne faux-rejette
    // pas les algos forts).
    let (b64, req) = saml_gen_signed_response();
    let mut store = BoundedReplayStore::new(16);
    assert!(
        saml_verify_and_extract(&saml_base_cfg(), &b64, &req, now(), &mut store).is_ok(),
        "un algorithme fort (rsa-sha256) ne doit JAMAIS être faux-rejeté par la garde #11"
    );
}

#[cfg(feature = "saml")]
#[test]
fn saml_acs_xsw_duplicate_assertion_rejected() {
    let (b64, req) = saml_gen_signed_response();
    // XSW : duplique l'assertion signée (MÊME ID) -> duplicate_saml_id / PotentialWrappingAttack (#2).
    let attacked = saml_mutate(&b64, |xml| {
        let a = xml.find("<saml:Assertion").expect("assertion");
        let end = xml.find("</saml:Assertion>").expect("fin assertion") + "</saml:Assertion>".len();
        let assertion = xml[a..end].to_string();
        xml.replacen("</samlp:Response>", &format!("{assertion}</samlp:Response>"), 1)
    });
    let mut store = BoundedReplayStore::new(16);
    assert!(saml_verify_and_extract(&saml_base_cfg(), &attacked, &req, now(), &mut store).is_err());
}

#[cfg(feature = "saml")]
#[test]
fn saml_acs_xsw_second_forged_assertion_rejected() {
    let (b64, req) = saml_gen_signed_response();
    // XSW : injecte une 2e assertion FORGÉE (ID différent, non signée) avant la vraie -> assertions.len()>1
    // -> PotentialWrappingAttack (#2).
    let forged = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_forged-evil" Version="2.0" IssueInstant="2099-01-01T00:00:00Z"><saml:Issuer>https://idp.example.com/metadata</saml:Issuer><saml:Subject><saml:NameID>attacker</saml:NameID></saml:Subject></saml:Assertion>"#;
    let attacked = saml_mutate(&b64, |xml| xml.replacen("<saml:Assertion", &format!("{forged}<saml:Assertion"), 1));
    let mut store = BoundedReplayStore::new(16);
    assert!(saml_verify_and_extract(&saml_base_cfg(), &attacked, &req, now(), &mut store).is_err());
}

#[cfg(feature = "saml")]
#[test]
fn saml_acs_status_not_success_rejected() {
    let (b64, req) = saml_gen_signed_response();
    // StatusCode Success -> Requester (le statut vit sur la Response, hors assertion signée) (#10).
    let attacked = saml_mutate(&b64, |xml| {
        xml.replace("urn:oasis:names:tc:SAML:2.0:status:Success", "urn:oasis:names:tc:SAML:2.0:status:Requester")
    });
    let mut store = BoundedReplayStore::new(16);
    assert!(saml_verify_and_extract(&saml_base_cfg(), &attacked, &req, now(), &mut store).is_err());
}

// cert self-signé d'un AUTRE émetteur (clé RSA différente, VALIDE) — pour le test « mauvais certificat ».
#[cfg(feature = "saml")]
const SAML_OTHER_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIDCTCCAfGgAwIBAgIUSkHkPVvhe/bBDRG45ixa8r+g9IswDQYJKoZIhvcNAQEL\nBQAwFDESMBAGA1UEAwwJb3RoZXItaWRwMB4XDTI2MDcxNzE2MDI0OFoXDTM2MDcx\nNDE2MDI0OFowFDESMBAGA1UEAwwJb3RoZXItaWRwMIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEA5rdA1HQD8sKgoLXkWG3Nkf7my+i5fmZIZo9i9QapoqYx\n0YqEfgn4nWoNI5klI8Bsxx2PbXFb9LO2BO+NLfxb+3j8stiiDzgFaRQyrFp3CMvw\n8GrM+m7TqzrcP00dWeilZPHZB/j7FNe4H3Le5RIV5r1crBSBNiRylVmc8V7oUh9n\nEktB3Y0dV9wUpqmO88kRW7lfAUx6iAbaORYB2vsot0SWCWaxJAPECjsHRhmkBWVL\nCGKBACH6coTMWW4bvcT7MKL+bczr9HXu2Af2BzPddyp1731TpXtVKmcanZa4UIOM\nSZbTwEzQ4kvt3F4PfdbKeO0M/XJiFi2K0ZOKfYjr9wIDAQABo1MwUTAdBgNVHQ4E\nFgQU5mGxat+q1bDaiTL/kOnVxFWfGXQwHwYDVR0jBBgwFoAU5mGxat+q1bDaiTL/\nkOnVxFWfGXQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAtVcE\nH5uLPxQWOfLN/ApVqhcIyYmfhSGrcrYEBj5o8oOASy1NFsFJMG2P6KxfMH96+XHe\nXQHZCRGZ1E6qMzevhKaGJQKkc6jPAEjCiJcdT4HyxhGIjt/+Cj+GHEmoZ8uOdhAz\nCK8h89f2Ebk88YIuzQJSsN9wN6rGIMqj428xnM1IZ8K1neE/IdxF2Xt+yNdlVmMO\nId8MKVR2a9xB8xpWvf3Cfz/28bWkntx4zViKg7E9S5Xxwe44TTri7vU33FxudMeN\n0N33qVT/K6KUr2wb4qsz80t63nS3wPlBUkwFafUHBv7JQlvEaUh7B2VGQtkG2n4O\nhK0oCxMy/kKMe28ztQ==\n-----END CERTIFICATE-----\n";
