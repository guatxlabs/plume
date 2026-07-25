// Tests de durcissement sécurité : audit d'identité, ledger keyé, garde SSRF, shred du clair, CSRF SSO,
// SCIM tenant-scopé, self-detection.
// Inclus dans le module `tests` (voir mod.rs) -> tous les helpers partagés (test_db, tenant_test_state,
// mk_test_control, ensure_platform_user, tok_resp_json, ergo_au, open_db_keyed…) sont en portée.

// ------------------------------------------------------------------------------------------------
// AUDIT D'IDENTITÉ — les mutations d'IDENTITÉ émettent un audit fail-closed (ledger + event plume-config)
// et la règle de self-detection MATCHE. Couvre create (admin), role_change, password_reset, delete.
// ------------------------------------------------------------------------------------------------
#[tokio::test]
async fn sec_c1_identity_mutations_audited_and_rule_matches() {
    let st = sso_test_state("admins", "editors", "supers"); // mode 0 (control None) -> base user en mémoire
    let admin = ergo_au("admin");

    // 1) CREATE d'un ADMIN -> 200 + event action=config.user.create + ledger.
    let (code, v) = tok_resp_json(
        user_create(State(st.clone()), Extension(admin.clone()),
            Json(json!({ "name": "eviladmin", "password": "longenoughpw12", "role": "admin" }))).await,
    ).await;
    assert_eq!(code, StatusCode::OK, "create admin -> 200");
    assert!(v.get("id").is_some(), "id renvoyé");

    // 2) ROLE_CHANGE (admin->viewer sur un 2e compte) + PASSWORD_RESET.
    let (_c, v2) = tok_resp_json(
        user_create(State(st.clone()), Extension(admin.clone()),
            Json(json!({ "name": "bob", "password": "longenoughpw12", "role": "editor" }))).await,
    ).await;
    let bob_id = v2["id"].as_i64().unwrap();
    let r = user_update(State(st.clone()), Extension(admin.clone()), axum::extract::Path(bob_id),
        Json(json!({ "role": "viewer", "password": "anotherlongpw34" }))).await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT, "role_change + reset -> 204");

    // 3) DELETE (bob).
    let rd = user_delete(State(st.clone()), Extension(admin.clone()), axum::extract::Path(bob_id)).await;
    assert_eq!(rd.status(), StatusCode::NO_CONTENT, "delete -> 204");

    // --- vérifs base : ledger + events plume-config action=config.user.* ---
    let conn = st.db.lock();
    let ledger_kinds: i64 = conn.query_row(
        "SELECT COUNT(*) FROM ledger WHERE kind IN ('config.user.create','config.user.role_change','config.user.password_reset','config.user.delete')",
        [], |r| r.get(0)).unwrap();
    assert_eq!(ledger_kinds, 5, "5 entrées ledger d'identité (2 create, 1 role_change, 1 password_reset, 1 delete)");
    let cfg_events: i64 = conn.query_row(
        "SELECT COUNT(*) FROM event WHERE source='plume-config' AND category='config' AND json_extract(fields,'$.action') LIKE 'config.user.%'",
        [], |r| r.get(0)).unwrap();
    assert_eq!(cfg_events, 5, "5 events plume-config action=config.user.* (aucune mutation d'identité sans trace)");
    // aucun secret/hash dans l'audit
    let leak: i64 = conn.query_row(
        "SELECT COUNT(*) FROM event WHERE source='plume-config' AND (fields LIKE '%hash%' OR fields LIKE '%$argon2%' OR fields LIKE '%longenoughpw%')",
        [], |r| r.get(0)).unwrap();
    assert_eq!(leak, 0, "aucun hash / mot de passe dans l'audit d'identité");

    // --- la règle SEC4 C1 (identité) MATCHE (count>0) ---
    let sql = soql_to_sql_x("search source=plume-config action=config.user.* | stats count", 0, 0, None).unwrap();
    let n: i64 = conn.query_row(&sql, [], |r| r.get(0)).unwrap();
    assert!(n >= 5, "règle identité : count={n} > 0 (matche les mutations)");

    // --- la requête M1 (config-tamper) COMPTE bien les events config (le SEUIL de rafale est testé à part) ---
    let sql_m1 = soql_to_sql_x("search source=plume-config category=config | stats count", 0, 0, None).unwrap();
    let n1: i64 = conn.query_row(&sql_m1, [], |r| r.get(0)).unwrap();
    assert!(n1 >= 5, "la requête M1 compte les mutations de config");
}

/// AUDIT D'IDENTITÉ fail-closed CONTRE-ÉPREUVE : un nom en doublon -> 409 ET aucune ligne user/ledger/event créée.
#[tokio::test]
async fn sec_c1_duplicate_name_conflict_no_partial() {
    let st = sso_test_state("admins", "editors", "supers");
    let admin = ergo_au("admin");
    let _ = user_create(State(st.clone()), Extension(admin.clone()),
        Json(json!({ "name": "dup", "password": "longenoughpw12", "role": "editor" }))).await;
    let r = user_create(State(st.clone()), Extension(admin.clone()),
        Json(json!({ "name": "dup", "password": "longenoughpw12", "role": "editor" }))).await;
    assert_eq!(r.status(), StatusCode::CONFLICT, "nom en doublon -> 409 (sémantique préservée)");
    let conn = st.db.lock();
    assert_eq!(conn.query_row::<i64,_,_>("SELECT COUNT(*) FROM user WHERE name='dup'", [], |r| r.get(0)).unwrap(), 1, "un seul compte 'dup'");
    assert_eq!(conn.query_row::<i64,_,_>("SELECT COUNT(*) FROM ledger WHERE kind='config.user.create'", [], |r| r.get(0)).unwrap(), 1, "un seul audit create (le doublon n'a rien écrit)");
}

/// SEC4 — les 4 règles de self-detection sont SEEDÉES sur PVC neuf ET BACKFILLÉES par migrate_v100 sur une
/// instance live (sans doublon, idempotent).
#[test]
fn sec4_rules_seeded_and_backfilled_idempotent() {
    let names = [
        "SOC: mutation d'identité (compte créé / rôle / reset mdp / suppression)",
        "SOC: rafale de mutations de configuration (tamper-evidence plume-config)",
        "SOC: rafale de dénis RBAC sur route mutante (recon/priv-esc)",
        "SOC: lecture/export de masse (exfiltration potentielle)",
    ];
    let conn = test_db(); // schema + migrate (seeded flag absent -> v100 SKIP)
    seed_detection_rules(&conn); // pose le flag + toutes les règles dont SEC4
    let present = |c: &Connection| -> i64 {
        names.iter().map(|n| c.query_row("SELECT COUNT(*) FROM rule WHERE name=?1", params![n], |r| r.get::<_,i64>(0)).unwrap()).sum()
    };
    assert_eq!(present(&conn), 4, "seed_detection_rules pose les 4 règles de self-detection");

    // Simule une instance LIVE antérieure à SEC4 : règles absentes + version < 100 + seeded flag présent.
    for n in names { conn.execute("DELETE FROM rule WHERE name=?1", params![n]).unwrap(); }
    conn.execute("UPDATE meta SET value='99' WHERE key='schema_version'", []).unwrap();
    assert_eq!(present(&conn), 0, "règles retirées (simulation d'un état antérieur)");
    let _ = migrate(&conn); // v<100 -> migrate_v100 backfill (seeded présent)
    assert_eq!(present(&conn), 4, "migrate_v100 backfille les 4 règles de self-detection sur instance live");
    // idempotent : re-migrer ne duplique pas.
    let _ = migrate(&conn);
    assert_eq!(present(&conn), 4, "backfill idempotent (aucun doublon)");
}

// ------------------------------------------------------------------------------------------------
// LEDGER — verify_ledger_conn ne PANIQUE JAMAIS : Ok sur base keyée lisible, Err sur clé incorrecte /
// ledger illisible ; broken=Some sur falsification. verify_ledger (wrapper prod) OK sur base en clair.
// ------------------------------------------------------------------------------------------------
#[test]
fn sec_h1_verify_ledger_keyed_never_panics() {
    // Schéma minimal ledger+checkpoint (colonnes réelles de ledger_append / sign_checkpoint).
    let ddl = "CREATE TABLE ledger(id INTEGER PRIMARY KEY, ts INTEGER, kind TEXT, detail TEXT, prev_hash TEXT, hash TEXT);\
               CREATE TABLE checkpoint(id INTEGER PRIMARY KEY, ts INTEGER, ledger_hash TEXT, sig TEXT, pubkey TEXT);";

    // (a) base CHIFFRÉE (SQLCipher) lisible AVEC la bonne clé -> Ok, chaîne intègre.
    let p = mk_tmp_path("h1-keyed.db");
    {
        let c = open_db_keyed(&p, Some("cipher-key-1")).unwrap();
        c.execute_batch(ddl).unwrap();
        ledger_append(&c, "config.user.create", "compte 'x' créé");
        ledger_append(&c, "config.mode", "mode passif");
    }
    {
        let c = open_db_keyed(&p, Some("cipher-key-1")).unwrap();
        let (n, _ok, _bad, broken) = verify_ledger_conn(&c, None).expect("clé correcte -> Ok (pas de panic)");
        assert_eq!(n, 2, "2 entrées chaînées");
        assert!(broken.is_none(), "chaîne intègre");
    }

    // (b) MÊME base, MAUVAISE clé -> Err propre (pas de panic, pas d'unwrap).
    {
        let c = open_db_keyed(&p, Some("mauvaise-cle")).unwrap();
        let r = verify_ledger_conn(&c, None);
        assert!(r.is_err(), "clé incorrecte -> Err (l'outil rapporte au lieu de paniquer)");
    }

    // (c) FALSIFICATION : réécrire le detail d'une entrée -> broken=Some (chaîne cassée).
    {
        let c = open_db_keyed(&p, Some("cipher-key-1")).unwrap();
        c.execute("UPDATE ledger SET detail='FALSIFIÉ' WHERE id=1", []).unwrap();
        let (_n, _ok, _bad, broken) = verify_ledger_conn(&c, None).expect("Ok (résultat), rupture détectée");
        assert!(broken.is_some(), "falsification -> rupture de chaîne signalée");
    }

    // (d) wrapper prod verify_ledger sur base EN CLAIR (apply_key no-op hors env) -> Ok. Ne teste que si
    //     PLUME_DB_KEY n'est pas posé dans l'env (sinon apply_key tenterait un PRAGMA key sur du clair).
    if std::env::var("PLUME_DB_KEY").map(|v| v.is_empty()).unwrap_or(true) {
        let p2 = mk_tmp_path("h1-plain.db");
        {
            let c = open_db_keyed(&p2, None).unwrap();
            c.execute_batch(ddl).unwrap();
            ledger_append(&c, "config.user.delete", "compte 'y' supprimé");
        }
        let (n, _o, _b, broken) = verify_ledger(&p2).expect("base en clair lisible -> Ok");
        assert_eq!(n, 1);
        assert!(broken.is_none());
        let _ = std::fs::remove_file(&p2);
    }
    let _ = std::fs::remove_file(&p);
}

// ------------------------------------------------------------------------------------------------
// v134 (#11) — PIN escrow OPTIONNEL du pubkey ledger (PLUME_LEDGER_PUBKEY) : un checkpoint dont le pubkey
// IN-BAND != le pubkey épinglé FAIL (re-signature d'un attaquant DB-write-sans-ledger.key). Épinglé=match
// -> PASSE ; épinglé!=in-band -> ÉCHOUE. UNSET -> comportement historique (confiance au pubkey in-band).
// ------------------------------------------------------------------------------------------------
#[test]
fn v134_ledger_pubkey_pin_rejects_resign() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
    let _ = migrate(&conn);
    // clé qui SIGNE le checkpoint (son pubkey devient le pubkey IN-BAND stocké dans la ligne checkpoint).
    let legit = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let legit_pub = legit.verifying_key().to_bytes();
    ledger_append(&conn, "config.mode", "mode passif");
    sign_checkpoint(&conn, &legit);

    // sanity — SANS pin : la signature in-band est valide (comportement historique préservé).
    let (_n, ok0, bad0, broken0) = verify_ledger_conn(&conn, None).expect("verify OK");
    assert!(ok0 >= 1 && bad0 == 0 && broken0.is_none(), "sans pin -> signature in-band valide");
    // (1) PIN == pubkey in-band -> PASSE.
    let (_n, ok1, bad1, _b) = verify_ledger_conn(&conn, Some(&legit_pub)).expect("verify OK");
    assert!(ok1 >= 1 && bad1 == 0, "pin == pubkey in-band -> vérif PASSE");
    // (2) PIN != pubkey in-band (le checkpoint est signé par 'legit' mais l'escrow de confiance est 'other' :
    //     simule une re-signature attaquant, in-band auto-cohérent mais NON de confiance) -> ÉCHOUE.
    let other_pub = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();
    let (_n, ok2, bad2, _b) = verify_ledger_conn(&conn, Some(&other_pub)).expect("verify OK (résultat)");
    assert!(ok2 == 0 && bad2 >= 1, "pin != pubkey in-band -> vérif ÉCHOUE (re-signature rejetée)");

    // parsing du pin : hex 64 chars (format checkpoint) ET base64 -> mêmes 32 octets ; invalide -> None.
    let hex = hex_encode(&legit_pub);
    assert_eq!(parse_ed25519_pubkey(&hex), Some(legit_pub), "hex 64 -> 32 octets");
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(legit_pub);
    assert_eq!(parse_ed25519_pubkey(&b64), Some(legit_pub), "base64 -> 32 octets");
    assert_eq!(parse_ed25519_pubkey("zz"), None, "invalide -> None");

    // ledger_pinned_pubkey() lit PLUME_LEDGER_PUBKEY (var touchée par ce SEUL test -> race-safe).
    let save = std::env::var("PLUME_LEDGER_PUBKEY").ok();
    std::env::remove_var("PLUME_LEDGER_PUBKEY");
    assert_eq!(ledger_pinned_pubkey(), None, "non posé -> None (comportement historique)");
    std::env::set_var("PLUME_LEDGER_PUBKEY", &hex);
    assert_eq!(ledger_pinned_pubkey(), Some(legit_pub), "posé -> pin actif");
    match save { Some(v) => std::env::set_var("PLUME_LEDGER_PUBKEY", v), None => std::env::remove_var("PLUME_LEDGER_PUBKEY") }
}

// ------------------------------------------------------------------------------------------------
// GARDE SSRF — rejette loopback / link-local (metadata) / RFC1918 / IPv6 interne / schéma
// interdit / hôte résolvant en interne ; laisse passer un hôte public. Fonction réutilisable unique.
// ------------------------------------------------------------------------------------------------
#[test]
fn sec2_ssrf_guard_blocks_internal_allows_public() {
    // NEVER-EGRESS = REFUS INCONDITIONNEL : metadata (link-local), loopback, unspecified, IPv4-mapped IPv6.
    for bad in [
        "http://169.254.169.254/latest/meta-data/",   // AWS/GCP metadata (link-local)
        "https://169.254.169.254/",
        "http://127.0.0.1:8200/v1/secret",             // loopback
        "http://[::1]/",                               // loopback IPv6
        "smtp://127.0.0.1:25",                          // loopback (canal email)
        "http://localhost/",                           // résout vers 127.0.0.1 (re-check DNS)
        // FIX #2 — contournements d'encodage désormais FERMÉS :
        "http://[::ffff:169.254.169.254]/",            // IPv4-mapped IPv6 de la metadata
        "http://0.0.0.0/",                             // unspecified v4 (résout loopback sous Linux)
        "http://[::]/",                                // unspecified v6
    ] {
        assert!(ssrf_guard(bad).is_err(), "SSRF doit REFUSER {bad}");
    }
    // schémas interdits.
    for bad in ["file:///etc/passwd", "gopher://x/", "ftp://host/", "-oProxyCommand=x"] {
        assert!(ssrf_guard(bad).is_err(), "SSRF doit REFUSER le schéma de {bad}");
    }
    // FIX #3 (on-prem) — RFC1918 AUTORISÉ PAR DÉFAUT (relais SMTP interne / webhook / IdP OIDC on-prem légitimes).
    for onprem in ["http://10.1.2.3/api", "http://172.16.9.9/", "http://192.168.1.10/hook", "smtp://10.0.0.25:25"] {
        assert!(ssrf_guard(onprem).is_ok(), "SSRF doit AUTORISER le RFC1918 on-prem par défaut : {onprem}");
    }
    // hôtes PUBLICS (IP littérale -> pas de DNS requis en test) = OK.
    for ok in ["http://93.184.216.34/", "https://93.184.216.34:8443/x", "smtp://93.184.216.34:587"] {
        assert!(ssrf_guard(ok).is_ok(), "SSRF doit AUTORISER {ok}");
    }
    // egress_url_ok (notifiers) = safe_url(schéma) ET ssrf_guard.
    assert!(!egress_url_ok("http://169.254.169.254/"), "notifier egress metadata -> refus");
    assert!(!egress_url_ok("http://[::ffff:169.254.169.254]/"), "notifier egress metadata mapped-v6 -> refus");
    assert!(egress_url_ok("https://93.184.216.34/"), "notifier egress public -> ok");
    assert!(egress_url_ok("http://10.20.30.40/hook"), "notifier egress RFC1918 on-prem -> ok par défaut");
}

/// FIX #2/#3 — politique SSRF au niveau IP (testable sans env global) : never-egress INCONDITIONNEL (loopback/
/// link-local=metadata/unspecified/ULA + IPv4-mapped) ; RFC1918 uniquement quand `block_private=true`.
#[test]
fn sec2_ssrf_ip_policy_and_cidr_allow() {
    use std::net::IpAddr;
    let ip = |s: &str| ssrf_norm_ip(s).unwrap();
    // never-egress -> bloqué QUEL QUE SOIT block_private.
    for s in ["127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "::", "fe80::1", "fc00::1", "fd12::9",
              "::ffff:169.254.169.254", "::ffff:127.0.0.1"] {
        assert!(ssrf_blocked_policy(ip(s), false), "{s} never-egress -> bloqué (block_private off)");
        assert!(ssrf_blocked_policy(ip(s), true),  "{s} never-egress -> bloqué (block_private on)");
    }
    // RFC1918 : autorisé par défaut, bloqué si opt-in.
    for s in ["10.1.2.3", "172.16.0.9", "172.31.255.254", "192.168.1.10"] {
        assert!(!ssrf_blocked_policy(ip(s), false), "{s} RFC1918 -> AUTORISÉ par défaut");
        assert!(ssrf_blocked_policy(ip(s), true),   "{s} RFC1918 -> bloqué si PLUME_SSRF_BLOCK_PRIVATE=1");
    }
    // public -> jamais bloqué.
    for s in ["93.184.216.34", "8.8.8.8"] {
        assert!(!ssrf_blocked_policy(ip(s), false) && !ssrf_blocked_policy(ip(s), true), "{s} public -> autorisé");
    }
    // FIX #3 — allowlist CIDR : une entrée `10.20.0.0/16` couvre TOUTE sa plage, pas seulement un hôte exact.
    let entry = parse_ssrf_allow("10.20.0.0/16").expect("CIDR parseable");
    let (net, bits) = match entry { SsrfAllow::Net(n, b) => (n, b), _ => panic!("CIDR -> Net") };
    assert!(ip_in_cidr("10.20.5.6".parse::<IpAddr>().unwrap(), net, bits), "10.20.5.6 ∈ 10.20.0.0/16");
    assert!(ip_in_cidr("10.20.255.255".parse::<IpAddr>().unwrap(), net, bits), "borne haute ∈ /16");
    assert!(!ip_in_cidr("10.21.0.1".parse::<IpAddr>().unwrap(), net, bits), "10.21.0.1 ∉ 10.20.0.0/16");
    // une IP nue s'interprète en /32 exact.
    match parse_ssrf_allow("203.0.113.7").unwrap() {
        SsrfAllow::Net(n, b) => { assert_eq!(b, 32); assert!(ip_in_cidr("203.0.113.7".parse().unwrap(), n, b)); assert!(!ip_in_cidr("203.0.113.8".parse().unwrap(), n, b)); }
        _ => panic!("IP nue -> Net /32"),
    }
}

// ------------------------------------------------------------------------------------------------
// SHRED — shred_file écrase puis supprime une copie EN CLAIR (mécanisme de nettoyage du .plaintext.bak).
// ------------------------------------------------------------------------------------------------
#[test]
fn sec2_shred_file_overwrites_and_removes() {
    let p = mk_tmp_path("plaintext.bak");
    std::fs::write(&p, b"secret-plaintext-database-contents").unwrap();
    assert!(std::path::Path::new(&p).exists());
    shred_file(&p);
    assert!(!std::path::Path::new(&p).exists(), "shred_file supprime la copie en clair");
    // idempotent / best-effort sur fichier absent (ne panique pas).
    shred_file(&p);
}

// ------------------------------------------------------------------------------------------------
// SELF-DETECTION — un déni RBAC mutant émet source=plume-authz action=denied ; la règle rafale (>10/principal)
// MATCHE au-delà du seuil et PAS en-dessous (mode-0-inert : aucun event si rien n'est refusé).
// ------------------------------------------------------------------------------------------------
#[tokio::test]
async fn sec_m2_authz_denied_ingest_and_rule() {
    let st = sso_test_state("admins", "editors", "supers");
    // sous le seuil : 5 dénis d'un principal -> la règle NE tire PAS.
    for _ in 0..5 { ingest_authz_denied(&st, "faible", "viewer", "/api/notifiers", "POST"); }
    let sql = soql_to_sql_x(
        "search source=plume-authz action=denied | stats count by principal | where count > 10 | stats count", 0, 0, None).unwrap();
    {
        let conn = st.db.lock();
        let n: i64 = conn.query_row(&sql, [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "5 dénis < seuil 10 -> règle ne tire pas");
    }
    // au-dessus du seuil : 11 dénis d'un MÊME principal -> la règle tire (1 principal en rafale).
    for _ in 0..11 { ingest_authz_denied(&st, "mallory", "viewer", "/api/mode", "POST"); }
    {
        let conn = st.db.lock();
        let n: i64 = conn.query_row(&sql, [], |r| r.get(0)).unwrap();
        assert!(n >= 1, "11 dénis > seuil -> règle tire (count={n})");
        // pas de secret dans l'event authz.
        let leak: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE source='plume-authz' AND fields LIKE '%pass%'", [], |r| r.get(0)).unwrap();
        assert_eq!(leak, 0);
    }
}

// ------------------------------------------------------------------------------------------------
// SELF-DETECTION — audit_bulk_read émet SEULEMENT au-delà du seuil de lignes ; la règle export-de-masse matche.
// ------------------------------------------------------------------------------------------------
#[tokio::test]
async fn sec_m3_bulk_read_audit_and_rule() {
    let st = sso_test_state("admins", "editors", "supers");
    let au = ergo_au("admin");
    // sous le seuil (défaut 10 000) -> aucun event.
    audit_bulk_read(&st, &au, "export", 100);
    let sql = soql_to_sql_x("search source=plume-audit action=bulk_read | stats count", 0, 0, None).unwrap();
    {
        let conn = st.db.lock();
        assert_eq!(conn.query_row::<i64,_,_>(&sql, [], |r| r.get(0)).unwrap(), 0, "sous le seuil -> inerte");
    }
    // au-dessus du seuil -> event + règle tire.
    audit_bulk_read(&st, &au, "export", 25_000);
    {
        let conn = st.db.lock();
        assert!(conn.query_row::<i64,_,_>(&sql, [], |r| r.get(0)).unwrap() >= 1, "export de masse -> règle tire");
    }
}

// ------------------------------------------------------------------------------------------------
// CSRF — une mutation authentifiée SSO SANS Origin/Referer (ou d'origine étrangère) est REFUSÉE ;
// une même-origine passe ; le M2M Basic reste EXEMPTÉ.
// ------------------------------------------------------------------------------------------------
#[tokio::test]
async fn sec1_csrf_sso_mutation_requires_same_origin() {
    let st = sso_test_state("admins", "editors", "supers");
    let mk = |origin: Option<&str>| {
        let mut b = axum::http::Request::builder().method("POST").uri("/api/notifiers").header("host", "plume.local");
        if let Some(o) = origin { b = b.header("origin", o); }
        b.body(axum::body::Body::empty()).unwrap()
    };
    let gate = |req: &Request, method: &str| apply_gates(&st, req, "/api/notifiers", "admin", "default", true, false, "alice", method, "");

    // SSO mutant SANS Origin/Referer -> refus (fail-closed).
    assert!(gate(&mk(None), "sso").is_err(), "SSO mutation sans Origin -> refus CSRF");
    // SSO mutant, Origin ÉTRANGÈRE -> refus.
    assert!(gate(&mk(Some("https://evil.example")), "sso").is_err(), "SSO mutation origine étrangère -> refus");
    // SSO mutant, Origin = même hôte que Host -> OK.
    assert!(gate(&mk(Some("https://plume.local")), "sso").is_ok(), "SSO mutation same-origin -> OK");
    // M2M Basic (pas 'sso') -> EXEMPTÉ même sans Origin (M2M inchangé).
    assert!(gate(&mk(None), "basic").is_ok(), "Basic M2M -> exempté de CSRF (inchangé)");
}

// ------------------------------------------------------------------------------------------------
// SCIM — PUT/DELETE sur un id d'un AUTRE tenant -> 404 (existence tenant-scopée, comme le GET).
// ------------------------------------------------------------------------------------------------
#[tokio::test]
async fn sec1_scim_put_delete_tenant_scoped() {
    let cp = mk_test_control();
    let alice = ensure_platform_user(&cp, "alice").unwrap(); // t1
    let bob = ensure_platform_user(&cp, "bob").unwrap();       // t2
    {
        let c = cp.conn.lock();
        c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,'t1','editor')", params![alice]).unwrap();
        c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,'t2','editor')", params![bob]).unwrap();
    }
    let st = tenant_test_state("admins", "editors", "supers", Some(cp.clone()));
    let ctx = ScimCtx { tenant: "t1".into() };

    // PUT (replace) bob (t2) via token t1 -> 404 (avant : existence GLOBALE -> révélait/mutait cross-tenant).
    let (c1, _) = tok_resp_json(scim_user_replace(State(st.clone()), Extension(ctx.clone()),
        axum::extract::Path(bob.clone()), Json(json!({ "active": false }))).await).await;
    assert_eq!(c1, StatusCode::NOT_FOUND, "PUT bob (t2) via token t1 -> 404");

    // DELETE bob (t2) via token t1 -> 404.
    let rd = scim_user_delete(State(st.clone()), Extension(ctx.clone()), axum::extract::Path(bob.clone())).await.into_response();
    assert_eq!(rd.status(), StatusCode::NOT_FOUND, "DELETE bob (t2) via token t1 -> 404");

    // CONTRE-ÉPREUVE : PUT alice (membre t1) -> pas 404 (200).
    let (c2, _) = tok_resp_json(scim_user_replace(State(st.clone()), Extension(ctx.clone()),
        axum::extract::Path(alice.clone()), Json(json!({ "active": true }))).await).await;
    assert_eq!(c2, StatusCode::OK, "PUT alice (t1) -> 200 (accès légitime intact)");
}

// ------------------------------------------------------------------------------------------------
// FIX #1 (deploy-blocker) — les DESTINATIONS #50 (forward de la donnée SOC COMPLÈTE non masquée) sont
// gardées SSRF À LA CRÉATION (dest_endpoint_ok) ET AU POINT D'ÉGRESS (dest_transport). Une destination
// loopback/metadata/mapped/unspecified ne peut ni être créée ni jamais égresser ; RFC1918 on-prem passe.
// ------------------------------------------------------------------------------------------------
#[test]
fn sec_dest_ssrf_rejects_internal_endpoints() {
    // CRÉATION (dest_endpoint_ok) : webhook/hec vers never-egress = REFUS.
    for bad in ["http://127.0.0.1/hook", "http://169.254.169.254/", "https://[::1]/",
                "http://[::ffff:169.254.169.254]/", "http://0.0.0.0/"] {
        assert!(!dest_endpoint_ok("webhook", bad), "webhook interne refusé à la création : {bad}");
        assert!(!dest_endpoint_ok("hec", bad), "hec interne refusé : {bad}");
    }
    // syslog tcp:// vers loopback/metadata = REFUS.
    for bad in ["tcp://127.0.0.1:514", "tcp://169.254.169.254:514"] {
        assert!(!dest_endpoint_ok("syslog", bad), "syslog interne refusé : {bad}");
    }
    // public OK ; RFC1918 on-prem OK par défaut (parité notifiers, fix #3).
    assert!(dest_endpoint_ok("webhook", "https://93.184.216.34/hook"), "webhook public OK");
    assert!(dest_endpoint_ok("webhook", "http://10.0.0.9/hook"), "webhook RFC1918 on-prem OK par défaut");
    assert!(dest_endpoint_ok("syslog", "tcp://10.0.0.9:514"), "syslog RFC1918 on-prem OK par défaut");
    // ÉGRESS (dest_transport) : choke-point non contournable même si la ligne fut posée hors create/update.
    let wh = Wire::Http { method: "POST".into(), url: "http://169.254.169.254/".into(), headers: vec![], body: b"{}".to_vec() };
    assert!(dest_transport(&wh).is_err(), "égress webhook vers metadata bloqué au transport");
    let ws = Wire::Tcp { host: "127.0.0.1".into(), port: 514, body: b"x".to_vec() };
    assert!(dest_transport(&ws).is_err(), "égress syslog vers loopback bloqué au transport");
}

// ------------------------------------------------------------------------------------------------
// FIX #4 — notifier_create/update valident l'ÉGRESS (schéma + SSRF) : une cible interne (never-egress) est
// REFUSÉE IMMÉDIATEMENT (plus d'échec d'envoi silencieux) ; un endpoint RFC1918 on-prem légitime est accepté.
// ------------------------------------------------------------------------------------------------
#[tokio::test]
async fn sec_notifier_create_update_egress_guarded() {
    let st = sso_test_state("admins", "editors", "supers");
    let admin = ergo_au("admin");
    // never-egress -> refus explicite à la création (pas d'id).
    for bad in ["http://169.254.169.254/", "http://127.0.0.1/ntfy"] {
        let Json(v) = notifier_create(State(st.clone()), Extension(admin.clone()),
            Json(json!({ "kind": "webhook", "url": bad }))).await;
        assert!(v.get("error").is_some() && v.get("id").is_none(), "notifier interne {bad} refusé à la création");
    }
    // FIX #3 — endpoint RFC1918 on-prem légitime accepté PAR DÉFAUT.
    let Json(v) = notifier_create(State(st.clone()), Extension(admin.clone()),
        Json(json!({ "kind": "webhook", "url": "http://10.0.0.9/ntfy" }))).await;
    let id = v.get("id").and_then(|x| x.as_i64()).expect("RFC1918 on-prem accepté par défaut");
    // UPDATE ré-pointant vers la metadata -> 400 (pas de re-cible interne silencieuse).
    let code = notifier_update(State(st.clone()), Extension(admin.clone()),
        axum::extract::Path(id), Json(json!({ "url": "http://169.254.169.254/" }))).await;
    assert_eq!(code, StatusCode::BAD_REQUEST, "update vers metadata -> 400");
}

// ------------------------------------------------------------------------------------------------
// FIX #5 — la règle M1 (config-tamper) est une RAFALE (> 20/fenêtre), pas `count>0` : une administration
// quotidienne normale ne lève RIEN ; seul un burst anormal de mutations tire. (C1 identité reste count>0.)
// ------------------------------------------------------------------------------------------------
#[test]
fn sec_m1_config_tamper_is_burst_not_every_action() {
    let (_n, q, _is, op, th, _sev, _iv, _w, _mi) = DETECTION_RULES_SEC4[1];
    assert_eq!(op, ">", "M1 opère en seuil >");
    assert!(th >= 20.0, "M1 = rafale (seuil {th} >> 0), pas chaque action");
    let conn = test_db();
    let sql = soql_to_sql_x(q, 0, 0, None).unwrap();
    let ins = |c: &Connection, n: usize| for _ in 0..n {
        c.execute("INSERT INTO event(ts,source,category,severity,message,origin) VALUES(?1,'plume-config','config',3,'cfg','daemon')", params![now()]).unwrap();
    };
    // 15 mutations (admin normal) -> SOUS le seuil : la règle NE tirerait PAS (bruit éliminé).
    ins(&conn, 15);
    let c15: i64 = conn.query_row(&sql, [], |r| r.get(0)).unwrap();
    assert!(c15 <= th as i64, "15 mutations ({c15}) <= seuil {th} -> pas d'alerte");
    // +10 (tampering scripté) -> 25 > 20 : la règle tire.
    ins(&conn, 10);
    let c25: i64 = conn.query_row(&sql, [], |r| r.get(0)).unwrap();
    assert!(c25 > th as i64, "25 mutations ({c25}) > seuil {th} -> rafale détectée");
}

// ================================================================================================
// v105 CHANGE 1 — GARDE ANTI-DOWNGRADE. Cœur testable `schema_downgrade_guard` (sans exit process) :
// une base estampillée v103 est REFUSÉE par un binaire v102 ; une base <= CODE_SCHEMA_MAX ouvre.
// ================================================================================================
#[test]
fn v105_downgrade_guard_refuses_newer_db() {
    let conn = test_db(); // schema.sql + migrate() -> base fraîche estampillée à la version courante
    // (a) VERROU anti-dérive : une base migrée à blanc DOIT être exactement à CODE_SCHEMA_MAX (si ce test
    //     casse, c'est qu'une migration a été ajoutée sans bumper la constante -> corrige la constante).
    assert_eq!(read_schema_version(&conn), CODE_SCHEMA_MAX,
        "base migrée à blanc == CODE_SCHEMA_MAX (bumper la const avec chaque migration)");
    // (b) v == max -> Ok : chemin forward normal, aucun refus.
    assert_eq!(schema_downgrade_guard(&conn), Ok(CODE_SCHEMA_MAX), "v==max ouvre");
    // (c) v < max (base plus ancienne) -> Ok : sera migrée, pas de refus.
    conn.execute("UPDATE meta SET value=?1 WHERE key='schema_version'", params![(CODE_SCHEMA_MAX - 1).to_string()]).unwrap();
    assert_eq!(schema_downgrade_guard(&conn), Ok(CODE_SCHEMA_MAX - 1), "v<max migre (pas de refus)");
    // (d) v > max : base v103 ouverte par un binaire v102 -> Err(v) = REFUS (anti-corruption rollback).
    let newer = CODE_SCHEMA_MAX + 1; // v103 vs binaire v102
    conn.execute("UPDATE meta SET value=?1 WHERE key='schema_version'", params![newer.to_string()]).unwrap();
    assert_eq!(schema_downgrade_guard(&conn), Err(newer),
        "base v{newer} > CODE_SCHEMA_MAX REFUSÉE (un binaire ancien ne corrompt pas une base plus récente)");
}

// ================================================================================================
// v105 CHANGE 2 — ledger.key relocalisable (PLUME_LEDGER_KEY_PATH) + FAIL-CLOSED. Une clé lue depuis un
// chemin Secret ; refus de GÉNÉRER une nouvelle clé quand un chemin non-legacy (Secret) est absent/vide
// (préserve la continuité de vérification du ledger sur restore/DR).
// ================================================================================================
#[test]
fn v105_ledger_key_path_legacy_classification() {
    assert!(ledger_key_path_is_legacy(LEDGER_KEY_LEGACY_DEFAULT), "défaut compilé = legacy (auto-gen OK)");
    assert!(ledger_key_path_is_legacy("/data/ledger.key"), "/data (manifest live) = legacy");
    assert!(!ledger_key_path_is_legacy("/etc/plume/ledger/ledger.key"), "Secret monté hors /data = NON legacy");
    assert!(!ledger_key_path_is_legacy("/secrets/ledger.key"), "Secret hors /data = NON legacy (fail-closed)");
}

#[test]
fn v105_ledger_key_read_and_failclosed() {
    // (a) clé PRÉSENTE à un chemin Secret (non-legacy) -> lue telle quelle (pas de fail-closed).
    let good = mk_tmp_path("v105-ledger-good.key");
    let key_hex = hex_encode(&[7u8; 32]);
    std::fs::write(&good, &key_hex).unwrap();
    let k = ledger_key_load(&good, false).expect("clé Secret présente -> lue");
    assert_eq!(hex_encode(k.to_bytes().as_slice()), key_hex, "octets de clé lus tels quels (déterministe)");

    // (b) chemin Secret ABSENT (non-legacy) -> FAIL-CLOSED : None + AUCUNE génération de fichier.
    let missing = mk_tmp_path("v105-ledger-missing.key");
    let _ = std::fs::remove_file(&missing);
    assert!(ledger_key_load(&missing, false).is_none(), "Secret absent -> fail-closed None");
    assert!(!std::path::Path::new(&missing).exists(), "fail-closed : AUCUNE clé générée sur un chemin Secret");

    // (c) chemin Secret VIDE (monté, ESO pas encore peuplé) -> FAIL-CLOSED None ; le fichier n'est PAS écrasé.
    let empty = mk_tmp_path("v105-ledger-empty.key");
    std::fs::write(&empty, "").unwrap();
    assert!(ledger_key_load(&empty, false).is_none(), "Secret vide -> fail-closed None");
    assert_eq!(std::fs::read_to_string(&empty).unwrap(), "", "Secret vide NON écrasé (pas de clé divergente)");

    // (d) chemin LEGACY ABSENT + génération autorisée -> génère+persiste (compat first-run base neuve).
    let legacy = mk_tmp_path("v105-ledger-legacy.key");
    let _ = std::fs::remove_file(&legacy);
    let g1 = ledger_key_load(&legacy, true).expect("legacy absent -> génération autorisée");
    assert!(std::path::Path::new(&legacy).exists(), "clé legacy générée et persistée");
    // idempotent : relecture ne régénère pas -> MÊME clé.
    let g2 = ledger_key_load(&legacy, true).expect("relecture legacy");
    assert_eq!(hex_encode(g1.to_bytes().as_slice()), hex_encode(g2.to_bytes().as_slice()), "clé legacy stable (non régénérée)");
    let _ = std::fs::remove_file(&legacy);

    // (e) résolution via conf (PLUME_LEDGER_KEY_PATH préféré) vers un Secret ABSENT -> fail-closed None.
    //     NB: on passe par la conf-map (pas l'env process-global) -> pas de course inter-tests.
    let secret_missing = mk_tmp_path("v105-ledger-conf-secret.key");
    let _ = std::fs::remove_file(&secret_missing);
    let mut conf: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    conf.insert("PLUME_LEDGER_KEY_PATH".to_string(), secret_missing.clone());
    // garde-fou : le test n'a de sens que si l'env process n'impose pas déjà le chemin (cfg lit l'env d'abord).
    if std::env::var("PLUME_LEDGER_KEY_PATH").is_err() {
        assert!(ledger_key(&conf).is_none(), "PLUME_LEDGER_KEY_PATH -> Secret absent -> fail-closed");
        assert!(!std::path::Path::new(&secret_missing).exists(), "fail-closed : aucune clé générée");
    }
}

// ================================================================================================
// v105 (CHANGE 2 / STEP 1 backstop — HIGH) — ÉGALITÉ DE CLÉ AU CUTOVER VAULT. `ledger_key_cutover_check`
// (cœur pur, aucune génération) : détecte un ESCROW DIVERGENT (clé Vault active ≠ clé legacy résiduelle)
// SANS jamais bloquer un démarrage normal (absence/vacuité/chemin legacy -> NotApplicable).
// ================================================================================================
#[test]
fn v105_ledger_cutover_key_equality_backstop() {
    let key_a = hex_encode(&[0x11u8; 32]);
    let key_b = hex_encode(&[0x22u8; 32]);
    // chemins ACTIFS non-legacy (hors /data, ≠ défaut compilé) + un résidu legacy simulé.
    let active = mk_tmp_path("v105-cutover-active.key");   // Secret Vault (non-legacy)
    let legacy = mk_tmp_path("v105-cutover-legacy.key");   // résidu on-PVC

    // (a) MÊME clé escrow des deux côtés -> Match (continuité prouvée).
    std::fs::write(&active, &key_a).unwrap();
    std::fs::write(&legacy, &key_a).unwrap();
    assert_eq!(ledger_key_cutover_check(&active, &legacy), LedgerKeyCutover::Match, "clés identiques -> Match");
    // insensibilité casse/espaces : MÊME clé, encodage différent -> toujours Match (compare octets décodés).
    std::fs::write(&legacy, format!("  {}\n", key_a.to_uppercase())).unwrap();
    assert_eq!(ledger_key_cutover_check(&active, &legacy), LedgerKeyCutover::Match, "même clé (casse/espaces) -> Match");

    // (b) clé Vault ≠ clé legacy -> Mismatch (fork silencieux : c'est CE cas que le refus-de-boot attrape).
    std::fs::write(&legacy, &key_b).unwrap();
    assert_eq!(ledger_key_cutover_check(&active, &legacy), LedgerKeyCutover::Mismatch, "clés divergentes -> Mismatch (refus-boot)");

    // (c) legacy ABSENT / VIDE / mal formé -> NotApplicable (jamais un faux positif bloquant).
    let _ = std::fs::remove_file(&legacy);
    assert_eq!(ledger_key_cutover_check(&active, &legacy), LedgerKeyCutover::NotApplicable, "legacy absent -> NotApplicable");
    std::fs::write(&legacy, "").unwrap();
    assert_eq!(ledger_key_cutover_check(&active, &legacy), LedgerKeyCutover::NotApplicable, "legacy vide -> NotApplicable");
    std::fs::write(&legacy, "pas-de-l-hex").unwrap();
    assert_eq!(ledger_key_cutover_check(&active, &legacy), LedgerKeyCutover::NotApplicable, "legacy mal formé -> NotApplicable");

    // (d) chemin ACTIF LEGACY (pas de cutover en cours) -> NotApplicable, quels que soient les fichiers.
    assert_eq!(ledger_key_cutover_check("/data/ledger.key", &legacy), LedgerKeyCutover::NotApplicable, "actif legacy /data -> NotApplicable");
    assert_eq!(ledger_key_cutover_check(LEDGER_KEY_LEGACY_DEFAULT, &active), LedgerKeyCutover::NotApplicable, "actif défaut compilé -> NotApplicable");
    // (e) actif == legacy (même fichier) -> NotApplicable (rien à comparer).
    std::fs::write(&active, &key_a).unwrap();
    assert_eq!(ledger_key_cutover_check(&active, &active), LedgerKeyCutover::NotApplicable, "même fichier -> NotApplicable");
    let _ = std::fs::remove_file(&active);
    let _ = std::fs::remove_file(&legacy);
}

// ================================================================================================
// v105 (CHANGE 2 / STEP 2 — MED-HIGH) — SIGNAL SOC de signature DÉGRADÉE. Émis en `event` SOC-visible,
// NON-PURGEABLE (source='plume-config' + origin='daemon' -> RETENTION_NONPURGE), DÉDUPÉ à l'heure
// (anti-tempête boot-crashloop / ticks retention). Le signal mismatch (STEP 1) porte un `dedup` DISTINCT.
// ================================================================================================
#[test]
fn v105_ledger_unsigned_signal_soc_visible_nonpurgeable_deduped() {
    let conn = test_db();
    let cnt_health = |c: &Connection| c.query_row(
        "SELECT COUNT(*) FROM event WHERE source='plume-config' AND origin='daemon' AND category='health'", [], |r| r.get::<_, i64>(0)).unwrap();
    let old = now() - 40 * 86400; // bien au-delà de la rétention event (7 j) -> preuve de non-purge

    // (a) 1er signal -> écrit ; sévérité 4 (P1) ; message SOC-parlant.
    assert!(emit_ledger_unsigned(&conn, old, "/etc/plume/ledger/ledger.key"), "1er signal émis");
    assert_eq!(cnt_health(&conn), 1);
    let (sev, msg): (i64, String) = conn.query_row(
        "SELECT severity,message FROM event WHERE source='plume-config' AND category='health' LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!(sev, 4, "sévérité P1");
    assert!(msg.contains("DÉGRADÉE"), "message SOC explicite");

    // (b) DÉDUP HORAIRE : 2e appel même heure -> aucune nouvelle ligne (anti-tempête crashloop/ticks).
    assert!(!emit_ledger_unsigned(&conn, old + 59, "/etc/plume/ledger/ledger.key"), "dédup: pas de 2e signal dans l'heure");
    assert_eq!(cnt_health(&conn), 1, "1 signal/heure malgré 2 appels");
    // heure suivante -> nouveau signal autorisé.
    assert!(emit_ledger_unsigned(&conn, old + 3600, "/etc/plume/ledger/ledger.key"), "heure suivante -> nouveau signal");
    assert_eq!(cnt_health(&conn), 2);

    // (c) le signal MISMATCH (STEP 1) porte un dedup DISTINCT -> coexiste la MÊME heure (jamais étouffé).
    assert!(emit_ledger_key_mismatch(&conn, old, "/etc/plume/ledger/ledger.key", "/data/ledger.key"), "signal mismatch émis");
    assert_eq!(cnt_health(&conn), 3, "unsigned + mismatch = dedup distincts");

    // (d) NON-PURGEABLE : retention à 7 j ne supprime PAS ces signaux vieux de 40 j (origin=daemon), alors
    //     qu'un event ordinaire du même âge EST purgé (preuve que la purge a bien tourné).
    conn.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','7')", []).unwrap();
    conn.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'sshd','ancien purgeable','')", params![old]).unwrap();
    let db = Arc::new(Mutex::new(conn));
    retention_run(&db);
    assert_eq!(cnt_health(&db.lock()), 3, "signaux ledger NON-PURGEABLES (origin=daemon, source=plume-config)");
    assert_eq!(db.lock().query_row("SELECT COUNT(*) FROM event WHERE source='sshd'", [], |r| r.get::<_, i64>(0)).unwrap(), 0,
        "event ordinaire du même âge PURGÉ -> la purge a bien tourné (non-purge n'est pas un no-op)");
}

// ================================================================================================
// SECRET-PROVIDER PHASE 1 — les secrets applicatifs (PLUME_PASS_HASH / PLUME_SSO_HEADER_SECRET /
// PLUME_NOTIFY_NTFY_TOKEN) se lisent depuis un FICHIER monté RO (`{key}_FILE`, préféré), VERBATIM et
// FAIL-CLOSED, avec REPLI env `{key}` (parité v116). Généralisation stricte du modèle F1 `db_key()`.
// ================================================================================================
#[test]
fn secretprov_phase1_read_secret_file_verbatim_and_failclosed() {
    // (a) VERBATIM : un `\n` final est CONSERVÉ (= exactement ce que `env::var("{key}")` renverrait pour la
    //     même valeur de Secret k8s -> file == env byte-pour-byte, anti-divergence au cutover, comme F1).
    let ok = mk_tmp_path("secretprov-ok.key");
    std::fs::write(&ok, b"sso-shared-secret\n").unwrap();
    assert_eq!(read_secret_file(&ok).unwrap(), "sso-shared-secret\n",
        "newline final CONSERVÉ (verbatim) -> byte-identique à env, PAS de strip");
    std::fs::write(&ok, b"sso-shared-secret").unwrap();
    assert_eq!(read_secret_file(&ok).unwrap(), "sso-shared-secret", "sans newline -> valeur exacte");
    // (b) FAIL-CLOSED : fichier absent -> Err (l'appelant cfg_secret exit(78), comme db_key()).
    assert!(read_secret_file(&mk_tmp_path("secretprov-absent.key")).is_err(), "absent -> Err (fail-closed)");
    // (c) FAIL-CLOSED : fichier VIDE (0 octet) -> Err (comme env::var(..).filter(!is_empty) rejette "").
    let empty = mk_tmp_path("secretprov-empty.key");
    std::fs::write(&empty, b"").unwrap();
    assert!(read_secret_file(&empty).is_err(), "vide (0 octet) -> Err");
    // (d) VERBATIM cohérent : « \n » seul N'EST PAS vide -> "\n" (pas strippé à "").
    std::fs::write(&empty, b"\n").unwrap();
    assert_eq!(read_secret_file(&empty).unwrap(), "\n", "newline seul -> \"\\n\" verbatim (pas strippé à vide)");
    let _ = std::fs::remove_file(&ok);
    let _ = std::fs::remove_file(&empty);
}

#[test]
fn secretprov_phase1_cfg_secret_file_preferred_env_fallback() {
    // Clés inventées (JAMAIS dans l'env du process de test) -> cfg() tombe sur la conf map de façon déterministe.
    const K: &str = "PLUME_UNITTEST_SECRETPROV";
    let file_key = format!("{K}_FILE");
    // (a) `{key}_FILE` NON posé -> REPLI sur env/conf `{key}` (parité v116 STRICTE : chemin env inchangé).
    let mut conf = std::collections::HashMap::new();
    conf.insert(K.to_string(), "env-fallback-value".to_string());
    assert_eq!(cfg_secret(&conf, K), "env-fallback-value",
        "KEY_FILE absent -> repli env/conf = comportement v116");
    // (b) `{key}_FILE` posé -> le FICHIER gagne sur l'env (même si `{key}` env/conf est aussi présent).
    let f = mk_tmp_path("secretprov-cfg.key");
    std::fs::write(&f, b"file-wins-token\n").unwrap();
    conf.insert(file_key.clone(), f.clone());
    assert_eq!(cfg_secret(&conf, K), "file-wins-token\n",
        "KEY_FILE posé -> fichier VERBATIM préféré, ignore l'env KEY");
    // (c) `{key}_FILE` = "" (vide) traité comme NON posé -> repli env (pas d'exit, pas de faux fail-closed).
    conf.insert(file_key.clone(), String::new());
    assert_eq!(cfg_secret(&conf, K), "env-fallback-value", "KEY_FILE vide -> traité comme absent -> repli env");
    // NB: le cas `{key}_FILE` posé mais fichier illisible/vide -> `read_secret_file` renvoie Err (prouvé en (b)/(c)
    // du test read_secret_file) -> cfg_secret `std::process::exit(78)` (mécanique IDENTIQUE à db_key(), non
    // testable in-process car elle tue le runner ; le cœur pur Err est couvert ci-dessus).
    let _ = std::fs::remove_file(&f);
}

// ================================================================================================
// SECRET-PROVIDER PHASE 1 (v118) — PLUME_PASS_HASH en mount fichier SETUP-SAFE. CRUX SÉCURITÉ : distinguer
// « fichier ABSENT » (état légitime = MODE SETUP au premier boot) de « fichier PRÉSENT mais illisible/cassé »
// (fail-closed exit 78 ; retomber en setup = re-bootstrap d'auth = CRITIQUE). Miroir du modèle F1/db_key.
// ================================================================================================
#[test]
fn secretprov_v118_passhash_setup_safe_reader() {
    // (a) PRÉSENT & lisible & non-vide -> Value VERBATIM (aucun strip -> byte-identique à env, comme read_secret_file).
    let f = mk_tmp_path("v118-passhash-ok.key");
    std::fs::write(&f, b"$2b$12$realbcrypthashvalue\n").unwrap();
    match read_secret_file_setup_safe(&f) {
        SetupSecret::Value(v) => assert_eq!(v, "$2b$12$realbcrypthashvalue\n", "hash présent -> VERBATIM (newline conservé)"),
        _ => panic!("fichier présent+lisible+non-vide doit être Value"),
    }
    // (b) ABSENT (ErrorKind::NotFound) -> NotSet -> MODE SETUP OK (surtout PAS fail-closed). C'est le cas
    //     du mount k8s `optional: true` sur un cluster non-bootstrappé (Secret absent -> fichier absent).
    assert!(matches!(read_secret_file_setup_safe(&mk_tmp_path("v118-passhash-absent.key")), SetupSecret::NotSet),
        "fichier ABSENT -> NotSet (mode setup), JAMAIS FailClosed");
    // (c) VIDE (0 octet) -> NotSet -> mode setup OK (hash vide = pas de hash, miroir env::var(..).filter(!is_empty)).
    let empty = mk_tmp_path("v118-passhash-empty.key");
    std::fs::write(&empty, b"").unwrap();
    assert!(matches!(read_secret_file_setup_safe(&empty), SetupSecret::NotSet),
        "fichier VIDE (0 octet) -> NotSet (mode setup), PAS FailClosed");
    // (d) PRÉSENT mais NON-UTF8 -> FailClosed (fichier PRÉSENT-mais-cassé -> l'appelant exit 78 ; NE retombe
    //     PAS en setup). On assert le VARIANT (pas l'exit process, non-testable in-process comme db_key).
    let bad = mk_tmp_path("v118-passhash-nonutf8.key");
    std::fs::write(&bad, [0xff, 0xfe, 0x00, 0x80]).unwrap();
    assert!(matches!(read_secret_file_setup_safe(&bad), SetupSecret::FailClosed(_)),
        "PRÉSENT mais non-UTF8 -> FailClosed (fail-closed ; PAS de retour en mode setup)");
    // (e) « \n » seul (1 octet, non-vide, UTF8) -> Value("\n") (présent, verbatim) -> NON setup : un hash
    //     présent-mais-garbage verrouille (aucun login ne matche) SANS ouvrir le setup = direction fail-secure.
    std::fs::write(&empty, b"\n").unwrap();
    match read_secret_file_setup_safe(&empty) {
        SetupSecret::Value(v) => assert_eq!(v, "\n", "newline seul -> Value verbatim (présent, NON setup)"),
        _ => panic!("« \\n » (non-vide) doit être Value, pas NotSet"),
    }
    let _ = std::fs::remove_file(&f);
    let _ = std::fs::remove_file(&empty);
    let _ = std::fs::remove_file(&bad);
}

#[test]
fn secretprov_v118_passhash_cfg_secret_optional_wiring() {
    const K: &str = "PLUME_UNITTEST_PASSHASH_V118"; // clé inventée -> jamais dans l'env du runner
    let file_key = format!("{K}_FILE");
    // (a) `_FILE` posé + fichier ABSENT + AUCUN env -> "" -> MODE SETUP (le boot teste pass.is_empty()).
    //     Reproduit exactement l'invariant setup du mount `optional: true` sur cluster non-bootstrappé.
    let mut conf = std::collections::HashMap::new();
    conf.insert(file_key.clone(), mk_tmp_path("v118-cfgopt-absent.key"));
    assert_eq!(cfg_secret_optional(&conf, K), "", "_FILE posé + fichier absent + pas d'env -> \"\" -> mode setup");
    // (b) `_FILE` posé + fichier PRÉSENT lisible -> hash VERBATIM (l'auth l'utilise), ignore l'env.
    let f = mk_tmp_path("v118-cfgopt-real.key");
    std::fs::write(&f, b"$2b$12$fromfile\n").unwrap();
    conf.insert(file_key.clone(), f.clone());
    conf.insert(K.to_string(), "$2b$12$fromenv".to_string()); // env présent -> le FICHIER doit gagner
    assert_eq!(cfg_secret_optional(&conf, K), "$2b$12$fromfile\n", "_FILE présent -> fichier VERBATIM préféré à l'env");
    // (c) `_FILE` posé + fichier VIDE -> "" (mode setup), même si l'env porte une valeur (vide = pas de hash).
    let empty = mk_tmp_path("v118-cfgopt-empty.key");
    std::fs::write(&empty, b"").unwrap();
    conf.insert(file_key.clone(), empty.clone());
    assert_eq!(cfg_secret_optional(&conf, K), "", "_FILE vide -> \"\" -> mode setup (hash vide = pas de hash)");
    // (d) `_FILE` NON posé -> repli env `{key}` (parité v116/v117 STRICTE : chemin env inchangé).
    conf.remove(&file_key);
    assert_eq!(cfg_secret_optional(&conf, K), "$2b$12$fromenv", "_FILE absent -> repli env = comportement v116/v117");
    // (e) `_FILE` NON posé + env absent -> "" -> mode setup (parité stricte du premier boot v116).
    conf.remove(K);
    assert_eq!(cfg_secret_optional(&conf, K), "", "ni _FILE ni env -> \"\" -> mode setup (premier boot v116)");
    // NB: `_FILE` posé + fichier PRÉSENT-mais-illisible -> read_secret_file_setup_safe = FailClosed (prouvé (d)
    // du test reader) -> cfg_secret_optional std::process::exit(78) (IDENTIQUE à db_key/cfg_secret ; non testable
    // in-process car tue le runner ; le cœur pur FailClosed est couvert). Il NE retombe JAMAIS sur "" (setup).
    let _ = std::fs::remove_file(&f);
    let _ = std::fs::remove_file(&empty);
}

// v118 — Cache-Control par chemin : /api -> no-store (défense en profondeur post-logout bfcache), shell ->
// no-cache (inchangé), /loki -> AUCUN (inchangé ; no-store NON appliqué à /loki, scoping prudent range/stream).
#[test]
fn v118_cache_control_no_store_scope() {
    assert_eq!(cache_control_for("/api/query"), Some("no-store"), "/api/* -> no-store (nouveau v118)");
    assert_eq!(cache_control_for("/api/session"), Some("no-store"), "/api/* -> no-store");
    assert_eq!(cache_control_for("/index.html"), Some("no-cache"), "shell -> no-cache (inchangé v117)");
    assert_eq!(cache_control_for("/app.js"), Some("no-cache"), "asset shell -> no-cache (inchangé)");
    assert_eq!(cache_control_for("/"), Some("no-cache"), "racine -> no-cache (inchangé)");
    assert_eq!(cache_control_for("/loki/api/v1/query_range"), None, "/loki/* -> AUCUN Cache-Control (no-store NON appliqué)");
    assert_eq!(cache_control_for("/loki/api/v1/push"), None, "/loki/* -> AUCUN Cache-Control (inchangé v117)");
}

// ------------------------------------------------------------------------------------------------
// SECRET-PROVIDER PHASE 1 — retrait SÛR du résidu legacy /data/ledger.key : `ledger_residue_removable`
// ne renvoie true QUE sur le verdict `Match` du backstop (cutover cohérent, clé identique). JAMAIS sur
// Mismatch (résidu = vérité) ni NotApplicable (résidu absent / chemin actif encore legacy). Idempotent.
// ------------------------------------------------------------------------------------------------
#[test]
fn secretprov_phase1_ledger_residue_removable_only_on_match() {
    let key_a = hex_encode(&[0x33u8; 32]);
    let key_b = hex_encode(&[0x44u8; 32]);
    let active = mk_tmp_path("residue-active.key");  // Secret Vault non-legacy
    let residue = mk_tmp_path("residue-legacy.key"); // résidu on-PVC simulé
    // (a) MÊME clé des deux côtés (Match) -> RETIRABLE.
    std::fs::write(&active, &key_a).unwrap();
    std::fs::write(&residue, &key_a).unwrap();
    assert!(ledger_residue_removable(&active, &residue), "cutover cohérent (Match) -> résidu retirable");
    // (b) clés DIFFÉRENTES (Mismatch) -> JAMAIS retirable (le résidu est la vérité, backstop refuse le boot).
    std::fs::write(&residue, &key_b).unwrap();
    assert!(!ledger_residue_removable(&active, &residue), "clé divergente (Mismatch) -> résidu JAMAIS retiré");
    // (c) résidu ABSENT -> NotApplicable -> non retirable (rien à faire ; garantit l'idempotence post-retrait).
    let _ = std::fs::remove_file(&residue);
    assert!(!ledger_residue_removable(&active, &residue), "résidu absent -> non retirable (idempotent)");
    // (d) chemin actif ENCORE legacy (/data/...) -> NotApplicable -> non retirable (le résidu pourrait être la
    //     clé ACTIVE : on n'y touche jamais tant que le cutover Vault n'est pas en cours).
    std::fs::write(&residue, &key_a).unwrap();
    assert!(!ledger_residue_removable("/data/ledger.key", &residue), "actif legacy -> résidu JAMAIS retiré");
    let _ = std::fs::remove_file(&active);
    let _ = std::fs::remove_file(&residue);
}

// ================================================================================================
// SECRET-PROVIDER PHASE 2 — PARITÉ. Les 4 résolveurs historiques (cfg_secret / db_key_from_file /
// resolve_tenant_key / resolve_secret_ref) sont désormais adossés à la SPI `guatx_core::secret`
// (trait `SecretProvider` + grammaire `SecretRef` + providers PURS). CES TESTS PROUVENT que la
// sémantique PROPRE à CHAQUE appelant est PRÉSERVÉE (verbatim vs trim, filter-vide vs env-brut,
// NotFound-> "" / None / Err selon la politique, les DEUX sens de `vault:`). Les chemins fail-closed
// appellent `std::process::exit(78)` (non testables in-process) -> on éprouve la COUCHE PURE
// (providers + `read_secret_file*` + `SetupSecret`) exactement comme l'oracle Phase 1.
// ================================================================================================

#[test]
fn secretprov_phase2_file_layer_byte_parity() {
    use guatx_core::secret::{SecretError, SecretOutcome, SecretProvider, SecretRef};
    // Les TROIS surfaces de lecture-fichier (read_secret_file STRICT, read_secret_file_setup_safe
    // SETUP-SAFE, db_key_from_file STRICT) délèguent au MÊME FileProvider VERBATIM. On les fait
    // toutes converger sur les MÊMES fichiers et on vérifie l'accord byte-pour-byte + le mapping
    // de politique (NotFound vs Err) identique à l'historique.
    let fp = guatx_core::secret::FileProvider;

    // (1) VERBATIM : newline final CONSERVÉ, identique sur les 3 surfaces + le provider brut.
    let ok = mk_tmp_path("p2-ok.key");
    std::fs::write(&ok, b"crown-jewel\n").unwrap();
    assert_eq!(read_secret_file(&ok).unwrap(), "crown-jewel\n", "read_secret_file VERBATIM");
    assert_eq!(crate::crypto::db_key_from_file(&ok).unwrap(), "crown-jewel\n", "db_key_from_file VERBATIM (byte-identique -> SQLCipher OK au cutover)");
    match read_secret_file_setup_safe(&ok) {
        SetupSecret::Value(v) => assert_eq!(v, "crown-jewel\n", "setup-safe VERBATIM"),
        _ => panic!("présent -> Value"),
    }
    match fp.get(&SecretRef::file(&ok)).unwrap() {
        SecretOutcome::Present(v) => assert_eq!(v.expose(), "crown-jewel\n", "FileProvider VERBATIM"),
        _ => panic!("présent -> Present"),
    }

    // (2) ABSENT : STRICT -> Err (les 2) ; SETUP-SAFE -> NotSet (setup légitime) ; provider -> NotFound.
    let absent = mk_tmp_path("p2-absent.key");
    assert!(read_secret_file(&absent).is_err(), "absent STRICT -> Err (cfg_secret exit78)");
    assert!(crate::crypto::db_key_from_file(&absent).is_err(), "absent STRICT -> Err (db_key exit78)");
    assert!(matches!(read_secret_file_setup_safe(&absent), SetupSecret::NotSet), "absent SETUP-SAFE -> NotSet (mode setup)");
    assert!(matches!(fp.get(&SecretRef::file(&absent)).unwrap(), SecretOutcome::NotFound), "absent -> NotFound");

    // (3) VIDE (0 octet) : STRICT -> Err ; SETUP-SAFE -> NotSet ; provider -> NotFound (miroir filter-empty).
    let empty = mk_tmp_path("p2-empty.key");
    std::fs::write(&empty, b"").unwrap();
    assert!(read_secret_file(&empty).is_err(), "vide STRICT -> Err");
    assert!(crate::crypto::db_key_from_file(&empty).is_err(), "vide STRICT -> Err (db_key)");
    assert!(matches!(read_secret_file_setup_safe(&empty), SetupSecret::NotSet), "vide SETUP-SAFE -> NotSet");
    assert!(matches!(fp.get(&SecretRef::file(&empty)).unwrap(), SecretOutcome::NotFound), "vide -> NotFound");

    // (4) NON-UTF8 (PRÉSENT MAIS CASSÉ) : STRICT -> Err ; SETUP-SAFE -> FailClosed (PAS NotSet ! triple-guard
    //     PASS_HASH : un fichier présent-mais-cassé NE retombe JAMAIS en setup) ; provider -> Malformed.
    let bad = mk_tmp_path("p2-nonutf8.key");
    std::fs::write(&bad, [0xff, 0xfe, 0x00, 0x80]).unwrap();
    assert!(read_secret_file(&bad).is_err(), "non-UTF8 STRICT -> Err");
    assert!(matches!(read_secret_file_setup_safe(&bad), SetupSecret::FailClosed(_)), "non-UTF8 SETUP-SAFE -> FailClosed (JAMAIS NotSet)");
    assert!(matches!(fp.get(&SecretRef::file(&bad)), Err(SecretError::Malformed(_))), "non-UTF8 -> Malformed");

    // (5) PRÉSENT-MAIS-ILLISIBLE (simulé par un CHEMIN=RÉPERTOIRE -> EISDIR, déterministe et non-root) :
    //     STRICT -> Err ; SETUP-SAFE -> FailClosed (fail-closed, PAS setup) ; provider -> Unreadable.
    let dir = mk_tmp_path("p2-dir.key");
    std::fs::create_dir(&dir).unwrap();
    assert!(read_secret_file(&dir).is_err(), "illisible(dir) STRICT -> Err");
    assert!(matches!(read_secret_file_setup_safe(&dir), SetupSecret::FailClosed(_)), "illisible(dir) SETUP-SAFE -> FailClosed");
    assert!(matches!(fp.get(&SecretRef::file(&dir)), Err(SecretError::Unreadable(_))), "illisible(dir) -> Unreadable");

    // (6) « \n » seul (1 octet non-vide) : PRÉSENT -> Value("\n") sur les 3 surfaces (NON strippé à vide,
    //     direction fail-secure : un hash présent-mais-garbage verrouille SANS ouvrir le setup).
    std::fs::write(&empty, b"\n").unwrap();
    assert_eq!(read_secret_file(&empty).unwrap(), "\n", "« \\n » seul -> \"\\n\" verbatim");
    match read_secret_file_setup_safe(&empty) {
        SetupSecret::Value(v) => assert_eq!(v, "\n", "« \\n » seul -> Value (présent, NON setup)"),
        _ => panic!("« \\n » -> Value"),
    }

    for p in [&ok, &empty, &bad] { let _ = std::fs::remove_file(p); }
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn secretprov_phase2_tenant_vs_overlay_semantics_preserved() {
    // resolve_tenant_key (filter-vide, `Result<Option<String>>`) et resolve_secret_ref (env-BRUT + file-TRIM,
    // `Result<String>`) partagent la MÊME grammaire `SecretRef` mais gardent des sémantiques VOLONTAIREMENT
    // DIFFÉRENTES. On prouve la divergence là où elle compte (anti-homogénéisation).
    let pid = std::process::id();

    // ---- env: — filter-vide (tenant) vs BRUT (overlay) ----
    let tvar = format!("PLUME_PARITY_TENANT_ENV_{pid}");
    let ovar = format!("PLUME_PARITY_OAC_ENV_{pid}");
    // (a) présent non-vide -> VERBATIM des deux côtés.
    std::env::set_var(&tvar, "tenant-key\n");
    std::env::set_var(&ovar, "oac-secret\n");
    assert_eq!(resolve_tenant_key(&format!("env:{tvar}")).unwrap().as_deref(), Some("tenant-key\n"), "tenant env: VERBATIM");
    assert_eq!(resolve_secret_ref(&format!("env:{ovar}")).unwrap(), "oac-secret\n", "overlay env: VERBATIM (pas de trim de la valeur)");
    // (b) VIDE : tenant -> Ok(None) (filter-vide, base en clair) ; overlay -> Ok("") (BRUT, PAS de filter).
    std::env::set_var(&tvar, "");
    std::env::set_var(&ovar, "");
    assert_eq!(resolve_tenant_key(&format!("env:{tvar}")).unwrap(), None, "tenant env: vide -> None (filter-vide, miroir db_key)");
    assert_eq!(resolve_secret_ref(&format!("env:{ovar}")).unwrap(), "", "overlay env: vide -> Ok(\"\") (BRUT — divergence caller-4 PRÉSERVÉE)");
    // (c) ABSENT : tenant -> Ok(None) ; overlay -> Err (variable absente).
    std::env::remove_var(&tvar);
    std::env::remove_var(&ovar);
    assert_eq!(resolve_tenant_key(&format!("env:{tvar}")).unwrap(), None, "tenant env: absent -> None");
    assert!(resolve_secret_ref(&format!("env:{ovar}")).is_err(), "overlay env: absent -> Err (divergence PRÉSERVÉE)");

    // ---- literal: — tenant l'accepte ; overlay le REJETTE (cleartext interdit en git) ----
    assert_eq!(resolve_tenant_key("literal:abc").unwrap().as_deref(), Some("abc"), "tenant literal: -> Some");
    assert!(resolve_tenant_key("literal:").is_err(), "tenant literal: vide -> Err");
    assert!(resolve_secret_ref("literal:abc").is_err(), "overlay literal: -> REJETÉ (cleartext interdit)");

    // ---- file: — overlay TRIM + tolère le vide (caller-4) ; (les callers verbatim sont éprouvés ailleurs) ----
    let f = mk_tmp_path("p2-oac-file.secret");
    std::fs::write(&f, b"  padded-secret  \n").unwrap();
    assert_eq!(resolve_secret_ref(&format!("file:{f}")).unwrap(), "padded-secret", "overlay file: TRIMMÉ (spécifique caller-4)");
    std::fs::write(&f, b"").unwrap();
    assert_eq!(resolve_secret_ref(&format!("file:{f}")).unwrap(), "", "overlay file: vide -> Ok(\"\") (toléré)");
    assert!(resolve_secret_ref(&format!("file:{}", mk_tmp_path("p2-oac-absent.secret"))).is_err(), "overlay file: absent -> Err");
    let _ = std::fs::remove_file(&f);

    // ---- LES DEUX SENS DE `vault:` restent atteignables et DISTINCTS ----
    // Overlay = ENV-PROJECTION Vault-Agent : `vault:secret/data/foo` -> var d'env DÉRIVÉE SECRET_DATA_FOO.
    let proj = format!("SECRET_DATA_FOO_{pid}");
    std::env::set_var(&proj, "projected-secret");
    assert_eq!(
        resolve_secret_ref(&format!("vault:secret/data/foo/{pid}")).unwrap_or_default(),
        "projected-secret",
        "overlay vault: = ENV-PROJECTION (forme distincte, atteignable)"
    );
    std::env::remove_var(&proj);
    // Tenant/db-key/{KEY}_REF = client HTTP KV-v2 : non configuré (PLUME_VAULT_ADDR absent) -> Err (fail-closed).
    if std::env::var("PLUME_VAULT_ADDR").is_err() {
        assert!(resolve_tenant_key("vault:secret/data/ghost").is_err(),
            "tenant vault: HTTP non configuré -> Err (fail-closed ; sens HTTP distinct de l'env-projection)");
    }

    // ---- préfixe INCONNU / cleartext -> Err des deux côtés (fail-closed) ----
    assert!(resolve_tenant_key("garbage").is_err(), "tenant préfixe inconnu -> Err");
    assert!(resolve_secret_ref("plaintextsecret").is_err(), "overlay cleartext -> Err");
}

#[test]
fn secretprov_phase2_cfg_secret_ref_additive_and_default_unchanged() {
    // `{KEY}_REF` (ADDITIF Phase 2) résout n'importe quel SecretRef et GAGNE ; NON posé -> chemin
    // historique STRICTEMENT inchangé (default path byte-identique). Clés inventées -> jamais dans l'env.
    const K: &str = "PLUME_UNITTEST_P2REF";
    let ref_key = format!("{K}_REF");
    let file_key = format!("{K}_FILE");
    let pid = std::process::id();

    // (a) DÉFAUT (ni _REF ni _FILE) -> repli env/conf `{key}` : v116 INCHANGÉ.
    let mut conf = std::collections::HashMap::new();
    conf.insert(K.to_string(), "legacy-env-value".to_string());
    assert_eq!(cfg_secret(&conf, K), "legacy-env-value", "défaut -> repli env/conf (byte-identique v116)");

    // (b) _REF = literal: -> GAGNE sur le repli env.
    conf.insert(ref_key.clone(), "literal:from-ref".to_string());
    assert_eq!(cfg_secret(&conf, K), "from-ref", "_REF=literal: -> gagne sur env");

    // (c) _REF = env: -> résout la var explicite (VERBATIM), GAGNE sur _FILE + repli.
    let evar = format!("PLUME_PARITY_REF_ENV_{pid}");
    std::env::set_var(&evar, "from-ref-env\n");
    conf.insert(ref_key.clone(), format!("env:{evar}"));
    let f = mk_tmp_path("p2-ref-file.key");
    std::fs::write(&f, b"from-file\n").unwrap();
    conf.insert(file_key.clone(), f.clone());
    assert_eq!(cfg_secret(&conf, K), "from-ref-env\n", "_REF=env: -> VERBATIM, gagne sur _FILE");
    std::env::remove_var(&evar);

    // (d) _REF = file: (chemin explicite) -> VERBATIM (aucun trim, contrairement à l'overlay caller-4).
    conf.insert(ref_key.clone(), format!("file:{f}"));
    assert_eq!(cfg_secret(&conf, K), "from-file\n", "_REF=file: -> VERBATIM (pas de trim -> parité db_key)");

    // (e) _REF retiré -> _FILE reprend la main (chemin v117 inchangé) : VERBATIM préféré à l'env repli.
    conf.remove(&ref_key);
    assert_eq!(cfg_secret(&conf, K), "from-file\n", "_REF absent -> _FILE VERBATIM (v117 inchangé)");
    let _ = std::fs::remove_file(&f);
}
