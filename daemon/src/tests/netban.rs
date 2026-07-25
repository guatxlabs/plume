// BAN NATIF PLUME (chantier ② Phase 1) — tests du ban IP au niveau HTTP du daemon : IP réelle derrière proxy
// (anti-spoof), store live `net_ban` (TTL/permanent/reversibilité/agrégation), décision du guard (mode-0
// passthrough, banni -> bloqué, exemptions, fail-open) et l'API admin `/api/netban` (protected-IP refusée,
// pose/liste/retrait). Les tests qui touchent le CACHE GLOBAL (`netban_cache`) sont SÉRIALISÉS + nettoient le
// cache sous lock (le cache est un OnceLock partagé au process ; les fns PURES n'en dépendent pas).

    static NETBAN_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn mk_req(peer: &str, path: &str, headers: &[(&str, &str)]) -> Request {
        let mut b = Request::builder().uri(path);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut req = b.body(axum::body::Body::empty()).unwrap();
        if !peer.is_empty() {
            let sa: std::net::SocketAddr = format!("{peer}:40000").parse().unwrap();
            req.extensions_mut().insert(axum::extract::ConnectInfo(sa));
        }
        req
    }

    fn mk_admin() -> AuthUser {
        AuthUser {
            name: "op".into(),
            role: "admin".into(),
            tenant: "default".into(),
            is_superadmin: false,
            method: "basic".into(),
            csrf: String::new(),
            env: None,
        }
    }

    // ----------------------------------------------------------------------------------------------
    // (1) real_client_ip — les 4 cas anti-spoof requis + priorité des en-têtes.
    // ----------------------------------------------------------------------------------------------

    #[test]
    fn real_client_ip_public_peer_ignores_spoofed_cf_header() {
        // (a) pair PUBLIC + CF-Connecting-IP forgé -> on renvoie le PAIR public (en-tête ignoré : anti-spoof).
        let req = mk_req("203.0.113.9", "/api/query", &[("cf-connecting-ip", "1.2.3.4")]);
        assert_eq!(real_client_ip(&req), "203.0.113.9", "pair non-proxy : XFF/CF NE sont PAS de confiance");
    }

    #[test]
    fn real_client_ip_trusted_private_peer_reads_cf() {
        // (b) pair PRIVÉ (10.42.x = Traefik/ingress) + CF-Connecting-IP=1.2.3.4 -> IP RÉELLE 1.2.3.4.
        let req = mk_req("10.42.0.7", "/api/query", &[("cf-connecting-ip", "1.2.3.4")]);
        assert_eq!(real_client_ip(&req), "1.2.3.4", "pair proxy de confiance : CF-Connecting-IP lu");
    }

    #[test]
    fn real_client_ip_trusted_peer_malformed_header_falls_back_to_peer() {
        // (c) pair de confiance + en-tête MALFORMÉ -> repli sur le pair (jamais une valeur non-IP).
        let req = mk_req("10.42.0.7", "/api/query", &[("cf-connecting-ip", "not-an-ip")]);
        assert_eq!(real_client_ip(&req), "10.42.0.7", "en-tête non parsable -> repli sur le pair");
    }

    #[test]
    fn real_client_ip_xff_leftmost_valid_from_trusted_peer() {
        // (d) X-Forwarded-For multi-hops depuis un pair de confiance -> hop GAUCHE valide.
        let req = mk_req("10.42.0.7", "/api/query", &[("x-forwarded-for", "5.6.7.8, 10.0.0.1, 10.42.0.7")]);
        assert_eq!(real_client_ip(&req), "5.6.7.8", "XFF : hop le plus à gauche (client d'origine)");
    }

    #[test]
    fn real_client_ip_header_priority_cf_over_xrealip_over_xff() {
        // Priorité CF-Connecting-IP > X-Real-IP > X-Forwarded-For.
        let req = mk_req(
            "10.42.0.7",
            "/api/query",
            &[("cf-connecting-ip", "1.1.1.1"), ("x-real-ip", "2.2.2.2"), ("x-forwarded-for", "3.3.3.3")],
        );
        assert_eq!(real_client_ip(&req), "1.1.1.1", "CF prioritaire");
        let req2 = mk_req("10.42.0.7", "/api/query", &[("x-real-ip", "2.2.2.2"), ("x-forwarded-for", "3.3.3.3")]);
        assert_eq!(real_client_ip(&req2), "2.2.2.2", "X-Real-IP avant XFF");
    }

    #[test]
    fn proxy_is_trusted_default_and_explicit_list() {
        // DÉFAUT (liste vide) : privé/loopback = confiance ; public = non.
        assert!(proxy_is_trusted("10.42.0.1", &[]), "RFC1918 -> confiance par défaut");
        assert!(proxy_is_trusted("127.0.0.1", &[]), "loopback -> confiance par défaut");
        assert!(!proxy_is_trusted("203.0.113.9", &[]), "public -> jamais de confiance par défaut");
        assert!(!proxy_is_trusted("", &[]), "pair vide -> pas de confiance");
        // Liste EXPLICITE : confiance EXACTE uniquement (remplace le défaut privé/loopback).
        let list = vec!["10.42.0.1".to_string()];
        assert!(proxy_is_trusted("10.42.0.1", &list), "IP exacte listée -> confiance");
        assert!(!proxy_is_trusted("10.42.0.2", &list), "IP privée NON listée -> refus (liste exacte)");
        assert!(!proxy_is_trusted("127.0.0.1", &list), "loopback non listé -> refus quand liste explicite");
    }

    // ----------------------------------------------------------------------------------------------
    // (2) net_ban store — verdict PUR (snapshot) + chargement/agrégation depuis la base.
    // ----------------------------------------------------------------------------------------------

    #[test]
    fn snapshot_blocked_semantics() {
        let mut m: HashMap<String, Option<i64>> = HashMap::new();
        let t = 1_000_000i64;
        assert!(!netban_snapshot_blocked(&m, "1.2.3.4", t), "absente -> pass (mode-0 parité)");
        assert!(!netban_snapshot_blocked(&m, "", t), "ip vide -> jamais bloquée");
        m.insert("1.2.3.4".into(), None); // permanent
        assert!(netban_snapshot_blocked(&m, "1.2.3.4", t), "permanent -> bloqué");
        m.insert("5.6.7.8".into(), Some(t + 100)); // TTL futur
        assert!(netban_snapshot_blocked(&m, "5.6.7.8", t), "TTL futur -> bloqué");
        m.insert("9.9.9.9".into(), Some(t - 1)); // TTL passé
        assert!(!netban_snapshot_blocked(&m, "9.9.9.9", t), "TTL expiré -> pass");
    }

    #[test]
    fn netban_load_aggregates_permanent_wins() {
        let c = test_db();
        // même IP, 2 env : un TTL + un PERMANENT -> le permanent l'emporte (None).
        c.execute("INSERT INTO net_ban(ip,expires_ts,env_id) VALUES('1.2.3.4',9999999999,'prod')", []).unwrap();
        c.execute("INSERT INTO net_ban(ip,expires_ts,env_id) VALUES('1.2.3.4',NULL,'staging')", []).unwrap();
        // autre IP : 2 TTL -> expiry MAX conservé.
        c.execute("INSERT INTO net_ban(ip,expires_ts,env_id) VALUES('5.6.7.8',100,'prod')", []).unwrap();
        c.execute("INSERT INTO net_ban(ip,expires_ts,env_id) VALUES('5.6.7.8',500,'staging')", []).unwrap();
        let m = netban_load(&c);
        assert_eq!(m.get("1.2.3.4"), Some(&None), "permanent l'emporte sur le TTL");
        assert_eq!(m.get("5.6.7.8"), Some(&Some(500)), "TTL agrégé = expiry max");
    }

    // ----------------------------------------------------------------------------------------------
    // (3) guard — mode-0 passthrough, banni bloqué (route non-auth), exemptions, TTL, fail-open.
    // ----------------------------------------------------------------------------------------------

    #[test]
    fn guard_mode0_empty_set_passes() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        // set vide + config défaut -> AUCUN blocage (mode-0 byte-identique : la requête traverse le guard intacte).
        let req = mk_req("203.0.113.77", "/api/query", &[]);
        assert!(!net_ban_guard_blocks(&req), "cache vide -> passthrough");
    }

    #[test]
    fn guard_blocks_banned_ip_on_unauthenticated_route() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        // pair PUBLIC direct -> real_client_ip = pair ; on le bannit (permanent).
        netban_cache().write().insert("203.0.113.80".into(), None);
        // route SANS aucune identité (pas d'Authorization) -> le guard bloque AVANT auth.
        let req = mk_req("203.0.113.80", "/api/query", &[]);
        assert!(net_ban_guard_blocks(&req), "IP bannie -> bloquée sur route non authentifiée");
        // une AUTRE IP passe (le blocage est ciblé).
        let req2 = mk_req("203.0.113.81", "/api/query", &[]);
        assert!(!net_ban_guard_blocks(&req2), "IP non bannie -> passe");
    }

    #[test]
    fn guard_exempts_health_and_metrics_even_when_banned() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        netban_cache().write().insert("203.0.113.90".into(), None);
        for p in ["/healthz", "/readyz", "/metrics"] {
            let req = mk_req("203.0.113.90", p, &[]);
            assert!(!net_ban_guard_blocks(&req), "{p} exempté du guard même pour une IP bannie");
        }
        // mais une route normale reste bloquée pour la même IP.
        assert!(net_ban_guard_blocks(&mk_req("203.0.113.90", "/api/query", &[])), "route normale -> bloquée");
    }

    #[test]
    fn guard_ttl_expiry_then_passes() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let ip = "203.0.113.95";
        // ban DÉJÀ expiré -> passe.
        netban_cache().write().insert(ip.into(), Some(now() - 10));
        assert!(!net_ban_guard_blocks(&mk_req(ip, "/api/query", &[])), "TTL expiré -> passthrough");
        // ban futur -> bloqué.
        netban_cache().write().insert(ip.into(), Some(now() + 3600));
        assert!(net_ban_guard_blocks(&mk_req(ip, "/api/query", &[])), "TTL futur -> bloqué");
    }

    #[test]
    fn guard_fail_open_for_absent_ip() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        // store "fonctionnel" mais l'IP visée n'y est pas -> jamais de 403 (fail-open / parité).
        netban_cache().write().insert("198.51.100.1".into(), None);
        assert!(!net_ban_guard_blocks(&mk_req("203.0.113.200", "/api/query", &[])), "IP absente -> passe (fail-open)");
        // Et une IP RÉELLE indisponible (pas de ConnectInfo) -> vide -> jamais bloquée.
        let req = mk_req("", "/api/query", &[]);
        assert!(!net_ban_guard_blocks(&req), "pas d'IP source -> passthrough (fail-open)");
    }

    #[test]
    fn store_reversibility_upsert_then_remove() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let c = test_db();
        let ip = "198.51.100.42";
        netban_upsert(&c, ip, None, "test", "op", "prod");
        assert!(net_ban_is_blocked(ip, now()), "après upsert -> bloqué (cache cohérent)");
        netban_remove(&c, ip);
        assert!(!net_ban_is_blocked(ip, now()), "après remove -> plus bloqué (réversible)");
        let n: i64 = c.query_row("SELECT COUNT(*) FROM net_ban WHERE ip=?1", params![ip], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "ligne net_ban supprimée");
    }

    // ----------------------------------------------------------------------------------------------
    // (4) API admin /api/netban — protected-IP refusée, pose/liste, DELETE.
    // ----------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn api_post_rejects_protected_ip() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        for prot in ["127.0.0.1", "10.0.0.1", "192.168.1.1"] {
            let resp = netban_add(State(st.clone()), Extension(mk_admin()), Json(json!({ "ip": prot }))).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{prot} (protégée) -> POST refusé (anti self-lockout)");
        }
        let n: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM net_ban", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "aucune IP protégée insérée");
    }

    #[tokio::test]
    async fn api_post_list_delete_roundtrip() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let ip = "203.0.113.123";
        // POST avec TTL.
        let resp = netban_add(State(st.clone()), Extension(mk_admin()), Json(json!({ "ip": ip, "ttl_s": 3600, "reason": "scan" }))).await;
        assert_eq!(resp.status(), StatusCode::OK, "POST IP publique valide -> 200");
        {
            let c = st.db.lock();
            let (exp, reason): (Option<i64>, Option<String>) = c
                .query_row("SELECT expires_ts, reason FROM net_ban WHERE ip=?1", params![ip], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap();
            assert!(exp.is_some() && exp.unwrap() > now(), "TTL -> expires_ts futur");
            assert_eq!(reason.as_deref(), Some("scan"));
        }
        // GET liste : la voit active.
        let Json(list) = netban_list(State(st.clone()), Extension(mk_admin())).await;
        assert_eq!(list["active"].as_i64(), Some(1), "1 ban actif listé");
        assert_eq!(list["bans"][0]["ip"].as_str(), Some(ip));
        // DELETE : retirée.
        let resp = netban_delete(State(st.clone()), Extension(mk_admin()), Path(ip.to_string())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let n: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM net_ban WHERE ip=?1", params![ip], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "DELETE -> ligne retirée (réversible)");
    }

    #[tokio::test]
    async fn api_post_permanent_when_no_ttl() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let ip = "203.0.113.124";
        let resp = netban_add(State(st.clone()), Extension(mk_admin()), Json(json!({ "ip": ip }))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let exp: Option<i64> = st.db.lock().query_row("SELECT expires_ts FROM net_ban WHERE ip=?1", params![ip], |r| r.get(0)).unwrap();
        assert_eq!(exp, None, "sans ttl_s -> ban PERMANENT (expires_ts NULL)");
    }

    // ----------------------------------------------------------------------------------------------
    // (5) DURCISSEMENTS : valve de récup /api/netban, reload fail-static, IPv6 + canonicalisation.
    // ----------------------------------------------------------------------------------------------

    #[test]
    fn guard_exempts_netban_recovery_route_even_when_banned() {
        // F1 : un opérateur dont l'IP réelle est bannie DOIT pouvoir atteindre /api/netban pour se DÉBANNIR en direct.
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        netban_cache().write().insert("203.0.113.140".into(), None);
        for p in ["/api/netban", "/api/netban/203.0.113.140"] {
            assert!(!net_ban_guard_blocks(&mk_req("203.0.113.140", p, &[])), "{p} = valve de récup, exemptée du gate");
        }
        assert!(net_ban_guard_blocks(&mk_req("203.0.113.140", "/", &[])), "toute autre route reste bloquée pour l'IP bannie");
    }

    #[test]
    fn netban_reload_fail_static_keeps_last_good_on_read_error() {
        // F3 : une erreur de lecture (table absente) NE VIDE PAS le cache (garde le dernier bon instantané).
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let c = test_db();
        netban_upsert(&c, "198.51.100.77", None, "t", "op", "prod"); // remplit table + cache
        assert!(net_ban_is_blocked("198.51.100.77", now()));
        c.execute("DROP TABLE net_ban", []).unwrap(); // la prochaine lecture ÉCHOUERA (prepare Err)
        netban_reload(&c); // try_load -> None -> cache CONSERVÉ (fail-static)
        assert!(net_ban_is_blocked("198.51.100.77", now()), "fail-static : ban conservé malgré l'échec de lecture");
        // une table VIDE (LECTURE réussie) remplace bien -> unban légitime non figé.
        c.execute("CREATE TABLE net_ban(ip TEXT NOT NULL, reason TEXT, created_ts INTEGER, expires_ts INTEGER, created_by TEXT, env_id TEXT NOT NULL DEFAULT 'prod', PRIMARY KEY(ip,env_id))", []).unwrap();
        netban_reload(&c);
        assert!(!net_ban_is_blocked("198.51.100.77", now()), "table vide (lecture OK) -> cache remplacé");
    }

    #[test]
    fn netban_validate_accepts_ipv6_and_canonicalizes() {
        // F5 : IPv6 bannissable. F7 : canonicalisation (jamais stocké tel quel -> matche real_client_ip).
        assert_eq!(netban_validate_ip("2001:DB8::1", "").unwrap(), "2001:db8::1", "IPv6 canonique (minuscule/compressé)");
        assert_eq!(netban_validate_ip("  1.2.3.4 ", "").unwrap(), "1.2.3.4", "IPv4 trim + canonique");
        // octets à zéro-tête : soit refusés, soit canonicalisés — JAMAIS stockés tels quels (fin du faux no-op).
        let r = netban_validate_ip("01.02.03.04", "");
        assert!(r.is_err() || r.as_deref() == Ok("1.2.3.4"), "zéro-tête : refusé ou canonicalisé, jamais brut");
        assert!(netban_validate_ip("pas-une-ip", "").is_err());
        // protégées (v4 & v6) refusées.
        assert!(netban_validate_ip("127.0.0.1", "").is_err(), "loopback v4 protégé");
        assert!(netban_validate_ip("::1", "").is_err(), "loopback v6 protégé");
    }

    #[test]
    fn guard_blocks_banned_ipv6_end_to_end() {
        // F5 bout-en-bout : une IPv6 RÉELLE (via CF derrière un proxy de confiance) bannie -> bloquée.
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        netban_cache().write().insert("2001:db8::dead".into(), None);
        let req = mk_req("10.42.0.7", "/api/query", &[("cf-connecting-ip", "2001:db8::dead")]);
        assert!(net_ban_guard_blocks(&req), "IPv6 réelle bannie -> 403");
    }

    #[test]
    fn real_client_ip_edge_secret_gates_header_trust() {
        // ② Phase 2 (F2) : secret d'edge configuré -> en-têtes d'IP réelle fiables SEULEMENT si le secret CF est
        // présent+correct. Pair de confiance (privé) dans tous les cas.
        let h = "x-plume-edge";
        let s = "s3cr3t-de-cf";
        let ok = mk_req("10.42.0.7", "/api/query", &[("cf-connecting-ip", "1.2.3.4"), (h, s)]);
        assert_eq!(real_client_ip_ctx(&ok, &[], h, s), "1.2.3.4", "secret correct -> IP réelle lue");
        let no = mk_req("10.42.0.7", "/api/query", &[("cf-connecting-ip", "1.2.3.4")]);
        assert_eq!(real_client_ip_ctx(&no, &[], h, s), "10.42.0.7", "secret ABSENT -> repli pair (pas de spoof direct)");
        let bad = mk_req("10.42.0.7", "/api/query", &[("cf-connecting-ip", "1.2.3.4"), (h, "mauvais")]);
        assert_eq!(real_client_ip_ctx(&bad, &[], h, s), "10.42.0.7", "secret FAUX -> repli pair");
        let p1 = mk_req("10.42.0.7", "/api/query", &[("cf-connecting-ip", "1.2.3.4")]);
        assert_eq!(real_client_ip_ctx(&p1, &[], h, ""), "1.2.3.4", "secret VIDE (défaut) -> comportement Phase 1");
    }

    #[test]
    fn real_client_ip_ctx_explicit_trusted_list_pins_proxy() {
        // PLUME_TRUSTED_PROXIES explicite (durcissement F4) : seul le pair EXACT est de confiance.
        let trusted = vec!["10.42.0.9".to_string()];
        let ok = mk_req("10.42.0.9", "/api/query", &[("cf-connecting-ip", "1.2.3.4")]);
        assert_eq!(real_client_ip_ctx(&ok, &trusted, "x-plume-edge", ""), "1.2.3.4", "pair listé -> confiance");
        let other = mk_req("10.42.0.50", "/api/query", &[("cf-connecting-ip", "1.2.3.4")]);
        assert_eq!(real_client_ip_ctx(&other, &trusted, "x-plume-edge", ""), "10.42.0.50", "pod PRIVÉ hors liste -> pair (anti-spoof pod)");
    }
