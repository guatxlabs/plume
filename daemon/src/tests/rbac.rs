    // ===================== RBAC MULTI-TENANT (#2b) =====================

    #[test]
    fn sso_grants_parses_tenant_role_and_superadmin() {
        // #2b (spec B.3) : plume-<tenant>-<role> + plume-superadmin + legacy plume-admin/editor/viewer.
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        // (1) convention multi-tenant : rôle per-tenant, plusieurs tenants, MAX(grants).
        let (m, sa) = sso_grants(&st, "plume-acme-admin|plume-beta-viewer|plume-beta-editor");
        assert!(!sa, "aucun groupe superadmin -> is_superadmin=false");
        assert_eq!(m.get("acme").map(String::as_str), Some("admin"), "plume-acme-admin -> admin sur acme");
        assert_eq!(m.get("beta").map(String::as_str), Some("editor"), "MAX(viewer,editor)=editor sur beta");
        // (2) superadmin : nom canonique OU groupe configuré (anti-lockout).
        assert!(sso_grants(&st, "plume-superadmin").1, "plume-superadmin -> superadmin");
        assert!(sso_grants(&st, "x|admins|y").1, "groupe sso_group_superadmin configuré -> superadmin");
        // (3) legacy mono-tenant -> tenant `default` (rétro-compat).
        let (ml, _) = sso_grants(&st, "plume-admin");
        assert_eq!(ml.get("default").map(String::as_str), Some("admin"), "plume-admin (legacy) -> admin sur default");
        let (me2, _) = sso_grants(&st, "plume-editor|plume-viewer");
        assert_eq!(me2.get("default").map(String::as_str), Some("editor"), "MAX(editor,viewer)=editor sur default");
        // (4) slug avec '-' interne (rsplit -> dernier segment = rôle).
        let (ms, _) = sso_grants(&st, "plume-site-paris-viewer");
        assert_eq!(ms.get("site-paris").map(String::as_str), Some("viewer"), "slug 'site-paris' + rôle viewer");
        // (5) rôle hors enum / groupe inconnu -> ignoré (aucun grant fabriqué).
        let (mn, san) = sso_grants(&st, "plume-acme-superuser|random|plume-x");
        assert!(mn.is_empty() && !san, "rôle hors enum + groupes inconnus -> aucun grant, pas superadmin : {mn:?}");
    }

    #[test]
    fn mode1_rbac_role_per_tenant() {
        // #2b : un même user est admin dans A et viewer dans B ; un viewer-de-B ne peut pas MUTER B ; un
        // user SANS grant sur C -> 403. Grants Basic/cookie (table `grant`) ET grants SSO (map live).
        let cp = mk_test_control();
        {
            let c = cp.conn.lock();
            for (id, p) in [("a", "/d/a.db"), ("b", "/d/b.db"), ("c", "/d/c.db")] {
                c.execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,?1,'',?2,?3,0)",
                          params![id, p, now()]).unwrap();
            }
            c.execute("INSERT INTO platform_user(id,name,hash,is_superadmin,created) VALUES('u','analyst',NULL,0,?1)", params![now()]).unwrap();
            c.execute("INSERT INTO platform_user(id,name,hash,is_superadmin,created) VALUES('s','stranger',NULL,0,?1)", params![now()]).unwrap();
            c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES('u','a','admin')", []).unwrap();
            c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES('u','b','viewer')", []).unwrap();
        }
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));

        // (1) rôle PER-TENANT : admin dans A, viewer dans B (grants control-plane, chemin Basic/cookie).
        let a = resolve_tenant_access(&st, "analyst", None, false, Some("a"), true, None).unwrap();
        assert_eq!((a.role.as_str(), a.cross_tenant, a.is_superadmin), ("admin", false, false), "analyst = admin dans A");
        let b = resolve_tenant_access(&st, "analyst", None, false, Some("b"), false, None).unwrap();
        assert_eq!(b.role, "viewer", "analyst = viewer dans B (rôle par-tenant, pas admin partout)");

        // (2) un viewer-de-B ne peut pas MUTER B (gate RBAC sur le rôle per-tenant résolu) ; un admin, oui.
        assert!(rbac_gate("viewer", "/api/incidents", true).is_err(), "viewer de B : mutation refusée (403)");
        assert!(rbac_gate("viewer", "/api/query", false).is_ok(), "viewer de B : lecture autorisée");
        assert!(rbac_gate("admin", "/api/incidents", true).is_ok(), "admin de A : mutation autorisée");

        // (3) sélection implicite -> 1er grant (ordre stable) = A (admin).
        let d = resolve_tenant_access(&st, "analyst", None, false, None, false, None).unwrap();
        assert_eq!((d.tenant.as_str(), d.role.as_str()), ("a", "admin"), "défaut = 1er grant (A, admin)");

        // (4) un user SANS grant sur C -> 403 (ni membre, ni superadmin). Idem analyst hors de ses grants.
        let c1 = resolve_tenant_access(&st, "stranger", None, false, Some("c"), false, None);
        assert_eq!(c1.unwrap_err().0, StatusCode::FORBIDDEN, "user sans grant sur C -> 403");
        let c2 = resolve_tenant_access(&st, "analyst", None, false, Some("c"), false, None);
        assert_eq!(c2.unwrap_err().0, StatusCode::FORBIDDEN, "analyst (granté A/B) sur C non granté -> 403");
        // user inconnu / sans aucun grant, sans sélection -> 403.
        assert!(resolve_tenant_access(&st, "stranger", None, false, None, false, None).is_err(), "aucun grant + pas de sélection -> 403");

        // (5) MÊMES rôles per-tenant via SSO (map LIVE), SANS ligne `grant` (compte SSO-only).
        let (map, sa) = sso_grants(&st, "plume-a-admin|plume-b-viewer");
        assert!(!sa);
        let sa_a = resolve_tenant_access(&st, "sso-user", Some(&map), false, Some("a"), true, None).unwrap();
        assert_eq!(sa_a.role, "admin", "SSO : admin dans A");
        let sa_b = resolve_tenant_access(&st, "sso-user", Some(&map), false, Some("b"), false, None).unwrap();
        assert_eq!(sa_b.role, "viewer", "SSO : viewer dans B");
        assert!(resolve_tenant_access(&st, "sso-user", Some(&map), false, Some("c"), false, None).is_err(), "SSO : tenant hors map -> 403");
    }

    #[test]
    fn mode1_superadmin_read_emits_marker() {
        // #2b/D3/R9 : un super-admin lit un tenant dont il n'est PAS membre -> accès CROSS-TENANT (viewer,
        // read-only) MARQUÉ 2x : control_ledger à CHAQUE accès + event `plume-operator-access` NON
        // DÉSACTIVABLE dans la base du tenant visité, DEBOUNCÉ (1 par fenêtre).
        let cp = mk_test_control();
        let p = mk_tmp_path("op-read.db");
        {
            let c = cp.conn.lock();
            c.execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('opread','R','',?1,?2,0)", params![p, now()]).unwrap();
            // super-admin plateforme SANS grant sur 'opread' (opérateur ESN).
            c.execute("INSERT INTO platform_user(id,name,hash,is_superadmin,created) VALUES('sa','op-reader',NULL,1,?1)", params![now()]).unwrap();
        }
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
        // crée le schéma de la base tenant visitée (writer mémoïsé).
        {
            let h = st.tenants.handle_for("opread").unwrap();
            let c = h.lock();
            c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&c);
        }
        // (1) résolution : accès CROSS-TENANT lecture (viewer, non membre).
        let acc = resolve_tenant_access(&st, "op-reader", None, false, Some("opread"), false, None).unwrap();
        assert_eq!((acc.role.as_str(), acc.is_superadmin, acc.cross_tenant), ("viewer", true, true),
                   "super-admin hors grant -> lecture cross-tenant (viewer, audité)");

        // (2) marqueur STRUCTUREL émis 2x (comme auth_guard le fait à chaque requête). control_ledger = 1
        //     entrée PAR accès ; l'event tenant-visible est DEBOUNCÉ (1 seul dans la fenêtre) mais garanti.
        emit_operator_access(&st, "op-reader", "opread", false, None);
        emit_operator_access(&st, "op-reader", "opread", false, None);
        let ledger: i64 = st.tenants.control.as_ref().unwrap().conn.lock()
            .query_row("SELECT COUNT(*) FROM control_ledger WHERE kind='superadmin.read' AND tenant='opread'", [], |r| r.get(0)).unwrap();
        assert_eq!(ledger, 2, "control_ledger : 1 entrée par accès (à CHAQUE accès)");
        let (ev, sev, cat): (i64, i64, String) = st.tenants.handle_for("opread").unwrap().lock()
            .query_row("SELECT COUNT(*), COALESCE(MAX(severity),0), COALESCE(MAX(category),'') FROM event WHERE source='plume-operator-access'", [],
                       |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!(ev, 1, "event operator-access DEBOUNCÉ (1 dans la fenêtre) mais NON désactivable -> garanti");
        assert_eq!((sev, cat.as_str()), (2, "audit"), "marqueur lecture : sévérité info/low, catégorie audit");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn mode1_superadmin_write_breakglass() {
        // #2b/D3 : une MUTATION cross-tenant par un super-admin exige le break-glass explicite. SANS le flag
        // -> 403 (jamais d'écriture cross-tenant silencieuse) ; AVEC -> autorisée (admin borné) + auditée 2x.
        let cp = mk_test_control();
        let p = mk_tmp_path("op-write.db");
        {
            let c = cp.conn.lock();
            c.execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('opwrite','W','',?1,?2,0)", params![p, now()]).unwrap();
            c.execute("INSERT INTO platform_user(id,name,hash,is_superadmin,created) VALUES('sa','op-writer',NULL,1,?1)", params![now()]).unwrap();
            // un non-superadmin sans grant -> ne peut JAMAIS écrire cross-tenant, même avec un flag.
            c.execute("INSERT INTO platform_user(id,name,hash,is_superadmin,created) VALUES('nb','nobody',NULL,0,?1)", params![now()]).unwrap();
        }
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
        {
            let h = st.tenants.handle_for("opwrite").unwrap();
            let c = h.lock();
            c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&c);
        }
        // (1) mutation cross-tenant SANS break-glass -> 403.
        let no_bg = resolve_tenant_access(&st, "op-writer", None, false, Some("opwrite"), true, None);
        assert_eq!(no_bg.unwrap_err().0, StatusCode::FORBIDDEN, "écriture cross-tenant sans break-glass -> 403");
        // (2) AVEC break-glass (raison non vide) -> autorisée, rôle admin BORNÉ, cross_tenant.
        let bg = resolve_tenant_access(&st, "op-writer", None, false, Some("opwrite"), true, Some("incident-77")).unwrap();
        assert_eq!((bg.role.as_str(), bg.cross_tenant), ("admin", true), "break-glass -> écriture autorisée (admin borné)");
        // raison VIDE = pas de break-glass valable -> 403.
        assert!(resolve_tenant_access(&st, "op-writer", None, false, Some("opwrite"), true, Some("   ")).is_err(), "raison vide -> 403");
        // (3) un NON-superadmin ne peut pas écrire cross-tenant, même avec un flag.
        assert_eq!(resolve_tenant_access(&st, "nobody", None, false, Some("opwrite"), true, Some("x")).unwrap_err().0,
                   StatusCode::FORBIDDEN, "non-superadmin : écriture cross-tenant refusée malgré le flag");

        // (4) marqueur break-glass : DEUX ledgers (control + tenant), event forcé + sévérité élevée.
        emit_operator_access(&st, "op-writer", "opwrite", true, Some("incident-77"));
        let ledger: i64 = st.tenants.control.as_ref().unwrap().conn.lock()
            .query_row("SELECT COUNT(*) FROM control_ledger WHERE kind='superadmin.write' AND tenant='opwrite'", [], |r| r.get(0)).unwrap();
        assert_eq!(ledger, 1, "1er ledger : control_ledger (superadmin.write)");
        let (ev, sev): (i64, i64) = st.tenants.handle_for("opwrite").unwrap().lock()
            .query_row("SELECT COUNT(*), COALESCE(MAX(severity),0) FROM event WHERE source='plume-operator-access'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((ev, sev), (1, 4), "2e ledger : event operator-access dans la base du tenant, sévérité élevée");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn session_cookie_roundtrip_and_tamper() {
        // FORM-LOGIN : un jeton frais se vérifie (user/role restitués) ; toute altération invalide.
        let secret = b"unit-test-secret-32-bytes-long!!";
        let tok = mint_session(secret, "alice|x", "admin", 3600, 0); // user contenant '|' : doit survivre
        assert_eq!(verify_session(secret, &tok, 0), Some(("alice|x".to_string(), "admin".to_string())));
        // signature falsifiée -> rejet
        let mut bad = tok.clone();
        bad.pop();
        bad.push(if tok.ends_with('0') { '1' } else { '0' });
        assert_eq!(verify_session(secret, &bad, 0), None, "signature altérée -> None");
        // mauvais secret -> rejet (HMAC)
        assert_eq!(verify_session(b"other-secret", &tok, 0), None, "mauvais secret -> None");
        // expiré -> rejet (mint_session clampe le TTL >=1 -> on forge un jeton à exp passé à la main).
        // La signature est calculée sur `{p_b64}|{epoch}` (epoch=0) pour matcher le format L2.
        use base64::Engine as _;
        let exp = now() - 10;
        let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("bob|viewer|{exp}").as_bytes());
        let sig = hmac_sha256(secret, format!("{p_b64}|0").as_bytes());
        let expired = format!("{p_b64}.{}", hex_encode(&sig));
        assert_eq!(verify_session(secret, &expired, 0), None, "jeton expiré -> None");
    }

    #[test]
    fn csrf_token_is_deterministic_and_bound_to_session() {
        // le CSRF est dérivé (HMAC) du jeton de session -> recalculable sans état, lié à la session.
        let secret = b"unit-test-secret-32-bytes-long!!";
        let tok = mint_session(secret, "carol", "editor", 3600, 0);
        let a = csrf_for(secret, &tok);
        assert_eq!(a, csrf_for(secret, &tok), "déterministe pour un même (secret, session)");
        assert!(!a.is_empty());
        let other = mint_session(secret, "carol", "editor", 3600, 0); // exp différent (now+...) ou même : token distinct probable
        // un token de session DIFFÉRENT donne un CSRF différent (sauf collision improbable du même token)
        if other != tok {
            assert_ne!(a, csrf_for(secret, &other), "CSRF lié au jeton de session");
        }
    }

    #[test]
    fn cookie_value_extracts_named_cookie() {
        let h = "foo=1; plume_session=abc.def; plume_csrf=zzz";
        assert_eq!(cookie_value(h, "plume_session"), Some("abc.def".to_string()));
        assert_eq!(cookie_value(h, "plume_csrf"), Some("zzz".to_string()));
        assert_eq!(cookie_value(h, "absent"), None);
        assert_eq!(cookie_value("", "plume_session"), None);
    }

    #[test]
    fn session_epoch_revokes_prior_tokens() {
        // L2 (RÉVOCATION) : un bump d'epoch (logout / changement de mdp) invalide TOUS les jetons antérieurs
        // (leur signature, recalculée avec le nouvel epoch, ne correspond plus). Un jeton frappé au NOUVEL
        // epoch reste valide -> une reconnexion après logout marche. Le TTL reste indépendant (double borne).
        let secret = b"unit-test-secret-32-bytes-long!!";
        let tok0 = mint_session(secret, "alice", "admin", 3600, 0);
        assert_eq!(verify_session(secret, &tok0, 0), Some(("alice".to_string(), "admin".to_string())), "epoch courant -> valide");
        // epoch bumpé (logout) -> l'ancien jeton est REJETÉ.
        assert_eq!(verify_session(secret, &tok0, 1), None, "epoch bumpé -> jeton antérieur révoqué");
        // un nouveau jeton à l'epoch courant (relogin) est valide, et n'est PAS accepté à un autre epoch.
        let tok1 = mint_session(secret, "alice", "admin", 3600, 1);
        assert_eq!(verify_session(secret, &tok1, 1), Some(("alice".to_string(), "admin".to_string())), "relogin post-bump -> valide");
        assert_eq!(verify_session(secret, &tok1, 0), None, "jeton d'epoch 1 rejeté à l'epoch 0");
        assert_eq!(verify_session(secret, &tok1, 2), None, "jeton d'epoch 1 rejeté après un nouveau bump");
    }

    #[test]
    fn bump_session_epoch_persists_and_increments() {
        // L2 : bump_session_epoch incrémente le compteur EN MÉMOIRE et le PERSISTE dans meta (survit au
        // redémarrage -> load_session_epoch relit la valeur). Effet immédiat + durable.
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None); // mode 0
        assert_eq!(st.session_epoch.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(load_session_epoch(&st.db.lock()), 0, "meta démarre à 0 (schema.sql)");
        bump_session_epoch(&st);
        assert_eq!(st.session_epoch.load(std::sync::atomic::Ordering::Relaxed), 1, "compteur mémoire incrémenté");
        assert_eq!(load_session_epoch(&st.db.lock()), 1, "compteur PERSISTÉ dans meta");
        bump_session_epoch(&st);
        assert_eq!(load_session_epoch(&st.db.lock()), 2, "re-bump persiste 2");
    }

    #[tokio::test]
    async fn logout_bumps_epoch_only_with_valid_session_antidos() {
        // L2-fix (ANTI-DoS) : /api/logout est PUBLIC ; le bump d'epoch (révocation GLOBALE de TOUTES les
        // sessions) ne doit se produire QUE si l'appelant présente un cookie de session VALIDE. Sinon un tiers
        // NON authentifié pourrait marteler /api/logout pour déconnecter en boucle tous les utilisateurs
        // (DoS d'auth). Le but sécu est préservé : un logout LÉGITIME (cookie valide) révoque bien les jetons.
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None); // mode 0
        let e0 = st.session_epoch.load(std::sync::atomic::Ordering::Relaxed);
        // (1) AUCUN cookie -> réponse OK (cookies effacés) mais PAS de bump.
        let resp = logout_post(State(st.clone()), axum::http::HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::OK, "logout répond toujours 200 (efface les cookies)");
        assert_eq!(st.session_epoch.load(std::sync::atomic::Ordering::Relaxed), e0, "logout non authentifié -> AUCUN bump (anti-DoS)");
        // (2) cookie INVALIDE (signature bidon) -> pas de bump.
        let mut bad = axum::http::HeaderMap::new();
        bad.insert(header::COOKIE, "plume_session=not.a.valid.token".parse().unwrap());
        let _ = logout_post(State(st.clone()), bad).await;
        assert_eq!(st.session_epoch.load(std::sync::atomic::Ordering::Relaxed), e0, "cookie invalide -> AUCUN bump");
        // (3) cookie VALIDE (frappé à l'epoch courant) -> bump (révocation légitime : le cookie exfiltré tombe).
        let tok = mint_session(st.session_secret.as_slice(), "alice", "admin", 3600, e0);
        let mut good = axum::http::HeaderMap::new();
        good.insert(header::COOKIE, format!("plume_session={tok}").parse().unwrap());
        let _ = logout_post(State(st.clone()), good).await;
        assert_eq!(st.session_epoch.load(std::sync::atomic::Ordering::Relaxed), e0 + 1, "logout authentifié (cookie valide) -> révocation serveur (bump)");
    }

    #[test]
    fn live_role_reresolves_and_denies_deleted_user() {
        // L2 (mode 0) : le rôle est RE-RÉSOLU LIVE depuis la table `user`, jamais le rôle figé du cookie.
        // Un rôle changé prend effet immédiatement ; un compte supprimé -> None (cookie refusé, 401).
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None); // mode 0 (control=None)
        {
            let c = st.db.lock();
            c.execute("INSERT INTO user(name,hash,role) VALUES('bob','x','editor')", []).unwrap();
        }
        assert_eq!(live_role_for(&st, "bob").as_deref(), Some("editor"), "rôle live = editor");
        // rétrogradation editor -> viewer : le rôle live suit IMMÉDIATEMENT (pas d'attente du TTL cookie).
        st.db.lock().execute("UPDATE user SET role='viewer' WHERE name='bob'", []).unwrap();
        assert_eq!(live_role_for(&st, "bob").as_deref(), Some("viewer"), "rétrogradation prise en compte live");
        // suppression -> None (le cookie ne vaut plus rien -> 401 côté auth_guard).
        st.db.lock().execute("DELETE FROM user WHERE name='bob'", []).unwrap();
        assert_eq!(live_role_for(&st, "bob"), None, "compte supprimé -> plus d'identité");
        // un utilisateur jamais inscrit (ni table, ni admin, ni config) -> None.
        assert_eq!(live_role_for(&st, "ghost"), None, "inconnu -> None");
    }

    #[test]
    fn live_role_falls_back_to_wizard_admin() {
        // L2 : un admin défini par le wizard (meta, PAS dans la table user à ce test) est résolu admin.
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        *st.admin.lock() = Some(("root".to_string(), "$argon2id$fake".to_string()));
        assert_eq!(live_role_for(&st, "root").as_deref(), Some("admin"), "admin wizard résolu admin");
        assert_eq!(live_role_for(&st, "autre"), None, "un autre nom n'hérite pas d'admin");
    }

    #[test]
    fn ingest_disk_guard_pure_thresholds() {
        // L1 (DÉCISION PURE du garde disque). Refuse ssi free < seuil ; désactivé si seuil=0 ; FAIL-OPEN si
        // la mesure est indisponible (None). INVARIANT : ne coupe QUE quand on SAIT le disque saturé.
        assert!(!ingest_disk_reject(0, Some(0)), "seuil 0 = garde désactivé (jamais de refus)");
        assert!(!ingest_disk_reject(512, None), "mesure indispo -> FAIL-OPEN (collecte préservée)");
        assert!(ingest_disk_reject(512, Some(100)), "100 Mo libres < 512 -> refus");
        assert!(!ingest_disk_reject(512, Some(512)), "pile au seuil -> autorisé (strictement inférieur)");
        assert!(!ingest_disk_reject(512, Some(10_000)), "disque sain -> autorisé");
        // fs_free_mb mesure un volume RÉEL : le répertoire temp existe et a de l'espace libre (>0).
        let tmp = std::env::temp_dir();
        let free = fs_free_mb(tmp.to_str().unwrap());
        assert!(free.map(|f| f > 0).unwrap_or(false), "statvfs du répertoire temp -> espace libre > 0 ({free:?})");
        assert_eq!(fs_free_mb("/chemin/inexistant/plume-xyz"), None, "chemin absent -> None (fail-open)");
    }

    /// GARDE-FOU #29 — décisions PURES de l'alerte pré-saturation disque (usage % + seuil).
    #[test]
    fn disk_health_pure_thresholds() {
        assert_eq!(disk_used_pct(100, 20), Some(80), "80% utilisé");
        assert_eq!(disk_used_pct(100, 10), Some(90));
        assert_eq!(disk_used_pct(100, 0), Some(100));
        assert_eq!(disk_used_pct(0, 0), None, "volume vide/illisible -> None (fail-open)");
        assert_eq!(disk_used_pct(100, 200), Some(0), "dispo>total (réservé) -> 0% (saturate)");
        assert!(!disk_health_should_warn(80, 80), "pile au seuil -> pas de warn (strict)");
        assert!(disk_health_should_warn(81, 80), "au-delà du seuil -> warn");
        assert!(disk_health_should_warn(94, 80), "94% -> warn (scénario incident VPS)");
        assert!(!disk_health_should_warn(99, 0), "seuil 0 = garde désactivé");
        // fs_total_avail_mb mesure un volume RÉEL (répertoire temp) : total>0 et total>=dispo.
        let tmp = std::env::temp_dir();
        if let Some((total, avail)) = fs_total_avail_mb(tmp.to_str().unwrap()) {
            assert!(total > 0 && total >= avail, "statvfs cohérent (total={total}, avail={avail})");
        }
        assert_eq!(fs_total_avail_mb("/chemin/inexistant/plume-xyz"), None, "chemin absent -> None");
    }

    /// GARDE-FOU #29 — l'émission est RATE-LIMITÉE par dedup horaire : deux appels dans la même heure -> UN
    /// seul event ; l'heure suivante -> un nouveau. Seuil 0 -> aucun event.
    #[test]
    fn disk_health_emit_rate_limited_hourly() {
        let conn = test_db();
        let tmp = std::env::temp_dir();
        let p = tmp.to_string_lossy().into_owned();
        let cnt = |c: &Connection| c.query_row("SELECT COUNT(*) FROM event WHERE source='plume-disk'", [], |r| r.get::<_, i64>(0)).unwrap();
        // seuil 0 = désactivé -> jamais d'event.
        assert!(!emit_disk_health(&conn, &p, 0, 3600));
        assert_eq!(cnt(&conn), 0);
        // seuil 1% : tout volume réel est >1% utilisé -> émet (si statvfs mesurable sur cet env).
        let e1 = emit_disk_health(&conn, &p, 1, 3600);
        let _ = emit_disk_health(&conn, &p, 1, 3601); // même bucket horaire (3600/3600 == 3601/3600 == 1)
        if e1 {
            assert_eq!(cnt(&conn), 1, "dedup horaire : 1 warn/heure malgré 2 appels");
            let _ = emit_disk_health(&conn, &p, 1, 7200); // heure suivante
            assert_eq!(cnt(&conn), 2, "nouvelle heure -> nouveau warn autorisé");
            // l'event porte le contexte structuré attendu (used_pct + seuil).
            let f: String = conn.query_row("SELECT fields FROM event WHERE source='plume-disk' LIMIT 1", [], |r| r.get(0)).unwrap();
            assert!(f.contains("used_pct") && f.contains("threshold_pct"), "fields structurés");
        }
    }

    /// #23/#24 — les règles d'activation seedées (TI alert + RBA starter) COMPILENT via rule_sql (sinon
    /// run_due_rules/run_risk_rules les sauteraient silencieusement -> activation inerte). Garde-fou direct.
    #[test]
    fn seeded_activation_rules_compile() {
        for (_n, q, is_soql, _op, _th, _sev, _iv, win, _m) in TI_ALERT_RULES {
            rule_sql(q, is_soql != 0, win).unwrap_or_else(|e| panic!("règle TI '{q}' ne compile pas: {e}"));
        }
        for (_n, q, is_soql, win, _sev, _rs, _et, _ef, _iv, _m) in RISK_STARTER_RULES {
            rule_sql(q, is_soql != 0, win).unwrap_or_else(|e| panic!("règle RBA '{q}' ne compile pas: {e}"));
        }
    }

    /// #23/#24 — seed_ti_alert_rules + seed_risk_rules posent des règles MANAGÉES (managed=0 : éditables/
    /// réversibles en UI), IDEMPOTENTES (flag meta), et les règles RBA sont bien en MODE RISK (risk_score>0
    /// + entité) -> exclues de run_due_rules, traitées par run_risk_rules.
    #[test]
    fn seed_activation_rules_are_managed_idempotent_and_risk_mode() {
        let conn = test_db();
        seed_ti_alert_rules(&conn);
        seed_risk_rules(&conn);
        seed_ti_alert_rules(&conn); // ré-exécution -> idempotent (flag meta)
        seed_risk_rules(&conn);
        // TI : 2 règles managed=0, risk_score=0 (alerte scalaire), seedées DÉSACTIVÉES (dark-by-default,
        // Wave 3 git-durability : une règle TI activée-mais-sans-feed-IOC est GHOST -> ne doit pas suggérer
        // une couverture inexistante ; un admin l'active via le toggle une fois un feed câblé). Cet assert
        // ENCODE le comportement dark-by-default : enabled=0 au seed.
        let ti: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE name LIKE 'Threat-intel%' AND managed=0 AND enabled=0 AND COALESCE(risk_score,0)=0", [], |r| r.get(0)).unwrap();
        assert_eq!(ti, 2, "2 règles TI managées, mode alerte, seedées DÉSACTIVÉES (dark-by-default)");
        // RBA : 2 règles managed=0, enabled=1, risk_score>0 + entité renseignée (mode risque).
        let rba: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE name LIKE 'RBA %' AND managed=0 AND enabled=1 AND risk_score>0 AND risk_entity_type<>'' AND risk_entity_field<>''", [], |r| r.get(0)).unwrap();
        assert_eq!(rba, 2, "2 règles RBA managées, activées, mode risque (entité renseignée)");
    }

    /// #26 — prune config.d : supprime UNIQUEMENT les overlays orphelins (managed=1 sans fichier adossé),
    /// jamais un builtin (managed=0) ni un ad-hoc UI (managed=2). Un overlay TOUJOURS adossé survit.
    #[test]
    fn overlay_prune_removes_orphans_only() {
        let conn = test_db();
        // 2 overlays (managed=1) : 'ov-kept' (adossé) + 'ov-orphan' (fichier retiré) ; 1 builtin ; 1 ad-hoc.
        conn.execute("INSERT INTO rule(name,managed) VALUES('ov-kept',1)", []).unwrap();
        conn.execute("INSERT INTO rule(name,managed) VALUES('ov-orphan',1)", []).unwrap();
        conn.execute("INSERT INTO rule(name,managed) VALUES('builtin-rule',0)", []).unwrap();
        conn.execute("INSERT INTO rule(name,managed) VALUES('adhoc-rule',2)", []).unwrap();
        // un parseur overlay orphelin (aucun fichier parsers/) -> doit être élagué aussi.
        conn.execute("INSERT INTO parser(name,source,pattern,enabled,builtin,managed) VALUES('ov-parser','*','x',1,0,1)", []).unwrap();
        // config.d temporaire avec SEULEMENT rules/kept.json (adosse 'ov-kept').
        let mut root = std::env::temp_dir();
        root.push(format!("plume-cfgd-{}-{}", std::process::id(), now()));
        std::fs::create_dir_all(root.join("rules")).unwrap();
        std::fs::write(root.join("rules").join("kept.json"), br#"{"name":"ov-kept","query":"search | stats count","is_soql":true}"#).unwrap();
        let counts = prune_orphan_overlays(&conn, &root).unwrap();
        assert_eq!(counts.rule, 1, "seul l'overlay règle orphelin (ov-orphan) est élagué");
        assert_eq!(counts.parser, 1, "l'overlay parseur orphelin est élagué");
        let has = |name: &str| conn.query_row("SELECT COUNT(*) FROM rule WHERE name=?1", params![name], |r| r.get::<_, i64>(0)).unwrap() == 1;
        assert!(has("ov-kept"), "overlay adossé conservé");
        assert!(!has("ov-orphan"), "overlay orphelin supprimé");
        assert!(has("builtin-rule"), "builtin (managed=0) JAMAIS touché");
        assert!(has("adhoc-rule"), "ad-hoc UI (managed=2) JAMAIS touché");
        // idempotent : re-appel -> 0 orphelin.
        let again = prune_orphan_overlays(&conn, &root).unwrap();
        assert_eq!(again, PruneCounts::default(), "idempotent : aucun orphelin au 2e passage");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ingest_events_cap_pure() {
        // L1 (PLAFOND DE CARDINALITÉ). Ne compte QUE le tableau `events` ; > plafond -> refus (413).
        let three = json!({ "kind": "events", "events": [1, 2, 3] });
        assert!(ingest_events_over_cap(&three, 2), "3 events > plafond 2 -> refus");
        assert!(!ingest_events_over_cap(&three, 3), "3 events == plafond 3 -> OK (strictement supérieur)");
        assert!(!ingest_events_over_cap(&three, 50000), "batch normal sous plafond généreux -> OK");
        assert!(!ingest_events_over_cap(&three, 0), "plafond 0 = désactivé");
        // les autres kinds (pas de tableau `events`) ne sont jamais concernés.
        let metrics = json!({ "kind": "metrics", "metrics": [1, 2, 3, 4] });
        assert!(!ingest_events_over_cap(&metrics, 1), "kind sans tableau events -> jamais de refus");
    }

    #[test]
    fn alert_defaults_mitre_to_empty_string() {
        // une alerte SANS mitre explicite (chemins non-règle) -> '' (NOT NULL DEFAULT), jamais NULL.
        let conn = test_db();
        conn.execute(
            "INSERT INTO alert(ts,rule,severity,title) VALUES(?1,'manual',2,'test')",
            params![now()],
        ).unwrap();
        let m: String = conn.query_row("SELECT mitre FROM alert WHERE rule='manual'", [], |r| r.get(0)).unwrap();
        assert_eq!(m, "", "alert.mitre doit défauter à '' (rétro-compat)");
    }

    #[test]
    fn seeded_rules_carry_mitre_tags() {
        // la règle « pic d'échecs d'auth » est taguée T1110 (brute force) ; la règle CPU reste non mappée ''.
        let conn = test_db();
        seed_example_rules(&conn);
        let auth: String = conn.query_row(
            "SELECT mitre FROM rule WHERE name LIKE 'Pic d%authentification%'", [], |r| r.get(0),
        ).unwrap();
        assert_eq!(auth, "T1110", "la règle auth doit être taguée T1110");
        let cpu: String = conn.query_row(
            "SELECT mitre FROM rule WHERE name LIKE 'CPU%'", [], |r| r.get(0),
        ).unwrap();
        assert_eq!(cpu, "", "la règle CPU (opérationnelle) ne doit pas être mappée");
    }

    /// Réplique EXACTE de l'agrégation servie par coverage_detections() -> garantit que le test mesure
    /// le même contrat que l'endpoint (mitre<>'' GROUP BY mitre -> [{mitre,count,first_ts}], ts>=since).
    fn coverage(conn: &Connection, since: i64) -> Vec<(String, i64, i64)> {
        let mut st = conn.prepare(
            "SELECT mitre, COUNT(*) AS count, MIN(ts) AS first_ts FROM alert \
             WHERE mitre IS NOT NULL AND mitre<>'' AND ts>=?1 GROUP BY mitre ORDER BY count DESC, mitre",
        ).unwrap();
        st.query_map(params![since], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)))
            .unwrap().flatten().collect()
    }

    #[test]
    fn coverage_aggregates_detected_techniques() {
        let conn = test_db();
        // 2 détections T1110 (à t=100 puis t=150 -> first_ts=100) + 1 détection T1190 + 1 alerte non mappée.
        conn.execute("INSERT INTO alert(ts,rule,severity,title,mitre) VALUES(100,'rule.1',3,'a','T1110')", []).unwrap();
        conn.execute("INSERT INTO alert(ts,rule,severity,title,mitre) VALUES(150,'rule.1',3,'b','T1110')", []).unwrap();
        conn.execute("INSERT INTO alert(ts,rule,severity,title,mitre) VALUES(120,'rule.2',4,'c','T1190')", []).unwrap();
        conn.execute("INSERT INTO alert(ts,rule,severity,title,mitre) VALUES(130,'manual',1,'d','')", []).unwrap();

        let cov = coverage(&conn, 0);
        // tri par count DESC : T1110 (2) avant T1190 (1) ; la ligne mitre='' est EXCLUE.
        assert_eq!(cov.len(), 2, "seules les techniques mappées doivent apparaître");
        assert_eq!(cov[0], ("T1110".to_string(), 2, 100), "T1110 = 2 détections, 1re à t=100");
        assert_eq!(cov[1], ("T1190".to_string(), 1, 120), "T1190 = 1 détection, t=120");

        // borne `since` : à partir de t=130, seule la 2e alerte T1110 (t=150) compte -> count=1, first_ts=150.
        let cov2 = coverage(&conn, 130);
        assert_eq!(cov2, vec![("T1110".to_string(), 1, 150)]);
    }

    // --- #22 : matrice de couverture ATT&CK (build_attack_matrix, pur) ---
    // Helpers de navigation dans le JSON de matrice.
    fn find_tactic<'a>(m: &'a Value, tac: &str) -> Option<&'a Value> {
        m["tactics"].as_array()?.iter().find(|t| t["tactic"] == tac)
    }
    fn find_tech<'a>(m: &'a Value, tac: &str, tid: &str) -> Option<&'a Value> {
        find_tactic(m, tac)?["techniques"].as_array()?.iter().find(|t| t["tid"] == tid)
    }

    #[test]
    fn attack_matrix_aggregates_and_classifies() {
        // 2 règles activées : T1110 (credential-access) + T1046 (discovery). Alertes : 3× T1110, 1× T1595.
        let rules = vec!["T1110".to_string(), "T1046".to_string()];
        let mut alerts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        alerts.insert("T1110".into(), 3);
        alerts.insert("T1595".into(), 1); // reconnaissance : détectée mais AUCUNE règle -> blind-spot alerté.
        let m = build_attack_matrix(&rules, &alerts);

        // technique->tactique : T1110 rangée sous credential-access, T1046 sous discovery.
        let t1110 = find_tech(&m, "credential-access", "T1110").expect("T1110 sous credential-access");
        assert_eq!(t1110["rule_count"], 1);
        assert_eq!(t1110["alert_count"], 3);
        assert_eq!(t1110["covered"], true);
        let t1046 = find_tech(&m, "discovery", "T1046").expect("T1046 sous discovery");
        assert_eq!(t1046["rule_count"], 1);
        assert_eq!(t1046["covered"], true);

        // BLIND-SPOT : T1595 a une alerte mais 0 règle -> covered=false, rule_count=0 (visible dans la matrice).
        let t1595 = find_tech(&m, "reconnaissance", "T1595").expect("T1595 présent (catalogue)");
        assert_eq!(t1595["rule_count"], 0);
        assert_eq!(t1595["alert_count"], 1);
        assert_eq!(t1595["covered"], false);

        // Une technique du catalogue jamais touchée reste présente et non couverte (le point du navigator).
        let t1486 = find_tech(&m, "impact", "T1486").expect("T1486 présent");
        assert_eq!(t1486["covered"], false);
        assert_eq!(t1486["rule_count"], 0);

        // Agrégats par TACTIQUE : credential-access couvert (>=1 règle) ; reconnaissance NON (0 règle).
        assert_eq!(find_tactic(&m, "credential-access").unwrap()["covered"], true);
        assert_eq!(find_tactic(&m, "credential-access").unwrap()["rule_count"], 1);
        assert_eq!(find_tactic(&m, "reconnaissance").unwrap()["covered"], false);
        assert_eq!(find_tactic(&m, "reconnaissance").unwrap()["rule_count"], 0);

        // Totaux : 2 techniques couvertes, 2 tactiques couvertes (credential-access + discovery), rules_mapped=2.
        assert_eq!(m["totals"]["techniques_covered"], 2);
        assert_eq!(m["totals"]["tactics_covered"], 2);
        assert_eq!(m["totals"]["rules_mapped"], 2);
        assert_eq!(m["totals"]["alerts"], 4); // 3 + 1
        // toutes les techniques du catalogue apparaissent, dont beaucoup non couvertes.
        let total = m["totals"]["techniques"].as_i64().unwrap();
        assert!(total >= 180, "la matrice énumère tout le catalogue (blind-spots inclus), vu {total}");
        assert_eq!(total, m["totals"]["techniques_covered"].as_i64().unwrap() + m["totals"]["techniques_uncovered"].as_i64().unwrap());
    }

    #[test]
    fn attack_matrix_empty_rules_all_uncovered() {
        // Aucune règle, aucune alerte -> toute la matrice non couverte (0 covered), catalogue complet présent.
        let m = build_attack_matrix(&[], &std::collections::HashMap::new());
        assert_eq!(m["totals"]["techniques_covered"], 0);
        assert_eq!(m["totals"]["tactics_covered"], 0);
        assert_eq!(m["totals"]["rules_mapped"], 0);
        assert_eq!(m["totals"]["alerts"], 0);
        assert_eq!(m["totals"]["techniques"], m["totals"]["techniques_uncovered"]);
        // chaque tactique canonique est présente et non couverte.
        for tac in guatx_core::attack::TACTICS {
            assert_eq!(find_tactic(&m, tac).expect("tactique présente")["covered"], false);
        }
    }

    #[test]
    fn attack_matrix_rule_with_multiple_techniques() {
        // SUPERSET : une seule règle taguée avec PLUSIEURS techniques (espaces/virgules) couvre chacune.
        // Sous-technique -> parente (T1562.001 -> T1562). Doublon (T1110 + T1110.001) compté une fois.
        let rules = vec!["T1110 T1046, T1562.001".to_string(), "T1110.001;T1110".to_string()];
        let m = build_attack_matrix(&rules, &std::collections::HashMap::new());
        // T1046 & T1562 couvertes par la 1re règle.
        assert_eq!(find_tech(&m, "discovery", "T1046").unwrap()["covered"], true);
        assert_eq!(find_tech(&m, "defense-evasion", "T1562").unwrap()["rule_count"], 1);
        // T1110 : ciblée par les DEUX règles (chacune une fois, malgré le doublon T1110/T1110.001 interne) -> 2.
        assert_eq!(find_tech(&m, "credential-access", "T1110").unwrap()["rule_count"], 2);
        // rules_mapped = 2 règles (chacune a >=1 technique reconnue).
        assert_eq!(m["totals"]["rules_mapped"], 2);
    }

    #[test]
    fn attack_matrix_unmapped_technique_preserved() {
        // SUPERSET : un tag hors catalogue (technique custom/vendeur valide en format) n'est JAMAIS perdu ->
        // replié dans la pseudo-tactique `unmapped`, jamais faussement attribué à une tactique connue.
        let rules = vec!["T9999".to_string()]; // format valide, hors CATALOG curé.
        let m = build_attack_matrix(&rules, &std::collections::HashMap::new());
        let unm = find_tactic(&m, "unmapped").expect("pseudo-tactique unmapped présente");
        assert_eq!(unm["covered"], true);
        let t = find_tech(&m, "unmapped", "T9999").expect("T9999 préservée");
        assert_eq!(t["rule_count"], 1);
    }

    #[test]
    fn rule_mitre_propagates_to_alert_on_fire() {
        // simule le coeur de run_due_rules : une règle taguée T1046 qui déclenche -> l'alerte HÉRITE du mitre.
        let conn = test_db();
        conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,window_s,mitre) \
             VALUES('scan ports','search source=nmap | stats count',1,'>',0.0,2,3600,'T1046')",
            [],
        ).unwrap();
        let (id, name, mitre, window_s, severity): (i64, String, String, i64, i64) = conn.query_row(
            "SELECT id,name,COALESCE(mitre,''),window_s,severity FROM rule WHERE name='scan ports'", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).unwrap();
        // reproduit l'INSERT d'alerte de la phase 3 (mitre hérité de la règle).
        let now_ts = 1_000_000i64;
        let dedup = format!("rule-{}-{}", id, now_ts / window_s.max(60));
        conn.execute(
            "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup,mitre) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![now_ts, format!("rule.{id}"), severity, format!("{name} : déclenche"), "q", dedup, mitre],
        ).unwrap();
        let got: String = conn.query_row(
            "SELECT mitre FROM alert WHERE rule=?1", params![format!("rule.{id}")], |r| r.get(0),
        ).unwrap();
        assert_eq!(got, "T1046", "l'alerte doit hériter du tag MITRE de sa règle");
        // et l'endpoint de couverture la voit.
        let cov = coverage(&conn, 0);
        assert_eq!(cov, vec![("T1046".to_string(), 1, now_ts)]);
    }

    // ----- FTS-FIELDS : tests du chemin PLUME_FTS_FIELDS=1 (reconcile crée triggers + indexe) et du
    // kill-switch reconcile (toggle on->off droppe vtable+triggers). On passe la conf en argument
    // (pas d'env muté -> déterministe et sûr en parallèle ; cfg() lit l'env AVANT la conf, donc on
    // s'assure qu'aucune var d'env de test n'interfère via un nom de clé qui n'est posé QUE en conf).

    fn obj_exists(conn: &Connection, typ: &str, name: &str) -> bool {
        conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type=?1 AND name=?2",
            params![typ, name],
            |_| Ok(()),
        )
        .is_ok()
    }

    /// conf isolée : on retire toute var d'env homonyme (PLUME_*) pour que cfg() prenne la conf.
    fn conf_with(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        let mut m = std::collections::HashMap::new();
        for (k, v) in pairs {
            // garde-fou : si l'env porte la même clé, le test serait non déterministe -> on la retire.
            std::env::remove_var(k);
            m.insert(k.to_string(), v.to_string());
        }
        m
    }

    #[test]
    fn reconcile_fts_on_creates_infra_and_indexes_insert() {
        // PLUME_FTS_FIELDS=1 -> reconcile crée la vtable + les triggers ; un INSERT event remplit le FTS.
        let conn = test_db();
        let conf = conf_with(&[("PLUME_FTS_FIELDS", "1")]);
        reconcile_index_state(&conn, &conf);

        assert!(obj_exists(&conn, "table", "event_fields_fts"), "vtable FTS absente après reconcile ON");
        assert!(obj_exists(&conn, "trigger", "event_ff_ai"), "trigger AI absent après reconcile ON");
        assert!(obj_exists(&conn, "trigger", "event_ff_ad"), "trigger AD absent après reconcile ON");

        // INSERT -> le trigger AI doit produire 1 doc FTS contenant les valeurs scalaires de `fields`.
        conn.execute(
            "INSERT INTO event(id,ts,source,fields) VALUES(1,100,'sshd',json('{\"user\":\"alice\",\"action\":\"login\"}'))",
            [],
        ).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM event_fields_fts WHERE event_fields_fts MATCH 'alice'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "le MATCH sur la valeur 'alice' doit trouver le doc FTS de l'event inséré");
    }

    #[test]
    fn reconcile_fts_delete_leaves_no_orphan_postings() {
        // TRIGGER AD : après DELETE de l'event, le trigger AD (reconstruction des tokens) doit décrémenter
        // les postings -> plus aucun doc ne matche (table contentless 3.39.4, sans contentless_delete).
        let conn = test_db();
        let conf = conf_with(&[("PLUME_FTS_FIELDS", "1")]);
        reconcile_index_state(&conn, &conf);

        conn.execute(
            "INSERT INTO event(id,ts,source,fields) VALUES(7,100,'sshd',json('{\"user\":\"bob\",\"action\":\"login\"}'))",
            [],
        ).unwrap();
        let before: i64 = conn
            .query_row("SELECT COUNT(*) FROM event_fields_fts WHERE event_fields_fts MATCH 'bob'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(before, 1, "doc présent avant DELETE");

        conn.execute("DELETE FROM event WHERE id=7", []).unwrap();
        let after: i64 = conn
            .query_row("SELECT COUNT(*) FROM event_fields_fts WHERE event_fields_fts MATCH 'bob'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(after, 0, "le DELETE doit retirer le doc FTS (pas de posting orphelin -> pas de fuite disque)");
    }

    #[test]
    fn reconcile_toggle_on_then_off_drops_infra() {
        // KILL-SWITCH : le vrai kill-switch. ON crée, puis OFF (toggle env + redeploy simulé) droppe TOUT.
        let conn = test_db();

        let on = conf_with(&[("PLUME_FTS_FIELDS", "1")]);
        reconcile_index_state(&conn, &on);
        assert!(obj_exists(&conn, "table", "event_fields_fts"), "vtable doit exister après ON");

        let off = conf_with(&[("PLUME_FTS_FIELDS", "0")]);
        reconcile_index_state(&conn, &off);
        assert!(!obj_exists(&conn, "table", "event_fields_fts"), "vtable doit être DROPPÉE après OFF (kill-switch)");
        assert!(!obj_exists(&conn, "trigger", "event_ff_ai"), "trigger AI doit être droppé après OFF");
        assert!(!obj_exists(&conn, "trigger", "event_ff_ad"), "trigger AD doit être droppé après OFF");
    }

    #[test]
    fn reconcile_is_idempotent_on_and_off() {
        // re-jouer reconcile (ON puis ON, OFF puis OFF) ne doit jamais échouer (CREATE/DROP IF [NOT] EXISTS).
        let conn = test_db();
        let on = conf_with(&[("PLUME_FTS_FIELDS", "1")]);
        reconcile_index_state(&conn, &on);
        reconcile_index_state(&conn, &on); // 2e passe : no-op, pas d'erreur
        assert!(obj_exists(&conn, "table", "event_fields_fts"));
        let off = conf_with(&[("PLUME_FTS_FIELDS", "0")]);
        reconcile_index_state(&conn, &off);
        reconcile_index_state(&conn, &off); // 2e passe : no-op, pas d'erreur
        assert!(!obj_exists(&conn, "table", "event_fields_fts"));
    }

    #[test]
    fn reconcile_expr_index_off_drops_indexes() {
        // PLUME_EXPRINDEX=0 -> les 7 index expression sont droppés (kill-switch dur). On en crée un à la
        // main (comme le ferait le background ON) puis on vérifie que le reconcile OFF le retire.
        let conn = test_db();
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ev_f_user ON event(json_extract(fields,'$.user')) \
             WHERE json_extract(fields,'$.user') IS NOT NULL",
            [],
        ).unwrap();
        assert!(obj_exists(&conn, "index", "idx_ev_f_user"), "index présent avant OFF");
        let off = conf_with(&[("PLUME_EXPRINDEX", "0")]);
        reconcile_index_state(&conn, &off);
        assert!(!obj_exists(&conn, "index", "idx_ev_f_user"), "index doit être droppé après PLUME_EXPRINDEX=0");
    }

