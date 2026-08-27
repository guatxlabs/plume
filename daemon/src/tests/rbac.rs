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
        let (cp, _cptmp) = mk_test_control();
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
        let (cp, _cptmp) = mk_test_control();
        let p = mk_tmp_path("op-read.db");
        {
            let c = cp.conn.lock();
            c.execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('opread','R','',?1,?2,0)", params![p.as_str(), now()]).unwrap();
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
        let (cp, _cptmp) = mk_test_control();
        let p = mk_tmp_path("op-write.db");
        {
            let c = cp.conn.lock();
            c.execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('opwrite','W','',?1,?2,0)", params![p.as_str(), now()]).unwrap();
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
        let tmp = crate::tmp_possede::TmpPossede::neuf("statvfs-free");
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
        let tmp = crate::tmp_possede::TmpPossede::neuf("statvfs-total");
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
        let tmp = crate::tmp_possede::TmpPossede::neuf("disk-health");
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
        let _tmpg1 = crate::tmp_possede::TmpPossede::neuf("cfgd");
        let root = _tmpg1.racine().chemin().to_path_buf();
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

    /// Réplique EXACTE de ce que sert coverage_detections() -> garantit que le test mesure le même
    /// contrat que l'endpoint : mêmes SQL/binds (mitre<>'' GROUP BY mitre, ts>=since) PUIS le MÊME
    /// éclatement des tags multi-techniques (`explode_detection_rows`, la fonction de production —
    /// pas une seconde implémentation qui pourrait diverger en silence).
    fn coverage(conn: &Connection, since: i64) -> Vec<(String, i64, i64)> {
        let mut st = conn.prepare(
            "SELECT mitre, COUNT(*) AS count, MIN(ts) AS first_ts FROM alert \
             WHERE mitre IS NOT NULL AND mitre<>'' AND ts>=?1 GROUP BY mitre ORDER BY count DESC, mitre",
        ).unwrap();
        let rows: Vec<(String, i64, i64)> = st
            .query_map(params![since], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)))
            .unwrap().flatten().collect();
        explode_detection_rows(rows)
            .into_iter()
            .map(|v| (
                v["mitre"].as_str().unwrap().to_string(),
                v["count"].as_i64().unwrap(),
                v["first_ts"].as_i64().unwrap(),
            ))
            .collect()
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

    /// PURPLE — un tag de règle portant PLUSIEURS techniques (norme SigmaHQ : plusieurs `attack.` par
    /// règle) est SERVI ÉCLATÉ par /api/coverage/detections : une entrée par technique, counts sommés,
    /// `first_ts` = la PREMIÈRE détection. Sans cet éclatement, le consommateur purple joindrait sur la
    /// pseudo-technique `"T1595.002 T1046"` — qui n'existe dans aucun référentiel — et fabriquerait
    /// deux faux « missed ». La SOUS-technique est PRÉSERVÉE (pas de repli sur la parente : c'est elle
    /// qui distingue une détection exacte d'une simple couverture parente côté Forge).
    #[test]
    fn coverage_splits_multi_technique_tags_preserving_subtechniques() {
        let conn = test_db();
        // une règle Sigma taguée de DEUX techniques -> 2 alertes ; + 1 alerte T1046 nue (agrégation).
        conn.execute("INSERT INTO alert(ts,rule,severity,title,mitre) VALUES(100,'rule.sigma',3,'a','T1595.002 T1046')", []).unwrap();
        conn.execute("INSERT INTO alert(ts,rule,severity,title,mitre) VALUES(140,'rule.sigma',3,'b','T1595.002 T1046')", []).unwrap();
        conn.execute("INSERT INTO alert(ts,rule,severity,title,mitre) VALUES(120,'rule.scan',3,'c','T1046')", []).unwrap();

        let cov = coverage(&conn, 0);
        let by: std::collections::HashMap<&str, (i64, i64)> =
            cov.iter().map(|(m, c, t)| (m.as_str(), (*c, *t))).collect();
        assert!(!by.contains_key("T1595.002 T1046"),
            "le tag COMPOSÉ ne doit JAMAIS être servi tel quel comme une technique : {cov:?}");
        assert_eq!(by.get("T1595.002"), Some(&(2i64, 100i64)),
            "la SOUS-technique est servie telle quelle (jamais repliée sur T1595) : {cov:?}");
        assert_eq!(by.get("T1046"), Some(&(3i64, 100i64)),
            "T1046 agrège le tag composé (2) + l'alerte nue (1), first_ts = la 1re des deux : {cov:?}");
        assert!(!by.contains_key("T1595"),
            "aucun repli sur la technique PARENTE ici — la distinction exact/parent meurt sinon");
        // tri de sortie conservé : count DESC puis mitre ASC.
        assert_eq!(cov[0].0, "T1046", "tri count DESC conservé : {cov:?}");

        // borne `since` : l'éclatement n'échappe pas à la fenêtre (seule l'alerte t=140 reste).
        let cov2 = coverage(&conn, 130);
        let by2: std::collections::HashMap<&str, (i64, i64)> =
            cov2.iter().map(|(m, c, t)| (m.as_str(), (*c, *t))).collect();
        assert_eq!(by2.get("T1595.002"), Some(&(1i64, 140i64)));
        assert_eq!(by2.get("T1046"), Some(&(1i64, 140i64)));
    }

    /// PURPLE — `mitre_techniques` (éclatement SANS repli parent) : les 3 séparateurs, la casse, la
    /// déduplication, le rejet des tokens hors format — et la garantie ANTI-SILENT-DROP au niveau des
    /// lignes servies (un tag vendeur illisible reste servi VERBATIM plutôt que de disparaître).
    /// CONTRASTE avec `mitre_parents`, qui replie sur la parente pour la grille de couverture.
    #[test]
    fn mitre_techniques_splits_without_collapsing_to_parent() {
        assert_eq!(mitre_techniques("T1595.002 T1046"), vec!["T1595.002", "T1046"]);
        assert_eq!(mitre_techniques("T1595.002,T1046"), vec!["T1595.002", "T1046"]);
        assert_eq!(mitre_techniques("T1595.002;T1046"), vec!["T1595.002", "T1046"]);
        assert_eq!(mitre_techniques("t1046  T1046"), vec!["T1046"], "casse normalisée + dédupliqué");
        assert_eq!(mitre_techniques("attack.t1046 TA0043 T1046"), vec!["T1046"], "tokens hors format ignorés");
        assert!(mitre_techniques("pas-une-technique").is_empty());
        // CONTRASTE explicite : mitre_parents replie, mitre_techniques NON.
        assert_eq!(mitre_parents("T1110.001"), vec!["T1110"], "mitre_parents replie sur la parente");
        assert_eq!(mitre_techniques("T1110.001"), vec!["T1110.001"], "mitre_techniques PRÉSERVE la sous-technique");
        // ANTI-SILENT-DROP au niveau des lignes servies.
        let out = explode_detection_rows(vec![("vendor-custom".to_string(), 5, 42)]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["mitre"], "vendor-custom", "un tag illisible est servi VERBATIM, jamais perdu");
        assert_eq!(out[0]["count"], 5);
        // une ligne au tag VIDE après trim ne produit rien (rien à joindre).
        assert!(explode_detection_rows(vec![("   ".to_string(), 1, 1)]).is_empty());
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
        let m = build_attack_matrix(&rules, &[], &alerts);

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
        let m = build_attack_matrix(&[], &[], &std::collections::HashMap::new());
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
        let m = build_attack_matrix(&rules, &[], &std::collections::HashMap::new());
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
        let m = build_attack_matrix(&rules, &[], &std::collections::HashMap::new());
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
        let _env = VERROU_ENV_PROCESSUS.write(); // l'environnement du processus est MUTÉ ici : verrou UNIQUE en écriture (common.rs)
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
        let _env = VERROU_ENV_PROCESSUS.write(); // l'environnement du processus est MUTÉ ici : verrou UNIQUE en écriture (common.rs)
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
        let _env = VERROU_ENV_PROCESSUS.write(); // l'environnement du processus est MUTÉ ici : verrou UNIQUE en écriture (common.rs)
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
        let _env = VERROU_ENV_PROCESSUS.write(); // l'environnement du processus est MUTÉ ici : verrou UNIQUE en écriture (common.rs)
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
        let _env = VERROU_ENV_PROCESSUS.write(); // l'environnement du processus est MUTÉ ici : verrou UNIQUE en écriture (common.rs)
        // PLUME_EXPRINDEX=0 -> TOUS les index expression (un par EXPR_INDEX_FIELDS) sont droppés
        // (kill-switch dur). On en crée un à la
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


// ================================================================================================
// CÂBLAGE DU ROUTEUR (composition) — mesuré AVANT correctif : en retirant la couche `auth_guard` de
// `build_router`, la suite passait 762/762. Chaque garde d'autorisation était prouvée à la COUTURE
// (`rbac_gate` / `route_min_role` / `is_readonly_post`, fonctions pures) et AUCUNE au CÂBLAGE. Le
// précédent CRITICAL du projet était précisément un défaut de COMPOSITION (route mutante hors de
// l'allowlist admin-only, `rbac_gate` fail-open par défaut) : c'est un angle mort STRUCTUREL.
//
// GARDE DÉRIVÉE (pas d'énumération de routes) : axum n'expose PAS d'itérateur sur sa table matchit, mais
// les routes sont déclarées à UN SEUL endroit (`daemon/src/server/groupes_de_routes.rs`, les `*_routes()` fusionnés par
// `build_router`). Les tests ci-dessous LISENT cette table dans la source, CONSTRUISENT le routeur réel,
// le servent sur une socket loopback éphémère, et interrogent CHAQUE (route, méthode) déclarée. Une route
// ajoutée demain entre donc automatiquement dans le périmètre — personne n'a à l'inscrire sur une liste.
// ================================================================================================

/// LE TEXTE DU MODULE `server` — la façade ET tous ses sous-modules, concaténés dans l'ordre des
/// chemins. DÉRIVÉ DU PRÉFIXE DE RÉPERTOIRE, jamais d'un nom de fichier : `server/mod.rs` est devenu
/// `server/mod.rs` plus des sous-modules (`P7.18-a`), et une garde restée sur le nom du fichier serait
/// devenue VERTE EN ÉTANT AVEUGLE — elle aurait cessé de lire la table de routage sans que rien ne le
/// dise. Un sous-module ajouté demain est lu sans que personne ait à l'inscrire quelque part.
fn texte_du_module_serveur() -> String {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("server");
    let mut fichiers = Vec::new();
    crate::db_open::door_tests::rs_files(&dir, &mut fichiers);
    fichiers.sort();
    assert!(
        !fichiers.is_empty(),
        "INSTRUMENT MUET : aucun fichier `.rs` sous `{}` — le module `server` a été déplacé et la \
         garde ne lit plus rien.",
        dir.display()
    );
    fichiers.iter().map(|p| std::fs::read_to_string(p).expect("source du module `server` lisible"))
        .collect::<Vec<_>>().join("\n")
}

/// Table de routage DÉCLARÉE, lue à son UNIQUE site de déclaration : (chemin axum, méthodes HTTP).
/// Une route ajoutée dans le module `server` apparaît ici sans action supplémentaire.
fn declared_route_table() -> Vec<(String, Vec<String>)> {
    let src = texte_du_module_serveur();
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for line in src.lines() {
        let code = line.split("//").next().unwrap_or(""); // jamais un `.route(` en commentaire
        let Some(rest) = code.split_once(".route(\"") else { continue };
        let Some((path, tail)) = rest.1.split_once('"') else { continue };
        let mut methods: Vec<String> = ["get", "post", "put", "delete", "patch"]
            .iter().filter(|v| tail.contains(&format!("{v}("))).map(|v| v.to_uppercase()).collect();
        if methods.is_empty() { continue; }
        methods.sort();
        out.push((path.to_string(), methods));
    }
    out
}

/// Chemin CONCRET pour une route paramétrée (`/api/rules/{id}/test` -> `/api/rules/1/test`).
///
/// LA SYNTAXE DU GABARIT EST CELLE DU ROUTEUR, ET ELLE A DÉJÀ CHANGÉ (axum 0.7 `:id` -> axum 0.8
/// `{id}`). Une substitution muette est le pire des cas : le chemin sondé resterait le gabarit
/// LITTÉRAL, le routeur répondrait 404, et TOUTE la famille `router_*` / `netban_*` passerait au vert
/// en ne mesurant plus rien. La fonction REFUSE donc de rendre un chemin qui porte encore une marque
/// de gabarit, au lieu de le sonder tel quel.
///
/// CE QU'ELLE NE TIENT PAS : elle ne valide pas que la valeur substituée (`1`) est acceptable pour le
/// handler — un identifiant inexistant est justement ce qu'on veut (on mesure le CÂBLAGE d'autorisation,
/// qui décide AVANT le handler), et un 404 métier ne se distingue pas ici d'un 404 de table.
fn concrete_path(p: &str) -> String {
    let concret = p
        .split('/')
        .map(|seg| if seg.starts_with('{') && seg.ends_with('}') { "1" } else { seg })
        .collect::<Vec<_>>()
        .join("/");
    assert!(
        !concret.contains(['{', '}']) && !concret.split('/').any(|s| s.starts_with(':')),
        "INSTRUMENT MUET : `{p}` n'a pas été rendu concret (`{concret}`). La syntaxe de gabarit du \
         routeur a changé sous la substitution : les sondes interrogeraient le gabarit LITTÉRAL, \
         récolteraient des 404, et les gardes de câblage seraient VERTES EN ÉTANT AVEUGLES."
    );
    concret
}

/// Routes que `auth_guard` sert AVANT toute vérification d'identité/rôle (chaque entrée = une décision de
/// sécurité assumée, justifiée). Les tests n'attendent donc PAS de 403 dessus — mais `router_*_anonymous`
/// exige quand même qu'AUCUNE ne réponde 2xx à un anonyme hors des trois sondes publiques.
const ROUTER_PRE_GATE_BYPASS: &[(&str, &str)] = &[
    ("/healthz", "sonde k8s liveness (aucune donnée)"),
    ("/readyz", "sonde k8s readiness (aucune donnée)"),
    ("/api/login", "l'auth se fait DANS le handler (verify_pw + lockout)"),
    ("/api/logout", "efface le cookie ; aucune donnée"),
    ("/api/login/mfa", "2e facteur : validé DANS le handler (code TOTP)"),
    ("/api/auth/ldap", "bind LDAP validé DANS le handler"),
    ("/api/auth/oidc/", "id_token OIDC signé, validé DANS le handler"),
    ("/api/auth/saml/", "assertion SAML signée, validée DANS le handler"),
    ("/services/collector/health", "health-check HEC public (comme Splunk)"),
    ("/api/ingest/firehose", "clé de livraison AWS propriétaire, vérifiée DANS le handler"),
    ("/api/ingest/pubsub", "clé de livraison GCP en query, vérifiée DANS le handler"),
    ("/scim/v2/", "bearer SCIM dédié ; mode 0 -> 404 (endpoint fonctionnellement absent)"),
    ("/api/ai/", "feature `ai` OFF par défaut -> routes EXCLUES à la compilation (absentes du routeur)"),
];
fn router_bypassed(path: &str) -> bool {
    ROUTER_PRE_GATE_BYPASS.iter().any(|(p, _)| if p.ends_with('/') { path.starts_with(p) } else { path == *p })
}

/// Routes de MÉTHODE MUTANTE délibérément ouvertes à un `viewer` : SELF-SERVICE STRICT — le handler n'opère
/// que sur `au.name` (owner-scopé), aucune donnée d'autrui, aucun secret, aucune autorisation. Aujourd'hui
/// ces décisions ne vivaient que dans des commentaires de `route_min_role` : les épingler ici force toute
/// NOUVELLE route mutante ouverte au viewer à être déclarée (et justifiée) au lieu de passer inaperçue.
/// Chemins EXACTS (pas de préfixe) : un préfixe `/api/mfa/` exempterait tout le sous-arbre, donc une route
/// mutante AJOUTÉE demain sous ce préfixe — c'est précisément la mutation qu'on doit détecter. Mesuré :
/// avec des préfixes, `POST /api/mfa/purge-all-events` (route mutante rangée sous un préfixe classé LECTURE
/// par `route_min_role`, la forme EXACTE du CRITICAL historique) passait le test. En exact, elle rougit.
const ROUTER_VIEWER_SELF_SERVICE: &[(&str, &str)] = &[
    ("/api/prefs", "#62 préférences d'UI self-scopées (le handler écrit user_pref WHERE user=au.name)"),
    ("/api/saved-queries", "requêtes GXQL nommées per-user (owner=au.name posé par le handler ; IDOR fermé)"),
    ("/api/saved-queries/{id}", "idem, mutation WHERE id=? AND owner=au.name (IDOR fermé)"),
    ("/api/mfa/enroll", "#44 enrôlement de SA PROPRE MFA (au.name uniquement)"),
    ("/api/mfa/verify", "#44 vérification de SON PROPRE code TOTP"),
    ("/api/mfa/disable", "#44 désactivation de SA PROPRE MFA"),
];
fn router_viewer_self_service(path: &str) -> bool {
    ROUTER_VIEWER_SELF_SERVICE.iter().any(|(p, _)| path == *p)
}

/// AppState file-backed avec un mot de passe admin POSÉ (sinon `auth_guard` est en mode SETUP et répond
/// 401 partout pour une raison qui n'est PAS l'authentification) + un compte `viewer` réel.
fn router_test_state(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
    let path = ff_tmp_path(tag);
    {
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture routeur : migrations complètes");
        conn.execute("INSERT INTO user(name,hash,role) VALUES('vwr',?1,'viewer')", params![hash_pw("viewerpw12345").unwrap()]).unwrap();
    }
    let mut st = ds_file_state(&path);
    st.user = Arc::new("root".to_string());
    st.pass_hash = Arc::new(hash_pw("rootpw1234567").unwrap());
    // Plafonds de rate-limit relevés : le balayage envoie >250 requêtes depuis 127.0.0.1 en <10 s, ce qui
    // franchit LÉGITIMEMENT le budget d'auth strict (`rl_auth_max`=120/10 s, partagé par IP) -> /api/setup
    // et /api/password répondraient 429 au lieu de 401. Ces tests mesurent le câblage AUTH/RBAC, pas le
    // limiteur (qui n'est donc PAS couvert ici — dit explicitement).
    st.rl_auth_max = 1_000_000;
    st.rl_ip_max = 1_000_000;
    st.rl_global_max = 1_000_000;
    (st, path)
}

/// Sert le routeur RÉEL (toutes ses couches) sur 127.0.0.1:0 et renvoie l'adresse liée.
async fn router_serve(st: AppState) -> std::net::SocketAddr {
    // Répertoire web VOLONTAIREMENT inexistant (ServeDir doit 404) : RIEN n'y est jamais créé, donc
    // il n'y a rien à posséder. On passe par le coffre pour que ce cas reste visible en un seul point.
    let webdir = crate::tmp_possede::racine_systeme().join("plume-router-test-webdir-inexistant");
    let app = build_router(st, webdir.to_string_lossy().into_owned());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await;
    });
    addr
}

/// Une requête HTTP/1.1 brute -> code de statut (0 si pas de réponse). Aucune dépendance nouvelle : on
/// parle le protocole à la main sur une TcpStream (et c'est CE chemin-là qu'on veut, pas un appel direct
/// au handler : le but est justement de traverser les 6 couches du routeur).
async fn router_probe(addr: std::net::SocketAddr, method: &str, path: &str, authz: Option<&str>) -> u16 {
    router_probe_h(addr, method, path, authz, &[]).await
}

/// La MÊME sonde, avec des en-têtes libres — la couche `net_ban_guard` décide sur l'IP RÉELLE, qui se
/// présente justement dans un en-tête posé par le proxy. UNE seule implémentation du dialogue HTTP : deux
/// sondes divergeraient, et la famille de tests qui défend la COMPOSITION du routeur doit interroger le
/// routeur de la même façon partout.
async fn router_probe_h(addr: std::net::SocketAddr, method: &str, path: &str, authz: Option<&str>, headers: &[(&str, &str)]) -> u16 {
    router_probe_corps(addr, method, path, authz, headers).await.0
}

/// La MÊME sonde, qui rend AUSSI le début de la réponse (borné à 4 Kio). MESURÉ : deux couches
/// différentes rendent le MÊME code — `POST /api/ingest/firehose` répond 403 sur une clé de livraison
/// invalide, exactement comme le gate de ban. Un test qui ne lit que le code compte alors un refus de
/// handler comme la preuve d'un blocage qu'il n'a pas observé. Ce que la couche ÉCRIT, lui, la nomme.
async fn router_probe_corps(addr: std::net::SocketAddr, method: &str, path: &str, authz: Option<&str>, headers: &[(&str, &str)]) -> (u16, String) {
    router_probe_envoi(addr, method, path, authz, headers, "").await
}

/// La MÊME sonde, qui ENVOIE un corps de requête. Une seule implémentation du dialogue HTTP (celle-ci) :
/// `router_probe_corps` n'est plus que le cas « corps vide », et `Content-Length` est DÉRIVÉ du corps
/// plutôt qu'écrit à zéro — une sonde qui annoncerait 0 en envoyant des octets ferait lire au serveur une
/// requête tronquée, et le refus mesuré serait celui du protocole, pas celui de l'extracteur.
async fn router_probe_envoi(addr: std::net::SocketAddr, method: &str, path: &str, authz: Option<&str>, headers: &[(&str, &str)], corps: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        corps.len()
    );
    if let Some(a) = authz { req.push_str(&format!("Authorization: {a}\r\n")); }
    for (k, v) in headers { req.push_str(&format!("{k}: {v}\r\n")); }
    req.push_str("\r\n");
    req.push_str(corps);
    let fut = async {
        let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
        s.write_all(req.as_bytes()).await.ok()?;
        // Lecture BORNÉE : le serveur ferme après la réponse (`Connection: close`), mais une réponse
        // longue (exposition Prometheus, page servie) ne doit pas faire lire la sonde sans limite.
        let mut brut: Vec<u8> = Vec::with_capacity(1024);
        let mut buf = [0u8; 1024];
        while brut.len() < 4096 {
            match s.read(&mut buf).await.ok()? {
                0 => break,
                n => brut.extend_from_slice(&buf[..n]),
            }
        }
        let texte = String::from_utf8_lossy(&brut).into_owned();
        let code = texte.split_whitespace().nth(1)?.parse::<u16>().ok()?;
        Some((code, texte))
    };
    tokio::time::timeout(Duration::from_secs(20), fut).await.ok().flatten().unwrap_or((0, String::new()))
}

fn viewer_authz() -> String {
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("vwr:viewerpw12345"))
}

/// (B-1) AUTHENTIFICATION CÂBLÉE — toute route déclarée hors bypass répond EXACTEMENT 401 à une requête
/// ANONYME. L'attente est le CONTRAT de `auth_guard` (« pas d'identité -> 401 »), pas un simple « pas de
/// 2xx » : sans la couche, l'extracteur `Extension<AuthUser>` échoue en 500 et un test « pas de 2xx »
/// laisserait passer la suppression de l'authentification. Mesuré : retirer la couche fait rougir 176 (route,
/// méthode) mutantes + 28 GET admin-only + 3 routes servies en 200 à un anonyme (/metrics,
/// /api/soql/templates, /api/setup-status) ; avant ces tests, la même mutation ne faisait rougir RIEN.
#[tokio::test]
async fn router_no_declared_route_serves_anonymous_requests() {
    let (st, dbp) = router_test_state("router-anon");
    let table = declared_route_table();
    assert!(table.len() > 200, "table de routage lue depuis le module `server` : {} routes", table.len());
    let addr = router_serve(st).await;
    let mut bad: Vec<String> = Vec::new();
    let mut probed = 0usize;
    for (path, methods) in &table {
        if router_bypassed(path) { continue; } // routes servies AVANT le gate (liste déclarée + justifiée)
        for m in methods {
            let code = router_probe(addr, m, &concrete_path(path), None).await;
            probed += 1;
            if code != 401 { bad.push(format!("{m} {path} -> {code}")); }
        }
    }
    assert!(probed > 250, "sonde effective sur toute la table ({probed} requêtes)");
    assert!(bad.is_empty(),
        "ROUTE NE RÉPONDANT PAS 401 À UN ANONYME : {bad:?}. Toute route déclarée doit exiger une identité \
         (couche auth_guard dans build_router) ; une route servie avant le gate doit être AJOUTÉE À \
         `ROUTER_PRE_GATE_BYPASS` avec sa justification, jamais par accident.");
    ff_rm(&dbp);
}

/// (B-2) RBAC CÂBLÉ, ET L'ATTENTE N'EST PAS DÉRIVÉE DE LA TABLE QU'ON VÉRIFIE — pour chaque route dont la
/// MÉTHODE HTTP est mutante (POST/PUT/DELETE/PATCH), un compte `viewer` AUTHENTIFIÉ doit recevoir 403, sauf
/// si le chemin est un POST DE LECTURE déclaré (`is_readonly_post`). L'attente vient de la MÉTHODE (un fait
/// externe), PAS de `route_min_role` : une erreur de classification de chemin — exactement le CRITICAL
/// historique (route mutante rangée du côté lecture) — est donc DÉTECTÉE et non recopiée.
/// (Les routes attendues 403 sont rejetées par `auth_guard` AVANT le handler : aucun handler ne s'exécute.)
#[tokio::test]
async fn router_viewer_cannot_reach_any_mutating_route() {
    let (st, dbp) = router_test_state("router-viewer");
    let addr = router_serve(st).await;
    let authz = viewer_authz();
    let mut leaks: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for (path, methods) in declared_route_table() {
        if router_bypassed(&path) || router_viewer_self_service(&path) { continue; }
        for m in &methods {
            if m == "GET" { continue; }
            if is_readonly_post(&concrete_path(&path)) { continue; } // POST de LECTURE déclaré (liste gardée en B-3)
            let code = router_probe(addr, m, &concrete_path(&path), Some(&authz)).await;
            checked += 1;
            if code != 403 { leaks.push(format!("{m} {path} -> {code}")); }
        }
    }
    assert!(checked > 100, "sonde effective sur les routes mutantes ({checked})");
    assert!(leaks.is_empty(),
        "ROUTE MUTANTE ATTEIGNABLE PAR UN VIEWER (attendu 403) : {leaks:?}. Soit la route est mal classée \
         par route_min_role (le CRITICAL historique), soit la couche RBAC n'est plus câblée dans build_router.");
    ff_rm(&dbp);
}

/// (B-3) Les GET ADMIN-ONLY sont câblés eux aussi (secrets/config exposés en LECTURE : users, tokens, idp,
/// notifiers, connectors, ledger…), ET la liste des POST DE LECTURE — le levier EXACT du fail-open
/// historique — est enfin épinglée : `is_readonly_post` accorde `mutating=false` (donc viewer+) à des POST ;
/// aucun test ne gardait cette liste, malgré le commentaire d'auth.rs qui en annonçait un.
#[tokio::test]
async fn router_admin_only_gets_and_readonly_post_allowlist_are_wired() {
    // (a) la liste des POST DE LECTURE est FERMÉE et déclarée : chaque entrée est une LECTURE (compile ou
    //     exécute un GXQL via le chemin masqué #45 ; aucune mutation, aucun SQL brut).
    const DECLARED_READONLY_POSTS: &[&str] = &[
        "/api/query", "/api/cancel", "/api/export",
        "/api/ds/query", "/api/v1/query", "/api/v1/query_range", "/api/v1/series", "/api/v1/labels",
        "/loki/api/v1/query_range", "/api/pivot/compile", "/api/pivot/run", "/api/soql/validate",
        "/api/datasets/1/run", "/api/workflow-actions/1/resolve",
        // NB : `/api/search` est AUSSI dans `is_readonly_post` mais sa route est déclarée en GET SEUL ->
        // l'exemption y est INERTE (aucune surface mutante ouverte). Elle apparaîtrait ici si un POST
        // /api/search était un jour déclaré — ce qui EXIGERAIT de le justifier.
    ];
    let mut found: Vec<String> = Vec::new();
    for (path, methods) in declared_route_table() {
        if methods.iter().all(|m| m == "GET") { continue; }
        let c = concrete_path(&path);
        if is_readonly_post(&c) { found.push(c); }
    }
    found.sort();
    found.dedup();
    let mut declared: Vec<String> = DECLARED_READONLY_POSTS.iter().map(|s| s.to_string()).collect();
    declared.sort();
    assert_eq!(found, declared,
        "POST DE LECTURE (viewer+ sur une méthode mutante) : l'ensemble TROUVÉ doit être l'ensemble \
         DÉCLARÉ. Trouvé={found:?} / Déclaré={declared:?}. Ajouter un chemin à `is_readonly_post` OUVRE \
         cette route au viewer : c'est le levier exact du fail-open historique -> à déclarer ICI.");

    // (b) CÂBLAGE : tout GET que `rbac_gate` refuse à un viewer doit RÉELLEMENT renvoyer 403 via le routeur.
    let (st, dbp) = router_test_state("router-adminget");
    let addr = router_serve(st).await;
    let authz = viewer_authz();
    let mut leaks: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for (path, methods) in declared_route_table() {
        if router_bypassed(&path) || !methods.iter().any(|m| m == "GET") { continue; }
        if rbac_gate("viewer", &concrete_path(&path), false).is_ok() { continue; }
        let code = router_probe(addr, "GET", &concrete_path(&path), Some(&authz)).await;
        checked += 1;
        if code != 403 { leaks.push(format!("GET {path} -> {code}")); }
    }
    assert!(checked > 20, "sonde effective sur les GET admin-only ({checked})");
    assert!(leaks.is_empty(), "GET ADMIN-ONLY ATTEIGNABLE PAR UN VIEWER (attendu 403) : {leaks:?}");
    ff_rm(&dbp);
}

/// (B-4) UN CORPS JSON SUIVI D'OCTETS PARASITES EST DÉSORMAIS REFUSÉ — 400, LÀ OÙ IL ÉTAIT ACCEPTÉ.
///
/// CE N'EST PAS UNE PROPRIÉTÉ DE PLUME, C'EST UNE PROPRIÉTÉ DE SON EXTRACTEUR, ET ELLE A CHANGÉ SOUS
/// NOS PIEDS. `axum::Json` appelle `Deserializer::end()` depuis axum 0.8.5 — VERSION D'INTRODUCTION
/// VÉRIFIÉE, pas empruntée : l'entrée « Reject JSON request bodies with trailing characters after the
/// JSON document » (#3453) est celle de `0.8.5` dans le `CHANGELOG.md` de la caisse `axum` 0.8.9 telle
/// qu'elle est VERROUILLÉE par `Cargo.lock` (lu le 2026-08-26). Ce que ce chiffre ne dit toujours pas :
/// la source est le journal de l'éditeur, pas un banc de cette machine — aucun essai n'a été fait
/// CONTRE 0.8.4 ici. Ce qui EST mesuré sur ce poste, c'est la borne large : 0.7.9 accepte, 0.8.9
/// refuse. Un corps qui est un
/// document JSON valide SUIVI de n'importe quoi (`{"user":"x"} parasite`) était lu jusqu'au document
/// et le reste IGNORÉ ; il rend maintenant `JsonSyntaxError`, c'est-à-dire **400**. Toutes les routes
/// du démon qui prennent `Json<T>` sont concernées — c'est-à-dire l'essentiel de la surface mutante.
///
/// La sonde traverse le ROUTEUR RÉEL. `/api/login` est le bon site : il prend `Json<Value>`, il est
/// servi AVANT le gate d'identité (`ROUTER_PRE_GATE_BYPASS`), donc le code observé vient de
/// l'extracteur ou du handler, jamais de l'autorisation.
///
/// DEUX TÉMOINS, sans quoi un 400 ne prouverait rien :
///   - POSITIF : le MÊME corps sans les octets parasites atteint le handler et rend 401
///     (identifiants invalides) — la route est donc bien joignable et l'extracteur bien passant ;
///   - NÉGATIF : avec les octets parasites, 400 ET le corps de la réponse NOMME l'analyse JSON.
///     Sans la lecture du corps, un 400 rendu par une tout autre couche se lirait comme une preuve.
///
/// CE QUE CE TEST NE TIENT PAS, ET POURQUOI CE N'EST PLUS UN TROU : il ne dit rien des clients qui
/// envoient ces octets parasites (il n'y en a aucun dans `web/`, qui sérialise par `JSON.stringify`).
/// Il ne sonde ni `Form<T>` ni `Query<T>` — et la raison n'est pas « seul le texte change », c'est que
/// leur refus est INATTEIGNABLE dans cet arbre. MESURÉ le 2026-08-26 : les VINGT-SEPT sites `Query<…>`
/// et l'UNIQUE site `Form<…>` du démon sont tous `HashMap<String, String>`, or `form_urlencoded::parse`
/// ne rend que des paires de chaînes (il remplace un octet non-UTF-8 au lieu d'échouer) — il n'existe
/// donc aucune entrée qui fasse échouer la désérialisation, et le `serde_path_to_error` qu'axum 0.8
/// ajoute n'a aucun champ à nommer. C'est le même argument qui rend le 422 d'axum inatteignable :
/// 193 des 194 `Json<…>` sont `Json<Value>`.
///
/// LA SURFACE LARGE N'EST PAS CELLE-LÀ, C'EST `Path` — 101 sites `Path<i64>`, dont le CORPS de refus a
/// changé sans changer de code. Elle a sa propre sonde :
/// `router_path_i64_ecrit_la_valeur_de_refus_sans_guillemets`.
#[tokio::test]
async fn router_json_refuse_les_octets_parasites_apres_le_document() {
    let (st, dbp) = router_test_state("router-json-parasite");
    let addr = router_serve(st).await;
    let entetes = [("Content-Type", "application/json")];

    let propre = r#"{"user":"compte-inexistant-a","pass":"motdepasse-invalide"}"#;
    let (code_propre, corps_propre) =
        router_probe_envoi(addr, "POST", "/api/login", None, &entetes, propre).await;
    assert_eq!(
        code_propre, 401,
        "TÉMOIN POSITIF EN ÉCHEC : un corps JSON PROPRE doit atteindre le handler de connexion et \
         rendre 401 (identifiants invalides). Reçu {code_propre} — la sonde ne mesure pas l'extracteur \
         mais autre chose. Réponse : {corps_propre}"
    );

    let parasite = format!("{propre} parasite");
    let (code_parasite, corps_parasite) =
        router_probe_envoi(addr, "POST", "/api/login", None, &entetes, &parasite).await;
    assert_eq!(
        code_parasite, 400,
        "MÊME corps + octets parasites après le document : attendu 400 (l'extracteur `Json` refuse \
         depuis axum 0.8.5). Reçu {code_parasite}. Si c'est 401, l'extracteur a REPRIS l'indulgence \
         d'axum 0.7 et le contrat de refus de l'API a changé sans que personne ne l'ait décidé. \
         Réponse : {corps_parasite}"
    );
    assert!(
        corps_parasite.contains("Failed to parse the request body as JSON"),
        "le 400 doit être ÉCRIT par l'analyse JSON, pas par une autre couche qui rend le même code : \
         {corps_parasite}"
    );
    ff_rm(&dbp);
}

/// (B-5) LE CORPS D'UN REFUS DE `Path<i64>` A CHANGÉ — MÊME CODE, AUTRE TEXTE, ET RIEN NE LE DISAIT.
///
/// C'EST LA SURFACE LA PLUS LARGE DE LA MONTÉE. Entre axum 0.7.9 et 0.8.9, l'affichage de
/// `ErrorKind::ParseError` passe de `{value:?}` à `{value}` (`src/extract/path/mod.rs`, les deux
/// caisses lues dans le registre cargo le 2026-08-26) : le corps servi passe de
/// ``Invalid URL: Cannot parse `"abc"` to a `i64` `` à ``Invalid URL: Cannot parse `abc` to a `i64` ``.
/// Le CODE reste 400 des deux côtés — `ParseError` est dans la liste `BAD_REQUEST` des deux `status()`
/// — donc AUCUNE garde de code de refus ne pouvait le voir. MESURÉ sur l'arbre le 2026-08-26 :
/// 101 sites `Path<i64>`, c'est-à-dire la quasi-totalité des routes à identifiant, atteignable par
/// n'importe quel segment non numérique.
///
/// DEUX TÉMOINS :
///   - POSITIF : le MÊME gabarit avec un identifiant NUMÉRIQUE n'est pas refusé par l'extracteur —
///     sans quoi un 400 ne dirait pas d'où il vient (la route pourrait être fermée, absente, gatée) ;
///   - NÉGATIF (celui qui porte la mutation) : le segment non numérique rend 400 ET le corps porte la
///     valeur SANS guillemets. La forme d'AVANT est asserte absente, faute de quoi un retour en
///     arrière d'axum passerait au vert.
///
/// CE QUE CE TEST NE TIENT PAS : il épingle le texte d'UNE famille de refus (`ParseError`), pas la
/// liste des refus de `Path` ; et il ne répare rien — un client qui APPARIAIT ce texte reste cassé,
/// le test dit seulement que le changement est connu et ne rebougera pas en silence.
#[tokio::test]
async fn router_path_i64_ecrit_la_valeur_de_refus_sans_guillemets() {
    let (st, dbp) = router_test_state("router-path-i64");
    let addr = router_serve(st).await;
    let authz = viewer_authz();

    let (code_num, corps_num) = router_probe_corps(addr, "GET", "/api/cases/1", Some(&authz), &[]).await;
    assert_ne!(
        code_num, 400,
        "TÉMOIN POSITIF EN ÉCHEC : `/api/cases/1` (identifiant NUMÉRIQUE) ne doit pas être refusé par \
         l'extracteur. Reçu 400 — la sonde ne mesure alors pas l'analyse du segment mais autre chose. \
         Réponse : {corps_num}"
    );

    let (code, corps) = router_probe_corps(addr, "GET", "/api/cases/abc", Some(&authz), &[]).await;
    assert_eq!(
        code, 400,
        "un segment non numérique sur un gabarit servi par `Path<i64>` doit être refusé 400 par \
         l'extracteur. Reçu {code} : {corps}"
    );
    assert!(
        corps.contains("Cannot parse `abc` to a `i64`"),
        "CORPS DE REFUS INATTENDU : attendu la forme axum 0.8 (valeur SANS guillemets). Reçu : {corps}"
    );
    assert!(
        !corps.contains("Cannot parse `\"abc\"`"),
        "LA FORME D'AVANT EST REVENUE (valeur entre guillemets, axum 0.7) : le corps servi par 101 \
         routes à identifiant a rebougé sans que le code de refus change. Reçu : {corps}"
    );
    ff_rm(&dbp);
}

/// (B-6) UN SEGMENT STATIQUE GAGNE SUR SON PARAMÈTRE FRÈRE — ET LE MOTEUR QUI EN DÉCIDE VIENT D'ÊTRE
/// REMPLACÉ (matchit 0.7.3 -> 0.8.4 sous axum 0.8), SANS QU'AUCUN TEST NE TIENNE LA PROPRIÉTÉ.
///
/// La table de routes portait, pour toute justification, un commentaire qui donnait un mécanisme FAUX
/// (« axum matche l'ordre littéral »). Le vrai mécanisme est la PRIORITÉ DU SEGMENT STATIQUE dans
/// l'arbre de matchit (« Routing Priority », README de matchit 0.8.4) : l'ordre des appels `.route(…)`
/// n'y entre pas. Une propriété dont l'unique trace était une phrase fausse n'était tenue par personne.
///
/// LE CORPUS EST DÉRIVÉ, JAMAIS ÉNUMÉRÉ : tout gabarit déclaré dont le chemin concret est ENTIÈREMENT
/// littéral et qui possède, à une position, un FRÈRE paramétré de même arité, est un point où la
/// précédence se joue. Un point ajouté demain entre dans le périmètre sans qu'on l'inscrive.
///
/// TROIS TÉMOINS :
///   - BALAYAGE : aucun de ces chemins ne doit être servi par la branche PARAMÈTRE. La signature d'une
///     bascule est le refus d'analyse de `Path` (`Invalid URL: Cannot parse …`) sur un segment qui est
///     un mot ;
///   - NÉGATIF : le MÊME parent, avec un segment non déclaré, DOIT rendre ce refus — sans lui, le
///     balayage serait vacuous et vert quoi qu'il arrive ;
///   - FORME : `/api/cases/queues` rend la forme des files, et `/api/cases/1` NE la rend PAS. Sans ce
///     dernier, un vert ne distinguerait pas « le statique gagne » de « les deux rendent pareil ».
///
/// CE QUE CE TEST NE TIENT PAS : le refus RBAC est décidé sur le chemin BRUT, par une couche posée
/// AVANT l'appariement fin — une route admin-only rend donc 403 des deux côtés, et le balayage ne
/// prouve rien sur elle. Il ne prouve rien non plus là où le frère paramétré est un `Path<String>`
/// (`/api/auth/oidc/{name}`), qui accepterait le mot sans broncher : c'est exactement pour ces
/// angles-là que le témoin de FORME existe, et il ne couvre qu'UN point de la table. Enfin le balayage
/// ne retient que les GET — sur une méthode mutante un viewer est refusé 403 par une couche antérieure
/// (la sonde n'apprendrait rien), et un compte admin déclencherait de VRAIES mutations pour l'apprendre.
#[tokio::test]
async fn router_un_segment_statique_gagne_sur_son_parametre_frere() {
    let table = declared_route_table();
    let gabarits: Vec<String> = table.iter().map(|(p, _)| p.clone()).collect();
    let est_param = |s: &str| s.starts_with('{') && s.ends_with('}');

    // DÉRIVATION : chemins entièrement littéraux qui ont un frère paramétré de MÊME arité.
    let mut ambigus: Vec<String> = Vec::new();
    for (chemin, methodes) in &table {
        if !methodes.iter().any(|m| m == "GET") { continue; }
        let segs: Vec<&str> = chemin.split('/').collect();
        if segs.iter().any(|s| est_param(s)) { continue; }
        let frere = gabarits.iter().any(|autre| {
            let a: Vec<&str> = autre.split('/').collect();
            a.len() == segs.len()
                && a.iter().zip(&segs).all(|(x, y)| x == y || est_param(x))
                && a.iter().zip(&segs).any(|(x, y)| est_param(x) && x != y)
        });
        if frere { ambigus.push(chemin.clone()); }
    }
    // CLIQUET : QUATRE points mesurés le 2026-08-26 (`/api/connectors/presets`, `/api/engagements/active`,
    // `/api/cases/queues`, `/api/cases/metrics`). Ce plancher ne se BAISSE pas sans raison écrite ici —
    // une dérivation qui en trouve moins a cessé de lire la table, pas la table de porter des ambiguïtés.
    assert!(
        ambigus.len() >= 4,
        "INSTRUMENT MUET : la dérivation ne trouve plus les points où un segment statique et un \
         paramètre sont frères ({ambigus:?}). La table a changé de forme et le test ne mesure plus la \
         précédence."
    );

    let (st, dbp) = router_test_state("router-precedence");
    let addr = router_serve(st).await;
    let authz = viewer_authz();

    let mut bascules: Vec<(String, String)> = Vec::new();
    for chemin in &ambigus {
        let (_, corps) = router_probe_corps(addr, "GET", chemin, Some(&authz), &[]).await;
        if corps.contains("Invalid URL: Cannot parse") {
            bascules.push((chemin.clone(), corps.lines().last().unwrap_or("").to_string()));
        }
    }
    assert!(
        bascules.is_empty(),
        "UN SEGMENT STATIQUE A ÉTÉ SERVI PAR SON FRÈRE PARAMÉTRÉ : le routeur a préféré `{{id}}` au \
         littéral, donc la route déclarée est INATTEIGNABLE et rend un refus d'analyse. {bascules:?}"
    );

    // TÉMOIN NÉGATIF — sans lui, le balayage ci-dessus est vert même si plus rien n'atteint la branche
    // paramètre (route disparue, gate qui court-circuite, sonde muette).
    let (_, corps_param) =
        router_probe_corps(addr, "GET", "/api/cases/segment-non-declare", Some(&authz), &[]).await;
    assert!(
        corps_param.contains("Invalid URL: Cannot parse"),
        "TÉMOIN NÉGATIF EN ÉCHEC : un segment NON déclaré sous `/api/cases` doit tomber dans la branche \
         `{{id}}` et rendre le refus d'analyse de `Path<i64>`. Il ne le rend pas, donc le balayage \
         ci-dessus ne pouvait RIEN attraper. Réponse : {corps_param}"
    );

    // TÉMOIN DE FORME — le handler ATTEINT, pas seulement le code. `/api/cases/queues` et
    // `/api/cases/{id}` sont tous deux lisibles par un viewer : un vert doit distinguer les deux.
    let (code_q, corps_q) = router_probe_corps(addr, "GET", "/api/cases/queues", Some(&authz), &[]).await;
    assert!(
        code_q == 200 && corps_q.contains("\"queues\""),
        "le segment STATIQUE `/api/cases/queues` doit être servi par le handler des files (200 + clé \
         `queues`). Reçu {code_q} : {corps_q}"
    );
    let (_, corps_id) = router_probe_corps(addr, "GET", "/api/cases/1", Some(&authz), &[]).await;
    assert!(
        !corps_id.contains("\"queues\""),
        "TÉMOIN DE FORME EN ÉCHEC : `/api/cases/1` rend la MÊME forme que `/api/cases/queues`, donc le \
         témoin positif ne prouve pas que le littéral a gagné. Réponse : {corps_id}"
    );
    ff_rm(&dbp);
}
