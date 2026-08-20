    // ============================================================================================
    // JETONS (#tokens) — provisioning UI agent/HEC, pendant du CLI `plume-daemon token`.
    // ============================================================================================

    fn tok_au(role: &str) -> AuthUser {
        AuthUser { name: format!("{role}-user"), role: role.into(), tenant: "default".into(), is_superadmin: false, method: "cookie".into(), csrf: String::new(), env: None }
    }
    async fn tok_resp_json<R: axum::response::IntoResponse>(r: R) -> (StatusCode, Value) {
        let r = r.into_response();
        let code = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        let v = serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null);
        (code, v)
    }

    /// (1) create (agent host-lié + HEC non lié) -> SHA-256 STOCKÉ (jamais le clair) ; le secret renvoyé UNE
    /// fois s'authentifie par token_lookup à l'IDENTIQUE d'un token CLI, sur le seam agent (host projeté) ET
    /// sur le collector HEC. (2) list ne fuit JAMAIS le secret. (3) revoke supprime + token_lookup -> None.
    #[tokio::test]
    async fn tokens_create_lookup_list_revoke() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        // --- create AGENT host-lié ---
        let (code, v) = tok_resp_json(token_create(State(st.clone()), Extension(tok_au("admin")),
            Json(json!({ "name": "agent-a", "kind": "agent", "host": "web01.internal" }))).await).await;
        assert_eq!(code, StatusCode::OK, "create agent -> 200");
        let agent_secret = v["token"].as_str().expect("secret CLAIR renvoyé une fois").to_string();
        assert_eq!(v["kind"], "agent");
        assert_eq!(v["host"], "web01.internal");
        // le SHA-256 est stocké, JAMAIS le clair.
        {
            let c = st.db.lock();
            let stored: String = c.query_row("SELECT token_hash FROM token WHERE name='agent-a'", [], |r| r.get(0)).unwrap();
            assert_eq!(stored, sha256_hex(agent_secret.as_bytes()), "token_hash = SHA-256 du secret");
            assert_ne!(stored, agent_secret, "le clair n'est JAMAIS stocké");
        }
        // token_lookup projette l'hôte lié -> responder OK (comme un token CLI host-lié).
        assert_eq!(valid_token(&st, &agent_secret), Some("web01.internal".to_string()), "agent host-lié -> host projeté");
        // --- create HEC RELAIS (non lié) — P5.2-b : « non lié » se DÉCLARE (`relay: true`). L'omission
        // n'est plus un défaut silencieux : sans déclaration, ce même appel rend 400 (assertion ci-dessous).
        let (code, _) = tok_resp_json(token_create(State(st.clone()), Extension(tok_au("admin")),
            Json(json!({ "name": "hec-sans-portee", "kind": "hec" }))).await).await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "kind hec SANS portée déclarée -> 400 (P5.2-b)");
        {
            let c = st.db.lock();
            let n: i64 = c.query_row("SELECT COUNT(*) FROM token WHERE name='hec-sans-portee'", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "un refus de portée n'écrit AUCUNE ligne token");
        }
        let (code, v) = tok_resp_json(token_create(State(st.clone()), Extension(tok_au("admin")),
            Json(json!({ "name": "hec-splunk", "kind": "hec", "relay": true }))).await).await;
        assert_eq!(code, StatusCode::OK, "create hec relais -> 200");
        let hec_secret = v["token"].as_str().unwrap().to_string();
        assert_eq!(v["kind"], "hec");
        assert!(v["host"].is_null(), "HEC non lié -> host null");
        // le token HEC s'authentifie via la MÊME infra token_lookup (host vide = non lié, ingest/HEC only).
        assert_eq!(valid_token(&st, &hec_secret), Some(String::new()), "HEC non lié -> host vide (ingest only)");
        // --- list : name/kind/host/last_used, JAMAIS le secret ni le hash ---
        let (code, v) = tok_resp_json(tokens_list(State(st.clone()), Extension(tok_au("admin"))).await).await;
        assert_eq!(code, StatusCode::OK);
        let list = v["tokens"].as_array().unwrap();
        assert_eq!(list.len(), 2, "deux jetons listés");
        let dump = v.to_string();
        assert!(!dump.contains(&agent_secret) && !dump.contains(&hec_secret), "la liste ne fuit JAMAIS le secret clair");
        assert!(!dump.contains("token_hash") && !dump.contains(&sha256_hex(agent_secret.as_bytes())), "la liste ne fuit JAMAIS le hash");
        assert!(list.iter().any(|t| t["name"] == "agent-a" && t["kind"] == "agent" && t["host"] == "web01.internal"));
        assert!(list.iter().any(|t| t["name"] == "hec-splunk" && t["kind"] == "hec" && t["host"].is_null()));
        // --- revoke : supprime + token_lookup -> None ---
        let r = token_delete(State(st.clone()), Extension(tok_au("admin")), Path("agent-a".into())).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT, "revoke -> 204");
        assert_eq!(valid_token(&st, &agent_secret), None, "jeton révoqué -> plus authentifiable");
        let (_c, v) = tok_resp_json(tokens_list(State(st.clone()), Extension(tok_au("admin"))).await).await;
        assert_eq!(v["tokens"].as_array().unwrap().len(), 1, "un seul jeton après révocation");
        // revoke d'un nom inconnu -> 404.
        assert_eq!(token_delete(State(st.clone()), Extension(tok_au("admin")), Path("nope".into())).await.status(), StatusCode::NOT_FOUND);
    }

    /// Garde-fous : handler re-check admin (editor/viewer -> 403 sur list/create/revoke) + validation d'entrée.
    #[tokio::test]
    async fn tokens_admin_only_and_validation() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        // re-check admin DANS le handler (au-delà de route_min_role) : editor & viewer -> 403 partout.
        for role in ["editor", "viewer"] {
            assert_eq!(tokens_list(State(st.clone()), Extension(tok_au(role))).await.into_response().status(), StatusCode::FORBIDDEN, "{role} -> 403 list");
            let r = token_create(State(st.clone()), Extension(tok_au(role)), Json(json!({ "name": "x", "kind": "agent" }))).await;
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "{role} -> 403 create");
            assert_eq!(token_delete(State(st.clone()), Extension(tok_au(role)), Path("x".into())).await.status(), StatusCode::FORBIDDEN, "{role} -> 403 revoke");
        }
        // le create refusé par un editor ne DOIT rien avoir persisté.
        { let c = st.db.lock(); let n: i64 = c.query_row("SELECT COUNT(*) FROM token", [], |r| r.get(0)).unwrap(); assert_eq!(n, 0, "aucun jeton créé par un non-admin"); }
        // validation : nom vide/invalide + hôte invalide -> 400.
        assert_eq!(token_create(State(st.clone()), Extension(tok_au("admin")), Json(json!({ "name": "", "kind": "agent" }))).await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(token_create(State(st.clone()), Extension(tok_au("admin")), Json(json!({ "name": "bad name!", "kind": "agent" }))).await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(token_create(State(st.clone()), Extension(tok_au("admin")), Json(json!({ "name": "ok", "kind": "agent", "host": "bad host!" }))).await.status(), StatusCode::BAD_REQUEST);
        // P5.2-b — PORTÉE NON DÉCLARÉE : ni hôte, ni `relay` -> 400. La garde du CLI serait contournable par
        // le SPA sans celle-ci (les deux écrivent la MÊME table `token`). Et une déclaration CONTRADICTOIRE
        // (hôte ET relais) est refusée elle aussi, plutôt qu'arbitrée en silence.
        assert_eq!(token_create(State(st.clone()), Extension(tok_au("admin")), Json(json!({ "name": "ok", "kind": "agent" }))).await.status(), StatusCode::BAD_REQUEST, "ni hôte ni relais -> 400");
        assert_eq!(token_create(State(st.clone()), Extension(tok_au("admin")), Json(json!({ "name": "ok", "kind": "agent", "host": "web01", "relay": true }))).await.status(), StatusCode::BAD_REQUEST, "hôte ET relais -> 400");
        { let c = st.db.lock(); let n: i64 = c.query_row("SELECT COUNT(*) FROM token", [], |r| r.get(0)).unwrap(); assert_eq!(n, 0, "aucun refus n'a écrit de jeton"); }
    }

    /// MODE 0 INCHANGÉ : un token créé via l'UI est byte-identique à un token CLI (même colonnes, kind=NULL du
    /// CLI présenté comme 'agent') -> la coexistence CLI/UI est transparente pour token_lookup.
    #[tokio::test]
    async fn tokens_cli_ui_coexist_mode0() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        // simulate un token créé par le CLI (kind NULL, host lié) — insertion IDENTIQUE au CLI.
        {
            let c = st.db.lock();
            c.execute("INSERT INTO token(name,token_hash,created,host) VALUES('cli-agent',?1,?2,'db01')",
                      params![sha256_hex(b"cli-secret"), now()]).unwrap();
        }
        // le CLI-token (kind NULL) est listé comme 'agent' (défaut historique du CLI).
        let (_c, v) = tok_resp_json(tokens_list(State(st.clone()), Extension(tok_au("admin"))).await).await;
        let list = v["tokens"].as_array().unwrap();
        assert!(list.iter().any(|t| t["name"] == "cli-agent" && t["kind"] == "agent" && t["host"] == "db01"), "token CLI (kind NULL) présenté comme agent");
        assert_eq!(valid_token(&st, "cli-secret"), Some("db01".to_string()), "token CLI toujours authentifiable");
    }

    // ============================================================================================
    // HEC (#16) — endpoint wire-compatible Splunk HTTP Event Collector (bring-your-own-forwarder).
    // ============================================================================================

    /// HEC parse : objet unique, objets CONCATÉNÉS `{...}{...}`, ND-JSON, array JSON -> même liste.
    #[test]
    fn hec_parse_single_concat_ndjson_array() {
        assert_eq!(hec_parse_body(r#"{"event":"a"}"#).len(), 1);
        let c = hec_parse_body(r#"{"event":"a"}{"event":"b"}{"event":"c"}"#);
        assert_eq!(c.len(), 3, "objets HEC concaténés (sans séparateur)");
        let nd = hec_parse_body("{\"event\":\"a\"}\n{\"event\":\"b\"}");
        assert_eq!(nd.len(), 2, "ND-JSON");
        assert_eq!(hec_parse_body(r#"[{"event":"a"},{"event":"b"}]"#).len(), 2, "array JSON aplati");
        assert!(hec_parse_body("   ").is_empty(), "vide -> vide");
    }

    /// HEC event STRING -> message ; event OBJET -> message=JSON + champs fusionnés dans fields ; ts robuste.
    #[test]
    fn hec_record_string_vs_object_event() {
        let ov = HashMap::new();
        let rec = json!({"event":"hello world","source":"app","host":"h1","sourcetype":"syslog","time":1700000000});
        let ev = hec_record_to_event(&rec, &ov).unwrap();
        assert_eq!(ev.get("message").unwrap(), "hello world");
        assert_eq!(ev.get("source").unwrap(), "app");
        assert_eq!(ev.get("host").unwrap(), "h1");
        assert_eq!(ev.get("ts").unwrap(), 1700000000i64);
        assert_eq!(ev.get("category").unwrap(), "syslog", "sourcetype syslog -> CIM syslog");
        // event OBJET -> champs fusionnés dans fields, message = JSON
        let rec2 = json!({"event":{"user":"bob","action":"failure"},"fields":{"src_ip":"1.2.3.4"}});
        let ev2 = hec_record_to_event(&rec2, &ov).unwrap();
        let f = ev2.get("fields").unwrap();
        assert_eq!(f.get("user").unwrap(), "bob", "champ de l'event objet fusionné dans fields");
        assert_eq!(f.get("action").unwrap(), "failure");
        assert_eq!(f.get("src_ip").unwrap(), "1.2.3.4", "fields HEC préservés");
        assert!(ev2.get("message").unwrap().as_str().unwrap().contains("bob"), "message = JSON de l'event objet");
        // sans event ni fields -> None (rien à ingérer)
        assert!(hec_record_to_event(&json!({"source":"x"}), &ov).is_none());
        // ts : millisecondes (robustesse) -> secondes ; string numérique -> secondes.
        assert_eq!(hec_record_to_event(&json!({"event":"x","time":1700000000000i64}), &ov).unwrap().get("ts").unwrap(), 1700000000i64);
        assert_eq!(hec_record_to_event(&json!({"event":"x","time":"1700000001"}), &ov).unwrap().get("ts").unwrap(), 1700000001i64);
    }

    /// HEC sourcetype -> CIM : built-in valides, override (map directe) prioritaire, hors-CIM rejeté, vide=None.
    #[test]
    fn hec_sourcetype_cim_mapping() {
        let ov = HashMap::new();
        assert_eq!(hec_category("access_combined", &ov).as_deref(), Some("web"));
        assert_eq!(hec_category("linux_secure", &ov).as_deref(), Some("auth"));
        assert_eq!(hec_category("WinEventLog:Security", &ov).as_deref(), Some("auth"), "casse insensible");
        assert_eq!(hec_category("suricata", &ov).as_deref(), Some("ids"));
        assert_eq!(hec_category("cisco:asa", &ov).as_deref(), Some("firewall"));
        assert_eq!(hec_category("some_random_sourcetype", &ov), None, "inconnu -> None (category vide, jamais un drop)");
        assert_eq!(hec_category("", &ov), None);
        // override (map directe) prime sur le built-in ET n'accepte QUE des categories CIM valides.
        let mut ov2 = HashMap::new();
        ov2.insert("myapp".to_string(), "web".to_string());
        ov2.insert("access_combined".to_string(), "network".to_string());
        ov2.insert("badcat".to_string(), "not_a_cim_category".to_string());
        assert_eq!(hec_category("myapp", &ov2).as_deref(), Some("web"));
        assert_eq!(hec_category("access_combined", &ov2).as_deref(), Some("network"), "override écrase le built-in");
        assert_eq!(hec_category("badcat", &ov2), None, "override hors-CIM rejeté (jamais de category hors-contrat)");
        for stype in ["access_combined","linux_secure","wineventlog:security","suricata","cisco:asa","dns","syslog"] {
            if let Some(cc) = hec_category(stype, &ov) { assert!(cim_category_ok(&cc), "category built-in {cc} DOIT être CIM"); }
        }
    }

    /// HEC token extraction : `Authorization: Splunk <tok>` (casse tolérée) + `?token=` ; rejets ; routes fermées.
    #[test]
    fn hec_token_extraction_and_routes() {
        assert_eq!(hec_token("Splunk abc123", None).as_deref(), Some("abc123"));
        assert_eq!(hec_token("splunk abc123", None).as_deref(), Some("abc123"), "schéma insensible à la casse");
        assert_eq!(hec_token("", Some("token=qtok&x=1")).as_deref(), Some("qtok"));
        assert_eq!(hec_token("", Some("x=1&token=qtok")).as_deref(), Some("qtok"));
        assert_eq!(hec_token("Splunk hdr", Some("token=qs")).as_deref(), Some("hdr"), "header prime sur query");
        assert_eq!(hec_token("Bearer x", None), None, "Bearer n'est PAS un token HEC (schémas disjoints)");
        assert_eq!(hec_token("Splunk ", None), None);
        assert_eq!(hec_token("", None), None);
        assert!(hec_collector_path("/services/collector"));
        assert!(hec_collector_path("/services/collector/event"));
        assert!(!hec_collector_path("/services/collector/health"), "/health public -> hors allowlist token");
        assert!(!hec_collector_path("/api/ingest"));
    }

    /// HEC token auth : réutilise token_lookup (infra existante) -> accept valide, reject inconnu ; ingest-only.
    #[test]
    fn hec_token_reuses_token_infra_ingest_only() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        {
            let c = st.db.lock();
            c.execute("INSERT INTO token(name,token_hash,created,host) VALUES('hec-fwd',?1,?2,'fwd-1')",
                      params![sha256_hex(b"hec-secret"), now()]).unwrap();
        }
        let tok = hec_token("Splunk hec-secret", None).unwrap();
        let ti = token_lookup(&st, &tok).expect("token HEC valide résolu par l'infra existante");
        assert_eq!(ti.host, "fwd-1");
        assert!(token_lookup(&st, "nope").is_none(), "token inconnu -> None (auth_guard renverra 401 HEC code 4)");
        // RBAC : collector = INGEST (agent OK, viewer NON) -> ingest-only, jamais UI/admin.
        assert!(matches!(route_min_role("/services/collector", true), MinRole::Ingest));
        assert!(matches!(route_min_role("/services/collector/event", true), MinRole::Ingest));
        assert!(role_satisfies("agent", MinRole::Ingest), "token HEC (rôle agent) satisfait Ingest");
        assert!(!role_satisfies("viewer", MinRole::Ingest), "viewer JAMAIS ingest");
    }

    /// HEC -> event mappé -> ingest_events_batch : la ligne stockée porte category/host/source/fields attendus
    /// (le mapping HEC produit le schéma d'ingest EXISTANT ; src_ip promu par le chemin existant).
    #[test]
    fn hec_mapped_event_matches_ingest_schema() {
        let conn = test_db();
        let ov = HashMap::new();
        let rec = json!({
            "event": {"msg":"login failed","action":"failure"},
            "sourcetype": "linux_secure", "source": "sshd", "host": "web-7",
            "time": 1700000123, "index": "main", "fields": {"src_ip":"9.9.9.9"}
        });
        let ev = hec_record_to_event(&rec, &ov).unwrap();
        let n = ingest_events_batch(&conn, ":memory:", std::slice::from_ref(&ev), now(), None, None).unwrap();
        assert_eq!(n, 1);
        let (cat, host, source, sev): (String, String, String, i64) = conn.query_row(
            "SELECT category, host, source, severity FROM event ORDER BY id DESC LIMIT 1", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap();
        assert_eq!(cat, "auth", "linux_secure -> CIM auth");
        assert_eq!(host, "web-7", "host HEC porté en colonne");
        assert_eq!(source, "sshd");
        assert_eq!(sev, 0, "severity par défaut (HEC ne la fournit pas)");
        let src_ip: Option<String> = conn.query_row(
            "SELECT src_ip FROM event ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).unwrap();
        assert_eq!(src_ip.as_deref(), Some("9.9.9.9"), "src_ip des fields HEC promu en colonne (ingest existant)");
        let fields: String = conn.query_row(
            "SELECT fields FROM event ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).unwrap();
        let fj: Value = serde_json::from_str(&fields).unwrap();
        assert_eq!(fj.get("action").unwrap(), "failure", "champ de l'event objet dans fields");
        assert_eq!(fj.get("sourcetype").unwrap(), "linux_secure", "provenance sourcetype tracée");
        assert_eq!(fj.get("index").unwrap(), "main", "provenance index tracée");
    }

    #[test]
    fn mode1_identity_resolves_from_control_plane() {
        // (c) : mode 1 (control-plane temp) -> token->tenant + platform_user auth lus du CONTROL-PLANE,
        // PAS de la base tenant. Prouve R6/R7 : l'identité vit hors de portée du SQL brut d'un tenant-admin.
        let (cp, _cptmp) = mk_test_control();
        // seed control-plane : 1 tenant, 1 platform_user (auth), 1 token agent.
        let hash = hash_pw("cp-pass").unwrap();
        {
            let c = cp.conn.lock();
            c.execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('acme','Acme','',?1,?2,0)",
                      params!["/data/tenants/acme/plume.db", now()]).unwrap();
            c.execute("INSERT INTO platform_user(id,name,hash,is_superadmin,created) VALUES('u1','bob',?1,0,?2)",
                      params![hash, now()]).unwrap();
            c.execute("INSERT INTO token(hash,tenant_id,env_id,host,created) VALUES(?1,'acme','prod','host-z',?2)",
                      params![sha256_hex(b"cp-token"), now()]).unwrap();
        }
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
        assert!(st.multi_tenant, "mode 1");
        // token résolu depuis le control-plane -> (tenant=acme, env=prod, host=host-z).
        let ti = token_lookup(&st, "cp-token").expect("token du control-plane résolu");
        assert_eq!((ti.tenant.as_str(), ti.env.as_str(), ti.host.as_str()), ("acme", "prod", "host-z"));
        assert_eq!(valid_token(&st, "cp-token"), Some("host-z".to_string()), "valid_token projette le host");
        // un token présent SEULEMENT dans la base tenant (st.db) ne résout PAS en mode 1 (fail-closed).
        {
            let c = st.db.lock();
            c.execute("INSERT INTO token(name,token_hash,created,host) VALUES('leg',?1,?2,'legacy')",
                      params![sha256_hex(b"tenant-only"), now()]).unwrap();
        }
        assert_eq!(valid_token(&st, "tenant-only"), None, "mode 1 : la table token de la base tenant n'est PAS lue");
        // auth Basic résolue depuis platform_user (control-plane), pas depuis user (base tenant).
        use base64::Engine as _;
        let authz = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("bob:cp-pass"));
        assert_eq!(authenticate(&st, &authz), Some(("bob".to_string(), "viewer".to_string())),
                   "platform_user non-superadmin -> rôle plancher viewer (rôle per-tenant = #2a-2b)");
        // resolve depuis le catalogue control-plane (tenant acme).
        let (p, _k) = st.tenants.resolve("acme").unwrap();
        assert_eq!(p, "/data/tenants/acme/plume.db");
        assert_eq!(st.tenants.resolve("ghost"), None, "tenant inconnu -> None (fail-closed)");
    }

    #[test]
    fn mode1_suspended_tenant_and_key_ref_resolution() {
        // tenant suspendu -> resolve None (fail-closed) ; key_ref literal/env résolus.
        let (cp, _cptmp) = mk_test_control();
        {
            let c = cp.conn.lock();
            c.execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('susp','S','literal:sekret','/d/s.db',?1,1)",
                      params![now()]).unwrap();
            c.execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('live','L','literal:sekret','/d/l.db',?1,0)",
                      params![now()]).unwrap();
        }
        let st = tenant_test_state("a", "e", "s", Some(cp));
        assert_eq!(st.tenants.resolve("susp"), None, "tenant suspendu -> pas de handle");
        let (p, k) = st.tenants.resolve("live").unwrap();
        assert_eq!(p, "/d/l.db");
        assert_eq!(k.as_deref(), Some("sekret"), "key_ref literal: résolue");
        // #2a-3 : resolve_tenant_key -> Result. "" = clair (Ok(None)) ; literal: = clé ; préfixe inconnu = Err.
        assert_eq!(resolve_tenant_key(""), Ok(None), "'' -> base en clair");
        assert_eq!(resolve_tenant_key("literal:abc").unwrap().as_deref(), Some("abc"), "literal: -> clé directe");
        assert!(resolve_tenant_key("literal:").is_err(), "literal: vide -> Err");
        assert!(resolve_tenant_key("garbage").is_err(), "préfixe inconnu -> Err (fail-closed)");
    }

    /// LE CRITÈRE #2a-2b : en mode 1, une requête « as tenant B » ne voit JAMAIS la donnée de A sur AUCUN
    /// chemin requête. Deux tenants (A/B) = deux fichiers SQLCipher temp distincts (en clair pour le test) +
    /// un control-plane temp. Couvre EXPLICITEMENT : overview(count), search/query, freshness, un panel_id
    /// PARTAGÉ (même id=1), et un qid PARTAGÉ (cancel). Prouve aussi req_db/req_db_path distincts + fail-closed.
    #[tokio::test]
    async fn mode1_request_path_isolation_no_cross_tenant_leak() {
        use std::sync::atomic::{AtomicBool, Ordering};
        // control-plane temp + 2 tenants sur 2 fichiers temp DISTINCTS (key_ref='' -> en clair pour le test).
        let (cp, _cptmp) = mk_test_control();
        let pa = mk_tmp_path("tenant-a.db");
        let pb = mk_tmp_path("tenant-b.db");
        {
            let c = cp.conn.lock();
            c.execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('a','A','',?1,?2,0)", params![pa.as_str(), now()]).unwrap();
            c.execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('b','B','',?1,?2,0)", params![pb.as_str(), now()]).unwrap();
            // un user 'analyst' granté sur les 2 tenants (rôles différents PAR tenant).
            c.execute("INSERT INTO platform_user(id,name,hash,is_superadmin,created) VALUES('u','analyst',NULL,0,?1)", params![now()]).unwrap();
            c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES('u','a','admin')", []).unwrap();
            c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES('u','b','viewer')", []).unwrap();
        }
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
        assert!(st.multi_tenant, "mode 1");
        // migre le schéma des 2 bases tenant (fichiers neufs) via le writer mémoïsé du manager.
        for t in ["a", "b"] {
            let h = st.tenants.handle_for(t).unwrap();
            let c = h.lock();
            c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&c);
        }
        // AuthUser par tenant : c'est au.tenant qui pilote le routing req_db/req_db_path.
        let au_a = AuthUser { name: "analyst".into(), role: "admin".into(), tenant: "a".into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None };
        let au_b = AuthUser { name: "analyst".into(), role: "viewer".into(), tenant: "b".into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None };

        // (0) FAIL-CLOSED + accesseurs distincts.
        assert_ne!(req_db_path(&st, &au_a), req_db_path(&st, &au_b), "req_db_path distinct par tenant");
        assert!(!Arc::ptr_eq(&req_db(&st, &au_a), &req_db(&st, &au_b)), "req_db = writer distinct par tenant");
        assert_ne!(req_db_path(&st, &au_a), *st.db_path, "mode 1 : jamais la base par défaut/opérateur");
        assert_eq!(resolve_user_tenant(&st, "analyst", None).map(|(t, _)| t), Some("a".to_string()), "défaut = 1er grant");
        assert!(resolve_user_tenant(&st, "analyst", Some("ghost")).is_none(), "tenant non granté -> None (403 côté guard)");
        assert!(resolve_user_tenant(&st, "nobody", None).is_none(), "user inconnu -> None (fail-closed)");

        // seed données DISTINCTES : A = 3 events 'sshd' + 1 alerte 'new' ; B = 1 event 'web', 0 alerte.
        {
            let h = req_db(&st, &au_a);
            let c = h.lock();
            for i in 0..3 { c.execute("INSERT INTO event(ts,source,message) VALUES(?1,'sshd',?2)", params![now(), format!("A-secret-{i}")]).unwrap(); }
            c.execute("INSERT INTO alert(ts,rule,severity,title,status) VALUES(?1,'ra',3,'ALERT-A','new')", params![now()]).unwrap();
            c.execute("INSERT INTO event_rollup(bucket,source,severity,action,n,last_ts) VALUES(?1,'sshd',0,'',5,?1)", params![now()]).unwrap();
        }
        {
            let h = req_db(&st, &au_b);
            let c = h.lock();
            c.execute("INSERT INTO event(ts,source,message) VALUES(?1,'web','B-secret')", params![now()]).unwrap();
            c.execute("INSERT INTO event_rollup(bucket,source,severity,action,n,last_ts) VALUES(?1,'web',0,'',5,?1)", params![now()]).unwrap();
        }

        // (1) OVERVIEW (count) — handler RÉEL « as A » puis « as B ». Le cache EVENTS_COUNT (R2) ne fuit pas.
        let va = overview(State(st.clone()), Extension(au_a.clone())).await.0;
        let vb = overview(State(st.clone()), Extension(au_b.clone())).await.0;
        assert_eq!(va["events"].as_i64(), Some(3), "overview A = 3 events");
        assert_eq!(vb["events"].as_i64(), Some(1), "overview B = 1 event (JAMAIS le count de A)");
        assert_eq!(va["open_alerts"].as_i64(), Some(1), "A a 1 alerte 'new'");
        assert_eq!(vb["open_alerts"].as_i64(), Some(0), "B n'a AUCUNE alerte (celle de A ne fuit pas)");

        // (2) SEARCH / QUERY — pool read-only keyé par db_path (R1). « as B » ne lit jamais la base de A.
        let ca = run_query(&req_db_path(&st, &au_a), "SELECT COUNT(*) FROM event").unwrap();
        let cb = run_query(&req_db_path(&st, &au_b), "SELECT COUNT(*) FROM event").unwrap();
        assert_eq!(ca["rows"][0][0].as_i64(), Some(3), "query A = 3");
        assert_eq!(cb["rows"][0][0].as_i64(), Some(1), "query B = 1");
        let leak = run_query(&req_db_path(&st, &au_b), "SELECT COUNT(*) FROM event WHERE message LIKE 'A-secret%'").unwrap();
        assert_eq!(leak["rows"][0][0].as_i64(), Some(0), "aucun secret de A visible depuis B");

        // (2b) SEARCH via le HANDLER RÉEL (chemin ad-hoc = le vecteur de fuite classique) : « as B » ne
        // voit JAMAIS les events de A. Champ structuré `source:` -> aucune dépendance FTS. ÉCHOUERAIT si
        // `search` oubliait req_db_path (les deux liraient la base opérateur vide -> A ne trouverait pas
        // ses 3 events sshd, et B pourrait voir ceux de A). C'est le test qui casse si le routing saute.
        let mk_q = |s: &str| -> HashMap<String, String> { let mut m = HashMap::new(); m.insert("q".to_string(), s.to_string()); m };
        let sa = search(State(st.clone()), Extension(au_a.clone()), Query(mk_q("source:sshd"))).await.0;
        let sb = search(State(st.clone()), Extension(au_b.clone()), Query(mk_q("source:sshd"))).await.0;
        assert_eq!(sa["results"].as_array().map(|a| a.len()), Some(3), "search(source:sshd) « as A » = ses 3 events");
        assert_eq!(sb["results"].as_array().map(|a| a.len()), Some(0), "search(source:sshd) « as B » = 0 (les events sshd de A ne fuitent JAMAIS via le handler)");
        let sb_web = search(State(st.clone()), Extension(au_b.clone()), Query(mk_q("source:web"))).await.0;
        assert_eq!(sb_web["results"].as_array().map(|a| a.len()), Some(1), "search(source:web) « as B » = son propre event (routing handler correct)");

        // (3) FRESHNESS — compute_freshness par tenant (FRESHNESS_CACHE keyé db_path, R3). Feeds disjoints.
        let fa = compute_freshness(&req_db_path(&st, &au_a), None);
        let fb = compute_freshness(&req_db_path(&st, &au_b), None);
        let names = |v: &Value| -> Vec<String> {
            v["feeds"].as_array().map(|a| a.iter().filter_map(|f| f["name"].as_str().map(String::from)).collect()).unwrap_or_default()
        };
        let (na, nb) = (names(&fa), names(&fb));
        assert!(na.iter().any(|s| s == "sshd") && !na.iter().any(|s| s == "web"), "A ne voit que ses feeds : {na:?}");
        assert!(nb.iter().any(|s| s == "web") && !nb.iter().any(|s| s == "sshd"), "B ne voit que ses feeds (jamais 'sshd' de A) : {nb:?}");

        // (4) PANEL_ID PARTAGÉ — même id (900001, hors seeds) dans A et B, contenus différents. « as B »
        // -> panneau de B (le fichier EST le tenant : un même panel_id vit dans 2 bases isolées).
        req_db(&st, &au_a).lock().execute("INSERT INTO panel(id,dashboard_id,title) VALUES(900001,1,'PANEL-A')", []).unwrap();
        req_db(&st, &au_b).lock().execute("INSERT INTO panel(id,dashboard_id,title) VALUES(900001,1,'PANEL-B')", []).unwrap();
        let ta: String = { let h = req_db(&st, &au_a); let c = h.lock(); c.query_row("SELECT title FROM panel WHERE id=900001", [], |r| r.get(0)).unwrap() };
        let tb: String = { let h = req_db(&st, &au_b); let c = h.lock(); c.query_row("SELECT title FROM panel WHERE id=900001", [], |r| r.get(0)).unwrap() };
        assert_eq!(ta, "PANEL-A");
        assert_eq!(tb, "PANEL-B", "panel_id partagé « as B » = panneau de B, jamais celui de A");

        // (5) QID PARTAGÉ — QUERY_CANCEL keyé (db_path, qid) : un cancel « as B » n'annule JAMAIS A (R5).
        let pa_path = req_db_path(&st, &au_a);
        let conn_a = read_conn_get(&pa_path).unwrap();
        let flag_a = Arc::new(AtomicBool::new(false));
        let _cg = cancel_register(&pa_path, "shared-qid", conn_a.get_interrupt_handle(), flag_a.clone());
        // réplique EXACTE de la clé du handler `cancel` : (req_db_path(&st,&au), qid).
        let cancel_as = |path: &str| -> u32 {
            let mut n = 0u32;
            if let Some(reg) = QUERY_CANCEL.get() {
                { let map = reg.lock();
                    if let Some(vec) = map.get(&(path.to_string(), "shared-qid".to_string())) {
                        for e in vec { e.cancelled.store(true, Ordering::Relaxed); e.interrupt.interrupt(); n += 1; }
                    }
                }
            }
            n
        };
        assert_eq!(cancel_as(&req_db_path(&st, &au_b)), 0, "cancel « as B » n'annule AUCUNE requête de A (qid namespacé par tenant)");
        assert!(!flag_a.load(Ordering::Relaxed), "la requête de A n'est pas annulée par un cancel de B");
        assert_eq!(cancel_as(&req_db_path(&st, &au_a)), 1, "cancel « as A » annule bien la requête de A");
        assert!(flag_a.load(Ordering::Relaxed));
        drop(_cg);
        let _ = std::fs::remove_file(&pa);
        let _ = std::fs::remove_file(&pb);
    }

    /// LE CRITÈRE CRYPTO #2a-3 : chaque base tenant s'ouvre avec SA clé. Deux tenants A/B, clés DISTINCTES
    /// (générées). Prouve la FRONTIÈRE crypto : le fichier de A est illisible avec la clé de B (ou en clair
    /// = « clé globale » db_key()=None en test), lisible AVEC la clé de A ; et le read-pool (read_conn_open)
    /// ouvre bien chaque fichier avec la clé DU tenant (via le registre alimenté par resolve).
    #[test]
    fn mode1_per_tenant_distinct_key_crypto_frontier() {
        // Deux clés fortes DISTINCTES (exerce aussi tenant_generate_key).
        let key_a = tenant_generate_key().expect("l'hôte de test fournit de l'entropie");
        let key_b = tenant_generate_key().expect("l'hôte de test fournit de l'entropie");
        assert_ne!(key_a, key_b, "deux clés générées sont distinctes");
        assert_eq!(key_a.len(), 64, "clé = 256 bits en hex (64 chars)");

        let (cp, _cptmp) = mk_test_control();
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
        let pa = mk_tmp_path("keyed-a.db");
        let pb = mk_tmp_path("keyed-b.db");
        // ONBOARDING : crée l'entrée control-plane + la base CHIFFRÉE avec SA clé + seed minimal.
        tenant_provision(&st.tenants, "a", "A", &pa, &format!("literal:{key_a}")).expect("provision A");
        tenant_provision(&st.tenants, "b", "B", &pb, &format!("literal:{key_b}")).expect("provision B");

        // (1) FRONTIÈRE CRYPTO AU NIVEAU FICHIER : ouvrable AVEC sa clé, refusé avec l'autre / en clair.
        let readable = |path: &str, key: Option<&str>| -> bool {
            match open_db_keyed(path, key) {
                Ok(c) => c.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).is_ok(),
                Err(_) => false,
            }
        };
        assert!(readable(&pa, Some(&key_a)), "A ouvrable avec SA clé");
        assert!(!readable(&pa, Some(&key_b)), "A OUVERT AVEC LA CLÉ DE B -> ÉCHOUE (frontière crypto)");
        assert!(!readable(&pa, None), "A ouvert EN CLAIR (clé globale db_key()=None) -> ÉCHOUE (base chiffrée)");
        assert!(readable(&pb, Some(&key_b)) && !readable(&pb, Some(&key_a)), "B : sa clé OK, clé de A refusée");

        // (2) FRONTIÈRE AU NIVEAU READ-POOL : resolve enregistre (db_path -> clé du tenant) ; read_conn_open
        // ouvre CHAQUE fichier avec SA clé. On écrit une donnée distincte par tenant via le writer keyé, puis
        // on la relit via run_query (= read pool). Un secret de A n'est JAMAIS lisible depuis la base de B.
        {
            let h = st.tenants.handle_for("a").unwrap();
            h.lock().execute("INSERT INTO event(ts,source,message) VALUES(?1,'sshd','A-KEYED-SECRET')", params![now()]).unwrap();
        }
        {
            let h = st.tenants.handle_for("b").unwrap();
            h.lock().execute("INSERT INTO event(ts,source,message) VALUES(?1,'web','B-KEYED')", params![now()]).unwrap();
        }
        let (pa_r, _ka) = st.tenants.resolve("a").unwrap();
        let (pb_r, _kb) = st.tenants.resolve("b").unwrap();
        let ca = run_query(&pa_r, "SELECT COUNT(*) FROM event WHERE message='A-KEYED-SECRET'").unwrap();
        assert_eq!(ca["rows"][0][0].as_i64(), Some(1), "read pool ouvre A avec la clé de A -> voit son event");
        let cb = run_query(&pb_r, "SELECT COUNT(*) FROM event WHERE message='B-KEYED'").unwrap();
        assert_eq!(cb["rows"][0][0].as_i64(), Some(1), "read pool ouvre B avec la clé de B -> voit son event");
        let leak = run_query(&pb_r, "SELECT COUNT(*) FROM event WHERE message='A-KEYED-SECRET'").unwrap();
        assert_eq!(leak["rows"][0][0].as_i64(), Some(0), "le secret de A n'est JAMAIS visible depuis la base de B");

        // (3) DESTRUCTION CRYPTO (RGPD) : oublie la clé (entrée catalogue + registre) + supprime le fichier.
        assert!(std::path::Path::new(&pa).exists());
        tenant_destroy(&st.tenants, "a").expect("destroy A");
        assert!(!std::path::Path::new(&pa).exists(), "fichier de A supprimé (destruction crypto)");
        assert_eq!(st.tenants.resolve("a"), None, "entrée catalogue de A oubliée -> plus de handle");
        assert!(!db_key_registry().lock().contains_key(pa.as_str()), "clé de A oubliée du registre read-pool");
        assert!(tenant_destroy(&st.tenants, "default").is_err(), "le tenant 'default' ne peut PAS être détruit");

        let _ = std::fs::remove_file(&pb);
    }

    /// FAIL-CLOSED : un tenant dont la clé ne résout PAS (vault: non configuré, préfixe inconnu) ne s'ouvre
    /// JAMAIS — ni en lecture, ni en écriture, ni en ingest — et JAMAIS avec une clé par défaut.
    #[test]
    fn mode1_unresolvable_key_fails_closed() {
        // Déterminisme : pas de Vault configuré -> résolution vault: échoue AVANT tout accès réseau.
        std::env::remove_var("PLUME_VAULT_ADDR");
        std::env::remove_var("PLUME_VAULT_TOKEN");
        let (cp, _cptmp) = mk_test_control();
        {
            let c = cp.conn.lock();
            c.execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('vlt','V','vault:secret/data/ghost','/d/v.db',?1,0)", params![now()]).unwrap();
            c.execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('bad','X','garbage','/d/x.db',?1,0)", params![now()]).unwrap();
        }
        let st = tenant_test_state("a", "e", "s", Some(cp));
        // vault: sans configuration -> Err (jamais None-clair, jamais db_key()).
        assert!(resolve_tenant_key("vault:secret/data/ghost").is_err(), "vault: non configuré -> Err (fail-closed)");
        assert_eq!(st.tenants.resolve("vlt"), None, "clé Vault non résoluble -> pas de handle (fail-closed)");
        assert!(st.tenants.handle_for("vlt").is_none(), "writer refusé si clé non résoluble");
        assert!(resolve_ingest_target(&st.tenants, "vlt").is_none(), "ingest refusé (quarantaine) si clé non résoluble");
        // préfixe inconnu -> Err -> pas de handle non plus.
        assert_eq!(st.tenants.resolve("bad"), None, "key_ref inconnu -> pas de handle (fail-closed)");
        // aucune clé enregistrée pour un tenant fail-closed : sa base ne sera jamais ouverte avec une clé par défaut.
        assert!(!db_key_registry().lock().contains_key("/d/v.db"), "aucun enregistrement de clé pour un tenant fail-closed");
        // provisioning avec une clé non résoluble -> refus, rien créé.
        assert!(tenant_provision(&st.tenants, "z", "Z", "/d/z.db", "vault:secret/data/none").is_err(), "provision refusée si clé non résoluble");
        assert!(!std::path::Path::new("/d/z.db").exists(), "aucun fichier créé pour un provision fail-closed");
    }

    /// LE CONTRAT DE SCHÉMA S'APPLIQUE AUSSI AUX BASES TENANT — mesuré, pas déduit d'une relecture.
    ///
    /// Ce que la revue a mesuré sur le code précédent : une base tenant n'était migrée qu'AU
    /// PROVISIONNEMENT. Le writer, lui, était ouvert au fil de l'eau sans `prepare_schema`, sans
    /// `migrate` et sans contrôle -> après une mise à jour de binaire ajoutant une migration, les bases
    /// tenant EXISTANTES étaient servies et ÉCRITES sur l'ancien schéma. Le cache mémoïse : on l'ÉVINCE
    /// pour reproduire ce qu'est un nouveau processus (redémarrage après montée de version).
    ///
    /// Trois formes, dont deux que rien ne « vise » explicitement :
    ///   (1) base tenant en RETARD de version -> elle est MIGRÉE à l'ouverture (et pas servie telle quelle) ;
    ///   (2) base tenant estampillée au maximum mais AMPUTÉE D'UNE TABLE -> writer REFUSÉ (None) ;
    ///   (3) base tenant estampillée au maximum mais AMPUTÉE D'UNE COLONNE -> writer REFUSÉ aussi.
    #[test]
    fn mode1_tenant_writer_applies_the_schema_contract() {
        let key = tenant_generate_key().expect("l'hôte de test fournit de l'entropie");
        let (cp, _cptmp) = mk_test_control();
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
        let path = mk_tmp_path("writer-contract.db");
        tenant_provision(&st.tenants, "t", "T", &path, &format!("literal:{key}")).expect("provision");

        // outil : agit DIRECTEMENT sur le fichier tenant, puis évince le writer mémoïsé (= nouveau processus).
        let direct = |sql: &str| {
            let c = open_db_keyed(&path, Some(&key)).expect("ouverture directe");
            c.execute_batch(sql).expect("ordre direct");
        };
        let evict = || {
            st.tenants.writers.lock().remove("t");
        };

        // (1) RETARD DE VERSION : la base est rendue « pré-v111 » ; le writer doit la MIGRER, pas la servir.
        direct("UPDATE meta SET value='100' WHERE key='schema_version'");
        evict();
        let h = st.tenants.handle_for("t").expect("base en retard : elle doit être migrée puis servie");
        assert_eq!(
            read_schema_version(&h.lock()),
            CODE_SCHEMA_MAX,
            "la base tenant a été MIGRÉE à l'ouverture du writer (elle était servie telle quelle avant)"
        );

        // (2) TABLE ABSENTE sur une base estampillée au maximum : aucune garde `if v < N` ne la recrée.
        direct("DROP TABLE net_ban");
        evict();
        assert!(
            st.tenants.handle_for("t").is_none(),
            "table absente -> writer REFUSÉ (fail-closed), pas de handle sur un schéma inconnu"
        );

        // (3) COLONNE ABSENTE : forme que le correctif précédent ne voyait pas du tout.
        direct("CREATE TABLE IF NOT EXISTS net_ban(ip TEXT NOT NULL, reason TEXT, created_ts INTEGER, \
                expires_ts INTEGER, created_by TEXT, env_id TEXT NOT NULL DEFAULT 'prod', PRIMARY KEY(ip, env_id))");
        evict();
        assert!(st.tenants.handle_for("t").is_some(), "précondition : la table recréée rend la base servable");
        direct("ALTER TABLE event DROP COLUMN env_id");
        evict();
        assert!(
            st.tenants.handle_for("t").is_none(),
            "colonne absente -> writer REFUSÉ (fail-closed)"
        );

        // (4) ET LE REFUS NE DOIT PAS FAIRE ÉCRIRE AILLEURS. `req_db` doit rendre un handle (aucun des
        // sites de `req_conn!` ne sait échouer) : historiquement il retombait sur `st.db`, donc les
        // écritures d'un tenant indisponible atterrissaient dans la base d'un AUTRE tenant. Le repli est
        // désormais une base CUL-DE-SAC : écriture ET lecture y échouent, et rien n'a bougé chez `default`.
        let avant: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
        let au = AuthUser { name: "u".into(), role: "admin".into(), tenant: "t".into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None };
        let h = req_db(&st, &au);
        assert!(!Arc::ptr_eq(&h, &st.db), "le repli ne doit PAS être la base d'un autre tenant");
        let ecrit = h.lock().execute("INSERT INTO event(ts,source,message) VALUES(1,'x','y')", []);
        assert!(ecrit.is_err(), "écriture sur le repli : REFUSÉE ({ecrit:?})");
        let apres: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
        assert_eq!(avant, apres, "AUCUNE ligne n'a atterri dans la base d'un autre tenant");

        let _ = std::fs::remove_file(&path);
    }

    /// LE CRITÈRE #2a-2c : en mode 1, un JOB DE FOND dispatché via `for_each_active_tenant` ne touche QUE la
    /// base du tenant. Deux tenants A/B (fichiers SQLCipher temp, en clair pour le test) + un tenant 'x' à clé
    /// NON résoluble (vault: sans config). Prouve : (0) l'itération visite A et B, SKIP 'x' (fail-closed) et
    /// jamais 'default' ; (1) une RÈGLE qui fire crée une alerte dans A SEULEMENT (jamais B) ; (2) un SETTING
    /// de rétention propre à A ne s'applique qu'à A (chaque tenant lit SES settings depuis SA base).
    #[test]
    fn mode1_background_jobs_per_tenant() {
        // Déterminisme : pas de Vault configuré -> la clé du tenant 'x' échoue AVANT tout accès réseau.
        std::env::remove_var("PLUME_VAULT_ADDR");
        std::env::remove_var("PLUME_VAULT_TOKEN");
        let (cp, _cptmp) = mk_test_control();
        let pa = mk_tmp_path("jobs-a.db");
        let pb = mk_tmp_path("jobs-b.db");
        {
            let c = cp.conn.lock();
            c.execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('a','A','',?1,?2,0)", params![pa.as_str(), now()]).unwrap();
            c.execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('b','B','',?1,?2,0)", params![pb.as_str(), now()]).unwrap();
            // tenant à clé NON résoluble -> DOIT être SKIP (fail-closed) par for_each_active_tenant.
            c.execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('x','X','vault:secret/data/ghost','/d/x.db',?1,0)", params![now()]).unwrap();
        }
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
        assert!(st.multi_tenant, "mode 1");
        // migre le schéma des 2 bases tenant (fichiers neufs) via le writer mémoïsé du manager.
        for t in ["a", "b"] {
            let h = st.tenants.handle_for(t).unwrap();
            let c = h.lock();
            c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&c);
        }

        // (0) ITÉRATION + SKIP FAIL-CLOSED : for_each_active_tenant visite A et B, jamais 'x' (clé vault non
        //     résoluble), jamais 'default' (mode 1). On collecte les (tenant, db_path) visités.
        let mut visited: Vec<(String, String)> = Vec::new();
        for_each_active_tenant(&st.tenants, |tid, _h, dbp| visited.push((tid.to_string(), dbp.to_string())));
        let ids: Vec<&str> = visited.iter().map(|(t, _)| t.as_str()).collect();
        assert!(ids.contains(&"a") && ids.contains(&"b"), "for_each_active_tenant itère A et B : {ids:?}");
        assert!(!ids.contains(&"x"), "tenant 'x' (clé vault non résoluble) SKIP fail-closed : {ids:?}");
        assert!(!ids.contains(&"default"), "mode 1 : jamais le tenant opérateur 'default'");
        // chaque tenant reçoit SON db_path (jamais celui d'un autre / jamais la base default).
        let dbp_of = |t: &str| visited.iter().find(|(x, _)| x == t).map(|(_, p)| p.clone()).unwrap();
        assert_eq!(dbp_of("a"), pa.as_str());
        assert_eq!(dbp_of("b"), pb.as_str());
        assert_ne!(dbp_of("a"), dbp_of("b"), "db_path distinct par tenant");

        // (1) RÈGLE PAR TENANT : A pose une règle (COUNT(event) >= 1) qui fire (A a 1 event) ; B n'a AUCUNE
        //     règle. run_due_rules dispatché PAR TENANT (comme la boucle de fond) -> l'alerte n'apparaît que
        //     dans A. ÉCHOUERAIT si le job écrivait dans une base partagée (l'alerte fuirait dans B).
        {
            let ha = st.tenants.handle_for("a").unwrap();
            let c = ha.lock();
            c.execute("INSERT INTO event(ts,source,message) VALUES(?1,'sshd','A-evt')", params![now()]).unwrap();
            c.execute("INSERT INTO rule(name,query,is_soql,op,threshold,severity,window_s,interval_s,enabled) \
                       VALUES('r-a','SELECT COUNT(*) FROM event',0,'>=',1,3,86400,0,1)", []).unwrap();
        }
        {
            let hb = st.tenants.handle_for("b").unwrap();
            let c = hb.lock();
            c.execute("INSERT INTO event(ts,source,message) VALUES(?1,'web','B-evt')", params![now()]).unwrap();
        }
        for_each_active_tenant(&st.tenants, |_tid, handle, db_path| {
            run_due_rules(handle, db_path);
        });
        let alerts_a: i64 = st.tenants.handle_for("a").unwrap().lock()
            .query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
        let alerts_b: i64 = st.tenants.handle_for("b").unwrap().lock()
            .query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
        assert_eq!(alerts_a, 1, "la règle de A a fire -> 1 alerte dans A");
        assert_eq!(alerts_b, 0, "B n'a pas de règle -> 0 alerte (l'alerte de A ne fuit JAMAIS dans B)");

        // (2) RÉTENTION PAR TENANT : A pose retention_days=7 (plancher), B pose 3650 (max). Les DEUX ont un
        //     event vieux de 40 j. retention_run dispatché par tenant lit SES settings depuis SA base -> A
        //     purge l'event ancien, B le conserve. Prouve « chaque tenant lit SES settings #1b de SA base ».
        let old_ts = now() - 40 * 86400; // au-delà du plancher 7 j de A, en-deçà des 3650 j de B
        {
            let ha = st.tenants.handle_for("a").unwrap();
            let c = ha.lock();
            c.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','7')", []).unwrap();
            c.execute("INSERT INTO event(ts,source,message) VALUES(?1,'old','A-OLD')", params![old_ts]).unwrap();
        }
        {
            let hb = st.tenants.handle_for("b").unwrap();
            let c = hb.lock();
            c.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','3650')", []).unwrap();
            c.execute("INSERT INTO event(ts,source,message) VALUES(?1,'old','B-OLD')", params![old_ts]).unwrap();
        }
        for_each_active_tenant(&st.tenants, |_tid, handle, _db_path| {
            retention_run(handle);
        });
        let old_a: i64 = st.tenants.handle_for("a").unwrap().lock()
            .query_row("SELECT COUNT(*) FROM event WHERE message='A-OLD'", [], |r| r.get(0)).unwrap();
        let old_b: i64 = st.tenants.handle_for("b").unwrap().lock()
            .query_row("SELECT COUNT(*) FROM event WHERE message='B-OLD'", [], |r| r.get(0)).unwrap();
        assert_eq!(old_a, 0, "rétention 7 j de A (SON setting) purge l'event vieux de 40 j");
        assert_eq!(old_b, 1, "rétention 3650 j de B (SON setting) conserve le MÊME event vieux -> settings PAR tenant");

        let _ = std::fs::remove_file(&pa);
        let _ = std::fs::remove_file(&pb);
    }

    // --- LOOKUP (v61) : upload -> lookup_kv, puis requête GXQL `lookup` enrichit -----------------------
    #[test]
    fn build_lookup_kv_serializes_non_key_cols() {
        // `key_field` devient la CLÉ ; les autres colonnes (requêtables) sont sérialisées dans `val`.
        let rows: Vec<Value> = serde_json::from_str(
            r#"[{"ip":"1.2.3.4","country":"FR","asn":"AS3215"},{"ip":"8.8.8.8","country":"US"},{"no_key":"x"}]"#,
        ).unwrap();
        let (kv, cols) = build_lookup_kv("ip", &rows);
        assert_eq!(kv.len(), 2, "la ligne sans champ-clé est ignorée");
        assert!(cols.contains(&"country".to_string()) && cols.contains(&"asn".to_string()), "{cols:?}");
        // la clé n'est PAS recopiée dans val ; val est du JSON valide.
        let (k0, v0) = &kv[0];
        assert_eq!(k0, "1.2.3.4");
        let parsed: Value = serde_json::from_str(v0).unwrap();
        assert_eq!(parsed["country"], "FR");
        assert!(parsed.get("ip").is_none(), "le champ-clé ne doit pas être dupliqué dans val");
    }

    #[test]
    fn lookup_upload_then_soql_enriches_with_left_join() {
        let conn = test_db();
        // (1) UPLOAD (émule POST /api/lookups) : 2 entrées geoip keyées par `ip`.
        let rows: Vec<Value> = serde_json::from_str(
            r#"[{"ip":"1.2.3.4","country":"FR"},{"ip":"8.8.8.8","country":"US"}]"#,
        ).unwrap();
        let (kv, _cols) = build_lookup_kv("ip", &rows);
        for (k, v) in &kv {
            conn.execute("INSERT OR REPLACE INTO lookup_kv(name,\"key\",val) VALUES('geoip',?1,?2)", params![k, v]).unwrap();
        }
        // une entrée volontairement MALFORMÉE -> json_valid faux -> NULL en lecture (pas d'erreur SQL).
        conn.execute("INSERT OR REPLACE INTO lookup_kv(name,\"key\",val) VALUES('geoip','7.7.7.7','not json')", []).unwrap();
        // (2) des events web : un IP connu, un inconnu (LEFT JOIN -> NULL), un malformé.
        for ip in ["1.2.3.4", "9.9.9.9", "7.7.7.7"] {
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,host,message,src_ip) VALUES(?1,'web','network',1,'h','m',?2)",
                params![now(), ip],
            ).unwrap();
        }
        // (3) REQUÊTE GXQL : enrichissement src_ip -> country via le lookup geoip.
        let sql = soql_to_sql_x("search source=web | lookup geoip src_ip OUTPUT country", 0, 0, None).unwrap();
        let mut stmt = conn.prepare(&format!("SELECT src_ip, country FROM ({sql}) ORDER BY src_ip")).unwrap();
        let got: Vec<(String, Option<String>)> = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)))
            .unwrap()
            .flatten()
            .collect();
        assert_eq!(
            got,
            vec![
                ("1.2.3.4".to_string(), Some("FR".to_string())), // clé présente -> enrichi
                ("7.7.7.7".to_string(), None),                   // val malformé -> NULL (pas d'erreur)
                ("9.9.9.9".to_string(), None),                   // clé absente -> NULL (LEFT JOIN)
            ]
        );
    }

    /// LOOKUP × DÉTECTION ORDONNANCÉE (Tier-1 #36) : une règle GXQL peut RÉFÉRENCER un lookup pour
    /// enrichir puis FILTRER, et ce chemin traverse l'ORDONNANCEUR (`run_due_rules`), pas seulement le
    /// dry-run. On prouve DEUX choses en une passe :
    ///   (a) FIRING — règle `search source=web | lookup badips src_ip OUTPUT flagged | where flagged in
    ///       (bad) | stats count` : seuls les events dont l'IP est dans le lookup denylist sont comptés ->
    ///       l'alerte TIRE avec last_value = nb d'events flaggés (enrichissement utilisable en détection).
    ///   (b) FAIL-CLOSED — règle avec un champ-clé de lookup INVALIDE (`lookup badips bad-field`) : le GXQL
    ///       NE COMPILE PAS (rule_sql Err) -> l'ordonnanceur la traite comme un échec d'éval : il N'ÉCRIT PAS
    ///       un faux last_value 0.0 « tout clair » et NE LÈVE PAS d'alerte (mêmes semantics fail-closed que
    ///       (6), appliquées au seam lookup). Garde-fou contre un lookup cassé qui simulerait un all-clear.
    #[test]
    fn scheduled_run_due_rules_with_lookup_enrich_filter_and_failclosed() {
        let _tmpg1 = crate::tmp_possede::TmpPossede::neuf("schedlk");
        let path = _tmpg1.sous("plume.db").chemin().to_path_buf();
        let p = path.to_string_lossy().to_string();
        let t = now() - 10; // en fenêtre (window_s=600)
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            // Lookup denylist `badips` keyé par `ip` : 9.9.9.9 -> flagged=bad (via l'API interne build_lookup_kv).
            let rows: Vec<Value> = serde_json::from_str(r#"[{"ip":"9.9.9.9","flagged":"bad"}]"#).unwrap();
            let (kv, _c) = build_lookup_kv("ip", &rows);
            for (k, v) in &kv {
                w.execute("INSERT OR REPLACE INTO lookup_kv(name,\"key\",val) VALUES('badips',?1,?2)", params![k, v]).unwrap();
            }
            // (a) règle qui enrichit puis filtre sur la colonne enrichie (DUE, last_run NULL).
            w.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed) \
                 VALUES('denylist-hit',1,'search source=web | lookup badips src_ip OUTPUT flagged | where flagged in (bad) | stats count',1,'>',0.0,4,300,600,'T1071',2)",
                [],
            ).unwrap();
            // (b) règle avec champ-clé de lookup INVALIDE -> ne compile pas (fail-closed). last_value seed 42.
            w.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed,last_value) \
                 VALUES('lookup-casse',1,'search source=web | lookup badips bad-field | stats count',1,'>',0.0,3,300,600,'T1071',2,42.0)",
                [],
            ).unwrap();
            // 3 events d'une IP denylistée + 2 d'une IP propre (ne doivent PAS compter).
            for i in 0..3 {
                w.execute("INSERT INTO event(ts,source,severity,src_ip,fields,dedup) VALUES(?1,'web',4,'9.9.9.9','{}',?2)", params![t, format!("bad-{i}")]).unwrap();
            }
            for i in 0..2 {
                w.execute("INSERT INTO event(ts,source,severity,src_ip,fields,dedup) VALUES(?1,'web',2,'1.1.1.1','{}',?2)", params![t, format!("ok-{i}")]).unwrap();
            }
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_due_rules(&db, &p);
        let (hit_lv, nalert, alert_sev, broke_lv, broke_alerts): (f64, i64, i64, f64, i64) = {
            let c = db.lock();
            let hit_lv: f64 = c.query_row("SELECT COALESCE(last_value,-1) FROM rule WHERE name='denylist-hit'", [], |r| r.get(0)).unwrap();
            let broke_lv: f64 = c.query_row("SELECT COALESCE(last_value,-1) FROM rule WHERE name='lookup-casse'", [], |r| r.get(0)).unwrap();
            // alertes DE la règle denylist uniquement (rule='rule.<id>')
            let hit_id: i64 = c.query_row("SELECT id FROM rule WHERE name='denylist-hit'", [], |r| r.get(0)).unwrap();
            let broke_id: i64 = c.query_row("SELECT id FROM rule WHERE name='lookup-casse'", [], |r| r.get(0)).unwrap();
            let (n, sev): (i64, i64) = c.query_row("SELECT COUNT(*), COALESCE(MAX(severity),0) FROM alert WHERE rule=?1", params![format!("rule.{hit_id}")], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            let nb: i64 = c.query_row("SELECT COUNT(*) FROM alert WHERE rule=?1", params![format!("rule.{broke_id}")], |r| r.get(0)).unwrap();
            (hit_lv, n, sev, broke_lv, nb)
        };
        let _ = std::fs::remove_file(&p);
        // (a) FIRING : 3 events denylistés comptés (l'IP propre exclue par le filtre sur la colonne enrichie).
        assert_eq!(hit_lv, 3.0, "la règle lookup compte EXACTEMENT les 3 events denylistés (enrichissement + filtre)");
        assert_eq!(nalert, 1, "la règle lookup LÈVE une alerte via l'ordonnanceur");
        assert_eq!(alert_sev, 4, "sévérité héritée de la règle");
        // (b) FAIL-CLOSED : lookup invalide -> pas de compilation -> pas de faux 0.0, pas d'alerte.
        assert_eq!(broke_lv, 42.0, "un lookup INVALIDE ne réécrit PAS last_value en 0.0 (pas de faux 'tout clair')");
        assert_eq!(broke_alerts, 0, "un lookup INVALIDE ne LÈVE PAS d'alerte (fail-closed, pas d'exécution partielle)");
    }

    #[test]
    fn migration_v43_rebrands_live_soc_to_plume() {
        // Simule une base LIVE héritée (état pré-v43) : on part d'une base PLEINEMENT migrée (schéma panel
        // complet), on INJECTE l'état hérité (clé meta 'soc_mode' + panneaux key=soc_*) puis on RÉTROGRADE
        // schema_version à 42 -> migrate() doit RENOMMER la clé et RÉPARER les requêtes (idempotent).
        let conn = test_db();
        conn.execute("DELETE FROM meta WHERE key='plume_mode'", []).unwrap();      // efface le seed plume_mode (v5)
        conn.execute("INSERT INTO meta(key,value) VALUES('soc_mode','active')", []).unwrap();
        for q in [
            "search source=dataaccess key=soc_creds | table user",
            "search source=dataaccess key=soc_etc | table user",
            "search source=dataaccess key=soc_data | table user",
        ] {
            conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(1,'t',?1,1,'table',0,2)", params![q]).unwrap();
        }
        conn.execute("UPDATE meta SET value='42' WHERE key='schema_version'", []).unwrap();  // rétrograde -> v43 re-tourne
        let _ = migrate(&conn);
        // (a) meta : soc_mode renommée en plume_mode, valeur préservée, plus de soc_mode résiduel.
        let mode: String = conn.query_row("SELECT value FROM meta WHERE key='plume_mode'", [], |r| r.get(0)).unwrap();
        assert_eq!(mode, "active", "v43 doit préserver la valeur du mode en renommant la clé");
        assert!(conn.query_row("SELECT 1 FROM meta WHERE key='soc_mode'", [], |r| r.get::<_, i64>(0)).is_err(), "la clé soc_mode héritée doit disparaître");
        // (b) panneaux : plus aucune requête key=soc_* ; les key=plume_* sont présentes.
        let leftover: i64 = conn.query_row("SELECT COUNT(*) FROM panel WHERE query LIKE '%key=soc_%'", [], |r| r.get(0)).unwrap();
        assert_eq!(leftover, 0, "aucune requête key=soc_* ne doit subsister après v43");
        let fixed: i64 = conn.query_row("SELECT COUNT(*) FROM panel WHERE query LIKE '%key=plume_creds%' OR query LIKE '%key=plume_etc%' OR query LIKE '%key=plume_data%'", [], |r| r.get(0)).unwrap();
        assert_eq!(fixed, 3, "les 3 panneaux doivent viser key=plume_*");
        // idempotent : re-jouer ne casse rien.
        let _ = migrate(&conn);
        let v: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(v, CODE_SCHEMA_MAX.to_string());
    }

    #[test]
    fn excl_v54_parse_and_clause_generation() {
        // parse : IPv4 exact, IPv6 /32 -> préfixe, IPv4 CIDR, /32 exact, wildcard explicite, vide ignoré.
        // (littéraux = exemples doc RFC 5737 / RFC 3849 — aucune donnée perso bakée dans le binaire).
        assert_eq!(parse_excl_item("203.0.113.7"), Some(("203.0.113.7".into(), false)));
        assert_eq!(parse_excl_item("2001:db8::/32"), Some(("2001:db8:".into(), true)));
        assert_eq!(parse_excl_item("10.0.0.0/24"), Some(("10.0.0.".into(), true)));
        assert_eq!(parse_excl_item("203.0.113.7/32"), Some(("203.0.113.7".into(), false)));
        assert_eq!(parse_excl_item("2001:db8:*"), Some(("2001:db8:".into(), true)));
        assert_eq!(parse_excl_item("   "), None);
        // clause opérateur (src_ip = colonne réelle) : SQL natif + termes soql (exemples doc).
        let (op_sql, op_soql) = ExclClauses::build("src_ip", "203.0.113.7,2001:db8::/32");
        assert_eq!(op_sql, "src_ip != '203.0.113.7' AND src_ip NOT LIKE '2001:db8:%'");
        assert_eq!(op_soql, "src_ip!=203.0.113.7 src_ip!=2001:db8:*");
        // self vhost = champ JSON -> json_extract en SQL natif ; terme par nom de champ en soql.
        let (self_sql, self_soql) = ExclClauses::build("vhost", "plume.example.com");
        assert_eq!(self_sql, "json_extract(fields,'$.vhost') != 'plume.example.com'");
        assert_eq!(self_soql, "vhost!=plume.example.com");
        // liste vide -> no-op (1=1 en SQL, terme vide en soql) : exclusion désactivable.
        let (empty_sql, empty_soql) = ExclClauses::build("src_ip", "");
        assert_eq!(empty_sql, "1=1");
        assert_eq!(empty_soql, "");
    }

    #[test]
    fn excl_v55_detection_has_zero_exclusion_panels_keep_it() {
        // INVARIANT SÉCURITÉ (v55) : collecte + DÉTECTION = ZÉRO exclusion (on doit TOUT voir, y compris une
        // attaque venant de l'IP opérateur) ; l'exclusion reste UNIQUEMENT sur les PANNEAUX d'affichage.
        let conn = test_db();

        // (A) DÉTECTION — aucune RÈGLE seedée ne porte de placeholder d'exclusion (pas d'angle mort).
        seed_detection_rules(&conn);
        let leftover: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM rule WHERE query LIKE '%__OPERATOR_EXCL__%' OR query LIKE '%__SELF_EXCL__%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(leftover, 0, "AUCUNE règle de détection ne doit porter d'exclusion self/opérateur (angle mort)");

        // (B) DÉTECTION — `rule_sql` NE SUBSTITUE PAS les placeholders d'exclusion : un placeholder éventuel
        // reste LITTÉRAL (deviendrait du SQL invalide -> visible, jamais un angle mort silencieux).
        let raw = rule_sql("SELECT 1 FROM event WHERE ts>=__FROM__ AND __OPERATOR_EXCL__", false, 900).unwrap();
        assert!(raw.contains("__OPERATOR_EXCL__"), "rule_sql NE DOIT PAS substituer l'exclusion (détection) : {raw}");

        // (C) DÉTECTION — la règle 38 canonique (anti-join) est PROPRE (sans exclusion) et compile en SQL valide.
        assert!(!ATTACKER_UNMITIGATED_RULE_SQL.contains("__OPERATOR_EXCL__"), "la règle 38 ne doit plus porter d'exclusion");
        let r38 = rule_sql(ATTACKER_UNMITIGATED_RULE_SQL, false, 3600).unwrap();
        conn.prepare(&r38).unwrap_or_else(|e| panic!("SQL règle 38 invalide : {e}\n{r38}"));

        // (D) PANNEAUX (affichage seul) — `compile_panel_sql` SUBSTITUE bien l'exclusion -> SQL valide, plus
        // aucun placeholder résiduel. Panneau web GXQL (src_ip + vhost) + panneaux banpass natifs.
        let web = "search source=web __OPERATOR_EXCL__ __SELF_EXCL__ | where severity>=2 | sort -ts | table vhost,path,status,src_ip,ua";
        let wsql = compile_panel_sql(web, true, now() - 3600, 0, None).unwrap_or_else(|e| panic!("compilation web échouée : {e}"));
        conn.prepare(&wsql).unwrap_or_else(|e| panic!("SQL web invalide : {e}\n{wsql}"));
        assert!(!wsql.contains("__OPERATOR_EXCL__") && !wsql.contains("__SELF_EXCL__"), "placeholders panneau web substitués : {wsql}");
        // Avec le DÉFAUT GÉNÉRIQUE vide (aucune IP perso bakée), la substitution panneau est un no-op voulu.
        // Le MÉCANISME d'exclusion d'affichage — quand une IP opérateur EST configurée — reste prouvé ici
        // sans donnée perso en dur : une liste opérateur non vide produit bien la clause d'exclusion.
        let (op_sql_cfg, _) = ExclClauses::build("src_ip", "203.0.113.7");
        assert!(op_sql_cfg.contains("203.0.113.7"), "une IP opérateur CONFIGURÉE produit la clause d'exclusion (affichage) : {op_sql_cfg}");
        for q in [BANPASS_UNMITIGATED_SQL, BANPASS_COVERAGE_SQL] {
            assert!(q.contains("__OPERATOR_EXCL__"), "les panneaux banpass GARDENT l'exclusion (affichage)");
            let bp = compile_panel_sql(q, false, now() - 86400, 0, None).unwrap();
            conn.prepare(&bp).unwrap_or_else(|e| panic!("SQL banpass invalide : {e}\n{bp}"));
            assert!(!bp.contains("__OPERATOR_EXCL__"), "placeholder banpass substitué : {bp}");
        }
    }

    #[test]
    fn cf_rules_v45_compile_to_valid_sql() {
        // CHANGEMENT 3 : les 5 requêtes CF re-tunées DOIVENT compiler (soql_to_sql) ET être du SQL valide
        // (PREPARE sur le schéma réel). Couvre le fix soql_agg : `dc(vhost)`/`dc(src_ip)` doivent json_extract
        // / référencer la colonne réelle au lieu d'une colonne inexistante (sinon la règle est MUETTE).
        let conn = test_db();
        let cf_queries = [
            "search source=cloudflare action=challenged | stats count by src_ip | where count > 20 | stats count",
            "search source=cloudflare cf_source=waf | stats count by src_ip | where count > 3 | stats count",
            "search source=cloudflare | stats count by src_ip | where count > 100 | stats count",
            "search source=cloudflare | stats dc(vhost) by src_ip | where dc > 3 | stats count",
            "search source=cloudflare action=challenged | stats dc(src_ip)",
        ];
        for q in cf_queries {
            let sql = rule_sql(q, true, 900).unwrap_or_else(|e| panic!("compilation GXQL échouée pour `{q}` : {e}"));
            conn.prepare(&sql).unwrap_or_else(|e| panic!("SQL invalide pour `{q}` : {e}\nSQL: {sql}"));
        }
        // le fix soql_agg : dc(vhost) doit json_extract le champ JSON (pas COUNT(DISTINCT "vhost")).
        let sql28 = rule_sql("search source=cloudflare | stats dc(vhost) by src_ip | where dc > 3 | stats count", true, 900).unwrap();
        assert!(sql28.contains("json_extract(fields,'$.vhost')"), "dc(vhost) doit json_extract le champ JSON, SQL: {sql28}");
        // dc(src_ip) : src_ip étant une colonne RÉELLE, reste référencée telle quelle (pas de json_extract).
        let sql29 = rule_sql("search source=cloudflare action=challenged | stats dc(src_ip)", true, 900).unwrap();
        assert!(!sql29.contains("json_extract(fields,'$.src_ip')"), "dc(src_ip) ne doit PAS json_extract une colonne réelle, SQL: {sql29}");
    }

    #[test]
    fn panel_cost_v46_roundtrip_classification_and_query_fp_isolation() {
        // PHASE 3d : la table panel_cost existe + le couple lire/écrire le coût classe le panneau (LIVE/SWR)
        // et s'auto-reclasse, avec isolation par query_fp (un panel_update « oublie » l'ancien coût).
        let conn = test_db();
        assert!(
            conn.query_row("SELECT 1 FROM sqlite_master WHERE type='table' AND name='panel_cost'", [], |_| Ok(())).is_ok(),
            "panel_cost doit exister après migrate()"
        );
        // panneau NOUVEAU (aucun coût) -> None -> l'appelant exécute en LIVE (1re mesure).
        assert!(read_panel_cost(&conn, 1, "fpA").is_none(), "un panneau inconnu n'a pas de coût (-> LIVE)");
        // 1re mesure CHEAP (< seuil défaut 100) -> classé LIVE.
        record_panel_cost(&conn, 1, "fpA", 12.5, now());
        assert_eq!(read_panel_cost(&conn, 1, "fpA"), Some(12.5));
        // AUTO-RECLASSEMENT : le même panneau ralentit (>= seuil) -> OR REPLACE met à jour le coût (-> SWR).
        record_panel_cost(&conn, 1, "fpA", 350.0, now());
        assert_eq!(read_panel_cost(&conn, 1, "fpA"), Some(350.0), "le coût se met à jour (auto-reclassement)");
        let rows: i64 = conn.query_row("SELECT COUNT(*) FROM panel_cost WHERE panel_id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(rows, 1, "1 seule ligne par panneau (PK panel_id, OR REPLACE)");
        // ISOLATION par query_fp : une requête DIFFÉRENTE (panel_update) ne réutilise pas l'ancien coût.
        assert!(read_panel_cost(&conn, 1, "fpB").is_none(), "un q_fp différent ne sert pas le coût d'une autre requête");
        record_panel_cost(&conn, 1, "fpB", 5.0, now());
        assert!(read_panel_cost(&conn, 1, "fpA").is_none(), "le nouveau fp remplace l'ancien (1 ligne/panneau)");
        assert_eq!(read_panel_cost(&conn, 1, "fpB"), Some(5.0));
        // measured_cost_ms extrait bien stats.elapsed_ms d'un résultat run_query, None si absent.
        assert_eq!(measured_cost_ms(&json!({"stats": {"elapsed_ms": 7.0}})), Some(7.0));
        assert!(measured_cost_ms(&json!({"columns": [], "rows": []})).is_none());
    }

    #[test]
    fn merge_rollup_dims_env_is_additive_validated_and_capped() {
        // PHASE 2 : PLUME_ROLLUP_DIMS fusionne ADDITIVEMENT (union dédupliquée), valide les idents,
        // cap 6 dims/source, et crée des sources nouvelles — SANS jamais retirer un défaut.
        let base = || -> Vec<(String, Vec<String>)> {
            vec![("k8s-log".to_string(), vec!["ns".into(), "pod".into(), "level".into()])]
        };
        let dims = |s: &[(String, Vec<String>)], src: &str| -> Vec<String> {
            s.iter().find(|(n, _)| n == src).map(|(_, d)| d.clone()).unwrap_or_default()
        };
        // (a) ajoute une dim à une source connue, sans doublonner les existantes.
        let mut s = base();
        merge_rollup_dims(&mut s, "k8s-log:container,level");
        assert_eq!(dims(&s, "k8s-log"), ["ns", "pod", "level", "container"], "additif + dédup level");
        // (b) crée une source nouvelle.
        let mut s = base();
        merge_rollup_dims(&mut s, "myapp:env,region");
        assert_eq!(dims(&s, "myapp"), ["env", "region"]);
        // (c) idents invalides (source/dim) ignorés silencieusement (jamais d'injection/crash).
        let mut s = base();
        merge_rollup_dims(&mut s, "bad source:x;k8s-log:bad-dim,ok_dim;:nodim;nosep");
        let k8s = &s.iter().find(|(n, _)| n == "k8s-log").unwrap().1;
        assert!(k8s.contains(&"ok_dim".to_string()) && !k8s.iter().any(|d| d == "bad-dim"), "{k8s:?}");
        assert!(!s.iter().any(|(n, _)| n.contains(' ')), "source invalide ne doit pas être créée");
        // (d) cap 6 dims/source (défauts compris).
        let mut s = base(); // déjà 3 dims
        merge_rollup_dims(&mut s, "k8s-log:a,b,c,d,e,f,g");
        assert_eq!(s.iter().find(|(n, _)| n == "k8s-log").unwrap().1.len(), DIM_ROLLUP_MAX_DIMS_PER_SOURCE);
    }

    #[test]
    fn dim_rollup_specs_default_includes_k8s_log_level() {
        // Le défaut effectif (sans env) doit router `search source=k8s-log | stats count by level`.
        let specs = dim_rollup_specs();
        let k8s = specs.iter().find(|(s, _)| s == "k8s-log").expect("k8s-log présent");
        assert!(k8s.1.iter().any(|d| d == "level"), "level doit être un défaut k8s-log: {:?}", k8s.1);
    }

    #[test]
    fn dim_rollup_v44_populates_and_matches_live_groupby() {
        // v44 : event_dim_rollup existe + son peuplement par rollup_events CORRESPOND au `stats count by`.
        let conn = test_db();
        assert!(
            conn.query_row("SELECT 1 FROM sqlite_master WHERE type='table' AND name='event_dim_rollup'", [], |_| Ok(())).is_ok(),
            "event_dim_rollup doit exister après migrate()"
        );
        // events web dans l'heure courante (fenêtre chaude) avec status variés.
        let t = now();
        let ins = |status: &str, n: i64| {
            for _ in 0..n {
                conn.execute(
                    "INSERT INTO event(ts,source,fields) VALUES(?1,'web',?2)",
                    params![t, format!("{{\"status\":\"{status}\",\"vhost\":\"a.example\",\"path\":\"/x\"}}")],
                ).unwrap();
            }
        };
        ins("200", 5);
        ins("404", 3);
        ins("500", 2);
        rollup_events(&conn);
        // (a) CORRECTNESS : le rollup status correspond exactement au stats count by status (1 bucket, pas de cap atteint).
        let rollup: Vec<(String, i64)> = {
            let mut s = conn.prepare("SELECT val, SUM(n) FROM event_dim_rollup WHERE source='web' AND dim='status' GROUP BY val ORDER BY val").unwrap();
            s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).unwrap().flatten().collect()
        };
        assert_eq!(rollup, vec![("200".into(), 5), ("404".into(), 3), ("500".into(), 2)], "rollup status != live");
        // (b) le tick est idempotent (la fenêtre chaude est purgée puis ré-agrégée -> pas de double comptage).
        rollup_events(&conn);
        let total: i64 = conn.query_row("SELECT SUM(n) FROM event_dim_rollup WHERE source='web' AND dim='status'", [], |r| r.get(0)).unwrap();
        assert_eq!(total, 10, "re-tick ne doit pas doubler la fenêtre chaude");
    }

    #[test]
    fn seed_web_panels_rewritten_to_dim_rollup() {
        // les panneaux GROUP-BY purs sont semés en is_soql=0 sur event_dim_rollup ; les autres restent GXQL.
        let conn = test_db();
        seed_web_dashboard(&conn);
        let (q, is_soql): (String, i64) = conn
            .query_row("SELECT query, is_soql FROM panel WHERE title='Codes statut'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(is_soql, 0, "Codes statut doit être is_soql=0");
        assert!(q.contains("event_dim_rollup") && q.contains("dim='status'"), "doit lire event_dim_rollup/status : {q}");
        let tc: i64 = conn.query_row("SELECT is_soql FROM panel WHERE title='Requêtes dans le temps'", [], |r| r.get(0)).unwrap();
        assert_eq!(tc, 1, "le timechart doit rester is_soql=1 (non réécrit)");
    }

    #[test]
    fn migration_v44_rewrites_existing_panel() {
        // simule la PROD : panneau déjà semé en is_soql=1 -> v44 le réécrit en is_soql=0 sur le pré-agrégé.
        let conn = test_db();
        conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) \
             VALUES(1,'Codes statut','search source=web | stats count by status | sort -count',1,'bar',0,2)",
            [],
        ).unwrap();
        conn.execute("UPDATE meta SET value='43' WHERE key='schema_version'", []).unwrap(); // rétrograde -> v44 re-tourne
        let _ = migrate(&conn);
        let (q, is_soql): (String, i64) = conn
            .query_row("SELECT query, is_soql FROM panel WHERE title='Codes statut'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(is_soql, 0, "v44 doit passer le panneau existant en is_soql=0");
        assert!(q.contains("event_dim_rollup") && q.contains("source='web'") && q.contains("dim='status'"), "réécrit sur le pré-agrégé : {q}");
    }

    #[test]
    fn seeded_creds_panel_queries_plume_creds() {
        // le seed frais du dashboard 'Accès données' doit viser key=plume_creds (régression item 1).
        let conn = test_db();
        seed_dataaccess_dashboard(&conn);
        let cnt: i64 = conn.query_row("SELECT COUNT(*) FROM panel WHERE query LIKE '%key=plume_creds%'", [], |r| r.get(0)).unwrap();
        assert_eq!(cnt, 1, "le panneau creds doit viser key=plume_creds");
        let stale: i64 = conn.query_row("SELECT COUNT(*) FROM panel WHERE query LIKE '%key=soc_creds%'", [], |r| r.get(0)).unwrap();
        assert_eq!(stale, 0, "aucun panneau ne doit viser key=soc_creds");
    }

    /// AppState minimal pour tester sso_role (champs non pertinents -> valeurs vides/neutres).
    fn sso_test_state(admin: &str, editor: &str, superadmin: &str) -> AppState {
        tenant_test_state(admin, editor, superadmin, None)
    }

    /// VENDOR-AGNOSTIC (C1) — les NOMS d'en-têtes trusted-header sont configurables ; défauts = x-authentik-*.
    /// (a) DÉFAUT : x-authentik-username/groups honorés à l'IDENTIQUE (GUATX byte-identique).
    /// (b) CUSTOM : les noms configurés (x-idp-user/x-idp-groups) sont honorés ET les anciens x-authentik-*
    ///     n'accordent RIEN (pas de dual-accept qui prêterait à confusion / élargirait la surface).
    /// (c) GATE SECRET fail-closed : sans le bon x-plume-sso-secret, AUCUN en-tête (défaut ou custom) n'accorde
    ///     d'identité -> rendre le nom configurable NE crée aucun chemin de lecture hors du gate secret.
    #[test]
    fn sso_header_names_configurable_default_preserves_and_secret_gates() {
        let secret = "s3cr3t-shared";
        // state avec le secret partagé POSÉ (sinon le bloc SSO est inerte) + noms d'en-têtes paramétrables.
        let with_names = |user_hdr: &str, groups_hdr: &str| {
            let mut st = sso_test_state("plume-admin", "plume-editor", "admins");
            st.sso_secret = Arc::new(secret.to_string());
            st.sso_header_user = Arc::new(user_hdr.to_string());
            st.sso_header_groups = Arc::new(groups_hdr.to_string());
            st
        };
        // Requête : (secret optionnel) + une paire (nom_user, val_user) + (nom_groups, val_groups).
        let mk = |sec: Option<&str>, uh: &str, uv: &str, gh: &str, gv: &str| {
            let mut b = Request::builder().uri("/api/query");
            if let Some(s) = sec { b = b.header("x-plume-sso-secret", s); }
            b.header(uh, uv).header(gh, gv).body(axum::body::Body::empty()).unwrap()
        };

        // (a) DÉFAUT : x-authentik-* honorés, rôle mappé via les groupes -> comportement GUATX inchangé.
        let st_def = with_names("x-authentik-username", "x-authentik-groups");
        let (id, m, _, _, _) = resolve_identity(&st_def, &mk(Some(secret), "x-authentik-username", "alice", "x-authentik-groups", "plume-admin"));
        assert_eq!(id, Some(("alice".to_string(), "admin".to_string())), "défaut : x-authentik-* -> admin");
        assert_eq!(m, "sso");

        // (b) CUSTOM : les noms configurés sont honorés ...
        let st_cust = with_names("x-idp-user", "x-idp-groups");
        let (id2, m2, _, _, _) = resolve_identity(&st_cust, &mk(Some(secret), "x-idp-user", "bob", "x-idp-groups", "plume-editor"));
        assert_eq!(id2, Some(("bob".to_string(), "editor".to_string())), "custom : x-idp-* -> editor");
        assert_eq!(m2, "sso");
        // ... ET les anciens x-authentik-* n'accordent RIEN quand un AUTRE nom est configuré (pas de dual-accept).
        let (id3, _, _, _, _) = resolve_identity(&st_cust, &mk(Some(secret), "x-authentik-username", "eve", "x-authentik-groups", "plume-admin"));
        assert!(id3.is_none(), "custom : les anciens x-authentik-* ne sont PLUS lus (pas de dual-accept élargissant la surface)");

        // (c) GATE SECRET fail-closed : bon nom mais secret absent/mauvais -> AUCUNE identité forgée.
        let (id4, _, _, _, _) = resolve_identity(&st_def, &mk(None, "x-authentik-username", "alice", "x-authentik-groups", "plume-admin"));
        assert!(id4.is_none(), "sans x-plume-sso-secret : en-têtes ignorés (fail-closed)");
        let (id5, _, _, _, _) = resolve_identity(&st_cust, &mk(Some("wrong-secret-value"), "x-idp-user", "bob", "x-idp-groups", "plume-admin"));
        assert!(id5.is_none(), "mauvais secret : en-têtes ignorés même avec les bons noms (le nom ne bypass pas le secret)");
    }

    /// AppState de test complet, paramétré par un control-plane optionnel (`None` = mode 0, `Some` = mode 1).
    /// La base tenant (`db`) est en mémoire, schéma + migrations appliqués -> utilisable pour l'identité
    /// mode 0 (table user/token) ; en mode 1, l'identité est lue du control-plane fourni.
    fn tenant_test_state(admin: &str, editor: &str, superadmin: &str, control: Option<ControlPlane>) -> AppState {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        let db = Arc::new(Mutex::new(conn));
        let db_path = Arc::new(String::new());
        let multi_tenant = control.is_some();
        let tenants = TenantDbManager {
            default_db_path: db_path.clone(),
            default_writer: db.clone(),
            control,
            writers: Arc::new(Mutex::new(HashMap::new())),
        };
        AppState {
            db,
            user: Arc::new(String::new()),
            pass_hash: Arc::new(String::new()),
            admin: Arc::new(Mutex::new(None)),
            setup_token: Arc::new(String::new()),
            host: Arc::new(String::new()),
            host_strict: false,
            sso_secret: Arc::new(String::new()),
            sso_group_admin: Arc::new(admin.to_string()),
            sso_group_editor: Arc::new(editor.to_string()),
            sso_group_superadmin: Arc::new(superadmin.to_string()),
            sso_header_user: Arc::new("x-authentik-username".to_string()),
            sso_header_groups: Arc::new("x-authentik-groups".to_string()),
            public_demo: false,
            metrics_token: Arc::new(String::new()),
            search_limit_default: 100,
            search_limit_max: 5000,
            db_path,
            spool: Arc::new(String::new()),
            auth_cache: Arc::new(Mutex::new(HashMap::new())),
            rl: Arc::new(Mutex::new((Instant::now(), 0))),
            query_sem: Arc::new(tokio::sync::Semaphore::new(1)),
            ingest_sem: Arc::new(tokio::sync::Semaphore::new(4)),
            refresh_sem: Arc::new(tokio::sync::Semaphore::new(1)),
            panel_refresh_inflight: Arc::new(Mutex::new(HashSet::new())),
            auth_fails: Arc::new(Mutex::new(HashMap::new())),
            lock_threshold: 10,
            lock_base_s: 30,
            lock_max_s: 900,
            rl_ip: Arc::new(Mutex::new(HashMap::new())),
            rl_ip_max: 1200,
            rl_auth_max: 120,
            rl_global_max: 6000,
            session_secret: Arc::new(b"test-session-secret".to_vec()),
            session_ttl_s: 43200,
            session_epoch: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            ingest_min_free_mb: 512,
            ingest_max_events: 50000,
            multi_tenant,
            tenants,
        }
    }

    /// Control-plane de TEST : base SQLCipher (ici en clair) sur disque temp, schéma control-plane créé.
    /// Sert les tests d'identité mode 1 (token->tenant + platform_user auth lus du control-plane).
    fn mk_test_control() -> (ControlPlane, crate::tmp_possede::TmpDb) {
        let path = mk_tmp_path("control");
        let cp = mk_control_at(path.as_str());
        (cp, path)
    }

    /// Control-plane à un chemin DONNÉ. Sépare « où vit le fichier » de « qui le possède », pour que
    /// l'appelant qui possède DÉJÀ un répertoire y loge son control-plane au lieu d'en faire naître
    /// un second qu'il devrait maintenir vivant en parallèle.
    fn mk_control_at(path: &str) -> ControlPlane {
        let conn = open_db_keyed(path, None).unwrap();
        migrate_control(&conn);
        ControlPlane { conn: Arc::new(Mutex::new(conn)), db_path: Arc::new(path.to_string()) }
    }

    // ---------- (#2c) GESTION DES TENANTS EN ROUTES HTTP ----------

    /// AppState MODE 1 avec control-plane (tenant `default` catalogué) et un db_path SOUS un répertoire temp
    /// UNIQUE -> tenant_db_path(...) crée les bases tenant dans ce répertoire (isolé, nettoyable). Renvoie
    /// (state, répertoire temp) ; l'appelant supprime le répertoire en fin de test.
    fn mk_mode1_state() -> (AppState, crate::tmp_possede::TmpPossede) {
        let dir = crate::tmp_possede::TmpPossede::neuf("mt2c");
        let main_db = format!("{dir}/plume.db");
        // Le control-plane vit DANS le répertoire déjà possédé : un seul propriétaire pour tout ce que
        // la fixture crée. (Un second temporaire aurait été détruit à la sortie de cette fonction —
        // la base du control-plane disparaissait sous le test.)
        let cp = mk_control_at(dir.sous("control.db").as_str());
        {
            let c = cp.conn.lock();
            c.execute(
                "INSERT OR IGNORE INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('default','default','',?1,?2,0)",
                params![main_db, now()],
            )
            .unwrap();
        }
        let mut st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
        st.db_path = Arc::new(main_db.clone());
        st.tenants.default_db_path = Arc::new(main_db.clone());
        (st, dir)
    }
    fn au_super(name: &str) -> AuthUser {
        AuthUser { name: name.into(), role: "admin".into(), tenant: "default".into(), is_superadmin: true, method: "basic".into(), csrf: String::new(), env: None }
    }
    fn au_tadmin(name: &str, tenant: &str) -> AuthUser {
        AuthUser { name: name.into(), role: "admin".into(), tenant: tenant.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }
    fn count_grant(st: &AppState, tenant: &str, user: &str) -> i64 {
        let cp = st.tenants.control.as_ref().unwrap();
        let c = cp.conn.lock();
        c.query_row(
            "SELECT COUNT(*) FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id WHERE g.tenant_id=?1 AND p.name=?2",
            params![tenant, user],
            |r| r.get(0),
        )
        .unwrap_or(0)
    }
    fn ledger_kinds(st: &AppState) -> Vec<String> {
        let cp = st.tenants.control.as_ref().unwrap();
        let c = cp.conn.lock();
        let mut s = c.prepare("SELECT kind FROM control_ledger ORDER BY id").unwrap();
        s.query_map([], |r| r.get::<_, String>(0)).unwrap().flatten().collect()
    }

    /// GATING SERVEUR (path-guard + helpers PURS) : super-admin vs tenant-admin, anti-escalade, borne au
    /// tenant courant. C'est le cœur des garde-fous (enforce SERVEUR) exercé hors handlers.
    #[test]
    fn mt2c_gating_pure_functions() {
        // mgmt_target_tenant : Some UNIQUEMENT pour les routes `grants` (le tenant-admin y est borné).
        assert_eq!(mgmt_target_tenant("/api/tenants/acme/grants"), Some("acme".into()));
        assert_eq!(mgmt_target_tenant("/api/tenants/acme/grants/bob"), Some("acme".into()));
        assert_eq!(mgmt_target_tenant("/api/tenants/acme/suspend"), None, "suspend != grants -> contexte default");
        assert_eq!(mgmt_target_tenant("/api/tenants/acme"), None, "DELETE tenant -> contexte default");
        assert_eq!(mgmt_target_tenant("/api/tenants"), None);

        // valid_grant_role : enum FERMÉ -> jamais 'superadmin' (anti-escalade plateforme).
        assert!(valid_grant_role("admin") && valid_grant_role("editor") && valid_grant_role("viewer"));
        assert!(!valid_grant_role("superadmin"), "superadmin n'est PAS un rôle de grant (anti-escalade)");
        assert!(!valid_grant_role("owner"));

        // can_manage_grants : super-admin partout ; tenant-admin UNIQUEMENT son tenant courant.
        assert!(can_manage_grants(&au_super("op"), "acme"));
        assert!(can_manage_grants(&au_super("op"), "beta"));
        assert!(can_manage_grants(&au_tadmin("al", "acme"), "acme"), "admin de acme gère acme");
        assert!(!can_manage_grants(&au_tadmin("al", "acme"), "beta"), "admin de acme NE gère PAS beta (anti cross-tenant)");
        assert!(!can_manage_grants(&AuthUser { name: "v".into(), role: "viewer".into(), tenant: "acme".into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }, "acme"), "viewer ne gère aucun grant");

        // tenant_mgmt_gate (path-guard) : CRUD/suspend/list = super-admin only ; grants = super-admin OU admin du tenant.
        // super-admin : tout autorisé.
        assert!(tenant_mgmt_gate("/api/tenants", "admin", "default", true).is_ok());
        assert!(tenant_mgmt_gate("/api/tenants/acme", "admin", "default", true).is_ok());
        assert!(tenant_mgmt_gate("/api/tenants/acme/suspend", "admin", "default", true).is_ok());
        assert!(tenant_mgmt_gate("/api/tenants/acme/grants", "viewer", "default", true).is_ok());
        // non-super-admin admin d'un tenant : CRUD/suspend/list REFUSÉS (super-admin only).
        assert!(tenant_mgmt_gate("/api/tenants", "admin", "acme", false).is_err(), "tenant-admin NE peut PAS lister/créer des tenants");
        assert!(tenant_mgmt_gate("/api/tenants/beta", "admin", "acme", false).is_err(), "tenant-admin NE peut PAS détruire un tenant");
        assert!(tenant_mgmt_gate("/api/tenants/acme/suspend", "admin", "acme", false).is_err(), "tenant-admin NE peut PAS suspendre");
        // grants : admin borné à SON tenant.
        assert!(tenant_mgmt_gate("/api/tenants/acme/grants", "admin", "acme", false).is_ok(), "admin de acme gère les grants de acme");
        assert!(tenant_mgmt_gate("/api/tenants/beta/grants", "admin", "acme", false).is_err(), "admin de acme NE gère PAS les grants de beta");
        assert!(tenant_mgmt_gate("/api/tenants/acme/grants", "editor", "acme", false).is_err(), "editor ne gère pas les grants");
        // my-tenants : ouvert à tout user authentifié.
        assert!(tenant_mgmt_gate("/api/my-tenants", "viewer", "acme", false).is_ok());
        // route non-gérée -> pass-through (le reste du RBAC s'applique ailleurs).
        assert!(tenant_mgmt_gate("/api/overview", "viewer", "acme", false).is_ok());
    }

    /// ONBOARDING (POST /api/tenants) super-admin : provisionne l'entrée control-plane + la base chiffrée +
    /// le SEED complet (D7), pose le 1er grant admin, et AUDITE (control_ledger `tenant.create` + event tenant).
    #[tokio::test]
    async fn mt2c_onboarding_creates_tenant_seed_grant_and_audit() {
        let (st, dir) = mk_mode1_state();
        let resp = tenant_create(
            State(st.clone()),
            Extension(au_super("op")),
            Json(json!({ "id": "acme", "name": "AcmeCorp", "admin": "alice" })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "onboarding -> 201");

        // (a) entrée catalogue créée + base chiffrée sur disque.
        let (name, db_path): (String, String) = {
            let cp = st.tenants.control.as_ref().unwrap();
            let c = cp.conn.lock();
            c.query_row("SELECT name, db_path FROM tenant WHERE id='acme'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap()
        };
        assert_eq!(name, "AcmeCorp");
        assert!(std::path::Path::new(&db_path).exists(), "base tenant créée sur disque");

        // (b) SEED complet (D7) : la base tenant démarre avec des règles + dashboards (pas vide).
        {
            let h = st.tenants.handle_for("acme").unwrap();
            let c = h.lock();
            let rules: i64 = c.query_row("SELECT COUNT(*) FROM rule", [], |r| r.get(0)).unwrap();
            let dashes: i64 = c.query_row("SELECT COUNT(*) FROM dashboard", [], |r| r.get(0)).unwrap();
            assert!(rules > 0, "seed de règles de détection présent ({rules})");
            assert!(dashes > 0, "seed de dashboards présent ({dashes})");
        }

        // (c) 1er grant admin posé (alice matérialisée en platform_user + grant admin sur acme).
        assert_eq!(count_grant(&st, "acme", "alice"), 1, "1er grant admin posé pour alice");
        let role: String = {
            let cp = st.tenants.control.as_ref().unwrap();
            let c = cp.conn.lock();
            c.query_row(
                "SELECT g.role FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id WHERE g.tenant_id='acme' AND p.name='alice'",
                [], |r| r.get(0),
            ).unwrap()
        };
        assert_eq!(role, "admin");

        // (d) AUDIT : control_ledger `tenant.create` + event `plume-tenant-admin` DANS la base du tenant.
        assert!(ledger_kinds(&st).contains(&"tenant.create".to_string()), "control_ledger tenant.create");
        {
            let h = st.tenants.handle_for("acme").unwrap();
            let c = h.lock();
            let ev: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE source='plume-tenant-admin'", [], |r| r.get(0)).unwrap();
            assert!(ev >= 1, "event d'audit tenant.create visible dans la base du tenant");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// REFUS d'onboarding : slug invalide (400), `default` réservé (400), doublon (409), NON-super-admin (403),
    /// et un TENANT-ADMIN ne peut JAMAIS créer un tenant (anti-escalade — re-check serveur DANS le handler).
    #[tokio::test]
    async fn mt2c_onboarding_rejections_and_no_tenant_admin_create() {
        let (st, dir) = mk_mode1_state();
        // slug invalide.
        let r = tenant_create(State(st.clone()), Extension(au_super("op")), Json(json!({ "id": "bad slug!" }))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "slug invalide -> 400");
        // `default` réservé.
        let r = tenant_create(State(st.clone()), Extension(au_super("op")), Json(json!({ "id": "default" }))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "default réservé -> 400");
        // NON-super-admin (tenant-admin) -> 403 (le handler re-vérifie is_superadmin, indépendamment du path-guard).
        let r = tenant_create(State(st.clone()), Extension(au_tadmin("alice", "acme")), Json(json!({ "id": "acme2" }))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "tenant-admin NE peut PAS créer un tenant (anti-escalade)");
        assert!(st.tenants.resolve("acme2").is_none(), "aucun tenant créé par le tenant-admin");
        // doublon -> 409.
        let r = tenant_create(State(st.clone()), Extension(au_super("op")), Json(json!({ "id": "acme", "name": "A" }))).await;
        assert_eq!(r.status(), StatusCode::CREATED);
        let r = tenant_create(State(st.clone()), Extension(au_super("op")), Json(json!({ "id": "acme", "name": "A2" }))).await;
        assert_eq!(r.status(), StatusCode::CONFLICT, "id existant -> 409");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SUSPENSION : super-admin suspend/unsuspend (rend le tenant non résoluble puis résoluble), `default`
    /// protégé, tenant-admin refusé (403), audit control_ledger.
    #[tokio::test]
    async fn mt2c_suspend_unsuspend_scoping_and_audit() {
        let (st, dir) = mk_mode1_state();
        assert_eq!(tenant_create(State(st.clone()), Extension(au_super("op")), Json(json!({ "id": "acme", "name": "A" }))).await.status(), StatusCode::CREATED);
        // tenant-admin -> 403 (in-handler is_superadmin check).
        let r = tenant_suspend(State(st.clone()), Extension(au_tadmin("alice", "acme")), Path("acme".into())).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "tenant-admin NE peut PAS suspendre");
        // `default` protégé.
        let r = tenant_suspend(State(st.clone()), Extension(au_super("op")), Path("default".into())).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "default ne peut pas être suspendu");
        // super-admin suspend -> tenant non résoluble (accès coupé).
        let r = tenant_suspend(State(st.clone()), Extension(au_super("op")), Path("acme".into())).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(st.tenants.resolve("acme").is_none(), "tenant suspendu -> non résoluble (accès coupé)");
        // unsuspend -> résoluble à nouveau.
        let r = tenant_unsuspend(State(st.clone()), Extension(au_super("op")), Path("acme".into())).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(st.tenants.resolve("acme").is_some(), "tenant réactivé -> résoluble");
        let k = ledger_kinds(&st);
        assert!(k.contains(&"tenant.suspend".to_string()) && k.contains(&"tenant.unsuspend".to_string()), "audit suspend/unsuspend");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// DESTRUCTION : exige la confirmation forte (confirm==name), `default` INTERDIT, tenant-admin refusé,
    /// destruction crypto effective (fichier + entrée catalogue disparus), audit `tenant.destroy`.
    #[tokio::test]
    async fn mt2c_delete_confirmation_default_protected_and_crypto_destroy() {
        let (st, dir) = mk_mode1_state();
        assert_eq!(tenant_create(State(st.clone()), Extension(au_super("op")), Json(json!({ "id": "acme", "name": "AcmeCorp" }))).await.status(), StatusCode::CREATED);
        let db_path: String = {
            let cp = st.tenants.control.as_ref().unwrap();
            let c = cp.conn.lock();
            c.query_row("SELECT db_path FROM tenant WHERE id='acme'", [], |r| r.get(0)).unwrap()
        };
        assert!(std::path::Path::new(&db_path).exists());
        // tenant-admin -> 403.
        let r = tenant_delete(State(st.clone()), Extension(au_tadmin("alice", "acme")), Path("acme".into()), Json(json!({ "confirm": "AcmeCorp" }))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "tenant-admin NE peut PAS détruire");
        // `default` INTERDIT même pour super-admin.
        let r = tenant_delete(State(st.clone()), Extension(au_super("op")), Path("default".into()), Json(json!({ "confirm": "default" }))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "default interdit");
        // mauvaise confirmation -> 400, tenant INTACT.
        let r = tenant_delete(State(st.clone()), Extension(au_super("op")), Path("acme".into()), Json(json!({ "confirm": "WRONG" }))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "confirmation invalide -> 400");
        assert!(st.tenants.resolve("acme").is_some(), "tenant intact après confirmation erronée");
        // confirmation correcte -> destruction crypto.
        let r = tenant_delete(State(st.clone()), Extension(au_super("op")), Path("acme".into()), Json(json!({ "confirm": "AcmeCorp" }))).await;
        assert_eq!(r.status(), StatusCode::OK, "destruction confirmée -> 200");
        assert!(!std::path::Path::new(&db_path).exists(), "fichier tenant supprimé (destruction crypto)");
        assert!(st.tenants.resolve("acme").is_none(), "entrée catalogue oubliée");
        assert!(ledger_kinds(&st).contains(&"tenant.destroy".to_string()), "audit tenant.destroy");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// GRANTS : super-admin gère n'importe quel tenant ; un tenant-admin UNIQUEMENT le sien (jamais un autre) ;
    /// rôle enum FERMÉ (jamais superadmin) ; anti-lockout du dernier admin ; audit.
    #[tokio::test]
    async fn mt2c_grants_scoping_antiescalade_and_antilockout() {
        let (st, dir) = mk_mode1_state();
        assert_eq!(tenant_create(State(st.clone()), Extension(au_super("op")), Json(json!({ "id": "acme", "name": "A", "admin": "alice" }))).await.status(), StatusCode::CREATED);
        assert_eq!(tenant_create(State(st.clone()), Extension(au_super("op")), Json(json!({ "id": "beta", "name": "B", "admin": "bob" }))).await.status(), StatusCode::CREATED);

        // (1) tenant-admin alice pose un grant editor sur SON tenant acme -> OK.
        let r = grant_set(State(st.clone()), Extension(au_tadmin("alice", "acme")), Path("acme".into()), Json(json!({ "user": "carol", "role": "editor" }))).await;
        assert_eq!(r.status(), StatusCode::OK, "admin de acme pose un grant sur acme");
        assert_eq!(count_grant(&st, "acme", "carol"), 1);

        // (2) ANTI CROSS-TENANT : alice (admin de acme) NE peut PAS granter sur beta -> 403.
        let r = grant_set(State(st.clone()), Extension(au_tadmin("alice", "acme")), Path("beta".into()), Json(json!({ "user": "carol", "role": "admin" }))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "admin de acme NE grante PAS sur beta (anti cross-tenant)");
        assert_eq!(count_grant(&st, "beta", "carol"), 0);

        // (3) ANTI-ESCALADE : rôle 'superadmin' REFUSÉ (enum fermé) même pour le super-admin.
        let r = grant_set(State(st.clone()), Extension(au_super("op")), Path("acme".into()), Json(json!({ "user": "dave", "role": "superadmin" }))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "rôle superadmin refusé (anti-escalade)");
        // is_superadmin de dave inchangé (0) : l'API de grants ne touche JAMAIS le flag plateforme.
        {
            let cp = st.tenants.control.as_ref().unwrap();
            let c = cp.conn.lock();
            let sa: Option<i64> = c.query_row("SELECT is_superadmin FROM platform_user WHERE name='dave'", [], |r| r.get(0)).ok();
            assert!(sa.is_none() || sa == Some(0), "aucune escalade superadmin via l'API de grants");
        }

        // (4) ANTI-LOCKOUT : alice (seule admin de acme) NE peut PAS se rétrograder viewer.
        let r = grant_set(State(st.clone()), Extension(au_tadmin("alice", "acme")), Path("acme".into()), Json(json!({ "user": "alice", "role": "viewer" }))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "dernier admin du tenant -> rétrogradation refusée");
        // ... mais le super-admin, lui, le peut (management-plane).
        let r = grant_set(State(st.clone()), Extension(au_super("op")), Path("acme".into()), Json(json!({ "user": "alice", "role": "viewer" }))).await;
        assert_eq!(r.status(), StatusCode::OK, "le super-admin peut rétrograder (il peut toujours re-granter)");

        // (5) DELETE grant : super-admin retire carol de acme -> OK ; audit présent.
        let r = grant_delete(State(st.clone()), Extension(au_super("op")), Path(("acme".into(), "carol".into()))).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        assert_eq!(count_grant(&st, "acme", "carol"), 0);
        let k = ledger_kinds(&st);
        assert!(k.contains(&"grant.set".to_string()) && k.contains(&"grant.remove".to_string()), "audit grant.set/remove");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ANTI-ESCALADE CROSS-TENANT via le PLANCHER D'IDENTITÉ (régression) : le rôle de gestion `grants` d'un
    /// tenant VISÉ est résolu STRICTEMENT via les grants, JAMAIS via role_floor. Un actor sans grant sur le
    /// tenant (ex. admin LOCAL/config non-superadmin, role_floor="admin") retombe sur "viewer" -> le path-guard
    /// le refuse (403). Sans ce garde, comme tenant_mgmt_gate teste `role=="admin" && tenant==tid` (or `tenant`
    /// EST le tid visé, tautologie), un role_floor="admin" aurait autorisé la gestion des grants de N'IMPORTE
    /// quel tenant (escalade). Le VRAI admin (grant présent) garde bien "admin" sur SON tenant.
    #[tokio::test]
    async fn mt2c_grants_role_never_inherits_identity_floor() {
        let (st, dir) = mk_mode1_state();
        assert_eq!(tenant_create(State(st.clone()), Extension(au_super("op")), Json(json!({ "id": "acme", "name": "A", "admin": "alice" }))).await.status(), StatusCode::CREATED);
        assert_eq!(tenant_create(State(st.clone()), Extension(au_super("op")), Json(json!({ "id": "beta", "name": "B" }))).await.status(), StatusCode::CREATED);

        // (a) VRAI admin de acme (grant présent, NON-superadmin) -> "admin" SUR acme, "viewer" sur beta.
        assert_eq!(mgmt_grants_role(&st, "alice", "acme", None, false), "admin", "grant admin réel -> admin sur SON tenant");
        assert_eq!(mgmt_grants_role(&st, "alice", "beta", None, false), "viewer", "admin de acme = NON-membre de beta -> viewer (jamais role_floor)");

        // (b) admin LOCAL/config INCONNU du control-plane (aucun platform_user, aucun grant, NON-superadmin) :
        // role_floor="admin" côté auth_guard, mais mgmt_grants_role NE le lit PAS -> "viewer" partout.
        assert_eq!(mgmt_grants_role(&st, "localadmin", "acme", None, false), "viewer", "admin local sans grant -> viewer (pas d'héritage du plancher)");
        assert_eq!(mgmt_grants_role(&st, "localadmin", "beta", None, false), "viewer");

        // (c) SUPER-ADMIN non-membre (aucun grant) : repli "admin" -> passe rbac_gate en écriture + le flag
        // is_superadmin autorise la gestion cross-tenant. AUCUNE régression du management-plane.
        assert_eq!(mgmt_grants_role(&st, "op", "acme", None, true), "admin", "super-admin non-membre garde un rôle admin (accès cross-tenant légitime)");

        // (d) le path-guard REFUSE l'admin local sur les grants d'un tenant tiers (rôle résolu=viewer, non-SA)
        // — EXACTEMENT le contexte que produit auth_guard pour ce chemin.
        let role_local = mgmt_grants_role(&st, "localadmin", "beta", None, false);
        assert!(tenant_mgmt_gate("/api/tenants/beta/grants", &role_local, "beta", false).is_err(),
            "admin local (role résolu=viewer, non-superadmin) REFUSÉ sur les grants de beta (anti-escalade cross-tenant)");
        // ... alors que le VRAI admin de acme passe bien sur SON tenant, et le SUPER-ADMIN partout.
        let role_alice = mgmt_grants_role(&st, "alice", "acme", None, false);
        assert!(tenant_mgmt_gate("/api/tenants/acme/grants", &role_alice, "acme", false).is_ok(),
            "admin réel de acme autorisé sur les grants de acme");
        let role_op = mgmt_grants_role(&st, "op", "beta", None, true);
        assert!(tenant_mgmt_gate("/api/tenants/beta/grants", &role_op, "beta", true).is_ok(),
            "super-admin autorisé sur les grants de n'importe quel tenant");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// INVARIANT ABSOLU MODE 0 : les routes de gestion sont INERTES — my-tenants=`default`, liste vide, et
    /// toute mutation -> 404 (aucun control-plane, aucun effet). Comportement STRICTEMENT identique.
    #[tokio::test]
    async fn mt2c_mode0_routes_are_inert() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        assert!(!st.multi_tenant, "mode 0");
        // my-tenants -> [{id:default, role}].
        let v = my_tenants(State(st.clone()), Extension(au_super("op"))).await.0;
        assert_eq!(v, json!([{ "id": "default", "role": "admin" }]), "mode 0 : my-tenants = default");
        // tenants list -> vide.
        let r = tenants_list(State(st.clone()), Extension(au_super("op"))).await;
        assert_eq!(r.status(), StatusCode::OK, "mode 0 : liste inerte (200 vide)");
        // mutations -> 404 (route inerte, aucun effet, control-plane JAMAIS ouvert).
        assert_eq!(tenant_create(State(st.clone()), Extension(au_super("op")), Json(json!({ "id": "x" }))).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(tenant_suspend(State(st.clone()), Extension(au_super("op")), Path("x".into())).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(tenant_delete(State(st.clone()), Extension(au_super("op")), Path("x".into()), Json(json!({ "confirm": "x" }))).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(grant_set(State(st.clone()), Extension(au_super("op")), Path("x".into()), Json(json!({ "user": "u", "role": "admin" }))).await.status(), StatusCode::NOT_FOUND);
        assert!(st.tenants.control.is_none(), "control-plane JAMAIS ouvert en mode 0");
    }

    #[test]
    fn sso_role_accepts_plume_groups_only_legacy_soc_dropped() {
        // défauts canoniques plume-* (comme run()) ; le dual-accept soc-* transitoire a été retiré.
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        // admin : seul le nom canonique plume-* accorde admin.
        assert_eq!(sso_role(&st, "plume-admin"), "admin", "plume-admin -> admin");
        assert_eq!(sso_role(&st, "other|plume-admin|x"), "admin", "plume-admin reconnu dans une liste séparée par |");
        // editor : idem.
        assert_eq!(sso_role(&st, "plume-editor"), "editor", "plume-editor -> editor");
        // superadmin anti-lockout (CONSERVÉ).
        assert_eq!(sso_role(&st, "admins"), "admin", "groupe superadmin -> admin");
        // legacy soc-* N'ACCORDE PLUS de privilège -> viewer (dual-accept retiré).
        assert_eq!(sso_role(&st, "soc-admin"), "viewer", "soc-admin NE donne PLUS admin (dual-accept retiré)");
        assert_eq!(sso_role(&st, "other|soc-admin|x"), "viewer", "soc-admin dans une liste -> viewer (plus de privilège)");
        assert_eq!(sso_role(&st, "soc-editor"), "viewer", "soc-editor NE donne PLUS editor");
        // non privilégié -> viewer (défaut), pas d'élévation.
        assert_eq!(sso_role(&st, "unknown-group|random"), "viewer", "groupe inconnu -> viewer");
        assert_eq!(sso_role(&st, ""), "viewer", "aucun groupe -> viewer");
    }

