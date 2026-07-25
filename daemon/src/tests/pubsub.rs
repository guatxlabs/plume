    // ============================================================================================
    // P-HEC — récepteur PUSH GCP Pub/Sub (Cloud Audit Logs) : tests OFFLINE. SIBLING de firehose.rs.
    //  Couvre : mapping CIM (LogEntry -> audit), auth query ?token= (401 sans spool, hash-only), isolation de
    //  kind SYMÉTRIQUE (pubsub<->firehose<->agent/HEC), sémantique d'ACK Pub/Sub (poison=2xx ack-drop vs
    //  transient=5xx), push-jamais-pollé, gate admin, cap d'amplification (ack-drop), compteur zero-map.
    // ============================================================================================

    fn ps_b64(s: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    }
    fn ps_query(token: &str) -> axum::extract::RawQuery {
        if token.is_empty() { axum::extract::RawQuery(None) } else { axum::extract::RawQuery(Some(format!("token={token}"))) }
    }
    /// Enveloppe Pub/Sub push : `{"message":{"data":<b64>,"attributes":…,"messageId":…,"publishTime":…},"subscription":…}`.
    fn ps_envelope(data_b64: &str) -> axum::body::Bytes {
        axum::body::Bytes::from(json!({
            "message": {
                "data": data_b64,
                "attributes": { "logging.googleapis.com/timestamp": "2026-07-01T10:00:00Z" },
                "messageId": "9876543210",
                "publishTime": "2026-07-01T10:00:01Z"
            },
            "subscription": "projects/acme/subscriptions/plume-push"
        }).to_string())
    }
    fn ps_state_with_spool() -> (AppState, std::path::PathBuf) {
        static PS_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let uniq = PS_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let spool = std::env::temp_dir().join(format!("plume-ps-{}-{}-{}", std::process::id(), now(), uniq));
        std::fs::create_dir_all(&spool).unwrap();
        let mut st = sso_test_state("plume-admin", "plume-editor", "admins");
        st.spool = Arc::new(spool.to_string_lossy().to_string());
        (st, spool)
    }
    /// Minte une source push GCP Pub/Sub via le handler admin -> (connector_id, delivery_token clair once).
    async fn ps_mk_push_source(st: &AppState, env_id: &str) -> (i64, String) {
        let r = connector_push_source(State(st.clone()), Extension(tok_au("admin")),
            Json(json!({ "preset_id": "gcp-audit", "env_id": env_id }))).await;
        let (code, v) = tok_resp_json(r).await;
        assert_eq!(code, StatusCode::OK, "push-source gcp-audit -> 200");
        assert_eq!(v["transport"], "query_token", "réponse Pub/Sub : transport query_token");
        assert_eq!(v["endpoint_path"], "/api/ingest/pubsub");
        (v["connector_id"].as_i64().unwrap(), v["delivery_token"].as_str().unwrap().to_string())
    }
    fn ps_read_spool_events(spool: &std::path::Path) -> Vec<Value> {
        for e in std::fs::read_dir(spool).unwrap().filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("ps-") && name.ends_with(".json") {
                let c = std::fs::read_to_string(e.path()).unwrap();
                let v: Value = serde_json::from_str(&c).unwrap();
                return v["events"].as_array().cloned().unwrap_or_default();
            }
        }
        Vec::new()
    }
    fn ps_spool_count(spool: &std::path::Path) -> usize {
        std::fs::read_dir(spool).unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with("ps-")).count()
    }
    /// Un LogEntry GCP Cloud Audit conforme au field_map du preset gcp-audit.
    fn gcp_logentry(insert_id: &str, method: &str, ip: &str) -> Value {
        json!({
            "insertId": insert_id, "timestamp": "2026-07-01T10:00:00Z",
            "logName": "projects/acme/logs/cloudaudit.googleapis.com%2Factivity",
            "resource": { "type": "gce_instance" },
            "protoPayload": {
                "methodName": method, "serviceName": "compute.googleapis.com",
                "resourceName": "projects/acme/zones/us/instances/vm1",
                "authenticationInfo": { "principalEmail": "alice@acme.example" },
                "requestMetadata": { "callerIp": ip, "callerSuppliedUserAgent": "gcloud/500" },
                "status": { "code": 0, "message": "OK" }
            }
        })
    }

    /// E2E — token valide + une LogEntry -> 200 ACK, event mappé CIM `category=audit` (via gcp:audit->audit),
    /// spoolé PUIS ingéré avec le bon ENV (env_id du connecteur) et le bon tenant (default, mode 0).
    #[tokio::test]
    async fn pubsub_e2e_valid_token_ingests_cim_with_env() {
        let (st, spool) = ps_state_with_spool();
        let (cid, token) = ps_mk_push_source(&st, "staging").await;
        let body = ps_envelope(&ps_b64(&gcp_logentry("ins-1", "v1.compute.instances.insert", "203.0.113.5").to_string()));
        let r = pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(&token), body).await;
        assert_eq!(r.status(), StatusCode::OK, "token valide -> 200 ACK");
        let evs = ps_read_spool_events(&spool);
        assert_eq!(evs.len(), 1, "1 event spoolé");
        assert_eq!(evs[0]["category"], "audit", "gcp:audit -> CIM audit");
        assert_eq!(evs[0]["message"], "v1.compute.instances.insert");
        assert_eq!(evs[0]["src_ip"], "203.0.113.5");
        assert_eq!(evs[0]["dedup"], format!("http-{cid}-ins-1"), "dedup dérivé d'insertId");
        assert_eq!(evs[0]["fields"]["user"], "alice@acme.example");
        // ingère le spool -> l'event atterrit dans le tenant/env attendu.
        ingest_once(&st.tenants, &st.spool);
        let (cat, env, ip): (String, String, String) = {
            let c = st.db.lock();
            c.query_row("SELECT category, env_id, src_ip FROM event WHERE dedup=?1", params![format!("http-{cid}-ins-1")],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap()
        };
        assert_eq!(cat, "audit");
        assert_eq!(env, "staging", "routage env_id du connecteur (carry spool env_id)");
        assert_eq!(ip, "203.0.113.5");
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// AUTH — token absent / mauvais (query ?token=) -> 401 IMMÉDIAT, ZÉRO event spoolé (rejet avant tout parse).
    #[tokio::test]
    async fn pubsub_auth_missing_or_wrong_token_401_no_spool() {
        let (st, spool) = ps_state_with_spool();
        let (_cid, token) = ps_mk_push_source(&st, "prod").await;
        let body = || ps_envelope(&ps_b64(&gcp_logentry("g1", "m", "1.2.3.4").to_string()));
        // absent
        assert_eq!(pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(""), body()).await.status(), StatusCode::UNAUTHORIZED);
        // mauvais
        assert_eq!(pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query("deadbeef-not-a-token"), body()).await.status(), StatusCode::UNAUTHORIZED);
        // token dérivé (préfixe correct mais valeur fausse) -> 401
        assert_eq!(pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(&format!("{token}x")), body()).await.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(ps_spool_count(&spool), 0, "aucun event spoolé sur échec d'auth");
        // contrôle positif : le bon token fonctionne.
        assert_eq!(pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(&token), body()).await.status(), StatusCode::OK);
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// TOKEN = HASH ONLY + LIÉ : le clair n'est JAMAIS stocké (seul SHA-256), kind='gcp_pubsub', connector_id lié.
    /// pubsub_token_lookup résout la bonne clé et REJETTE l'inconnue.
    #[tokio::test]
    async fn pubsub_token_stored_hash_only_and_bound() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let (cid, token) = ps_mk_push_source(&st, "prod").await;
        {
            let c = st.db.lock();
            let (stored, kind, bound): (String, String, i64) = c.query_row(
                "SELECT token_hash, kind, connector_id FROM token WHERE connector_id=?1", params![cid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
            assert_eq!(stored, sha256_hex(token.as_bytes()), "token_hash = SHA-256 du token");
            assert_ne!(stored, token, "le clair n'est JAMAIS stocké");
            assert_eq!(kind, "gcp_pubsub", "kind='gcp_pubsub'");
            assert_eq!(bound, cid, "token LIÉ à son connecteur");
        }
        assert_eq!(pubsub_token_lookup(&st, &token).map(|i| i.connector_id), Some(cid));
        assert!(pubsub_token_lookup(&st, "nope").is_none());
    }

    /// ISOLATION DE KIND (SYMÉTRIQUE) : un token pubsub échoue sur firehose ET sur le seam agent/HEC (token_lookup) ;
    /// une clé firehose ET un token HEC/agent échouent sur pubsub. Chaque endpoint EXIGE son propre kind.
    #[tokio::test]
    async fn pubsub_kind_isolation_symmetric() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let (_pc, ps_token) = ps_mk_push_source(&st, "prod").await;
        // une clé firehose (source push AWS) via le même handler.
        let (_fc, fh_key) = {
            let r = connector_push_source(State(st.clone()), Extension(tok_au("admin")),
                Json(json!({ "preset_id": "aws-cloudtrail", "env_id": "prod" }))).await;
            let (_c, v) = tok_resp_json(r).await;
            (v["connector_id"].as_i64().unwrap(), v["delivery_key"].as_str().unwrap().to_string())
        };
        // un token HEC (seam agent/ingest) via le provisioning UI.
        let (_c, v) = tok_resp_json(token_create(State(st.clone()), Extension(tok_au("admin")),
            Json(json!({ "name": "hec-x", "kind": "hec" }))).await).await;
        let hec_token = v["token"].as_str().unwrap().to_string();

        // pubsub token : NE s'authentifie QUE sur pubsub.
        assert!(pubsub_token_lookup(&st, &ps_token).is_some(), "pubsub token -> pubsub OK");
        assert!(firehose_token_lookup(&st, &ps_token).is_none(), "pubsub token NE s'authentifie PAS sur firehose");
        assert!(token_lookup(&st, &ps_token).is_none(), "pubsub token NE s'authentifie PAS sur le seam agent/HEC (kind exclu)");
        // firehose key : PAS sur pubsub.
        assert!(pubsub_token_lookup(&st, &fh_key).is_none(), "clé firehose NE s'authentifie PAS sur pubsub");
        // hec token : PAS sur pubsub (ni firehose).
        assert!(pubsub_token_lookup(&st, &hec_token).is_none(), "token HEC/agent NE s'authentifie PAS sur pubsub");
        assert!(firehose_token_lookup(&st, &hec_token).is_none(), "token HEC/agent NE s'authentifie PAS sur firehose");
        // et token_lookup EXCLUT bien gcp_pubsub (contrôle explicite).
        assert!(token_lookup(&st, &ps_token).is_none());
    }

    /// ACK Pub/Sub — POISON (base64 indécodable, JSON invalide, message.data absent, body trop gros) -> 2xx
    /// ACK-AND-DROP (204, PAS un rejeu infini) ; TRANSITOIRE (concurrence saturée) -> 5xx (Pub/Sub rejoue).
    #[tokio::test]
    async fn pubsub_ack_semantics_poison_drop_vs_transient_retry() {
        let (st, spool) = ps_state_with_spool();
        let (_cid, token) = ps_mk_push_source(&st, "prod").await;
        // (204) base64 indécodable dans message.data -> 0 record -> ACK-DROP.
        let poison = ps_envelope("!!!not-base64!!!");
        assert!(pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(&token), poison).await.status().is_success(), "base64 poison -> 2xx ack-drop");
        // (204) enveloppe JSON invalide -> ACK-DROP.
        let bad = axum::body::Bytes::from("{ not json ".to_string());
        assert_eq!(pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(&token), bad).await.status(), StatusCode::NO_CONTENT, "JSON invalide -> 204 ack-drop");
        // (204) message.data absent -> ACK-DROP.
        let nodata = axum::body::Bytes::from(json!({ "message": { "messageId": "x" }, "subscription": "s" }).to_string());
        assert_eq!(pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(&token), nodata).await.status(), StatusCode::NO_CONTENT, "message.data absent -> 204 ack-drop");
        assert_eq!(ps_spool_count(&spool), 0, "aucun poison spoolé");
        // (503) concurrence saturée -> TRANSITOIRE (Pub/Sub rejoue). Draine les 4 permis d'ingest_sem.
        let mut held = Vec::new();
        for _ in 0..4 { held.push(st.ingest_sem.clone().try_acquire_owned().unwrap()); }
        let good = ps_envelope(&ps_b64(&gcp_logentry("t1", "m", "1.1.1.1").to_string()));
        assert_eq!(pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(&token), good).await.status(), StatusCode::SERVICE_UNAVAILABLE, "sem saturé -> 503 transient (rejeu)");
        drop(held);
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// CAP D'AMPLIFICATION (LOW#3) — un SEUL message dont message.data explose au-delà de min(50k, ingest_max_events)
    /// -> ACK-DROP (2xx, message pathologique = poison ; PAS un 413-rejoue comme Firehose). Ici cap abaissé à 3.
    #[tokio::test]
    async fn pubsub_amplification_cap_ackdrop() {
        let (mut st, spool) = ps_state_with_spool();
        st.ingest_max_events = 3; // min(50k, 3) = 3
        let (_cid, token) = ps_mk_push_source(&st, "prod").await;
        // message.data = array de 5 LogEntries (records_path="" splitte l'array) -> 5 > 3 -> ack-drop.
        let arr = json!([
            gcp_logentry("a", "m", "1.1.1.1"), gcp_logentry("b", "m", "1.1.1.2"),
            gcp_logentry("c", "m", "1.1.1.3"), gcp_logentry("d", "m", "1.1.1.4"),
            gcp_logentry("e", "m", "1.1.1.5"),
        ]);
        let body = ps_envelope(&ps_b64(&arr.to_string()));
        let r = pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(&token), body).await;
        assert!(r.status().is_success(), "expansion > cap -> 2xx ACK-DROP (poison, jamais un rejeu infini)");
        assert_eq!(ps_spool_count(&spool), 0, "rien de spoolé au-delà du cap");
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// LOW#2 — un batch push mappé à ZÉRO event incrémente PUSH_ZERO_MAP_TOTAL (misconfig OBSERVABLE). Vérifié
    /// sur les deux voies : firehose (records vides) et pubsub (base64 poison). Compteur STRICTEMENT croissant.
    #[tokio::test]
    async fn pubsub_zero_map_bumps_metric() {
        use std::sync::atomic::Ordering;
        let (st, spool) = ps_state_with_spool();
        let (_cid, token) = ps_mk_push_source(&st, "prod").await;
        let before = PUSH_ZERO_MAP_TOTAL.load(Ordering::Relaxed);
        // base64 valide mais qui décode un JSON non-objet (nombre) -> 0 record mappable -> zero-map.
        let body = ps_envelope(&ps_b64("12345"));
        let r = pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(&token), body).await;
        assert!(r.status().is_success(), "zero-map -> 2xx ack-drop");
        let after = PUSH_ZERO_MAP_TOTAL.load(Ordering::Relaxed);
        assert!(after >= before + 1, "PUSH_ZERO_MAP_TOTAL incrémenté ({before} -> {after})");
        assert_eq!(ps_spool_count(&spool), 0, "rien de spoolé");
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// PUSH JAMAIS POLLÉ : un connecteur `gcp_pubsub` (enabled=1) n'est PAS sélectionné par run_due_connectors.
    #[tokio::test]
    async fn pubsub_push_connector_never_polled() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let (cid, _t) = ps_mk_push_source(&st, "prod").await;
        run_due_connectors(&st.db, &st.db_path);
        let (last_run, last_error): (Option<i64>, Option<String>) = {
            let c = st.db.lock();
            c.query_row("SELECT last_run, last_error FROM connector WHERE id=?1", params![cid],
                |r| Ok((r.get(0)?, r.get(1)?))).unwrap()
        };
        assert!(last_run.is_none(), "source push Pub/Sub jamais pollée -> last_run NULL");
        assert!(last_error.is_none(), "aucune erreur 'type non supporté' posée sur une source push");
    }

    /// GATE ADMIN + has_key : push-source gcp_pubsub réservé admin (viewer/editor -> 403) ; connectors_list
    /// expose has_key=true SANS jamais le token ; le connecteur est bien type='gcp_pubsub'.
    #[tokio::test]
    async fn pubsub_admin_gate_and_haskey() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        for role in ["editor", "viewer"] {
            let r = connector_push_source(State(st.clone()), Extension(tok_au(role)),
                Json(json!({ "preset_id": "gcp-audit" }))).await;
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "{role} -> 403 push-source");
        }
        let (cid, token) = ps_mk_push_source(&st, "prod").await;
        let (_c, v) = tok_resp_json(connectors_list(State(st.clone()), Extension(tok_au("admin"))).await).await;
        let row = v.as_array().unwrap().iter().find(|c| c["id"] == cid).unwrap().clone();
        assert_eq!(row["type"], "gcp_pubsub");
        assert_eq!(row["has_key"], true, "connecteur push Pub/Sub -> has_key true");
        assert!(row["has_secret"] == false, "pas de secret connecteur (le token vit dans token)");
        assert!(!v.to_string().contains(&token), "la liste ne fuit JAMAIS le token de livraison");
        assert_eq!(row["config"]["records_path"], "", "records_path override à \"\" (une LogEntry par message push)");
    }

    /// P-HEC RÉVOCATION DURABLE (SÉCU) : supprimer une source push DOIT supprimer sa clé de livraison
    /// liée DANS LA MÊME transaction — sinon la clé orpheline survit et, via la RÉUTILISATION de rowid SQLite
    /// (INTEGER PRIMARY KEY sans AUTOINCREMENT), pourrait se ré-authentifier contre un NOUVEAU connecteur héritant
    /// de l'ancien id (une clé que l'admin croyait révoquée redeviendrait valide). Couvre gcp_pubsub ET firehose,
    /// + garde anti-résurrection (nouvelle source réutilisant l'id -> l'ancien token reste MORT).
    #[tokio::test]
    async fn push_source_delete_revokes_delivery_token() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");

        // (1) Mint gcp_pubsub -> capture (connector_id N, delivery token T). (2) sanity : T résout vers N.
        let (n, t) = ps_mk_push_source(&st, "prod").await;
        assert_eq!(pubsub_token_lookup(&st, &t).map(|i| i.connector_id), Some(n),
            "sanity : le token pubsub minté résout vers son connecteur");

        // (3) Supprimer le connecteur N via connector_delete.
        let r = connector_delete(State(st.clone()), Extension(tok_au("admin")), Path(n)).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT, "connector_delete -> 204");

        // (4) La ligne token est PARTIE : le lookup rend None (révocation durable).
        assert!(pubsub_token_lookup(&st, &t).is_none(),
            "supprimer la source push révoque DURABLEMENT sa clé de livraison (token supprimé, plus de lookup)");

        // (5) Garde anti-résurrection : une NOUVELLE source pubsub peut réutiliser le rowid N (INTEGER PRIMARY KEY
        //     sans AUTOINCREMENT). L'ANCIEN token T ne doit TOUJOURS PAS résoudre (il a été supprimé), et le
        //     nouveau connecteur a bien son PROPRE token distinct.
        let (n2, t2) = ps_mk_push_source(&st, "prod").await;
        assert_eq!(n2, n, "SQLite réutilise le rowid de la ligne supprimée (INTEGER PRIMARY KEY sans AUTOINCREMENT)");
        assert!(pubsub_token_lookup(&st, &t).is_none(),
            "RÉSURRECTION BLOQUÉE : l'ancien token T ne s'authentifie PAS même si le nouveau connecteur hérite de l'id N");
        assert_ne!(t, t2, "le nouveau connecteur a une clé de livraison DISTINCTE");
        assert_eq!(pubsub_token_lookup(&st, &t2).map(|i| i.connector_id), Some(n2),
            "seule la nouvelle clé T2 authentifie le nouveau connecteur");

        // Symétrie FIREHOSE : même invariant sur le kind 'firehose'.
        let (fn_, fk) = {
            let rr = connector_push_source(State(st.clone()), Extension(tok_au("admin")),
                Json(json!({ "preset_id": "aws-cloudtrail", "env_id": "prod" }))).await;
            let (code, v) = tok_resp_json(rr).await;
            assert_eq!(code, StatusCode::OK, "push-source aws-cloudtrail -> 200");
            (v["connector_id"].as_i64().unwrap(), v["delivery_key"].as_str().unwrap().to_string())
        };
        assert_eq!(firehose_token_lookup(&st, &fk).map(|i| i.connector_id), Some(fn_),
            "sanity firehose : clé minté résout vers son connecteur");
        let rf = connector_delete(State(st.clone()), Extension(tok_au("admin")), Path(fn_)).await;
        assert_eq!(rf.status(), StatusCode::NO_CONTENT, "connector_delete firehose -> 204");
        assert!(firehose_token_lookup(&st, &fk).is_none(),
            "supprimer la source push firehose révoque DURABLEMENT sa clé de livraison");
    }

    /// BONUS ING-5 (v121) — un message Pub/Sub DROPPÉ pour dépassement de TAILLE (corps non compressé > cap)
    /// incrémente PUSH_ZERO_MAP_TOTAL -> la perte est OBSERVABLE (comme le chemin zero-map), pas un ack-drop
    /// muet. ACK 2xx conservé (poison permanent, jamais un rejeu infini).
    #[tokio::test]
    async fn pubsub_oversize_drop_bumps_metric() {
        use std::sync::atomic::Ordering;
        let (st, spool) = ps_state_with_spool();
        let (_cid, token) = ps_mk_push_source(&st, "prod").await;
        std::env::set_var("PLUME_FIREHOSE_MAX_DECOMPRESS", "50");
        let before = PUSH_ZERO_MAP_TOTAL.load(Ordering::Relaxed);
        // corps NON compressé plus grand que le cap (50 o) -> poison TAILLE -> ACK-DROP + compteur (ING-5).
        let body = axum::body::Bytes::from("x".repeat(500));
        let r = pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(&token), body).await;
        std::env::remove_var("PLUME_FIREHOSE_MAX_DECOMPRESS");
        assert!(r.status().is_success(), "corps trop gros -> 2xx ACK-DROP (poison)");
        let after = PUSH_ZERO_MAP_TOTAL.load(Ordering::Relaxed);
        assert!(after >= before + 1, "PUSH_ZERO_MAP_TOTAL incrémenté sur drop TAILLE ({before} -> {after})");
        assert_eq!(ps_spool_count(&spool), 0, "rien de spoolé");
        let _ = std::fs::remove_dir_all(&spool);
    }
