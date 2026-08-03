    // ============================================================================================
    // P-HEC — récepteur PUSH AWS Kinesis Firehose (CloudTrail/GuardDuty) : tests OFFLINE.
    //  Couvre : mapping CIM (envelope CloudTrail split + événement GuardDuty), gzip + cap anti-bombe,
    //  auth clé de livraison (hash-only, 403 rapide sans spool), push-jamais-pollé, gate admin, env.
    // ============================================================================================

    fn fh_b64(s: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    }
    fn fh_headers(key: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        if !key.is_empty() {
            h.insert("x-amz-firehose-access-key", axum::http::HeaderValue::from_str(key).unwrap());
        }
        h
    }
    fn fh_gzip(bytes: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }
    fn fh_body(request_id: &str, datas: &[String]) -> axum::body::Bytes {
        let recs: Vec<Value> = datas.iter().map(|d| json!({ "data": d })).collect();
        axum::body::Bytes::from(json!({ "requestId": request_id, "timestamp": 1_700_000_000_000i64, "records": recs }).to_string())
    }
    // Le spool RENDU porte sa propriété avec lui : l'appelant le garde vivant le temps du test, et
    // sa destruction efface le répertoire entier. Rendre un `PathBuf` nu laisserait le répertoire
    // sans propriétaire — la fuite exacte qu'on ferme.
    fn fh_state_with_spool() -> (AppState, crate::tmp_possede::TmpPossede) {
        // suffixe UNIQUE par appel (les tests tournent en PARALLÈLE : pid+secondes seuls collisionnent, et le
        // remove_dir_all d'un test effacerait le spool d'un autre -> read_dir NotFound). Compteur atomique.
        static FH_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let uniq = FH_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let spool = crate::tmp_possede::TmpPossede::neuf(&format!("fh-{uniq}"));
        let mut st = sso_test_state("plume-admin", "plume-editor", "admins");
        st.spool = Arc::new(spool.to_string_lossy().to_string());
        (st, spool)
    }
    /// Minte une source push via le handler admin -> (connector_id, delivery_key clair montré une fois).
    async fn fh_mk_push_source(st: &AppState, preset_id: &str, env_id: &str) -> (i64, String) {
        let r = connector_push_source(State(st.clone()), Extension(tok_au("admin")),
            Json(json!({ "preset_id": preset_id, "env_id": env_id }))).await;
        let (code, v) = tok_resp_json(r).await;
        assert_eq!(code, StatusCode::OK, "push-source create -> 200");
        (v["connector_id"].as_i64().unwrap(), v["delivery_key"].as_str().unwrap().to_string())
    }
    fn fh_read_spool_events(spool: &std::path::Path) -> Vec<Value> {
        for e in std::fs::read_dir(spool).unwrap().filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("fh-") && name.ends_with(".json") {
                let c = std::fs::read_to_string(e.path()).unwrap();
                let v: Value = serde_json::from_str(&c).unwrap();
                return v["events"].as_array().cloned().unwrap_or_default();
            }
        }
        Vec::new()
    }
    fn ct_record(id: &str, name: &str, ip: &str) -> Value {
        json!({
            "eventID": id, "eventTime": "2026-07-01T10:00:00Z", "eventName": name,
            "sourceIPAddress": ip, "eventSource": "signin.amazonaws.com", "awsRegion": "us-east-1",
            "recipientAccountId": "123456789012",
            "userIdentity": { "arn": "arn:aws:iam::123456789012:user/bob", "userName": "bob", "type": "IAMUser" },
            "userAgent": "aws-cli/2", "readOnly": false
        })
    }

    /// MAPPING (pur) — enveloppe CloudTrail `{"Records":[…]}` base64 -> N events CIM `category=audit`, message =
    /// eventName, src_ip promu, dedup dérivé d'eventID. RÉUTILISE firehose_decode_record_data + httppull_map_record.
    #[test]
    fn firehose_cloudtrail_envelope_splits_and_maps_cim() {
        // config push dérivée du preset aws-cloudtrail (field_map transport-indépendant).
        let raw = include_str!("../../../docs/connector-presets/aws-cloudtrail.json");
        let full: Value = serde_json::from_str(raw).unwrap();
        let cfg_json = json!({
            "field_map": full["field_map"], "records_path": "Records",
            "sourcetype": "cloudtrail", "sourcetype_map": { "cloudtrail": "audit" }, "source": "aws-cloudtrail"
        });
        let cfg = HttpPullCfg::from_json(&cfg_json);
        let envelope = json!({ "Records": [ ct_record("e1", "ConsoleLogin", "1.2.3.4"), ct_record("e2", "RunInstances", "5.6.7.8") ] });
        let data = fh_b64(&envelope.to_string());
        let recs = firehose_decode_record_data(&data, cfg.records_path());
        assert_eq!(recs.len(), 2, "enveloppe CloudTrail -> 2 records");
        let evs: Vec<Value> = recs.iter().filter_map(|r| httppull_map_record(r, &cfg, 42)).collect();
        assert_eq!(evs.len(), 2, "2 events mappés");
        assert_eq!(evs[0]["category"], "audit", "cloudtrail -> CIM audit (via sourcetype_map)");
        assert_eq!(evs[0]["message"], "ConsoleLogin");
        assert_eq!(evs[0]["src_ip"], "1.2.3.4");
        assert_eq!(evs[0]["dedup"], "http-42-e1", "dedup dérivé d'eventID (idempotence redelivery)");
        assert_eq!(evs[0]["fields"]["user"], "arn:aws:iam::123456789012:user/bob");
        assert_eq!(evs[1]["message"], "RunInstances");
    }

    /// MAPPING (pur) — événement GuardDuty (records_path="") -> 1 event `category=ids`, severity BORNÉE 0..4.
    #[test]
    fn firehose_guardduty_finding_maps_ids_and_clamps_severity() {
        let raw = include_str!("../../../docs/connector-presets/aws-guardduty.json");
        let full: Value = serde_json::from_str(raw).unwrap();
        let cfg = HttpPullCfg::from_json(&json!({
            "field_map": full["field_map"], "records_path": "",
            "sourcetype": "guardduty", "sourcetype_map": { "guardduty": "ids" }, "source": "aws-guardduty"
        }));
        let finding = json!({
            "Id": "g1", "UpdatedAt": "2026-07-01T10:00:00Z", "Severity": 8.0,
            "Title": "Recon:EC2/PortProbeUnprotectedPort", "Type": "Recon:EC2/PortProbeUnprotectedPort",
            "Description": "probe", "Region": "us-east-1", "AccountId": "123456789012",
            "Service": { "Action": { "ActionType": "NETWORK_CONNECTION",
                "NetworkConnectionAction": { "RemoteIpDetails": { "IpAddressV4": "9.9.9.9" } } }, "Count": 3 },
            "Resource": { "ResourceType": "Instance" }
        });
        let data = fh_b64(&finding.to_string());
        let recs = firehose_decode_record_data(&data, cfg.records_path());
        assert_eq!(recs.len(), 1, "finding unique -> 1 record");
        let ev = httppull_map_record(&recs[0], &cfg, 7).unwrap();
        assert_eq!(ev["category"], "ids", "guardduty -> CIM ids");
        assert_eq!(ev["severity"], 4, "severity 8.0 bornée à 4");
        assert_eq!(ev["src_ip"], "9.9.9.9");
        assert_eq!(ev["message"], "Recon:EC2/PortProbeUnprotectedPort");
    }

    /// ND-JSON dans un seul record `data` (plusieurs events concaténés) -> plusieurs events mappés.
    #[test]
    fn firehose_ndjson_data_expands() {
        let cfg = HttpPullCfg::from_json(&json!({
            "field_map": { "id": "eventID", "message": "eventName", "sourcetype": "=cloudtrail" },
            "records_path": "", "sourcetype_map": { "cloudtrail": "audit" }
        }));
        let ndjson = format!("{}\n{}", ct_record("a", "A", "1.1.1.1"), ct_record("b", "B", "2.2.2.2"));
        let recs = firehose_decode_record_data(&fh_b64(&ndjson), cfg.records_path());
        assert_eq!(recs.len(), 2, "ND-JSON -> 2 records (via hec_parse_body réutilisé)");
    }

    /// E2E — clé valide + enveloppe CloudTrail -> 200 ACK {requestId echo}, events spoolés puis INGÉRÉS avec la
    /// bonne CATÉGORIE et le bon ENV (routage env_id du connecteur). tenant=default (mode 0).
    #[tokio::test]
    async fn firehose_e2e_valid_key_ingests_with_env_and_category() {
        let (st, spool) = fh_state_with_spool();
        let (_cid, key) = fh_mk_push_source(&st, "aws-cloudtrail", "staging").await;
        let envelope = json!({ "Records": [ ct_record("e1", "ConsoleLogin", "1.2.3.4") ] });
        let body = fh_body("req-123", &[fh_b64(&envelope.to_string())]);
        let r = firehose_ingest_post(State(st.clone()), fh_headers(&key), body).await;
        let (code, v) = tok_resp_json(r).await;
        assert_eq!(code, StatusCode::OK, "clé valide -> 200 ACK");
        assert_eq!(v["requestId"], "req-123", "ACK échoie le requestId (contrat Firehose)");
        let evs = fh_read_spool_events(&spool);
        assert_eq!(evs.len(), 1, "1 event spoolé");
        assert_eq!(evs[0]["category"], "audit");
        // ingère le spool -> l'event atterrit dans le tenant/env attendu.
        ingest_once(&st.tenants, &st.spool);
        let (cat, env, ip): (String, String, String) = {
            let c = st.db.lock();
            c.query_row(&format!("SELECT category, env_id, src_ip FROM event WHERE dedup='{}'", ddk(Some(&host_self()), "http-1-e1")), [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap()
        };
        assert_eq!(cat, "audit", "CIM category persistée");
        assert_eq!(env, "staging", "routage env_id du connecteur (carry spool env_id)");
        assert_eq!(ip, "1.2.3.4");
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// AUTH — clé absente / mauvaise -> 403 IMMÉDIAT, ZÉRO event spoolé (rejet avant tout parse/spool).
    #[tokio::test]
    async fn firehose_auth_missing_or_wrong_key_403_no_spool() {
        let (st, spool) = fh_state_with_spool();
        let (_cid, key) = fh_mk_push_source(&st, "aws-guardduty", "prod").await;
        let good_env = json!({ "Id": "g1", "UpdatedAt": "2026-07-01T10:00:00Z", "Severity": 5.0, "Title": "x" });
        let body = || fh_body("r", &[fh_b64(&good_env.to_string())]);
        // absente
        assert_eq!(firehose_ingest_post(State(st.clone()), fh_headers(""), body()).await.status(), StatusCode::FORBIDDEN);
        // mauvaise
        assert_eq!(firehose_ingest_post(State(st.clone()), fh_headers("deadbeef-not-a-key"), body()).await.status(), StatusCode::FORBIDDEN);
        // clé d'un AUTRE format (préfixe correct mais valeur fausse) -> 403
        assert_eq!(firehose_ingest_post(State(st.clone()), fh_headers(&format!("{key}x")), body()).await.status(), StatusCode::FORBIDDEN);
        let n = std::fs::read_dir(&spool).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with("fh-")).count();
        assert_eq!(n, 0, "aucun event spoolé sur échec d'auth");
        // la bonne clé fonctionne (contrôle positif)
        assert_eq!(firehose_ingest_post(State(st.clone()), fh_headers(&key), body()).await.status(), StatusCode::OK);
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// CLÉ = HASH ONLY : le clair n'est JAMAIS stocké (seul SHA-256), la clé est liée au connecteur, et la
    /// vérification RÉUTILISE la primitive token (sha256 sur colonne indexée). firehose_token_lookup résout la
    /// bonne clé et REJETTE l'inconnue.
    #[tokio::test]
    async fn firehose_key_stored_hash_only_and_bound() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let (cid, key) = fh_mk_push_source(&st, "aws-cloudtrail", "prod").await;
        {
            let c = st.db.lock();
            let (stored, kind, bound): (String, String, i64) = c.query_row(
                "SELECT token_hash, kind, connector_id FROM token WHERE connector_id=?1", params![cid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
            assert_eq!(stored, sha256_hex(key.as_bytes()), "token_hash = SHA-256 de la clé");
            assert_ne!(stored, key, "le clair n'est JAMAIS stocké");
            assert_eq!(kind, "firehose", "kind='firehose' (isolé du seam agent/HEC)");
            assert_eq!(bound, cid, "clé LIÉE à son connecteur");
        }
        // firehose_token_lookup : bonne clé -> binding ; inconnue -> None ; la clé N'AUTHENTIFIE PAS le seam agent.
        assert_eq!(firehose_token_lookup(&st, &key).map(|i| i.connector_id), Some(cid));
        assert!(firehose_token_lookup(&st, "nope").is_none());
        assert!(token_lookup(&st, &key).is_none(), "une clé firehose NE s'authentifie PAS sur le seam agent/HEC (kind exclu)");
    }

    /// PUSH JAMAIS POLLÉ : un connecteur `aws_firehose` (enabled=1) n'est PAS sélectionné par run_due_connectors
    /// (filtre par type) -> last_run/last_error restent NULL (aucun poll, aucune erreur « type non supporté »).
    #[tokio::test]
    async fn firehose_push_connector_never_polled() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let (cid, _key) = fh_mk_push_source(&st, "aws-guardduty", "prod").await;
        run_due_connectors(&st.db, &st.db_path);
        let (last_run, last_error): (Option<i64>, Option<String>) = {
            let c = st.db.lock();
            c.query_row("SELECT last_run, last_error FROM connector WHERE id=?1", params![cid],
                |r| Ok((r.get(0)?, r.get(1)?))).unwrap()
        };
        assert!(last_run.is_none(), "source push jamais pollée -> last_run NULL");
        assert!(last_error.is_none(), "aucune erreur 'type non supporté' posée sur une source push");
    }

    /// GATE ADMIN + has_key + non-fuite : push-source réservé admin (viewer/editor -> 403) ; connectors_list
    /// expose has_key=true SANS jamais la clé ; from-preset des presets AWS reste REFUSÉ (voie poll inchangée).
    #[tokio::test]
    async fn firehose_admin_gate_haskey_and_frompreset_unchanged() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        // gate admin : editor/viewer -> 403 (re-check handler, au-delà du path-guard).
        for role in ["editor", "viewer"] {
            let r = connector_push_source(State(st.clone()), Extension(tok_au(role)),
                Json(json!({ "preset_id": "aws-cloudtrail" }))).await;
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "{role} -> 403 push-source");
        }
        // preset non-push -> 400 (okta n'est pas une source push).
        assert_eq!(connector_push_source(State(st.clone()), Extension(tok_au("admin")),
            Json(json!({ "preset_id": "okta" }))).await.status(), StatusCode::BAD_REQUEST);
        // crée une source push -> has_key=true, clé jamais dans la liste.
        let (cid, key) = fh_mk_push_source(&st, "aws-cloudtrail", "prod").await;
        let (_c, v) = tok_resp_json(connectors_list(State(st.clone()), Extension(tok_au("admin"))).await).await;
        let row = v.as_array().unwrap().iter().find(|c| c["id"] == cid).unwrap().clone();
        assert_eq!(row["type"], "aws_firehose");
        assert_eq!(row["has_key"], true, "connecteur push -> has_key true");
        assert!(row["has_secret"] == false, "pas de secret connecteur (la clé vit dans token)");
        assert!(!v.to_string().contains(&key), "la liste ne fuit JAMAIS la clé de livraison");
        // VOIE POLL INCHANGÉE : from-preset d'un preset AWS reste REFUSÉ (instantiable:false).
        assert_eq!(connector_from_preset(State(st.clone()), Extension(tok_au("admin")),
            Json(json!({ "preset_id": "aws-cloudtrail" }))).await.status(), StatusCode::BAD_REQUEST,
            "from-preset AWS toujours refusé (voie poll http_pull inchangée)");
    }

    /// DoS — gzip décodé (200) ; décompressé > cap -> 413 ; trop de records -> 413.
    #[tokio::test]
    async fn firehose_dos_gzip_cap_and_record_cap() {
        let (st, spool) = fh_state_with_spool();
        let (_cid, key) = fh_mk_push_source(&st, "aws-cloudtrail", "prod").await;
        let envelope = json!({ "Records": [ ct_record("e1", "ConsoleLogin", "1.2.3.4") ] });
        let raw = fh_body("rgz", &[fh_b64(&envelope.to_string())]);
        // (200) corps gzippé + Content-Encoding: gzip -> décodé, ingéré.
        let mut h = fh_headers(&key);
        h.insert(axum::http::header::CONTENT_ENCODING, axum::http::HeaderValue::from_static("gzip"));
        let gz = axum::body::Bytes::from(fh_gzip(&raw));
        assert_eq!(firehose_ingest_post(State(st.clone()), h.clone(), gz).await.status(), StatusCode::OK, "gzip décodé -> 200");
        // (413) décompressé au-delà du cap (abaissé à 1 Kio) -> refus décompression.
        std::env::set_var("PLUME_FIREHOSE_MAX_DECOMPRESS", "1024");
        let big = axum::body::Bytes::from(fh_gzip("a".repeat(50_000).as_bytes()));
        assert_eq!(firehose_ingest_post(State(st.clone()), h.clone(), big).await.status(), StatusCode::PAYLOAD_TOO_LARGE, "décompressé > cap -> 413");
        std::env::remove_var("PLUME_FIREHOSE_MAX_DECOMPRESS");
        // (413) trop de records (> FIREHOSE_MAX_RECORDS=10000).
        let many: Vec<String> = (0..10_001).map(|_| fh_b64("{}")).collect();
        assert_eq!(firehose_ingest_post(State(st.clone()), fh_headers(&key), fh_body("rmany", &many)).await.status(),
            StatusCode::PAYLOAD_TOO_LARGE, "records > cap -> 413");
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// CAP D'AMPLIFICATION EVENTS (LOW#3) — UN record dont l'enveloppe CloudTrail explose au-delà de
    /// min(50k, ingest_max_events) matérialise > cap events -> 413 (le stream réduit son buffer et rejoue ;
    /// JAMAIS de troncature muette). Ici ingest_max_events abaissé à 3 : une enveloppe de 5 Records -> 413.
    #[tokio::test]
    async fn firehose_expanded_event_cap_413() {
        let (mut st, spool) = fh_state_with_spool();
        st.ingest_max_events = 3; // min(FIREHOSE_MAX_EVENTS=50k, 3) = 3
        let (_cid, key) = fh_mk_push_source(&st, "aws-cloudtrail", "prod").await;
        // UN seul record Firehose, mais son data = enveloppe {"Records":[5]} -> 5 events > 3 -> 413.
        let envelope = json!({ "Records": [
            ct_record("e1", "A", "1.1.1.1"), ct_record("e2", "B", "1.1.1.2"),
            ct_record("e3", "C", "1.1.1.3"), ct_record("e4", "D", "1.1.1.4"),
            ct_record("e5", "E", "1.1.1.5"),
        ] });
        let body = fh_body("ramp", &[fh_b64(&envelope.to_string())]);
        assert_eq!(firehose_ingest_post(State(st.clone()), fh_headers(&key), body).await.status(),
            StatusCode::PAYLOAD_TOO_LARGE, "events matérialisés > min(50k,ingest_max_events) -> 413");
        let n = std::fs::read_dir(&spool).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with("fh-")).count();
        assert_eq!(n, 0, "rien de spoolé au-delà du cap");
        let _ = std::fs::remove_dir_all(&spool);
    }
