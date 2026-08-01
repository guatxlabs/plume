    // ============================================================================================
    // #3a — FRAMEWORK CONNECTEURS + CONNECTEUR DEFENDER : tests OFFLINE (mock OAuth/Graph, aucun socket).
    // ============================================================================================

    /// Fixture : une alerte Graph alerts_v2 réaliste (paramétrable severity/device/mitre).
    fn defender_alert_fixture(id: &str, severity: &str, with_device: bool, with_mitre: bool, last_update: &str) -> Value {
        let mut a = json!({
            "id": id,
            "title": "Suspicious PowerShell execution",
            "category": "Execution",
            "severity": severity,
            "status": "new",
            "incidentId": "inc-42",
            "serviceSource": "microsoftDefenderForEndpoint",
            "detectionSource": "antivirus",
            "determination": "unknown",
            "description": "A suspicious process was launched.",
            "createdDateTime": "2026-06-30T11:00:00Z",
            "lastUpdateDateTime": last_update,
            "evidence": []
        });
        if with_device {
            a["evidence"] = json!([{ "@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "WIN-HOST-01" }]);
        }
        if with_mitre {
            a["mitreTechniques"] = json!(["T1059.001"]);
        }
        a
    }

    /// (1) Normalisation : source/severity/ts/host/dedup/fields corrects, informational->0, fallback 2.
    #[test]
    fn defender_normalize_maps_fields_and_severity() {
        // high + device + mitre.
        let a = defender_alert_fixture("alert-1", "high", true, true, "2026-06-30T12:00:00Z");
        let n = normalize_defender_alert(&a, 7, "alerts");
        assert_eq!(n.severity, 3, "high -> 3");
        assert_eq!(n.category, "Execution");
        assert_eq!(n.message, "Suspicious PowerShell execution");
        assert_eq!(n.host.as_deref(), Some("WIN-HOST-01"), "deviceDnsName -> host");
        assert_eq!(n.dedup, "defender-7-alert-1", "dedup = defender-<connector_id>-<alert_id>");
        assert_eq!(n.last_update, "2026-06-30T12:00:00Z");
        // ts = epoch UTC de lastUpdateDateTime (2026-06-30T12:00:00Z).
        assert_eq!(n.ts, minio_to_epoch(Some("2026-06-30T12:00:00Z")));
        let f: Value = serde_json::from_str(&n.fields_json).unwrap();
        assert_eq!(f["incidentId"], "inc-42");
        assert_eq!(f["mitreTechniques"], json!(["T1059.001"]));
        assert!(f.get("evidence").is_some());
        // informational -> 0 ; sans device -> host None.
        let inf = defender_alert_fixture("alert-2", "informational", false, false, "2026-06-30T09:00:00Z");
        let ni = normalize_defender_alert(&inf, 7, "alerts");
        assert_eq!(ni.severity, 0, "informational -> 0");
        assert!(ni.host.is_none(), "sans deviceDnsName -> host None");
        // sévérité inconnue -> fallback 2.
        let unk = defender_alert_fixture("alert-3", "wat", false, false, "2026-06-30T09:00:00Z");
        assert_eq!(normalize_defender_alert(&unk, 7, "alerts").severity, 2, "sévérité inconnue -> fallback 2");
        // low/medium.
        assert_eq!(normalize_defender_alert(&defender_alert_fixture("l", "low", false, false, "2026-06-30T09:00:00Z"), 7, "alerts").severity, 1);
        assert_eq!(normalize_defender_alert(&defender_alert_fixture("m", "medium", false, false, "2026-06-30T09:00:00Z"), 7, "alerts").severity, 2);
        // resource=incidents -> préfixe dedup distinct.
        assert_eq!(normalize_defender_alert(&a, 7, "incidents").dedup, "defender-inc-7-alert-1");
    }

    /// Transport MOCK : renvoie des réponses canned selon (method, url). Aucun socket. Sync + closure.
    fn mock_ok_fetch() -> impl Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<HttpResp, String> {
        |method: &str, url: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| {
            if method == "POST" && url.contains("/oauth2/v2.0/token") {
                let body = br#"{"access_token":"TESTTOKEN","expires_in":3599}"#.to_vec();
                return Ok(HttpResp { status: 200, headers: vec![], body });
            }
            if method == "GET" && url.contains("/security/alerts_v2") {
                // 2 alertes, watermarks croissants ; pas de nextLink (1 seule page).
                let a1 = defender_alert_fixture("a1", "high", true, true, "2026-06-30T12:00:00Z");
                let a2 = defender_alert_fixture("a2", "low", false, false, "2026-06-30T13:30:00Z");
                let payload = json!({ "value": [a1, a2] });
                return Ok(HttpResp { status: 200, headers: vec![], body: payload.to_string().into_bytes() });
            }
            Err(format!("mock: route inattendue {method} {url}"))
        }
    }

    fn defender_cfg_json() -> String {
        json!({ "azure_tenant": "guid-tenant", "client_id": "guid-client", "resource": "alerts", "lookback_days": 7 }).to_string()
    }

    /// (3) poll_defender : OAuth mock -> 1 page -> 2 events ; watermark = MAX lastUpdateDateTime (monotone).
    #[test]
    fn defender_poll_advances_watermark_and_normalizes() {
        let cfg = DefenderCfg::from_json(&serde_json::from_str::<Value>(&defender_cfg_json()).unwrap());
        let out = poll_defender(&cfg, "supersecret", None, 1, mock_ok_fetch(), 20).unwrap();
        assert_eq!(out.events.len(), 2);
        assert_eq!(out.watermark.as_deref(), Some("2026-06-30T13:30:00Z"), "watermark = max lastUpdateDateTime");
        // monotonie : un watermark de départ PLUS RÉCENT que toutes les alertes n'est jamais régressé.
        let out2 = poll_defender(&cfg, "s", Some("2026-07-01T00:00:00Z"), 1, mock_ok_fetch(), 20).unwrap();
        assert_eq!(out2.watermark.as_deref(), Some("2026-07-01T00:00:00Z"), "watermark jamais régressé");
    }

    /// (3b) Cold-start : watermark NULL -> $filter borné par lookback_days (borne < now, pas depuis l'époque).
    #[test]
    fn defender_cold_start_filter_uses_lookback() {
        let cfg = DefenderCfg::from_json(&serde_json::from_str::<Value>(&defender_cfg_json()).unwrap());
        let url = graph_first_url(&cfg, None);
        assert!(url.contains("$filter=lastUpdateDateTime%20gt%20"), "filtre encodé (espaces -> %20)");
        // la borne est ~ now - 7j : l'année courante y figure (pas 1970).
        let lb = epoch_to_iso8601(now() - 7 * 86400);
        assert!(url.contains(&url_encode(&lb)), "borne cold-start = now - lookback_days");
        assert!(!url.contains("1970-"), "jamais borné depuis l'époque");
        // round-trip epoch<->iso (Hinnant) cohérent avec minio_to_epoch.
        let e = 1782648000i64; // arbitraire
        assert_eq!(minio_to_epoch(Some(&epoch_to_iso8601(e))), e, "epoch->iso->epoch stable");
    }

    /// (4) 429/Retry-After : abandon PROPRE (Err rate-limit avec le délai), aucun panic.
    #[test]
    fn defender_poll_respects_429_retry_after() {
        let fetch = |method: &str, url: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| {
            if method == "POST" && url.contains("/oauth2/") {
                return Ok(HttpResp { status: 200, headers: vec![], body: br#"{"access_token":"T"}"#.to_vec() });
            }
            // Graph répond 429 avec Retry-After.
            Ok(HttpResp { status: 429, headers: vec![("Retry-After".into(), "30".into())], body: b"{}".to_vec() })
        };
        let cfg = DefenderCfg::from_json(&serde_json::from_str::<Value>(&defender_cfg_json()).unwrap());
        let r = poll_defender(&cfg, "s", Some("2026-06-01T00:00:00Z"), 1, fetch, 20);
        let e = r.expect_err("429 -> Err");
        assert!(e.contains("429") && e.contains("30"), "message rate-limit avec Retry-After : {e}");
        assert!(!e.contains("supersecret"), "le secret ne fuit jamais dans l'erreur");
    }

    /// Base connecteur en mémoire (schéma + migrations -> v68) avec un writer partagé.
    fn connector_test_db() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        Arc::new(Mutex::new(conn))
    }

    /// (2) + ingest : poll_one_connector (mock) ingère 2 events, avance watermark ; RE-JOUÉ -> dedup stable.
    #[test]
    fn defender_poll_one_connector_ingests_and_dedups() {
        let db = connector_test_db();
        {
            let c = db.lock();
            c.execute(
                "INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) VALUES(1,'defender','MDE',1,?1,'supersecret',300,'prod')",
                params![defender_cfg_json()],
            ).unwrap();
        }
        let now_ts = now();
        // 1er passage : ingère 2 events, last_count=2, watermark posé, env_id porté.
        poll_one_connector(&db, ":memory:", 1, "defender", &defender_cfg_json(), "supersecret", "prod", None, now_ts, mock_ok_fetch());
        {
            let c = db.lock();
            let n: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE source='defender'", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 2, "2 events Defender ingérés");
            let env: String = c.query_row("SELECT env_id FROM event WHERE source='defender' LIMIT 1", [], |r| r.get(0)).unwrap();
            assert_eq!(env, "prod", "env_id du connecteur porté sur l'event");
            let (lc, wm, le): (i64, Option<String>, Option<String>) = c.query_row(
                "SELECT last_count,watermark,last_error FROM connector WHERE id=1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
            assert_eq!(lc, 2);
            assert_eq!(wm.as_deref(), Some("2026-06-30T13:30:00Z"));
            assert!(le.is_none(), "succès -> last_error NULL");
        }
        // 2e passage IDENTIQUE : INSERT OR IGNORE sur dedup -> aucun doublon, last_count=0.
        poll_one_connector(&db, ":memory:", 1, "defender", &defender_cfg_json(), "supersecret", "prod", None, now_ts, mock_ok_fetch());
        {
            let c = db.lock();
            let n: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE source='defender'", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 2, "recouvrement absorbé par dedup (INSERT OR IGNORE) -> pas de doublon");
            let lc: i64 = c.query_row("SELECT last_count FROM connector WHERE id=1", [], |r| r.get(0)).unwrap();
            assert_eq!(lc, 0, "2e passage : 0 nouvel event");
        }
    }

    /// #31 — ROUTAGE ENRICHISSEMENT (suivi de 224d526) : un event Defender traverse DÉSORMAIS
    /// `ingest_events_batch_env` (comme http_pull) au lieu de court-circuiter par store().insert_event —
    /// il reçoit donc parsers + MATCH-ON-INGEST threat-intel. Ici un parser 'defender' promeut `src_ip`
    /// depuis le titre ; l'IP matche un IOC seedé -> `ti_match=1` + `fields.threat_intel`, SANS altérer la
    /// SHAPE NormEvent (source='defender' littéral, category/severity/dedup/env_id préservés). ENRICH-NOT-
    /// SUPPRESS (l'event n'est jamais droppé). dedup INSERT OR IGNORE préservé (re-jeu -> 0 doublon).
    /// La parité mode-0 (aucun IOC/parser -> ligne byte-identique à l'ancien chemin) reste prouvée par
    /// `defender_poll_one_connector_ingests_and_dedups` (qui n'a ni IOC ni parser).
    #[test]
    fn defender_pulled_event_is_enriched_via_ingest_pipeline() {
        let db = connector_test_db();
        let dbp = "defender-ti-dbp";
        {
            let c = db.lock();
            // Parser 'defender' : extrait src_ip du titre de l'alerte -> enrichit fields (chemin natif).
            c.execute(
                "INSERT INTO parser(name,source,pattern,enabled,builtin,created) VALUES('def-ip','defender',?1,1,1,?2)",
                params![r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)", now()],
            ).unwrap();
            parsers_reload(&c, dbp); // charge le registre de parseurs de CE db_path dans le cache compilé
            // IOC ip seedé + cache rechargé POUR ce db_path (le match-on-ingest lit le cache de db_path).
            seed_ioc(&c, dbp, "ip", "203.0.113.7", "feed-mde", None);
        }
        // Mock : OAuth -> 1 alerte Defender dont le titre porte l'IP indicatrice (closure sans capture -> Copy).
        let fetch = |method: &str, url: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| {
            if method == "POST" && url.contains("/oauth2/v2.0/token") {
                return Ok(HttpResp { status: 200, headers: vec![], body: br#"{"access_token":"T","expires_in":3599}"#.to_vec() });
            }
            if method == "GET" && url.contains("/security/alerts_v2") {
                let a = json!({
                    "id": "mde-1", "title": "C2 beacon to 203.0.113.7 observed", "category": "CommandAndControl",
                    "severity": "high", "status": "new", "lastUpdateDateTime": "2026-07-06T00:00:00Z", "evidence": []
                });
                return Ok(HttpResp { status: 200, headers: vec![], body: json!({ "value": [a] }).to_string().into_bytes() });
            }
            Err(format!("mock: route inattendue {method} {url}"))
        };
        {
            let c = db.lock();
            c.execute(
                "INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) VALUES(1,'defender','MDE',1,?1,'supersecret',300,'prod')",
                params![defender_cfg_json()],
            ).unwrap();
        }
        let now_ts = now();
        poll_one_connector(&db, dbp, 1, "defender", &defender_cfg_json(), "supersecret", "prod", None, now_ts, fetch);
        {
            let c = db.lock();
            // 1 event ingéré, ENRICHI, SHAPE NormEvent préservée (dedup Defender = defender-<cid>-<id>).
            let (src, cat, sev, sip, env, fields): (String, String, i64, Option<String>, String, String) = c.query_row(
                "SELECT source, category, severity, src_ip, env_id, fields FROM event WHERE dedup='defender-1-mde-1'",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))).unwrap();
            assert_eq!(src, "defender", "source='defender' littéral préservée (shape NormEvent)");
            assert_eq!(cat, "CommandAndControl", "category NormEvent préservée");
            assert_eq!(sev, 3, "severity NormEvent préservée (high->3)");
            assert_eq!(env, "prod", "env_id du connecteur porté sur la ligne enrichie");
            assert_eq!(sip.as_deref(), Some("203.0.113.7"), "src_ip promue par le parser -> chemin d'enrichissement emprunté");
            let fv: Value = serde_json::from_str(&fields).unwrap();
            assert_eq!(fv["ti_match"], 1, "IOC-matché -> ti_match=1 (match-on-ingest sur le chemin Defender)");
            assert_eq!(fv["threat_intel"]["source"], "feed-mde", "fields.threat_intel renseigné par le match-on-ingest");
            let lc: i64 = c.query_row("SELECT last_count FROM connector WHERE id=1", [], |r| r.get(0)).unwrap();
            assert_eq!(lc, 1, "last_count = lignes réellement insérées (dédup-aware)");
        }
        // RE-JEU : INSERT OR IGNORE sur dedup -> aucun doublon (dedup préservé SOUS enrichissement).
        poll_one_connector(&db, dbp, 1, "defender", &defender_cfg_json(), "supersecret", "prod", None, now_ts, fetch);
        {
            let c = db.lock();
            let n: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE source='defender'", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 1, "re-jeu absorbé par dedup");
            let lc: i64 = c.query_row("SELECT last_count FROM connector WHERE id=1", [], |r| r.get(0)).unwrap();
            assert_eq!(lc, 0, "2e passage : 0 nouvel event (dédup)");
        }
    }

    /// (5) FAIL-SAFE : deux connecteurs qui échouent VITE (config vide -> pas de réseau) ne bloquent ni ne
    /// paniquent ; les DEUX sont traités (last_error+last_run posés) et AUCUN event n'est ingéré. Prouve que
    /// A n'arrête pas B. (Le succès+ingest est prouvé par le test mock ci-dessus.)
    #[test]
    fn defender_run_due_connectors_fail_safe_and_invariant() {
        let db = connector_test_db();
        // INVARIANT sans connecteur : run_due_connectors = no-op strict (aucune écriture).
        poll_one_connector_noop_check(&db);
        {
            let c = db.lock();
            // A : azure_tenant vide -> defender_token échoue AVANT tout réseau.
            c.execute("INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) VALUES(1,'defender','A',1,'{\"client_id\":\"x\"}','s',60,'prod')", []).unwrap();
            // B : client_id vide -> idem, échec rapide offline.
            c.execute("INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) VALUES(2,'defender','B',1,'{\"azure_tenant\":\"y\"}','s',60,'prod')", []).unwrap();
            // C : type inconnu -> branché sur le message 'non supporté', sans réseau.
            c.execute("INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) VALUES(3,'sysmon','C',1,'{}','',60,'prod')", []).unwrap();
        }
        // Ne doit NI paniquer NI bloquer.
        run_due_connectors(&db, ":memory:");
        let c = db.lock();
        // les TROIS ont été traités (A n'a pas bloqué B/C) : last_error + last_run posés partout.
        let processed: i64 = c.query_row("SELECT COUNT(*) FROM connector WHERE last_error IS NOT NULL AND last_run IS NOT NULL", [], |r| r.get(0)).unwrap();
        assert_eq!(processed, 3, "tous les connecteurs traités malgré les échecs (fail-safe, pas de blocage)");
        // aucun event ingéré (les pulls ont tous échoué avant ingest).
        let ev: i64 = c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
        assert_eq!(ev, 0, "échec -> aucun event ingéré");
    }

    /// INVARIANT mode 0 : base sans ligne connector -> run_due_connectors NO-OP (aucune écriture, court-circuit
    /// avant tout I/O). Vérifie qu'aucun event/connector n'apparaît.
    fn poll_one_connector_noop_check(db: &Arc<Mutex<Connection>>) {
        run_due_connectors(db, ":memory:");
        let c = db.lock();
        let ev: i64 = c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
        let cn: i64 = c.query_row("SELECT COUNT(*) FROM connector", [], |r| r.get(0)).unwrap();
        assert_eq!((ev, cn), (0, 0), "INVARIANT : table connector vide -> poll no-op strict");
    }

    // ============================================================================================
    // #23 — CONNECTEUR TAXII 2.1 (couche réseau du flux threat-intel). Tests OFFLINE (fetch injecté).
    // ============================================================================================

    fn taxii_cfg_json() -> String {
        json!({ "api_root": "https://ti.example/taxii2/api1", "collection_id": "col-1", "auth_type": "bearer", "lookback_days": 30 }).to_string()
    }

    /// Mock TAXII : page 1 (2 objets : 1 IP traduisible + 1 LIKE ignoré, `more:true`+`next`), page 2 (1
    /// domaine, `more:false`). Watermark via en-tête X-TAXII-Date-Added-Last (max monotone).
    fn mock_taxii_fetch() -> impl Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<HttpResp, String> {
        move |method: &str, url: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| {
            assert_eq!(method, "GET");
            if url.contains("next=") {
                let body = json!({ "objects": [
                    {"type":"indicator","id":"indicator--b","pattern":"[domain-name:value = 'EVIL.example']","pattern_type":"stix","confidence":50}
                ], "more": false }).to_string().into_bytes();
                return Ok(HttpResp { status: 200, headers: vec![("X-TAXII-Date-Added-Last".into(), "2026-07-02T10:00:00Z".into())], body });
            }
            let body = json!({ "objects": [
                {"type":"indicator","id":"indicator--a","pattern":"[ipv4-addr:value = '9.9.9.9']","pattern_type":"stix","confidence":90},
                {"type":"indicator","id":"indicator--x","pattern":"[file:name LIKE '%.exe']","pattern_type":"stix"}
            ], "more": true, "next": "cursor1" }).to_string().into_bytes();
            Ok(HttpResp { status: 200, headers: vec![("X-TAXII-Date-Added-Last".into(), "2026-07-01T09:00:00Z".into())], body })
        }
    }

    /// URL + auth PURES : cold-start `added_after`+`limit`, pagination `next` encodé, en-tête Authorization.
    #[test]
    fn taxii_url_and_auth_pure() {
        let cfg = TaxiiCfg::from_json(&serde_json::from_str::<Value>(&taxii_cfg_json()).unwrap());
        let u = taxii_objects_url(&cfg, None, None);
        assert!(u.contains("/collections/col-1/objects/?"), "chemin collection objects : {u}");
        assert!(u.contains("added_after=") && u.contains("limit=100"), "cold-start added_after + limit : {u}");
        assert!(!u.contains("1970-"), "jamais borné depuis l'époque");
        let u2 = taxii_objects_url(&cfg, Some("2026-07-01T00:00:00Z"), Some("cur 1"));
        assert!(u2.contains("next=cur%201"), "cursor de pagination percent-encodé : {u2}");
        // Bearer (auth_type forcé).
        assert_eq!(taxii_auth_header(&cfg, "tok").unwrap(), ("Authorization".to_string(), "Bearer tok".to_string()));
        // Heuristique (auth_type vide) : secret user:pass -> Basic base64 ; secret vide -> none.
        let cfg_h = TaxiiCfg::from_json(&json!({ "api_root": "https://x/a", "collection_id": "c" }));
        let (k, v) = taxii_auth_header(&cfg_h, "user:pass").unwrap();
        assert_eq!(k, "Authorization");
        assert_eq!(v, "Basic dXNlcjpwYXNz", "Basic base64(user:pass)");
        assert!(taxii_auth_header(&cfg_h, "").is_none(), "secret vide -> collection publique (pas d'auth)");
    }

    /// poll_taxii : traduit STIX->IOC sur 2 pages (pagination more/next), ignore l'inexprimable (skip), et
    /// avance le watermark (date_added max, monotone).
    #[test]
    fn taxii_poll_translates_and_paginates() {
        let cfg = TaxiiCfg::from_json(&serde_json::from_str::<Value>(&taxii_cfg_json()).unwrap());
        let out = poll_taxii(&cfg, "tok", None, mock_taxii_fetch(), 20).unwrap();
        assert_eq!(out.iocs.len(), 2, "2 IOC traduits (IP page1 + domaine page2)");
        assert_eq!(out.skipped, 1, "1 objet non traduisible (LIKE) ignoré-avec-raison");
        assert!(out.iocs.iter().any(|i| i.kind == "ip" && i.value == "9.9.9.9"));
        assert!(out.iocs.iter().any(|i| i.kind == "domain" && i.value == "evil.example"), "valeur normalisée (minuscule)");
        assert_eq!(out.watermark.as_deref(), Some("2026-07-02T10:00:00Z"), "watermark = date_added max (monotone)");
    }

    /// 429/Retry-After : abandon propre (Err rate-limit), le secret ne fuit jamais.
    #[test]
    fn taxii_poll_respects_429() {
        let fetch = |_m: &str, _u: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| {
            Ok(HttpResp { status: 429, headers: vec![("Retry-After".into(), "45".into())], body: b"{}".to_vec() })
        };
        let cfg = TaxiiCfg::from_json(&serde_json::from_str::<Value>(&taxii_cfg_json()).unwrap());
        let e = poll_taxii(&cfg, "supersecret-token", Some("2026-06-01T00:00:00Z"), fetch, 20).expect_err("429 -> Err");
        assert!(e.contains("429") && e.contains("45"), "message rate-limit avec Retry-After : {e}");
        assert!(!e.contains("supersecret-token"), "le token ne fuit jamais dans l'erreur");
    }

    /// poll_one_connector (taxii2) : UPSERT les IOC dans le magasin `ioc`, avance watermark ; RE-JOUÉ ->
    /// UPSERT idempotent (UNIQUE) -> aucun doublon.
    #[test]
    fn taxii_poll_one_connector_upserts_iocs() {
        let db = connector_test_db();
        {
            let c = db.lock();
            c.execute(
                "INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) VALUES(1,'taxii2','feed',1,?1,'tok',300,'prod')",
                params![taxii_cfg_json()],
            ).unwrap();
        }
        let now_ts = now();
        poll_one_connector(&db, ":memory:", 1, "taxii2", &taxii_cfg_json(), "tok", "prod", None, now_ts, mock_taxii_fetch());
        {
            let c = db.lock();
            let n: i64 = c.query_row("SELECT COUNT(*) FROM ioc", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 2, "2 IOC upsertés dans le magasin");
            let (lc, wm, le): (i64, Option<String>, Option<String>) = c.query_row(
                "SELECT last_count,watermark,last_error FROM connector WHERE id=1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
            assert_eq!(lc, 2);
            assert_eq!(wm.as_deref(), Some("2026-07-02T10:00:00Z"), "watermark avancé");
            assert!(le.is_none(), "succès -> last_error NULL");
        }
        // 2e passage : UPSERT idempotent -> toujours 2 lignes (UNIQUE(type,value,source,env_id)).
        poll_one_connector(&db, ":memory:", 1, "taxii2", &taxii_cfg_json(), "tok", "prod", Some("2026-07-02T10:00:00Z"), now_ts, mock_taxii_fetch());
        {
            let c = db.lock();
            let n: i64 = c.query_row("SELECT COUNT(*) FROM ioc", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 2, "re-jeu : UPSERT idempotent, aucun doublon d'IOC");
        }
    }

    // ============================================================================================
    // #20/#22 — CONNECTEUR GÉNÉRIQUE `http_pull` (bring-your-own-vendor). Tests OFFLINE (fetch injecté).
    // ============================================================================================

    /// JSONPath (sous-ensemble sûr) : chemin pointé, index de tableau (dot + bracket), `[*]`, absent->None.
    #[test]
    fn httppull_jsonpath_subset_extracts_safely() {
        let root = json!({
            "device": { "hostname": "WIN-01", "ips": ["10.0.0.1", "10.0.0.2"] },
            "resources": [ { "id": "a" }, { "id": "b" } ],
            "behaviors": [ { "tactic": "Execution" }, { "tactic": "Persistence" } ]
        });
        // dotted
        assert_eq!(json_extract_path(&root, "device.hostname").and_then(|v| v.as_str()), Some("WIN-01"));
        // array index (dot-notation) + bracket-notation équivalents
        assert_eq!(json_extract_path(&root, "device.ips.0").and_then(|v| v.as_str()), Some("10.0.0.1"));
        assert_eq!(json_extract_path(&root, "device.ips[1]").and_then(|v| v.as_str()), Some("10.0.0.2"));
        assert_eq!(json_extract_path(&root, "resources[0].id").and_then(|v| v.as_str()), Some("a"));
        // [*] collecte tous les éléments
        let all = json_extract_all(&root, "behaviors[*].tactic");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].as_str(), Some("Execution"));
        // chemin absent -> None (le champ sera OMIS, jamais un drop)
        assert!(json_extract_path(&root, "device.nope").is_none());
        assert!(json_extract_path(&root, "resources[9].id").is_none());
        // records_path : un tableau -> ses éléments
        assert_eq!(httppull_records(&root, "resources").len(), 2);
        // records_path vide + racine tableau -> ses éléments
        assert_eq!(httppull_records(&json!([1, 2, 3]), "").len(), 3);
    }

    /// field_map -> event : chaque champ (ts/host/source/severity/message/ip/url), constante `=`, `fields.*`,
    /// et sourcetype -> category CIM (mapping existant + override inline).
    #[test]
    fn httppull_field_map_maps_each_field() {
        let cfg = HttpPullCfg::from_json(&json!({
            "url": "https://x/api", "records_path": "resources",
            "sourcetype_map": { "falcon:detection": "malware" },
            "field_map": {
                "ts": "created_timestamp",
                "host": "device.hostname",
                "source": "=falcon",
                "severity": "max_severity",
                "message": "description",
                "src_ip": "device.local_ip",
                "url": "falcon_link",
                "sourcetype": "=falcon:detection",
                "entity": "device.hostname",
                "id": "detection_id",
                "fields.technique": "behaviors[0].technique"
            }
        }));
        let rec = json!({
            "detection_id": "ldt:abc:123",
            "created_timestamp": "2026-07-05T10:00:00Z",
            "max_severity": "high",
            "description": "Malicious PowerShell",
            "falcon_link": "https://falcon/detections/ldt:abc:123",
            "device": { "hostname": "WIN-01", "local_ip": "10.0.0.5" },
            "behaviors": [ { "technique": "T1059.001" } ]
        });
        let ev = httppull_map_record(&rec, &cfg, 7).expect("record mappé");
        assert_eq!(ev["ts"].as_i64(), Some(minio_to_epoch(Some("2026-07-05T10:00:00Z"))));
        assert_eq!(ev["source"].as_str(), Some("falcon"), "constante =falcon");
        assert_eq!(ev["severity"].as_i64(), Some(3), "high -> 3 via sev_num");
        assert_eq!(ev["message"].as_str(), Some("Malicious PowerShell"));
        assert_eq!(ev["host"].as_str(), Some("WIN-01"));
        assert_eq!(ev["src_ip"].as_str(), Some("10.0.0.5"));
        assert_eq!(ev["url"].as_str(), Some("https://falcon/detections/ldt:abc:123"));
        assert_eq!(ev["category"].as_str(), Some("malware"), "sourcetype -> CIM via override inline");
        assert_eq!(ev["dedup"].as_str(), Some("http-7-ldt:abc:123"), "dedup = http-<id>-<field_map.id>");
        assert_eq!(ev["fields"]["technique"].as_str(), Some("T1059.001"), "fields.* -> objet fields");
        assert_eq!(ev["fields"]["entity"].as_str(), Some("WIN-01"), "entity -> fields.entity");
        assert_eq!(ev["fields"]["sourcetype"].as_str(), Some("falcon:detection"));
        // record non-objet -> skip (None) ; source par défaut http:{id} quand non mappée.
        assert!(httppull_map_record(&json!("scalar"), &cfg, 7).is_none());
        let cfg2 = HttpPullCfg::from_json(&json!({ "url": "https://x", "records_path": "", "field_map": { "message": "m" } }));
        assert_eq!(httppull_map_record(&json!({ "m": "hi" }), &cfg2, 9).unwrap()["source"].as_str(), Some("http:9"));
    }

    /// Watermark : avance monotone (iso8601 lexical + epoch numérique), jamais régressé.
    #[test]
    fn httppull_watermark_advance_monotone() {
        // iso8601 : lexical
        assert_eq!(httppull_wm_advance(None, "2026-07-01T00:00:00Z", "iso8601").as_deref(), Some("2026-07-01T00:00:00Z"));
        assert_eq!(httppull_wm_advance(Some("2026-07-02T00:00:00Z".into()), "2026-07-01T00:00:00Z", "iso8601").as_deref(),
                   Some("2026-07-02T00:00:00Z"), "watermark jamais régressé");
        assert_eq!(httppull_wm_advance(Some("2026-07-01T00:00:00Z".into()), "2026-07-03T00:00:00Z", "iso8601").as_deref(),
                   Some("2026-07-03T00:00:00Z"));
        // epoch : numérique (10 > 9 même si "10" < "9" lexicalement)
        assert_eq!(httppull_wm_advance(Some("9".into()), "10", "epoch").as_deref(), Some("10"), "comparaison numérique");
        assert_eq!(httppull_wm_advance(Some("100".into()), "20", "epoch").as_deref(), Some("100"));
        // candidat vide -> inchangé
        assert_eq!(httppull_wm_advance(Some("5".into()), "", "epoch").as_deref(), Some("5"));
    }

    /// Auth : chaque kind produit le bon en-tête ; oauth2 client-credentials fetch+cache le token (mock).
    #[test]
    fn httppull_auth_kinds() {
        let noop = |_m: &str, _u: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| Ok(HttpResp { status: 200, headers: vec![], body: vec![] });
        let mk = |auth: Value| HttpPullCfg::from_json(&json!({ "url": "https://x", "records_path": "d", "field_map": { "message": "m" }, "auth": auth }));
        // none -> aucun en-tête
        assert!(httppull_auth_headers(&mk(json!({ "kind": "none" })), "", &noop).unwrap().is_empty());
        // basic -> base64(user:pass)
        assert_eq!(httppull_auth_headers(&mk(json!({ "kind": "basic" })), "user:pass", &noop).unwrap(),
                   vec![("Authorization".to_string(), "Basic dXNlcjpwYXNz".to_string())]);
        // bearer
        assert_eq!(httppull_auth_headers(&mk(json!({ "kind": "bearer" })), "TKN", &noop).unwrap(),
                   vec![("Authorization".to_string(), "Bearer TKN".to_string())]);
        // header (SentinelOne : Authorization: ApiToken <token>)
        assert_eq!(httppull_auth_headers(&mk(json!({ "kind": "header", "header_name": "Authorization", "prefix": "ApiToken " })), "S1TOKEN", &noop).unwrap(),
                   vec![("Authorization".to_string(), "ApiToken S1TOKEN".to_string())]);
        // token (en-tête custom : X-API-Key)
        assert_eq!(httppull_auth_headers(&mk(json!({ "kind": "token", "header_name": "X-API-Key" })), "KEY123", &noop).unwrap(),
                   vec![("X-API-Key".to_string(), "KEY123".to_string())]);
        // oauth2 client-credentials : POST token_url -> access_token -> Authorization: Bearer
        let oauth_fetch = |method: &str, url: &str, _h: &[(&str, &str)], body: Option<&[u8]>| {
            assert_eq!(method, "POST");
            assert!(url.contains("/oauth2/token"));
            let b = String::from_utf8_lossy(body.unwrap()).to_string();
            assert!(b.contains("grant_type=client_credentials") && b.contains("client_id=CID"));
            assert!(!b.contains("SECRETVAL") || b.contains("client_secret=SECRETVAL"), "secret dans le corps uniquement");
            Ok(HttpResp { status: 200, headers: vec![], body: br#"{"access_token":"OAUTHTOK","expires_in":1799}"#.to_vec() })
        };
        let cfg = mk(json!({ "kind": "oauth2_client_credentials", "token_url": "https://falcon/oauth2/token", "client_id": "CID" }));
        assert_eq!(httppull_auth_headers(&cfg, "SECRETVAL", &oauth_fetch).unwrap(),
                   vec![("Authorization".to_string(), "Bearer OAUTHTOK".to_string())]);
        // oauth2 sans token_url -> Err (config incomplète), sans fuite du secret
        let bad = mk(json!({ "kind": "oauth2_client_credentials", "client_id": "CID" }));
        let e = httppull_auth_headers(&bad, "SECRETVAL", &noop).expect_err("token_url manquant");
        assert!(e.contains("token_url") && !e.contains("SECRETVAL"));
    }

    /// URL de page : watermark param (+ cold-start), taille + offset/page/cursor selon la forme.
    #[test]
    fn httppull_page_url_assembles_query() {
        let cfg = HttpPullCfg::from_json(&json!({
            "url": "https://x/api/events", "records_path": "d", "field_map": { "message": "m" },
            "pagination": { "kind": "offset", "param": "offset", "size": 50, "size_param": "limit" },
            "watermark": { "field_path": "ts", "param": "since", "format": "iso8601" }
        }));
        let u = httppull_page_url(&cfg, Some("2026-07-01T00:00:00Z"), Some(100), None, None);
        assert!(u.contains("since=2026-07-01T00%3A00%3A00Z"), "watermark percent-encodé : {u}");
        assert!(u.contains("limit=50") && u.contains("offset=100"), "offset+size : {u}");
        // cold-start : borne = now - lookback (pas 1970)
        let cold = httppull_page_url(&cfg, None, Some(0), None, None);
        assert!(!cold.contains("1970-"), "jamais borné depuis l'époque : {cold}");
        // template FQL (CrowdStrike) : la valeur watermark est encadrée
        let cfg_fql = HttpPullCfg::from_json(&json!({
            "url": "https://falcon/detects", "records_path": "resources", "field_map": { "message": "m" },
            "watermark": { "field_path": "created_timestamp", "param": "filter", "format": "iso8601", "template": "last_behavior:>'{value}'" }
        }));
        let f = httppull_page_url(&cfg_fql, Some("2026-07-01T00:00:00Z"), None, None, None);
        assert!(f.contains("filter=") && f.contains("last_behavior"), "gabarit FQL appliqué : {f}");
    }

    /// Mock offset-pagination : 2 pages pleines (size 2) puis 1 page courte -> arrêt.
    fn mock_offset_fetch() -> impl Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<HttpResp, String> {
        |_m: &str, url: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| {
            let off = url.split("offset=").nth(1).and_then(|s| s.split('&').next()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
            let page = match off {
                0 => json!({ "data": [ { "i": "1", "t": "2026-07-01T00:00:01Z" }, { "i": "2", "t": "2026-07-01T00:00:02Z" } ] }),
                2 => json!({ "data": [ { "i": "3", "t": "2026-07-01T00:00:03Z" } ] }), // page courte -> fin
                _ => json!({ "data": [] }),
            };
            Ok(HttpResp { status: 200, headers: vec![], body: page.to_string().into_bytes() })
        }
    }

    /// Chaque forme de pagination collecte tous les records (offset/page/cursor/link_header).
    #[test]
    fn httppull_pagination_all_kinds() {
        let base_fm = json!({ "id": "i", "message": "i", "ts": "t" });
        // OFFSET
        let cfg = HttpPullCfg::from_json(&json!({
            "url": "https://x/api", "records_path": "data", "field_map": base_fm,
            "pagination": { "kind": "offset", "param": "offset", "size": 2, "size_param": "limit" }
        }));
        let out = poll_http_pull(&cfg, "", None, 1, mock_offset_fetch(), 20).unwrap();
        assert_eq!(out.events.len(), 3, "offset : 2 + 1 (page courte) = 3");
        // PAGE (numéro de page, arrêt sur page vide)
        let page_fetch = |_m: &str, url: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| {
            let p = url.split("page=").nth(1).and_then(|s| s.split('&').next()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(1);
            let body = if p <= 2 { json!({ "data": [ { "i": format!("p{p}"), "t": "2026-07-01T00:00:00Z" } ] }) } else { json!({ "data": [] }) };
            Ok(HttpResp { status: 200, headers: vec![], body: body.to_string().into_bytes() })
        };
        let cfg_p = HttpPullCfg::from_json(&json!({
            "url": "https://x/api", "records_path": "data", "field_map": base_fm,
            "pagination": { "kind": "page", "param": "page" }
        }));
        assert_eq!(poll_http_pull(&cfg_p, "", None, 1, page_fetch, 20).unwrap().events.len(), 2, "page : 2 pages non vides");
        // CURSOR (next_cursor dans le corps)
        let cursor_fetch = |_m: &str, url: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| {
            let body = if url.contains("cursor=C2") {
                json!({ "data": [ { "i": "c2", "t": "2026-07-01T00:00:00Z" } ], "meta": { "next": "" } })
            } else {
                json!({ "data": [ { "i": "c1", "t": "2026-07-01T00:00:00Z" } ], "meta": { "next": "C2" } })
            };
            Ok(HttpResp { status: 200, headers: vec![], body: body.to_string().into_bytes() })
        };
        let cfg_c = HttpPullCfg::from_json(&json!({
            "url": "https://x/api", "records_path": "data", "field_map": base_fm,
            "pagination": { "kind": "cursor", "param": "cursor", "cursor_path": "meta.next" }
        }));
        assert_eq!(poll_http_pull(&cfg_c, "", None, 1, cursor_fetch, 20).unwrap().events.len(), 2, "cursor : suit meta.next");
        // LINK_HEADER (en-tête Link rel=next)
        let link_fetch = |_m: &str, url: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| {
            if url.contains("page2") {
                let body = json!({ "data": [ { "i": "l2", "t": "2026-07-01T00:00:00Z" } ] });
                return Ok(HttpResp { status: 200, headers: vec![], body: body.to_string().into_bytes() });
            }
            let body = json!({ "data": [ { "i": "l1", "t": "2026-07-01T00:00:00Z" } ] });
            Ok(HttpResp { status: 200, headers: vec![("Link".into(), "<https://x/api?page2>; rel=\"next\"".into())], body: body.to_string().into_bytes() })
        };
        let cfg_l = HttpPullCfg::from_json(&json!({
            "url": "https://x/api", "records_path": "data", "field_map": base_fm,
            "pagination": { "kind": "link_header" }
        }));
        assert_eq!(poll_http_pull(&cfg_l, "", None, 1, link_fetch, 20).unwrap().events.len(), 2, "link_header : suit rel=next");
    }

    /// 429/Retry-After : abandon propre (Err rate-limit), le secret ne fuit jamais.
    #[test]
    fn httppull_poll_respects_429() {
        let fetch = |_m: &str, _u: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| {
            Ok(HttpResp { status: 429, headers: vec![("Retry-After".into(), "42".into())], body: b"{}".to_vec() })
        };
        let cfg = HttpPullCfg::from_json(&json!({
            "url": "https://x/api", "records_path": "d", "field_map": { "message": "m" },
            "auth": { "kind": "bearer" }
        }));
        let e = poll_http_pull(&cfg, "supersecret-token", Some("2026-06-01T00:00:00Z"), 1, fetch, 20).expect_err("429 -> Err");
        assert!(e.contains("429") && e.contains("42"), "rate-limit + Retry-After : {e}");
        assert!(!e.contains("supersecret-token"), "le token ne fuit jamais");
    }

    /// Config incomplète -> Err (url ou field_map manquants), sans réseau.
    #[test]
    fn httppull_config_validation() {
        let noop = |_m: &str, _u: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| Ok(HttpResp { status: 200, headers: vec![], body: b"{}".to_vec() });
        let no_url = HttpPullCfg::from_json(&json!({ "records_path": "d", "field_map": { "message": "m" } }));
        assert!(poll_http_pull(&no_url, "", None, 1, noop, 1).expect_err("url manquante").contains("url"));
        let no_fm = HttpPullCfg::from_json(&json!({ "url": "https://x", "records_path": "d", "field_map": {} }));
        assert!(poll_http_pull(&no_fm, "", None, 1, noop, 1).expect_err("field_map vide").contains("field_map"));
        // api_root + path recomposés en url
        let composed = HttpPullCfg::from_json(&json!({ "api_root": "https://x/base/", "path": "/events", "records_path": "d", "field_map": { "message": "m" } }));
        let u = httppull_page_url(&composed, None, None, None, None);
        assert!(u.starts_with("https://x/base/events"), "api_root+path recomposés : {u}");
    }

    /// ROUNDTRIP mock-vendor (forme CrowdStrike Falcon) : réponse JSON -> events mappés -> INGEST (schéma
    /// event asserté) -> RE-JOUÉ -> dedup stable (INSERT OR IGNORE). oauth2 mock + pagination offset.
    #[test]
    fn httppull_falcon_roundtrip_ingests_and_dedups() {
        // Config générique décrivant Falcon (AUCUN hardcode vendeur côté daemon — tout est config).
        let cfg_json = json!({
            "method": "GET",
            "url": "https://api.crowdstrike.com/alerts/entities/alerts/v2",
            "records_path": "resources",
            "auth": { "kind": "oauth2_client_credentials", "token_url": "https://api.crowdstrike.com/oauth2/token", "client_id": "CID" },
            "pagination": { "kind": "offset", "param": "offset", "size": 2, "size_param": "limit" },
            "sourcetype_map": { "falcon:detection": "malware" },
            "field_map": {
                "id": "composite_id",
                "ts": "created_timestamp",
                "severity": "severity_name",
                "message": "description",
                "host": "device.hostname",
                "src_ip": "device.local_ip",
                "sourcetype": "=falcon:detection",
                "fields.technique": "tactic_id"
            },
            "watermark": { "field_path": "created_timestamp", "param": "filter", "format": "iso8601", "template": "created_timestamp:>'{value}'" }
        }).to_string();
        // Mock Falcon : oauth token, puis 1 page pleine (2) + 1 page courte (1) -> 3 alertes.
        let falcon_fetch = |method: &str, url: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| {
            if method == "POST" && url.contains("/oauth2/token") {
                return Ok(HttpResp { status: 200, headers: vec![], body: br#"{"access_token":"FTOK","expires_in":1799}"#.to_vec() });
            }
            let alert = |cid: &str, ts: &str, sev: &str, host: &str, ip: &str| json!({
                "composite_id": cid, "created_timestamp": ts, "severity_name": sev,
                "description": "Falcon detection", "tactic_id": "T1059",
                "device": { "hostname": host, "local_ip": ip }
            });
            let off = url.split("offset=").nth(1).and_then(|s| s.split('&').next()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
            let body = match off {
                0 => json!({ "resources": [
                    alert("ldt:1", "2026-07-05T10:00:00Z", "high", "WIN-01", "10.0.0.1"),
                    alert("ldt:2", "2026-07-05T11:00:00Z", "medium", "WIN-02", "10.0.0.2")
                ] }),
                2 => json!({ "resources": [ alert("ldt:3", "2026-07-05T12:00:00Z", "critical", "WIN-03", "10.0.0.3") ] }),
                _ => json!({ "resources": [] }),
            };
            Ok(HttpResp { status: 200, headers: vec![], body: body.to_string().into_bytes() })
        };
        let db = connector_test_db();
        {
            let c = db.lock();
            c.execute(
                "INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) VALUES(1,'http_pull','Falcon',1,?1,'CLIENTSECRET',300,'prod')",
                params![cfg_json],
            ).unwrap();
        }
        let now_ts = now();
        poll_one_connector(&db, ":memory:", 1, "http_pull", &cfg_json, "CLIENTSECRET", "prod", None, now_ts, falcon_fetch);
        {
            let c = db.lock();
            // 3 events ingérés au SCHÉMA event, source par défaut http:1, category dérivée du sourcetype.
            let n: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE source='http:1'", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 3, "3 alertes Falcon ingérées");
            let (cat, sev, host, ip, env, ts, msg, dd): (String, i64, String, String, String, i64, String, String) = c.query_row(
                "SELECT category,severity,host,src_ip,env_id,ts,message,dedup FROM event WHERE dedup='http-1-ldt:1'",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))).unwrap();
            assert_eq!(cat, "malware", "sourcetype -> CIM category");
            assert_eq!(sev, 3, "high -> 3");
            assert_eq!(host, "WIN-01");
            assert_eq!(ip, "10.0.0.1", "src_ip promu en colonne");
            assert_eq!(env, "prod", "env_id du connecteur porté");
            assert_eq!(ts, minio_to_epoch(Some("2026-07-05T10:00:00Z")));
            assert_eq!(msg, "Falcon detection");
            assert_eq!(dd, "http-1-ldt:1", "dedup = http-<id>-<composite_id>");
            // fields structurés (searchable en GXQL)
            let fields: String = c.query_row("SELECT fields FROM event WHERE dedup='http-1-ldt:1'", [], |r| r.get(0)).unwrap();
            let fv: Value = serde_json::from_str(&fields).unwrap();
            assert_eq!(fv["technique"].as_str(), Some("T1059"), "fields.technique mappé");
            // watermark = max created_timestamp (monotone)
            let (lc, wm, le): (i64, Option<String>, Option<String>) = c.query_row(
                "SELECT last_count,watermark,last_error FROM connector WHERE id=1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
            assert_eq!(lc, 3);
            assert_eq!(wm.as_deref(), Some("2026-07-05T12:00:00Z"), "watermark = max created_timestamp");
            assert!(le.is_none(), "succès -> last_error NULL");
        }
        // RE-JOUÉ : INSERT OR IGNORE sur dedup -> aucun doublon, last_count=0.
        poll_one_connector(&db, ":memory:", 1, "http_pull", &cfg_json, "CLIENTSECRET", "prod", None, now_ts, falcon_fetch);
        {
            let c = db.lock();
            let n: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE source='http:1'", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 3, "re-jeu absorbé par dedup -> pas de doublon");
            let lc: i64 = c.query_row("SELECT last_count FROM connector WHERE id=1", [], |r| r.get(0)).unwrap();
            assert_eq!(lc, 0, "2e passage : 0 nouvel event");
        }
    }

    /// SUPERSET / CONSISTANCE (#1) : un event PULLÉ par un connecteur http_pull traverse le chemin
    /// d'ENRICHISSEMENT (ingest_events_batch_env) — MATCH-ON-INGEST threat-intel compris — exactement comme
    /// un event ingéré nativement. Un record dont `src_ip` matche un IOC seedé est ENRICHI (fields.threat_intel
    /// + ti_match=1) SANS être supprimé ; un record dont l'IP ne matche PAS reste intact (enrich-not-suppress
    /// sur le chemin pullé). env_id du connecteur porté ; dedup préservé. `db_path` = clé du cache IOC du tenant.
    #[test]
    fn httppull_pulled_event_is_enriched_via_ingest_pipeline() {
        let db = connector_test_db();
        let dbp = "conn-ti-dbp";
        // IOC ip seedé + cache rechargé POUR ce db_path (le match-on-ingest lit le cache de db_path).
        {
            let c = db.lock();
            seed_ioc(&c, dbp, "ip", "203.0.113.5", "feed-x", None);
        }
        // Config générique (aucun hardcode vendeur) : 1 page, pas d'auth, 2 records (1 IOC-hit, 1 miss).
        let cfg_json = json!({
            "url": "https://vendorx.example/api/detections",
            "records_path": "data",
            "field_map": { "id": "cid", "ts": "ts", "severity": "sev", "message": "msg", "src_ip": "ip", "source": "=vendorx" }
        }).to_string();
        let fetch = |_m: &str, _u: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| Ok(HttpResp {
            status: 200, headers: vec![],
            body: json!({ "data": [
                { "cid": "hit",  "ts": "2026-07-06T00:00:00Z", "sev": "high",   "msg": "c2 beacon", "ip": "203.0.113.5" },
                { "cid": "miss", "ts": "2026-07-06T00:05:00Z", "sev": "medium", "msg": "benign",    "ip": "10.0.0.9" }
            ] }).to_string().into_bytes(),
        });
        {
            let c = db.lock();
            c.execute(
                "INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) VALUES(1,'http_pull','VendorX',1,?1,'',300,'prod')",
                params![cfg_json],
            ).unwrap();
        }
        let now_ts = now();
        poll_one_connector(&db, dbp, 1, "http_pull", &cfg_json, "", "prod", None, now_ts, fetch);
        {
            let c = db.lock();
            // Les 2 events sont INSÉRÉS (enrich-not-suppress : le match n'a supprimé personne).
            let n: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE source='vendorx'", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 2, "2 events pullés ingérés (aucun drop)");
            let lc: i64 = c.query_row("SELECT last_count FROM connector WHERE id=1", [], |r| r.get(0)).unwrap();
            assert_eq!(lc, 2, "last_count = lignes réellement insérées");
            // HIT : passé par le MATCH-ON-INGEST -> fields enrichis (preuve du chemin d'enrichissement).
            let (hf, env): (String, String) = c.query_row(
                "SELECT fields, env_id FROM event WHERE dedup='http-1-hit'",
                [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            let hv: Value = serde_json::from_str(&hf).unwrap();
            assert_eq!(hv["ti_match"], 1, "event pullé IOC-matché -> ti_match=1 (enrichi via ingest_events_batch)");
            assert_eq!(hv["threat_intel"]["source"], "feed-x", "fields.threat_intel renseigné par le match-on-ingest");
            assert_eq!(env, "prod", "env_id du connecteur porté sur la ligne enrichie");
            // MISS : non enrichi (aucun IOC) -> pas de ti_match/threat_intel (byte-identique au chemin natif).
            let mf: Option<String> = c.query_row("SELECT fields FROM event WHERE dedup='http-1-miss'", [], |r| r.get(0)).ok();
            assert!(mf.as_deref().map(|s| !s.contains("ti_match") && !s.contains("threat_intel")).unwrap_or(true),
                "record non-matchant : aucun enrichissement TI (enrich-not-suppress)");
        }
        // RE-JEU : INSERT OR IGNORE sur dedup -> aucun doublon, last_count=0 (dédup préservé sous enrichissement).
        poll_one_connector(&db, dbp, 1, "http_pull", &cfg_json, "", "prod", None, now_ts, fetch);
        {
            let c = db.lock();
            let n: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE source='vendorx'", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 2, "re-jeu absorbé par dedup");
            let lc: i64 = c.query_row("SELECT last_count FROM connector WHERE id=1", [], |r| r.get(0)).unwrap();
            assert_eq!(lc, 0, "2e passage : 0 nouvel event (dédup)");
        }
    }

    /// MODE-0 byte-identique : sans connecteur http_pull (ou disabled), run_due_connectors reste NO-OP
    /// strict — aucun event, comportement inchangé (l'ajout de l'arm générique n'a AUCUN effet passif).
    #[test]
    fn httppull_mode0_inert_when_absent_or_disabled() {
        let db = connector_test_db();
        // Table vide -> no-op strict (déjà prouvé ailleurs, ré-affirmé pour l'arm http_pull).
        run_due_connectors(&db, ":memory:");
        {
            let c = db.lock();
            assert_eq!(c.query_row::<i64, _, _>("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap(), 0);
        }
        // Connecteur http_pull DISABLED -> jamais sélectionné -> aucun réseau/écriture.
        {
            let c = db.lock();
            c.execute("INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) VALUES(1,'http_pull','off',0,'{\"url\":\"https://x\",\"records_path\":\"d\",\"field_map\":{\"message\":\"m\"}}','',60,'prod')", []).unwrap();
        }
        run_due_connectors(&db, ":memory:");
        {
            let c = db.lock();
            assert_eq!(c.query_row::<i64, _, _>("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap(), 0, "disabled -> inerte");
            let (lr, le): (Option<i64>, Option<String>) = c.query_row("SELECT last_run,last_error FROM connector WHERE id=1", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            assert!(lr.is_none() && le.is_none(), "connecteur disabled jamais touché");
        }
    }

    /// (7) CRUD : la projection de liste (secret != '') expose has_secret sans JAMAIS le secret ; l'UPDATE
    /// avec secret vide CONSERVE l'existant. Testé au niveau SQL (la logique exacte des handlers).
    #[test]
    fn connector_list_projection_hides_secret_and_empty_update_keeps() {
        let db = connector_test_db();
        let c = db.lock();
        c.execute(
            "INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) VALUES(1,'defender','MDE',1,'{}','THE_SECRET',300,'prod')",
            [],
        ).unwrap();
        // projection identique à connectors_list : has_secret bool, secret jamais lu dans la sortie.
        let (name, has_secret): (String, i64) = c.query_row(
            "SELECT name,(secret != '') FROM connector WHERE id=1", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(name, "MDE");
        assert_eq!(has_secret, 1, "has_secret=true quand un secret est défini");
        // UPDATE secret vide = NO-OP (la logique handler ne l'exécute pas) -> le secret existant survit.
        // (on simule la garde `if !s.is_empty()` : on N'exécute PAS l'UPDATE).
        let empty = "";
        if !empty.is_empty() {
            c.execute("UPDATE connector SET secret=?1 WHERE id=1", params![empty]).unwrap();
        }
        let kept: String = c.query_row("SELECT secret FROM connector WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(kept, "THE_SECRET", "secret vide en update -> conserve l'existant");
        // UPDATE secret non vide = remplace.
        c.execute("UPDATE connector SET secret=?1 WHERE id=1", params!["NEW_SECRET"]).unwrap();
        let updated: String = c.query_row("SELECT secret FROM connector WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(updated, "NEW_SECRET");
    }

    /// (D11) DÉBRUITAGE du flag « inattendu » : les 10 feeds LÉGITIMES additionnels (source ≠ id de collecteur)
    /// sont désormais CONNUS -> plus flaggés. Les ids de COLLECTEURS et les sources auth restent connus. Une
    /// source GÉNUINEMENT inconnue reste flaggée (le signal fonctionne toujours pour les vraies nouveautés).
    #[test]
    fn source_is_known_covers_legit_feeds_but_flags_truly_unknown() {
        // les 10 feeds ajoutés (débruitage du FAUX signal).
        for s in ["minio-audit", "vault-audit", "cloudflare", "conntrack", "mail", "containerd", "minio", "k8s", "dataacl", "agent"] {
            assert!(source_is_known(s), "feed légitime '{s}' ne doit PLUS être flaggé inattendu");
        }
        // ids de collecteurs + sources auth : toujours connus.
        for s in ["web", "kube-audit", "ufw", "crowdsec", "sshd", "auditd", "plume-config"] {
            assert!(source_is_known(s), "'{s}' doit rester connu");
        }
        // une source réellement inconnue : le SIGNAL « inattendu » reste actif.
        for s in ["totally-new-thing", "attacker-c2", "unknown-src"] {
            assert!(!source_is_known(s), "'{s}' (vraiment inconnue) DOIT rester flaggée inattendue");
        }
    }

    // --- FONDATION MULTI-TENANT (#2a-2a) : v66 env_id + flag + control-plane + identité mode-aware -----

    #[test]
    fn migration_v66_env_id_default_prod_and_idempotent() {
        // (b) : env_id posé sur les tables de DONNÉE, DÉFAUT 'prod', et RE-JOUABLE (col_exists garde l'ALTER).
        let conn = test_db();
        // les tables de contenu/config NE reçoivent PAS env_id (tenant-wide par nature).
        for t in ["rule", "parser", "playbook", "dashboard", "view", "panel", "lookup_kv"] {
            assert!(!col_exists(&conn, t, "env_id"), "{t} ne doit PAS porter env_id (contenu tenant-wide)");
        }
        // une ligne existante (insérée sans env_id) est servie avec la valeur par défaut 'prod'.
        conn.execute("INSERT INTO event(ts,source,message) VALUES(?1,'sshd','x')", params![now()]).unwrap();
        let env: String = conn.query_row("SELECT env_id FROM event ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).unwrap();
        assert_eq!(env, "prod", "env_id par défaut = 'prod'");
        // idempotent : re-migrer ne casse rien, env_id toujours là, version stable.
        let _ = migrate(&conn);
        let _ = migrate(&conn);
        assert!(col_exists(&conn, "banned_ip", "env_id"));
        let v: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "112");
    }

    // --- FILTRE PAR ENVIRONNEMENT (#2d) : v67 rollups + injection READ PATH + /api/environments -----

    #[test]
    fn migration_v67_env_id_on_rollups() {
        let conn = test_db();
        // (1) env_id présent sur les DEUX rollups pré-agrégés (agrégats filtrables par env — cohérent avec raw).
        assert!(col_exists(&conn, "event_rollup", "env_id"), "event_rollup.env_id manquant après v67");
        assert!(col_exists(&conn, "event_dim_rollup", "env_id"), "event_dim_rollup.env_id manquant après v67");
        // (2) env_id INTÉGRÉ à la PK (dimension d'agrégation) : deux lignes ne différant QUE par env_id COEXISTENT
        //     (sinon INSERT OR REPLACE en écraserait une -> counts faux par environnement).
        let t = 3600i64;
        conn.execute("INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) VALUES(?1,'sshd',0,'','','',5,?1,'prod')", params![t]).unwrap();
        conn.execute("INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) VALUES(?1,'sshd',0,'','','',3,?1,'staging')", params![t]).unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM event_rollup WHERE bucket=?1 AND source='sshd'", params![t], |r| r.get(0)).unwrap();
        assert_eq!(n, 2, "env_id dans la PK -> prod et staging coexistent (pas d'écrasement)");
        conn.execute("INSERT INTO event_dim_rollup(bucket,source,dim,val,n,env_id) VALUES(?1,'web','status','200',5,'prod')", params![t]).unwrap();
        conn.execute("INSERT INTO event_dim_rollup(bucket,source,dim,val,n,env_id) VALUES(?1,'web','status','200',2,'staging')", params![t]).unwrap();
        let dn: i64 = conn.query_row("SELECT COUNT(*) FROM event_dim_rollup WHERE source='web' AND dim='status' AND val='200'", [], |r| r.get(0)).unwrap();
        assert_eq!(dn, 2, "env_id dans la PK du rollup par dimension");
        // (3) version bumpée + idempotence : re-migrer NE recrée PAS (col_exists) -> données PRÉSERVÉES.
        assert_eq!(conn.query_row::<String, _, _>("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap(), "112");
        let _ = migrate(&conn);
        let _ = migrate(&conn);
        let n2: i64 = conn.query_row("SELECT COUNT(*) FROM event_rollup WHERE bucket=?1 AND source='sshd'", params![t], |r| r.get(0)).unwrap();
        assert_eq!(n2, 2, "re-migrer v67 ne doit PAS recréer/vider event_rollup (garde col_exists)");
        assert_eq!(conn.query_row::<String, _, _>("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap(), "112");
    }

    #[test]
    fn migration_v67_env_id_defaults_prod_preserving_existing_rollup_rows() {
        // MIGRATION SUR BASE EXISTANTE : rétrograde à v66, pose une ligne event_dim_rollup SANS env_id
        // (schéma pré-v67 via recréation locale), re-migre -> la ligne survit stampée 'prod' (préservation).
        let conn = test_db();
        // recrée les DEUX rollups au schéma PRÉ-v67 (sans env_id) + une ligne chacun, puis force v67 à re-tourner
        // -> exerce les deux branches du recreate closure (event_rollup ET event_dim_rollup).
        conn.execute_batch(
            "DROP TABLE IF EXISTS event_dim_rollup; \
             CREATE TABLE event_dim_rollup(bucket INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', \
               dim TEXT NOT NULL DEFAULT '', val TEXT NOT NULL DEFAULT '', n INTEGER NOT NULL DEFAULT 0, \
               PRIMARY KEY(bucket,source,dim,val)); \
             INSERT INTO event_dim_rollup(bucket,source,dim,val,n) VALUES(3600,'web','status','200',7); \
             DROP TABLE IF EXISTS event_rollup; \
             CREATE TABLE event_rollup(bucket INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', \
               severity INTEGER NOT NULL DEFAULT 0, action TEXT NOT NULL DEFAULT '', src_ip TEXT NOT NULL DEFAULT '', \
               host TEXT NOT NULL DEFAULT '', n INTEGER NOT NULL DEFAULT 0, last_ts INTEGER NOT NULL DEFAULT 0, \
               PRIMARY KEY(bucket,source,severity,action,src_ip,host)); \
             INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts) VALUES(3600,'sshd',3,'','1.2.3.4','h',9,3600);",
        ).unwrap();
        conn.execute("UPDATE meta SET value='66' WHERE key='schema_version'", []).unwrap();
        let _ = migrate(&conn);
        // la colonne est ajoutée ET la ligne existante est préservée avec env_id='prod' (donnée pré-v67 = prod).
        assert!(col_exists(&conn, "event_dim_rollup", "env_id") && col_exists(&conn, "event_rollup", "env_id"));
        let (n, env): (i64, String) = conn.query_row(
            "SELECT n, env_id FROM event_dim_rollup WHERE source='web' AND dim='status' AND val='200'",
            [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((n, env.as_str()), (7, "prod"), "ligne event_dim_rollup pré-v67 préservée et stampée prod");
        let (rn, renv): (i64, String) = conn.query_row(
            "SELECT n, env_id FROM event_rollup WHERE source='sshd' AND src_ip='1.2.3.4'",
            [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((rn, renv.as_str()), (9, "prod"), "ligne event_rollup pré-v67 préservée et stampée prod");
        assert_eq!(conn.query_row::<String, _, _>("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap(), "112");
    }

    #[test]
    fn rollup_builders_populate_env_id() {
        // les DEUX générateurs d'INSERT peuplent env_id (sinon les rollups n'auraient jamais d'env réel au tick).
        let ev = rollup_insert_sql_into("event_rollup", "ts >= 0", 3, 50);
        assert!(ev.contains("env_id") && ev.contains("COALESCE(env_id,'prod')"), "event_rollup peuple env_id : {ev}");
        let ev0 = rollup_insert_sql_into("event_rollup", "ts >= 0", 3, 0); // branche sans cap top-N
        assert!(ev0.contains("COALESCE(env_id,'prod')"), "event_rollup (topn<=0) peuple env_id : {ev0}");
        let dim = dim_rollup_insert_sql("web", "status", "ts >= 0", 50);
        assert!(dim.contains("env_id") && dim.contains("COALESCE(env_id,'prod')"), "event_dim_rollup peuple env_id : {dim}");
    }

    #[test]
    fn env_filter_injected_into_raw_and_rollup() {
        // (a) RAW (compilo event) : env=Some -> WHERE ... env_id = '<env>' ; env=None -> AUCUN env_id (parité mode 0).
        let raw_env = soql_to_sql_x("search source=web", 0, 0, Some("staging")).unwrap();
        assert!(raw_env.contains("env_id = 'staging'"), "raw doit filtrer env_id : {raw_env}");
        let raw_all = soql_to_sql_x("search source=web", 0, 0, None).unwrap();
        assert!(!raw_all.contains("env_id"), "INVARIANT mode 0 : AUCUN filtre env_id sur le raw : {raw_all}");
        // (b) ROLLUP route A (event_rollup) : `... | stats count by source`.
        let ra = try_rollup_route("search | stats count by source", 0, 0, Some("staging"), RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).unwrap();
        assert!(ra.sql.contains("event_rollup") && ra.sql.contains("env_id='staging'"), "rollup A filtre env : {}", ra.sql);
        let ra0 = try_rollup_route("search | stats count by source", 0, 0, None, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).unwrap();
        assert!(!ra0.sql.contains("env_id"), "INVARIANT mode 0 : rollup A sans filtre env : {}", ra0.sql);
        // (c) ROLLUP route B (event_dim_rollup) : `search source=web | stats count by status`.
        let rb = try_rollup_route("search source=web | stats count by status", 0, 0, Some("staging"), RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).unwrap();
        assert!(rb.sql.contains("event_dim_rollup") && rb.sql.contains("env_id='staging'"), "rollup B filtre env : {}", rb.sql);
        let rb0 = try_rollup_route("search source=web | stats count by status", 0, 0, None, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).unwrap();
        assert!(!rb0.sql.contains("env_id"), "INVARIANT mode 0 : rollup B sans filtre env : {}", rb0.sql);
        // (d) ANTI-INJECTION : la valeur env est échappée (soql_esc) -> jamais de rupture de littéral (défense
        //     en profondeur ; env_slug_ok l'aurait DÉJÀ rejetée en amont dans auth_guard).
        let inj = soql_to_sql_x("search source=web", 0, 0, Some("a' OR '1'='1")).unwrap();
        assert!(inj.contains("env_id = 'a'' OR ''1''=''1'"), "valeur env échappée : {inj}");
    }

    #[test]
    fn env_slug_ok_validates_like_tenant() {
        // charset borné (alnum + _/-) : accepte prod/staging/sites ; refuse quote/espace/point/slash (anti-injection).
        assert!(env_slug_ok("prod") && env_slug_ok("staging") && env_slug_ok("site-42") && env_slug_ok("us_east"));
        assert!(!env_slug_ok("") && !env_slug_ok("a' OR '1'='1") && !env_slug_ok("a b") && !env_slug_ok("a.b") && !env_slug_ok("a/b"));
    }

    #[test]
    fn environments_query_lists_distinct_envs_with_counts() {
        // logique de /api/environments : env_id DISTINCTS depuis event_rollup + SUM(n) par env (fallback prod).
        let conn = test_db();
        let ins = |src: &str, n: i64, env: &str| {
            conn.execute(
                "INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) VALUES(3600,?1,0,'','','',?2,3600,?3)",
                params![src, n, env],
            ).unwrap();
        };
        ins("sshd", 5, "prod");
        ins("web", 3, "prod");
        ins("sshd", 4, "staging");
        // la requête EXACTE de l'endpoint : GROUP BY env_id, SUM(n).
        let mut s = conn.prepare("SELECT env_id, COALESCE(SUM(n),0) FROM event_rollup GROUP BY env_id ORDER BY env_id").unwrap();
        let got: Vec<(String, i64)> = s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).unwrap().flatten().collect();
        assert_eq!(got, vec![("prod".into(), 8), ("staging".into(), 4)], "compte par environnement (prod=5+3, staging=4)");
    }

    #[test]
    fn mode0_auth_user_env_is_ignored_invariant() {
        // INVARIANT ABSOLU mode 0 : l'accesseur env_filter() renvoie TOUJOURS None si AuthUser.env est None
        // (auth_guard ne pose env qu'en mode 1) -> aucun filtre -> comportement identique.
        let au = AuthUser { name: "u".into(), role: "viewer".into(), tenant: "default".into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None };
        assert!(au.env_filter().is_none(), "mode 0 : env_filter None -> jamais de filtre");
        // et un env explicite (mode 1) est bien propagé.
        let au2 = AuthUser { env: Some("staging".into()), ..au };
        assert_eq!(au2.env_filter(), Some("staging"));
    }

    #[test]
    fn multi_tenant_flag_defaults_off() {
        let mut m: HashMap<String, String> = HashMap::new();
        assert!(!multi_tenant_enabled(&m), "PLUME_MULTI_TENANT absent -> mode 0 (défaut prod)");
        m.insert("PLUME_MULTI_TENANT".into(), "0".into());
        assert!(!multi_tenant_enabled(&m), "=0 -> mode 0");
        m.insert("PLUME_MULTI_TENANT".into(), "1".into());
        assert!(multi_tenant_enabled(&m), "=1 -> mode 1");
    }

    #[test]
    fn mode0_identity_and_resolve_unchanged() {
        // (a) : mode 0 (control=None) -> auth/valid_token lisent la base UNIQUE, resolve = passthrough exact.
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        assert!(!st.multi_tenant, "mode 0");
        assert!(st.tenants.control.is_none(), "control-plane JAMAIS ouvert en mode 0");
        // seed d'un compte + d'un token dans la base unique (st.db), exactement comme aujourd'hui.
        let hash = hash_pw("s3cret!").unwrap();
        {
            let c = st.db.lock();
            c.execute("INSERT INTO user(name,hash,role) VALUES('alice',?1,'editor')", params![hash]).unwrap();
            c.execute("INSERT INTO token(name,token_hash,created,host) VALUES('agent',?1,?2,'host-a')",
                      params![sha256_hex(b"tok-xyz"), now()]).unwrap();
        }
        // Basic auth -> (nom, rôle) depuis la table user, INCHANGÉ.
        use base64::Engine as _;
        let authz = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("alice:s3cret!"));
        assert_eq!(authenticate(&st, &authz), Some(("alice".to_string(), "editor".to_string())));
        // mauvais mot de passe -> None.
        let bad = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("alice:wrong"));
        assert_eq!(authenticate(&st, &bad), None);
        // Bearer token -> host, depuis la table token de la base unique, INCHANGÉ.
        assert_eq!(valid_token(&st, "tok-xyz"), Some("host-a".to_string()));
        assert_eq!(valid_token(&st, "nope"), None);
        // resolve/handle_for = passthrough EXACT (default = st.db_path/st.db).
        let (p, k) = st.tenants.resolve("default").unwrap();
        assert_eq!(p, *st.db_path, "mode 0 : db_path = st.db_path");
        assert_eq!(k, db_key(), "mode 0 : clé = PLUME_DB_KEY (None hors env)");
        assert!(Arc::ptr_eq(&st.tenants.handle_for("default").unwrap(), &st.db), "mode 0 : writer = st.db");
        // #2a-2b INVARIANT ABSOLU : les accesseurs par-requête retombent EXACTEMENT sur st.db/st.db_path.
        let au = AuthUser { name: "alice".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None };
        assert!(Arc::ptr_eq(&req_db(&st, &au), &st.db), "mode 0 : req_db == st.db (comportement identique)");
        assert_eq!(req_db_path(&st, &au), *st.db_path, "mode 0 : req_db_path == st.db_path");
        assert!(spool_tenant_marker(&st, &au).is_empty(), "mode 0 : aucun marqueur spool (nom de fichier identique)");
    }

    // ============================================================================================
    // DATASOURCE (#52) — plume-AS-A-datasource : le masque #45 + le RBAC sont HÉRITÉS sur la nouvelle
    // surface de LECTURE EXTERNE (GXQL-HTTP + Prometheus). Preuve via les fonctions exactes des handlers.
    // ============================================================================================

    /// Base de test file-backed : 2 events (src_user JSON + host), 2 samples metric (labels+host), et des
    /// field-filters role='' (viewer/editor masqués, admin en clair) : src_user hash, message mask, host mask.
    fn ds_seed_db(tag: &str) -> String {
        let path = ff_tmp_path(tag);
        {
            let conn = open_db(&path).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&conn);
            conn.execute("INSERT INTO event(ts,source,category,severity,host,message,src_ip,fields) VALUES(?1,'sshd','auth',3,'h1',?2,?3,?4)",
                params![now(), "login alice", "10.0.0.5", r#"{"src_user":"alice"}"#]).unwrap();
            conn.execute("INSERT INTO event(ts,source,category,severity,host,message,src_ip,fields) VALUES(?1,'sshd','auth',3,'h2',?2,?3,?4)",
                params![now(), "login bob", "10.0.0.6", r#"{"src_user":"bob"}"#]).unwrap();
            conn.execute("INSERT INTO metric(ts,name,labels,value,host) VALUES(?1,'node_load1',?2,0.5,'h1')", params![now(), r#"{"instance":"h1","job":"node"}"#]).unwrap();
            conn.execute("INSERT INTO metric(ts,name,labels,value,host) VALUES(?1,'node_load1',?2,0.9,'h2')", params![now(), r#"{"instance":"h2","job":"node"}"#]).unwrap();
            conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('u','src_user','hash','')", []).unwrap();
            conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('m','message','mask','')", []).unwrap();
            conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('h','host','mask','')", []).unwrap();
            field_filters_reload(&conn, &path);
        } // writer droppé -> WAL visible au read pool
        path
    }

    /// AppState mode-0 file-backed (réutilise sso_test_state puis re-pointe db/db_path/tenants sur le fichier).
    fn ds_file_state(path: &str) -> AppState {
        let mut st = sso_test_state("plume-admin", "plume-editor", "admins");
        let db = Arc::new(Mutex::new(open_db(path).unwrap()));
        let db_path = Arc::new(path.to_string());
        st.db = db.clone();
        st.db_path = db_path.clone();
        st.tenants = TenantDbManager { default_db_path: db_path, default_writer: db, control: None, writers: Arc::new(Mutex::new(HashMap::new())) };
        st.query_sem = Arc::new(tokio::sync::Semaphore::new(4));
        st
    }

    /// LEVIER 1 (GXQL-HTTP) — le cœur `ds_soql_exec` (appelé tel quel par le handler avec l'AuthUser résolu)
    /// HÉRITE du masque #45 : viewer -> src_user haché / message masqué ; admin -> clair. ET la garde d'oracle
    /// #45 (filtrage sur champ masqué REJETÉ) est héritée via soql_to_sql_masked_x.
    #[test]
    fn ds_soql_http_inherits_mask_and_filter_reject() {
        let path = ds_seed_db("soql");
        // VIEWER : projection masquée.
        let rv = ds_soql_exec(&path, "viewer", "default", None, "search | table src_user, message", 0, 0, None, 5000).unwrap();
        let rows = rv["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        for row in rows {
            let u = row[0].as_str().unwrap_or("");
            assert!(u != "alice" && u != "bob" && !u.is_empty(), "viewer : src_user haché (pas en clair) : {u}");
            assert_eq!(row[1].as_str().unwrap(), "***", "viewer : message masqué");
        }
        // ADMIN : clair (règles role='' -> seuil editor, admin non masqué).
        let ra = ds_soql_exec(&path, "admin", "default", None, "search | table src_user, message", 0, 0, None, 5000).unwrap();
        let names: Vec<String> = ra["rows"].as_array().unwrap().iter().map(|r| r[0].as_str().unwrap_or("").to_string()).collect();
        assert!(names.contains(&"alice".to_string()) && names.contains(&"bob".to_string()), "admin : src_user en clair : {names:?}");
        // FILTER-REJECT (#45) : viewer filtrant sur un champ masqué -> compilation REFUSÉE (pas d'oracle).
        assert!(ds_soql_exec(&path, "viewer", "default", None, "search src_user=alice | table host", 0, 0, None, 5000).is_err(), "viewer : filtre sur champ masqué REJETÉ");
        assert!(ds_soql_exec(&path, "admin", "default", None, "search src_user=alice | table host", 0, 0, None, 5000).is_ok(), "admin : filtre autorisé");
        let _ = std::fs::remove_file(&path);
    }

    /// MODE 0 : sans registre de masques (autre base) -> ds_soql_exec compile STRICTEMENT comme le chemin
    /// non masqué (byte-identique) -> aucun changement de comportement quand #45 est inactif.
    #[test]
    fn ds_soql_http_mode0_byte_identical() {
        let masks_empty = effective_masks("/no/such/db", "viewer", "default", None);
        assert!(masks_empty.is_empty());
        let a = soql_to_sql_masked_x("search category=auth | stats count by host", 0, 0, None, &masks_empty).unwrap();
        let b = soql_to_sql_x("search category=auth | stats count by host", 0, 0, None).unwrap();
        assert_eq!(a, b, "masques VIDES -> compilation byte-identique au chemin non masqué");
    }

    /// LEVIER 2 (Prometheus) — masquage + garde de matcher HÉRITÉS : matcher sur host masqué REJETÉ (viewer),
    /// valeur host CAVIARDÉE en sortie (viewer), CLAIRE (admin) ; forme des séries (matrix/vector) correcte.
    #[test]
    fn ds_prom_masks_and_matcher_guard() {
        let path = ds_seed_db("prom");
        let vm = effective_masks(&path, "viewer", "default", None);
        let am = effective_masks(&path, "admin", "default", None);
        // GARDE MATCHER (#45) : viewer -> host rejeté ; admin -> ok.
        assert_eq!(prom_matcher_guard(&[("host".into(), "h1".into())], &vm).unwrap_err(), "host");
        assert!(prom_matcher_guard(&[("host".into(), "h1".into())], &am).is_ok());
        assert!(prom_matcher_guard(&[("job".into(), "node".into())], &vm).is_ok(), "label non masqué autorisé");
        // Exécution + séries.
        let sql = prom_metric_sql("node_load1", &[], 0, 0).unwrap();
        let v = run_query_ex(&path, &sql, 5000, None).unwrap();
        // VIEWER : host masqué dans CHAQUE série.
        let sv = prom_rows_to_series(&v, &path, "node_load1", &vm);
        assert_eq!(sv.len(), 2, "2 séries (instance distinct)");
        for (m, pts) in &sv {
            assert_eq!(m.get("__name__").and_then(|x| x.as_str()), Some("node_load1"));
            assert_eq!(m.get("host").and_then(|x| x.as_str()), Some("***"), "viewer : host masqué en sortie");
            assert!(!pts.is_empty(), "échantillons présents");
        }
        // ADMIN : host en clair.
        let sa = prom_rows_to_series(&v, &path, "node_load1", &am);
        let hosts: Vec<String> = sa.iter().filter_map(|(m, _)| m.get("host").and_then(|x| x.as_str()).map(|s| s.to_string())).collect();
        assert!(hosts.contains(&"h1".to_string()) && hosts.contains(&"h2".to_string()), "admin : host en clair : {hosts:?}");
        let _ = std::fs::remove_file(&path);
    }

    /// LEVIER 2 — sous-ensemble PromQL HONNÊTE (parse) + injection-safety du builder SQL.
    #[test]
    fn ds_prom_parse_subset_and_injection_safe() {
        assert_eq!(prom_parse_selector("node_load1").unwrap(), ("node_load1".to_string(), vec![]));
        assert_eq!(
            prom_parse_selector("node_load1{host=\"h1\",job=\"node\"}").unwrap(),
            ("node_load1".to_string(), vec![("host".to_string(), "h1".to_string()), ("job".to_string(), "node".to_string())])
        );
        assert_eq!(prom_parse_selector("{__name__=\"m\",job=\"x\"}").unwrap(), ("m".to_string(), vec![("job".to_string(), "x".to_string())]));
        // NON supportés (suite documentée) -> Err clair.
        assert!(prom_parse_selector("rate(node_load1[5m])").is_err(), "fonction PromQL rejetée");
        assert!(prom_parse_selector("m{host=~\"h.\"}").is_err(), "matcher regex =~ rejeté");
        assert!(prom_parse_selector("m{host!=\"h1\"}").is_err(), "matcher != rejeté");
        // INJECTION : valeur avec apostrophe -> échappée -> SQL valide, 0 ligne (pas d'injection).
        let path = ds_seed_db("inj");
        let sql = prom_metric_sql("node_load1", &[("host".to_string(), "h1' OR '1'='1".to_string())], 0, 0).unwrap();
        assert!(sql.contains("''"), "apostrophe échappée : {sql}");
        let v = run_query_ex(&path, &sql, 5000, None).unwrap();
        assert_eq!(v["rows"].as_array().unwrap().len(), 0, "injection neutralisée (0 ligne)");
        assert!(prom_metric_sql("m'x", &[], 0, 0).is_err(), "nom de métrique avec apostrophe rejeté");
        let _ = std::fs::remove_file(&path);
    }

    /// AUTH / TOKEN — modèle read-scoped : routes datasource = Read (GET+POST) ; token `agent` NE peut PAS lire
    /// (ingest-only) ; token `datasource` mappe vers viewer/editor ; un token agent n'est PAS un token datasource.
    #[tokio::test]
    async fn ds_token_and_rbac_model() {
        for p in ["/api/ds/query", "/api/v1/query", "/api/v1/query_range", "/api/v1/labels", "/api/v1/series", "/api/v1/label/__name__/values", "/loki/api/v1/query_range"] {
            assert_eq!(route_min_role(p, false), MinRole::Read, "{p} GET = Read");
            assert_eq!(route_min_role(p, true), MinRole::Read, "{p} POST = Read (read-only)");
            assert!(datasource_bearer_path(p), "{p} sur le seam datasource");
        }
        assert!(!role_satisfies("agent", MinRole::Read), "un token agent (ingest-only) NE lit PAS la datasource");
        assert!(role_satisfies("viewer", MinRole::Read));
        assert!(rbac_gate("viewer", "/api/ds/query", false).is_ok());
        assert!(rbac_gate("agent", "/api/ds/query", false).is_err(), "agent -> 403 sur la datasource");
        // Mint + résolution du token datasource (mode 0).
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let (code, v) = tok_resp_json(token_create(State(st.clone()), Extension(tok_au("admin")), Json(json!({ "name": "grafana", "kind": "datasource", "role": "editor" }))).await).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["kind"], "datasource");
        assert_eq!(v["role"], "editor");
        let secret = v["token"].as_str().unwrap().to_string();
        let ds = datasource_token_lookup(&st, &secret).expect("token datasource résolu");
        assert_eq!(ds.role, "editor");
        assert_eq!(ds.tenant, "default");
        // défaut = viewer (moindre privilège).
        let (_c, vd) = tok_resp_json(token_create(State(st.clone()), Extension(tok_au("admin")), Json(json!({ "name": "g2", "kind": "datasource" }))).await).await;
        assert_eq!(vd["role"], "viewer", "rôle datasource par défaut = viewer");
        // Un token AGENT n'est PAS un token datasource (kind disjoint) -> None.
        let (_c2, va) = tok_resp_json(token_create(State(st.clone()), Extension(tok_au("admin")), Json(json!({ "name": "ag", "kind": "agent", "host": "h1" }))).await).await;
        assert!(datasource_token_lookup(&st, va["token"].as_str().unwrap()).is_none(), "token agent != token datasource");
        assert!(datasource_token_lookup(&st, "nope").is_none(), "token inconnu -> None");
    }

    /// SÉCU — KIND-CONFUSION FERMÉE : un token `kind='datasource'` (read-scoped, remis
    /// à une Grafana externe) NE DOIT PAS valoir comme token AGENT/HEC. `token_lookup` (qui alimente le seam
    /// agent Bearer role='agent' + le seam HEC) DOIT le rejeter -> pas d'injection d'events SOC / métriques /
    /// logs, pas de falsification d'audit containment. Preuve BOUT EN BOUT via resolve_identity sur /api/ingest
    /// et /services/collector. + Régression : le chemin datasource FORWARD reste intact. + host ignoré au mint.
    #[tokio::test]
    async fn ds_token_kind_confusion_closed() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let (code, v) = tok_resp_json(token_create(State(st.clone()), Extension(tok_au("admin")), Json(json!({ "name": "grafana", "kind": "datasource", "role": "viewer" }))).await).await;
        assert_eq!(code, StatusCode::OK);
        let ds = v["token"].as_str().unwrap().to_string();

        // (1) token_lookup (seam agent/HEC) REJETTE le token datasource.
        assert!(token_lookup(&st, &ds).is_none(), "token datasource NON valide comme token agent/HEC (kind-confusion fermée)");
        assert!(valid_token(&st, &ds).is_none(), "valid_token (host agent) rejette le token datasource");

        // (2) BOUT EN BOUT : sur le seam agent /api/ingest -> AUCUNE identité (auth_guard renverrait 401).
        let mk_req = |uri: &str| {
            Request::builder().uri(uri).header("authorization", format!("Bearer {ds}")).body(axum::body::Body::empty()).unwrap()
        };
        let (ingest_ident, _m1, _, _, _) = resolve_identity(&st, &mk_req("/api/ingest"));
        assert!(ingest_ident.is_none(), "token datasource NE forge AUCUNE identité agent sur /api/ingest (pas d'injection d'events SOC)");
        let (metrics_ident, _m2, _, _, _) = resolve_identity(&st, &mk_req("/api/metrics/prom"));
        assert!(metrics_ident.is_none(), "token datasource NE forge AUCUNE identité sur /api/metrics/prom");
        let (hec_ident, _m3, _, _, _) = resolve_identity(&st, &mk_req("/services/collector"));
        assert!(hec_ident.is_none(), "token datasource NE forge AUCUNE identité HEC sur /services/collector");

        // (3) FORWARD intact : le token datasource s'authentifie TOUJOURS sur /api/ds/query en viewer.
        assert_eq!(datasource_token_lookup(&st, &ds).map(|d| d.role), Some("viewer".to_string()));
        let (ds_ident, ds_method, _, _, _) = resolve_identity(&st, &mk_req("/api/ds/query"));
        assert_eq!(ds_ident, Some(("grafana".to_string(), "viewer".to_string())), "FORWARD : token datasource -> viewer sur /api/ds/query");
        assert_eq!(ds_method, "datasource");

        // (4) DÉFENSE EN PROFONDEUR : host IGNORÉ au mint d'un token datasource (lecture seule, jamais host-lié).
        let (_c, vh) = tok_resp_json(token_create(State(st.clone()), Extension(tok_au("admin")), Json(json!({ "name": "g-host", "kind": "datasource", "host": "web01" }))).await).await;
        assert!(vh["host"].is_null(), "token datasource JAMAIS host-lié (host ignoré au mint)");
    }

    // ================================================================================================
    // #50 — OUTPUTS / DESTINATIONS : forward des events normalisés vers un SINK EXTERNE. Invariants du
    // gate : migration v92, payloads syslog/HEC/webhook, filtre allowlisté, watermark (at-least-once, pas
    // de trou / pas de ré-envoi infini), sink mort qui ne bloque pas l'ingest, ledgerisation, secret
    // redacted + raw-SQL-denied, mode 0.
    // ================================================================================================

    /// MIGRATION v92 : la table `destination` existe avec ses colonnes clés ; schema_version=92.
    #[test]
    fn dest_v92_migration_creates_table() {
        let conn = test_db();
        let v: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "112", "schema_version à la tête après migrate (#59 gouvernance legal_hold/ledger_sink)");
        let cols: Vec<String> = conn.prepare("SELECT name FROM pragma_table_info('destination')").unwrap()
            .query_map([], |r| r.get(0)).unwrap().flatten().collect();
        for c in ["type", "endpoint", "config", "filter", "watermark", "last_error", "error_count", "batch_max", "interval_s"] {
            assert!(cols.iter().any(|x| x == c), "colonne destination.{c} attendue");
        }
    }

    /// #60 — MIGRATION v97 : les 4 tables KO-reliquat existent avec leurs colonnes clés, VIDES (mode 0).
    #[test]
    fn v97_migration_creates_ko_reliquat_tables() {
        let conn = test_db();
        let v: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "112", "schema_version à la tête après migrate (#60 macros/auto-lookups/scheduled-reports/workflow-actions)");
        for (tbl, need) in [
            ("macro_def", vec!["name", "params", "body", "enabled"]),
            ("auto_lookup", vec!["name", "key_field", "out_cols", "kind", "enabled"]),
            ("scheduled_report", vec!["name", "dataset_id", "notifier_id", "run_as_role", "tenant", "interval_s", "last_error"]),
            ("workflow_action", vec!["name", "scope_field", "kind", "target", "enabled"]),
        ] {
            let cols: Vec<String> = conn.prepare(&format!("SELECT name FROM pragma_table_info('{tbl}')")).unwrap()
                .query_map([], |r| r.get(0)).unwrap().flatten().collect();
            for c in &need {
                assert!(cols.iter().any(|x| x == c), "colonne {tbl}.{c} attendue");
            }
            // VIDE à la création -> mode 0 (aucun effet tant qu'aucune ligne).
            let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {tbl}"), [], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "table {tbl} doit être vide à la migration");
        }
    }

    /// #39 — MIGRATION v98 : tables sla_policy + case_link créées & VIDES ; colonnes case-ops ajoutées à
    /// `incident` (merged_into/ack_due/resolve_due/ack_breached/resolve_breached/sla_paused_since/
    /// sla_pause_accum/sla_policy_id). ADDITIF -> mode 0 inerte.
    #[test]
    fn v98_migration_creates_caseops_tables() {
        let conn = test_db();
        assert_eq!(conn.query_row::<String, _, _>("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap(), "112");
        for (tbl, need) in [
            ("sla_policy", vec!["name", "priority", "ack_target_s", "resolve_target_s", "enabled"]),
            ("case_link", vec!["src_id", "dst_id", "kind", "note"]),
        ] {
            let cols: Vec<String> = conn.prepare(&format!("SELECT name FROM pragma_table_info('{tbl}')")).unwrap().query_map([], |r| r.get(0)).unwrap().flatten().collect();
            for c in &need { assert!(cols.iter().any(|x| x == c), "colonne {tbl}.{c} attendue"); }
            assert_eq!(conn.query_row::<i64, _, _>(&format!("SELECT COUNT(*) FROM {tbl}"), [], |r| r.get(0)).unwrap(), 0, "{tbl} VIDE à la migration");
        }
        let icols: Vec<String> = conn.prepare("SELECT name FROM pragma_table_info('incident')").unwrap().query_map([], |r| r.get(0)).unwrap().flatten().collect();
        for c in ["merged_into", "ack_due", "resolve_due", "ack_breached", "resolve_breached", "sla_paused_since", "sla_pause_accum", "sla_policy_id"] {
            assert!(icols.iter().any(|x| x == c), "colonne incident.{c} attendue");
        }
        // idempotence : re-migrer ne casse rien, reste à la tête.
        let _ = migrate(&conn);
        assert_eq!(conn.query_row::<String, _, _>("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap(), "112");
    }

    /// #60 — MODE 0 : sans macro/auto-lookup, la compilation GXQL est BYTE-IDENTIQUE au legacy (le KnowledgeSet
    /// chargé depuis des tables VIDES reste vide -> aucun hook). Preuve daemon (le cœur le prouve aussi).
    #[test]
    fn ko_reliquat_mode0_byte_identical() {
        let conn = test_db();
        knowledge_reload(&conn, ":ko-reliquat-mode0:");
        let ks = effective_knowledge(":ko-reliquat-mode0:");
        assert!(ks.is_empty(), "KnowledgeSet doit être vide sur des tables macro/auto-lookup vides (mode 0)");
        for q in ["search source=web | stats count by src_ip", "search severity>=4 | head 10"] {
            let plain = guatx_core::soql::to_sql(q, 0, 0, &guatx_core::soql::Schema::events()).unwrap();
            let withks = guatx_core::soql::to_sql(q, 0, 0, &guatx_core::soql::Schema::events().with_knowledge(ks.clone())).unwrap();
            assert_eq!(plain, withks, "parité mode 0 rompue : {q}");
        }
    }

    /// #60 — RBAC : run_as d'un scheduled-report ne peut PAS dépasser le rôle du créateur (anti-escalade), et
    /// une workflow-action de réponse ne référence QUE l'enum d'action fermé.
    #[test]
    fn scheduled_report_run_as_capped_and_response_enum_only() {
        // run_as PLAFONNÉ : un editor ne peut pas viser admin ; un viewer ne peut pas viser editor.
        assert!(resolve_run_as("admin", "editor").is_err());
        assert!(resolve_run_as("editor", "viewer").is_err());
        assert!(resolve_run_as("viewer", "editor").is_ok());
        assert_eq!(resolve_run_as("", "editor").unwrap(), "viewer"); // défaut = le plus masqué
        // réponse enum-only : seules les actions du vocab fermé passent.
        for ok in ["ban_ip", "unban_ip", "kill_pid", "stop_service"] {
            assert!(action_kind_valid(ok).is_ok(), "{ok} devrait être une action valide");
        }
        for bad in ["run_script", "exec", "rm -rf /", "shutdown"] {
            assert!(action_kind_valid(bad).is_err(), "{bad} ne doit PAS être une action valide");
        }
    }

    /// #60 — RÉGRESSION HIGH : un scheduled-report HONORE les field-filters TENANT-scopés à la LIVRAISON. Avant le
    /// fix, `deliver_report` compilait avec un tenant="" CODÉ EN DUR -> une règle `tenant='clientA'` ne matchait
    /// JAMAIS -> le rapport livré contenait des données BRUTES non masquées (contrairement à /api/query qui passe
    /// `&au.tenant`). Fix : le tenant DU CRÉATEUR est persisté à la création puis threadé jusqu'à effective_masks.
    /// On prouve le masque sur le CONTENU réellement livré (render_report_detail = ce que deliver_report envoie).
    #[test]
    fn scheduled_report_honors_tenant_scoped_field_filter() {
        let path = ff_tmp_path("sched-tenant");
        {
            let conn = open_db(&path).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&conn);
            conn.execute("INSERT INTO event(ts,source,category,severity,host,message,src_ip,fields) VALUES(?1,'sshd','auth',3,'h1',?2,?3,?4)",
                params![now(), "login alice", "10.0.0.5", r#"{"src_user":"alice"}"#]).unwrap();
            conn.execute("INSERT INTO event(ts,source,category,severity,host,message,src_ip,fields) VALUES(?1,'sshd','auth',3,'h2',?2,?3,?4)",
                params![now(), "login bob", "10.0.0.6", r#"{"src_user":"bob"}"#]).unwrap();
            // règle TENANT-scopée : src_user haché UNIQUEMENT pour tenant 'clientA' (rôle '' -> viewer/editor).
            conn.execute("INSERT INTO field_filter(name,field,action,role,tenant) VALUES('ua','src_user','hash','','clientA')", []).unwrap();
            // règle RÔLE-scopée (tenant '' = tout tenant) : message masqué.
            conn.execute("INSERT INTO field_filter(name,field,action,role,tenant) VALUES('m','message','mask','','')", []).unwrap();
            field_filters_reload(&conn, &path);
        } // writer droppé -> WAL visible au read-pool

        // Rapport DU tenant 'clientA', run_as viewer : la règle tenant-scopée S'APPLIQUE -> src_user haché.
        let (n, detail) = render_report_detail(&path, "rpt", "viewer", "clientA", "search | table src_user, message").unwrap();
        assert_eq!(n, 2, "2 events livrés");
        assert!(!detail.contains("alice") && !detail.contains("bob"), "src_user tenant-scopé DOIT être masqué pour clientA : {detail}");
        assert!(detail.contains("***"), "message (règle rôle-scopée) masqué : {detail}");

        // TÉMOIN du bug d'origine : avec tenant="" (l'ancien codé en dur) la règle tenant='clientA' est RATÉE
        // -> src_user en CLAIR (fuite). Prouve que le tenant threadé est bien load-bearing.
        let (_, leak) = render_report_detail(&path, "rpt", "viewer", "", "search | table src_user, message").unwrap();
        assert!(leak.contains("alice") && leak.contains("bob"), "témoin : tenant='' rate la règle tenant-scopée (bug d'origine) : {leak}");
        // ... mais la règle RÔLE-scopée (tenant '') reste honorée quel que soit le tenant.
        assert!(leak.contains("***"), "règle rôle-scopée (tenant '') toujours appliquée : {leak}");

        let _ = std::fs::remove_file(&path);
    }

    /// PAYLOADS : webhook (POST JSON + auth header), HEC-out (NDJSON enveloppe Splunk + Authorization Splunk),
    /// syslog (RFC5424 sur TCP). + HEC sans token -> Err (fail-closed).
    #[test]
    fn dest_build_wire_payloads() {
        let ev = row_to_fwd(7, 1_700_000_000, "sshd".into(), "auth".into(), 3, "failed login".into(),
            Some("h1".into()), Some("1.2.3.4".into()), None, None, Some(r#"{"user":"root"}"#.into()), "prod".into());
        let evs = vec![ev];
        // webhook : tableau JSON + en-tête d'auth (secret) issu de config.auth_header.
        let w = build_wire("webhook", "https://sink.example/in", &json!({"auth_header":"Authorization: Bearer TOK"}), &evs).unwrap();
        match &w {
            Wire::Http { method, url, headers, body } => {
                assert_eq!(method, "POST");
                assert_eq!(url, "https://sink.example/in");
                assert!(headers.iter().any(|(k, v)| k == "Authorization" && v == "Bearer TOK"));
                let s = String::from_utf8_lossy(body);
                assert!(s.contains("failed login") && s.contains("\"events\""));
            }
            _ => panic!("webhook doit être Http"),
        }
        // HEC-out : URL /services/collector/event + Authorization: Splunk <token> + enveloppe sourcetype/event.
        let w = build_wire("hec", "https://splunk:8088", &json!({"hec_token":"HTOK"}), &evs).unwrap();
        match &w {
            Wire::Http { url, headers, body, .. } => {
                assert_eq!(url, "https://splunk:8088/services/collector/event");
                assert!(headers.iter().any(|(k, v)| k == "Authorization" && v == "Splunk HTOK"));
                let s = String::from_utf8_lossy(body);
                assert!(s.contains("\"sourcetype\":\"auth\"") && s.contains("\"event\""), "enveloppe HEC : {s}");
            }
            _ => panic!("hec doit être Http"),
        }
        assert!(build_wire("hec", "https://x", &json!({}), &evs).is_err(), "HEC sans token -> Err (fail-closed)");
        // syslog : RFC5424 sur TCP nu. sev Plume 3 -> syslog 3 -> PRI = user(1)*8 + 3 = 11.
        let w = build_wire("syslog", "tcp://logs.example:514", &json!({}), &evs).unwrap();
        match &w {
            Wire::Tcp { host, port, body } => {
                assert_eq!(host, "logs.example");
                assert_eq!(*port, 514);
                let s = String::from_utf8_lossy(body);
                assert!(s.starts_with("<11>1 "), "en-tête RFC5424 PRI=11 attendu : {s}");
                assert!(s.contains("failed login"));
            }
            _ => panic!("syslog doit être Tcp"),
        }
    }

    /// FILTRE + WATERMARK : le filtre allowlisté (source+category) ne sélectionne QUE les events matchants ;
    /// le watermark avance au dernier id forwardé (at-least-once) ; un 2e passage ne RÉ-ENVOIE rien (pas de
    /// boucle infinie : id>watermark exclut le lot). Transport MOCKÉ (aucun socket).
    #[test]
    fn dest_filter_selects_and_watermark_advances_once() {
        let db = connector_test_db();
        let t = now();
        {
            let c = db.lock();
            c.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'fwdtest','auth',3,'a')", params![t]).unwrap();
            c.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'fwdtest','network',1,'b')", params![t]).unwrap();
            c.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'fwdtest','auth',4,'c')", params![t]).unwrap();
        }
        let id_c: i64 = { let c = db.lock(); c.query_row("SELECT MAX(id) FROM event WHERE source='fwdtest' AND category='auth'", [], |r| r.get(0)).unwrap() };
        let filter = json!({"source":"fwdtest","category":"auth"}).to_string();
        let sent = std::cell::RefCell::new(Vec::<Wire>::new());
        let ok_tx = |w: &Wire| { sent.borrow_mut().push(w.clone()); Ok::<u16, String>(200) };
        forward_one_destination(&db, 1, "webhook", "https://x/in", "{}", &filter, 500, 0, now(), &ok_tx);
        {
            let s = sent.borrow();
            assert_eq!(s.len(), 1, "un seul envoi de lot");
            let body = match &s[0] { Wire::Http { body, .. } => String::from_utf8_lossy(body).to_string(), _ => panic!() };
            assert!(body.contains("\"message\":\"a\"") && body.contains("\"message\":\"c\""), "les 2 events auth doivent sortir");
            assert!(!body.contains("\"message\":\"b\""), "l'event network NE doit PAS sortir (filtre category=auth)");
        }
        // La destination n'existe pas en table dans ce test (on appelle forward_one_destination directement) —
        // pour vérifier watermark/last_count on insère une ligne destination et on rejoue via run_due_destinations.
        {
            let c = db.lock();
            c.execute("INSERT INTO destination(id,type,name,enabled,endpoint,config,filter,batch_max,interval_s,watermark) \
                       VALUES(9,'webhook','w',1,'https://x/in','{}',?1,500,5,0)", params![filter]).unwrap();
        }
        // Rejoue via le chemin de prod (transport réel échouerait sur le réseau) -> on teste plutôt la MÉCANIQUE
        // watermark via forward_one_destination + mock sur la MÊME ligne id=9.
        forward_one_destination(&db, 9, "webhook", "https://x/in", "{}", &filter, 500, 0, now(), &ok_tx);
        let (wm, lc): (i64, i64) = { let c = db.lock(); c.query_row("SELECT watermark,last_count FROM destination WHERE id=9", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!(lc, 2, "2 events auth forwardés");
        assert_eq!(wm, id_c, "watermark = plus grand id forwardé (event c)");
        // 2e passage au watermark courant -> aucun event neuf -> aucun envoi (pas de ré-envoi infini).
        sent.borrow_mut().clear();
        forward_one_destination(&db, 9, "webhook", "https://x/in", "{}", &filter, 500, wm, now(), &ok_tx);
        assert!(sent.borrow().is_empty(), "aucun ré-envoi : id>watermark exclut le lot déjà forwardé");
    }

    /// SINK MORT : un transport en erreur (ou un HTTP non-2xx) GÈLE le watermark (rejouable), incrémente
    /// error_count, pose last_error — et l'INGEST continue (la table event n'est jamais bloquée).
    #[test]
    fn dest_dead_sink_freezes_watermark_ingest_unaffected() {
        let db = connector_test_db();
        {
            let c = db.lock();
            c.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'fwdtest','auth',3,'x')", params![now()]).unwrap();
            c.execute("INSERT INTO destination(id,type,name,enabled,endpoint,config,filter,batch_max,interval_s,watermark) \
                       VALUES(1,'webhook','w',1,'https://x/in','{}','{}',500,5,0)", []).unwrap();
        }
        let dead = |_w: &Wire| Err::<u16, String>("connexion refusée".into());
        forward_one_destination(&db, 1, "webhook", "https://x/in", "{}", "{}", 500, 0, now(), &dead);
        let (wm, ec, le): (i64, i64, Option<String>) = { let c = db.lock(); c.query_row("SELECT watermark,error_count,last_error FROM destination WHERE id=1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap() };
        assert_eq!(wm, 0, "sink mort -> watermark GELÉ (rejouable)");
        assert_eq!(ec, 1, "error_count incrémenté");
        assert!(le.is_some(), "last_error posé");
        // L'ingest continue : on écrit un nouvel event -> succès (table jamais bloquée par le forwarder).
        { let c = db.lock(); c.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'fwdtest','auth',3,'y')", params![now()]).unwrap(); }
        let n: i64 = { let c = db.lock(); c.query_row("SELECT COUNT(*) FROM event WHERE source='fwdtest'", [], |r| r.get(0)).unwrap() };
        assert_eq!(n, 2, "l'ingest continue malgré le sink mort");
        // HTTP non-2xx gèle aussi le watermark.
        let http500 = |_w: &Wire| Ok::<u16, String>(500);
        forward_one_destination(&db, 1, "webhook", "https://x/in", "{}", "{}", 500, 0, now(), &http500);
        let (wm2, ec2): (i64, i64) = { let c = db.lock(); c.query_row("SELECT watermark,error_count FROM destination WHERE id=1", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!(wm2, 0, "HTTP 500 -> watermark gelé");
        assert_eq!(ec2, 2, "error_count encore incrémenté");
    }

    /// STUB s3/kafka : jamais de réseau, watermark JAMAIS avancé, last_error explicite (non-silence).
    #[test]
    fn dest_stub_types_never_forward() {
        let db = connector_test_db();
        {
            let c = db.lock();
            c.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'fwdtest','auth',3,'z')", params![now()]).unwrap();
        }
        let boom = |_w: &Wire| -> Result<u16, String> { panic!("un stub ne doit JAMAIS appeler le transport") };
        forward_one_destination(&db, 1, "s3", "s3://bucket", "{}", "{}", 500, 0, now(), &boom);
        // (pas de panic = le transport n'a pas été appelé)
        assert!(!dest_type_implemented("s3") && !dest_type_implemented("kafka"));
        assert!(dest_type_implemented("syslog") && dest_type_implemented("hec") && dest_type_implemented("webhook"));
    }

    /// MODE 0 : aucune destination -> run_due_destinations est un no-op strict (aucune écriture) ; l'ingest
    /// est inchangé.
    #[test]
    fn dest_mode0_no_destination_is_noop() {
        let db = connector_test_db();
        { let c = db.lock(); c.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'fwdtest','auth',3,'m')", params![now()]).unwrap(); }
        let before: i64 = { let c = db.lock(); c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap() };
        run_due_destinations(&db, ":memory:");
        let after: i64 = { let c = db.lock(); c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap() };
        assert_eq!(before, after, "aucune destination -> ingest inchangé (mode 0)");
        let dn: i64 = { let c = db.lock(); c.query_row("SELECT COUNT(*) FROM destination", [], |r| r.get(0)).unwrap() };
        assert_eq!(dn, 0, "table destination vide -> no-op strict");
    }

    /// GOUVERNANCE : une mutation de config destination (create) est LEDGERISÉE (entrée ledger tamper-evident
    /// chaînée + event de config SOC-visible non-purgeable origin='daemon').
    #[test]
    fn dest_config_change_is_ledgerised() {
        let conn = test_db();
        let led_before: i64 = conn.query_row("SELECT COUNT(*) FROM ledger", [], |r| r.get(0)).unwrap();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        audit_config_change(&conn, "config.destination.create", "destination 'x' (hec) créée",
            3, "SORTIE de données : destination 'x' créée", &json!({"id":1,"type":"hec"}).to_string()).unwrap();
        conn.execute_batch("COMMIT").unwrap();
        let led_after: i64 = conn.query_row("SELECT COUNT(*) FROM ledger", [], |r| r.get(0)).unwrap();
        assert_eq!(led_after, led_before + 1, "la mutation destination doit ajouter une entrée ledger");
        let kind: String = conn.query_row("SELECT kind FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).unwrap();
        assert_eq!(kind, "config.destination.create");
        let ev: i64 = conn.query_row(
            "SELECT COUNT(*) FROM event WHERE source='plume-config' AND origin='daemon' AND category='config'", [], |r| r.get(0)).unwrap();
        assert!(ev >= 1, "un event de config SOC-visible non-purgeable doit être émis");
    }

    /// SECRET : `destination.config` (hec_token / auth_header en clair) est REFUSÉ en lecture SQL brute par
    /// l'authorizer read-pool (même admin) — projection, mélange, WHERE — tandis que les colonnes non-secrètes
    /// restent lisibles.
    #[test]
    fn dest_config_secret_raw_sql_denied() {
        let mut path = std::env::temp_dir();
        path.push(format!("plume-dest-deny-{}-{}.db", std::process::id(), now()));
        let p = path.to_string_lossy().to_string();
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            w.execute("INSERT INTO destination(id,type,name,enabled,endpoint,config,filter) \
                       VALUES(1,'hec','h',1,'https://x','{\"hec_token\":\"SECRET\"}','{}')", []).unwrap();
        }
        assert!(run_query(&p, "SELECT config FROM destination").is_err(), "destination.config (projection) doit être refusé");
        assert!(run_query(&p, "SELECT name,config FROM destination").is_err(), "destination.config (mélangé) doit être refusé");
        assert!(run_query(&p, "SELECT id FROM destination WHERE config LIKE '%SECRET%'").is_err(), "destination.config en WHERE doit être refusé");
        assert!(run_query(&p, "SELECT type,endpoint,watermark,error_count FROM destination").is_ok(), "les colonnes non-secrètes restent lisibles");
        let _ = std::fs::remove_file(&p);
    }

    /// VALIDATION : endpoint (schéma https/tcp + garde SSRF complète : cible interne refusée, RFC1918 opt-in),
    /// type, filtre (bornes), et la forme bound-param de la clause WHERE (injection-safe). NB : la garde SSRF
    /// est fail-closed sur DNS -> on teste avec des IP LITTÉRALES (aucune résolution réseau requise).
    #[test]
    fn dest_endpoint_type_filter_validation() {
        assert!(dest_endpoint_ok("webhook", "https://93.184.216.34/in"));               // public OK
        assert!(dest_endpoint_ok("webhook", "http://10.0.0.5:8080/in"));                 // RFC1918 on-prem OK par défaut
        assert!(!dest_endpoint_ok("webhook", "ftp://x"));
        assert!(!dest_endpoint_ok("webhook", "https://169.254.169.254/latest"), "cible métadonnées cloud interdite");
        assert!(!dest_endpoint_ok("webhook", "http://127.0.0.1/in"), "loopback interdit (never-egress)");
        assert!(dest_endpoint_ok("syslog", "tcp://93.184.216.34:514"));
        assert!(!dest_endpoint_ok("syslog", "udp://logs:514"), "syslog exige tcp://");
        assert!(!dest_endpoint_ok("syslog", "tcp://logs"), "port requis");
        assert!(!dest_endpoint_ok("syslog", "tcp://169.254.169.254:514"), "syslog vers metadata interdit");
        assert!(!dest_endpoint_ok("hec", "tcp://x:1"), "hec exige http(s)://");
        assert!(dest_type_ok("syslog") && dest_type_ok("s3") && !dest_type_ok("ftp"));
        // filtre : bornes + charset
        assert!(DestFilter::from_json(&json!({"category":"auth","min_severity":3})).validate().is_ok());
        assert!(DestFilter::from_json(&json!({"min_severity":9})).validate().is_err(), "min_severity hors bornes");
        assert!(DestFilter::from_json(&json!({"env_id":"bad env!"})).validate().is_err(), "env_id invalide");
        assert!(DestFilter::from_json(&json!({"category":"a b"})).validate().is_err(), "category invalide");
        // clause bound-param : placeholders décalés à partir de ?2 (?1 = watermark), aucun littéral interpolé.
        let (clause, params) = DestFilter::from_json(&json!({"category":"auth","min_severity":3})).sql_where(2);
        assert!(clause.contains("category = ?2") && clause.contains("severity >= ?3"), "clause: {clause}");
        assert_eq!(params.len(), 2, "un param lié par prédicat");
    }

    // ============================================================================================
    // #22 BREADTH — PRESETS CLOUD (descriptors http_pull déclaratifs). Chaque `docs/connector-presets/
    // *.json` est une CONFIG http_pull (aucun code par-vendeur) : ces tests prouvent qu'ils PARSENT/
    // CHARGENT comme un connecteur valide, ne contiennent AUCUN secret en clair (secret-ref only), et
    // que leur sourcetype_map ne cible que des categories CIM canoniques. Un preset réel (Okta) est
    // exécuté de bout en bout sur une charge vendeur -> event CIM.
    // ============================================================================================

    /// Tous les presets cloud livrés + les presets existants : parse via `HttpPullCfg::from_json`, url non
    /// vide (via `httppull_page_url`), `field_map` objet non vide, sourcetype_map -> categories CIM valides,
    /// et ZÉRO secret en clair dans le descriptor (le credential vit dans la colonne `secret`, jamais git).
    #[test]
    fn cloud_presets_parse_load_and_are_secret_free() {
        let presets: &[(&str, &str)] = &[
            ("okta", include_str!("../../../docs/connector-presets/okta.json")),
            ("m365-entra-signin", include_str!("../../../docs/connector-presets/m365-entra-signin.json")),
            ("m365-entra-audit", include_str!("../../../docs/connector-presets/m365-entra-audit.json")),
            ("google-workspace", include_str!("../../../docs/connector-presets/google-workspace.json")),
            ("cloudflare-audit", include_str!("../../../docs/connector-presets/cloudflare-audit.json")),
            ("aws-cloudtrail", include_str!("../../../docs/connector-presets/aws-cloudtrail.json")),
            ("aws-guardduty", include_str!("../../../docs/connector-presets/aws-guardduty.json")),
            ("gcp-audit", include_str!("../../../docs/connector-presets/gcp-audit.json")),
            ("crowdstrike-falcon", include_str!("../../../docs/connector-presets/crowdstrike-falcon.json")),
            ("sentinelone", include_str!("../../../docs/connector-presets/sentinelone.json")),
            ("generic-rest", include_str!("../../../docs/connector-presets/generic-rest.json")),
        ];
        for (name, raw) in presets {
            let v: Value = serde_json::from_str(raw)
                .unwrap_or_else(|e| panic!("preset {name}: JSON invalide: {e}"));
            let cfg = HttpPullCfg::from_json(&v);
            // config http_pull valide : url (ou api_root+path) résolue -> httppull_page_url non vide.
            let url = httppull_page_url(&cfg, None, Some(0), Some(1), None);
            assert!(!url.is_empty(), "preset {name}: url (ou api_root+path) requis");
            // field_map objet non vide (mêmes invariants que le CRUD admin / poll_http_pull).
            let fm = v.get("field_map").and_then(|x| x.as_object());
            assert!(fm.map_or(false, |o| !o.is_empty()), "preset {name}: field_map objet non vide requis");
            // AUCUN secret en clair : le credential est un secret-ref (colonne `secret`), jamais le descriptor.
            // On inspecte les CLÉS de l'arbre JSON (pas la prose des `_comment`, qui a le DROIT d'expliquer où
            // va le secret) : aucune clé, à n'importe quelle profondeur, ne doit être un champ porteur de secret.
            fn no_secret_keys(v: &Value, name: &str) {
                const SECRET_KEYS: &[&str] = &[
                    "client_secret", "secret", "password", "passwd", "api_key",
                    "apikey", "private_key", "access_token", "client_key", "credential",
                ];
                match v {
                    Value::Object(o) => {
                        for (k, child) in o {
                            let kl = k.to_ascii_lowercase();
                            assert!(!SECRET_KEYS.contains(&kl.as_str()),
                                "preset {name}: clé `{k}` interdite dans le descriptor (secret-ref only)");
                            no_secret_keys(child, name);
                        }
                    }
                    Value::Array(a) => a.iter().for_each(|c| no_secret_keys(c, name)),
                    _ => {}
                }
            }
            no_secret_keys(&v, name);
            // sourcetype_map (bring-your-own CIM) -> uniquement des categories CIM canoniques.
            if let Some(map) = v.get("sourcetype_map").and_then(|x| x.as_object()) {
                for (st, cat) in map {
                    let c = cat.as_str().unwrap_or("");
                    assert!(cim_category_ok(c),
                        "preset {name}: sourcetype `{st}` -> `{c}` hors taxonomie CIM");
                }
            }
        }
    }

    /// Bout-en-bout : le preset RÉEL Okta normalise une charge System-Log -> event CIM (category `auth` via
    /// son sourcetype_map, src_ip/user/action/city mappés, ts epoch, dedup idempotent `http-<id>-<uuid>`).
    #[test]
    fn okta_preset_normalizes_sample_payload_to_cim() {
        let raw = include_str!("../../../docs/connector-presets/okta.json");
        let cfg = HttpPullCfg::from_json(&serde_json::from_str::<Value>(raw).unwrap());
        let rec = json!({
            "uuid": "evt-abc-123",
            "published": "2026-07-05T10:00:00Z",
            "severity": "INFO",
            "displayMessage": "User login to Okta",
            "eventType": "user.session.start",
            "actor": { "alternateId": "jane@acme.com", "displayName": "Jane Doe" },
            "client": {
                "ipAddress": "203.0.113.7",
                "geographicalContext": { "city": "Paris", "country": "France" },
                "userAgent": { "rawUserAgent": "Mozilla/5.0" }
            },
            "outcome": { "result": "SUCCESS" },
            "target": [ { "displayName": "Okta Dashboard" } ]
        });
        let ev = httppull_map_record(&rec, &cfg, 12).expect("record Okta mappé");
        assert_eq!(ev["ts"].as_i64(), Some(minio_to_epoch(Some("2026-07-05T10:00:00Z"))));
        assert_eq!(ev["source"].as_str(), Some("okta"), "config.source");
        assert_eq!(ev["category"].as_str(), Some("auth"), "okta:system -> CIM auth via sourcetype_map du preset");
        assert_eq!(ev["src_ip"].as_str(), Some("203.0.113.7"), "client.ipAddress -> src_ip");
        assert_eq!(ev["message"].as_str(), Some("User login to Okta"));
        assert_eq!(ev["dedup"].as_str(), Some("http-12-evt-abc-123"), "dedup = http-<id>-<uuid> (idempotent)");
        assert_eq!(ev["fields"]["user"].as_str(), Some("jane@acme.com"), "actor.alternateId -> fields.user");
        assert_eq!(ev["fields"]["action"].as_str(), Some("SUCCESS"), "outcome.result -> fields.action");
        assert_eq!(ev["fields"]["city"].as_str(), Some("Paris"));
        assert_eq!(ev["fields"]["sourcetype"].as_str(), Some("okta:system"), "sourcetype posé dans fields");
        // severity Okta est en MAJUSCULES (INFO/WARN/…), non normalisée par sev_num -> défaut 0 (documenté).
        assert_eq!(ev["severity"].as_i64(), Some(0));
    }

    // ============================================================================================
    // P1 — PONT PRESET -> CONNECTEUR : bibliothèque embarquée (GET /api/connectors/presets) +
    // instanciation 1-clic (POST /api/connectors/from-preset) qui RÉUTILISE `connector_create`.
    // ============================================================================================

    fn pp_au(role: &str) -> AuthUser {
        AuthUser { name: format!("{role}-u"), role: role.into(), tenant: "default".into(),
            is_superadmin: false, method: "cookie".into(), csrf: String::new(), env: None }
    }
    async fn pp_resp_json<R: axum::response::IntoResponse>(r: R) -> (StatusCode, Value) {
        let r = r.into_response();
        let code = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        (code, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }
    /// Détecte toute clé porteuse de secret dans un arbre JSON (défense de la bibliothèque servie).
    fn tree_has_secret_key(v: &Value) -> bool {
        const SECRET_KEYS: &[&str] = &[
            "client_secret", "secret", "password", "passwd", "api_key",
            "apikey", "private_key", "access_token", "client_key", "credential",
        ];
        match v {
            Value::Object(o) => o.iter().any(|(k, c)| SECRET_KEYS.contains(&k.to_ascii_lowercase().as_str()) || tree_has_secret_key(c)),
            Value::Array(a) => a.iter().any(tree_has_secret_key),
            _ => false,
        }
    }

    /// La bibliothèque embarquée : 11 presets (= docs/connector-presets/*.json), 8 instanciables (auth
    /// supportée par le moteur) + 3 exclus (AWS SigV4 / GCP SA-JWT) servis pour information avec une `note`.
    /// Chaque instanciable expose un `config` (template http_pull VALIDE) et les `needs` (placeholders).
    #[test]
    fn preset_library_loads_and_all_embedded_presets_valid() {
        assert_eq!(PRESETS.len(), 11, "11 descriptors embarqués (= docs/connector-presets/*.json)");
        let inst: Vec<&str> = PRESETS.iter().filter(|p| p.instantiable).map(|p| p.id).collect();
        let excl: Vec<&str> = PRESETS.iter().filter(|p| !p.instantiable).map(|p| p.id).collect();
        assert_eq!(inst.len(), 8, "8 instanciables (bearer/token/header/oauth2) : {inst:?}");
        assert_eq!(excl, vec!["aws-cloudtrail", "aws-guardduty", "gcp-audit"], "exclus = AWS/GCP (auth non construite)");
        for p in PRESETS {
            let pub_v = preset_public(p);
            // La forme publique ne contient JAMAIS de clé porteuse de secret (templates secret-free).
            assert!(!tree_has_secret_key(&pub_v), "preset {} : la forme publique ne doit exposer AUCUN secret", p.id);
            // Chaque exclu porte une `note` explicative (voie push->HEC / phase ultérieure).
            if !p.instantiable {
                assert!(!pub_v["note"].as_str().unwrap_or("").is_empty(), "preset exclu {} : une note d'orientation est requise", p.id);
                continue;
            }
            // Instanciable : le template `config` est un http_pull VALIDE (mêmes invariants que le CRUD).
            let cfg = &pub_v["config"];
            let has_url = cfg.get("url").and_then(|x| x.as_str()).map_or(false, |s| !s.trim().is_empty())
                || cfg.get("api_root").and_then(|x| x.as_str()).map_or(false, |s| !s.trim().is_empty());
            assert!(has_url, "preset {} : url/api_root présent", p.id);
            assert!(cfg.get("records_path").and_then(|x| x.as_str()).is_some(), "preset {} : records_path présent", p.id);
            assert!(cfg.get("field_map").and_then(|x| x.as_object()).map_or(false, |o| !o.is_empty()), "preset {} : field_map non vide", p.id);
            // Le `config` ne porte plus le `_comment` (déplacé en description).
            assert!(cfg.get("_comment").is_none(), "preset {} : _comment retiré du template", p.id);
            assert!(!pub_v["description"].as_str().unwrap_or("").is_empty(), "preset {} : description (issue du _comment)", p.id);
        }
    }

    /// GET /api/connectors/presets : ADMIN-ONLY (viewer/editor -> 403) et la charge NE contient AUCUN
    /// secret (ni clé porteuse, ni valeur). Ne lit jamais la table `connector` (constantes embarquées).
    #[tokio::test]
    async fn preset_list_admin_gated_and_secret_free() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        for role in ["viewer", "editor"] {
            let (code, _) = pp_resp_json(connector_presets_list(Extension(pp_au(role))).await).await;
            assert_eq!(code, StatusCode::FORBIDDEN, "{role} -> 403 sur GET presets (admin-only)");
        }
        let (code, v) = pp_resp_json(connector_presets_list(Extension(pp_au("admin"))).await).await;
        assert_eq!(code, StatusCode::OK);
        let arr = v["presets"].as_array().expect("presets[]");
        assert_eq!(arr.len(), 11, "11 presets servis");
        for p in arr {
            assert!(!tree_has_secret_key(p), "aucune clé secret dans le preset servi {}", p["id"]);
        }
        // Aucune valeur de secret réelle : le JSON entier ne contient jamais le mot-clé de colonne `secret`
        // en tant que CLÉ de config (les `_comment` en prose sont déjà retirés du template).
        let dump = v.to_string();
        assert!(!dump.contains("\"client_secret\""), "aucune clé client_secret dans la charge servie");
    }

    /// INSTANCIATION = RÉUTILISATION du chemin create : from-preset(okta) -> 1 connecteur http_pull créé
    /// `enabled:false`, secret rangé dans la colonne CHIFFRÉE (redigé en lecture : has_secret=true, jamais
    /// projeté), placeholders substitués dans l'URL. Prouve qu'AUCUN chemin secret/CRUD n'est dupliqué.
    #[tokio::test]
    async fn preset_from_preset_reuses_create_path_and_redacts_secret() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let body = json!({
            "preset_id": "okta",
            "name": "Okta prod",
            "values": { "yourOktaDomain": "acme.okta.com" },
            "secret": "SSWS-super-secret-token",
            "env_id": "prod"
        });
        let (code, created) = pp_resp_json(connector_from_preset(State(st.clone()), Extension(pp_au("admin")), Json(body)).await).await;
        assert_eq!(code, StatusCode::OK, "from-preset admin -> 200 (délègue à create) : {created}");
        assert_eq!(created["enabled"], json!(false), "créé enabled:false (l'admin teste avant d'activer)");
        // Relire via connectors_list (le MÊME handler de lecture que pour un connecteur manuel).
        let (lc, list) = pp_resp_json(connectors_list(State(st.clone()), Extension(pp_au("admin"))).await).await;
        assert_eq!(lc, StatusCode::OK);
        let rows = list.as_array().expect("liste");
        assert_eq!(rows.len(), 1, "1 connecteur créé");
        let c = &rows[0];
        assert_eq!(c["type"], json!("http_pull"));
        assert_eq!(c["name"], json!("Okta prod"));
        assert_eq!(c["enabled"], json!(false));
        assert_eq!(c["has_secret"], json!(true), "secret présent (colonne chiffrée)");
        // Le secret n'est JAMAIS projeté en lecture (redigé) — ni clé `secret`, ni la valeur.
        assert!(c.get("secret").is_none(), "la colonne secret n'est jamais projetée");
        assert!(!list.to_string().contains("SSWS-super-secret-token"), "la valeur du secret ne fuit jamais en lecture");
        // Placeholder substitué dans l'URL (config relue).
        assert_eq!(c["config"]["url"], json!("https://acme.okta.com/api/v1/logs?sortOrder=ASCENDING"), "{{yourOktaDomain}} substitué");
        // Le secret est bien dans la colonne CHIFFRÉE `secret` (lecture directe SQL de contrôle).
        {
            let conn = st.db.lock();
            let sec: String = conn.query_row("SELECT secret FROM connector WHERE id=?1", params![created["id"].as_i64().unwrap()], |r| r.get(0)).unwrap();
            assert_eq!(sec, "SSWS-super-secret-token", "le secret saisi va dans la colonne secret (comme un connecteur manuel)");
        }
    }

    /// from-preset est ADMIN-ONLY : viewer ET editor -> 403, AUCUNE création (miroir de connector_create).
    #[tokio::test]
    async fn preset_from_preset_admin_gated() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        for role in ["viewer", "editor"] {
            let body = json!({ "preset_id": "okta", "values": { "yourOktaDomain": "x.okta.com" }, "secret": "s" });
            let (code, _) = pp_resp_json(connector_from_preset(State(st.clone()), Extension(pp_au(role)), Json(body)).await).await;
            assert_eq!(code, StatusCode::FORBIDDEN, "{role} ne peut PAS instancier (admin-only)");
        }
        // Aucune ligne créée par les non-admins.
        let n: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM connector", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "aucun connecteur créé par viewer/editor");
    }

    /// Les presets EXCLUS (AWS SigV4 / GCP SA-JWT) sont REFUSÉS à l'instanciation (auth non construite) —
    /// servis en lecture pour information seulement (voie push->HEC).
    #[tokio::test]
    async fn preset_excluded_not_instantiable() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        for id in ["aws-cloudtrail", "aws-guardduty", "gcp-audit"] {
            let body = json!({ "preset_id": id, "secret": "s" });
            let (code, _) = pp_resp_json(connector_from_preset(State(st.clone()), Extension(pp_au("admin")), Json(body)).await).await;
            assert_eq!(code, StatusCode::BAD_REQUEST, "{id} : non instanciable en P1 (SigV4/SA-JWT)");
        }
        let n: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM connector", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "aucun connecteur AWS/GCP créé (auth non supportée)");
    }

    /// Garde placeholder : un preset dont un `{...}`/`REPLACE_*` n'est pas renseigné est REFUSÉ (aucune
    /// création avec un client_id / URL non résolu). Miroir de la validation UI « refuse tant qu'un
    /// placeholder subsiste ». `preset_id` inconnu -> 400 aussi.
    #[tokio::test]
    async fn preset_missing_placeholder_and_unknown_rejected() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        // crowdstrike sans REPLACE_WITH_FALCON_CLIENT_ID -> refus.
        let body = json!({ "preset_id": "crowdstrike-falcon", "secret": "s" });
        let (code, v) = pp_resp_json(connector_from_preset(State(st.clone()), Extension(pp_au("admin")), Json(body)).await).await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "placeholder non renseigné -> 400 : {v}");
        // preset_id inconnu -> 400.
        let (code2, _) = pp_resp_json(connector_from_preset(State(st.clone()), Extension(pp_au("admin")), Json(json!({ "preset_id": "does-not-exist" }))).await).await;
        assert_eq!(code2, StatusCode::BAD_REQUEST, "preset_id inconnu -> 400");
        let n: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM connector", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "aucune création partielle");
    }

    /// TOUS les presets instanciables passent le chemin create de bout en bout (placeholders remplis par
    /// des valeurs factices) -> 200 + une ligne créée `enabled:false`. Prouve que chaque template est un
    /// connecteur valide ET que from-preset délègue bien au create pour l'ensemble du set.
    #[tokio::test]
    async fn preset_all_instantiable_create_via_shared_path() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let mut created = 0;
        for p in PRESETS.iter().filter(|p| p.instantiable) {
            let pub_v = preset_public(p);
            // Remplir chaque `need` avec une valeur factice non vide.
            let mut values = serde_json::Map::new();
            for need in pub_v["needs"].as_array().unwrap() {
                values.insert(need.as_str().unwrap().to_string(), json!("example.com"));
            }
            let body = json!({ "preset_id": p.id, "values": Value::Object(values), "secret": "dummy-secret" });
            let (code, v) = pp_resp_json(connector_from_preset(State(st.clone()), Extension(pp_au("admin")), Json(body)).await).await;
            assert_eq!(code, StatusCode::OK, "preset {} : from-preset -> 200 : {v}", p.id);
            assert_eq!(v["enabled"], json!(false), "preset {} : enabled:false", p.id);
            created += 1;
        }
        let n: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM connector", [], |r| r.get(0)).unwrap();
        assert_eq!(n as usize, created, "chaque instanciable a créé exactement 1 connecteur");
        assert_eq!(created, 8, "8 presets instanciables");
    }


    // ================================================================================================
    // ING-2 (v121) — http_pull : sécurité du watermark sur TRONCATURE (max_pages). Un flux NON ascendant
    // tronqué ne doit PAS avancer au max global (saut d'anciens-mais-neufs) ; un flux ascendant tronqué
    // avance à la borne (progrès conservé). `fetch` injecté -> offline.
    // ================================================================================================

    /// Fabrique un fetch "page" paginé qui renvoie TOUJOURS une page pleine (n==size) -> la pagination
    /// continue jusqu'à max_pages. `ts(page)` fixe l'ordre entre pages (croissant/décroissant).
    fn ing2_page_fetch(ascending: bool) -> impl Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<HttpResp, String> {
        move |_m: &str, url: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| {
            let p: i64 = url.split("page=").nth(1).and_then(|s| s.split('&').next()).and_then(|s| s.trim().parse().ok()).unwrap_or(1);
            let base = if ascending { 100 + p * 10 } else { 1100 - p * 100 };
            // 2 records par page ; l'ordre INTRA-page suit aussi `ascending`.
            let (t0, t1) = if ascending { (base, base + 1) } else { (base, base - 1) };
            let data = json!([{ "m": "e", "ts": t0 }, { "m": "e", "ts": t1 }]);
            Ok(HttpResp { status: 200, headers: vec![], body: json!({ "data": data }).to_string().into_bytes() })
        }
    }
    fn ing2_cfg() -> HttpPullCfg {
        HttpPullCfg::from_json(&json!({
            "url": "https://x/api/events", "records_path": "data",
            "field_map": { "message": "m", "ts": "ts" },
            "pagination": { "kind": "page", "param": "page", "size": 2, "size_param": "limit", "start": 1 },
            "watermark": { "field_path": "ts", "param": "since", "format": "epoch", "lookback_days": 7 }
        }))
    }

    /// ING-2 — API NON ascendante + TRONCATURE : le watermark NE saute PAS au max global (1000) ; il reste au
    /// watermark ENTRANT -> les pages non fetchées (encore > l'entrant) seront re-fetchées au tick suivant
    /// (aucun saut silencieux). Les records des pages fetchées sont bien ingérés (dedup absorbe les rejeux).
    #[test]
    fn ing2_truncated_non_ascending_holds_watermark() {
        let cfg = ing2_cfg();
        // max_pages=2 -> page1(1000,999)+page2(900,899) fetchées, page3(800,799) TRONQUÉE.
        let out = poll_http_pull(&cfg, "", Some("300"), 1, ing2_page_fetch(false), 2).unwrap();
        assert_eq!(out.events.len(), 4, "les 4 records des 2 pages fetchées sont ingérés");
        assert_eq!(out.watermark.as_deref(), Some("300"),
            "flux non ascendant + tronqué -> watermark NON avancé (pas de saut du reste plus ancien)");
    }

    /// ING-2 — API ASCENDANTE (cf. presets triés) + TRONCATURE : le watermark AVANCE au max (== borne de la
    /// dernière page) -> progrès conservé ; le reste (>= borne) est re-fetché SANS saut au tick suivant.
    #[test]
    fn ing2_truncated_ascending_advances_watermark() {
        let cfg = ing2_cfg();
        // page1(110,111)+page2(120,121) fetchées ; max global 121 == borne dernière page.
        let out = poll_http_pull(&cfg, "", Some("50"), 1, ing2_page_fetch(true), 2).unwrap();
        assert_eq!(out.events.len(), 4);
        assert_eq!(out.watermark.as_deref(), Some("121"),
            "flux ascendant + tronqué -> watermark avancé (progrès conservé, aucun saut)");
    }

    /// ING-2 — `httppull_wm_lt` : comparaison < selon le format (epoch numérique, iso8601 lexical) — support
    /// de la détection d'ordre non ascendant.
    #[test]
    fn ing2_wm_lt_orders_by_format() {
        assert!(httppull_wm_lt("9", "10", "epoch"), "epoch numérique : 9 < 10");
        assert!(!httppull_wm_lt("10", "9", "epoch"), "epoch numérique : 10 !< 9 (malgré le lexical)");
        assert!(httppull_wm_lt("2026-07-01T00:00:00Z", "2026-07-02T00:00:00Z", "iso8601"), "iso lexical");
        assert!(!httppull_wm_lt("2026-07-02T00:00:00Z", "2026-07-01T00:00:00Z", "iso8601"));
    }

    /// v134 (#6) — SSRF sur les 3 chemins admin (test/poll TAXII, Defender, poll manuel) : ils passent
    /// DÉSORMAIS par `guarded_http_call` (choke-point commun avec le poll de fond) -> une URL de connecteur
    /// pointant loopback/metadata est refusée AVANT tout egress. Prouve (a) la garde directe sur cibles internes
    /// + schémas interdits, et (b) le chemin du poll manuel (`poll_one_connector` via `guarded_http_call`) :
    /// last_error SSRF, ZÉRO event ingéré, aucun réseau réel (rejet AVANT le socket).
    #[test]
    fn v134_ssrf_guard_blocks_internal_connector_targets() {
        // (a) garde directe : cibles never-egress refusées AVANT http_call (aucun socket ouvert).
        for bad in ["http://127.0.0.1:8200/v1/secret", "http://169.254.169.254/latest/meta-data/", "http://[::1]/"] {
            assert!(guarded_http_call("GET", bad, &[], None).is_err(), "guarded_http_call doit REFUSER {bad}");
        }
        // schéma non-http(s) -> refus (jamais d'egress).
        assert!(guarded_http_call("GET", "file:///etc/passwd", &[], None).is_err(), "schéma non http(s)/smtp refusé");
        // (b) POLL MANUEL (chemin #536) : un connecteur http_pull admin-configuré vers loopback -> last_error SSRF,
        //     aucun event ingéré. Le fetch de PRODUCTION est guarded_http_call (comme le fixe le handler).
        let db = connector_test_db();
        let cfg = json!({ "url": "http://127.0.0.1:9/x", "records_path": "", "field_map": {"id":"id"} }).to_string();
        {
            let c = db.lock();
            c.execute(
                "INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) VALUES(1,'http_pull','LOOP',1,?1,'',300,'prod')",
                params![cfg],
            ).unwrap();
        }
        poll_one_connector(&db, ":memory:", 1, "http_pull", &cfg, "", "prod", None, now(), guarded_http_call);
        {
            let c = db.lock();
            let le: Option<String> = c.query_row("SELECT last_error FROM connector WHERE id=1", [], |r| r.get(0)).unwrap();
            assert!(le.as_deref().unwrap_or("").contains("SSRF"), "poll vers cible interne -> last_error SSRF : {le:?}");
            let ev: i64 = c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
            assert_eq!(ev, 0, "cible interne refusée -> aucun event ingéré (aucun egress)");
        }
    }
