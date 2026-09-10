    // ============================================================================================
    // P11.22-g — LES VINGT LISTES BORNÉES QUI RESTAIENT MUETTES DISENT LEUR COUPE (2026-09-10).
    // Douze fonctions, vingt énoncés, trois portes du fabricant `handlers::liste_bornee` : `corps` (la liste
    // EST le corps), `poser_la_sous_liste` (la liste vit dans un corps plus grand), `couper_le_corps_a_la_borne`
    // (la borne enveloppe une requête COMPILÉE). Chaque témoin FABRIQUE une population qui dépasse la borne
    // d'une ligne, mesure la coupe par la ligne excédentaire, puis retombe à la borne exacte et vérifie que
    // rien n'est avoué à tort — un aveu inconditionnel serait le défaut symétrique de celui qu'on ferme.
    // La reconnaissance textuelle de ces portes est tenue par `une_liste_bornee_servie_dit_ce_qu_elle_borne`.
    // ============================================================================================

    fn b64_basic(id: &str) -> String {
        use base64::Engine as _;
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(id))
    }

    #[test]
    fn p11_22g_la_ligne_de_temps_du_portail_client_dit_sa_coupe() {
        use crate::handlers::caseops::{client_case_get_json, CLIENT_CASE_TIMELINE_WINDOW};
        let conn = test_db();
        let id = case_create_row(&conn, "alice", "Portail", 2, "", None, 3);
        let masks = guatx_core::soql::FieldMaskSet::new();
        let borne = CLIENT_CASE_TIMELINE_WINDOW as usize;
        // La population de la ligne de temps servie : les items dont le `kind` est dans l'allowlist du portail.
        let compte = |c: &Connection| -> i64 {
            c.query_row("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind IN ('created','status','sla','merge')", params![id], |r| r.get(0)).unwrap()
        };
        let deja = compte(&conn);
        for k in 0..(borne as i64 + 1 - deja) {
            conn.execute("INSERT INTO incident_item(incident_id,ts,kind,author,body) VALUES(?1,?2,'status','a','')", params![id, 2000 + k]).unwrap();
        }
        assert_eq!(compte(&conn), borne as i64 + 1, "population : la borne plus une");
        let c = client_case_get_json(&conn, ":memory:", &masks, id, now()).unwrap();
        assert_eq!(c["timeline"].as_array().unwrap().len(), borne, "la ligne de temps est servie à la borne");
        assert_eq!(c["timeline_served"], borne, "`timeline_served`");
        assert_eq!(c["timeline_window"], borne, "`timeline_window`");
        assert_eq!(c["timeline_truncated"], true, "la ligne excédentaire fonde l'aveu");
        // PILE la borne : rien à avouer.
        conn.execute("DELETE FROM incident_item WHERE id=(SELECT MAX(id) FROM incident_item WHERE incident_id=?1)", params![id]).unwrap();
        let c = client_case_get_json(&conn, ":memory:", &masks, id, now()).unwrap();
        assert_eq!(c["timeline"].as_array().unwrap().len(), borne);
        assert_eq!(c["timeline_truncated"], false, "à la borne exacte, aucune coupe n'est avouée");
    }

    #[test]
    fn p11_22g_les_files_par_assigne_disent_leur_total_borne() {
        use crate::handlers::caseops::{case_queues_json, CASE_QUEUES_WINDOW};
        let conn = test_db();
        let borne = CASE_QUEUES_WINDOW as usize;
        for n in 0..(borne + 1) {
            case_create_row(&conn, "alice", &format!("Q{n}"), 2, "", Some(&format!("a{n:04}")), 3);
        }
        let q = case_queues_json(&conn, now());
        assert_eq!(q["queues"].as_array().unwrap().len(), borne, "les files sont servies à la borne");
        assert_eq!(q["served"], borne);
        assert_eq!(q["window"], borne);
        assert_eq!(q["total"], borne, "le total est plafonné à la borne…");
        assert_eq!(q["total_capped"], true, "…et le plafonnement est DIT");
        // Un seul assigné de moins : la borne ne mord plus, le total est exact.
        conn.execute("DELETE FROM incident WHERE assignee='a0000'", []).unwrap();
        let q = case_queues_json(&conn, now());
        assert_eq!(q["served"], borne);
        assert_eq!(q["total_capped"], false);
        assert_eq!(q["total"], borne);
    }

    #[test]
    fn p11_22g_les_liens_d_un_dossier_disent_leur_coupe() {
        use crate::handlers::caseops::{case_link_add, case_links_json, CASE_LINKS_WINDOW};
        let conn = test_db();
        let borne = CASE_LINKS_WINDOW as usize;
        let a = case_create_row(&conn, "alice", "A", 2, "", None, 3);
        for n in 0..(borne + 1) {
            let b = case_create_row(&conn, "alice", &format!("B{n}"), 2, "", None, 3);
            assert!(case_link_add(&conn, a, b, "related", "", "bob"));
        }
        let l = case_links_json(&conn, a);
        assert_eq!(l["links"].as_array().unwrap().len(), borne);
        assert_eq!(l["served"], borne);
        assert_eq!(l["window"], borne);
        assert_eq!(l["total_capped"], true, "deux cent un liens : la coupe est dite");
        assert!(l.get("error").is_none(), "une lecture qui a abouti ne porte pas d'erreur");
    }

    #[test]
    fn p11_22g_les_metriques_de_dossiers_disent_leur_echantillon_et_leurs_fenetres() {
        use crate::handlers::caseops::{case_metrics_json, CASE_METRICS_BY_ASSIGNEE_WINDOW, CASE_METRICS_BY_SEVERITY_WINDOW, CASE_METRICS_SAMPLE_WINDOW};
        let conn = test_db();
        let base = now();
        let c1 = case_create_row(&conn, "alice", "Q1", 3, "", Some("alice"), 2);
        conn.execute("UPDATE incident SET ts=?1, first_response_ts=?2, closed_ts=?3, status='resolved' WHERE id=?4", params![base - 1000, base - 950, base - 800, c1]).unwrap();
        let m = case_metrics_json(&conn, base - 2000, base);
        assert_eq!(m["overall"]["mtta_mean"], 50, "la mesure elle-même est inchangée");
        assert_eq!(m["sample_window"], CASE_METRICS_SAMPLE_WINDOW, "la fenêtre de l'échantillon est rendue");
        assert_eq!(m["sample_size"], 1, "un seul dossier résolu dans la fenêtre");
        assert_eq!(m["sample_truncated"], false, "un échantillon sous la borne n'est pas avoué coupé");
        assert_eq!(m["by_assignee_window"], CASE_METRICS_BY_ASSIGNEE_WINDOW);
        assert_eq!(m["by_assignee_served"], 1);
        assert_eq!(m["by_assignee_truncated"], false);
        assert_eq!(m["by_severity_window"], CASE_METRICS_BY_SEVERITY_WINDOW);
        assert_eq!(m["by_severity_truncated"], false);
        assert!(m["by_assignee"].is_array() && m["by_severity"].is_array(), "les deux ventilations restent des tableaux");
        // Une ventilation par assigné qui dépasse sa borne est coupée ET dite.
        for n in 0..(CASE_METRICS_BY_ASSIGNEE_WINDOW as usize) {
            let c = case_create_row(&conn, "alice", &format!("R{n}"), 2, "", Some(&format!("r{n:04}")), 3);
            conn.execute("UPDATE incident SET ts=?1, closed_ts=?2, status='resolved' WHERE id=?3", params![base - 900, base - 700, c]).unwrap();
        }
        let m = case_metrics_json(&conn, base - 2000, base);
        assert_eq!(m["by_assignee"].as_array().unwrap().len(), CASE_METRICS_BY_ASSIGNEE_WINDOW as usize);
        assert_eq!(m["by_assignee_truncated"], true, "deux cent un assignés résolus : la coupe est dite");
        assert_eq!(m["sample_size"], CASE_METRICS_BY_ASSIGNEE_WINDOW + 1, "l'échantillon, lui, tient tout");
    }

    #[tokio::test]
    async fn p11_22g_la_recherche_dit_quand_sa_borne_mord() {
        let (st, path) = router_test_state("recherche-bornee");
        {
            let conn = open_db(&path).unwrap();
            for k in 0..3 {
                conn.execute("INSERT INTO event(ts,source,category,severity,message,host) VALUES(?1,'sshd','auth',3,'échec','web1')", params![now() - k]).unwrap();
            }
        }
        let addr = router_serve(st).await;
        let root = b64_basic("root:rootpw1234567");
        let (code, corps) = lire_le_corps_entier(addr, "/api/search?q=host%3Aweb1%20limit%3A2", &root).await;
        assert_eq!(code, 200);
        let v: Value = serde_json::from_str(&corps).unwrap_or_else(|e| panic!("corps non-JSON ({e}) : {}", &corps[..corps.len().min(200)]));
        assert_eq!(v["results"].as_array().unwrap().len(), 2, "deux résultats servis pour `limit:2`");
        assert_eq!(v["served"], 2);
        assert_eq!(v["window"], 2);
        assert_eq!(v["truncated"], true, "trois événements, borne à deux : la borne a mordu et la réponse le dit");
        let (_, corps) = lire_le_corps_entier(addr, "/api/search?q=host%3Aweb1%20limit%3A3", &root).await;
        let v: Value = serde_json::from_str(&corps).unwrap();
        assert_eq!(v["served"], 3);
        assert_eq!(v["truncated"], false, "à la borne exacte, aucune coupe n'est avouée");
    }

    #[test]
    fn p11_22g_le_paquet_de_diagnostic_dit_ses_trois_coupes() {
        use crate::handlers::system::{diag_bundle_json, DIAG_HEARTBEAT_ALERTS_WINDOW, DIAG_RECENT_EVENTS_WINDOW, DIAG_UNCLASSIFIED_SOURCES_WINDOW};
        let c = day2_conn();
        for k in 0..(DIAG_RECENT_EVENTS_WINDOW + 1) {
            c.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'plume-disk','ops',2,'disque')", params![now() - k]).unwrap();
        }
        for k in 0..(DIAG_UNCLASSIFIED_SOURCES_WINDOW + 1) {
            c.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,?2,'',2,'sans catégorie')", params![now() - k, format!("src-{k:03}")]).unwrap();
        }
        let b = diag_bundle_json(&c, "/spool", "", 80);
        assert_eq!(b["recent_events"].as_array().unwrap().len(), DIAG_RECENT_EVENTS_WINDOW as usize);
        assert_eq!(b["recent_events_window"], DIAG_RECENT_EVENTS_WINDOW);
        assert_eq!(b["recent_events_truncated"], true, "trente et un événements opérationnels : la coupe est dite");
        assert_eq!(b["unclassified_by_source"].as_array().unwrap().len(), DIAG_UNCLASSIFIED_SOURCES_WINDOW as usize);
        assert_eq!(b["unclassified_by_source_truncated"], true, "vingt et un émetteurs sans catégorie : la coupe est dite");
        assert_eq!(b["heartbeat_alerts_window"], DIAG_HEARTBEAT_ALERTS_WINDOW);
        assert_eq!(b["heartbeat_alerts_served"], 0);
        assert_eq!(b["heartbeat_alerts_truncated"], false, "aucune alerte de capteur muet : rien n'est avoué à tort");
    }

    #[tokio::test]
    async fn p11_22g_la_ligne_de_temps_d_une_entite_a_risque_dit_sa_coupe() {
        use crate::handlers::rba::RISK_ENTITY_CONTRIBUTIONS_WINDOW;
        let (st, path) = router_test_state("risque-borne");
        {
            let conn = open_db(&path).unwrap();
            for k in 0..(RISK_ENTITY_CONTRIBUTIONS_WINDOW + 1) {
                conn.execute("INSERT INTO risk_event(ts,entity_type,entity,risk_score,source,rule_id,reason,mitre,severity) VALUES(?1,'host','web1',1,'s',NULL,'r','',1)", params![now() - k]).unwrap();
            }
        }
        let addr = router_serve(st).await;
        let (code, corps) = lire_le_corps_entier(addr, "/api/risk/entity/host/web1", &b64_basic("root:rootpw1234567")).await;
        assert_eq!(code, 200);
        let v: Value = serde_json::from_str(&corps).unwrap_or_else(|e| panic!("corps non-JSON ({e}) : {}", &corps[..corps.len().min(200)]));
        assert_eq!(v["contributions"].as_array().unwrap().len(), RISK_ENTITY_CONTRIBUTIONS_WINDOW as usize);
        assert_eq!(v["contributions_served"], RISK_ENTITY_CONTRIBUTIONS_WINDOW);
        assert_eq!(v["contributions_window"], RISK_ENTITY_CONTRIBUTIONS_WINDOW);
        assert_eq!(v["contributions_truncated"], true, "deux cent une contributions : la coupe est dite");
    }

    #[test]
    fn p11_22g_la_datasource_et_le_rapport_disent_la_coupe_d_une_requete_compilee() {
        use crate::handlers::datasource::ds_soql_exec;
        use crate::handlers::liste_bornee::couper_le_corps_a_la_borne;
        use crate::handlers::scheduled_reports::{render_report_detail, REPORT_DETAIL_WINDOW};
        // La troisième porte, seule : trois lignes, borne deux -> deux servies, coupe dite ; borne trois -> rien.
        let mut corps = json!({ "columns": ["a"], "rows": [[1], [2], [3]] });
        couper_le_corps_a_la_borne(&mut corps, "rows", 2);
        assert_eq!(corps["rows"].as_array().unwrap().len(), 2);
        assert_eq!((corps["served"].clone(), corps["window"].clone(), corps["truncated"].clone()), (json!(2), json!(2), json!(true)));
        let mut corps = json!({ "columns": ["a"], "rows": [[1], [2], [3]] });
        couper_le_corps_a_la_borne(&mut corps, "rows", 3);
        assert_eq!(corps["truncated"], false, "à la borne exacte, rien n'est avoué");
        let mut sans = json!({ "columns": [] });
        couper_le_corps_a_la_borne(&mut sans, "rows", 3);
        assert_eq!((sans["served"].clone(), sans["truncated"].clone()), (json!(0), json!(false)), "un corps sans lignes n'a rien coupé");
        // La datasource, sur une base réelle de deux événements : `limit=1` mord, `limit=2` non.
        let path = ds_seed_db("coupe-compilee");
        let v = ds_soql_exec(&path, "admin", "default", None, "search | table src_user, message", 0, 0, Some(1), 5000).unwrap();
        assert_eq!(v["rows"].as_array().unwrap().len(), 1);
        assert_eq!((v["served"].clone(), v["window"].clone(), v["truncated"].clone()), (json!(1), json!(1), json!(true)));
        let v = ds_soql_exec(&path, "admin", "default", None, "search | table src_user, message", 0, 0, Some(2), 5000).unwrap();
        assert_eq!(v["truncated"], false);
        // Le rapport planifié : deux lignes, pas de coupe ; cinq mille et une, la coupe est DITE dans le texte livré.
        let (n, texte) = render_report_detail(&path, "rpt", "admin", "default", "search | table src_user, message").unwrap();
        assert_eq!(n, 2);
        assert!(!texte.contains("LISTE COUPÉE"), "deux lignes : rien à avouer");
        {
            let conn = open_db(&path).unwrap();
            conn.execute_batch("BEGIN").unwrap();
            for k in 0..(REPORT_DETAIL_WINDOW - 1) {
                conn.execute("INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,'sshd','auth',3,'h3','login carol')", params![now() - 10 - k]).unwrap();
            }
            conn.execute_batch("COMMIT").unwrap();
        }
        let (n, texte) = render_report_detail(&path, "rpt", "admin", "default", "search | table src_user, message").unwrap();
        assert_eq!(n, REPORT_DETAIL_WINDOW, "le compte livré est celui des lignes SERVIES, pas de la population");
        assert!(texte.contains(&format!("LISTE COUPÉE à {REPORT_DETAIL_WINDOW} lignes")), "le texte livré dit la coupe : {}", texte.lines().last().unwrap_or(""));
    }

    #[tokio::test]
    async fn p11_22g_le_navigateur_d_etiquettes_prometheus_avertit_quand_la_liste_est_coupee() {
        use crate::handlers::datasource::{PROM_LABELS_SAMPLE_WINDOW, PROM_LABEL_VALUES_WINDOW};
        let (st, path) = router_test_state("prom-borne");
        {
            let conn = open_db(&path).unwrap();
            conn.execute_batch("BEGIN").unwrap();
            for k in 0..(PROM_LABEL_VALUES_WINDOW + 1) {
                conn.execute("INSERT INTO metric(ts,name,labels,value,host) VALUES(?1,'node_load1',?2,0.5,?3)", params![now() - k, format!(r#"{{"k{k}":"v"}}"#), format!("h{k:05}")]).unwrap();
            }
            conn.execute_batch("COMMIT").unwrap();
        }
        let addr = router_serve(st).await;
        let root = b64_basic("root:rootpw1234567");
        // Valeurs d'une étiquette : cinq mille et un hôtes distincts -> cinq mille servis et un avertissement Prometheus.
        let (code, corps) = lire_le_corps_entier(addr, "/api/v1/label/host/values", &root).await;
        assert_eq!(code, 200);
        let v: Value = serde_json::from_str(&corps).unwrap_or_else(|e| panic!("corps non-JSON ({e}) : {}", &corps[..corps.len().min(200)]));
        assert_eq!(v["status"], "success");
        assert_eq!(v["data"].as_array().unwrap().len(), PROM_LABEL_VALUES_WINDOW as usize);
        let avertissement = v["warnings"][0].as_str().expect("un avertissement Prometheus porte la coupe");
        assert!(avertissement.contains(&PROM_LABEL_VALUES_WINDOW.to_string()), "l'avertissement nomme la borne : {avertissement}");
        // Un seul nom de métrique : aucune coupe, aucun avertissement — la réponse reste celle d'avant.
        let (_, corps) = lire_le_corps_entier(addr, "/api/v1/label/__name__/values", &root).await;
        let v: Value = serde_json::from_str(&corps).unwrap();
        assert_eq!(v["data"].as_array().unwrap().len(), 1);
        assert!(v.get("warnings").is_none(), "sans coupe, pas d'avertissement");
        // Les NOMS d'étiquettes : l'union est calculée sur les deux mille blobs les plus récents, et cela est dit.
        let (_, corps) = lire_le_corps_entier(addr, "/api/v1/labels", &root).await;
        let v: Value = serde_json::from_str(&corps).unwrap();
        let avertissement = v["warnings"][0].as_str().expect("l'échantillon de blobs a été coupé : avertissement");
        assert!(avertissement.contains(&PROM_LABELS_SAMPLE_WINDOW.to_string()), "l'avertissement nomme la borne de l'échantillon : {avertissement}");
        assert!(v["data"].as_array().unwrap().len() >= 2, "les clés `__name__` et `host` au moins");
    }
