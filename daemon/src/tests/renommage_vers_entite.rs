    // ============================================================================================
    // P4.12-b — LE RENOMMAGE CHAMP->COLONNE D'ENTITÉ ATTEINT TOUTES LES VOIES D'ENTRÉE, ET CE QUI RESTE
    // SANS ADRESSE EST COMPTÉ (2026-09-10). Le levier est l'action `rename` du moteur des processeurs, qui
    // s'exécute après la promotion sur la voie générique ET sur la voie journald (ralliée par ce lot) ;
    // la mesure est le compte, par source, des lignes ÉCRITES sans adresse source.
    // ============================================================================================

    /// L'adresse source de la ligne ÉCRITE pour (source, message) — la clé de dédup stockée n'est pas la clé brute.
    fn src_ip_de(conn: &Connection, source: &str, message: &str) -> Option<String> {
        conn.query_row("SELECT src_ip FROM event WHERE source=?1 AND message=?2", params![source, message], |r| r.get::<_, Option<String>>(0))
            .unwrap_or_else(|e| panic!("aucune ligne écrite pour {source} / {message} : {e}"))
    }

    #[test]
    fn p4_12b_un_rename_promeut_un_champ_vendeur_en_adresse_source_sur_la_voie_generique() {
        let conn = test_db();
        let dbp = "p412b-rename";
        // OTLP : l'adresse arrive sous `otel.client.address` ; HEC : sous `src`. Deux règles, une par source.
        add_ingest_rule(&conn, dbp, 0, "source", "eq", "otel-svc-p412b-a", "rename", "fields.otel.client.address->src_ip");
        add_ingest_rule(&conn, dbp, 1, "source", "eq", "hec-x-p412b-a", "rename", "fields.src->src_ip");
        let events = vec![
            json!({"ts": 1, "source": "otel-svc-p412b-a", "category": "trace", "message": "span", "fields": {"otel.client.address": "10.0.0.7"}, "dedup": "o1"}),
            json!({"ts": 2, "source": "hec-x-p412b-a", "category": "auth", "message": "login", "fields": {"src": "10.0.0.9"}, "dedup": "h1"}),
            json!({"ts": 3, "source": "autre-p412b-a", "category": "auth", "message": "sans règle", "fields": {"src": "10.0.0.1"}, "dedup": "a1"}),
        ];
        ingest_events_batch(&conn, dbp, &events, 1, None, None).unwrap();
        assert_eq!(src_ip_de(&conn, "otel-svc-p412b-a", "span").as_deref(), Some("10.0.0.7"), "l'attribut OTLP est devenu l'adresse source");
        assert_eq!(src_ip_de(&conn, "hec-x-p412b-a", "login").as_deref(), Some("10.0.0.9"), "la clé HEC est devenue l'adresse source");
        assert_eq!(src_ip_de(&conn, "autre-p412b-a", "sans règle"), None, "sans règle pour sa source, rien n'est promu — le prédicat par source tient");
        let c = processors_counters_json(dbp);
        assert_eq!(c["totals"]["renamed"], 2, "deux lignes renommées, comptées");
        assert!(crate::metrics::sans_adresse_source_de("otel-svc-p412b-a").is_none(), "une source renommée n'est pas comptée sans adresse (nom de source propre à ce témoin : le compte est un static global clé par source)");
        assert_eq!(crate::metrics::sans_adresse_source_de("autre-p412b-a"), Some(1), "la source sans règle est comptée sans adresse");
        // L'origine reste dans `fields` : renommer, c'est promouvoir, pas perdre.
        let f: String = conn.query_row("SELECT fields FROM event WHERE source='otel-svc-p412b-a'", [], |r| r.get(0)).unwrap();
        assert!(f.contains("otel.client.address"), "l'origine est conservée : {f}");
    }

    #[test]
    fn p4_12b_une_colonne_deja_posee_par_le_producteur_gagne_et_la_preemption_est_comptee() {
        let conn = test_db();
        let dbp = "p412b-preempte";
        add_ingest_rule(&conn, dbp, 0, "source", "eq", "otel-svc-p412b-b", "rename", "fields.otel.client.address->src_ip");
        let avant = crate::metrics::CHAMPS_PREEMPTES.lock().map(|m| m.get("src_ip").copied().unwrap_or(0)).unwrap();
        let events = vec![
            json!({"ts": 1, "source": "otel-svc-p412b-b", "category": "trace", "message": "span-p1", "src_ip": "1.1.1.1", "fields": {"otel.client.address": "10.0.0.7"}, "dedup": "p1"}),
            json!({"ts": 2, "source": "otel-svc-p412b-b", "category": "trace", "message": "span-p2", "src_ip": "10.0.0.7", "fields": {"otel.client.address": "10.0.0.7"}, "dedup": "p2"}),
            json!({"ts": 3, "source": "otel-svc-p412b-b", "category": "trace", "message": "span-p3", "fields": {}, "dedup": "p3"}),
        ];
        ingest_events_batch(&conn, dbp, &events, 1, None, None).unwrap();
        assert_eq!(src_ip_de(&conn, "otel-svc-p412b-b", "span-p1").as_deref(), Some("1.1.1.1"), "la valeur du producteur gagne");
        let apres = crate::metrics::CHAMPS_PREEMPTES.lock().map(|m| m.get("src_ip").copied().unwrap_or(0)).unwrap();
        assert_eq!(apres - avant, 1, "une préemption (valeur DIFFÉRENTE) comptée sous la clé cible ; une valeur égale ne fait taire rien");
        assert_eq!(processors_counters_json(dbp)["totals"]["renamed"], 0, "aucune cible écrite : ni préemptée, ni sans origine");
        assert_eq!(crate::metrics::sans_adresse_source_de("otel-svc-p412b-b"), Some(1), "la ligne sans origine est écrite sans adresse, et comptée");
    }

    #[test]
    fn p4_12b_une_cible_hors_entite_est_refusee_a_la_compilation() {
        let dbp = "p412b-compile";
        let compile = |arg: &str| compile_rule(dbp, 1, "source", "eq", "x", "rename", arg).map(|_| ());
        assert!(compile("fields.a->src_ip").is_ok());
        assert!(compile("fields.a->fields.b").is_ok(), "le sac fields est une cible admise");
        assert!(compile("fields.a->category").is_err(), "category est une dimension de détection");
        assert!(compile("fields.a->severity").is_err());
        assert!(compile("fields.a->message").is_err(), "le texte n'est pas une cible");
        assert!(compile("fields.a->source").is_err(), "l'identité du producteur n'est pas une cible");
        assert!(compile("src_ip->src_ip").is_err(), "rename vers soi-même");
        assert!(compile("fields.a src_ip").is_err(), "sans flèche, pas de rename");
        assert!(compile("fields.a->pas_un_champ").is_err(), "cible hors allowlist");
    }

    #[test]
    fn p4_12b_les_evenements_ecrits_sans_adresse_source_sont_comptes_par_source_et_publies() {
        let conn = test_db();
        let dbp = "p412b-sans-adresse";
        let source = "loki-app-p412b";
        let events = vec![
            json!({"ts": 1, "source": source, "category": "log", "message": "l1", "fields": {"job": "app"}, "dedup": "l1"}),
            json!({"ts": 2, "source": source, "category": "log", "message": "l2", "fields": {"job": "app"}, "dedup": "l2"}),
            json!({"ts": 3, "source": source, "category": "log", "message": "l3", "src_ip": "10.0.0.3", "dedup": "l3"}),
        ];
        ingest_events_batch(&conn, dbp, &events, 1, None, None).unwrap();
        assert_eq!(crate::metrics::sans_adresse_source_de(source), Some(2), "deux lignes écrites sans adresse, la troisième en porte une");
        let m = crate::gather_json(&conn, "/spool", dbp, 0, 80);
        assert!(m["ingest"]["events_without_src_ip_total"].as_u64().unwrap_or(0) >= 2, "le total est publié dans /api/metrics");
        assert_eq!(m["ingest"]["sources_without_src_ip"][source], 2, "la ventilation par source est publiée");
        // L'exposition Prometheus est une inscription statique : elle se lit dans le texte du module (le rendu
        // du texte Prometheus est tenu par ses propres témoins, sur la table d'inscriptions entière).
        assert!(include_str!("../metrics.rs").contains("\"plume_ingest_events_without_src_ip_total\""), "la métrique Prometheus est inscrite");
    }

    #[test]
    fn p4_12b_la_voie_journald_passe_par_les_processeurs_et_compte_ses_lignes_sans_adresse() {
        let conn = test_db();
        let dbp = "p412b-journald";
        // Avant ce lot, aucune règle ne s'appliquait à journald : MASK, DROP et RENAME y passaient à côté.
        add_ingest_rule(&conn, dbp, 0, "source", "eq", "sshd", "mask", "message");
        add_ingest_rule(&conn, dbp, 1, "source", "eq", "cron", "drop", "");
        let sshd_avant = crate::metrics::sans_adresse_source_de("sshd").unwrap_or(0);
        let lignes = [
            r#"{"__REALTIME_TIMESTAMP":"1700000000000000","_COMM":"sshd","MESSAGE":"Failed password for root from 203.0.113.5 port 22 ssh2","PRIORITY":"6","__CURSOR":"j1","_HOSTNAME":"h1"}"#,
            r#"{"__REALTIME_TIMESTAMP":"1700000001000000","_COMM":"sshd","MESSAGE":"session opened for user root","PRIORITY":"6","__CURSOR":"j2","_HOSTNAME":"h1"}"#,
            r#"{"__REALTIME_TIMESTAMP":"1700000002000000","_COMM":"cron","MESSAGE":"job ran","PRIORITY":"6","__CURSOR":"j3","_HOSTNAME":"h1"}"#,
        ].join("\n");
        let n = ingest_journal_lines(&conn, dbp, &lignes, None).unwrap();
        assert_eq!(n, 3, "les trois lignes sont traitées (la droppée est comptée, pas écrite)");
        let ecrites: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE source IN ('sshd','cron')", [], |r| r.get(0)).unwrap();
        assert_eq!(ecrites, 2, "la ligne cron est DROPPÉE par le processeur — la voie journald y passe désormais");
        let lignes_sshd: Vec<(Option<String>, String)> = conn
            .prepare("SELECT src_ip, message FROM event WHERE source='sshd' ORDER BY ts").unwrap()
            .query_map([], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, String>(1)?))).unwrap().flatten().collect();
        assert_eq!(lignes_sshd.len(), 2);
        assert_eq!(lignes_sshd[0].1, "[redacted]", "MASK s'applique à journald");
        assert_eq!(lignes_sshd[0].0.as_deref(), Some("203.0.113.5"), "l'adresse extraite du message est conservée");
        assert_eq!(lignes_sshd[1].0, None, "la seconde ligne n'a pas d'adresse dans son message");
        assert_eq!(processors_counters_json(dbp)["totals"]["dropped"], 1);
        assert_eq!(crate::metrics::sans_adresse_source_de("sshd").unwrap_or(0) - sshd_avant, 1, "la ligne sans adresse dans son message est comptée pour sa source (delta : `sshd` est une source que d'autres témoins écrivent)");
    }
