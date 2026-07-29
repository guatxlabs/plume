    // ============================================================================================
    // #37 DÉTECTION AVANCÉE — corrélation multi-événements stateful + baselining statistique (UEBA).
    // ============================================================================================

    /// EXEC-LEVER (Wave 3) — les deux règles catalogue auditd/exec de ce lot COMPILENT via rule_sql (sinon
    /// le loader d'overlay les WARN+skip -> détection inerte). (a) exec-depuis-un-dir-monde-inscriptible
    /// ÉTENDU aux 4 racines (/tmp, /dev/shm, /var/tmp, /run) via `append` — SOQL ne sait pas OU-er un
    /// préfixe dans le filtre de base (le `|` d'alternation regex casse le découpage d'étapes) ; (b) le
    /// dead-man's-switch anti-forensics `source=auditd | stats count` avec op '<' seuil 1 (fire quand le
    /// COUNT tombe à 0 = auditd tué). Garde-fou : ces requêtes doivent rester compilables.
    #[test]
    fn exec_lever_catalog_rules_compile() {
        let exec_from_tmp = "search source=auditd category=exec exe=/tmp/* | append [search source=auditd category=exec exe=/dev/shm/*] | append [search source=auditd category=exec exe=/var/tmp/*] | append [search source=auditd category=exec exe=/run/*] | stats count";
        rule_sql(exec_from_tmp, true, 900).unwrap_or_else(|e| panic!("exec-from-tmp étendu ne compile pas: {e}"));
        let auditd_silent = "search source=auditd | stats count";
        rule_sql(auditd_silent, true, 600).unwrap_or_else(|e| panic!("auditd-silent heartbeat ne compile pas: {e}"));
    }

    /// (#37-a) ALGORITHME PUR d'appariement de séquence : matche une chaîne ORDONNÉE, décline un ordre
    /// inversé, une étape manquante, ou un min_count non atteint.
    #[test]
    fn correlation_match_pure_sequence() {
        // 3× étape0 (ts 10,11,12) PUIS étape1 (ts 20) : chaîne valide (min_counts 3,1).
        assert!(correlation_match(&[vec![10, 11, 12], vec![20]], &[3, 1]), "séquence ordonnée doit matcher");
        // étape1 AVANT étape0 (ts 5 < 10) : pas de chaîne (l'unique event étape1 précède l'ancre étape0).
        assert!(!correlation_match(&[vec![10, 11, 12], vec![5]], &[3, 1]), "ordre inversé ne doit PAS matcher");
        // étape1 VIDE (event manquant) : pas de chaîne.
        assert!(!correlation_match(&[vec![10, 11, 12], vec![]], &[3, 1]), "étape manquante ne doit PAS matcher");
        // min_count non atteint à l'étape0 (2 events, need 3).
        assert!(!correlation_match(&[vec![10, 11], vec![20]], &[3, 1]), "min_count non atteint ne doit PAS matcher");
        // 3 étapes recon->exploit->c2, ancres strictement croissantes.
        assert!(correlation_match(&[vec![1], vec![2], vec![3]], &[1, 1, 1]), "3 étapes ordonnées doivent matcher");
        assert!(!correlation_match(&[vec![3], vec![2], vec![1]], &[1, 1, 1]), "3 étapes désordonnées : non");
    }

    /// (#37-b) ORDONNANCEUR run_correlations : une séquence « failed-auth ×3 puis success même IP » DOIT lever
    /// UN finding-group (alerte `corr-<id>-<entity>`), sur le CHEMIN PLANIFIÉ (pas le dry-run).
    #[test]
    fn scheduled_run_correlations_fires_on_sequence() {
        let mut path = std::env::temp_dir();
        path.push(format!("plume-corr-fire-{}-{}.db", std::process::id(), now()));
        let p = path.to_string_lossy().to_string();
        let base = now() - 100; // en fenêtre (window_s=3600)
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            let steps = r#"[{"name":"echec auth","query":"search source=auth outcome=fail","min_count":3},{"name":"succes","query":"search source=auth outcome=success","min_count":1}]"#;
            w.execute(
                "INSERT INTO correlation(name,enabled,key_field,entity_type,steps,window_s,interval_s,severity,mitre,risk_score,managed) \
                 VALUES('brute-force réussi',1,'src_ip','ip',?1,3600,300,4,'T1110',0,2)",
                params![steps],
            ).unwrap();
            // 3 échecs (ts base..base+2) PUIS 1 succès (base+30) depuis 9.9.9.9 -> chaîne valide.
            for i in 0..3 {
                w.execute("INSERT INTO event(ts,source,src_ip,fields,dedup) VALUES(?1,'auth','9.9.9.9','{\"outcome\":\"fail\"}',?2)", params![base + i, format!("f{i}")]).unwrap();
            }
            w.execute("INSERT INTO event(ts,source,src_ip,fields,dedup) VALUES(?1,'auth','9.9.9.9','{\"outcome\":\"success\"}','ok')", params![base + 30]).unwrap();
            // IP témoin : QUE des échecs (jamais de succès) -> ne DOIT pas matcher.
            for i in 0..5 {
                w.execute("INSERT INTO event(ts,source,src_ip,fields,dedup) VALUES(?1,'auth','1.1.1.1','{\"outcome\":\"fail\"}',?2)", params![base + i, format!("n{i}")]).unwrap();
            }
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_correlations(&db, &p);
        let (n, dedup, sev, mitre): (i64, String, i64, String) = {
            let c = db.lock();
            c.query_row(
                "SELECT COUNT(*), COALESCE(MAX(dedup),''), COALESCE(MAX(severity),0), COALESCE(MAX(mitre),'') FROM alert",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            ).unwrap()
        };
        let _ = std::fs::remove_file(&p);
        assert_eq!(n, 1, "run_correlations lève UN finding-group pour l'IP qui complète la séquence");
        assert_eq!(dedup, "corr-1-9.9.9.9", "dédup keyé (corrélation, entité)");
        assert_eq!(sev, 4, "sévérité héritée de la corrélation");
        assert_eq!(mitre, "T1110", "MITRE hérité (couverture purple)");
    }

    /// (#37-c) NON-DÉCLENCHEMENT sur séquence CASSÉE : que des échecs, jamais de succès -> aucun finding-group.
    #[test]
    fn scheduled_run_correlations_no_fire_on_broken_sequence() {
        let mut path = std::env::temp_dir();
        path.push(format!("plume-corr-nofire-{}-{}.db", std::process::id(), now()));
        let p = path.to_string_lossy().to_string();
        let base = now() - 100;
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            let steps = r#"[{"name":"echec","query":"search source=auth outcome=fail","min_count":3},{"name":"succes","query":"search source=auth outcome=success","min_count":1}]"#;
            w.execute(
                "INSERT INTO correlation(name,enabled,key_field,entity_type,steps,window_s,interval_s,severity,mitre,risk_score,managed) \
                 VALUES('brute-force',1,'src_ip','ip',?1,3600,300,4,'T1110',0,2)",
                params![steps],
            ).unwrap();
            for i in 0..10 {
                w.execute("INSERT INTO event(ts,source,src_ip,fields,dedup) VALUES(?1,'auth','9.9.9.9','{\"outcome\":\"fail\"}',?2)", params![base + i, format!("f{i}")]).unwrap();
            }
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_correlations(&db, &p);
        let n: i64 = { let c = db.lock(); c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap() };
        let _ = std::fs::remove_file(&p);
        assert_eq!(n, 0, "séquence incomplète (jamais de succès) -> AUCUN finding-group");
    }

    /// (#37-d) FAIL-CLOSED ORDONNANCEUR : une corrélation dont une étape ERRE à l'évaluation (colonne de clé
    /// absente du résultat -> échec d'éval, PAS un « aucun match ») NE RÉSOUT PAS un finding-group ouvert.
    #[test]
    fn scheduled_run_correlations_eval_failure_fail_closed() {
        let mut path = std::env::temp_dir();
        path.push(format!("plume-corr-failclosed-{}-{}.db", std::process::id(), now()));
        let p = path.to_string_lossy().to_string();
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            // key_field = colonne INEXISTANTE dans la projection SOQL -> key_idx None -> ok=false (échec d'éval).
            let steps = r#"[{"name":"e","query":"search source=auth","min_count":1}]"#;
            w.execute(
                "INSERT INTO correlation(name,enabled,key_field,entity_type,steps,window_s,interval_s,severity,mitre,risk_score,managed) \
                 VALUES('corr-cassee',1,'colonne_absente','ip',?1,3600,300,3,'T1110',0,2)",
                params![steps],
            ).unwrap();
            let cid: i64 = w.query_row("SELECT id FROM correlation", [], |r| r.get(0)).unwrap();
            // finding-group DÉJÀ OUVERT pour cette corrélation (épisode en cours).
            w.execute(
                "INSERT INTO alert(ts,rule,severity,title,detail,dedup,status,mitre) VALUES(?1,?2,3,'épisode','x',?3,'new','T1110')",
                params![now(), format!("corr.{cid}"), format!("corr-{cid}-9.9.9.9")],
            ).unwrap();
            // event qui rendrait le résultat non vide (mais la clé reste introuvable).
            w.execute("INSERT INTO event(ts,source,src_ip,fields,dedup) VALUES(?1,'auth','9.9.9.9','{}','x')", params![now() - 10]).unwrap();
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_correlations(&db, &p);
        let (status, last_run_set): (String, i64) = {
            let c = db.lock();
            let s: String = c.query_row("SELECT status FROM alert", [], |r| r.get(0)).unwrap();
            let lr: i64 = c.query_row("SELECT CASE WHEN last_run IS NULL THEN 0 ELSE 1 END FROM correlation", [], |r| r.get(0)).unwrap();
            (s, lr)
        };
        let _ = std::fs::remove_file(&p);
        assert_eq!(status, "new", "un ÉCHEC d'éval ne RÉSOUT PAS le finding-group ouvert (fail-closed)");
        assert_eq!(last_run_set, 1, "last_run AVANCE quand même (re-tentera au prochain intervalle)");
    }

    /// (#37-e) SCORING de déviation (z-score) PUR : calcul correct, None si échantillon insuffisant ou
    /// variance nulle (jamais un z fabriqué / jamais de division par zéro).
    #[test]
    fn baseline_deviation_scoring_pure() {
        // historique {4,5,6,5,4,6,5,4,6,5} (mean=5.0), valeur 5 -> z≈0.
        let hist = [4.0, 5.0, 6.0, 5.0, 4.0, 6.0, 5.0, 4.0, 6.0, 5.0];
        let z0 = deviation_score(5.0, &hist, 5).unwrap();
        assert!(z0.abs() < 0.2, "valeur = moyenne -> z≈0 (obtenu {z0})");
        // valeur très au-dessus -> z largement > 3.
        let z = deviation_score(50.0, &hist, 5).unwrap();
        assert!(z > 3.0, "pic massif -> z>3 (obtenu {z})");
        assert!(baseline_anomaly(50.0, &hist, 5, 3.0).is_some(), "pic massif = anomalie");
        assert!(baseline_anomaly(5.0, &hist, 5, 3.0).is_none(), "valeur normale ≠ anomalie");
        // échantillon insuffisant (min_samples 5, 3 points) -> None.
        assert!(deviation_score(50.0, &[1.0, 2.0, 3.0], 5).is_none(), "historique < min_samples -> None");
        // variance nulle (série constante) -> None (pas de baseline exploitable).
        assert!(deviation_score(50.0, &[5.0, 5.0, 5.0, 5.0, 5.0], 5).is_none(), "variance nulle -> None");
    }

    /// (#37-f) ORDONNANCEUR run_baselines : un pic massif du bucket clos vs une baseline basse DOIT lever une
    /// anomalie (alerte `baseline-<id>-<entity>-<bucket>`), sur le CHEMIN PLANIFIÉ.
    #[test]
    fn scheduled_run_baselines_flags_anomaly() {
        let mut path = std::env::temp_dir();
        path.push(format!("plume-baseline-{}-{}.db", std::process::id(), now()));
        let p = path.to_string_lossy().to_string();
        let bucket_s = 3600i64;
        let cur = now() / bucket_s;
        let closed = cur - 1;
        let bstart = closed * bucket_s;
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            w.execute(
                "INSERT INTO ueba_baseline(name,enabled,query,is_soql,entity_type,entity_field,value_field,bucket_s,min_samples,z_threshold,window_s,interval_s,severity,mitre,risk_score,managed) \
                 VALUES('volume auth par hôte',1,'search source=auth | stats count by host',1,'host','host','',3600,5,3.0,604800,3600,3,'T1110',0,2)",
                [],
            ).unwrap();
            let bid: i64 = w.query_row("SELECT id FROM ueba_baseline", [], |r| r.get(0)).unwrap();
            // baseline basse : 10 buckets passés à ~5 (variance non nulle) pour l'hôte h1.
            let vals = [4.0, 5.0, 6.0, 5.0, 4.0, 6.0, 5.0, 4.0, 6.0, 5.0];
            for (k, v) in vals.iter().enumerate() {
                w.execute(
                    "INSERT INTO ueba_baseline_obs(baseline_id,entity_type,entity,bucket,value,env_id) VALUES(?1,'host','h1',?2,?3,'prod')",
                    params![bid, closed - 1 - (k as i64), v],
                ).unwrap();
            }
            // PIC : 60 events auth pour h1 DANS le bucket clos -> count=60 >> baseline ~5 -> z énorme.
            for i in 0..60 {
                w.execute("INSERT INTO event(ts,source,host,fields,dedup) VALUES(?1,'auth','h1','{}',?2)", params![bstart + 10, format!("p{i}")]).unwrap();
            }
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_baselines(&db, &p);
        let (nalert, dedup, obs): (i64, String, i64) = {
            let c = db.lock();
            let (n, d): (i64, String) = c.query_row("SELECT COUNT(*), COALESCE(MAX(dedup),'') FROM alert", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            let o: i64 = c.query_row("SELECT COUNT(*) FROM ueba_baseline_obs WHERE bucket=?1", params![closed], |r| r.get(0)).unwrap();
            (n, d, o)
        };
        let _ = std::fs::remove_file(&p);
        assert_eq!(nalert, 1, "un pic massif vs baseline basse -> UNE anomalie");
        assert_eq!(dedup, format!("baseline-1-h1-{closed}"), "dédup par (baseline, entité, bucket)");
        assert_eq!(obs, 1, "l'observation du bucket clos est persistée");
    }

    /// (#37-g) MODE 0 : sans corrélation ni baseline définie, run_correlations/run_baselines ne touchent RIEN
    /// (aucune alerte, aucune observation) -> tick byte-identique.
    #[test]
    fn advanced_detection_mode0_inert() {
        let mut path = std::env::temp_dir();
        path.push(format!("plume-adv-mode0-{}-{}.db", std::process::id(), now()));
        let p = path.to_string_lossy().to_string();
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            for i in 0..20 {
                w.execute("INSERT INTO event(ts,source,src_ip,fields,dedup) VALUES(?1,'auth','9.9.9.9','{\"outcome\":\"fail\"}',?2)", params![now() - 10, format!("e{i}")]).unwrap();
            }
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_correlations(&db, &p);
        run_baselines(&db, &p);
        let (na, no): (i64, i64) = {
            let c = db.lock();
            (c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap(),
             c.query_row("SELECT COUNT(*) FROM ueba_baseline_obs", [], |r| r.get(0)).unwrap())
        };
        let _ = std::fs::remove_file(&p);
        assert_eq!(na, 0, "mode 0 : aucune alerte");
        assert_eq!(no, 0, "mode 0 : aucune observation baseline");
    }

    /// (#37-h) MIGRATION v84 : les tables correlation/baseline/ueba_baseline_obs existent et sont VIDES.
    #[test]
    fn migration_v84_creates_empty_advanced_tables() {
        let conn = test_db();
        let ver: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert!(ver.parse::<i64>().unwrap() >= 84, "schema_version >= 84 (obtenu {ver})");
        for t in ["correlation", "ueba_baseline", "ueba_baseline_obs"] {
            let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "table {t} créée et vide (mode 0 inerte)");
        }
    }

    /// (3) CORRÉLATION path × src_ip (règle 21, T1595.002 web-scan, agg `dc`) : idem, décline -> raw exact.
    #[test]
    fn rollup_route_declines_dc_path_by_srcip_correlation_rule21() {
        assert!(try_rollup_route("search source=web status=404 | stats dc(path) by src_ip", 0, 0, None, i64::MAX).is_none(),
                "rule21 corrélation path×src_ip (dc + 2e filtre) DOIT décliner -> raw");
        let conn = test_db();
        let t = now() - 10;
        for i in 0..35 { // scanner 8.8.8.8 : 35 chemins 404 DISTINCTS (> seuil 30)
            conn.execute("INSERT INTO event(ts,source,severity,src_ip,fields) VALUES(?1,'web',2,'8.8.8.8',?2)",
                params![t, format!("{{\"status\":\"404\",\"path\":\"/scan{i}\"}}")]).unwrap();
        }
        let sql = soql_to_sql_x("search source=web status=404 | stats dc(path) by src_ip | where dc > 30 | stats count", 0, 0, None).unwrap();
        let got: i64 = conn.query_row(&sql, [], |r| r.get(0)).unwrap();
        assert_eq!(got, 1, "raw-scan doit voir 1 IP scannant >30 chemins (règle 21 TIRE) ; SQL={sql}");
    }

    /// (2) NON-RÉGRESSION : une requête que le rollup PEUT exprimer (filtre = `source=` seul, group-by = dim
    /// matérialisée) route TOUJOURS vers le rollup, SQL BYTE-IDENTIQUE au comportement historique.
    #[test]
    fn rollup_route_still_routes_expressible_queries() {
        // ROUTE A (by source) : counts exacts EN SOMME depuis event_rollup, mais grain HORAIRE -> approx:true
        // (QRY-1, jamais « exact » au sous-horaire) ; truncated:false (aucune source abandonnée).
        let a = try_rollup_route("search | stats count by source", 0, 0, None, i64::MAX).expect("A doit router");
        assert!(a.sql.contains("FROM event_rollup") && a.approx && !a.truncated, "A route event_rollup (approx horaire, non tronqué) : {}", a.sql);
        // ROUTE B (source=web | count by status) : status EST une dim web -> event_dim_rollup (approx/partiel).
        let b = try_rollup_route("search source=web | stats count by status", 0, 0, None, i64::MAX).expect("B doit router");
        assert_eq!(
            b.sql,
            "SELECT val AS \"status\", SUM(n) AS \"count\" FROM event_dim_rollup WHERE source='web' AND dim='status' GROUP BY val ORDER BY \"count\" DESC",
            "B : SQL rollup byte-identique (non-régression du fast-path)"
        );
        assert!(b.approx && b.truncated, "B : dim cappée top-N -> approx/partiel signalé");
        // src_ip N'EST PAS une dim web (colonne réelle exclue à dessein) -> même SANS 2e filtre, décline -> raw.
        assert!(try_rollup_route("search source=web | stats count by src_ip", 0, 0, None, i64::MAX).is_none(),
                "by src_ip (non pré-agrégé) décline -> raw exact via idx couvrant");
    }

    /// (4) PARITÉ / MODE 0 : l'expressibilité est INDÉPENDANTE du filtre env (None = mode 0). Les décisions
    /// de routage (décline vs route) sont identiques avec/sans env -> aucune régression multi-tenant.
    #[test]
    fn rollup_route_expressibility_parity_env_modes() {
        for env in [None, Some("staging")] {
            // inexprimable (2e filtre) -> décline dans LES DEUX modes.
            assert!(try_rollup_route("search source=web status>=500 | stats count by src_ip", 0, 0, env, i64::MAX).is_none(),
                    "décline stable quel que soit env={env:?}");
            // exprimable -> route dans les DEUX modes (env ajoute juste un env_id au WHERE).
            let r = try_rollup_route("search source=web | stats count by status", 0, 0, env, i64::MAX).expect("route stable");
            assert_eq!(r.sql.contains("env_id"), env.is_some(), "env_id présent SSI env=Some ; env={env:?}");
        }
    }

    /// (5) QRY-1 : le rollup-route ne prétend JAMAIS être exact au grain sous-horaire (approx:true sur route A),
    /// et signale un caveat de fraîcheur quand la borne haute touche le bucket horaire COURANT (non matérialisé).
    #[test]
    fn rollup_route_qry1_approx_and_recency_note() {
        // Horloge FIGÉE : now=1_000_000 -> bucket courant = 997_200 (277*3600), fin = 1_000_800.
        let now_ts: i64 = 1_000_000;
        let cur_hour = (now_ts / 3600) * 3600; // 997_200

        // (a) Fenêtre SOUS-HORAIRE dans une heure PASSÉE (to < heure courante) : route A count-by-source ->
        //     approx:true (grain horaire, jamais « exact »), truncated:false, PAS de caveat de fraîcheur.
        let past_to = cur_hour - 100; // dans le bucket précédent
        let past_from = past_to - 900; // fenêtre 15 min
        let a = try_rollup_route_at("search | stats count by source", past_from, past_to, None, now_ts, i64::MAX).expect("route A");
        assert!(a.sql.contains("FROM event_rollup"), "route A -> event_rollup");
        assert!(a.approx, "grain horaire -> approx:true (jamais exact au sous-horaire)");
        assert!(!a.truncated, "counts par source non tronqués");
        assert!(a.note.is_none(), "fenêtre passée -> pas de caveat de fraîcheur : {:?}", a.note);

        // (b) Fenêtre RÉCENTE courte (« 15 dernières min », to=now dans l'heure courante) : NON rapportée exacte
        //     (approx:true) + caveat « bucket courant non matérialisé » -> jamais un sous-comptage SILENCIEUX.
        let recent_from = now_ts - 900;
        let r = try_rollup_route_at("search | stats count by source", recent_from, now_ts, None, now_ts, i64::MAX).expect("route A récente");
        assert!(r.approx, "fenêtre récente -> jamais exacte");
        assert!(r.note.as_deref().map(|s| s.contains("bucket courant")).unwrap_or(false),
                "to dans l'heure courante -> caveat de fraîcheur ; note={:?}", r.note);

        // (c) Route B (dim) reste approx+truncated ET porte le caveat de fraîcheur si récente.
        let b = try_rollup_route_at("search source=web | stats count by status", recent_from, now_ts, None, now_ts, i64::MAX).expect("route B récente");
        assert!(b.approx && b.truncated, "route B dim -> approx/partiel");
        assert!(b.note.is_some(), "route B récente -> caveat de fraîcheur");
    }

    /// CIM (Slice #7, pièce 1) — PARITÉ const-code <-> miroir machine `config.d/cim/cim.v1.json`.
    /// L'auto-cohérence PURE du contrat (cim_category_ok + taxonomie sans doublon) a été déplacée AVEC
    /// les consts dans `guatx_core::cim` (test `cim_contract_is_self_consistent`) — P1-M2 ; ce test-ci
    /// garde la moitié couplée au FICHIER (embarqué à la compilation), qui vit dans le dépôt plume.
    /// Interdit la dérive code/schéma : modifier l'un sans l'autre casse ce test (source unique de vérité).
    #[test]
    fn cim_const_mirror_matches_config_schema() {
        // PARITÉ const-code <-> schéma machine (embarqué à la compilation -> pas de FS runtime).
        let schema: Value =
            serde_json::from_str(include_str!("../../../config.d/cim/cim.v1.json")).unwrap();
        assert_eq!(schema["version"].as_str(), Some(CIM_VERSION), "version doc/json divergente");
        let json_cats: Vec<&str> = schema["categories"].as_array().unwrap().iter()
            .map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(json_cats.as_slice(), CIM_CATEGORIES, "categories json != CIM_CATEGORIES");
        let json_core: Vec<&str> = schema["core_fields"].as_array().unwrap().iter()
            .map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(json_core.as_slice(), CIM_CORE_FIELDS, "core_fields json != CIM_CORE_FIELDS");
        let json_act: Vec<&str> = schema["action_vocab"].as_array().unwrap().iter()
            .map(|c| c.as_str().unwrap()).collect();
        assert_eq!(json_act.as_slice(), CIM_ACTION_VOCAB, "action_vocab json != CIM_ACTION_VOCAB");
    }

    /// Parité avec le relais Python (minio-audit-relay.py / record_to_event) : mêmes champs, sévérité,
    /// message, dedup, filtres (scope buckets + bruit). Garde-fou de la bascule Option C (étape 1).
    #[test]
    fn minio_native_parser_parity() {
        let buckets = minio_buckets();
        let drop_apis = minio_drop_apis();
        let ev = |r: Value| minio_record_to_event(&r, &buckets, &drop_apis);
        // DeleteObject + versionId -> sev 4, version_delete=1, src nettoyé, dedup=requestID, ts UTC parsé.
        let d = ev(json!({"time":"2026-06-28T05:46:28.007Z","api":{"name":"DeleteObject","bucket":"backups","object":"k.tar","status":"OK","statusCode":204},"remotehost":"10.42.0.5","requestID":"18BD28870CA90E93","userAgent":"MinIO-go","requestQuery":{"versionId":"abc-123"},"accessKey":"backup-svc"})).unwrap();
        assert_eq!(d["severity"], 4);
        assert_eq!(d["ts"], 1782625588);
        assert_eq!(d["dedup"], "minioaudit-18BD28870CA90E93");
        assert_eq!(d["fields"]["version_delete"], "1");
        assert_eq!(d["fields"]["statusCode"], "204");
        assert_eq!(d["src_ip"], "10.42.0.5");
        assert_eq!(d["message"], "minio-audit DeleteObject backups/k.tar status=OK code=204 ak=backup-svc src=10.42.0.5 req=18BD28870CA90E93 VERSION-DELETE");
        // GetObject [::1] -> sev 3, crochets strippés.
        let g = ev(json!({"time":"2026-06-28T05:46:28Z","api":{"name":"GetObject","bucket":"cluster-backups","object":"b/o","status":"OK","statusCode":200},"remotehost":"[::1]","requestID":"R2","userAgent":"cluster-backup-agent","accessKey":"cluster-backup-svc"})).unwrap();
        assert_eq!(g["severity"], 3);
        assert_eq!(g["src_ip"], "::1");
        // PutObject sans userAgent -> sev 2, user_agent vide.
        let p = ev(json!({"api":{"name":"PutObject","bucket":"backups","object":"o2","status":"OK","statusCode":200},"remotehost":"1.2.3.4","requestID":"R3","accessKey":"ak"})).unwrap();
        assert_eq!(p["severity"], 2);
        assert_eq!(p["fields"]["user_agent"], "");
        // bruit (List/Head), hors scope, sans bucket -> None.
        assert!(ev(json!({"api":{"name":"ListObjectsV2","bucket":"cluster-backups"},"requestID":"R4"})).is_none());
        assert!(ev(json!({"api":{"name":"HeadBucket","bucket":"backups"},"requestID":"R6"})).is_none());
        assert!(ev(json!({"api":{"name":"GetObject","bucket":"other-bucket"},"requestID":"R5"})).is_none());
        assert!(ev(json!({"api":{"name":"GetObject"},"requestID":"R7"})).is_none());
        // tolérance de forme : array + ND-JSON.
        assert_eq!(minio_parse_body("[{\"a\":1},{\"b\":2}]").len(), 2);
        assert_eq!(minio_parse_body("{\"a\":1}\n{\"b\":2}").len(), 2);
    }

    // --- EXTRACTEUR GÉNÉRIQUE (PARSER PHASE 1) ---------------------------------------------------
    // NB : aucun test ne POSE PLUME_GENERIC_EXTRACT -> generic_sources() = défaut ["k8s-log"] (OnceLock).
    // On teste donc avec source="k8s-log" (opt-in par défaut) et les sources hors liste / auditd (gate).

    #[test]
    fn extract_generic_logfmt_and_json() {
        // logfmt : key=value + key="valeur quotée avec espace".
        let out = extract_generic("k8s-log", "level=info user=alice path=\"/a b\" n=3", "{}").unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["level"], "info");
        assert_eq!(v["user"], "alice");
        assert_eq!(v["path"], "/a b");
        assert_eq!(v["n"], "3");
        // json-first : objet aplati (string/number/bool -> string).
        let out = extract_generic("k8s-log", r#"{"a":"x","b":2,"c":true}"#, "{}").unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["a"], "x");
        assert_eq!(v["b"], "2");
        assert_eq!(v["c"], "true");
    }

    #[test]
    fn extract_generic_merge_no_overwrite() {
        // `user` déjà présent (collecteur/parser) -> JAMAIS écrasé. Seule la clé NOUVELLE est ajoutée.
        let out = extract_generic("k8s-log", "user=bob role=admin", r#"{"user":"alice"}"#).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["user"], "alice"); // préservé (précédence collecteur > générique)
        assert_eq!(v["role"], "admin"); // ajouté
        // Rien de nouveau -> None.
        assert!(extract_generic("k8s-log", "user=bob", r#"{"user":"alice"}"#).is_none());
    }

    #[test]
    fn extract_generic_gate_blocks_non_optin_and_auditd() {
        assert!(extract_generic("auditd", "user=x", "{}").is_none()); // garde-fou DUR : jamais auditd
        assert!(extract_generic("sshd", "user=x", "{}").is_none());   // source hors liste opt-in
    }

    #[test]
    fn extract_generic_caps_keys_and_value_len() {
        // > 24 clés -> CAP à 24.
        let mut msg = String::new();
        for i in 0..40 { msg.push_str(&format!("k{i}=v{i} ")); }
        let out = extract_generic("k8s-log", &msg, "{}").unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v.as_object().unwrap().len(), GENERIC_MAX_KEYS);
        // valeur > 256 c. -> TRONQUÉE à 256.
        let long = "x".repeat(300);
        let out = extract_generic("k8s-log", &format!("big={long}"), "{}").unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["big"].as_str().unwrap().len(), GENERIC_MAX_VAL);
    }

    #[test]
    fn extract_generic_skips_non_ident_keys() {
        // clé simple OK ; sous-objet aplati `sub.x` rejeté par soql_ident_ok ('.') -> non requêtable.
        let out = extract_generic("k8s-log", r#"{"ok":"1","sub":{"x":"y"}}"#, "{}").unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], "1");
        assert!(v.get("sub.x").is_none());
    }

    /// Base de test : schéma bundlé (db/schema.sql) + migrations -> état v39 avec les colonnes mitre.
    /// In-memory, NON chiffrée (pas de PLUME_DB_KEY) -> indépendant de l'environnement.

    // ============================================================================================
    // THREAT-INTEL (#23) — IOC store + match-on-ingest (enrich-not-suppress) + mode-0 byte-identique.
    // ============================================================================================

    /// Insère un IOC directement (miroir de ioc_upsert) puis (re)charge le cache mémoire du db_path donné.
    fn seed_ioc(conn: &Connection, db_path: &str, kind: &str, value: &str, source: &str, expires: Option<i64>) {
        conn.execute(
            "INSERT INTO ioc(type,value,source,confidence,severity,first_seen,last_seen,expires,env_id) \
             VALUES(?1,?2,?3,80,3,?4,?4,?5,'prod')",
            params![kind, value, source, now(), expires],
        ).unwrap();
        ioc_cache_reload(conn, db_path);
    }

    /// MODE 0 BYTE-IDENTIQUE : magasin d'IOC VIDE -> le cache est vide -> ti_match_event NE TOUCHE PAS les
    /// fields (aucune clé threat_intel/ti_match). L'ingest écrit exactement comme avant #23.
    #[test]
    fn ti_mode0_empty_store_is_byte_identical() {
        let conn = test_db(); // table ioc créée par migrate_v79, VIDE
        // fast path : cache jamais chargé pour ce db_path -> None immédiat -> fields inchangés.
        assert_eq!(ti_match_event("dbp-empty", Some("1.2.3.4"), None, Some("http://x"), Some("{\"a\":1}".into())).as_deref(), Some("{\"a\":1}"));
        assert_eq!(ti_match_event("dbp-empty", Some("1.2.3.4"), None, None, None), None);
        // Ingest complet : un event dont l'IP serait un IOC SI le store en contenait -> ici aucun -> pas d'enrichissement.
        let events = vec![json!({"ts": 500, "source": "agent", "message": "x", "src_ip": "203.0.113.9", "dedup": "e1"})];
        ingest_events_batch(&conn, "dbp-empty", &events, 500, None, None).unwrap();
        let f: Option<String> = conn.query_row("SELECT fields FROM event WHERE dedup='e1'", [], |r| r.get(0)).unwrap();
        assert!(f.as_deref().map(|s| !s.contains("ti_match") && !s.contains("threat_intel")).unwrap_or(true), "aucun enrichissement TI en mode 0 (store vide)");
    }

    /// MATCH-ON-INGEST : un IOC ip -> l'event dont src_ip matche est ENRICHI (threat_intel + ti_match=1)
    /// SANS être supprimé ; l'event dont l'IP ne matche PAS reste intact (cas négatif). Preuve enrich-not-suppress.
    #[test]
    fn ti_match_on_ingest_enriches_not_suppresses() {
        let conn = test_db();
        let dbp = "dbp-match";
        seed_ioc(&conn, dbp, "ip", "203.0.113.9", "feed-x", None);
        let events = vec![
            json!({"ts": 600, "source": "agent", "message": "bad", "src_ip": "203.0.113.9", "dedup": "hit"}),
            json!({"ts": 601, "source": "agent", "message": "ok",  "src_ip": "10.0.0.1",     "dedup": "miss"}),
        ];
        let n = ingest_events_batch(&conn, dbp, &events, 600, None, None).unwrap();
        assert_eq!(n, 2, "les 2 events sont INSÉRÉS (enrich-not-suppress : aucun drop)");
        let cnt: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE dedup IN ('hit','miss')", [], |r| r.get(0)).unwrap();
        assert_eq!(cnt, 2, "aucun event supprimé par le match");
        // HIT : fields enrichis.
        let hit: String = conn.query_row("SELECT fields FROM event WHERE dedup='hit'", [], |r| r.get(0)).unwrap();
        let hv: Value = serde_json::from_str(&hit).unwrap();
        assert_eq!(hv["ti_match"], 1);
        assert_eq!(hv["threat_intel"]["source"], "feed-x");
        assert_eq!(hv["threat_intel"]["ioc_type"], "ip");
        assert_eq!(hv["threat_intel"]["value"], "203.0.113.9");
        // MISS : pas d'enrichissement.
        let miss: Option<String> = conn.query_row("SELECT fields FROM event WHERE dedup='miss'", [], |r| r.get(0)).unwrap();
        assert!(miss.as_deref().map(|s| !s.contains("ti_match")).unwrap_or(true), "l'event non-IOC reste intact (cas négatif)");
    }

    /// Le match confronte aussi les HASHES/DOMAINE portés par le JSON `fields` (pas seulement les colonnes IP/URL).
    #[test]
    fn ti_match_hash_and_domain_in_fields() {
        let conn = test_db();
        let dbp = "dbp-fields";
        let sha = "a".repeat(64);
        seed_ioc(&conn, dbp, "hash_sha256", &sha, "mal-feed", None);
        seed_ioc(&conn, dbp, "domain", "evil.example", "dns-feed", None);
        // hash en majuscules dans l'event -> normalisé en minuscules pour le lookup -> match.
        let events = vec![
            json!({"ts": 700, "source": "agent", "message": "f", "dedup": "h", "fields": {"sha256": sha.to_uppercase()}}),
            json!({"ts": 701, "source": "agent", "message": "d", "dedup": "d", "fields": {"domain": "EVIL.example"}}),
        ];
        ingest_events_batch(&conn, dbp, &events, 700, None, None).unwrap();
        let h: String = conn.query_row("SELECT fields FROM event WHERE dedup='h'", [], |r| r.get(0)).unwrap();
        assert!(h.contains("\"ti_match\":1") && h.contains("hash_sha256"), "hash sha256 (des fields) matché");
        let d: String = conn.query_row("SELECT fields FROM event WHERE dedup='d'", [], |r| r.get(0)).unwrap();
        assert!(d.contains("\"ti_match\":1") && d.contains("\"ioc_type\":\"domain\""), "domaine (des fields) matché, casse-insensible");
    }

    /// EXPIRY : un IOC expiré (expires<=now) est EXCLU du cache -> aucun enrichissement (rétention au read).
    #[test]
    fn ti_expired_ioc_is_not_matched() {
        let conn = test_db();
        let dbp = "dbp-exp";
        seed_ioc(&conn, dbp, "ip", "198.51.100.7", "old-feed", Some(now() - 10)); // déjà expiré
        let events = vec![json!({"ts": 800, "source": "agent", "message": "e", "src_ip": "198.51.100.7", "dedup": "x"})];
        ingest_events_batch(&conn, dbp, &events, 800, None, None).unwrap();
        let f: Option<String> = conn.query_row("SELECT fields FROM event WHERE dedup='x'", [], |r| r.get(0)).unwrap();
        assert!(f.as_deref().map(|s| !s.contains("ti_match")).unwrap_or(true), "un IOC expiré ne matche pas (exclu du cache)");
    }

    /// STIX import (cœur pur guatx_core::ti) via ioc_upsert : chaque type parse -> ligne ioc ; un pattern
    /// non supporté est ignoré-avec-raison (jamais une ligne). Preuve de bout en bout du chemin d'import.
    #[test]
    fn ti_stix_bundle_import_roundtrip_and_normalization() {
        let conn = test_db();
        let good = json!({"type":"bundle","id":"b","objects":[
            {"type":"indicator","id":"indicator--1","pattern_type":"stix","pattern":"[ipv4-addr:value = '5.5.5.5']"},
            {"type":"indicator","id":"indicator--2","pattern_type":"stix","pattern":"[domain-name:value = 'BAD.Example']"},
            {"type":"indicator","id":"indicator--3","pattern_type":"stix","pattern":"[file:name LIKE '%.exe']"}
        ]});
        let imp = guatx_core::ti::stix_bundle_to_iocs(&good);
        assert_eq!(imp.iocs.len(), 2, "ip + domaine traduits ; LIKE ignoré");
        assert_eq!(imp.skipped.len(), 1, "le pattern LIKE est skippé-avec-raison");
        // écrit via ioc_upsert (le chemin du handler) et vérifie la normalisation (domaine minuscule).
        for ioc in &imp.iocs {
            assert!(ioc_upsert(&conn, &ioc.kind, &ioc.value, "stix-import", 50, 2, None, ioc.stix_id.as_deref(), "prod", now()));
        }
        let dom: String = conn.query_row("SELECT value FROM ioc WHERE type='domain'", [], |r| r.get(0)).unwrap();
        assert_eq!(dom, "bad.example", "valeur STOCKÉE normalisée (minuscule)");
        // UNIQUE(type,value,source,env_id) : ré-import du même IOC = UPDATE, pas un doublon.
        let before: i64 = conn.query_row("SELECT COUNT(*) FROM ioc", [], |r| r.get(0)).unwrap();
        for ioc in &imp.iocs {
            ioc_upsert(&conn, &ioc.kind, &ioc.value, "stix-import", 90, 3, None, ioc.stix_id.as_deref(), "prod", now());
        }
        let after: i64 = conn.query_row("SELECT COUNT(*) FROM ioc", [], |r| r.get(0)).unwrap();
        assert_eq!(before, after, "ré-import = UPDATE (dédup UNIQUE), aucune ligne en double");
        let conf: i64 = conn.query_row("SELECT confidence FROM ioc WHERE type='domain'", [], |r| r.get(0)).unwrap();
        assert_eq!(conf, 90, "l'UPDATE a rafraîchi la confiance");
    }

    // ============================================================================================
    // #30 — IocIndex (fondation passage à l'échelle) : trait de pré-filtre d'appartenance devant le
    // magasin exact. HashSet (défaut) == exact (byte-identique) ; Bloom = probabiliste SANS faux négatif,
    // rattrapé par le confirm exact. Reconstruit au reload.
    // ============================================================================================

    /// INVARIANT ABSOLU : le bloom ne produit JAMAIS de faux négatif. Toute valeur insérée -> maybe_contains
    /// == true. Prouvé à l'échelle (60000 valeurs distinctes, au-dessus du seuil d'auto-bascule par défaut).
    #[test]
    fn ti_bloom_never_false_negative() {
        let pairs: Vec<(String, String)> = (0..60_000u32).map(|i| ("ip".into(), format!("10.{}.{}.{}", i >> 16 & 0xff, i >> 8 & 0xff, i & 0xff))).collect();
        let mut bloom = BloomIocIndex::new();
        bloom.rebuild(&pairs);
        assert_eq!(bloom.kind_name(), "bloom");
        for (_k, v) in &pairs {
            assert!(bloom.maybe_contains("ip", v), "faux négatif interdit : {v} inséré mais absent du filtre");
        }
        // Sanité : le filtre discrimine (des valeurs jamais insérées sont majoritairement négatives -> il
        // sert bien de pré-filtre, pas un "always true"). On tolère quelques FP (rattrapés par l'exact).
        let absent_negatives = (0..10_000u32).filter(|i| !bloom.maybe_contains("ip", &format!("203.0.{}.{}", i >> 8 & 0xff, i & 0xff))).count();
        assert!(absent_negatives > 9_000, "le bloom doit majoritairement rejeter les absents (FP<10%), rejetés={absent_negatives}/10000");
    }

    /// HashSetIocIndex (DÉFAUT) = appartenance EXACTE : inséré -> true, absent -> false. Aucun faux positif.
    #[test]
    fn ti_hashset_index_is_exact() {
        let mut idx = HashSetIocIndex::default();
        idx.rebuild(&[("ip".into(), "1.2.3.4".into()), ("domain".into(), "evil.example".into())]);
        assert_eq!(idx.kind_name(), "hashset");
        assert!(idx.maybe_contains("", "1.2.3.4"));
        assert!(idx.maybe_contains("", "evil.example"));
        assert!(!idx.maybe_contains("", "9.9.9.9"), "absent -> false (exact, aucun faux positif)");
    }

    /// REBUILD AU RELOAD : ioc_cache_reload (re)construit l'index en même temps que le magasin. Volume
    /// petit + pas de forçage env -> impl DÉFAUT = HashSet ; la valeur seedée est bien indexée.
    #[test]
    fn ti_index_rebuilt_on_reload_default_hashset() {
        let conn = test_db();
        let dbp = "dbp-idx-reload";
        seed_ioc(&conn, dbp, "ip", "203.0.113.9", "feed-x", None); // seed_ioc appelle ioc_cache_reload
        let guard = ioc_index().read();
        let idx = guard.get(dbp).expect("index reconstruit pour ce db_path au reload");
        assert_eq!(idx.kind_name(), "hashset", "défaut = HashSet exact (petit volume, pas de forçage)");
        assert!(idx.maybe_contains("", "203.0.113.9"), "la valeur seedée est indexée");
        assert!(!idx.maybe_contains("", "10.0.0.1"), "une valeur non-IOC n'est pas indexée (exact)");
    }

    /// Double d'index de test qui répond POSSIBLE à TOUT (pire cas de faux positifs du filtre).
    struct AllTrueIndex;
    impl IocIndex for AllTrueIndex {
        fn maybe_contains(&self, _k: &str, _v: &str) -> bool { true }
        fn rebuild(&mut self, _iocs: &[(String, String)]) {}
        fn kind_name(&self) -> &'static str { "all-true" }
    }

    /// LE CONFIRM EXACT FAIT AUTORITÉ : même avec un index qui laisse TOUT passer (100 % de faux positifs),
    /// seul l'IOC réellement présent dans le magasin est enrichi ; une valeur non-IOC n'est PAS matchée.
    /// Preuve qu'un faux positif du filtre ne peut pas fabriquer un faux match.
    #[test]
    fn ti_exact_confirm_gates_bloom_false_positives() {
        let conn = test_db();
        let dbp = "dbp-fp-gate";
        seed_ioc(&conn, dbp, "ip", "203.0.113.9", "feed-x", None);
        // Remplace l'index par un double "tout passe" APRÈS le seed (le magasin exact reste la vérité).
        ioc_index().write().insert(dbp.to_string(), Box::new(AllTrueIndex));
        let events = vec![
            json!({"ts": 900, "source": "agent", "message": "hit",  "src_ip": "203.0.113.9", "dedup": "fp-hit"}),
            json!({"ts": 901, "source": "agent", "message": "miss", "src_ip": "8.8.8.8",     "dedup": "fp-miss"}),
        ];
        ingest_events_batch(&conn, dbp, &events, 900, None, None).unwrap();
        let hit: String = conn.query_row("SELECT fields FROM event WHERE dedup='fp-hit'", [], |r| r.get(0)).unwrap();
        assert!(hit.contains("\"ti_match\":1"), "l'IOC réel est enrichi (confirm exact = présent)");
        let miss: Option<String> = conn.query_row("SELECT fields FROM event WHERE dedup='fp-miss'", [], |r| r.get(0)).unwrap();
        assert!(miss.as_deref().map(|s| !s.contains("ti_match")).unwrap_or(true), "faux positif du filtre RATTRAPÉ par le confirm exact : aucun faux match");
    }

    /// BOUT EN BOUT via un BloomIocIndex réel câblé pour ce db_path : le match reste IDENTIQUE au HashSet
    /// (hit enrichi, miss intact) — le bloom laisse passer le vrai IOC (aucun faux négatif) et le miss est
    /// écarté (négatif du filtre OU confirm exact). Prouve la parité de comportement de l'impl bloom.
    #[test]
    fn ti_bloom_wired_matches_identically() {
        let conn = test_db();
        let dbp = "dbp-bloom-e2e";
        seed_ioc(&conn, dbp, "ip", "203.0.113.9", "feed-x", None);
        // Reconstruit un bloom depuis les mêmes paires et le câble à la place du HashSet.
        let mut bloom = BloomIocIndex::new();
        bloom.rebuild(&[("ip".into(), "203.0.113.9".into())]);
        ioc_index().write().insert(dbp.to_string(), Box::new(bloom));
        let events = vec![
            json!({"ts": 950, "source": "agent", "message": "hit",  "src_ip": "203.0.113.9", "dedup": "bl-hit"}),
            json!({"ts": 951, "source": "agent", "message": "miss", "src_ip": "10.0.0.1",     "dedup": "bl-miss"}),
        ];
        ingest_events_batch(&conn, dbp, &events, 950, None, None).unwrap();
        let hit: String = conn.query_row("SELECT fields FROM event WHERE dedup='bl-hit'", [], |r| r.get(0)).unwrap();
        assert!(hit.contains("\"ti_match\":1") && hit.contains("203.0.113.9"), "bloom : vrai IOC toujours matché (aucun faux négatif)");
        let miss: Option<String> = conn.query_row("SELECT fields FROM event WHERE dedup='bl-miss'", [], |r| r.get(0)).unwrap();
        assert!(miss.as_deref().map(|s| !s.contains("ti_match")).unwrap_or(true), "bloom : le miss reste intact");
    }

    // ============================================================================================
    // #24 — RISK-BASED ALERTING (fondation) : store, accumulation, déclenchement dédupliqué, composition
    // ti->risk, mode 0 byte-identique, decay/expiry-at-read.
    // ============================================================================================

    // #33 — ISOLATION DES TESTS RBA SOUS PARALLÉLISME. Les tests `rba_*` pilotent le comportement du
    // rollup de risque via des VARIABLES D'ENVIRONNEMENT (`PLUME_RISK_SCORE_THRESHOLD` /
    // `_TACTICS_THRESHOLD` / `_VELOCITY` / `_VELOCITY_WINDOW_S`), qui sont un ÉTAT PROCESSUS GLOBAL.
    // Sous `cargo test` (threads parallèles dans le même process), deux tests `rba_*` qui posent des
    // seuils DIFFÉRENTS se clobbaient mutuellement en cours d'exécution -> flake (ex.
    // `rba_distinct_tactics_trigger` voyait un seuil écrasé par un test concurrent et n'armait pas
    // l'alerte). FIX (isolation de test SEULEMENT, la logique RBA est INCHANGÉE) : un verrou de module
    // sérialise EXACTEMENT ce groupe de tests entre eux (le guard est tenu tout le corps du test, donc
    // set_var -> rollup -> assert -> remove_var est atomique vis-à-vis des autres tests du groupe). Les
    // autres tests de la suite continuent de tourner en parallèle. Verrou parking_lot SANS empoisonnement
    // (audit #67) : un panic dans un test relâche le verrou sain -> pas de cascade d'échecs de verrou.
    fn rba_env_lock() -> parking_lot::MutexGuard<'static, ()> {
        RBA_ENV_LOCK.lock()
    }

    /// Helper : insère une contribution de risque directement (miroir run_risk_rules / ti_risk_contribution).
    fn seed_risk(conn: &Connection, ts: i64, etype: &str, entity: &str, score: i64, mitre: &str, dedup: Option<&str>) {
        assert!(risk_event_insert(conn, ts, etype, entity, score, "rule", Some(1), "test", mitre, 2, "prod", dedup)
            || dedup.is_some());
    }

    /// ACCUMULATION : plusieurs contributions sur la MÊME entité s'additionnent dans risk_rollup (score
    /// cumulé, contrib, tactiques MITRE distinctes) ; le franchissement du SEUIL DE CUMUL lève UNE alerte.
    #[test]
    fn rba_accumulation_and_threshold_alert_fires_once() {
        let _env = rba_env_lock(); // #33 : sérialise le groupe RBA (env process global)
        let conn = test_db();
        std::env::set_var("PLUME_RISK_SCORE_THRESHOLD", "100");
        std::env::set_var("PLUME_RISK_TACTICS_THRESHOLD", "0"); // isole le seuil de cumul
        std::env::set_var("PLUME_RISK_VELOCITY", "0");
        let n = now();
        seed_risk(&conn, n - 10, "ip", "9.9.9.9", 40, "T1110", None);
        seed_risk(&conn, n - 8, "ip", "9.9.9.9", 40, "T1110", None); // même technique
        seed_risk(&conn, n - 5, "ip", "9.9.9.9", 40, "T1046", None); // technique distincte
        rollup_risk(&conn);
        let (score, contrib, dt): (i64, i64, i64) = conn.query_row(
            "SELECT score,contrib,distinct_tactics FROM risk_rollup WHERE entity='9.9.9.9'", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).unwrap();
        assert_eq!(score, 120, "score cumulé = 40*3");
        assert_eq!(contrib, 3, "3 contributions");
        assert_eq!(dt, 2, "2 techniques MITRE distinctes");
        // UNE alerte risk dédupliquée pour l'entité.
        let na: i64 = conn.query_row("SELECT COUNT(*) FROM alert WHERE dedup='risk-ip-9.9.9.9' AND status IN ('new','ack')", [], |r| r.get(0)).unwrap();
        assert_eq!(na, 1, "exactement UNE alerte risk pour l'entité (dédup)");
        // Ré-exécuter le rollup NE crée PAS de 2e alerte (INSERT OR IGNORE sur dedup).
        rollup_risk(&conn);
        let na2: i64 = conn.query_row("SELECT COUNT(*) FROM alert WHERE dedup='risk-ip-9.9.9.9'", [], |r| r.get(0)).unwrap();
        assert_eq!(na2, 1, "pas de doublon d'alerte au 2e rollup (dédup par entité)");
        std::env::remove_var("PLUME_RISK_SCORE_THRESHOLD");
        std::env::remove_var("PLUME_RISK_TACTICS_THRESHOLD");
        std::env::remove_var("PLUME_RISK_VELOCITY");
    }

    /// #3 — distinct_tactics compte de VRAIES TACTIQUES ATT&CK, pas des techniques : deux techniques de la
    /// MÊME tactique (T1110 + T1552 = credential-access) ne comptent qu'UNE tactique ; une technique d'une
    /// autre tactique (T1046 = discovery) en ajoute une -> total 2. Une technique NON curée (T9999) retombe
    /// sur son ID brut (bucket distinct, jamais un sous-comptage).
    #[test]
    fn rba_distinct_tactics_counts_real_tactics_not_techniques() {
        let _env = rba_env_lock(); // #33 : sérialise le groupe RBA (env process global)
        let conn = test_db();
        std::env::set_var("PLUME_RISK_SCORE_THRESHOLD", "100000"); // isole : on n'inspecte que le rollup
        std::env::set_var("PLUME_RISK_TACTICS_THRESHOLD", "0");
        std::env::set_var("PLUME_RISK_VELOCITY", "0");
        let n = now();
        seed_risk(&conn, n - 9, "ip", "5.5.5.5", 10, "T1110", None); // credential-access
        seed_risk(&conn, n - 7, "ip", "5.5.5.5", 10, "T1552", None); // credential-access (MÊME tactique)
        seed_risk(&conn, n - 5, "ip", "5.5.5.5", 10, "T1046", None); // discovery (autre tactique)
        rollup_risk(&conn);
        let dt: i64 = conn.query_row("SELECT distinct_tactics FROM risk_rollup WHERE entity='5.5.5.5'", [], |r| r.get(0)).unwrap();
        assert_eq!(dt, 2, "3 techniques mais 2 tactiques distinctes (T1110+T1552 collapse en credential-access)");
        // une technique NON curée retombe sur son ID brut -> ajoute un bucket distinct (jamais un sous-comptage).
        seed_risk(&conn, n - 3, "ip", "5.5.5.5", 10, "T9999", None);
        rollup_risk(&conn);
        let dt2: i64 = conn.query_row("SELECT distinct_tactics FROM risk_rollup WHERE entity='5.5.5.5'", [], |r| r.get(0)).unwrap();
        assert_eq!(dt2, 3, "technique non curée = bucket distinct (2 tactiques + T9999)");
        std::env::remove_var("PLUME_RISK_SCORE_THRESHOLD");
        std::env::remove_var("PLUME_RISK_TACTICS_THRESHOLD");
        std::env::remove_var("PLUME_RISK_VELOCITY");
    }

    /// DÉCLENCHEUR TACTIQUES DISTINCTES : sous le seuil de cumul, ≥N techniques MITRE distinctes -> alerte.
    #[test]
    fn rba_distinct_tactics_trigger() {
        let _env = rba_env_lock(); // #33 : sérialise le groupe RBA (env process global) -> fin du flake
        let conn = test_db();
        std::env::set_var("PLUME_RISK_SCORE_THRESHOLD", "100000"); // hors d'atteinte -> isole le déclencheur tactiques
        std::env::set_var("PLUME_RISK_TACTICS_THRESHOLD", "3");
        std::env::set_var("PLUME_RISK_VELOCITY", "0");
        let n = now();
        for (i, t) in ["T1110", "T1046", "T1190"].iter().enumerate() {
            seed_risk(&conn, n - (i as i64) - 1, "host", "srv1", 5, t, None);
        }
        rollup_risk(&conn);
        let na: i64 = conn.query_row("SELECT COUNT(*) FROM alert WHERE dedup='risk-host-srv1' AND status='new'", [], |r| r.get(0)).unwrap();
        assert_eq!(na, 1, "3 techniques distinctes -> alerte même sous le seuil de cumul");
        std::env::remove_var("PLUME_RISK_SCORE_THRESHOLD");
        std::env::remove_var("PLUME_RISK_TACTICS_THRESHOLD");
        std::env::remove_var("PLUME_RISK_VELOCITY");
    }

    /// DÉCLENCHEUR VÉLOCITÉ : une RAFALE de risque dans la sous-fenêtre chaude franchit le seuil de vélocité
    /// même si le cumul et les tactiques ne le franchissent pas.
    #[test]
    fn rba_velocity_trigger() {
        let _env = rba_env_lock(); // #33 : sérialise le groupe RBA (env process global)
        let conn = test_db();
        std::env::set_var("PLUME_RISK_SCORE_THRESHOLD", "100000");
        std::env::set_var("PLUME_RISK_TACTICS_THRESHOLD", "0");
        std::env::set_var("PLUME_RISK_VELOCITY", "60");
        std::env::set_var("PLUME_RISK_VELOCITY_WINDOW_S", "3600");
        let n = now();
        seed_risk(&conn, n - 100, "user", "bob", 30, "", None); // dans la sous-fenêtre chaude
        seed_risk(&conn, n - 50, "user", "bob", 40, "", None);
        rollup_risk(&conn);
        let (score_hot, na): (i64, i64) = (
            conn.query_row("SELECT score_hot FROM risk_rollup WHERE entity='bob'", [], |r| r.get(0)).unwrap(),
            conn.query_row("SELECT COUNT(*) FROM alert WHERE dedup='risk-user-bob' AND status='new'", [], |r| r.get(0)).unwrap(),
        );
        assert_eq!(score_hot, 70, "score chaud = 30+40");
        assert_eq!(na, 1, "rafale (vélocité) -> alerte");
        std::env::remove_var("PLUME_RISK_SCORE_THRESHOLD");
        std::env::remove_var("PLUME_RISK_TACTICS_THRESHOLD");
        std::env::remove_var("PLUME_RISK_VELOCITY");
        std::env::remove_var("PLUME_RISK_VELOCITY_WINDOW_S");
    }

    /// DECAY / EXPIRY-AT-READ : une contribution HORS fenêtre d'accumulation sort du rollup (aucune purge de
    /// ligne) ; sous le seuil, l'alerte risk OUVERTE est RÉSOLUE au rollup suivant.
    #[test]
    fn rba_decay_out_of_window_resolves_alert() {
        let _env = rba_env_lock(); // #33 : sérialise le groupe RBA (env process global)
        let conn = test_db();
        std::env::set_var("PLUME_RISK_WINDOW_S", "3600");
        std::env::set_var("PLUME_RISK_SCORE_THRESHOLD", "50");
        std::env::set_var("PLUME_RISK_TACTICS_THRESHOLD", "0");
        std::env::set_var("PLUME_RISK_VELOCITY", "0");
        let n = now();
        seed_risk(&conn, n - 60, "ip", "1.1.1.1", 80, "T1", None); // dans la fenêtre
        rollup_risk(&conn);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM alert WHERE dedup='risk-ip-1.1.1.1' AND status='new'", [], |r| r.get::<_, i64>(0)).unwrap(), 1, "alerte levée dans la fenêtre");
        // Vieillit la contribution HORS fenêtre (>3600s) -> sort du rollup -> plus de franchissement.
        conn.execute("UPDATE risk_event SET ts=?1 WHERE entity='1.1.1.1'", params![n - 7200]).unwrap();
        rollup_risk(&conn);
        let present: i64 = conn.query_row("SELECT COUNT(*) FROM risk_rollup WHERE entity='1.1.1.1'", [], |r| r.get(0)).unwrap();
        assert_eq!(present, 0, "decay : contribution hors fenêtre absente du rollup (sans purge de ligne)");
        let resolved: i64 = conn.query_row("SELECT COUNT(*) FROM alert WHERE rule='risk.ip.1.1.1.1' AND status='resolved'", [], |r| r.get(0)).unwrap();
        assert_eq!(resolved, 1, "l'alerte risk est RÉSOLUE quand l'entité retombe hors seuil");
        std::env::remove_var("PLUME_RISK_WINDOW_S");
        std::env::remove_var("PLUME_RISK_SCORE_THRESHOLD");
        std::env::remove_var("PLUME_RISK_TACTICS_THRESHOLD");
        std::env::remove_var("PLUME_RISK_VELOCITY");
    }

    /// MODE 0 BYTE-IDENTIQUE : aucune règle risk + IOC store vide -> AUCUN risk_event émis à l'ingest, rollup
    /// no-op (fast-path), risk_rollup vide, AUCUNE alerte risk. L'ingest écrit exactement comme sans #24.
    #[test]
    fn rba_mode0_no_risk_events_byte_identical() {
        let conn = test_db();
        let dbp = "dbp-rba0";
        // ingest normal (aucun IOC seedé -> aucun ti hit -> aucune contribution ti).
        let events = vec![json!({"ts": 500, "source": "agent", "message": "x", "src_ip": "203.0.113.9", "dedup": "e1"})];
        ingest_events_batch(&conn, dbp, &events, 500, None, None).unwrap();
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM risk_event", [], |r| r.get::<_, i64>(0)).unwrap(), 0, "aucun risk_event en mode 0");
        rollup_risk(&conn); // fast-path : no-op
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM risk_rollup", [], |r| r.get::<_, i64>(0)).unwrap(), 0, "risk_rollup vide");
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM alert WHERE dedup LIKE 'risk-%'", [], |r| r.get::<_, i64>(0)).unwrap(), 0, "aucune alerte risk");
        // l'event est byte-identique (aucun enrichissement, cf. #23) — le champ fields n'a pas de marqueur risk.
        let f: Option<String> = conn.query_row("SELECT fields FROM event WHERE dedup='e1'", [], |r| r.get(0)).unwrap();
        assert!(f.as_deref().map(|s| !s.contains("ti_match")).unwrap_or(true), "event byte-identique (mode 0)");
    }

    /// COMPOSITION #23->#24 : un match threat-intel à l'ingest ÉMET un risk_event (source='ti') attribué à
    /// l'entité de l'IOC, dédupliqué par bucket horaire (un scanner bruyant = 1 apport/bucket, pas N).
    #[test]
    fn rba_ti_match_composes_risk_event() {
        let _env = rba_env_lock(); // #33 : sérialise le groupe RBA (env process global)
        let conn = test_db();
        std::env::set_var("PLUME_RISK_TI_SCORE", "20");
        std::env::set_var("PLUME_RISK_TI_BUCKET_S", "3600");
        let dbp = "dbp-rba-ti";
        seed_ioc(&conn, dbp, "ip", "203.0.113.9", "feed-x", None);
        // deux events du MÊME attaquant dans le même bucket horaire -> UNE seule contribution ti (dédup).
        let events = vec![
            json!({"ts": 3600, "source": "agent", "message": "a", "src_ip": "203.0.113.9", "dedup": "t1"}),
            json!({"ts": 3601, "source": "agent", "message": "b", "src_ip": "203.0.113.9", "dedup": "t2"}),
        ];
        ingest_events_batch(&conn, dbp, &events, 3600, None, None).unwrap();
        let (cnt, src, ent): (i64, String, String) = conn.query_row(
            "SELECT COUNT(*), MIN(source), MIN(entity) FROM risk_event WHERE source='ti'", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).unwrap();
        assert_eq!(cnt, 1, "un match ti -> UN risk_event (dédup par bucket, pas un par event)");
        assert_eq!(src, "ti");
        assert_eq!(ent, "203.0.113.9", "risque attribué à l'IP de l'IOC");
        std::env::remove_var("PLUME_RISK_TI_SCORE");
        std::env::remove_var("PLUME_RISK_TI_BUCKET_S");
    }

    /// RÈGLE EN MODE RISK : run_risk_rules exécute une règle `search … | stats count by src_ip` et CONTRIBUE
    /// du risque à CHAQUE entité de la colonne, SANS lever d'alerte scalaire (run_due_rules l'exclut).
    #[test]
    fn rba_risk_rule_emits_per_entity_contributions() {
        // DB fichier : run_risk_rules éval via run_query (pool lecture sur chemin disque, comme la prod).
        let mut path = std::env::temp_dir();
        path.push(format!("plume-rba-rule-{}-{}.db", std::process::id(), now()));
        let p = path.to_string_lossy().to_string();
        // Writer via open_db (WAL + busy_timeout + clé mode 0) -> run_query (pool lecture) coexiste sans
        // blocage, EXACTEMENT comme le test e2e de run_due_rules.
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&conn);
            // deux IP distinctes en source=web sévérité 3 -> `stats count by src_ip` = 2 lignes (2 entités).
            for (ip, k) in [("11.0.0.1", "a"), ("22.0.0.2", "b")] {
                conn.execute("INSERT INTO event(ts,source,severity,message,src_ip,dedup) VALUES(?1,'web',3,'m',?2,?3)", params![now() - 5, ip, k]).unwrap();
            }
            // règle EN MODE RISK : risk_score=25, entité = colonne src_ip du résultat.
            conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,risk_score,risk_entity_type,risk_entity_field) \
                 VALUES('scanners',1,'search source=web | stats count by src_ip',1,'>',0,3,300,3600,'T1046',25,'ip','src_ip')",
                [],
            ).unwrap();
        }
        run_risk_rules(&db, &p);
        // NB : ne JAMAIS tenir le lock `db` en appelant run_*_rules (Mutex std non ré-entrant -> deadlock).
        {
            let conn = db.lock();
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM risk_event WHERE source='rule'", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 2, "une contribution par entité (2 IP distinctes)");
            let sc: i64 = conn.query_row("SELECT risk_score FROM risk_event WHERE entity='11.0.0.1'", [], |r| r.get(0)).unwrap();
            assert_eq!(sc, 25, "score de la contribution = risk_score de la règle");
        }
        // run_due_rules NE traite PAS la règle risk -> aucune alerte scalaire 'rule.*' pour elle.
        run_due_rules(&db, &p);
        {
            let conn = db.lock();
            let scalar: i64 = conn.query_row("SELECT COUNT(*) FROM alert WHERE rule LIKE 'rule.%'", [], |r| r.get(0)).unwrap();
            assert_eq!(scalar, 0, "une règle risk ne lève PAS d'alerte scalaire (instead-of)");
        }
        let _ = std::fs::remove_file(&p);
    }

    /// STORE SPI (readiness pivot) — prouve que `SqlcipherStore` (a) STOCKE des lignes BYTE-IDENTIQUES à
    /// l'INSERT legacy (même la ligne écrite par un producteur qui OMETTAIT des colonnes = DEFAULT), et
    /// (b) que la lecture `query_soql` TRAVERSE le store (compile via Dialect + exécute) et rend la donnée.
    #[test]
    fn store_spi_byte_identical_writes_and_query_soql() {
        // DB fichier (query_soql lit via le pool READ_ONLY sur un chemin disque, comme la prod).
        let mut path = std::env::temp_dir();
        path.push(format!("plume-store-spi-{}-{}.db", std::process::id(), now()));
        let p = path.to_string_lossy().to_string();
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);

            // (a) PARITÉ D'ÉCRITURE. Même contenu écrit par l'INSERT LEGACY (forme journal : category 'auth'
            // littérale, env_id/dst_ip/url/engagement_id/origin OMIS -> DEFAULT) et par le store. La ligne
            // stockée doit être IDENTIQUE sur TOUTES les colonnes. On distingue par `dedup` (les 2 s'insèrent).
            w.execute(
                "INSERT OR IGNORE INTO event(ts,source,category,severity,message,fields,dedup,host,src_ip) \
                 VALUES(?1,?2,'auth',?3,?4,?5,?6,?7,?8)",
                params![100i64, "sshd", 3i64, "row", "{\"a\":1}", "legacy", Some("h1"), Some("1.2.3.4")],
            ).unwrap();
            store().insert_event(&w, &EventRow {
                ts: 100, source: "sshd".into(), category: "auth".into(), severity: 3,
                message: "row".into(), host: Some("h1".into()), src_ip: Some("1.2.3.4".into()),
                dst_ip: None, url: None, dedup: Some("store".into()), fields: Some("{\"a\":1}".into()),
                engagement_id: String::new(), origin: String::new(), env_id: None,
            }).unwrap();
            // Signature ligne = concat de TOUTES les colonnes (NULL -> ∅). env_id doit valoir 'prod' des deux
            // côtés (legacy: DEFAULT NOT NULL ; store: None -> lie 'prod', jamais NULL).
            let sig = |dedup: &str| -> String {
                w.query_row(
                    "SELECT ts||'|'||source||'|'||category||'|'||severity||'|'||message||'|'||COALESCE(host,'∅') \
                     ||'|'||COALESCE(src_ip,'∅')||'|'||COALESCE(dst_ip,'∅')||'|'||COALESCE(url,'∅') \
                     ||'|'||COALESCE(fields,'∅')||'|'||engagement_id||'|'||origin||'|'||env_id \
                     FROM event WHERE dedup=?1",
                    params![dedup], |r| r.get::<_, String>(0),
                ).unwrap()
            };
            assert_eq!(sig("legacy"), sig("store"), "store écrit une ligne BYTE-IDENTIQUE à l'INSERT legacy");
            assert!(sig("store").ends_with("|prod"), "env_id None -> 'prod' (jamais NULL) : {}", sig("store"));

            // (a bis) dédup OR IGNORE + fields/metric/snapshot via le store.
            assert_eq!(store().insert_event(&w, &EventRow { ts: 100, source: "sshd".into(), category: "auth".into(), severity: 3, message: "dup".into(), dedup: Some("store".into()), ..Default::default() }).unwrap(), 0, "OR IGNORE : dedup en collision -> 0 ligne");
            store().insert_metric(&w, &MetricRow { ts: 100, name: "load1".into(), labels: None, value: 0.5, host: Some("h1".into()) }).unwrap();
            store().insert_snapshot(&w, &SnapshotRow { ts: 100, kind: "firewall".into(), hash: "h".into(), data: "{}".into(), host: Some("h1".into()) }).unwrap();
            let mlabels: Option<String> = w.query_row("SELECT labels FROM metric WHERE name='load1'", [], |r| r.get(0)).unwrap();
            assert_eq!(mlabels, None, "labels None -> NULL stocké (== littéral NULL legacy)");
            let (skind, senv): (String, String) = w.query_row("SELECT kind, env_id FROM snapshot WHERE kind='firewall'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            assert_eq!((skind.as_str(), senv.as_str()), ("firewall", "prod"), "snapshot stocké + env_id DEFAULT 'prod'");
        } // writer fermé -> le pool READ_ONLY ouvre une connexion fraîche

        // (b) LECTURE VIA LE STORE : query_soql compile le SOQL (émission Dialect) PUIS exécute. Les 2 events
        // sshd (legacy + store) sont comptés. Rows = vue typée du SPI.
        let v = store().query_soql(&p, "search source=sshd | stats count", 0, 0, None, query_budget_ms(), None).unwrap();
        let rows = Rows::from_query_json(&v).expect("forme {columns,rows,stats}");
        assert_eq!(rows.columns, vec!["count".to_string()]);
        assert_eq!(rows.rows[0][0].as_i64(), Some(2), "query_soql voit les 2 events sshd écrits par le store/legacy");
        // ÉMISSION identique à soql_to_sql_x (même point d'émission = le store).
        assert_eq!(
            store().soql_to_sql("search source=sshd | stats count", 0, 0, None).unwrap(),
            soql_to_sql_x("search source=sshd | stats count", 0, 0, None).unwrap()
        );
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(format!("{p}-wal"));
        let _ = std::fs::remove_file(format!("{p}-shm"));
    }

    /// M5 — cap de décompression : un flux snappy dont la taille décompressée dépasse le plafond est REFUSÉ
    /// (anti-bombe) ; un flux normal passe ; un corps non-snappy est renvoyé tel quel.
    #[test]
    fn v2_m5_decompress_cap_rejects_bomb() {
        // corps NON-snappy -> renvoyé tel quel (borné par la limite HTTP).
        assert_eq!(ingest_decompress_capped(b"not snappy at all").unwrap(), b"not snappy at all");
        // petit flux snappy légitime -> décompressé.
        let small = snap::raw::Encoder::new().compress_vec(b"hello world").unwrap();
        assert_eq!(ingest_decompress_capped(&small).unwrap(), b"hello world");
        // flux snappy annonçant une sortie > cap -> REFUS (Err) sans allouer la sortie.
        let bomb = snap::raw::Encoder::new().compress_vec(&vec![0u8; INGEST_MAX_DECOMPRESS + 1024]).unwrap();
        assert!(bomb.len() < INGEST_MAX_DECOMPRESS, "la bombe est PETITE compressée (amplification)");
        assert!(ingest_decompress_capped(&bomb).is_err(), "décompressé > cap -> 413");
    }

    /// Base temporaire UNIQUE (pid + horodatage + compteur) pour les tests sur disque.
    fn mk_tmp_path(tag: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("plume-bk-{}-{tag}-{}-{n}", std::process::id(), now()));
        p.to_string_lossy().into_owned()
    }
    fn bytes_contain(hay: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
    }

    /// PREUVE DE REJOUABILITÉ (acceptation critique) : backup compressé+chiffré -> restore ->
    /// la DB restaurée est IDENTIQUE et OUVRABLE. Vérifie en plus : (a) dest PLUS PETIT que le
    /// plaintext, (b) AUCUN plaintext lisible dans dest (ni marqueur ni en-tête SQLite),
    /// (c) la restauration n'est lisible QU'AVEC la clé (chiffrée at-rest).
    #[test]
    fn backup_restore_roundtrip_compressed() {
        let key = "test-backup-passphrase-correct-horse-battery-staple";
        let marker = "MARKER_NEEDLE_DO_NOT_LEAK_7Q";
        let src = mk_tmp_path("src.db");
        let dest = mk_tmp_path("dest.age");
        let restored = mk_tmp_path("restored.db");
        const N: i64 = 5000;

        // --- 1) DB SQLCipher source avec données connues (schéma réel + migrations + N events) ---
        let (orig_events, orig_parsers, orig_schema_v, orig_msg1): (i64, i64, String, String);
        {
            let conn = open_db_keyed(&src, Some(key)).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&conn);
            conn.execute_batch("BEGIN;").unwrap();
            for i in 0..N {
                conn.execute(
                    "INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,'sshd','auth',3,'host-a',?2,'{}')",
                    params![now(), format!("{marker} failed login attempt n={i} from 10.0.0.{}", i % 255)],
                ).unwrap();
            }
            conn.execute_batch("COMMIT;").unwrap();
            orig_events = conn.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
            orig_parsers = conn.query_row("SELECT COUNT(*) FROM parser", [], |r| r.get(0)).unwrap();
            orig_schema_v = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
            orig_msg1 = conn.query_row("SELECT message FROM event WHERE id=1", [], |r| r.get(0)).unwrap();
            assert_eq!(orig_events, N, "pré-condition : N events insérés");
            assert!(orig_parsers > 0, "pré-condition : migrate() seede des parsers builtin");
        } // conn droppée -> WAL flushé/fermé

        // --- 2) BACKUP compressé+chiffré ---
        let stats = backup_compressed(&src, &dest, Some(key), None).expect("backup_compressed OK");
        let ratio = stats.plaintext_bytes as f64 / stats.dest_bytes.max(1) as f64;
        eprintln!(
            "[roundtrip] plaintext={} o  dest={} o  ratio={:.1}x",
            stats.plaintext_bytes, stats.dest_bytes, ratio);

        // (a) dest STRICTEMENT plus petit que le plaintext (compression effective).
        assert!(stats.dest_bytes > 0 && stats.plaintext_bytes > 0, "tailles non nulles");
        assert!(
            stats.dest_bytes < stats.plaintext_bytes,
            "le backup compressé ({} o) doit être plus petit que le plaintext ({} o)",
            stats.dest_bytes, stats.plaintext_bytes);

        // (b) AUCUN plaintext lisible dans le fichier de backup chiffré.
        let dest_bytes = std::fs::read(&dest).unwrap();
        assert!(!bytes_contain(&dest_bytes, marker.as_bytes()), "le marqueur ne doit PAS fuiter en clair");
        assert!(!bytes_contain(&dest_bytes, b"SQLite format 3"), "l'en-tête SQLite ne doit PAS apparaître en clair");
        assert!(bytes_contain(&dest_bytes, b"age-encryption.org"), "l'en-tête conteneur age doit être présent");

        // --- 3) RESTORE -> NOUVELLE DB SQLCipher ---
        // refus d'écrasement sans force (le fichier existe : on le crée d'abord).
        std::fs::write(&restored, b"sentinel").unwrap();
        let refused = restore_compressed(&dest, &restored, Some(key), false, None);
        assert!(refused.is_err(), "restore doit REFUSER d'écraser sans --force");
        restore_compressed(&dest, &restored, Some(key), true, None).expect("restore_compressed OK (force)");

        // --- 4) La DB restaurée est IDENTIQUE et OUVRABLE avec la clé ---
        {
            let r = open_db_keyed(&restored, Some(key)).unwrap();
            let n_events: i64 = r.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
            let n_parsers: i64 = r.query_row("SELECT COUNT(*) FROM parser", [], |r| r.get(0)).unwrap();
            let schema_v: String = r.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
            let msg1: String = r.query_row("SELECT message FROM event WHERE id=1", [], |r| r.get(0)).unwrap();
            assert_eq!(n_events, orig_events, "même nombre d'events après round-trip");
            assert_eq!(n_parsers, orig_parsers, "mêmes parsers après round-trip");
            assert_eq!(schema_v, orig_schema_v, "même schema_version après round-trip");
            assert_eq!(msg1, orig_msg1, "contenu identique (event id=1)");
            assert!(msg1.contains(marker), "le contenu connu est bien restauré");
            // FTS5 (table virtuelle + triggers) survit au round-trip sqlcipher_export.
            let fts: i64 = r.query_row("SELECT COUNT(*) FROM event_fts WHERE event_fts MATCH 'failed'", [], |r| r.get(0)).unwrap();
            assert_eq!(fts, N, "l'index FTS5 est intact et requêtable après restauration");
        }

        // (c) la DB restaurée n'est PAS lisible SANS la clé (réellement chiffrée at-rest).
        {
            let bad = Connection::open(&restored).unwrap();
            let res = bad.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0));
            assert!(res.is_err(), "la DB restaurée doit être illisible sans la clé SQLCipher");
        }

        // nettoyage best-effort.
        for f in [&src, &dest, &restored] {
            let _ = std::fs::remove_file(f);
            let _ = std::fs::remove_file(format!("{f}-wal"));
            let _ = std::fs::remove_file(format!("{f}-shm"));
        }
    }

    /// FUITE #65 — le garde RAII efface le plaintext temporaire ET son sidecar `-journal` sur
    /// TOUTE sortie de portée, y compris le CHEMIN D'ERREUR (early-return via `?`). On simule un
    /// export interrompu (temp + journal écrits) puis on force l'échec (clé absente) : à la sortie,
    /// AUCUN plaintext en clair ne doit subsister.
    #[test]
    fn backup_dropguard_reaps_temp_and_journal_on_error_path() {
        let dir = std::env::temp_dir().join(format!("plume-dropguard-{}-{}", std::process::id(), now()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("plume.db.age").to_string_lossy().into_owned();

        // portée qui matérialise un guard, écrit un temp + son journal, puis retourne tôt sur erreur.
        let observed_tmp: std::path::PathBuf = {
            let guard = crate::backup::PlaintextTempGuard(crate::backup::plain_temp_path(&dest));
            let tmp = guard.path().to_path_buf();
            std::fs::write(&tmp, b"SQLite format 3\0<plaintext pages>").unwrap();
            std::fs::write(format!("{}-journal", tmp.display()), b"<journal plaintext pages>").unwrap();
            assert!(tmp.exists() && std::path::Path::new(&format!("{}-journal", tmp.display())).exists());
            // simule un early-return `?` : on sort de la portée sans supprimer explicitement.
            let _ = (|| -> Result<(), String> { Err("échec simulé (clé absente)".into()) })();
            tmp
            // <- guard droppé ICI (sortie de portée) : doit tout effacer.
        };

        assert!(!observed_tmp.exists(), "le plaintext temporaire doit être effacé par le garde (chemin d'erreur)");
        assert!(!std::path::Path::new(&format!("{}-journal", observed_tmp.display())).exists(),
            "le sidecar -journal (pages en clair) doit AUSSI être effacé par le garde");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Lit les 1ers octets de la CHARGE décompressée d'un backup `.age` (déchiffre age passphrase + dézstd)
    /// -> permet de PROUVER le format effectif (B1 `PLUMEDUMP1\n` vs legacy `SQLite format 3\0`).
    fn backup_payload_head(dest: &str, key: &str) -> Vec<u8> {
        use std::io::Read;
        let f = std::fs::File::open(dest).unwrap();
        let dec = age::Decryptor::new_buffered(std::io::BufReader::new(f)).unwrap();
        let id = age::scrypt::Identity::new(age::secrecy::SecretString::from(key.to_string()));
        let reader = dec.decrypt(std::iter::once(&id as &dyn age::Identity)).unwrap();
        let mut zd = zstd::Decoder::new(reader).unwrap();
        let mut head = [0u8; 16];
        let mut n = 0;
        while n < head.len() {
            match zd.read(&mut head[n..]).unwrap() { 0 => break, m => n += m }
        }
        head[..n].to_vec()
    }

    /// Fingerprint DÉTERMINISTE et ORDRE-INDÉPENDANT d'une table, couvrant TOUS les types Y COMPRIS la
    /// CLASSE DE STOCKAGE (Integer(1) != Real(1.0) != Text("1") != Blob([1]) != Null). Renvoie
    /// (row_count, hash_accumulé). Si UNE ligne/valeur/type diffère -> le couple diffère.
    fn b1_table_fp(conn: &Connection, table: &str) -> (u64, u64) {
        use std::hash::{Hash, Hasher};
        let mut stmt = conn.prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\""))).unwrap();
        let ncols = stmt.column_count();
        let mut rows = stmt.query([]).unwrap();
        let (mut count, mut acc) = (0u64, 0u64);
        while let Some(row) = rows.next().unwrap() {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            for i in 0..ncols {
                use rusqlite::types::ValueRef as VR;
                match row.get_ref(i).unwrap() {
                    VR::Null => 0u8.hash(&mut h),
                    VR::Integer(n) => { 1u8.hash(&mut h); n.hash(&mut h); }
                    VR::Real(f) => { 2u8.hash(&mut h); f.to_bits().hash(&mut h); }
                    VR::Text(t) => { 3u8.hash(&mut h); t.hash(&mut h); }
                    VR::Blob(b) => { 4u8.hash(&mut h); b.hash(&mut h); }
                }
            }
            acc = acc.wrapping_add(h.finish()); // somme -> INDÉPENDANT de l'ordre des lignes
            count += 1;
        }
        (count, acc)
    }
    /// Schéma comparable : (type,name,sql) hors objets internes sqlite_*, trié.
    fn b1_schema(conn: &Connection) -> Vec<(String, String, String)> {
        let mut stmt = conn.prepare(
            "SELECT type,name,COALESCE(sql,'') FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(|x| x.unwrap()).collect()
    }
    /// Tables ORDINAIRES à fingerprinter (hors sqlite_*, hors vtables, hors shadow FTS).
    fn b1_user_tables(conn: &Connection) -> Vec<String> {
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' \
             AND sql NOT LIKE 'CREATE VIRTUAL%' \
             AND name NOT LIKE '%\\_data' ESCAPE '\\' AND name NOT LIKE '%\\_idx' ESCAPE '\\' \
             AND name NOT LIKE '%\\_docsize' ESCAPE '\\' AND name NOT LIKE '%\\_config' ESCAPE '\\' \
             AND name NOT LIKE '%\\_content' ESCAPE '\\' ORDER BY name").unwrap();
        stmt.query_map([], |r| r.get::<_, String>(0)).unwrap().map(|x| x.unwrap()).collect()
    }

    /// B1 (backup STREAMING) — HARNAIS DE PARITÉ round-trip, GARDE-FOU DATA-LOSS-CRITICAL. Crée une DB
    /// SQLCipher réaliste (types mixtes INTEGER/REAL/TEXT/BLOB/NULL ; colonne SANS affinité à classes de
    /// stockage MIXTES par ligne ; unicode/quotes/newlines/gros textes ; BLOB avec octets nuls + 0xFF +
    /// tous-les-octets ; NULL vs "" ; -0.0/dénormal/1e308 ; AUTOINCREMENT+sqlite_sequence désynchronisé ;
    /// index/vue/trigger ; FTS5 à contenu externe ; N lignes = streaming réel), fait backup B1 -> restore
    /// B1, puis PROUVE l'identité : même schéma, même row-count ET même HASH par table (tous types, y.c.
    /// classe de stockage), FTS fonctionnelle, compteur AUTOINCREMENT exact. Échoue si UNE valeur diffère.
    #[test]
    fn backup_b1_parity_roundtrip() {
        let key = "b1-parity-passphrase-correct-horse-battery-staple";
        let src = mk_tmp_path("b1src.db");
        let dest = mk_tmp_path("b1dest.age");
        let restored = mk_tmp_path("b1restored.db");
        const N: i64 = 20000;

        // --- 1) DB SOURCE : schéma adverse + données adverses ---
        {
            let w = open_db_keyed(&src, Some(key)).unwrap();
            w.execute_batch(
                "CREATE TABLE t_any(x);                                   -- SANS affinité -> classes mixtes\n\
                 CREATE TABLE t_typed(i INTEGER, r REAL, t TEXT, b BLOB, note TEXT);\n\
                 CREATE TABLE t_auto(id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT);\n\
                 CREATE TABLE t_txtpk(k TEXT PRIMARY KEY, v TEXT);        -- rowid SANS alias\n\
                 CREATE INDEX idx_typed_i ON t_typed(i);\n\
                 CREATE VIEW v_cnt AS SELECT count(*) AS c FROM t_typed;\n\
                 CREATE TABLE doc(id INTEGER PRIMARY KEY, body TEXT);\n\
                 CREATE VIRTUAL TABLE doc_fts USING fts5(body, content='doc', content_rowid='id');\n\
                 CREATE TRIGGER doc_ai AFTER INSERT ON doc BEGIN INSERT INTO doc_fts(rowid,body) VALUES(new.id,new.body); END;",
            ).unwrap();

            // t_any : MÊME colonne, classes de stockage DIFFÉRENTES par ligne (le cas de fidélité crucial).
            w.execute("INSERT INTO t_any(x) VALUES(?)", params![5i64]).unwrap();          // Integer(5)
            w.execute("INSERT INTO t_any(x) VALUES(?)", params![5.0f64]).unwrap();        // Real(5.0) != Integer(5)
            w.execute("INSERT INTO t_any(x) VALUES(?)", params!["5"]).unwrap();           // Text("5")
            w.execute("INSERT INTO t_any(x) VALUES(?)", params![vec![5u8]]).unwrap();      // Blob([5])
            w.execute("INSERT INTO t_any(x) VALUES(?)", params![rusqlite::types::Null]).unwrap(); // Null
            w.execute("INSERT INTO t_any(x) VALUES(?)", params![2.0f64]).unwrap();        // Real(2.0) entier-valué -> RESTE Real

            // t_typed : lignes adverses (i, r, t, b, note).
            let big_text: String = "é🚀ü".repeat(4000);
            let all_bytes: Vec<u8> = (0u8..=255).collect();
            let embedded: Vec<u8> = vec![0, 0, 0, 1, 255, 0, 255, 0];
            w.execute("INSERT INTO t_typed(i,r,t,b,note) VALUES(?,?,?,?,?)",
                params![i64::MIN, 0.0f64, "", all_bytes, rusqlite::types::Null]).unwrap();
            w.execute("INSERT INTO t_typed(i,r,t,b,note) VALUES(?,?,?,?,?)",
                params![i64::MAX, -0.0f64, "unicode ✓ éàü 日本語 😀", embedded, ""]).unwrap(); // NULL vs "" distingués
            w.execute("INSERT INTO t_typed(i,r,t,b,note) VALUES(?,?,?,?,?)",
                params![0i64, std::f64::consts::PI, "quotes 'single' \"double\"\nnewline\ttab", vec![0u8], "note"]).unwrap();
            w.execute("INSERT INTO t_typed(i,r,t,b,note) VALUES(?,?,?,?,?)",
                params![-1i64, 1e308f64, big_text, Vec::<u8>::new(), rusqlite::types::Null]).unwrap(); // blob vide
            w.execute("INSERT INTO t_typed(i,r,t,b,note) VALUES(?,?,?,?,?)",
                params![42i64, 5e-324f64, "NULL", vec![0u8, 255, 0, 255], "end"]).unwrap(); // dénormal min
            w.execute("INSERT INTO t_typed(i,r,t,b,note) VALUES(?,?,?,?,?)",
                params![7i64, 2.0f64, "two", vec![255u8; 100], ""]).unwrap();

            // volume -> streaming réel.
            w.execute_batch("BEGIN;").unwrap();
            for k in 0..N {
                w.execute("INSERT INTO t_typed(i,r,t,b,note) VALUES(?,?,?,?,?)",
                    params![k, k as f64 + 0.5, format!("row {k} data payload"), rusqlite::types::Null, format!("n{k}")]).unwrap();
            }
            w.execute_batch("COMMIT;").unwrap();

            // FTS externe : contenu recherchable.
            for k in 0..500 {
                w.execute("INSERT INTO doc(body) VALUES(?)", params![format!("alpha beta gamma searchable document {k}")]).unwrap();
            }
            w.execute("INSERT INTO doc(body) VALUES('unique_needle_xyzzy special')", []).unwrap();

            // AUTOINCREMENT : insère 10, supprime le dernier -> sqlite_sequence.seq (10) > MAX(id) (9).
            for k in 0..10 { w.execute("INSERT INTO t_auto(v) VALUES(?)", params![format!("a{k}")]).unwrap(); }
            w.execute("DELETE FROM t_auto WHERE id=(SELECT MAX(id) FROM t_auto)", []).unwrap();

            w.execute("INSERT INTO t_txtpk(k,v) VALUES('key1','v1')", []).unwrap();
            w.execute("INSERT INTO t_txtpk(k,v) VALUES('clé2','valeur2')", []).unwrap();
        } // conn droppée -> flush.

        // --- 2) EMPREINTES ORIGINALES ---
        let (orig_schema, orig_tables, orig_fps, orig_fts_search, orig_fts_needle, orig_seq): (_, Vec<String>, Vec<(u64, u64)>, i64, i64, i64);
        {
            let c = open_db_keyed(&src, Some(key)).unwrap();
            orig_schema = b1_schema(&c);
            orig_tables = b1_user_tables(&c);
            orig_fps = orig_tables.iter().map(|t| b1_table_fp(&c, t)).collect();
            orig_fts_search = c.query_row("SELECT count(*) FROM doc_fts WHERE doc_fts MATCH 'searchable'", [], |r| r.get(0)).unwrap();
            orig_fts_needle = c.query_row("SELECT count(*) FROM doc_fts WHERE doc_fts MATCH 'unique_needle_xyzzy'", [], |r| r.get(0)).unwrap();
            orig_seq = c.query_row("SELECT seq FROM sqlite_sequence WHERE name='t_auto'", [], |r| r.get(0)).unwrap();
            assert_eq!(orig_fts_search, 500, "pré-condition FTS");
            assert_eq!(orig_seq, 10, "pré-condition : compteur AUTOINCREMENT désynchronisé (10 > max id 9)");
        }

        // --- 3) BACKUP B1 -> RESTORE B1 ---
        backup_compressed(&src, &dest, Some(key), None).expect("backup B1 OK");
        // PREUVE que le chemin B1 (dump streaming) a bien été emprunté (PAS le repli legacy).
        assert!(backup_payload_head(&dest, key).starts_with(b"PLUMEDUMP1\n"),
            "le backup doit être au format B1 (dump typé), pas legacy (SQLite clair)");
        // AUCUN plaintext SQLite ne doit apparaître dans le fichier chiffré.
        let dest_bytes = std::fs::read(&dest).unwrap();
        assert!(!bytes_contain(&dest_bytes, b"SQLite format 3"), "aucun en-tête SQLite en clair dans le .age");
        restore_compressed(&dest, &restored, Some(key), true, None).expect("restore B1 OK");

        // --- 4) PARITÉ : schéma, row-counts, HASH par table, FTS, sqlite_sequence ---
        let c = open_db_keyed(&restored, Some(key)).unwrap();
        assert_eq!(b1_schema(&c), orig_schema, "le schéma (tables/index/triggers/vues) doit être IDENTIQUE");
        let new_tables = b1_user_tables(&c);
        assert_eq!(new_tables, orig_tables, "même ensemble de tables ordinaires");
        for (t, orig) in orig_tables.iter().zip(orig_fps.iter()) {
            let got = b1_table_fp(&c, t);
            assert_eq!(got.0, orig.0, "row-count IDENTIQUE pour la table {t}");
            assert_eq!(got, *orig, "HASH par table IDENTIQUE pour {t} (aucune valeur/type/BLOB perdu)");
        }
        let fts_search: i64 = c.query_row("SELECT count(*) FROM doc_fts WHERE doc_fts MATCH 'searchable'", [], |r| r.get(0)).unwrap();
        let fts_needle: i64 = c.query_row("SELECT count(*) FROM doc_fts WHERE doc_fts MATCH 'unique_needle_xyzzy'", [], |r| r.get(0)).unwrap();
        assert_eq!(fts_search, orig_fts_search, "FTS externe RECONSTRUITE, fonctionnellement identique");
        assert_eq!(fts_needle, orig_fts_needle, "FTS : le token unique est retrouvé après restore");
        let seq: i64 = c.query_row("SELECT seq FROM sqlite_sequence WHERE name='t_auto'", [], |r| r.get(0)).unwrap();
        assert_eq!(seq, orig_seq, "compteur AUTOINCREMENT (sqlite_sequence) préservé EXACTEMENT -> pas de réutilisation de rowid");

        // la DB restaurée est réellement chiffrée at-rest (illisible sans la clé).
        {
            let bad = Connection::open(&restored).unwrap();
            assert!(bad.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).is_err(),
                "la DB restaurée doit être illisible sans la clé SQLCipher");
        }

        for f in [&src, &dest, &restored] {
            for ext in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{f}{ext}")); }
        }
    }

    /// B1 — REPLI LEGACY prouvé : une DB avec une FTS5 CONTENTLESS (`content=''`, cas de `event_fields_fts`)
    /// n'est PAS représentable en dump typé -> `backup_compressed` DÉTECTE et RETOMBE sur le legacy
    /// (sqlcipher_export, format age(zstd(fichier SQLite clair))). Le backup produit est bien au FORMAT
    /// LEGACY, et le restore le rejoue fidèlement (l'index contentless, stocké dans les shadow tables,
    /// survit via la copie bit-à-bit). -> zéro perte pour les schémas hors périmètre B1.
    #[test]
    fn backup_b1_falls_back_to_legacy_for_contentless_fts() {
        let key = "b1-fallback-passphrase-xyz";
        let src = mk_tmp_path("b1fbsrc.db");
        let dest = mk_tmp_path("b1fbdest.age");
        let restored = mk_tmp_path("b1fbrestored.db");
        {
            let w = open_db_keyed(&src, Some(key)).unwrap();
            w.execute_batch(
                "CREATE TABLE base(id INTEGER PRIMARY KEY, txt TEXT);\n\
                 CREATE VIRTUAL TABLE base_fts USING fts5(v, content='');", // CONTENTLESS -> non-B1
            ).unwrap();
            for k in 0..50 {
                w.execute("INSERT INTO base(id,txt) VALUES(?,?)", params![k, format!("doc {k}")]).unwrap();
                w.execute("INSERT INTO base_fts(rowid,v) VALUES(?,?)", params![k, format!("token{k} contentless searchword")]).unwrap();
            }
        }
        let orig_match: i64 = {
            let c = open_db_keyed(&src, Some(key)).unwrap();
            c.query_row("SELECT count(*) FROM base_fts WHERE base_fts MATCH 'searchword'", [], |r| r.get(0)).unwrap()
        };
        assert_eq!(orig_match, 50);

        backup_compressed(&src, &dest, Some(key), None).expect("backup (repli legacy) OK");
        // PREUVE du repli : le backup est au FORMAT LEGACY (fichier SQLite clair), PAS un dump B1.
        assert!(backup_payload_head(&dest, key).starts_with(b"SQLite format 3"),
            "schéma contentless -> le backup doit retomber sur le legacy (format SQLite), pas B1");
        restore_compressed(&dest, &restored, Some(key), true, None).expect("restore legacy OK");

        let c = open_db_keyed(&restored, Some(key)).unwrap();
        let base_rows: i64 = c.query_row("SELECT count(*) FROM base", [], |r| r.get(0)).unwrap();
        let fts_match: i64 = c.query_row("SELECT count(*) FROM base_fts WHERE base_fts MATCH 'searchword'", [], |r| r.get(0)).unwrap();
        assert_eq!(base_rows, 50, "table de base restaurée");
        assert_eq!(fts_match, orig_match, "l'index FTS contentless (shadow tables) survit à la copie bit-à-bit legacy");

        for f in [&src, &dest, &restored] {
            for ext in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{f}{ext}")); }
        }
    }

    /// FUITE #65 — le balayage de démarrage efface un temp orphelin ANCIEN (crash/OOM antérieur),
    /// mais ÉPARGNE (1) un temp RÉCENT (backup concurrent en vol) et (2) la vraie DB `plume.db`
    /// (+ `-wal`/`-shm`) et les artefacts `.age`. Réape aussi le sidecar `-journal` de l'orphelin.
    #[test]
    fn backup_startup_sweep_reaps_old_orphan_spares_fresh_and_real_db() {
        use std::time::{Duration, SystemTime};
        let dir = std::env::temp_dir().join(format!("plume-sweep-{}-{}", std::process::id(), now()));
        std::fs::create_dir_all(&dir).unwrap();
        let mk = |name: &str, body: &[u8]| -> std::path::PathBuf {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            p
        };

        // (a) ORPHELIN ANCIEN : temp + sidecar journal, mtime vieillie à 3 h.
        let old_tmp = mk(".plume-20260708.db.age.plain.tmp.123.999.0", b"old plaintext");
        let old_journal = mk(".plume-20260708.db.age.plain.tmp.123.999.0-journal", b"old journal");
        let three_h_ago = SystemTime::now() - Duration::from_secs(3 * 3600);
        for p in [&old_tmp, &old_journal] {
            filetime_set(p, three_h_ago);
        }
        // (b) TEMP RÉCENT : backup concurrent en vol (mtime = maintenant) -> à ÉPARGNER.
        let fresh_tmp = mk(".plume-20260711.db.age.plain.tmp.456.111.0", b"fresh plaintext");
        // (c) vraie DB + sidecars + artefact backup : NE DOIVENT JAMAIS être touchés (pas le marqueur).
        let real_db = mk("plume.db", b"SQLCipher at-rest");
        let real_wal = mk("plume.db-wal", b"wal");
        let real_shm = mk("plume.db-shm", b"shm");
        let real_age = mk("plume-20260711.db.age", b"age(zstd(...))");

        let removed = crate::backup::sweep_orphan_temps(&dir, Duration::from_secs(3600));

        assert_eq!(removed, 2, "exactement le temp ancien + son sidecar journal réapés");
        assert!(!old_tmp.exists(), "l'orphelin ancien doit être effacé");
        assert!(!old_journal.exists(), "le sidecar -journal ancien doit être effacé");
        assert!(fresh_tmp.exists(), "un temp RÉCENT (backup concurrent) doit être ÉPARGNÉ");
        assert!(real_db.exists() && real_wal.exists() && real_shm.exists(), "la vraie DB SQLCipher (+wal/shm) NE DOIT PAS être touchée");
        assert!(real_age.exists(), "un artefact .age NE DOIT PAS être touché");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F1 — la clé SQLCipher se lit depuis un FICHIER (secret mount RO), VERBATIM (aucun strip -> byte-identique
    /// à l'env `PLUME_DB_KEY` qui, lui, ne retire RIEN : le MÊME Secret alimente les deux), et FAIL-CLOSE si le
    /// fichier configuré est absent/vide (l'appelant `db_key()` refuse alors de démarrer, jamais de repli env).
    /// Régression review 2026-07-13 : un `\n` final était strippé -> divergence file≠env si la valeur du Secret
    /// se terminait par `\n` -> clé DIFFÉRENTE au cutover -> base illisible. On PROUVE ici la lecture verbatim.
    #[test]
    fn f1_db_key_from_file_reads_and_fails_closed() {
        let dir = std::env::temp_dir().join(format!("plume-dbkeyfile-{}-{}", std::process::id(), now()));
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("db.key");
        // (a) VERBATIM : un `\n` final est CONSERVÉ (= exactement ce que `env::var("PLUME_DB_KEY")` renverrait
        //     pour la même valeur de Secret). C'est l'anti-divergence : file == env byte-pour-byte.
        std::fs::write(&ok, b"s3cr3t-sqlcipher-key\n").unwrap();
        assert_eq!(crate::crypto::db_key_from_file(&ok.to_string_lossy()).unwrap(), "s3cr3t-sqlcipher-key\n",
            "newline final CONSERVÉ (verbatim) -> byte-identique à env, PAS de strip (sinon divergence au cutover)");
        std::fs::write(&ok, b"s3cr3t-sqlcipher-key").unwrap();
        assert_eq!(crate::crypto::db_key_from_file(&ok.to_string_lossy()).unwrap(), "s3cr3t-sqlcipher-key",
            "sans newline -> valeur exacte identique");
        // (b) FAIL-CLOSED : fichier absent -> Err.
        assert!(crate::crypto::db_key_from_file(&dir.join("nope.key").to_string_lossy()).is_err(),
            "fichier absent -> Err (fail-closed)");
        // (c) FAIL-CLOSED : fichier VIDE (0 octet) -> Err (comme env::var(..).filter(!is_empty) rejette "").
        let empty = dir.join("empty.key");
        std::fs::write(&empty, b"").unwrap();
        assert!(crate::crypto::db_key_from_file(&empty.to_string_lossy()).is_err(), "vide (0 octet) -> Err");
        // (d) VERBATIM cohérent : un fichier « \n » seul N'EST PAS vide -> renvoie "\n" (byte-identique à ce que
        //     l'env donnerait pour un Secret valant "\n"). Prouve qu'AUCUN strip ne le réduit à "" (ex-comportement).
        std::fs::write(&empty, b"\n").unwrap();
        assert_eq!(crate::crypto::db_key_from_file(&empty.to_string_lossy()).unwrap(), "\n",
            "newline seul -> \"\\n\" verbatim (pas strippé à vide) : file == env même pour cette valeur");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// v134 (#8) — TOKEN Vault file-first (PLUME_VAULT_TOKEN_FILE), MIROIR de PLUME_DB_KEY_FILE : lecture
    /// VERBATIM, fail-closed sur set-but-broken, repli sur l'env PLUME_VAULT_TOKEN sinon (le token ne transite
    /// plus par /proc/environ quand le fichier est utilisé). Le cœur `vault_token_from_file` est PUR (no env).
    #[test]
    fn v134_vault_token_file_first_and_env_fallback() {
        let dir = std::env::temp_dir().join(format!("plume-vaulttok-{}-{}", std::process::id(), now()));
        std::fs::create_dir_all(&dir).unwrap();
        // (a) lecture VERBATIM du fichier (comme db_key_from_file) — cœur PUR, déterministe.
        let ok = dir.join("tok");
        std::fs::write(&ok, b"s.hvs-token-abc").unwrap();
        assert_eq!(crate::crypto::vault_token_from_file(&ok.to_string_lossy()).unwrap(), "s.hvs-token-abc", "token lu verbatim");
        // (b) fail-closed : fichier absent / vide -> Err.
        assert!(crate::crypto::vault_token_from_file(&dir.join("nope").to_string_lossy()).is_err(), "absent -> Err (fail-closed)");
        let empty = dir.join("empty");
        std::fs::write(&empty, b"").unwrap();
        assert!(crate::crypto::vault_token_from_file(&empty.to_string_lossy()).is_err(), "vide -> Err (fail-closed)");

        // Sauvegarde/restauration de l'état env (d'autres tests remove PLUME_VAULT_TOKEN).
        let save_file = std::env::var("PLUME_VAULT_TOKEN_FILE").ok();
        let save_env = std::env::var("PLUME_VAULT_TOKEN").ok();
        // (c) FILE-FIRST : _FILE (bon) GAGNE même si l'env est posé à une AUTRE valeur (le fichier prime, race-safe).
        std::env::set_var("PLUME_VAULT_TOKEN_FILE", &ok);
        std::env::set_var("PLUME_VAULT_TOKEN", "env-loser");
        assert_eq!(crate::crypto::vault_token().unwrap(), "s.hvs-token-abc", "fichier prioritaire sur l'env");
        // (d) FAIL-CLOSED : _FILE posé mais cassé -> Err (JAMAIS de repli silencieux sur l'env).
        std::env::set_var("PLUME_VAULT_TOKEN_FILE", dir.join("nope").to_string_lossy().as_ref());
        assert!(crate::crypto::vault_token().is_err(), "_FILE cassé -> Err (pas de repli sur env)");
        // (e) REPLI ENV : _FILE non posé -> lit PLUME_VAULT_TOKEN (comportement historique préservé).
        std::env::remove_var("PLUME_VAULT_TOKEN_FILE");
        std::env::set_var("PLUME_VAULT_TOKEN", "env-token-xyz");
        assert_eq!(crate::crypto::vault_token().unwrap(), "env-token-xyz", "repli sur l'env quand _FILE absent");
        // (f) rien posé -> Err (fail-closed, comme avant #8).
        std::env::remove_var("PLUME_VAULT_TOKEN");
        assert!(crate::crypto::vault_token().is_err(), "ni fichier ni env -> Err (fail-closed)");

        // restauration de l'état env initial.
        match save_file { Some(v) => std::env::set_var("PLUME_VAULT_TOKEN_FILE", v), None => std::env::remove_var("PLUME_VAULT_TOKEN_FILE") }
        match save_env { Some(v) => std::env::set_var("PLUME_VAULT_TOKEN", v), None => std::env::remove_var("PLUME_VAULT_TOKEN") }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F1a (SELF-CHECK boot, review 2026-07-13) — `probe_db` classe correctement une base EXISTANTE vis-à-vis
    /// d'une clé, pour qu'une clé PRÉSENTE mais FAUSSE sur une base NON VIDE fail-CLOSE au boot (via
    /// `ensure_encrypted -> exit(78)`) au lieu de surgir plus tard. On PROUVE : (a) bonne clé -> OpensWithKey ;
    /// (b) MAUVAISE clé sur une base chiffrée non vide -> WrongKeyOrCorrupt (le signal de fail-closed) ;
    /// (c) base EN CLAIR -> Plaintext (migration, pas de faux positif) ; (d) FRESH (absente / 0 octet) ->
    /// Fresh avec N'IMPORTE quelle clé (aucun faux positif à l'install / au premier boot).
    #[test]
    fn f1a_probe_db_wrong_key_fails_closed_but_never_on_fresh() {
        use crate::crypto::{probe_db, DbProbe};
        let dir = std::env::temp_dir().join(format!("plume-probe-{}-{}", std::process::id(), now()));
        std::fs::create_dir_all(&dir).unwrap();

        // (a)+(b) base chiffrée NON VIDE avec la BONNE clé (pages réelles écrites).
        let enc = dir.join("enc.db").to_string_lossy().into_owned();
        {
            let c = open_db_keyed(&enc, Some("clef-correcte-1")).unwrap();
            c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES(1);").unwrap();
        } // conn droppée -> pages flushées dans le fichier principal (journal_mode par défaut = delete)
        assert_eq!(probe_db(&enc, "clef-correcte-1"), DbProbe::OpensWithKey,
            "bonne clé sur base chiffrée existante -> OpensWithKey");
        assert_eq!(probe_db(&enc, "MAUVAISE-clef"), DbProbe::WrongKeyOrCorrupt,
            "MAUVAISE clé sur base chiffrée non vide -> WrongKeyOrCorrupt (fail-closed au boot)");

        // (c) base EN CLAIR non vide -> Plaintext (le chemin de migration, jamais WrongKey).
        let plain = dir.join("plain.db").to_string_lossy().into_owned();
        {
            let c = open_db_keyed(&plain, None).unwrap();
            c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES(2);").unwrap();
        }
        assert_eq!(probe_db(&plain, "n-importe-quelle-clef"), DbProbe::Plaintext,
            "base en clair -> Plaintext (migration), pas de faux WrongKey");

        // (d) FRESH : fichier absent -> Fresh ; fichier 0 octet -> Fresh (s'ouvrira avec toute clé).
        assert_eq!(probe_db(&dir.join("absent.db").to_string_lossy(), "k"), DbProbe::Fresh,
            "fichier absent -> Fresh");
        let empty = dir.join("empty.db").to_string_lossy().into_owned();
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(probe_db(&empty, "k"), DbProbe::Fresh,
            "fichier 0 octet -> Fresh (install fraîche / premier boot) : AUCUN faux positif WrongKey");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// v108 follow-up #2 — un VERROU SQLite (SQLITE_BUSY/LOCKED) doit être classé `Locked`, PAS
    /// `WrongKeyOrCorrupt` : sinon un lock transitoire du sidecar backup pendant un chevauchement de boot
    /// ferait faux `exit(78)` -> faux crashloop. On PROUVE, en tenant un verrou EXCLUSIVE réel sur une base
    /// chiffrée non vide (busy=0 -> BUSY immédiat, test déterministe) : (a) BONNE clé mais base VERROUILLÉE
    /// -> `Locked` (pas OpensWithKey car la lecture est bloquée, mais surtout PAS WrongKeyOrCorrupt) ;
    /// (b) MAUVAISE clé sur base VERROUILLÉE -> `Locked` aussi (indécidable tant que le verrou tient — on ne
    /// conclut PAS à tort) ; puis, LE VERROU RELÂCHÉ : (c) bonne clé -> OpensWithKey ; (d) MAUVAISE clé
    /// -> WrongKeyOrCorrupt (le fail-closed d'origine est PRÉSERVÉ : une mauvaise clé exit(78) TOUJOURS).
    #[test]
    fn v108_locked_probe_is_locked_never_wrongkey_but_wrongkey_still_fails_closed() {
        use crate::crypto::{probe_db, probe_db_with_busy, DbProbe};
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("plume-lockprobe-{}-{}", std::process::id(), now()));
        std::fs::create_dir_all(&dir).unwrap();
        let enc = dir.join("enc.db").to_string_lossy().into_owned();
        // Base chiffrée NON VIDE avec la BONNE clé (journal_mode par défaut = delete -> EXCLUSIVE bloque les
        // lecteurs, contrairement au WAL).
        {
            let c = open_db_keyed(&enc, Some("clef-correcte-1")).unwrap();
            c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES(1);").unwrap();
        }
        // Tient un verrou EXCLUSIVE (2e connexion, bonne clé) -> toute lecture concurrente = SQLITE_BUSY.
        let holder = open_db_keyed(&enc, Some("clef-correcte-1")).unwrap();
        holder.execute_batch("BEGIN EXCLUSIVE;").unwrap();

        // (a) VERROUILLÉE + bonne clé -> Locked (surtout : PAS WrongKeyOrCorrupt).
        assert_eq!(probe_db_with_busy(&enc, "clef-correcte-1", Duration::ZERO), DbProbe::Locked,
            "base verrouillée (bonne clé) -> Locked, jamais WrongKeyOrCorrupt");
        // (b) VERROUILLÉE + MAUVAISE clé -> Locked (indécidable tant que le verrou tient ; on ne conclut pas).
        assert_eq!(probe_db_with_busy(&enc, "MAUVAISE-clef", Duration::ZERO), DbProbe::Locked,
            "base verrouillée (mauvaise clé) -> Locked : on ne fail-close PAS sur un verrou");

        // Verrou relâché : le verdict redevient décidable.
        holder.execute_batch("COMMIT;").unwrap();
        drop(holder);

        // (c) bonne clé -> OpensWithKey (aucune régression du chemin normal).
        assert_eq!(probe_db(&enc, "clef-correcte-1"), DbProbe::OpensWithKey,
            "verrou relâché + bonne clé -> OpensWithKey");
        // (d) MAUVAISE clé -> WrongKeyOrCorrupt : LE FAIL-CLOSED D'ORIGINE EST PRÉSERVÉ (exit(78) au boot).
        assert_eq!(probe_db(&enc, "MAUVAISE-clef"), DbProbe::WrongKeyOrCorrupt,
            "verrou relâché + MAUVAISE clé -> WrongKeyOrCorrupt (fail-closed conservé, la régression ne réapparaît pas)");

        // FRESH/plaintext inchangés par busy=0 (le verrou ne les concerne pas) : régression-guard rapide.
        assert_eq!(probe_db_with_busy(&dir.join("absent.db").to_string_lossy(), "k", Duration::ZERO), DbProbe::Fresh,
            "absent -> Fresh (inchangé)");
        let plain = dir.join("plain.db").to_string_lossy().into_owned();
        {
            let c = open_db_keyed(&plain, None).unwrap();
            c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES(2);").unwrap();
        }
        assert_eq!(probe_db_with_busy(&plain, "peu-importe", Duration::ZERO), DbProbe::Plaintext,
            "base en clair -> Plaintext (inchangé)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F2 — sans `PLUME_BACKUP_STAGING_DIR` (défaut, aucun test ne le pose), le staging du plaintext retombe
    /// sur le répertoire de `dest` (compat) et le temp porte le marqueur `.plain.tmp.` (cible RAII+balayage).
    /// L'orientation vers un emptyDir ÉPHÉMÈRE est un choix de MANIFEST (env) — ici on prouve la sémantique.
    #[test]
    fn f2_staging_dir_default_is_dest_parent() {
        let sd = crate::backup::staging_dir("/data/.backup-staging/plume-x.db.age");
        assert_eq!(sd, std::path::PathBuf::from("/data/.backup-staging"));
        let p = crate::backup::plain_temp_path("/data/.backup-staging/plume-x.db.age");
        assert_eq!(p.parent().unwrap(), std::path::Path::new("/data/.backup-staging"),
            "le plaintext temporaire vit dans le répertoire de staging");
        assert!(p.file_name().unwrap().to_string_lossy().contains(".plain.tmp."), "marqueur présent");
    }

    /// F3 — backup ASYMÉTRIQUE (destinataire public age) : roundtrip complet avec l'identité PRIVÉE, dégrade
    /// en vérif STRUCTURELLE-seule sans elle (modèle in-cluster), et n'est PAS déchiffrable à la passphrase.
    /// Et INERTE : recipient=None -> chiffrement SYMÉTRIQUE historique, full-verify EN cluster (aucun changement).
    #[test]
    fn f3_asymmetric_roundtrip_and_symmetric_inert() {
        let dir = std::env::temp_dir().join(format!("plume-f3-{}-{}", std::process::id(), now()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = "test-sqlcipher-key-f3";
        let src = dir.join("src.db").to_string_lossy().into_owned();
        {
            let c = open_db_keyed(&src, Some(key)).unwrap();
            c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES(42);").unwrap();
        }
        let identity = age::x25519::Identity::generate();
        let rcpt_str = identity.to_public().to_string();

        // (1) BACKUP asymétrique -> en-tête X25519 ; verify complet AVEC identité, structurel-seul SANS.
        let dest = dir.join("bk.age").to_string_lossy().into_owned();
        crate::backup::backup_compressed(&src, &dest, Some(key), Some(&rcpt_str)).expect("backup asym OK");
        let (kind, full) = crate::backup::verify_backup(&dest, Some(key), Some(&identity)).expect("verify OK");
        assert_eq!(kind, crate::backup::BackupKind::Asymmetric);
        assert!(full, "avec identité privée -> full decrypt vérifié");
        let (_, full_nokey) = crate::backup::verify_backup(&dest, Some(key), None).expect("verify structurel OK");
        assert!(!full_nokey, "sans identité privée -> DÉGRADE en structurel-seul");

        // (2) RESTORE avec identité -> données intactes.
        let restored = dir.join("restored.db").to_string_lossy().into_owned();
        crate::backup::restore_compressed(&dest, &restored, Some(key), true, Some(&identity)).expect("restore asym OK");
        {
            let c = open_db_keyed(&restored, Some(key)).unwrap();
            let v: i64 = c.query_row("SELECT x FROM t", [], |r| r.get(0)).unwrap();
            assert_eq!(v, 42);
        }
        // (3) restore SANS identité (passphrase seule) -> ÉCHOUE (le pod ne peut pas lire les backups asym).
        let r2 = dir.join("r2.db").to_string_lossy().into_owned();
        assert!(crate::backup::restore_compressed(&dest, &r2, Some(key), true, None).is_err(),
            "backup asymétrique NON déchiffrable à la seule passphrase");

        // (4) INERTE : recipient=None -> symétrique (scrypt), full-verify EN cluster (comportement historique).
        let dest_sym = dir.join("sym.age").to_string_lossy().into_owned();
        crate::backup::backup_compressed(&src, &dest_sym, Some(key), None).expect("backup sym OK");
        assert_eq!(crate::backup::verify_backup(&dest_sym, Some(key), None).unwrap(),
            (crate::backup::BackupKind::Symmetric, true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// v134 (#7) — repli SYMÉTRIQUE (backup node-déchiffrable) : (a) NON-CASSANT par DÉFAUT (recipient=None ->
    /// backup symétrique produit, warn-only) ; (b) OPT-IN FAIL-CLOSED `PLUME_BACKUP_REQUIRE_ASYMMETRIC=1` ->
    /// REFUS ; (c) destinataire asymétrique -> toujours OK ; (d) signal SOC NON-PURGEABLE (source managée
    /// plume-config, origin=daemon, dedup horaire idempotent). PLUME_BACKUP_REQUIRE_ASYMMETRIC n'est touché que
    /// par ce test -> pas de course.
    #[test]
    fn v134_backup_require_asymmetric_gate_and_signal() {
        let dir = std::env::temp_dir().join(format!("plume-v134bk-{}-{}", std::process::id(), now()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = "v134-backup-key";
        let src = dir.join("src.db").to_string_lossy().into_owned();
        {
            let c = open_db_keyed(&src, Some(key)).unwrap();
            c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES(7);").unwrap();
        }
        let dest = dir.join("bk.age").to_string_lossy().into_owned();

        let save = std::env::var("PLUME_BACKUP_REQUIRE_ASYMMETRIC").ok();
        std::env::remove_var("PLUME_BACKUP_REQUIRE_ASYMMETRIC");
        assert!(!crate::backup::backup_require_asymmetric(), "non posé -> OFF (défaut)");
        // (a) DÉFAUT (OFF) : recipient=None -> backup SYMÉTRIQUE produit (non-cassant, comportement historique).
        crate::backup::backup_compressed(&src, &dest, Some(key), None).expect("défaut OFF -> backup symétrique OK");
        // (b) OPT-IN : REQUIRE=1 + recipient=None -> REFUS fail-closed (aucun backup node-déchiffrable silencieux).
        std::env::set_var("PLUME_BACKUP_REQUIRE_ASYMMETRIC", "1");
        assert!(crate::backup::backup_require_asymmetric(), "=1 -> ON");
        let _ = std::fs::remove_file(&dest);
        assert!(crate::backup::backup_compressed(&src, &dest, Some(key), None).is_err(),
            "REQUIRE=1 + pas de destinataire -> backup REFUSÉ (fail-closed)");
        assert!(!std::path::Path::new(&dest).exists(), "aucun backup produit sur refus (fail-closed AVANT écriture)");
        // (c) REQUIRE=1 + destinataire asymétrique -> OK (l'exigence est satisfaite).
        let rcpt = age::x25519::Identity::generate().to_public().to_string();
        crate::backup::backup_compressed(&src, &dest, Some(key), Some(&rcpt)).expect("REQUIRE=1 + destinataire -> OK");
        match save { Some(v) => std::env::set_var("PLUME_BACKUP_REQUIRE_ASYMMETRIC", v), None => std::env::remove_var("PLUME_BACKUP_REQUIRE_ASYMMETRIC") }

        // (d) SIGNAL SOC NON-PURGEABLE (miroir de emit_ledger_unsigned/emit_disk_health) : source managée
        //     plume-config, category=health, severity 4, origin=daemon, dedup HORAIRE (idempotent).
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        let t0 = 1_700_000_000i64;
        assert!(crate::backup::emit_backup_symmetric_signal(&conn, t0), "1er signal écrit");
        let (src_s, cat, sev, org): (String, String, i64, String) = conn.query_row(
            "SELECT source,category,severity,origin FROM event WHERE source='plume-config' AND category='health' ORDER BY id DESC LIMIT 1",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap();
        assert_eq!((src_s.as_str(), cat.as_str(), sev, org.as_str()), ("plume-config", "health", 4, "daemon"),
            "signal managé non-purgeable (origin=daemon)");
        // idempotent HORAIRE : 2e appel dans le même bucket -> aucune nouvelle ligne (anti-spam).
        assert!(!crate::backup::emit_backup_symmetric_signal(&conn, t0 + 60), "même heure -> dédup");
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE source='plume-config'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "un seul signal par heure");

        // (e) v135 (#7) — RELOCALISATION : le signal part du VRAI chemin backup (sidecar -> signal_backup_symmetric_if_needed),
        //     PLUS du boot du conteneur principal. Contrat : (i) destinataire ASYMÉTRIQUE -> JAMAIS de signal (posture
        //     saine, cas des backups live `-> X25519`) ; (ii) repli SYMÉTRIQUE (None ou "") -> signal émis. Buckets
        //     horaires distincts pour isoler du dédup ci-dessus.
        let rcpt2 = age::x25519::Identity::generate().to_public().to_string();
        assert!(!crate::backup::signal_backup_symmetric_if_needed(&conn, Some(&rcpt2), t0 + 7200),
            "destinataire asymétrique -> AUCUN signal (posture saine), même dans un bucket neuf");
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE source='plume-config'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "backup asymétrique n'émet rien -> toujours 1 signal");
        assert!(crate::backup::signal_backup_symmetric_if_needed(&conn, None, t0 + 7200),
            "repli symétrique (recipient=None) -> signal émis depuis le chemin backup");
        assert!(crate::backup::signal_backup_symmetric_if_needed(&conn, Some(""), t0 + 10800),
            "repli symétrique (recipient=\"\" vide) -> signal émis (bucket neuf)");
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE source='plume-config'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 3, "2 nouveaux signaux symétriques (buckets distincts) s'ajoutent au 1er");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Vieillit la mtime d'un fichier (helper de test du balayage) via `libc::utimes` — std ne
    /// réexpose pas utime, et `libc` est déjà une dépendance de l'arbre.
    fn filetime_set(path: &std::path::Path, t: std::time::SystemTime) {
        use std::os::unix::ffi::OsStrExt;
        let secs = t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let tv = [
            libc::timeval { tv_sec: secs, tv_usec: 0 },
            libc::timeval { tv_sec: secs, tv_usec: 0 },
        ];
        unsafe { libc::utimes(c.as_ptr(), tv.as_ptr()); }
    }

    fn col_exists(conn: &Connection, table: &str, col: &str) -> bool {
        let mut st = conn.prepare(&format!("PRAGMA table_info({table})")).unwrap();
        let cols: Vec<String> = st.query_map([], |r| r.get::<_, String>(1)).unwrap().flatten().collect();
        cols.iter().any(|c| c == col)
    }

    // --- PERSONNALISATION PHASE 1 : overlays config.d -------------------------------------------------
    // Répertoire temporaire unique (pid + compteur monotone) -> pas de collision entre tests parallèles.
    fn mk_overlay_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("plume-overlays-{}-{tag}-{}-{n}", std::process::id(), now()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    fn write_overlay(root: &std::path::Path, sub: &str, file: &str, json: &str) {
        let d = root.join(sub);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(file), json).unwrap();
    }

    #[test]
    fn overlays_load_idempotent_and_managed() {
        let conn = test_db();
        let dir = mk_overlay_dir("idem");
        write_overlay(&dir, "parsers", "p.json", r#"{"_comment":"exemple","name":"ov-parser","source":"nginx","pattern":"status=(?P<status>\\d+)","enabled":true}"#);
        write_overlay(&dir, "rules", "r.json", r#"{"name":"ov-rule","query":"search severity>=3 | stats count","is_soql":true,"op":">","threshold":5,"severity":3,"mitre":"T1110"}"#);
        write_overlay(&dir, "playbooks", "b.json", r#"{"name":"ov-pb","query":"search source=x | table src_ip","is_soql":true,"action_kind":"ban_ip","enabled":false}"#);
        load_overlays_dir(&conn, &dir);
        // managed=1 partout (source git).
        let pm: i64 = conn.query_row("SELECT managed FROM parser WHERE name='ov-parser'", [], |r| r.get(0)).unwrap();
        let rm: i64 = conn.query_row("SELECT managed FROM rule WHERE name='ov-rule'", [], |r| r.get(0)).unwrap();
        let bm: i64 = conn.query_row("SELECT managed FROM playbook WHERE name='ov-pb'", [], |r| r.get(0)).unwrap();
        assert_eq!((pm, rm, bm), (1, 1, 1), "overlays posés avec managed=1");
        // IDEMPOTENT : re-jouer -> toujours UNE ligne par name, même état.
        load_overlays_dir(&conn, &dir);
        let pc: i64 = conn.query_row("SELECT COUNT(*) FROM parser WHERE name='ov-parser'", [], |r| r.get(0)).unwrap();
        let rc: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE name='ov-rule'", [], |r| r.get(0)).unwrap();
        let bc: i64 = conn.query_row("SELECT COUNT(*) FROM playbook WHERE name='ov-pb'", [], |r| r.get(0)).unwrap();
        assert_eq!((pc, rc, bc), (1, 1, 1), "re-load idempotent : pas de doublon");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overlay_wins_over_builtin_same_name() {
        // migrate() v22 seede le builtin parser "sshd — user + rhost" (managed=0, builtin=1). Un overlay
        // du MÊME nom doit l'écraser : nouveau motif, builtin=0, managed=1, et UNE seule ligne (pas de doublon).
        let conn = test_db();
        let before: i64 = conn.query_row("SELECT builtin FROM parser WHERE name='sshd — user + rhost'", [], |r| r.get(0)).unwrap();
        assert_eq!(before, 1, "pré-condition : le builtin existe");
        let dir = mk_overlay_dir("wins");
        write_overlay(&dir, "parsers", "p.json", r#"{"name":"sshd — user + rhost","source":"sshd","pattern":"OVERRIDE (?P<user>\\S+)","enabled":true}"#);
        load_overlays_dir(&conn, &dir);
        let (pat, builtin, managed): (String, i64, i64) = conn.query_row(
            "SELECT pattern,builtin,managed FROM parser WHERE name='sshd — user + rhost'", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert!(pat.contains("OVERRIDE"), "l'overlay écrase le motif builtin");
        assert_eq!((builtin, managed), (0, 1), "désormais overlay-managed");
        let c: i64 = conn.query_row("SELECT COUNT(*) FROM parser WHERE name='sshd — user + rhost'", [], |r| r.get(0)).unwrap();
        assert_eq!(c, 1, "pas de doublon : UPSERT keyé par name");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overlay_invalid_files_skipped_no_crash() {
        let conn = test_db();
        let dir = mk_overlay_dir("bad");
        write_overlay(&dir, "parsers", "broken.json", r#"{ pas du json "#);              // JSON cassé
        write_overlay(&dir, "parsers", "badrx.json", r#"{"name":"bad-rx","pattern":"(?P<x>","enabled":true}"#); // regex invalide
        write_overlay(&dir, "rules", "badrule.json", r#"{"name":"bad-rule","query":"search x | stats nope(y)","is_soql":true}"#); // SOQL invalide
        write_overlay(&dir, "rules", "badmitre.json", r#"{"name":"bad-mitre","query":"search severity>=3 | stats count","is_soql":true,"mitre":"XXXX"}"#); // MITRE invalide
        write_overlay(&dir, "parsers", "good.json", r#"{"name":"good-parser","pattern":"ok=(?P<ok>\\d+)","enabled":true}"#); // valide
        load_overlays_dir(&conn, &dir); // NE doit PAS paniquer
        let good: i64 = conn.query_row("SELECT COUNT(*) FROM parser WHERE name='good-parser'", [], |r| r.get(0)).unwrap();
        assert_eq!(good, 1, "le fichier valide passe");
        let bad_rx: i64 = conn.query_row("SELECT COUNT(*) FROM parser WHERE name='bad-rx'", [], |r| r.get(0)).unwrap();
        let bad_rule: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE name='bad-rule'", [], |r| r.get(0)).unwrap();
        let bad_mitre: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE name='bad-mitre'", [], |r| r.get(0)).unwrap();
        assert_eq!((bad_rx, bad_rule, bad_mitre), (0, 0, 0), "les fichiers invalides sont skippés");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overlays_missing_dir_is_noop() {
        let conn = test_db();
        let mut p = std::env::temp_dir();
        p.push(format!("plume-overlays-absent-{}-{}", std::process::id(), now()));
        load_overlays_dir(&conn, &p); // répertoire inexistant -> no-op gracieux, pas de panique
    }

    #[test]
    fn shipped_config_d_examples_load() {
        // Garde-fou : les EXEMPLES livrés dans le repo (../config.d) doivent réellement charger (regex +
        // SOQL valides), pas être silencieusement skippés. Chemin résolu via CARGO_MANIFEST_DIR (= daemon/).
        let conn = test_db();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config.d");
        load_overlays_dir(&conn, &root);
        let p: i64 = conn.query_row("SELECT managed FROM parser WHERE name='nginx — méthode + chemin + statut'", [], |r| r.get(0)).unwrap();
        let r: i64 = conn.query_row("SELECT managed FROM rule WHERE name='Exemple — pic de 5xx nginx par IP (10 min)'", [], |r| r.get(0)).unwrap();
        let b: i64 = conn.query_row("SELECT managed FROM playbook WHERE name='Exemple — auto-ban brute-force nginx 401 (10 min)'", [], |r| r.get(0)).unwrap();
        assert_eq!((p, r, b), (1, 1, 1), "les 3 exemples config.d doivent charger avec managed=1");
    }

    // ============================================================================================
    //  #5 PURPLE — FERMETURE DES ANGLES MORTS DE DÉTECTION (scan low-and-slow + télémétrie multi-couche).
    //  Contexte : un tir Forge réel a scoré 0% sur 2 techniques car (a) le log UFW rate-limité 3/min ÉTOUFFE
    //  un scan lent avant le SIEM et (b) Cloudflare absorbe les web-scans AU EDGE avant l'origine surveillée.
    //  Parade (subset AUTONOME, daemon+config.d) : 2 parseurs déclaratifs qui normalisent une télémétrie
    //  ALTERNATIVE (nft scan-detect ; firewallEventsAdaptive CF) en CIM + des règles de corrélation dont le
    //  seuil porte sur la DIVERSITÉ (dc), PAS sur le volume/débit -> tirent sur le PATTERN de ce qui ARRIVE,
    //  même clairsemé. Tous les e2e exercent le CHEMIN PLANIFIÉ `run_due_rules` (pas le dry-run) : la leçon
    //  2026-07-10 = un dry-run qui passe ne prouve PAS que l'ordonnanceur tire.
    // ============================================================================================

    // Spec du parseur nft scan-detect (miroir de config.d/parsers/nft-scan-detect.json, sans _comment).
    fn nft_parser_spec() -> String {
        r#"{"name":"nft scan-detect","source":"nft","enabled":true,"match":"PORTSCAN[46]?:",
        "extract":[{"regex":"SRC=(?P<src>[0-9A-Fa-f.:]+)"},{"regex":"DST=(?P<dst>[0-9A-Fa-f.:]+)"},
        {"regex":"DPT=(?P<dpt>[0-9]+)"},{"regex":"PROTO=(?P<proto>[A-Za-z0-9_-]+)"}],
        "map":{"category":"firewall","severity":2,"action":"deny","src_ip":"$src","dst_ip":"$dst",
        "fields":{"dst_port":"$dpt","proto":"$proto","signal":"portscan"}}}"#.to_string()
    }
    // Spec du parseur Cloudflare firewallEventsAdaptive (miroir de config.d/parsers/cloudflare-firewall-events.json).
    fn cf_parser_spec() -> String {
        r#"{"name":"cf fw events","source":"cloudflare","enabled":true,"match":"\"clientIP\"",
        "extract":[{"json":true}],
        "map":{"category":"firewall","severity":2,"action":"$action","src_ip":"$clientIP",
        "fields":{"vhost":"$clientRequestHTTPHost","path":"$clientRequestPath","cf_source":"$source",
        "cf_rule":"$ruleId","cf_ua":"$userAgent"}}}"#.to_string()
    }
    // Une ligne LOG kernel nft PORTSCAN réaliste (format iptables/nft key=value) vers le port `dpt`.
    fn nft_portscan_line(src: &str, dst: &str, dpt: u32) -> String {
        format!("kernel: PORTSCAN4: IN=eth0 OUT= MAC=de:ad SRC={src} DST={dst} LEN=44 TOS=0x00 PREC=0x00 \
                 TTL=52 ID=1234 PROTO=TCP SPT=40000 DPT={dpt} WINDOW=1024 RES=0x00 SYN URGP=0")
    }

    /// UNIT — le parseur nft scan-detect normalise une ligne PORTSCAN kernel en CIM (category/action/src/dst/port).
    #[test]
    fn dparser_nft_scan_line_to_cim() {
        let conn = test_db();
        let dpath = ":memory:dparser-nft-sd";
        conn.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('nft-sd','nft',?1,1,0,1,0)",
            params![nft_parser_spec()]).unwrap();
        dparsers_reload(&conn, dpath);
        let (fields, cat, sev) = dparsers_apply(dpath, "nft", &nft_portscan_line("203.0.113.50", "198.51.100.9", 445), None);
        assert_eq!(cat.as_deref(), Some("firewall"), "category CIM littérale");
        assert_eq!(sev, Some(2), "severity mappée");
        let fv: Value = serde_json::from_str(fields.as_deref().unwrap()).unwrap();
        assert_eq!(fv["src_ip"], "203.0.113.50", "SRC -> src_ip");
        assert_eq!(fv["dst_ip"], "198.51.100.9", "DST -> dst_ip");
        assert_eq!(fv["dst_port"], "445", "DPT -> fields.dst_port");
        assert_eq!(fv["proto"], "TCP", "PROTO -> fields.proto");
        assert_eq!(fv["action"], "deny", "probe droppée -> action=deny (alimente category=firewall action=deny)");
        assert_eq!(fv["signal"], "portscan");
        // GARDE : le match `PORTSCAN` -> une ligne SANS ce préfixe sous la même source n'est PAS mappée (no-op).
        let (_f2, c2, _s2) = dparsers_apply(dpath, "nft", "kernel: ACCEPT SRC=10.0.0.1 DPT=22", None);
        assert!(c2.is_none(), "ligne non-PORTSCAN -> parseur ne s'applique pas (match gardé)");
    }

    /// UNIT — le parseur Cloudflare firewallEventsAdaptive (JSON) extrait la VRAIE IP attaquant + vhost/path.
    #[test]
    fn dparser_cloudflare_json_to_cim() {
        let conn = test_db();
        let dpath = ":memory:dparser-cf-fe";
        conn.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('cf-fe','cloudflare',?1,1,0,1,0)",
            params![cf_parser_spec()]).unwrap();
        dparsers_reload(&conn, dpath);
        let msg = json!({"action":"managed_challenge","clientIP":"203.0.113.9","clientRequestHTTPHost":"lab.example.com",
                         "clientRequestPath":"/wp-admin","source":"firewallManaged","ruleId":"r-42","userAgent":"nuclei"}).to_string();
        let (fields, cat, sev) = dparsers_apply(dpath, "cloudflare", &msg, None);
        assert_eq!(cat.as_deref(), Some("firewall"));
        assert_eq!(sev, Some(2));
        let fv: Value = serde_json::from_str(fields.as_deref().unwrap()).unwrap();
        assert_eq!(fv["src_ip"], "203.0.113.9", "clientIP -> src_ip (VRAIE IP attaquant, PAS l'edge)");
        assert_eq!(fv["action"], "managed_challenge", "action CF brute préservée");
        assert_eq!(fv["vhost"], "lab.example.com");
        assert_eq!(fv["path"], "/wp-admin");
        assert_eq!(fv["cf_source"], "firewallManaged");
    }

    /// E2E ORDONNANCEUR — un scan VERTICAL low-and-slow (12 probes SEULEMENT, mais 12 ports DISTINCTS d'UNE IP)
    /// TIRE via `run_due_rules` : le seuil dc(dst_port)>8 porte sur la DIVERSITÉ, pas sur le volume -> ce que le
    /// throttle laisse passer suffit. Contraste PROUVÉ dans le même test : une règle volume (count>50) NE tire
    /// PAS (12 << 50) et la règle HORIZONTALE (dc(dst_ip)>5) NE tire PAS (1 seul hôte cible). C'est exactement
    /// « détecter le pattern dans ce qui arrive, pas le débit brut ». Ingest via le PARSEUR nft (chemin réel).
    #[test]
    fn scheduled_low_and_slow_portscan_fires_on_diverse_low_volume() {
        let mut path = std::env::temp_dir();
        path.push(format!("plume-lns-ps-{}-{}.db", std::process::id(), now()));
        let p = path.to_string_lossy().to_string();
        let base = now() - 1800; // dans la fenêtre 3600s
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            w.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('nft-sd','nft',?1,1,0,1,0)",
                params![nft_parser_spec()]).unwrap();
            dparsers_reload(&w, &p);
            // Règle VERTICALE (contenu shippé) : dc(dst_port) by src_ip > 8.
            w.execute("INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed) \
                VALUES('Port-scan vertical low-and-slow',1,'search category=firewall action=deny | stats dc(dst_port) by src_ip | where dc > 8 | stats count',1,'>',0,3,300,3600,'T1046',2)", []).unwrap();
            // Règle HORIZONTALE (shippée) : dc(dst_ip) > 5 — NE doit PAS tirer (1 seul dst_ip).
            w.execute("INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed) \
                VALUES('Scan horizontal low-and-slow',1,'search category=firewall action=deny | stats dc(dst_ip) by src_ip | where dc > 5 | stats count',1,'>',0,3,300,3600,'T1046',2)", []).unwrap();
            // Règle VOLUME témoin : count > 50 — NE doit PAS tirer (12 events seulement).
            w.execute("INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed) \
                VALUES('temoin-volume',1,'search category=firewall action=deny | stats count by src_ip | where count > 50 | stats count',1,'>',0,3,300,3600,'T1046',2)", []).unwrap();
            // 12 probes d'UNE IP vers 12 ports DISTINCTS (bas volume, forte diversité) — via le PARSEUR.
            let ports = [21u32, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389];
            let events: Vec<Value> = ports.iter().enumerate().map(|(i, dpt)| json!({
                "ts": base + (i as i64) * 20, "source": "nft", "category": "", "severity": 0,
                "message": nft_portscan_line("203.0.113.66", "198.51.100.9", *dpt), "dedup": format!("nft-{i}")
            })).collect();
            assert_eq!(ingest_events_batch(&w, &p, &events, base, None, None).expect("ingest"), 12);
            // sanity : le parseur a bien produit category=firewall + dst_port variés.
            let ncat: i64 = w.query_row("SELECT COUNT(*) FROM event WHERE category='firewall' AND src_ip='203.0.113.66'", [], |r| r.get(0)).unwrap();
            assert_eq!(ncat, 12, "les 12 probes normalisées en CIM firewall par le parseur");
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_due_rules(&db, &p);
        let (vert_val, vert_fired, horiz_val, vol_val, n_t1046): (f64, i64, f64, f64, i64) = {
            let c = db.lock();
            let vv: f64 = c.query_row("SELECT COALESCE(last_value,-1) FROM rule WHERE name='Port-scan vertical low-and-slow'", [], |r| r.get(0)).unwrap();
            let vf: i64 = c.query_row("SELECT CASE WHEN last_fired IS NULL THEN 0 ELSE 1 END FROM rule WHERE name='Port-scan vertical low-and-slow'", [], |r| r.get(0)).unwrap();
            let hv: f64 = c.query_row("SELECT COALESCE(last_value,-1) FROM rule WHERE name='Scan horizontal low-and-slow'", [], |r| r.get(0)).unwrap();
            let ov: f64 = c.query_row("SELECT COALESCE(last_value,-1) FROM rule WHERE name='temoin-volume'", [], |r| r.get(0)).unwrap();
            let na: i64 = c.query_row("SELECT COUNT(*) FROM alert WHERE mitre='T1046'", [], |r| r.get(0)).unwrap();
            (vv, vf, hv, ov, na)
        };
        let _ = std::fs::remove_file(&p);
        assert_eq!(vert_val, 1.0, "VERTICAL : 1 IP au-dessus de dc(dst_port)>8 (12 ports distincts) -> tire");
        assert_eq!(vert_fired, 1, "VERTICAL : last_fired posé (chemin ordonnanceur)");
        assert_eq!(horiz_val, 0.0, "HORIZONTAL : 1 seul dst_ip -> sous seuil, NE tire pas");
        assert_eq!(vol_val, 0.0, "VOLUME témoin : 12 << 50 -> NE tire pas (preuve : c'est la DIVERSITÉ, pas le débit)");
        assert!(n_t1046 >= 1, "une alerte T1046 persistée (la matrice de couverture s'allume)");
    }

    /// E2E ORDONNANCEUR — recon web EDGE low-and-slow via Cloudflare : 6 requêtes challengées d'UNE IP vers 6
    /// chemins DISTINCTS (sous TOUS les seuils volume CF : 25>20, 28>3) TIRENT sur dc(path)>5. Ingest via le
    /// PARSEUR CF (firewallEventsAdaptive JSON -> CIM). Prouve la fermeture de l'angle mort edge single-shot.
    #[test]
    fn scheduled_low_and_slow_cf_recon_fires() {
        let mut path = std::env::temp_dir();
        path.push(format!("plume-lns-cf-{}-{}.db", std::process::id(), now()));
        let p = path.to_string_lossy().to_string();
        let base = now() - 900;
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            w.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('cf-fe','cloudflare',?1,1,0,1,0)",
                params![cf_parser_spec()]).unwrap();
            dparsers_reload(&w, &p);
            w.execute("INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed) \
                VALUES('Recon web edge low-and-slow',1,'search source=cloudflare | stats dc(path) by src_ip | where dc > 5 | stats count',1,'>',0,3,300,3600,'T1595.002',2)", []).unwrap();
            let paths = ["/admin", "/.env", "/wp-login.php", "/api/v1/keys", "/backup.zip", "/.git/config"];
            let events: Vec<Value> = paths.iter().enumerate().map(|(i, pth)| {
                let m = json!({"action":"managed_challenge","clientIP":"203.0.113.99","clientRequestHTTPHost":"lab.example.com",
                               "clientRequestPath": pth, "source":"firewallManaged","ruleId":"r","userAgent":"nuclei"}).to_string();
                json!({"ts": base + (i as i64) * 60, "source": "cloudflare", "category": "", "severity": 0,
                       "message": m, "dedup": format!("cf-{i}")})
            }).collect();
            assert_eq!(ingest_events_batch(&w, &p, &events, base, None, None).expect("ingest"), 6);
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_due_rules(&db, &p);
        let (val, fired, n_mitre): (f64, i64, i64) = {
            let c = db.lock();
            let v: f64 = c.query_row("SELECT COALESCE(last_value,-1) FROM rule WHERE name='Recon web edge low-and-slow'", [], |r| r.get(0)).unwrap();
            let f: i64 = c.query_row("SELECT CASE WHEN last_fired IS NULL THEN 0 ELSE 1 END FROM rule WHERE name='Recon web edge low-and-slow'", [], |r| r.get(0)).unwrap();
            let n: i64 = c.query_row("SELECT COUNT(*) FROM alert WHERE mitre='T1595.002'", [], |r| r.get(0)).unwrap();
            (v, f, n)
        };
        let _ = std::fs::remove_file(&p);
        assert_eq!(val, 1.0, "1 IP au-dessus de dc(path)>5 (6 chemins distincts au edge) -> tire");
        assert_eq!(fired, 1, "last_fired posé (chemin ordonnanceur)");
        assert!(n_mitre >= 1, "alerte T1595.002 persistée (couverture edge allumée)");
    }

    /// GARDE-FOU — le contenu de détection SHIPPÉ (config.d réel) charge : les 2 nouveaux parseurs (nft/CF) et
    /// les 3 nouvelles règles low-and-slow sont posés managed=1 ET compilent (regex + SOQL valides), pas
    /// silencieusement skippés. Chemin RÉEL load_overlays_dir sur ../config.d.
    #[test]
    fn shipped_config_d_scan_content_loads() {
        let conn = test_db();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config.d");
        load_overlays_dir(&conn, &root);
        for pname in ["nft scan-detect (PORTSCAN LOG) → CIM firewall", "Cloudflare firewallEventsAdaptive (JSON) → CIM"] {
            let (src, m): (String, i64) = conn.query_row("SELECT source, managed FROM dparser WHERE name=?1", params![pname],
                |r| Ok((r.get(0)?, r.get(1)?))).unwrap_or_else(|_| panic!("parseur shippé absent: {pname}"));
            assert_eq!(m, 1, "parseur {pname} managed=1");
            assert!(!src.is_empty(), "parseur {pname} a une source");
            let leg: i64 = conn.query_row("SELECT COUNT(*) FROM parser WHERE name=?1", params![pname], |r| r.get(0)).unwrap();
            assert_eq!(leg, 0, "parseur déclaratif {pname} PAS dans la table parser legacy");
        }
        for (rname, mitre) in [
            ("Port-scan vertical low-and-slow (firewall, tout vendeur)", "T1046"),
            ("Scan horizontal low-and-slow (firewall, tout vendeur)", "T1046"),
            ("Recon web edge low-and-slow (Cloudflare path-breadth)", "T1595.002"),
        ] {
            let (en, mgd, mt): (i64, i64, String) = conn.query_row(
                "SELECT enabled, managed, COALESCE(mitre,'') FROM rule WHERE name=?1", params![rname],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap_or_else(|_| panic!("règle shippée absente: {rname}"));
            assert_eq!((en, mgd), (1, 1), "règle {rname} enabled + managed=1 (compile via rule_sql, sinon skippée)");
            assert_eq!(mt, mitre, "règle {rname} taguée {mitre}");
        }
    }

    // ============================================================================================
    //  SLICE #7 — PIÈCE 3 : IMPORTEUR SIGMA
    // ============================================================================================

    /// SÉCURITÉ — l'import Sigma (`/api/sigma/import`) est ADMIN-ONLY (default-deny : hors allowlist).
    #[test]
    fn sigma_import_route_is_admin_only() {
        assert!(rbac_gate("admin", "/api/sigma/import", true).is_ok(), "admin importe");
        assert!(rbac_gate("editor", "/api/sigma/import", true).is_err(), "editor n'importe PAS (default-deny)");
        assert!(rbac_gate("viewer", "/api/sigma/import", true).is_err(), "viewer n'importe PAS");
        assert!(rbac_gate("agent", "/api/sigma/import", true).is_err(), "agent n'importe PAS");
    }

    /// La table logsource->category ne cible QUE des catégories CIM valides (pas de dérive taxonomie).
    #[test]
    fn sigma_logsource_map_targets_are_cim() {
        for (k, c) in SIGMA_LOGSOURCE_CATEGORY {
            assert!(cim_category_ok(c), "logsource '{k}' -> '{c}' n'est PAS une catégorie CIM");
        }
    }

    /// RÈGLE RÉELLE #1 (Sysmon process_creation, |contains) -> SOQL + métadonnées correctes.
    #[test]
    fn sigma_process_creation_contains_translates() {
        let doc = json!({
            "title": "Whoami Command Execution (Discovery)",
            "logsource": { "category": "process_creation", "product": "windows" },
            "detection": { "selection": { "CommandLine|contains": "whoami" }, "condition": "selection" },
            "level": "low",
            "tags": ["attack.discovery", "attack.t1033"]
        });
        let t = sigma_translate(&doc).expect("doit traduire");
        assert_eq!(t.query, "search category=endpoint CommandLine=~(?i)whoami | stats count");
        assert_eq!(t.severity, 1, "level low -> sev 1");
        assert_eq!(t.mitre, "T1033", "attack.t1033 -> T1033");
        assert_eq!(t.op, ">");
        assert_eq!(t.threshold, 0.0);
        // C'est une règle Plume VALIDE (recompile via le compilo SOQL du cœur).
        assert!(rule_sql(&t.query, true, t.window_s).is_ok(), "le SOQL produit doit compiler");
    }

    /// RÈGLE RÉELLE #2 (firewall, `selection and not filter` avec liste) -> égalité + `not in`.
    #[test]
    fn sigma_firewall_negated_list_translates() {
        let doc = json!({
            "title": "Firewall Denied to Non-Standard Port",
            "logsource": { "category": "firewall" },
            "detection": {
                "selection": { "action": "deny" },
                "filter": { "dst_port": [80, 443] },
                "condition": "selection and not filter"
            },
            "level": "low",
            "tags": ["attack.t1046"]
        });
        let t = sigma_translate(&doc).expect("doit traduire");
        assert_eq!(t.query, "search category=firewall action=~(?i)^deny$ dport not in (80,443) | stats count");
        assert_eq!(t.severity, 1);
        assert_eq!(t.mitre, "T1046");
        assert!(rule_sql(&t.query, true, t.window_s).is_ok());
    }

    /// Les modificateurs `|contains` vs `|startswith` mappent DIFFÉREMMENT (non ancré vs ancré début) ;
    /// la ponctuation littérale (`/`) est échappée sans casser SOQL.
    #[test]
    fn sigma_contains_vs_startswith_map_correctly() {
        let mk = |k: &str| json!({
            "title": "t", "logsource": { "category": "webserver" },
            "detection": { "selection": { k: "/admin" }, "condition": "selection" }
        });
        let c = sigma_translate(&mk("url|contains")).unwrap();
        let s = sigma_translate(&mk("url|startswith")).unwrap();
        assert_eq!(c.query, "search category=web url=~(?i)\\/admin | stats count", "contains = non ancré");
        assert_eq!(s.query, "search category=web url=~(?i)^\\/admin | stats count", "startswith = ancré début ^");
        // endswith = ancré fin $
        let e = sigma_translate(&mk("url|endswith")).unwrap();
        assert_eq!(e.query, "search category=web url=~(?i)\\/admin$ | stats count");
        // égalité pure d'un entier -> comparaison numérique (pas de regex).
        let n = sigma_translate(&json!({
            "title": "t", "logsource": { "category": "firewall" },
            "detection": { "selection": { "dst_port": 4444 }, "condition": "selection" }
        })).unwrap();
        assert_eq!(n.query, "search category=firewall dport=4444 | stats count");
    }

    /// Une liste d'égalités (OU) sur un champ -> `field in (...)`, et un logsource inconnu N'EST PAS
    /// un drop (règle importée, avertissement émis).
    #[test]
    fn sigma_equals_list_and_unknown_logsource_warns_not_drops() {
        let doc = json!({
            "title": "t", "logsource": { "product": "someexoticproduct" },
            "detection": { "selection": { "EventID": [4624, 4625, 4672] }, "condition": "selection" }
        });
        let t = sigma_translate(&doc).expect("importée malgré logsource inconnu");
        assert_eq!(t.query, "search EventID in (4624,4625,4672) | stats count", "pas de category (logsource non mappé), OU d'égalités -> in()");
        assert!(t.warnings.iter().any(|w| w.contains("logsource")), "un avertissement de non-mapping doit être présent");
    }

    /// GARDE ANTI-ANGLE-MORT : les construits inexprimables sont FLAGGÉS (Err avec raison), JAMAIS
    /// traduits en une règle silencieusement fausse (sous-matchante).
    #[test]
    fn sigma_unsupported_constructs_are_flagged_not_silently_wrong() {
        let base = |det: Value| json!({ "title": "t", "logsource": {"category":"firewall"}, "detection": det });
        // (a) OU inter-champs via 'or'
        let e = sigma_translate(&base(json!({ "a": {"action":"deny"}, "b": {"action":"allow"}, "condition": "a or b" }))).unwrap_err();
        assert!(e.to_lowercase().contains("or") || e.contains("OU"), "or doit être flaggé : {e}");
        // (b) '1 of them'
        let e = sigma_translate(&base(json!({ "s1": {"action":"deny"}, "s2": {"action":"drop"}, "condition": "1 of them" }))).unwrap_err();
        assert!(e.contains("1 of") || e.contains("OU"), "1 of them doit être flaggé : {e}");
        // (c) modificateur d'encodage non exprimable
        let e = sigma_translate(&base(json!({ "selection": {"CommandLine|base64": "d2hvYW1p"}, "condition": "selection" }))).unwrap_err();
        assert!(e.contains("base64") || e.contains("modificateur"), "base64 doit être flaggé : {e}");
        // (d) OU de sous-chaînes (liste + contains)
        let e = sigma_translate(&base(json!({ "selection": {"CommandLine|contains": ["a","b"]}, "condition": "selection" }))).unwrap_err();
        assert!(e.to_lowercase().contains("ou") || e.contains("liste"), "OR-of-contains doit être flaggé : {e}");
        // (e) match sur null (existence)
        let e = sigma_translate(&base(json!({ "selection": {"user": null}, "condition": "selection" }))).unwrap_err();
        assert!(e.contains("null"), "null doit être flaggé : {e}");
        // (f) champ imbriqué (non-identifiant SOQL)
        let e = sigma_translate(&base(json!({ "selection": {"winlog.event_data.X": "y"}, "condition": "selection" }))).unwrap_err();
        assert!(e.contains("non mappable") || e.contains("imbriqué"), "champ imbriqué doit être flaggé : {e}");
        // (g) agrégation Sigma
        let e = sigma_translate(&base(json!({ "selection": {"action":"deny"}, "condition": "selection | count() by src_ip > 5" }))).unwrap_err();
        assert!(e.contains("agrégation") || e.contains("count"), "agrégation doit être flaggée : {e}");
    }

    /// #3/#5 — la négation d'un QUANTIFICATEUR/GROUPE (De Morgan -> OU) est FLAGGÉE (Err), jamais
    /// mistranslatée en une règle silencieusement plus étroite (sous-match). Le cas fidèle reste OK.
    #[test]
    fn sigma_negated_group_and_quantifier_are_flagged() {
        // `not all of <multi>` = NON(a ET b) = (NON a OU NON b) -> Err.
        let multi = json!({
            "title":"t","logsource":{"category":"firewall"},
            "detection": { "selection":{"action":"deny"}, "filter_a":{"user":"SYSTEM"}, "filter_b":{"user":"root"}, "condition":"selection and not all of filter_*" }
        });
        let e = sigma_translate(&multi).unwrap_err();
        assert!(e.contains("all of") || e.contains("OU"), "not all of <multi> doit être flaggé : {e}");
        // `not (a and b)` = NON(a ET b) -> Err (De Morgan OU), pas un `NON a ET b` faux.
        let grp = json!({
            "title":"t","logsource":{"category":"firewall"},
            "detection": { "selection":{"action":"deny"}, "a":{"user":"SYSTEM"}, "b":{"user":"root"}, "condition":"selection and not (a and b)" }
        });
        let e = sigma_translate(&grp).unwrap_err();
        assert!(e.contains("GROUPE") || e.contains("parenthèses") || e.contains("OU"), "not (group) doit être flaggé : {e}");
        // FIDÈLE (pas de régression) : `not all of <un seul sélecteur>` = NON(single) reste exprimable.
        let single = json!({
            "title":"t","logsource":{"category":"firewall"},
            "detection": { "selection":{"action":"deny"}, "filter_x":{"user":"root"}, "condition":"selection and not all of filter_*" }
        });
        assert!(sigma_translate(&single).is_ok(), "not all of <single> reste traduisible");
    }

    /// #8 — un `|re` embarquable mais INVALIDE pour le moteur regex de Rust est FLAGGÉ à l'import (sinon
    /// l'UDF échoue à CHAQUE éval -> règle MUETTE silencieuse). Un `|re` valide reste importable.
    #[test]
    fn sigma_invalid_re_is_flagged_at_import() {
        let bad = json!({
            "title":"t","logsource":{"category":"webserver"},
            "detection": { "selection": {"CommandLine|re": "*foo"}, "condition":"selection" }
        });
        let e = sigma_translate(&bad).unwrap_err();
        assert!(e.to_lowercase().contains("regex") || e.contains("|re"), "regex |re invalide doit être flaggé : {e}");
        let ok = json!({
            "title":"t","logsource":{"category":"webserver"},
            "detection": { "selection": {"CommandLine|re": "foo.*bar"}, "condition":"selection" }
        });
        assert!(sigma_translate(&ok).is_ok(), "|re valide reste importable");
    }

    /// #9 — un joker Sigma `*` INTERNE reste ACTIF sous |contains (parité pySigma), pas un `*` littéral ;
    /// une valeur SANS joker produit une sortie identique à avant (non-régression).
    #[test]
    fn sigma_wildcard_active_under_contains() {
        let t = sigma_translate(&json!({
            "title":"t","logsource":{"category":"webserver"},
            "detection": { "selection": {"url|contains": "Enable-*Logging"}, "condition":"selection" }
        })).unwrap();
        assert!(t.query.contains("Enable\\-.*Logging"), "le * interne devient .* (joker actif) : {}", t.query);
        assert!(!t.query.contains("\\*"), "le * n'est PAS traité en littéral \\* : {}", t.query);
        let plain = sigma_translate(&json!({
            "title":"t","logsource":{"category":"webserver"},
            "detection": { "selection": {"url|contains": "/admin"}, "condition":"selection" }
        })).unwrap();
        assert_eq!(plain.query, "search category=web url=~(?i)\\/admin | stats count", "sans joker = sortie inchangée");
    }

    /// #2/#6 — une liste OU d'égalités TEXTUELLES Sigma compile en `in(...)` CASSE-INSENSIBLE (COLLATE
    /// NOCASE) : plus de sous-match silencieux sur des membres à casse variable. Numérique = pas de COLLATE.
    #[test]
    fn sigma_equals_string_list_is_case_insensitive() {
        let t = sigma_translate(&json!({
            "title": "t", "logsource": {"category":"process_creation"},
            "detection": { "selection": { "Image": ["cmd.exe","PowerShell.exe"] }, "condition": "selection" }
        })).unwrap();
        assert_eq!(t.query, "search category=endpoint Image in (cmd.exe,PowerShell.exe) | stats count");
        let sql = rule_sql(&t.query, true, t.window_s).unwrap();
        assert!(sql.contains("COLLATE NOCASE IN ('cmd.exe','PowerShell.exe')"), "in(...) textuel doit être COLLATE NOCASE : {sql}");
        let n = sigma_translate(&json!({
            "title":"t","logsource":{"category":"firewall"},
            "detection": { "selection": {"dst_port":[80,443]}, "condition":"selection" }
        })).unwrap();
        let nsql = rule_sql(&n.query, true, n.window_s).unwrap();
        assert!(!nsql.contains("COLLATE NOCASE"), "liste numérique = pas de COLLATE : {nsql}");
    }

    /// #1 (ANTI-ANGLE-MORT) — une règle Sigma endpoint/champ étendu s'IMPORTE (pas rejetée) MAIS porte
    /// des warnings la distinguant d'une règle qui va réellement fire ; une règle réseau vivante n'en a pas.
    #[test]
    fn sigma_inert_endpoint_import_is_warned_not_silent() {
        let t = sigma_translate(&json!({
            "title":"Whoami Discovery","logsource":{"category":"process_creation","product":"windows"},
            "detection": { "selection": {"CommandLine|contains":"whoami"}, "condition":"selection" },
            "level":"low","tags":["attack.t1033"]
        })).unwrap();
        assert!(t.warnings.iter().any(|w| w.contains("endpoint")), "category=endpoint non collectée signalée : {:?}", t.warnings);
        assert!(t.warnings.iter().any(|w| w.contains("CommandLine")), "champ étendu inerte signalé : {:?}", t.warnings);
        let live = sigma_translate(&json!({
            "title":"fw","logsource":{"category":"firewall"},
            "detection": { "selection": {"action":"deny","dst_port":4444}, "condition":"selection" }
        })).unwrap();
        assert!(!live.warnings.iter().any(|w| w.contains("endpoint") || w.contains("étendu")), "règle réseau vivante sans warning inerte : {:?}", live.warnings);
    }

    /// SÉPARATION DES RÔLES — l'oracle d'inertie répond « plume COLLECTE-t-il cette donnée ? », il ne répond
    /// PAS « existe-t-il un alias ? ». On épingle les QUATRE quadrants sur des cas dont la collecte est
    /// citée dans `collected.rs` :
    ///   (1) colonne CŒUR (`src_ip`)                        -> VIVANT ;
    ///   (2) champ étendu inventorié, sans alias (`action`)  -> VIVANT ;
    ///   (3) nom Sigma ALIASÉ vers une cible collectée (`dst_port` -> `dport`) -> VIVANT ;
    ///   (4) champ étendu qu'AUCUN collecteur livré n'émet (`CommandLine`)     -> INERTE.
    /// Et le cas qui MORD si l'on re-confondait la whitelist de PERFORMANCE avec l'inventaire de collecte :
    /// `operation` est membre de `HOT_FIELDS` (index-expression prévu pour vault-audit) mais AUCUN
    /// collecteur livré ne l'émet -> il DOIT rester signalé inerte. Ré-introduire `HOT_FIELDS` dans l'oracle
    /// ferait rougir cette ligne.
    ///
    /// LIMITE HONNÊTE DE CETTE GARDE : elle ne peut PAS, à elle seule, détecter le retour du court-circuit
    /// `if SIGMA_FIELD_ALIAS.iter().any(..) { return false; }`. Raison : les cibles actuelles de la table
    /// d'alias (`src_ip`, `dst_ip`, `url`, `host`, `user`, `dport`) sont toutes collectées, donc « être une
    /// clé d'alias » et « être collecté » coïncident sur le corpus existant — un court-circuit y rendrait le
    /// MÊME verdict. Ce qui le détecte est la MUTATION : ajouter un alias vers un champ NON collecté et
    /// vérifier que la règle reste signalée inerte ; c'est le contrôle exécuté pour valider ce lot. Et cette
    /// coïncidence n'est PAS érigée en invariant (un alias vers un champ non collecté est légitime : c'est
    /// une traduction correcte d'une donnée que plume ne collecte pas encore — il doit rester AVERTI).
    #[test]
    fn sigma_inertia_oracle_follows_collection_not_aliases() {
        use crate::collected::plume_collects_field;
        // (1) colonne CŒUR de l'enveloppe.
        assert!(!sigma_field_is_inert_extended("src_ip"), "colonne cœur : jamais inerte");
        // (2) champ étendu inventorié, qui n'est PAS une clé d'alias.
        assert!(sigma_field_to_plume("action").as_deref() == Some("action"), "prémisse : `action` se traduit en lui-même (aucun alias)");
        assert!(plume_collects_field("action"), "prémisse : `action` est inventorié comme collecté");
        assert!(!sigma_field_is_inert_extended("action"), "champ collecté : pas inerte");
        // (3) nom Sigma ALIASÉ dont la CIBLE est collectée.
        assert_eq!(sigma_field_to_plume("dst_port").as_deref(), Some("dport"), "prémisse : traduction dst_port -> dport");
        assert!(plume_collects_field("dport"), "prémisse : `dport` est inventorié comme collecté");
        assert!(!sigma_field_is_inert_extended("dst_port"), "alias vers une cible COLLECTÉE : pas inerte");
        // (4) champ étendu qu'aucun collecteur livré n'émet.
        assert!(!plume_collects_field("CommandLine"), "prémisse : `CommandLine` n'est pas inventorié");
        assert!(sigma_field_is_inert_extended("CommandLine"), "champ non collecté : INERTE");
        // (5) MORSURE anti-reconfusion perf/collecte : membre de HOT_FIELDS, émis par AUCUN collecteur livré.
        assert!(HOT_FIELDS.contains(&"operation"), "prémisse : `operation` est bien dans la whitelist de perf");
        assert!(!plume_collects_field("operation"), "prémisse : aucun collecteur livré n'émet `operation`");
        assert!(sigma_field_is_inert_extended("operation"),
            "`operation` est une entrée de la whitelist de PERFORMANCE (HOT_FIELDS), pas une preuve de \
             collecte : il doit rester signalé INERTE. Si cette ligne rougit, l'oracle d'inertie a re-absorbé \
             une table qui ne répond pas à la question « plume collecte-t-il cette donnée ? ».");
    }

    /// EXTRACTEUR MÉCANIQUE DE CHAMPS ÉMIS — le SEUL oracle des DEUX sens de la garde d'inventaire (cf. la
    /// doc de `collected.rs` pour les familles balayées et les positions de producteur P1..P5). Renvoie, pour
    /// chaque fichier LIVRÉ de la surface, la liste des noms de champs qu'il écrit dans `fields`, avec son
    /// chemin RELATIF à la racine du dépôt.
    ///
    /// Il sert (A) — un champ inventorié doit être extrait de son fichier cité, donc y figurer en POSITION DE
    /// PRODUCTEUR, une occurrence quelconque du nom ne suffisant pas — ET (B) — tout champ extrait doit être
    /// inventorié. Un seul extracteur pour les deux sens : impossible qu'ils divergent.
    fn collected_extract_shipped(root: &std::path::Path) -> Vec<(String, String, &'static str)> {
        // P1 — ouverture d'un objet LITTÉRAL `fields`. Deux branches : (a) `…fields… :|= …{` — le préfixe
        // toléré entre le `:`/`=` et la `{` est BORNÉ (24 car., sans saut de ligne, alphabet fermé) : il
        // couvre `"{`, `@{`, `serde_json::json!({`, `$(printf '{`, et RIEN d'autre — un préfixe libre ferait
        // sauter le marqueur par-dessus du texte quelconque (mesuré : `"fields": self.fields,` capturait
        // alors des mots de commentaires) ; (b) `-Fields @{` — le sac passé EN PARAMÈTRE d'une cmdlet
        // PowerShell, sans `=` (mesuré : 4 sites d'appel de `plume-collector.ps1`, 11 champs, dont
        // `profile`/`local_port`/`os`, invisibles sans cette branche).
        let marker = regex::Regex::new(r#"(?i)(?:(?:\\?"|\$)?\w*fields\w*(?:\\?")?\s*[:=]\s*[A-Za-z0-9_:!@$('" ]{0,24}?|-fields\s+@)\{"#).unwrap();
        // Clé en tête d'un élément de PROFONDEUR 1 : quotée (`"x":`), quotée-échappée (`\"x\":`), nue jq
        // (`x:`) ou nue PowerShell (`x =`). Une clé imbriquée n'est PAS `fields.<X>` -> jamais extraite.
        let keyre = regex::Regex::new(r#"^\s*[,;]?\s*\\?"?([A-Za-z_][A-Za-z0-9_]*)\\?"?\s*[:=]"#).unwrap();
        // P2 — insertion par clé LITTÉRALE dans le sac de champs (Rust : `obj`/`fields`/`o` ; python).
        let insrs = regex::Regex::new(r#"\.insert\(\s*"([A-Za-z_][A-Za-z0-9_]*)"(?:\.into\(\)|\.to_string\(\))\s*,\s*Value::"#).unwrap();
        let inspy = regex::Regex::new(r#"(?i)\$?\w*fields\w*\[\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*\]\s*="#).unwrap();
        // P3 — groupes nommés d'un `pattern` de parseur.
        let grpre = regex::Regex::new(r"\(\?P<([A-Za-z_][A-Za-z0-9_]*)>").unwrap();
        // P4 — ajouteur de champ awk, conditionné à la DÉFINITION de `af` dans le même fichier.
        let afdef = regex::Regex::new(r"function\s+af\s*\(").unwrap();
        let afuse = regex::Regex::new(r#"\baf\(\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*,"#).unwrap();
        // P5 — fragment d'objet JSON échappé, à VALEUR STRING (`,\"x\":\"`). La valeur string est exigée :
        // sans elle, l'enveloppe de spool (`,\"events\":[`) serait prise pour un champ.
        let frag = regex::Regex::new(r#"[",]\s*,?\\"([A-Za-z_][A-Za-z0-9_]*)\\"\s*:\s*\\""#).unwrap();

        let mut out: Vec<(String, String, &'static str)> = Vec::new();
        for (dir, ext, fam, _) in COLLECTED_SCAN_SURFACE {
            let (dir, ext, fam) = (*dir, *ext, *fam);
            let d = root.join(dir);
            assert!(d.is_dir(), "surface d'extraction : répertoire livré `{dir}` INTROUVABLE (déplacé ?)");
            let mut files: Vec<_> = std::fs::read_dir(&d).unwrap().flatten().map(|e| e.path()).collect();
            files.sort();
            for p in files {
                if p.extension().and_then(|x| x.to_str()) != Some(ext) { continue; }
                let base = p.file_name().unwrap().to_string_lossy().to_string();
                if base == "tests.rs" { continue; }
                let rel = format!("{dir}/{base}");
                let mut body = match std::fs::read_to_string(&p) { Ok(b) => b, Err(_) => continue };

                if ext == "json" {
                    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                    if let Some(o) = v.pointer("/map/fields").and_then(|x| x.as_object()) {
                        for k in o.keys() { out.push((k.clone(), rel.clone(), fam)); }
                    }
                    if let Some(pat) = v.get("pattern").and_then(|x| x.as_str()) {
                        for c in grpre.captures_iter(pat) { out.push((c[1].to_string(), rel.clone(), fam)); }
                    }
                    continue;
                }
                // Les fixtures de test ne sont pas de la collecte LIVRÉE : on tronque au `#[cfg(test)]` de
                // COLONNE 0 (le `mod tests` final) — pas au premier, qui peut être un attribut INDENTÉ sur
                // une fonction test-only au milieu du fichier (mesuré : `fim/mod.rs:667`).
                if ext == "rs" {
                    if let Some(i) = body.find("\n#[cfg(test)]") { body.truncate(i); }
                }

                let mut has_fields_obj = false;
                for m in marker.find_iter(&body) {
                    has_fields_obj = true;
                    // Bloc à accolades ÉQUILIBRÉES ; on ne retient que les clés de PROFONDEUR 1, découpées
                    // sur les séparateurs d'élément (`,` JSON/jq/py, `;` et saut de ligne PowerShell).
                    let (bytes, start) = (body.as_bytes(), m.end());
                    let (mut i, mut depth, mut seg) = (start, 1usize, start);
                    // `closed` : on ne coupe la QUEUE du bloc que si l'accolade s'est refermée dans le
                    // budget — sinon `i` pourrait tomber au milieu d'un caractère UTF-8 (les collecteurs
                    // sont commentés en français). Les autres bornes sont des délimiteurs ASCII.
                    let mut closed = false;
                    while i < bytes.len() && i - start < 8000 {
                        match bytes[i] {
                            b'{' => depth += 1,
                            b'}' => { depth -= 1; if depth == 0 { closed = true; break; } }
                            b',' | b';' | b'\n' if depth == 1 => {
                                if let Some(c) = keyre.captures(&body[seg..i]) { out.push((c[1].to_string(), rel.clone(), fam)); }
                                seg = i + 1;
                            }
                            _ => {}
                        }
                        i += 1;
                    }
                    if closed {
                        if let Some(c) = keyre.captures(&body[seg..i]) { out.push((c[1].to_string(), rel.clone(), fam)); }
                    }
                }
                if ext == "rs" { for c in insrs.captures_iter(&body) { out.push((c[1].to_string(), rel.clone(), fam)); } }
                if ext == "py" { for c in inspy.captures_iter(&body) { out.push((c[1].to_string(), rel.clone(), fam)); } }
                if afdef.is_match(&body) { for c in afuse.captures_iter(&body) { out.push((c[1].to_string(), rel.clone(), fam)); } }
                if ext == "sh" && has_fields_obj {
                    for c in frag.captures_iter(&body) { out.push((c[1].to_string(), rel.clone(), fam)); }
                }
            }
        }
        out
    }

    /// FAMILLES de collecteurs livrés balayées par l'extracteur, avec le PLANCHER d'extractions de chacune.
    /// Le garde-fou anti-rot global (`derived.len() > 50`) était trop lâche : la perte d'une famille ENTIÈRE
    /// passait inaperçue (mesuré — l'extraction ne mordait en fait que sur `collectors/*.sh`, et 45 champs
    /// réellement émis étaient déclarés inertes). Un plancher PAR FAMILLE rend cette perte rouge.
    /// Planchers ≈ 75-80 % du MESURÉ à ce commit (sh 412 · py 14 · ps1 27 · rs 11 · fim 18 · parsers 21) :
    /// assez lâches pour qu'une retouche de collecteur ne rougisse pas, assez serrés pour qu'en perdre une
    /// FORME de production rougisse (mesuré : retirer P5 fait tomber `collectors/*.sh` de 412 à 211).
    const COLLECTED_SCAN_SURFACE: &[(&str, &str, &str, usize)] = &[
        ("collectors", "sh", "collectors/*.sh", 330),
        ("collectors", "py", "collectors/*.py", 11),
        ("collectors/windows", "ps1", "collectors/windows/*.ps1", 20),
        ("agent/src/source", "rs", "agent/src/source/*.rs", 8),
        ("agent/src/source/fim", "rs", "agent/src/source/fim/*.rs", 14),
        ("config.d/parsers", "json", "config.d/parsers/*.json", 16),
    ];

    /// GARDE DE L'INVENTAIRE DE COLLECTE (`collected::COLLECTED_EXTENDED_FIELDS`) — il doit rester COLLÉ à ce
    /// que les collecteurs/parseurs/agent LIVRÉS émettent, DANS LES DEUX SENS, avec LE MÊME extracteur :
    ///   (A) AUCUNE ENTRÉE FANTÔME — le champ doit être EXTRAIT du fichier cité, donc y apparaître en
    ///       POSITION DE PRODUCTEUR. La version précédente se contentait d'une SOUS-CHAÎNE : `web.sh`
    ///       contient `sval("RequestPath")` (une clé Traefik qu'il LIT) et n'émet que `fields.path`, si bien
    ///       qu'`("RequestPath","web.sh")` éteignait l'avertissement en restant VERTE — faux vert
    ///       re-fabricable en une ligne. Le test `collected_citation_rejects_a_read_only_key` fige ce cas.
    ///   (B) AUCUNE DÉRIVE SILENCIEUSE — tout champ extrait doit figurer dans l'inventaire. Un collecteur
    ///       qui se met à émettre un champ fait rougir ce test tant qu'il n'est pas inventorié.
    ///   (C) ANTI-ROT PAR FAMILLE — chaque famille de collecteurs doit fournir au moins son plancher
    ///       d'extractions, sinon en perdre une entière (chemin déplacé, syntaxe changée) serait SILENCIEUX.
    /// C'est le PROTOCOLE DE MISE À JOUR : on ne « pense pas à » mettre l'inventaire à jour, le test l'exige.
    /// Ce que l'extracteur ne voit pas (EventData Windows recopié verbatim, sources déclaratives
    /// `[[source]]`, clé non-string ou première clé d'un fragment P5) est ÉNUMÉRÉ dans `collected.rs` et
    /// produit un SUR-avertissement (donnée collectée dite inerte), jamais un silence.
    #[test]
    fn collected_inventory_is_backed_by_shipped_collectors() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let derived = collected_extract_shipped(&root);

        // ---------- (C) anti-rot : chaque FAMILLE mord encore ----------
        for (_, _, fam, floor) in COLLECTED_SCAN_SURFACE {
            let n = derived.iter().filter(|(_, _, f)| f == fam).count();
            assert!(n >= *floor,
                "famille `{fam}` : l'extraction n'a ramené que {n} champs (plancher {floor}). Cette famille \
                 de collecteurs a cessé d'être vue (répertoire déplacé ? syntaxe d'émission changée ?) — et \
                 ce qu'elle émet serait désormais déclaré INERTE en silence. Corriger l'extracteur, puis \
                 re-mesurer et remettre à jour le plancher.");
        }

        // ---------- (A) aucune entrée fantôme : citation = POSITION DE PRODUCTEUR ----------
        for (field, cite) in crate::collected::COLLECTED_EXTENDED_FIELDS {
            let files: std::collections::BTreeSet<&String> = derived.iter()
                .map(|(_, rel, _)| rel)
                .filter(|rel| rel.as_str() == *cite || rel.ends_with(&format!("/{cite}")))
                .collect();
            assert!(!files.is_empty(),
                "champ inventorié `{field}` : fichier livré cité `{cite}` INTROUVABLE dans la surface \
                 d'extraction. Si le collecteur a été retiré, RETIRER l'entrée d'inventaire — sinon l'oracle \
                 déclare vivante une donnée que plus rien n'émet (avertissement d'inertie éteint à tort).");
            assert!(files.len() == 1,
                "champ inventorié `{field}` : la citation `{cite}` désigne PLUSIEURS fichiers livrés \
                 ({files:?}). Allonger la citation jusqu'à ce qu'elle soit unique (ex. `fim/mod.rs`).");
            let file = files.into_iter().next().unwrap();
            let produced = derived.iter().any(|(f, rel, _)| f == field && rel == file);
            assert!(produced,
                "champ inventorié `{field}` : son fichier cité `{cite}` ne l'ÉMET PAS — l'extracteur ne l'y \
                 trouve dans AUCUNE position de producteur (objet `fields` littéral, insertion par clé, \
                 `af(…)` awk, fragment JSON, overlay de parseur). Le nom peut y figurer autrement (une clé \
                 LUE dans un log tiers, un commentaire) : ce n'est pas de la collecte. Une entrée que rien \
                 n'émet éteindrait l'avertissement d'inertie sans qu'aucune donnée ne soit collectée.");
        }

        // ---------- (B) aucune dérive silencieuse : extraction ⊆ inventaire ----------
        let mut missing: Vec<String> = derived.iter()
            .filter(|(f, _, _)| !CIM_CORE_FIELDS.contains(&f.as_str()) && !crate::collected::plume_collects_field(f))
            .map(|(f, src, _)| format!("{f} (émis par {src})")).collect();
        missing.sort(); missing.dedup();
        assert!(missing.is_empty(),
            "champ(s) émis par un collecteur/parseur LIVRÉ mais ABSENT(S) de l'inventaire de collecte : {missing:?}. \
             Ajouter chaque champ à `collected::COLLECTED_EXTENDED_FIELDS` avec le fichier qui l'émet — sinon \
             l'oracle signale INERTES des règles qui porteraient sur une donnée réellement collectée.");
    }

    /// NON-RÉGRESSION DU FAUX VERT PAR SOUS-CHAÎNE (défaut mesuré par la revue adverse). `web.sh` CONTIENT
    /// le nom `RequestPath` — c'est une clé du log Traefik qu'il LIT (`sval("RequestPath")`) — mais il
    /// n'émet que `fields.path`. Sous l'ancienne citation (`body.contains("\"RequestPath\"")`), l'entrée
    /// `("RequestPath","web.sh")` passait VERTE et éteignait l'avertissement d'inertie : faux vert en une
    /// ligne. Ce test fige les DEUX moitiés du raisonnement — la prémisse (le nom est bien là) et la
    /// conclusion (il n'est PAS en position de producteur) — pour qu'un retour à la sous-chaîne rougisse.
    #[test]
    fn collected_citation_rejects_a_read_only_key() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let body = std::fs::read_to_string(root.join("collectors/web.sh")).unwrap();
        assert!(body.contains("\"RequestPath\""),
            "prémisse : `web.sh` contient bien le littéral \"RequestPath\" (clé Traefik LUE)");
        let derived = collected_extract_shipped(&root);
        let web: Vec<&String> = derived.iter()
            .filter(|(_, rel, _)| rel == "collectors/web.sh").map(|(f, _, _)| f).collect();
        assert!(!web.contains(&&"RequestPath".to_string()),
            "`RequestPath` est LU par web.sh, pas ÉMIS : l'extracteur ne doit pas l'en dériver, sinon \
             l'entrée d'inventaire `(\"RequestPath\",\"web.sh\")` redeviendrait acceptable et rendrait le \
             faux vert re-fabricable en une ligne.");
        assert!(web.contains(&&"path".to_string()),
            "contrôle en sens inverse : ce que web.sh ÉMET réellement (`fields.path`) EST dérivé — sans quoi \
             ce test passerait pour une raison vide (extracteur muet sur web.sh).");
    }

    /// #4 — un import Sigma NE peut PAS écraser une détection native (managed=0) ni un overlay git
    /// (managed=1) sur collision de nom ; seul un ad-hoc (managed=2) est mis à jour.
    #[test]
    fn sigma_import_protects_native_and_overlay_rules() {
        assert_eq!(sigma_import_disposition(None), SigmaDisp::Insert);
        assert_eq!(sigma_import_disposition(Some(0)), SigmaDisp::SkipManaged(0), "détection native protégée");
        assert_eq!(sigma_import_disposition(Some(1)), SigmaDisp::SkipManaged(1), "overlay git protégé");
        assert_eq!(sigma_import_disposition(Some(2)), SigmaDisp::Update, "ad-hoc mis à jour au ré-import");
    }

    /// #10 — ENRICH-only : un dparser NE remplace PAS une category/severity DÉJÀ déclarée par le
    /// collecteur (parité avec `fields`) ; il ne comble QUE le vide (category vide / severity défaut 0).
    #[test]
    fn dparser_does_not_override_declared_collector_category() {
        let conn = test_db();
        let dpath = ":memory:dparser-noover";
        conn.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('wild','*',?1,1,0,1,0)",
            params![r#"{"name":"wild","source":"*","map":{"category":"web","severity":1}}"#]).unwrap();
        dparsers_reload(&conn, dpath);
        // event AVEC category/severity déclarées -> NON écrasées par le parseur wildcard.
        ingest_events_batch(&conn, dpath, &[json!({"ts":1,"source":"firewall","category":"malware","severity":4,"message":"x","dedup":"d1"})], 1, None, None).unwrap();
        let (c, s): (String, i64) = conn.query_row("SELECT category,severity FROM event WHERE dedup='d1'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((c.as_str(), s), ("malware", 4), "category/severity déclarées NON écrasées");
        // event SANS category -> le dparser enrichit (comble le vide).
        ingest_events_batch(&conn, dpath, &[json!({"ts":2,"source":"firewall","category":"","severity":0,"message":"y","dedup":"d2"})], 2, None, None).unwrap();
        let (c2, s2): (String, i64) = conn.query_row("SELECT category,severity FROM event WHERE dedup='d2'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((c2.as_str(), s2), ("web", 1), "category vide / severity défaut -> enrichies");
    }

    // ============================================================================================
    // SLICE #7 — IMPORT EN MASSE (BULK) : bundle Sigma -> règles managées + delta de couverture ATT&CK.
    // ============================================================================================

    /// SÉCURITÉ — `/api/sigma/import-bulk` est ADMIN-ONLY (default-deny : mutation hors allowlist).
    #[test]
    fn sigma_import_bulk_route_is_admin_only() {
        assert!(rbac_gate("admin", "/api/sigma/import-bulk", true).is_ok(), "admin importe en masse");
        assert!(rbac_gate("editor", "/api/sigma/import-bulk", true).is_err(), "editor n'importe PAS (default-deny)");
        assert!(rbac_gate("viewer", "/api/sigma/import-bulk", true).is_err(), "viewer n'importe PAS");
        assert!(rbac_gate("agent", "/api/sigma/import-bulk", true).is_err(), "agent n'importe PAS");
    }

    /// BUNDLE — le décodeur accepte les 3 formes : tableau JSON `{rules:[…]}`, YAML MULTI-DOCS `{content}`,
    /// base64 `{content_b64}`. Réutilise sigma_yaml_to_docs (front-end existant).
    #[test]
    fn sigma_bulk_decode_accepts_yaml_json_and_b64() {
        // (a) tableau JSON de docs
        let arr = json!({ "rules": [ {
            "title": "a", "logsource": {"category":"firewall"},
            "detection": {"selection": {"action":"deny"}, "condition":"selection"}
        } ] });
        assert_eq!(sigma_bulk_docs_from_body(&arr).unwrap().len(), 1, "JSON array -> 1 doc");
        // (b) YAML MULTI-DOCUMENTS (`---`) dans content
        let yaml = "title: a\nlogsource:\n  category: firewall\ndetection:\n  selection:\n    action: deny\n  condition: selection\n---\ntitle: b\nlogsource:\n  category: dns\ndetection:\n  selection:\n    query|contains: x\n  condition: selection\n";
        assert_eq!(sigma_bulk_docs_from_body(&json!({ "content": yaml })).unwrap().len(), 2, "YAML multi-docs -> 2");
        // (c) base64 du MÊME YAML
        let b64 = base64::engine::general_purpose::STANDARD.encode(yaml.as_bytes());
        assert_eq!(sigma_bulk_docs_from_body(&json!({ "content_b64": b64 })).unwrap().len(), 2, "content_b64 décodé -> 2");
    }

    /// SKIP-WITH-REASON — un doc à condition NON SUPPORTÉE (OU) est écarté AVEC raison (jamais une règle
    /// silencieusement fausse) et classé is_error ; le doc valide traduit normalement.
    #[test]
    fn sigma_bulk_skips_unsupported_with_reason() {
        let good = json!({ "title":"ok", "logsource":{"category":"firewall"},
            "detection":{"selection":{"action":"deny"}, "condition":"selection"} });
        let bad = json!({ "title":"nope", "logsource":{"category":"firewall"},
            "detection":{"sel_a":{"action":"deny"}, "sel_b":{"dst_port":22}, "condition":"sel_a or sel_b"} });
        let (t, skipped) = sigma_bulk_translate(&[good, bad]);
        assert_eq!(t.len(), 1, "seul le doc valide traduit");
        assert_eq!(skipped.len(), 1, "un skip");
        assert_eq!(skipped[0].reference, "nope", "réf = titre à défaut d'id");
        assert!(skipped[0].is_error, "classé erreur de traduction");
        assert!(skipped[0].reason.contains("OU") || skipped[0].reason.contains("'or'"), "raison mentionne le OU non supporté : {}", skipped[0].reason);
    }

    /// DELTA DE COUVERTURE — réutilise l'agrégation coverage_attack (mitre_parents). Techniques nouvellement
    /// couvrables listées ; sous-technique repliée sur la parente ; déjà couverte -> delta nul ; tag vide -> 0.
    #[test]
    fn sigma_bulk_coverage_delta_computed() {
        let (before, after, newly) = sigma_bulk_coverage_delta(&[], &["T1059".into(), "T1110.001".into()]);
        assert_eq!(before, 0, "aucune couverture avant");
        assert_eq!(after, 2, "2 techniques parentes nouvellement couvrables");
        assert!(newly.contains(&"T1059".to_string()) && newly.contains(&"T1110".to_string()), "sous-technique repliée sur parent : {newly:?}");
        // déjà couverte -> pas de nouveauté.
        let (b2, a2, newly2) = sigma_bulk_coverage_delta(&["T1059".into()], &["T1059".into()]);
        assert_eq!((b2, a2), (1, 1), "couverture inchangée");
        assert!(newly2.is_empty(), "technique déjà couverte : delta nul");
        // tag vide (règle sans MITRE) -> aucune couverture ajoutée.
        let (b3, a3, n3) = sigma_bulk_coverage_delta(&[], &["".into()]);
        assert_eq!((b3, a3), (0, 0));
        assert!(n3.is_empty());
    }

    /// BORNÉ — la taille (octets) est vérifiée AVANT parse (OOM-safe) : un bundle sur-cap est rejeté ; sous le
    /// cap il passe. Caps doc/octets par défaut strictement positifs. (Cap explicite -> pas de mutation d'env.)
    #[test]
    fn sigma_bulk_bounded_caps_enforced() {
        let over = json!({ "content": "title: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }); // > 16 octets
        let e = sigma_bulk_docs_from_body_capped(&over, 16).unwrap_err();
        assert!(e.contains("volumineux"), "bundle > cap octets rejeté AVANT parse : {e}");
        // base64 sur-cap rejeté sur la taille ENCODÉE.
        let b64_over = json!({ "content_b64": base64::engine::general_purpose::STANDARD.encode(vec![b'x'; 200]) });
        assert!(sigma_bulk_docs_from_body_capped(&b64_over, 16).is_err(), "base64 sur-cap rejeté");
        // sous le cap : OK.
        let ok = json!({ "content": "title: a\nlogsource:\n  category: firewall\ndetection:\n  selection:\n    action: deny\n  condition: selection\n" });
        assert!(sigma_bulk_docs_from_body_capped(&ok, 16 * 1024 * 1024).is_ok(), "sous le cap : parse OK");
        assert!(sigma_bulk_max_docs() > 0 && sigma_bulk_max_bytes() > 0, "caps par défaut positifs");
    }

    /// CREATED-DISABLED + DEDUP + MODE-0 — contre une vraie base : dédup intra-bundle par titre (dernier gagne),
    /// règles créées DÉSACTIVÉES, ré-import idempotent (UPDATE, aucun doublon) préservant le `enabled` de l'admin.
    #[test]
    fn sigma_bulk_apply_disabled_dedup_and_idempotent() {
        let conn = test_db();
        // 'Bulk A' apparaît 2× (le dernier — dst_port — gagne) + 'Bulk B'.
        let yaml = "\
title: Bulk A\nlogsource:\n  category: firewall\ndetection:\n  selection:\n    action: deny\n  condition: selection\ntags:\n  - attack.t1046\n\
---\ntitle: Bulk A\nlogsource:\n  category: firewall\ndetection:\n  selection:\n    dst_port: 4444\n  condition: selection\ntags:\n  - attack.t1046\n\
---\ntitle: Bulk B\nlogsource:\n  category: dns\ndetection:\n  selection:\n    query|contains: evil\n  condition: selection\ntags:\n  - attack.t1071\n";
        let docs = sigma_yaml_to_docs(yaml).unwrap();
        let (translations, terr) = sigma_bulk_translate(&docs);
        assert!(terr.is_empty(), "traduction sans erreur : {terr:?}");
        assert_eq!(translations.len(), 2, "dedup intra-bundle par titre (Bulk A ×2 -> 1)");
        let a = translations.iter().find(|t| t.name == "Bulk A").unwrap();
        assert!(a.query.contains("dport"), "dernier doc du titre dupliqué gagne : {}", a.query);
        // apply : créées DÉSACTIVÉES.
        let (plan, mskip) = sigma_bulk_classify(&conn, &translations);
        assert!(mskip.is_empty(), "aucune collision managed");
        assert_eq!(plan.len(), 2);
        sigma_bulk_apply(&conn, &plan, false).unwrap();
        let (n, dis): (i64, i64) = conn.query_row("SELECT COUNT(*), COALESCE(SUM(enabled=0),0) FROM rule WHERE managed=2", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(n, 2, "2 règles importées");
        assert_eq!(dis, 2, "toutes DÉSACTIVÉES à l'import (created-disabled)");
        // ré-import : UPDATE, aucun doublon.
        let (plan2, _) = sigma_bulk_classify(&conn, &translations);
        assert!(plan2.iter().all(|(_, target)| target.is_some()), "ré-import -> UPDATE (managed=2), aucun INSERT");
        sigma_bulk_apply(&conn, &plan2, false).unwrap();
        let n2: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE managed=2", [], |r| r.get(0)).unwrap();
        assert_eq!(n2, 2, "ré-import ne duplique pas (idempotent)");
        // enabled PRÉSERVÉ au ré-import : l'admin active Bulk B, un ré-import ne le désactive pas.
        conn.execute("UPDATE rule SET enabled=1 WHERE name='Bulk B'", []).unwrap();
        let (plan3, _) = sigma_bulk_classify(&conn, &translations);
        sigma_bulk_apply(&conn, &plan3, false).unwrap();
        let en: i64 = conn.query_row("SELECT enabled FROM rule WHERE name='Bulk B'", [], |r| r.get(0)).unwrap();
        assert_eq!(en, 1, "UPDATE ne désactive PAS une règle que l'admin a activée");
    }

    /// DÉDUP PAR `sigma_id` (#2) — un ré-import d'un ruleset dont le TITRE a DÉRIVÉ mais dont l'`id` (UUID) est
    /// STABLE dédup toujours par l'UUID (UPDATE, pas de doublon ; le titre est rafraîchi). Un doc SANS id retombe
    /// sur la dédup par titre (comportement historique). Migration ADDITIVE idempotente (colonne sigma_id, NULL
    /// pour l'existant). Preuve intra-bundle (deux docs même id -> une traduction) + contre-base (UPDATE ciblé).
    #[test]
    fn sigma_dedup_by_sigma_id_survives_title_drift() {
        let conn = test_db();
        // MIGRATION ADDITIVE : la colonne sigma_id existe (v81) et est NULL pour toute règle non-Sigma.
        let col: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('rule') WHERE name='sigma_id'", [], |r| r.get(0)).unwrap();
        assert_eq!(col, 1, "colonne rule.sigma_id présente (migration v81)");
        // IDEMPOTENCE MIGRATION : re-jouer migrate() ne casse rien (garde de version) et la colonne reste unique.
        let _ = migrate(&conn);
        let col2: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('rule') WHERE name='sigma_id'", [], |r| r.get(0)).unwrap();
        assert_eq!(col2, 1, "migration idempotente : sigma_id toujours unique après re-jeu");

        // (1) Import initial : règle AVEC id UUID + titre 'Ancien Titre'.
        let v1 = json!({ "id": "11111111-2222-3333-4444-555555555555", "title": "Ancien Titre",
            "logsource": {"category":"firewall"}, "detection": {"selection":{"action":"deny"}, "condition":"selection"},
            "tags": ["attack.t1046"] });
        let (tr1, e1) = sigma_bulk_translate(std::slice::from_ref(&v1));
        assert!(e1.is_empty() && tr1.len() == 1);
        assert_eq!(tr1[0].sigma_id.as_deref(), Some("11111111-2222-3333-4444-555555555555"), "sigma_id capturé depuis le doc");
        let (p1, _) = sigma_bulk_classify(&conn, &tr1);
        assert!(p1.iter().all(|(_, t)| t.is_none()), "1er import -> INSERT");
        sigma_bulk_apply(&conn, &p1, false).unwrap();

        // (2) RÉ-IMPORT : MÊME id, TITRE DÉRIVÉ ('Nouveau Titre'), logique modifiée.
        let v2 = json!({ "id": "11111111-2222-3333-4444-555555555555", "title": "Nouveau Titre",
            "logsource": {"category":"firewall"}, "detection": {"selection":{"action":"drop"}, "condition":"selection"},
            "tags": ["attack.t1046"] });
        let (tr2, _) = sigma_bulk_translate(std::slice::from_ref(&v2));
        let (p2, _) = sigma_bulk_classify(&conn, &tr2);
        assert!(p2.iter().all(|(_, t)| t.is_some()), "dérive de titre mais MÊME sigma_id -> UPDATE (pas d'INSERT)");
        sigma_bulk_apply(&conn, &p2, false).unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE managed=2", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "ré-import titre-dérivé dédup par UUID : AUCUN doublon");
        let (name, q): (String, String) = conn.query_row(
            "SELECT name, query FROM rule WHERE sigma_id='11111111-2222-3333-4444-555555555555'",
            [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(name, "Nouveau Titre", "le titre dérivé est rafraîchi sur la règle dédupliquée");
        assert!(q.contains("drop"), "la logique ré-importée a bien été mise à jour : {q}");

        // (3) INTRA-BUNDLE : deux docs de MÊME id (titres différents) -> UNE traduction (dernier gagne).
        let dup = vec![
            json!({ "id":"aaaa", "title":"T-a", "logsource":{"category":"dns"}, "detection":{"selection":{"query|contains":"x"}, "condition":"selection"} }),
            json!({ "id":"aaaa", "title":"T-b", "logsource":{"category":"dns"}, "detection":{"selection":{"query|contains":"y"}, "condition":"selection"} }),
        ];
        let (trd, _) = sigma_bulk_translate(&dup);
        assert_eq!(trd.len(), 1, "dédup intra-bundle par sigma_id (2 docs même id -> 1)");
        assert_eq!(trd[0].name, "T-b", "le dernier doc du même id gagne");

        // (4) REPLI TITRE : un doc SANS id dédup par titre (comportement historique inchangé).
        let noid = json!({ "title": "Sans Id", "logsource": {"category":"firewall"},
            "detection": {"selection":{"action":"deny"}, "condition":"selection"} });
        let (trn, _) = sigma_bulk_translate(std::slice::from_ref(&noid));
        assert!(trn[0].sigma_id.is_none(), "aucun id -> sigma_id None (repli titre)");
        let (pn1, _) = sigma_bulk_classify(&conn, &trn);
        sigma_bulk_apply(&conn, &pn1, false).unwrap();
        let (pn2, _) = sigma_bulk_classify(&conn, &trn); // ré-import du MÊME doc sans id
        assert!(pn2.iter().all(|(_, t)| t.is_some()), "sans id : dédup par titre -> UPDATE au ré-import");
        sigma_bulk_apply(&conn, &pn2, false).unwrap();
        let nn: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE name='Sans Id'", [], |r| r.get(0)).unwrap();
        assert_eq!(nn, 1, "repli titre : pas de doublon pour un doc sans id");
    }

    /// MODE-0 — un bundle VIDE (séparateurs `---` nuls) ne crée AUCUNE règle (no-op idempotent).
    #[test]
    fn sigma_bulk_empty_bundle_is_noop() {
        let conn = test_db();
        let docs = sigma_yaml_to_docs("---\n---\n").unwrap();
        assert!(docs.is_empty(), "séparateurs vides -> aucun doc");
        let (translations, _) = sigma_bulk_translate(&docs);
        let (plan, _) = sigma_bulk_classify(&conn, &translations);
        assert!(plan.is_empty(), "plan vide");
        sigma_bulk_apply(&conn, &plan, false).unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE managed=2", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "bundle vide : AUCUNE règle créée (mode-0 no-op)");
    }

    /// PROTECTION — un import en masse n'écrase NI une détection native (managed=0) NI un overlay git (managed=1) ;
    /// ces docs sont écartés (skip de protection, is_error=false), seul l'ad-hoc (managed=2) est mis à jour.
    #[test]
    fn sigma_bulk_classify_protects_native_and_overlay() {
        let conn = test_db();
        conn.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('Native','1','search x | stats count',1,0)", []).unwrap();
        conn.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('Overlay','1','search x | stats count',1,1)", []).unwrap();
        let (translations, _) = sigma_bulk_translate(&[
            json!({ "title":"Native", "logsource":{"category":"firewall"}, "detection":{"selection":{"action":"deny"}, "condition":"selection"} }),
            json!({ "title":"Overlay", "logsource":{"category":"firewall"}, "detection":{"selection":{"action":"deny"}, "condition":"selection"} }),
            json!({ "title":"Fresh", "logsource":{"category":"firewall"}, "detection":{"selection":{"action":"deny"}, "condition":"selection"} }),
        ]);
        let (plan, skipped) = sigma_bulk_classify(&conn, &translations);
        assert_eq!(plan.len(), 1, "seul 'Fresh' entre dans le plan (insert)");
        assert_eq!(plan[0].0.name, "Fresh");
        assert!(plan[0].1.is_none(), "insert (pas update)");
        assert_eq!(skipped.len(), 2, "Native + Overlay protégés");
        assert!(skipped.iter().all(|s| !s.is_error), "skips de PROTECTION, pas des erreurs");
        assert!(skipped.iter().any(|s| s.reference == "Native" && s.reason.contains("native")));
        assert!(skipped.iter().any(|s| s.reference == "Overlay" && s.reason.contains("overlay")));
    }

    // --- DURCISSEMENT 3a : SQL brut réservé admin -----------------------------------------------------
    #[test]
    fn raw_sql_rule_gate_admin_only() {
        // SOQL (langage borné, read-only) -> tout rôle OK.
        assert!(raw_sql_allowed(true, "editor"));
        assert!(raw_sql_allowed(true, "viewer"));
        assert!(raw_sql_allowed(true, "admin"));
        // SQL brut (lecture intégrale) -> admin SEUL ; editor/viewer refusés.
        assert!(!raw_sql_allowed(false, "editor"));
        assert!(!raw_sql_allowed(false, "viewer"));
        assert!(raw_sql_allowed(false, "admin"));
    }

    // --- DURCISSEMENT 3b : l'éval (run_query) est en LECTURE SEULE ------------------------------------
    #[test]
    fn eval_path_is_read_only() {
        // DB fichier temporaire (run_query ouvre une connexion du pool READ_ONLY sur un chemin disque).
        let mut path = std::env::temp_dir();
        path.push(format!("plume-eval-ro-{}-{}.db", std::process::id(), now()));
        let p = path.to_string_lossy().to_string();
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
        }
        // (a) une requête LÉGITIME de règle fonctionne (lecture).
        let ok = run_query(&p, "SELECT COUNT(*) AS n FROM event");
        assert!(ok.is_ok(), "une lecture légitime de règle doit passer : {ok:?}");
        // (b) une écriture est REFUSÉE par le chemin d'éval (query_only + READ_ONLY + garde stmt.readonly()).
        let wr = run_query(&p, "UPDATE meta SET value='x' WHERE key='schema_version'");
        assert!(wr.is_err(), "une écriture via le chemin d'éval doit être bloquée");
        let ins = run_query(&p, "INSERT INTO meta(key,value) VALUES('hack','1')");
        assert!(ins.is_err(), "un INSERT via le chemin d'éval doit être bloqué");
        // (c) DURCISSEMENT 3 (#1c) — l'authorizer du read-pool REFUSE la lecture des colonnes de secrets
        //     (user.hash, token.token_hash) MÊME en SQL brut : la préparation SQLite échoue « not authorized »
        //     -> Err (aucune ligne servie). Couvre projection directe, mélange, WHERE et sous-requête.
        assert!(run_query(&p, "SELECT hash FROM user").is_err(), "user.hash (projection) doit être refusé par l'authorizer");
        assert!(run_query(&p, "SELECT name,hash FROM user").is_err(), "user.hash (mélangé à name) doit être refusé");
        assert!(run_query(&p, "SELECT name FROM user WHERE hash='x'").is_err(), "user.hash en WHERE doit être refusé");
        assert!(run_query(&p, "SELECT * FROM (SELECT hash FROM user)").is_err(), "user.hash en sous-requête doit être refusé");
        assert!(run_query(&p, "SELECT token_hash FROM token").is_err(), "token.token_hash doit être refusé par l'authorizer");
        assert!(run_query(&p, "SELECT name FROM token WHERE token_hash='x'").is_err(), "token.token_hash en WHERE doit être refusé");
        // #3a — connector.secret (client_secret externe) DÉNIÉ par l'authorizer, même en SQL brut admin :
        // projection directe, mélange à une colonne non-secrète, et WHERE (couvre aussi SELECT * / sous-requête).
        assert!(run_query(&p, "SELECT secret FROM connector").is_err(), "connector.secret (projection) doit être refusé par l'authorizer");
        assert!(run_query(&p, "SELECT name,secret FROM connector").is_err(), "connector.secret (mélangé à name) doit être refusé");
        assert!(run_query(&p, "SELECT id FROM connector WHERE secret='x'").is_err(), "connector.secret en WHERE doit être refusé");
        // export-leak — notifier.config (token ntfy / user:pass SMTP en CLAIR) DÉNIÉ par l'authorizer, même en SQL
        // brut admin (miroir de notifiers_list qui ne projette jamais `config`) : projection, mélange, et WHERE.
        assert!(run_query(&p, "SELECT config FROM notifier").is_err(), "notifier.config (projection) doit être refusé par l'authorizer");
        assert!(run_query(&p, "SELECT id,name,config FROM notifier").is_err(), "notifier.config (mélangé à name) doit être refusé");
        assert!(run_query(&p, "SELECT id FROM notifier WHERE config LIKE '%pass%'").is_err(), "notifier.config en WHERE doit être refusé");
        // #44 IdP natif — idp_provider.secret (client_secret OIDC / bind pw LDAP) DÉNIÉ par l'authorizer, même
        // en SQL brut admin : projection, mélange, WHERE, sous-requête (miroir de connector.secret).
        assert!(run_query(&p, "SELECT secret FROM idp_provider").is_err(), "idp_provider.secret (projection) doit être refusé par l'authorizer");
        assert!(run_query(&p, "SELECT name,secret FROM idp_provider").is_err(), "idp_provider.secret (mélangé à name) doit être refusé");
        assert!(run_query(&p, "SELECT id FROM idp_provider WHERE secret='x'").is_err(), "idp_provider.secret en WHERE doit être refusé");
        assert!(run_query(&p, "SELECT * FROM (SELECT secret FROM idp_provider)").is_err(), "idp_provider.secret en sous-requête doit être refusé");
        // #44 MFA — user_mfa.secret (graine TOTP en clair -> clonage du 2e facteur) ET user_mfa.recovery (hachés)
        // DÉNIÉS par l'authorizer, même admin : projection, mélange, WHERE. Défaite du clonage MFA par un rogue admin.
        assert!(run_query(&p, "SELECT secret FROM user_mfa").is_err(), "user_mfa.secret (projection) doit être refusé par l'authorizer");
        assert!(run_query(&p, "SELECT user,secret FROM user_mfa").is_err(), "user_mfa.secret (mélangé à user) doit être refusé");
        assert!(run_query(&p, "SELECT secret FROM user_mfa WHERE user='alice'").is_err(), "user_mfa.secret ciblé (WHERE user) doit être refusé");
        assert!(run_query(&p, "SELECT recovery FROM user_mfa").is_err(), "user_mfa.recovery (codes de secours) doit être refusé par l'authorizer");
        assert!(run_query(&p, "SELECT user FROM user_mfa WHERE recovery LIKE '%a%'").is_err(), "user_mfa.recovery en WHERE doit être refusé");
        // #16 IA — ai_provider.secret (clé/token d'inférence, ex. `literal:sk-…`)
        // DÉNIÉ par l'authorizer même admin SQL brut, comme les sœurs connector/idp_provider/user_mfa. La table
        // existe inconditionnellement (migrate v109) -> le déni s'applique au build par défaut. Projection/mélange/WHERE/sous-req.
        assert!(run_query(&p, "SELECT secret FROM ai_provider").is_err(), "ai_provider.secret (projection) doit être refusé par l'authorizer");
        assert!(run_query(&p, "SELECT id,name,secret FROM ai_provider").is_err(), "ai_provider.secret (mélangé à name) doit être refusé");
        assert!(run_query(&p, "SELECT id FROM ai_provider WHERE secret='x'").is_err(), "ai_provider.secret en WHERE doit être refusé");
        assert!(run_query(&p, "SELECT * FROM (SELECT secret FROM ai_provider)").is_err(), "ai_provider.secret en sous-requête doit être refusé");
        assert!(run_query(&p, "SELECT id,name,vendor,endpoint,enabled FROM ai_provider").is_ok(), "les colonnes non secrètes de ai_provider doivent rester lisibles");
        // …SANS sur-restreindre : les colonnes NON secrètes de idp_provider/user_mfa restent lisibles.
        assert!(run_query(&p, "SELECT id,name,kind,enabled,created FROM idp_provider").is_ok(), "les colonnes non secrètes de idp_provider doivent rester lisibles");
        assert!(run_query(&p, "SELECT user,enabled,last_step FROM user_mfa").is_ok(), "les colonnes non secrètes de user_mfa doivent rester lisibles");
        // …SANS sur-restreindre : les colonnes NON secrètes de user/token/connector/notifier restent parfaitement lisibles.
        assert!(run_query(&p, "SELECT id,name,kind,enabled,url,min_severity FROM notifier").is_ok(), "les colonnes non secrètes de notifier doivent rester lisibles");
        assert!(run_query(&p, "SELECT id,name,role,created FROM user").is_ok(), "les colonnes non secrètes de user doivent rester lisibles");
        assert!(run_query(&p, "SELECT id,name,created,last_used FROM token").is_ok(), "les colonnes non secrètes de token doivent rester lisibles");
        assert!(run_query(&p, "SELECT id,type,name,enabled,env_id FROM connector").is_ok(), "les colonnes non secrètes de connector doivent rester lisibles");
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(format!("{p}-wal"));
        let _ = std::fs::remove_file(format!("{p}-shm"));
    }

    #[test]
    fn migration_adds_mitre_columns_and_bumps_version() {
        let conn = test_db();
        assert!(col_exists(&conn, "rule", "mitre"), "rule.mitre manquant après migrate");
        assert!(col_exists(&conn, "alert", "mitre"), "alert.mitre manquant après migrate");
        let v: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "111", "schema_version à la tête (… v94 knowledge + v95 data models + v96 #59 gouvernance legal_hold/ledger_sink)");
    }

    #[test]
    fn migration_is_idempotent() {
        // re-jouer migrate() ne doit PAS échouer (ALTER déjà appliqué = duplicate column ignoré) ni régresser.
        let conn = test_db();
        let _ = migrate(&conn);
        let _ = migrate(&conn);
        let v: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "111");
        // FIX (test-confidence #11) : re-jouer migrate() court-circuite au niveau courant (v<N faux) -> le
        // bloc v75 n'était JAMAIS ré-exécuté, donc un statement non-idempotent y serait passé inaperçu. On
        // RÉTROGRADE schema_version (pattern v43/v44 lignes 17965/18201) pour FORCER la ré-exécution du bloc
        // v75 sur une base où engagement/engagement_grant existent déjà + event/alert/action/rollups portent
        // déjà engagement_id -> prouve que CREATE ... IF NOT EXISTS + ALTER gardé par col_exists + INSERT-règle
        // borné par nom sont RE-JOUABLES sans panic ni doublon.
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_detection_rules','1')", []).unwrap(); // simule instance live (le seed a tourné)
        let eng_rule = "SOC: engagement autorisé déclaré (défense auto-ban baissée)";
        for _ in 0..2 {
            conn.execute("UPDATE meta SET value='74' WHERE key='schema_version'", []).unwrap(); // rétrograde -> le bloc v75 re-tourne
            let _ = migrate(&conn);
            assert_eq!(conn.query_row::<String, _, _>("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap(), "111", "v75+v76+v77+v78 ré-exécutés remontent proprement au sommet (aucun statement non-idempotent ; host_rollup rebuild à blanc ; dparser CREATE IF NOT EXISTS)");
        }
        let dup: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE name=?1", params![eng_rule], |r| r.get(0)).unwrap();
        assert_eq!(dup, 1, "ré-exécuter v75 (instance live) n'insère la règle self-detection engagement QU'UNE fois (INSERT borné par nom)");
        // v65 : tables setting + source_settings (#1b Administration UI) présentes.
        assert!(col_exists(&conn, "setting", "value") && col_exists(&conn, "source_settings", "expected"));
        // v64 : colonne last_ts présente sur event_rollup (Fraîcheur âge réel).
        assert!(col_exists(&conn, "event_rollup", "last_ts"));
        // v67 (#2d) : env_id sur les rollups pré-agrégés.
        assert!(col_exists(&conn, "event_rollup", "env_id") && col_exists(&conn, "event_dim_rollup", "env_id"));
        assert!(col_exists(&conn, "rule", "mitre") && col_exists(&conn, "alert", "mitre"));
        // v60 : colonne `managed` présente sur les 3 tables d'overlay (parser/rule/playbook).
        assert!(col_exists(&conn, "rule", "managed") && col_exists(&conn, "parser", "managed") && col_exists(&conn, "playbook", "managed"));
        // v61 : tables d'enrichissement lookup présentes (kv + meta).
        assert!(col_exists(&conn, "lookup_kv", "val") && col_exists(&conn, "lookup_meta", "key_field"));
        // v66 : env_id sur les tables de donnée client scopables par environnement (#2a-2a).
        for t in ["event", "alert", "metric", "snapshot", "action", "incident", "incident_item", "banned_ip"] {
            assert!(col_exists(&conn, t, "env_id"), "{t}.env_id manquant après migrate v66");
        }
        // v68 (#3a) : table connector présente avec ses colonnes clés (secret + watermark + env_id).
        for c in ["type", "enabled", "config_json", "secret", "interval_s", "env_id", "watermark", "last_run", "last_error", "last_count"] {
            assert!(col_exists(&conn, "connector", c), "connector.{c} manquant après migrate v68");
        }
        // v69 (#4a) : colonnes cases first-class sur incident.
        for c in ["priority", "assignee", "sla_due", "first_response_ts", "escalated"] {
            assert!(col_exists(&conn, "incident", c), "incident.{c} manquant après migrate v69");
        }
        // v70 (#4a-bis) : colonnes archive/soft-delete sur incident.
        for c in ["archived", "archived_ts", "archived_by"] {
            assert!(col_exists(&conn, "incident", c), "incident.{c} manquant après migrate v70");
        }
        // v71 (durcissement sécu) : colonne created_by_role sur playbook (autorité d'auto-exécution).
        assert!(col_exists(&conn, "playbook", "created_by_role"), "playbook.created_by_role manquant après migrate v71");
        // v72 (durcissement sécu) : colonne origin sur event (découplage de l'exclusion de rétention).
        assert!(col_exists(&conn, "event", "origin"), "event.origin manquant après migrate v72");
        // v73 (durcissement sécu) : compteur de révocation session_epoch présent dans meta (défaut '0').
        let se: String = conn.query_row("SELECT value FROM meta WHERE key='session_epoch'", [], |r| r.get(0)).unwrap();
        assert_eq!(se, "0", "meta.session_epoch manquant/≠0 après migrate v73");
        // v75 (fondation mode engagement) : colonne engagement_id sur event/alert/action + les rollups.
        for t in ["event", "alert", "action", "event_rollup", "event_dim_rollup"] {
            assert!(col_exists(&conn, t, "engagement_id"), "{t}.engagement_id manquant après migrate v75");
        }
        // v75 : tables engagement + engagement_grant présentes avec leurs colonnes clés.
        for c in ["box", "scope", "window_start", "window_end", "authorizer", "reason", "status", "adapter", "created_by", "ended_ts"] {
            assert!(col_exists(&conn, "engagement", c), "engagement.{c} manquant après migrate v75");
        }
        for c in ["engagement_id", "kind", "ref", "idp_adapter", "issued_ts", "revoked_ts", "status"] {
            assert!(col_exists(&conn, "engagement_grant", c), "engagement_grant.{c} manquant après migrate v75");
        }
    }
    // ============================================================================================
    //  #1c-toggle — (DÉS)ACTIVATION ADMIN d'un contenu de détection avec OVERRIDE PERSISTANT qui survit au
    //  reboot pour les overlays config.d (managed=1). Vérifie : persistance de l'override + flip live ; que
    //  l'override GAGNE après ré-application des overlays (reboot simulé), dans les DEUX sens ; que
    //  l'ordonnanceur (run_due_rules) TIRE la règle nouvellement activée (enable -> it-runs) ; parité mode 0
    //  (aucun override -> apply_content_overrides est un no-op) ; admin-only (route + handler 403).
    // ============================================================================================

    /// (a) TOGGLE d'un overlay (managed=1) : écrit/maj un override (kind,name,enabled) + flippe la ligne live,
    /// et AUDITE (event plume-config). managed=0 (seed) : PAS d'override (l'enabled=0 durable suffit) — parité.
    #[test]
    fn override_toggle_managed1_persists_and_audits() {
        let conn = test_db();
        // règle overlay (managed=1) livrée DÉSACTIVÉE (comme un exemple config.d inerte).
        conn.execute("INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed) \
            VALUES('ov-toggle',0,'search severity>=3 | stats count',1,'>',0,3,300,3600,'T1046',1)", []).unwrap();
        let id: i64 = conn.query_row("SELECT id FROM rule WHERE name='ov-toggle'", [], |r| r.get(0)).unwrap();
        let body = set_content_enabled_tx(&conn, "rule", "rule", id, true, "alice").expect("toggle ok");
        assert_eq!(body["override"], true, "managed=1 -> override écrit");
        let en: i64 = conn.query_row("SELECT enabled FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        assert_eq!(en, 1, "ligne live activée");
        let ov: i64 = conn.query_row("SELECT enabled FROM detection_override WHERE kind='rule' AND name='ov-toggle'", [], |r| r.get(0)).unwrap();
        assert_eq!(ov, 1, "override persisté à 1");
        // audité : un event de contrôle plume-config est écrit (ledger + event non-purgeable).
        let nconf: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE source='plume-config' AND category='config'", [], |r| r.get(0)).unwrap();
        assert!(nconf >= 1, "(dés)activation auditée : event plume-config présent");
        let nledger: i64 = conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind='config.rule.enable'", [], |r| r.get(0)).unwrap();
        assert!(nledger >= 1, "ledger tamper-evident enregistre l'activation");
        // re-désactive : UPSERT -> UNE seule ligne, mise à 0 (pas de doublon).
        set_content_enabled_tx(&conn, "rule", "rule", id, false, "alice").expect("toggle ok");
        let (cnt, mn): (i64, i64) = conn.query_row("SELECT COUNT(*),COALESCE(MAX(enabled),-1) FROM detection_override WHERE kind='rule' AND name='ov-toggle'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((cnt, mn), (1, 0), "UPSERT : une seule ligne d'override, remise à 0");
        // managed=0 (seed) : flip enabled mais AUCUN override écrit (comportement historique conservé).
        conn.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('seed-r',1,'search severity>=3 | stats count',1,0)", []).unwrap();
        let sid: i64 = conn.query_row("SELECT id FROM rule WHERE name='seed-r'", [], |r| r.get(0)).unwrap();
        set_content_enabled_tx(&conn, "rule", "rule", sid, false, "alice").expect("ok");
        let sc: i64 = conn.query_row("SELECT COUNT(*) FROM detection_override WHERE name='seed-r'", [], |r| r.get(0)).unwrap();
        assert_eq!(sc, 0, "managed=0 : aucun override (parité historique)");
        let sen: i64 = conn.query_row("SELECT enabled FROM rule WHERE id=?1", params![sid], |r| r.get(0)).unwrap();
        assert_eq!(sen, 0, "managed=0 : enabled bien flippé");
        // introuvable -> 404.
        assert!(matches!(set_content_enabled_tx(&conn, "rule", "rule", 999999, true, "alice"), Err((StatusCode::NOT_FOUND, _))));
    }

    /// (b) L'override GAGNE après RÉ-APPLICATION des overlays (reboot simulé), dans les DEUX sens : une règle
    /// livrée enabled=false qu'un admin ACTIVE reste active ; une règle livrée enabled=true qu'un admin
    /// DÉSACTIVE reste désactivée. C'est le cœur du fix : le fichier git ne re-stompe plus le choix admin.
    #[test]
    fn override_wins_after_overlay_reapply_both_directions() {
        let conn = test_db();
        let dir = mk_overlay_dir("ovr-reapply");
        write_overlay(&dir, "rules", "a.json", r#"{"name":"ovr-A","query":"search severity>=3 | stats count","is_soql":true,"enabled":false,"mitre":"T1046"}"#);
        write_overlay(&dir, "rules", "b.json", r#"{"name":"ovr-B","query":"search severity>=3 | stats count","is_soql":true,"enabled":true,"mitre":"T1046"}"#);
        load_overlays_dir(&conn, &dir); // boot #1
        let ea: i64 = conn.query_row("SELECT enabled FROM rule WHERE name='ovr-A'", [], |r| r.get(0)).unwrap();
        let eb: i64 = conn.query_row("SELECT enabled FROM rule WHERE name='ovr-B'", [], |r| r.get(0)).unwrap();
        assert_eq!((ea, eb), (0, 1), "état initial = celui des fichiers");
        let ida: i64 = conn.query_row("SELECT id FROM rule WHERE name='ovr-A'", [], |r| r.get(0)).unwrap();
        let idb: i64 = conn.query_row("SELECT id FROM rule WHERE name='ovr-B'", [], |r| r.get(0)).unwrap();
        // ADMIN : active A (contre le fichier false), désactive B (contre le fichier true).
        set_content_enabled_tx(&conn, "rule", "rule", ida, true, "alice").unwrap();
        set_content_enabled_tx(&conn, "rule", "rule", idb, false, "alice").unwrap();
        load_overlays_dir(&conn, &dir); // boot #2 (reboot simulé) : fichier ré-imposé PUIS override gagne
        let ea2: i64 = conn.query_row("SELECT enabled FROM rule WHERE name='ovr-A'", [], |r| r.get(0)).unwrap();
        let eb2: i64 = conn.query_row("SELECT enabled FROM rule WHERE name='ovr-B'", [], |r| r.get(0)).unwrap();
        assert_eq!(ea2, 1, "A : override admin (activé) GAGNE sur enabled=false du fichier");
        assert_eq!(eb2, 0, "B : override admin (désactivé) GAGNE sur enabled=true du fichier");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// (e) PARITÉ MODE 0 : sans aucune ligne d'override, apply_content_overrides ne touche AUCUNE ligne
    /// (0 UPDATE) -> le boot reste byte-identique à l'historique.
    #[test]
    fn apply_content_overrides_is_noop_without_rows() {
        let conn = test_db();
        conn.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('no-ovr',1,'search severity>=3 | stats count',1,1)", []).unwrap();
        conn.execute("INSERT INTO parser(name,source,pattern,enabled,builtin,managed,created) VALUES('no-ovr-p','*','x=(?P<x>\\d+)',1,0,1,0)", []).unwrap();
        apply_content_overrides(&conn);
        let en: i64 = conn.query_row("SELECT enabled FROM rule WHERE name='no-ovr'", [], |r| r.get(0)).unwrap();
        let ep: i64 = conn.query_row("SELECT enabled FROM parser WHERE name='no-ovr-p'", [], |r| r.get(0)).unwrap();
        assert_eq!((en, ep), (1, 1), "aucun override -> enabled inchangé (mode 0 byte-identique)");
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM detection_override", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "aucune ligne d'override créée");
    }

    /// (c) ENABLE -> IT-RUNS : une règle overlay LIVRÉE DÉSACTIVÉE, activée par l'admin (override), reste
    /// active après reboot ET est ÉVALUÉE + TIRE par l'ORDONNANCEUR run_due_rules (pas le dry-run). Prouve
    /// que la bascule débouche réellement sur une détection qui tourne. Télémétrie via le PARSEUR nft (réel).
    #[test]
    fn scheduler_fires_override_enabled_config_d_rule() {
        let mut path = std::env::temp_dir();
        path.push(format!("plume-ovr-sched-{}-{}.db", std::process::id(), now()));
        let p = path.to_string_lossy().to_string();
        let base = now() - 900;
        let dir = mk_overlay_dir("ovr-sched");
        // règle overlay firewall LIVRÉE DÉSACTIVÉE (comme fw-denied-portscan) : dc(dst_port) by src_ip > 8.
        write_overlay(&dir, "rules", "r.json",
            r#"{"name":"ovr-sched-ps","query":"search category=firewall action=deny | stats dc(dst_port) by src_ip | where dc > 8 | stats count","is_soql":true,"op":">","threshold":0,"severity":3,"interval_s":300,"window_s":3600,"mitre":"T1046","enabled":false}"#);
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            w.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('nft-sd','nft',?1,1,0,1,0)",
                params![nft_parser_spec()]).unwrap();
            dparsers_reload(&w, &p);
            load_overlays_dir(&w, &dir); // boot #1 : chargée DÉSACTIVÉE
            let id: i64 = w.query_row("SELECT id FROM rule WHERE name='ovr-sched-ps'", [], |r| r.get(0)).unwrap();
            let en0: i64 = w.query_row("SELECT enabled FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap();
            assert_eq!(en0, 0, "pré-condition : la règle overlay démarre désactivée");
            set_content_enabled_tx(&w, "rule", "rule", id, true, "alice").expect("toggle"); // ADMIN active
            load_overlays_dir(&w, &dir); // boot #2 (reboot) : override gagne -> ACTIVE
            let en1: i64 = w.query_row("SELECT enabled FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap();
            assert_eq!(en1, 1, "après reboot, l'override admin gagne -> règle ACTIVE");
            // 12 probes d'UNE IP vers 12 ports distincts (via le parseur nft -> CIM firewall/deny).
            let ports = [21u32, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389];
            let events: Vec<Value> = ports.iter().enumerate().map(|(i, dpt)| json!({
                "ts": base + (i as i64) * 20, "source": "nft", "category": "", "severity": 0,
                "message": nft_portscan_line("203.0.113.7", "198.51.100.4", *dpt), "dedup": format!("nft-{i}")
            })).collect();
            assert_eq!(ingest_events_batch(&w, &p, &events, base, None, None).expect("ingest"), 12);
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_due_rules(&db, &p);
        let (val, fired): (f64, i64) = {
            let c = db.lock();
            (c.query_row("SELECT COALESCE(last_value,-1) FROM rule WHERE name='ovr-sched-ps'", [], |r| r.get(0)).unwrap(),
             c.query_row("SELECT CASE WHEN last_fired IS NULL THEN 0 ELSE 1 END FROM rule WHERE name='ovr-sched-ps'", [], |r| r.get(0)).unwrap())
        };
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(val, 1.0, "1 IP au-dessus de dc(dst_port)>8 -> valeur 1");
        assert_eq!(fired, 1, "l'ordonnanceur TIRE la règle activée par override -> enable->it-runs prouvé");
    }

    /// (d) ADMIN-ONLY au niveau ROUTE : le toggle /enabled est classé Admin (route_min_role) et rbac_gate
    /// (default-deny) refuse editor/viewer/agent — pour règles, parseurs ET playbooks. Le CRUD éditorial des
    /// règles (sans /enabled) reste editor+ (invariant non régressé).
    #[test]
    fn content_enabled_toggle_route_is_admin_only() {
        for path in ["/api/rules/5/enabled", "/api/parsers/5/enabled", "/api/playbooks/5/enabled"] {
            assert_eq!(route_min_role(path, true), MinRole::Admin, "{path} POST = admin-only");
            assert!(rbac_gate("admin", path, true).is_ok(), "admin bascule {path}");
            assert!(rbac_gate("editor", path, true).is_err(), "editor NE bascule PAS {path} (default-deny)");
            assert!(rbac_gate("viewer", path, true).is_err(), "viewer NE bascule PAS {path}");
            assert!(rbac_gate("agent", path, true).is_err(), "agent NE bascule PAS {path}");
        }
        // non-régression : l'édition de règle (CRUD) reste editor+.
        assert!(rbac_gate("editor", "/api/rules/5", true).is_ok(), "l'édition de règle reste editor+");
    }

    /// (d bis) ADMIN-ONLY au niveau HANDLER : rule_set_enabled re-check require_admin. editor -> 403 SANS
    /// aucun flip ni override ; admin -> 200 + flip + override ; corps sans `enabled` -> 400.
    #[tokio::test]
    async fn rule_set_enabled_handler_admin_gate() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        { let c = st.db.lock(); c.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('h-ovr',0,'search severity>=3 | stats count',1,1)", []).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM rule WHERE name='h-ovr'", [], |r| r.get(0)).unwrap() };
        // NON-ADMIN (editor) -> 403, aucun changement.
        let (code, _v) = tok_resp_json(rule_set_enabled(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"enabled": true}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor -> 403");
        let en_ed: i64 = { let c = st.db.lock(); c.query_row("SELECT enabled FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap() };
        let ov_ed: i64 = { let c = st.db.lock(); c.query_row("SELECT COUNT(*) FROM detection_override WHERE name='h-ovr'", [], |r| r.get(0)).unwrap() };
        assert_eq!((en_ed, ov_ed), (0, 0), "editor refusé -> ni flip ni override");
        // ADMIN -> 200, override écrit + flip.
        let (code, v) = tok_resp_json(rule_set_enabled(State(st.clone()), Extension(tok_au("admin")), Path(id), Json(json!({"enabled": true}))).await).await;
        assert_eq!(code, StatusCode::OK, "admin -> 200");
        assert_eq!(v["override"], true);
        let en: i64 = { let c = st.db.lock(); c.query_row("SELECT enabled FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap() };
        let ov: i64 = { let c = st.db.lock(); c.query_row("SELECT enabled FROM detection_override WHERE kind='rule' AND name='h-ovr'", [], |r| r.get(0)).unwrap() };
        assert_eq!((en, ov), (1, 1), "admin : flip live + override persisté");
        // corps invalide (enabled absent) -> 400.
        let (code, _v) = tok_resp_json(rule_set_enabled(State(st.clone()), Extension(tok_au("admin")), Path(id), Json(json!({}))).await).await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "enabled manquant -> 400");
    }

    // ============================================================================================
    //  FIX HIGH-1 — le CRUD éditorial pré-existant (rule/parser/playbook _update) ne doit PLUS laisser un
    //  non-admin basculer `enabled` sur une détection MANAGÉE (managed=0 seed / managed=1 overlay). L'editor
    //  garde l'invariant : CRUD complet sur SON propre contenu ad-hoc managed=2, y compris (dés)activation.
    // ============================================================================================

    /// (HIGH-1.1) editor POST /api/rules/:id {"enabled":false} sur un SEED managed=0 -> 403 ; la règle reste
    /// enabled=1 ET managed=0 (PAS d'adoption managed=0->2 : le refus est fail-closed, aucune écriture).
    #[tokio::test]
    async fn crud_editor_cannot_disable_managed0_seed_rule() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        { let c = st.db.lock(); c.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('selfdetect-seed',1,'search severity>=3 | stats count',1,0)", []).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM rule WHERE name='selfdetect-seed'", [], |r| r.get(0)).unwrap() };
        let (code, _v) = tok_resp_json(rule_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE désactive PAS un seed managed=0 via CRUD");
        let (en, mgd): (i64, i64) = { let c = st.db.lock(); c.query_row("SELECT enabled,managed FROM rule WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((en, mgd), (1, 0), "seed INTACT : toujours activé + toujours managed=0 (NON adopté)");
    }

    /// (HIGH-1.2) editor POST /api/rules/:id {"enabled":false} sur un OVERLAY managed=1 -> 403 ; inchangé.
    #[tokio::test]
    async fn crud_editor_cannot_disable_managed1_overlay_rule() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        { let c = st.db.lock(); c.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('ov-rule',1,'search severity>=3 | stats count',1,1)", []).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM rule WHERE name='ov-rule'", [], |r| r.get(0)).unwrap() };
        let (code, _v) = tok_resp_json(rule_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE fait PAS taire un overlay managed=1 via CRUD");
        let (en, mgd): (i64, i64) = { let c = st.db.lock(); c.query_row("SELECT enabled,managed FROM rule WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((en, mgd), (1, 1), "overlay INTACT : activé + managed=1");
    }

    /// (HIGH-1.3) INVARIANT PRÉSERVÉ : editor CRÉE puis (dés)active SON PROPRE ad-hoc managed=2 via le CRUD
    /// -> 200, `enabled` flippe bien. Le fix ne casse PAS le flux légitime editor-sur-son-contenu.
    #[tokio::test]
    async fn crud_editor_can_toggle_own_managed2_rule() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        { let c = st.db.lock(); c.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('adhoc-ed',1,'search severity>=3 | stats count',1,2)", []).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM rule WHERE name='adhoc-ed'", [], |r| r.get(0)).unwrap() };
        // désactive
        let (code, _v) = tok_resp_json(rule_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::OK, "editor désactive SON ad-hoc managed=2 -> 200");
        let en0: i64 = { let c = st.db.lock(); c.query_row("SELECT enabled FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap() };
        assert_eq!(en0, 0, "flip vers désactivé appliqué");
        // ré-active
        let (code, _v) = tok_resp_json(rule_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"enabled": true}))).await).await;
        assert_eq!(code, StatusCode::OK, "editor ré-active SON ad-hoc managed=2 -> 200");
        let en1: i64 = { let c = st.db.lock(); c.query_row("SELECT enabled FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap() };
        assert_eq!(en1, 1, "flip vers activé appliqué -> invariant editor-CRUD-managed=2 PRÉSERVÉ");
    }

    /// (HIGH-1.4) NON-RÉGRESSION : l'admin n'est PAS sur-restreint — il bascule `enabled` via le CRUD sur un
    /// seed managed=0 (200, flip) ET sur un overlay managed=1 (200, flip, managed=1 conservé).
    #[tokio::test]
    async fn crud_admin_can_toggle_managed_rules() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        { let c = st.db.lock();
          c.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('seed-a',1,'search severity>=3 | stats count',1,0)", []).unwrap();
          c.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('ov-a',1,'search severity>=3 | stats count',1,1)", []).unwrap();
        }
        let sid: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM rule WHERE name='seed-a'", [], |r| r.get(0)).unwrap() };
        let oid: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM rule WHERE name='ov-a'", [], |r| r.get(0)).unwrap() };
        let (code, _v) = tok_resp_json(rule_update(State(st.clone()), Extension(tok_au("admin")), Path(sid), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::OK, "admin désactive un seed via CRUD -> 200");
        let ens: i64 = { let c = st.db.lock(); c.query_row("SELECT enabled FROM rule WHERE id=?1", params![sid], |r| r.get(0)).unwrap() };
        assert_eq!(ens, 0, "seed flippé par l'admin");
        let (code, _v) = tok_resp_json(rule_update(State(st.clone()), Extension(tok_au("admin")), Path(oid), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::OK, "admin désactive un overlay via CRUD -> 200");
        let (eno, mgo): (i64, i64) = { let c = st.db.lock(); c.query_row("SELECT enabled,managed FROM rule WHERE id=?1", params![oid], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((eno, mgo), (0, 1), "overlay flippé par l'admin, managed=1 conservé");
    }

    // ============================================================================================
    //  FIX HIGH-1b — bypass adopt-then-toggle EN 2 REQUÊTES fermé. La garde HIGH-1 (par `cur_managed==2`)
    //  suffisait pour UNE requête "edit+disable", mais l'effet de bord d'adoption managed=0->2 la rendait
    //  contournable : req#1 = édition cosmétique/vide d'un seed (managed passe 0->2), req#2 = {"enabled":false}
    //  (la garde HIGH-1 laisse passer via `cur_managed==2`). Fix PRIMAIRE : interdire TOUTE édition non-admin
    //  d'un managed=0 -> plus d'adoption -> `cur_managed` ne bascule jamais 0->2 pour un editor.
    // ============================================================================================

    /// (HIGH-1b.1 — RULE) req#1 : editor édite (cosmétique/neuter-via-query) un SEED managed=0 -> 403, AUCUNE
    /// adoption (managed reste 0, enabled reste 1, query intacte). req#2 : editor {"enabled":false} -> 403,
    /// toujours enabled=1. Le tremplin d'adoption est supprimé -> le seed n'est JAMAIS durablement désactivable.
    #[tokio::test]
    async fn crud_editor_cannot_adopt_then_disable_seed_rule() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        { let c = st.db.lock(); c.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('selfdetect-rule',1,'search severity>=3 | stats count',1,0)", []).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM rule WHERE name='selfdetect-rule'", [], |r| r.get(0)).unwrap() };
        // req#1a : édition PUREMENT cosmétique (nom) — le tremplin d'adoption AVANT le fix.
        let (code, _v) = tok_resp_json(rule_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"name": "pwn"}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE peut PAS éditer un seed managed=0 (pas d'adoption tremplin)");
        let (nm, mgd): (String, i64) = { let c = st.db.lock(); c.query_row("SELECT name,managed FROM rule WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((nm.as_str(), mgd), ("selfdetect-rule", 0), "seed NON adopté : nom + managed=0 intacts");
        // req#1b : NEUTER-VIA-QUERY (réécrire la requête pour qu'elle ne matche jamais) -> 403, query intacte.
        let (code, _v) = tok_resp_json(rule_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"query": "search 1=0 | stats count"}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE peut PAS neutraliser un seed en réécrivant sa requête");
        let q: String = { let c = st.db.lock(); c.query_row("SELECT query FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap() };
        assert_eq!(q, "search severity>=3 | stats count", "requête du seed intacte (neuter fermé)");
        // req#2 : la désactivation reste 403 (managed toujours 0 -> le disjoint cur_managed==2 inatteignable).
        let (code, _v) = tok_resp_json(rule_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE peut PAS désactiver le seed (bypass 2-requêtes fermé)");
        let (en, mgd): (i64, i64) = { let c = st.db.lock(); c.query_row("SELECT enabled,managed FROM rule WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((en, mgd), (1, 0), "état FINAL : seed toujours activé + toujours managed=0");
    }

    /// (HIGH-1b.2 — PARSER) même scénario sur un parseur builtin managed=0 : édition editor -> 403 sans adoption,
    /// puis {"enabled":false} -> 403 ; parseur toujours activé + managed=0/builtin=1.
    #[tokio::test]
    async fn crud_editor_cannot_adopt_then_disable_seed_parser() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        { let c = st.db.lock(); c.execute("INSERT INTO parser(name,source,pattern,enabled,builtin,managed,created) VALUES('sshd-seed','sshd','user=(?P<user>\\w+)',1,1,0,0)", []).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM parser WHERE name='sshd-seed'", [], |r| r.get(0)).unwrap() };
        // req#1 : édition cosmétique (source) -> 403, aucune adoption (managed=0, builtin=1 conservés).
        let (code, _v) = tok_resp_json(parser_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"source": "sshd-x"}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE peut PAS éditer un parseur seed managed=0");
        let (mgd, blt): (i64, i64) = { let c = st.db.lock(); c.query_row("SELECT managed,builtin FROM parser WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((mgd, blt), (0, 1), "parseur seed NON adopté (managed=0, builtin=1)");
        // req#2 : désactivation -> 403, toujours activé.
        let (code, _v) = tok_resp_json(parser_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE peut PAS désactiver le parseur seed (bypass fermé)");
        let en: i64 = { let c = st.db.lock(); c.query_row("SELECT enabled FROM parser WHERE id=?1", params![id], |r| r.get(0)).unwrap() };
        assert_eq!(en, 1, "état FINAL : parseur seed toujours activé");
    }

    /// (HIGH-1b.3 — PLAYBOOK) un playbook seed managed=0 : édition editor -> 403 (double garde : l'ENUM d'actions
    /// est INTÉGRALEMENT destructif -> arm-gate ; PLUS le refus baseline managed=0), aucune adoption, puis
    /// {"enabled":false} -> 403 ; playbook toujours activé + managed=0.
    #[tokio::test]
    async fn crud_editor_cannot_adopt_then_disable_seed_playbook() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        { let c = st.db.lock(); c.execute("INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,created_by_role) VALUES('auto-ban-seed',1,'search severity>=4 | table src',1,'ban_ip',300,3600,0,'admin')", []).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM playbook WHERE name='auto-ban-seed'", [], |r| r.get(0)).unwrap() };
        // req#1 : édition cosmétique -> 403 (aucune adoption).
        let (code, _v) = tok_resp_json(playbook_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"name": "pwn-pb"}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE peut PAS éditer un playbook seed managed=0");
        let (nm, mgd): (String, i64) = { let c = st.db.lock(); c.query_row("SELECT name,managed FROM playbook WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((nm.as_str(), mgd), ("auto-ban-seed", 0), "playbook seed NON adopté (nom + managed=0 intacts)");
        // req#2 : désactivation -> 403, toujours activé.
        let (code, _v) = tok_resp_json(playbook_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE peut PAS désactiver le playbook seed (bypass fermé)");
        let en: i64 = { let c = st.db.lock(); c.query_row("SELECT enabled FROM playbook WHERE id=?1", params![id], |r| r.get(0)).unwrap() };
        assert_eq!(en, 1, "état FINAL : playbook seed toujours activé");
    }

    /// (HIGH-1b.4 — RÉGRESSION ADMIN) l'admin garde le flux légitime : il ÉDITE un seed managed=0 (adoption
    /// 0->2), PUIS le (dés)active — les deux -> 200. Le fix ne sur-restreint QUE le non-admin.
    #[tokio::test]
    async fn crud_admin_can_adopt_and_toggle_seed_rule() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        { let c = st.db.lock(); c.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('seed-tune',1,'search severity>=3 | stats count',1,0)", []).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM rule WHERE name='seed-tune'", [], |r| r.get(0)).unwrap() };
        // admin édite (tune) le seed -> 200 + adoption managed=0->2 (le seed devient contenu admin ad-hoc).
        let (code, _v) = tok_resp_json(rule_update(State(st.clone()), Extension(tok_au("admin")), Path(id), Json(json!({"name": "seed-tuned"}))).await).await;
        assert_eq!(code, StatusCode::OK, "admin ÉDITE un seed -> 200");
        let mgd: i64 = { let c = st.db.lock(); c.query_row("SELECT managed FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap() };
        assert_eq!(mgd, 2, "adoption admin managed=0->2 préservée");
        // admin (dés)active -> 200.
        let (code, _v) = tok_resp_json(rule_update(State(st.clone()), Extension(tok_au("admin")), Path(id), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::OK, "admin désactive le seed adopté -> 200");
        let en: i64 = { let c = st.db.lock(); c.query_row("SELECT enabled FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap() };
        assert_eq!(en, 0, "flip admin appliqué");
    }

    /// (HIGH-1b.5 — INVARIANT PARSER) l'editor garde le CRUD COMPLET sur SON PROPRE parseur ad-hoc managed=2
    /// (créé via POST /api/parsers, qui insère managed=2 DIRECTEMENT, PAS via adoption) : (dés)activation -> 200.
    #[tokio::test]
    async fn crud_editor_retains_crud_on_own_managed2_parser() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        // création via le handler : POST insère managed=2 (contenu ad-hoc de l'editor).
        let (code, v) = tok_resp_json(parser_create(State(st.clone()), Extension(tok_au("editor")), Json(json!({"name": "ed-parser", "source": "app", "pattern": "user=(?P<user>\\w+)"}))).await).await;
        assert_eq!(code, StatusCode::OK, "editor CRÉE son parseur -> 200");
        assert_eq!(v["managed"], 2, "création editor -> managed=2 (direct, pas adoption)");
        let id = v["id"].as_i64().unwrap();
        // éditer + désactiver SON parseur managed=2 -> 200 (le fix ne casse PAS ce flux légitime).
        let (code, _v) = tok_resp_json(parser_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::OK, "editor désactive SON parseur managed=2 -> 200 (invariant préservé)");
        let en: i64 = { let c = st.db.lock(); c.query_row("SELECT enabled FROM parser WHERE id=?1", params![id], |r| r.get(0)).unwrap() };
        assert_eq!(en, 0, "flip appliqué sur le parseur ad-hoc de l'editor");
    }

    // ============================================================================================
    //  FIX HIGH-1b (PORT SIBLING) — même classe fermée sur correlation_update + baseline_update (détection
    //  avancée #37). Route /api/correlations + /api/baselines = editor+ (rbac §7) -> TROU LIVE exploitable :
    //  sans garde, un editor désactivait/neutralisait une corrélation OU une baseline SEEDÉE (managed=0) en
    //  UNE requête (adoption managed=0->2 + écriture inconditionnelle de `enabled`). Miroir exact des tests
    //  crud_editor_cannot_adopt_then_disable_seed_{rule,parser,playbook}.
    // ============================================================================================

    /// (HIGH-1b.6 — CORRÉLATION) editor {"enabled":false} sur une corrélation SEED managed=0 -> 403, INTACTE ;
    /// puis PATCH vide/query-rewrite -> 403, aucune adoption (managed reste 0). Bypass single-request fermé.
    #[tokio::test]
    async fn crud_editor_cannot_disable_seed_correlation() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        let steps = r#"[{"name":"s1","query":"search source=auth outcome=fail","min_count":3},{"name":"s2","query":"search source=auth outcome=success","min_count":1}]"#;
        { let c = st.db.lock(); c.execute("INSERT INTO correlation(name,enabled,key_field,entity_type,steps,window_s,interval_s,severity,mitre,risk_score,managed) VALUES('bf-seed',1,'src_ip','ip',?1,3600,300,4,'T1110',0,0)", params![steps]).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM correlation WHERE name='bf-seed'", [], |r| r.get(0)).unwrap() };
        // req#1 : désactivation directe -> 403, corrélation INTACTE.
        let (code, _v) = tok_resp_json(correlation_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE désactive PAS une corrélation seed managed=0");
        let (en, mgd): (i64, i64) = { let c = st.db.lock(); c.query_row("SELECT enabled,managed FROM correlation WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((en, mgd), (1, 0), "seed INTACT : activé + managed=0 (non adopté)");
        // req#2 : PATCH cosmétique (tremplin d'adoption AVANT le fix) -> 403, pas d'adoption.
        let (code, _v) = tok_resp_json(correlation_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"name": "pwn"}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE peut PAS éditer une corrélation seed (pas d'adoption tremplin)");
        let (nm, mgd): (String, i64) = { let c = st.db.lock(); c.query_row("SELECT name,managed FROM correlation WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((nm.as_str(), mgd), ("bf-seed", 0), "corrélation NON adoptée : nom + managed=0 intacts");
    }

    /// (HIGH-1b.7 — BASELINE UEBA) editor {"enabled":false} sur une baseline SEED managed=0 -> 403, INTACTE ;
    /// puis PATCH cosmétique -> 403, aucune adoption (managed reste 0). Bypass single-request fermé.
    #[tokio::test]
    async fn crud_editor_cannot_disable_seed_baseline() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        { let c = st.db.lock(); c.execute("INSERT INTO ueba_baseline(name,enabled,query,is_soql,entity_type,entity_field,value_field,bucket_s,min_samples,z_threshold,window_s,interval_s,severity,mitre,risk_score,managed) VALUES('auth-vol-seed',1,'search source=auth | stats count by host',1,'host','host','',3600,5,3.0,604800,3600,3,'T1110',0,0)", []).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM ueba_baseline WHERE name='auth-vol-seed'", [], |r| r.get(0)).unwrap() };
        // req#1 : désactivation directe -> 403, baseline INTACTE.
        let (code, _v) = tok_resp_json(baseline_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE désactive PAS une baseline seed managed=0");
        let (en, mgd): (i64, i64) = { let c = st.db.lock(); c.query_row("SELECT enabled,managed FROM ueba_baseline WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((en, mgd), (1, 0), "seed INTACT : activé + managed=0 (non adopté)");
        // req#2 : PATCH cosmétique -> 403, pas d'adoption.
        let (code, _v) = tok_resp_json(baseline_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"name": "pwn"}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE peut PAS éditer une baseline seed (pas d'adoption tremplin)");
        let (nm, mgd): (String, i64) = { let c = st.db.lock(); c.query_row("SELECT name,managed FROM ueba_baseline WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((nm.as_str(), mgd), ("auth-vol-seed", 0), "baseline NON adoptée : nom + managed=0 intacts");
    }

    /// (HIGH-1b.8 — RÉGRESSION ADMIN) l'admin garde le flux légitime sur les DEUX moteurs : il ÉDITE un seed
    /// managed=0 (adoption 0->2) PUIS le désactive -> 200. Le fix ne sur-restreint QUE le non-admin.
    #[tokio::test]
    async fn crud_admin_can_adopt_and_toggle_seed_correlation_and_baseline() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        let steps = r#"[{"name":"s1","query":"search source=auth outcome=fail","min_count":3},{"name":"s2","query":"search source=auth outcome=success","min_count":1}]"#;
        { let c = st.db.lock();
          c.execute("INSERT INTO correlation(name,enabled,key_field,entity_type,steps,window_s,interval_s,severity,mitre,risk_score,managed) VALUES('bf-adm',1,'src_ip','ip',?1,3600,300,4,'T1110',0,0)", params![steps]).unwrap();
          c.execute("INSERT INTO ueba_baseline(name,enabled,query,is_soql,entity_type,entity_field,value_field,bucket_s,min_samples,z_threshold,window_s,interval_s,severity,mitre,risk_score,managed) VALUES('bl-adm',1,'search source=auth | stats count by host',1,'host','host','',3600,5,3.0,604800,3600,3,'T1110',0,0)", []).unwrap();
        }
        let cid: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM correlation WHERE name='bf-adm'", [], |r| r.get(0)).unwrap() };
        let bid: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM ueba_baseline WHERE name='bl-adm'", [], |r| r.get(0)).unwrap() };
        // admin édite (adoption 0->2) puis désactive la corrélation -> 200.
        let (code, _v) = tok_resp_json(correlation_update(State(st.clone()), Extension(tok_au("admin")), Path(cid), Json(json!({"name": "bf-adm-tuned"}))).await).await;
        assert_eq!(code, StatusCode::OK, "admin ÉDITE une corrélation seed -> 200");
        let (code, _v) = tok_resp_json(correlation_update(State(st.clone()), Extension(tok_au("admin")), Path(cid), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::OK, "admin désactive la corrélation seed -> 200");
        let (en, mgd): (i64, i64) = { let c = st.db.lock(); c.query_row("SELECT enabled,managed FROM correlation WHERE id=?1", params![cid], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((en, mgd), (0, 2), "corrélation : flip admin appliqué + adoption 0->2");
        // idem baseline.
        let (code, _v) = tok_resp_json(baseline_update(State(st.clone()), Extension(tok_au("admin")), Path(bid), Json(json!({"name": "bl-adm-tuned"}))).await).await;
        assert_eq!(code, StatusCode::OK, "admin ÉDITE une baseline seed -> 200");
        let (code, _v) = tok_resp_json(baseline_update(State(st.clone()), Extension(tok_au("admin")), Path(bid), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::OK, "admin désactive la baseline seed -> 200");
        let (en, mgd): (i64, i64) = { let c = st.db.lock(); c.query_row("SELECT enabled,managed FROM ueba_baseline WHERE id=?1", params![bid], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((en, mgd), (0, 2), "baseline : flip admin appliqué + adoption 0->2");
    }

    /// (HIGH-1b.9 — INVARIANT EDITOR) l'editor garde le CRUD sur SON PROPRE contenu ad-hoc managed=2 (créé via
    /// POST, qui insère managed=2 DIRECTEMENT) : (dés)activer sa corrélation ET sa baseline -> 200.
    #[tokio::test]
    async fn crud_editor_retains_crud_on_own_managed2_correlation_and_baseline() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        let steps = r#"[{"name":"s1","query":"search source=auth outcome=fail","min_count":3},{"name":"s2","query":"search source=auth outcome=success","min_count":1}]"#;
        { let c = st.db.lock();
          c.execute("INSERT INTO correlation(name,enabled,key_field,entity_type,steps,window_s,interval_s,severity,mitre,risk_score,managed) VALUES('bf-ed',1,'src_ip','ip',?1,3600,300,4,'T1110',0,2)", params![steps]).unwrap();
          c.execute("INSERT INTO ueba_baseline(name,enabled,query,is_soql,entity_type,entity_field,value_field,bucket_s,min_samples,z_threshold,window_s,interval_s,severity,mitre,risk_score,managed) VALUES('bl-ed',1,'search source=auth | stats count by host',1,'host','host','',3600,5,3.0,604800,3600,3,'T1110',0,2)", []).unwrap();
        }
        let cid: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM correlation WHERE name='bf-ed'", [], |r| r.get(0)).unwrap() };
        let bid: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM ueba_baseline WHERE name='bl-ed'", [], |r| r.get(0)).unwrap() };
        let (code, _v) = tok_resp_json(correlation_update(State(st.clone()), Extension(tok_au("editor")), Path(cid), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::OK, "editor désactive SA corrélation managed=2 -> 200 (invariant préservé)");
        let en: i64 = { let c = st.db.lock(); c.query_row("SELECT enabled FROM correlation WHERE id=?1", params![cid], |r| r.get(0)).unwrap() };
        assert_eq!(en, 0, "flip appliqué sur la corrélation ad-hoc de l'editor");
        let (code, _v) = tok_resp_json(baseline_update(State(st.clone()), Extension(tok_au("editor")), Path(bid), Json(json!({"enabled": false}))).await).await;
        assert_eq!(code, StatusCode::OK, "editor désactive SA baseline managed=2 -> 200 (invariant préservé)");
        let en: i64 = { let c = st.db.lock(); c.query_row("SELECT enabled FROM ueba_baseline WHERE id=?1", params![bid], |r| r.get(0)).unwrap() };
        assert_eq!(en, 0, "flip appliqué sur la baseline ad-hoc de l'editor");
    }

    // ============================================================================================
    //  INVARIANT — la garde d'adoption passe de `cur_managed == 0` à `cur_managed != 2` sur les 5
    //  handlers (rule/parser/playbook/correlation/baseline). AVANT : un editor pouvait TRANSITOIREMENT
    //  NEUTRALISER un OVERLAY managed=1 en éditant sa query/threshold/pattern/steps (tout SAUF `enabled`, déjà
    //  gardé par HIGH-1) — l'overlay est ré-imposé au prochain boot, mais le trou live-neuter était réel.
    //  Ces tests VÉRIFIENT le neuter-via-content-field sur managed=1 -> 403, contenu INTACT. L'invariant
    //  editor-CRUD-managed=2 reste couvert par les tests HIGH-1/HIGH-1b (crud_editor_can_toggle_own_managed2_*).
    // ============================================================================================

    /// (INVARIANT 1 — RULE) editor réécrit la QUERY d'un OVERLAY managed=1 (neuter) -> 403, query + managed intacts.
    #[tokio::test]
    async fn crud_editor_cannot_neuter_managed1_overlay_rule() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        { let c = st.db.lock(); c.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('ov-neuter',1,'search severity>=3 | stats count',1,1)", []).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM rule WHERE name='ov-neuter'", [], |r| r.get(0)).unwrap() };
        // neuter-via-query : réécrire la requête pour qu'elle ne matche jamais.
        let (code, _v) = tok_resp_json(rule_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"query": "search 1=0 | stats count"}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE neutralise PAS un overlay managed=1 en réécrivant sa requête");
        // neuter-via-threshold : monter le seuil hors d'atteinte.
        let (code, _v) = tok_resp_json(rule_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"threshold": 999999.0}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE neutralise PAS un overlay managed=1 via son seuil");
        let (q, mgd): (String, i64) = { let c = st.db.lock(); c.query_row("SELECT query,managed FROM rule WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((q.as_str(), mgd), ("search severity>=3 | stats count", 1), "overlay INTACT : query d'origine + managed=1");
    }

    /// (INVARIANT 2 — PARSER) editor réécrit le PATTERN d'un OVERLAY managed=1 -> 403, pattern + managed intacts.
    #[tokio::test]
    async fn crud_editor_cannot_neuter_managed1_overlay_parser() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        { let c = st.db.lock(); c.execute("INSERT INTO parser(name,source,pattern,enabled,builtin,managed,created) VALUES('ov-parser','app','user=(?P<user>\\w+)',1,0,1,0)", []).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM parser WHERE name='ov-parser'", [], |r| r.get(0)).unwrap() };
        let (code, _v) = tok_resp_json(parser_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"pattern": "NEVERMATCH(?P<user>\\w+)ZZZ"}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE neutralise PAS un parseur overlay managed=1 via son motif");
        let (pat, mgd): (String, i64) = { let c = st.db.lock(); c.query_row("SELECT pattern,managed FROM parser WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((pat.as_str(), mgd), ("user=(?P<user>\\w+)", 1), "parseur overlay INTACT : motif d'origine + managed=1");
    }

    /// (INVARIANT 3 — PLAYBOOK) editor réécrit la QUERY d'un OVERLAY managed=1 -> 403, query + managed intacts.
    /// DOUBLE garde pour un playbook : (1) l'ENUM d'actions est INTÉGRALEMENT destructif (ban/unban/kill/stop) ->
    /// l'arm-gate refuse déjà tout editor ; (2) le refus baseline `cur_managed != 2` (CHANGE 1) en défense en
    /// profondeur. action_kind='ban_ip' (valide) pour ATTEINDRE le refus (un action_kind hors-ENUM ferait un 400
    /// avant les gardes). Résultat éditeur : bloqué (403), contenu de l'overlay INTACT.
    #[tokio::test]
    async fn crud_editor_cannot_neuter_managed1_overlay_playbook() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        { let c = st.db.lock(); c.execute("INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,created_by_role) VALUES('ov-pb',1,'search severity>=4 | table src',1,'ban_ip',300,3600,1,'admin')", []).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM playbook WHERE name='ov-pb'", [], |r| r.get(0)).unwrap() };
        let (code, _v) = tok_resp_json(playbook_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"query": "search 1=0 | table src"}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE neutralise PAS un playbook overlay managed=1 via sa requête");
        let (q, mgd): (String, i64) = { let c = st.db.lock(); c.query_row("SELECT query,managed FROM playbook WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((q.as_str(), mgd), ("search severity>=4 | table src", 1), "playbook overlay INTACT : query d'origine + managed=1");
    }

    /// (INVARIANT 4 — CORRÉLATION) editor réécrit un champ d'un OVERLAY managed=1 -> 403, managed intact.
    #[tokio::test]
    async fn crud_editor_cannot_neuter_managed1_overlay_correlation() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        let steps = r#"[{"name":"s1","query":"search source=auth outcome=fail","min_count":3},{"name":"s2","query":"search source=auth outcome=success","min_count":1}]"#;
        { let c = st.db.lock(); c.execute("INSERT INTO correlation(name,enabled,key_field,entity_type,steps,window_s,interval_s,severity,mitre,risk_score,managed) VALUES('ov-corr',1,'src_ip','ip',?1,3600,300,4,'T1110',0,1)", params![steps]).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM correlation WHERE name='ov-corr'", [], |r| r.get(0)).unwrap() };
        // neuter-via-window : fenêtre à 1s rend la corrélation ininflammable.
        let (code, _v) = tok_resp_json(correlation_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"window_s": 1}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE neutralise PAS une corrélation overlay managed=1 via sa fenêtre");
        let (w, mgd): (i64, i64) = { let c = st.db.lock(); c.query_row("SELECT window_s,managed FROM correlation WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((w, mgd), (3600, 1), "corrélation overlay INTACTE : fenêtre d'origine + managed=1");
    }

    /// (INVARIANT 5 — BASELINE UEBA) editor réécrit la QUERY d'un OVERLAY managed=1 -> 403, query + managed intacts.
    #[tokio::test]
    async fn crud_editor_cannot_neuter_managed1_overlay_baseline() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        { let c = st.db.lock(); c.execute("INSERT INTO ueba_baseline(name,enabled,query,is_soql,entity_type,entity_field,value_field,bucket_s,min_samples,z_threshold,window_s,interval_s,severity,mitre,risk_score,managed) VALUES('ov-bl',1,'search source=auth | stats count by host',1,'host','host','',3600,5,3.0,604800,3600,3,'T1110',0,1)", []).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM ueba_baseline WHERE name='ov-bl'", [], |r| r.get(0)).unwrap() };
        let (code, _v) = tok_resp_json(baseline_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"query": "search 1=0 | stats count by host"}))).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "editor NE neutralise PAS une baseline overlay managed=1 via sa requête");
        let (q, mgd): (String, i64) = { let c = st.db.lock(); c.query_row("SELECT query,managed FROM ueba_baseline WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((q.as_str(), mgd), ("search source=auth | stats count by host", 1), "baseline overlay INTACTE : query d'origine + managed=1");
    }

    /// (INVARIANT 6 — NON CASSÉ) l'editor édite un CHAMP DE CONTENU (query) de SON PROPRE ad-hoc
    /// managed=2 -> 200, écriture appliquée. `cur_managed != 2` n'a PAS sur-restreint le flux légitime.
    #[tokio::test]
    async fn crud_editor_can_edit_content_of_own_managed2_rule() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        { let c = st.db.lock(); c.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('adhoc-edit',1,'search severity>=3 | stats count',1,2)", []).unwrap(); }
        let id: i64 = { let c = st.db.lock(); c.query_row("SELECT id FROM rule WHERE name='adhoc-edit'", [], |r| r.get(0)).unwrap() };
        let (code, _v) = tok_resp_json(rule_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({"query": "search severity>=5 | stats count"}))).await).await;
        assert_eq!(code, StatusCode::OK, "editor édite le contenu de SON ad-hoc managed=2 -> 200 (invariant préservé)");
        let (q, mgd): (String, i64) = { let c = st.db.lock(); c.query_row("SELECT query,managed FROM rule WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!((q.as_str(), mgd), ("search severity>=5 | stats count", 2), "édition appliquée, managed=2 conservé");
    }

    /// (HIGH-2) apply_content_overrides ne touche QUE managed=1 : un override admin pour un overlay `name=X`
    /// NE fait PAS basculer un ad-hoc editor managed=2 qui PARTAGE le même `name=X` (pas d'UNIQUE(name)).
    #[test]
    fn apply_content_overrides_scoped_to_managed1_ignores_colliding_adhoc() {
        let conn = test_db();
        // overlay managed=1 nommé 'collide' (activé) + ad-hoc managed=2 editor du MÊME nom (activé).
        conn.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('collide',1,'search severity>=3 | stats count',1,1)", []).unwrap();
        conn.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('collide',1,'search severity>=3 | stats count',1,2)", []).unwrap();
        let ov_id: i64 = conn.query_row("SELECT id FROM rule WHERE name='collide' AND managed=1", [], |r| r.get(0)).unwrap();
        let ad_id: i64 = conn.query_row("SELECT id FROM rule WHERE name='collide' AND managed=2", [], |r| r.get(0)).unwrap();
        // override ADMIN (désactive 'collide') — légitime, vise l'overlay.
        conn.execute("INSERT INTO detection_override(kind,name,enabled,updated,updated_by) VALUES('rule','collide',0,0,'alice')", []).unwrap();
        apply_content_overrides(&conn);
        let en_ov: i64 = conn.query_row("SELECT enabled FROM rule WHERE id=?1", params![ov_id], |r| r.get(0)).unwrap();
        let en_ad: i64 = conn.query_row("SELECT enabled FROM rule WHERE id=?1", params![ad_id], |r| r.get(0)).unwrap();
        assert_eq!(en_ov, 0, "overlay managed=1 : l'override admin s'applique (désactivé)");
        assert_eq!(en_ad, 1, "ad-hoc managed=2 homonyme : NON touché par l'override (scope managed=1)");
    }

    // ============================================================================================
    // T1190 (Exploit Public-Facing Application) — les DEUX règles overlay config.d/rules/t1190-*.json
    // CHARGENT (parse + SOQL compile via load_overlays_dir/rule_sql), puis TIRENT via l'ORDONNANCEUR
    // (run_due_rules, PAS le dry-run) sur de la télémétrie CIM synthétique. Calque de
    // scheduled_run_due_rules_fires_rule22_srcip_5xx_correlation (rollup.rs). Ferme l'angle mort :
    // avant, le seul signal T1190 était le seed `source=web` — INERTE (web.sh vide, CF absorbe au edge).
    // Ici : (1) blocage CrowdSec sur signature HTTP (source=crowdsec action=blocked "http") = signal qui
    // TIRE sur la télémétrie DÉJÀ EN VOL ; (2) rafale de 5xx multi-chemins (category=web, dc(path)>8) =
    // signal vendor-neutral qui TIRE dès qu'un log web/CF est branché.
    // ============================================================================================
    #[test]
    fn scheduled_run_due_rules_fires_t1190_overlay_rules() {
        // Charge les DEUX fichiers overlay RÉELS (ceux qui shippent) dans un dossier config.d temporaire.
        let src_rules = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config.d/rules");
        let dir = mk_overlay_dir("t1190");
        let rd = dir.join("rules");
        std::fs::create_dir_all(&rd).unwrap();
        for f in ["t1190-web-exploit-blocked.json", "t1190-web-exploit-5xx-burst.json"] {
            std::fs::copy(src_rules.join(f), rd.join(f)).unwrap_or_else(|e| panic!("copie overlay {f}: {e}"));
        }

        let mut path = std::env::temp_dir();
        path.push(format!("plume-t1190-{}-{}.db", std::process::id(), now()));
        let p = path.to_string_lossy().to_string();
        let t = now() - 10; // en fenêtre (window_s 900 / 1800)
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            // Chemin RÉEL de chargement des overlays (valide + compile la SOQL, pose managed=1).
            load_overlays_dir(&w, &dir);

            // Les deux règles ont chargé, managed=1, enabled=1, mitre=T1190 (preuve parse + compile).
            let (n_loaded, n_t1190): (i64, i64) = w.query_row(
                "SELECT COUNT(*), COALESCE(SUM(CASE WHEN mitre='T1190' AND enabled=1 AND managed=1 THEN 1 ELSE 0 END),0) \
                 FROM rule WHERE name IN ('Exploit web bloqué au périmètre (signature HTTP, tout vendeur)', \
                                          'Exploit web : rafale de 5xx multi-chemins par IP (tout vendeur, CIM web)')",
                [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            assert_eq!((n_loaded, n_t1190), (2, 2), "les 2 overlays T1190 chargent (compilent), enabled+managed, mitre=T1190");

            // --- Télémétrie règle 1 : blocage CrowdSec sur scénario HTTP (source=crowdsec action=blocked). ---
            for i in 0..2 {
                w.execute("INSERT INTO event(ts,source,category,severity,src_ip,message,fields,dedup) \
                    VALUES(?1,'crowdsec','network',3,'9.9.9.9','CrowdSec: crowdsecurity/http-probing (src 9.9.9.9)','{\"action\":\"blocked\"}',?2)",
                    params![t, format!("cs-http-{i}")]).unwrap();
            }
            // TÉMOIN NÉGATIF : blocage CrowdSec ssh-bruteforce -> action=blocked mais message SANS 'http'
            // -> NE DOIT PAS matcher la règle 1 (sinon last_value=2, pas 1). Sépare T1190 de T1110.
            w.execute("INSERT INTO event(ts,source,category,severity,src_ip,message,fields,dedup) \
                VALUES(?1,'crowdsec','network',3,'8.8.8.8','CrowdSec: crowdsecurity/ssh-bf (src 8.8.8.8)','{\"action\":\"blocked\"}','cs-ssh')",
                params![t]).unwrap();

            // --- Télémétrie règle 2 : rafale de 5xx sur 9 chemins DISTINCTS depuis une IP (dc(path)>8). ---
            for i in 0..9 {
                w.execute("INSERT INTO event(ts,source,category,severity,src_ip,fields,dedup) \
                    VALUES(?1,'web','web',3,'7.7.7.7',?2,?3)",
                    params![t, format!("{{\"status\":\"500\",\"path\":\"/exploit/{i}\"}}"), format!("w5-{i}")]).unwrap();
            }
            // TÉMOIN NÉGATIF : IP avec seulement 3 chemins 5xx (< seuil 8) + du 200 -> ne franchit pas dc>8.
            for i in 0..3 {
                w.execute("INSERT INTO event(ts,source,category,severity,src_ip,fields,dedup) \
                    VALUES(?1,'web','web',3,'6.6.6.6',?2,?3)",
                    params![t, format!("{{\"status\":\"500\",\"path\":\"/p{i}\"}}"), format!("w3-{i}")]).unwrap();
            }
            for i in 0..4 {
                w.execute("INSERT INTO event(ts,source,category,severity,src_ip,fields,dedup) \
                    VALUES(?1,'web','web',1,'6.6.6.6',?2,?3)",
                    params![t, format!("{{\"status\":\"200\",\"path\":\"/ok{i}\"}}"), format!("w2-{i}")]).unwrap();
            }
        }

        // L'ORDONNANCEUR (pas le dry-run) évalue et écrit les alertes.
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_due_rules(&db, &p);

        let (lv_block, lv_burst, n_t1190_alerts, sev_max): (f64, f64, i64, i64) = {
            let c = db.lock();
            let lvb: f64 = c.query_row(
                "SELECT COALESCE(last_value,-1) FROM rule WHERE name='Exploit web bloqué au périmètre (signature HTTP, tout vendeur)'",
                [], |r| r.get(0)).unwrap();
            let lvr: f64 = c.query_row(
                "SELECT COALESCE(last_value,-1) FROM rule WHERE name='Exploit web : rafale de 5xx multi-chemins par IP (tout vendeur, CIM web)'",
                [], |r| r.get(0)).unwrap();
            let (na, sv): (i64, i64) = c.query_row(
                "SELECT COUNT(*), COALESCE(MAX(severity),0) FROM alert WHERE mitre='T1190'",
                [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            (lvb, lvr, na, sv)
        };
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(lv_block, 1.0, "règle blocage HTTP : 1 IP (9.9.9.9) avec blocage http ; le ssh-bf témoin (8.8.8.8) est EXCLU (sinon 2)");
        assert_eq!(lv_burst, 1.0, "règle rafale 5xx : 1 IP (7.7.7.7) dc(path)>8 ; le témoin 6.6.6.6 (dc=3) est SOUS le seuil");
        assert_eq!(n_t1190_alerts, 2, "les DEUX règles T1190 lèvent une alerte via l'ordonnanceur (couverture T1190 fermée)");
        assert_eq!(sev_max, 4, "sévérité 4 héritée de la règle blocage d'exploit (critical)");
    }


    // ============================================================================================
    // CATALOGUE DE DÉTECTION CURÉ (#22) — starter pack vendor-agnostic sous config.d/rules/catalog/.
    // GARDE : CHAQUE règle du catalogue DOIT compiler (sinon droppée au boot = angle mort silencieux),
    // charger managed=1 et rester enabled=0 (bibliothèque : l'opérateur active par télémétrie via l'UI).
    // + 2 règles FIRENT réellement sur des events CIM synthétiques (compile-et-matche, pas juste compile).
    // ============================================================================================

    fn catalog_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config.d/rules/catalog")
    }

    /// Chaque JSON du catalogue : COMPILE via rule_sql (chemin EXACT du loader/éval), enabled=false
    /// (politique bibliothèque), is_soql=true (injection-safe par construction), MITRE valide.
    #[test]
    fn catalog_rules_all_compile_and_are_disabled_by_default() {
        let dir = catalog_dir();
        let mut names: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("config.d/rules/catalog absent").flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") { continue; }
            let txt = std::fs::read_to_string(&p).unwrap();
            let v: Value = serde_json::from_str(&txt)
                .unwrap_or_else(|e| panic!("JSON invalide {}: {e}", p.display()));
            let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
            assert!(!name.is_empty(), "catalogue {} sans name", p.display());
            assert!(name.starts_with("Catalogue —"), "nom '{name}' doit être préfixé 'Catalogue —' (unicité vs seeds)");
            let query = v.get("query").and_then(|x| x.as_str()).unwrap_or("");
            let is_soql = v.get("is_soql").and_then(|x| x.as_bool()).unwrap_or(true);
            assert!(is_soql, "catalogue '{name}' : is_soql doit être true (compilateur fermé, injection-safe)");
            let window_s = v.get("window_s").and_then(|x| x.as_i64()).unwrap_or(3600);
            // LA garde : compile via le MÊME rule_sql que le loader (une règle qui ne compile pas est droppée au boot).
            rule_sql(query, is_soql, window_s)
                .unwrap_or_else(|e| panic!("catalogue '{name}' NE COMPILE PAS : {e} — requête: {query}"));
            // Politique bibliothèque : enabled=false par défaut. EXCEPTION (v103, CHANGE 3) : la règle de
            // self-detection `content-mutated` est activée par défaut (FP quasi-nul : le contenu de détection
            // change rarement hors setup, et chaque édition DOIT être visible -> watcher par-édition).
            let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true);
            let is_self_detect = name.contains("modification du contenu de détection");
            if is_self_detect {
                assert!(enabled, "catalogue '{name}' (self-detection contenu) doit être enabled=true (v103)");
            } else {
                assert!(!enabled, "catalogue '{name}' doit être enabled=false (bibliothèque activée par l'opérateur)");
            }
            // MITRE valide (Txxxx[.yyy]) — sinon la couverture ATT&CK ne s'allume pas.
            let mitre = v.get("mitre").and_then(|x| x.as_str()).unwrap_or("");
            assert!(norm_mitre(mitre).is_some() && !mitre.is_empty(), "catalogue '{name}' : MITRE '{mitre}' invalide");
            names.push(name);
        }
        names.sort();
        names.dedup();
        assert!(names.len() >= 30, "catalogue attendu >= 30 règles, trouvé {}", names.len());

        // CHARGEMENT RÉEL via load_overlays_dir (chemin boot) : chaque règle -> rule managed=1, enabled=0.
        let conn = test_db();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config.d");
        load_overlays_dir(&conn, &root);
        for name in &names {
            let (managed, enabled): (i64, i64) = conn.query_row(
                "SELECT managed, enabled FROM rule WHERE name=?1", params![name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ).unwrap_or_else(|_| panic!("règle catalogue '{name}' ABSENTE après load (a-t-elle compilé ?)"));
            // v103 CHANGE 3 : la self-detection `content-mutated` charge enabled=1 ; le reste enabled=0.
            let want_enabled = if name.contains("modification du contenu de détection") { 1 } else { 0 };
            assert_eq!((managed, enabled), (1, want_enabled), "catalogue '{name}' : attendu managed=1 enabled={want_enabled}");
        }
        // Le compte chargé (managed=1) couvre AU MOINS le catalogue (les overlays racine sont en plus).
        let loaded_cat: i64 = conn.query_row(
            "SELECT COUNT(*) FROM rule WHERE managed=1 AND name LIKE 'Catalogue —%'", [], |r| r.get(0),
        ).unwrap();
        assert_eq!(loaded_cat as usize, names.len(), "toutes les règles catalogue chargées managed=1");
    }

    /// FIRE : 2 règles du catalogue rendent un scalaire > 0 sur des events CIM synthétiques (donc
    /// alerteraient avec op '>' threshold 0), et une variante SOUS le seuil ne tire PAS (anti-faux-positif).
    #[test]
    fn catalog_rules_fire_on_synthetic_cim_events() {
        let conn = test_db();
        // (1) Brute-force login web : 21 réponses 401 depuis la même IP -> 1 groupe > 20 -> fire.
        for i in 0..21 {
            store().insert_event(&conn, &EventRow {
                ts: 1000 + i, source: "web".into(), category: "web".into(), severity: 2,
                message: "GET /login 401".into(), src_ip: Some("9.9.9.9".into()),
                fields: Some(r#"{"status":"401"}"#.into()), dedup: Some(format!("web401-{i}")),
                ..Default::default()
            }).unwrap();
        }
        // Une IP différente avec seulement 5 x 401 : NE doit PAS pousser le groupe au-dessus du seuil.
        for i in 0..5 {
            store().insert_event(&conn, &EventRow {
                ts: 1000 + i, source: "web".into(), category: "web".into(), severity: 2,
                message: "GET /login 401".into(), src_ip: Some("8.8.8.8".into()),
                fields: Some(r#"{"status":"401"}"#.into()), dedup: Some(format!("web401b-{i}")),
                ..Default::default()
            }).unwrap();
        }
        let q_web = "search source=web status=401 | stats count by src_ip | where count > 20 | stats count";
        let sql = soql_to_sql_x(q_web, 0, 0, None).unwrap();
        let n: i64 = conn.query_row(&sql, [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "brute-force web : exactement l'IP à 21 x 401 franchit le seuil (l'IP à 5 ne tire pas)");

        // (2) Alerte IDS Suricata haute-sévérité : 1 event category=alert sev4 -> fire.
        store().insert_event(&conn, &EventRow {
            ts: 1001, source: "suricata".into(), category: "alert".into(), severity: 4,
            message: "ET EXPLOIT ... [1:2000000]".into(), dedup: Some("suri-1".into()),
            ..Default::default()
        }).unwrap();
        let q_ids = "search source=suricata category=alert severity>=3 | stats count";
        let sql2 = soql_to_sql_x(q_ids, 0, 0, None).unwrap();
        let n2: i64 = conn.query_row(&sql2, [], |r| r.get(0)).unwrap();
        assert!(n2 >= 1, "alerte IDS Suricata sev>=3 : la règle catalogue tire (count={n2})");
    }

    /// FIX v103 CHANGE 3 — la self-detection `content-mutated`, ACTIVÉE par défaut, TIRE réellement sur les
    /// audits de mutation de contenu de détection (config.rule.* / config.parser.* -> fields.kind rule/parser)
    /// et NE tire PAS sur les autres events de config (kind=user/notifier…) ni au repos. Prouve que la query
    /// N'EST PLUS INERTE (l'ancienne `action=config.rule.*` ne matchait rien : ces events ne portent pas
    /// fields.action). C'est le vrai chemin d'audit : audit_config_change écrit source=plume-config category=config.
    #[test]
    fn content_mutated_rule_fires_on_rule_and_parser_audits_only() {
        let conn = test_db();
        // La query EXACTE du catalogue (chargée telle quelle par le loader).
        let q = "search source=plume-config category=config kind in (rule,parser) | stats count";
        let sql = soql_to_sql_x(q, 0, 0, None).unwrap();
        // Au repos : aucun event config -> 0.
        let n0: i64 = conn.query_row(&sql, [], |r| r.get(0)).unwrap();
        assert_eq!(n0, 0, "au repos (aucune mutation de détection) -> ne tire pas");
        // Chemin d'audit RÉEL : audit_config_change pose source=plume-config, category=config, fields=... .
        audit_config_change(&conn, "config.rule.update", "règle #1 modifiée", 2, "règle #1 modifiée",
            &json!({ "op": "update", "kind": "rule", "id": 1, "actor": "mallory" }).to_string()).unwrap();
        audit_config_change(&conn, "config.parser.update", "parseur #2 modifié", 2, "parseur #2 modifié",
            &json!({ "op": "update", "kind": "parser", "id": 2, "actor": "mallory" }).to_string()).unwrap();
        // Bruit : une mutation d'IDENTITÉ (kind=user) NE doit PAS être comptée par CETTE règle (couverte par C1).
        audit_config_change(&conn, "config.user.create", "compte créé", 4, "compte créé",
            &json!({ "action": "config.user.create", "kind": "user", "target": "x", "actor": "mallory" }).to_string()).unwrap();
        let n: i64 = conn.query_row(&sql, [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2, "tire sur les 2 mutations de contenu de détection (rule+parser), ignore kind=user");
        // Preuve d'INERTIE de l'ancienne query : `action=config.rule.*` ne matche RIEN (pas de fields.action).
        let old_q = "search source=plume-config action=config.rule.* | stats count";
        let old_sql = soql_to_sql_x(old_q, 0, 0, None).unwrap();
        let n_old: i64 = conn.query_row(&old_sql, [], |r| r.get(0)).unwrap();
        assert_eq!(n_old, 0, "l'ANCIENNE query (action=config.rule.*) était INERTE : 0 malgré 2 mutations de règle/parser");
    }

    /// FIX v103 CHANGE 6 — le seed purple 5xx (T1190, `source=web status>=500`, id 22 en prod) est DÉSORMAIS
    /// seedé enabled=0 (doublon de l'overlay id 89 `category=web status>=500`, un SUR-ENSEMBLE). Les DEUX autres
    /// règles purple restent enabled=1 : 404-par-IP (T1595.002, id 21, COMPLÉMENTAIRE de l'edge CF) et port-scan
    /// UFW (T1046). Git-durable : une base neuve ne re-crée PAS le doublon activé.
    #[test]
    fn seed_purple_5xx_rule_disabled_others_enabled() {
        let conn = test_db();
        seed_purple_rules(&conn);
        let en_5xx: i64 = conn.query_row(
            "SELECT enabled FROM rule WHERE name='Anomalie exploit web : pic de 5xx par IP (10 min)'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(en_5xx, 0, "seed 5xx (T1190, id 22) DÉSACTIVÉ — doublon de l'overlay 5xx category=web (id 89)");
        let en_404: i64 = conn.query_row(
            "SELECT enabled FROM rule WHERE name='Web-scan : pic de 404 par IP (10 min)'",
            [], |r| r.get(0)).unwrap();
        let en_ufw: i64 = conn.query_row(
            "SELECT enabled FROM rule WHERE name='Port-scan entrant (UFW, 10 min)'",
            [], |r| r.get(0)).unwrap();
        assert_eq!((en_404, en_ufw), (1, 1), "404 (id 21, complémentaire edge CF) et port-scan UFW restent activés");
    }

    // ============================================================================================
    // RÉTENTION GFS À PALIERS — `backup_prune_plan` (logique de sélection PURE, aucun S3).
    // Voir daemon/src/backup.rs (section GFS) : paliers dense/daily/weekly + premigrate keep-N,
    // invariants fail-safe (jamais le plus récent, keep-si-non-parseable, vide->vide, idempotent).
    // ============================================================================================

    /// Inverse de `days_from_civil` (Hinnant `civil_from_days`) — jours Unix -> (année, mois, jour) UTC.
    /// Utilisé UNIQUEMENT par les tests pour SYNTHÉTISER des noms de backup à des instants précis.
    fn gfs_civil_from_days(z: i64) -> (i64, i64, i64) {
        let z = z + 719468;
        let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
        let doe = z - era * 146097;                                  // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);          // [0, 365]
        let mp = (5 * doy + 2) / 153;                                // [0, 11]
        let d = doy - (153 * mp + 2) / 5 + 1;                        // [1, 31]
        let m = if mp < 10 { mp + 3 } else { mp - 9 };              // [1, 12]
        (if m <= 2 { y + 1 } else { y }, m, d)
    }

    /// Formate des secondes Unix en horodatage `YYYYMMDDTHHMMSSZ` (UTC) — miroir exact de
    /// `date -u +%Y%m%dT%H%M%SZ`. Round-trip garanti avec `parse_backup_ts`.
    fn gfs_fmt_ts(secs: i64) -> String {
        let days = secs.div_euclid(86400);
        let rem = secs.rem_euclid(86400);
        let (y, m, d) = gfs_civil_from_days(days);
        format!("{:04}{:02}{:02}T{:02}{:02}{:02}Z", y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
    }

    fn gfs_reg(secs: i64) -> String { format!("plume-{}.db.age", gfs_fmt_ts(secs)) }
    fn gfs_premig(sha: &str, secs: i64) -> String { format!("premigrate-{}-{}.db.age", sha, gfs_fmt_ts(secs)) }

    /// Le formateur de test et le parseur de prod font un round-trip exact (pré-condition des autres tests).
    #[test]
    fn gfs_ts_roundtrip_fmt_parse() {
        // 2026-07-16T12:34:56Z + quelques dates limites.
        for &(y, m, d, h, mi, s) in &[
            (2026, 7, 16, 12, 34, 56), (1970, 1, 1, 0, 0, 0), (2000, 2, 29, 23, 59, 59),
            (2024, 12, 31, 1, 2, 3), (2026, 1, 1, 0, 0, 0),
        ] {
            let secs = crate::backup::days_from_civil(y, m, d) * 86400 + h * 3600 + mi * 60 + s;
            let ts = gfs_fmt_ts(secs);
            assert_eq!(crate::backup::parse_backup_ts(&ts), Some(secs), "round-trip {ts}");
            assert_eq!(ts.len(), 16, "TS long de 16 chars");
        }
    }

    /// SYNTHÈSE 0..120 jours à cadence 2h : assert le keep-set exact (tous < DENSE présents, exactement
    /// 1/jour dans le palier DAILY, 1/semaine ISO dans le palier WEEKLY, aucun > WEEKLY) + le plus récent
    /// TOUJOURS gardé. Le keep attendu est recalculé par un ORACLE indépendant (méthode naïve).
    #[test]
    fn gfs_regular_tiers_keep_set() {
        let p = crate::backup::GfsParams { dense_days: 2, daily_days: 14, weekly_days: 90, premigrate_keep: 2 };
        // now = 2026-07-16T12:00:00Z (midi, aligné) -> les âges tombent nettement dans les paliers.
        let now = crate::backup::days_from_civil(2026, 7, 16) * 86400 + 12 * 3600;
        let step = 7200; // 2h
        // objets d'âge 0 à 120 jours (inclus), cadence 2h.
        let mut all_secs: Vec<i64> = Vec::new();
        let mut t = now;
        while now - t <= 120 * 86400 { all_secs.push(t); t -= step; }
        let names: Vec<String> = all_secs.iter().map(|&s| gfs_reg(s)).collect();

        let plan = crate::backup::backup_prune_plan(&names, now, &p);
        let plan_set: std::collections::HashSet<&String> = plan.iter().collect();
        let keep: std::collections::HashSet<String> =
            names.iter().filter(|n| !plan_set.contains(n)).cloned().collect();

        // --- ORACLE indépendant du keep attendu ---
        use std::collections::{HashMap, HashSet};
        let (dense, daily, weekly) = (2 * 86400, 14 * 86400, 90 * 86400);
        let mut expected: HashSet<String> = HashSet::new();
        expected.insert(gfs_reg(now)); // le plus récent (âge 0) — garde inconditionnelle.
        let mut day_max: HashMap<i64, i64> = HashMap::new();
        let mut week_max: HashMap<i64, i64> = HashMap::new();
        for &s in &all_secs {
            let age = now - s;
            if age < dense { expected.insert(gfs_reg(s)); }
            else if age < daily { let e = day_max.entry(crate::backup::day_key(s)).or_insert(s); if s > *e { *e = s; } }
            else if age < weekly { let e = week_max.entry(crate::backup::week_key(s)).or_insert(s); if s > *e { *e = s; } }
            // age >= weekly -> jeté
        }
        for (_, s) in &day_max { expected.insert(gfs_reg(*s)); }
        for (_, s) in &week_max { expected.insert(gfs_reg(*s)); }

        assert_eq!(keep, expected, "keep-set doit correspondre à l'oracle GFS");

        // --- assertions ciblées explicites ---
        // (1) le plus récent JAMAIS supprimé.
        assert!(!plan_set.contains(&gfs_reg(now)), "INVARIANT 1 : le backup le plus récent n'est jamais supprimé");
        // (2) tous les objets d'âge < 2j présents (24 objets à 2h : âges 0h..46h).
        let dense_kept = all_secs.iter().filter(|&&s| now - s < dense).count();
        assert_eq!(dense_kept, 24, "24 objets dans la fenêtre dense 2j @2h");
        for &s in all_secs.iter().filter(|&&s| now - s < dense) {
            assert!(keep.contains(&gfs_reg(s)), "objet dense {} gardé", gfs_fmt_ts(s));
        }
        // (3) palier DAILY : exactement 1 par jour civil, et c'est le MAX de ce jour.
        for (&dk, &smax) in &day_max {
            let kept_that_day: Vec<i64> = all_secs.iter().copied()
                .filter(|&s| { let a = now - s; a >= dense && a < daily && crate::backup::day_key(s) == dk })
                .filter(|&s| keep.contains(&gfs_reg(s))).collect();
            assert_eq!(kept_that_day, vec![smax], "exactement le dernier du jour {dk} gardé");
        }
        // (4) palier WEEKLY : exactement 1 par semaine ISO, et c'est le MAX de la semaine.
        for (&wk, &smax) in &week_max {
            let kept_that_week: Vec<i64> = all_secs.iter().copied()
                .filter(|&s| { let a = now - s; a >= daily && a < weekly && crate::backup::week_key(s) == wk })
                .filter(|&s| keep.contains(&gfs_reg(s))).collect();
            assert_eq!(kept_that_week, vec![smax], "exactement le dernier de la semaine {wk} gardé");
        }
        // (5) aucun objet d'âge >= 90j gardé.
        for &s in all_secs.iter().filter(|&&s| now - s >= weekly) {
            assert!(!keep.contains(&gfs_reg(s)), "objet > weekly {} supprimé", gfs_fmt_ts(s));
        }
        // (6) comptes de paliers sains (borne l'objectif « ~47 objets » du scope).
        assert!(day_max.len() >= 10 && day_max.len() <= 13, "≈12 points quotidiens (2..14j), obtenu {}", day_max.len());
        assert!(week_max.len() >= 9 && week_max.len() <= 12, "≈11 points hebdo (14..90j), obtenu {}", week_max.len());
    }

    /// PREMIGRATE : garde les 2 plus récents par TS, supprime le reste ; le plus récent jamais supprimé.
    /// Les noms portent des <sha> variés (dont un absent = cas du scope) -> le routage est par TS, pas par SHA.
    #[test]
    fn gfs_premigrate_keep_2() {
        let p = crate::backup::GfsParams { dense_days: 2, daily_days: 14, weekly_days: 90, premigrate_keep: 2 };
        let now = crate::backup::days_from_civil(2026, 7, 16) * 86400 + 12 * 3600;
        let d = 86400;
        // du plus vieux au plus récent : c14 (3j), e33 (2j), b9c (1j), c8f (12h), ace (1h).
        let items = [
            ("c14c8e9", now - 3 * d), ("e332a2d", now - 2 * d), ("b9c4aa0", now - d),
            ("c8f393a", now - 3600 * 12), ("acecda2", now - 3600),
        ];
        let names: Vec<String> = items.iter().map(|&(sha, s)| gfs_premig(sha, s)).collect();
        let plan = crate::backup::backup_prune_plan(&names, now, &p);
        let plan_set: std::collections::HashSet<&String> = plan.iter().collect();
        // gardés : les 2 plus récents (acecda2, c8f393a) ; supprimés : les 3 plus vieux.
        assert!(!plan_set.contains(&gfs_premig("acecda2", now - 3600)), "le plus récent jamais supprimé");
        assert!(!plan_set.contains(&gfs_premig("c8f393a", now - 3600 * 12)), "le 2e plus récent gardé");
        assert!(plan_set.contains(&gfs_premig("b9c4aa0", now - d)), "3e plus récent supprimé");
        assert!(plan_set.contains(&gfs_premig("e332a2d", now - 2 * d)), "supprimé");
        assert!(plan_set.contains(&gfs_premig("c14c8e9", now - 3 * d)), "supprimé");
        assert_eq!(plan.len(), 3, "keep-2 sur 5 -> 3 supprimés");
    }

    /// Régulier ET premigrate mélangés dans une même entrée -> pruned indépendamment, les 2 « plus récents »
    /// (un par set) restent intouchés. Prouve que le sous-command tolère un flux combiné.
    #[test]
    fn gfs_mixed_regular_and_premigrate() {
        let p = crate::backup::GfsParams { dense_days: 2, daily_days: 14, weekly_days: 90, premigrate_keep: 2 };
        let now = crate::backup::days_from_civil(2026, 7, 16) * 86400 + 12 * 3600;
        let d = 86400;
        let mut names = vec![
            gfs_reg(now), gfs_reg(now - d), gfs_reg(now - 100 * d),   // dense, daily, >weekly(supprimé)
            gfs_premig("aaa", now - 3600), gfs_premig("bbb", now - 5 * d), gfs_premig("ccc", now - 6 * d),
        ];
        // clé complète avec préfixe de sous-répertoire -> routée par base-name.
        names.push(format!("premigrate/{}", gfs_premig("ddd", now - 7 * d)));
        let plan = crate::backup::backup_prune_plan(&names, now, &p);
        let ps: std::collections::HashSet<&String> = plan.iter().collect();
        assert!(!ps.contains(&gfs_reg(now)), "régulier le plus récent gardé");
        assert!(ps.contains(&gfs_reg(now - 100 * d)), "régulier > weekly supprimé");
        assert!(!ps.contains(&gfs_premig("aaa", now - 3600)), "premigrate le plus récent gardé");
        assert!(ps.contains(&gfs_premig("ccc", now - 6 * d)), "3e premigrate supprimé (keep-2)");
        assert!(ps.contains(&format!("premigrate/{}", gfs_premig("ddd", now - 7 * d))), "clé complète routée + supprimée");
    }

    /// Un nom NON parseable (format inconnu OU TS invalide) n'est JAMAIS émis pour suppression (INVARIANT 3).
    #[test]
    fn gfs_unparseable_kept() {
        let p = crate::backup::GfsParams { dense_days: 2, daily_days: 14, weekly_days: 90, premigrate_keep: 2 };
        let now = crate::backup::days_from_civil(2026, 7, 16) * 86400 + 12 * 3600;
        let names = vec![
            "README.md".to_string(),
            "plume-notatimestamp.db.age".to_string(),          // préfixe OK, TS invalide
            "plume-20261301T000000Z.db.age".to_string(),        // mois 13 -> invalide
            "plume-20260716T250000Z.db.age".to_string(),        // heure 25 -> invalide
            "premigrate-sha-BADTS.db.age".to_string(),          // premigrate TS invalide
            "plume-.db.age".to_string(),                        // TS vide
            "".to_string(),                                     // vide (filtré côté CLI, ignoré ici)
            gfs_reg(now - 200 * 86400),                          // un VRAI vieux régulier -> lui SERA supprimé
            gfs_reg(now),                                        // le plus récent
        ];
        let plan = crate::backup::backup_prune_plan(&names, now, &p);
        let ps: std::collections::HashSet<&String> = plan.iter().collect();
        for bad in ["README.md", "plume-notatimestamp.db.age", "plume-20261301T000000Z.db.age",
                    "plume-20260716T250000Z.db.age", "premigrate-sha-BADTS.db.age", "plume-.db.age", ""] {
            assert!(!ps.contains(&bad.to_string()), "nom non parseable jamais supprimé : {bad}");
        }
        assert!(ps.contains(&gfs_reg(now - 200 * 86400)), "un VRAI régulier trop vieux est bien supprimé");
        assert!(!ps.contains(&gfs_reg(now)), "le plus récent gardé");
    }

    /// Entrée vide -> sortie vide (INVARIANT 4).
    #[test]
    fn gfs_empty_input_empty_output() {
        let p = crate::backup::GfsParams { dense_days: 2, daily_days: 14, weekly_days: 90, premigrate_keep: 2 };
        let now = crate::backup::days_from_civil(2026, 7, 16) * 86400 + 12 * 3600;
        assert!(crate::backup::backup_prune_plan(&[], now, &p).is_empty());
        // liste 100% non parseable -> plan vide.
        let junk = vec!["a".to_string(), "b.txt".to_string(), "plume-x.db.age".to_string()];
        assert!(crate::backup::backup_prune_plan(&junk, now, &p).is_empty(), "aucun objet parseable -> rien à supprimer");
    }

    /// IDEMPOTENCE (INVARIANT 5) : rejouer le plan sur (entrée - plan) -> plan vide. Régulier + premigrate.
    #[test]
    fn gfs_idempotent() {
        let p = crate::backup::GfsParams { dense_days: 2, daily_days: 14, weekly_days: 90, premigrate_keep: 2 };
        let now = crate::backup::days_from_civil(2026, 7, 16) * 86400 + 12 * 3600;
        let step = 7200;
        let mut names: Vec<String> = Vec::new();
        let mut t = now;
        while now - t <= 120 * 86400 { names.push(gfs_reg(t)); t -= step; }
        for (i, &off) in [3600i64, 43200, 86400, 3 * 86400, 6 * 86400].iter().enumerate() {
            names.push(gfs_premig(&format!("sha{i:02x}"), now - off));
        }
        let plan1 = crate::backup::backup_prune_plan(&names, now, &p);
        assert!(!plan1.is_empty(), "1er passage supprime des objets");
        let plan1_set: std::collections::HashSet<&String> = plan1.iter().collect();
        let survivors: Vec<String> = names.iter().filter(|n| !plan1_set.contains(n)).cloned().collect();
        let plan2 = crate::backup::backup_prune_plan(&survivors, now, &p);
        assert!(plan2.is_empty(), "IDEMPOTENT : rejouer sur les survivants ne supprime plus rien (obtenu {plan2:?})");
    }

    /// ENV-TUNABLE : DENSE_DAYS 2 -> 1 rétrécit le palier dense (12 objets @2h de moins gardés en dense).
    /// Prouvé au niveau de la LOGIQUE (GfsParams construit) — from_env() ne fait que env->struct.
    #[test]
    fn gfs_dense_days_tunable() {
        let now = crate::backup::days_from_civil(2026, 7, 16) * 86400 + 12 * 3600;
        let step = 7200;
        let mut names: Vec<String> = Vec::new();
        let mut secs: Vec<i64> = Vec::new();
        let mut t = now;
        while now - t <= 30 * 86400 { names.push(gfs_reg(t)); secs.push(t); t -= step; }

        let count_dense_kept = |dense_days: i64| -> usize {
            let p = crate::backup::GfsParams { dense_days, daily_days: 14, weekly_days: 90, premigrate_keep: 2 };
            let plan = crate::backup::backup_prune_plan(&names, now, &p);
            let ps: std::collections::HashSet<&String> = plan.iter().collect();
            // objets d'âge < dense_days encore présents (= palier dense).
            secs.iter().filter(|&&s| now - s < dense_days * 86400)
                .filter(|&&s| !ps.contains(&gfs_reg(s))).count()
        };
        let dense2 = count_dense_kept(2);
        let dense1 = count_dense_kept(1);
        assert_eq!(dense2, 24, "DENSE=2j @2h -> 24 objets denses");
        assert_eq!(dense1, 12, "DENSE=1j @2h -> 12 objets denses (palier rétréci)");
        assert!(dense1 < dense2, "réduire DENSE_DAYS rétrécit bien le palier dense");
    }

    /// Départage DÉTERMINISTE : deux objets au MÊME TS dans le palier daily -> le nom lexicographiquement
    /// le plus grand est retenu ; le plan est stable entre deux exécutions (déterminisme, INVARIANT 6).
    #[test]
    fn gfs_deterministic_tiebreak() {
        let p = crate::backup::GfsParams { dense_days: 2, daily_days: 14, weekly_days: 90, premigrate_keep: 2 };
        let now = crate::backup::days_from_civil(2026, 7, 16) * 86400 + 12 * 3600;
        // deux objets même TS (âge 5j, palier daily) mais noms différents — construits à la main.
        let ts = gfs_fmt_ts(now - 5 * 86400);
        let a = format!("plume-{ts}.db.age");
        // un doublon lexicographiquement plus petit : préfixe alternatif de clé complète -> même base-name !
        // pour un VRAI départage, on force deux base-names distincts au même instant en variant d'1s.
        let b = format!("plume-{}.db.age", gfs_fmt_ts(now - 5 * 86400 + 1));
        let names = vec![a.clone(), b.clone(), gfs_reg(now)];
        let plan1 = crate::backup::backup_prune_plan(&names, now, &p);
        let plan2 = crate::backup::backup_prune_plan(&names, now, &p);
        assert_eq!(plan1, plan2, "plan déterministe entre deux exécutions");
        // le plus grand TS du jour (b, +1s) gagne -> a supprimé, b gardé.
        let ps: std::collections::HashSet<&String> = plan1.iter().collect();
        assert!(ps.contains(&a) && !ps.contains(&b), "le dernier du jour (TS max) est retenu");
    }

    // ========================================================================================
    // OPS NATIVE — SCHEDULER DE BACKUP IN-DAEMON (portable host/Docker). Voir server.rs
    // (spawn_backup_scheduler / scheduled_backup_cycle) + backup.rs (fmt_backup_ts /
    // backup_keep_recent_plan). Preuves : (1) fmt inverse EXACT de parse ; (2) rétention KEEP-N
    // pure + fail-safe ; (3) OFF-par-défaut = aucune tâche/aucun disque touché ; (4) un cycle du
    // scheduler écrit un .age B1 valide + restore fidèle + rétention effective.
    // ========================================================================================

    /// (1) `fmt_backup_ts` est l'INVERSE EXACT de `parse_backup_ts` (le scheduler nomme, la rétention parse).
    #[test]
    fn native_fmt_backup_ts_roundtrip() {
        for &(y, m, d, h, mi, s) in &[
            (2026, 7, 16, 12, 34, 56), (1970, 1, 1, 0, 0, 0), (2000, 2, 29, 23, 59, 59),
            (2024, 12, 31, 1, 2, 3), (2026, 1, 1, 0, 0, 0),
        ] {
            let secs = crate::backup::days_from_civil(y, m, d) * 86400 + h * 3600 + mi * 60 + s;
            let ts = crate::backup::fmt_backup_ts(secs);
            assert_eq!(ts.len(), crate::backup::BACKUP_TS_LEN, "TS long de 16 chars");
            assert_eq!(crate::backup::parse_backup_ts(&ts), Some(secs), "fmt/parse round-trip {ts}");
            // parité EXACTE avec le formateur du sidecar shell (gfs_fmt_ts = `date -u +%Y%m%dT%H%M%SZ`).
            assert_eq!(ts, gfs_fmt_ts(secs), "fmt_backup_ts == date -u +%Y%m%dT%H%M%SZ");
        }
    }

    /// (2) Rétention KEEP-N PURE : garde exactement les N plus récents, supprime les plus vieux, et FAIL-SAFE
    /// (jamais un non-parseable / un premigrate / le plus récent ; keep=0 traité comme keep=1 ; <=N -> vide).
    #[test]
    fn native_keep_recent_plan_semantics() {
        let base = crate::backup::days_from_civil(2026, 7, 16) * 86400 + 12 * 3600;
        // 5 réguliers espacés d'1h (t0 le plus vieux .. t4 le plus récent).
        let regs: Vec<String> = (0..5).map(|i| gfs_reg(base + i * 3600)).collect();
        // KEEP=2 -> supprime les 3 plus vieux (t0,t1,t2), garde t3,t4.
        let plan = crate::backup::backup_keep_recent_plan(&regs, 2);
        let del: std::collections::HashSet<&String> = plan.iter().collect();
        assert_eq!(plan.len(), 3, "KEEP=2 sur 5 -> 3 supprimés");
        assert!(del.contains(&regs[0]) && del.contains(&regs[1]) && del.contains(&regs[2]), "les 3 plus vieux");
        assert!(!del.contains(&regs[3]) && !del.contains(&regs[4]), "les 2 plus récents GARDÉS");
        // entrée <= keep -> vide ; keep=0 borné à 1 (jamais tout supprimer).
        assert!(crate::backup::backup_keep_recent_plan(&regs, 5).is_empty(), "5<=keep -> rien à supprimer");
        assert!(crate::backup::backup_keep_recent_plan(&regs, 10).is_empty(), ">keep -> rien");
        assert_eq!(crate::backup::backup_keep_recent_plan(&regs, 0).len(), 4, "keep=0 traité comme keep=1");
        assert!(crate::backup::backup_keep_recent_plan(&[], 3).is_empty(), "vide -> vide");
        // FAIL-SAFE : non-parseables (dont le `.tmp` d'un backup en vol) + premigrate JAMAIS supprimés.
        let mut mixed = regs.clone();
        mixed.push(".plume-INPROGRESS.db.age.tmp.4242".to_string()); // temp en cours de rename
        mixed.push("garbage-name.txt".to_string());
        mixed.push(gfs_premig("abc1234", base + 10 * 3600)); // premigrate hors périmètre
        let plan2 = crate::backup::backup_keep_recent_plan(&mixed, 1);
        for name in &plan2 {
            assert!(name.starts_with("plume-") && name.ends_with(".db.age"),
                "seul un backup RÉGULIER peut être supprimé (jamais tmp/garbage/premigrate) : {name}");
        }
        // avec KEEP=1 sur 5 réguliers -> 4 réguliers supprimés, le reste intact.
        assert_eq!(plan2.len(), 4, "KEEP=1 supprime 4 réguliers, ignore tmp/garbage/premigrate");
    }

    /// (3) OFF-PAR-DÉFAUT = INCHANGÉ : sans `PLUME_BACKUP_INTERVAL` / `PLUME_AUTOVACUUM_INTERVAL`, les spawns
    /// RETOURNENT immédiatement — aucun thread, aucun répertoire de backup créé, aucune requête sur la base.
    #[test]
    fn native_ops_off_by_default_no_effect() {
        let dest = mk_tmp_path("sched-off-dest");
        let mut conf = std::collections::HashMap::new();
        conf.insert("PLUME_BACKUP_DEST".to_string(), dest.clone()); // DEST posé MAIS interval absent -> inerte.
        // PLUME_BACKUP_INTERVAL / PLUME_AUTOVACUUM_INTERVAL ABSENTS (env de test propre) -> désactivés.
        assert!(std::env::var("PLUME_BACKUP_INTERVAL").is_err(), "pré-condition : interval non posé");
        assert!(std::env::var("PLUME_AUTOVACUUM_INTERVAL").is_err(), "pré-condition : autovacuum non posé");
        crate::server::spawn_backup_scheduler(conf.clone(), "/nonexistent/plume.db".to_string());
        // autovacuum OFF : on lui passe une base bidon ; s'il spawnait il paniquerait au lock -> il ne DOIT PAS.
        let dummy = std::sync::Arc::new(parking_lot::Mutex::new(
            rusqlite::Connection::open_in_memory().unwrap()));
        crate::server::spawn_autovacuum_loop(conf, dummy);
        std::thread::sleep(std::time::Duration::from_millis(250));
        assert!(!std::path::Path::new(&dest).exists(),
            "OFF par défaut : le scheduler n'a créé AUCUN répertoire de backup ({dest})");
    }

    /// (4) UN CYCLE du scheduler natif = backup B1 -> rename atomique -> rétention KEEP-N, PROUVÉ de bout en
    /// bout : (a) écrit exactement UN `plume-<TS>.db.age` canonique (aucun `.tmp` résiduel) ; (b) chiffré age
    /// (aucun plaintext lisible) ; (c) RESTORE fidèle (mêmes events/parsers/schema_version) ; (d) rétention
    /// KEEP-N effective (les anciens backups synthétiques en trop sont supprimés).
    #[test]
    fn native_scheduler_cycle_roundtrip_and_retention() {
        let key = "test-native-scheduler-passphrase-xyzzy";
        let marker = "NATIVE_SCHED_MARKER_5Z";
        let src = mk_tmp_path("sched-src.db");
        let dest_dir = mk_tmp_path("sched-dest");
        std::fs::create_dir_all(&dest_dir).unwrap();
        const N: i64 = 1500;

        // --- base source SQLCipher réelle (schéma + migrate + N events connus) ---
        let (orig_events, orig_parsers, orig_schema): (i64, i64, String);
        {
            let conn = open_db_keyed(&src, Some(key)).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&conn);
            conn.execute_batch("BEGIN;").unwrap();
            for i in 0..N {
                conn.execute(
                    "INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,'sshd','auth',3,'host-a',?2,'{}')",
                    params![now(), format!("{marker} n={i}")],
                ).unwrap();
            }
            conn.execute_batch("COMMIT;").unwrap();
            orig_events = conn.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
            orig_parsers = conn.query_row("SELECT COUNT(*) FROM parser", [], |r| r.get(0)).unwrap();
            orig_schema = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
            assert_eq!(orig_events, N);
        }

        // --- SEED de rétention : 3 vieux backups RÉGULIERS synthétiques (contenu bidon, noms valides) ---
        let old_base = crate::backup::days_from_civil(2020, 1, 1) * 86400;
        for i in 0..3 {
            let name = format!("plume-{}.db.age", crate::backup::fmt_backup_ts(old_base + i * 3600));
            std::fs::write(format!("{dest_dir}/{name}"), b"OLD-DUMMY").unwrap();
        }

        // --- UN CYCLE (clé passée explicitement, hermétique ; recipient=None = symétrique) avec KEEP=2 ---
        crate::server::scheduled_backup_cycle(&src, &dest_dir, 2, Some(key), None);

        // (a) exactement UN backup canonique produit ; ZÉRO fichier `.tmp` résiduel.
        let entries: Vec<String> = std::fs::read_dir(&dest_dir).unwrap()
            .filter_map(|e| e.ok()).filter_map(|e| e.file_name().into_string().ok()).collect();
        let canon: Vec<&String> = entries.iter()
            .filter(|n| n.starts_with("plume-") && n.ends_with(".db.age")).collect();
        assert!(entries.iter().all(|n| !n.contains(".tmp.")), "aucun fichier .tmp résiduel : {entries:?}");
        // (d) rétention KEEP=2 : 3 vieux + 1 nouveau = 4 réguliers -> il en reste EXACTEMENT 2 (les plus récents).
        assert_eq!(canon.len(), 2, "KEEP=2 : 2 backups réguliers conservés (le neuf + le plus récent vieux) : {entries:?}");
        // le backup FRAIS (TS d'aujourd'hui > 2020) DOIT survivre ; les 2 plus vieux de 2020 supprimés.
        let fresh = canon.iter().find(|n| !n.contains("20200101")).expect("le backup frais est conservé");
        let fresh_path = format!("{dest_dir}/{fresh}");

        // (b) chiffré : aucun plaintext (marqueur / en-tête SQLite) lisible ; en-tête age présent.
        let bytes = std::fs::read(&fresh_path).unwrap();
        assert!(!bytes_contain(&bytes, marker.as_bytes()), "le marqueur ne fuit PAS en clair");
        assert!(!bytes_contain(&bytes, b"SQLite format 3"), "en-tête SQLite absent en clair");
        assert!(bytes_contain(&bytes, b"age-encryption.org"), "conteneur age présent");

        // (c) RESTORE fidèle -> DB identique (events/parsers/schema + contenu marqueur).
        let restored = mk_tmp_path("sched-restored.db");
        restore_compressed(&fresh_path, &restored, Some(key), true, None).expect("restore du backup du scheduler");
        {
            let r = open_db_keyed(&restored, Some(key)).unwrap();
            assert_eq!(r.query_row("SELECT COUNT(*) FROM event", [], |x| x.get::<_, i64>(0)).unwrap(), orig_events, "events fidèles");
            assert_eq!(r.query_row("SELECT COUNT(*) FROM parser", [], |x| x.get::<_, i64>(0)).unwrap(), orig_parsers, "parsers fidèles");
            assert_eq!(r.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |x| x.get::<_, String>(0)).unwrap(), orig_schema, "schema_version fidèle");
            let msg: String = r.query_row("SELECT message FROM event WHERE id=1", [], |x| x.get(0)).unwrap();
            assert!(msg.contains(marker), "contenu restauré fidèle");
        }

        // nettoyage best-effort.
        for f in [&src, &restored] {
            let _ = std::fs::remove_file(f);
            let _ = std::fs::remove_file(format!("{f}-wal"));
            let _ = std::fs::remove_file(format!("{f}-shm"));
        }
        let _ = std::fs::remove_dir_all(&dest_dir);
    }

    // ========================================================================================
    // B1 (DATA-LOSS-CRITICAL) — tests round-trip HOSTILES.
    // But : prouver une perte/corruption au round-trip backup->restore OU un fallback raté.
    // ========================================================================================

    /// Empreinte storage-class-aware d'une table via une requête EXPLICITE de colonnes (permet de lire
    /// des valeurs TEXT non-UTF8 sans passer par String). Renvoie (row_count, hash) où le hash encode la
    /// classe de stockage EXACTE (Null/Integer/Real/Text-bytes/Blob-bytes). Ordre-indépendant.
    fn adv_table_fp(conn: &Connection, select_sql: &str, ncols: usize) -> (u64, u64) {
        use std::hash::{Hash, Hasher};
        let mut stmt = conn.prepare(select_sql).unwrap();
        let mut rows = stmt.query([]).unwrap();
        let (mut count, mut acc) = (0u64, 0u64);
        while let Some(row) = rows.next().unwrap() {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            for i in 0..ncols {
                use rusqlite::types::ValueRef as VR;
                match row.get_ref(i).unwrap() {
                    VR::Null => 0u8.hash(&mut h),
                    VR::Integer(n) => { 1u8.hash(&mut h); n.hash(&mut h); }
                    VR::Real(f) => { 2u8.hash(&mut h); f.to_bits().hash(&mut h); }
                    VR::Text(t) => { 3u8.hash(&mut h); t.hash(&mut h); }   // OCTETS bruts (UTF-8 non requis)
                    VR::Blob(b) => { 4u8.hash(&mut h); b.hash(&mut h); }
                }
            }
            acc = acc.wrapping_add(h.finish());
            count += 1;
        }
        (count, acc)
    }
    fn adv_cleanup(paths: &[&str]) {
        for f in paths { for ext in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{f}{ext}")); } }
    }

    /// ADVERSE #1 — COLONNES GÉNÉRÉES (`GENERATED ALWAYS AS ... STORED`/`VIRTUAL`). `collect_dump_plan` NE
    /// détecte PAS ce schéma comme non-B1 (il n'inspecte que les tables virtuelles), et `build_table_dump`
    /// s'appuie sur `PRAGMA table_info` qui LISTE les colonnes générées -> elles atterrissent dans la liste
    /// INSERT. SQLite REFUSE d'insérer dans une colonne générée. Attendu SÛR : soit fidélité B1, soit repli
    /// legacy — mais un backup RESTAURABLE. Si ça casse : backup produit mais IRRESTAURABLE (perte totale à DR).
    #[test]
    fn adv_b1_generated_columns_roundtrip_or_fallback() {
        let key = "adv-gencol-key";
        let src = mk_tmp_path("advgcsrc.db");
        let dest = mk_tmp_path("advgcdest.age");
        let restored = mk_tmp_path("advgcrestored.db");
        {
            let w = open_db_keyed(&src, Some(key)).unwrap();
            w.execute_batch(
                "CREATE TABLE g(a INTEGER, \
                   b INTEGER GENERATED ALWAYS AS (a * 2) STORED, \
                   c TEXT GENERATED ALWAYS AS (a || 'x') VIRTUAL);"
            ).unwrap();
            for k in 0..25i64 { w.execute("INSERT INTO g(a) VALUES(?)", params![k]).unwrap(); }
        }
        let orig = { let c = open_db_keyed(&src, Some(key)).unwrap(); adv_table_fp(&c, "SELECT a,b,c FROM g", 3) };

        let bk = backup_compressed(&src, &dest, Some(key), None);
        assert!(bk.is_ok(), "ADVERSE#1 : backup d'une table à colonnes générées a ÉCHOUÉ : {:?}", bk.err());
        let rs = restore_compressed(&dest, &restored, Some(key), true, None);
        assert!(rs.is_ok(), "ADVERSE#1 : restore d'un backup à colonnes générées a ÉCHOUÉ (backup IRRESTAURABLE) : {:?}", rs.err());

        let c = open_db_keyed(&restored, Some(key)).unwrap();
        let got = adv_table_fp(&c, "SELECT a,b,c FROM g", 3);
        assert_eq!(got, orig, "ADVERSE#1 : les colonnes générées ne round-trippent PAS à l'identique");
        adv_cleanup(&[&src, &dest, &restored]);
    }

    /// ADVERSE #2 — **DÉFAUT CONFIRMÉ (test ROUGE volontaire)**. TEXT NON-UTF8. Le commentaire de
    /// `write_value_ref` (backup.rs:388-390) ET le message d'erreur lui-même PROMETTENT un « repli legacy »
    /// pour un TEXT non-UTF8. En réalité l'erreur remonte en `PlanErr::Fatal` (backup_compressed_stream:711
    /// `map_err(PlanErr::Fatal)`) et `backup_compressed:755` traite `Fatal` en ÉCHEC SEC (remove dest + Err) —
    /// AUCUN repli legacy. Conséquence : un SEUL octet non-UTF8 dans N'IMPORTE quelle cellule TEXT fait
    /// ÉCHOUER TOTALEMENT tout backup (0 sauvegarde produite). FIX : router ce cas en `PlanErr::Unsupported`
    /// (comme les schémas non-B1) pour que la branche `Unsupported => backup_compressed_legacy` s'active.
    /// Ce test ÉCHOUE tant que le fix prod n'est pas appliqué — c'est la preuve du défaut.
    #[test]
    fn adv_b1_non_utf8_text_falls_back_to_legacy() {
        let key = "adv-nonutf8-key";
        let src = mk_tmp_path("advnu8src.db");
        let dest = mk_tmp_path("advnu8dest.age");
        let restored = mk_tmp_path("advnu8restored.db");
        {
            let w = open_db_keyed(&src, Some(key)).unwrap();
            w.execute_batch("CREATE TABLE t(x);").unwrap();
            // TEXT (affinité storage=text) à octets NON-UTF8 (0xFF) — parfaitement stockable en SQLite.
            w.execute_batch("INSERT INTO t(x) VALUES (CAST(X'ff' AS TEXT));").unwrap();
            w.execute("INSERT INTO t(x) VALUES(?)", params![7i64]).unwrap();
        }
        // pré-condition : la cellule EST bien de classe 'text' et non-UTF8.
        {
            let c = open_db_keyed(&src, Some(key)).unwrap();
            let ty: String = c.query_row("SELECT typeof(x) FROM t WHERE rowid=1", [], |r| r.get(0)).unwrap();
            assert_eq!(ty, "text", "pré-condition : storage class = text");
        }
        let orig = { let c = open_db_keyed(&src, Some(key)).unwrap(); adv_table_fp(&c, "SELECT x FROM t", 1) };

        let bk = backup_compressed(&src, &dest, Some(key), None);
        assert!(bk.is_ok(), "ADVERSE#2 : un TEXT non-UTF8 fait ÉCHOUER TOUT le backup (pas de repli legacy) : {:?}", bk.err());
        let rs = restore_compressed(&dest, &restored, Some(key), true, None);
        assert!(rs.is_ok(), "ADVERSE#2 : restore a échoué : {:?}", rs.err());
        let c = open_db_keyed(&restored, Some(key)).unwrap();
        let got = adv_table_fp(&c, "SELECT x FROM t", 1);
        assert_eq!(got, orig, "ADVERSE#2 : le TEXT non-UTF8 doit round-tripper octet-à-octet");
        adv_cleanup(&[&src, &dest, &restored]);
    }

    /// ADVERSE #3 — WITHOUT ROWID + PK composite + collations + CHECK + DEFAULT non-trivial. Prouve que le
    /// schéma et les données (dont classes de stockage) round-trippent, et que le schéma survit VERBATIM.
    #[test]
    fn adv_b1_without_rowid_and_constraints_roundtrip() {
        let key = "adv-worid-key";
        let src = mk_tmp_path("advwrsrc.db");
        let dest = mk_tmp_path("advwrdest.age");
        let restored = mk_tmp_path("advwrrestored.db");
        {
            let w = open_db_keyed(&src, Some(key)).unwrap();
            w.execute_batch(
                "CREATE TABLE wr(\
                   k1 TEXT COLLATE NOCASE, k2 INTEGER, \
                   v TEXT COLLATE RTRIM, \
                   n INTEGER NOT NULL DEFAULT 42, \
                   flag INTEGER CHECK(flag IN (0,1)), \
                   PRIMARY KEY(k1, k2)) WITHOUT ROWID;"
            ).unwrap();
            w.execute("INSERT INTO wr(k1,k2,v,n,flag) VALUES(?,?,?,?,?)", params!["Alpha", 1i64, "x  ", 5i64, 1i64]).unwrap();
            w.execute("INSERT INTO wr(k1,k2,v,n,flag) VALUES(?,?,?,?,?)", params!["beta", 2i64, "y", 42i64, 0i64]).unwrap();
            w.execute("INSERT INTO wr(k1,k2,v,n,flag) VALUES(?,?,?,?,?)", params!["Gamma", 3i64, "z", 7i64, rusqlite::types::Null]).unwrap();
        }
        let (orig_schema, orig_fp) = {
            let c = open_db_keyed(&src, Some(key)).unwrap();
            (b1_schema(&c), adv_table_fp(&c, "SELECT k1,k2,v,n,flag FROM wr", 5))
        };
        backup_compressed(&src, &dest, Some(key), None).expect("ADVERSE#3 backup OK");
        assert!(backup_payload_head(&dest, key).starts_with(b"PLUMEDUMP1\n"), "ADVERSE#3 : doit rester B1");
        restore_compressed(&dest, &restored, Some(key), true, None).expect("ADVERSE#3 restore OK");
        let c = open_db_keyed(&restored, Some(key)).unwrap();
        assert_eq!(b1_schema(&c), orig_schema, "ADVERSE#3 : schéma (WITHOUT ROWID/collations/CHECK/DEFAULT) VERBATIM");
        assert_eq!(adv_table_fp(&c, "SELECT k1,k2,v,n,flag FROM wr", 5), orig_fp, "ADVERSE#3 : données identiques");
        adv_cleanup(&[&src, &dest, &restored]);
    }

    /// ADVERSE #4 — INDEX EXPRESSION (json_extract, cf. idx_ev_f_*) + INDEX PARTIEL (WHERE) + UNIQUE. Le SQL
    /// d'index doit être re-créé EXACTEMENT et rester fonctionnel après restore.
    #[test]
    fn adv_b1_expression_and_partial_index_roundtrip() {
        let key = "adv-idx-key";
        let src = mk_tmp_path("advidxsrc.db");
        let dest = mk_tmp_path("advidxdest.age");
        let restored = mk_tmp_path("advidxrestored.db");
        {
            let w = open_db_keyed(&src, Some(key)).unwrap();
            w.execute_batch(
                "CREATE TABLE ev(id INTEGER PRIMARY KEY, fields TEXT, dedup TEXT);\n\
                 CREATE INDEX idx_ev_f_user ON ev(json_extract(fields,'$.user'));\n\
                 CREATE UNIQUE INDEX idx_ev_dedup ON ev(dedup) WHERE dedup IS NOT NULL;"
            ).unwrap();
            for k in 0..100i64 {
                let dedup: Option<String> = if k % 3 == 0 { None } else { Some(format!("d{k}")) };
                w.execute("INSERT INTO ev(fields,dedup) VALUES(?,?)",
                    params![format!("{{\"user\":\"u{}\"}}", k % 7), dedup]).unwrap();
            }
        }
        let (orig_schema, orig_fp) = {
            let c = open_db_keyed(&src, Some(key)).unwrap();
            (b1_schema(&c), adv_table_fp(&c, "SELECT id,fields,dedup FROM ev", 3))
        };
        backup_compressed(&src, &dest, Some(key), None).expect("ADVERSE#4 backup OK");
        restore_compressed(&dest, &restored, Some(key), true, None).expect("ADVERSE#4 restore OK");
        let c = open_db_keyed(&restored, Some(key)).unwrap();
        assert_eq!(b1_schema(&c), orig_schema, "ADVERSE#4 : index expression+partiel re-créés VERBATIM");
        assert_eq!(adv_table_fp(&c, "SELECT id,fields,dedup FROM ev", 3), orig_fp, "ADVERSE#4 : données identiques");
        // l'index expression reste fonctionnel (le planner peut l'utiliser).
        let n: i64 = c.query_row("SELECT count(*) FROM ev WHERE json_extract(fields,'$.user')='u3'", [], |r| r.get(0)).unwrap();
        assert!(n > 0, "ADVERSE#4 : requête sur index expression après restore");
        adv_cleanup(&[&src, &dest, &restored]);
    }

    /// ADVERSE #5 — VRAI SCHÉMA PLUME (`db/schema.sql`) chargé dans une DB SQLCipher, données réalistes
    /// (events avec `fields` JSON, déclenchant le trigger event_ai -> event_fts externe), backup B1 ->
    /// restore -> comparaison TOTALE (schéma, row-counts + HASH par table, FTS externe fonctionnelle).
    /// C'est le cas de production qui compte le plus.
    #[test]
    fn adv_b1_real_plume_schema_roundtrip() {
        let key = "adv-realschema-key";
        let src = mk_tmp_path("advrssrc.db");
        let dest = mk_tmp_path("advrsdest.age");
        let restored = mk_tmp_path("advrsrestored.db");
        let schema = include_str!("../../../db/schema.sql");
        {
            let w = open_db_keyed(&src, Some(key)).unwrap();
            w.execute_batch(schema).expect("schéma plume appliqué");
            // events réalistes -> trigger event_ai peuple event_fts (contenu externe = 'event').
            w.execute_batch("BEGIN;").unwrap();
            for k in 0..3000i64 {
                let dedup: Option<String> = if k % 2 == 0 { Some(format!("dk{k}")) } else { None };
                w.execute(
                    "INSERT INTO event(ts,source,category,severity,host,message,fields,dedup) VALUES(?,?,?,?,?,?,?,?)",
                    params![
                        1_700_000_000i64 + k,
                        ["sshd","sudo","auditd","suricata","firewall"][(k % 5) as usize],
                        ["auth","exec","network","integrity"][(k % 4) as usize],
                        (k % 5) as i64,
                        format!("host-{}", k % 17),
                        format!("event message searchable_needle_{k} from source"),
                        format!("{{\"user\":\"u{}\",\"port\":{},\"pid\":{}}}", k % 11, 1024 + (k % 40000), k),
                        dedup
                    ]).unwrap();
            }
            w.execute_batch("COMMIT;").unwrap();
            // quelques métriques/snapshots/alertes pour couvrir REAL/JSON/status.
            w.execute("INSERT INTO metric(ts,name,labels,value) VALUES(?,?,?,?)", params![1_700_000_000i64, "cpu", "{\"h\":\"a\"}", 0.5f64]).unwrap();
            w.execute("INSERT INTO metric(ts,name,labels,value) VALUES(?,?,?,?)", params![1_700_000_001i64, "mem", rusqlite::types::Null, 1e308f64]).unwrap();
            w.execute("INSERT INTO snapshot(ts,kind,hash,data) VALUES(?,?,?,?)", params![1_700_000_000i64, "ports", "abc", "{\"open\":[22,80]}"]).unwrap();
            w.execute("INSERT INTO alert(ts,rule,severity,title,detail) VALUES(?,?,?,?,?)", params![1_700_000_000i64, "r1", 3i64, "t", "d"]).unwrap();
        }
        // empreintes originales.
        let (orig_schema, orig_tables, orig_fps, orig_fts): (_, Vec<String>, Vec<(u64,u64)>, i64);
        {
            let c = open_db_keyed(&src, Some(key)).unwrap();
            orig_schema = b1_schema(&c);
            orig_tables = b1_user_tables(&c);
            orig_fps = orig_tables.iter().map(|t| b1_table_fp(&c, t)).collect();
            orig_fts = c.query_row("SELECT count(*) FROM event_fts WHERE event_fts MATCH 'searchable_needle_42'", [], |r| r.get(0)).unwrap();
            assert!(orig_fts >= 1, "pré-condition FTS externe peuplée");
        }
        backup_compressed(&src, &dest, Some(key), None).expect("ADVERSE#5 backup OK");
        // sur le schéma prod par défaut (FTS_FIELDS off -> pas d'event_fields_fts contentless), B1 s'applique.
        assert!(backup_payload_head(&dest, key).starts_with(b"PLUMEDUMP1\n"),
            "ADVERSE#5 : le schéma prod (event_fts externe) doit passer par B1");
        let raw = std::fs::read(&dest).unwrap();
        assert!(!bytes_contain(&raw, b"SQLite format 3"), "ADVERSE#5 : aucun clair SQLite dans le .age");
        restore_compressed(&dest, &restored, Some(key), true, None).expect("ADVERSE#5 restore OK");

        let c = open_db_keyed(&restored, Some(key)).unwrap();
        assert_eq!(b1_schema(&c), orig_schema, "ADVERSE#5 : schéma plume IDENTIQUE");
        assert_eq!(b1_user_tables(&c), orig_tables, "ADVERSE#5 : mêmes tables");
        for (t, orig) in orig_tables.iter().zip(orig_fps.iter()) {
            assert_eq!(b1_table_fp(&c, t), *orig, "ADVERSE#5 : HASH par table IDENTIQUE pour {t}");
        }
        let fts: i64 = c.query_row("SELECT count(*) FROM event_fts WHERE event_fts MATCH 'searchable_needle_42'", [], |r| r.get(0)).unwrap();
        assert_eq!(fts, orig_fts, "ADVERSE#5 : FTS externe event_fts reconstruite et fonctionnelle");
        adv_cleanup(&[&src, &dest, &restored]);
    }

