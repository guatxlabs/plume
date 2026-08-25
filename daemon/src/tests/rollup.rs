
    // ============================================================================================
    // ROLLUP-ROUTE SOUNDNESS (#33 follow-up) — le rollup-route est une OPTIMISATION qui ne doit s'appliquer
    // QUE si le rollup peut EXACTEMENT reproduire la requête (group-by ∪ filtres ⊆ dims du rollup). Sinon il
    // DÉCLINE -> scan RAW. Garde-fou contre l'angle mort SILENCIEUX (un 0 de rollup sur une vraie attaque) des
    // corrélations `source=X <filtre2> | … by <dim>` — cf. règles purple 21 (T1595.002) / 22 (T1190).
    // ============================================================================================

    /// (1) CORRÉLATION status × src_ip (règle 22, T1190 exploit web) : le rollup ne peut PAS exprimer un
    /// filtre `status` joint à un group-by `src_ip` -> le routeur DÉCLINE (None) et le scan RAW compilé
    /// renvoie le compte EXACT non-nul (avant : risque d'un 0 silencieux si la route avait été prise).
    #[test]
    fn rollup_route_declines_status_by_srcip_correlation_rule22() {
        // (a) EXPRESSIBILITÉ : le filtre `status>=500` n'est PAS une dim exprimable jointement -> décline.
        for q in [
            "search source=web status>=500 | stats count by src_ip",
            "search source=web status>=500 | stats count by src_ip | where count > 10 | stats count",
        ] {
            assert!(try_rollup_route(q, 0, 0, None, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(), "rule22 corrélation status×src_ip DOIT décliner -> raw : {q}");
        }
        // (b) le CHEMIN RAW (celui qu'emprunte réellement la détection via rule_sql/soql_to_sql_x) renvoie le
        //     compte EXACT non-nul : preuve que la règle TIRE (pas d'angle mort).
        let conn = test_db();
        let t = now() - 10;
        for _ in 0..15 { // attaquant 9.9.9.9 : 15 x 5xx (> seuil 10)
            conn.execute("INSERT INTO event(ts,source,severity,src_ip,fields) VALUES(?1,'web',4,'9.9.9.9','{\"status\":\"500\"}')", params![t]).unwrap();
        }
        for _ in 0..3 { // bruit 200 (ne doit PAS compter)
            conn.execute("INSERT INTO event(ts,source,severity,src_ip,fields) VALUES(?1,'web',2,'1.1.1.1','{\"status\":\"200\"}')", params![t]).unwrap();
        }
        let sql = soql_to_sql_x("search source=web status>=500 | stats count by src_ip | where count > 10 | stats count", 0, 0, None).unwrap();
        let got: i64 = conn.query_row(&sql, [], |r| r.get(0)).unwrap();
        assert_eq!(got, 1, "raw-scan doit voir 1 IP au-dessus du seuil (règle 22 TIRE) ; SQL={sql}");
    }

    /// (5) RÉGRESSION MANQUANTE — chemin ORDONNANCEUR (`run_due_rules`), PAS le dry-run. Les tests (1)/(3)
    /// prouvaient le RAW-COMPILE via `conn.query_row` direct ; ils NE traversaient PAS l'ordonnanceur
    /// (sélection des règles dues -> `rule_sql` -> `eval_value_budget` sur le pool read-only -> écriture de
    /// l'alerte). C'est CE chemin qui doit TIRER : règle 22 (T1190), 24 x 5xx d'une SEULE IP en fenêtre ->
    /// une alerte persistée, `last_value` > seuil, MITRE hérité. Garde-fou contre un ordonnanceur muet
    /// pendant que le dry-run passe (le mode d'échec exact décrit par la revue purple).
    #[test]
    fn scheduled_run_due_rules_fires_rule22_srcip_5xx_correlation() {
        let _tmpg1 = crate::tmp_possede::TmpPossede::neuf("sched22");
        let path = _tmpg1.sous("plume.db").chemin().to_path_buf();
        let p = path.to_string_lossy().to_string();
        let t = now() - 10; // en fenêtre (window_s=600)
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            // règle 22 (T1190) canonique (const seed_purple_rules), DUE (last_run NULL).
            w.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed) \
                 VALUES('Anomalie exploit web : pic de 5xx par IP (10 min)',1,'search source=web status>=500 | stats count by src_ip | where count > 10 | stats count',1,'>',0.0,4,300,600,'T1190',2)",
                [],
            ).unwrap();
            // 24 x 5xx d'une SEULE IP (> seuil 10) + du bruit 200 qui ne DOIT pas compter.
            for i in 0..24 {
                w.execute("INSERT INTO event(ts,source,severity,src_ip,fields,dedup) VALUES(?1,'web',4,'9.9.9.9','{\"status\":\"500\"}',?2)", params![t, format!("s5-{i}")]).unwrap();
            }
            for i in 0..5 {
                w.execute("INSERT INTO event(ts,source,severity,src_ip,fields,dedup) VALUES(?1,'web',2,'1.1.1.1','{\"status\":\"200\"}',?2)", params![t, format!("ok-{i}")]).unwrap();
            }
        }
        // L'ORDONNANCEUR (pas le dry-run) évalue et écrit.
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_due_rules(&db, &p);
        let (lv, nalert, sev, mitre): (f64, i64, i64, String) = {
            let c = db.lock();
            let lv: f64 = c.query_row("SELECT COALESCE(last_value,-1) FROM rule WHERE mitre='T1190'", [], |r| r.get(0)).unwrap();
            let (n, sev, m): (i64, i64, String) = c.query_row(
                "SELECT COUNT(*), COALESCE(MAX(severity),0), COALESCE(MAX(mitre),'') FROM alert", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
            (lv, n, sev, m)
        };
        let _ = std::fs::remove_file(&p);
        assert_eq!(lv, 1.0, "last_value = 1 IP au-dessus du seuil (l'ordonnanceur a bien évalué en RAW, pas 0.0 rollup)");
        assert_eq!(nalert, 1, "run_due_rules LÈVE une alerte (chemin ordonnanceur, pas dry-run)");
        assert_eq!(sev, 4, "sévérité 4 héritée de la règle 22");
        assert_eq!(mitre, "T1190", "MITRE hérité (mesure de couverture purple)");
    }

    /// (6) SOUNDNESS ORDONNANCEUR — un ÉCHEC d'évaluation (requête qui COMPILE mais ERRE à l'exécution :
    /// colonne absente / UDF regexp / watchdog budget) NE DOIT PAS se faire passer pour un « tout va bien »
    /// 0.0 : il ne réécrit PAS `last_value` et il NE RÉSOUT PAS une alerte OUVERTE. C'est le mode d'échec
    /// EXACT que le dry-run cachait (rule_test surface « évaluation échouée » ; l'ordonnanceur AVALAIT le
    /// None en 0.0 -> une détection réelle résolue par une erreur transitoire = angle mort SILENCIEUX).
    #[test]
    fn scheduled_run_due_rules_eval_failure_does_not_fake_all_clear() {
        let _tmpg2 = crate::tmp_possede::TmpPossede::neuf("schedfail");
        let path = _tmpg2.sous("plume.db").chemin().to_path_buf();
        let p = path.to_string_lossy().to_string();
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            // Règle qui COMPILE (rule_sql Ok — is_soql=0 = substitution __FROM__ pure) mais ERRE à l'éval
            // (colonne inexistante -> conn.prepare échoue -> run_query Err -> eval_value None). DUE.
            w.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed,last_value) \
                 VALUES('regle-erreur-eval',1,'SELECT colonne_absente FROM event WHERE ts>=__FROM__',0,'>',0.0,3,300,600,'T1190',2,42.0)",
                [],
            ).unwrap();
            let rid: i64 = w.query_row("SELECT id FROM rule WHERE name='regle-erreur-eval'", [], |r| r.get(0)).unwrap();
            // Alerte DÉJÀ OUVERTE portant la clé de dédup de cette règle (un épisode réel en cours).
            w.execute(
                "INSERT INTO alert(ts,rule,severity,title,detail,dedup,status,mitre) VALUES(?1,?2,3,'épisode réel','x',?3,'new','T1190')",
                params![now(), format!("rule.{rid}"), format!("rule-{rid}")],
            ).unwrap();
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_due_rules(&db, &p);
        let (status, lv, last_run_set): (String, f64, i64) = {
            let c = db.lock();
            let st: String = c.query_row("SELECT status FROM alert", [], |r| r.get(0)).unwrap();
            let lv: f64 = c.query_row("SELECT COALESCE(last_value,-1) FROM rule WHERE name='regle-erreur-eval'", [], |r| r.get(0)).unwrap();
            let lr: i64 = c.query_row("SELECT CASE WHEN last_run IS NULL THEN 0 ELSE 1 END FROM rule WHERE name='regle-erreur-eval'", [], |r| r.get(0)).unwrap();
            (st, lv, lr)
        };
        let _ = std::fs::remove_file(&p);
        assert_eq!(status, "new", "un ÉCHEC d'éval ne RÉSOUT PAS l'alerte ouverte (pas de faux 'tout clair')");
        assert_eq!(lv, 42.0, "un ÉCHEC d'éval ne réécrit PAS last_value en 0.0 (valeur préservée)");
        assert_eq!(last_run_set, 1, "last_run AVANCE quand même (la règle re-tentera au prochain intervalle)");
    }


    // ============================================================================================
    // #23 F3 — PURGE DE RÉTENTION CHUNKÉE (verrou writer relâché entre lots) + retrait des re-runs redondants.
    // Prouve : (a) chunked_purge converge multi-lots (mêmes lignes finales qu'un DELETE non borné) ;
    //          (b) retention_run purge le vieux et CONSERVE le récent sur les 5 tables (event/metric/snapshot/
    //              alert/metric_rollup), l'alerte 'new' restant NON-purgeable.
    // ============================================================================================

    /// (a) chunked_purge avec batch=2 sur 7 vieilles lignes -> 4 lots (2+2+2+1) : le prédicat est STABLE ->
    /// convergence, TOUTES les lignes < cutoff supprimées, les lignes >= cutoff intactes. (État final identique
    /// à `DELETE FROM event WHERE ts<cutoff` non borné.)
    #[test]
    fn f3_chunked_purge_converges_multichunk_same_final_state() {
        let db = Arc::new(Mutex::new(test_db()));
        {
            let c = db.lock();
            for i in 0..7 { c.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'agent',?2,'')", params![100_i64, format!("old{i}")]).unwrap(); }
            for i in 0..3 { c.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'agent',?2,'')", params![9_999_999_999_i64, format!("keep{i}")]).unwrap(); }
        }
        chunked_purge(&db, "event", "ts < ?1", &[&1000_i64], 2);
        let c = db.lock();
        let old_left: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE ts < 1000", [], |r| r.get(0)).unwrap();
        let kept: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE ts >= 1000", [], |r| r.get(0)).unwrap();
        assert_eq!(old_left, 0, "toutes les lignes < cutoff supprimées malgré batch=2 (convergence multi-lots)");
        assert_eq!(kept, 3, "les lignes >= cutoff intactes");
    }

    /// (b) retention_run : vieux (au-delà de tout plafond) purgé, récent conservé, sur les 5 tables ; l'alerte
    /// 'new' n'est JAMAIS purgée (status<>'new'). Prouve que la réécriture chunkée + verrou relâché préserve
    /// l'ÉTAT FINAL et les sémantiques (planchers, RETENTION_NONPURGE, filtre status).
    #[test]
    fn f3_retention_run_chunked_purges_old_keeps_recent() {
        let db = Arc::new(Mutex::new(test_db()));
        let n = now();
        let old = n - 4000 * 86400; // au-delà du plafond 3650 j -> purgé quelles que soient les valeurs de rétention.
        let recent = n - 3600;      // < toutes les fenêtres (raw 48 h inclus) -> conservé.
        {
            let c = db.lock();
            for i in 0..5 { c.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'agent',?2,'')", params![old, format!("o{i}")]).unwrap(); }
            for i in 0..3 { c.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'agent',?2,'')", params![recent, format!("n{i}")]).unwrap(); }
            for _ in 0..4 { c.execute("INSERT INTO metric(ts,name,value) VALUES(?1,'m',1.0)", params![old]).unwrap(); }
            for _ in 0..2 { c.execute("INSERT INTO metric(ts,name,value) VALUES(?1,'m',1.0)", params![recent]).unwrap(); }
            for _ in 0..3 { c.execute("INSERT INTO snapshot(ts,kind) VALUES(?1,'firewall')", params![old]).unwrap(); }
            c.execute("INSERT INTO snapshot(ts,kind) VALUES(?1,'firewall')", params![recent]).unwrap();
            c.execute("INSERT INTO alert(ts,rule,severity,status) VALUES(?1,'r',2,'closed')", params![old]).unwrap();
            c.execute("INSERT INTO alert(ts,rule,severity,status) VALUES(?1,'r',2,'new')", params![old]).unwrap();
            c.execute("INSERT INTO alert(ts,rule,severity,status) VALUES(?1,'r',2,'closed')", params![recent]).unwrap();
        }
        retention_run(&db);
        let c = db.lock();
        let ev_total: i64 = c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
        let ev_old: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE ts=?1", params![old], |r| r.get(0)).unwrap();
        let mt_old: i64 = c.query_row("SELECT COUNT(*) FROM metric WHERE ts=?1", params![old], |r| r.get(0)).unwrap();
        let mt_new: i64 = c.query_row("SELECT COUNT(*) FROM metric WHERE ts=?1", params![recent], |r| r.get(0)).unwrap();
        let sn_old: i64 = c.query_row("SELECT COUNT(*) FROM snapshot WHERE ts=?1", params![old], |r| r.get(0)).unwrap();
        let sn_new: i64 = c.query_row("SELECT COUNT(*) FROM snapshot WHERE ts=?1", params![recent], |r| r.get(0)).unwrap();
        let al_old_new: i64 = c.query_row("SELECT COUNT(*) FROM alert WHERE ts=?1 AND status='new'", params![old], |r| r.get(0)).unwrap();
        let al_old_closed: i64 = c.query_row("SELECT COUNT(*) FROM alert WHERE ts=?1 AND status='closed'", params![old], |r| r.get(0)).unwrap();
        let al_new_closed: i64 = c.query_row("SELECT COUNT(*) FROM alert WHERE ts=?1 AND status='closed'", params![recent], |r| r.get(0)).unwrap();
        assert_eq!(ev_old, 0, "events anciens purgés (chunkés)");
        assert_eq!(ev_total, 3, "events récents conservés");
        assert_eq!(mt_old, 0, "metrics raw anciens purgés (rollup+purge)");
        assert_eq!(mt_new, 2, "metrics récents conservés");
        assert_eq!(sn_old, 0, "snapshots anciens purgés");
        assert_eq!(sn_new, 1, "snapshot récent conservé");
        assert_eq!(al_old_closed, 0, "alerte close ancienne purgée");
        assert_eq!(al_old_new, 1, "alerte 'new' ancienne JAMAIS purgée (status<>'new')");
        assert_eq!(al_new_closed, 1, "alerte close récente conservée");
    }

    /// v134 (#10) — le rollup metric ET la purge metric sont ATOMIQUES sous UN SEUL verrou (plus de fenêtre où
    /// une ligne raw <cutoff serait purgée SANS avoir été agrégée = perte silencieuse, COR MED-1). INVARIANT
    /// OBSERVABLE : toute ligne raw purgée est REPRÉSENTÉE dans metric_rollup (agrégat) -> AUCUNE perte. On
    /// choisit `old` ENTRE raw_h (48 h -> rollup+purge) et metric_days (90 j -> le rollup SURVIT ce tick).
    #[test]
    fn v134_metric_rollup_and_purge_atomic_no_loss() {
        let db = Arc::new(Mutex::new(test_db()));
        let n = now();
        let old = n - 10 * 86400; // 10 j : > raw_h (48 h -> rollup+purge), < metric_days (90 j -> rollup conservé).
        let recent = n - 3600;    // 1 h : < raw_h -> conservé, jamais rollup-é/purgé.
        {
            let c = db.lock();
            for _ in 0..5 { c.execute("INSERT INTO metric(ts,name,host,value) VALUES(?1,'cpu','h1',1.0)", params![old]).unwrap(); }
            for _ in 0..2 { c.execute("INSERT INTO metric(ts,name,host,value) VALUES(?1,'cpu','h1',2.0)", params![recent]).unwrap(); }
        }
        retention_run(&db);
        let c = db.lock();
        let raw_old: i64 = c.query_row("SELECT COUNT(*) FROM metric WHERE ts=?1", params![old], |r| r.get(0)).unwrap();
        let raw_recent: i64 = c.query_row("SELECT COUNT(*) FROM metric WHERE ts=?1", params![recent], |r| r.get(0)).unwrap();
        // n cumulé dans metric_rollup == nb de lignes raw anciennes -> preuve qu'elles ont été AGRÉGÉES (pas perdues).
        let rolled_n: i64 = c.query_row("SELECT COALESCE(SUM(n),0) FROM metric_rollup WHERE name='cpu'", [], |r| r.get(0)).unwrap();
        assert_eq!(raw_old, 0, "raw metric ancien purgé (atomique, même verrou que le rollup)");
        assert_eq!(raw_recent, 2, "raw metric récent conservé (< raw_h)");
        assert_eq!(rolled_n, 5, "les 5 lignes raw anciennes AGRÉGÉES dans metric_rollup -> AUCUNE perte");
    }

    // ============================================================================================
    // #23 F4 — refresh de rôle cookie-session via le READ POOL (hors mutex writer). Prouve : rôle lu correct,
    // rétrogradation LIVE reflétée (fraîcheur WAL préservée), compte supprimé -> None.
    // ============================================================================================
    #[test]
    fn f4_cookie_role_via_read_pool_reflects_live_change() {
        let _tmpg3 = crate::tmp_possede::TmpPossede::neuf("f4");
        let path = _tmpg3.sous("plume.db").chemin().to_path_buf();
        let p = path.to_string_lossy().to_string();
        {
            let w = open_db(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            w.execute("INSERT INTO user(name,hash,role) VALUES('carol','$argon2id$x','editor')", []).unwrap();
        }
        let st = ds_file_state(&p); // mode 0 : st.db / st.db_path / tenants pointent le fichier.
        assert_eq!(live_role_for(&st, "carol").as_deref(), Some("editor"), "rôle lu via read pool");
        st.db.lock().execute("UPDATE user SET role='viewer' WHERE name='carol'", []).unwrap();
        assert_eq!(live_role_for(&st, "carol").as_deref(), Some("viewer"), "rétrogradation LIVE reflétée (read pool frais)");
        st.db.lock().execute("DELETE FROM user WHERE name='carol'", []).unwrap();
        assert_eq!(live_role_for(&st, "carol"), None, "compte supprimé -> pas de rôle (cookie invalidé)");
        let _ = std::fs::remove_file(&p);
    }

    // ============================================================================================
    // #23 — /api/integrations : compute_integrations (extrait, SWR-caché) rend la MÊME forme (23 collecteurs +
    // hosts) et le bon statut (auditd récent -> 'audit' actif).
    // ============================================================================================
    #[test]
    fn integrations_compute_shape_and_status() {
        let _tmpg4 = crate::tmp_possede::TmpPossede::neuf("int");
        let path = _tmpg4.sous("plume.db").chemin().to_path_buf();
        let p = path.to_string_lossy().to_string();
        {
            let w = open_db(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            w.execute("INSERT INTO event(ts,source,category,origin) VALUES(?1,'auditd','exec','')", params![now() - 10]).unwrap();
        }
        let v = compute_integrations(&p);
        let cols = v["collectors"].as_array().unwrap();
        assert_eq!(cols.len(), COLLECTORS.len(), "un descripteur par collecteur (forme préservée)");
        let audit = cols.iter().find(|c| c["id"] == "audit").expect("collecteur audit présent");
        assert_eq!(audit["status"], "actif", "auditd récent -> collecteur audit 'actif'");
        assert!(v["hosts"].is_array(), "inventaire hosts présent (host_rollup)");
        let _ = std::fs::remove_file(&p);
    }

    // ============================================================================================
    // #23 — migrate-check : DÉCISION (live vs CODE_SCHEMA_MAX) qui gouverne les codes de sortie (0=en attente,
    // 1=à jour, 2=erreur). Teste la logique de comparaison read-only sans le process::exit du sous-commande.
    // ============================================================================================
    #[test]
    fn migrate_check_decision_pending_vs_uptodate() {
        let c = test_db(); // migrate() -> schema_version = CODE_SCHEMA_MAX.
        assert_eq!(read_schema_version(&c), CODE_SCHEMA_MAX, "test_db migre au max");
        assert!(read_schema_version(&c) >= CODE_SCHEMA_MAX, "À JOUR -> exit 1");
        c.execute("UPDATE meta SET value=?1 WHERE key='schema_version'", params![(CODE_SCHEMA_MAX - 1).to_string()]).unwrap();
        assert!(read_schema_version(&c) < CODE_SCHEMA_MAX, "version antérieure -> migration EN ATTENTE -> exit 0");
        c.execute("DELETE FROM meta WHERE key='schema_version'", []).unwrap();
        assert!(read_schema_version(&c) < CODE_SCHEMA_MAX, "meta absent -> défaut 1 < max -> EN ATTENTE (fail-safe)");
    }

    // ============================================================================================
    // B2 (fix#2) — GROUP-BY MULTI-DIM HOT via event_rollup. Gates : (1) PARITÉ rollup==raw sur le grain
    // exact ; (2) NON-ROUTE stricte des dims hors grain (src_ip approx / JSON / doublon) ; (3) APPROX
    // explicite (jamais un approx silencieux : src_ip décline, résultat routé = approx:true) ; (4)
    // FRAÎCHEUR (bornes bucket + recency note, comme ROUTE A) ; (bench) gain rollup vs scan brut.
    // MASQUAGE (#45, gate 5) : NON testé ici car STRUCTUREL — `try_rollup_route` n'a pas de param masques ;
    // l'appelant (handlers/query.rs) ne l'invoque QUE si `masks.is_empty()` (event_rollup porte les dims EN
    // CLAIR) -> une dim déniée => masks non vide => route non tentée => chemin masqué. Inchangé par B2.
    // ============================================================================================

    // Les tests B2 MUTENT PLUME_ROLLUP_MULTIDIM : ils prennent `VERROU_ENV_PROCESSUS.write()` (déclaré
    // une seule fois dans common.rs). Un verrou « à eux » ne les excluait que d'eux-mêmes.

    /// Sème des events RÉALISTES (source/severity/action/host TOUS peuplés -> pas de divergence NULL vs ''),
    /// tous dans l'HEURE COURANTE, puis matérialise event_rollup. `n_each` copies par combinaison.
    fn b2_seed(conn: &Connection, n_each: usize) {
        let t = now() - 10; // heure courante -> rollup_events la ré-agrège (fenêtre chaude)
        // combinaisons variées sur les 4 dims exactes + du src_ip (qui NE doit PAS influencer un group-by
        // hors-src_ip : il est fondu dans le grain, ré-agrégé en somme).
        let combos: &[(&str, i64, &str, &str, &str)] = &[
            ("web", 4, "blocked", "web1", "9.9.9.9"),
            ("web", 2, "allowed", "web1", "1.1.1.1"),
            ("web", 4, "blocked", "web2", "9.9.9.9"),
            ("sshd", 3, "login", "bastion", "2.2.2.2"),
            ("sshd", 1, "login", "bastion", "3.3.3.3"),
            ("auditd", 3, "exec", "web1", "4.4.4.4"),
            ("auditd", 3, "exec", "web2", "4.4.4.4"),
            ("firewall", 2, "drop", "gw", "5.5.5.5"),
        ];
        for (src, sev, act, host, ip) in combos {
            for i in 0..n_each {
                conn.execute(
                    "INSERT INTO event(ts,source,severity,src_ip,host,fields,dedup) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![t, src, sev, ip, host, format!("{{\"action\":\"{act}\"}}"), format!("{src}-{sev}-{act}-{host}-{i}")],
                ).unwrap();
            }
        }
        rollup_events(conn);
    }

    /// Exécute `sql` et renvoie un map TRIÉ (clé = colonnes de group-by jointes par '|', valeur = dernier
    /// col = count). Ordre des LIGNES ignoré (parité = multiset (clé -> count), pas ordre d'affichage).
    fn b2_map(conn: &Connection, sql: &str) -> Vec<(String, i64)> {
        let mut stmt = conn.prepare(sql).unwrap_or_else(|e| panic!("prepare: {e}\nSQL={sql}"));
        let ncol = stmt.column_count();
        let rows = stmt
            .query_map([], |r| {
                let mut key = Vec::new();
                for i in 0..ncol - 1 {
                    let v: rusqlite::types::Value = r.get(i)?;
                    key.push(match v {
                        rusqlite::types::Value::Null => "∅".to_string(),
                        rusqlite::types::Value::Integer(n) => n.to_string(),
                        rusqlite::types::Value::Real(f) => f.to_string(),
                        rusqlite::types::Value::Text(s) => s,
                        rusqlite::types::Value::Blob(_) => "<blob>".to_string(),
                    });
                }
                let cnt: i64 = r.get(ncol - 1)?;
                Ok((key.join("|"), cnt))
            })
            .unwrap();
        let mut out: Vec<(String, i64)> = rows.map(|x| x.unwrap()).collect();
        out.sort();
        out
    }

    /// (1) PARITÉ EXACTE — pour CHAQUE motif multi-dim sur le grain exact, le résultat MERGÉ (corps rollup ∪
    /// queue raw) est IDENTIQUE au `count by` compilé en RAW sur `event`. Fenêtre non bornée (0,0) + events dans
    /// l'heure courante (volatile) -> tout servi par la QUEUE raw sur `event` -> EXACT (`approx:false`, note:none).
    #[test]
    fn b2_multidim_parity_rollup_equals_raw() {
        let _g = VERROU_ENV_PROCESSUS.write();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM"); // défaut = activé
        let conn = test_db();
        b2_seed(&conn, 3);
        // B2 n'accélère QUE le grain EXACT sans divergence NULL/'' = {source,severity} (NOT NULL, nus).
        // action/host sont EXCLUS (COALESCE '' à la matérialisation -> testé par les non-régressions plus bas).
        for soql in [
            "search | stats count by source,severity",
            "search | stats count by severity,source",           // ordre inversé -> route aussi
            "search source=web | stats count by source,severity", // + filtre source
        ] {
            let rr = try_rollup_route(soql, 0, 0, None, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test())
                .unwrap_or_else(|| panic!("multi-dim DOIT router : {soql}"));
            // B2b MERGE : corps rollup (event_rollup) ∪ queue raw (event). Tous les events sont dans l'heure
            // courante (volatile) -> le corps rollup ne sert rien, la QUEUE raw sur `event` sert tout -> EXACT.
            assert!(rr.sql.contains("FROM event_rollup"), "corps rollup présent : {}", rr.sql);
            assert!(rr.sql.contains("FROM event WHERE"), "queue raw sur `event` présente (fraîcheur) : {}", rr.sql);
            assert!(!rr.approx, "MERGE exact -> approx:false : {soql}");
            assert!(rr.note.is_none(), "MERGE frais -> aucun caveat de fraîcheur : {soql}");
            assert!(!rr.cap.plafonne(), "truncated:false (dims exactes, rien d'abandonné) : {soql}");
            let raw = soql_to_sql_x(soql, 0, 0, None).unwrap();
            let got = b2_map(&conn, &rr.sql);
            let want = b2_map(&conn, &raw);
            assert_eq!(got, want, "PARITÉ rollup==raw pour `{soql}`\nrollup={got:?}\nraw={want:?}");
            // sanity : au moins une ligne + total conservé (aucune perte)
            let tot_r: i64 = got.iter().map(|(_, n)| n).sum();
            let tot_w: i64 = want.iter().map(|(_, n)| n).sum();
            assert!(tot_r > 0 && tot_r == tot_w, "total rollup==raw : {tot_r} vs {tot_w}");
        }
    }

    /// (2)+(3) NON-ROUTE STRICTE / APPROX EXPLICITE — dès qu'une dim n'est pas dans le grain EXACT (src_ip
    /// cappé=approx / JSON hors-grain / doublon), la route DÉCLINE (None) -> scan RAW (jamais un faux count,
    /// jamais un approx silencieux). Et le single-dim reste au comportement pré-B2 (zéro régression).
    #[test]
    fn b2_multidim_declines_non_grain_dims() {
        let _g = VERROU_ENV_PROCESSUS.write();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        // src_ip est APPROX (top-N) -> tout multi-dim qui l'inclut DÉCLINE (pas d'approx silencieux servi exact).
        for q in [
            "search | stats count by source,src_ip",
            "search | stats count by source,severity,src_ip",
            "search source=web | stats count by src_ip,action",
        ] {
            assert!(try_rollup_route(q, 0, 0, None, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(), "src_ip approx dans le group-by DOIT décliner -> raw : {q}");
        }
        // dim JSON hors grain (path/vhost) -> non exprimable par event_rollup -> décline.
        for q in [
            "search | stats count by source,path",
            "search | stats count by status,severity",
            "search source=web | stats count by severity,vhost",
        ] {
            assert!(try_rollup_route(q, 0, 0, None, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(), "dim hors grain dans le multi-dim DOIT décliner -> raw : {q}");
        }
        // host/action sont COALESCE'd '' à la matérialisation (NULL relabélisé/fusionné) -> EXCLUS du grain
        // routable (sinon faux group-by sous approx:true, cf. non-régressions b2_adverse_*). DOIVENT décliner.
        for q in [
            "search | stats count by source,host",
            "search | stats count by source,action",
            "search | stats count by severity,host",
            "search | stats count by severity,action",
            "search source=web | stats count by severity,action",
        ] {
            assert!(try_rollup_route(q, 0, 0, None, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(), "host/action (COALESCE '' -> divergence NULL/'') DOIT décliner -> raw : {q}");
        }
        // doublon -> refus (garde-fou).
        assert!(try_rollup_route("search | stats count by source,source", 0, 0, None, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(), "doublon de dim DOIT décliner");
        // NON-RÉGRESSION single-dim : `by source` route (ROUTE A) ; `by severity` seul NE route PAS (inchangé,
        // pré-B2 -> scan raw) ; ROUTE B `search source=X | stats count by <dim rollée>` intacte.
        let a = try_rollup_route("search | stats count by source", 0, 0, None, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).expect("ROUTE A single-source intacte");
        assert!(a.sql.contains("GROUP BY source ORDER BY"), "ROUTE A single-dim inchangée (GROUP BY source seul) : {}", a.sql);
        assert!(try_rollup_route("search | stats count by severity", 0, 0, None, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(), "single `by severity` inchangé (pré-B2) -> raw");
    }

    /// (2 boundary) STRUCTURE DU MERGE + FRAÎCHEUR SANS RETARD — corps rollup borné aux buckets DÉFINITIFS
    /// `[body_lo, recent)` + queue raw sur `event` `[recent, to]` (heure préc.+courante). Testé sans horloge
    /// murale via `try_rollup_route_at(now_ts)`. La fenêtre touchant l'heure COURANTE reste EXACTE (approx:false)
    /// et SANS caveat de fraîcheur (note:none) : l'heure courante est servie par le SCAN BRUT à jour, PAS le
    /// rollup en retard d'un tick. Fenêtre sub-horaire sans bucket définitif -> DÉCLINE (None -> raw).
    #[test]
    fn b2b_multidim_merge_bounds_exact_no_freshness_lag() {
        let _g = VERROU_ENV_PROCESSUS.write();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        let now_ts = 1_000_000_000_i64;
        let cur = (now_ts / 3600) * 3600;
        let recent = cur - 3600; // frontière DÉFINITIVE du rollup
        let soql = "search | stats count by source,severity";
        // (a) fenêtre alignée dans le passé (to = recent) -> corps `[from, recent)`, queue raw à `recent`.
        let from = cur - 10 * 3600;
        let past = try_rollup_route_at(soql, from, recent, None, now_ts, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).unwrap();
        assert!(past.sql.contains(&format!("bucket >= {from}")), "corps rollup borné bas au from aligné : {}", past.sql);
        assert!(past.sql.contains(&format!("bucket < {recent}")), "corps BORNÉ aux buckets DÉFINITIFS (< recent) : {}", past.sql);
        assert!(past.sql.contains("FROM event WHERE"), "queue RAW sur `event` présente : {}", past.sql);
        assert!(past.sql.contains(&format!("ts >= {recent}")), "queue raw démarre à recent : {}", past.sql);
        assert!(!past.sql.contains("bucket <= "), "plus de borne bucket <= to (remplacée par le merge) : {}", past.sql);
        assert!(!past.approx, "MERGE exact -> approx:false");
        assert!(past.note.is_none(), "MERGE exact -> aucune note");
        // (b) fenêtre touchant l'heure COURANTE -> queue raw couvre heure préc.+courante -> EXACT & FRAIS.
        let recent_w = try_rollup_route_at(soql, from, now_ts, None, now_ts, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).unwrap();
        assert!(recent_w.sql.contains(&format!("bucket < {recent}")), "corps s'arrête à la frontière définitive : {}", recent_w.sql);
        assert!(
            recent_w.sql.contains(&format!("ts >= {recent}")) && recent_w.sql.contains(&format!("ts <= {now_ts}")),
            "queue raw couvre [recent, now] (heure préc.+courante) : {}",
            recent_w.sql
        );
        assert!(!recent_w.approx, "heure courante RAW-servie -> EXACT (approx:false)");
        assert!(recent_w.note.is_none(), "heure courante RAW-servie -> AUCUN retard de fraîcheur (note:none)");
        // (c) fenêtre ENTIÈREMENT sub-horaire dans l'heure courante -> aucun bucket définitif -> DÉCLINE (raw).
        assert!(
            try_rollup_route_at(soql, cur + 100, cur + 200, None, now_ts, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(),
            "fenêtre sub-horaire (aucun bucket définitif complet) -> décline -> scan raw exact"
        );
    }

    /// Sème des events sur PLUSIEURS heures (buckets DÉFINITIFS < recent ET heure courante/précédente volatiles),
    /// avec (source,severity) variés. `n` = horloge pinnée (insertion + rollup + route cohérents).
    fn b2b_seed_multi_hour(conn: &Connection, n: i64) {
        let combos: &[(&str, i64)] = &[("web", 4), ("web", 2), ("sshd", 3), ("auditd", 3), ("firewall", 2)];
        // offsets (s avant n) : heure courante, préc., -2h, -3h, -4h -> au moins -2h/-3h/-4h sont DÉFINITIFS.
        let offsets = [30_i64, 3_700, 7_300, 10_900, 14_500];
        let mut k = 0i64;
        for off in offsets {
            for (src, sev) in combos {
                for _ in 0..2 {
                    conn.execute(
                        "INSERT INTO event(ts,source,severity,host,fields,dedup) VALUES(?1,?2,?3,'h1','{}',?4)",
                        params![n - off, src, sev, format!("mh-{k}")],
                    )
                    .unwrap();
                    k += 1;
                }
            }
        }
        rollup_events(conn);
    }

    /// (1b) PARITÉ EXACTE MULTI-HEURES — le MERGE (corps rollup DÉFINITIF ∪ tête/queue raw) == `count by
    /// source,severity` RAW sur `event`, au COMPTE près, pour des fenêtres ALIGNÉES, à bornes SUB-HORAIRES et
    /// TOUCHANT l'heure courante. Boundary : tête/corps/queue disjoints -> ni double-comptage ni perte.
    #[test]
    fn b2b_multidim_merge_parity_multi_hour() {
        let _g = VERROU_ENV_PROCESSUS.write();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        let conn = test_db();
        let n = now();
        let cur = (n / 3600) * 3600;
        b2b_seed_multi_hour(&conn, n);
        let soql = "search | stats count by source,severity";
        // Fenêtres qui GARANTISSENT un corps définitif (donc routent) : alignée+touche-now, DEUX bornes
        // sub-horaires, passé-aligné-sans-heure-courante, non-bornée.
        let windows: &[(i64, i64)] = &[
            (cur - 4 * 3600, n),                  // aligné bas, touche maintenant (queue = heure préc.+courante)
            (cur - 4 * 3600 + 1234, n - 567),     // DEUX bornes SUB-HORAIRES (tête + queue raw)
            (cur - 3 * 3600, cur - 3600),         // passé aligné, sans toucher l'heure courante
            (0, 0),                               // non borné
        ];
        for &(from, to) in windows {
            let rr = try_rollup_route_at(soql, from, to, None, n, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test())
                .unwrap_or_else(|| panic!("multi-dim (corps définitif présent) DOIT router : ({from},{to})"));
            let raw = soql_to_sql_x(soql, from, to, None).unwrap();
            let got = b2_map(&conn, &rr.sql);
            let want = b2_map(&conn, &raw);
            assert_eq!(got, want, "PARITÉ EXACTE merge==raw ({from},{to})\nmerge={got:?}\nraw={want:?}\nSQL={}", rr.sql);
            let tot_r: i64 = got.iter().map(|(_, x)| x).sum();
            let tot_w: i64 = want.iter().map(|(_, x)| x).sum();
            assert!(tot_r > 0 && tot_r == tot_w, "total conservé ({from},{to}) : {tot_r} vs {tot_w}");
            assert!(!rr.approx, "HOT merge exact -> approx:false ({from},{to})");
            assert!(rr.note.is_none(), "HOT merge frais -> note:none ({from},{to})");
        }
        // + filtre source= : la parité tient aussi (source= appliqué au corps ET aux partiels raw).
        let sf = "search source=web | stats count by source,severity";
        let rr = try_rollup_route_at(sf, cur - 4 * 3600 + 55, n, None, n, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).unwrap();
        assert_eq!(b2_map(&conn, &rr.sql), b2_map(&conn, &soql_to_sql_x(sf, cur - 4 * 3600 + 55, n, None).unwrap()), "PARITÉ avec filtre source=");
    }

    /// (fraîcheur) — des events RÉCENTS ingérés APRÈS le tick de rollup (que `event_rollup` n'a JAMAIS vus)
    /// sont comptés EXACTEMENT par la QUEUE raw sur `event` -> le merge n'a AUCUN retard de fraîcheur (c'était
    /// le sous-comptage `approx:true`+note de l'ancien B2). Prouve que le corps ≠ toute la vérité et la queue rattrape.
    #[test]
    fn b2b_multidim_recent_events_after_rollup_exact() {
        let _g = VERROU_ENV_PROCESSUS.write();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        let conn = test_db();
        let n = now();
        let cur = (n / 3600) * 3600;
        b2b_seed_multi_hour(&conn, n); // matérialise event_rollup (définitif + volatile) UNE fois
        // events TRÈS récents ingérés APRÈS -> présents SEULEMENT dans `event`, jamais dans event_rollup.
        for i in 0..7 {
            conn.execute(
                "INSERT INTO event(ts,source,severity,host,fields,dedup) VALUES(?1,'web',4,'h1','{}',?2)",
                params![n - 3, format!("late-{i}")],
            )
            .unwrap();
        }
        let soql = "search | stats count by source,severity";
        let rr = try_rollup_route_at(soql, cur - 2 * 3600, n, None, n, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).unwrap();
        let raw = soql_to_sql_x(soql, cur - 2 * 3600, n, None).unwrap();
        assert_eq!(
            b2_map(&conn, &rr.sql),
            b2_map(&conn, &raw),
            "events récents post-rollup comptés via la QUEUE raw (fraîcheur SANS retard) : merge={:?} raw={:?}\nSQL={}",
            b2_map(&conn, &rr.sql),
            b2_map(&conn, &raw),
            rr.sql
        );
        assert!(!rr.approx && rr.note.is_none(), "résultat EXACT & FRAIS (approx:false, note:none)");
    }

    /// (killswitch) — `PLUME_ROLLUP_MULTIDIM=0` désactive B2 : le multi-dim retombe au scan brut (None),
    /// tandis que ROUTE A single-dim reste servie (kill-switch ciblé, réversible sans redéploiement).
    #[test]
    fn b2_multidim_killswitch_disables_route() {
        let _g = VERROU_ENV_PROCESSUS.write();
        std::env::set_var("PLUME_ROLLUP_MULTIDIM", "0");
        let multidim = try_rollup_route("search | stats count by source,severity", 0, 0, None, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test());
        let single = try_rollup_route("search | stats count by source", 0, 0, None, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test());
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM"); // RESTORE avant les asserts (pas de fuite d'env)
        assert!(multidim.is_none(), "flag OFF -> multi-dim NON routé (fallback scan brut)");
        assert!(single.is_some(), "flag OFF -> ROUTE A single-dim reste routée (kill-switch ciblé B2)");
    }

    // ============================================================================================
    // B2 NON-RÉGRESSION — VERROUILLE LE FIX du faux group-by NULL/''. Le défaut prouvé était
    // que `host`/`action` divergeaient : la MATÉRIALISATION du rollup COALESCE la valeur
    // (host = COALESCE(host,'') ; action = COALESCE(json_extract(fields,'$.action'),'')) TANDIS QUE le
    // compilo RAW (`soql_field`) émet la colonne réelle NUE (`"host"`, NULL préservé) et le
    // `json_extract(fields,'$.action')` NU (NULL si clé absente), SANS coalesce -> le rollup RELABÉLISAIT
    // NULL en '' ET FUSIONNAIT NULL avec '' explicite -> faux compte + groupe NULL disparu, servi approx:true.
    // FIX : `host`/`action` RETIRÉS de ROLLUP_EXACT_DIMS -> tout `by`-set les incluant DÉCLINE (None) ->
    // scan RAW exact (NULL préservé, aucun '' fabriqué). Ces tests prouvent DÉSORMAIS : (a) la route DÉCLINE
    // et (b) le chemin raw emprunté rend le résultat CORRECT (groupe NULL présent, pas de fusion).
    // ============================================================================================

    /// NON-RÉG #1 — `count by source,host` avec host NULL + '' explicite : la route DÉCLINE (host hors grain)
    /// -> scan RAW qui DISTINGUE le groupe host=NULL (3) du groupe host='' explicite (2) -> plus de fusion.
    #[test]
    fn b2_adverse_host_null_merged_with_empty_wrong_counts() {
        let _g = VERROU_ENV_PROCESSUS.write();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        let conn = test_db();
        let t = now() - 10; // heure courante
        // source=web : 3 events host=NULL, 2 events host='' (chaîne vide EXPLICITE), 4 events host='web1'
        for i in 0..3 {
            conn.execute("INSERT INTO event(ts,source,severity,fields,dedup) VALUES(?1,'web',2,'{}',?2)", params![t, format!("hn-{i}")]).unwrap();
        }
        for i in 0..2 {
            conn.execute("INSERT INTO event(ts,source,severity,host,fields,dedup) VALUES(?1,'web',2,'','{}',?2)", params![t, format!("he-{i}")]).unwrap();
        }
        for i in 0..4 {
            conn.execute("INSERT INTO event(ts,source,severity,host,fields,dedup) VALUES(?1,'web',2,'web1','{}',?2)", params![t, format!("hw-{i}")]).unwrap();
        }
        rollup_events(&conn);

        let soql = "search | stats count by source,host";
        // FIX : la route DÉCLINE (host hors grain routable) -> pas de faux group-by servi approx:true.
        assert!(try_rollup_route(soql, 0, 0, None, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(), "host hors grain -> DÉCLINE -> scan raw : {soql}");

        // Le chemin RAW réellement emprunté rend le résultat CORRECT (3 groupes DISTINCTS, NULL préservé).
        let raw = soql_to_sql_x(soql, 0, 0, None).unwrap();
        let want = b2_map(&conn, &raw); // ORACLE = scan brut exact
        eprintln!("[B2 NON-RÉG host] raw={want:?}");
        assert!(want.contains(&("web|∅".to_string(), 3)), "raw voit le groupe host=NULL (3) : {want:?}");
        assert!(want.contains(&("web|".to_string(), 2)), "raw voit host='' explicite (2) : {want:?}");
        assert!(want.contains(&("web|web1".to_string(), 4)), "raw voit host='web1' (4) : {want:?}");
        // AUCUN '' sur-compté à 5 (la fusion NULL+'' est éliminée) et le groupe NULL n'est PAS perdu.
        assert!(!want.iter().any(|(k, n)| k == "web|" && *n == 5), "raw ne FUSIONNE PAS NULL+'' (pas de host=''=5) : {want:?}");
    }

    /// NON-RÉG #2 — `count by source,action` (clé JSON absente = NULL vs action='' explicite) : la route
    /// DÉCLINE (action hors grain) -> scan RAW qui DISTINGUE action=NULL (3) de action='' (2) -> plus de fusion.
    #[test]
    fn b2_adverse_action_missing_merged_with_empty_wrong_counts() {
        let _g = VERROU_ENV_PROCESSUS.write();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        let conn = test_db();
        let t = now() - 10;
        // source=sshd : 3 sans clé action, 2 avec action='' explicite, 4 avec action='login' (host peuplé pour
        // isoler la divergence à `action` seule — host non-NULL ici).
        for i in 0..3 {
            conn.execute("INSERT INTO event(ts,source,severity,host,fields,dedup) VALUES(?1,'sshd',3,'bastion','{}',?2)", params![t, format!("am-{i}")]).unwrap();
        }
        for i in 0..2 {
            conn.execute("INSERT INTO event(ts,source,severity,host,fields,dedup) VALUES(?1,'sshd',3,'bastion','{\"action\":\"\"}',?2)", params![t, format!("ae-{i}")]).unwrap();
        }
        for i in 0..4 {
            conn.execute("INSERT INTO event(ts,source,severity,host,fields,dedup) VALUES(?1,'sshd',3,'bastion','{\"action\":\"login\"}',?2)", params![t, format!("al-{i}")]).unwrap();
        }
        rollup_events(&conn);

        let soql = "search | stats count by source,action";
        assert!(try_rollup_route(soql, 0, 0, None, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(), "action hors grain -> DÉCLINE -> scan raw : {soql}");

        let raw = soql_to_sql_x(soql, 0, 0, None).unwrap();
        let want = b2_map(&conn, &raw);
        eprintln!("[B2 NON-RÉG action] raw={want:?}");
        assert!(want.contains(&("sshd|∅".to_string(), 3)), "raw voit action ABSENTE=NULL (3) : {want:?}");
        assert!(want.contains(&("sshd|".to_string(), 2)), "raw voit action='' explicite (2) : {want:?}");
        assert!(want.contains(&("sshd|login".to_string(), 4)), "raw voit action='login' (4) : {want:?}");
        assert!(!want.iter().any(|(k, n)| k == "sshd|" && *n == 5), "raw ne FUSIONNE PAS NULL+'' (pas de action=''=5) : {want:?}");
    }

    /// NON-RÉG #3 (le plus fréquent en prod) — `count by source,host` avec host NULL SEUL (aucun '' explicite :
    /// la quasi-totalité des sources n'écrivent jamais `host`). La route DÉCLINE -> scan RAW qui rend le groupe
    /// `host=NULL` HONNÊTE (absence), PAS un `host=''` fabriqué -> plus d'hôte '' fantôme, attribution correcte.
    #[test]
    fn b2_adverse_host_null_relabeled_empty_string() {
        let _g = VERROU_ENV_PROCESSUS.write();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        let conn = test_db();
        let t = now() - 10;
        for i in 0..5 {
            conn.execute("INSERT INTO event(ts,source,severity,fields,dedup) VALUES(?1,'firewall',2,'{}',?2)", params![t, format!("fw-{i}")]).unwrap();
        }
        for i in 0..3 {
            conn.execute("INSERT INTO event(ts,source,severity,host,fields,dedup) VALUES(?1,'firewall',2,'gw','{}',?2)", params![t, format!("gw-{i}")]).unwrap();
        }
        rollup_events(&conn);
        let soql = "search | stats count by source,host";
        assert!(try_rollup_route(soql, 0, 0, None, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(), "host hors grain -> DÉCLINE -> scan raw : {soql}");
        let raw = soql_to_sql_x(soql, 0, 0, None).unwrap();
        let want = b2_map(&conn, &raw);
        eprintln!("[B2 NON-RÉG host-null-only] raw={want:?}");
        assert!(want.contains(&("firewall|∅".to_string(), 5)), "raw: groupe host=NULL honnête (5) : {want:?}");
        assert!(want.contains(&("firewall|gw".to_string(), 3)), "raw: groupe host='gw' (3) : {want:?}");
        assert!(!want.iter().any(|(k, _)| k == "firewall|"), "raw ne FABRIQUE PAS de host='' (pas d'hôte fantôme) : {want:?}");
    }

    /// (bench) — GAIN mesuré : sur une fenêtre DÉFINITIVE alignée (corps rollup PUR, aucun partiel raw), le
    /// group-by multi-dim via event_rollup (peu de lignes de grain) est nettement plus rapide que le scan+
    /// agrégation brut sur `event`. B2b : le gain rollup ne vaut QUE pour les buckets définitifs -> on sème
    /// les 48k events dans une heure PASSÉE (< recent) et on interroge une fenêtre alignée-passée (zéro queue
    /// raw). Nommé `..._bench_...` -> exclu par `cargo test -- --skip bench`. Parité vérifiée sous volume.
    #[test]
    fn b2_multidim_bench_rollup_vs_rawscan() {
        let _g = VERROU_ENV_PROCESSUS.write();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        let conn = test_db();
        let n = now();
        let cur = (n / 3600) * 3600;
        let t = cur - 3 * 3600 + 60; // heure DÉFINITIVE (< recent) -> matérialisée dans event_rollup
        let combos: &[(&str, i64)] = &[("web", 4), ("web", 2), ("web", 4), ("sshd", 3), ("sshd", 1), ("auditd", 3), ("auditd", 3), ("firewall", 2)];
        for i in 0..6000 {
            for (ci, (src, sev)) in combos.iter().enumerate() {
                conn.execute(
                    "INSERT INTO event(ts,source,severity,host,fields,dedup) VALUES(?1,?2,?3,'h1','{}',?4)",
                    params![t, src, sev, format!("b-{ci}-{i}")],
                )
                .unwrap();
            }
        } // 8 combos * 6000 = 48 000 lignes event ; event_rollup = ~8 lignes de grain
        rollup_events(&conn);
        let soql = "search | stats count by source,severity"; // grain routable exact (source,severity)
        // fenêtre ALIGNÉE entièrement DÉFINITIVE (to strictement < recent) -> corps rollup PUR, aucune queue raw.
        let from = cur - 4 * 3600;
        let to = cur - 3600 - 1;
        let rr = try_rollup_route_at(soql, from, to, None, n, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).unwrap();
        assert!(!rr.sql.contains("FROM event WHERE"), "fenêtre définitive alignée -> corps rollup PUR (aucun scan raw) : {}", rr.sql);
        let raw = soql_to_sql_x(soql, from, to, None).unwrap();
        // chauffe + mesure
        let t0 = std::time::Instant::now();
        let got = b2_map(&conn, &rr.sql);
        let d_roll = t0.elapsed();
        let t1 = std::time::Instant::now();
        let want = b2_map(&conn, &raw);
        let d_raw = t1.elapsed();
        assert_eq!(got, want, "bench : résultats identiques (parité) sous volume");
        eprintln!("[B2 bench] 48k events — rollup={:?} raw={:?} (x{:.1})", d_roll, d_raw, d_raw.as_secs_f64() / d_roll.as_secs_f64().max(1e-9));
        assert!(d_roll <= d_raw, "le group-by multi-dim via rollup (corps définitif) NE DOIT PAS être plus lent que le scan brut (rollup={d_roll:?} raw={d_raw:?})");
    }
