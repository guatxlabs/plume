    // ============================================================================================
    // #3 INCIDENTS + RESPONSE WIZARD (Phase 1) — élévation case->incident, auto-pick runbook par tactique
    // MITRE dominante, instanciation des steps, avancement (timeline+ledger+MTTA), parité mode 0, non-fuite
    // client-read, migration v104. Réutilise case_add_item/ledger_append/attack/soql/action_kind_valid.
    // ============================================================================================

    /// MIGRATION v104+v105 : idempotente (2 passes -> tête 105), colonnes incident nullables + 3 tables additives
    /// (v104) + colonnes STRUCTURÉES nullables alert.src_ip/alert.pid + case_step.host (v105, #3 P3-A).
    #[test]
    fn incident_migration_v105_idempotent() {
        let conn = test_db(); // schema.sql + migrate -> 105
        assert_eq!(conn.query_row::<String, _, _>("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap(), CODE_SCHEMA_MAX.to_string());
        // re-migrate = no-op (ALTER guardé par col_exists + CREATE IF NOT EXISTS avalés).
        let _ = migrate(&conn);
        assert_eq!(conn.query_row::<String, _, _>("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap(), CODE_SCHEMA_MAX.to_string());
        for c in ["incident_tier", "incident_type", "commander"] {
            assert!(col_exists(&conn, "incident", c), "incident.{c} manquant");
        }
        for t in ["runbook", "runbook_step", "case_step"] {
            let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "{t} VIDE à la création (mode 0)");
        }
        // #3 P3-A — colonnes structurées présentes (nullable, additif).
        assert!(col_exists(&conn, "alert", "src_ip"), "alert.src_ip manquant (v105)");
        assert!(col_exists(&conn, "alert", "pid"), "alert.pid manquant (v105)");
        assert!(col_exists(&conn, "case_step", "host"), "case_step.host manquant (v105)");
        // A2 : `user`/`entity_user` DÉLIBÉRÉMENT NON ajouté (différé).
        assert!(!col_exists(&conn, "alert", "entity_user"), "alert.entity_user NE DOIT PAS exister (A2 différé)");
    }

    /// SEED : les gabarits GXQL des steps 'search' COMPILENT (après substitution de $target$) — verrou
    /// anti-régression sur le compilateur FERMÉ (jamais de SQL brut ; recompilé à la résolution).
    #[test]
    fn seed_runbook_searches_compile() {
        let conn = test_db();
        seed_runbooks(&conn);
        let tpls: Vec<String> = conn
            .prepare("SELECT search_soql FROM runbook_step WHERE step_kind='search' AND search_soql IS NOT NULL")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0)).unwrap().flatten().collect();
        assert!(tpls.len() >= 4, "au moins 4 steps search seedées");
        for t in &tpls {
            let sub = t.replace("$target$", "203.0.113.9");
            let ok = guatx_core::soql::to_sql(&sub, 0, 0, &guatx_core::soql::Schema::events()).is_ok()
                || guatx_core::soql::to_sql(&format!("search {sub}"), 0, 0, &guatx_core::soql::Schema::events()).is_ok();
            assert!(ok, "gabarit search NON compilable : {t}");
        }
        // les steps 'response' référencent l'enum d'action FERMÉ.
        let acts: Vec<String> = conn.prepare("SELECT action_kind FROM runbook_step WHERE step_kind='response' AND action_kind IS NOT NULL").unwrap()
            .query_map([], |r| r.get::<_, String>(0)).unwrap().flatten().collect();
        assert!(!acts.is_empty(), "au moins une step response seedée");
        for a in &acts { assert!(action_kind_valid(a).is_ok(), "action_kind hors enum : {a}"); }
    }

    /// ÉLÉVATION / RÉTROGRADATION : incident_tier + type/commander, timeline 'incident' + ledger ; demote NULL.
    #[test]
    fn incident_elevate_and_demote() {
        let conn = test_db();
        let id = case_create_row(&conn, "alice", "Scan suspect", 3, "", None, 3);
        // ordinaire : tier NULL.
        let tier0: Option<i64> = conn.query_row("SELECT incident_tier FROM incident WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        assert_eq!(tier0, None, "case ordinaire : tier NULL");
        // élévation.
        assert!(incident_apply_tier(&conn, id, "bob", Some(2), Some("intrusion"), Some("carol")));
        let (tier, ty, cmd): (Option<i64>, Option<String>, Option<String>) = conn.query_row("SELECT incident_tier,incident_type,commander FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!((tier, ty.as_deref(), cmd.as_deref()), (Some(2), Some("intrusion"), Some("carol")));
        let tl: i64 = conn.query_row("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='incident'", params![id], |r| r.get(0)).unwrap();
        assert_eq!(tl, 1, "item timeline 'incident'");
        let lg: i64 = conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind='case.incident'", [], |r| r.get(0)).unwrap();
        assert_eq!(lg, 1, "ledger case.incident");
        // rétrogradation -> tier NULL (type/commander conservés = trace).
        assert!(incident_apply_tier(&conn, id, "bob", None, None, None));
        let tier2: Option<i64> = conn.query_row("SELECT incident_tier FROM incident WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        assert_eq!(tier2, None, "demote -> tier NULL");
        // case inexistant -> false.
        assert!(!incident_apply_tier(&conn, 9999, "bob", Some(1), None, None));
    }

    /// INC-2 : tie-break DÉTERMINISTE de la tactique/technique dominante. std HashMap a un ordre d'itération
    /// randomisé PAR instance -> sans départage, `max_by_key` basculerait entre appels (runbook recommandé qui
    /// clignote). Avec le tie-break (compte desc, nom asc) -> dominant STABLE = plus petit nom lexicographique.
    #[test]
    fn dominant_tactic_tie_break_is_deterministic() {
        let conn = test_db();
        let id = case_create_row(&conn, "a", "tie", 3, "", None, 3);
        // ÉGALITÉ 1-1 : discovery(T1046) vs initial-access(T1190). Attendu déterministe = plus petit nom.
        link_alert(&conn, id, "T1046", None); // discovery
        link_alert(&conn, id, "T1190", None); // initial-access
        let (tac0, tech0, _) = dominant_tactic_and_target(&conn, id);
        assert_eq!(tac0.as_deref(), Some("discovery"), "tie -> tactique lexicographiquement min");
        assert_eq!(tech0.as_deref(), Some("T1046"), "tie -> technique lexicographiquement min");
        // stabilité : 64 appels (donc 64 HashMap distincts) rendent EXACTEMENT le même dominant.
        for _ in 0..64 {
            let (tac, tech, _) = dominant_tactic_and_target(&conn, id);
            assert_eq!(tac, tac0, "tactique dominante STABLE entre appels (déterminisme)");
            assert_eq!(tech, tech0, "technique dominante STABLE entre appels");
        }
    }

    /// MISC (off-by-one) : une valeur type/pilote VIDE (ou espaces) ne doit PAS produire de label pendouillant
    /// « , type » / « , pilote » (l'ancien seuil `s.len() > 6/8` sur la chaîne PRÉFIXÉE était toujours vrai).
    #[test]
    fn incident_label_no_dangling_when_value_empty() {
        let conn = test_db();
        let id = case_create_row(&conn, "a", "lbl", 3, "", None, 3);
        // type=espaces, pilote=vide -> AUCUN label additionnel.
        assert!(incident_apply_tier(&conn, id, "bob", Some(2), Some("  "), Some("")));
        let body: String = conn.query_row(
            "SELECT body FROM incident_item WHERE incident_id=?1 AND kind='incident' ORDER BY id DESC LIMIT 1",
            params![id], |r| r.get(0)).unwrap();
        assert_eq!(body, "incident DÉCLARÉ (tier 2)", "valeurs vides -> pas de label pendouillant ; body={body}");
        // valeurs NON vides -> les deux labels apparaissent (trimés).
        assert!(incident_apply_tier(&conn, id, "bob", Some(1), Some(" intrusion "), Some(" carol ")));
        let body2: String = conn.query_row(
            "SELECT body FROM incident_item WHERE incident_id=?1 AND kind='incident' ORDER BY id DESC LIMIT 1",
            params![id], |r| r.get(0)).unwrap();
        assert_eq!(body2, "incident DÉCLARÉ (tier 1), type intrusion, pilote carol");
    }

    /// CONC-3 : le garde RAII `Txn` ROLLBACK au Drop sauf `.commit()` — et surtout LIBÈRE l'écrivain même sur
    /// panic entre BEGIN et le terminateur (sinon la connexion resterait coincée « transaction within a
    /// transaction » pour toutes les écritures suivantes).
    #[test]
    fn txn_guard_rolls_back_on_drop_and_survives_panic() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t(x INTEGER)").unwrap();
        // (a) drop SANS commit -> ROLLBACK (mutation annulée).
        {
            let tx = Txn::begin(&conn).unwrap();
            conn.execute("INSERT INTO t(x) VALUES(1)", []).unwrap();
            drop(tx); // Drop -> ROLLBACK
        }
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "drop sans commit -> ROLLBACK");
        // writer LIBRE : un nouveau BEGIN réussit (pas de txn ouverte laissée).
        let tx2 = Txn::begin(&conn).expect("nouveau BEGIN OK (writer libéré)");
        conn.execute("INSERT INTO t(x) VALUES(2)", []).unwrap();
        tx2.commit().unwrap();
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap(), 1, "commit -> persisté");
        // (b) PANIC entre BEGIN et COMMIT : le Drop se DÉROULE -> ROLLBACK -> writer libre.
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _tx = Txn::begin(&conn).unwrap();
            conn.execute("INSERT INTO t(x) VALUES(3)", []).unwrap();
            panic!("boom entre BEGIN et COMMIT");
        }));
        assert!(r.is_err(), "le panic est bien survenu");
        // Sans le garde, ce BEGIN échouerait (transaction encore ouverte). Avec, il réussit et l'INSERT paniqué
        // a été annulé.
        let tx3 = Txn::begin(&conn).expect("writer libéré après panic (Drop a rollback)");
        drop(tx3);
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap(), 1, "INSERT du bloc paniqué ROLLBACK");
    }

    /// Helper : crée un case et y lie une alerte portant `mitre` (+ host optionnel).
    fn link_alert(conn: &Connection, case_id: i64, mitre: &str, host: Option<&str>) {
        conn.execute("INSERT INTO alert(ts,rule,severity,title,status,mitre,host) VALUES(?1,'r',3,'a','new',?2,?3)", params![now(), mitre, host]).unwrap();
        let aid = conn.last_insert_rowid();
        case_add_item(conn, case_id, now(), "alert", "sys", "alerte liée", Some(&format!("alert:{aid}")));
    }

    /// AUTO-PICK : la tactique DOMINANTE des alertes liées choisit le bon runbook ; discovery->reconnaissance ;
    /// aucune alerte -> repli générique '*' ; cible best-effort = host de l'alerte.
    #[test]
    fn runbook_autopick_by_dominant_tactic() {
        let conn = test_db();
        seed_runbooks(&conn);
        // (a) case avec T1190 (initial-access) dominant.
        let ia = case_create_row(&conn, "a", "exploit", 4, "", None, 2);
        link_alert(&conn, ia, "T1190", Some("web-1"));
        link_alert(&conn, ia, "T1190", None);
        link_alert(&conn, ia, "T1110", None); // minoritaire
        let (tac, tech, targets) = dominant_tactic_and_target(&conn, ia);
        assert_eq!(tac.as_deref(), Some("initial-access"));
        assert_eq!(tech.as_deref(), Some("T1190"));
        assert_eq!(targets.host.as_deref(), Some("web-1"), "host best-effort pré-rempli = host de l'alerte");
        let rb = pick_runbook_id(&conn, tac.as_deref(), None).unwrap();
        let key: String = conn.query_row("SELECT key FROM runbook WHERE id=?1", params![rb], |r| r.get(0)).unwrap();
        assert_eq!(key, "initial-access-exploit");
        // (b) discovery (T1046 port-scan) -> runbook de reconnaissance (alias).
        let ds = case_create_row(&conn, "a", "portscan", 3, "", None, 3);
        link_alert(&conn, ds, "T1046", None);
        let (tac2, _, _) = dominant_tactic_and_target(&conn, ds);
        assert_eq!(tac2.as_deref(), Some("discovery"));
        let rb2 = pick_runbook_id(&conn, tac2.as_deref(), None).unwrap();
        let key2: String = conn.query_row("SELECT key FROM runbook WHERE id=?1", params![rb2], |r| r.get(0)).unwrap();
        assert_eq!(key2, "recon-scan", "discovery route vers le runbook de reconnaissance");
        // (c) aucune alerte -> repli générique.
        let none = case_create_row(&conn, "a", "vide", 2, "", None, 3);
        let (tac3, _, _) = dominant_tactic_and_target(&conn, none);
        assert_eq!(tac3, None);
        let rb3 = pick_runbook_id(&conn, tac3.as_deref(), None).unwrap();
        let key3: String = conn.query_row("SELECT key FROM runbook WHERE id=?1", params![rb3], |r| r.get(0)).unwrap();
        assert_eq!(key3, "generic-default");
    }

    /// ATTACH : instancie les steps du runbook en case_step (fige le contenu + pré-remplit target) ; re-attach
    /// refusé ; timeline 'runbook' + ledger.
    #[test]
    fn attach_runbook_instantiates_steps() {
        let conn = test_db();
        seed_runbooks(&conn);
        let id = case_create_row(&conn, "a", "exploit", 4, "", None, 2);
        link_alert(&conn, id, "T1190", Some("web-1"));
        let rb = pick_runbook_id(&conn, Some("initial-access"), None).unwrap();
        let n = attach_runbook(&conn, id, rb, "bob", &PrefillTargets { host: Some("web-1".into()), ..Default::default() }).unwrap();
        assert!(n >= 4, "steps instanciées");
        let cnt: i64 = conn.query_row("SELECT COUNT(*) FROM case_step WHERE incident_id=?1", params![id], |r| r.get(0)).unwrap();
        assert_eq!(cnt, n);
        // #3 P3-A : le host best-effort pré-remplit les steps search/manual ; les steps response reçoivent leur
        // cible PAR action_kind (ici aucune src_ip/pid sur l'alerte -> blanc, JAMAIS le host mislabelé).
        let non_resp_total: i64 = conn.query_row("SELECT COUNT(*) FROM case_step WHERE incident_id=?1 AND step_kind!='response'", params![id], |r| r.get(0)).unwrap();
        let non_resp_target: i64 = conn.query_row("SELECT COUNT(*) FROM case_step WHERE incident_id=?1 AND step_kind!='response' AND target='web-1'", params![id], |r| r.get(0)).unwrap();
        assert_eq!(non_resp_target, non_resp_total, "steps search/manual pré-remplies au host best-effort");
        // response step référence l'enum fermé + cible blanche (pas de host mislabelé dans un ban_ip/kill_pid).
        let resp: i64 = conn.query_row("SELECT COUNT(*) FROM case_step WHERE incident_id=?1 AND step_kind='response'", params![id], |r| r.get(0)).unwrap();
        assert!(resp >= 1);
        let resp_blank: i64 = conn.query_row("SELECT COUNT(*) FROM case_step WHERE incident_id=?1 AND step_kind='response' AND COALESCE(target,'')=''", params![id], |r| r.get(0)).unwrap();
        assert_eq!(resp_blank, resp, "steps response sans src_ip/pid -> cible blanche (anti-mislabel)");
        // re-attach refusé.
        assert!(attach_runbook(&conn, id, rb, "bob", &PrefillTargets::default()).is_err(), "re-attach refusé (progression existante)");
        // timeline + ledger.
        let tl: i64 = conn.query_row("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='runbook'", params![id], |r| r.get(0)).unwrap();
        assert_eq!(tl, 1);
        let lg: i64 = conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind='case.runbook_attach'", [], |r| r.get(0)).unwrap();
        assert_eq!(lg, 1);
    }

    /// STEP ADVANCE : done/skip met à jour status+actor+note, écrit timeline 'step' + ledger, alimente la
    /// progression ET fige first_response_ts (MTTA) au 1er geste analyste ; anti-IDOR (step d'un autre case).
    #[test]
    fn step_advance_writes_timeline_ledger_and_mtta() {
        let conn = test_db();
        seed_runbooks(&conn);
        let id = case_create_row(&conn, "a", "exploit", 4, "", None, 2);
        // MTTA non encore figé.
        let fr0: Option<i64> = conn.query_row("SELECT first_response_ts FROM incident WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        assert_eq!(fr0, None);
        let rb = pick_runbook_id(&conn, Some("initial-access"), None).unwrap();
        attach_runbook(&conn, id, rb, "bob", &PrefillTargets::default()).unwrap();
        let first_step: i64 = conn.query_row("SELECT id FROM case_step WHERE incident_id=?1 ORDER BY ordinal LIMIT 1", params![id], |r| r.get(0)).unwrap();
        assert!(step_advance(&conn, id, first_step, "done", "bob", None));
        let (status, actor): (String, String) = conn.query_row("SELECT status,COALESCE(actor,'') FROM case_step WHERE id=?1", params![first_step], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((status.as_str(), actor.as_str()), ("done", "bob"));
        // skip avec note.
        let second: i64 = conn.query_row("SELECT id FROM case_step WHERE incident_id=?1 ORDER BY ordinal LIMIT 1 OFFSET 1", params![id], |r| r.get(0)).unwrap();
        assert!(step_advance(&conn, id, second, "skipped", "bob", Some("hors périmètre")));
        let note: Option<String> = conn.query_row("SELECT note FROM case_step WHERE id=?1", params![second], |r| r.get(0)).unwrap();
        assert_eq!(note.as_deref(), Some("hors périmètre"));
        // progression.
        let js = case_steps_json(&conn, id);
        assert_eq!(js["progress"]["done"], json!(1));
        assert_eq!(js["progress"]["skipped"], json!(1));
        // timeline 'step' (attach 'runbook' déjà écrit) + ledger case.step.
        let steps_tl: i64 = conn.query_row("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='step'", params![id], |r| r.get(0)).unwrap();
        assert_eq!(steps_tl, 2);
        let lg: i64 = conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind='case.step'", [], |r| r.get(0)).unwrap();
        assert_eq!(lg, 2);
        // MTTA figé (le 1er geste de runbook/step = 1re réponse analyste).
        let fr1: Option<i64> = conn.query_row("SELECT first_response_ts FROM incident WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        assert!(fr1.is_some(), "first_response_ts figé (MTTA)");
        // anti-IDOR : la step d'un AUTRE case ne peut être avancée via cet id.
        let other = case_create_row(&conn, "a", "autre", 2, "", None, 3);
        assert!(!step_advance(&conn, other, first_step, "done", "eve", None), "step d'un autre case refusée");
        // statut invalide refusé.
        assert!(!step_advance(&conn, id, first_step, "bogus", "bob", None));
    }

    /// RUN SEARCH : la résolution substitue la cible, recompile (FERMÉ) et renvoie le GXQL ; valeur interdite
    /// refusée ; step non-search refusée. (Aucune exécution — juste de la navigation, comme workflow_action.)
    #[test]
    fn step_search_resolve_reuses_closed_compiler() {
        let conn = test_db();
        seed_runbooks(&conn);
        let id = case_create_row(&conn, "a", "recon", 3, "", None, 3);
        link_alert(&conn, id, "T1595", Some("edge-1"));
        let rb = pick_runbook_id(&conn, Some("reconnaissance"), None).unwrap();
        attach_runbook(&conn, id, rb, "bob", &PrefillTargets { host: Some("203.0.113.7".into()), ..Default::default() }).unwrap();
        let search_step: i64 = conn.query_row("SELECT id FROM case_step WHERE incident_id=?1 AND step_kind='search' ORDER BY ordinal LIMIT 1", params![id], |r| r.get(0)).unwrap();
        // défaut = cible figée.
        let soql = resolve_step_search(&conn, id, search_step, None).unwrap();
        assert!(soql.contains("203.0.113.7"), "cible substituée");
        assert!(!soql.contains("$target$"), "placeholder résolu");
        // override explicite.
        let soql2 = resolve_step_search(&conn, id, search_step, Some("198.51.100.4")).unwrap();
        assert!(soql2.contains("198.51.100.4"));
        // valeur avec caractère interdit -> refus (anti-injection).
        assert!(resolve_step_search(&conn, id, search_step, Some("a | delete")).is_err());
        // step non-search -> refus.
        let resp_step: i64 = conn.query_row("SELECT id FROM case_step WHERE incident_id=?1 AND step_kind='response' ORDER BY ordinal LIMIT 1", params![id], |r| r.get(0)).unwrap();
        assert!(resolve_step_search(&conn, id, resp_step, None).is_err(), "step response n'est pas une recherche");
    }

    /// PARITÉ MODE 0 : un case ORDINAIRE (jamais élevé, aucun runbook) se comporte EXACTEMENT comme aujourd'hui —
    /// aucune ligne case_step, tier NULL, case_get_json inchangé (n'expose PAS de champ incident), et la
    /// projection CLIENT-READ ne fuit NI incident_tier NI steps.
    #[test]
    fn mode0_parity_and_client_projection_no_leak() {
        let conn = test_db();
        seed_runbooks(&conn); // seed présent mais AUCUN runbook attaché
        let id = case_create_row(&conn, "alice", "ordinaire", 2, "rien", None, 3);
        // aucune step, tier NULL.
        let cs: i64 = conn.query_row("SELECT COUNT(*) FROM case_step WHERE incident_id=?1", params![id], |r| r.get(0)).unwrap();
        assert_eq!(cs, 0);
        // case_get_json n'expose PAS de clé incident (le SELECT reste l'existant).
        let c = case_get_json(&conn, id, now()).unwrap();
        assert!(c.get("incident_tier").is_none(), "case_get_json n'expose pas incident_tier (parité)");
        assert!(c.get("steps").is_none());
        // case_steps_json d'un case sans runbook = vide (progress 0/0).
        let js = case_steps_json(&conn, id);
        assert_eq!(js["progress"]["total"], json!(0));
        assert!(js["runbook"].is_null());
        // ÉLÈVE + attache, puis vérifie que la projection CLIENT ne fuit toujours rien.
        incident_apply_tier(&conn, id, "bob", Some(1), Some("secret-type"), Some("secret-cmd"));
        let rb = pick_runbook_id(&conn, None, None).unwrap();
        attach_runbook(&conn, id, rb, "bob", &PrefillTargets::default()).unwrap();
        let masks = guatx_core::soql::FieldMaskSet::new();
        let cv = client_case_get_json(&conn, ":memory:", &masks, id, now()).unwrap();
        let blob = cv.to_string();
        for leak in ["incident_tier", "secret-type", "secret-cmd", "case_step", "runbook", "commander"] {
            assert!(!blob.contains(leak), "la projection client NE DOIT PAS contenir '{leak}' : {blob}");
        }
        // la timeline client reste l'allowlist de cycle de vie (jamais 'incident'/'runbook'/'step').
        if let Some(items) = cv.get("timeline").and_then(|t| t.as_array()) {
            for it in items {
                let ev = it.get("event").and_then(|v| v.as_str()).unwrap_or("");
                assert!(matches!(ev, "created" | "status" | "sla" | "merge"), "kind non-cycle-de-vie fuite : {ev}");
            }
        }
    }

    // ============================================================================================
    // #3 PHASE 3 — Part A : CIBLES DE RÉPONSE STRUCTURÉES. Capture best-effort de src_ip/pid/host à la création
    // d'alerte (moteurs row-aware) + pré-remplissage PAR action_kind au wizard (ban_ip->src_ip, kill_pid->pid+host,
    // stop_service->blanc). Anti-mislabel (NULL si ambigu), validé par action_valid_ctx, jamais auto-joué, jamais
    // projeté au client. Réutilise run_advanced_rules/run_correlations, dominant_tactic_and_target, attach_runbook.
    // ============================================================================================

    /// Helper : lie une alerte STRUCTURÉE (mitre + src_ip/pid/host optionnels) à un case.
    fn link_alert_struct(conn: &Connection, case_id: i64, mitre: &str, src_ip: Option<&str>, pid: Option<&str>, host: Option<&str>) {
        conn.execute("INSERT INTO alert(ts,rule,severity,title,status,mitre,src_ip,pid,host) VALUES(?1,'r',3,'a','new',?2,?3,?4,?5)",
            params![now(), mitre, src_ip, pid, host]).unwrap();
        let aid = conn.last_insert_rowid();
        case_add_item(conn, case_id, now(), "alert", "sys", "alerte liée", Some(&format!("alert:{aid}")));
    }

    /// Helper : un runbook custom avec UNE step response de `kind` donné + une step search (pour la parité host).
    fn attach_response_runbook(conn: &Connection, case_id: i64, action: &str, targets: &PrefillTargets) -> i64 {
        let steps = vec![
            ("triage".to_string(), "Chercher".to_string(), "".to_string(), "search".to_string(), Some("search src_ip=$target$ | stats count by source".to_string()), None),
            ("containment".to_string(), "Répondre".to_string(), "".to_string(), "response".to_string(), None, Some(action.to_string())),
        ];
        let rb = create_custom_runbook(conn, &format!("rb-{action}"), "*", "", "", &steps, true).unwrap();
        incident_apply_tier(conn, case_id, "bob", Some(1), None, None);
        attach_runbook(conn, case_id, rb, "bob", targets).unwrap();
        rb
    }

    /// CAPTURE MOTEUR (advanced/throttle) : une règle throttlée par `src_ip` peuple `alert.src_ip` = la valeur de
    /// l'IP franchissante ; le wizard pré-remplit ALORS la step `ban_ip` avec cette IP (chemin ordonnanceur réel).
    #[test]
    fn p3a_advanced_rule_captures_src_ip_and_wizard_prefills_ban_ip() {
        let _tmpg1 = crate::tmp_possede::TmpPossede::neuf("p3a-adv");
        let path = _tmpg1.sous("plume.db").chemin().to_path_buf();
        let p = path.to_string_lossy().to_string();
        let t = now() - 10; // en fenêtre (window_s=600)
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            // règle AVANCÉE : throttle_field='src_ip' -> une unité de tir par IP distincte ; la requête projette
            // src_ip (group-by) et NE collapse PAS en scalaire (l'ordonnanceur extrait le dernier champ=count).
            w.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed,throttle_field) \
                 VALUES('exploit web par IP',1,'search source=web status>=500 | stats count by src_ip | where count > 10',1,'>',0.0,4,300,600,'T1190',2,'src_ip')",
                [],
            ).unwrap();
            for i in 0..24 {
                w.execute("INSERT INTO event(ts,source,severity,src_ip,fields,dedup) VALUES(?1,'web',4,'9.9.9.9','{\"status\":\"500\"}',?2)", params![t, format!("s5-{i}")]).unwrap();
            }
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_advanced_rules(&db, &p);
        {
            let c = db.lock();
            // l'alerte porte l'IP structurée capturée (pas seulement le titre).
            let (nalert, sip): (i64, Option<String>) = c.query_row(
                "SELECT COUNT(*), MAX(src_ip) FROM alert", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            assert_eq!(nalert, 1, "run_advanced_rules lève 1 alerte (une IP franchissante)");
            assert_eq!(sip.as_deref(), Some("9.9.9.9"), "alert.src_ip capturé depuis le champ de throttle");
            // WIZARD : lie l'alerte à un case, attache un runbook ban_ip -> la step ban_ip pré-remplit l'IP.
            let aid: i64 = c.query_row("SELECT id FROM alert", [], |r| r.get(0)).unwrap();
            let case_id = case_create_row(&c, "alice", "exploit", 4, "", None, 2);
            case_add_item(&c, case_id, now(), "alert", "sys", "liée", Some(&format!("alert:{aid}")));
            let (_, _, targets) = dominant_tactic_and_target(&c, case_id);
            assert_eq!(targets.src_ip.as_deref(), Some("9.9.9.9"));
            let rb = attach_response_runbook(&c, case_id, "ban_ip", &targets);
            let _ = rb;
            let ban_target: String = c.query_row("SELECT COALESCE(target,'') FROM case_step WHERE incident_id=?1 AND action_kind='ban_ip'", params![case_id], |r| r.get(0)).unwrap();
            assert_eq!(ban_target, "9.9.9.9", "step ban_ip pré-remplie avec la src_ip capturée");
            // la step search reçoit le host best-effort (ici NULL) -> blanc (parité), PAS l'IP.
        }
        let _ = std::fs::remove_file(&p);
    }

    /// ANTI-MISLABEL (moteur) : un throttle par un champ NON-entité (`source`) ne remplit AUCUNE colonne
    /// structurée -> alert.src_ip/pid restent NULL (on ne fait pas passer un group-by arbitraire pour une IP).
    #[test]
    fn p3a_ambiguous_groupby_leaves_structured_null() {
        let _tmpg2 = crate::tmp_possede::TmpPossede::neuf("p3a-amb");
        let path = _tmpg2.sous("plume.db").chemin().to_path_buf();
        let p = path.to_string_lossy().to_string();
        let t = now() - 10;
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            w.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed,throttle_field) \
                 VALUES('5xx par source',1,'search status>=500 | stats count by source | where count > 10',1,'>',0.0,3,300,600,'T1190',2,'source')",
                [],
            ).unwrap();
            for i in 0..24 {
                w.execute("INSERT INTO event(ts,source,severity,src_ip,fields,dedup) VALUES(?1,'web',3,'9.9.9.9','{\"status\":\"500\"}',?2)", params![t, format!("a-{i}")]).unwrap();
            }
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_advanced_rules(&db, &p);
        {
            let c = db.lock();
            let (n, sip, pid): (i64, Option<String>, Option<String>) = c.query_row(
                "SELECT COUNT(*), MAX(src_ip), MAX(pid) FROM alert", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
            assert_eq!(n, 1, "alerte levée (source franchissante)");
            assert_eq!(sip, None, "group-by 'source' NE mislabel PAS une src_ip");
            assert_eq!(pid, None, "ni un pid");
        }
        let _ = std::fs::remove_file(&p);
    }

    /// CAPTURE MOTEUR (corrélation) : une corrélation keyée `src_ip` (mode alerte) range l'entité dans alert.src_ip.
    #[test]
    fn p3a_correlation_captures_src_ip() {
        let _tmpg3 = crate::tmp_possede::TmpPossede::neuf("p3a-corr");
        let path = _tmpg3.sous("plume.db").chemin().to_path_buf();
        let p = path.to_string_lossy().to_string();
        let t = now() - 10;
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            // corrélation MODE ALERTE (risk_score=0), 1 étape keyée src_ip, min_count=1.
            w.execute(
                "INSERT INTO correlation(name,enabled,key_field,entity_type,steps,window_s,interval_s,severity,mitre,risk_score,managed,created) \
                 VALUES('recon puis exploit',1,'src_ip','ip','[{\"query\":\"search source=web\",\"min_count\":1}]',3600,60,3,'T1190',0,2,?1)",
                params![now()],
            ).unwrap();
            for i in 0..3 {
                w.execute("INSERT INTO event(ts,source,severity,src_ip,fields,dedup) VALUES(?1,'web',3,'203.0.113.5','{}',?2)", params![t, format!("c-{i}")]).unwrap();
            }
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_correlations(&db, &p);
        {
            let c = db.lock();
            let sip: Option<String> = c.query_row("SELECT src_ip FROM alert WHERE rule LIKE 'corr.%'", [], |r| r.get(0)).ok().flatten();
            assert_eq!(sip.as_deref(), Some("203.0.113.5"), "corrélation keyée src_ip -> alert.src_ip capturé");
        }
        let _ = std::fs::remove_file(&p);
    }

    /// WIZARD kill_pid : une alerte portant pid+host pré-remplit la step kill_pid avec le PID + fige l'hôte
    /// d'exécution (case_step.host). La step search reçoit le host best-effort.
    #[test]
    fn p3a_wizard_kill_pid_prefills_pid_and_host() {
        let conn = test_db();
        let case_id = case_create_row(&conn, "alice", "process malveillant", 3, "", None, 2);
        link_alert_struct(&conn, case_id, "T1059", None, Some("4242"), Some("db-01"));
        let (_, _, targets) = dominant_tactic_and_target(&conn, case_id);
        assert_eq!(targets.pid.as_deref(), Some("4242"));
        assert_eq!(targets.host.as_deref(), Some("db-01"));
        attach_response_runbook(&conn, case_id, "kill_pid", &targets);
        let (tgt, host): (String, String) = conn.query_row(
            "SELECT COALESCE(target,''),COALESCE(host,'') FROM case_step WHERE incident_id=?1 AND action_kind='kill_pid'", params![case_id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(tgt, "4242", "step kill_pid pré-remplie avec le pid");
        assert_eq!(host, "db-01", "hôte d'exécution figé sur la step kill_pid");
        // surface JSON expose l'hôte.
        let js = case_steps_json(&conn, case_id);
        let kp = js["steps"].as_array().unwrap().iter().find(|s| s["action_kind"] == "kill_pid").unwrap();
        assert_eq!(kp["host"], "db-01");
    }

    /// VALIDATION prefill : une src_ip GARBAGE (non-IPv4) est REJETÉE par action_valid_ctx -> step ban_ip blanche
    /// (jamais une cible invalide/trompeuse) ; un pid trop bas (<=300) est rejeté de même.
    #[test]
    fn p3a_prefill_rejects_invalid_target_blank() {
        let conn = test_db();
        // src_ip garbage.
        let c1 = case_create_row(&conn, "a", "x", 3, "", None, 3);
        link_alert_struct(&conn, c1, "T1190", Some("pas-une-ip"), None, None);
        let (_, _, tg1) = dominant_tactic_and_target(&conn, c1);
        attach_response_runbook(&conn, c1, "ban_ip", &tg1);
        let b1: String = conn.query_row("SELECT COALESCE(target,'') FROM case_step WHERE incident_id=?1 AND action_kind='ban_ip'", params![c1], |r| r.get(0)).unwrap();
        assert_eq!(b1, "", "src_ip invalide -> ban_ip blanc (anti-cible-trompeuse)");
        // pid trop bas.
        let c2 = case_create_row(&conn, "a", "y", 3, "", None, 3);
        link_alert_struct(&conn, c2, "T1059", None, Some("42"), Some("h"));
        let (_, _, tg2) = dominant_tactic_and_target(&conn, c2);
        attach_response_runbook(&conn, c2, "kill_pid", &tg2);
        let b2: String = conn.query_row("SELECT COALESCE(target,'') FROM case_step WHERE incident_id=?1 AND action_kind='kill_pid'", params![c2], |r| r.get(0)).unwrap();
        assert_eq!(b2, "", "pid<=300 rejeté par action_valid_ctx -> blanc");
        // src_ip VALIDE passe (contrôle positif).
        let c3 = case_create_row(&conn, "a", "z", 3, "", None, 3);
        link_alert_struct(&conn, c3, "T1190", Some("198.51.100.7"), None, None);
        let (_, _, tg3) = dominant_tactic_and_target(&conn, c3);
        attach_response_runbook(&conn, c3, "ban_ip", &tg3);
        let b3: String = conn.query_row("SELECT COALESCE(target,'') FROM case_step WHERE incident_id=?1 AND action_kind='ban_ip'", params![c3], |r| r.get(0)).unwrap();
        assert_eq!(b3, "198.51.100.7", "src_ip valide -> pré-remplie");
    }

    /// PARITÉ MODE 0 : une alerte SANS colonnes structurées (moteur scalaire de base) -> src_ip/pid NULL ->
    /// toutes les cibles response blanches -> comportement analyste-tape-la-cible d'aujourd'hui (inchangé).
    #[test]
    fn p3a_basic_scalar_alert_blank_prefill_parity() {
        let conn = test_db();
        let case_id = case_create_row(&conn, "a", "scan", 3, "", None, 3);
        link_alert(&conn, case_id, "T1190", None); // aucune colonne structurée (comme run_due_rules)
        let (_, _, targets) = dominant_tactic_and_target(&conn, case_id);
        assert_eq!(targets.src_ip, None);
        assert_eq!(targets.pid, None);
        attach_response_runbook(&conn, case_id, "ban_ip", &targets);
        let blank: String = conn.query_row("SELECT COALESCE(target,'') FROM case_step WHERE incident_id=?1 AND action_kind='ban_ip'", params![case_id], |r| r.get(0)).unwrap();
        assert_eq!(blank, "", "alerte scalaire -> cible blanche (parité mode 0)");
    }

    /// ISOLATION CLIENT : les colonnes structurées (src_ip/pid) NE FUITENT JAMAIS dans la projection client-read
    /// (Part B différée) — même quand l'alerte dominante les porte et est liée à l'incident.
    #[test]
    fn p3a_client_projection_excludes_src_ip_pid() {
        let conn = test_db();
        let case_id = case_create_row(&conn, "alice", "case", 3, "", None, 3);
        link_alert_struct(&conn, case_id, "T1190", Some("203.0.113.99"), Some("31337"), Some("secret-host-01"));
        incident_apply_tier(&conn, case_id, "bob", Some(1), None, None);
        let rb = create_custom_runbook(&conn, "rb", "*", "", "", &[("containment".to_string(), "Ban".to_string(), "".to_string(), "response".to_string(), None, Some("ban_ip".to_string()))], true).unwrap();
        let (_, _, targets) = dominant_tactic_and_target(&conn, case_id);
        attach_runbook(&conn, case_id, rb, "bob", &targets).unwrap();
        let masks = guatx_core::soql::FieldMaskSet::new();
        let cv = client_case_get_json(&conn, ":memory:", &masks, case_id, now()).unwrap();
        let blob = cv.to_string();
        for leak in ["203.0.113.99", "31337", "secret-host-01", "src_ip", "case_step"] {
            assert!(!blob.contains(leak), "la projection client NE DOIT PAS contenir '{leak}' : {blob}");
        }
    }

    // ============================================================================================
    // #3 INCIDENTS — PHASE 2 : runbooks CUSTOM (bring-your-own), protection de la baseline managée,
    // gabarits managés supplémentaires, adaptivité NIVEAU-TECHNIQUE. Réutilise le compilateur GXQL FERMÉ
    // (validate_search_template), l'enum d'action FERMÉ (action_kind_valid), la doctrine detection_override
    // (enable/disable survit au re-seed), route_min_role (admin-only), pick_runbook_id (technique>tactique).
    // ============================================================================================

    /// Helper : 3 étapes valides (search compilable + response enum + manual).
    fn valid_steps() -> Vec<(String, String, String, String, Option<String>, Option<String>)> {
        vec![
            ("triage".into(), "Confirmer".into(), "guide".into(), "search".into(), Some("search host=$target$ | stats count by source".into()), None),
            ("containment".into(), "Bannir".into(), "".into(), "response".into(), None, Some("ban_ip".into())),
            ("recovery".into(), "Clore".into(), "".into(), "manual".into(), None, None),
        ]
    }

    /// ADAPTIVITÉ NIVEAU-TECHNIQUE : technique > tactique > générique, DÉTERMINISTE. technique=None reproduit
    /// exactement le repli Phase 1 (parité). Sous-technique normalisée. Alias discovery->reconnaissance intact.
    #[test]
    fn autopick_technique_over_tactic() {
        let conn = test_db();
        seed_runbooks(&conn);
        let key_of = |rb: i64| -> String { conn.query_row("SELECT key FROM runbook WHERE id=?1", params![rb], |r| r.get(0)).unwrap() };
        // (1) T1110 : runbook TECHNIQUE gagne sur la tactique credential-access.
        assert_eq!(key_of(pick_runbook_id(&conn, Some("credential-access"), Some("T1110")).unwrap()), "technique-bruteforce-t1110");
        // sous-technique normalisée -> même runbook technique.
        assert_eq!(key_of(pick_runbook_id(&conn, Some("credential-access"), Some("T1110.001")).unwrap()), "technique-bruteforce-t1110");
        // (2) technique SANS runbook dédié -> repli TACTIQUE.
        assert_eq!(key_of(pick_runbook_id(&conn, Some("credential-access"), Some("T9999")).unwrap()), "credential-access-bruteforce");
        // (3) technique=None -> tactique (PARITÉ Phase 1, inchangé).
        assert_eq!(key_of(pick_runbook_id(&conn, Some("credential-access"), None).unwrap()), "credential-access-bruteforce");
        // (4) T1083 host-discovery : technique gagne ; l'alias discovery->recon reste pour le SCAN réseau (T1046).
        assert_eq!(key_of(pick_runbook_id(&conn, Some("discovery"), Some("T1083")).unwrap()), "technique-host-discovery-t1083");
        assert_eq!(key_of(pick_runbook_id(&conn, Some("discovery"), None).unwrap()), "recon-scan", "T1046/discovery route toujours vers recon (alias intact)");
        // (5) nouvelles tactiques managées.
        assert_eq!(key_of(pick_runbook_id(&conn, Some("persistence"), None).unwrap()), "persistence-mechanism");
        assert_eq!(key_of(pick_runbook_id(&conn, Some("exfiltration"), None).unwrap()), "exfiltration");
        // (6) rien ne matche -> générique.
        assert_eq!(key_of(pick_runbook_id(&conn, Some("resource-development"), Some("T9999")).unwrap()), "generic-default");
    }

    /// GABARITS MANAGÉS SUPPLÉMENTAIRES : le seed pose >=15 runbooks managés dont >=2 niveau-technique ; tous les
    /// gabarits search compilent (verrou du compilateur fermé, déjà couvert par seed_runbook_searches_compile).
    #[test]
    fn phase2_managed_templates_seeded() {
        let conn = test_db();
        seed_runbooks(&conn);
        let managed: i64 = conn.query_row("SELECT COUNT(*) FROM runbook WHERE managed=1", [], |r| r.get(0)).unwrap();
        assert!(managed >= 15, "au moins 15 runbooks managés (6 Phase 1 + 9 Phase 2), trouvé {managed}");
        let tech: i64 = conn.query_row("SELECT COUNT(*) FROM runbook WHERE managed=1 AND match_kind='technique'", [], |r| r.get(0)).unwrap();
        assert!(tech >= 2, "au moins 2 runbooks niveau-technique");
    }

    /// CRUD CUSTOM (cœur) : create (managed=0, key préfixée custom-), update (remplace étapes), clone (copie
    /// managed=0), delete scopé managed=0.
    #[test]
    fn custom_runbook_crud_core() {
        let conn = test_db();
        seed_runbooks(&conn);
        let steps = valid_steps();
        let id = create_custom_runbook(&conn, "Mon Runbook", "tactic", "execution", "desc", &steps, true).unwrap();
        let (mgd, key, active, name): (i64, String, i64, String) = conn.query_row("SELECT managed,key,active,name FROM runbook WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap();
        assert_eq!(mgd, 0, "custom = managed 0");
        assert!(key.starts_with("custom-"), "key custom préfixée (pas de masquerade managé) : {key}");
        assert_eq!(active, 1);
        assert_eq!(name, "Mon Runbook");
        let sc: i64 = conn.query_row("SELECT COUNT(*) FROM runbook_step WHERE runbook_id=?1", params![id], |r| r.get(0)).unwrap();
        assert_eq!(sc, 3);
        // UPDATE : remplace name/match/étapes.
        let steps2 = vec![("triage".to_string(), "Seule".to_string(), "".to_string(), "manual".to_string(), None, None)];
        update_custom_runbook(&conn, id, "Mon Runbook v2", "technique", "T1059", "d2", &steps2).unwrap();
        let (name2, mk, mkey): (String, String, String) = conn.query_row("SELECT name,match_kind,match_key FROM runbook WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!((name2.as_str(), mk.as_str(), mkey.as_str()), ("Mon Runbook v2", "technique", "T1059"));
        let sc2: i64 = conn.query_row("SELECT COUNT(*) FROM runbook_step WHERE runbook_id=?1", params![id], |r| r.get(0)).unwrap();
        assert_eq!(sc2, 1, "étapes remplacées");
        // CLONE : copie managed=0, key distincte, étapes copiées.
        let cid = clone_runbook(&conn, id, Some("Cloné")).unwrap();
        assert_ne!(cid, id);
        let (cmgd, ckey, cname, csc): (i64, String, String, i64) = conn.query_row("SELECT managed,key,name,(SELECT COUNT(*) FROM runbook_step WHERE runbook_id=?1) FROM runbook WHERE id=?1", params![cid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap();
        assert_eq!(cmgd, 0);
        assert_ne!(ckey, key);
        assert_eq!(cname, "Cloné");
        assert_eq!(csc, 1, "étapes clonées");
        // DELETE scopé managed=0 : le custom part.
        let n = conn.execute("DELETE FROM runbook_step WHERE runbook_id=?1", params![id]).unwrap();
        assert!(n >= 1);
        let d = conn.execute("DELETE FROM runbook WHERE id=?1 AND managed=0", params![id]).unwrap();
        assert_eq!(d, 1, "custom supprimable");
    }

    /// PROTECTION BASELINE MANAGÉE : update d'un managé=1 REFUSÉ ; delete scopé managed=0 n'affecte pas un managé ;
    /// clone d'un managé -> copie managed=0 ; enable/disable (override) PERSISTE et SURVIT au re-seed (jamais
    /// ré-activé), le re-seed ne DUPLIQUE rien ni ne clobber une personnalisation custom.
    #[test]
    fn managed_protection_and_reseed_idempotent() {
        let conn = test_db();
        seed_runbooks(&conn);
        let mid: i64 = conn.query_row("SELECT id FROM runbook WHERE managed=1 AND key='recon-scan'", [], |r| r.get(0)).unwrap();
        // UPDATE managé -> Err (baseline git immuable en place).
        assert!(update_custom_runbook(&conn, mid, "x", "*", "", "", &valid_steps()).is_err(), "managé non éditable en place");
        // DELETE scopé managed=0 -> 0 ligne (le managé survit).
        let d = conn.execute("DELETE FROM runbook WHERE id=?1 AND managed=0", params![mid]).unwrap();
        assert_eq!(d, 0, "managé non supprimable via le scope custom");
        assert!(conn.query_row("SELECT 1 FROM runbook WHERE id=?1", params![mid], |_| Ok(())).is_ok());
        // CLONE d'un managé -> copie managed=0.
        let cid = clone_runbook(&conn, mid, None).unwrap();
        let cmgd: i64 = conn.query_row("SELECT managed FROM runbook WHERE id=?1", params![cid], |r| r.get(0)).unwrap();
        assert_eq!(cmgd, 0, "clone d'un managé = custom");
        // DISABLE (override admin) le managé + crée une personnalisation custom.
        conn.execute("UPDATE runbook SET active=0 WHERE id=?1", params![mid]).unwrap();
        let custom_id = create_custom_runbook(&conn, "MaPerso", "tactic", "impact", "d", &valid_steps(), true).unwrap();
        let before: i64 = conn.query_row("SELECT COUNT(*) FROM runbook", [], |r| r.get(0)).unwrap();
        // RE-SEED (boot suivant, nouveau binaire) : INSERT-si-absent par key.
        seed_runbooks(&conn);
        let after: i64 = conn.query_row("SELECT COUNT(*) FROM runbook", [], |r| r.get(0)).unwrap();
        assert_eq!(after, before, "re-seed ne DUPLIQUE aucun runbook (idempotent par key)");
        // le managé désactivé N'EST PAS ré-activé.
        let still: i64 = conn.query_row("SELECT active FROM runbook WHERE id=?1", params![mid], |r| r.get(0)).unwrap();
        assert_eq!(still, 0, "re-seed ne ressuscite pas l'état actif d'un managé désactivé");
        // la personnalisation custom SURVIT intacte.
        assert!(conn.query_row("SELECT 1 FROM runbook WHERE id=?1 AND name='MaPerso'", params![custom_id], |_| Ok(())).is_ok(), "custom non clobber par le re-seed");
    }

    /// AUTHOR-TIME — CLÔTURE du gabarit GXQL de step 'search'. Le compilateur FERMÉ (validate_search_template) est
    /// la garantie : (a) un gabarit valide compile ; (b) tout gabarit ACCEPTÉ compile en UN SEUL `SELECT ... FROM
    /// event` sûr — un texte ressemblant à du SQL brut (`; DROP`, `'; DELETE`, `UNION SELECT token_hash`) DÉGRADE
    /// en termes de recherche plein-texte ÉCHAPPÉS (`message LIKE '%...%'`), jamais une 2e instruction ni un accès
    /// hors-vue `event` -> AUCUNE injection possible ; (c) une commande GXQL inconnue / un pipe malformé est REJETÉ.
    /// (Le temps-résolution est couvert par step_search_resolve_reuses_closed_compiler : value_scalar_ok + recompile.)
    #[test]
    fn author_time_search_template_closure() {
        // (a) gabarits valides -> Ok (standalone ou préfixé search).
        for good in [
            "search host=$target$ | stats count by source",
            "search src_ip=$target$ severity>=2 | stats count by rule",
            "host=$target$",
        ] {
            assert!(validate_search_template(good).is_ok(), "gabarit valide rejeté : {good}");
        }
        // (b) CLÔTURE — un gabarit « SQL-looking » est ACCEPTÉ mais compile en UN SELECT sûr sur la vue `event`,
        //     payload échappé en LIKE ; jamais une 2e instruction ni un autre FROM. Prouve l'impossibilité d'injecter.
        for inj in [
            "host=$target$; DROP TABLE alert",
            "'; DELETE FROM incident; --",
            "$target$ ) UNION SELECT token_hash FROM token",
        ] {
            let dummy = inj.replace("$target$", "x1");
            assert!(validate_search_template(inj).is_ok(), "gabarit dégradable rejeté : {inj}");
            let sql = guatx_core::soql::to_sql(&dummy, 0, 0, &guatx_core::soql::Schema::events())
                .or_else(|_| guatx_core::soql::to_sql(&format!("search {dummy}"), 0, 0, &guatx_core::soql::Schema::events()))
                .expect("compile");
            assert!(sql.trim_start().to_ascii_uppercase().starts_with("SELECT"), "sortie non-SELECT : {sql}");
            assert!(sql.contains("FROM event"), "FROM autre que la vue fermée event : {sql}");
            assert!(!sql.contains("; DROP") && !sql.contains("; DELETE") && !sql.contains(") UNION"), "instruction injectée : {sql}");
            assert!(!sql.contains("token_hash FROM token"), "accès hors-event : {sql}");
        }
        // (c) commande GXQL inconnue / pipe malformé -> REJET.
        for bad in [
            "search host=$target$ | delete",
            "$target$ | drop",
            "host=$target$ | inputlookup secret",
            "host=$target$ || 1=1 |||| garbage",
        ] {
            assert!(validate_search_template(bad).is_err(), "commande GXQL invalide ACCEPTÉE à tort : {bad}");
        }
    }

    /// AUTHOR-TIME — step 'response' : SEUL l'ENUM D'ACTION FERMÉ est accepté (action_kind_valid) ; tout le reste
    /// (script/commande/action inconnue) est REJETÉ. Aucune exécution n'est accordée (elle reste /api/actions).
    #[test]
    fn author_time_response_enum_only() {
        for good in ["ban_ip", "unban_ip", "kill_pid", "stop_service"] {
            assert!(action_kind_valid(good).is_ok(), "action enum rejetée : {good}");
        }
        for bad in ["exec", "rm -rf /", "curl evil", "ban_ip; rm", "notify", "run_script", ""] {
            assert!(action_kind_valid(bad).is_err(), "action hors-enum ACCEPTÉE à tort : {bad}");
        }
        // enums de phase / step_kind fermés aussi.
        assert!(valid_phase("triage") && valid_phase("recovery") && !valid_phase("pwn"));
        assert!(valid_step_kind("search") && valid_step_kind("response") && valid_step_kind("manual") && !valid_step_kind("exec"));
    }

    /// AUTZ : /api/runbooks* = ADMIN toutes méthodes (route_min_role section 3, GET compris) ; le picker/attach du
    /// wizard (/api/cases/{id}/runbook(s)) reste editor+/viewer+ (inchangé) -> un viewer/editor n'accède PAS à
    /// l'authoring mais garde le wizard.
    #[test]
    fn runbook_authoring_routes_admin_only() {
        for (path, m) in [("/api/runbooks", true), ("/api/runbooks", false), ("/api/runbooks/5", true), ("/api/runbooks/5", false), ("/api/runbooks/5/enabled", true), ("/api/runbooks/5/clone", true)] {
            assert_eq!(route_min_role(path, m), MinRole::Admin, "{path} (mutating={m}) doit être admin-only");
        }
        assert!(!role_satisfies("editor", MinRole::Admin), "editor n'atteint PAS l'authoring runbook");
        assert!(!role_satisfies("viewer", MinRole::Admin), "viewer non plus");
        // le wizard reste accessible : attach = editor+ (mutation /api/cases/*), lecture = viewer+.
        assert_eq!(route_min_role("/api/cases/5/runbook", true), MinRole::Write, "attach runbook (wizard) reste editor+");
        assert_eq!(route_min_role("/api/cases/5/runbooks", false), MinRole::Read, "picker (wizard) reste viewer+");
    }

    /// DoS : le quota de runbooks custom (RUNBOOK_MAX_CUSTOM) est appliqué par create_custom_runbook.
    #[test]
    fn custom_runbook_quota_enforced() {
        let conn = test_db();
        // remplit jusqu'au quota (noms distincts -> keys sans collision, O(n)).
        let mut last = Ok(0);
        for i in 0..250 {
            last = create_custom_runbook(&conn, &format!("rb{i}"), "*", "", "", &[("triage".to_string(), "s".to_string(), "".to_string(), "manual".to_string(), None, None)], true);
            if last.is_err() { break; }
        }
        assert!(last.is_err(), "le quota de runbooks custom finit par refuser la création");
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM runbook WHERE managed=0", [], |r| r.get(0)).unwrap();
        assert!(n <= 200, "jamais plus de 200 customs, trouvé {n}");
    }

    /// CLIENT-READ NO-LEAK (custom) : un runbook CUSTOM attaché à un incident ne fuit JAMAIS dans la projection
    /// client (ni son nom, ni sa key, ni ses étapes).
    #[test]
    fn custom_runbook_client_projection_no_leak() {
        let conn = test_db();
        let id = case_create_row(&conn, "alice", "case", 3, "", None, 3);
        let secret_steps = vec![("triage".to_string(), "SECRET-STEP-TITLE".to_string(), "SECRET-GUIDE".to_string(), "manual".to_string(), None, None)];
        let rb = create_custom_runbook(&conn, "SECRET-CUSTOM-RB", "*", "", "", &secret_steps, true).unwrap();
        incident_apply_tier(&conn, id, "bob", Some(1), None, None);
        attach_runbook(&conn, id, rb, "bob", &PrefillTargets::default()).unwrap();
        let masks = guatx_core::soql::FieldMaskSet::new();
        let cv = client_case_get_json(&conn, ":memory:", &masks, id, now()).unwrap();
        let blob = cv.to_string();
        for leak in ["SECRET-CUSTOM-RB", "SECRET-STEP-TITLE", "SECRET-GUIDE", "custom-", "runbook", "case_step"] {
            assert!(!blob.contains(leak), "projection client fuit '{leak}' : {blob}");
        }
    }

    // ============================================================================================
    // #3 PHASE 3 — Part B : VISIBILITÉ CLIENT MINIMALE & SÛRE. La projection client gagne 3 champs ADDITIFS
    // (is_incident bool / phase coarse / acknowledged bool), tous dérivés de colonnes NON secrètes déjà
    // tenant-scopées. La denylist DURE reste fermée : tier brut, incident_type, commander, runbook, case_step,
    // GXQL, action_kind, notes, identité analyste, cross-tenant. Réutilise client_case_get_json/_list_json,
    // incident_apply_tier, create_custom_runbook, attach_runbook. ⚠ surface d'isolation sensible.
    // ============================================================================================

    /// Part B — ADDITIF + NO-LEAK : la projection client EXPOSE is_incident/phase/acknowledged, et NE FUIT AUCUN
    /// interne même avec runbook + steps custom + action de réponse + marqueurs SECRETS (type/commander/step/host).
    #[test]
    fn p3b_client_incident_view_additive_and_no_leak() {
        let conn = test_db();
        let masks = guatx_core::soql::FieldMaskSet::new();
        // (1) case ORDINAIRE (jamais élevé) : is_incident=false, phase coarse DÉGRADE proprement (status 'new'->ouvert),
        //     acknowledged=false. Parité mode 0 : rien d'autre ne change.
        let ord = case_create_row(&conn, "alice", "case ordinaire", 2, "resume", None, 3);
        let ov = client_case_get_json(&conn, ":memory:", &masks, ord, now()).unwrap();
        assert_eq!(ov["is_incident"], json!(false), "case ordinaire -> is_incident=false");
        assert_eq!(ov["phase"], json!("ouvert"), "phase coarse dégrade sur un case ordinaire");
        assert_eq!(ov["acknowledged"], json!(false), "pas de first_response -> acknowledged=false");
        // les champs pré-existants restent intacts (allowlist inchangée hormis l'additif).
        assert_eq!(ov["status"], json!("open"));
        assert!(ov.get("id").is_some() && ov.get("overdue").is_some());

        // (2) INCIDENT : élève (tier + type/commander SECRETS) + runbook CUSTOM (nom secret) avec step SECRET +
        //     action de réponse ; host secret pré-rempli. Marque acknowledged (first_response_ts).
        let id = case_create_row(&conn, "analyst_alice", "case incident", 3, "resume interne", Some("analyst_bob"), 1);
        incident_apply_tier(&conn, id, "analyst_bob", Some(2), Some("SECRET-INCIDENT-TYPE"), Some("SECRET-COMMANDER"));
        let secret_steps: Vec<NewStep> = vec![
            ("triage".into(), "SECRET-STEP-TITLE".into(), "SECRET-GUIDE".into(), "search".into(), Some("search src_ip=$target$ | stats count by source".into()), None),
            ("containment".into(), "SECRET-BAN-STEP".into(), "".into(), "response".into(), None, Some("ban_ip".into())),
        ];
        let rb = create_custom_runbook(&conn, "SECRET-RUNBOOK-NAME", "*", "", "", &secret_steps, true).unwrap();
        attach_runbook(&conn, id, rb, "analyst_bob", &PrefillTargets { host: Some("203.0.113.55".into()), ..Default::default() }).unwrap();
        conn.execute("UPDATE incident SET first_response_ts=?1 WHERE id=?2", params![now(), id]).unwrap();

        let cv = client_case_get_json(&conn, ":memory:", &masks, id, now()).unwrap();
        // ADDITIF présent : is_incident=true (le BOOL, pas le tier), phase coarse (string), acknowledged=true.
        assert_eq!(cv["is_incident"], json!(true), "case élevé -> is_incident=true");
        assert_eq!(cv["acknowledged"], json!(true), "first_response_ts posé -> acknowledged=true");
        assert!(cv["phase"].is_string(), "phase coarse présente (string)");
        // le tier BRUT (2) n'est JAMAIS exposé, ni comme champ, ni comme valeur.
        assert!(cv.get("incident_tier").is_none(), "tier brut jamais exposé comme champ");
        // DENYLIST DURE : ni valeur ni chaîne dérivable.
        let blob = cv.to_string();
        for leak in ["SECRET-INCIDENT-TYPE", "SECRET-COMMANDER", "SECRET-RUNBOOK-NAME", "SECRET-STEP-TITLE",
                     "SECRET-GUIDE", "SECRET-BAN-STEP", "203.0.113.55", "incident_tier", "incident_type",
                     "commander", "case_step", "runbook", "action_kind", "ban_ip", "src_ip", "$target$",
                     "analyst_bob", "analyst_alice", "resume interne"] {
            assert!(!blob.contains(leak), "projection client Part B fuit '{leak}' : {blob}");
        }
        // la timeline reste l'allowlist CYCLE-DE-VIE (jamais 'incident'/'runbook'/'step').
        if let Some(items) = cv.get("timeline").and_then(|t| t.as_array()) {
            for it in items {
                let ev = it.get("event").and_then(|v| v.as_str()).unwrap_or("");
                assert!(matches!(ev, "created" | "status" | "sla" | "merge"), "kind non-cycle-de-vie fuite : {ev}");
            }
        }
        // même vérité côté LISTE (mêmes 3 champs additifs, même non-fuite).
        let lst = client_cases_list_json(&conn, ":memory:", &masks, now(), "", 100, 0);
        let lblob = serde_json::to_string(&lst).unwrap();
        for leak in ["SECRET-INCIDENT-TYPE", "SECRET-COMMANDER", "SECRET-RUNBOOK-NAME", "SECRET-STEP-TITLE", "incident_tier", "commander"] {
            assert!(!lblob.contains(leak), "liste client Part B fuit '{leak}'");
        }
        let inc_row = lst["cases"].as_array().unwrap().iter().find(|c| c["id"].as_i64() == Some(id)).unwrap();
        assert_eq!(inc_row["is_incident"], json!(true), "la liste expose aussi is_incident");
        assert!(inc_row["phase"].is_string() && inc_row.get("acknowledged").is_some());
    }

    /// Part B — PHASE COARSE : chaque état de cycle de vie -> un bucket coarse, dérivé UNIQUEMENT de `status`
    /// (jamais d'une étape). 'contained' (état de case, pas étape) -> « contenu ». Aucune granularité d'étape.
    #[test]
    fn p3b_coarse_phase_from_status_only() {
        let conn = test_db();
        let masks = guatx_core::soql::FieldMaskSet::new();
        let id = case_create_row(&conn, "a", "c", 3, "", None, 2);
        let phase_now = |c: &Connection| client_case_get_json(c, ":memory:", &masks, id, now()).unwrap()["phase"].as_str().unwrap().to_string();
        for (st, want) in [("new", "ouvert"), ("triage", "ouvert"), ("in_progress", "en cours de traitement"),
                           ("waiting", "en attente"), ("contained", "contenu"), ("resolved", "résolu"), ("closed", "clôturé")] {
            conn.execute("UPDATE incident SET status=?1 WHERE id=?2", params![st, id]).unwrap();
            // 'contained'/'closed'/'resolved' mettent merged_into à NULL déjà ; le détail exige non-archivé/non-fusionné.
            assert_eq!(phase_now(&conn), want, "status '{st}' -> phase coarse '{want}'");
        }
    }

    /// Part B — TENANT-SCOPE : un client ne peut PAS voir le statut d'incident d'un AUTRE tenant. Isolation
    /// PAR-BASE : l'incident vit dans la base du tenant A ; ouvrir la base du tenant B (vide) et demander cet id
    /// -> None (aucun cross-tenant). Miroir de l'isolation /api/query & #60.
    #[test]
    fn p3b_tenant_scope_no_cross_tenant_incident() {
        let _tmpg4 = crate::tmp_possede::TmpPossede::neuf("p3b-tenantA");
        let pa = _tmpg4.sous("plume.db").chemin().to_path_buf();
        let _tmpg5 = crate::tmp_possede::TmpPossede::neuf("p3b-tenantB");
        let pb = _tmpg5.sous("plume.db").chemin().to_path_buf();
        let (pa, pb) = (pa.to_string_lossy().to_string(), pb.to_string_lossy().to_string());
        let mkdb = |p: &str| { let c = Connection::open(p).unwrap(); c.execute_batch(include_str!("../../../db/schema.sql")).unwrap(); assert!(migrate(&c)); c };
        let ca = mkdb(&pa);
        let cb = mkdb(&pb);
        // tenant A : un incident acquitté.
        let id = case_create_row(&ca, "alice", "incident tenant A", 3, "", None, 1);
        incident_apply_tier(&ca, id, "alice", Some(1), Some("A-TYPE"), Some("A-CMD"));
        ca.execute("UPDATE incident SET first_response_ts=?1 WHERE id=?2", params![now(), id]).unwrap();
        let masks = guatx_core::soql::FieldMaskSet::new();
        // le client du tenant A voit SON incident.
        let va = client_case_get_json(&ca, &pa, &masks, id, now()).unwrap();
        assert_eq!(va["is_incident"], json!(true));
        // le client du tenant B (base distincte) ne voit RIEN de cet id.
        assert!(client_case_get_json(&cb, &pb, &masks, id, now()).is_none(), "cross-tenant : le tenant B ne voit pas l'incident du tenant A");
        let lb = client_cases_list_json(&cb, &pb, &masks, now(), "", 100, 0);
        assert_eq!(lb["total"], json!(0), "la liste du tenant B est vide (aucun cross-tenant)");
        let _ = std::fs::remove_file(&pa);
        let _ = std::fs::remove_file(&pb);
    }
