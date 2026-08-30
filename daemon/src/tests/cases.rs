    // ============================================================================================
    // #4a — CASES FIRST-CLASS : migration/backfill, workflow, timeline typée, overdue, liens, escalade, RBAC.
    // ============================================================================================

    /// MIGRATION v69 SUR BASE EXISTANTE : incident au schéma PRÉ-v69 (v16 + env_id v66) -> migrate -> colonnes
    /// posées + backfill priority (depuis severity) + sla_due (ts+cible) SANS jamais réécrire le status legacy.
    #[test]
    fn case_v69_backfill_and_legacy_preserved() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)", []).unwrap();
        conn.execute("INSERT INTO meta VALUES('schema_version','68')", []).unwrap();
        conn.execute(
            "CREATE TABLE incident(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, updated INTEGER NOT NULL, \
             title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', severity INTEGER NOT NULL DEFAULT 2, \
             owner TEXT, summary TEXT, closed_ts INTEGER, env_id TEXT NOT NULL DEFAULT 'prod')",
            [],
        ).unwrap();
        conn.execute("INSERT INTO incident(ts,updated,title,status,severity) VALUES(1000,1000,'crit','open',4)", []).unwrap();
        conn.execute("INSERT INTO incident(ts,updated,title,status,severity) VALUES(2000,2000,'mid','investigating',2)", []).unwrap();
        conn.execute("INSERT INTO incident(ts,updated,title,status,severity) VALUES(3000,3000,'low','contained',1)", []).unwrap();
        // Le backfill v77 (host_rollup) agrège event∪metric∪snapshot ; en prod ces tables existent TOUJOURS
        // (schema.sql avant migrate). Ici la base est minimale -> on pose les tables (vides) qu'il lit, sinon
        // le backfill échoue légitimement (erreur NON avalée) et migrate refuse de bumper à 77.
        conn.execute("CREATE TABLE event(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, host TEXT, env_id TEXT NOT NULL DEFAULT 'prod')", []).unwrap();
        conn.execute("CREATE TABLE metric(ts INTEGER NOT NULL, host TEXT, env_id TEXT NOT NULL DEFAULT 'prod')", []).unwrap();
        conn.execute("CREATE TABLE snapshot(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, host TEXT, env_id TEXT NOT NULL DEFAULT 'prod')", []).unwrap();
        let _ = migrate(&conn);
        assert_eq!(conn.query_row::<String, _, _>("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap(), CODE_SCHEMA_MAX.to_string());
        for c in ["priority", "assignee", "sla_due", "first_response_ts", "escalated"] {
            assert!(col_exists(&conn, "incident", c), "incident.{c} manquant");
        }
        let rows: Vec<(i64, String, i64, i64)> = {
            let mut s = conn.prepare("SELECT id,status,priority,sla_due FROM incident ORDER BY id").unwrap();
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap().flatten().collect()
        };
        assert_eq!(rows[0], (1, "open".into(), 1, 1000 + 3600), "sev4->P1, sla ts+1h ; statut legacy 'open' préservé");
        assert_eq!(rows[1], (2, "investigating".into(), 3, 2000 + 86400), "sev2->P3, sla ts+24h ; 'investigating' préservé");
        assert_eq!(rows[2], (3, "contained".into(), 4, 3000 + 259200), "sev1->P4, sla ts+72h ; 'contained' préservé");
        let (esc, fr): (i64, Option<i64>) = conn.query_row("SELECT escalated, first_response_ts FROM incident WHERE id=1", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((esc, fr), (0, None), "escalated=0, first_response_ts NULL par défaut");
        // idempotent : re-migrer n'altère pas les priorités backfillées.
        let _ = migrate(&conn);
        let p0: i64 = conn.query_row("SELECT priority FROM incident WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(p0, 1, "re-migrer ne réécrase pas la priorité backfillée");
    }

    /// Helpers purs : priorité (int/libellé/alias/borne), libellé miroir, cible SLA, normalisation de statut.
    #[test]
    fn case_priority_and_status_helpers() {
        assert_eq!(parse_priority(&json!(1)), Some(1));
        assert_eq!(parse_priority(&json!(4)), Some(4));
        assert_eq!(parse_priority(&json!(9)), Some(4), "borné à 4");
        assert_eq!(parse_priority(&json!(0)), Some(1), "borné à 1");
        assert_eq!(parse_priority(&json!("critical")), Some(1));
        assert_eq!(parse_priority(&json!("HIGH")), Some(2), "insensible à la casse");
        assert_eq!(parse_priority(&json!("med")), Some(3));
        assert_eq!(parse_priority(&json!("low")), Some(4));
        assert_eq!(parse_priority(&json!("p2")), Some(2));
        assert_eq!(parse_priority(&json!("bogus")), None);
        assert_eq!((priority_label(1), priority_label(2), priority_label(3), priority_label(4)), ("critical", "high", "med", "low"));
        assert_eq!((sla_target_s(1), sla_target_s(2), sla_target_s(3), sla_target_s(4)), (3600, 14400, 86400, 259200));
        assert_eq!(norm_case_status("new"), Some("new"));
        assert_eq!(norm_case_status("open"), Some("new"), "alias legacy");
        assert_eq!(norm_case_status("triage"), Some("triage"));
        assert_eq!(norm_case_status("investigating"), Some("in_progress"), "alias legacy");
        assert_eq!(norm_case_status("in_progress"), Some("in_progress"));
        assert_eq!(norm_case_status("contained"), Some("resolved"), "alias legacy");
        assert_eq!(norm_case_status("resolved"), Some("resolved"));
        assert_eq!(norm_case_status("closed"), Some("closed"));
        assert_eq!(norm_case_status("garbage"), None);
    }

    /// WORKFLOW de bout en bout : create (new) -> assign -> priorisation -> in_progress -> resolved (close) ->
    /// reopen. Vérifie statut canonique, priorité, assignee, closed_ts, MTTA, timeline TYPÉE, audit ledger.
    #[test]
    fn case_first_class_workflow() {
        let conn = test_db();
        let id = case_create_row(&conn, "alice", "Intrusion SSH", 3, "brute force", None, 2);
        let c = case_get_json(&conn, id, now()).unwrap();
        assert_eq!(c["status"], "new");
        assert_eq!(c["priority"], 2);
        assert_eq!(c["priority_label"], "high");
        assert_eq!(c["owner"], "alice");
        assert_eq!(c["overdue"], false, "sla dans le futur -> pas overdue");
        let items = c["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["kind"], "created");
        assert!(case_apply_update(&conn, id, "bob", &json!({"assignee":"carol"})));
        assert!(case_apply_update(&conn, id, "bob", &json!({"priority":"critical"})));
        assert!(case_apply_update(&conn, id, "bob", &json!({"status":"in_progress"})));
        assert!(case_apply_update(&conn, id, "bob", &json!({"status":"resolved"})));
        let c2 = case_get_json(&conn, id, now()).unwrap();
        assert_eq!(c2["status"], "resolved");
        assert_eq!(c2["priority"], 1);
        assert_eq!(c2["assignee"], "carol");
        assert!(c2["closed_ts"].as_i64().is_some(), "resolved pose closed_ts");
        assert!(c2["first_response_ts"].as_i64().is_some(), "MTTA figé au 1er item de réponse (assign)");
        let kinds: Vec<String> = c2["items"].as_array().unwrap().iter().map(|i| i["kind"].as_str().unwrap().to_string()).collect();
        assert_eq!(kinds, vec!["created", "assign", "priority", "status", "status"], "timeline typée dans l'ordre");
        // reopen : statut non terminal -> closed_ts remis à NULL.
        assert!(case_apply_update(&conn, id, "bob", &json!({"status":"triage"})));
        let c3 = case_get_json(&conn, id, now()).unwrap();
        assert_eq!(c3["status"], "triage");
        assert!(c3["closed_ts"].is_null(), "reopen efface closed_ts");
        let kc: i64 = conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind='case.create'", [], |r| r.get(0)).unwrap();
        let ka: i64 = conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind='case.assign'", [], |r| r.get(0)).unwrap();
        let ks: i64 = conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind='case.status'", [], |r| r.get(0)).unwrap();
        assert_eq!((kc, ka, ks), (1, 1, 3), "audit ledger : 1 create, 1 assign, 3 changements de statut");
        assert!(!case_apply_update(&conn, 999999, "bob", &json!({"status":"closed"})), "case inexistant -> false");
    }

    /// OVERDUE calculé (now>sla_due ET non terminal) + FILTRES liste (status/assignee/priority/overdue) + tri
    /// overdue-first. Un case résolu n'est JAMAIS overdue même échéance passée.
    #[test]
    fn case_overdue_and_filters() {
        let conn = test_db();
        let base = now();
        let a = case_create_row(&conn, "alice", "A", 4, "", Some("carol"), 1);
        let b = case_create_row(&conn, "alice", "B", 2, "", None, 3);
        conn.execute("UPDATE incident SET sla_due=?1 WHERE id=?2", params![base - 100, a]).unwrap();
        assert_eq!(case_get_json(&conn, a, now()).unwrap()["overdue"], true, "A overdue (sla passé, non terminal)");
        assert_eq!(case_get_json(&conn, b, now()).unwrap()["overdue"], false, "B dans les temps");
        let all = cases_list_json(&conn, now(), "", "", 0, false, false);
        assert_eq!(all["cases"].as_array().unwrap()[0]["id"], a, "overdue en tête de liste");
        let od = cases_list_json(&conn, now(), "", "", 0, true, false);
        let odc = od["cases"].as_array().unwrap();
        assert_eq!(odc.len(), 1);
        assert_eq!(odc[0]["id"], a, "filtre overdue -> seulement A");
        assert_eq!(cases_list_json(&conn, now(), "", "carol", 0, false, false)["cases"].as_array().unwrap().len(), 1, "filtre assignee");
        let p3 = cases_list_json(&conn, now(), "", "", 3, false, false);
        let p3c = p3["cases"].as_array().unwrap();
        assert_eq!(p3c.len(), 1);
        assert_eq!(p3c[0]["id"], b, "filtre priority=P3 -> B");
        assert!(case_apply_update(&conn, a, "bob", &json!({"status":"resolved"})));
        assert_eq!(case_get_json(&conn, a, now()).unwrap()["overdue"], false, "resolved -> jamais overdue");
        assert_eq!(cases_list_json(&conn, now(), "", "", 0, true, false)["cases"].as_array().unwrap().len(), 0, "plus aucun overdue");
    }

    /// #4a DISPOSITION — MIGRATION v106 ADDITIVE/VIDE = MODE 0 BYTE-IDENTIQUE + IDEMPOTENTE. Une base pré-v106
    /// (incident sans les 3 colonnes) migre : colonnes NULLABLES posées, la ligne existante RESTE octet pour
    /// octet identique (disposition/_ts/_by NULL, tous les autres champs inchangés) ; re-migrer ne touche rien.
    #[test]
    fn disposition_migration_v106_additive_empty_mode0() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)", []).unwrap();
        // v=105 : SEUL `if v < 106` (migrate_v106) s'exécute (migrate() capture v une fois au sommet).
        conn.execute("INSERT INTO meta VALUES('schema_version','105')", []).unwrap();
        conn.execute(
            "CREATE TABLE incident(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, updated INTEGER NOT NULL, \
             title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new', severity INTEGER NOT NULL DEFAULT 2, \
             owner TEXT, summary TEXT, closed_ts INTEGER, priority INTEGER NOT NULL DEFAULT 3)",
            [],
        ).unwrap();
        conn.execute("INSERT INTO incident(id,ts,updated,title,status,severity,owner,summary,priority) \
                      VALUES(7,1000,1000,'T','in_progress',2,'alice','resume',2)", []).unwrap();
        let fp = "SELECT id||'|'||ts||'|'||updated||'|'||title||'|'||status||'|'||severity||'|'||\
                  COALESCE(owner,'')||'|'||COALESCE(summary,'')||'|'||COALESCE(closed_ts,'')||'|'||priority \
                  FROM incident WHERE id=7";
        let before: String = conn.query_row(fp, [], |r| r.get(0)).unwrap();
        let _ = migrate(&conn);
        for c in ["disposition", "disposition_ts", "disposition_by"] {
            assert!(col_exists(&conn, "incident", c), "incident.{c} posée par v106");
        }
        assert_eq!(conn.query_row::<String, _, _>("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap(), CODE_SCHEMA_MAX.to_string());
        let after: String = conn.query_row(fp, [], |r| r.get(0)).unwrap();
        assert_eq!(before, after, "colonnes préexistantes BYTE-IDENTIQUES après l'ALTER additif");
        let (d, dts, dby): (Option<String>, Option<i64>, Option<String>) = conn.query_row(
            "SELECT disposition, disposition_ts, disposition_by FROM incident WHERE id=7",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert!(d.is_none() && dts.is_none() && dby.is_none(), "verdict NULL = non-défini (mode 0)");
        // IDEMPOTENT : re-migrer (v106 re-tourné via rétrograde) reste à la tête sans réécrire.
        conn.execute("UPDATE meta SET value='105' WHERE key='schema_version'", []).unwrap();
        let _ = migrate(&conn);
        assert_eq!(conn.query_row::<String, _, _>("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap(), CODE_SCHEMA_MAX.to_string());
    }

    /// #4a DISPOSITION — ENUM FERMÉ (source unique DISPOSITION_VALUES). Exactement les 4 verdicts ; toute autre
    /// valeur (inconnue, casse, espaces, vide) N'EST PAS membre -> l'API la rejette (400) ou la traite en unset.
    #[test]
    fn disposition_enum_allowlist_is_closed() {
        assert_eq!(DISPOSITION_VALUES, &["true_positive", "false_positive", "benign", "duplicate"]);
        for v in DISPOSITION_VALUES { assert!(disposition_valid(v), "{v} membre"); }
        for bad in ["malware", "TRUE_POSITIVE", "true positive", "fp", "", "tp", "resolved"] {
            assert!(!disposition_valid(bad), "{bad:?} REJETÉ (hors allowlist)");
        }
    }

    /// #4a DISPOSITION — SET->GET roundtrip : verdict posé -> disposition + disposition_ts (>0) + disposition_by
    /// (l'acteur) peuplés + item timeline 'disposition' + entrée ledger case.disposition. '' -> unset (efface).
    /// FAIL-CLOSED au niveau capture : une valeur hors allowlist n'est JAMAIS écrite (no-op).
    #[test]
    fn disposition_set_get_roundtrip_audit_and_failclosed() {
        let conn = test_db();
        let id = case_create_row(&conn, "alice", "A", 3, "", None, 2);
        // SET valide (accompagne une clôture, comme en prod).
        assert!(case_apply_update(&conn, id, "bob", &json!({ "status": "closed", "disposition": "false_positive" })));
        let c = case_get_json(&conn, id, now()).unwrap();
        assert_eq!(c["disposition"], "false_positive", "verdict lu au GET");
        assert!(c["disposition_ts"].as_i64().unwrap() > 0, "disposition_ts peuplé (now)");
        assert_eq!(c["disposition_by"], "bob", "disposition_by = acteur");
        // ledger case.disposition présent.
        let led: i64 = conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind='case.disposition' AND detail LIKE ?1",
            params![format!("#{id} -> false_positive by bob")], |r| r.get(0)).unwrap();
        assert_eq!(led, 1, "changement de verdict AUDITÉ au ledger (case.disposition)");
        // item timeline typé.
        let it: i64 = conn.query_row("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='disposition'", params![id], |r| r.get(0)).unwrap();
        assert_eq!(it, 1, "item timeline 'disposition'");
        // FAIL-CLOSED : valeur hors allowlist -> AUCUNE écriture (le verdict reste false_positive).
        assert!(case_apply_update(&conn, id, "bob", &json!({ "disposition": "garbage" })));
        assert_eq!(case_get_json(&conn, id, now()).unwrap()["disposition"], "false_positive", "valeur invalide NON écrite (fail-closed)");
        // UNSET : '' efface le verdict.
        assert!(case_apply_update(&conn, id, "carol", &json!({ "disposition": "" })));
        assert!(case_get_json(&conn, id, now()).unwrap()["disposition"].is_null(), "'' -> verdict effacé (unset)");
    }

    /// #4a DISPOSITION — VALIDATION 400 AU BORD (handler case_update) : un verdict non-vide hors allowlist ->
    /// 400 AVANT toute écriture (DB inchangée) ; un verdict valide -> 204 + persistance. RBAC editor+ réutilisée.
    #[tokio::test]
    async fn disposition_bad_value_rejected_at_api_400() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let id = { let g = st.db.lock(); case_create_row(&g, "alice", "A", 3, "", None, 2) };
        // (a) valeur invalide -> 400, rien écrit.
        let code = case_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({ "disposition": "not_a_verdict" }))).await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "verdict hors allowlist -> 400");
        { let g = st.db.lock();
          let d: Option<String> = g.query_row("SELECT disposition FROM incident WHERE id=?1", params![id], |r| r.get(0)).unwrap();
          assert!(d.is_none(), "aucune écriture sur rejet 400"); }
        // (b) valeur valide -> 204 + persistée.
        let ok = case_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(json!({ "disposition": "true_positive" }))).await;
        assert_eq!(ok, StatusCode::NO_CONTENT, "verdict valide accepté");
        { let g = st.db.lock();
          let d: Option<String> = g.query_row("SELECT disposition FROM incident WHERE id=?1", params![id], |r| r.get(0)).unwrap();
          assert_eq!(d.as_deref(), Some("true_positive"), "verdict valide persisté"); }
    }

    /// #4a DISPOSITION — NON-FUITE CLIENT : le verdict est INTERNE. Même quand un case le PORTE, la projection
    /// client-read (client_cases_list_json / client_case_get_json) NE contient NI la clé `disposition` NI la
    /// valeur du verdict -> contrat d'isolation MSSP préservé ([[plume-multitenant]]).
    #[test]
    fn disposition_absent_from_client_read_projection() {
        let path = ff_tmp_path("dispclient");
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        let masks = effective_masks(&path, "client", "default", None);
        let id = case_create_row(&conn, "analyst_alice", "T", 3, "", None, 2);
        assert!(case_apply_update(&conn, id, "bob", &json!({ "disposition": "true_positive" })));
        assert_eq!(case_get_json(&conn, id, now()).unwrap()["disposition"], "true_positive", "verdict bien posé côté interne");
        let list = serde_json::to_string(&client_cases_list_json(&conn, &path, &masks, now(), "", 100, 0)).unwrap();
        let det = serde_json::to_string(&client_case_get_json(&conn, &path, &masks, id, now()).unwrap()).unwrap();
        for blob in [&list, &det] {
            assert!(!blob.contains("disposition"), "projection client NE contient PAS la clé disposition : {blob}");
            assert!(!blob.contains("true_positive"), "projection client NE contient PAS la valeur du verdict : {blob}");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// BATCH 1 (scalabilité) — cases_list_json_paged : `total` compte APRÈS filtres (pas la page), LIMIT/OFFSET
    /// borne la page, `sort` replie le tri serveur. Rétro-compat : wrapper cases_list_json == défaut (sort="",
    /// LIMIT 300, tri overdue-first) prouvé inchangé.
    #[test]
    fn cases_paged_total_sort() {
        let conn = test_db();
        // 5 cases, priorités et updated distincts pour tester le tri.
        let mut ids = Vec::new();
        for i in 0..5 {
            let id = case_create_row(&conn, "alice", &format!("C{i}"), 2, "", None, ((i % 4) + 1) as i64);
            conn.execute("UPDATE incident SET updated=?1 WHERE id=?2", params![1000 + i as i64, id]).unwrap();
            ids.push(id);
        }
        // total = 5 quelle que soit la page ; page bornée par LIMIT.
        let p0 = cases_list_json_paged(&conn, now(), "", "", 0, false, false, "", 2, 0);
        assert_eq!(p0["total"], 5, "total = COUNT complet (pas la taille de page)");
        assert_eq!(p0["cases"].as_array().unwrap().len(), 2, "page 0 bornée à LIMIT=2");
        let p1 = cases_list_json_paged(&conn, now(), "", "", 0, false, false, "", 2, 2);
        assert_eq!(p1["cases"].as_array().unwrap().len(), 2, "page 1 (offset 2)");
        let p2 = cases_list_json_paged(&conn, now(), "", "", 0, false, false, "", 2, 4);
        assert_eq!(p2["cases"].as_array().unwrap().len(), 1, "dernière page partielle");
        // OFFSET saute bien : aucune collision d'id entre pages.
        let id_p0: Vec<i64> = p0["cases"].as_array().unwrap().iter().map(|c| c["id"].as_i64().unwrap()).collect();
        let id_p1: Vec<i64> = p1["cases"].as_array().unwrap().iter().map(|c| c["id"].as_i64().unwrap()).collect();
        assert!(id_p0.iter().all(|x| !id_p1.contains(x)), "pages disjointes (offset)");
        // tri serveur : updated DESC -> updated le plus grand (1004) en tête.
        let su = cases_list_json_paged(&conn, now(), "", "", 0, false, false, "updated", 300, 0);
        let first_upd = su["cases"].as_array().unwrap()[0]["ts"].as_i64().is_some(); // sanity
        assert!(first_upd);
        assert_eq!(su["cases"].as_array().unwrap()[0]["title"], "C4", "sort=updated -> updated le + récent en tête");
        // tri serveur : priority ASC -> P1 en tête (C0 a priority=(0%4)+1=1).
        let sp = cases_list_json_paged(&conn, now(), "", "", 0, false, false, "priority", 300, 0);
        assert_eq!(sp["cases"].as_array().unwrap()[0]["priority"], 1, "sort=priority -> P1 en tête");
        // filtre PRÉSERVÉ sous pagination : priority=2 (C1 seul) -> total 1.
        let fp = cases_list_json_paged(&conn, now(), "", "", 2, false, false, "", 300, 0);
        assert_eq!(fp["total"], 1, "filtre priority préservé dans le COUNT");
        assert_eq!(fp["cases"].as_array().unwrap().len(), 1);
        // RÉTRO-COMPAT : wrapper == paged défaut.
        let w = cases_list_json(&conn, now(), "", "", 0, false, false);
        let d = cases_list_json_paged(&conn, now(), "", "", 0, false, false, "", 300, 0);
        assert_eq!(w["cases"], d["cases"], "wrapper == paged (sort défaut, LIMIT 300)");
    }

    // =============================================================================================
    // `P11.16-d` — LE JOURNAL D'AUDIT : FENÊTRE DE TEMPS, CLÉ, ET COÛT QUI NE SUIT PLUS LE VOLUME
    // ---------------------------------------------------------------------------------------------
    // CE QUE CES TESTS PROUVENT, ET PAR QUELLE VALEUR :
    //   1. `ledger_page_par_cle_et_fenetre`      — le CONTRAT : page par clé, fenêtre, total, `oldest_ts`.
    //   2. `ledger_parcours_integral_par_cle`    — AUCUN trou, AUCUN doublon : chaque entrée vue une fois.
    //   3. `ledger_total_cout_independant_du_volume` — LE THÉORÈME du total : le volume DOUBLE, les lignes
    //      lues par le comptage ne bougent PAS ; et l'ANCIENNE forme, elle, double (contre-exemple porté
    //      par le test lui-même : un instrument qui ne saurait pas voir la faute ne prouverait rien).
    //   4. `ledger_page_cout_independant_de_la_profondeur` — LE THÉORÈME de la page : atteindre la page 40
    //      par CLÉ coûte ce que coûte la page 2 ; par DÉCALAGE, ça coûte vingt fois plus.
    //   5. `ledger_total_plafonne_est_annonce`   — au-dessus du plafond, le total est plafonné ET DIT.
    //   6. `ledger_lecture_ne_prend_pas_le_verrou_d_ecriture` — LE VERDICT sur la connexion.
    //   7. `ledger_saut_hors_plafond_est_un_refus` — au-delà de la borne, un REFUS, jamais une page vide.
    //   8. `ledger_fenetre_ne_touche_ni_ordre_ni_chaine` — ce que la fenêtre n'a PAS le droit de changer.
    //
    // L'INSTRUMENT DE COÛT est celui de `tests/sondes_cout.rs` : `SQLITE_STMTSTATUS_VM_STEP`, compté par
    // SQLite lui-même. Il ne dépend ni de la charge machine, ni du cache, ni de l'horloge — deux
    // exécutions identiques rendent le même nombre, ce qui rend le théorème opposable au lieu d'être un
    // chronomètre. Il est lu sur le SQL RÉELLEMENT ÉMIS (`ledger_total_sql`/`ledger_page_sql`), jamais sur
    // une copie : une copie ne mesurerait que sa propre exactitude.
    // =============================================================================================

    /// Le coût d'un énoncé, compté par SQLite lui-même. Le statement est préparé ICI et jeté après la
    /// mesure : `sqlite3_stmt_status(resetFlg=0)` rend un CUMUL sur la vie du statement, donc réutiliser un
    /// statement mesurerait la somme de toutes ses exécutions.
    ///
    /// DEUX COMPTEURS, PARCE QU'ILS NE DISENT PAS LA MÊME CHOSE — et l'un des deux a menti (cf. le test 3).
    /// `VmStep` compte les pas de machine virtuelle : il mesure le TRAVAIL D'INTERPRÉTATION. `FullscanStep`
    /// compte les LIGNES traversées en balayage de table : c'est lui qui suit les pages lues et — sous
    /// SQLCipher — déchiffrées, donc la grandeur qui doit cesser de croître avec le journal.
    fn led_cout(conn: &Connection, sql: &str, binds: &[i64], quoi: rusqlite::StatementStatus) -> i64 {
        let mut s = conn.prepare(sql).expect("le journal émet un SQL valide");
        {
            let mut rows = s.query(rusqlite::params_from_iter(binds.iter())).unwrap();
            while rows.next().unwrap().is_some() {}
        }
        s.get_status(quoi) as i64
    }

    /// LIGNES traversées en balayage — la grandeur que la borne doit plafonner.
    fn led_lignes(conn: &Connection, sql: &str, binds: &[i64]) -> i64 {
        led_cout(conn, sql, binds, rusqlite::StatementStatus::FullscanStep)
    }

    /// PAS de machine virtuelle — la grandeur qui suit la PROFONDEUR d'un décalage.
    fn led_pas(conn: &Connection, sql: &str, binds: &[i64]) -> i64 {
        led_cout(conn, sql, binds, rusqlite::StatementStatus::VmStep)
    }

    /// Sème `n` entrées de journal en UN énoncé (CTE récursive) : `ts` croissant avec `id`, comme
    /// `ledger_append` qui écrit `now()` à chaque appel. Le `hash` est un remplissage — les tests qui
    /// portent sur la CHAÎNE (n° 8) passent par `ledger_append`, le vrai chemin d'écriture.
    fn led_semer(conn: &Connection, n: i64, ts0: i64) {
        conn.execute_batch(&format!(
            "WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i<{n}) \
             INSERT INTO ledger(ts,kind,detail,prev_hash,hash) SELECT {ts0}+i,'k'||i,'d'||i,'p','h'||i FROM s;"
        ))
        .unwrap();
    }

    fn led_ask(limit: i64, since: i64, window_days: i64, cursor: Option<i64>, offset: i64) -> LedgerAsk {
        LedgerAsk { limit, since, window_days, cursor, offset, count: true }
    }

    fn led_ids(v: &Value) -> Vec<i64> {
        v["entries"].as_array().unwrap().iter().map(|e| e["id"].as_i64().unwrap()).collect()
    }

    /// (1) LE CONTRAT. Première page = les plus RÉCENTES (`id` décroissant, l'ordre de la chaîne) ; la page
    /// suivante se prend par CURSEUR ; la dernière page rend `has_more:false` + `next_cursor:null` ; le
    /// total est EXACT sous le plafond ; la fenêtre FILTRE et DIT qu'elle mord (`older_outside_window`)
    /// en nommant la plus ancienne entrée STOCKÉE (`oldest_ts`).
    #[test]
    fn ledger_page_par_cle_et_fenetre() {
        let conn = test_db();
        led_semer(&conn, 7, 1000); // ts 1001..1007, id 1..7
        // --- SANS BORNE (paramètre absent -> `since` = i64::MIN) : tout l'historique, total exact.
        let p0 = ledger_page(&conn, &led_ask(3, i64::MIN, 0, None, 0));
        assert_eq!(p0["total"], json!(7), "total EXACT sous le plafond de comptage");
        assert_eq!(p0["total_capped"], json!(false));
        assert_eq!(led_ids(&p0), vec![7, 6, 5], "première page = les plus récentes, id décroissant");
        assert_eq!(p0["has_more"], json!(true), "page pleine -> il reste probablement des lignes");
        assert_eq!(p0["next_cursor"], json!(5), "curseur = id de la DERNIÈRE ligne rendue");
        assert_eq!(p0["since"], Value::Null, "aucune borne -> aucune date de borne inventée");
        assert_eq!(p0["older_outside_window"], json!(false), "sans borne, rien n'est hors du cadre");
        assert_eq!(p0["oldest_ts"], json!(1001), "la plus ancienne entrée STOCKÉE est nommée");
        // --- PAGE SUIVANTE PAR CLÉ.
        let p1 = ledger_page(&conn, &led_ask(3, i64::MIN, 0, Some(5), 0));
        assert_eq!(led_ids(&p1), vec![4, 3, 2], "curseur -> strictement APRÈS la dernière ligne rendue");
        // --- DERNIÈRE PAGE : partielle -> fin explicite.
        let p2 = ledger_page(&conn, &led_ask(3, i64::MIN, 0, Some(2), 0));
        assert_eq!(led_ids(&p2), vec![1], "reste une ligne");
        assert_eq!(p2["has_more"], json!(false), "page partielle -> dernière page");
        assert_eq!(p2["next_cursor"], Value::Null, "dernière page -> aucun curseur de continuation");
        // --- FENÊTRE : ne garde que ts>=1005, et DIT que des entrées plus anciennes existent.
        let f = ledger_page(&conn, &led_ask(10, 1005, 1, None, 0));
        assert_eq!(led_ids(&f), vec![7, 6, 5], "la fenêtre filtre, elle ne réordonne pas");
        assert_eq!(f["total"], json!(3), "le total porte sur la FENÊTRE, pas sur la table");
        assert_eq!(f["since"], json!(1005), "la borne effective est rendue : la vue peut la DIRE");
        assert_eq!(f["window_days"], json!(1));
        assert_eq!(f["older_outside_window"], json!(true), "la borne MORD, et la route le dit");
        assert_eq!(f["oldest_ts"], json!(1001), "…en nommant la plus ancienne entrée du journal");
    }

    /// (2) PARCOURS INTÉGRAL PAR CLÉ : chaque entrée visitée EXACTEMENT une fois, dans l'ordre de la
    /// chaîne, sans trou ni doublon — la propriété qui manque à une pagination par décalage dès qu'une
    /// écriture tombe pendant le parcours.
    #[test]
    fn ledger_parcours_integral_par_cle() {
        let conn = test_db();
        led_semer(&conn, 38, 1000);
        let mut vus: Vec<i64> = Vec::new();
        let mut cursor: Option<i64> = None;
        let mut pages = 0usize;
        loop {
            let p = ledger_page(&conn, &led_ask(8, i64::MIN, 0, cursor, 0));
            vus.extend(led_ids(&p));
            pages += 1;
            assert!(pages < 100, "garde-fou anti-boucle infinie");
            if !p["has_more"].as_bool().unwrap() {
                assert_eq!(p["next_cursor"], Value::Null);
                break;
            }
            cursor = Some(p["next_cursor"].as_i64().unwrap());
        }
        let attendu: Vec<i64> = (1..=38).rev().collect();
        assert_eq!(vus, attendu, "l'ensemble collecté == la table entière, dans l'ordre de la chaîne");
        assert!(pages >= 5, "38 lignes / 8 par page -> au moins 5 pages (parcours réel)");
    }

    /// (3) LE THÉORÈME DU TOTAL — le volume DOUBLE, le comptage borné ne lit PAS une ligne de plus, et il
    /// SATURE (il rend la même valeur, donc il a cessé de regarder). Le contre-exemple est le MÊME énoncé
    /// privé de sa seule clause de bornage : c'est la mutation de la correction elle-même, pas la
    /// comparaison à un énoncé d'une autre forme.
    ///
    /// UN INSTRUMENT A ÉTÉ RÉFUTÉ ICI, ET C'EST POURQUOI LE CONTRE-EXEMPLE A CETTE FORME. Mesuré le
    /// 2026-08-25 : `SELECT COUNT(*) FROM ledger` — la forme D'ORIGINE de cette route — coûte NEUF pas de
    /// machine virtuelle, que la table porte dix mille lignes ou vingt et un mille. SQLite la sert par un
    /// comptage de B-tree (`OP_Count`), qui visite toutes les pages de la table SANS boucle VDBE : le
    /// compteur de pas est AVEUGLE à ce coût — la table n'est pas bon marché, c'est l'instrument qui ne
    /// voit rien. Opposer les deux formes aurait donc rendu VERT en ne mesurant rien. Ce qui est éprouvé
    /// ici est donc la seule chose qui décide, comptée par `FULLSCAN_STEP` — les LIGNES traversées, celles
    /// qui coûtent une page lue et, sous SQLCipher, déchiffrée.
    ///
    /// RELEVÉ le 2026-08-25 sur cette fixture (lignes traversées) : comptage BORNÉ = 10 000 sur un journal
    /// de 10 500 comme sur un journal de 21 000 ; le MÊME comptage privé de sa borne = 10 499 puis 20 999.
    /// La borne cesse donc de suivre le volume, et elle le fait AU PLAFOND. À l'inverse, en pas de machine
    /// virtuelle, la forme bornée en coûte DAVANTAGE (90 024 contre 42 011 et 84 011) : la borne empêche
    /// l'aplatissement de la sous-requête, donc chaque ligne coûte plus d'interprétation — pendant qu'il y
    /// a deux fois moins de lignes à lire. Deux compteurs, deux verdicts opposés : c'est pourquoi celui qui
    /// est retenu est nommé, avec ce qu'il mesure.
    #[test]
    fn ledger_total_cout_independant_du_volume() {
        // Le MÊME énoncé, privé de `LIMIT CAP+1` — la mutation exacte de ce que la correction ajoute.
        const SANS_BORNE: &str = "SELECT COUNT(*) FROM (SELECT 1 FROM ledger WHERE ts>=?1)";
        let petit = test_db();
        led_semer(&petit, PAGINATION_COUNT_CAP + 500, 1_700_000_000);
        let grand = test_db();
        led_semer(&grand, 2 * (PAGINATION_COUNT_CAP + 500), 1_700_000_000);

        let sql = ledger_total_sql();
        let c_petit = led_lignes(&petit, &sql, &[i64::MIN]);
        let c_grand = led_lignes(&grand, &sql, &[i64::MIN]);
        assert_eq!(c_petit, c_grand, "MUTATION x2 du volume : le comptage borné lit le MÊME nombre de lignes");
        assert!(c_grand <= PAGINATION_COUNT_CAP + 1, "…et ce nombre est le plafond lui-même ({c_grand})");

        let s_petit = led_lignes(&petit, SANS_BORNE, &[i64::MIN]);
        let s_grand = led_lignes(&grand, SANS_BORNE, &[i64::MIN]);
        assert!(
            s_grand > s_petit * 3 / 2,
            "témoin INVERSE : privé de sa borne, le MÊME comptage DOIT suivre le volume (petit={s_petit}, \
             grand={s_grand}) — sinon l'instrument ne mesure pas ce qu'il prétend mesurer"
        );
        assert!(
            c_grand < s_petit,
            "le comptage borné du GROS journal lit moins de lignes que le comptage non borné du PETIT \
             (borné_grand={c_grand}, sans_borne_petit={s_petit})"
        );

        // SATURATION : le total rendu est le MÊME des deux côtés, et il se déclare plafonné. Un comptage
        // qui rend la même valeur sur deux volumes différents est un comptage qui a cessé de regarder.
        for (nom, base) in [("petit", &petit), ("grand", &grand)] {
            let v = ledger_page(base, &led_ask(10, i64::MIN, 0, None, 0));
            assert_eq!(v["total"], json!(PAGINATION_COUNT_CAP), "{nom} : total plafonné");
            assert_eq!(v["total_capped"], json!(true), "{nom} : et il le DIT");
        }
    }

    /// (4) LE THÉORÈME DE LA PAGE — atteindre une page LOINTAINE par CLÉ coûte ce que coûte une page
    /// proche. Le contre-exemple est le décalage, sur la MÊME base et la MÊME page : c'est exactement ce
    /// que la clé achète, et pourquoi le saut par décalage reste borné par `LEDGER_JUMP_MAX`.
    #[test]
    fn ledger_page_cout_independant_de_la_profondeur() {
        let conn = test_db();
        led_semer(&conn, 4000, 1_700_000_000);
        let max_id: i64 = conn.query_row("SELECT MAX(id) FROM ledger", [], |r| r.get(0)).unwrap();
        let (lim, proche, loin) = (50i64, 2i64, 40i64);
        // Par CLÉ : le curseur qui ouvre la page k est l'id de la dernière ligne de la page k-1.
        let cle = |k: i64| {
            let sql = ledger_page_sql(&ledger_plan(Some(max_id - (k - 1) * lim + 1), 0));
            led_pas(&conn, &sql, &[i64::MIN, lim])
        };
        let c_proche = cle(proche);
        let c_loin = cle(loin);
        assert_eq!(c_proche, c_loin, "par CLÉ, la page {loin} coûte ce que coûte la page {proche}");
        // Par DÉCALAGE, sur les MÊMES pages.
        let saut = |k: i64| {
            let sql = ledger_page_sql(&ledger_plan(None, (k - 1) * lim));
            led_pas(&conn, &sql, &[i64::MIN, lim])
        };
        let s_proche = saut(proche);
        let s_loin = saut(loin);
        assert!(
            s_loin > s_proche * 5,
            "témoin INVERSE : par DÉCALAGE le coût DOIT croître avec la profondeur (page {proche}={s_proche}, \
             page {loin}={s_loin}) — sinon la comparaison ci-dessus ne prouve rien"
        );
        assert!(c_loin < s_loin / 5, "la clé rend la page lointaine sans en payer la profondeur");
    }

    /// (5) AU-DESSUS DU PLAFOND, LE TOTAL EST PLAFONNÉ **ET DIT**. Un chiffre coûteux n'est pas remplacé
    /// par un chiffre faux présenté comme exact : `total_capped` est ce qui autorise la vue à rendre un
    /// pager non numéroté dont le Suivant reste fiable, au lieu d'un dernier numéro qui cacherait des pages.
    #[test]
    fn ledger_total_plafonne_est_annonce() {
        let sous = test_db();
        led_semer(&sous, PAGINATION_COUNT_CAP - 1, 1_700_000_000);
        let v = ledger_page(&sous, &led_ask(10, i64::MIN, 0, None, 0));
        assert_eq!(v["total"], json!(PAGINATION_COUNT_CAP - 1), "sous le plafond : total EXACT");
        assert_eq!(v["total_capped"], json!(false));

        let au_dessus = test_db();
        led_semer(&au_dessus, PAGINATION_COUNT_CAP + 1, 1_700_000_000);
        let v = ledger_page(&au_dessus, &led_ask(10, i64::MIN, 0, None, 0));
        assert_eq!(v["total"], json!(PAGINATION_COUNT_CAP), "au plafond : le total est PLAFONNÉ…");
        assert_eq!(v["total_capped"], json!(true), "…et il le DIT");

        // NON DEMANDÉ, DONC NON COMPTÉ — et `null` le dit. Un `0` mentirait (« journal vide »), et sur
        // cette vue un chiffre faux ne se remarque pas. Un total ne bouge pas au fil d'un parcours : la
        // vue le demande une fois par fenêtre, les pages suivantes ne repaient plus le plafond.
        let sans = LedgerAsk { limit: 10, since: i64::MIN, window_days: 0, cursor: None, offset: 0, count: false };
        let v = ledger_page(&au_dessus, &sans);
        assert_eq!(v["total"], Value::Null, "non demandé -> `total:null`, jamais un zéro");
        assert_eq!(v["total_capped"], Value::Null, "et rien n'est affirmé sur un plafond qu'on n'a pas éprouvé");
        assert_eq!(v["entries"].as_array().unwrap().len(), 10, "la page, elle, est servie");
        assert_eq!(v["oldest_ts"], json!(1_700_000_001i64), "la plus ancienne entrée reste NOMMÉE (coût constant)");
    }

    /// (6) LE VERDICT SUR LA CONNEXION. L'en-tête de la route disait « lecture seule » pendant que le corps
    /// prenait le MUTEX D'ÉCRITURE — celui de l'ingestion. Ici l'écrivain tient le verrou pendant toute la
    /// requête : si la lecture le réclamait, elle ne rendrait JAMAIS. La valeur qui change entre avant et
    /// après est donc binaire : la réponse arrive, ou elle n'arrive pas.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ledger_lecture_ne_prend_pas_le_verrou_d_ecriture() {
        let path = ff_tmp_path("ledger-verrou");
        {
            let conn = open_db(&path).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : chaîne de migrations complète");
            led_semer(&conn, 5, 1_700_000_000);
        }
        let st = ds_file_state(&path);
        // L'ÉCRIVAIN (ingestion) prend le verrou et ne le rend pas avant la fin de la mesure.
        let ecrivain = st.db.clone();
        let (pris_tx, pris_rx) = std::sync::mpsc::channel::<()>();
        let (fin_tx, fin_rx) = std::sync::mpsc::channel::<()>();
        let fil = std::thread::spawn(move || {
            let _verrou = ecrivain.lock();
            pris_tx.send(()).unwrap();
            let _ = fin_rx.recv();
        });
        pris_rx.recv().unwrap();

        let au = AuthUser {
            name: "root".into(), role: "admin".into(), tenant: "default".into(),
            is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None,
        };
        let appel = tokio::spawn(ledger_get(State(st.clone()), Extension(au), Query(HashMap::new())));
        let issue = tokio::time::timeout(std::time::Duration::from_secs(5), appel).await;
        let _ = fin_tx.send(());
        fil.join().unwrap();

        let rep = issue
            .expect("la lecture du journal a réclamé le verrou d'ÉCRITURE : sous un écrivain unique, elle \
                     attend l'ingestion au lieu de passer par le pool de lecture")
            .expect("le handler a paniqué");
        let (code, corps) = tok_resp_json(rep).await;
        assert_eq!(code, StatusCode::OK, "la page est servie verrou d'écriture TENU");
        assert_eq!(corps["entries"].as_array().unwrap().len(), 5, "et elle porte bien les entrées");
    }

    /// (7) AU-DELÀ DE LA BORNE, UN REFUS QUI NOMME LE PLAFOND — jamais une page vide. Sur cette vue, un
    /// vide se lit comme un fait (« le journal s'arrête là »), et une ligne manquante ne se remarque pas.
    #[tokio::test]
    async fn ledger_saut_hors_plafond_est_un_refus() {
        let path = ff_tmp_path("ledger-saut");
        {
            let conn = open_db(&path).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : chaîne de migrations complète");
            led_semer(&conn, 3, 1_700_000_000);
        }
        let st = ds_file_state(&path);
        let au = AuthUser {
            name: "root".into(), role: "admin".into(), tenant: "default".into(),
            is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None,
        };
        let mut q = HashMap::new();
        q.insert("offset".to_string(), (LEDGER_JUMP_MAX + 1).to_string());
        let (code, corps) = tok_resp_json(ledger_get(State(st.clone()), Extension(au.clone()), Query(q)).await).await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "un saut hors plafond est REFUSÉ, pas servi vide");
        let msg = corps["error"].as_str().unwrap_or("");
        assert!(msg.contains(&LEDGER_JUMP_MAX.to_string()), "le refus NOMME le plafond : {msg}");
        // Une fenêtre non numérique est un refus, pas un silencieux retour au défaut.
        let mut q = HashMap::new();
        q.insert("window_days".to_string(), "trente".to_string());
        let (code, corps) = tok_resp_json(ledger_get(State(st.clone()), Extension(au.clone()), Query(q)).await).await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "fenêtre illisible -> refus explicite");
        assert!(
            corps["error"].as_str().unwrap_or("").contains(&LEDGER_WINDOW_MAX_DAYS.to_string()),
            "le refus dit quelle fenêtre est acceptable"
        );
        // Une fenêtre AU-DELÀ du plafond est ramenée au plafond, et la réponse REND la valeur effective.
        let mut q = HashMap::new();
        q.insert("window_days".to_string(), (LEDGER_WINDOW_MAX_DAYS * 10).to_string());
        let (code, corps) = tok_resp_json(ledger_get(State(st), Extension(au), Query(q)).await).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(corps["window_days"], json!(LEDGER_WINDOW_MAX_DAYS), "la fenêtre EFFECTIVE est rendue");
    }

    /// (8) CE QUE LA FENÊTRE N'A PAS LE DROIT DE CHANGER. Le journal d'intégrité est infalsifiable par
    /// conception : lire une fenêtre ne doit toucher ni ce qu'il contient, ni son ordre, ni sa chaîne de
    /// vérification. Chaîne construite par le VRAI chemin d'écriture (`ledger_append`).
    #[test]
    fn ledger_fenetre_ne_touche_ni_ordre_ni_chaine() {
        let conn = test_db();
        for i in 0..12 {
            ledger_append(&conn, &format!("config.k{i}"), &format!("detail {i}"));
        }
        let (n_avant, _, _, rompue_avant) = verify_ledger_conn(&conn, None).expect("chaîne lisible");
        assert_eq!(n_avant, 12);
        assert!(rompue_avant.is_none(), "chaîne intacte avant lecture");

        let sans = ledger_page(&conn, &led_ask(50, i64::MIN, 0, None, 0));
        // Fenêtre LARGE : les 12 entrées viennent d'être écrites -> toutes dedans, à l'identique.
        let large = ledger_page(&conn, &led_ask(50, now() - 86_400, 1, None, 0));
        assert_eq!(sans["entries"], large["entries"], "même contenu, même ordre, mêmes empreintes");
        assert_eq!(large["older_outside_window"], json!(false), "rien hors du cadre");
        // Fenêtre qui EXCLUT tout : zéro entrée, et la route le DIT au lieu de laisser croire à un journal vide.
        let vide = ledger_page(&conn, &led_ask(50, now() + 86_400, 1, None, 0));
        assert!(vide["entries"].as_array().unwrap().is_empty());
        assert_eq!(vide["total"], json!(0));
        assert_eq!(vide["older_outside_window"], json!(true), "toutes les entrées sont hors de la fenêtre");
        assert!(vide["oldest_ts"].is_i64(), "et la plus ancienne entrée reste NOMMÉE");
        // La chaîne, après toutes ces lectures, est celle d'avant.
        let (n_apres, _, _, rompue_apres) = verify_ledger_conn(&conn, None).expect("chaîne lisible");
        assert_eq!((n_apres, rompue_apres), (n_avant, rompue_avant), "lire ne touche pas la chaîne");
    }

    /// (9) UN SEUL FABRICANT DE PAGE, UN SEUL FABRICANT DE COMPTAGE — garde DÉRIVÉE DE LA SOURCE, sur le
    /// modèle de `page_sql_is_the_only_place_that_builds_an_offset` (tests/keyset.rs).
    ///
    /// Le défaut n'était pas « ce site-là utilise un décalage » ni « ce site-là compte toute la table » :
    /// c'était qu'AUCUNE forme n'empêchait un deuxième site de naître à côté. Les deux invariants tenus
    /// ici, dans `handlers/admin_ui.rs` et sans aucune liste de sites :
    ///   * aucune ligne non commentée ne fabrique un `OFFSET` hors du corps de `ledger_page_sql` ;
    ///   * aucune ligne non commentée ne fabrique un `COUNT(` sur `ledger` hors du corps de
    ///     `ledger_total_sql` — les comptages des AUTRES tables (aperçu de rétention) ne sont pas visés,
    ///     et la règle le dit par son prédicat, pas par une exception nommée.
    /// Les deux moitiés sont exigées NON VIDES : un invariant qui ne trouve plus la forme qu'il garde est
    /// un invariant mort, et il rendrait vert en étant aveugle.
    #[test]
    fn ledger_un_seul_fabricant_de_page_et_de_comptage() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers/admin_ui.rs"),
        )
        .unwrap();
        let (mut dans_page, mut dans_total) = (false, false);
        let (mut vus_page, mut vus_total) = (0usize, 0usize);
        let mut fautes: Vec<(usize, &str)> = Vec::new();
        for (n, ligne) in src.lines().enumerate() {
            if ligne.starts_with("pub(crate) fn ledger_page_sql(") {
                dans_page = true;
            } else if ligne.starts_with("pub(crate) fn ledger_total_sql(") {
                dans_total = true;
            } else if ligne.starts_with('}') {
                dans_page = false;
                dans_total = false;
            }
            let code = ligne.trim_start();
            if code.starts_with("//") {
                continue; // commentaire : la prose cite les deux formes, c'est son rôle
            }
            if code.contains("OFFSET") {
                if dans_page {
                    vus_page += 1;
                } else {
                    fautes.push((n + 1, ligne));
                }
            }
            if code.contains("COUNT(") && code.contains("ledger") {
                if dans_total {
                    vus_total += 1;
                } else {
                    fautes.push((n + 1, ligne));
                }
            }
        }
        assert!(
            fautes.is_empty(),
            "une page ou un comptage du journal est fabriqué HORS de son fabricant unique — un chemin \
             peut donc retomber sur un décalage nu ou sur un comptage intégral sans passer par la \
             décision unique : {fautes:?}"
        );
        assert!(vus_page >= 1, "invariant vide = invariant mort : `ledger_page_sql` doit porter la forme OFFSET");
        assert!(vus_total >= 1, "invariant vide = invariant mort : `ledger_total_sql` doit porter le COUNT borné");
    }

    /// BATCH 1 — alerts_query_page : `total` renvoyé uniquement quand want_total (vue tous-statuts) ; LIMIT/OFFSET
    /// borne la page ; le filtre statut reste appliqué (backlog). Preuve rétro-compat du chemin borné (None).
    #[test]
    fn alerts_page_pagination() {
        let conn = test_db();
        // 6 'new' + 3 'closed'.
        for i in 0..6 {
            conn.execute("INSERT INTO alert(ts,rule,severity,title,status) VALUES(?1,'rule.1',2,?2,'new')", params![1000 + i as i64, format!("N{i}")]).unwrap();
        }
        for i in 0..3 {
            conn.execute("INSERT INTO alert(ts,rule,severity,title,status) VALUES(?1,'rule.1',2,?2,'closed')", params![2000 + i as i64, format!("C{i}")]).unwrap();
        }
        // tous statuts + total : 9 lignes, page bornée.
        let (p0, t0, _) = alerts_query_page(&conn, &FiltreAlertes::default(), None, "", 4, 0, true);
        assert_eq!(t0, Some(9), "want_total -> total = COUNT tous statuts");
        assert_eq!(p0.len(), 4, "page bornée à LIMIT=4");
        let (p1, _, _) = alerts_query_page(&conn, &FiltreAlertes::default(), None, "", 4, 4, true);
        assert_eq!(p1.len(), 4, "page 1 (offset 4)");
        let (p2, _, _) = alerts_query_page(&conn, &FiltreAlertes::default(), None, "", 4, 8, true);
        assert_eq!(p2.len(), 1, "dernière page partielle");
        // pages disjointes.
        let id0: Vec<i64> = p0.iter().map(|a| a["id"].as_i64().unwrap()).collect();
        let id1: Vec<i64> = p1.iter().map(|a| a["id"].as_i64().unwrap()).collect();
        assert!(id0.iter().all(|x| !id1.contains(x)), "pages disjointes (offset)");
        // chemin BACKLOG (want_total=false, filtre statut=new) : total None, seulement les 'new'.
        let (bk, tb, _) = alerts_query_page(&conn, &FiltreAlertes { statut: Some("new".into()), ..Default::default() }, None, "", 200, 0, false);
        assert_eq!(tb, None, "backlog : pas de total (borné)");
        assert_eq!(bk.len(), 6, "filtre statut=new appliqué");
        assert!(bk.iter().all(|a| a["status"] == "new"));
    }

    /// TRIAGE GROUPÉ — alert_groups_query_page (« 1 groupe = N occurrences ») + expansion via le chemin plat.
    /// Prouve : agrégat par colonne whitelistée (rule/host), compteurs (n/open_n/sev/last_ts), total = groupes
    /// distincts, aperçu échantillon (dernière occurrence), et que l'EXPANSION (group_col=rule) filtre bien à
    /// UN groupe via alerts_query_page (une seule occurrence-query).
    #[test]
    fn alert_groups_query() {
        let conn = test_db();
        // rule.1 : 4 alertes (3 new + 1 closed) sur hôtes h1/h2 ; rule.2 : 2 alertes (new) sur h1.
        conn.execute("INSERT INTO alert(ts,rule,severity,title,status,host) VALUES(1000,'rule.1',2,'A1','new','h1')", []).unwrap();
        conn.execute("INSERT INTO alert(ts,rule,severity,title,status,host) VALUES(1005,'rule.1',5,'A2','new','h2')", []).unwrap();
        conn.execute("INSERT INTO alert(ts,rule,severity,title,status,host) VALUES(1010,'rule.1',3,'A3-dernier','new','h1')", []).unwrap();
        conn.execute("INSERT INTO alert(ts,rule,severity,title,status,host) VALUES(900,'rule.1',2,'A0','closed','h1')", []).unwrap();
        conn.execute("INSERT INTO alert(ts,rule,severity,title,status,host) VALUES(2000,'rule.2',4,'B1','new','h1')", []).unwrap();
        conn.execute("INSERT INTO alert(ts,rule,severity,title,status,host) VALUES(2001,'rule.2',4,'B2-dernier','new','h1')", []).unwrap();
        // GROUPE PAR RÈGLE, tous statuts : 2 groupes ; rule.2 en tête (last_ts=2001 > rule.1 last_ts=1010).
        let (groups, total) = alert_groups_query_page(&conn, "rule", &FiltreAlertes::default(), 50, 0);
        assert_eq!(total, Some(2), "2 groupes distincts (rule.1, rule.2)");
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["gkey"], "rule.2", "tri par last_ts DESC -> rule.2 en tête");
        assert_eq!(groups[0]["n"], 2);
        assert_eq!(groups[0]["sample_title"], "B2-dernier", "aperçu = occurrence la plus récente du groupe");
        let g1 = &groups[1];
        assert_eq!(g1["gkey"], "rule.1");
        assert_eq!(g1["n"], 4, "4 occurrences (tous statuts)");
        assert_eq!(g1["open_n"], 3, "3 encore 'new'");
        assert_eq!(g1["severity"], 5, "sévérité MAX du groupe");
        assert_eq!(g1["last_ts"], 1010);
        assert_eq!(g1["first_ts"], 900);
        assert_eq!(g1["sample_title"], "A3-dernier", "titre échantillon = dernière alerte du groupe");
        // GROUPE PAR RÈGLE, statut=new : rule.1 compte 3 (le 'closed' exclu du WHERE).
        let (gnew, _) = alert_groups_query_page(&conn, "rule", &FiltreAlertes { statut: Some("new".into()), ..Default::default() }, 50, 0);
        let r1 = gnew.iter().find(|g| g["gkey"] == "rule.1").unwrap();
        assert_eq!(r1["n"], 3, "filtre statut=new appliqué au groupe");
        // GROUPE PAR HÔTE, tous statuts : h1 (5) + h2 (1) + 2 alertes SANS hôte (host NULL) -> groupe '' (n=2).
        conn.execute("INSERT INTO alert(ts,rule,severity,title,status) VALUES(1500,'rule.9',2,'NH1','new')", []).unwrap(); // host NULL
        conn.execute("INSERT INTO alert(ts,rule,severity,title,status) VALUES(1501,'rule.9',2,'NH2','new')", []).unwrap(); // host NULL
        let (gh, ght) = alert_groups_query_page(&conn, "host", &FiltreAlertes::default(), 50, 0);
        assert_eq!(ght, Some(3), "3 clés hôte distinctes (h1, h2, '' pour NULL)");
        let h1 = gh.iter().find(|g| g["gkey"] == "h1").unwrap();
        assert_eq!(h1["n"], 5, "5 alertes sur h1");
        let hnull = gh.iter().find(|g| g["gkey"] == "").unwrap();
        assert_eq!(hnull["n"], 2, "les alertes host NULL fusionnent dans le groupe ''");
        // ROUND-TRIP du groupe NULL : l'expansion `gval=''` (COALESCE(host,'')='') matche bien les lignes NULL.
        let (nocc, noct, _) = alerts_query_page(&conn, &FiltreAlertes::default(), Some("host"), "", 50, 0, true);
        assert_eq!(noct, Some(2), "expansion du groupe host '' -> les 2 alertes NULL (round-trip)");
        assert!(nocc.iter().all(|a| a["title"] == "NH1" || a["title"] == "NH2"));
        // EXPANSION d'un groupe via le chemin PLAT (gkey=rule&gval=rule.1) : les 4 occurrences de rule.1, paginées.
        let (occ, occt, _) = alerts_query_page(&conn, &FiltreAlertes::default(), Some("rule"), "rule.1", 50, 0, true);
        assert_eq!(occt, Some(4), "expansion -> total = occurrences du groupe");
        assert_eq!(occ.len(), 4);
        assert!(occ.iter().all(|a| a["rule"] == "rule.1"), "l'expansion est SCOPÉE au groupe");
        // COHÉRENCE D'APERÇU — APERÇU RE-SCOPÉ AU STATUT : un 'closed' PLUS RÉCENT que le dernier
        // 'new' du groupe NE DOIT PAS être l'aperçu en scope Actives (sinon titre incohérent avec last_ts/n
        // filtrés). rule.7/h9 est disjoint des données ci-dessus -> n'affecte aucune assertion précédente.
        conn.execute("INSERT INTO alert(ts,rule,severity,title,status,host) VALUES(3000,'rule.7',2,'C-new','new','h9')", []).unwrap();
        conn.execute("INSERT INTO alert(ts,rule,severity,title,status,host) VALUES(3100,'rule.7',2,'C-closed-plus-recent','closed','h9')", []).unwrap();
        let (gact, _) = alert_groups_query_page(&conn, "rule", &FiltreAlertes { statut: Some("new".into()), ..Default::default() }, 50, 0);
        let r7 = gact.iter().find(|g| g["gkey"] == "rule.7").unwrap();
        assert_eq!(r7["n"], 1, "scope Actives : seule l'alerte 'new' compte");
        assert_eq!(r7["last_ts"], 3000, "last_ts = la 'new' (la 'closed' plus récente est hors scope)");
        assert_eq!(r7["sample_title"], "C-new", "aperçu RE-SCOPÉ : la 'new', PAS la 'closed' plus récente (cohérent avec last_ts)");
        // …et en TOUS statuts l'aperçu redevient la plus récente ABSOLUE (closed incluse) : best-effort inchangé.
        let (gall7, _) = alert_groups_query_page(&conn, "rule", &FiltreAlertes::default(), 50, 0);
        let r7all = gall7.iter().find(|g| g["gkey"] == "rule.7").unwrap();
        assert_eq!(r7all["sample_title"], "C-closed-plus-recent", "tous statuts : aperçu = plus récente absolue");
    }

    /// TRIAGE GROUPÉ — garanties RBAC + sûreté de la whitelist de colonnes de groupement.
    #[test]
    fn alert_groups_rbac_and_whitelist() {
        // GET /api/alerts/groups = LECTURE (non-mutant) -> viewer+ (route_min_role case 6), pas de mutation.
        assert_eq!(route_min_role("/api/alerts/groups", false), MinRole::Read, "liste groupée = lecture viewer+");
        assert!(rbac_gate("viewer", "/api/alerts/groups", false).is_ok(), "viewer lit les groupes");
        assert!(rbac_gate("editor", "/api/alerts/groups", false).is_ok());
        // La colonne de groupement est STRICTEMENT whitelistée (jamais d'interpolation de texte client).
        assert_eq!(alert_group_col("rule"), Some("rule"));
        assert_eq!(alert_group_col("host"), Some("host"));
        assert_eq!(alert_group_col("mitre"), Some("mitre"));
        assert_eq!(alert_group_col("dedup"), Some("dedup"));
        assert_eq!(alert_group_col("title); DROP TABLE alert;--"), None, "toute autre entrée est REJETÉE");
        assert_eq!(alert_group_col(""), None);
        // Colonnes nullables normalisées COALESCE (round-trip du groupe '') ; NOT NULL laissées nues (index).
        assert_eq!(alert_group_expr("host"), "COALESCE(alert.host,'')");
        assert_eq!(alert_group_expr("dedup"), "COALESCE(alert.dedup,'')");
        assert_eq!(alert_group_expr("rule"), "alert.rule");
        assert_eq!(alert_group_expr("mitre"), "alert.mitre");
    }

    /// FLOTTE — fleet_query_page : inventaire d'hôtes (dernier/premier signal + nb de signaux, toutes tables ;
    /// statut fresh/stale/silent dérivé de l'âge), enrôlement best-effort (token host-lié), tri whitelisté +
    /// pagination Rust, total = hôtes distincts. Prouve aussi le gating LECTURE viewer+ de GET /api/fleet.
    #[test]
    fn fleet_inventory_and_rbac() {
        let conn = test_db();
        let now_ts = 1_000_000_i64;
        // h-fresh : dernier signal il y a 60 s (fresh) + 2 events + 1 metric = 3 signaux, ENRÔLÉ (token host-lié).
        conn.execute("INSERT INTO event(ts,host,source,category,severity,message) VALUES(?1,'h-fresh','ufw','net',1,'a')", params![now_ts - 60]).unwrap();
        conn.execute("INSERT INTO event(ts,host,source,category,severity,message) VALUES(?1,'h-fresh','ufw','net',1,'b')", params![now_ts - 120]).unwrap();
        conn.execute("INSERT INTO metric(ts,host,name,value) VALUES(?1,'h-fresh','load1',0.5)", params![now_ts - 90]).unwrap();
        // h-stale : dernier signal il y a 1800 s (stale, entre 15 min et 1 h), PAS de token -> non enrôlé.
        conn.execute("INSERT INTO event(ts,host,source,category,severity,message) VALUES(?1,'h-stale','web','http',1,'c')", params![now_ts - 1800]).unwrap();
        // h-silent : dernier signal il y a 7200 s (> 1 h -> silent). Un snapshot suffit.
        conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,'controls','h','{}','h-silent')", params![now_ts - 7200]).unwrap();
        // host '' (NULL/vide) EXCLU de l'inventaire (WHERE host<>'').
        conn.execute("INSERT INTO event(ts,host,source,category,severity,message) VALUES(?1,'','x','y',1,'z')", params![now_ts - 10]).unwrap();
        conn.execute("INSERT INTO token(name,token_hash,created,last_used,host) VALUES('agent-fresh',?1,?2,?3,'h-fresh')", params!["deadbeef01", now_ts - 100_000, now_ts - 55]).unwrap();

        // Les vues LISENT le rollup pré-agrégé host_rollup (plus de scan event∪metric∪snapshot). On le peuple via
        // rollup_hosts ; le watermark est remis à 0 pour que la fenêtre DÉFINITIVE [0, recent) couvre les timestamps
        // SYNTHÉTIQUES du test (bien en-deçà de l'heure réelle utilisée en interne par rollup_hosts).
        conn.execute("DELETE FROM meta WHERE key='host_rollup_wm'", []).unwrap();
        rollup_hosts(&conn);

        let (page, total, pipe) = fleet_query_page(&conn, now_ts, "", true, 50, 0);
        assert_eq!(total, 3, "3 hôtes nommés (host '' exclu)");
        assert!(pipe, "pipeline frais (dernier signal < 600 s)");
        // tri défaut = last_seen DESC -> h-fresh (dernier signal le plus récent) en tête.
        assert_eq!(page[0]["host"], "h-fresh");
        assert_eq!(page[0]["status"], "fresh");
        assert_eq!(page[0]["signals"], 3, "2 events + 1 metric");
        assert_eq!(page[0]["first_seen"], now_ts - 120, "premier signal = MIN(ts)");
        assert_eq!(page[0]["enrolled"], true);
        assert_eq!(page[0]["enroll_name"], "agent-fresh");
        assert_eq!(page[0]["enroll_created"], now_ts - 100_000);
        assert_eq!(page[0]["token_last_used"], now_ts - 55);
        // statuts dérivés de l'âge (fresh<=900<stale<=3600<silent) + enrôlement absent sans token.
        let stale = page.iter().find(|h| h["host"] == "h-stale").unwrap();
        assert_eq!(stale["status"], "stale");
        assert_eq!(stale["enrolled"], false, "pas de token -> non enrôlé, aucune fuite");
        assert_eq!(stale["enroll_name"], "");
        let silent = page.iter().find(|h| h["host"] == "h-silent").unwrap();
        assert_eq!(silent["status"], "silent");
        // tri par STATUT (problèmes d'abord, ASCENDANT) : silent en tête.
        let (bystatus, _, _) = fleet_query_page(&conn, now_ts, "status", false, 50, 0);
        assert_eq!(bystatus[0]["status"], "silent");
        // pagination (tri host ASC) : limit=1 -> 1 ligne, total inchangé, pages disjointes.
        let (p0, t0, _) = fleet_query_page(&conn, now_ts, "host", false, 1, 0);
        assert_eq!(p0.len(), 1);
        assert_eq!(t0, 3);
        assert_eq!(p0[0]["host"], "h-fresh", "host ASC : h-fresh d'abord");
        let (p1, _, _) = fleet_query_page(&conn, now_ts, "host", false, 1, 1);
        assert_eq!(p1[0]["host"], "h-silent", "page suivante (offset) disjointe");
        // whitelist de tri : une clé inconnue retombe sur last_seen (jamais d'ORDER interpolé).
        assert_eq!(fleet_sort_key("host"), "host");
        assert_eq!(fleet_sort_key("title); DROP TABLE token;--"), "last_seen", "clé de tri inconnue -> défaut sûr");
        // RBAC : GET /api/fleet = LECTURE (non-mutant) -> viewer+ (route_min_role case 6), pas une mutation.
        assert_eq!(route_min_role("/api/fleet", false), MinRole::Read, "flotte = lecture viewer+");
        assert!(rbac_gate("viewer", "/api/fleet", false).is_ok(), "viewer lit la flotte");
        assert!(rbac_gate("editor", "/api/fleet", false).is_ok());
    }

    /// HOST_ROLLUP (v77) — le rollup se MET À JOUR au tick (mirror ingest), l'UPSERT est BATCHÉ (un statement), et
    /// le data-plane reste BYTE-IDENTIQUE (rollup_hosts ne touche JAMAIS la table event). Idempotence de la fenêtre
    /// chaude (re-tick ne double pas les signaux).
    #[test]
    fn host_rollup_updates_on_ingest_batched_and_data_plane_untouched() {
        let conn = test_db();
        let t = now();
        // « ingestion » : 3 events + 1 metric + 1 snapshot pour hostA ; 1 event pour hostB (fenêtre chaude).
        for i in 0..3 { conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'hostA','sshd','m')", params![t - i]).unwrap(); }
        conn.execute("INSERT INTO metric(ts,host,name,value) VALUES(?1,'hostA','load1',0.4)", params![t - 5]).unwrap();
        conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,'controls','h','{}','hostA')", params![t - 10]).unwrap();
        conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'hostB','web','m')", params![t - 2]).unwrap();
        // MODE 0 BYTE-IDENTIQUE : empreinte de la table event AVANT le rollup.
        let ev_before: Vec<(i64, String, i64)> = {
            let mut s = conn.prepare("SELECT id,host,ts FROM event ORDER BY id").unwrap();
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().flatten().collect()
        };

        rollup_hosts(&conn); // = ce que fait rollup_events() à chaque tick (piggyback)

        // host_rollup reflète l'ingestion : last_ts=MAX / first_ts=MIN toutes tables, signals = compte exact.
        let (a_last, a_first, a_sig): (i64, i64, i64) = conn.query_row(
            "SELECT last_ts, first_ts, sig_total + sig_hot FROM host_rollup WHERE host='hostA'",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!(a_last, t, "last_ts = MAX(ts)");
        assert_eq!(a_first, t - 10, "first_ts = MIN(ts) sur event∪metric∪snapshot");
        assert_eq!(a_sig, 5, "5 signaux (3 events + 1 metric + 1 snapshot)");
        let b_sig: i64 = conn.query_row("SELECT sig_total + sig_hot FROM host_rollup WHERE host='hostB'", [], |r| r.get(0)).unwrap();
        assert_eq!(b_sig, 1, "hostB : 1 signal");

        // DATA-PLANE INCHANGÉ : rollup_hosts n'a NI modifié NI ajouté/supprimé de ligne event.
        let ev_after: Vec<(i64, String, i64)> = {
            let mut s = conn.prepare("SELECT id,host,ts FROM event ORDER BY id").unwrap();
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().flatten().collect()
        };
        assert_eq!(ev_before, ev_after, "rollup_hosts ne touche JAMAIS event (mode 0 byte-identique)");

        // IDEMPOTENT : ré-agréger la fenêtre chaude ne double PAS les signaux (sig_hot recalculé, pas additionné).
        rollup_hosts(&conn);
        let a_sig2: i64 = conn.query_row("SELECT sig_total + sig_hot FROM host_rollup WHERE host='hostA'", [], |r| r.get(0)).unwrap();
        assert_eq!(a_sig2, 5, "re-tick ne double pas la fenêtre chaude");
    }

    /// HOST_ROLLUP (v77) — PREUVE que /api/fleet ET /api/integrations lisent le ROLLUP et NON un scan de
    /// event∪metric∪snapshot : après avoir peuplé host_rollup, on VIDE les 3 tables brutes ; les hôtes DOIVENT
    /// rester (un scan renverrait 0). C'est aussi la garantie « agent mort reste visible » (rollup jamais pruné).
    #[test]
    fn fleet_and_integrations_read_rollup_not_event_scan() {
        let conn = test_db();
        let now_ts = 2_000_000_i64;
        conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'ghost','sshd','m')", params![now_ts - 30]).unwrap();
        conn.execute("INSERT INTO metric(ts,host,name,value) VALUES(?1,'ghost','load1',1.0)", params![now_ts - 40]).unwrap();
        conn.execute("DELETE FROM meta WHERE key='host_rollup_wm'", []).unwrap(); // fenêtre définitive couvre les ts synthétiques
        rollup_hosts(&conn);
        // On PURGE les tables brutes : si les vues scannaient event/metric/snapshot elles renverraient 0 hôte.
        conn.execute_batch("DELETE FROM event; DELETE FROM metric; DELETE FROM snapshot;").unwrap();
        // /api/integrations (host_inventory_simple) : l'hôte survit.
        let simple = host_inventory_simple(&conn);
        assert_eq!(simple.len(), 1, "integrations lit host_rollup (survivant à la purge des tables brutes)");
        assert_eq!(simple[0]["host"], "ghost");
        assert_eq!(simple[0]["last_seen"], now_ts - 30, "last_seen = MAX(last_ts) du rollup");
        // /api/fleet (fleet_scan_all) : idem, avec first_seen/signals du rollup.
        let (page, total, _) = fleet_query_page(&conn, now_ts, "", true, 50, 0);
        assert_eq!(total, 1, "fleet lit host_rollup (agent mort reste VISIBLE)");
        assert_eq!(page[0]["host"], "ghost");
        assert_eq!(page[0]["signals"], 2, "2 signaux (1 event + 1 metric) préservés dans le rollup");
        assert_eq!(page[0]["first_seen"], now_ts - 40);
    }

    /// HOST_ROLLUP (v77) — statut fresh/stale/silent correct À TRAVERS LES DEUX FENÊTRES : le silent (heure
    /// définitive, [0,recent)) atterrit dans sig_total ; fresh/stale (fenêtre chaude, [recent,now]) dans sig_hot.
    #[test]
    fn host_rollup_status_fresh_stale_silent_across_windows() {
        let conn = test_db();
        let t = now();
        conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'h-fresh','sshd','m')", params![t - 60]).unwrap();       // <15 min -> fresh (chaude)
        conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'h-stale','web','m')", params![t - 1800]).unwrap();      // 30 min -> stale (chaude)
        conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,'controls','h','{}','h-silent')", params![t - 7200]).unwrap(); // 2 h -> silent (définitive)
        conn.execute("DELETE FROM meta WHERE key='host_rollup_wm'", []).unwrap();
        rollup_hosts(&conn);
        let (page, total, _) = fleet_query_page(&conn, t, "", true, 50, 0);
        assert_eq!(total, 3);
        let st = |h: &str| page.iter().find(|x| x["host"] == h).unwrap()["status"].as_str().unwrap().to_string();
        assert_eq!(st("h-fresh"), "fresh");
        assert_eq!(st("h-stale"), "stale");
        assert_eq!(st("h-silent"), "silent");
        // le silent (heure définitive) est compté dans sig_total ; fresh (fenêtre chaude) dans sig_hot.
        let sil: (i64, i64) = conn.query_row("SELECT sig_total, sig_hot FROM host_rollup WHERE host='h-silent'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(sil, (1, 0), "silent = heure définitive -> sig_total");
        let fr: (i64, i64) = conn.query_row("SELECT sig_total, sig_hot FROM host_rollup WHERE host='h-fresh'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(fr, (0, 1), "fresh = fenêtre chaude -> sig_hot");
    }

    /// HOST_ROLLUP (v77) — le BACKFILL de la migration seede les hôtes EXISTANTS (sans aucun tick rollup) : on
    /// rétrograde + DROP host_rollup (simule une base PRÉ-v77 avec des données), on re-migre, et les hôtes présents
    /// dans event/metric/snapshot sont immédiatement dans host_rollup (last/first/signals corrects).
    #[test]
    fn host_rollup_backfill_seeds_existing_hosts_on_migration() {
        let conn = test_db(); // déjà v77
        let now_ts = 3_000_000_i64;
        conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'seed-a','sshd','m')", params![now_ts - 100]).unwrap();
        conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'seed-a','sshd','m')", params![now_ts - 200]).unwrap();
        conn.execute("INSERT INTO metric(ts,host,name,value) VALUES(?1,'seed-b','load1',0.1)", params![now_ts - 300]).unwrap();
        conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'','ignored','m')", params![now_ts - 50]).unwrap(); // host '' exclu
        // simule PRÉ-v77 : DROP la table dérivée + rétrograde -> le bloc v77 (CREATE + backfill) DOIT re-tourner.
        conn.execute("DROP TABLE host_rollup", []).unwrap();
        conn.execute("UPDATE meta SET value='76' WHERE key='schema_version'", []).unwrap();
        let _ = migrate(&conn);
        assert_eq!(conn.query_row::<String, _, _>("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap(), CODE_SCHEMA_MAX.to_string());
        let (a_last, a_first, a_sig): (i64, i64, i64) = conn.query_row(
            "SELECT last_ts, first_ts, sig_total + sig_hot FROM host_rollup WHERE host='seed-a'",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!((a_last, a_first, a_sig), (now_ts - 100, now_ts - 200, 2), "seed-a backfillé (2 events)");
        let b_sig: i64 = conn.query_row("SELECT sig_total + sig_hot FROM host_rollup WHERE host='seed-b'", [], |r| r.get(0)).unwrap();
        assert_eq!(b_sig, 1, "seed-b (metric-only) backfillé");
        let empty: i64 = conn.query_row("SELECT COUNT(*) FROM host_rollup WHERE host=''", [], |r| r.get(0)).unwrap();
        assert_eq!(empty, 0, "host '' exclu du backfill");
        // les vues lisent immédiatement les hôtes seedés.
        let (_page, total, _) = fleet_query_page(&conn, now_ts, "", true, 50, 0);
        assert_eq!(total, 2);
    }

    /// HOST_ROLLUP (v77) — COÛT du tick borné : l'UPSERT est UN statement batché (agrégat), pas du travail
    /// par-ligne, et reste TRÈS en-dessous du watchdog 5 s. (Mesure imprimée avec --nocapture.)
    #[test]
    fn host_rollup_maintenance_cost_is_bounded() {
        let conn = test_db();
        let t = now();
        conn.execute_batch("BEGIN").unwrap();
        for i in 0..5000i64 {
            conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,?2,'sshd','m')",
                params![t - (i % 3000), format!("host{}", i % 20)]).unwrap();
        }
        conn.execute_batch("COMMIT").unwrap();
        conn.execute("DELETE FROM meta WHERE key='host_rollup_wm'", []).unwrap();
        let start = std::time::Instant::now();
        rollup_hosts(&conn);
        let d = start.elapsed();
        eprintln!("[measure] rollup_hosts sur 5000 events / 20 hôtes : {d:?}");
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM host_rollup", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 20, "20 hôtes agrégés en une passe");
        assert!(d < std::time::Duration::from_secs(2), "un tick rollup_hosts reste bien SOUS le watchdog 5 s (mesuré {d:?})");
    }

    /// HOST_ROLLUP (cas BACKDATED) — un event TARDIF (ts < watermark, agent offline qui rejoue son buffer) doit
    /// être RATTRAPÉ : sans le plancher il tombe hors des fenêtres définitive/chaude -> hôte INVISIBLE / first_seen
    /// trop récent. Avec note_host_backfill_floor + le fold Backfill [floor, wm), l'hôte apparaît avec le VRAI
    /// first_seen, et le rattrapage est IDEMPOTENT (re-tick ne double pas).
    #[test]
    fn host_rollup_backdated_event_caught_up() {
        let conn = test_db();
        let t = now();
        let cur = (t / 3600) * 3600;
        let recent = (cur - 3600).max(0);
        // régime établi : watermark déjà à `recent` (la fenêtre définitive [wm,recent) est vide).
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('host_rollup_wm', ?1)", params![recent.to_string()]).unwrap();
        let late_ts = recent - 7200; // 2 h SOUS le watermark
        conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'late-host','journal','m')", params![late_ts]).unwrap();
        // AVANT le plancher : l'event tardif n'est dans AUCUNE fenêtre -> hôte invisible (régression corrigée).
        rollup_hosts(&conn);
        let before: i64 = conn.query_row("SELECT COUNT(*) FROM host_rollup WHERE host='late-host'", [], |r| r.get(0)).unwrap();
        assert_eq!(before, 0, "sans plancher, event tardif (<wm) hors fenêtres -> hôte invisible");
        // l'ingest note le plancher (ts < wm) ; le tick suivant folde [late_ts, recent) -> hôte visible.
        note_host_backfill_floor(&conn, late_ts);
        rollup_hosts(&conn);
        let (first, sig): (i64, i64) = conn.query_row(
            "SELECT first_ts, sig_total + sig_hot FROM host_rollup WHERE host='late-host'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(first, late_ts, "first_seen = ts réel de la 1re activité (pas 'trop récent')");
        assert_eq!(sig, 1, "hôte entièrement backdaté -> compté (visible dans /api/fleet + /api/integrations)");
        // IDEMPOTENT : le floor a été remonté à wm -> plus de rattrapage -> pas de double.
        rollup_hosts(&conn);
        let sig2: i64 = conn.query_row("SELECT sig_total + sig_hot FROM host_rollup WHERE host='late-host'", [], |r| r.get(0)).unwrap();
        assert_eq!(sig2, 1, "rattrapage idempotent (re-tick ne double pas)");
    }

    /// HOST_ROLLUP (cas BACKDATED / double-comptage) — un fold Backfill qui CHEVAUCHE des heures déjà comptées
    /// dans la fenêtre définitive NE re-compte PAS un hôte déjà présent (sig_total figé sur conflit) ; seul le
    /// NOUVEL hôte backdaté est compté à l'INSERT. Prouve que le rattrapage ne peut pas gonfler `signals`.
    #[test]
    fn host_rollup_backfill_no_double_count_on_overlap() {
        let conn = test_db();
        let t = now();
        let cur = (t / 3600) * 3600;
        let recent = (cur - 3600).max(0);
        conn.execute("DELETE FROM meta WHERE key='host_rollup_wm'", []).unwrap(); // wm=0 -> définitive [0,recent)
        let def_ts = recent - 3600; // dans la fenêtre définitive
        conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'present','sshd','m')", params![def_ts]).unwrap();
        rollup_hosts(&conn); // 'present' folké en définitif -> sig_total=1 ; wm avance à recent
        assert_eq!(conn.query_row::<i64,_,_>("SELECT sig_total + sig_hot FROM host_rollup WHERE host='present'", [], |r| r.get(0)).unwrap(), 1);
        // un event TARDIF d'un AUTRE hôte abaisse le floor SOUS def_ts -> le catch-up [floor,recent) RECOUVRE def_ts.
        let late_ts = def_ts - 60;
        conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'late2','journal','m')", params![late_ts]).unwrap();
        note_host_backfill_floor(&conn, late_ts);
        rollup_hosts(&conn);
        assert_eq!(conn.query_row::<i64,_,_>("SELECT sig_total + sig_hot FROM host_rollup WHERE host='present'", [], |r| r.get(0)).unwrap(),
                   1, "hôte présent PAS re-compté par le catch-up chevauchant (Backfill fige sig_total sur conflit)");
        assert_eq!(conn.query_row::<i64,_,_>("SELECT sig_total + sig_hot FROM host_rollup WHERE host='late2'", [], |r| r.get(0)).unwrap(),
                   1, "nouvel hôte backdaté compté à l'INSERT");
    }

    /// note_host_backfill_floor — n'enregistre RIEN pour de la donnée courante (ts >= wm), et est MONOTONE
    /// DÉCROISSANT pour de la donnée tardive (ts < wm) : ne garde que le plus vieux ts. -> zéro surcoût ingest
    /// en régime normal, rattrapage borné au buffer réel.
    #[test]
    fn note_host_backfill_floor_monotone_decreasing() {
        let conn = test_db();
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('host_rollup_wm','1000')", []).unwrap();
        let floor = || conn.query_row::<String, _, _>("SELECT value FROM meta WHERE key='host_rollup_backfill_floor'", [], |r| r.get(0));
        note_host_backfill_floor(&conn, 2000); // >= wm (courant) -> aucun plancher écrit
        assert!(floor().is_err(), "donnée courante (ts>=wm) -> aucun plancher (zéro surcoût ingest nominal)");
        note_host_backfill_floor(&conn, 500);  // < wm (tardif) -> plancher = 500
        assert_eq!(floor().unwrap(), "500");
        note_host_backfill_floor(&conn, 800);  // < wm mais > plancher -> inchangé (monotone décroissant)
        assert_eq!(floor().unwrap(), "500");
        note_host_backfill_floor(&conn, 300);  // plus bas -> plancher = 300
        assert_eq!(floor().unwrap(), "300");
    }

    /// HOST_ROLLUP (cas DOUBLE-COMPTAGE) — l'avance du watermark définitif est ATOMIQUE avec le fold : après un
    /// tick, host_rollup_wm == recent (upsert, jamais d'état ligne-absente), et re-tick n'additionne pas sig_total
    /// (fenêtre définitive vide car wm==recent). Régression du re-fold [0,recent) qui doublait sig_total.
    #[test]
    fn host_rollup_definitive_watermark_atomic_no_double() {
        let conn = test_db();
        let t = now();
        let cur = (t / 3600) * 3600;
        let recent = (cur - 3600).max(0);
        conn.execute("DELETE FROM meta WHERE key='host_rollup_wm'", []).unwrap();
        conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'h','sshd','m')", params![recent - 3600]).unwrap();
        rollup_hosts(&conn);
        assert_eq!(conn.query_row::<String,_,_>("SELECT value FROM meta WHERE key='host_rollup_wm'", [], |r| r.get(0)).unwrap(),
                   recent.to_string(), "watermark avancé à recent en UN upsert (pas de DELETE laissant la ligne absente)");
        let s1: i64 = conn.query_row("SELECT sig_total FROM host_rollup WHERE host='h'", [], |r| r.get(0)).unwrap();
        assert_eq!(s1, 1, "compté une fois en définitif");
        rollup_hosts(&conn); // wm==recent -> fenêtre définitive vide -> pas de ré-addition
        let s2: i64 = conn.query_row("SELECT sig_total FROM host_rollup WHERE host='h'", [], |r| r.get(0)).unwrap();
        assert_eq!(s2, 1, "re-tick n'additionne pas (pas de double-comptage sig_total)");
    }

    /// MIGRATION v77 (cas BACKFILL AVALÉ) — si le backfill échoue, schema_version NE doit PAS passer à 77
    /// (sinon backfill perdu + faux 'succès' sans retry). Mirroir du pattern v33. On bloque l'INSERT host_rollup
    /// par un trigger -> le backfill retourne Err -> version LAISSÉE à 76 (RE-TENTÉE au prochain boot).
    #[test]
    fn migration_v77_failed_backfill_does_not_bump_version() {
        let conn = test_db(); // déjà v77
        conn.execute("CREATE TRIGGER hr_block BEFORE INSERT ON host_rollup BEGIN SELECT RAISE(ABORT,'blocked'); END", []).unwrap();
        // une ligne à backfiller -> l'INSERT ... SELECT tentera d'insérer -> le trigger ABORT -> Err propagée.
        conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'h','sshd','m')", params![now() - 100]).unwrap();
        conn.execute("UPDATE meta SET value='76' WHERE key='schema_version'", []).unwrap();
        let _ = migrate(&conn);
        assert_eq!(conn.query_row::<String,_,_>("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap(),
                   "76", "backfill en échec -> version reste 76 (retry au prochain boot ; JAMAIS avalée + faux succès)");
    }

    /// INDEX ts-leading (cas FULL-SCAN metric/snapshot + MAX(ts) par-requête) — ensure_host_rollup_scan_indexes_
    /// background crée idx_metric_ts / idx_snapshot_ts (idempotent), et le `MAX(ts)` de pipeline_is_fresh devient
    /// alors un MAX INDEXÉ (plan SQLite = index, pas un full-scan). Preuve de l'optimisation sans changer la sémantique.
    #[test]
    fn host_rollup_scan_indexes_created_and_used_by_max_ts() {
        let db = std::sync::Arc::new(parking_lot::Mutex::new(test_db()));
        ensure_host_rollup_scan_indexes_background(&db);
        ensure_host_rollup_scan_indexes_background(&db); // idempotent (court-circuit, aucune erreur)
        let conn = db.lock();
        for name in ["idx_metric_ts", "idx_snapshot_ts"] {
            assert!(conn.query_row("SELECT 1 FROM sqlite_master WHERE type='index' AND name=?1", params![name], |_| Ok(())).is_ok(),
                    "{name} créé");
        }
        let plan = |sql: &str| -> String {
            let mut s = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let rows: Vec<String> = s.query_map([], |r| r.get::<_, String>(3)).unwrap().flatten().collect();
            rows.join(" | ")
        };
        // MIN/MAX sur colonne indexée = optimisation DÉTERMINISTE de SQLite (un seul accès index, O(1)), indépendante
        // du nombre de lignes -> pipeline_is_fresh ne full-scanne plus metric/snapshot.
        let pm = plan("SELECT MAX(ts) FROM metric");
        assert!(pm.contains("idx_metric_ts"), "MAX(ts) metric = max indexé O(1), plan={pm}");
        let ps = plan("SELECT MAX(ts) FROM snapshot");
        assert!(ps.contains("idx_snapshot_ts"), "MAX(ts) snapshot = max indexé O(1), plan={ps}");
    }

    /// LIENS event/alerte : item typé + ref 'alert:ID'/'event:ID' -> résolution INVERSE (titre + sévérité) dans
    /// la timeline. Ref inconnue/vide -> résolution nulle (pas de panic, pas de scan).
    #[test]
    fn case_link_ref_resolution() {
        let conn = test_db();
        conn.execute("INSERT INTO alert(ts,rule,severity,title,status) VALUES(?1,'rule.1',3,'Alerte SSH','new')", params![now()]).unwrap();
        let aid = conn.last_insert_rowid();
        conn.execute("INSERT INTO event(ts,source,severity,message) VALUES(?1,'sshd',2,'login failed')", params![now()]).unwrap();
        let eid = conn.last_insert_rowid();
        let id = case_create_row(&conn, "alice", "Case", 2, "", None, 3);
        case_add_item(&conn, id, now(), "alert", "alice", "rattachée", Some(&format!("alert:{aid}")));
        case_add_item(&conn, id, now(), "event", "alice", "rattaché", Some(&format!("event:{eid}")));
        let c = case_get_json(&conn, id, now()).unwrap();
        let items = c["items"].as_array().unwrap();
        let ai = items.iter().find(|i| i["kind"] == "alert").unwrap();
        assert_eq!(ai["ref"], format!("alert:{aid}"));
        assert_eq!(ai["ref_title"], "Alerte SSH", "titre alerte résolu");
        assert_eq!(ai["ref_severity"], 3);
        let ei = items.iter().find(|i| i["kind"] == "event").unwrap();
        assert_eq!(ei["ref_title"], "login failed", "message event résolu");
        assert_eq!(ei["ref_severity"], 2);
        assert_eq!(resolve_case_ref(&conn, "alert:999999"), (None, None), "cible absente -> null");
        assert_eq!(resolve_case_ref(&conn, ""), (None, None), "ref vide -> null");
    }

    /// DÉTACHEMENT : supprime l'item du case (borné à incident_id, anti-IDOR) + trace une note. false si l'item
    /// n'appartient pas au case.
    #[test]
    fn case_detach_item_test() {
        let conn = test_db();
        let id = case_create_row(&conn, "alice", "Case", 2, "", None, 3);
        case_add_item(&conn, id, now(), "alert", "alice", "rattachée", Some("alert:5"));
        let item_id: i64 = conn.query_row("SELECT id FROM incident_item WHERE incident_id=?1 AND kind='alert'", params![id], |r| r.get(0)).unwrap();
        assert!(case_detach_item(&conn, id, item_id, "bob"));
        // NB : ne pas compter par rowid (SQLite réutilise le rowid libéré pour la note de détachement) -> par kind.
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='alert'", params![id], |r| r.get(0)).unwrap(), 0, "item alerte détaché");
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='note' AND body LIKE 'détaché%'", params![id], |r| r.get(0)).unwrap(), 1, "note de détachement tracée");
        assert!(!case_detach_item(&conn, id, 999999, "bob"), "item inexistant -> false");
        let other = case_create_row(&conn, "alice", "Other", 2, "", None, 3);
        case_add_item(&conn, other, now(), "note", "alice", "x", None);
        let other_item: i64 = conn.query_row("SELECT id FROM incident_item WHERE incident_id=?1 AND kind='note'", params![other], |r| r.get(0)).unwrap();
        assert!(!case_detach_item(&conn, id, other_item, "bob"), "ne détache pas l'item d'un AUTRE case (anti-IDOR)");
    }

    /// ESCALADE SLA : un case overdue non escaladé -> escalated=1 + item 'sla' + ledger, une SEULE fois. Sans
    /// notifier activé : aucun réseau (testable offline). Un case dans les temps n'est jamais escaladé.
    #[test]
    fn case_escalate_overdue_test() {
        let conn = test_db();
        let base = now();
        let id = case_create_row(&conn, "alice", "Overdue", 4, "", None, 1);
        conn.execute("UPDATE incident SET sla_due=?1 WHERE id=?2", params![base - 100, id]).unwrap();
        let db = Arc::new(Mutex::new(conn));
        escalate_overdue_cases(&db);
        {
            let c = db.lock();
            assert_eq!(c.query_row::<i64, _, _>("SELECT escalated FROM incident WHERE id=?1", params![id], |r| r.get(0)).unwrap(), 1, "overdue -> escalated");
            assert_eq!(c.query_row::<i64, _, _>("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='sla'", params![id], |r| r.get(0)).unwrap(), 1, "item sla tracé");
            assert_eq!(c.query_row::<i64, _, _>("SELECT COUNT(*) FROM ledger WHERE kind='case.sla_escalate'", [], |r| r.get(0)).unwrap(), 1, "ledger sla");
        }
        escalate_overdue_cases(&db); // 2e passage : idempotent (escalated=1)
        {
            let c = db.lock();
            assert_eq!(c.query_row::<i64, _, _>("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='sla'", params![id], |r| r.get(0)).unwrap(), 1, "pas de re-notification");
        }
        let fresh = { let c = db.lock(); case_create_row(&c, "alice", "Fresh", 2, "", None, 3) };
        escalate_overdue_cases(&db);
        {
            let c = db.lock();
            assert_eq!(c.query_row::<i64, _, _>("SELECT escalated FROM incident WHERE id=?1", params![fresh], |r| r.get(0)).unwrap(), 0, "case dans les temps non escaladé");
        }
    }

    /// RBAC serveur (hérité du choke-point) : viewer = lecture seule ; editor & admin gèrent les cases (pas
    /// admin-only). Confirme l'INVARIANT rôles côté /api/cases sans toucher rbac_gate.
    #[test]
    fn case_rbac_roles() {
        assert!(rbac_gate("viewer", "/api/cases", false).is_ok(), "viewer lit les cases");
        assert!(rbac_gate("viewer", "/api/cases/5", false).is_ok());
        assert!(rbac_gate("viewer", "/api/cases", true).is_err(), "viewer ne mute pas");
        assert!(rbac_gate("viewer", "/api/cases/5/items", true).is_err());
        assert!(rbac_gate("viewer", "/api/cases/5/items/7", true).is_err(), "viewer ne détache pas");
        assert!(rbac_gate("editor", "/api/cases", true).is_ok(), "editor gère les cases");
        assert!(rbac_gate("editor", "/api/cases/5/items/7", true).is_ok(), "editor détache");
        assert!(rbac_gate("admin", "/api/cases", true).is_ok(), "admin gère les cases");
    }

    /// #4a-bis — ARCHIVE (soft-delete) : masque de la liste par défaut, visible via ?archived=1, AJOUTE un item
    /// de timeline SANS rien supprimer (append-only), puis désarchive (ré-affiché + item 'unarchive'). INVARIANT
    /// mode 0 : un case non archivé est servi exactement comme avant.
    #[test]
    fn case_archive_soft_delete() {
        let conn = test_db();
        let a = case_create_row(&conn, "alice", "Actif", 3, "", None, 2);
        let z = case_create_row(&conn, "alice", "ZZ_DEPLOY_VERIFY_4a", 2, "résidu", None, 3);
        // pré-condition : les 2 cases sont visibles par défaut, 0 archive.
        assert_eq!(cases_list_json(&conn, now(), "", "", 0, false, false)["cases"].as_array().unwrap().len(), 2, "2 cases actifs avant archive (mode 0 inchangé)");
        assert_eq!(cases_list_json(&conn, now(), "", "", 0, false, true)["cases"].as_array().unwrap().len(), 0, "aucune archive avant");
        let items_before: i64 = conn.query_row("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1", params![z], |r| r.get(0)).unwrap();
        // ARCHIVE le case résiduel.
        assert!(case_set_archived(&conn, z, "root", true));
        // (1) liste par défaut : l'archivé disparaît, l'actif reste.
        let defc = cases_list_json(&conn, now(), "", "", 0, false, false);
        let defc = defc["cases"].as_array().unwrap();
        assert_eq!(defc.len(), 1, "l'archivé est masqué de la liste par défaut");
        assert_eq!(defc[0]["id"], a, "seul le case actif reste visible");
        // (2) vue dédiée ?archived=1 : uniquement l'archivé.
        let archc = cases_list_json(&conn, now(), "", "", 0, false, true);
        let archc = archc["cases"].as_array().unwrap();
        assert_eq!(archc.len(), 1, "vue archives -> uniquement l'archivé");
        assert_eq!(archc[0]["id"], z);
        assert_eq!(archc[0]["archived"], true, "flag archived exposé sur la ligne");
        // (3) APPEND-ONLY : la ligne existe toujours + timeline a GAGNÉ un item 'archive' (rien supprimé).
        let row = case_get_json(&conn, z, now()).unwrap();
        assert_eq!(row["archived"], true);
        assert_eq!(row["archived_by"], "root");
        assert!(row["archived_ts"].as_i64().is_some(), "archived_ts posé");
        let items_after: i64 = conn.query_row("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1", params![z], |r| r.get(0)).unwrap();
        assert_eq!(items_after, items_before + 1, "archive AJOUTE un item (append-only, aucune suppression)");
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='archive'", params![z], |r| r.get(0)).unwrap(), 1, "item 'archive' tracé");
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM ledger WHERE kind='case.archive'", [], |r| r.get(0)).unwrap(), 1, "audit ledger case.archive");
        assert!(row["first_response_ts"].is_null(), "archive ne pollue pas le MTTA (pas une réponse analyste)");
        // DÉSARCHIVE : ré-affiché + item 'unarchive', flags remis à NULL (toujours append-only).
        assert!(case_set_archived(&conn, z, "root", false));
        assert_eq!(cases_list_json(&conn, now(), "", "", 0, false, false)["cases"].as_array().unwrap().len(), 2, "désarchivé -> ré-affiché dans la liste par défaut");
        let row2 = case_get_json(&conn, z, now()).unwrap();
        assert_eq!(row2["archived"], false);
        assert!(row2["archived_ts"].is_null() && row2["archived_by"].as_str().unwrap().is_empty(), "flags d'archive effacés au désarchivage");
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='unarchive'", params![z], |r| r.get(0)).unwrap(), 1, "item 'unarchive' tracé");
        assert!(!case_set_archived(&conn, 999999, "root", true), "case inexistant -> false");
    }

    /// #4a-bis — RBAC : archive/désarchive = ADMIN-ONLY (action delete-like) ; editor/viewer refusés. Les autres
    /// routes /api/cases/* restent editor+ (non-régression : la garde archive est ciblée sur les suffixes).
    #[test]
    fn case_archive_rbac_admin_only() {
        assert!(rbac_gate("admin", "/api/cases/5/archive", true).is_ok(), "admin archive");
        assert!(rbac_gate("admin", "/api/cases/5/unarchive", true).is_ok(), "admin désarchive");
        assert!(rbac_gate("editor", "/api/cases/5/archive", true).is_err(), "editor NE peut PAS archiver (delete-like)");
        assert!(rbac_gate("editor", "/api/cases/5/unarchive", true).is_err(), "editor NE peut PAS désarchiver");
        assert!(rbac_gate("viewer", "/api/cases/5/archive", true).is_err(), "viewer refusé");
        // non-régression : les autres routes cases restent editor+ (l'archive ne les gate pas).
        assert!(rbac_gate("editor", "/api/cases", true).is_ok(), "editor gère toujours les cases");
        assert!(rbac_gate("editor", "/api/cases/5", true).is_ok());
        assert!(rbac_gate("editor", "/api/cases/5/items", true).is_ok());
    }

    /// DURCISSEMENT — le CŒUR : rbac_gate DEFAULT-DENY. Verrouille les 3 trous fermés ET la non-régression
    /// des accès légitimes (editor CRUD détection/cases/dashboards ; viewer lecture ; agent ingest ; admin tout).
    #[test]
    fn rbac_gate_default_deny_hotfix_w1() {
        // ---------- TROUS FERMÉS ----------
        // CRITICAL — /api/password : un editor ne reset PLUS le mdp admin.
        assert!(rbac_gate("editor", "/api/password", true).is_err(), "editor NE reset PAS le mdp admin");
        assert!(rbac_gate("viewer", "/api/password", true).is_err(), "viewer refusé sur /api/password");
        assert!(rbac_gate("admin", "/api/password", true).is_ok(), "admin change le mdp");
        // HIGH — /api/mode : POST (armement réponse) = admin ; GET (lecture du mode) = viewer+.
        assert!(rbac_gate("editor", "/api/mode", true).is_err(), "editor N'ARME PAS la réponse (mode active)");
        assert!(rbac_gate("viewer", "/api/mode", true).is_err(), "viewer refusé sur POST /api/mode");
        assert!(rbac_gate("admin", "/api/mode", true).is_ok(), "admin arme le mode");
        assert!(rbac_gate("viewer", "/api/mode", false).is_ok(), "viewer LIT le mode courant (GET)");
        assert!(rbac_gate("editor", "/api/mode", false).is_ok(), "editor LIT le mode courant (GET)");
        // MEDIUM — /api/notifiers : mutation ET LECTURE (config = token/mdp) = admin only.
        assert!(rbac_gate("editor", "/api/notifiers", true).is_err(), "editor ne crée pas de canal");
        assert!(rbac_gate("editor", "/api/notifiers", false).is_err(), "editor ne LIT pas les canaux (secret)");
        assert!(rbac_gate("viewer", "/api/notifiers", false).is_err(), "viewer ne LIT pas les canaux (fuite token/mdp fermée)");
        assert!(rbac_gate("editor", "/api/notifiers/3", true).is_err(), "editor ne modifie pas un canal");
        assert!(rbac_gate("editor", "/api/notifiers/3/test", true).is_err(), "editor ne teste pas un canal");
        assert!(rbac_gate("admin", "/api/notifiers", false).is_ok(), "admin lit les canaux");
        assert!(rbac_gate("admin", "/api/notifiers", true).is_ok(), "admin gère les canaux");

        // ---------- NON-RÉGRESSION editor (INVARIANT : CRUD détection/cases/dashboards/vues/panneaux/lookups) ----------
        for p in ["/api/rules", "/api/rules/5", "/api/rules/5/test", "/api/parsers", "/api/parsers/5",
                  "/api/parser-test", "/api/rule-test", "/api/lookups", "/api/lookups/geo", "/api/views",
                  "/api/views/2", "/api/dashboards", "/api/dashboard/2", "/api/panels", "/api/panels/2",
                  "/api/playbooks", "/api/playbooks/2", "/api/playbooks/2/test", "/api/cases", "/api/cases/2",
                  "/api/cases/2/items", "/api/cases/2/items/3", "/api/alerts/ack-all", "/api/alerts/9/ack",
                  "/api/mail/body"] {
            assert!(rbac_gate("editor", p, true).is_ok(), "editor DOIT garder l'écriture sur {p}");
            assert!(rbac_gate("admin", p, true).is_ok(), "admin écrit sur {p}");
        }

        // ---------- NON-RÉGRESSION viewer (INVARIANT : lecture partout, jamais d'écriture) ----------
        for p in ["/api/overview", "/api/environments", "/api/panel/x", "/api/search", "/api/alerts",
                  "/api/coverage/detections", "/api/rules", "/api/parsers", "/api/sources", "/api/freshness",
                  "/api/integrations", "/api/fleet", "/api/cases", "/api/cases/2", "/api/dashboards", "/api/views",
                  "/api/me", "/api/my-tenants", "/api/panels/2/data"] {
            assert!(rbac_gate("viewer", p, false).is_ok(), "viewer DOIT lire {p}");
            assert!(rbac_gate("editor", p, false).is_ok(), "editor lit aussi {p}");
        }
        // POST de LECTURE (query/search/cancel : mutating=false) restent viewer.
        for p in ["/api/query", "/api/search", "/api/cancel"] {
            assert!(rbac_gate("viewer", p, false).is_ok(), "viewer exécute {p} (lecture)");
        }
        // viewer NE mute JAMAIS (échantillon).
        for p in ["/api/rules", "/api/parsers", "/api/dashboards", "/api/cases", "/api/lookups", "/api/views"] {
            assert!(rbac_gate("viewer", p, true).is_err(), "viewer NE mute PAS {p}");
        }

        // ---------- NON-RÉGRESSION agent (INVARIANT : ingest + responder uniquement) ----------
        for p in ["/api/ingest", "/api/ingest/minio", "/api/ingest/journal", "/api/metrics/prom",
                  "/api/metrics/write", "/loki/api/v1/push", "/api/actions/result"] {
            assert!(rbac_gate("agent", p, true).is_ok(), "agent DOIT ingérer {p}");
        }
        assert!(rbac_gate("agent", "/api/actions/pending", false).is_ok(), "agent réclame ses actions (GET pending)");
        // agent n'est PAS un rôle privilégié : ni admin, ni lecture UI, ni écriture éditoriale.
        assert!(rbac_gate("agent", "/api/users", true).is_err(), "agent n'administre pas les users");
        assert!(rbac_gate("agent", "/api/rules", true).is_err(), "agent n'édite pas les règles");
        assert!(rbac_gate("agent", "/api/overview", false).is_err(), "agent ne lit pas l'UI");
        // viewer/editor NE peuvent PAS ingérer (INVARIANT ingest = machine-to-machine, jamais viewer ; editor OK).
        assert!(rbac_gate("viewer", "/api/ingest", true).is_err(), "viewer n'ingère pas");
        assert!(rbac_gate("editor", "/api/ingest", true).is_ok(), "compte editor/admin collecteur peut ingérer (non-régression Basic)");

        // ---------- admin = TOUT, y compris routes admin-only et inconnues ----------
        for p in ["/api/users", "/api/users/5", "/api/connectors", "/api/retention", "/api/ledger",
                  "/api/sources/settings", "/api/actions", "/api/actions/5/approve", "/api/setup",
                  "/api/tenants", "/api/tenants/acme/grants"] {
            assert!(rbac_gate("admin", p, true).is_ok(), "admin gère {p}");
        }
        // editor/viewer bloqués sur l'admin-only (échantillon).
        for r in ["editor", "viewer"] {
            // `/api/sources/settings` n'est plus dans cet échantillon : editor+ depuis P11.3-a (cf. tests/sources_attendues_et_cadence.rs).
            for p in ["/api/users", "/api/connectors", "/api/retention", "/api/ledger", "/api/actions"] {
                assert!(rbac_gate(r, p, true).is_err(), "{r} refusé sur admin-only {p}");
            }
            assert!(rbac_gate(r, "/api/users", false).is_err(), "{r} ne LIT pas /api/users");
        }

        // ---------- DEFAULT-DENY : mutation NON déclarée (route oubliée/future) = ADMIN (fail-closed) ----------
        assert!(rbac_gate("editor", "/api/incidents", true).is_err(), "route mutante inconnue fermée à l'editor (fail-closed)");
        assert!(rbac_gate("viewer", "/api/incidents", true).is_err(), "route mutante inconnue fermée au viewer");
        assert!(rbac_gate("admin", "/api/incidents", true).is_ok(), "admin passe la route inconnue");
        assert!(rbac_gate("editor", "/api/totally-new-danger", true).is_err(), "toute mutation oubliée retombe ADMIN");
        assert!(rbac_gate("admin", "/api/totally-new-danger", true).is_ok());

        // ---------- #44 IdP natif : CRUD providers = ADMIN-ONLY (secrets) ; MFA self-service = viewer+ ----------
        for p in ["/api/idp/providers", "/api/idp/providers/5"] {
            assert!(rbac_gate("admin", p, true).is_ok(), "admin gère les providers IdP {p}");
            assert!(rbac_gate("admin", p, false).is_ok(), "admin lit les providers IdP {p}");
            assert!(rbac_gate("editor", p, false).is_err(), "editor ne LIT PAS les providers (client_secret) {p}");
            assert!(rbac_gate("editor", p, true).is_err(), "editor ne gère PAS les providers {p}");
            assert!(rbac_gate("viewer", p, false).is_err(), "viewer ne LIT PAS les providers {p}");
            assert!(rbac_gate("agent", p, true).is_err(), "agent n'a aucun accès providers {p}");
        }
        // MFA self-service : tout compte authentifié (viewer/editor/admin) enrôle/vérifie/désactive SA MFA.
        for p in ["/api/mfa/status", "/api/mfa/enroll", "/api/mfa/verify", "/api/mfa/disable"] {
            assert!(rbac_gate("viewer", p, true).is_ok(), "viewer gère sa propre MFA {p}");
            assert!(rbac_gate("editor", p, true).is_ok(), "editor gère sa propre MFA {p}");
            assert!(rbac_gate("admin", p, true).is_ok(), "admin gère sa propre MFA {p}");
        }
    }

    /// DURCISSEMENT — armement réponse : un editor NE PEUT PAS poser un playbook portant une
    /// action destructive (ban/unban/kill/stop) ; un admin le peut. Verrouille validate_detection_content.
    #[test]
    fn playbook_arming_requires_admin_hotfix_w1() {
        let _rg = CUSTOM_ROLES_TEST_LOCK.lock();
        // GXQL borné qui COMPILE (même fixture que l'overlay playbook des tests d'intégration).
        let q = "search source=x | table src_ip";
        // editor : REFUSÉ (403) pour CHAQUE action de l'ENUM (toutes destructives).
        for kind in ["ban_ip", "unban_ip", "kill_pid", "stop_service"] {
            let r = validate_detection_content("playbook", true, q, kind, 3600, "editor");
            assert!(r.is_err(), "editor NE pose PAS un playbook action_kind={kind}");
            assert_eq!(r.unwrap_err().0, StatusCode::FORBIDDEN, "403 attendu (armement réservé admin) pour {kind}");
            // admin : ACCEPTÉ.
            assert!(validate_detection_content("playbook", true, q, kind, 3600, "admin").is_ok(), "admin pose action_kind={kind}");
        }
        // action_kind_destructive : l'ENUM FERMÉ est intégralement destructif.
        for kind in ["ban_ip", "unban_ip", "kill_pid", "stop_service"] {
            assert!(action_kind_destructive(kind), "{kind} est destructif");
        }
        assert!(!action_kind_destructive("notify"), "une future action non-destructive resterait ouverte à l'editor");
        // NON-RÉGRESSION : l'editor garde le CRUD des RÈGLES GXQL (la garde ne touche QUE les playbooks armés).
        assert!(validate_detection_content("rule", true, "search severity>=3 | stats count", "", 3600, "editor").is_ok(), "editor garde les règles GXQL");
        assert!(validate_detection_content("parser", true, "^ok$", "", 0, "editor").is_ok(), "editor garde les parseurs");
        // #64 RÔLE COMPOSABLE : un base=admin SANS deny `arm_response` peut armer ; AVEC deny `arm_response`
        // il NE peut PAS (le deny subsiste sur la surface playbook, non couverte par route_denied_perm=/api/actions).
        {
            let mut m = custom_roles_cell().lock();
            m.insert("gov-armer".into(), RoleDef { base: "admin".into(), deny: vec![] });
            m.insert("gov-noarm".into(), RoleDef { base: "admin".into(), deny: vec!["arm_response".into()] });
            m.insert("gov-vw".into(), RoleDef { base: "viewer".into(), deny: vec![] });
        }
        assert!(validate_detection_content("playbook", true, q, "ban_ip", 3600, "gov-armer").is_ok(), "custom base=admin sans deny arm_response -> arme le playbook");
        let rn = validate_detection_content("playbook", true, q, "ban_ip", 3600, "gov-noarm");
        assert!(rn.is_err() && rn.unwrap_err().0 == StatusCode::FORBIDDEN, "custom base=admin AVEC deny arm_response -> armement REFUSÉ (deny soustractif)");
        assert!(validate_detection_content("playbook", true, q, "ban_ip", 3600, "gov-vw").is_err(), "custom base=viewer -> jamais d'armement (pas d'escalade)");
        let mut m = custom_roles_cell().lock();
        for k in ["gov-armer", "gov-noarm", "gov-vw"] { m.remove(k); }
    }

    // ============================================================================================
    // #39 TEAM CASE-OPS — invariants : SLA multi-niveau, merge/link, queues, MTTA/MTTR, CLIENT-READ.
    // ============================================================================================

    /// MODE 0 PARITÉ : sans politique SLA / fusion / lien, les colonnes v98 restent NULL/0, sla_apply_policy est
    /// un no-op, le tick multi-niveau EARLY-RETURN (0 travail), le SLA legacy (sla_due) est INCHANGÉ, la liste
    /// est identique. C'est la garantie « inutilisé -> byte-identique ».
    #[test]
    fn caseops_mode0_inert() {
        let conn = test_db();
        let id = case_create_row(&conn, "alice", "C", 3, "", None, 1);
        let (ack, res, pol): (Option<i64>, Option<i64>, Option<i64>) = conn
            .query_row("SELECT ack_due, resolve_due, sla_policy_id FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert!(ack.is_none() && res.is_none() && pol.is_none(), "mode 0 : dues multi-niveau NULL");
        let sla_due: Option<i64> = conn.query_row("SELECT sla_due FROM incident WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        assert_eq!(sla_due, Some(conn.query_row::<i64, _, _>("SELECT ts FROM incident WHERE id=?1", params![id], |r| r.get(0)).unwrap() + 3600), "SLA legacy sla_due P1 INCHANGÉ");
        let db = Arc::new(Mutex::new(conn));
        sla_multilevel_tick(&db); // 0 politique -> early-return
        let c = db.lock();
        let (ab, rb): (i64, i64) = c.query_row("SELECT ack_breached, resolve_breached FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((ab, rb), (0, 0), "mode 0 : aucun breach multi-niveau");
        assert_eq!(cases_list_json(&c, now(), "", "", 0, false, false)["cases"].as_array().unwrap().len(), 1, "liste inchangée");
    }

    /// SLA MULTI-NIVEAU : une politique pose ack_due/resolve_due depuis le `ts` IMMUABLE ; le tick marque les
    /// breach (ack + resolve) UNE SEULE FOIS, ancrés sur des timestamps immuables (un analyste ne peut pas
    /// reculer `ts` pour esquiver un breach : ack_due/resolve_due dérivent de `ts`, immuable).
    #[test]
    fn caseops_sla_multilevel_breach_immutable() {
        let conn = test_db();
        conn.execute("INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,600,1,0,'root',0)", []).unwrap();
        let id = case_create_row(&conn, "alice", "Crit", 4, "", None, 1);
        let ts: i64 = conn.query_row("SELECT ts FROM incident WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        let (ack, res, pol): (i64, i64, i64) = conn.query_row("SELECT ack_due, resolve_due, sla_policy_id FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!(ack, ts + 60, "ack_due = ts(immuable) + cible ack");
        assert_eq!(res, ts + 600, "resolve_due = ts(immuable) + cible resolve");
        assert!(pol > 0, "sla_policy_id renseigné");
        // simule l'écoulement du temps : échéances passées -> tick pose les breach.
        conn.execute("UPDATE incident SET ack_due=?1, resolve_due=?1 WHERE id=?2", params![now() - 10, id]).unwrap();
        let db = Arc::new(Mutex::new(conn));
        sla_multilevel_tick(&db);
        {
            let c = db.lock();
            let (ab, rb): (i64, i64) = c.query_row("SELECT ack_breached, resolve_breached FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            assert_eq!((ab, rb), (1, 1), "ack + resolve breach posés");
            assert_eq!(c.query_row::<i64, _, _>("SELECT COUNT(*) FROM ledger WHERE kind IN ('case.sla_ack_breach','case.sla_resolve_breach')", [], |r| r.get(0)).unwrap(), 2, "2 breach ledgerisés");
        }
        sla_multilevel_tick(&db); // idempotent
        let c = db.lock();
        assert_eq!(c.query_row::<i64, _, _>("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='sla'", params![id], |r| r.get(0)).unwrap(), 2, "pas de re-notification");
    }

    /// SLA PAUSE/REPRISE : 'waiting' met le chrono en PAUSE ; en sortir cumule la pause et DÉCALE les échéances
    /// de la durée écoulée (le temps « en attente » ne consomme pas le SLA). INERTE si pas de politique.
    #[test]
    fn caseops_sla_pause_resume() {
        let conn = test_db();
        conn.execute("INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P2',2,120,1200,1,0,'root',0)", []).unwrap();
        let id = case_create_row(&conn, "alice", "H", 3, "", None, 2);
        let res0: i64 = conn.query_row("SELECT resolve_due FROM incident WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        assert!(case_apply_update(&conn, id, "alice", &json!({ "status": "waiting" })));
        let paused: Option<i64> = conn.query_row("SELECT sla_paused_since FROM incident WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        assert!(paused.is_some(), "waiting -> chrono en pause");
        // simule 100 s de pause puis reprise.
        conn.execute("UPDATE incident SET sla_paused_since=sla_paused_since-100 WHERE id=?1", params![id]).unwrap();
        assert!(case_apply_update(&conn, id, "alice", &json!({ "status": "in_progress" })));
        let (res1, accum, paused2): (i64, i64, Option<i64>) = conn.query_row("SELECT resolve_due, sla_pause_accum, sla_paused_since FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert!(paused2.is_none(), "reprise -> paused_since effacé");
        assert!(accum >= 100, "pause cumulée >= 100 s (accum={accum})");
        assert!(res1 >= res0 + 100, "resolve_due décalé de la durée de pause (res0={res0} res1={res1})");
    }

    /// MERGE (soft) : LEDGERISÉ + NON DESTRUCTIF — la SOURCE est conservée (items intacts, merged_into posé,
    /// close) et RÉVERSIBLE (unmerge) ; la timeline de la source est COMBINÉE dans la cible ; la source disparaît
    /// de la liste active. Refus : re-fusion / self-merge.
    #[test]
    fn caseops_merge_ledgered_nondestructive() {
        let conn = test_db();
        let src = case_create_row(&conn, "alice", "Dup", 2, "", None, 3);
        let dst = case_create_row(&conn, "alice", "Main", 3, "", None, 2);
        case_add_item(&conn, src, now(), "note", "alice", "indice source", None);
        let items_before: i64 = conn.query_row("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1", params![src], |r| r.get(0)).unwrap();
        assert!(case_merge(&conn, src, dst, "bob"));
        let (mi, stt): (Option<i64>, String) = conn.query_row("SELECT merged_into, status FROM incident WHERE id=?1", params![src], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(mi, Some(dst));
        assert_eq!(stt, "closed");
        assert!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1", params![src], |r| r.get(0)).unwrap() >= items_before, "items source PRÉSERVÉS (append-only)");
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM ledger WHERE kind='case.merge'", [], |r| r.get(0)).unwrap(), 1, "fusion ledgerisée");
        let lst = cases_list_json(&conn, now(), "", "", 0, false, false);
        let ids: Vec<i64> = lst["cases"].as_array().unwrap().iter().map(|c| c["id"].as_i64().unwrap()).collect();
        assert!(!ids.contains(&src) && ids.contains(&dst), "source fusionnée masquée, cible visible");
        let d = case_get_json(&conn, dst, now()).unwrap();
        assert!(serde_json::to_string(&d["items"]).unwrap().contains("indice source"), "timeline cible COMBINE les items de la source");
        assert!(!case_merge(&conn, src, dst, "bob"), "source déjà fusionnée -> refus");
        assert!(!case_merge(&conn, dst, dst, "bob"), "self-merge -> refus");
        assert!(case_unmerge(&conn, src, "bob"));
        assert!(conn.query_row::<Option<i64>, _, _>("SELECT merged_into FROM incident WHERE id=?1", params![src], |r| r.get(0)).unwrap().is_none(), "unmerge -> réversible");
    }

    /// #39 CORRECTIVE (IMPORTANT) — un CYCLE de fusion de 3+ nœuds est REFUSÉ (pas seulement le 2-cycle direct).
    /// merge(A,B);merge(B,C) OK ; merge(C,A) fermerait le cycle A->B->C->A et poserait merged_into sur TOUS les
    /// cases -> aucun survivant listable. L'anti-cycle borné (remontée de chaîne depuis dst) refuse cette 3e
    /// fusion ; les cases restent cohérents et une racine survit dans la liste.
    #[test]
    fn merge_cycle_multi_node_rejected() {
        let conn = test_db();
        let a = case_create_row(&conn, "alice", "A", 3, "", None, 2);
        let b = case_create_row(&conn, "alice", "B", 3, "", None, 2);
        let c = case_create_row(&conn, "alice", "C", 3, "", None, 2);
        assert!(case_merge(&conn, a, b, "op"), "A->B OK");
        assert!(case_merge(&conn, b, c, "op"), "B->C OK");
        // 3e fusion C->A : src=C est EN AMONT de dst=A (chaîne A->B->C) -> refus (fermerait le cycle).
        assert!(!case_merge(&conn, c, a, "op"), "C->A fermerait un cycle 3-nœuds -> REFUSÉ");
        // la racine C survit (merged_into NULL) -> reste listable ; le graphe n'est pas totalement masqué.
        assert!(conn.query_row::<Option<i64>, _, _>("SELECT merged_into FROM incident WHERE id=?1", params![c], |r| r.get(0)).unwrap().is_none(), "C (racine) non fusionné -> survit");
        let lst = cases_list_json(&conn, now(), "", "", 0, false, false);
        let ids: Vec<i64> = lst["cases"].as_array().unwrap().iter().map(|x| x["id"].as_i64().unwrap()).collect();
        assert!(ids.contains(&c), "au moins la destination racine (C) reste visible");
        // contre-épreuve : le 2-cycle direct reste refusé lui aussi (merge(A,B) déjà fait ; merge(B,A) via chaîne).
        let d = case_create_row(&conn, "alice", "D", 3, "", None, 2);
        let e = case_create_row(&conn, "alice", "E", 3, "", None, 2);
        assert!(case_merge(&conn, d, e, "op"), "D->E OK");
        assert!(!case_merge(&conn, e, d, "op"), "E->D (2-cycle direct) -> REFUSÉ");
    }

    /// LINK (association) : lie deux cases (dédup UNIQUE), trace des DEUX côtés + ledger ; unlink retire le lien
    /// SANS toucher aux cases.
    #[test]
    fn caseops_link_nondestructive() {
        let conn = test_db();
        let a = case_create_row(&conn, "alice", "A", 2, "", None, 3);
        let b = case_create_row(&conn, "alice", "B", 2, "", None, 3);
        assert!(case_link_add(&conn, a, b, "related", "same actor", "bob"));
        assert!(case_link_add(&conn, a, b, "related", "", "bob"), "idempotent (dédup)");
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM case_link", [], |r| r.get(0)).unwrap(), 1, "dédup : un seul lien");
        assert_eq!(case_links_json(&conn, a).len(), 1);
        assert_eq!(case_links_json(&conn, b).len(), 1, "visible des deux côtés");
        assert_eq!(case_links_json(&conn, a)[0]["id"].as_i64().unwrap(), b);
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM ledger WHERE kind='case.link'", [], |r| r.get(0)).unwrap(), 1);
        assert!(case_link_remove(&conn, b, a, "bob"), "unlink des deux sens");
        assert_eq!(case_links_json(&conn, a).len(), 0);
        assert!(case_get_json(&conn, a, now()).is_some() && case_get_json(&conn, b, now()).is_some(), "cases intacts");
    }

    /// QUEUES + MTTA/MTTR : l'agrégat par assignee compte les cases ouverts ; les métriques calculent MTTA
    /// (first_response_ts - ts) et MTTR (closed_ts - ts - pause) sur la fenêtre.
    #[test]
    fn caseops_queues_and_metrics() {
        let conn = test_db();
        let base = now();
        let c1 = case_create_row(&conn, "alice", "Q1", 3, "", Some("alice"), 2);
        let _c2 = case_create_row(&conn, "alice", "Q2", 3, "", Some("bob"), 3);
        conn.execute("UPDATE incident SET ts=?1, first_response_ts=?2, closed_ts=?3, status='resolved' WHERE id=?4", params![base - 1000, base - 950, base - 800, c1]).unwrap();
        let q = case_queues_json(&conn, now());
        let queues = q["queues"].as_array().unwrap();
        let bob = queues.iter().find(|x| x["assignee"] == "bob").expect("bob dans les queues");
        assert_eq!(bob["open"], 1, "bob a 1 case ouvert");
        assert!(queues.iter().find(|x| x["assignee"] == "alice").is_none(), "alice : 0 ouvert (c1 résolu)");
        let m = case_metrics_json(&conn, base - 2000, base);
        assert_eq!(m["overall"]["resolved"], 1);
        assert_eq!(m["overall"]["mtta_mean"], 50, "MTTA = 950-1000... = 50 s");
        assert_eq!(m["overall"]["mttr_mean"], 200, "MTTR = 800-1000... = 200 s");
    }

    /// CLIENT-READ (SÉCU) — RBAC read-only STRICT : le rôle `client` satisfait la
    /// LECTURE, JAMAIS write/admin/ingest/agent ; rank 0 (masquage maximal) ; le seam est DISJOINT des routes
    /// mutantes / query / ingest.
    #[test]
    fn client_read_rbac_readonly_and_seam() {
        assert!(role_satisfies("client", MinRole::Read), "client lit");
        assert!(!role_satisfies("client", MinRole::Write), "client N'ÉCRIT PAS");
        assert!(!role_satisfies("client", MinRole::Admin));
        assert!(!role_satisfies("client", MinRole::Ingest), "client N'INGÈRE PAS");
        assert!(!role_satisfies("client", MinRole::Agent));
        assert_eq!(role_rank("client"), 0, "client rank 0 -> masqué par TOUTE règle (fail-closed)");
        assert!(rbac_gate("client", "/api/client/cases", false).is_ok());
        assert!(rbac_gate("client", "/api/client/cases/5", false).is_ok());
        assert!(rbac_gate("client", "/api/cases", true).is_err(), "client NE mute PAS un case");
        assert!(rbac_gate("client", "/api/cases/5/merge", true).is_err(), "client NE fusionne PAS");
        assert!(rbac_gate("client", "/api/query", true).is_err());
        assert!(rbac_gate("client", "/api/ingest", false).is_err(), "client NE lit PAS l'ingest");
        assert!(client_bearer_path("/api/client/cases") && client_bearer_path("/api/client/cases/42"));
        assert!(!client_bearer_path("/api/ingest") && !client_bearer_path("/api/query") && !client_bearer_path("/api/cases") && !client_bearer_path("/api/ds/query"));
    }

    /// #39 CORRECTIVE (CRITICAL, couche b/2) — INVARIANT d'autorisation AUTH-INDÉPENDANT : le rôle `client` est
    /// CONFINÉ aux routes client-read PEU IMPORTE l'origine de l'identité. Sur TOUTE autre route — MÊME en
    /// LECTURE — rbac_gate renvoie 403, JAMAIS un 200 masqué-vide (c'était le trou : Read opt-in au masque
    /// -> données tenant renvoyées à un client sur /api/query, /api/cases, /api/alerts…). Décision testée au
    /// choke-point (indépendante de la méthode d'auth).
    #[test]
    fn client_role_confined_to_client_routes() {
        // AUTORISÉ : les 2 routes client-read en lecture (seam légitime du jeton mode-0).
        assert!(rbac_gate("client", "/api/client/cases", false).is_ok(), "client-read cases -> Ok");
        assert!(rbac_gate("client", "/api/client/cases/42", false).is_ok(), "client-read case:id -> Ok");
        // REFUSÉ : toute LECTURE hors du seam (le trou CRITICAL fermé).
        for p in ["/api/query", "/api/cases", "/api/cases/5", "/api/alerts", "/api/overview", "/api/ds/query", "/api/v1/query", "/api/sources", "/api/me"] {
            assert!(rbac_gate("client", p, false).is_err(), "client CONFINÉ : lecture {p} -> 403 (pas un 200 masqué-vide)");
        }
        // REFUSÉ : toute MUTATION / ingest hors du seam.
        for p in ["/api/cases", "/api/cases/5/merge", "/api/ingest", "/api/rules", "/api/query"] {
            assert!(rbac_gate("client", p, true).is_err(), "client CONFINÉ : mutation {p} -> 403");
        }
        // READ-ONLY STRICT préservé : une MUTATION même sur une route client-read retombe en DEFAULT-DENY.
        assert!(rbac_gate("client", "/api/client/cases", true).is_err(), "client-read reste read-only strict (mutation -> 403)");
    }

    /// #39 CORRECTIVE (CRITICAL, couche a/2) — `client` est un rôle RÉSERVÉ : impossible de le (re)définir via
    /// role_create ni de l'octroyer via grant_set / valid_grant_role. Ferme la collision de nom #59 (un rôle
    /// custom `client` base viewer/editor aurait contourné le confinement en passant par le pipeline SSO/Basic
    /// NORMAL comme son base_role).
    #[tokio::test]
    async fn client_role_cannot_be_created_or_granted() {
        let _rg = CUSTOM_ROLES_TEST_LOCK.lock();
        assert!(is_builtin_role("client"), "client RÉSERVÉ (rôle intégré)");
        assert!(!valid_grant_role("client"), "client NON-octroyable (valid_grant_role)");
        assert!(custom_role_lookup("client").is_none(), "client jamais résolu comme rôle custom");
        // (a) role_create REFUSE le nom réservé.
        let (cp, _cptmp) = mk_test_control();
        let st = tenant_test_state("admins", "editors", "supers", Some(cp.clone()));
        let sa = || { let mut a = tok_au("admin"); a.is_superadmin = true; a };
        let (c1, _) = tok_resp_json(role_create(State(st.clone()), Extension(sa()), Json(json!({ "name": "client", "base_role": "viewer" }))).await).await;
        assert_eq!(c1, StatusCode::BAD_REQUEST, "role_create refuse le nom réservé 'client'");
        let n: i64 = cp.conn.lock().query_row("SELECT COUNT(*) FROM role_def WHERE name='client'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "aucun rôle 'client' persisté");
        // (b) grant_set REFUSE le rôle 'client' (mode 1).
        let (st2, dir) = mk_mode1_state();
        assert_eq!(tenant_create(State(st2.clone()), Extension(au_super("op")), Json(json!({ "id": "acme", "name": "A", "admin": "alice" }))).await.status(), StatusCode::CREATED);
        let r = grant_set(State(st2.clone()), Extension(au_super("op")), Path("acme".into()), Json(json!({ "user": "carol", "role": "client" }))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "grant_set refuse le rôle 'client'");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CLIENT-READ — jeton `kind='client'` : s'authentifie UNIQUEMENT sur le seam client-read (kind-confusion
    /// fermée : NE vaut PAS agent/HEC/datasource) et NE forge AUCUNE identité sur /api/query, /api/cases,
    /// /api/ingest, /api/ds/query, /services/collector -> pas de SQL/mutation/ingest. Tenant='default', rôle='client'.
    #[tokio::test]
    async fn client_read_token_seam_and_kind_confusion() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let (code, v) = tok_resp_json(token_create(State(st.clone()), Extension(tok_au("admin")), Json(json!({ "name": "acme", "kind": "client" }))).await).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["kind"], "client");
        assert!(v["host"].is_null(), "jeton client JAMAIS host-lié");
        let tok = v["token"].as_str().unwrap().to_string();
        let ci = client_token_lookup(&st, &tok).expect("jeton client résolu");
        assert_eq!(ci.role, "client");
        assert_eq!(ci.tenant, "default");
        assert!(token_lookup(&st, &tok).is_none(), "jeton client != agent/HEC (kind-confusion fermée)");
        assert!(datasource_token_lookup(&st, &tok).is_none(), "jeton client != datasource");
        let mk = |uri: &str| Request::builder().uri(uri).header("authorization", format!("Bearer {tok}")).body(axum::body::Body::empty()).unwrap();
        let (id_client, m, _, _, _) = resolve_identity(&st, &mk("/api/client/cases"));
        assert_eq!(id_client, Some(("acme".to_string(), "client".to_string())));
        assert_eq!(m, "client");
        for uri in ["/api/query", "/api/cases", "/api/ingest", "/api/ds/query", "/services/collector"] {
            let (id_other, _, _, _, _) = resolve_identity(&st, &mk(uri));
            assert!(id_other.is_none(), "jeton client NE forge AUCUNE identité sur {uri}");
        }
    }

    /// CLIENT-READ — PROJECTION MASQUÉE & FERMÉE : (1) un field-filter sur `title` masque le titre pour le client
    /// (rank 0) ; (2) la projection N'EXPOSE PAS owner/assignee/résumé interne ni les refs alert/event ; (3) la
    /// timeline client se limite au cycle de vie (auteurs anonymisés « SOC ») ; (4) archivés & fusionnés EXCLUS.
    #[test]
    fn client_read_projection_masked_and_closed() {
        let path = ff_tmp_path("clientread");
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('t','title','mask','')", []).unwrap();
        field_filters_reload(&conn, &path);
        let masks = effective_masks(&path, "client", "default", None);
        assert!(!masks.is_empty(), "le client hérite du masque (rank 0)");
        let id = case_create_row(&conn, "analyst_alice", "Secret Title", 3, "resume interne confidentiel", Some("analyst_bob"), 2);
        case_add_item(&conn, id, now(), "note", "analyst_bob", "note interne sensible", None);
        case_add_item(&conn, id, now(), "alert", "analyst_bob", "", Some("alert:99"));
        let v = client_cases_list_json(&conn, &path, &masks, now(), "", 100, 0);
        let blob = serde_json::to_string(&v).unwrap();
        assert!(!blob.contains("Secret Title"), "titre client MASQUÉ : {blob}");
        assert!(blob.contains("***"), "titre remplacé par le masque");
        assert!(!blob.contains("analyst_alice") && !blob.contains("analyst_bob"), "aucune identité analyste exposée");
        assert!(!blob.contains("resume interne"), "résumé interne NON exposé");
        assert!(!blob.contains("alert:99"), "refs alert/event NON exposées");
        let d = client_case_get_json(&conn, &path, &masks, id, now()).unwrap();
        let db = serde_json::to_string(&d).unwrap();
        assert!(!db.contains("note interne sensible"), "note interne EXCLUE de la vue client");
        assert!(!db.contains("analyst_bob"), "auteur anonymisé");
        assert!(db.contains("SOC"), "auteurs client-facing = SOC");
        let arch = case_create_row(&conn, "x", "ArchMe", 2, "", None, 3);
        case_set_archived(&conn, arch, "root", true);
        let merged = case_create_row(&conn, "x", "MergeMe", 2, "", None, 3);
        case_merge(&conn, merged, id, "root");
        let v2 = client_cases_list_json(&conn, &path, &masks, now(), "", 100, 0);
        let ids: Vec<i64> = v2["cases"].as_array().unwrap().iter().map(|c| c["id"].as_i64().unwrap()).collect();
        assert!(!ids.contains(&arch) && !ids.contains(&merged), "archivés & fusionnés EXCLUS de la vue client");
        assert!(client_case_get_json(&conn, &path, &masks, arch, now()).is_none(), "détail client refuse un archivé");
        assert!(client_case_get_json(&conn, &path, &masks, merged, now()).is_none(), "détail client refuse un fusionné");
        let _ = std::fs::remove_file(&path);
    }

    /// HANDLER bout-en-bout : le handler ds_query_get LIT au.role (viewer) et renvoie des RECORDS masqués ;
    /// prom_query renvoie la forme vector avec host caviardé. Preuve du câblage complet (pas juste la primitive).
    #[tokio::test]
    async fn ds_handlers_end_to_end_mask() {
        let path = ds_seed_db("handler");
        let st = ds_file_state(&path);
        let viewer = AuthUser { name: "grafana".into(), role: "viewer".into(), tenant: "default".into(), is_superadmin: false, method: "datasource".into(), csrf: String::new(), env: None };
        // GXQL-HTTP (records) : src_user/message masqués.
        let mut q = HashMap::new();
        q.insert("soql".to_string(), "search | table src_user, message".to_string());
        q.insert("format".to_string(), "records".to_string());
        let (code, v) = tok_resp_json(ds_query_get(State(st.clone()), Extension(viewer.clone()), Query(q)).await).await;
        assert_eq!(code, StatusCode::OK);
        let arr = v.as_array().expect("records = tableau d'objets");
        assert_eq!(arr.len(), 2);
        let blob = serde_json::to_string(&v).unwrap();
        assert!(!blob.contains("alice") && !blob.contains("bob"), "handler : src_user masqué pour viewer : {blob}");
        assert!(blob.contains("***"), "handler : message masqué");
        // Prometheus instant : vector, host caviardé.
        let mut pq = HashMap::new();
        pq.insert("query".to_string(), "node_load1".to_string());
        let (pc, pv) = tok_resp_json(prom_query(State(st.clone()), Extension(viewer), Query(pq)).await).await;
        assert_eq!(pc, StatusCode::OK);
        assert_eq!(pv["status"], "success");
        assert_eq!(pv["data"]["resultType"], "vector");
        let res = pv["data"]["result"].as_array().unwrap();
        assert!(!res.is_empty(), "au moins une série");
        for s in res {
            assert_eq!(s["metric"]["host"].as_str(), Some("***"), "viewer : host masqué dans la sortie Prometheus");
            assert!(s["value"].as_array().map(|a| a.len() == 2).unwrap_or(false), "échantillon [ts, \"val\"]");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn field_filter_json_bag_no_leak() {
        // Le SAC JSON brut (`fields`) ne doit JAMAIS exposer une clé masquée, ni via `search` NU, ni via
        // `| table fields`, ni via `| head` (qui ne re-projette pas). Sinon un viewer contournerait le masque.
        let path = ff_tmp_path("bag");
        {
            let conn = open_db(&path).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&conn);
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,'sshd','auth',3,'h1','m',?2)",
                params![now(), r#"{"src_user":"alice","other":"ok"}"#],
            ).unwrap();
            conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('u','src_user','mask','')", []).unwrap();
            field_filters_reload(&conn, &path);
        }
        let vm = effective_masks(&path, "viewer", "default", None);
        for q in ["search | table fields", "search", "search | head 5"] {
            let sql = soql_to_sql_masked_x(q, 0, 0, None, &vm).unwrap();
            let r = run_query_ex(&path, &sql, 5000, None).unwrap();
            let blob = serde_json::to_string(&r["rows"]).unwrap();
            assert!(!blob.contains("alice"), "clé masquée src_user NE DOIT PAS fuiter via '{q}' : {blob}");
            assert!(blob.contains("other"), "les clés NON masquées restent visibles via '{q}' : {blob}");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn field_filter_search_guard_rejects_oracle() {
        // FIX 2 (#45) — /api/search : refus fail-closed de tout filtre/plein-texte sondant un champ masqué.
        use guatx_core::soql::{FieldMaskSet, MaskAction};
        let mut m = FieldMaskSet::new();
        m.insert("pan", MaskAction::Deny);      // clé JSON
        m.insert("src_user", MaskAction::Hash); // clé JSON
        m.insert("src_ip", MaskAction::Mask);   // colonne réelle whitelistée
        m.insert("message", MaskAction::Mask);  // colonne réelle
        // Filtre STRUCTURÉ sur une colonne masquée whitelistée -> Err(col).
        assert_eq!(search_mask_guard("src_ip=~\"^10\"", &m, false).unwrap_err(), "src_ip");
        assert_eq!(search_mask_guard("message:secret", &m, false).unwrap_err(), "message");
        assert_eq!(search_mask_guard("regex=4111", &m, false).unwrap_err(), "message");
        // Blob `fields` -> probe des clés JSON masquées -> Err("fields").
        assert_eq!(search_mask_guard("fields:~\"pan\"", &m, false).unwrap_err(), "fields");
        // Terme libre avec message masqué -> Err("plein-texte").
        assert_eq!(search_mask_guard("hello world", &m, false).unwrap_err(), "plein-texte");
        // Colonne NON masquée + tokens de contrôle -> autorisé.
        assert!(search_mask_guard("host=web01", &m, false).is_ok());
        assert!(search_mask_guard("host=web01 limit:10", &m, false).is_ok());
        // ADMIN (masques VIDES) -> tout autorisé (mode 0, jamais restrictif).
        let empty = FieldMaskSet::new();
        assert!(search_mask_guard("src_ip=~\"^10\" fields:~pan hello", &empty, true).is_ok());
        // Seule une clé JSON masquée, message NON masqué :
        let mut j = FieldMaskSet::new(); j.insert("src_user", MaskAction::Hash);
        assert!(search_mask_guard("hello", &j, false).is_ok(), "free-text OK : message non masqué, FTS_FIELDS off");
        assert_eq!(search_mask_guard("hello", &j, true).unwrap_err(), "plein-texte", "FTS_FIELDS on -> FTS probe le JSON -> refus");
        assert_eq!(search_mask_guard("fields:~x", &j, false).unwrap_err(), "fields", "blob fields refusé (clé JSON masquée)");
        // ?q=src_user=alice (src_user non whitelisté -> free-text) : oracle SEULEMENT si FTS étend au JSON.
        assert_eq!(search_mask_guard("src_user=alice", &j, true).unwrap_err(), "plein-texte", "oracle FTS_FIELDS sur src_user refusé");
    }

    #[test]
    fn field_filter_deny_overlay_beats_weaker_specific_rule() {
        // FIX 4 (#45) — DENY est une classe DURE : une règle plus faible mais plus spécifique (role=admin Mask,
        // seuil 3 -> masque aussi viewer/editor) NE DOIT PAS rétrograder un DENY role='' en Mask.
        let path = ff_tmp_path("deny_overlay");
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('d','pan','deny','')", []).unwrap();
        conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('m','pan','mask','admin')", []).unwrap();
        field_filters_reload(&conn, &path);
        for role in ["viewer", "editor", "admin"] {
            let eff = effective_masks(&path, role, "default", None);
            assert_eq!(
                eff.get("pan"), Some(guatx_core::soql::MaskAction::Deny),
                "pan reste DENY pour {role} (overlay dur, jamais rétrogradé en Mask)"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn field_filter_mode0_read_byte_identical() {
        // Sans AUCUNE règle : le chemin masqué == chemin non masqué (SQL ET résultat).
        let path = ff_tmp_path("mode0");
        {
            let conn = open_db(&path).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&conn);
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,'sshd','auth',3,'h1','msg',?2)",
                params![now(), r#"{"src_user":"alice"}"#],
            ).unwrap();
            field_filters_reload(&conn, &path);
        }
        let empty = effective_masks(&path, "viewer", "default", None);
        assert!(empty.is_empty(), "aucune règle -> jeu VIDE (court-circuit mode 0)");
        let q = "search | table src_user, message";
        let plain = soql_to_sql_x(q, 0, 0, None).unwrap();
        let masked = soql_to_sql_masked_x(q, 0, 0, None, &empty).unwrap();
        assert_eq!(plain, masked, "SQL byte-identique en mode 0");
        // et le résultat expose la valeur en clair (pas de masquage fantôme).
        let r = run_query_ex(&path, &masked, 5000, None).unwrap();
        assert_eq!(r["rows"][0][0].as_str().unwrap(), "alice", "src_user en clair (mode 0)");
        let _ = std::fs::remove_file(&path);
    }

