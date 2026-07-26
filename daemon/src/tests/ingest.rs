    // ============================================================================================
    // #49 — INDEXES LOGIQUES NOMMÉS + RÉTENTION PAR INDEX. L'index = env_id (aligné sur l'action ROUTE #40).
    // Data-safety : per-index prune SEULEMENT son index à SA fenêtre ; no-policy -> global ; mode 0 identique ;
    // policy mal réglée = fail-safe (jamais de sur-purge) ; plafonds row/size ; migration v91.
    // ============================================================================================

    fn cnt_env(c: &Connection, env: &str) -> i64 {
        c.query_row("SELECT COUNT(*) FROM event WHERE env_id=?1", params![env], |r| r.get(0)).unwrap()
    }

    /// A — la purge PER-INDEX ne purge QUE son index à SA fenêtre : un index à rétention PLUS LONGUE que le
    /// global garde ses events (au-delà du global) ; ses events au-delà de SA fenêtre sont purgés ; un autre
    /// index sans policy tombe sur le global.
    #[test]
    fn idx49_per_index_retention_prunes_only_its_index() {
        let conn = test_db();
        conn.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','30')", []).unwrap();
        conn.execute("INSERT INTO index_policy(name,retention_days) VALUES('auth',400)", []).unwrap();
        let n = now();
        ins_ev(&conn, n - 100 * 86400, "auth", "auth vieux mais < 400j");   // SURVIT (policy auth=400)
        ins_ev(&conn, n - 500 * 86400, "auth", "auth au-dela de 400j");     // PURGÉ (> policy)
        ins_ev(&conn, n - 1 * 86400,   "auth", "auth recent");              // SURVIT
        ins_ev(&conn, n - 100 * 86400, "prod", "prod vieux");               // PURGÉ (global 30, pas de policy)
        ins_ev(&conn, n - 1 * 86400,   "prod", "prod recent");              // SURVIT
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        let c = db.lock();
        assert_eq!(cnt_env(&c, "auth"), 2, "auth: garde <400j (vieux+recent), purge >400j");
        assert_eq!(cnt_env(&c, "prod"), 1, "prod (sans policy) purgé au global 30j -> seul le récent reste");
    }

    /// B — un index SANS policy tombe sur la rétention GLOBALE, même quand d'AUTRES index ont une policy.
    #[test]
    fn idx49_no_policy_index_falls_back_to_global() {
        let conn = test_db();
        conn.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','30')", []).unwrap();
        conn.execute("INSERT INTO index_policy(name,retention_days) VALUES('auth',400)", []).unwrap(); // policy sur un AUTRE index
        let n = now();
        ins_ev(&conn, n - 100 * 86400, "web", "web vieux");   // PURGÉ (global 30 ; 'web' n'a pas de policy)
        ins_ev(&conn, n - 1 * 86400,   "web", "web recent");  // SURVIT
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        let c = db.lock();
        assert_eq!(cnt_env(&c, "web"), 1, "web sans policy -> global 30j (la policy 'auth' ne le protège pas)");
    }

    /// C — MODE 0 : AUCUNE policy -> rétention globale appliquée à TOUS les env EXACTEMENT comme avant #49
    /// (chemin byte-identique) ; les events de contrôle daemon survivent toujours (garde inchangée).
    #[test]
    fn idx49_mode0_no_policy_global_retention_identical() {
        let conn = test_db();
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM index_policy", [], |r| r.get::<_,i64>(0)).unwrap(), 0, "aucune policy = mode 0");
        conn.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','30')", []).unwrap();
        let n = now();
        let old = n - 100 * 86400;
        ins_ev(&conn, old, "prod", "prod vieux");
        ins_ev(&conn, old, "siteA", "env custom vieux");           // tombe sur le global
        ins_ev(&conn, n - 1 * 86400, "prod", "prod recent");
        conn.execute("INSERT INTO event(ts,source,message,origin,env_id) VALUES(?1,'plume-config','audit','daemon','prod')", params![old]).unwrap();
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        let c = db.lock();
        assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE message='prod vieux'", [], |r| r.get::<_,i64>(0)).unwrap(), 0, "prod vieux purgé (global)");
        assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE message='env custom vieux'", [], |r| r.get::<_,i64>(0)).unwrap(), 0, "env custom sans policy purgé (global, comme avant)");
        assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE message='prod recent'", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "récent conservé");
        assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE source='plume-config' AND origin='daemon'", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "audit daemon NON purgeable (garde inchangée)");
    }

    /// D — une policy MAL RÉGLÉE échoue en SÉCURITÉ (jamais de SUR-purge) : (1) nom invalide -> policy IGNORÉE
    /// (l'env tombe sur le global, jamais purgé à la fenêtre agressive) ; (2) rétention sous le plancher ->
    /// planchée à 7 j (un event < 7 j SURVIT malgré une policy à 1 j).
    #[test]
    fn idx49_bad_policy_fails_safe_no_over_delete() {
        let conn = test_db();
        conn.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','30')", []).unwrap();
        // (1) nom INVALIDE (espace + '!') avec une rétention agressive 1 j -> load_index_policies l'ÉCARTE.
        conn.execute("INSERT INTO index_policy(name,retention_days) VALUES('bad name!',1)", []).unwrap();
        // (2) nom valide 'auth' mais rétention SOUS le plancher (1 j) -> clampée à 7 j à l'application.
        conn.execute("INSERT INTO index_policy(name,retention_days) VALUES('auth',1)", []).unwrap();
        // load_index_policies : la policy invalide est écartée, l'autre planchée à 7.
        {
            let pols = load_index_policies(&conn);
            assert_eq!(pols.len(), 1, "policy au nom invalide ÉCARTÉE (fail-safe)");
            assert_eq!(pols[0].name, "auth");
            assert_eq!(pols[0].retention_days, 7, "rétention 1j planchée à 7j (anti-sur-purge)");
        }
        let n = now();
        ins_ev(&conn, n - 10 * 86400, "prod", "prod 10j");   // SURVIT (global 30 ; la policy invalide 1j est ignorée)
        ins_ev(&conn, n - 5 * 86400,  "auth", "auth 5j");    // SURVIT (planché 7j > 5j, PAS purgé à 1j)
        ins_ev(&conn, n - 10 * 86400, "auth", "auth 10j");   // PURGÉ (> 7j)
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        let c = db.lock();
        assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE message='prod 10j'", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "nom invalide ignoré -> prod suit le global 30j (pas de sur-purge à 1j)");
        assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE message='auth 5j'", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "planché 7j -> l'event de 5j SURVIT");
        assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE message='auth 10j'", [], |r| r.get::<_,i64>(0)).unwrap(), 0, "event de 10j purgé (> plancher 7j)");
    }

    /// E — PLAFONDS de dimensionnement : max_rows garde les N events les plus RÉCENTS ; max_bytes garde la
    /// fenêtre récente sous le budget estimé. Tous les events sont récents (global inactif) -> seul le plafond agit.
    #[test]
    fn idx49_row_and_size_caps() {
        let conn = test_db();
        conn.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','30')", []).unwrap();
        conn.execute("INSERT INTO index_policy(name,max_rows) VALUES('cap',3)", []).unwrap();
        // max_bytes : message de 100 o + fields '{}' (2) + 64 overhead = 166 o/ligne ; budget 350 -> 2 lignes.
        conn.execute("INSERT INTO index_policy(name,max_bytes) VALUES('sz',350)", []).unwrap();
        let n = now();
        for i in 0..6 { ins_ev(&conn, n - i, "cap", &format!("cap {i}")); } // 6 récents, cap=3
        let big = "x".repeat(100);
        for i in 0..5 {
            conn.execute("INSERT INTO event(ts,source,message,fields,env_id,origin) VALUES(?1,'agent',?2,'{}',?3,'')",
                params![n - i, big, "sz"]).unwrap();
        }
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        let c = db.lock();
        assert_eq!(cnt_env(&c, "cap"), 3, "max_rows=3 -> 3 events les plus récents conservés");
        assert_eq!(cnt_env(&c, "sz"), 2, "max_bytes=350 (~166 o/ligne) -> 2 events récents conservés");
        // le plus ANCIEN 'cap' (cap 5, ts=n-5) doit avoir disparu ; le plus récent (cap 0, ts=n) reste.
        assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE message='cap 0'", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "le plus récent conservé");
        assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE message='cap 5'", [], |r| r.get::<_,i64>(0)).unwrap(), 0, "le plus ancien purgé par le cap");
    }

    // FIX #18 (size-caps #49 bypass sous COLD, NO-LOSS) — sous cold ON, l'aging a déjà columnarisé+supprimé les
    // vieux jours ; les lignes restées HOT sont les RÉCENTES NON archivées. Un plafond count/byte qui ne garde
    // que les N plus récentes supprimerait EXACTEMENT ces lignes SANS copie cold -> PERTE. La correction SKIP les
    // plafonds quand PLUME_COLD_TIER=1. Ces tests sont gatés `cold_tier` (jamais dans la suite par défaut = 749)
    // et sérialisés (COLD_CAPS_ENV_LOCK) car ils mutent l'env process-global PLUME_COLD_TIER/PLUME_COLD_DIR.

    /// Prépare un env cold : PLUME_COLD_TIER=1 + PLUME_COLD_DIR=<temp> (aucune clé -> aging fail-closed, ne
    /// touche RIEN ; de toute façon les events de test sont RÉCENTS, hors fenêtre d'aging). Renvoie le temp dir.
    #[cfg(feature = "cold_tier")]
    fn cold_env_on() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("plume-caps-cold-{}-{}", std::process::id(), now()));
        std::fs::create_dir_all(&d).unwrap();
        std::env::set_var("PLUME_COLD_TIER", "1");
        std::env::set_var("PLUME_COLD_DIR", d.to_string_lossy().to_string());
        d
    }
    #[cfg(feature = "cold_tier")]
    fn cold_env_off() {
        std::env::remove_var("PLUME_COLD_TIER");
        std::env::remove_var("PLUME_COLD_DIR");
    }

    /// FIX #18 (a) — CONTRÔLE cold OFF : les plafonds trient toujours les plus VIEILLES (comportement inchangé).
    #[cfg(feature = "cold_tier")]
    #[test]
    fn fix18_caps_still_trim_when_cold_off() {
        let _g = COLD_CAPS_ENV_LOCK.lock();
        cold_env_off(); // garantit PLUME_COLD_TIER absent -> caps_active=true
        let conn = test_db();
        conn.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','30')", []).unwrap();
        conn.execute("INSERT INTO index_policy(name,max_rows) VALUES('cap',3)", []).unwrap();
        let n = now();
        for i in 0..6 { ins_ev(&conn, n - i, "cap", &format!("cap {i}")); }
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        let c = db.lock();
        assert_eq!(cnt_env(&c, "cap"), 3, "cold off -> max_rows=3 trime les plus vieux (inchangé)");
        assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE message='cap 5'", [], |r| r.get::<_,i64>(0)).unwrap(), 0, "le plus ancien purgé");
    }

    /// FIX #18 (b) — NO-LOSS (preuve centrale) : cold ON, max_rows < nb de lignes HOT récentes (aucune copie
    /// cold) -> TOUTES survivent (zéro capée). Sans le fix, 3 lignes non-archivées seraient perdues.
    #[cfg(feature = "cold_tier")]
    #[test]
    fn fix18_cold_on_max_rows_no_loss_all_survive() {
        let _g = COLD_CAPS_ENV_LOCK.lock();
        let dir = cold_env_on();
        let conn = test_db();
        conn.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','30')", []).unwrap();
        conn.execute("INSERT INTO index_policy(name,max_rows) VALUES('cap',3)", []).unwrap();
        let n = now();
        for i in 0..6 { ins_ev(&conn, n - i, "cap", &format!("cap {i}")); } // 6 récents (>= hot_cutoff), aucun seal cold
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        {
            let c = db.lock();
            assert_eq!(cnt_env(&c, "cap"), 6, "cold ON -> plafond count SKIP -> aucune ligne non-archivée perdue (NO-LOSS)");
            assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE message='cap 5'", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "la plus ANCIENNE (sans copie cold) survit");
        }
        cold_env_off();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// FIX #18 (c) — cold ON + max_bytes serré -> zéro suppression (le plafond taille est aussi skippé).
    #[cfg(feature = "cold_tier")]
    #[test]
    fn fix18_cold_on_max_bytes_zero_deletion() {
        let _g = COLD_CAPS_ENV_LOCK.lock();
        let dir = cold_env_on();
        let conn = test_db();
        conn.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','30')", []).unwrap();
        conn.execute("INSERT INTO index_policy(name,max_bytes) VALUES('sz',350)", []).unwrap(); // ~166 o/ligne -> 2 sous cold OFF
        let n = now();
        let big = "x".repeat(100);
        for i in 0..5 {
            conn.execute("INSERT INTO event(ts,source,message,fields,env_id,origin) VALUES(?1,'agent',?2,'{}',?3,'')",
                params![n - i, big, "sz"]).unwrap();
        }
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        {
            let c = db.lock();
            assert_eq!(cnt_env(&c, "sz"), 5, "cold ON -> plafond taille SKIP -> zéro suppression");
        }
        cold_env_off();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// FIX #18 (d) — CONTRÔLE : sous cold ON, les events NON-PURGEABLES (origin=daemon/source=plume-config) sont
    /// intacts (ils l'étaient déjà via RETENTION_NONPURGE ; le skip des plafonds ne change rien) ET les events
    /// ordinaires récents aussi (plafond skippé). Aucune régression des invariants NONPURGE.
    #[cfg(feature = "cold_tier")]
    #[test]
    fn fix18_cold_on_nonpurge_control_events_unaffected() {
        let _g = COLD_CAPS_ENV_LOCK.lock();
        let dir = cold_env_on();
        let conn = test_db();
        conn.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','30')", []).unwrap();
        conn.execute("INSERT INTO index_policy(name,max_rows) VALUES('cap',1)", []).unwrap(); // plafond très serré
        let n = now();
        // 1 event de CONTRÔLE (non-purgeable) + 3 events ordinaires, tous dans l'index 'cap'.
        conn.execute("INSERT INTO event(ts,source,category,severity,message,origin,env_id) VALUES(?1,'plume-config','health',4,'ctrl','daemon','cap')", params![n]).unwrap();
        for i in 0..3 { ins_ev(&conn, n - i - 1, "cap", &format!("ord {i}")); }
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        {
            let c = db.lock();
            assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE message='ctrl'", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "event de contrôle NON-PURGEABLE intact");
            assert_eq!(cnt_env(&c, "cap"), 4, "cold ON -> plafond skippé -> les 4 (contrôle + 3 ordinaires) survivent");
        }
        cold_env_off();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F — MIGRATION v91 : la table index_policy existe (colonnes attendues) et schema_version >= 91.
    #[test]
    fn idx49_migration_v91_index_policy_table() {
        let conn = test_db();
        let ver: i64 = conn.query_row("SELECT CAST(value AS INTEGER) FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert!(ver >= 91, "schema_version >= 91 après migrate (v={ver})");
        // insert nominal (prouve les colonnes) + UNIQUE(name).
        conn.execute("INSERT INTO index_policy(name,retention_days,max_rows,max_bytes,description) VALUES('auth',400,0,0,'auth logs')", []).unwrap();
        assert!(conn.execute("INSERT INTO index_policy(name) VALUES('auth')", []).is_err(), "UNIQUE(name) rejette le doublon");
        let rd: i64 = conn.query_row("SELECT retention_days FROM index_policy WHERE name='auth'", [], |r| r.get(0)).unwrap();
        assert_eq!(rd, 400);
    }

    /// M2 — DENYLIST d'IP protégées : un ban est REFUSÉ sur loopback/RFC1918/opérateur ; ACCEPTÉ sur une IP
    /// publique (attaquant). L'unban n'est jamais bridé. Les autres actions sont inchangées.
    #[test]
    fn v2_m2_ban_denylist_protects_infra_ips() {
        // public (attaquant) -> ban autorisé. db_path="default" : aucun engagement scope pour ce tenant.
        assert!(action_valid("ban_ip", "203.0.113.7", "default").is_ok(), "ban d'une IP publique OK");
        assert!(action_valid("ban_ip", "192.0.2.18", "default").is_ok());
        // protégées (loopback / RFC1918 / link-local — codé EN DUR) -> ban REFUSÉ. NB : la protection
        // OPÉRATEUR/self n'est plus bakée (défaut PLUME_OPERATOR_IPS vide = build générique) ; une IP
        // opérateur CONFIGURÉE reste protégée via protected_ip_matchers -> parse_excl_item (couvert par
        // excl_v54_parse_and_clause_generation), sans donnée perso en dur dans le test.
        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.9", "172.31.255.254", "169.254.1.1"] {
            assert!(action_valid("ban_ip", ip, "default").is_err(), "ban d'une IP protégée ({ip}) DOIT être refusé");
            assert!(ip_is_protected(ip), "{ip} doit être classée protégée");
        }
        // 172.15 / 172.32 ne sont PAS RFC1918 -> bannissables.
        assert!(!ip_is_protected("172.15.0.1") && !ip_is_protected("172.32.0.1"));
        // unban jamais bridé (inoffensif) ; format toujours validé.
        assert!(action_valid("unban_ip", "10.0.0.5", "default").is_ok(), "unban d'une IP protégée reste permis");
        assert!(action_valid("ban_ip", "not-an-ip", "default").is_err(), "format toujours validé");
    }

    /// M2 — marqueur host `#H#…#H#` : posé pour un agent à token lié, relu à l'ingest (écrase event.host).
    /// Roundtrip + refus d'un host non conforme + jamais posé pour un collecteur Basic (multiplexe des hôtes).
    #[test]
    fn v2_m2_spool_host_marker_roundtrip() {
        let agent = AuthUser { name: "web01.internal".into(), role: "agent".into(), tenant: "default".into(), is_superadmin: false, method: "bearer".into(), csrf: String::new(), env: None };
        let mk = spool_host_marker(&agent);
        assert_eq!(mk, "#H#web01.internal#H#");
        assert_eq!(spool_file_host(&format!("ingest-1-2{mk}.json")).as_deref(), Some("web01.internal"));
        // collecteur central Basic (editor) : PAS de marqueur -> multiplexage d'hôtes préservé.
        let editor = AuthUser { name: "collector".into(), role: "editor".into(), ..agent.clone() };
        assert_eq!(spool_host_marker(&editor), "");
        // agent à token NON lié (name vide) : pas de marqueur.
        let unbound = AuthUser { name: "".into(), ..agent.clone() };
        assert_eq!(spool_host_marker(&unbound), "");
        // fichier sans marqueur host -> None (comportement historique).
        assert_eq!(spool_file_host("ingest-1-2.json"), None);
        assert!(!host_marker_ok("bad host/../#"));
    }

    /// PERF ×3-10 — bascule du chemin `kind=events` en UNE transaction/fichier (BEGIN IMMEDIATE/COMMIT).
    /// INVARIANTS : (a) un batch multi-events COMMIT ATOMIQUEMENT (tout visible après commit) ; (b) la
    /// dédup `INSERT OR IGNORE` (colonne `dedup UNIQUE`) TIENT toujours — un doublon DANS le batch et un
    /// re-jeu du batch n'insèrent qu'une fois ; (c) un event sans `dedup` (NULL) s'insère toujours.
    #[test]
    fn ingest_events_batch_atomic_commit_and_dedup() {
        let conn = test_db();
        let events = vec![
            json!({"ts": 1000, "source": "agent", "message": "alpha", "dedup": "k1"}),
            json!({"ts": 1001, "source": "agent", "message": "bravo", "dedup": "k2"}),
            json!({"ts": 1002, "source": "agent", "message": "charlie", "dedup": "k1"}), // MÊME dedup que le 1er
            json!({"ts": 1003, "source": "agent", "message": "delta"}),                  // sans dedup -> toujours inséré
        ];
        // db_path ":memory:" + source "agent" -> parsers_apply/extract_generic sont no-op (aucun parser
        // enregistré pour ce db_path, source hors opt-in générique) : on teste la transaction+dédup PURES.
        let n = ingest_events_batch(&conn, ":memory:", &events, 1234, None, None).expect("batch committé");
        assert_eq!(n, 4, "les 4 events du batch sont traités (avant dédup)");
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 3, "INSERT OR IGNORE : le doublon dedup=k1 est ignoré -> 3 lignes (k1, k2, sans-dedup)");
        // (a) ATOMICITÉ : APRÈS COMMIT, tous les non-doublons sont visibles (rien resté dans une transaction ouverte).
        let visible: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE message IN ('alpha','bravo','delta')", [], |r| r.get(0)).unwrap();
        assert_eq!(visible, 3, "alpha/bravo/delta committés et visibles");
        assert_eq!(conn.query_row("SELECT message FROM event WHERE dedup='k1'", [], |r| r.get::<_, String>(0)).unwrap(), "alpha", "le 1er gagne (OR IGNORE)");
        // (b) RE-JEU du même batch = idempotent sur les clés dédup ; seul 'delta' (dedup NULL) ré-insère.
        let n2 = ingest_events_batch(&conn, ":memory:", &events, 1234, None, None).expect("2e batch committé");
        assert_eq!(n2, 4);
        let count2: i64 = conn.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
        assert_eq!(count2, 4, "re-jeu : seul 'delta' (dedup NULL, distinct en UNIQUE) ré-insère -> 3 + 1 = 4");
        // Batch vide -> Ok(0), transaction propre (COMMIT d'une transaction vide, aucune erreur).
        assert_eq!(ingest_events_batch(&conn, ":memory:", &[], 1, None, None).unwrap(), 0);
    }

    // ============================================================================================
    // #40 — PROCESSEUR D'INGEST (edge/ingest processor). Chaque test utilise un db_path UNIQUE : le
    // registre compilé + les compteurs sont des statics globaux clés par db_path -> isolation stricte
    // sous parallélisme (aucune contamination croisée).
    // ============================================================================================

    /// Insère une règle `ingest_rule` puis recompile le registre chaud de `dbp` (miroir du CRUD).
    #[allow(clippy::too_many_arguments)]
    fn add_ingest_rule(conn: &Connection, dbp: &str, ord: i64, mf: &str, mo: &str, mv: &str, action: &str, arg: &str) {
        conn.execute(
            "INSERT INTO ingest_rule(name,ord,match_field,match_op,match_value,action,action_arg,enabled,managed,created) \
             VALUES('t',?1,?2,?3,?4,?5,?6,1,2,0)",
            params![ord, mf, mo, mv, action, arg],
        ).unwrap();
        processors_reload(conn, dbp);
    }

    /// DROP : la règle matche -> event NON indexé + compteur `dropped` incrémenté (dropped-by-policy visible).
    #[test]
    fn proc_drop_rule_drops_and_counts() {
        let conn = test_db();
        let dbp = "proc-drop";
        add_ingest_rule(&conn, dbp, 0, "category", "eq", "noise", "drop", "");
        let events = vec![
            json!({"ts": 1, "source": "agent", "category": "noise", "message": "spam", "dedup": "d1"}),
            json!({"ts": 2, "source": "agent", "category": "auth",  "message": "login", "dedup": "d2"}),
        ];
        let n = ingest_events_batch(&conn, dbp, &events, 1, None, None).unwrap();
        assert_eq!(n, 2, "les 2 events sont TRAITÉS (parité du retour), même le droppé");
        let stored: i64 = conn.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
        assert_eq!(stored, 1, "seul l'event non-noise est indexé (le noise est droppé par policy)");
        assert!(conn.query_row("SELECT 1 FROM event WHERE dedup='d1'", [], |r| r.get::<_, i64>(0)).is_err(), "l'event droppé n'existe PAS");
        let c = processors_counters_json(dbp);
        assert_eq!(c["totals"]["dropped"], 1, "1 drop COMPTÉ (non-silence)");
        assert_eq!(c["totals"]["not_indexed"], 1);
    }

    /// MASK : réécrit un champ (redaction PII) sur la ligne STOCKÉE + compteur `masked`. Colonne ET fields.<clé>.
    #[test]
    fn proc_mask_rewrites_field() {
        let conn = test_db();
        let dbp = "proc-mask";
        add_ingest_rule(&conn, dbp, 0, "source", "eq", "pii", "mask", "message");
        add_ingest_rule(&conn, dbp, 1, "source", "eq", "pii", "mask", "fields.ssn");
        let events = vec![json!({"ts": 1, "source": "pii", "message": "SSN=123-45-6789", "fields": {"ssn": "123-45-6789", "keep": "ok"}, "dedup": "m1"})];
        ingest_events_batch(&conn, dbp, &events, 1, None, None).unwrap();
        let (msg, fields): (String, String) = conn.query_row("SELECT message, fields FROM event WHERE dedup='m1'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(msg, "[redacted]", "le message est masqué");
        let fv: Value = serde_json::from_str(&fields).unwrap();
        assert_eq!(fv["ssn"], "[redacted]", "fields.ssn masqué");
        assert_eq!(fv["keep"], "ok", "les autres champs sont préservés (redaction ciblée)");
        assert_eq!(processors_counters_json(dbp)["totals"]["masked"], 2);
    }

    /// ROUTE : pose l'environnement cible (`env_id`) sur la ligne stockée + compteur `routed`.
    #[test]
    fn proc_route_sets_target_env() {
        let conn = test_db();
        let dbp = "proc-route";
        add_ingest_rule(&conn, dbp, 0, "source", "eq", "app", "route", "cold");
        let events = vec![json!({"ts": 1, "source": "app", "message": "x", "dedup": "r1"})];
        ingest_events_batch(&conn, dbp, &events, 1, None, None).unwrap();
        let env: String = conn.query_row("SELECT env_id FROM event WHERE dedup='r1'", [], |r| r.get(0)).unwrap();
        assert_eq!(env, "cold", "l'event est routé vers l'environnement cible");
        assert_eq!(processors_counters_json(dbp)["totals"]["routed"], 1);
    }

    /// SAMPLE : garde ~1 event sur N d'une source bruyante ; les N-1 autres droppés (comptés sampled_out).
    #[test]
    fn proc_sample_keeps_one_in_n() {
        let conn = test_db();
        let dbp = "proc-sample";
        add_ingest_rule(&conn, dbp, 0, "source", "eq", "chatty", "sample", "3");
        let events: Vec<Value> = (0..9).map(|i| json!({"ts": i, "source": "chatty", "message": "noise", "dedup": format!("s{i}")})).collect();
        ingest_events_batch(&conn, dbp, &events, 1, None, None).unwrap();
        let stored: i64 = conn.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
        assert_eq!(stored, 3, "1-sur-3 sur 9 events -> 3 gardés (k=0,3,6)");
        assert_eq!(processors_counters_json(dbp)["totals"]["sampled_out"], 6, "les 6 autres sont échantillonnés-out (comptés)");
    }

    /// FAIL-SAFE : une règle INVALIDE (regex non compilable) est SKIPPÉE au reload (compteur reload_errors)
    /// -> elle n'entre jamais dans le pipeline ; l'event est indexé INCHANGÉ (jamais un drop silencieux par bug).
    #[test]
    fn proc_bad_rule_fails_safe_event_indexed() {
        let conn = test_db();
        let dbp = "proc-bad";
        // Règle regex volontairement cassée -> compile_rule Err -> skippée au reload.
        conn.execute(
            "INSERT INTO ingest_rule(name,ord,match_field,match_op,match_value,action,action_arg,enabled,managed,created) \
             VALUES('bad',0,'message','regex','(unclosed','drop','',1,2,0)",
            [],
        ).unwrap();
        processors_reload(&conn, dbp);
        let events = vec![json!({"ts": 1, "source": "agent", "message": "important", "dedup": "b1"})];
        ingest_events_batch(&conn, dbp, &events, 1, None, None).unwrap();
        let msg: String = conn.query_row("SELECT message FROM event WHERE dedup='b1'", [], |r| r.get(0)).unwrap();
        assert_eq!(msg, "important", "l'event est indexé INCHANGÉ malgré la règle cassée (fail-safe)");
        assert_eq!(processors_counters_json(dbp)["reload_errors"], 1, "la règle invalide est COMPTÉE (visible), jamais silencieuse");
    }

    /// MODE 0 BYTE-IDENTIQUE : AUCUNE règle sur ce db_path -> l'ingest écrit EXACTEMENT comme sans le
    /// processeur (registre vide -> Keep instantané). On compare la ligne stockée à l'entrée, champ par champ.
    #[test]
    fn proc_mode0_byte_identical_no_rules() {
        let conn = test_db();
        let dbp = "proc-mode0";
        // Reload EXPLICITE sur une table vide -> entrée de registre présente mais VIDE -> Keep (chemin mode 0).
        processors_reload(&conn, dbp);
        let events = vec![json!({"ts": 42, "source": "agent", "category": "auth", "severity": 3, "message": "hello", "src_ip": "1.2.3.4", "dedup": "z1"})];
        let n = ingest_events_batch(&conn, dbp, &events, 42, None, None).unwrap();
        assert_eq!(n, 1);
        let (src, cat, sev, msg, ip, env): (String, String, i64, String, Option<String>, String) = conn.query_row(
            "SELECT source, category, severity, message, src_ip, env_id FROM event WHERE dedup='z1'",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        ).unwrap();
        assert_eq!((src.as_str(), cat.as_str(), sev, msg.as_str(), ip.as_deref(), env.as_str()),
                   ("agent", "auth", 3, "hello", Some("1.2.3.4"), "prod"),
                   "ligne stockée byte-identique à l'ingest sans processeur");
        let c = processors_counters_json(dbp);
        assert_eq!(c["totals"]["not_indexed"], 0, "aucune donnée non-indexée en mode 0");
    }

    /// MIGRATION v83 : la table de contrôle `ingest_rule` existe après migrate + schema_version bumpé.
    #[test]
    fn proc_migration_v83_creates_table() {
        let conn = test_db();
        let exists: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ingest_rule'", [], |r| r.get(0)
        ).unwrap();
        assert_eq!(exists, 1, "la table ingest_rule est créée par migrate_v83");
        let v: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert!(v.parse::<i64>().unwrap() >= 83, "schema_version >= 83");
    }

    /// PIPELINE ORDONNÉ : MASK (n'arrête pas) PUIS une règle DROP en aval s'applique bien sur la ligne masquée.
    #[test]
    fn proc_ordered_mask_then_drop() {
        let conn = test_db();
        let dbp = "proc-order";
        add_ingest_rule(&conn, dbp, 0, "source", "any", "", "mask", "message"); // masque tout
        add_ingest_rule(&conn, dbp, 1, "category", "eq", "drop-me", "drop", ""); // puis droppe une catégorie
        let events = vec![
            json!({"ts": 1, "source": "a", "category": "keep",    "message": "s1", "dedup": "o1"}),
            json!({"ts": 2, "source": "a", "category": "drop-me", "message": "s2", "dedup": "o2"}),
        ];
        ingest_events_batch(&conn, dbp, &events, 1, None, None).unwrap();
        let stored: i64 = conn.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
        assert_eq!(stored, 1, "o2 droppé par la 2e règle malgré le masque de la 1re");
        let msg: String = conn.query_row("SELECT message FROM event WHERE dedup='o1'", [], |r| r.get(0)).unwrap();
        assert_eq!(msg, "[redacted]", "o1 gardé ET masqué (MASK ne court-circuite pas)");
        let c = processors_counters_json(dbp);
        assert_eq!(c["totals"]["masked"], 2, "les 2 events matchent le MASK (avant le drop de o2)");
        assert_eq!(c["totals"]["dropped"], 1);
    }

    // =========================================================================================
    // #57 — SUITE D'INGEST SÉCURITÉ ENDPOINT (BYO-agent : normalisation CIM du schéma Wazuh).
    // Helper : ingère UN event source=wazuh dont le `message` est l'alerte Wazuh (objet JSON stringifié),
    // puis lit la ligne `event` normalisée. Réutilise le chemin d'ingest RÉEL (ingest_events_batch) ->
    // prouve que la normalisation passe par le sac `fields` bindé (injection-safe), pas par du SQL brut.
    // =========================================================================================
    fn ingest_wazuh(conn: &Connection, dbp: &str, dedup: &str, alert: Value) -> (String, i64, String) {
        let ev = json!({ "ts": 1000, "source": "wazuh", "message": alert.to_string(), "dedup": dedup });
        ingest_events_batch(conn, dbp, std::slice::from_ref(&ev), 1000, None, None).unwrap();
        conn.query_row("SELECT category,severity,COALESCE(fields,'{}') FROM event WHERE dedup=?1", params![dedup],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?))).unwrap()
    }
    fn jf(fields: &str, key: &str) -> Option<String> {
        serde_json::from_str::<Value>(fields).ok()?.get(key)?.as_str().map(|s| s.to_string())
    }

    #[test]
    fn endpoint_wazuh_sca_normalized_to_posture() {
        let conn = test_db();
        let dbp = ":memory:eps-sca";
        let alert = json!({
            "agent": {"id":"001","name":"web01","ip":"10.0.0.5"},
            "rule": {"level":7,"groups":["sca"]},
            "data": {"sca": {
                "type":"check",
                "policy":"CIS Ubuntu Linux 22.04 LTS Benchmark",
                "policy_id":"cis_ubuntu22-04",
                "check": {
                    "id":"28500",
                    "title":"Ensure permissions on /etc/shadow are configured",
                    "result":"failed",
                    "remediation":"chmod 0640 /etc/shadow",
                    "compliance":[{"cis":["6.1.3"]},{"pci_dss":["8.7"]}]
                }
            }}
        });
        let (cat, sev, f) = ingest_wazuh(&conn, dbp, "sca1", alert);
        assert_eq!(cat, "posture", "SCA -> category posture");
        assert_eq!(sev, 2, "contrôle failed -> severity warning (2)");
        assert_eq!(jf(&f, "posture_result").as_deref(), Some("fail"), "result normalisé pass/fail/na");
        assert_eq!(jf(&f, "posture_check_id").as_deref(), Some("28500"));
        assert_eq!(jf(&f, "posture_policy").as_deref(), Some("CIS Ubuntu Linux 22.04 LTS Benchmark"));
        assert_eq!(jf(&f, "posture_kind").as_deref(), Some("check"));
        assert_eq!(jf(&f, "agent_name").as_deref(), Some("web01"), "identité endpoint (agent) surfacée");
        assert_eq!(jf(&f, "posture_framework").as_deref(), Some("cis,pci_dss"), "cadres de conformité aplatis");
        assert_eq!(jf(&f, "posture_compliance").as_deref(), Some("cis:6.1.3,pci_dss:8.7"));
    }

    #[test]
    fn endpoint_wazuh_vuln_normalized_to_vuln() {
        let conn = test_db();
        let dbp = ":memory:eps-vuln";
        let alert = json!({
            "agent": {"name":"db02"},
            "data": {"vulnerability": {
                "cve":"CVE-2024-3094",
                "severity":"High",
                "status":"Active",
                "title":"xz backdoor",
                "package":{"name":"liblzma5","version":"5.6.0"},
                "cvss":{"cvss3":{"base_score":"9.8"}}
            }}
        });
        let (cat, sev, f) = ingest_wazuh(&conn, dbp, "v1", alert);
        assert_eq!(cat, "vuln", "vulnerability -> category vuln");
        assert_eq!(sev, 3, "High -> severity 3");
        assert_eq!(jf(&f, "cve").as_deref(), Some("CVE-2024-3094"));
        assert_eq!(jf(&f, "vuln_severity").as_deref(), Some("high"), "sévérité normalisée en minuscule");
        assert_eq!(jf(&f, "vuln_package").as_deref(), Some("liblzma5"));
        assert_eq!(jf(&f, "vuln_package_version").as_deref(), Some("5.6.0"));
        assert_eq!(jf(&f, "vuln_cvss").as_deref(), Some("9.8"));
        assert_eq!(jf(&f, "vuln_status").as_deref(), Some("Active"));
    }

    #[test]
    fn endpoint_wazuh_fim_extends_integrity() {
        let conn = test_db();
        let dbp = ":memory:eps-fim";
        let alert = json!({
            "agent": {"name":"host7"},
            "syscheck": {
                "path":"/usr/bin/sudo",
                "event":"modified",
                "mode":"whodata",
                "sha256_after":"deadbeef",
                "audit":{"effective_user":{"name":"root"}}
            }
        });
        let (cat, sev, f) = ingest_wazuh(&conn, dbp, "fim1", alert);
        assert_eq!(cat, "integrity", "syscheck -> category integrity (étendue)");
        assert_eq!(sev, 2, "modified -> severity 2");
        assert_eq!(jf(&f, "fim_path").as_deref(), Some("/usr/bin/sudo"));
        assert_eq!(jf(&f, "fim_event").as_deref(), Some("modified"));
        assert_eq!(jf(&f, "action").as_deref(), Some("modify"), "outcome neutre CIM");
        assert_eq!(jf(&f, "fim_actor").as_deref(), Some("root"), "whodata : qui a modifié");
        assert_eq!(jf(&f, "fim_sha256").as_deref(), Some("deadbeef"));
    }

    #[test]
    fn endpoint_wazuh_syscollector_inventory() {
        let conn = test_db();
        let dbp = ":memory:eps-inv";
        let alert = json!({
            "agent": {"name":"host7"},
            "location":"syscollector",
            "data": {"program": {"name":"openssl","version":"3.0.2","vendor":"Ubuntu"}}
        });
        let (cat, _sev, f) = ingest_wazuh(&conn, dbp, "inv1", alert);
        assert_eq!(cat, "inventory", "syscollector -> category inventory");
        assert_eq!(jf(&f, "inv_type").as_deref(), Some("package"));
        assert_eq!(jf(&f, "inv_name").as_deref(), Some("openssl"));
        assert_eq!(jf(&f, "inv_version").as_deref(), Some("3.0.2"));
    }

    /// Le collecteur GAGNE : un event source=wazuh qui DÉCLARE déjà une category/severity n'est PAS
    /// ré-catégorisé par le normaliseur (ENRICH-only, comme les dparsers). Les fields sont quand même enrichis.
    #[test]
    fn endpoint_normalizer_does_not_override_declared_category() {
        let conn = test_db();
        let dbp = ":memory:eps-noover";
        let alert = json!({"agent":{"name":"h"},"data":{"vulnerability":{"cve":"CVE-1","severity":"Low"}}});
        let ev = json!({ "ts": 1, "source":"wazuh", "category":"malware", "severity":4, "message": alert.to_string(), "dedup":"o1" });
        ingest_events_batch(&conn, dbp, std::slice::from_ref(&ev), 1, None, None).unwrap();
        let (cat, sev, f): (String, i64, String) = conn.query_row(
            "SELECT category,severity,COALESCE(fields,'{}') FROM event WHERE dedup='o1'", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!((cat.as_str(), sev), ("malware", 4), "category/severity déclarées NON écrasées");
        assert_eq!(jf(&f, "cve").as_deref(), Some("CVE-1"), "mais les fields sont enrichis");
    }

    /// MODE 0 sur le CHEMIN D'INGEST : un event NON-endpoint dont le message est un JSON contenant `syscheck`
    /// n'est PAS normalisé (gate par source) -> category inchangée, aucun champ `fim_*`. Preuve byte-identique.
    #[test]
    fn endpoint_mode0_gate_ignores_non_endpoint_source() {
        let conn = test_db();
        let dbp = ":memory:eps-mode0";
        // même charge utile FIM mais source=firewall (hors PLUME_ENDPOINT_NORMALIZE) -> aucun traitement.
        let msg = json!({"syscheck":{"path":"/x","event":"modified"}}).to_string();
        let ev = json!({ "ts": 1, "source":"firewall", "category":"firewall", "message": msg, "dedup":"m0" });
        ingest_events_batch(&conn, dbp, std::slice::from_ref(&ev), 1, None, None).unwrap();
        let (cat, f): (String, String) = conn.query_row(
            "SELECT category,COALESCE(fields,'{}') FROM event WHERE dedup='m0'", [],
            |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(cat, "firewall", "source non-endpoint -> category inchangée");
        assert!(jf(&f, "fim_path").is_none(), "aucune normalisation FIM hors source endpoint");
        // et la fonction pure elle-même est un no-op strict pour une source hors gate.
        assert_eq!(endpoint_normalize("firewall", &msg, None), (None, None, None));
    }

    /// Le panneau SCA-posture est SOQL-backed : la requête `stats count by posture_result` renvoie les
    /// comptes pass/fail attendus après ingest de plusieurs contrôles (2 fail + 1 pass).
    #[test]
    fn endpoint_sca_posture_panel_soql_counts() {
        let conn = test_db();
        let dbp = ":memory:eps-panel";
        let mk = |res: &str| json!({"agent":{"name":"h"},"data":{"sca":{"type":"check","policy":"CIS","check":{"id":"1","title":"t","result":res}}}});
        ingest_wazuh(&conn, dbp, "p1", mk("failed"));
        ingest_wazuh(&conn, dbp, "p2", mk("failed"));
        ingest_wazuh(&conn, dbp, "p3", mk("passed"));
        // requête EXACTE du panneau semé (seed_sca_dashboard) -> chemin SOQL (masqué VIDE == non masqué).
        let sql = soql_to_sql_x("search category=posture posture_kind=check | stats count by posture_result", 0, 0, None).unwrap();
        let mut st = conn.prepare(&sql).unwrap();
        let rows: std::collections::HashMap<String, i64> = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .unwrap().flatten().collect();
        assert_eq!(rows.get("fail").copied(), Some(2), "2 contrôles échoués ; rows={rows:?}");
        assert_eq!(rows.get("pass").copied(), Some(1), "1 contrôle réussi ; rows={rows:?}");
    }

    /// VOIE VENDOR-AGNOSTIC : la MÊME famille (FIM) depuis un AUTRE agent (`source=fim-agent`, key=value) est
    /// mappée en CIM `integrity` par un PARSEUR DÉCLARATIF (DSL, config.d) — SANS le preset built-in Wazuh,
    /// SANS rebuild. Prouve la couture DSL de la slice #57.
    #[test]
    fn endpoint_dparser_fim_mapping() {
        let conn = test_db();
        let dbp = ":memory:eps-dsl";
        let spec = r#"{"name":"fim","source":"fim-agent","match":"\\bevent=(?:added|modified|deleted)\\b","extract":[{"kv":true}],"map":{"category":"integrity","action":"$action","fields":{"fim_path":"$path","fim_event":"$event","fim_sha256":"$sha256"}}}"#;
        conn.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('fim','fim-agent',?1,1,0,1,0)", params![spec]).unwrap();
        dparsers_reload(&conn, dbp);
        let ev = json!({ "ts":1, "source":"fim-agent", "message":"path=/etc/passwd event=modified sha256=abc123 action=modify", "dedup":"dsl1" });
        ingest_events_batch(&conn, dbp, std::slice::from_ref(&ev), 1, None, None).unwrap();
        let (cat, f): (String, String) = conn.query_row("SELECT category,COALESCE(fields,'{}') FROM event WHERE dedup='dsl1'", [],
            |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(cat, "integrity", "DSL mappe fim-agent -> category integrity");
        assert_eq!(jf(&f, "fim_path").as_deref(), Some("/etc/passwd"));
        assert_eq!(jf(&f, "fim_event").as_deref(), Some("modified"));
        assert_eq!(jf(&f, "action").as_deref(), Some("modify"));
    }

    #[test]
    fn endpoint_seed_sca_dashboard_panels() {
        let conn = test_db();
        seed_sca_dashboard(&conn);
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM panel p JOIN dashboard d ON p.dashboard_id=d.id WHERE d.name='Posture de configuration (SCA/CIS)'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 5, "5 panneaux SCA semés");
        let cnt: i64 = conn.query_row("SELECT COUNT(*) FROM panel WHERE query LIKE '%category=posture%'", [], |r| r.get(0)).unwrap();
        assert!(cnt >= 4, "les panneaux composent sur category=posture");
    }

    // ===== PHASE SURE : auto-index adaptatif — DECAY + ATTRIBUTION DU SLOW ====================
    // Ces tests touchent des GLOBAUX partagés (AUTOINDEX_ON atomique, buffer mémoire, set indexé). Les
    // tests cargo tournent en parallèle -> on sérialise via un mutex dédié et on RESET le buffer + le
    // toggle à chaque entrée pour rester déterministe et ne pas polluer les autres tests.
    // db_path fixe utilisé par ces tests mono-base (MT-KEY : les globaux sont clés par db_path).
    const TDB: &str = "unit-test.db";

    fn autoindex_test_reset() {
        AUTOINDEX_ON.store(true, std::sync::atomic::Ordering::Relaxed);
        autoindex_buf().lock().clear();
        let _ = autoindex_take_filter_fields(); // vide le thread-local de la requête précédente
    }
    fn autoindex_test_teardown() {
        AUTOINDEX_ON.store(false, std::sync::atomic::Ordering::Relaxed);
        autoindex_buf().lock().clear();
        let _ = autoindex_take_filter_fields();
    }
    fn buf_get(name: &str) -> (u32, u32) {
        autoindex_buf().lock()
            .get(TDB).and_then(|b| b.get(name)).copied().unwrap_or((0, 0))
    }

    #[test]
    fn autoindex_slow_credits_only_filter_fields_not_projections() {
        let _g = AUTOINDEX_TEST_LOCK.lock();
        autoindex_test_reset();
        // `dport` est FILTRÉ (where) ; `proto` n'est que PROJETÉ (stats/group-by) -> seul dport doit
        // recevoir le slow_hits quand la requête est lente.
        autoindex_note(TDB, "dport");                       // vu via soql_filter_field (hit)
        autoindex_note(TDB, "proto");                       // vu via soql_field (projection) (hit)
        autoindex_note_filter("dport", AUTOINDEX_SEL_EQ); // dport est un FILTRE (thread-local, non keyé)
        // requête lente simulée :
        let slow_ok = Ok(serde_json::json!({"stats": {"elapsed_ms": 5000.0}}));
        autoindex_mark_slow_if(TDB, &slow_ok);
        assert_eq!(buf_get("dport").1, 1, "le filtre dport doit recevoir le slow_hits");
        assert_eq!(buf_get("proto").1, 0, "la projection proto NE doit PAS recevoir de slow_hits");
        autoindex_test_teardown();
    }

    #[test]
    fn autoindex_slow_picks_most_selective_filter() {
        let _g = AUTOINDEX_TEST_LOCK.lock();
        autoindex_test_reset();
        // deux filtres : `eqf` en égalité (EQ, sélectif) + `rxf` en regex (SCAN, non sargable). Seul le
        // plus sélectif (eqf) doit être crédité du slow.
        autoindex_note(TDB, "eqf");
        autoindex_note(TDB, "rxf");
        autoindex_note_filter("rxf", AUTOINDEX_SEL_SCAN);
        autoindex_note_filter("eqf", AUTOINDEX_SEL_EQ);
        let slow_ok = Ok(serde_json::json!({"stats": {"elapsed_ms": 2000.0}}));
        autoindex_mark_slow_if(TDB, &slow_ok);
        assert_eq!(buf_get("eqf").1, 1, "le filtre égalité (plus sélectif) doit être crédité");
        assert_eq!(buf_get("rxf").1, 0, "le filtre regex (moins sélectif) NE doit PAS être crédité");
        autoindex_test_teardown();
    }

    #[test]
    fn autoindex_fast_query_drains_filters_no_leak() {
        let _g = AUTOINDEX_TEST_LOCK.lock();
        autoindex_test_reset();
        // requête RAPIDE -> pas de slow, MAIS le thread-local de filtres doit être vidé (pas de fuite
        // sur la requête suivante du même thread).
        autoindex_note(TDB, "ffield");
        autoindex_note_filter("ffield", AUTOINDEX_SEL_EQ);
        let fast = Ok(serde_json::json!({"stats": {"elapsed_ms": 1.0}}));
        autoindex_mark_slow_if(TDB, &fast);
        assert_eq!(buf_get("ffield").1, 0, "une requête rapide ne crédite aucun slow");
        // requête suivante : SANS filtre, lente -> ne doit RIEN créditer (filtres précédents bien drainés).
        autoindex_note(TDB, "other");
        let slow = Ok(serde_json::json!({"stats": {"elapsed_ms": 9000.0}}));
        autoindex_mark_slow_if(TDB, &slow);
        assert_eq!(buf_get("ffield").1, 0, "le filtre de la requête précédente NE doit PAS fuiter");
        assert_eq!(buf_get("other").1, 0, "requête lente sans filtre json -> aucun slow attribué");
        autoindex_test_teardown();
    }

    #[test]
    fn autoindex_decay_cools_and_purges_idle_fields() {
        let _g = AUTOINDEX_TEST_LOCK.lock();
        autoindex_test_reset();
        let conn = test_db();
        // un champ chaud historique mais désormais INACTIF (aucun trafic), indexed=0.
        conn.execute(
            "INSERT INTO autoindex(field, hits, slow_hits, last_seen, indexed) VALUES('cold', 4, 2, 100, 0)",
            [],
        ).unwrap();
        let db = std::sync::Arc::new(parking_lot::Mutex::new(conn));
        // tick AGRESSIF (decay 0.5) SANS nouveau trafic (buffer vide) -> décroissance géométrique.
        // cap=0 désactive toute création (on ne teste QUE le decay/purge ici).
        for _ in 0..6 {
            autoindex_tick(&db, TDB, 10, 3, 0, 604_800, 0.5);
        }
        let c = db.lock();
        let remaining: i64 = c.query_row("SELECT COUNT(*) FROM autoindex WHERE field='cold'", [], |r| r.get(0)).unwrap();
        assert_eq!(remaining, 0, "un champ inactif doit décroître à ~0 puis être PURGÉ (anti-bloat)");
        drop(c);
        autoindex_test_teardown();
    }

    #[test]
    fn autoindex_decay_never_purges_indexed_rows() {
        let _g = AUTOINDEX_TEST_LOCK.lock();
        autoindex_test_reset();
        let conn = test_db();
        // une ligne PORTEUSE d'index (indexed=1) avec compteurs déjà à 0 : le decay/purge ne doit JAMAIS
        // la retirer (le cycle de vie des index reste géré par l'éviction LRU, anti-régression).
        conn.execute(
            "INSERT INTO autoindex(field, hits, slow_hits, last_seen, indexed) VALUES('hot', 0, 0, 100, 1)",
            [],
        ).unwrap();
        let db = std::sync::Arc::new(parking_lot::Mutex::new(conn));
        autoindex_tick(&db, TDB, 10, 3, 8, 604_800, 0.5);
        let c = db.lock();
        let n: i64 = c.query_row("SELECT COUNT(*) FROM autoindex WHERE field='hot' AND indexed=1", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "une ligne indexed=1 ne doit jamais être purgée par le decay");
        drop(c);
        autoindex_test_teardown();
    }

    #[test]
    fn autoindex_decay_disabled_keeps_cumulative_behavior() {
        let _g = AUTOINDEX_TEST_LOCK.lock();
        autoindex_test_reset();
        let conn = test_db();
        conn.execute(
            "INSERT INTO autoindex(field, hits, slow_hits, last_seen, indexed) VALUES('keep', 4, 2, 100, 0)",
            [],
        ).unwrap();
        let db = std::sync::Arc::new(parking_lot::Mutex::new(conn));
        // decay=1.0 (kill-switch) -> compteurs INCHANGÉS, AUCUNE purge (comportement historique exact).
        for _ in 0..5 {
            autoindex_tick(&db, TDB, 10, 3, 0, 604_800, 1.0);
        }
        let c = db.lock();
        let (h, s): (i64, i64) = c.query_row(
            "SELECT hits, slow_hits FROM autoindex WHERE field='keep'", [], |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();
        assert_eq!((h, s), (4, 2), "decay=1.0 -> compteurs cumulatifs inchangés, pas de purge");
        drop(c);
        autoindex_test_teardown();
    }


    // ============================================================================================
    // #41 — OTLP TRACES : récepteur OpenTelemetry (OTLP/HTTP JSON). Mapping span->CIM (category=trace),
    // bornes DoS du décodeur, auth-required (ingest-only), gate mode-0, et requêtabilité SOQL des traces.
    // ============================================================================================

    /// Un ExportTraceServiceRequest OTLP/JSON minimal, réaliste (1 resource, 1 scope, 1 span SERVER en erreur).
    fn otlp_sample() -> Value {
        json!({
          "resourceSpans": [{
            "resource": { "attributes": [
              { "key": "service.name", "value": { "stringValue": "checkout" } },
              { "key": "host.name",    "value": { "stringValue": "pod-checkout-7" } }
            ]},
            "scopeSpans": [{
              "scope": { "name": "io.opentelemetry.http", "version": "1.2.0" },
              "spans": [{
                "traceId": "5b8efff798038103d269b633813fc60c",
                "spanId":  "eee19b7ec3c1b174",
                "parentSpanId": "eee19b7ec3c1b173",
                "name": "GET /api/orders",
                "kind": 2,
                "startTimeUnixNano": "1544712660000000000",
                "endTimeUnixNano":   "1544712660050000000",
                "attributes": [
                  { "key": "http.method", "value": { "stringValue": "GET" } },
                  { "key": "http.status_code", "value": { "intValue": "500" } }
                ],
                "status": { "code": 2, "message": "internal error" }
              }]
            }]
          }]
        })
    }

    /// OTLP JSON -> event CIM : category=trace, source dérivée du service, trace/span id normalisés hex,
    /// duration_ms calculée, status error -> severity 3, attributs plats préfixés, host = attribut resource.
    #[test]
    fn otlp_json_maps_to_cim_trace_event() {
        let evs = otlp_request_to_events(&otlp_sample(), 10_000).unwrap();
        assert_eq!(evs.len(), 1, "1 span -> 1 event");
        let ev = &evs[0];
        assert_eq!(ev["category"], "trace");
        assert_eq!(ev["source"], "checkout", "source = service.name");
        assert_eq!(ev["severity"], 3, "status ERROR -> severity 3 (error CIM)");
        assert_eq!(ev["message"], "GET /api/orders", "message = nom du span");
        assert_eq!(ev["host"], "pod-checkout-7", "host = attribut resource host.name (non forgé par span)");
        assert_eq!(ev["ts"], 1544712660i64, "ts = startTimeUnixNano / 1e9");
        assert_eq!(ev["dedup"], "otel-5b8efff798038103d269b633813fc60c-eee19b7ec3c1b174", "idempotent par trace+span");
        let f = &ev["fields"];
        assert_eq!(f["trace_id"], "5b8efff798038103d269b633813fc60c");
        assert_eq!(f["span_id"], "eee19b7ec3c1b174");
        assert_eq!(f["parent_span_id"], "eee19b7ec3c1b173");
        assert_eq!(f["span_kind"], "server");
        assert_eq!(f["trace_status"], "error");
        assert_eq!(f["status_message"], "internal error");
        assert_eq!(f["service"], "checkout");
        assert_eq!(f["scope_name"], "io.opentelemetry.http");
        assert_eq!(f["duration_ms"], 50.0, "50ms = (end-start)/1e6");
        assert_eq!(f["otel.http.method"], "GET", "attribut span aplati, préfixe otel.");
        assert_eq!(f["otel.http.status_code"], 500, "intValue string -> nombre");
        assert_eq!(f["otel.service.name"], "checkout", "attribut resource partagé aplati");
    }

    /// Le span mappé traverse le MÊME `ingest_events_batch` que tout event -> ligne `event` stockée avec
    /// category=trace, fields.trace_id searchable. Prouve masquage/rollups/détection UNIFORMES (mêmes couture).
    #[test]
    fn otlp_span_ingests_via_events_batch_and_is_queryable() {
        let conn = test_db();
        let evs = otlp_request_to_events(&otlp_sample(), 10_000).unwrap();
        let n = ingest_events_batch(&conn, ":memory:", &evs, now(), None, None).unwrap();
        assert_eq!(n, 1);
        let (cat, host, source): (String, Option<String>, String) = conn.query_row(
            "SELECT category, host, source FROM event ORDER BY id DESC LIMIT 1", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!(cat, "trace", "category trace stockée (CIM v1.2, cim_category_ok)");
        assert!(cim_category_ok(&cat), "trace DOIT être une catégorie CIM canonique");
        assert_eq!(host.as_deref(), Some("pod-checkout-7"));
        assert_eq!(source, "checkout");
        // corrélation : requête par trace_id dans fields (le chemin SOQL/search interroge la colonne fields).
        let found: i64 = conn.query_row(
            "SELECT COUNT(*) FROM event WHERE category='trace' AND json_extract(fields,'$.trace_id')=?1",
            params!["5b8efff798038103d269b633813fc60c"], |r| r.get(0)).unwrap();
        assert_eq!(found, 1, "trace requêtable/corrélable par trace_id");
    }

    /// BORNE DoS #1 — cap de spans/req : au-delà de `max_spans` -> Err (l'appelant renvoie 413), jamais une
    /// troncature muette. Prouve que le décodeur ne matérialise pas un batch attaquant illimité.
    #[test]
    fn otlp_span_count_cap_enforced() {
        let mut spans = Vec::new();
        for i in 0..100 {
            spans.push(json!({
                "traceId": format!("{:032x}", i + 1),
                "spanId":  format!("{:016x}", i + 1),
                "name": "op", "startTimeUnixNano": "1",
            }));
        }
        let req = json!({ "resourceSpans": [{ "scopeSpans": [{ "spans": spans }] }] });
        assert!(otlp_request_to_events(&req, 10).is_err(), "101 spans, cap 10 -> 413 (Err), pas de troncature");
        assert_eq!(otlp_request_to_events(&req, 1000).unwrap().len(), 100, "sous le cap -> tout ingéré");
    }

    /// BORNE DoS #2 — cap d'attributs/span : un span à 10 000 attributs ne matérialise que OTLP_MAX_ATTRS_PER_SPAN
    /// clés (anti-cardinalité). BORNE DoS #3 — profondeur de valeur : un kvlist profondément imbriqué ne fait pas
    /// exploser la récursion (au-delà de la profondeur -> Null, borné).
    #[test]
    fn otlp_attr_count_and_depth_bounded() {
        let mut attrs = Vec::new();
        for i in 0..10_000 {
            attrs.push(json!({ "key": format!("k{i}"), "value": { "stringValue": "v" } }));
        }
        let span = json!({
            "traceId": "5b8efff798038103d269b633813fc60c", "spanId": "eee19b7ec3c1b174",
            "name": "x", "startTimeUnixNano": "1", "attributes": attrs
        });
        let ev = otlp_span_to_event(&span, &serde_json::Map::new(), None, None, None).unwrap();
        let nkeys = ev["fields"].as_object().unwrap().len();
        assert!(nkeys <= 256 + 16, "attributs bornés (cap 256 + qq champs de trace), obtenu {nkeys}");
        // profondeur : imbrique 50 kvlist -> la valeur finale est tronquée à Null, pas de stack overflow / hang.
        let mut nested = json!({ "stringValue": "deep" });
        for _ in 0..50 {
            nested = json!({ "kvlistValue": { "values": [ { "key": "n", "value": nested } ] } });
        }
        let v = otlp_any_value(&nested, 6);
        // ne panique pas ; la conversion s'arrête à la profondeur bornée (valeur profonde -> Null quelque part).
        assert!(v.is_object() || v.is_null(), "conversion bornée en profondeur, sans panic");
    }

    /// SÉCURITÉ décodeur — JSON malformé -> pas de panic (serde renvoie Err ; le handler renvoie 400).
    /// Un corps vide / sans resourceSpans -> 0 event (jamais un crash ni une ligne vide).
    #[test]
    fn otlp_malformed_and_empty_are_safe() {
        assert!(serde_json::from_str::<Value>("{ not json").is_err(), "JSON invalide -> Err (handler 400)");
        assert_eq!(otlp_request_to_events(&json!({}), 100).unwrap().len(), 0, "pas de resourceSpans -> 0 event");
        assert_eq!(otlp_request_to_events(&json!({ "resourceSpans": [] }), 100).unwrap().len(), 0);
        // span sans traceId/spanId -> ignoré (inexploitable), pas une ligne vide.
        let req = json!({ "resourceSpans": [{ "scopeSpans": [{ "spans": [{ "name": "orphan" }] }] }] });
        assert_eq!(otlp_request_to_events(&req, 100).unwrap().len(), 0, "span sans id -> ignoré");
    }

    /// AUTH — /v1/traces est un chemin d'INGEST (Bearer -> agent host-bound ; jamais viewer). Miroir des
    /// autres récepteurs : aucune surface d'ingest non-authentifiée. + gate mode-0 par PLUME_OTLP_TRACES.
    #[test]
    fn otlp_route_is_ingest_only_and_gated() {
        assert!(matches!(route_min_role("/v1/traces", true), MinRole::Ingest), "/v1/traces = INGEST");
        assert!(agent_bearer_path("/v1/traces"), "Bearer agent accepté sur /v1/traces (seam machine)");
        assert!(role_satisfies("agent", MinRole::Ingest), "agent satisfait Ingest");
        assert!(!role_satisfies("viewer", MinRole::Ingest), "viewer JAMAIS ingest (pas de forge de traces)");
        // gate : par défaut OFF (mode 0). L'activation est explicite (PLUME_OTLP_TRACES=1).
        let _g = OTLP_ENV_LOCK.lock();
        std::env::remove_var("PLUME_OTLP_TRACES");
        assert!(!otlp_traces_enabled(), "défaut OFF -> handler 404, mode 0 byte-identique");
        std::env::set_var("PLUME_OTLP_TRACES", "1");
        assert!(otlp_traces_enabled(), "=1 -> activé");
        std::env::remove_var("PLUME_OTLP_TRACES");
    }

    /// BORNE DoS #4 — décompression gzip bornée (anti-bombe) : un gzip légitime se décode ; un cap trop bas
    /// -> Err (413) au lieu d'une allocation illimitée. Prouve le garde-fou AVANT parse (OOM du pod 2 Gio).
    #[test]
    fn otlp_gunzip_cap_enforced() {
        use std::io::Write;
        let payload = otlp_sample().to_string();
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(payload.as_bytes()).unwrap();
        let gz = enc.finish().unwrap();
        // cap large -> décode OK, roundtrip identique.
        let out = otlp_gunzip_capped(&gz, 1 << 20).unwrap();
        assert_eq!(out, payload.as_bytes(), "gzip légitime décodé sans perte");
        // cap plus petit que la sortie -> Err (413), jamais d'allocation illimitée.
        assert!(otlp_gunzip_capped(&gz, payload.len() - 1).is_err(), "sortie > cap -> refus (anti-bombe)");
    }

    /// ID normalisation : hex accepté (minuscule), base64 -> hex, tout-zéro/vide -> None (id nul invalide OTLP).
    #[test]
    fn otlp_id_normalization() {
        assert_eq!(otlp_id_hex(Some(&json!("5B8EFFFF798038103D269B633813FC60"))).as_deref(),
                   Some("5b8effff798038103d269b633813fc60"), "hex majuscule -> minuscule");
        // base64 de 0x01020304 -> hex 01020304.
        assert_eq!(otlp_id_hex(Some(&json!("AQIDBA=="))).as_deref(), Some("01020304"), "base64 -> hex");
        assert_eq!(otlp_id_hex(Some(&json!("00000000000000000000000000000000"))), None, "tout-zéro -> None");
        assert_eq!(otlp_id_hex(Some(&json!(""))), None);
        assert_eq!(otlp_id_hex(None), None);
    }

    /// FIX DoS #41 — LAYER 1 : cap de décompression OTLP-spécifique (défaut 16 Mio) PLUS PETIT que le cap
    /// partagé metrics/loki (64 Mio), env-override `PLUME_OTLP_MAX_DECOMPRESS`. RAISON : OTLP/JSON n'amortit
    /// pas le coût par un decode protobuf structuré (serde matérialise l'arbre Value entier avant les caps).
    #[test]
    fn otlp_max_decompress_cap_default_and_env() {
        let _g = OTLP_ENV_LOCK.lock();
        std::env::remove_var("PLUME_OTLP_MAX_DECOMPRESS");
        assert_eq!(otlp_max_decompress(), 16 * 1024 * 1024, "défaut 16 Mio");
        assert!(otlp_max_decompress() < INGEST_MAX_DECOMPRESS, "cap OTLP < cap partagé 64 Mio");
        std::env::set_var("PLUME_OTLP_MAX_DECOMPRESS", "4096");
        assert_eq!(otlp_max_decompress(), 4096, "env override honoré");
        std::env::set_var("PLUME_OTLP_MAX_DECOMPRESS", "0");
        assert_eq!(otlp_max_decompress(), 16 * 1024 * 1024, "0 invalide -> défaut (jamais un cap nul)");
        std::env::set_var("PLUME_OTLP_MAX_DECOMPRESS", "pas-un-nombre");
        assert_eq!(otlp_max_decompress(), 16 * 1024 * 1024, "non-numérique -> défaut");
        std::env::remove_var("PLUME_OTLP_MAX_DECOMPRESS");
    }

    /// FIX DoS #41 — LAYER 2 : vérif de FORME O(scan) AVANT le parse. Le vecteur adverse (un JSON VALIDE mais
    /// NON-OTLP — array plat géant, objet arbitraire — qui gonfle jusqu'au cap et fait matérialiser un énorme
    /// arbre Value AVANT que les caps span ne s'appliquent) est rejeté par une simple recherche d'octets, SANS
    /// parser. Un vrai payload OTLP (objet + clé resourceSpans, y.c. avec whitespace de tête) passe.
    #[test]
    fn otlp_shape_check_rejects_non_otlp_before_parse() {
        assert!(otlp_looks_like_traces(b"{\"resourceSpans\":[]}"));
        assert!(otlp_looks_like_traces(b"   \n\t {\"resourceSpans\":[{}]}"), "whitespace de tête toléré");
        assert!(!otlp_looks_like_traces(b"[0,0,0,0,0,0,0,0]"), "array plat -> refus (pas un objet racine)");
        assert!(!otlp_looks_like_traces(b"{\"a\":[0,0,0,0]}"), "objet sans resourceSpans -> refus");
        assert!(!otlp_looks_like_traces(b"12345"), "scalaire -> refus");
        assert!(!otlp_looks_like_traces(b""), "vide -> refus");
        assert!(!otlp_looks_like_traces(b"   "), "que du whitespace -> refus");
        // un gros corps NON-OTLP (~1 Mio) est rejeté par le scan borné, JAMAIS parsé (coût quasi nul).
        let mut big = String::from("[");
        big.push_str(&"0,".repeat(500_000));
        big.push_str("0]");
        assert!(big.len() > 900_000);
        assert!(!otlp_looks_like_traces(big.as_bytes()), "array plat ~1Mio -> refus O(scan)");
    }

    /// FIX DoS #41 (handler bout-en-bout) — les 3 couches sur /v1/traces : (200) un vrai payload OTLP ingère
    /// et écrit le spool ; (400) un gzip NON-OTLP qui gonfle sous le cap est rejeté par la FORME AVANT le
    /// parse ; (413) un gzip qui DÉPASSE le cap OTLP est refusé à la décompression ; (503) la borne de
    /// concurrence d'ingest coupe quand tous les permits sont pris. Gate PLUME_OTLP_TRACES=1 (OTLP_ENV_LOCK).
    #[tokio::test]
    async fn otlp_handler_dos_layers_end_to_end() {
        use std::io::Write;
        let _g = OTLP_ENV_LOCK.lock();
        std::env::set_var("PLUME_OTLP_TRACES", "1");
        std::env::remove_var("PLUME_OTLP_MAX_DECOMPRESS");

        let spool = std::env::temp_dir().join(format!("plume-otlp-{}-{}", std::process::id(), now()));
        std::fs::create_dir_all(&spool).unwrap();
        let mut st = sso_test_state("plume-admin", "plume-editor", "admins");
        st.spool = Arc::new(spool.to_string_lossy().to_string());
        let au = AuthUser { name: "otel".into(), role: "agent".into(), tenant: "default".into(), is_superadmin: false, method: "bearer".into(), csrf: String::new(), env: None };

        let gzip = |bytes: &[u8]| -> Vec<u8> {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(bytes).unwrap();
            enc.finish().unwrap()
        };
        let mut gz_headers = axum::http::HeaderMap::new();
        gz_headers.insert(axum::http::header::CONTENT_ENCODING, axum::http::HeaderValue::from_static("gzip"));

        // (200) vrai payload OTLP gzippé -> ingère + écrit un fichier spool otlp-*.json.
        let ok_body = gzip(otlp_sample().to_string().as_bytes());
        let r = otlp_traces_post(State(st.clone()), Extension(au.clone()), gz_headers.clone(), axum::body::Bytes::from(ok_body)).await;
        assert_eq!(r.status(), StatusCode::OK, "OTLP légitime -> 200");
        let spooled = std::fs::read_dir(&spool).unwrap().filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("otlp-")).count();
        assert_eq!(spooled, 1, "un event batch écrit dans le spool");

        // (400) gzip NON-OTLP (~800 Kio décompressé, < cap) -> rejet de FORME AVANT le parse coûteux.
        let mut junk = String::from("[");
        junk.push_str(&"0,".repeat(400_000));
        junk.push_str("0]");
        let r = otlp_traces_post(State(st.clone()), Extension(au.clone()), gz_headers.clone(), axum::body::Bytes::from(gzip(junk.as_bytes()))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "JSON non-OTLP -> 400 (rejet de forme, pas de parse)");

        // (413) gzip qui GONFLE au-delà du cap OTLP (abaissé à 64 Kio pour le test) -> refus décompression.
        std::env::set_var("PLUME_OTLP_MAX_DECOMPRESS", "65536");
        let r = otlp_traces_post(State(st.clone()), Extension(au.clone()), gz_headers.clone(), axum::body::Bytes::from(gzip("a".repeat(200_000).as_bytes()))).await;
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE, "décompressé > cap OTLP -> 413");
        std::env::remove_var("PLUME_OTLP_MAX_DECOMPRESS");

        // (503) borne de concurrence : tous les permits pris -> ingest coupé (le client OTLP rejoue).
        st.ingest_sem = Arc::new(tokio::sync::Semaphore::new(1));
        let _held = st.ingest_sem.clone().acquire_owned().await.unwrap();
        let r = otlp_traces_post(State(st.clone()), Extension(au.clone()), gz_headers.clone(), axum::body::Bytes::from(gzip(otlp_sample().to_string().as_bytes()))).await;
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE, "concurrence saturée -> 503");
        drop(_held);

        std::env::remove_var("PLUME_OTLP_TRACES");
        let _ = std::fs::remove_dir_all(&spool);
    }

    // =========================================================================================
    // Reorg Wave 2 — extension de taxonomie CIM v1.3 + tampon de version par event (fields.cim).
    // =========================================================================================

    /// Helper `cim_stamp` : ADDITIF, idempotent, fail-safe (ne perd jamais de donnée).
    #[test]
    fn cim_stamp_unit_additive_idempotent_failsafe() {
        let ver = guatx_core::cim::CIM_VERSION;
        // sac absent / vide / trivial -> objet à une seule clé {"cim":ver}.
        for triv in [None, Some(String::new()), Some("{}".to_string()), Some("null".to_string())] {
            let out = cim_stamp(triv).unwrap();
            let v: Value = serde_json::from_str(&out).unwrap();
            assert_eq!(v["cim"], ver, "sac trivial -> {{cim:ver}}");
            assert_eq!(v.as_object().unwrap().len(), 1, "sac trivial -> exactement 1 clé");
        }
        // MERGE : les clés d'origine survivent, `cim` s'ajoute.
        let out = cim_stamp(Some(r#"{"user":"bob","action":"read"}"#.to_string())).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["cim"], ver);
        assert_eq!(v["user"], "bob");
        assert_eq!(v["action"], "read");
        // IDEMPOTENT : une valeur `cim` déjà posée (connecteur qui pré-tamponne) n'est JAMAIS écrasée.
        let pre = cim_stamp(Some(r#"{"cim":"9.9","k":1}"#.to_string())).unwrap();
        let v: Value = serde_json::from_str(&pre).unwrap();
        assert_eq!(v["cim"], "9.9", "cim préexistant jamais écrasé (idempotent)");
        // FAIL-SAFE : JSON non-objet imprévu -> renvoyé INCHANGÉ (jamais de perte de donnée).
        assert_eq!(cim_stamp(Some("[1,2,3]".to_string())).as_deref(), Some("[1,2,3]"));
    }

    /// RÉTRO-CONFORMITÉ v1.3 : les catégories DÉJÀ émises par des collecteurs live sont désormais
    /// canoniques — `cim_category_ok` est une pure appartenance à l'allow-list, aucune ligne réécrite.
    #[test]
    fn v1_3_live_categories_are_canonical() {
        for c in ["exec", "secrets", "account", "recon",
                  "postscreen", "reject", "mailflow", "mail-phishing", "mail-url"] {
            assert!(cim_category_ok(c), "catégorie live '{c}' DOIT être canonique en CIM v1.3");
        }
        assert_eq!(guatx_core::cim::CIM_VERSION, "1.3", "version de contrat bumpée à v1.3");
    }

    /// TAMPON AU REPOS : un event ingéré porte `fields.cim = CIM_VERSION` dans la ligne STOCKÉE ->
    /// dérive de contrat détectable au repos via `json_extract(fields,'$.cim')`. Additif : les fields
    /// d'origine survivent ; un event sans fields est stocké `{"cim":ver}` (jamais NULL après tampon).
    #[test]
    fn ingest_stamps_cim_version_at_rest() {
        let conn = test_db();
        let dbp = "cim-stamp-at-rest";
        let ver = guatx_core::cim::CIM_VERSION;
        let events = vec![
            json!({"ts": 1, "source": "auditd",      "category": "exec",    "message": "execve", "fields": {"user": "root"}, "dedup": "s1"}),
            json!({"ts": 2, "source": "vault-audit", "category": "secrets", "message": "read",                               "dedup": "s2"}),
        ];
        let n = ingest_events_batch(&conn, dbp, &events, 1, None, None).unwrap();
        assert_eq!(n, 2);
        let stamped: i64 = conn.query_row(
            "SELECT COUNT(*) FROM event WHERE json_extract(fields,'$.cim')=?1", params![ver], |r| r.get(0)).unwrap();
        assert_eq!(stamped, 2, "les 2 events portent fields.cim = CIM_VERSION au repos");
        let user: Option<String> = conn.query_row(
            "SELECT json_extract(fields,'$.user') FROM event WHERE dedup='s1'", [], |r| r.get(0)).unwrap();
        assert_eq!(user.as_deref(), Some("root"), "tampon ADDITIF : les fields d'origine survivent");
    }

    // ================================================================================================
    // v121 INGEST — corrections de correction (ING-1 quarantaine journald/metrics/snapshot ; ING-3 HEC
    // skip-and-continue ; ING-4 balayage des `.tmp` orphelins). Tests OFFLINE, spool en tmpdir isolé.
    // ================================================================================================

    /// State de test + spool ISOLÉ (tmpdir unique par appel — les tests tournent en parallèle).
    fn ing_state_with_spool() -> (AppState, std::path::PathBuf) {
        static ING_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let uniq = ING_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let spool = std::env::temp_dir().join(format!("plume-ing-{}-{}-{}", std::process::id(), now(), uniq));
        std::fs::create_dir_all(&spool).unwrap();
        let mut st = sso_test_state("plume-admin", "plume-editor", "admins");
        st.spool = Arc::new(spool.to_string_lossy().to_string());
        (st, spool)
    }

    /// ING-1 (HIGH, DATA-LOSS) — un fichier spool journald `.ndjson` dont l'INSERT échoue est mis en
    /// QUARANTAINE (rejouable), PAS supprimé -> aucune perte silencieuse d'events auth sous une écriture DB en
    /// échec. Contraste : le MÊME chemin, base saine, INGÈRE puis SUPPRIME (succès inchangé).
    #[test]
    fn ing1_journald_insert_failure_quarantines_not_deletes() {
        let jline = json!({
            "__REALTIME_TIMESTAMP": "1700000000000000",
            "_HOSTNAME": "web01", "_COMM": "sshd",
            "MESSAGE": "Failed password for invalid user root from 1.2.3.4 port 22",
            "PRIORITY": "5"
        }).to_string();

        // (A) BASE POISON : plus de table `event` -> tout INSERT échoue (simule disque plein/corruption).
        let (st, spool) = ing_state_with_spool();
        st.db.lock().execute_batch("DROP TABLE event").unwrap();
        let fpath = spool.join(format!("jrnl-{}-1.ndjson", now()));
        std::fs::write(&fpath, format!("{jline}\n")).unwrap();
        ingest_once(&st.tenants, &st.spool);
        assert!(!fpath.exists(), "le fichier a été traité (retiré du spool racine)");
        let qcount = std::fs::read_dir(spool.join("quarantine"))
            .map(|r| r.filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().starts_with("jrnl-")).count())
            .unwrap_or(0);
        assert_eq!(qcount, 1, "INSERT échoué -> QUARANTAINE (rejouable), JAMAIS supprimé silencieusement");
        let _ = std::fs::remove_dir_all(&spool);

        // (B) BASE SAINE : même fichier -> event INGÉRÉ + fichier SUPPRIMÉ (succès byte-identique, 0 quarantaine).
        let (st2, spool2) = ing_state_with_spool();
        let fpath2 = spool2.join(format!("jrnl-{}-2.ndjson", now()));
        std::fs::write(&fpath2, format!("{jline}\n")).unwrap();
        ingest_once(&st2.tenants, &st2.spool);
        assert!(!fpath2.exists(), "succès -> fichier supprimé");
        assert!(!spool2.join("quarantine").exists(), "succès -> aucune quarantaine créée");
        let got: i64 = st2.db.lock().query_row(
            "SELECT COUNT(*) FROM event WHERE src_ip='1.2.3.4' AND category='auth'", [], |r| r.get(0)).unwrap();
        assert_eq!(got, 1, "l'event auth journald a bien été ingéré sur la base saine");
        let _ = std::fs::remove_dir_all(&spool2);
    }

    /// ING-1 — voie `metrics` : un fichier spool `.json` kind=metrics dont l'INSERT échoue -> QUARANTAINE
    /// (rejouable), pas de suppression silencieuse (miroir de la voie events).
    #[test]
    fn ing1_metrics_insert_failure_quarantines_not_deletes() {
        let (st, spool) = ing_state_with_spool();
        st.db.lock().execute_batch("DROP TABLE metric").unwrap();
        let content = json!({ "kind": "metrics", "ts": 1700000000i64,
            "data": { "metrics": [ { "name": "cpu", "value": 1.0 } ] } }).to_string();
        let fpath = spool.join(format!("ingest-{}-9.json", now()));
        std::fs::write(&fpath, content).unwrap();
        ingest_once(&st.tenants, &st.spool);
        assert!(!fpath.exists(), "fichier traité");
        let qcount = std::fs::read_dir(spool.join("quarantine"))
            .map(|r| r.filter_map(|e| e.ok()).count()).unwrap_or(0);
        assert_eq!(qcount, 1, "metrics INSERT échoué -> QUARANTAINE, pas de perte silencieuse");
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// ING-1 — voie `snapshot` (firewall/controls/…) : insert snapshot en échec -> QUARANTAINE (rejouable).
    #[test]
    fn ing1_snapshot_insert_failure_quarantines_not_deletes() {
        let (st, spool) = ing_state_with_spool();
        st.db.lock().execute_batch("DROP TABLE snapshot").unwrap();
        let content = json!({ "kind": "firewall", "ts": 1700000000i64, "hash": "h1",
            "data": { "control_docker_lockdown": { "ok": true } } }).to_string();
        let fpath = spool.join(format!("ingest-{}-8.json", now()));
        std::fs::write(&fpath, content).unwrap();
        ingest_once(&st.tenants, &st.spool);
        assert!(!fpath.exists(), "fichier traité");
        let qcount = std::fs::read_dir(spool.join("quarantine"))
            .map(|r| r.filter_map(|e| e.ok()).count()).unwrap_or(0);
        assert_eq!(qcount, 1, "snapshot INSERT échoué -> QUARANTAINE, pas de perte silencieuse");
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// CONC-3 (v124) — les blocs `metrics` ET `snapshot/firewall/controls` de `ingest_once` passent par le
    /// garde RAII `Txn` (BEGIN IMMEDIATE au begin ; ROLLBACK au Drop sauf `.commit()`). Ce test PROUVE (a) la
    /// PARITÉ du chemin SUCCÈS — les deux INSERT sont COMMITTÉS, les fichiers spool supprimés, 0 quarantaine —
    /// et (b) qu'après ingestion l'écrivain PROCESS-GLOBAL n'est PAS coincé dans une transaction ouverte : un
    /// nouveau `Txn::begin` réussit (sinon toute écriture suivante échouerait « transaction within a
    /// transaction »). C'est la garantie que les blocs manuels BEGIN/COMMIT convertis restent byte-équivalents.
    #[test]
    fn conc3_ingest_metrics_and_snapshot_commit_and_release_writer() {
        let (st, spool) = ing_state_with_spool();
        // (metrics) base saine -> INSERT committé, fichier supprimé (succès byte-identique au manuel).
        let mfile = spool.join(format!("ingest-{}-71.json", now()));
        std::fs::write(&mfile, json!({ "kind": "metrics", "ts": 1700000001i64,
            "data": { "metrics": [ { "name": "cpu", "value": 4.2 } ] } }).to_string()).unwrap();
        // (snapshot/firewall) base saine, lockdown OK -> INSERT snapshot committé, aucune alerte, fichier supprimé.
        let sfile = spool.join(format!("ingest-{}-72.json", now()));
        std::fs::write(&sfile, json!({ "kind": "firewall", "ts": 1700000002i64, "hash": "hs1",
            "data": { "control_docker_lockdown": { "ok": true } } }).to_string()).unwrap();

        ingest_once(&st.tenants, &st.spool);

        assert!(!mfile.exists() && !sfile.exists(), "succès -> les deux fichiers spool supprimés");
        assert!(!spool.join("quarantine").exists(), "succès -> aucune quarantaine créée");
        {
            let conn = st.db.lock();
            let mc: i64 = conn.query_row("SELECT COUNT(*) FROM metric WHERE name='cpu'", [], |r| r.get(0)).unwrap();
            assert_eq!(mc, 1, "bloc metrics (Txn) COMMITté -> ligne présente");
            let mv: f64 = conn.query_row("SELECT value FROM metric WHERE name='cpu'", [], |r| r.get(0)).unwrap();
            assert!((mv - 4.2).abs() < 1e-9, "valeur métrique préservée (byte-équivalent)");
            let sc: i64 = conn.query_row("SELECT COUNT(*) FROM snapshot WHERE kind='firewall' AND hash='hs1'", [], |r| r.get(0)).unwrap();
            assert_eq!(sc, 1, "bloc snapshot (Txn) COMMITté -> ligne présente");
            // ÉCRIVAIN LIBRE : aucune transaction fuitée par les blocs Txn -> un nouveau BEGIN IMMEDIATE réussit.
            let tx = Txn::begin(&conn).expect("writer PROCESS-GLOBAL libre après ingest metrics+snapshot (aucune txn fuitée)");
            tx.commit().unwrap();
        }
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// ING-3 — `hec_parse_body` SAUTE un fragment malformé et CONTINUE : un corps `{good}{bad}{good}` ingère
    /// les DEUX bons records (avant : `break` -> perte silencieuse de tout ce qui suit le fragment fautif).
    #[test]
    fn ing3_hec_parse_body_skips_bad_fragment_keeps_both_sides() {
        let recs = hec_parse_body(r#"{"event":"a"}{oops-not-json}{"event":"b"}"#);
        assert_eq!(recs.len(), 2, "les 2 bons records survivent au fragment invalide du MILIEU");
        assert_eq!(recs[0]["event"].as_str(), Some("a"));
        assert_eq!(recs[1]["event"].as_str(), Some("b"));
        // un fragment fautif en TÊTE ne mange pas les suivants.
        let head = hec_parse_body(r#"{bad}{"event":"c"}"#);
        assert_eq!(head.len(), 1, "record après un fragment fautif en tête");
        assert_eq!(head[0]["event"].as_str(), Some("c"));
        // PARITÉ : corps entièrement bon -> aucun record perdu, aucun skip (contrat succès inchangé).
        assert_eq!(hec_parse_body(r#"{"event":"a"}{"event":"b"}"#).len(), 2, "concat OK");
        assert_eq!(hec_parse_body("{\"e\":1}\n{\"e\":2}").len(), 2, "ND-JSON OK");
        assert_eq!(hec_parse_body(r#"[{"e":1},{"e":2},{"e":3}]"#).len(), 3, "array top-level aplati");
        assert_eq!(hec_parse_body("   ").len(), 0, "corps vide -> 0 record");
    }

    /// ING-4 — `sweep_orphan_ingest_tmps` : la garde d'ÂGE épargne un `.tmp` récent (POST en vol) ; un seuil 0
    /// balaye les `.tmp` orphelins ; un fichier spool PUBLIÉ (`.json`/`.ndjson`) n'est JAMAIS touché.
    #[test]
    fn ing4_sweep_orphan_tmps_age_guarded_and_scoped() {
        let (_st, spool) = ing_state_with_spool();
        let sp = spool.to_string_lossy().to_string();
        let tmp_a = spool.join(".hec-1-1.tmp");
        let tmp_b = spool.join(".fh-2-2.tmp");
        let published_json = spool.join("ingest-3-3.json");
        let published_nd = spool.join("jrnl-4-4.ndjson");
        for p in [&tmp_a, &tmp_b] { std::fs::write(p, b"partial").unwrap(); }
        std::fs::write(&published_json, b"{}").unwrap();
        std::fs::write(&published_nd, b"{}\n").unwrap();

        // (1) seuil LARGE -> les `.tmp` fraîchement créés sont trop RÉCENTS -> ÉPARGNÉS (garde d'âge).
        let n0 = sweep_orphan_ingest_tmps(&sp, std::time::Duration::from_secs(3600));
        assert_eq!(n0, 0, "garde d'âge : un `.tmp` récent (POST en vol) n'est pas balayé");
        assert!(tmp_a.exists() && tmp_b.exists());

        // (2) seuil 0 -> tous les `.tmp` orphelins qualifient par l'âge -> balayés ; le PUBLIÉ reste intact.
        let n1 = sweep_orphan_ingest_tmps(&sp, std::time::Duration::ZERO);
        assert_eq!(n1, 2, "les 2 `.tmp` orphelins sont balayés");
        assert!(!tmp_a.exists() && !tmp_b.exists(), "`.tmp` orphelins effacés");
        assert!(published_json.exists(), "fichier spool `.json` publié JAMAIS touché");
        assert!(published_nd.exists(), "fichier spool `.ndjson` publié JAMAIS touché");
        let _ = std::fs::remove_dir_all(&spool);
    }
