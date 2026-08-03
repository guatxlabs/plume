    // ============================================================================================
    // DURCISSEMENT SÉCU — invariants des 6 durcissements (+ bonus).
    // ============================================================================================

    /// M1 — le namespace de contrôle `plume-*` est réservé : toute source INGÉRÉE qui l'usurpe est renommée
    /// `ext:plume-*` ; toute autre source (collecteur légitime) passe INCHANGÉE (collecte intacte).
    #[test]
    fn v2_m1_ext_ingest_source_reserves_plume_namespace() {
        assert_eq!(ext_ingest_source("plume-config"), "ext:plume-config");
        assert_eq!(ext_ingest_source("plume-operator-access"), "ext:plume-operator-access");
        // collecteurs légitimes : AUCUN renommage.
        for s in ["sshd", "auditd", "minio-audit", "cloudflare", "loki", "agent", "web", "k8s-log"] {
            assert_eq!(ext_ingest_source(s), s, "source légitime NE doit PAS être renommée");
        }
    }

    /// M1/M4 — l'exclusion de rétention est liée au marqueur `origin='daemon'` (posé par le DAEMON seul), NON
    /// plus à la valeur de `source`. Un event de contrôle FORGÉ par un agent (origin='') est PURGÉ ; le vrai
    /// (origin='daemon') SURVIT. Preuve du découplage anti-empoisonnement / anti-remplissage disque.
    #[test]
    fn v2_m1_retention_purge_decoupled_from_forgeable_source() {
        let conn = test_db();
        let old = now() - 40 * 86400; // au-delà du plancher 7 j
        conn.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','7')", []).unwrap();
        // (a) vrai audit daemon (origin='daemon') ; (b) plume-config FORGÉ par un agent (origin='') ; (c) event normal.
        conn.execute("INSERT INTO event(ts,source,message,host,origin) VALUES(?1,'plume-config','vrai audit','plume-daemon','daemon')", params![old]).unwrap();
        conn.execute("INSERT INTO event(ts,source,message,host,origin) VALUES(?1,'plume-config','FORGÉ','attacker','')", params![old]).unwrap();
        conn.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'sshd','normal ancien','')", params![old]).unwrap();
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        let c = db.lock();
        let real: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE source='plume-config' AND origin='daemon'", [], |r| r.get(0)).unwrap();
        let forged: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE source='plume-config' AND origin=''", [], |r| r.get(0)).unwrap();
        let normal: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE source='sshd'", [], |r| r.get(0)).unwrap();
        assert_eq!(real, 1, "l'audit daemon (origin='daemon') SURVIT à la purge");
        assert_eq!(forged, 0, "le plume-config FORGÉ (origin='') est PURGÉ -> plus de ligne non-purgeable forgeable");
        assert_eq!(normal, 0, "un event normal ancien est purgé comme avant");
    }

    // ================================ FIELD FILTERS (#45) ================================
    /// Rend un temporaire QUI SE POSSÈDE : l'appelant reçoit la propriété du répertoire, donc il
    /// vit exactement le temps du test puis disparaît entièrement. Rendre un `String` nu ici
    /// aurait laissé le chemin sans propriétaire — c'est la forme même de la fuite.
    fn ff_tmp_path(tag: &str) -> crate::tmp_possede::TmpDb {
        crate::tmp_possede::TmpDb::neuf(&format!("ff-{tag}"))
    }

    #[test]
    fn field_filter_migration_v86() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        assert_eq!(
            conn.query_row::<String, _, _>("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap(),
            CODE_SCHEMA_MAX.to_string(), "migrate atteint la tête (v96)"
        );
        // table field_filter présente + colonnes attendues.
        let cnt: i64 = conn.query_row("SELECT COUNT(*) FROM field_filter", [], |r| r.get(0)).unwrap();
        assert_eq!(cnt, 0, "field_filter VIDE à la création (mode 0)");
        // sel de hash posé, 64 hex (32 octets).
        let salt: String = conn.query_row("SELECT value FROM meta WHERE key='field_mask_salt'", [], |r| r.get(0)).unwrap();
        assert_eq!(salt.len(), 64, "sel = 32 octets hex");
        assert!(salt.bytes().all(|b| b.is_ascii_hexdigit()), "sel hex");
    }

    // ===== KNOWLEDGE OBJECTS (#46) =============================================================
    #[test]
    fn knowledge_migration_v94_tables_created_empty() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        for t in ["knowledge_alias", "knowledge_calc", "knowledge_eventtype", "knowledge_tag"] {
            let c: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0)).unwrap();
            assert_eq!(c, 0, "{t} VIDE à la création (mode 0)");
        }
    }

    #[test]
    fn knowledge_reload_applies_four_types() {
        let path = ff_tmp_path("ko");
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        // mode 0 : aucun KO -> active_knowledge VIDE -> compilation byte-identique.
        knowledge_reload(&conn, &path);
        assert!(effective_knowledge(&path).is_empty(), "aucun KO -> jeu vide (mode 0)");
        let base = guatx_core::soql::to_sql("search host=web01", 0, 0, &guatx_core::soql::Schema::events()).unwrap();
        let with_empty = guatx_core::soql::to_sql("search host=web01", 0, 0, &guatx_core::soql::Schema::events().with_knowledge(effective_knowledge(&path))).unwrap();
        assert_eq!(base, with_empty, "KO vide -> SQL byte-identique");
        // insère les 4 types.
        conn.execute("INSERT INTO knowledge_alias(canonical,source) VALUES('client_ip','src_ip')", []).unwrap();
        conn.execute("INSERT INTO knowledge_calc(name,expr) VALUES('sev_up','upper(severity)')", []).unwrap();
        conn.execute("INSERT INTO knowledge_eventtype(name,filter) VALUES('web_attack','source=web severity=HIGH')", []).unwrap();
        conn.execute("INSERT INTO knowledge_tag(label,field,value) VALUES('pci','category','payment')", []).unwrap();
        knowledge_reload(&conn, &path);
        let ko = effective_knowledge(&path);
        assert!(!ko.is_empty(), "KO chargés depuis la DB");
        let sch = guatx_core::soql::Schema::events().with_knowledge(ko);
        // 1) alias résout la source.
        let f = guatx_core::soql::to_sql("search client_ip=1.2.3.4", 0, 0, &sch).unwrap();
        assert!(f.contains("\"src_ip\" = '1.2.3.4'"), "alias client_ip -> src_ip : {f}");
        // 2) champ calculé injecté (eval implicite).
        let c = guatx_core::soql::to_sql("search | table sev_up", 0, 0, &sch).unwrap();
        assert!(c.contains("upper(severity)") && c.contains("AS \"sev_up\""), "calc injecté : {c}");
        // 3) eventtype détend le filtre stocké.
        let e = guatx_core::soql::to_sql("search eventtype=web_attack", 0, 0, &sch).unwrap();
        assert!(e.contains("\"source\" = 'web'") && e.contains("\"severity\" = 'HIGH'"), "eventtype détendu : {e}");
        // 4) tag -> condition field=value.
        let t = guatx_core::soql::to_sql("search tag=pci", 0, 0, &sch).unwrap();
        assert!(t.contains("\"category\" = 'payment'"), "tag détendu : {t}");
    }

    /// PHASE B — opt-in daemon `PLUME_SOQL_PRUNE_MESSAGE` (défaut OFF). INVARIANT ABSOLU : env non défini ->
    /// le daemon pose `with_message_pruning(false)` -> émission BYTE-IDENTIQUE à `Schema::events()` d'aujourd'hui
    /// (`message` présent). Prouvé ici sans dépendre du OnceLock caché (on construit les schémas directement,
    /// comme le préconise le task) ; le cœur prouve déjà l'élagage réel. On vérifie AUSSI que le flag ON est
    /// bien câblé (il élague `message` sur une requête éligible) -> preuve que le point d'ancrage est le bon.
    #[test]
    fn phaseb_optin_default_off_byte_identical() {
        let q = "search source=x | stats count";
        // Ce que le daemon émet quand PLUME_SOQL_PRUNE_MESSAGE est absent : with_message_pruning(false).
        let default_today = guatx_core::soql::to_sql(q, 0, 0, &guatx_core::soql::Schema::events()).unwrap();
        let optin_off = guatx_core::soql::to_sql(q, 0, 0,
            &guatx_core::soql::Schema::events().with_message_pruning(false)).unwrap();
        assert_eq!(default_today, optin_off, "opt-in OFF DOIT être byte-identique à Schema::events() (mode 0)");
        assert!(optin_off.contains("message"), "OFF : `message` conservé dans le SELECT de base : {optin_off}");
        // Flag ON : le point d'ancrage est réellement câblé -> `message` élagué sur cette requête éligible.
        let optin_on = guatx_core::soql::to_sql(q, 0, 0,
            &guatx_core::soql::Schema::events().with_message_pruning(true)).unwrap();
        assert!(!optin_on.contains("message"), "ON : `message` élagué (requête réductrice) : {optin_on}");
    }

    #[test]
    fn knowledge_validators_reject_injection() {
        assert!(validate_ko_ident("evil; DROP").is_err(), "ident hostile rejeté");
        assert!(validate_ko_ident("ts").is_err(), "champ structurel rejeté");
        assert!(validate_ko_ident("src_user").is_ok(), "ident CIM valide accepté");
        assert!(validate_calc_expr("x", "(SELECT token_hash FROM token)").is_err(), "SELECT rejeté par eval");
        assert!(validate_calc_expr("x", "upper(severity)").is_ok(), "expr eval valide acceptée");
        assert!(validate_eventtype_filter("t", "source=web severity=HIGH").is_ok(), "filtre eventtype valide accepté");
    }

    #[test]
    fn field_filter_effective_masks_roles_and_failclosed() {
        let path = ff_tmp_path("roles");
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        // src_user hash pour rôles bas ('' = viewer+editor) ; pan deny (tous, admin compris).
        conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('u','src_user','hash','')", []).unwrap();
        conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('p','pan','deny','')", []).unwrap();
        // règle admin-inclusive explicite : email mask role=admin (seuil admin -> tous masqués).
        conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('e','email','mask','admin')", []).unwrap();
        field_filters_reload(&conn, &path);

        let viewer = effective_masks(&path, "viewer", "default", None);
        assert_eq!(viewer.get("src_user"), Some(guatx_core::soql::MaskAction::Hash), "viewer : src_user haché");
        assert_eq!(viewer.get("pan"), Some(guatx_core::soql::MaskAction::Deny), "viewer : pan denied");
        assert_eq!(viewer.get("email"), Some(guatx_core::soql::MaskAction::Mask), "viewer : email masqué");

        let admin = effective_masks(&path, "admin", "default", None);
        assert_eq!(admin.get("src_user"), None, "admin : src_user EN CLAIR (rôle '' = seuil editor)");
        assert_eq!(admin.get("pan"), Some(guatx_core::soql::MaskAction::Deny), "admin : DENY s'applique à TOUS");
        assert_eq!(admin.get("email"), Some(guatx_core::soql::MaskAction::Mask), "admin : email masqué (role=admin explicite)");

        // FAIL-CLOSED : rôle inconnu -> rank 0 -> masqué par tout (comme viewer, et plus).
        let unknown = effective_masks(&path, "wat", "default", None);
        assert_eq!(unknown.get("src_user"), Some(guatx_core::soql::MaskAction::Hash), "rôle inconnu -> masqué (fail-closed)");
        assert_eq!(unknown.get("pan"), Some(guatx_core::soql::MaskAction::Deny));

        // mode 0 : aucune règle sur une AUTRE base -> jeu VIDE.
        assert!(effective_masks("/no/such/db", "viewer", "default", None).is_empty(), "pas de registre -> VIDE");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn field_filter_hash_stable_and_nonreversible() {
        let salt = "pepper-xyz";
        let h1 = fmask_hash(salt, "alice");
        let h2 = fmask_hash(salt, "alice");
        let hb = fmask_hash(salt, "bob");
        assert_eq!(h1, h2, "HASH déterministe (corrélation préservée)");
        assert_ne!(h1, hb, "valeurs distinctes -> hash distincts");
        assert_eq!(h1.len(), 16, "hash tronqué 16 hex");
        assert!(h1.bytes().all(|b| b.is_ascii_hexdigit()), "hash hex");
        assert_ne!(h1, "alice", "non réversible en surface (pas la valeur brute)");
        // sel différent -> hash différent (non réversible sans le sel).
        assert_ne!(h1, fmask_hash("other-salt", "alice"), "le sel change le hash");
    }

    #[test]
    fn field_filter_mask_json_value_semantics() {
        use guatx_core::soql::MaskAction;
        let salt = "s";
        assert_eq!(mask_json_value(MaskAction::Mask, salt, &json!("secret")), json!("***"));
        assert_eq!(mask_json_value(MaskAction::MaskPartial, salt, &json!("4111111111111234")), json!("***1234"));
        assert_eq!(mask_json_value(MaskAction::Redact, salt, &json!("x")), Value::Null);
        assert_eq!(mask_json_value(MaskAction::Deny, salt, &json!("x")), Value::Null);
        assert_eq!(mask_json_value(MaskAction::Mask, salt, &Value::Null), Value::Null, "NULL reste NULL");
        assert_eq!(mask_json_value(MaskAction::Hash, salt, &json!("alice")), json!(fmask_hash(salt, "alice")));
    }

    #[test]
    fn field_filter_end_to_end_execution() {
        // Preuve BOUT EN BOUT via le read pool (run_query_ex : authorizer + plume_fmask_hash enregistrés).
        let path = ff_tmp_path("e2e");
        {
            let conn = open_db(&path).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&conn);
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,host,message,src_ip,fields) VALUES(?1,'sshd','auth',3,'h1',?2,?3,?4)",
                params![now(), "login alice", "10.0.0.5", r#"{"src_user":"alice"}"#],
            ).unwrap();
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,host,message,src_ip,fields) VALUES(?1,'sshd','auth',3,'h2',?2,?3,?4)",
                params![now(), "login bob", "10.0.0.6", r#"{"src_user":"bob"}"#],
            ).unwrap();
            conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('u','src_user','hash','')", []).unwrap();
            conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('m','message','mask','')", []).unwrap();
            conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('ip','src_ip','deny','')", []).unwrap();
            field_filters_reload(&conn, &path);
        } // writer droppé -> WAL visible aux connexions read-only du pool

        // VIEWER : src_user haché, message masqué.
        let vm = effective_masks(&path, "viewer", "default", None);
        let sqlv = soql_to_sql_masked_x("search | table src_user, message", 0, 0, None, &vm).unwrap();
        let rv = run_query_ex(&path, &sqlv, 5000, None).unwrap();
        let rows = rv["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2, "2 events");
        for row in rows {
            let u = row[0].as_str().unwrap_or("");
            assert!(u != "alice" && u != "bob" && !u.is_empty(), "src_user haché (pas en clair) : {u}");
            assert_eq!(row[1].as_str().unwrap(), "***", "message masqué pour viewer");
        }
        // corrélation : hash distinct par valeur distincte.
        assert_ne!(rows[0][0], rows[1][0], "hash distinct alice/bob");

        // ADMIN : src_user + message EN CLAIR (rôle '' = seuil editor -> admin non masqué).
        let am = effective_masks(&path, "admin", "default", None);
        assert!(am.get("src_user").is_none() && am.get("message").is_none(), "admin non masqué sur ces règles '' ");
        let sqla = soql_to_sql_masked_x("search | table src_user, message", 0, 0, None, &am).unwrap();
        let ra = run_query_ex(&path, &sqla, 5000, None).unwrap();
        let names: Vec<String> = ra["rows"].as_array().unwrap().iter().map(|r| r[0].as_str().unwrap_or("").to_string()).collect();
        assert!(names.contains(&"alice".to_string()) && names.contains(&"bob".to_string()), "admin voit src_user en clair : {names:?}");

        // AGRÉGATION viewer : values(src_user) ne fuit AUCUNE valeur en clair.
        let sqlagg = soql_to_sql_masked_x("search | stats values(src_user)", 0, 0, None, &vm).unwrap();
        let ragg = run_query_ex(&path, &sqlagg, 5000, None).unwrap();
        let cell = ragg["rows"][0][0].as_str().unwrap_or("");
        assert!(!cell.contains("alice") && !cell.contains("bob"), "agrégat viewer ne fuit pas : {cell}");

        // DENY src_ip : lecture refusée MÊME en SQL brut admin (authorizer read-pool).
        assert!(run_query_ex(&path, "SELECT src_ip FROM event", 5000, None).is_err(), "DENY src_ip -> SQL brut refusé");
        // colonne NON déniée reste lisible en SQL brut admin.
        assert!(run_query_ex(&path, "SELECT host FROM event", 5000, None).is_ok(), "host reste lisible");

        let _ = std::fs::remove_file(&path);
    }

    /// v134 (#9) — le DENY d'un champ (#45) doit couvrir les tables DÉRIVÉES/MIROIRS (host_rollup, event_rollup,
    /// event_dim_rollup, event_fields_fts, risk_rollup, banned_ip), pas seulement `event` : sinon un admin en SQL
    /// brut ré-exfiltre la donnée déniée via une autre table (`SELECT host FROM host_rollup`, `SELECT src_ip FROM
    /// banned_ip`). ADDITIF & CIBLÉ : (1)
    /// avec DENY host actif -> les colonnes-miroirs sont refusées au prepare(), les colonnes non-miroirs restent
    /// lisibles (déni ciblé, pas la table entière) ; (2) SANS aucun DENY -> TOUTES les lectures de rollup restent
    /// INCHANGÉES (le cas commun, rollup-route intacte).
    #[test]
    fn v134_field_deny_covers_derived_mirror_tables() {
        let path = ff_tmp_path("mirror-deny");
        {
            let conn = open_db(&path).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&conn);
            // vtable FTS-champs (créée par reconcile en prod ; inline ici pour tester le déni de `v`).
            conn.execute_batch("CREATE VIRTUAL TABLE IF NOT EXISTS event_fields_fts USING fts5(v, content='');").unwrap();
            conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('h','host','deny','')", []).unwrap();
            field_filters_reload(&conn, &path);
        } // writer droppé -> le read pool voit le WAL

        // MIROIRS de host DENIÉS (même donnée que event.host, autres tables).
        assert!(run_query_ex(&path, "SELECT host FROM host_rollup", 5000, None).is_err(), "host_rollup.host DENIÉ (miroir)");
        assert!(run_query_ex(&path, "SELECT entity FROM risk_rollup", 5000, None).is_err(), "risk_rollup.entity DENIÉ (miroir host)");
        // Miroirs CONSERVATEURS (mélange de valeurs de champs) DENIÉS dès qu'UN champ est dénié.
        assert!(run_query_ex(&path, "SELECT val FROM event_dim_rollup", 5000, None).is_err(), "event_dim_rollup.val DENIÉ (conservateur)");
        assert!(run_query_ex(&path, "SELECT v FROM event_fields_fts", 5000, None).is_err(), "event_fields_fts.v DENIÉ (conservateur)");
        // event.host lui-même reste dénié (comportement #45 existant, généralisé).
        assert!(run_query_ex(&path, "SELECT host FROM event", 5000, None).is_err(), "event.host DENIÉ (#45)");
        // DÉNI CIBLÉ : les colonnes NON-miroirs des tables dérivées restent LISIBLES (jamais la table entière).
        assert!(run_query_ex(&path, "SELECT last_ts FROM host_rollup", 5000, None).is_ok(), "host_rollup.last_ts lisible (non-miroir)");
        assert!(run_query_ex(&path, "SELECT score FROM risk_rollup", 5000, None).is_ok(), "risk_rollup.score lisible (non-miroir)");
        assert!(run_query_ex(&path, "SELECT dim FROM event_dim_rollup", 5000, None).is_ok(), "event_dim_rollup.dim lisible (nom de dim, pas valeur)");
        let _ = std::fs::remove_file(&path);

        // (1b) v134 fix#9 complétion — `banned_ip` (table PLAINE matérialisée depuis event) + risk_rollup.entity
        // pour entity_type='ip'. Avec DENY src_ip -> `SELECT src_ip FROM banned_ip` ET `SELECT entity FROM
        // risk_rollup` DENIÉS (miroirs de event.src_ip) ; avec DENY source -> `SELECT source FROM banned_ip` DENIÉ.
        // Déni CIBLÉ : les autres colonnes de banned_ip (label) restent lisibles.
        let ip = ff_tmp_path("mirror-deny-ip");
        {
            let conn = open_db(&ip).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&conn);
            conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('s','src_ip','deny','')", []).unwrap();
            conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('so','source','deny','')", []).unwrap();
            field_filters_reload(&conn, &ip);
        }
        assert!(run_query_ex(&ip, "SELECT src_ip FROM banned_ip", 5000, None).is_err(), "banned_ip.src_ip DENIÉ (miroir src_ip)");
        assert!(run_query_ex(&ip, "SELECT source FROM banned_ip", 5000, None).is_err(), "banned_ip.source DENIÉ (miroir source)");
        assert!(run_query_ex(&ip, "SELECT entity FROM risk_rollup", 5000, None).is_err(), "risk_rollup.entity DENIÉ (miroir src_ip, entity_type='ip')");
        assert!(run_query_ex(&ip, "SELECT src_ip FROM event", 5000, None).is_err(), "event.src_ip DENIÉ (#45)");
        assert!(run_query_ex(&ip, "SELECT label FROM banned_ip", 5000, None).is_ok(), "banned_ip.label lisible (non-miroir, déni ciblé)");
        let _ = std::fs::remove_file(&ip);

        // (2) INVARIANT (cas commun) : AUCUN field-DENY -> deny set VIDE -> TOUTES les lectures de rollup INCHANGÉES.
        let clean = ff_tmp_path("mirror-clean");
        {
            let conn = open_db(&clean).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&conn);
            conn.execute_batch("CREATE VIRTUAL TABLE IF NOT EXISTS event_fields_fts USING fts5(v, content='');").unwrap();
            field_filters_reload(&conn, &clean); // aucun field_filter -> deny set VIDE
        }
        assert!(run_query_ex(&clean, "SELECT host FROM host_rollup", 5000, None).is_ok(), "sans DENY -> host_rollup.host lisible (rollup-route intacte)");
        assert!(run_query_ex(&clean, "SELECT source FROM event_rollup", 5000, None).is_ok(), "sans DENY -> event_rollup.source lisible");
        assert!(run_query_ex(&clean, "SELECT val FROM event_dim_rollup", 5000, None).is_ok(), "sans DENY -> event_dim_rollup.val lisible");
        assert!(run_query_ex(&clean, "SELECT v FROM event_fields_fts", 5000, None).is_ok(), "sans DENY -> event_fields_fts.v lisible");
        assert!(run_query_ex(&clean, "SELECT entity FROM risk_rollup", 5000, None).is_ok(), "sans DENY -> risk_rollup.entity lisible");
        assert!(run_query_ex(&clean, "SELECT src_ip FROM banned_ip", 5000, None).is_ok(), "sans DENY -> banned_ip.src_ip lisible");
        assert!(run_query_ex(&clean, "SELECT source FROM banned_ip", 5000, None).is_ok(), "sans DENY -> banned_ip.source lisible");
        let _ = std::fs::remove_file(&clean);
    }

    // ================================ #54 ERGONOMIE DASHBOARDS ================================

    #[test]
    fn v90_migration_creates_ergonomics_tables() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        let ver: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(ver, CODE_SCHEMA_MAX.to_string(), "schéma bumpé à la tête (v96)");
        for t in ["library_panel", "playlist", "dashboard_snapshot"] {
            let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "{t} VIDE à la création (mode 0)");
        }
        // colonne ADDITIVE panel.library_panel_id présente + NULL par défaut (panneau autonome = mode 0).
        conn.execute("INSERT INTO dashboard(name,created) VALUES('d',0)", []).unwrap();
        let did = conn.last_insert_rowid();
        conn.execute("INSERT INTO panel(dashboard_id,title,query) VALUES(?1,'p','search')", params![did]).unwrap();
        let pid = conn.last_insert_rowid();
        let lib: Option<i64> = conn.query_row("SELECT library_panel_id FROM panel WHERE id=?1", params![pid], |r| r.get(0)).unwrap();
        assert!(lib.is_none(), "library_panel_id NULL par défaut (mode 0 byte-identique)");
    }

    #[test]
    fn library_panel_resolves_across_two_dashboards() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        conn.execute("INSERT INTO library_panel(name,title,query,is_soql,viz) VALUES('lib','T','search source=sudo | stats count',1,'stat')", []).unwrap();
        let lib = conn.last_insert_rowid();
        conn.execute("INSERT INTO dashboard(name,created,visibility) VALUES('A',0,'shared')", []).unwrap();
        let da = conn.last_insert_rowid();
        conn.execute("INSERT INTO dashboard(name,created,visibility) VALUES('B',0,'shared')", []).unwrap();
        let db = conn.last_insert_rowid();
        conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,library_panel_id) VALUES(?1,'local','search LOCAL10',1,?2)", params![da, lib]).unwrap();
        let p1 = conn.last_insert_rowid();
        conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,library_panel_id) VALUES(?1,'local2','search LOCAL20',1,?2)", params![db, lib]).unwrap();
        let p2 = conn.last_insert_rowid();
        let au = ergo_au("admin");
        // les DEUX panneaux (dashboards distincts) résolvent la MÊME requête de bibliothèque.
        let (q1, s1, _, _) = panel_access(&conn, &au, p1).unwrap();
        let (q2, _, _, _) = panel_access(&conn, &au, p2).unwrap();
        assert_eq!(q1, "search source=sudo | stats count", "panel 1 -> requête de la bibliothèque");
        assert_eq!(q2, "search source=sudo | stats count", "panel 2 -> requête de la bibliothèque");
        assert!(s1, "is_soql hérité de la bibliothèque");
        // ÉDITION UNIQUE de la bibliothèque -> met à jour la résolution des DEUX panneaux (partout).
        conn.execute("UPDATE library_panel SET query='search source=web | stats count' WHERE id=?1", params![lib]).unwrap();
        assert_eq!(panel_access(&conn, &au, p1).unwrap().0, "search source=web | stats count");
        assert_eq!(panel_access(&conn, &au, p2).unwrap().0, "search source=web | stats count");
        // DÉTACHER (library_panel_id NULL) -> retombe sur la requête LOCALE (mode 0 byte-identique).
        conn.execute("UPDATE panel SET library_panel_id=NULL WHERE id=?1", params![p1]).unwrap();
        assert_eq!(panel_access(&conn, &au, p1).unwrap().0, "search LOCAL10", "détaché -> requête locale");
    }

    #[test]
    fn playlist_items_preserve_order() {
        // helper PUR : normalise en liste d'ids (ignore le non-entier, préserve l'ordre voulu par l'opérateur).
        let b = json!({ "items": [3, 1, 2, "x", 5] });
        let s = playlist_items_json(&b).unwrap();
        assert_eq!(s, "[3,1,2,5]", "ordre préservé, non-entier ignoré");
        // round-trip DB : l'ordre stocké est restitué tel quel -> rotation NOC déterministe.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        conn.execute("INSERT INTO playlist(name,interval_s,items) VALUES('noc',30,?1)", params![s]).unwrap();
        let got: String = conn.query_row("SELECT items FROM playlist WHERE name='noc'", [], |r| r.get(0)).unwrap();
        let ids: Vec<i64> = serde_json::from_str(&got).unwrap();
        assert_eq!(ids, vec![3, 1, 2, 5], "playlist = liste ORDONNÉE de dashboards");
    }

    #[test]
    fn dashboard_snapshot_captures_masked_data_and_token_readonly() {
        let path = ff_tmp_path("snap");
        let did;
        {
            let conn = open_db(&path).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&conn);
            conn.execute("INSERT INTO event(ts,source,category,severity,host,message,src_ip) VALUES(?1,'sshd','auth',3,'h1','login',?2)", params![now(), "10.0.0.5"]).unwrap();
            conn.execute("INSERT INTO event(ts,source,category,severity,host,message,src_ip) VALUES(?1,'sshd','auth',3,'h2','login',?2)", params![now(), "10.0.0.6"]).unwrap();
            conn.execute("INSERT INTO dashboard(name,created,visibility) VALUES('D',0,'shared')", []).unwrap();
            did = conn.last_insert_rowid();
            conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'ips','search source=sshd | table src_ip',1,'table')", params![did]).unwrap();
            // masque src_ip pour les rôles bas ('' = viewer/editor ; admin en clair).
            conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('ip','src_ip','mask','')", []).unwrap();
            field_filters_reload(&conn, &path);
        } // writer droppé -> WAL visible au read pool (run_query lit le FICHIER)

        // CAPTURE au rôle VIEWER (masques actifs) -> passe par le chemin GXQL MASQUÉ.
        let vm = effective_masks(&path, "viewer", "default", None);
        assert!(!vm.is_empty(), "le viewer a un masque src_ip actif");
        let rconn = open_db(&path).unwrap();
        let data = capture_dashboard_data(&path, &rconn, did, "D", 0, 0, None, &vm);
        let panels = data["panels"].as_array().unwrap();
        assert_eq!(panels.len(), 1, "1 panneau capturé");
        assert!(!panels[0]["rows"].as_array().unwrap().is_empty(), "le snapshot contient des lignes");
        // PREUVE DE MASQUAGE : src_ip masqué (***), IP brute ABSENTE du snapshot du viewer.
        let dump = serde_json::to_string(&data).unwrap();
        assert!(dump.contains("***"), "snapshot viewer -> src_ip masqué (***)");
        assert!(!dump.contains("10.0.0.5") && !dump.contains("10.0.0.6"), "aucune IP en clair dans le snapshot viewer");
        // CONTRASTE ADMIN (rôle '' = seuil editor -> admin NON masqué) : IP en clair.
        let am = effective_masks(&path, "admin", "default", None);
        let dadmin = serde_json::to_string(&capture_dashboard_data(&path, &rconn, did, "D", 0, 0, None, &am)).unwrap();
        assert!(dadmin.contains("10.0.0."), "admin (non masqué) -> IP en clair (le masquage dépend BIEN du rôle du créateur)");

        // TOKEN read-only : stockage + relecture PAR TOKEN renvoie les données FIGÉES & MASQUÉES (aucune re-exécution).
        let token = gen_snapshot_token().expect("entropie /dev/urandom dispo en test");
        assert_eq!(token.len(), 64, "token CSPRNG = 32 octets hex");
        assert!(token.bytes().all(|b| b.is_ascii_hexdigit()), "token hex");
        rconn.execute(
            "INSERT INTO dashboard_snapshot(dashboard_id,name,token,data,created,created_by,role_at_capture) VALUES(?1,'D',?2,?3,?4,'viewer-u','viewer')",
            params![did, token, serde_json::to_string(&data).unwrap(), now()],
        ).unwrap();
        let got: String = rconn.query_row("SELECT data FROM dashboard_snapshot WHERE token=?1", params![token], |r| r.get(0)).unwrap();
        assert!(got.contains("***") && !got.contains("10.0.0.5"), "relecture par token -> données MASQUÉES figées (read-only)");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dashboard_snapshot_mode0_no_mask_is_clear() {
        // Sans field_filter (mode 0), la capture = rendu live NON masqué (données en clair, comportement identique).
        let path = ff_tmp_path("snap0");
        let did;
        {
            let conn = open_db(&path).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&conn);
            conn.execute("INSERT INTO event(ts,source,category,severity,host,message,src_ip) VALUES(?1,'web','x',1,'h','m','1.2.3.4')", params![now()]).unwrap();
            conn.execute("INSERT INTO dashboard(name,created,visibility) VALUES('D',0,'shared')", []).unwrap();
            did = conn.last_insert_rowid();
            conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'ips','search source=web | table src_ip',1,'table')", params![did]).unwrap();
        }
        let empty = guatx_core::soql::FieldMaskSet::new();
        let rconn = open_db(&path).unwrap();
        let data = capture_dashboard_data(&path, &rconn, did, "D", 0, 0, None, &empty);
        let dump = serde_json::to_string(&data).unwrap();
        assert!(dump.contains("1.2.3.4"), "mode 0 (aucun masque) -> IP en clair dans le snapshot");
        assert!(!dump.contains("***"), "mode 0 -> aucun masquage fantôme");
        let _ = std::fs::remove_file(&path);
    }

    // =================== #51 DAY-2 OPS : console d'opérabilité ===================
    use std::sync::atomic::Ordering as MOrd;

    /// Base en mémoire (schéma + migrations) — pour les fonctions PURES métriques/santé/diag/bulletin (elles
    /// prennent &Connection, aucune dépendance read-pool/db_path).
    fn day2_conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&c);
        c
    }

    async fn resp_bytes<R: axum::response::IntoResponse>(r: R) -> (StatusCode, String) {
        let r = r.into_response();
        let code = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        (code, String::from_utf8_lossy(&b).into_owned())
    }

    /// RBAC : les nouvelles routes ont la bonne capability minimale (diag = admin, bulletin GET viewer /
    /// POST admin, system/* = viewer, /metrics = viewer+ en repli). Gate mutations diag/bulletin.
    #[test]
    fn day2_route_rbac_model() {
        assert_eq!(route_min_role("/api/system/diag", false), MinRole::Admin, "diag GET = admin-only");
        assert_eq!(route_min_role("/api/system/metrics", false), MinRole::Read, "system/metrics GET = viewer+");
        assert_eq!(route_min_role("/api/system/health", false), MinRole::Read, "system/health GET = viewer+");
        assert_eq!(route_min_role("/api/bulletin", false), MinRole::Read, "bulletin GET = viewer+ (MOTD pour tous)");
        assert_eq!(route_min_role("/api/bulletin", true), MinRole::Admin, "bulletin POST = admin (default-deny)");
        assert_eq!(route_min_role("/metrics", false), MinRole::Read, "/metrics repli auth = viewer+ (jamais anonyme)");
        // un viewer NE peut PAS lire le diag ni poser un bulletin ; il PEUT lire metrics/health/bulletin.
        assert!(rbac_gate("viewer", "/api/system/diag", false).is_err(), "viewer -> 403 diag");
        assert!(rbac_gate("viewer", "/api/bulletin", true).is_err(), "viewer -> 403 set bulletin");
        assert!(rbac_gate("viewer", "/api/system/metrics", false).is_ok());
        assert!(rbac_gate("viewer", "/api/system/health", false).is_ok());
        assert!(rbac_gate("viewer", "/api/bulletin", false).is_ok(), "viewer lit le MOTD");
    }

    /// /healthz = 200 + version + schéma (aucune donnée sensible).
    #[tokio::test]
    async fn day2_healthz_200() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let (code, v) = tok_resp_json(healthz(State(st)).await).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["ok"], true);
        assert!(v["schema"].as_i64().unwrap() >= 92, "schéma courant exposé");
    }

    /// /readyz reflète l'état READY : 503 tant que non prêt, 200 après le flag (DB ouvrable).
    #[tokio::test]
    async fn day2_readyz_reflects_state() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        READY.store(false, MOrd::Relaxed);
        let (code, v) = tok_resp_json(readyz(State(st.clone())).await).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "non prêt -> 503");
        assert_eq!(v["ready"], false);
        READY.store(true, MOrd::Relaxed);
        let (code2, v2) = tok_resp_json(readyz(State(st)).await).await;
        assert_eq!(code2, StatusCode::OK, "prêt + DB ouvrable -> 200");
        assert_eq!(v2["ready"], true);
        assert_eq!(v2["db"], true);
    }

    /// /metrics : forme d'exposition Prometheus + auth. Le handler sert le texte ; l'AUTH (jamais anonyme)
    /// est prouvée séparément : /metrics N'EST PAS dans l'allowlist unauth d'auth_guard (seuls healthz/readyz
    /// y sont), et route_min_role("/metrics") = Read -> un anonyme (aucune identité) est rejeté 401 en amont.
    #[tokio::test]
    async fn day2_metrics_exposition_shape_and_auth() {
        SCHED_RULE_LAST_TS.store(now(), MOrd::Relaxed);
        SCHED_ROLLUP_LAST_TS.store(now(), MOrd::Relaxed);
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let (code, body) = resp_bytes(metrics_endpoint(State(st)).await).await;
        assert_eq!(code, StatusCode::OK);
        for m in ["plume_up 1", "# TYPE plume_up gauge", "plume_build_info{", "plume_ingest_events_total",
                  "plume_search_latency_ms{quantile=\"0.5\"}", "plume_component_up{component=\"ingest\"}",
                  "plume_scheduler_rule_ticks_total"] {
            assert!(body.contains(m), "exposition /metrics doit contenir `{m}`\n---\n{body}");
        }
        // AUTH : /metrics gaté (jamais dans l'allowlist unauth du choke-point). Preuve par le repli RBAC.
        assert_eq!(route_min_role("/metrics", false), MinRole::Read);
        assert!(rbac_gate("agent", "/metrics", false).is_err(), "un token agent ne lit pas /metrics");
    }

    /// SELF-MÉTRIQUE : une recherche enregistrée met à jour p50/p95 et le compteur.
    #[test]
    fn day2_search_metric_updates() {
        let before = SEARCH_TOTAL.load(MOrd::Relaxed);
        for ms in [10u32, 20, 30, 40, 100] { record_search(ms); }
        assert!(SEARCH_TOTAL.load(MOrd::Relaxed) >= before + 5, "compteur de recherches incrémenté");
        let (p50, p95, n) = search_quantiles();
        assert!(n >= 5);
        assert!(p50 >= 10 && p50 <= 40, "p50 dans la plage observée: {p50}");
        assert!(p95 >= p50, "p95 >= p50: {p95} >= {p50}");
    }

    /// SANTÉ PAR COMPOSANT : R/J/V calculé depuis fraîcheur + ticks + disque + destinations.
    #[test]
    fn day2_component_health_rgy() {
        let c = day2_conn();
        // ticks récents -> détection/rollups verts ; event frais -> ingest vert.
        SCHED_RULE_LAST_TS.store(now(), MOrd::Relaxed);
        SCHED_ROLLUP_LAST_TS.store(now(), MOrd::Relaxed);
        c.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'sshd','auth',1,'x')", params![now()]).unwrap();
        let comps = component_health(&c, "/nonexistent-spool", "", 80);
        let get = |name: &str| comps.iter().find(|v| v["component"] == name).cloned().unwrap();
        assert_eq!(get("ingest")["state"], "green", "event frais -> ingest vert");
        assert_eq!(get("detection")["state"], "green", "tick règles récent -> détection verte");
        assert_eq!(get("rollups")["state"], "green", "tick rollup récent -> rollups verts");
        assert_eq!(get("forwarder")["state"], "idle", "aucune destination -> forwarder idle");
        // détection en retard : tick ancien -> jaune/rouge (pas vert).
        SCHED_RULE_LAST_TS.store(now() - 1000, MOrd::Relaxed);
        let comps2 = component_health(&c, "/nonexistent-spool", "", 80);
        let det = comps2.iter().find(|v| v["component"] == "detection").unwrap();
        assert_ne!(det["state"], "green", "tick règles ancien -> détection non verte ({})", det["state"]);
        // posture globale = pire état.
        assert!(matches!(worst_state(&comps2), "yellow" | "red"));
    }

    /// DIAG-BUNDLE : n'expose AUCUN secret (denylist query_exec) ni PII, mais bien le schéma + la config.
    #[test]
    fn day2_diag_bundle_excludes_secrets() {
        let c = day2_conn();
        // Sème des SECRETS dans les colonnes de la denylist + de la PII plausible.
        c.execute("INSERT INTO user(name,hash,role) VALUES('alice','$argon2id$SECRETHASHZZZ','admin')", []).unwrap();
        c.execute("INSERT INTO token(token_hash,name,host) VALUES('SECRETTOKENHASH','agent1','h1')", []).ok();
        c.execute("INSERT INTO notifier(kind,name,config) VALUES('ntfy','n','{\"token\":\"SECRETNTFYTOKEN\"}')", []).ok();
        c.execute("INSERT INTO destination(type,name,endpoint,config) VALUES('webhook','d','https://x','{\"auth\":\"SECRETSINKAUTH\"}')", []).ok();
        // PII : un event plume-auth (username + src_ip) NE DOIT PAS finir dans le bundle.
        c.execute("INSERT INTO event(ts,source,category,severity,message,src_ip) VALUES(?1,'plume-auth','auth',3,'échec compte bob depuis 203.0.113.9','203.0.113.9')", params![now()]).unwrap();
        let bundle = diag_bundle_json(&c, "/spool", "", 80);
        let s = bundle.to_string();
        for secret in ["SECRETHASHZZZ", "SECRETTOKENHASH", "SECRETNTFYTOKEN", "SECRETSINKAUTH", "203.0.113.9", "bob"] {
            assert!(!s.contains(secret), "le bundle NE DOIT PAS contenir le secret/PII `{secret}`");
        }
        // mais il contient bien la donnée opérationnelle utile.
        assert!(bundle["schema_version"].as_i64().unwrap() >= 92);
        assert_eq!(bundle["kind"], "plume-diagnostic-bundle");
        assert!(bundle["config"].is_object(), "résumé de config présent");
        assert!(bundle["counts"]["users"].as_i64().unwrap() >= 1, "comptes agrégés (nombres) présents");
        assert!(bundle["health"].is_array());
    }

    /// Une clé de config d'apparence secrète est refusée par le garde-fou d'allowlist.
    #[test]
    fn day2_config_secretish_guard() {
        assert!(key_is_secretish("PLUME_DB_KEY"));
        assert!(key_is_secretish("PLUME_METRICS_TOKEN"));
        assert!(key_is_secretish("PLUME_SSO_HEADER_SECRET"));
        assert!(key_is_secretish("PLUME_PASS_HASH"));
        assert!(!key_is_secretish("PLUME_ADDR"));
        assert!(!key_is_secretish("PLUME_RETENTION_DAYS"));
    }

    /// BULLETIN/MOTD : absent -> aucun bandeau (mode 0) ; posé -> lu ; effacé -> None.
    #[tokio::test]
    async fn day2_bulletin_show_and_clear() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        // mode 0 : aucun bulletin.
        { let c = st.db.lock(); assert!(bulletin_read(&c).is_none(), "aucun bulletin -> pas de bandeau"); }
        let (code, _v) = tok_resp_json(bulletin_get(State(st.clone()), Extension(tok_au("viewer"))).await).await;
        assert_eq!(code, StatusCode::OK);
        // pose (admin).
        let (c1, v1) = tok_resp_json(bulletin_set(State(st.clone()), Extension(tok_au("admin")), Json(json!({ "message": "maintenance 22h", "level": "warn" }))).await).await;
        assert_eq!(c1, StatusCode::OK);
        assert_eq!(v1["bulletin"]["message"], "maintenance 22h");
        assert_eq!(v1["bulletin"]["level"], "warn");
        { let c = st.db.lock(); assert_eq!(bulletin_read(&c).unwrap()["message"], "maintenance 22h"); }
        // un viewer NE peut PAS poser (403) — défense en profondeur (le gate RBAC est prouvé plus haut).
        let (cx, _vx) = tok_resp_json(bulletin_set(State(st.clone()), Extension(tok_au("viewer")), Json(json!({ "message": "pirate" }))).await).await;
        assert_eq!(cx, StatusCode::FORBIDDEN, "viewer -> 403 (re-check require_admin dans le handler)");
        // efface -> None.
        let (c2, _v2) = tok_resp_json(bulletin_clear(State(st.clone()), Extension(tok_au("admin"))).await).await;
        assert_eq!(c2, StatusCode::OK);
        { let c = st.db.lock(); assert!(bulletin_read(&c).is_none(), "après clear -> aucun bandeau (retour mode 0)"); }
        // niveau invalide -> replié sur info (enum fermé, anti-injection CSS).
        let (_c3, v3) = tok_resp_json(bulletin_set(State(st.clone()), Extension(tok_au("admin")), Json(json!({ "message": "x", "level": "<script>" }))).await).await;
        assert_eq!(v3["bulletin"]["level"], "info", "niveau non listé -> info");
    }

    /// CONC-2 : PATTERN d'isolation des boucles infinies ingest/règles (catch_unwind par itération). Un panic
    /// n'interrompt NI les autres itérations NI la boucle ; un `return` de closure = un `continue` de boucle.
    /// (Un panic RÉEL dans l'ingest ne peut être forcé sans injection de faute ; on verrouille ici le contrat
    /// exact sur lequel reposent les deux refactors — mêmes catch_unwind/AssertUnwindSafe.)
    #[test]
    fn conc2_catch_unwind_isolates_panicking_iteration() {
        let items = [1, 2, 3, 4, 5];
        let mut processed: Vec<i32> = Vec::new();
        let mut quarantined: Vec<i32> = Vec::new();
        for &it in &items {
            let processed_ptr = &mut processed;
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if it == 3 { panic!("poison"); }        // panic capturé -> quarantaine + continue
                if it == 2 { return; }                  // ex-`continue` : sort de la closure sans effet de bord
                processed_ptr.push(it);
            }));
            if res.is_err() { quarantined.push(it); }
        }
        assert_eq!(processed, vec![1, 4, 5], "items sains AVANT et APRÈS le poison traités (boucle survit)");
        assert_eq!(quarantined, vec![3], "seul l'item empoisonné isolé");
    }

    /// MIG-67 : reprise SANS PERTE d'une recréation de table interrompue dans la fenêtre `DROP {tbl}` ->
    /// `RENAME {tmp}`. Reproduit l'état intermédiaire (cible ABSENTE, staging `_v67` DÉJÀ peuplée) et vérifie
    /// que la logique de reprise (table_exists + finir le rename) préserve les lignes — là où l'ancien code
    /// (re-DROP {tmp} puis `INSERT ... FROM {tbl}` disparue) restait bloqué à jamais.
    #[test]
    fn mig67_recovery_completes_swap_without_data_loss() {
        let conn = Connection::open_in_memory().unwrap();
        // état APRÈS crash : `orig` a été DROPée, `orig_v67` (staging) est complète.
        conn.execute_batch(
            "CREATE TABLE orig_v67(bucket INTEGER, source TEXT, env_id TEXT NOT NULL DEFAULT 'prod', PRIMARY KEY(bucket,source,env_id));\
             INSERT INTO orig_v67(bucket,source,env_id) VALUES(3600,'web','prod'),(7200,'sshd','prod');",
        ).unwrap();
        // invariants de l'état de crash reconnu par la reprise (mêmes prédicats que le fix).
        assert!(!table_exists(&conn, "orig"), "cible détruite (fenêtre DROP->RENAME)");
        assert!(table_exists(&conn, "orig_v67"), "staging présente et peuplée");
        // reprise = TERMINER le swap (ce que fait la branche de reprise MIG-67).
        if !table_exists(&conn, "orig") && table_exists(&conn, "orig_v67") {
            conn.execute("ALTER TABLE orig_v67 RENAME TO orig", []).unwrap();
        }
        assert!(table_exists(&conn, "orig") && !table_exists(&conn, "orig_v67"), "swap terminé");
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM orig", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2, "les 2 lignes du staging PRÉSERVÉES (aucune perte) ; env_id porté");
        assert!(col_exists(&conn, "orig", "env_id"), "end-state = schéma cible (env_id présent)");
    }


    // Rename legacy soc.db -> plume.db in-daemon : rename + no-clobber + no-op.
    #[test]
    fn rename_legacy_soc_db_to_plume() {
        use std::fs;
        let _tmpg2 = crate::tmp_possede::TmpPossede::neuf("rn");
        let base = _tmpg2.racine().chemin().to_path_buf();
        // (1) legacy soc.db seul -> renommé (+ wal/shm) en plume.db.
        let d1 = base.join("case1");
        fs::create_dir_all(&d1).unwrap();
        fs::write(d1.join("soc.db"), b"legacy").unwrap();
        fs::write(d1.join("soc.db-wal"), b"w").unwrap();
        crate::rename_legacy_db(d1.join("plume.db").to_str().unwrap());
        assert!(d1.join("plume.db").exists() && !d1.join("soc.db").exists(), "soc.db -> plume.db");
        assert!(d1.join("plume.db-wal").exists(), "WAL renommé aussi");
        assert_eq!(fs::read(d1.join("plume.db")).unwrap(), b"legacy", "contenu préservé (rename, pas copie)");
        // (2) plume.db DÉJÀ présent -> JAMAIS de clobber (soc.db intact, plume.db intouché).
        let d2 = base.join("case2");
        fs::create_dir_all(&d2).unwrap();
        fs::write(d2.join("soc.db"), b"legacy").unwrap();
        fs::write(d2.join("plume.db"), b"current").unwrap();
        crate::rename_legacy_db(d2.join("plume.db").to_str().unwrap());
        assert_eq!(fs::read(d2.join("plume.db")).unwrap(), b"current", "plume.db existant JAMAIS clobbé");
        assert!(d2.join("soc.db").exists(), "soc.db laissé tel quel (cible déjà là)");
        // (3) PVC neuf (aucun soc.db) -> no-op.
        let d3 = base.join("case3");
        fs::create_dir_all(&d3).unwrap();
        crate::rename_legacy_db(d3.join("plume.db").to_str().unwrap());
        assert!(!d3.join("plume.db").exists(), "aucun legacy -> no-op (pas de création)");
        let _ = fs::remove_dir_all(&base);
    }

    // ============================================================================================
    // CLI — AUCUN ARGUMENT INCONNU NE DOIT DEVENIR « lance le serveur ».
    // ============================================================================================

    /// L'AIDE DIT CE QUE LE DISPATCH FAIT. `SUBCOMMANDS` ne sert qu'à AFFICHER l'aide — la détection
    /// d'un argument inconnu, elle, est le COMPLÉMENT calculé par le flot de contrôle (chaque bloc de
    /// `main` retourne). Ce test empêche la seule dérive possible : une sous-commande ajoutée au
    /// dispatch et absente de l'aide (ou l'inverse), qui ferait mentir le message d'erreur.
    ///
    /// MESURÉ le 2026-08-02 sur le binaire release AVANT la garde : `plume-daemon --help` (et
    /// `--version`, et `help`, et toute faute de frappe) migrait la base, imprimait un jeton
    /// d'installation à usage unique, puis ÉCOUTAIT sur :7000 jusqu'à ce qu'on le tue.
    #[test]
    fn aide_cli_liste_les_memes_sous_commandes_que_le_dispatch() {
        let src = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"),
        )
        .expect("src/main.rs lisible");
        // Les sites RÉELS du dispatch : `args.get(1).map(String::as_str) == Some("<nom>")`.
        const MOTIF: &str = r#"args.get(1).map(String::as_str) == Some(""#;
        let mut dispatch: Vec<String> = Vec::new();
        for (i, _) in src.match_indices(MOTIF) {
            let reste = &src[i + MOTIF.len()..];
            if let Some(fin) = reste.find('"') {
                dispatch.push(reste[..fin].to_string());
            }
        }
        assert!(
            dispatch.len() > 10,
            "précondition : le scanner voit le dispatch ({} sites trouvés)",
            dispatch.len()
        );
        // L'aide = les sous-commandes inconditionnelles + celles qui dépendent d'une feature (elles
        // restent LISTÉES même quand le build ne les a pas — marquées indisponibles).
        let mut aide: Vec<String> = crate::SUBCOMMANDS
            .iter()
            .chain(crate::SUBCOMMANDS_COLD.iter())
            .map(|(n, _)| n.to_string())
            .collect();
        let mut d = dispatch.clone();
        d.sort();
        aide.sort();
        assert_eq!(
            d, aide,
            "l'aide `plume-daemon --help` et le dispatch de main() ont divergé"
        );
        // Chaque ligne d'aide COMMENCE par le nom de sa sous-commande (sinon l'aide est illisible).
        for (nom, ligne) in crate::SUBCOMMANDS.iter().chain(crate::SUBCOMMANDS_COLD.iter()) {
            assert!(ligne.starts_with(nom), "ligne d'aide de {nom} : {ligne}");
        }
        // Le texte d'usage dit les DEUX modes, sans quoi « argument inconnu » n'est pas actionnable.
        let u = crate::usage();
        assert!(u.contains("lance le serveur (aucun argument)"), "{u}");
        for (nom, _) in crate::SUBCOMMANDS.iter().chain(crate::SUBCOMMANDS_COLD.iter()) {
            assert!(u.contains(nom), "usage sans {nom}");
        }
    }

    /// UNE 500 EST TRAÇABLE, UNE 400 NE CHANGE PAS. Le client reçoit un identifiant court que le
    /// serveur a écrit dans son journal ; sans lui, un ticket « ça a planté » n'était rattachable à
    /// rien (mesuré le 2026-08-02 : 237 chemins rendent un 5xx, 0 ligne de journal, 0 corrélation,
    /// aucun TraceLayer monté).
    #[tokio::test]
    async fn une_erreur_serveur_porte_un_identifiant_de_correlation() {
        let json = |t: String| serde_json::from_str::<serde_json::Value>(&t).unwrap();
        let (c5, t5) = resp_bytes(crate::server_err("verrou base indisponible")).await;
        let v5 = json(t5);
        assert_eq!(c5, StatusCode::INTERNAL_SERVER_ERROR);
        let id = v5.get("id").and_then(|x| x.as_str()).unwrap_or("");
        assert!(id.starts_with("plume-e"), "un 5xx porte un id greppable : {v5}");
        assert_eq!(v5["error"], "verrou base indisponible", "le message d'origine est préservé");
        // Deux 500 ne partagent PAS le même identifiant (sinon la corrélation ne sert à rien).
        let (_, t5b) = resp_bytes(crate::server_err("verrou base indisponible")).await;
        assert_ne!(json(t5b)["id"], v5["id"]);
        // Un 4xx garde sa forme EXACTE d'avant : pas d'id, pas de trace serveur.
        let (c4, t4) = resp_bytes(crate::bad_req("paramètre absent")).await;
        let v4 = json(t4);
        assert_eq!(c4, StatusCode::BAD_REQUEST);
        assert!(v4.get("id").is_none(), "une faute du client n'est pas un incident serveur : {v4}");
        assert_eq!(v4["error"], "paramètre absent");
    }
