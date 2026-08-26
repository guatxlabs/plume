    // ============================================================================================
    // #55 OBSERVABILITY-AS-CODE — overlays config.d des OBJETS DE CONFIG (overlays_oac.rs).
    // ============================================================================================

    /// Un overlay de chaque type (dashboard/notifier/destination/index-policy/field-filter) CHARGE + est
    /// managed=1. Chemin RÉEL (load_overlays_dir -> load_oac_overlays_dir).
    #[test]
    fn oac_overlays_load_and_managed() {
        let conn = test_db();
        let dir = mk_overlay_dir("oac-load");
        write_overlay(&dir, "notifiers", "n.json", r#"{"name":"oac-ntfy","kind":"ntfy","url":"https://ntfy.example/topic","config":{}}"#);
        write_overlay(&dir, "destinations", "d.json", r#"{"name":"oac-dest","type":"webhook","endpoint":"https://93.184.216.34/in","config":{}}"#);
        write_overlay(&dir, "index-policies", "i.json", r#"{"name":"staging","retention_days":30}"#);
        write_overlay(&dir, "field-filters", "f.json", r#"{"name":"oac-mask-user","field":"user","action":"mask","role":"viewer"}"#);
        write_overlay(&dir, "library-panels", "lp.json", r#"{"name":"oac-lib","title":"T","query":"search severity>=3 | stats count","is_soql":true}"#);
        write_overlay(&dir, "dashboards", "db.json", r#"{"name":"oac-dash","panels":[{"title":"P1","query":"search severity>=3 | stats count by host","is_soql":true,"viz":"table"}]}"#);
        load_overlays_dir(&conn, &dir);
        let nm: i64 = conn.query_row("SELECT managed FROM notifier WHERE name='oac-ntfy'", [], |r| r.get(0)).unwrap();
        let dm: i64 = conn.query_row("SELECT managed FROM destination WHERE name='oac-dest'", [], |r| r.get(0)).unwrap();
        let im: i64 = conn.query_row("SELECT managed FROM index_policy WHERE name='staging'", [], |r| r.get(0)).unwrap();
        let fm: i64 = conn.query_row("SELECT managed FROM field_filter WHERE name='oac-mask-user'", [], |r| r.get(0)).unwrap();
        let lm: i64 = conn.query_row("SELECT managed FROM library_panel WHERE name='oac-lib'", [], |r| r.get(0)).unwrap();
        let (dbm, pcount): (i64, i64) = conn.query_row(
            "SELECT d.managed, (SELECT COUNT(*) FROM panel p WHERE p.dashboard_id=d.id AND p.managed=1) FROM dashboard d WHERE d.name='oac-dash'",
            [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((nm, dm, im, fm, lm, dbm), (1, 1, 1, 1, 1, 1), "chaque objet OAC est managed=1");
        assert_eq!(pcount, 1, "le panneau du dashboard managed est posé managed=1");
        // IDEMPOTENT : re-jouer -> pas de doublon (UPSERT keyé par name) et toujours 1 panneau.
        load_overlays_dir(&conn, &dir);
        let nc: i64 = conn.query_row("SELECT COUNT(*) FROM notifier WHERE name='oac-ntfy'", [], |r| r.get(0)).unwrap();
        let pc2: i64 = conn.query_row("SELECT COUNT(*) FROM panel p JOIN dashboard d ON p.dashboard_id=d.id WHERE d.name='oac-dash'", [], |r| r.get(0)).unwrap();
        assert_eq!((nc, pc2), (1, 1), "re-load idempotent (pas de doublon notifier ni panneau)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SECRET EN CLAIR dans un overlay -> l'objet est REJETÉ (fail-closed) : un notifier dont config.token est
    /// un secret littéral N'EST PAS chargé.
    #[test]
    fn oac_notifier_inline_secret_rejected() {
        let conn = test_db();
        let dir = mk_overlay_dir("oac-inline");
        write_overlay(&dir, "notifiers", "n.json", r#"{"name":"leaky","kind":"ntfy","url":"https://ntfy.example/t","config":{"token":"xoxb-SECRET-IN-GIT"}}"#);
        load_overlays_dir(&conn, &dir);
        let c: i64 = conn.query_row("SELECT COUNT(*) FROM notifier WHERE name='leaky'", [], |r| r.get(0)).unwrap();
        assert_eq!(c, 0, "un secret EN CLAIR dans un overlay -> objet REJETÉ, jamais persisté");
        // Idem pour un connecteur avec un champ 'secret' littéral top-level.
        write_overlay(&dir, "connectors", "c.json", r#"{"name":"leaky-conn","type":"defender","config":{"azure_tenant":"t","client_id":"c"},"secret":"PLAINTEXT"}"#);
        load_overlays_dir(&conn, &dir);
        let cc: i64 = conn.query_row("SELECT COUNT(*) FROM connector WHERE name='leaky-conn'", [], |r| r.get(0)).unwrap();
        assert_eq!(cc, 0, "connecteur avec 'secret' en clair -> REJETÉ (utiliser secret_ref)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Une RÉFÉRENCE de secret env: est RÉSOLUE au chargement -> le secret est écrit résolu, jamais la référence.
    #[test]
    fn oac_secret_ref_env_resolves() {
        let _env = VERROU_ENV_PROCESSUS.write(); // l'environnement du processus est MUTÉ ici : verrou UNIQUE en écriture (common.rs)
        let conn = test_db();
        let var = format!("PLUME_TEST_OAC_TOKEN_{}", std::process::id());
        std::env::set_var(&var, "resolved-secret-value");
        let dir = mk_overlay_dir("oac-ref");
        write_overlay(&dir, "connectors", "c.json", &format!(r#"{{"name":"oac-conn","type":"defender","config":{{"azure_tenant":"t","client_id":"c"}},"secret_ref":"env:{var}"}}"#));
        load_overlays_dir(&conn, &dir);
        let secret: String = conn.query_row("SELECT secret FROM connector WHERE name='oac-conn'", [], |r| r.get(0)).unwrap();
        assert_eq!(secret, "resolved-secret-value", "secret_ref env: résolu au chargement");
        // Une référence env absente -> objet rejeté (fail-closed), pas de ligne à secret vide trompeuse.
        write_overlay(&dir, "connectors", "c2.json", r#"{"name":"oac-conn-missing","type":"defender","config":{"azure_tenant":"t","client_id":"c"},"secret_ref":"env:PLUME_TEST_OAC_ABSENT_XYZ"}"#);
        load_overlays_dir(&conn, &dir);
        let cnt: i64 = conn.query_row("SELECT COUNT(*) FROM connector WHERE name='oac-conn-missing'", [], |r| r.get(0)).unwrap();
        assert_eq!(cnt, 0, "référence env absente -> objet rejeté");
        std::env::remove_var(&var);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// OVERRIDE-SAFE : un overlay NE clobber PAS un objet ad-hoc UI (managed=2) du même nom.
    #[test]
    fn oac_override_safe_skips_user_object() {
        let conn = test_db();
        // objet utilisateur (UI) : managed=2, config utilisateur.
        conn.execute("INSERT INTO notifier(name,kind,enabled,url,min_severity,config,managed) VALUES('shared-name','ntfy',1,'https://user.example/t',2,'{\"user\":\"me\"}',2)", []).unwrap();
        let dir = mk_overlay_dir("oac-safe");
        write_overlay(&dir, "notifiers", "n.json", r#"{"name":"shared-name","kind":"ntfy","url":"https://overlay.example/t","config":{}}"#);
        load_overlays_dir(&conn, &dir);
        let (url, managed): (String, i64) = conn.query_row("SELECT url,managed FROM notifier WHERE name='shared-name'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((url.as_str(), managed), ("https://user.example/t", 2), "l'objet UI (managed=2) n'est PAS clobbé par l'overlay");
        let c: i64 = conn.query_row("SELECT COUNT(*) FROM notifier WHERE name='shared-name'", [], |r| r.get(0)).unwrap();
        assert_eq!(c, 1, "pas de doublon créé");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// LIFECYCLE (#26) : retirer un overlay -> prune supprime l'objet managed=1 orphelin ; JAMAIS un managed=2.
    #[test]
    fn oac_prune_removes_orphans() {
        let conn = test_db();
        // un objet utilisateur (managed=2) DOIT survivre au prune.
        conn.execute("INSERT INTO destination(type,name,enabled,endpoint,config,filter,managed) VALUES('webhook','user-dest',0,'https://u.example/i','{}','{}',2)", []).unwrap();
        let dir = mk_overlay_dir("oac-prune");
        write_overlay(&dir, "destinations", "d.json", r#"{"name":"ov-dest","type":"webhook","endpoint":"https://93.184.216.34/in","config":{}}"#);
        load_overlays_dir(&conn, &dir);
        assert_eq!(1i64, conn.query_row("SELECT COUNT(*) FROM destination WHERE name='ov-dest' AND managed=1", [], |r| r.get::<_, i64>(0)).unwrap());
        // retire le fichier -> l'overlay devient orphelin.
        std::fs::remove_file(dir.join("destinations").join("d.json")).unwrap();
        let counts = prune_oac_orphans(&conn, &dir).unwrap();
        assert_eq!(counts.destination, 1, "1 destination overlay orpheline élaguée");
        assert_eq!(0i64, conn.query_row("SELECT COUNT(*) FROM destination WHERE name='ov-dest'", [], |r| r.get::<_, i64>(0)).unwrap(), "orphelin managed=1 supprimé");
        assert_eq!(1i64, conn.query_row("SELECT COUNT(*) FROM destination WHERE name='user-dest'", [], |r| r.get::<_, i64>(0)).unwrap(), "objet UI managed=2 préservé");
        // idempotent : re-prune = 0.
        let again = prune_oac_orphans(&conn, &dir).unwrap();
        assert_eq!(again.destination, 0, "re-prune idempotent");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// MODE 0 : aucun sous-dossier OAC -> AUCUNE ligne dans les tables d'objets de config (byte-identique).
    #[test]
    fn oac_mode0_no_overlays_identical() {
        let conn = test_db();
        let dir = mk_overlay_dir("oac-mode0");
        // seulement des overlays de détection (existants) — aucun sous-dossier OAC.
        write_overlay(&dir, "rules", "r.json", r#"{"name":"m0-rule","query":"search severity>=3 | stats count","is_soql":true,"mitre":"T1110"}"#);
        load_overlays_dir(&conn, &dir);
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM notifier WHERE managed=1", [], |r| r.get(0)).unwrap();
        let d: i64 = conn.query_row("SELECT COUNT(*) FROM destination WHERE managed=1", [], |r| r.get(0)).unwrap();
        let dash: i64 = conn.query_row("SELECT COUNT(*) FROM dashboard WHERE managed=1", [], |r| r.get(0)).unwrap();
        assert_eq!((n, d, dash), (0, 0, 0), "sans sous-dossier OAC -> aucun objet managed=1 (mode 0)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// VALIDATION : un objet invalide (type hors allowlist, endpoint invalide, action inconnue, requête qui ne
    /// compile pas) est REJETÉ, jamais inséré — et ne fait PAS paniquer le boot.
    #[test]
    fn oac_validation_rejects_bad_objects() {
        let conn = test_db();
        let dir = mk_overlay_dir("oac-bad");
        write_overlay(&dir, "destinations", "badtype.json", r#"{"name":"bad-type","type":"carrier-pigeon","endpoint":"https://x/y","config":{}}"#);
        write_overlay(&dir, "destinations", "badep.json", r#"{"name":"bad-ep","type":"webhook","endpoint":"ftp://nope","config":{}}"#);
        write_overlay(&dir, "field-filters", "badact.json", r#"{"name":"bad-act","field":"user","action":"teleport"}"#);
        write_overlay(&dir, "library-panels", "badq.json", r#"{"name":"bad-q","title":"T","query":"search x | stats nope(y)","is_soql":true}"#);
        write_overlay(&dir, "notification-policies", "badmatch.json", r#"{"name":"bad-match","matchers":{"not_a_field":"x"},"contact_points":[1]}"#);
        load_overlays_dir(&conn, &dir); // NE doit PAS paniquer
        for (tbl, name) in [("destination","bad-type"),("destination","bad-ep"),("field_filter","bad-act"),("library_panel","bad-q"),("notification_policy","bad-match")] {
            let c: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {tbl} WHERE name=?1"), params![name], |r| r.get(0)).unwrap();
            assert_eq!(c, 0, "{tbl}/{name} invalide -> rejeté");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #38 COMPLIANCE RULE-TAGS : une règle overlay peut porter un tag de conformité validé.
    #[test]
    fn oac_rule_compliance_tag_loads() {
        let conn = test_db();
        let dir = mk_overlay_dir("oac-compl");
        write_overlay(&dir, "rules", "r.json", r#"{"name":"compl-rule","query":"search severity>=3 | stats count","is_soql":true,"mitre":"T1110","compliance":"pci_dss:8.7"}"#);
        write_overlay(&dir, "rules", "bad.json", r#"{"name":"compl-bad","query":"search severity>=3 | stats count","is_soql":true,"mitre":"T1110","compliance":"not_a_framework"}"#);
        load_overlays_dir(&conn, &dir);
        let (compliance, managed): (String, i64) = conn.query_row("SELECT COALESCE(compliance,''),managed FROM rule WHERE name='compl-rule'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((compliance.as_str(), managed), ("pci_dss:8.7", 1), "tag compliance validé + posé, règle managed=1");
        let bad: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE name='compl-bad'", [], |r| r.get(0)).unwrap();
        assert_eq!(bad, 0, "un cadre de conformité hors vocabulaire -> règle rejetée");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// INVARIANT : les overlays config.d sont GXQL-ONLY. Une règle managed=1 en SQL brut
    /// (is_soql=false) est REFUSÉE au chargement (elle contournerait sinon le gate admin raw_sql_allowed +
    /// l'audit) ; une règle is_soql=true du même dossier CHARGE normalement (managed=1). Un event de refus
    /// (source=plume-config, kind=config.overlay.reject) est émis -> visible in-console, pas juste sur stdout.
    #[test]
    fn oac_overlay_rejects_raw_sql_rule() {
        let conn = test_db();
        let dir = mk_overlay_dir("oac-rawsql");
        // règle GXQL légitime -> charge. règle raw-SQL managed=1 -> refusée.
        write_overlay(&dir, "rules", "soql.json", r#"{"name":"ov-soql-ok","query":"search severity>=3 | stats count","is_soql":true,"mitre":"T1110"}"#);
        write_overlay(&dir, "rules", "raw.json", r#"{"name":"ov-rawsql-bad","query":"SELECT * FROM event WHERE severity>=3","is_soql":false,"mitre":"T1110"}"#);
        // playbook raw-SQL managed=1 -> refusé aussi (même frontière).
        write_overlay(&dir, "playbooks", "rawpb.json", r#"{"name":"ov-rawpb-bad","query":"SELECT src FROM event","is_soql":false,"action_kind":"notify"}"#);
        load_overlays_dir(&conn, &dir); // NE doit PAS paniquer
        let ok: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE name='ov-soql-ok' AND managed=1", [], |r| r.get(0)).unwrap();
        assert_eq!(ok, 1, "règle GXQL overlay CHARGE (managed=1)");
        let bad: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE name='ov-rawsql-bad'", [], |r| r.get(0)).unwrap();
        assert_eq!(bad, 0, "règle raw-SQL managed=1 REFUSÉE (GXQL-only)");
        let badpb: i64 = conn.query_row("SELECT COUNT(*) FROM playbook WHERE name='ov-rawpb-bad'", [], |r| r.get(0)).unwrap();
        assert_eq!(badpb, 0, "playbook raw-SQL managed=1 REFUSÉ (GXQL-only)");
        // event de refus émis (source=plume-config, kind config.overlay.reject) -> traçable in-console.
        let ev: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE source='plume-config' AND category='config' AND message LIKE '%refus%GXQL%'", [], |r| r.get(0)).unwrap();
        assert!(ev >= 2, "au moins 2 events de refus émis (règle + playbook raw-SQL) — visibles in-console");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- SLICE #7 PIÈCE 2 : PARSEUR DÉCLARATIF (DSL CIM) -----------------------------------------------
    // Registre DPARSERS global keyé par db_path -> chaque test utilise une clé db_path UNIQUE pour éviter
    // toute contamination croisée (les tests parallèles qui ingèrent sous ":memory:"/":memory:test" ne voient
    // AUCUN dparser -> restent byte-identiques). Un dparser est posé dans la table `dparser` puis compilé au
    // registre par dparsers_reload(db_path) (= chemin de prod : table -> registre compilé).

    /// BOUT-EN-BOUT : un log de firewall GÉNÉRIQUE (key=value) -> catégorie `firewall` + src_ip/dst_ip promus
    /// en COLONNES + action/proto en fields. Charge via load_overlays_dir (chemin overlay réel), reload, ingère.
    #[test]
    fn dparser_maps_firewall_line_to_cim() {
        let conn = test_db();
        let dpath = ":memory:dparser-fw-e2e";
        let dir = mk_overlay_dir("dpar-fw");
        write_overlay(&dir, "parsers", "fw.json", r#"{
          "name":"fw-generic-e2e","source":"firewall","enabled":true,
          "match":"action=",
          "extract":[{"kv":true}],
          "map":{"category":"firewall","severity":2,"action":"$action","src_ip":"$src","dst_ip":"$dst","fields":{"proto":"$proto"}}
        }"#);
        load_overlays_dir(&conn, &dir);
        // (a) chargé comme parseur DÉCLARATIF (managed=1), PAS dans la table `parser` legacy (discriminant `map`).
        let m: i64 = conn.query_row("SELECT managed FROM dparser WHERE name='fw-generic-e2e'", [], |r| r.get(0)).unwrap();
        assert_eq!(m, 1, "chargé comme parseur déclaratif managed=1");
        let leg: i64 = conn.query_row("SELECT COUNT(*) FROM parser WHERE name='fw-generic-e2e'", [], |r| r.get(0)).unwrap();
        assert_eq!(leg, 0, "PAS inséré dans la table parser legacy");
        dparsers_reload(&conn, dpath);
        // (b) event brut : source=firewall, category vide -> le dparser le mappe.
        let events = vec![json!({
            "ts": 1000, "source": "firewall", "category": "", "severity": 0,
            "message": "action=deny proto=tcp src=203.0.113.7 dst=198.51.100.2 dport=22", "dedup": "fw1"
        })];
        assert_eq!(ingest_events_batch(&conn, dpath, &events, 1000, None, None).expect("batch"), 1);
        let (cat, sev, src, dst): (String, i64, String, Option<String>) = conn.query_row(
            &format!("SELECT category, severity, src_ip, dst_ip FROM event WHERE dedup='{}'", ddk(None, "fw1")), [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?))).unwrap();
        assert_eq!(cat, "firewall", "category mappée depuis le map littéral");
        assert_eq!(sev, 2, "severity mappée");
        assert_eq!(src, "203.0.113.7", "src_ip mappé (fields.src_ip) PROMU en colonne");
        assert_eq!(dst.as_deref(), Some("198.51.100.2"), "dst_ip mappé PROMU en colonne");
        let fv: Value = serde_json::from_str(&conn.query_row::<String, _, _>(&format!("SELECT fields FROM event WHERE dedup='{}'", ddk(None, "fw1")), [], |r| r.get(0)).unwrap()).unwrap();
        assert_eq!(fv["action"], "deny", "action (vendeur) -> fields.action (outcome CIM)");
        assert_eq!(fv["proto"], "tcp", "proto -> fields.proto");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// EXTRACTION REGEX + RENAME vendeur->CIM + capture ABSENTE = AUCUNE écriture (jamais un champ vide/drop).
    #[test]
    fn dparser_regex_rename_and_missing_capture_no_write() {
        let conn = test_db();
        let dpath = ":memory:dparser-rx";
        conn.execute(
            "INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('waf','waflog',?1,1,0,1,0)",
            params![r#"{"name":"waf","source":"waflog","extract":[{"regex":"client=(?P<srcip>\\S+)(?: backend=(?P<dstip>\\S+))?"}],"map":{"category":"web","src_ip":"$srcip","dst_ip":"$dstip"}}"#],
        ).unwrap();
        dparsers_reload(&conn, dpath);
        let (fields, cat, sev) = dparsers_apply(dpath, "waflog", "client=203.0.113.9 blocked", None);
        assert_eq!(cat.as_deref(), Some("web"), "category littérale mappée");
        assert!(sev.is_none(), "aucune severity mappée -> pas d'override");
        let fv: Value = serde_json::from_str(fields.as_deref().unwrap()).unwrap();
        assert_eq!(fv["src_ip"], "203.0.113.9", "srcip (vendeur) RENOMMÉ src_ip (CIM)");
        assert!(fv.get("dst_ip").is_none(), "backend absent -> capture dstip vide -> AUCUNE écriture dst_ip");
    }

    /// VALIDÉ-OU-IGNORÉ : specs invalides (regex/match cassés, map vide) SKIPPÉES sans crash ; la bonne charge.
    #[test]
    fn dparser_bad_spec_ignored_not_fatal() {
        let conn = test_db();
        let dpath = ":memory:dparser-bad";
        let dir = mk_overlay_dir("dpar-bad");
        write_overlay(&dir, "parsers", "badrx.json",    r#"{"name":"dbad-rx","source":"x","extract":[{"regex":"(?P<a>"}],"map":{"category":"web"}}"#);
        write_overlay(&dir, "parsers", "empty.json",    r#"{"name":"dbad-empty","source":"x","map":{}}"#);
        write_overlay(&dir, "parsers", "badmatch.json", r#"{"name":"dbad-match","source":"x","match":"(","map":{"category":"web"}}"#);
        write_overlay(&dir, "parsers", "badstep.json",  r#"{"name":"dbad-step","source":"x","extract":[{"nope":true}],"map":{"category":"web"}}"#);
        write_overlay(&dir, "parsers", "good.json",     r#"{"name":"dgood","source":"x","match":"go","map":{"category":"firewall","action":"blocked"}}"#);
        load_overlays_dir(&conn, &dir); // NE doit PAS paniquer
        let good: i64 = conn.query_row("SELECT COUNT(*) FROM dparser WHERE name='dgood'", [], |r| r.get(0)).unwrap();
        assert_eq!(good, 1, "le dparser valide est chargé");
        let bad: i64 = conn.query_row("SELECT COUNT(*) FROM dparser WHERE name LIKE 'dbad-%'", [], |r| r.get(0)).unwrap();
        assert_eq!(bad, 0, "les 4 specs invalides sont skippées (validé-ou-ignoré)");
        // l'ingest reste fonctionnel : le bon dparser mappe la category.
        dparsers_reload(&conn, dpath);
        ingest_events_batch(&conn, dpath, &[json!({"ts":1,"source":"x","category":"","message":"go now","dedup":"g1"})], 1, None, None).unwrap();
        assert_eq!(conn.query_row::<String, _, _>(&format!("SELECT category FROM event WHERE dedup='{}'", ddk(None, "g1")), [], |r| r.get(0)).unwrap(), "firewall");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// MODE 0 : registre vide pour ce db_path -> dparsers_apply est un NO-OP strict (byte-identique).
    #[test]
    fn dparser_absent_is_byte_identical() {
        let (f, c, s) = dparsers_apply(":memory:dparser-absent", "firewall", "action=deny src=203.0.113.4", Some(r#"{"k":"v"}"#.to_string()));
        assert_eq!(f.as_deref(), Some(r#"{"k":"v"}"#), "fields Some inchangés à l'octet");
        assert!(c.is_none() && s.is_none(), "aucun override category/severity");
        let (f2, c2, s2) = dparsers_apply(":memory:dparser-absent", "firewall", "x", None);
        assert!(f2.is_none() && c2.is_none() && s2.is_none(), "None fields -> None (byte-identique)");
    }

    /// ENRICH sans écrasement : une clé déjà posée par le COLLECTEUR gagne (le dparser n'écrase jamais).
    #[test]
    fn dparser_does_not_overwrite_collector_fields() {
        let conn = test_db();
        let dpath = ":memory:dparser-nowrite";
        conn.execute(
            "INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('nw','ap',?1,1,0,1,0)",
            params![r#"{"name":"nw","source":"ap","map":{"action":"blocked","fields":{"tag":"x"}}}"#],
        ).unwrap();
        dparsers_reload(&conn, dpath);
        let (fields, _, _) = dparsers_apply(dpath, "ap", "msg", Some(r#"{"action":"allowed"}"#.to_string()));
        let fv: Value = serde_json::from_str(fields.as_deref().unwrap()).unwrap();
        assert_eq!(fv["action"], "allowed", "collecteur prioritaire : action NON écrasée");
        assert_eq!(fv["tag"], "x", "champ nouveau ajouté par le dparser");
    }

    /// L'EXEMPLE LIVRÉ (config.d) est un dparser valide : chargé managed=1, absent de `parser`, et COMPILE.
    #[test]
    fn shipped_config_d_dparser_example_loads() {
        let conn = test_db();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config.d");
        load_overlays_dir(&conn, &root);
        let (source, managed): (String, i64) = conn.query_row(
            "SELECT source, managed FROM dparser WHERE name='firewall générique (key=value) → CIM'", [],
            |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((source.as_str(), managed), ("firewall", 1), "exemple déclaratif : source=firewall managed=1");
        let leg: i64 = conn.query_row("SELECT COUNT(*) FROM parser WHERE name='firewall générique (key=value) → CIM'", [], |r| r.get(0)).unwrap();
        assert_eq!(leg, 0, "l'exemple déclaratif n'est PAS dans la table parser legacy");
        // il compile et mappe réellement.
        dparsers_reload(&conn, ":memory:dparser-shipped");
        let (fields, cat, sev) = dparsers_apply(":memory:dparser-shipped", "firewall",
            "devname=edge action=deny proto=tcp src=203.0.113.7 dst=198.51.100.2 dport=22 url=/x", None);
        assert_eq!(cat.as_deref(), Some("firewall"));
        assert_eq!(sev, Some(2));
        let fv: Value = serde_json::from_str(fields.as_deref().unwrap()).unwrap();
        assert_eq!(fv["src_ip"], "203.0.113.7");
        assert_eq!(fv["dst_ip"], "198.51.100.2");
        assert_eq!(fv["action"], "deny");
        assert_eq!(fv["proto"], "tcp");
        assert_eq!(fv["vendor"], "edge");
    }

    // ============================================================================================
    // #38 — MAPPING DE CONFORMITÉ : tags de cadre par règle + rollup posture + dashboards + mode 0.
    // ============================================================================================

    /// v88 est ADDITIVE : la colonne `rule.compliance` existe après migrate, à NULL pour l'existant.
    #[test]
    fn compliance_migration_v88_additive() {
        let conn = test_db();
        let ver: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(ver, CODE_SCHEMA_MAX.to_string(), "schema à la tête après migrate");
        let has_col: bool = conn.prepare("SELECT compliance FROM rule LIMIT 0").is_ok();
        assert!(has_col, "colonne rule.compliance présente (v88)");
    }

    /// VOCAB + NORMALISATION : cadre ∈ vocab requis (fail-closed), contrôle libre charset-borné, dédup/canonique.
    #[test]
    fn compliance_norm_and_vocab() {
        // cadres canoniques connus.
        for fw in ["pci_dss", "hipaa", "nist_800_53", "gdpr", "tsc", "iso_27001", "cis"] {
            assert!(compliance_framework_known(fw), "cadre connu: {fw}");
        }
        assert!(!compliance_framework_known("nope"));
        // `compliance_framework_known` NORMALISE la casse (le socle core `compliance_framework_ok` est strict).
        assert!(compliance_framework_known("PCI_DSS"), "known normalise la casse -> connu");
        assert!(!guatx_core::cim::compliance_framework_ok("PCI_DSS"), "le socle core est strict (casse rejetée)");
        // vide -> Some("") (non tagué, licite).
        assert_eq!(norm_compliance("  "), Some(String::new()));
        // valide : normalise casse du cadre, garde le contrôle, dédup.
        assert_eq!(norm_compliance("PCI_DSS:8.7, hipaa:164.312 , pci_dss:8.7"), Some("pci_dss:8.7,hipaa:164.312".into()));
        // cadre seul autorisé.
        assert_eq!(norm_compliance("gdpr"), Some("gdpr".into()));
        // cadre HORS vocab -> rejet (None), fail-closed.
        assert_eq!(norm_compliance("pci_dss:8.7,bogusframework:1"), None);
        // contrôle avec charset hostile (injection) -> rejet global (None).
        assert_eq!(norm_compliance("pci_dss:8.7'; DROP TABLE rule;--"), None);
        // paires : split multi-contrôle sur '/'.
        assert_eq!(compliance_pairs("pci_dss:1.1/1.2,cis"), vec![
            ("pci_dss".to_string(), "1.1".to_string()),
            ("pci_dss".to_string(), "1.2".to_string()),
            ("cis".to_string(), String::new()),
        ]);
    }

    /// La règle PORTE et RESTITUE ses tags de conformité (colonne + SELECT de rules_list). Une règle NON taguée
    /// -> compliance vide (mode 0 : champ additif, aucun autre changement).
    #[test]
    fn compliance_rule_carries_and_returns() {
        let conn = test_db();
        let tagged = norm_compliance("pci_dss:8.7,hipaa:164.312").unwrap();
        conn.execute("INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,compliance,managed) VALUES('tag',1,'search severity>=3 | stats count',1,'>',0,2,300,3600,'T1110',?1,2)", params![tagged]).unwrap();
        conn.execute("INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed) VALUES('untagged',1,'search severity>=3 | stats count',1,'>',0,2,300,3600,'',2)", []).unwrap();
        // exact SELECT de rules_list.
        let mut st = conn.prepare("SELECT name,COALESCE(compliance,'') FROM rule ORDER BY id").unwrap();
        let rows: std::collections::HashMap<String, String> = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).unwrap().flatten().collect();
        assert_eq!(rows.get("tag").map(|s| s.as_str()), Some("pci_dss:8.7,hipaa:164.312"), "la règle restitue ses tags");
        assert_eq!(rows.get("untagged").map(|s| s.as_str()), Some(""), "règle non taguée -> vide (mode 0)");
        // MODE 0 : la sélection de run_due_rules (dues) ne dépend PAS de compliance -> les 2 règles sont dues.
        let due: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE enabled=1 AND COALESCE(risk_score,0)=0 AND (last_run IS NULL OR 9999999999 - last_run >= interval_s)", [], |r| r.get(0)).unwrap();
        assert_eq!(due, 2, "compliance n'affecte pas la sélection d'ordonnancement (mode 0)");
    }

    /// IMPORT SIGMA : les tags de cadre du doc sont mappés en `compliance` normalisé ; aucun tag de cadre -> "".
    #[test]
    fn compliance_sigma_import_maps_tags() {
        let doc = json!({
            "title": "sca-rule", "logsource": {"category":"webserver"},
            "detection": { "selection": { "status": 500 }, "condition": "selection" },
            "tags": ["attack.t1059", "pci_dss.8.7", "hipaa.164.312", "cve.2021.1"]
        });
        let t = sigma_translate(&doc).expect("traduit");
        assert_eq!(t.compliance, "pci_dss:8.7,hipaa:164.312", "cadres mappés, attack/cve ignorés ; got={}", t.compliance);
        // alias : `pci`, `nist`, `iso` -> ids canoniques.
        assert_eq!(sigma_compliance_tags(Some(&json!(["pci.3.4", "nist.au-2", "iso.a.12"]))), "pci_dss:3.4,nist_800_53:au-2,iso_27001:a.12");
        // aucun tag de cadre.
        let doc2 = json!({ "title": "no-comp", "logsource": {"category":"webserver"}, "detection": { "selection": { "status": 500 }, "condition": "selection" }, "tags": ["attack.t1190"] });
        assert_eq!(sigma_translate(&doc2).unwrap().compliance, "", "aucun cadre -> vide");
    }

    /// ROLLUP POSTURE : la posture SCA ingérée (Wazuh) est comptée pass/fail PAR (cadre, contrôle) via le MÊME
    /// GXQL que le rollup/handler, puis agrégée. Prouve la couture posture ingérée -> compteurs de conformité.
    #[test]
    fn compliance_posture_rollup_counts() {
        let conn = test_db();
        let dbp = ":memory:comp-rollup";
        let mk = |ctrl: &str, res: &str| json!({"agent":{"name":"h1"},"data":{"sca":{"type":"check","policy":"CIS","check":{"id":ctrl,"title":"t","result":res,"compliance":[{"pci_dss":["8.7"]},{"hipaa":["164.312"]}]}}}});
        ingest_wazuh(&conn, dbp, "c1", mk("1", "failed"));
        ingest_wazuh(&conn, dbp, "c2", mk("2", "failed"));
        ingest_wazuh(&conn, dbp, "c3", mk("3", "passed"));
        // MÊME GXQL que le handler/rollup, compilé par le cœur (masque VIDE = non masqué).
        let sql = soql_to_sql_x(&compliance_posture_soql(), 0, 0, None).unwrap();
        let mut st = conn.prepare(&sql).unwrap();
        let rows: Vec<(String, String, String)> = st.query_map([], |r| Ok((
            r.get::<_, Option<String>>(0)?.unwrap_or_default(),
            r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            r.get::<_, Option<String>>(2)?.unwrap_or_default(),
        ))).unwrap().flatten().collect();
        // filtré PCI DSS.
        let agg = posture_aggregate(rows.clone(), Some("pci_dss"));
        let pci_total: (i64, i64) = agg.values().fold((0, 0), |(p, f), c| (p + c.pass, f + c.fail));
        assert_eq!(pci_total, (1, 2), "PCI DSS : 1 pass / 2 fail ; agg={agg:?}");
        // HIPAA aussi présent (chaque contrôle porte les 2 cadres).
        let agg_h = posture_aggregate(rows, Some("hipaa"));
        let h_total: (i64, i64) = agg_h.values().fold((0, 0), |(p, f), c| (p + c.pass, f + c.fail));
        assert_eq!(h_total, (1, 2), "HIPAA : 1 pass / 2 fail");
    }

    /// SEEDS : 3 dashboards de conformité (PCI/HIPAA/NIST), idempotents, filtrant chacun leur cadre, dans la vue
    /// « Conformité (posture) ». Additif -> mode 0 (VIDES tant qu'aucune posture ingérée).
    #[test]
    fn compliance_seed_dashboards() {
        let conn = test_db();
        seed_compliance_dashboards(&conn);
        seed_compliance_dashboards(&conn); // idempotent
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM dashboard WHERE name LIKE 'Conformité — %'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 3, "3 dashboards de conformité (PCI/HIPAA/NIST)");
        let pci: i64 = conn.query_row("SELECT COUNT(*) FROM panel p JOIN dashboard d ON p.dashboard_id=d.id WHERE d.name='Conformité — PCI DSS' AND p.query LIKE '%posture_framework=*pci_dss*%'", [], |r| r.get(0)).unwrap();
        assert_eq!(pci, 4, "4 panneaux PCI DSS filtrant le cadre pci_dss");
        let v: i64 = conn.query_row("SELECT COUNT(*) FROM view WHERE name='Conformité (posture)'", [], |r| r.get(0)).unwrap();
        assert_eq!(v, 1, "vue Conformité (posture) créée une fois");
        // CHAQUE requête de panneau (dont le filtre wildcard `posture_framework=*<fw>*`) COMPILE via le cœur
        // GXQL (injection-safe) -> pas de panneau mort. 12 panneaux (3 cadres × 4).
        let mut st = conn.prepare("SELECT p.query FROM panel p JOIN dashboard d ON p.dashboard_id=d.id WHERE d.name LIKE 'Conformité — %'").unwrap();
        let queries: Vec<String> = st.query_map([], |r| r.get::<_, String>(0)).unwrap().flatten().collect();
        assert_eq!(queries.len(), 12, "12 panneaux de conformité (3 cadres × 4)");
        for q in &queries {
            assert!(soql_to_sql_x(q, 0, 0, None).is_ok(), "panneau de conformité doit compiler : {q}");
        }
    }

    /// SÉCURITÉ — une valeur Sigma HOSTILE (quotes/pipe/SQL) est NEUTRALISÉE : hex-échappée dans le
    /// motif regex, donc INVISIBLE au découpage GXQL (aucune étape de pipeline injectée) et le GXQL
    /// compile. Pas d'interpolation « à cru ».
    #[test]
    fn sigma_injection_is_neutralized() {
        let doc = json!({
            "title": "hostile", "logsource": {"category":"webserver"},
            "detection": { "selection": { "CommandLine|contains": "x' OR 1=1 | drop \"z\"" }, "condition": "selection" }
        });
        let t = sigma_translate(&doc).expect("doit traduire (valeur neutralisée, pas rejetée)");
        // Un SEUL `|` littéral subsiste : celui du pipeline `| stats count`. Le `|` injecté est encodé \x7c.
        assert_eq!(t.query.matches('|').count(), 1, "aucun pipe injecté : {}", t.query);
        assert_eq!(soql_split_pipes_count(&t.query), 2, "exactement 2 étapes (search + stats)");
        // caractères hostiles neutralisés en hex.
        assert!(t.query.contains("\\x7c"), "| encodé \\x7c");
        assert!(t.query.contains("\\x27"), "' encodé \\x27");
        assert!(t.query.contains("\\x22"), "\" encodé \\x22");
        assert!(t.query.contains("\\x20"), "espace encodé \\x20");
        // et ça compile via le compilo GXQL du cœur (chemin injection-safe).
        assert!(rule_sql(&t.query, true, t.window_s).is_ok());
    }

    // helper local : nombre d'étapes GXQL (pipes de 1er niveau).
    fn soql_split_pipes_count(q: &str) -> usize {
        guatx_core::soql::soql_split_pipes(q).len()
    }

    /// BOUT-EN-BOUT : règle Sigma importée -> DÉCLENCHE sur un event matchant, PAS sur un non-matchant.
    /// (DB fichier : l'éval `run_due_rules` ouvre une connexion de lecture sur le chemin disque.)
    #[test]
    fn sigma_imported_rule_fires_on_matching_event() {
        // DB fichier temporaire.
        let _tmpg1 = crate::tmp_possede::TmpPossede::neuf("sigma-e2e");
        let path = _tmpg1.sous("plume.db").chemin().to_path_buf();
        let p = path.to_string_lossy().to_string();
        let ts = now();
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            // event MATCHANT (fields.CommandLine contient whoami) + event NON matchant (dir).
            // F7 — `category` = `exec`, la catégorie que le chemin 4688 des collecteurs Windows LIVRÉS émet
            // réellement (`process_creation` -> `exec`, cf. la doc de `SIGMA_LOGSOURCE_CATEGORY`). La fixture
            // suppose `fields.CommandLine` PEUPLÉ : dans un 4688 cela exige la GPO « Include command line in
            // process creation events » (sinon le champ est absent). Le cas 4688 par DÉFAUT (sans GPO, donc
            // sans CommandLine) est prouvé par `sigma_process_creation_rule_fires_on_real_4688_event`.
            w.execute("INSERT INTO event(ts,source,category,severity,message,fields,dedup) VALUES(?1,'WinEventLog:Security','exec',1,'proc','{\"CommandLine\":\"cmd /c whoami /priv\"}','ev-match')", params![ts]).unwrap();
            w.execute("INSERT INTO event(ts,source,category,severity,message,fields,dedup) VALUES(?1,'WinEventLog:Security','exec',1,'proc','{\"CommandLine\":\"cmd /c dir\"}','ev-nomatch')", params![ts]).unwrap();
            // traduit + insère la règle Sigma.
            let t = sigma_translate(&json!({
                "title": "e2e whoami", "logsource": {"category":"process_creation"},
                "detection": { "selection": { "CommandLine|contains": "whoami" }, "condition": "selection" },
                "level": "high", "tags": ["attack.t1033"]
            })).unwrap();
            w.execute("INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed) VALUES(?1,1,?2,1,?3,?4,?5,?6,?7,?8,2)",
                params![t.name, t.query, t.op, t.threshold, t.severity, t.interval_s, t.window_s, t.mitre]).unwrap();
            // SPÉCIFICITÉ : la requête compte EXACTEMENT 1 (le whoami), pas 2 (le regex ne matche pas 'dir').
            let sql = rule_sql(&t.query, true, t.window_s).unwrap();
            assert_eq!(eval_value(&p, &sql), Some(1.0), "compte le seul event matchant (spécificité du regex)");
        }
        // exécute les règles dues.
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_due_rules(&db, &p);
        // une alerte est ouverte, avec la sévérité et le MITRE hérités de la règle.
        let (n, sev, mitre): (i64, i64, String) = {
            let c = db.lock();
            c.query_row("SELECT COUNT(*), COALESCE(MAX(severity),0), COALESCE(MAX(mitre),'') FROM alert", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap()
        };
        assert_eq!(n, 1, "une alerte déclenchée par la règle Sigma importée");
        assert_eq!(sev, 3, "sévérité high (3) héritée");
        assert_eq!(mitre, "T1033", "MITRE hérité par l'alerte (mesure de couverture)");
        let _ = std::fs::remove_file(&p);
    }

    /// FRONT-END YAML : un vrai texte Sigma (YAML) est parsé puis traduit (le cœur opère sur Value).
    #[test]
    fn sigma_yaml_frontend_parses_and_translates() {
        let yaml = "\
title: SSH auth failure
logsource:
    service: sshd
detection:
    selection:
        action: failure
    condition: selection
level: medium
tags:
    - attack.t1110
";
        let docs = sigma_yaml_to_docs(yaml).expect("YAML valide");
        assert_eq!(docs.len(), 1);
        let t = sigma_translate(&docs[0]).unwrap();
        assert_eq!(t.query, "search category=auth action=~(?i)^failure$ | stats count");
        assert_eq!(t.severity, 2);
        assert_eq!(t.mitre, "T1110");
    }

    /// VALIDÉ-OU-IGNORÉ : un dossier Sigma mêlant docs valides et invalides -> seuls les valides sont
    /// importés (managed=1), aucun crash, la règle valide COMPILE et est bien en base.
    #[test]
    fn sigma_overlay_loads_valid_skips_invalid() {
        let conn = test_db();
        let dir = mk_overlay_dir("sigma-mix");
        write_overlay(&dir, "sigma", "good.yml", "\
title: overlay ssh brute
logsource:
    service: sshd
detection:
    selection:
        action: failure
    condition: selection
level: medium
tags: [attack.t1110]
");
        // invalide : condition en OU -> flaggée -> skip (pas de crash).
        write_overlay(&dir, "sigma", "bad-or.yml", "\
title: overlay bad or
logsource:
    category: firewall
detection:
    a: {action: deny}
    b: {action: allow}
    condition: a or b
");
        load_overlays_dir(&conn, &dir); // NE doit PAS paniquer
        let ok: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE name='overlay ssh brute' AND managed=1", [], |r| r.get(0)).unwrap();
        assert_eq!(ok, 1, "la règle Sigma valide est importée managed=1");
        let bad: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE name='overlay bad or'", [], |r| r.get(0)).unwrap();
        assert_eq!(bad, 0, "la règle Sigma invalide (OU) est ignorée");
        let q: String = conn.query_row("SELECT query FROM rule WHERE name='overlay ssh brute'", [], |r| r.get(0)).unwrap();
        assert!(rule_sql(&q, true, 3600).is_ok(), "la règle importée COMPILE");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Les EXEMPLES LIVRÉS (config.d/sigma/*.yml) sont tous des règles Sigma valides : chargées managed=1.
    #[test]
    fn shipped_config_d_sigma_examples_load() {
        let conn = test_db();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config.d");
        load_overlays_dir(&conn, &root);
        for name in ["Firewall Denied Connection to Non-Standard Port", "Blocked Web Access to Admin Path", "Whoami Command Execution (Discovery)"] {
            let (m, q): (i64, String) = conn.query_row("SELECT managed, query FROM rule WHERE name=?1", params![name], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap_or_else(|_| panic!("exemple Sigma '{name}' non chargé"));
            assert_eq!(m, 1, "exemple Sigma '{name}' managed=1");
            assert!(rule_sql(&q, true, 3600).is_ok(), "exemple Sigma '{name}' compile");
        }
    }

    // =============================================================================================
    // CHANTIER « whitelists → webui » — registre unique + panneau RO + édition display-only auditée.
    // =============================================================================================

    /// (1) PUR REFACTOR : le registre / la voie `resolve` produisent des clauses BYTE-IDENTIQUES au builder
    /// canonique et à `from_config` (aucune constante magique divergente n'a été introduite).
    #[test]
    fn suppr_registry_exclusions_are_byte_identical() {
        let conn = test_db();
        let conf: HashMap<String, String> = HashMap::new(); // env vide -> défauts génériques
        // (a) sans override setting : resolve == from_config, champ par champ (byte-identique).
        let r = ExclClauses::resolve(&conn, &conf);
        let f = ExclClauses::from_config(&conf);
        assert_eq!(r.op_sql, f.op_sql, "op_sql byte-identique (pur refactor)");
        assert_eq!(r.op_soql, f.op_soql);
        assert_eq!(r.self_sql, f.self_sql);
        assert_eq!(r.self_soql, f.self_soql);
        // (b) le registre DÉCLARE la MÊME clause SQL/soql que le builder canonique (source de vérité unique).
        let reg = daemon_excl_registry(&conn, &conf);
        let op = reg.iter().find(|e| e.name == "operator_excl").unwrap();
        assert_eq!(op.detail["sql"], json!(f.op_sql), "detail.sql = clause runtime");
        assert_eq!(op.detail["soql"], json!(f.op_soql));
        // (c) A3/A6 déclarent EXACTEMENT les constantes runtime (rien caché, rien divergent).
        assert_eq!(reg.iter().find(|e| e.name == "sources_attendues_par_construction").unwrap().value, sources_attendues_sans_base().join(","));
        assert_eq!(reg.iter().find(|e| e.name == "hot_fields").unwrap().value, HOT_FIELDS.join(","));
        // (d) après un override setting, le registre reflète la nouvelle valeur ET reste byte-identique au builder.
        conn.execute("INSERT INTO setting(scope,key,value,updated,updated_by) VALUES('global',?1,'198.51.100.4',0,'t')", params![EXCL_OP_SETTING]).unwrap();
        let reg2 = daemon_excl_registry(&conn, &conf);
        let op2 = reg2.iter().find(|e| e.name == "operator_excl").unwrap();
        assert_eq!(op2.value, "198.51.100.4", "le registre reflète l'override setting");
        let (canon_sql, _) = ExclClauses::build("src_ip", "198.51.100.4");
        assert_eq!(op2.detail["sql"], json!(canon_sql), "override -> clause byte-identique au builder");
    }

    /// (2) PANNEAU : le registre liste les TROIS types (display-only/collection-reducing/host) — aucun angle
    /// mort de taxonomie — et SEULES les 2 exclusions display-only operator/self sont `editable`.
    #[test]
    fn suppr_registry_lists_all_types_only_operator_self_editable() {
        let conn = test_db();
        let conf: HashMap<String, String> = HashMap::new();
        let reg = daemon_excl_registry(&conn, &conf);
        let types: std::collections::HashSet<&str> = reg.iter().map(|e| e.etype.as_str()).collect();
        assert!(types.contains("display-only"), "type display-only présent");
        assert!(types.contains("collection-reducing"), "type collection-reducing présent (rétention)");
        assert!(types.contains("host"), "type host présent (never-ban)");
        // éditable => display-only ET operator/self uniquement (surfacer ≠ piloter).
        for e in &reg {
            if e.editable {
                assert_eq!(e.etype.as_str(), "display-only", "seul display-only peut être éditable : {}", e.name);
                assert!(e.name == "operator_excl" || e.name == "self_excl", "seuls operator/self éditables : {}", e.name);
            }
        }
        let editable: Vec<&str> = reg.iter().filter(|e| e.editable).map(|e| e.name).collect();
        assert_eq!(editable, vec!["operator_excl", "self_excl"], "exactement 2 exclusions éditables");
        // collection-reducing (rétention) + host (never-ban) sont READ-ONLY.
        assert!(!reg.iter().find(|e| e.name == "retention_floors").unwrap().editable, "rétention read-only");
        assert!(!reg.iter().find(|e| e.name == "protected_ip_matchers").unwrap().editable, "never-ban read-only");
        // chaque entrée porte la garantie explicite « collecte/règles NON modifiées ».
        for e in &reg {
            assert_eq!(e.to_json()["guarantee"], json!("collecte/règles NON modifiées"), "garantie sur {}", e.name);
        }
    }

    /// (3) ÉDITION display-only AUDITÉE + reste display-only : l'édition operator/self écrit le setting, audite
    /// (ledger + event plume-config sev 3 origin=daemon), SUBSTITUE dans compile_panel_sql (affichage) mais
    /// JAMAIS dans rule_sql (détection) — donc ne peut créer AUCUN angle mort — ni dans never-ban (HOST, §4).
    #[test]
    fn suppr_editing_operator_excl_audited_and_stays_display_only() {
        let conn = test_db();
        let conf: HashMap<String, String> = HashMap::new();
        // état initial : aucun override -> no-op (byte-identique au défaut générique).
        assert_eq!(ExclClauses::resolve(&conn, &conf).op_sql, "1=1");
        let led0: i64 = conn.query_row("SELECT COUNT(*) FROM ledger", [], |r| r.get(0)).unwrap();
        // ÉDITE via le vrai cœur testable du handler (mêmes statements).
        let (field, old, new) = apply_display_excl_edit(&conn, &conf, "set_operator_excl", "203.0.113.7,2001:db8::/32", "admin").unwrap();
        assert_eq!(field, "operator");
        assert_eq!(old, "");
        assert_eq!(new, "203.0.113.7,2001:db8::/32");
        // AUDIT : ledger append-only a grandi + event plume-config category=config sev 3 origin=daemon (non-forgeable).
        let led1: i64 = conn.query_row("SELECT COUNT(*) FROM ledger", [], |r| r.get(0)).unwrap();
        assert!(led1 > led0, "édition auditée : le ledger a grandi");
        let (sev, org, cat): (i64, String, String) = conn.query_row(
            "SELECT severity, origin, category FROM event WHERE source='plume-config' AND message LIKE '%operator%display-only%' ORDER BY id DESC LIMIT 1",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!(sev, 3, "de-bruitage d'affichage audité sev 3 (B8-like)");
        assert_eq!(org, "daemon", "audit non-forgeable (origin=daemon, non purgeable)");
        assert_eq!(cat, "config", "event SOC-visible category=config");
        // DISPLAY-ONLY : la valeur éditée = clause byte-identique au builder canonique.
        let (canon_sql, canon_soql) = ExclClauses::build("src_ip", "203.0.113.7,2001:db8::/32");
        let resolved = ExclClauses::resolve(&conn, &conf);
        assert_eq!(resolved.op_sql, canon_sql);
        assert_eq!(resolved.op_soql, canon_soql);
        // hot-reload -> compile_panel_sql (AFFICHAGE) porte la nouvelle exclusion ; rule_sql (DÉTECTION) JAMAIS.
        excl_clauses_refresh(&conn, &conf);
        let web = "search source=web __OPERATOR_EXCL__ | where severity>=2 | table vhost,path,status,src_ip,ua";
        let wsql = compile_panel_sql(web, true, now() - 3600, 0, None).unwrap();
        assert!(wsql.contains("203.0.113.7"), "panneau (affichage) porte la nouvelle exclusion : {wsql}");
        assert!(!wsql.contains("__OPERATOR_EXCL__"), "placeholder panneau substitué");
        let det = rule_sql("SELECT 1 FROM event WHERE __OPERATOR_EXCL__", false, 900).unwrap();
        assert!(det.contains("__OPERATOR_EXCL__"), "DÉTECTION : rule_sql NE substitue JAMAIS (aucun angle mort créé) : {det}");
        assert!(!det.contains("203.0.113.7"), "l'IP éditée n'entre JAMAIS dans le chemin détection");
        // §4 — HOST découplé : l'override d'AFFICHAGE ne rend JAMAIS une IP never-ban (protected_ip_matchers lit
        // l'ENV PLUME_OPERATOR_IPS, pas le setting excl_operator_ips ; env vide en test -> IP publique non protégée).
        assert!(!ip_is_protected("203.0.113.7"), "l'override display ne pilote JAMAIS le never-ban HOST (§4)");
        // CLEAR : révocation auditée -> retour au no-op.
        let (_, _, after) = apply_display_excl_edit(&conn, &conf, "clear_operator_excl", "", "admin").unwrap();
        assert_eq!(after, "", "clear -> repli sur l'env (vide)");
        // restaure le cache global par défaut (propreté inter-tests).
        excl_clauses_refresh(&conn, &conf);
    }

    /// #53 — RBAC des politiques de notification + silences : GET = viewer+ (lecture), mutation = editor+
    /// (CRUD gouverné, ledgerisé), admin = total. Les CANAUX (/api/notifiers, secrets) restent admin-only.
    #[test]
    fn routing_silences_rbac_editor_plus_read_viewer() {
        for base in ["/api/notification-policies", "/api/silences"] {
            let with_id = format!("{base}/7");
            // GET = lecture (viewer + editor), pas d'admin requis.
            assert!(matches!(route_min_role(base, false), MinRole::Read), "GET {base} = viewer+");
            assert!(rbac_gate("viewer", base, false).is_ok(), "viewer LIT {base}");
            // mutation = editor+ (viewer refusé, editor ok, admin ok).
            assert!(matches!(route_min_role(base, true), MinRole::Write), "POST {base} = editor+");
            assert!(rbac_gate("editor", base, true).is_ok(), "editor mute/route {base}");
            assert!(rbac_gate("editor", &with_id, true).is_ok(), "editor mute/route {with_id}");
            assert!(rbac_gate("viewer", base, true).is_err(), "viewer NE mute PAS {base}");
            assert!(rbac_gate("admin", base, true).is_ok(), "admin gère {base}");
        }
        // les canaux restent admin-only (secret) — non régressé par #53.
        assert!(rbac_gate("editor", "/api/notifiers", false).is_err(), "editor ne LIT toujours pas les canaux");
    }

    /// (4) READ-ONLY par conception : /api/suppressions est admin-only fail-closed ; l'édition n'accepte QUE
    /// les 4 actions display-only operator/self — toute action collection-reducing / host / inconnue = 400.
    #[test]
    fn suppr_collection_and_host_filters_are_readonly() {
        let conn = test_db();
        let conf: HashMap<String, String> = HashMap::new();
        // (a) RBAC fail-closed : GET (config sensible) ET mutation = Admin.
        assert!(matches!(route_min_role("/api/suppressions", true), MinRole::Admin), "PUT suppressions = admin");
        assert!(matches!(route_min_role("/api/suppressions", false), MinRole::Admin), "GET suppressions = admin");
        // (b) ENUM FERMÉ : aucune action pilotant un filtre collection-reducing/host/inconnu n'est acceptée.
        for bad in ["set_retention", "set_protected_ip", "set_known_extra_sources", "set_hot_fields", "disable_conntrack_keep", "set_pod_log_skip", "set_min_sev", "clear", ""] {
            let err = apply_display_excl_edit(&conn, &conf, bad, "x", "admin").unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST, "action non-display-only refusée (read-only) : {bad}");
        }
        // (c) SEULES les 4 actions display-only operator/self passent.
        for ok in ["set_operator_excl", "clear_operator_excl", "set_self_excl", "clear_self_excl"] {
            assert!(apply_display_excl_edit(&conn, &conf, ok, "203.0.113.7", "admin").is_ok(), "action display-only acceptée : {ok}");
        }
        // (d) les entrées collection-reducing/host du registre restent read-only (jamais rendues pilotables).
        let reg = daemon_excl_registry(&conn, &conf);
        assert!(!reg.iter().find(|e| e.etype == ExclType::CollectionReducing).unwrap().editable);
        assert!(!reg.iter().find(|e| e.etype == ExclType::Host).unwrap().editable);
    }

    /// (5) ANTI-EMPOISONNEMENT du panneau + ALLOW-LIST des `fields`. Un auto-report
    /// `category='config'` porte une PROVENANCE SERVEUR non-forgeable (`origin`, jamais lue de l'event) : `agent`
    /// si le token est lié à un host (forced_host, M2), sinon `unverified`. Un `type` display-only FORGÉ ne peut
    /// donc plus masquer EN SILENCE un vrai filtre collection-reducing (il ressort unverified/contesté). Les
    /// `fields` ne surfacent QUE des clés connues (jamais un secret inattendu). Un event NON-config garde
    /// origin='' -> LIGNE BYTE-IDENTIQUE (parité mode-0). Aucun de ces signaux ne rend un filtre
    /// pilotable (invariants a/b : visibilité seule ; le contrôle reste à la frontière hôte).
    #[test]
    fn suppr_config_report_provenance_and_field_allowlist() {
        let conn = test_db();
        let db_path = ":memory:test";
        // (a) report config d'un AGENT lié (forced_host) -> origin='agent' (ATTESTÉ), host forcé au token.
        let ev_att = json!({ "source": "mail", "category": "config", "ts": 1000, "dedup": "cfg-mail-a", "host": "spoofed",
            "fields": { "type": "collection-reducing", "collector": "mail", "filters": { "skip_ip": "10.0.0.9" } } });
        ingest_events_batch(&conn, db_path, &[ev_att], 1000, None, Some("mail01")).unwrap();
        // (b) report config FORGÉ, même source, hôte DIFFÉRENT, token NON lié (pas de forced_host), ts PLUS RÉCENT,
        //     type display-only + filtres vides + secret embarqué -> tentative de masquage du vrai filtre.
        let ev_forge = json!({ "source": "mail", "category": "config", "ts": 2000, "dedup": "cfg-mail-b",
            "host": "attacker", "fields": { "type": "display-only", "collector": "mail", "filters": {},
                "stolen_token": "SECRET-XYZ", "note": "no filters" } });
        ingest_events_batch(&conn, db_path, &[ev_forge], 2000, None, None).unwrap();
        // (c) event NON-config -> origin='' (byte-identique à avant le stamping).
        let ev_norm = json!({ "source": "web", "category": "http", "ts": 3000, "dedup": "n1", "message": "hit" });
        ingest_events_batch(&conn, db_path, &[ev_norm], 3000, None, Some("web01")).unwrap();

        // PROVENANCE non-forgeable persistée dans origin (colonne serveur, jamais lue de l'event).
        let att_org: String = conn.query_row(&format!("SELECT origin FROM event WHERE dedup='{}'", ddk(Some("mail01"), "cfg-mail-a")), [], |r| r.get(0)).unwrap();
        assert_eq!(att_org, "agent", "report d'un agent lié -> origin=agent (attesté)");
        let att_host: String = conn.query_row(&format!("SELECT host FROM event WHERE dedup='{}'", ddk(Some("mail01"), "cfg-mail-a")), [], |r| r.get(0)).unwrap();
        assert_eq!(att_host, "mail01", "M2 : host FORCÉ au token, le host déclaré 'spoofed' est écrasé");
        let forge_org: String = conn.query_row(&format!("SELECT origin FROM event WHERE dedup='{}'", ddk(Some("attacker"), "cfg-mail-b")), [], |r| r.get(0)).unwrap();
        assert_eq!(forge_org, "unverified", "report sans token lié -> origin=unverified (host auto-déclaré, non attesté)");
        let norm_org: String = conn.query_row(&format!("SELECT origin FROM event WHERE dedup='{}'", ddk(Some("web01"), "n1")), [], |r| r.get(0)).unwrap();
        assert_eq!(norm_org, "", "event non-config -> origin='' (parité mode-0)");

        // CONTESTE : 2 hôtes distincts revendiquent source='mail' -> le conflit est VISIBLE (>1).
        let n: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT host) FROM event WHERE category='config' AND origin<>'daemon' AND source='mail'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2, "hôtes contestés (mail01 + attacker) -> le report forgé ne peut plus masquer en silence");

        // ALLOW-LIST : le champ secret inattendu est DROPPÉ ; les descripteurs connus sont préservés.
        let raw = json!({ "type": "display-only", "collector": "mail", "filters": { "skip_ip": "x" },
            "note": "n", "enforcement": {"a":1}, "detector": "d", "max": "5", "source": "mail", "carve_out": "c",
            "stolen_token": "SECRET-XYZ", "aws_key": "AKIA..." });
        let proj = suppression_fields_allowlist(&raw);
        for k in ["type", "collector", "filters", "note", "enforcement", "detector", "max", "source", "carve_out"] {
            assert!(proj.get(k).is_some(), "descripteur connu préservé : {k}");
        }
        assert!(proj.get("stolen_token").is_none(), "champ secret inattendu DROPPÉ");
        assert!(proj.get("aws_key").is_none(), "clé secrète inattendue DROPPÉE");
        // un `fields` non-objet -> objet vide (jamais de panique / echo brut).
        assert_eq!(suppression_fields_allowlist(&json!("scalar")), json!({}));
    }

    // ============================================================================================
    // #59 GOUVERNANCE ENTREPRISE — invariants de sécurité (legal-hold fail-closed, ledger export chaîne
    // préservée + read-only, rôles composables non-escaladants + default-deny, SCIM anti-superadmin, mode 0).
    // ============================================================================================

    /// legal-hold BLOQUE la suppression (fail-safe) : un hold actif épingle sa portée contre retention_run ;
    /// hors portée -> purgé ; après levée -> re-purgeable. Preuve que la garde est branchée sur le chemin réel.
    #[test]
    fn gov_legal_hold_blocks_deletion() {
        let conn = test_db();
        let old = now() - 40 * 86400; // au-delà du plancher 7 j
        conn.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','7')", []).unwrap();
        conn.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'sshd','ancien retenu','')", params![old]).unwrap();
        conn.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'web','ancien hors portée','')", params![old]).unwrap();
        // hold ACTIF scopé à source='sshd', fenêtre ouverte.
        conn.execute("INSERT INTO legal_hold(name,scope_source,active,created,created_by) VALUES('litige-A','sshd',1,?1,'admin')", params![now()]).unwrap();
        assert!(event_is_held(&conn, "sshd", old), "l'event sshd est reconnu retenu");
        assert!(!event_is_held(&conn, "web", old), "l'event web hors portée n'est pas retenu");
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        {
            let c = db.lock();
            assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE source='sshd'", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "event sshd RETENU par le hold -> NON purgé");
            assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE source='web'", [], |r| r.get::<_,i64>(0)).unwrap(), 0, "event web HORS portée -> purgé normalement");
            // LÈVE le hold.
            c.execute("UPDATE legal_hold SET active=0 WHERE name='litige-A'", []).unwrap();
        }
        retention_run(&db);
        {
            let c = db.lock();
            assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE source='sshd'", [], |r| r.get::<_,i64>(0)).unwrap(), 0, "hold levé -> l'event redevient purgeable");
        }
    }

    /// legal-hold FAIL-CLOSED : si la table `legal_hold` EXISTE mais devient illisible (schéma corrompu ->
    /// le compte des holds actifs erre), retention_run S'ABSTIENT de purger `event` (jamais supprimer une
    /// preuve dont on ne peut prouver qu'elle n'est pas retenue). Décision testée directement + de bout en bout.
    #[test]
    fn gov_legal_hold_failclosed_when_undeterminable() {
        let conn = test_db();
        // Décision unitaire : pas de hold -> NoHolds ; hold actif -> Guard.
        assert!(matches!(legal_hold_enforcement(&conn), HoldEnforce::NoHolds));
        conn.execute("INSERT INTO legal_hold(name,active,created) VALUES('h',1,0)", []).unwrap();
        assert!(matches!(legal_hold_enforcement(&conn), HoldEnforce::Guard(_)));
        // Corrompt le schéma : table présente mais SANS colonne `active` -> COUNT(... WHERE active=1) erre.
        conn.execute_batch("DROP TABLE legal_hold; CREATE TABLE legal_hold(id INTEGER);").unwrap();
        assert!(table_present(&conn, "legal_hold"), "table présente");
        assert!(matches!(legal_hold_enforcement(&conn), HoldEnforce::FailClosed), "table illisible -> FailClosed (fail-closed)");
        // De bout en bout : un event ancien N'EST PAS purgé quand l'état des holds est indéterminé.
        let old = now() - 40 * 86400;
        conn.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','7')", []).unwrap();
        conn.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'sshd','ancien','')", params![old]).unwrap();
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        let c = db.lock();
        assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE source='sshd'", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "état des holds indéterminé -> purge de `event` SUSPENDUE (fail-closed)");
    }

    /// EXPORT du ledger : la chaîne se VÉRIFIE après export (loi identique à verify_run) ; toute altération
    /// d'une ligne exportée est DÉTECTÉE par un vérificateur externe. Preuve que l'export préserve la chaîne.
    #[test]
    fn gov_ledger_export_preserves_and_verifies_chain() {
        let conn = test_db();
        for i in 0..5 {
            ledger_append(&conn, "test.kind", &format!("entrée {i}"));
        }
        let (lines, last_id, last_hash) = ledger_export_lines(&conn, 0, 0);
        assert_eq!(lines.len(), 5, "5 entrées exportées");
        assert!(last_id > 0 && !last_hash.is_empty());
        // Vérification EXTERNE (hors base) : chaîne intègre depuis genesis.
        assert_eq!(ledger_verify_export(&lines, "").unwrap(), 5, "chaîne exportée vérifiée");
        // ALTÉRATION d'une ligne (detail modifié) -> détectée.
        let mut tampered = lines.clone();
        let v: Value = serde_json::from_str(&tampered[2]).unwrap();
        tampered[2] = json!({ "id": v["id"], "ts": v["ts"], "kind": v["kind"], "detail": "FALSIFIÉ", "prev_hash": v["prev_hash"], "hash": v["hash"] }).to_string();
        assert!(ledger_verify_export(&tampered, "").is_err(), "ligne altérée -> rupture détectée");
    }

    /// EXPORT = READ-ONLY : ledger_export_lines ne MUTE jamais le ledger (append-only intact) — aucun chemin
    /// de mutation vers le ledger via l'export. Le head/compte reste identique après export.
    #[test]
    fn gov_ledger_export_is_readonly() {
        let conn = test_db();
        for i in 0..3 {
            ledger_append(&conn, "k", &format!("{i}"));
        }
        let head_before: String = conn.query_row("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).unwrap();
        let n_before: i64 = conn.query_row("SELECT COUNT(*) FROM ledger", [], |r| r.get(0)).unwrap();
        let _ = ledger_export_lines(&conn, 0, 0);
        let head_after: String = conn.query_row("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).unwrap();
        let n_after: i64 = conn.query_row("SELECT COUNT(*) FROM ledger", [], |r| r.get(0)).unwrap();
        assert_eq!(head_before, head_after, "export ne modifie pas le head du ledger");
        assert_eq!(n_before, n_after, "export n'ajoute/ne retire aucune entrée");
    }

    /// RÔLES COMPOSABLES : (a) un rôle custom ne dépasse JAMAIS sa base (pas d'escalade) ; (b) un base=admin
    /// avec deny `raw_sql` PERD le SQL brut ; (c) un base=admin avec deny `manage_users` est REFUSÉ sur
    /// /api/users ; (d) un nom INCONNU -> rang 0, refusé partout (DEFAULT-DENY) ; (e) grant restreint aux
    /// rôles définis. Aucun de ces chemins ne peut atteindre raw-SQL/colonne-secret/enum-action interdits.
    #[test]
    fn gov_composable_role_cannot_escalate() {
        let _rg = CUSTOM_ROLES_TEST_LOCK.lock();
        {
            let mut m = custom_roles_cell().lock();
            m.insert("gov-auditor".into(), RoleDef { base: "viewer".into(), deny: vec![] });
            m.insert("gov-power".into(), RoleDef { base: "admin".into(), deny: vec!["raw_sql".into()] });
            m.insert("gov-nousers".into(), RoleDef { base: "admin".into(), deny: vec!["manage_users".into()] });
        }
        // (a) plafond = base : auditor(viewer) ne peut pas atteindre une route admin ni le SQL brut.
        assert_eq!(effective_base_role("gov-auditor"), "viewer");
        assert_eq!(role_rank("gov-auditor"), 1);
        assert!(rbac_gate("gov-auditor", "/api/users", false).is_err(), "custom viewer ne lit pas /api/users (admin-only)");
        assert!(!raw_sql_allowed(false, "gov-auditor"), "custom viewer -> pas de SQL brut");
        // (b) base=admin mais raw_sql RETIRÉ -> SQL brut refusé, mais capacité de route admin conservée.
        assert!(!raw_sql_allowed(false, "gov-power"), "deny raw_sql -> SQL brut refusé MÊME base=admin");
        assert!(rbac_gate("gov-power", "/api/rules", true).is_ok(), "base=admin -> route éditoriale OK");
        assert!(rbac_gate("gov-power", "/api/users", true).is_ok(), "power ne retire PAS manage_users -> /api/users OK");
        // (c) deny manage_users -> /api/users refusé même base=admin.
        assert!(rbac_gate("gov-nousers", "/api/users", true).is_err(), "deny manage_users -> /api/users refusé");
        assert!(rbac_gate("gov-nousers", "/api/rules", true).is_ok(), "les autres routes admin restent OK");
        // (d) DEFAULT-DENY : un nom inconnu n'a AUCUNE autorité.
        assert_eq!(effective_base_role("gov-ghost"), "");
        assert_eq!(role_rank("gov-ghost"), 0);
        assert!(rbac_gate("gov-ghost", "/api/rules", true).is_err(), "rôle inconnu -> refusé (default-deny)");
        assert!(!raw_sql_allowed(false, "gov-ghost"), "rôle inconnu -> pas de SQL brut");
        // (e) grant : seuls les rôles DÉFINIS (+ base) sont assignables ; jamais un superadmin.
        assert!(valid_grant_role("gov-auditor"), "rôle défini -> assignable");
        assert!(!valid_grant_role("gov-ghost"), "rôle indéfini -> NON assignable (default-deny)");
        assert!(valid_grant_role("admin") && valid_grant_role("editor") && valid_grant_role("viewer"));
        for bad in ["superadmin", "is_superadmin", "plume-superadmin", "root"] {
            assert!(!valid_grant_role(bad), "'{bad}' n'est jamais un rôle assignable");
        }
        // nettoyage (ne pas fuiter dans le cache global partagé entre tests).
        let mut m = custom_roles_cell().lock();
        m.remove("gov-auditor");
        m.remove("gov-power");
        m.remove("gov-nousers");
    }

    /// SCIM ne peut JAMAIS accorder le super-admin : ensure_platform_user crée toujours is_superadmin=0, et le
    /// mapping de rôle passe par valid_grant_role (enum fermé) — aucun rôle « superadmin » n'y est valide.
    #[test]
    fn gov_scim_cannot_grant_superadmin() {
        let conn = Connection::open_in_memory().unwrap();
        migrate_control(&conn);
        let cp = ControlPlane { conn: Arc::new(Mutex::new(conn)), db_path: Arc::new(String::new()) };
        // Provisioning d'un user -> is_superadmin IMPOSÉ à 0.
        let id = ensure_platform_user(&cp, "scim-alice").expect("create");
        let is_sa: i64 = cp.conn.lock().query_row("SELECT is_superadmin FROM platform_user WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        assert_eq!(is_sa, 0, "SCIM ne provisionne JAMAIS un super-admin");
        // ré-appel idempotent : ne modifie pas is_superadmin.
        let id2 = ensure_platform_user(&cp, "scim-alice").expect("idempotent");
        assert_eq!(id, id2, "idempotent par userName");
        // Aucune valeur 'superadmin' n'est un rôle de grant valide (le mapping SCIM group->grant l'exclut).
        for bad in ["superadmin", "is_superadmin", "plume-superadmin"] {
            assert!(!valid_grant_role(bad), "SCIM ne peut mapper vers '{bad}'");
        }
    }

    /// MODE 0 (byte-identique) : cache de rôles VIDE + aucun hold -> tous les chemins RBAC/rétention gardent
    /// EXACTEMENT le comportement pré-#59. (a) résolution des rôles de base inchangée ; (b) gate identique ;
    /// (c) legal_hold_enforcement=NoHolds -> guard=RETENTION_NONPURGE exact -> purge byte-identique.
    #[test]
    fn gov_mode0_parity() {
        // (a) rôles de base : résolution COURT-CIRCUITÉE avant tout lookup custom (indépendant du cache).
        assert_eq!(effective_base_role("admin"), "admin");
        assert_eq!(role_rank("admin"), 3);
        assert_eq!(role_rank("editor"), 2);
        assert_eq!(role_rank("viewer"), 1);
        // (b) raw_sql_allowed + rbac_gate : identiques à l'historique pour les rôles de base.
        assert!(raw_sql_allowed(false, "admin") && raw_sql_allowed(true, "editor"));
        assert!(!raw_sql_allowed(false, "editor") && !raw_sql_allowed(false, "viewer"));
        assert!(rbac_gate("admin", "/api/users", true).is_ok());
        assert!(rbac_gate("editor", "/api/rules", true).is_ok());
        assert!(rbac_gate("viewer", "/api/rules", true).is_err());
        assert!(rbac_gate("editor", "/api/users", true).is_err(), "editor jamais admin (fail-closed préservé)");
        // (c) rétention sans hold : NoHolds -> comportement inchangé (event ancien purgé comme avant).
        let conn = test_db();
        assert!(matches!(legal_hold_enforcement(&conn), HoldEnforce::NoHolds), "aucun hold -> NoHolds (guard byte-identique)");
        let old = now() - 40 * 86400;
        conn.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','7')", []).unwrap();
        conn.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'sshd','ancien','')", params![old]).unwrap();
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        assert_eq!(db.lock().query_row("SELECT COUNT(*) FROM event WHERE source='sshd'", [], |r| r.get::<_,i64>(0)).unwrap(), 0, "sans hold -> purge identique à l'historique");
    }

    /// CRITICAL #59 (corrigé) : le legal-hold pince DÉSORMAIS `alert` + `snapshot` (preuve non-reconstructible,
    /// sans colonne `source`), pas seulement `event`. (1) un hold GLOBAL (scope_source='') bloque les TROIS ;
    /// (2) un hold source-scopé ne bloque QUE `event` (alert/snapshot n'ont pas de source) ; (3) FAIL-CLOSED
    /// (état des holds indéterminé) SUSPEND la purge des TROIS ce tick. Mode 0 (aucun hold) reste byte-identique
    /// (prouvé par gov_mode0_parity : les littéraux snapshot/alert de la branche NoHolds sont inchangés).
    #[test]
    fn gov_legal_hold_blocks_alert_and_snapshot() {
        let old = now() - 4000 * 86400; // au-delà de tout plafond de rétention (event/alert/snapshot)
        let seed = |conn: &Connection| {
            conn.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','7')", []).unwrap();
            conn.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'sshd','ev','')", params![old]).unwrap();
            conn.execute("INSERT INTO alert(ts,rule,severity,status) VALUES(?1,'r',3,'closed')", params![old]).unwrap(); // status<>'new' -> purgeable
            conn.execute("INSERT INTO snapshot(ts,kind) VALUES(?1,'ports')", params![old]).unwrap();
        };
        // (1) HOLD GLOBAL (scope_source='') -> event + alert + snapshot TOUS retenus.
        let conn = test_db();
        seed(&conn);
        conn.execute("INSERT INTO legal_hold(name,scope_source,active,created,created_by) VALUES('global-A','',1,?1,'admin')", params![now()]).unwrap();
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        {
            let c = db.lock();
            assert_eq!(c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "hold global -> event NON purgé");
            assert_eq!(c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "hold global -> alert NON purgée (CRITICAL fix)");
            assert_eq!(c.query_row("SELECT COUNT(*) FROM snapshot", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "hold global -> snapshot NON purgé (CRITICAL fix)");
        }
        // (2) HOLD SOURCE-SCOPÉ (sshd) -> event retenu, mais alert/snapshot (sans source) purgés normalement.
        let conn = test_db();
        seed(&conn);
        conn.execute("INSERT INTO legal_hold(name,scope_source,active,created,created_by) VALUES('scoped-sshd','sshd',1,?1,'admin')", params![now()]).unwrap();
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        {
            let c = db.lock();
            assert_eq!(c.query_row("SELECT COUNT(*) FROM event WHERE source='sshd'", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "hold scopé sshd -> event retenu");
            assert_eq!(c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get::<_,i64>(0)).unwrap(), 0, "hold source-scopé ne protège PAS alert (aucune colonne source) -> purgée");
            assert_eq!(c.query_row("SELECT COUNT(*) FROM snapshot", [], |r| r.get::<_,i64>(0)).unwrap(), 0, "hold source-scopé ne protège PAS snapshot -> purgé");
        }
        // (3) FAIL-CLOSED : legal_hold présente mais illisible -> purge event+alert+snapshot SUSPENDUE.
        let conn = test_db();
        seed(&conn);
        conn.execute_batch("DROP TABLE legal_hold; CREATE TABLE legal_hold(id INTEGER);").unwrap();
        assert!(matches!(legal_hold_enforcement(&conn), HoldEnforce::FailClosed));
        let db = Arc::new(Mutex::new(conn));
        retention_run(&db);
        {
            let c = db.lock();
            assert_eq!(c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "fail-closed -> event suspendu");
            assert_eq!(c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "fail-closed -> alert suspendue");
            assert_eq!(c.query_row("SELECT COUNT(*) FROM snapshot", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "fail-closed -> snapshot suspendu");
        }
    }

    /// HIGH #59 : les endpoints SCIM `Users` sont TENANT-SCOPÉS (platform_user est GLOBAL). Un token pour le
    /// tenant t1 ne liste/ne renvoie JAMAIS un user provisionné seulement dans t2 ; un GET /Users/{id} d'un id
    /// hors tenant -> 404 (identité cross-tenant jamais révélée).
    #[tokio::test]
    async fn gov_scim_users_are_tenant_scoped() {
        let (cp, _cptmp) = mk_test_control();
        let alice = ensure_platform_user(&cp, "alice").unwrap();
        let bob = ensure_platform_user(&cp, "bob").unwrap();
        {
            let c = cp.conn.lock();
            c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,'t1','editor')", params![alice]).unwrap();
            c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,'t2','editor')", params![bob]).unwrap();
        }
        let st = tenant_test_state("admins", "editors", "supers", Some(cp.clone()));
        let ctx = ScimCtx { tenant: "t1".into() };
        // LIST (token t1) : alice seule — bob (t2) JAMAIS listé.
        let (code, v) = tok_resp_json(scim_users_list(State(st.clone()), Extension(ctx.clone()), axum::extract::Query(HashMap::new())).await).await;
        assert_eq!(code, StatusCode::OK);
        let names: Vec<String> = v["Resources"].as_array().unwrap().iter().map(|r| r["userName"].as_str().unwrap().to_string()).collect();
        assert_eq!(names, vec!["alice".to_string()], "SCIM list tenant-scopé : bob (t2) absent");
        // GET alice (membre t1) -> 200.
        let (c1, _) = tok_resp_json(scim_user_get(State(st.clone()), Extension(ctx.clone()), axum::extract::Path(alice.clone())).await).await;
        assert_eq!(c1, StatusCode::OK, "GET alice (t1) -> 200");
        // GET bob (t2) via token t1 -> 404.
        let (c2, _) = tok_resp_json(scim_user_get(State(st.clone()), Extension(ctx.clone()), axum::extract::Path(bob.clone())).await).await;
        assert_eq!(c2, StatusCode::NOT_FOUND, "GET bob (t2) via token t1 -> 404 (cross-tenant jamais révélé)");
    }

    /// HIGH #59 : aucune mutation SCIM RETIRANT un grant ne peut ORPHELINER le tenant (dernier admin). Les
    /// trois chemins (replace active=false, DELETE, group op=remove sur 'admin') sont REFUSÉS (409) quand ils
    /// videraient le dernier admin ; avec DEUX admins, en retirer un est permis (contre-épreuve).
    #[tokio::test]
    async fn gov_scim_cannot_remove_last_admin() {
        let (cp, _cptmp) = mk_test_control();
        let sole = ensure_platform_user(&cp, "sole-admin").unwrap();
        cp.conn.lock().execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,'t1','admin')", params![sole]).unwrap();
        let st = tenant_test_state("admins", "editors", "supers", Some(cp.clone()));
        let ctx = ScimCtx { tenant: "t1".into() };
        // (a) replace active=false -> 409.
        let (c1, _) = tok_resp_json(scim_user_replace(State(st.clone()), Extension(ctx.clone()), axum::extract::Path(sole.clone()), Json(json!({ "active": false }))).await).await;
        assert_eq!(c1, StatusCode::CONFLICT, "désactiver le dernier admin -> refusé");
        // (b) DELETE -> 409.
        let r = scim_user_delete(State(st.clone()), Extension(ctx.clone()), axum::extract::Path(sole.clone())).await.into_response();
        assert_eq!(r.status(), StatusCode::CONFLICT, "deprovision du dernier admin -> refusé");
        // (c) group remove -> 409.
        let (c3, _) = tok_resp_json(scim_group_patch(State(st.clone()), Extension(ctx.clone()), axum::extract::Path("admin".to_string()), Json(json!({ "Operations": [{ "op": "remove", "value": [{ "value": sole }] }] }))).await).await;
        assert_eq!(c3, StatusCode::CONFLICT, "retrait du dernier admin via group -> refusé");
        // le grant admin SURVIT aux trois tentatives.
        let cnt: i64 = cp.conn.lock().query_row("SELECT COUNT(*) FROM \"grant\" WHERE tenant_id='t1' AND role='admin'", [], |r| r.get(0)).unwrap();
        assert_eq!(cnt, 1, "le dernier admin est toujours présent");
        // CONTRE-ÉPREUVE : avec DEUX admins, en retirer un est AUTORISÉ (204).
        let second = ensure_platform_user(&cp, "second-admin").unwrap();
        cp.conn.lock().execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,'t1','admin')", params![second]).unwrap();
        let r2 = scim_user_delete(State(st.clone()), Extension(ctx.clone()), axum::extract::Path(second.clone())).await.into_response();
        assert_eq!(r2.status(), StatusCode::NO_CONTENT, "avec 2 admins, en retirer un est permis");
    }

    // Le catalogue de rôles composables est un GLOBAL process (`custom_roles_cell`), remplacé EN BLOC par
    // `reload_custom_roles` à chaque mutation (role_create/update/delete). Tout test qui INJECTE des rôles en
    // mémoire pour assertion ET tout test qui DÉCLENCHE un reload doivent donc se sérialiser, sinon un reload
    // concurrent efface les entrées d'un autre test (flakiness). Même patron que ENGAGEMENT_TEST_LOCK/VERROU_ENV_PROCESSUS.

    /// #64 CORRECTIF (fix 1) : l'auto-approbation de `run_playbooks` suit l'AUTORITÉ ADMIN EFFECTIVE de
    /// l'auteur, pas un `created_by_role == "admin"` LITTÉRAL. Un rôle composable base=admin SANS deny
    /// `arm_response` -> auto-approuve en mode active (approved+réel, dry_run=0) ; AVEC deny arm_response ->
    /// reste pending/dry (le deny soustractif subsiste sur la surface playbook) ; base non-admin -> jamais.
    /// Le littéral `admin` reste byte-identique (mode-0 parité).
    #[test]
    fn gov_playbook_autoapprove_effective_admin() {
        let _rg = CUSTOM_ROLES_TEST_LOCK.lock();
        let path = mk_tmp_path("pb-autoapprove.db");
        {
            let w = Connection::open(&path).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            w.execute("INSERT INTO meta(key,value) VALUES('plume_mode','active') ON CONFLICT(key) DO UPDATE SET value='active'", []).unwrap();
        }
        {
            let mut m = custom_roles_cell().lock();
            m.insert("c64pb-armer".into(), RoleDef { base: "admin".into(), deny: vec![] });
            m.insert("c64pb-noarm".into(), RoleDef { base: "admin".into(), deny: vec!["arm_response".into()] });
            m.insert("c64pb-vw".into(), RoleDef { base: "viewer".into(), deny: vec![] });
        }
        // Chaque exécution : playbook `stop_service` dont la requête renvoie une cible constante -> 1 action.
        let run_for = |role: &str| -> (String, i64) {
            let conn = Connection::open(&path).unwrap();
            conn.execute("DELETE FROM action", []).unwrap();
            conn.execute("DELETE FROM playbook", []).unwrap();
            conn.execute(
                "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,last_run,created_by_role) \
                 VALUES('pb-t',1,'SELECT ''nginx-svc''',0,'stop_service',0,3600,0,NULL,?1)",
                params![role],
            ).unwrap();
            let db = Arc::new(Mutex::new(conn));
            run_playbooks(&db, &path);
            let c = db.lock();
            c.query_row(
                "SELECT status,dry_run FROM action WHERE reason LIKE 'playbook:%' ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            ).unwrap()
        };
        assert_eq!(run_for("c64pb-armer"), ("approved".to_string(), 0), "custom base=admin SANS deny arm_response -> auto-approuve (réel)");
        assert_eq!(run_for("c64pb-noarm"), ("pending".to_string(), 1), "custom base=admin AVEC deny arm_response -> reste pending/dry (deny soustractif)");
        assert_eq!(run_for("c64pb-vw"), ("pending".to_string(), 1), "custom base=viewer -> jamais auto-approuvé (pas d'escalade)");
        assert_eq!(run_for("admin"), ("approved".to_string(), 0), "littéral admin -> auto-approuve (mode-0 parité)");
        assert_eq!(run_for("editor"), ("pending".to_string(), 1), "littéral editor -> jamais auto-approuvé (non-régression)");
        {
            let mut m = custom_roles_cell().lock();
            for k in ["c64pb-armer", "c64pb-noarm", "c64pb-vw"] { m.remove(k); }
        }
        let _ = std::fs::remove_file(&path);
    }

    /// #64 CORRECTIF (fix 2b) : l'anti-lockout SCIM compte les grants à AUTORITÉ ADMIN EFFECTIVE (littéral OU
    /// rôle composable base=admin), pas seulement `role='admin'`. Retirer le DERNIER `c64sc-admin` (base=admin)
    /// d'un tenant — via group op=remove OU via DELETE user — est REFUSÉ (409) : sinon le tenant serait orphelin
    /// (0 admin effectif = lockout DoS). Contre-épreuve : avec un 2e admin (littéral), le retrait redevient permis.
    #[tokio::test]
    async fn gov_scim_anti_lockout_counts_custom_admin() {
        let _rg = CUSTOM_ROLES_TEST_LOCK.lock();
        {
            let mut m = custom_roles_cell().lock();
            m.insert("c64sc-admin".into(), RoleDef { base: "admin".into(), deny: vec![] });
        }
        let (cp, _cptmp) = mk_test_control();
        let sole = ensure_platform_user(&cp, "sole-gov-admin").unwrap();
        cp.conn.lock().execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,'t1','c64sc-admin')", params![sole]).unwrap();
        let st = tenant_test_state("admins", "editors", "supers", Some(cp.clone()));
        let ctx = ScimCtx { tenant: "t1".into() };
        // (a) group remove du dernier admin EFFECTIF (custom base=admin) -> 409 (avant #64 : passait -> lockout).
        let (c1, _) = tok_resp_json(scim_group_patch(State(st.clone()), Extension(ctx.clone()), axum::extract::Path("c64sc-admin".to_string()), Json(json!({ "Operations": [{ "op": "remove", "value": [{ "value": sole }] }] }))).await).await;
        assert_eq!(c1, StatusCode::CONFLICT, "retrait du dernier admin EFFECTIF (custom base=admin) via group -> refusé");
        // (b) DELETE user (deprovision) -> 409 aussi (scim_would_orphan_last_admin effective-aware).
        let r = scim_user_delete(State(st.clone()), Extension(ctx.clone()), axum::extract::Path(sole.clone())).await.into_response();
        assert_eq!(r.status(), StatusCode::CONFLICT, "deprovision du dernier admin EFFECTIF (custom base=admin) -> refusé");
        // le grant custom-admin SURVIT aux deux tentatives.
        let cnt: i64 = cp.conn.lock().query_row("SELECT COUNT(*) FROM \"grant\" WHERE tenant_id='t1' AND role='c64sc-admin'", [], |r| r.get(0)).unwrap();
        assert_eq!(cnt, 1, "le dernier admin effectif est toujours présent");
        // CONTRE-ÉPREUVE : avec un 2e admin (littéral), retirer le custom-admin devient permis (200).
        let lit = ensure_platform_user(&cp, "lit-admin").unwrap();
        cp.conn.lock().execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,'t1','admin')", params![lit]).unwrap();
        let (c2, _) = tok_resp_json(scim_group_patch(State(st.clone()), Extension(ctx.clone()), axum::extract::Path("c64sc-admin".to_string()), Json(json!({ "Operations": [{ "op": "remove", "value": [{ "value": sole }] }] }))).await).await;
        assert_eq!(c2, StatusCode::OK, "avec un 2e admin (littéral), retirer le custom-admin est permis");
        let gone: i64 = cp.conn.lock().query_row("SELECT COUNT(*) FROM \"grant\" WHERE tenant_id='t1' AND user_id=?1", params![sole], |r| r.get(0)).unwrap();
        assert_eq!(gone, 0, "le custom-admin a bien été retiré (contre-épreuve)");
        custom_roles_cell().lock().remove("c64sc-admin");
    }

    /// #64 CORRECTIF (fix 2a) : le path-guard `tenant_mgmt_gate` des grants suit l'AUTORITÉ ADMIN EFFECTIVE
    /// (cohérent avec le re-check aval `can_manage_grants`). Un rôle composable base=admin de SON tenant gère
    /// ses propres grants ; il NE gère PAS ceux d'un autre tenant (confinement inchangé) ; un base non-admin /
    /// builtin editor|viewer / rôle inconnu -> 403 (default-deny) ; le CRUD tenants reste super-admin only.
    #[test]
    fn tenant_mgmt_gate_effective_admin_grants() {
        let _rg = CUSTOM_ROLES_TEST_LOCK.lock();
        {
            let mut m = custom_roles_cell().lock();
            m.insert("c64tg-admin".into(), RoleDef { base: "admin".into(), deny: vec![] });
            m.insert("c64tg-editor".into(), RoleDef { base: "editor".into(), deny: vec![] });
        }
        // custom base=admin de acme -> gère les grants de acme (nouveau : plus de 403 fail-closed incohérent).
        assert!(tenant_mgmt_gate("/api/tenants/acme/grants", "c64tg-admin", "acme", false).is_ok(), "custom base=admin de acme gère les grants de acme");
        // ... mais PAS ceux d'un AUTRE tenant (confinement cross-tenant INCHANGÉ).
        assert!(tenant_mgmt_gate("/api/tenants/beta/grants", "c64tg-admin", "acme", false).is_err(), "custom base=admin de acme NE gère PAS les grants de beta");
        // custom base=editor -> 403 (jamais admin).
        assert!(tenant_mgmt_gate("/api/tenants/acme/grants", "c64tg-editor", "acme", false).is_err(), "custom base=editor -> refusé");
        // builtin editor|viewer -> 403 (non-régression).
        assert!(tenant_mgmt_gate("/api/tenants/acme/grants", "editor", "acme", false).is_err(), "editor -> refusé");
        assert!(tenant_mgmt_gate("/api/tenants/acme/grants", "viewer", "acme", false).is_err(), "viewer -> refusé");
        // rôle INCONNU (ni base, ni défini) -> 403 (default-deny, aucune escalade).
        assert!(tenant_mgmt_gate("/api/tenants/acme/grants", "c64tg-ghost", "acme", false).is_err(), "rôle inconnu -> refusé");
        // le CRUD/suspend des tenants reste SUPER-ADMIN only, même pour un custom base=admin.
        assert!(tenant_mgmt_gate("/api/tenants", "c64tg-admin", "acme", false).is_err(), "custom base=admin NE peut PAS lister/créer des tenants");
        assert!(tenant_mgmt_gate("/api/tenants/acme/suspend", "c64tg-admin", "acme", false).is_err(), "custom base=admin NE peut PAS suspendre");
        {
            let mut m = custom_roles_cell().lock();
            m.remove("c64tg-admin"); m.remove("c64tg-editor");
        }
    }

    /// #64 : `role_create` ACCEPTE de nouveau base=admin (blocage MEDIUM #59 levé). Le rôle composable
    /// base=admin est bien PERSISTÉ, résout vers l'autorité admin (`effective_base_role`), et voit ses
    /// `deny_perms` conservés (soustractifs). base ∈ {viewer, editor, admin} ; un base HORS enum (ex.
    /// "superadmin") reste REFUSÉ (aucune escalade plateforme).
    #[tokio::test]
    async fn gov_role_create_accepts_admin_base() {
        let _rg = CUSTOM_ROLES_TEST_LOCK.lock();
        let (cp, _cptmp) = mk_test_control();
        let st = tenant_test_state("admins", "editors", "supers", Some(cp.clone()));
        let sa = || { let mut a = tok_au("admin"); a.is_superadmin = true; a };
        // base=admin (avec un deny explicite) -> ACCEPTÉ + créé + résout admin + deny conservé.
        let (c1, _) = tok_resp_json(role_create(State(st.clone()), Extension(sa()), Json(json!({ "name": "gov-admin", "base_role": "admin", "deny_perms": ["manage_users"] }))).await).await;
        assert_eq!(c1, StatusCode::OK, "base=admin de nouveau accepté (#64)");
        let n: i64 = cp.conn.lock().query_row("SELECT COUNT(*) FROM role_def WHERE name='gov-admin' AND base_role='admin'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "le rôle base=admin EST persisté");
        assert_eq!(effective_base_role("gov-admin"), "admin", "résout vers l'autorité admin");
        assert!(role_perm_denied("gov-admin", "manage_users"), "deny_perms conservé (soustractif)");
        assert!(!role_perm_denied("gov-admin", "raw_sql"), "seul le deny déclaré est retiré");
        // base ∈ {editor, viewer} restent acceptés.
        let (c2, _) = tok_resp_json(role_create(State(st.clone()), Extension(sa()), Json(json!({ "name": "r-ed", "base_role": "editor" }))).await).await;
        assert_eq!(c2, StatusCode::OK, "base=editor accepté");
        let (c3, _) = tok_resp_json(role_create(State(st.clone()), Extension(sa()), Json(json!({ "name": "r-vw", "base_role": "viewer" }))).await).await;
        assert_eq!(c3, StatusCode::OK, "base=viewer accepté");
        // base HORS enum -> REFUSÉ (jamais de super-admin ni de base inconnue).
        for bad in ["superadmin", "is_superadmin", "root", "client"] {
            let (cx, _) = tok_resp_json(role_create(State(st.clone()), Extension(sa()), Json(json!({ "name": format!("x-{bad}"), "base_role": bad }))).await).await;
            assert_eq!(cx, StatusCode::BAD_REQUEST, "base='{bad}' refusé (hors enum {{viewer,editor,admin}})");
        }
        // nettoyage du cache process global.
        let mut m = custom_roles_cell().lock();
        m.remove("gov-admin"); m.remove("r-ed"); m.remove("r-vw");
    }

    /// #64 SÉCU — `AuthUser::is_admin()` = AUTORITÉ ADMIN EFFECTIVE (`effective_base_role(role)=="admin"`), sans
    /// escalade : (a) rôle de base admin/editor/viewer inchangé (mode-0 byte-identique) ; (b) custom base=admin
    /// -> is_admin()=true (autorité de route) MAIS ses `deny_perms` restent soustraits par rbac_gate EN AMONT ;
    /// (c) custom base=viewer/editor -> JAMAIS admin ; (d) nom INCONNU -> JAMAIS admin ; (e) un custom-admin ne
    /// peut PAS s'auto-éditer pour retirer ses denies (roles_guard = super-admin only) ; (f) confinement #39 du
    /// rôle `client` intact ; (g) colonne-secret/raw-SQL toujours refusés à un custom-admin qui les a en deny.
    #[tokio::test]
    async fn gov_is_admin_effective_no_escalation() {
        let _rg = CUSTOM_ROLES_TEST_LOCK.lock();
        // Setup : catalogue de rôles composables.
        {
            let mut m = custom_roles_cell().lock();
            m.insert("gov-admin".into(), RoleDef { base: "admin".into(), deny: vec!["manage_users".into()] });
            m.insert("gov-fulladmin".into(), RoleDef { base: "admin".into(), deny: vec![] });
            m.insert("gov-editor".into(), RoleDef { base: "editor".into(), deny: vec![] });
            m.insert("gov-viewer".into(), RoleDef { base: "viewer".into(), deny: vec![] });
            m.insert("gov-sqlless".into(), RoleDef { base: "admin".into(), deny: vec!["raw_sql".into()] });
        }
        // (a) MODE-0 PARITÉ : rôles de base identiques à `role=="admin"`.
        assert!(tok_au("admin").is_admin(), "builtin admin -> is_admin()");
        assert!(!tok_au("editor").is_admin(), "builtin editor -> JAMAIS admin");
        assert!(!tok_au("viewer").is_admin(), "builtin viewer -> JAMAIS admin");
        assert!(!tok_au("client").is_admin(), "builtin client -> JAMAIS admin");
        // (b) custom base=admin -> autorité admin sur les ROUTES (is_admin) ; deny soustrait EN AMONT par rbac_gate.
        assert!(tok_au("gov-admin").is_admin(), "custom base=admin -> is_admin() (autorité de route)");
        assert!(tok_au("gov-fulladmin").is_admin(), "custom base=admin sans deny -> is_admin()");
        assert!(rbac_gate("gov-admin", "/api/users", true).is_err(), "deny manage_users -> /api/users refusé EN AMONT (path-guard) malgré is_admin()");
        assert!(rbac_gate("gov-admin", "/api/connectors", true).is_ok(), "surface admin NON déniée -> autorisée (admin-minus-denies)");
        assert!(rbac_gate("gov-fulladmin", "/api/users", true).is_ok(), "custom-admin sans deny -> /api/users OK (ceiling admin)");
        // (c) custom base=viewer/editor -> JAMAIS admin (pas d'escalade au-dessus de la base).
        assert!(!tok_au("gov-editor").is_admin(), "custom base=editor -> JAMAIS admin");
        assert!(!tok_au("gov-viewer").is_admin(), "custom base=viewer -> JAMAIS admin");
        // (d) nom INCONNU (ni base, ni défini) -> JAMAIS admin (default-deny).
        assert!(!tok_au("gov-ghost").is_admin(), "rôle inconnu -> JAMAIS admin");
        assert!(!tok_au("").is_admin(), "rôle vide -> JAMAIS admin");
        // (e) ANTI-AUTO-ESCALADE : la création/édition de rôles est réservée au SUPER-ADMIN (roles_guard). Un
        // custom-admin (is_superadmin=false) ne peut donc PAS retirer ses propres denies via POST /api/roles.
        let (cp, _cptmp) = mk_test_control();
        let st = tenant_test_state("admins", "editors", "supers", Some(cp.clone()));
        let mut au_ca = tok_au("gov-admin"); // base=admin, is_superadmin=false
        au_ca.is_superadmin = false;
        let (ce, _) = tok_resp_json(role_create(State(st.clone()), Extension(au_ca), Json(json!({ "name": "gov-admin", "base_role": "admin", "deny_perms": [] }))).await).await;
        assert_eq!(ce, StatusCode::FORBIDDEN, "un custom-admin NON super-admin ne peut PAS s'auto-éditer (retirer ses denies)");
        // le deny SURVIT à la tentative.
        assert!(role_perm_denied("gov-admin", "manage_users"), "deny_perms intact après tentative d'auto-escalade");
        // (f) CONFINEMENT #39 : `client` reste réservé + confiné aux routes client-read, indépendamment de #64.
        assert!(is_builtin_role("client"), "client reste réservé (jamais custom)");
        assert!(rbac_gate("client", "/api/query", false).is_err(), "client confiné hors des routes client-read");
        // (g) raw-SQL / colonne-secret : un custom-admin avec deny raw_sql N'a PAS le SQL brut MÊME admin.
        assert!(!raw_sql_allowed(false, "gov-sqlless"), "deny raw_sql -> SQL brut refusé malgré base=admin");
        assert!(raw_sql_allowed(false, "gov-fulladmin"), "custom-admin sans deny raw_sql -> SQL brut OK (ceiling admin)");
        // nettoyage.
        let mut m = custom_roles_cell().lock();
        for k in ["gov-admin", "gov-fulladmin", "gov-editor", "gov-viewer", "gov-sqlless"] { m.remove(k); }
    }

    /// MEDIUM #59 : un sink kind=file est CONFINÉ à la racine d'export. `ledger_file_target_validate` refuse
    /// l'évasion (chemin hors racine, `..`), les liens symboliques et les non-fichiers-réguliers ; l'écriture
    /// confinée (O_NOFOLLOW + régulier) réussit sur une cible légitime, et le chemin CLI (None) reste libre.
    #[test]
    fn gov_ledger_sink_rejects_path_escape() {
        let root_s = mk_tmp_path("ledger-root");
        std::fs::create_dir_all(&root_s).unwrap();
        let root = std::path::Path::new(&root_s);
        // (a) fichier régulier (inexistant) DANS la racine -> OK.
        assert!(ledger_file_target_validate(root, &format!("{root_s}/audit.jsonl")).is_ok(), "fichier dans la racine -> OK");
        // (b) chemin absolu HORS racine -> refusé.
        assert!(ledger_file_target_validate(root, "/etc/passwd").is_err(), "chemin hors racine -> refusé");
        // (c) évasion par `..` -> refusé.
        assert!(ledger_file_target_validate(root, &format!("{root_s}/../escape.jsonl")).is_err(), ".. hors racine -> refusé");
        // (d) lien symbolique dans la racine -> refusé.
        let link = format!("{root_s}/link.jsonl");
        std::os::unix::fs::symlink("/etc/hosts", &link).unwrap();
        assert!(ledger_file_target_validate(root, &link).is_err(), "lien symbolique -> refusé");
        // (e) non-fichier-régulier (répertoire) -> refusé.
        let sub = format!("{root_s}/adir");
        std::fs::create_dir_all(&sub).unwrap();
        assert!(ledger_file_target_validate(root, &sub).is_err(), "répertoire cible -> refusé (non régulier)");
        // (f) écriture CONFINÉE régulière -> OK ; CLI (None) hors racine -> libre.
        assert!(ledger_sink_write("file", &format!("{root_s}/ok.jsonl"), &["l1".to_string()], Some(root)).is_ok(), "écriture confinée régulière -> OK");
        assert!(ledger_sink_write("file", &link, &["x".to_string()], Some(root)).is_err(), "écriture confinée sur un lien -> refusée (O_NOFOLLOW)");
        let outside = mk_tmp_path("cli-out.jsonl");
        assert!(ledger_sink_write("file", &outside, &["x".to_string()], None).is_ok(), "CLI opérateur (None) -> chemin libre");
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(&outside);
    }
