    // ============================================================================================
    // v75 — MODE ENGAGEMENT AUTORISÉ : drapeau/inertie, migration, tag d'ingest, guard auto-ban (Arm A),
    // auto-expiry + révocation des grants, validation de scope, grants par box, RBAC, invariant SACRÉ.
    // Ces tests touchent des GLOBAUX (drapeau atomique ENGAGEMENT_ON + index scope) -> sérialisés + reset.
    // ============================================================================================
    fn eng_test_reset() {
        set_engagement_mode(false);
        engagement_scope_map().write().clear();
    }
    fn mk_active(id: &str, cidr: &str, window_end: i64) -> ActiveEngagement {
        let scope = vec![cidr.to_string()];
        let matchers: Vec<(String, bool)> = scope.iter().filter_map(|c| parse_excl_item(c)).collect();
        ActiveEngagement { engagement_id: id.into(), scope, matchers, window_end, box_kind: "blackbox".into(), adapter: String::new() }
    }

    /// DRAPEAU + INERTIE : le flag pur reflète PLUME_ENGAGEMENT_MODE ; OFF (défaut) -> le tag renvoie "" pour
    /// TOUTE ip (index vide) ET action_valid_ctx(...,false) n'ajoute AUCUN refus (byte-identique).
    #[test]
    fn engagement_mode_off_is_inert() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        let mut m = HashMap::new();
        assert!(!engagement_enabled_in(&m), "absent -> off (défaut prod)");
        m.insert("PLUME_ENGAGEMENT_MODE".into(), "0".into());
        assert!(!engagement_enabled_in(&m), "=0 -> off");
        m.insert("PLUME_ENGAGEMENT_MODE".into(), "1".into());
        assert!(engagement_enabled_in(&m), "=1 -> on");
        // OFF : tag inerte quelle que soit l'ip, guard inerte (byte-identique).
        assert_eq!(engagement_tag_for_ip("db", Some("198.51.100.9")), "", "mode off -> tag vide (byte-identique)");
        assert!(action_valid_ctx("ban_ip", "198.51.100.9", false, "db").is_ok(), "mode off -> ban NON suspendu (byte-identique)");
        eng_test_reset();
    }

    /// TAG D'INGEST : seuls les `eip` DANS le scope d'un engagement actif reçoivent l'engagement_id ; les autres
    /// (et tout, mode off) restent ''. Prouve le « tag only scoped IPs » + le zéro-coût index-vide.
    #[test]
    fn engagement_tag_only_scoped_ips() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        engagement_scope_map().write().insert("eng-tag.db".into(), vec![mk_active("eng1", "198.51.100.0/24", now() + 3600)]);
        assert_eq!(engagement_tag_for_ip("eng-tag.db", Some("198.51.100.9")), "eng1", "ip scopée -> taguée");
        assert_eq!(engagement_tag_for_ip("eng-tag.db", Some("8.8.8.8")), "", "ip hors scope -> non taguée");
        assert_eq!(engagement_tag_for_ip("autre.db", Some("198.51.100.9")), "", "autre base (index absent) -> non taguée");
        assert_eq!(engagement_tag_for_ip("eng-tag.db", None), "", "pas d'ip -> non taguée");
        eng_test_reset();
    }

    /// TAG D'INGEST BOUT-EN-BOUT (mode OFF) : ingest_events_batch écrit engagement_id='' -> ligne byte-identique.
    #[test]
    fn engagement_ingest_batch_off_byte_identical() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        let conn = test_db();
        let events = vec![json!({"ts": 1000, "source": "agent", "message": "x", "src_ip": "198.51.100.9", "dedup": "z1"})];
        ingest_events_batch(&conn, ":memory:", &events, 1234, None, None).expect("batch committé");
        let eid: String = conn.query_row(&format!("SELECT engagement_id FROM event WHERE dedup='{}'", ddk(None, "z1")), [], |r| r.get(0)).unwrap();
        assert_eq!(eid, "", "mode off -> engagement_id='' (= DEFAULT, byte-identique)");
        eng_test_reset();
    }

    /// GUARD Arm A : en mode engagement, ban d'une ip scopée REFUSÉ ; ban hors-scope OK ; unban/kill/stop
    /// INCHANGÉS même sur une ip scopée ; mode off -> ban NON suspendu (byte-identique).
    #[test]
    fn engagement_auto_block_guard_arm_a() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        engagement_scope_map().write().insert("eng-guard.db".into(), vec![mk_active("eng1", "198.51.100.0/24", now() + 3600)]);
        // engagement_on=true : le BAN d'une ip scopée est suspendu (SEULEMENT le ban) — pour CE tenant.
        assert!(action_valid_ctx("ban_ip", "198.51.100.9", true, "eng-guard.db").is_err(), "ban d'une ip sous engagement -> REFUSÉ (auto-ban suspendu)");
        assert!(action_valid_ctx("ban_ip", "8.8.8.8", true, "eng-guard.db").is_ok(), "ban d'une ip HORS scope -> autorisé (enforcé)");
        // ISOLATION TENANT : un AUTRE db_path (index absent) N'EST PAS exempté par l'engagement de eng-guard.db.
        assert!(action_valid_ctx("ban_ip", "198.51.100.9", true, "autre.db").is_ok(), "ban de l'ip scopée depuis un AUTRE tenant -> autorisé (pas d'union cross-tenant)");
        // unban / kill / stop : jamais suspendus (ip scopée incluse).
        assert!(action_valid_ctx("unban_ip", "198.51.100.9", true, "eng-guard.db").is_ok(), "unban jamais suspendu");
        assert!(action_valid_ctx("kill_pid", "4242", true, "eng-guard.db").is_ok(), "kill inchangé");
        assert!(action_valid_ctx("stop_service", "nginx", true, "eng-guard.db").is_ok(), "stop inchangé");
        // engagement_on=false : byte-identique -> ban de l'ip scopée AUTORISÉ.
        assert!(action_valid_ctx("ban_ip", "198.51.100.9", false, "eng-guard.db").is_ok(), "mode off -> ban NON suspendu (byte-identique)");
        eng_test_reset();
    }

    // ============================================================================================
    // EXÉCUTEUR PAR-PLATEFORME (#20/#21) — descripteur du VOCAB FERMÉ, injection-safe, vocab clos.
    // ============================================================================================

    /// LINUX = DÉFAUT = BYTE-IDENTIQUE : platform_command("linux", ...) DOIT rendre EXACTEMENT
    /// action_command(...) pour toute action ET tout backend (nft/fail2ban/crowdsec). Zéro dérive.
    #[test]
    fn platform_exec_linux_is_byte_identical() {
        let cases = [
            ("ban_ip", "203.0.113.7"),
            ("unban_ip", "203.0.113.7"),
            ("kill_pid", "4242"),
            ("stop_service", "nginx"),
        ];
        for backend in ["nft", "fail2ban", "crowdsec", "auto"] {
            for (kind, target) in cases {
                let want = action_command(kind, target, backend, "sshd");
                let got = platform_command("linux", kind, target, backend, "sshd", None)
                    .expect("linux toujours Ok");
                assert_eq!(got, want, "linux {kind}/{backend} DOIT être byte-identique à action_command");
            }
        }
    }

    /// WINDOWS : chaque action -> la commande native VETTÉE attendue (argv fixe, slot typé substitué).
    #[test]
    fn platform_exec_windows_commands() {
        let ban = platform_command("windows", "ban_ip", "203.0.113.9", "nft", "sshd", None).unwrap();
        assert_eq!(ban.0, "netsh");
        assert_eq!(ban.1, vec!["advfirewall", "firewall", "add", "rule", "name=plume-ban-203.0.113.9", "dir=in", "action=block", "remoteip=203.0.113.9"]);
        let unban = platform_command("windows", "unban_ip", "203.0.113.9", "nft", "sshd", None).unwrap();
        assert_eq!(unban, ("netsh".into(), vec!["advfirewall".into(), "firewall".into(), "delete".into(), "rule".into(), "name=plume-ban-203.0.113.9".into()]));
        let kill = platform_command("windows", "kill_pid", "5150", "nft", "sshd", None).unwrap();
        assert_eq!(kill, ("taskkill".into(), vec!["/PID".to_string(), "5150".into(), "/F".into()]));
        let stop = platform_command("windows", "stop_service", "Spooler", "nft", "sshd", None).unwrap();
        assert_eq!(stop, ("sc".into(), vec!["stop".to_string(), "Spooler".into()]));
    }

    /// PFSENSE / FreeBSD : pfctl (ban/unban), kill, service (stop) — argv fixe + slot typé.
    #[test]
    fn platform_exec_pfsense_commands() {
        let ban = platform_command("pfsense", "ban_ip", "198.51.100.4", "nft", "sshd", None).unwrap();
        assert_eq!(ban, ("pfctl".into(), vec!["-t".to_string(), "plume_blocklist".into(), "-T".into(), "add".into(), "198.51.100.4".into()]));
        let unban = platform_command("pfsense", "unban_ip", "198.51.100.4", "nft", "sshd", None).unwrap();
        assert_eq!(unban.1[3], "delete");
        let kill = platform_command("pfsense", "kill_pid", "9001", "nft", "sshd", None).unwrap();
        assert_eq!(kill, ("kill".into(), vec!["-TERM".to_string(), "9001".into()]));
        let stop = platform_command("pfsense", "stop_service", "unbound", "nft", "sshd", None).unwrap();
        assert_eq!(stop, ("service".into(), vec!["unbound".to_string(), "stop".into()]));
    }

    /// GENERIC-APPLIANCE : gabarit BRUT admin-configuré rendu en argv sûr ; slot typé substitué,
    /// programme = 1er jeton ; gabarit absent -> Err (jamais d'exécution floue).
    #[test]
    fn platform_exec_generic_appliance() {
        let raw = "ipset add plume-blocklist {ip}";
        let got = platform_command("generic-appliance", "ban_ip", "192.0.2.55", "nft", "sshd", Some(raw)).unwrap();
        assert_eq!(got, ("ipset".into(), vec!["add".to_string(), "plume-blocklist".into(), "192.0.2.55".into()]));
        // gabarit manquant -> Err.
        assert!(platform_command("generic-appliance", "ban_ip", "192.0.2.55", "nft", "sshd", None).is_err());
        // forme --flag valeur OK (pas de k=v en generic).
        let g2 = platform_command("generic-appliance", "kill_pid", "7777", "nft", "sshd", Some("pkill --pid {pid}")).unwrap();
        assert_eq!(g2, ("pkill".into(), vec!["--pid".to_string(), "7777".into()]));
    }

    /// VOCAB FERMÉ : une action HORS enum est refusée par platform_command sur TOUTE plateforme
    /// (verrou redondant avec action_kind_valid — le descripteur n'ouvre JAMAIS le vocab).
    #[test]
    fn platform_exec_vocab_stays_closed() {
        for platform in ["linux", "windows", "pfsense", "generic-appliance"] {
            for bad in ["run_script", "exec", "notify", "custom", ""] {
                assert!(
                    platform_command(platform, bad, "203.0.113.1", "nft", "sshd", Some("echo {ip}")).is_err(),
                    "{platform}/{bad} : action hors vocab DOIT être refusée"
                );
            }
        }
        // le vocab reste EXACTEMENT ban_ip/unban_ip/kill_pid/stop_service (action_kind_valid intouché).
        assert!(action_kind_valid("run_script").is_err());
        assert!(action_kind_valid("ban_ip").is_ok());
    }

    /// INJECTION IMPOSSIBLE : plateforme inconnue, métacaractère dans la cible, placeholder inconnu,
    /// chaînage shell dans un gabarit generic -> tous REJETÉS (Err), jamais de commande construite.
    #[test]
    fn platform_exec_injection_rejected() {
        // plateforme inconnue -> Err.
        assert!(platform_command("solaris", "ban_ip", "203.0.113.1", "nft", "sshd", None).is_err());
        // cible avec métacaractère / espace (ne PASSERAIT jamais action_valid ; def-in-depth au rendu).
        assert!(platform_command("windows", "ban_ip", "1.2.3.4; rm -rf /", "nft", "sshd", None).is_err(), "ip avec ';' et espace -> refusée");
        assert!(platform_command("pfsense", "stop_service", "ng|nx", "nft", "sshd", None).is_err(), "service avec '|' -> refusé");
        assert!(platform_command("windows", "stop_service", "a b", "nft", "sshd", None).is_err(), "service avec espace -> refusé");
        assert!(platform_command("windows", "kill_pid", "$(id)", "nft", "sshd", None).is_err(), "pid non numérique -> refusé");
        // gabarit generic : placeholder INCONNU -> Err.
        assert!(platform_command("generic-appliance", "ban_ip", "203.0.113.1", "nft", "sshd", Some("fwctl block {addr}")).is_err(), "placeholder {{addr}} inconnu -> refusé");
        // gabarit generic : chaînage shell / métacaractère -> Err.
        assert!(platform_command("generic-appliance", "ban_ip", "203.0.113.1", "nft", "sshd", Some("fwctl block {ip}; reboot")).is_err(), "chaînage ';' -> refusé");
        assert!(platform_command("generic-appliance", "ban_ip", "203.0.113.1", "nft", "sshd", Some("fwctl `id` {ip}")).is_err(), "backtick -> refusé");
        assert!(platform_command("generic-appliance", "ban_ip", "203.0.113.1", "nft", "sshd", Some("fwctl block {ip} && rm x")).is_err(), "'&&' -> refusé");
        // le SLOT d'une AUTRE action ne résout pas ({pid} pour ban_ip -> {ip} attendu, {pid} reste inconnu).
        assert!(platform_command("generic-appliance", "ban_ip", "203.0.113.1", "nft", "sshd", Some("fwctl block {pid}")).is_err(), "mauvais slot -> placeholder non résolu");
    }

    /// INVARIANT SACRÉ (enforcement ≠ détection) — STRUCTUREL : (1) `rule_sql` ne substitue JAMAIS un
    /// placeholder engagement (un `__ENGAGEMENT_EXCL__` résiduel resterait LITTÉRAL -> SQL invalide visible,
    /// jamais un angle mort silencieux — garantie v55) ni les exclusions opérateur/self ; (2) le tag engagement
    /// NE RETIRE PAS les events du chemin détection (un count source-scopé les compte) ET la couverture (table
    /// `alert`) reste pleine -> l'attaquant scopé reste DÉTECTÉ+compté, juste pas auto-bloqué.
    #[test]
    fn engagement_detection_untouched_sacred_invariant() {
        // (1) aucune substitution engagement/opérateur/self dans le chemin détection (rule_sql).
        for is_soql in [false, true] {
            let compiled = rule_sql("search source=web __ENGAGEMENT_EXCL__ | stats count", is_soql, 0)
                .or_else(|_| rule_sql("SELECT COUNT(*) FROM event WHERE 1=1 /*__ENGAGEMENT_EXCL__*/", false, 0)).unwrap();
            assert!(compiled.contains("__ENGAGEMENT_EXCL__"), "rule_sql NE substitue JAMAIS __ENGAGEMENT_EXCL__ (rien retiré de la détection)");
        }
        // (2) le tag engagement n'exclut pas de la détection : des events tagués sont TOUJOURS comptés,
        //     et la couverture (table alert) les voit via le mitre hérité (enforcement≠détection : 2 moteurs).
        let conn = test_db();
        for i in 0..5 {
            conn.execute("INSERT INTO event(ts,source,category,severity,message,src_ip,engagement_id) VALUES(?1,'web','network',3,'scan','198.51.100.9','eng1')", params![100 + i]).unwrap();
        }
        let seen: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE source='web'", [], |r| r.get(0)).unwrap();
        assert_eq!(seen, 5, "les events tagués engagement restent ENTIÈREMENT visibles à la détection (aucun filtrage)");
        // l'alerte MITRE (issue de la détection) est comptée par la couverture indépendamment du tag.
        conn.execute("INSERT INTO alert(ts,rule,severity,title,mitre,engagement_id) VALUES(100,'rule.1',3,'scan','T1046','eng1')", []).unwrap();
        conn.execute("INSERT INTO alert(ts,rule,severity,title,mitre) VALUES(101,'rule.1',3,'scan','T1046')", []).unwrap();
        let cov = coverage(&conn, 0);
        assert_eq!(cov.iter().find(|(m, _, _)| m == "T1046").map(|(_, c, _)| *c), Some(2), "couverture : les 2 alertes T1046 comptées (tag engagement n'y change rien)");
    }

    /// VALIDATION DE SCOPE : refuse route par défaut (0.0.0.0/0, ::/0), masque trop large, chevauchement
    /// loopback/opérateur ; accepte un /24 public ET un /24 RFC1918 interne (pentest interne légitime).
    #[test]
    fn engagement_scope_validation() {
        let op = vec![("203.0.113.7".to_string(), false)]; // IP opérateur configurée (exacte)
        assert!(validate_engagement_scope(&[], &op).is_err(), "scope vide refusé");
        assert!(validate_engagement_scope(&["0.0.0.0/0".into()], &op).is_err(), "0.0.0.0/0 refusé");
        assert!(validate_engagement_scope(&["::/0".into()], &op).is_err(), "::/0 refusé");
        assert!(validate_engagement_scope(&["10.0.0.0/4".into()], &op).is_err(), "masque /4 (< /8) refusé");
        assert!(validate_engagement_scope(&["127.0.0.0/8".into()], &op).is_err(), "loopback refusé");
        assert!(validate_engagement_scope(&["203.0.113.0/24".into()], &op).is_err(), "scope couvrant l'IP opérateur refusé");
        assert!(validate_engagement_scope(&["198.51.100.0/24".into()], &op).is_ok(), "/24 public hors protégé accepté");
        assert!(validate_engagement_scope(&["10.10.0.0/16".into()], &op).is_ok(), "/16 RFC1918 interne accepté (pentest interne)");
    }

    /// FIX (critique) : le suffixe joker `*` contournait le plancher de masque (jamais de '/') -> "8*"
    /// exemptait ~11 /8 (8.x + 80-89.x + 8xxx::). On REJETTE tout joker et toute forme non-CIDR/non-IP-exacte.
    #[test]
    fn engagement_scope_rejects_wildcard_breadth() {
        let op: Vec<(String, bool)> = vec![];
        for tok in ["8*", "2*", "3*", "4*", "5*", "6*", "7*", "9*", "*", "20*", "8", "20", "80", "foo", "2001:*"] {
            assert!(validate_engagement_scope(&[tok.into()], &op).is_err(), "scope joker/large '{tok}' DOIT être refusé");
        }
        // les CIDR stricts équivalents au plancher restent ACCEPTÉS (rien de légitime cassé).
        assert!(validate_engagement_scope(&["8.0.0.0/8".into()], &op).is_ok(), "8.0.0.0/8 (plancher /8) accepté");
        assert!(validate_engagement_scope(&["203.0.113.7".into()], &op).is_ok(), "IP exacte v4 acceptée");
        assert!(validate_engagement_scope(&["2001:db8::/32".into()], &op).is_ok(), "/32 IPv6 (>= /16) accepté");
        assert!(validate_engagement_scope(&["2001:db8::/8".into()], &op).is_err(), "/8 IPv6 (< /16) refusé");
    }

    /// FIX TOCTOU (window_end) : un engagement dont la fenêtre est écoulée n'exempte PLUS sur le chemin chaud,
    /// même si l'index scope n'a pas encore été rafraîchi (tick 20 s) — le guard/tag se self-expirent via now().
    #[test]
    fn engagement_scope_match_self_expires_on_window_end() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        // fenêtre DÉJÀ écoulée (window_end dans le passé) mais TOUJOURS dans l'index (refresh pas encore passé).
        let expired = vec![mk_active("engX", "198.51.100.0/24", now() - 1)];
        assert_eq!(engagement_scope_match(&expired, "198.51.100.9"), None, "fenêtre écoulée -> aucun match (self-expiry chaud)");
        // même index dans la map + guard tenant : le ban n'est PLUS suspendu malgré l'entrée résiduelle.
        set_engagement_mode(true);
        engagement_scope_map().write().insert("eng-exp.db".into(), expired);
        assert!(action_valid_ctx("ban_ip", "198.51.100.9", true, "eng-exp.db").is_ok(), "engagement expiré résiduel -> auto-ban RÉTABLI");
        assert_eq!(engagement_tag_for_ip("eng-exp.db", Some("198.51.100.9")), "", "engagement expiré -> plus de tag");
        // contrôle : la MÊME entrée avec fenêtre future matche bien (le gate ne casse pas le cas nominal).
        let live = vec![mk_active("engY", "198.51.100.0/24", now() + 3600)];
        assert_eq!(engagement_scope_match(&live, "198.51.100.9"), Some("engY".into()), "fenêtre future -> match nominal");
        eng_test_reset();
    }

    /// FIX cycle de vie : un engagement 'scheduled' dont window_start est atteint s'ACTIVE (+ audit) ; un
    /// 'scheduled' dont la fenêtre est écoulée sans activation EXPIRE (+ grants révoqués) ; un 'scheduled'
    /// encore futur reste INTACT. (Avant : branche morte -> jamais activé, jamais expiré.)
    #[test]
    fn engagement_scheduled_activates_and_stale_expires() {
        let conn = test_db();
        let past = now() - 100;
        let future = now() + 3600;
        conn.execute("INSERT INTO engagement(id,name,box,scope,window_start,window_end,status,created) VALUES('s1','n','blackbox','[\"198.51.100.0/24\"]',?1,?2,'scheduled',?3)", params![past, future, now()]).unwrap();
        conn.execute("INSERT INTO engagement(id,name,box,scope,window_start,window_end,status,created) VALUES('s2','n','greybox','[\"198.51.100.0/24\"]',?1,?2,'scheduled',?3)", params![past - 200, now() - 50, now()]).unwrap();
        conn.execute("INSERT INTO engagement_grant(engagement_id,kind,status) VALUES('s2','scoped_cred','pending')", []).unwrap();
        conn.execute("INSERT INTO engagement(id,name,box,scope,window_start,window_end,status,created) VALUES('s3','n','blackbox','[\"198.51.100.0/24\"]',?1,?2,'scheduled',?3)", params![future, future + 3600, now()]).unwrap();
        let (activated, expired) = activate_due_engagements_conn(&conn, now());
        assert_eq!((activated, expired), (1, 1), "s1 activé, s2 expiré (scheduled écoulé)");
        assert_eq!(conn.query_row::<String, _, _>("SELECT status FROM engagement WHERE id='s1'", [], |r| r.get(0)).unwrap(), "active", "s1 (fenêtre ouverte) -> active");
        assert_eq!(conn.query_row::<String, _, _>("SELECT status FROM engagement WHERE id='s2'", [], |r| r.get(0)).unwrap(), "expired", "s2 (fenêtre écoulée) -> expired");
        let open_s2: i64 = conn.query_row("SELECT COUNT(*) FROM engagement_grant WHERE engagement_id='s2' AND status IN ('pending','issued')", [], |r| r.get(0)).unwrap();
        assert_eq!(open_s2, 0, "grants 'pending' de s2 révoqués à l'expiry");
        assert_eq!(conn.query_row::<String, _, _>("SELECT status FROM engagement WHERE id='s3'", [], |r| r.get(0)).unwrap(), "scheduled", "s3 (window_start futur) INTACT");
        let acts: i64 = conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind='config.engagement.activate'", [], |r| r.get(0)).unwrap();
        assert!(acts >= 1, "activation auditée (config.engagement.activate)");
        // idempotent : re-balayer ne ré-active/ré-expire rien.
        assert_eq!(activate_due_engagements_conn(&conn, now()), (0, 0), "second balayage -> aucun changement");
    }

    /// FIX rapport scopé vide : une alerte MITRE de PRODUCTION (non taguée, engagement_id='') est bien
    /// ATTRIBUÉE à l'engagement quand un event SCOPÉ existe dans la fenêtre -> le rapport n'est plus vide.
    #[test]
    fn scoped_coverage_attributes_untagged_alert_via_scoped_events() {
        let conn = test_db();
        let (ws, we) = (1000i64, 2000i64);
        conn.execute("INSERT INTO engagement(id,name,box,scope,window_start,window_end,status) VALUES('engX','n','blackbox','[\"198.51.100.0/24\"]',?1,?2,'active')", params![ws, we]).unwrap();
        // alerte de PRODUCTION : mitre hérité de la règle, engagement_id='' (jamais tagué par run_due_rules).
        conn.execute("INSERT INTO alert(ts,rule,severity,title,mitre) VALUES(1500,'rule.20',3,'scan','T1046')", []).unwrap();
        // event SCOPÉ dans la fenêtre (tagué à l'ingest par engagement_tag_for_ip).
        conn.execute("INSERT INTO event(ts,source,category,severity,message,src_ip,engagement_id) VALUES(1400,'portscan','network',3,'scan','198.51.100.9','engX')", []).unwrap();
        let out = scoped_coverage_detections(&conn, "engX", 0, ws, we);
        assert_eq!(out.len(), 1, "le rapport scopé n'est PLUS vide");
        assert_eq!(out[0]["mitre"], json!("T1046"), "T1046 attribué à l'engagement (via event scopé), pas 100 %-manqué");
        assert_eq!(out[0]["count"], json!(1));
        // GATE : sans event scopé (autre engagement, aucun event tagué) -> rapport vide (pas de sur-attribution globale).
        conn.execute("INSERT INTO engagement(id,name,box,scope,window_start,window_end,status) VALUES('engEmpty','n','blackbox','[\"203.0.113.0/24\"]',?1,?2,'active')", params![ws, we]).unwrap();
        let empty = scoped_coverage_detections(&conn, "engEmpty", 0, ws, we);
        assert!(empty.is_empty(), "aucun event scopé -> rapport scopé vide (l'alerte n'est pas sur-attribuée)");
    }

    /// La règle self-detection « engagement autorisé déclaré » est BIEN seedée + enabled, et
    /// keyée sur l'event d'audit plume-engagement (l'ouverture d'un engagement PAGE le SOC, pas seulement audit).
    #[test]
    fn engagement_declaration_has_shipped_detection_rule() {
        let conn = test_db();
        seed_detection_rules(&conn);
        let (q, sev, enabled, mitre): (String, i64, i64, String) = conn.query_row(
            "SELECT query,severity,enabled,COALESCE(mitre,'') FROM rule WHERE name='SOC: engagement autorisé déclaré (défense auto-ban baissée)'",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ).expect("règle self-detection engagement seedée");
        assert!(q.contains("source=plume-engagement") && q.contains("category=config"), "keyée sur l'audit plume-engagement : {q}");
        assert_eq!((sev, enabled), (4, 1), "sévérité 4 + enabled");
        assert_eq!(mitre, "T1562", "MITRE T1562 (Impair Defenses)");
    }

    /// GRANTS PAR BOX : blackbox=0 ; greybox=1 scoped_cred ; whitebox=scoped_cred+config_read. + box valide.
    #[test]
    fn engagement_grants_per_box() {
        assert!(engagement_box_valid("blackbox") && engagement_box_valid("greybox") && engagement_box_valid("whitebox"));
        assert!(!engagement_box_valid("purple") && !engagement_box_valid(""));
        assert_eq!(engagement_grant_kinds_for_box("blackbox"), &[] as &[&str], "blackbox : aucun grant");
        assert_eq!(engagement_grant_kinds_for_box("greybox"), &["scoped_cred"], "greybox : cred scopée");
        assert_eq!(engagement_grant_kinds_for_box("whitebox"), &["scoped_cred", "config_read"], "whitebox : cred + lecture config");
    }

    /// AUTO-EXPIRY : un engagement actif dont la fenêtre est écoulée passe 'expired' + ses grants ouverts sont
    /// révoqués (pending/issued -> revoked, TOUT box) ; un engagement encore dans sa fenêtre est intact.
    #[test]
    fn engagement_auto_expiry_flips_and_revokes_grants() {
        let conn = test_db();
        let past = now() - 100;
        let future = now() + 3600;
        conn.execute("INSERT INTO engagement(id,name,box,scope,window_start,window_end,status,created) VALUES('e1','n','whitebox','[\"198.51.100.0/24\"]',0,?1,'active',?2)", params![past, now()]).unwrap();
        conn.execute("INSERT INTO engagement_grant(engagement_id,kind,status) VALUES('e1','scoped_cred','pending')", []).unwrap();
        conn.execute("INSERT INTO engagement_grant(engagement_id,kind,status) VALUES('e1','config_read','issued')", []).unwrap();
        conn.execute("INSERT INTO engagement(id,name,box,scope,window_start,window_end,status,created) VALUES('e2','n','greybox','[\"198.51.100.0/24\"]',0,?1,'active',?2)", params![future, now()]).unwrap();
        conn.execute("INSERT INTO engagement_grant(engagement_id,kind,status) VALUES('e2','scoped_cred','pending')", []).unwrap();
        let n = expire_due_engagements_conn(&conn, now());
        assert_eq!(n, 1, "seul e1 (fenêtre écoulée) expire");
        assert_eq!(conn.query_row::<String, _, _>("SELECT status FROM engagement WHERE id='e1'", [], |r| r.get(0)).unwrap(), "expired");
        let open_e1: i64 = conn.query_row("SELECT COUNT(*) FROM engagement_grant WHERE engagement_id='e1' AND status IN ('pending','issued')", [], |r| r.get(0)).unwrap();
        assert_eq!(open_e1, 0, "TOUS les grants ouverts de e1 révoqués (grey/whitebox ne survivent pas)");
        assert_eq!(conn.query_row::<String, _, _>("SELECT status FROM engagement WHERE id='e2'", [], |r| r.get(0)).unwrap(), "active", "e2 dans sa fenêtre : intact");
        assert_eq!(conn.query_row::<String, _, _>("SELECT status FROM engagement_grant WHERE engagement_id='e2'", [], |r| r.get(0)).unwrap(), "pending", "grant de e2 intact");
        // audit non-purgeable écrit (source plume-engagement, origin daemon).
        let audited: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE source='plume-engagement' AND origin='daemon'", [], |r| r.get(0)).unwrap();
        assert!(audited >= 1, "expiry auditée (event plume-engagement non-purgeable)");
    }

    /// RBAC : /api/engagements/active = agent (seam pull) ; le reste = admin-only (break-glass). Editor/viewer
    /// refusés ; admin OK ; agent limité à /active.
    #[test]
    fn engagement_rbac_admin_only_except_active() {
        assert_eq!(route_min_role("/api/engagements", true), MinRole::Admin, "create = admin");
        assert_eq!(route_min_role("/api/engagements", false), MinRole::Admin, "list = admin");
        assert_eq!(route_min_role("/api/engagements/eng_x", false), MinRole::Admin, "get = admin");
        assert_eq!(route_min_role("/api/engagements/eng_x/end", true), MinRole::Admin, "end = admin");
        assert_eq!(route_min_role("/api/engagements/active", false), MinRole::Agent, "active = agent (seam pull)");
        assert!(rbac_gate("admin", "/api/engagements", true).is_ok(), "admin crée");
        assert!(rbac_gate("editor", "/api/engagements", true).is_err(), "editor NE crée PAS");
        assert!(rbac_gate("viewer", "/api/engagements", false).is_err(), "viewer NE lit PAS (admin-only)");
        assert!(rbac_gate("agent", "/api/engagements/active", false).is_ok(), "agent PULL /active");
        assert!(rbac_gate("editor", "/api/engagements/active", false).is_err(), "editor ≠ agent -> pas /active");
    }

    /// SEAM AUTH (BLOCKER A) : `agent_bearer_path` AUTHENTIFIE un token Bearer d'agent EXACTEMENT sur le seam
    /// machine — ingest/métriques/responder + le PULL enforcer /api/engagements/active — et RIEN d'autre. Avant
    /// le fix, /active était OMIS -> le token agent n'établissait aucune identité -> 401 (avant même route_min_role
    /// /handler). DÉFAUT FERMÉ : aucune route UI/admin (ni la GESTION d'engagements create/end/list/get) n'est
    /// authentifiable par un token agent -> elle retombe sur 401.
    #[test]
    fn agent_bearer_path_allows_seam_only() {
        for p in ["/api/ingest", "/api/ingest/minio", "/api/ingest/journal", "/api/metrics/prom",
                  "/api/metrics/write", "/loki/api/v1/push", "/api/actions/pending", "/api/actions/result",
                  "/api/engagements/active"] {
            assert!(agent_bearer_path(p), "token agent DOIT authentifier sur le seam {p}");
        }
        // BLOCKER A : /active est authentifiable (sinon 401, jamais atteindre route_min_role/handler).
        assert!(agent_bearer_path("/api/engagements/active"), "BLOCKER A : /active authentifiable par token agent");
        // Tout le reste (UI/admin + gestion d'engagements) N'EST PAS authentifiable par un token agent.
        for p in ["/api/engagements", "/api/engagements/eng_x", "/api/engagements/eng_x/end", "/api/users",
                  "/api/overview", "/api/rules", "/api/mode", "/api/actions", "/api/query", "/", "/api/me"] {
            assert!(!agent_bearer_path(p), "token agent NE doit PAS authentifier {p} (défaut fermé)");
        }
    }

    /// SEAM PULL enforcer bout-en-bout (BLOCKER A/B côté daemon). Le handler /api/engagements/active :
    /// (1) EXIGE un token agent HOST-BOUND -> viewer/cookie et agent-sans-hôte -> 403 ;
    /// (2) mode OFF -> 200 `[]` (JAMAIS 401/404 : l'adaptateur reçoit une réponse propre et 'reconcile' au lieu
    ///     de churner 'revert-all') — AUCUNE donnée d'engagement ;
    /// (3) mode ON -> n'expose QUE {engagement_id,scope,window_end,box,adapter} — JAMAIS reason/authorizer/secret
    ///     ni un champ en trop.
    #[tokio::test]
    async fn engagements_active_agent_host_bound_and_off_is_empty() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let mk_au = |name: &str, role: &str| AuthUser {
            name: name.into(), role: role.into(), tenant: "default".into(),
            is_superadmin: false, method: "bearer".into(), csrf: String::new(), env: None,
        };
        // (1) non-agent -> 403.
        let r = engagements_active(State(st.clone()), Extension(mk_au("web-01", "viewer"))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "viewer -> 403 (jamais lu hors token agent)");
        // (1b) agent NON host-bound (name vide) -> 403 (anti-spoof : un token non lié ne PULL pas).
        let r = engagements_active(State(st.clone()), Extension(mk_au("", "agent"))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "agent sans hôte lié -> 403");
        // (2) agent host-bound + mode OFF -> 200 [] (jamais 401/404 ; aucune donnée d'engagement).
        let r = engagements_active(State(st.clone()), Extension(mk_au("web-01", "agent"))).await;
        assert_eq!(r.status(), StatusCode::OK, "agent host-bound -> 200 (jamais 401/404)");
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&b).unwrap(), json!([]), "mode off -> [] (aucune donnée d'engagement)");
        // (3) mode ON + engagement actif portant reason/authorizer SECRETS : n'expose QUE les 5 champs sûrs.
        set_engagement_mode(true);
        {
            let c = st.db.lock();
            c.execute(
                "INSERT INTO engagement(id,name,box,scope,window_start,window_end,authorizer,reason,status,adapter,created) \
                 VALUES('eng-seam','pentest','blackbox','[\"198.51.100.0/24\"]',0,?1,'SECRET-AUTH','SECRET-REASON','active','host-adapter',?2)",
                params![now() + 3600, now()],
            ).unwrap();
        }
        let r = engagements_active(State(st.clone()), Extension(mk_au("web-01", "agent"))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        let v: Value = serde_json::from_slice(&b).unwrap();
        let arr = v.as_array().expect("tableau JSON");
        assert_eq!(arr.len(), 1, "1 engagement actif exposé");
        let obj = arr[0].as_object().unwrap();
        assert_eq!(obj["engagement_id"], json!("eng-seam"));
        assert_eq!(obj["scope"], json!(["198.51.100.0/24"]));
        assert_eq!(obj["box"], json!("blackbox"));
        assert_eq!(obj["adapter"], json!("host-adapter"));
        assert!(obj["window_end"].as_i64().unwrap() > now(), "window_end (borne) exposé");
        // AUCUNE fuite : EXACTEMENT 5 champs, jamais reason/authorizer/status/secret ni un champ en trop.
        assert_eq!(obj.len(), 5, "EXACTEMENT 5 champs (engagement_id,scope,window_end,box,adapter)");
        for leak in ["reason", "authorizer", "status", "name", "created", "created_by", "id", "env_id"] {
            assert!(obj.get(leak).is_none(), "le champ '{leak}' NE doit PAS fuiter vers l'agent");
        }
        let s = String::from_utf8_lossy(&b);
        assert!(!s.contains("SECRET-REASON") && !s.contains("SECRET-AUTH"), "aucun reason/authorizer secret dans la réponse agent");
        eng_test_reset();
    }

    // ============================================================================================
    // v75 — PROVISIONING PLUME-LOCAL (mint/révoque un credential plume SCOPÉ IN-PROCESS).
    // ============================================================================================
    async fn eng_resp_json<R: axum::response::IntoResponse>(r: R) -> (StatusCode, Value) {
        let r = r.into_response();
        let code = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        (code, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }
    fn eng_admin_au() -> AuthUser {
        AuthUser { name: "root".into(), role: "admin".into(), tenant: "default".into(),
            is_superadmin: false, method: "cookie".into(), csrf: String::new(), env: None }
    }
    fn eng_basic(u: &str, p: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}")))
    }

    /// GREYBOX : create -> minte 1 credential VIEWER scopé ; s'authentifie en viewer (pas admin) ; /end ->
    /// compte supprimé + grant révoqué -> l'auth échoue.
    #[tokio::test]
    async fn engagement_greybox_mints_viewer_cred_revoked_on_end() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let admin = eng_admin_au();
        let body = json!({ "box": "greybox", "scope": ["198.51.100.0/24"], "reason": "pentest", "window_end": now() + 3600 });
        let (code, v) = eng_resp_json(engagement_create(State(st.clone()), Extension(admin.clone()), Json(body)).await).await;
        assert_eq!(code, StatusCode::OK, "création greybox OK");
        let id = v["id"].as_str().unwrap().to_string();
        let creds = v["credentials"].as_array().unwrap();
        assert_eq!(creds.len(), 1, "greybox : EXACTEMENT 1 credential (scoped_cred)");
        assert_eq!(creds[0]["kind"], json!("scoped_cred"));
        assert_eq!(creds[0]["role"], json!("viewer"), "greybox -> rôle viewer (low-priv)");
        let username = creds[0]["username"].as_str().unwrap().to_string();
        let secret = creds[0]["secret"].as_str().unwrap().to_string();
        assert!(username.starts_with(ENG_CRED_PREFIX), "nom réservé eng-cred-*");
        {
            let conn = st.db.lock();
            let (gk, gref, gst): (String, String, String) = conn.query_row(
                "SELECT kind, ref, status FROM engagement_grant WHERE engagement_id=?1", params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
            assert_eq!((gk.as_str(), gref.as_str(), gst.as_str()), ("scoped_cred", username.as_str(), "issued"),
                "grant issued, ref=username (handle non secret), jamais le secret");
            let urole: String = conn.query_row("SELECT role FROM user WHERE name=?1", params![username], |r| r.get(0)).unwrap();
            assert_eq!(urole, "viewer");
        }
        // s'authentifie en viewer ; ne franchit PAS un gate admin.
        let basic = eng_basic(&username, &secret);
        assert_eq!(authenticate(&st, &basic), Some((username.clone(), "viewer".into())), "credential -> viewer");
        assert!(rbac_gate("viewer", "/api/users", false).is_err(), "viewer ne peut PAS administrer");
        // /end -> INVALIDATION : compte supprimé + grant révoqué -> auth échoue.
        let r = engagement_end(State(st.clone()), Extension(admin.clone()), Path(id.clone())).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(authenticate(&st, &basic), None, "après /end : le credential ne s'authentifie plus");
        {
            let conn = st.db.lock();
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM user WHERE name=?1", params![username], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "compte minté SUPPRIMÉ de la table user");
            let gst: String = conn.query_row("SELECT status FROM engagement_grant WHERE engagement_id=?1", params![id], |r| r.get(0)).unwrap();
            assert_eq!(gst, "revoked");
        }
        eng_test_reset();
    }

    /// WHITEBOX : create -> minte un credential ADMIN scopé (élevé mais borné) + grant config_read issued ;
    /// s'authentifie en admin ; le secret est rendu UNE FOIS (create) et JAMAIS par GET ; /end -> révoqué.
    #[tokio::test]
    async fn engagement_whitebox_admin_scoped_plus_config_read_secret_once() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let admin = eng_admin_au();
        let body = json!({ "box": "whitebox", "scope": ["198.51.100.0/24"], "reason": "audit interne", "window_end": now() + 3600 });
        let (code, v) = eng_resp_json(engagement_create(State(st.clone()), Extension(admin.clone()), Json(body)).await).await;
        assert_eq!(code, StatusCode::OK);
        let id = v["id"].as_str().unwrap().to_string();
        let creds = v["credentials"].as_array().unwrap();
        assert_eq!(creds.len(), 2, "whitebox : scoped_cred + config_read");
        assert_eq!(creds[0]["kind"], json!("scoped_cred"));
        assert_eq!(creds[0]["role"], json!("admin"), "whitebox -> rôle admin (élevé, mais borné engagement + hard-expiry)");
        assert_eq!(creds[1]["kind"], json!("config_read"), "config_read enregistré (capacité lecture seule)");
        assert!(creds[1].get("secret").is_none(), "config_read : aucune sécret (capacité, pas un credential)");
        let username = creds[0]["username"].as_str().unwrap().to_string();
        let secret = creds[0]["secret"].as_str().unwrap().to_string();
        assert_eq!(authenticate(&st, &eng_basic(&username, &secret)), Some((username.clone(), "admin".into())), "credential whitebox -> admin scopé");
        // les DEUX grants sont 'issued' ; config_read a un ref marqueur (pas un secret).
        {
            let conn = st.db.lock();
            let issued: i64 = conn.query_row("SELECT COUNT(*) FROM engagement_grant WHERE engagement_id=?1 AND status='issued'", params![id], |r| r.get(0)).unwrap();
            assert_eq!(issued, 2, "scoped_cred + config_read tous deux 'issued'");
            let cr_ref: String = conn.query_row("SELECT ref FROM engagement_grant WHERE engagement_id=?1 AND kind='config_read'", params![id], |r| r.get(0)).unwrap();
            assert_eq!(cr_ref, "cap:config_read");
        }
        // GET ne ré-expose JAMAIS le secret (ni en clair nulle part).
        let (_c, gv) = eng_resp_json(engagement_get(State(st.clone()), Extension(admin.clone()), Path(id.clone())).await).await;
        assert!(!gv.to_string().contains(&secret), "GET /api/engagements/:id ne ré-expose JAMAIS le secret minté");
        assert!(gv["grants"].as_array().unwrap().iter().any(|g| g["ref"] == json!(username)), "GET expose le ref (username) mais pas le secret");
        // /end -> auth échoue + config_read révoqué.
        let r = engagement_end(State(st.clone()), Extension(admin.clone()), Path(id.clone())).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(authenticate(&st, &eng_basic(&username, &secret)), None, "après /end : credential whitebox invalidé");
        {
            let conn = st.db.lock();
            let revoked: i64 = conn.query_row("SELECT COUNT(*) FROM engagement_grant WHERE engagement_id=?1 AND status='revoked'", params![id], |r| r.get(0)).unwrap();
            assert_eq!(revoked, 2, "scoped_cred + config_read tous deux révoqués à la fin");
        }
        eng_test_reset();
    }

    /// HARD-EXPIRY (double-garde horloge-murale) : un credential ne s'authentifie PAS passé window_end MÊME si
    /// le sweep n'a pas tourné (engagement encore 'active', grant encore 'issued', compte encore présent) ;
    /// et s'authentifie NORMALEMENT dans la fenêtre.
    #[tokio::test]
    async fn engagement_cred_hard_expires_at_window_end_even_if_sweep_late() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let dead_user = format!("{ENG_CRED_PREFIX}dead");
        let live_user = format!("{ENG_CRED_PREFIX}live");
        let secret = "pentest-secret-abcdef012345";
        let hash = hash_pw(secret).unwrap();
        {
            let conn = st.db.lock();
            // (a) engagement ENCORE 'active' (sweep PAS passé) mais window_end DÉJÀ écoulé.
            conn.execute("INSERT INTO engagement(id,name,box,scope,window_start,window_end,status,created) VALUES('edead','n','greybox','[\"198.51.100.0/24\"]',0,?1,'active',?2)", params![now() - 5, now()]).unwrap();
            conn.execute("INSERT INTO engagement_grant(engagement_id,kind,ref,status) VALUES('edead','scoped_cred',?1,'issued')", params![dead_user]).unwrap();
            conn.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,'viewer')", params![dead_user, hash]).unwrap();
            // (b) engagement ouvert (fenêtre future) -> credential valide.
            conn.execute("INSERT INTO engagement(id,name,box,scope,window_start,window_end,status,created) VALUES('elive','n','greybox','[\"198.51.100.0/24\"]',0,?1,'active',?2)", params![now() + 3600, now()]).unwrap();
            conn.execute("INSERT INTO engagement_grant(engagement_id,kind,ref,status) VALUES('elive','scoped_cred',?1,'issued')", params![live_user]).unwrap();
            conn.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,'viewer')", params![live_user, hash]).unwrap();
        }
        assert_eq!(authenticate(&st, &eng_basic(&dead_user, secret)), None,
            "window_end écoulé -> auth REFUSÉE même si le sweep n'a pas tourné (compte encore présent)");
        assert_eq!(authenticate(&st, &eng_basic(&live_user, secret)), Some((live_user.clone(), "viewer".into())),
            "fenêtre ouverte -> auth OK");
        {
            let conn = st.db.lock();
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM user WHERE name=?1", params![dead_user], |r| r.get(0)).unwrap();
            assert_eq!(n, 1, "le compte expiré est TOUJOURS présent : c'est la HARD-EXPIRY (fenêtre), pas la suppression, qui bloque l'auth");
        }
        eng_test_reset();
    }

    /// SWEEP D'EXPIRY : quand l'auto-expiry révoque les grants d'un engagement, le compte minté est SUPPRIMÉ
    /// (invalidé) -> l'auth échoue. Couvre la révocation par le sweep de fond (pas seulement /end).
    #[test]
    fn engagement_sweep_expiry_deletes_minted_user_and_blocks_auth() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let username = format!("{ENG_CRED_PREFIX}sweep");
        let secret = "pentest-secret-sweep-000000";
        let hash = hash_pw(secret).unwrap();
        {
            let conn = st.db.lock();
            conn.execute("INSERT INTO engagement(id,name,box,scope,window_start,window_end,status,created) VALUES('esw','n','greybox','[\"198.51.100.0/24\"]',0,?1,'active',?2)", params![now() - 5, now()]).unwrap();
            conn.execute("INSERT INTO engagement_grant(engagement_id,kind,ref,status) VALUES('esw','scoped_cred',?1,'issued')", params![username]).unwrap();
            conn.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,'viewer')", params![username, hash]).unwrap();
            assert_eq!(expire_due_engagements_conn(&conn, now()), 1, "1 engagement expiré par le sweep");
            assert_eq!(conn.query_row::<String, _, _>("SELECT status FROM engagement_grant WHERE engagement_id='esw'", [], |r| r.get(0)).unwrap(), "revoked");
            let ucount: i64 = conn.query_row("SELECT COUNT(*) FROM user WHERE name=?1", params![username], |r| r.get(0)).unwrap();
            assert_eq!(ucount, 0, "sweep d'expiry : compte minté SUPPRIMÉ (invalidé)");
        }
        assert_eq!(authenticate(&st, &eng_basic(&username, secret)), None, "après sweep d'expiry : auth échoue");
        eng_test_reset();
    }

    /// MODE OFF : create 409 (inerte, aucun mint) ; préfixe réservé refusé à la création interactive.
    #[tokio::test]
    async fn engagement_mode_off_no_mint_and_prefix_reserved() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset(); // mode OFF
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let admin = eng_admin_au();
        let body = json!({ "box": "greybox", "scope": ["198.51.100.0/24"], "reason": "x", "window_end": now() + 3600 });
        let r = engagement_create(State(st.clone()), Extension(admin.clone()), Json(body)).await;
        assert_eq!(r.status(), StatusCode::CONFLICT, "mode off : create 409 (inerte)");
        {
            let conn = st.db.lock();
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM user WHERE name LIKE 'eng-cred-%'", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "mode off : AUCUN credential minté");
        }
        // préfixe réservé : user_create refuse un nom eng-cred-* (aucun compte durable ne l'usurpe).
        let r = user_create(State(st.clone()), Extension(admin.clone()),
            Json(json!({ "name": "eng-cred-x", "password": "longenoughpw12", "role": "viewer" }))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "user_create REFUSE le préfixe réservé");
        eng_test_reset();
    }

    /// INVARIANT SACRÉ : le provisioning change ce que le TESTEUR ATTEINT (auth), JAMAIS ce que le SOC
    /// ENREGISTRE — 0 alerte, 0 event de collecte (seul l'audit plume-engagement), 0 règle modifiée.
    #[tokio::test]
    async fn engagement_provisioning_preserves_sacred_invariant() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let rules_before: i64 = { let c = st.db.lock(); c.query_row("SELECT COUNT(*) FROM rule", [], |r| r.get(0)).unwrap() };
        let body = json!({ "box": "whitebox", "scope": ["198.51.100.0/24"], "reason": "audit", "window_end": now() + 3600 });
        let r = engagement_create(State(st.clone()), Extension(eng_admin_au()), Json(body)).await;
        assert_eq!(r.status(), StatusCode::OK);
        let c = st.db.lock();
        let alerts: i64 = c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
        assert_eq!(alerts, 0, "provisioning n'écrit AUCUNE alerte (détection intacte)");
        let non_audit: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE source<>'plume-engagement'", [], |r| r.get(0)).unwrap();
        assert_eq!(non_audit, 0, "provisioning n'écrit AUCUN event de collecte (seul l'audit plume-engagement)");
        let rules_after: i64 = c.query_row("SELECT COUNT(*) FROM rule", [], |r| r.get(0)).unwrap();
        assert_eq!(rules_before, rules_after, "provisioning ne modifie AUCUNE règle de détection");
        drop(c);
        eng_test_reset();
    }

    /// CONTAINMENT eng-cred (whitebox=admin) : le credential d'engagement est LECTURE SEULE. TOUTE mutation
    /// est refusée (anti-persistance post-fenêtre + détection non réductible), MÊME avec le rôle admin ; la
    /// LECTURE reste ouverte (visibilité whitebox). INERTE pour un compte normal (byte-identique).
    #[test]
    fn engagement_cred_write_gate_readonly_no_persistence_no_detection_cut() {
        let cred = format!("{ENG_CRED_PREFIX}deadbeef");
        // MUTATIONS de PERSISTANCE / réduction de détection : REFUSÉES pour un eng-cred (quel que soit le rôle
        // que rbac_gate lui aurait accordé). Ce sont exactement les vecteurs d'échappement du hard-expiry.
        for p in ["/api/users", "/api/users/5", "/api/password", "/api/mode", "/api/engagements",
                  "/api/rules", "/api/rules/5", "/api/connectors", "/api/sources/settings",
                  "/api/notifiers", "/api/actions", "/api/playbooks"] {
            let _ = p; // le gate est volontairement path-agnostic (fail-closed : aucune route future oubliée)
            assert!(engagement_cred_write_gate(&cred, true).is_err(),
                "eng-cred REFUSÉ en écriture sur {p} (anti-persistance / détection non réductible)");
        }
        // LECTURE (dont query/search : mutating=false) : AUTORISÉE -> la visibilité whitebox est intacte.
        assert!(engagement_cred_write_gate(&cred, false).is_ok(), "eng-cred LIT (visibilité whitebox)");
        // INVARIANT byte-identique : un compte NORMAL (même admin) n'est JAMAIS affecté par ce gate.
        assert!(engagement_cred_write_gate("root", true).is_ok(), "compte normal admin : gate INERTE (mutation OK)");
        assert!(engagement_cred_write_gate("svc-metrics", true).is_ok(), "compte normal : gate INERTE");
        assert!(engagement_cred_write_gate("root", false).is_ok(), "compte normal : lecture OK");
        // le code d'erreur est bien un 403 (refus d'autorisation, pas un 401/409).
        assert_eq!(engagement_cred_write_gate(&cred, true).unwrap_err().0, StatusCode::FORBIDDEN);
    }

    /// MULTI-TENANT (PLUME_MULTI_TENANT=1) : le provisioning plume-local minte dans la base TENANT, mais l'auth
    /// résout le control-plane (platform_user) -> le credential serait MORT. engagement_create REFUSE donc le
    /// scoped_cred (409) AVANT tout mint (ni grant 'issued' trompeur, ni secret inutilisable rendu).
    #[tokio::test]
    async fn engagement_multitenant_refuses_scoped_cred_before_mint() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let (cp, _cptmp) = mk_test_control();
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
        assert!(st.tenants.control.is_some(), "mode 1 : control-plane présent");
        let admin = eng_admin_au();
        // greybox (scoped_cred seul) ET whitebox (scoped_cred + config_read) sont tous deux refusés.
        for box_kind in ["greybox", "whitebox"] {
            let body = json!({ "box": box_kind, "scope": ["198.51.100.0/24"], "reason": "pentest", "window_end": now() + 3600 });
            let (code, v) = eng_resp_json(engagement_create(State(st.clone()), Extension(admin.clone()), Json(body)).await).await;
            assert_eq!(code, StatusCode::CONFLICT, "{box_kind} : provisioning scoped_cred REFUSÉ en mode 1");
            assert!(v.get("credentials").is_none(), "aucun secret rendu ({box_kind})");
            assert!(v["error"].as_str().unwrap_or("").contains("multi-tenant"), "erreur explicite multi-tenant");
        }
        eng_test_reset();
    }

