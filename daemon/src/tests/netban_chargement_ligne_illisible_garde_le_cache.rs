// `P10.7-f` (restes hors handlers/) — LE CHARGEMENT DU STORE DE BANS NE REND JAMAIS UNE MAP PARTIELLE
// POUR UNE RAISON PASSAGÈRE, ET UNE LIGNE ABÎMÉE NE FIGE PLUS LE STORE. `auth::netban_try_load_cap`
// aplatissait son parcours (`.flatten()`) : une ligne illisible était sautée (son ban levé sans un mot), un
// pas raté du moteur tarissait l'itérateur, et `Some(map partielle)` REMPLAÇAIT le dernier bon instantané.
// Deux causes, deux traitements (`auth::netban_charger_cap`) : un PAS raté rend `Err` et `netban_reload`
// garde l'instantané ; une CELLULE illisible est permanente et se juge sur sa ligne — échéance illisible :
// IP BLOQUÉE ; IP illisible : ligne sautée et comptée. Témoins : échéance illisible (cellule TEXTE), table
// saine, table vide, pas raté (vue temporaire), démarrage, valve de levée, pose, IP illisible (BLOB), et la
// ligne de journal dédupliquée lue sur le stderr d'un sous-processus. Les témoins qui touchent le cache
// global prennent `NETBAN_TEST_LOCK` (déclaré dans `netban.rs`, même module de test).

    fn netban_chargement_poser(c: &Connection, ip: &str, exp: Option<i64>) {
        c.execute(
            "INSERT INTO net_ban(ip, reason, created_ts, expires_ts, created_by, env_id) VALUES (?1,'t',0,?2,'op','prod')",
            params![ip, exp],
        )
        .unwrap();
    }

    #[test]
    fn netban_chargement_echeance_illisible_tient_l_ip_bloquee_et_charge_le_reste() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let c = test_db();
        let loin = now() + 3600;
        netban_chargement_poser(&c, "203.0.113.201", None);
        netban_chargement_poser(&c, "203.0.113.202", Some(loin));
        netban_chargement_poser(&c, "203.0.113.203", Some(loin + 60));
        netban_reload(&c);
        assert!(net_ban_is_blocked("203.0.113.203", now()), "contrôle positif : le ban est chargé avant la corruption");
        // La cellule devient un TEXTE non entier (affinité INTEGER impuissante) : la requête reste saine,
        // seule la lecture de CETTE cellule échoue.
        c.execute("UPDATE net_ban SET expires_ts='jamais' WHERE ip='203.0.113.203'", []).unwrap();
        let typ: String =
            c.query_row("SELECT typeof(expires_ts) FROM net_ban WHERE ip='203.0.113.203'", [], |r| r.get(0)).unwrap();
        assert_eq!(typ, "text", "la fixture doit porter une cellule réellement indécodable en i64");
        let ch = netban_charger_cap(&c, NETBAN_CACHE_CAP).expect("une cellule illisible n'est pas un pas raté");
        assert_eq!((ch.ip_illisibles, ch.echeances_illisibles), (0, 1), "la ligne est jugée ET comptée");
        let attendu: HashMap<String, Option<i64>> = [
            ("203.0.113.201".to_string(), None),
            ("203.0.113.202".to_string(), Some(loin)),
            ("203.0.113.203".to_string(), None),
        ]
        .into_iter()
        .collect();
        assert_eq!(ch.map, attendu, "échéance illisible = IP tenue bloquée sans échéance, le reste chargé tel quel");
        netban_reload(&c);
        for ip in ["203.0.113.201", "203.0.113.202", "203.0.113.203"] {
            assert!(net_ban_is_blocked(ip, now()), "{ip} reste enforcée");
        }
    }

    /// SONDE_DEMARRAGE du vérificateur : le préchauffage d'un cache vide sur une base qui porte déjà une
    /// ligne illisible enforce les TROIS bans (zéro avant cette correction, deux avant le lot).
    #[test]
    fn netban_chargement_demarrage_avec_ligne_illisible_enforce_tout() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let c = test_db();
        let loin = now() + 3600;
        netban_chargement_poser(&c, "192.0.2.41", None);
        netban_chargement_poser(&c, "192.0.2.42", Some(loin));
        netban_chargement_poser(&c, "192.0.2.43", Some(loin));
        c.execute("UPDATE net_ban SET expires_ts='jamais' WHERE ip='192.0.2.43'", []).unwrap();
        netban_reload(&c);
        let bloquees: Vec<&str> =
            ["192.0.2.41", "192.0.2.42", "192.0.2.43"].into_iter().filter(|ip| net_ban_is_blocked(ip, now())).collect();
        assert_eq!(bloquees, ["192.0.2.41", "192.0.2.42", "192.0.2.43"], "démarrage : les trois bans enforcés");
    }

    /// SONDE_VALVE : la valve `DELETE /api/netban/{ip}` lève RÉELLEMENT une IP saine quand une AUTRE ligne est
    /// illisible, et la ligne illisible elle-même reste levable par la même valve.
    #[test]
    fn netban_chargement_valve_leve_malgre_une_ligne_illisible() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let c = test_db();
        netban_chargement_poser(&c, "192.0.2.51", None);
        netban_chargement_poser(&c, "192.0.2.52", None);
        netban_reload(&c);
        assert!(net_ban_is_blocked("192.0.2.51", now()), "contrôle");
        c.execute("UPDATE net_ban SET expires_ts='jamais' WHERE ip='192.0.2.52'", []).unwrap();
        assert_eq!(netban_remove(&c, "192.0.2.51"), Ok(1));
        assert!(!net_ban_is_blocked("192.0.2.51", now()), "la levée répondue est une levée réelle");
        assert!(net_ban_is_blocked("192.0.2.52", now()), "la ligne illisible reste bloquée (fail-closed)");
        assert_eq!(netban_remove(&c, "192.0.2.52"), Ok(1));
        assert!(!net_ban_is_blocked("192.0.2.52", now()), "la ligne illisible se lève par la valve");
    }

    /// SONDE_POSE : une pose rendue `Arme` est enforcée malgré une autre ligne illisible, et une nouvelle pose
    /// sur l'IP abîmée RÉPARE sa cellule.
    #[test]
    fn netban_chargement_pose_armee_est_enforcee_et_repare() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let c = test_db();
        let loin = now() + 3600;
        netban_chargement_poser(&c, "192.0.2.61", Some(loin));
        netban_reload(&c);
        c.execute("UPDATE net_ban SET expires_ts='jamais' WHERE ip='192.0.2.61'", []).unwrap();
        assert!(matches!(netban_upsert(&c, "192.0.2.62", None, "t", "op", "prod"), PoseDeBan::Arme));
        assert!(net_ban_is_blocked("192.0.2.62", now()), "Arme = enforcée");
        assert!(net_ban_is_blocked("192.0.2.61", now()), "la ligne illisible reste bloquée");
        assert!(matches!(netban_upsert(&c, "192.0.2.61", Some(loin), "t", "op", "prod"), PoseDeBan::Arme));
        let typ: String =
            c.query_row("SELECT typeof(expires_ts) FROM net_ban WHERE ip='192.0.2.61'", [], |r| r.get(0)).unwrap();
        assert_eq!(typ, "integer", "la nouvelle pose a réécrit la cellule");
        let ch = netban_charger_cap(&c, NETBAN_CACHE_CAP).expect("lecture réussie");
        assert_eq!(ch.echeances_illisibles, 0);
        assert_eq!(ch.map.get("192.0.2.61"), Some(&Some(loin)), "l'échéance réparée est relue");
    }

    /// IP illisible (BLOB dans la colonne TEXT) : on ne sait pas qui bloquer, et la valve (paramètre texte) ne
    /// pourrait jamais la lever -> ligne SAUTÉE, et COMPTÉE ; le reste charge.
    #[test]
    fn netban_chargement_ip_illisible_sautee_et_comptee() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let c = test_db();
        netban_chargement_poser(&c, "203.0.113.242", None);
        c.execute(
            "INSERT INTO net_ban(ip, reason, created_ts, expires_ts, created_by, env_id) \
             VALUES (CAST('203.0.113.241' AS BLOB),'t',0,NULL,'op','prod')",
            [],
        )
        .unwrap();
        let typ: String = c.query_row("SELECT typeof(ip) FROM net_ban WHERE ip <> '203.0.113.242'", [], |r| r.get(0)).unwrap();
        assert_eq!(typ, "blob", "la fixture porte une IP réellement illisible en texte");
        let ch = netban_charger_cap(&c, NETBAN_CACHE_CAP).expect("une IP illisible n'est pas un pas raté");
        assert_eq!((ch.ip_illisibles, ch.echeances_illisibles), (1, 0), "la ligne sautée est COMPTÉE");
        assert_eq!(ch.map.len(), 1);
        netban_reload(&c);
        assert!(net_ban_is_blocked("203.0.113.242", now()), "le reste est chargé");
    }

    #[test]
    fn netban_chargement_table_saine_rend_la_meme_map() {
        let c = test_db();
        let loin = now() + 3600;
        netban_chargement_poser(&c, "198.51.100.211", None);
        netban_chargement_poser(&c, "198.51.100.212", Some(loin));
        netban_chargement_poser(&c, "::ffff:198.51.100.213", Some(loin + 5));
        let (map, tronque) = netban_try_load_cap(&c, NETBAN_CACHE_CAP).expect("table saine : lecture réussie");
        let attendu: HashMap<String, Option<i64>> = [
            ("198.51.100.211".to_string(), None),
            ("198.51.100.212".to_string(), Some(loin)),
            ("198.51.100.213".to_string(), Some(loin + 5)),
        ]
        .into_iter()
        .collect();
        assert_eq!(map, attendu, "chemin nominal inchangé (repli ::ffff: compris)");
        assert!(!tronque);
        // Plafond et troncature identiques : cap=2 garde le permanent puis l'échéance la plus lointaine.
        let (map2, tronque2) = netban_try_load_cap(&c, 2).expect("lecture réussie");
        assert!(tronque2, "la troncature reste DITE");
        assert_eq!(map2.len(), 2);
        assert!(map2.contains_key("198.51.100.211") && map2.contains_key("198.51.100.213"));
    }

    #[test]
    fn netban_chargement_table_vide_remplace_le_cache() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let c = test_db();
        netban_chargement_poser(&c, "203.0.113.221", None);
        netban_reload(&c);
        assert!(net_ban_is_blocked("203.0.113.221", now()), "contrôle positif");
        c.execute("DELETE FROM net_ban", []).unwrap();
        let (map, tronque) = netban_try_load_cap(&c, NETBAN_CACHE_CAP).expect("table vide = lecture RÉUSSIE");
        assert!(map.is_empty() && !tronque);
        netban_reload(&c);
        assert!(!net_ban_is_blocked("203.0.113.221", now()), "table vide : levée légitime, le cache est remplacé");
    }

    #[test]
    fn netban_chargement_pas_rate_du_moteur_garde_le_cache() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let c = test_db();
        netban_chargement_poser(&c, "203.0.113.231", None);
        netban_chargement_poser(&c, "203.0.113.232", Some(now() + 3600));
        netban_reload(&c);
        assert!(net_ban_is_blocked("203.0.113.231", now()) && net_ban_is_blocked("203.0.113.232", now()));
        // Une vue TEMPORAIRE masque la table (le schéma temp est résolu en premier) ; pour une ligne, son
        // évaluation lève « integer overflow » (abs du plus petit entier). Le tri évalue toutes les lignes
        // avant d'en rendre une : la préparation réussit, le PREMIER pas échoue.
        c.execute_batch(
            "CREATE TEMP VIEW net_ban AS SELECT ip, \
             CASE WHEN ip='203.0.113.232' THEN abs(-9223372036854775807 - 1) ELSE expires_ts END AS expires_ts \
             FROM main.net_ban;",
        )
        .unwrap();
        {
            // Contrôle de l'instrument : c'est bien un PAS raté (pas un échec de préparation ni de mappeur).
            let mut st = c
                .prepare("SELECT ip, expires_ts FROM net_ban ORDER BY (expires_ts IS NULL) DESC, expires_ts DESC, ip LIMIT 10")
                .expect("la préparation réussit");
            let mut rows = st.query([]).unwrap();
            assert!(rows.next().is_err(), "le premier pas doit échouer");
        }
        assert!(
            netban_try_load_cap(&c, NETBAN_CACHE_CAP).is_none(),
            "un pas raté = chargement RATÉ, jamais Some(map vide)"
        );
        assert!(
            netban_charger_cap(&c, NETBAN_CACHE_CAP).is_err_and(|cause| cause.contains("overflow")),
            "le pas raté porte la cause du moteur"
        );
        netban_reload(&c);
        assert!(
            net_ban_is_blocked("203.0.113.231", now()) && net_ban_is_blocked("203.0.113.232", now()),
            "fail-static : aucun ban levé par un pas raté"
        );
    }

    /// LA LIGNE DE JOURNAL, ÉCRITE ET DÉDUPLIQUÉE. L'enfant (variable posée) rejoue des chargements dans un
    /// processus neuf ; le parent lit son stderr : UNE ligne par cause qui persiste (échéance illisible sur
    /// trois rechargements, pas raté sur deux), puis UNE ligne au retour à la normale. Ni IP ni valeur.
    #[test]
    fn netban_chargement_journal_une_ligne_par_cause() {
        const ENFANT: &str = "NETBAN_CHARGEMENT_ENFANT";
        if std::env::var(ENFANT).is_ok() {
            let _g = NETBAN_TEST_LOCK.lock();
            netban_cache().write().clear();
            let c = test_db();
            netban_chargement_poser(&c, "203.0.113.251", None);
            netban_chargement_poser(&c, "203.0.113.252", Some(now() + 3600));
            netban_reload(&c); // sain : rien au journal
            c.execute("UPDATE net_ban SET expires_ts='jamais' WHERE ip='203.0.113.252'", []).unwrap();
            for _ in 0..3 {
                netban_reload(&c);
            }
            c.execute_batch(
                "CREATE TEMP VIEW net_ban AS SELECT ip, \
                 CASE WHEN ip='203.0.113.251' THEN abs(-9223372036854775807 - 1) ELSE 1 END AS expires_ts \
                 FROM main.net_ban;",
            )
            .unwrap();
            for _ in 0..2 {
                netban_reload(&c);
            }
            c.execute_batch("DROP VIEW temp.net_ban; DELETE FROM main.net_ban WHERE ip='203.0.113.252';").unwrap();
            for _ in 0..2 {
                netban_reload(&c);
            }
            println!("NETBAN-ENFANT-A-JOUE");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::netban_chargement_journal_une_ligne_par_cause"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("NETBAN-ENFANT-A-JOUE"), "contrôle : l'enfant a vraiment joué : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[plume] netban :")).collect();
        assert_eq!(lignes.len(), 3, "une ligne par cause, pas une par tick : {lignes:#?}");
        assert!(lignes[0].contains("0 ligne(s) à IP illisible") && lignes[0].contains("1 ligne(s) à échéance illisible"), "{}", lignes[0]);
        assert!(lignes[1].contains("refusé") && lignes[1].contains("overflow"), "{}", lignes[1]);
        assert!(lignes[2].contains("rétabli"), "{}", lignes[2]);
        for l in &lignes {
            assert!(!l.contains("203.0.113") && !l.contains("jamais"), "ni IP ni valeur au journal : {l}");
        }
    }
