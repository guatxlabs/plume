    // ============================================================================================
    // P10.5-q — LE COFFRE DES PANNEAUX DIT QU'IL NE VOIT PAS LA BANDE FROIDE (2026-09-10). Il exécute sur
    // le pool CHAUD seul et n'atteint jamais l'union froide ; quand la fenêtre demandée commence sous la
    // frontière mesurée, `stats.cold` porte l'aveu du même fabricant que le pivot, avec le chemin nommé.
    // Sans tier froid, rien n'est ajouté : la charge utile reste celle d'avant.
    // ============================================================================================

    #[test]
    fn p10_5q_sans_tier_froid_le_coffre_ne_publie_aucun_aveu_de_bande_froide() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (path, conn) = pa_base("coffre-sans-froid");
        let conf = pa_conf();
        #[cfg(feature = "cold_tier")]
        assert!(!crate::cold_store::cold_tier_runtime_on(&conf), "INSTRUMENT : ce témoin décrit le tier froid ÉTEINT ; il l'est sur cette conf");
        conn.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(1799000000,'s','auth',3,'m')", []).unwrap();
        drop(conn);
        let now_s: i64 = 1_800_000_000;
        let sql = "SELECT COUNT(*) AS n FROM event WHERE ts >= 1700000000";
        let (cov, frontiere) = panneau_avoue::horizon_et_frontiere_du_sql(path.as_str(), &conf, sql, 1_700_000_000, now_s);
        assert!(frontiere.is_none(), "sans tier froid, aucune frontière n'est mesurée — {cov}");
        assert_eq!(cov["reason"], json!(panneau_avoue::RAISON_RETENTION), "l'horizon reste celui de la rétention — {cov}");
        let pc = panneau_avoue::compile_panneau_avoue(sql, false, 1_700_000_000, 0, None).unwrap();
        let v = panneau_avoue::executer(path.as_str(), &conf, pc, 1_700_000_000).unwrap();
        assert!(v["stats"].get("cold").is_none(), "sans tier froid, `stats.cold` n'est pas posé — {}", v["stats"]);
        assert!(v["stats"].get("coverage").is_some(), "l'aveu de couverture, lui, est toujours là");
    }

    #[cfg(feature = "cold_tier")]
    #[test]
    fn p10_5q_sous_le_tier_froid_le_coffre_dit_la_bande_qu_il_ne_lit_pas() {
        use crate::handlers::panneau_avoue::CHEMIN_DU_COFFRE_DES_PANNEAUX;
        let _env = VERROU_ENV_PROCESSUS.read();
        let (path, conn) = pa_base("coffre-froid");
        let mut conf = pa_conf();
        conf.insert("PLUME_COLD_TIER".into(), "1".into());
        conf.insert("PLUME_COLD_HOT_WINDOW_DAYS".into(), "2".into());
        assert!(crate::cold_store::cold_tier_runtime_on(&conf), "INSTRUMENT : la conf allume le tier froid (et l'environnement ne l'éteint pas)");
        conn.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(1799000000,'s','auth',3,'m')", []).unwrap();
        drop(conn);
        let now_s: i64 = 1_800_000_000;
        let jour = 86_400;
        let sql = "SELECT COUNT(*) AS n FROM event WHERE ts >= 1700000000";
        let (cov, frontiere) = panneau_avoue::horizon_et_frontiere_du_sql(path.as_str(), &conf, sql, now_s - 30 * jour, now_s);
        let b = frontiere.unwrap_or_else(|| panic!("tier froid allumé et requête sur `event` : une frontière est mesurée — {cov}"));
        assert!(b <= now_s - 2 * jour && b > now_s - 4 * jour, "la frontière est la fenêtre chaude alignée au jour : {b} pour now {now_s}");
        // `executer` mesure la frontière à l'HORLOGE MURALE (`horizon` -> `now()`) : la fenêtre qu'on lui
        // demande se cale sur elle, pas sur l'horloge injectée ci-dessus (faute d'instrument attrapée le
        // 2026-09-10 : une fenêtre de 2027 tenait AU-DESSUS d'une frontière de 2026, et rien n'était avoué).
        let now_reel = now();
        let b_reel = panneau_avoue::horizon_et_frontiere_du_sql(path.as_str(), &conf, sql, now_reel - 30 * jour, now_reel).1.expect("frontière à l'horloge murale");
        // Fenêtre qui commence SOUS la frontière : l'aveu est posé, nomme le coffre, porte la frontière.
        let pc = panneau_avoue::compile_panneau_avoue(sql, false, now_reel - 30 * jour, 0, None).unwrap();
        let v = panneau_avoue::executer(path.as_str(), &conf, pc, now_reel - 30 * jour).unwrap();
        assert_eq!(v["stats"]["cold"]["served_from"], "hot", "le coffre ne lit que le chaud — {}", v["stats"]);
        assert_eq!(v["stats"]["cold"]["boundary_ts"], b_reel, "la frontière publiée est celle qui a été mesurée");
        let aveu = v["stats"]["cold"]["aveu"].as_str().expect("l'aveu est une phrase");
        assert!(aveu.contains(CHEMIN_DU_COFFRE_DES_PANNEAUX), "l'aveu nomme son chemin : {aveu}");
        assert_eq!(v["stats"]["coverage"]["reason"], json!(panneau_avoue::RAISON_COLD), "et la couverture continue de nommer la frontière froide");
        // Fenêtre entièrement CHAUDE : rien à avouer, `stats.cold` absent — un aveu inconditionnel serait faux.
        let pc = panneau_avoue::compile_panneau_avoue(sql, false, b_reel + jour, 0, None).unwrap();
        let v = panneau_avoue::executer(path.as_str(), &conf, pc, b_reel + jour).unwrap();
        assert!(v["stats"].get("cold").is_none(), "fenêtre chaude : aucun aveu de bande froide — {}", v["stats"]);
        // Une requête qui ne nomme pas `event` (les métriques ne vieillissent pas) : aucune frontière, aucun aveu.
        let (_, f) = panneau_avoue::horizon_et_frontiere_du_sql(path.as_str(), &conf, "SELECT COUNT(*) FROM metric WHERE ts >= 1700000000", now_s - 30 * jour, now_s);
        assert!(f.is_none(), "une requête sur `metric` n'a pas de frontière froide");
    }
