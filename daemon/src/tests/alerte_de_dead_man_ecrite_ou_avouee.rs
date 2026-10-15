// =====================================================================================
// `P10.20-w` (queue des écritures non scrutées) — L'ALERTE D'UN DEAD-MAN'S-SWITCH EST ÉCRITE, OU LE REFUS SE COMPTE.
//
// VU (re-mesuré au commit de départ) : les trois dead-man's-switch du tick de santé — capteur muet et flotte
// muette (`handlers/freshness.rs`), magasin de secrets (`sonde_du_magasin_de_secrets.rs`) — écrivaient leur
// alerte en `let _ = conn.execute("INSERT OR IGNORE INTO alert …")` puis rendaient `Lue(0)`. Une écriture
// refusée par la base (lecture seule, disque plein, verrou, déclencheur) : aucune alerte, un tick « rien
// d'abandonné », et le même silence au tick suivant.
//
// CE QUE CES TÉMOINS JOUENT : un déclencheur `RAISE(ABORT)` sur `INSERT INTO alert`, le capteur / la flotte / le
// magasin fabriqués muets, le tick suivant sans panne qui écrit l'alerte, l'épisode déjà ouvert (`Ok(0)`, PAS un
// refus), et la ligne de journal lue sur le stderr d'un sous-processus. Hôtes de test : noms fictifs.
// =====================================================================================
mod alerte_de_dead_man_ecrite_ou_avouee {
    use super::*;
    use crate::mesure_environnement::Mesure;
    use crate::sonde_du_magasin_de_secrets::{
        verifier_le_magasin_de_secrets, DEDUP_MAGASIN, FENETRE_DE_JUGEMENT_S, SERIE_MAGASINS_NON_PRETS,
        SERIE_MAGASINS_TOTAL,
    };

    const DMS_REFUS: &str = "CREATE TRIGGER dms_refus BEFORE INSERT ON alert \
                             BEGIN SELECT RAISE(ABORT,'alerte refusee par le temoin dms'); END;";
    /// Instant fixe pour le magasin (la sonde reçoit l'instant en argument).
    const DMS_NOW: i64 = 1_750_000_000;

    fn dms_compte(db: &Arc<Mutex<Connection>>, regle: &str) -> i64 {
        db.lock().query_row("SELECT COUNT(*) FROM alert WHERE rule=?1", params![regle], |r| r.get(0)).unwrap()
    }

    /// Deux capteurs CONTINUS muets depuis deux heures (pare-feu, catalogue de contrôles) sur un hôte fictif ;
    /// aucune autre donnée : les sondes événementielles restent « jamais vues », la flotte est vide.
    fn dms_capteurs_muets(conn: &Connection, now_ts: i64) {
        for kind in ["firewall", "controls"] {
            conn.execute(
                "INSERT INTO snapshot(ts,host,kind,data) VALUES(?1,'hote-dms-pare-feu',?2,'{}')",
                params![now_ts - 7200, kind],
            )
            .unwrap();
        }
    }

    /// Un parc de deux machines fictives par le vrai chemin (`metric` -> plancher -> rollup) : l'une parle,
    /// l'autre se tait depuis deux heures. Seule la sonde `resources` s'anime, et elle est fraîche.
    fn dms_flotte_muette(conn: &Connection, now_ts: i64) {
        for (hote, ts) in [("hote-dms-vivant", now_ts - 60), ("hote-dms-muet", now_ts - 7200)] {
            conn.execute("INSERT INTO metric(ts,name,labels,value,host) VALUES(?1,'cpu','{}',1.0,?2)", params![ts, hote])
                .unwrap();
        }
        note_host_backfill_floor(conn, now_ts - 7200);
        rollup_hosts(conn);
    }

    /// Six relevés unanimes « un magasin sur trois pas prêt » dans la fenêtre de jugement.
    fn dms_magasin_arrete(conn: &Connection) {
        for i in 0..6i64 {
            let ts = DMS_NOW - (FENETRE_DE_JUGEMENT_S / 4) + i * 60;
            for (serie, v) in [(SERIE_MAGASINS_NON_PRETS, 1.0f64), (SERIE_MAGASINS_TOTAL, 3.0)] {
                conn.execute("INSERT INTO metric(ts,name,labels,value) VALUES(?1,?2,'{}',?3)", params![ts, serie, v]).unwrap();
            }
        }
    }

    #[test]
    fn p10_20w_capteur_muet_alerte_refusee_compte_un_abandon_puis_s_ecrit() {
        let conn = test_db();
        conn.execute(
            "INSERT INTO snapshot(ts,host,kind,data) VALUES(?1,'hote-dms-pare-feu','firewall','{}')",
            params![now() - 7200],
        )
        .unwrap();
        conn.execute_batch(DMS_REFUS).unwrap();
        let db = Arc::new(Mutex::new(conn));
        assert_eq!(check_heartbeats(&db), Mesure::Lue(1), "alerte « capteur muet » refusée : UN abandon au bilan");
        assert_eq!(dms_compte(&db, "heartbeat.firewall"), 0, "contrôle : aucune alerte n'a été écrite");
        db.lock().execute_batch("DROP TRIGGER dms_refus;").unwrap();
        assert_eq!(check_heartbeats(&db), Mesure::Lue(0), "tick sans panne : aucun abandon");
        assert_eq!(dms_compte(&db, "heartbeat.firewall"), 1, "le tick sans panne écrit l'alerte");
        assert_eq!(check_heartbeats(&db), Mesure::Lue(0), "épisode déjà ouvert : `Ok(0)` n'est PAS un refus");
        assert_eq!(dms_compte(&db, "heartbeat.firewall"), 1, "toujours un seul épisode");
    }

    #[test]
    fn p10_20w_flotte_muette_alerte_refusee_compte_un_abandon_puis_s_ecrit() {
        let conn = test_db();
        dms_flotte_muette(&conn, now());
        conn.execute_batch(DMS_REFUS).unwrap();
        let db = Arc::new(Mutex::new(conn));
        assert_eq!(check_heartbeats(&db), Mesure::Lue(1), "alerte « flotte muette » refusée : UN abandon au bilan");
        assert_eq!(dms_compte(&db, "heartbeat.flotte-hotes-muets"), 0, "contrôle : aucune alerte écrite");
        db.lock().execute_batch("DROP TRIGGER dms_refus;").unwrap();
        assert_eq!(check_heartbeats(&db), Mesure::Lue(0), "tick sans panne : aucun abandon");
        assert_eq!(dms_compte(&db, "heartbeat.flotte-hotes-muets"), 1, "le tick sans panne écrit l'alerte");
        assert_eq!(check_heartbeats(&db), Mesure::Lue(0), "épisode du même ensemble déjà ouvert : pas un refus");
        assert_eq!(dms_compte(&db, "heartbeat.flotte-hotes-muets"), 1, "toujours un seul épisode");
    }

    #[test]
    fn p10_20w_magasin_alerte_refusee_compte_un_abandon_puis_s_ecrit() {
        let conn = test_db();
        dms_magasin_arrete(&conn);
        conn.execute_batch(DMS_REFUS).unwrap();
        let ouvertes = |c: &Connection| -> i64 {
            c.query_row("SELECT COUNT(*) FROM alert WHERE dedup=?1", params![DEDUP_MAGASIN], |r| r.get(0)).unwrap()
        };
        assert_eq!(verifier_le_magasin_de_secrets(&conn, DMS_NOW), Mesure::Lue(1), "alerte du magasin refusée : UN abandon");
        assert_eq!(ouvertes(&conn), 0, "contrôle : aucune alerte écrite");
        conn.execute_batch("DROP TRIGGER dms_refus;").unwrap();
        assert_eq!(verifier_le_magasin_de_secrets(&conn, DMS_NOW), Mesure::Lue(0), "sans panne : aucun abandon");
        assert_eq!(ouvertes(&conn), 1, "sans panne, l'alerte est écrite");
        assert_eq!(verifier_le_magasin_de_secrets(&conn, DMS_NOW + 300), Mesure::Lue(0), "épisode ouvert : pas un refus");
        assert_eq!(ouvertes(&conn), 1, "toujours un seul épisode");
    }

    /// Les refus s'ADDITIONNENT : deux capteurs muets et une flotte muette refusés dans le même tick -> `Lue(3)`.
    #[test]
    fn p10_20w_refus_additionnes_dans_le_meme_tick() {
        let conn = test_db();
        let t = now();
        dms_capteurs_muets(&conn, t);
        dms_flotte_muette(&conn, t);
        conn.execute_batch(DMS_REFUS).unwrap();
        let db = Arc::new(Mutex::new(conn));
        assert_eq!(check_heartbeats(&db), Mesure::Lue(3), "un abandon par alerte refusée, additionnés");
        let n: i64 = db.lock().query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "contrôle : aucune alerte écrite");
        db.lock().execute_batch("DROP TRIGGER dms_refus;").unwrap();
        assert_eq!(check_heartbeats(&db), Mesure::Lue(0), "contre-épreuve sans panne");
        let n: i64 = db.lock().query_row("SELECT COUNT(*) FROM alert WHERE rule LIKE 'heartbeat.%'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 3, "contre-épreuve : les trois alertes sont écrites");
    }

    /// La LIGNE DE JOURNAL, lue sur le stderr d'un sous-processus : une ligne par alerte refusée, qui nomme le
    /// capteur / la flotte / le magasin et porte la cause du moteur — jamais un nom d'hôte ni le détail.
    #[test]
    fn p10_20w_ligne_de_journal_cause_sans_hote_ni_detail() {
        const ENFANT: &str = "DMS_ENFANT_JOURNAL";
        const PHASE: &str = "DMS-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let t = now();
            eprintln!("{PHASE}capteur");
            let conn = test_db();
            conn.execute(
                "INSERT INTO snapshot(ts,host,kind,data) VALUES(?1,'hote-dms-pare-feu','firewall','{}')",
                params![t - 7200],
            )
            .unwrap();
            conn.execute_batch(DMS_REFUS).unwrap();
            println!("DMS-BILAN-CAPTEUR:{:?}", check_heartbeats(&Arc::new(Mutex::new(conn))));
            eprintln!("{PHASE}flotte");
            let conn = test_db();
            dms_flotte_muette(&conn, t);
            conn.execute_batch(DMS_REFUS).unwrap();
            println!("DMS-BILAN-FLOTTE:{:?}", check_heartbeats(&Arc::new(Mutex::new(conn))));
            eprintln!("{PHASE}magasin");
            let conn = test_db();
            dms_magasin_arrete(&conn);
            conn.execute_batch(DMS_REFUS).unwrap();
            println!("DMS-BILAN-MAGASIN:{:?}", verifier_le_magasin_de_secrets(&conn, DMS_NOW));
            eprintln!("{PHASE}nominal");
            let conn = test_db();
            dms_capteurs_muets(&conn, t);
            dms_flotte_muette(&conn, t);
            println!("DMS-BILAN-NOMINAL:{:?}", check_heartbeats(&Arc::new(Mutex::new(conn))));
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::alerte_de_dead_man_ecrite_ou_avouee::p10_20w_ligne_de_journal_cause_sans_hote_ni_detail",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        for (marque, attendu) in [
            ("DMS-BILAN-CAPTEUR:", "Lue(1)"),
            ("DMS-BILAN-FLOTTE:", "Lue(1)"),
            ("DMS-BILAN-MAGASIN:", "Lue(1)"),
            ("DMS-BILAN-NOMINAL:", "Lue(0)"),
        ] {
            assert!(stdout.contains(&format!("{marque}{attendu}")), "contrôle : bilan {marque}{attendu} : {stdout}");
        }
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[plume]")).map(str::to_string).collect()
        };
        for (nom, debut) in [
            ("capteur", "[plume] battement de cœur : alerte « capteur muet » du capteur firewall NON ÉCRITE"),
            ("flotte", "[plume] battement de cœur : alerte « flotte muette » NON ÉCRITE"),
            ("magasin", "[plume] magasin de secrets : alerte NON ÉCRITE"),
        ] {
            let lignes = phase(nom);
            let refus: Vec<&String> = lignes.iter().filter(|l| l.contains("NON ÉCRITE")).collect();
            assert_eq!(refus.len(), 1, "phase {nom} : une ligne et une seule pour l'alerte refusée : {lignes:?}");
            assert!(refus[0].starts_with(debut), "phase {nom} : le sujet nommé : {}", refus[0]);
            assert!(refus[0].contains("alerte refusee par le temoin dms"), "phase {nom} : la cause du moteur : {}", refus[0]);
            for l in &lignes {
                for interdit in ["hote-dms", "aucune donnée depuis", "machines en retard", "Hôtes muets", "rotation des clés", "magasin(s) de secrets"] {
                    assert!(!l.contains(interdit), "phase {nom} : ni nom d'hôte ni détail d'alerte ({interdit}) : {l}");
                }
            }
        }
        let nominal = phase("nominal");
        assert!(!nominal.iter().any(|l| l.contains("NON ÉCRITE")), "chemin nominal sans aveu : {nominal:?}");
    }
}
