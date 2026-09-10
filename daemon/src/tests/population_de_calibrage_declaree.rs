// =====================================================================================
// `P4.12-g` — LA POPULATION DE CALIBRAGE D'UNE RÈGLE LIVRÉE EST LISIBLE PAR LE CODE, ET UNE POPULATION
// NEUVE SOUS LA RÈGLE EST DITE AU TIR, là où l'exploitant lit la règle. Migration v122. Table unique
// (`population_de_calibrage.rs`) jouée par les semeurs et par la migration ; le débordement est dérivé
// de l'imputation déjà calculée — aucune requête de plus par règle.
// =====================================================================================
mod population_de_calibrage_declaree {
    use super::*;
    use crate::handlers::detection::run_due_rules;
    use crate::population_de_calibrage::{sources_hors_population, POPULATIONS_DE_CALIBRAGE};

    #[test]
    fn les_sources_hors_population_sont_derivees_sans_juger_une_population_non_declaree() {
        let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(sources_hors_population("sshd,mail", &v(&["sshd", "winlog"])), v(&["winlog"]));
        assert_eq!(sources_hors_population("sshd", &v(&["sshd"])), Vec::<String>::new(), "dans la population : rien");
        assert_eq!(sources_hors_population("", &v(&["winlog"])), Vec::<String>::new(), "population non déclarée : on ne juge pas");
        assert_eq!(sources_hors_population("sshd", &v(&[crate::imputation::SOURCE_INDETERMINABLE])), Vec::<String>::new(), "l'inconnu nommé n'est pas une source étrangère");
        assert_eq!(sources_hors_population(" sshd , mail ", &v(&["mail", " sshd"])), Vec::<String>::new(), "les blancs ne font pas une source neuve");
    }

    /// GARDE DÉRIVÉE : chaque règle livrée de la table existe dans les semeurs sous ce nom exact — un
    /// renommage d'une règle graine ferait pourrir la table en silence.
    #[test]
    fn chaque_regle_livree_de_la_table_existe_dans_les_semeurs() {
        let semeurs = std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/seeds.rs")).unwrap();
        let absentes: Vec<&str> = POPULATIONS_DE_CALIBRAGE.iter().map(|(n, _)| *n).filter(|n| !semeurs.contains(&format!("\"{n}\""))).collect();
        assert!(absentes.is_empty(), "règles de la table absentes des semeurs : {absentes:?}");
        assert!(POPULATIONS_DE_CALIBRAGE.iter().all(|(_, p)| !p.trim().is_empty()), "une entrée sans population ne déclare rien");
    }

    #[test]
    fn une_population_neuve_sous_une_regle_est_ecrite_sur_la_regle_au_tir() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("p412g-tir");
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn));
            conn.execute("DELETE FROM rule", []).unwrap();
            conn.execute("DELETE FROM alert", []).unwrap();
            conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,population) \
                 VALUES('p412g',1,'search category=auth | stats count',1,'>',0,2,0,3600,'sshd')",
                [],
            ).unwrap();
            conn.execute("INSERT INTO event(ts,source,category,severity,message,fields) VALUES(?1,'winlog','auth',1,'échec','{\"action\":\"failure\"}')", params![now]).unwrap();
        }
        run_due_rules(&db, &p);
        let vue: String = db.lock().query_row("SELECT population_vue FROM rule WHERE name='p412g'", [], |r| r.get(0)).unwrap();
        assert_eq!(vue, "winlog", "la source neuve est écrite sur la règle au tir");
        {
            let conn = db.lock();
            conn.execute("DELETE FROM event", []).unwrap();
            conn.execute("INSERT INTO event(ts,source,category,severity,message,fields) VALUES(?1,'sshd','auth',1,'échec','{\"action\":\"failure\"}')", params![now]).unwrap();
        }
        run_due_rules(&db, &p);
        let vue: String = db.lock().query_row("SELECT population_vue FROM rule WHERE name='p412g'", [], |r| r.get(0)).unwrap();
        assert_eq!(vue, "", "la population de calibrage seule : rien à dire, et l'ancienne mention s'efface");
    }

    #[test]
    fn la_migration_v122_declare_les_populations_des_regles_livrees_existantes_sans_ecraser_l_exploitant() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("p412g-migration");
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let conn = open_db(&p).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn));
        conn.execute_batch(
            "ALTER TABLE rule DROP COLUMN population; ALTER TABLE rule DROP COLUMN population_vue; \
             UPDATE meta SET value='121' WHERE key='schema_version'; DELETE FROM rule;",
        ).expect("une base v121 se fabrique en retirant les colonnes de v122");
        conn.execute("INSERT INTO rule(name,query) VALUES('Brute-force auth par IP (5 min)','search x | stats count')", []).unwrap();
        conn.execute("INSERT INTO rule(name,query) VALUES('règle de l\'\'exploitant','search y | stats count')", []).unwrap();
        assert!(migrate(&conn), "la migration 121 -> 122 passe");
        let v: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(v, crate::migrate::CODE_SCHEMA_MAX.to_string());
        let livree: String = conn.query_row("SELECT population FROM rule WHERE name='Brute-force auth par IP (5 min)'", [], |r| r.get(0)).unwrap();
        assert_eq!(livree, "sshd", "la règle livrée reçoit sa population de calibrage");
        let exploitant: String = conn.query_row("SELECT population FROM rule WHERE name LIKE 'règle de l%'", [], |r| r.get(0)).unwrap();
        assert_eq!(exploitant, "", "une règle de l'exploitant n'est pas jugée : rien n'est inventé");
        // et une déclaration déjà posée n'est pas écrasée par un second passage
        conn.execute("UPDATE rule SET population='sshd,vpn' WHERE name='Brute-force auth par IP (5 min)'", []).unwrap();
        crate::population_de_calibrage::declarer_les_populations(&conn);
        let gardee: String = conn.query_row("SELECT population FROM rule WHERE name='Brute-force auth par IP (5 min)'", [], |r| r.get(0)).unwrap();
        assert_eq!(gardee, "sshd,vpn", "la déclaration de l'exploitant prime");
    }
}
