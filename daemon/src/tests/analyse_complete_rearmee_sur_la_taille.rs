// P7.19-h : la passe d'analyse complète se RÉARME sur la taille de la table, plus seulement sur la
// version de schéma. Le piège : à l'installation, la passe tourne sur une base VIDE et pose son jalon ;
// le moteur cible écrit alors un ZÉRO pour l'index partiel de `event`, que le planificateur lirait pour
// toute la vie de cette version de schéma. Le jalon porte désormais `<version>@<lignes>`, et la passe se
// refait quand la table a franchi le seuil et grandi du facteur depuis la mesure.
mod analyse_complete_rearmee_sur_la_taille {
    use crate::maintenance::{
        la_passe_d_analyse_complete_est_a_refaire, lire_le_jalon_d_analyse_complete,
        FACTEUR_DE_CROISSANCE_DE_REARMEMENT_DE_L_ANALYSE, SEUIL_DE_LIGNES_DE_REARMEMENT_DE_L_ANALYSE,
    };

    #[test]
    fn un_jalon_ancien_sans_taille_vaut_une_base_vide_et_se_refait_au_seuil() {
        let seuil = SEUIL_DE_LIGNES_DE_REARMEMENT_DE_L_ANALYSE;
        assert_eq!(lire_le_jalon_d_analyse_complete("119"), ("119", 0));
        assert!(!la_passe_d_analyse_complete_est_a_refaire(Some("119"), "119", 0), "vide et restée vide : rien à relancer");
        assert!(!la_passe_d_analyse_complete_est_a_refaire(Some("119"), "119", seuil - 1));
        assert!(la_passe_d_analyse_complete_est_a_refaire(Some("119"), "119", seuil), "au seuil, la passe prise sur le vide est refaite");
        assert!(la_passe_d_analyse_complete_est_a_refaire(None, "119", 0), "jamais analysée");
    }

    #[test]
    fn la_passe_se_refait_sur_un_bump_de_schema_ou_une_croissance_du_facteur() {
        let facteur = FACTEUR_DE_CROISSANCE_DE_REARMEMENT_DE_L_ANALYSE;
        assert!(la_passe_d_analyse_complete_est_a_refaire(Some("118@50000"), "119", 50_000), "un bump réarme, quelle que soit la taille");
        assert!(!la_passe_d_analyse_complete_est_a_refaire(Some("119@500"), "119", 900), "sous le seuil, une croissance ne compte pas");
        assert!(la_passe_d_analyse_complete_est_a_refaire(Some("119@500"), "119", 2_000));
        assert!(!la_passe_d_analyse_complete_est_a_refaire(Some("119@1000000"), "119", 1_200_000), "20 % de plus : statistiques encore justes");
        assert!(!la_passe_d_analyse_complete_est_a_refaire(Some("119@1000000"), "119", 1_000_000 * facteur - 1));
        assert!(la_passe_d_analyse_complete_est_a_refaire(Some("119@1000000"), "119", 1_000_000 * facteur));
        assert!(!la_passe_d_analyse_complete_est_a_refaire(Some("119@abc"), "119", 999), "un jalon illisible vaut base vide, pas une boucle");
        assert!(la_passe_d_analyse_complete_est_a_refaire(Some("119@abc"), "119", 1_000));
    }

    /// Sur une base RÉELLE : analysée vide, le jalon dit `@0` ; dix lignes plus tard, rien ne se
    /// refait (le jalon ne bouge pas) ; au seuil, la passe se refait, le jalon porte la taille et
    /// `sqlite_stat1` connaît enfin la table ; le double du seuil ne relance rien avant le facteur.
    #[test]
    fn une_base_analysee_vide_est_reanalysee_quand_elle_se_remplit() {
        use std::sync::Arc;
        let seuil = SEUIL_DE_LIGNES_DE_REARMEMENT_DE_L_ANALYSE;
        let tmp = crate::tmp_possede::TmpPossede::neuf("analyse-rearmee");
        let chemin = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let db = Arc::new(parking_lot::Mutex::new(crate::db_open::open_db(&chemin).unwrap()));
        db.lock().execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let jalon = |db: &Arc<parking_lot::Mutex<rusqlite::Connection>>| -> Option<String> {
            db.lock().query_row("SELECT value FROM meta WHERE key='analyze_full_done'", [], |r| r.get(0)).ok()
        };
        let remplir_jusqu_a = |db: &Arc<parking_lot::Mutex<rusqlite::Connection>>, id_max: i64| {
            let conn = db.lock();
            let depuis: i64 = conn.query_row("SELECT COALESCE(MAX(id),0) FROM event", [], |r| r.get(0)).unwrap();
            for id in (depuis + 1)..=id_max {
                conn.execute(
                    "INSERT INTO event(id,ts,source,category,severity,message) VALUES(?1,?2,'sshd','auth',1,'x')",
                    rusqlite::params![id, 1_700_000_000 + id],
                )
                .unwrap();
            }
        };
        let version: String = db.lock().query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();

        crate::maintenance::analyze_full_background(&db);
        assert_eq!(jalon(&db).as_deref(), Some(format!("{version}@0").as_str()), "analysée vide : le jalon le dit");

        remplir_jusqu_a(&db, 10);
        crate::maintenance::analyze_full_background(&db);
        assert_eq!(jalon(&db).as_deref(), Some(format!("{version}@0").as_str()), "dix lignes : rien ne se refait");

        remplir_jusqu_a(&db, seuil);
        crate::maintenance::analyze_full_background(&db);
        assert_eq!(jalon(&db).as_deref(), Some(format!("{version}@{seuil}").as_str()), "au seuil : la passe se refait et le jalon porte la taille");
        let stat: i64 = db
            .lock()
            .query_row("SELECT COUNT(*) FROM sqlite_stat1 WHERE tbl='event'", [], |r| r.get(0))
            .unwrap();
        assert!(stat > 0, "sqlite_stat1 connaît la table analysée pleine");

        remplir_jusqu_a(&db, seuil * 2);
        crate::maintenance::analyze_full_background(&db);
        assert_eq!(jalon(&db).as_deref(), Some(format!("{version}@{seuil}").as_str()), "le double ne relance rien avant le facteur");
    }
}
