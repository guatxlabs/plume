// P7.18-a — LA FEUILLE `tri_des_connexions` RELIT LE BUDGET, ELLE NE L'ÉCRIT PAS
// ================================================================================================
// LE DÉFAUT QUE CES TESTS FERMENT. Au déplacement du verdict de tri vers `tri_des_connexions.rs`, la
// garde `le_budget_memoire_sqlite_na_quun_seul_auteur` avait exempté le fichier ENTIER, pour les quatre
// motifs, et le comptait comme auteur : la feuille pouvait écrire `cache_size`, `hard_heap_limit` ou
// `temp_store=FILE` sans rougir, et la précondition « l'auteur décide vraiment » tenait par la feuille
// seule. Désormais l'auteur est `sqlite_plafond.rs` SEUL, et dans la feuille n'est admise qu'une ligne
// qui RELIT `temp_store`.
//
// MUTATIONS JOUÉES (VERIF_MUT, retirées du source avant le commit) : `feuille_entiere` (la feuille
// redevient exemptée en bloc et comptée) rougit (b) (c) (d) (e) ; `en_memoire_deverse` (`constat_de_tri`
// rend pour EnMemoire le texte de SurDisque) rougit (g).

#[cfg(test)]
mod budget_sqlite_feuille_en_lecture_seule_tests {
    use crate::db_open::door_tests::{est_test, fichiers_de_test, rs_files};
    use crate::sqlite_plafond::plafond_tests::{juger_le_budget, FEUILLE_QUI_RELIT};
    use crate::sqlite_plafond::{constat_de_tri, Tri};
    use std::path::PathBuf;

    fn racine() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    /// Les fichiers de production réels et leur source, comme la garde les lit.
    fn textes_reels() -> Vec<(PathBuf, String)> {
        let mut fichiers = Vec::new();
        rs_files(&racine(), &mut fichiers);
        let marques = fichiers_de_test(&fichiers);
        fichiers
            .iter()
            .filter(|f| !est_test(f, &marques))
            .map(|f| (f.clone(), std::fs::read_to_string(f).unwrap()))
            .collect()
    }

    /// Les sources réelles, la feuille préfixée d'une ligne de production hostile.
    fn feuille_injectee(ligne: &str) -> Vec<(PathBuf, String)> {
        let feuille = racine().join(FEUILLE_QUI_RELIT);
        let mut t = textes_reels();
        let e = t.iter_mut().find(|(f, _)| *f == feuille).expect("la feuille est parmi les sources de production");
        e.1 = format!("{ligne}\n{}", e.1);
        t
    }

    fn accuse_la_feuille(v: &[String]) -> bool {
        v.iter().any(|s| s.contains(FEUILLE_QUI_RELIT))
    }

    /// (a) Les lignes RÉELLES de la feuille sont toutes des relectures : aucune violation.
    #[test]
    fn a_la_feuille_reelle_est_admise() {
        let (ici, v) = juger_le_budget(&racine(), &textes_reels());
        assert!(ici >= 2, "l'auteur décide ({ici})");
        assert!(v.is_empty(), "{v:#?}");
    }

    /// (b) La feuille qui ÉCRIT `cache_size` et `hard_heap_limit` est accusée.
    #[test]
    fn b_la_feuille_qui_ecrit_le_cache_ou_le_plafond_est_accusee() {
        let (_, v) = juger_le_budget(&racine(), &feuille_injectee(r#"const X: &str = "PRAGMA cache_size=-1; PRAGMA hard_heap_limit=1";"#));
        assert!(accuse_la_feuille(&v), "{v:#?}");
    }

    /// (c) La feuille qui pose `temp_store=FILE` (avec ou sans blancs) est accusée.
    #[test]
    fn c_la_feuille_qui_pose_temp_store_est_accusee() {
        for l in [r#"const X: &str = "PRAGMA temp_store=FILE;";"#, r#"const X: &str = "PRAGMA temp_store = FILE;";"#] {
            let (_, v) = juger_le_budget(&racine(), &feuille_injectee(l));
            assert!(accuse_la_feuille(&v), "{l} : {v:#?}");
        }
    }

    /// (d) La feuille qui écrit `temp_store` par l'API (sans `=`) est accusée.
    #[test]
    fn d_la_feuille_qui_ecrit_par_pragma_update_est_accusee() {
        let (_, v) = juger_le_budget(&racine(), &feuille_injectee(r#"fn x(c: &rusqlite::Connection) { let _ = c.pragma_update(None, "temp_store", 1); }"#));
        assert!(accuse_la_feuille(&v), "{v:#?}");
    }

    /// (e) Sans l'auteur, la précondition tombe : la feuille ne compte PAS comme auteur.
    #[test]
    fn e_la_feuille_seule_ne_tient_pas_la_precondition() {
        let auteur = racine().join("sqlite_plafond.rs");
        let t: Vec<_> = textes_reels().into_iter().filter(|(f, _)| *f != auteur).collect();
        let (ici, _) = juger_le_budget(&racine(), &t);
        assert_eq!(ici, 0, "la feuille ne décide de rien, elle ne doit pas compter");
    }

    /// (f) La feuille renommée sort de l'exception : ses relectures tombent en violation.
    #[test]
    fn f_la_feuille_renommee_tombe_en_violation() {
        let feuille = racine().join(FEUILLE_QUI_RELIT);
        let t: Vec<_> = textes_reels()
            .into_iter()
            .map(|(f, s)| if f == feuille { (racine().join("tri_des_connexions_bis.rs"), s) } else { (f, s) })
            .collect();
        let (_, v) = juger_le_budget(&racine(), &t);
        assert!(v.iter().any(|s| s.contains("tri_des_connexions_bis.rs")), "{v:#?}");
    }

    /// (g) Le constat d'un tri EN MÉMOIRE le dit, et ne dit jamais qu'il déverse (et réciproquement).
    #[test]
    fn g_le_constat_dit_le_bon_monde() {
        let m = constat_de_tri(&Tri::EnMemoire { compile: 2, local: 0 });
        assert!(m.contains("reste en MÉMOIRE") && !m.contains("DÉVERSE"), "{m}");
        let d = constat_de_tri(&Tri::SurDisque { compile: 2, local: 1 });
        assert!(d.contains("DÉVERSE sur le disque") && !d.contains("MÉMOIRE"), "{d}");
    }
}
