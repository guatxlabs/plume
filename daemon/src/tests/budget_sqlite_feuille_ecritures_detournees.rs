// P7.18-a (second tour) — LES ÉCRITURES DÉTOURNÉES DE `temp_store` DANS LA FEUILLE SONT ACCUSÉES
// ================================================================================================
// LE DÉFAUT QUE CES TESTS FERMENT. La garde jugeait la feuille `tri_des_connexions.rs` LIGNE À LIGNE
// et ne cherchait que `temp_store` suivi d'un `=` : `PRAGMA temp_store(1)` (qui ÉCRIT, témoin h0) et
// un `pragma_update` replié par rustfmt sur plusieurs lignes (`"temp_store"` seul sur sa ligne)
// passaient. Aucun témoin ne couvrait `soft_heap_limit`, `.pragma(`, `execute`, ni une seconde
// occurrence de `temp_store` sur une ligne. La feuille est désormais jugée sur son TEXTE ENTIER
// (`ecritures_de_la_feuille`).

#[cfg(test)]
mod budget_sqlite_feuille_ecritures_detournees_tests {
    use crate::db_open::door_tests::{est_test, fichiers_de_test, rs_files};
    use crate::sqlite_plafond::plafond_tests::{juger_le_budget, FEUILLE_QUI_RELIT};
    use std::path::PathBuf;

    fn racine() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    /// Les sources de production réelles, la feuille préfixée d'un texte hostile (une ou plusieurs lignes).
    fn feuille_injectee(texte: &str) -> Vec<(PathBuf, String)> {
        let mut fichiers = Vec::new();
        rs_files(&racine(), &mut fichiers);
        let marques = fichiers_de_test(&fichiers);
        let feuille = racine().join(FEUILLE_QUI_RELIT);
        let mut t: Vec<(PathBuf, String)> = fichiers
            .iter()
            .filter(|f| !est_test(f, &marques))
            .map(|f| (f.clone(), std::fs::read_to_string(f).unwrap()))
            .collect();
        let e = t.iter_mut().find(|(f, _)| *f == feuille).expect("la feuille est parmi les sources de production");
        e.1 = format!("{texte}\n{}", e.1);
        t
    }

    fn accuse(texte: &str) -> bool {
        let (_, v) = juger_le_budget(&racine(), &feuille_injectee(texte));
        v.iter().any(|s| s.contains(FEUILLE_QUI_RELIT))
    }

    /// (h0) La forme parenthésée ÉCRIT vraiment : ce n'est pas une accusation de principe.
    #[test]
    fn h0_la_forme_parenthesee_ecrit_temp_store() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        let _ = c.query_row("PRAGMA temp_store(1)", [], |r| r.get::<_, i64>(0));
        let apres: i64 = c.query_row("PRAGMA temp_store", [], |r| r.get(0)).unwrap();
        assert_eq!(apres, 1, "PRAGMA temp_store(1) pose temp_store");
    }

    /// (h) `PRAGMA temp_store(1)` dans la feuille est accusé.
    #[test]
    fn h_la_forme_parenthesee_est_accusee() {
        assert!(accuse(r#"fn x(c: &rusqlite::Connection) { let _ = c.query_row("PRAGMA temp_store(1)", [], |r| r.get::<_, i64>(0)); }"#));
    }

    /// (i) Un `pragma_update` replié par rustfmt (`"temp_store"` seul sur sa ligne) est accusé.
    #[test]
    fn i_le_pragma_update_replie_est_accuse() {
        assert!(accuse("fn x(c: &rusqlite::Connection) {\n    let _ = c.pragma_update(\n        None,\n        \"temp_store\",\n        1,\n    );\n}"));
    }

    /// (j) Un `=` renvoyé à la ligne suivante est accusé.
    #[test]
    fn j_le_signe_egal_a_la_ligne_suivante_est_accuse() {
        assert!(accuse("const X: &str = \"PRAGMA temp_store\n    = FILE\";"));
    }

    /// (k) Chacun des trois autres motifs, SEUL, est accusé.
    #[test]
    fn k_chaque_autre_motif_seul_est_accuse() {
        for m in ["cache_size", "soft_heap_limit", "hard_heap_limit"] {
            assert!(accuse(&format!("const X: &str = \"PRAGMA {m}=1\";")), "{m}");
        }
    }

    /// (l) L'API `.pragma(` est accusée, même repliée.
    #[test]
    fn l_l_api_pragma_est_accusee() {
        assert!(accuse("fn x(c: &rusqlite::Connection) {\n    let _ = c.pragma(\n        None,\n        \"temp_store\",\n        1,\n        |_| Ok(()),\n    );\n}"));
    }

    /// (m) `execute` est accusé, même quand la requête a la forme d'une relecture.
    #[test]
    fn m_execute_est_accuse() {
        assert!(accuse("fn x(c: &rusqlite::Connection) {\n    let _ = c.execute_batch(\n        \"PRAGMA temp_store\",\n    );\n}"));
    }

    /// (n) CHAQUE occurrence est jugée : une relecture suivie d'une écriture sur la même ligne est accusée.
    #[test]
    fn n_la_seconde_occurrence_est_jugee() {
        assert!(accuse(r#"const X: &str = "PRAGMA temp_store; PRAGMA temp_store=1";"#));
    }

    /// (o) TÉMOIN NÉGATIF : une relecture repliée, ou par `pragma_query_value`, reste admise.
    #[test]
    fn o_une_relecture_repliee_reste_admise() {
        assert!(!accuse("fn x(c: &rusqlite::Connection) {\n    let _ = c.query_row(\n        \"PRAGMA temp_store\",\n        [],\n        |r| r.get::<_, i64>(0),\n    );\n}"));
        assert!(!accuse(r#"fn y(c: &rusqlite::Connection) { let _ = c.pragma_query_value(None, "temp_store", |r| r.get::<_, i64>(0)); }"#));
    }
}
