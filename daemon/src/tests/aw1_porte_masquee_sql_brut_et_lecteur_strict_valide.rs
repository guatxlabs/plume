// =====================================================================================================
// `P10.5-p` — LA PORTE MASQUÉE NE TIENT PAS UN SQL BRUT POUR FILTRÉ ; LE LECTEUR STRICT VALIDE COMME LA PURGE.
//
// LES DÉFAUTS (relevés par la vérification indépendante du lot, sans témoin capable de rougir) :
//  * `panneau_avoue::compile_panneau_avoue_masque` publie l'environnement lu (`environnement_lu(is_soql, env)`), mais
//    seul le GXQL masqué était témoigné. Un SQL brut masqué tenu pour filtré par l'environnement de l'appelant
//    restait vert : l'horizon prenait la politique de cet environnement (plus longue que la globale) alors que le SQL
//    brut ne filtre aucun `env_id` — un aveu OPTIMISTE. Chemin atteignable : une règle Deny vaut pour tous les rôles,
//    donc `panel_data_masked_live` et les instantanés compilent un panneau SQL brut sous masques avec l'environnement
//    de l'appelant ;
//  * `rollups::lire_les_politiques_d_index` partage `politique_validee` avec la purge (plancher 7 j, plafond 3650 j,
//    nom hors allowlist écarté, plafonds négatifs ramenés à 0), mais aucun témoin ne le jugeait : lire les lignes
//    brutes restait vert. Une ligne au-delà de 3650 j donnerait un horizon plus profond que la purge, qui plafonne.
//    Aucun écrivain du produit ne crée une telle ligne (API et `config.d` plafonnent et filtrent) : la ligne est
//    posée en base directement.
//
// MUTANTS (variable de mutation sous `cfg!(test)`, retirés du source avant le commit), chacun vu ROUGE :
//  AW1C_MASQUE_SQL_BRUT_ENV : (1) ; AW1C_LECTEUR_STRICT_BRUT : (2).
// =====================================================================================================

mod aw1c_porte_masquee_sql_brut_et_lecteur_strict_valide {
    use super::*;

    const AW1C_JOUR: i64 = 86_400;

    /// Base migrée, globale à trente jours, `ajuster` joué AVANT que l'état (et son pool de lecture) n'existe.
    fn aw1c_base(tag: &str, ajuster: impl FnOnce(&Connection)) -> (AppState, crate::tmp_possede::TmpDb) {
        let path = ff_tmp_path(tag);
        {
            let conn = open_db(&path).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : migrations complètes");
            conn.execute("INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global','retention_days','30')", [])
                .expect("fixture : globale à trente jours");
            ajuster(&conn);
        }
        (ds_file_state(&path), path)
    }

    fn aw1c_politique(conn: &Connection, nom: &str, jours: i64, lignes: i64, octets: i64) {
        conn.execute(
            "INSERT INTO index_policy(name,retention_days,max_rows,max_bytes,enabled) VALUES(?1,?2,?3,?4,1)",
            params![nom, jours, lignes, octets],
        )
        .expect("fixture : ligne de politique");
    }

    fn aw1c_couverture(chemin: &str, pc: panneau_avoue::PanneauCompile, depuis: i64) -> Value {
        panneau_avoue::executer(chemin, &HashMap::new(), pc, depuis).expect("exécuté")["stats"]["coverage"].clone()
    }

    fn aw1c_calcule_a(cov: &Value) -> i64 {
        cov["calcule_a"].as_i64().unwrap_or_else(|| panic!("instant du calcul non publié : {cov}"))
    }

    /// (1) PORTE MASQUÉE, SQL BRUT : appelant borné à `stage` (politique de soixante jours, globale à trente), fenêtre de
    /// quarante-cinq jours. Le SQL brut ne filtre aucun environnement : l'horizon est la plus courte des fenêtres
    /// (trente jours) et la fenêtre en descend sous lui — jamais les soixante jours de `stage` ni « rien n'est resté
    /// dehors ». Contrôle sur la même base : le GXQL masqué compilé avec `stage` lit bien soixante jours (la politique
    /// de la fixture mord). MUTANT : AW1C_MASQUE_SQL_BRUT_ENV (SQL brut masqué tenu pour filtré par `stage`).
    #[test]
    fn aw1c_porte_masquee_sql_brut_prend_la_plus_courte() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (_st, p) = aw1c_base("aw1c-masque-brut", |c| aw1c_politique(c, "stage", 60, 0, 0));
        let depuis = now() - 45 * AW1C_JOUR;
        let masques = guatx_core::soql::FieldMaskSet::new();

        let pc = panneau_avoue::compile_panneau_avoue_masque("SELECT ts FROM event WHERE ts >= __FROM__", false, depuis, 0, Some("stage"), &masques)
            .expect("SQL brut masqué compilé");
        let cov = aw1c_couverture(p.as_str(), pc, depuis);
        let a = aw1c_calcule_a(&cov);
        assert_eq!(cov["horizon_ts"], json!(a - 30 * AW1C_JOUR), "SQL brut masqué, appelant stage : la plus courte (trente jours) : {cov}");
        assert_eq!(cov["older_outside_window"], json!(true), "la fenêtre de quarante-cinq jours descend sous l'horizon : {cov}");
        assert_eq!(cov["reason"], json!("retention_floor"), "{cov}");

        let pc = panneau_avoue::compile_panneau_avoue_masque("search source=web | table message", true, depuis, 0, Some("stage"), &masques)
            .expect("GXQL masqué compilé");
        let cov = aw1c_couverture(p.as_str(), pc, depuis);
        let a = aw1c_calcule_a(&cov);
        assert_eq!(cov["horizon_ts"], json!(a - 60 * AW1C_JOUR), "contrôle : GXQL masqué filtré stage, soixante jours : {cov}");
        assert_eq!(cov["older_outside_window"], json!(false), "contrôle : {cov}");
    }

    /// (2) LE LECTEUR STRICT VALIDE LES LIGNES COMME LA PURGE : `stage` à cinq mille jours (plafonné à 3650), `prod` à deux
    /// jours (planché à 7), un nom hors allowlist (écarté), des plafonds négatifs (ramenés à 0). Le lecteur de l'horizon
    /// rend exactement la liste de la purge, et l'horizon d'un panneau filtré `stage` est le plafond de la purge, jamais
    /// plus profond. MUTANT : AW1C_LECTEUR_STRICT_BRUT (lignes rendues sans validation).
    #[test]
    fn aw1c_le_lecteur_strict_valide_comme_la_purge() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, p) = aw1c_base("aw1c-lecteur-strict", |c| {
            aw1c_politique(c, "stage", 5_000, 0, 0);
            aw1c_politique(c, "prod", 2, 0, 0);
            aw1c_politique(c, "nom hors allowlist", 40, 0, 0);
            aw1c_politique(c, "negatifs", 20, -5, -9);
        });
        let comme_tuples = |v: Vec<crate::rollups::IndexPolicy>| -> Vec<(String, i64, i64, i64)> {
            v.into_iter().map(|p| (p.name, p.retention_days, p.max_rows, p.max_bytes)).collect()
        };
        let attendues = vec![
            ("stage".to_string(), 3_650, 0, 0),
            ("prod".to_string(), 7, 0, 0),
            ("negatifs".to_string(), 20, 0, 0),
        ];
        {
            let c = st.db.lock();
            let strictes = comme_tuples(crate::rollups::lire_les_politiques_d_index(&c).expect("politiques lisibles : lues"));
            assert_eq!(strictes, attendues, "lecteur de l'horizon : lignes validées");
            assert_eq!(comme_tuples(load_index_policies(&c)), attendues, "contrôle : la purge voit les mêmes politiques");
        }

        let maintenant: i64 = 1_800_000_000;
        let depuis = maintenant - 4_000 * AW1C_JOUR;
        let (cov, _) = panneau_avoue::horizon_et_frontiere_selon_l_index(p.as_str(), &HashMap::new(), "SELECT ts FROM event", Some("stage"), depuis, maintenant);
        assert_eq!(cov["horizon_ts"], json!(maintenant - 3_650 * AW1C_JOUR), "stage : le plafond de la purge, jamais cinq mille jours : {cov}");
        assert_eq!(cov["older_outside_window"], json!(true), "{cov}");
        let (cov, _) = panneau_avoue::horizon_et_frontiere_selon_l_index(p.as_str(), &HashMap::new(), "SELECT ts FROM event", Some("prod"), depuis, maintenant);
        assert_eq!(cov["horizon_ts"], json!(maintenant - 7 * AW1C_JOUR), "prod : le plancher de la purge, jamais deux jours : {cov}");
    }
}
