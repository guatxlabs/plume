// =====================================================================================
// `P10.20-b` (reprise de la tranche des instantanés) — LA BRANCHE `Err` DE `query_map` DANS
// `dernier_instantane_par_hote` (`ingest/store.rs`) A SON TÉMOIN.
//
// La vague précédente l'avait déclarée « sans témoin possible » et son mutant (rendre `Complet`) « équivalent ».
// C'est faux : la préparation ne lie rien, et la liaison du seul `&str` (`kind`) se refuse dès que le texte dépasse
// `SQLITE_LIMIT_LENGTH` de la connexion. On abaisse cette limite sur la connexion de test (`sqlite3_limit`) : la
// préparation passe (le texte SQL relève de `SQLITE_LIMIT_SQL_LENGTH`, pas de cette limite), la liaison d'un `kind`
// plus long que la limite échoue. Un mutant qui rend `Complet` sur cette branche sert alors « parc vide, lu en
// entier » : ce témoin rougit.
//
// Le témoin de contrôle joue la MÊME connexion sous la MÊME limite avec un `kind` court : la lecture est complète et
// rend sa ligne. La fin `NonCommence` vient donc de la liaison refusée, pas de la limite seule ni de la préparation.
//
// MUTANTS JOUÉS (commutateurs retirés avant le commit), chacun vu ROUGE : AX2_QM_COMPLET (branche `Err` de
// `query_map` rendue `Complet`), AX2_QM_CAUSE (cause inventée au lieu du texte rendu par la liaison).
// =====================================================================================
mod liaison_refusee_du_parcours_des_instantanes {
    use super::*;
    use crate::query_exec::FinDeParcours;

    /// Le texte que rend le moteur pour une liaison refusée (`SQLITE_TOOBIG`).
    const AX2_CAUSE_LIAISON_TROP_LONGUE: &str = "string or blob too big";
    /// Limite de longueur posée sur la connexion de test : au-dessus des valeurs de la fixture de contrôle, au-dessous
    /// du `kind` long.
    const AX2_LIMITE_DE_LONGUEUR: std::os::raw::c_int = 32;

    fn ax2_abaisser_la_limite_de_longueur(conn: &Connection) {
        // SAFETY : la poignée vient d'une connexion vivante, empruntée pendant l'appel ; `sqlite3_limit` ne la garde pas.
        let avant = unsafe {
            rusqlite::ffi::sqlite3_limit(conn.handle(), rusqlite::ffi::SQLITE_LIMIT_LENGTH, AX2_LIMITE_DE_LONGUEUR)
        };
        assert!(avant > AX2_LIMITE_DE_LONGUEUR, "contrôle : la limite d'origine ({avant}) est au-dessus de celle posée");
    }

    #[test]
    fn ax2_une_liaison_refusee_rend_non_commence_jamais_complet() {
        let conn = test_db();
        let kind_long = "k".repeat(2000);
        // Une ligne EXISTE pour ce kind : un `Complet` vide serait un parc plus petit que la base, servi comme un fait.
        conn.execute(
            "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(1000,?1,'h-a','{}','srv-a')",
            params![kind_long],
        )
        .expect("fixture");
        ax2_abaisser_la_limite_de_longueur(&conn);
        let lu = crate::ingest::store::dernier_instantane_par_hote(&conn, &kind_long, 500);
        assert!(lu.lignes.is_empty(), "rien n'est lu quand la liaison est refusée");
        match &lu.fin {
            FinDeParcours::NonCommence { cause } => {
                assert_eq!(cause, AX2_CAUSE_LIAISON_TROP_LONGUE, "la cause est celle que la liaison a rendue")
            }
            autre => panic!("fin attendue NonCommence, pas {:?}", autre.etat()),
        }
    }

    #[test]
    fn ax2_controle_meme_limite_kind_court_lecture_complete() {
        let conn = test_db();
        conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(1000,'fw','h-a','{}','srv-a')", [])
            .expect("fixture");
        ax2_abaisser_la_limite_de_longueur(&conn);
        let lu = crate::ingest::store::dernier_instantane_par_hote(&conn, "fw", 500);
        let hotes: Vec<_> = lu.iter().map(|r| r.0.clone().unwrap_or_default()).collect();
        assert_eq!(hotes, ["srv-a"], "sous la même limite, un kind court se lit");
        assert!(matches!(lu.fin, FinDeParcours::Complet), "fin {:?}", lu.fin.etat());
    }
}
