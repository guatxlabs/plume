// =====================================================================================
// `P10.28-k` et `P10.28-l` (correction de la vague AQ, après vérification indépendante) — UNE LECTURE RATÉE DE L'ÉTAT
// D'UN GABARIT DE RUNBOOK EST UNE PRÉSENCE NON LUE, DRAPEAU POSÉ OU NON, ET L'ABSENCE DE BANNI / PASS APRÈS SON SEMIS
// N'EST PLUS SERVIE AVEC UNE CAUSE INVENTÉE.
//
// LES DÉFAUTS, LUS SUR e7a6a055 :
//  * `etat_du_gabarit_de_runbook` (seeds.rs) : sa PREMIÈRE lecture (la ligne `runbook` : id, managed) n'avait aucun
//    témoin. Un mutant qui l'avale (`Err` -> `Ok(None)` -> absent) restait vert ; drapeau posé (l'état normal des
//    gabarits livrés), `deja_seme` rendait alors « semé » : la lecture ratée était tue, ni comptée ni dite ;
//  * drapeau ABSENT, `deja_seme` rend « non semé » sans lire l'état, la fermeture le relit sous la transaction : une
//    lecture ratée y était comptée sous « écriture ou COMMIT refusé » et dite « une écriture a été refusée » — le
//    même mauvais classement que celui que la vague AQ corrige pour le nom de vue ;
//  * `seed_banpass_dashboard_et_compter_son_refus` : l'absence après le semis était comptée avec
//    `rusqlite::Error::QueryReturnedNoRows`, une erreur que le moteur n'a pas rendue ; la dernière cause servie dans
//    `/api/system/metrics` valait « absent après le semis : Query returned no rows ».
//
// CE QUE CES TÉMOINS TIENNENT : (a) drapeaux posés, la lecture de `runbook.managed` refusée seule -> rien d'écrit
// (le gabarit amputé le reste), chaque gabarit compté sous « présence non lue », aucun sous « écriture ou COMMIT
// refusé » ; lecture rendue, réparé, rien de plus ; (b) le drapeau d'un gabarit amputé retiré, la lecture de
// `runbook_step.ordinal` puis celle de `runbook.managed` refusées -> chaque gabarit (celui-là compris, lu dans la
// fermeture) compté sous « présence non lue », zéro écriture refusée, rien d'écrit, drapeau toujours absent ; lecture
// rendue, réparé et drapeau posé ; (c) en sous-processus (compteur de processus vierge) : les lignes `[seed]` de ce
// gabarit, entières, disent « sa présence n'a pas pu être lue » avec la cause du moteur, et la dernière cause servie
// pour Banni / Pass absent après son semis est l'étape seule, « absent après le semis », comptée une fois.
//
// CE QU'ILS NE TIENNENT PAS : le `ROLLBACK TO` refusé (`rollups.rs`) reste non éprouvé ; les tableaux de bord déjà
// amputés ne sont pas réparés ; le refus de Banni / Pass sous la migration v52 (`MigTx`) reste hors compte.
//
// MUTANTS JOUÉS (retirés avant le commit), chacun vu ROUGE sur son témoin : `AQC_M1` (la première lecture de
// `etat_du_gabarit_de_runbook` avalée en absence, l'AQV26 du vérificateur), `AQC_M2` (la fermeture sans
// `LectureRateeDuSemis` : la forme d'avant), `AQC_M3` (la phrase d'écriture refusée pour une présence non lue de la
// fermeture), `AQC_M4` (la cause inventée `QueryReturnedNoRows` remise), `AQC_M5` (`etape_du_refus_du_semis` qui
// ignore le marqueur).
// =====================================================================================
mod semis_gabarit_lecture_ratee_et_banni_pass_sans_cause_inventee {
    use super::*;
    use crate::comptes_de_transaction::compte_des_temoins;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const AQC_AMPUTE: &str = "recon-scan";

    fn aqc_base_sur_disque(tag: &str) -> (crate::tmp_possede::TmpPossede, Connection) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let conn = open_db(&p).expect("base sur disque");
        conn.execute_batch(include_str!("../../../db/schema.sql")).expect("schéma");
        assert!(migrate(&conn), "la chaîne de migrations doit aller au bout");
        (tmp, conn)
    }

    /// (présence non lue, écriture ou COMMIT refusé) comptés pour les gabarits de runbook.
    fn aqc_comptes(conn: &Connection) -> (u64, u64) {
        let compte = |etape: &str| compte_des_temoins(conn, &format!("geste de fond non validé seed : {GESTE_GABARIT_DE_RUNBOOK} : {etape}"));
        (compte(ETAPE_PRESENCE_NON_LUE), compte(ETAPE_ECRITURE_REFUSEE))
    }

    fn aqc_rendre_la_main(conn: &Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// Refuse la lecture de `table.colonne`, et elle seule.
    fn aqc_refuser_la_lecture(conn: &Connection, table: &'static str, colonne: &'static str) {
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == table && column_name == colonne => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn aqc_ordinaux(conn: &Connection, cle: &str) -> Vec<i64> {
        let mut st = conn
            .prepare("SELECT ordinal FROM runbook_step WHERE runbook_id=(SELECT id FROM runbook WHERE key=?1) ORDER BY ordinal")
            .expect("préparée");
        st.query_map(params![cle], |r| r.get(0)).expect("lue").collect::<rusqlite::Result<Vec<i64>>>().expect("ordinaux")
    }

    fn aqc_gabarits(conn: &Connection) -> u64 {
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM runbook", [], |r| r.get(0)).expect("gabarits");
        assert!(n >= 15, "instrument : les gabarits livrés sont semés ({n})");
        u64::try_from(n).expect("nombre")
    }

    fn aqc_drapeau_pose(conn: &Connection, cle: &str) -> bool {
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM meta WHERE key=?1", params![format!("seeded_runbook_{cle}")], |r| r.get(0)).expect("drapeau");
        n == 1
    }

    /// Le gabarit `AQC_AMPUTE` privé de son ordinal 1 ; son drapeau retiré si `sans_drapeau`.
    fn aqc_amputer(conn: &Connection, sans_drapeau: bool) {
        conn.execute("DELETE FROM runbook_step WHERE runbook_id=(SELECT id FROM runbook WHERE key=?1) AND ordinal=1", params![AQC_AMPUTE])
            .expect("gabarit amputé");
        if sans_drapeau {
            conn.execute("DELETE FROM meta WHERE key=?1", params![format!("seeded_runbook_{AQC_AMPUTE}")]).expect("drapeau retiré");
        }
        assert_eq!(aqc_ordinaux(conn, AQC_AMPUTE), vec![0, 2, 3, 4], "instrument : gabarit amputé de son ordinal 1");
        assert_eq!(aqc_drapeau_pose(conn, AQC_AMPUTE), !sans_drapeau, "instrument : drapeau tel que voulu");
    }

    // -------------------------------------------------------------------------------------
    // (a) DRAPEAUX POSÉS, LA LIGNE `runbook` ILLISIBLE
    // -------------------------------------------------------------------------------------

    /// MUTANT QUI LE ROUGIT : `AQC_M1` (la lecture ratée de la ligne `runbook` prise pour une absence : chaque gabarit
    /// « semé », rien compté — `(0, 0)` au lieu de `(n, 0)`).
    #[test]
    fn aqc_ligne_du_gabarit_illisible_drapeau_pose_presence_non_lue() {
        let (_tmp, conn) = aqc_base_sur_disque("aqc-ligne-illisible");
        seed_runbooks(&conn);
        let n = aqc_gabarits(&conn);
        aqc_amputer(&conn, false);
        assert_eq!(aqc_comptes(&conn), (0, 0), "instrument : rien compté avant");

        aqc_refuser_la_lecture(&conn, "runbook", "managed");
        seed_runbooks(&conn);
        aqc_rendre_la_main(&conn);
        assert_eq!(aqc_ordinaux(&conn, AQC_AMPUTE), vec![0, 2, 3, 4], "ligne illisible : rien d'écrit");
        assert!(conn.is_autocommit(), "aucune transaction ouverte");
        assert_eq!(aqc_comptes(&conn), (n, 0), "ligne illisible, drapeau posé : chaque gabarit compté sous « présence non lue »");

        seed_runbooks(&conn);
        assert_eq!(aqc_ordinaux(&conn, AQC_AMPUTE), vec![0, 1, 2, 3, 4], "lecture rendue : réparé");
        assert_eq!(aqc_comptes(&conn), (n, 0), "lecture rendue : rien de plus compté");
    }

    // -------------------------------------------------------------------------------------
    // (b) DRAPEAU ABSENT, L'ÉTAT RELU DANS LA FERMETURE
    // -------------------------------------------------------------------------------------

    /// La sonde du vérificateur (gabarit amputé sans drapeau, `runbook_step.ordinal` refusée) rendait `(n - 1, 1)` :
    /// la lecture ratée dans la fermeture comptée comme une écriture refusée. Puis la même chose pour la ligne `runbook`.
    /// MUTANTS QUI LE ROUGISSENT : `AQC_M2` et `AQC_M5` (`(n - 1, 1)`).
    #[test]
    fn aqc_drapeau_absent_etat_illisible_presence_non_lue_pas_ecriture() {
        let (_tmp, conn) = aqc_base_sur_disque("aqc-drapeau-absent");
        seed_runbooks(&conn);
        let n = aqc_gabarits(&conn);
        aqc_amputer(&conn, true);

        aqc_refuser_la_lecture(&conn, "runbook_step", "ordinal");
        seed_runbooks(&conn);
        aqc_rendre_la_main(&conn);
        assert_eq!(aqc_ordinaux(&conn, AQC_AMPUTE), vec![0, 2, 3, 4], "étapes illisibles : rien d'écrit");
        assert!(!aqc_drapeau_pose(&conn, AQC_AMPUTE), "étapes illisibles : drapeau toujours absent");
        assert!(conn.is_autocommit(), "transaction fermée");
        assert_eq!(aqc_comptes(&conn), (n, 0), "étapes illisibles : la fermeture compte une présence non lue, pas une écriture");

        aqc_refuser_la_lecture(&conn, "runbook", "managed");
        seed_runbooks(&conn);
        aqc_rendre_la_main(&conn);
        assert_eq!(aqc_ordinaux(&conn, AQC_AMPUTE), vec![0, 2, 3, 4], "ligne illisible : rien d'écrit");
        assert!(!aqc_drapeau_pose(&conn, AQC_AMPUTE), "ligne illisible : drapeau toujours absent");
        assert_eq!(aqc_comptes(&conn), (2 * n, 0), "ligne illisible : la fermeture compte une présence non lue, pas une écriture");

        seed_runbooks(&conn);
        assert_eq!(aqc_ordinaux(&conn, AQC_AMPUTE), vec![0, 1, 2, 3, 4], "lecture rendue : réparé");
        assert!(aqc_drapeau_pose(&conn, AQC_AMPUTE), "lecture rendue : drapeau posé");
        assert_eq!(aqc_comptes(&conn), (2 * n, 0), "lecture rendue : rien de plus compté");
    }

    // -------------------------------------------------------------------------------------
    // (c) LES LIGNES `[seed]` ET LA DERNIÈRE CAUSE SERVIE, EN SOUS-PROCESSUS
    // -------------------------------------------------------------------------------------

    /// MUTANTS QUI LE ROUGISSENT : `AQC_M2`, `AQC_M3` et `AQC_M5` (« une écriture a été refusée »), `AQC_M4` (la
    /// dernière cause « absent après le semis : Query returned no rows »).
    #[test]
    fn aqc_lignes_seed_et_derniere_cause_de_banni_pass_en_sous_processus() {
        const ENFANT: &str = "AQC_ENFANT_JOURNAL";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            let (_tmp, conn) = aqc_base_sur_disque("aqc-enfant");
            seed_runbooks(&conn);
            aqc_amputer(&conn, true);
            conn.execute("DELETE FROM panel WHERE dashboard_id IN (SELECT id FROM dashboard WHERE name=?1)", params![NOM_DU_BANNI_PASS])
                .expect("panneaux retirés");
            conn.execute("DELETE FROM dashboard WHERE name=?1", params![NOM_DU_BANNI_PASS]).expect("tableau retiré");
            conn.execute("UPDATE view SET name='aqc ancienne vue' WHERE name='Détection'", []).expect("vue renommée");
            conn.execute_batch("CREATE TRIGGER aqc_refus BEFORE INSERT ON view WHEN NEW.name='Détection' BEGIN SELECT RAISE(ABORT,'aqc refus'); END;")
                .expect("déclencheur de refus");
            println!("AQC-ENFANT-A-JOUE");
            eprintln!("AQC-DEBUT");
            aqc_refuser_la_lecture(&conn, "runbook_step", "ordinal");
            seed_runbooks(&conn);
            aqc_rendre_la_main(&conn);
            aqc_refuser_la_lecture(&conn, "runbook", "managed");
            seed_runbooks(&conn);
            aqc_rendre_la_main(&conn);
            seed_banpass_dashboard_et_compter_son_refus(&conn);
            let mut scheduler = serde_json::Map::new();
            crate::comptes_de_transaction::poser_les_gestes_de_fond_non_valides(&mut scheduler);
            let banni_pass = &scheduler["gestes_de_fond_non_valides"][format!("seed : {GESTE_BANNI_PASS}")];
            println!("AQC-BANNI-PASS {banni_pass}");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::semis_gabarit_lecture_ratee_et_banni_pass_sans_cause_inventee::aqc_lignes_seed_et_derniere_cause_de_banni_pass_en_sous_processus",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("AQC-ENFANT-A-JOUE"), "contrôle : l'enfant a vraiment joué : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let qui = format!("[seed] `seeded_runbook_{AQC_AMPUTE}` NON semé : ");
        let lues: Vec<&str> = stderr.lines().skip_while(|l| *l != "AQC-DEBUT").filter(|l| l.starts_with(&qui)).collect();
        let presence = |colonne: &str| {
            format!("{qui}sa présence n'a pas pu être lue (access to {colonne} is prohibited) — rien n'est écrit, le semis sera retenté au prochain démarrage")
        };
        assert_eq!(lues, vec![presence("runbook_step.ordinal"), presence("runbook.managed")], "lignes [seed] entières du gabarit :\n{stderr}");
        let banni_pass: Vec<&str> = stdout.lines().filter_map(|l| l.strip_prefix("AQC-BANNI-PASS ")).collect();
        assert_eq!(banni_pass.len(), 1, "contrôle : une ventilation de Banni / Pass imprimée : {stdout}");
        let banni_pass: serde_json::Value = serde_json::from_str(banni_pass[0]).expect("ventilation JSON");
        assert_eq!(
            banni_pass,
            json!({ "n": 1, "derniere_cause": ETAPE_ABSENT_APRES_LE_SEMIS }),
            "Banni / Pass absent après son semis : compté une fois, dernière cause = l'étape seule"
        );
        assert_eq!(ETAPE_ABSENT_APRES_LE_SEMIS, "absent après le semis", "instrument : l'étape servie");
    }
}
