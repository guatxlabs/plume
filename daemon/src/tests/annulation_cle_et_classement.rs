// ================================================================================================
// P10.31-y — LA CLÉ DE L'ANNULATION EST (base, qid), ET `classer_l_echec` NE CLASSE QUE CE QU'IL DOIT
// ================================================================================================
// Suite de `annulation_reiteree.rs`, mêmes aides. Cinq propriétés que les témoins de ce fichier-là
// laissaient sans juge, chacune démontrée par un mutant resté vert :
//
//   · LE QID EST JUGÉ. En mono-tenant, tous les comptes partagent UNE base : une annulation qui ne
//     regarderait que la base (`Y9`) laisserait n'importe quel lecteur tuer d'un seul `/api/cancel` les
//     requêtes de tous les autres. Les témoins existants mettaient le même qid des deux côtés ;
//   · UNE ERREUR DE PAS N'EST PAS UNE INTERRUPTION. Une `SqliteFailure` quelconque classée interruption
//     (`Y11`) masquerait la vraie cause (`integer overflow`, `out of memory`) sous « budget dépassé ». Le
//     témoin existant ne provoquait qu'une erreur d'ANALYSE, que rusqlite 0.31 rend en `SqlInputError` ;
//   · LE MANQUE DE MÉMOIRE AU PAS REND LE REFUS D'EXPLOITANT, à travers `run_on_conn` (`Y12`) ;
//   · LE QUOTA DE DÉVERSEMENT EST RECONNU à travers `run_on_conn` (`F5`) : les témoins du quota
//     appellent `message_erreur` directement, et `classer_l_echec` porte désormais ce contrôle ;
//   · LE RÉVEIL ATTEINT UNE GARDE QUI ATTEND DÉJÀ (`Y2`, réveil sans `notify_all`) : les témoins existants
//     annulaient tôt, et le mutant n'y rougissait qu'au hasard de l'ordonnancement.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS :
//   · le témoin du réveil attend 50 ms pour que le fil de la garde soit entré dans son attente. Sur le
//     code juste, ce délai ne change rien au verdict ; il ne sert qu'à faire rougir `Y2`, et un fil de
//     garde démarré plus de 50 ms après son armement laisserait `Y2` vert ce jour-là ;
//   · le manque de mémoire est FABRIQUÉ par une fonction scalaire qui rend le code `SQLITE_NOMEM` : c'est
//     le code que rend le franchissement du budget mémoire, pas ce franchissement lui-même (jugé ailleurs,
//     `sqlite_plafond.rs`) ;
//   · le quota de déversement est jugé sur un tri qui déverse dans un répertoire possédé par le témoin ;
//     son franchissement par un autre fil du processus n'est pas exercé.

#[cfg(test)]
mod annulation_cle_et_classement {
    use super::annulation_reiteree::{
        annuler_par_la_route, attendre_au_moins, compte, Instruments, LONGUE, SUIVANTE,
    };
    use rusqlite::functions::FunctionFlags;
    use rusqlite::Connection;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// SÉCURITÉ ENTRE COMPTES D'UNE MÊME BASE : deux lecteurs, une seule base (mono-tenant), deux qid. Le
    /// `/api/cancel` de Bob sur SON qid atteint sa seule requête et laisse celle d'Alice finir ENTIÈRE ;
    /// celui d'Alice sur SON qid abandonne sa requête et laisse l'entrée de Bob intacte.
    #[test]
    fn la_route_cancel_n_annule_que_le_qid_demande_sur_une_meme_base() {
        let (st, _p) = super::sp_state("acc-meme-base-deux-qid");
        let (alice, bob) = (super::sp_au("alice", "viewer"), super::sp_au("bob", "viewer"));
        let base = crate::req_db_path(&st, &alice);
        assert_eq!(base, crate::req_db_path(&st, &bob), "instrument : les deux comptes doivent partager la base");
        let (qid_alice, qid_bob) = ("qid-d-alice", "qid-de-bob");
        let c_alice = Connection::open_in_memory().unwrap();
        let c_bob = Connection::open_in_memory().unwrap();
        let _i = Instruments::poser(&Arc::new(AtomicUsize::new(0)));

        // (1) Bob annule son qid pendant que la requête d'Alice est en vol sur la même base.
        let drapeau_bob = Arc::new(AtomicBool::new(false));
        let entree_bob = crate::query_exec::cancel_register(&base, qid_bob, c_bob.get_interrupt_handle(), drapeau_bob.clone());
        let atteintes_par_bob = Arc::new(AtomicU32::new(u32::MAX));
        {
            let (st, bob, atteintes) = (st.clone(), bob.clone(), atteintes_par_bob.clone());
            crate::query_exec::avant_la_preparation_de_ce_fil(Some(Box::new(move || {
                atteintes.store(annuler_par_la_route(&st, &bob, qid_bob) as u32, Ordering::SeqCst);
            })));
        }
        let r = crate::query_exec::run_on_conn(&c_alice, &base, SUIVANTE, 600_000, Some(qid_alice));
        crate::query_exec::avant_la_preparation_de_ce_fil(None);
        drop(entree_bob);
        assert_eq!(
            atteintes_par_bob.load(Ordering::SeqCst),
            1,
            "l'annulation de Bob doit atteindre sa SEULE requête, jamais celle d'Alice (même base, autre qid)"
        );
        assert!(drapeau_bob.load(Ordering::SeqCst), "l'annulation de Bob doit annuler la requête de Bob");
        let v = r.unwrap_or_else(|e| panic!("la requête d'Alice a été interrompue par l'annulation de Bob : {e}"));
        assert_eq!(compte(&v), 2_000_000, "la requête d'Alice doit finir entière malgré l'annulation de Bob");

        // (2) Alice annule son qid : sa requête est abandonnée, l'entrée de Bob n'est pas touchée.
        let drapeau_bob = Arc::new(AtomicBool::new(false));
        let entree_bob = crate::query_exec::cancel_register(&base, qid_bob, c_bob.get_interrupt_handle(), drapeau_bob.clone());
        let atteintes_par_alice = Arc::new(AtomicU32::new(u32::MAX));
        {
            let (st, alice, atteintes) = (st.clone(), alice.clone(), atteintes_par_alice.clone());
            crate::query_exec::avant_la_preparation_de_ce_fil(Some(Box::new(move || {
                atteintes.store(annuler_par_la_route(&st, &alice, qid_alice) as u32, Ordering::SeqCst);
            })));
        }
        let r = crate::query_exec::run_on_conn(&c_alice, &base, LONGUE, 600_000, Some(qid_alice));
        crate::query_exec::avant_la_preparation_de_ce_fil(None);
        drop(entree_bob);
        assert_eq!(atteintes_par_alice.load(Ordering::SeqCst), 1, "l'annulation d'Alice doit atteindre sa requête, et elle seule");
        assert!(!drapeau_bob.load(Ordering::SeqCst), "l'annulation d'Alice ne doit pas toucher la requête de Bob");
        assert_eq!(r.expect_err("la requête d'Alice annulée doit être abandonnée"), "requête annulée par l'utilisateur");
    }

    /// Une erreur rendue AU PAS, qui n'est pas une interruption (`abs` du plus petit entier : « integer
    /// overflow »), sort TELLE QUELLE de `run_on_conn`, jamais en dépassement de budget ni en annulation.
    #[test]
    fn une_erreur_de_pas_n_est_pas_une_interruption() {
        const SQL: &str = "SELECT abs(-9223372036854775807 - 1)";
        let c = Connection::open_in_memory().unwrap();
        // Prémisse : l'erreur naît au PAS et c'est une `SqliteFailure` (pas une erreur d'analyse).
        let mut st = c.prepare(SQL).expect("instrument : la requête doit se préparer");
        match st.query([]).and_then(|mut rows| rows.next().map(|_| ())) {
            Err(rusqlite::Error::SqliteFailure(f, Some(m))) => {
                assert_ne!(f.code, rusqlite::ErrorCode::OperationInterrupted, "instrument : ce n'est pas une interruption");
                assert!(m.contains("integer overflow"), "instrument : message du moteur inattendu : {m}");
            }
            autre => panic!("instrument : le pas devait rendre une SqliteFailure « integer overflow » : {autre:?}"),
        }
        drop(st);
        let err = crate::query_exec::run_on_conn(&c, ":memory:erreur-de-pas", SQL, 600_000, None)
            .expect_err("le pas échoue");
        assert!(err.contains("integer overflow"), "l'erreur du moteur doit sortir telle quelle : {err}");
        assert!(
            !err.contains("budget") && !err.contains("annulée") && !err.contains("interrompue"),
            "une erreur de pas classée interruption masque sa vraie cause : {err}"
        );
    }

    /// Un `SQLITE_NOMEM` rendu AU PAS sort de `run_on_conn` en refus d'exploitant (ce qui s'est passé, quoi
    /// faire), jamais avec le texte brut du moteur ni en dépassement de budget.
    #[test]
    fn un_manque_de_memoire_au_pas_rend_le_refus_d_exploitant() {
        const SQL: &str = "SELECT acc_manque_de_memoire(1)";
        let c = Connection::open_in_memory().unwrap();
        c.create_scalar_function("acc_manque_de_memoire", 1, FunctionFlags::SQLITE_UTF8, |_| -> rusqlite::Result<i64> {
            // Sans message : un message ferait rabattre le code sur SQLITE_ERROR (`sqlite3_result_error`).
            Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOMEM), None))
        })
        .unwrap();
        // Prémisse : le pas rend bien le code SQLITE_NOMEM.
        match c.query_row(SQL, [], |r| r.get::<_, i64>(0)) {
            Err(rusqlite::Error::SqliteFailure(f, _)) if f.code == rusqlite::ErrorCode::OutOfMemory => {}
            autre => panic!("instrument : le pas devait rendre SQLITE_NOMEM : {autre:?}"),
        }
        let err = crate::query_exec::run_on_conn(&c, ":memory:manque-de-memoire", SQL, 600_000, None)
            .expect_err("le pas échoue");
        assert!(
            err.contains("budget mémoire dépassé") || err.contains("mémoire épuisée"),
            "un SQLITE_NOMEM doit sortir en refus d'exploitant, pas en texte brut : {err}"
        );
        assert!(!err.contains("annulée") && !err.contains("interrompue"), "ce n'est pas une interruption : {err}");
    }

    /// Un tri qui déverse au-delà du quota, exécuté par `run_on_conn` : le refus nomme le quota (seule
    /// cause qui laisse une note), jamais « budget dépassé ».
    #[test]
    fn un_quota_de_deversement_franchi_sort_de_run_on_conn_en_refus_de_quota() {
        const LIGNES: i64 = 40_000;
        let dir = crate::tmp_possede::TmpPossede::neuf("acc-quota-run-on-conn");
        let conn = Connection::open_in_memory().expect("base d'épreuve ouvrable");
        conn.execute_batch(&format!(
            "PRAGMA temp_store_directory='{}'; PRAGMA temp_store=FILE; PRAGMA cache_size=-2048;",
            dir.display()
        ))
        .expect("les réglages de déversement doivent être acceptés");
        let pris: String = conn.query_row("PRAGMA temp_store_directory", [], |r| r.get(0)).unwrap_or_default();
        assert_eq!(
            pris.trim_matches('\''),
            dir.display().to_string(),
            "PRÉMISSE RÉFUTÉE : le moteur n'a pas pris le répertoire du témoin, le déversement irait ailleurs"
        );
        conn.execute_batch(&format!(
            "CREATE TABLE t(a TEXT); \
             INSERT INTO t(a) WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i<{LIGNES}) \
             SELECT hex(randomblob(80)) FROM s;"
        ))
        .expect("le jeu d'épreuve doit se construire");
        crate::sqlite_plafond::poser_la_surveillance_du_quota(&conn, dir.to_path_buf(), 1048576);
        let r = crate::query_exec::run_on_conn(&conn, ":memory:quota-run-on-conn", "SELECT a FROM t ORDER BY a", 600_000, None);
        // Le réglage est GLOBAL au processus : le rendre au silence avant que la fixture ne s'efface.
        let _ = conn.execute_batch("PRAGMA temp_store_directory=''");
        let err = match r {
            Ok(v) => panic!("le tri a déversé au-delà du quota sans être refusé : {}", v["stats"]),
            Err(m) => m,
        };
        assert!(err.contains("quota de déversement dépassé"), "le refus ne nomme pas le quota : {err}");
        assert!(
            !err.contains("budget") && !err.contains("interrompue") && !err.contains("annulée"),
            "un franchissement de quota rendu comme budget dépassé ou annulation : {err}"
        );
        assert!(
            crate::sqlite_plafond::refus_de_quota_de_deversement().is_none(),
            "la note de refus survit à sa requête"
        );
    }

    /// L'annulation posée APRÈS que le fil de la garde est entré dans son attente le réveille : la garde
    /// émet sa première interruption sans attendre son échéance (dix minutes).
    #[test]
    fn une_annulation_reveille_une_garde_qui_attend_deja() {
        let (cle, qid) = (":memory:garde-qui-attend", "qid-garde-qui-attend");
        let c = Connection::open_in_memory().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let drapeau = Arc::new(AtomicBool::new(false));
        let _i = Instruments::poser(&n);
        let garde = crate::query_exec::budget_guard(c.get_interrupt_handle(), 600_000);
        let entree = crate::query_exec::cancel_register(
            cle,
            qid,
            c.get_interrupt_handle(),
            crate::query_exec::DrapeauDAnnulation::avec_reveil(drapeau.clone(), garde.reveil()),
        );
        // Le fil de la garde est entré dans son attente (voir l'aveu en tête de fichier).
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(n.load(Ordering::SeqCst), 0, "instrument : la garde a interrompu avant toute annulation");
        assert_eq!(crate::query_exec::annuler_les_requetes(cle, qid), 1, "instrument : l'annulation n'a rien atteint");
        assert!(
            attendre_au_moins(&n, 1),
            "la garde qui attendait déjà n'a pas été réveillée par l'annulation : aucune interruption émise"
        );
        drop(entree);
        drop(garde);
    }
}
