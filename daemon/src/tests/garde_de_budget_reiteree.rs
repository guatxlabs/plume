// ================================================================================================
// P10.31-w — UNE ÉCHÉANCE TOMBÉE AVANT LE PREMIER PAS N'EST PLUS EFFACÉE
// ================================================================================================
// SQLite remet à zéro le drapeau d'interruption au début de la préparation et au premier pas quand
// aucune instruction de la connexion n'est active. La garde de budget n'appelait `interrupt()` qu'UNE
// fois : une échéance passée pendant la préparation (ou entre la préparation et le premier pas) était
// effacée, et la requête folle courait jusqu'au bout. Ces témoins sont DÉTERMINISTES : ils attendent
// que la garde ait RÉELLEMENT émis son interruption (instrument `temoin_des_interruptions_de_ce_fil`)
// avant de laisser la requête démarrer — aucune course contre une durée.
//
// MUTATIONS jouées (VERIF_MUT, retirées du source avant le commit) :
//   · « une seule interruption » (la garde rend la main après le premier `interrupt()`, comportement
//     d'avant) ⇒ les deux premiers témoins ROUGISSENT (la requête rend son compte) ;
//   · `M4` « réitération bornée à deux » ⇒ `la_garde_expiree_interrompt_chaque_requete_jusqu_a_sa_fin`
//     ROUGIT (trois interruptions perdues ne sont jamais atteintes) ;
//   · `M5` « Drop sans signal ni join » (la garde survit à sa portée et interrompt toujours) ⇒ les
//     deux premiers témoins ROUGISSENT sur la requête SUIVANTE, plus longue qu'une période ;
//   · `M3` « période de 1500 ms » ⇒ `la_periode_de_reiteration_est_de_dix_millisecondes` ROUGIT.

#[cfg(test)]
mod garde_de_budget_reiteree {
    use rusqlite::hooks::{AuthContext, Authorization};
    use rusqlite::Connection;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Dix millions d'itérations : sans garde, plusieurs secondes de calcul (la requête se TERMINE,
    /// donc le rouge du mutant est un compte rendu, pas un blocage).
    const LONGUE: &str =
        "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 10000000) SELECT count(*) FROM c";

    /// Deux millions d'itérations : la requête SUIVANTE, hors garde. Elle dure des centaines de
    /// périodes de réitération, donc une garde qui interromprait encore après sa portée la casserait
    /// à coup sûr (un `SELECT 1` n'a aucun point de contrôle de l'interruption : il ne prouve rien).
    const SUIVANTE: &str =
        "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 2000000) SELECT count(*) FROM c";

    /// Borne d'attente de l'instrument : au-delà, le témoin refuse de conclure (il ne passe pas vert).
    const ATTENTE_MAX: Duration = Duration::from_secs(20);

    /// Attend que la garde armée sur ce fil ait émis au moins une interruption.
    fn attendre_une_interruption(n: &AtomicUsize) -> bool {
        attendre_au_moins(n, 1)
    }

    /// Attend que la garde armée sur ce fil ait émis au moins `seuil` interruptions.
    fn attendre_au_moins(n: &AtomicUsize, seuil: usize) -> bool {
        let t0 = Instant::now();
        while n.load(Ordering::SeqCst) < seuil {
            if t0.elapsed() > ATTENTE_MAX {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        true
    }

    /// La garde est jointe : plus rien n'interrompt la connexion. Une requête plus longue qu'une période
    /// de réitération rend son compte, et le compteur de la garde ne bouge plus.
    fn rien_n_interrompt_plus_la_connexion(c: &Connection, n: &AtomicUsize) {
        let avant = n.load(Ordering::SeqCst);
        let r = c.query_row(SUIVANTE, [], |row| row.get::<_, i64>(0));
        assert_eq!(
            r.expect("la requête suivante, hors garde, ne doit pas être interrompue"),
            2_000_000,
            "connexion réutilisable après la garde"
        );
        assert_eq!(n.load(Ordering::SeqCst), avant, "la garde a interrompu après sa portée");
    }

    /// L'échéance tombe PENDANT la préparation : l'autorisateur (appelé à la génération du code)
    /// retient la préparation jusqu'à ce que la garde ait interrompu. Avant le correctif, le premier
    /// pas effaçait cette interruption et la requête rendait son compte.
    #[test]
    fn une_echeance_passee_pendant_la_preparation_abandonne_la_requete() {
        let c = Connection::open_in_memory().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let vue = Arc::new(AtomicBool::new(false));
        {
            let n = n.clone();
            let vue = vue.clone();
            let mut premier = true;
            c.authorizer(Some(move |_ctx: AuthContext<'_>| {
                if premier {
                    premier = false;
                    vue.store(attendre_une_interruption(&n), Ordering::SeqCst);
                }
                Authorization::Allow
            }));
        }
        crate::query_exec::temoin_des_interruptions_de_ce_fil(Some(n.clone()));
        let r = crate::query_exec::run_on_conn(&c, ":memory:garde-reiteree-preparation", LONGUE, 1, None);
        crate::query_exec::temoin_des_interruptions_de_ce_fil(None);
        c.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        assert!(
            vue.load(Ordering::SeqCst),
            "instrument : la garde n'a émis aucune interruption pendant la préparation, rien n'est prouvé"
        );
        let err = r.expect_err(
            "une échéance passée pendant la préparation DOIT abandonner la requête ; elle a couru jusqu'au bout",
        );
        assert!(err.contains("budget"), "la cause rendue doit être le budget : {err}");
        assert!(!err.contains("annulée"), "un dépassement de budget n'est pas une annulation client : {err}");
        // La connexion rendue n'est pas empoisonnée : la garde est jointe, plus rien ne l'interrompt.
        rien_n_interrompt_plus_la_connexion(&c, &n);
    }

    /// L'échéance tombe AVANT la préparation (fil déprogrammé), sur la garde telle que
    /// `read_with_watchdog` l'arme autour d'une fermeture : la requête lancée ensuite est abandonnée.
    #[test]
    fn une_echeance_passee_avant_le_premier_pas_abandonne_la_requete() {
        let c = Connection::open_in_memory().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        crate::query_exec::temoin_des_interruptions_de_ce_fil(Some(n.clone()));
        let r = {
            let _garde = crate::query_exec::budget_guard(c.get_interrupt_handle(), 1);
            assert!(attendre_une_interruption(&n), "instrument : la garde n'a émis aucune interruption");
            c.query_row(LONGUE, [], |row| row.get::<_, i64>(0))
        };
        crate::query_exec::temoin_des_interruptions_de_ce_fil(None);
        match r {
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::OperationInterrupted => {}
            autre => panic!("une échéance passée avant le premier pas DOIT abandonner la requête ; rendu : {autre:?}"),
        }
        rien_n_interrompt_plus_la_connexion(&c, &n);
    }

    /// « Jusqu'à la fin de la requête » : la garde expirée n'abandonne jamais. Trois interruptions
    /// sont PERDUES avant le premier pas (aucune instruction active), puis DEUX requêtes s'enchaînent
    /// sous la même garde, comme les fermetures de `read_with_watchdog` : chacune est abandonnée, et
    /// la garde continue d'interrompre entre les deux.
    #[test]
    fn la_garde_expiree_interrompt_chaque_requete_jusqu_a_sa_fin() {
        let c = Connection::open_in_memory().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        crate::query_exec::temoin_des_interruptions_de_ce_fil(Some(n.clone()));
        let (premiere, seconde) = {
            let _garde = crate::query_exec::budget_guard(c.get_interrupt_handle(), 1);
            assert!(attendre_au_moins(&n, 3), "la garde expirée a cessé d'interrompre avant trois interruptions");
            let premiere = c.query_row(LONGUE, [], |row| row.get::<_, i64>(0));
            let apres = n.load(Ordering::SeqCst);
            assert!(attendre_au_moins(&n, apres + 3), "la garde expirée a cessé d'interrompre après la première requête");
            let seconde = c.query_row(LONGUE, [], |row| row.get::<_, i64>(0));
            (premiere, seconde)
        };
        crate::query_exec::temoin_des_interruptions_de_ce_fil(None);
        for (nom, r) in [("première", premiere), ("seconde", seconde)] {
            match r {
                Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::OperationInterrupted => {}
                autre => panic!("la {nom} requête sous la garde expirée DOIT être abandonnée ; rendu : {autre:?}"),
            }
        }
        rien_n_interrompt_plus_la_connexion(&c, &n);
    }

    /// La période de réitération est fixée : elle borne le dépassement d'une échéance perdue. Assertion
    /// sur la constante, pas sur un chronomètre (un témoin chronométrique frappe dans les deux sens).
    #[test]
    fn la_periode_de_reiteration_est_de_dix_millisecondes() {
        assert_eq!(Duration::as_millis(&crate::query_exec::REITERATION_DE_L_INTERRUPTION), 10);
    }

    /// La distinction annulation client / budget reste juste : une annulation (registre `QUERY_CANCEL`)
    /// pendant le parcours, sous un budget non atteint, se dit « annulée par l'utilisateur », et la garde
    /// n'a rien émis. Ce n'est PAS le geste de /api/cancel : depuis `P10.31-y`, la route passe par
    /// `annuler_les_requetes`, qui réveille AUSSI la garde (elle réitère alors, et `n` ne vaudrait plus 0).
    /// Ici seuls le drapeau et une interruption unique sont posés, à dessein : le témoin juge le CLASSEMENT
    /// (drapeau lu, pas le budget), et `n == 0` dit seulement que l'échéance n'est pas passée. Le geste
    /// réel de la route est témoigné dans `annulation_reiteree.rs`.
    #[test]
    fn l_annulation_client_reste_distincte_du_budget() {
        let c = Connection::open_in_memory().unwrap();
        let cle = ":memory:garde-reiteree-annulation";
        let qid = "qid-garde-reiteree";
        c.create_scalar_function("gbr_annuler_ici", 1, rusqlite::functions::FunctionFlags::SQLITE_UTF8, move |ctx| {
            let x: i64 = ctx.get(0)?;
            if x == 1000 {
                if let Some(reg) = crate::query_exec::QUERY_CANCEL.get() {
                    let map = reg.lock();
                    if let Some(v) = map.get(&(cle.to_string(), qid.to_string())) {
                        for e in v {
                            e.cancelled.store(true, Ordering::Relaxed);
                            e.interrupt.interrupt();
                        }
                    }
                }
            }
            Ok(x)
        })
        .unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        crate::query_exec::temoin_des_interruptions_de_ce_fil(Some(n.clone()));
        let sql = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 10000000) \
                   SELECT count(gbr_annuler_ici(x)) FROM c";
        let r = crate::query_exec::run_on_conn(&c, cle, sql, 600_000, Some(qid));
        crate::query_exec::temoin_des_interruptions_de_ce_fil(None);
        assert_eq!(r.expect_err("l'annulation doit arrêter la requête"), "requête annulée par l'utilisateur");
        assert_eq!(n.load(Ordering::SeqCst), 0, "sous un budget non atteint, la garde n'interrompt jamais");
    }
}
