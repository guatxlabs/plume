// =====================================================================================
// `P10.29-w` (vague BC) — LA COUVERTURE D'UNE RÉPONSE DONT LE BRAS FROID A ÉTÉ LU, JUGÉE À L'APPELANT RÉEL SOUS UNE
// BASE PRISE : NI « RÉGLAGE NON LU », NI « POOL NON PRIS ».
//
// LES DÉFAUTS, RELEVÉS PAR LE VÉRIFICATEUR DE LA VAGUE BB (de4b4bd9) ET RE-MESURÉS ICI :
//  * le classement de l'échec de l'horizon froid dans `panneau_avoue::horizon_de_la_voie_froide_lue` (bras
//    `Err(Err(notice))` et son `continue`, puis `horizon_froid_non_mesure.or(politique_muette)`) n'était jugé par rien :
//    les témoins `bb2c_` n'appellent que l'aide `plancher_de_l_horizon_froid`. Le chemin est atteignable : le crochet
//    `AvantLaPriseDeLHorizon` prend la base pendant la lecture du pool ;
//  * une famille CHAUDE nommée par le même SQL (`metric`, `alert`…) lisait son réglage par `retention_effective_lue`,
//    texte sans code : sous la base prise, la couverture disait « réglage `metric_raw_hours` non lu ». Remède :
//    `panneau_avoue::retention_de_la_famille_lue`, même patron que `HorizonDeLecture::lire` (point de sauvegarde, sonde
//    classée par son code, lecture tenue jusqu'à la libération).
//
// Base en journal de rollback (en WAL, un lecteur ne rencontre pas le verrou d'un écrivain) : un écrivain du même
// processus tient le verrou EXCLUSIF. Le pool de lecture attend son délai d'occupation avant d'échouer.
//
// MUTANTS (variable VERIF_MUT sous `cfg!(test)` dans `panneau_avoue.rs`, retirés avant le commit), chacun vu ROUGE :
//  BC2_FORME_D_AVANT (l'échec non classé de `event` rendu « retention_days ») : (1), (2) ;
//  BC2_NOTICE_PERDUE (`continue` sans noter la notice de `event`) : (1) — en (2), la famille chaude occupée sert la même
//    notice, la perte n'y est pas observable ;
//  BC2_OR_PERDU (la notice de l'horizon non mesuré jamais servie) : (1), (2), (3) ;
//  BC2_CHAUD_FORME_D_AVANT (famille chaude lue par `retention_effective_lue` nue) : (2), (3), (6), (7) ;
//  BC2_CHAUD_NOTICE_PERDUE (famille chaude occupée : `continue` sans noter) : (3) ;
//  BC2_CHAUD_OCC_EN_NON_PRIS (occupée classée « non prise ») : (3) ;
//  BC2_CHAUD_NON_PRIS_EN_OCC (tout échec de prise classé occupé) : (6) ;
//  BC2_CHAUD_ILLISIBLE_EN_NON_PRIS (réglage chaud illisible classé « non prise ») : (4) ;
//  BC2_CHAUD_SANS_RELEASE_SUR_ERREUR : (4) ; BC2_CHAUD_SANS_RELEASE_SUR_SUCCES : (3), (5) ;
//  BC2_CHAUD_RELACHE_APRES_SONDE (point libéré juste après la sonde) : (7) ;
//  BC2_CHAUD_SANS_RELEASE_SUR_PRISE (sonde occupée : rendu avant le `RELEASE`, connexion laissée en transaction) :
//    (3) (la connexion du pool rendue en transaction est fermée, plus aucune au repos), (8).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la classe « non prise » d'une famille chaude n'est jugée que sur l'aide (un
// fichier qui n'est pas une base ne laisse pas le pool ouvrir sa connexion : la couverture y rend « pool non pris »).
// L'échec du `RELEASE` lui-même est dit HORS D'ATTEINTE au site.
// RESTE NOMMÉ (vérificateur BC2-1) : `SELECT ts FROM event` sous une base prise AVANT l'appel (pool chaud) rend la
// notice « les politiques de rétention par environnement n'ont pas pu être lues », pas la base occupée :
// `politique_lue` (`panneau_avoue.rs`) range tout `Err` de `lire_les_politiques_d_index` en `NonLue`, et cette lecture
// précède l'horizon de `event`. Les témoins (1) et (2) arment le verrou à `AvantLaPriseDeLHorizon`, donc APRÈS elle.
// =====================================================================================
#[cfg(all(test, feature = "cold_tier"))]
mod bc2_couverture_froide_sous_base_prise {
    use super::*;
    use crate::query_exec::crochet_de_l_union_froide::{armer, desarmer, Etape};

    const BC2_RAISON_NON_MESUREE: &str = "horizon_non_mesure";
    const BC2_NOTICE_OCCUPEE: &str = "la base est occupée (verrou tenu par une autre opération) : l'horizon de conservation de cette lecture n'a PAS été mesuré, réessayez dans un instant. Cette réponse ne dit donc RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";
    const BC2_NOTICE_NON_PRISE: &str = "la lecture de l'horizon de conservation n'a pas pu être prise (refus de la base) ; l'horizon n'a PAS été mesuré. Cette réponse ne dit donc RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";
    const BC2_SQL_EVENT: &str = "SELECT ts FROM event";
    const BC2_SQL_EVENT_ET_METRIC: &str = "SELECT ts FROM event UNION ALL SELECT ts FROM metric";
    const BC2_SQL_METRIC: &str = "SELECT ts FROM metric";
    /// Valeur écrite de `metric_raw_hours` : distincte du défaut (48), pour que le repli ne passe pas pour elle.
    const BC2_HEURES_ECRITES: i64 = 72;

    /// Retire un crochet resté armé (témoin qui panique avant l'étape).
    struct Bc2Desarme;
    impl Drop for Bc2Desarme {
        fn drop(&mut self) {
            desarmer();
        }
    }

    /// Le banc froid, passé en journal de rollback avant toute connexion de lecture.
    async fn bc2_banc(etiquette: &str) -> BancFroidSurLaRoute {
        let banc = BancFroidSurLaRoute::monter(etiquette, false).await;
        assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(&banc.chemin_base), 0, "{etiquette} : instrument : aucune connexion de lecture ouverte");
        let mode: String = banc.st.db.lock().query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0)).expect("fixture : mode de journal");
        assert_eq!(mode, "delete", "{etiquette} : instrument : base passée en journal de rollback");
        banc
    }

    /// La couverture rendue par l'appelant réel, pour `sql`.
    fn bc2_couverture(banc: &BancFroidSurLaRoute, sql: &str) -> Value {
        crate::panneau_avoue::horizon_de_la_voie_froide_lue(
            &banc.chemin_base,
            &banc.conf,
            sql,
            banc.base_froide - 60,
            banc.maintenant,
            banc.minuit - 2 * JOUR,
            None,
        )
    }

    /// Les clés de la couverture, triées.
    fn bc2_cles(cov: &Value) -> Vec<String> {
        let mut cles: Vec<String> = cov.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        cles.sort();
        cles
    }

    /// La couverture d'un horizon NON MESURÉ sous une base occupée : corps entier.
    fn bc2_est_occupee(cov: &Value, etiquette: &str) {
        assert_eq!(bc2_cles(cov), vec!["calcule_a", "notice", "reason", "searched_from"], "{etiquette} : corps entier, aucun réglage nommé : {cov}");
        assert_eq!(cov["reason"], json!(BC2_RAISON_NON_MESUREE), "{etiquette} : {cov}");
        assert_eq!(cov["notice"], json!(BC2_NOTICE_OCCUPEE), "{etiquette} : la base occupée, ni réglage non lu ni pool non pris : {cov}");
    }

    /// Un horizon MESURÉ : la couverture porte `horizon_ts`.
    fn bc2_est_mesuree(cov: &Value, etiquette: &str) {
        assert!(cov["horizon_ts"].is_i64(), "{etiquette} : contrôle, horizon mesuré : {cov}");
        assert!(cov.get("reglage_non_lu").is_none(), "{etiquette} : contrôle, aucun réglage non lu : {cov}");
    }

    /// Arme, à `AvantLaPriseDeLHorizon` sur la base du banc, l'écrivain du banc qui prend le verrou EXCLUSIF et le garde.
    fn bc2_armer_le_verrou_a_l_horizon(banc: &BancFroidSurLaRoute) -> std::sync::Arc<parking_lot::Mutex<Vec<String>>> {
        let chemin = banc.st.db.lock().path().expect("instrument : chemin de la base").to_string();
        let constats: std::sync::Arc<parking_lot::Mutex<Vec<String>>> = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let db = banc.st.db.clone();
        let c = constats.clone();
        armer(
            &chemin,
            Etape::AvantLaPriseDeLHorizon,
            Box::new(move || {
                let pris = db.lock().execute_batch("BEGIN EXCLUSIVE; INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global','bc2-verrou','1');");
                c.lock().push(match pris {
                    Ok(()) => "verrou pris".to_string(),
                    Err(e) => format!("verrou NON pris : {e}"),
                });
            }),
        );
        constats
    }

    /// Une base prise à la lecture de l'horizon de `event`, pour `sql` : la couverture dit l'occupation ; contrôle, verrou
    /// rendu, l'horizon est mesuré.
    async fn bc2_event_sous_base_prise(etiquette: &str, sql: &str) {
        let banc = bc2_banc(etiquette).await;
        let _desarme = Bc2Desarme;
        let constats = bc2_armer_le_verrou_a_l_horizon(&banc);
        let cov = bc2_couverture(&banc, sql);
        banc.st.db.lock().execute_batch("ROLLBACK;").expect("fixture : verrou rendu");
        assert!(!desarmer(), "{etiquette} : la lecture de l'horizon froid a été atteinte (crochet passé) : {cov}");
        assert_eq!(*constats.lock(), vec!["verrou pris".to_string()], "{etiquette} : instrument : la base était prise à l'horizon");
        bc2_est_occupee(&cov, etiquette);
        bc2_est_mesuree(&bc2_couverture(&banc, sql), etiquette);
    }

    /// (1) `event` seul : la notice de l'horizon froid occupé est servie.
    /// MUTANTS : BC2_FORME_D_AVANT, BC2_NOTICE_PERDUE, BC2_OR_PERDU.
    #[tokio::test]
    async fn bc2_couverture_event_sous_base_prise_dit_occupee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        bc2_event_sous_base_prise("bc2-event", BC2_SQL_EVENT).await;
    }

    /// (2) `event` et `metric` : la base reste prise pour la famille chaude, qui ne se dit pas « réglage non lu ».
    /// MUTANTS : BC2_FORME_D_AVANT, BC2_OR_PERDU, BC2_CHAUD_FORME_D_AVANT.
    #[tokio::test]
    async fn bc2_couverture_event_et_metric_sous_base_prise_dit_occupee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        bc2_event_sous_base_prise("bc2-event-metric", BC2_SQL_EVENT_ET_METRIC).await;
    }

    /// (3) `metric` seul, base prise avant l'appel (le pool est chaud : sa connexion est déjà ouverte) : l'occupation est
    /// dite. Contrôle avant et après : l'horizon est mesuré.
    /// MUTANTS : BC2_OR_PERDU, BC2_CHAUD_FORME_D_AVANT, BC2_CHAUD_NOTICE_PERDUE, BC2_CHAUD_OCC_EN_NON_PRIS,
    /// BC2_CHAUD_SANS_RELEASE_SUR_SUCCES (la connexion du pool rendue en transaction est fermée, le pool n'est plus chaud),
    /// BC2_CHAUD_SANS_RELEASE_SUR_PRISE (même fermeture, sur la sonde occupée : plus aucune connexion au repos).
    #[tokio::test]
    async fn bc2_couverture_famille_chaude_sous_base_prise_dit_occupee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let banc = bc2_banc("bc2-metric").await;
        bc2_est_mesuree(&bc2_couverture(&banc, BC2_SQL_METRIC), "bc2-metric avant");
        assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(&banc.chemin_base), 1, "instrument : la connexion du pool est au repos");
        banc.st.db.lock().execute_batch("BEGIN EXCLUSIVE; INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global','bc2-verrou','1');").expect("fixture : verrou exclusif");
        let cov = bc2_couverture(&banc, BC2_SQL_METRIC);
        let au_repos = crate::query_exec::connexions_de_lecture_au_repos(&banc.chemin_base);
        banc.st.db.lock().execute_batch("ROLLBACK;").expect("fixture : verrou rendu");
        bc2_est_occupee(&cov, "bc2-metric");
        assert_eq!(au_repos, 1, "la connexion du pool revient au repos après la sonde occupée (point de sauvegarde libéré) : {cov}");
        bc2_est_mesuree(&bc2_couverture(&banc, BC2_SQL_METRIC), "bc2-metric après");
    }

    /// Une connexion neuve sur la base du banc (clé du registre).
    fn bc2_connexion(banc: &BancFroidSurLaRoute) -> Connection {
        let c = Connection::open(&banc.chemin_base).expect("fixture : connexion");
        crate::crypto::apply_key_for(&c, &banc.chemin_base);
        c
    }

    /// (4) RÉGLAGE CHAUD ÉCRIT ET ILLISIBLE : la couverture le nomme toujours (corps entier) ; l'aide le rend sous sa clé
    /// et libère son point de sauvegarde sur l'erreur.
    /// MUTANTS : BC2_CHAUD_ILLISIBLE_EN_NON_PRIS, BC2_CHAUD_SANS_RELEASE_SUR_ERREUR.
    #[tokio::test]
    async fn bc2_reglage_chaud_illisible_reste_nomme_et_libere() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let banc = bc2_banc("bc2-illisible").await;
        banc.st.db.lock().execute("INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global','metric_raw_hours','dix')", []).expect("fixture : réglage illisible");
        let cov = bc2_couverture(&banc, BC2_SQL_METRIC);
        assert_eq!(bc2_cles(&cov), vec!["calcule_a", "notice", "reason", "reglage_non_lu", "searched_from"], "corps entier : {cov}");
        assert_eq!(cov["reason"], json!(BC2_RAISON_NON_MESUREE), "{cov}");
        assert_eq!(cov["reglage_non_lu"], json!("metric_raw_hours"), "le réglage illisible est nommé : {cov}");
        let c = bc2_connexion(&banc);
        assert_eq!(crate::panneau_avoue::retention_de_la_famille_lue(&c, &banc.conf, "metric_raw_hours"), Err(Ok("metric_raw_hours")), "aide : réglage illisible");
        assert!(c.is_autocommit(), "le point de sauvegarde est libéré sur l'erreur");
    }

    /// (5) RÉGLAGE CHAUD LU : la couverture mesure l'horizon sur la valeur ÉCRITE ; l'aide la rend et libère.
    /// MUTANT : BC2_CHAUD_SANS_RELEASE_SUR_SUCCES.
    #[tokio::test]
    async fn bc2_reglage_chaud_lu_mesure_et_libere() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let banc = bc2_banc("bc2-lu").await;
        banc.st
            .db
            .lock()
            .execute("INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global','metric_raw_hours',?1)", params![BC2_HEURES_ECRITES.to_string()])
            .expect("fixture : réglage écrit");
        let cov = bc2_couverture(&banc, BC2_SQL_METRIC);
        assert_eq!(cov["horizon_ts"], json!(banc.maintenant - BC2_HEURES_ECRITES * 3_600), "horizon sur la valeur écrite : {cov}");
        let c = bc2_connexion(&banc);
        assert_eq!(crate::panneau_avoue::retention_de_la_famille_lue(&c, &banc.conf, "metric_raw_hours"), Ok(BC2_HEURES_ECRITES), "aide : valeur écrite");
        assert!(c.is_autocommit(), "le point de sauvegarde est libéré sur le succès");
    }

    /// (6) LECTURE NON PRISE HORS OCCUPATION (aide seule) : un fichier qui n'est pas une base fait échouer la sonde
    /// (NOTADB) ; ni occupée, ni réglage non lu.
    /// MUTANTS : BC2_CHAUD_NON_PRIS_EN_OCC, BC2_CHAUD_FORME_D_AVANT.
    #[test]
    fn bc2_lecture_chaude_non_prise_dite_non_prise() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let base = crate::tmp_possede::TmpDb::neuf("bc2-pas-une-base");
        std::fs::write(base.as_str(), vec![0x5Au8; 8192]).expect("fixture : fichier qui n'est pas une base");
        let c = Connection::open(base.as_str()).expect("fixture : connexion");
        let conf: HashMap<String, String> = HashMap::new();
        assert_eq!(crate::panneau_avoue::retention_de_la_famille_lue(&c, &conf, "metric_raw_hours"), Err(Err(BC2_NOTICE_NON_PRISE)), "lecture non prise : dite non prise");
    }

    /// (7) LA LECTURE DE `main` EST TENUE DE LA SONDE AU RÉGLAGE : juste après la sonde, un écrivain neuf (attente nulle)
    /// tente le verrou EXCLUSIF ; il lui est refusé, et l'horizon est mesuré.
    /// MUTANTS : BC2_CHAUD_RELACHE_APRES_SONDE (l'écrivain prend le verrou, le réglage rencontre la base prise),
    /// BC2_CHAUD_FORME_D_AVANT (aucune sonde : le crochet n'est pas passé).
    #[tokio::test]
    async fn bc2_lecture_chaude_tenue_de_la_sonde_au_reglage() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let banc = bc2_banc("bc2-tenue").await;
        let chemin = banc.st.db.lock().path().expect("instrument : chemin de la base").to_string();
        let constats: std::sync::Arc<parking_lot::Mutex<Vec<String>>> = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let tenu: std::sync::Arc<parking_lot::Mutex<Option<Connection>>> = std::sync::Arc::new(parking_lot::Mutex::new(None));
        let _desarme = Bc2Desarme;
        {
            let c = constats.clone();
            let t = tenu.clone();
            let chemin_ecrivain = banc.chemin_base.clone();
            armer(
                &chemin,
                Etape::ApresLaPriseDeLaRetentionDeLaFamille,
                Box::new(move || {
                    let ecrivain = Connection::open(&chemin_ecrivain).expect("instrument : écrivain neuf");
                    crate::crypto::apply_key_for(&ecrivain, &chemin_ecrivain);
                    let _ = ecrivain.busy_timeout(std::time::Duration::ZERO);
                    match ecrivain.execute_batch("BEGIN EXCLUSIVE;") {
                        Ok(()) => {
                            c.lock().push("verrou pris".to_string());
                            *t.lock() = Some(ecrivain);
                        }
                        Err(e) => c.lock().push(match e.sqlite_error_code() {
                            Some(rusqlite::ErrorCode::DatabaseBusy) => "verrou refusé".to_string(),
                            _ => format!("verrou NON tenté : {e}"),
                        }),
                    }
                }),
            );
        }
        let cov = bc2_couverture(&banc, BC2_SQL_METRIC);
        if let Some(ecrivain) = tenu.lock().take() {
            ecrivain.execute_batch("ROLLBACK;").expect("fixture : verrou rendu");
        }
        assert!(!desarmer(), "le crochet de la famille chaude a été passé : {cov}");
        assert_eq!(*constats.lock(), vec!["verrou refusé".to_string()], "la lecture tient la base contre un écrivain : {cov}");
        bc2_est_mesuree(&cov, "bc2-tenue");
    }

    /// (8) SONDE OCCUPÉE (aide seule) : un écrivain tient le verrou EXCLUSIF, la connexion de l'aide n'attend pas ; la
    /// sonde échoue occupée, et le point de sauvegarde est libéré sur cet échec de PRISE (connexion hors transaction).
    /// MUTANT : BC2_CHAUD_SANS_RELEASE_SUR_PRISE.
    #[tokio::test]
    async fn bc2_sonde_occupee_dite_occupee_et_libere() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let banc = bc2_banc("bc2-sonde-occupee").await;
        banc.st.db.lock().execute_batch("BEGIN EXCLUSIVE; INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global','bc2-verrou','1');").expect("fixture : verrou exclusif");
        let c = bc2_connexion(&banc);
        c.busy_timeout(std::time::Duration::ZERO).expect("fixture : attente nulle");
        let lu = crate::panneau_avoue::retention_de_la_famille_lue(&c, &banc.conf, "metric_raw_hours");
        let hors_transaction = c.is_autocommit();
        banc.st.db.lock().execute_batch("ROLLBACK;").expect("fixture : verrou rendu");
        assert_eq!(lu, Err(Err(BC2_NOTICE_OCCUPEE)), "aide : sonde occupée, dite occupée");
        assert!(hors_transaction, "le point de sauvegarde est libéré sur l'échec de la prise");
    }
}
