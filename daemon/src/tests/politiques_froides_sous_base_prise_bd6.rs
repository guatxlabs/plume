// =====================================================================================
// `P10.29-w` (vague BD) — SOUS LA VOIE FROIDE LUE, UNE BASE OCCUPÉE À LA LECTURE DES POLITIQUES PAR INDEX EST DITE
// OCCUPÉE, PAS « POLITIQUES NON LUES » ; ET L'ORDRE DES DEUX AVEUX (horizon non mesuré d'abord) A SON TÉMOIN.
//
// LE DÉFAUT, NOMMÉ PAR LE VÉRIFICATEUR DE LA VAGUE BC (en-tête de `couverture_froide_sous_base_prise_bc2.rs`) ET
// RE-MESURÉ ICI : `panneau_avoue::horizon_de_la_voie_froide_lue` lit les politiques par index AVANT l'horizon de toute
// famille, par `politique_lue`, qui rangeait tout refus de `rollups::lire_les_politiques_d_index` en `NonLue`. Une base
// prise AVANT l'appel (pool chaud) faisait donc dire à `SELECT ts FROM event` (et à `event_rollup`) « les politiques de
// rétention par environnement n'ont pas pu être lues ». Remède : `politique_de_la_voie_froide_lue` classe le refus par
// son CODE (BUSY, LOCKED : `code_de_base_occupee`) ; occupée, la notice rejoint l'aveu de l'horizon non mesuré.
//
// L'ORDRE `horizon_froid_non_mesure.or(politique_muette)` : après le remède, une base prise AVANT l'appel ne pose plus
// jamais `politique_muette` (le refus occupé des politiques va à `horizon_froid_non_mesure`), si bien que le SQL
// `event`+`metric` sous une base prise avant l'appel (5) ne distingue plus l'ordre : les deux voies rendent la même
// notice. Le témoin (3) pose les DEUX aveux distincts : une politique illisible (refus hors occupation, `NonLue`) puis la
// base prise par un crochet APRÈS la lecture des politiques (`Etape::ApresLesPolitiquesDeLaVoieFroide`), avant la sonde
// de `metric`.
//
// Base en journal de rollback (en WAL, un lecteur ne rencontre pas le verrou d'un écrivain) : l'écrivain du banc tient
// le verrou EXCLUSIF. Le pool de lecture attend son délai d'occupation avant d'échouer.
//
// MUTANTS (variable VERIF_MUT sous `cfg!(test)` dans `panneau_avoue.rs`, retirés avant le commit), chacun vu ROUGE :
//  BD6_OCCUPEE_EN_NON_LUE (refus occupé des politiques rangé `NonLue`, forme d'avant) : (1), (2) ;
//  BD6_OCCUPEE_NOTICE_PERDUE (`continue` sans noter la notice occupée) : (1), (2) ;
//  BD6_TOUT_REFUS_OCCUPE (tout refus des politiques dit occupé) : (4), et le contrôle de (3) ;
//  P_OR_INVERSE (`politique_muette.or(horizon_froid_non_mesure)`) : (3).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'horizon du panneau hors voie froide (`horizon_et_frontiere_selon_l_index`)
// range toujours un refus des politiques en `NonLue` (ce n'est pas une voie froide ; sous une base occupée, son réglage
// `retention_days` est d'ailleurs lu par `retention_effective_lue` sans classe). L'occupation est fabriquée par une
// connexion du même processus en journal de rollback.
// =====================================================================================
#[cfg(all(test, feature = "cold_tier"))]
mod bd6_politiques_froides_sous_base_prise {
    use super::*;
    use crate::query_exec::crochet_de_l_union_froide::{armer, desarmer, Etape};

    const BD6_RAISON_NON_MESUREE: &str = "horizon_non_mesure";
    const BD6_NOTICE_OCCUPEE: &str = "la base est occupée (verrou tenu par une autre opération) : l'horizon de conservation de cette lecture n'a PAS été mesuré, réessayez dans un instant. Cette réponse ne dit donc RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";
    const BD6_NOTICE_POLITIQUES_NON_LUES: &str = "l'horizon de conservation de ce panneau n'est PAS établi : les politiques de rétention par environnement n'ont pas pu être lues, et aucune fenêtre n'est calculée sur la seule rétention globale. Cette réponse ne dit RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";
    const BD6_SQL_EVENT: &str = "SELECT ts FROM event";
    const BD6_SQL_EVENT_ROLLUP: &str = "SELECT bucket FROM event_rollup";
    const BD6_SQL_EVENT_ET_METRIC: &str = "SELECT ts FROM event UNION ALL SELECT ts FROM metric";
    const BD6_VERROU: &str = "BEGIN EXCLUSIVE; INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global','bd6-verrou','1');";

    /// Retire un crochet resté armé (témoin qui panique avant l'étape).
    struct Bd6Desarme;
    impl Drop for Bd6Desarme {
        fn drop(&mut self) {
            desarmer();
        }
    }

    /// Le banc froid, passé en journal de rollback avant toute connexion de lecture.
    async fn bd6_banc(etiquette: &str) -> BancFroidSurLaRoute {
        let banc = BancFroidSurLaRoute::monter(etiquette, false).await;
        assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(&banc.chemin_base), 0, "{etiquette} : instrument : aucune connexion de lecture ouverte");
        let mode: String = banc.st.db.lock().query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0)).expect("fixture : mode de journal");
        assert_eq!(mode, "delete", "{etiquette} : instrument : base passée en journal de rollback");
        banc
    }

    /// La couverture rendue par l'appelant réel, pour `sql`.
    fn bd6_couverture(banc: &BancFroidSurLaRoute, sql: &str) -> Value {
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

    /// Un horizon NON MESURÉ, corps ENTIER : aucun réglage nommé, la notice exacte.
    fn bd6_non_mesure(banc: &BancFroidSurLaRoute, notice: &str) -> Value {
        json!({ "searched_from": banc.base_froide - 60, "calcule_a": banc.maintenant, "reason": BD6_RAISON_NON_MESUREE, "notice": notice })
    }

    /// Un horizon MESURÉ : la couverture porte `horizon_ts`.
    fn bd6_est_mesuree(cov: &Value, etiquette: &str) {
        assert!(cov["horizon_ts"].is_i64(), "{etiquette} : contrôle, horizon mesuré : {cov}");
    }

    /// Une politique écrite et ILLISIBLE (`retention_days` non entier) : la lecture des politiques est refusée hors
    /// occupation.
    fn bd6_politique_illisible(banc: &BancFroidSurLaRoute) {
        banc.st
            .db
            .lock()
            .execute("INSERT INTO index_policy(name,retention_days,max_rows,max_bytes,enabled) VALUES('prod','dix',0,0,1)", [])
            .expect("fixture : politique illisible");
    }

    /// Base prise AVANT l'appel, pool chaud, pour `sql` : contrôle avant (horizon mesuré, connexion du pool au repos), la
    /// couverture sous la base prise, la connexion du pool revenue au repos, contrôle après.
    async fn bd6_sous_base_prise_avant_l_appel(etiquette: &str, sql: &str) {
        let banc = bd6_banc(etiquette).await;
        bd6_est_mesuree(&bd6_couverture(&banc, sql), &format!("{etiquette} avant"));
        assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(&banc.chemin_base), 1, "{etiquette} : instrument : la connexion du pool est au repos");
        banc.st.db.lock().execute_batch(BD6_VERROU).expect("fixture : verrou exclusif");
        let cov = bd6_couverture(&banc, sql);
        let au_repos = crate::query_exec::connexions_de_lecture_au_repos(&banc.chemin_base);
        banc.st.db.lock().execute_batch("ROLLBACK;").expect("fixture : verrou rendu");
        assert_eq!(cov, bd6_non_mesure(&banc, BD6_NOTICE_OCCUPEE), "{etiquette} : la base occupée, ni politiques non lues ni pool non pris");
        assert_eq!(au_repos, 1, "{etiquette} : la connexion du pool est restée chaude (pas « pool non pris ») : {cov}");
        bd6_est_mesuree(&bd6_couverture(&banc, sql), &format!("{etiquette} après"));
    }

    /// (1) `event` seul, base prise avant l'appel : la lecture des politiques rencontre la base occupée et le dit.
    /// MUTANTS : BD6_OCCUPEE_EN_NON_LUE, BD6_OCCUPEE_NOTICE_PERDUE.
    #[tokio::test]
    async fn bd6_event_sous_base_prise_avant_l_appel_dit_occupee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        bd6_sous_base_prise_avant_l_appel("bd6-event", BD6_SQL_EVENT).await;
    }

    /// (2) `event_rollup` seul (famille chaude gouvernée par les politiques), base prise avant l'appel : même aveu.
    /// MUTANTS : BD6_OCCUPEE_EN_NON_LUE, BD6_OCCUPEE_NOTICE_PERDUE.
    #[tokio::test]
    async fn bd6_event_rollup_sous_base_prise_avant_l_appel_dit_occupee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        bd6_sous_base_prise_avant_l_appel("bd6-event-rollup", BD6_SQL_EVENT_ROLLUP).await;
    }

    /// (3) L'ORDRE DES DEUX AVEUX : politique illisible (`politique_muette` = politiques non lues), puis la base prise
    /// juste après la lecture des politiques, avant la sonde de `metric` (`horizon_froid_non_mesure` = occupée).
    /// L'horizon non mesuré l'emporte. Contrôle, verrou rendu : la politique illisible seule est dite.
    /// MUTANTS : P_OR_INVERSE ; BD6_TOUT_REFUS_OCCUPE (contrôle).
    #[tokio::test]
    async fn bd6_ordre_horizon_non_mesure_avant_politique_muette() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let banc = bd6_banc("bd6-ordre").await;
        bd6_politique_illisible(&banc);
        let constats: std::sync::Arc<parking_lot::Mutex<Vec<String>>> = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let _desarme = Bd6Desarme;
        {
            let db = banc.st.db.clone();
            let c = constats.clone();
            armer(
                &banc.chemin_base,
                Etape::ApresLesPolitiquesDeLaVoieFroide,
                Box::new(move || {
                    c.lock().push(match db.lock().execute_batch(BD6_VERROU) {
                        Ok(()) => "verrou pris".to_string(),
                        Err(e) => format!("verrou NON pris : {e}"),
                    });
                }),
            );
        }
        let cov = bd6_couverture(&banc, BD6_SQL_EVENT_ET_METRIC);
        banc.st.db.lock().execute_batch("ROLLBACK;").expect("fixture : verrou rendu");
        assert!(!desarmer(), "le crochet après les politiques a été passé : {cov}");
        assert_eq!(*constats.lock(), vec!["verrou pris".to_string()], "instrument : la base était prise avant la sonde de metric");
        assert_eq!(cov, bd6_non_mesure(&banc, BD6_NOTICE_OCCUPEE), "les deux aveux posés : l'horizon non mesuré (occupée) l'emporte");
        assert_eq!(
            bd6_couverture(&banc, BD6_SQL_EVENT_ET_METRIC),
            bd6_non_mesure(&banc, BD6_NOTICE_POLITIQUES_NON_LUES),
            "contrôle, verrou rendu : la politique illisible seule"
        );
    }

    /// (4) POLITIQUE ILLISIBLE, BASE LIBRE : un refus hors occupation reste « politiques non lues », jamais « occupée ».
    /// MUTANT : BD6_TOUT_REFUS_OCCUPE.
    #[tokio::test]
    async fn bd6_politique_illisible_reste_non_lue() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let banc = bd6_banc("bd6-illisible").await;
        bd6_politique_illisible(&banc);
        assert_eq!(bd6_couverture(&banc, BD6_SQL_EVENT), bd6_non_mesure(&banc, BD6_NOTICE_POLITIQUES_NON_LUES), "refus hors occupation : politiques non lues");
    }

    /// (5) `event` et `metric`, base prise avant l'appel (la forme citée par le vérificateur BC2) : l'occupation est
    /// dite. Après le remède, les deux aveux y sont la même notice : l'ordre est jugé en (3) (P_OR_INVERSE reste vert ici,
    /// vu à l'exécution). MUTANTS : aucun propre ; forme d'avant (BD6_OCCUPEE_EN_NON_LUE) aussi verte ici, la notice
    /// occupée de `metric` y était déjà servie par l'ordre.
    #[tokio::test]
    async fn bd6_event_et_metric_sous_base_prise_avant_l_appel_dit_occupee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        bd6_sous_base_prise_avant_l_appel("bd6-event-metric", BD6_SQL_EVENT_ET_METRIC).await;
    }
}
