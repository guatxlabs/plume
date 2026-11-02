// =====================================================================================
// `P10.29-w` (vague BE) — L'HORIZON D'UN PANNEAU (HORS VOIE FROIDE) SOUS UNE BASE PRISE EST DIT « OCCUPÉE », JAMAIS
// « POLITIQUES NON LUES » NI « RÉGLAGE NON LU » ; UNE PRISE REFUSÉE HORS OCCUPATION EST DITE « NON PRISE ».
//
// LE DÉFAUT, NOMMÉ PAR LE LOT BD6 (en-tête de `politiques_froides_sous_base_prise_bd6.rs`) ET RE-MESURÉ ICI :
// `panneau_avoue::horizon_et_frontiere_selon_l_index` (appelé par `/api/query` avant l'aiguillage, et par
// `horizon_et_frontiere` pour les panneaux) lisait les politiques par index par `politique_lue`, qui range tout refus en
// `NonLue`, puis chaque réglage de rétention par `retention_effective_lue`, texte sans code, chacun en autocommit. Sous
// une base prise, vu à l'exécution sur la forme d'avant (mutant BE5_SANS_SONDE) : `SELECT ts FROM event` rendait
// « réglage `retention_days` non lu » (le refus des politiques, rangé `NonLue`, y est couvert par le réglage non lu qui
// l'emporte), `SELECT ts FROM metric` « réglage `metric_raw_hours` non lu », et un fichier qui n'est pas une base aussi
// « réglage `retention_days` non lu ». Remède :
// `sous_la_lecture_de_l_horizon_du_panneau`, même patron que `HorizonDeLecture::lire` et `retention_de_la_famille_lue`
// (point de sauvegarde, sonde du schéma classée par son code, lecture tenue jusqu'à la libération).
//
// Base en journal de rollback (en WAL, un lecteur ne rencontre pas le verrou d'un écrivain) : l'écrivain du banc tient
// le verrou EXCLUSIF. Le pool de lecture attend son délai d'occupation avant d'échouer.
//
// MUTANTS (variable VERIF_MUT sous `cfg!(test)` dans `panneau_avoue.rs`, retirés avant le commit), chacun vu ROUGE :
//  BE5_SANS_SONDE (ni point de sauvegarde ni sonde, forme d'avant) : (1), (2), (3), (4) ;
//  BE5_OCC_EN_NON_PRIS (sonde occupée classée « non prise ») : (1), (2) ;
//  BE5_TOUT_EN_OCC (tout échec de la sonde classé occupé) : (4) ;
//  BE5_NOTICE_PERDUE (le refus de la prise servi comme un pool non pris) : (1), (2), (4) ;
//  BE5_SANS_RELEASE_SUR_ECHEC (sonde refusée : rendu avant le `RELEASE`) : (1), (2) (la connexion rendue en transaction
//    est fermée par le pool, aucune au repos) ;
//  BE5_SANS_RELEASE_SUR_SUCCES : (1), (2), (3) (même observation, après un horizon mesuré) ;
//  BE5_LIBERE_APRES_SONDE (le point libéré juste après la sonde) : (3) (l'écrivain prend le verrou), et (1), (2) (le
//    `RELEASE` final ne trouve plus son point : l'horizon de contrôle est dit non pris) ; ce mutant rougit (3) dès son
//    contrôle, d'où le suivant ;
//  BE5_RELACHE_PUIS_REPRISE (après la sonde, le point est libéré puis repris, sans lecture tenue entre les deux) : (3), à
//    l'assertion de l'écrivain (« verrou pris ») ;
//  V9 (erreur du `RELEASE` avalée, `(Ok(v), Err(_)) => Ok(v)`) : (5).
// Reprise (vague BF, défauts du vérificateur BE5) :
//  BF2_POOL_EN_NP (le pool non pris servi comme une lecture non prise, `NOTICE_HORIZON_FROID_NON_PRIS`) : (7) ;
//  BF2_MATCH_REL_D_ABORD (le refus du `RELEASE` jugé avant celui de la sonde) : (8) ;
//  BF2_SP_AVALE (l'erreur du `SAVEPOINT` avalée : `lire` s'exécute hors de toute lecture tenue) : (6), au crochet ;
//  BF2_FAMILLE_RELEASE_AVALE (`retention_de_la_famille_lue`, erreur du `RELEASE` avalée) : (9) ;
//  BF2_HORIZON_RELEASE_AVALE (`HorizonDeLecture::lire`, erreur du `RELEASE` avalée) : (10).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'occupation est fabriquée par une connexion du même processus en journal de
// rollback ; LOCKED n'est pas produit (aucune connexion du démon n'ouvre de cache partagé ; le prédicat commun
// `code_de_base_occupee` est jugé par les témoins `au1_`) ; l'échec du `SAVEPOINT` et du `RELEASE` est fabriqué par un
// autorisateur (témoins (5), (6), (8), (9), (10)), pas par un vrai retour en arrière automatique de SQLite (IOERR, NOMEM,
// FULL), seule cause d'un `RELEASE` refusé en production. La frontière froide n'est pas affirmée : sans le tier froid
// elle vaut toujours `None`. Le pool non pris est joué par un chemin absent (ouverture en lecture seule refusée, témoin
// (7)) ; une ouverture refusée sur un chemin qui existe (droits, descripteurs épuisés) prend le même bras, non jouée.
// =====================================================================================
#[cfg(test)]
mod be5_horizon_du_panneau_sous_base_prise {
    use super::*;
    use crate::query_exec::crochet_de_l_union_froide::{armer, desarmer, Etape};
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const BE5_RAISON_NON_MESUREE: &str = "horizon_non_mesure";
    const BE5_NOTICE_OCCUPEE: &str = "la base est occupée (verrou tenu par une autre opération) : l'horizon de conservation de cette lecture n'a PAS été mesuré, réessayez dans un instant. Cette réponse ne dit donc RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";
    const BE5_NOTICE_NON_PRISE: &str = "la lecture de l'horizon de conservation n'a pas pu être prise (refus de la base) ; l'horizon n'a PAS été mesuré. Cette réponse ne dit donc RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";
    const BE5_SQL_EVENT: &str = "SELECT ts FROM event";
    const BE5_SQL_METRIC: &str = "SELECT ts FROM metric";
    const BE5_VERROU: &str = "BEGIN EXCLUSIVE; INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global','be5-verrou','1');";
    const BE5_JOUR: i64 = 86_400;

    /// Retire un crochet resté armé (témoin qui panique avant l'étape).
    struct Be5Desarme;
    impl Drop for Be5Desarme {
        fn drop(&mut self) {
            desarmer();
        }
    }

    /// Une base aux migrations complètes, passée en journal de rollback avant toute connexion de lecture.
    fn be5_banc(etiquette: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(etiquette);
        assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(p.as_str()), 0, "{etiquette} : instrument : aucune connexion de lecture ouverte");
        let mode: String = st.db.lock().query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0)).expect("fixture : mode de journal");
        assert_eq!(mode, "delete", "{etiquette} : instrument : base passée en journal de rollback");
        (st, p)
    }

    /// L'horizon rendu par le point d'entrée que `/api/query` appelle, pour `sql`, à l'instant `maintenant`.
    fn be5_horizon(chemin: &str, sql: &str, maintenant: i64) -> (Value, Option<i64>) {
        let conf: HashMap<String, String> = HashMap::new();
        crate::handlers::panneau_avoue::horizon_et_frontiere_selon_l_index(chemin, &conf, sql, None, maintenant - 200 * BE5_JOUR, maintenant)
    }

    /// Un horizon NON MESURÉ, corps ENTIER : aucun réglage nommé, aucun horizon, la notice exacte.
    fn be5_non_mesure(maintenant: i64, notice: &str) -> Value {
        json!({ "searched_from": maintenant - 200 * BE5_JOUR, "calcule_a": maintenant, "reason": BE5_RAISON_NON_MESUREE, "notice": notice })
    }

    /// Un horizon MESURÉ : `horizon_ts` publié, aucun réglage non lu.
    fn be5_est_mesure(cov: &Value, etiquette: &str) {
        assert!(cov["horizon_ts"].is_i64(), "{etiquette} : horizon mesuré : {cov}");
        assert!(cov.get("reglage_non_lu").is_none(), "{etiquette} : aucun réglage non lu : {cov}");
    }

    /// Base prise AVANT l'appel, pool chaud, pour `sql` : contrôle avant (horizon mesuré, connexion du pool revenue au
    /// repos), l'horizon sous la base prise (corps entier, aucune frontière), la connexion du pool revenue au repos,
    /// contrôle après.
    fn be5_sous_base_prise_avant_l_appel(etiquette: &str, sql: &str) {
        let (st, p) = be5_banc(etiquette);
        let maintenant = crate::now();
        be5_est_mesure(&be5_horizon(p.as_str(), sql, maintenant).0, &format!("{etiquette} avant"));
        assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(p.as_str()), 1, "{etiquette} : la connexion du pool revient au repos après un horizon mesuré");
        st.db.lock().execute_batch(BE5_VERROU).expect("fixture : verrou exclusif");
        let (cov, _) = be5_horizon(p.as_str(), sql, maintenant);
        let au_repos = crate::query_exec::connexions_de_lecture_au_repos(p.as_str());
        st.db.lock().execute_batch("ROLLBACK;").expect("fixture : verrou rendu");
        assert_eq!(cov, be5_non_mesure(maintenant, BE5_NOTICE_OCCUPEE), "{etiquette} : la base occupée, ni politiques non lues, ni réglage non lu, ni pool non pris");
        assert_eq!(au_repos, 1, "{etiquette} : la connexion du pool est revenue au repos, point de sauvegarde libéré : {cov}");
        be5_est_mesure(&be5_horizon(p.as_str(), sql, maintenant).0, &format!("{etiquette} après"));
        assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(p.as_str()), 1, "{etiquette} : contrôle après, connexion au repos");
    }

    /// (1) `event` (famille gouvernée par les politiques par index, lues en premier), base prise avant l'appel.
    /// MUTANTS : BE5_SANS_SONDE, BE5_OCC_EN_NON_PRIS, BE5_NOTICE_PERDUE, BE5_SANS_RELEASE_SUR_ECHEC,
    /// BE5_SANS_RELEASE_SUR_SUCCES, BE5_LIBERE_APRES_SONDE.
    #[test]
    fn be5_event_sous_base_prise_dit_occupee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        be5_sous_base_prise_avant_l_appel("be5-event", BE5_SQL_EVENT);
    }

    /// (2) `metric` (aucune politique lue : le premier énoncé d'avant était le réglage `metric_raw_hours`), base prise
    /// avant l'appel. MUTANTS : les mêmes que (1).
    #[test]
    fn be5_metric_sous_base_prise_dit_occupee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        be5_sous_base_prise_avant_l_appel("be5-metric", BE5_SQL_METRIC);
    }

    /// (3) LA LECTURE EST TENUE DE LA SONDE À LA FIN : juste après la sonde, un écrivain neuf (attente nulle) tente le
    /// verrou EXCLUSIF ; il lui est refusé (code BUSY), et l'horizon est mesuré, connexion du pool revenue au repos.
    /// MUTANTS : BE5_RELACHE_PUIS_REPRISE, BE5_LIBERE_APRES_SONDE, BE5_SANS_SONDE, BE5_SANS_RELEASE_SUR_SUCCES.
    #[test]
    fn be5_lecture_tenue_de_la_sonde_a_la_fin() {
        // En écriture : le crochet est un emplacement unique du processus, un témoin voisin qui arme le sien l'écraserait.
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let (_st, p) = be5_banc("be5-tenue");
        let maintenant = crate::now();
        be5_est_mesure(&be5_horizon(p.as_str(), BE5_SQL_EVENT, maintenant).0, "contrôle avant");
        let constats: std::sync::Arc<parking_lot::Mutex<Vec<String>>> = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let pris: std::sync::Arc<parking_lot::Mutex<Option<Connection>>> = std::sync::Arc::new(parking_lot::Mutex::new(None));
        let _desarme = Be5Desarme;
        {
            let chemin = p.as_str().to_string();
            let c = constats.clone();
            let garde = pris.clone();
            armer(
                p.as_str(),
                Etape::ApresLaPriseDeLHorizonDuPanneau,
                Box::new(move || {
                    let w = open_db(&chemin).expect("fixture : écrivain neuf");
                    w.busy_timeout(std::time::Duration::ZERO).expect("fixture : attente nulle");
                    match w.execute_batch("BEGIN EXCLUSIVE") {
                        Ok(()) => {
                            c.lock().push("verrou pris".to_string());
                            *garde.lock() = Some(w);
                        }
                        Err(e) => c.lock().push(format!("verrou refusé : {:?}", e.sqlite_error_code())),
                    }
                }),
            );
        }
        let (cov, _) = be5_horizon(p.as_str(), BE5_SQL_EVENT, maintenant);
        let au_repos = crate::query_exec::connexions_de_lecture_au_repos(p.as_str());
        let verrou_pris = pris.lock().take();
        if let Some(w) = verrou_pris {
            w.execute_batch("ROLLBACK").expect("fixture : verrou rendu");
        }
        assert!(!desarmer(), "le crochet après la sonde a été passé : {cov}");
        assert_eq!(*constats.lock(), vec!["verrou refusé : Some(DatabaseBusy)".to_string()], "la lecture de main est tenue après la sonde");
        be5_est_mesure(&cov, "sous la lecture tenue");
        assert_eq!(au_repos, 1, "la connexion du pool est revenue au repos : {cov}");
    }

    /// (4) LECTURE NON PRISE HORS OCCUPATION, au point d'entrée : un fichier qui n'est pas une base fait échouer la sonde
    /// (NOTADB) ; ni occupée, ni politiques non lues, ni réglage non lu. MUTANTS : BE5_TOUT_EN_OCC, BE5_SANS_SONDE,
    /// BE5_NOTICE_PERDUE.
    #[test]
    fn be5_lecture_non_prise_dite_non_prise() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let base = crate::tmp_possede::TmpDb::neuf("be5-pas-une-base");
        std::fs::write(base.as_str(), vec![0x5Au8; 8192]).expect("fixture : fichier qui n'est pas une base");
        let maintenant = crate::now();
        let (cov, _) = be5_horizon(base.as_str(), BE5_SQL_EVENT, maintenant);
        assert_eq!(cov, be5_non_mesure(maintenant, BE5_NOTICE_NON_PRISE), "lecture non prise : dite non prise");
    }

    /// Remet au pool (chaud, une connexion au repos) sa connexion de lecture, l'autorisateur `refus` posé.
    fn be5_autorisateur_sur_la_connexion_du_pool(chemin: &str, refus: TransactionOperation) {
        let c = crate::query_exec::read_conn_get(chemin).expect("fixture : connexion du pool");
        c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Savepoint { operation, savepoint_name } if operation == refus && savepoint_name == "horizon_du_panneau" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        crate::query_exec::read_conn_put(chemin, c);
        assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(chemin), 1, "instrument : la connexion à l'autorisateur est au pool");
    }

    /// (5) LE `RELEASE` REFUSÉ APRÈS UNE LECTURE RÉUSSIE (la libération qui échoue, comme après un retour en arrière
    /// automatique de SQLite pendant `lire`) : l'horizon lu n'est PAS servi comme mesuré, il est dit non pris ; la
    /// connexion restée en transaction est fermée par le pool (aucune au repos) ; contrôle après mesuré.
    /// MUTANT : V9 (erreur du `RELEASE` avalée, `(Ok(v), Err(_)) => Ok(v)`).
    #[test]
    fn be5_liberation_refusee_dite_non_prise() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (_st, p) = be5_banc("be5-release-refuse");
        let maintenant = crate::now();
        be5_est_mesure(&be5_horizon(p.as_str(), BE5_SQL_EVENT, maintenant).0, "contrôle avant");
        be5_autorisateur_sur_la_connexion_du_pool(p.as_str(), TransactionOperation::Release);
        let (cov, _) = be5_horizon(p.as_str(), BE5_SQL_EVENT, maintenant);
        let au_repos = crate::query_exec::connexions_de_lecture_au_repos(p.as_str());
        assert_eq!(cov, be5_non_mesure(maintenant, BE5_NOTICE_NON_PRISE), "RELEASE refusé : horizon dit non pris, jamais mesuré");
        assert_eq!(au_repos, 0, "la connexion rendue en transaction est fermée par le pool : {cov}");
        be5_est_mesure(&be5_horizon(p.as_str(), BE5_SQL_EVENT, maintenant).0, "contrôle après");
    }

    /// (6) LE `SAVEPOINT` REFUSÉ : dit non pris, et `lire` n'est PAS exécutée (le crochet posé juste après la sonde, au
    /// début de `lire`, reste armé). Avalée, l'erreur du `SAVEPOINT` laisserait la sonde et `lire` s'exécuter hors de
    /// toute lecture tenue ; le `RELEASE` qui ne trouve pas son point rendrait la même notice, d'où le crochet.
    /// MUTANT : BF2_SP_AVALE (le crochet est passé).
    #[test]
    fn be5_prise_refusee_dite_non_prise() {
        // En écriture : le crochet est un emplacement unique du processus (voir (3)).
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let (_st, p) = be5_banc("be5-savepoint-refuse");
        let maintenant = crate::now();
        be5_est_mesure(&be5_horizon(p.as_str(), BE5_SQL_EVENT, maintenant).0, "contrôle avant");
        be5_autorisateur_sur_la_connexion_du_pool(p.as_str(), TransactionOperation::Begin);
        let _desarme = Be5Desarme;
        let lu: std::sync::Arc<parking_lot::Mutex<bool>> = std::sync::Arc::new(parking_lot::Mutex::new(false));
        {
            let lu = lu.clone();
            armer(p.as_str(), Etape::ApresLaPriseDeLHorizonDuPanneau, Box::new(move || *lu.lock() = true));
        }
        let (cov, _) = be5_horizon(p.as_str(), BE5_SQL_EVENT, maintenant);
        let encore_arme = desarmer();
        assert_eq!(cov, be5_non_mesure(maintenant, BE5_NOTICE_NON_PRISE), "SAVEPOINT refusé : horizon dit non pris");
        assert!(encore_arme && !*lu.lock(), "SAVEPOINT refusé : `lire` n'est pas exécutée (crochet resté armé) : {cov}");
        drop(crate::query_exec::read_conn_get(p.as_str()).expect("fixture : connexion à l'autorisateur retirée"));
        be5_est_mesure(&be5_horizon(p.as_str(), BE5_SQL_EVENT, maintenant).0, "contrôle après");
    }

    /// L'aveu du pool non pris, phrase écrite ici (jamais lue dans la production).
    const BE5_NOTICE_POOL_NON_PRIS: &str = "le pool de lecture n'a pas pu être pris ; l'horizon n'a PAS été mesuré. Cette réponse ne dit donc RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";

    /// (7) POOL NON PRIS, au point d'entrée : le chemin n'existe pas, l'ouverture en lecture seule de la connexion du pool
    /// échoue (CANTOPEN) ; corps entier, sous l'aveu du pool non pris, jamais celui de la lecture non prise ni de la base
    /// occupée. Le chemin n'est pas créé par l'appel. MUTANT : BF2_POOL_EN_NP.
    #[test]
    fn be5_pool_non_pris_dit_pool_non_pris() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let base = crate::tmp_possede::TmpDb::neuf("be5-pool-non-pris");
        assert!(!std::path::Path::new(base.as_str()).exists(), "instrument : le chemin n'existe pas");
        let maintenant = crate::now();
        let (cov, frontiere) = be5_horizon(base.as_str(), BE5_SQL_EVENT, maintenant);
        assert_eq!(cov, be5_non_mesure(maintenant, BE5_NOTICE_POOL_NON_PRIS), "chemin absent : pool non pris");
        assert_eq!(frontiere, None, "aucune frontière sans connexion : {cov}");
        assert!(!std::path::Path::new(base.as_str()).exists(), "l'ouverture en lecture seule n'a pas créé la base");
        assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(base.as_str()), 0, "aucune connexion de lecture ouverte");
    }

    /// (8) LA SONDE OCCUPÉE ET LE `RELEASE` REFUSÉ : la classe servie est celle de la sonde. Base prise avant l'appel (pool
    /// chaud), autorisateur qui refuse le `RELEASE` du point de l'horizon : la notice est celle de la base occupée, jamais
    /// celle de la lecture non prise. La connexion restée en transaction est fermée par le pool. Contrôle après mesuré.
    /// MUTANT : BF2_MATCH_REL_D_ABORD.
    #[test]
    fn be5_sonde_occupee_et_release_refuse_dit_occupee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, p) = be5_banc("be5-occupee-et-release");
        let maintenant = crate::now();
        be5_est_mesure(&be5_horizon(p.as_str(), BE5_SQL_EVENT, maintenant).0, "contrôle avant");
        be5_autorisateur_sur_la_connexion_du_pool(p.as_str(), TransactionOperation::Release);
        st.db.lock().execute_batch(BE5_VERROU).expect("fixture : verrou exclusif");
        let (cov, _) = be5_horizon(p.as_str(), BE5_SQL_EVENT, maintenant);
        let au_repos = crate::query_exec::connexions_de_lecture_au_repos(p.as_str());
        st.db.lock().execute_batch("ROLLBACK;").expect("fixture : verrou rendu");
        assert_eq!(cov, be5_non_mesure(maintenant, BE5_NOTICE_OCCUPEE), "sonde occupée et RELEASE refusé : la base occupée l'emporte");
        assert_eq!(au_repos, 0, "la connexion restée en transaction (RELEASE refusé) est fermée par le pool : {cov}");
        be5_est_mesure(&be5_horizon(p.as_str(), BE5_SQL_EVENT, maintenant).0, "contrôle après");
    }
}

// (9), (10) — LES DEUX SITES VOISINS DU TIER FROID (même patron) : l'échec du `RELEASE` est rendu, jamais avalé.
#[cfg(all(test, feature = "cold_tier"))]
mod be5_release_refuse_sous_la_voie_froide {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const BE5F_NOTICE_NON_PRISE: &str = "la lecture de l'horizon de conservation n'a pas pu être prise (refus de la base) ; l'horizon n'a PAS été mesuré. Cette réponse ne dit donc RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";
    const BE5F_JOUR: i64 = 86_400;

    /// La couverture de la voie froide lue (`horizon_de_la_voie_froide_lue`, l'appelant réel), pour `sql`.
    fn be5f_couverture(chemin: &str, sql: &str, maintenant: i64) -> Value {
        let conf: HashMap<String, String> = HashMap::new();
        let frontiere = (maintenant.div_euclid(BE5F_JOUR) - 2) * BE5F_JOUR;
        crate::panneau_avoue::horizon_de_la_voie_froide_lue(chemin, &conf, sql, maintenant - 200 * BE5F_JOUR, maintenant, frontiere, None)
    }

    /// Remet au pool (chaud) sa connexion, un autorisateur qui refuse le `RELEASE` du point `point` posé.
    fn be5f_refuser_le_release(chemin: &str, point: &'static str) {
        let c = crate::query_exec::read_conn_get(chemin).expect("fixture : connexion du pool");
        c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Savepoint { operation: TransactionOperation::Release, savepoint_name } if savepoint_name == point => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        crate::query_exec::read_conn_put(chemin, c);
        assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(chemin), 1, "instrument : la connexion à l'autorisateur est au pool");
    }

    /// Contrôle avant (mesuré), `RELEASE` du point refusé : corps entier « non prise », connexion fermée par le pool,
    /// contrôle après mesuré.
    fn be5f_release_refuse(etiquette: &str, sql: &str, point: &'static str) {
        let (_st, p) = sp_state(etiquette);
        let maintenant = crate::now();
        let avant = be5f_couverture(p.as_str(), sql, maintenant);
        assert!(avant["horizon_ts"].is_i64(), "{etiquette} : contrôle avant, horizon mesuré : {avant}");
        be5f_refuser_le_release(p.as_str(), point);
        let cov = be5f_couverture(p.as_str(), sql, maintenant);
        let au_repos = crate::query_exec::connexions_de_lecture_au_repos(p.as_str());
        assert_eq!(
            cov,
            json!({ "searched_from": maintenant - 200 * BE5F_JOUR, "calcule_a": maintenant, "reason": "horizon_non_mesure", "notice": BE5F_NOTICE_NON_PRISE }),
            "{etiquette} : RELEASE refusé, l'horizon lu n'est pas servi comme mesuré"
        );
        assert_eq!(au_repos, 0, "{etiquette} : la connexion restée en transaction est fermée par le pool : {cov}");
        let apres = be5f_couverture(p.as_str(), sql, maintenant);
        assert!(apres["horizon_ts"].is_i64(), "{etiquette} : contrôle après, horizon mesuré : {apres}");
    }

    /// (9) `retention_de_la_famille_lue` (famille chaude `metric`). MUTANT : BF2_FAMILLE_RELEASE_AVALE.
    #[test]
    fn be5f_famille_chaude_release_refuse_dite_non_prise() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        be5f_release_refuse("be5f-famille", "SELECT ts FROM metric", "retention_de_la_famille");
    }

    /// (10) `HorizonDeLecture::lire` (`event`, par `plancher_de_l_horizon_froid`). MUTANT : BF2_HORIZON_RELEASE_AVALE.
    #[test]
    fn be5f_horizon_froid_release_refuse_dit_non_prise() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        be5f_release_refuse("be5f-horizon", "SELECT ts FROM event", "horizon_de_lecture");
    }
}
