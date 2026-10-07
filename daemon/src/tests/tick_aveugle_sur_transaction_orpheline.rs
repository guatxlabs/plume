// =====================================================================================
// `P10.27-z` — UNE TRANSACTION ORPHELINE SUR L'ÉCRIVAIN REND LE TICK DE DÉTECTION AVEUGLE, DÉCLARÉ ET COMPTÉ, SANS
// ROLLBACK. Mesuré le 2026-10-07 : `run_due_rules` voyait l'orpheline (sonde `P10.27-g`), la comptait, puis évaluait
// et ÉCRIVAIT ses alertes et son `last_run` par `conn.execute` DANS cette transaction — visibles de l'écrivain seul,
// invisibles de toute autre connexion, perdues au redémarrage. Décision d'Hugo (2026-09-29) : déclarer le tick
// aveugle (bilan nommé + cause au compteur existant des ticks aveugles), ne rien annuler.
// =====================================================================================
mod tick_aveugle_sur_transaction_orpheline {
    use super::*;
    use crate::bilan_de_tick::{BOUCLE_REGLES, CAUSE_TRANSACTION_ORPHELINE};
    use crate::handlers::detection::run_due_rules;
    use crate::mesure_environnement::Mesure;

    fn tato_base(tag: &str) -> (crate::tmp_possede::TmpPossede, String, Arc<Mutex<Connection>>) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn));
            conn.execute("DELETE FROM rule", []).unwrap();
            conn.execute("DELETE FROM alert", []).unwrap();
            conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) \
                 VALUES('tato',1,'search source=tato | stats count',1,'>',0,2,0,3600)",
                [],
            )
            .unwrap();
            // Une règle « avancée » (fenêtre de suppression) : évaluée par `run_advanced_rules`, une AUTRE famille du
            // même tick — c'est elle qui dit si la sonde rend le TICK aveugle ou seulement la famille des règles.
            conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,suppress_window_s) \
                 VALUES('tato-avancee',1,'search source=tato | stats count',1,'>',0,2,0,3600,600)",
                [],
            )
            .unwrap();
            let maintenant = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            conn.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'tato','auth',1,'échec')", params![maintenant])
                .unwrap();
        }
        (tmp, p, db)
    }

    /// (alertes, `last_run` de la règle 'tato' posé) vus par une connexion donnée.
    fn tato_etat(c: &Connection) -> (i64, bool) {
        let alertes: i64 = c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
        let last_run: Option<i64> = c.query_row("SELECT last_run FROM rule WHERE name='tato'", [], |r| r.get(0)).unwrap();
        (alertes, last_run.is_some())
    }

    /// (alertes, règles dont `last_run` est posé), toutes familles confondues.
    fn tato_etat_global(c: &Connection) -> (i64, i64) {
        let alertes: i64 = c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
        let evaluees: i64 = c.query_row("SELECT COUNT(*) FROM rule WHERE last_run IS NOT NULL", [], |r| r.get(0)).unwrap();
        (alertes, evaluees)
    }

    /// La ligne que la FIXTURE a écrite dans l'orpheline : présente tant que l'orpheline n'a été ni annulée ni remplacée.
    fn tato_marque(c: &Connection) -> i64 {
        c.query_row("SELECT COUNT(*) FROM meta WHERE key='tato'", [], |r| r.get(0)).unwrap()
    }

    fn tato_compte() -> u64 {
        crate::metrics::tick_aveugle_de(BOUCLE_REGLES).map(|(n, _)| n).unwrap_or(0)
    }

    fn tato_orpheline(db: &Arc<Mutex<Connection>>) {
        db.lock().execute_batch("BEGIN IMMEDIATE; INSERT INTO meta(key,value) VALUES('tato','1');").expect("fixture : transaction laissée ouverte");
    }

    /// CE QU'IL TIENT : une transaction laissée ouverte sur l'écrivain, `run_due_rules` rend un bilan ILLISIBLE qui
    /// nomme la famille et la transaction orpheline ; il n'écrit RIEN — ni alerte ni `last_run`, ni vus par l'écrivain
    /// (qui verrait ses propres écritures dans l'orpheline) ni à froid ; il ne TOUCHE PAS à l'orpheline : la ligne que
    /// la fixture y a écrite est encore là, vue par l'écrivain seul (un `ROLLBACK` suivi d'un `BEGIN` neuf la ferait
    /// disparaître) ; il compte un tick aveugle sous la boucle `regles` avec la cause nommée.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer la déclaration de `run_due_rules` ; ne plus porter la cause au
    /// compteur ; annuler l'orpheline et en rouvrir une neuve dans la branche de la sonde.
    #[test]
    fn tato_une_orpheline_rend_le_tick_aveugle_sans_ecrire_ni_annuler() {
        let (_tmp, p, db) = tato_base("tato-orpheline");
        tato_orpheline(&db);
        let avant = tato_compte();
        let bilan = run_due_rules(&db, &p);
        let apres = crate::metrics::tick_aveugle_de(BOUCLE_REGLES);
        let ecrivain = { let c = db.lock(); (tato_etat(&c), c.is_autocommit(), tato_marque(&c)) };
        let a_froid = { let c = open_db(&p).unwrap(); (tato_etat(&c), tato_marque(&c)) };
        db.lock().execute_batch("ROLLBACK").expect("fixture : fermeture");

        match &bilan {
            Mesure::Illisible { detail, .. } => assert!(
                detail.contains("règles") && detail.contains("transaction orpheline") && detail.contains(CAUSE_TRANSACTION_ORPHELINE),
                "le bilan nomme la famille et la transaction orpheline : {detail}"
            ),
            Mesure::Lue(n) => panic!("le tick se dit lu ({n} abandon(s)) alors qu'il n'a rien pu écrire de visible"),
        }
        assert_eq!(ecrivain.0, (0, false), "aucune alerte ni last_run écrits dans la transaction orpheline");
        assert_eq!(a_froid.0, (0, false), "et rien à froid");
        assert!(!ecrivain.1, "la transaction orpheline est toujours ouverte");
        assert_eq!(ecrivain.2, 1, "C'EST LA MÊME orpheline : la ligne de la fixture y est encore (ni annulée ni remplacée)");
        assert_eq!(a_froid.1, 0, "et cette ligne reste invisible à froid : la transaction n'a pas été validée non plus");
        let (n, cause) = apres.expect("le tick aveugle est COMPTÉ sous la boucle des règles");
        assert!(n > avant, "le compteur des ticks aveugles monte : {avant} -> {n}");
        assert_eq!(cause, CAUSE_TRANSACTION_ORPHELINE, "sous la cause nommée");
    }

    /// CE QU'IL TIENT : c'est le TICK, toutes familles, qui est aveugle — pas la seule famille des règles. Le corps du
    /// tick d'un tenant, l'écrivain portant une orpheline, n'écrit rien par AUCUNE famille (la règle avancée, évaluée par
    /// `run_advanced_rules`, n'a ni `last_run` ni alerte), rend un bilan qui le dit, et laisse l'orpheline intacte.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer la sonde en tête de `tick_de_detection_d_un_tenant` — `run_due_rules`
    /// se déclare encore aveugle, mais `run_advanced_rules` écrit son `last_run` dans l'orpheline.
    #[test]
    fn tato_une_orpheline_rend_tout_le_tick_aveugle_pas_seulement_les_regles() {
        let (_tmp, p, db) = tato_base("tato-tick-entier");
        tato_orpheline(&db);
        let bilan = crate::server::boucles_de_fond::tick_de_detection_d_un_tenant(&db, &p).bilan_de_tick();
        let ecrivain = { let c = db.lock(); (tato_etat_global(&c), tato_marque(&c)) };
        db.lock().execute_batch("ROLLBACK").expect("fixture : fermeture");

        match &bilan {
            Mesure::Illisible { detail, .. } => assert!(
                detail.contains("toutes les familles") && detail.contains(CAUSE_TRANSACTION_ORPHELINE),
                "le bilan dit que tout le tick est aveugle : {detail}"
            ),
            Mesure::Lue(n) => panic!("le tick se dit lu ({n} abandon(s))"),
        }
        assert_eq!(ecrivain.0, (0, 0), "aucune famille n'écrit dans l'orpheline (alertes, règles évaluées)");
        assert_eq!(ecrivain.1, 1, "l'orpheline est intacte");
    }

    /// CE QU'IL TIENT : une orpheline laissée PENDANT l'évaluation (entre la lecture des règles dues et leurs écritures,
    /// hors du verrou) est vue par la sonde reprise avant d'écrire : bilan aveugle, rien d'écrit, orpheline intacte.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer la sonde reprise de la phase 3 de `run_due_rules`.
    #[test]
    fn tato_une_orpheline_laissee_pendant_l_evaluation_est_vue_avant_d_ecrire() {
        let (_tmp, p, db) = tato_base("tato-fenetre");
        crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(tato_orpheline));
        let bilan = run_due_rules(&db, &p);
        crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(crate::handlers::detection::sans_crochet));
        let ecrivain = { let c = db.lock(); (tato_etat(&c), c.is_autocommit(), tato_marque(&c)) };
        let _ = db.lock().execute_batch("ROLLBACK");

        assert!(matches!(bilan, Mesure::Illisible { .. }), "le tick se déclare aveugle : {bilan:?}");
        assert_eq!(ecrivain.0, (0, false), "ni alerte ni last_run écrits dans l'orpheline ouverte pendant l'évaluation");
        assert_eq!((ecrivain.1, ecrivain.2), (false, 1), "l'orpheline est intacte");
    }

    /// CONTRÔLE POSITIF (les témoins ci-dessus ne sont pas vacants) : la même base sans orpheline, le tick est LU,
    /// l'alerte et `last_run` sont écrits et visibles à froid — par la famille des règles comme par la règle avancée ;
    /// puis, l'orpheline fermée par son geste, le tick suivant reprend — les règles n'ont pas été perdues.
    #[test]
    fn tato_sans_orpheline_le_tick_evalue_et_ecrit() {
        let (_tmp, p, db) = tato_base("tato-sain");
        db.lock().execute_batch("BEGIN IMMEDIATE;").expect("fixture : transaction laissée ouverte");
        let _ = crate::server::boucles_de_fond::tick_de_detection_d_un_tenant(&db, &p);
        db.lock().execute_batch("ROLLBACK").expect("fixture : le geste ferme sa transaction");
        assert_eq!(
            crate::server::boucles_de_fond::tick_de_detection_d_un_tenant(&db, &p).bilan_de_tick(),
            Mesure::Lue(0),
            "écrivain sain : tick lu, rien d'abandonné"
        );
        let (alertes, evaluees) = tato_etat_global(&open_db(&p).unwrap());
        assert!(alertes >= 1, "au moins une alerte validée, visible à froid : {alertes}");
        assert_eq!(evaluees, 2, "les deux règles (famille des règles ET règle avancée) ont leur last_run validé");
    }
}
