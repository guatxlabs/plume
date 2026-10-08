// =====================================================================================
// `P10.20-b` (rang trois : `rollup_risk`) — UNE PANNE D'ÉCRITURE NE RÉSOUT JAMAIS UNE ALERTE DE RISQUE.
//
// CE QUI ÉTAIT FAUX, MESURÉ SUR aa78ddd (`handlers/rba.rs`, `rollup_risk`) :
//   * la reconstruction du rollup avalait ses deux écritures (`let _ = DELETE`, `let _ = INSERT … SELECT`) : un
//     `DELETE` passé suivi d'un `INSERT` refusé laissait `risk_rollup` VIDE, puis `risk_incidents_eval` RÉSOLVAIT
//     toutes les alertes de risque ouvertes (`status='resolved', dedup=NULL`) sous un bilan `Lue(0)` vert ;
//   * les trois sondes `EXISTS` retombaient à `false` sur un `Err` (`unwrap_or(false)`) : trois sondes ratées
//     rendaient `Lue(0)` commenté « VRAI zéro », et la seule sonde `risk_event` ratée menait à la reconstruction
//     ci-dessus (l'`INSERT … SELECT FROM risk_event` échoue à son tour) ;
//   * la garde single-row classait ce site au rang trois « fail-safe » : faux pour le `DELETE`/`INSERT`.
//
// LA FORME DU CORRECTIF : sondes lues en `Result`, un `Err` rend `tick_aveugle` nommé ; `DELETE`+`INSERT` dans un
// SAVEPOINT (transaction propre sur un écrivain libre ; sur un écrivain qui porte une transaction étrangère, seules
// ses écritures sont annulées — `ROLLBACK TO` + `RELEASE`, jamais `ROLLBACK`, décision `P10.27-z`) ; un refus rend
// le tick aveugle, garde le rollup d'avant et ne joue PAS l'évaluation des incidents.
//
// LES VOIES DE L'ÉCHEC : un déclencheur `RAISE(ABORT)` sur `INSERT` puis sur `DELETE` de `risk_rollup` (le second
// aussi sans conflit de clé, pour juger le `?` du `DELETE` seul) ; chacune des TROIS tables sondées renommée (la sonde
// échoue « no such table ») ; le `RELEASE` refusé par une clé étrangère DIFFÉRÉE violée depuis un déclencheur ; le
// `SAVEPOINT` lui-même refusé par un autorisateur SQLite (`AuthAction::Savepoint`, technique des tests de migrate.rs) ;
// l'évaluation des incidents NON jouée sur refus (l'alerte ouverte n'est pas rafraîchie).
//
// CE QUE CE LOT NE TIENT PAS :
//   * l'aveu publié passe par `tick_aveugle`, dont le texte dit « liste des éléments dus illisible » même quand c'est
//     une ÉCRITURE qui a été refusée : la cause nommée (« reconstruction du rollup … ») est juste, la fin du texte non ;
//   * les écritures de `risk_incidents_eval` (`INSERT OR IGNORE`/`UPDATE` d'alerte, résolution) restent avalées :
//     un refus là ne résout rien à tort (il laisse une alerte ouverte ou non levée), mais n'est pas compté ;
//   * le tick n'appelle pas `signaler_une_transaction_ouverte_hors_de_tout_geste` avant `rollup_risk` : sur un
//     écrivain qui porte une transaction orpheline, le savepoint réussi écrit DANS cette transaction (comme avant) ;
//   * la console ne lit pas la cause nommée du bilan au-delà de ce que la surface détection publie déjà.
// =====================================================================================
mod rollup_de_risque_lu_et_ecrit_compte {
    use super::*;

    const ENTITE: &str = "198.51.100.7";
    const DEDUP: &str = "risk-ip-198.51.100.7";

    fn rre_regler() -> parking_lot::RwLockWriteGuard<'static, ()> {
        let g = VERROU_ENV_PROCESSUS.write();
        std::env::set_var("PLUME_RISK_SCORE_THRESHOLD", "100");
        std::env::set_var("PLUME_RISK_TACTICS_THRESHOLD", "0");
        std::env::set_var("PLUME_RISK_VELOCITY", "0");
        g
    }

    fn rre_oublier() {
        std::env::remove_var("PLUME_RISK_SCORE_THRESHOLD");
        std::env::remove_var("PLUME_RISK_TACTICS_THRESHOLD");
        std::env::remove_var("PLUME_RISK_VELOCITY");
    }

    /// Une base où l'entité franchit le seuil : rollup nominal joué, UNE alerte de risque ouverte.
    fn rre_base_avec_alerte_ouverte() -> Connection {
        let conn = test_db();
        let n = now();
        for (dt, mitre) in [(10, "T1110"), (8, "T1110"), (5, "T1046")] {
            assert!(risk_event_insert(&conn, n - dt, "ip", ENTITE, 40, "rule", Some(1), "test", mitre, 2, "prod", None));
        }
        assert!(matches!(rollup_risk(&conn), crate::mesure_environnement::Mesure::Lue(0)), "rollup nominal : Lue(0)");
        assert_eq!(rre_ouvertes(&conn), 1, "départ : une alerte de risque ouverte");
        assert_eq!(rre_rollup(&conn), Some(120), "départ : rollup écrit (40 x 3)");
        conn
    }

    fn rre_ouvertes(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM alert WHERE dedup=?1 AND status IN ('new','ack')", [DEDUP], |r| r.get(0)).unwrap()
    }

    fn rre_rollup(conn: &Connection) -> Option<i64> {
        conn.query_row("SELECT score FROM risk_rollup WHERE entity=?1", [ENTITE], |r| r.get(0)).ok()
    }

    fn rre_illisible(b: &crate::bilan_de_tick::BilanDeTick) -> String {
        match b {
            crate::mesure_environnement::Mesure::Illisible { detail, .. } => detail.clone(),
            autre => panic!("bilan attendu Illisible, rendu {autre:?}"),
        }
    }

    /// `INSERT` du rollup refusé : l'alerte reste OUVERTE, le rollup d'avant est intact, le bilan est aveugle.
    /// Forme d'avant : `DELETE` passé, rollup vide, alerte résolue, `Lue(0)`.
    #[test]
    fn rre_insert_refuse_ne_resout_aucune_alerte() {
        let _g = rre_regler();
        let conn = rre_base_avec_alerte_ouverte();
        conn.execute_batch(
            "CREATE TRIGGER rre_refuse_insert BEFORE INSERT ON risk_rollup BEGIN SELECT RAISE(ABORT, 'rollup non inscriptible'); END;",
        ).unwrap();
        let bilan = rollup_risk(&conn);
        // L'intégrité d'abord (c'est ce que la forme d'avant cassait), le bilan ensuite.
        assert_eq!(rre_ouvertes(&conn), 1, "une panne d'écriture ne résout PAS l'alerte de risque ouverte");
        assert_eq!(rre_rollup(&conn), Some(120), "le rollup d'avant est CONSERVÉ (DELETE annulé avec le savepoint)");
        let detail = rre_illisible(&bilan);
        assert!(detail.contains("reconstruction du rollup refusée"), "cause nommée : {detail}");
        assert!(conn.is_autocommit(), "aucune transaction laissée ouverte par le savepoint");
        rre_oublier();
    }

    /// `DELETE` du rollup refusé : bilan aveugle (la forme d'avant rendait `Lue(0)` sur un rollup périmé).
    #[test]
    fn rre_delete_refuse_rend_un_tick_aveugle() {
        let _g = rre_regler();
        let conn = rre_base_avec_alerte_ouverte();
        conn.execute_batch(
            "CREATE TRIGGER rre_refuse_delete BEFORE DELETE ON risk_rollup BEGIN SELECT RAISE(ABORT, 'rollup non effaçable'); END;",
        ).unwrap();
        let bilan = rollup_risk(&conn);
        rre_illisible(&bilan);
        assert_eq!(rre_ouvertes(&conn), 1, "l'alerte reste ouverte");
        assert_eq!(rre_rollup(&conn), Some(120), "rollup d'avant intact");
        assert!(conn.is_autocommit());
        rre_oublier();
    }

    /// Sonde `EXISTS` ratée sur une base sans donnée de risque : `Illisible`, jamais le « VRAI zéro » `Lue(0)`.
    #[test]
    fn rre_sonde_ratee_n_est_pas_un_vrai_zero() {
        let _g = rre_regler();
        let conn = test_db();
        assert!(matches!(rollup_risk(&conn), crate::mesure_environnement::Mesure::Lue(0)), "mode 0 lisible : vrai zéro");
        conn.execute_batch("ALTER TABLE risk_event RENAME TO risk_event_ecartee;").unwrap();
        let detail = rre_illisible(&rollup_risk(&conn));
        assert!(detail.contains("sonde risk_event"), "la sonde ratée est nommée : {detail}");
        rre_oublier();
    }

    /// Sonde `risk_event` ratée avec une alerte ouverte : l'alerte n'est pas résolue (forme d'avant : reconstruction,
    /// `INSERT … FROM risk_event` refusé, rollup vidé, alerte résolue).
    #[test]
    fn rre_sonde_ratee_ne_resout_aucune_alerte() {
        let _g = rre_regler();
        let conn = rre_base_avec_alerte_ouverte();
        conn.execute_batch("ALTER TABLE risk_event RENAME TO risk_event_ecartee;").unwrap();
        let bilan = rollup_risk(&conn);
        assert_eq!(rre_ouvertes(&conn), 1, "l'alerte reste ouverte");
        assert_eq!(rre_rollup(&conn), Some(120), "rollup d'avant intact");
        rre_illisible(&bilan);
        rre_oublier();
    }

    /// Transaction ÉTRANGÈRE ouverte sur l'écrivain : un refus n'annule QUE les écritures du rollup — l'écriture
    /// étrangère pendante survit et la transaction reste ouverte (décision `P10.27-z` : aucun `ROLLBACK`).
    #[test]
    fn rre_refus_sous_transaction_etrangere_ne_l_annule_pas() {
        let _g = rre_regler();
        let conn = rre_base_avec_alerte_ouverte();
        conn.execute_batch(
            "CREATE TRIGGER rre_refuse_insert BEFORE INSERT ON risk_rollup BEGIN SELECT RAISE(ABORT, 'rollup non inscriptible'); END;",
        ).unwrap();
        conn.execute_batch("BEGIN; INSERT INTO meta(key,value) VALUES('rre_etrangere','pendante');").unwrap();
        let bilan = rollup_risk(&conn);
        assert_eq!(rre_ouvertes(&conn), 1, "l'alerte reste ouverte");
        assert_eq!(rre_rollup(&conn), Some(120), "rollup d'avant intact");
        assert!(!conn.is_autocommit(), "la transaction étrangère est toujours ouverte (pas de ROLLBACK)");
        let v: String = conn.query_row("SELECT value FROM meta WHERE key='rre_etrangere'", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "pendante", "l'écriture étrangère pendante n'est pas annulée");
        rre_illisible(&bilan);
        conn.execute_batch("ROLLBACK").unwrap();
        rre_oublier();
    }

    /// Inverse : chemin nominal inchangé, le savepoint est libéré (aucune transaction laissée), retombée sous le seuil
    /// (événements expirés) résout l'alerte comme avant.
    #[test]
    fn rre_nominal_inchange_et_resolution_legitime() {
        let _g = rre_regler();
        let conn = rre_base_avec_alerte_ouverte();
        assert!(conn.is_autocommit(), "savepoint libéré après succès");
        conn.execute("DELETE FROM risk_event", []).unwrap();
        assert!(matches!(rollup_risk(&conn), crate::mesure_environnement::Mesure::Lue(0)));
        assert_eq!(rre_rollup(&conn), None, "rollup reconstruit à vide (plus aucune contribution)");
        assert_eq!(rre_ouvertes(&conn), 0, "retombée réelle sous le seuil : alerte résolue");
        rre_oublier();
    }

    /// Sonde `risk_rollup` ratée sur une base sans donnée de risque : `Illisible` nommé, jamais `Lue(0)`.
    #[test]
    fn rre_sonde_rollup_ratee_n_est_pas_un_vrai_zero() {
        let _g = rre_regler();
        let conn = test_db();
        conn.execute_batch("ALTER TABLE risk_rollup RENAME TO risk_rollup_ecartee;").unwrap();
        let detail = rre_illisible(&rollup_risk(&conn));
        assert!(detail.contains("sonde risk_rollup"), "la sonde ratée est nommée : {detail}");
        rre_oublier();
    }

    /// Sonde des alertes ouvertes ratée sur une base sans donnée de risque : `Illisible` nommé, jamais `Lue(0)`.
    #[test]
    fn rre_sonde_alertes_ratee_n_est_pas_un_vrai_zero() {
        let _g = rre_regler();
        let conn = test_db();
        conn.execute_batch("ALTER TABLE alert RENAME TO alert_ecartee;").unwrap();
        let detail = rre_illisible(&rollup_risk(&conn));
        assert!(detail.contains("sonde des alertes ouvertes"), "la sonde ratée est nommée : {detail}");
        rre_oublier();
    }

    /// `DELETE` refusé alors que l'`INSERT` ne heurte AUCUNE clé (seule une entité NEUVE contribue) : rien n'est
    /// écrit, l'entité périmée n'est pas complétée d'une neuve, bilan aveugle. Un `DELETE` avalé insérerait l'entité
    /// neuve À CÔTÉ de la périmée et servirait ce rollup sous `Lue(0)`.
    #[test]
    fn rre_delete_refuse_sans_conflit_de_cle_n_ecrit_rien() {
        let _g = rre_regler();
        let conn = rre_base_avec_alerte_ouverte();
        conn.execute("DELETE FROM risk_event", []).unwrap();
        assert!(risk_event_insert(&conn, now() - 3, "ip", "203.0.113.9", 10, "rule", Some(1), "test", "T1046", 2, "prod", None));
        conn.execute_batch(
            "CREATE TRIGGER rre_refuse_delete BEFORE DELETE ON risk_rollup BEGIN SELECT RAISE(ABORT, 'rollup non effaçable'); END;",
        ).unwrap();
        let bilan = rollup_risk(&conn);
        let neuve: Option<i64> =
            conn.query_row("SELECT score FROM risk_rollup WHERE entity='203.0.113.9'", [], |r| r.get(0)).ok();
        assert_eq!(neuve, None, "DELETE refusé : aucune entité neuve écrite à côté du rollup périmé");
        assert_eq!(rre_rollup(&conn), Some(120), "rollup d'avant intact");
        assert_eq!(rre_ouvertes(&conn), 1, "l'alerte reste ouverte");
        let detail = rre_illisible(&bilan);
        assert!(detail.contains("reconstruction du rollup refusée"), "cause nommée : {detail}");
        assert!(conn.is_autocommit());
        rre_oublier();
    }

    /// `RELEASE` (le commit du savepoint) refusé par une clé étrangère DIFFÉRÉE violée : bilan aveugle, aucune
    /// transaction laissée ouverte sur l'écrivain, alerte ouverte, rollup d'avant intact. Un `RELEASE` avalé
    /// laisserait une transaction ORPHELINE où partiraient les écritures d'évaluation, sous `Lue(0)`.
    #[test]
    fn rre_release_refuse_ne_laisse_aucune_transaction() {
        let _g = rre_regler();
        let conn = rre_base_avec_alerte_ouverte();
        conn.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE rre_parent(id INTEGER PRIMARY KEY);
             CREATE TABLE rre_enfant(p INTEGER REFERENCES rre_parent(id) DEFERRABLE INITIALLY DEFERRED);
             CREATE TRIGGER rre_fk_differee AFTER INSERT ON risk_rollup BEGIN INSERT INTO rre_enfant(p) VALUES(999); END;",
        ).unwrap();
        let bilan = rollup_risk(&conn);
        let ouverte = !conn.is_autocommit();
        if ouverte {
            conn.execute_batch("ROLLBACK").unwrap();
        }
        assert!(!ouverte, "aucune transaction laissée ouverte par un commit refusé (bilan : {bilan:?})");
        let detail = rre_illisible(&bilan);
        assert!(detail.contains("reconstruction du rollup refusée"), "cause nommée : {detail}");
        assert_eq!(rre_ouvertes(&conn), 1, "l'alerte reste ouverte");
        assert_eq!(rre_rollup(&conn), Some(120), "rollup d'avant intact");
        let enfants: i64 = conn.query_row("SELECT COUNT(*) FROM rre_enfant", [], |r| r.get(0)).unwrap();
        assert_eq!(enfants, 0, "l'écriture du savepoint est annulée");
        rre_oublier();
    }

    /// `SAVEPOINT` refusé (autorisateur SQLite) avec un `INSERT` refusé : rien n'est écrit HORS savepoint. Un échec de
    /// `SAVEPOINT` ignoré validerait le `DELETE` en autocommit : rollup VIDE servi sous « rollup d'avant conservé ».
    #[test]
    fn rre_savepoint_refuse_rollup_conserve() {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
        let _g = rre_regler();
        let conn = rre_base_avec_alerte_ouverte();
        conn.execute_batch(
            "CREATE TRIGGER rre_refuse_insert BEFORE INSERT ON risk_rollup BEGIN SELECT RAISE(ABORT, 'rollup non inscriptible'); END;",
        ).unwrap();
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Savepoint { operation: TransactionOperation::Begin, savepoint_name }
                if savepoint_name == "rollup_risk_reconstruction" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let bilan = rollup_risk(&conn);
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(rre_rollup(&conn), Some(120), "SAVEPOINT refusé : aucun DELETE validé en autocommit");
        assert_eq!(rre_ouvertes(&conn), 1, "l'alerte reste ouverte");
        assert!(conn.is_autocommit(), "aucune transaction laissée ouverte");
        let detail = rre_illisible(&bilan);
        assert!(detail.contains("reconstruction du rollup non ouverte"), "cause nommée : {detail}");
        rre_oublier();
    }

    /// `INSERT` refusé : `risk_incidents_eval` n'est PAS joué — l'alerte ouverte n'est pas rafraîchie depuis un rollup
    /// qu'on n'a pas su réécrire (une évaluation jouée puis son résultat jeté réécrirait `ts`/`title`).
    #[test]
    fn rre_evaluation_non_jouee_sur_refus() {
        let _g = rre_regler();
        let conn = rre_base_avec_alerte_ouverte();
        conn.execute("UPDATE alert SET ts=1000, title='rre_marque' WHERE dedup=?1", [DEDUP]).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER rre_refuse_insert BEFORE INSERT ON risk_rollup BEGIN SELECT RAISE(ABORT, 'rollup non inscriptible'); END;",
        ).unwrap();
        let detail = rre_illisible(&rollup_risk(&conn));
        let (ts, title): (i64, String) =
            conn.query_row("SELECT ts, title FROM alert WHERE dedup=?1", [DEDUP], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((ts, title.as_str()), (1000, "rre_marque"), "évaluation non jouée sur refus d'écriture ({detail})");
        rre_oublier();
    }
}
