// =====================================================================================
// `P10.31-s` — UNE ENTITÉ NON JUGÉE NE VOIT JAMAIS SON ALERTE DE RISQUE RÉSOLUE, ET UNE ÉCRITURE REFUSÉE N'EST
// JAMAIS UN TICK VERT.
//
// CE QUI ÉTAIT FAUX, MESURÉ SUR b52f097 (`handlers/rba.rs`, `risk_incidents_eval`) :
//   * une ligne de `risk_rollup` indécodable (un `risk_score` réel somme un `score` réel, que `get::<i64>` refuse)
//     n'incrémentait que `abandonnees` ; son entité n'entrait pas dans `crossing`, et la boucle de résolution mettait
//     son alerte ouverte à `status='resolved', dedup=NULL` sous un bilan `Lue(1)` ;
//   * les trois écritures de l'évaluation (`INSERT OR IGNORE` de levée, `UPDATE` de rafraîchissement, `UPDATE` de
//     résolution) étaient avalées (`let _`) : un refus rendait `Lue(0)` vert ;
//   * la reconstruction de `risk_rollup` (`SAVEPOINT`, `DELETE`+`INSERT`, `RELEASE`) avouait un refus d'ÉCRITURE par
//     `tick_aveugle`, donc par « liste des éléments dus illisible » (reste nommé par `P10.20-b`).
//
// LA FORME DU CORRECTIF : la clé (`entity_type`, `entity`) est lue À PART des mesures ; une mesure indécodable range la
// clé dans `non_jugees`, exclue de la résolution ; une clé illisible SUSPEND toute la résolution et rend `Illisible`
// nommé ; les trois écritures sont jugées, un refus rend `Illisible` avec une phrase construite dans `rba.rs`
// (« écriture refusée »), jamais celle de `tick_aveugle` (« liste des éléments dus illisible ») ; la reconstruction du
// rollup passe par la même sorte de phrase (`tick_ecriture_du_rollup_refusee`, étiquette `cause_sql` inchangée) ; une
// ERREUR DE PAS au milieu du balayage de `risk_rollup` suspend la résolution sous sa propre phrase ; un refus d'écriture
// est avoué AVANT une résolution suspendue, et le compte des refus est celui de la phrase.
//
// CE QUE CE LOT NE TIENT PAS :
//   * le déclencheur RÉEL d'un score non entier n'est pas reproduit par l'API : `risk_event_insert` lie un `i64`, les
//     témoins posent la ligne par une écriture SQL directe ;
//   * un `INSERT OR IGNORE` à zéro ligne est lu « déjà ouverte » : une alerte NON ouverte qui garderait la clé de dédup
//     (statut clos sans `dedup=NULL`) bloquerait la levée sans être comptée ;
//   * une clé illisible suspend AUSSI les résolutions légitimes des autres entités ce tick (choix assumé : on ne sait
//     pas quelle alerte la ligne protège) ;
//   * la console ne lit pas la phrase au-delà de ce que la surface détection publie déjà (domaine de `P10.31-j`).
// =====================================================================================
mod evaluation_du_risque_ligne_non_jugee_ne_resout_rien {
    use super::*;

    const ENTITE: &str = "198.51.100.8";
    const DEDUP: &str = "risk-ip-198.51.100.8";
    const AUTRE: &str = "203.0.113.20";
    const DEDUP_AUTRE: &str = "risk-ip-203.0.113.20";

    fn rnj_regler() -> parking_lot::RwLockWriteGuard<'static, ()> {
        let g = VERROU_ENV_PROCESSUS.write();
        std::env::set_var("PLUME_RISK_SCORE_THRESHOLD", "100");
        std::env::set_var("PLUME_RISK_TACTICS_THRESHOLD", "0");
        std::env::set_var("PLUME_RISK_VELOCITY", "0");
        g
    }

    fn rnj_oublier() {
        std::env::remove_var("PLUME_RISK_SCORE_THRESHOLD");
        std::env::remove_var("PLUME_RISK_TACTICS_THRESHOLD");
        std::env::remove_var("PLUME_RISK_VELOCITY");
    }

    fn rnj_semer(conn: &Connection, entite: &str) {
        let n = now();
        for (dt, mitre) in [(10, "T1110"), (8, "T1110"), (5, "T1046")] {
            assert!(risk_event_insert(conn, n - dt, "ip", entite, 40, "rule", Some(1), "test", mitre, 2, "prod", None));
        }
    }

    /// Une base où ENTITE franchit le seuil : rollup nominal joué, UNE alerte de risque ouverte.
    fn rnj_base_avec_alerte_ouverte() -> Connection {
        let conn = test_db();
        rnj_semer(&conn, ENTITE);
        assert_eq!(rollup_risk(&conn), crate::mesure_environnement::Mesure::Lue(0), "rollup nominal : Lue(0)");
        assert_eq!(rnj_ouvertes(&conn, DEDUP), 1, "départ : une alerte de risque ouverte");
        conn
    }

    fn rnj_ouvertes(conn: &Connection, dedup: &str) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM alert WHERE dedup=?1 AND status IN ('new','ack')", [dedup], |r| r.get(0))
            .unwrap()
    }

    /// Le `risk_score` RÉEL d'une contribution posée en écriture directe : la somme du rollup devient réelle.
    fn rnj_contribution_reelle(conn: &Connection, entite: &str) {
        conn.execute(
            "INSERT INTO risk_event(ts,entity_type,entity,risk_score,source,rule_id,reason,mitre,severity,env_id) \
             VALUES(?1,'ip',?2,0.5,'rule',1,'test','T1046',2,'prod')",
            params![now() - 3, entite],
        )
        .unwrap();
    }

    fn rnj_illisible(b: &crate::bilan_de_tick::BilanDeTick) -> String {
        match b {
            crate::mesure_environnement::Mesure::Illisible { detail, .. } => detail.clone(),
            autre => panic!("bilan attendu Illisible, rendu {autre:?}"),
        }
    }

    /// Le VU : une mesure indécodable ne résout PAS l'alerte ouverte de son entité ; le bilan compte l'abandon.
    #[test]
    fn rnj_mesure_indecodable_ne_resout_pas_l_alerte_ouverte() {
        let _g = rnj_regler();
        let conn = rnj_base_avec_alerte_ouverte();
        rnj_contribution_reelle(&conn, ENTITE);
        let bilan = rollup_risk(&conn);
        let reel: String =
            conn.query_row("SELECT typeof(score) FROM risk_rollup WHERE entity=?1", [ENTITE], |r| r.get(0)).unwrap();
        assert_eq!(reel, "real", "le témoin pose bien une ligne de rollup indécodable");
        assert_eq!(rnj_ouvertes(&conn, DEDUP), 1, "une entité non jugée garde son alerte ouverte (bilan {bilan:?})");
        assert_eq!(bilan, crate::mesure_environnement::Mesure::Lue(1), "l'entité non jugée est comptée");
        rnj_oublier();
    }

    /// L'exclusion est PAR ENTITÉ : une autre entité réellement retombée sous le seuil est résolue au même tick.
    #[test]
    fn rnj_exclusion_par_entite_la_retombee_voisine_est_resolue() {
        let _g = rnj_regler();
        let conn = rnj_base_avec_alerte_ouverte();
        rnj_semer(&conn, AUTRE);
        assert_eq!(rollup_risk(&conn), crate::mesure_environnement::Mesure::Lue(0));
        assert_eq!(rnj_ouvertes(&conn, DEDUP_AUTRE), 1, "départ : seconde alerte ouverte");
        conn.execute("DELETE FROM risk_event WHERE entity=?1", [AUTRE]).unwrap();
        rnj_contribution_reelle(&conn, ENTITE);
        let bilan = rollup_risk(&conn);
        assert_eq!(rnj_ouvertes(&conn, DEDUP), 1, "entité non jugée : alerte gardée");
        assert_eq!(rnj_ouvertes(&conn, DEDUP_AUTRE), 0, "entité retombée : alerte résolue comme avant");
        assert_eq!(bilan, crate::mesure_environnement::Mesure::Lue(1));
        rnj_oublier();
    }

    /// Clé d'entité illisible (un BLOB) : la ligne ne dit pas quelle alerte elle protège, la résolution est suspendue
    /// et le bilan l'avoue. Forme d'avant : ligne abandonnée, alerte de la même entité résolue, `Lue(1)`.
    #[test]
    fn rnj_cle_illisible_suspend_la_resolution_et_le_dit() {
        let _g = rnj_regler();
        let conn = rnj_base_avec_alerte_ouverte();
        conn.execute("UPDATE risk_event SET entity=CAST(entity AS BLOB) WHERE entity=?1", [ENTITE]).unwrap();
        let bilan = rollup_risk(&conn);
        assert_eq!(rnj_ouvertes(&conn, DEDUP), 1, "clé illisible : aucune alerte résolue (bilan {bilan:?})");
        let detail = rnj_illisible(&bilan);
        assert!(detail.contains("résolution des alertes de risque ouvertes SUSPENDUE"), "aveu nommé : {detail}");
        assert!(!detail.contains("liste des éléments dus illisible"), "phrase juste : {detail}");
        rnj_oublier();
    }

    /// Levée refusée (`INSERT` sur `alert` refusé) : bilan Illisible « écriture refusée », jamais `Lue(0)`.
    #[test]
    fn rnj_levee_refusee_n_est_pas_un_tick_vert() {
        let _g = rnj_regler();
        let conn = test_db();
        rnj_semer(&conn, ENTITE);
        conn.execute_batch(
            "CREATE TRIGGER rnj_refuse_insert BEFORE INSERT ON alert BEGIN SELECT RAISE(ABORT, 'alerte non inscriptible'); END;",
        )
        .unwrap();
        let bilan = rollup_risk(&conn);
        assert_eq!(rnj_ouvertes(&conn, DEDUP), 0);
        let detail = rnj_illisible(&bilan);
        assert!(detail.contains("écriture refusée") && detail.contains("levée"), "phrase juste : {detail}");
        assert!(!detail.contains("liste des éléments dus illisible"), "phrase juste : {detail}");
        rnj_oublier();
    }

    /// Rafraîchissement refusé (`UPDATE OF title`) : bilan Illisible, l'alerte reste ouverte.
    #[test]
    fn rnj_rafraichissement_refuse_n_est_pas_un_tick_vert() {
        let _g = rnj_regler();
        let conn = rnj_base_avec_alerte_ouverte();
        conn.execute_batch(
            "CREATE TRIGGER rnj_refuse_maj BEFORE UPDATE OF title ON alert BEGIN SELECT RAISE(ABORT, 'alerte figée'); END;",
        )
        .unwrap();
        let detail = rnj_illisible(&rollup_risk(&conn));
        assert!(detail.contains("écriture refusée") && detail.contains("rafraîchissement"), "phrase juste : {detail}");
        assert_eq!(rnj_ouvertes(&conn, DEDUP), 1);
        rnj_oublier();
    }

    /// Résolution refusée (`UPDATE OF status`) sur une retombée réelle : bilan Illisible, pas `Lue(0)`.
    #[test]
    fn rnj_resolution_refusee_n_est_pas_un_tick_vert() {
        let _g = rnj_regler();
        let conn = rnj_base_avec_alerte_ouverte();
        conn.execute("DELETE FROM risk_event", []).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER rnj_refuse_resolution BEFORE UPDATE OF status ON alert BEGIN SELECT RAISE(ABORT, 'alerte non résoluble'); END;",
        )
        .unwrap();
        let bilan = rollup_risk(&conn);
        assert_eq!(rnj_ouvertes(&conn, DEDUP), 1, "la résolution a bien été refusée");
        let detail = rnj_illisible(&bilan);
        assert!(detail.contains("écriture refusée") && detail.contains("résolution"), "phrase juste : {detail}");
        rnj_oublier();
    }

    /// Inverse nominal : levée, rafraîchissement sans doublon, retombée résolue — tout sous `Lue(0)`.
    #[test]
    fn rnj_nominal_inchange() {
        let _g = rnj_regler();
        let conn = rnj_base_avec_alerte_ouverte();
        assert_eq!(
            rollup_risk(&conn),
            crate::mesure_environnement::Mesure::Lue(0),
            "rafraîchissement nominal : INSERT OR IGNORE à zéro ligne = déjà ouverte, pas un refus"
        );
        conn.execute("DELETE FROM risk_event", []).unwrap();
        assert_eq!(rollup_risk(&conn), crate::mesure_environnement::Mesure::Lue(0));
        assert_eq!(rnj_ouvertes(&conn, DEDUP), 0, "retombée réelle : alerte résolue");
        rnj_oublier();
    }

    fn rnj_cause(b: &crate::bilan_de_tick::BilanDeTick) -> &'static str {
        match b {
            crate::mesure_environnement::Mesure::Illisible { cause, .. } => cause,
            autre => panic!("bilan attendu Illisible, rendu {autre:?}"),
        }
    }

    /// Reconstruction de `risk_rollup` refusée (`INSERT` du rollup) : la phrase dit une ÉCRITURE refusée, pas une liste
    /// illisible. Forme d'avant (`tick_aveugle`) : « … : liste des éléments dus illisible (rollup non inscriptible) ».
    #[test]
    fn rnj_reconstruction_refusee_dit_ecriture_refusee() {
        let _g = rnj_regler();
        let conn = rnj_base_avec_alerte_ouverte();
        conn.execute_batch(
            "CREATE TRIGGER rnj_refuse_rollup BEFORE INSERT ON risk_rollup BEGIN SELECT RAISE(ABORT, 'rollup non inscriptible'); END;",
        )
        .unwrap();
        let bilan = rollup_risk(&conn);
        let detail = rnj_illisible(&bilan);
        assert!(detail.contains("reconstruction du rollup refusée") && detail.contains("écriture refusée"), "phrase juste : {detail}");
        assert!(!detail.contains("liste des éléments dus illisible"), "phrase juste : {detail}");
        assert_eq!(rnj_cause(&bilan), crate::mesure_environnement::CAUSE_SOURCE_ILLISIBLE, "étiquette fermée inchangée");
        assert_eq!(rnj_ouvertes(&conn, DEDUP), 1);
        rnj_oublier();
    }

    /// `SAVEPOINT` de la reconstruction refusé (autorisateur) : même phrase juste.
    #[test]
    fn rnj_savepoint_refuse_dit_ecriture_refusee() {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
        let _g = rnj_regler();
        let conn = rnj_base_avec_alerte_ouverte();
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Savepoint { operation: TransactionOperation::Begin, savepoint_name }
                if savepoint_name == "rollup_risk_reconstruction" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let bilan = rollup_risk(&conn);
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        let detail = rnj_illisible(&bilan);
        assert!(detail.contains("reconstruction du rollup non ouverte") && detail.contains("écriture refusée"), "phrase juste : {detail}");
        assert!(!detail.contains("liste des éléments dus illisible"), "phrase juste : {detail}");
        rnj_oublier();
    }

    /// ERREUR DE PAS au milieu du balayage de `risk_rollup` (une vue qui calcule `abs(i64::MIN)` sur la ligne d'AUTRE) :
    /// les lignes non lues ne disent pas quelles alertes elles protègent, la résolution est suspendue, la phrase nomme
    /// le balayage interrompu (pas une clé indécodable). La vue n'est ARMÉE qu'après la reconstruction (le `DELETE`
    /// d'une vue matérialise ses lignes : armée dès le départ, c'est la reconstruction qui échouerait).
    #[test]
    fn rnj_balayage_interrompu_suspend_la_resolution() {
        let _g = rnj_regler();
        let conn = rnj_base_avec_alerte_ouverte();
        rnj_semer(&conn, AUTRE);
        assert_eq!(rollup_risk(&conn), crate::mesure_environnement::Mesure::Lue(0));
        assert_eq!(rnj_ouvertes(&conn, DEDUP_AUTRE), 1, "départ : seconde alerte ouverte");
        conn.execute_batch(&format!(
            "ALTER TABLE risk_rollup RENAME TO rnj_rollup_reel;
             CREATE TABLE rnj_arme(a INTEGER NOT NULL);
             INSERT INTO rnj_arme VALUES(0);
             CREATE VIEW risk_rollup AS SELECT entity_type, entity, env_id,
                 CASE WHEN entity='{AUTRE}' AND (SELECT a FROM rnj_arme)=1 THEN abs(-9223372036854775807-1+contrib*0) ELSE score END AS score,
                 contrib, distinct_tactics, tactics, score_hot, contrib_hot, max_severity, first_ts, last_ts, updated
               FROM rnj_rollup_reel;
             CREATE TRIGGER rnj_vue_delete INSTEAD OF DELETE ON risk_rollup BEGIN DELETE FROM rnj_rollup_reel; END;
             CREATE TRIGGER rnj_vue_insert INSTEAD OF INSERT ON risk_rollup BEGIN
               INSERT INTO rnj_rollup_reel(entity_type,entity,env_id,score,contrib,distinct_tactics,tactics,score_hot,
                                           contrib_hot,max_severity,first_ts,last_ts,updated)
               VALUES(NEW.entity_type,NEW.entity,NEW.env_id,NEW.score,NEW.contrib,NEW.distinct_tactics,NEW.tactics,
                      NEW.score_hot,NEW.contrib_hot,NEW.max_severity,NEW.first_ts,NEW.last_ts,NEW.updated);
               UPDATE rnj_arme SET a=1;
             END;"
        ))
        .unwrap();
        let bilan = rollup_risk(&conn);
        assert_eq!(rnj_ouvertes(&conn, DEDUP_AUTRE), 1, "entité jamais lue : alerte gardée (bilan {bilan:?})");
        assert_eq!(rnj_ouvertes(&conn, DEDUP), 1, "résolution suspendue : alerte gardée (bilan {bilan:?})");
        let detail = rnj_illisible(&bilan);
        assert!(detail.contains("lecture de risk_rollup interrompue") && detail.contains("SUSPENDUE"), "aveu nommé : {detail}");
        assert!(!detail.contains("clé d'entité indécodable"), "une erreur de pas n'est pas une clé indécodable : {detail}");
        rnj_oublier();
    }

    /// Un refus d'écriture ET une clé illisible au même tick : le refus est avoué D'ABORD, sa cause est l'étiquette.
    #[test]
    fn rnj_refus_et_cle_illisible_le_refus_d_abord() {
        let _g = rnj_regler();
        let conn = rnj_base_avec_alerte_ouverte();
        conn.execute("UPDATE risk_event SET entity=CAST(entity AS BLOB) WHERE entity=?1", [ENTITE]).unwrap();
        rnj_semer(&conn, AUTRE);
        conn.execute_batch(
            "CREATE TRIGGER rnj_refuse_insert BEFORE INSERT ON alert BEGIN SELECT RAISE(ABORT, 'alerte non inscriptible'); END;",
        )
        .unwrap();
        let bilan = rollup_risk(&conn);
        let detail = rnj_illisible(&bilan);
        let refus = detail.find("écriture refusée").unwrap_or_else(|| panic!("refus avoué : {detail}"));
        let suspendue = detail.find("SUSPENDUE").unwrap_or_else(|| panic!("suspension avouée : {detail}"));
        assert!(refus < suspendue, "le refus d'abord : {detail}");
        assert_eq!(rnj_cause(&bilan), crate::mesure_environnement::CAUSE_SOURCE_ILLISIBLE, "cause du refus : {detail}");
        rnj_oublier();
    }

    /// Deux levées refusées : la phrase compte DEUX écritures refusées.
    #[test]
    fn rnj_deux_levees_refusees_sont_comptees() {
        let _g = rnj_regler();
        let conn = test_db();
        rnj_semer(&conn, ENTITE);
        rnj_semer(&conn, AUTRE);
        conn.execute_batch(
            "CREATE TRIGGER rnj_refuse_insert BEFORE INSERT ON alert BEGIN SELECT RAISE(ABORT, 'alerte non inscriptible'); END;",
        )
        .unwrap();
        let detail = rnj_illisible(&rollup_risk(&conn));
        assert!(detail.contains("(2 écriture(s) d'alerte de risque refusée(s)"), "compte juste : {detail}");
        rnj_oublier();
    }
}
