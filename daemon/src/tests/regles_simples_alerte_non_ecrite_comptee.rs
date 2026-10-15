// =====================================================================================
// `P10.20-b` (rang trois, famille Q3 : `run_due_rules` et son consignateur `detection_aveugle`) — UNE ALERTE QUE LE
// MOTEUR REFUSE D'ÉCRIRE EST COMPTÉE, ET RIEN N'AFFIRME UN TIR OU UNE ALERTE QUI N'EXISTE PAS.
//
// VU sur `c78be971` : `run_due_rules` avalait l'INSERT de l'alerte d'une règle simple qui TIRE (`let _ =
// conn.execute(..)`) et posait `last_fired` AVANT, sans condition ; le bilan du tick ne comptait que les abandons
// d'évaluation. `consigner_abandon` avalait l'incrément du compte consécutif (puis posait l'alerte de cécité sur le
// compte RELU, non écrit) et l'INSERT de l'alerte de cécité (puis rendait `alerte_posee: true`).
// `consigner_evaluation_reussie` avalait la remise à zéro et la résolution (alerte de cécité restée ouverte sur une
// règle saine, sans un mot). Le jumeau `run_advanced_rules` est jugé par `alertes_ecrites_avant_d_avancer_l_etat`.
//
// ATTENDU, tenu ici : les refus sont fabriqués par des triggers `RAISE(ABORT)` (l'`OR IGNORE` ne les absorbe pas),
// chacun ciblé sur UNE écriture. Alerte de tir refusée -> `Lue(1)`, aucune alerte, `last_fired` NULL ; trigger
// retiré -> alerte écrite, `last_fired` posé, `Lue(0)`. Épisode déjà ouvert (`Ok(0)`) -> pas un refus : `Lue(0)`,
// `last_fired` reposé, une seule alerte. Incrément du compte refusé -> `None`, aucune alerte de cécité, compte
// inchangé, l'abandon reste compté par le tick. INSERT de cécité refusé -> `alerte_posee == false`, aucune alerte ;
// épisode de cécité déjà ouvert -> `alerte_posee == true`. Remise à zéro ou résolution refusée -> `false` rendu, le
// tick compte la règle (`Lue(1)`). Contrôle nominal : alerte de cécité résolue, compte à zéro, `true`, `Lue(0)`.
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit) : R5_INSERT_AVALE, R5_LASTFIRED_AVANT, R5_ABANDON_NON_COMPTE,
// R5_OK0_REFUS (`run_due_rules`) ; R5_CPT_AVALE, R5_CECITE_AVALE, R5_POSEE_TRUE, R5_OK0_CECITE (`consigner_abandon`) ;
// R5_RAZ_AVALE, R5_RESOL_AVALE (`consigner_evaluation_reussie`), R5_RESOL_NON_COMPTE (l'appelant n'en compte pas
// l'issue) — chacun rouge sur son témoin. Second passage (après vérification) : R5_COURT_CIRCUIT (`return false`
// après le refus de la remise à zéro, résolution jamais tentée) rouge sur `p10_20b_r5_remise_a_zero_refusee_comptee` ;
// R5_DOUBLE (refus de l'alerte de tir compté une seconde fois si la remise à zéro a aussi été refusée) rouge sur
// `p10_20b_r5_remise_a_zero_et_alerte_de_tir_refusees_une_regle_un_abandon`.
// Troisième passage : R5_FIN_PAR_TICK (le compte de fin de tour — remise à zéro ou résolution refusée — fait une fois
// par tick au lieu d'une fois par règle) rouge sur `p10_20b_r5_deux_regles_remise_a_zero_refusee_deux_abandons` et
// `p10_20b_r5_deux_regles_resolution_refusee_deux_abandons` (Lue(1) au lieu de Lue(2)).
// `P10.32-x` (quatrième passage) : le compte de fin de tour est témoigné pour une règle qui TIRE et dont l'alerte est
// ÉCRITE (`p10_32x_s1_*`, remise à zéro ou résolution de cécité refusée -> `Lue(1)`) ; l'état de la règle n'avance
// plus avant l'alerte (alerte refusée : ni `last_run`, ni `last_value`, ni compte, ni résolution de cécité, ni
// `population_vue`). Mutants : S1_D11_FIN_DANS_ELSE (compte dans la seule branche du non-tir), S1_CONSIGNER_AVANT_INSERT
// (l'ordre d'avant), S1_POPVUE_AVANT_INSERT — chacun rouge sur son témoin.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les lignes de journal des refus (non lues ; les rendre muettes reste vert) ;
// les écritures restées `let _` — `population_vue`, le rafraîchissement de l'alerte de tir et de l'alerte de cécité,
// `last_fired` lui-même, la résolution de l'alerte de tir au retour sous le seuil ; un refus par verrou, disque
// plein ou base en lecture seule (même `Err`, non fabriqué) ; une défaillance DURABLE de la base (comptée à chaque
// tick, rien de plus) ; les autres moteurs (corrélation, lignes de base, risque). Le CONTRAT de `Lue(n)` n'est pas
// réaligné : `bilan_de_tick.rs` (doc de `Mesure::Lue`) et le commentaire de `metrics.rs` disent que `n` compte les
// règles « qui n'ont PAS été évaluées » ; `run_due_rules` y compte désormais AUSSI une règle évaluée dont une
// écriture a été refusée (comme le jumeau `run_advanced_rules` le faisait déjà). Les deux causes sortent sous le même
// compte publié ; seule la ligne de journal les distingue. Ces deux fichiers sont hors du périmètre de ce changement.
// Prix assumé de « rien n'avance » : tant que l'alerte de tir est refusée, la règle est réévaluée à CHAQUE tick (pas à
// son intervalle), son compte d'abandons n'est pas remis à zéro et une alerte de cécité ouverte le reste. Le jumeau
// `run_advanced_rules` (`handlers/alerting.rs`, hors périmètre) pose encore `last_run`/`last_value` AVANT ses alertes.
// =====================================================================================
mod regles_simples_alerte_non_ecrite_comptee {
    use super::*;
    use crate::detection_aveugle::{cle_dedup, consigner_abandon, consigner_evaluation_reussie, seuil_d_abandons_consecutifs, AbandonDEvaluation};
    use crate::mesure_environnement::Mesure;

    const R5_INTERVALLE_S: i64 = 600;

    fn r5_base(tag: &str) -> (crate::tmp_possede::TmpPossede, Arc<Mutex<Connection>>, String) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(&format!("r5-{tag}"));
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM rule", []).unwrap();
            conn.execute("DELETE FROM alert", []).unwrap();
        }
        (tmp, db, p)
    }

    /// Une règle simple en SQL brut (`op` '>' seuil 1) : `SELECT 5` tire, `SELECT 0` non, une table absente abandonne.
    fn r5_regle(db: &Arc<Mutex<Connection>>, nom: &str, sql: &str) -> i64 {
        let c = db.lock();
        c.execute(
            "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) VALUES(?1,1,?2,0,'>',1,3,?3,3600)",
            params![nom, sql, R5_INTERVALLE_S],
        )
        .unwrap();
        c.last_insert_rowid()
    }

    fn r5_sql(db: &Arc<Mutex<Connection>>, sql: &str) {
        db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    /// Un tick où la règle est due (`last_run` effacé).
    fn r5_tick(db: &Arc<Mutex<Connection>>, p: &str) -> Mesure<u32> {
        r5_sql(db, "UPDATE rule SET last_run=NULL");
        run_due_rules(db, p)
    }

    fn r5_n(db: &Arc<Mutex<Connection>>, sql: &str) -> i64 {
        db.lock().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn r5_last_fired(db: &Arc<Mutex<Connection>>, id: i64) -> Option<i64> {
        db.lock().query_row("SELECT last_fired FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap()
    }

    fn r5_abandons(db: &Arc<Mutex<Connection>>, id: i64) -> i64 {
        db.lock().query_row("SELECT abandons_consecutifs FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap()
    }

    fn r5_cecite_ouverte(db: &Arc<Mutex<Connection>>, id: i64) -> i64 {
        db.lock()
            .query_row("SELECT COUNT(*) FROM alert WHERE dedup=?1 AND status IN ('new','ack')", params![cle_dedup(id)], |r| r.get(0))
            .unwrap()
    }

    fn r5_seuil() -> i64 {
        i64::from(seuil_d_abandons_consecutifs(R5_INTERVALLE_S))
    }

    // ---------------------------------------------------------------- run_due_rules : l'alerte de tir

    #[test]
    fn p10_20b_r5_alerte_de_tir_refusee_comptee_last_fired_non_pose_puis_rejouee() {
        let (_t, db, p) = r5_base("tir-refuse");
        let id = r5_regle(&db, "r5-tire", "SELECT 5");
        r5_sql(&db, "CREATE TRIGGER r5_refus BEFORE INSERT ON alert WHEN NEW.rule LIKE 'rule.%' BEGIN SELECT RAISE(ABORT, 'alerte refusée par le témoin'); END;");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(1), "alerte de tir refusée : la règle est comptée abandonnée");
        assert_eq!(r5_n(&db, "SELECT COUNT(*) FROM alert"), 0, "aucune alerte n'est entrée");
        assert_eq!(r5_last_fired(&db, id), None, "last_fired n'affirme pas un tir dont l'alerte n'existe pas");
        r5_sql(&db, "DROP TRIGGER r5_refus;");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(0), "trigger retiré : rien d'abandonné");
        assert_eq!(r5_n(&db, "SELECT COUNT(*) FROM alert WHERE rule LIKE 'rule.%' AND status='new'"), 1, "l'alerte est rejouée");
        assert!(r5_last_fired(&db, id).is_some(), "alerte écrite : last_fired posé");
    }

    #[test]
    fn p10_20b_r5_controle_nominal_alerte_ecrite_last_fired_pose() {
        let (_t, db, p) = r5_base("tir-ok");
        let id = r5_regle(&db, "r5-tire-ok", "SELECT 5");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(0));
        assert_eq!(r5_n(&db, "SELECT COUNT(*) FROM alert WHERE rule LIKE 'rule.%' AND status='new'"), 1);
        assert!(r5_last_fired(&db, id).is_some());
    }

    #[test]
    fn p10_20b_r5_episode_deja_ouvert_ok_zero_n_est_pas_un_refus() {
        let (_t, db, p) = r5_base("tir-ok0");
        let id = r5_regle(&db, "r5-tire-ok0", "SELECT 5");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(0));
        r5_sql(&db, "UPDATE rule SET last_fired=NULL");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(0), "INSERT OR IGNORE écarté par la dédup (Ok(0)) : pas un abandon");
        assert_eq!(r5_n(&db, "SELECT COUNT(*) FROM alert"), 1, "une seule alerte par épisode");
        assert!(r5_last_fired(&db, id).is_some(), "épisode déjà ouvert : last_fired reposé");
    }

    // ---------------------------------------------------------------- consigner_abandon

    #[test]
    fn p10_20b_r5_compte_d_abandons_refuse_rien_n_est_pose_et_l_abandon_reste_compte() {
        let (_t, db, p) = r5_base("cpt-refuse");
        let id = r5_regle(&db, "r5-aveugle", "SELECT x FROM table_absente_r5");
        let seuil = r5_seuil();
        r5_sql(&db, &format!("UPDATE rule SET abandons_consecutifs={seuil} WHERE id={id}"));
        r5_sql(&db, "CREATE TRIGGER r5_cpt BEFORE UPDATE OF abandons_consecutifs ON rule WHEN NEW.abandons_consecutifs > OLD.abandons_consecutifs BEGIN SELECT RAISE(ABORT, 'compte refusé par le témoin'); END;");
        {
            let c = db.lock();
            let abandon = AbandonDEvaluation::compilation_refusee("x");
            assert_eq!(consigner_abandon(&c, id, "r5-aveugle", 3, now(), &abandon), None, "compte non écrit : None");
        }
        assert_eq!(r5_n(&db, "SELECT COUNT(*) FROM alert"), 0, "aucune alerte de cécité sur un compte non écrit");
        assert_eq!(r5_abandons(&db, id), seuil, "le compte est celui d'avant");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(1), "par l'ordonnanceur : l'abandon reste compté");
        assert_eq!(r5_n(&db, "SELECT COUNT(*) FROM alert"), 0);
    }

    #[test]
    fn p10_20b_r5_alerte_de_cecite_refusee_alerte_posee_faux() {
        let (_t, db, _p) = r5_base("cecite-refusee");
        let id = r5_regle(&db, "r5-aveugle-2", "SELECT x FROM table_absente_r5");
        let seuil = r5_seuil();
        r5_sql(&db, &format!("UPDATE rule SET abandons_consecutifs={} WHERE id={id}", seuil - 1));
        r5_sql(&db, &format!(
            "CREATE TRIGGER r5_cecite BEFORE INSERT ON alert WHEN NEW.dedup='{}' BEGIN SELECT RAISE(ABORT, 'cécité refusée par le témoin'); END;",
            cle_dedup(id)
        ));
        let c = db.lock();
        let abandon = AbandonDEvaluation::compilation_refusee("x");
        let r = consigner_abandon(&c, id, "r5-aveugle-2", 3, now(), &abandon).expect("compte écrit et relu : Some");
        assert_eq!(i64::from(r.consecutifs), seuil, "le seuil est atteint");
        assert!(!r.alerte_posee, "INSERT de cécité refusé : alerte_posee ne ment pas");
        let n: i64 = c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn p10_20b_r5_episode_de_cecite_deja_ouvert_alerte_posee_vrai() {
        let (_t, db, _p) = r5_base("cecite-ok0");
        let id = r5_regle(&db, "r5-aveugle-3", "SELECT x FROM table_absente_r5");
        r5_sql(&db, &format!("UPDATE rule SET abandons_consecutifs={} WHERE id={id}", r5_seuil() - 1));
        let c = db.lock();
        let abandon = AbandonDEvaluation::compilation_refusee("x");
        assert!(consigner_abandon(&c, id, "r5-aveugle-3", 3, now(), &abandon).unwrap().alerte_posee, "écrite : posée");
        assert!(consigner_abandon(&c, id, "r5-aveugle-3", 3, now(), &abandon).unwrap().alerte_posee, "déjà ouverte (Ok(0)) : posée");
        let n: i64 = c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "une seule alerte de cécité par épisode");
    }

    // ---------------------------------------------------------------- consigner_evaluation_reussie

    /// Une règle saine (non franchissante) dont l'épisode de cécité est ouvert.
    fn r5_regle_saine_cecite_ouverte(db: &Arc<Mutex<Connection>>, nom: &str) -> i64 {
        r5_regle_cecite_ouverte(db, nom, "SELECT 0")
    }

    /// Une règle (`sql` dit si elle tire) dont l'épisode de cécité est ouvert.
    fn r5_regle_cecite_ouverte(db: &Arc<Mutex<Connection>>, nom: &str, sql: &str) -> i64 {
        let id = r5_regle(db, nom, sql);
        r5_sql(db, &format!("UPDATE rule SET abandons_consecutifs={} WHERE id={id}", r5_seuil() - 1));
        let posee = {
            let c = db.lock();
            consigner_abandon(&c, id, nom, 3, now(), &AbandonDEvaluation::compilation_refusee("x")).unwrap().alerte_posee
        };
        assert!(posee, "fixture : épisode de cécité ouvert");
        assert_eq!(r5_cecite_ouverte(db, id), 1);
        id
    }

    #[test]
    fn p10_20b_r5_resolution_de_cecite_refusee_comptee() {
        let (_t, db, p) = r5_base("resol-refusee");
        let id = r5_regle_saine_cecite_ouverte(&db, "r5-saine");
        r5_sql(&db, "CREATE TRIGGER r5_resol BEFORE UPDATE OF status ON alert WHEN NEW.status='resolved' BEGIN SELECT RAISE(ABORT, 'résolution refusée par le témoin'); END;");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(1), "résolution refusée : la règle est comptée");
        assert_eq!(r5_cecite_ouverte(&db, id), 1, "fixture : l'alerte de cécité est restée ouverte");
        assert_eq!(r5_abandons(&db, id), 0, "la remise à zéro, elle, est passée");
        let c = db.lock();
        assert!(!consigner_evaluation_reussie(&c, id, now(), 0.0), "résolution refusée : false rendu");
    }

    #[test]
    fn p10_20b_r5_remise_a_zero_refusee_comptee() {
        let (_t, db, p) = r5_base("raz-refusee");
        let id = r5_regle_saine_cecite_ouverte(&db, "r5-saine-2");
        r5_sql(&db, "CREATE TRIGGER r5_raz BEFORE UPDATE OF last_value ON rule BEGIN SELECT RAISE(ABORT, 'remise à zéro refusée par le témoin'); END;");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(1), "remise à zéro refusée : la règle est comptée");
        assert_eq!(r5_abandons(&db, id), r5_seuil(), "fixture : le compte n'a pas été remis à zéro");
        assert_eq!(
            r5_cecite_ouverte(&db, id),
            0,
            "remise à zéro refusée : la résolution de l'alerte de cécité est QUAND MÊME tentée (les deux écritures sont tentées)"
        );
        let c = db.lock();
        assert!(!consigner_evaluation_reussie(&c, id, now(), 0.0), "remise à zéro refusée : false rendu");
    }

    /// Une règle, un abandon : la remise à zéro ET l'alerte de tir refusées pour la MÊME règle font UN abandon.
    #[test]
    fn p10_20b_r5_remise_a_zero_et_alerte_de_tir_refusees_une_regle_un_abandon() {
        let (_t, db, p) = r5_base("double-refus");
        let id = r5_regle(&db, "r5-double", "SELECT 5");
        r5_sql(&db, "CREATE TRIGGER r5_raz2 BEFORE UPDATE OF last_value ON rule BEGIN SELECT RAISE(ABORT, 'remise à zéro refusée par le témoin'); END;");
        r5_sql(&db, "CREATE TRIGGER r5_tir2 BEFORE INSERT ON alert WHEN NEW.rule LIKE 'rule.%' BEGIN SELECT RAISE(ABORT, 'alerte refusée par le témoin'); END;");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(1), "deux écritures refusées pour une seule règle : un seul abandon");
        assert_eq!(r5_n(&db, "SELECT COUNT(*) FROM alert"), 0, "fixture : aucune alerte n'est entrée");
        assert_eq!(r5_last_fired(&db, id), None, "fixture : last_fired non posé");
        // Contrôle : deux règles dans le même cas font deux abandons (le compte est par règle, pas par tick).
        r5_regle(&db, "r5-double-bis", "SELECT 7");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(2), "deux règles, deux abandons");
    }

    /// Le compte de fin de tour est PAR RÈGLE : deux règles saines dont la remise à zéro est refusée font deux abandons.
    #[test]
    fn p10_20b_r5_deux_regles_remise_a_zero_refusee_deux_abandons() {
        let (_t, db, p) = r5_base("raz-deux");
        let a = r5_regle(&db, "r5-saine-a", "SELECT 0");
        let b = r5_regle(&db, "r5-saine-b", "SELECT 0");
        r5_sql(&db, "CREATE TRIGGER r5_raz3 BEFORE UPDATE OF last_value ON rule BEGIN SELECT RAISE(ABORT, 'remise à zéro refusée par le témoin'); END;");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(2), "deux règles dont la remise à zéro est refusée : deux abandons");
        assert_eq!(r5_n(&db, "SELECT COUNT(*) FROM alert"), 0, "fixture : aucune des deux ne tire");
        for id in [a, b] {
            let lv: Option<f64> = db.lock().query_row("SELECT last_value FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap();
            assert_eq!(lv, None, "fixture : la remise à zéro de la règle #{id} a bien été refusée");
        }
        r5_sql(&db, "DROP TRIGGER r5_raz3;");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(0), "trigger retiré : rien d'abandonné");
    }

    /// Même chose pour la résolution de cécité refusée sur deux règles saines.
    #[test]
    fn p10_20b_r5_deux_regles_resolution_refusee_deux_abandons() {
        let (_t, db, p) = r5_base("resol-deux");
        let a = r5_regle_saine_cecite_ouverte(&db, "r5-saine-c");
        let b = r5_regle_saine_cecite_ouverte(&db, "r5-saine-d");
        r5_sql(&db, "CREATE TRIGGER r5_resol2 BEFORE UPDATE OF status ON alert WHEN NEW.status='resolved' BEGIN SELECT RAISE(ABORT, 'résolution refusée par le témoin'); END;");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(2), "deux résolutions refusées : deux abandons");
        assert_eq!(r5_cecite_ouverte(&db, a) + r5_cecite_ouverte(&db, b), 2, "fixture : les deux alertes de cécité restent ouvertes");
    }

    // ---------------------------------------------------------------- `P10.32-x` : une règle qui TIRE, alerte écrite

    /// Le compte de fin de tour vaut AUSSI pour une règle qui TIRE et dont l'alerte est écrite : remise à zéro refusée
    /// -> `Lue(1)`. MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=S1_D11_FIN_DANS_ELSE` (compte dans la seule branche du
    /// non-tir -> `Lue(0)`).
    #[test]
    fn p10_32x_s1_regle_qui_tire_alerte_ecrite_remise_a_zero_refusee_comptee() {
        let (_t, db, p) = r5_base("tir-raz");
        let id = r5_regle(&db, "r5-tire-raz", "SELECT 5");
        r5_sql(&db, &format!("UPDATE rule SET abandons_consecutifs=2 WHERE id={id}"));
        r5_sql(&db, "CREATE TRIGGER s1_raz BEFORE UPDATE OF last_value ON rule BEGIN SELECT RAISE(ABORT, 'remise à zéro refusée par le témoin'); END;");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(1), "règle qui tire, alerte écrite, remise à zéro refusée : la règle est comptée");
        assert_eq!(r5_n(&db, "SELECT COUNT(*) FROM alert WHERE rule LIKE 'rule.%' AND status='new'"), 1, "fixture : l'alerte de tir est écrite");
        assert!(r5_last_fired(&db, id).is_some(), "fixture : alerte écrite, last_fired posé");
        assert_eq!(r5_abandons(&db, id), 2, "fixture : la remise à zéro a bien été refusée");
        r5_sql(&db, "DROP TRIGGER s1_raz;");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(0), "trigger retiré : rien d'abandonné (épisode déjà ouvert, Ok(0))");
        assert_eq!(r5_abandons(&db, id), 0);
    }

    /// Même chose pour la résolution de cécité refusée sur une règle qui TIRE (alerte de tir écrite) -> `Lue(1)`.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=S1_D11_FIN_DANS_ELSE`.
    #[test]
    fn p10_32x_s1_regle_qui_tire_alerte_ecrite_resolution_de_cecite_refusee_comptee() {
        let (_t, db, p) = r5_base("tir-resol");
        let id = r5_regle_cecite_ouverte(&db, "r5-tire-resol", "SELECT 5");
        r5_sql(&db, "CREATE TRIGGER s1_resol BEFORE UPDATE OF status ON alert WHEN NEW.status='resolved' BEGIN SELECT RAISE(ABORT, 'résolution refusée par le témoin'); END;");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(1), "règle qui tire, alerte écrite, résolution de cécité refusée : la règle est comptée");
        assert_eq!(r5_n(&db, "SELECT COUNT(*) FROM alert WHERE rule LIKE 'rule.%' AND status='new'"), 1, "fixture : l'alerte de tir est écrite");
        assert_eq!(r5_cecite_ouverte(&db, id), 1, "fixture : l'alerte de cécité est restée ouverte");
        assert_eq!(r5_abandons(&db, id), 0, "fixture : la remise à zéro, elle, est passée");
    }

    /// Alerte de tir refusée : RIEN de la règle n'avance — `last_run`, `last_value`, le compte d'abandons, l'alerte de
    /// cécité et `population_vue` restent ceux d'avant ; la règle reste due au tick suivant. MUTATIONS QUI LE FONT
    /// ROUGIR : `VERIF_MUT=S1_CONSIGNER_AVANT_INSERT` (l'ordre d'avant : état écrit puis alerte),
    /// `VERIF_MUT=S1_POPVUE_AVANT_INSERT` (`population_vue` écrite avant l'alerte).
    #[test]
    fn p10_32x_s1_alerte_de_tir_refusee_l_etat_de_la_regle_n_avance_pas() {
        let (_t, db, p) = r5_base("tir-refuse-etat");
        let id = r5_regle_cecite_ouverte(&db, "r5-tire-etat", "SELECT 5");
        let seuil = r5_seuil();
        r5_sql(&db, &format!("UPDATE rule SET population_vue='avant-s1', last_value=NULL WHERE id={id}"));
        r5_sql(&db, "CREATE TRIGGER s1_tir BEFORE INSERT ON alert WHEN NEW.rule LIKE 'rule.%' BEGIN SELECT RAISE(ABORT, 'alerte refusée par le témoin'); END;");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(1), "alerte de tir refusée : comptée");
        let (last_run, last_value, popvue): (Option<i64>, Option<f64>, Option<String>) = db
            .lock()
            .query_row("SELECT last_run, last_value, population_vue FROM rule WHERE id=?1", params![id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(last_run, None, "last_run non posé : la règle reste due");
        assert_eq!(last_value, None, "last_value non posé");
        assert_eq!(popvue.as_deref(), Some("avant-s1"), "population_vue non réécrite pour un tir sans alerte");
        assert_eq!(r5_abandons(&db, id), seuil, "compte d'abandons non remis à zéro");
        assert_eq!(r5_cecite_ouverte(&db, id), 1, "alerte de cécité non résolue");
        assert_eq!(r5_last_fired(&db, id), None);
        // Due au tick suivant SANS qu'on efface last_run : la règle est réévaluée et l'alerte entre.
        r5_sql(&db, "DROP TRIGGER s1_tir;");
        assert_eq!(run_due_rules(&db, &p), Mesure::Lue(0), "trigger retiré : rejouée au tick suivant, rien d'abandonné");
        assert_eq!(r5_n(&db, "SELECT COUNT(*) FROM alert WHERE rule LIKE 'rule.%' AND status='new'"), 1, "l'alerte entre au tick suivant");
        assert_eq!(r5_abandons(&db, id), 0);
        assert_eq!(r5_cecite_ouverte(&db, id), 0);
    }

    #[test]
    fn p10_20b_r5_controle_nominal_cecite_resolue_compte_a_zero() {
        let (_t, db, p) = r5_base("resol-ok");
        let id = r5_regle_saine_cecite_ouverte(&db, "r5-saine-3");
        assert_eq!(r5_tick(&db, &p), Mesure::Lue(0));
        assert_eq!(r5_cecite_ouverte(&db, id), 0, "épisode de cécité résolu");
        assert_eq!(r5_abandons(&db, id), 0);
        let c = db.lock();
        assert!(consigner_evaluation_reussie(&c, id, now(), 0.0), "écritures passées : true");
    }
}
