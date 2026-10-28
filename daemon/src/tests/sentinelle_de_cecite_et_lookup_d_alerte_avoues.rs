// =====================================================================================
// `P10.32-x` (détection) et `P10.33-h` (sorties) — CE QUE LA SENTINELLE DES RÈGLES ÉTEINTES, LES ÉCRITURES D'APRÈS
// L'ALERTE D'UNE RÈGLE SIMPLE ET LE CANAL LOOKUP N'ÉCRIVENT PAS SE DIT ET SE COMPTE ; UNE PHRASE DE JOURNAL OU DE
// SURFACE NE DIT PLUS PLUS QUE CE QUI A EU LIEU.
//
// VU sur 5100db29 (re-mesuré par le lot) :
//   * `run_due_rules` jetait l'issue de `consigner_abandon` (`let _ =`) : compte refusé, compte non relu, alerte de
//     cécité refusée au seuil (`alerte_posee: false`) ne laissaient de trace qu'au journal — et la relecture du compte
//     (`.ok().map(..)?`) confondait « règle disparue » (rien à poser) et « lecture ratée » (sans une ligne de journal) ;
//     un incrément sans effet (`Ok(0)`, déclencheur `RAISE(IGNORE)`) posait l'alerte sur le compte d'AVANT ;
//   * `run_due_rules` jetait encore quatre écritures (`population_vue`, `last_fired`, le rafraîchissement de l'alerte
//     ouverte, la résolution au retour sous le seuil) ; les lignes de journal des refus n'avaient aucun témoin ;
//   * `bilan_de_tick` (contrat de `Mesure::Lue`) et la surface d'état disaient « non évalués » d'un compte qui recouvre
//     aussi les règles évaluées dont l'alerte ou l'état a été refusé ;
//   * `compter_un_tick_aveugle` écrivait « aucun geste de ce balayage ce tour-ci » pour le marqueur du dispatch, alors
//     que l'alerte était partie ;
//   * `write_alert_to_lookup` faisait deux `INSERT OR REPLACE` hors transaction : `lookup_meta` refusé laissait
//     `lookup_kv` écrit (une moitié), et un `Ok(0)` passait pour un envoi pris.
//
// ATTENDU, tenu ici : refus fabriqués par déclencheurs (`RAISE(ABORT)`, `RAISE(IGNORE)`), une lecture rendue illisible
// SEULE (`interval_s` en BLOB), une règle effacée par un déclencheur APRÈS l'incrément. Chaque issue de la consignation
// a son témoin direct (point d'entrée de l'ordonnanceur : `issue_de_consigner_abandon`) ; les comptes par genre et
// chaque ligne de journal (égalité de la ligne ENTIÈRE) sont lus dans un sous-processus, où seul ce témoin tourne ;
// les écritures d'après l'alerte comptent la règle UNE fois ; le lookup est tout ou rien, `Ok(0)` compris, et sous une
// transaction étrangère il n'annule que ses propres écritures ; la phrase du marqueur du dispatch et celles de la
// surface sont comparées à des LITTÉRAUX du témoin.
//
// MUTANTS (posés sous cfg!(test) par variable de mutation, retirés avant le commit), chacun rouge sur son témoin : AV7_RELU_OK, AV7_RELU_MUET,
// AV7_ABSENTE_DEFAUT, AV7_SANS_EFFET, AV7_SEUIL_STRICT, AV7_SEUIL_IGNORE (`detection_aveugle`) ; AV7_ISSUE_JETEE,
// AV7_POPVUE_MUETTE, AV7_POPVUE_SANS_LIGNE, AV7_LASTFIRED_MUET, AV7_RAFRAICHI_MUET, AV7_RESOLUTION_MUETTE,
// AV7_DOUBLE_COMPTE (`run_due_rules`) ; AV7_PHRASE_COMMUNE, AV7_PHRASE_TOUJOURS (sans objet depuis P10.33-h), AV7_SENTINELLE_NON_SERVIE
// (`metrics`) ; AV7_SENS_ANCIEN, AV7_SENS_ANCIEN_PASSES (`bilan_de_tick`) ; AV7_LOOKUP_SANS_POINT, AV7_LOOKUP_OK0,
// AV7_LOOKUP_ROLLBACK_TOTAL, AV7_LOOKUP_SANS_RELEASE (`write_alert_to_lookup`).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : un refus par verrou, disque plein ou base en lecture seule (même `Err`, non
// fabriqué) ; une annulation (`ROLLBACK TO`) elle-même refusée dans le lookup (laissée à la sonde des transactions
// orphelines) ; un `Ok(0)` sur `population_vue`/`last_fired` (règle supprimée pendant le tick, non jugé comme la remise
// à zéro voisine) ; l'absence de pas de reprise pendant un refus durable (réévaluée et dite à chaque tick, délibéré).
// =====================================================================================
mod sentinelle_de_cecite_et_lookup_d_alerte_avoues {
    use super::*;
    use crate::detection_aveugle::{
        cle_dedup, issue_de_consigner_abandon, seuil_d_abandons_consecutifs, AbandonConsigne, AbandonDEvaluation,
        IssueDeConsignation, DEFAUT_ALERTE_DE_CECITE_NON_ECRITE, DEFAUT_COMPTE_NON_ECRIT, DEFAUT_COMPTE_NON_RELU,
    };
    use crate::handlers::alerting::write_alert_to_lookup;
    use crate::handlers::notifiers::dispatch_notifications;
    use crate::mesure_environnement::Mesure;

    const AV7_INTERVALLE_S: i64 = 600;
    const AV7_SQL_ABSENTE: &str = "SELECT x FROM table_absente_av7";
    /// La cause que rusqlite rend pour la relecture d'un `interval_s` posé en BLOB (colonne 1 de la relecture).
    const AV7_CAUSE_BLOB: &str = "Invalid column type Blob at index: 1, name: interval_s";

    fn av7_base(tag: &str) -> (crate::tmp_possede::TmpPossede, Arc<Mutex<Connection>>, String) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(&format!("av7-{tag}"));
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
    fn av7_regle(db: &Arc<Mutex<Connection>>, nom: &str, sql: &str) -> i64 {
        let c = db.lock();
        c.execute(
            "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) VALUES(?1,1,?2,0,'>',1,3,?3,3600)",
            params![nom, sql, AV7_INTERVALLE_S],
        )
        .unwrap();
        c.last_insert_rowid()
    }

    fn av7_sql(db: &Arc<Mutex<Connection>>, sql: &str) {
        db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn av7_tick(db: &Arc<Mutex<Connection>>, p: &str) -> Mesure<u32> {
        av7_sql(db, "UPDATE rule SET last_run=NULL");
        run_due_rules(db, p)
    }

    fn av7_n(db: &Arc<Mutex<Connection>>, sql: &str) -> i64 {
        db.lock().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn av7_seuil() -> i64 {
        i64::from(seuil_d_abandons_consecutifs(AV7_INTERVALLE_S))
    }

    fn av7_issue(db: &Arc<Mutex<Connection>>, id: i64) -> IssueDeConsignation {
        let c = db.lock();
        issue_de_consigner_abandon(&c, id, "av7-aveugle", 3, now(), &AbandonDEvaluation::compilation_refusee("x"))
    }

    /// Une alerte ouverte posée par la fixture (`rule` et `dedup` donnés).
    fn av7_alerte_ouverte(db: &Arc<Mutex<Connection>>, rule: &str, dedup: &str) {
        db.lock()
            .execute(
                "INSERT INTO alert(ts,rule,severity,title,detail,dedup,status,mitre,sources) VALUES(?1,?2,3,'av7','av7',?3,'new','','')",
                params![now() - 100, rule, dedup],
            )
            .unwrap();
    }

    // ---------------------------------------------------------------- l'issue de la consignation, par issue

    /// Règle absente (identifiant inconnu, puis règle effacée par un déclencheur APRÈS l'incrément) : `RegleAbsente`,
    /// pas un défaut, rien de posé. MUTATION : `AV7_ABSENTE_DEFAUT` (relecture sans ligne lue comme non relue).
    #[test]
    fn av7_issue_regle_absente_n_est_pas_un_defaut() {
        let (_t, db, _p) = av7_base("absente");
        let issue = av7_issue(&db, 424242);
        assert_eq!(issue, IssueDeConsignation::RegleAbsente, "identifiant inconnu : rien à poser");
        assert_eq!(issue.defaut_de_la_sentinelle(), None, "une règle disparue n'est pas un défaut de la sentinelle");
        let id = av7_regle(&db, "av7-effacee", AV7_SQL_ABSENTE);
        av7_sql(&db, "CREATE TRIGGER av7_efface AFTER UPDATE OF abandons_consecutifs ON rule BEGIN DELETE FROM rule WHERE id=NEW.id; END;");
        let issue = av7_issue(&db, id);
        assert_eq!(issue, IssueDeConsignation::RegleAbsente, "effacée après l'incrément (écrit : Ok(1)) : relecture sans ligne");
        assert_eq!(issue.defaut_de_la_sentinelle(), None);
        assert_eq!(av7_n(&db, "SELECT COUNT(*) FROM alert"), 0, "rien n'est posé");
    }

    /// Incrément refusé (`RAISE(ABORT)`) : `CompteNonEcrit`, défaut `compte_non_ecrit`, compte inchangé, rien de posé.
    #[test]
    fn av7_issue_compte_refuse_est_un_defaut() {
        let (_t, db, _p) = av7_base("cpt-refuse");
        let id = av7_regle(&db, "av7-cpt", AV7_SQL_ABSENTE);
        av7_sql(&db, &format!("UPDATE rule SET abandons_consecutifs={} WHERE id={id}", av7_seuil()));
        av7_sql(&db, "CREATE TRIGGER av7_cpt BEFORE UPDATE OF abandons_consecutifs ON rule BEGIN SELECT RAISE(ABORT,'compte refusé av7'); END;");
        let issue = av7_issue(&db, id);
        assert_eq!(issue, IssueDeConsignation::CompteNonEcrit);
        assert_eq!(issue.defaut_de_la_sentinelle(), Some(DEFAUT_COMPTE_NON_ECRIT));
        assert_eq!(av7_n(&db, "SELECT COUNT(*) FROM alert"), 0);
    }

    /// Incrément SANS EFFET (`RAISE(IGNORE)`, `Ok(0)`) sur une règle présente dont le compte est DÉJÀ au seuil : la forme
    /// d'avant relisait ce compte et posait l'alerte dessus. `CompteNonEcrit`, rien de posé. MUTATION : `AV7_SANS_EFFET`.
    #[test]
    fn av7_issue_compte_sans_effet_au_seuil_ne_pose_rien() {
        let (_t, db, _p) = av7_base("cpt-ignore");
        let id = av7_regle(&db, "av7-ignore", AV7_SQL_ABSENTE);
        av7_sql(&db, &format!("UPDATE rule SET abandons_consecutifs={} WHERE id={id}", av7_seuil()));
        av7_sql(&db, "CREATE TRIGGER av7_ignore BEFORE UPDATE ON rule BEGIN SELECT RAISE(IGNORE); END;");
        let issue = av7_issue(&db, id);
        assert_eq!(issue, IssueDeConsignation::CompteNonEcrit, "aucune ligne écrite sur une règle présente : compte non écrit");
        assert_eq!(issue.defaut_de_la_sentinelle(), Some(DEFAUT_COMPTE_NON_ECRIT));
        assert_eq!(av7_n(&db, "SELECT COUNT(*) FROM alert"), 0, "aucune alerte de cécité sur un compte que la base n'a pas pris");
    }

    /// Relecture illisible SEULE (`interval_s` en BLOB : l'incrément passe, la relecture échoue) : `CompteNonRelu`,
    /// défaut `compte_non_relu`. MUTATION : `AV7_RELU_OK` (lecture ratée rangée sous « règle absente »).
    #[test]
    fn av7_issue_compte_non_relu_est_un_defaut() {
        let (_t, db, _p) = av7_base("cpt-non-relu");
        let id = av7_regle(&db, "av7-relu", AV7_SQL_ABSENTE);
        av7_sql(&db, &format!("UPDATE rule SET interval_s=X'00' WHERE id={id}"));
        let issue = av7_issue(&db, id);
        assert_eq!(issue, IssueDeConsignation::CompteNonRelu);
        assert_eq!(issue.defaut_de_la_sentinelle(), Some(DEFAUT_COMPTE_NON_RELU));
        assert_eq!(av7_n(&db, &format!("SELECT abandons_consecutifs FROM rule WHERE id={id}")), 1, "fixture : l'incrément, lui, est passé");
        assert_eq!(av7_n(&db, "SELECT COUNT(*) FROM alert"), 0);
    }

    /// Alerte de cécité refusée au seuil EXACT (`consecutifs == seuil`) : défaut `alerte_de_cecite_non_ecrite`.
    /// MUTATION : `AV7_SEUIL_STRICT` (`>` au lieu de `>=`).
    #[test]
    fn av7_issue_alerte_de_cecite_refusee_au_seuil_exact_est_un_defaut() {
        let (_t, db, _p) = av7_base("cecite-refusee");
        let id = av7_regle(&db, "av7-cecite", AV7_SQL_ABSENTE);
        let seuil = av7_seuil();
        av7_sql(&db, &format!("UPDATE rule SET abandons_consecutifs={} WHERE id={id}", seuil - 1));
        av7_sql(&db, &format!(
            "CREATE TRIGGER av7_cecite BEFORE INSERT ON alert WHEN NEW.dedup='{}' BEGIN SELECT RAISE(ABORT,'cécité refusée av7'); END;",
            cle_dedup(id)
        ));
        let issue = av7_issue(&db, id);
        let s = u32::try_from(seuil).unwrap();
        assert_eq!(issue, IssueDeConsignation::Consigne(AbandonConsigne { consecutifs: s, seuil: s, alerte_posee: false }));
        assert_eq!(issue.defaut_de_la_sentinelle(), Some(DEFAUT_ALERTE_DE_CECITE_NON_ECRITE));
    }

    /// Sous le seuil (rien à poser) et alerte posée ou déjà ouverte au seuil : aucun défaut. MUTATION : `AV7_SEUIL_IGNORE`
    /// (tout `alerte_posee: false` compté, même sous le seuil).
    #[test]
    fn av7_issue_sous_le_seuil_et_alerte_posee_ne_sont_pas_des_defauts() {
        let (_t, db, _p) = av7_base("sous-seuil");
        let id = av7_regle(&db, "av7-sous", AV7_SQL_ABSENTE);
        let seuil = u32::try_from(av7_seuil()).unwrap();
        let issue = av7_issue(&db, id);
        assert_eq!(issue, IssueDeConsignation::Consigne(AbandonConsigne { consecutifs: 1, seuil, alerte_posee: false }));
        assert_eq!(issue.defaut_de_la_sentinelle(), None, "sous le seuil : rien à poser, pas un défaut");
        av7_sql(&db, &format!("UPDATE rule SET abandons_consecutifs={} WHERE id={id}", seuil - 1));
        let issue = av7_issue(&db, id);
        assert_eq!(issue, IssueDeConsignation::Consigne(AbandonConsigne { consecutifs: seuil, seuil, alerte_posee: true }));
        assert_eq!(issue.defaut_de_la_sentinelle(), None, "alerte écrite : pas un défaut");
        let issue = av7_issue(&db, id);
        assert_eq!(issue, IssueDeConsignation::Consigne(AbandonConsigne { consecutifs: seuil + 1, seuil, alerte_posee: true }));
        assert_eq!(issue.defaut_de_la_sentinelle(), None, "déjà ouverte (Ok(0)) : pas un défaut");
        assert_eq!(av7_n(&db, "SELECT COUNT(*) FROM alert"), 1);
    }

    // ---------------------------------------------------------------- run_due_rules : les écritures d'après l'alerte

    /// Chaque écriture d'après l'alerte, refusée SEULE, compte la règle (`Lue(1)`) ; deux refus pour la même règle font
    /// UN abandon ; sans refus, `Lue(0)` et les écritures passent. MUTATIONS : `AV7_POPVUE_MUETTE`,
    /// `AV7_LASTFIRED_MUET`, `AV7_RAFRAICHI_MUET`, `AV7_RESOLUTION_MUETTE` (refus non compté), `AV7_DOUBLE_COMPTE`.
    #[test]
    fn av7_ecritures_apres_l_alerte_refusees_comptent_la_regle_une_fois() {
        // `population_vue` refusée : l'alerte et `last_fired` sont écrits, `population_vue` reste celle d'avant.
        let (_t, db, p) = av7_base("popvue");
        let id = av7_regle(&db, "av7-tire", "SELECT 5");
        av7_sql(&db, &format!("UPDATE rule SET population_vue='avant-av7' WHERE id={id}"));
        av7_sql(&db, "CREATE TRIGGER av7_pop BEFORE UPDATE OF population_vue ON rule BEGIN SELECT RAISE(ABORT,'population refusée av7'); END;");
        assert_eq!(av7_tick(&db, &p), Mesure::Lue(1), "population_vue refusée : la règle est comptée");
        assert_eq!(av7_n(&db, "SELECT COUNT(*) FROM alert WHERE rule LIKE 'rule.%' AND status='new'"), 1, "l'alerte de tir est écrite");
        assert_eq!(av7_n(&db, &format!("SELECT COUNT(*) FROM rule WHERE id={id} AND last_fired IS NOT NULL AND population_vue='avant-av7'")), 1);

        // `last_fired` refusé : `population_vue` est réécrite (vide : aucune population déclarée), `last_fired` reste NULL.
        let (_t, db, p) = av7_base("lastfired");
        let id = av7_regle(&db, "av7-tire", "SELECT 5");
        av7_sql(&db, &format!("UPDATE rule SET population_vue='avant-av7' WHERE id={id}"));
        av7_sql(&db, "CREATE TRIGGER av7_lf BEFORE UPDATE OF last_fired ON rule BEGIN SELECT RAISE(ABORT,'last_fired refusé av7'); END;");
        assert_eq!(av7_tick(&db, &p), Mesure::Lue(1), "last_fired refusé : la règle est comptée");
        assert_eq!(av7_n(&db, &format!("SELECT COUNT(*) FROM rule WHERE id={id} AND last_fired IS NULL AND population_vue=''")), 1);

        // Rafraîchissement de l'alerte ouverte refusé.
        let (_t, db, p) = av7_base("rafraichi");
        av7_regle(&db, "av7-tire", "SELECT 5");
        av7_sql(&db, "CREATE TRIGGER av7_raf BEFORE UPDATE OF current_value ON alert BEGIN SELECT RAISE(ABORT,'rafraîchissement refusé av7'); END;");
        assert_eq!(av7_tick(&db, &p), Mesure::Lue(1), "rafraîchissement refusé : la règle est comptée");
        assert_eq!(av7_n(&db, "SELECT COUNT(*) FROM alert WHERE rule LIKE 'rule.%' AND status='new'"), 1, "fixture : l'alerte est écrite");

        // Résolution au retour sous le seuil refusée : l'alerte reste ouverte, sa clé tenue.
        let (_t, db, p) = av7_base("resolution");
        let id = av7_regle(&db, "av7-calme", "SELECT 0");
        av7_alerte_ouverte(&db, &format!("rule.{id}"), &format!("rule-{id}"));
        av7_sql(&db, &format!(
            "CREATE TRIGGER av7_res BEFORE UPDATE OF status ON alert WHEN OLD.dedup='rule-{id}' BEGIN SELECT RAISE(ABORT,'résolution refusée av7'); END;"
        ));
        assert_eq!(av7_tick(&db, &p), Mesure::Lue(1), "résolution refusée : la règle est comptée");
        assert_eq!(av7_n(&db, &format!("SELECT COUNT(*) FROM alert WHERE dedup='rule-{id}' AND status='new'")), 1, "fixture : l'alerte reste ouverte");
        av7_sql(&db, "DROP TRIGGER av7_res;");
        assert_eq!(av7_tick(&db, &p), Mesure::Lue(0), "contrôle : trigger retiré, rien d'abandonné");
        assert_eq!(av7_n(&db, &format!("SELECT COUNT(*) FROM alert WHERE status='resolved' AND dedup IS NULL AND rule='rule.{id}'")), 1, "contrôle : résolue");

        // Deux refus pour la même règle : UN abandon.
        let (_t, db, p) = av7_base("deux");
        av7_regle(&db, "av7-tire", "SELECT 5");
        av7_sql(&db, "CREATE TRIGGER av7_pop BEFORE UPDATE OF population_vue ON rule BEGIN SELECT RAISE(ABORT,'population refusée av7'); END;");
        av7_sql(&db, "CREATE TRIGGER av7_lf BEFORE UPDATE OF last_fired ON rule BEGIN SELECT RAISE(ABORT,'last_fired refusé av7'); END;");
        assert_eq!(av7_tick(&db, &p), Mesure::Lue(1), "deux écritures refusées pour une règle : un abandon");

        // Contrôle nominal : tir puis rafraîchissement, `Lue(0)`, `last_fired` et `population_vue` écrits.
        let (_t, db, p) = av7_base("nominal");
        let id = av7_regle(&db, "av7-tire", "SELECT 5");
        av7_sql(&db, &format!("UPDATE rule SET population_vue='avant-av7' WHERE id={id}"));
        assert_eq!(av7_tick(&db, &p), Mesure::Lue(0));
        assert_eq!(av7_tick(&db, &p), Mesure::Lue(0), "épisode ouvert, rafraîchi : rien d'abandonné");
        assert_eq!(av7_n(&db, &format!("SELECT COUNT(*) FROM rule WHERE id={id} AND last_fired IS NOT NULL AND population_vue=''")), 1);
    }

    // ---------------------------------------------------------------- run_due_rules : comptes et journal (sous-processus)

    const AV7_ENFANT_SENTINELLE: &str = "AV7_ENFANT_SENTINELLE_ET_JOURNAL";
    const AV7_PHASE: &str = "AV7-PHASE:";
    const AV7_BILAN: &str = "AV7-BILAN:";

    /// Les lignes `[detection]` attendues d'une phase, pour la règle `id` (seuil `s`), à l'égalité près.
    fn av7_lignes_attendues(nom: &str, id: i64, s: i64) -> Vec<String> {
        let t = format!("[detection] WARN règle #{id} : ");
        match nom {
            "cecite_refusee" => vec![format!("{t}l'alerte de cécité n'a pas pu être écrite (cécité refusée av7) — {s} abandons consécutifs comptés, elle sera reposée au prochain abandon")],
            "compte_refuse" => vec![format!("{t}le compte de ses abandons consécutifs n'a pas pu être écrit (compte refusé av7) — aucune alerte de cécité posée sur un compte non écrit")],
            "compte_sans_effet" => vec![format!("{t}le compte de ses abandons consécutifs n'a pas été écrit (0 ligne(s) écrite(s) au lieu d'une) — aucune alerte de cécité posée sur un compte non écrit")],
            "compte_non_relu" => vec![format!("{t}le compte de ses abandons consécutifs n'a pas pu être relu ({AV7_CAUSE_BLOB}) — aucune alerte de cécité posée sur un compte non lu")],
            "tir_refuse" => vec![format!("{t}l'alerte de son tir n'a pas pu être écrite (tir refusé av7) — la règle est comptée abandonnée ; ni last_fired, ni last_run, ni son compte d'abandons ne sont posés : elle est due dès le tick suivant")],
            "population_refusee" => vec![format!("{t}les sources vues hors de sa population n'ont pas pu être écrites (population refusée av7) — l'alerte de son tir est écrite, la règle est comptée abandonnée")],
            "last_fired_refuse" => vec![format!("{t}l'instant de son tir (last_fired) n'a pas pu être écrit (last_fired refusé av7) — l'alerte de son tir est écrite, la règle est comptée abandonnée")],
            "rafraichissement_refuse" => vec![format!("{t}son alerte ouverte n'a pas pu être rafraîchie (rafraîchissement refusé av7) — valeur, sévérité, imputation et re-notification restent celles d'avant, la règle est comptée abandonnée")],
            "resolution_refusee" => vec![format!("{t}son alerte n'a pas pu être résolue au retour sous le seuil (résolution refusée av7) — elle reste ouverte et sa clé n'est pas libérée, la règle est comptée abandonnée")],
            "remise_a_zero_refusee" => vec![format!("{t}son évaluation réussie n'a pas pu être écrite (remise à zéro refusée av7) — compte d'abandons non remis à zéro")],
            "resolution_de_cecite_refusee" => vec![format!("{t}son alerte de cécité n'a pas pu être résolue (résolution de cécité refusée av7) — elle reste ouverte sur une règle évaluée")],
            "regle_disparue" | "sous_le_seuil" | "cecite_posee" | "nominal_tir" => Vec::new(),
            autre => panic!("phase inconnue du témoin : {autre}"),
        }
    }

    /// Les phases et ce qu'elles rendent : (nom, bilan, écarts [total, compte_non_ecrit, compte_non_relu,
    /// alerte_de_cecite_non_ecrite]). Les comptes de défauts ne bougent QUE sur les quatre défauts de la sentinelle.
    const AV7_PHASES: [(&str, &str, &str); 15] = [
        ("cecite_refusee", "Lue(1)", "1,0,0,1"),
        ("compte_refuse", "Lue(1)", "1,1,0,0"),
        ("compte_sans_effet", "Lue(1)", "1,1,0,0"),
        ("compte_non_relu", "Lue(1)", "1,0,1,0"),
        ("regle_disparue", "Lue(1)", "0,0,0,0"),
        ("sous_le_seuil", "Lue(1)", "0,0,0,0"),
        ("cecite_posee", "Lue(1)", "0,0,0,0"),
        ("tir_refuse", "Lue(1)", "0,0,0,0"),
        ("population_refusee", "Lue(1)", "0,0,0,0"),
        ("last_fired_refuse", "Lue(1)", "0,0,0,0"),
        ("rafraichissement_refuse", "Lue(1)", "0,0,0,0"),
        ("resolution_refusee", "Lue(1)", "0,0,0,0"),
        ("remise_a_zero_refusee", "Lue(1)", "0,0,0,0"),
        ("resolution_de_cecite_refusee", "Lue(1)", "0,0,0,0"),
        ("nominal_tir", "Lue(0)", "0,0,0,0"),
    ];

    /// Prépare la base d'une phase et rend (tmp, base, chemin, identifiant de la règle).
    fn av7_preparer(nom: &str) -> (crate::tmp_possede::TmpPossede, Arc<Mutex<Connection>>, String, i64) {
        let (t, db, p) = av7_base(&format!("enfant-{nom}"));
        let seuil = av7_seuil();
        let sql = match nom {
            "tir_refuse" | "population_refusee" | "last_fired_refuse" | "rafraichissement_refuse" | "nominal_tir" => "SELECT 5",
            "resolution_refusee" | "remise_a_zero_refusee" | "resolution_de_cecite_refusee" => "SELECT 0",
            _ => AV7_SQL_ABSENTE,
        };
        let id = av7_regle(&db, &format!("av7-{nom}"), sql);
        let declencheur = |quand: &str, cause: &str| {
            av7_sql(&db, &format!("CREATE TRIGGER av7_t {quand} BEGIN SELECT RAISE(ABORT,'{cause}'); END;"));
        };
        match nom {
            "cecite_refusee" => {
                av7_sql(&db, &format!("UPDATE rule SET abandons_consecutifs={} WHERE id={id}", seuil - 1));
                declencheur(&format!("BEFORE INSERT ON alert WHEN NEW.dedup='{}'", cle_dedup(id)), "cécité refusée av7");
            }
            "compte_refuse" => declencheur("BEFORE UPDATE OF abandons_consecutifs ON rule", "compte refusé av7"),
            "compte_sans_effet" => {
                av7_sql(&db, &format!("UPDATE rule SET abandons_consecutifs={seuil} WHERE id={id}"));
                av7_sql(&db, "CREATE TRIGGER av7_t BEFORE UPDATE OF abandons_consecutifs ON rule BEGIN SELECT RAISE(IGNORE); END;");
            }
            "compte_non_relu" => av7_sql(&db, &format!("UPDATE rule SET interval_s=X'00' WHERE id={id}")),
            "regle_disparue" => av7_sql(&db, "CREATE TRIGGER av7_t AFTER UPDATE OF abandons_consecutifs ON rule BEGIN DELETE FROM rule WHERE id=NEW.id; END;"),
            "cecite_posee" => av7_sql(&db, &format!("UPDATE rule SET abandons_consecutifs={} WHERE id={id}", seuil - 1)),
            "tir_refuse" => declencheur("BEFORE INSERT ON alert WHEN NEW.rule LIKE 'rule.%'", "tir refusé av7"),
            "population_refusee" => declencheur("BEFORE UPDATE OF population_vue ON rule", "population refusée av7"),
            "last_fired_refuse" => declencheur("BEFORE UPDATE OF last_fired ON rule", "last_fired refusé av7"),
            "rafraichissement_refuse" => declencheur("BEFORE UPDATE OF current_value ON alert", "rafraîchissement refusé av7"),
            "resolution_refusee" => {
                av7_alerte_ouverte(&db, &format!("rule.{id}"), &format!("rule-{id}"));
                declencheur(&format!("BEFORE UPDATE OF status ON alert WHEN OLD.dedup='rule-{id}'"), "résolution refusée av7");
            }
            "remise_a_zero_refusee" => declencheur("BEFORE UPDATE OF last_value ON rule", "remise à zéro refusée av7"),
            "resolution_de_cecite_refusee" => {
                av7_alerte_ouverte(&db, &format!("heartbeat.regle-aveugle.{id}"), &cle_dedup(id));
                declencheur(&format!("BEFORE UPDATE OF status ON alert WHEN OLD.dedup='{}'", cle_dedup(id)), "résolution de cécité refusée av7");
            }
            _ => {}
        }
        (t, db, p, id)
    }

    fn av7_comptes() -> [u64; 4] {
        [
            crate::metrics::DEFAUTS_DE_LA_SENTINELLE_DE_CECITE_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
            crate::metrics::defaut_de_la_sentinelle_de_cecite_de(DEFAUT_COMPTE_NON_ECRIT),
            crate::metrics::defaut_de_la_sentinelle_de_cecite_de(DEFAUT_COMPTE_NON_RELU),
            crate::metrics::defaut_de_la_sentinelle_de_cecite_de(DEFAUT_ALERTE_DE_CECITE_NON_ECRITE),
        ]
    }

    /// Dans un sous-processus où seul ce témoin tourne : chaque phase passe par `run_due_rules`, son bilan et l'écart
    /// des comptes par genre sont exacts, ses lignes `[detection]` sont exactement celles attendues (ligne entière) ;
    /// puis `/api/metrics` et `/metrics` servent la somme. MUTATIONS : `AV7_ISSUE_JETEE` (comptes à zéro),
    /// `AV7_RELU_MUET` et `AV7_POPVUE_SANS_LIGNE` (ligne manquante), `AV7_SENTINELLE_NON_SERVIE`, et chacune des
    /// mutations de l'issue (`AV7_RELU_OK`, `AV7_ABSENTE_DEFAUT`, `AV7_SANS_EFFET`, `AV7_SEUIL_*`).
    #[test]
    fn av7_run_due_rules_compte_les_defauts_et_dit_chaque_ecriture_refusee() {
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(AV7_ENFANT_SENTINELLE).is_ok() {
            for (nom, _, _) in AV7_PHASES {
                let (_t, db, p, id) = av7_preparer(nom);
                let avant = av7_comptes();
                eprintln!("{AV7_PHASE}{nom}");
                let bilan = av7_tick(&db, &p);
                let apres = av7_comptes();
                let ecarts: Vec<String> = avant.iter().zip(apres.iter()).map(|(a, b)| (b - a).to_string()).collect();
                println!("{AV7_BILAN}{nom}:{id}:{bilan:?}:{}", ecarts.join(","));
            }
            eprintln!("{AV7_PHASE}fin");
            let conn = test_db();
            let j = crate::gather_json(&conn, "/nonexistent-spool", "", &crate::handlers::system::VersionDeSchema::Lue(1), 80);
            println!(
                "AV7-JSON:{}",
                json!({ "total": j["scheduler"]["defauts_de_la_sentinelle_de_cecite_total"], "genres": j["scheduler"]["defauts_de_la_sentinelle_de_cecite"] })
            );
            let prom = crate::gather_prom(&conn, "/nonexistent-spool", "", &crate::handlers::system::VersionDeSchema::Lue(1), 80);
            for l in prom.lines().filter(|l| l.contains("plume_scheduler_defauts_de_la_sentinelle_de_cecite_total")) {
                println!("AV7-PROM:{l}");
            }
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::sentinelle_de_cecite_et_lookup_d_alerte_avoues::av7_run_due_rules_compte_les_defauts_et_dit_chaque_ecriture_refusee",
            ])
            .env(AV7_ENFANT_SENTINELLE, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let rendus: Vec<(String, i64, String, String)> = stdout
            .lines()
            .filter_map(|l| l.split_once(AV7_BILAN).map(|(_, r)| r))
            .map(|r| {
                let c: Vec<&str> = r.splitn(4, ':').collect();
                (c[0].to_string(), c[1].parse().expect("identifiant"), c[2].to_string(), c[3].to_string())
            })
            .collect();
        assert_eq!(rendus.len(), AV7_PHASES.len(), "contrôle : chaque phase a rendu son bilan : {stdout}");
        let seuil = av7_seuil();
        for ((nom, id, bilan, ecarts), (nom_attendu, bilan_attendu, ecarts_attendus)) in rendus.iter().zip(AV7_PHASES.iter()) {
            assert_eq!(nom, nom_attendu, "ordre des phases");
            assert_eq!((bilan.as_str(), ecarts.as_str()), (*bilan_attendu, *ecarts_attendus), "phase {nom} : bilan et comptes par genre");
            let debut = stderr.split_once(&format!("{AV7_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(AV7_PHASE).map(|(c, _)| c).unwrap_or(debut);
            let lignes: Vec<String> = corps.lines().filter(|l| l.starts_with("[detection]")).map(str::to_string).collect();
            assert_eq!(lignes, av7_lignes_attendues(nom, *id, seuil), "phase {nom} : les lignes de journal, entières");
        }
        let json_servi = stdout.lines().find_map(|l| l.strip_prefix("AV7-JSON:")).unwrap_or_else(|| panic!("contrôle : JSON servi : {stdout}"));
        let servi: Value = serde_json::from_str(json_servi).expect("JSON servi");
        assert_eq!(
            servi,
            json!({ "total": 4, "genres": { "compte_non_ecrit": 2, "compte_non_relu": 1, "alerte_de_cecite_non_ecrite": 1 } }),
            "la somme des phases, servie sous /api/metrics"
        );
        let prom: Vec<&str> = stdout.lines().filter_map(|l| l.strip_prefix("AV7-PROM:")).collect();
        assert_eq!(
            prom,
            vec![
                "# HELP plume_scheduler_defauts_de_la_sentinelle_de_cecite_total Règles abandonnées dont la sentinelle n'a pas pu consigner l'abandon ou poser l'alerte de cécité au seuil (P10.32-x ; ventilation par genre dans /api/metrics scheduler.defauts_de_la_sentinelle_de_cecite)",
                "# TYPE plume_scheduler_defauts_de_la_sentinelle_de_cecite_total counter",
                "plume_scheduler_defauts_de_la_sentinelle_de_cecite_total 4",
            ],
            "la série Prometheus : {stdout}"
        );
    }

    // ---------------------------------------------------------------- la surface : ce qu'un abandon recouvre

    /// La surface dit le contrat de `Lue(n)` en entier (non évalués, OU évalués sans que l'alerte ou l'état soit écrit).
    /// MUTATIONS : `AV7_SENS_ANCIEN` (composant), `AV7_SENS_ANCIEN_PASSES` (passes hors composant).
    #[test]
    fn av7_la_surface_dit_ce_qu_un_abandon_recouvre() {
        assert_eq!(
            crate::bilan_de_tick::etat_de_surface("green", "actif".to_string(), Some(&Mesure::Lue(2))),
            (
                "yellow",
                "actif ; 2 élément(s) dû(s) ABANDONNÉ(S) au dernier tick (non évalués, ou évalués sans que leur alerte ou \
                 leur état soit écrit ; re-tentés à leur prochaine échéance)"
                    .to_string()
            )
        );
        assert_eq!(
            crate::bilan_de_tick::etat_des_passes_orphelines(&[("av7_passe", Mesure::Lue(3))]),
            (
                "yellow",
                "élément(s) dû(s) ABANDONNÉ(S) au dernier passage (av7_passe : 3) — non évalués, ou évalués sans que leur \
                 alerte ou leur état soit écrit ; re-tentés à leur prochaine échéance"
                    .to_string()
            )
        );
    }

    // ---------------------------------------------------------------- `P10.33-h` : le marqueur du dispatch et les `# HELP`

    const AV7_ENFANT_DISPATCH: &str = "AV7_ENFANT_PHRASE_DU_MARQUEUR";
    /// INVERSÉ par `P10.33-h` (vague AW) : la phrase disait « l'alerte en cours est traitée (envoyée ou silencée) […] les
    /// suivantes attendent le tour suivant » ; le marqueur est désormais écrit avant tout envoi, et les suivantes sont
    /// traitées.
    const AV7_ALERTE_DU_MARQUEUR: i64 = 7741;
    const AV7_PHRASE_MARQUEUR: &str = "[plume] dispatch : alerte 7741 : marqueur `notified` NON ÉCRIT, rien n'est envoyé pour \
         elle ce tour-ci ; elle reste à notifier et sera retentée au tour suivant, les alertes suivantes de ce tour sont \
         traitées : marqueur refusé av7";
    const AV7_PHRASE_AVEUGLE: &str = "[plume] balayage de fond AVEUGLE (dispatch_alerts) : aucun geste de ce balayage ce tour-ci : liste refusée av7";
    const AV7_AIDES: [&str; 2] = [
        "# HELP plume_scheduler_ticks_aveugles_total Tours de balayage de fond suspendus ou interrompus : liste de travail non lue \
         (rien fait ce tour-ci), marqueur d'escalade refusé après la notification (le tour s'arrête là), ou marqueur d'alerte \
         refusé avant tout envoi (rien n'est envoyé pour elle, les suivantes sont traitées) (P10.7-f, P10.33-h ; ventilation \
         par balayage avec la dernière cause dans /api/metrics scheduler.ticks_aveugles)",
        "# HELP plume_scheduler_av7_passe_abandons Éléments dus ABANDONNÉS au dernier passage de « av7_passe » (non évalués, \
         ou évalués sans que leur alerte ou leur état soit écrit)",
    ];

    /// Dans un sous-processus : le marqueur `notified` refusé dit sa phrase (rien n'est parti : `P10.33-h`, vague AW, le
    /// marqueur précède les envois — INVERSÉ, l'alerte partait avant), jamais « aucun geste de ce balayage » ; un autre
    /// balayage garde la phrase commune ; les `# HELP` réécrits sont servis tels quels.
    /// MUTATIONS de la vague AV (`AV7_PHRASE_COMMUNE`, `AV7_PHRASE_TOUJOURS`) : sans objet depuis `P10.33-h` (vague AW), le
    /// marqueur a sa propre fonction et la branche qui choisissait la phrase est supprimée ; les mutants du marqueur sont
    /// ceux de `dispatch_marqueur_avant_envoi_et_tenant_du_tour` (MENTION_MARQUEUR, MARQUEUR_MUET…).
    #[test]
    fn av7_le_marqueur_du_dispatch_refuse_ne_se_dit_pas_sans_geste() {
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(AV7_ENFANT_DISPATCH).is_ok() {
            eprintln!("{AV7_PHASE}marqueur");
            let conn = test_db();
            conn.execute_batch("DELETE FROM alert; DELETE FROM notifier;").unwrap();
            conn.execute(
                "INSERT INTO alert(id,ts,rule,severity,title,detail,status,mitre,sources,host) VALUES(?1,?2,'r.av7',3,'A','','new','','','192.0.2.41')",
                params![AV7_ALERTE_DU_MARQUEUR, now()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('L','lookup',1,'',0,'{\"lookup\":\"av7_marqueur\",\"key_field\":\"host\"}')",
                [],
            )
            .unwrap();
            conn.execute_batch("CREATE TRIGGER av7_marqueur BEFORE UPDATE OF notified ON alert BEGIN SELECT RAISE(ABORT,'marqueur refusé av7'); END;").unwrap();
            let db = Arc::new(Mutex::new(conn));
            dispatch_notifications(&db);
            let pris: i64 = db.lock().query_row("SELECT COUNT(*) FROM lookup_kv WHERE name='av7_marqueur'", [], |r| r.get(0)).unwrap();
            println!("AV7-PRIS:{pris}");
            eprintln!("{AV7_PHASE}autre");
            crate::metrics::compter_un_tick_aveugle("dispatch_alerts", "liste refusée av7");
            eprintln!("{AV7_PHASE}fin");
            crate::bilan_de_tick::publier("av7_passe", Mesure::Lue(2));
            let conn = test_db();
            let prom = crate::gather_prom(&conn, "/nonexistent-spool", "", &crate::handlers::system::VersionDeSchema::Lue(1), 80);
            for l in prom.lines().filter(|l| {
                l.starts_with("# HELP plume_scheduler_ticks_aveugles_total") || l.starts_with("# HELP plume_scheduler_av7_passe_abandons")
            }) {
                println!("AV7-AIDE:{l}");
            }
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::sentinelle_de_cecite_et_lookup_d_alerte_avoues::av7_le_marqueur_du_dispatch_refuse_ne_se_dit_pas_sans_geste",
            ])
            .env(AV7_ENFANT_DISPATCH, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains("AV7-PRIS:0"), "marqueur refusé : l'alerte n'est PAS envoyée au lookup (INVERSÉ, vague AW) : {stdout}");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{AV7_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(AV7_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[plume] balayage de fond") || l.starts_with("[plume] dispatch")).map(str::to_string).collect()
        };
        assert_eq!(phase("marqueur"), vec![AV7_PHRASE_MARQUEUR.to_string()], "le marqueur refusé avant l'envoi : sa phrase, entière, seule");
        assert_eq!(phase("autre"), vec![AV7_PHRASE_AVEUGLE.to_string()], "un autre balayage garde la phrase commune");
        let aides: Vec<&str> = stdout.lines().filter_map(|l| l.strip_prefix("AV7-AIDE:")).collect();
        assert_eq!(aides, AV7_AIDES.to_vec(), "les deux `# HELP` réécrits, servis tels quels : {stdout}");
    }

    // ---------------------------------------------------------------- `P10.33-h` : le lookup, tout ou rien

    fn av7_champs() -> Value {
        json!({ "host": "192.0.2.5", "source": "r.av7", "mitre": "", "severity": 3, "title": "av7", "ts": 1 })
    }

    fn av7_compte(conn: &Connection, table: &str, nom: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table} WHERE name=?1"), params![nom], |r| r.get(0)).unwrap()
    }

    /// `lookup_meta` refusée : rien n'est écrit (la ligne `lookup_kv` est annulée), la cause est celle du moteur, et
    /// l'écrivain revient en autocommit. `lookup_kv` refusée : `lookup_meta` n'est jamais écrite. MUTATION :
    /// `AV7_LOOKUP_SANS_POINT` (deux écritures hors transaction : une moitié reste).
    #[test]
    fn av7_lookup_une_ecriture_refusee_n_en_laisse_aucune() {
        let conn = test_db();
        conn.execute_batch("CREATE TRIGGER av7_meta BEFORE INSERT ON lookup_meta WHEN NEW.name='av7_refuse' BEGIN SELECT RAISE(ABORT,'méta refusée av7'); END;").unwrap();
        let r = write_alert_to_lookup(&conn, "av7_refuse", "host", "192.0.2.5", &av7_champs());
        assert_eq!(r.map_err(|e| e.to_string()), Err("méta refusée av7".to_string()), "la cause du premier refus");
        assert_eq!((av7_compte(&conn, "lookup_kv", "av7_refuse"), av7_compte(&conn, "lookup_meta", "av7_refuse")), (0, 0), "aucune moitié");
        assert!(conn.is_autocommit(), "le point est fermé");
        conn.execute_batch("CREATE TRIGGER av7_kv BEFORE INSERT ON lookup_kv WHEN NEW.name='av7_kv' BEGIN SELECT RAISE(ABORT,'valeur refusée av7'); END;").unwrap();
        let r = write_alert_to_lookup(&conn, "av7_kv", "host", "192.0.2.5", &av7_champs());
        assert_eq!(r.map_err(|e| e.to_string()), Err("valeur refusée av7".to_string()));
        assert_eq!((av7_compte(&conn, "lookup_kv", "av7_kv"), av7_compte(&conn, "lookup_meta", "av7_kv")), (0, 0));
        assert!(conn.is_autocommit());
    }

    /// Une écriture SANS EFFET (`RAISE(IGNORE)`, `Ok(0)`) est un refus : sur `lookup_kv` (méta jamais écrite) comme sur
    /// `lookup_meta` (valeur annulée). MUTATION : `AV7_LOOKUP_OK0`.
    #[test]
    fn av7_lookup_une_ecriture_sans_effet_est_un_refus() {
        let conn = test_db();
        conn.execute_batch("CREATE TRIGGER av7_kv0 BEFORE INSERT ON lookup_kv WHEN NEW.name='av7_kv0' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        let r = write_alert_to_lookup(&conn, "av7_kv0", "host", "192.0.2.5", &av7_champs());
        assert!(matches!(r, Err(rusqlite::Error::StatementChangedRows(0))), "aucune ligne écrite : refus ({r:?})");
        assert_eq!(av7_compte(&conn, "lookup_meta", "av7_kv0"), 0);
        conn.execute_batch("CREATE TRIGGER av7_meta0 BEFORE INSERT ON lookup_meta WHEN NEW.name='av7_meta0' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        let r = write_alert_to_lookup(&conn, "av7_meta0", "host", "192.0.2.5", &av7_champs());
        assert!(matches!(r, Err(rusqlite::Error::StatementChangedRows(0))), "méta sans effet : refus ({r:?})");
        assert_eq!(av7_compte(&conn, "lookup_kv", "av7_meta0"), 0, "la valeur est annulée avec la méta");
        assert!(conn.is_autocommit());
    }

    /// Sous une transaction ÉTRANGÈRE déjà ouverte : un refus n'annule QUE les écritures du lookup ; la transaction de
    /// l'autre geste reste ouverte avec ses écritures, et se valide ensuite. MUTATION : `AV7_LOOKUP_ROLLBACK_TOTAL`.
    #[test]
    fn av7_lookup_sous_une_transaction_etrangere_n_annule_que_ses_ecritures() {
        let conn = test_db();
        conn.execute_batch("CREATE TRIGGER av7_meta BEFORE INSERT ON lookup_meta WHEN NEW.name='av7_refuse' BEGIN SELECT RAISE(ABORT,'méta refusée av7'); END;").unwrap();
        conn.execute_batch("BEGIN; INSERT INTO lookup_kv(name,\"key\",val) VALUES('av7_externe','k','v');").unwrap();
        assert!(write_alert_to_lookup(&conn, "av7_refuse", "host", "192.0.2.5", &av7_champs()).is_err());
        assert!(!conn.is_autocommit(), "la transaction étrangère est toujours ouverte");
        assert_eq!(av7_compte(&conn, "lookup_kv", "av7_externe"), 1, "son écriture est toujours là");
        assert_eq!(av7_compte(&conn, "lookup_kv", "av7_refuse"), 0);
        conn.execute_batch("COMMIT").unwrap();
        assert_eq!(av7_compte(&conn, "lookup_kv", "av7_externe"), 1, "et elle se valide");
    }

    /// Chemin nominal : les deux lignes écrites, le point relâché (autocommit), un remplacement de la même clé passe.
    /// MUTATION : `AV7_LOOKUP_SANS_RELEASE`.
    #[test]
    fn av7_lookup_nominal_ecrit_les_deux_et_relache_le_point() {
        let conn = test_db();
        write_alert_to_lookup(&conn, "av7_ok", "host", "192.0.2.5", &av7_champs()).expect("nominal");
        assert!(conn.is_autocommit(), "le point est relâché");
        assert_eq!((av7_compte(&conn, "lookup_kv", "av7_ok"), av7_compte(&conn, "lookup_meta", "av7_ok")), (1, 1));
        let mut champs = av7_champs();
        champs["title"] = json!("av7-bis");
        write_alert_to_lookup(&conn, "av7_ok", "host", "192.0.2.5", &champs).expect("remplacement de la même clé");
        let val: String = conn.query_row("SELECT val FROM lookup_kv WHERE name='av7_ok'", [], |r| r.get(0)).unwrap();
        assert!(val.contains("av7-bis"), "la valeur remplacée : {val}");
        assert!(conn.is_autocommit());
    }

    /// PAR LE POINT D'ENTRÉE DU DISPATCH : un canal lookup dont la méta est refusée ne laisse aucune moitié dans
    /// `lookup_kv` ; le marqueur garde son sens (l'alerte est traitée). MUTATION : `AV7_LOOKUP_SANS_POINT`.
    #[test]
    fn av7_dispatch_lookup_refuse_ne_laisse_aucune_moitie() {
        let conn = test_db();
        conn.execute_batch("DELETE FROM alert; DELETE FROM notifier;").unwrap();
        conn.execute(
            "INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources,host) VALUES(?1,'r.av7',3,'A','','new','','','192.0.2.42')",
            params![now()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('L','lookup',1,'',0,'{\"lookup\":\"av7_disp\",\"key_field\":\"host\"}')",
            [],
        )
        .unwrap();
        conn.execute_batch("CREATE TRIGGER av7_meta BEFORE INSERT ON lookup_meta WHEN NEW.name='av7_disp' BEGIN SELECT RAISE(ABORT,'méta refusée av7'); END;").unwrap();
        let db = Arc::new(Mutex::new(conn));
        dispatch_notifications(&db);
        let c = db.lock();
        assert_eq!((av7_compte(&c, "lookup_kv", "av7_disp"), av7_compte(&c, "lookup_meta", "av7_disp")), (0, 0), "aucune moitié");
        let marquee: i64 = c.query_row("SELECT notified FROM alert WHERE rule='r.av7'", [], |r| r.get(0)).unwrap();
        assert_eq!(marquee, 1, "le marqueur garde son sens : l'alerte est traitée");
        assert!(c.is_autocommit(), "aucun point laissé ouvert sur l'écrivain");
    }
}
