// =====================================================================================
// `P10.21-n` / `P10.22-q` (reste : `case_add_item` avale chronologie et MTTA chez ses autres appelants de cases.rs) et
// `P10.31-u` (maillons nus de cases.rs) — LA CHRONOLOGIE FAIT PARTIE DU GESTE, LE MAILLON MANQUANT EST AVOUÉ.
//
// LE DÉFAUT, MESURÉ SUR aa19c5fa. Neuf appels de `case_add_item` (qui jette l'issue d'`ajouter_l_element_au_dossier` :
// élément, date du dossier, MTTA `first_response_ts`) suivis de huit `ledger_append` nus : création (`created`,
// `case.create`), assignation (`assign`, `case.assign`), priorité (`priority`), statut (`status`, `case.status`), verdict
// effacé et posé (`disposition`, `case.disposition`), escalade SLA (`sla`, `case.sla_escalate`), archivage et
// désarchivage (`archive`/`unarchive`, `case.archive`/`case.unarchive`). Une chronologie refusée laissait le geste écrit
// et la route en 200/204 (dossier sans chronologie, MTTA non figé) ; l'escalade, marquée puis notifiée sans aveu,
// n'était jamais renvoyée ; un maillon refusé, un succès muet.
//
// DÉCISION PAR DÉFAUT (vague AC, modèle de la fusion de la vague AB) : création, archivage et escalade jouent écriture,
// chronologie comptée et maillon dans UNE transaction (`jouer_le_geste_garde`) ; refus de la chronologie, du `BEGIN` ou
// du `COMMIT` -> geste annulé, 503 EXISTANTS (`CAUSE_DOSSIER_NON_OUVERT`, `CAUSE_ARCHIVAGE_NON_ECRIT`,
// `CAUSE_DESARCHIVAGE_NON_ECRIT`) ; l'escalade suit le chemin du marqueur refusé (envoi avec l'aveu, compté au balayage
// `escalate_overdue_marqueur`, renvoyé). `case_apply_update` : AUCUNE transaction n'englobe la demande (contrat écrit :
// les champs précédents peuvent rester écrits) ; chaque champ attesté est un geste à lui (UPDATE + chronologie +
// maillon) — refusé, le champ est annulé avec sa chronologie, 503 `CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE` existant.
// Un maillon manquant n'annule rien : création 200 avec `registre_sans_maillon` à côté du corps ; mise à jour, archivage
// et désarchivage 200 `{ok, registre_sans_maillon}` au lieu du 204 (forme `geste_fait_sans_trace`) ; escalade : la
// primitive l'a dit au journal.
//
// LES REFUS SONT FABRIQUÉS par des triggers temporaires (`RAISE(ABORT)`, `RAISE(IGNORE)`) sur `incident_item` et
// `ledger`, une transaction laissée ouverte sur l'écrivain (`BEGIN` refusé, état lu AVANT le `ROLLBACK` du témoin) et une
// clé étrangère DIFFÉRÉE violée (`COMMIT` refusé). Les témoins de l'escalade lisent le compteur global du balayage
// `escalate_overdue_marqueur`, que `fec_` (fusion_et_escalade_comptees.rs) lit en différence exacte sans verrou : ils
// tournent dans un SOUS-PROCESSUS (`current_exe`), pour ne pas le fausser sous `cargo test`.
//
// MUTANTS JOUÉS (interrupteurs de test sous cfg!(test), retirés avant le commit), chacun vu ROUGE : `ac2_creation_chrono_avalee`,
// `ac2_creation_hors_transaction`, `ac2_creation_maillon_jete`, `ac2_creation_maillon_annule`,
// `ac2_creation_begin_ecrit`, `ac2_creation_nonvalide_ouvert`, `ac2_archive_chrono_avalee`,
// `ac2_archive_hors_transaction`, `ac2_archive_maillon_jete`, `ac2_route_archive_204`, `ac2_route_desarchive_204`,
// `ac2_archive_nonouvert_ecrite`, `ac2_archive_nonvalide_ecrite`, `ac2_maj_chrono_avalee`, `ac2_maj_hors_transaction`,
// `ac2_maj_rattrapage_saute`, `ac2_maj_maillon_jete`, `ac2_maj_maillon_annule`, `ac2_route_maj_204`,
// `ac2_maj_nonouvert_ecrit`, `ac2_maj_nonvalide_ecrit`, `ac2_escalade_chrono_avalee`, `ac2_escalade_hors_transaction`,
// `ac2_escalade_refus_tait`, `ac2_escalade_nonouvert_tait`, `ac2_escalade_nonvalide_tait`, `ac2_escalade_maillon_refus`.
//
// CE QU'ILS NE TIENNENT PAS : ce que la console fait du 200 `registre_sans_maillon` sur ces routes (web/ hors
// périmètre : `apiSend` le lit comme un succès, l'aveu n'est pas affiché) ; un maillon manquant d'un champ attesté suivi
// d'un refus d'un champ ultérieur (le 503 sert le refus, l'aveu du maillon reste au journal de la primitive) ; un
// `ROLLBACK` refusé ; l'existence lue avant le geste d'archivage reste hors de sa transaction (comme avant).
// =====================================================================================
mod chronologie_et_maillon_des_gestes_de_dossier {
    use super::*;
    use crate::handlers::cases::{
        CAUSE_ARCHIVAGE_NON_ECRIT, CAUSE_DESARCHIVAGE_NON_ECRIT, CAUSE_DOSSIER_NON_OUVERT, CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE,
        ESCALADE_NON_ENREGISTREE,
    };

    fn ac2_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("ac2-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn ac2_qui(role: &str) -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: role.into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn ac2_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ac2_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn ac2_textes(st: &AppState, sql: &str) -> Vec<String> {
        let conn = st.db.lock();
        let mut s = conn.prepare(sql).unwrap();
        s.query_map([], |r| r.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    fn ac2_phrase(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    fn ac2_refuser_l_element(st: &AppState, condition: &str, forme: &str) {
        ac2_sql(st, &format!("CREATE TEMP TRIGGER ac2_element BEFORE INSERT ON incident_item WHEN {condition} BEGIN SELECT {forme}; END;"));
    }

    const AC2_ABORT: &str = "RAISE(ABORT, 'ac2 chronologie refusée')";
    const AC2_IGNORE: &str = "RAISE(IGNORE)";

    fn ac2_refuser_le_maillon(st: &AppState, genre: &str) {
        ac2_sql(
            st,
            &format!("CREATE TEMP TRIGGER ac2_maillon BEFORE INSERT ON ledger WHEN NEW.kind='{genre}' BEGIN SELECT RAISE(ABORT, 'ac2 maillon refusé'); END;"),
        );
    }

    /// `COMMIT` refusé : clé étrangère DIFFÉRÉE violée par un trigger sur l'élément de chronologie (patron `ab3_`).
    fn ac2_refuser_le_commit(st: &AppState) {
        ac2_sql(
            st,
            "PRAGMA foreign_keys=ON;
             CREATE TEMP TABLE ac2_parent(id INTEGER PRIMARY KEY);
             CREATE TEMP TABLE ac2_enfant(p INTEGER REFERENCES ac2_parent(id) DEFERRABLE INITIALLY DEFERRED);
             CREATE TEMP TRIGGER ac2_fk AFTER INSERT ON incident_item BEGIN INSERT INTO ac2_enfant VALUES(999); END;",
        );
    }

    fn ac2_lever_le_commit(st: &AppState) {
        ac2_sql(st, "DROP TRIGGER ac2_fk; DROP TABLE ac2_enfant; DROP TABLE ac2_parent; PRAGMA foreign_keys=OFF;");
    }

    fn ac2_maillon_avoue(corps: &Value) -> bool {
        corps.get(CLE_REGISTRE_SANS_MAILLON).and_then(|v| v.as_str()).is_some_and(|p| p.starts_with(CAUSE_GESTE_SANS_TRACE) && p.contains("ac2 maillon refusé"))
    }

    async fn ac2_creer(st: &AppState) -> (u16, Value) {
        pb_json(case_create(State(st.clone()), Extension(ac2_qui("editor")), Json(json!({ "title": "Dossier ac2", "severity": 3, "priority": 2 }))).await).await
    }

    /// Un dossier dont `updated` est ramené dans le passé : une écriture annulée se voit à `updated` inchangé.
    fn ac2_dossier(st: &AppState) -> i64 {
        let conn = st.db.lock();
        let id = dossier_seme(&conn, "alice", "D", 3, "", None, 3);
        conn.execute("UPDATE incident SET updated=1000 WHERE id=?1", params![id]).unwrap();
        id
    }

    /// L'état que les gestes écrivent : archivage, assignation, priorité, statut, verdict, `updated`, MTTA, escalade.
    #[allow(clippy::type_complexity)]
    fn ac2_etat_du_dossier(st: &AppState, id: i64) -> (i64, Option<String>, Option<String>, i64, String, Option<String>, i64, Option<i64>, i64) {
        st.db
            .lock()
            .query_row(
                "SELECT archived, archived_by, assignee, priority, status, disposition, updated, first_response_ts, escalated FROM incident WHERE id=?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)),
            )
            .expect("fixture : le dossier se lit")
    }

    // ---------------------------------------------------------------------------------------------- création

    /// CE QU'IL TIENT (`case_create`, par la route) : la chronologie « créé » refusée (ABORT puis IGNORE) -> 503
    /// `CAUSE_DOSSIER_NON_OUVERT` qui nomme la chronologie, et AUCUN dossier n'existe : zéro ligne `incident`, zéro
    /// élément, zéro `case.create`, aucune transaction laissée ouverte. Contrôle positif : trigger levé, 200 avec
    /// l'identifiant, UN élément « Incident créé », UN maillon aux textes d'avant, aucun aveu.
    /// MUTANTS : `ac2_creation_chrono_avalee` (200), `ac2_creation_hors_transaction` (la ligne survit).
    #[tokio::test]
    async fn ac2_une_creation_dont_la_chronologie_est_refusee_n_ouvre_aucun_dossier() {
        let (st, _tmp) = ac2_etat("creation-chrono");
        for forme in [AC2_ABORT, AC2_IGNORE] {
            ac2_refuser_l_element(&st, "NEW.kind='created'", forme);
            let (statut, corps) = ac2_creer(&st).await;
            ac2_sql(&st, "DROP TRIGGER ac2_element;");
            assert_eq!(statut, 503, "{forme} : chronologie refusée -> 503, jamais un dossier sans chronologie : {corps}");
            let phrase = ac2_phrase(&corps);
            assert!(phrase.starts_with(CAUSE_DOSSIER_NON_OUVERT), "{forme} : le 503 existant : {corps}");
            assert!(phrase.contains("chronologie de l'ouverture"), "{forme} : la cause nomme la chronologie : {corps}");
            assert!(!corps["id"].is_i64(), "{forme} : aucun identifiant de dossier servi (l'`id` d'un refus est celui de la requête) : {corps}");
            assert!(st.db.lock().is_autocommit(), "{forme} : aucune transaction laissée ouverte");
            assert_eq!(ac2_compte(&st, "SELECT COUNT(*) FROM incident"), 0, "{forme} : la ligne du dossier est annulée");
            assert_eq!(ac2_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='created'"), 0, "{forme} : aucun élément");
            assert_eq!(ac2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.create'"), 0, "{forme} : rien au registre");
        }
        let (statut, corps) = ac2_creer(&st).await;
        assert_eq!(statut, 200, "contrôle positif : {corps}");
        let id = corps["id"].as_i64().expect("l'identifiant est servi");
        assert!(corps.get(CLE_REGISTRE_SANS_MAILLON).is_none(), "nominal : aucun aveu : {corps}");
        assert_eq!(ac2_textes(&st, &format!("SELECT body FROM incident_item WHERE incident_id={id} AND kind='created'")), vec!["Incident créé".to_string()]);
        assert_eq!(ac2_textes(&st, "SELECT detail FROM ledger WHERE kind='case.create'"), vec![format!("#{id} 'Dossier ac2' by analyste")]);
    }

    /// CE QU'IL TIENT (`case_create`) : le maillon `case.create` refusé -> 200, identifiant servi, et
    /// `registre_sans_maillon` (`CAUSE_GESTE_SANS_TRACE` + cause) à côté du corps ; le dossier EST ouvert : sa ligne et sa
    /// chronologie existent, rien au registre.
    /// MUTANTS : `ac2_creation_maillon_jete` (aucun aveu), `ac2_creation_maillon_annule` (503, dossier annulé).
    #[tokio::test]
    async fn ac2_un_maillon_de_creation_refuse_est_avoue_sans_annuler_le_dossier() {
        let (st, _tmp) = ac2_etat("creation-maillon");
        ac2_refuser_le_maillon(&st, "case.create");
        let (statut, corps) = ac2_creer(&st).await;
        assert_eq!(statut, 200, "maillon manquant : le dossier est servi : {corps}");
        let id = corps["id"].as_i64().expect("l'identifiant est servi");
        assert!(ac2_maillon_avoue(&corps), "le corps avoue la trace manquante : {corps}");
        assert_eq!(corps["status"], json!("new"), "le corps d'avant est inchangé à côté de l'aveu : {corps}");
        assert_eq!(ac2_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={id}")), 1, "le dossier existe");
        assert_eq!(ac2_compte(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={id} AND kind='created'")), 1);
        assert_eq!(ac2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.create'"), 0);
    }

    /// CE QU'IL TIENT (`case_create`) : `BEGIN` refusé (transaction étrangère) -> 503 `CAUSE_DOSSIER_NON_OUVERT` qui nomme
    /// le refus, aucune ligne — lu AVANT le `ROLLBACK` du témoin, dans la transaction étrangère elle-même ; `COMMIT`
    /// refusé -> 503 « validation refusée », aucune ligne. Contrôle : leviers retirés, 200.
    /// MUTANTS : `ac2_creation_begin_ecrit`, `ac2_creation_nonvalide_ouvert`.
    #[tokio::test]
    async fn ac2_une_creation_dont_la_transaction_est_refusee_n_ouvre_aucun_dossier() {
        let (st, _tmp) = ac2_etat("creation-transaction");
        ac2_sql(&st, "BEGIN;");
        let (statut, corps) = ac2_creer(&st).await;
        // LU AVANT le ROLLBACK, sur la même connexion : une écriture faite dans la transaction étrangère s'y voit encore.
        let pendant = ac2_compte(&st, "SELECT COUNT(*) FROM incident") + ac2_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='created'")
            + ac2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.create'");
        ac2_sql(&st, "ROLLBACK;");
        assert_eq!(statut, 503, "BEGIN refusé : 503 : {corps}");
        assert!(ac2_phrase(&corps).starts_with(CAUSE_DOSSIER_NON_OUVERT) && ac2_phrase(&corps).contains("transaction non ouverte"), "{corps}");
        assert_eq!(pendant, 0, "BEGIN refusé : rien n'est écrit, pas même dans la transaction étrangère");

        ac2_refuser_le_commit(&st);
        let (statut, corps) = ac2_creer(&st).await;
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte après le COMMIT refusé");
        ac2_lever_le_commit(&st);
        assert_eq!(statut, 503, "COMMIT refusé : 503 : {corps}");
        assert!(ac2_phrase(&corps).starts_with(CAUSE_DOSSIER_NON_OUVERT) && ac2_phrase(&corps).contains("validation refusée"), "{corps}");
        assert_eq!(ac2_compte(&st, "SELECT COUNT(*) FROM incident") + ac2_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='created'"), 0);

        assert_eq!(ac2_creer(&st).await.0, 200, "contrôle : leviers retirés, le dossier est ouvert");
    }

    // ---------------------------------------------------------------------------------------------- archivage

    async fn ac2_archiver(st: &AppState, id: i64, archiver: bool) -> (u16, Value) {
        let r = if archiver {
            case_archive(State(st.clone()), Extension(ac2_qui("admin")), Path(id)).await
        } else {
            case_unarchive(State(st.clone()), Extension(ac2_qui("admin")), Path(id)).await
        };
        pb_json(r).await
    }

    /// (genre de l'élément, genre du maillon, cause du 503) de l'archivage, puis du désarchivage.
    const AC2_ARCHIVAGES: [(bool, &str, &str, &str); 2] =
        [(true, "archive", "case.archive", CAUSE_ARCHIVAGE_NON_ECRIT), (false, "unarchive", "case.unarchive", CAUSE_DESARCHIVAGE_NON_ECRIT)];

    /// Un dossier dans l'état d'avant le geste : non archivé pour l'archivage, archivé (sans trace) pour le désarchivage.
    fn ac2_dossier_a_archiver(st: &AppState, archiver: bool) -> i64 {
        let id = ac2_dossier(st);
        if !archiver {
            ac2_sql(st, &format!("UPDATE incident SET archived=1, archived_ts=900, archived_by='root' WHERE id={id};"));
        }
        id
    }

    /// CE QU'IL TIENT (`case_archive`, `case_unarchive`) : la chronologie refusée (ABORT puis IGNORE) -> 503 existant qui
    /// nomme la chronologie, et le geste est ANNULÉ : `archived`, `archived_by`, `updated` et MTTA inchangés, aucun
    /// élément, aucun maillon, aucune transaction ouverte. Contrôle positif : 204, élément et maillon aux textes d'avant.
    /// MUTANTS : `ac2_archive_chrono_avalee` (204), `ac2_archive_hors_transaction` (l'archivage survit).
    #[tokio::test]
    async fn ac2_un_archivage_dont_la_chronologie_est_refusee_est_annule() {
        for &(archiver, genre, registre, cause) in table_declaree!(AC2_ARCHIVAGES) {
            let (st, _tmp) = ac2_etat(&format!("archive-chrono-{genre}"));
            let id = ac2_dossier_a_archiver(&st, archiver);
            let avant = ac2_etat_du_dossier(&st, id);
            for forme in [AC2_ABORT, AC2_IGNORE] {
                ac2_refuser_l_element(&st, &format!("NEW.kind='{genre}'"), forme);
                let (statut, corps) = ac2_archiver(&st, id, archiver).await;
                ac2_sql(&st, "DROP TRIGGER ac2_element;");
                assert_eq!(statut, 503, "{genre} {forme} : chronologie refusée -> 503 : {corps}");
                let phrase = ac2_phrase(&corps);
                assert!(phrase.starts_with(cause) && phrase.contains("chronologie"), "{genre} {forme} : le 503 existant nomme la chronologie : {corps}");
                assert!(st.db.lock().is_autocommit(), "{genre} {forme} : aucune transaction laissée ouverte");
                assert_eq!(ac2_etat_du_dossier(&st, id), avant, "{genre} {forme} : le geste est ANNULÉ");
                assert_eq!(ac2_compte(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE kind='{genre}'")), 0, "{genre} {forme}");
                assert_eq!(ac2_compte(&st, &format!("SELECT COUNT(*) FROM ledger WHERE kind='{registre}'")), 0, "{genre} {forme}");
            }
            let (statut, corps) = ac2_archiver(&st, id, archiver).await;
            assert_eq!(statut, 204, "{genre} : contrôle positif : {corps}");
            assert_eq!(ac2_etat_du_dossier(&st, id).0, i64::from(archiver), "{genre} : le geste est fait");
            assert_eq!(ac2_compte(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE kind='{genre}'")), 1);
            assert_eq!(ac2_textes(&st, &format!("SELECT detail FROM ledger WHERE kind='{registre}'")), vec![format!("#{id} by analyste")]);
        }
    }

    /// CE QU'IL TIENT : le maillon refusé -> 200 `{ok, registre_sans_maillon}` (jamais un 204 muet), et le geste EST fait :
    /// drapeau écrit, élément écrit, rien au registre — pour l'archivage puis le désarchivage.
    /// MUTANTS : `ac2_archive_maillon_jete`, `ac2_route_archive_204`, `ac2_route_desarchive_204`.
    #[tokio::test]
    async fn ac2_un_maillon_d_archivage_refuse_est_avoue_sans_annuler() {
        for &(archiver, genre, registre, _) in table_declaree!(AC2_ARCHIVAGES) {
            let (st, _tmp) = ac2_etat(&format!("archive-maillon-{genre}"));
            let id = ac2_dossier_a_archiver(&st, archiver);
            ac2_refuser_le_maillon(&st, registre);
            let (statut, corps) = ac2_archiver(&st, id, archiver).await;
            assert_eq!(statut, 200, "{genre} : maillon manquant -> 200 qui l'avoue : {corps}");
            assert!(corps.get("ok") == Some(&json!(true)) && ac2_maillon_avoue(&corps), "{genre} : {corps}");
            assert_eq!(ac2_etat_du_dossier(&st, id).0, i64::from(archiver), "{genre} : le geste a eu lieu");
            assert_eq!(ac2_compte(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE kind='{genre}'")), 1, "{genre} : élément écrit");
            assert_eq!(ac2_compte(&st, &format!("SELECT COUNT(*) FROM ledger WHERE kind='{registre}'")), 0);
        }
    }

    /// CE QU'IL TIENT (`case_archive`) : `BEGIN` refusé -> 503 « transaction non ouverte », rien d'écrit (lu avant le
    /// `ROLLBACK`) ; `COMMIT` refusé -> 503 « validation refusée », rien d'écrit. Contrôle : 204.
    /// MUTANTS : `ac2_archive_nonouvert_ecrite`, `ac2_archive_nonvalide_ecrite`.
    #[tokio::test]
    async fn ac2_un_archivage_dont_la_transaction_est_refusee_n_ecrit_rien() {
        let (st, _tmp) = ac2_etat("archive-transaction");
        let id = ac2_dossier(&st);
        let avant = ac2_etat_du_dossier(&st, id);
        ac2_sql(&st, "BEGIN;");
        let (statut, corps) = ac2_archiver(&st, id, true).await;
        let pendant = ac2_etat_du_dossier(&st, id);
        let traces = ac2_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='archive'") + ac2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.archive'");
        ac2_sql(&st, "ROLLBACK;");
        assert_eq!(statut, 503, "BEGIN refusé : {corps}");
        assert!(ac2_phrase(&corps).starts_with(CAUSE_ARCHIVAGE_NON_ECRIT) && ac2_phrase(&corps).contains("transaction non ouverte"), "{corps}");
        assert_eq!((pendant, traces), (avant.clone(), 0), "BEGIN refusé : rien d'écrit, pas même dans la transaction étrangère");

        ac2_refuser_le_commit(&st);
        let (statut, corps) = ac2_archiver(&st, id, true).await;
        assert!(st.db.lock().is_autocommit());
        ac2_lever_le_commit(&st);
        assert_eq!(statut, 503, "COMMIT refusé : {corps}");
        assert!(ac2_phrase(&corps).starts_with(CAUSE_ARCHIVAGE_NON_ECRIT) && ac2_phrase(&corps).contains("validation refusée"), "{corps}");
        assert_eq!(ac2_etat_du_dossier(&st, id), avant);
        assert_eq!(ac2_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='archive'"), 0);

        assert_eq!(ac2_archiver(&st, id, true).await.0, 204, "contrôle : leviers retirés, l'archivage aboutit");
    }

    // ---------------------------------------------------------------------------------------------- mise à jour

    async fn ac2_mettre_a_jour(st: &AppState, id: i64, corps: Value) -> (u16, Value) {
        pb_json(case_update(State(st.clone()), Extension(ac2_qui("editor")), Path(id), Json(corps)).await).await
    }

    /// CE QU'IL TIENT (`case_update`) : pour chaque champ attesté — assignation, priorité, statut, verdict effacé, verdict
    /// posé —, la chronologie refusée (ABORT ; IGNORE pour l'assignation) -> 503 `CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE`
    /// dont la cause dit « <champ>: chronologie : », et le CHAMP n'est PAS écrit (la phrase « il n'est PAS modifié » est
    /// vraie) : état du dossier inchangé (champ, `updated`, MTTA), aucun élément, aucun maillon. Contrôle : 204, champ,
    /// élément et maillon écrits, MTTA figé.
    /// MUTANTS : `ac2_maj_chrono_avalee` (204), `ac2_maj_hors_transaction` (le champ survit à sa chronologie refusée).
    #[tokio::test]
    async fn ac2_un_champ_atteste_dont_la_chronologie_est_refusee_n_est_pas_ecrit() {
        let cas: [(&str, Value, &str, Option<&str>, &str); 6] = [
            ("assignee", json!({ "assignee": "carol" }), "assign", Some("case.assign"), AC2_ABORT),
            ("assignee", json!({ "assignee": "carol" }), "assign", Some("case.assign"), AC2_IGNORE),
            ("priority", json!({ "priority": 1 }), "priority", None, AC2_ABORT),
            ("status", json!({ "status": "in_progress" }), "status", Some("case.status"), AC2_ABORT),
            ("disposition", json!({ "disposition": "" }), "disposition", Some("case.disposition"), AC2_ABORT),
            ("disposition", json!({ "disposition": "true_positive" }), "disposition", Some("case.disposition"), AC2_ABORT),
        ];
        for (champ, demande, genre, registre, forme) in cas {
            let (st, _tmp) = ac2_etat(&format!("maj-chrono-{champ}"));
            let id = ac2_dossier(&st);
            ac2_sql(&st, &format!("UPDATE incident SET disposition='benign' WHERE id={id};"));
            let avant = ac2_etat_du_dossier(&st, id);
            ac2_refuser_l_element(&st, &format!("NEW.kind='{genre}'"), forme);
            let (statut, corps) = ac2_mettre_a_jour(&st, id, demande.clone()).await;
            ac2_sql(&st, "DROP TRIGGER ac2_element;");
            assert_eq!(statut, 503, "{demande} {forme} : chronologie refusée -> 503, jamais un 204 : {corps}");
            let phrase = ac2_phrase(&corps);
            assert!(phrase.starts_with(CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE), "{demande} : le 503 existant : {corps}");
            assert!(phrase.contains(&format!("({champ}: chronologie : ")), "{demande} : la cause nomme le champ et sa chronologie : {corps}");
            assert!(st.db.lock().is_autocommit(), "{demande} : aucune transaction laissée ouverte");
            assert_eq!(ac2_etat_du_dossier(&st, id), avant, "{demande} {forme} : le champ n'est PAS écrit, ni updated ni MTTA");
            assert_eq!(ac2_compte(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE kind='{genre}'")), 0, "{demande}");
            if let Some(registre) = registre {
                assert_eq!(ac2_compte(&st, &format!("SELECT COUNT(*) FROM ledger WHERE kind='{registre}'")), 0, "{demande} : rien au registre");
            }

            let (statut, corps) = ac2_mettre_a_jour(&st, id, demande.clone()).await;
            assert_eq!(statut, 204, "{demande} : contrôle positif : {corps}");
            assert_ne!(ac2_etat_du_dossier(&st, id), avant, "{demande} : le champ est écrit");
            assert_eq!(ac2_compte(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE kind='{genre}'")), 1, "{demande}");
            assert!(ac2_etat_du_dossier(&st, id).7.is_some(), "{demande} : la chronologie fige le MTTA");
            if let Some(registre) = registre {
                assert_eq!(ac2_compte(&st, &format!("SELECT COUNT(*) FROM ledger WHERE kind='{registre}'")), 1, "{demande}");
            }
        }
    }

    /// CE QU'IL TIENT (`case_update`, contrat non transactionnel) : priorité P3 -> P1 ÉCRITE, puis la chronologie du
    /// statut refusée -> 503 qui dit le rattrapage de l'échéance sur la priorité écrite ; la priorité et sa chronologie
    /// restent (contrat écrit), le statut n'est PAS écrit, `sla_due` vaut la cible de P1.
    /// MUTANT : `ac2_maj_rattrapage_saute`.
    #[tokio::test]
    async fn ac2_une_chronologie_de_statut_refusee_apres_une_priorite_ecrite_rattrape_l_echeance() {
        let (st, _tmp) = ac2_etat("maj-rattrapage");
        let id = ac2_dossier(&st);
        ac2_refuser_l_element(&st, "NEW.kind='status'", AC2_ABORT);
        let (statut, corps) = ac2_mettre_a_jour(&st, id, json!({ "priority": 1, "status": "in_progress" })).await;
        assert_eq!(statut, 503, "{corps}");
        let phrase = ac2_phrase(&corps);
        assert!(phrase.contains("status: chronologie : ") && phrase.contains("échéance recalculée sur la priorité écrite"), "le rattrapage est dit : {corps}");
        let (_, _, _, priorite, statut_en_base, ..) = ac2_etat_du_dossier(&st, id);
        assert_eq!((priorite, statut_en_base.as_str()), (1, "new"), "la priorité précédente reste écrite, le statut ne l'est pas");
        assert_eq!(ac2_compte(&st, &format!("SELECT sla_due - ts FROM incident WHERE id={id}")), sla_target_s(1), "échéance de la priorité écrite");
        assert_eq!(ac2_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='priority'"), 1);
    }

    /// CE QU'IL TIENT (`case_update`) : le maillon `case.status` refusé dans une demande assignation + statut -> 200
    /// `{ok, registre_sans_maillon}` dont la cause nomme le statut ; les DEUX champs sont écrits avec leurs chronologies,
    /// `case.assign` au registre, `case.status` absent.
    /// MUTANTS : `ac2_maj_maillon_jete` (204), `ac2_maj_maillon_annule` (503), `ac2_route_maj_204` (204).
    #[tokio::test]
    async fn ac2_un_maillon_de_mise_a_jour_refuse_est_avoue_sans_annuler() {
        let (st, _tmp) = ac2_etat("maj-maillon");
        let id = ac2_dossier(&st);
        ac2_refuser_le_maillon(&st, "case.status");
        let (statut, corps) = ac2_mettre_a_jour(&st, id, json!({ "assignee": "carol", "status": "in_progress" })).await;
        assert_eq!(statut, 200, "maillon manquant : 200 qui l'avoue, jamais un 204 muet ni un 503 : {corps}");
        assert!(corps.get("ok") == Some(&json!(true)) && ac2_maillon_avoue(&corps), "{corps}");
        assert!(corps[CLE_REGISTRE_SANS_MAILLON].as_str().unwrap_or("").contains("(status: "), "l'aveu nomme le champ : {corps}");
        let (_, _, assignee, _, statut_en_base, ..) = ac2_etat_du_dossier(&st, id);
        assert_eq!((assignee.as_deref(), statut_en_base.as_str()), (Some("carol"), "in_progress"), "les deux champs sont écrits");
        assert_eq!(ac2_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind IN ('assign','status')"), 2);
        assert_eq!(ac2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.assign'"), 1);
        assert_eq!(ac2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.status'"), 0);
    }

    /// CE QU'IL TIENT (`case_update`, bras SANS rattrapage de `champ_atteste!`) : le maillon `case.assign` refusé dans une
    /// demande qui ne porte QUE l'assignation -> 200 `{ok, registre_sans_maillon}` dont la cause nomme l'assignation ;
    /// le champ est écrit avec sa chronologie, rien au registre. Le témoin précédent ne passe que par le bras `rattrape`
    /// (statut) : celui-ci est le seul qui rougit si le bras nu perd son maillon.
    /// MUTANT : `V_U_MACRO_EXTEND` (le bras nu jette le maillon -> 204).
    #[tokio::test]
    async fn ac2_un_maillon_d_assignation_seule_refuse_est_avoue_sans_annuler() {
        let (st, _tmp) = ac2_etat("maj-maillon-assign");
        let id = ac2_dossier(&st);
        ac2_refuser_le_maillon(&st, "case.assign");
        let (statut, corps) = ac2_mettre_a_jour(&st, id, json!({ "assignee": "carol" })).await;
        assert_eq!(statut, 200, "maillon d'assignation manquant : 200 qui l'avoue, jamais un 204 muet : {corps}");
        assert!(corps.get("ok") == Some(&json!(true)) && ac2_maillon_avoue(&corps), "{corps}");
        assert!(corps[CLE_REGISTRE_SANS_MAILLON].as_str().unwrap_or("").contains("(assignee: "), "l'aveu nomme le champ : {corps}");
        let (_, _, assignee, ..) = ac2_etat_du_dossier(&st, id);
        assert_eq!(assignee.as_deref(), Some("carol"), "le champ est écrit");
        assert_eq!(ac2_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='assign'"), 1);
        assert_eq!(ac2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.assign'"), 0);
    }

    /// CE QU'IL TIENT (`case_update`) : `BEGIN` refusé -> 503 « assignee: transaction non ouverte », rien d'écrit (lu avant
    /// le `ROLLBACK`) ; `COMMIT` refusé -> 503 « assignee: validation refusée », rien d'écrit. Contrôle : 204.
    /// MUTANTS : `ac2_maj_nonouvert_ecrit`, `ac2_maj_nonvalide_ecrit`.
    #[tokio::test]
    async fn ac2_un_champ_atteste_dont_la_transaction_est_refusee_n_est_pas_ecrit() {
        let (st, _tmp) = ac2_etat("maj-transaction");
        let id = ac2_dossier(&st);
        let avant = ac2_etat_du_dossier(&st, id);
        ac2_sql(&st, "BEGIN;");
        let (statut, corps) = ac2_mettre_a_jour(&st, id, json!({ "assignee": "carol" })).await;
        let pendant = ac2_etat_du_dossier(&st, id);
        let traces = ac2_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='assign'") + ac2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.assign'");
        ac2_sql(&st, "ROLLBACK;");
        assert_eq!(statut, 503, "BEGIN refusé : {corps}");
        assert!(ac2_phrase(&corps).contains("(assignee: transaction non ouverte"), "{corps}");
        assert_eq!((pendant, traces), (avant.clone(), 0), "BEGIN refusé : rien d'écrit, pas même dans la transaction étrangère");

        ac2_refuser_le_commit(&st);
        let (statut, corps) = ac2_mettre_a_jour(&st, id, json!({ "assignee": "carol" })).await;
        assert!(st.db.lock().is_autocommit());
        ac2_lever_le_commit(&st);
        assert_eq!(statut, 503, "COMMIT refusé : {corps}");
        assert!(ac2_phrase(&corps).contains("(assignee: validation refusée"), "{corps}");
        assert_eq!(ac2_etat_du_dossier(&st, id), avant);
        assert_eq!(ac2_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='assign'"), 0);

        assert_eq!(ac2_mettre_a_jour(&st, id, json!({ "assignee": "carol" })).await.0, 204, "contrôle : leviers retirés");
    }

    // ---------------------------------------------------------------------------------------------- escalade SLA

    /// Un dossier P1 dont l'échéance est dépassée, non escaladé, et un canal.
    fn ac2_escalade_fixture(st: &AppState) -> i64 {
        let conn = st.db.lock();
        let id = dossier_seme(&conn, "alice", "Échu", 4, "", None, 1);
        conn.execute("UPDATE incident SET sla_due=?1 WHERE id=?2", params![now() - 100, id]).unwrap();
        conn.execute(
            "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('ac2_canal','webhook',1,'https://example.invalid/h',0,'{}')",
            [],
        )
        .unwrap();
        id
    }

    fn ac2_tour(st: &AppState) -> Vec<String> {
        let mut envois = Vec::new();
        escalate_overdue_cases_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, detail: &str, _h: &str, _ts: i64| {
            envois.push(detail.to_string());
            true
        });
        envois
    }

    fn ac2_balayage() -> (u64, String) {
        crate::metrics::tick_aveugle_de("escalate_overdue_marqueur").unwrap_or((0, String::new()))
    }

    fn ac2_traces_d_escalade(st: &AppState, id: i64) -> (i64, i64, i64) {
        (
            ac2_compte(st, &format!("SELECT escalated FROM incident WHERE id={id}")),
            ac2_compte(st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={id} AND kind='sla'")),
            ac2_compte(st, "SELECT COUNT(*) FROM ledger WHERE kind='case.sla_escalate'"),
        )
    }

    /// Le corps du sous-processus : toutes les assertions de l'escalade (le compteur global y est seul).
    fn ac2_escalade_dans_l_enfant() {
        // (1) chronologie refusée : marqueur annulé, envoi avec l'aveu, compté par tour, renvoyé ; puis contrôle positif.
        let (st, _tmp) = ac2_etat("escalade-chrono");
        let id = ac2_escalade_fixture(&st);
        ac2_refuser_l_element(&st, "NEW.kind='sla'", AC2_ABORT);
        let avant = ac2_balayage().0;
        for tour in 0..2u64 {
            let envois = ac2_tour(&st);
            assert_eq!(envois.len(), 1, "tour {tour} : un SLA dépassé ne se tait pas : {envois:?}");
            assert!(envois[0].ends_with(ESCALADE_NON_ENREGISTREE), "tour {tour} : l'envoi avoue l'escalade non enregistrée : {envois:?}");
            let (compte, cause) = ac2_balayage();
            assert_eq!(compte, avant + tour + 1, "tour {tour} : compté une fois par tour au balayage `escalate_overdue_marqueur`");
            assert!(cause.contains("chronologie de l'escalade") && cause.contains("ac2 chronologie refusée"), "tour {tour} : la cause comptée : {cause}");
            assert_eq!(ac2_traces_d_escalade(&st, id), (0, 0, 0), "tour {tour} : marqueur annulé, ni chronologie ni registre");
        }
        ac2_sql(&st, "DROP TRIGGER ac2_element;");
        let envois = ac2_tour(&st);
        assert_eq!(envois.len(), 1, "contrôle positif : un envoi : {envois:?}");
        assert!(!envois[0].contains(ESCALADE_NON_ENREGISTREE), "contrôle positif : sans aveu : {envois:?}");
        assert_eq!(ac2_traces_d_escalade(&st, id), (1, 1, 1), "marqueur, chronologie, maillon");
        assert!(ac2_tour(&st).is_empty(), "escaladé : plus de renvoi");
        assert_eq!(ac2_balayage().0, avant + 2, "base saine : plus aucun refus compté");

        // (2) maillon refusé : rien n'est annulé, envoi nominal, pas compté, jamais renvoyé.
        let (st, _tmp) = ac2_etat("escalade-maillon");
        let id = ac2_escalade_fixture(&st);
        ac2_refuser_le_maillon(&st, "case.sla_escalate");
        let avant = ac2_balayage().0;
        let envois = ac2_tour(&st);
        assert_eq!(envois.len(), 1);
        assert!(!envois[0].contains(ESCALADE_NON_ENREGISTREE), "maillon manquant : l'escalade est enregistrée, envoi nominal : {envois:?}");
        assert_eq!(ac2_traces_d_escalade(&st, id), (1, 1, 0), "marqué, chronologie écrite, maillon absent");
        assert_eq!(ac2_balayage().0, avant, "maillon manquant : pas un refus du marqueur");
        assert!(ac2_tour(&st).is_empty(), "jamais renvoyé");

        // (3) BEGIN refusé (état lu avant le ROLLBACK), puis COMMIT refusé : aveu, compte, rien d'écrit.
        let (st, _tmp) = ac2_etat("escalade-transaction");
        let id = ac2_escalade_fixture(&st);
        let avant = ac2_balayage().0;
        ac2_sql(&st, "BEGIN;");
        let envois = ac2_tour(&st);
        let pendant = ac2_traces_d_escalade(&st, id);
        ac2_sql(&st, "ROLLBACK;");
        assert_eq!(envois.len(), 1);
        assert!(envois[0].ends_with(ESCALADE_NON_ENREGISTREE), "BEGIN refusé : aveu : {envois:?}");
        assert_eq!(pendant, (0, 0, 0), "BEGIN refusé : rien d'écrit, pas même dans la transaction étrangère");
        let (compte, cause) = ac2_balayage();
        assert!(compte == avant + 1 && cause.contains("transaction non ouverte"), "BEGIN refusé : compté : {compte} {cause}");
        ac2_refuser_le_commit(&st);
        let envois = ac2_tour(&st);
        assert!(st.db.lock().is_autocommit());
        ac2_lever_le_commit(&st);
        assert!(envois.len() == 1 && envois[0].ends_with(ESCALADE_NON_ENREGISTREE), "COMMIT refusé : aveu : {envois:?}");
        assert_eq!(ac2_traces_d_escalade(&st, id), (0, 0, 0), "COMMIT refusé : rien d'écrit");
        let (compte, cause) = ac2_balayage();
        assert!(compte == avant + 2 && cause.contains("validation refusée"), "COMMIT refusé : compté : {compte} {cause}");
    }

    /// CE QU'IL TIENT (`escalate_overdue_cases_par`, dans un sous-processus) : chronologie, `BEGIN` ou `COMMIT` refusés
    /// annulent le marqueur — envoi QUAND MÊME avec `ESCALADE_NON_ENREGISTREE`, rien en chronologie ni au registre,
    /// compté au balayage `escalate_overdue_marqueur` (cause nommée), renvoyé au tour suivant ; maillon manquant : rien
    /// d'annulé, envoi nominal, pas compté, jamais renvoyé ; contrôle positif : marqueur, chronologie, maillon.
    /// MUTANTS : `ac2_escalade_chrono_avalee`, `ac2_escalade_hors_transaction`, `ac2_escalade_refus_tait`,
    /// `ac2_escalade_nonouvert_tait`, `ac2_escalade_nonvalide_tait`, `ac2_escalade_maillon_refus`.
    #[test]
    fn ac2_une_escalade_dont_la_chronologie_est_refusee_s_avoue_et_revient() {
        const ENFANT: &str = "AC2_ENFANT_ESCALADE";
        if std::env::var(ENFANT).is_ok() {
            ac2_escalade_dans_l_enfant();
            println!("AC2-ESCALADE-TENUE");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::chronologie_et_maillon_des_gestes_de_dossier::ac2_une_escalade_dont_la_chronologie_est_refusee_s_avoue_et_revient",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant tient l'escalade : {stdout}\n{stderr}");
        assert!(stdout.contains("AC2-ESCALADE-TENUE"), "l'enfant a joué ses assertions jusqu'au bout : {stdout}\n{stderr}");
    }
}
