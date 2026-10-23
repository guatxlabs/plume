// =====================================================================================
// `P10.20-l` (sites de la famille dans handlers/field_filters.rs et handlers/destinations.rs) et `P10.29-l` (famille
// « texte du moteur servi », alerting.rs, destinations.rs, field_filters.rs) — UNE LECTURE RATÉE D'UN MASQUE DE CHAMP
// OU D'UNE DESTINATION N'EST PAS UNE ABSENCE, ET LE TEXTE DU MOTEUR NE PART PAS AU CLIENT.
//
// LE DÉFAUT, MESURÉ SUR f0df6162 AVANT LE CORRECTIF. `field_filter_update` et `field_filter_delete` lisaient la règle de
// masquage par `match … { Ok(t) => t, Err(_) => return not_found("field-filter introuvable") }`, et
// `destination_update` le type de la destination (qui juge l'endpoint contre la garde SSRF) par la même forme : une
// lecture qui n'avait pas eu lieu (ligne qui ne se convertit pas, table retirée) se servait 404 — un masque de
// confidentialité ou une sortie de données toujours en place se disait inexistant. Douze sites (six dans alerting.rs,
// trois dans destinations.rs, trois dans field_filters.rs) refusaient une écriture (geste ou trace d'audit) par un 500
// `échec transaction audit (aucune modification): <phrase du moteur SQLite>`.
//
// LE CORRECTIF (décision par défaut de la vague AE). Trois issues : lue, le geste suit ; absente, le 404 d'avant à
// l'identique ; lecture ratée, 503 nommé (`CAUSE_MASQUE_DE_CHAMP_INCHANGE_NON_LU`,
// `CAUSE_MASQUE_DE_CHAMP_NON_RETIRE_NON_LU`, `CAUSE_DESTINATION_INCHANGEE_NON_LUE`), RIEN n'est écrit, la cause du
// moteur au journal seul. Les douze 500 gardent leur statut et la phrase fixe `PHRASE_ECHEC_TRANSACTION_AUDIT`, la cause
// du moteur au journal avec l'identifiant de corrélation servi (`servir_l_echec_de_la_transaction_d_audit`).
//
// LES PANNES ÉPROUVÉES : une colonne lue stockée en BLOB (la ligne existe, sa lecture comme texte échoue) et la table
// retirée ; un déclencheur `RAISE(ABORT)` sur `BEFORE INSERT ON ledger` (la trace d'audit refusée) ; les lignes de
// journal lues sur le stderr d'un sous-processus.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : par lecture (`FF_MAJ`, `FF_RETRAIT`, `DEST_MAJ`)
// `AE3_<L>_LECTURE_EN_404`, `AE3_<L>_ABSENT_EN_503`, `AE3_<L>_CAUSE_EXPOSEE`, `AE3_<L>_LECTURE_FAIT_LE_GESTE`,
// `AE3_<L>_SANS_JOURNAL` ; par 500 `AE3_<S>_MOTEUR_SERVI` et `AE3_<S>_SANS_JOURNAL`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les écrans (web/fieldfilters.js, web/destinations.js, web/alerting.js, web/suppressions.js) ne sont pas
// exercés — ils peignent le corps par `peindreLeRefusDUnGeste`, en refus nommé (phrase entière), aucune des trois
// ouvertures « rien n'a changé » ne reconnaissant une lecture manquée ; une lecture ratée par verrou n'est pas jouée ;
// le mode multi-tenant n'est pas joué.
// =====================================================================================
mod masques_destinations_alerting_lecture_ratee_et_texte_du_moteur {
    use super::*;

    /// Ce que rusqlite écrit quand une colonne n'a pas le type demandé : la cause du moteur d'une lecture ratée.
    const AE3_MOTEUR_LECTURE: &str = "Invalid column type";
    /// La phrase du déclencheur qui refuse la trace d'audit : la cause du moteur d'une écriture refusée.
    const AE3_MOTEUR_ECRITURE: &str = "registre hors d atteinte (temoin AE3)";
    const AE3_ABSENT: i64 = 987_654;
    /// L'endpoint d'une destination de fixture (adresse privée) : il ne doit paraître dans aucune ligne de ce lot.
    const AE3_ENDPOINT: &str = "http://10.0.0.9/ae3-sortie";
    /// L'hôte des critères de politique et de silence : il ne doit paraître dans aucune ligne de ce lot.
    const AE3_HOTE: &str = "web-ae3-critere";

    fn ae3_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    fn ae3_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ae3_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn ae3_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    /// Un 5xx nommé, EN ENTIER : exactement les clés `error` et `id`, l'erreur égale à la phrase attendue, l'identifiant
    /// de corrélation, et aucune trace de la cause du moteur.
    fn ae3_juger_5xx(quoi: &str, (statut, corps, v): &(u16, String, Value), attendu_statut: u16, phrase: &str, moteur: &str) {
        assert_eq!(*statut, attendu_statut, "{quoi} : statut : {corps}");
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"], "{quoi} : exactement `error` et `id` : {corps}");
        assert_eq!(v["error"], json!(phrase), "{quoi} : la phrase nommée, seule : {corps}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
        assert!(!corps.contains(moteur) && !corps.contains("Blob") && !corps.contains("no such table") && !corps.contains("hors d atteinte"),
            "{quoi} : la cause du moteur ne sort pas : {corps}");
    }

    // ---- les gestes, par leur point d'entrée ----

    async fn ae3_poser_un_masque(st: &AppState, nom: &str) -> (u16, String, Value) {
        ae3_reponse(field_filter_create(State(st.clone()), Extension(ae3_adm()), Json(json!({ "name": nom, "field": "src_user", "action": "hash" }))).await).await
    }

    async fn ae3_modifier_le_masque(st: &AppState, id: i64) -> (u16, String, Value) {
        ae3_reponse(field_filter_update(State(st.clone()), Extension(ae3_adm()), Path(id), Json(json!({ "enabled": false }))).await).await
    }

    async fn ae3_retirer_le_masque(st: &AppState, id: i64) -> (u16, String, Value) {
        ae3_reponse(field_filter_delete(State(st.clone()), Extension(ae3_adm()), Path(id)).await).await
    }

    async fn ae3_creer_une_destination(st: &AppState, nom: &str) -> (u16, String, Value) {
        let corps = json!({ "type": "webhook", "name": nom, "endpoint": AE3_ENDPOINT, "enabled": true });
        ae3_reponse(destination_create(State(st.clone()), Extension(ae3_adm()), Json(corps)).await).await
    }

    async fn ae3_modifier_la_destination(st: &AppState, id: i64) -> (u16, String, Value) {
        ae3_reponse(destination_update(State(st.clone()), Extension(ae3_adm()), Path(id), Json(json!({ "enabled": false }))).await).await
    }

    async fn ae3_supprimer_la_destination(st: &AppState, id: i64) -> (u16, String, Value) {
        ae3_reponse(destination_delete(State(st.clone()), Extension(ae3_adm()), Path(id)).await).await
    }

    fn ae3_corps_de_politique() -> Value {
        json!({ "matchers": { "host": AE3_HOTE }, "contact_points": [1] })
    }

    async fn ae3_creer_une_politique(st: &AppState) -> (u16, String, Value) {
        ae3_reponse(policy_create(State(st.clone()), Extension(ae3_adm()), Json(ae3_corps_de_politique())).await).await
    }

    async fn ae3_modifier_la_politique(st: &AppState, id: i64) -> (u16, String, Value) {
        let corps = json!({ "matchers": { "host": AE3_HOTE }, "contact_points": [1], "enabled": false });
        ae3_reponse(policy_update(State(st.clone()), Extension(ae3_adm()), Path(id), Json(corps)).await).await
    }

    async fn ae3_supprimer_la_politique(st: &AppState, id: i64) -> (u16, String, Value) {
        ae3_reponse(policy_delete(State(st.clone()), Extension(ae3_adm()), Path(id)).await).await
    }

    async fn ae3_poser_un_silence(st: &AppState) -> (u16, String, Value) {
        let corps = json!({ "matchers": { "host": AE3_HOTE }, "duration_s": 600, "reason": "ae3" });
        ae3_reponse(silence_create(State(st.clone()), Extension(ae3_adm()), Json(corps)).await).await
    }

    async fn ae3_modifier_le_silence(st: &AppState, id: i64) -> (u16, String, Value) {
        ae3_reponse(silence_update(State(st.clone()), Extension(ae3_adm()), Path(id), Json(json!({ "reason": "ae3-modifie" }))).await).await
    }

    async fn ae3_lever_le_silence(st: &AppState, id: i64) -> (u16, String, Value) {
        ae3_reponse(silence_delete(State(st.clone()), Extension(ae3_adm()), Path(id)).await).await
    }

    fn ae3_id(quoi: &str, (statut, corps, v): &(u16, String, Value)) -> i64 {
        assert_eq!(*statut, 200, "fixture : {quoi} : {corps}");
        v["id"].as_i64().unwrap_or_else(|| panic!("fixture : identifiant de {quoi} : {corps}"))
    }

    fn ae3_registre_refuse(st: &AppState) {
        ae3_sql(st, &format!("CREATE TRIGGER ae3_ledger_refuse BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, '{AE3_MOTEUR_ECRITURE}'); END;"));
    }

    fn ae3_registre_rendu(st: &AppState) {
        ae3_sql(st, "DROP TRIGGER ae3_ledger_refuse;");
    }

    /// CE QU'IL TIENT (modification d'un masque de champ) : absent, `404 {"error": "field-filter introuvable"}`
    /// exactement ; champ illisible puis table retirée, `503` nommé `CAUSE_MASQUE_DE_CHAMP_INCHANGE_NON_LU` en entier,
    /// sans la cause du moteur — jamais `404` ; la règle reste ACTIVE et son champ intact, aucune modification attestée,
    /// la transaction est fermée. Contrôle : un masque lisible se modifie (`200`).
    /// MUTATIONS : `AE3_FF_MAJ_LECTURE_EN_404`, `AE3_FF_MAJ_ABSENT_EN_503`, `AE3_FF_MAJ_CAUSE_EXPOSEE`,
    /// `AE3_FF_MAJ_LECTURE_FAIT_LE_GESTE`.
    #[tokio::test]
    async fn ae3_modification_d_un_masque_lecture_ratee_jamais_404_et_rien_n_est_ecrit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (configuration)
        let (st, _p) = sp_state("ae3-masque-maj");
        let (statut, corps, v) = ae3_modifier_le_masque(&st, AE3_ABSENT).await;
        assert_eq!(statut, 404, "contrôle : l'absence établie reste un 404 : {corps}");
        assert_eq!(v, json!({ "error": "field-filter introuvable" }), "l'absence, rien d'autre : {corps}");

        let id = ae3_id("masque", &ae3_poser_un_masque(&st, "ae3-masque-illisible").await);
        ae3_sql(&st, &format!("UPDATE field_filter SET field=X'00' WHERE id={id}"));
        let r = ae3_modifier_le_masque(&st, id).await;
        ae3_juger_5xx("masque illisible", &r, 503, CAUSE_MASQUE_DE_CHAMP_INCHANGE_NON_LU, AE3_MOTEUR_LECTURE);
        assert_eq!(ae3_compte(&st, &format!("SELECT enabled FROM field_filter WHERE id={id}")), 1, "la règle illisible reste ACTIVE");
        assert_eq!(ae3_compte(&st, &format!("SELECT typeof(field)='blob' FROM field_filter WHERE id={id}")), 1, "son champ n'est pas réécrit");
        assert_eq!(ae3_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.field_filter.update'"), 0, "aucune modification attestée");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let lisible = ae3_id("masque lisible", &ae3_poser_un_masque(&st, "ae3-masque-lisible").await);
        let (statut, corps, _) = ae3_modifier_le_masque(&st, lisible).await;
        assert_eq!(statut, 200, "contrôle : un masque lisible se modifie : {corps}");
        assert_eq!(ae3_compte(&st, &format!("SELECT enabled FROM field_filter WHERE id={lisible}")), 0, "contrôle : il est désactivé");

        ae3_sql(&st, "ALTER TABLE field_filter RENAME TO field_filter_ae3_retiree;");
        let r = ae3_modifier_le_masque(&st, id).await;
        ae3_juger_5xx("table des masques retirée", &r, 503, CAUSE_MASQUE_DE_CHAMP_INCHANGE_NON_LU, "no such table");
        assert_eq!(ae3_compte(&st, &format!("SELECT enabled FROM field_filter_ae3_retiree WHERE id={id}")), 1, "la règle reste active");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");
    }

    /// CE QU'IL TIENT (retrait d'un masque de champ) : absent, `404 {"error": "field-filter introuvable"}` exactement ;
    /// nom illisible puis table retirée, `503` nommé `CAUSE_MASQUE_DE_CHAMP_NON_RETIRE_NON_LU` en entier, sans la cause
    /// du moteur ; la règle reste là, aucun retrait attesté, transaction fermée. Contrôle : un masque lisible se retire.
    /// MUTATIONS : `AE3_FF_RETRAIT_LECTURE_EN_404`, `AE3_FF_RETRAIT_ABSENT_EN_503`, `AE3_FF_RETRAIT_CAUSE_EXPOSEE`,
    /// `AE3_FF_RETRAIT_LECTURE_FAIT_LE_GESTE`.
    #[tokio::test]
    async fn ae3_retrait_d_un_masque_lecture_ratee_jamais_404_et_rien_n_est_supprime() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (configuration)
        let (st, _p) = sp_state("ae3-masque-retrait");
        let (statut, corps, v) = ae3_retirer_le_masque(&st, AE3_ABSENT).await;
        assert_eq!(statut, 404, "contrôle : l'absence établie reste un 404 : {corps}");
        assert_eq!(v, json!({ "error": "field-filter introuvable" }), "l'absence, rien d'autre : {corps}");

        let id = ae3_id("masque", &ae3_poser_un_masque(&st, "ae3-masque-a-retirer").await);
        ae3_sql(&st, &format!("UPDATE field_filter SET name=X'00' WHERE id={id}"));
        let r = ae3_retirer_le_masque(&st, id).await;
        ae3_juger_5xx("masque illisible", &r, 503, CAUSE_MASQUE_DE_CHAMP_NON_RETIRE_NON_LU, AE3_MOTEUR_LECTURE);
        assert_eq!(ae3_compte(&st, &format!("SELECT COUNT(*) FROM field_filter WHERE id={id}")), 1, "la règle illisible reste là");
        assert_eq!(ae3_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.field_filter.delete'"), 0, "aucun retrait attesté");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let lisible = ae3_id("masque lisible", &ae3_poser_un_masque(&st, "ae3-masque-lisible").await);
        let (statut, corps, _) = ae3_retirer_le_masque(&st, lisible).await;
        assert_eq!(statut, 200, "contrôle : un masque lisible se retire : {corps}");

        ae3_sql(&st, "ALTER TABLE field_filter RENAME TO field_filter_ae3_retiree;");
        let r = ae3_retirer_le_masque(&st, id).await;
        ae3_juger_5xx("table des masques retirée", &r, 503, CAUSE_MASQUE_DE_CHAMP_NON_RETIRE_NON_LU, "no such table");
        assert_eq!(ae3_compte(&st, &format!("SELECT COUNT(*) FROM field_filter_ae3_retiree WHERE id={id}")), 1, "la règle reste là");
    }

    /// CE QU'IL TIENT (modification d'une destination, dont le type juge l'endpoint) : absent,
    /// `404 {"error": "destination introuvable"}` exactement ; type illisible puis table retirée, `503` nommé
    /// `CAUSE_DESTINATION_INCHANGEE_NON_LUE` en entier, sans la cause du moteur ; la destination reste ACTIVE (elle
    /// envoie toujours), aucune modification attestée, transaction fermée. Contrôle : une destination lisible se modifie.
    /// MUTATIONS : `AE3_DEST_MAJ_LECTURE_EN_404`, `AE3_DEST_MAJ_ABSENT_EN_503`, `AE3_DEST_MAJ_CAUSE_EXPOSEE`,
    /// `AE3_DEST_MAJ_LECTURE_FAIT_LE_GESTE`.
    #[tokio::test]
    async fn ae3_modification_d_une_destination_lecture_ratee_jamais_404_et_rien_n_est_ecrit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // la garde SSRF lit l'environnement
        let (st, _p) = sp_state("ae3-destination");
        let (statut, corps, v) = ae3_modifier_la_destination(&st, AE3_ABSENT).await;
        assert_eq!(statut, 404, "contrôle : l'absence établie reste un 404 : {corps}");
        assert_eq!(v, json!({ "error": "destination introuvable" }), "l'absence, rien d'autre : {corps}");

        let id = ae3_id("destination", &ae3_creer_une_destination(&st, "ae3-sortie-illisible").await);
        ae3_sql(&st, &format!("UPDATE destination SET type=X'00' WHERE id={id}"));
        let r = ae3_modifier_la_destination(&st, id).await;
        ae3_juger_5xx("destination illisible", &r, 503, CAUSE_DESTINATION_INCHANGEE_NON_LUE, AE3_MOTEUR_LECTURE);
        assert_eq!(ae3_compte(&st, &format!("SELECT enabled FROM destination WHERE id={id}")), 1, "la destination illisible reste ACTIVE");
        assert_eq!(ae3_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.destination.update'"), 0, "aucune modification attestée");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let lisible = ae3_id("destination lisible", &ae3_creer_une_destination(&st, "ae3-sortie-lisible").await);
        let (statut, corps, _) = ae3_modifier_la_destination(&st, lisible).await;
        assert_eq!(statut, 200, "contrôle : une destination lisible se modifie : {corps}");
        assert_eq!(ae3_compte(&st, &format!("SELECT enabled FROM destination WHERE id={lisible}")), 0, "contrôle : elle est désactivée");

        ae3_sql(&st, "ALTER TABLE destination RENAME TO destination_ae3_retiree;");
        let r = ae3_modifier_la_destination(&st, id).await;
        ae3_juger_5xx("table des destinations retirée", &r, 503, CAUSE_DESTINATION_INCHANGEE_NON_LUE, "no such table");
        assert_eq!(ae3_compte(&st, &format!("SELECT enabled FROM destination_ae3_retiree WHERE id={id}")), 1, "la destination reste active");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");
    }

    /// CE QU'IL TIENT (les douze 500 d'écriture) : la trace d'audit refusée, chacun des douze gestes rend `500` dont le
    /// corps est EXACTEMENT `{error: PHRASE_ECHEC_TRANSACTION_AUDIT, id}` — sans la phrase du moteur ; rien n'est écrit
    /// (aucun objet de plus, aucun objet modifié ni retiré) et la transaction est fermée.
    /// MUTATIONS : `AE3_<S>_MOTEUR_SERVI` pour les douze sites (la phrase du moteur réapposée, la forme d'avant).
    #[tokio::test]
    async fn ae3_ecritures_refusees_rendent_500_sans_le_texte_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (garde SSRF, configuration)
        let (st, _p) = sp_state("ae3-moteur");
        let masque = ae3_id("masque", &ae3_poser_un_masque(&st, "ae3-masque-garde").await);
        let dest = ae3_id("destination", &ae3_creer_une_destination(&st, "ae3-sortie-gardee").await);
        let pol = ae3_id("politique", &ae3_creer_une_politique(&st).await);
        let sil = ae3_id("silence", &ae3_poser_un_silence(&st).await);
        let raison_avant = ae3_compte(&st, &format!("SELECT reason='ae3' FROM silence WHERE id={sil}"));
        assert_eq!(raison_avant, 1, "fixture : la raison d'avant");
        ae3_registre_refuse(&st);
        let cas = [
            ("pose d'un masque", ae3_poser_un_masque(&st, "ae3-masque-refuse").await),
            ("modification d'un masque", ae3_modifier_le_masque(&st, masque).await),
            ("retrait d'un masque", ae3_retirer_le_masque(&st, masque).await),
            ("création d'une destination", ae3_creer_une_destination(&st, "ae3-sortie-refusee").await),
            ("modification d'une destination", ae3_modifier_la_destination(&st, dest).await),
            ("suppression d'une destination", ae3_supprimer_la_destination(&st, dest).await),
            ("création d'une politique", ae3_creer_une_politique(&st).await),
            ("modification d'une politique", ae3_modifier_la_politique(&st, pol).await),
            ("suppression d'une politique", ae3_supprimer_la_politique(&st, pol).await),
            ("pose d'un silence", ae3_poser_un_silence(&st).await),
            ("modification d'un silence", ae3_modifier_le_silence(&st, sil).await),
            ("levée d'un silence", ae3_lever_le_silence(&st, sil).await),
        ];
        assert!(cas.len() >= 12, "plancher : les douze sites");
        for (quoi, r) in &cas {
            ae3_juger_5xx(quoi, r, 500, PHRASE_ECHEC_TRANSACTION_AUDIT, AE3_MOTEUR_ECRITURE);
        }
        ae3_registre_rendu(&st);
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");
        assert_eq!(ae3_compte(&st, "SELECT COUNT(*) FROM field_filter"), 1, "aucun masque de plus, le masque reste là");
        assert_eq!(ae3_compte(&st, &format!("SELECT enabled FROM field_filter WHERE id={masque}")), 1, "le masque reste actif");
        assert_eq!(ae3_compte(&st, "SELECT COUNT(*) FROM destination"), 1, "aucune destination de plus, la destination reste là");
        assert_eq!(ae3_compte(&st, &format!("SELECT enabled FROM destination WHERE id={dest}")), 1, "la destination reste active");
        assert_eq!(ae3_compte(&st, "SELECT COUNT(*) FROM notification_policy"), 1, "aucune politique de plus, la politique reste là");
        assert_eq!(ae3_compte(&st, &format!("SELECT enabled FROM notification_policy WHERE id={pol}")), 1, "la politique reste active");
        assert_eq!(ae3_compte(&st, "SELECT COUNT(*) FROM silence"), 1, "aucun silence de plus, le silence reste là");
        assert_eq!(ae3_compte(&st, &format!("SELECT reason='ae3' FROM silence WHERE id={sil}")), 1, "le silence garde sa raison");
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus : chaque lecture ratée écrit UNE ligne
    /// `[<module>] WARN <geste> #<id> refusé(e) : … n'a pas pu être lue (<cause du moteur>)`, chaque écriture refusée
    /// UNE ligne `[<identifiant servi>] [<module>] WARN <geste> refusé : transaction d'audit annulée, aucune modification
    /// (<cause du moteur>)` ; aucune ne porte l'endpoint, le nom ni les critères ; le nominal et les absences n'en
    /// écrivent aucune. MUTATIONS : `AE3_<L>_SANS_JOURNAL` (trois lectures) et `AE3_<S>_SANS_JOURNAL` (douze 500).
    #[tokio::test]
    async fn ae3_lignes_de_journal_des_refus() {
        const ENFANT: &str = "AE3_ENFANT_JOURNAL";
        const PHASE: &str = "AE3-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
            let (st, _p) = sp_state("ae3-journal");
            let fm = ae3_id("masque", &ae3_poser_un_masque(&st, "ae3-journal-masque-maj").await);
            let fr = ae3_id("masque", &ae3_poser_un_masque(&st, "ae3-journal-masque-retrait").await);
            let dm = ae3_id("destination", &ae3_creer_une_destination(&st, "ae3-journal-sortie-maj").await);
            ae3_sql(&st, &format!("UPDATE field_filter SET field=X'00' WHERE id={fm}; UPDATE field_filter SET name=X'00' WHERE id={fr}; UPDATE destination SET type=X'00' WHERE id={dm};"));
            eprintln!("{PHASE}lectures");
            let a = ae3_modifier_le_masque(&st, fm).await.0;
            let b = ae3_retirer_le_masque(&st, fr).await.0;
            let c = ae3_modifier_la_destination(&st, dm).await.0;
            println!("AE3-STATUT-LECTURES:{a}:{b}:{c}:{fm}:{fr}:{dm}");
            eprintln!("{PHASE}preparation");
            let masque = ae3_id("masque", &ae3_poser_un_masque(&st, "ae3-journal-masque").await);
            let dest = ae3_id("destination", &ae3_creer_une_destination(&st, "ae3-journal-sortie").await);
            let pol = ae3_id("politique", &ae3_creer_une_politique(&st).await);
            let sil = ae3_id("silence", &ae3_poser_un_silence(&st).await);
            ae3_registre_refuse(&st);
            eprintln!("{PHASE}ecritures");
            let rs = [
                ae3_poser_un_masque(&st, "ae3-journal-masque-refuse").await,
                ae3_modifier_le_masque(&st, masque).await,
                ae3_retirer_le_masque(&st, masque).await,
                ae3_creer_une_destination(&st, "ae3-journal-sortie-refusee").await,
                ae3_modifier_la_destination(&st, dest).await,
                ae3_supprimer_la_destination(&st, dest).await,
                ae3_creer_une_politique(&st).await,
                ae3_modifier_la_politique(&st, pol).await,
                ae3_supprimer_la_politique(&st, pol).await,
                ae3_poser_un_silence(&st).await,
                ae3_modifier_le_silence(&st, sil).await,
                ae3_lever_le_silence(&st, sil).await,
            ];
            let statuts: Vec<String> = rs.iter().map(|r| r.0.to_string()).collect();
            let ids: Vec<String> = rs.iter().map(|r| r.2["id"].as_str().unwrap_or("").to_string()).collect();
            println!("AE3-STATUT-ECRITURES:{}", statuts.join(":"));
            println!("AE3-ID-SERVI:{}", ids.join(":"));
            println!("AE3-OBJETS:{masque}:{dest}:{pol}:{sil}");
            ae3_registre_rendu(&st);
            eprintln!("{PHASE}calme");
            let (st, _p) = sp_state("ae3-journal-calme");
            let m = ae3_id("masque", &ae3_poser_un_masque(&st, "ae3-calme-masque").await);
            let d = ae3_id("destination", &ae3_creer_une_destination(&st, "ae3-calme-sortie").await);
            let p = ae3_id("politique", &ae3_creer_une_politique(&st).await);
            let s = ae3_id("silence", &ae3_poser_un_silence(&st).await);
            let calme = [
                ae3_modifier_le_masque(&st, m).await.0,
                ae3_retirer_le_masque(&st, m).await.0,
                ae3_modifier_la_destination(&st, d).await.0,
                ae3_supprimer_la_destination(&st, d).await.0,
                ae3_modifier_la_politique(&st, p).await.0,
                ae3_supprimer_la_politique(&st, p).await.0,
                ae3_modifier_le_silence(&st, s).await.0,
                ae3_lever_le_silence(&st, s).await.0,
                ae3_modifier_le_masque(&st, AE3_ABSENT).await.0,
                ae3_retirer_le_masque(&st, AE3_ABSENT).await.0,
                ae3_modifier_la_destination(&st, AE3_ABSENT).await.0,
            ];
            println!("AE3-STATUT-CALME:{}", calme.iter().map(u16::to_string).collect::<Vec<_>>().join(":"));
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::masques_destinations_alerting_lecture_ratee_et_texte_du_moteur::ae3_lignes_de_journal_des_refus",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> Vec<String> {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").split(':').map(str::to_string).collect()
        };
        let lectures = marque("AE3-STATUT-LECTURES:");
        assert_eq!(lectures[..3], ["503", "503", "503"], "contrôle : trois lectures ratées");
        let statuts = marque("AE3-STATUT-ECRITURES:");
        assert!(statuts.len() >= 12, "plancher : les douze écritures");
        assert!(statuts.iter().all(|s| s == "500"), "contrôle : douze écritures refusées : {statuts:?}");
        let ids = marque("AE3-ID-SERVI:");
        assert!(ids.len() >= 12 && ids.iter().all(|i| i.starts_with("plume-e")), "contrôle : douze identifiants servis : {ids:?}");
        let objets = marque("AE3-OBJETS:");
        assert_eq!(marque("AE3-STATUT-CALME:"), ["200", "200", "200", "204", "200", "200", "200", "200", "404", "404", "404"], "contrôle : nominal et absences");
        let est_de_ce_lot = |l: &str| ["[masques] WARN", "[destinations] WARN", "[alerting] WARN"].iter().any(|t| l.starts_with(t) || l.contains(&format!("] {t}")));
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| est_de_ce_lot(l)).map(str::to_string).collect()
        };
        let attendues_lectures = [
            format!("[masques] WARN modification du masque de champ #{} refusée : la règle n'a pas pu être lue (", lectures[3]),
            format!("[masques] WARN retrait du masque de champ #{} refusé : la règle n'a pas pu être lue (", lectures[4]),
            format!("[destinations] WARN modification de la destination #{} refusée : la destination n'a pas pu être lue (", lectures[5]),
        ];
        assert!(attendues_lectures.len() >= 3, "plancher : les trois lectures");
        let lignes = phase("lectures");
        assert_eq!(lignes.len(), attendues_lectures.len(), "phase lectures : une ligne par lecture ratée : {lignes:?}");
        for (ligne, tete) in lignes.iter().zip(attendues_lectures.iter()) {
            assert!(ligne.starts_with(tete.as_str()) && ligne.contains(AE3_MOTEUR_LECTURE), "phase lectures : sujet et cause du moteur : {ligne}");
        }
        let (m, d, p, s) = (&objets[0], &objets[1], &objets[2], &objets[3]);
        let gestes = [
            ("[masques]", "pose d'un masque de champ".to_string()),
            ("[masques]", format!("modification du masque de champ #{m}")),
            ("[masques]", format!("retrait du masque de champ #{m}")),
            ("[destinations]", "création d'une destination".to_string()),
            ("[destinations]", format!("modification de la destination #{d}")),
            ("[destinations]", format!("suppression de la destination #{d}")),
            ("[alerting]", "création d'une politique de notification".to_string()),
            ("[alerting]", format!("modification de la politique de notification #{p}")),
            ("[alerting]", format!("suppression de la politique de notification #{p}")),
            ("[alerting]", "pose d'un silence".to_string()),
            ("[alerting]", format!("modification du silence #{s}")),
            ("[alerting]", format!("levée du silence #{s}")),
        ];
        assert!(gestes.len() >= 12, "plancher : les douze gestes");
        let lignes = phase("ecritures");
        assert_eq!(lignes.len(), gestes.len(), "phase ecritures : une ligne par écriture refusée : {lignes:?}");
        for ((ligne, (module, geste)), id) in lignes.iter().zip(gestes.iter()).zip(ids.iter()) {
            let attendue = format!("[{id}] {module} WARN {geste} refusé : transaction d'audit annulée, aucune modification ({AE3_MOTEUR_ECRITURE})");
            assert_eq!(ligne, &attendue, "phase ecritures : identifiant servi, geste et cause du moteur");
        }
        let toutes: Vec<String> = stderr.lines().filter(|l| est_de_ce_lot(l)).map(str::to_string).collect();
        assert!(toutes.iter().all(|l| !l.contains(AE3_ENDPOINT) && !l.contains("10.0.0.9") && !l.contains(AE3_HOTE) && !l.contains("ae3-journal-")),
            "aucune ligne ne porte l'endpoint, les critères ni un nom : {toutes:?}");
        assert!(phase("calme").is_empty(), "le nominal et les absences n'écrivent aucune ligne : {:?}", phase("calme"));
    }
}
