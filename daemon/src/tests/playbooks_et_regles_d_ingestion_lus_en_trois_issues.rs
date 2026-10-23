// =====================================================================================
// `P10.20-l` (sites de la famille dans handlers/playbooks.rs et handlers/processors.rs) et `P10.29-l` (famille « texte
// du moteur servi ») — UNE LECTURE RATÉE D'UN PLAYBOOK OU D'UNE RÈGLE D'INGESTION N'EST PAS UNE ABSENCE, ET LE TEXTE DU
// MOTEUR NE PART PAS AU CLIENT.
//
// LE DÉFAUT, MESURÉ SUR f0df6162 AVANT LE CORRECTIF. `playbook_update`, `playbook_delete`, `processor_update` et
// `processor_delete` lisaient leur ligne par `match … { Ok(x) => x, Err(_) => return not_found(…) }` : une lecture qui
// n'avait pas eu lieu (ligne qui ne se convertit pas, table retirée) se servait 404 « playbook introuvable » / « règle
// introuvable » — un playbook toujours armé (riposte `ban_ip`) ou une règle qui rejette encore les lots entrants se
// disait inexistant. La lecture du playbook porte ce qui juge l'élévation editor -> SQL brut (`is_soql`, `managed`) et
// l'action de riposte. `playbook_create`, `playbook_update`, `processor_create` et `processor_update` refusaient une
// écriture (geste ou trace d'audit) par un 500 `échec transaction audit (aucune modification): <phrase du moteur>`.
//
// LE CORRECTIF (décision par défaut de la vague AE). Trois issues : lue, le geste suit ; absente, le 404 d'avant à
// l'identique ; lecture ratée, 503 nommé (`CAUSE_PLAYBOOK_INCHANGE_NON_LU`, `CAUSE_PLAYBOOK_NON_SUPPRIME_NON_LU`,
// `CAUSE_REGLE_D_INGESTION_INCHANGEE_NON_LU`, `CAUSE_REGLE_D_INGESTION_NON_SUPPRIMEE_NON_LU`), RIEN n'est écrit, la
// cause du moteur au journal seul avec l'identifiant de l'objet. Les quatre 500 gardent leur statut et passent par
// `servir_l_echec_de_la_transaction_d_audit` (phrase fixe `PHRASE_ECHEC_TRANSACTION_AUDIT`, cause au journal).
//
// LES PANNES ÉPROUVÉES : une colonne stockée en BLOB (la ligne existe, sa lecture échoue) et la table retirée ; un
// déclencheur `RAISE(ABORT)` sur `BEFORE INSERT ON ledger` (la trace d'audit refusée) ; les lignes de journal lues sur
// le stderr d'un sous-processus.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : par lecture (`PB_MAJ`, `PB_SUPPR`, `REGLE_MAJ`,
// `REGLE_SUPPR`) `AE2_<L>_LECTURE_EN_404`, `AE2_<L>_ABSENT_EN_503`, `AE2_<L>_CAUSE_EXPOSEE`,
// `AE2_<L>_LECTURE_FAIT_LE_GESTE`, `AE2_<L>_SANS_JOURNAL` ; par 500 (`PB_CREATION`, `PB_MAJ`, `REGLE_CREATION`,
// `REGLE_MAJ`) `AE2_<S>_MOTEUR_SERVI` et `AE2_<S>_SANS_JOURNAL` (`…_MAJ_TX_SANS_JOURNAL` pour les deux modifications) ;
// le nom de l'acteur apposé après la cause du moteur, `AE2_<L>_ACTEUR_AU_JOURNAL` et `AE2_TX_ACTEUR_AU_JOURNAL`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'écran n'est pas joué (la console peint ces 503 par la forme partagée du refus
// d'un geste, nature `refus_nomme` : `web/detection_admin.js` par `contentSubmit`/`contentDelete`, `web/processors.js`
// par `peindreLeRefusDUnGeste`) ; une lecture ratée par verrou n'est pas jouée ; le non-rechargement du registre chaud
// des processeurs sur une lecture ratée n'est pas observé (seule l'absence d'écriture l'est).
// =====================================================================================
mod playbooks_et_regles_d_ingestion_lus_en_trois_issues {
    use super::*;

    /// Ce que rusqlite écrit quand une colonne n'a pas le type demandé : la cause du moteur d'une lecture ratée.
    const AE2_MOTEUR_LECTURE: &str = "Invalid column type";
    /// La phrase du déclencheur qui refuse la trace d'audit : la cause du moteur d'une écriture refusée.
    const AE2_MOTEUR_ECRITURE: &str = "registre hors d atteinte (temoin AE2)";
    const AE2_ABSENT: i64 = 987_654;
    /// La requête des playbooks de ces témoins : elle ne doit jamais apparaître dans le journal.
    const AE2_REQUETE: &str = "search source=auth outcome=fail | stats count by src_ip";
    /// La valeur du prédicat des règles de ces témoins : elle ne doit jamais apparaître dans le journal.
    const AE2_PREDICAT: &str = "ae2-predicat-temoin";

    fn ae2_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    fn ae2_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ae2_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn ae2_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn ae2_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    /// Un 5xx nommé, EN ENTIER : exactement les clés `error` et `id`, l'erreur égale à la phrase attendue, l'identifiant
    /// de corrélation, et aucune trace de la cause du moteur.
    fn ae2_juger_5xx(quoi: &str, (statut, corps, v): &(u16, String, Value), attendu_statut: u16, phrase: &str, moteur: &str) {
        assert_eq!(*statut, attendu_statut, "{quoi} : statut : {corps}");
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"], "{quoi} : exactement `error` et `id` : {corps}");
        assert_eq!(v["error"], json!(phrase), "{quoi} : la phrase nommée, seule : {corps}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
        assert!(!corps.contains(moteur) && !corps.contains("Blob") && !corps.contains("no such table") && !corps.contains("hors d atteinte"),
            "{quoi} : la cause du moteur ne sort pas : {corps}");
    }

    async fn ae2_creer_un_playbook(st: &AppState, nom: &str) -> (u16, String, Value) {
        ae2_reponse(playbook_create(State(st.clone()), Extension(ae2_adm()),
            Json(json!({ "name": nom, "query": AE2_REQUETE, "action_kind": "ban_ip" }))).await).await
    }

    async fn ae2_modifier_un_playbook(st: &AppState, au: AuthUser, id: i64, corps: Value) -> (u16, String, Value) {
        ae2_reponse(playbook_update(State(st.clone()), Extension(au), Path(id), Json(corps)).await).await
    }

    async fn ae2_supprimer_un_playbook(st: &AppState, id: i64) -> (u16, String, Value) {
        ae2_reponse(playbook_delete(State(st.clone()), Extension(ae2_adm()), Path(id)).await).await
    }

    async fn ae2_creer_une_regle(st: &AppState, nom: &str) -> (u16, String, Value) {
        ae2_reponse(processor_create(State(st.clone()), Extension(ae2_adm()),
            Json(json!({ "name": nom, "match_field": "category", "match_op": "eq", "match_value": AE2_PREDICAT, "action": "drop" }))).await).await
    }

    async fn ae2_modifier_une_regle(st: &AppState, id: i64, corps: Value) -> (u16, String, Value) {
        ae2_reponse(processor_update(State(st.clone()), Extension(ae2_adm()), Path(id), Json(corps)).await).await
    }

    async fn ae2_supprimer_une_regle(st: &AppState, id: i64) -> (u16, String, Value) {
        ae2_reponse(processor_delete(State(st.clone()), Extension(ae2_adm()), Path(id)).await).await
    }

    /// Un objet créé par sa route, puis rendu illisible (`colonne` en BLOB) ; rend son identifiant.
    async fn ae2_illisible(st: &AppState, table: &str, colonne: &str, cree: (u16, String, Value)) -> i64 {
        let (statut, corps, v) = cree;
        assert_eq!(statut, 200, "fixture : la ligne de {table} se crée : {corps}");
        let id = v["id"].as_i64().expect("identifiant");
        ae2_sql(st, &format!("UPDATE {table} SET {colonne}=X'00' WHERE id={id}"));
        id
    }

    fn ae2_registre_refuse(st: &AppState) {
        ae2_sql(st, &format!("CREATE TRIGGER ae2_ledger_refuse BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, '{AE2_MOTEUR_ECRITURE}'); END;"));
    }

    fn ae2_registre_rendu(st: &AppState) {
        ae2_sql(st, "DROP TRIGGER ae2_ledger_refuse;");
    }

    /// CE QU'IL TIENT (modification d'un playbook) : absent, `404 {"error": "playbook introuvable"}` exactement ; ligne
    /// illisible (sa requête en BLOB) puis table retirée, `503` nommé `CAUSE_PLAYBOOK_INCHANGE_NON_LU` en entier, sans
    /// la cause du moteur — jamais `404` ; rien n'est écrit (nom d'avant, aucune modification attestée), transaction
    /// fermée. Un editor qui tente le passage au SQL brut sur la ligne illisible reçoit le même `503` (ni `403` ni
    /// `200`) et `is_soql` reste à un : la garde anti-contournement reste FERMÉE. Contrôle : un playbook lisible se
    /// modifie (`200`).
    /// MUTATIONS : `AE2_PB_MAJ_LECTURE_EN_404` (la forme d'avant), `AE2_PB_MAJ_ABSENT_EN_503`, `AE2_PB_MAJ_CAUSE_EXPOSEE`,
    /// `AE2_PB_MAJ_LECTURE_FAIT_LE_GESTE` (une lecture ratée qui modifie quand même).
    #[tokio::test]
    async fn ae2_modification_d_un_playbook_lecture_ratee_jamais_404_et_rien_n_est_ecrit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = sp_state("ae2-pb-maj");
        let (statut, corps, v) = ae2_modifier_un_playbook(&st, ae2_adm(), AE2_ABSENT, json!({ "name": "pb-ae2-x" })).await;
        assert_eq!(statut, 404, "contrôle : l'absence établie reste un 404 : {corps}");
        assert_eq!(v, json!({ "error": "playbook introuvable" }), "l'absence, rien d'autre : {corps}");

        let cree = ae2_creer_un_playbook(&st, "pb-ae2-illisible").await;
        let id = ae2_illisible(&st, "playbook", "query", cree).await;
        let r = ae2_modifier_un_playbook(&st, ae2_adm(), id, json!({ "name": "pb-ae2-renomme" })).await;
        ae2_juger_5xx("playbook illisible", &r, 503, CAUSE_PLAYBOOK_INCHANGE_NON_LU, AE2_MOTEUR_LECTURE);
        assert_eq!(ae2_texte(&st, &format!("SELECT name FROM playbook WHERE id={id}")), "pb-ae2-illisible", "rien n'est renommé");
        assert_eq!(ae2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.playbook.update'"), 0, "aucune modification attestée");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let r = ae2_modifier_un_playbook(&st, sp_au("alice", "editor"), id,
            json!({ "is_soql": false, "query": "SELECT 1", "name": "pb-ae2-eleve" })).await;
        ae2_juger_5xx("élévation editor sur un playbook illisible", &r, 503, CAUSE_PLAYBOOK_INCHANGE_NON_LU, AE2_MOTEUR_LECTURE);
        assert_eq!(ae2_compte(&st, &format!("SELECT is_soql FROM playbook WHERE id={id}")), 1, "la garde editor -> SQL brut reste fermée");
        assert_eq!(ae2_texte(&st, &format!("SELECT name FROM playbook WHERE id={id}")), "pb-ae2-illisible", "rien n'est écrit");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let (statut, corps, v) = ae2_creer_un_playbook(&st, "pb-ae2-lisible").await;
        assert_eq!(statut, 200, "{corps}");
        let lisible = v["id"].as_i64().expect("identifiant");
        let (statut, corps, _) = ae2_modifier_un_playbook(&st, ae2_adm(), lisible, json!({ "name": "pb-ae2-lisible-renomme" })).await;
        assert_eq!(statut, 200, "contrôle : un playbook lisible se modifie : {corps}");
        assert_eq!(ae2_texte(&st, &format!("SELECT name FROM playbook WHERE id={lisible}")), "pb-ae2-lisible-renomme");

        ae2_sql(&st, "ALTER TABLE playbook RENAME TO playbook_ae2_retiree;");
        let r = ae2_modifier_un_playbook(&st, ae2_adm(), lisible, json!({ "name": "pb-ae2-encore" })).await;
        ae2_juger_5xx("table des playbooks retirée", &r, 503, CAUSE_PLAYBOOK_INCHANGE_NON_LU, "no such table");
        assert_eq!(ae2_texte(&st, &format!("SELECT name FROM playbook_ae2_retiree WHERE id={lisible}")), "pb-ae2-lisible-renomme", "rien n'est écrit");
    }

    /// CE QU'IL TIENT (suppression d'un playbook) : absent, `404 {"error": "playbook introuvable"}` exactement ; ligne
    /// illisible (`managed` en BLOB) puis table retirée, `503` nommé `CAUSE_PLAYBOOK_NON_SUPPRIME_NON_LU` en entier, sans
    /// la cause du moteur ; le playbook illisible reste PRÉSENT et ARMÉ (`enabled` = 1), aucun retrait ni aucune
    /// désactivation attestés, transaction fermée. Contrôle : un playbook lisible se supprime (`200`).
    /// MUTATIONS : `AE2_PB_SUPPR_LECTURE_EN_404`, `AE2_PB_SUPPR_ABSENT_EN_503`, `AE2_PB_SUPPR_CAUSE_EXPOSEE`,
    /// `AE2_PB_SUPPR_LECTURE_FAIT_LE_GESTE` (une lecture ratée qui supprime quand même).
    #[tokio::test]
    async fn ae2_suppression_d_un_playbook_lecture_ratee_jamais_404_et_rien_n_est_supprime() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = sp_state("ae2-pb-suppr");
        let (statut, corps, v) = ae2_supprimer_un_playbook(&st, AE2_ABSENT).await;
        assert_eq!(statut, 404, "contrôle : l'absence établie reste un 404 : {corps}");
        assert_eq!(v, json!({ "error": "playbook introuvable" }), "l'absence, rien d'autre : {corps}");

        let cree = ae2_creer_un_playbook(&st, "pb-ae2-suppr-illisible").await;
        let id = ae2_illisible(&st, "playbook", "managed", cree).await;
        let r = ae2_supprimer_un_playbook(&st, id).await;
        ae2_juger_5xx("playbook illisible", &r, 503, CAUSE_PLAYBOOK_NON_SUPPRIME_NON_LU, AE2_MOTEUR_LECTURE);
        assert_eq!(ae2_compte(&st, &format!("SELECT COUNT(*) FROM playbook WHERE id={id} AND enabled=1")), 1, "le playbook illisible reste présent et armé");
        assert_eq!(ae2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind IN ('config.playbook.delete','config.playbook.disable')"), 0,
            "aucun retrait ni désactivation attestés");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let (statut, corps, v) = ae2_creer_un_playbook(&st, "pb-ae2-suppr-lisible").await;
        assert_eq!(statut, 200, "{corps}");
        let lisible = v["id"].as_i64().expect("identifiant");
        let (statut, corps, _) = ae2_supprimer_un_playbook(&st, lisible).await;
        assert_eq!(statut, 200, "contrôle : un playbook lisible se supprime : {corps}");
        assert_eq!(ae2_compte(&st, &format!("SELECT COUNT(*) FROM playbook WHERE id={lisible}")), 0);

        ae2_sql(&st, "ALTER TABLE playbook RENAME TO playbook_ae2_retiree;");
        let r = ae2_supprimer_un_playbook(&st, id).await;
        ae2_juger_5xx("table des playbooks retirée", &r, 503, CAUSE_PLAYBOOK_NON_SUPPRIME_NON_LU, "no such table");
        assert_eq!(ae2_compte(&st, &format!("SELECT COUNT(*) FROM playbook_ae2_retiree WHERE id={id}")), 1, "le playbook reste présent");
    }

    /// CE QU'IL TIENT (modification d'une règle d'ingestion) : absent, `404 {"error": "règle introuvable"}` exactement ;
    /// ligne illisible (`match_value` en BLOB) puis table retirée, `503` nommé `CAUSE_REGLE_D_INGESTION_INCHANGEE_NON_LU`
    /// en entier, sans la cause du moteur ; rien n'est écrit (nom et action d'avant, aucune modification attestée),
    /// transaction fermée. Contrôle : une règle lisible se modifie (`200`).
    /// MUTATIONS : `AE2_REGLE_MAJ_LECTURE_EN_404`, `AE2_REGLE_MAJ_ABSENT_EN_503`, `AE2_REGLE_MAJ_CAUSE_EXPOSEE`,
    /// `AE2_REGLE_MAJ_LECTURE_FAIT_LE_GESTE` (une lecture ratée qui modifie quand même).
    #[tokio::test]
    async fn ae2_modification_d_une_regle_d_ingestion_lecture_ratee_jamais_404_et_rien_n_est_ecrit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = sp_state("ae2-regle-maj");
        let (statut, corps, v) = ae2_modifier_une_regle(&st, AE2_ABSENT, json!({ "name": "regle-ae2-x" })).await;
        assert_eq!(statut, 404, "contrôle : l'absence établie reste un 404 : {corps}");
        assert_eq!(v, json!({ "error": "règle introuvable" }), "l'absence, rien d'autre : {corps}");

        let cree = ae2_creer_une_regle(&st, "regle-ae2-illisible").await;
        let id = ae2_illisible(&st, "ingest_rule", "match_value", cree).await;
        let r = ae2_modifier_une_regle(&st, id, json!({ "name": "regle-ae2-renommee", "action": "mask", "action_arg": "message" })).await;
        ae2_juger_5xx("règle illisible", &r, 503, CAUSE_REGLE_D_INGESTION_INCHANGEE_NON_LU, AE2_MOTEUR_LECTURE);
        assert_eq!(ae2_texte(&st, &format!("SELECT name || '/' || action FROM ingest_rule WHERE id={id}")), "regle-ae2-illisible/drop", "rien n'est écrit");
        assert_eq!(ae2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.ingest_rule.update'"), 0, "aucune modification attestée");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let (statut, corps, v) = ae2_creer_une_regle(&st, "regle-ae2-lisible").await;
        assert_eq!(statut, 200, "{corps}");
        let lisible = v["id"].as_i64().expect("identifiant");
        let (statut, corps, _) = ae2_modifier_une_regle(&st, lisible, json!({ "name": "regle-ae2-lisible-renommee" })).await;
        assert_eq!(statut, 200, "contrôle : une règle lisible se modifie : {corps}");
        assert_eq!(ae2_texte(&st, &format!("SELECT name FROM ingest_rule WHERE id={lisible}")), "regle-ae2-lisible-renommee");

        ae2_sql(&st, "ALTER TABLE ingest_rule RENAME TO ingest_rule_ae2_retiree;");
        let r = ae2_modifier_une_regle(&st, lisible, json!({ "name": "regle-ae2-encore" })).await;
        ae2_juger_5xx("table des règles retirée", &r, 503, CAUSE_REGLE_D_INGESTION_INCHANGEE_NON_LU, "no such table");
        assert_eq!(ae2_texte(&st, &format!("SELECT name FROM ingest_rule_ae2_retiree WHERE id={lisible}")), "regle-ae2-lisible-renommee", "rien n'est écrit");
    }

    /// CE QU'IL TIENT (suppression d'une règle d'ingestion) : absent, `404 {"error": "règle introuvable"}` exactement ;
    /// ligne illisible (`managed` en BLOB) puis table retirée, `503` nommé `CAUSE_REGLE_D_INGESTION_NON_SUPPRIMEE_NON_LU`
    /// en entier, sans la cause du moteur ; la règle illisible reste PRÉSENTE et ACTIVE, aucun retrait attesté,
    /// transaction fermée. Contrôle : une règle lisible se supprime (`200`).
    /// MUTATIONS : `AE2_REGLE_SUPPR_LECTURE_EN_404`, `AE2_REGLE_SUPPR_ABSENT_EN_503`, `AE2_REGLE_SUPPR_CAUSE_EXPOSEE`,
    /// `AE2_REGLE_SUPPR_LECTURE_FAIT_LE_GESTE` (une lecture ratée qui supprime quand même).
    #[tokio::test]
    async fn ae2_suppression_d_une_regle_d_ingestion_lecture_ratee_jamais_404_et_rien_n_est_supprime() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = sp_state("ae2-regle-suppr");
        let (statut, corps, v) = ae2_supprimer_une_regle(&st, AE2_ABSENT).await;
        assert_eq!(statut, 404, "contrôle : l'absence établie reste un 404 : {corps}");
        assert_eq!(v, json!({ "error": "règle introuvable" }), "l'absence, rien d'autre : {corps}");

        let cree = ae2_creer_une_regle(&st, "regle-ae2-suppr-illisible").await;
        let id = ae2_illisible(&st, "ingest_rule", "managed", cree).await;
        let r = ae2_supprimer_une_regle(&st, id).await;
        ae2_juger_5xx("règle illisible", &r, 503, CAUSE_REGLE_D_INGESTION_NON_SUPPRIMEE_NON_LU, AE2_MOTEUR_LECTURE);
        assert_eq!(ae2_compte(&st, &format!("SELECT COUNT(*) FROM ingest_rule WHERE id={id} AND enabled=1")), 1, "la règle illisible reste présente et active");
        assert_eq!(ae2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind IN ('config.ingest_rule.delete','config.ingest_rule.disable')"), 0,
            "aucun retrait attesté");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let (statut, corps, v) = ae2_creer_une_regle(&st, "regle-ae2-suppr-lisible").await;
        assert_eq!(statut, 200, "{corps}");
        let lisible = v["id"].as_i64().expect("identifiant");
        let (statut, corps, _) = ae2_supprimer_une_regle(&st, lisible).await;
        assert_eq!(statut, 200, "contrôle : une règle lisible se supprime : {corps}");
        assert_eq!(ae2_compte(&st, &format!("SELECT COUNT(*) FROM ingest_rule WHERE id={lisible}")), 0);

        ae2_sql(&st, "ALTER TABLE ingest_rule RENAME TO ingest_rule_ae2_retiree;");
        let r = ae2_supprimer_une_regle(&st, id).await;
        ae2_juger_5xx("table des règles retirée", &r, 503, CAUSE_REGLE_D_INGESTION_NON_SUPPRIMEE_NON_LU, "no such table");
        assert_eq!(ae2_compte(&st, &format!("SELECT COUNT(*) FROM ingest_rule_ae2_retiree WHERE id={id}")), 1, "la règle reste présente");
    }

    /// CE QU'IL TIENT (les quatre 500 d'écriture) : la trace d'audit refusée, la création et la modification d'un
    /// playbook puis d'une règle d'ingestion rendent `500` dont le corps est EXACTEMENT `{error:
    /// PHRASE_ECHEC_TRANSACTION_AUDIT, id}` — sans la phrase du moteur ; rien n'est écrit (aucun playbook ni règle de
    /// plus, noms d'avant) et la transaction est fermée.
    /// MUTATIONS : `AE2_PB_CREATION_MOTEUR_SERVI`, `AE2_PB_MAJ_MOTEUR_SERVI`, `AE2_REGLE_CREATION_MOTEUR_SERVI`,
    /// `AE2_REGLE_MAJ_MOTEUR_SERVI` (la phrase du moteur réapposée, la forme d'avant).
    #[tokio::test]
    async fn ae2_ecriture_refusee_rend_500_sans_le_texte_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = sp_state("ae2-moteur");
        let (_, corps, v) = ae2_creer_un_playbook(&st, "pb-ae2-a-modifier").await;
        let pb = v["id"].as_i64().unwrap_or_else(|| panic!("fixture : playbook créé : {corps}"));
        let (_, corps, v) = ae2_creer_une_regle(&st, "regle-ae2-a-modifier").await;
        let regle = v["id"].as_i64().unwrap_or_else(|| panic!("fixture : règle créée : {corps}"));
        ae2_registre_refuse(&st);
        let cas = [
            ("création d'un playbook", ae2_creer_un_playbook(&st, "pb-ae2-refuse").await),
            ("modification d'un playbook", ae2_modifier_un_playbook(&st, ae2_adm(), pb, json!({ "name": "pb-ae2-refuse-renomme" })).await),
            ("création d'une règle d'ingestion", ae2_creer_une_regle(&st, "regle-ae2-refusee").await),
            ("modification d'une règle d'ingestion", ae2_modifier_une_regle(&st, regle, json!({ "name": "regle-ae2-refusee-renommee" })).await),
        ];
        assert!(cas.len() >= 4, "plancher : les quatre sites");
        for (quoi, r) in &cas {
            ae2_juger_5xx(quoi, r, 500, PHRASE_ECHEC_TRANSACTION_AUDIT, AE2_MOTEUR_ECRITURE);
        }
        ae2_registre_rendu(&st);
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");
        assert_eq!(ae2_compte(&st, "SELECT COUNT(*) FROM playbook"), 1, "aucun playbook de plus");
        assert_eq!(ae2_texte(&st, &format!("SELECT name FROM playbook WHERE id={pb}")), "pb-ae2-a-modifier", "le playbook garde son nom");
        assert_eq!(ae2_compte(&st, "SELECT COUNT(*) FROM ingest_rule"), 1, "aucune règle de plus");
        assert_eq!(ae2_texte(&st, &format!("SELECT name FROM ingest_rule WHERE id={regle}")), "regle-ae2-a-modifier", "la règle garde son nom");
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus et comparées EN ENTIER : chaque lecture ratée écrit
    /// UNE ligne `[playbooks|processors] WARN <objet> #<id> NON lu… : <cause exacte du moteur>` ; chaque écriture
    /// refusée UNE ligne `[<corrélation servie>] [playbooks|processors] WARN <geste> refusé : … (<cause du moteur>)` ;
    /// rien après la cause (aucun identifiant de personne), ni la requête du playbook ni le prédicat de la règle ; le
    /// nominal et les quatre absences n'en écrivent aucune.
    /// MUTATIONS : `AE2_PB_MAJ_SANS_JOURNAL`, `AE2_PB_SUPPR_SANS_JOURNAL`, `AE2_REGLE_MAJ_SANS_JOURNAL`,
    /// `AE2_REGLE_SUPPR_SANS_JOURNAL`, `AE2_PB_CREATION_SANS_JOURNAL`, `AE2_PB_MAJ_TX_SANS_JOURNAL`,
    /// `AE2_REGLE_CREATION_SANS_JOURNAL`, `AE2_REGLE_MAJ_TX_SANS_JOURNAL` ; le nom de l'acteur apposé après la cause
    /// (`AE2_<L>_ACTEUR_AU_JOURNAL` par lecture, `AE2_TX_ACTEUR_AU_JOURNAL` dans la ligne commune des écritures).
    #[tokio::test]
    async fn ae2_lignes_de_journal_des_refus() {
        const ENFANT: &str = "AE2_ENFANT_JOURNAL";
        const PHASE: &str = "AE2-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
            let (st, _p) = sp_state("ae2-journal");
            eprintln!("{PHASE}pb_maj");
            let cree = ae2_creer_un_playbook(&st, "pb-ae2-journal-maj").await;
            let id = ae2_illisible(&st, "playbook", "query", cree).await;
            println!("AE2-STATUT-PB_MAJ:{}:{id}", ae2_modifier_un_playbook(&st, ae2_adm(), id, json!({ "name": "pb-ae2-j" })).await.0);
            eprintln!("{PHASE}pb_suppr");
            let cree = ae2_creer_un_playbook(&st, "pb-ae2-journal-suppr").await;
            let id = ae2_illisible(&st, "playbook", "managed", cree).await;
            println!("AE2-STATUT-PB_SUPPR:{}:{id}", ae2_supprimer_un_playbook(&st, id).await.0);
            eprintln!("{PHASE}regle_maj");
            let cree = ae2_creer_une_regle(&st, "regle-ae2-journal-maj").await;
            let id = ae2_illisible(&st, "ingest_rule", "match_value", cree).await;
            println!("AE2-STATUT-REGLE_MAJ:{}:{id}", ae2_modifier_une_regle(&st, id, json!({ "name": "regle-ae2-j" })).await.0);
            eprintln!("{PHASE}regle_suppr");
            let cree = ae2_creer_une_regle(&st, "regle-ae2-journal-suppr").await;
            let id = ae2_illisible(&st, "ingest_rule", "managed", cree).await;
            println!("AE2-STATUT-REGLE_SUPPR:{}:{id}", ae2_supprimer_une_regle(&st, id).await.0);
            eprintln!("{PHASE}ecritures");
            let (st, _p2) = sp_state("ae2-journal-ecritures");
            let pb = ae2_creer_un_playbook(&st, "pb-ae2-journal-a-modifier").await.2["id"].as_i64().unwrap_or(0);
            let regle = ae2_creer_une_regle(&st, "regle-ae2-journal-a-modifier").await.2["id"].as_i64().unwrap_or(0);
            ae2_registre_refuse(&st);
            let refus = [
                ae2_creer_un_playbook(&st, "pb-ae2-journal-refuse").await,
                ae2_modifier_un_playbook(&st, ae2_adm(), pb, json!({ "name": "pb-ae2-journal-refuse-renomme" })).await,
                ae2_creer_une_regle(&st, "regle-ae2-journal-refusee").await,
                ae2_modifier_une_regle(&st, regle, json!({ "name": "regle-ae2-journal-refusee-renommee" })).await,
            ];
            let [a, b, c, d] = refus.each_ref().map(|r| r.0);
            println!("AE2-STATUT-ECRITURES:{a}:{b}:{c}:{d}:{pb}:{regle}");
            // L'identifiant de corrélation servi au client : la ligne de journal se compare alors EN ENTIER.
            let [ia, ib, ic, id] = refus.each_ref().map(|r| r.2["id"].as_str().unwrap_or("").to_string());
            println!("AE2-CORRELATION-ECRITURES:{ia}:{ib}:{ic}:{id}");
            ae2_registre_rendu(&st);
            eprintln!("{PHASE}calme");
            let (st, _p3) = sp_state("ae2-journal-calme");
            let pb = ae2_creer_un_playbook(&st, "pb-ae2-calme").await.2["id"].as_i64().unwrap_or(0);
            let regle = ae2_creer_une_regle(&st, "regle-ae2-calme").await.2["id"].as_i64().unwrap_or(0);
            let m = ae2_modifier_un_playbook(&st, ae2_adm(), pb, json!({ "name": "pb-ae2-calme-renomme" })).await.0;
            let n = ae2_modifier_une_regle(&st, regle, json!({ "name": "regle-ae2-calme-renommee" })).await.0;
            let s = ae2_supprimer_un_playbook(&st, pb).await.0;
            let t = ae2_supprimer_une_regle(&st, regle).await.0;
            let w = ae2_modifier_un_playbook(&st, ae2_adm(), AE2_ABSENT, json!({ "name": "pb-ae2-x" })).await.0;
            let x = ae2_supprimer_un_playbook(&st, AE2_ABSENT).await.0;
            let y = ae2_modifier_une_regle(&st, AE2_ABSENT, json!({ "name": "regle-ae2-x" })).await.0;
            let z = ae2_supprimer_une_regle(&st, AE2_ABSENT).await.0;
            println!("AE2-STATUT-CALME:{m}:{n}:{s}:{t}:{w}:{x}:{y}:{z}");
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::playbooks_et_regles_d_ingestion_lus_en_trois_issues::ae2_lignes_de_journal_des_refus",
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
        let pb_maj = marque("AE2-STATUT-PB_MAJ:");
        let pb_suppr = marque("AE2-STATUT-PB_SUPPR:");
        let regle_maj = marque("AE2-STATUT-REGLE_MAJ:");
        let regle_suppr = marque("AE2-STATUT-REGLE_SUPPR:");
        let ecritures = marque("AE2-STATUT-ECRITURES:");
        let correlations = marque("AE2-CORRELATION-ECRITURES:");
        assert_eq!(correlations.len(), 4, "contrôle : quatre identifiants de corrélation : {correlations:?}");
        assert!(correlations.iter().all(|i| i.starts_with("plume-e")), "contrôle : identifiants de corrélation servis : {correlations:?}");
        assert_eq!([pb_maj[0].as_str(), pb_suppr[0].as_str(), regle_maj[0].as_str(), regle_suppr[0].as_str()], ["503", "503", "503", "503"],
            "contrôle : quatre lectures ratées");
        assert_eq!(ecritures[..4], ["500", "500", "500", "500"], "contrôle : quatre écritures refusées");
        assert_eq!(marque("AE2-STATUT-CALME:"), ["200", "200", "200", "200", "404", "404", "404", "404"], "contrôle : nominal et absences");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.contains("[playbooks] ") || l.contains("[processors] ")).map(str::to_string).collect()
        };
        // La cause EXACTE du moteur (rusqlite : type, rang de la colonne dans la lecture du gestionnaire, nom) : la ligne
        // se compare EN ENTIER, pour qu'aucun suffixe (nom de l'acteur, contenu de l'objet) ne passe derrière la cause.
        let lectures = [
            ("pb_maj", format!("[playbooks] WARN playbook #{} NON lu pour la modification, rien n'est modifié : ", pb_maj[1]),
                format!("{AE2_MOTEUR_LECTURE} Blob at index: 1, name: query")),
            ("pb_suppr", format!("[playbooks] WARN playbook #{} NON lu pour la suppression, rien n'est supprimé ni désactivé : ", pb_suppr[1]),
                format!("{AE2_MOTEUR_LECTURE} Blob at index: 0, name: managed")),
            ("regle_maj", format!("[processors] WARN règle d'ingestion #{} NON lue pour la modification, rien n'est modifié : ", regle_maj[1]),
                format!("{AE2_MOTEUR_LECTURE} Blob at index: 2, name: match_value")),
            ("regle_suppr", format!("[processors] WARN règle d'ingestion #{} NON lue pour la suppression, rien n'est supprimé : ", regle_suppr[1]),
                format!("{AE2_MOTEUR_LECTURE} Blob at index: 0, name: managed")),
        ];
        assert!(lectures.len() >= 4, "plancher : les quatre lectures");
        for (nom, tete, cause) in &lectures {
            let lignes = phase(nom);
            assert_eq!(lignes.len(), 1, "phase {nom} : une ligne et une seule : {lignes:?}");
            assert_eq!(lignes[0].strip_prefix(tete.as_str()), Some(cause.as_str()),
                "phase {nom} : la ligne ENTIÈRE est le sujet puis la cause du moteur, rien d'autre : {}", lignes[0]);
        }
        let (pb, regle) = (&ecritures[4], &ecritures[5]);
        let attendues = [
            format!("[{}] [playbooks] WARN création d'un playbook refusé : transaction d'audit annulée, aucune modification ({AE2_MOTEUR_ECRITURE})", correlations[0]),
            format!("[{}] [playbooks] WARN modification du playbook #{pb} refusé : transaction d'audit annulée, aucune modification ({AE2_MOTEUR_ECRITURE})", correlations[1]),
            format!("[{}] [processors] WARN création d'une règle d'ingestion refusé : transaction d'audit annulée, aucune modification ({AE2_MOTEUR_ECRITURE})", correlations[2]),
            format!("[{}] [processors] WARN modification de la règle d'ingestion #{regle} refusé : transaction d'audit annulée, aucune modification ({AE2_MOTEUR_ECRITURE})", correlations[3]),
        ];
        assert!(attendues.len() >= 4, "plancher : les quatre écritures");
        let lignes = phase("ecritures");
        assert_eq!(lignes.len(), attendues.len(), "phase ecritures : une ligne par écriture refusée : {lignes:?}");
        for (ligne, attendue) in lignes.iter().zip(attendues.iter()) {
            assert_eq!(ligne, attendue, "phase ecritures : la ligne ENTIÈRE (corrélation servie, sujet, cause du moteur), rien d'autre");
        }
        assert!(!stderr.contains(AE2_REQUETE) && !stderr.contains(AE2_PREDICAT), "le journal ne porte ni la requête ni le prédicat : {stderr}");
        assert!(phase("calme").is_empty(), "le nominal et les quatre absences n'écrivent aucune ligne : {:?}", phase("calme"));
    }
}
