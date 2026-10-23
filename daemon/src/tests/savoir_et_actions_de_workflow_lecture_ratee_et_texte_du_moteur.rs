// =====================================================================================
// `P10.20-l` (sites de la famille dans handlers/knowledge.rs et handlers/workflow_actions.rs) et `P10.29-l` (famille
// « texte du moteur servi », mêmes fichiers) — UNE LECTURE RATÉE D'UN OBJET DE SAVOIR OU D'UNE WORKFLOW-ACTION N'EST
// PAS UNE ABSENCE, ET LE TEXTE DU MOTEUR NE PART PAS AU CLIENT.
//
// LE DÉFAUT, MESURÉ SUR 536bda8a AVANT LE CORRECTIF. Les six suppressions d'objets de savoir (alias, champ calculé,
// type d'événement, étiquette, macro, recherche automatique) lisaient le nom de l'objet par
// `match … { Ok(n) => n, Err(_) => return not_found(…) }`, et `workflow_action_delete` / `workflow_action_resolve` leur
// ligne par la même forme : une lecture qui n'avait pas eu lieu (ligne qui ne se convertit pas, table retirée) se
// servait 404 — un objet toujours appliqué à TOUTES les requêtes de la plateforme, ou une action `response` qui mène à
// `/api/actions` (riposte), se disait inexistant. Trois 500 servaient la phrase du moteur SQLite : `ko_commit` et la
// création d'une workflow-action sous `échec transaction audit (aucune modification): <moteur>`, la suppression d'une
// workflow-action sous `échec transaction audit: <moteur>`.
//
// LE CORRECTIF (décision par défaut de la vague AF). Trois issues : lue, le geste suit ; absente (ou désactivée pour la
// résolution), le 404 d'avant au corps près ; lecture ratée, 503 nommé (`CAUSE_OBJET_DE_SAVOIR_NON_SUPPRIME_NON_LU`,
// `CAUSE_WORKFLOW_ACTION_NON_SUPPRIMEE_NON_LUE`, `CAUSE_WORKFLOW_ACTION_NON_RESOLUE_NON_LUE`), RIEN n'est écrit,
// supprimé ni résolu, la cause du moteur au journal seul. Les trois 500 gardent leur statut et servent
// `PHRASE_ECHEC_TRANSACTION_AUDIT` par `servir_l_echec_de_la_transaction_d_audit` (cause au journal avec l'identifiant
// de corrélation servi). La branche `UNIQUE` reste un 400 nommé (« un objet de savoir porte déjà ce nom », « une
// workflow-action porte déjà ce nom »), témoignée ici.
//
// LES PANNES ÉPROUVÉES : une colonne lue stockée en BLOB (la ligne existe, sa lecture comme texte échoue) et la table
// retirée ; un déclencheur `RAISE(ABORT)` sur `BEFORE INSERT ON ledger` (la trace d'audit refusée) ; les lignes de
// journal lues sur le stderr d'un sous-processus et comparées EN ENTIER.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : par lecture de savoir `AF3_<S>_LECTURE_EN_404`
// (S = ALIAS, CALC, EVENTTYPE, TAG, MACRO, AUTOLOOKUP) ; lecteur commun `AF3_KO_ABSENT_EN_503`, `AF3_KO_CAUSE_EXPOSEE`,
// `AF3_KO_SANS_JOURNAL`, `AF3_KO_LECTURE_FAIT_LE_GESTE` ; par lecture de workflow-action (`WFD` suppression, `WFR`
// résolution) `AF3_<L>_LECTURE_EN_404`, `_ABSENT_EN_503`, `_CAUSE_EXPOSEE`, `_SANS_JOURNAL`, `_LECTURE_FAIT_LE_GESTE` ;
// par 500 (`KO`, `WFC`, `WFD`) `AF3_<T>_MOTEUR_SERVI`, `AF3_<T>_SANS_JOURNAL_ECRITURE`, plus `AF3_KO_GESTE_IGNORE`,
// `AF3_KO_UNIQUE_RETIRE`, `AF3_WFC_UNIQUE_RETIRE`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'écran des objets de savoir (web/knowledge.js) n'est pas exercé — il peint le
// corps d'un refus de suppression par `peindreLeRefusDUnGeste`, en refus nommé (phrase entière), aucune des trois
// ouvertures « rien n'a changé » ne reconnaissant une lecture manquée ; aucun écran de la console n'appelle
// `/api/workflow-actions` ; le registre appliqué (`knowledge_reload`) non rechargé sur une lecture ratée n'est pas
// observé directement (seulement l'objet resté en base et l'absence de trace) ; une lecture ratée par verrou et le mode
// multi-tenant ne sont pas joués.
// =====================================================================================
mod savoir_et_actions_de_workflow_lecture_ratee_et_texte_du_moteur {
    use super::*;

    /// Ce que rusqlite écrit quand une colonne n'a pas le type demandé : la cause du moteur d'une lecture ratée.
    const AF3_MOTEUR_LECTURE: &str = "Invalid column type";
    /// La phrase du déclencheur qui refuse la trace d'audit : la cause du moteur d'une écriture refusée (sans « UNIQUE »).
    const AF3_MOTEUR_ECRITURE: &str = "registre hors d atteinte (temoin AF3)";
    const AF3_ABSENT: i64 = 987_654;
    /// Le nom de l'acteur : il ne doit paraître dans aucune ligne de journal de ce lot.
    const AF3_ACTEUR: &str = "af3_operatrice";
    /// La valeur soumise à la résolution : elle ne doit paraître dans aucune ligne de journal de ce lot.
    const AF3_VALEUR: &str = "192.0.2.77";

    fn af3_adm() -> AuthUser {
        sp_au(AF3_ACTEUR, "admin")
    }

    fn af3_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn af3_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn af3_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    /// Un 5xx nommé, EN ENTIER : exactement les clés `error` et `id`, l'erreur égale à la phrase attendue, l'identifiant
    /// de corrélation, et aucune trace de la cause du moteur.
    fn af3_juger_5xx(quoi: &str, (statut, corps, v): &(u16, String, Value), attendu_statut: u16, phrase: &str) {
        assert_eq!(*statut, attendu_statut, "{quoi} : statut : {corps}");
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"], "{quoi} : exactement `error` et `id` : {corps}");
        assert_eq!(v["error"], json!(phrase), "{quoi} : la phrase nommée, seule : {corps}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
        assert!(!corps.contains(AF3_MOTEUR_LECTURE) && !corps.contains("Blob") && !corps.contains("no such table")
            && !corps.contains("hors d atteinte"), "{quoi} : la cause du moteur ne sort pas : {corps}");
    }

    // ---- les six familles d'objets de savoir, par leur point d'entrée ----

    #[derive(Clone, Copy, Debug)]
    enum Af3Famille { Alias, Calc, Eventtype, Tag, Macro, AutoLookup }

    const AF3_FAMILLES: [Af3Famille; 6] =
        [Af3Famille::Alias, Af3Famille::Calc, Af3Famille::Eventtype, Af3Famille::Tag, Af3Famille::Macro, Af3Famille::AutoLookup];

    impl Af3Famille {
        /// (table, colonne lue par la suppression, 404 d'avant, sorte de trace, geste de création, objet du geste)
        fn fiche(self) -> (&'static str, &'static str, &'static str, &'static str, &'static str, &'static str) {
            match self {
                Af3Famille::Alias => ("knowledge_alias", "canonical", "alias introuvable", "alias", "création d'un alias de champ", "de l'alias"),
                Af3Famille::Calc => ("knowledge_calc", "name", "champ calculé introuvable", "calc", "création d'un champ calculé", "du champ calculé"),
                Af3Famille::Eventtype => ("knowledge_eventtype", "name", "eventtype introuvable", "eventtype", "création d'un type d'événement", "du type d'événement"),
                Af3Famille::Tag => ("knowledge_tag", "label", "tag introuvable", "tag", "création d'une étiquette", "de l'étiquette"),
                Af3Famille::Macro => ("macro_def", "name", "macro introuvable", "macro", "création d'une macro", "de la macro"),
                Af3Famille::AutoLookup => ("auto_lookup", "name", "auto-lookup introuvable", "autolookup", "création d'une recherche automatique", "de la recherche automatique"),
            }
        }

        fn corps(self, nom: &str) -> Value {
            match self {
                Af3Famille::Alias => json!({ "canonical": nom, "source": format!("{nom}_src") }),
                Af3Famille::Calc => json!({ "name": nom, "expr": "upper(severity)" }),
                Af3Famille::Eventtype => json!({ "name": nom, "filter": "source=web severity=HIGH" }),
                Af3Famille::Tag => json!({ "label": nom, "field": "user", "value": "af3" }),
                Af3Famille::Macro => json!({ "name": nom, "params": ["src"], "body": "source=$src$" }),
                Af3Famille::AutoLookup => json!({ "name": nom, "key_field": "user", "out_cols": ["proprietaire"] }),
            }
        }

        async fn creer(self, st: &AppState, nom: &str) -> (u16, String, Value) {
            let (s, a, b) = (State(st.clone()), Extension(af3_adm()), Json(self.corps(nom)));
            af3_reponse(match self {
                Af3Famille::Alias => alias_create(s, a, b).await,
                Af3Famille::Calc => calc_create(s, a, b).await,
                Af3Famille::Eventtype => eventtype_create(s, a, b).await,
                Af3Famille::Tag => tag_create(s, a, b).await,
                Af3Famille::Macro => macro_create(s, a, b).await,
                Af3Famille::AutoLookup => auto_lookup_create(s, a, b).await,
            }).await
        }

        async fn supprimer(self, st: &AppState, id: i64) -> (u16, String, Value) {
            let (s, a, p) = (State(st.clone()), Extension(af3_adm()), Path(id));
            af3_reponse(match self {
                Af3Famille::Alias => alias_delete(s, a, p).await,
                Af3Famille::Calc => calc_delete(s, a, p).await,
                Af3Famille::Eventtype => eventtype_delete(s, a, p).await,
                Af3Famille::Tag => tag_delete(s, a, p).await,
                Af3Famille::Macro => macro_delete(s, a, p).await,
                Af3Famille::AutoLookup => auto_lookup_delete(s, a, p).await,
            }).await
        }
    }

    // ---- les workflow-actions, par leur point d'entrée ----

    async fn af3_creer_une_action(st: &AppState, nom: &str, kind: &str, target: &str) -> (u16, String, Value) {
        let corps = json!({ "name": nom, "kind": kind, "scope_field": "host", "target": target });
        af3_reponse(workflow_action_create(State(st.clone()), Extension(af3_adm()), Json(corps)).await).await
    }

    async fn af3_supprimer_l_action(st: &AppState, id: i64) -> (u16, String, Value) {
        af3_reponse(workflow_action_delete(State(st.clone()), Extension(af3_adm()), Path(id)).await).await
    }

    async fn af3_resoudre_l_action(st: &AppState, id: i64) -> (u16, String, Value) {
        // la résolution est ouverte au lecteur (viewer+) : jouée sous ce rôle.
        af3_reponse(workflow_action_resolve(State(st.clone()), Extension(sp_au(AF3_ACTEUR, "viewer")), Path(id), Json(json!({ "value": AF3_VALEUR }))).await).await
    }

    fn af3_id(quoi: &str, (statut, corps, v): &(u16, String, Value)) -> i64 {
        assert_eq!(*statut, 200, "fixture : {quoi} : {corps}");
        v["id"].as_i64().unwrap_or_else(|| panic!("fixture : identifiant de {quoi} : {corps}"))
    }

    fn af3_registre_refuse(st: &AppState) {
        af3_sql(st, &format!("CREATE TRIGGER af3_ledger_refuse BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, '{AF3_MOTEUR_ECRITURE}'); END;"));
    }

    fn af3_registre_rendu(st: &AppState) {
        af3_sql(st, "DROP TRIGGER af3_ledger_refuse;");
    }

    /// CE QU'IL TIENT (suppression des six familles d'objets de savoir) : absent, `404 {"error": "<famille> introuvable"}`
    /// exactement ; colonne lue illisible puis table retirée, `503` nommé `CAUSE_OBJET_DE_SAVOIR_NON_SUPPRIME_NON_LU` en
    /// entier, sans la cause du moteur — jamais `404` ; l'objet reste en base, aucune suppression attestée, transaction
    /// fermée. Contrôle : un objet lisible se supprime (`200 {"ok": true}`).
    /// MUTATIONS : `AF3_<S>_LECTURE_EN_404` (une par famille), `AF3_KO_ABSENT_EN_503`, `AF3_KO_CAUSE_EXPOSEE`,
    /// `AF3_KO_LECTURE_FAIT_LE_GESTE`.
    #[tokio::test]
    async fn af3_suppression_d_un_objet_de_savoir_lecture_ratee_jamais_404_et_rien_n_est_supprime() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (configuration)
        let (st, _p) = sp_state("af3-savoir");
        assert!(AF3_FAMILLES.len() >= 6, "plancher : les six familles");
        for f in AF3_FAMILLES {
            let (table, colonne, introuvable, sorte, _, _) = f.fiche();
            let trace = format!("SELECT COUNT(*) FROM ledger WHERE kind='config.knowledge.{sorte}.delete'");

            let (statut, corps, v) = f.supprimer(&st, AF3_ABSENT).await;
            assert_eq!(statut, 404, "{f:?} : l'absence établie reste un 404 : {corps}");
            assert_eq!(v, json!({ "error": introuvable }), "{f:?} : l'absence, rien d'autre : {corps}");

            let id = af3_id("objet illisible", &f.creer(&st, &format!("af3_illisible_{sorte}")).await);
            af3_sql(&st, &format!("UPDATE {table} SET {colonne}=X'00' WHERE id={id}"));
            let r = f.supprimer(&st, id).await;
            af3_juger_5xx(&format!("{f:?} illisible"), &r, 503, CAUSE_OBJET_DE_SAVOIR_NON_SUPPRIME_NON_LU);
            assert_eq!(af3_compte(&st, &format!("SELECT COUNT(*) FROM {table} WHERE id={id}")), 1, "{f:?} : l'objet illisible reste en base");
            assert_eq!(af3_compte(&st, &trace), 0, "{f:?} : aucune suppression attestée");
            assert!(st.db.lock().is_autocommit(), "{f:?} : la transaction est fermée");

            let lisible = af3_id("objet lisible", &f.creer(&st, &format!("af3_lisible_{sorte}")).await);
            let (statut, corps, v) = f.supprimer(&st, lisible).await;
            assert_eq!((statut, v), (200, json!({ "ok": true })), "{f:?} : contrôle : un objet lisible se supprime : {corps}");
            assert_eq!(af3_compte(&st, &format!("SELECT COUNT(*) FROM {table} WHERE id={lisible}")), 0, "{f:?} : contrôle : il est parti");
            assert_eq!(af3_compte(&st, &trace), 1, "{f:?} : contrôle : la suppression est attestée");

            af3_sql(&st, &format!("ALTER TABLE {table} RENAME TO {table}_af3_retiree;"));
            let r = f.supprimer(&st, id).await;
            af3_juger_5xx(&format!("{f:?} table retirée"), &r, 503, CAUSE_OBJET_DE_SAVOIR_NON_SUPPRIME_NON_LU);
            assert_eq!(af3_compte(&st, &format!("SELECT COUNT(*) FROM {table}_af3_retiree WHERE id={id}")), 1, "{f:?} : l'objet reste");
            assert_eq!(af3_compte(&st, &trace), 1, "{f:?} : aucune autre suppression attestée");
            assert!(st.db.lock().is_autocommit(), "{f:?} : la transaction est fermée");
        }
    }

    /// CE QU'IL TIENT (suppression d'une workflow-action) : absente, `404 {"error": "workflow-action introuvable"}`
    /// exactement ; nom illisible puis table retirée, `503` nommé `CAUSE_WORKFLOW_ACTION_NON_SUPPRIMEE_NON_LUE` en entier,
    /// sans la cause du moteur ; l'action reste, aucune suppression attestée, transaction fermée. Contrôle : une action
    /// lisible se supprime.
    /// MUTATIONS : `AF3_WFD_LECTURE_EN_404`, `AF3_WFD_ABSENT_EN_503`, `AF3_WFD_CAUSE_EXPOSEE`,
    /// `AF3_WFD_LECTURE_FAIT_LE_GESTE`.
    #[tokio::test]
    async fn af3_suppression_d_une_workflow_action_lecture_ratee_jamais_404_et_rien_n_est_supprime() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (configuration)
        let (st, _p) = sp_state("af3-action-retrait");
        let trace = "SELECT COUNT(*) FROM ledger WHERE kind='config.workflow_action.delete'";
        let (statut, corps, v) = af3_supprimer_l_action(&st, AF3_ABSENT).await;
        assert_eq!(statut, 404, "contrôle : l'absence établie reste un 404 : {corps}");
        assert_eq!(v, json!({ "error": "workflow-action introuvable" }), "l'absence, rien d'autre : {corps}");

        let id = af3_id("action", &af3_creer_une_action(&st, "af3_action_illisible", "response", "ban_ip").await);
        af3_sql(&st, &format!("UPDATE workflow_action SET name=X'00' WHERE id={id}"));
        let r = af3_supprimer_l_action(&st, id).await;
        af3_juger_5xx("action illisible", &r, 503, CAUSE_WORKFLOW_ACTION_NON_SUPPRIMEE_NON_LUE);
        assert_eq!(af3_compte(&st, &format!("SELECT COUNT(*) FROM workflow_action WHERE id={id}")), 1, "l'action illisible reste");
        assert_eq!(af3_compte(&st, trace), 0, "aucune suppression attestée");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let lisible = af3_id("action lisible", &af3_creer_une_action(&st, "af3_action_lisible", "search", "search host=$field$").await);
        let (statut, corps, v) = af3_supprimer_l_action(&st, lisible).await;
        assert_eq!((statut, v), (200, json!({ "ok": true })), "contrôle : une action lisible se supprime : {corps}");
        assert_eq!(af3_compte(&st, trace), 1, "contrôle : la suppression est attestée");

        af3_sql(&st, "ALTER TABLE workflow_action RENAME TO workflow_action_af3_retiree;");
        let r = af3_supprimer_l_action(&st, id).await;
        af3_juger_5xx("table des actions retirée", &r, 503, CAUSE_WORKFLOW_ACTION_NON_SUPPRIMEE_NON_LUE);
        assert_eq!(af3_compte(&st, &format!("SELECT COUNT(*) FROM workflow_action_af3_retiree WHERE id={id}")), 1, "l'action reste");
        assert_eq!(af3_compte(&st, trace), 1, "aucune autre suppression attestée");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");
    }

    /// CE QU'IL TIENT (résolution d'une workflow-action) : absente ET désactivée, `404 {"error": "workflow-action
    /// introuvable ou désactivée"}` exactement (même lecture : `enabled` dans le `WHERE`) ; cible illisible d'une action
    /// `response` (riposte), genre illisible, puis table retirée : `503` nommé `CAUSE_WORKFLOW_ACTION_NON_RESOLUE_NON_LUE`
    /// en entier, sans la cause du moteur, et aucune riposte proposée. Contrôles : une action `search` puis `response`
    /// lisibles se résolvent (corps entiers).
    /// MUTATIONS : `AF3_WFR_LECTURE_EN_404`, `AF3_WFR_ABSENT_EN_503`, `AF3_WFR_CAUSE_EXPOSEE`,
    /// `AF3_WFR_LECTURE_FAIT_LE_GESTE`.
    #[tokio::test]
    async fn af3_resolution_d_une_workflow_action_lecture_ratee_jamais_404_et_rien_n_est_propose() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (configuration)
        let (st, _p) = sp_state("af3-action-resolution");
        let absente = json!({ "error": "workflow-action introuvable ou désactivée" });
        let (statut, corps, v) = af3_resoudre_l_action(&st, AF3_ABSENT).await;
        assert_eq!((statut, &v), (404, &absente), "contrôle : l'absence établie reste un 404, rien d'autre : {corps}");

        let eteinte = af3_id("action désactivée", &af3_creer_une_action(&st, "af3_action_eteinte", "response", "ban_ip").await);
        af3_sql(&st, &format!("UPDATE workflow_action SET enabled=0 WHERE id={eteinte}"));
        let (statut, corps, v) = af3_resoudre_l_action(&st, eteinte).await;
        assert_eq!((statut, &v), (404, &absente), "une action désactivée reste un 404, rien d'autre : {corps}");

        let riposte = af3_id("riposte", &af3_creer_une_action(&st, "af3_action_riposte", "response", "ban_ip").await);
        let (statut, corps, v) = af3_resoudre_l_action(&st, riposte).await;
        assert_eq!(statut, 200, "contrôle : une riposte lisible se résout : {corps}");
        assert_eq!(v, json!({ "kind": "response", "action_kind": "ban_ip", "target": AF3_VALEUR,
            "note": "à jouer via POST /api/actions (approbation + ledger)" }), "contrôle : corps entier : {corps}");
        let recherche = af3_id("recherche", &af3_creer_une_action(&st, "af3_action_recherche", "search", "search host=$field$").await);
        let (statut, corps, v) = af3_resoudre_l_action(&st, recherche).await;
        assert_eq!(statut, 200, "contrôle : une recherche lisible se résout : {corps}");
        assert_eq!(v["kind"], json!("search"), "contrôle : genre : {corps}");

        af3_sql(&st, &format!("UPDATE workflow_action SET target=X'00' WHERE id={riposte}"));
        let r = af3_resoudre_l_action(&st, riposte).await;
        af3_juger_5xx("cible de riposte illisible", &r, 503, CAUSE_WORKFLOW_ACTION_NON_RESOLUE_NON_LUE);
        assert!(!r.1.contains("action_kind") && !r.1.contains(AF3_VALEUR), "aucune riposte proposée : {}", r.1);

        af3_sql(&st, &format!("UPDATE workflow_action SET kind=X'00' WHERE id={recherche}"));
        let r = af3_resoudre_l_action(&st, recherche).await;
        af3_juger_5xx("genre illisible", &r, 503, CAUSE_WORKFLOW_ACTION_NON_RESOLUE_NON_LUE);

        af3_sql(&st, "ALTER TABLE workflow_action RENAME TO workflow_action_af3_retiree;");
        let r = af3_resoudre_l_action(&st, eteinte).await;
        af3_juger_5xx("table des actions retirée", &r, 503, CAUSE_WORKFLOW_ACTION_NON_RESOLUE_NON_LUE);
    }

    /// CE QU'IL TIENT (les trois 500 : `ko_commit` pour les douze gestes de savoir, création et suppression d'une
    /// workflow-action) : sous une trace d'audit refusée, `500` EXACTEMENT `{error: PHRASE_ECHEC_TRANSACTION_AUDIT, id}`,
    /// sans la phrase du moteur ; rien n'est créé ni supprimé, transaction fermée. Puis la branche `UNIQUE`, INCHANGÉE :
    /// un doublon de nom est un `400` `{"error": "un objet de savoir porte déjà ce nom"}` (cinq familles à contrainte
    /// d'unicité) ou `{"error": "une workflow-action porte déjà ce nom"}`, corps entier.
    /// MUTATIONS : `AF3_KO_MOTEUR_SERVI`, `AF3_WFC_MOTEUR_SERVI`, `AF3_WFD_MOTEUR_SERVI`, `AF3_KO_UNIQUE_RETIRE`,
    /// `AF3_WFC_UNIQUE_RETIRE`.
    #[tokio::test]
    async fn af3_ecritures_refusees_phrase_fixe_et_doublon_reste_un_400() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (configuration)
        let (st, _p) = sp_state("af3-ecritures");
        let mut objets = Vec::new();
        for f in AF3_FAMILLES {
            let (_, _, _, sorte, _, _) = f.fiche();
            objets.push((f, af3_id("objet", &f.creer(&st, &format!("af3_garde_{sorte}")).await)));
        }
        let action = af3_id("action", &af3_creer_une_action(&st, "af3_action_gardee", "search", "search host=$field$").await);
        af3_registre_refuse(&st);
        assert!(objets.len() >= 6, "plancher : les six familles");
        for (f, id) in &objets {
            let (table, colonne, _, sorte, _, _) = f.fiche();
            let nom = format!("af3_refuse_{sorte}");
            let r = f.creer(&st, &nom).await;
            af3_juger_5xx(&format!("{f:?} création refusée"), &r, 500, PHRASE_ECHEC_TRANSACTION_AUDIT);
            assert_eq!(af3_compte(&st, &format!("SELECT COUNT(*) FROM {table} WHERE {colonne}='{nom}'")), 0, "{f:?} : rien n'est créé");
            let r = f.supprimer(&st, *id).await;
            af3_juger_5xx(&format!("{f:?} suppression refusée"), &r, 500, PHRASE_ECHEC_TRANSACTION_AUDIT);
            assert_eq!(af3_compte(&st, &format!("SELECT COUNT(*) FROM {table} WHERE id={id}")), 1, "{f:?} : rien n'est supprimé");
            assert!(st.db.lock().is_autocommit(), "{f:?} : la transaction est fermée");
        }
        let r = af3_creer_une_action(&st, "af3_action_refusee", "search", "search host=$field$").await;
        af3_juger_5xx("création d'action refusée", &r, 500, PHRASE_ECHEC_TRANSACTION_AUDIT);
        assert_eq!(af3_compte(&st, "SELECT COUNT(*) FROM workflow_action WHERE name='af3_action_refusee'"), 0, "rien n'est créé");
        let r = af3_supprimer_l_action(&st, action).await;
        af3_juger_5xx("suppression d'action refusée", &r, 500, PHRASE_ECHEC_TRANSACTION_AUDIT);
        assert_eq!(af3_compte(&st, &format!("SELECT COUNT(*) FROM workflow_action WHERE id={action}")), 1, "rien n'est supprimé");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");
        af3_registre_rendu(&st);

        let uniques: Vec<Af3Famille> = AF3_FAMILLES.into_iter().filter(|f| !matches!(f, Af3Famille::Tag)).collect();
        assert!(uniques.len() >= 5, "plancher : les cinq familles à contrainte d'unicité");
        for f in uniques {
            let (_, _, _, sorte, _, _) = f.fiche();
            let (statut, corps, v) = f.creer(&st, &format!("af3_garde_{sorte}")).await;
            assert_eq!((statut, v), (400, json!({ "error": "un objet de savoir porte déjà ce nom" })), "{f:?} : doublon, corps entier : {corps}");
        }
        let (statut, corps, v) = af3_creer_une_action(&st, "af3_action_gardee", "search", "search host=$field$").await;
        assert_eq!((statut, v), (400, json!({ "error": "une workflow-action porte déjà ce nom" })), "doublon d'action, corps entier : {corps}");
    }

    /// CE QU'IL TIENT (journal) : chaque lecture ratée écrit UNE ligne, comparée EN ENTIER (geste, identifiant, cause du
    /// moteur rejouée sur la même base) ; chaque 500 écrit `[<id servi>] <module> WARN <geste> refusé : transaction
    /// d'audit annulée, aucune modification (<cause du moteur>)`, ligne entière, pour les douze gestes de savoir et les
    /// deux gestes d'action ; aucune ligne ne porte le nom d'un objet, de l'acteur, ni la valeur soumise ; le nominal et
    /// les absences n'écrivent rien.
    /// MUTATIONS : `AF3_KO_SANS_JOURNAL`, `AF3_WFD_SANS_JOURNAL`, `AF3_WFR_SANS_JOURNAL`, `AF3_KO_SANS_JOURNAL_ECRITURE`,
    /// `AF3_WFC_SANS_JOURNAL_ECRITURE`, `AF3_WFD_SANS_JOURNAL_ECRITURE`, `AF3_KO_GESTE_IGNORE`.
    #[tokio::test]
    async fn af3_lignes_de_journal_des_refus() {
        const ENFANT: &str = "PLUME_TEMOIN_AF3_ENFANT";
        const PHASE: &str = "AF3-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
            let (st, _p) = sp_state("af3-journal");
            let mut illisibles = Vec::new();
            for f in AF3_FAMILLES {
                let (table, colonne, _, sorte, _, _) = f.fiche();
                let id = af3_id("objet", &f.creer(&st, &format!("af3_journal_lecture_{sorte}")).await);
                af3_sql(&st, &format!("UPDATE {table} SET {colonne}=X'00' WHERE id={id}"));
                illisibles.push((f, id));
            }
            let wd = af3_id("action", &af3_creer_une_action(&st, "af3_journal_action_retrait", "response", "ban_ip").await);
            let wr = af3_id("action", &af3_creer_une_action(&st, "af3_journal_action_riposte", "response", "ban_ip").await);
            af3_sql(&st, &format!("UPDATE workflow_action SET name=X'00' WHERE id={wd}; UPDATE workflow_action SET target=X'00' WHERE id={wr};"));
            // La cause du moteur, rejouée sur la même base par la même lecture : la ligne attendue se compare en entier.
            let cause = |sql: String| -> String {
                st.db.lock().query_row(&sql, [], |r| r.get::<_, String>(0)).expect_err("fixture : la lecture rate").to_string()
            };
            let mut attendues = Vec::new();
            for (f, id) in &illisibles {
                let (table, colonne, _, _, _, objet) = f.fiche();
                let e = cause(format!("SELECT {colonne} FROM {table} WHERE id={id}"));
                attendues.push(format!("[knowledge] WARN suppression {objet} #{id} refusée : l'objet de savoir n'a pas pu être lu ({e})"));
            }
            let e = cause(format!("SELECT name FROM workflow_action WHERE id={wd}"));
            attendues.push(format!("[workflow-actions] WARN suppression de la workflow-action #{wd} refusée : l'action n'a pas pu être lue ({e})"));
            let e = st.db.lock().query_row(&format!("SELECT kind,target FROM workflow_action WHERE id={wr} AND enabled=1"), [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).expect_err("fixture : la lecture rate").to_string();
            attendues.push(format!("[workflow-actions] WARN résolution de la workflow-action #{wr} refusée : l'action n'a pas pu être lue ({e})"));
            eprintln!("{PHASE}lectures");
            let mut statuts = Vec::new();
            for (f, id) in &illisibles {
                statuts.push(f.supprimer(&st, *id).await.0);
            }
            statuts.push(af3_supprimer_l_action(&st, wd).await.0);
            statuts.push(af3_resoudre_l_action(&st, wr).await.0);
            println!("AF3-STATUT-LECTURES:{}", statuts.iter().map(u16::to_string).collect::<Vec<_>>().join(":"));
            for a in &attendues {
                println!("AF3-ATTENDUE-LECTURE:{a}");
            }
            eprintln!("{PHASE}preparation");
            let mut objets = Vec::new();
            for f in AF3_FAMILLES {
                let (_, _, _, sorte, _, _) = f.fiche();
                objets.push((f, af3_id("objet", &f.creer(&st, &format!("af3_journal_objet_{sorte}")).await)));
            }
            let action = af3_id("action", &af3_creer_une_action(&st, "af3_journal_action", "search", "search host=$field$").await);
            af3_registre_refuse(&st);
            eprintln!("{PHASE}ecritures");
            let mut rs = Vec::new();
            let mut gestes = Vec::new();
            for (f, id) in &objets {
                let (_, _, _, sorte, creation, objet) = f.fiche();
                rs.push(f.creer(&st, &format!("af3_journal_refuse_{sorte}")).await);
                gestes.push(format!("[knowledge] WARN {creation}"));
                rs.push(f.supprimer(&st, *id).await);
                gestes.push(format!("[knowledge] WARN suppression {objet} #{id}"));
            }
            rs.push(af3_creer_une_action(&st, "af3_journal_action_refusee", "search", "search host=$field$").await);
            gestes.push("[workflow-actions] WARN création d'une workflow-action".to_string());
            rs.push(af3_supprimer_l_action(&st, action).await);
            gestes.push(format!("[workflow-actions] WARN suppression de la workflow-action #{action}"));
            println!("AF3-STATUT-ECRITURES:{}", rs.iter().map(|r| r.0.to_string()).collect::<Vec<_>>().join(":"));
            for (r, g) in rs.iter().zip(gestes.iter()) {
                let id = r.2["id"].as_str().unwrap_or("");
                println!("AF3-ATTENDUE-ECRITURE:[{id}] {g} refusé : transaction d'audit annulée, aucune modification ({AF3_MOTEUR_ECRITURE})");
            }
            af3_registre_rendu(&st);
            eprintln!("{PHASE}calme");
            let (st, _p) = sp_state("af3-journal-calme");
            let mut calme = Vec::new();
            for f in AF3_FAMILLES {
                let (_, _, _, sorte, _, _) = f.fiche();
                let id = af3_id("objet", &f.creer(&st, &format!("af3_calme_{sorte}")).await);
                calme.push(f.supprimer(&st, id).await.0);
                calme.push(f.supprimer(&st, AF3_ABSENT).await.0);
            }
            let a = af3_id("action", &af3_creer_une_action(&st, "af3_calme_action", "response", "ban_ip").await);
            calme.push(af3_resoudre_l_action(&st, a).await.0);
            calme.push(af3_supprimer_l_action(&st, a).await.0);
            calme.push(af3_supprimer_l_action(&st, AF3_ABSENT).await.0);
            calme.push(af3_resoudre_l_action(&st, AF3_ABSENT).await.0);
            println!("AF3-STATUT-CALME:{}", calme.iter().map(u16::to_string).collect::<Vec<_>>().join(":"));
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::savoir_et_actions_de_workflow_lecture_ratee_et_texte_du_moteur::af3_lignes_de_journal_des_refus",
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
        let lignes_marquees = |m: &str| -> Vec<String> {
            stdout.lines().filter_map(|l| l.split_once(m).map(|(_, r)| r.to_string())).collect()
        };
        let lectures = marque("AF3-STATUT-LECTURES:");
        assert!(lectures.len() >= 8, "plancher : les huit lectures");
        assert!(lectures.iter().all(|s| s == "503"), "contrôle : huit lectures ratées : {lectures:?}");
        let ecritures = marque("AF3-STATUT-ECRITURES:");
        assert!(ecritures.len() >= 14, "plancher : les quatorze écritures");
        assert!(ecritures.iter().all(|s| s == "500"), "contrôle : quatorze écritures refusées : {ecritures:?}");
        assert_eq!(marque("AF3-STATUT-CALME:"),
            ["200", "404", "200", "404", "200", "404", "200", "404", "200", "404", "200", "404", "200", "200", "404", "404"],
            "contrôle : nominal et absences");
        let est_de_ce_lot = |l: &str| ["[knowledge] WARN", "[workflow-actions] WARN"].iter().any(|t| l.starts_with(t) || l.contains(&format!("] {t}")));
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| est_de_ce_lot(l)).map(str::to_string).collect()
        };
        let attendues = lignes_marquees("AF3-ATTENDUE-LECTURE:");
        assert!(attendues.len() >= 8, "plancher : une ligne attendue par lecture");
        assert_eq!(phase("lectures"), attendues, "phase lectures : une ligne par lecture ratée, en entier");
        assert!(attendues.iter().all(|l| l.contains(AF3_MOTEUR_LECTURE)), "contrôle : la cause rejouée est celle du moteur : {attendues:?}");
        let attendues = lignes_marquees("AF3-ATTENDUE-ECRITURE:");
        assert!(attendues.len() >= 14, "plancher : une ligne attendue par écriture");
        assert!(attendues.iter().all(|l| l.starts_with("[plume-e")), "contrôle : identifiants servis : {attendues:?}");
        assert_eq!(phase("ecritures"), attendues, "phase ecritures : identifiant servi, geste et cause du moteur, en entier");
        let toutes: Vec<String> = stderr.lines().filter(|l| est_de_ce_lot(l)).map(str::to_string).collect();
        assert!(toutes.iter().all(|l| !l.contains("af3_journal_") && !l.contains(AF3_ACTEUR) && !l.contains(AF3_VALEUR)),
            "aucune ligne ne porte un nom d'objet, l'acteur ni la valeur soumise : {toutes:?}");
        assert!(phase("calme").is_empty(), "le nominal et les absences n'écrivent aucune ligne : {:?}", phase("calme"));
    }
}
