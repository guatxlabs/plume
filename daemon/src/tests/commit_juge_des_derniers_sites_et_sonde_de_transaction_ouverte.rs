// =====================================================================================
// `P10.25-g`, `P10.26-x` — LES DERNIERS `COMMIT` AVALÉS SONT JUGÉS. `P10.27-g` — LA SONDE D'UNE TRANSACTION OUVERTE.
//
// Depuis `P10.26-s`, une transaction laissée ouverte sur l'écrivain partagé n'est plus validée par accident par le geste
// suivant : elle BLOQUE l'ingestion (503, lots gardés au spool), le pli des hôtes, le reparse et l'envoi des puits
// jusqu'au redémarrage. Chaque `let _ = … execute_batch("COMMIT")` restant pouvait en laisser une : ces témoins tiennent,
// geste par geste, qu'un `COMMIT` refusé (autorisateur SQLite) rend le refus NOMMÉ du geste, FERME la transaction, ne
// laisse rien de validé à froid (connexion neuve sur le même fichier, ce qu'un redémarrage relit) ni rien de pendant
// pour ce processus (lecture par l'écrivain), et ne recharge rien en mémoire.
//
// LA FORME DU JUGEMENT : chaque geste refusé est jugé par `cjds_juger`, qui relève TOUTES les propriétés avant de
// conclure et nomme celles qui manquent. Rejouées sur la forme d'avant (mutation : le `COMMIT` rendu à `let _ =`), elles
// disent le défaut mesuré, pas seulement le premier symptôme.
//
// LES DÉFAUTS, MESURÉS LE 2026-09-24 SUR LA FORME D'AVANT, SITE PAR SITE (quarante-huit mutations en six tours, un site
// par fichier et par tour, empreintes des sources vérifiées identiques après chaque restauration) :
//  * les quarante et un `COMMIT` avalés rendaient 200 (204 pour les canaux), laissaient la transaction OUVERTE sur
//    l'écrivain, et ce processus lisait l'état pendant (règle, politique, silence, destination, indicateur… créés pour
//    lui, absents à froid ; supprimés pour lui, présents à froid) ; la création d'un canal rendait même son `id` ;
//  * le parseur créé était CHARGÉ par l'ingestion depuis la transaction pendante, le parseur modifié y remplaçait
//    l'ancien motif — rien de cela n'existait à froid ;
//  * les cinq gestes des runbooks (garde `Txn`) fermaient bien leur transaction, mais rendaient le succès ;
//  * le poll manuel et l'envoi manuel rendaient une réponse identique à celle d'un geste tracé : l'absence de trace
//    n'était dite nulle part.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les deux `COMMIT` que ce lot laissait avalés (`report_create`,
// `workflow_action_create`) sont jugés depuis le lot suivant et tenus par les témoins `isdl_` (ensemble toléré de
// `check_a_transaction_boundary_is_never_swallowed.py` désormais vide) ; les deux fins d'instantané de lecture (ventilation, sauvegarde en
// flux), dont seule l'aide commune est jouée ici (une connexion du pool de lecture ou privée n'accepte pas d'autorisateur
// posé depuis un témoin) — leur câblage est tenu par la garde ; un `COMMIT` que SQLite annule de lui-même (disque plein,
// E/S) et le mode multi-tenant ne sont pas joués ; aucun module de `web/` n'est exercé.
// =====================================================================================
mod commit_juge_des_derniers_sites_et_sonde_de_transaction_ouverte {
    use super::*;
    use crate::handlers::transaction_validee::{
        fermer_l_instantane_de_lecture, signaler_une_transaction_ouverte_hors_de_tout_geste,
        transactions_ouvertes_hors_de_tout_geste,
    };
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    /// `COMMIT` (et `END`) refusés sur l'écrivain partagé ; `BEGIN` et `ROLLBACK` restent permis.
    fn cjds_refuser_le_commit(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn cjds_lever_l_autorisateur(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    async fn cjds_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
        (statut, corps)
    }

    /// Ce que rend un geste joué sous un `COMMIT` refusé : statut, corps, et si la transaction est FERMÉE après lui.
    struct CjdsRefus {
        statut: u16,
        corps: Value,
        fermee: bool,
    }

    async fn cjds_sous_commit_refuse(st: &AppState, geste: impl std::future::Future<Output = Response>) -> CjdsRefus {
        cjds_refuser_le_commit(st);
        let r = geste.await;
        let fermee = st.db.lock().is_autocommit();
        cjds_lever_l_autorisateur(st);
        let (statut, corps) = cjds_corps(r).await;
        CjdsRefus { statut, corps, fermee }
    }

    /// Le jugement : TOUTES les propriétés relevées d'abord, puis une seule conclusion qui nomme celles qui manquent.
    fn cjds_juger(quoi: &str, refus: &CjdsRefus, autres: &[(&str, bool)]) {
        let mut manquent: Vec<String> = Vec::new();
        if !refus.fermee {
            manquent.push("transaction FERMÉE".into());
        }
        for (propriete, tenue) in autres {
            if !tenue {
                manquent.push((*propriete).to_string());
            }
        }
        assert!(manquent.is_empty(), "{quoi} : manquent {manquent:?} — statut {}, corps {}", refus.statut, refus.corps);
    }

    /// Le refus nommé d'une route : 503 et la cause du geste sous `error`.
    fn cjds_refus_nomme(refus: &CjdsRefus, cause: &str) -> [(&'static str, bool); 2] {
        [("statut 503", refus.statut == 503), ("cause nommée sous `error`", refus.corps["error"] == json!(cause))]
    }

    fn cjds_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    /// Ce que le processus lit, sur l'écrivain partagé (il voit une transaction PENDANTE).
    fn cjds_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// Ce qu'un redémarrage relirait : une connexion NEUVE sur le même fichier ne voit que ce qui est validé.
    fn cjds_a_froid(p: &crate::tmp_possede::TmpDb, sql: &str) -> i64 {
        let c = open_db(p.as_str()).expect("relecture à froid");
        c.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture à froid de `{sql}` ({e})"))
    }

    fn cjds_ecrire(st: &AppState, sql: &str) -> i64 {
        let c = st.db.lock();
        c.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
        c.last_insert_rowid()
    }

    // -------------------------------------------------------------------------------------
    // (1) `detection.rs` — RÈGLES ET PARSEURS : rien d'écrit, et le parseur n'est pas RECHARGÉ dans l'ingestion
    // -------------------------------------------------------------------------------------

    fn cjds_parseur_charge(db_path: &str, motif: &str) -> bool {
        parsers_cell().read().get(db_path).map(|l| l.iter().any(|(_, re)| re.as_str() == motif)).unwrap_or(false)
    }

    /// CE QU'IL TIENT : création et modification d'une règle, création et modification d'un parseur, sous un `COMMIT`
    /// refusé — 503 nommé, transaction fermée, rien à froid ni pour ce processus, et le registre des parseurs de
    /// l'ingestion n'a pas chargé le motif. Levé, chaque geste aboutit (la fixture est saine).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre l'un des quatre `COMMIT` à `let _ =` (la forme d'avant).
    #[tokio::test]
    async fn cjds_detection_regles_et_parseurs_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-detection");
        let adm = cjds_adm();
        let db_path = req_db_path(&st, &adm);
        let regle = json!({ "name": "cjds-regle", "query": "search source=auth outcome=fail | stats count", "threshold": 3 });

        let r = cjds_sous_commit_refuse(&st, rule_create(State(st.clone()), Extension(adm.clone()), Json(regle.clone()))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_REGLE_NON_CREEE);
        cjds_juger("création de règle", &r, &[a, b,
            ("aucune règle à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM rule WHERE name='cjds-regle'") == 0),
            ("aucune règle pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM rule WHERE name='cjds-regle'") == 0)]);
        let (statut, corps) = cjds_corps(rule_create(State(st.clone()), Extension(adm.clone()), Json(regle)).await).await;
        assert_eq!(statut, 200, "levé, la règle est créée : {corps}");
        let id = corps["id"].as_i64().expect("identifiant de règle");

        let r = cjds_sous_commit_refuse(&st, rule_update(State(st.clone()), Extension(adm.clone()), Path(id), Json(json!({ "threshold": 9 })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_REGLE_INCHANGEE);
        let sql = format!("SELECT CAST(threshold AS INTEGER) FROM rule WHERE id={id}");
        cjds_juger("modification de règle", &r, &[a, b,
            ("seuil d'avant à froid", cjds_a_froid(&p, &sql) == 3),
            ("seuil d'avant pour ce processus", cjds_compte(&st, &sql) == 3)]);

        let motif = "cjds=(?P<cjds_champ>\\w+)";
        let parseur = json!({ "name": "cjds-parseur", "source": "cjds", "pattern": motif });
        let r = cjds_sous_commit_refuse(&st, parser_create(State(st.clone()), Extension(adm.clone()), Json(parseur.clone()))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_PARSEUR_NON_CREE);
        cjds_juger("création de parseur", &r, &[a, b,
            ("aucun parseur à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM parser WHERE name='cjds-parseur'") == 0),
            ("motif NON chargé par l'ingestion", !cjds_parseur_charge(&db_path, motif))]);
        let (statut, corps) = cjds_corps(parser_create(State(st.clone()), Extension(adm.clone()), Json(parseur)).await).await;
        assert_eq!(statut, 200, "levé, le parseur est créé : {corps}");
        let pid = corps["id"].as_i64().expect("identifiant de parseur");
        assert!(cjds_parseur_charge(&db_path, motif), "levé, le motif est chargé (contrôle positif du registre)");

        let motif2 = "cjds2=(?P<cjds_autre>\\w+)";
        let r = cjds_sous_commit_refuse(&st, parser_update(State(st.clone()), Extension(adm.clone()), Path(pid), Json(json!({ "pattern": motif2 })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_PARSEUR_INCHANGE);
        let sql = format!("SELECT COUNT(*) FROM parser WHERE id={pid} AND pattern='{}'", motif.replace('\'', "''"));
        cjds_juger("modification de parseur", &r, &[a, b,
            ("motif d'avant à froid", cjds_a_froid(&p, &sql) == 1),
            ("nouveau motif NON chargé", !cjds_parseur_charge(&db_path, motif2)),
            ("motif d'avant toujours chargé", cjds_parseur_charge(&db_path, motif))]);
    }

    // -------------------------------------------------------------------------------------
    // (2) `detection.rs` — SUPPRESSION GÉRÉE ET BASCULE D'ACTIVATION (`delete_managed_row_tx`, `set_content_enabled_tx`)
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la bascule d'activation et la suppression d'une règle ad-hoc, sous un `COMMIT` refusé — 503
    /// nommé, transaction fermée, la règle toujours active et présente, à froid comme pour ce processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre le `COMMIT` de `set_content_enabled_tx` ou de `delete_managed_row_tx` à
    /// `let _ =`.
    #[tokio::test]
    async fn cjds_detection_suppression_et_activation_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-gere");
        let adm = cjds_adm();
        let id = cjds_ecrire(&st, "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,managed) \
                                   VALUES('cjds-geree',1,'search source=auth | stats count',1,'>',0,2,300,3600,2)");
        let sql = format!("SELECT COUNT(*) FROM rule WHERE id={id} AND enabled=1");

        let r = cjds_sous_commit_refuse(&st, rule_set_enabled(State(st.clone()), Extension(adm.clone()), Path(id), Json(json!({ "enabled": false })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_ACTIVATION_DE_CONTENU_INCHANGEE);
        cjds_juger("désactivation de règle", &r, &[a, b,
            ("toujours active à froid", cjds_a_froid(&p, &sql) == 1),
            ("toujours active pour ce processus", cjds_compte(&st, &sql) == 1),
            ("aucune dérogation retenue", cjds_a_froid(&p, "SELECT COUNT(*) FROM detection_override") == 0)]);

        let r = cjds_sous_commit_refuse(&st, rule_delete(State(st.clone()), Extension(adm.clone()), Path(id))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_SUPPRESSION_DE_CONTENU_NON_VALIDEE);
        cjds_juger("suppression de règle", &r, &[a, b,
            ("toujours là à froid", cjds_a_froid(&p, &sql) == 1),
            ("toujours là pour ce processus", cjds_compte(&st, &sql) == 1)]);

        let (statut, corps) = cjds_corps(rule_delete(State(st.clone()), Extension(adm.clone()), Path(id)).await).await;
        assert_eq!(statut, 200, "levé, la suppression a lieu : {corps}");
        assert_eq!(cjds_a_froid(&p, &sql), 0, "et elle est validée");
    }

    // -------------------------------------------------------------------------------------
    // (3) `alerting.rs` — POLITIQUES DE NOTIFICATION ET SILENCES
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : les six gestes (politique créée, modifiée, supprimée ; silence posé, modifié, levé) sous un
    /// `COMMIT` refusé — 503 nommé, transaction fermée, rien de changé à froid ni pour ce processus (qui lit le routage et
    /// les silences actifs par l'écrivain). Le silence non levé ÉTOUFFE toujours, comme sa cause le dit.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre l'un des six `COMMIT` à `let _ =`.
    #[tokio::test]
    async fn cjds_alerting_politiques_et_silences_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-alerting");
        let adm = cjds_adm();
        let politique = json!({ "matchers": { "host": "web-01" }, "contact_points": [1] });

        let r = cjds_sous_commit_refuse(&st, policy_create(State(st.clone()), Extension(adm.clone()), Json(politique.clone()))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_POLITIQUE_DE_NOTIFICATION_NON_CREEE);
        cjds_juger("création de politique", &r, &[a, b,
            ("aucune politique à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM notification_policy") == 0),
            ("aucune politique pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM notification_policy") == 0)]);
        let (statut, corps) = cjds_corps(policy_create(State(st.clone()), Extension(adm.clone()), Json(politique)).await).await;
        assert_eq!(statut, 200, "levé, la politique est créée : {corps}");
        let pid = corps["id"].as_i64().expect("identifiant de politique");
        let sql = format!("SELECT COUNT(*) FROM notification_policy WHERE id={pid} AND contact_points='1'");

        let r = cjds_sous_commit_refuse(&st, policy_update(State(st.clone()), Extension(adm.clone()), Path(pid),
            Json(json!({ "matchers": { "host": "web-02" }, "contact_points": [2] })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_POLITIQUE_DE_NOTIFICATION_INCHANGEE);
        cjds_juger("modification de politique", &r, &[a, b,
            ("canaux d'avant à froid", cjds_a_froid(&p, &sql) == 1),
            ("canaux d'avant pour ce processus", cjds_compte(&st, &sql) == 1)]);

        let r = cjds_sous_commit_refuse(&st, policy_delete(State(st.clone()), Extension(adm.clone()), Path(pid))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_POLITIQUE_DE_NOTIFICATION_NON_SUPPRIMEE);
        cjds_juger("suppression de politique", &r, &[a, b,
            ("toujours là à froid", cjds_a_froid(&p, &sql) == 1),
            ("toujours là pour ce processus", cjds_compte(&st, &sql) == 1)]);

        let silence = json!({ "matchers": { "host": "web-01" }, "duration_s": 600, "reason": "cjds" });
        let r = cjds_sous_commit_refuse(&st, silence_create(State(st.clone()), Extension(adm.clone()), Json(silence.clone()))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_SILENCE_NON_POSE);
        cjds_juger("pose de silence", &r, &[a, b,
            ("aucun silence à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM silence") == 0),
            ("aucun silence pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM silence") == 0)]);
        let (statut, corps) = cjds_corps(silence_create(State(st.clone()), Extension(adm.clone()), Json(silence)).await).await;
        assert_eq!(statut, 200, "levé, le silence est posé : {corps}");
        let sid = corps["id"].as_i64().expect("identifiant de silence");
        let sql = format!("SELECT COUNT(*) FROM silence WHERE id={sid} AND reason='cjds'");

        let r = cjds_sous_commit_refuse(&st, silence_update(State(st.clone()), Extension(adm.clone()), Path(sid), Json(json!({ "reason": "autre" })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_SILENCE_INCHANGE);
        cjds_juger("modification de silence", &r, &[a, b,
            ("raison d'avant à froid", cjds_a_froid(&p, &sql) == 1),
            ("raison d'avant pour ce processus", cjds_compte(&st, &sql) == 1)]);

        let r = cjds_sous_commit_refuse(&st, silence_delete(State(st.clone()), Extension(adm.clone()), Path(sid))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_SILENCE_NON_LEVE);
        cjds_juger("levée de silence", &r, &[a, b,
            ("toujours là à froid", cjds_a_froid(&p, &sql) == 1),
            ("toujours là pour ce processus, qui étouffe donc toujours", cjds_compte(&st, &sql) == 1)]);
    }

    // -------------------------------------------------------------------------------------
    // (4) `detection_advanced.rs` — CORRÉLATIONS ET RÉFÉRENCES UEBA
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : création et modification d'une corrélation et d'une référence UEBA sous un `COMMIT` refusé —
    /// 503 nommé, transaction fermée, rien de changé à froid ni pour ce processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre l'un des quatre `COMMIT` à `let _ =`.
    #[tokio::test]
    async fn cjds_detection_avancee_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-avancee");
        let adm = cjds_adm();
        let correlation = json!({ "name": "cjds-corr", "key_field": "src_ip", "entity_type": "ip", "window_s": 3600,
            "steps": [{ "name": "s1", "query": "search source=auth outcome=fail", "min_count": 3 },
                      { "name": "s2", "query": "search source=auth outcome=success", "min_count": 1 }] });
        let r = cjds_sous_commit_refuse(&st, correlation_create(State(st.clone()), Extension(adm.clone()), Json(correlation.clone()))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_CORRELATION_NON_CREEE);
        cjds_juger("création de corrélation", &r, &[a, b,
            ("aucune corrélation à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM correlation WHERE name='cjds-corr'") == 0),
            ("aucune pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM correlation WHERE name='cjds-corr'") == 0)]);
        let (statut, corps) = cjds_corps(correlation_create(State(st.clone()), Extension(adm.clone()), Json(correlation)).await).await;
        assert_eq!(statut, 200, "levé, la corrélation est créée : {corps}");
        let cid = corps["id"].as_i64().expect("identifiant de corrélation");
        let r = cjds_sous_commit_refuse(&st, correlation_update(State(st.clone()), Extension(adm.clone()), Path(cid), Json(json!({ "severity": 5 })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_CORRELATION_INCHANGEE);
        let sql = format!("SELECT COUNT(*) FROM correlation WHERE id={cid} AND severity=5");
        cjds_juger("modification de corrélation", &r, &[a, b,
            ("sévérité d'avant à froid", cjds_a_froid(&p, &sql) == 0),
            ("sévérité d'avant pour ce processus", cjds_compte(&st, &sql) == 0)]);

        let reference = json!({ "name": "cjds-base", "query": "search source=auth | stats count by host", "entity_field": "host", "entity_type": "host" });
        let r = cjds_sous_commit_refuse(&st, baseline_create(State(st.clone()), Extension(adm.clone()), Json(reference.clone()))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_REFERENCE_UEBA_NON_CREEE);
        cjds_juger("création de référence UEBA", &r, &[a, b,
            ("aucune référence à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM ueba_baseline WHERE name='cjds-base'") == 0),
            ("aucune pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM ueba_baseline WHERE name='cjds-base'") == 0)]);
        let (statut, corps) = cjds_corps(baseline_create(State(st.clone()), Extension(adm.clone()), Json(reference)).await).await;
        assert_eq!(statut, 200, "levé, la référence est créée : {corps}");
        let bid = corps["id"].as_i64().expect("identifiant de référence");
        let r = cjds_sous_commit_refuse(&st, baseline_update(State(st.clone()), Extension(adm.clone()), Path(bid), Json(json!({ "severity": 4 })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_REFERENCE_UEBA_INCHANGEE);
        let sql = format!("SELECT COUNT(*) FROM ueba_baseline WHERE id={bid} AND severity=4");
        cjds_juger("modification de référence UEBA", &r, &[a, b,
            ("sévérité d'avant à froid", cjds_a_froid(&p, &sql) == 0),
            ("sévérité d'avant pour ce processus", cjds_compte(&st, &sql) == 0)]);
    }

    // -------------------------------------------------------------------------------------
    // (5) `notifiers.rs` — CANAUX DE NOTIFICATION (types de réponse gardés)
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : les trois gestes rendent le 503 NOMMÉ de leur geste (`P10.28-c`, `P10.28-q` : la création ne
    /// refuse plus par un deux cents `{error}`, la modification et la suppression ne rendent plus un 503 sans corps) ;
    /// transaction fermée, rien de changé à froid ni pour ce processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre l'un des trois `COMMIT` à `let _ =`.
    #[tokio::test]
    async fn cjds_canaux_de_notification_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-canaux");
        let adm = cjds_adm();
        let canal = json!({ "kind": "webhook", "url": "http://10.0.0.9/cjds", "name": "cjds-canal" });
        let r = cjds_sous_commit_refuse(&st, async { notifier_create(State(st.clone()), Extension(adm.clone()), Json(canal.clone())).await.into_response() }).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_CANAL_DE_NOTIFICATION_NON_CREE);
        cjds_juger("création de canal", &r, &[a, b,
            ("aucun identifiant d'objet rendu (seul l'identifiant du 5xx)", r.corps.get("id").and_then(|v| v.as_i64()).is_none()),
            ("aucun canal à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM notifier WHERE name='cjds-canal'") == 0),
            ("aucun canal pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM notifier WHERE name='cjds-canal'") == 0)]);
        let (_, v) = cjds_corps(notifier_create(State(st.clone()), Extension(adm.clone()), Json(canal)).await).await;
        let nid = v["id"].as_i64().unwrap_or_else(|| panic!("levé, le canal est créé : {v}"));
        let sql = format!("SELECT COUNT(*) FROM notifier WHERE id={nid} AND name='cjds-canal'");

        let r = cjds_sous_commit_refuse(&st, async {
            notifier_update(State(st.clone()), Extension(adm.clone()), Path(nid), Json(json!({ "name": "cjds-renomme" }))).await.into_response()
        }).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_CANAL_DE_NOTIFICATION_INCHANGE);
        cjds_juger("modification de canal", &r, &[a, b,
            ("nom d'avant à froid", cjds_a_froid(&p, &sql) == 1),
            ("nom d'avant pour ce processus", cjds_compte(&st, &sql) == 1)]);

        let r = cjds_sous_commit_refuse(&st, async { notifier_delete(State(st.clone()), Extension(adm.clone()), Path(nid)).await.into_response() }).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_CANAL_DE_NOTIFICATION_NON_SUPPRIME);
        cjds_juger("suppression de canal", &r, &[a, b,
            ("toujours là à froid", cjds_a_froid(&p, &sql) == 1),
            ("toujours là pour ce processus", cjds_compte(&st, &sql) == 1)]);
    }

    // -------------------------------------------------------------------------------------
    // (6) `destinations.rs` — DESTINATIONS DE SORTIE, ET LA TRACE DE L'ENVOI MANUEL
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : création, modification (désactivation) et suppression d'une destination sous un `COMMIT` refusé —
    /// 503 nommé, transaction fermée, rien de changé ; l'envoi manuel (type `s3`, sans réseau) rend son bilan AVEC
    /// `trace_non_ecrite`, sans ligne de registre ; levé, la trace est écrite et le champ absent.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre l'un des trois `COMMIT` à `let _ =`, ou la trace de l'envoi à la forme
    /// `if let Ok(tx) = Txn::begin(..) { … let _ = tx.commit(); }`.
    #[tokio::test]
    async fn cjds_destinations_et_trace_de_l_envoi_manuel_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-destinations");
        let adm = cjds_adm();
        let sortie = json!({ "type": "webhook", "name": "cjds-sortie", "endpoint": "http://10.0.0.9/cjds", "enabled": true });
        let r = cjds_sous_commit_refuse(&st, destination_create(State(st.clone()), Extension(adm.clone()), Json(sortie.clone()))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_DESTINATION_NON_CREEE);
        cjds_juger("création de destination", &r, &[a, b,
            ("aucune destination à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM destination") == 0),
            ("aucune pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM destination") == 0)]);
        let (statut, corps) = cjds_corps(destination_create(State(st.clone()), Extension(adm.clone()), Json(sortie)).await).await;
        assert_eq!(statut, 200, "levé, la destination est créée : {corps}");
        let did = corps["id"].as_i64().expect("identifiant de destination");
        let sql = format!("SELECT COUNT(*) FROM destination WHERE id={did} AND enabled=1");

        let r = cjds_sous_commit_refuse(&st, destination_update(State(st.clone()), Extension(adm.clone()), Path(did), Json(json!({ "enabled": false })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_DESTINATION_INCHANGEE);
        cjds_juger("désactivation de destination", &r, &[a, b,
            ("toujours active à froid", cjds_a_froid(&p, &sql) == 1),
            ("toujours active pour ce processus", cjds_compte(&st, &sql) == 1)]);

        let r = cjds_sous_commit_refuse(&st, destination_delete(State(st.clone()), Extension(adm.clone()), Path(did))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_DESTINATION_NON_SUPPRIMEE);
        cjds_juger("suppression de destination", &r, &[a, b,
            ("toujours là à froid", cjds_a_froid(&p, &sql) == 1),
            ("toujours là pour ce processus", cjds_compte(&st, &sql) == 1)]);

        let stub = cjds_ecrire(&st, "INSERT INTO destination(type,name,enabled,endpoint) VALUES('s3','cjds-stub',1,'s3://cjds')");
        let traces = "SELECT COUNT(*) FROM ledger WHERE kind='config.destination.flush'";
        let r = cjds_sous_commit_refuse(&st, destination_flush(State(st.clone()), Extension(adm.clone()), Path(stub))).await;
        cjds_juger("trace de l'envoi manuel", &r, &[("statut 200 (l'envoi a eu lieu)", r.statut == 200),
            ("`trace_non_ecrite` nommée", r.corps["trace_non_ecrite"] == json!(CAUSE_TRACE_DE_L_ENVOI_MANUEL_NON_ECRITE)),
            ("aucune trace à froid", cjds_a_froid(&p, traces) == 0),
            ("aucune trace pour ce processus", cjds_compte(&st, traces) == 0)]);
        let (statut, corps) = cjds_corps(destination_flush(State(st.clone()), Extension(adm.clone()), Path(stub)).await).await;
        assert_eq!(statut, 200, "levé, l'envoi manuel répond : {corps}");
        assert!(corps.get("trace_non_ecrite").is_none(), "levé, la trace est écrite et le champ absent : {corps}");
        assert_eq!(cjds_a_froid(&p, traces), 1, "levé, la trace est validée");
    }

    // -------------------------------------------------------------------------------------
    // (7) `incidents.rs` — RUNBOOKS (garde `Txn`)
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : les cinq gestes des runbooks (création, modification, bascule d'activation, clonage,
    /// suppression) sous un `COMMIT` refusé — 503 nommé (la forme d'avant rendait le succès), transaction fermée par le
    /// garde, rien de changé à froid ni pour ce processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre l'un des cinq `Txn::commit` à `let _ =`.
    #[tokio::test]
    async fn cjds_runbooks_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-runbooks");
        let adm = cjds_adm();
        let runbook = |nom: &str| json!({ "name": nom, "match_kind": "*", "steps": [{ "phase": "triage", "title": "regarder", "step_kind": "manual" }] });
        let r = cjds_sous_commit_refuse(&st, runbook_create(State(st.clone()), Extension(adm.clone()), Json(runbook("cjds-runbook")))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_RUNBOOK_NON_CREE);
        cjds_juger("création de runbook", &r, &[a, b,
            ("aucun runbook à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM runbook WHERE name LIKE 'cjds%'") == 0),
            ("aucun pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM runbook WHERE name LIKE 'cjds%'") == 0)]);
        let (statut, corps) = cjds_corps(runbook_create(State(st.clone()), Extension(adm.clone()), Json(runbook("cjds-runbook"))).await).await;
        assert_eq!(statut, 200, "levé, le runbook est créé : {corps}");
        let rid = corps["id"].as_i64().expect("identifiant de runbook");
        let present = format!("SELECT COUNT(*) FROM runbook WHERE id={rid} AND name='cjds-runbook' AND active=1");
        let custom = "SELECT COUNT(*) FROM runbook WHERE name LIKE 'cjds%'";

        let r = cjds_sous_commit_refuse(&st, runbook_update_handler(State(st.clone()), Extension(adm.clone()), Path(rid), Json(runbook("cjds-renomme")))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_RUNBOOK_INCHANGE);
        cjds_juger("modification de runbook", &r, &[a, b,
            ("nom d'avant à froid", cjds_a_froid(&p, &present) == 1), ("nom d'avant pour ce processus", cjds_compte(&st, &present) == 1)]);

        let r = cjds_sous_commit_refuse(&st, runbook_set_enabled(State(st.clone()), Extension(adm.clone()), Path(rid), Json(json!({ "enabled": false })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_ACTIVATION_DU_RUNBOOK_INCHANGEE);
        cjds_juger("désactivation de runbook", &r, &[a, b,
            ("toujours actif à froid", cjds_a_froid(&p, &present) == 1), ("toujours actif pour ce processus", cjds_compte(&st, &present) == 1)]);

        let r = cjds_sous_commit_refuse(&st, runbook_clone_handler(State(st.clone()), Extension(adm.clone()), Path(rid), Json(json!({ "name": "cjds-copie" })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_RUNBOOK_NON_CLONE);
        cjds_juger("clonage de runbook", &r, &[a, b,
            ("aucune copie à froid", cjds_a_froid(&p, custom) == 1), ("aucune copie pour ce processus", cjds_compte(&st, custom) == 1)]);

        let r = cjds_sous_commit_refuse(&st, runbook_delete(State(st.clone()), Extension(adm.clone()), Path(rid))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_RUNBOOK_NON_SUPPRIME);
        cjds_juger("suppression de runbook", &r, &[a, b,
            ("toujours là à froid", cjds_a_froid(&p, &present) == 1), ("toujours là pour ce processus", cjds_compte(&st, &present) == 1)]);
    }

    // -------------------------------------------------------------------------------------
    // (8) `connectors/mod.rs` — LA TRACE DU POLL MANUEL
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : le poll manuel d'un connecteur (type inconnu : aucun réseau, `last_error` posé) sous un
    /// `COMMIT` refusé rend son bilan AVEC `trace_non_ecrite`, sans ligne de registre, transaction fermée ; levé, la
    /// trace est écrite et le champ absent.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre la trace à la forme `if let Ok(tx) = Txn::begin(..) { … let _ = tx.commit(); }`.
    #[tokio::test]
    async fn cjds_trace_du_poll_manuel_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-poll");
        let adm = cjds_adm();
        let id = cjds_ecrire(&st, "INSERT INTO connector(type,name,enabled) VALUES('cjds-inconnu','cjds-connecteur',0)");
        let traces = "SELECT COUNT(*) FROM ledger WHERE kind='config.connector.poll'";
        let r = cjds_sous_commit_refuse(&st, connector_poll(State(st.clone()), Extension(adm.clone()), Path(id))).await;
        cjds_juger("trace du poll manuel", &r, &[("statut 200 (le poll a eu lieu)", r.statut == 200),
            ("`trace_non_ecrite` nommée", r.corps["trace_non_ecrite"] == json!(CAUSE_TRACE_DU_POLL_MANUEL_NON_ECRITE)),
            ("aucune trace à froid", cjds_a_froid(&p, traces) == 0),
            ("aucune trace pour ce processus", cjds_compte(&st, traces) == 0)]);
        let (statut, corps) = cjds_corps(connector_poll(State(st.clone()), Extension(adm.clone()), Path(id)).await).await;
        assert_eq!(statut, 200, "levé, le poll manuel répond : {corps}");
        assert!(corps.get("trace_non_ecrite").is_none(), "levé, la trace est écrite et le champ absent : {corps}");
        assert_eq!(cjds_a_froid(&p, traces), 1, "levé, la trace est validée");
    }

    // -------------------------------------------------------------------------------------
    // (9) `sigma.rs` — IMPORTS SIGMA
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : l'import unitaire et l'import en masse sous un `COMMIT` refusé — 503 nommé (la forme d'avant
    /// rendait la liste des règles « importées »), transaction fermée, aucune règle à froid ni pour ce processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre l'un des deux `COMMIT` à `let _ =`.
    #[tokio::test]
    async fn cjds_imports_sigma_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-sigma");
        let adm = cjds_adm();
        let doc = |titre: &str| json!({ "title": titre, "logsource": { "service": "sshd" },
            "detection": { "selection": { "action": "failure" }, "condition": "selection" }, "level": "medium" });
        let r = cjds_sous_commit_refuse(&st, sigma_import(State(st.clone()), Extension(adm.clone()), Json(json!({ "rules": [doc("cjds sigma")] })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_IMPORT_SIGMA_NON_ECRIT);
        cjds_juger("import Sigma", &r, &[a, b,
            ("aucune règle à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM rule WHERE name LIKE 'cjds%'") == 0),
            ("aucune règle pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM rule WHERE name LIKE 'cjds%'") == 0)]);
        let r = cjds_sous_commit_refuse(&st, sigma_import_bulk(State(st.clone()), Extension(adm.clone()), Json(json!({ "rules": [doc("cjds masse")] })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_IMPORT_SIGMA_EN_MASSE_NON_ECRIT);
        cjds_juger("import Sigma en masse", &r, &[a, b,
            ("aucune règle à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM rule WHERE name LIKE 'cjds%'") == 0),
            ("aucune règle pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM rule WHERE name LIKE 'cjds%'") == 0)]);
        let (statut, corps) = cjds_corps(sigma_import(State(st.clone()), Extension(adm.clone()), Json(json!({ "rules": [doc("cjds sigma")] }))).await).await;
        assert_eq!(statut, 200, "levé, l'import a lieu : {corps}");
        assert_eq!(cjds_a_froid(&p, "SELECT COUNT(*) FROM rule WHERE name LIKE 'cjds%'"), 1, "levé, la règle est validée");
    }

    // -------------------------------------------------------------------------------------
    // (10) `threat_intel.rs` — INDICATEURS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : l'ajout manuel d'un indicateur et l'import STIX sous un `COMMIT` refusé — 503 nommé,
    /// transaction fermée, aucun indicateur à froid ni pour ce processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre l'un des deux `COMMIT` à `let _ =`.
    #[tokio::test]
    async fn cjds_indicateurs_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-ti");
        let adm = cjds_adm();
        let r = cjds_sous_commit_refuse(&st, ioc_add(State(st.clone()), Extension(adm.clone()), Json(json!({ "type": "ip", "value": "203.0.113.77" })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_INDICATEURS_NON_AJOUTES);
        cjds_juger("ajout d'indicateur", &r, &[a, b,
            ("aucun indicateur à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM ioc") == 0),
            ("aucun indicateur pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM ioc") == 0)]);
        let paquet = json!({ "bundle": { "type": "bundle", "id": "bundle--cjds", "objects": [
            { "type": "indicator", "id": "indicator--cjds", "pattern_type": "stix", "pattern": "[ipv4-addr:value = '198.51.100.77']" }] } });
        let r = cjds_sous_commit_refuse(&st, stix_import(State(st.clone()), Extension(adm.clone()), Json(paquet))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_IMPORT_STIX_NON_ECRIT);
        cjds_juger("import STIX", &r, &[a, b,
            ("aucun indicateur à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM ioc") == 0),
            ("aucun indicateur pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM ioc") == 0)]);
        let (statut, corps) = cjds_corps(ioc_add(State(st.clone()), Extension(adm.clone()), Json(json!({ "type": "ip", "value": "203.0.113.77" }))).await).await;
        assert_eq!(statut, 200, "levé, l'indicateur est ajouté : {corps}");
        assert_eq!(cjds_a_froid(&p, "SELECT COUNT(*) FROM ioc"), 1, "levé, l'indicateur est validé");
    }

    // -------------------------------------------------------------------------------------
    // (11) `processors.rs` — RÈGLES D'INGESTION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : création et modification d'une règle d'ingestion sous un `COMMIT` refusé — 503 nommé,
    /// transaction fermée, rien de changé à froid ni pour ce processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre l'un des deux `COMMIT` à `let _ =`.
    #[tokio::test]
    async fn cjds_regles_d_ingestion_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-processeurs");
        let adm = cjds_adm();
        let regle = json!({ "name": "cjds-jeter", "match_field": "category", "match_op": "eq", "match_value": "cjds", "action": "drop" });
        let r = cjds_sous_commit_refuse(&st, processor_create(State(st.clone()), Extension(adm.clone()), Json(regle.clone()))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_REGLE_D_INGESTION_NON_CREEE);
        cjds_juger("création de règle d'ingestion", &r, &[a, b,
            ("aucune règle à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM ingest_rule WHERE name='cjds-jeter'") == 0),
            ("aucune règle pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM ingest_rule WHERE name='cjds-jeter'") == 0)]);
        let (statut, corps) = cjds_corps(processor_create(State(st.clone()), Extension(adm.clone()), Json(regle)).await).await;
        assert_eq!(statut, 200, "levé, la règle d'ingestion est créée : {corps}");
        let id = corps["id"].as_i64().expect("identifiant de règle d'ingestion");
        let r = cjds_sous_commit_refuse(&st, processor_update(State(st.clone()), Extension(adm.clone()), Path(id), Json(json!({ "match_value": "cjds2" })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_REGLE_D_INGESTION_INCHANGEE);
        let sql = format!("SELECT COUNT(*) FROM ingest_rule WHERE id={id} AND match_value='cjds'");
        cjds_juger("modification de règle d'ingestion", &r, &[a, b,
            ("valeur d'avant à froid", cjds_a_froid(&p, &sql) == 1), ("valeur d'avant pour ce processus", cjds_compte(&st, &sql) == 1)]);
    }

    // -------------------------------------------------------------------------------------
    // (12) `playbooks.rs` — PLAYBOOKS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : création et modification d'un playbook sous un `COMMIT` refusé — 503 nommé, transaction fermée,
    /// rien de changé à froid ni pour ce processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre l'un des deux `COMMIT` à `let _ =`.
    #[tokio::test]
    async fn cjds_playbooks_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-playbooks");
        let adm = cjds_adm();
        let pb = json!({ "name": "cjds-pb", "query": "search source=auth outcome=fail | stats count by src_ip", "action_kind": "ban_ip" });
        let r = cjds_sous_commit_refuse(&st, playbook_create(State(st.clone()), Extension(adm.clone()), Json(pb.clone()))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_PLAYBOOK_NON_CREE);
        cjds_juger("création de playbook", &r, &[a, b,
            ("aucun playbook à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM playbook WHERE name='cjds-pb'") == 0),
            ("aucun pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM playbook WHERE name='cjds-pb'") == 0)]);
        let (statut, corps) = cjds_corps(playbook_create(State(st.clone()), Extension(adm.clone()), Json(pb)).await).await;
        assert_eq!(statut, 200, "levé, le playbook est créé : {corps}");
        let id = corps["id"].as_i64().expect("identifiant de playbook");
        let r = cjds_sous_commit_refuse(&st, playbook_update(State(st.clone()), Extension(adm.clone()), Path(id), Json(json!({ "interval_s": 900 })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_PLAYBOOK_INCHANGE);
        let sql = format!("SELECT COUNT(*) FROM playbook WHERE id={id} AND interval_s=900");
        cjds_juger("modification de playbook", &r, &[a, b,
            ("intervalle d'avant à froid", cjds_a_froid(&p, &sql) == 0), ("intervalle d'avant pour ce processus", cjds_compte(&st, &sql) == 0)]);
    }

    // -------------------------------------------------------------------------------------
    // (13) `index_policies.rs` — POLITIQUES D'INDEX
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : création et modification d'une politique d'index sous un `COMMIT` refusé — 503 nommé,
    /// transaction fermée, la rétention d'avant à froid comme pour ce processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre l'un des deux `COMMIT` à `let _ =`.
    #[tokio::test]
    async fn cjds_politiques_d_index_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-index");
        let adm = cjds_adm();
        let politique = json!({ "name": "cjds-index", "retention_days": 30 });
        let r = cjds_sous_commit_refuse(&st, index_policy_create(State(st.clone()), Extension(adm.clone()), Json(politique.clone()))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_POLITIQUE_D_INDEX_NON_CREEE);
        cjds_juger("création de politique d'index", &r, &[a, b,
            ("aucune politique à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM index_policy WHERE name='cjds-index'") == 0),
            ("aucune pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM index_policy WHERE name='cjds-index'") == 0)]);
        let (statut, corps) = cjds_corps(index_policy_create(State(st.clone()), Extension(adm.clone()), Json(politique)).await).await;
        assert_eq!(statut, 200, "levé, la politique d'index est créée : {corps}");
        let id = corps["id"].as_i64().expect("identifiant de politique d'index");
        let r = cjds_sous_commit_refuse(&st, index_policy_update(State(st.clone()), Extension(adm.clone()), Path(id), Json(json!({ "retention_days": 60 })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_POLITIQUE_D_INDEX_INCHANGEE);
        let sql = format!("SELECT COUNT(*) FROM index_policy WHERE id={id} AND retention_days=30");
        cjds_juger("modification de politique d'index", &r, &[a, b,
            ("rétention d'avant à froid", cjds_a_froid(&p, &sql) == 1), ("rétention d'avant pour ce processus", cjds_compte(&st, &sql) == 1)]);
    }

    // -------------------------------------------------------------------------------------
    // (14) `admin_ui.rs` — RÉTENTION ET EXCLUSIONS D'AFFICHAGE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : le réglage de la rétention et l'édition d'une exclusion d'affichage sous un `COMMIT` refusé —
    /// 503 nommé (corps texte pour l'exclusion, comme tous les refus de cette route), transaction fermée, aucun réglage
    /// à froid ni pour ce processus (dont la purge lit la rétention par l'écrivain).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre l'un des deux `COMMIT` à `let _ =`.
    #[tokio::test]
    async fn cjds_retention_et_exclusions_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-reglages");
        let adm = cjds_adm();
        let reglages = "SELECT COUNT(*) FROM setting";
        let avant = cjds_a_froid(&p, reglages);
        let r = cjds_sous_commit_refuse(&st, retention_settings_put(State(st.clone()), Extension(adm.clone()), Json(json!({ "retention_days": 45 })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_RETENTION_INCHANGEE);
        cjds_juger("réglage de la rétention", &r, &[a, b,
            ("aucun réglage à froid", cjds_a_froid(&p, reglages) == avant), ("aucun réglage pour ce processus", cjds_compte(&st, reglages) == avant)]);
        let r = cjds_sous_commit_refuse(&st, suppressions_put(State(st.clone()), Extension(adm.clone()),
            Json(json!({ "action": "set_operator_excl", "value": "203.0.113.7" })))).await;
        // `P10.28-r` — la cause est servie en JSON nommé (elle l'était en corps texte).
        let [a, b] = cjds_refus_nomme(&r, CAUSE_EXCLUSION_D_AFFICHAGE_INCHANGEE);
        cjds_juger("exclusion d'affichage", &r, &[a, b,
            ("aucun réglage à froid", cjds_a_froid(&p, reglages) == avant), ("aucun réglage pour ce processus", cjds_compte(&st, reglages) == avant)]);
    }

    // -------------------------------------------------------------------------------------
    // (15) `hotes_declares.rs` — DÉCLARATION D'HÔTE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une déclaration d'hôte sous un `COMMIT` refusé — 503 nommé, transaction fermée, aucune ligne à
    /// froid ni pour ce processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre le `COMMIT` de `host_settings_put` à `let _ =`.
    #[tokio::test]
    async fn cjds_declaration_d_hote_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-hote");
        let r = cjds_sous_commit_refuse(&st, host_settings_put(State(st.clone()), Extension(cjds_adm()),
            Json(json!({ "host": "srv-9", "action": "set_attente", "value": "silence_attendu", "motif": "cjds" })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_DECLARATION_D_HOTE_INCHANGEE);
        cjds_juger("déclaration d'hôte", &r, &[a, b,
            ("aucune déclaration à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM host_settings") == 0),
            ("aucune pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM host_settings") == 0)]);
    }

    // -------------------------------------------------------------------------------------
    // (16) `sources.rs` — RÉGLAGES D'UNE SOURCE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : le libellé d'une source sous un `COMMIT` refusé — 503 nommé, transaction fermée, aucune ligne à
    /// froid ni pour ce processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre le `COMMIT` de `source_settings_put` à `let _ =`.
    #[tokio::test]
    async fn cjds_reglages_de_source_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-source");
        let r = cjds_sous_commit_refuse(&st, source_settings_put(State(st.clone()), Extension(cjds_adm()),
            Json(json!({ "source": "okta", "action": "set_label", "value": "Okta" })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_REGLAGES_DE_SOURCE_INCHANGES);
        cjds_juger("réglage de source", &r, &[a, b,
            ("aucun réglage à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM source_settings") == 0),
            ("aucun pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM source_settings") == 0)]);
    }

    // -------------------------------------------------------------------------------------
    // (17) `datamodels.rs` — MODÈLES DE DONNÉES (squelette commun `dm_commit`)
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la création d'un modèle de données sous un `COMMIT` refusé — 503 nommé, transaction fermée,
    /// aucun modèle à froid ni pour ce processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre le `COMMIT` de `dm_commit` à `let _ =`.
    #[tokio::test]
    async fn cjds_modeles_de_donnees_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-modeles");
        let r = cjds_sous_commit_refuse(&st, model_create(State(st.clone()), Extension(cjds_adm()), Json(json!({ "name": "cjds_modele" })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_MODELE_DE_DONNEES_NON_ECRIT);
        cjds_juger("création de modèle de données", &r, &[a, b,
            ("aucun modèle à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM data_model") == 0),
            ("aucun pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM data_model") == 0)]);
    }

    // -------------------------------------------------------------------------------------
    // (18) `knowledge.rs` — OBJETS DE SAVOIR (squelette commun `ko_commit`)
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la création d'un alias de champ sous un `COMMIT` refusé — 503 nommé, transaction fermée, aucun
    /// alias à froid ni pour ce processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre le `COMMIT` de `ko_commit` à `let _ =`.
    #[tokio::test]
    async fn cjds_objets_de_savoir_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-savoir");
        let r = cjds_sous_commit_refuse(&st, alias_create(State(st.clone()), Extension(cjds_adm()),
            Json(json!({ "canonical": "cjds_canon", "source": "cjds_src" })))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_OBJET_DE_SAVOIR_NON_ECRIT);
        cjds_juger("création d'alias", &r, &[a, b,
            ("aucun alias à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM knowledge_alias") == 0),
            ("aucun pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM knowledge_alias") == 0)]);
    }

    // -------------------------------------------------------------------------------------
    // (19) `overlays.rs` — ÉLAGAGE DES OVERLAYS ORPHELINS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une règle `managed=1` qu'aucun fichier n'adosse ; l'élagage sous un `COMMIT` refusé rend 503
    /// nommé, transaction fermée, et la règle orpheline est toujours là, à froid comme pour ce processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre le `COMMIT` de `config_overlays_prune` à `let _ =`.
    #[tokio::test]
    async fn cjds_elagage_des_overlays_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-overlays");
        cjds_ecrire(&st, "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,managed) \
                          VALUES('cjds-orpheline',1,'search source=auth | stats count',1,'>',0,2,300,3600,1)");
        let sql = "SELECT COUNT(*) FROM rule WHERE name='cjds-orpheline'";
        let r = cjds_sous_commit_refuse(&st, config_overlays_prune(State(st.clone()), Extension(cjds_adm()))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_ELAGAGE_DES_OVERLAYS_NON_FAIT);
        cjds_juger("élagage des overlays", &r, &[a, b,
            ("l'orpheline est là à froid", cjds_a_froid(&p, sql) == 1), ("et pour ce processus", cjds_compte(&st, sql) == 1)]);
    }

    // -------------------------------------------------------------------------------------
    // (20) `scheduled_reports.rs` — SUPPRESSION D'UN RAPPORT PLANIFIÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la suppression d'un rapport planifié sous un `COMMIT` refusé — 503 nommé, transaction fermée,
    /// le rapport toujours là (il PART toujours à son échéance).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre le `COMMIT` de `report_delete` à `let _ =`.
    #[tokio::test]
    async fn cjds_suppression_de_rapport_planifie_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-rapports");
        let id = cjds_ecrire(&st, "INSERT INTO scheduled_report(name,dataset_id,notifier_id) VALUES('cjds_rapport',1,1)");
        let r = cjds_sous_commit_refuse(&st, report_delete(State(st.clone()), Extension(cjds_adm()), Path(id))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_RAPPORT_PLANIFIE_NON_SUPPRIME);
        cjds_juger("suppression de rapport planifié", &r, &[a, b,
            ("toujours là à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM scheduled_report") == 1),
            ("toujours là pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM scheduled_report") == 1)]);
    }

    // -------------------------------------------------------------------------------------
    // (21) `workflow_actions.rs` — SUPPRESSION D'UNE WORKFLOW-ACTION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la suppression d'une workflow-action sous un `COMMIT` refusé — 503 nommé, transaction fermée,
    /// l'action toujours là.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre le `COMMIT` de `workflow_action_delete` à `let _ =`.
    #[tokio::test]
    async fn cjds_suppression_de_workflow_action_sous_commit_refuse() {
        let (st, p) = sp_state("cjds-workflow");
        let id = cjds_ecrire(&st, "INSERT INTO workflow_action(name,kind,target) VALUES('cjds_action','search','search host=$host$')");
        let r = cjds_sous_commit_refuse(&st, workflow_action_delete(State(st.clone()), Extension(cjds_adm()), Path(id))).await;
        let [a, b] = cjds_refus_nomme(&r, CAUSE_WORKFLOW_ACTION_NON_SUPPRIMEE);
        cjds_juger("suppression de workflow-action", &r, &[a, b,
            ("toujours là à froid", cjds_a_froid(&p, "SELECT COUNT(*) FROM workflow_action") == 1),
            ("toujours là pour ce processus", cjds_compte(&st, "SELECT COUNT(*) FROM workflow_action") == 1)]);
    }

    // -------------------------------------------------------------------------------------
    // (22) LA FIN D'UN INSTANTANÉ DE LECTURE (`fermer_l_instantane_de_lecture`, ventilation et sauvegarde en flux)
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, DANS LES TROIS CAS : `COMMIT` accepté -> connexion fermée, `true` ; `COMMIT` refusé -> annulé,
    /// connexion fermée, `true` (la forme d'avant la laissait dans son instantané) ; `COMMIT` ET `ROLLBACK` refusés ->
    /// `false`, et la connexion est bien restée ouverte (ce que le journal dit).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer le `ROLLBACK` de l'aide (deuxième cas), ou rendre `true` sans lire
    /// l'état (troisième cas).
    #[test]
    fn cjds_la_fin_d_un_instantane_de_lecture_est_jugee_et_ferme_la_connexion() {
        let (_st, p) = sp_state("cjds-instantane");
        let lire = |c: &Connection| {
            c.execute_batch("BEGIN DEFERRED").expect("fixture : instantané ouvert");
            let _: i64 = c.query_row("SELECT COUNT(*) FROM rule", [], |r| r.get(0)).expect("fixture : lecture");
            assert!(!c.is_autocommit(), "fixture : l'instantané est ouvert");
        };
        let c = open_db(p.as_str()).expect("connexion");
        lire(&c);
        assert!(fermer_l_instantane_de_lecture(&c, "cjds", "témoin"), "COMMIT accepté : fermé");
        assert!(c.is_autocommit());

        lire(&c);
        c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let ferme = fermer_l_instantane_de_lecture(&c, "cjds", "témoin");
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert!(ferme && c.is_autocommit(), "COMMIT refusé : annulé, la connexion n'est pas rendue dans son instantané");

        lire(&c);
        c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { .. } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let ferme = fermer_l_instantane_de_lecture(&c, "cjds", "témoin");
        let ouverte = !c.is_autocommit();
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert!(!ferme && ouverte, "COMMIT et ROLLBACK refusés : l'aide ne ment pas, l'instantané reste ouvert et le dit");
        c.execute_batch("ROLLBACK").expect("fixture : fermeture");
    }

    // -------------------------------------------------------------------------------------
    // (23) `P10.27-g` — LA SONDE D'UNE TRANSACTION OUVERTE HORS DE TOUT GESTE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, DANS LES DEUX SENS : sur un écrivain en autocommit, la sonde ne dit rien (`false`) ; sur un
    /// écrivain qui porte une transaction, elle la voit (`true`), la compte, et ne la FERME PAS (la décision de la
    /// fermer n'est pas prise ici).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : une sonde qui rend toujours `false` (positif), toujours `true` (négatif), qui ne
    /// compte pas, ou qui ferme la transaction.
    #[test]
    fn cjds_la_sonde_voit_une_transaction_ouverte_et_ne_la_ferme_pas() {
        let (st, _p) = sp_state("cjds-sonde");
        let c = st.db.lock();
        assert!(!signaler_une_transaction_ouverte_hors_de_tout_geste(&c, "témoin"), "négatif : écrivain en autocommit, rien à dire");
        c.execute_batch("BEGIN IMMEDIATE; INSERT INTO meta(key,value) VALUES('cjds-sonde','1');").expect("fixture : transaction laissée ouverte");
        let avant = transactions_ouvertes_hors_de_tout_geste();
        assert!(signaler_une_transaction_ouverte_hors_de_tout_geste(&c, "témoin"), "positif : la transaction ouverte est vue");
        assert!(transactions_ouvertes_hors_de_tout_geste() > avant, "et comptée");
        assert!(!c.is_autocommit(), "la sonde ne ferme pas la transaction à la place de son geste");
        c.execute_batch("ROLLBACK").expect("fixture : fermeture");
    }

    /// CE QU'IL TIENT : la sonde est CÂBLÉE dans une boucle de fond — le tick de détection (`run_due_rules`), qui prend le
    /// verrou de l'écrivain de chaque tenant toutes les 20 s, la voit quand une transaction a été laissée ouverte.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer l'appel de la sonde dans `run_due_rules`.
    #[test]
    fn cjds_le_tick_de_detection_porte_la_sonde() {
        let (st, p) = sp_state("cjds-tick");
        st.db.lock().execute_batch("BEGIN IMMEDIATE; INSERT INTO meta(key,value) VALUES('cjds-tick','1');").expect("fixture : transaction laissée ouverte");
        let avant = transactions_ouvertes_hors_de_tout_geste();
        let _ = run_due_rules(&st.db, p.as_str());
        let vue = transactions_ouvertes_hors_de_tout_geste() > avant;
        st.db.lock().execute_batch("ROLLBACK").expect("fixture : fermeture");
        assert!(vue, "le tick de détection a vu la transaction laissée ouverte sur l'écrivain");
    }
}
