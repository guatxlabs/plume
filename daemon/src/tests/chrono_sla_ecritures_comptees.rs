// =====================================================================================
// `P10.20-w` (reste) — LES ÉCRITURES INTERNES DU CHRONO SLA MULTI-NIVEAU SONT COMPTÉES ET PROPAGÉES.
//
// CE QUI ÉTAIT FAUX, MESURÉ SUR b52f097 : `sla_apply_policy` (deux `UPDATE` : échéances d'acquittement et de
// résolution) et `sla_on_status_change` (deux `UPDATE` : pause, reprise) avalaient leurs écritures par `let _` et
// rendaient `()`. Conséquences : une mise à jour de priorité ou de statut refusée par la base sur ces colonnes rendait
// 204 (échéance de l'ancienne priorité, chrono resté en pause ou jamais mis en pause) ; `case_create` servait le
// dossier sans dire que la politique active n'était pas appliquée ; le recalcul de l'upsert comptait « recalculé » un
// dossier dont l'échéance était refusée (`recalcules` gonflé, route muette en 204) ; le rattrapage multi-niveau ne
// jugeait que par relecture, et la branche terminale du rattrapage taisait une reprise refusée.
// CORRIGÉ : `IssueDuChronoSla::{Ecrit, RienAFaire, Refuse}` ; refus -> 503 nommé (`NonEcrite("sla…: cause")`), aveu
// `echeances_multi_niveau_non_posees` à la création, `recalcules` = écrites et refus nommé dans `manque`, cause du
// rattrapage nommant la colonne refusée.
//
// CE QU'ILS NE TIENNENT PAS : les LECTURES `.ok()` de `sla_policy_for` / `sla_apply_policy` / `sla_on_status_change`
// (entrées de la garde single-row, hors lot) — une ligne non lue reste « rien à faire » ; les bras `Ok(0)` du statut et
// du verdict de `case_apply_update` (dossier disparu -> `DossierAbsent`, sans rattrapage multi-niveau) ; un statut écrit
// SANS priorité écrite puis un refus (aucun rattrapage, comportement d'avant) ; `ack_due` n'est pas rattrapé une fois le
// dossier acquitté (figé, à dessein) ; la console ne lit pas l'aveu de création.
// Mutants (VERIF_MUT, retirés avant le commit) nommés sur chaque témoin.
// =====================================================================================
mod chrono_sla_ecritures_comptees {
    use super::*;

    fn cse_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("cse-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
            conn.execute_batch(
                "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,600,1,0,'root',0);
                 INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P3',3,3000,30000,1,0,'root',0);",
            )
            .unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn cse_au() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn cse_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn cse_refuser(st: &AppState, colonne: &str) {
        cse_sql(st, &format!(
            "CREATE TEMP TRIGGER cse_refus_{colonne} BEFORE UPDATE OF {colonne} ON incident BEGIN SELECT RAISE(ABORT, 'cse {colonne}'); END;"
        ));
    }

    fn cse_permettre(st: &AppState, colonne: &str) {
        cse_sql(st, &format!("DROP TRIGGER cse_refus_{colonne};"));
    }

    fn cse_entier(st: &AppState, sql: &str) -> Option<i64> {
        st.db.lock().query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).expect("fixture : la valeur se lit")
    }

    fn cse_dossier(st: &AppState, priorite: i64) -> i64 {
        let conn = st.db.lock();
        dossier_seme(&conn, "alice", "Dossier", 3, "", None, priorite)
    }

    fn cse_en_pause(st: &AppState, id: i64) {
        cse_sql(st, &format!(
            "UPDATE incident SET status='waiting', sla_paused_since=CAST(strftime('%s','now') AS INTEGER) - 1000 WHERE id={id};"
        ));
    }

    async fn cse_patch(st: &AppState, id: i64, corps: Value) -> (u16, Value) {
        pb_json(case_update(State(st.clone()), Extension(cse_au()), Path(id), Json(corps)).await).await
    }

    /// La cause entre parenthèses d'un 503 de mise à jour.
    async fn cse_cause(st: &AppState, id: i64, corps: Value) -> String {
        let (statut, avoue) = cse_patch(st, id, corps).await;
        assert_eq!(statut, 503, "écriture du chrono refusée : 503 attendu ({avoue})");
        let phrase = avoue["error"].as_str().unwrap_or("").to_string();
        let prefixe = format!("{CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE} (");
        assert!(phrase.starts_with(&prefixe) && phrase.ends_with(')'), "{avoue}");
        phrase[prefixe.len()..phrase.len() - 1].to_string()
    }

    /// CE QU'IL TIENT (`case_create`) : politique active, échéances refusées par la base -> le dossier est servi (200,
    /// identifiant) AVEC l'aveu `echeances_multi_niveau_non_posees` nommé, et `ack_due` n'est pas posé. Contrôle : sans
    /// refus, le corps d'avant mot pour mot (aucun champ d'aveu), échéances posées ; mode 0 -> `RienAFaire`.
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=H5_APPLY_ACK` (le `let _` d'avant), `VERIF_MUT=H5_CREATE_TAIT`.
    #[tokio::test]
    async fn cse_creation_politique_refusee_avouee_dossier_servi() {
        let (st, _t) = cse_etat("creation");
        cse_refuser(&st, "ack_due");
        let (statut, corps) = pb_json(case_create(State(st.clone()), Extension(cse_au()), Json(json!({ "title": "D", "priority": 1 }))).await).await;
        assert_eq!(statut, 200, "le dossier existe : il est servi : {corps}");
        let id = corps["id"].as_i64().expect("identifiant servi");
        let aveu = corps.get("echeances_multi_niveau_non_posees").and_then(|v| v.as_str()).unwrap_or("");
        assert!(aveu.starts_with(CAUSE_ECHEANCES_MULTI_NIVEAU_NON_POSEES), "l'aveu est porté : {corps}");
        assert!(aveu.contains("sla_policy_id/ack_due/resolve_due: cse ack_due"), "la cause nomme les colonnes : {aveu}");
        assert_eq!(cse_entier(&st, &format!("SELECT ack_due FROM incident WHERE id={id}")), None, "échéance non posée");
        cse_permettre(&st, "ack_due");

        // CONTRÔLE NOMINAL — corps d'avant, champ pour champ, et échéances posées.
        let (statut, corps) = pb_json(case_create(State(st.clone()), Extension(cse_au()), Json(json!({ "title": "D", "priority": 1 }))).await).await;
        assert_eq!(statut, 200);
        let id = corps["id"].as_i64().unwrap();
        let echeance = cse_entier(&st, &format!("SELECT sla_due FROM incident WHERE id={id}"));
        assert_eq!(corps, json!({ "id": id, "status": "new", "priority": 1, "priority_label": priority_label(1), "sla_due": echeance }));
        assert_eq!(cse_entier(&st, &format!("SELECT ack_due - ts FROM incident WHERE id={id}")), Some(60));
        // Mode 0 (priorité sans politique) : rien à faire, jamais un refus.
        let conn = st.db.lock();
        let (_, issue) = case_create_row_et_echeances(&conn, "alice", "D", 2, "", None, 2);
        assert_eq!(issue, IssueDuChronoSla::RienAFaire);
    }

    /// CE QU'IL TIENT (recalcul de l'upsert) : échéances refusées -> `recalcules` = 0 (jamais gonflé), `manque` nomme les
    /// dossiers refusés, la réponse est un 200 qui le dit (plus un 204 « tout fait »), l'échéance d'avant est conservée.
    /// Contrôle : sans refus, deux recalculés et silence.
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=H5_APPLY_ACK`, `VERIF_MUT=H5_RECALC` (compte chaque appel).
    #[test]
    fn cse_recalcul_refuse_n_est_pas_compte() {
        let conn = test_db();
        conn.execute_batch(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('p',2,60,600,1,0,'t',0);
             INSERT INTO incident(ts,updated,title,status,severity,priority,resolve_due) VALUES(1000,1000,'a','new',2,2,77);
             INSERT INTO incident(ts,updated,title,status,severity,priority,resolve_due) VALUES(1001,1001,'b','new',2,2,77);
             CREATE TEMP TRIGGER cse_r BEFORE UPDATE OF resolve_due ON incident BEGIN SELECT RAISE(ABORT, 'cse resolve_due'); END;",
        )
        .unwrap();
        let r = sla_recalcule_la_priorite_bornee(&conn, 2, 10);
        assert_eq!(r.recalcules, 0, "aucune échéance écrite, aucune comptée");
        let raison = r.manque.clone().expect("le refus est dit");
        assert!(raison.contains("2 échéance(s) REFUSÉE(S)") && raison.contains("cse resolve_due"), "{raison}");
        assert_eq!(reponse_de_l_upsert_sla(Ok(()), &r).status(), StatusCode::OK, "plus un 204 « tout fait »");
        let restees: i64 = conn.query_row("SELECT COUNT(*) FROM incident WHERE resolve_due=77", [], |x| x.get(0)).unwrap();
        assert_eq!(restees, 2, "l'échéance d'avant est conservée");

        conn.execute_batch("DROP TRIGGER cse_r;").unwrap();
        let r = sla_recalcule_la_priorite_bornee(&conn, 2, 10);
        assert_eq!(r, RecalculDesEcheances { recalcules: 2, manque: None }, "contrôle nominal");
    }

    /// CE QU'IL TIENT (sortie nominale de `case_apply_update`, dossier acquitté) : priorité P3 -> P1 écrite, pose de la
    /// politique refusée -> 503 nommé `sla_policy_id/resolve_due: …` (c'était un 204), `resolve_due` de P3 conservé.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=H5_APPLY_RESOLVE`.
    #[tokio::test]
    async fn cse_priorite_ecrite_politique_refusee_rend_503() {
        let (st, _t) = cse_etat("prio");
        let id = cse_dossier(&st, 3);
        assert_eq!(cse_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(30000), "fixture P3");
        cse_refuser(&st, "resolve_due");
        let cause = cse_cause(&st, id, json!({ "priority": 1 })).await;
        assert_eq!(cause, "sla_policy_id/resolve_due: cse resolve_due");
        assert_eq!(cse_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(30000), "échéance d'avant");
        cse_permettre(&st, "resolve_due");
        assert_eq!(cse_patch(&st, id, json!({ "priority": 1 })).await.0, 204, "contrôle nominal");
        assert_eq!(cse_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(600));
    }

    /// CE QU'IL TIENT : entrée en `waiting` sur un dossier gouverné, pause refusée -> 503 `sla_paused_since: …`, chrono
    /// non mis en pause en base (et la route ne le dit plus « fait »).
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=H5_PAUSE`.
    #[tokio::test]
    async fn cse_pause_refusee_rend_503() {
        let (st, _t) = cse_etat("pause");
        let id = cse_dossier(&st, 3);
        cse_refuser(&st, "sla_paused_since");
        let cause = cse_cause(&st, id, json!({ "status": "waiting" })).await;
        assert_eq!(cause, "sla_paused_since: cse sla_paused_since");
        assert_eq!(cse_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={id}")), None);
        cse_permettre(&st, "sla_paused_since");
        assert_eq!(cse_patch(&st, id, json!({ "status": "waiting" })).await.0, 204, "contrôle nominal");
        assert!(cse_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={id}")).is_some(), "chrono en pause");
    }

    /// CE QU'IL TIENT : politique active, passage `waiting` -> `open` avec la reprise refusée -> 503
    /// `sla_pause_accum/ack_due/resolve_due: …`, échéance d'avant conservée, chrono resté en pause. Contrôle : reprise
    /// écrite -> 204, pause cumulée, échéance décalée d'autant.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=H5_REPRISE`.
    #[tokio::test]
    async fn cse_reprise_refusee_waiting_vers_open_rend_503() {
        let (st, _t) = cse_etat("reprise");
        let id = cse_dossier(&st, 3);
        cse_en_pause(&st, id);
        cse_refuser(&st, "sla_pause_accum");
        let cause = cse_cause(&st, id, json!({ "status": "open" })).await;
        assert_eq!(cause, "sla_pause_accum/ack_due/resolve_due: cse sla_pause_accum");
        assert_eq!(cse_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(30000), "échéance d'avant");
        assert!(cse_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={id}")).is_some(), "chrono resté en pause");
        cse_permettre(&st, "sla_pause_accum");
        assert_eq!(cse_patch(&st, id, json!({ "status": "open" })).await.0, 204, "contrôle nominal");
        assert_eq!(cse_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={id}")), None);
        let decalage = cse_entier(&st, &format!("SELECT resolve_due - ts - 30000 FROM incident WHERE id={id}")).unwrap_or(0);
        assert!((1000..=1010).contains(&decalage), "échéance décalée de la pause : {decalage}");
    }

    /// CE QU'IL TIENT (rattrapage) : sortie de `waiting` + priorité écrite, verdict refusé, reprise refusée -> la cause
    /// nomme la colonne refusée (valeur de retour), pas seulement « relue non conforme » ; et vers un statut TERMINAL, la
    /// reprise refusée est DITE (elle se taisait : « la cause ne gagne aucun mot »).
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=H5_REPRISE` (les deux), `VERIF_MUT=H5_TERMINAL_TAIT` (la seconde).
    #[tokio::test]
    async fn cse_rattrapage_dit_la_reprise_refusee() {
        let (st, _t) = cse_etat("rattrapage");
        cse_refuser(&st, "disposition");
        cse_refuser(&st, "sla_pause_accum");
        let id = cse_dossier(&st, 3);
        cse_en_pause(&st, id);
        let cause = cse_cause(&st, id, json!({ "priority": 1, "status": "in_progress", "disposition": "true_positive" })).await;
        assert!(cause.starts_with("disposition: cse disposition ; échéance recalculée sur la priorité écrite ; "), "{cause}");
        assert!(cause.contains("ÉCHÉANCES MULTI-NIVEAU NON RECALCULÉES sur la priorité écrite (sla_pause_accum/ack_due/resolve_due: cse sla_pause_accum)"), "{cause}");
        let id2 = cse_dossier(&st, 3);
        cse_en_pause(&st, id2);
        let cause = cse_cause(&st, id2, json!({ "priority": 1, "status": "closed", "disposition": "true_positive" })).await;
        assert_eq!(cause, "disposition: cse disposition ; REPRISE DU CHRONO SLA NON ÉCRITE (sla_pause_accum/ack_due/resolve_due: cse sla_pause_accum)");
        assert!(cse_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={id2}")).is_some(), "fixture : reprise refusée");
    }

    /// CE QU'IL TIENT (sortie nominale, pause ou reprise refusée APRÈS une priorité écrite) : P3 -> P1 écrite, reprise
    /// (puis pause) refusée -> 503, et la politique et `resolve_due` suivent P1 avant la sortie, la cause le disant.
    /// Ce qui était faux sur 70061e26 : la sortie se faisait avant `sla_apply_policy`, le dossier P1 gardait la politique
    /// et l'échéance de P3 (30000 s au lieu de 600) sans que la cause le dise ; sur b52f097 la politique était appliquée.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=H5C_REGRESSION` (la sortie d'avant, sans rattrapage).
    #[tokio::test]
    async fn cse_priorite_ecrite_puis_pause_ou_reprise_refusee_suit_la_priorite() {
        let (st, _t) = cse_etat("regression");
        let p1 = cse_entier(&st, "SELECT id FROM sla_policy WHERE priority=1");
        // Reprise refusée (sortie de `waiting`).
        let id = cse_dossier(&st, 3);
        cse_en_pause(&st, id);
        cse_refuser(&st, "sla_pause_accum");
        let cause = cse_cause(&st, id, json!({ "priority": 1, "status": "open" })).await;
        assert_eq!(cause, "sla_pause_accum/ack_due/resolve_due: cse sla_pause_accum, échéances multi-niveau recalculées sur la priorité écrite");
        assert_eq!(cse_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(600), "échéance de P1");
        assert_eq!(cse_entier(&st, &format!("SELECT sla_policy_id FROM incident WHERE id={id}")), p1, "politique de P1");
        cse_permettre(&st, "sla_pause_accum");
        // Pause refusée (entrée en `waiting`).
        let id = cse_dossier(&st, 3);
        cse_refuser(&st, "sla_paused_since");
        let cause = cse_cause(&st, id, json!({ "priority": 1, "status": "waiting" })).await;
        assert_eq!(cause, "sla_paused_since: cse sla_paused_since, échéances multi-niveau recalculées sur la priorité écrite");
        assert_eq!(cse_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(600), "échéance de P1");
        assert_eq!(cse_entier(&st, &format!("SELECT sla_policy_id FROM incident WHERE id={id}")), p1, "politique de P1");
        // Contrôle : sans priorité écrite, la cause reste nue (aucun rattrapage).
        let id = cse_dossier(&st, 3);
        assert_eq!(cse_cause(&st, id, json!({ "status": "waiting" })).await, "sla_paused_since: cse sla_paused_since");
        assert_eq!(cse_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(30000));
    }

    /// CE QU'IL TIENT (rattrapage, application refusée) : statut refusé après une priorité écrite, `resolve_due` refusé ->
    /// la cause nomme la colonne refusée par la valeur de retour, pas le libellé générique de la relecture.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=H5C_M21` (refus de l'application retiré de `refus`).
    #[tokio::test]
    async fn cse_rattrapage_nomme_l_application_refusee() {
        let (st, _t) = cse_etat("application");
        let id = cse_dossier(&st, 3);
        cse_refuser(&st, "status");
        cse_refuser(&st, "resolve_due");
        let cause = cse_cause(&st, id, json!({ "priority": 1, "status": "in_progress" })).await;
        assert!(
            cause.ends_with(" ; ÉCHÉANCES MULTI-NIVEAU NON RECALCULÉES sur la priorité écrite (sla_policy_id/resolve_due: cse resolve_due)"),
            "{cause}"
        );
    }

    /// CE QU'IL TIENT (rattrapage, priorité écrite SANS politique) : P3 en pause -> P2 (sans politique) + `open` écrits,
    /// verdict refusé, reprise refusée -> la reprise refusée est dite.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=H5C_M19` (chaîne vide dans cette branche).
    #[tokio::test]
    async fn cse_rattrapage_sans_politique_dit_la_reprise_refusee() {
        let (st, _t) = cse_etat("sanspolitique");
        let id = cse_dossier(&st, 3);
        cse_en_pause(&st, id);
        cse_refuser(&st, "disposition");
        cse_refuser(&st, "sla_pause_accum");
        let cause = cse_cause(&st, id, json!({ "priority": 2, "status": "open", "disposition": "true_positive" })).await;
        assert!(cause.ends_with(" ; REPRISE DU CHRONO SLA NON ÉCRITE (sla_pause_accum/ack_due/resolve_due: cse sla_pause_accum)"), "{cause}");
    }

    /// CE QU'IL TIENT (bras `Ok(n)` d'`ecriture_du_chrono`) : un déclencheur `RAISE(IGNORE)` fait écrire ZÉRO ligne sans
    /// erreur -> à la création, l'aveu dit « 0 ligne(s) écrite(s) au lieu d'une ».
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=H5C_M5` (zéro ligne compté écrit).
    #[tokio::test]
    async fn cse_zero_ligne_ecrite_est_un_refus() {
        let (st, _t) = cse_etat("zeroligne");
        cse_sql(&st, "CREATE TEMP TRIGGER cse_ignore BEFORE UPDATE OF ack_due ON incident BEGIN SELECT RAISE(IGNORE); END;");
        let (statut, corps) = pb_json(case_create(State(st.clone()), Extension(cse_au()), Json(json!({ "title": "D", "priority": 1 }))).await).await;
        assert_eq!(statut, 200, "{corps}");
        let aveu = corps.get("echeances_multi_niveau_non_posees").and_then(|v| v.as_str()).unwrap_or("");
        assert!(aveu.contains("sla_policy_id/ack_due/resolve_due: 0 ligne(s) écrite(s) au lieu d'une"), "{corps}");
    }

    /// CE QU'IL TIENT (recalcul) : politique DÉSACTIVÉE -> `RienAFaire` n'est jamais compté recalculé.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=H5C_M11`.
    #[test]
    fn cse_recalcul_rien_a_faire_n_est_pas_compte() {
        let conn = test_db();
        conn.execute_batch(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('p',2,60,600,0,0,'t',0);
             INSERT INTO incident(ts,updated,title,status,severity,priority) VALUES(1000,1000,'a','new',2,2);
             INSERT INTO incident(ts,updated,title,status,severity,priority) VALUES(1001,1001,'b','new',2,2);",
        )
        .unwrap();
        assert_eq!(sla_recalcule_la_priorite_bornee(&conn, 2, 10), RecalculDesEcheances { recalcules: 0, manque: None });
    }

    /// CE QU'IL TIENT (recalcul, refus nombreux) : six refus -> cinq dossiers nommés et l'ellipse « , … » ; cinq refus
    /// -> cinq nommés, sans ellipse.
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=H5C_M13` (borne retirée), `VERIF_MUT=H5C_M13B` (ellipse retirée).
    #[test]
    fn cse_recalcul_refus_nommes_bornes_a_cinq() {
        let conn = test_db();
        conn.execute_batch(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('p',2,60,600,1,0,'t',0);
             CREATE TEMP TRIGGER cse_r BEFORE UPDATE OF resolve_due ON incident BEGIN SELECT RAISE(ABORT, 'cse resolve_due'); END;",
        )
        .unwrap();
        for i in 0..5 {
            conn.execute("INSERT INTO incident(ts,updated,title,status,severity,priority) VALUES(?1,?1,'x','new',2,2)", params![1000 + i]).unwrap();
        }
        let raison = sla_recalcule_la_priorite_bornee(&conn, 2, 10).manque.expect("refus dits");
        assert!(raison.starts_with("5 échéance(s) REFUSÉE(S)"), "{raison}");
        assert_eq!(raison.matches("cse resolve_due").count(), 5, "{raison}");
        assert!(!raison.contains('…'), "cinq refus, tous nommés : pas d'ellipse : {raison}");
        conn.execute("INSERT INTO incident(ts,updated,title,status,severity,priority) VALUES(2000,2000,'x','new',2,2)", []).unwrap();
        let raison = sla_recalcule_la_priorite_bornee(&conn, 2, 10).manque.expect("refus dits");
        assert!(raison.starts_with("6 échéance(s) REFUSÉE(S)"), "{raison}");
        assert_eq!(raison.matches("cse resolve_due").count(), 5, "cinq nommés au plus : {raison}");
        assert!(raison.ends_with(", …"), "{raison}");
    }

    /// CE QU'IL TIENT (recalcul, refus ET plafond) : trois dossiers P2, plafond 2, `resolve_due` refusé -> le manque
    /// dit LES DEUX accusations, jointes par « ; » : les deux refus nommés ET le plafond atteint (le troisième dossier
    /// garde son ancienne échéance). Rien n'est compté recalculé.
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=H5D_TRONQUE` (seul le premier manque gardé : le plafond est tu),
    /// `VERIF_MUT=H5D_PREMIER_PERDU` (seul le dernier gardé : les refus sont tus).
    #[test]
    fn cse_recalcul_refus_et_plafond_dits_ensemble() {
        let conn = test_db();
        conn.execute_batch(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('p',2,60,600,1,0,'t',0);
             INSERT INTO incident(ts,updated,title,status,severity,priority) VALUES(1000,1000,'a','new',2,2);
             INSERT INTO incident(ts,updated,title,status,severity,priority) VALUES(1001,1001,'b','new',2,2);
             INSERT INTO incident(ts,updated,title,status,severity,priority) VALUES(1002,1002,'c','new',2,2);
             CREATE TEMP TRIGGER cse_rp BEFORE UPDATE OF resolve_due ON incident BEGIN SELECT RAISE(ABORT, 'cse resolve_due'); END;",
        )
        .unwrap();
        let r = sla_recalcule_la_priorite_bornee(&conn, 2, 2);
        assert_eq!(r.recalcules, 0);
        let raison = r.manque.expect("refus et plafond dits");
        assert!(raison.starts_with("2 échéance(s) REFUSÉE(S)"), "{raison}");
        assert_eq!(raison.matches("cse resolve_due").count(), 2, "{raison}");
        assert!(raison.contains(" ; plafond de 2 case(s) atteint"), "{raison}");
    }
}
