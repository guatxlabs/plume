// =====================================================================================
// `P10.20-b` (rang trois) et `P10.20-w` (reste) — LES LECTURES DU CHRONO SLA MULTI-NIVEAU SONT JUGÉES, ET UNE
// PRIORITÉ SANS POLITIQUE N'HÉRITE PLUS DE CELLE D'AVANT.
//
// CE QUI ÉTAIT FAUX, MESURÉ SUR cc71144 : trois lectures qui gouvernent le chrono absorbaient l'échec par `.ok()` —
// `sla_policy_for` (politique non lue = `None` = repli muet sur le régime legacy), `sla_apply_policy` (ligne du dossier
// non lue = `RienAFaire`), `sla_on_status_change` (idem : pause ou reprise sautée). La création servait le dossier sans
// aveu, la mise à jour rendait 204, le recalcul de l'upsert se taisait. Et `sla_apply_policy` sortait en `RienAFaire`
// quand la nouvelle priorité n'avait pas de politique : `sla_policy_id`, `ack_due`, `resolve_due` de l'ANCIENNE
// priorité restaient, servis comme ceux de la priorité courante.
// CORRIGÉ : lectures en `.optional()` (absence établie = sortie d'avant) ; lecture ratée = `IssueDuChronoSla::NonLu`,
// rien d'écrit — 503 `CAUSE_CHRONO_SLA_NON_LU` à la mise à jour, aveu `echeances_multi_niveau_non_lues` à la création,
// dossier nommé dans `manque` au recalcul, cause du rattrapage qui dit « NON LUE » ; priorité sans politique -> les
// trois colonnes reviennent à NULL (régime legacy), et une pause en cours se reprend sans politique portée.
// Tables et colonnes rendues illisibles par RENOMMAGE (jamais par trigger sur SELECT) ; les refus d'écriture du statut
// passent par un trigger sur UPDATE, comme `chrono_sla_ecritures_comptees`.
//
// CE QU'ILS NE TIENNENT PAS : les marqueurs `ack_breached`/`resolve_breached` ne sont pas remis à zéro à l'effacement
// (à dessein, écrit dans la doc) ; la suppression d'une politique (`sla_policy_delete`, `P10.31-v`, témoins
// `politique_sla_supprimee_degouverne_ses_dossiers`) ; la console
// (web/cases.js) ne lit ni `echeances_multi_niveau_non_lues` ni le 503 `CHRONO SLA NON LU` ; une politique écrite
// pendant qu'un dossier est en pause ne reprend que la pause portée (limite d'avant).
// Mutants (VERIF_MUT, retirés avant le commit) nommés sur chaque témoin.
// =====================================================================================
mod chrono_sla_lectures_avouees {
    use super::*;

    fn csl_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("csl-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
            // Politiques en P1 et P3 ; AUCUNE en P2 ni en P4.
            conn.execute_batch(
                "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,600,1,0,'root',0);
                 INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P3',3,3000,30000,1,0,'root',0);",
            )
            .unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn csl_au() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn csl_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn csl_entier(st: &AppState, sql: &str) -> Option<i64> {
        st.db.lock().query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).expect("fixture : la valeur se lit")
    }

    fn csl_dossier(st: &AppState, priorite: i64) -> i64 {
        let conn = st.db.lock();
        dossier_seme(&conn, "alice", "Dossier", 3, "", None, priorite)
    }

    async fn csl_patch(st: &AppState, id: i64, corps: Value) -> (u16, Value) {
        pb_json(case_update(State(st.clone()), Extension(csl_au()), Path(id), Json(corps)).await).await
    }

    /// La cause entre parenthèses d'un 503 de mise à jour, sous le préfixe attendu.
    async fn csl_cause(st: &AppState, id: i64, corps: Value, prefixe: &str) -> String {
        let (statut, avoue) = csl_patch(st, id, corps).await;
        assert_eq!(statut, 503, "503 nommé attendu ({avoue})");
        let phrase = avoue["error"].as_str().unwrap_or("").to_string();
        let prefixe = format!("{prefixe} (");
        assert!(phrase.starts_with(&prefixe) && phrase.ends_with(')'), "préfixe `{prefixe}` attendu : {avoue}");
        phrase[prefixe.len()..phrase.len() - 1].to_string()
    }

    /// CE QU'IL TIENT (`case_create`, `sla_policy_for`) : table `sla_policy` illisible -> le dossier est servi (200,
    /// identifiant) AVEC `echeances_multi_niveau_non_lues` nommé, `ack_due` non posé. Contrôles : table lisible -> corps
    /// d'avant champ pour champ (aucun aveu), échéances posées ; priorité sans politique (P2) -> `RienAFaire`, corps nu.
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=I3_POLITIQUE_OK` (le `.ok()` d'avant), `VERIF_MUT=I3_CREATE_TAIT`.
    #[tokio::test]
    async fn csl_creation_politique_non_lue_avouee_dossier_servi() {
        let (st, _t) = csl_etat("creation");
        csl_sql(&st, "ALTER TABLE sla_policy RENAME TO csl_politique_cachee;");
        let (statut, corps) = pb_json(case_create(State(st.clone()), Extension(csl_au()), Json(json!({ "title": "D", "priority": 1 }))).await).await;
        assert_eq!(statut, 200, "le dossier existe : il est servi : {corps}");
        assert!(corps["id"].as_i64().is_some(), "identifiant servi : {corps}");
        let aveu = corps.get("echeances_multi_niveau_non_lues").and_then(|v| v.as_str()).unwrap_or("");
        assert!(aveu.starts_with(CAUSE_ECHEANCES_MULTI_NIVEAU_NON_LUES), "l'aveu est porté : {corps}");
        assert!(aveu.contains("politique de la priorité 1:") && aveu.contains("sla_policy"), "la cause nomme la lecture : {aveu}");
        assert!(corps.get("echeances_multi_niveau_non_posees").is_none(), "ce n'est pas un refus d'écriture : {corps}");
        // Pas d'assertion « ack_due/sla_policy_id NULL » ici : sans table lisible, aucune valeur ne PEUT être posée, et
        // l'assertion serait vraie sous n'importe quelle implémentation (assertion vacante relevée par le vérificateur).
        // Le discriminant est l'aveu ci-dessus.
        csl_sql(&st, "ALTER TABLE csl_politique_cachee RENAME TO sla_policy;");

        // CONTRÔLE NOMINAL — corps d'avant, champ pour champ, et échéances posées.
        let (statut, corps) = pb_json(case_create(State(st.clone()), Extension(csl_au()), Json(json!({ "title": "D", "priority": 1 }))).await).await;
        assert_eq!(statut, 200);
        let id = corps["id"].as_i64().unwrap();
        let echeance = csl_entier(&st, &format!("SELECT sla_due FROM incident WHERE id={id}"));
        assert_eq!(corps, json!({ "id": id, "status": "new", "priority": 1, "priority_label": priority_label(1), "sla_due": echeance }));
        assert_eq!(csl_entier(&st, &format!("SELECT ack_due - ts FROM incident WHERE id={id}")), Some(60));
        // Absence ÉTABLIE (aucune politique en P2) : la sortie d'avant, jamais un aveu.
        let (statut, corps) = pb_json(case_create(State(st.clone()), Extension(csl_au()), Json(json!({ "title": "D", "priority": 2 }))).await).await;
        assert_eq!(statut, 200);
        let id = corps["id"].as_i64().unwrap();
        let echeance = csl_entier(&st, &format!("SELECT sla_due FROM incident WHERE id={id}"));
        assert_eq!(corps, json!({ "id": id, "status": "new", "priority": 2, "priority_label": priority_label(2), "sla_due": echeance }));
        let conn = st.db.lock();
        let (_, issue) = case_create_row_et_echeances(&conn, "alice", "D", 2, "", None, 2);
        assert_eq!(issue, IssueDuChronoSla::RienAFaire);
    }

    /// CE QU'IL TIENT (`sla_apply_policy`, lecture de la ligne) : colonne `sla_pause_accum` illisible -> `NonLu` nommé,
    /// RIEN d'écrit ; par la route, un changement de priorité rend le 503 `CAUSE_CHRONO_SLA_NON_LU` (c'était 204 sur les
    /// échéances de l'ancienne priorité). Contrôles : dossier absent -> `RienAFaire` ; colonne lisible -> `Ecrit`, 204.
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=I3_APPLY_OK` (le `.ok()` d'avant), `VERIF_MUT=I3_UPDATE_204`.
    #[tokio::test]
    async fn csl_ligne_du_dossier_non_lue_n_est_pas_rien_a_faire() {
        let (st, _t) = csl_etat("ligne");
        let id = csl_dossier(&st, 3);
        let avant = csl_entier(&st, &format!("SELECT resolve_due FROM incident WHERE id={id}"));
        assert!(avant.is_some(), "fixture : dossier gouverné par P3");
        csl_sql(&st, "ALTER TABLE incident RENAME COLUMN sla_pause_accum TO csl_pause_cachee;");
        {
            let conn = st.db.lock();
            match sla_apply_policy(&conn, id) {
                IssueDuChronoSla::NonLu(cause) => assert!(cause.starts_with("ligne du dossier:") && cause.contains("sla_pause_accum"), "{cause}"),
                autre => panic!("lecture ratée : NonLu attendu, pas {autre:?}"),
            }
        }
        let cause = csl_cause(&st, id, json!({ "priority": 1 }), CAUSE_CHRONO_SLA_NON_LU).await;
        assert!(cause.starts_with("ligne du dossier:"), "{cause}");
        assert_eq!(csl_entier(&st, &format!("SELECT resolve_due FROM incident WHERE id={id}")), avant, "rien d'écrit au chrono");
        csl_sql(&st, "ALTER TABLE incident RENAME COLUMN csl_pause_cachee TO sla_pause_accum;");

        // CONTRÔLES — absence établie, puis chemin nominal.
        {
            let conn = st.db.lock();
            assert_eq!(sla_apply_policy(&conn, 987_654), IssueDuChronoSla::RienAFaire, "dossier absent : rien à faire");
        }
        let (statut, corps) = csl_patch(&st, id, json!({ "priority": 1 })).await;
        assert_eq!(statut, 204, "{corps}");
        assert_eq!(csl_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(600), "échéance de P1");
    }

    /// CE QU'IL TIENT (`sla_on_status_change`) : colonne `sla_paused_since` illisible -> passage en `waiting` d'un dossier
    /// gouverné = 503 `CAUSE_CHRONO_SLA_NON_LU` (c'était 204 sur un chrono qui courait pendant l'attente). Contrôles :
    /// dossier absent -> `RienAFaire` ; colonne lisible -> 204 et chrono en pause.
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=I3_STATUT_OK` (le `.ok()` d'avant), `VERIF_MUT=I3_UPDATE_204`.
    #[tokio::test]
    async fn csl_chrono_non_lu_au_changement_de_statut() {
        let (st, _t) = csl_etat("statut");
        let id = csl_dossier(&st, 1);
        csl_sql(&st, "ALTER TABLE incident RENAME COLUMN sla_paused_since TO csl_pause_cachee;");
        let cause = csl_cause(&st, id, json!({ "status": "waiting" }), CAUSE_CHRONO_SLA_NON_LU).await;
        assert!(cause.starts_with("chrono du dossier:") && cause.contains("sla_paused_since"), "{cause}");
        csl_sql(&st, "ALTER TABLE incident RENAME COLUMN csl_pause_cachee TO sla_paused_since;");
        {
            let conn = st.db.lock();
            assert_eq!(sla_on_status_change(&conn, 987_654, "waiting", now()), IssueDuChronoSla::RienAFaire, "dossier absent");
        }
        let (statut, corps) = csl_patch(&st, id, json!({ "status": "in_progress" })).await;
        assert_eq!(statut, 204, "{corps}");
        let (statut, corps) = csl_patch(&st, id, json!({ "status": "waiting" })).await;
        assert_eq!(statut, 204, "{corps}");
        assert!(csl_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={id}")).is_some(), "chrono en pause");
    }

    /// CE QU'IL TIENT (recalcul de l'upsert) : politique illisible -> `recalcules` = 0, `manque` nomme les dossiers NON
    /// RECALCULÉS faute de lecture, réponse 200 (plus un 204 « tout fait »), échéances d'avant conservées. Contrôle :
    /// politique lisible -> deux recalculés et silence.
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=I3_RECALC_TAIT`, `VERIF_MUT=I3_POLITIQUE_OK`.
    #[test]
    fn csl_recalcul_politique_non_lue_nommee() {
        let conn = test_db();
        conn.execute_batch(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('p',2,60,600,1,0,'t',0);
             INSERT INTO incident(ts,updated,title,status,severity,priority,resolve_due) VALUES(1000,1000,'a','new',2,2,77);
             INSERT INTO incident(ts,updated,title,status,severity,priority,resolve_due) VALUES(1001,1001,'b','new',2,2,77);
             ALTER TABLE sla_policy RENAME TO csl_politique_cachee;",
        )
        .unwrap();
        let r = sla_recalcule_la_priorite_bornee(&conn, 2, 10);
        assert_eq!(r.recalcules, 0, "rien de lu, rien de compté");
        let raison = r.manque.clone().expect("la lecture ratée est dite");
        assert!(raison.contains("2 échéance(s) NON RECALCULÉE(S) faute de LECTURE") && raison.contains("politique de la priorité 2:"), "{raison}");
        assert_eq!(reponse_de_l_upsert_sla(Ok(()), &r).status(), StatusCode::OK, "plus un 204 « tout fait »");
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM incident WHERE resolve_due=77", [], |r| r.get(0)).unwrap(), 2, "rien d'écrit");
        conn.execute_batch("ALTER TABLE csl_politique_cachee RENAME TO sla_policy;").unwrap();
        let r = sla_recalcule_la_priorite_bornee(&conn, 2, 10);
        assert_eq!((r.recalcules, r.manque.clone()), (2, None), "nominal : deux recalculés, silence");
        assert_eq!(reponse_de_l_upsert_sla(Ok(()), &r).status(), StatusCode::NO_CONTENT);
    }

    /// CE QU'IL TIENT (`P10.20-w`, priorité écrite sans politique) : un dossier P1 (gouverné) passé en P2 (aucune
    /// politique) retombe sur le régime legacy — `sla_policy_id`, `ack_due`, `resolve_due` NULL, `sla_due` = cible P2 —
    /// au lieu de garder la politique et les échéances de P1. Contrôle : P1 -> P3 pose la politique de P3 ; un dossier
    /// legacy passé en P4 reste `RienAFaire` (aucune écriture, mode 0).
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=I3_GARDE_ANCIENNE` (la sortie `RienAFaire` d'avant).
    #[tokio::test]
    async fn csl_priorite_sans_politique_retombe_sur_le_legacy() {
        let (st, _t) = csl_etat("legacy");
        let id = csl_dossier(&st, 1);
        assert!(csl_entier(&st, &format!("SELECT sla_policy_id FROM incident WHERE id={id}")).is_some(), "fixture : gouverné par P1");
        let (statut, corps) = csl_patch(&st, id, json!({ "priority": 2 })).await;
        assert_eq!(statut, 204, "{corps}");
        for col in ["sla_policy_id", "ack_due", "resolve_due"] {
            assert_eq!(csl_entier(&st, &format!("SELECT {col} FROM incident WHERE id={id}")), None, "{col} : plus celui de P1");
        }
        assert_eq!(csl_entier(&st, &format!("SELECT sla_due - ts FROM incident WHERE id={id}")), Some(sla_target_s(2)), "SLA legacy de P2");

        // CONTRÔLES — priorité AVEC politique : celle-ci est posée ; dossier legacy : rien n'est écrit.
        let (statut, _) = csl_patch(&st, id, json!({ "priority": 3 })).await;
        assert_eq!(statut, 204);
        assert_eq!(csl_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(30000), "politique de P3");
        let legacy = csl_dossier(&st, 2);
        csl_sql(&st, &format!("UPDATE incident SET priority=4 WHERE id={legacy};"));
        let conn = st.db.lock();
        assert_eq!(sla_apply_policy(&conn, legacy), IssueDuChronoSla::RienAFaire, "mode 0 : aucune écriture");
    }

    /// CE QU'IL TIENT (`P10.20-w`, rattrapage) : P1 -> P2 écrite, statut refusé -> le rattrapage efface la politique de
    /// P1 et la cause le dit ; et une politique ILLISIBLE au rattrapage est dite « NON LUE » (c'était le silence d'un
    /// « aucune politique »).
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=I3_GARDE_ANCIENNE` (premier volet), `VERIF_MUT=I3_POLITIQUE_OK` (second).
    #[tokio::test]
    async fn csl_rattrapage_dit_l_effacement_et_la_politique_non_lue() {
        let (st, _t) = csl_etat("rattrapage");
        let id = csl_dossier(&st, 1);
        csl_sql(&st, "CREATE TEMP TRIGGER csl_refus_statut BEFORE UPDATE OF status ON incident BEGIN SELECT RAISE(ABORT, 'csl status'); END;");
        let cause = csl_cause(&st, id, json!({ "priority": 2, "status": "in_progress" }), CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE).await;
        assert_eq!(cause, "status: csl status ; échéance recalculée sur la priorité écrite, politique de l'ancienne priorité effacée (aucune politique active pour la priorité écrite)");
        assert_eq!(csl_entier(&st, &format!("SELECT sla_policy_id FROM incident WHERE id={id}")), None, "politique de P1 effacée");

        let id = csl_dossier(&st, 3);
        csl_sql(&st, "ALTER TABLE sla_policy RENAME TO csl_politique_cachee;");
        let cause = csl_cause(&st, id, json!({ "priority": 1, "status": "in_progress" }), CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE).await;
        assert!(cause.starts_with("status: csl status ; échéance recalculée sur la priorité écrite ; ÉCHÉANCES MULTI-NIVEAU NON RECALCULÉES : politique de la priorité écrite NON LUE ("), "{cause}");
        assert_eq!(csl_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(30000), "rien d'écrit : échéance de P3");
    }

    /// CE QU'IL TIENT (`P10.20-w`, pause orpheline) : un dossier en pause sous P1, passé en P2 (politique effacée), puis
    /// sorti de `waiting` -> la pause est REPRISE (cumul compté, `sla_paused_since` NULL) ; sinon le tour multi-niveau le
    /// sauterait pour toujours au retour d'une politique. Contrôle : repassé en P1, échéance = ts + 600 + pause.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=I3_PAUSE_ORPHELINE` (inerte dès que la politique est NULL, comme avant).
    #[tokio::test]
    async fn csl_pause_reprise_apres_effacement_de_la_politique() {
        let (st, _t) = csl_etat("pause");
        let id = csl_dossier(&st, 1);
        let (statut, _) = csl_patch(&st, id, json!({ "status": "waiting" })).await;
        assert_eq!(statut, 204);
        csl_sql(&st, &format!("UPDATE incident SET sla_paused_since = sla_paused_since - 1000 WHERE id={id};"));
        let (statut, _) = csl_patch(&st, id, json!({ "priority": 2 })).await;
        assert_eq!(statut, 204);
        assert_eq!(csl_entier(&st, &format!("SELECT sla_policy_id FROM incident WHERE id={id}")), None, "fixture : politique effacée");
        assert!(csl_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={id}")).is_some(), "la pause est conservée");
        let (statut, _) = csl_patch(&st, id, json!({ "status": "in_progress" })).await;
        assert_eq!(statut, 204);
        assert_eq!(csl_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={id}")), None, "pause reprise");
        let cumul = csl_entier(&st, &format!("SELECT sla_pause_accum FROM incident WHERE id={id}")).unwrap_or(0);
        assert!(cumul >= 1000, "cumul compté : {cumul}");
        let (statut, _) = csl_patch(&st, id, json!({ "priority": 1 })).await;
        assert_eq!(statut, 204);
        assert_eq!(csl_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(600 + cumul), "P1 + pause");
        assert_eq!(csl_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={id}")), None, "le tour ne le saute pas");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // LES SIX BRAS DU RATTRAPAGE ET DE LA MISE À JOUR (cases.rs) — un témoin par bras, chacun atteint par sa panne propre.
    // Relevé du vérificateur indépendant : chacun de ces bras pouvait être tu (mutant) sans qu'aucun témoin ne rougisse.
    // MUTANTS (VERIF_MUT, posés sur cases.rs le temps de la preuve, retirés avant le commit) : I3C_M17, I3C_M20,
    // I3C_M21, I3C_M25, I3C_M26, I3C_M27 — chacun ne fait rougir que son témoin.
    // ---------------------------------------------------------------------------------------------------------------

    /// Fixe un refus d'écriture sur une colonne par trigger TEMP (jamais sur SELECT).
    fn csl_refuser(st: &AppState, nom: &str, colonne: &str, message: &str) {
        csl_sql(st, &format!("CREATE TEMP TRIGGER {nom} BEFORE UPDATE OF {colonne} ON incident BEGIN SELECT RAISE(ABORT, '{message}'); END;"));
    }

    /// Vérifie qu'une cause commence par `prefixe`, contient `contient` et finit par `)`.
    fn csl_forme(cause: &str, prefixe: &str, contient: &str) {
        assert!(cause.starts_with(prefixe), "préfixe attendu `{prefixe}` : {cause}");
        assert!(cause.contains(contient), "la cause nomme `{contient}` : {cause}");
        assert!(cause.ends_with(')'), "la cause du moteur est entre parenthèses : {cause}");
    }

    /// BRAS `case_apply_update` / statut `NonLu` AVEC priorité écrite : P3 -> P1 et `in_progress`, chrono illisible
    /// (`sla_paused_since` renommée) -> 503 « non lu », ET les échéances multi-niveau suivent quand même P1
    /// (`resolve_due` = ts + 600) ; la cause dit que leur relecture n'a pas eu lieu.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=I3C_M17` (rattrapage sauté : `resolve_due` reste celui de P3).
    #[tokio::test]
    async fn csl_bras_statut_non_lu_avec_priorite_rattrape_les_echeances() {
        let (st, _t) = csl_etat("bras-m17");
        let id = csl_dossier(&st, 3);
        csl_sql(&st, "ALTER TABLE incident RENAME COLUMN sla_paused_since TO csl_pause_cachee;");
        let cause = csl_cause(&st, id, json!({ "priority": 1, "status": "in_progress" }), CAUSE_CHRONO_SLA_NON_LU).await;
        csl_forme(&cause, "chrono du dossier: ", " ; ÉCHÉANCES MULTI-NIVEAU NON RELUES après le rattrapage (");
        assert_eq!(csl_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(600), "échéance de P1 posée");
    }

    /// BRAS `rattraper_l_echeance` / statut TERMINAL : P1 -> P3 et `closed` écrits, verdict refusé, chrono illisible ->
    /// la cause dit « REPRISE DU CHRONO SLA NON LUE » (le dossier clos peut rester en pause : on ne le sait pas).
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=I3C_M20` (la phrase se tait).
    #[tokio::test]
    async fn csl_bras_rattrapage_terminal_dit_la_reprise_non_lue() {
        let (st, _t) = csl_etat("bras-m20");
        let id = csl_dossier(&st, 1);
        csl_sql(&st, "ALTER TABLE incident RENAME COLUMN sla_paused_since TO csl_pause_cachee;");
        csl_refuser(&st, "csl_refus_verdict", "disposition", "csl verdict");
        let corps = json!({ "priority": 3, "status": "closed", "disposition": "true_positive" });
        let cause = csl_cause(&st, id, corps, CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE).await;
        csl_forme(&cause, "disposition: csl verdict ; REPRISE DU CHRONO SLA NON LUE (chrono du dossier: ", "sla_paused_since");
    }

    /// BRAS `dire_la_reprise` / `NonLu` : P1 -> P2 (sans politique) et `in_progress` écrits, verdict refusé, chrono
    /// illisible -> l'effacement de la politique de P1 est dit, PUIS la reprise non lue.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=I3C_M21` (la reprise non lue se tait).
    #[tokio::test]
    async fn csl_bras_effacement_puis_reprise_non_lue() {
        let (st, _t) = csl_etat("bras-m21");
        let id = csl_dossier(&st, 1);
        csl_sql(&st, "ALTER TABLE incident RENAME COLUMN sla_paused_since TO csl_pause_cachee;");
        csl_refuser(&st, "csl_refus_verdict", "disposition", "csl verdict");
        let corps = json!({ "priority": 2, "status": "in_progress", "disposition": "benign" });
        let cause = csl_cause(&st, id, corps, CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE).await;
        csl_forme(
            &cause,
            "disposition: csl verdict ; échéance recalculée sur la priorité écrite, politique de l'ancienne priorité effacée (aucune politique active pour la priorité écrite) ; REPRISE DU CHRONO SLA NON LUE (chrono du dossier: ",
            "sla_paused_since",
        );
        assert_eq!(csl_entier(&st, &format!("SELECT sla_policy_id FROM incident WHERE id={id}")), None, "politique de P1 effacée");
    }

    /// BRAS effacement `Refuse` : P1 -> P2 écrite, statut refusé, effacement de la politique de P1 refusé par la base ->
    /// la cause dit « POLITIQUE DE L'ANCIENNE PRIORITÉ NON EFFACÉE » (c'est le défaut même de la clé : sans elle, la
    /// politique de P1 reste portée en silence).
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=I3C_M25`.
    #[tokio::test]
    async fn csl_bras_effacement_refuse_dit_la_politique_gardee() {
        let (st, _t) = csl_etat("bras-m25");
        let id = csl_dossier(&st, 1);
        csl_refuser(&st, "csl_refus_statut", "status", "csl status");
        csl_refuser(&st, "csl_refus_politique", "sla_policy_id", "csl politique");
        let cause = csl_cause(&st, id, json!({ "priority": 2, "status": "in_progress" }), CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE).await;
        assert_eq!(
            cause,
            "status: csl status ; échéance recalculée sur la priorité écrite ; POLITIQUE DE L'ANCIENNE PRIORITÉ NON EFFACÉE (sla_policy_id/ack_due/resolve_due (effacement): csl politique)"
        );
        assert!(csl_entier(&st, &format!("SELECT sla_policy_id FROM incident WHERE id={id}")).is_some(), "fixture : politique de P1 gardée");
    }

    /// BRAS effacement `NonLu` : P1 -> P2 écrite, statut refusé, ligne du dossier illisible (`sla_pause_accum` renommée)
    /// -> la cause dit « ÉCHÉANCES MULTI-NIVEAU NON LUES », rien n'est effacé.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=I3C_M26`.
    #[tokio::test]
    async fn csl_bras_effacement_non_lu_le_dit() {
        let (st, _t) = csl_etat("bras-m26");
        let id = csl_dossier(&st, 1);
        csl_sql(&st, "ALTER TABLE incident RENAME COLUMN sla_pause_accum TO csl_pause_cachee;");
        csl_refuser(&st, "csl_refus_statut", "status", "csl status");
        let cause = csl_cause(&st, id, json!({ "priority": 2, "status": "in_progress" }), CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE).await;
        csl_forme(&cause, "status: csl status ; échéance recalculée sur la priorité écrite ; ÉCHÉANCES MULTI-NIVEAU NON LUES (ligne du dossier: ", "sla_pause_accum");
        assert!(csl_entier(&st, &format!("SELECT sla_policy_id FROM incident WHERE id={id}")).is_some(), "rien d'effacé sur une ligne non lue");
    }

    /// BRAS du filtre `refus` / `NonLu` : P3 -> P1 écrite (politique lisible), statut refusé, ligne du dossier illisible
    /// pour `sla_apply_policy` seulement (`first_response_ts` illisible ; la relecture ne la lit pas) -> la cause porte
    /// « NON LU — ligne du dossier » au lieu du générique « (ack_due/resolve_due/pause) ».
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=I3C_M27`.
    /// `P10.21-n` (vague AC) — LA FIXTURE AFFIRMAIT LE DÉFAUT CORRIGÉ : elle RENOMMAIT `first_response_ts`, que la
    /// chronologie de la priorité écrit (MTTA) ; `case_add_item` avalait ce refus et la priorité restait écrite. La
    /// chronologie étant désormais comptée dans le geste du champ, la priorité était annulée et le bras visé jamais
    /// atteint. La colonne garde son nom et porte un texte : l'`UPDATE … WHERE first_response_ts IS NULL` de la
    /// chronologie ne touche aucune ligne sans erreur, la lecture typée de `sla_apply_policy` échoue — même bras.
    #[tokio::test]
    async fn csl_bras_application_non_lue_nommee_dans_le_rattrapage() {
        let (st, _t) = csl_etat("bras-m27");
        let id = csl_dossier(&st, 3);
        csl_sql(&st, &format!("UPDATE incident SET first_response_ts='illisible' WHERE id={id};"));
        csl_refuser(&st, "csl_refus_statut", "status", "csl status");
        let cause = csl_cause(&st, id, json!({ "priority": 1, "status": "in_progress" }), CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE).await;
        csl_forme(
            &cause,
            "status: csl status ; échéance recalculée sur la priorité écrite ; ÉCHÉANCES MULTI-NIVEAU NON RECALCULÉES sur la priorité écrite (NON LU — ligne du dossier: ",
            "first_response_ts",
        );
        assert_eq!(csl_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(30000), "rien d'écrit : échéance de P3");
    }
}
