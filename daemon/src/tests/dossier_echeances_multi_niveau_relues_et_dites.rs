// =====================================================================================
// `P10.20-w` (reprise après revue) — LE RATTRAPAGE MULTI-NIVEAU DIT CE QUE LA BASE PORTE, SUR CHACUN DE SES SITES.
//
// CE QUI ÉTAIT FAUX, MESURÉ SUR d50d8d1 :
//   * aucun témoin ne jouait la branche « ÉCHÉANCES MULTI-NIVEAU NON RECALCULÉES » : une relecture qui affirmait
//     toujours « recalculées » passait au vert ;
//   * le site `escalated` refusé -> rattrapage, la garde `priorite_ecrite`, le mode 0 (cause inchangée, mot pour mot)
//     et les suffixes des bras `Err` de `rattraper_l_echeance` n'avaient pas de témoin ;
//   * un PATCH qui sort de `waiting` et écrit la priorité, puis voit un champ suivant refusé : le rattrapage rejouait
//     `sla_apply_policy` SANS la reprise du chrono — chrono resté en pause sur un dossier actif, `resolve_due` sans la
//     pause (600 au lieu de 1600) — pendant que la cause disait « échéances multi-niveau recalculées ». Corrigé : la
//     reprise (`sla_on_status_change`) est rejouée d'abord, et la relecture exige `sla_paused_since` NULL hors `waiting`.
//
// CE QU'ILS NE TIENNENT PAS : `sla_on_status_change` et `sla_apply_policy` avalent toujours leurs écritures (caseops.rs,
// hors lot) — on RELIT, on ne compte pas ; un statut écrit SANS priorité écrite puis un verdict refusé ne rejoue pas
// la reprise du chrono (aucun rattrapage hors priorité écrite, comportement d'avant) ; l'entrée en `waiting` n'est pas
// relue (un dossier non gouverné avant la demande n'a légitimement pas de pause en cours) ; `ack_due` n'est pas relu.
// Mutants (VERIF_MUT, retirés avant le commit) nommés sur chaque témoin.
// =====================================================================================
mod dossier_echeances_multi_niveau_relues_et_dites {
    use super::*;

    const DMR_RECALCULEES: &str = "échéances multi-niveau recalculées sur la priorité écrite";
    const DMR_NON_RECALCULEES: &str = "ÉCHÉANCES MULTI-NIVEAU NON RECALCULÉES";

    fn dmr_etat(tag: &str, politiques: bool) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("dmr-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
            if politiques {
                dmr_politiques(&conn);
            }
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn dmr_politiques(conn: &Connection) {
        conn.execute_batch(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,600,1,0,'root',0);
             INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P3',3,3000,30000,1,0,'root',0);",
        )
        .unwrap();
    }

    fn dmr_utilisateur() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn dmr_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn dmr_refuser(st: &AppState, nom: &str, colonne: &str) {
        dmr_ecrire(st, &format!(
            "CREATE TEMP TRIGGER {nom} BEFORE UPDATE OF {colonne} ON incident BEGIN SELECT RAISE(ABORT, 'dmr {colonne}'); END;"
        ));
    }

    fn dmr_entier(st: &AppState, sql: &str) -> Option<i64> {
        st.db.lock().query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).expect("fixture : la valeur se lit")
    }

    fn dmr_dossier_p3(st: &AppState) -> i64 {
        let conn = st.db.lock();
        dossier_seme(&conn, "alice", "Dossier", 3, "", None, 3)
    }

    async fn dmr_cause(st: &AppState, id: i64, corps: Value) -> String {
        let (statut, avoue) = pb_json(case_update(State(st.clone()), Extension(dmr_utilisateur()), Path(id), Json(corps)).await).await;
        assert_eq!(statut, 503, "écriture refusée : 503 attendu ({avoue})");
        let phrase = avoue["error"].as_str().unwrap_or("").to_string();
        let prefixe = format!("{CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE} (");
        assert!(phrase.starts_with(&prefixe) && phrase.ends_with(')'), "{avoue}");
        phrase[prefixe.len()..phrase.len() - 1].to_string()
    }

    /// CE QU'IL TIENT : `sla_apply_policy` refusé par la base au rattrapage (statut refusé après une priorité écrite) ->
    /// la cause dit « NON RECALCULÉES », jamais « recalculées », et `resolve_due` garde la cible de P3.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4_RELU_MENT` (toute relecture non terminale dit « recalculées »).
    #[tokio::test]
    async fn dmr_une_politique_refusee_au_rattrapage_est_dite_non_recalculee() {
        let (st, _tmp) = dmr_etat("relu", true);
        let id = dmr_dossier_p3(&st);
        dmr_refuser(&st, "dmr_a", "status");
        dmr_refuser(&st, "dmr_b", "resolve_due");
        let cause = dmr_cause(&st, id, json!({ "priority": 1, "status": "in_progress" })).await;
        assert!(cause.starts_with("status: dmr status ; échéance recalculée sur la priorité écrite ; "), "{cause}");
        assert!(cause.contains(DMR_NON_RECALCULEES), "la relecture dit le refus : {cause}");
        assert!(!cause.contains(DMR_RECALCULEES), "la relecture ne ment pas : {cause}");
        assert_eq!(dmr_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(30000), "resolve_due de P3 en base");
    }

    /// CE QU'IL TIENT : `escalated` refusé au recalcul après une priorité écrite -> rattrapage multi-niveau, dit mot
    /// pour mot, et `resolve_due` suit P1.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4_ESCALATED_NU` (la sortie `NonEcrite("escalated: …")` d'avant).
    #[tokio::test]
    async fn dmr_escalade_refusee_apres_priorite_ecrite_rattrape_le_multi_niveau() {
        let (st, _tmp) = dmr_etat("escalade", true);
        let id = dmr_dossier_p3(&st);
        dmr_refuser(&st, "dmr_a", "escalated");
        let cause = dmr_cause(&st, id, json!({ "priority": 1 })).await;
        assert_eq!(cause, format!("escalated: dmr escalated, {DMR_RECALCULEES}"));
        assert_eq!(dmr_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(600), "resolve_due de P1");
    }

    /// CE QU'IL TIENT : SANS priorité écrite, un `sla_due` refusé ne rejoue AUCUNE politique : un dossier non gouverné
    /// le reste (la demande a échoué), et la cause est le seul refus.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4_SANS_GARDE` (`priorite_ecrite` ignoré) — politique posée.
    #[tokio::test]
    async fn dmr_sans_priorite_ecrite_aucune_politique_n_est_posee() {
        let (st, _tmp) = dmr_etat("garde", false);
        let id = dmr_dossier_p3(&st);
        { let conn = st.db.lock(); dmr_politiques(&conn); }
        assert_eq!(dmr_entier(&st, &format!("SELECT sla_policy_id FROM incident WHERE id={id}")), None, "fixture : dossier non gouverné");
        dmr_refuser(&st, "dmr_a", "sla_due");
        let cause = dmr_cause(&st, id, json!({ "title": "Titre neuf" })).await;
        assert_eq!(cause, "sla_due: dmr sla_due");
        assert_eq!(dmr_entier(&st, &format!("SELECT sla_policy_id FROM incident WHERE id={id}")), None, "toujours non gouverné");
        assert_eq!(dmr_entier(&st, &format!("SELECT resolve_due FROM incident WHERE id={id}")), None);
    }

    /// CE QU'IL TIENT : MODE 0 (aucune politique) — la cause d'un statut refusé après une priorité écrite est celle
    /// d'avant, mot pour mot : aucun mot sur le multi-niveau.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4_MODE0_BRUIT` (« NON RECALCULÉES » rendu sans politique).
    #[tokio::test]
    async fn dmr_mode_zero_la_cause_est_inchangee() {
        let (st, _tmp) = dmr_etat("mode0", false);
        let id = dmr_dossier_p3(&st);
        dmr_refuser(&st, "dmr_a", "status");
        let cause = dmr_cause(&st, id, json!({ "priority": 1, "status": "in_progress" })).await;
        assert_eq!(cause, "status: dmr status ; échéance recalculée sur la priorité écrite");
        assert_eq!(dmr_entier(&st, &format!("SELECT sla_policy_id FROM incident WHERE id={id}")), None);
    }

    /// CE QU'IL TIENT : statut ET `sla_due` refusés, puis statut ET `escalated` refusés : le rattrapage multi-niveau
    /// est dit dans les deux bras `Err` de `rattraper_l_echeance`, et `resolve_due` suit P1.
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=G4_ERR_TAIT_DUE`, `VERIF_MUT=G4_ERR_TAIT_ESC` (suffixe tu).
    #[tokio::test]
    async fn dmr_les_bras_err_du_rattrapage_disent_le_multi_niveau() {
        let (st, _tmp) = dmr_etat("bras", true);
        for (colonne, attendu) in [
            ("sla_due", format!("status: dmr status ; ÉCHÉANCE NON RECALCULÉE sur la priorité écrite (sla_due: dmr sla_due), {DMR_RECALCULEES}")),
            ("escalated", format!("status: dmr status ; échéance recalculée sur la priorité écrite, ESCALADE NON RÉ-ARMÉE (escalated: dmr escalated), {DMR_RECALCULEES}")),
        ] {
            let id = dmr_dossier_p3(&st);
            dmr_refuser(&st, "dmr_a", "status");
            dmr_refuser(&st, "dmr_b", colonne);
            let cause = dmr_cause(&st, id, json!({ "priority": 1, "status": "in_progress" })).await;
            assert_eq!(cause, attendu, "{colonne}");
            assert_eq!(dmr_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(600), "{colonne} : resolve_due de P1");
            dmr_ecrire(&st, "DROP TRIGGER dmr_a; DROP TRIGGER dmr_b;");
        }
    }

    /// Dossier P3 gouverné, en `waiting` depuis 1000 s (chrono en pause).
    fn dmr_dossier_en_pause(st: &AppState) -> i64 {
        let id = dmr_dossier_p3(st);
        dmr_ecrire(st, &format!(
            "UPDATE incident SET status='waiting', sla_paused_since=CAST(strftime('%s','now') AS INTEGER) - 1000 WHERE id={id};"
        ));
        id
    }

    /// CE QU'IL TIENT : sortie de `waiting` + priorité écrite, verdict refusé : la reprise du chrono est rejouée comme en
    /// nominal (pause cumulée, chrono plus en pause) et `resolve_due` = ts + 600 + pause ; la cause le dit.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4_SANS_REPRISE` (la reprise n'est pas rejouée) — chrono en pause.
    #[tokio::test]
    async fn dmr_sortie_de_pause_puis_refus_rejoue_la_reprise_du_chrono() {
        let (st, _tmp) = dmr_etat("pause", true);
        let id = dmr_dossier_en_pause(&st);
        dmr_refuser(&st, "dmr_a", "disposition");
        let cause = dmr_cause(&st, id, json!({ "priority": 1, "status": "in_progress", "disposition": "true_positive" })).await;
        assert_eq!(cause, format!("disposition: dmr disposition ; échéance recalculée sur la priorité écrite, {DMR_RECALCULEES}"));
        assert_eq!(dmr_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={id}")), None, "le chrono reprend");
        let pause = dmr_entier(&st, &format!("SELECT sla_pause_accum FROM incident WHERE id={id}")).unwrap_or(0);
        assert!((1000..=1010).contains(&pause), "pause cumulée : {pause}");
        assert_eq!(dmr_entier(&st, &format!("SELECT resolve_due - ts - sla_pause_accum FROM incident WHERE id={id}")), Some(600));
    }

    /// CE QU'IL TIENT : la reprise elle-même refusée par la base -> chrono resté en pause, et la cause dit
    /// « NON RECALCULÉES », jamais « recalculées » (la relecture juge la pause, pas seulement `resolve_due`).
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4_SANS_RELU_PAUSE` (la pause n'est pas relue).
    #[tokio::test]
    async fn dmr_reprise_refusee_est_dite_non_recalculee() {
        let (st, _tmp) = dmr_etat("reprise", true);
        let id = dmr_dossier_en_pause(&st);
        dmr_refuser(&st, "dmr_a", "disposition");
        dmr_refuser(&st, "dmr_b", "sla_paused_since");
        let cause = dmr_cause(&st, id, json!({ "priority": 1, "status": "in_progress", "disposition": "true_positive" })).await;
        assert!(cause.contains(DMR_NON_RECALCULEES), "{cause}");
        assert!(!cause.contains(DMR_RECALCULEES), "{cause}");
        assert!(dmr_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={id}")).is_some(), "fixture : la reprise a bien été refusée");
    }
}
