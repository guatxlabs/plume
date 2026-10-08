// =====================================================================================
// `P10.20-w` (reprise, second tour de revue) — CHAQUE CONJONCTION DU RATTRAPAGE MULTI-NIVEAU A SON TÉMOIN.
//
// CE QUI ÉTAIT FAUX, MESURÉ PAR LE VÉRIFICATEUR SUR 89a8937e (sondes reprises ici, mutants rejoués) :
//   * le second site d'appel (`politique`, `sla_due`/`escalated` refusé) passait le statut écrit au rattrapage sans
//     témoin : `None` à sa place laissait le chrono en pause sur un dossier actif, tout vert ;
//   * la relecture : `p == pid`, `due == ts + cible + pause`, le bras `Err`, et les deux termes de `reprise_due`
//     pouvaient sauter sans rougir ; le suffixe multi-niveau du bras `Ok(0)` aussi ;
//   * trou non déclaré : sortie de `waiting` vers un statut TERMINAL + priorité écrite, puis verdict refusé -> le
//     dossier clos gardait `sla_paused_since` (la sortie nominale le remet à NULL). Corrigé dans
//     `rattraper_l_echeance` : sur statut terminal ÉCRIT, la reprise du chrono est rejouée ; rien n'est recalculé.
//
// CE QU'ILS NE TIENNENT PAS : sans priorité écrite, un statut écrit puis un verdict refusé ne rejoue toujours pas la
// reprise (aucun rattrapage hors priorité écrite) ; `sla_on_status_change` avale encore ses écritures (caseops.rs) ;
// le bras terminal de la relecture est inatteignable (les deux appelants filtrent le terminal) — défensif, sans témoin ;
// `ack_due` n'est pas rattrapé (figé par `first_response_ts` posé avec l'élément « priorité »).
// =====================================================================================
mod dossier_rattrapage_multi_niveau_chaque_conjonction {
    use super::*;

    const DRC_RECALCULEES: &str = "échéances multi-niveau recalculées sur la priorité écrite";
    const DRC_NON_RECALCULEES: &str = "ÉCHÉANCES MULTI-NIVEAU NON RECALCULÉES";

    fn drc_etat(tag: &str, memes_cibles: bool) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("drc-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn));
            conn.execute("DELETE FROM incident", []).unwrap();
            let res1 = if memes_cibles { 30000 } else { 600 };
            conn.execute_batch(&format!(
                "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,{res1},1,0,'root',0);
                 INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P3',3,3000,30000,1,0,'root',0);"
            )).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn drc_au() -> AuthUser {
        AuthUser { name: "analyste".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }

    fn drc_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture `{sql}` ({e})"));
    }

    fn drc_entier(st: &AppState, sql: &str) -> Option<i64> {
        st.db.lock().query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).unwrap()
    }

    fn drc_dossier(st: &AppState) -> i64 {
        let conn = st.db.lock();
        dossier_seme(&conn, "alice", "Dossier", 3, "", None, 3)
    }

    async fn drc_cause(st: &AppState, id: i64, corps: Value) -> String {
        let (statut, avoue) = pb_json(case_update(State(st.clone()), Extension(drc_au()), Path(id), Json(corps)).await).await;
        assert_eq!(statut, 503, "{avoue}");
        let phrase = avoue["error"].as_str().unwrap_or("").to_string();
        let prefixe = format!("{CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE} (");
        assert!(phrase.starts_with(&prefixe) && phrase.ends_with(')'), "{avoue}");
        phrase[prefixe.len()..phrase.len() - 1].to_string()
    }

    // site `politique` (cases.rs:394, argument statut) : sortie de `waiting` + priorité écrite, puis `sla_due` refusé.
    // MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4W_POL_STATUT` (témoins du lot précédent tous verts sous elle).
    #[tokio::test]
    async fn drc_p1_sortie_de_pause_puis_sla_due_refuse_rejoue_la_reprise() {
        let (st, _t) = drc_etat("p1", false);
        let id = drc_dossier(&st);
        drc_sql(&st, &format!("UPDATE incident SET status='waiting', sla_paused_since=CAST(strftime('%s','now') AS INTEGER) - 1000 WHERE id={id};"));
        drc_sql(&st, "CREATE TEMP TRIGGER drc_a BEFORE UPDATE OF sla_due ON incident BEGIN SELECT RAISE(ABORT, 'drc sla_due'); END;");
        let cause = drc_cause(&st, id, json!({ "priority": 1, "status": "in_progress" })).await;
        assert_eq!(cause, format!("sla_due: drc sla_due, {DRC_RECALCULEES}"));
        assert_eq!(drc_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={id}")), None, "le chrono reprend");
        assert_eq!(drc_entier(&st, &format!("SELECT resolve_due - ts - sla_pause_accum FROM incident WHERE id={id}")), Some(600));
    }

    // bras `Ok(0)` de `rattraper_l_echeance` (cases.rs:435).
    // MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4W_OK0_TAIT` (témoins du lot précédent tous verts sous elle).
    #[tokio::test]
    async fn drc_p2_bras_ok0_dit_le_multi_niveau() {
        let (st, _t) = drc_etat("p2", false);
        let id = drc_dossier(&st);
        drc_sql(&st, "CREATE TEMP TRIGGER drc_a BEFORE UPDATE OF status ON incident BEGIN SELECT RAISE(ABORT, 'drc status'); END;
                     CREATE TEMP TRIGGER drc_b BEFORE UPDATE OF sla_due ON incident BEGIN SELECT RAISE(IGNORE); END;");
        let cause = drc_cause(&st, id, json!({ "priority": 1, "status": "in_progress" })).await;
        assert_eq!(cause, format!("status: drc status ; ÉCHÉANCE NON RECALCULÉE sur la priorité écrite (sla_due: aucune ligne écrite), {DRC_RECALCULEES}"));
    }

    // `reprise_due` terme `statut == "waiting"` (cases.rs:463).
    // MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4W_REPRISE_WAIT` (témoins du lot précédent tous verts sous elle).
    #[tokio::test]
    async fn drc_p3_entree_en_waiting_puis_refus_dit_recalculees() {
        let (st, _t) = drc_etat("p3", false);
        let id = drc_dossier(&st);
        drc_sql(&st, "CREATE TEMP TRIGGER drc_a BEFORE UPDATE OF disposition ON incident BEGIN SELECT RAISE(ABORT, 'drc disposition'); END;");
        let cause = drc_cause(&st, id, json!({ "priority": 1, "status": "waiting", "disposition": "true_positive" })).await;
        assert_eq!(cause, format!("disposition: drc disposition ; échéance recalculée sur la priorité écrite, {DRC_RECALCULEES}"));
        assert!(drc_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={id}")).is_some(), "chrono en pause comme en nominal");
    }

    // `reprise_due` terme `statut_ecrit.is_none()` (cases.rs:463) : pause héritée sur un dossier actif.
    // MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4W_REPRISE_NONE` (témoins du lot précédent tous verts sous elle).
    #[tokio::test]
    async fn drc_p4_statut_non_ecrit_pause_heritee() {
        let (st, _t) = drc_etat("p4", false);
        let id = drc_dossier(&st);
        drc_sql(&st, &format!("UPDATE incident SET status='in_progress', sla_paused_since=CAST(strftime('%s','now') AS INTEGER) - 1000 WHERE id={id};"));
        drc_sql(&st, "CREATE TEMP TRIGGER drc_a BEFORE UPDATE OF escalated ON incident BEGIN SELECT RAISE(ABORT, 'drc escalated'); END;");
        let cause = drc_cause(&st, id, json!({ "priority": 1 })).await;
        assert_eq!(cause, format!("escalated: drc escalated, {DRC_RECALCULEES}"));
    }

    // conjonction `p == pid` (cases.rs:466) : P1 et P3 de même cible de résolution, politique refusée.
    // MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4W_PID` (témoins du lot précédent tous verts sous elle).
    #[tokio::test]
    async fn drc_p5_politique_non_posee_meme_cible_dite_non_recalculee() {
        let (st, _t) = drc_etat("p5", true);
        let id = drc_dossier(&st);
        drc_sql(&st, "CREATE TEMP TRIGGER drc_a BEFORE UPDATE OF status ON incident BEGIN SELECT RAISE(ABORT, 'drc status'); END;
                     CREATE TEMP TRIGGER drc_b BEFORE UPDATE OF sla_policy_id ON incident BEGIN SELECT RAISE(ABORT, 'drc policy'); END;");
        let cause = drc_cause(&st, id, json!({ "priority": 1, "status": "in_progress" })).await;
        assert!(cause.contains(DRC_NON_RECALCULEES), "{cause}");
        assert!(!cause.contains(DRC_RECALCULEES), "{cause}");
    }

    // bras `Err` de la relecture (cases.rs:470).
    // MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4W_RELU_ERR` (témoins du lot précédent tous verts sous elle).
    #[tokio::test]
    async fn drc_p6_relecture_en_echec_dite() {
        let (st, _t) = drc_etat("p6", false);
        let id = drc_dossier(&st);
        drc_sql(&st, "CREATE TEMP TRIGGER drc_a BEFORE UPDATE OF status ON incident BEGIN SELECT RAISE(ABORT, 'drc status'); END;
                     CREATE TEMP TRIGGER drc_b BEFORE UPDATE OF resolve_due ON incident BEGIN UPDATE incident SET ts='pas un entier' WHERE id=OLD.id; SELECT RAISE(IGNORE); END;");
        let cause = drc_cause(&st, id, json!({ "priority": 1, "status": "in_progress" })).await;
        assert!(cause.contains("ÉCHÉANCES MULTI-NIVEAU NON RELUES après le rattrapage"), "{cause}");
        assert!(!cause.contains(DRC_RECALCULEES), "{cause}");
    }

    // conjonction `due == ts + res_s + pause` (cases.rs:466) : même politique, resolve_due périmé, politique refusée.
    // MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4W_DUE` (témoins du lot précédent tous verts sous elle).
    #[tokio::test]
    async fn drc_p7_echeance_perimee_meme_politique_dite_non_recalculee() {
        let (st, _t) = drc_etat("p7", false);
        let id = { let conn = st.db.lock(); dossier_seme(&conn, "alice", "Dossier", 3, "", None, 1) };
        assert_eq!(drc_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(600), "fixture P1 gouverné");
        drc_sql(&st, &format!("UPDATE incident SET resolve_due = ts + 5 WHERE id={id};"));
        drc_sql(&st, "CREATE TEMP TRIGGER drc_a BEFORE UPDATE OF status ON incident BEGIN SELECT RAISE(ABORT, 'drc status'); END;
                     CREATE TEMP TRIGGER drc_b BEFORE UPDATE OF resolve_due ON incident BEGIN SELECT RAISE(ABORT, 'drc resolve'); END;");
        let cause = drc_cause(&st, id, json!({ "priority": 1, "status": "in_progress" })).await;
        assert!(cause.contains(DRC_NON_RECALCULEES), "{cause}");
        assert!(!cause.contains(DRC_RECALCULEES), "{cause}");
        assert_eq!(drc_entier(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), Some(5));
    }

    // sortie de `waiting` vers un statut TERMINAL + priorité écrite, verdict refusé : reprise du chrono rejouée.
    // MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4W_TERMINAL_REPRISE` (le comportement d'avant : pause conservée).
    #[tokio::test]
    async fn drc_p8_terminal_avec_priorite_puis_refus_reprend_le_chrono() {
        let (st, _t) = drc_etat("p8", false);
        let id = drc_dossier(&st);
        drc_sql(&st, &format!("UPDATE incident SET status='waiting', sla_paused_since=CAST(strftime('%s','now') AS INTEGER) - 1000 WHERE id={id};"));
        drc_sql(&st, "CREATE TEMP TRIGGER drc_a BEFORE UPDATE OF disposition ON incident BEGIN SELECT RAISE(ABORT, 'drc disposition'); END;");
        let cause = drc_cause(&st, id, json!({ "priority": 1, "status": "closed", "disposition": "true_positive" })).await;
        assert_eq!(cause, "disposition: drc disposition");
        assert_eq!(drc_entier(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND status='closed'")), Some(1));
        assert_eq!(drc_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={id}")), None, "reprise rejouée sur le dossier clos, comme en nominal");
        drc_sql(&st, "DROP TRIGGER drc_a;");
        let id2 = drc_dossier(&st);
        drc_sql(&st, &format!("UPDATE incident SET status='waiting', sla_paused_since=CAST(strftime('%s','now') AS INTEGER) - 1000 WHERE id={id2};"));
        let (statut, _) = pb_json(case_update(State(st.clone()), Extension(drc_au()), Path(id2), Json(json!({ "priority": 1, "status": "closed", "disposition": "true_positive" }))).await).await;
        assert_eq!(statut, 204);
        assert_eq!(drc_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={id2}")), None, "nominal : reprise jouée");
    }
}
