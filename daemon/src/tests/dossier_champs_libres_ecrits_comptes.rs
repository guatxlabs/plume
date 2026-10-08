// =====================================================================================
// `P10.20-w` (restes de `case_apply_update`) — LES CHAMPS LIBRES SONT COMPTÉS ; LES ÉCHÉANCES MULTI-NIVEAU SUIVENT UNE
// PRIORITÉ ÉCRITE SUR UNE ÉCRITURE PARTIELLE.
//
// CE QUI ÉTAIT FAUX, MESURÉ SUR aa78ddd :
//   * `title`, `severity`, `owner`, `summary` et `updated` étaient écrits par `let _ = conn.execute(…)` : un champ refusé
//     par la base restait non écrit pendant que la route rendait 204 ;
//   * priorité écrite (P3 -> P1) puis statut, verdict ou `sla_due` refusé : `sla_due` était rattrapé, mais
//     `ack_due`/`resolve_due` (politique multi-niveau) gardaient la cible de l'ANCIENNE priorité — `sla_apply_policy`
//     n'était appelé qu'en sortie nominale.
// RÉFUTÉ DANS L'ÉNONCÉ : « priorité écrite puis summary refusé » n'existe pas — les champs libres sont écrits AVANT la
// priorité ; leur refus sort avant toute écriture attestée. Le seul champ libre qui suit une priorité est `updated`,
// et il suit aussi le recalcul nominal (rien à rattraper).
//
// CE QU'ILS NE TIENNENT PAS : `sla_apply_policy` avale toujours ses propres écritures (caseops.rs, hors lot) — le
// rattrapage RELIT `resolve_due` pour dire vrai, il ne compte pas l'`UPDATE` ; `ack_due` n'est pas relu (seul
// `resolve_due` l'est), et il reste figé dès que l'élément « priorité » acquitte le dossier, rattrapage ou non ; `sla_on_status_change` reste avalé ; la console (web/cases.js) n'a pas été relue pour ce 503.
// =====================================================================================
mod dossier_champs_libres_ecrits_comptes {
    use super::*;

    fn dcl_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("dcl-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn dcl_utilisateur() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn dcl_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn dcl_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn dcl_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get::<_, Option<String>>(0)).expect("fixture : la valeur se lit").unwrap_or_default()
    }

    async fn dcl_mettre_a_jour(st: &AppState, id: i64, corps: Value) -> (u16, Value) {
        pb_json(case_update(State(st.clone()), Extension(dcl_utilisateur()), Path(id), Json(corps)).await).await
    }

    /// CE QU'IL TIENT : chacun des quatre champs libres refusé (`RAISE(ABORT)`) -> 503 nommé
    /// `CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE (<champ>: …)`, champ inchangé en base, et l'assignation demandée APRÈS
    /// lui n'est ni écrite, ni en chronologie, ni au registre ; `updated` refusé -> 503 « (updated: … ».
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4_AVALE_<champ>` (le `let _` d'avant pour ce champ) — 204.
    #[tokio::test]
    async fn dcl_un_champ_libre_refuse_rend_503_nomme_et_n_ecrit_rien_apres_lui() {
        let (st, _tmp) = dcl_etat("libres");
        for (colonne, valeur, lecture) in [
            ("title", json!("Titre neuf"), "title"),
            ("severity", json!(9), "CAST(severity AS TEXT)"),
            ("owner", json!("mallory"), "owner"),
            ("summary", json!("résumé neuf"), "summary"),
        ] {
            let id = { let conn = st.db.lock(); dossier_seme(&conn, "alice", "Dossier", 3, "résumé", None, 3) };
            let avant = dcl_texte(&st, &format!("SELECT {lecture} FROM incident WHERE id={id}"));
            let items = dcl_compte(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={id}"));
            let maillons = dcl_compte(&st, "SELECT COUNT(*) FROM ledger");
            dcl_ecrire(&st, &format!(
                "CREATE TEMP TRIGGER dcl_refus BEFORE UPDATE OF {colonne} ON incident BEGIN SELECT RAISE(ABORT, 'dcl: {colonne}'); END;"
            ));
            let mut corps = serde_json::Map::new();
            corps.insert(colonne.to_string(), valeur);
            corps.insert("assignee".to_string(), json!("bob"));
            let (statut, avoue) = dcl_mettre_a_jour(&st, id, Value::Object(corps)).await;
            let phrase = avoue["error"].as_str().unwrap_or("");
            assert_eq!(statut, 503, "{colonne} refusé : 503 attendu, pas {statut} ({avoue})");
            assert!(phrase.starts_with(CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE), "{avoue}");
            assert!(phrase.contains(&format!("({colonne}: ")), "la cause nomme {colonne} : {avoue}");
            assert_eq!(dcl_texte(&st, &format!("SELECT {lecture} FROM incident WHERE id={id}")), avant, "{colonne} inchangé en base");
            assert_eq!(dcl_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND assignee IS NULL")), 1, "l'assignation qui suit {colonne} n'est pas écrite");
            assert_eq!(dcl_compte(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={id}")), items, "aucun élément de chronologie posé");
            assert_eq!(dcl_compte(&st, "SELECT COUNT(*) FROM ledger"), maillons, "aucun maillon de registre posé");
            dcl_ecrire(&st, "DROP TRIGGER dcl_refus;");
        }

        // `updated` refusé : tout ce qui précède est écrit, la cause nomme `updated`.
        let id = { let conn = st.db.lock(); dossier_seme(&conn, "alice", "Dossier", 3, "", None, 3) };
        dcl_ecrire(&st, "CREATE TEMP TRIGGER dcl_refus BEFORE UPDATE OF updated ON incident BEGIN SELECT RAISE(ABORT, 'dcl: updated'); END;");
        let (statut, avoue) = dcl_mettre_a_jour(&st, id, json!({ "title": "Titre écrit" })).await;
        assert_eq!(statut, 503, "{avoue}");
        assert!(avoue["error"].as_str().unwrap_or("").contains("(updated: "), "{avoue}");
        assert_eq!(dcl_texte(&st, &format!("SELECT title FROM incident WHERE id={id}")), "Titre écrit", "fixture : le titre qui précède est écrit");
        dcl_ecrire(&st, "DROP TRIGGER dcl_refus;");
    }

    /// CE QU'IL TIENT : politique multi-niveau active (P3 et P1), priorité P3 -> P1 écrite puis statut refusé, ou
    /// `sla_due` refusé : `resolve_due` porte la cible de P1 et la cause le dit ; `ack_due` reste celui de P3, figé par
    /// l'acquittement (l'élément « priorité » pose `first_response_ts`) — cette assertion-là tient quelle que soit
    /// l'implémentation, elle documente le figement, elle ne témoigne pas du rattrapage.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=G4_SANS_POLITIQUE` (pas de `sla_apply_policy` au rattrapage) — cibles de P3.
    #[tokio::test]
    async fn dcl_une_priorite_ecrite_puis_un_refus_rattrape_les_echeances_multi_niveau() {
        let (st, _tmp) = dcl_etat("multi");
        dcl_ecrire(&st, "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,600,1,0,'root',0);
                         INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P3',3,3000,30000,1,0,'root',0);");
        for colonne in ["status", "sla_due"] {
            let id = { let conn = st.db.lock(); dossier_seme(&conn, "alice", "Dossier", 3, "", None, 3) };
            assert_eq!(dcl_compte(&st, &format!("SELECT ack_due - ts FROM incident WHERE id={id}")), 3000, "fixture : ack_due de P3");
            dcl_ecrire(&st, &format!(
                "CREATE TEMP TRIGGER dcl_refus BEFORE UPDATE OF {colonne} ON incident BEGIN SELECT RAISE(ABORT, 'dcl: {colonne}'); END;"
            ));
            let (statut, avoue) = dcl_mettre_a_jour(&st, id, json!({ "priority": 1, "status": "in_progress" })).await;
            let phrase = avoue["error"].as_str().unwrap_or("");
            assert_eq!(statut, 503, "{avoue}");
            assert!(phrase.contains(&format!("({colonne}: ")), "{avoue}");
            assert!(phrase.contains("échéances multi-niveau recalculées sur la priorité écrite"), "le rattrapage multi-niveau est dit : {avoue}");
            assert_eq!(dcl_compte(&st, &format!("SELECT priority FROM incident WHERE id={id}")), 1, "fixture : la priorité est écrite");
            // `ack_due` reste celui de P3 : l'élément « priorité » est la première réponse, l'échéance d'acquittement est
            // figée — exactement comme sur une mise à jour réussie (`sla_apply_policy`, `first_response_ts` posé).
            assert_eq!(dcl_compte(&st, &format!("SELECT ack_due - ts FROM incident WHERE id={id}")), 3000, "{colonne} refusé : ack_due figé comme en nominal");
            assert_eq!(dcl_compte(&st, &format!("SELECT resolve_due - ts FROM incident WHERE id={id}")), 600, "{colonne} refusé : resolve_due suit P1");
            dcl_ecrire(&st, "DROP TRIGGER dcl_refus;");
        }
    }

    /// CONTRÔLE NOMINAL (inverse) : un PATCH complet rend 204 et écrit chaque champ ; un PATCH vide aussi (rien ne
    /// change sauf `updated`). Aucun mutant ne le rougit : il garde le correctif d'un faux 503.
    #[tokio::test]
    async fn dcl_un_patch_complet_reste_204_et_ecrit_chaque_champ() {
        let (st, _tmp) = dcl_etat("nominal");
        dcl_ecrire(&st, "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,600,1,0,'root',0);");
        let id = { let conn = st.db.lock(); dossier_seme(&conn, "alice", "Dossier", 3, "résumé", None, 3) };
        let (statut, avoue) = dcl_mettre_a_jour(&st, id, json!({
            "title": "  Titre neuf  ", "severity": 7, "owner": "carol", "summary": "résumé neuf",
            "assignee": "bob", "priority": 1, "status": "in_progress", "disposition": "true_positive"
        })).await;
        assert_eq!(statut, 204, "{avoue}");
        let ligne = dcl_texte(&st, &format!(
            "SELECT title||'|'||severity||'|'||owner||'|'||summary||'|'||assignee||'|'||priority||'|'||status||'|'||disposition||'|'||(sla_due-ts)||'|'||(resolve_due-ts)||'|'||(ack_due IS NULL) FROM incident WHERE id={id}"
        ));
        // `ack_due` NULL : créé en P3 sans politique, acquitté par l'élément « priorité » avant `sla_apply_policy`.
        assert_eq!(ligne, format!("Titre neuf|7|carol|résumé neuf|bob|1|in_progress|true_positive|{}|600|1", sla_target_s(1)));
        assert_eq!(dcl_mettre_a_jour(&st, id, json!({})).await.0, 204);
        assert_eq!(dcl_texte(&st, &format!("SELECT title FROM incident WHERE id={id}")), "Titre neuf");
    }
}
