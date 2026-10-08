// =====================================================================================
// `P10.20-w` (reste de `case_apply_update`) — UNE PRIORITÉ ÉCRITE N'EST PAS LAISSÉE SUR L'ÉCHÉANCE DE L'ANCIENNE ;
// UNE MISE À JOUR INTERROMPUE APRÈS D'AUTRES ÉCRITURES NE DIT PAS « RIEN N'EST ÉCRIT ».
//
// CE QUI ÉTAIT FAUX, MESURÉ SUR 4700281 :
//   * priorité écrite (P3 -> P1) puis statut ou verdict refusé : la fonction sortait en `NonEcrite` AVANT le recalcul,
//     et `sla_due` restait à ts + cible(P3) sur un dossier P1 ;
//   * une écriture à zéro ligne APRÈS l'assignation (déclencheur `RAISE(IGNORE)` sur `sla_due`) rendait `DossierAbsent`,
//     que la route servait en « DOSSIER NON LU, GESTE NON FAIT … Rien n'est écrit » alors que l'assignation et sa ligne
//     `case.assign` étaient écrites.
//
// CE QU'ILS NE TIENNENT PAS : le bras `Ok(0)` du statut et du verdict (dossier écarté après une priorité écrite) sort
// sans rattrapage ; les échéances multi-niveau (`sla_apply_policy`, `ack_due`/`resolve_due`) ne sont pas rattrapées
// sur une écriture partielle ; la fonction rend toujours `DossierAbsent` sur ces zéros (seule la route a changé de
// phrase) ; aucune base réellement en lecture seule.
// =====================================================================================
mod dossier_priorite_ecrite_echeance_rattrapee {
    use super::*;

    fn dpe_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("dpe-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn dpe_utilisateur() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn dpe_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn dpe_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn dpe_echeance_relative(st: &AppState, id: i64) -> i64 {
        dpe_compte(st, &format!("SELECT sla_due - ts FROM incident WHERE id={id}"))
    }

    async fn dpe_mettre_a_jour(st: &AppState, id: i64, corps: Value) -> (u16, Value) {
        pb_json(case_update(State(st.clone()), Extension(dpe_utilisateur()), Path(id), Json(corps)).await).await
    }

    /// CE QU'IL TIENT : priorité écrite puis statut refusé, ou verdict refusé — `NonEcrite` nomme le champ refusé ET
    /// le rattrapage, l'échéance est celle de la NOUVELLE priorité ; dossier terminal en base : échéance intacte.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=F4_RATTRAPAGE` (aucun rattrapage : la sortie d'avant).
    #[tokio::test]
    async fn dpe_une_priorite_ecrite_puis_un_champ_refuse_porte_l_echeance_de_la_nouvelle_priorite() {
        let (st, _tmp) = dpe_etat("rattrapage");
        for (colonne, corps, priorite) in [
            ("status", json!({ "priority": 1, "status": "in_progress" }), 1),
            ("disposition", json!({ "priority": 2, "disposition": "true_positive" }), 2),
        ] {
            let id = { let conn = st.db.lock(); dossier_seme(&conn, "alice", "Dossier", 3, "", None, 3) };
            assert_eq!(dpe_echeance_relative(&st, id), sla_target_s(3), "fixture : échéance de P3");
            dpe_ecrire(&st, &format!(
                "CREATE TEMP TRIGGER dpe_refus BEFORE UPDATE OF {colonne} ON incident BEGIN SELECT RAISE(ABORT, 'dpe: {colonne}'); END;"
            ));
            let issue = { let conn = st.db.lock(); case_apply_update(&conn, id, "analyste", &corps) };
            match &issue {
                IssueDuDossierModifie::NonEcrite(cause) => {
                    assert!(cause.starts_with(&format!("{colonne}: ")), "la cause nomme {colonne} : {cause}");
                    assert!(cause.contains("échéance recalculée sur la priorité écrite"), "le rattrapage est dit : {cause}");
                }
                autre => panic!("{colonne} refusé : `NonEcrite` attendu, pas {autre:?}"),
            }
            assert_eq!(dpe_compte(&st, &format!("SELECT priority FROM incident WHERE id={id}")), priorite, "fixture : la priorité est écrite");
            assert_eq!(dpe_echeance_relative(&st, id), sla_target_s(priorite), "{colonne} refusé : l'échéance suit la priorité ÉCRITE");
            dpe_ecrire(&st, "DROP TRIGGER dpe_refus;");
        }

        // PAR LA ROUTE : 503 nommé, la cause porte le rattrapage.
        let id = { let conn = st.db.lock(); dossier_seme(&conn, "alice", "Dossier", 3, "", None, 4) };
        dpe_ecrire(&st, "CREATE TEMP TRIGGER dpe_refus BEFORE UPDATE OF status ON incident BEGIN SELECT RAISE(ABORT, 'dpe: status'); END;");
        let (statut, avoue) = dpe_mettre_a_jour(&st, id, json!({ "priority": 1, "status": "in_progress" })).await;
        assert_eq!(statut, 503, "{avoue}");
        assert!(avoue["error"].as_str().unwrap_or("").contains("échéance recalculée sur la priorité écrite"), "{avoue}");
        assert_eq!(dpe_echeance_relative(&st, id), sla_target_s(1));

        // TERMINAL EN BASE : l'échéance n'est pas recalculée (comme le recalcul d'une mise à jour réussie).
        let id = { let conn = st.db.lock(); dossier_seme(&conn, "alice", "Dossier", 3, "", None, 3) };
        dpe_ecrire(&st, "DROP TRIGGER dpe_refus;");
        dpe_ecrire(&st, &format!("UPDATE incident SET status='closed' WHERE id={id}"));
        dpe_ecrire(&st, "CREATE TEMP TRIGGER dpe_refus BEFORE UPDATE OF status ON incident BEGIN SELECT RAISE(ABORT, 'dpe: status'); END;");
        let issue = { let conn = st.db.lock(); case_apply_update(&conn, id, "analyste", &json!({ "priority": 1, "status": "in_progress" })) };
        assert!(matches!(issue, IssueDuDossierModifie::NonEcrite(ref c) if c.starts_with("status: ")), "{issue:?}");
        assert_eq!(dpe_echeance_relative(&st, id), sla_target_s(3), "dossier clos en base : échéance intacte");
        dpe_ecrire(&st, "DROP TRIGGER dpe_refus;");

        // CONTRÔLE POSITIF — la sortie d'avant.
        let id = { let conn = st.db.lock(); dossier_seme(&conn, "alice", "Dossier", 3, "", None, 3) };
        assert_eq!(dpe_mettre_a_jour(&st, id, json!({ "priority": 1, "status": "in_progress" })).await.0, 204);
        assert_eq!(dpe_echeance_relative(&st, id), sla_target_s(1));
    }

    /// CE QU'IL TIENT (route) : un recalcul à zéro ligne APRÈS une assignation écrite rend 503
    /// `CAUSE_MISE_A_JOUR_DU_DOSSIER_INTERROMPUE` (des champs ont pu être écrits), jamais « dossier non lu, rien
    /// n'est écrit » ; l'assignation est bien en base.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=F4_ROUTE_ABSENT` (le bras `refus_du_dossier_non_lu` d'avant).
    #[tokio::test]
    async fn dpe_une_mise_a_jour_interrompue_apres_une_assignation_ne_dit_pas_rien_n_est_ecrit() {
        let (st, _tmp) = dpe_etat("interrompue");
        let id = { let conn = st.db.lock(); dossier_seme(&conn, "alice", "Dossier", 3, "", None, 3) };
        dpe_ecrire(&st, "CREATE TEMP TRIGGER dpe_ignore BEFORE UPDATE OF sla_due ON incident BEGIN SELECT RAISE(IGNORE); END;");
        let (statut, avoue) = dpe_mettre_a_jour(&st, id, json!({ "assignee": "bob" })).await;
        let phrase = avoue["error"].as_str().unwrap_or("");
        assert_eq!(statut, 503, "{avoue}");
        assert!(phrase.starts_with(CAUSE_MISE_A_JOUR_DU_DOSSIER_INTERROMPUE), "{avoue}");
        assert!(!phrase.contains("Rien n'est écrit"), "l'assignation est écrite : « rien n'est écrit » serait faux : {avoue}");
        assert_eq!(dpe_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND assignee='bob'")), 1, "fixture : l'assignation est écrite");
        dpe_ecrire(&st, "DROP TRIGGER dpe_ignore;");

        // CONTRÔLE POSITIF.
        assert_eq!(dpe_mettre_a_jour(&st, id, json!({ "assignee": "carol" })).await.0, 204);
    }
}
