// =====================================================================================
// `P10.33-k` (reste), `P10.22-q` (reste) — LA CHRONOLOGIE D'UN GESTE D'INCIDENT EST ÉCRITE AVEC LUI, ET COMPTÉE.
//
// LE DÉFAUT, RE-MESURÉ SUR 7c167699. Trois gestes de `handlers/incidents.rs` posaient leur élément de chronologie par
// `case_add_item`, qui jette l'issue d'`ajouter_l_element_au_dossier` (élément, date du dossier, MTTA
// `first_response_ts`) :
//   * `attach_runbook` — APRÈS `txn.commit()` : étapes validées, élément « runbook attaché » absent, MTTA non figé,
//     maillon `case.runbook_attach` posé, `{"attached":n}` servi ;
//   * `step_advance` — l'`UPDATE case_step` écrit, la chronologie `step` avalée, maillon `case.step`, `204` ;
//   * `incident_apply_tier` — palier/type/pilote écrits, la chronologie « incident DÉCLARÉ » avalée, maillon
//     `case.incident`, `204`.
// Aucun appelant ne tient de transaction (`with_write` ne prend que le verrou du processus) : `step_advance` et
// `incident_apply_tier` ouvrent la leur (`jouer_le_geste_garde`), l'attache écrit la chronologie dans la sienne avant
// le `COMMIT`. Une chronologie refusée annule le fait : rien en base, rien au registre, MTTA non figé, 503 nommé.
//
// LES REFUS sont fabriqués par un déclencheur TEMPORAIRE `BEFORE INSERT ON incident_item` : `RAISE(ABORT)` (l'INSERT
// échoue) puis `RAISE(IGNORE)` (l'INSERT ne pose aucune ligne, `Ok(0)`). Le `BEGIN` et le `COMMIT` refusés par un
// autorisateur SQLite (branches neuves de `step_advance` et `incident_apply_tier`).
//
// MUTANTS (VERIF_MUT, retirés avant le commit) : `V4_A_APRES_COMMIT` (chronologie après le commit), `V4_A_AVALE`,
// `V4_B_AVALE`, `V4_C_AVALE` (la forme `case_add_item` d'avant, un site à la fois), `V4_ERR_OK` (l'`Err` de la
// chronologie de l'étape rendu `Ok`), `V4_B_NONOUVERT`, `V4_B_NONVALIDE`, `V4_C_NONOUVERT`, `V4_C_NONVALIDE` (un bras
// de transaction refusée qui continue vers le registre).
//
// CE QU'ILS NE TIENNENT PAS : `ledger_append` reste APRÈS la validation (`P10.31-u` : un maillon manquant est avoué
// `registre_sans_maillon`, le fait est écrit) ; les vingt autres appelants de `case_add_item` (statut, assignation,
// fusion, échéance…) avalent toujours ; la mutation « `RAISE(IGNORE)` accepté » vit dans `ajouter_l_element_au_dossier`
// (`cases.rs`, hors de ce lot) et n'est pas rejouée ici ; aucune base réellement en lecture seule ; la console n'est pas
// jugée (les 503 servis sont des causes existantes).
// =====================================================================================
mod chronologie_de_dossier_comptee_apres_l_ecriture {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const CDC_REFUS_ABORT: &str = "CREATE TEMP TRIGGER cdc_refus BEFORE INSERT ON incident_item BEGIN SELECT RAISE(ABORT, 'cdc chronologie refusee'); END;";
    const CDC_REFUS_IGNORE: &str = "CREATE TEMP TRIGGER cdc_refus BEFORE INSERT ON incident_item BEGIN SELECT RAISE(IGNORE); END;";
    const CDC_LEVER: &str = "DROP TRIGGER cdc_refus;";

    fn cdc_n(conn: &Connection, sql: &str, id: i64) -> i64 {
        conn.query_row(sql, params![id], |r| r.get(0)).expect("compte de témoin")
    }

    fn cdc_registre(conn: &Connection, kind: &str) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1", params![kind], |r| r.get(0)).expect("compte du registre")
    }

    fn cdc_mtta_nul(conn: &Connection, id: i64) -> bool {
        cdc_n(conn, "SELECT COUNT(*) FROM incident WHERE id=?1 AND first_response_ts IS NULL", id) == 1
    }

    fn cdc_dossier_et_runbook(conn: &Connection, cle: &str) -> (i64, i64) {
        let id = dossier_seme(conn, "adm", "dossier-cdc", 4, "", None, 2);
        conn.execute(
            "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES(?1,'Procédure cdc','*','','',0,1,1000)",
            params![cle],
        )
        .expect("fixture : le runbook");
        let rb = conn.last_insert_rowid();
        for ordinal in 0..2 {
            conn.execute(
                "INSERT INTO runbook_step(runbook_id,ordinal,phase,title,guidance,step_kind) VALUES(?1,?2,'triage','Vérifier','','manual')",
                params![rb, ordinal],
            )
            .expect("fixture : une étape");
        }
        (id, rb)
    }

    fn cdc_dossier_et_etape(conn: &Connection) -> (i64, i64) {
        let id = dossier_seme(conn, "adm", "dossier-cdc-etape", 3, "", None, 2);
        conn.execute(
            "INSERT INTO case_step(incident_id,runbook_id,step_id,ordinal,phase,title) VALUES(?1,1,1,1,'containment','Isoler l''hôte')",
            params![id],
        )
        .expect("fixture : une étape");
        (id, conn.last_insert_rowid())
    }

    fn cdc_refuser(conn: &Connection, op: TransactionOperation) {
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation } if operation == op => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn cdc_lever_l_autorisateur(conn: &Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// CE QU'IL TIENT : la chronologie de l'attache refusée (ABORT puis IGNORE) rend `EtapesNonEcrites` dont la cause
    /// nomme la chronologie, et ANNULE les étapes : zéro `case_step`, zéro élément « runbook », zéro maillon, MTTA non
    /// figé. Contrôle positif : le déclencheur levé, l'attache passe (2 étapes), UN élément, MTTA figé, UN maillon.
    ///
    /// MUTATIONS QUI LE FONT ROUGIR : `V4_A_APRES_COMMIT` (les étapes restent en base) ; `V4_A_AVALE` (`Ok(2)` sans
    /// chronologie, MTTA non figé, maillon posé).
    #[test]
    fn cdc_attache_dont_la_chronologie_est_refusee_n_attache_rien() {
        let conn = test_db();
        let (id, rb) = cdc_dossier_et_runbook(&conn, "cdc-attache");
        assert!(cdc_mtta_nul(&conn, id), "fixture : MTTA non figé");
        for refus in [CDC_REFUS_ABORT, CDC_REFUS_IGNORE] {
            conn.execute_batch(refus).unwrap();
            match attach_runbook(&conn, id, rb, "adm", &PrefillTargets::default()) {
                Err(RefusDAttache::EtapesNonEcrites(cause)) => {
                    assert!(cause.starts_with("chronologie"), "la cause nomme la chronologie ({refus}) : {cause:?}")
                }
                autre => panic!("chronologie refusée ({refus}) : `EtapesNonEcrites`, pas {autre:?}"),
            }
            conn.execute_batch(CDC_LEVER).unwrap();
            assert!(conn.is_autocommit(), "la transaction de l'attache est fermée");
            assert_eq!(cdc_n(&conn, "SELECT COUNT(*) FROM case_step WHERE incident_id=?1", id), 0, "aucune étape ne survit à sa chronologie refusée ({refus})");
            assert_eq!(cdc_n(&conn, "SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='runbook'", id), 0);
            assert_eq!(cdc_registre(&conn, "case.runbook_attach"), 0, "rien n'est attesté ({refus})");
            assert!(cdc_mtta_nul(&conn, id), "le MTTA n'est pas figé ({refus})");
        }
        // CONTRÔLE POSITIF : l'attache reste possible et se trace une fois.
        assert_eq!(attach_runbook(&conn, id, rb, "adm", &PrefillTargets::default()).expect("attache nominale"), 2);
        assert_eq!(cdc_n(&conn, "SELECT COUNT(*) FROM case_step WHERE incident_id=?1", id), 2);
        assert_eq!(cdc_n(&conn, "SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='runbook'", id), 1);
        assert_eq!(cdc_registre(&conn, "case.runbook_attach"), 1);
        assert!(!cdc_mtta_nul(&conn, id), "le MTTA est figé par l'attache écrite");
    }

    /// CE QU'IL TIENT : la chronologie de l'étape refusée (ABORT puis IGNORE) rend `NonEcrite` (cause « chronologie »),
    /// l'étape garde `pending`, aucun élément `step`, aucun maillon `case.step`, MTTA non figé. Contrôle positif : levé,
    /// `Ecrite`, statut `done`, UN élément, UN maillon, MTTA figé.
    ///
    /// MUTATIONS QUI LE FONT ROUGIR : `V4_B_AVALE` (`Ecrite`, étape `done`) ; `V4_ERR_OK` (même chose par l'`Err` rendu `Ok`).
    #[test]
    fn cdc_etape_dont_la_chronologie_est_refusee_garde_son_statut() {
        let conn = test_db();
        let (id, sid) = cdc_dossier_et_etape(&conn);
        for refus in [CDC_REFUS_ABORT, CDC_REFUS_IGNORE] {
            conn.execute_batch(refus).unwrap();
            let issue = step_advance(&conn, id, sid, "done", "analyste", None);
            conn.execute_batch(CDC_LEVER).unwrap();
            let IssueDeLEtape::NonEcrite(cause) = issue else { panic!("chronologie refusée ({refus}) : `NonEcrite`, pas {issue:?}") };
            assert!(cause.starts_with("chronologie"), "la cause nomme la chronologie : {cause:?}");
            assert!(conn.is_autocommit());
            assert_eq!(cdc_n(&conn, "SELECT COUNT(*) FROM case_step WHERE id=?1 AND status='pending'", sid), 1, "l'étape garde son statut ({refus})");
            assert_eq!(cdc_n(&conn, "SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='step'", id), 0);
            assert_eq!(cdc_registre(&conn, "case.step"), 0, "aucun maillon ({refus})");
            assert!(cdc_mtta_nul(&conn, id), "MTTA non figé ({refus})");
        }
        assert_eq!(step_advance(&conn, id, sid, "done", "analyste", None), IssueDeLEtape::Ecrite);
        assert_eq!(cdc_n(&conn, "SELECT COUNT(*) FROM case_step WHERE id=?1 AND status='done'", sid), 1);
        assert_eq!(cdc_n(&conn, "SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='step'", id), 1);
        assert_eq!(cdc_registre(&conn, "case.step"), 1);
        assert!(!cdc_mtta_nul(&conn, id));
    }

    /// CE QU'IL TIENT : la chronologie de la déclaration refusée (ABORT puis IGNORE) rend `NonEcrite` (cause
    /// « chronologie »), palier/type/pilote restent NULL, aucun élément « incident », aucun maillon, MTTA non figé.
    /// Contrôle positif : levé, `Posee`, palier 2, type et pilote écrits, UN élément, UN maillon, MTTA figé.
    ///
    /// MUTATION QUI LE FAIT ROUGIR : `V4_C_AVALE` (`Posee`, palier écrit sans chronologie).
    #[test]
    fn cdc_declaration_dont_la_chronologie_est_refusee_ne_declare_rien() {
        let conn = test_db();
        let id = dossier_seme(&conn, "adm", "dossier-cdc-incident", 3, "", None, 2);
        for refus in [CDC_REFUS_ABORT, CDC_REFUS_IGNORE] {
            conn.execute_batch(refus).unwrap();
            let issue = incident_apply_tier(&conn, id, "analyste", Some(2), Some("intrusion"), Some("carol"));
            conn.execute_batch(CDC_LEVER).unwrap();
            let DeclarationDIncident::NonEcrite(cause) = issue else { panic!("chronologie refusée ({refus}) : `NonEcrite`, pas {issue:?}") };
            assert!(cause.starts_with("chronologie"), "la cause nomme la chronologie : {cause:?}");
            assert!(conn.is_autocommit());
            assert_eq!(
                cdc_n(&conn, "SELECT COUNT(*) FROM incident WHERE id=?1 AND incident_tier IS NULL AND incident_type IS NULL AND commander IS NULL", id),
                1,
                "rien n'est déclaré ({refus})"
            );
            assert_eq!(cdc_n(&conn, "SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='incident'", id), 0);
            assert_eq!(cdc_registre(&conn, "case.incident"), 0);
            assert!(cdc_mtta_nul(&conn, id));
        }
        assert_eq!(incident_apply_tier(&conn, id, "analyste", Some(2), Some("intrusion"), Some("carol")), DeclarationDIncident::Posee);
        assert_eq!(
            cdc_n(&conn, "SELECT COUNT(*) FROM incident WHERE id=?1 AND incident_tier=2 AND incident_type='intrusion' AND commander='carol'", id),
            1
        );
        assert_eq!(cdc_n(&conn, "SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='incident'", id), 1);
        assert_eq!(cdc_registre(&conn, "case.incident"), 1);
        assert!(!cdc_mtta_nul(&conn, id));
    }

    /// CE QU'IL TIENT : les deux bras neufs — `BEGIN` refusé, `COMMIT` refusé — de `step_advance` et
    /// `incident_apply_tier` rendent `NonEcrite` (« transaction refusée », « validation refusée »), rien d'écrit ni
    /// attesté, la transaction fermée.
    ///
    /// MUTATIONS QUI LE FONT ROUGIR : `V4_B_NONOUVERT`, `V4_B_NONVALIDE`, `V4_C_NONOUVERT`, `V4_C_NONVALIDE` (le bras
    /// continue vers le registre : `Ecrite`/`Posee` et un maillon).
    #[test]
    fn cdc_begin_ou_commit_refuses_n_ecrivent_ni_n_attestent() {
        let conn = test_db();
        let (id, sid) = cdc_dossier_et_etape(&conn);
        for (op, debut) in [(TransactionOperation::Begin, "transaction refusée"), (TransactionOperation::Unknown, "validation refusée")] {
            cdc_refuser(&conn, op);
            let etape = step_advance(&conn, id, sid, "done", "analyste", None);
            let declaration = incident_apply_tier(&conn, id, "analyste", Some(1), None, None);
            cdc_lever_l_autorisateur(&conn);
            match etape {
                IssueDeLEtape::NonEcrite(c) => assert!(c.starts_with(debut), "étape : {c:?} commence par {debut:?}"),
                autre => panic!("étape sous {debut} : `NonEcrite`, pas {autre:?}"),
            }
            match declaration {
                DeclarationDIncident::NonEcrite(c) => assert!(c.starts_with(debut), "déclaration : {c:?} commence par {debut:?}"),
                autre => panic!("déclaration sous {debut} : `NonEcrite`, pas {autre:?}"),
            }
            assert!(conn.is_autocommit(), "transaction fermée ({debut})");
            assert_eq!(cdc_n(&conn, "SELECT COUNT(*) FROM case_step WHERE id=?1 AND status='pending'", sid), 1);
            assert_eq!(cdc_n(&conn, "SELECT COUNT(*) FROM incident WHERE id=?1 AND incident_tier IS NULL", id), 1);
            assert_eq!(cdc_n(&conn, "SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind IN ('step','incident')", id), 0);
            assert_eq!(cdc_registre(&conn, "case.step") + cdc_registre(&conn, "case.incident"), 0);
            assert!(cdc_mtta_nul(&conn, id));
        }
    }

    fn cdc_utilisateur() -> AuthUser {
        AuthUser { name: "adm".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false, method: "cookie".into(), csrf: String::new(), env: None }
    }

    fn cdc_phrase(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    /// CE QU'IL TIENT : par les GESTIONNAIRES, une chronologie refusée sert le 503 nommé de chaque geste (cause
    /// existante, jamais 200/204) : attache `CAUSE_ETAPES_DU_RUNBOOK_NON_ECRITES`, étape `CAUSE_ETAPE_NON_ECRITE`,
    /// déclaration `CAUSE_DECLARATION_D_INCIDENT_NON_ECRITE`. Contrôle positif : levé, 200 `{"attached":2}`, 204, 204.
    ///
    /// MUTATIONS QUI LE FONT ROUGIR : `V4_A_AVALE`, `V4_B_AVALE`, `V4_C_AVALE` (succès servi).
    #[tokio::test]
    async fn cdc_les_routes_servent_le_refus_nomme() {
        let chemin = crate::tmp_possede::TmpDb::neuf("cdc-routes");
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations va au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        let (id, rb, sid) = {
            let conn = st.db.lock();
            let (id, rb) = cdc_dossier_et_runbook(&conn, "cdc-routes");
            conn.execute(
                "INSERT INTO case_step(incident_id,runbook_id,step_id,ordinal,phase,title) VALUES(?1,1,1,1,'containment','Isoler')",
                params![id],
            )
            .unwrap();
            let sid = conn.last_insert_rowid();
            (id, rb, sid)
        };
        let id_attache = {
            let conn = st.db.lock();
            dossier_seme(&conn, "adm", "dossier-cdc-attache", 3, "", None, 2)
        };
        st.db.lock().execute_batch(CDC_REFUS_ABORT).unwrap();
        let (s1, v1) = pb_json(case_runbook_attach(State(st.clone()), Extension(cdc_utilisateur()), Path(id_attache), Json(json!({ "runbook_id": rb }))).await).await;
        let (s2, v2) = pb_json(case_step_set(State(st.clone()), Extension(cdc_utilisateur()), Path((id, sid)), Json(json!({ "status": "done" }))).await).await;
        let (s3, v3) = pb_json(incident_set(State(st.clone()), Extension(cdc_utilisateur()), Path(id), Json(json!({ "tier": 2 }))).await).await;
        st.db.lock().execute_batch(CDC_LEVER).unwrap();
        assert_eq!(s1, 503, "attache : {v1}");
        assert!(cdc_phrase(&v1).starts_with(CAUSE_ETAPES_DU_RUNBOOK_NON_ECRITES), "attache : {v1}");
        assert_eq!(s2, 503, "étape : {v2}");
        assert!(cdc_phrase(&v2).starts_with(CAUSE_ETAPE_NON_ECRITE), "étape : {v2}");
        assert_eq!(s3, 503, "déclaration : {v3}");
        assert!(cdc_phrase(&v3).starts_with(CAUSE_DECLARATION_D_INCIDENT_NON_ECRITE), "déclaration : {v3}");
        // CONTRÔLE POSITIF.
        let (s1, v1) = pb_json(case_runbook_attach(State(st.clone()), Extension(cdc_utilisateur()), Path(id_attache), Json(json!({ "runbook_id": rb }))).await).await;
        assert_eq!((s1, v1.get("attached").and_then(|n| n.as_i64())), (200, Some(2)), "attache nominale : {v1}");
        let (s2, _) = pb_json(case_step_set(State(st.clone()), Extension(cdc_utilisateur()), Path((id, sid)), Json(json!({ "status": "done" }))).await).await;
        assert_eq!(s2, 204);
        let (s3, _) = pb_json(incident_set(State(st.clone()), Extension(cdc_utilisateur()), Path(id), Json(json!({ "tier": 2 }))).await).await;
        assert_eq!(s3, 204);
    }
}
