// =====================================================================================
// `P10.31-u` (tranche : `handlers/incidents.rs`) — LA DÉCLARATION D'INCIDENT ET L'AVANCEMENT D'ÉTAPE AVOUENT UN
// MAILLON MANQUANT.
//
// LE DÉFAUT, MESURÉ SUR c78be971 AVANT LE CORRECTIF. `incident_apply_tier` et `step_advance` posaient leur maillon
// (`case.incident`, `case.step`) par un appel NU de `ledger_append` puis rendaient `Posee` / `Ecrite` ; les routes
// `POST /api/cases/{id}/incident` et `POST /api/cases/{id}/steps/{step_id}` servaient `204` quel que soit le maillon.
// Une déclaration (palier, pilote) ou une étape marquée faite pouvait être servie comme attestée sans sa ligne d'audit.
//
// LE CORRECTIF. Issues neuves `DeclarationDIncident::PoseeSansTrace(cause)` et `IssueDeLEtape::EcriteSansTrace(cause)`.
// Le geste a eu lieu : il n'est pas annulé ni refusé (le rejouer poserait une seconde déclaration et ne comblerait
// pas le trou) ; la route rend `200 {"ok":true,"registre_sans_maillon":"<CAUSE_GESTE_SANS_TRACE> (<cause>)"}`.
// CONTRAT CHANGÉ sur ce seul cas : `204` -> `200` avec corps. Nominal : `204` sans corps, inchangé.
//
// LA PANNE ÉPROUVÉE : un déclencheur `BEFORE INSERT ON ledger` qui lève `RAISE(ABORT)` (précédent :
// `requetes_sauvegardees_trace_avouee.rs`). Les routes n'ouvrent pas de transaction : l'abandon ne défait que le
// maillon, l'écriture du geste et la chronologie restent.
//
// MUTANTS (VERIF_MUT, retirés avant le commit) : `R7_INC_JETTE` et `R7_ETP_JETTE` (le maillon est de nouveau jeté :
// `Posee` / `Ecrite` sur un `NonInscrit`), `R7_AVEU_SANS_PANNE` (la déclaration nominale sert l'aveu),
// `R7_INC_NON_FAIT` et `R7_ETP_NON_FAIT` (le geste fait sans trace est servi comme un 503 « non écrit »).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la console ne lit pas `registre_sans_maillon` sur ces deux routes ;
// `attach_runbook` jette encore son maillon ; `case_add_item` (chronologie) reste une écriture non jugée après le
// geste ; la sortie d'erreur de la primitive n'est pas capturée ici.
// =====================================================================================
mod incident_et_etape_trace_avouee {
    use super::*;

    fn iet_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("iet-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.31-u` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn iet_utilisateur() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn iet_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn iet_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn iet_registre_hors_d_atteinte(st: &AppState) {
        iet_ecrire(
            st,
            "CREATE TRIGGER iet_ledger_refuse BEFORE INSERT ON ledger \
             BEGIN SELECT RAISE(ABORT, 'registre hors d atteinte (temoin P10.31-u incidents)'); END;",
        );
    }

    /// Un dossier neuf portant UNE étape `pending`.
    fn iet_dossier_et_etape(st: &AppState, titre: &str) -> (i64, i64) {
        let conn = st.db.lock();
        let id = dossier_seme(&conn, "alice", titre, 3, "", None, 2);
        conn.execute(
            "INSERT INTO case_step(incident_id,runbook_id,step_id,ordinal,phase,title) VALUES(?1,1,1,1,'containment','Isoler l''hôte')",
            params![id],
        )
        .unwrap();
        (id, conn.last_insert_rowid())
    }

    async fn iet_reponse(r: Response) -> (u16, Vec<u8>, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, octets, v)
    }

    async fn iet_declarer(st: &AppState, id: i64) -> (u16, Vec<u8>, Value) {
        let corps = json!({ "tier": 2, "incident_type": "rançongiciel", "commander": "pilote-iet" });
        iet_reponse(incident_set(State(st.clone()), Extension(iet_utilisateur()), Path(id), Json(corps)).await).await
    }

    async fn iet_avancer(st: &AppState, id: i64, sid: i64) -> (u16, Vec<u8>, Value) {
        iet_reponse(case_step_set(State(st.clone()), Extension(iet_utilisateur()), Path((id, sid)), Json(json!({ "status": "done" }))).await).await
    }

    fn iet_aveu_conforme(v: &Value) {
        let aveu = v.get(CLE_REGISTRE_SANS_MAILLON).and_then(|x| x.as_str()).unwrap_or_else(|| panic!("le geste sans trace porte `registre_sans_maillon` : {v}"));
        assert!(aveu.starts_with(CAUSE_GESTE_SANS_TRACE), "l'aveu d'un GESTE fait sans trace : {aveu}");
        assert!(aveu.ends_with(&format!(" ({CAUSE_MAILLON_NON_ECRIT})")) && !aveu.contains("registre hors d atteinte"), "INVERSÉ NOMMÉMENT par P10.29-l (vague AM) : l'aveu porte la phrase fixe du maillon non écrit, jamais le texte du moteur : {aveu}");
        assert_eq!(v.get("ok"), Some(&json!(true)), "le geste a eu lieu : {v}");
    }

    const IET_MAILLON_INCIDENT: &str = "SELECT COUNT(*) FROM ledger WHERE kind='case.incident'";
    const IET_MAILLON_ETAPE: &str = "SELECT COUNT(*) FROM ledger WHERE kind='case.step'";

    /// CE QU'IL TIENT : registre hors d'atteinte, la déclaration est ÉCRITE (palier, type, pilote) et racontée en
    /// chronologie ; la fonction rend `PoseeSansTrace` (cause du moteur) ; la route rend 200 avec l'aveu, jamais un
    /// 204 (déclaration attestée) ni un 503 (geste déclaré non fait). Aucun maillon `case.incident`.
    /// MUTATIONS : `R7_INC_JETTE` (204 servi), `R7_INC_NON_FAIT` (503 servi).
    #[tokio::test]
    async fn iet_declaration_sans_maillon_reste_posee_et_l_avoue() {
        let (st, _tmp) = iet_etat("decl-panne");
        let (id, _) = iet_dossier_et_etape(&st, "Dossier déclaré");
        iet_registre_hors_d_atteinte(&st);
        let issue = {
            let conn = st.db.lock();
            incident_apply_tier(&conn, id, "analyste", Some(1), None, None)
        };
        let DeclarationDIncident::PoseeSansTrace(cause) = issue else { panic!("maillon refusé : `PoseeSansTrace`, pas {issue:?}") };
        assert_eq!(cause, CAUSE_MAILLON_NON_ECRIT, "INVERSÉ NOMMÉMENT par P10.29-l (vague AM) : la cause portée est la phrase fixe, jamais le texte du moteur");

        let (statut, _, v) = iet_declarer(&st, id).await;
        assert_eq!(statut, 200, "déclaration faite sans trace : 200 qui l'avoue, ni 204 ni 503 : {v}");
        iet_aveu_conforme(&v);
        let (palier, type_, pilote): (Option<i64>, Option<String>, Option<String>) = st
            .db
            .lock()
            .query_row("SELECT incident_tier, incident_type, commander FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert_eq!((palier, type_.as_deref(), pilote.as_deref()), (Some(2), Some("rançongiciel"), Some("pilote-iet")), "la déclaration est écrite et n'est pas annulée");
        assert_eq!(iet_compte(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={id} AND kind='incident'")), 2, "la chronologie raconte les deux déclarations");
        assert_eq!(iet_compte(&st, IET_MAILLON_INCIDENT), 0, "fixture : aucun maillon `case.incident` n'est entré");
    }

    /// CONTRÔLE NÉGATIF : registre sain, 204 SANS corps et un maillon `case.incident`.
    /// MUTATION : `R7_AVEU_SANS_PANNE` (la déclaration nominale sert l'aveu : 200 avec corps).
    #[tokio::test]
    async fn iet_declaration_nominale_reste_un_deux_cent_quatre_sans_corps() {
        let (st, _tmp) = iet_etat("decl-sain");
        let (id, _) = iet_dossier_et_etape(&st, "Dossier déclaré sain");
        let (statut, octets, v) = iet_declarer(&st, id).await;
        assert_eq!(statut, 204, "déclaration attestée : 204 inchangé : {v}");
        assert!(octets.is_empty(), "aucun corps, donc aucun aveu : {:?}", String::from_utf8_lossy(&octets));
        assert_eq!(iet_compte(&st, IET_MAILLON_INCIDENT), 1, "la déclaration est inscrite au registre");
    }

    /// CE QU'IL TIENT : registre hors d'atteinte, l'étape est ÉCRITE (`done`, acteur) et racontée, le MTTA figé ; la
    /// fonction rend `EcriteSansTrace` ; la route rend 200 avec l'aveu. Aucun maillon `case.step`.
    /// MUTATIONS : `R7_ETP_JETTE` (204 servi), `R7_ETP_NON_FAIT` (503 servi).
    #[tokio::test]
    async fn iet_etape_sans_maillon_reste_ecrite_et_l_avoue() {
        let (st, _tmp) = iet_etat("etape-panne");
        let (id, sid) = iet_dossier_et_etape(&st, "Dossier étape");
        let (_, sid2) = {
            let conn = st.db.lock();
            conn.execute(
                "INSERT INTO case_step(incident_id,runbook_id,step_id,ordinal,phase,title) VALUES(?1,1,2,2,'eradication','Purger')",
                params![id],
            )
            .unwrap();
            (id, conn.last_insert_rowid())
        };
        iet_registre_hors_d_atteinte(&st);
        let issue = {
            let conn = st.db.lock();
            step_advance(&conn, id, sid2, "skipped", "analyste", Some("hors périmètre"))
        };
        let IssueDeLEtape::EcriteSansTrace(cause) = issue else { panic!("maillon refusé : `EcriteSansTrace`, pas {issue:?}") };
        assert_eq!(cause, CAUSE_MAILLON_NON_ECRIT, "INVERSÉ NOMMÉMENT par P10.29-l (vague AM) : la cause portée est la phrase fixe, jamais le texte du moteur");

        let (statut, _, v) = iet_avancer(&st, id, sid).await;
        assert_eq!(statut, 200, "étape faite sans trace : 200 qui l'avoue, ni 204 ni 503 : {v}");
        iet_aveu_conforme(&v);
        let (etat, acteur): (String, Option<String>) =
            st.db.lock().query_row("SELECT status, actor FROM case_step WHERE id=?1", params![sid], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((etat.as_str(), acteur.as_deref()), ("done", Some("analyste")), "l'étape est écrite et n'est pas annulée");
        assert_eq!(iet_compte(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={id} AND kind='step'")), 2, "la chronologie raconte les deux étapes");
        assert_eq!(iet_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND first_response_ts IS NOT NULL")), 1, "le MTTA est figé : le geste a eu lieu");
        assert_eq!(iet_compte(&st, IET_MAILLON_ETAPE), 0, "fixture : aucun maillon `case.step` n'est entré");
    }

    /// CONTRÔLE NÉGATIF : registre sain, 204 SANS corps et un maillon `case.step`.
    #[tokio::test]
    async fn iet_etape_nominale_reste_un_deux_cent_quatre_sans_corps() {
        let (st, _tmp) = iet_etat("etape-sain");
        let (id, sid) = iet_dossier_et_etape(&st, "Dossier étape saine");
        let (statut, octets, v) = iet_avancer(&st, id, sid).await;
        assert_eq!(statut, 204, "étape attestée : 204 inchangé : {v}");
        assert!(octets.is_empty(), "aucun corps : {:?}", String::from_utf8_lossy(&octets));
        assert_eq!(iet_compte(&st, IET_MAILLON_ETAPE), 1, "l'étape est inscrite au registre");
    }

    /// CONTRÔLES DE NON-CONFUSION, registre hors d'atteinte : un geste qui N'A PAS EU LIEU n'avoue aucune trace
    /// manquante (il n'y a rien à tracer) — étape d'un autre dossier (404 nommé), étape non écrite (503 nommé
    /// `CAUSE_ETAPE_NON_ECRITE`), dossier introuvable (`DossierIntrouvable`). Aucun ne porte `registre_sans_maillon`.
    #[tokio::test]
    async fn iet_geste_non_fait_n_avoue_aucune_trace_manquante() {
        let (st, _tmp) = iet_etat("non-fait");
        let (id, _) = iet_dossier_et_etape(&st, "Dossier A");
        let (_, sid_autre) = iet_dossier_et_etape(&st, "Dossier B");
        iet_registre_hors_d_atteinte(&st);

        let (statut, _, v) = iet_avancer(&st, id, sid_autre).await;
        assert_eq!(statut, 404, "étape d'un autre dossier : 404 inchangé : {v}");
        assert!(v.get(CLE_REGISTRE_SANS_MAILLON).is_none(), "rien n'a été fait, rien à avouer : {v}");

        let introuvable = {
            let conn = st.db.lock();
            incident_apply_tier(&conn, id + 1000, "analyste", Some(1), None, None)
        };
        assert_eq!(introuvable, DeclarationDIncident::DossierIntrouvable, "dossier absent : rien d'écrit, rien à avouer");

        let (_, sid) = {
            let conn = st.db.lock();
            let s: i64 = conn.query_row("SELECT id FROM case_step WHERE incident_id=?1", params![id], |r| r.get(0)).unwrap();
            (id, s)
        };
        iet_ecrire(&st, "ALTER TABLE case_step RENAME TO case_step_source; CREATE TEMP VIEW case_step AS SELECT * FROM case_step_source;");
        let (statut, _, v) = iet_avancer(&st, id, sid).await;
        assert_eq!(statut, 503, "étape non écrite : 503 inchangé : {v}");
        let phrase = v.get("error").and_then(|e| e.as_str()).unwrap_or("");
        assert!(phrase.starts_with(CAUSE_ETAPE_NON_ECRITE), "le refus nomme l'écriture refusée : {v}");
        assert!(v.get(CLE_REGISTRE_SANS_MAILLON).is_none(), "geste non fait : aucun aveu de trace : {v}");
        assert_eq!(iet_compte(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={id} AND kind='step'")), 0, "rien n'est raconté");
    }
}
