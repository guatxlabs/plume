// =====================================================================================
// `P10.20-w` (rang trois, dernier site) — L'AVANCEMENT D'UNE ÉTAPE DE RUNBOOK COMPTE SON ÉCRITURE AVANT LE FAIT.
//
// CE QUE CES TÉMOINS TIENNENT. `step_advance` (incidents.rs) AVALAIT `UPDATE case_step SET status=…` (`let _ =`)
// puis posait l'élément de chronologie `step` (qui fige aussi `first_response_ts`, le MTTA) et la ligne `case.step`
// au registre non purgeable, et rendait `true` : la route `POST /api/cases/{id}/steps/{step_id}` répondait 204.
// Les témoins jouent la table `case_step` rendue NON MODIFIABLE (vue temporaire de même nom, comme les témoins
// `ecf_`, `fec_` et `dec_` : la lecture passe, seule l'écriture échoue), comptent chronologie, registre et MTTA,
// puis rejouent la base saine pour prouver que la sortie d'avant est intacte (contrôle positif, textes relus).
//
// CONTRAT CHANGÉ, ASSUMÉ : l'écriture refusée rend un 503 NOMMÉ `CAUSE_ETAPE_NON_ECRITE` (elle rendait 204), distinct
// du 503 de la relecture ratée (`CAUSE_ETAPE_NON_LUE_GESTE_NON_FAIT`, inchangé) ; un second appel, la base revenue,
// écrit l'étape et la trace une fois — rien n'a été posé au premier.
//
// LE BRAS `Ok(0)` (l'`UPDATE` ne modifie aucune ligne) est fabriqué par un déclencheur temporaire
// `BEFORE UPDATE … RAISE(IGNORE)` : `step_advance` rend `EtapeAbsente` sans rien tracer, et la route, qui vient de lire
// l'étape, sert un 503 NOMMÉ `CAUSE_ETAPE_NON_RETROUVEE_AU_GESTE` (elle servait la cause « non lue », imprécise).
//
// CE QU'ILS NE TIENNENT PAS : aucune base réellement en lecture seule ; `case_add_item` et `ledger_append` restent des écritures non jugées
// APRÈS l'`UPDATE` compté (hors de cette clé) ; rien de ce que la console PEINT du 503 neuf.
//
// Mutants joués par VERIF_MUT (rouges, retirés avant le commit) : `F3_AVALE` (le bras `Err` de l'`UPDATE` continue,
// la forme d'avant), `F3_ROUTE_CONFOND` (la route sert la cause de la relecture ratée pour une écriture refusée),
// `F3_OK0_ECRITE` (`Ok(0)` continue comme une écriture faite), `F3_ABSENTE_204` (la route rend 204 sur `EtapeAbsente`),
// `M_ERR_VIDE` (la cause du moteur n'est pas portée), `M_R_NE_SANSCAUSE` (la route ne la sert pas) et
// `F3_LECTURE_ABSENTE` (une relecture du titre en ERREUR rend `EtapeAbsente`, la confusion d'avant).
//
// LA RELECTURE DU TITRE EN ERREUR (autre que `NoRows`) est fabriquée par une vue temporaire `case_step` SANS colonne
// `title` : la lecture d'appartenance de la route passe (elle ne lit que `id` et `incident_id`), celle de
// `step_advance` échoue ; la fonction rend `NonRelue` (cause portée) et la route sert le 503 « non lue » avec la cause.
// =====================================================================================
mod etape_de_runbook_ecriture_comptee {
    use super::*;

    fn eta_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("eta-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.20-w` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn eta_utilisateur() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn eta_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn eta_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn eta_texte(st: &AppState, sql: &str) -> Vec<String> {
        let conn = st.db.lock();
        let mut s = conn.prepare(sql).unwrap();
        s.query_map([], |r| r.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    fn eta_phrase(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    /// Un dossier neuf portant UNE étape `pending` (posée directement : l'attache du runbook n'est pas le sujet).
    fn eta_dossier_et_etape(st: &AppState, titre: &str) -> (i64, i64) {
        let conn = st.db.lock();
        let id = dossier_seme(&conn, "alice", titre, 3, "", None, 2);
        conn.execute(
            "INSERT INTO case_step(incident_id,runbook_id,step_id,ordinal,phase,title) VALUES(?1,1,1,1,'containment','Isoler l''hôte')",
            params![id],
        )
        .unwrap();
        (id, conn.last_insert_rowid())
    }

    fn eta_table_case_step_non_modifiable(st: &AppState) {
        eta_ecrire(st, "ALTER TABLE case_step RENAME TO case_step_source; CREATE TEMP VIEW case_step AS SELECT * FROM case_step_source;");
    }

    fn eta_table_case_step_modifiable(st: &AppState) {
        eta_ecrire(st, "DROP VIEW case_step; ALTER TABLE case_step_source RENAME TO case_step;");
    }

    async fn eta_avancer(st: &AppState, id: i64, sid: i64, corps: Value) -> (u16, Value) {
        pb_json(case_step_set(State(st.clone()), Extension(eta_utilisateur()), Path((id, sid)), Json(corps)).await).await
    }

    const ETA_REGISTRE: &str = "SELECT COUNT(*) FROM ledger WHERE kind='case.step'";

    /// CE QU'IL TIENT : l'`UPDATE` de l'étape refusé par la base rend `NonEcrite` (cause du moteur portée), sans
    /// élément `step` en chronologie, sans maillon `case.step` au registre, sans MTTA figé ; la route sert un 503
    /// NOMMÉ `CAUSE_ETAPE_NON_ECRITE` (jamais un 204, jamais la cause de la relecture ratée). Contrôle positif
    /// dans le même corps : la base revenue, la MÊME demande rend 204 et les traces sont
    /// exactement celles d'avant (textes relus).
    ///
    /// MUTATIONS QUI LE FONT ROUGIR : `F3_AVALE` (la fonction rend `Ecrite`, la chronologie et le registre gagnent
    /// une ligne, la route rend 204) ; `F3_ROUTE_CONFOND` (le 503 porte la phrase de la relecture ratée) ;
    /// `M_ERR_VIDE` (`NonEcrite` porte une cause vide) ; `M_R_NE_SANSCAUSE` (la route sert la phrase sans la cause).
    #[tokio::test]
    async fn eta_une_etape_non_ecrite_n_est_ni_un_deux_cent_quatre_ni_une_ligne_de_registre() {
        let (st, _tmp) = eta_etat("non-ecrite");
        let (id, sid) = eta_dossier_et_etape(&st, "Dossier étape");
        let mtta = format!("SELECT COUNT(*) FROM incident WHERE id={id} AND first_response_ts IS NULL");
        assert_eq!(eta_compte(&st, &mtta), 1, "fixture : MTTA non figé au départ");

        eta_table_case_step_non_modifiable(&st);
        let registre_avant = eta_compte(&st, ETA_REGISTRE);
        let chronologie_avant = eta_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='step'");
        let issue = {
            let conn = st.db.lock();
            step_advance(&conn, id, sid, "done", "analyste", None)
        };
        let IssueDeLEtape::NonEcrite(cause) = issue else { panic!("écriture refusée : `NonEcrite`, pas {issue:?}") };
        assert!(cause.contains("case_step"), "la cause du MOTEUR est portée (elle nomme la vue refusée) : {cause:?}");
        assert_eq!(eta_compte(&st, ETA_REGISTRE), registre_avant, "aucun maillon `case.step` n'atteste une étape non écrite");
        assert_eq!(eta_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='step'"), chronologie_avant, "aucune chronologie ne la raconte");
        assert_eq!(eta_compte(&st, &mtta), 1, "le MTTA n'est pas figé par une étape non écrite");

        let (statut, avoue) = eta_avancer(&st, id, sid, json!({ "status": "skipped", "note": "hors périmètre" })).await;
        assert_eq!(statut, 503, "étape non écrite : 503 nommé, jamais un 204 : {avoue}");
        assert!(eta_phrase(&avoue).starts_with(CAUSE_ETAPE_NON_ECRITE), "le refus NOMME l'écriture refusée : {avoue}");
        assert!(!eta_phrase(&avoue).starts_with(CAUSE_ETAPE_NON_LUE_GESTE_NON_FAIT), "ce n'est pas une relecture ratée : {avoue}");
        assert_eq!(eta_phrase(&avoue), format!("{CAUSE_ETAPE_NON_ECRITE} ({cause})"), "la route SERT la cause du moteur : {avoue}");
        assert_eq!(eta_compte(&st, ETA_REGISTRE), registre_avant, "la route n'atteste rien non plus");
        assert_eq!(eta_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='step'"), chronologie_avant);
        assert_eq!(eta_compte(&st, &mtta), 1);
        eta_table_case_step_modifiable(&st);

        // CONTRÔLE POSITIF — la base revenue, la même demande : la sortie d'avant, octet pour octet.
        let (statut, corps) = eta_avancer(&st, id, sid, json!({ "status": "skipped", "note": "hors périmètre" })).await;
        assert_eq!(statut, 204, "base saine : 204, comme avant : {corps}");
        assert_eq!(eta_compte(&st, &format!("SELECT COUNT(*) FROM case_step WHERE id={sid} AND status='skipped' AND actor='analyste' AND note='hors périmètre'")), 1);
        assert_eq!(
            eta_texte(&st, "SELECT detail FROM ledger WHERE kind='case.step' ORDER BY id"),
            vec![format!("#{id} step={sid} -> skipped by analyste")],
            "un seul maillon, celui de l'écriture réussie"
        );
        assert_eq!(
            eta_texte(&st, &format!("SELECT body FROM incident_item WHERE incident_id={id} AND kind='step' ORDER BY id")),
            vec!["étape « Isoler l'hôte » IGNORÉE — hors périmètre".to_string()],
        );
        assert_eq!(eta_compte(&st, &mtta), 0, "l'écriture réussie fige le MTTA, comme avant");
    }

    /// CE QU'IL TIENT : l'étape d'un AUTRE dossier (anti-IDOR) et le statut invalide rendent `EtapeAbsente` — la
    /// sortie d'avant (`false`) — sans rien écrire ni tracer, et la route garde ses refus d'avant (404, 400).
    #[tokio::test]
    async fn eta_etape_d_un_autre_dossier_reste_absente_et_rien_n_est_trace() {
        let (st, _tmp) = eta_etat("autre-dossier");
        let (id, sid) = eta_dossier_et_etape(&st, "Dossier A");
        let (autre, _) = eta_dossier_et_etape(&st, "Dossier B");
        let registre_avant = eta_compte(&st, ETA_REGISTRE);
        let issue = {
            let conn = st.db.lock();
            step_advance(&conn, autre, sid, "done", "eve", None)
        };
        assert_eq!(issue, IssueDeLEtape::EtapeAbsente, "l'étape d'un autre dossier n'est pas avancée");
        let issue = {
            let conn = st.db.lock();
            step_advance(&conn, id, sid, "bogus", "eve", None)
        };
        assert_eq!(issue, IssueDeLEtape::EtapeAbsente, "statut invalide : absente, comme avant");
        assert_eq!(eta_avancer(&st, autre, sid, json!({ "status": "done" })).await.0, 404, "route : 404 nommé, inchangé");
        assert_eq!(eta_avancer(&st, id, sid, json!({ "status": "bogus" })).await.0, 400, "route : 400 nommé, inchangé");
        assert_eq!(eta_compte(&st, ETA_REGISTRE), registre_avant);
        assert_eq!(eta_compte(&st, &format!("SELECT COUNT(*) FROM case_step WHERE id={sid} AND status='pending'")), 1);
    }

    /// CE QU'IL TIENT : un `UPDATE` qui ne modifie AUCUNE ligne (`Ok(0)`, fabriqué par un déclencheur temporaire
    /// `RAISE(IGNORE)`) rend `EtapeAbsente` — jamais `Ecrite` — sans élément `step` en chronologie, sans maillon
    /// `case.step` au registre, sans MTTA figé ; la route, qui a lu l'étape juste avant, sert un 503 NOMMÉ
    /// `CAUSE_ETAPE_NON_RETROUVEE_AU_GESTE` (ni 204, ni « non lue », ni « écriture refusée »). Contrôle positif : le
    /// déclencheur retiré, la même demande rend 204 et pose un maillon.
    ///
    /// MUTATIONS QUI LE FONT ROUGIR : `F3_OK0_ECRITE` (`Ecrite`, chronologie et registre gagnent une ligne) ;
    /// `F3_ABSENTE_204` (la route rend 204).
    #[tokio::test]
    async fn eta_un_update_sans_ligne_modifiee_n_est_ni_ecrit_ni_trace() {
        let (st, _tmp) = eta_etat("aucune-ligne");
        let (id, sid) = eta_dossier_et_etape(&st, "Dossier sans ligne");
        let mtta = format!("SELECT COUNT(*) FROM incident WHERE id={id} AND first_response_ts IS NULL");
        eta_ecrire(&st, "CREATE TEMP TRIGGER eta_ignore BEFORE UPDATE ON case_step BEGIN SELECT RAISE(IGNORE); END;");
        let registre_avant = eta_compte(&st, ETA_REGISTRE);
        let chronologie_avant = eta_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='step'");
        let issue = {
            let conn = st.db.lock();
            step_advance(&conn, id, sid, "done", "analyste", None)
        };
        assert_eq!(issue, IssueDeLEtape::EtapeAbsente, "aucune ligne modifiée : jamais `Ecrite`");
        assert_eq!(eta_compte(&st, ETA_REGISTRE), registre_avant, "aucun maillon pour une étape non écrite");
        assert_eq!(eta_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='step'"), chronologie_avant);
        assert_eq!(eta_compte(&st, &mtta), 1, "le MTTA n'est pas figé");

        let (statut, avoue) = eta_avancer(&st, id, sid, json!({ "status": "done" })).await;
        assert_eq!(statut, 503, "aucune ligne modifiée : 503 nommé, jamais un 204 : {avoue}");
        assert!(eta_phrase(&avoue).starts_with(CAUSE_ETAPE_NON_RETROUVEE_AU_GESTE), "la cause est nommée : {avoue}");
        assert_eq!(eta_compte(&st, ETA_REGISTRE), registre_avant, "la route n'atteste rien");
        assert_eq!(eta_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='step'"), chronologie_avant);
        assert_eq!(eta_compte(&st, &mtta), 1);

        // CONTRÔLE POSITIF — le déclencheur retiré, la même demande écrit et trace une fois.
        eta_ecrire(&st, "DROP TRIGGER eta_ignore;");
        assert_eq!(eta_avancer(&st, id, sid, json!({ "status": "done" })).await.0, 204);
        assert_eq!(eta_compte(&st, ETA_REGISTRE), registre_avant + 1, "un seul maillon, celui de l'écriture réussie");
        assert_eq!(eta_compte(&st, &mtta), 0);
    }

    /// CE QU'IL TIENT : une relecture du titre en ERREUR (pas `NoRows`) rend `NonRelue` avec la cause du moteur —
    /// jamais `EtapeAbsente` — sans rien écrire ni tracer ; la route sert le 503 NOMMÉ
    /// `CAUSE_ETAPE_NON_LUE_GESTE_NON_FAIT (cause)`, pas « non retrouvée au geste ». La vue retirée, la même demande
    /// rend 204 (contrôle positif).
    ///
    /// MUTATION QUI LE FAIT ROUGIR : `F3_LECTURE_ABSENTE` (la lecture ratée redevient `EtapeAbsente`).
    #[tokio::test]
    async fn eta_une_relecture_du_titre_en_erreur_n_est_pas_une_absence() {
        let (st, _tmp) = eta_etat("relecture");
        let (id, sid) = eta_dossier_et_etape(&st, "Dossier relecture");
        eta_ecrire(&st, "ALTER TABLE case_step RENAME TO case_step_source; CREATE TEMP VIEW case_step AS SELECT id, incident_id FROM case_step_source;");
        let registre_avant = eta_compte(&st, ETA_REGISTRE);
        let issue = {
            let conn = st.db.lock();
            step_advance(&conn, id, sid, "done", "analyste", None)
        };
        let IssueDeLEtape::NonRelue(cause) = issue else { panic!("relecture en erreur : `NonRelue`, pas {issue:?}") };
        assert!(cause.contains("title"), "la cause du MOTEUR est portée (colonne absente) : {cause:?}");
        let (statut, avoue) = eta_avancer(&st, id, sid, json!({ "status": "done" })).await;
        assert_eq!(statut, 503, "relecture en erreur : 503 nommé : {avoue}");
        assert_eq!(eta_phrase(&avoue), format!("{CAUSE_ETAPE_NON_LUE_GESTE_NON_FAIT} ({cause})"), "cause nommée et portée : {avoue}");
        assert_eq!(eta_compte(&st, ETA_REGISTRE), registre_avant, "rien n'est attesté");
        eta_table_case_step_modifiable(&st);
        assert_eq!(eta_compte(&st, &format!("SELECT COUNT(*) FROM case_step WHERE id={sid} AND status='pending'")), 1, "rien n'a été écrit");
        assert_eq!(eta_avancer(&st, id, sid, json!({ "status": "done" })).await.0, 204, "base saine : 204");
        assert_eq!(eta_compte(&st, ETA_REGISTRE), registre_avant + 1);
    }
}
