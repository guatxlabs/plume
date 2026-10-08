// =====================================================================================
// `P10.20-b` (rang deux, `case_create`) et `P10.20-w` (reste de `case_apply_update`) — L'ÉCHÉANCE D'UN DOSSIER
// CRÉÉ EST RELUE OU AVOUÉE ; LA PRIORITÉ ET LE RECALCUL DE L'ÉCHÉANCE SONT COMPTÉS.
//
// CE QUI ÉTAIT FAUX, MESURÉ SUR af310b3 :
//   * `case_create` (cases.rs) relisait `sla_due` par `.unwrap_or(None)` et servait `sla_due: null` sur une
//     relecture ratée — « pas d'échéance » là où la ligne n'avait pas été relue ;
//   * `case_apply_update` avalait `UPDATE incident SET priority` puis posait l'élément « priorité -> P… » : la
//     chronologie racontait un changement non écrit ;
//   * le recalcul `sla_due` puis `escalated=0` était avalé pendant que la route rendait 204.
//
// LES VOIES DE L'ÉCHEC : un AUTORISATEUR qui refuse la lecture de la seule colonne `incident.sla_due` (l'insertion
// du dossier passe) ; des DÉCLENCHEURS `BEFORE UPDATE OF <colonne>` qui refusent l'écriture de la seule colonne
// visée (les autres écritures du geste passent, la chronologie aussi).
//
// LES DEUX BRAS `Ok(0)` DU RECALCUL : celui de `sla_due` (ligne écartée par un déclencheur `RAISE(IGNORE)`, la
// forme fabriquable d'un dossier disparu entre la lecture et l'écriture) est une ABSENCE ; celui d'`escalated`
// (échéance déjà passée, la condition `sla_due > maintenant` n'en retient aucune) est un FAIT, jamais une absence.
//
// CE QU'ILS NE TIENNENT PAS : aucune base réellement en lecture seule ; la console n'est pas jugée (`web/cases.js` ne lit pas
// `sla_due` dans le corps de création : elle rouvre le dossier par GET) ; les écritures sans registre ni chronologie
// (titre, sévérité, propriétaire, résumé, `updated`) restent avalées ; `sla_apply_policy` (caseops.rs) non touché.
// =====================================================================================
mod dossier_cree_echeance_relue_priorite_comptee {
    use super::*;

    fn dcp_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("dcp-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn dcp_utilisateur() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn dcp_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn dcp_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn dcp_refuser_l_ecriture_de(st: &AppState, colonne: &str) {
        dcp_ecrire(st, &format!(
            "CREATE TEMP TRIGGER dcp_refus_{colonne} BEFORE UPDATE OF {colonne} ON incident BEGIN SELECT RAISE(ABORT, 'dcp: {colonne} non inscriptible'); END;"
        ));
    }

    fn dcp_permettre_l_ecriture_de(st: &AppState, colonne: &str) {
        dcp_ecrire(st, &format!("DROP TRIGGER dcp_refus_{colonne};"));
    }

    async fn dcp_creer(st: &AppState) -> (u16, Value) {
        pb_json(case_create(State(st.clone()), Extension(dcp_utilisateur()), Json(json!({ "title": "Dossier", "priority": 2 }))).await).await
    }

    async fn dcp_mettre_a_jour(st: &AppState, id: i64, corps: Value) -> (u16, Value) {
        pb_json(case_update(State(st.clone()), Extension(dcp_utilisateur()), Path(id), Json(corps)).await).await
    }

    fn dcp_items_priorite(st: &AppState, id: i64) -> i64 {
        dcp_compte(st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={id} AND kind='priority'"))
    }

    /// CE QU'IL TIENT (`case_create`) : la relecture de `sla_due` refusée sert le dossier créé avec son identifiant,
    /// `sla_due: null` ET `sla_due_non_lu` nommé ; la ligne relue sert le corps d'avant, sans champ d'aveu.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=F4_CREATE` (la forme `.unwrap_or(None)` d'avant) — aucun aveu.
    #[tokio::test]
    async fn dcp_une_echeance_non_relue_a_la_creation_est_avouee_et_le_dossier_reste_servi() {
        let (st, _tmp) = dcp_etat("creation");
        {
            use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
            st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Read { table_name: "incident", column_name: "sla_due" } => Authorization::Deny,
                _ => Authorization::Allow,
            }));
        }
        let (statut, corps) = dcp_creer(&st).await;
        {
            use rusqlite::hooks::{AuthContext, Authorization};
            st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        }
        assert_eq!(statut, 200, "le dossier est créé : il reste servi : {corps}");
        let id = corps["id"].as_i64().expect("l'identifiant est servi");
        assert_eq!(dcp_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND sla_due IS NOT NULL")), 1, "fixture : l'échéance existe");
        assert!(corps["sla_due"].is_null(), "échéance non lue : null : {corps}");
        let aveu = corps.get("sla_due_non_lu").and_then(|v| v.as_str()).unwrap_or("");
        assert!(aveu.starts_with(CAUSE_ECHEANCE_DU_DOSSIER_CREE_NON_RELUE), "le null est AVOUÉ non lu, jamais « sans échéance » : {corps}");

        // CONTRÔLE POSITIF — le corps d'avant, champ pour champ.
        let (statut, corps) = dcp_creer(&st).await;
        assert_eq!(statut, 200);
        let id = corps["id"].as_i64().unwrap();
        let echeance = dcp_compte(&st, &format!("SELECT sla_due FROM incident WHERE id={id}"));
        assert_eq!(corps, json!({ "id": id, "status": "new", "priority": 2, "priority_label": priority_label(2), "sla_due": echeance }));
    }

    /// CE QU'IL TIENT (`case_apply_update`, priorité) : une priorité que la base refuse d'écrire rend
    /// `NonEcrite("priority: …")` et 503 nommé, sans élément « priorité » de chronologie ; écriture réussie : 204,
    /// un élément de plus, la priorité écrite.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=F4_PRIO` (l'`UPDATE` avalé d'avant) — `Ecrite` et un élément menteur.
    #[tokio::test]
    async fn dcp_une_priorite_non_ecrite_n_est_pas_racontee_par_la_chronologie() {
        let (st, _tmp) = dcp_etat("priorite");
        let id = { let conn = st.db.lock(); dossier_seme(&conn, "alice", "Dossier", 3, "", None, 3) };
        let avant = dcp_items_priorite(&st, id);
        dcp_refuser_l_ecriture_de(&st, "priority");
        let issue = { let conn = st.db.lock(); case_apply_update(&conn, id, "analyste", &json!({ "priority": 1 })) };
        match &issue {
            IssueDuDossierModifie::NonEcrite(cause) => assert!(cause.starts_with("priority: "), "la cause nomme la priorité : {cause}"),
            autre => panic!("priorité refusée : `NonEcrite` attendu, pas {autre:?}"),
        }
        let (statut, avoue) = dcp_mettre_a_jour(&st, id, json!({ "priority": 1 })).await;
        assert_eq!(statut, 503, "priorité non écrite : 503 nommé : {avoue}");
        assert!(avoue["error"].as_str().unwrap_or("").starts_with(CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE), "{avoue}");
        assert_eq!(dcp_items_priorite(&st, id), avant, "aucune chronologie « priorité » pour un changement non écrit");
        dcp_permettre_l_ecriture_de(&st, "priority");

        // CONTRÔLE POSITIF — la sortie d'avant.
        assert_eq!(dcp_mettre_a_jour(&st, id, json!({ "priority": 1 })).await.0, 204);
        assert_eq!(dcp_items_priorite(&st, id), avant + 1);
        assert_eq!(dcp_compte(&st, &format!("SELECT priority FROM incident WHERE id={id}")), 1);
    }

    /// CE QU'IL TIENT (`case_apply_update`, recalcul) : `sla_due` refusé rend `NonEcrite("sla_due: …")`, `escalated`
    /// refusé rend `NonEcrite("escalated: …")`, la route 503 nommé (c'était un 204) ; écritures permises : 204,
    /// échéance recalculée et `escalated` ré-armé.
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=F4_SLA` et `VERIF_MUT=F4_ESC` (les `UPDATE` avalés d'avant).
    #[tokio::test]
    async fn dcp_un_recalcul_d_echeance_non_ecrit_n_est_pas_un_deux_cent_quatre() {
        let (st, _tmp) = dcp_etat("recalcul");
        let id = { let conn = st.db.lock(); dossier_seme(&conn, "alice", "Dossier", 3, "", None, 4) };
        dcp_ecrire(&st, &format!("UPDATE incident SET escalated=1 WHERE id={id}"));
        for colonne in ["sla_due", "escalated"] {
            dcp_refuser_l_ecriture_de(&st, colonne);
            let issue = { let conn = st.db.lock(); case_apply_update(&conn, id, "analyste", &json!({ "priority": 1 })) };
            match &issue {
                IssueDuDossierModifie::NonEcrite(cause) => assert!(cause.starts_with(&format!("{colonne}: ")), "la cause nomme {colonne} : {cause}"),
                autre => panic!("{colonne} refusé : `NonEcrite` attendu, pas {autre:?}"),
            }
            let (statut, avoue) = dcp_mettre_a_jour(&st, id, json!({ "title": "renommé" })).await;
            assert_eq!(statut, 503, "{colonne} non écrit : 503 nommé, jamais 204 : {avoue}");
            assert!(avoue["error"].as_str().unwrap_or("").contains(&format!("({colonne}: ")), "{avoue}");
            dcp_permettre_l_ecriture_de(&st, colonne);
        }
        assert_eq!(dcp_compte(&st, &format!("SELECT escalated FROM incident WHERE id={id}")), 1, "escalated n'a pas été ré-armé");

        // CONTRÔLE POSITIF.
        assert_eq!(dcp_mettre_a_jour(&st, id, json!({ "priority": 1 })).await.0, 204);
        assert_eq!(dcp_compte(&st, &format!("SELECT sla_due - ts FROM incident WHERE id={id}")), sla_target_s(1));
        assert_eq!(dcp_compte(&st, &format!("SELECT escalated FROM incident WHERE id={id}")), 0);
    }

    /// CE QU'IL TIENT (`case_apply_update`, `escalated`) : un dossier non terminal dont l'échéance est DÉJÀ passée —
    /// l'`UPDATE` conditionnel d'`escalated` touche zéro ligne, et c'est un fait : la mise à jour reste `Ecrite`,
    /// la route rend 204, `escalated` reste posé. Uniformiser ce site avec `ecriture_comptee!` rendrait
    /// `DossierAbsent`, donc un 503 « dossier non lu » sur toute mise à jour d'un dossier en retard.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=F4_ESC_ZERO_ABSENT` (le site passé par la macro).
    #[tokio::test]
    async fn dcp_une_echeance_deja_passee_n_est_pas_un_dossier_absent() {
        let (st, _tmp) = dcp_etat("retard");
        let id = { let conn = st.db.lock(); dossier_seme(&conn, "alice", "Dossier", 3, "", None, 1) };
        dcp_ecrire(&st, &format!("UPDATE incident SET ts = ts - 100000, escalated = 1 WHERE id={id}"));
        let issue = { let conn = st.db.lock(); case_apply_update(&conn, id, "analyste", &json!({ "title": "t" })) };
        assert_eq!(issue, IssueDuDossierModifie::Ecrite, "zéro ligne sur une échéance passée est un fait, pas une absence");
        assert_eq!(dcp_mettre_a_jour(&st, id, json!({ "title": "renommé" })).await.0, 204, "dossier en retard : 204");
        assert!(dcp_compte(&st, &format!("SELECT sla_due FROM incident WHERE id={id}")) < now(), "fixture : échéance passée");
        assert_eq!(dcp_compte(&st, &format!("SELECT sla_due - ts FROM incident WHERE id={id}")), sla_target_s(1));
        assert_eq!(dcp_compte(&st, &format!("SELECT escalated FROM incident WHERE id={id}")), 1, "échéance passée : escalated reste posé");
    }

    /// CE QU'IL TIENT (`case_apply_update`, `sla_due`) : un recalcul qui n'écrit AUCUNE ligne (un déclencheur
    /// `RAISE(IGNORE)` l'écarte, comme un dossier disparu depuis la lecture) rend `DossierAbsent`, jamais `Ecrite` ;
    /// déclencheur retiré : `Ecrite`.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=F4_SLA_ZERO_ECRIT` (`Ok(0)` traité comme écrit).
    #[test]
    fn dcp_un_recalcul_d_echeance_qui_n_ecrit_aucune_ligne_est_une_absence() {
        let (st, _tmp) = dcp_etat("zero-ligne");
        let id = { let conn = st.db.lock(); dossier_seme(&conn, "alice", "Dossier", 3, "", None, 3) };
        dcp_ecrire(&st, "CREATE TEMP TRIGGER dcp_ignore_sla_due BEFORE UPDATE OF sla_due ON incident BEGIN SELECT RAISE(IGNORE); END;");
        let issue = { let conn = st.db.lock(); case_apply_update(&conn, id, "analyste", &json!({ "title": "t" })) };
        assert_eq!(issue, IssueDuDossierModifie::DossierAbsent, "zéro ligne écrite au recalcul : absence");
        dcp_ecrire(&st, "DROP TRIGGER dcp_ignore_sla_due;");

        // CONTRÔLE POSITIF.
        let issue = { let conn = st.db.lock(); case_apply_update(&conn, id, "analyste", &json!({ "title": "t" })) };
        assert_eq!(issue, IssueDuDossierModifie::Ecrite);
    }
}
