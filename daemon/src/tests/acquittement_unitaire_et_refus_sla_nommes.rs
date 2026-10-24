// =====================================================================================
// `P10.29-l` et `P10.31-u` (tranche : `cases.rs::ack`) — L'ACQUITTEMENT D'UNE ALERTE ET LES REFUS VOISINS DE
// `caseops.rs` SONT NOMMÉS.
//
// LE DÉFAUT, MESURÉ SUR 7ecbec19 AVANT LE CORRECTIF. `POST /api/alerts/{id}/ack` : `Ok(_) => { ledger_append(
// "alert.ack") ; 204 }` — un identifiant ABSENT (zéro ligne modifiée) était attesté au registre non purgeable et
// rendu `204` ; une écriture refusée sortait en `500` sans corps ; le maillon était jeté (appel nu). Dans
// `caseops.rs` : `sla_policy_upsert` refusait par deux `400` sans corps, `sla_policy_delete` par un `403` et un
// `404` sans corps, `client_case_get` par un `404` en texte `case introuvable`.
//
// LE CORRECTIF (décision par défaut de la vague AA). `ack` : zéro ligne -> `404` `CAUSE_ALERTE_INTROUVABLE`, rien au
// registre ; erreur du moteur -> `503` `CAUSE_ACQUITTEMENT_DE_L_ALERTE_NON_ECRIT`, cause du moteur au journal seul ;
// maillon manquant -> `200 {"ok":true,"registre_sans_maillon":…}`, l'acquittement n'est pas annulé. Les refus de
// `caseops.rs` gardent leur statut et prennent un corps `{"error": …}` nommé.
//
// LES PANNES ÉPROUVÉES : un déclencheur `BEFORE INSERT ON ledger` (maillon refusé) et un déclencheur
// `BEFORE UPDATE ON alert` (écriture refusée) qui lèvent `RAISE(ABORT)`.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : `AA2_ACK_ZERO_ATTESTE`, `AA2_ACK_AVEU_SANS_PANNE`,
// `AA2_ACK_MAILLON_JETE`, `AA2_ACK_ERR_NU`, `AA2_ACK_CAUSE_EXPOSEE`, `AA2_SLA_PRIORITE_NUE`, `AA2_SLA_CIBLE_NUE`,
// `AA2_SLA_403_NU`, `AA2_SLA_404_NU`, `AA2_CLIENT_404_TEXTE`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la console ne lit pas `registre_sans_maillon` sur l'acquittement unitaire ;
// l'`UPDATE` d'`ack` ne filtre aucun statut (une alerte `resolved` repasse `ack`) ; `notifier_test` et
// `retention_settings_put` (autres restes de `P10.29-l`) ne sont pas touchés ; la sortie d'erreur n'est pas capturée.
// =====================================================================================
mod acquittement_unitaire_et_refus_sla_nommes {
    use super::*;

    fn aa2_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("aa2-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.29-l` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM sla_policy", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn aa2_utilisateur(role: &str) -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: role.into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn aa2_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn aa2_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn aa2_alerte(st: &AppState) -> i64 {
        let conn = st.db.lock();
        conn.execute("INSERT INTO alert(ts,rule,severity,title,status) VALUES(1000,'rule.aa2',2,'Alerte AA2','new')", []).unwrap();
        conn.last_insert_rowid()
    }

    fn aa2_statut_de_l_alerte(st: &AppState, id: i64) -> (String, Option<String>) {
        st.db.lock().query_row("SELECT status, acked_by FROM alert WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap()
    }

    async fn aa2_reponse(r: Response) -> (u16, Vec<u8>, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, octets, v)
    }

    async fn aa2_acquitter(st: &AppState, id: i64) -> (u16, Vec<u8>, Value) {
        aa2_reponse(ack(State(st.clone()), Extension(aa2_utilisateur("editor")), Path(id)).await).await
    }

    const AA2_MAILLONS_ACK: &str = "SELECT COUNT(*) FROM ledger WHERE kind='alert.ack'";
    const AA2_MOTEUR_ALERTE: &str = "alerte hors d atteinte (temoin AA2)";
    const AA2_MOTEUR_REGISTRE: &str = "registre hors d atteinte (temoin AA2)";

    /// CE QU'IL TIENT : un identifiant qu'aucune alerte ne porte rend `404` avec `CAUSE_ALERTE_INTROUVABLE`, et le
    /// registre ne porte AUCUN `alert.ack`. MUTATION : `AA2_ACK_ZERO_ATTESTE` (204 et un maillon pour zéro ligne).
    #[tokio::test]
    async fn aa2_acquitter_une_alerte_absente_rend_404_nomme_sans_registre() {
        let (st, _tmp) = aa2_etat("ack-absente");
        let (statut, _, v) = aa2_acquitter(&st, 987_654).await;
        assert_eq!(statut, 404, "aucune alerte ne porte cet identifiant : 404, jamais un 204 attesté : {v}");
        assert_eq!(v["error"], json!(CAUSE_ALERTE_INTROUVABLE), "le 404 est nommé : {v}");
        assert_eq!(aa2_compte(&st, AA2_MAILLONS_ACK), 0, "rien n'a été acquitté : le registre n'en porte rien");
    }

    /// CONTRÔLE : registre sain, `204` SANS corps, alerte `ack` par `analyste`, un maillon `#id by analyste`.
    /// MUTATION : `AA2_ACK_AVEU_SANS_PANNE` (le nominal sert l'aveu).
    #[tokio::test]
    async fn aa2_acquitter_une_alerte_reste_un_204_sans_corps_et_un_maillon() {
        let (st, _tmp) = aa2_etat("ack-sain");
        let id = aa2_alerte(&st);
        let (statut, octets, v) = aa2_acquitter(&st, id).await;
        assert_eq!(statut, 204, "acquittement attesté : 204 inchangé : {v}");
        assert!(octets.is_empty(), "aucun corps, donc aucun aveu : {:?}", String::from_utf8_lossy(&octets));
        assert_eq!(aa2_statut_de_l_alerte(&st, id), ("ack".to_string(), Some("analyste".to_string())));
        let detail: String = st.db.lock().query_row("SELECT detail FROM ledger WHERE kind='alert.ack'", [], |r| r.get(0)).unwrap();
        assert_eq!(detail, format!("#{id} by analyste"), "le maillon dit l'alerte et l'auteur, comme avant");
    }

    /// CE QU'IL TIENT : registre hors d'atteinte, l'alerte EST acquittée (pas d'annulation) et la route rend `200`
    /// `{"ok":true,"registre_sans_maillon":"<CAUSE_GESTE_SANS_TRACE> (<cause>)"}`, jamais un 204 muet.
    /// MUTATION : `AA2_ACK_MAILLON_JETE` (204 servi sur un maillon refusé).
    #[tokio::test]
    async fn aa2_acquitter_sans_maillon_reste_fait_et_l_avoue() {
        let (st, _tmp) = aa2_etat("ack-registre");
        let id = aa2_alerte(&st);
        aa2_sql(&st, &format!("CREATE TRIGGER aa2_ledger_refuse BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, '{AA2_MOTEUR_REGISTRE}'); END;"));
        let (statut, _, v) = aa2_acquitter(&st, id).await;
        assert_eq!(statut, 200, "acquittement fait sans trace : 200 qui l'avoue, ni 204 ni 5xx : {v}");
        assert_eq!(v.get("ok"), Some(&json!(true)), "le geste a eu lieu : {v}");
        let aveu = v[CLE_REGISTRE_SANS_MAILLON].as_str().unwrap_or_else(|| panic!("l'aveu est porté : {v}"));
        assert!(aveu.starts_with(CAUSE_GESTE_SANS_TRACE), "l'aveu d'un GESTE fait sans trace : {aveu}");
        assert!(aveu.ends_with(&format!(" ({CAUSE_MAILLON_NON_ECRIT})")) && !aveu.contains(AA2_MOTEUR_REGISTRE), "INVERSÉ NOMMÉMENT par P10.29-l (vague AM) : l'aveu porte la phrase fixe du maillon non écrit, jamais le texte du moteur : {aveu}");
        assert_eq!(aa2_statut_de_l_alerte(&st, id).0, "ack", "l'acquittement n'est pas annulé");
        assert_eq!(aa2_compte(&st, AA2_MAILLONS_ACK), 0, "fixture : aucun maillon n'est entré");
    }

    /// CE QU'IL TIENT : écriture refusée par la base, `503` dont l'erreur est EXACTEMENT
    /// `CAUSE_ACQUITTEMENT_DE_L_ALERTE_NON_ECRIT` (la cause du moteur va au journal seul), avec l'identifiant de
    /// corrélation ; l'alerte reste `new`, rien au registre. L'ouverture n'est pas celle que la console lit comme
    /// « AUCUNE alerte acquittée » (`ACQUITTEMENT NON ENREGISTRÉ`). MUTATIONS : `AA2_ACK_ERR_NU` (500 sans corps),
    /// `AA2_ACK_CAUSE_EXPOSEE` (la cause du moteur dans le corps).
    #[tokio::test]
    async fn aa2_acquitter_une_alerte_que_la_base_refuse_rend_503_nomme() {
        let (st, _tmp) = aa2_etat("ack-ecriture");
        let id = aa2_alerte(&st);
        aa2_sql(&st, &format!("CREATE TRIGGER aa2_alerte_refuse BEFORE UPDATE ON alert BEGIN SELECT RAISE(ABORT, '{AA2_MOTEUR_ALERTE}'); END;"));
        let (statut, octets, v) = aa2_acquitter(&st, id).await;
        assert_eq!(statut, 503, "écriture refusée : 503 nommé : {:?}", String::from_utf8_lossy(&octets));
        assert_eq!(v["error"], json!(CAUSE_ACQUITTEMENT_DE_L_ALERTE_NON_ECRIT), "la cause servie est la phrase nommée, seule : {v}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "le 5xx porte son identifiant de corrélation : {v}");
        assert!(!String::from_utf8_lossy(&octets).contains("hors d atteinte"), "la cause du moteur ne sort pas : {v}");
        assert!(!CAUSE_ACQUITTEMENT_DE_L_ALERTE_NON_ECRIT.starts_with("ACQUITTEMENT NON ENREGISTR"), "ouverture distincte de l'acquittement global");
        assert_eq!(aa2_statut_de_l_alerte(&st, id), ("new".to_string(), None), "l'alerte garde son état");
        assert_eq!(aa2_compte(&st, AA2_MAILLONS_ACK), 0, "rien n'est attesté");
    }

    /// CE QU'IL TIENT : `sla_policy_upsert` refuse une priorité hors 1..4 et une cible nulle par `400` NOMMÉS,
    /// distincts, sans rien écrire. MUTATIONS : `AA2_SLA_PRIORITE_NUE`, `AA2_SLA_CIBLE_NUE` (400 sans corps).
    #[tokio::test]
    async fn aa2_upsert_de_politique_refuse_par_400_nommes() {
        let (st, _tmp) = aa2_etat("sla-upsert");
        let hors = json!({ "name": "P0", "priority": 0, "ack_target_s": 60, "resolve_target_s": 600 });
        let (statut, _, v) = aa2_reponse(sla_policy_upsert(State(st.clone()), Extension(aa2_utilisateur("editor")), Json(hors)).await).await;
        assert_eq!(statut, 400, "priorité hors bornes : 400 : {v}");
        assert_eq!(v["error"], json!(CAUSE_POLITIQUE_SLA_PRIORITE_HORS_BORNES), "le 400 dit la priorité : {v}");
        let nulle = json!({ "name": "P2", "priority": 2, "ack_target_s": 0, "resolve_target_s": 600 });
        let (statut, _, v) = aa2_reponse(sla_policy_upsert(State(st.clone()), Extension(aa2_utilisateur("editor")), Json(nulle)).await).await;
        assert_eq!(statut, 400, "cible nulle : 400 : {v}");
        assert_eq!(v["error"], json!(CAUSE_POLITIQUE_SLA_CIBLE_NULLE), "le 400 dit les cibles : {v}");
        assert_eq!(aa2_compte(&st, "SELECT COUNT(*) FROM sla_policy"), 0, "rien n'est écrit");
    }

    /// CE QU'IL TIENT : `sla_policy_delete` hors admin -> `403` nommé (la politique reste) ; identifiant absent -> `404`
    /// nommé, rien au registre. MUTATIONS : `AA2_SLA_403_NU`, `AA2_SLA_404_NU` (sans corps).
    #[tokio::test]
    async fn aa2_suppression_de_politique_refuse_par_403_et_404_nommes() {
        let (st, _tmp) = aa2_etat("sla-delete");
        aa2_sql(&st, "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,600,1,0,'root',0)");
        let pid = aa2_compte(&st, "SELECT id FROM sla_policy WHERE priority=1");
        let (statut, _, v) = aa2_reponse(sla_policy_delete(State(st.clone()), Extension(aa2_utilisateur("editor")), Path(pid)).await).await;
        assert_eq!(statut, 403, "hors admin : 403 : {v}");
        assert_eq!(v["error"], json!(CAUSE_SUPPRESSION_DE_POLITIQUE_SLA_RESERVEE), "le 403 est nommé : {v}");
        assert_eq!(aa2_compte(&st, "SELECT COUNT(*) FROM sla_policy"), 1, "la politique reste");
        let (statut, _, v) = aa2_reponse(sla_policy_delete(State(st.clone()), Extension(aa2_utilisateur("admin")), Path(pid + 9_999)).await).await;
        assert_eq!(statut, 404, "aucune politique : 404 : {v}");
        assert_eq!(v["error"], json!(CAUSE_POLITIQUE_SLA_INTROUVABLE), "le 404 est nommé : {v}");
        assert_eq!(aa2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='sla_policy.delete'"), 0, "rien n'est attesté");
    }

    /// CE QU'IL TIENT : `client_case_get` sur un identifiant absent rend `404` JSON `CAUSE_DOSSIER_CLIENT_INTROUVABLE`
    /// (c'était le texte `case introuvable`) ; contrôle : un dossier réel est servi en 200.
    /// MUTATION : `AA2_CLIENT_404_TEXTE`.
    #[tokio::test]
    async fn aa2_dossier_client_absent_rend_404_json_nomme() {
        let (st, _tmp) = aa2_etat("client");
        let au = aa2_utilisateur("admin");
        let id = with_write(&st, &au, |conn| dossier_seme(conn, "analyste", "Dossier client AA2", 2, "", None, 3));
        let (statut, _, v) = aa2_reponse(client_case_get(State(st.clone()), Extension(au.clone()), Path(id)).await).await;
        assert_eq!(statut, 200, "contrôle : un dossier réel est servi : {v}");
        let (statut, octets, v) = aa2_reponse(client_case_get(State(st.clone()), Extension(au.clone()), Path(id + 1_000_000)).await).await;
        assert_eq!(statut, 404, "absence établie : 404 : {:?}", String::from_utf8_lossy(&octets));
        assert_eq!(v["error"], json!(CAUSE_DOSSIER_CLIENT_INTROUVABLE), "le 404 est un JSON nommé : {:?}", String::from_utf8_lossy(&octets));
    }
}
