// =====================================================================================
// `P10.20-l` (vague BD) — L'ÉCHEC D'UN RAPPORT PLANIFIÉ DÉCLENCHÉ À LA MAIN EST SERVI À LA VALEUR EXACTE.
//
// VU (re-mesuré sur la base) : le reste « le vieux témoin `p10_20w` reste en « non vide » » de `P10.20-l` désigne
// `p10_20w_run_echec_dit_si_l_erreur_est_consignee` (`rapport_planifie_marque_ecrite_ou_avouee.rs`), qui ne juge le
// corps du 400 de POST /api/scheduled-reports/{id}/run que par `!e.is_empty()` : un `error` remplacé par n'importe
// quelle phrase (le texte du moteur, une phrase d'absence) y restait vert. Le fichier qu'on désignait pour ce reste
// (`alerte_de_dead_man_ecrite_ou_avouee.rs`) ne porte AUCUNE assertion « non vide » : ses témoins comparent déjà des
// valeurs exactes (`Mesure::Lue(n)`, comptes, lignes de journal).
//
// CE QUE CES TÉMOINS JOUENT : la route par son gestionnaire (`report_run_now`, jeton du rôle le plus faible admis :
// editor), une requête GXQL que le compilateur de plume refuse, le corps 400 comparé EN ENTIER à une constante écrite
// ici (ensemble exact des clés, valeur de `error`), la même phrase relue dans `last_error` ; puis la consignation
// refusée par un déclencheur `RAISE(ABORT)` : même phrase servie, `marque_ecrite: false`, rien d'écrit.
// =====================================================================================
mod rapport_planifie_echec_servi_a_la_valeur_exacte {
    use super::*;

    const RPX_GXQL_CASSE: &str = "search | where (((";
    /// La phrase du compilateur de plume pour `RPX_GXQL_CASSE`, ÉCRITE ici (jamais relue de la production).
    const RPX_PHRASE_DU_COMPILATEUR: &str = r#"where : 'champ op valeur' attendu (ex: count > 5 ou src_ip =~ "^90\.")"#;
    const RPX_REFUS_ERREUR: &str = "CREATE TRIGGER rpx_err BEFORE UPDATE OF last_error ON scheduled_report \
         BEGIN SELECT RAISE(ABORT,'erreur refusee par le temoin rpx'); END;";

    fn rpx_base(tag: &str) -> (crate::tmp_possede::TmpDb, Connection, i64) {
        let path = crate::tmp_possede::TmpDb::neuf(&format!("rpx-{tag}"));
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        conn.execute("INSERT INTO dataset(id,name,soql) VALUES(51,'rpx-ds',?1)", params![RPX_GXQL_CASSE]).unwrap();
        conn.execute(
            "INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) VALUES(52,'rpx-n','temoin-rpx',1,'https://198.51.100.41/hook',0,'{}')",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO scheduled_report(id,name,dataset_id,notifier_id,interval_s) VALUES(53,'rpx-rapport',51,52,3600)", [])
            .unwrap();
        (path, conn, 53)
    }

    async fn rpx_run(tag: &str, declencheur: Option<&str>) -> (StatusCode, Value, i64, Option<String>) {
        use axum::response::IntoResponse;
        let (path, conn, id) = rpx_base(tag);
        if let Some(sql) = declencheur {
            conn.execute_batch(sql).unwrap();
        }
        let st = ds_file_state_sur(&path, conn);
        let au = AuthUser {
            name: "rpx-editeur".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        };
        let r = crate::handlers::scheduled_reports::report_run_now(State(st.clone()), Extension(au), axum::extract::Path(id))
            .await
            .into_response();
        let code = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps: Value = serde_json::from_slice(&b).unwrap_or(Value::Null);
        let (last_run, last_error): (i64, Option<String>) = st
            .db
            .lock()
            .query_row("SELECT last_run,last_error FROM scheduled_report WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        drop(path);
        (code, corps, last_run, last_error)
    }

    #[tokio::test]
    async fn bd5_echec_consigne_corps_entier_et_last_error_a_la_valeur_exacte() {
        let (code, c, last_run, last_error) = rpx_run("consigne", None).await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{c}");
        assert_eq!(c, json!({ "error": RPX_PHRASE_DU_COMPILATEUR, "marque_ecrite": true }), "corps entier du 400");
        assert!(last_run > 0, "échec consigné : last_run posé");
        assert_eq!(last_error.as_deref(), Some(RPX_PHRASE_DU_COMPILATEUR), "last_error porte la phrase servie, à l'octet");
    }

    #[tokio::test]
    async fn bd5_echec_consignation_refusee_meme_phrase_rien_d_ecrit() {
        let (code, c, last_run, last_error) = rpx_run("refus", Some(RPX_REFUS_ERREUR)).await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{c}");
        assert_eq!(c, json!({ "error": RPX_PHRASE_DU_COMPILATEUR, "marque_ecrite": false }), "corps entier du 400");
        assert_eq!((last_run, last_error), (0, None), "consignation refusée : rien d'écrit");
    }
}
