// =====================================================================================
// `P10.7-g` (lot 102) — UNE CAUSE JETÉE PAR LE MOTEUR DE REQUÊTE N'EST PLUS UNE ABSENCE.
//
// Le compte total de la route de requête rendait `-1` (« ? » dans la console) sur tout échec — budget dépassé,
// annulation, SQL refusé, tâche interrompue — sans sa cause, ce qui se lisait comme « trop grand pour compter » ;
// l'union des clés de labels Prometheus servait les clés fixes comme l'union établie quand l'échantillon ne
// se lisait pas. La cause voyage : `total_error` à côté de `-1`, et un avertissement qui dit l'union non établie.
// =====================================================================================

#[test]
fn p10_7g_un_total_non_etabli_porte_sa_cause_et_moins_un_reste_le_mot_du_contrat() {
    use crate::handlers::query::total_lu;
    let (n, cause) = total_lu(Ok(Ok(json!({ "rows": [[42]] }))));
    assert_eq!((n, cause), (42, None), "un compte lu est un nombre, sans cause");
    let (n, cause) = total_lu(Ok(Ok(json!({ "rows": [] }))));
    assert_eq!(n, -1);
    assert!(cause.as_deref().unwrap_or("").starts_with("total NON ÉTABLI"), "un compte sans ligne est dit non établi : {cause:?}");
    let (n, cause) = total_lu(Ok(Err("budget dépassé".to_string())));
    assert_eq!(n, -1, "« -1 » reste le mot du contrat");
    assert!(cause.as_deref().unwrap_or("").contains("budget dépassé"), "la cause du moteur voyage : {cause:?}");
}

#[tokio::test]
async fn p10_7g_un_echantillon_de_labels_non_lu_ne_se_sert_pas_comme_lunion_etablie() {
    use axum::response::IntoResponse;
    let (st, _p) = sp_state("cm-labels");
    let au = sp_au("adm", "admin");
    let lire = |r: Response| async move {
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null)
    };
    let avant = lire(prom_labels(State(st.clone()), Extension(au.clone())).await.into_response()).await;
    assert_eq!(avant["status"], json!("success"), "{avant}");
    assert!(avant.get("warnings").map(|w| w.as_array().map(|a| a.iter().all(|x| !x.as_str().unwrap_or("").contains("NON LU"))).unwrap_or(true)).unwrap_or(true), "table présente : aucun aveu de lecture ratée : {avant}");
    with_write(&st, &au, |conn| conn.execute_batch("ALTER TABLE metric RENAME TO metric_hors_d_atteinte;").expect("la fixture peut renommer la table"));
    let apres = lire(prom_labels(State(st.clone()), Extension(au.clone())).await.into_response()).await;
    let avert = apres["warnings"].as_array().cloned().unwrap_or_default();
    assert!(avert.iter().any(|w| w.as_str().unwrap_or("").contains("échantillon de labels NON LU")), "l'union non établie est dite : {apres}");
    assert!(apres["data"].as_array().map(|a| a.iter().any(|x| x == "__name__")).unwrap_or(false), "les clés fixes restent servies : {apres}");
}
