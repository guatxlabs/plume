// =====================================================================================
// `P10.7-g` (lot 98) — UN INVENTAIRE DE SOURCES NON LU N'EST PAS UNE INGESTION EN PANNE.
//
// L'inventaire servait `ok: true` et une liste vide quand les sources observées ne se lisaient pas, « rien de
// déclaré » quand les déclarations ne se lisaient pas, et — la fraîcheur du pipeline étant aplatie — une
// lecture ratée valait « pas frais » : la console peignait alors « Ingestion en panne — aucune donnée reçue
// récemment », une panne que personne n'avait observée. Les trois lectures sont typées ; la première qui
// échoue rend l'inventaire NON LU avec sa cause et `pipeline_fresh: null`.
//
// CE QUE CES TÉMOINS JOUENT : la route appelée avant et après qu'une table soit renommée sous les pieds du
// gestionnaire (voie de `P10.7-z`), une fois sur les sources observées, une fois sur le pipeline.
// =====================================================================================

async fn is_corps(r: Response) -> Value {
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    serde_json::from_slice(&b).unwrap_or(Value::Null)
}

async fn is_inventaire(st: &AppState, au: &AuthUser) -> Value {
    use axum::response::IntoResponse;
    is_corps(crate::handlers::sources::sources_inventory(State(st.clone()), Extension(au.clone())).await.into_response()).await
}

#[tokio::test]
async fn p10_7g_un_inventaire_de_sources_non_lu_nest_pas_une_ingestion_en_panne() {
    let (st, _p) = sp_state("is-observees");
    let au = sp_au("adm", "admin");
    let avant = is_inventaire(&st, &au).await;
    assert_eq!(avant["ok"], json!(true), "tables présentes : l'inventaire est lu : {avant}");
    assert!(avant.get("error").is_none() && avant["pipeline_fresh"].is_boolean(), "rien à avouer, la fraîcheur est dite : {avant}");
    with_write(&st, &au, |conn| conn.execute_batch("ALTER TABLE event_rollup RENAME TO event_rollup_hors_d_atteinte;").expect("la fixture peut renommer la table"));
    let apres = is_inventaire(&st, &au).await;
    assert_eq!(apres["ok"], json!(false), "un inventaire non lu n'est pas « ok » : {apres}");
    assert_eq!(apres["pipeline_fresh"], Value::Null, "la fraîcheur n'est pas dite : ni fraîche, ni en panne : {apres}");
    assert_eq!(apres["sources"], json!([]), "la forme est conservée : {apres}");
    assert!(apres["error"].as_str().unwrap_or("").starts_with("inventaire NON LU : sources observées"), "la cause est nommée : {apres}");
}

#[tokio::test]
async fn p10_7g_une_fraicheur_de_pipeline_non_lue_ne_dit_pas_lingestion_en_panne() {
    let (st, _p) = sp_state("is-pipeline");
    let au = sp_au("adm", "admin");
    let avant = is_inventaire(&st, &au).await;
    assert_eq!(avant["ok"], json!(true), "instrument : l'inventaire est lu avant la coupe : {avant}");
    with_write(&st, &au, |conn| conn.execute_batch("ALTER TABLE snapshot RENAME TO snapshot_hors_d_atteinte;").expect("la fixture peut renommer la table"));
    let apres = is_inventaire(&st, &au).await;
    assert_eq!(apres["ok"], json!(false), "{apres}");
    assert_eq!(apres["pipeline_fresh"], Value::Null, "une fraîcheur non lue n'est jamais servie « pas fraîche » : {apres}");
    assert!(apres["error"].as_str().unwrap_or("").starts_with("inventaire NON LU : pipeline"), "la cause nomme le pipeline : {apres}");
}
