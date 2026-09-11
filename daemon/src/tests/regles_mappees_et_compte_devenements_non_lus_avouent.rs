// =====================================================================================
// `P10.7-g` (lot 99) — LE COMPTE D'ÉVÉNEMENTS ET LES RÈGLES MAPPÉES SONT LUS OU NON LUS.
//
// Le compte d'événements de la vue d'ensemble valait 0 sur un COUNT raté ET ce zéro se mettait en cache pour la
// durée du TTL : un zéro rassurant servi à tout le monde. Les règles mappées de la posture de conformité rendaient
// une carte vide sur une table `rule` illisible — « aucune règle ne couvre aucun contrôle ». Les deux lectures
// sont typées : le compte est nommé dans `non_etablis` (jamais mis en cache), la carte rejoint la cause.
//
// CE QUE CES TÉMOINS JOUENT : une table renommée sous les pieds du gestionnaire (voie de `P10.7-z`), AVANT tout
// appel pour le compte (cache froid), deux appels de suite pour prouver que l'échec n'est pas mis en cache.
// =====================================================================================

async fn rc_corps(r: Response) -> Value {
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    serde_json::from_slice(&b).unwrap_or(Value::Null)
}

fn rc_q() -> Query<std::collections::HashMap<String, String>> {
    Query(std::collections::HashMap::new())
}

fn rc_non_etablis(corps: &Value) -> Vec<String> {
    corps["non_etablis"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default()
}

#[tokio::test]
async fn p10_7g_un_compte_devenements_non_lu_est_nomme_et_jamais_mis_en_cache() {
    let (st, _p) = sp_state("rc-events");
    let au = sp_au("adm", "admin");
    with_write(&st, &au, |conn| conn.execute_batch("ALTER TABLE event RENAME TO event_hors_d_atteinte;").expect("la fixture peut renommer la table"));
    let premier = overview(State(st.clone()), Extension(au.clone())).await.0;
    assert!(rc_non_etablis(&premier).iter().any(|s| s == "events"), "un COUNT raté est nommé, jamais servi comme 0 établi : {premier}");
    assert!(premier["error"].as_str().unwrap_or("").contains("NON ÉTABLI"), "le corps porte la cause : {premier}");
    let second = overview(State(st.clone()), Extension(au.clone())).await.0;
    assert!(rc_non_etablis(&second).iter().any(|s| s == "events"), "l'échec n'est PAS mis en cache : le second appel avoue encore : {second}");
}

#[tokio::test]
async fn p10_7g_des_regles_mappees_non_lues_rejoignent_la_cause_de_la_posture() {
    use axum::response::IntoResponse;
    let (st, _p) = sp_state("rc-regles");
    let au = sp_au("adm", "admin");
    let avant = rc_corps(compliance_posture(State(st.clone()), Extension(au.clone()), rc_q()).await.into_response()).await;
    assert!(avant.get("error").is_none(), "tables présentes : rien à avouer : {avant}");
    with_write(&st, &au, |conn| conn.execute_batch("ALTER TABLE rule RENAME TO rule_hors_d_atteinte;").expect("la fixture peut renommer la table"));
    let apres = rc_corps(compliance_posture(State(st.clone()), Extension(au.clone()), rc_q()).await.into_response()).await;
    assert!(apres["error"].as_str().unwrap_or("").contains("règles mappées NON LUES"), "une carte vide n'est pas servie comme « aucune règle ne couvre » : {apres}");
}
