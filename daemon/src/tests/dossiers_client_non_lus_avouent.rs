// =====================================================================================
// `P10.7-g` (lot 95) — LE PORTAIL CLIENT ET LES MÉTRIQUES DE DOSSIERS DISENT CE QUI N'A PAS ÉTÉ LU.
//
// La liste client servait `{ cases: [], total: 0 }` sur un compte ou des lignes illisibles ; la fiche client
// rendait 404 « case introuvable » dès qu'une lecture échouait, ligne de temps comprise ; le tableau de bord
// MTTA/MTTR servait des zéros et des ventilations vides sur chacune de ses huit lectures ratées — « aucun
// dossier résolu, aucun retard, aucune violation », le corps le plus rassurant qui soit.
//
// CE QUE CES TÉMOINS JOUENT : un dossier RÉEL créé par le semeur de production, la route appelée avant et après
// qu'une table soit renommée sous les pieds du gestionnaire (voie de `P10.7-z`), sans requête entre les deux,
// et un identifiant inexistant pour tenir le 404 là où il est vrai.
// =====================================================================================

async fn dc_corps(r: Response) -> (u16, Value) {
    let statut = r.status().as_u16();
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    (statut, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

fn dc_renommer(st: &AppState, au: &AuthUser, de: &str, vers: &str) {
    with_write(st, au, |conn| conn.execute_batch(&format!("ALTER TABLE {de} RENAME TO {vers};")).expect("la fixture peut renommer la table"));
}

fn dc_q() -> Query<std::collections::HashMap<String, String>> {
    Query(std::collections::HashMap::new())
}

#[tokio::test]
async fn p10_7g_une_liste_client_non_lue_est_dite_non_etablie() {
    use axum::response::IntoResponse;
    use crate::handlers::caseops::client_cases_list;
    let (st, _p) = sp_state("dc-liste");
    let au = sp_au("adm", "admin");
    with_write(&st, &au, |conn| { case_create_row(conn, "adm", "Dossier client", 2, "", None, 3); });
    let (_, avant) = dc_corps(client_cases_list(State(st.clone()), Extension(au.clone()), dc_q()).await.into_response()).await;
    assert!(avant.get("error").is_none(), "table présente : rien à avouer : {avant}");
    assert_eq!(avant["total"], json!(1), "un dossier compté : {avant}");
    dc_renommer(&st, &au, "incident", "incident_hors_d_atteinte");
    let (_, apres) = dc_corps(client_cases_list(State(st.clone()), Extension(au.clone()), dc_q()).await.into_response()).await;
    assert_eq!(apres["cases"], json!([]), "la forme est conservée : {apres}");
    assert_eq!(apres["total"], Value::Null, "un compte qui n'a pas abouti rend `null`, jamais un zéro rassurant : {apres}");
    assert_eq!(apres["error"], json!(crate::handlers::liste_bornee::CAUSE_LISTE_ILLISIBLE), "la liste dit qu'elle n'est pas établie : {apres}");
}

#[tokio::test]
async fn p10_7g_une_fiche_client_non_lue_est_un_5xx_nomme_et_une_absence_reste_un_404() {
    use axum::response::IntoResponse;
    use crate::handlers::caseops::client_case_get;
    let (st, _p) = sp_state("dc-fiche");
    let au = sp_au("adm", "admin");
    let id = with_write(&st, &au, |conn| case_create_row(conn, "adm", "Dossier client lu", 2, "", None, 3));
    let (statut, corps) = dc_corps(client_case_get(State(st.clone()), Extension(au.clone()), Path(id)).await.into_response()).await;
    assert_eq!(statut, 200, "dossier réel, tables présentes : servi : {corps}");
    assert!(corps.is_object() && corps.get("error").is_none(), "une fiche lue ne porte aucun aveu : {corps}");
    let (statut, _) = dc_corps(client_case_get(State(st.clone()), Extension(au.clone()), Path(id + 1_000_000)).await.into_response()).await;
    assert_eq!(statut, 404, "un identifiant qui n'existe pas est une absence ÉTABLIE : 404");
    dc_renommer(&st, &au, "incident_item", "incident_item_hors_d_atteinte");
    let (statut, corps) = dc_corps(client_case_get(State(st.clone()), Extension(au.clone()), Path(id)).await.into_response()).await;
    assert_eq!(statut, 500, "la fiche existe mais sa ligne de temps est illisible : ce n'est PAS « introuvable » : {corps}");
    assert!(corps["error"].as_str().unwrap_or("").starts_with("dossier NON LU"), "le 5xx nomme sa cause : {corps}");
}

#[tokio::test]
async fn p10_7g_des_metriques_de_dossiers_non_lues_sont_dites_non_etablies() {
    use axum::response::IntoResponse;
    use crate::handlers::caseops::case_metrics;
    let (st, _p) = sp_state("dc-metriques");
    let au = sp_au("adm", "admin");
    with_write(&st, &au, |conn| { case_create_row(conn, "adm", "Dossier mesuré", 2, "", None, 3); });
    let (_, avant) = dc_corps(case_metrics(State(st.clone()), Extension(au.clone()), dc_q()).await.into_response()).await;
    assert!(avant.get("error").is_none() && avant.get("non_etablis").is_none(), "tables présentes : rien à avouer : {avant}");
    assert_eq!(avant["overall"]["open_now"], json!(1), "un dossier ouvert compté : {avant}");
    dc_renommer(&st, &au, "incident", "incident_hors_d_atteinte");
    let (_, apres) = dc_corps(case_metrics(State(st.clone()), Extension(au.clone()), dc_q()).await.into_response()).await;
    assert!(apres["error"].as_str().unwrap_or("").starts_with("métriques NON ÉTABLIES"), "le corps dit ce qui n'est pas établi : {apres}");
    assert_eq!(
        apres["non_etablis"],
        json!(["sample", "resolved", "open_now", "overdue_now", "ack_breaches", "resolve_breaches", "by_assignee", "by_severity"]),
        "les huit lectures ratées sont nommées, dans l'ordre de lecture : {apres}"
    );
    assert_eq!(apres["overall"]["open_now"], Value::Null, "un compte qui n'a pas abouti rend `null`, jamais 0 : {apres}");
    assert_eq!(apres["overall"]["resolved"], Value::Null, "idem pour les résolus : {apres}");
    assert_eq!(apres["by_assignee"], json!([]), "la forme est conservée : {apres}");
    assert!(apres.get("sample_truncated").is_some(), "les aveux de coupe restent posés : {apres}");
}
