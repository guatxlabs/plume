// =====================================================================================
// `P10.7-g` (lot 93) — UN DOSSIER NON LU N'EST NI « INTROUVABLE » NI UNE LISTE VIDE.
//
// La fiche de dossier rendait 404 « incident introuvable » dès qu'une lecture échouait — la ligne de temps
// comprise —, c'est-à-dire qu'elle INVENTAIT une absence ; la liste paginée servait `{ cases: [], total: 0 }`
// sur un compte ou des lignes illisibles, c'est-à-dire « aucun dossier ». Les deux lectures sont typées :
// une absence ÉTABLIE reste un 404, tout échec de lecture est un 5xx nommé ou une liste NON ÉTABLIE.
//
// CE QUE CES TÉMOINS JOUENT : un dossier RÉEL créé par le semeur de production, la route appelée avant et après
// qu'une table soit renommée sous les pieds du gestionnaire (voie de `P10.7-z`), et un identifiant inexistant
// pour tenir le 404 là où il est vrai.
// =====================================================================================

async fn dn_corps(r: Response) -> (u16, Value) {
    let statut = r.status().as_u16();
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    (statut, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

fn dn_renommer(st: &AppState, au: &AuthUser, de: &str, vers: &str) {
    with_write(st, au, |conn| conn.execute_batch(&format!("ALTER TABLE {de} RENAME TO {vers};")).expect("la fixture peut renommer la table"));
}

#[tokio::test]
async fn p10_7g_une_fiche_de_dossier_non_lue_est_un_5xx_nomme_et_une_absence_reste_un_404() {
    use axum::response::IntoResponse;
    let (st, _p) = sp_state("dn-fiche");
    let au = sp_au("adm", "admin");
    let id = with_write(&st, &au, |conn| case_create_row(conn, "adm", "Dossier lu", 2, "", None, 3));
    let (statut, corps) = dn_corps(case_get(State(st.clone()), Extension(au.clone()), Path(id)).await.into_response()).await;
    assert_eq!(statut, 200, "dossier réel, tables présentes : servi : {corps}");
    assert_eq!(corps["title"], json!("Dossier lu"));
    let (statut, _) = dn_corps(case_get(State(st.clone()), Extension(au.clone()), Path(id + 1_000_000)).await.into_response()).await;
    assert_eq!(statut, 404, "un identifiant qui n'existe pas est une absence ÉTABLIE : 404");
    dn_renommer(&st, &au, "incident_item", "incident_item_hors_d_atteinte");
    let (statut, corps) = dn_corps(case_get(State(st.clone()), Extension(au.clone()), Path(id)).await.into_response()).await;
    assert_eq!(statut, 500, "la fiche existe mais sa ligne de temps est illisible : ce n'est PAS « introuvable » : {corps}");
    assert!(corps["error"].as_str().unwrap_or("").starts_with("dossier NON LU"), "le 5xx nomme sa cause : {corps}");
}

#[tokio::test]
async fn p10_7g_une_liste_de_dossiers_non_lue_est_dite_non_etablie() {
    use axum::response::IntoResponse;
    let (st, _p) = sp_state("dn-liste");
    let au = sp_au("adm", "admin");
    with_write(&st, &au, |conn| { case_create_row(conn, "adm", "Dossier compté", 2, "", None, 3); });
    let q = || Query(std::collections::HashMap::<String, String>::new());
    let (_, avant) = dn_corps(cases_list(State(st.clone()), Extension(au.clone()), q()).await.into_response()).await;
    assert!(avant.get("error").is_none(), "table présente : rien à avouer : {avant}");
    assert_eq!(avant["total"], json!(1), "un dossier compté : {avant}");
    dn_renommer(&st, &au, "incident", "incident_hors_d_atteinte");
    let (_, apres) = dn_corps(cases_list(State(st.clone()), Extension(au.clone()), q()).await.into_response()).await;
    assert_eq!(apres["cases"], json!([]), "la forme est conservée : {apres}");
    assert_eq!(apres["total"], Value::Null, "un compte qui n'a pas abouti rend `null`, jamais un zéro rassurant : {apres}");
    assert_eq!(apres["error"], json!(crate::handlers::liste_bornee::CAUSE_LISTE_ILLISIBLE), "la liste dit qu'elle n'est pas établie : {apres}");
}
