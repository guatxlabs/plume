// =====================================================================================
// `P10.7-g` (lot 94) — LE JOURNAL D'AUDIT ET LE MODE GLOBAL DISENT CE QUI N'A PAS ÉTÉ LU.
//
// La page du journal d'audit servait un compte de 0, « aucune entrée » et « rien hors de la fenêtre » quand ses
// lectures échouaient — sur un journal d'AUDIT, les trois zéros les plus rassurants qui soient ; le mode global
// servait « observe » sur toute lecture ratée, indiscernable de la valeur enregistrée. La page type ses trois
// lectures et le gestionnaire rend un 5xx nommé ; le mode garde son repli sûr et le dit.
// =====================================================================================

async fn jm_corps(r: Response) -> (u16, Value) {
    let statut = r.status().as_u16();
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    (statut, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

fn jm_renommer(st: &AppState, au: &AuthUser, de: &str, vers: &str) {
    with_write(st, au, |conn| conn.execute_batch(&format!("ALTER TABLE {de} RENAME TO {vers};")).expect("la fixture peut renommer la table"));
}

#[tokio::test]
async fn p10_7g_le_journal_daudit_non_lu_est_un_5xx_nomme_jamais_une_page_vide() {
    use axum::response::IntoResponse;
    let (st, _p) = sp_state("jm-journal");
    let au = sp_au("adm", "admin");
    let q = || Query(std::collections::HashMap::<String, String>::new());
    let (statut, avant) = jm_corps(ledger_get(State(st.clone()), Extension(au.clone()), q()).await.into_response()).await;
    assert_eq!(statut, 200, "journal lisible : la page est servie : {avant}");
    assert_eq!(avant["ok"], json!(true));
    jm_renommer(&st, &au, "ledger", "ledger_hors_d_atteinte");
    let (statut, apres) = jm_corps(ledger_get(State(st.clone()), Extension(au.clone()), q()).await.into_response()).await;
    assert_eq!(statut, 500, "journal illisible : aucune page n'est rendue, et le 5xx le dit : {apres}");
}

#[tokio::test]
async fn p10_7g_un_mode_non_lu_reste_observe_et_le_dit() {
    let (st, _p) = sp_state("jm-mode");
    let au = sp_au("adm", "admin");
    let avant = mode_get(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(avant["mode"], json!("observe"), "aucun mode posé : « observe » est ÉTABLI : {avant}");
    assert!(avant.get("error").is_none(), "un mode établi n'a rien à avouer : {avant}");
    jm_renommer(&st, &au, "meta", "meta_hors_d_atteinte");
    let apres = mode_get(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(apres["mode"], json!("observe"), "le repli reste le mode le plus sûr : {apres}");
    assert!(apres["error"].as_str().unwrap_or("").starts_with("mode NON LU"), "…et le corps dit que c'est un repli : {apres}");
}
