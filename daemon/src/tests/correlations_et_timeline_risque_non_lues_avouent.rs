// =====================================================================================
// `P10.7-g` (lot 107) — DEUX ROUTES SERVIES DE DÉTECTION/RISQUE AVOUENT UNE LECTURE RATÉE.
//
// VU : `correlations_list` servait `{ correlations: [] }` sur une lecture ratée (`Err(_) => []`), indiscernable
// de « aucune corrélation » ; `risk_entity_timeline` servait `timeline: []` et `contributions: []` de la même
// façon. Deux parcours de la famille `P10.7-f/g` sur des routes SERVIES : ils lisent désormais EN BLOC et
// rendent `null` + une cause quand la lecture n'a pas pu se faire.
//
// CE QUE CES TÉMOINS JOUENT : la table est renommée sous les pieds du gestionnaire par la voie d'écriture
// (`P10.7-z` : cache de schéma du pool encore vrai à la préparation, échec au premier pas ; ou prépa à froid
// qui échoue — les deux voies rendent le même refus nommé), puis la route est rappelée.
// =====================================================================================

fn ct107_renommer(st: &AppState, au: &AuthUser, de: &str, vers: &str) {
    with_write(st, au, |conn| {
        conn.execute_batch(&format!("ALTER TABLE {de} RENAME TO {vers};")).expect("la fixture peut renommer la table")
    });
}

#[tokio::test]
async fn p10_7g_les_correlations_non_lues_ne_sont_pas_une_liste_vide() {
    let (st, _p) = sp_state("ct107-correlations");
    let au = sp_au("adm", "admin");
    let avant = correlations_list(State(st.clone()), Extension(au.clone())).await.0;
    assert!(avant.get("error").is_none() && avant["correlations"].is_array(), "table présente : liste servie, rien à avouer : {avant}");
    ct107_renommer(&st, &au, "correlation", "correlation_hors_d_atteinte");
    let apres = correlations_list(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(apres["correlations"], json!(null), "une lecture ratée n'est plus une liste vide : {apres}");
    assert!(apres["error"].as_str().unwrap_or("").contains("NON LUES"), "le refus est NOMMÉ : {apres}");
    assert_eq!(apres["lecture_non_faite"], json!(true), "l'aveu marque la non-lecture : {apres}");
}

#[tokio::test]
async fn p10_7g_la_timeline_de_risque_non_lue_dit_sa_cause() {
    let (st, _p) = sp_state("ct107-rba");
    let au = sp_au("adm", "admin");
    let etype = "ip".to_string();
    let entity = "198.51.100.7".to_string();
    let avant = risk_entity_timeline(State(st.clone()), Extension(au.clone()), Path((etype.clone(), entity.clone()))).await.0;
    assert!(avant["timeline"].is_array() && avant.get("timeline_error").is_none(), "table présente : timeline servie : {avant}");
    ct107_renommer(&st, &au, "risk_event", "risk_event_hors_d_atteinte");
    let apres = risk_entity_timeline(State(st.clone()), Extension(au.clone()), Path((etype, entity))).await.0;
    assert_eq!(apres["timeline"], json!(null), "timeline non lue = null, jamais [] : {apres}");
    assert!(apres["timeline_error"].as_str().unwrap_or("").contains("NON LUE"), "la cause de la timeline est nommée : {apres}");
    assert_eq!(apres["contributions"], json!(null), "contributions non lues = null : {apres}");
    assert!(apres["contributions_error"].as_str().unwrap_or("").contains("NON LUES"), "la cause des contributions est nommée : {apres}");
    assert_eq!(apres["lecture_non_faite"], json!(true), "l'aveu marque la non-lecture : {apres}");
}
