// =====================================================================================
// `P10.7-g` (lot 91) — TROIS CORPS RASSURANTS AVOUENT.
//
// La garde des lectures non faites nommait ces trois sites comme les plus graves de sa jambe B, et le plan de
// descente écrit dans son en-tête en donnait le geste. VU : la vue d'ensemble servait cinq zéros (posture « OK »)
// quand rien n'avait été lu ; la liste des environnements servait « [prod, 0] » sur un rollup illisible ; la
// flotte servait `{ hosts: [] }` sur un `host_rollup` illisible ET METTAIT CE VIDE EN CACHE pour tout le TTL.
//
// CE QUE CES TÉMOINS JOUENT : la table est renommée sous les pieds du gestionnaire par la voie d'écriture, sans
// aucune requête entre la page « avant » et la page « après » (c'est la voie mesurée par `P10.7-z` : cache de
// schéma du pool encore vrai à la préparation, échec rendu au premier pas). Pour la flotte, le témoin prouve en
// plus que le vide n'a PAS été mis en cache : la table revient, un hôte est écrit, et la page suivante le sert.
// =====================================================================================

fn cr_renommer(st: &AppState, au: &AuthUser, de: &str, vers: &str) {
    with_write(st, au, |conn| {
        conn.execute_batch(&format!("ALTER TABLE {de} RENAME TO {vers};")).expect("la fixture peut renommer la table")
    });
}

#[tokio::test]
async fn p10_7g_la_vue_densemble_dit_les_comptes_non_etablis() {
    let (st, _p) = sp_state("cr-overview");
    let au = sp_au("adm", "admin");
    let avant = overview(State(st.clone()), Extension(au.clone())).await.0;
    assert!(avant.get("error").is_none(), "tables présentes : rien à avouer : {avant}");
    cr_renommer(&st, &au, "incident", "incident_hors_d_atteinte");
    let apres = overview(State(st.clone()), Extension(au.clone())).await.0;
    let cause = apres["error"].as_str().unwrap_or("");
    assert!(cause.starts_with("compte NON ÉTABLI"), "deux comptes ne sont plus lisibles : le corps doit le dire, or : {apres}");
    let non_etablis: Vec<String> = apres["non_etablis"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
    assert_eq!(non_etablis, vec!["cases_open".to_string(), "cases_closed".to_string()], "les comptes non établis sont NOMMÉS, dans l'ordre de lecture : {apres}");
    assert_eq!(apres["open_alerts"], avant["open_alerts"], "un compte encore lisible reste servi tel quel : {apres}");
}

#[tokio::test]
async fn p10_7g_les_environnements_disent_que_prod_est_un_repli_quand_le_rollup_est_illisible() {
    let (st, _p) = sp_state("cr-environments");
    let au = sp_au("adm", "admin");
    let avant = environments(State(st.clone()), Extension(au.clone())).await.0;
    assert!(avant.get("error").is_none(), "rollup présent : rien à avouer : {avant}");
    cr_renommer(&st, &au, "event_rollup", "event_rollup_hors_d_atteinte");
    let apres = environments(State(st.clone()), Extension(au.clone())).await.0;
    assert!(apres["error"].as_str().unwrap_or("").starts_with("liste NON LUE"), "rollup illisible : le corps doit le dire : {apres}");
    assert_eq!(apres["environments"][0]["env"], json!("prod"), "le repli « prod » reste servi (le sélecteur veut une valeur) : {apres}");
}

#[tokio::test]
async fn p10_7g_une_flotte_non_lue_est_dite_et_nest_jamais_mise_en_cache() {
    let (st, _p) = sp_state("cr-fleet");
    let au = sp_au("adm", "admin");
    let q = || Query(std::collections::HashMap::<String, String>::new());
    // Le cache est GLOBAL, clé = chemin de base : cette fixture a le sien, et il est froid.
    cr_renommer(&st, &au, "host_rollup", "host_rollup_hors_d_atteinte");
    let non_lue = fleet(State(st.clone()), Extension(au.clone()), q()).await.0;
    assert_eq!(non_lue["error"], json!(FLOTTE_NON_LUE), "hôtes illisibles : le corps doit le dire : {non_lue}");
    assert_eq!(non_lue["hosts"], json!([]), "la forme est conservée : {non_lue}");
    // La table revient et un hôte y est écrit : si le vide avait été mis en cache, la page suivante servirait
    // encore « aucun hôte » pendant tout le TTL — c'est exactement le défaut fermé.
    cr_renommer(&st, &au, "host_rollup_hors_d_atteinte", "host_rollup");
    with_write(&st, &au, |conn| {
        conn.execute("INSERT INTO host_rollup(host,env_id,last_ts,first_ts,sig_total,sig_hot) VALUES('srv-cr',\'prod\',?1,?1,3,1)", params![now()])
            .expect("la fixture écrit un hôte");
    });
    let lue = fleet(State(st.clone()), Extension(au.clone()), q()).await.0;
    assert!(lue.get("error").is_none(), "hôtes lisibles : rien à avouer : {lue}");
    assert_eq!(lue["hosts"].as_array().map(|a| a.len()).unwrap_or(0), 1, "le vide non lu n'a PAS été mis en cache : l'hôte écrit ensuite est servi : {lue}");
}
