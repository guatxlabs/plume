// =====================================================================================
// `P10.7-g` (lot 100) — UNE FLOTTE DONT L'ENRÔLEMENT OU LES DÉCLARATIONS N'ONT PAS ÉTÉ LUS LE DIT.
//
// Le balayage de flotte lisait les jetons d'agent et les déclarations d'hôtes en meilleur effort : une lecture
// ratée faisait passer chaque hôte pour « non enrôlé » et pour « personne n'a rien dit », sans un mot, et la
// flotte ainsi lue partait en cache pour tout le TTL. Le sens était SÛR (plus d'alertes, jamais moins) — mais ce
// n'était pas une observation. Le corps le dit, `enrolled` reste `null`, et rien n'est mis en cache.
//
// CE QUE CES TÉMOINS JOUENT : un hôte réel, une table renommée sous les pieds du gestionnaire (voie de `P10.7-z`),
// la route appelée deux fois de suite pour prouver que la flotte partielle n'est pas mise en cache.
// =====================================================================================

fn fp_renommer(st: &AppState, au: &AuthUser, de: &str, vers: &str) {
    with_write(st, au, |conn| conn.execute_batch(&format!("ALTER TABLE {de} RENAME TO {vers};")).expect("la fixture peut renommer la table"));
}

fn fp_hote(st: &AppState, au: &AuthUser, nom: &str) {
    with_write(st, au, |conn| {
        conn.execute("INSERT INTO host_rollup(host,env_id,last_ts,first_ts,sig_total,sig_hot) VALUES(?1,'prod',?2,?2,3,1)", params![nom, now()])
            .expect("la fixture écrit un hôte");
    });
}

#[tokio::test]
async fn p10_7g_un_enrolement_non_lu_ne_fait_pas_passer_les_hotes_pour_non_enroles() {
    let (st, _p) = sp_state("fp-enrol");
    let au = sp_au("adm", "admin");
    let q = || Query(std::collections::HashMap::<String, String>::new());
    fp_hote(&st, &au, "srv-fp");
    fp_renommer(&st, &au, "token", "token_hors_d_atteinte");
    let premier = fleet(State(st.clone()), Extension(au.clone()), q()).await.0;
    let err = premier["error"].as_str().unwrap_or("").to_string();
    assert!(err.starts_with("flotte partiellement NON LUE") && err.contains("enrôlement"), "la lecture ratée est nommée : {premier}");
    let hotes = premier["hosts"].as_array().cloned().unwrap_or_default();
    assert!(!hotes.is_empty() && hotes.iter().all(|h| h["enrolled"].is_null()), "les hôtes sont servis et leur enrôlement n'est ni vrai ni faux : {premier}");
    let second = fleet(State(st.clone()), Extension(au.clone()), q()).await.0;
    assert!(second["error"].as_str().unwrap_or("").contains("enrôlement"), "une flotte partiellement non lue n'est PAS mise en cache : le second appel avoue encore : {second}");
}

#[tokio::test]
async fn p10_7g_des_declarations_dhotes_non_lues_sont_dites_et_le_silence_alerte_encore() {
    let q = || Query(std::collections::HashMap::<String, String>::new());
    // INSTRUMENT sur un état DISTINCT : le cache de flotte est clé par base et une flotte LUE y reste pour tout le TTL —
    // jouer « avant » puis « après » sur la même base servirait la flotte lue depuis le cache (c'est le contrat SWR).
    let (st_temoin, _pt) = sp_state("fp-decl-temoin");
    let au = sp_au("adm", "admin");
    fp_hote(&st_temoin, &au, "srv-fp2");
    let avant = fleet(State(st_temoin.clone()), Extension(au.clone()), q()).await.0;
    assert!(avant.get("error").is_none(), "tables présentes : rien à avouer : {avant}");
    let (st, _p) = sp_state("fp-decl");
    fp_hote(&st, &au, "srv-fp2");
    fp_renommer(&st, &au, "host_settings", "host_settings_hors_d_atteinte");
    let apres = fleet(State(st.clone()), Extension(au.clone()), q()).await.0;
    let err = apres["error"].as_str().unwrap_or("").to_string();
    assert!(err.starts_with("flotte partiellement NON LUE") && err.contains("déclarations"), "la lecture ratée est nommée : {apres}");
    let hotes = apres["hosts"].as_array().cloned().unwrap_or_default();
    assert!(!hotes.is_empty() && hotes.iter().all(|h| h["attente"] == json!("non_declare") && h["alerte_si_muet"] == json!(true)), "le sens sûr est conservé : non déclaré, le silence alerte : {apres}");
}
