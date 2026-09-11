// =====================================================================================
// `P10.7-g` (lot 97) — « JE N'AI PAS PU REGARDER » N'EST NI « JAMAIS VU » NI « MUET ».
//
// La dette était déclarée dans `sondes.rs` : `.ok()` confondait « la table n'a rien » et « je n'ai pas pu
// regarder ». Sur le panneau des intégrations, une sonde non lue passait « inconnu » (jamais vue), une page
// d'hôtes non lue « aucun hôte », un verdict de flotte non lu `null` sans cause, et une fraîcheur de pipeline
// non lue rendait MUETS tous les capteurs événementiels. Au tick de battement de cœur, la même confusion
// levait des alertes sur une base non lue et RÉSOLVAIT l'épisode ouvert d'un capteur réellement mort.
//
// CE QUE CES TÉMOINS JOUENT : une base réelle, une table renommée sous les pieds du lecteur (voie de
// `P10.7-z`), le panneau avant et après, et le tick de battement de cœur avec un épisode ouvert.
// =====================================================================================

#[test]
fn p10_7g_les_hotes_et_la_flotte_non_lus_sont_nommes_et_les_capteurs_restent_juges() {
    let (st, _p) = sp_state("cn-hotes");
    let au = sp_au("adm", "admin");
    let avant = compute_integrations(&st.db_path);
    assert!(avant.get("error").is_none() && avant.get("non_lus").is_none(), "tables présentes : rien à avouer : {avant}");
    assert!(avant["flotte"].is_object(), "instrument : le verdict de flotte est rendu sur une base lisible : {avant}");
    assert_eq!(avant["hosts_total"], json!(0), "instrument : un total LU vaut 0 sur une base vide : {avant}");
    with_write(&st, &au, |conn| conn.execute_batch("ALTER TABLE host_rollup RENAME TO host_rollup_hors_d_atteinte;").expect("la fixture peut renommer la table"));
    let apres = compute_integrations(&st.db_path);
    assert_eq!(apres["flotte"], Value::Null, "un verdict de flotte non lu est `null` : {apres}");
    assert_eq!(apres["hosts_total"], Value::Null, "un total d'hôtes non lu est `null`, jamais 0 : {apres}");
    assert_eq!(apres["hosts"], json!([]), "la forme est conservée : {apres}");
    let nl: Vec<String> = apres["non_lus"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
    assert!(nl.iter().any(|s| s.starts_with("hôtes : ")) && nl.iter().any(|s| s.starts_with("flotte : ")), "les deux lectures ratées sont nommées : {apres}");
    assert!(apres["error"].as_str().unwrap_or("").starts_with("lectures NON FAITES"), "le corps porte la cause : {apres}");
    let capteurs = apres["collectors"].as_array().cloned().unwrap_or_default();
    assert!(!capteurs.is_empty() && capteurs.iter().all(|c| c["status"] != json!("non_lu")), "les sondes restent jugées quand seul l'inventaire est illisible : {apres}");
}

#[test]
fn p10_7g_un_capteur_non_lu_nest_ni_jamais_vu_ni_muet() {
    let (st, _p) = sp_state("cn-capteurs");
    let au = sp_au("adm", "admin");
    let avant = compute_integrations(&st.db_path);
    let capteurs = avant["collectors"].as_array().cloned().unwrap_or_default();
    assert!(!capteurs.is_empty() && capteurs.iter().all(|c| c["status"] == json!("inconnu")), "instrument : base vide, toutes les sondes sont « jamais vues » : {avant}");
    with_write(&st, &au, |conn| conn.execute_batch("ALTER TABLE snapshot RENAME TO snapshot_hors_d_atteinte;").expect("la fixture peut renommer la table"));
    let apres = compute_integrations(&st.db_path);
    let capteurs = apres["collectors"].as_array().cloned().unwrap_or_default();
    assert!(
        !capteurs.is_empty() && capteurs.iter().all(|c| c["status"] == json!("non_lu") && c["last_seen"].is_null()),
        "pipeline illisible : aucune sonde ne peut être jugée, toutes sont « non_lu » (ni « inconnu » ni « muet ») : {apres}"
    );
    let nl: Vec<String> = apres["non_lus"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
    assert!(nl.iter().any(|s| s.starts_with("pipeline : ")), "la lecture ratée est nommée : {apres}");
}

#[test]
fn p10_7g_un_battement_de_coeur_aveugle_ne_leve_ni_ne_resout_rien_et_le_dit() {
    let conn = test_db();
    let now_ts = now();
    let id = COLLECTORS[0].0;
    let ouvrir = |conn: &Connection| {
        conn.execute(
            "INSERT INTO alert(ts,rule,severity,title,detail,dedup,sources,basis) VALUES(?1,?2,2,'Capteur muet : fixture','fixture',?3,'',?4)",
            params![now_ts - 60, format!("heartbeat.{id}"), format!("hb-{id}"), crate::fondement::Fondement::BattementDeCoeur.mot()],
        )
        .expect("la fixture ouvre un épisode");
    };
    let ouverts = |conn: &Connection| -> i64 {
        conn.query_row("SELECT COUNT(*) FROM alert WHERE rule LIKE 'heartbeat.%' AND status IN ('new','ack')", [], |r| r.get(0)).unwrap()
    };
    // INSTRUMENT : sur une base LISIBLE et vide, le tick résout l'épisode (capteur jamais vu -> rien à constater).
    ouvrir(&conn);
    let db = Arc::new(Mutex::new(conn));
    let lisible = check_heartbeats(&db);
    assert!(matches!(lisible, crate::mesure_environnement::Mesure::Lue(_)), "instrument : un tick sur une base lisible se dit lu : {lisible:?}");
    assert_eq!(ouverts(&db.lock()), 0, "instrument : le tick lisible résout l'épisode d'un capteur jamais vu");
    // LE TICK AVEUGLE : l'épisode est rouvert, le pipeline devient illisible ; rien n'est levé, rien n'est résolu.
    {
        let conn = db.lock();
        ouvrir(&conn);
        conn.execute_batch("ALTER TABLE snapshot RENAME TO snapshot_hors_d_atteinte").unwrap();
    }
    let aveugle = check_heartbeats(&db);
    match &aveugle {
        crate::mesure_environnement::Mesure::Illisible { detail, .. } => {
            assert!(detail.contains("capteurs : pipeline : "), "le bilan nomme ce qui n'a pas été lu : {detail}");
        }
        autre => panic!("un tick qui n'a pas pu lire le pipeline se dit aveugle, il a rendu {autre:?}"),
    }
    assert_eq!(ouverts(&db.lock()), 1, "ni levée (aucune alerte neuve) ni résolution (l'épisode ouvert reste ouvert)");
}
