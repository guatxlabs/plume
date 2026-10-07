// =====================================================================================
// `P10.20-b` (rang deux, famille hors `handlers/`) — LA SIMULATION DE PURGE NE REND PLUS UN ZÉRO POUR UNE
// LECTURE NON FAITE.
//
// LE DÉFAUT : `purge_uncovered` lisait ses quatre comptes « non couverts » (alertes, métriques, captures
// d'état dans la fenêtre, instantanés de dashboard partageables) par `.unwrap_or(0)`. Une lecture ratée
// faisait dire à la simulation de la fonctionnalité la plus destructrice du dépôt « rien d'autre dans la
// fenêtre : 0 » — fausse assurance de confidentialité, puisque ces lignes RESTENT après la purge.
//
// CE QUE CES TÉMOINS JUGENT : pour CHAQUE famille, la table rendue hors d'atteinte (renommée) fait servir
// `null` dans le JSON avec la cause sous `not_covered.not_read.<clé>`, et « NON LU » dans le texte, jamais
// un zéro ; le jeton est toujours rendu (la simulation n'est pas refusée). Le témoin inverse fixe le chemin
// nominal : comptes lus inchangés, aucune clé `not_read`. Mutation par famille (jouée, retirée du source) :
// le repli `Lue(0)` restauré sur l'erreur de CETTE famille fait rougir son témoin, et lui seul (ligne du `null`).
// =====================================================================================

fn pnl_db_peuplee() -> Connection {
    let c = test_db();
    c.execute(
        "INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id) \
         VALUES(1000,'flux-de-test','test',1,'x','h1','prod','','')",
        [],
    )
    .unwrap();
    c.execute("INSERT INTO alert(ts,rule,severity,title) VALUES(1000,'r',3,'t')", []).unwrap();
    c.execute("INSERT INTO metric(ts,name,value) VALUES(1000,'m',1.0)", []).unwrap();
    c.execute("INSERT INTO snapshot(ts,kind,data) VALUES(1000,'k','{}')", []).unwrap();
    c.execute("INSERT INTO dashboard_snapshot(token,data) VALUES('jeton-a','{}')", []).unwrap();
    c.execute("INSERT INTO dashboard_snapshot(token,data) VALUES('jeton-b','{}')", []).unwrap();
    c
}

fn pnl_plan(c: &Connection) -> PurgePlan {
    let v = vec![("source".to_string(), "flux-de-test".to_string())];
    let scope = purge_scope_from_args(&v, "0", "2000", now()).expect("périmètre valide");
    purge_plan(c, scope).expect("la simulation n'est PAS refusée pour une famille non couverte non lue")
}

/// Rend `table` hors d'atteinte, simule, et juge l'aveu de la famille `cle` dans le JSON et le texte.
fn pnl_juger_famille_non_lue(table: &str, cle: &str, libelle_texte: &str) {
    let c = pnl_db_peuplee();
    // Contrôle positif dans le même corps : AVANT le retrait, la famille est lue et non nulle.
    let avant = purge_plan_json(&pnl_plan(&c));
    assert!(avant["not_covered"][cle].as_i64().unwrap_or(0) >= 1, "contrôle positif {cle} : {avant}");
    assert!(avant["not_covered"].get("not_read").is_none(), "nominal : pas d'aveu : {avant}");

    let jeton_avant = pnl_plan(&c).digest().to_string();
    c.execute_batch(&format!("ALTER TABLE {table} RENAME TO {table}_hors_d_atteinte;")).unwrap();
    let p = pnl_plan(&c);
    let j = purge_plan_json(&p);
    let nc = &j["not_covered"];
    assert!(nc.get(cle).is_some(), "la clé {cle} reste PRÉSENTE : {j}");
    assert!(nc[cle].is_null(), "{cle} non lue -> null, jamais 0 : {j}");
    let cause = nc["not_read"][cle].as_str().unwrap_or("");
    // La cause nomme la table PAR LE CODE (préfixe « lecture de `<table>` »), pas seulement par le message du
    // moteur : sur une vraie panne (base verrouillée, corrompue) le moteur ne nomme pas la table.
    let prefixe = format!("lecture de `{table}`");
    assert!(cause.contains(&prefixe), "la cause porte « {prefixe} » : {j}");
    assert!(cause.contains("no such table"), "la cause porte l'erreur du moteur : {j}");
    // Le jeton ne dépend pas des comptes non couverts : identique avant et après le retrait de la table.
    assert_eq!(p.digest(), jeton_avant, "purge_digest inchangé par une famille non lue");
    // Les autres familles restent lues.
    for autre in ["alerts_in_window", "metrics_in_window", "snapshots_in_window", "dashboard_snapshots"] {
        if autre != cle {
            assert!(nc[autre].as_i64().unwrap_or(0) >= 1, "{autre} reste lue : {j}");
            assert!(nc["not_read"].get(autre).is_none(), "{autre} non avouée à tort : {j}");
        }
    }

    let t = purge_plan_text(&p);
    // Métriques et captures partagent UNE ligne (« métriques : … / captures d'état : … ») : juger le SEGMENT
    // de la famille, pas la ligne, sinon une permutation des deux rendus passe.
    let ligne = t.lines().find(|l| l.contains(libelle_texte)).unwrap_or("");
    let segment = ligne.split(" / ").find(|s| s.contains(libelle_texte)).unwrap_or("");
    assert!(segment.contains("NON LU"), "texte : le segment « {libelle_texte} » dit NON LU : {t}");
    assert!(segment.contains(&prefixe), "texte : la cause porte « {prefixe} » : {segment}");
    for autre in ligne.split(" / ").filter(|s| !s.contains(libelle_texte)) {
        assert!(!autre.contains("NON LU"), "texte : l'autre famille de la ligne reste lue : {ligne}");
    }
}

#[test]
fn purge_simulation_alertes_non_lues_avouees_jamais_zero() {
    pnl_juger_famille_non_lue("alert", "alerts_in_window", "alertes dans la fenêtre");
}

#[test]
fn purge_simulation_metriques_non_lues_avouees_jamais_zero() {
    pnl_juger_famille_non_lue("metric", "metrics_in_window", "métriques :");
}

#[test]
fn purge_simulation_captures_non_lues_avouees_jamais_zero() {
    pnl_juger_famille_non_lue("snapshot", "snapshots_in_window", "captures d'état :");
}

#[test]
fn purge_simulation_instantanes_dashboard_non_lus_avoues_jamais_zero() {
    pnl_juger_famille_non_lue("dashboard_snapshot", "dashboard_snapshots", "instantanés de dashboard");
}

/// Témoin INVERSE : tables lues -> comptes inchangés (`1` reste `1`, `2` reste `2`), aucune clé `not_read`,
/// aucun « NON LU » dans le texte.
#[test]
fn purge_simulation_tables_lues_comptes_inchanges_sans_aveu() {
    let c = pnl_db_peuplee();
    let p = pnl_plan(&c);
    let u = p.uncovered();
    assert_eq!(u.alerts_in_window, MesureNonCouverte::Lue(1));
    assert_eq!(u.metrics_in_window, MesureNonCouverte::Lue(1));
    assert_eq!(u.snapshots_in_window, MesureNonCouverte::Lue(1));
    assert_eq!(u.dashboard_snapshots, MesureNonCouverte::Lue(2));
    let j = purge_plan_json(&p);
    assert_eq!(j["not_covered"]["alerts_in_window"], 1);
    assert_eq!(j["not_covered"]["metrics_in_window"], 1);
    assert_eq!(j["not_covered"]["snapshots_in_window"], 1);
    assert_eq!(j["not_covered"]["dashboard_snapshots"], 2);
    assert!(j["not_covered"].get("not_read").is_none(), "chemin nominal sans aveu : {j}");
    assert!(!purge_plan_text(&p).contains("NON LU"));
}

/// BORD ZÉRO : fenêtre où les quatre familles sont VIDES. Un zéro LU est un zéro ÉTABLI : il sort `0` en
/// JSON (jamais `null`), aucune clé `not_read`, aucun « NON LU » dans le texte — sinon l'aveu s'afficherait
/// à chaque simulation sur une table vide et l'opérateur apprendrait à l'ignorer.
#[test]
fn purge_simulation_familles_vides_zero_etabli_sans_aveu() {
    let c = test_db();
    c.execute(
        "INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id) \
         VALUES(1000,'flux-de-test','test',1,'x','h1','prod','','')",
        [],
    )
    .unwrap();
    for t in ["alert", "metric", "snapshot", "dashboard_snapshot"] {
        let n: i64 = c.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "précondition : `{t}` vide");
    }
    let p = pnl_plan(&c);
    let u = p.uncovered();
    assert_eq!(u.alerts_in_window, MesureNonCouverte::Lue(0));
    assert_eq!(u.metrics_in_window, MesureNonCouverte::Lue(0));
    assert_eq!(u.snapshots_in_window, MesureNonCouverte::Lue(0));
    assert_eq!(u.dashboard_snapshots, MesureNonCouverte::Lue(0));
    let j = purge_plan_json(&p);
    for cle in ["alerts_in_window", "metrics_in_window", "snapshots_in_window", "dashboard_snapshots"] {
        assert_eq!(j["not_covered"][cle], json!(0), "{cle} : zéro établi -> 0, jamais null : {j}");
    }
    assert!(j["not_covered"].get("not_read").is_none(), "zéro lu : pas d'aveu : {j}");
    let t = purge_plan_text(&p);
    assert!(!t.contains("NON LU"), "zéro lu : pas de NON LU : {t}");
    assert!(t.contains("alertes dans la fenêtre : 0 "), "texte : alertes 0 : {t}");
    assert!(t.contains("métriques : 0 / captures d'état : 0 "), "texte : métriques et captures 0 : {t}");
    assert!(t.contains("instantanés de dashboard partageables : 0 "), "texte : instantanés 0 : {t}");
}
