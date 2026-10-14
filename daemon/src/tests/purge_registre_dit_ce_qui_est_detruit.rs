// =====================================================================================
// `P10.32-e` (restes) — PURGE : LE REGISTRE DIT CE QUI EST DÉTRUIT, SOURCE PAR SOURCE ET EN NOMBRE.
//
// LE DÉFAUT (relu sur 55c7ecbb) : `purge_inscribe` écrit au registre un détail qui porte `rows` et `per_source`
// (ventilation par source de la mesure confirmée), et un message SOC « PURGE D'ÉVÉNEMENTS : N ligne(s)
// détruite(s) … ». Seul `rows` du détail était lu par un témoin (`purge_is_inscribed_in_the_hash_chained_ledger`) ;
// la ventilation inscrite et le compte du message ne l'étaient par aucun. Un registre qui aurait inscrit une
// ventilation vide, ou les lignes d'une source au nom d'une autre, ou un message décalé, passait tous les témoins
// — alors que `P10.32-e` vient précisément de garantir que l'ensemble supprimé est l'ensemble confirmé.
//
// CE QUE CES TÉMOINS JUGENT (aucun code de production touché) :
//  (a) COMPENSATION : purge `env=prod` sur trois sources de comptes différents (3, 2, 1), plus des lignes hors
//      périmètre. Le `per_source` du détail inscrit est égal, source par source, à la ventilation du PLAN et au
//      nombre RÉELLEMENT supprimé par source (compté avant/après) ; `rows` du détail égale la somme et le reçu ;
//      le message de l'événement SOC porte le même compte, et son `fields` le même détail ; ni le registre ni le
//      SOC ne portent le contenu purgé (message, hôte) ;
//  (b) contre-épreuve à une seule source (`source=flux-a`, deux envs) : ventilation à une entrée, compte 4 partout ;
//  (c) contre-épreuve refusée (`count_mismatch`, trigger `RAISE(IGNORE)` sur une ligne) : aucune ligne de
//      registre de purge, aucun événement SOC de purge, rien supprimé.
// MUTATIONS (jouées dans `purge_inscribe` sous variable de mutation, retirées du source) : `Q8_VENT_VIDE`
// (ventilation inscrite vide : a, b rouges), `Q8_VENT_AUTRE` (chaque compte inscrit au nom de la source
// suivante : a rouge), `Q8_MSG_PLUS_UN` (compte du message + 1 : a, b rouges), `Q8_ROWS_FAUX` (`rows` du détail
// + 1 : a, b rouges).
// CE QUE CE LOT NE TIENT PAS : l'étape de PRÉPARATION de la ventilation (`prepare` et liaison) n'a toujours aucun
// témoin d'échec (le balayage par `progress_handler` ne l'atteint pas) ; le registre inscrit la mesure CONFIRMÉE,
// égale à ce qui est supprimé parce que `purge_delete_rows` la relit sous verrou — si cette relecture disparaissait,
// (a) resterait vert (aucune écriture concurrente ici) : c'est le témoin de
// `purge_ensemble_confirme_relu_dans_la_transaction.rs` qui la garde.
// =====================================================================================

/// Ligne purgeable (`origin=''`). Le message porte un contenu qui ne doit jamais atteindre le registre.
fn prd_ins(c: &Connection, ts: i64, source: &str, env: &str) {
    c.execute(
        "INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id) \
         VALUES(?1,?2,'test',1,'contenu-purge-confidentiel-7c1e','hote-confidentiel-7c1e',?3,'','')",
        params![ts, source, env],
    )
    .unwrap();
}

/// Trois sources du périmètre, comptes 3/2/1, et deux lignes hors périmètre (autre env, hors fenêtre).
fn prd_base() -> Connection {
    let c = test_db();
    for i in 0..3 {
        prd_ins(&c, 1_000 + i, "flux-a", "prod");
    }
    for i in 0..2 {
        prd_ins(&c, 1_100 + i, "flux-b", "prod");
    }
    prd_ins(&c, 1_200, "flux-c", "prod");
    prd_ins(&c, 1_000, "flux-a", "staging");
    prd_ins(&c, 5_000, "flux-b", "prod");
    c
}

fn prd_scope(sel: (&str, &str)) -> PurgeScope {
    let v = vec![(sel.0.to_string(), sel.1.to_string())];
    purge_scope_from_args(&v, "0", "2000", now()).expect("périmètre valide")
}

/// Lignes purgeables par source, toutes envs et fenêtres confondues.
fn prd_par_source(c: &Connection) -> std::collections::BTreeMap<String, i64> {
    let mut st = c.prepare("SELECT source, COUNT(*) FROM event WHERE origin='' GROUP BY source").unwrap();
    st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn prd_registre(c: &Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1", params![PURGE_LEDGER_KIND], |r| r.get(0)).unwrap()
}

fn prd_soc_purges(c: &Connection) -> Vec<(String, String)> {
    let mut st = c
        .prepare(
            "SELECT message, COALESCE(fields,'') FROM event WHERE source='plume-config' AND origin='daemon' \
             AND message LIKE 'PURGE D''ÉVÉNEMENTS%' ORDER BY id",
        )
        .unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<Result<_, _>>().unwrap()
}

/// Ventilation d'un détail inscrit, en table source -> lignes. Exige la forme (tableau d'objets).
fn prd_ventilation(d: &Value, quoi: &str) -> std::collections::BTreeMap<String, i64> {
    let entrees = d["per_source"].as_array().unwrap_or_else(|| panic!("{quoi} : `per_source` absent ou non tableau : {d}"));
    let mut m = std::collections::BTreeMap::new();
    for e in entrees {
        let s = e["source"].as_str().unwrap_or_else(|| panic!("{quoi} : entrée sans source : {e}")).to_string();
        let n = e["rows"].as_i64().unwrap_or_else(|| panic!("{quoi} : entrée sans compte : {e}"));
        assert!(m.insert(s.clone(), n).is_none(), "{quoi} : source `{s}` inscrite deux fois : {d}");
    }
    m
}

/// Compte porté par le message SOC « PURGE D'ÉVÉNEMENTS : N ligne(s) détruite(s) … », lu exactement.
fn prd_compte_du_message(m: &str) -> i64 {
    let reste = m.strip_prefix("PURGE D'ÉVÉNEMENTS : ").unwrap_or_else(|| panic!("préfixe du message : {m}"));
    let (n, suite) = reste.split_once(' ').unwrap_or_else(|| panic!("compte du message : {m}"));
    assert!(suite.starts_with("ligne(s) détruite(s)"), "forme du message : {m}");
    n.parse().unwrap_or_else(|_| panic!("compte du message non numérique : {m}"))
}

/// Joue la purge du périmètre et juge le registre contre le plan ET contre ce que la base a supprimé.
fn prd_purger_et_juger(sel: (&str, &str), attendu: &[(&str, i64)]) {
    let quoi = format!("purge {}={}", sel.0, sel.1);
    let c = prd_base();
    let plan = purge_plan(&c, prd_scope(sel)).expect("plan nominal");
    let du_plan: std::collections::BTreeMap<String, i64> = plan.per_source().iter().cloned().collect();
    let attendu: std::collections::BTreeMap<String, i64> = attendu.iter().map(|(s, n)| (s.to_string(), *n)).collect();
    assert_eq!(du_plan, attendu, "{quoi} : instrument — ventilation du plan");
    let jeton = plan.digest().to_string();
    let avant = prd_par_source(&c);
    let registre_avant = prd_registre(&c);
    let recu = purge_confirm_and_apply(&c, prd_scope(sel), &jeton, "api:alice", "demande d'effacement 7").expect("purge");
    let apres = prd_par_source(&c);
    let supprime: std::collections::BTreeMap<String, i64> = avant
        .iter()
        .map(|(s, n)| (s.clone(), n - apres.get(s).copied().unwrap_or(0)))
        .filter(|(_, n)| *n != 0)
        .collect();
    assert_eq!(supprime, attendu, "{quoi} : instrument — ce que la base a supprimé, par source");

    assert_eq!(prd_registre(&c), registre_avant + 1, "{quoi} : une inscription");
    let detail: String = c
        .query_row(
            "SELECT COALESCE(detail,'') FROM ledger WHERE kind=?1 ORDER BY id DESC LIMIT 1",
            params![PURGE_LEDGER_KIND],
            |r| r.get(0),
        )
        .unwrap();
    let d: Value = serde_json::from_str(&detail).expect("détail JSON");
    let inscrite = prd_ventilation(&d, &quoi);
    assert_eq!(inscrite, du_plan, "{quoi} : ventilation inscrite = ventilation du plan, source par source");
    assert_eq!(inscrite, supprime, "{quoi} : ventilation inscrite = lignes supprimées, source par source");
    let somme: i64 = supprime.values().sum();
    assert_eq!(d["rows"].as_i64(), Some(somme), "{quoi} : `rows` du détail = somme des lignes supprimées");
    assert_eq!(recu.rows_deleted, somme, "{quoi} : reçu = somme");

    let soc = prd_soc_purges(&c);
    assert_eq!(soc.len(), 1, "{quoi} : un événement SOC de purge : {soc:?}");
    let (message, fields) = &soc[0];
    assert_eq!(prd_compte_du_message(message), somme, "{quoi} : le message SOC porte le compte supprimé : {message}");
    let f: Value = serde_json::from_str(fields).expect("fields SOC JSON");
    assert_eq!(f, d, "{quoi} : le SOC porte le même détail que le registre");
    for fuite in ["contenu-purge-confidentiel-7c1e", "hote-confidentiel-7c1e"] {
        assert!(!detail.contains(fuite) && !message.contains(fuite) && !fields.contains(fuite), "{quoi} : `{fuite}` fuit");
    }
}

/// (a) Trois sources de comptes différents : le registre dit, source par source, ce qui est détruit.
#[test]
fn prd_registre_ventile_et_compte_ce_qui_est_detruit() {
    prd_purger_et_juger(("env", "prod"), &[("flux-a", 3), ("flux-b", 2), ("flux-c", 1)]);
}

/// (b) Une seule source, deux envs (3 lignes `prod`, 1 `staging`) : ventilation à une entrée, compte 4.
#[test]
fn prd_registre_a_une_source() {
    prd_purger_et_juger(("source", "flux-a"), &[("flux-a", 4)]);
}

/// (c) Purge refusée (`count_mismatch`) : aucune ligne de registre ni événement SOC de purge, rien supprimé.
#[test]
fn prd_purge_refusee_n_inscrit_rien() {
    let c = prd_base();
    let plan = purge_plan(&c, prd_scope(("env", "prod"))).expect("plan nominal");
    let jeton = plan.digest().to_string();
    let avant = prd_par_source(&c);
    let id: i64 = c.query_row("SELECT MIN(id) FROM event WHERE source='flux-b'", [], |r| r.get(0)).unwrap();
    c.execute_batch(&format!(
        "CREATE TRIGGER prd_bloque BEFORE DELETE ON event BEGIN SELECT RAISE(IGNORE) WHERE OLD.id={id}; END;"
    ))
    .unwrap();
    let e = purge_confirm_and_apply(&c, prd_scope(("env", "prod")), &jeton, "t", "m").unwrap_err();
    assert_eq!(purge_refusal_code(&e), "count_mismatch", "refus : {e}");
    assert_eq!(prd_registre(&c), 0, "aucune inscription au registre");
    assert!(prd_soc_purges(&c).is_empty(), "aucun événement SOC de purge");
    assert_eq!(prd_par_source(&c), avant, "rien supprimé");
}
