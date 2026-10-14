// LES DEUX COMPTES DE LA BASE DU PANNEAU SYSTÈME, ET L'ÉTAT DE LA DÉTECTION, AVOUENT LEURS LECTURES
// RATÉES (`P10.20-b`, hors handlers/ : metrics.rs).
//
// VU sur d8239ceb (metrics.rs) : `gather_json` lisait `events_1h` (somme d'`event_rollup` sur l'heure) et
// `alerts_open` (compte d'`alert` au statut `new`) par `unwrap_or(0)` — une table qui ne répond pas
// servait « Ingest / h 0 » et « Alertes ouvertes 0 » à la console, et `/metrics` publiait les deux séries
// à zéro ; le composant `detection` restait vert quand `rule` n'était pas lue (seule la clé
// `enabled_rules` disparaissait).
//
// Les lectures ratées sont fabriquées sans chronomètre, par un refus d'autorisation ciblé sur UNE table
// (même instrument que `sante_forwarder_et_regles_lectures_avouees.rs`) : un seul compte est aveuglé à la
// fois, l'autre doit rester lu à sa valeur. Les valeurs semées sont NON nulles et distinctes, pour qu'un
// compte figé à zéro ou recopié de l'autre rougisse.
//
// MUTATIONS QUI LES FONT ROUGIR (jouées sous variable d environnement en `cfg!(test)`, puis retirées du source) : `P7_EVENTS_ZERO`
// (`unwrap_or(0)` rétabli sur `events_1h`), `P7_ALERTS_ZERO` (idem sur `alerts_open`), `P7_DETECTION_VERT`
// (l'état de `detection` ne descend plus quand `rule` n'est pas lue), `P7_PROM_LU` (la jauge de
// lisibilité dit « lu » sur un compte non lu).
//
// CE QU'ILS NE TIENNENT PAS : le rendu console (témoin 142 du harnais ESM) ; la forme d'une interruption
// en cours de lecture (un compte est une ligne unique : prépa ou pas, rien de partiel) ; le bundle de
// diagnostic (`handlers/system.rs`, tenu ailleurs).

fn p7c_refuser_la_table(conn: &Connection, table: &'static str) {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
        AuthAction::Read { table_name, .. } if table_name == table => Authorization::Deny,
        _ => Authorization::Allow,
    }));
}
fn p7c_tout_permettre(conn: &Connection) {
    use rusqlite::hooks::{AuthContext, Authorization};
    conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
}

/// Sept événements dans l'heure (5 + 2, deux seaux), un hors fenêtre ; trois alertes `new`, une close.
const P7C_EVENEMENTS: i64 = 7;
const P7C_ALERTES: i64 = 3;
fn p7c_semer(conn: &Connection) {
    let t = now();
    conn.execute("INSERT INTO event_rollup(bucket,source,severity,action,n) VALUES(?1,'p7c-a',0,'',5)", params![t - 60]).unwrap();
    conn.execute("INSERT INTO event_rollup(bucket,source,severity,action,n) VALUES(?1,'p7c-b',0,'',2)", params![t - 120]).unwrap();
    conn.execute("INSERT INTO event_rollup(bucket,source,severity,action,n) VALUES(?1,'p7c-c',0,'',40)", params![t - 7200]).unwrap();
    for (i, statut) in ["new", "new", "new", "closed"].iter().enumerate() {
        conn.execute(
            "INSERT INTO alert(ts,rule,severity,title,status) VALUES(?1,'rule.p7c',2,?2,?3)",
            params![1000 + i as i64, format!("p7c-{i}"), statut],
        )
        .unwrap();
    }
}

fn p7c_mesurer(conn: &Connection) -> (Value, String) {
    let spool = crate::tmp_possede::TmpPossede::neuf("p7c-spool");
    let v = crate::handlers::system::VersionDeSchema::Lue(1);
    let j = crate::gather_json(conn, spool.to_str().unwrap(), "p7c-comptes", &v, 80);
    let p = crate::gather_prom(conn, spool.to_str().unwrap(), "p7c-comptes", &v, 80);
    (j, p)
}
fn p7c_serie(prom: &str, nom: &str) -> Option<String> {
    prom.lines().find_map(|l| l.strip_prefix(&format!("{nom} ")).map(str::to_string))
}

fn p7c_avoue(objet: &Value, cle: &str, quoi: &str) {
    assert!(objet.get(cle).is_none(), "{cle} non lu : la clé est ABSENTE, jamais 0 — {objet}");
    assert_eq!(objet[format!("{cle}_verdict")], crate::mesure_environnement::VERDICT_ILLISIBLE, "{objet}");
    assert_eq!(objet[format!("{cle}_cause")], crate::mesure_environnement::CAUSE_SOURCE_ILLISIBLE, "{objet}");
    let d = objet[format!("{cle}_detail")].as_str().unwrap_or_default();
    assert!(d.contains("NON LU") && d.contains(quoi) && d.contains("ce n'est PAS"), "le détail nomme ce qui n'est pas lu : {d}");
}
fn p7c_lu_a_l_identique(objet: &Value, cle: &str, attendu: i64) {
    assert_eq!(objet[cle], json!(attendu), "{cle} lu : valeur à l'identique — {objet}");
    for suffixe in ["_verdict", "_cause", "_detail"] {
        assert!(objet.get(format!("{cle}{suffixe}")).is_none(), "nominal octet pour octet : aucune clé {cle}{suffixe} — {objet}");
    }
}

#[test]
fn p7c_nominal_les_deux_comptes_lus_a_l_identique() {
    let conn = test_db();
    p7c_semer(&conn);
    let (j, prom) = p7c_mesurer(&conn);
    p7c_lu_a_l_identique(&j["ingest"], "events_1h", P7C_EVENEMENTS);
    p7c_lu_a_l_identique(&j, "alerts_open", P7C_ALERTES);
    assert_eq!(p7c_serie(&prom, "plume_ingest_events_1h").as_deref(), Some("7"), "{prom}");
    assert_eq!(p7c_serie(&prom, "plume_alerts_open").as_deref(), Some("3"), "{prom}");
    assert!(prom.contains("plume_ingest_events_1h_lisible{cause=\"aucune\"} 1"), "{prom}");
    assert!(prom.contains("plume_alerts_open_lisible{cause=\"aucune\"} 1"), "{prom}");
}

#[test]
fn p7c_vrai_zero_lu_reste_un_zero() {
    // Base vide : zéro LU n'est pas un aveu (une version qui avouerait toujours passerait les autres).
    let conn = test_db();
    let (j, prom) = p7c_mesurer(&conn);
    p7c_lu_a_l_identique(&j["ingest"], "events_1h", 0);
    p7c_lu_a_l_identique(&j, "alerts_open", 0);
    assert_eq!(p7c_serie(&prom, "plume_alerts_open").as_deref(), Some("0"), "{prom}");
    assert!(prom.contains("plume_alerts_open_lisible{cause=\"aucune\"} 1"), "{prom}");
}

#[test]
fn p7c_event_rollup_illisible_seul_events_1h_avoue_alertes_lues() {
    let conn = test_db();
    p7c_semer(&conn);
    p7c_refuser_la_table(&conn, "event_rollup");
    let (j, prom) = p7c_mesurer(&conn);
    p7c_tout_permettre(&conn);
    p7c_avoue(&j["ingest"], "events_1h", "event_rollup");
    p7c_lu_a_l_identique(&j, "alerts_open", P7C_ALERTES);
    assert_eq!(p7c_serie(&prom, "plume_ingest_events_1h"), None, "série de valeur ABSENTE, jamais 0 : {prom}");
    assert!(prom.contains("plume_ingest_events_1h_lisible{cause=\"source_illisible\"} 0"), "{prom}");
    assert_eq!(p7c_serie(&prom, "plume_alerts_open").as_deref(), Some("3"), "{prom}");
    assert!(prom.contains("plume_alerts_open_lisible{cause=\"aucune\"} 1"), "{prom}");
}

#[test]
fn p7c_alert_illisible_seul_alerts_open_avoue_ingest_lu() {
    let conn = test_db();
    p7c_semer(&conn);
    p7c_refuser_la_table(&conn, "alert");
    let (j, prom) = p7c_mesurer(&conn);
    p7c_tout_permettre(&conn);
    p7c_avoue(&j, "alerts_open", "alert");
    p7c_lu_a_l_identique(&j["ingest"], "events_1h", P7C_EVENEMENTS);
    assert_eq!(p7c_serie(&prom, "plume_alerts_open"), None, "série de valeur ABSENTE, jamais 0 : {prom}");
    assert!(prom.contains("plume_alerts_open_lisible{cause=\"source_illisible\"} 0"), "{prom}");
    assert_eq!(p7c_serie(&prom, "plume_ingest_events_1h").as_deref(), Some("7"), "{prom}");
    assert!(prom.contains("plume_ingest_events_1h_lisible{cause=\"aucune\"} 1"), "{prom}");
}

fn p7c_detection(conn: &Connection) -> Value {
    let spool = crate::tmp_possede::TmpPossede::neuf("p7c-sante-spool");
    let recente = FraicheurDesTicks { regles: now(), rollups: now() };
    let v = crate::metrics::component_health_avec_pertes(
        conn,
        spool.to_str().unwrap(),
        "p7c-detection",
        80,
        recente,
        &crate::metrics::PertesDAcces::aucune(),
    );
    v.into_iter()
        .find(|c| c["component"] == crate::bilan_de_tick::COMPOSANT_DETECTION)
        .expect("composant detection")
}

#[test]
fn p7c_regles_non_lues_detection_jaune_jamais_rouge() {
    let conn = test_db();
    let lu = p7c_detection(&conn);
    let etat_lu = lu["state"].as_str().unwrap().to_string();
    assert!(lu.get("enabled_rules_verdict").is_none(), "nominal : aucun verdict servi — {lu}");
    assert!(!lu["detail"].as_str().unwrap().contains("règles actives"), "nominal : aucun aveu — {lu}");
    p7c_refuser_la_table(&conn, "rule");
    let non_lu = p7c_detection(&conn);
    p7c_tout_permettre(&conn);
    let etat = non_lu["state"].as_str().unwrap();
    // Jaune, jamais rouge : seul un état DÉJÀ rouge pour une autre raison le reste.
    let attendu = if etat_lu == "red" { "red" } else { "yellow" };
    assert_eq!(etat, attendu, "règles non lues : le composant descend au jaune (lu : {etat_lu}) — {non_lu}");
    let d = non_lu["detail"].as_str().unwrap();
    assert!(d.contains("nombre de règles actives NON LU") && d.contains("ce n'est PAS « zéro règle active »"), "la phrase du composant nomme la lecture : {d}");
    p7c_avoue(&non_lu, "enabled_rules", "règles actives");
}
