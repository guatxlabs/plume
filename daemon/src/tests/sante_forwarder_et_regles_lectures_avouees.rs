// LA SANTÉ DU FORWARDER ET LE COMPTE DE RÈGLES AVOUENT LEURS LECTURES RATÉES (`P10.20-b`, hors handlers/).
//
// VU sur f54efa36 (metrics.rs) : `destination_health` rendait « idle, aucune destination configurée »
// quand `SELECT COUNT(*) FROM destination` échouait (l'absence de la table était DÉDUITE d'une erreur),
// et « green, N destination(s) OK » quand le compte des destinations EN ERREUR échouait
// (`unwrap_or(0)`) ; le composant `detection` servait `enabled_rules: 0` sur une lecture ratée de `rule`.
//
// Les lectures ratées sont fabriquées sans chronomètre : une interruption du PREMIER énoncé (rappel de
// progression) et des refus d'autorisation ciblés sur une table ou une colonne.
//
// MUTATIONS QUI LES FONT ROUGIR (jouées par `VERIF_MUT`, puis retirées du source) : `O7_PRESENCE_IDLE`
// (catalogue non lu -> idle), `O7_TOTAL_ZERO` (compte non lu -> 0), `O7_ERRORED_ZERO` (compte en erreur
// non lu -> 0), `O7_RULES_ZERO` (`enabled_rules` à 0 sur lecture ratée), `O7_JAUNE_VERT` (non lu -> vert) ;
// puis `O7_TOTAL_LABEL` (cause du total fusionnée avec celle du catalogue), `O7_TOTAL_FABRIQUE` (total
// non lu remplacé par 2), `O7_RULES_NOMINAL_ZERO` (`enabled_rules` à 0 après lecture réussie),
// `O7_ERRORED_FUITE` (le détail recopie `group_concat(last_error)` quand le compte en erreur échoue).
//
// CE QU'ILS NE TIENNENT PAS : `events_1h` et `alerts_open` de `gather_json` (lus par la console en
// `?? 0`, lot console à part) ; l'ÉTAT du composant `detection` quand `rule` n'est pas lue (inchangé :
// seule la clé disparaît, avec sa cause) ; aucun `enabled_rules_verdict` n'est servi (la console ne
// lit pas ce compte).

fn o7_refuser_la_lecture(conn: &Connection, table: &'static str, colonne: Option<&'static str>) {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
        AuthAction::Read { table_name, column_name } if table_name == table && colonne.map_or(true, |c| c == column_name) => {
            Authorization::Deny
        }
        _ => Authorization::Allow,
    }));
}
fn o7_tout_permettre(conn: &Connection) {
    use rusqlite::hooks::{AuthContext, Authorization};
    conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
}
fn o7_deux_destinations(conn: &Connection, erreur: &str) {
    conn.execute(
        "INSERT INTO destination(name,enabled,last_error) VALUES('d-ok',1,NULL),('d-err',1,?1)",
        params![erreur],
    )
    .unwrap();
}
fn o7_avoue_non_lu(etat: &str, detail: &str) {
    assert_eq!(etat, "yellow", "une lecture ratée n'est ni idle ni green : {detail}");
    assert!(detail.contains("NON LU"), "la phrase nomme la lecture non faite : {detail}");
    assert!(!detail.starts_with("aucune destination"), "jamais l'état calme : {detail}");
    assert!(!detail.ends_with("destination(s) OK"), "jamais « OK » : {detail}");
}

#[test]
fn o7_catalogue_interrompu_jaune_jamais_idle() {
    let conn = test_db();
    o7_deux_destinations(&conn, "");
    let premier = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    conn.progress_handler(1, Some(move || premier.swap(false, std::sync::atomic::Ordering::SeqCst)));
    let (e, d) = crate::metrics::destination_health(&conn);
    conn.progress_handler(1, None::<fn() -> bool>);
    o7_avoue_non_lu(e, &d);
    assert!(d.contains("présence de la table"), "{d}");
    assert!(d.contains("ce n'est PAS « aucune destination configurée »"), "{d}");
}

#[test]
fn o7_table_des_destinations_illisible_jaune_jamais_idle() {
    let conn = test_db();
    o7_deux_destinations(&conn, "");
    o7_refuser_la_lecture(&conn, "destination", None);
    let (e, d) = crate::metrics::destination_health(&conn);
    o7_tout_permettre(&conn);
    o7_avoue_non_lu(e, &d);
    // La cause NOMME le site du compte total (le gabarit de `non_lue` contient déjà « ni le nombre de
    // destinations ni » : un simple `contains("nombre de destinations")` était vrai pour toute sortie).
    assert!(d.starts_with("état des destinations NON LU (nombre de destinations :"), "cause du compte total : {d}");
    // Le total n'a pas été lu : aucun nombre de destinations configurées ne peut être servi.
    assert!(!d.contains("configurée(s)"), "aucun total fabriqué : {d}");
}

#[test]
fn o7_compte_en_erreur_illisible_jaune_jamais_ok() {
    let conn = test_db();
    o7_deux_destinations(&conn, "connexion refusée");
    o7_refuser_la_lecture(&conn, "destination", Some("last_error"));
    let (e, d) = crate::metrics::destination_health(&conn);
    o7_tout_permettre(&conn);
    o7_avoue_non_lu(e, &d);
    assert!(d.starts_with("2 destination(s) configurée(s)"), "le total lu reste dit : {d}");
    assert!(d.contains("ce n'est PAS « destination(s) OK »"), "{d}");
}

#[test]
fn o7_compte_en_erreur_illisible_ne_recopie_aucune_cellule() {
    // Le refus porte sur `enabled` : le compte en erreur échoue, mais `last_error` reste LISIBLE. Une
    // implémentation qui irait chercher les messages d'erreur pour le détail les recopierait ici (le
    // refus de `last_error` du témoin précédent rendait cette assertion vacante).
    let conn = test_db();
    o7_deux_destinations(&conn, "connexion refusée par 10.9.8.7");
    o7_refuser_la_lecture(&conn, "destination", Some("enabled"));
    let (e, d) = crate::metrics::destination_health(&conn);
    let lisible: Option<String> =
        conn.query_row("SELECT group_concat(last_error) FROM destination", [], |r| r.get(0)).unwrap();
    o7_tout_permettre(&conn);
    assert_eq!(lisible.as_deref(), Some("connexion refusée par 10.9.8.7"), "la cellule reste lisible sous ce refus");
    o7_avoue_non_lu(e, &d);
    assert!(d.starts_with("2 destination(s) configurée(s)"), "le total lu reste dit : {d}");
    assert!(!d.contains("connexion refusée") && !d.contains("10.9.8.7"), "aucune valeur de cellule dans le détail : {d}");
}

#[test]
fn o7_nominal_octet_pour_octet() {
    let conn = test_db();
    let idle = ("idle", "aucune destination configurée".to_string());
    assert_eq!(crate::metrics::destination_health(&conn), idle, "table vide -> idle comme avant");
    o7_deux_destinations(&conn, "");
    assert_eq!(crate::metrics::destination_health(&conn), ("green", "2 destination(s) OK".to_string()));
    conn.execute("UPDATE destination SET last_error='x' WHERE name='d-err'", []).unwrap();
    assert_eq!(crate::metrics::destination_health(&conn), ("yellow", "1/2 destination(s) en erreur".to_string()));
    conn.execute_batch("DROP TABLE destination").unwrap();
    assert_eq!(crate::metrics::destination_health(&conn), idle, "table absente AU CATALOGUE -> idle comme avant");
}

fn o7_composants(conn: &Connection) -> Vec<Value> {
    let spool = crate::tmp_possede::TmpPossede::neuf("o7-sante-spool");
    let recente = FraicheurDesTicks { regles: now(), rollups: now() };
    crate::metrics::component_health_avec_pertes(
        conn,
        spool.to_str().unwrap(),
        "o7-sante-forwarder",
        80,
        recente,
        &crate::metrics::PertesDAcces::aucune(),
    )
}
fn o7_composant<'a>(v: &'a [Value], nom: &str) -> &'a Value {
    v.iter().find(|c| c["component"] == nom).unwrap_or_else(|| panic!("composant {nom}"))
}

#[test]
fn o7_forwarder_non_lu_remonte_le_jaune_dans_la_posture() {
    let conn = test_db();
    o7_deux_destinations(&conn, "");
    o7_refuser_la_lecture(&conn, "destination", None);
    let v = o7_composants(&conn);
    o7_tout_permettre(&conn);
    let f = o7_composant(&v, crate::bilan_de_tick::COMPOSANT_FORWARDER);
    o7_avoue_non_lu(f["state"].as_str().unwrap(), f["detail"].as_str().unwrap());
    assert_eq!(crate::metrics::worst_state(std::slice::from_ref(f)), "yellow", "le jaune remonte : {f}");
    assert_ne!(crate::metrics::worst_state(&v), "green", "posture globale jamais verte : {f}");
}

#[test]
fn o7_regles_non_lues_cle_absente_et_cause() {
    let conn = test_db();
    o7_refuser_la_lecture(&conn, "rule", None);
    let v = o7_composants(&conn);
    o7_tout_permettre(&conn);
    let d = o7_composant(&v, crate::bilan_de_tick::COMPOSANT_DETECTION);
    assert!(d.get("enabled_rules").is_none(), "règles non lues : la clé est ABSENTE, jamais 0 — {d}");
    assert_eq!(d["enabled_rules_cause"], crate::mesure_environnement::CAUSE_SOURCE_ILLISIBLE, "{d}");
    assert!(d["enabled_rules_detail"].as_str().unwrap_or_default().contains("NON LU"), "{d}");
}

#[test]
fn o7_regles_lues_cle_presente_a_l_identique() {
    let conn = test_db();
    let avant: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE enabled=1", [], |r| r.get(0)).unwrap();
    // Deux règles actives et une inactive : un `enabled_rules` figé à 0, ou qui compterait l'inactive,
    // rougit (`test_db` n'en sème aucune, l'assertion d'avant était vacante).
    conn.execute_batch(
        "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) VALUES \
         ('o7-a',1,'search source=o7 | stats count',1,'>',2,2,0,3600), \
         ('o7-b',1,'search source=o7 | stats count',1,'>',2,2,0,3600), \
         ('o7-c',0,'search source=o7 | stats count',1,'>',2,2,0,3600);",
    )
    .unwrap();
    let attendu = avant + 2;
    let v = o7_composants(&conn);
    let d = o7_composant(&v, crate::bilan_de_tick::COMPOSANT_DETECTION);
    assert_eq!(d["enabled_rules"], json!(attendu), "{d}");
    assert!(d.get("enabled_rules_cause").is_none() && d.get("enabled_rules_detail").is_none(), "nominal inchangé : {d}");
}
