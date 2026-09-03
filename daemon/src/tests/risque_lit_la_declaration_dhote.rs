// =====================================================================================
// `P11.20-h` — LE RISQUE LIT ENFIN LA DÉCLARATION D'HÔTE.
//
// LE DÉFAUT MESURÉ (2026-09-03, `9c2ae23`). `risk_entities_page` ne lisait RIEN de `host_settings` :
// une machine que l'exploitant a DÉCLARÉE hors du parc (`retire`) et un banc de test dont le silence
// est déclaré normal (`silence_attendu`) arrivaient dans le classement de risque et dans
// `over_threshold_total` exactement comme une machine de production — sans un mot pour les
// distinguer. Le panneau de posture mélangeait le parc et ce qui n'en fait plus partie.
//
// CE QUE LE PARTAGE D'ESPACE DE NOMS ÉCONOMISE — MESURÉ, PAS SUPPOSÉ. `host_settings.host`,
// `host_rollup.host` et `risk_rollup.entity` (pour `entity_type='host'`) nomment tous la MÊME valeur,
// `event.host`. UNE déclaration, déjà posée pour la vue de flotte par `P11.10-a`, sert donc les DEUX
// vues : aucune table, aucune colonne (donc AUCUN franchissement de schéma), aucune seconde surface
// de déclaration à tenir cohérente, aucune API de plus. Le geste se réduit à une lecture et à deux
// champs publiés. Le témoin `une_seule_declaration_sert_les_deux_vues` le prouve : le MÊME geste
// éteint l'alerte de parc ET marque l'entité à risque.
//
// LA PRESCRIPTION QU'ON N'A PAS SUIVIE, PARCE QU'ELLE EST REFUSÉE PAR ÉCRIT. « Exclure les hôtes
// déclarés » : le chemin de DÉTECTION ne porte AUCUNE exclusion de ce genre, délibérément — une règle
// doit TOUT voir (`rule_sql_masked`). Rien n'est donc retiré ici : ni du classement, ni du total, ni
// de l'alerte. On MARQUE et on COMPTE À CÔTÉ. Convertir un signal en extinction ferait taire une
// accusation ; c'est le contraire de ce que la clé demande.
// =====================================================================================

fn rd_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
    assert!(migrate(&conn), "fixture P11.20-h : migrations complètes");
    conn
}

/// Une entité À RISQUE, au-dessus du seuil de cumul par construction (score 500 >= 100).
fn rd_entite(conn: &Connection, etype: &str, entity: &str, score: i64) {
    conn.execute(
        "INSERT INTO risk_rollup(entity_type,entity,env_id,score,contrib,distinct_tactics,tactics,score_hot,contrib_hot,max_severity,first_ts,last_ts,updated) \
         VALUES(?1,?2,'prod',?3,1,1,'TA0001',0,0,3,10,20,20)",
        params![etype, entity, score],
    )
    .unwrap();
}

fn rd_declare(conn: &Connection, host: &str, attente: &str) {
    conn.execute(
        "INSERT OR REPLACE INTO host_settings(scope,host,attente,attente_motif,attente_par,attente_le,updated,updated_by) \
         VALUES('global',?1,?2,'motif écrit','exploitante',100,100,'exploitante')",
        params![host, attente],
    )
    .unwrap();
}

/// La marque publiée pour une entité (`null` -> `None`).
fn rd_attente(page: &Value, etype: &str, entity: &str) -> Option<String> {
    page.get("entities")?
        .as_array()?
        .iter()
        .find(|e| e.get("entity_type").and_then(|v| v.as_str()) == Some(etype) && e.get("entity").and_then(|v| v.as_str()) == Some(entity))
        .and_then(|e| e.get("attente"))
        .and_then(|v| v.as_str())
        .map(String::from)
}

fn rd_servies(page: &Value) -> usize {
    page.get("entities").and_then(|e| e.as_array()).map(|a| a.len()).unwrap_or(0)
}

// -------------------------------------------------------------------------------------
// (1) LA MARQUE — et ce qu'elle ne couvre PAS.
// -------------------------------------------------------------------------------------
/// Le classement porte la déclaration de l'exploitant pour les entités `host`, et RIEN pour les
/// autres types : c'est le seul espace de noms partagé. Le contrôle le plus tranchant est le
/// dernier — une entité `user` HOMONYME d'une machine retirée n'hérite PAS de sa marque, sans quoi la
/// jointure serait faite sur la valeur seule et un compte utilisateur pourrait être blanchi par la
/// déclaration d'une machine.
#[test]
fn le_classement_de_risque_porte_la_declaration_de_lhote_et_seulement_pour_un_hote() {
    let conn = rd_conn();
    rd_entite(&conn, "host", "srv-retire", 500);
    rd_entite(&conn, "host", "srv-vivant", 500);
    rd_entite(&conn, "host", "banc-de-test", 500);
    rd_entite(&conn, "user", "srv-retire", 500); // HOMONYME, d'un autre type
    rd_declare(&conn, "srv-retire", "retire");
    rd_declare(&conn, "banc-de-test", "silence_attendu");

    let page = risk_entities_page(&conn, 100, 3, 50);
    assert_eq!(rd_attente(&page, "host", "srv-retire").as_deref(), Some("retire"), "AVANT correctif : aucune marque, le classement ne lisait rien de la déclaration");
    assert_eq!(rd_attente(&page, "host", "banc-de-test").as_deref(), Some("silence_attendu"));
    assert_eq!(rd_attente(&page, "host", "srv-vivant"), None, "personne n'a rien dit : on n'invente pas une déclaration");
    assert_eq!(rd_attente(&page, "user", "srv-retire"), None, "l'espace de noms est celui des HÔTES — un homonyme d'un autre type n'hérite de rien");
}

// -------------------------------------------------------------------------------------
// (2) LE COMPTE SE LIT À CÔTÉ DU TOTAL, JAMAIS À SA PLACE — et rien n'est éteint.
// -------------------------------------------------------------------------------------
/// Le contrôle qui compte le plus : `over_threshold_total` et le nombre de lignes SERVIES sont
/// INCHANGÉS par la déclaration. Une machine retirée qui accumule du risque reste VISIBLE et reste
/// COMPTÉE — la clé demandait de savoir lire, pas de faire taire. Deux mutations nomment la valeur
/// qui change : retirer la déclaration fait tomber le seul compte `hors_parc` (et lui seul) ; en
/// déclarer une seconde le fait monter (et lui seul).
#[test]
fn le_compte_hors_parc_se_lit_a_cote_du_total_et_n_eteint_rien() {
    let conn = rd_conn();
    for h in ["srv-retire", "srv-vivant", "banc-de-test"] {
        rd_entite(&conn, "host", h, 500);
    }
    rd_entite(&conn, "user", "alice", 500);
    rd_declare(&conn, "srv-retire", "retire");
    rd_declare(&conn, "banc-de-test", "silence_attendu");

    let page = risk_entities_page(&conn, 100, 3, 50);
    assert_eq!(rd_servies(&page), 4, "rien n'est retiré du classement");
    assert_eq!(page["total"], json!(4));
    assert_eq!(page["over_threshold_total"], json!(4), "le total au-dessus du seuil ne bouge pas d'un pouce : aucune extinction");
    assert_eq!(page["over_threshold_hors_parc"], json!(1), "AVANT correctif : la clé n'existait pas. `retire` SEUL compte");

    // MUTATION 1 — la déclaration retirée : `hors_parc` tombe, le TOTAL ne bouge pas.
    conn.execute("DELETE FROM host_settings WHERE host='srv-retire'", []).unwrap();
    let page = risk_entities_page(&conn, 100, 3, 50);
    assert_eq!(page["over_threshold_hors_parc"], json!(0), "sans déclaration, plus rien n'est hors parc");
    assert_eq!(page["over_threshold_total"], json!(4), "…et le total est le MÊME : le compte est un À-CÔTÉ, pas un filtre");
    assert_eq!(rd_servies(&page), 4);

    // MUTATION 2 — une seconde machine déclarée retirée : `hors_parc` monte, seul.
    rd_declare(&conn, "srv-retire", "retire");
    rd_declare(&conn, "srv-vivant", "retire");
    let page = risk_entities_page(&conn, 100, 3, 50);
    assert_eq!(page["over_threshold_hors_parc"], json!(2));
    assert_eq!(page["over_threshold_total"], json!(4), "toujours le même total");
    assert_eq!(rd_servies(&page), 4, "toujours les mêmes lignes servies");
}

// -------------------------------------------------------------------------------------
// (3) UN SILENCE ATTENDU N'EST PAS UN RETRAIT.
// -------------------------------------------------------------------------------------
/// `silence_attendu` dit que la machine SE TAIT normalement — pas qu'elle a quitté le parc. Elle peut
/// parfaitement être attaquée, et son risque est celui d'une machine vivante. Confondre les deux
/// éteindrait un signal réel sous couvert d'hygiène de parc ; c'est le sens de l'énoncé de
/// `P11.10-a` (« elle reste dans le parc et dans la liste »), transposé au risque.
#[test]
fn un_silence_attendu_n_est_pas_un_retrait_du_parc() {
    let conn = rd_conn();
    rd_entite(&conn, "host", "banc-de-test", 500);
    rd_declare(&conn, "banc-de-test", "silence_attendu");
    let page = risk_entities_page(&conn, 100, 3, 50);
    assert_eq!(rd_attente(&page, "host", "banc-de-test").as_deref(), Some("silence_attendu"), "la marque est bien LUE…");
    assert_eq!(page["over_threshold_hors_parc"], json!(0), "…mais ne vaut PAS « hors parc »");

    // CONTRÔLE POSITIF, dans le même corps : la MÊME machine déclarée `retire` compte, elle.
    rd_declare(&conn, "banc-de-test", "retire");
    let page = risk_entities_page(&conn, 100, 3, 50);
    assert_eq!(page["over_threshold_hors_parc"], json!(1), "sans ce bras, le 0 ci-dessus serait vert par construction");

    // …et `signal_attendu` — la déclaration qui RÉARME — ne compte pas davantage.
    rd_declare(&conn, "banc-de-test", "signal_attendu");
    let page = risk_entities_page(&conn, 100, 3, 50);
    assert_eq!(rd_attente(&page, "host", "banc-de-test").as_deref(), Some("signal_attendu"));
    assert_eq!(page["over_threshold_hors_parc"], json!(0));
}

// -------------------------------------------------------------------------------------
// (4) UNE SEULE DÉCLARATION SERT LES DEUX VUES — l'économie, MESURÉE.
// -------------------------------------------------------------------------------------
/// L'énoncé de la clé disait que les deux vues partagent l'espace de noms `event.host` et qu'une
/// seule déclaration suffirait. Ce témoin le MESURE au lieu de le croire : le MÊME geste (une ligne
/// de `host_settings`, posée une fois) est lu par `hotes_hors_alerte` — la sonde de parc — ET par le
/// classement de risque. Si un jour l'un des deux se mettait à lire ailleurs, ce test rougirait, et
/// c'est exactement l'économie qu'il garde.
#[test]
fn une_seule_declaration_sert_les_deux_vues() {
    let conn = rd_conn();
    rd_entite(&conn, "host", "srv-decommissionne", 500);
    rd_declare(&conn, "srv-decommissionne", "retire");

    // VUE 1 — la sonde de parc (`P11.10-a`).
    let (_silences, retires) = hotes_hors_alerte(&conn);
    assert!(retires.contains("srv-decommissionne"), "la sonde de parc lit la déclaration");
    // VUE 2 — le classement de risque (`P11.20-h`), SANS aucune écriture supplémentaire.
    let page = risk_entities_page(&conn, 100, 3, 50);
    assert_eq!(rd_attente(&page, "host", "srv-decommissionne").as_deref(), Some("retire"), "le risque lit la MÊME ligne");
    assert_eq!(page["over_threshold_hors_parc"], json!(1));

    // LA MUTATION QUI PROUVE QU'IL N'Y A QU'UNE SOURCE : un seul geste éteint les DEUX lectures.
    conn.execute("DELETE FROM host_settings WHERE host='srv-decommissionne'", []).unwrap();
    let (_s, retires) = hotes_hors_alerte(&conn);
    assert!(!retires.contains("srv-decommissionne"));
    let page = risk_entities_page(&conn, 100, 3, 50);
    assert_eq!(rd_attente(&page, "host", "srv-decommissionne"), None);
    assert_eq!(page["over_threshold_hors_parc"], json!(0), "un seul geste, deux vues — c'est ce que le partage d'espace de noms achète");
}

// -------------------------------------------------------------------------------------
// (5) « NON RECENSÉ » N'EST PAS « AUCUNE » — le nouveau compte hérite de la discipline du voisin.
// -------------------------------------------------------------------------------------
/// `over_threshold_total` vaut `null` — jamais `0` — quand le recensement n'a pas pu être lu, parce
/// que sur un panneau de posture l'écart va dans le sens dangereux. Le compte ajouté doit obéir à la
/// même règle, sinon il rassurerait précisément quand personne ne sait. On rend la table illisible
/// (elle est renommée) pour l'éprouver.
#[test]
fn un_recensement_illisible_ne_rend_pas_un_zero_rassurant() {
    let conn = rd_conn();
    rd_entite(&conn, "host", "srv", 500);
    rd_declare(&conn, "srv", "retire");
    // CONTRÔLE POSITIF D'ABORD : la lecture marche, et les deux chiffres sont des nombres.
    let page = risk_entities_page(&conn, 100, 3, 50);
    assert_eq!(page["over_threshold_total"], json!(1));
    assert_eq!(page["over_threshold_hors_parc"], json!(1));

    conn.execute("ALTER TABLE risk_rollup RENAME TO risk_rollup_absente", []).unwrap();
    let page = risk_entities_page(&conn, 100, 3, 50);
    assert!(page["over_threshold_total"].is_null(), "le voisin dit déjà « je n'ai pas pu lire »");
    assert!(page["over_threshold_hors_parc"].is_null(), "AVANT correctif : la clé n'existait pas. Un `0` ici serait un aveu OPTIMISTE");
}
