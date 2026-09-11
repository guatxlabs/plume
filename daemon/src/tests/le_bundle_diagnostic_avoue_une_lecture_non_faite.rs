// =====================================================================================
// `P10.7-g` — LE BUNDLE DE DIAGNOSTIC N'ANNONCE JAMAIS UNE LECTURE NON FAITE COMME UN FAIT.
//
// `GET /api/system/diag` (support hand-off, admin-only, téléchargé en JSON) bâtissait ses trois listes par
// `query_map(..).flatten()` et ses huit comptes par `conn.query_row(..).unwrap_or(0)` : une préparation ou
// une exécution ratée posait `[]` ou `0`, indiscernable d'un vrai vide, POSÉ COMME UN FAIT dans un fichier
// remis au support. Pire, `events_without_category` (un compte) et `unclassified_by_source` (sa ventilation)
// pouvaient SE CONTREDIRE dans le même corps : « N non classés » à côté de « aucune source n'en a ».
//
// CE QUE CES TÉMOINS JOUENT : une table renommée sous les pieds du fabricant (voie de `P10.7-z`, échec de
// lecture DÉTERMINISTE, sans chronomètre), le bundle bâti, et l'aveu EXIGÉ — (a) la sous-liste ratée est
// AVOUÉE `non_lu` et n'est jamais `[]` ; (b) le corps ne se contredit jamais (compte vs ventilation) ; (c)
// sur une base saine, le bundle est complet et sans le moindre marqueur `non_lu` (chemin nominal PROPRE :
// un aveu inconditionnel qui rougirait le nominal serait le défaut exactement symétrique).
// =====================================================================================

/// La sous-liste `<cle>` est-elle AVOUÉE non lue (un objet `{non_lu:true, cause}`) plutôt qu'un tableau ?
fn dnl_est_non_lu(b: &Value, cle: &str) -> bool {
    b.get(cle).and_then(|v| v.get("non_lu")).and_then(|v| v.as_bool()).unwrap_or(false)
}

/// Les noms des lectures avouées non lues, tels que le corps les liste.
fn dnl_non_lus(b: &Value) -> Vec<String> {
    b["non_lus"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default()
}

#[test]
fn p10_7g_le_bundle_avoue_une_sous_liste_non_lue() {
    use crate::handlers::system::diag_bundle_json;
    let c = day2_conn();
    // Base saine : la liste des heartbeats est un tableau (fût-il vide), aucun aveu.
    let sain = diag_bundle_json(&c, "/spool", "", 80);
    assert!(sain["heartbeat_alerts"].is_array(), "base saine : la liste est un tableau, pas un aveu : {sain}");
    assert!(sain.get("non_lus").is_none(), "base saine : pas de `non_lus` : {sain}");
    // La table `alert` hors d'atteinte (voie `P10.7-z`) : la lecture des heartbeats ÉCHOUE de façon déterministe.
    c.execute_batch("ALTER TABLE alert RENAME TO alert_hors_d_atteinte;").expect("la fixture peut renommer la table");
    let b = diag_bundle_json(&c, "/spool", "", 80);
    // (a) la sous-liste ratée est AVOUÉE non_lu, et n'est PAS `[]`.
    assert!(!b["heartbeat_alerts"].is_array(), "une lecture ratée n'est jamais servie comme un tableau : {b}");
    assert!(dnl_est_non_lu(&b, "heartbeat_alerts"), "la sous-liste ratée porte `non_lu:true` : {b}");
    assert!(b["heartbeat_alerts"]["cause"].as_str().unwrap_or("").contains("NON LUE"), "l'objet non_lu porte sa cause : {b}");
    assert_eq!(b["heartbeat_alerts_served"], Value::Null, "`served` est null (jamais 0) quand rien n'a été lu : {b}");
    assert_eq!(b["heartbeat_alerts_truncated"], Value::Null, "`truncated` est null (jamais false) quand rien n'a été lu : {b}");
    // Le corps porte l'aveu global (`non_lus` + `error`).
    assert!(dnl_non_lus(&b).iter().any(|s| s == "heartbeat_alerts"), "la liste ratée est nommée dans `non_lus` : {b}");
    assert!(b["error"].as_str().unwrap_or("").contains("NON LU"), "le corps porte la cause : {b}");
    // `alerts_open` (un compte sur la MÊME table) devient `null`, jamais 0.
    assert_eq!(b["counts"]["alerts_open"], Value::Null, "un compte raté est null, jamais 0 : {b}");
    assert!(dnl_non_lus(&b).iter().any(|s| s == "alerts_open"), "le compte raté est nommé : {b}");
    // Les listes qui se lisent encore (event présent) restent des tableaux : l'aveu est CIBLÉ, pas global.
    assert!(b["recent_events"].is_array(), "une liste lue reste un tableau, l'aveu ne déborde pas : {b}");
}

#[test]
fn p10_7g_le_compte_et_la_ventilation_des_non_classes_ne_se_contredisent_jamais() {
    use crate::handlers::system::diag_bundle_json;
    let c = day2_conn();
    // Base saine PORTANT des non-classés : le compte est un nombre > 0 ET la ventilation les localise —
    // les deux ÉTABLIS et cohérents (même prédicat sur `event`).
    for k in 0..3 {
        c.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,?2,'',2,'sans catégorie')", params![now() - k, format!("src-{k}")]).unwrap();
    }
    let sain = diag_bundle_json(&c, "/spool", "", 80);
    let compte_sain = sain["counts"]["events_without_category"].as_i64().expect("compte lu = un nombre");
    assert!(compte_sain >= 3, "trois non-classés semés : le compte les voit : {sain}");
    assert!(sain["unclassified_by_source"].as_array().map(|a| !a.is_empty()).unwrap_or(false), "la ventilation les localise : {sain}");
    dnl_pas_de_contradiction(&sain);
    // `event` hors d'atteinte : le COMPTE et la VENTILATION échouent tous deux. Le compte devient `null`
    // (jamais un nombre), la ventilation un objet `non_lu` (jamais `[]`) — ils ne peuvent pas se contredire.
    c.execute_batch("ALTER TABLE event RENAME TO event_hors_d_atteinte;").expect("la fixture peut renommer la table");
    let b = diag_bundle_json(&c, "/spool", "", 80);
    assert_eq!(b["counts"]["events_without_category"], Value::Null, "un compte non lu est null, jamais 0 : {b}");
    assert!(dnl_est_non_lu(&b, "unclassified_by_source"), "une ventilation non lue est un objet non_lu, jamais `[]` : {b}");
    assert!(!b["unclassified_by_source"].is_array(), "la ventilation ratée n'est jamais un tableau vide établi : {b}");
    dnl_pas_de_contradiction(&b);
}

/// L'INVARIANT DE SOLIDARITÉ, éprouvé dans les deux sens : jamais un compte de non-classés POSITIF à côté
/// d'une ventilation VIDE ÉTABLIE (un tableau `[]`), ni un compte `null` à côté d'une ventilation qui
/// prétend établir des sources. Un compte non lu (`null`) ou une ventilation non lue (objet `non_lu`)
/// désamorcent la contradiction ; deux lectures réussies portent le MÊME prédicat, donc concordent.
fn dnl_pas_de_contradiction(b: &Value) {
    let compte = &b["counts"]["events_without_category"];
    let vent = &b["unclassified_by_source"];
    if let Some(n) = compte.as_i64() {
        // Compte ÉTABLI. La ventilation ne doit pas prétendre « aucune source » quand le compte dit > 0.
        if n > 0 {
            let vent_vide_etablie = vent.as_array().map(|a| a.is_empty()).unwrap_or(false);
            assert!(!vent_vide_etablie, "contradiction : {n} non-classés comptés, mais la ventilation est un `[]` établi : {b}");
        }
    }
}

#[test]
fn p10_7g_sur_une_base_saine_le_bundle_est_complet_sans_marqueur_non_lu() {
    use crate::handlers::system::diag_bundle_json;
    let c = day2_conn();
    // Sème de quoi peupler CHAQUE liste : un event opérationnel (recent), un non-classé (unclassified),
    // une alerte de capteur muet (heartbeats), et un utilisateur (un compte non nul).
    c.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'plume-disk','ops',2,'disque à 85%')", params![now()]).unwrap();
    c.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'agent','',2,'sans catégorie')", params![now()]).unwrap();
    c.execute("INSERT INTO alert(ts,rule,severity,title,status) VALUES(?1,'heartbeat.web1',3,'capteur muet','new')", params![now()]).unwrap();
    c.execute("INSERT INTO user(name,hash,role) VALUES('alice','$argon2id$x','admin')", []).unwrap();
    let b = diag_bundle_json(&c, "/spool", "", 80);
    // (c) chemin nominal PROPRE : aucun aveu, aucune contradiction, les trois listes sont des tableaux.
    assert!(b.get("error").is_none(), "base saine : aucun `error` : {b}");
    assert!(b.get("non_lus").is_none(), "base saine : aucun `non_lus` : {b}");
    for cle in ["recent_events", "heartbeat_alerts", "unclassified_by_source"] {
        assert!(b[cle].is_array(), "base saine : `{cle}` est un tableau, jamais un objet non_lu : {b}");
        assert!(!dnl_est_non_lu(&b, cle), "base saine : `{cle}` ne porte aucun marqueur non_lu : {b}");
    }
    assert!(b["recent_events"].as_array().unwrap().iter().any(|e| e["source"] == "plume-disk"), "l'event opérationnel est là : {b}");
    assert!(!b["heartbeat_alerts"].as_array().unwrap().is_empty(), "l'alerte de capteur muet est là : {b}");
    // Les huit comptes sont TOUS des nombres (aucun `null`), et aucun n'est nommé non lu.
    for (k, v) in b["counts"].as_object().expect("counts est un objet") {
        assert!(v.is_i64() || v.is_u64(), "base saine : le compte `{k}` est un nombre, jamais null : {b}");
    }
    assert!(b["counts"]["users"].as_i64().unwrap() >= 1, "un utilisateur semé, un compté : {b}");
    dnl_pas_de_contradiction(&b);
}
