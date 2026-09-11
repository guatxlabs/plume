// =====================================================================================
// `P10.7-g` (lot 96) — UN TOTAL DE LISTE D'ALERTES NON ÉTABLI EST NOMMÉ, JAMAIS TU.
//
// Le COUNT est le premier énoncé exécuté par les deux routes de triage et le plus lourd ; coupé par le
// budget, il rendait `None` — la même valeur qu'un total non demandé — et la console lisait « reste
// indéterminable » sans cause. Le total est typé (`TotalDeListe`) : le corps sert `total: null` ET
// `total_error` avec la cause du moteur, pendant que la page, elle, est servie entière.
//
// CE QUE CES TÉMOINS JOUENT : la fixture de `troncature_sous_budget.rs` (compteur de pas SQLite), un tir
// CHERCHÉ qui coupe PENDANT le COUNT et laisse la page aboutir, sur la liste plate et sur les groupes.
// =====================================================================================

fn tdn_total_non_etabli(r: &(Vec<Value>, crate::handlers::alerts::TotalDeListe, FinDeParcours)) -> bool {
    matches!(r.1, crate::handlers::alerts::TotalDeListe::NonEtabli(_))
}

#[test]
fn p10_7g_un_total_dalertes_non_etabli_est_nomme_jamais_tu() {
    const N: i64 = 60;
    let conn = tsb_base(N);
    // MESURÉ : sans WHERE, `SELECT COUNT(*) FROM alert` est un seul opcode de comptage du B-tree et passe SOUS le
    // pas du rappel de progression (8) : aucun tir ne peut le couper. Sous un filtre, le COUNT parcourt les lignes
    // et se laisse couper ; toutes les alertes de la fixture sont `new`, le total reste N.
    let filtre = FiltreAlertes { statut: Some("new".into()), ..Default::default() };
    let (page, total, fin) = alerts_query_page(&conn, &filtre, None, "", 200, 0, true);
    assert_eq!(total, Some(N), "instrument : le COUNT aboutit sur le chemin nominal");
    let nominal = corps_de_liste_d_alertes(page, total, &fin);
    assert!(nominal.get("total_error").is_none() && nominal["total"] == json!(N), "chemin nominal : total compté, aucun aveu : {nominal}");
    let mut coupe = None;
    for tir in 1..400usize {
        tsb_couper_au_tir(&conn, tir);
        let r = alerts_query_page(&conn, &filtre, None, "", 200, 0, true);
        tsb_ne_plus_couper(&conn);
        if tdn_total_non_etabli(&r) && r.0.len() as i64 == N {
            coupe = Some(r);
            break;
        }
    }
    let (page, total, fin) = coupe.expect("instrument : aucun tir n'a coupé le COUNT en laissant la page aboutir — le témoin ne conclut pas");
    assert!(fin.cause().is_none(), "instrument : la page est entière, seul le COUNT a été coupé");
    let corps = corps_de_liste_d_alertes(page, total, &fin);
    assert_eq!(corps["total"], Value::Null, "un compte interrompu rend `null`, jamais un chiffre ni une absence de demande : {corps}");
    assert!(corps["total_error"].as_str().unwrap_or("").starts_with("total NON ÉTABLI"), "la cause est nommée : {corps}");
    assert_eq!(corps["alerts"].as_array().map(|a| a.len() as i64), Some(N), "la page entière reste servie : {corps}");
}

#[test]
fn p10_7g_un_total_de_groupes_non_etabli_est_nomme_jamais_tu() {
    const N: i64 = 60;
    let conn = tsb_base(N);
    let filtre = FiltreAlertes::default();
    let (groupes, total, fin) = alert_groups_query_page(&conn, "rule", &filtre, 500, 0);
    let g = groupes.len() as i64;
    assert!(g > 0 && total == Some(g), "instrument : le COUNT DISTINCT aboutit sur le chemin nominal ({g} groupes, {total:?})");
    let nominal = corps_de_liste_de_groupes(groupes, total, "rule", &fin);
    assert!(nominal.get("total_error").is_none(), "chemin nominal : aucun aveu : {nominal}");
    let mut coupe = None;
    for tir in 1..400usize {
        tsb_couper_au_tir(&conn, tir);
        let r = alert_groups_query_page(&conn, "rule", &filtre, 500, 0);
        tsb_ne_plus_couper(&conn);
        if tdn_total_non_etabli(&r) && r.0.len() as i64 == g {
            coupe = Some(r);
            break;
        }
    }
    let (groupes, total, fin) = coupe.expect("instrument : aucun tir n'a coupé le COUNT DISTINCT en laissant les groupes aboutir — le témoin ne conclut pas");
    let corps = corps_de_liste_de_groupes(groupes, total, "rule", &fin);
    assert_eq!(corps["total"], Value::Null, "un compte interrompu rend `null` : {corps}");
    assert!(corps["total_error"].as_str().unwrap_or("").starts_with("total NON ÉTABLI"), "la cause est nommée : {corps}");
}
