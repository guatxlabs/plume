// =====================================================================================
// `P10.7-g` (lot 108) — LA COUVERTURE THREAT-INTEL AVOUE UNE VENTILATION NON LUE.
//
// VU : `ti_coverage_json` servait `by_type: []` / `by_source: []` sur une lecture ratée (`.flatten()` +
// `unwrap_or_default`), à côté d'un `total`/`active` qui, eux, comptent le magasin ENTIER — un exploitant qui
// n'y voit pas son flux conclut « ce flux n'alimente pas le magasin ». Les deux ventilations sont désormais
// lues EN BLOC : une lecture ratée rend `null` + `by_type_error`/`by_source_error`, jamais une liste vide.
//
// CE QUE CE TÉMOIN JOUE : la table `ioc` renommée sous le lecteur (échec au premier pas), puis la couverture
// rappelée — le corps doit porter l'aveu, et un total illisible ne se sert JAMAIS comme un nombre (S32).
// =====================================================================================

#[test]
fn p10_7g_la_couverture_ti_non_lue_dit_sa_cause() {
    let conn = test_db();
    let avant = crate::handlers::threat_intel::ti_coverage_json(&conn, now());
    assert!(avant["by_type"].is_array() && avant["by_source"].is_array(), "tables présentes : ventilations servies : {avant}");
    assert!(avant.get("by_type_error").is_none() && avant.get("by_source_error").is_none(), "rien à avouer sur une base lisible : {avant}");
    conn.execute_batch("ALTER TABLE ioc RENAME TO ioc_hors_d_atteinte;").unwrap();
    let apres = crate::handlers::threat_intel::ti_coverage_json(&conn, now());
    assert_eq!(apres["by_type"], json!(null), "ventilation par type non lue = null, jamais [] : {apres}");
    assert!(apres["by_type_error"].as_str().unwrap_or("").contains("NON LUE"), "la cause du type est nommée : {apres}");
    assert_eq!(apres["by_source"], json!(null), "ventilation par source non lue = null : {apres}");
    assert!(apres["by_source_error"].as_str().unwrap_or("").contains("NON LUE"), "la cause de la source est nommée : {apres}");
    assert_eq!(apres["lecture_non_faite"], json!(true), "l'aveu marque la non-lecture : {apres}");
    assert!(!apres["total"].is_number(), "un total illisible ne se sert jamais comme un nombre (S32) : {apres}");
}
