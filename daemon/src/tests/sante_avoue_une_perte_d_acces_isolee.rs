// LA SANTÉ DE COMPOSANT AVOUE UNE PERTE D'ACCÈS ISOLÉE (`P10.21-n`, second tour du vérificateur).
//
// VU sur ac9a697 : le seul témoin de bout en bout comptait un événement ET une trace dans la même
// seconde. Une lecture CROISÉE dans `PertesDAcces::du_processus` (l'horodatage des traces lu sur
// l'atomique des événements, ou l'inverse ; le total des traces lu sur celui des événements) restait
// verte, alors qu'elle empêche l'aveu d'une perte ISOLÉE sur le voyant de production, ou fausse son compte.
//
// Chaque témoin ne compte qu'UN genre de perte, avec des noms qui lui sont propres. Sens robuste au
// parallélisme : le code juste est toujours vert (horodatage posé après `avant`, total encadré par
// deux lectures du MÊME atomique, compteurs monotones) ; sous nextest (un processus par témoin), la
// lecture croisée lit un atomique que personne n'a touché et rougit.
//
// CE QU'ILS NE TIENNENT PAS : sous `cargo test` (un seul processus), une perte concurrente de l'autre
// genre peut masquer une lecture croisée — le rouge est garanti sous nextest seulement.

/// Une trace opérateur perdue SEULE atteint le voyant de production : `du_processus` relit son
/// horodatage à elle (pas celui des événements), et `component_health` l'avoue.
#[test]
fn g7w_une_trace_operateur_perdue_seule_atteint_le_voyant_de_production() {
    const TRACE: &str = "g7w-trace-seule";
    let avant = now();
    crate::metrics::compter_un_acces_operateur_non_trace(TRACE, "g7w cause trace seule");
    let p = crate::metrics::PertesDAcces::du_processus();
    assert!(p.derniere_perte_trace >= avant, "horodatage de TRACE relu sur son propre atomique : {p:?}");

    let c = day2_conn();
    let spool = crate::tmp_possede::TmpPossede::neuf("g7w-trace-seule-spool");
    let det = crate::metrics::component_health(&c, spool.to_str().unwrap(), "g7w-trace-seule", 80)
        .into_iter()
        .find(|v| v["component"] == "detection")
        .expect("composant détection");
    let d = det["detail"].as_str().unwrap_or_default();
    assert!(matches!(det["state"].as_str(), Some("yellow") | Some("red")), "{det}");
    assert!(d.contains(TRACE) && d.contains("trace(s) d'accès opérateur cross-tenant NON ÉCRITE(S)"), "{det}");
}

/// Un événement d'accès perdu SEUL atteint le voyant de production : symétrique du précédent.
#[test]
fn g7w_un_evenement_d_acces_perdu_seul_atteint_le_voyant_de_production() {
    const GENRE: &str = "g7w-genre-seul";
    let avant = now();
    crate::metrics::compter_un_evenement_d_acces_non_ecrit(GENRE, "g7w cause evenement seul");
    let p = crate::metrics::PertesDAcces::du_processus();
    assert!(p.derniere_perte_evenement >= avant, "horodatage d'ÉVÉNEMENT relu sur son propre atomique : {p:?}");

    let c = day2_conn();
    let spool = crate::tmp_possede::TmpPossede::neuf("g7w-evenement-seul-spool");
    let det = crate::metrics::component_health(&c, spool.to_str().unwrap(), "g7w-evenement-seul", 80)
        .into_iter()
        .find(|v| v["component"] == "detection")
        .expect("composant détection");
    let d = det["detail"].as_str().unwrap_or_default();
    assert!(matches!(det["state"].as_str(), Some("yellow") | Some("red")), "{det}");
    assert!(d.contains(GENRE) && d.contains("événement(s) d'accès auto-ingéré(s) NON ÉCRIT(S)"), "{det}");
}

/// Chaque total est relu sur SON atomique : encadré par deux lectures de ce même atomique, avec des
/// comptes DIFFÉRENTS pour les deux genres (5 événements, 1 trace) afin qu'une lecture croisée tombe
/// hors de l'encadrement.
#[test]
fn g7w_chaque_total_est_relu_sur_son_propre_atomique() {
    use std::sync::atomic::Ordering;
    let ev_avant = crate::metrics::EVENEMENTS_D_ACCES_NON_ECRITS_TOTAL.load(Ordering::Relaxed);
    let tr_avant = crate::metrics::ACCES_OPERATEUR_NON_TRACES_TOTAL.load(Ordering::Relaxed);
    for _ in 0..5 {
        crate::metrics::compter_un_evenement_d_acces_non_ecrit("g7w-genre-totaux", "g7w cause totaux");
    }
    crate::metrics::compter_un_acces_operateur_non_trace("g7w-trace-totaux", "g7w cause totaux");
    let p = crate::metrics::PertesDAcces::du_processus();
    let ev_apres = crate::metrics::EVENEMENTS_D_ACCES_NON_ECRITS_TOTAL.load(Ordering::Relaxed);
    let tr_apres = crate::metrics::ACCES_OPERATEUR_NON_TRACES_TOTAL.load(Ordering::Relaxed);
    assert!(ev_avant + 5 <= p.total_evenements && p.total_evenements <= ev_apres, "total d'événements {ev_avant}+5..={ev_apres} : {p:?}");
    assert!(tr_avant + 1 <= p.total_traces && p.total_traces <= tr_apres, "total de traces {tr_avant}+1..={tr_apres} : {p:?}");
}

/// LA PORTÉE EST DITE : les compteurs sont ceux du PROCESSUS, `component_health` décrit la base du
/// tenant courant ; chacune des deux phrases d'aveu le précise (multi-tenant : la perte peut venir
/// d'une autre base).
#[test]
fn g7w_l_aveu_dit_que_le_compte_est_celui_du_processus() {
    use crate::metrics::{etat_de_surface_pertes_d_acces as surface, PORTEE_DES_PERTES_D_ACCES as PORTEE};
    let now_ts = 1_000_000;
    let mut p = crate::metrics::PertesDAcces::aucune();
    p.evenements.insert("g7w-genre-portee".into(), (1, "c".into()));
    p.derniere_perte_evenement = now_ts - 10;
    let (_, d) = surface("green", "base".into(), &p, now_ts);
    assert_eq!(d.matches(PORTEE).count(), 1, "phrase des événements : {d}");
    p.traces_operateur.insert("g7w-trace-portee".into(), (1, "c".into()));
    p.derniere_perte_trace = now_ts - 10;
    let (_, d) = surface("green", "base".into(), &p, now_ts);
    assert_eq!(d.matches(PORTEE).count(), 2, "les deux phrases : {d}");
    assert!(PORTEE.contains("processus") && PORTEE.contains("tenant"), "{PORTEE}");
}
