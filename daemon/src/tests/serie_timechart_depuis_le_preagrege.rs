// =====================================================================================
// ROUTE C (timechart) — P10.5-e moitié 1, TRANCHE 1 : une COURBE TEMPORELLE `count` est servie depuis le
// pré-agrégé (`event_rollup ∪ cold_rollup ∪ raw-partiels`), pas par un scan déchiffré d'`event`.
// Oracle = `compile_timechart` du cœur sur `event` brut (scan complet = vérité). La série routée DOIT
// reproduire ce compte EXACTEMENT, SEAU PAR SEAU. Réutilise le harnais de rollup.rs (même module via
// include!) : VERROU_ENV_PROCESSUS, b2_map, b2adv_seed_at, test_db, rollup_events, try_rollup_route_at,
// try_cold_rollup_route_at, soql_to_sql_x.
//
// POURQUOI CES TÉMOINS : avant ROUTE C, aucune voie ne servait une courbe temporelle depuis un pré-agrégé
// (le dépôt le TESTAIT) -> la bande froide dessinait une chute à zéro qui n'était qu'une absence de lecture.
// La parité SEAU PAR SEAU contre le scan brut est la preuve que la courbe routée == la courbe vraie ; les
// déclins prouvent qu'une forme non exacte (span sous-horaire, `by`, autre agrégat) retombe sur le scan raw
// plutôt que de servir un faux ; l'invariant `Cap::Aucun` est celui que P10.5-e exige explicitement.
// =====================================================================================

/// Plancher-heure de `now()` (le grain du rollup). Local au fichier (les seaux du merge sont horaires).
fn tc_cur() -> i64 {
    (now() / 3600) * 3600
}

/// (1) PARITÉ SEAU PAR SEAU, span=1h, HOT. Des événements sur plusieurs heures DÉFINITIVES (corps rollup) +
/// l'heure courante (queue raw) : la série routée `timechart span=1h count` est IDENTIQUE, seau par seau,
/// au `compile_timechart` compilé en RAW sur `event`. La route lit bien `event_rollup` (pré-agrégé), ne pose
/// AUCUN plafond, et le total est conservé.
#[test]
fn serie_timechart_hot_span_1h_parite_rollup_egale_raw() {
    let _g = VERROU_ENV_PROCESSUS.write();
    std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
    let conn = test_db();
    let n = now();
    let cur = tc_cur();
    // Buckets DÉFINITIFS (corps rollup) : cur-5H..cur-2H. Heure courante (queue raw) : cur+ (n).
    b2adv_seed_at(&conn, cur - 5 * 3600, 3, "h5");
    b2adv_seed_at(&conn, cur - 4 * 3600, 2, "h4");
    b2adv_seed_at(&conn, cur - 3 * 3600, 4, "h3");
    b2adv_seed_at(&conn, cur - 2 * 3600, 1, "h2"); // = recent-1H : encore définitif
    b2adv_seed_at(&conn, n - 10, 5, "cur"); // heure courante (volatile) -> queue raw
    rollup_events(&conn);

    let soql = "search | timechart span=1h count";
    let from = cur - 6 * 3600;
    let rr = try_rollup_route_at(soql, from, n, None, n, RollupCoverage::of(&conn), DimRollupCoverage::of(&conn))
        .expect("une courbe `timechart span=1h count` DOIT être routée vers le pré-agrégé");
    // Servie depuis le pré-agrégé (le constat de P10.5-e = aucune route ne le faisait) + queue raw fraîche.
    assert!(rr.sql.contains("FROM event_rollup"), "corps servi depuis event_rollup (pré-agrégé) : {}", rr.sql);
    assert!(rr.sql.contains("FROM event WHERE"), "queue raw (heure courante, fraîcheur) : {}", rr.sql);
    assert!(!rr.cap.plafonne(), "ROUTE C ne pose JAMAIS de plafond (exact en somme) — invariant P10.5-e : {}", rr.sql);
    // Parité seau par seau contre l'oracle brut.
    let raw = soql_to_sql_x(soql, from, n, None).unwrap();
    let got = b2_map(&conn, &rr.sql);
    let want = b2_map(&conn, &raw);
    assert_eq!(got, want, "PARITÉ courbe routée == brute (seau -> compte)\nroutée={got:?}\nbrute={want:?}");
    let tot_r: i64 = got.iter().map(|(_, c)| c).sum();
    let tot_w: i64 = want.iter().map(|(_, c)| c).sum();
    assert!(tot_r > 0 && tot_r == tot_w, "total conservé : {tot_r} vs {tot_w}");
    // Au moins un seau DÉFINITIF est bien servi par le corps rollup (pas seulement la queue) : le seau de
    // l'heure la plus ancienne (cur-5H), refloré à l'heure, est présent dans la série.
    let seau_ancien = ((cur - 5 * 3600) / 3600) * 3600;
    assert!(got.iter().any(|(k, _)| k == &seau_ancien.to_string()), "le seau définitif le plus ancien est servi : {got:?}");
}

/// (2) PARITÉ, span=1d. Un seau JOURNALIER couvre 24 seaux horaires : il reçoit la SOMME de ses fragments
/// (corps rollup des heures complètes + queue raw de l'heure courante) par le `SUM(c) GROUP BY bucket` final.
/// La parité tient donc pour un span > 1h (régions disjointes, aucun double comptage ni trou).
#[test]
fn serie_timechart_hot_span_1d_parite_seau_journalier() {
    let _g = VERROU_ENV_PROCESSUS.write();
    std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
    let conn = test_db();
    let n = now();
    let cur = tc_cur();
    b2adv_seed_at(&conn, cur - 5 * 3600, 2, "h5");
    b2adv_seed_at(&conn, cur - 3 * 3600, 3, "h3");
    b2adv_seed_at(&conn, n - 10, 4, "cur");
    rollup_events(&conn);

    let soql = "search | timechart span=1d count";
    let from = cur - 8 * 3600;
    let rr = try_rollup_route_at(soql, from, n, None, n, RollupCoverage::of(&conn), DimRollupCoverage::of(&conn))
        .expect("une courbe `timechart span=1d count` DOIT router (span multiple exact de 3600)");
    assert!(rr.sql.contains("/86400)*86400"), "seau journalier = (t/86400)*86400 : {}", rr.sql);
    let raw = soql_to_sql_x(soql, from, n, None).unwrap();
    assert_eq!(b2_map(&conn, &rr.sql), b2_map(&conn, &raw), "PARITÉ span=1d (seau journalier = somme des fragments)");
}

/// (3) DÉCLIN sur span SOUS-HORAIRE : un pré-agrégé HORAIRE ne peut pas servir un seau de 15 min / 30 s sans
/// mentir -> `parse_timechart_shape` rend None ET la route DÉCLINE (fall-through vers le scan raw, exact).
#[test]
fn serie_timechart_decline_span_sous_horaire() {
    let _g = VERROU_ENV_PROCESSUS.write();
    std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
    let conn = test_db();
    b2adv_seed_at(&conn, tc_cur() - 3 * 3600, 2, "x");
    rollup_events(&conn);
    for q in ["search | timechart span=15m count", "search | timechart span=30s count", "search | timechart span=90m count"] {
        assert!(parse_timechart_shape(q).is_none(), "span sous-horaire NON reconnu : {q}");
        assert!(
            try_rollup_route_at(q, tc_cur() - 6 * 3600, now(), None, now(), RollupCoverage::of(&conn), DimRollupCoverage::of(&conn)).is_none(),
            "span sous-horaire DÉCLINE -> scan raw exact : {q}"
        );
    }
    // Contrôle POSITIF : les unités horaires exactes SONT reconnues (sinon le déclin ne prouve rien).
    assert!(parse_timechart_shape("search | timechart span=1h count").is_some(), "span=1h reconnu");
    assert!(parse_timechart_shape("search | timechart span=2h count").is_some(), "span=2h reconnu");
    assert!(parse_timechart_shape("search | timechart span=1d count").is_some(), "span=1d reconnu");
}

/// (4) DÉCLIN sur ventilation (`by …`), agrégat autre que `count`, ou étape en aval : hors de la TRANCHE 1.
/// Chaque forme non exacte DÉCLINE plutôt que de servir un faux — jamais un `by`/agrégat non pré-agrégé lu
/// comme une série routée.
#[test]
fn serie_timechart_decline_hors_perimetre_routable() {
    let _g = VERROU_ENV_PROCESSUS.write();
    std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
    for q in [
        "search | timechart span=1h count by src_ip",       // dim cappée (top-N) -> sous-comptée -> décline
        "search | timechart span=1h count by host",         // COALESCE '' à la matérialisation -> fusion NULL/''
        "search | timechart span=1h count by action",       // clé JSON absente = NULL, COALESCE '' -> idem
        "search | timechart span=1h count by source,src_ip", // un seul membre hors grain suffit à décliner
        "search | timechart span=1h count by source,source", // doublon -> refus
        "search | timechart span=1h count by path",         // dim hors grain
        "search | timechart span=1h avg(bytes)",            // agrégat autre que count
        "search | timechart span=1h max(value)",
        "search | timechart span=1h sum(bytes) by source",  // agrégat≠count même ventilé
        "search | timechart span=1h count | head 5",        // étape en aval
        "search | timechart span=1h count by source | sort bucket",
        "search | timechart count",                         // sans span -> bucket auto, non aligné au grain
        "search | timechart span=15m count by source",      // span sous-horaire même ventilé
        "metric plume_x | timechart span=1h avg(value)",     // base metric, pas search
    ] {
        assert!(parse_timechart_shape(q).is_none(), "forme hors périmètre NON reconnue : {q}");
        assert!(
            try_rollup_route_at(q, 0, 0, None, now(), RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(),
            "forme hors périmètre DÉCLINE -> raw : {q}"
        );
    }
    // Le filtre `source=X` optionnel est reconnu (partition unique exprimable) ; combiné à une ventilation aussi.
    assert!(parse_timechart_shape("search source=web | timechart span=1h count").is_some(), "filtre source= reconnu");
    assert!(parse_timechart_shape("search source=web | timechart span=1h count by severity").is_some(), "filtre + ventilation grain reconnus");
    assert!(parse_timechart_shape("search source=web status>=500 | timechart span=1h count").is_none(), "un 2e filtre non exprimable DÉCLINE");
}

/// (7) TRANCHE 2 — PARITÉ VENTILÉE : `timechart span=1h count by <dim⊆{source,severity}>` est servi depuis le
/// pré-agrégé (une série par (seau, dim)) et IDENTIQUE, seau-dim par seau-dim, au scan brut. Les dims du grain
/// EXACT {source,severity} sont NOT NULL nues -> `SUM(n) GROUP BY` == `count by` brut. `Cap::Aucun` conservé.
#[test]
fn serie_timechart_ventilee_parite_rollup_egale_raw() {
    let _g = VERROU_ENV_PROCESSUS.write();
    std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
    let conn = test_db();
    let n = now();
    let cur = tc_cur();
    b2adv_seed_at(&conn, cur - 5 * 3600, 3, "h5");
    b2adv_seed_at(&conn, cur - 3 * 3600, 4, "h3");
    b2adv_seed_at(&conn, n - 10, 5, "cur");
    rollup_events(&conn);
    let from = cur - 6 * 3600;
    for soql in [
        "search | timechart span=1h count by source",
        "search | timechart span=1h count by severity",
        "search | timechart span=1h count by source,severity",
        "search | timechart span=1h count by severity,source", // ordre inversé -> route aussi
        "search source=web | timechart span=1h count by severity", // filtre + ventilation
    ] {
        let rr = try_rollup_route_at(soql, from, n, None, n, RollupCoverage::of(&conn), DimRollupCoverage::of(&conn))
            .unwrap_or_else(|| panic!("courbe ventilée sur le grain exact DOIT router : {soql}"));
        assert!(rr.sql.contains("FROM event_rollup"), "servie depuis le pré-agrégé : {soql}");
        assert!(!rr.cap.plafonne(), "Cap::Aucun (exact en somme) : {soql}");
        let raw = soql_to_sql_x(soql, from, n, None).unwrap();
        assert_eq!(b2_map(&conn, &rr.sql), b2_map(&conn, &raw), "PARITÉ ventilée routée == brute pour `{soql}`");
    }
}

/// (5) SPAN horaire, unité inconnue, débordement : `timechart_span_horaire` n'accepte QUE h/d et refuse le
/// reste (fail-closed) — jamais une substitution silencieuse d'un bucket automatique.
#[test]
fn serie_timechart_span_horaire_borne() {
    assert_eq!(timechart_span_horaire("1h"), Some(3600));
    assert_eq!(timechart_span_horaire("6h"), Some(21600));
    assert_eq!(timechart_span_horaire("1d"), Some(86400));
    assert_eq!(timechart_span_horaire("7d"), Some(604800));
    for bad in ["15m", "30s", "90m", "0h", "0d", "1w", "3600", "h", "", "1x", "999999999999999999999d"] {
        assert!(timechart_span_horaire(bad).is_none(), "span non-horaire refusé : {bad}");
    }
}

/// (6) COLD — PARTITION DISJOINTE À LA FRONTIÈRE `B` (forme de SQL) : le corps froid ne lit QUE `cold_rollup`
/// sous `B`, le corps chaud ne lit `event_rollup` que `>= B`. C'est l'invariant qu'épingle
/// `cold_route_a_ne_lit_jamais_event_rollup_sous_la_frontiere`, tenu par la MÊME machinerie que la ROUTE A.
#[cfg(feature = "cold_tier")]
#[test]
fn serie_timechart_cold_partition_disjointe_a_la_frontiere() {
    let _g = VERROU_ENV_PROCESSUS.write();
    std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
    let conn = test_db();
    let n = now();
    let cur = tc_cur();
    // Assez d'histoire définitive pour qu'il y ait un corps des deux côtés de la frontière.
    b2adv_seed_at(&conn, cur - 10 * 3600, 2, "vieux");
    b2adv_seed_at(&conn, cur - 3 * 3600, 2, "recent");
    rollup_events(&conn);
    // Frontière froide `B` posée AU MILIEU de l'histoire (cur-6H) : sous B = froid, au-dessus = chaud.
    let boundary = cur - 6 * 3600;
    let soql = "search | timechart span=1h count";
    let from = cur - 12 * 3600;
    let rr = try_cold_rollup_route_at(soql, from, n, None, boundary, n, RollupCoverage::of(&conn), DimRollupCoverage::of(&conn))
        .expect("la ROUTE C froide DOIT router une courbe sur une fenêtre à cheval sur B");
    // Inspection PAR FRAGMENT (les fragments sont joints par ` UNION ALL `) : le froid vient de cold_rollup
    // sous B, le chaud d'event_rollup au-dessus de B, et — GARDIEN — le fragment event_rollup ne porte JAMAIS
    // `bucket < B` (sinon double lecture avec cold_rollup sous la frontière).
    let fragments: Vec<&str> = rr.sql.split(" UNION ALL ").collect();
    let frag_hot = fragments.iter().find(|f| f.contains("FROM event_rollup")).expect("un fragment corps chaud (event_rollup)");
    let frag_cold = fragments.iter().find(|f| f.contains("FROM cold_rollup")).expect("un fragment corps froid (cold_rollup)");
    assert!(frag_hot.contains(&format!("bucket >= {boundary}")), "event_rollup borné AU-DESSUS de B : {frag_hot}");
    assert!(!frag_hot.contains(&format!("bucket < {boundary}")), "GARDIEN : event_rollup n'est JAMAIS lu SOUS B : {frag_hot}");
    assert!(frag_cold.contains(&format!("bucket < {boundary}")), "cold_rollup borné SOUS B : {frag_cold}");
    assert!(!frag_cold.contains(&format!("bucket >= {boundary}")), "cold_rollup ne lit JAMAIS au-dessus de B : {frag_cold}");
    assert!(!rr.cap.plafonne(), "ROUTE C froide : Cap::Aucun (exact en somme)");
}
