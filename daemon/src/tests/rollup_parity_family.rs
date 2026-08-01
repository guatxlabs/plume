// =====================================================================================
// PARITÉ « ROUTE RAPIDE == CHEMIN BRUT » — SUR UNE FAMILLE, PAS SUR UN CAS NOMMÉ.
//
// POURQUOI CE FICHIER EXISTE. La divergence du 31/07 (`search | stats count by source,severity`,
// fenêtre au-delà de 7 j : 164 165 servis sous `approx:false` contre 1 080 321 réels, ×6,6) a été
// trouvée par un BANC, pas par la suite. Les tests B2/B2b existants couvraient chacun un vecteur
// NOMMÉ (frontières, watermark, env, déclin) et aucun ne posait la question générale : *une route
// rapide peut-elle rendre, sous `approx:false`, une valeur différente du chemin brut ?* Ici, cette
// question est posée sur un PRODUIT CARTÉSIEN dérivé, pas sur une liste :
//
//   REQUÊTES      dérivées de `ROLLUP_EXACT_DIMS` — tous les sous-ensembles routables, dans les deux
//                 ordres, avec et sans filtre `source=`. Une dim ajoutée au grain routable entre dans
//                 la famille SANS ÉDITION de ce fichier.
//   FENÊTRES      dérivées des FRONTIÈRES du plan de merge (`hour_floor`/`hour_ceil`, `recent`, la
//                 borne de couverture) : alignée, sub-horaire d'un côté, des deux, profonde,
//                 volatile pure, non bornée. Pas de dates choisies.
//   ÉTATS         dérivés du CYCLE DE VIE du rollup : jamais tické · tické · tické puis écriture À
//                 L'HEURE · tické puis écriture BACKDATÉE sous le watermark · re-tické après. C'est
//                 l'axe qui manquait, et c'est celui qui portait le défaut.
//
// L'ORACLE est le SQL compilé en brut (`soql_to_sql_x`) : le seul chemin dont l'exactitude ne
// dépend d'aucune table dérivée.
//
// LA PROPRIÉTÉ, et elle est la formulation exécutable de l'invariant de `rollup_coverage` :
//   pour toute cellule, ou bien la route DÉCLINE (le brut sert, exact par construction),
//   ou bien elle rend EXACTEMENT l'oracle,
//   ou bien elle se déclare `approx`/`truncated`.
//   JAMAIS un nombre différent de l'oracle sous `approx:false`.
// =====================================================================================

    /// Les REQUÊTES de la famille : dérivées du grain routable, jamais énumérées. Tous les
    /// sous-ensembles de taille >= 2 de `ROLLUP_EXACT_DIMS` (c'est la condition de `multidim_routable`),
    /// pris dans l'ordre naturel ET dans l'ordre inverse, × {sans filtre, avec `source=`}.
    fn parity_family_queries() -> Vec<String> {
        let dims = ROLLUP_EXACT_DIMS;
        let mut sets: Vec<Vec<&str>> = Vec::new();
        for mask in 1u32..(1 << dims.len()) {
            let sub: Vec<&str> = (0..dims.len()).filter(|i| mask & (1 << i) != 0).map(|i| dims[i]).collect();
            if sub.len() < 2 {
                continue; // single-dim = ROUTE A/B, hors du merge multi-dim (et déjà `approx:true`)
            }
            let mut rev = sub.clone();
            rev.reverse();
            sets.push(sub);
            sets.push(rev);
        }
        let mut out = Vec::new();
        for s in sets {
            for pre in ["search", "search source=web"] {
                out.push(format!("{pre} | stats count by {}", s.join(",")));
            }
        }
        out
    }

    /// Les FENÊTRES de la famille : dérivées des frontières que `plan_merge` calcule (plancher/plafond
    /// horaire, `recent`), pas d'une liste de durées. Chacune place la borne d'un côté ou de l'autre
    /// d'une frontière — c'est là que vivent les erreurs de découpe.
    fn parity_family_windows(now_ts: i64) -> Vec<(i64, i64)> {
        let cur = (now_ts / 3600) * 3600;
        let recent = cur - 3600;
        vec![
            (0, 0),                                    // non bornée des deux côtés
            (cur - 9 * 3600, now_ts),                  // from aligné, to = maintenant (tête absente, queue vive)
            (cur - 9 * 3600 + 137, now_ts),            // tête SUB-HORAIRE
            (cur - 9 * 3600, recent),                  // to PILE sur la frontière volatile
            (cur - 9 * 3600, recent - 1),              // to juste SOUS la frontière volatile
            (cur - 9 * 3600, cur - 5 * 3600),          // profonde, entièrement définitive, bornes alignées
            (cur - 9 * 3600 + 137, cur - 5 * 3600 - 41), // profonde, sub-horaire DES DEUX CÔTÉS
            (cur - 7 * 3600, cur - 6 * 3600),          // une seule heure, profonde
            (recent + 5, now_ts),                      // volatile pure -> la route doit décliner
        ]
    }

    /// Les ÉTATS de fraîcheur de la famille, dérivés du cycle de vie du rollup. Le nom dit ce que
    /// l'état FAIT, pas quel bug il reproduit.
    #[derive(Clone, Copy, Debug)]
    enum RollupState {
        /// Aucun tick n'est passé : rien n'a jamais été agrégé ni publié.
        JamaisTicke,
        /// Un tick est passé sur tout ce qui existait.
        Ticke,
        /// Un tick est passé, puis des lignes sont arrivées DANS la fenêtre volatile (cas nominal).
        TickePuisEcritureALHeure,
        /// Un tick est passé, puis des lignes sont arrivées SOUS le watermark : le cas mesuré (import
        /// d'historique, tampon d'agent hors-ligne, relais en retard). Le watermark dit « couvert »,
        /// la table ne l'est pas.
        TickePuisEcritureBackdatee,
        /// Le même, plus un tick : la réparation a-t-elle eu lieu ?
        BackdateePuisReTicke,
    }

    /// Sème le socle commun (des lignes réparties sur les heures DÉFINITIVES et sur la fenêtre
    /// volatile), puis amène le rollup dans l'état demandé. Renvoie la base prête à être interrogée.
    fn parity_family_db(state: RollupState, now_ts: i64) -> Connection {
        let conn = test_db();
        let cur = (now_ts / 3600) * 3600;
        let combos: &[(&str, i64)] = &[("web", 4), ("web", 2), ("sshd", 3), ("auditd", 3), ("firewall", 2)];
        let seed = |c: &Connection, ts: i64, n_each: usize, tag: &str| {
            for (src, sev) in combos {
                for i in 0..n_each {
                    c.execute(
                        "INSERT INTO event(ts,source,severity,host,fields,dedup) VALUES(?1,?2,?3,'h1','{}',?4)",
                        params![ts, src, sev, format!("{tag}-{src}-{sev}-{i}")],
                    )
                    .unwrap();
                }
            }
        };
        // SOCLE : heures définitives profondes + heure précédente + heure courante.
        for h in [9i64, 8, 7, 6, 5, 4, 3, 2] {
            seed(&conn, cur - h * 3600 + 61, 2, &format!("socle{h}"));
        }
        seed(&conn, cur - 3600 + 30, 2, "vol_prec");
        seed(&conn, cur + 30, 2, "vol_cur");
        match state {
            RollupState::JamaisTicke => {}
            RollupState::Ticke => rollup_events(&conn),
            RollupState::TickePuisEcritureALHeure => {
                rollup_events(&conn);
                seed(&conn, cur + 45, 3, "apres_tick_a_lheure");
            }
            RollupState::TickePuisEcritureBackdatee => {
                rollup_events(&conn);
                // SOUS le watermark (= `recent`) : la bande que le tick vient de déclarer finie.
                seed(&conn, cur - 6 * 3600 + 77, 3, "backdate");
                seed(&conn, cur - 4 * 3600 + 12, 3, "backdate2");
            }
            RollupState::BackdateePuisReTicke => {
                rollup_events(&conn);
                seed(&conn, cur - 6 * 3600 + 77, 3, "backdate");
                seed(&conn, cur - 4 * 3600 + 12, 3, "backdate2");
                rollup_events(&conn);
            }
        }
        conn
    }

    /// LA PROPRIÉTÉ. Toute cellule (requête × fenêtre × état) : décliner, ou rendre l'oracle, ou se
    /// déclarer approx/truncated. Jamais un nombre différent sous `approx:false`.
    #[test]
    fn parity_famille_route_rapide_jamais_un_faux_exact() {
        let _g = B2_ENV_LOCK.lock();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM"); // défaut = activé
        let now_ts = now();
        let queries = parity_family_queries();
        assert!(!queries.is_empty(), "la famille de requêtes est DÉRIVÉE du grain : elle ne peut pas être vide");
        let mut cellules = 0usize;
        let mut routees = 0usize;
        for state in [
            RollupState::JamaisTicke,
            RollupState::Ticke,
            RollupState::TickePuisEcritureALHeure,
            RollupState::TickePuisEcritureBackdatee,
            RollupState::BackdateePuisReTicke,
        ] {
            let conn = parity_family_db(state, now_ts);
            let cov = RollupCoverage::of(&conn);
            let dim_cov = DimRollupCoverage::of(&conn);
            for soql in &queries {
                for (from, to) in parity_family_windows(now_ts) {
                    cellules += 1;
                    let Some(rr) = try_rollup_route_at(soql, from, to, None, now_ts, cov, dim_cov) else {
                        continue; // DÉCLINE -> le compilo brut sert -> exact par construction
                    };
                    routees += 1;
                    let got = b2_map(&conn, &rr.sql);
                    let want = b2_map(&conn, &soql_to_sql_x(soql, from, to, None).unwrap());
                    if got == want {
                        continue;
                    }
                    let s: i64 = got.iter().map(|(_, c)| c).sum();
                    let w: i64 = want.iter().map(|(_, c)| c).sum();
                    assert!(
                        rr.approx || rr.cap.plafonne(),
                        "NOMBRE FAUX SOUS `approx:false` — état {state:?}, fenêtre ({from},{to})\n  \
                         requête : {soql}\n  route : {s} sur {} groupes\n  brut  : {w} sur {} groupes\n  SQL={}",
                        got.len(), want.len(), rr.sql
                    );
                }
            }
        }
        // La famille doit RÉELLEMENT exercer la route : si plus rien ne route, la propriété devient
        // vraie pour une mauvaise raison (tout décline) et le test ne prouve plus rien.
        assert!(cellules >= 100, "famille trop petite pour prouver quoi que ce soit : {cellules} cellules");
        assert!(routees > 0, "AUCUNE cellule routée : le test passerait à vide");
        eprintln!("[parité-famille] {cellules} cellules, dont {routees} servies par la route");
    }

    /// LA RÉPARATION, mesurée et non supposée. Après une écriture backdatée sous le watermark, un tick
    /// doit RENDRE la couverture vraie — c'est-à-dire faire revenir la route (et pas seulement la faire
    /// décliner pour toujours, ce qui serait honnête mais rendrait le rollup inutile après le premier
    /// import d'historique). On le vérifie sur ce que la TABLE porte, pas sur ce que le job annonce.
    #[test]
    fn parity_famille_un_tick_repare_la_couverture_backdatee() {
        let _g = B2_ENV_LOCK.lock();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        let now_ts = now();
        let cur = (now_ts / 3600) * 3600;
        let recent = cur - 3600;
        let somme_rollup = |c: &Connection| -> i64 {
            c.query_row("SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE bucket < ?1", params![recent], |r| r.get(0))
                .unwrap()
        };
        let somme_brute = |c: &Connection| -> i64 {
            c.query_row("SELECT COUNT(*) FROM event WHERE ts < ?1", params![recent], |r| r.get(0)).unwrap()
        };
        let sale = parity_family_db(RollupState::TickePuisEcritureBackdatee, now_ts);
        let manquant = somme_brute(&sale) - somme_rollup(&sale);
        assert!(manquant > 0, "le vecteur doit RÉELLEMENT créer un trou (sinon il ne teste rien)");
        let repare = parity_family_db(RollupState::BackdateePuisReTicke, now_ts);
        assert_eq!(
            somme_rollup(&repare),
            somme_brute(&repare),
            "un tick doit RÉPARER la bande backdatée (trou avant réparation : {manquant} lignes)"
        );
        // …et la couverture doit être PUBLIÉE, sinon la route déclinerait éternellement.
        assert!(
            RollupCoverage::of(&repare).late_floor_id().is_some(),
            "couverture republiée après réparation"
        );
        // …et le corps doit REDEVENIR servable sur une fenêtre profonde.
        let soql = "search | stats count by source,severity";
        assert!(
            try_rollup_route_at(soql, cur - 9 * 3600, cur - 5 * 3600, None, now_ts, RollupCoverage::of(&repare), DimRollupCoverage::of(&repare)).is_some(),
            "après réparation la route doit REPRENDRE (sinon le rollup ne sert plus à rien)"
        );
    }

    /// LA COUVERTURE NE SE DÉCLARE PAS. Une base dont le job n'a jamais publié la couverture — c'est
    /// l'état de TOUTE base antérieure à ce correctif, y compris celle du banc — ne peut pas être servie
    /// depuis le corps rollup, quoi que porte le watermark. Fail-closed par le TYPE, pas par un `if`.
    #[test]
    fn parity_famille_couverture_absente_vaut_refus_du_corps() {
        let _g = B2_ENV_LOCK.lock();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        let now_ts = now();
        let cur = (now_ts / 3600) * 3600;
        let conn = parity_family_db(RollupState::Ticke, now_ts);
        // On simule EXACTEMENT une base d'avant le correctif : watermark présent, couverture absente.
        conn.execute("DELETE FROM meta WHERE key=?1", params![META_ROLLUP_COV_ID]).unwrap();
        let cov = RollupCoverage::of(&conn);
        assert_eq!(cov.covered_below(), i64::MIN, "couverture absente -> borne effondrée");
        assert!(cov.late_floor_id().is_none(), "couverture absente -> aucun rattrapage à faire (il n'y a pas de corps)");
        for soql in parity_family_queries() {
            for (from, to) in parity_family_windows(now_ts) {
                assert!(
                    try_rollup_route_at(&soql, from, to, None, now_ts, cov, DimRollupCoverage::of(&conn)).is_none(),
                    "corps servi SANS couverture établie : {soql} ({from},{to})"
                );
            }
        }
        // …et le watermark seul ne rachète rien : c'est bien la couverture qui ouvre la porte.
        let ouverte = RollupCoverage::asserted_by_the_test(cur - 3600, i64::MAX);
        assert!(
            try_rollup_route_at("search | stats count by source,severity", cur - 9 * 3600, cur - 5 * 3600, None, now_ts, ouverte, DimRollupCoverage::of(&conn)).is_some(),
            "avec une couverture, la même requête route : la différence vient bien de la couverture"
        );
    }
