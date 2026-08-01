// =====================================================================================
// LE ROLLUP PAR DIMENSION — LE TROU, SA FERMETURE, ET LA GARDE QUI L'EMPÊCHE DE ROUVRIR.
//
// CE QUI EST ÉPROUVÉ ICI, ET POURQUOI ÇA N'EST PAS LE MÊME DÉFAUT QU'`event_rollup`. La ROUTE B
// (`search source=X | stats count by <dim>`) s'est TOUJOURS déclarée `approx:true, truncated:true`.
// Elle ne rend donc pas un faux EXACT, et le test de parité `rollup_parity_family` ne l'accuse de
// rien. Le défaut mesuré est ailleurs : le job n'agrégeait JAMAIS plus loin que 24 h sous l'heure
// courante et posait quand même son watermark AU SOMMET — donc par-dessus tout ce qu'il n'avait pas
// vu. Mesuré sur la base de banc le 31/07 (cf. `rollup_coverage`, section « LE JUMEAU ») :
// `event_dim_rollup` comptait 19 991 événements là où `event` en portait 1 440 007, sur une bande de
// 25 heures d'un jeu de 28 jours ; et la fenêtre « au-delà de 7 j » rendait **0** contre 5 696.
//
// LES PROPRIÉTÉS, dans l'ordre où elles se déduisent :
//   1. le trou EXISTE et se REFERME  — la bande finit par couvrir tout ce qu'`event` porte ;
//   2. une écriture rétro-datée RÉTRACTE la bande, puis est ré-agrégée ;
//   3. une indisponibilité ne fait plus SAUTER la bande ;
//   4. une couverture absente vaut REFUS de la route (toute base d'avant ce correctif) ;
//   5. la route ne lit QUE des buckets témoignés — un bucket hors bande ne peut pas entrer dans le
//      compte, même s'il est physiquement dans la table ;
//   6. un `0` de couverture n'est JAMAIS rendu comme un `0` de données : la route décline.
// =====================================================================================

    /// Le grain horaire, recalculé ici : `rollup_route::hour_floor` est privé à son module.
    fn dimt_bucket(ts: i64) -> i64 {
        (ts / 3600) * 3600
    }

    /// Sème `n` events d'une source à un `ts`, avec une dim de CARDINALITÉ BASSE (sous le cap top-N,
    /// donc le rollup est exact-en-somme sur les buckets qu'il couvre — toute différence restante est
    /// alors une différence de COUVERTURE, ce qui est exactement ce qu'on mesure).
    fn dimt_seed(c: &Connection, ts: i64, source: &str, dim: &str, val: &str, n: usize, tag: &str) {
        for i in 0..n {
            c.execute(
                "INSERT INTO event(ts,source,fields,dedup) VALUES(?1,?2,?3,?4)",
                params![ts, source, format!("{{\"{dim}\":\"{val}\"}}"), format!("{tag}-{i}")],
            )
            .unwrap();
        }
    }

    /// Ce que le rollup par dimension COMPTE pour un couple (source, dim), toutes valeurs confondues.
    fn dimt_rollup_sum(c: &Connection, source: &str, dim: &str) -> i64 {
        c.query_row(
            "SELECT COALESCE(SUM(n),0) FROM event_dim_rollup WHERE source=?1 AND dim=?2",
            params![source, dim],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// L'ORACLE : ce qu'`event` porte réellement pour cette source. Pas de table dérivée dans la boucle.
    fn dimt_raw_count(c: &Connection, source: &str) -> i64 {
        c.query_row("SELECT COUNT(*) FROM event WHERE source=?1", params![source], |r| r.get(0)).unwrap()
    }

    /// Un jeu d'HISTOIRE : `days` jours d'events horaires, tous ANTÉRIEURS à la fenêtre volatile. C'est
    /// exactement la forme d'une base restaurée, d'un import d'historique ou d'un premier démarrage sur
    /// une base déjà remplie — le cas mesuré.
    fn dimt_db_avec_histoire(days: i64, now_ts: i64) -> Connection {
        let conn = test_db();
        let recent = dimt_bucket(now_ts) - 3600;
        for h in 1..=(days * 24) {
            dimt_seed(&conn, recent - h * 3600 + 61, "web", "status", if h % 2 == 0 { "200" } else { "404" }, 2, &format!("h{h}"));
        }
        conn
    }

    /// (1) LE TROU EXISTE, ET IL SE REFERME. Un tick ne peut pas tout couvrir (c'est la garde de coût
    /// qui borne chaque tick à `PLUME_ROLLUP_DIM_BACKFILL`), mais la bande DESCEND à chaque tick au lieu
    /// de rester collée sous l'heure courante — et elle finit par témoigner de tout ce qu'`event` porte.
    /// L'ANCIENNE RÈGLE ne pouvait pas passer ce test : elle plafonnait à 24 h POUR TOUJOURS.
    #[test]
    fn dim_le_trou_de_couverture_existe_et_se_referme_tick_apres_tick() {
        let now_ts = now();
        let conn = dimt_db_avec_histoire(3, now_ts);
        let verite = dimt_raw_count(&conn, "web");
        assert!(verite > 0, "le vecteur doit semer quelque chose");

        rollup_events(&conn);
        let apres_1 = dimt_rollup_sum(&conn, "web", "status");
        assert!(apres_1 < verite, "un seul tick ne peut PAS couvrir 3 jours (le pas est borné) : {apres_1} / {verite}");
        assert!(apres_1 > 0, "…mais il doit couvrir la bande la plus récente : {apres_1}");

        // La bande DESCEND. Trois jours, un pas de 24 h -> au plus trois ticks de plus.
        let mut vus = vec![apres_1];
        for _ in 0..4 {
            rollup_events(&conn);
            vus.push(dimt_rollup_sum(&conn, "web", "status"));
        }
        assert_eq!(
            *vus.last().unwrap(),
            verite,
            "la bande doit FINIR par couvrir tout ce qu'`event` porte — progression mesurée : {vus:?}"
        );
        // …et la couverture publiée doit le DIRE : son plancher atteint le plus vieux `ts` d'`event`.
        let plus_vieux: i64 = conn.query_row("SELECT MIN(ts) FROM event", [], |r| r.get(0)).unwrap();
        let (from, _below, _hot) = DimRollupCoverage::of(&conn).band().expect("couverture publiée");
        assert_eq!(from, dimt_bucket(plus_vieux), "le plancher de la bande = le plus vieux bucket qu'`event` porte encore");
    }

    /// (2) UNE ÉCRITURE RÉTRO-DATÉE RÉTRACTE LA BANDE, PUIS EST RÉ-AGRÉGÉE. C'est le vecteur qui a
    /// tué `event_rollup` (tampon d'agent hors-ligne, relais en retard, import d'historique) : le
    /// watermark disait « couvert », la table ne l'était pas. Ici la bande AVOUE d'abord (elle se
    /// rétracte au bucket sale), puis la remontée reconstruit — et le compte redevient juste.
    #[test]
    fn dim_ecriture_retrodatee_retracte_la_bande_puis_est_reagregee() {
        let now_ts = now();
        let conn = dimt_db_avec_histoire(1, now_ts);
        for _ in 0..3 {
            rollup_events(&conn); // bande établie sur toute l'histoire
        }
        let (_from, below_avant, _hot) = DimRollupCoverage::of(&conn).band().expect("couverture établie");
        assert_eq!(dimt_rollup_sum(&conn, "web", "status"), dimt_raw_count(&conn, "web"), "socle : bande à jour");

        // SOUS la bande, APRÈS sa publication : la ligne que l'ancien watermark n'aurait jamais revue.
        let recent = dimt_bucket(now_ts) - 3600;
        let retro_ts = recent - 6 * 3600 + 77;
        dimt_seed(&conn, retro_ts, "web", "status", "500", 5, "retro");
        let verite = dimt_raw_count(&conn, "web");

        rollup_events(&conn);
        let (_f2, below_apres, _h2) = DimRollupCoverage::of(&conn).band().expect("couverture republiée");
        assert!(
            below_apres <= dimt_bucket(retro_ts) + 86400,
            "la bande doit s'être RÉTRACTÉE au bucket sale (avant {below_avant}, après {below_apres}, sale {})",
            dimt_bucket(retro_ts)
        );
        for _ in 0..3 {
            rollup_events(&conn);
        }
        assert_eq!(dimt_rollup_sum(&conn, "web", "status"), verite, "la remontée doit avoir RÉ-AGRÉGÉ la bande sale");
    }

    /// (3) UNE INDISPONIBILITÉ NE FAIT PLUS SAUTER LA BANDE. On rejoue exactement l'état d'un daemon
    /// arrêté deux jours : la couverture publiée est vieille, l'heure courante est loin devant. L'ancienne
    /// règle posait `max(watermark, heure-24h)` — donc SAUTAIT la bande intermédiaire, définitivement.
    #[test]
    fn dim_indisponibilite_longue_ne_saute_plus_la_bande() {
        let now_ts = now();
        let conn = dimt_db_avec_histoire(3, now_ts);
        for _ in 0..5 {
            rollup_events(&conn);
        }
        let verite = dimt_raw_count(&conn, "web");
        assert_eq!(dimt_rollup_sum(&conn, "web", "status"), verite, "socle : tout est couvert");

        // On REJOUE l'arrêt : la table est vidée de sa bande haute et la couverture republiée deux jours
        // en arrière — l'état exact d'un daemon qui redémarre après 48 h.
        let recent = dimt_recent(now_ts);
        let vieux_below = recent - 2 * 86400;
        conn.execute("DELETE FROM event_dim_rollup WHERE bucket >= ?1", params![vieux_below]).unwrap();
        let at_id: i64 = conn.query_row("SELECT COALESCE(MAX(id),0) FROM event", [], |r| r.get(0)).unwrap();
        let (from, _b, _h) = DimRollupCoverage::of(&conn).band().unwrap();
        DimRollupCoverage::publish(&conn, from, vieux_below, vieux_below, at_id);

        rollup_events(&conn);
        let (_f, below1, _h1) = DimRollupCoverage::of(&conn).band().expect("couverture");
        assert!(below1 < recent, "la bande ne doit PAS sauter jusqu'à l'heure courante en un tick : {below1} vs {recent}");
        assert!(below1 > vieux_below, "…mais elle doit avancer : {below1} vs {vieux_below}");
        for _ in 0..3 {
            rollup_events(&conn);
        }
        assert_eq!(dimt_rollup_sum(&conn, "web", "status"), verite, "la bande sautée doit avoir été RATTRAPÉE, pas perdue");
    }

    /// `recent` du job : plancher-heure de maintenant, moins une heure.
    fn dimt_recent(now_ts: i64) -> i64 {
        dimt_bucket(now_ts) - 3600
    }

    /// (4) COUVERTURE ABSENTE = REFUS. C'est l'état de TOUTE base d'avant ce correctif : la table peut
    /// être pleine, le watermark peut dire ce qu'il veut — rien n'est ÉTABLI, donc la route décline et le
    /// chemin brut sert (exact). Fail-closed par le TYPE (aucun constructeur littéral), pas par un `if`.
    #[test]
    fn dim_couverture_absente_vaut_refus_de_la_route() {
        let now_ts = now();
        let cur = dimt_bucket(now_ts);
        let soql = "search source=web | stats count by status";
        let fenetres = [
            (0i64, 0i64),
            (cur - 9 * 3600, now_ts),
            (cur - 9 * 3600, cur - 5 * 3600),
            (cur - 30 * 86400, cur - 7 * 86400),
        ];
        for (from, to) in fenetres {
            assert!(
                try_rollup_route_at(soql, from, to, None, now_ts, RollupCoverage::unproven(), DimRollupCoverage::unproven()).is_none(),
                "ROUTE B servie SANS couverture établie : ({from},{to})"
            );
            // …et c'est bien LA COUVERTURE qui ouvre la porte : la même requête, la même fenêtre, une
            // bande témoignée -> elle route. Sinon le test passerait pour une mauvaise raison.
            assert!(
                try_rollup_route_at(
                    soql, from, to, None, now_ts,
                    RollupCoverage::unproven(),
                    DimRollupCoverage::all_asserted_by_the_test()
                )
                .is_some(),
                "avec une bande témoignée la MÊME requête doit router : ({from},{to})"
            );
        }
    }

    /// (5) LA ROUTE NE LIT QUE DES BUCKETS TÉMOIGNÉS. On empoisonne la table AVEC une ligne dans un
    /// bucket HORS de la bande publiée : si la garde de couverture n'est pas dans le SQL, elle entre dans
    /// le compte. C'est la forme la plus directe de « la garde MORD ».
    #[test]
    fn dim_route_ne_lit_que_des_buckets_temoignes() {
        let now_ts = now();
        let conn = dimt_db_avec_histoire(1, now_ts);
        for _ in 0..3 {
            rollup_events(&conn);
        }
        let (from, below, hot) = DimRollupCoverage::of(&conn).band().expect("couverture");
        // Une ligne PLANTÉE sous le plancher de la bande — donc dans un bucket dont personne ne témoigne.
        let hors = from - 10 * 3600;
        conn.execute(
            "INSERT OR REPLACE INTO event_dim_rollup(bucket,source,dim,val,n,env_id) VALUES(?1,'web','status','999',777,'prod')",
            params![hors],
        )
        .unwrap();
        let rr = try_rollup_route_at(
            "search source=web | stats count by status",
            hors - 3600,
            now_ts,
            None,
            now_ts,
            RollupCoverage::unproven(),
            DimRollupCoverage::asserted_by_the_test(from, below, hot, i64::MAX),
        )
        .expect("la fenêtre rencontre la bande -> la route sert");
        let total: i64 = conn
            .query_row(&format!("SELECT COALESCE(SUM(\"count\"),0) FROM ({})", rr.sql), [], |r| r.get(0))
            .unwrap();
        assert_eq!(total, dimt_raw_count(&conn, "web"), "le bucket hors bande ne doit PAS entrer dans le compte");
        assert!(rr.approx && rr.cap.plafonne(), "la ROUTE B reste déclarée approchée et partielle");
        // …et l'absence est NOMMÉE, pas tue : la note dit CE QUI manque, pas seulement « approximatif ».
        let note = rr.note.expect("une fenêtre qui déborde la bande doit porter une note de couverture");
        assert!(note.contains("ne couvre PAS"), "la note doit NOMMER ce qui manque : {note}");
    }

    /// (6) UN ZÉRO DE COUVERTURE N'EST JAMAIS RENDU COMME UN ZÉRO DE DONNÉES. C'est le cas mesuré sur la
    /// base de banc (fenêtre « au-delà de 7 j » : `0` servi contre 5 696 réels). La propriété est
    /// vérifiée sur une FAMILLE dérivée — tous les couples (source, dim) réellement pré-agrégés × des
    /// fenêtres placées de part et d'autre des bornes de la bande — et non sur un cas nommé.
    #[test]
    fn dim_un_zero_de_couverture_n_est_jamais_rendu_comme_un_zero_de_donnees() {
        let now_ts = now();
        let cur = dimt_bucket(now_ts);
        let recent = cur - 3600;
        // Une bande ÉTROITE et connue : [recent-24h, recent), plus la volatile. Tout ce qui est plus
        // vieux n'est témoigné par personne.
        let bande_lo = recent - 86400;
        let cov = DimRollupCoverage::asserted_by_the_test(bande_lo, recent, recent, i64::MAX);
        // Les fenêtres sont DÉRIVÉES des bornes de la bande (et non choisies), chacune avec l'attente
        // qu'elle IMPOSE. `Dehors` = aucun bucket témoigné -> décliner est la SEULE réponse admissible
        // (servir rendrait 0). `Dedans` = la fenêtre est couverte -> servir sans caveat de couverture.
        // `Cheval` = elle déborde -> servir en NOMMANT ce qui manque.
        #[derive(Clone, Copy, Debug)]
        enum Attente {
            Dehors,
            Dedans,
            Cheval,
        }
        let fenetres = [
            (bande_lo - 20 * 86400, bande_lo - 1, Attente::Dehors), // entièrement SOUS la bande
            (bande_lo - 5 * 86400, bande_lo + 3600, Attente::Cheval), // à cheval sur le plancher
            (bande_lo + 3600, recent - 3600, Attente::Dedans),      // entièrement DEDANS la bande prouvée
            (recent + 60, now_ts, Attente::Dedans),                 // entièrement dans la volatile
            (bande_lo - 5 * 86400, now_ts, Attente::Cheval),        // à cheval des deux côtés
        ];
        let mut testees = 0usize;
        let mut declinees = 0usize;
        for (src, dims) in dim_rollup_specs().iter() {
            for dim in dims.iter() {
                let soql = format!("search source={src} | stats count by {dim}");
                for (from, to, attente) in fenetres {
                    testees += 1;
                    let rr = try_rollup_route_at(&soql, from, to, None, now_ts, RollupCoverage::unproven(), cov);
                    match (attente, rr) {
                        (Attente::Dehors, None) => declinees += 1,
                        (Attente::Dehors, Some(_)) => panic!(
                            "ZÉRO DE COUVERTURE SERVI COMME UN ZÉRO DE DONNÉES : {soql} ({from},{to}) — \
                             aucun bucket n'est témoigné sur cette fenêtre, la route DOIT décliner"
                        ),
                        (_, None) => declinees += 1, // décliner reste toujours permis : le brut sert, exact
                        (Attente::Dedans, Some(r)) => {
                            let note = r.note.unwrap_or_default();
                            assert!(
                                !note.contains("ne couvre PAS"),
                                "caveat de couverture posé sur une fenêtre COUVERTE : {soql} ({from},{to}) note={note}"
                            );
                        }
                        (Attente::Cheval, Some(r)) => {
                            let note = r.note.unwrap_or_default();
                            assert!(
                                note.contains("ne couvre PAS"),
                                "débordement NON nommé : {soql} ({from},{to}) note={note}"
                            );
                        }
                    }
                }
            }
        }
        assert!(testees >= 100, "famille trop petite pour prouver quoi que ce soit : {testees}");
        assert!(declinees > 0, "aucune cellule déclinée : la garde ne mordrait rien");
    }

    /// (7) LA RÉTENTION SUPPRIME DES BUCKETS — LA BANDE DOIT REMONTER SON PLANCHER. Sinon la couverture
    /// témoignerait d'un intervalle dont la purge vient d'effacer le bas : la même erreur, par une autre
    /// porte. Le plancher est remonté au cutoff (conservateur), et si la purge dépasse le haut de la bande,
    /// la couverture est RÉTRACTÉE — jamais une bande vide déclarée pleine.
    #[test]
    fn dim_la_purge_de_retention_remonte_le_plancher_de_la_bande() {
        let conn = test_db();
        DimRollupCoverage::publish(&conn, 1_000_000, 2_000_000, 2_000_000, 42);
        // Purge SOUS la bande : rien à remonter.
        DimRollupCoverage::raise_floor(&conn, 900_000);
        assert_eq!(DimRollupCoverage::of(&conn).band(), Some((1_000_000, 2_000_000, 2_000_000)), "purge sous la bande -> inchangée");
        // Purge DANS la bande : le plancher remonte au cutoff, le reste est conservé.
        DimRollupCoverage::raise_floor(&conn, 1_500_000);
        assert_eq!(DimRollupCoverage::of(&conn).band(), Some((1_500_000, 2_000_000, 2_000_000)), "plancher remonté au cutoff");
        // Purge AU-DELÀ du haut : plus rien de prouvé -> aveu, donc refus de la route.
        DimRollupCoverage::raise_floor(&conn, 2_000_000);
        assert_eq!(DimRollupCoverage::of(&conn).band(), None, "bande entièrement purgée -> couverture RÉTRACTÉE");
        assert_eq!(DimRollupCoverage::of(&conn), DimRollupCoverage::unproven());
    }

    /// RÉSIDU VOISIN — LA ROUTE A (`stats count by source`) NE CONSULTE AUCUNE COUVERTURE, ET ELLE PEUT
    /// SUR-COMPTER. `rollup_events` ne redescend JAMAIS sous `MIN(event.ts)` : les buckets plus anciens
    /// sont l'histoire que SEUL `event_rollup` garde (lignes agées en Parquet, purge non symétrique). La
    /// ROUTE A les lit — donc sur une fenêtre qui descend sous `MIN(event.ts)` elle rend PLUS que le
    /// scan brut. Ce n'est pas un mensonge (`approx:true` a toujours été posé), mais ce n'était PROUVÉ
    /// par aucun test : ce test le PIN, pour qu'un futur passage à `approx:false` casse ici et pas en
    /// production.
    ///
    /// ────────────────────────────────────────────────────────────────────────────────────────────
    /// LA DÉCISION (2026-08-01) : ON LAISSE — ET VOICI CE QUI LA SOUTIENT.
    ///
    /// Le point à trancher n'était pas « est-ce que ça arrive dans ce test » (il le fabrique), mais
    /// « PAR QUELLE PORTE la production y entre ». Il y en a deux, et elles ont été mesurées :
    ///
    ///   PORTE 1 — LA RÉTENTION. FERMÉE, prouvé par `la_retention_ne_laisse_jamais_le_rollup_plus_vieux_qu_event`
    ///     (module `topn_ampleur`). `retention_run_tenant` purge `event` par `ts < cutoff` ET
    ///     `event_rollup` par `bucket < cutoff` ; comme un bucket commence AVANT les `ts` qu'il
    ///     contient, le rollup est toujours purgé AU MOINS aussi profond — et même davantage, les
    ///     sources de contrôle (`origin='daemon'`) étant épargnées dans `event` et pas dans le rollup.
    ///     Le sur-compte est donc INATTEIGNABLE par là. Contrepartie MESURÉE et épinglée par ce même
    ///     test : un SOUS-compte confiné au seul bucket qui chevauche le cutoff.
    ///
    ///   PORTE 2 — LE TIER FROID. OUVERTE dans la TABLE, fermée sur le CHEMIN SERVI. Le vieillissement
    ///     supprime les lignes d'`event` d'un jour scellé sans toucher aux rollups (délibéré :
    ///     `cold_rollup`/`cold_dim_rollup` servent ces heures). Mais une fenêtre qui descend sous la
    ///     frontière `B` est servie par la route COLD (`query.rs` : `from < B` -> `cold_boundary`), qui
    ///     partitionne à `B` et n'a JAMAIS le droit de lire `event_rollup` en dessous — épinglé par un
    ///     piège explicite (`phase_a_hot_cold_union_no_double_count_at_boundary`, feature `cold_tier`,
    ///     une ligne stale à `n=999` sous `B` que la route DOIT exclure).
    ///
    /// IL NE RESTE QUE « le tier froid a tourné, puis a été désactivé ». Là, la ROUTE A sert la mémoire
    /// que le rollup garde d'événements qui ont RÉELLEMENT existé (ils sont en Parquet, simplement
    /// illisibles dans ce mode), sous `approx:true` — et la ROUTE B fait EXACTEMENT LA MÊME CHOSE, sa
    /// bande n'étant remontée que par la rétention (`raise_floor`) et jamais par le vieillissement. Les
    /// deux routes restent donc D'ACCORD ENTRE ELLES ; la seule divergence est route-contre-brut, et
    /// elle est déclarée. CORRIGER voudrait dire clamper la ROUTE A au plancher d'`event`, c'est-à-dire
    /// EFFACER de la réponse des événements réels sur le seul chemin qui les compte encore — un
    /// sous-compte choisi pour éviter un sur-compte subi. On garde donc l'état actuel, épinglé ici.
    /// ────────────────────────────────────────────────────────────────────────────────────────────
    #[test]
    fn route_a_sur_compte_sous_le_plancher_event_et_le_declare() {
        let now_ts = now();
        let conn = dimt_db_avec_histoire(2, now_ts);
        rollup_events(&conn);
        let recent = dimt_recent(now_ts);
        // On PURGE le brut sous une frontière (ce que fait la rétention, ou l'aging vers le Parquet) sans
        // toucher au rollup : `event_rollup` garde alors une histoire qu'`event` n'a plus.
        let frontiere = recent - 86400;
        conn.execute("DELETE FROM event WHERE ts < ?1", params![frontiere]).unwrap();
        let brut: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE source='web'", [], |r| r.get(0)).unwrap();
        let rr = try_rollup_route_at(
            "search | stats count by source",
            0,
            0,
            None,
            now_ts,
            RollupCoverage::unproven(),
            DimRollupCoverage::unproven(),
        )
        .expect("ROUTE A route toujours (elle n'a jamais dépendu de la couverture)");
        let total: i64 = conn
            .query_row(&format!("SELECT COALESCE(SUM(\"count\"),0) FROM ({}) WHERE \"source\"='web'", rr.sql), [], |r| r.get(0))
            .unwrap();
        assert!(total > brut, "ROUTE A doit SUR-compter sous le plancher d'`event` ({total} contre {brut} en brut)");
        assert!(rr.approx, "…et elle DOIT le déclarer : un sur-compte sous `approx:false` serait un nombre faux");
    }

    /// RÉSIDU VOISIN — LA ROUTE A BÉNÉFICIE DE LA RÉPARATION D'`event_rollup`, ET C'EST MAINTENANT
    /// PROUVÉ ICI. Elle lit tous les buckets sans consulter la couverture ; jusqu'ici, rien dans la
    /// route ne montrait qu'après une écriture rétro-datée elle redevenait juste. C'est le tick qui le
    /// lui donne — ce test le tient.
    #[test]
    fn route_a_redevient_juste_apres_reparation_du_rollup() {
        let now_ts = now();
        let conn = dimt_db_avec_histoire(1, now_ts);
        rollup_events(&conn);
        let recent = dimt_recent(now_ts);
        dimt_seed(&conn, recent - 5 * 3600 + 33, "web", "status", "500", 7, "retro-a");
        let verite: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE source='web'", [], |r| r.get(0)).unwrap();
        let route_total = |c: &Connection| -> i64 {
            let rr = try_rollup_route_at(
                "search | stats count by source", 0, 0, None, now_ts,
                RollupCoverage::unproven(), DimRollupCoverage::unproven(),
            )
            .expect("ROUTE A");
            c.query_row(&format!("SELECT COALESCE(SUM(\"count\"),0) FROM ({}) WHERE \"source\"='web'", rr.sql), [], |r| r.get(0))
                .unwrap()
        };
        assert!(route_total(&conn) < verite, "avant le tick, la ligne rétro-datée manque au rollup (c'est le vecteur)");
        rollup_events(&conn);
        assert_eq!(route_total(&conn), verite, "après le tick, la RÉPARATION d'`event_rollup` rend la ROUTE A juste");
    }
