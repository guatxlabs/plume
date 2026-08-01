// =====================================================================================
// L'AMPLEUR DU PLAFOND TOP-N — ce que la route écarte, et DE COMBIEN.
//
// CE QUI EST ÉPROUVÉ ICI, ET POURQUOI ÇA N'EST PAS UN CINQUIÈME MENSONGE. Le plafond top-N du rollup
// par dimension écarte VOLONTAIREMENT la queue des valeurs de chaque (bucket, env), et la route l'a
// toujours déclaré. Le reproche n'est donc pas qu'elle mente, c'est que son aveu n'était pas
// INTERPRÉTABLE : `truncated: true` ne dit pas « il en manque seize fois plus que ce que tu vois ».
// MESURÉ le 2026-08-01 sur la base de banc (1 436 026 événements, fenêtre entièrement DANS la bande
// témoignée) : de x1,00 (23 couples sur 37 : rien d'écarté) à x16,4 (auditd/exe — 24 055 servis pour
// 395 043 réels, 370 988 écartés). Voir `topn_cap` pour le tableau complet.
//
// LES PROPRIÉTÉS, dans l'ordre où elles se déduisent :
//   1. la dimension de RESTE ne peut PAS entrer en collision avec une dimension configurable ;
//   2. la ligne de reste chiffre EXACTEMENT ce que le plafond a écarté (servis + reste == vérité brute),
//      sur une FAMILLE dérivée de plafonds et de cardinalités — pas sur un cas nommé ;
//   3. elle est écrite MÊME À ZÉRO — sinon son absence serait indiscernable d'un reste nul ;
//   4. la route PUBLIE cette ampleur, et le chiffre publié est celui de l'oracle brut ;
//   5. sans lignes de reste, l'ampleur est AVOUÉE, pas supposée nulle (c'est la garde qui MORD) ;
//   6. le reste ne pollue AUCUN résultat servi (ni la route, ni les panneaux).
// =====================================================================================

    /// Sème `n` events d'une source à `ts`, chacun avec une VALEUR DISTINCTE de la dimension -> le
    /// nombre de valeurs du bucket est exactement `n`. C'est la forme qui exerce le plafond : au-delà
    /// de `topn`, la queue est écartée, et chaque valeur écartée vaut exactement un événement.
    fn amp_seed_distinct(c: &Connection, ts: i64, source: &str, dim: &str, n: usize, tag: &str) {
        for i in 0..n {
            c.execute(
                "INSERT INTO event(ts,source,fields,dedup) VALUES(?1,?2,?3,?4)",
                params![ts, source, format!("{{\"{dim}\":\"v{i}\"}}"), format!("{tag}-{i}")],
            )
            .unwrap();
        }
    }

    /// Ce que le rollup SERT pour un couple (source, dim) : la somme des lignes GARDÉES.
    fn amp_servi(c: &Connection, source: &str, dim: &str) -> i64 {
        c.query_row(
            "SELECT COALESCE(SUM(n),0) FROM event_dim_rollup WHERE source=?1 AND dim=?2",
            params![source, dim],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// Ce que le rollup dit avoir ÉCARTÉ pour ce couple : la somme des lignes de RESTE.
    fn amp_reste(c: &Connection, source: &str, dim: &str) -> i64 {
        c.query_row(
            "SELECT COALESCE(SUM(n),0) FROM event_dim_rollup WHERE source=?1 AND dim=?2",
            params![source, reste_dim(dim)],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// L'ORACLE : ce qu'`event` porte réellement pour cette source. Aucune table dérivée dans la boucle.
    fn amp_verite(c: &Connection, source: &str) -> i64 {
        c.query_row("SELECT COUNT(*) FROM event WHERE source=?1", params![source], |r| r.get(0)).unwrap()
    }

    /// (1) LA DIMENSION DE RESTE NE PEUT PAS ENTRER EN COLLISION. Elle vit dans la MÊME table que les
    /// lignes gardées — donc si une dimension configurable pouvait s'appeler `!status`, son compte se
    /// mélangerait au reste de `status`. Ce n'est pas une convention à respecter : `soql_ident_ok` filtre
    /// DÉJÀ toute dimension (défauts comme spec d'environnement) et REFUSE le préfixe. On l'épingle des
    /// deux côtés — le validateur, et le chemin réel qui l'applique.
    #[test]
    fn le_prefixe_du_reste_ne_peut_pas_etre_une_dimension() {
        assert!(!soql_ident_ok(RESTE_DIM_PREFIX), "le préfixe DOIT être hors de l'alphabet des identifiants");
        // Aucune dimension LIVRÉE ne le porte (sinon la collision serait déjà là).
        for (src, dims) in dim_rollup_specs().iter() {
            for d in dims.iter() {
                assert!(!d.starts_with(RESTE_DIM_PREFIX), "dim livrée réservée : {src}/{d}");
                assert!(soql_ident_ok(d), "dim livrée non validable : {src}/{d}");
            }
        }
        // Et la spec d'ENVIRONNEMENT ne peut pas en introduire une : `merge_rollup_dims` la rejette.
        let mut specs: Vec<(String, Vec<String>)> = Vec::new();
        merge_rollup_dims(&mut specs, &format!("web:{}collision,legitime", RESTE_DIM_PREFIX));
        let web = specs.iter().find(|(s, _)| s == "web").map(|(_, d)| d.clone()).unwrap_or_default();
        assert!(
            web.iter().all(|d| !d.starts_with(RESTE_DIM_PREFIX)),
            "une dim d'environnement a réussi à porter le préfixe réservé : {web:?}"
        );
        assert!(web.iter().any(|d| d == "legitime"), "…et la dim légitime du même groupe doit rester acceptée");
    }

    /// (2) LA LIGNE DE RESTE CHIFFRE EXACTEMENT CE QUE LE PLAFOND ÉCARTE. Propriété vérifiée sur une
    /// FAMILLE DÉRIVÉE — le produit des plafonds par les cardinalités, de part et d'autre du plafond —
    /// et non sur un cas choisi : `servi + reste == vérité brute`, à l'unité, dans chaque cellule.
    #[test]
    fn la_ligne_de_reste_chiffre_exactement_ce_que_le_plafond_ecarte() {
        let _g = ROLLUP_DIMS_ENV_LOCK.lock();
        let now_ts = now();
        let bucket = (now_ts / 3600) * 3600; // fenêtre chaude : ré-agrégée à chaque tick, aucune bande à attendre
        let mut cellules = 0usize;
        let mut avec_perte = 0usize;
        for topn in [1i64, 3, 10, 50] {
            for cardinalite in [1usize, 2, 5, 25, 60, 120] {
                let conn = test_db();
                std::env::set_var("PLUME_ROLLUP_DIM_TOPN", topn.to_string());
                amp_seed_distinct(&conn, bucket + 61, "web", "status", cardinalite, "f");
                rollup_events(&conn);
                let (servi, reste, verite) = (amp_servi(&conn, "web", "status"), amp_reste(&conn, "web", "status"), amp_verite(&conn, "web"));
                assert_eq!(
                    servi + reste,
                    verite,
                    "plafond {topn}, cardinalité {cardinalite} : servi({servi}) + reste({reste}) doit être la VÉRITÉ ({verite})"
                );
                let attendu = (cardinalite as i64 - topn).max(0);
                assert_eq!(reste, attendu, "plafond {topn}, cardinalité {cardinalite} : le reste doit valoir exactement ce qui dépasse");
                cellules += 1;
                if reste > 0 {
                    avec_perte += 1;
                }
            }
        }
        std::env::remove_var("PLUME_ROLLUP_DIM_TOPN");
        assert!(cellules >= 20, "famille trop petite pour prouver quoi que ce soit : {cellules}");
        assert!(avec_perte >= 8, "aucune cellule ne perd rien : le plafond ne serait pas exercé ({avec_perte})");
    }

    /// (3) LE RESTE EST ÉCRIT MÊME QUAND IL EST NUL. C'est ce qui rend l'ABSENCE porteuse de sens : sans
    /// cette ligne à zéro, « rien n'a été écarté ici » et « cette heure a été agrégée par un binaire qui
    /// ne le notait pas » se ressembleraient — et la route publierait un 0 qu'elle n'a pas mesuré. C'est
    /// exactement la faute des quatre correctifs précédents, prise à sa racine.
    #[test]
    fn le_reste_est_ecrit_meme_quand_il_est_nul() {
        let _g = ROLLUP_DIMS_ENV_LOCK.lock(); // le plafond est un env process-global : sans ce verrou, une
        let conn = test_db();                 // cellule voisine le change sous nos pieds (constaté).
        std::env::remove_var("PLUME_ROLLUP_DIM_TOPN");
        let bucket = (now() / 3600) * 3600;
        amp_seed_distinct(&conn, bucket + 61, "web", "status", 3, "nul"); // 3 valeurs, plafond 50 -> rien d'écarté
        rollup_events(&conn);
        let lignes: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM event_dim_rollup WHERE source='web' AND dim=?1",
                params![reste_dim("status")],
                |r| r.get(0),
            )
            .unwrap();
        let dump: Vec<(String, String, i64, i64)> = conn
            .prepare("SELECT dim, val, n, bucket FROM event_dim_rollup WHERE source='web'").unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap().map(|x| x.unwrap()).collect();
        assert_eq!(lignes, 1, "une ligne de reste par (bucket, env) DOIT exister même à zéro : {dump:?}");
        assert_eq!(amp_reste(&conn, "web", "status"), 0, "…et valoir zéro");
    }

    /// (4) LA ROUTE PUBLIE L'AMPLEUR, ET LE CHIFFRE PUBLIÉ EST CELUI DE L'ORACLE. On exécute la route ET
    /// sa sonde sur la même base, et on confronte au scan brut : ce que la route sert, plus ce qu'elle
    /// déclare écarter, égale ce qu'`event` porte. La phrase rendue à l'analyste doit porter le nombre.
    #[test]
    fn la_route_publie_une_ampleur_qui_est_celle_de_l_oracle() {
        let _g = ROLLUP_DIMS_ENV_LOCK.lock();
        let conn = test_db();
        std::env::set_var("PLUME_ROLLUP_DIM_TOPN", "5");
        let now_ts = now();
        let bucket = (now_ts / 3600) * 3600;
        amp_seed_distinct(&conn, bucket + 61, "web", "status", 37, "route");
        rollup_events(&conn);
        std::env::remove_var("PLUME_ROLLUP_DIM_TOPN");

        let rr = try_rollup_route_at(
            "search source=web | stats count by status",
            0,
            0,
            None,
            now_ts,
            RollupCoverage::unproven(),
            DimRollupCoverage::of(&conn),
        )
        .expect("ROUTE B doit router (la bande volatile témoigne du bucket courant)");
        assert!(rr.cap.plafonne(), "la ROUTE B pose un plafond");
        let servi: i64 = conn.query_row(&format!("SELECT COALESCE(SUM(\"count\"),0) FROM ({})", rr.sql), [], |r| r.get(0)).unwrap();
        let mesure = rr.cap.mesurer(&conn);
        let (ecartes, servis_mesures, total) = mesure.chiffres().expect("l'ampleur DOIT être établie : le job vient d'écrire les restes");
        let verite = amp_verite(&conn, "web");
        assert_eq!(servis_mesures, servi, "la sonde et la route doivent parler du MÊME ensemble servi");
        assert_eq!(total, verite, "servi + écarté DOIT être la vérité brute ({total} contre {verite})");
        assert_eq!(ecartes, verite - servi, "l'ampleur publiée DOIT être l'écart réel");
        assert!(ecartes > 0, "le vecteur doit réellement faire écarter quelque chose");
        // …et l'analyste doit LIRE le nombre, pas seulement le mot « tronqué ».
        let note = mesure.note().expect("une perte non nulle DOIT porter sa phrase");
        assert!(note.contains(&ecartes.to_string()), "la note doit NOMMER l'ampleur : {note}");
        assert!(note.contains(&total.to_string()), "…et le total sur lequel elle porte : {note}");
    }

    /// (5) SANS LIGNE DE RESTE, L'AMPLEUR EST AVOUÉE — PAS SUPPOSÉE NULLE. On retire les lignes de reste
    /// (l'état EXACT d'une base agrégée par un binaire antérieur, ou d'une tranche froide scellée avant
    /// ce correctif) : la route doit alors DIRE qu'elle ne sait pas, et NE PUBLIER AUCUN chiffre. Servir
    /// `écartés: 0` ici serait le même défaut que le `0` de couverture, par une autre porte.
    #[test]
    fn sans_ligne_de_reste_l_ampleur_est_avouee_pas_supposee_nulle() {
        let _g = ROLLUP_DIMS_ENV_LOCK.lock();
        let conn = test_db();
        std::env::set_var("PLUME_ROLLUP_DIM_TOPN", "5");
        let now_ts = now();
        let bucket = (now_ts / 3600) * 3600;
        amp_seed_distinct(&conn, bucket + 61, "web", "status", 37, "aveu");
        rollup_events(&conn);
        std::env::remove_var("PLUME_ROLLUP_DIM_TOPN");
        let rr = try_rollup_route_at(
            "search source=web | stats count by status", 0, 0, None, now_ts,
            RollupCoverage::unproven(), DimRollupCoverage::of(&conn),
        )
        .expect("ROUTE B");
        assert!(rr.cap.mesurer(&conn).chiffres().is_some(), "socle : avec les restes, l'ampleur est établie");

        // L'ÉTAT D'AVANT : la table porte ses comptes, mais aucune trace de ce qui a été écarté.
        conn.execute("DELETE FROM event_dim_rollup WHERE dim LIKE ?1", params![format!("{RESTE_DIM_PREFIX}%")]).unwrap();
        let mesure = rr.cap.mesurer(&conn);
        assert!(mesure.tronque(), "le plafond reste POSÉ : c'est son ampleur qui manque, pas la troncature");
        assert!(mesure.chiffres().is_none(), "AUCUN chiffre ne doit être publié quand rien ne l'établit");
        let note = mesure.note().expect("l'aveu doit être dit, pas tu");
        assert!(note.contains("n'est pas établie"), "la note doit AVOUER l'ignorance : {note}");
    }

    /// (6) LE RESTE NE POLLUE AUCUN RÉSULTAT SERVI. Il vit dans la même table que les lignes gardées :
    /// s'il fuyait, il apparaîtrait comme une VALEUR de dimension (« !status ») dans un group-by, ou
    /// gonflerait le compte d'un panneau. Les deux surfaces sont vérifiées sur la base réelle.
    #[test]
    fn la_ligne_de_reste_ne_pollue_aucun_resultat_servi() {
        let _g = ROLLUP_DIMS_ENV_LOCK.lock();
        let conn = test_db();
        std::env::set_var("PLUME_ROLLUP_DIM_TOPN", "5");
        let now_ts = now();
        let bucket = (now() / 3600) * 3600;
        amp_seed_distinct(&conn, bucket + 61, "web", "status", 37, "poll");
        rollup_events(&conn);
        std::env::remove_var("PLUME_ROLLUP_DIM_TOPN");
        let attendu = 5i64; // le plafond garde 5 valeurs -> 5 lignes, 5 événements

        let rr = try_rollup_route_at(
            "search source=web | stats count by status", 0, 0, None, now_ts,
            RollupCoverage::unproven(), DimRollupCoverage::of(&conn),
        )
        .expect("ROUTE B");
        let (lignes, somme): (i64, i64) = conn
            .query_row(&format!("SELECT COUNT(*), COALESCE(SUM(\"count\"),0) FROM ({})", rr.sql), [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(lignes, attendu, "la route ne doit rendre QUE les valeurs gardées");
        assert_eq!(somme, attendu, "…et son compte ne doit pas inclure le reste");

        // Le panneau pré-câblé lit la même table par une autre porte : même exigence.
        let sql = dim_panel_sql("web", "status", 0, false).replace("__FROM__", "0");
        let (plignes, psomme): (i64, i64) = conn
            .query_row(&format!("SELECT COUNT(*), COALESCE(SUM(count),0) FROM ({sql})"), [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!((plignes, psomme), (attendu, attendu), "le panneau ne doit pas voir le reste non plus");
    }
