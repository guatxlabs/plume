// QUERY-VERIFY — preuve que le CHEMIN DE REQUÊTE SOC ne PERD JAMAIS silencieusement d'événements.
// On compile la VRAIE SoQL via le choke-point du daemon (`crate::soql_to_sql_masked_x` -> store().schema =
// events()), puis on EXÉCUTE le SQL émis sur une base in-memory au schéma de prod (`test_db()`), en installant
// la même UDF `regexp` que la connexion de lecture du daemon (`crate::query_exec::install_query_udfs`) pour les
// requêtes `=~`. On vérifie l'ensemble de lignes RENDU contre un ensemble ATTENDU calculé à la main.
//
// Réutilise les helpers du module `tests` (mêmes includes) : `test_db()`, `ks_run_page()`, `ks_col()`.

    // `FieldMaskSet` est déjà `use`é par keyset.rs (même module `tests` via include!) -> on le qualifie complet.

    // Insère un event source=auditd avec message + severity + fields explicites.
    fn qv_ins(c: &Connection, ts: i64, sev: i64, msg: &str, fields: &str) {
        c.execute(
            "INSERT INTO event(ts,source,severity,message,fields,origin) VALUES(?1,'auditd',?2,?3,?4,'')",
            params![ts, sev, msg, fields],
        )
        .unwrap();
    }

    // Compile la SoQL (fenêtre from/to), l'exécute sur `c`, renvoie la LISTE ORDONNÉE des ts rendus.
    fn qv_ts(c: &Connection, soql: &str, from: i64, to: i64) -> Vec<i64> {
        let sql = crate::soql_to_sql_masked_x(soql, from, to, None, &guatx_core::soql::FieldMaskSet::new())
            .unwrap_or_else(|e| panic!("compile SoQL a échoué pour `{soql}` : {e}"));
        let v = ks_run_page(c, &sql);
        let ti = ks_col(&v, "ts");
        v["rows"].as_array().unwrap().iter().map(|r| r[ti].as_i64().unwrap()).collect()
    }

    // Idem mais renvoie juste le nombre de lignes.
    fn qv_count(c: &Connection, soql: &str, from: i64, to: i64) -> usize {
        qv_ts(c, soql, from, to).len()
    }

    // ---------------------------------------------------------------------------------------------
    // (1) BORNES TEMPORELLES INCLUSIVES — aucune perte de bord. `from`>0 -> `ts >= from` ; `to`>0 -> `ts <= to`.
    // ---------------------------------------------------------------------------------------------
    #[test]
    fn qv_time_bounds_inclusive_no_edge_loss() {
        let c = test_db();
        for ts in [100, 200, 300, 400, 500] {
            qv_ins(&c, ts, 1, "x", "{}");
        }
        // Fenêtre [200,400] : les DEUX bornes doivent être RENDUES (inclusif), 100 et 500 exclus.
        let mut got = qv_ts(&c, "search source=auditd", 200, 400);
        got.sort();
        assert_eq!(got, vec![200, 300, 400], "bornes INCLUSIVES : 200 et 400 présents, 100/500 exclus");

        // Sans borne (0,0) -> les 5.
        let mut all = qv_ts(&c, "search source=auditd", 0, 0);
        all.sort();
        assert_eq!(all, vec![100, 200, 300, 400, 500], "from=0,to=0 -> aucune borne -> tout");

        // Borne basse seule (250,0) -> 300,400,500 (250 non présent en data ; 300 est >= 250).
        let mut lo = qv_ts(&c, "search source=auditd", 250, 0);
        lo.sort();
        assert_eq!(lo, vec![300, 400, 500], "from=250,to=0 -> ts >= 250, aucune borne haute");
    }

    // ---------------------------------------------------------------------------------------------
    // (2) REGEX SUR message (`=~`) — l'UDF regexp FILTRE réellement (pas un pass-through).
    // ---------------------------------------------------------------------------------------------
    #[test]
    fn qv_regex_message() {
        let c = test_db();
        crate::query_exec::install_query_udfs(&c); // UDF `regexp` (comme la connexion de lecture du daemon)
        qv_ins(&c, 100, 1, "login failed", "{}");
        qv_ins(&c, 200, 1, "login ok", "{}");
        qv_ins(&c, 300, 1, "LOGIN FAILED", "{}"); // casse différente -> capté par (?i)
        qv_ins(&c, 400, 1, "sudo cmd", "{}");

        // (?i)^login failed$ -> matche EXACTEMENT "login failed" et "LOGIN FAILED" (2), pas "login ok"/"sudo cmd".
        let mut got = qv_ts(&c, r#"search source=auditd | where message =~ "(?i)^login failed$""#, 0, 0);
        got.sort();
        assert_eq!(got, vec![100, 300], "regex insensible à la casse -> exactement les 2 matches");

        // Motif non-correspondant -> 0 ligne : prouve que l'UDF FILTRE (sinon les 4 passeraient).
        let n = qv_count(&c, r#"search source=auditd | where message =~ "zzz""#, 0, 0);
        assert_eq!(n, 0, "motif sans correspondance -> 0 ligne (l'UDF filtre vraiment)");
    }

    // ---------------------------------------------------------------------------------------------
    // (3) FILTRE SUR CHAMP JSON — `user=alice` -> json_extract(fields,'$.user')='alice' ; regex idem.
    // ---------------------------------------------------------------------------------------------
    #[test]
    fn qv_regex_json_field() {
        let c = test_db();
        crate::query_exec::install_query_udfs(&c);
        qv_ins(&c, 100, 1, "m", r#"{"user":"alice"}"#);
        qv_ins(&c, 200, 1, "m", r#"{"user":"bob"}"#);

        // Filtre d'égalité de base sur un champ JSON -> exactement 1 ligne (alice).
        let got = qv_ts(&c, "search source=auditd user=alice", 0, 0);
        assert_eq!(got, vec![100], "user=alice via json_extract -> exactement 1 ligne");

        // Même résultat via regex sur le champ JSON.
        let got_re = qv_ts(&c, r#"search source=auditd | where user =~ "^al""#, 0, 0);
        assert_eq!(got_re, vec![100], "user =~ ^al -> exactement 1 ligne (alice), bob exclu");
    }

    // ---------------------------------------------------------------------------------------------
    // (4) TERME LIBRE (LIKE) et le JOKER `*`. On DOCUMENTE le comportement RÉEL de `search *`.
    // ---------------------------------------------------------------------------------------------
    #[test]
    fn qv_freetext_and_star() {
        let c = test_db();
        qv_ins(&c, 100, 1, "alpha one", "{}");
        qv_ins(&c, 200, 1, "beta two", "{}");

        // Terme libre -> message LIKE '%alpha%' -> 1 ligne.
        let got = qv_ts(&c, "search source=auditd alpha", 0, 0);
        assert_eq!(got, vec![100], "terme libre `alpha` -> LIKE %alpha% -> 1 ligne");

        // COMPORTEMENT RÉEL de `search *` : le compilateur intercepte `*` SEUL comme le JOKER SIEM « tous les
        // événements » (aucun filtre plein-texte) -> renvoie TOUTES les lignes, PAS 0. (Contredit l'hypothèse
        // « *` -> LIKE %*% -> 0 ligne » : ce n'est PAS un terme littéral.)
        let mut star = qv_ts(&c, "search *", 0, 0);
        star.sort();
        assert_eq!(star, vec![100, 200], "`search *` = JOKER match-all -> TOUTES les lignes (PAS 0, PAS littéral)");

        // Le SQL émis pour `search *` ne contient AUCUN filtre `message LIKE` (preuve que `*` n'est pas littéral).
        let star_sql = crate::soql_to_sql_masked_x("search *", 0, 0, None, &guatx_core::soql::FieldMaskSet::new()).unwrap();
        assert!(!star_sql.contains("LIKE '%*%'"), "`*` NE compile PAS en LIKE '%*%' : {star_sql}");
    }

    // ---------------------------------------------------------------------------------------------
    // (5) COMBO COMPLEXE — fenêtre temporelle + `where severity>=3` + regex + `sort -ts`.
    //     Croisé contre un ensemble attendu calculé à la main.
    // ---------------------------------------------------------------------------------------------
    #[test]
    fn qv_complex_combo() {
        let c = test_db();
        crate::query_exec::install_query_udfs(&c);
        //     ts   sev  message           dans le résultat ?
        qv_ins(&c, 100, 5, "alert boom", "{}");   // hors fenêtre (from=150)
        qv_ins(&c, 200, 2, "alert low", "{}");    // severity 2 < 3 -> exclu
        qv_ins(&c, 250, 4, "alert alpha", "{}");  // GARDÉ
        qv_ins(&c, 300, 4, "alert fire", "{}");   // GARDÉ
        qv_ins(&c, 400, 5, "noise", "{}");        // regex `alert` ne matche pas -> exclu
        qv_ins(&c, 500, 4, "alert storm", "{}");  // hors fenêtre (to=400)

        // Fenêtre [150,400] : {200,250,300,400}. severity>=3 : {250,300,400}. regex alert : {250,300}. -ts : [300,250].
        let got = qv_ts(
            &c,
            r#"search source=auditd | where severity>=3 | where message =~ "alert" | sort -ts"#,
            150,
            400,
        );
        assert_eq!(got, vec![300, 250], "combo fenêtre+severity+regex+sort -> exactement [300,250] (ordre DESC)");
    }

    // ---------------------------------------------------------------------------------------------
    // (6) GARDE DE BUDGET — ce qu'elle DOIT protéger, et ce qu'elle NE DOIT PAS coûter.
    //
    // L'ancienne garde SONDAIT un drapeau (`sleep(50 ms)` en boucle) et le chemin de requête la
    // JOIGNAIT avant de rendre sa réponse : toute lecture était donc arrondie au multiple de 50 ms
    // supérieur (mesuré sur la base de banc : SQL 0,76 ms -> 50,7 ms de `server_ms`). Les trois tests
    // ci-dessous épinglent, dans cet ordre : (a) la protection MORD toujours, (b) elle ne coûte plus
    // l'arrondi — sur les DEUX portes d'exécution, (c) aucune autre porte ne peut apparaître.
    // ---------------------------------------------------------------------------------------------

    /// Un SELECT dont la durée est PARAMÉTRABLE, sans horloge ni dépendance à la machine : une CTE
    /// récursive qui compte jusqu'à `n`. `readonly()` vaut vrai (c'est un SELECT) -> passe la garde
    /// `stmt.readonly()` de `run_on_conn`.
    fn qb_slow_sql(n: i64) -> String {
        format!("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < {n}) SELECT count(*) FROM c")
    }

    /// (a) LA PROTECTION MORD. Une requête qui dépasse son budget DOIT être interrompue et remonter
    /// l'erreur de budget — sinon un scan fou monopoliserait un thread de lecture et un permit du
    /// sémaphore sans fin. C'est ce que la garde existe pour empêcher ; le levier de latence ne doit
    /// pas l'échanger contre des millisecondes.
    #[test]
    fn budget_guard_interrupts_a_runaway_query() {
        let c = test_db();
        let t0 = std::time::Instant::now();
        // 400 millions d'itérations : des dizaines de secondes sans garde, ~0,3 s avec.
        let r = crate::query_exec::run_on_conn(&c, ":memory:", &qb_slow_sql(400_000_000), 300, None);
        let waited = t0.elapsed();
        let err = r.expect_err("une requête au-delà de son budget DOIT être interrompue, pas rendue");
        assert!(
            err.contains("budget"),
            "l'erreur doit NOMMER le budget (et non se confondre avec une annulation utilisateur) : {err}"
        );
        // Borne LARGE (10 s) : on prouve que l'interruption tombe, pas la précision de l'échéance —
        // une borne serrée serait floconneuse sur une machine chargée.
        assert!(waited < std::time::Duration::from_secs(10), "l'interruption doit tomber près de l'échéance, pas après : {waited:?}");
    }

    /// (b) LA GARDE NE QUANTIFIE PLUS LA LATENCE — sur les DEUX portes d'exécution bornées du daemon
    /// (`run_on_conn`, qui sert /api/query, et `read_with_watchdog`, qui sert alertes/cases/fraîcheur/
    /// /api/search). On mesure le SURCOÛT (mur total − durée SQL rapportée) et on prend le MINIMUM sur
    /// plusieurs tirs : le minimum est insensible aux pics de charge, alors que l'arrondi au tick, lui,
    /// est DÉTERMINISTE (il ne peut pas être « chanceux »). Avec le sondage `sleep(50 ms)`, ce minimum
    /// valait ~50 ms − durée SQL ; ici il doit rester très en dessous d'un demi-tick.
    #[test]
    fn budget_guard_does_not_quantize_query_latency() {
        let c = test_db();
        // Requête volontairement PLUS LONGUE que le démarrage d'un thread (~50 µs) et bien plus courte
        // qu'un tick : sinon la course « la requête finit avant que la garde ne s'endorme » masquerait
        // l'arrondi et le test passerait même en présence du défaut.
        let sql = qb_slow_sql(2_000);
        let mut min_overhead_ms = f64::MAX;
        let mut min_sql_ms = f64::MAX;
        for _ in 0..7 {
            let t0 = std::time::Instant::now();
            let v = crate::query_exec::run_on_conn(&c, ":memory:", &sql, 60_000, None).expect("la requête doit aboutir");
            let wall_ms = t0.elapsed().as_secs_f64() * 1000.0;
            let sql_ms = v["stats"]["elapsed_ms"].as_f64().expect("stats.elapsed_ms");
            min_overhead_ms = min_overhead_ms.min(wall_ms - sql_ms);
            min_sql_ms = min_sql_ms.min(sql_ms);
        }
        // La requête doit bien être dans la fenêtre où l'arrondi serait visible (garde-fou du test
        // lui-même : si la CTE devenait instantanée ou dépassait 50 ms, le test ne prouverait rien).
        assert!(
            (0.2..45.0).contains(&min_sql_ms),
            "la requête témoin doit coûter entre 0,2 et 45 ms pour que l'arrondi au tick de 50 ms soit observable (mesuré {min_sql_ms:.2} ms)"
        );
        assert!(
            min_overhead_ms < 20.0,
            "run_on_conn : surcoût minimal {min_overhead_ms:.2} ms — au-delà de 20 ms la latence est arrondie au tick de la garde (le sondage est revenu)"
        );

        // MÊME preuve sur l'autre porte. `read_with_watchdog` prend une connexion DANS LE POOL du
        // db_path ; on l'exerce sur une base fichier temporaire pour que le pool puisse l'ouvrir.
        let _tmpg1 = crate::tmp_possede::TmpPossede::neuf("budget-guard");
        let dir = _tmpg1.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let dbp = dir.join("q.db");
        let dbps = dbp.to_string_lossy().to_string();
        {
            let c2 = Connection::open(&dbp).unwrap();
            c2.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&c2), "fixture de test : la chaîne de migrations doit aller au bout");
        }
        let mut min_overhead2 = f64::MAX;
        for _ in 0..7 {
            let t0 = std::time::Instant::now();
            let sql_ms = crate::query_exec::read_with_watchdog(&dbps, -1.0f64, |conn| {
                let t1 = std::time::Instant::now();
                let _n: i64 = conn.query_row(&sql, [], |r| r.get(0)).unwrap();
                t1.elapsed().as_secs_f64() * 1000.0
            });
            assert!(sql_ms >= 0.0, "read_with_watchdog n'a pas pu ouvrir la base de test");
            min_overhead2 = min_overhead2.min(t0.elapsed().as_secs_f64() * 1000.0 - sql_ms);
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            min_overhead2 < 20.0,
            "read_with_watchdog : surcoût minimal {min_overhead2:.2} ms — la latence des listes/panneaux est arrondie au tick de la garde"
        );
    }

    /// (c) AUCUNE AUTRE PORTE. Le défaut corrigé n'était pas « une ligne à changer » : c'était DEUX
    /// gardes de budget écrites à la main, chacune avec sa boucle de sondage, et rien n'empêchait une
    /// troisième d'apparaître. L'invariant DÉRIVÉ est : un `InterruptHandle` ne peut être armé que par
    /// les deux mécanismes sanctionnés — `budget_guard` (budget temps, attente à CONDITION) ou
    /// `cancel_register` (annulation utilisateur). Tout nouveau site qui prendrait un handle pour
    /// piloter son propre fil de garde fait rougir ce test, sans qu'il ait besoin d'être énuméré ici.
    #[test]
    fn budget_guard_is_the_only_way_to_arm_an_interrupt() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sites: Vec<(String, String)> = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    // `src/tests/` est du code de test : il a le droit d'exercer les primitives.
                    if p.file_name().map(|n| n == "tests").unwrap_or(false) {
                        continue;
                    }
                    stack.push(p);
                    continue;
                }
                if p.extension().map(|x| x != "rs").unwrap_or(true) {
                    continue;
                }
                let src = std::fs::read_to_string(&p).unwrap();
                for line in src.lines() {
                    if line.contains("get_interrupt_handle()") {
                        sites.push((p.strip_prefix(&root).unwrap().to_string_lossy().to_string(), line.trim().to_string()));
                    }
                }
            }
        }
        assert!(!sites.is_empty(), "invariant vide = invariant mort : aucun site d'armement trouvé, la sonde est cassée");
        for (file, line) in &sites {
            assert!(
                line.contains("budget_guard(") || line.contains("cancel_register("),
                "{file} arme un InterruptHandle hors des deux mécanismes sanctionnés \
                 (`budget_guard` = budget temps par attente à condition, `cancel_register` = annulation \
                 utilisateur). Une garde écrite à la main réintroduit le sondage et son arrondi : {line}"
            );
        }
        // Et le sondage lui-même ne doit plus exister dans l'exécuteur de lecture : c'est là que les
        // deux boucles vivaient, et c'est la forme (pas le site) qu'on interdit.
        let qe = std::fs::read_to_string(root.join("query_exec.rs")).unwrap();
        assert!(
            !qe.lines().any(|l| l.contains("thread::sleep") && !l.trim_start().starts_with("//")),
            "query_exec.rs ne doit plus attendre par SONDAGE : une garde de budget attend une CONDITION (condvar avec délai)"
        );
    }

    // ===================== P7.3-b/c — L'EXPORT AVOUE DANS LE FICHIER =====================
    // Le handler `export` n'avait AUCUN test. Ce qui est éprouvé ici, c'est la RÈGLE : ce que le
    // nom du fichier doit dire, pour toute combinaison (tronqué ?, ampleur connue ?).

    /// L'INVARIANT ANTI-OUBLI, dérivé sur la famille ENTIÈRE des cas plutôt qu'énuméré sur trois
    /// exemples choisis : la marque est présente SI ET SEULEMENT SI le résultat est tronqué. Aucun
    /// couple (tronqué, ampleur) ne peut produire un nom d'apparence complète.
    #[test]
    fn la_marque_de_troncature_est_presente_exactement_quand_le_resultat_est_tronque() {
        for tronque in [false, true] {
            for ecartes in [None, Some(-1), Some(0), Some(1), Some(42), Some(16_420)] {
                let m = marque_troncature(tronque, ecartes);
                assert_eq!(
                    !m.is_empty(), tronque,
                    "marque présente <=> tronqué (tronqué={tronque}, ecartes={ecartes:?}, marque={m:?})"
                );
                if tronque {
                    assert!(m.contains("TRONQUE"), "un nom tronqué doit se lire comme tel : {m:?}");
                }
            }
        }
    }

    /// L'AMPLEUR quand elle est connue — le NOMBRE lui-même est dans le nom, pas seulement un
    /// drapeau. C'est ce qui manquait au top-N, où une perte jusqu'à x16,42 tenait dans un booléen.
    #[test]
    fn la_marque_porte_le_nombre_de_lignes_manquantes_quand_il_est_mesure() {
        for n in [1_i64, 7, 4_242] {
            let m = marque_troncature(true, Some(n));
            assert!(m.contains(&n.to_string()), "l'ampleur mesurée ({n}) doit figurer dans le nom : {m:?}");
            assert!(!m.contains("inconnue"), "ampleur mesurée -> jamais « inconnue » : {m:?}");
        }
    }

    /// UNE AMPLEUR NON ÉTABLIE S'AVOUE — elle n'est pas repliée sur zéro. `None` (sonde sans base)
    /// et `Some(0)` (aucune ligne écartée COMPTÉE) valent tous deux « inconnue » ici : le plafond a
    /// mordu, donc annoncer « 0 ligne manquante » serait un chiffre faux, pas une absence de perte.
    #[test]
    fn une_ampleur_non_etablie_est_avouee_pas_supposee_nulle() {
        for ecartes in [None, Some(0), Some(-3)] {
            let m = marque_troncature(true, ecartes);
            assert!(m.contains("ampleur-inconnue"), "ampleur non établie ({ecartes:?}) -> aveu explicite : {m:?}");
            assert!(!m.contains("-0-"), "jamais « 0 ligne manquante » sur une ampleur non établie : {m:?}");
        }
    }
