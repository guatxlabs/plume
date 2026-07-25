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
