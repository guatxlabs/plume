    // ================================================================================================
    // P11.1-b — LE FILTRE `source` DE /api/alerts ET /api/alerts/groups EST UN PRÉDICAT D'IMPUTATION EXACT.
    //
    // CE QUI ÉTAIT LA LIMITE. La facette source de la liste des alertes était évaluée CÔTÉ CLIENT, sur les
    // alertes actives bornées à 200 : sous cette facette, les tris groupés et la portée « tous statuts »
    // étaient désactivés avec leur raison. Le serveur stocke pourtant l'imputation (`alert.sources`,
    // migration v115) : une liste de noms séparés par un saut de ligne, encodée par `imputation_encoder`.
    //
    // CE QUE CES TESTS PROUVENT, ET DANS QUEL ORDRE :
    //   1. L'EXACTITUDE : `?source=k8s` rend les alertes imputées à `k8s` — y compris celles imputées à DEUX
    //      sources — et AUCUNE de celles imputées à `k8s-audit`, `audit-k8s` ou `K8S`. Le mutant naïf
    //      (`LIKE '%k8s%'`) est joué sur la MÊME fixture pour montrer qu'il prend les trois : c'est la
    //      preuve que la fixture discrimine, donc que le témoin rougirait sous cette mutation.
    //   2. LA COMPOSITION avec statut, technique et « hors case », et le `total` sous le même WHERE.
    //   3. LES ROUTES GROUPÉES : groupes restreints, compte par groupe restreint, APERÇU re-scopé à la source
    //      (la plus récente du groupe qui n'est pas imputée à la source ne devient pas le titre échantillon),
    //      et expansion d'un groupe filtrée.
    //   4. LA BORNE : une valeur de contrôle ou trop longue est REFUSÉE (400 par le routeur réel), jamais
    //      transformée en liste vide.
    //   5. LA DÉRIVATION : le prédicat SQL lit le séparateur de l'encodeur — encoder puis filtrer retrouve
    //      chaque nom entier et aucun fragment.
    //
    // LA LIMITE NOMMÉE : une alerte d'AVANT la migration (`sources=''`) n'est appariée à aucune source par
    // ce filtre, alors que la fraîcheur la compte encore par le texte de la règle (`extract_query_sources`).
    // Le test (1) le constate au lieu de le taire ; le remède est un remplissage unique de la colonne, pas
    // un `LIKE` sur `detail` qui réintroduirait l'imprécision que ce filtre retire.
    // ================================================================================================

    /// Insère une alerte imputée à `sources` (encodées comme le démon les écrit) et rend son id.
    fn fs_alerte(c: &Connection, ts: i64, rule: &str, title: &str, status: &str, mitre: &str, sources: &[&str]) -> i64 {
        let enc = imputation_encoder(&sources.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        c.execute(
            "INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources) VALUES(?1,?2,2,?3,'',?4,?5,?6)",
            params![ts, rule, title, status, mitre, enc],
        )
        .unwrap();
        c.last_insert_rowid()
    }

    /// Les titres d'une page, triés — la comparaison d'ensembles se lit mieux que des ids.
    fn fs_titres(page: &[Value]) -> Vec<String> {
        let mut t: Vec<String> = page.iter().map(|a| a["title"].as_str().unwrap_or("").to_string()).collect();
        t.sort();
        t
    }

    /// La fixture commune : sept alertes dont les imputations se ressemblent sans être égales.
    struct FixtureSources {
        conn: Connection,
        id_c_deux_sources: i64,
    }
    fn fs_fixture() -> FixtureSources {
        let conn = test_db();
        fs_alerte(&conn, 1000, "rule.1", "A-k8s", "new", "T1046", &["k8s"]);
        fs_alerte(&conn, 1001, "rule.1", "B-k8s-audit", "new", "T1046", &["k8s-audit"]);
        let id_c = fs_alerte(&conn, 1002, "rule.2", "C-deux-sources", "closed", "T1110", &["k8s", "k8s-audit"]);
        fs_alerte(&conn, 1003, "rule.2", "D-suffixe", "new", "", &["audit-k8s"]);
        // E : ANTÉRIEURE à la migration — colonne vide, la source n'est nommée que dans le texte.
        conn.execute(
            "INSERT INTO alert(ts,rule,severity,title,detail,status,sources) VALUES(1004,'rule.3',2,'E-avant-migration','search source=k8s | stats count','new','')",
            [],
        )
        .unwrap();
        fs_alerte(&conn, 1005, "heartbeat.x", "F-inconnu", "new", "", &[SOURCE_INDETERMINABLE]);
        // G : même nom en casse haute — `LIKE` replie la casse ASCII, `instr` non.
        fs_alerte(&conn, 1006, "rule.1", "G-casse", "new", "", &["K8S"]);
        FixtureSources { conn, id_c_deux_sources: id_c }
    }

    fn fs_filtre(source: &str) -> FiltreAlertes {
        FiltreAlertes { source: source.to_string(), ..Default::default() }
    }

    // ---------------------------------------------------------------------------------------------
    // (1) L'EXACTITUDE, avec le mutant joué sur la même fixture
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn filtre_source_rend_exactement_les_alertes_imputees_au_nom_entier() {
        let fx = fs_fixture();
        let (page, total, _) = alerts_query_page(&fx.conn, &fs_filtre("k8s"), None, "", 50, 0, true);
        assert_eq!(fs_titres(&page), vec!["A-k8s", "C-deux-sources"], "`k8s` = les alertes imputées à k8s, dont celle à deux sources — ni k8s-audit, ni audit-k8s, ni K8S");
        assert_eq!(total, Some(2), "le total est compté sous le MÊME WHERE");
        let (page, _, _) = alerts_query_page(&fx.conn, &fs_filtre("k8s-audit"), None, "", 50, 0, true);
        assert_eq!(fs_titres(&page), vec!["B-k8s-audit", "C-deux-sources"], "`k8s-audit` ne remonte pas `k8s` seul");
        let (page, _, _) = alerts_query_page(&fx.conn, &fs_filtre(SOURCE_INDETERMINABLE), None, "", 50, 0, true);
        assert_eq!(fs_titres(&page), vec!["F-inconnu"], "l'inconnu NOMMÉ se filtre comme un nom (espaces et parenthèses compris)");
        for fragment in ["k8s-au", "8s", "k8", "audit"] {
            let (page, total, _) = alerts_query_page(&fx.conn, &fs_filtre(fragment), None, "", 50, 0, true);
            assert!(page.is_empty() && total == Some(0), "un fragment (`{fragment}`) n'est le nom d'aucune source : liste vide et total 0, obtenu {:?}", fs_titres(&page));
        }
        // LA LIMITE NOMMÉE : l'alerte d'avant la migration n'est pas appariée — et la colonne vide est bien
        // le signal que la lecture (fraîcheur) utilise pour retomber sur le texte. Deux lecteurs, un écart
        // connu, écrit ici plutôt que découvert en exploitation.
        let (page, _, _) = alerts_query_page(&fx.conn, &fs_filtre("k8s"), None, "", 50, 0, true);
        assert!(!fs_titres(&page).iter().any(|t| t == "E-avant-migration"), "une alerte `sources=''` n'est pas appariée par le prédicat SQL (limite nommée)");
        assert!(imputation_decoder("").is_empty() && !extract_query_sources("search source=k8s | stats count").is_empty(), "…alors que le chemin de lecture textuel, lui, la nommerait : l'écart existe et il est borné aux alertes d'avant la migration");

        // LE MUTANT : `LIKE '%x%'` à la place de l'appariement sur le nom entier. Joué sur la même fixture,
        // il prend `k8s-audit`, `audit-k8s` ET `K8S` : la première assertion ci-dessus rougirait sous cette
        // mutation, et c'est ce qui fait de la fixture un témoin et non une illustration.
        let mutant = "SELECT title FROM alert WHERE COALESCE(alert.sources,'') LIKE '%'||?||'%' ORDER BY title";
        let mut st = fx.conn.prepare(mutant).unwrap();
        let pris: Vec<String> = st.query_map(params!["k8s"], |r| r.get::<_, String>(0)).unwrap().flatten().collect();
        assert_eq!(pris, vec!["A-k8s", "B-k8s-audit", "C-deux-sources", "D-suffixe", "G-casse"], "le mutant LIKE prend les voisins : la fixture discrimine");
        let exact = format!("SELECT title FROM alert WHERE {} ORDER BY title", imputation_predicat_sql("alert"));
        let mut st = fx.conn.prepare(&exact).unwrap();
        let pris: Vec<String> = st.query_map(params!["k8s"], |r| r.get::<_, String>(0)).unwrap().flatten().collect();
        assert_eq!(pris, vec!["A-k8s", "C-deux-sources"], "le prédicat servi ne prend que le nom entier");
    }

    // ---------------------------------------------------------------------------------------------
    // (2) LA COMPOSITION avec statut, technique, « hors case »
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn filtre_source_se_compose_avec_statut_technique_et_hors_case() {
        let fx = fs_fixture();
        let actives = FiltreAlertes { statut: Some("new".into()), source: "k8s".into(), ..Default::default() };
        let (page, total, _) = alerts_query_page(&fx.conn, &actives, None, "", 200, 0, true);
        assert_eq!(fs_titres(&page), vec!["A-k8s"], "statut=new ∧ source=k8s : C est close");
        assert_eq!(total, Some(1));
        let technique = FiltreAlertes { mitre: "T1110".into(), source: "k8s".into(), ..Default::default() };
        let (page, _, _) = alerts_query_page(&fx.conn, &technique, None, "", 200, 0, true);
        assert_eq!(fs_titres(&page), vec!["C-deux-sources"], "mitre=T1110 ∧ source=k8s : A porte T1046");
        // C rattachée à un cas -> « hors case » l'écarte, la source seule la garde.
        fx.conn.execute("INSERT INTO incident(ts,updated,title) VALUES(1000,1000,'enquête')", []).unwrap();
        let inc = fx.conn.last_insert_rowid();
        fx.conn
            .execute("INSERT INTO incident_item(incident_id,ts,kind,author,body,ref) VALUES(?1,1000,'evidence','a','b',?2)", params![inc, format!("alert:{}", fx.id_c_deux_sources)])
            .unwrap();
        let hors_case = FiltreAlertes { uncased: true, source: "k8s".into(), ..Default::default() };
        let (page, total, _) = alerts_query_page(&fx.conn, &hors_case, None, "", 200, 0, true);
        assert_eq!(fs_titres(&page), vec!["A-k8s"], "uncased ∧ source=k8s : C est dans un cas");
        assert_eq!(total, Some(1));
        let (page, _, _) = alerts_query_page(&fx.conn, &fs_filtre("k8s"), None, "", 200, 0, true);
        assert_eq!(fs_titres(&page), vec!["A-k8s", "C-deux-sources"], "cases comprises : C revient");
        // Le chemin BORNÉ (backlog, sans total) applique le même prédicat.
        let (page, total, _) = alerts_query_page(&fx.conn, &actives, None, "", 200, 0, false);
        assert_eq!(fs_titres(&page), vec!["A-k8s"]);
        assert_eq!(total, None, "le backlog borné ne compte pas");
    }

    // ---------------------------------------------------------------------------------------------
    // (3) LES ROUTES GROUPÉES : groupes, comptes, aperçu re-scopé, expansion
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn filtre_source_restreint_les_groupes_leur_apercu_et_leur_expansion() {
        let fx = fs_fixture();
        // Par règle, toute source : rule.1 = {A, B, G}, rule.2 = {C, D}, rule.3 = {E}, heartbeat.x = {F}.
        let (tous, total, _) = alert_groups_query_page(&fx.conn, "rule", &FiltreAlertes::default(), 50, 0);
        assert_eq!(total, Some(4), "témoin : sans filtre, quatre groupes");
        let r1 = tous.iter().find(|g| g["gkey"] == "rule.1").unwrap();
        assert_eq!(r1["n"], 3);
        assert_eq!(r1["sample_title"], "G-casse", "sans filtre, l'aperçu est la plus récente du groupe (G, ts 1006)");
        // Par règle, source=k8s : rule.1 = {A}, rule.2 = {C}. L'aperçu de rule.1 DOIT être A, pas G (plus
        // récente mais imputée à `K8S`) : la sous-requête d'aperçu est re-scopée à la source.
        let (groupes, total, _) = alert_groups_query_page(&fx.conn, "rule", &fs_filtre("k8s"), 50, 0);
        assert_eq!(total, Some(2), "deux groupes portent une alerte imputée à k8s");
        let cles: Vec<&str> = groupes.iter().map(|g| g["gkey"].as_str().unwrap()).collect();
        assert_eq!(cles, vec!["rule.2", "rule.1"], "ordre last_ts DESC dans le set filtré");
        let r1 = groupes.iter().find(|g| g["gkey"] == "rule.1").unwrap();
        assert_eq!(r1["n"], 1, "rule.1 : A seule (B = k8s-audit, G = K8S)");
        assert_eq!(r1["open_n"], 1);
        assert_eq!(r1["last_ts"], 1000, "last_ts = A, pas G");
        assert_eq!(r1["sample_title"], "A-k8s", "aperçu RE-SCOPÉ à la source");
        let r2 = groupes.iter().find(|g| g["gkey"] == "rule.2").unwrap();
        assert_eq!(r2["n"], 1, "rule.2 : C seule (D = audit-k8s)");
        assert_eq!(r2["sample_title"], "C-deux-sources");
        // Par hôte et par technique : le même WHERE (les trois tris sont des vues d'une même liste).
        let (par_mitre, _, _) = alert_groups_query_page(&fx.conn, "mitre", &fs_filtre("k8s"), 50, 0);
        let mut techniques: Vec<&str> = par_mitre.iter().map(|g| g["gkey"].as_str().unwrap()).collect();
        techniques.sort();
        assert_eq!(techniques, vec!["T1046", "T1110"], "par technique : A (T1046) et C (T1110)");
        let (par_hote, total_hote, _) = alert_groups_query_page(&fx.conn, "host", &fs_filtre("k8s-audit"), 50, 0);
        assert_eq!(total_hote, Some(1), "par hôte : un seul groupe (sans hôte), B et C");
        assert_eq!(par_hote[0]["n"], 2);
        // L'EXPANSION d'un groupe (chemin plat, gkey/gval) porte le même filtre : rule.1 ∧ k8s = {A}.
        let (occ, occ_total, _) = alerts_query_page(&fx.conn, &fs_filtre("k8s"), Some("rule"), "rule.1", 50, 0, true);
        assert_eq!(fs_titres(&occ), vec!["A-k8s"], "expansion de rule.1 sous source=k8s : A, pas B ni G");
        assert_eq!(occ_total, Some(1), "…et le total de l'expansion = le `n` du groupe");
        // Statut + source sur les groupes : rule.2 disparaît (C est close).
        let (actifs, total, _) = alert_groups_query_page(&fx.conn, "rule", &FiltreAlertes { statut: Some("new".into()), source: "k8s".into(), ..Default::default() }, 50, 0);
        assert_eq!(total, Some(1));
        assert_eq!(actifs[0]["gkey"], "rule.1");
    }

    // ---------------------------------------------------------------------------------------------
    // (4) LA BORNE : la valeur est validée, pas transformée en liste vide
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn filtre_source_borne_la_valeur_et_la_lit_une_fois_pour_les_deux_routes() {
        assert_eq!(filtre_source_de_requete(""), Ok(String::new()), "absent = pas de filtre");
        assert_eq!(filtre_source_de_requete("  k8s  "), Ok("k8s".into()), "les blancs de bord sont retirés");
        assert_eq!(filtre_source_de_requete("ext:plume-config"), Ok("ext:plume-config".into()), "le préfixe réservé des sources externes passe");
        assert_eq!(filtre_source_de_requete(SOURCE_INDETERMINABLE), Ok(SOURCE_INDETERMINABLE.into()), "l'inconnu nommé passe (espaces, parenthèses, accent)");
        assert!(filtre_source_de_requete("k8s\naudit").is_err(), "le séparateur de la liste stockée ne peut nommer aucune source : refusé");
        assert!(filtre_source_de_requete("k8s\tx").is_err() && filtre_source_de_requete("k8s\0").is_err(), "tout caractère de contrôle est refusé");
        let long = "a".repeat(SOURCE_FILTRE_MAX_OCTETS);
        assert!(filtre_source_de_requete(&long).is_ok(), "la borne est inclusive");
        assert!(filtre_source_de_requete(&format!("{long}a")).is_err(), "un octet de plus est refusé");
        // La lecture de requête est UNE fonction pour /api/alerts et /api/alerts/groups.
        let q = |paires: &[(&str, &str)]| paires.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<String, String>>();
        let f = FiltreAlertes::depuis_requete(&q(&[("source", "k8s"), ("status", "all"), ("mitre", "t1046"), ("uncased", "1")])).unwrap();
        assert_eq!(f, FiltreAlertes { statut: None, mitre: "T1046".into(), uncased: true, source: "k8s".into() });
        assert_eq!(FiltreAlertes::depuis_requete(&q(&[])).unwrap().statut.as_deref(), Some("new"), "défaut de route : statut new");
        assert!(FiltreAlertes::depuis_requete(&q(&[("source", "k8s\naudit")])).is_err(), "une source refusée refuse la requête entière");
    }

    // ---------------------------------------------------------------------------------------------
    // (5) LA DÉRIVATION : le prédicat lit le séparateur de l'encodeur
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn filtre_source_predicat_derive_du_separateur_de_l_encodeur() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE alert(id INTEGER PRIMARY KEY, sources TEXT NOT NULL DEFAULT '')").unwrap();
        let noms = ["k8s", "k8s-audit", "ext:plume-config", SOURCE_INDETERMINABLE];
        let enc = imputation_encoder(&noms.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        c.execute("INSERT INTO alert(sources) VALUES(?1)", params![enc]).unwrap();
        let sql = format!("SELECT COUNT(*) FROM alert WHERE {}", imputation_predicat_sql("alert"));
        let compte = |v: &str| c.query_row(&sql, params![v], |r| r.get::<_, i64>(0)).unwrap();
        for n in noms {
            assert_eq!(compte(n), 1, "chaque nom encodé est retrouvé ENTIER : `{n}`");
        }
        for fragment in ["k8s-", "8s", "plume-config", "ext:", "k8s k8s-audit", "", "(source", "K8S"] {
            assert_eq!(compte(fragment), 0, "un fragment, une casse voisine ou une concaténation n'est pas un nom : `{fragment}`");
        }
        assert_eq!(compte(&imputation_decoder(&enc)[1]), 1, "décodeur et prédicat lisent la même liste");
    }

    // ---------------------------------------------------------------------------------------------
    // (6) LE ROUTEUR RÉEL : 200 avec les bonnes lignes, 400 sur une valeur hors borne — sur les deux routes
    // ---------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn filtre_source_sur_le_routeur_reel_filtre_et_refuse() {
        let (st, dbp) = router_test_state("filtre-source");
        {
            let c = open_db(&dbp).unwrap();
            fs_alerte(&c, 1000, "rule.1", "A-k8s", "new", "T1046", &["k8s"]);
            fs_alerte(&c, 1001, "rule.1", "B-k8s-audit", "new", "T1046", &["k8s-audit"]);
            fs_alerte(&c, 1002, "rule.2", "C-deux-sources", "closed", "", &["k8s", "k8s-audit"]);
        }
        let addr = router_serve(st).await;
        let authz = viewer_authz();
        let (code, corps) = router_probe_corps(addr, "GET", "/api/alerts?status=all&source=k8s", Some(&authz), &[]).await;
        assert_eq!(code, 200, "viewer, valeur valide : {corps}");
        assert!(corps.contains("\"title\":\"A-k8s\"") && corps.contains("\"title\":\"C-deux-sources\""), "les deux imputées à k8s : {corps}");
        assert!(!corps.contains("B-k8s-audit"), "k8s-audit n'est pas k8s : {corps}");
        assert!(corps.contains("\"total\":2"), "tous statuts : total sous le même WHERE : {corps}");
        let (code, corps) = router_probe_corps(addr, "GET", "/api/alerts/groups?group=rule&status=all&source=k8s-audit", Some(&authz), &[]).await;
        assert_eq!(code, 200, "{corps}");
        assert!(corps.contains("\"gkey\":\"rule.1\"") && corps.contains("\"gkey\":\"rule.2\"") && corps.contains("\"total\":2"), "groupes sous source=k8s-audit : rule.1 (B) et rule.2 (C) : {corps}");
        assert!(corps.contains("\"sample_title\":\"B-k8s-audit\""), "l'aperçu de rule.1 est B (A n'est pas imputée à k8s-audit) : {corps}");
        // Hors borne : 400 sur les DEUX routes, jamais une liste vide en 200.
        let (code, corps) = router_probe_corps(addr, "GET", "/api/alerts?source=k8s%0Aaudit", Some(&authz), &[]).await;
        assert_eq!(code, 400, "caractère de contrôle dans `source` : refusé, pas « aucune alerte » : {corps}");
        assert!(corps.contains("caract\\u00e8re de contr\\u00f4le") || corps.contains("caractère de contrôle"), "la raison est dite : {corps}");
        let trop_long = "x".repeat(SOURCE_FILTRE_MAX_OCTETS + 1);
        let (code, _) = router_probe_corps(addr, "GET", &format!("/api/alerts/groups?group=rule&source={trop_long}"), Some(&authz), &[]).await;
        assert_eq!(code, 400, "valeur trop longue sur la route groupée : refusée");
        let (code, corps) = router_probe_corps(addr, "GET", "/api/alerts?status=all&source=%20", Some(&authz), &[]).await;
        assert_eq!(code, 200, "une valeur blanche = pas de filtre : {corps}");
        assert!(corps.contains("\"total\":3"), "sans filtre, les trois : {corps}");
    }
