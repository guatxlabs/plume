// PURGE EXPLICITE D'ÉVÉNEMENTS (purge.rs) — la seule suppression de `event` qui ne soit pas la rétention
// temporelle, donc la fonctionnalité la plus destructrice du dépôt.
//
// CE QUE CES TESTS MESURENT, ET CE QU'ILS NE PEUVENT PAS MESURER. Les garde-fous les plus forts de ce module
// sont des propriétés de TYPE : on ne peut pas écrire un périmètre sans borne temporelle (`PurgeWindow` est un
// champ, pas un `Option`), ni sans identifiant (`head` est un champ, pas un `Vec` qui pourrait être vide), ni
// exécuter sans avoir simulé (`purge_apply` n'accepte qu'un `ConfirmedPurge`, dont le seul ancêtre est
// `purge_plan`), ni supprimer sans avoir inscrit au registre (`purge_delete_rows` LIT le champ d'un
// `PurgeInscribed` que seul `purge_inscribe` produit). Un test d'exécution ne peut PAS observer ces
// propriétés — leur violation ne compile pas, donc il n'y a pas de binaire à interroger. Les tests ci-dessous
// couvrent tout le RESTE : les refus (rétention légale, tier froid, chaîne de preuve, index désynchronisé),
// la caducité du jeton, la réconciliation des artefacts dérivés, la confidentialité de l'inscription, et le
// câblage RBAC de la surface HTTP.

    /// Insère un event purgeable (origin='' -> jamais protégé par la clause non-purgeable). Rend son `id`.
    fn pg_ins(c: &Connection, ts: i64, source: &str, env: &str, msg: &str) -> i64 {
        c.execute(
            "INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id) \
             VALUES(?1,?2,'test',1,?3,'h1',?4,'','')",
            params![ts, source, msg, env],
        )
        .unwrap();
        c.last_insert_rowid()
    }

    /// Périmètre construit par le MÊME analyseur que la CLI et l'API (source unique de validation).
    fn pg_scope(sel: &[(&str, &str)], start: i64, end: i64) -> PurgeScope {
        let v: Vec<(String, String)> = sel.iter().map(|(k, x)| (k.to_string(), x.to_string())).collect();
        purge_scope_from_args(&v, &start.to_string(), &end.to_string(), now()).expect("périmètre valide")
    }

    fn pg_events(c: &Connection) -> i64 {
        c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap()
    }

    fn pg_ledger_purges(c: &Connection) -> i64 {
        c.query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1", params![PURGE_LEDGER_KIND], |r| r.get(0)).unwrap()
    }

    // ============================================================================================
    // 1. PÉRIMÈTRE — ce qui ne se construit PAS
    // ============================================================================================

    /// Une fenêtre inversée, négative, ou plus longue que le plafond de sanité n'existe pas. `PurgeWindow`
    /// n'a qu'un constructeur, et il est faillible : il n'y a donc aucun chemin vers un périmètre non borné.
    #[test]
    fn purge_window_refuses_inverted_negative_and_absurd() {
        assert!(PurgeWindow::new(200, 100).is_err(), "fenêtre inversée refusée");
        assert!(PurgeWindow::new(-1, 100).is_err(), "borne négative refusée");
        assert!(
            PurgeWindow::new(0, (PURGE_WINDOW_MAX_DAYS + 1) * 86_400).is_err(),
            "au-delà du plafond de sanité : refusé"
        );
        let w = PurgeWindow::new(100, 200).expect("fenêtre valide");
        assert_eq!((w.start(), w.end()), (100, 200));
        // Fenêtre PONCTUELLE (start==end) : légitime (« cette seconde-là »), et toujours bornée.
        assert!(PurgeWindow::new(100, 100).is_ok());
    }

    /// « Toute la fenêtre, toutes sources » n'est pas un périmètre acceptable : `PurgeScope` porte son premier
    /// sélecteur dans un CHAMP, donc un périmètre sans identifiant ne se construit pas. Ici on mesure la porte
    /// d'entrée (l'analyseur d'arguments), qui refuse plutôt que d'inventer un `head`.
    #[test]
    fn purge_scope_requires_at_least_one_identifier() {
        let e = purge_scope_from_args(&[], "0", "100", 1_000).unwrap_err();
        assert!(e.contains("NOMME"), "le refus explique qu'un périmètre se nomme : {e}");
        assert!(
            purge_scope_from_args(&[("source".into(), "sshd".into())], "0", "100", 1_000).is_ok(),
            "un seul identifiant suffit"
        );
    }

    /// Les deux bornes sont OBLIGATOIRES : il n'y a pas de valeur par défaut, parce qu'il n'y a pas de
    /// fenêtre par défaut. Une borne absente (chaîne vide) est un refus, pas un « depuis toujours ».
    #[test]
    fn purge_scope_refuses_a_missing_bound() {
        let sel = [("source".to_string(), "sshd".to_string())];
        assert!(purge_scope_from_args(&sel, "", "100", 1_000).is_err(), "borne basse absente -> refus");
        assert!(purge_scope_from_args(&sel, "0", "", 1_000).is_err(), "borne haute absente -> refus");
    }

    /// Aucun sélecteur ne transporte de PRÉDICAT. Un genre inconnu est refusé (default-deny) et une valeur
    /// qui ressemble à du SQL ne passe pas le charset d'identifiant : la purge accidentellement totale par
    /// expression n'a pas de forme dans le type.
    #[test]
    fn purge_selector_admits_no_free_predicate() {
        assert!(PurgeSelector::parse("sql", "1=1").is_err(), "genre inconnu -> refus (default-deny)");
        assert!(PurgeSelector::parse("where", "ts>0").is_err(), "aucun genre 'where'");
        assert!(PurgeSelector::parse("source", "a' OR 1=1 --").is_err(), "valeur hors charset d'identifiant");
        assert!(PurgeSelector::parse("source", "*").is_err(), "pas de joker : un périmètre nomme");
        assert!(PurgeSelector::parse("source", "").is_err(), "valeur vide -> refus");
        assert!(PurgeSelector::parse("source", "flux-de-test").is_ok());
    }

    /// La PISTE D'AUDIT n'est pas purgeable, et le refus est EXPLICITE plutôt qu'un « 0 ligne » silencieux
    /// (qui laisserait croire qu'il n'y avait rien).
    #[test]
    fn purge_selector_refuses_the_audit_trail() {
        for s in ["plume-config", "plume-operator-access", "plume-tenant-admin", "plume-engagement"] {
            assert!(PurgeSelector::parse("source", s).is_err(), "source de contrôle '{s}' refusée");
        }
        assert!(PurgeSelector::parse("origin", "daemon").is_err(), "origin='daemon' (lignes du daemon) refusée");
        assert!(PurgeSelector::parse("origin", "agent").is_ok());
    }

    /// Deux sélecteurs du même genre se conjoindraient en un ensemble vide : on refuse au lieu de deviner
    /// l'intention (union ? restriction ?). Une purge ne se devine pas.
    #[test]
    fn purge_scope_refuses_duplicate_selector_kinds() {
        let w = PurgeWindow::new(0, 100).unwrap();
        let e = PurgeScope::new(
            PurgeSelector::parse("source", "a").unwrap(),
            vec![PurgeSelector::parse("source", "b").unwrap()],
            w,
        )
        .unwrap_err();
        assert!(e.contains("deux fois"), "message explicite : {e}");
        assert!(
            PurgeScope::new(
                PurgeSelector::parse("source", "a").unwrap(),
                vec![PurgeSelector::parse("env", "prod").unwrap()],
                w
            )
            .is_ok(),
            "genres DIFFÉRENTS : conjonction légitime"
        );
    }

    /// La forme canonique est déterministe et indépendante de l'ORDRE des sélecteurs : c'est ce qui fait
    /// qu'un jeton vaut pour un PÉRIMÈTRE, pas pour une frappe d'arguments.
    #[test]
    fn purge_scope_canonical_is_order_independent() {
        let a = pg_scope(&[("source", "sshd"), ("env", "prod")], 10, 20);
        let b = pg_scope(&[("env", "prod"), ("source", "sshd")], 10, 20);
        assert_eq!(a.canonical(), b.canonical());
        let c = pg_scope(&[("source", "sshd"), ("env", "staging")], 10, 20);
        assert_ne!(a.canonical(), c.canonical(), "un périmètre différent a une forme différente");
    }

    /// Bornes acceptées : epoch absolu, et décalage relatif (`-7d`, `-24h`, `-30m`, `-3600s`). Une unité
    /// inconnue est refusée (pas d'interprétation généreuse d'une entrée de destruction).
    #[test]
    fn purge_parses_absolute_and_relative_bounds() {
        let n = 1_000_000i64;
        assert_eq!(purge_parse_ts("1785520800", n).unwrap(), 1_785_520_800);
        assert_eq!(purge_parse_ts("-7d", n).unwrap(), n - 7 * 86_400);
        assert_eq!(purge_parse_ts("-24h", n).unwrap(), n - 24 * 3600);
        assert_eq!(purge_parse_ts("-30m", n).unwrap(), n - 1_800);
        assert_eq!(purge_parse_ts("-3600s", n).unwrap(), n - 3_600);
        assert!(purge_parse_ts("-7w", n).is_err(), "unité inconnue -> refus");
        assert!(purge_parse_ts("hier", n).is_err());
        assert!(purge_parse_ts("", n).is_err());
    }

    // ============================================================================================
    // 2. SIMULATION — exacte, read-only, et elle rend ce qu'elle NE couvre pas
    // ============================================================================================

    /// La simulation rend le compte EXACT (pas une estimation), la ventilation par source, un échantillon des
    /// DEUX extrémités, et n'écrit RIEN (ni ligne supprimée, ni entrée de registre).
    #[test]
    fn purge_plan_is_exact_and_writes_nothing() {
        let c = test_db();
        for i in 0..12 {
            pg_ins(&c, 1_000 + i, "flux-de-test", "prod", &format!("ligne {i}"));
        }
        pg_ins(&c, 1_005, "sshd", "prod", "hors périmètre (autre source)");
        pg_ins(&c, 9_999, "flux-de-test", "prod", "hors périmètre (hors fenêtre)");
        let before = pg_events(&c);

        let p = purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 1_000, 1_011)).expect("plan");
        assert_eq!(p.rows(), 12, "compte EXACT du périmètre");
        assert_eq!(p.per_source(), &[("flux-de-test".to_string(), 12)], "ventilation par source");
        assert_eq!(p.ts_range(), (1_000, 1_011), "bornes ts réelles du périmètre");
        assert!(
            p.sample().len() >= 2 && p.sample().len() <= 2 * PURGE_SAMPLE_EACH_SIDE,
            "échantillon des deux extrémités, borné : {}",
            p.sample().len()
        );
        assert!(p.sample().iter().any(|r| r.message.contains("ligne 0")), "la plus VIEILLE est montrée");
        assert!(p.sample().iter().any(|r| r.message.contains("ligne 11")), "la plus RÉCENTE est montrée");
        assert!(!p.digest().is_empty(), "un jeton est rendu");

        assert_eq!(pg_events(&c), before, "SIMULATION : aucune ligne supprimée");
        assert_eq!(pg_ledger_purges(&c), 0, "SIMULATION : aucune inscription au registre");
    }

    /// Les sélecteurs se CONJOIGNENT : ajouter un identifiant ne peut que RÉTRÉCIR le périmètre.
    #[test]
    fn purge_selectors_only_narrow_the_scope() {
        let c = test_db();
        pg_ins(&c, 1_000, "flux-de-test", "prod", "a");
        pg_ins(&c, 1_001, "flux-de-test", "staging", "b");
        let large = purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 0, 2_000)).unwrap();
        let narrow =
            purge_plan(&c, pg_scope(&[("source", "flux-de-test"), ("env", "staging")], 0, 2_000)).unwrap();
        assert_eq!(large.rows(), 2);
        assert_eq!(narrow.rows(), 1, "le second sélecteur RÉTRÉCIT");
    }

    /// Ce que la purge NE couvre PAS est compté et rendu — dans le JSON comme dans le texte. Ne pas prétendre
    /// résoudre ce qu'on ne résout pas : les sauvegardes en particulier sont nommées, toujours.
    #[test]
    fn purge_plan_declares_what_it_does_not_cover() {
        let c = test_db();
        pg_ins(&c, 1_000, "flux-de-test", "prod", "x");
        c.execute("INSERT INTO alert(ts,rule,severity,title) VALUES(1000,'r',3,'t')", []).unwrap();
        c.execute("INSERT INTO metric(ts,name,value) VALUES(1000,'m',1.0)", []).unwrap();
        c.execute("INSERT INTO snapshot(ts,kind,data) VALUES(1000,'k','{}')", []).unwrap();
        let p = purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 0, 2_000)).unwrap();
        let u = p.uncovered();
        assert_eq!((u.alerts_in_window, u.metrics_in_window, u.snapshots_in_window), (1, 1, 1));

        let j = purge_plan_json(&p);
        assert_eq!(j["not_covered"]["alerts_in_window"], 1);
        assert!(
            j["not_covered"]["backups"].as_str().unwrap().contains("SAUVEGARDES"),
            "l'avertissement sauvegardes est TOUJOURS rendu en JSON"
        );
        let t = purge_plan_text(&p);
        assert!(t.contains("NON COUVERT"), "le texte CLI nomme la section");
        assert!(t.contains("SAUVEGARDES"), "le texte CLI nomme les sauvegardes");
        assert!(t.contains("host_rollup"), "l'inventaire de flotte non recalculé est nommé");
    }

    // ============================================================================================
    // 3. CONFIRMATION — le jeton prouve qu'on a vu CE résultat-là
    // ============================================================================================

    /// Confirmer SANS avoir simulé : impossible à écrire (il faut un `PurgePlan`). Ce qui RESTE observable,
    /// c'est le chemin CLI/API — qui re-simule et compare : un jeton inventé est rejeté.
    #[test]
    fn purge_refuses_a_token_that_was_never_a_plan() {
        let c = test_db();
        pg_ins(&c, 1_000, "flux-de-test", "prod", "x");
        let e = purge_confirm_and_apply(
            &c,
            pg_scope(&[("source", "flux-de-test")], 0, 2_000),
            "0000000000000000000000000000000000000000000000000000000000000000",
            "test",
            "motif",
        )
        .unwrap_err();
        assert_eq!(purge_refusal_code(&e), "stale_token");
        assert_eq!(pg_events(&c), 1, "aucune ligne détruite");
        assert_eq!(pg_ledger_purges(&c), 0);
    }

    /// Le jeton vaut pour UN périmètre : celui d'un autre périmètre est rejeté (il ne « transfère » pas).
    #[test]
    fn purge_token_does_not_transfer_between_scopes() {
        let c = test_db();
        pg_ins(&c, 1_000, "flux-de-test", "prod", "x");
        pg_ins(&c, 1_000, "sshd", "prod", "y");
        let tok = purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 0, 2_000)).unwrap().digest().to_string();
        let e = purge_confirm_and_apply(&c, pg_scope(&[("source", "sshd")], 0, 2_000), &tok, "t", "motif")
            .unwrap_err();
        assert_eq!(purge_refusal_code(&e), "stale_token");
        assert_eq!(pg_events(&c), 2);
    }

    /// LE PÉRIMÈTRE S'EST ÉLARGI ENTRE LA SIMULATION ET L'EXÉCUTION : une ligne ingérée dans la fenêtre
    /// change la cardinalité, donc l'empreinte, donc la confirmation devient CADUQUE. C'est le cas adverse
    /// central : l'humain a vu 12 lignes, il ne doit pas en détruire 13.
    #[test]
    fn purge_token_goes_stale_when_the_scope_grows() {
        let c = test_db();
        for i in 0..12 {
            pg_ins(&c, 1_000 + i, "flux-de-test", "prod", &format!("l{i}"));
        }
        let tok = purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 1_000, 1_100)).unwrap().digest().to_string();
        // …une 13e ligne arrive DANS la fenêtre (ingest concurrent, relais en retard).
        pg_ins(&c, 1_050, "flux-de-test", "prod", "arrivée tardive");
        let e = purge_confirm_and_apply(&c, pg_scope(&[("source", "flux-de-test")], 1_000, 1_100), &tok, "t", "m")
            .unwrap_err();
        assert_eq!(purge_refusal_code(&e), "stale_token");
        assert_eq!(pg_events(&c), 13, "rien détruit tant que l'humain n'a pas revu le périmètre");
    }

    /// REJEU : la même confirmation renvoyée une deuxième fois échoue. Il n'y a plus rien à détruire, donc
    /// l'empreinte du périmètre re-simulé a changé. (Et côté type, un `PurgePlan` est CONSOMMÉ par `confirm`.)
    #[test]
    fn purge_confirmation_cannot_be_replayed() {
        let c = test_db();
        for i in 0..4 {
            pg_ins(&c, 1_000 + i, "flux-de-test", "prod", &format!("l{i}"));
        }
        let sc = || pg_scope(&[("source", "flux-de-test")], 1_000, 1_100);
        let tok = purge_plan(&c, sc()).unwrap().digest().to_string();
        let r = purge_confirm_and_apply(&c, sc(), &tok, "t", "nettoyage").expect("1re exécution");
        assert_eq!(r.rows_deleted, 4);
        let e = purge_confirm_and_apply(&c, sc(), &tok, "t", "nettoyage").unwrap_err();
        assert_eq!(purge_refusal_code(&e), "stale_token", "le rejeu échoue");
        assert_eq!(pg_ledger_purges(&c), 1, "une seule purge inscrite");
    }

    /// Une raison NON VIDE est exigée : la destruction de preuves se motive, et la motivation entre au
    /// registre. Le refus arrive AVANT toute suppression.
    #[test]
    fn purge_requires_a_reason() {
        let c = test_db();
        pg_ins(&c, 1_000, "flux-de-test", "prod", "x");
        let sc = || pg_scope(&[("source", "flux-de-test")], 0, 2_000);
        let tok = purge_plan(&c, sc()).unwrap().digest().to_string();
        let e = purge_confirm_and_apply(&c, sc(), &tok, "t", "   ").unwrap_err();
        assert_eq!(purge_refusal_code(&e), "reason_required");
        assert_eq!(pg_events(&c), 1);
    }

    // ============================================================================================
    // 4. REFUS — rétention légale, tier froid, chaîne de preuve, index désynchronisé
    // ============================================================================================

    /// RÉTENTION LÉGALE. Un hold GLOBAL actif recouvrant la fenêtre bloque TOUT le périmètre : jamais une
    /// purge partielle « sauf les lignes tenues », qui laisserait l'opérateur croire que tout est parti. Le
    /// refus NOMME le hold. Après levée, la purge redevient possible.
    #[test]
    fn purge_refuses_under_an_active_legal_hold() {
        let c = test_db();
        pg_ins(&c, 1_000, "flux-de-test", "prod", "preuve");
        c.execute(
            "INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
             VALUES('litige-A','',' ',0,0,1,0,'admin')",
            [],
        )
        .unwrap();
        // scope_source=' ' (non vide) et non égal à la source : ne recouvre PAS -> la purge doit passer.
        assert!(purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 0, 2_000)).is_ok());

        c.execute("UPDATE legal_hold SET scope_source='' WHERE name='litige-A'", []).unwrap();
        let e = purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 0, 2_000)).unwrap_err();
        assert_eq!(purge_refusal_code(&e), "legal_hold");
        assert!(e.to_string().contains("litige-A"), "le refus NOMME le hold : {e}");

        c.execute("UPDATE legal_hold SET active=0 WHERE name='litige-A'", []).unwrap();
        assert!(purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 0, 2_000)).is_ok(), "hold levé -> purgeable");
    }

    /// Un hold SOURCE-SCOPÉ bloque une purge de CETTE source, et une purge SANS sélecteur `source` (donc
    /// potentiellement toutes sources) est bloquée par N'IMPORTE quel hold : « refuser plutôt que deviner ».
    #[test]
    fn purge_refuses_when_a_source_scoped_hold_may_cover() {
        let c = test_db();
        pg_ins(&c, 1_000, "sshd", "prod", "preuve");
        pg_ins(&c, 1_000, "flux-de-test", "prod", "test");
        c.execute(
            "INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
             VALUES('litige-sshd','','sshd',0,0,1,0,'admin')",
            [],
        )
        .unwrap();
        assert_eq!(
            purge_refusal_code(&purge_plan(&c, pg_scope(&[("source", "sshd")], 0, 2_000)).unwrap_err()),
            "legal_hold"
        );
        // Purge par ENV (aucun sélecteur source) : le hold sshd PEUT couvrir des lignes du périmètre -> refus.
        assert_eq!(
            purge_refusal_code(&purge_plan(&c, pg_scope(&[("env", "prod")], 0, 2_000)).unwrap_err()),
            "legal_hold"
        );
        // Une AUTRE source explicitement nommée n'est pas couverte par ce hold -> la purge passe.
        assert!(purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 0, 2_000)).is_ok());
    }

    /// Une fenêtre de hold qui NE RECOUPE PAS celle de la purge ne bloque pas ; celle qui la recoupe bloque.
    #[test]
    fn purge_legal_hold_window_intersection_is_respected() {
        let c = test_db();
        pg_ins(&c, 5_000, "flux-de-test", "prod", "x");
        c.execute(
            "INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
             VALUES('h','','',1,100,1,0,'admin')",
            [],
        )
        .unwrap();
        assert!(
            purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 4_000, 6_000)).is_ok(),
            "fenêtres disjointes -> pas de recouvrement"
        );
        c.execute("UPDATE legal_hold SET scope_end_ts=5500 WHERE name='h'", []).unwrap();
        assert_eq!(
            purge_refusal_code(&purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 4_000, 6_000)).unwrap_err()),
            "legal_hold"
        );
    }

    /// FAIL-CLOSED : si l'état des holds ne peut pas être déterminé (table présente mais illisible), on ne
    /// supprime rien. MÊME loi que `retention_run` — la décision vient de `legal_hold_enforcement`, source
    /// unique.
    #[test]
    fn purge_fails_closed_when_hold_state_is_undeterminable() {
        let c = test_db();
        pg_ins(&c, 1_000, "flux-de-test", "prod", "x");
        c.execute_batch("DROP TABLE legal_hold; CREATE TABLE legal_hold(id INTEGER);").unwrap();
        let e = purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 0, 2_000)).unwrap_err();
        assert_eq!(purge_refusal_code(&e), "legal_hold_undetermined");
        assert_eq!(pg_events(&c), 1);
    }

    /// TIER FROID — LE PIÈGE. Les vieilles lignes vivent en Parquet SCELLÉ, pas seulement dans SQLite : vider
    /// `event` laisserait ces copies INTERROGEABLES, et « purgé » serait un mensonge. La purge refuse et NOMME
    /// ce qu'elle ne peut pas atteindre. Le contrôle lit `cold_seal` en SQL pur -> il vaut AUSSI dans le build
    /// par défaut (feature `cold_tier` absente), qui sinon purgerait le chaud en laissant le froid lisible.
    #[test]
    fn purge_refuses_when_the_cold_tier_covers_the_window() {
        let c = test_db();
        pg_ins(&c, 5_000, "flux-de-test", "prod", "x");
        c.execute_batch(
            "CREATE TABLE cold_seal(env_id TEXT NOT NULL, day INTEGER NOT NULL, seq INTEGER NOT NULL, \
               expected_rows INTEGER NOT NULL, sealed_ts INTEGER NOT NULL, purged INTEGER NOT NULL DEFAULT 0, \
               max_id INTEGER NOT NULL, ts_min INTEGER NOT NULL, ts_max INTEGER NOT NULL, lo_ts INTEGER NOT NULL, \
               lo_id INTEGER NOT NULL, hi_id INTEGER NOT NULL, last_file INTEGER NOT NULL DEFAULT 0, \
               PRIMARY KEY(env_id,day,seq))",
        )
        .unwrap();
        // Fichier scellé DISJOINT de la fenêtre -> rien à refuser.
        c.execute(
            "INSERT INTO cold_seal VALUES('prod',1,0,10,0,1,99,100,200,100,1,99,1)",
            [],
        )
        .unwrap();
        assert!(purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 4_000, 6_000)).is_ok());

        // Fichier scellé RECOUVRANT la fenêtre -> REFUS nommé.
        c.execute(
            "INSERT INTO cold_seal VALUES('prod',2,0,10,0,1,99,4500,5500,4500,1,99,1)",
            [],
        )
        .unwrap();
        let e = purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 4_000, 6_000)).unwrap_err();
        assert_eq!(purge_refusal_code(&e), "cold_tier");
        assert!(e.to_string().contains("Parquet"), "le refus nomme le tier froid : {e}");
        assert_eq!(pg_events(&c), 1, "aucune ligne détruite");
    }

    /// CHAÎNE DE PREUVE : un event cité par la timeline d'un case/incident n'est pas purgeable en silence —
    /// on laisserait une référence pendante dans une investigation. Refus nommant les identifiants.
    #[test]
    fn purge_refuses_events_cited_by_a_case() {
        let c = test_db();
        let id = pg_ins(&c, 1_000, "flux-de-test", "prod", "pièce à conviction");
        pg_ins(&c, 1_001, "flux-de-test", "prod", "sans citation");
        c.execute(
            "INSERT INTO incident(ts,updated,title) VALUES(1000,1000,'enquête')",
            [],
        )
        .unwrap();
        let inc = c.last_insert_rowid();
        c.execute(
            "INSERT INTO incident_item(incident_id,ts,kind,author,body,ref) VALUES(?1,1000,'evidence','a','b',?2)",
            params![inc, format!("event:{id}")],
        )
        .unwrap();
        let e = purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 0, 2_000)).unwrap_err();
        assert_eq!(purge_refusal_code(&e), "cited_by_case");
        assert!(e.to_string().contains(&id.to_string()), "le refus nomme l'event cité : {e}");
        // Détacher l'item rend le périmètre purgeable (le refus est une porte, pas un mur).
        c.execute("DELETE FROM incident_item", []).unwrap();
        assert!(purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 0, 2_000)).is_ok());
    }

    /// INDEX PLEIN-TEXTE DÉSYNCHRONISÉ : si `event_fts` existe sans son trigger de suppression, un DELETE
    /// laisserait les postings et le message purgé resterait CHERCHABLE. Refus.
    #[test]
    fn purge_refuses_when_the_fts_delete_trigger_is_missing() {
        let c = test_db();
        pg_ins(&c, 1_000, "flux-de-test", "prod", "x");
        assert!(purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 0, 2_000)).is_ok(), "état nominal");
        c.execute("DROP TRIGGER event_ad", []).unwrap();
        let e = purge_plan(&c, pg_scope(&[("source", "flux-de-test")], 0, 2_000)).unwrap_err();
        assert_eq!(purge_refusal_code(&e), "fts_desync");
        assert_eq!(pg_events(&c), 1);
    }

    // ============================================================================================
    // 5. EXÉCUTION — ce qui part, ce qui reste, et ce que le registre en dit
    // ============================================================================================

    /// La purge détruit EXACTEMENT le périmètre et RIEN d'autre : autre source, hors fenêtre, autre
    /// environnement — tout survit.
    #[test]
    fn purge_deletes_exactly_the_scope_and_nothing_else() {
        let c = test_db();
        for i in 0..5 {
            pg_ins(&c, 1_000 + i, "flux-de-test", "prod", &format!("cible {i}"));
        }
        pg_ins(&c, 1_002, "sshd", "prod", "autre source");
        pg_ins(&c, 9_000, "flux-de-test", "prod", "hors fenêtre");
        pg_ins(&c, 1_002, "flux-de-test", "staging", "autre env");
        let sc = || pg_scope(&[("source", "flux-de-test"), ("env", "prod")], 1_000, 1_004);
        let tok = purge_plan(&c, sc()).unwrap().digest().to_string();
        let r = purge_confirm_and_apply(&c, sc(), &tok, "t", "nettoyage onboarding").unwrap();
        assert_eq!(r.rows_deleted, 5);
        // `origin=''` = les lignes INGÉRÉES. La ligne d'audit de la purge, elle, porte origin='daemon' :
        // elle est ajoutée par l'inscription au registre et n'a rien à faire dans ce décompte (elle est
        // vérifiée à part, cf. `purge_is_inscribed_in_the_hash_chained_ledger`).
        let restants: Vec<String> = {
            let mut st = c.prepare("SELECT message FROM event WHERE origin='' ORDER BY id").unwrap();
            st.query_map([], |x| x.get::<_, String>(0)).unwrap().flatten().collect()
        };
        assert_eq!(restants, vec!["autre source", "hors fenêtre", "autre env"], "seul le périmètre est parti");
    }

    /// LA PURGE NE PEUT PAS EFFACER SA PROPRE TRACE. Les events de contrôle (`origin='daemon'` +
    /// source d'audit) sont hors d'atteinte du prédicat de portée : une purge par `env` les épargne, et une
    /// SECONDE purge ne peut pas effacer l'audit de la première.
    #[test]
    fn purge_can_never_erase_the_audit_trail() {
        let c = test_db();
        pg_ins(&c, 1_000, "flux-de-test", "prod", "cible");
        c.execute(
            "INSERT INTO event(ts,source,category,severity,message,host,fields,origin,env_id) \
             VALUES(1000,'plume-config','config',3,'rétention baissée','plume-daemon','{}','daemon','prod')",
            [],
        )
        .unwrap();
        let sc = || pg_scope(&[("env", "prod")], 0, 2_000);
        let tok = purge_plan(&c, sc()).unwrap().digest().to_string();
        let r = purge_confirm_and_apply(&c, sc(), &tok, "t", "m").unwrap();
        assert_eq!(r.rows_deleted, 1, "la ligne de contrôle n'est PAS comptée dans le périmètre");
        let audit: i64 = c
            .query_row("SELECT COUNT(*) FROM event WHERE source='plume-config' AND origin='daemon'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(audit, 2, "l'audit préexistant + celui de CETTE purge, tous deux intacts");

        // Une SECONDE purge, même périmètre : elle ne trouve plus rien à détruire (l'audit lui échappe).
        let p2 = purge_plan(&c, sc()).unwrap();
        assert_eq!(p2.rows(), 0, "l'audit de la purge n'est pas purgeable par une purge");
    }

    /// L'INSCRIPTION AU REGISTRE EST PRÉALABLE ET NON OPTIONNELLE : après exécution, le registre chaîné porte
    /// l'entrée (qui / périmètre résolu / combien / quand), et le SOC porte un event non-purgeable alertable.
    #[test]
    fn purge_is_inscribed_in_the_hash_chained_ledger() {
        let c = test_db();
        for i in 0..3 {
            pg_ins(&c, 1_000 + i, "flux-de-test", "prod", &format!("l{i}"));
        }
        let sc = || pg_scope(&[("source", "flux-de-test")], 1_000, 1_002);
        let tok = purge_plan(&c, sc()).unwrap().digest().to_string();
        purge_confirm_and_apply(&c, sc(), &tok, "api:alice", "demande RGPD 42").unwrap();

        let (kind, detail): (String, String) = c
            .query_row(
                "SELECT kind, COALESCE(detail,'') FROM ledger WHERE kind=?1 ORDER BY id DESC LIMIT 1",
                params![PURGE_LEDGER_KIND],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(kind, "config.purge.events");
        let d: Value = serde_json::from_str(&detail).expect("détail JSON");
        assert_eq!(d["op"], "purge");
        assert_eq!(d["rows"], 3, "COMBIEN de lignes");
        assert_eq!(d["actor"], "api:alice", "QUI");
        assert_eq!(d["reason"], "demande RGPD 42", "POURQUOI");
        assert_eq!(d["scope"]["window"]["start_ts"], 1_000, "PÉRIMÈTRE RÉSOLU");
        assert_eq!(d["scope"]["selectors"][0]["kind"], "source");
        assert_eq!(d["digest"], tok, "l'empreinte confirmée est inscrite");

        // La chaîne de hachage reste intègre après l'ajout (c'est CE que `verify` recompute).
        let (n, _ok, _ko, broken) = verify_ledger_conn(&c, None).unwrap();
        assert!(n > 0 && broken.is_none(), "chaîne de registre intègre après purge");

        // Miroir SOC : event non-purgeable (origin='daemon', source de contrôle) et alertable.
        let sev: i64 = c
            .query_row(
                "SELECT severity FROM event WHERE source='plume-config' AND origin='daemon' ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(sev, 4, "une purge est un acte à sévérité élevée dans le SOC");
    }

    /// CONFIDENTIALITÉ DE L'INSCRIPTION : le registre dit QUOI a été détruit (périmètre, compteurs), jamais
    /// CE QUI a été détruit. Structurellement, `purge_inscribe` ne reçoit qu'un `ConfirmedPurge` — qui ne
    /// porte ni message, ni IP, ni `fields` : l'échantillon est laissé tomber par `confirm`.
    #[test]
    fn purge_ledger_entry_leaks_no_purged_content() {
        let c = test_db();
        let secret = "MOTDEPASSE-ULTRA-SENSIBLE-9f3a";
        c.execute(
            "INSERT INTO event(ts,source,category,severity,message,host,fields,src_ip,env_id,origin) \
             VALUES(1000,'flux-de-test','test',1,?1,'h','{\"user\":\"jean.dupont\"}','203.0.113.9','prod','')",
            params![format!("échec auth pour {secret}")],
        )
        .unwrap();
        let sc = || pg_scope(&[("source", "flux-de-test")], 0, 2_000);
        let tok = purge_plan(&c, sc()).unwrap().digest().to_string();
        // L'échantillon du PLAN, lui, MONTRE le contenu (c'est son rôle : prouver à l'humain ce qu'il détruit).
        assert!(purge_plan(&c, sc()).unwrap().sample()[0].message.contains(secret));
        purge_confirm_and_apply(&c, sc(), &tok, "t", "m").unwrap();

        let detail: String = c
            .query_row("SELECT COALESCE(detail,'') FROM ledger WHERE kind=?1", params![PURGE_LEDGER_KIND], |r| r.get(0))
            .unwrap();
        for fuite in [secret, "jean.dupont", "203.0.113.9"] {
            assert!(!detail.contains(fuite), "le registre ne doit pas porter '{fuite}' : {detail}");
        }
        let soc: String = c
            .query_row(
                "SELECT message || COALESCE(fields,'') FROM event WHERE source='plume-config' AND origin='daemon'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        for fuite in [secret, "jean.dupont", "203.0.113.9"] {
            assert!(!soc.contains(fuite), "l'event SOC ne doit pas porter '{fuite}' : {soc}");
        }
    }

    /// LE REGISTRE NE MENT PAS. Si la base supprime moins de lignes que ce qui vient d'être inscrit, TOUT est
    /// annulé : ni suppression, ni entrée de registre. Mesuré en interposant un trigger `BEFORE DELETE` qui
    /// IGNORE une ligne — la divergence est alors réelle, pas simulée.
    #[test]
    fn purge_rolls_back_entirely_when_ledger_and_reality_diverge() {
        let c = test_db();
        let mut ids = Vec::new();
        for i in 0..4 {
            ids.push(pg_ins(&c, 1_000 + i, "flux-de-test", "prod", &format!("l{i}")));
        }
        let sc = || pg_scope(&[("source", "flux-de-test")], 1_000, 1_003);
        let tok = purge_plan(&c, sc()).unwrap().digest().to_string();
        c.execute_batch(&format!(
            "CREATE TRIGGER pg_block BEFORE DELETE ON event BEGIN SELECT RAISE(IGNORE) WHERE OLD.id={}; END;",
            ids[2]
        ))
        .unwrap();
        let e = purge_confirm_and_apply(&c, sc(), &tok, "t", "m").unwrap_err();
        assert_eq!(purge_refusal_code(&e), "count_mismatch");
        assert_eq!(pg_events(&c), 4, "ROLLBACK : aucune ligne supprimée");
        assert_eq!(pg_ledger_purges(&c), 0, "ROLLBACK : l'entrée de registre est annulée avec le reste");
    }

    // ============================================================================================
    // 6. ARTEFACTS DÉRIVÉS — une purge qui laisse des agrégats gonflés est une purge qui ment
    // ============================================================================================

    /// L'index PLEIN-TEXTE ne garde aucun posting : le message purgé n'est plus cherchable. (Le trigger
    /// `event_ad` fait le travail ; son absence est un REFUS en amont — cf. `purge_refuses_when_the_fts…`.)
    #[test]
    fn purge_leaves_no_searchable_full_text_posting() {
        let c = test_db();
        pg_ins(&c, 1_000, "flux-de-test", "prod", "intrusion zzqqxx sur le bastion");
        pg_ins(&c, 1_000, "sshd", "prod", "intrusion zzqqxx ailleurs");
        let hits = |c: &Connection| -> i64 {
            c.query_row("SELECT COUNT(*) FROM event_fts WHERE event_fts MATCH 'zzqqxx'", [], |r| r.get(0)).unwrap()
        };
        assert_eq!(hits(&c), 2, "précondition : les deux lignes sont indexées");
        let sc = || pg_scope(&[("source", "flux-de-test")], 0, 2_000);
        let tok = purge_plan(&c, sc()).unwrap().digest().to_string();
        purge_confirm_and_apply(&c, sc(), &tok, "t", "m").unwrap();
        assert_eq!(hits(&c), 1, "le posting de la ligne purgée est parti, celui de l'autre reste");
    }

    /// LES ROLLUPS SONT RÉCONCILIÉS : après purge, `event_rollup` est une image des lignes SURVIVANTES sur la
    /// bande recouverte — pas un agrégat qui continue de compter les lignes détruites (ce qui rendrait le
    /// contenu purgé encore visible sous forme de comptes).
    #[test]
    fn purge_rebuilds_rollups_to_match_surviving_rows() {
        let c = test_db();
        let base = (now() / 3600) * 3600 - 2 * 3600; // heure ENTIÈREMENT définitive (sous la fenêtre chaude)
        for i in 0..6 {
            pg_ins(&c, base + i, "flux-de-test", "prod", &format!("t{i}"));
        }
        for i in 0..4 {
            pg_ins(&c, base + 10 + i, "sshd", "prod", &format!("s{i}"));
        }
        rollup_events(&c);
        let n_of = |c: &Connection, src: &str| -> i64 {
            c.query_row(
                "SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE bucket=?1 AND source=?2",
                params![base / 3600 * 3600, src],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!((n_of(&c, "flux-de-test"), n_of(&c, "sshd")), (6, 4), "précondition : rollup peuplé");

        let sc = || pg_scope(&[("source", "flux-de-test")], base, base + 5);
        let tok = purge_plan(&c, sc()).unwrap().digest().to_string();
        let r = purge_confirm_and_apply(&c, sc(), &tok, "t", "m").unwrap();
        // Le reçu DIT ce qui a été fait : ré-agrégé (une couverture était publiée) et non « seulement vidé ».
        assert!(r.rollup_reaggregated, "couverture publiée -> les buckets sont RÉ-AGRÉGÉS, pas seulement supprimés");
        assert!(purge_receipt_text(&r).contains("ré-agrégés"), "le reçu ne revendique que ce qui a eu lieu");

        assert_eq!(n_of(&c, "flux-de-test"), 0, "l'agrégat de la source purgée ne SURVIT PAS à la purge");
        assert_eq!(n_of(&c, "sshd"), 4, "l'agrégat des lignes SURVIVANTES est intact (pas d'effacement collatéral)");
    }

    /// Le CACHE DE PANNEAUX porte des résultats RENDUS, donc possiblement du contenu purgé : il est vidé dans
    /// la même transaction (il se recalcule tout seul en fond).
    #[test]
    fn purge_clears_the_rendered_panel_cache() {
        let c = test_db();
        pg_ins(&c, 1_000, "flux-de-test", "prod", "x");
        c.execute(
            "INSERT INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(1,'24h','fp',0,'{}')",
            [],
        )
        .unwrap();
        let sc = || pg_scope(&[("source", "flux-de-test")], 0, 2_000);
        let tok = purge_plan(&c, sc()).unwrap().digest().to_string();
        let r = purge_confirm_and_apply(&c, sc(), &tok, "t", "m").unwrap();
        assert_eq!(r.panel_cache_cleared, 1);
        let restants: i64 = c.query_row("SELECT COUNT(*) FROM panel_cache", [], |r| r.get(0)).unwrap();
        assert_eq!(restants, 0, "aucun payload rendu ne survit à la purge");
    }

    /// Le REÇU nomme les sauvegardes, toujours — en JSON comme en texte. Sans ça, « purgé » serait une fausse
    /// promesse pour une demande d'effacement.
    #[test]
    fn purge_receipt_always_names_the_backups_it_does_not_touch() {
        let c = test_db();
        pg_ins(&c, 1_000, "flux-de-test", "prod", "x");
        let sc = || pg_scope(&[("source", "flux-de-test")], 0, 2_000);
        let tok = purge_plan(&c, sc()).unwrap().digest().to_string();
        let r = purge_confirm_and_apply(&c, sc(), &tok, "t", "m").unwrap();
        assert!(purge_receipt_json(&r)["not_covered"]["backups"].as_str().unwrap().contains("SAUVEGARDES"));
        assert!(purge_receipt_text(&r).contains("SAUVEGARDES"));
        assert!(purge_receipt_text(&r).contains(PURGE_LEDGER_KIND), "le reçu dit OÙ la trace a été écrite");
    }

    // ============================================================================================
    // 7. AUTORISATION — pas par tout le monde, et la surface HTTP est fermée par défaut
    // ============================================================================================

    /// La purge est ADMIN-ONLY, GET compris (le préfixe ferme d'avance toute lecture future de périmètre ou
    /// de jeton), et « admin » n'est pas forcément le bon quantum d'autorité : un rôle composable base=admin
    /// peut se voir RETIRER `purge_events` sans perdre le reste.
    #[test]
    fn purge_routes_are_admin_only_and_carve_outable() {
        for p in ["/api/purge/plan", "/api/purge/apply", "/api/purge"] {
            assert_eq!(route_min_role(p, true), MinRole::Admin, "{p} mutant -> Admin");
            assert_eq!(route_min_role(p, false), MinRole::Admin, "{p} en LECTURE -> Admin aussi");
            assert!(rbac_gate("viewer", p, true).is_err(), "viewer refusé sur {p}");
            assert!(rbac_gate("editor", p, true).is_err(), "editor refusé sur {p}");
            assert!(rbac_gate("agent", p, true).is_err(), "agent refusé sur {p}");
            assert!(rbac_gate("client", p, true).is_err(), "jeton client-read refusé sur {p}");
            assert!(rbac_gate("admin", p, true).is_ok(), "admin passe sur {p}");
            assert_eq!(route_denied_perm(p), Some("purge_events"), "{p} porte une perm soustractible");
        }
        assert!(
            KNOWN_DENY_PERMS.contains(&"purge_events"),
            "la perm est dans l'enum FERMÉ (sinon un deny_perm serait ignoré au chargement)"
        );
        // ET LE BALAYAGE DU ROUTEUR COUVRE BIEN CES DEUX ROUTES. La garde de câblage (B-1/B-2/B-3) LIT la
        // table de routage dans `server/groupes_de_routes.rs` : si les deux routes n'y étaient pas lues (ligne commentée,
        // méthode non reconnue), elle passerait au vert en ne les sondant JAMAIS — un vert qui ne mesure
        // rien. On vérifie donc explicitement leur PRÉSENCE dans la table que la garde balaie.
        let table = declared_route_table();
        for p in ["/api/purge/plan", "/api/purge/apply"] {
            let e = table.iter().find(|(path, _)| path == p);
            let (_, methods) = e.unwrap_or_else(|| panic!("{p} absente de la table balayée par les gardes de câblage"));
            assert_eq!(methods, &vec!["POST".to_string()], "{p} déclarée en POST -> sondée comme route MUTANTE");
        }
    }

    /// Un rôle COMPOSABLE base=admin dont `purge_events` est retiré ne peut pas purger, tout en gardant
    /// l'autorité admin ailleurs. C'est la réponse à « admin suffit-il pour détruire des preuves ? » : non,
    /// et l'opérateur peut le trancher sans toucher au code.
    #[test]
    fn purge_can_be_removed_from_an_admin_based_custom_role() {
        let _g = CUSTOM_ROLES_TEST_LOCK.lock();
        *custom_roles_cell().lock() = std::collections::HashMap::from([(
            "admin-sans-purge".to_string(),
            RoleDef { base: "admin".into(), deny: vec!["purge_events".into()] },
        )]);
        assert!(rbac_gate("admin-sans-purge", "/api/purge/apply", true).is_err(), "purge RETIRÉE");
        assert!(rbac_gate("admin-sans-purge", "/api/users", true).is_ok(), "le reste de l'autorité admin demeure");
        custom_roles_cell().lock().clear();
    }

    /// La surface HTTP de purge est FERMÉE par défaut : elle ajoute une capacité de destruction de preuves À
    /// DISTANCE, ce que la sous-commande n'ajoute pas (son appelant détient déjà la clé de la base).
    #[test]
    fn purge_http_surface_is_closed_by_default() {
        assert!(
            !purge_api_enabled(),
            "sans PLUME_PURGE_API posé au déploiement, la route refuse (mode 0 : aucune capacité distante ajoutée)"
        );
    }

    // ============================================================================================
    // 8. VERROU DE COHÉRENCE avec la rétention
    // ============================================================================================

    /// La clause NON-PURGEABLE est UNE seule vérité. La purge en a besoin QUALIFIÉE (elle joint `event` à
    /// `incident_item`, qui porte aussi une colonne `ts`) ; la rétention l'utilise NUE. Ce test verrouille
    /// l'égalité : ajouter une source de contrôle d'un côté seulement fait rougir ici, au lieu de rendre
    /// cette source purgeable par la purge explicite alors que la rétention la protège.
    #[test]
    fn retention_nonpurge_qualified_matches_the_literal() {
        assert_eq!(
            retention_nonpurge_for(""),
            RETENTION_NONPURGE,
            "alias vide == littéral historique, à l'octet près"
        );
        let q = retention_nonpurge_for("event");
        assert!(q.contains("event.origin='daemon'") && q.contains("event.source IN"), "colonnes qualifiées : {q}");
        for s in ["plume-config", "plume-operator-access", "plume-tenant-admin", "plume-engagement"] {
            assert!(q.contains(s), "la source de contrôle '{s}' est protégée des DEUX côtés");
        }
    }
