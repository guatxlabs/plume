    // ================================================================================================
    // CE QUI N'A PAS ÉTÉ FAIT SE DIT — trois instruments de sûreté, mesurés le 2026-08-30.
    //
    // LE FIL COMMUN, ET IL N'EST PAS « UNE ERREUR EST AVALÉE » : c'est qu'un RÉSULTAT VIDE et un TRAVAIL
    // NON FAIT ont la même forme. Zéro case recalculé se lit comme « rien à recalculer ». Cinq cents
    // sources servies se lisent comme « il y en a cinq cents ». Dans les deux cas la réponse est
    // syntaxiquement irréprochable et sémantiquement fausse, et aucun test ne pouvait la prendre en
    // défaut tant que la mesure vivait à l'intérieur d'un handler.
    //
    // TROIS SECTIONS :
    //   (A) `P10.7-m` — le RECALCUL D'ÉCHÉANCES sauté, pendant que la route répond « fait ».
    //   (B) `P10.7-m` (premier défaut, RÉFUTATION) — ce que le vérificateur du journal d'intégrité SAIT
    //       DÉJÀ faire d'un maillon écrit avec un hachage précédent VIDE. L'énoncé disait qu'une
    //       vérification pouvait PASSER dessus. Elle ne passe pas. Ce témoin l'ÉTABLIT, et il rougira le
    //       jour où quelqu'un « corrigera » `ledger_append` en apprenant au vérificateur à tolérer la
    //       rupture — c'est-à-dire le jour où on fermerait une fausse accusation en faisant taire une vraie.
    //   (C) `P11.22-e` — la borne de l'inventaire des `source`, et son aveu.
    //
    // AUCUN TÉMOIN CHRONOMÉTRIQUE ICI : tout est adossé à un GESTE (une table absente), un COMPTE (le
    // nombre de lignes recalculées, la longueur servie) ou une PROPRIÉTÉ STRUCTURELLE (le verdict du
    // vérificateur, le code de statut). Le répertoire temporaire de ce poste est en mémoire ; une mesure
    // de durée y serait verte par construction.
    // ================================================================================================

    /// Trois cases ACTIFS de priorité `pr`, plus une politique SLA qui les gouverne. Rend les identifiants
    /// dans l'ordre où la lecture bornée les prendra (`ORDER BY id`).
    fn trois_cases_actifs(conn: &Connection, pr: i64, combien: i64) -> Vec<i64> {
        conn.execute(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) \
             VALUES('p',?1,60,600,1,1000,'test',1000)",
            params![pr],
        )
        .expect("politique SLA posée");
        let mut ids = Vec::new();
        for i in 0..combien {
            conn.execute(
                "INSERT INTO incident(ts,updated,title,status,severity,priority) VALUES(?1,?1,?2,'open',2,?3)",
                params![1000 + i, format!("case {i}"), pr],
            )
            .expect("case inséré");
            ids.push(conn.last_insert_rowid());
        }
        ids
    }

    /// L'échéance de résolution d'un case, ou `None` si elle n'a jamais été posée.
    fn echeance_de(conn: &Connection, id: i64) -> Option<i64> {
        conn.query_row("SELECT resolve_due FROM incident WHERE id=?1", params![id], |r| r.get::<_, Option<i64>>(0))
            .expect("case lisible")
    }

    // ------------------------------------------------------------------------------------------------
    // (A) `P10.7-m` — LE RECALCUL SAUTÉ.
    // ------------------------------------------------------------------------------------------------

    /// (A1) LE CHEMIN NOMINAL EST MUET, ET IL A VRAIMENT TRAVAILLÉ. Deux assertions, pas une : le compte
    /// ET l'effet. Un recalcul qui compterait trois sans poser aucune échéance passerait la première.
    ///
    /// C'est le TÉMOIN NÉGATIF de toute la section A : si l'aveu était inconditionnel, il rougirait ici.
    #[test]
    fn un_recalcul_complet_ne_dit_rien_et_pose_les_echeances() {
        let conn = test_db();
        let ids = trois_cases_actifs(&conn, 2, 3);
        for id in &ids {
            assert_eq!(echeance_de(&conn, *id), None, "avant recalcul, aucune échéance n'est posée");
        }

        let r = sla_recalcule_la_priorite_bornee(&conn, 2, 10);

        assert_eq!(r.recalcules, 3, "les trois cases actifs sont recalculés");
        assert!(r.complet(), "rien ne manque : la route n'a RIEN à avouer");
        assert_eq!(r.manque, None, "et elle ne dit rien");
        for id in &ids {
            assert!(echeance_de(&conn, *id).is_some(), "case #{id} : l'échéance a RÉELLEMENT été posée");
        }
    }

    /// (A2) LA BORNE EFFLEURÉE NE MENT PAS. Trois cases, plafond de trois : tout a été fait, et la route
    /// doit rester muette. C'est ce cas — et lui seul — qui prouve que l'aveu vient de la ligne
    /// EXCÉDENTAIRE et non d'un `recalcules == plafond`. Un correctif qui aurait comparé le compte au
    /// plafond serait vert partout ailleurs et rouge ICI.
    #[test]
    fn un_recalcul_qui_atteint_exactement_le_plafond_reste_muet() {
        let conn = test_db();
        let ids = trois_cases_actifs(&conn, 3, 3);

        let r = sla_recalcule_la_priorite_bornee(&conn, 3, 3);

        assert_eq!(r.recalcules, 3, "les trois y sont");
        assert!(r.complet(), "pile le plafond n'est PAS une troncature : {:?}", r.manque);
        for id in &ids {
            assert!(echeance_de(&conn, *id).is_some(), "case #{id} recalculé");
        }
    }

    /// (A3) LA BORNE QUI MORD LE DIT, ET DIT COMBIEN. Trois cases, plafond de deux : deux échéances
    /// posées, la troisième INCHANGÉE, et la raison nomme le plafond.
    #[test]
    fn un_recalcul_borne_dit_que_des_cases_gardent_leur_ancienne_echeance() {
        let conn = test_db();
        let ids = trois_cases_actifs(&conn, 1, 3);

        let r = sla_recalcule_la_priorite_bornee(&conn, 1, 2);

        assert_eq!(r.recalcules, 2, "le plafond est SERVI, pas dépassé");
        assert!(!r.complet(), "la borne a mordu : la route doit le dire");
        let raison = r.manque.clone().expect("une raison est portée");
        assert!(raison.contains("plafond"), "la raison nomme le plafond : {raison}");
        assert!(echeance_de(&conn, ids[0]).is_some() && echeance_de(&conn, ids[1]).is_some());
        assert_eq!(
            echeance_de(&conn, ids[2]),
            None,
            "le case au-delà du plafond garde son ANCIENNE échéance — c'est exactement ce que le silence cachait"
        );
    }

    /// (A4) UNE LISTE ILLISIBLE N'EST PAS UNE LISTE VIDE, ET LES DEUX RAISONS NE SE CONFONDENT PAS.
    ///
    /// LE GESTE : une base SANS table `incident` (pas une base lente, pas une base grande — une base où la
    /// lecture ne peut PAS aboutir). `prepare` échoue, l'ancien `unwrap_or_default()` rendait une liste
    /// vide, la boucle ne tournait pas, et la route répondait `204` = « fait ».
    ///
    /// Et la raison rendue doit être la BONNE : « illisible », jamais « plafond ». Une seule des deux se
    /// répare en augmentant la borne.
    #[test]
    fn une_liste_de_cases_illisible_ne_se_lit_pas_comme_aucun_case() {
        let sans_incident = Connection::open_in_memory().expect("base en mémoire");

        let r = sla_recalcule_la_priorite_bornee(&sans_incident, 2, 5000);

        assert_eq!(r.recalcules, 0, "aucune échéance n'a été recalculée");
        assert!(!r.complet(), "et la route ne doit PAS répondre « fait »");
        let raison = r.manque.clone().expect("une raison est portée");
        assert!(raison.contains("ILLISIBLE"), "la raison nomme l'illisibilité : {raison}");
        assert!(!raison.contains("plafond"), "et surtout PAS le plafond : {raison}");

        // Le contraste, sur la MÊME assertion : zéro case ACTIF, mais la table se lit -> rien à faire,
        // donc tout est fait, donc silence. `recalcules == 0` porte deux vérités opposées ; seul `manque`
        // les sépare.
        let vide = test_db();
        let r_vide = sla_recalcule_la_priorite_bornee(&vide, 2, 5000);
        assert_eq!(r_vide.recalcules, 0, "même compte");
        assert!(r_vide.complet(), "et pourtant : rien à faire = tout est fait");
    }

    /// (A5) CE QUE LA ROUTE REND, AUX TROIS ISSUES. Le `204` nominal est SANS CORPS — c'est le contrat
    /// d'avant, et il est conservé : une route qui se justifierait à chaque appel n'apprendrait rien.
    #[tokio::test]
    async fn la_route_d_upsert_sla_ne_parle_que_quand_fait_serait_faux() {
        // (i) NOMINAL : politique écrite, recalcul complet -> 204, corps VIDE.
        let complet = RecalculDesEcheances { recalcules: 3, manque: None };
        let r = reponse_de_l_upsert_sla(Ok(()), &complet).into_response();
        assert_eq!(r.status(), StatusCode::NO_CONTENT, "nominal -> 204");
        let corps = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        assert!(corps.is_empty(), "nominal -> AUCUN corps (un aveu inconditionnel ne vaut rien)");

        // (ii) POLITIQUE POSÉE, RECALCUL INCOMPLET -> 200 + le corps dit lequel des deux a eu lieu.
        let partiel = RecalculDesEcheances { recalcules: 5000, manque: Some("plafond de 5000 case(s) atteint".into()) };
        let (code, v) = tok_resp_json(reponse_de_l_upsert_sla(Ok(()), &partiel)).await;
        assert_eq!(code, StatusCode::OK, "la politique EST posée : un 5xx ferait croire le contraire");
        // `policy_saved` et `recompute_complete` ont été RETIRÉS le 2026-08-31 : le premier répétait
        // le statut asséré juste au-dessus, le second était constant. Ce que le client lit est le CODE.
        assert_eq!(v["recomputed"], json!(5000));
        assert!(v["reason"].as_str().unwrap().contains("plafond"), "la raison est SERVIE : {v}");

        // (iii) POLITIQUE NON ÉCRITE -> 500, et le corps le dit. C'est la phrase de l'énoncé prise au mot :
        // « un exploitant croit avoir appliqué une politique qui ne l'a pas été ».
        let (code, v) = tok_resp_json(reponse_de_l_upsert_sla(
            Err("table sla_policy absente".into()),
            &RecalculDesEcheances::default(),
        ))
        .await;
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR, "rien n'a été posé -> 500");
        // le statut asséré ci-dessus EST la réponse ; un booléen qui le répète n'ajoutait rien.
        assert!(v["reason"].as_str().unwrap().contains("NON enregistrée"), "{v}");
    }

    // ------------------------------------------------------------------------------------------------
    // (B) `P10.7-m` PREMIER DÉFAUT — RÉFUTATION MESURÉE.
    // ------------------------------------------------------------------------------------------------

    /// UN MAILLON À HACHAGE PRÉCÉDENT VIDE, EN MILIEU DE CHAÎNE, EST REFUSÉ PAR LES DEUX VÉRIFICATEURS.
    ///
    /// L'ÉNONCÉ QUI A OUVERT CETTE CLÉ DISAIT : « une vérification d'intégrité peut PASSER sur un journal
    /// dont un maillon a été perdu », le journal restant « vérifiable des DEUX CÔTÉS de la coupure ».
    /// C'EST FAUX SUR CET ARBRE, et ce témoin le mesure. `verify_ledger_conn` ne vérifie pas des segments :
    /// il déroule UNE chaîne depuis le genèse, en portant le hachage courant. Un maillon dont le `prev_hash`
    /// est vide alors que la chaîne courante ne l'est pas échoue sur `prev_hash != prev`, et le verdict
    /// NOMME l'entrée. Le vérificateur d'export (`ledger_verify_export`) applique la même loi.
    ///
    /// CE QUE CE TÉMOIN TIENT DONC, ET C'EST SA VRAIE RAISON D'ÊTRE : il interdit qu'on rende cette
    /// rupture TOLÉRABLE. Des trois issues offertes à `ledger_append` quand il ne peut pas lire le maillon
    /// précédent — refuser d'écrire · écrire en marquant la rupture · écrire en tête d'une chaîne neuve
    /// DÉCLARÉE — les deux dernières exigent que le vérificateur apprenne à laisser passer un chaînon
    /// vide. Ce jour-là, ce test rougit. Il est là pour ça : un correctif qui ferme une fausse accusation
    /// ne doit pas faire taire une vraie.
    ///
    /// INSTRUMENT VALIDÉ DANS LES DEUX SENS — un quatrième maillon écrit par le VRAI chemin n'accuse
    /// personne, le cinquième, forgé comme le ferait une lecture ratée, accuse. Sans le premier sens, un
    /// vérificateur qui crierait à tout propos passerait ce test sans rien prouver.
    #[test]
    fn un_maillon_a_hachage_precedent_vide_est_refuse_par_le_verificateur() {
        let conn = test_db();
        let deja: i64 = conn.query_row("SELECT COUNT(*) FROM ledger", [], |r| r.get(0)).expect("journal lisible");
        for i in 0..3 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }

        // SENS 1 — la chaîne écrite par le VRAI chemin n'accuse personne.
        let (n, _, _, rupture) = verify_ledger_conn(&conn, None).expect("chaîne lisible");
        assert_eq!(n as i64, deja + 3, "les trois maillons sont vus");
        assert!(rupture.is_none(), "une chaîne saine ne doit accuser personne : {rupture:?}");

        // SENS 1 bis — un quatrième maillon, toujours par le vrai chemin : toujours muet.
        ledger_append(&conn, "config.mode", "maillon 3");
        let (_, _, _, rupture) = verify_ledger_conn(&conn, None).expect("chaîne lisible");
        assert!(rupture.is_none(), "le chaînage nominal reste muet : {rupture:?}");

        // SENS 2 — LE MAILLON QUE `ledger_append` ÉCRIRAIT SI SA LECTURE DU HACHAGE PRÉCÉDENT ÉCHOUAIT.
        // On ne casse rien à la main : on reproduit EXACTEMENT son calcul avec `prev` retombé sur la
        // valeur par défaut (le vide) — donc un maillon PARFAITEMENT cohérent avec lui-même, en tête
        // d'une chaîne neuve. C'est le cas que l'énoncé disait indétectable.
        let ts = now();
        let (kind, detail) = ("config.mode", "en tete d'une chaine neuve");
        let hash = sha256_hex(format!("|{ts}|{kind}|{detail}").as_bytes());
        conn.execute(
            "INSERT INTO ledger(ts,kind,detail,prev_hash,hash) VALUES(?1,?2,?3,'',?4)",
            params![ts, kind, detail, hash],
        )
        .expect("maillon inséré");
        let orphelin = conn.last_insert_rowid();

        let (_, _, _, rupture) = verify_ledger_conn(&conn, None).expect("chaîne lisible");
        assert_eq!(
            rupture,
            Some(orphelin),
            "le vérificateur DOIT nommer le maillon orphelin — si ce test rougit ici, c'est que la \
             vérification est devenue tolérante à une chaîne neuve non déclarée"
        );

        // ET LE VÉRIFICATEUR D'EXPORT, sur la MÊME base : même loi, même refus.
        let (lignes, _, _) = ledger_export_lines(&conn, 0, 0);
        let verdict = ledger_verify_export(&lignes, "");
        let message = verdict.expect_err("l'export d'une chaîne rompue ne doit pas se vérifier");
        assert!(message.contains("rupture de chaîne"), "le message NOMME la rupture : {message}");
    }

    // ------------------------------------------------------------------------------------------------
    // (C) `P11.22-e` — LA BORNE DE L'INVENTAIRE DES `source`.
    // ------------------------------------------------------------------------------------------------

    /// Pose `combien` sources DISTINCTES dans le rollup, en une transaction.
    fn semer_des_sources(conn: &Connection, combien: usize) {
        conn.execute_batch("BEGIN").expect("transaction ouverte");
        {
            let mut s = conn
                .prepare("INSERT INTO event_rollup(bucket,source,severity,action,n) VALUES(?1,?2,0,'',1)")
                .expect("insertion préparée");
            for i in 0..combien {
                s.execute(params![1000i64, format!("src-{i:05}")]).expect("source semée");
            }
        }
        conn.execute_batch("COMMIT").expect("transaction close");
    }

    /// (C1) SOUS LA BORNE : la liste EST l'inventaire, et la réponse ne dit rien de plus. TÉMOIN NÉGATIF.
    #[test]
    fn un_inventaire_de_sources_sous_la_borne_ne_s_avoue_pas_ecourte() {
        let conn = test_db();
        semer_des_sources(&conn, 3);

        let s = soql_known_sources_bornees(&conn);

        assert_eq!(s.valeurs.len(), 3, "les trois sources sont servies");
        assert!(!s.ecourtee, "rien n'est caché : la réponse ne doit RIEN avouer");
    }

    /// (C2) PILE LA BORNE : cinq cents sources et cinq cents servies — la liste EST l'inventaire. C'est le
    /// cas qui sépare un aveu MESURÉ d'un aveu déduit de `len() == SOQL_SOURCES_MAX` : ce dernier serait
    /// rouge ici. Il joue la VRAIE constante de production, pas un plafond de test.
    #[test]
    fn un_inventaire_de_sources_pile_a_la_borne_ne_s_avoue_pas_ecourte() {
        let conn = test_db();
        semer_des_sources(&conn, SOQL_SOURCES_MAX);

        let s = soql_known_sources_bornees(&conn);

        assert_eq!(s.valeurs.len(), SOQL_SOURCES_MAX, "les cinq cents sont servies");
        assert!(!s.ecourtee, "pile la borne n'est PAS une troncature");
    }

    /// (C3) UNE DE PLUS QUE LA BORNE : la liste n'est plus l'inventaire, et la réponse le DIT. La 501e
    /// n'est pas servie — elle est LUE, et son existence seule fonde l'aveu.
    #[test]
    fn un_inventaire_de_sources_au_dela_de_la_borne_s_avoue_ecourte() {
        let conn = test_db();
        semer_des_sources(&conn, SOQL_SOURCES_MAX + 1);

        let s = soql_known_sources_bornees(&conn);

        assert_eq!(s.valeurs.len(), SOQL_SOURCES_MAX, "la borne est SERVIE, jamais dépassée");
        assert!(s.ecourtee, "il en existait davantage, et l'exploitant doit l'apprendre");
        assert!(
            !s.valeurs.contains(&format!("src-{:05}", SOQL_SOURCES_MAX)),
            "la ligne excédentaire PROUVE le reste, elle ne se sert pas"
        );
        // La compat des deux lecteurs internes (`sigma`, `detection_aveugle`) : même liste, sans l'aveu.
        assert_eq!(soql_known_sources(&conn), s.valeurs, "la façade de compat rend EXACTEMENT la liste");
    }

    /// (C4) CE QUE L'AVEU NE COUVRE PAS, ÉCRIT PLUTÔT QUE SUPPOSÉ. Un rollup ILLISIBLE rend une liste vide
    /// et `ecourtee=false` — délibérément : cette lecture n'a rien vu, donc elle ne sait pas qu'il en
    /// existait davantage, et crier « écourté » y serait un second mensonge. Le type sépare « bornée » de
    /// « complète » ; il ne sépare PAS « vide » de « illisible ». C'est le défaut de la section A, sur une
    /// autre lecture, et il reste OUVERT ici.
    #[test]
    fn un_rollup_illisible_ne_s_avoue_pas_ecourte_et_c_est_dit() {
        let sans_rollup = Connection::open_in_memory().expect("base en mémoire");

        let s = soql_known_sources_bornees(&sans_rollup);

        assert!(s.valeurs.is_empty(), "rien n'a pu être lu");
        assert!(!s.ecourtee, "une lecture qui n'a rien vu ne peut pas affirmer qu'il en existait plus");
    }

    /// (C5) L'AVEU ATTEINT LE CLIENT. Mesurer la troncature sans la SERVIR ne corrigerait rien : c'est la
    /// console qui doit pouvoir dire à l'exploitant que le compte affiché n'est pas le total. Le corps de
    /// `/api/soql/schema` est une fonction PURE (aucun `AppState`, aucun cache) précisément pour que sa
    /// FORME soit prouvable ici, et pas seulement sa mesure.
    #[test]
    fn la_route_de_schema_sert_l_aveu_de_troncature() {
        let ecourtee = soql_schema_json(SourcesConnues { valeurs: vec!["a".into(), "b".into()], ecourtee: true });
        assert_eq!(ecourtee["values"]["source"], json!(["a", "b"]), "la liste est servie telle quelle");
        assert_eq!(ecourtee["values"]["source_capped"], json!(true), "et la troncature est SERVIE : {ecourtee}");

        let complete = soql_schema_json(SourcesConnues { valeurs: vec!["a".into()], ecourtee: false });
        assert_eq!(
            complete["values"]["source_capped"],
            json!(false),
            "et le chemin nominal ne crie pas : un aveu inconditionnel ne vaut rien"
        );

        // Le reste du vocabulaire est INCHANGÉ par l'extraction (déplacement pur du corps de la route).
        assert_eq!(complete["commands"], json!(SOQL_PIPE_COMMANDS), "les commandes sont intactes");
        assert!(complete["docs"]["commands"].is_object(), "la doc inline est intacte");
        assert_eq!(complete["cim_version"], json!(CIM_VERSION), "la version CIM est intacte");
    }

    /// (A6) LA ROUTE RÉELLE, CÂBLÉE — parce qu'une fonction de réponse juste ne prouve pas qu'un handler
    /// l'appelle. Ce témoin monte l'état, poste la politique et lit la BASE, sur les deux issues qui
    /// vivaient dans le silence :
    ///   · NOMINAL : `204`, la politique EST en base, ET le journal d'intégrité en porte la trace ;
    ///   · ÉCRITURE IMPOSSIBLE : `500`, et le journal ne gagne AUCUNE ligne. L'ancien `let _ = execute`
    ///     ledgerisait inconditionnellement : le journal aurait porté une politique que la base n'avait pas.
    #[tokio::test]
    async fn la_route_d_upsert_sla_ne_ledgerise_que_ce_qui_a_ete_ecrit() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let corps = json!({ "name": "or", "priority": 2, "ack_target_s": 60, "resolve_target_s": 600 });
        let compter = |st: &AppState| -> i64 {
            st.db.lock()
                .query_row("SELECT COUNT(*) FROM ledger WHERE kind='sla_policy.upsert'", [], |r| r.get(0))
                .expect("journal lisible")
        };
        assert_eq!(compter(&st), 0, "rien n'a encore été posé");

        // (i) NOMINAL.
        let r = sla_policy_upsert(State(st.clone()), Extension(tok_au("editor")), Json(corps.clone())).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT, "politique posée, recalcul complet -> 204 muet");
        {
            let c = st.db.lock();
            let n: i64 = c.query_row("SELECT COUNT(*) FROM sla_policy WHERE priority=2", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 1, "la politique est RÉELLEMENT en base");
        }
        assert_eq!(compter(&st), 1, "et le journal d'intégrité la porte");

        // (ii) ÉCRITURE IMPOSSIBLE — le GESTE : la table de destination n'existe plus.
        st.db.lock().execute("DROP TABLE sla_policy", []).expect("table retirée");
        let (code, v) = tok_resp_json(sla_policy_upsert(State(st.clone()), Extension(tok_au("editor")), Json(corps)).await).await;
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR, "rien n'a pu être écrit -> la route ne dit pas « fait »");
        assert_eq!(
            compter(&st),
            1,
            "LE JOURNAL N'A PAS BOUGÉ : une politique non écrite ne s'y consigne pas"
        );
    }
