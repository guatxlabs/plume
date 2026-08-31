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
        let (lignes, _, _) = ledger_export_lines(&conn, 0, 0).expect("toutes les lignes se LISENT : c'est leur CHAÎNAGE qui est rompu");
        let verdict = ledger_verify_export(&lignes, "");
        let message = verdict.expect_err("l'export d'une chaîne rompue ne doit pas se vérifier");
        assert!(message.contains("rupture de chaîne"), "le message NOMME la rupture : {message}");
    }

    // ------------------------------------------------------------------------------------------------
    // (B bis) `P10.7-m` — LA MOITIÉ ÉCRITURE, FERMÉE LE 2026-08-31. Le vérificateur n'a pas bougé d'une
    // ligne ; c'est `ledger_append` / `audit_source_change` qui cessent d'écrire un maillon orphelin.
    //
    // CE QUE LE GESTE EST, ET CE QU'IL N'EST PAS : il ne « refuse » pas — il DISCRIMINE SUR L'ERREUR.
    // L'absence de ligne (`QueryReturnedNoRows`) est l'ORIGINE LÉGITIME du journal, donc la toute
    // première écriture nominale : elle s'accroche à la chaîne vide et ne dit rien. Toute AUTRE erreur de
    // lecture veut dire qu'on ignore à quoi s'accrocher : là, et là seulement, on n'écrit pas.
    //
    // LE GESTE DES TÉMOINS (aucune horloge, aucune durée) : une dernière ligne dont le `hash` est un
    // BLOB. SQLite range un BLOB tel quel dans une colonne d'affinité TEXT -> la LECTURE du maillon
    // précédent meurt, l'ÉCRITURE reste parfaitement vivante. C'est ce qui rend ces témoins
    // DISCRIMINANTS : sous une panne globale (table retirée, base fermée) l'écriture échouerait AUSSI et
    // « aucune ligne écrite » serait vrai pour la mauvaise raison — vert par construction.
    // ------------------------------------------------------------------------------------------------

    /// Un journal REMIS À VIERGE : `test_db()` fait tourner la chaîne de migrations, qui consigne. Pour
    /// mesurer la TOUTE PREMIÈRE écriture il faut donc une table réellement vide, pas « presque vide ».
    fn un_journal_vierge() -> Connection {
        let conn = test_db();
        conn.execute("DELETE FROM ledger", []).expect("journal vidé");
        assert_eq!(compter_les_maillons(&conn), 0, "fixture : le journal part VIERGE");
        conn
    }

    fn compter_les_maillons(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM ledger", [], |r| r.get(0)).expect("journal comptable")
    }

    /// LE GESTE. La dernière ligne du journal porte un `hash` NON TEXTUEL : `SELECT hash … LIMIT 1` ne se
    /// convertit plus en `String`, et l'erreur rendue n'est PAS `QueryReturnedNoRows`. C'est exactement la
    /// classe d'échec que l'ancien `unwrap_or_default()` confondait avec un journal vierge.
    fn rendre_le_maillon_precedent_illisible(conn: &Connection) {
        conn.execute(
            "INSERT INTO ledger(ts,kind,detail,prev_hash,hash) VALUES(?1,'poison','hachage non textuel','',X'FF')",
            params![now()],
        )
        .expect("ligne de poison insérée");
    }

    /// (B1) LE CHEMIN NOMINAL — TÉMOIN NÉGATIF DE TOUT LE LOT. La toute première écriture d'un journal
    /// VIERGE s'accroche à la chaîne vide, réussit, et n'accuse personne. Un correctif qui aurait refusé
    /// « quand la lecture ne rend rien » — c'est-à-dire qui n'aurait pas discriminé sur l'ERREUR —
    /// rougirait ICI, et il aurait rendu le journal d'intégrité INÉCRIVIBLE sur une base neuve.
    ///
    /// Les DEUX voies sont exercées : `ledger_append` (best-effort) et `audit_source_change` (fail-closed).
    #[test]
    fn la_toute_premiere_ecriture_d_un_journal_vierge_reussit_et_reste_muette() {
        // (i) la voie best-effort.
        let conn = un_journal_vierge();
        ledger_append(&conn, "config.mode", "toute première écriture");
        assert_eq!(compter_les_maillons(&conn), 1, "l'origine s'ÉCRIT : refuser ici rendrait le journal inécrivible");
        let (prev_hash, hash): (String, String) = conn
            .query_row("SELECT prev_hash,hash FROM ledger ORDER BY id DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("maillon lisible");
        assert_eq!(prev_hash, "", "l'origine s'accroche à la chaîne VIDE — c'est le seul vide légitime");
        assert!(!hash.is_empty(), "et elle porte bien un hachage");
        let (n, _, _, rupture) = verify_ledger_conn(&conn, None).expect("chaîne lisible");
        assert_eq!(n, 1, "le vérificateur voit l'unique maillon");
        assert!(rupture.is_none(), "la toute première écriture n'accuse personne : {rupture:?}");

        // (ii) la voie fail-closed, sur un journal vierge lui aussi.
        let conn = un_journal_vierge();
        audit_source_change(&conn, "plume-config", "config.mode", "mode passif", 3, "mode changé", "{}")
            .expect("le double-audit RÉUSSIT sur un journal vierge");
        assert_eq!(compter_les_maillons(&conn), 1, "le maillon d'origine est posé");
        let (_, _, _, rupture) = verify_ledger_conn(&conn, None).expect("chaîne lisible");
        assert!(rupture.is_none(), "et il n'accuse personne : {rupture:?}");
    }

    /// (B2) LE LECTEUR SÉPARE LES DEUX CAS, ET C'EST TOUT CE QU'IL FAIT. Témoin direct de la
    /// discrimination, indépendant des deux appelants : vierge -> `Ok("")`, illisible -> `Err`, et
    /// l'erreur rendue n'est PAS celle de l'absence (sans quoi les deux se reconfondraient).
    #[test]
    fn le_lecteur_du_maillon_precedent_separe_le_journal_vierge_de_l_illisible() {
        let conn = un_journal_vierge();
        assert_eq!(ledger_prev_hash(&conn).expect("un journal vierge N'EST PAS une erreur"), "");

        ledger_append(&conn, "config.mode", "maillon 0");
        let pose = ledger_prev_hash(&conn).expect("journal lisible");
        assert!(!pose.is_empty(), "une chaîne commencée rend son dernier hachage");

        rendre_le_maillon_precedent_illisible(&conn);
        let e = ledger_prev_hash(&conn).expect_err("un hachage non textuel est une ERREUR, pas une chaîne vide");
        assert!(
            !matches!(e, rusqlite::Error::QueryReturnedNoRows),
            "et surtout PAS l'erreur d'absence — c'est cette confusion-là que la clé ferme : {e}"
        );
    }

    /// (B3) UNE LECTURE IMPOSSIBLE FAIT REFUSER L'ÉCRITURE — `ledger_append`. Avant le 2026-08-31, ce
    /// témoin comptait UN maillon de plus : un orphelin de `prev_hash` vide, en tête d'une chaîne neuve
    /// que personne n'a déclarée, et que les deux vérificateurs auraient dès lors accusé pour toujours.
    ///
    /// INSTRUMENT VALIDÉ DANS LES DEUX SENS, et c'est ce qui le rend opposable : sous le MÊME poison une
    /// écriture BRUTE passe (la lecture est morte, pas l'écriture), et une fois le poison retiré la voie
    /// nominale réécrit. Un « correctif » qui aurait simplement cessé d'écrire serait vert au premier
    /// tiers et rouge au troisième.
    #[test]
    fn un_hachage_precedent_illisible_fait_refuser_l_ecriture_du_maillon() {
        let conn = un_journal_vierge();
        ledger_append(&conn, "config.mode", "maillon 0");
        rendre_le_maillon_precedent_illisible(&conn);
        let avant = compter_les_maillons(&conn);

        ledger_append(&conn, "config.mode", "maillon qui romprait la chaîne");

        assert_eq!(
            compter_les_maillons(&conn),
            avant,
            "AUCUN maillon écrit : à hachage précédent illisible, on préfère l'entrée manquante à la chaîne rompue"
        );

        // SENS 2 — la LECTURE est morte, l'ÉCRITURE ne l'est pas. Sans cette assertion, le refus mesuré
        // ci-dessus pourrait n'être qu'une base inutilisable, et le témoin serait vert pour rien.
        conn.execute(
            "INSERT INTO ledger(ts,kind,detail,prev_hash,hash) VALUES(?1,'sonde','','','sonde')",
            params![now()],
        )
        .expect("une écriture brute passe sous le MÊME poison");

        // SENS 3 — poison retiré, la voie nominale réécrit. Le refus était CONDITIONNEL.
        conn.execute("DELETE FROM ledger WHERE kind IN ('poison','sonde')", []).expect("poison retiré");
        let avant = compter_les_maillons(&conn);
        ledger_append(&conn, "config.mode", "maillon 1");
        assert_eq!(compter_les_maillons(&conn), avant + 1, "la lecture redevenue possible, l'écriture reprend");
        let (_, _, _, rupture) = verify_ledger_conn(&conn, None).expect("chaîne lisible");
        assert!(rupture.is_none(), "et la chaîne est restée UNE chaîne : {rupture:?}");
    }

    /// (B4) UNE LECTURE IMPOSSIBLE FAIT REMONTER L'ERREUR — `audit_source_change`. C'est la forme que le
    /// jumeau portait DÉJÀ pour ses deux écritures : l'erreur remonte, l'appelant ROLLBACK, la mutation
    /// n'est jamais persistée sans audit. Elle couvre maintenant AUSSI la lecture du maillon précédent.
    ///
    /// DEUX assertions, pas une : l'erreur remonte ET rien n'a été écrit — ni le maillon, ni l'event de
    /// contrôle. Un correctif qui aurait rendu `Err` APRÈS avoir posé l'orphelin passerait la première.
    #[test]
    fn un_hachage_precedent_illisible_fait_remonter_l_erreur_du_double_audit() {
        let conn = un_journal_vierge();
        ledger_append(&conn, "config.mode", "maillon 0");
        rendre_le_maillon_precedent_illisible(&conn);
        let maillons_avant = compter_les_maillons(&conn);
        let events_avant: i64 = conn
            .query_row("SELECT COUNT(*) FROM event WHERE source='plume-config'", [], |r| r.get(0))
            .expect("events comptables");

        let verdict = audit_source_change(&conn, "plume-config", "config.mode", "mode passif", 3, "mode changé", "{}");

        verdict.expect_err("l'erreur DOIT remonter — c'est elle qui fait annuler l'appelant");
        assert_eq!(compter_les_maillons(&conn), maillons_avant, "aucun maillon orphelin n'a été posé");
        let events_apres: i64 = conn
            .query_row("SELECT COUNT(*) FROM event WHERE source='plume-config'", [], |r| r.get(0))
            .expect("events comptables");
        assert_eq!(events_apres, events_avant, "et l'event de contrôle non plus : le double-audit est resté ENTIER");
    }

    /// (B5) LE DOUBLE ANCRAGE DU VÉRIFICATEUR D'EXPORT, MESURÉ SANS TOUCHER AU VÉRIFICATEUR. On ne relâche
    /// pas son code : on lui présente DEUX variantes du même maillon orphelin, taillées pour n'exposer
    /// qu'un ancrage à la fois.
    ///
    /// POURQUOI CE TÉMOIN EXISTE — c'est LUI qui justifie le geste retenu. Si un seul ancrage tenait la
    /// chaîne, « marquer la rupture » resterait envisageable : il suffirait d'apprendre UNE tolérance.
    /// Les deux tenant CHACUN SEUL, marquer la rupture ou déclarer une chaîne neuve exigerait d'en
    /// apprendre DEUX — donc de créer le chemin par lequel une chaîne rompue devient VERTE. D'où : on
    /// refuse d'écrire, et le vérificateur ne bouge pas.
    #[test]
    fn les_deux_ancrages_du_verificateur_d_export_mordent_chacun_seul() {
        let conn = un_journal_vierge();
        for i in 0..2 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }
        let (saines, _, dernier_hash) = ledger_export_lines(&conn, 0, 0).expect("une chaîne saine s'exporte");
        assert_eq!(ledger_verify_export(&saines, "").expect("une chaîne saine se vérifie"), 2);

        // Le maillon tel que l'ancien repli l'écrivait : hachage calculé sur la chaîne VIDE.
        let ts = now();
        let (kind, detail) = ("config.mode", "en tete d'une chaine neuve");
        let hachage_du_vide = sha256_hex(format!("|{ts}|{kind}|{detail}").as_bytes());

        // VARIANTE 1 — tel quel : `prev_hash` vide. La COMPARAISON mord la première, et NOMME la rupture.
        let mut v1 = saines.clone();
        v1.push(ledger_export_line(99, ts, kind, detail, "", &hachage_du_vide));
        let m1 = ledger_verify_export(&v1, "").expect_err("un orphelin ne se vérifie pas");
        assert!(m1.contains("rupture de chaîne"), "premier ancrage — la comparaison : {m1}");

        // VARIANTE 2 — LE MÊME hachage, mais le `prev_hash` RÉPARÉ pour tromper la comparaison. Elle
        // passe ; le RECALCUL mord seul, et son message est DIFFÉRENT — deux ancrages, pas un dédoublé.
        let mut v2 = saines.clone();
        v2.push(ledger_export_line(99, ts, kind, detail, &dernier_hash, &hachage_du_vide));
        let m2 = ledger_verify_export(&v2, "").expect_err("un hachage calculé sur une autre chaîne ne se vérifie pas");
        assert!(m2.contains("hash altéré"), "second ancrage — le recalcul, SEUL : {m2}");
        assert_ne!(m1, m2, "les deux ancrages rendent des verdicts DISTINCTS : ils sont bien deux");
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

    // ------------------------------------------------------------------------------------------------
    // (D) `P10.7-q` — LE VÉRIFICATEUR DU JOURNAL D'INTÉGRITÉ CESSE D'APLATIR SES LIGNES.
    //
    // LE DÉFAUT, MESURÉ SUR CET ARBRE LE 2026-08-31 AVANT TOUTE CORRECTION, et il était logé DEUX FOIS
    // dans les quinze lignes de `verify_ledger_conn` — l'instrument même dont c'est le métier :
    //   · trois maillons en base, le `hash` du dernier remplacé par un blob -> `Ok((2, 0, 0, None))`,
    //     soit « deux entrées, aucune rupture » rendu sur une chaîne AMPUTÉE dont les trois lignes
    //     étaient toujours là. Un verdict d'INTÉGRITÉ trop OPTIMISTE ;
    //   · un checkpoint dont le `pubkey` est un blob -> `Ok((1, 0, 0, None))` : il quittait les DEUX
    //     compteurs. Et comme `verify_run` ne durcit (sortie 1) que sur `sig_ko > 0`, ABÎMER un
    //     checkpoint au lieu de le RE-SIGNER faisait imprimer « ledger OK … OK=0 KO=0 » et sortir en 0,
    //     PIN escrow posé ou non. Le second `flatten()` était donc aussi un contournement du PIN.
    //
    // LE GESTE DES TÉMOINS (aucune horloge, aucune durée — le répertoire temporaire est en mémoire ici) :
    // le MÊME que celui de la section (B bis), une valeur NON TEXTUELLE (`X'FF'`) dans une colonne
    // d'affinité TEXT. SQLite l'y range telle quelle : la LIGNE reste en base, comptable par
    // `COUNT(*)`, et c'est sa seule LECTURE typée qui meurt. C'est ce qui rend ces témoins
    // DISCRIMINANTS — sous une panne globale (table retirée, clé absente) `Err` serait vrai pour la
    // mauvaise raison, et chaque témoin ci-dessous assert donc l'état SAIN de la MÊME connexion avant
    // d'abîmer une seule ligne.
    //
    // LES QUATRE ISSUES SONT SÉPARÉES, ET DEUX TÉMOINS EXISTENT POUR QUE LE REMÈDE NE DEVIENNE PAS LE
    // DÉFAUT RETOURNÉ : `une_chaine_saine…` interdit le refus INCONDITIONNEL, `un_checkpoint_sans_
    // signature…` garde `Err` RÉSERVÉ à ce que la lecture ne rend pas (un NULL se LIT), et
    // `une_rupture_reelle…` interdit que la nouvelle sortie de refus AVALE l'accusation vraie.
    // ------------------------------------------------------------------------------------------------

    /// La clé qui SIGNE dans cette section (déterministe, jamais lue depuis un fichier ni l'environnement).
    fn cle_de_signature_du_temoin() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[3u8; 32])
    }

    /// Rend le `hash` du DERNIER maillon NON TEXTUEL. La ligne RESTE en base (COUNT(*) inchangé) : c'est
    /// sa lecture typée qui meurt, et elle seule.
    fn rendre_le_dernier_maillon_illisible(conn: &Connection) {
        let touchees = conn
            .execute("UPDATE ledger SET hash=X'FF' WHERE id=(SELECT MAX(id) FROM ledger)", [])
            .expect("maillon abîmé");
        assert_eq!(touchees, 1, "fixture : exactement UNE ligne abîmée");
    }

    /// (D1) TÉMOIN NÉGATIF DE TOUTE LA SECTION — UNE CHAÎNE SAINE RESTE VÉRIFIÉE ET MUETTE.
    ///
    /// Un instrument qui refuserait TOUJOURS de conclure ne vaut pas mieux qu'un instrument qui accepte
    /// toujours : il rend le même service (aucun), en coûtant la confiance en plus. Ce témoin est celui
    /// qui rougit si quelqu'un « durcit » le vérificateur en un refus inconditionnel.
    ///
    /// IL COUVRE AUSSI LE SEUL NULLABLE DE LA TABLE, et c'est là que passe la frontière du correctif :
    /// `ledger.detail` est nullable au schéma (les quatre autres colonnes lues sont `NOT NULL`). Un
    /// maillon LÉGITIME dont le `detail` est NULL — hachage calculé sur la chaîne vide, comme la
    /// production le fait — doit rester LU, pas refusé. `Err` est réservé à ce que la lecture ne rend
    /// PAS ; un NULL, elle le rend.
    #[test]
    fn une_chaine_saine_et_ses_checkpoints_restent_verifies_et_muets() {
        let conn = un_journal_vierge();
        for i in 0..3 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }
        sign_checkpoint(&conn, &cle_de_signature_du_temoin());

        let (n, sig_ok, sig_ko, rupture) = verify_ledger_conn(&conn, None).expect("une chaîne saine se VÉRIFIE");
        assert_eq!(n as i64, compter_les_maillons(&conn), "le compte rendu EST le compte en base");
        assert_eq!(n, 3, "les trois maillons sont vus");
        assert_eq!((sig_ok, sig_ko), (1, 0), "le checkpoint signé par le vrai chemin est compté OK");
        assert!(rupture.is_none(), "une chaîne saine n'accuse personne : {rupture:?}");

        // LE SEUL NULLABLE : un maillon légitime SANS `detail`, accroché à la chaîne courante.
        let (prev, ts, kind) = (
            conn.query_row("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get::<_, String>(0)).expect("tête lisible"),
            now(),
            "config.mode",
        );
        conn.execute(
            "INSERT INTO ledger(ts,kind,detail,prev_hash,hash) VALUES(?1,?2,NULL,?3,?4)",
            params![ts, kind, prev, sha256_hex(format!("{prev}|{ts}|{kind}|").as_bytes())],
        )
        .expect("maillon sans detail inséré");

        let (n, _, _, rupture) = verify_ledger_conn(&conn, None).expect("un `detail` NULL se LIT : il ne refuse rien");
        assert_eq!(n, 4, "le maillon sans `detail` est COMPTÉ, pas retiré du scan");
        assert!(rupture.is_none(), "et il n'accuse personne : {rupture:?}");
    }

    /// (D2) PREMIER ANCRAGE — UN MAILLON QU'ON NE SAIT PAS LIRE ARRÊTE LE SCAN.
    ///
    /// L'ancienne réponse est nommée dans l'assertion : `Ok((2, …, None))` sur TROIS lignes toujours
    /// présentes. Le témoin exige `Err` et vérifie que le compte en base n'a PAS bougé — sans quoi
    /// « la ligne a disparu » et « la ligne est illisible » se confondraient, ce qui est précisément
    /// l'erreur que le vérificateur commettait.
    #[test]
    fn un_maillon_illisible_fait_refuser_le_verdict_au_lieu_de_quitter_le_scan() {
        let conn = un_journal_vierge();
        for i in 0..3 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }
        // SENS 1 — la MÊME connexion, avant qu'on abîme quoi que ce soit : elle conclut.
        let (n, _, _, rupture) = verify_ledger_conn(&conn, None).expect("chaîne saine");
        assert_eq!((n, rupture), (3, None), "état de départ : trois maillons, aucune rupture");

        rendre_le_dernier_maillon_illisible(&conn);
        assert_eq!(compter_les_maillons(&conn), 3, "la ligne est TOUJOURS en base : elle est illisible, pas absente");

        // SENS 2 — le verdict DISPARAÎT. Il ne rétrécit pas à « 2 entrées, aucune rupture ».
        let message = verify_ledger_conn(&conn, None)
            .map(|v| format!("{v:?}"))
            .expect_err("une chaîne partiellement lue ne se conclut pas — l'ancienne réponse était Ok((2, 0, 0, None))");
        assert!(message.contains("maillon"), "le refus NOMME ce qui n'a pas pu être lu : {message}");
        assert!(message.contains("AUCUN verdict"), "et il dit qu'aucun verdict n'est rendu : {message}");
    }

    /// (D3) SECOND ANCRAGE, ET IL MORD SEUL — UN CHECKPOINT ILLISIBLE NE DISPARAÎT PLUS DES DEUX COMPTEURS.
    ///
    /// POURQUOI CE TÉMOIN EST DISTINCT DE (D2) ET NON SON DOUBLON : le correctif du scan des maillons ne
    /// touche pas au scan des signatures. Tant que celui-ci aplatissait, un checkpoint abîmé sortait de
    /// `sig_ok` ET de `sig_ko` — or `verify_run` ne durcit que sur `sig_ko > 0`. ABÎMER un checkpoint au
    /// lieu de le RE-SIGNER rendait donc « ledger OK … OK=0 KO=0 » et une sortie 0, PIN ESCROW POSÉ OU
    /// NON : le `flatten()` des signatures était un contournement du PIN. Les deux issues sont assertées.
    #[test]
    fn un_checkpoint_illisible_fait_refuser_le_verdict_meme_avec_un_pin_escrow() {
        let conn = un_journal_vierge();
        ledger_append(&conn, "config.mode", "maillon 0");
        let cle = cle_de_signature_du_temoin();
        let epingle = cle.verifying_key().to_bytes();
        sign_checkpoint(&conn, &cle);

        // SENS 1 — la MÊME connexion conclut, avec et sans PIN : la signature du vrai chemin est comptée OK.
        assert_eq!(verify_ledger_conn(&conn, None).expect("sain").1, 1, "sans PIN : une signature OK");
        assert_eq!(verify_ledger_conn(&conn, Some(&epingle)).expect("sain").1, 1, "PIN == pubkey in-band : OK");

        let touchees = conn
            .execute("UPDATE checkpoint SET pubkey=X'FF' WHERE id=(SELECT MAX(id) FROM checkpoint)", [])
            .expect("checkpoint abîmé");
        assert_eq!(touchees, 1, "fixture : exactement UNE ligne abîmée");
        let en_base: i64 = conn.query_row("SELECT COUNT(*) FROM checkpoint", [], |r| r.get(0)).expect("checkpoints comptables");
        assert_eq!(en_base, 1, "le checkpoint est TOUJOURS en base : il est illisible, pas absent");

        // SENS 2 — plus aucun verdict, et surtout plus de sortie 0 sur un checkpoint escamoté.
        for pin in [None, Some(&epingle)] {
            let message = verify_ledger_conn(&conn, pin)
                .map(|v| format!("{v:?}"))
                .expect_err("un checkpoint illisible ne se conclut pas — l'ancienne réponse était Ok((1, 0, 0, None))");
            assert!(message.contains("checkpoint"), "le refus NOMME ce qui n'a pas pu être lu : {message}");
            assert!(message.contains("AUCUN verdict"), "et il dit qu'aucun verdict n'est rendu : {message}");
        }
    }

    /// (D4) LA FRONTIÈRE DU REFUS, ET C'EST ELLE QUI EMPÊCHE LE REMÈDE DE DEVENIR LE DÉFAUT RETOURNÉ.
    ///
    /// Les TROIS colonnes de contenu de `checkpoint` sont NULLABLES au schéma
    /// (`ledger_hash TEXT, sig TEXT, pubkey TEXT`). Un NULL n'est PAS une ligne illisible : la lecture le
    /// rend parfaitement. Ce qu'il n'est pas, c'est une signature valide — donc `sig_ko`, un verdict, et
    /// pas un refus de conclure. Un correctif qui aurait lu ces colonnes en `String` aurait transformé
    /// une ligne LISIBLE en refus, c'est-à-dire troqué un verdict trop optimiste contre un mutisme.
    #[test]
    fn un_checkpoint_sans_signature_est_lu_et_compte_ko_jamais_un_refus() {
        let conn = un_journal_vierge();
        ledger_append(&conn, "config.mode", "maillon 0");
        conn.execute("INSERT INTO checkpoint(ts,ledger_hash,sig,pubkey) VALUES(?1,NULL,NULL,NULL)", params![now()])
            .expect("checkpoint sans contenu inséré");

        let (n, sig_ok, sig_ko, rupture) = verify_ledger_conn(&conn, None).expect("un NULL se LIT : aucun refus");
        assert_eq!(n, 1, "la chaîne reste lue entièrement");
        assert_eq!((sig_ok, sig_ko), (0, 1), "un checkpoint sans signature est COMPTÉ KO, pas escamoté ni refusé");
        assert!(rupture.is_none(), "et il ne rompt pas la chaîne des maillons : {rupture:?}");
    }

    /// (D5) LA VRAIE ACCUSATION SURVIT AU NOUVEAU REFUS.
    ///
    /// Un correctif qui ferme une fausse accusation peut faire TAIRE une vraie : il ne casse rien, ne
    /// fait rougir personne, et RÉTRÉCIT le canal de détection. Le signal d'alerte est exactement celui
    /// que ce témoin surveille — un verdict qui passerait d'« accuse » à « refuse de conclure ». La
    /// falsification est ici TEXTUELLE (un `detail` réécrit) : la lecture la rend sans peine, donc la
    /// sortie attendue reste `Ok((_, Some(id)))`, la rupture NOMMÉE.
    #[test]
    fn une_rupture_reelle_reste_une_rupture_nommee_et_non_un_refus() {
        let conn = un_journal_vierge();
        for i in 0..3 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }
        let vise: i64 = conn
            .query_row("SELECT id FROM ledger ORDER BY id LIMIT 1 OFFSET 1", [], |r| r.get(0))
            .expect("deuxième maillon");
        conn.execute("UPDATE ledger SET detail='reecrit apres coup' WHERE id=?1", params![vise])
            .expect("detail falsifié");

        let (intacts, _, _, rupture) = verify_ledger_conn(&conn, None).expect("une falsification LISIBLE se conclut");
        assert_eq!(rupture, Some(vise), "la rupture est NOMMÉE, pas convertie en refus de conclure");
        assert_eq!(intacts, 3, "et le compte rendu reste celui des lignes LUES, toutes lues");
    }

