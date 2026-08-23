    // ================================================================================================
    // P11.10-a — UN HÔTE MUET NE DIT PAS S'IL EST NORMAL, ET LE COMPTE MÉLANGE TROIS CHOSES.
    //
    // CE QUI A ÉTÉ MESURÉ AVANT DE CORRIGER (2026-08-23, par lecture du code servi) :
    //   (a) la charge utile de `/api/fleet` (`fleet_scan_all`) ne portait AUCUN champ distinguant une
    //       machine DÉCOMMISSIONNÉE, une machine de TEST et un AGENT TOMBÉ : les trois rendaient le même
    //       jeton `silent`, dérivé du seul âge du dernier signal ;
    //   (b) la sonde de parc (`sonde_de_flotte.rs`) alertait sur les trois, et son propre en-tête
    //       DÉCLARAIT le résidu en toutes lettres — « une machine DÉCOMMISSIONNÉE reste comptée muette
    //       indéfiniment … celui-ci NE se résorbe PAS tout seul ». Le défaut était donc connu, écrit, et
    //       sans issue : rien dans la console ne permettait de le combler ;
    //   (c) l'en-tête de la vue additionnait des parts calculées sur les lignes AFFICHÉES à côté d'un
    //       total calculé sur le parc ENTIER — la même famille de défaut que `P11.3-d` a mesurée sur les
    //       alertes de sources.
    //
    // CE QUI EST TENU ICI, ET DANS QUEL ORDRE :
    //   1. `hotes_declares_le_verdict_est_une_fonction_pure` — « quelqu'un a dit non » n'est PAS
    //      « personne n'a rien dit », et le geste l'emporte sur l'enrôlement (l'inverse des sources, et
    //      c'est mesuré : sans cela un retrait serait inopérant sur une machine enrôlée).
    //   2. `hotes_declares_le_silence_declare_attendu_sort_de_lalerte` — LA MUTATION : la valeur qui
    //      change est `FlotteMuette.muets`, et `attendus` ne bouge PAS.
    //   3. `hotes_declares_une_machine_retiree_sort_du_denominateur` — l'autre mutation : cette fois
    //      `attendus` bouge AUSSI.
    //   4. `hotes_declares_lalerte_dit_ce_quelle_ne_couvre_pas` — et le témoin NÉGATIF : sans machine
    //      déclarée, la phrase n'est pas rendue (sinon un texte qui la dirait toujours passerait).
    //   5. `hotes_declares_les_parts_sadditionnent_et_comptent_la_meme_population` — la leçon de
    //      `P11.3-d` : les parts publiées par le démon font le tout, et `muet_inattendu` est EXACTEMENT
    //      la population de la sonde.
    //   6. `hotes_declares_le_geste_est_editor_persistant_audite_et_exige_son_motif` — le chemin est
    //      FERMÉ (400) quand on éteint une alerte sans dire pourquoi, pas drapeauté.
    //   7. `hotes_declares_une_table_illisible_alerte_plus_jamais_moins` — le sens d'échec, prouvé en
    //      SUPPRIMANT la table.
    // ================================================================================================

    /// Un parc de `n` machines dont la première parle et les autres se taisent depuis `retard` secondes.
    /// Passe par le VRAI chemin (`hm_parc_metrique` : lignes `metric` -> plancher -> tick de rollup).
    fn hd_parc(conn: &Connection, now_ts: i64, n: usize, retard: i64) -> Vec<String> {
        let noms: Vec<String> = (0..n).map(|i| format!("srv{i:03}")).collect();
        let vivants: Vec<(&str, i64)> = noms
            .iter()
            .enumerate()
            .map(|(i, h)| (h.as_str(), if i == 0 { now_ts - 60 } else { now_ts - retard }))
            .collect();
        hm_parc_metrique(conn, &vivants);
        noms
    }

    /// Écrit une déclaration DIRECTEMENT en base (les tests de sonde n'ont pas d'`AppState`) — la même
    /// forme de ligne que celle qu'écrit `host_settings_put`, dont le test (6) prouve le chemin réel.
    fn hd_declarer(conn: &Connection, host: &str, attente: &str, par: &str, ts: i64) {
        conn.execute(
            "INSERT INTO host_settings(scope,host,attente,attente_motif,attente_par,attente_le,updated,updated_by) \
             VALUES('global',?1,?2,'motif de test',?3,?4,?4,?3)",
            params![host, attente, par, ts],
        )
        .unwrap();
    }

    // ---------------------------------------------------------------------------------------------
    // (1) LE VERDICT, EN FONCTION PURE
    // ---------------------------------------------------------------------------------------------

    /// LA DÉRIVATION SANS BASE. Quatre états, et non trois : « personne n'a rien dit » est DISTINCT de
    /// « quelqu'un a déclaré qu'un signal est attendu », même si les deux alertent — la console doit
    /// pouvoir dire lequel des deux elle a sous les yeux au lieu d'inventer une déclaration.
    ///
    /// ET LE GESTE L'EMPORTE SUR LA CONSTRUCTION, ce qui est l'INVERSE de l'ordre des sources. La
    /// mutation le montre : une machine ENRÔLÉE puis retirée doit être retirée. Si la dérivation
    /// gagnait, le retrait serait inopérant sur exactement les machines qui en ont besoin.
    #[test]
    fn hotes_declares_le_verdict_est_une_fonction_pure() {
        let enrolee = Some(RaisonDAttente::Enrolement { nom: "agent-01".into(), cree: Some(1000) });
        let marque = |a: AttenteDeclaree| MarquageHote {
            attente: Some(a),
            motif: Some("banc de test".into()),
            par: Some("eve".into()),
            le: Some(2000),
        };

        // personne n'a rien dit -> alerte quand même (défaut sûr d'un dead-man's-switch), mais l'état le DIT.
        let v = verdict_dhote(None, None);
        assert_eq!(v.jeton(), "non_declare");
        assert!(v.alerte_si_muet() && v.dans_la_flotte());
        assert_eq!(v.provenance(), None, "aucune déclaration -> aucun déclarant à nommer");
        assert_eq!(v.libelle(), None, "aucune déclaration -> aucune phrase inventée");

        // dérivé : un jeton d'agent lié à la machine.
        let v = verdict_dhote(enrolee.clone(), None);
        assert_eq!((v.jeton(), v.provenance()), ("signal_attendu", Some("un enrôlement")));
        assert!(v.alerte_si_muet());
        assert!(v.libelle().unwrap().contains("agent-01"), "le libellé nomme le jeton : {:?}", v.libelle());

        // l'exploitant a dit NON (le silence est normal) : distinct de « personne n'a rien dit ».
        let v = verdict_dhote(None, Some(&marque(AttenteDeclaree::SilenceAttendu)));
        assert_eq!((v.jeton(), v.provenance()), ("silence_attendu", Some("l'exploitant")));
        assert!(!v.alerte_si_muet(), "le silence déclaré attendu n'alerte plus");
        assert!(v.dans_la_flotte(), "…mais la machine reste dans le parc et dans la liste");
        let l = v.libelle().unwrap();
        assert!(l.contains("eve") && l.contains("2000") && l.contains("banc de test"), "qui, quand, pourquoi : {l}");

        // LA MUTATION D'ORDRE : la même machine, ENRÔLÉE, et déclarée retirée -> retirée.
        let v = verdict_dhote(enrolee.clone(), Some(&marque(AttenteDeclaree::Retire)));
        assert_eq!(v.jeton(), "retire", "le geste l'emporte sur l'enrôlement, sinon le retrait est inopérant");
        assert!(!v.alerte_si_muet() && !v.dans_la_flotte());

        // réarmement explicite : l'exploitant redit qu'un signal est attendu, et c'est LUI qu'on crédite.
        let v = verdict_dhote(enrolee, Some(&marque(AttenteDeclaree::SignalAttendu)));
        assert_eq!((v.jeton(), v.provenance()), ("signal_attendu", Some("l'exploitant")));
        assert!(v.alerte_si_muet());

        // l'enum de colonne est FERMÉ : une valeur écrite par une version future ne devient pas un état.
        assert_eq!(AttenteDeclaree::depuis_la_colonne(Some("silence_attendu")), Some(AttenteDeclaree::SilenceAttendu));
        assert_eq!(AttenteDeclaree::depuis_la_colonne(Some("peut-etre")), None);
        assert_eq!(AttenteDeclaree::depuis_la_colonne(None), None);
        // …et les trois jetons déclarables sont ceux que la lecture reconnaît (dérivé, jamais recopié).
        for j in ATTENTES_DECLARABLES {
            assert!(AttenteDeclaree::depuis_la_colonne(Some(j)).is_some(), "`{j}` est déclarable mais illisible");
        }
    }

    // ---------------------------------------------------------------------------------------------
    // (2)(3) LES DEUX MUTATIONS — QUELLE VALEUR CHANGE, ET LAQUELLE NE CHANGE PAS
    // ---------------------------------------------------------------------------------------------

    /// LA MUTATION. Sur un parc de 20 machines dont 19 muettes, déclarer le silence d'UNE machine
    /// attendu fait passer `FlotteMuette.muets` de 19 à 18 et `muets_declares_attendus` de 0 à 1 —
    /// pendant que `attendus` reste à 20 (la machine est toujours du parc). C'est exactement la
    /// distinction que la vue ne savait pas faire.
    #[test]
    fn hotes_declares_le_silence_declare_attendu_sort_de_lalerte() {
        let conn = test_db();
        let now_ts = now();
        let noms = hd_parc(&conn, now_ts, 20, 7200);

        let avant = flotte_muette(&conn, now_ts).expect("inventaire lisible");
        assert_eq!((avant.muets, avant.attendus, avant.muets_declares_attendus), (19, 20, 0));

        hd_declarer(&conn, &noms[5], "silence_attendu", "eve", now_ts);
        let apres = flotte_muette(&conn, now_ts).expect("inventaire lisible");
        assert_eq!(apres.muets, 18, "LA VALEUR QUI CHANGE : la machine déclarée n'est plus comptée muette");
        assert_eq!(apres.muets_declares_attendus, 1, "…elle est comptée À PART, jamais escamotée");
        assert_eq!(apres.attendus, 20, "LA VALEUR QUI NE CHANGE PAS : elle est toujours du parc");
        assert_ne!(avant.empreinte, apres.empreinte, "l'ensemble muet a changé -> épisode NEUF");

        // ET LE VERDICT VIENT DE LA TABLE, pas d'un état en mémoire : une dérivation FRAÎCHE le relit.
        let m = marquages_dhotes(&conn);
        assert_eq!(m.get(&noms[5]).and_then(|x| x.attente), Some(AttenteDeclaree::SilenceAttendu));
        assert_eq!(m.get(&noms[5]).and_then(|x| x.par.clone()).as_deref(), Some("eve"));
        assert!(m.get(&noms[6]).is_none(), "une machine non déclarée n'a aucune ligne");

        // RÉVERSIBLE : la déclaration retirée, la machine réintègre la population de l'alerte.
        conn.execute("DELETE FROM host_settings WHERE host=?1", params![&noms[5]]).unwrap();
        let rearme = flotte_muette(&conn, now_ts).expect("inventaire lisible");
        assert_eq!((rearme.muets, rearme.muets_declares_attendus), (19, 0), "le geste se défait");
    }

    /// L'AUTRE MUTATION : une machine RETIRÉE sort du dénominateur EN PLUS de sortir de l'alerte —
    /// « 19 sur 20 » ne veut plus rien dire si le 20 compte des machines dont quelqu'un a dit qu'elles
    /// n'en font plus partie. C'est ce qui distingue « retiré » de « silence attendu ».
    #[test]
    fn hotes_declares_une_machine_retiree_sort_du_denominateur() {
        let conn = test_db();
        let now_ts = now();
        let noms = hd_parc(&conn, now_ts, 20, 7200);

        hd_declarer(&conn, &noms[7], "retire", "root", now_ts);
        let f = flotte_muette(&conn, now_ts).expect("inventaire lisible");
        assert_eq!(f.attendus, 19, "LA VALEUR QUI CHANGE ICI, et qui ne bougeait pas sur un silence attendu");
        assert_eq!(f.muets, 18, "…et elle sort aussi de la population qui alerte");
        assert_eq!(f.muets_declares_attendus, 0, "une machine retirée n'est pas « muette déclarée » : elle n'est plus là");

        // Une machine retirée alors qu'elle PARLE ENCORE sort quand même du parc : c'est une décision,
        // pas une observation. Elle reste néanmoins listée par l'inventaire (test 5).
        hd_declarer(&conn, &noms[0], "retire", "root", now_ts);
        let f = flotte_muette(&conn, now_ts).expect("inventaire lisible");
        assert_eq!((f.attendus, f.muets), (18, 18), "la machine vivante retirée quitte aussi le dénominateur");
    }

    // ---------------------------------------------------------------------------------------------
    // (4) CE QUE L'ALERTE DIT D'ELLE-MÊME, ET LE TÉMOIN NÉGATIF
    // ---------------------------------------------------------------------------------------------

    /// Restreindre la population d'une alerte sans le DIRE échange un faux positif contre un angle mort.
    /// Le texte porte donc le compte des machines qu'il ne couvre pas — et ne le porte PAS quand il n'y
    /// en a aucune (sans ce second témoin, une phrase toujours présente passerait pour une réussite).
    #[test]
    fn hotes_declares_lalerte_dit_ce_quelle_ne_couvre_pas() {
        let conn = test_db();
        let now_ts = now();
        let noms = hd_parc(&conn, now_ts, 6, 7200);

        // TÉMOIN NÉGATIF d'abord : aucune déclaration -> la phrase n'existe pas.
        let f = flotte_muette(&conn, now_ts).expect("inventaire lisible");
        let nu = detail_flotte_muette(&f, now_ts);
        assert!(nu.contains("5 hôte(s) sur 6"), "le compte et son dénominateur : {nu}");
        assert!(!nu.contains("ne sont PAS comptées ici"), "rien de déclaré -> aucune phrase de non-couverture : {nu}");

        hd_declarer(&conn, &noms[2], "silence_attendu", "eve", now_ts);
        hd_declarer(&conn, &noms[3], "silence_attendu", "eve", now_ts);
        let f = flotte_muette(&conn, now_ts).expect("inventaire lisible");
        let dit = detail_flotte_muette(&f, now_ts);
        assert!(dit.contains("3 hôte(s) sur 6"), "la population a rétréci : {dit}");
        assert!(
            dit.contains("2 machine(s) muette(s) ne sont PAS comptées ici"),
            "l'alerte doit DIRE ce qu'elle ne couvre pas : {dit}"
        );
        assert!(dit.contains("silence est attendu"), "…et pourquoi : {dit}");

        // Le chemin réel : l'alerte levée par le planificateur porte le même texte, et sa population a
        // bien rétréci (une seule alerte de la famille, dédupliquée par l'empreinte de l'ensemble).
        let db = Arc::new(Mutex::new(conn));
        check_heartbeats(&db);
        let conn = db.lock();
        let detail: String = conn
            .query_row(
                "SELECT detail FROM alert WHERE rule='heartbeat.flotte-hotes-muets' ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .expect("l'alerte de parc est levée");
        assert!(detail.contains("ne sont PAS comptées ici"), "le texte SERVI porte l'aveu : {detail}");
        assert!(!detail.contains(&noms[2]), "une machine déclarée n'est plus NOMMÉE parmi les fautives : {detail}");
    }

    // ---------------------------------------------------------------------------------------------
    // (5) LES PARTS S'ADDITIONNENT, ET LES DEUX SURFACES COMPTENT LA MÊME POPULATION
    // ---------------------------------------------------------------------------------------------

    /// LA LEÇON DE `P11.3-d`, TRANSPOSÉE. Le démon publie la répartition, calculée sur la liste COMPLÈTE,
    /// et elle FAIT LE TOUT dans les deux sens : `frais + en_retard + muet_attendu + muet_inattendu`
    /// vaut la flotte, et `flotte + retires` vaut l'inventaire. Le lien qui interdit les deux comptes de
    /// diverger est vérifié ici : `muet_inattendu` est EXACTEMENT le `muets` de la sonde de parc.
    #[test]
    fn hotes_declares_les_parts_sadditionnent_et_comptent_la_meme_population() {
        let conn = test_db();
        let now_ts = now();
        // un parc composite : 2 fraîches, 1 en retard, 5 muettes.
        let mut vivants: Vec<(String, i64)> = Vec::new();
        for i in 0..2 {
            vivants.push((format!("frais{i}"), now_ts - 60));
        }
        vivants.push(("retard0".to_string(), now_ts - 1800));
        for i in 0..5 {
            vivants.push((format!("muet{i}"), now_ts - 7200));
        }
        let refs: Vec<(&str, i64)> = vivants.iter().map(|(h, t)| (h.as_str(), *t)).collect();
        hm_parc_metrique(&conn, &refs);
        hd_declarer(&conn, "muet0", "silence_attendu", "eve", now_ts);
        hd_declarer(&conn, "muet1", "retire", "root", now_ts);
        // une machine RETIRÉE qui parle encore : elle doit rester listée et sortir du dénominateur.
        hd_declarer(&conn, "frais0", "retire", "root", now_ts);

        let (hosts, _) = fleet_scan_all(&conn, now_ts);
        assert_eq!(hosts.len(), 8, "toutes les machines restent LISTÉES, retirées comprises");
        let r = repartition_de_flotte(&hosts);
        let g = |k: &str| r[k].as_i64().unwrap();
        assert_eq!(
            (g("frais"), g("en_retard"), g("muet_attendu"), g("muet_inattendu"), g("retires")),
            (1, 1, 1, 3, 2)
        );
        assert_eq!(
            g("frais") + g("en_retard") + g("muet_attendu") + g("muet_inattendu"),
            g("flotte"),
            "LES PARTS FONT LE TOUT : c'est ce qui manquait au compte affiché"
        );
        assert_eq!(g("flotte") + g("retires"), g("inventories"), "…et l'inventaire est la flotte plus les retirées");

        // LE LIEN : la part qui alerte est la population de la sonde, pas un compte parallèle.
        let f = flotte_muette(&conn, now_ts).expect("inventaire lisible");
        assert_eq!(g("muet_inattendu") as usize, f.muets, "les deux surfaces comptent la MÊME population");
        assert_eq!(g("muet_attendu") as usize, f.muets_declares_attendus);
        assert_eq!(g("flotte") as usize, f.attendus, "et le même dénominateur");

        // La charge utile de la vue porte la répartition, et elle NE BOUGE PAS avec la pagination — sans
        // quoi on retomberait exactement dans le défaut mesuré (des parts de page sous un total de parc).
        let page1 = fleet_response(&hosts, true, "host", false, 2, 0, now_ts);
        let page2 = fleet_response(&hosts, true, "host", false, 2, 2, now_ts);
        assert_eq!(page1["hosts"].as_array().unwrap().len(), 2);
        assert_eq!(page1["repartition"], page2["repartition"], "la répartition est celle du parc, pas de la page");
        assert_eq!(page1["repartition"], r);

        // Chaque ligne porte le jeton STABLE sur lequel la console pivote (elle ne le réécrit pas).
        let jeton = |h: &str| {
            hosts.iter().find(|x| x["host"] == h).unwrap()["attente"].as_str().unwrap().to_string()
        };
        assert_eq!(jeton("muet0"), "silence_attendu");
        assert_eq!(jeton("muet1"), "retire");
        assert_eq!(jeton("muet2"), "non_declare");
    }

    // ---------------------------------------------------------------------------------------------
    // (6) LE GESTE : editor+, persistant, audité, et son motif EXIGÉ
    // ---------------------------------------------------------------------------------------------

    fn hd_au(role: &str, nom: &str) -> AuthUser {
        AuthUser { name: nom.into(), role: role.into(), tenant: "default".into(), is_superadmin: false, method: "cookie".into(), csrf: String::new(), env: None }
    }
    async fn hd_put(st: &AppState, au: AuthUser, body: Value) -> StatusCode {
        host_settings_put(State(st.clone()), Extension(au), Json(body)).await.into_response().status()
    }
    fn hd_ligne(st: &AppState, host: &str) -> Option<(String, String, String)> {
        let c = st.db.lock();
        c.query_row(
            "SELECT COALESCE(attente,''), COALESCE(attente_par,''), COALESCE(attente_motif,'') FROM host_settings WHERE scope='global' AND host=?1",
            params![host],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
        )
        .ok()
    }

    /// LE CHEMIN RÉEL DU HANDLER. Mutation editor+ (le viewer est refusé par le path-guard ET par le
    /// handler), déclaration persistée avec SON déclarant et SA date, réversible, auditée — à la
    /// sévérité 3 quand elle ÉTEINT le dead-man's-switch sur une machine, à 2 quand elle le REND.
    /// Et le motif est EXIGÉ sur les deux gestes qui éteignent : le chemin est FERMÉ, pas drapeauté.
    #[tokio::test]
    async fn hotes_declares_le_geste_est_editor_persistant_audite_et_exige_son_motif() {
        assert!(rbac_gate("editor", "/api/hosts/settings", true).is_ok(), "un éditeur déclare une machine de son parc");
        assert!(rbac_gate("admin", "/api/hosts/settings", true).is_ok());
        assert!(rbac_gate("viewer", "/api/hosts/settings", true).is_err(), "un viewer ne déclare rien");
        assert!(rbac_gate("viewer", "/api/hosts/settings", false).is_ok(), "la liste brute se lit (rien de secret)");

        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let sev3 = || -> i64 {
            st.db.lock().query_row("SELECT COUNT(*) FROM event WHERE source='plume-config' AND severity=3", [], |r| r.get(0)).unwrap()
        };

        // le viewer est refusé même si le path-guard était contourné, et RIEN n'est persisté.
        assert_eq!(hd_put(&st, hd_au("viewer", "vic"), json!({"host":"srv-9","action":"set_attente","value":"silence_attendu","motif":"x"})).await, StatusCode::FORBIDDEN);
        assert!(hd_ligne(&st, "srv-9").is_none());

        // ÉTEINDRE SANS DIRE POURQUOI : refusé, et rien n'est écrit.
        assert_eq!(hd_put(&st, hd_au("editor", "eve"), json!({"host":"srv-9","action":"set_attente","value":"silence_attendu"})).await, StatusCode::BAD_REQUEST);
        assert_eq!(hd_put(&st, hd_au("editor", "eve"), json!({"host":"srv-9","action":"set_attente","value":"retire","motif":"   "})).await, StatusCode::BAD_REQUEST);
        assert!(hd_ligne(&st, "srv-9").is_none(), "un refus n'écrit rien");

        // avec son motif : persisté, crédité, et audité FORT (un signal est étouffé).
        let avant = sev3();
        assert_eq!(hd_put(&st, hd_au("editor", "eve"), json!({"host":"srv-9","action":"set_attente","value":"silence_attendu","motif":"banc de test"})).await, StatusCode::OK);
        assert_eq!(hd_ligne(&st, "srv-9"), Some(("silence_attendu".into(), "eve".into(), "banc de test".into())));
        assert_eq!(sev3(), avant + 1, "éteindre l'alerte de parc sur une machine est audité en sévérité 3");

        // RÉARMER : même surface, sévérité 2 — rendre une couverture n'est pas l'étouffer.
        let avant = sev3();
        assert_eq!(hd_put(&st, hd_au("admin", "root"), json!({"host":"srv-9","action":"set_attente","value":"signal_attendu"})).await, StatusCode::OK);
        assert_eq!(hd_ligne(&st, "srv-9"), Some(("signal_attendu".into(), "root".into(), String::new())));
        assert_eq!(sev3(), avant, "réarmer n'est pas un étouffement");

        // `clear` : la machine reprend le défaut (personne n'a rien dit -> son silence alerte).
        assert_eq!(hd_put(&st, hd_au("editor", "eve"), json!({"host":"srv-9","action":"clear"})).await, StatusCode::OK);
        assert!(hd_ligne(&st, "srv-9").is_none());

        // enums FERMÉS des deux côtés, et bornes du champ `host`.
        assert_eq!(hd_put(&st, hd_au("editor", "eve"), json!({"host":"srv-9","action":"drop_table"})).await, StatusCode::BAD_REQUEST);
        assert_eq!(hd_put(&st, hd_au("editor", "eve"), json!({"host":"srv-9","action":"set_attente","value":"peut-etre","motif":"x"})).await, StatusCode::BAD_REQUEST);
        assert_eq!(hd_put(&st, hd_au("editor", "eve"), json!({"host":"","action":"clear"})).await, StatusCode::BAD_REQUEST);
        assert_eq!(hd_put(&st, hd_au("editor", "eve"), json!({"host":"h".repeat(300),"action":"clear"})).await, StatusCode::BAD_REQUEST);

        // la liste brute est lisible par un viewer et rend la provenance PROPRE.
        assert_eq!(hd_put(&st, hd_au("editor", "eve"), json!({"host":"srv-1","action":"set_attente","value":"retire","motif":"décommissionnée"})).await, StatusCode::OK);
        let r = host_settings_get(State(st.clone()), Extension(hd_au("viewer", "vic"))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let corps = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        let v: Value = serde_json::from_slice(&corps).unwrap();
        let l = &v["settings"][0];
        assert_eq!((l["host"].as_str(), l["attente"].as_str(), l["attente_par"].as_str()), (Some("srv-1"), Some("retire"), Some("eve")));
        assert_eq!(l["attente_motif"].as_str(), Some("décommissionnée"));
    }

    // ---------------------------------------------------------------------------------------------
    // (7) LE SENS D'ÉCHEC
    // ---------------------------------------------------------------------------------------------

    /// NE PAS SAVOIR CE QUI EST DÉCLARÉ DOIT PRODUIRE PLUS D'ALERTES, JAMAIS MOINS. C'est l'inverse du
    /// sens d'échec de la lecture d'INVENTAIRE (qui, elle, rend `None` et n'autorise plus rien) : là il
    /// s'agit de ne pas affirmer un parc sain qu'on n'a pas observé, ici de ne pas éteindre une alerte
    /// faute d'avoir pu lire les exemptions. La table SUPPRIMÉE, la sonde alerte de nouveau sur tout.
    #[test]
    fn hotes_declares_une_table_illisible_alerte_plus_jamais_moins() {
        let conn = test_db();
        let now_ts = now();
        let noms = hd_parc(&conn, now_ts, 8, 7200);
        hd_declarer(&conn, &noms[1], "silence_attendu", "eve", now_ts);
        hd_declarer(&conn, &noms[2], "retire", "root", now_ts);
        let f = flotte_muette(&conn, now_ts).expect("inventaire lisible");
        assert_eq!((f.muets, f.attendus), (5, 7), "témoin positif : les déclarations sont lues");

        conn.execute_batch("DROP TABLE host_settings").unwrap();
        assert!(marquages_dhotes(&conn).is_empty(), "table absente -> carte VIDE, jamais une erreur qui masquerait tout");
        let f = flotte_muette(&conn, now_ts).expect("l'inventaire, lui, reste lisible");
        assert_eq!(
            (f.muets, f.attendus, f.muets_declares_attendus),
            (7, 8, 0),
            "sans les déclarations, la sonde retombe sur son comportement d'avant : elle alerte sur TOUT"
        );
        // et l'inventaire ne s'effondre pas non plus : chaque machine retombe sur « personne n'a rien dit ».
        let (hosts, _) = fleet_scan_all(&conn, now_ts);
        assert_eq!(hosts.len(), 8);
        assert!(hosts.iter().all(|h| h["attente"] == "non_declare" && h["alerte_si_muet"] == true));
    }
