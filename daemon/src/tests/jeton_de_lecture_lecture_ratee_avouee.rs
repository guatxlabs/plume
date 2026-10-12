// =====================================================================================
// `P10.20-b` (hors handlers/ : jetons de LECTURE datasource `#52` et client-read `#39`) — UNE LECTURE RATÉE DE LA
// TABLE DES JETONS N'EST PAS UN JETON INCONNU, ET ELLE NE RETOMBE PAS SUR LA DÉMONSTRATION PUBLIQUE.
//
// LE DÉFAUT, MESURÉ SUR 824949d. `datasource_token_lookup` et `client_token_lookup` lisaient le jeton par
// `query_row(..).ok()?` : une table `token` illisible rendait `None`, comme « aucune ligne ». Le garde
// (`resolve_identity_ou_refus`, branches datasource et client) poursuivait sans identité : 401 « auth requise » — une
// panne de lecture se lisait « jeton révoqué » pour la Grafana externe ou le client MSSP —, et, démonstration publique
// active, la requête était SERVIE sous l'identité anonyme partagée, en lecture. Le seam agent/HEC distinguait déjà
// les trois issues (`token_lookup_lu`, `jeton_d_agent_lecture_ratee_avouee.rs`).
//
// LES VOIES D'ÉCHEC : la table `token` RENOMMÉE au moment de l'appel (« no such table »), et une colonne de type
// inattendu (BLOB) sur la ligne du jeton — `role` pour le jeton datasource, `name` pour le jeton client : la table
// existe, la ligne est trouvée, sa lecture échoue. Jamais un trigger sur SELECT.
//
// ATTENDU, ET TENU ICI : trois issues (`Trouve` / `Absent` / `NonLu`) ; absence établie (jeton inconnu, mauvais
// `kind`, jeton vide, mode 1) = sortie d'avant ; lecture ratée = 503 nommé (`CAUSE_JETON_DE_LECTURE_NON_LU`,
// distincte de la cause du jeton d'agent, rien du moteur dans le corps), aucun `last_used` écrit, aucune identité,
// aucun repli (démonstration comprise), le gestionnaire jamais atteint. Les projections `Option` d'avant restent
// (témoins de `connectors.rs` et `cases.rs`, inchangés).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une base réellement corrompue ou verrouillée (même chemin refusé : toute erreur
// autre que « aucune ligne ») ; les clés de livraison push (`push_token_connector`, `.ok()?` gardé, callers
// `ingest/firehose.rs` et `ingest/pubsub.rs`) ; le mode 1, où aucun jeton de lecture n'existe par construction (la
// lecture n'y est pas faite, l'absence y est établie sans base) ; `engagement_cred_within_window` ; l'`UPDATE
// last_used` qui suit un jeton trouvé reste avalé (comme pour le jeton d'agent).
//
// LES MUTATIONS QUI LES FONT ROUGIR (jouées par la variable de mutation du banc, puis retirées du source) :
//  * « jdl_datasource_vaut_absent » (la lecture datasource ratée rend `Absent`, la forme `.ok()?` d'avant) : (a), (b), (c) ;
//  * « jdl_client_vaut_absent » (même chose pour le jeton client) : (a), (b), (c) ;
//  * « jdl_nonlu_poursuit » (les deux appelants d'auth.rs traitent `NonLu` comme `Absent`) : (b), (c) — (a) reste vert ;
//  * « jdl_tete » (les deux lectures à la forme d'avant : le chemin servi de 824949d) : (a), (b), (c) — (b) y lit le
//    401 « auth requise » d'avant là où le 503 est attendu.
// =====================================================================================
mod jeton_de_lecture_lecture_ratee_avouee {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const JDL_SECRET_DS: &str = "jdl-secret-de-la-datasource";
    const JDL_SECRET_CLIENT: &str = "jdl-secret-du-client";
    const JDL_SECRET_AGENT: &str = "jdl-secret-de-l-agent";
    const JDL_DS: &str = "/api/v1/labels";
    const JDL_CLIENT: &str = "/api/client/cases";
    const JDL_RENOMME: &str = "ALTER TABLE token RENAME TO jdl_token_mis_a_l_ecart;";
    const JDL_REMIS: &str = "ALTER TABLE jdl_token_mis_a_l_ecart RENAME TO token;";

    fn jdl_executer(conn: &rusqlite::Connection, sql: &str) {
        conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    /// Mode 0 : base unique en mémoire, un jeton datasource (`editor`), un jeton client et un jeton d'agent.
    fn jdl_etat_mode_zero(demonstration: bool) -> AppState {
        let mut st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        st.pass_hash = Arc::new("fixture : hors du mode d'installation".to_string());
        st.public_demo = demonstration;
        {
            let conn = st.db.lock();
            for (nom, secret, kind, role) in [
                ("ds-jdl", JDL_SECRET_DS, Some("datasource"), Some("editor")),
                ("client-jdl", JDL_SECRET_CLIENT, Some("client"), None),
                ("agent-jdl", JDL_SECRET_AGENT, None, None),
            ] {
                conn.execute(
                    "INSERT INTO token(name,token_hash,created,kind,role) VALUES(?1,?2,?3,?4,?5)",
                    params![nom, sha256_hex(secret.as_bytes()), now(), kind, role],
                )
                .expect("fixture : jeton");
            }
        }
        st
    }

    fn jdl_last_used(st: &AppState, nom: &str) -> Option<i64> {
        st.db
            .lock()
            .query_row("SELECT last_used FROM token WHERE name=?1", params![nom], |r| r.get(0))
            .expect("fixture : last_used se lit")
    }

    fn jdl_issue(lu: crate::state::LectureDuJetonDeLecture) -> String {
        match lu {
            crate::state::LectureDuJetonDeLecture::Trouve(d) => format!("Trouve({},{},{})", d.name, d.tenant, d.role),
            crate::state::LectureDuJetonDeLecture::Absent => "Absent".to_string(),
            crate::state::LectureDuJetonDeLecture::NonLu(_) => "NonLu".to_string(),
        }
    }

    fn jdl_ds(st: &AppState, tok: &str) -> String {
        jdl_issue(crate::state::datasource_token_lookup_lu(st, tok))
    }

    fn jdl_cl(st: &AppState, tok: &str) -> String {
        jdl_issue(crate::state::client_token_lookup_lu(st, tok))
    }

    fn jdl_requete(chemin: &str, autorisation: &str) -> Request<axum::body::Body> {
        Request::builder()
            .method("GET")
            .uri(chemin)
            .header("authorization", autorisation)
            .body(axum::body::Body::empty())
            .expect("fixture : requête")
    }

    /// (a) MODE 0, LES DEUX LECTURES TRI-ÉTAT : trouvé (last_used écrit), absent établi (inconnu, vide, mauvais kind),
    /// puis NON LU par colonne de type inattendu (aucun last_used) et par table renommée — jeton connu comme inconnu.
    /// Table remise : comportement d'avant ; les projections `Option` ne servent aucune identité sur lecture ratée.
    #[test]
    fn jdl_mode_zero_lecture_ratee_n_est_pas_un_jeton_absent() {
        let st = jdl_etat_mode_zero(false);
        assert_eq!(jdl_ds(&st, JDL_SECRET_DS), "Trouve(ds-jdl,default,editor)");
        assert_eq!(jdl_cl(&st, JDL_SECRET_CLIENT), "Trouve(client-jdl,default,client)");
        assert!(jdl_last_used(&st, "ds-jdl").is_some() && jdl_last_used(&st, "client-jdl").is_some(), "trouvé : last_used écrit");
        for (tok, quoi) in [("inconnu", "inconnu"), ("", "vide"), (JDL_SECRET_AGENT, "jeton d'agent")] {
            assert_eq!(jdl_ds(&st, tok), "Absent", "datasource, jeton {quoi} : absence établie");
            assert_eq!(jdl_cl(&st, tok), "Absent", "client, jeton {quoi} : absence établie");
        }
        assert_eq!(jdl_ds(&st, JDL_SECRET_CLIENT), "Absent", "jeton client sur la lecture datasource : mauvais kind");
        assert_eq!(jdl_cl(&st, JDL_SECRET_DS), "Absent", "jeton datasource sur la lecture client : mauvais kind");

        // colonne de type inattendu : la ligne est là, sa lecture échoue.
        jdl_executer(
            &st.db.lock(),
            "UPDATE token SET role=X'00FF', last_used=NULL WHERE name='ds-jdl'; \
             UPDATE token SET name=X'00FF', last_used=NULL WHERE name='client-jdl';",
        );
        assert_eq!(jdl_ds(&st, JDL_SECRET_DS), "NonLu", "role illisible : lecture NON faite, jamais « jeton absent »");
        assert_eq!(jdl_cl(&st, JDL_SECRET_CLIENT), "NonLu", "name illisible : lecture NON faite, jamais « jeton absent »");
        assert!(datasource_token_lookup(&st, JDL_SECRET_DS).is_none(), "projection : aucune identité");
        assert!(client_token_lookup(&st, JDL_SECRET_CLIENT).is_none(), "projection : aucune identité");
        let lus: Vec<Option<i64>> = {
            let conn = st.db.lock();
            let mut q = conn.prepare("SELECT last_used FROM token WHERE kind IN ('datasource','client')").expect("fixture");
            q.query_map([], |r| r.get(0)).expect("fixture").collect::<Result<_, _>>().expect("fixture")
        };
        assert_eq!(lus, vec![None, None], "lecture ratée : aucun last_used écrit");
        jdl_executer(
            &st.db.lock(),
            "UPDATE token SET role='editor' WHERE kind='datasource'; UPDATE token SET name='client-jdl' WHERE kind='client';",
        );

        // table renommée : rien ne se lit, ni le jeton connu ni un inconnu.
        jdl_executer(&st.db.lock(), JDL_RENOMME);
        for tok in [JDL_SECRET_DS, JDL_SECRET_CLIENT, "inconnu"] {
            assert_eq!(jdl_ds(&st, tok), "NonLu", "table illisible : datasource `{tok}` NON lu");
            assert_eq!(jdl_cl(&st, tok), "NonLu", "table illisible : client `{tok}` NON lu");
        }
        jdl_executer(&st.db.lock(), JDL_REMIS);
        assert_eq!(jdl_ds(&st, JDL_SECRET_DS), "Trouve(ds-jdl,default,editor)", "remis");
        assert_eq!(jdl_cl(&st, JDL_SECRET_CLIENT), "Trouve(client-jdl,default,client)", "remis");
        assert_eq!(jdl_ds(&st, "inconnu"), "Absent");
    }

    struct JdlBanc {
        st: AppState,
        adresse: std::net::SocketAddr,
        servies: Arc<AtomicUsize>,
    }

    /// Le garde d'authentification RÉEL devant une sonde qui compte ses exécutions, sur les deux seams de lecture.
    async fn jdl_banc(demonstration: bool) -> JdlBanc {
        let st = jdl_etat_mode_zero(demonstration);
        let servies = Arc::new(AtomicUsize::new(0));
        let (c1, c2) = (servies.clone(), servies.clone());
        let app = axum::Router::new()
            .route(
                JDL_DS,
                axum::routing::get(move || {
                    let c = c1.clone();
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        "servi"
                    }
                }),
            )
            .route(
                JDL_CLIENT,
                axum::routing::get(move || {
                    let c = c2.clone();
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        "servi"
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(st.clone(), auth_guard))
            .with_state(st.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("fixture : port local");
        let adresse = l.local_addr().expect("fixture : adresse liée");
        tokio::spawn(async move {
            let _ = axum::serve(l, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await;
        });
        JdlBanc { st, adresse, servies }
    }

    impl JdlBanc {
        async fn envoyer(&self, chemin: &str, autorisation: Option<&str>) -> (u16, String) {
            let (code, brut) = router_probe_corps(self.adresse, "GET", chemin, autorisation, &[]).await;
            (code, brut.split_once("\r\n\r\n").map(|(_, c)| c.to_string()).unwrap_or_default())
        }
    }

    /// (b) MODE 0, À TRAVERS LE GARDE SERVI, démonstration éteinte puis ACTIVE : nominal (jeton trouvé servi ; inconnu
    /// et jeton d'agent = sortie d'avant, celle d'une requête sans jeton) ; table illisible = 503 nommé sur les deux
    /// seams, rien du moteur dans le corps, aucun last_used, gestionnaire jamais atteint — aucun repli anonyme.
    #[tokio::test]
    async fn jdl_mode_zero_lecture_ratee_rend_un_503_nomme_sans_repli() {
        for demonstration in [false, true] {
            let b = jdl_banc(demonstration).await;
            let ds = format!("Bearer {JDL_SECRET_DS}");
            let cl = format!("Bearer {JDL_SECRET_CLIENT}");
            let agent = format!("Bearer {JDL_SECRET_AGENT}");

            // nominal : la sortie d'avant.
            assert_eq!(b.envoyer(JDL_DS, Some(&ds)).await, (200, "servi".to_string()), "démo={demonstration} : datasource trouvé");
            assert_eq!(b.envoyer(JDL_CLIENT, Some(&cl)).await, (200, "servi".to_string()), "démo={demonstration} : client trouvé");
            for chemin in [JDL_DS, JDL_CLIENT] {
                let sans_jeton = b.envoyer(chemin, None).await;
                if !demonstration {
                    assert_eq!(sans_jeton, (401, "auth requise".to_string()), "{chemin} sans jeton : 401 d'avant");
                }
                for autorisation in ["Bearer inconnu", agent.as_str()] {
                    assert_eq!(
                        b.envoyer(chemin, Some(autorisation)).await,
                        sans_jeton,
                        "démo={demonstration} {chemin} `{autorisation}` : absence établie = la sortie d'une requête sans jeton"
                    );
                }
            }
            let servies_nominales = b.servies.load(Ordering::SeqCst);
            jdl_executer(&b.st.db.lock(), "UPDATE token SET last_used=NULL;");

            // table illisible.
            jdl_executer(&b.st.db.lock(), JDL_RENOMME);
            for (chemin, autorisation) in
                [(JDL_DS, ds.as_str()), (JDL_DS, "Bearer inconnu"), (JDL_CLIENT, cl.as_str()), (JDL_CLIENT, "Bearer inconnu")]
            {
                let (code, corps) = b.envoyer(chemin, Some(autorisation)).await;
                assert_eq!(code, 503, "démo={demonstration} {chemin} `{autorisation}` : table illisible -> 503, jamais 401 ni repli ({corps})");
                let v: Value = serde_json::from_str(&corps).unwrap_or(Value::Null);
                assert_eq!(v["error"], json!(CAUSE_JETON_DE_LECTURE_NON_LU), "cause nommée et constante");
                assert_ne!(v["error"], json!(CAUSE_JETON_D_AGENT_NON_LU), "cause distincte de celle du jeton d'agent");
                assert!(!corps.contains("no such table") && !corps.contains("token"), "rien du moteur dans le corps : {corps}");
            }
            assert_eq!(b.servies.load(Ordering::SeqCst), servies_nominales, "démo={demonstration} : gestionnaire jamais atteint");
            jdl_executer(&b.st.db.lock(), JDL_REMIS);

            // colonne de type inattendu, même porte : 503, pas de last_used.
            jdl_executer(
                &b.st.db.lock(),
                "UPDATE token SET role=X'00FF' WHERE name='ds-jdl'; UPDATE token SET name=X'00FF' WHERE name='client-jdl';",
            );
            assert_eq!(b.envoyer(JDL_DS, Some(&ds)).await.0, 503, "démo={demonstration} : role illisible -> 503");
            assert_eq!(b.envoyer(JDL_CLIENT, Some(&cl)).await.0, 503, "démo={demonstration} : name illisible -> 503");
            assert_eq!(b.servies.load(Ordering::SeqCst), servies_nominales);
            jdl_executer(&b.st.db.lock(), "UPDATE token SET role='editor' WHERE kind='datasource'; UPDATE token SET name='client-jdl' WHERE kind='client';");
            assert_eq!(jdl_last_used(&b.st, "ds-jdl"), None, "démo={demonstration} : aucun last_used écrit par les refus");
            assert_eq!(jdl_last_used(&b.st, "client-jdl"), None, "démo={demonstration} : aucun last_used écrit par les refus");
        }
    }

    /// (c) LA RÉSOLUTION, PORTE NOMMÉE : table illisible -> `JetonDeLectureNonLu` avec sa porte, démonstration active
    /// comprise ; nominal -> identité d'avant ; mode 1 -> absence établie, aucun refus (aucun jeton de lecture n'y
    /// existe par construction).
    #[test]
    fn jdl_resolution_refuse_avec_sa_porte_et_mode_un_inchange() {
        for demonstration in [false, true] {
            let st = jdl_etat_mode_zero(demonstration);
            let (id, m, _, _, tenant) = resolve_identity_ou_refus(&st, &jdl_requete(JDL_DS, &format!("Bearer {JDL_SECRET_DS}")))
                .expect("datasource connu : pas de refus");
            assert_eq!((id, m, tenant.as_deref()), (Some(("ds-jdl".to_string(), "editor".to_string())), "datasource", Some("default")));
            let (id, m, ..) = resolve_identity_ou_refus(&st, &jdl_requete(JDL_CLIENT, &format!("Bearer {JDL_SECRET_CLIENT}")))
                .expect("client connu : pas de refus");
            assert_eq!((id, m), (Some(("client-jdl".to_string(), "client".to_string())), "client"));

            jdl_executer(&st.db.lock(), JDL_RENOMME);
            for (chemin, secret, porte) in [
                (JDL_DS, JDL_SECRET_DS, crate::auth::PorteDuJetonDeLecture::Datasource),
                (JDL_CLIENT, JDL_SECRET_CLIENT, crate::auth::PorteDuJetonDeLecture::Client),
            ] {
                match resolve_identity_ou_refus(&st, &jdl_requete(chemin, &format!("Bearer {secret}"))) {
                    Err(crate::auth::RefusDIdentite::JetonDeLectureNonLu { porte: p, .. }) => {
                        assert_eq!(p, porte, "démo={demonstration} {chemin} : la porte nommée")
                    }
                    Err(autre) => panic!("démo={demonstration} {chemin} : refus inattendu {autre:?}"),
                    Ok((id, m, ..)) => panic!("démo={demonstration} {chemin} : lecture ratée servie comme résolue ({id:?}, `{m}`)"),
                }
            }
            jdl_executer(&st.db.lock(), JDL_REMIS);
        }

        let (cp, _plan) = mk_test_control();
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
        assert_eq!(jdl_ds(&st, JDL_SECRET_DS), "Absent", "mode 1 : aucun jeton datasource par construction");
        assert_eq!(jdl_cl(&st, JDL_SECRET_CLIENT), "Absent", "mode 1 : aucun jeton client par construction");
        for chemin in [JDL_DS, JDL_CLIENT] {
            let (id, ..) = resolve_identity_ou_refus(&st, &jdl_requete(chemin, "Bearer inconnu")).expect("mode 1 : pas de refus");
            assert_eq!(id, None, "mode 1 {chemin} : aucune identité, comme avant");
        }
    }
}
