// =====================================================================================
// `P10.20-b` (hors handlers/ : résolution du jeton d'agent, seams Bearer et HEC) — UNE LECTURE RATÉE DE LA TABLE
// DES JETONS N'EST PAS UN JETON INCONNU.
//
// LE DÉFAUT, MESURÉ SUR cc71144. `token_lookup` lisait le jeton par `query_row(..).ok()?` (mode 1, plan de
// contrôle) et `query_row(..).ok()` (mode 0) : une table illisible rendait `None`, comme « aucune ligne ». Le garde
// (`resolve_identity_ou_refus`, branches Bearer agent et HEC) poursuivait sans identité et rendait le 401 du jeton
// inconnu (HEC : `{"text":"Invalid token","code":4}`) — pour l'exploitant, une panne de lecture se lisait « jeton
// révoqué », et la résolution continuait vers les méthodes suivantes (démonstration comprise).
//
// LES VOIES D'ÉCHEC : la table `token` RENOMMÉE au moment de l'appel (« no such table »), et une colonne `host` de
// type inattendu (BLOB) sur la ligne du jeton — la table existe, la ligne est trouvée, sa lecture échoue. Jamais un
// trigger sur SELECT.
//
// ATTENDU, ET TENU ICI : trois issues (`Trouve` / `Absent` / `NonLu`) en mode 0 ET en mode 1 ; absence établie = 401
// d'avant, octet pour octet ; lecture ratée = 503 nommé (cause constante, rien du moteur dans le corps), aucun
// `last_used` écrit, aucune identité, aucun repli (démonstration comprise), le gestionnaire jamais atteint.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une base réellement corrompue ou verrouillée (le chemin refusé est le même :
// toute erreur autre que « aucune ligne ») ; les jetons datasource, client et les clés de livraison push
// (`datasource_token_lookup`, `client_token_lookup`, `push_token_connector`, signatures inchangées, `.ok()?` gardé) ;
// le 503 du mode 1 à travers le garde servi (le refus y est jugé sur `resolve_identity_ou_refus`, le garde ne fait
// que le servir) ; ce que l'expéditeur fait du 503 (`collectors/ship.sh` conserve 401/403 et 5xx pour réessai).
//
// LES MUTATIONS QUI LES FONT ROUGIR (jouées par la variable de mutation du banc, puis retirées du source) :
//  * « jeton_lecture_vaut_absent » (mode 0 : une erreur de lecture rend `Absent`, la forme `.ok()` d'avant) : (a), (b) ;
//  * « jeton_mode1_lecture_vaut_absent » (mode 1 : la forme `.ok()?` d'avant) : (c) ;
//  * « jeton_nonlu_poursuit » (les deux appelants d'auth.rs traitent `NonLu` comme `Absent`) : (b), (c).
// =====================================================================================
mod jeton_d_agent_lecture_ratee_avouee {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const JALR_SECRET: &str = "jalr-secret-de-l-agent";
    const JALR_HOTE: &str = "hote-jalr";
    const JALR_INGEST: &str = "/api/ingest";
    const JALR_HEC: &str = "/services/collector";

    fn jalr_executer(conn: &rusqlite::Connection, sql: &str) {
        conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    /// Mode 0 : base unique en mémoire, un jeton d'agent lié à `JALR_HOTE`, hors du mode d'installation.
    fn jalr_etat_mode_zero(demonstration: bool) -> AppState {
        let mut st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        st.pass_hash = Arc::new("fixture : hors du mode d'installation".to_string());
        st.public_demo = demonstration;
        st.db
            .lock()
            .execute(
                "INSERT INTO token(name,token_hash,created,host) VALUES('agent-jalr',?1,?2,?3)",
                params![sha256_hex(JALR_SECRET.as_bytes()), now(), JALR_HOTE],
            )
            .expect("fixture : jeton d'agent");
        st
    }

    fn jalr_last_used(st: &AppState) -> Option<i64> {
        st.db
            .lock()
            .query_row("SELECT last_used FROM token WHERE name='agent-jalr'", [], |r| r.get(0))
            .expect("fixture : last_used se lit")
    }

    fn jalr_issue(lu: crate::state::LectureDuJetonDAgent) -> String {
        match lu {
            crate::state::LectureDuJetonDAgent::Trouve(ti) => format!("Trouve({},{},{})", ti.tenant, ti.env, ti.host),
            crate::state::LectureDuJetonDAgent::Absent => "Absent".to_string(),
            crate::state::LectureDuJetonDAgent::NonLu(_) => "NonLu".to_string(),
        }
    }

    fn jalr_requete(chemin: &str, autorisation: &str) -> Request<axum::body::Body> {
        Request::builder()
            .method("POST")
            .uri(chemin)
            .header("authorization", autorisation)
            .body(axum::body::Body::empty())
            .expect("fixture : requête")
    }

    /// (a) MODE 0, LA LECTURE TRI-ÉTAT : trouvé (last_used écrit), absent établi, puis NON LU par colonne de type
    /// inattendu (aucun last_used écrit) et par table renommée — pour un jeton connu comme inconnu. Table remise :
    /// comportement d'avant.
    #[test]
    fn jalr_mode_zero_lecture_ratee_n_est_pas_un_jeton_absent() {
        let st = jalr_etat_mode_zero(false);
        assert_eq!(jalr_last_used(&st), None, "fixture : jamais utilisé");
        assert_eq!(jalr_issue(crate::state::token_lookup_lu(&st, JALR_SECRET)), format!("Trouve(default,prod,{JALR_HOTE})"));
        assert!(jalr_last_used(&st).is_some(), "jeton trouvé : last_used écrit, comme avant");
        assert_eq!(jalr_issue(crate::state::token_lookup_lu(&st, "inconnu")), "Absent", "absence établie");
        assert_eq!(jalr_issue(crate::state::token_lookup_lu(&st, "")), "Absent", "jeton vide : absent, comme avant");

        // colonne de type inattendu : la ligne est là, sa lecture échoue.
        jalr_executer(&st.db.lock(), "UPDATE token SET host=X'00FF', last_used=NULL WHERE name='agent-jalr';");
        assert_eq!(
            jalr_issue(crate::state::token_lookup_lu(&st, JALR_SECRET)),
            "NonLu",
            "host illisible : lecture NON faite, jamais « jeton absent »"
        );
        assert_eq!(jalr_last_used(&st), None, "lecture ratée : aucun last_used écrit");
        assert!(token_lookup(&st, JALR_SECRET).is_none(), "la projection Option ne sert toujours aucune identité");
        jalr_executer(&st.db.lock(), &format!("UPDATE token SET host='{JALR_HOTE}' WHERE name='agent-jalr';"));

        // table renommée : rien ne se lit, ni le jeton connu ni un inconnu.
        jalr_executer(&st.db.lock(), "ALTER TABLE token RENAME TO jalr_token_mis_a_l_ecart;");
        assert_eq!(jalr_issue(crate::state::token_lookup_lu(&st, JALR_SECRET)), "NonLu", "table illisible : jeton connu NON lu");
        assert_eq!(jalr_issue(crate::state::token_lookup_lu(&st, "inconnu")), "NonLu", "table illisible : rien n'est établi absent");
        jalr_executer(&st.db.lock(), "ALTER TABLE jalr_token_mis_a_l_ecart RENAME TO token;");
        assert_eq!(jalr_issue(crate::state::token_lookup_lu(&st, JALR_SECRET)), format!("Trouve(default,prod,{JALR_HOTE})"));
        assert_eq!(jalr_issue(crate::state::token_lookup_lu(&st, "inconnu")), "Absent");
    }

    struct JalrBanc {
        st: AppState,
        adresse: std::net::SocketAddr,
        servies: Arc<AtomicUsize>,
    }

    /// Le garde d'authentification RÉEL devant une sonde qui compte ses exécutions, sur les deux seams.
    async fn jalr_banc(demonstration: bool) -> JalrBanc {
        let st = jalr_etat_mode_zero(demonstration);
        let servies = Arc::new(AtomicUsize::new(0));
        let (c1, c2) = (servies.clone(), servies.clone());
        let app = axum::Router::new()
            .route(
                JALR_INGEST,
                axum::routing::post(move || {
                    let c = c1.clone();
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        "servi"
                    }
                }),
            )
            .route(
                JALR_HEC,
                axum::routing::post(move || {
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
        JalrBanc { st, adresse, servies }
    }

    impl JalrBanc {
        async fn envoyer(&self, chemin: &str, autorisation: &str) -> (u16, String) {
            let (code, brut) = router_probe_corps(self.adresse, "POST", chemin, Some(autorisation), &[]).await;
            (code, brut.split_once("\r\n\r\n").map(|(_, c)| c.to_string()).unwrap_or_default())
        }
    }

    /// (b) MODE 0, À TRAVERS LE GARDE SERVI : absence établie = 401 d'avant (Bearer : `auth requise` ; HEC : code 4) ;
    /// table illisible = 503 nommé sur les deux seams (HEC : forme HEC, code 9), rien du moteur dans le corps, aucun
    /// last_used, gestionnaire jamais atteint — démonstration active comprise (aucun repli anonyme).
    #[tokio::test]
    async fn jalr_mode_zero_lecture_ratee_rend_un_503_nomme_sur_bearer_et_hec() {
        for demonstration in [false, true] {
            let b = jalr_banc(demonstration).await;
            let bearer = format!("Bearer {JALR_SECRET}");
            let hec = format!("Splunk {JALR_SECRET}");

            if !demonstration {
                assert_eq!(b.envoyer(JALR_INGEST, "Bearer inconnu").await, (401, "auth requise".to_string()), "Bearer inconnu : 401 d'avant");
                let (code, corps) = b.envoyer(JALR_HEC, "Splunk inconnu").await;
                assert_eq!(code, 401, "HEC inconnu : 401 d'avant");
                assert_eq!(serde_json::from_str::<Value>(&corps).ok(), Some(json!({ "text": "Invalid token", "code": 4 })), "HEC inconnu : corps d'avant");
                assert_eq!(b.servies.load(Ordering::SeqCst), 0, "fixture : aucun jeton connu présenté");
            }

            jalr_executer(&b.st.db.lock(), "ALTER TABLE token RENAME TO jalr_token_mis_a_l_ecart;");
            for autorisation in [bearer.as_str(), "Bearer inconnu"] {
                let (code, corps) = b.envoyer(JALR_INGEST, autorisation).await;
                assert_eq!(code, 503, "démo={demonstration} `{autorisation}` : table des jetons illisible -> 503, jamais 401 ni repli ({corps})");
                let v: Value = serde_json::from_str(&corps).unwrap_or(Value::Null);
                assert_eq!(v["error"], json!(CAUSE_JETON_D_AGENT_NON_LU), "Bearer : cause nommée et constante");
                assert!(!corps.contains("no such table") && !corps.contains("token"), "rien du moteur dans le corps : {corps}");
            }
            for autorisation in [hec.as_str(), "Splunk inconnu"] {
                let (code, corps) = b.envoyer(JALR_HEC, autorisation).await;
                assert_eq!(code, 503, "démo={demonstration} `{autorisation}` : HEC, table illisible -> 503 ({corps})");
                assert_eq!(
                    serde_json::from_str::<Value>(&corps).ok(),
                    Some(json!({ "text": CAUSE_JETON_D_AGENT_NON_LU, "code": 9 })),
                    "HEC : corps à la forme HEC, cause constante"
                );
            }
            assert_eq!(b.servies.load(Ordering::SeqCst), 0, "démo={demonstration} : le gestionnaire n'est jamais atteint");
            jalr_executer(&b.st.db.lock(), "ALTER TABLE jalr_token_mis_a_l_ecart RENAME TO token;");
            assert_eq!(jalr_last_used(&b.st), None, "démo={demonstration} : aucun last_used écrit par les refus");

            // la colonne de type inattendu, sur la même porte : 503, pas de last_used.
            jalr_executer(&b.st.db.lock(), "UPDATE token SET host=X'00FF' WHERE name='agent-jalr';");
            assert_eq!(b.envoyer(JALR_INGEST, &bearer).await.0, 503, "démo={demonstration} : host illisible -> 503");
            assert_eq!(b.envoyer(JALR_HEC, &hec).await.0, 503, "démo={demonstration} : HEC, host illisible -> 503");
            assert_eq!(jalr_last_used(&b.st), None, "démo={demonstration} : ligne non lue, last_used intact");
            assert_eq!(b.servies.load(Ordering::SeqCst), 0);
        }
    }

    /// (b') L'INVERSE NOMINAL À TRAVERS LA RÉSOLUTION : jeton connu -> agent lié à son hôte (Bearer et HEC), absent ->
    /// aucune identité, sans refus.
    #[test]
    fn jalr_mode_zero_nominal_inchange() {
        let st = jalr_etat_mode_zero(false);
        let (id, m, _, _, tenant) = resolve_identity_ou_refus(&st, &jalr_requete(JALR_INGEST, &format!("Bearer {JALR_SECRET}")))
            .expect("Bearer connu : pas de refus");
        assert_eq!((id, m, tenant.as_deref()), (Some((JALR_HOTE.to_string(), "agent".to_string())), "bearer", Some("default")));
        let (id, m, ..) = resolve_identity_ou_refus(&st, &jalr_requete(JALR_HEC, &format!("Splunk {JALR_SECRET}")))
            .expect("HEC connu : pas de refus");
        assert_eq!((id, m), (Some((JALR_HOTE.to_string(), "agent".to_string())), "hec"));
        let (id, ..) = resolve_identity_ou_refus(&st, &jalr_requete(JALR_INGEST, "Bearer inconnu")).expect("absent : pas de refus");
        assert_eq!(id, None, "jeton absent : aucune identité");
    }

    /// (c) MODE 1 (plan de contrôle) : la lecture tri-état, puis le refus nommé de la résolution sur les deux seams
    /// quand la table `token` du plan de contrôle est illisible (renommée, puis host de type inattendu).
    #[test]
    fn jalr_mode_un_lecture_ratee_refuse_la_resolution() {
        let (cp, _plan) = mk_test_control();
        cp.conn
            .lock()
            .execute(
                "INSERT INTO token(hash,tenant_id,env_id,host,created) VALUES(?1,'acme','prod',?2,?3)",
                params![sha256_hex(JALR_SECRET.as_bytes()), JALR_HOTE, now()],
            )
            .expect("fixture : jeton du plan de contrôle");
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
        let plan = |sql: &str| jalr_executer(&st.tenants.control.as_ref().expect("fixture : mode 1").conn.lock(), sql);

        assert_eq!(jalr_issue(crate::state::token_lookup_lu(&st, JALR_SECRET)), format!("Trouve(acme,prod,{JALR_HOTE})"));
        assert_eq!(jalr_issue(crate::state::token_lookup_lu(&st, "inconnu")), "Absent", "mode 1 : absence établie");
        let (id, ..) = resolve_identity_ou_refus(&st, &jalr_requete(JALR_INGEST, "Bearer inconnu")).expect("mode 1, absent : pas de refus");
        assert_eq!(id, None);

        for (casse, remise) in [
            ("ALTER TABLE token RENAME TO jalr_token_mis_a_l_ecart;", "ALTER TABLE jalr_token_mis_a_l_ecart RENAME TO token;"),
            ("UPDATE token SET host=X'00FF';", "UPDATE token SET host='hote-jalr';"),
        ] {
            plan(casse);
            assert_eq!(jalr_issue(crate::state::token_lookup_lu(&st, JALR_SECRET)), "NonLu", "mode 1 `{casse}` : NON lu, jamais absent");
            for (chemin, autorisation, porte) in [
                (JALR_INGEST, format!("Bearer {JALR_SECRET}"), crate::auth::PorteDuJetonDAgent::Bearer),
                (JALR_HEC, format!("Splunk {JALR_SECRET}"), crate::auth::PorteDuJetonDAgent::Hec),
            ] {
                match resolve_identity_ou_refus(&st, &jalr_requete(chemin, &autorisation)) {
                    Err(crate::auth::RefusDIdentite::JetonDAgentNonLu { porte: p, .. }) => {
                        assert_eq!(p, porte, "mode 1 `{casse}` {chemin} : la porte nommée")
                    }
                    Err(autre) => panic!("mode 1 `{casse}` {chemin} : refus inattendu {autre:?}"),
                    Ok((id, m, ..)) => panic!("mode 1 `{casse}` {chemin} : lecture ratée servie comme résolue ({id:?}, `{m}`)"),
                }
            }
            plan(remise);
        }
        assert_eq!(jalr_issue(crate::state::token_lookup_lu(&st, JALR_SECRET)), format!("Trouve(acme,prod,{JALR_HOTE})"), "mode 1 : remis");
    }
}
