// =====================================================================================
// `P10.20-b` (hors handlers/ : clés de livraison PUSH, `push_token_connector`) — UNE LECTURE RATÉE DE LA TABLE DES
// JETONS N'EST PAS UNE CLÉ DE LIVRAISON INCONNUE.
//
// LE DÉFAUT, MESURÉ SUR 318bf0e. `push_token_connector` (state.rs) lisait la clé par `query_row(..).ok()?` : une table
// `token` illisible rendait `None`, comme « aucune ligne ». Les deux récepteurs push, routes HORS `auth_guard`,
// répondaient alors comme à une clé révoquée : 403 « invalid or missing X-Amz-Firehose-Access-Key » (Firehose) et 401
// « invalid or missing ?token= delivery token » (Pub/Sub). Refus fermé, mais cause fausse : l'exploitant d'un stream
// cloud lit « clé révoquée » et va régénérer une clé saine.
//
// LES VOIES D'ÉCHEC : la table `token` RENOMMÉE au moment de l'appel (« no such table »), et une colonne
// `connector_id` de type inattendu (BLOB) sur la ligne de la clé — la table existe, la ligne est trouvée, sa lecture
// échoue. Jamais un trigger sur SELECT.
//
// ATTENDU, ET TENU ICI : trois issues (`Trouve` / `Absent` / `NonLu`) ; absence établie (clé inconnue, vide, mauvais
// `kind`, ligne sans connecteur lié) = 403/401 d'avant ; lecture ratée = 503 nommé (`CAUSE_CLE_DE_LIVRAISON_NON_LUE`,
// rien du moteur dans le corps), aucun `last_used` écrit, rien spoolé, aucun repli. Isolation de `kind` intacte
// (firehose / gcp_pubsub / agent). Les projections `Option` d'avant restent (témoins de firehose.rs, pubsub.rs…).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une base réellement corrompue ou verrouillée (même chemin : toute erreur autre
// que « aucune ligne ») ; le mode 1, où aucune clé push n'existe par construction (la lecture n'y est pas faite) ;
// `engagement_cred_within_window` (engagement.rs, `unwrap_or(false)`, callers state.rs et session.rs) ; l'`UPDATE
// last_used` qui suit une clé trouvée reste avalé ; le rejeu effectif par AWS Firehose ou GCP Pub/Sub d'un 503 est lu
// dans leur contrat, pas essayé.
//
// LES MUTATIONS QUI LES FONT ROUGIR (jouées par la variable de mutation du banc, puis retirées du source) :
//  * « k2_lu_vaut_absent » (la lecture ratée rend `Absent` : la forme `.ok()?` d'avant) : (a), (b), (c) ;
//  * « k2_firehose_nonlu_vaut_absent » (le récepteur Firehose traite `NonLu` comme `Absent`) : (b) seul ;
//  * « k2_pubsub_nonlu_vaut_absent » (le récepteur Pub/Sub traite `NonLu` comme `Absent`) : (c) seul ;
//  * « k2_kind_ignore » (le filtre `kind` retiré de la requête) : (a), (b), (c).
// =====================================================================================
mod cle_de_livraison_push_lecture_ratee_avouee {
    use super::*;

    const K2_RENOMME: &str = "ALTER TABLE token RENAME TO k2_token_mis_a_l_ecart;";
    const K2_REMIS: &str = "ALTER TABLE k2_token_mis_a_l_ecart RENAME TO token;";
    const K2_FH: &str = "k2-cle-firehose";
    const K2_PS: &str = "k2-cle-pubsub";
    const K2_AGENT: &str = "k2-jeton-agent";
    const K2_NON_LIE: &str = "k2-cle-firehose-sans-connecteur";

    fn k2_executer(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn k2_issue<T>(lu: crate::state::LectureDeLaCleDeLivraison<T>, cid: impl Fn(&T) -> i64) -> String {
        match lu {
            crate::state::LectureDeLaCleDeLivraison::Trouve(t) => format!("Trouve({})", cid(&t)),
            crate::state::LectureDeLaCleDeLivraison::Absent => "Absent".to_string(),
            crate::state::LectureDeLaCleDeLivraison::NonLu(_) => "NonLu".to_string(),
        }
    }

    fn k2_fh(st: &AppState, tok: &str) -> String {
        k2_issue(crate::state::firehose_token_lookup_lu(st, tok), |i| i.connector_id)
    }

    fn k2_ps(st: &AppState, tok: &str) -> String {
        k2_issue(crate::state::pubsub_token_lookup_lu(st, tok), |i| i.connector_id)
    }

    fn k2_last_used(st: &AppState, nom: &str) -> Option<i64> {
        st.db
            .lock()
            .query_row("SELECT last_used FROM token WHERE name=?1", params![nom], |r| r.get(0))
            .expect("fixture : last_used se lit")
    }

    async fn k2_corps(r: Response) -> (StatusCode, String) {
        let code = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (code, String::from_utf8_lossy(&b).into_owned())
    }

    /// (a) LECTURE TRI-ÉTAT : trouvé (last_used écrit), absences établies (inconnue, vide, mauvais kind, jeton d'agent,
    /// ligne sans connecteur), isolation du seam agent ; puis NON LU par colonne de type inattendu (aucun last_used
    /// écrit) et par table renommée — clé connue comme inconnue. Table remise : comportement d'avant.
    #[test]
    fn k2_lecture_ratee_d_une_cle_de_livraison_n_est_pas_une_cle_absente() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        {
            let conn = st.db.lock();
            for (nom, kind, cid) in [
                (K2_FH, Some("firehose"), Some(41i64)),
                (K2_PS, Some("gcp_pubsub"), Some(42)),
                (K2_AGENT, None, None),
                (K2_NON_LIE, Some("firehose"), None),
            ] {
                conn.execute(
                    "INSERT INTO token(name,token_hash,created,kind,connector_id) VALUES(?1,?2,?3,?4,?5)",
                    params![nom, sha256_hex(nom.as_bytes()), now(), kind, cid],
                )
                .expect("fixture : jeton");
            }
        }
        assert_eq!(k2_fh(&st, K2_FH), "Trouve(41)");
        assert_eq!(k2_ps(&st, K2_PS), "Trouve(42)");
        assert!(k2_last_used(&st, K2_FH).is_some() && k2_last_used(&st, K2_PS).is_some(), "trouvée : last_used écrit");
        for (tok, quoi) in [("inconnue", "inconnue"), ("", "vide"), (K2_AGENT, "jeton d'agent"), (K2_NON_LIE, "sans connecteur")] {
            assert_eq!(k2_fh(&st, tok), "Absent", "firehose, clé {quoi} : absence établie");
            assert_eq!(k2_ps(&st, tok), "Absent", "pubsub, clé {quoi} : absence établie");
        }
        assert_eq!(k2_fh(&st, K2_PS), "Absent", "clé Pub/Sub sur Firehose : mauvais kind");
        assert_eq!(k2_ps(&st, K2_FH), "Absent", "clé Firehose sur Pub/Sub : mauvais kind");
        assert!(matches!(token_lookup_lu(&st, K2_FH), crate::state::LectureDuJetonDAgent::Absent), "clé Firehose : jamais le seam agent");
        assert!(matches!(token_lookup_lu(&st, K2_PS), crate::state::LectureDuJetonDAgent::Absent), "clé Pub/Sub : jamais le seam agent");

        // colonne de type inattendu : la ligne est là, sa lecture échoue.
        k2_executer(&st, "UPDATE token SET connector_id=X'00FF', last_used=NULL WHERE kind IN ('firehose','gcp_pubsub');");
        assert_eq!(k2_fh(&st, K2_FH), "NonLu", "connector_id illisible : lecture NON faite, jamais « clé absente »");
        assert_eq!(k2_ps(&st, K2_PS), "NonLu", "connector_id illisible : lecture NON faite, jamais « clé absente »");
        assert!(firehose_token_lookup(&st, K2_FH).is_none(), "projection : aucun connecteur");
        assert!(pubsub_token_lookup(&st, K2_PS).is_none(), "projection : aucun connecteur");
        assert_eq!((k2_last_used(&st, K2_FH), k2_last_used(&st, K2_PS)), (None, None), "lecture ratée : aucun last_used écrit");
        k2_executer(
            &st,
            &format!("UPDATE token SET connector_id=41 WHERE name='{K2_FH}'; UPDATE token SET connector_id=42 WHERE name='{K2_PS}'; \
                      UPDATE token SET connector_id=NULL WHERE name='{K2_NON_LIE}';"),
        );

        // table renommée : rien ne se lit, ni la clé connue ni une inconnue.
        k2_executer(&st, K2_RENOMME);
        for tok in [K2_FH, K2_PS, "inconnue"] {
            assert_eq!(k2_fh(&st, tok), "NonLu", "table illisible : firehose `{tok}` NON lue");
            assert_eq!(k2_ps(&st, tok), "NonLu", "table illisible : pubsub `{tok}` NON lue");
        }
        k2_executer(&st, K2_REMIS);
        assert_eq!(k2_fh(&st, K2_FH), "Trouve(41)", "remise");
        assert_eq!(k2_ps(&st, K2_PS), "Trouve(42)", "remise");
        assert_eq!(k2_fh(&st, "inconnue"), "Absent", "remise");
        assert_eq!(k2_fh(&st, K2_PS), "Absent", "remise : kind toujours exigé");
    }

    /// (b) RÉCEPTEUR FIREHOSE : clé inconnue / clé Pub/Sub / jeton d'agent -> 403 d'avant ; table renommée -> 503
    /// nommé (requestId écho), rien du moteur au corps, rien spoolé, même pour une clé inconnue ; remise -> 200.
    #[tokio::test]
    async fn k2_recepteur_firehose_table_illisible_rend_503_nomme() {
        let (st, spool) = fh_state_with_spool();
        let (_cid, cle) = fh_mk_push_source(&st, "aws-guardduty", "prod").await;
        let (_pcid, cle_ps) = ps_mk_push_source(&st, "prod").await;
        k2_executer(&st, &format!("INSERT INTO token(name,token_hash,created) VALUES('{K2_AGENT}','{}',0);", sha256_hex(K2_AGENT.as_bytes())));
        let finding = json!({ "Id": "k2", "UpdatedAt": "2026-07-01T10:00:00Z", "Severity": 5.0, "Title": "x" });
        let corps = || fh_body("k2-req", &[fh_b64(&finding.to_string())]);
        let mut entetes_saines = fh_headers(&cle);
        entetes_saines.insert("x-amz-firehose-request-id", axum::http::HeaderValue::from_static("k2-req"));
        let spoole = || std::fs::read_dir(&spool).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with("fh-")).count();

        for (tok, quoi) in [("k2-inconnue", "inconnue"), (cle_ps.as_str(), "clé Pub/Sub"), (K2_AGENT, "jeton d'agent")] {
            let (code, b) = k2_corps(firehose_ingest_post(State(st.clone()), fh_headers(tok), corps()).await).await;
            assert_eq!(code, StatusCode::FORBIDDEN, "clé {quoi} : 403 d'avant");
            assert!(b.contains("invalid or missing X-Amz-Firehose-Access-Key"), "clé {quoi} : corps d'avant ({b})");
        }

        k2_executer(&st, K2_RENOMME);
        for (tok, quoi) in [(cle.as_str(), "connue"), ("k2-inconnue", "inconnue")] {
            let mut h = fh_headers(tok);
            h.insert("x-amz-firehose-request-id", axum::http::HeaderValue::from_static("k2-req"));
            let (code, b) = k2_corps(firehose_ingest_post(State(st.clone()), h, corps()).await).await;
            assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "table illisible, clé {quoi} : 503, jamais le 403 d'une clé révoquée ({b})");
            let v: Value = serde_json::from_str(&b).expect("corps Firehose JSON");
            assert_eq!(v["errorMessage"], CAUSE_CLE_DE_LIVRAISON_NON_LUE, "cause nommée et constante");
            assert_eq!(v["requestId"], "k2-req", "contrat Firehose : requestId en écho");
            assert!(!b.contains("no such table") && !b.contains("k2_token"), "rien du moteur au corps ({b})");
        }
        assert_eq!(spoole(), 0, "lecture ratée : rien spoolé");
        k2_executer(&st, K2_REMIS);

        let (code, b) = k2_corps(firehose_ingest_post(State(st.clone()), entetes_saines, corps()).await).await;
        assert_eq!(code, StatusCode::OK, "remise : la clé saine sert de nouveau ({b})");
        assert_eq!(spoole(), 1, "remise : une livraison spoolée");
    }

    /// (c) RÉCEPTEUR PUB/SUB : clé inconnue / clé Firehose / jeton d'agent -> 401 d'avant ; table renommée -> 503
    /// nommé, rien du moteur au corps, rien spoolé, même pour une clé inconnue ; remise -> 200.
    #[tokio::test]
    async fn k2_recepteur_pubsub_table_illisible_rend_503_nomme() {
        let (st, spool) = ps_state_with_spool();
        let (_cid, cle) = ps_mk_push_source(&st, "prod").await;
        let (_fcid, cle_fh) = fh_mk_push_source(&st, "aws-guardduty", "prod").await;
        k2_executer(&st, &format!("INSERT INTO token(name,token_hash,created) VALUES('{K2_AGENT}','{}',0);", sha256_hex(K2_AGENT.as_bytes())));
        let corps = || ps_envelope(&ps_b64(&gcp_logentry("k2-ins", "v1.compute.instances.insert", "203.0.113.9").to_string()));
        let spoole = || ps_spool_count(&spool);

        for (tok, quoi) in [("k2-inconnue", "inconnue"), (cle_fh.as_str(), "clé Firehose"), (K2_AGENT, "jeton d'agent")] {
            let (code, b) = k2_corps(pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(tok), corps()).await).await;
            assert_eq!(code, StatusCode::UNAUTHORIZED, "clé {quoi} : 401 d'avant");
            assert!(b.contains("invalid or missing ?token= delivery token"), "clé {quoi} : corps d'avant ({b})");
        }

        k2_executer(&st, K2_RENOMME);
        for (tok, quoi) in [(cle.as_str(), "connue"), ("k2-inconnue", "inconnue")] {
            let (code, b) = k2_corps(pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(tok), corps()).await).await;
            assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "table illisible, clé {quoi} : 503, jamais le 401 d'une clé révoquée ({b})");
            let v: Value = serde_json::from_str(&b).expect("corps JSON");
            assert_eq!(v["error"], CAUSE_CLE_DE_LIVRAISON_NON_LUE, "cause nommée et constante");
            assert!(!b.contains("no such table") && !b.contains("k2_token"), "rien du moteur au corps ({b})");
        }
        assert_eq!(spoole(), 0, "lecture ratée : rien spoolé");
        k2_executer(&st, K2_REMIS);

        let (code, b) = k2_corps(pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(&cle), corps()).await).await;
        assert_eq!(code, StatusCode::OK, "remise : la clé saine sert de nouveau ({b})");
        assert_eq!(spoole(), 1, "remise : une livraison spoolée");
    }
}
