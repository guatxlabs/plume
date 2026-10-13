// =====================================================================================
// `P10.20-b` (hors handlers/ : récepteurs push, lecture du CONNECTEUR LIÉ à une clé de livraison) — UNE LECTURE RATÉE
// DE LA TABLE `connector` N'EST PAS UN BINDING CASSÉ.
//
// LE DÉFAUT, MESURÉ SUR 2e4fe6eb. Les deux récepteurs push (routes HORS `auth_guard`) lisaient le connecteur lié par
// `match conn.query_row("SELECT type,config_json,env_id FROM connector WHERE id=?1") { Ok(x)=>x, Err(_)=>403 }`
// (firehose.rs:178-188, pubsub.rs:246-256) : un connecteur supprimé (aucune ligne) et une lecture ratée (table
// illisible, valeur d'un type inattendu) rendaient le même 403 « delivery key/token not bound to a live push
// source ». Refus fermé, mais cause fausse : le flux d'un stream cloud était refusé comme par une source supprimée
// au lieu d'être rejoué — le 503 nommé de la clé (`CAUSE_CLE_DE_LIVRAISON_NON_LUE`) existait déjà pour cela.
//
// LES VOIES D'ÉCHEC : `env_id` du connecteur posé en BLOB (la ligne est trouvée, `get::<String>` échoue — la colonne
// est `NOT NULL`, migrate.rs, aucune ligne saine n'y mène) et la table `connector` RENOMMÉE (« no such table »).
//
// ATTENDU, ET TENU ICI : trois issues (`connecteur_push_lie_lu`) ; connecteur supprimé = 403 d'avant (absence établie) ;
// lecture ratée = 503 nommé (`CAUSE_CONNECTEUR_LIE_NON_LU`, rien du moteur au corps), rien spoolé, aucun repli ; la
// clé saine sert de nouveau dès la remise. Firehose garde son enveloppe (requestId en écho).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une base réellement corrompue ou verrouillée (même chemin : toute erreur autre
// que « aucune ligne ») ; le mode 1 (aucune clé push hors control-plane, la lecture n'y est pas faite) ; le journal
// (la cause du moteur y est écrite par `eprintln!`, non capturée ici) ; l'`UPDATE last_used` de la clé, avalé, écarté
// du lot ; le rejeu effectif d'un 503 par AWS Firehose ou GCP Pub/Sub est lu dans leur contrat, pas essayé.
//
// LES MUTATIONS QUI LES FONT ROUGIR (jouées par `VERIF_MUT`, puis retirées du source) :
//  * « l3_lecture_vaut_absence » (la lecture ratée rend `Ok(None)` : le 403 d'avant rétabli) : (a), (b) ;
//  * « l3_fh_codes_inverses » (Firehose : 503 et 403 échangés) : (a) seul ;
//  * « l3_ps_codes_inverses » (Pub/Sub : 503 et 403 échangés) : (b) seul.
// =====================================================================================
mod connecteur_lie_lecture_ratee_avouee {
    use super::*;

    const L3_RENOMME: &str = "ALTER TABLE connector RENAME TO l3_connector_mis_a_l_ecart;";
    const L3_REMIS: &str = "ALTER TABLE l3_connector_mis_a_l_ecart RENAME TO connector;";

    fn l3_executer(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    async fn l3_corps(r: Response) -> (StatusCode, String) {
        let code = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (code, String::from_utf8_lossy(&b).into_owned())
    }

    fn l3_rien_du_moteur(b: &str) {
        for motif in ["Invalid column type", "Blob", "no such table", "l3_connector", "env_id"] {
            assert!(!b.contains(motif), "rien du moteur au corps (`{motif}` dans {b})");
        }
    }

    /// (a) FIREHOSE : env_id illisible, puis table renommée -> 503 nommé (requestId écho), rien spoolé ; remise ->
    /// 200 ; connecteur supprimé -> 403 d'avant (absence établie), rien de plus spoolé.
    #[tokio::test]
    async fn l3_firehose_connecteur_lie_illisible_rend_503_nomme_et_supprime_403() {
        let (st, spool) = fh_state_with_spool();
        let (cid, cle) = fh_mk_push_source(&st, "aws-guardduty", "prod").await;
        let finding = json!({ "Id": "l3", "UpdatedAt": "2026-07-01T10:00:00Z", "Severity": 5.0, "Title": "x" });
        let corps = || fh_body("l3-req", &[fh_b64(&finding.to_string())]);
        let entetes = || {
            let mut h = fh_headers(&cle);
            h.insert("x-amz-firehose-request-id", axum::http::HeaderValue::from_static("l3-req"));
            h
        };
        let spoole = || std::fs::read_dir(&spool).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with("fh-")).count();

        for (panne, remise, quoi) in [
            (format!("UPDATE connector SET env_id=X'00FF' WHERE id={cid};"), format!("UPDATE connector SET env_id='prod' WHERE id={cid};"), "env_id illisible"),
            (L3_RENOMME.to_string(), L3_REMIS.to_string(), "table renommée"),
        ] {
            l3_executer(&st, &panne);
            let (code, b) = l3_corps(firehose_ingest_post(State(st.clone()), entetes(), corps()).await).await;
            assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "{quoi} : 503, jamais le 403 d'un binding cassé ({b})");
            let v: Value = serde_json::from_str(&b).expect("corps Firehose JSON");
            assert_eq!(v["errorMessage"], CAUSE_CONNECTEUR_LIE_NON_LU, "{quoi} : cause nommée et constante");
            assert_eq!(v["requestId"], "l3-req", "{quoi} : contrat Firehose, requestId en écho");
            l3_rien_du_moteur(&b);
            assert_eq!(spoole(), 0, "{quoi} : rien spoolé");
            l3_executer(&st, &remise);
        }

        let (code, b) = l3_corps(firehose_ingest_post(State(st.clone()), entetes(), corps()).await).await;
        assert_eq!(code, StatusCode::OK, "remise : la clé saine sert de nouveau ({b})");
        assert_eq!(spoole(), 1, "remise : une livraison spoolée");

        l3_executer(&st, &format!("DELETE FROM connector WHERE id={cid};"));
        let (code, b) = l3_corps(firehose_ingest_post(State(st.clone()), entetes(), corps()).await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "connecteur supprimé : 403 d'avant ({b})");
        let v: Value = serde_json::from_str(&b).expect("corps Firehose JSON");
        assert_eq!(v["errorMessage"], "delivery key not bound to a live push source", "connecteur supprimé : corps d'avant");
        assert_eq!(v["requestId"], "l3-req", "connecteur supprimé : requestId en écho");
        assert_eq!(spoole(), 1, "connecteur supprimé : rien de plus spoolé");
    }

    /// (b) PUB/SUB : env_id illisible, puis table renommée -> 503 nommé, rien spoolé ; remise -> 200 ; connecteur
    /// supprimé -> 403 d'avant (absence établie), rien de plus spoolé.
    #[tokio::test]
    async fn l3_pubsub_connecteur_lie_illisible_rend_503_nomme_et_supprime_403() {
        let (st, spool) = ps_state_with_spool();
        let (cid, cle) = ps_mk_push_source(&st, "prod").await;
        let corps = || ps_envelope(&ps_b64(&gcp_logentry("l3-ins", "v1.compute.instances.insert", "203.0.113.9").to_string()));
        let spoole = || ps_spool_count(&spool);
        let livrer = || pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(&cle), corps());

        for (panne, remise, quoi) in [
            (format!("UPDATE connector SET env_id=X'00FF' WHERE id={cid};"), format!("UPDATE connector SET env_id='prod' WHERE id={cid};"), "env_id illisible"),
            (L3_RENOMME.to_string(), L3_REMIS.to_string(), "table renommée"),
        ] {
            l3_executer(&st, &panne);
            let (code, b) = l3_corps(livrer().await).await;
            assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "{quoi} : 503, jamais le 403 d'un binding cassé ({b})");
            let v: Value = serde_json::from_str(&b).expect("corps JSON");
            assert_eq!(v["error"], CAUSE_CONNECTEUR_LIE_NON_LU, "{quoi} : cause nommée et constante");
            l3_rien_du_moteur(&b);
            assert_eq!(spoole(), 0, "{quoi} : rien spoolé");
            l3_executer(&st, &remise);
        }

        let (code, b) = l3_corps(livrer().await).await;
        assert_eq!(code, StatusCode::OK, "remise : la clé saine sert de nouveau ({b})");
        assert_eq!(spoole(), 1, "remise : une livraison spoolée");

        l3_executer(&st, &format!("DELETE FROM connector WHERE id={cid};"));
        let (code, b) = l3_corps(livrer().await).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "connecteur supprimé : 403 d'avant ({b})");
        assert!(b.contains("delivery token not bound to a live push source"), "connecteur supprimé : corps d'avant ({b})");
        assert_eq!(spoole(), 1, "connecteur supprimé : rien de plus spoolé");
    }
}
