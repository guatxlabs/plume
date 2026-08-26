    // =========================================================================================
    // SUPPRESSIONS & LISTES BLANCHES — LES TROIS GESTES DE L'ADMINISTRATEUR SUR UN SILENCE (P11.5-a)
    //
    // Le panneau « Suppressions & whitelists actives » ne savait que LIRE. Les silences d'alertes
    // (la suppression que l'on crée) avaient une route de création et une route de levée, mais
    // aucune route de MODIFICATION : pour changer la durée d'un silence il fallait le lever et le
    // recréer, et le journal d'audit perdait le lien entre les deux. La route `PUT /api/silences/{id}`
    // ferme ce trou avec les MÊMES garanties que ses voisines : même classe de rôle, même audit
    // fail-closed (ledger + event plume-config), même borne de TTL.
    //
    // Ce que ces tests tiennent :
    //   (1) modifier change ce qui a été demandé et RIEN d'autre (matchers seuls ; durée seule ;
    //       raison seule), et chaque modification laisse une entrée de ledger `config.silence.update`
    //       ET un event `plume-config` de sévérité 3 — la preuve passe par la MUTATION du compte ;
    //   (2) une modification INVALIDE (matcher hors liste, durée au-delà du TTL, id inconnu) ne
    //       change rien et n'audite rien — le témoin négatif, sans lequel (1) pourrait passer par
    //       un handler qui accepterait tout ;
    //   (3) modifier exige la même classe de rôle que créer (editor+), et la lecture reste viewer+ ;
    //   (4) le corps d'une modification identique à l'état courant ne produit AUCUNE écriture
    //       (ni ligne, ni audit) : un « Enregistrer » sans changement n'est pas un événement.
    // =========================================================================================

    fn silence_row(st: &AppState, id: i64) -> (String, i64, String) {
        let conn = st.db.lock();
        conn.query_row("SELECT matchers, expires_at, COALESCE(reason,'') FROM silence WHERE id=?1", params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).expect("silence présent")
    }
    fn ledger_count(st: &AppState, kind: &str) -> i64 {
        let conn = st.db.lock();
        conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1", params![kind], |r| r.get(0)).unwrap()
    }
    fn config_events_count(st: &AppState, like: &str) -> i64 {
        let conn = st.db.lock();
        conn.query_row("SELECT COUNT(*) FROM event WHERE source='plume-config' AND origin='daemon' AND severity=3 AND message LIKE ?1", params![like], |r| r.get(0)).unwrap()
    }

    #[tokio::test]
    async fn un_silence_se_modifie_champ_par_champ_et_chaque_geste_est_audite() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let (code, v) = tok_resp_json(silence_create(State(st.clone()), Extension(tok_au("editor")),
            Json(json!({ "matchers": { "host": "web-01" }, "duration_s": 600, "reason": "maintenance" }))).await).await;
        assert_eq!(code, StatusCode::OK, "création : {v}");
        let id = v["id"].as_i64().expect("id du silence");
        let (m0, e0, r0) = silence_row(&st, id);
        let led0 = ledger_count(&st, "config.silence.update");
        let ev0 = config_events_count(&st, "%silence de notification%modifié%");

        // (1a) matchers seuls : durée et raison INCHANGÉES.
        let (code, v) = tok_resp_json(silence_update(State(st.clone()), Extension(tok_au("editor")), Path(id),
            Json(json!({ "matchers": { "host": "web-02", "severity": 3 } }))).await).await;
        assert_eq!(code, StatusCode::OK, "modification des matchers : {v}");
        assert_eq!(v["changed"], true);
        let (m1, e1, r1) = silence_row(&st, id);
        assert_ne!(m1, m0, "les matchers ont changé");
        assert!(m1.contains("web-02") && m1.contains("severity"), "nouveaux matchers stockés : {m1}");
        assert_eq!(e1, e0, "la durée n'a PAS bougé quand seuls les matchers sont envoyés");
        assert_eq!(r1, r0, "la raison n'a PAS bougé quand seuls les matchers sont envoyés");
        assert_eq!(ledger_count(&st, "config.silence.update"), led0 + 1, "un geste = une entrée de ledger");
        assert_eq!(config_events_count(&st, "%silence de notification%modifié%"), ev0 + 1, "un geste = un event plume-config sévérité 3");

        // (1b) durée seule : comptée depuis MAINTENANT, matchers et raison inchangés.
        let avant = now();
        let (code, v) = tok_resp_json(silence_update(State(st.clone()), Extension(tok_au("editor")), Path(id),
            Json(json!({ "duration_s": 7200 }))).await).await;
        assert_eq!(code, StatusCode::OK, "modification de la durée : {v}");
        let (m2, e2, r2) = silence_row(&st, id);
        assert_eq!(m2, m1, "matchers inchangés");
        assert_eq!(r2, r1, "raison inchangée");
        assert!(e2 >= avant + 7200 && e2 <= now() + 7200, "expiration recalculée depuis maintenant : {e2}");
        assert_eq!(v["expires_at"].as_i64(), Some(e2), "la réponse rend la nouvelle expiration");
        assert_eq!(ledger_count(&st, "config.silence.update"), led0 + 2);

        // (1c) raison seule.
        let (code, _) = tok_resp_json(silence_update(State(st.clone()), Extension(tok_au("editor")), Path(id),
            Json(json!({ "reason": "fenêtre prolongée" }))).await).await;
        assert_eq!(code, StatusCode::OK);
        let (m3, e3, r3) = silence_row(&st, id);
        assert_eq!((m3.as_str(), e3), (m2.as_str(), e2), "seule la raison a bougé");
        assert_eq!(r3, "fenêtre prolongée");
        assert_eq!(ledger_count(&st, "config.silence.update"), led0 + 3);
        assert_eq!(config_events_count(&st, "%silence de notification%modifié%"), ev0 + 3);

        // (4) corps identique à l'état courant : AUCUNE écriture, aucun audit.
        let (code, v) = tok_resp_json(silence_update(State(st.clone()), Extension(tok_au("editor")), Path(id),
            Json(json!({ "reason": "fenêtre prolongée" }))).await).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["changed"], false, "rien ne change -> le handler le dit");
        assert_eq!(ledger_count(&st, "config.silence.update"), led0 + 3, "un enregistrement sans changement n'est pas un événement d'audit");

        // la liste reflète l'état modifié, et la levée reste possible après modification.
        let v = silences_list(State(st.clone()), Extension(tok_au("viewer"))).await.0;
        let row = v["silences"].as_array().unwrap().iter().find(|s| s["id"] == id).expect("silence listé");
        assert_eq!(row["reason"], "fenêtre prolongée");
        assert_eq!(row["matchers"]["host"], "web-02");
        let (code, _) = tok_resp_json(silence_delete(State(st.clone()), Extension(tok_au("editor")), Path(id)).await).await;
        assert_eq!(code, StatusCode::OK, "levée après modification");
    }

    #[tokio::test]
    async fn une_modification_invalide_ne_change_rien_et_n_audite_rien() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let (_, v) = tok_resp_json(silence_create(State(st.clone()), Extension(tok_au("editor")),
            Json(json!({ "matchers": { "source": "sshd" }, "duration_s": 300, "reason": "r" }))).await).await;
        let id = v["id"].as_i64().unwrap();
        let before = silence_row(&st, id);
        let led0 = ledger_count(&st, "config.silence.update");
        let cas: Vec<(Value, StatusCode)> = vec![
            (json!({ "matchers": { "champ_inconnu": "x" } }), StatusCode::BAD_REQUEST),      // champ hors allowlist
            (json!({ "matchers": {} }), StatusCode::BAD_REQUEST),                            // plus aucun matcher
            (json!({ "duration_s": silence_max_ttl_s() + 1 }), StatusCode::BAD_REQUEST),    // au-delà du TTL : jamais permanent
            (json!({ "duration_s": 0 }), StatusCode::BAD_REQUEST),
            (json!({ "matchers": "pas un objet" }), StatusCode::BAD_REQUEST),
        ];
        for (body, attendu) in cas {
            let (code, _) = tok_resp_json(silence_update(State(st.clone()), Extension(tok_au("editor")), Path(id), Json(body.clone())).await).await;
            assert_eq!(code, attendu, "corps {body} refusé");
            assert_eq!(silence_row(&st, id), before, "corps {body} : la ligne n'a pas bougé");
        }
        assert_eq!(ledger_count(&st, "config.silence.update"), led0, "aucun refus n'est audité comme une modification");
        // id inconnu -> 404, et rien d'écrit.
        let (code, _) = tok_resp_json(silence_update(State(st.clone()), Extension(tok_au("editor")), Path(id + 1000),
            Json(json!({ "reason": "x" }))).await).await;
        assert_eq!(code, StatusCode::NOT_FOUND);
        assert_eq!(ledger_count(&st, "config.silence.update"), led0);
    }

    /// (3) Modifier un silence appartient à la MÊME classe de rôle que le créer ou le lever : la table RBAC
    /// classe tout `/api/silences*` mutant en Write (editor+) et la lecture en Read (viewer+). Un témoin
    /// négatif à côté : une route admin-only voisine reste Admin, sinon ce test passerait par une table qui
    /// rendrait Write pour tout.
    #[test]
    fn modifier_un_silence_exige_le_meme_role_que_le_creer() {
        assert_eq!(route_min_role("/api/silences/7", true), MinRole::Write, "PUT /api/silences/{{id}} = editor+");
        assert_eq!(route_min_role("/api/silences", true), MinRole::Write, "POST /api/silences = editor+");
        assert_eq!(route_min_role("/api/silences", false), MinRole::Read, "GET /api/silences = viewer+");
        assert_eq!(route_min_role("/api/suppressions", true), MinRole::Admin, "témoin négatif : le panneau des suppressions reste admin-only");
    }
