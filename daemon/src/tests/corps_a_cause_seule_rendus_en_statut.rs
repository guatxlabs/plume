// =====================================================================================
// `P10.20-j` — UN REFUS NE SE SERT PLUS EN DEUX CENTS : LES DIX ROUTES QUI RENDAIENT UN CORPS NE
// PORTANT QUE `error` RÉPONDENT PAR LE STATUT DE LEUR CAUSE.
//
// LE DÉFAUT, RE-MESURÉ LE 2026-09-29 SUR L'ARBRE `9db2915`. La garde « un refus n'est pas rendu comme
// une absence » nommait dix fonctions (`CORPS_A_CAUSE_SEULE`) qui servaient, EN DEUX CENTS, un corps
// `{"error": …}` et rien d'autre. Relevé par la dérivation même de la garde (littéraux `json!` à une
// seule clé de tête, hors instruction à statut) : VINGT-HUIT sites — et un vingt-neuvième qu'elle ne
// voyait pas, le refus du portillon de `case_metrics` posé sur un corps VIDE
// (`corps_de_refus(json!({}))`, forme « ajoutée ») qui sert lui aussi `{error}` seul. Un client d'API
// ou une supervision qui lit le STATUT y lisait un succès : un refus de rôle, une absence, une saisie
// écartée ou une lecture qui n'a pas eu lieu répondaient tous `200 OK`.
//
// LE CLASSEMENT, SITE PAR SITE, ET LE STATUT QUI EN SORT :
//   * refus du RÔLE (3) — 403 : `parser_reparse` et `rule_test_adhoc` par `forbidden` (objet JSON, la
//     phrase inchangée), `notifier_test` par la phrase TEXTE du rôle que `notifiers.rs` sert déjà à la
//     création d'un canal (`refus_du_role_sur_un_canal`, `P10.28-q`) ;
//   * ABSENCE (5) — 404 : règle, corrélation, canal, playbook introuvables ; et la ligne de base, mais
//     SEULEMENT sur `QueryReturnedNoRows` — sa lecture complète confondait absence et lecture ratée, et la
//     seconde rend désormais un 503 nommé (`CAUSE_LIGNE_DE_BASE_NON_LUE`) ;
//   * SAISIE écartée (5) — 400 : motif vide, regex invalide, requête vide, requête ad hoc qui ne compile
//     pas, cible refusée par `action_valid` ;
//   * DÉFINITION ENREGISTRÉE inexploitable (7) — 422 : une règle, un playbook, une corrélation ou une
//     ligne de base dont la requête ne compile pas pour l'appelant, ne s'exécute pas, ou ne porte pas les
//     colonnes que l'évaluateur attend ;
//   * LECTURE NON FAITE (4 + le portillon) — 503 : la pré-lecture qui arme la porte de masquage d'un
//     dry-run, la préparation du parcours du reparse, les deux défauts gardés de `case_metrics` et son
//     portillon clos ;
//   * TÂCHE INTERROMPUE (5) — 500 : `spawn_blocking` rendu en erreur (panique), où rien n'établit l'issue.
//
// CE QUE CES TÉMOINS JOUENT : chaque route appelée avec une identité réelle sur une base COMPLÈTE sur
// fichier, statut ET cause lus tels quels, et un CONTRÔLE POSITIF dans le même corps — sans lui, un refus
// inconditionnel passerait pour un refus fondé. Le dernier témoin traverse le ROUTEUR entier : aucune
// couche ne réécrit le statut que le gestionnaire pose.
//
// CE QU'ILS NE TIENNENT PAS : les cinq cents d'une tâche interrompue ne se provoquent pas de façon
// déterministe (il faudrait faire paniquer un `spawn_blocking`) — ils sont tenus par la garde de forme,
// pas par un témoin ; le 422 d'une évaluation échouée CONFOND une définition inexploitable et une lecture
// ratée dans l'évaluateur partagé avec l'ordonnanceur (`eval_correlation`, `eval_baseline` ne rendent
// qu'un booléen) ; et ce que la CONSOLE peint de ces statuts est jugé par le harnais ESM (témoins 127 à
// 129), jamais ici.
// =====================================================================================
mod corps_a_cause_seule_rendus_en_statut {
    use super::*;
    use axum::response::IntoResponse;
    use base64::Engine as _;

    /// Statut, corps JSON (ou `Null`) et texte brut d'une réponse : le refus du rôle d'un canal est un
    /// TEXTE, les autres sont des objets `{error}`.
    async fn ccs_reponse(r: Response) -> (u16, Value, String) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let texte = String::from_utf8_lossy(&b).into_owned();
        (statut, serde_json::from_slice(&b).unwrap_or(Value::Null), texte)
    }

    fn ccs_cause(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    fn ccs_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ccs_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn ccs_dernier_id(st: &AppState, table: &str) -> i64 {
        ccs_compte(st, &format!("SELECT MAX(id) FROM {table}"))
    }

    fn ccs_q() -> Query<std::collections::HashMap<String, String>> {
        Query(std::collections::HashMap::new())
    }

    /// Des events récents, lisibles par la réserve de lecture (le fichier est en WAL, l'écrivain valide
    /// chaque `INSERT` à part).
    fn ccs_semer_des_events(st: &AppState) {
        let conn = st.db.lock();
        for (h, ip) in [("h1", "10.0.0.5"), ("h2", "10.0.0.6")] {
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,host,message,src_ip) VALUES(?1,'sshd','auth',3,?2,'login',?3)",
                params![now() - 60, h, ip],
            )
            .expect("fixture : event");
        }
    }

    /// Un identifiant qu'aucune ligne ne porte : l'absence y est ÉTABLIE.
    const CCS_ABSENT: i64 = 987_654;
    /// Une requête GXQL qui ne compile pas : une macro que le compilateur fermé ne connaît pas.
    const CCS_REQUETE_QUI_NE_COMPILE_PAS: &str = "`macro_inexistante_ccs`";

    // -------------------------------------------------------------------------------------
    // (1) LA RIPOSTE — la saisie écartée par `action_valid`
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une cible que `action_valid` écarte rend un 400 qui porte la phrase de la
    /// validation, sans identifiant et sans ligne dans `action` ; la même route, sur une cible valable,
    /// rend l'identifiant de la ligne écrite.
    /// LA MUTATION QUI LE FERAIT ROUGIR : rendre de nouveau `Json(json!({ "error": e }))` — le statut
    /// redevient 200.
    #[tokio::test]
    async fn ccs_une_cible_ecartee_par_la_validation_est_un_400_nomme() {
        let (st, _p) = sp_state("ccs-riposte");
        let adm = sp_au("adm", "admin");
        let avant = ccs_compte(&st, "SELECT COUNT(*) FROM action");
        let (statut, corps, _) = ccs_reponse(
            action_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "kind": "ban_ip", "target": "pas-une-adresse", "dry_run": true }))).await.into_response(),
        )
        .await;
        assert_eq!(statut, 400, "une saisie écartée n'est pas un succès : {corps}");
        assert_eq!(ccs_cause(&corps), "IPv4 invalide", "la phrase de la validation est servie telle quelle : {corps}");
        assert!(corps.get("id").is_none(), "aucun identifiant n'est servi sur un refus : {corps}");
        assert_eq!(ccs_compte(&st, "SELECT COUNT(*) FROM action"), avant, "aucune riposte n'est mise en file");

        // CONTRÔLE POSITIF — la même route, une cible valable : l'identifiant de la ligne écrite. Le témoin pose un ban, il
        // déclare donc sa population (`P4.7-e`) — sans quoi la même porte refuse, en 400 aussi, faute de liste protégée.
        crate::ledger::declarer_la_liste_pour_ce_temoin();
        let (statut, corps, _) = ccs_reponse(
            action_create(State(st.clone()), Extension(adm), Json(json!({ "kind": "ban_ip", "target": "203.0.113.40", "dry_run": true, "reason": "témoin P10.20-j" }))).await.into_response(),
        )
        .await;
        assert_eq!(statut, 200, "une riposte valable est mise en file : {corps}");
        assert_eq!(corps["id"].as_i64(), Some(ccs_dernier_id(&st, "action")), "l'identifiant servi est celui de la ligne écrite : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (2) LES MÉTRIQUES DE DOSSIERS — une lecture qui n'a pas eu lieu
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sans connexion de lecture, `case_metrics` rend un 503 nommé (la cause de la
    /// lecture non faite, et l'identifiant de corrélation d'`err_json`), jamais un deux cents ; sur une
    /// base lue, le tableau de bord est servi en deux cents et ne porte aucun aveu.
    /// LA MUTATION QUI LE FERAIT ROUGIR : rendre le défaut gardé `json!({ "error": … })` servi par `Json`.
    #[tokio::test]
    async fn ccs_des_metriques_de_dossiers_non_lues_sont_un_503_nomme() {
        let (st, au, _p) = dg_etat_sans_base("ccs-metriques-sans-base");
        let (statut, corps, _) = ccs_reponse(case_metrics(State(st.clone()), Extension(au.clone()), ccs_q()).await.into_response()).await;
        assert_eq!(statut, 503, "une lecture qui n'a pas eu lieu n'est pas un succès : {corps}");
        assert_eq!(ccs_cause(&corps), crate::query_exec::LECTURE_NON_FAITE_SANS_CONNEXION, "la cause est celle de la lecture non faite : {corps}");
        assert!(corps["id"].as_str().unwrap_or("").starts_with("plume-e"), "un 5xx porte l'identifiant qui le retrouve au journal : {corps}");
        assert!(corps.get("overall").is_none(), "aucun compte n'est servi sur une lecture non faite : {corps}");

        // CONTRÔLE POSITIF — une base lue : le tableau de bord, en deux cents, sans aveu.
        let (st, _p2) = sp_state("ccs-metriques-lues");
        let adm = sp_au("adm", "admin");
        let (statut, corps, _) = ccs_reponse(case_metrics(State(st.clone()), Extension(adm), ccs_q()).await.into_response()).await;
        assert_eq!(statut, 200, "des métriques lues sont servies : {corps}");
        assert!(corps.get("error").is_none() && corps.get("overall").is_some(), "le tableau de bord est là, sans aveu : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (3) LE REPARSE — le rôle, puis le parcours qui ne commence pas
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un non-administrateur reçoit un 403 portant « réservé admin » (la route est
    /// ouverte à l'éditeur par `rbac_gate`, le gestionnaire est la seule porte) ; un parcours dont la
    /// préparation échoue rend un 503 nommé et ne compte rien ; l'administrateur, sur une base saine,
    /// reçoit son aperçu en deux cents.
    /// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `Json(json!({ "error": "réservé admin" }))`, ou servir
    /// `out.3` par `Json` — l'un ou l'autre statut redevient 200.
    #[tokio::test]
    async fn ccs_le_reparse_refuse_le_role_en_403_et_le_parcours_non_commence_en_503() {
        // Sous `cold_tier`, le reparse relit `PLUME_COLD_TIER` : même verrou que les autres lecteurs de l'environnement.
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let (st, _p) = sp_state("ccs-reparse");
        ccs_semer_des_events(&st);
        let editeur = sp_au("alice", "editor");
        let (statut, corps, _) = ccs_reponse(parser_reparse(State(st.clone()), Extension(editeur), Json(json!({ "dry_run": true }))).await).await;
        assert_eq!(statut, 403, "le reparse est réservé à l'administrateur : {corps}");
        assert_eq!(ccs_cause(&corps), "réservé admin", "la phrase du refus est inchangée : {corps}");

        // CONTRÔLE POSITIF — l'administrateur, sur une base saine : l'aperçu est servi.
        let adm = sp_au("adm", "admin");
        let (statut, corps, _) = ccs_reponse(parser_reparse(State(st.clone()), Extension(adm.clone()), Json(json!({ "dry_run": true }))).await).await;
        assert_eq!(statut, 200, "l'aperçu du reparse est servi à l'administrateur : {corps}");
        assert!(corps["scanned"].as_i64().unwrap_or(0) >= 2, "les events semés sont parcourus : {corps}");

        // LE PARCOURS QUI NE COMMENCE PAS — la table retirée sous les pieds du gestionnaire.
        ccs_ecrire(&st, "ALTER TABLE event RENAME TO event_hors_d_atteinte;");
        let (statut, corps, _) = ccs_reponse(parser_reparse(State(st.clone()), Extension(adm), Json(json!({ "dry_run": true }))).await).await;
        assert_eq!(statut, 503, "un parcours qui n'a pas pu commencer n'est pas un succès : {corps}");
        assert!(ccs_cause(&corps).starts_with("prepare:"), "la cause du moteur est servie telle quelle : {corps}");
        assert!(corps.get("scanned").is_none(), "aucun compte n'est servi sur un parcours non commencé : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (4) L'ESSAI D'UN PARSEUR — la saisie
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un motif vide et une regex qui ne compile pas rendent un 400 nommé ; un motif
    /// valable rend sa correspondance en deux cents.
    /// LA MUTATION QUI LE FERAIT ROUGIR : rétablir l'un des deux `Json(json!({ "error": … }))`.
    #[tokio::test]
    async fn ccs_l_essai_d_un_parseur_refuse_sa_saisie_en_400() {
        let (statut, corps, _) = ccs_reponse(parser_test(Json(json!({ "pattern": "", "sample": "x" }))).await.into_response()).await;
        assert_eq!(statut, 400, "un motif vide est une saisie écartée : {corps}");
        assert_eq!(ccs_cause(&corps), "motif vide", "{corps}");
        let (statut, corps, _) = ccs_reponse(parser_test(Json(json!({ "pattern": "(?P<x>", "sample": "x" }))).await.into_response()).await;
        assert_eq!(statut, 400, "une regex qui ne compile pas est une saisie écartée : {corps}");
        assert!(ccs_cause(&corps).starts_with("regex invalide : "), "la cause du compilateur est servie : {corps}");
        // CONTRÔLE POSITIF
        let (statut, corps, _) = ccs_reponse(parser_test(Json(json!({ "pattern": "(?P<x>a+)", "sample": "caab" }))).await.into_response()).await;
        assert_eq!(statut, 200, "un motif valable rend sa correspondance : {corps}");
        assert_eq!(corps["matched"], json!(true), "{corps}");
        assert_eq!(corps["fields"]["x"], json!("aa"), "{corps}");
    }

    // -------------------------------------------------------------------------------------
    // (5) L'ESSAI D'UNE RÈGLE ENREGISTRÉE, PUIS D'UNE REQUÊTE AD HOC
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une règle absente rend un 404 « règle introuvable » ; une règle dont la requête ne
    /// compile pas rend un 422 ; une règle saine rend sa valeur en deux cents.
    /// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `Json(json!({ "error": "règle introuvable" }))`.
    #[tokio::test]
    async fn ccs_l_essai_d_une_regle_enregistree_rend_le_statut_de_sa_cause() {
        let (st, _p) = sp_state("ccs-regle");
        ccs_semer_des_events(&st);
        let editeur = sp_au("alice", "editor");
        let (statut, corps, _) = ccs_reponse(rule_test(State(st.clone()), Extension(editeur.clone()), Path(CCS_ABSENT)).await.into_response()).await;
        assert_eq!(statut, 404, "une règle absente est une absence : {corps}");
        assert_eq!(ccs_cause(&corps), "règle introuvable", "{corps}");

        ccs_ecrire(&st, &format!(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,window_s,interval_s,enabled) VALUES('ccs-casse','{}',1,'>',0,3,86400,3600,0);",
            CCS_REQUETE_QUI_NE_COMPILE_PAS));
        let cassee = ccs_dernier_id(&st, "rule");
        let (statut, corps, _) = ccs_reponse(rule_test(State(st.clone()), Extension(editeur.clone()), Path(cassee)).await.into_response()).await;
        assert_eq!(statut, 422, "une règle dont la requête ne compile pas est une définition inexploitable : {corps}");
        assert!(!ccs_cause(&corps).is_empty(), "la cause du compilateur est servie : {corps}");

        // CONTRÔLE POSITIF
        ccs_ecrire(&st, "INSERT INTO rule(name,query,is_soql,op,threshold,severity,window_s,interval_s,enabled) \
                         VALUES('ccs-saine','search source=sshd | stats count',1,'>',0,3,86400,3600,0);");
        let saine = ccs_dernier_id(&st, "rule");
        let (statut, corps, _) = ccs_reponse(rule_test(State(st.clone()), Extension(editeur), Path(saine)).await.into_response()).await;
        assert_eq!(statut, 200, "une règle saine rend sa valeur : {corps}");
        assert_eq!(corps["value"].as_f64(), Some(2.0), "les deux events semés sont comptés : {corps}");
    }

    /// CE QU'IL TIENT : une requête vide et une requête qui ne compile pas rendent un 400 ; le SQL brut
    /// d'un éditeur rend un 403 portant la phrase de `/api/query` ; une requête saine rend sa valeur.
    /// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `Json(json!({ "error": "SQL brut réservé … " }))`.
    #[tokio::test]
    async fn ccs_l_essai_ad_hoc_d_une_regle_rend_le_statut_de_sa_cause() {
        let (st, _p) = sp_state("ccs-regle-ad-hoc");
        ccs_semer_des_events(&st);
        let editeur = sp_au("alice", "editor");
        let essai = |corps: Value| {
            let (st, au) = (st.clone(), editeur.clone());
            async move { ccs_reponse(rule_test_adhoc(State(st), Extension(au), Json(corps)).await.into_response()).await }
        };
        let (statut, corps, _) = essai(json!({ "query": "   " })).await;
        assert_eq!(statut, 400, "une requête vide est une saisie écartée : {corps}");
        assert_eq!(ccs_cause(&corps), "requête vide", "{corps}");
        let (statut, corps, _) = essai(json!({ "query": "SELECT COUNT(*) FROM event", "is_soql": false })).await;
        assert_eq!(statut, 403, "le SQL brut est réservé à l'administrateur : {corps}");
        assert_eq!(ccs_cause(&corps), "SQL brut réservé à l'administrateur (utilisez GXQL)", "la phrase de `/api/query`, inchangée : {corps}");
        let (statut, corps, _) = essai(json!({ "query": CCS_REQUETE_QUI_NE_COMPILE_PAS, "is_soql": true })).await;
        assert_eq!(statut, 400, "une requête soumise qui ne compile pas est une saisie écartée : {corps}");
        assert!(!ccs_cause(&corps).is_empty(), "{corps}");
        // CONTRÔLE POSITIF
        let (statut, corps, _) = essai(json!({ "query": "search source=sshd | stats count", "is_soql": true, "op": ">", "threshold": 0.0, "window_s": 86400 })).await;
        assert_eq!(statut, 200, "une requête saine rend sa valeur : {corps}");
        assert_eq!(corps["value"].as_f64(), Some(2.0), "{corps}");
    }

    // -------------------------------------------------------------------------------------
    // (6) L'ESSAI D'UNE CORRÉLATION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une corrélation absente rend un 404 ; une corrélation dont l'étape ne porte pas la
    /// colonne `ts` rend un 422 ; une corrélation saine rend son aperçu en deux cents.
    /// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `Json(json!({ "error": "évaluation échouée … " }))`.
    #[tokio::test]
    async fn ccs_l_essai_d_une_correlation_rend_le_statut_de_sa_cause() {
        let (st, _p) = sp_state("ccs-correlation");
        ccs_semer_des_events(&st);
        let editeur = sp_au("alice", "editor");
        let (statut, corps, _) = ccs_reponse(correlation_test(State(st.clone()), Extension(editeur.clone()), Path(CCS_ABSENT)).await.into_response()).await;
        assert_eq!(statut, 404, "une corrélation absente est une absence : {corps}");
        assert_eq!(ccs_cause(&corps), "corrélation introuvable", "{corps}");

        ccs_ecrire(&st, r#"INSERT INTO correlation(name,key_field,entity_type,steps,window_s,interval_s,severity,enabled)
                           VALUES('ccs-sans-ts','src_ip','ip','[{"query":"search source=sshd | stats count by src_ip"}]',86400,3600,3,0);"#);
        let sans_ts = ccs_dernier_id(&st, "correlation");
        let (statut, corps, _) = ccs_reponse(correlation_test(State(st.clone()), Extension(editeur.clone()), Path(sans_ts)).await.into_response()).await;
        assert_eq!(statut, 422, "une étape sans colonne `ts` rend la définition inexploitable : {corps}");
        assert!(ccs_cause(&corps).starts_with("évaluation échouée"), "{corps}");

        // CONTRÔLE POSITIF
        ccs_ecrire(&st, r#"INSERT INTO correlation(name,key_field,entity_type,steps,window_s,interval_s,severity,enabled)
                           VALUES('ccs-saine','src_ip','ip','[{"query":"search source=sshd | table ts,src_ip"}]',86400,3600,3,0);"#);
        let saine = ccs_dernier_id(&st, "correlation");
        let (statut, corps, _) = ccs_reponse(correlation_test(State(st.clone()), Extension(editeur), Path(saine)).await.into_response()).await;
        assert_eq!(statut, 200, "une corrélation saine rend son aperçu : {corps}");
        assert_eq!(corps["ok"], json!(true), "{corps}");
    }

    // -------------------------------------------------------------------------------------
    // (7) L'ESSAI D'UNE LIGNE DE BASE — quatre issues distinctes
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une ligne de base ABSENTE rend un 404 ; une pré-lecture ratée (la porte de masquage
    /// n'est pas armée) rend un 503 nommé `CAUSE_PORTE_DRYRUN_NON_ARMEE` ; une pré-lecture qui réussit
    /// suivie d'une lecture COMPLÈTE ratée rend un 503 nommé `CAUSE_LIGNE_DE_BASE_NON_LUE` — et JAMAIS
    /// « baseline introuvable », que l'ancienne forme servait sur toute erreur de cette lecture ; une
    /// évaluation dont la colonne d'entité manque rend un 422 ; une ligne de base saine rend son aperçu.
    /// LES MUTATIONS QUI LE FERAIENT ROUGIR : fondre les deux bras d'erreur de la lecture complète
    /// (`Err(_) => not_found(…)`) — le troisième bloc tombe ; rendre la cause de porte par `Json` — le
    /// deuxième tombe.
    #[tokio::test]
    async fn ccs_l_essai_d_une_ligne_de_base_separe_l_absence_de_la_lecture_ratee() {
        let (st, _p) = sp_state("ccs-ligne-de-base");
        ccs_semer_des_events(&st);
        let editeur = sp_au("alice", "editor");
        let essai = |id: i64| {
            let (st, au) = (st.clone(), editeur.clone());
            async move { ccs_reponse(baseline_test(State(st), Extension(au), Path(id)).await.into_response()).await }
        };
        let (statut, corps, _) = essai(CCS_ABSENT).await;
        assert_eq!(statut, 404, "une ligne de base absente est une absence : {corps}");
        assert_eq!(ccs_cause(&corps), "baseline introuvable", "{corps}");

        let semer = |nom: &str, entite: &str| {
            ccs_ecrire(&st, &format!(
                "INSERT INTO ueba_baseline(name,query,entity_field,value_field,entity_type,bucket_s,min_samples,z_threshold,window_s,interval_s,severity,enabled) \
                 VALUES('{nom}','search source=sshd | stats count by host','{entite}','count','host',3600,1,3.0,86400,3600,3,0);"));
            ccs_dernier_id(&st, "ueba_baseline")
        };
        // LA PRÉ-LECTURE RATÉE : `query` porte un BLOB, que la pré-lecture lit en `TEXT`.
        let porte = semer("ccs-porte", "host");
        ccs_ecrire(&st, &format!("UPDATE ueba_baseline SET query=x'FF' WHERE id={porte};"));
        let (statut, corps, _) = essai(porte).await;
        assert_eq!(statut, 503, "une porte de masquage non armée est une lecture non faite : {corps}");
        assert_eq!(ccs_cause(&corps), crate::handlers::detection_advanced::CAUSE_PORTE_DRYRUN_NON_ARMEE, "{corps}");

        // LA LECTURE COMPLÈTE RATÉE : `name` porte un BLOB — la pré-lecture ne le lit pas, la lecture complète si.
        let complete = semer("ccs-complete", "host");
        ccs_ecrire(&st, &format!("UPDATE ueba_baseline SET name=x'FF' WHERE id={complete};"));
        let (statut, corps, _) = essai(complete).await;
        assert_eq!(statut, 503, "une ligne de base qui EXISTE mais ne se lit pas n'est pas une absence : {corps}");
        assert_eq!(ccs_cause(&corps), crate::handlers::detection_advanced::CAUSE_LIGNE_DE_BASE_NON_LUE, "{corps}");
        assert_ne!(ccs_cause(&corps), "baseline introuvable", "« introuvable » n'est servi que sur une absence établie : {corps}");

        // L'ÉVALUATION IMPOSSIBLE : la colonne d'entité nommée n'existe pas dans le résultat.
        let sans_entite = semer("ccs-sans-entite", "colonne_absente");
        let (statut, corps, _) = essai(sans_entite).await;
        assert_eq!(statut, 422, "une définition dont la colonne d'entité manque est inexploitable : {corps}");
        assert!(ccs_cause(&corps).starts_with("évaluation échouée"), "{corps}");

        // CONTRÔLE POSITIF
        let saine = semer("ccs-saine", "host");
        let (statut, corps, _) = essai(saine).await;
        assert_eq!(statut, 200, "une ligne de base saine rend son aperçu : {corps}");
        assert_eq!(corps["ok"], json!(true), "{corps}");
    }

    // -------------------------------------------------------------------------------------
    // (8) L'ESSAI D'UN CANAL DE NOTIFICATION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un non-administrateur reçoit un 403 portant la phrase TEXTE du rôle — la forme
    /// que la console lit comme le refus du rôle (`leRefusEstCeluiDuRole`, web/core.js) et que la
    /// création d'un canal sert déjà ; un canal absent rend un 404 ; un canal présent est essayé, et
    /// son issue est servie en deux cents.
    /// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `Json(json!({ "error": "réservé à l'administrateur" }))`.
    #[tokio::test]
    async fn ccs_l_essai_d_un_canal_rend_le_statut_de_sa_cause() {
        let (st, _p) = sp_state("ccs-canal");
        let (statut, _, texte) = ccs_reponse(notifier_test(State(st.clone()), Extension(sp_au("alice", "editor")), Path(1)).await.into_response()).await;
        assert_eq!(statut, 403, "l'essai d'un canal est réservé à l'administrateur : {texte}");
        assert_eq!(texte, "réservé à l'administrateur", "la phrase TEXTE du rôle, sans objet JSON autour : {texte}");
        let adm = sp_au("adm", "admin");
        let (statut, corps, _) = ccs_reponse(notifier_test(State(st.clone()), Extension(adm.clone()), Path(CCS_ABSENT)).await.into_response()).await;
        assert_eq!(statut, 404, "un canal absent est une absence : {corps}");
        assert_eq!(ccs_cause(&corps), "canal introuvable", "{corps}");
        // CONTRÔLE POSITIF — une adresse de bouclage : la garde d'égress refuse l'envoi, l'essai rend `ok:false`
        // en deux cents (un essai qui a eu lieu et a échoué n'est pas un refus de la route).
        ccs_ecrire(&st, "INSERT INTO notifier(name,kind,url,enabled) VALUES('ccs','ntfy','http://127.0.0.1:9/ccs',1);");
        let canal = ccs_dernier_id(&st, "notifier");
        let (statut, corps, _) = ccs_reponse(notifier_test(State(st.clone()), Extension(adm), Path(canal)).await.into_response()).await;
        assert_eq!(statut, 200, "un canal présent est essayé : {corps}");
        assert_eq!(corps["ok"], json!(false), "l'envoi vers une adresse de bouclage n'a pas lieu : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (9) L'ESSAI D'UN PLAYBOOK
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un playbook absent rend un 404 ; un playbook dont la requête ne compile pas, puis
    /// un playbook dont la requête ne s'exécute pas, rendent un 422 ; un playbook sain rend ses cibles.
    /// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `Ok(Err(e)) => Json(json!({ "error": e }))`.
    #[tokio::test]
    async fn ccs_l_essai_d_un_playbook_rend_le_statut_de_sa_cause() {
        let (st, _p) = sp_state("ccs-playbook");
        ccs_semer_des_events(&st);
        let adm = sp_au("adm", "admin");
        let essai = |id: i64| {
            let (st, au) = (st.clone(), adm.clone());
            async move { ccs_reponse(playbook_test(State(st), Extension(au), Path(id)).await.into_response()).await }
        };
        let (statut, corps, _) = essai(CCS_ABSENT).await;
        assert_eq!(statut, 404, "un playbook absent est une absence : {corps}");
        assert_eq!(ccs_cause(&corps), "playbook introuvable", "{corps}");

        let semer = |nom: &str, requete: &str, gxql: i64| {
            ccs_ecrire(&st, &format!(
                "INSERT INTO playbook(name,query,is_soql,action_kind,window_s,interval_s,enabled,created_by_role) \
                 VALUES('{nom}','{requete}',{gxql},'ban_ip',86400,3600,0,'admin');"));
            ccs_dernier_id(&st, "playbook")
        };
        let (statut, corps, _) = essai(semer("ccs-ne-compile-pas", CCS_REQUETE_QUI_NE_COMPILE_PAS, 1)).await;
        assert_eq!(statut, 422, "une requête qui ne compile pas rend la définition inexploitable : {corps}");
        assert!(!ccs_cause(&corps).is_empty(), "{corps}");
        let (statut, corps, _) = essai(semer("ccs-ne-s-execute-pas", "SELECT src_ip FROM table_inexistante_ccs", 0)).await;
        assert_eq!(statut, 422, "une requête qui ne s'exécute pas rend la définition inexploitable : {corps}");
        assert!(ccs_cause(&corps).contains("table_inexistante_ccs"), "la cause du moteur est servie : {corps}");
        // CONTRÔLE POSITIF
        let (statut, corps, _) = essai(semer("ccs-sain", "search source=sshd | table src_ip", 1)).await;
        assert_eq!(statut, 200, "un playbook sain rend ses cibles : {corps}");
        assert_eq!(corps["targets"].as_array().map(|a| a.len()), Some(2), "les deux adresses semées sont des cibles : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (10) LE ROUTEUR ENTIER — aucune couche ne réécrit le statut
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : par le routeur réel (authentification, `rbac_gate`, garde de ban), un éditeur
    /// qui essaie un motif vide reçoit le 400 nommé du gestionnaire, et un motif valable son deux cents.
    /// CE QU'IL NE TIENT PAS : il ne joue qu'UNE route — les autres sont jouées gestionnaire par
    /// gestionnaire ci-dessus, et le chemin des couches est le même pour toutes.
    #[tokio::test]
    async fn ccs_le_statut_du_gestionnaire_traverse_le_routeur() {
        let (st, _p) = router_test_state("ccs-routeur");
        st.db.lock()
            .execute("INSERT INTO user(name,hash,role) VALUES('edt',?1,'editor')", params![hash_pw("editeurpw12345").unwrap()])
            .expect("fixture : compte éditeur");
        let addr = router_serve(st).await;
        let authz = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("edt:editeurpw12345"));
        let entetes = [("Content-Type", "application/json")];
        let (code, corps) = router_probe_envoi(addr, "POST", "/api/parser-test", Some(&authz), &entetes, r#"{"pattern":"","sample":"x"}"#).await;
        assert_eq!(code, 400, "le 400 du gestionnaire arrive tel quel au client : {corps}");
        assert!(corps.contains("motif vide"), "avec sa cause : {corps}");
        let (code, corps) = router_probe_envoi(addr, "POST", "/api/parser-test", Some(&authz), &entetes, r#"{"pattern":"(?P<x>a)","sample":"a"}"#).await;
        assert_eq!(code, 200, "CONTRÔLE POSITIF : un motif valable est servi : {corps}");
        assert!(corps.contains("\"matched\":true"), "{corps}");
    }
}
