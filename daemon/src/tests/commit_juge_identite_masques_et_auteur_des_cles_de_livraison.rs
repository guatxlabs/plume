// =====================================================================================
// `P10.25-e` — LE `COMMIT` DES GESTES D'IDENTITÉ EST JUGÉ : jetons (frappe, révocation), clé de livraison d'une source
//              push, fournisseurs d'identité (création, modification, suppression), engagements (création qui frappe
//              les crédences `eng-cred-*`, clôture qui les révoque, balayages d'activation et d'expiration), mode de
//              réponse. Un refus rend 503 nommé (routes) ou est dit au journal sans être compté (balayages), ferme la
//              transaction, et rien n'est montré, annoncé ni chargé en mémoire avant.
// `P10.25-f` — LE `COMMIT` DES MASQUES DE CHAMP EST JUGÉ, et le registre servi n'est rechargé qu'après.
// `P10.25-q` — LA CLÉ DE LIVRAISON D'UNE SOURCE PUSH PORTE SON AUTEUR, et suit à sa suppression la décision écrite
//              pour les jetons d'ingestion.
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF le 2026-09-24 (témoin de mesure joué sur la forme d'avant, puis retiré ;
// `COMMIT` refusé par un autorisateur SQLite, « à froid » = une connexion neuve sur le même fichier, ce qu'un
// redémarrage relit) :
//  * jetons : la frappe rendait 200 ET LE SECRET, qui authentifiait tant que la transaction restait pendante — zéro
//    ligne et zéro trace à froid ; la frappe suivante échouait en 500 « verrou base indisponible ». La révocation
//    rendait 204, le jeton n'authentifiait plus… jusqu'à ce que la transaction soit annulée : il authentifiait de
//    nouveau, et il était là à froid ;
//  * source push : 200 et la clé de livraison, qui authentifiait sur son récepteur ; à froid, ni clé ni connecteur.
//    L'énoncé de `P10.25-e` ne nommait pas ce site ;
//  * fournisseurs d'identité : création 200 (aucune ligne à froid), désactivation 200 (`enabled=1` à froid),
//    suppression 204 (ligne présente à froid) — une voie d'authentification fermée par l'administrateur se rouvrait ;
//  * engagements : la création rendait 200 ET LE SECRET d'un compte `eng-cred-*` qui authentifiait, et l'index de scope,
//    rechargé DANS la transaction pendante, suspendait l'auto-ban sur `198.51.100.0/24` — sans engagement, sans compte,
//    sans trace à froid ; la clôture rendait 200 `revoked`, la crédence refusée puis ACCEPTÉE de nouveau dès la
//    transaction annulée, l'engagement `active` à froid ; le balayage d'expiration rendait 1 pour deux engagements
//    échus (le second n'était pas tenté), l'activation (1, 0) de même, et l'index rechargé après exemptait le scope
//    d'un engagement resté `scheduled` à froid ; le mode : 200 `observe`, `active` à froid ;
//  * masques de champ : la pose d'un `hash` sur `src_user` rendait 200 et le masque était SERVI (registre rechargé
//    dans la transaction), puis absent au redémarrage ; désactivation et retrait rendaient 200 et démasquaient le champ
//    pour ce processus, la règle intacte à froid ;
//  * `P10.25-q` : la clé frappée par la console avait `created_by` NULL — `connectors/presets.rs` n'appelait ni
//    `inserer_jeton` ni `inserer_jeton_frappe_par` : il écrivait son propre `INSERT INTO token`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le journal des balayages refusés (dit par `eprintln`, ni compté ni servi par
// `/api/metrics`) ; les autres `COMMIT` ignorés du démon (`P10.25-g`) ; le mode multi-tenant (écrivain du tenant, non
// joué) ; un `COMMIT` que SQLite annule de lui-même (disque plein, E/S) — seul l'autorisateur est joué, qui laisse la
// transaction ouverte, le cas le plus dur ; les clés de livraison frappées avant ce lot (auteur NULL, non rétro-rempli).
// =====================================================================================
mod commit_juge_identite_masques_et_auteur_des_cles_de_livraison {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const CJGI_CONFIG_OIDC: &str = r#"{"issuer":"https://idp.cjgi.example","client_id":"cjgi","redirect_uri":"https://plume.cjgi.example/cb"}"#;

    /// `COMMIT` (et `END`) refusés sur l'écrivain partagé ; `BEGIN` et `ROLLBACK` restent permis.
    fn cjgi_refuser_le_commit(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn cjgi_lever_l_autorisateur(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn cjgi_transaction_fermee(st: &AppState) -> bool {
        st.db.lock().is_autocommit()
    }

    async fn cjgi_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
        (statut, corps)
    }

    fn cjgi_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    /// Ce que le processus lit, sur l'écrivain partagé.
    fn cjgi_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn cjgi_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// Ce qu'un redémarrage relirait : une connexion NEUVE sur le même fichier ne voit que ce qui est validé.
    fn cjgi_a_froid(p: &crate::tmp_possede::TmpDb, sql: &str) -> String {
        let c = open_db(p.as_str()).expect("relecture à froid");
        c.query_row(sql, [], |r| r.get::<_, rusqlite::types::Value>(0))
            .map(|v| match v {
                rusqlite::types::Value::Integer(n) => n.to_string(),
                rusqlite::types::Value::Text(t) => t,
                autre => format!("{autre:?}"),
            })
            .unwrap_or_else(|e| panic!("relecture à froid de `{sql}` ({e})"))
    }

    fn cjgi_basic(nom: &str, secret: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{nom}:{secret}")))
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.25-e` — UN COMMIT REFUSÉ NE FRAPPE NI NE RÉVOQUE AUCUN JETON, ET NE MONTRE AUCUNE CLÉ DE LIVRAISON
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, `COMMIT` refusé puis levé :
    ///  * FRAPPE d'un jeton d'agent : 503 nommé, aucun secret dans le corps, transaction fermée, aucune ligne, aucune
    ///    frappe attestée ; levé, la frappe suivante réussit (200) — l'écrivain n'est pas resté dans une transaction ;
    ///  * RÉVOCATION de ce jeton : 503 nommé, transaction fermée, le jeton authentifie toujours, la ligne est là à froid,
    ///    aucune révocation attestée ; levé, 204 et le jeton n'authentifie plus ;
    ///  * SOURCE PUSH : 503 nommé, aucune clé dans le corps, transaction fermée, ni connecteur ni clé ; levé, 200.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : ignorer le `COMMIT` de `token_create` (la forme d'avant) — 200 et un secret ;
    /// celui de `token_delete` — 204 ; celui de `connector_push_source` — 200 et une clé ; retirer le `ROLLBACK` de
    /// `valider_la_transaction` — transaction restée ouverte.
    #[tokio::test]
    async fn cjgi_un_commit_refuse_ne_frappe_ni_ne_revoque_aucun_jeton_ni_aucune_cle_de_livraison() {
        let (st, p) = sp_state("cjgi-jetons");
        let frapper = |st: AppState| async move {
            cjgi_corps(token_create(State(st), Extension(cjgi_adm()), Json(json!({ "name": "ag-cjgi", "kind": "agent", "host": "h-cjgi" }))).await).await
        };

        // FRAPPE
        cjgi_refuser_le_commit(&st);
        let (statut, corps) = frapper(st.clone()).await;
        let fermee = cjgi_transaction_fermee(&st);
        cjgi_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne frappe aucun jeton : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_JETON_NON_FRAPPE_COMMIT_REFUSE), "{corps}");
        assert!(corps.get("token").is_none(), "aucun secret n'est montré : {corps}");
        assert!(fermee, "la transaction de la frappe est fermée");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM token"), 0, "aucune ligne");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.token.create'"), 0, "aucune frappe attestée");
        let (statut, corps) = frapper(st.clone()).await;
        assert_eq!(statut, 200, "levé, la frappe suivante réussit : {corps}");
        let secret = corps["token"].as_str().expect("secret montré une fois").to_string();

        // RÉVOCATION
        let revoquer = |st: AppState| async move {
            cjgi_corps(token_delete(State(st), Extension(cjgi_adm()), axum::extract::Path("ag-cjgi".to_string())).await).await
        };
        cjgi_refuser_le_commit(&st);
        let (statut, corps) = revoquer(st.clone()).await;
        let fermee = cjgi_transaction_fermee(&st);
        cjgi_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne révoque aucun jeton : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_JETON_NON_REVOQUE_COMMIT_REFUSE), "{corps}");
        assert!(fermee, "la transaction de la révocation est fermée");
        assert!(token_lookup(&st, &secret).is_some(), "le jeton authentifie toujours, comme la cause le dit");
        assert_eq!(cjgi_a_froid(&p, "SELECT COUNT(*) FROM token WHERE name='ag-cjgi'"), "1", "et un redémarrage le relirait");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.token.revoke'"), 0, "aucune révocation attestée");
        let (statut, corps) = revoquer(st.clone()).await;
        assert_eq!(statut, 204, "levé, la révocation a lieu : {corps}");
        assert!(token_lookup(&st, &secret).is_none(), "et le jeton n'authentifie plus");

        // SOURCE PUSH
        let creer = |st: AppState| async move {
            cjgi_corps(connector_push_source(State(st), Extension(cjgi_adm()), Json(json!({ "preset_id": "gcp-audit" }))).await).await
        };
        cjgi_refuser_le_commit(&st);
        let (statut, corps) = creer(st.clone()).await;
        let fermee = cjgi_transaction_fermee(&st);
        cjgi_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne crée aucune source push : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_SOURCE_PUSH_NON_CREEE_COMMIT_REFUSE), "{corps}");
        assert!(corps.get("delivery_token").is_none() && corps.get("delivery_key").is_none(), "aucune clé montrée : {corps}");
        assert!(fermee, "la transaction de la source push est fermée");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM connector"), 0, "aucun connecteur");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM token"), 0, "aucune clé");
        let (statut, corps) = creer(st.clone()).await;
        assert_eq!(statut, 200, "levé, la source push se crée : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.25-e` — UN COMMIT REFUSÉ LAISSE LES FOURNISSEURS D'IDENTITÉ INTACTS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `COMMIT` refusé, la création rend 503 nommé sans ligne ; sur un fournisseur actif, la
    /// désactivation et la suppression rendent 503 nommé, il reste actif (ici et à froid), et aucune trace n'est
    /// écrite ; la transaction est fermée à chaque fois. Levé, les trois gestes ont lieu.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : ignorer le `COMMIT` de `idp_provider_create` — 200 ; de `idp_provider_update`
    /// — 200 ; de `idp_provider_delete` — 204.
    #[tokio::test]
    async fn cjgi_un_commit_refuse_laisse_les_fournisseurs_d_identite_intacts() {
        let (st, p) = sp_state("cjgi-idp");
        let config: Value = serde_json::from_str(CJGI_CONFIG_OIDC).expect("config OIDC");
        let creer = |st: AppState, nom: &'static str| {
            let config = config.clone();
            async move {
                cjgi_corps(idp_provider_create(State(st), Extension(cjgi_adm()), Json(json!({ "name": nom, "kind": "oidc", "enabled": true, "config": config }))).await).await
            }
        };

        cjgi_refuser_le_commit(&st);
        let (statut, corps) = creer(st.clone(), "idp-fantome").await;
        let fermee = cjgi_transaction_fermee(&st);
        cjgi_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne crée aucun fournisseur : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_FOURNISSEUR_D_IDENTITE_INCHANGE), "{corps}");
        assert!(fermee, "la transaction de la création est fermée");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM idp_provider"), 0, "aucune ligne");

        let (statut, corps) = creer(st.clone(), "idp-cjgi").await;
        assert_eq!(statut, 200, "levé, la création a lieu : {corps}");
        let id = corps["id"].as_i64().expect("identifiant");
        let desactiver = |st: AppState| async move {
            cjgi_corps(idp_provider_update(State(st), Extension(cjgi_adm()), axum::extract::Path(id), Json(json!({ "enabled": false }))).await).await
        };
        let supprimer = |st: AppState| async move {
            cjgi_corps(idp_provider_delete(State(st), Extension(cjgi_adm()), axum::extract::Path(id)).await).await
        };

        cjgi_refuser_le_commit(&st);
        let (statut, corps) = desactiver(st.clone()).await;
        let fermee = cjgi_transaction_fermee(&st);
        cjgi_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne désactive rien : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_FOURNISSEUR_D_IDENTITE_INCHANGE), "{corps}");
        assert!(fermee, "la transaction de la désactivation est fermée");
        assert_eq!(cjgi_compte(&st, "SELECT enabled FROM idp_provider"), 1, "toujours actif pour ce processus");
        assert_eq!(cjgi_a_froid(&p, "SELECT enabled FROM idp_provider"), "1", "et au redémarrage");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.idp.update'"), 0, "aucune trace");

        cjgi_refuser_le_commit(&st);
        let (statut, corps) = supprimer(st.clone()).await;
        let fermee = cjgi_transaction_fermee(&st);
        cjgi_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne supprime rien : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_FOURNISSEUR_D_IDENTITE_INCHANGE), "{corps}");
        assert!(fermee, "la transaction de la suppression est fermée");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM idp_provider WHERE enabled=1"), 1, "toujours là, toujours actif");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.idp.delete'"), 0, "aucune trace");

        let (statut, corps) = desactiver(st.clone()).await;
        assert_eq!(statut, 200, "levé, la désactivation a lieu : {corps}");
        assert_eq!(cjgi_compte(&st, "SELECT enabled FROM idp_provider"), 0, "désactivé");
        let (statut, corps) = supprimer(st.clone()).await;
        assert_eq!(statut, 204, "levé, la suppression a lieu : {corps}");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM idp_provider"), 0, "supprimé");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.25-e` — UN COMMIT REFUSÉ NE CRÉE NI NE CLÔT AUCUN ENGAGEMENT, ET NE TOUCHE PAS L'EXEMPTION EN MÉMOIRE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT (mode engagement ON), `COMMIT` refusé puis levé :
    ///  * CRÉATION d'un engagement greybox : 503 nommé, aucune crédence dans le corps, transaction fermée, ni
    ///    engagement ni compte `eng-cred-*`, et `198.51.100.9` n'est PAS exemptée d'auto-ban ; levé, 200 ;
    ///  * CLÔTURE de cet engagement : 503 nommé, transaction fermée, `active` ici et à froid, sa crédence authentifie
    ///    (`viewer`) et l'adresse reste exemptée — ce que la cause annonce ; levé, 200, la crédence est refusée et
    ///    l'exemption levée.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : ignorer le `COMMIT` de `engagement_create` — 200 et une crédence ; recharger
    /// l'index de scope AVANT de juger le `COMMIT` de la création — l'adresse est exemptée sans engagement ; ignorer le
    /// `COMMIT` de `engagement_end` — 200 ; le recharger AVANT de juger celui de la clôture — l'exemption tombe alors
    /// que l'engagement court.
    #[tokio::test]
    async fn cjgi_un_commit_refuse_ne_cree_ni_ne_clot_aucun_engagement() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let (st, p) = sp_state("cjgi-engagement");
        let chemin = st.db_path.as_str().to_string();
        let creer = |st: AppState| async move {
            let corps = json!({ "box": "greybox", "scope": ["198.51.100.0/24"], "reason": "cjgi", "window_end": now() + 3600 });
            cjgi_corps(engagement_create(State(st), Extension(cjgi_adm()), Json(corps)).await).await
        };

        // CRÉATION
        cjgi_refuser_le_commit(&st);
        let (statut, corps) = creer(st.clone()).await;
        let fermee = cjgi_transaction_fermee(&st);
        cjgi_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne crée aucun engagement : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_ENGAGEMENT_NON_CREE_COMMIT_REFUSE), "{corps}");
        assert!(corps.get("credentials").is_none(), "aucune crédence montrée : {corps}");
        assert!(fermee, "la transaction de la création est fermée");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM engagement"), 0, "aucun engagement");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM user WHERE name LIKE 'eng-cred-%'"), 0, "aucun compte frappé");
        assert!(!ip_in_active_engagement("198.51.100.9", &chemin), "aucune exemption d'auto-ban posée en mémoire");

        let (statut, corps) = creer(st.clone()).await;
        assert_eq!(statut, 200, "levé, la création a lieu : {corps}");
        let id = corps["id"].as_str().expect("identifiant").to_string();
        let credence = &corps["credentials"][0];
        let nom = credence["username"].as_str().expect("compte frappé").to_string();
        let basic = cjgi_basic(&nom, credence["secret"].as_str().expect("secret montré une fois"));
        assert!(ip_in_active_engagement("198.51.100.9", &chemin), "fixture : exemption posée");

        // CLÔTURE
        let clore = |st: AppState, id: String| async move {
            cjgi_corps(engagement_end(State(st), Extension(cjgi_adm()), axum::extract::Path(id)).await).await
        };
        cjgi_refuser_le_commit(&st);
        let (statut, corps) = clore(st.clone(), id.clone()).await;
        let fermee = cjgi_transaction_fermee(&st);
        cjgi_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne clôt aucun engagement : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_ENGAGEMENT_NON_CLOS_COMMIT_REFUSE), "{corps}");
        assert!(fermee, "la transaction de la clôture est fermée");
        assert_eq!(cjgi_a_froid(&p, &format!("SELECT status FROM engagement WHERE id='{id}'")), "active", "l'engagement court");
        assert_eq!(authenticate(&st, &basic), Some((nom.clone(), "viewer".to_string())), "sa crédence authentifie, comme la cause le dit");
        assert!(ip_in_active_engagement("198.51.100.9", &chemin), "et son exemption reste posée");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.engagement.end'"), 0, "aucune clôture attestée");

        let (statut, corps) = clore(st.clone(), id.clone()).await;
        assert_eq!(statut, 200, "levé, la clôture a lieu : {corps}");
        assert_eq!(authenticate(&st, &basic), None, "la crédence est révoquée");
        assert!(!ip_in_active_engagement("198.51.100.9", &chemin), "l'exemption est levée");
        eng_test_reset();
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.25-e` — UN BALAYAGE DONT LE COMMIT EST REFUSÉ NE COMPTE RIEN, NE BLOQUE RIEN, ET REPREND AU TOUR SUIVANT
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : deux engagements actifs échus, chacun avec une crédence frappée ; deux engagements planifiés
    /// dont la fenêtre s'ouvre. `COMMIT` refusé : l'expiration rend 0, l'activation (0, 0), la transaction est fermée
    /// après chacune, rien n'a bougé (ici et à froid), les grants sont `issued` et les comptes là — et pourtant la
    /// crédence d'un engagement échu n'authentifie PAS : la fenêtre est revérifiée à chaque authentification (ce que
    /// l'énoncé laissait croire perdu ne l'était pas) ; l'index rechargé après le balayage n'exempte pas le scope d'un
    /// engagement resté planifié. Levé, le balayage SUIVANT reprend les QUATRE — la forme d'avant ne tentait pas le
    /// second de chaque liste — révoque grants et comptes, et l'index exempte les deux activés.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : ignorer le `COMMIT` dans `clore_un_geste_du_cycle` (la forme d'avant) —
    /// expiration comptée 1, transaction ouverte ; compter le geste AVANT de juger le `COMMIT` — 2 pour 0.
    #[tokio::test]
    async fn cjgi_un_balayage_dont_le_commit_est_refuse_ne_compte_rien_et_reprend_au_tour_suivant() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let (st, p) = sp_state("cjgi-balayages");
        let chemin = st.db_path.as_str().to_string();
        let t = now();
        let secret = format!("cjgi-{}", "s".repeat(24));
        {
            let c = st.db.lock();
            for (id, statut, debut, fin, scope) in [
                ("eng_cjgi_a", "active", t - 7200, t - 10, "[\"192.0.2.0/24\"]"),
                ("eng_cjgi_b", "active", t - 7200, t - 5, "[\"192.0.2.0/24\"]"),
                ("eng_cjgi_c", "scheduled", t - 10, t + 3600, "[\"203.0.113.0/24\"]"),
                ("eng_cjgi_d", "scheduled", t - 10, t + 3600, "[\"203.0.113.0/24\"]"),
            ] {
                c.execute(
                    "INSERT INTO engagement(id,name,box,scope,window_start,window_end,status,created) VALUES(?1,?1,'greybox',?2,?3,?4,?5,?3)",
                    params![id, scope, debut, fin, statut],
                )
                .expect("fixture : engagement");
            }
            for id in ["eng_cjgi_a", "eng_cjgi_b"] {
                let compte = format!("{ENG_CRED_PREFIX}{id}");
                c.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,'viewer')", params![compte, hash_pw(&secret).expect("hachage")])
                    .expect("fixture : crédence");
                c.execute(
                    "INSERT INTO engagement_grant(engagement_id,kind,ref,idp_adapter,issued_ts,status) VALUES(?1,'scoped_cred',?2,'',?3,'issued')",
                    params![id, compte, t - 7200],
                )
                .expect("fixture : grant");
            }
        }
        let etats = "SELECT group_concat(id || ':' || status, ',') FROM (SELECT id, status FROM engagement ORDER BY id)";

        cjgi_refuser_le_commit(&st);
        let expires = expire_due_engagements_conn(&st.db.lock(), t);
        let fermee_apres_expiration = cjgi_transaction_fermee(&st);
        let activations = activate_due_engagements_conn(&st.db.lock(), t);
        let fermee_apres_activation = cjgi_transaction_fermee(&st);
        cjgi_lever_l_autorisateur(&st);
        engagement_scope_refresh(&chemin, &st.db.lock());
        assert_eq!(expires, 0, "aucune expiration n'est comptée");
        assert!(fermee_apres_expiration, "la transaction de l'expiration est fermée");
        assert_eq!(activations, (0, 0), "aucune activation n'est comptée");
        assert!(fermee_apres_activation, "la transaction de l'activation est fermée");
        let avant = "eng_cjgi_a:active,eng_cjgi_b:active,eng_cjgi_c:scheduled,eng_cjgi_d:scheduled";
        assert_eq!(cjgi_texte(&st, etats), avant, "rien n'a bougé");
        assert_eq!(cjgi_a_froid(&p, etats), avant, "ni à froid");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM engagement_grant WHERE status='issued'"), 2, "grants toujours émis");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM user WHERE name LIKE 'eng-cred-%'"), 2, "comptes toujours là");
        let basic_a = cjgi_basic(&format!("{ENG_CRED_PREFIX}eng_cjgi_a"), &secret);
        assert_eq!(authenticate(&st, &basic_a), None, "la crédence d'un engagement échu ne sert pas : la fenêtre est revérifiée");
        assert!(!ip_in_active_engagement("192.0.2.9", &chemin), "ni l'exemption d'un engagement échu");
        assert!(!ip_in_active_engagement("203.0.113.9", &chemin), "l'index ne lit pas une activation non validée");

        let expires = expire_due_engagements_conn(&st.db.lock(), t);
        let activations = activate_due_engagements_conn(&st.db.lock(), t);
        engagement_scope_refresh(&chemin, &st.db.lock());
        assert_eq!(expires, 2, "le balayage suivant reprend les DEUX engagements échus");
        assert_eq!(activations, (2, 0), "et les DEUX planifiés");
        assert_eq!(cjgi_texte(&st, etats), "eng_cjgi_a:expired,eng_cjgi_b:expired,eng_cjgi_c:active,eng_cjgi_d:active");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM engagement_grant WHERE status='revoked'"), 2, "grants révoqués");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM user WHERE name LIKE 'eng-cred-%'"), 0, "comptes révoqués");
        assert!(ip_in_active_engagement("203.0.113.9", &chemin), "les activés exemptent leur scope");
        eng_test_reset();
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.25-e` — UN COMMIT REFUSÉ NE BASCULE PAS LE MODE DE RÉPONSE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : le mode est `active` (exécution réelle armée). `COMMIT` refusé, la remise en observation rend 503
    /// nommé, la transaction est fermée, `GET /api/mode` et la base à froid disent `active`, et la bascule n'est pas
    /// attestée. Levé, 200 et `observe`.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : ignorer le `COMMIT` de `mode_set` (la forme d'avant) — 200 `observe`.
    #[tokio::test]
    async fn cjgi_un_commit_refuse_ne_bascule_pas_le_mode() {
        let (st, p) = sp_state("cjgi-mode");
        let basculer = |st: AppState, mode: &'static str| async move {
            cjgi_corps(mode_set(State(st), Extension(cjgi_adm()), Json(json!({ "mode": mode }))).await).await
        };
        let (statut, corps) = basculer(st.clone(), "active").await;
        assert_eq!(statut, 200, "fixture : armé : {corps}");
        let attestees = cjgi_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.mode'");

        cjgi_refuser_le_commit(&st);
        let (statut, corps) = basculer(st.clone(), "observe").await;
        let fermee = cjgi_transaction_fermee(&st);
        cjgi_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne bascule pas le mode : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_MODE_INCHANGE_COMMIT_REFUSE), "{corps}");
        assert!(fermee, "la transaction de la bascule est fermée");
        let lu = mode_get(State(st.clone()), Extension(cjgi_adm())).await.0;
        assert_eq!(lu["mode"], json!("active"), "le mode servi est celui d'avant : {lu}");
        assert_eq!(cjgi_a_froid(&p, "SELECT value FROM meta WHERE key='plume_mode'"), "active", "et au redémarrage");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.mode'"), attestees, "aucune bascule attestée");

        let (statut, corps) = basculer(st.clone(), "observe").await;
        assert_eq!((statut, &corps["mode"]), (200, &json!("observe")), "levé, la bascule a lieu : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.25-f` — UN COMMIT REFUSÉ NE POSE, NE MODIFIE NI NE RETIRE AUCUN MASQUE, NI DANS LA BASE NI DANS LE REGISTRE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `COMMIT` refusé, la pose d'un masque `hash` sur `src_user` rend 503 nommé, transaction fermée,
    /// aucune ligne, aucune trace, et le masque n'est PAS servi à un viewer ; levé, il l'est. Sur ce masque posé, la
    /// désactivation puis le retrait rendent 503 nommé, transaction fermée, la règle est là (active, à froid), et le
    /// masque est TOUJOURS servi. Levé, le retrait a lieu et le champ n'est plus masqué.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : ignorer le `COMMIT` de `field_filter_create` (la forme d'avant) — 200, masque
    /// servi ; recharger le registre AVANT de juger le `COMMIT` de `field_filter_update` — champ démasqué ; ignorer le
    /// `COMMIT` de `field_filter_delete` — 200, champ démasqué.
    #[tokio::test]
    async fn cjgi_un_commit_refuse_ne_pose_ni_ne_retire_aucun_masque_de_champ() {
        let (st, p) = sp_state("cjgi-masques");
        let chemin = st.db_path.as_str().to_string();
        field_filters_reload(&st.db.lock(), &chemin);
        let masque_servi = |chemin: &str| effective_masks(chemin, "viewer", "default", None).get("src_user").map(action_str);
        let poser = |st: AppState| async move {
            cjgi_corps(field_filter_create(State(st), Extension(cjgi_adm()), Json(json!({ "name": "cjgi-src-user", "field": "src_user", "action": "hash" }))).await).await
        };

        cjgi_refuser_le_commit(&st);
        let (statut, corps) = poser(st.clone()).await;
        let fermee = cjgi_transaction_fermee(&st);
        cjgi_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne pose aucun masque : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_MASQUE_DE_CHAMP_INCHANGE), "{corps}");
        assert!(fermee, "la transaction de la pose est fermée");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM field_filter"), 0, "aucune ligne");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.field_filter.create'"), 0, "aucune trace");
        assert_eq!(masque_servi(&chemin), None, "le registre servi n'annonce pas un masque que la base n'a pas");

        let (statut, corps) = poser(st.clone()).await;
        assert_eq!(statut, 200, "levé, la pose a lieu : {corps}");
        let id = corps["id"].as_i64().expect("identifiant");
        assert_eq!(masque_servi(&chemin), Some("hash"), "et le masque est servi");

        cjgi_refuser_le_commit(&st);
        let (statut, corps) =
            cjgi_corps(field_filter_update(State(st.clone()), Extension(cjgi_adm()), axum::extract::Path(id), Json(json!({ "enabled": false }))).await).await;
        let fermee = cjgi_transaction_fermee(&st);
        cjgi_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne désactive aucun masque : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_MASQUE_DE_CHAMP_INCHANGE), "{corps}");
        assert!(fermee, "la transaction de la désactivation est fermée");
        assert_eq!(cjgi_a_froid(&p, "SELECT enabled FROM field_filter"), "1", "la règle est active");
        assert_eq!(masque_servi(&chemin), Some("hash"), "et le masque toujours servi");

        let retirer = |st: AppState| async move {
            cjgi_corps(field_filter_delete(State(st), Extension(cjgi_adm()), axum::extract::Path(id)).await).await
        };
        cjgi_refuser_le_commit(&st);
        let (statut, corps) = retirer(st.clone()).await;
        let fermee = cjgi_transaction_fermee(&st);
        cjgi_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne retire aucun masque : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_MASQUE_DE_CHAMP_INCHANGE), "{corps}");
        assert!(fermee, "la transaction du retrait est fermée");
        assert_eq!(cjgi_a_froid(&p, "SELECT COUNT(*) FROM field_filter"), "1", "la règle est là");
        assert_eq!(masque_servi(&chemin), Some("hash"), "et le masque toujours servi");
        assert_eq!(cjgi_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind IN ('config.field_filter.update','config.field_filter.delete')"), 0, "aucune trace");

        let (statut, corps) = retirer(st.clone()).await;
        assert_eq!(statut, 200, "levé, le retrait a lieu : {corps}");
        assert_eq!(masque_servi(&chemin), None, "et le champ n'est plus masqué");
        field_filters_forget(&chemin);
    }

    // -------------------------------------------------------------------------------------
    // (7) `P10.25-q` — LA CLÉ DE LIVRAISON PORTE SON AUTEUR ET SUIT LA DÉCISION À SA SUPPRESSION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `eve`, administratrice, crée une source push Firehose et une source push Pub/Sub ; les deux clés
    /// portent `created_by = eve`. La clé Firehose sert une fois (un flux la porte), la clé Pub/Sub jamais. `eve` est
    /// supprimée (200) : le compte rendu RÉVOQUE la clé Pub/Sub (`jamais_servi`), CONSERVE et nomme la clé Firehose
    /// (secret connu, marquée `created_by_deleted_at`, `created_by` intact), ne compte aucun auteur non établi, et sert
    /// la décision écrite. Après : la clé Firehose authentifie sur son connecteur, la clé Pub/Sub non ; le connecteur
    /// Pub/Sub est toujours là, sans clé.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR, ET QUI EST LA FORME D'AVANT : l'`INSERT` propre à `connector_push_source`, sans
    /// `created_by` — rien n'est révoqué ni conservé, deux clés « d'auteur non établi ».
    #[tokio::test]
    async fn cjgi_la_cle_de_livraison_porte_son_auteur_et_suit_la_decision_a_sa_suppression() {
        let (st, _p) = sp_state("cjgi-cles-de-livraison");
        let mot = format!("cjgi-eve-{}", "m".repeat(PASSWORD_MIN_CHARS));
        let (statut, corps) =
            cjgi_corps(user_create(State(st.clone()), Extension(cjgi_adm()), Json(json!({ "name": "eve", "password": mot, "role": "admin" }))).await).await;
        assert_eq!(statut, 200, "fixture : eve créée : {corps}");
        let creer = |st: AppState, preset: &'static str| async move {
            cjgi_corps(connector_push_source(State(st), Extension(sp_au("eve", "admin")), Json(json!({ "preset_id": preset }))).await).await
        };
        let (statut, corps) = creer(st.clone(), "aws-cloudtrail").await;
        assert_eq!(statut, 200, "fixture : source Firehose : {corps}");
        let (cle_firehose, connecteur_firehose) =
            (corps["delivery_key"].as_str().expect("clé montrée").to_string(), corps["connector_id"].as_i64().expect("connecteur"));
        let (statut, corps) = creer(st.clone(), "gcp-audit").await;
        assert_eq!(statut, 200, "fixture : source Pub/Sub : {corps}");
        let (cle_pubsub, connecteur_pubsub) =
            (corps["delivery_token"].as_str().expect("clé montrée").to_string(), corps["connector_id"].as_i64().expect("connecteur"));
        assert_eq!(
            cjgi_compte(&st, "SELECT COUNT(*) FROM token WHERE created_by='eve' AND kind IN ('firehose','gcp_pubsub')"),
            2,
            "la frappe d'une clé de livraison écrit son auteur"
        );
        assert_eq!(firehose_token_lookup(&st, &cle_firehose).map(|i| i.connector_id), Some(connecteur_firehose), "fixture : servie une fois");

        let id = cjgi_compte(&st, "SELECT id FROM user WHERE name='eve'");
        let (statut, corps) = cjgi_corps(user_delete(State(st.clone()), Extension(cjgi_adm()), axum::extract::Path(id)).await).await;
        assert_eq!(statut, 200, "la suppression rend son compte rendu : {corps}");
        let jetons = &corps["jetons"];
        assert_eq!(
            jetons["revoques"],
            json!([{ "name": format!("gcp_pubsub-{connecteur_pubsub}"), "kind": "gcp_pubsub", "host": null, "raison": "jamais_servi" }]),
            "{corps}"
        );
        let conserves = jetons["conserves_secret_connu"].as_array().expect("liste des conservées");
        assert_eq!(conserves.len(), 1, "{corps}");
        assert_eq!(
            (&conserves[0]["name"], &conserves[0]["kind"], &conserves[0]["host"]),
            (&json!(format!("firehose-{connecteur_firehose}")), &json!("firehose"), &json!(null)),
            "{corps}"
        );
        assert!(conserves[0]["last_used"].as_i64().is_some(), "la conservée a servi : {corps}");
        assert_eq!(jetons["auteur_non_etabli"], json!({}), "aucune clé d'auteur non établi : {corps}");
        assert_eq!(jetons["decision"], json!(DECISION_SUR_LES_JETONS_DU_COMPTE_SUPPRIME), "{corps}");

        assert!(firehose_token_lookup(&st, &cle_firehose).is_some(), "conservée : le flux qui la porte n'est pas coupé");
        assert!(pubsub_token_lookup(&st, &cle_pubsub).is_none(), "jamais servie : révoquée avec son autrice");
        assert_eq!(cjgi_compte(&st, &format!("SELECT COUNT(*) FROM connector WHERE id={connecteur_pubsub}")), 1, "le connecteur reste");
        assert_eq!(cjgi_compte(&st, &format!("SELECT COUNT(*) FROM token WHERE connector_id={connecteur_pubsub}")), 0, "sans clé");
        let (auteur, marque): (Option<String>, Option<i64>) = st
            .db
            .lock()
            .query_row("SELECT created_by, created_by_deleted_at FROM token WHERE kind='firehose'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("clé conservée");
        assert_eq!(auteur.as_deref(), Some("eve"), "l'attestation n'est pas réécrite");
        assert!(marque.is_some(), "la conservée est marquée : son autrice est supprimée");
    }
}
