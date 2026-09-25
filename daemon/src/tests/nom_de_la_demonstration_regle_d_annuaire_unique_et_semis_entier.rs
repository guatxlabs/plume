// =====================================================================================
// `P10.25-h` — LE NOM DE LA DÉMONSTRATION PUBLIQUE NE DEVIENT PAS UN COMPTE LOCAL ; LES NOMS DE JETONS, SI (décision
//              mesurée : rien ne passe, dans aucun sens).
// `P10.25-t` — UNE SEULE RÈGLE POUR LES DEUX PORTES PAR LESQUELLES UN ANNUAIRE PREND UN NOM (en-têtes SSO, fédération
//              OIDC/SAML/LDAP) : `auth::juger_le_nom_pris_par_un_annuaire`.
// `P10.28-e` — UN SEMIS DE TABLEAU DE BORD EST ENTIER OU N'EST PAS, SON DRAPEAU `seeded_*` EN DERNIER.
// `P10.28-g` — CE QU'UNE INSERTION QUI PEUT NE RIEN INSÉRER LAISSE DANS `last_insert_rowid()`, sur le SQLite embarqué :
//              le fait sur lequel `check_an_inserted_id_is_read_at_the_foot_of_its_insert.py` fonde sa règle neuve.
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF le 2026-09-25 (témoin de mesure joué sur la forme d'avant, puis retiré) :
//  * `P10.25-h`, démonstration active : l'anonyme (aucun identifiant) est résolu `demo`/`viewer`. `adm` crée `demo`
//    (`editor`) — 200. Ce compte pose, par son mot de passe, une requête privée et ses préférences ; il possède un
//    tableau de bord privé. L'anonyme liste la requête AVEC son texte, voit le tableau de bord privé, lit les
//    préférences, SUPPRIME la requête (200 ; la liste du compte est vide ensuite) et ÉCRASE les préférences.
//    Démonstration inactive : la création rendait 200 aussi. JETONS, SURCOMPTÉ : un compte au nom d'un jeton de
//    source de données (`grafana-ndrs`), d'un jeton d'agent (`ag-ndrs`) ou de l'hôte qu'il porte (`h-ndrs`) se crée
//    (200) et ne reçoit ni ne cède rien — le jeton ne tient aucun objet, reste 401 sur les requêtes enregistrées et
//    200 sur sa route, le compte reste 403 sur la réponse d'agent ;
//  * `P10.25-t` : la fédération d'un nom qui est celui de l'administrateur de l'assistant SANS ligne rendait Ok, posait
//    une ligne fédérée qui fait autorité, et son mot de passe d'installation (200 `admin` avant) ne connectait plus ;
//    avec la lecture de `user.hash` refusée sur l'écrivain, la fédération de `bob` (`editor`, mot de passe) dans le
//    groupe administrateur rendait Ok, la ligne de `bob` passait `admin`, et son MOT DE PASSE LOCAL le connectait
//    ensuite en administrateur ;
//  * `P10.28-e` : tableau refusé — drapeau posé, aucun tableau, jamais rejoué ; panneau refusé — tableau VIDE, drapeau
//    posé, jamais réparé ; drapeau refusé — le démarrage suivant écrivait un SECOND tableau (2 tableaux, 14 panneaux
//    pour la vue d'ensemble), ce que l'énoncé ne disait pas ;
//  * `P10.28-g` : `INSERT OR IGNORE` ignoré et `ON CONFLICT DO NOTHING` rendent 0 ligne et laissent l'identifiant
//    d'une AUTRE table ; `ON CONFLICT DO UPDATE` qui met à jour rend UNE ligne (`Ok(1)`) et laisse AUSSI l'identifiant
//    d'une autre table — l'énoncé (« exiger `Ok(1)` ») sous-comptait. Aucun site de `daemon/src` ne lit un identifiant
//    après une telle insertion (recensé : 53 lectures, toutes au pied d'un `INSERT` simple).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la démonstration publique qui ÉCRIT (l'anonyme crée des requêtes
// enregistrées et des préférences sous `demo`, mesuré) et qui DÉSARME le frein anti-force brute du mot de passe
// (quarante essais faux servis `demo`, jamais freinés ; le vrai mot de passe ensuite connecte l'administrateur) —
// clés proposées, non corrigées ici ; un compte `demo` DÉJÀ présent quand la démonstration s'active ; un annuaire qui
// présente le nom `demo` (chemin d'en-têtes, fédération) ; le mode multi-tenant ; les semis de règles et de playbooks,
// dont le drapeau est aussi posé avant les données, et `seed_runbooks`, dont une étape refusée laisse le gabarit sans
// étapes pour toujours (mesuré : quinze gabarits sur quinze) ; la réponse HTTP des trois fédérations (non jouable sans
// fournisseur : la règle est jouée par `federer_le_nom`, le câblage par la lecture de `handlers/idp.rs`).
// =====================================================================================
mod nom_de_la_demonstration_regle_d_annuaire_unique_et_semis_entier {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// Le mot de passe que `sp_state` pose sur `alice`, `bob` et `adm`.
    const NDRS_MOT_DE_PASSE_DE_FIXTURE: &str = "motdepasse12345";
    const NDRS_SECRET_SSO: &str = "secret-de-bord-ndrs";
    const NDRS_ADMIN_DE_CONFIGURATION: &str = "root-ndrs";

    /// Un mot de passe recevable, construit — jamais un littéral de clé.
    fn ndrs_mot(marque: &str) -> String {
        format!("ndrs-{marque}-{}", "m".repeat(PASSWORD_MIN_CHARS))
    }

    fn ndrs_basic(nom: &str, mot: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{nom}:{mot}")))
    }

    async fn ndrs_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
        (statut, corps)
    }

    fn ndrs_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (mut st, p) = sp_state(tag);
        st.sso_secret = Arc::new(NDRS_SECRET_SSO.into());
        st.user = Arc::new(NDRS_ADMIN_DE_CONFIGURATION.into());
        st.pass_hash = Arc::new(hash_pw(&ndrs_mot("configuration")).expect("hachage"));
        (st, p)
    }

    async fn ndrs_creer(st: &AppState, nom: &str, role: &str) -> (u16, Value) {
        ndrs_corps(
            user_create(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({ "name": nom, "password": ndrs_mot(nom), "role": role })))
                .await,
        )
        .await
    }

    fn ndrs_compte(st: &AppState, sql: &str, p: &str) -> i64 {
        st.db.lock().query_row(sql, params![p], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    // -------------------------------------------------------------------------------------
    // Le banc du chemin servi : le garde d'authentification RÉEL devant les gestionnaires réels.
    // -------------------------------------------------------------------------------------

    struct NdrsBanc {
        adresse: std::net::SocketAddr,
        arret: Option<tokio::sync::oneshot::Sender<()>>,
        fil: Option<tokio::task::JoinHandle<()>>,
    }

    async fn ndrs_banc(st: &AppState) -> NdrsBanc {
        let app = axum::Router::new()
            .route("/api/me", axum::routing::get(me))
            .route("/api/saved-queries", axum::routing::get(saved_queries_list).post(saved_query_create))
            .route("/api/actions/pending", axum::routing::get(actions_pending))
            .route("/api/ds/query", axum::routing::post(ds_query_post))
            .layer(axum::middleware::from_fn_with_state(st.clone(), auth_guard))
            .with_state(st.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("fixture : port local");
        let adresse = l.local_addr().expect("fixture : adresse liée");
        let (arret, recu) = tokio::sync::oneshot::channel::<()>();
        let fil = tokio::spawn(async move {
            let _ = axum::serve(l, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .with_graceful_shutdown(async {
                    let _ = recu.await;
                })
                .await;
        });
        NdrsBanc { adresse, arret: Some(arret), fil: Some(fil) }
    }

    /// Un rouge avant `arreter` : le fil du serveur est interrompu (même geste que les bancs voisins).
    impl Drop for NdrsBanc {
        fn drop(&mut self) {
            if let Some(f) = self.fil.take() {
                f.abort();
            }
        }
    }

    impl NdrsBanc {
        async fn envoyer(&self, methode: &str, chemin: &str, autorisation: Option<&str>, corps: &str) -> (u16, Value) {
            let entetes: &[(&str, &str)] = if corps.is_empty() { &[] } else { &[("content-type", "application/json")] };
            let (code, brut) = router_probe_envoi(self.adresse, methode, chemin, autorisation, entetes, corps).await;
            let c = brut.split_once("\r\n\r\n").map(|(_, c)| c.to_string()).unwrap_or_default();
            (code, serde_json::from_str(&c).unwrap_or(Value::String(c)))
        }
        /// Le serveur est arrêté et son fil attendu AVANT que la base temporaire ne soit détruite.
        async fn arreter(mut self) {
            if let Some(a) = self.arret.take() {
                let _ = a.send(());
            }
            if let Some(f) = self.fil.take() {
                let _ = tokio::time::timeout(Duration::from_secs(20), f).await;
            }
        }
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.25-h` — LE NOM DE LA DÉMONSTRATION NE DEVIENT PAS UN COMPTE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : démonstration active, l'anonyme est servi `demo`/`viewer` (méthode `demo`) ; `adm` crée `demo` —
    /// 409, la cause nommée, aucune ligne, aucune création attestée ; l'anonyme est TOUJOURS servi `demo` (la
    /// démonstration n'est pas cassée). Démonstration INACTIVE : `demo` est refusé de même (elle s'active au
    /// redémarrage, un compte créé avant lui serait livré). CONTRÔLE POSITIF : `demo-ndrs` se crée (200).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR, ET QUI EST LA FORME D'AVANT : retirer la réservation de `user_create` — 200.
    #[tokio::test]
    async fn ndrs_le_nom_de_la_demonstration_ne_devient_pas_un_compte() {
        let (mut st, _p) = ndrs_etat("ndrs-demonstration");
        st.public_demo = true;
        let banc = ndrs_banc(&st).await;
        let (s, moi) = banc.envoyer("GET", "/api/me", None, "").await;
        assert_eq!(
            (s, moi["user"].as_str(), moi["role"].as_str(), moi["auth_method"].as_str()),
            (200, Some(crate::auth::IDENTITE_DE_LA_DEMONSTRATION), Some("viewer"), Some("demo")),
            "fixture : l'anonyme est servi sous l'identité de la démonstration : {moi}"
        );

        let (statut, corps) = ndrs_creer(&st, crate::auth::IDENTITE_DE_LA_DEMONSTRATION, "editor").await;
        assert_eq!(statut, 409, "le nom de la démonstration ne devient pas un compte : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_NOM_DE_L_IDENTITE_DE_LA_DEMONSTRATION), "{corps}");
        assert_eq!(ndrs_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1", "demo"), 0, "aucune ligne");
        assert_eq!(ndrs_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind=?1", "config.user.create"), 0, "aucune création attestée");
        let (s, moi) = banc.envoyer("GET", "/api/me", None, "").await;
        assert_eq!((s, moi["user"].as_str()), (200, Some("demo")), "la démonstration sert toujours l'anonyme : {moi}");
        banc.arreter().await;

        st.public_demo = false;
        let (statut, corps) = ndrs_creer(&st, "demo", "viewer").await;
        assert_eq!((statut, &corps["error"]), (409, &json!(CAUSE_NOM_DE_L_IDENTITE_DE_LA_DEMONSTRATION)), "démonstration inactive, refusé aussi : {corps}");

        let (statut, corps) = ndrs_creer(&st, "demo-ndrs", "viewer").await;
        assert_eq!(statut, 200, "CONTRÔLE POSITIF : un nom voisin se crée : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.25-h` — LES NOMS DE JETONS NE SONT PAS RÉSERVÉS, ET RIEN NE PASSE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT (la décision de NE PAS réserver) : un jeton de source de données `grafana-ndrs` (`editor`) et un
    /// jeton d'agent `ag-ndrs` lié à l'hôte `h-ndrs`. Trois comptes locaux à ces trois noms se créent (200). Le compte
    /// `grafana-ndrs` pose une requête privée ; le jeton du même nom ne la voit pas (401 sur les requêtes enregistrées :
    /// il ne s'authentifie que sur sa route) et sert toujours sa route (200). Le compte `h-ndrs` n'obtient pas les
    /// ripostes de l'hôte (403 : le rôle `agent` ne vient que du jeton) ; le jeton d'agent les obtient toujours (200).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : réserver dans `user_create` les noms que porte la table des jetons — 409 sur un
    /// nom qu'aucune identité ne tient au sens de `P10.24-u`.
    #[tokio::test]
    async fn ndrs_un_compte_au_nom_d_un_jeton_ne_lui_prend_ni_ne_lui_cede_rien() {
        let (st, _p) = ndrs_etat("ndrs-jetons");
        let jeton_ds = format!("ndrs-ds-{}", "a".repeat(24));
        let jeton_ag = format!("ndrs-ag-{}", "b".repeat(24));
        {
            let c = st.db.lock();
            c.execute(
                "INSERT INTO token(name,token_hash,created,kind,role) VALUES('grafana-ndrs',?1,1,'datasource','editor')",
                params![sha256_hex(jeton_ds.as_bytes())],
            )
            .expect("fixture : jeton de source de données");
            c.execute(
                "INSERT INTO token(name,token_hash,created,kind,host) VALUES('ag-ndrs',?1,1,'agent','h-ndrs')",
                params![sha256_hex(jeton_ag.as_bytes())],
            )
            .expect("fixture : jeton d'agent");
        }
        let (bearer_ds, bearer_ag) = (format!("Bearer {jeton_ds}"), format!("Bearer {jeton_ag}"));
        let banc = ndrs_banc(&st).await;
        for nom in ["grafana-ndrs", "h-ndrs", "ag-ndrs"] {
            let (statut, corps) = ndrs_creer(&st, nom, "editor").await;
            assert_eq!(statut, 200, "un compte au nom d'une identité de jeton se crée (`{nom}`) : {corps}");
        }
        let du_compte = ndrs_basic("grafana-ndrs", &ndrs_mot("grafana-ndrs"));
        let (s, corps) = banc.envoyer("POST", "/api/saved-queries", Some(&du_compte), r#"{"name":"privee ndrs","soql":"search secret"}"#).await;
        assert_eq!(s, 200, "fixture : le compte pose sa requête privée : {corps}");
        let (s, corps) = banc.envoyer("GET", "/api/saved-queries", Some(&bearer_ds), "").await;
        assert_eq!(s, 401, "le jeton du même nom ne voit pas la requête du compte : {corps}");
        let (s, corps) = banc.envoyer("POST", "/api/ds/query", Some(&bearer_ds), r#"{"soql":"search | stats count"}"#).await;
        assert_eq!(s, 200, "et il sert toujours sa route : {corps}");
        let (s, corps) = banc.envoyer("GET", "/api/actions/pending", Some(&ndrs_basic("h-ndrs", &ndrs_mot("h-ndrs"))), "").await;
        assert_eq!(s, 403, "le compte au nom de l'hôte n'obtient pas ses ripostes : {corps}");
        let (s, corps) = banc.envoyer("GET", "/api/actions/pending", Some(&bearer_ag), "").await;
        assert_eq!(s, 200, "le jeton d'agent les obtient toujours : {corps}");
        banc.arreter().await;
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.25-t` — L'ADMINISTRATEUR DE L'ASSISTANT SANS LIGNE, AUX DEUX PORTES
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `wiz-ndrs`, administrateur de l'assistant, crédence en mémoire, SANS ligne `user`. La fédération
    /// servie (`federer_le_nom`, celle d'OIDC, SAML et LDAP) le refuse : `CompteAMotDePasse`, 409 et le texte d'avant,
    /// aucune ligne posée, et son mot de passe d'installation le connecte toujours en administrateur. Le chemin
    /// d'en-têtes rend la MÊME décision. CONTRÔLE POSITIF : `fed-ndrs`, sans ligne, est pris aux deux portes, et la
    /// fédération pose une ligne SANS mot de passe local.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer de la règle unique la branche de l'administrateur de l'assistant (les
    /// deux portes le prennent) ; faire passer à `federer_le_nom` l'administrateur de configuration seul (la forme
    /// d'avant : la fédération le prend, pose sa ligne, et son mot de passe d'installation ne connecte plus).
    #[tokio::test]
    async fn ndrs_l_administrateur_de_l_assistant_sans_ligne_n_est_pris_par_aucune_porte() {
        let (st, _p) = ndrs_etat("ndrs-assistant");
        let d_installation = ndrs_mot("installation");
        *st.admin.lock() = Some(("wiz-ndrs".into(), hash_pw(&d_installation).expect("hachage")));
        assert_eq!(ndrs_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1", "wiz-ndrs"), 0, "fixture : sans ligne");
        assert_eq!(authenticate(&st, &ndrs_basic("wiz-ndrs", &d_installation)), Some(("wiz-ndrs".into(), "admin".into())), "fixture : il se connecte");

        let federation = federer_le_nom(&st, &st.db.lock(), "wiz-ndrs", "viewer");
        assert_eq!(
            federation,
            Err(RefusDeLaFederation::Nom(RefusDeLAnnuaire::CompteAMotDePasse("wiz-ndrs".into()))),
            "la fédération ne prend pas l'administrateur de l'assistant"
        );
        let (statut, corps) = ndrs_corps(federation.expect_err("refus").reponse()).await;
        assert_eq!(
            (statut, corps),
            (409, json!("le nom d'utilisateur correspond à un compte local existant (fédération refusée)")),
            "même statut et même texte qu'un compte local à mot de passe"
        );
        assert_eq!(ndrs_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1", "wiz-ndrs"), 0, "aucune ligne posée");
        st.auth_cache.lock().clear();
        assert_eq!(
            authenticate(&st, &ndrs_basic("wiz-ndrs", &d_installation)),
            Some(("wiz-ndrs".into(), "admin".into())),
            "son mot de passe d'installation le connecte toujours"
        );
        assert_eq!(
            juger_le_nom_presente_par_l_annuaire(&st, "wiz-ndrs"),
            Err(RefusDeLAnnuaire::CompteAMotDePasse("wiz-ndrs".into())),
            "le chemin d'en-têtes rend la même décision"
        );

        assert_eq!(juger_le_nom_presente_par_l_annuaire(&st, "fed-ndrs"), Ok(()), "CONTRÔLE POSITIF : en-têtes");
        assert_eq!(federer_le_nom(&st, &st.db.lock(), "fed-ndrs", "editor"), Ok(()), "CONTRÔLE POSITIF : fédération");
        let hachage: String = st.db.lock().query_row("SELECT hash FROM user WHERE name='fed-ndrs'", [], |r| r.get(0)).expect("ligne fédérée");
        assert_eq!(hachage, IDP_HASH_SENTINEL, "une ligne SANS mot de passe local");
        assert_eq!(juger_le_nom_presente_par_l_annuaire(&st, "fed-ndrs"), Ok(()), "et les en-têtes la prennent encore");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.25-t` — UN NOM NON VÉRIFIÉ N'EST PRIS PAR AUCUNE PORTE
    // -------------------------------------------------------------------------------------

    fn ndrs_refuser_la_lecture_du_hachage(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "user", column_name: "hash" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn ndrs_lever_l_autorisateur(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// CE QU'IL TIENT : la lecture de `user.hash` refusée sur l'écrivain. L'annuaire présente `bob` (`editor`, mot de
    /// passe local) dans le groupe administrateur : la fédération refuse `NonVerifie`, 503 et sa cause, la ligne de
    /// `bob` n'est pas touchée (`editor`), et son mot de passe le connecte toujours `editor` ; le chemin d'en-têtes rend
    /// la même décision.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR, ET QUI EST LA FORME D'AVANT : dans `idp_provision_user`, avaler l'échec de la
    /// lecture (`.ok()`, lu comme « aucune ligne ») — Ok, `bob` passe `admin` et son mot de passe le connecte `admin`.
    #[tokio::test]
    async fn ndrs_un_nom_non_verifie_n_est_pris_par_aucune_porte() {
        let (st, _p) = ndrs_etat("ndrs-non-verifie");
        ndrs_refuser_la_lecture_du_hachage(&st);
        let federation = federer_le_nom(&st, &st.db.lock(), "bob", "admin");
        let en_tetes = juger_le_nom_presente_par_l_annuaire(&st, "bob");
        ndrs_lever_l_autorisateur(&st);
        assert!(
            matches!(&federation, Err(RefusDeLaFederation::Nom(RefusDeLAnnuaire::NonVerifie(nom, _))) if nom == "bob"),
            "la fédération ne prend pas un nom qu'elle n'a pas pu vérifier : {federation:?}"
        );
        assert!(matches!(&en_tetes, Err(RefusDeLAnnuaire::NonVerifie(nom, _)) if nom == "bob"), "les en-têtes non plus : {en_tetes:?}");
        let (statut, corps) = ndrs_corps(federation.expect_err("refus").reponse()).await;
        assert_eq!((statut, &corps["error"]), (503, &json!(CAUSE_FEDERATION_NOM_NON_VERIFIE)), "{corps}");
        assert_eq!(
            st.db.lock().query_row("SELECT role FROM user WHERE name='bob'", [], |r| r.get::<_, String>(0)).expect("ligne de bob"),
            "editor",
            "la ligne de `bob` n'est pas touchée"
        );
        st.auth_cache.lock().clear();
        assert_eq!(
            authenticate(&st, &ndrs_basic("bob", NDRS_MOT_DE_PASSE_DE_FIXTURE)),
            Some(("bob".into(), "editor".into())),
            "son mot de passe le connecte toujours `editor`"
        );
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.25-t` — LES TROIS FÉDÉRATIONS SERVIES PASSENT PAR LA RÈGLE UNIQUE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par la lecture du source (les portes OIDC, SAML et LDAP ne se jouent pas sans fournisseur) : les
    /// trois fédérations de `handlers/idp.rs` appellent `federer_le_nom`, et plus aucune n'appelle `idp_provision_user`
    /// directement ; `federer_le_nom` lit les DEUX noms tenus hors de la table (`NomsTenusHorsDeLaTable::de`).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : une porte qui rappelle `idp_provision_user` avec un seul des deux noms.
    #[test]
    fn ndrs_les_trois_federations_servies_passent_par_la_regle_unique() {
        let portes = include_str!("../handlers/idp.rs");
        assert_eq!(portes.matches("federer_le_nom(&st, &conn, ").count(), 3, "OIDC, SAML et LDAP appellent `federer_le_nom`");
        assert_eq!(portes.matches("idp_provision_user(").count(), 0, "aucune porte n'appelle plus `idp_provision_user` directement");
        let oidc = include_str!("../idp/oidc.rs");
        let debut = oidc.find("pub(crate) fn federer_le_nom(").expect("`federer_le_nom` repérable");
        let corps = &oidc[debut..debut + oidc[debut..].find("\n}").expect("fin de `federer_le_nom`")];
        assert!(corps.contains("NomsTenusHorsDeLaTable::de(st)"), "`federer_le_nom` lit les deux noms sur l'état du démon : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.28-e` — UN SEMIS DE TABLEAU DE BORD EST ENTIER OU N'EST PAS
    // -------------------------------------------------------------------------------------

    fn ndrs_refuser_l_insertion_dans(st: &AppState, table: &'static str) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } if table_name == table => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// (tableaux de ce nom, leurs panneaux, drapeau posé).
    fn ndrs_etat_du_semis(st: &AppState, nom: &str, drapeau: &str) -> (i64, i64, i64) {
        let c = st.db.lock();
        let tableaux: i64 = c.query_row("SELECT COUNT(*) FROM dashboard WHERE name=?1", params![nom], |r| r.get(0)).expect("tableaux");
        let panneaux: i64 = c
            .query_row("SELECT COUNT(*) FROM panel WHERE dashboard_id IN (SELECT id FROM dashboard WHERE name=?1)", params![nom], |r| r.get(0))
            .expect("panneaux");
        let pose: i64 = c.query_row("SELECT COUNT(*) FROM meta WHERE key=?1", params![drapeau], |r| r.get(0)).expect("drapeau");
        (tableaux, panneaux, pose)
    }

    /// CE QU'IL TIENT, pour les quatre tableaux de bord semés sous un drapeau (vue d'ensemble, infra & logs, sécurité,
    /// réseau sortant) et les trois écritures qui peuvent être refusées (le tableau, un panneau, le drapeau) : après le
    /// refus, RIEN — ni tableau, ni panneau, ni drapeau — et la transaction de l'écrivain est fermée ; au démarrage
    /// suivant (refus levé), le tableau ENTIER et son drapeau ; au démarrage d'après, rien de plus (pas de doublon).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : poser le drapeau hors de la transaction et avant le semis (la forme d'avant :
    /// tableau refusé -> drapeau posé, jamais rejoué) ; semer sans transaction (panneau refusé -> tableau vide laissé).
    #[test]
    fn ndrs_un_semis_de_tableau_de_bord_refuse_se_rejoue_entier() {
        let semis: [(&str, &str, i64, fn(&Connection)); 4] = [
            ("SOC — Vue d'ensemble", "seeded_default", 7, seed_default_dashboard),
            ("Infra & logs (OBS)", "seeded_obs", 6, seed_obs_dashboard),
            ("Sécurité & détection", "seeded_security", 6, seed_security_dashboard),
            ("Réseau sortant (egress)", "seeded_egress", 4, seed_egress_dashboard),
        ];
        let mut joues = 0;
        for refusee in ["dashboard", "panel", "meta"] {
            for (nom, drapeau, panneaux, semer) in semis {
                let (st, _p) = sp_state("ndrs-semis");
                ndrs_refuser_l_insertion_dans(&st, refusee);
                semer(&st.db.lock());
                ndrs_lever_l_autorisateur(&st);
                assert_eq!(ndrs_etat_du_semis(&st, nom, drapeau), (0, 0, 0), "`{nom}`, `{refusee}` refusé : rien n'est conservé");
                assert!(st.db.lock().is_autocommit(), "`{nom}`, `{refusee}` refusé : la transaction du semis est fermée");
                semer(&st.db.lock());
                assert_eq!(ndrs_etat_du_semis(&st, nom, drapeau), (1, panneaux, 1), "`{nom}` : au démarrage suivant, le semis entier");
                semer(&st.db.lock());
                assert_eq!(ndrs_etat_du_semis(&st, nom, drapeau), (1, panneaux, 1), "`{nom}` : et rien de plus ensuite");
                joues += 1;
            }
        }
        assert_eq!(joues, 12, "les douze cas sont joués");
    }

    // -------------------------------------------------------------------------------------
    // (7) `P10.28-g` — CE QU'UNE INSERTION QUI PEUT NE RIEN INSÉRER LAISSE DANS `last_insert_rowid()`
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, sur le SQLite que le démon embarque : après une insertion dans une AUTRE table, `INSERT OR IGNORE`
    /// ignoré et `ON CONFLICT DO NOTHING` rendent 0 ligne et laissent l'identifiant de l'autre table ; `ON CONFLICT DO
    /// UPDATE` qui met à jour rend UNE ligne et laisse AUSSI l'identifiant de l'autre table — un compte `Ok(1)` ne
    /// l'en distingue pas ; `INSERT OR REPLACE` rend l'identifiant de la ligne écrite. C'est la règle que
    /// `check_an_inserted_id_is_read_at_the_foot_of_its_insert.py` applique : `OR IGNORE` et `DO NOTHING` sous un bras
    /// `Ok(1)` seulement, `DO UPDATE` jamais. Un témoin de fait, pas de site : aucun site de `daemon/src` n'a cette forme.
    #[test]
    fn ndrs_une_insertion_qui_peut_ne_rien_inserer_laisse_l_identifiant_d_une_autre_ligne() {
        let c = Connection::open_in_memory().expect("base en mémoire");
        c.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY, k TEXT UNIQUE, v TEXT); CREATE TABLE autre(id INTEGER PRIMARY KEY, x);")
            .expect("tables");
        c.execute("INSERT INTO t(k,v) VALUES('a','1')", []).expect("ligne de t");
        let id_de_t: i64 = c.last_insert_rowid();
        let autre = || {
            c.execute("INSERT INTO autre(x) VALUES(1)", []).expect("ligne d'une autre table");
            c.last_insert_rowid()
        };
        for _ in 0..4 {
            autre();
        }
        let id_d_autre = autre();
        assert_ne!(id_d_autre, id_de_t, "fixture : les deux identifiants diffèrent");
        let n = c.execute("INSERT OR IGNORE INTO t(k,v) VALUES('a','2')", []).expect("OR IGNORE");
        assert_eq!((n, c.last_insert_rowid()), (0, id_d_autre), "OR IGNORE ignoré : 0 ligne, l'identifiant de l'autre table");
        let id_d_autre = autre();
        let n = c.execute("INSERT INTO t(k,v) VALUES('a','3') ON CONFLICT(k) DO NOTHING", []).expect("DO NOTHING");
        assert_eq!((n, c.last_insert_rowid()), (0, id_d_autre), "DO NOTHING : 0 ligne, l'identifiant de l'autre table");
        let id_d_autre = autre();
        let n = c.execute("INSERT INTO t(k,v) VALUES('a','4') ON CONFLICT(k) DO UPDATE SET v=excluded.v", []).expect("DO UPDATE");
        assert_eq!(
            (n, c.last_insert_rowid()),
            (1, id_d_autre),
            "DO UPDATE qui met à jour : UNE ligne, et l'identifiant de l'autre table — `Ok(1)` ne protège pas"
        );
        assert_eq!(c.query_row("SELECT id FROM t WHERE k='a'", [], |r| r.get::<_, i64>(0)).expect("ligne"), id_de_t, "la ligne mise à jour garde le sien");
        autre();
        let n = c.execute("INSERT OR REPLACE INTO t(k,v) VALUES('a','5')", []).expect("OR REPLACE");
        let ecrite: i64 = c.query_row("SELECT id FROM t WHERE k='a'", [], |r| r.get(0)).expect("ligne remplacée");
        assert_eq!((n, c.last_insert_rowid()), (1, ecrite), "OR REPLACE : l'identifiant de la ligne écrite");
    }
}
