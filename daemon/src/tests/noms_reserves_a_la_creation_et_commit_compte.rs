// =====================================================================================
// `P10.24-u` — UN NOM TENU SANS LIGNE DANS `user` NE DEVIENT PAS UN COMPTE À MOT DE PASSE : ni celui de
//              l'administrateur de configuration, ni celui d'une identité de l'annuaire, ni un nom qui tient encore
//              des objets, une graine ou des préférences. La fédération (`idp_provision_user`) reste la voie d'un nom
//              de l'annuaire vers un compte, sans mot de passe local.
// `P10.24-x` — LE `COMMIT` DES GESTES DE `users_lookups.rs` EST JUGÉ : un refus rend 503 nommé, ferme la transaction,
//              et rien n'est oublié ni annoncé avant.
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF le 2026-09-24 (témoin de mesure joué sur la forme d'avant, puis retiré) :
//  * `P10.24-u`, administrateur de configuration : `root` (graine du second facteur active, requête privée et
//    instantané capturé au rôle `admin` à son nom) ; `adm` crée `root` `viewer` — 200. Son mot de passe de
//    configuration rendait ENCORE 200, rôle `admin`, par le cache d'authentification (la création ne le vide pas),
//    puis 401 une fois le cache vidé : la ligne créée fait autorité. Le nouveau titulaire, par son propre mot de passe,
//    était arrêté au second facteur de `root` ; avec un code de CETTE graine, il recevait une session `viewer` qui
//    listait la requête privée et l'instantané avec son jeton ;
//  * `P10.24-u`, identité de l'annuaire : `carol` (en-têtes SSO, groupe administrateur, consignée à l'inventaire des
//    accès) possède une requête privée, un tableau de bord privé et un instantané `admin` ; `adm` crée `carol`
//    `viewer` — 200. Le compte local se connecte (200), liste la requête et l'instantané, et le jeton sert les données
//    figées (200). Les en-têtes résolvent TOUJOURS `carol` en `admin`, et une requête écrite par le compte local se lit
//    par l'identité de l'annuaire : un nom, deux authentifications. L'énoncé (« graine, frein, objets ») sous-comptait
//    ce partage et surcomptait la graine et le frein pour une identité de l'annuaire, qui n'enrôle pas de second
//    facteur ;
//  * `P10.24-x` : `COMMIT` refusé (autorisateur SQLite), `user_create` rendait 200 et l'identifiant d'un compte qui n'a
//    jamais existé, `user_delete` 204 en ayant oublié les trois échecs de connexion d'un compte toujours là,
//    `user_update` 204, `lookup_upload` 200. Et, ce que l'énoncé ne disait pas : la transaction restait OUVERTE sur la
//    connexion d'écriture partagée, et le geste suivant échouait à `BEGIN IMMEDIATE` (500 « verrou base
//    indisponible »).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le sens inverse — l'annuaire qui présente le nom d'un compte LOCAL (mesuré :
// `bob`, `editor` à mot de passe, résolu `admin` par les en-têtes) ou celui de l'administrateur de configuration, que
// le chemin SSO d'en-têtes ne refuse pas ; les identités de jetons et de démonstration (`demo`), qui n'ont pas de
// ligne non plus et ne sont pas réservées ; une vue de l'annuaire sortie de l'inventaire plafonné sans rien tenir ;
// le mode multi-tenant (la réservation lit la base du tenant, non jouée) ; les autres gestes dont le `COMMIT` est
// ignoré hors de ce fichier (jetons, fournisseurs d'identité, engagements).
// =====================================================================================
mod noms_reserves_a_la_creation_et_commit_compte {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    /// Le mot de passe que `sp_state` pose sur `alice`, `bob` et `adm`.
    const RNCC_MOT_DE_PASSE_DE_FIXTURE: &str = "motdepasse12345";
    const RNCC_GRAINE: &[u8] = b"12345678901234567890";
    const RNCC_SECRET_SSO: &str = "secret-de-bord-rncc";
    const RNCC_ADMIN_DE_CONFIGURATION: &str = "root-rncc";

    /// Un mot de passe recevable (au moins `PASSWORD_MIN_CHARS`), construit — jamais un littéral de clé.
    fn rncc_mot(marque: &str) -> String {
        format!("rncc-{marque}-{}", "m".repeat(PASSWORD_MIN_CHARS))
    }

    /// Statut, jeton de session posé, corps (JSON, ou texte brut en chaîne quand la route rend du texte).
    async fn rncc_corps(r: Response) -> (u16, Option<String>, Value) {
        let statut = r.status().as_u16();
        let session = r
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|v| v.strip_prefix("plume_session=").map(|reste| reste.split(';').next().unwrap_or("").to_string()));
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
        (statut, session, corps)
    }

    fn rncc_pair(ip: &str) -> std::net::SocketAddr {
        format!("{ip}:45454").parse().expect("adresse de test")
    }

    async fn rncc_connexion(st: &AppState, nom: &str, mot: &str, ip: &str) -> (u16, Option<String>, Value) {
        rncc_corps(login_post(State(st.clone()), ConnectInfo(rncc_pair(ip)), Json(json!({ "user": nom, "pass": mot }))).await).await
    }

    async fn rncc_second_facteur(st: &AppState, ticket: &str, code: &str, ip: &str) -> (u16, Option<String>, Value) {
        rncc_corps(login_mfa_post(State(st.clone()), ConnectInfo(rncc_pair(ip)), Json(json!({ "ticket": ticket, "code": code }))).await).await
    }

    async fn rncc_creer(st: &AppState, nom: &str, mot: &str, role: &str) -> (u16, Value) {
        let (s, _, c) = rncc_corps(
            user_create(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({ "name": nom, "password": mot, "role": role }))).await,
        )
        .await;
        (s, c)
    }

    async fn rncc_supprimer(st: &AppState, cible: &str) -> (u16, Value) {
        let id = rncc_compte(st, "SELECT id FROM user WHERE name=?1", cible);
        let (s, _, c) = rncc_corps(user_delete(State(st.clone()), Extension(sp_au("adm", "admin")), axum::extract::Path(id)).await).await;
        (s, c)
    }

    fn rncc_compte(st: &AppState, sql: &str, nom: &str) -> i64 {
        st.db.lock().query_row(sql, params![nom], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn rncc_attestations(st: &AppState, genre: &str) -> i64 {
        rncc_compte(st, "SELECT COUNT(*) FROM ledger WHERE kind=?1", genre)
    }

    fn rncc_transaction_fermee(st: &AppState) -> bool {
        st.db.lock().is_autocommit()
    }

    fn rncc_enroler(st: &AppState, nom: &str) {
        st.db
            .lock()
            .execute(
                "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES(?1,?2,1,'[]',-1,0,0)",
                params![nom, base32_encode(RNCC_GRAINE)],
            )
            .expect("fixture : second facteur actif");
    }

    /// Une requête privée, un tableau de bord privé, un instantané capturé au rôle `admin` — écrits comme les
    /// créateurs de production les écrivent (le nom dans `owner` ou `created_by`).
    fn rncc_objets(st: &AppState, nom: &str, jeton: &str) {
        let c = st.db.lock();
        c.execute("INSERT INTO saved_query(owner,name,soql,created,updated) VALUES(?1,'chasse privee','search x',1,1)", params![nom])
            .expect("fixture : requête");
        c.execute("INSERT INTO dashboard(name,created,owner,visibility) VALUES('tdb prive rncc',1,?1,'private')", params![nom])
            .expect("fixture : tableau de bord");
        let tableau = c.last_insert_rowid();
        c.execute(
            "INSERT INTO dashboard_snapshot(dashboard_id,name,token,data,created,created_by,role_at_capture) VALUES(?1,'capture',?2,'{}',1,?3,'admin')",
            params![tableau, jeton, nom],
        )
        .expect("fixture : instantané");
    }

    fn rncc_requete_sso(nom: &str, groupes: &str) -> Request<axum::body::Body> {
        Request::builder()
            .uri("/api/me")
            .header("x-plume-sso-secret", RNCC_SECRET_SSO)
            .header("x-authentik-username", nom)
            .header("x-authentik-groups", groupes)
            .body(axum::body::Body::empty())
            .expect("requête")
    }

    /// L'annuaire présente `nom` : l'identité est résolue par `resolve_identity` puis consignée par
    /// `consigner_l_acces`, les deux appels que `auth_guard` fait pour chaque requête.
    fn rncc_vu_par_l_annuaire(st: &AppState, nom: &str, groupes: &str) -> (String, String) {
        let (identite, methode, _, _, _) = resolve_identity(st, &rncc_requete_sso(nom, groupes));
        let (resolu, role) = identite.expect("fixture : l'annuaire authentifie");
        assert_eq!((resolu.as_str(), methode), (nom, "sso"), "fixture : identité de l'annuaire");
        crate::acces_observe::consigner_l_acces(st, "default", &resolu, &role, methode);
        assert_eq!(
            rncc_compte(st, "SELECT COUNT(*) FROM acces_observe WHERE nom=?1 AND methode='sso'", nom),
            1,
            "fixture : consignée à l'inventaire des accès"
        );
        (resolu, role)
    }

    fn rncc_refuser_le_commit(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            // `COMMIT` (et `END`) : SQLite le passe à l'autorisateur comme une opération de transaction que rusqlite
            // ne nomme pas ; `BEGIN` et `ROLLBACK` restent permis.
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn rncc_lever_l_autorisateur(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.24-u` — LE NOM DE L'ADMINISTRATEUR DE CONFIGURATION NE DEVIENT PAS UN COMPTE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `root-rncc` est l'administrateur de configuration (aucune ligne `user`, aucun objet : seul le
    /// premier critère joue). Il s'est connecté. `adm` crée `root-rncc` : 409, la cause nommée, aucune ligne, aucune
    /// création attestée. Le cache d'authentification vidé, son mot de passe de configuration le connecte toujours en
    /// administrateur — il n'est pas masqué. La fédération de ce nom reste refusée (même réservation). CONTRÔLE
    /// POSITIF : un nom voisin se crée (200).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR, ET QUI EST LA FORME D'AVANT : retirer la réservation de `user_create` — 200, puis
    /// le mot de passe de configuration rend 401.
    #[tokio::test]
    async fn rncc_le_nom_de_l_administrateur_de_configuration_ne_devient_pas_un_compte() {
        let (mut st, _p) = sp_state("rncc-configuration");
        let de_configuration = rncc_mot("configuration");
        st.user = Arc::new(RNCC_ADMIN_DE_CONFIGURATION.into());
        st.pass_hash = Arc::new(hash_pw(&de_configuration).expect("hachage"));
        let (s, _, c) = rncc_connexion(&st, RNCC_ADMIN_DE_CONFIGURATION, &de_configuration, "10.91.0.1").await;
        assert_eq!((s, c["role"].as_str()), (200, Some("admin")), "fixture : l'administrateur de configuration se connecte : {c}");

        let (statut, corps) = rncc_creer(&st, RNCC_ADMIN_DE_CONFIGURATION, &rncc_mot("usurpe"), "viewer").await;
        assert_eq!(statut, 409, "le nom de l'administrateur de configuration ne devient pas un compte : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_NOM_DE_L_ADMINISTRATEUR_DE_CONFIGURATION), "{corps}");
        assert_eq!(rncc_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1", RNCC_ADMIN_DE_CONFIGURATION), 0, "aucune ligne");
        assert_eq!(rncc_attestations(&st, "config.user.create"), 0, "aucune création attestée");

        st.auth_cache.lock().clear();
        let (s, session, c) = rncc_connexion(&st, RNCC_ADMIN_DE_CONFIGURATION, &de_configuration, "10.91.0.2").await;
        assert_eq!((s, c["role"].as_str(), session.is_some()), (200, Some("admin"), true), "il n'est pas masqué : {c}");
        let federation = idp_provision_user(
            &st.db.lock(),
            RNCC_ADMIN_DE_CONFIGURATION,
            "viewer",
            crate::handlers::idp::reserved_static_admin(&st),
        );
        assert!(federation.is_err(), "la fédération de ce nom reste refusée : {federation:?}");

        let (statut, corps) = rncc_creer(&st, "root-rncc-bis", &rncc_mot("voisin"), "viewer").await;
        assert_eq!(statut, 200, "CONTRÔLE POSITIF : un nom voisin se crée : {corps}");
        assert_eq!(rncc_attestations(&st, "config.user.create"), 1, "et sa création est attestée");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.24-u` — UN NOM DE L'ANNUAIRE QUI TIENT DES OBJETS NE DEVIENT PAS UN COMPTE LOCAL ; LA FÉDÉRATION, SI
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `carol-rncc-objets`, présentée par l'annuaire en administratrice et consignée, possède une
    /// requête privée, un tableau de bord privé et un instantané `admin`. `adm` la crée comme compte local : 409, la
    /// cause nommée, et le détail dit ce que le nom tient (vu par l'annuaire ; une ligne dans chacune des trois
    /// tables). Rien n'est écrit ; l'annuaire la résout toujours `admin` et elle liste toujours sa requête.
    /// LA VOIE LÉGITIME : la fédération du même nom (`idp_provision_user`, celle d'OIDC, SAML et LDAP) réussit, pose
    /// une ligne SANS mot de passe local (aucun mot de passe ne la connecte) ; ensuite la création locale bute sur
    /// l'unicité, 409 « ce nom de compte existe déjà », comme avant.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR, ET QUI EST LA FORME D'AVANT : retirer la lecture de ce que le nom tient
    /// (`ce_que_le_nom_tient_sans_compte`) de `user_create` — 200.
    #[tokio::test]
    async fn rncc_un_nom_de_l_annuaire_qui_tient_des_objets_ne_devient_pas_un_compte_local() {
        let (mut st, _p) = sp_state("rncc-annuaire-objets");
        st.sso_secret = Arc::new(RNCC_SECRET_SSO.into());
        let nom = "carol-rncc-objets";
        assert_eq!(rncc_vu_par_l_annuaire(&st, nom, "plume-admin").1, "admin", "fixture : administratrice de l'annuaire");
        rncc_objets(&st, nom, &"cd".repeat(32));

        let (statut, corps) = rncc_creer(&st, nom, &rncc_mot("carol"), "viewer").await;
        assert_eq!(statut, 409, "un nom de l'annuaire ne devient pas un compte local : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_NOM_TENU_PAR_UNE_IDENTITE_SANS_COMPTE), "{corps}");
        assert_eq!(
            corps["ce_que_le_nom_tient"],
            json!({ "vu_par_l_annuaire": true, "lignes": { "saved_query": 1, "dashboard_snapshot": 1, "dashboard": 1 } }),
            "le détail dit ce que le nom tient : {corps}"
        );
        assert_eq!(rncc_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1", nom), 0, "aucune ligne");
        assert_eq!(rncc_attestations(&st, "config.user.create"), 0, "aucune création attestée");
        assert!(rncc_transaction_fermee(&st), "la transaction de la création est fermée");
        let (identite, _, _, _, _) = resolve_identity(&st, &rncc_requete_sso(nom, "plume-admin"));
        assert_eq!(identite, Some((nom.to_string(), "admin".to_string())), "l'annuaire la résout toujours");
        let au_sso = AuthUser { method: "sso".into(), ..sp_au(nom, "admin") };
        let (_, _, requetes) = rncc_corps(saved_queries_list(State(st.clone()), Extension(au_sso)).await).await;
        assert_eq!(requetes["queries"].as_array().map(Vec::len), Some(1), "et sa requête est à elle : {requetes}");

        // LA VOIE LÉGITIME : la fédération.
        let federation = idp_provision_user(&st.db.lock(), nom, "editor", crate::handlers::idp::reserved_static_admin(&st));
        assert_eq!(federation, Ok(()), "la fédération du même nom n'est pas touchée");
        let hachage: String = st.db.lock().query_row("SELECT hash FROM user WHERE name=?1", params![nom], |r| r.get(0)).expect("ligne fédérée");
        assert_eq!(hachage, IDP_HASH_SENTINEL, "une ligne SANS mot de passe local");
        let (s, session, _) = rncc_connexion(&st, nom, &rncc_mot("carol"), "10.92.0.1").await;
        assert_eq!((s, session.is_some()), (401, false), "aucun mot de passe ne connecte un compte fédéré");
        let (statut, corps) = rncc_creer(&st, nom, &rncc_mot("carol"), "viewer").await;
        assert_eq!((statut, corps), (409, json!("ce nom de compte existe déjà")), "ensuite, l'unicité, comme avant");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.24-u` — UN NOM DE L'ANNUAIRE EST RÉSERVÉ MÊME SANS OBJET ; UN ANCIEN COMPTE LOCAL SE RECRÉE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `dora-rncc`, vue par l'annuaire en lectrice, ne possède rien : sa création locale est refusée
    /// (409, vu par l'annuaire, aucune ligne) — l'annuaire peut la présenter de nouveau, et le compte local partagerait
    /// son nom. CONTRÔLE POSITIF, L'AUTRE SENS DU CRITÈRE : `ex-local-rncc`, compte LOCAL créé, vu à l'inventaire par
    /// son mot de passe, puis supprimé, se recrée (200) — une vue locale ne réserve pas un nom.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : ignorer la vue par l'annuaire (`vu_par_l_annuaire` forcé à faux) — `dora-rncc`
    /// créée, 200 ; réserver toute vue, quelle que soit la méthode (retirer `AND methode='sso'`) — `ex-local-rncc`
    /// refusée, 409.
    #[tokio::test]
    async fn rncc_un_nom_de_l_annuaire_sans_objet_est_reserve_et_un_ancien_compte_local_se_recree() {
        let (mut st, _p) = sp_state("rncc-annuaire-sans-objet");
        st.sso_secret = Arc::new(RNCC_SECRET_SSO.into());
        rncc_vu_par_l_annuaire(&st, "dora-rncc", "plume-viewer");
        let (statut, corps) = rncc_creer(&st, "dora-rncc", &rncc_mot("dora"), "editor").await;
        assert_eq!(statut, 409, "un nom de l'annuaire est réservé même sans objet : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_NOM_TENU_PAR_UNE_IDENTITE_SANS_COMPTE), "{corps}");
        assert_eq!(corps["ce_que_le_nom_tient"], json!({ "vu_par_l_annuaire": true, "lignes": {} }), "{corps}");
        assert_eq!(rncc_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1", "dora-rncc"), 0, "aucune ligne");

        let ancien = "ex-local-rncc";
        let (statut, corps) = rncc_creer(&st, ancien, &rncc_mot("ancien"), "editor").await;
        assert_eq!(statut, 200, "fixture : compte local créé : {corps}");
        crate::acces_observe::consigner_l_acces(&st, "default", ancien, "editor", "basic");
        assert_eq!(
            rncc_compte(&st, "SELECT COUNT(*) FROM acces_observe WHERE nom=?1 AND provenance='compte local'", ancien),
            1,
            "fixture : vu à l'inventaire comme compte local"
        );
        let (statut, corps) = rncc_supprimer(&st, ancien).await;
        assert_eq!(statut, 204, "fixture : supprimé : {corps}");
        let (statut, corps) = rncc_creer(&st, ancien, &rncc_mot("homonyme"), "viewer").await;
        assert_eq!(statut, 200, "CONTRÔLE POSITIF : un ancien compte local se recrée : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.24-u` — UN NOM QUI TIENT DES LIGNES SANS COMPTE EST RÉSERVÉ, MÊME JAMAIS VU
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `zed-rncc` n'a ni ligne `user` ni vue à l'inventaire — une identité de l'annuaire sortie de
    /// l'inventaire plafonné, un administrateur de configuration retiré, ou un compte supprimé avant que la suppression
    /// n'emporte ses objets — mais tient une graine du second facteur ACTIVE, des préférences et une playlist privée.
    /// Sa création est refusée (409), le détail nomme les trois tables ; rien n'est écrit, les trois lignes sont là.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer `LIGNES_DU_COMPTE_HORS_OBJETS` des colonnes d'autorité — le détail ne
    /// nomme plus que la playlist ; ne plus juger les lignes du tout — 200, et le nouveau `zed-rncc` hériterait de la
    /// graine.
    #[tokio::test]
    async fn rncc_un_nom_qui_tient_des_lignes_sans_compte_est_reserve_meme_jamais_vu() {
        let (st, _p) = sp_state("rncc-lignes-sans-compte");
        let nom = "zed-rncc";
        rncc_enroler(&st, nom);
        {
            let c = st.db.lock();
            c.execute("INSERT INTO user_pref(user,prefs,updated) VALUES(?1,'{\"theme\":\"sombre\"}',1)", params![nom]).expect("fixture : préférences");
            c.execute("INSERT INTO playlist(name,items,owner,visibility,created,updated) VALUES('pl rncc','[]',?1,'private',1,1)", params![nom])
                .expect("fixture : playlist");
        }
        let (statut, corps) = rncc_creer(&st, nom, &rncc_mot("zed"), "admin").await;
        assert_eq!(statut, 409, "un nom qui tient des lignes sans compte est réservé : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_NOM_TENU_PAR_UNE_IDENTITE_SANS_COMPTE), "{corps}");
        assert_eq!(
            corps["ce_que_le_nom_tient"],
            json!({ "vu_par_l_annuaire": false, "lignes": { "playlist": 1, "user_mfa": 1, "user_pref": 1 } }),
            "{corps}"
        );
        assert_eq!(rncc_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1", nom), 0, "aucune ligne");
        assert_eq!(rncc_compte(&st, "SELECT COUNT(*) FROM user_mfa WHERE user=?1 AND enabled=1", nom), 1, "la graine est là, intacte");
        assert_eq!(rncc_attestations(&st, "config.user.create"), 0, "aucune création attestée");
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.24-u` — UN NOM QU'ON N'A PAS PU VÉRIFIER NE DEVIENT PAS UN COMPTE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la lecture de l'inventaire des accès refusée (autorisateur SQLite), la création rend 503, la
    /// cause nommée ; aucune ligne, aucune création attestée, la transaction est fermée. L'autorisateur levé, le même
    /// geste crée le compte (200).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : traiter l'échec de lecture comme « le nom ne tient rien » (le bras `Err`
    /// ramené à celui de `Ok(None)`) — 200 sur un nom non vérifié.
    #[tokio::test]
    async fn rncc_un_nom_non_verifie_ne_devient_pas_un_compte() {
        let (st, _p) = sp_state("rncc-non-verifie");
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == "acces_observe" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (statut, corps) = rncc_creer(&st, "nina-rncc", &rncc_mot("nina"), "editor").await;
        let fermee = rncc_transaction_fermee(&st);
        rncc_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un nom non vérifié ne devient pas un compte : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_NOM_NON_VERIFIE_COMPTE_NON_CREE), "{corps}");
        assert!(fermee, "la transaction est fermée");
        assert_eq!(rncc_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1", "nina-rncc"), 0, "aucune ligne");
        assert_eq!(rncc_attestations(&st, "config.user.create"), 0, "aucune création attestée");

        let (statut, corps) = rncc_creer(&st, "nina-rncc", &rncc_mot("nina"), "editor").await;
        assert_eq!(statut, 200, "l'autorisateur levé, le même geste crée : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.24-x` — UN COMMIT REFUSÉ NE CRÉE, NE SUPPRIME, NE MODIFIE AUCUN COMPTE, ET N'OUBLIE RIEN
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, `COMMIT` refusé par un autorisateur SQLite, geste par geste, puis levé :
    ///  * CRÉATION de `dave` : 503 nommé, transaction fermée, aucune ligne, aucune création attestée ; levé, la
    ///    création suivante réussit (200) — la connexion d'écriture n'est pas restée dans une transaction ;
    ///  * SUPPRESSION de `bob` (trois échecs de connexion depuis une adresse, trois codes faux au second facteur) :
    ///    503 nommé, transaction fermée, `bob` là, sa graine là, son époque à zéro, aucune suppression attestée, et
    ///    la mémoire n'a rien oublié ; levé, 204, et la mémoire oublie ;
    ///  * MODIFICATION d'`alice` (rôle et mot de passe) : 503 nommé, transaction fermée, `alice` `editor`, son époque à
    ///    zéro, son ancien mot de passe la connecte ; levé, 204 et `viewer`.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : ignorer le `COMMIT` de `user_delete` (la forme d'avant) — 204 ; oublier la
    /// mémoire AVANT de juger le `COMMIT` — échecs perdus alors que rien n'est supprimé ; retirer le `ROLLBACK` de
    /// `valider_la_transaction` — transaction restée ouverte ; ignorer le `COMMIT` de `user_create` — 200 ; ignorer
    /// celui de `user_update` — 204.
    #[tokio::test]
    async fn rncc_un_commit_refuse_ne_cree_ne_supprime_ne_modifie_aucun_compte() {
        let (st, _p) = sp_state("rncc-commit-comptes");

        // CRÉATION
        rncc_refuser_le_commit(&st);
        let (statut, corps) = rncc_creer(&st, "dave-rncc", &rncc_mot("dave"), "editor").await;
        let fermee = rncc_transaction_fermee(&st);
        rncc_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne crée aucun compte : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_COMPTE_NON_CREE_COMMIT_REFUSE), "{corps}");
        assert!(fermee, "la transaction de la création est fermée");
        assert_eq!(rncc_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1", "dave-rncc"), 0, "aucune ligne");
        assert_eq!(rncc_attestations(&st, "config.user.create"), 0, "aucune création attestée");
        let (statut, corps) = rncc_creer(&st, "erin-rncc", &rncc_mot("erin"), "editor").await;
        assert_eq!(statut, 200, "levé, la création suivante réussit : {corps}");

        // SUPPRESSION
        rncc_enroler(&st, "bob");
        let x = "10.93.0.1";
        for _ in 0..3 {
            let _ = rncc_connexion(&st, "bob", "pas-le-mot-de-passe", x).await;
        }
        let (_, _, c) = rncc_connexion(&st, "bob", RNCC_MOT_DE_PASSE_DE_FIXTURE, "10.93.0.2").await;
        let ticket = c["ticket"].as_str().unwrap_or("").to_string();
        for _ in 0..3 {
            let _ = rncc_second_facteur(&st, &ticket, "000000", "10.93.0.3").await;
        }
        let echecs = |st: &AppState| st.auth_fails.lock().get(&("bob".to_string(), x.to_string())).map(|f| f.count);
        assert_eq!(echecs(&st), Some(3), "fixture : trois échecs de connexion");
        assert_eq!(crate::handlers::idp::echecs_consecutifs_du_second_facteur(&st, "bob"), 3, "fixture : trois codes faux");
        rncc_refuser_le_commit(&st);
        let (statut, corps) = rncc_supprimer(&st, "bob").await;
        let fermee = rncc_transaction_fermee(&st);
        rncc_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne supprime aucun compte : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_COMPTE_NON_SUPPRIME_COMMIT_REFUSE), "{corps}");
        assert!(fermee, "la transaction de la suppression est fermée");
        assert_eq!(rncc_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1", "bob"), 1, "bob est là");
        assert_eq!(rncc_compte(&st, "SELECT COUNT(*) FROM user_mfa WHERE user=?1", "bob"), 1, "sa graine aussi");
        assert_eq!(epoque_du_compte(&st.db.lock(), "bob").expect("époque lue"), 0, "son époque n'a pas bougé");
        assert_eq!(rncc_attestations(&st, "config.user.delete"), 0, "aucune suppression attestée");
        assert_eq!(echecs(&st), Some(3), "la mémoire n'a pas oublié ses échecs");
        assert_eq!(crate::handlers::idp::echecs_consecutifs_du_second_facteur(&st, "bob"), 3, "ni ses codes faux");
        let (statut, corps) = rncc_supprimer(&st, "bob").await;
        assert_eq!(statut, 204, "levé, la suppression a lieu : {corps}");
        assert_eq!(echecs(&st), None, "et la mémoire oublie");

        // MODIFICATION
        let id_alice = rncc_compte(&st, "SELECT id FROM user WHERE name=?1", "alice");
        let modifier = |st: AppState| async move {
            let r = user_update(
                State(st),
                ConnectInfo(rncc_pair("10.93.0.4")),
                Extension(sp_au("adm", "admin")),
                axum::extract::Path(id_alice),
                Json(json!({ "role": "viewer", "password": rncc_mot("alice-neuf") })),
            )
            .await;
            rncc_corps(r).await
        };
        rncc_refuser_le_commit(&st);
        let (statut, _, corps) = modifier(st.clone()).await;
        let fermee = rncc_transaction_fermee(&st);
        rncc_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne modifie aucun compte : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_COMPTE_NON_MODIFIE_COMMIT_REFUSE), "{corps}");
        assert!(fermee, "la transaction de la modification est fermée");
        assert_eq!(rncc_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1 AND role='editor'", "alice"), 1, "alice est editor");
        assert_eq!(epoque_du_compte(&st.db.lock(), "alice").expect("époque lue"), 0, "ses sessions ne sont pas révoquées");
        let (s, _, c) = rncc_connexion(&st, "alice", RNCC_MOT_DE_PASSE_DE_FIXTURE, "10.93.0.5").await;
        assert_eq!((s, c["role"].as_str()), (200, Some("editor")), "son ancien mot de passe la connecte : {c}");
        let (statut, _, corps) = modifier(st.clone()).await;
        assert_eq!(statut, 204, "levé, la modification a lieu : {corps}");
        assert_eq!(rncc_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1 AND role='viewer'", "alice"), 1, "alice est viewer");
    }

    // -------------------------------------------------------------------------------------
    // (7) `P10.24-x` — UN COMMIT REFUSÉ LAISSE LES TABLES D'ENRICHISSEMENT INTACTES
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `rncc_lk` chargée (une ligne). `COMMIT` refusé : son remplacement rend 503 nommé, sa
    /// suppression aussi, la transaction est fermée à chaque fois, le contenu d'avant est intact et aucune trace n'est
    /// écrite. Levé, la suppression a lieu.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : ignorer le `COMMIT` de `lookup_upload` — 200 ; celui de `lookup_delete` — 200.
    #[tokio::test]
    async fn rncc_un_commit_refuse_laisse_les_tables_d_enrichissement_intactes() {
        let (st, _p) = sp_state("rncc-commit-lookups");
        let charger = |st: AppState, lignes: Value| async move {
            let r = lookup_upload(State(st), Extension(sp_au("adm", "admin")), Json(json!({ "name": "rncc_lk", "key_field": "k", "rows": lignes }))).await;
            rncc_corps(r).await
        };
        let supprimer = |st: AppState| async move {
            rncc_corps(lookup_delete(State(st), Extension(sp_au("adm", "admin")), axum::extract::Path("rncc_lk".to_string())).await).await
        };
        let contenu = |st: &AppState| -> Vec<String> {
            st.db
                .lock()
                .prepare("SELECT \"key\" FROM lookup_kv WHERE name='rncc_lk' ORDER BY \"key\"")
                .and_then(|mut q| q.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>())
                .expect("fixture : lookup_kv se lit")
        };
        let (s, _, c) = charger(st.clone(), json!([{ "k": "avant", "v": 1 }])).await;
        assert_eq!(s, 200, "fixture : chargée : {c}");
        let traces = rncc_attestations(&st, "config.lookup.upload");

        rncc_refuser_le_commit(&st);
        let (statut, _, corps) = charger(st.clone(), json!([{ "k": "apres", "v": 2 }])).await;
        let fermee = rncc_transaction_fermee(&st);
        rncc_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne remplace rien : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_TABLE_D_ENRICHISSEMENT_INCHANGEE), "{corps}");
        assert!(fermee, "la transaction du remplacement est fermée");
        assert_eq!(contenu(&st), vec!["avant".to_string()], "le contenu d'avant est intact");
        assert_eq!(rncc_attestations(&st, "config.lookup.upload"), traces, "aucune trace écrite");

        rncc_refuser_le_commit(&st);
        let (statut, _, corps) = supprimer(st.clone()).await;
        let fermee = rncc_transaction_fermee(&st);
        rncc_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne supprime rien : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_TABLE_D_ENRICHISSEMENT_INCHANGEE), "{corps}");
        assert!(fermee, "la transaction de la suppression est fermée");
        assert_eq!(contenu(&st), vec!["avant".to_string()], "toujours intacte");
        assert_eq!(rncc_attestations(&st, "config.lookup.delete"), 0, "aucune suppression attestée");

        let (statut, _, corps) = supprimer(st.clone()).await;
        assert_eq!(statut, 200, "levé, la suppression a lieu : {corps}");
        assert!(contenu(&st).is_empty(), "et le contenu part");
    }
}
