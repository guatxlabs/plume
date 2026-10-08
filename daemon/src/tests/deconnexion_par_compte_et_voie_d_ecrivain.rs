// =====================================================================================
// `P10.23-o` — LA DÉCONNEXION RÉVOQUE LE SEUL COMPTE DU JETON ; LA RÉVOCATION GLOBALE EST UN GESTE D'ADMIN, TRACÉ.
// `P10.24-d` — LA VOIE D'ÉCRIVAIN DE LA RÉSOLUTION D'UNE SESSION JOUE LE MÊME ÉNONCÉ QUE LE READ POOL.
//
// MESURÉ AVANT CORRECTIF (forme d'avant, ces témoins joués dessus) :
//  * `P10.23-o` : la déconnexion de `bob` (cookie valide) avançait l'époque GLOBALE — la session d'`alice`, étrangère
//    au geste, était refusée ; aucun paramètre ne distinguait « me déconnecter » de « déconnecter tout le monde ».
//  * `P10.24-d` : la voie d'écrivain (`eng-cred-*`, read pool indisponible) lisait le rôle par `lookup_basic_ident`
//    (qui SELECTe `user.hash`) puis l'époque par une SECONDE requête : `user.hash` refusé sur l'écrivain, la session
//    valide d'un compte `eng-cred-*` ne résolvait plus aucune identité.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : en mode multi-tenant, l'admin y est jugé sur le rôle du jeton (plancher), à
// l'époque de son compte depuis `P10.31-i` (tenus : la déconnexion par compte et le refus de la portée globale à un
// non-admin, témoins (8) ; le reste du mode 1 dans `deconnexion_du_mode_un_par_compte.rs`) ; la révocation globale
// par un admin SSO ou Basic (sans `plume_session`, il reçoit le `403`) et l'interface (aucun écran ne pose l'en-tête
// de portée) ; le budget par adresse du `rate_limit` (non traversé par un appel direct). L'échec de persistance de
// l'époque globale : tenu par `epoque_globale_lue_et_persistee.rs` (`P10.20-b`). Le nombre de lectures de `meta.value` sur l'écrivain
// est compté pour un `eng-cred-*` (témoin (7)), pas pour le repli d'un pool indisponible.
// =====================================================================================
mod deconnexion_par_compte_et_voie_d_ecrivain {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::Ordering;

    const DPC_COMPTE_D_ENGAGEMENT: &str = "eng-cred-dpc000000001";

    /// `adm` administrateur de l'assistant (et ligne `admin` de `user`), `alice` et `bob` éditeurs.
    fn dpc_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(&format!("dpc-{tag}"));
        let h: String = st.db.lock().query_row("SELECT hash FROM user WHERE name='adm'", [], |r| r.get(0)).expect("fixture");
        *st.admin.lock() = Some(("adm".into(), h));
        (st, p)
    }

    fn dpc_session(st: &AppState, user: &str, role: &str) -> String {
        frapper_la_session_du_compte(st, user, role).unwrap_or_else(|_| panic!("fixture : session de {user} frappée"))
    }

    fn dpc_identite(st: &AppState, jeton: &str) -> Option<(String, String)> {
        let req = Request::builder()
            .uri("/api/me")
            .header(header::COOKIE, format!("plume_session={jeton}"))
            .body(axum::body::Body::empty())
            .expect("requête");
        resolve_identity(st, &req).0
    }

    fn dpc_epoque_globale(st: &AppState) -> i64 {
        st.session_epoch.load(Ordering::SeqCst)
    }

    fn dpc_epoque_du_compte(st: &AppState, user: &str) -> i64 {
        epoque_du_compte(&st.db.lock(), user).expect("fixture : l'époque du compte se lit")
    }

    fn dpc_traces_globales(st: &AppState) -> i64 {
        st.db
            .lock()
            .query_row("SELECT COUNT(*) FROM ledger WHERE kind='auth.deconnexion.globale'", [], |r| r.get(0))
            .expect("fixture : le registre se lit")
    }

    /// La déconnexion telle que le navigateur la joue : `(statut, cookies effacés, corps)`.
    async fn dpc_deconnexion(st: &AppState, jeton: Option<&str>, portee: Option<&str>) -> (u16, bool, Value) {
        let mut en_tetes = axum::http::HeaderMap::new();
        if let Some(j) = jeton {
            en_tetes.insert(header::COOKIE, format!("plume_session={j}").parse().expect("en-tête"));
        }
        if let Some(p) = portee {
            en_tetes.insert(PORTEE_DE_LA_DECONNEXION, p.parse().expect("en-tête"));
        }
        let r = logout_post(State(st.clone()), en_tetes).await;
        let statut = r.status().as_u16();
        let efface = r
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.starts_with("plume_session=;") && v.contains("Max-Age=0"));
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, efface, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.23-o` — LA DÉCONNEXION ORDINAIRE RÉVOQUE LE SEUL COMPTE DU JETON
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `bob` se déconnecte (cookie valide, aucun en-tête de portée) -> 200, cookies effacés, portée
    /// `compte` ; l'époque GLOBALE ne bouge pas, celle de `bob` avance d'une unité ; une COPIE du cookie de `bob` ne
    /// résout plus rien ; la session d'`alice` et celle de l'admin valent toujours. `compte` explicite fait pareil.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : mutant « deconnexion_globale » (la déconnexion ordinaire avance l'époque
    /// globale, la forme d'avant) — la session d'`alice` est refusée.
    #[tokio::test]
    async fn dpc_la_deconnexion_revoque_le_seul_compte_du_jeton() {
        let (st, _p) = dpc_etat("par-compte");
        let session_de_bob = dpc_session(&st, "bob", "editor");
        let copie_exfiltree = session_de_bob.clone();
        let session_d_alice = dpc_session(&st, "alice", "editor");
        let session_d_adm = dpc_session(&st, "adm", "admin");
        let globale = dpc_epoque_globale(&st);

        let (statut, efface, corps) = dpc_deconnexion(&st, Some(&session_de_bob), None).await;
        assert_eq!((statut, efface), (200, true), "{corps}");
        assert_eq!(corps["portee"], json!("compte"), "{corps}");
        assert_eq!(dpc_epoque_globale(&st), globale, "l'époque globale ne bouge pas");
        assert_eq!(dpc_epoque_du_compte(&st, "bob"), 1, "l'époque de bob avance");
        assert_eq!(dpc_identite(&st, &copie_exfiltree), None, "la copie du cookie de bob ne vaut plus rien");
        assert_eq!(dpc_identite(&st, &session_d_alice), Some(("alice".into(), "editor".into())), "alice reste connectée");
        assert_eq!(dpc_identite(&st, &session_d_adm), Some(("adm".into(), "admin".into())), "l'admin reste connecté");
        assert_eq!(dpc_epoque_du_compte(&st, "alice"), 0, "aucun autre compte n'est révoqué");

        let (statut, _, corps) = dpc_deconnexion(&st, Some(&session_d_alice), Some("compte")).await;
        assert_eq!((statut, corps["portee"].clone()), (200, json!("compte")), "{corps}");
        assert_eq!(dpc_epoque_globale(&st), globale, "la portée `compte` explicite non plus");
        assert_eq!(dpc_identite(&st, &session_d_adm), Some(("adm".into(), "admin".into())), "l'admin reste connecté");
        assert_eq!(dpc_traces_globales(&st), 0, "aucune révocation globale tracée");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.23-o` — LA GARDE ANTI-DoS TIENT : SANS COOKIE VALIDE, RIEN N'EST AVANCÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sans cookie, avec un cookie forgé, ou avec le cookie DÉJÀ révoqué de `bob`, la déconnexion
    /// efface les cookies (200, portée `aucune`) et n'avance AUCUNE époque — ni globale, ni celle d'un compte : un tiers
    /// qui martèle la route publique ne révoque personne et n'écrit rien. CONTRÔLE POSITIF : le cookie courant avance.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : mutant « compte_sans_garde » (signature seule, sans l'époque du compte —
    /// l'époque de `bob` grimpe à chaque rejeu de son cookie révoqué).
    #[tokio::test]
    async fn dpc_sans_cookie_valide_rien_n_est_avance() {
        let (st, _p) = dpc_etat("anti-dos");
        let ancien = dpc_session(&st, "bob", "editor");
        assert_eq!(dpc_deconnexion(&st, Some(&ancien), None).await.0, 200, "fixture : bob se déconnecte");
        assert_eq!(dpc_epoque_du_compte(&st, "bob"), 1, "fixture");
        let globale = dpc_epoque_globale(&st);
        let forge = mint_session(b"pas-le-secret-du-serveur-0123456789", "bob", "editor", 3600, globale);

        for (nom, jeton) in [("sans cookie", None), ("cookie forgé", Some(forge.as_str())), ("cookie révoqué", Some(ancien.as_str()))] {
            for portee in [None, Some("compte")] {
                let (statut, efface, corps) = dpc_deconnexion(&st, jeton, portee).await;
                assert_eq!((statut, efface), (200, true), "{nom} : les cookies sont effacés : {corps}");
                assert_eq!(corps["portee"], json!("aucune"), "{nom} : {corps}");
            }
            assert_eq!(dpc_epoque_du_compte(&st, "bob"), 1, "{nom} : l'époque de bob ne grimpe pas");
            assert_eq!(dpc_epoque_globale(&st), globale, "{nom} : l'époque globale ne bouge pas");
        }

        let courant = dpc_session(&st, "bob", "editor");
        assert_eq!(dpc_deconnexion(&st, Some(&courant), None).await.0, 200);
        assert_eq!(dpc_epoque_du_compte(&st, "bob"), 2, "le cookie courant avance l'époque de bob");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.23-o` — LA RÉVOCATION GLOBALE EST RÉSERVÉE À UN ADMIN (RÔLE LIVE), REFUS NOMMÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la portée `globale` demandée par `alice` (éditrice), sans cookie, ou par `bob` dont le jeton
    /// DIT `admin` alors que son rôle courant est `editor` (admin rétrogradé) rend `403` NOMMÉ, n'efface aucun cookie,
    /// n'avance aucune époque, n'écrit rien au registre ; la session d'`alice` vaut toujours. Une portée inconnue rend
    /// `400` nommé, sans effet. La COPIE du cookie d'`adm`, présentée après sa déconnexion, rend le même `403` :
    /// l'époque du compte est jugée.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : mutant « globale_sans_role » (toute session valide révoque tout le monde) ;
    /// mutant « globale_sans_epoque_du_compte » (rôle relu par `live_role_for`, sans juger l'époque du compte — la
    /// copie révoquée du cookie admin révoque tout le monde).
    #[tokio::test]
    async fn dpc_la_revocation_globale_est_reservee_a_un_admin() {
        let (st, _p) = dpc_etat("globale-refusee");
        let session_d_alice = dpc_session(&st, "alice", "editor");
        let globale = dpc_epoque_globale(&st);
        let epoch = dpc_epoque_globale(&st);
        let jeton_qui_ment = mint_session_du_compte(st.session_secret.as_slice(), "bob", "admin", 3600, epoch, 0);
        assert_eq!(dpc_identite(&st, &jeton_qui_ment), Some(("bob".into(), "editor".into())), "fixture : rôle LIVE editor");

        for (nom, jeton) in [("éditrice", Some(session_d_alice.as_str())), ("sans cookie", None), ("jeton qui dit admin", Some(jeton_qui_ment.as_str()))] {
            let (statut, efface, corps) = dpc_deconnexion(&st, jeton, Some("globale")).await;
            assert_eq!((statut, efface), (403, false), "{nom} : {corps}");
            assert_eq!(corps["error"], json!(CAUSE_DECONNEXION_GLOBALE_RESERVEE_A_UN_ADMIN), "{nom} : {corps}");
            assert_eq!(dpc_epoque_globale(&st), globale, "{nom} : rien n'est révoqué");
        }
        assert_eq!(dpc_epoque_du_compte(&st, "alice"), 0, "le refus n'est pas une déconnexion d'alice");
        assert_eq!(dpc_epoque_du_compte(&st, "bob"), 0, "ni de bob");
        assert_eq!(dpc_traces_globales(&st), 0, "rien au registre");
        assert!(dpc_identite(&st, &session_d_alice).is_some(), "alice reste connectée");

        // LA COPIE D'UN COOKIE ADMIN DÉJÀ RÉVOQUÉ (l'admin s'est déconnecté) : l'époque DU COMPTE est jugée, pas
        // seulement la signature et le rôle — sinon une copie exfiltrée révoquerait tout le monde au nom de l'admin.
        let session_d_adm = dpc_session(&st, "adm", "admin");
        let copie_d_adm = session_d_adm.clone();
        let (statut, _, corps) = dpc_deconnexion(&st, Some(&session_d_adm), None).await;
        assert_eq!((statut, corps["portee"].clone()), (200, json!("compte")), "fixture : l'admin se déconnecte : {corps}");
        let (statut, efface, corps) = dpc_deconnexion(&st, Some(&copie_d_adm), Some("globale")).await;
        assert_eq!((statut, efface), (403, false), "copie révoquée du cookie admin : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_DECONNEXION_GLOBALE_RESERVEE_A_UN_ADMIN), "{corps}");
        assert_eq!(dpc_epoque_globale(&st), globale, "copie révoquée : rien n'est révoqué");
        assert_eq!(dpc_traces_globales(&st), 0, "copie révoquée : rien au registre");
        assert!(dpc_identite(&st, &session_d_alice).is_some(), "alice reste connectée");

        let (statut, efface, corps) = dpc_deconnexion(&st, Some(&session_d_alice), Some("tous")).await;
        assert_eq!((statut, efface), (400, false), "{corps}");
        assert_eq!(corps["error"], json!(CAUSE_PORTEE_DE_DECONNEXION_INCONNUE), "{corps}");
        assert_eq!((dpc_epoque_globale(&st), dpc_epoque_du_compte(&st, "alice")), (globale, 0), "sans effet");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.23-o` — L'ADMIN RÉVOQUE TOUT LE MONDE, ET LE GESTE EST TRACÉ AVANT
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `adm` demande la portée `globale` -> 200, portée `globale`, cookies effacés ; l'époque
    /// globale avance ; les sessions d'`alice` et de `bob` ne valent plus rien ; UN maillon `auth.deconnexion.globale`
    /// nomme l'administrateur. Le registre illisible (table retirée), le même geste rend `503` nommé et ne révoque
    /// RIEN (la session d'`alice`, refrappée, vaut toujours).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : mutant « globale_sans_bump » (le maillon écrit, l'époque globale non avancée
    /// — un geste tracé qui n'a pas eu lieu).
    #[tokio::test]
    async fn dpc_l_admin_revoque_tout_le_monde_et_le_geste_est_trace() {
        let (st, _p) = dpc_etat("globale-admin");
        let session_d_alice = dpc_session(&st, "alice", "editor");
        let session_de_bob = dpc_session(&st, "bob", "editor");
        let session_d_adm = dpc_session(&st, "adm", "admin");
        let globale = dpc_epoque_globale(&st);

        let (statut, efface, corps) = dpc_deconnexion(&st, Some(&session_d_adm), Some("globale")).await;
        assert_eq!((statut, efface), (200, true), "{corps}");
        assert_eq!(corps["portee"], json!("globale"), "{corps}");
        assert_eq!(dpc_epoque_globale(&st), globale + 1, "l'époque globale avance");
        assert_eq!(dpc_identite(&st, &session_d_alice), None, "alice est déconnectée");
        assert_eq!(dpc_identite(&st, &session_de_bob), None, "bob est déconnecté");
        assert_eq!(dpc_traces_globales(&st), 1, "le geste est tracé");
        let detail: String = st
            .db
            .lock()
            .query_row("SELECT detail FROM ledger WHERE kind='auth.deconnexion.globale'", [], |r| r.get(0))
            .expect("maillon");
        assert!(detail.contains("'adm'"), "le maillon nomme l'administrateur : {detail}");

        // NON TRACÉE, RIEN N'EST RÉVOQUÉ.
        let (st, _p) = dpc_etat("globale-non-tracee");
        let session_d_alice = dpc_session(&st, "alice", "editor");
        let session_d_adm = dpc_session(&st, "adm", "admin");
        let globale = dpc_epoque_globale(&st);
        st.db.lock().execute_batch("DROP TABLE ledger").expect("fixture : registre retiré");
        let (statut, efface, corps) = dpc_deconnexion(&st, Some(&session_d_adm), Some("globale")).await;
        assert_eq!((statut, efface), (503, false), "{corps}");
        assert_eq!(corps["error"], json!(CAUSE_DECONNEXION_GLOBALE_NON_TRACEE), "{corps}");
        assert_eq!(dpc_epoque_globale(&st), globale, "rien n'est révoqué sans trace");
        assert!(dpc_identite(&st, &session_d_alice).is_some(), "alice reste connectée");
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.24-d` — LA VOIE D'ÉCRIVAIN NE LIT PLUS `user.hash` ET JUGE L'ÉPOQUE DU COMPTE
    // -------------------------------------------------------------------------------------

    fn dpc_compte_d_engagement(st: &AppState) {
        let c = st.db.lock();
        c.execute(
            "INSERT INTO user(name,hash,role) VALUES(?1,?2,'viewer')",
            params![DPC_COMPTE_D_ENGAGEMENT, hash_pw("motdepasse12345").expect("hash")],
        )
        .expect("fixture : compte d'engagement");
        c.execute(
            "INSERT INTO engagement(id,window_start,window_end,status) VALUES('dpc-eng',?1,?2,'active')",
            params![now() - 60, now() + 3600],
        )
        .expect("fixture : engagement");
        c.execute(
            "INSERT INTO engagement_grant(engagement_id,kind,ref,status) VALUES('dpc-eng','scoped_cred',?1,'issued')",
            params![DPC_COMPTE_D_ENGAGEMENT],
        )
        .expect("fixture : grant");
    }

    fn dpc_refuser_le_hash_sur_l_ecrivain(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "user" && column_name == "hash" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn dpc_rendre_l_ecrivain(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// CE QU'IL TIENT : la session d'un compte `eng-cred-*` (voie d'écrivain par construction) résout son identité
    /// alors que `user.hash` est REFUSÉ sur l'écrivain ; idem pour `alice` quand le read pool est indisponible
    /// (chemin de base absent) — la voie d'écrivain joue `ROLE_ET_EPOQUE_DU_COMPTE`, comme le read pool. L'époque y est
    /// JUGÉE : avancée, la session ne vaut plus rien ; illisible, rien n'est rendu ; hors fenêtre, le compte
    /// d'engagement ne vaut plus rien.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : mutant « ecrivain_relit_a_part » (la forme d'avant : `lookup_basic_ident`
    /// puis une seconde requête — `user.hash` refusé, aucune identité) ; mutant « ecrivain_epoque_zero » (l'époque
    /// de la voie d'écrivain lue comme zéro — la session révoquée vaut encore) ; mutant « ecrivain_illisible_zero »
    /// (une époque ILLISIBLE lue comme zéro sur la voie d'écrivain — le jeton d'époque zéro vaut).
    #[tokio::test]
    async fn dpc_la_voie_d_ecrivain_ne_lit_pas_le_hash_et_juge_l_epoque() {
        let (st, _p) = dpc_etat("ecrivain");
        dpc_compte_d_engagement(&st);
        let session = dpc_session(&st, DPC_COMPTE_D_ENGAGEMENT, "viewer");
        let epoch = dpc_epoque_globale(&st);

        dpc_refuser_le_hash_sur_l_ecrivain(&st);
        let eng = live_role_si_l_epoque_du_compte_vaut(&st, DPC_COMPTE_D_ENGAGEMENT, 0);
        let mut pool_absent = st.clone();
        pool_absent.db_path = Arc::new(format!("{}-pool-absent", st.db_path));
        let alice = live_role_si_l_epoque_du_compte_vaut(&pool_absent, "alice", 0);
        dpc_rendre_l_ecrivain(&st);
        assert_eq!(eng.as_deref(), Some("viewer"), "eng-cred : la voie d'écrivain ne lit pas user.hash");
        assert_eq!(alice.as_deref(), Some("editor"), "pool indisponible : la voie d'écrivain ne lit pas user.hash");
        assert!(verify_session_du_compte(st.session_secret.as_slice(), &session, epoch).is_some(), "fixture : jeton valide");
        assert_eq!(dpc_identite(&st, &session), Some((DPC_COMPTE_D_ENGAGEMENT.into(), "viewer".into())), "contrôle positif");

        // L'ÉPOQUE EST JUGÉE SUR LA VOIE D'ÉCRIVAIN.
        assert_eq!(avancer_l_epoque_du_compte(&st.db.lock(), DPC_COMPTE_D_ENGAGEMENT).expect("avancée"), 1);
        assert_eq!(dpc_identite(&st, &session), None, "eng-cred : la session révoquée ne vaut plus rien");
        assert_eq!(avancer_l_epoque_du_compte(&st.db.lock(), "alice").expect("avancée"), 1);
        assert_eq!(live_role_si_l_epoque_du_compte_vaut(&pool_absent, "alice", 0), None, "pool indisponible : révoquée");
        assert_eq!(live_role_si_l_epoque_du_compte_vaut(&pool_absent, "alice", 1).as_deref(), Some("editor"), "à l'époque courante");
        st.db
            .lock()
            .execute("UPDATE meta SET value='abc' WHERE key=?1", params![cle_de_l_epoque_du_compte("alice")])
            .expect("fixture : époque corrompue");
        assert_eq!(live_role_si_l_epoque_du_compte_vaut(&pool_absent, "alice", 1), None, "illisible : rien n'est rendu");
        assert_eq!(
            live_role_si_l_epoque_du_compte_vaut(&pool_absent, "alice", 0),
            None,
            "illisible : un jeton d'époque zéro non plus (l'illisible n'est pas lu comme zéro)"
        );

        // HORS FENÊTRE, LE COMPTE D'ENGAGEMENT NE VAUT PLUS RIEN.
        let neuve = dpc_session(&st, DPC_COMPTE_D_ENGAGEMENT, "viewer");
        assert!(dpc_identite(&st, &neuve).is_some(), "fixture : session neuve dans la fenêtre");
        st.db.lock().execute("UPDATE engagement SET window_end=?1 WHERE id='dpc-eng'", params![now() - 1]).expect("fixture");
        assert_eq!(dpc_identite(&st, &neuve), None, "hors fenêtre : aucune identité");
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.23-o` — LA RÉVOCATION DU COMPTE NON ÉCRITE SE DIT : `503` NOMMÉ, COOKIES EFFACÉS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `bob` se déconnecte (cookie valide) alors que l'écriture de `meta` est refusée sur
    /// l'écrivain : la réponse est `503` NOMMÉE (et non un `200` « compte » qui mentirait), les cookies du navigateur
    /// sont effacés, l'époque de `bob` n'a pas bougé (rien n'est écrit), ni l'époque globale.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : mutant « compte_echec_avale » (l'échec d'`avancer_l_epoque_du_compte` rendu
    /// en `200` portée `compte`).
    #[tokio::test]
    async fn dpc_la_revocation_du_compte_non_ecrite_rend_503_nomme() {
        let (st, _p) = dpc_etat("compte-non-ecrit");
        let session_de_bob = dpc_session(&st, "bob", "editor");
        let globale = dpc_epoque_globale(&st);
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } if table_name == "meta" => Authorization::Deny,
            AuthAction::Update { table_name, .. } if table_name == "meta" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (statut, efface, corps) = dpc_deconnexion(&st, Some(&session_de_bob), None).await;
        dpc_rendre_l_ecrivain(&st);
        assert_eq!((statut, efface), (503, true), "{corps}");
        assert_eq!(corps["error"], json!(CAUSE_REVOCATION_DU_COMPTE_NON_ECRITE), "{corps}");
        assert_eq!(dpc_epoque_du_compte(&st, "bob"), 0, "rien n'est écrit");
        assert_eq!(dpc_epoque_globale(&st), globale, "l'époque globale ne bouge pas");
        assert!(dpc_identite(&st, &session_de_bob).is_some(), "la révocation n'a pas eu lieu, et la réponse l'a dit");
    }

    // -------------------------------------------------------------------------------------
    // (7) `P10.24-d` — LA VOIE D'ÉCRIVAIN LIT L'ÉPOQUE UNE FOIS, ET UN ÉNONCÉ EN ÉCHEC N'Y VAUT PAS « ÉPOQUE ZÉRO »
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la résolution d'un compte `eng-cred-*` (voie d'écrivain par construction) lit `meta.value`
    /// UNE SEULE FOIS sur l'écrivain — l'époque vient de l'énoncé du rôle, aucune seconde requête ne la relit.
    /// CONTRÔLE : le rôle est rendu.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : mutant « ecrivain_seconde_requete » (rôle par l'énoncé partagé, époque relue
    /// par `epoque_du_compte` — deux lectures de `meta.value`).
    #[test]
    fn dpc_la_voie_d_ecrivain_lit_l_epoque_une_seule_fois() {
        let (st, _p) = dpc_etat("une-lecture");
        dpc_compte_d_engagement(&st);
        let lectures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let compteur = lectures.clone();
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| {
            if let AuthAction::Read { table_name, column_name } = ctx.action {
                if table_name == "meta" && column_name == "value" {
                    compteur.fetch_add(1, Ordering::SeqCst);
                }
            }
            Authorization::Allow
        }));
        let role = live_role_si_l_epoque_du_compte_vaut(&st, DPC_COMPTE_D_ENGAGEMENT, 0);
        dpc_rendre_l_ecrivain(&st);
        assert_eq!(role.as_deref(), Some("viewer"), "contrôle : le compte d'engagement est résolu");
        assert_eq!(lectures.load(Ordering::SeqCst), 1, "une seule lecture de l'époque sur l'écrivain");
    }

    /// CE QU'IL TIENT : read pool indisponible ET `meta` illisible sur l'écrivain (l'énoncé échoue) : le jeton
    /// RÉVOQUÉ de l'administrateur de l'assistant (jeton à l'époque 0, compte avancé à 1) reste refusé — l'échec n'est
    /// pas lu comme « compte absent, époque zéro » (qui le rendrait admin). CONTRÔLE : sans le refus, il est déjà
    /// refusé parce que révoqué.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : mutant « lecture_erreur_absente » (`Err(_)` de `lire_le_compte` rendu
    /// `Absent { epoque: Ok(0) }`).
    #[test]
    fn dpc_un_enonce_en_echec_sur_l_ecrivain_ne_vaut_pas_epoque_zero() {
        let (st, _p) = dpc_etat("enonce-en-echec");
        assert_eq!(avancer_l_epoque_du_compte(&st.db.lock(), "adm").expect("avancée"), 1);
        let mut pool_absent = st.clone();
        pool_absent.db_path = Arc::new(format!("{}-pool-absent", st.db_path));
        assert_eq!(live_role_si_l_epoque_du_compte_vaut(&pool_absent, "adm", 0), None, "contrôle : révoqué");
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == "meta" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let role = live_role_si_l_epoque_du_compte_vaut(&pool_absent, "adm", 0);
        dpc_rendre_l_ecrivain(&st);
        assert_eq!(role, None, "époque non lue : le jeton révoqué de l'admin reste refusé");
    }

    // -------------------------------------------------------------------------------------
    // (8) `P10.23-o` / `P10.31-i` — MODE MULTI-TENANT : LA DÉCONNEXION RÉVOQUE LE COMPTE, LA PORTÉE GLOBALE RESTE ADMIN
    // -------------------------------------------------------------------------------------

    fn dpc_mode_1(st: &AppState) -> AppState {
        let mut st1 = st.clone();
        st1.multi_tenant = true;
        st1
    }

    /// CE QU'IL TIENT — CONTRAT CHANGÉ PAR `P10.31-i` (il tenait l'avancée de l'époque GLOBALE, sans trace ni réserve
    /// admin) : en mode 1, la déconnexion d'une session valide de `bob` avance l'époque de SON compte, pas la globale ;
    /// la copie du cookie ne résout plus d'identité en mode 1.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : mutant « F2_deconnexion_mode1_globale » (la forme d'avant : le mode 1 avance
    /// l'époque globale).
    #[tokio::test]
    async fn dpc_mode_1_la_deconnexion_revoque_la_copie_du_cookie() {
        let (st, _p) = dpc_etat("mode-1-compte");
        let st1 = dpc_mode_1(&st);
        let e0 = dpc_epoque_globale(&st1);
        let jeton = mint_session_du_compte(st1.session_secret.as_slice(), "bob", "editor", 3600, e0, 0);
        let (statut, efface, corps) = dpc_deconnexion(&st1, Some(&jeton), None).await;
        assert_eq!((statut, efface), (200, true), "{corps}");
        assert_eq!(corps["portee"], json!("compte"), "{corps}");
        assert_eq!(dpc_epoque_globale(&st1), e0, "mode 1 : l'époque globale ne bouge pas");
        assert_eq!(dpc_epoque_du_compte(&st1, "bob"), 1, "mode 1 : l'époque de bob avance");
        assert_eq!(dpc_identite(&st1, &jeton), None, "mode 1 : la copie du cookie ne résout plus");
    }

    /// CE QU'IL TIENT : en mode 1, la portée `globale` demandée avec un jeton `editor` est refusée (`403`), rien
    /// n'est tracé ni avancé. CONTRÔLE POSITIF : avec un jeton `admin`, `200`, un maillon tracé, l'époque avancée.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : mutant « admin_mode1_sans_role » (le filtre `admin` retiré dans
    /// `admin_de_la_session` en mode 1 — l'éditeur obtient `200` et un maillon qui le nomme administrateur).
    #[tokio::test]
    async fn dpc_mode_1_la_revocation_globale_reste_reservee_a_un_admin() {
        let (st, _p) = dpc_etat("mode-1-globale");
        let st1 = dpc_mode_1(&st);
        let e0 = dpc_epoque_globale(&st1);
        let editeur = mint_session_du_compte(st1.session_secret.as_slice(), "bob", "editor", 3600, e0, 0);
        let (statut, _, corps) = dpc_deconnexion(&st1, Some(&editeur), Some("globale")).await;
        assert_eq!(statut, 403, "{corps}");
        assert_eq!(dpc_traces_globales(&st1), 0, "aucune trace qui nommerait bob administrateur");
        assert_eq!(dpc_epoque_globale(&st1), e0, "rien n'est révoqué");

        let admin = mint_session_du_compte(st1.session_secret.as_slice(), "adm", "admin", 3600, e0, 0);
        let (statut, _, corps) = dpc_deconnexion(&st1, Some(&admin), Some("globale")).await;
        assert_eq!(statut, 200, "contrôle positif : {corps}");
        assert_eq!(dpc_traces_globales(&st1), 1, "contrôle positif : le geste est tracé");
        assert_eq!(dpc_epoque_globale(&st1), e0 + 1, "contrôle positif : l'époque globale avance");
    }
}
