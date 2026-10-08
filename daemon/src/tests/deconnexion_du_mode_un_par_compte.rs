// =====================================================================================
// `P10.31-i` (volet 1) — EN MODE 1, LA DÉCONNEXION ORDINAIRE RÉVOQUE LE SEUL COMPTE DU JETON, COMME EN MODE 0.
//
// MESURÉ AVANT CORRECTIF (forme d'avant, ces témoins joués dessus) : en mode multi-tenant, `logout_post` appelait
// `bump_session_epoch` pour TOUTE session valide — l'époque GLOBALE, sans trace ni réserve admin : la déconnexion d'un
// simple éditeur révoquait les sessions et les tickets MFA de TOUS les comptes. Cause : le mode 1 frappait l'époque
// du compte à zéro sans la lire (`frapper_la_session_du_compte`), ne la jugeait ni dans la garde de la déconnexion
// (`compte_de_la_session_ouverte`) ni dans la résolution d'identité (`auth::resolve_identity_ou_refus`) — révoquer le
// compte n'y aurait rien révoqué.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la révocation globale par un admin SSO ou Basic sans `plume_session` (403) et
// l'écran console qui poserait l'en-tête de portée (volet 2 de `P10.31-i`, ouvert) ; les gestes qui avancent l'époque
// d'un compte de PLATEFORME en mode 1 (changement de mot de passe d'un `platform_user` : aucun n'avance son époque) ;
// la clé `session_epoch:<nom>` est lue dans la `meta` de `st.db`, comme l'époque globale du mode 1 — un compte de
// plateforme et un compte homonyme d'une base de tenant y partagent la même clé (jamais joué en prod).
// =====================================================================================
mod deconnexion_du_mode_un_par_compte {
    use super::*;
    use std::sync::atomic::Ordering;

    const DMU_MOT_DE_PASSE_DE_FIXTURE: &str = "motdepasse12345";
    const DMU_GRAINE: &[u8] = b"12345678901234567890";

    /// Mode 0 (`st`) et mode 1 (`st1`) sur la MÊME base et la MÊME époque globale (`Arc` partagée) : `adm`
    /// administrateur de l'assistant, `alice` et `bob` éditeurs.
    fn dmu_etats(tag: &str) -> (AppState, AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(&format!("dmu-{tag}"));
        let h: String = st.db.lock().query_row("SELECT hash FROM user WHERE name='adm'", [], |r| r.get(0)).expect("fixture");
        *st.admin.lock() = Some(("adm".into(), h));
        let mut st1 = st.clone();
        st1.multi_tenant = true;
        (st, st1, p)
    }

    fn dmu_session(st: &AppState, user: &str, role: &str) -> String {
        frapper_la_session_du_compte(st, user, role).unwrap_or_else(|_| panic!("fixture : session de {user} frappée"))
    }

    fn dmu_identite(st: &AppState, jeton: &str) -> Option<(String, String)> {
        let req = Request::builder()
            .uri("/api/me")
            .header(header::COOKIE, format!("plume_session={jeton}"))
            .body(axum::body::Body::empty())
            .expect("requête");
        resolve_identity(st, &req).0
    }

    fn dmu_epoque_du_compte(st: &AppState, user: &str) -> i64 {
        epoque_du_compte(&st.db.lock(), user).expect("fixture : l'époque du compte se lit")
    }

    fn dmu_traces_globales(st: &AppState) -> i64 {
        st.db
            .lock()
            .query_row("SELECT COUNT(*) FROM ledger WHERE kind='auth.deconnexion.globale'", [], |r| r.get(0))
            .expect("fixture : le registre se lit")
    }

    async fn dmu_corps(r: Response) -> (u16, bool, Option<String>, Value) {
        let statut = r.status().as_u16();
        let cookies: Vec<String> =
            r.headers().get_all(header::SET_COOKIE).iter().filter_map(|v| v.to_str().ok()).map(str::to_string).collect();
        let efface = cookies.iter().any(|v| v.starts_with("plume_session=;") && v.contains("Max-Age=0"));
        let session = cookies
            .iter()
            .find_map(|v| v.strip_prefix("plume_session=").map(|reste| reste.split(';').next().unwrap_or("").to_string()))
            .filter(|s| !s.is_empty());
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, efface, session, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    async fn dmu_deconnexion(st: &AppState, jeton: &str, portee: Option<&str>) -> (u16, bool, Value) {
        let mut en_tetes = axum::http::HeaderMap::new();
        en_tetes.insert(header::COOKIE, format!("plume_session={jeton}").parse().expect("en-tête"));
        if let Some(p) = portee {
            en_tetes.insert(PORTEE_DE_LA_DECONNEXION, p.parse().expect("en-tête"));
        }
        let (statut, efface, _, corps) = dmu_corps(logout_post(State(st.clone()), en_tetes).await).await;
        (statut, efface, corps)
    }

    fn dmu_pair() -> std::net::SocketAddr {
        "10.65.0.1:45454".parse().expect("adresse de test")
    }

    /// CE QU'IL TIENT : mode 1, `bob` se déconnecte (cookie valide, aucun en-tête) -> 200, portée `compte`, cookies
    /// effacés ; l'époque GLOBALE ne bouge pas (mémoire et `meta`), celle de `bob` avance d'une unité, rien n'est
    /// tracé ; la COPIE du cookie de `bob` ne résout plus d'identité en mode 1 ; la session d'`alice` résout encore ;
    /// le ticket MFA d'`adm` (un tiers, émis avant) ouvre encore sa session avec un code juste.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : mutant « F2_deconnexion_mode1_globale » (la branche d'avant : le mode 1
    /// avance l'époque globale — alice et le ticket tombent) ; mutant « F2_identite_mode1_sans_epoque » (la résolution
    /// du mode 1 ne juge plus l'époque du compte — la copie du cookie de bob vaut encore).
    #[tokio::test]
    async fn dmu_mode_1_la_deconnexion_de_bob_ne_revoque_que_bob() {
        let (st, st1, _p) = dmu_etats("par-compte");
        let graine = base32_encode(DMU_GRAINE);
        st.db
            .lock()
            .execute(
                "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES('adm',?1,1,'[]',-1,0,0)",
                params![graine],
            )
            .expect("fixture : MFA d'adm");
        let (statut, _, _, corps) = dmu_corps(
            login_post(State(st.clone()), ConnectInfo(dmu_pair()), Json(json!({ "user": "adm", "pass": DMU_MOT_DE_PASSE_DE_FIXTURE }))).await,
        )
        .await;
        let ticket_d_adm = corps["ticket"].as_str().unwrap_or("").to_string();
        assert_eq!((statut, ticket_d_adm.is_empty()), (200, false), "fixture : le mot de passe d'adm rend un ticket : {corps}");

        let session_de_bob = dmu_session(&st1, "bob", "editor");
        let copie_exfiltree = session_de_bob.clone();
        let session_d_alice = dmu_session(&st1, "alice", "editor");
        assert_eq!(dmu_identite(&st1, &copie_exfiltree), Some(("bob".into(), "editor".into())), "fixture : bob résout");
        let globale = st1.session_epoch.load(Ordering::SeqCst);
        let persistee = lire_l_epoque_de_session(&st1.db.lock()).expect("fixture : époque persistée");

        let (statut, efface, corps) = dmu_deconnexion(&st1, &session_de_bob, None).await;
        assert_eq!((statut, efface), (200, true), "{corps}");
        assert_eq!(corps, json!({ "ok": true, "portee": "compte" }), "{corps}");
        assert_eq!(st1.session_epoch.load(Ordering::SeqCst), globale, "mode 1 : l'époque globale ne bouge pas");
        assert_eq!(lire_l_epoque_de_session(&st1.db.lock()), Ok(persistee), "ni sur disque");
        assert_eq!(dmu_epoque_du_compte(&st1, "bob"), 1, "l'époque de bob avance");
        assert_eq!(dmu_epoque_du_compte(&st1, "alice"), 0, "aucun autre compte n'est révoqué");
        assert_eq!(dmu_traces_globales(&st1), 0, "aucune révocation globale tracée");
        assert_eq!(dmu_identite(&st1, &copie_exfiltree), None, "mode 1 : la copie du cookie de bob ne vaut plus rien");
        assert_eq!(dmu_identite(&st1, &session_d_alice), Some(("alice".into(), "editor".into())), "alice reste connectée");

        let code = hotp(&base32_decode(&graine).expect("graine base32"), (now() / 30) as u64, 6);
        let (statut, _, session, corps) = dmu_corps(
            login_mfa_post(State(st.clone()), ConnectInfo(dmu_pair()), Json(json!({ "ticket": ticket_d_adm, "code": code }))).await,
        )
        .await;
        assert_eq!((statut, session.is_some()), (200, true), "le ticket MFA d'un tiers vaut encore : {corps}");
    }

    /// CE QU'IL TIENT : mode 1, la valeur `session_epoch:bob` de `meta` illisible -> aucune session frappée : `503` +
    /// `CAUSE_EPOQUE_DU_COMPTE_NON_LUE` ; un jeton de `bob` frappé avant ne résout plus d'identité en mode 1 (une
    /// révocation non relue n'est pas absente). CONTRÔLE POSITIF : `alice` (époque lisible) est frappée et résout.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : mutant « F2_frappe_mode1_zero » (le mode 1 frappe l'époque zéro sans la lire —
    /// une session est émise) ; mutant « F2_identite_mode1_sans_epoque » (la résolution du mode 1 ne lit pas l'époque).
    #[tokio::test]
    async fn dmu_mode_1_une_epoque_du_compte_non_lue_ne_frappe_ni_ne_resout() {
        let (_st, st1, _p) = dmu_etats("non-lue");
        let jeton_d_avant = dmu_session(&st1, "bob", "editor");
        st1.db
            .lock()
            .execute("INSERT INTO meta(key,value) VALUES(?1,'illisible')", params![cle_de_l_epoque_du_compte("bob")])
            .expect("fixture : époque de bob illisible");
        let refus = frapper_la_session_du_compte(&st1, "bob", "editor").err().expect("mode 1 : aucune session frappée");
        let (statut, _, session, corps) = dmu_corps(refus).await;
        assert_eq!((statut, session), (503, None), "{corps}");
        assert_eq!(corps["error"], json!(CAUSE_EPOQUE_DU_COMPTE_NON_LUE), "{corps}");
        assert_eq!(dmu_identite(&st1, &jeton_d_avant), None, "mode 1 : époque non lue, le jeton ne résout pas");

        let session_d_alice = dmu_session(&st1, "alice", "editor");
        assert_eq!(dmu_identite(&st1, &session_d_alice), Some(("alice".into(), "editor".into())), "contrôle positif");
    }

    /// CE QU'IL TIENT : mode 1, la garde anti-DoS et la réserve admin jugent l'époque du compte. Le cookie RÉVOQUÉ de
    /// `bob` (son époque avancée par sa déconnexion) rejoué : portée `aucune`, son époque ne grimpe plus. Le jeton
    /// `admin` RÉVOQUÉ d'`adm` (son époque avancée) demande la portée `globale` : `403`, rien tracé ni avancé.
    /// CONTRÔLES POSITIFS : une session NEUVE de `bob` (frappée après sa déconnexion, époque du compte 1) résout en
    /// mode 1 ; le jeton `admin` courant d'`adm` obtient la révocation globale, tracée.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : mutant « F2_garde_mode1_sans_epoque » (`compte_de_la_session_ouverte` ne
    /// compare plus l'époque en mode 1 — l'époque de bob grimpe, le jeton révoqué d'adm révoque tout le monde) ;
    /// mutant « F2_identite_mode1_epoque_zero » (la résolution du mode 1 compare l'époque du compte à 0 au lieu de
    /// celle du jeton — tout compte déconnecté une fois est verrouillé dehors pour toujours).
    #[tokio::test]
    async fn dmu_mode_1_un_jeton_revoque_ne_deconnecte_rien() {
        let (_st, st1, _p) = dmu_etats("garde");
        let session_de_bob = dmu_session(&st1, "bob", "editor");
        assert_eq!(dmu_deconnexion(&st1, &session_de_bob, None).await.0, 200, "fixture : bob se déconnecte");
        assert_eq!(dmu_epoque_du_compte(&st1, "bob"), 1, "fixture");
        let (statut, efface, corps) = dmu_deconnexion(&st1, &session_de_bob, None).await;
        assert_eq!((statut, efface, corps["portee"].clone()), (200, true, json!("aucune")), "{corps}");
        assert_eq!(dmu_epoque_du_compte(&st1, "bob"), 1, "le cookie révoqué n'avance plus rien");
        let session_neuve_de_bob = dmu_session(&st1, "bob", "editor");
        assert_eq!(
            dmu_identite(&st1, &session_neuve_de_bob),
            Some(("bob".into(), "editor".into())),
            "contrôle positif : bob, déconnecté une fois, se reconnecte (époque du compte 1, pas 0)"
        );

        let globale = st1.session_epoch.load(Ordering::SeqCst);
        let admin_revoque = dmu_session(&st1, "adm", "admin");
        avancer_l_epoque_du_compte(&st1.db.lock(), "adm").expect("fixture : adm révoqué");
        let (statut, _, corps) = dmu_deconnexion(&st1, &admin_revoque, Some("globale")).await;
        assert_eq!(statut, 403, "{corps}");
        assert_eq!((st1.session_epoch.load(Ordering::SeqCst), dmu_traces_globales(&st1)), (globale, 0), "rien révoqué ni tracé");

        let admin_courant = dmu_session(&st1, "adm", "admin");
        let (statut, _, corps) = dmu_deconnexion(&st1, &admin_courant, Some("globale")).await;
        assert_eq!(statut, 200, "contrôle positif : {corps}");
        assert_eq!((st1.session_epoch.load(Ordering::SeqCst), dmu_traces_globales(&st1)), (globale + 1, 1), "contrôle positif");
    }

    /// CE QU'IL TIENT : mode 1, la résolution d'identité par cookie lit l'époque du compte SANS le verrou écrivain
    /// (read pool, comme le mode 0 — #23 F4) : le verrou de `st.db` tenu par le témoin, la session de `bob` résout
    /// quand même. Propriété STRUCTURELLE, pas une durée : avec la lecture par l'écrivain, le fil attend la fin de la
    /// prise ; le délai de 30 s ne sert qu'à ne pas pendre la suite.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : mutant « F2_epoque_mode1_par_l_ecrivain » (l'époque relue sous `st.db.lock()`
    /// — le fil ne rend rien tant que le verrou est tenu).
    #[test]
    fn dmu_mode_1_l_epoque_du_compte_se_lit_hors_du_verrou_ecrivain() {
        let (_st, st1, _p) = dmu_etats("hors-verrou");
        let session_de_bob = dmu_session(&st1, "bob", "editor");
        let (envoi, reception) = std::sync::mpsc::channel();
        let garde = st1.db.lock();
        let st_fil = st1.clone();
        let fil = std::thread::spawn(move || {
            let _ = envoi.send(dmu_identite(&st_fil, &session_de_bob));
        });
        let rendu = reception.recv_timeout(std::time::Duration::from_secs(30));
        drop(garde);
        fil.join().expect("le fil de résolution se termine");
        assert_eq!(
            rendu.ok(),
            Some(Some(("bob".into(), "editor".into()))),
            "mode 1 : la session résout sans attendre le verrou écrivain"
        );
    }

    /// CE QU'IL TIENT : mode 1, la session de `bob` résout encore quand le read pool ne sert pas l'époque du compte —
    /// pool INDISPONIBLE (aucune base au chemin) comme pool OUVERT dont l'énoncé échoue (base vide : `no such table:
    /// meta`) : l'époque est relue par l'écrivain, comme le mode 0 (`NonLu`). CONTRÔLE NÉGATIF : `bob` révoqué (son
    /// époque avancée sur l'écrivain), son jeton ne résout plus par aucune des deux voies — le repli JUGE l'époque.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : mutant « F2_pool_absent_refuse » (pool indisponible -> refus au lieu de
    /// l'écrivain) ; mutant « F2_pool_en_echec_refuse » (énoncé du pool en échec -> refus, la forme d'avant ce correctif).
    #[test]
    fn dmu_mode_1_un_pool_absent_ou_en_echec_se_relit_par_l_ecrivain() {
        let (_st, st1, _p) = dmu_etats("repli");
        let session_de_bob = dmu_session(&st1, "bob", "editor");
        let mut pool_absent = st1.clone();
        pool_absent.db_path = Arc::new(format!("{}-pool-absent", st1.db_path));
        let base_vide = format!("{}-base-vide", st1.db_path);
        std::fs::write(&base_vide, b"").expect("fixture : base vide");
        let mut pool_en_echec = st1.clone();
        pool_en_echec.db_path = Arc::new(base_vide.clone());

        let absent_avant = dmu_identite(&pool_absent, &session_de_bob);
        let en_echec_avant = dmu_identite(&pool_en_echec, &session_de_bob);
        avancer_l_epoque_du_compte(&st1.db.lock(), "bob").expect("fixture : bob révoqué");
        let absent_apres = dmu_identite(&pool_absent, &session_de_bob);
        let en_echec_apres = dmu_identite(&pool_en_echec, &session_de_bob);
        let _ = std::fs::remove_file(&base_vide);

        let bob = Some(("bob".to_string(), "editor".to_string()));
        assert_eq!(absent_avant, bob, "pool indisponible : l'écrivain relit l'époque");
        assert_eq!(en_echec_avant, bob, "énoncé du pool en échec : l'écrivain relit l'époque");
        assert_eq!((absent_apres, en_echec_apres), (None, None), "contrôle négatif : le repli juge l'époque");
    }

    /// CE QU'IL TIENT : mode 1, une époque de compte ILLISIBLE n'ouvre pas la garde de la déconnexion
    /// (`compte_de_la_session_ouverte`, bras `Err`) : le cookie de `bob` (époque illisible) se déconnecte en portée
    /// `aucune` (pas un 503 d'écriture) ; le jeton `admin` d'`adm` (époque illisible) demandant la portée `globale` ->
    /// `403`, rien révoqué ni tracé. CONTRÔLE POSITIF : `alice` (époque lisible) se déconnecte en portée `compte`.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : mutant « F2_garde_mode1_illisible_ouverte » (en mode 1 seulement, une époque
    /// non lue vaut ouverte — bob rend 503, le jeton d'adm révoque tout le monde).
    #[tokio::test]
    async fn dmu_mode_1_une_epoque_illisible_n_ouvre_pas_la_deconnexion() {
        let (_st, st1, _p) = dmu_etats("garde-illisible");
        let session_de_bob = dmu_session(&st1, "bob", "editor");
        let jeton_d_adm = dmu_session(&st1, "adm", "admin");
        let session_d_alice = dmu_session(&st1, "alice", "editor");
        for compte in ["bob", "adm"] {
            st1.db
                .lock()
                .execute("INSERT INTO meta(key,value) VALUES(?1,'illisible')", params![cle_de_l_epoque_du_compte(compte)])
                .expect("fixture : époque illisible");
        }
        let globale = st1.session_epoch.load(Ordering::SeqCst);

        let (statut, efface, corps) = dmu_deconnexion(&st1, &session_de_bob, None).await;
        assert_eq!((statut, efface, corps["portee"].clone()), (200, true, json!("aucune")), "{corps}");
        let (statut, _, corps) = dmu_deconnexion(&st1, &jeton_d_adm, Some("globale")).await;
        assert_eq!(statut, 403, "{corps}");
        assert_eq!((st1.session_epoch.load(Ordering::SeqCst), dmu_traces_globales(&st1)), (globale, 0), "rien révoqué ni tracé");

        let (statut, _, corps) = dmu_deconnexion(&st1, &session_d_alice, None).await;
        assert_eq!((statut, corps["portee"].clone()), (200, json!("compte")), "contrôle positif : {corps}");
    }
}
