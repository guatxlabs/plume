// =====================================================================================
// `P10.31-i` (volet 2) et `P10.24-e` — LA RÉVOCATION GLOBALE SANS COOKIE, ET LES COMPTES DU MODE MULTI-TENANT.
//
// MESURÉ SUR LA FORME D'AVANT (base 26d7a24f, chaque mutant ci-dessous la rejoue site par site) :
//  * `P10.31-i` : la seule porte de la révocation globale était `logout_post` sous la portée `globale`, qui exige un cookie
//    `plume_session` d'administrateur — un administrateur servi par le SSO d'en-têtes ou par Basic n'avait aucun geste.
//    Porte posée : `POST /api/sessions/revocation-globale` (`session::revocation_globale_post`).
//  * `P10.24-e` : l'énoncé « l'époque du compte n'y est ni frappée ni jugée » est PÉRIMÉ depuis la vague F (`ac60e3c`) :
//    en mode multi-tenant le compte qui tient une session est un compte de la PLATEFORME (`state::lookup_basic_ident_lu`),
//    son époque est frappée par `frapper_la_session_du_compte` et jugée par `l_epoque_du_compte_vaut`. Ce qui restait :
//    `user_update` posait le mot de passe d'une LIGNE de tenant (jamais lue par une connexion) et jugeait le mot de passe
//    actuel par la résolution du mode zéro ; `user_update` et `user_delete` avançaient `session_epoch:<nom>` dans la base
//    du tenant `default`, ce qui révoquait le compte de plateforme HOMONYME ; `/api/password` acceptait le mot de passe
//    d'un compte de plateforme homonyme de l'administrateur de l'assistant comme preuve, et remplaçait la crédence de
//    l'assistant ; les refus du compte de l'assistant (`P10.24-n`, `P10.24-s`) ne jouaient sur AUCUN tenant avec un plan
//    de contrôle (la poignée du tenant `default` n'est pas `st.db`).
//
// CORRECTION APRÈS VÉRIFICATION (mutants `BA6C_*`) : la route n'exige plus le secret des gestes (la portée `globale` de
// `logout_post`, l'autre porte, ne l'exigeait pas : les deux ont désormais la même autorité, celle de la décision sur
// `P10.23-o`) ; la portée `globale` de `logout_post` relit le super-administrateur dans le plan de contrôle au lieu du rôle
// porté par le jeton ; la réserve réelle du mode multi-tenant est JOUÉE ; les refus du compte de l'assistant disent, sous
// un plan de contrôle, un remède qui y tient ; `user_create` refuse sous un plan de contrôle la ligne inerte que
// `user_update` refusait déjà.
//
// POURQUOI L'ÉPOQUE N'EST PAS PORTÉE PAR LA BASE DU TENANT : la session du mode multi-tenant est celle d'un compte de
// plateforme, le tenant se choisit à CHAQUE requête (`x-plume-tenant`, `auth::resolve_tenant_and_role`). Une époque par
// tenant laisserait la copie d'un cookie déconnecté valoir dans les AUTRES tenants du compte : plus faible que l'époque du
// compte, jugée partout (témoin `rgsc_mode_1_deconnexion_par_compte_deux_tenants_et_homonymes`).
// =====================================================================================
mod revocation_globale_sans_cookie_et_comptes_du_mode_un {
    use super::*;
    use crate::secret_des_gestes::{ENTETE_DU_SECRET_DES_GESTES, SECRET_DES_GESTES_DE_TEST};
    use rusqlite::OptionalExtension;
    use std::sync::atomic::Ordering;

    const RGSC_ROUTE: &str = "/api/sessions/revocation-globale";
    const RGSC_SECRET_SSO: &str = "secret-de-bord-rgsc";
    pub(super) const RGSC_MOT_DE_PASSE: &str = "motdepasse-rgsc-12345";
    pub(super) const RGSC_MOT_DE_PASSE_NEUF: &str = "motdepasse-neuf-rgsc-67890";
    pub(super) const RGSC_MOT_DE_PASSE_DE_LA_LIGNE: &str = "motdepasse-ligne-rgsc-24680";
    const RGSC_MOT_DE_PASSE_DE_PLATEFORME: &str = "motdepasse-plateforme-rgsc-13579";
    pub(super) const RGSC_TENANT_A: &str = "rgsca";
    pub(super) const RGSC_TENANT_B: &str = "rgscb";
    const RGSC_ORIGINE: (&str, &str) = ("Origin", "http://127.0.0.1");
    pub(super) const RGSC_JSON: (&str, &str) = ("Content-Type", "application/json");
    pub(super) const RGSC_SECRET: (&str, &str) = (ENTETE_DU_SECRET_DES_GESTES, SECRET_DES_GESTES_DE_TEST);

    pub(super) struct RgscReponse {
        pub(super) statut: u16,
        pub(super) corps: Value,
        pub(super) texte: String,
    }

    impl RgscReponse {
        pub(super) fn cookie_efface(&self) -> bool {
            self.texte.lines().any(|l| {
                let l = l.to_ascii_lowercase();
                l.starts_with("set-cookie: plume_session=;") && l.contains("max-age=0")
            })
        }
        fn cookie_pose(&self) -> Option<String> {
            self.texte.lines().find_map(|l| {
                let bas = l.to_ascii_lowercase();
                if !bas.starts_with("set-cookie: plume_session=") {
                    return None;
                }
                let valeur = l["set-cookie: plume_session=".len()..].split(';').next().unwrap_or("").to_string();
                (!valeur.is_empty()).then_some(valeur)
            })
        }
    }

    /// Le corps d'une réponse HTTP/1.1 brute ; un corps `Transfer-Encoding: chunked` est remis bout à bout.
    fn rgsc_corps_brut(texte: &str) -> String {
        let Some((entetes, corps)) = texte.split_once("\r\n\r\n") else { return String::new() };
        if !entetes.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            return corps.to_string();
        }
        let (mut reste, mut assemble) = (corps, String::new());
        while let Some((taille, suite)) = reste.split_once("\r\n") {
            let n = usize::from_str_radix(taille.trim(), 16).unwrap_or(0);
            if n == 0 || suite.len() < n {
                break;
            }
            assemble.push_str(&suite[..n]);
            reste = suite[n..].strip_prefix("\r\n").unwrap_or(&suite[n..]);
        }
        assemble
    }

    pub(super) async fn rgsc_envoyer(addr: std::net::SocketAddr, methode: &str, chemin: &str, authz: Option<&str>, entetes: &[(&str, &str)], corps: &str) -> RgscReponse {
        let (statut, texte) = router_probe_envoi(addr, methode, chemin, authz, entetes, corps).await;
        let brut = rgsc_corps_brut(&texte);
        let corps = serde_json::from_str(&brut).unwrap_or(Value::String(brut));
        RgscReponse { statut, corps, texte }
    }

    pub(super) fn rgsc_basic(nom: &str, mot: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{nom}:{mot}")))
    }

    /// `GET /api/me` sous un cookie (et un tenant), au routeur : le statut seul.
    pub(super) async fn rgsc_me(addr: std::net::SocketAddr, jeton: &str, tenant: Option<&str>) -> u16 {
        let cookie = format!("plume_session={jeton}");
        let mut entetes = vec![("Cookie", cookie.as_str())];
        if let Some(t) = tenant {
            entetes.push(("x-plume-tenant", t));
        }
        rgsc_envoyer(addr, "GET", "/api/me", None, &entetes, "").await.statut
    }

    /// (époque globale en mémoire, époque globale persistée).
    pub(super) fn rgsc_epoques(st: &AppState) -> (i64, i64) {
        (st.session_epoch.load(Ordering::SeqCst), lire_l_epoque_de_session(&st.db.lock()).expect("fixture : époque persistée lue"))
    }

    pub(super) fn rgsc_traces_globales(st: &AppState) -> Vec<String> {
        let c = st.db.lock();
        let mut s = c.prepare("SELECT detail FROM ledger WHERE kind='auth.deconnexion.globale' ORDER BY id").expect("fixture : registre");
        s.query_map([], |r| r.get::<_, String>(0)).expect("fixture : registre lu").collect::<rusqlite::Result<Vec<_>>>().expect("fixture : lignes lues")
    }

    pub(super) fn rgsc_compter(c: &Connection, sql: &str, nom: &str) -> i64 {
        c.query_row(sql, params![nom], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn rgsc_trace_attendue(admin: &str, revoquee: i64) -> String {
        format!("sessions de TOUS les comptes révoquées par l'administrateur '{admin}' (époque globale {revoquee} révoquée)")
    }

    /// Un 5xx d'`err_json` : exactement `error` (la phrase) et `id` (l'identifiant de corrélation).
    pub(super) fn rgsc_cinq_cent_trois(r: &RgscReponse, cause: &str) {
        assert_eq!(r.statut, 503, "{}", r.texte);
        let objet = r.corps.as_object().unwrap_or_else(|| panic!("corps JSON : {}", r.texte));
        let mut cles: Vec<&str> = objet.keys().map(String::as_str).collect();
        cles.sort_unstable();
        assert_eq!(cles, vec!["error", "id"], "{}", r.texte);
        assert_eq!(objet["error"], json!(cause), "{}", r.texte);
        assert!(objet["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{}", r.texte);
    }

    /// MODE 0 : la base du routeur (`vwr` lecteur, `root` administrateur de configuration), `rgsc-alice` éditrice et
    /// `rgsc-adm` administrateur à mot de passe local, le SSO d'en-têtes armé.
    fn rgsc_mode_0(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (mut st, p) = router_test_state(&format!("rgsc-{tag}"));
        st.sso_secret = Arc::new(RGSC_SECRET_SSO.into());
        st.installation_ouverte.store(false, Ordering::SeqCst);
        {
            let c = st.db.lock();
            for (nom, role) in [("rgsc-alice", "editor"), ("rgsc-adm", "admin")] {
                c.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![nom, hash_pw(RGSC_MOT_DE_PASSE).expect("hachage"), role]).expect("fixture : compte");
            }
        }
        (st, p)
    }

    fn rgsc_sso(nom: &'static str, groupes: &'static str) -> Vec<(&'static str, &'static str)> {
        vec![("x-plume-sso-secret", RGSC_SECRET_SSO), ("x-authentik-username", nom), ("x-authentik-groups", groupes), RGSC_ORIGINE]
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.31-i` volet 2 — LA PORTE, PAR LE ROUTEUR RÉEL
    // -------------------------------------------------------------------------------------

    /// Un geste de révocation globale admis, joué par la route sous `entetes` : alice (frappée juste avant) résout avant et
    /// plus après ; `200`, corps exact, cookie effacé ; l'époque globale passe à `rang + 1` (mémoire et disque) ; le
    /// registre porte exactement `attendues` plus la ligne de cet auteur.
    async fn rgsc_un_geste_admis(st: &AppState, addr: std::net::SocketAddr, auteur: &str, rang: i64, authz: Option<&str>, entetes: &[(&str, &str)], attendues: &mut Vec<String>) {
        let alice = frapper_la_session_du_compte(st, "rgsc-alice", "editor").expect("fixture : session d'alice");
        assert_eq!(rgsc_me(addr, &alice, None).await, 200, "{auteur} : fixture, alice résout avant le geste");
        let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, authz, entetes, "").await;
        assert_eq!((r.statut, &r.corps), (200, &json!({ "ok": true, "portee": "globale" })), "{auteur} : {}", r.texte);
        assert!(r.cookie_efface(), "{auteur} : le cookie de ce navigateur est effacé : {}", r.texte);
        assert_eq!(rgsc_epoques(st), (rang + 1, rang + 1), "{auteur} : l'époque globale avance, en mémoire et sur disque");
        attendues.push(rgsc_trace_attendue(auteur, rang));
        assert_eq!(&rgsc_traces_globales(st), attendues, "{auteur} : une ligne de registre par geste, au nom de son auteur");
        assert_eq!(rgsc_me(addr, &alice, None).await, 401, "{auteur} : la session d'alice est révoquée");
    }

    /// CE QU'IL TIENT : mode 0, un administrateur servi par le SSO d'en-têtes (aucun cookie plume), puis `root` en Basic,
    /// puis `rgsc-adm` par son cookie et son jeton CSRF, révoquent chacun TOUTES les sessions, SANS secret des gestes :
    /// `200`, corps exact `{"ok":true,"portee":"globale"}`, cookie de ce navigateur effacé ; l'époque globale avance d'une
    /// unité en mémoire ET sur disque ; le registre porte une ligne `auth.deconnexion.globale` par geste, au nom de son
    /// auteur ; la session d'alice frappée avant chaque geste ne résout plus (`401`), celle d'`rgsc-adm` non plus.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BA6_RG_SANS_REVOCATION » (la route rend `200` sans révoquer) ;
    /// « BA6C_RG_SECRET_EXIGE » (la forme du lot avant correction : `403` secret absent).
    #[tokio::test]
    async fn rgsc_mode_0_sso_basic_et_cookie_revoquent_tous_les_comptes() {
        let (st, _p) = rgsc_mode_0("nominal");
        let addr = router_serve(st.clone()).await;
        let mut attendues = Vec::new();
        let sso = rgsc_sso("rgsc-carol", "plume-admin");
        rgsc_un_geste_admis(&st, addr, "rgsc-carol", 0, None, &sso, &mut attendues).await;
        let basic = rgsc_basic("root", "rootpw1234567");
        rgsc_un_geste_admis(&st, addr, "root", 1, Some(&basic), &[], &mut attendues).await;
        let adm = frapper_la_session_du_compte(&st, "rgsc-adm", "admin").expect("fixture : session d'adm, frappée à l'époque courante");
        let (cookie, csrf) = (format!("plume_session={adm}"), csrf_for(st.session_secret.as_slice(), &adm));
        rgsc_un_geste_admis(&st, addr, "rgsc-adm", 2, None, &[("Cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())], &mut attendues).await;
        assert_eq!(rgsc_me(addr, &adm, None).await, 401, "la session de l'auteur par cookie est révoquée avec les autres");
    }

    /// CE QU'IL TIENT : les deux phrases neuves, lues contre des littéraux du témoin (pas contre leur constante) : la
    /// réserve nomme le super-administrateur du mode multi-tenant et dit que rien n'est révoqué ; le refus du mot de passe
    /// d'une ligne de tenant nomme le compte de la plateforme, les droits du tenant, et dit que rien n'est écrit.
    #[test]
    fn rgsc_les_phrases_neuves_disent_ce_qu_elles_refusent() {
        for (phrase, fragments) in [
            (CAUSE_REVOCATION_GLOBALE_RESERVEE, &["RÉVOCATION GLOBALE RÉSERVÉE", "super-administrateur de la plateforme", "Rien n'est révoqué"][..]),
            (
                CAUSE_MOT_DE_PASSE_NON_POSE_IDENTITE_DE_PLATEFORME,
                &["MOT DE PASSE NON POSÉ", "compte de la plateforme", "/api/tenants/{id}/grants", "Rien n'est écrit", "aucun mot de passe actuel"][..],
            ),
            (
                CAUSE_COMPTE_NON_CREE_IDENTITE_DE_PLATEFORME,
                &["COMPTE NON CRÉÉ", "compte de la plateforme", "ne se connecterait pas", "/api/tenants/{id}/grants", "Rien n'est écrit"][..],
            ),
            (CAUSE_REVOCATION_GLOBALE_RESERVEE, &["administrateur", "bris de glace", "X-Plume-Breakglass"][..]),
        ] {
            assert!(fragments.len() >= 3, "plancher");
            for f in fragments {
                assert!(phrase.contains(f), "« {f} » absent de : {phrase}");
            }
        }
    }

    /// CE QU'IL TIENT : mode 0, le secret des gestes CONFIGURÉ (la fixture du routeur le pose), la route jouée SANS son
    /// en-tête, en Basic puis par le SSO d'en-têtes, puis avec un secret FAUX : `200` les trois fois, l'époque globale
    /// avance à chaque geste ; AUCUNE ligne `secret_des_gestes` au registre (le secret n'est pas examiné), trois lignes
    /// `auth.deconnexion.globale`. La portée `globale` de `logout_post` (l'autre porte) ne l'exige pas non plus : un
    /// cookie d'administrateur sans l'en-tête révoque (`200`). Les deux portes ont la même autorité.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « BA6C_RG_SECRET_EXIGE » (la forme du lot avant correction : `403`
    /// `secret_des_gestes_absent`, rien n'est révoqué).
    #[tokio::test]
    async fn rgsc_la_route_n_exige_pas_le_secret_des_gestes_comme_l_autre_porte() {
        let (st, _p) = rgsc_mode_0("sans-secret");
        assert!(
            crate::secret_des_gestes::exiger_le_secret_des_gestes(&st, &crate::secret_des_gestes::presente_de_test(), "rgsc-fixture", "fixture").is_ok(),
            "fixture : le secret des gestes est configuré"
        );
        let addr = router_serve(st.clone()).await;
        let basic = rgsc_basic("root", "rootpw1234567");
        let faux = [(ENTETE_DU_SECRET_DES_GESTES, "ce-n-est-pas-le-secret-rgsc")];
        let essais: [(&str, Option<&str>, Vec<(&str, &str)>); 3] =
            [("Basic sans en-tête", Some(basic.as_str()), Vec::new()), ("SSO sans en-tête", None, rgsc_sso("rgsc-carol", "plume-admin")), ("Basic secret faux", Some(basic.as_str()), faux.to_vec())];
        for (rang, (porte, authz, entetes)) in essais.iter().enumerate() {
            let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, *authz, entetes, "").await;
            assert_eq!((r.statut, &r.corps), (200, &json!({ "ok": true, "portee": "globale" })), "{porte} : {}", r.texte);
            assert_eq!(rgsc_epoques(&st), (rang as i64 + 1, rang as i64 + 1), "{porte} : l'époque globale avance");
        }
        assert_eq!(rgsc_compter(&st.db.lock(), "SELECT COUNT(*) FROM ledger WHERE kind=?1", "secret_des_gestes"), 0, "le secret n'est pas examiné");
        assert_eq!(rgsc_traces_globales(&st).len(), 3, "trois révocations inscrites");
        let adm = frapper_la_session_du_compte(&st, "rgsc-adm", "admin").expect("fixture : session d'adm");
        let r = rgsc_deconnexion_globale(addr, &adm).await;
        assert_eq!((r.statut, &r.corps), (200, &json!({ "ok": true, "portee": "globale" })), "l'autre porte, sans l'en-tête : {}", r.texte);
        assert_eq!(rgsc_epoques(&st), (4, 4));
    }

    /// CE QU'IL TIENT : mode 0, un non-administrateur est refusé AU ROUTEUR (`route_min_role` : mutation non déclarée =
    /// administrateur) — `vwr` en Basic : `403` « lecture seule (rôle viewer) » ; alice éditrice par cookie et CSRF : `403`
    /// « réservé à l'administrateur » ; et le gestionnaire appelé sous une identité éditrice (la réserve re-jugée, défense
    /// en profondeur du mode 0) : `403`, corps exact `{error: CAUSE_REVOCATION_GLOBALE_RESERVEE}`. Rien n'est révoqué.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « BA6_RG_MODE0_OUVERT » (la réserve du mode 0 laisse passer tout rôle — le
    /// gestionnaire révoque pour une éditrice).
    #[tokio::test]
    async fn rgsc_un_non_administrateur_est_refuse() {
        let (st, _p) = rgsc_mode_0("non-admin");
        let addr = router_serve(st.clone()).await;
        let alice = frapper_la_session_du_compte(&st, "rgsc-alice", "editor").expect("fixture : session d'alice");
        let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, Some(&viewer_authz()), &[], "").await;
        assert_eq!((r.statut, &r.corps), (403, &json!("lecture seule (rôle viewer)")), "{}", r.texte);
        let (cookie, csrf) = (format!("plume_session={alice}"), csrf_for(st.session_secret.as_slice(), &alice));
        let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, None, &[("Cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())], "").await;
        assert_eq!((r.statut, &r.corps), (403, &json!("réservé à l'administrateur")), "{}", r.texte);
        let editrice = AuthUser {
            name: "rgsc-alice".into(),
            role: "editor".into(),
            tenant: "default".into(),
            is_superadmin: false,
            method: "basic".into(),
            csrf: String::new(),
            env: None,
        };
        let reponse = revocation_globale_post(State(st.clone()), Extension(editrice)).await;
        let statut = reponse.status().as_u16();
        let corps: Value = serde_json::from_slice(&axum::body::to_bytes(reponse.into_body(), usize::MAX).await.expect("corps")).expect("JSON");
        assert_eq!((statut, corps), (403, json!({ "error": CAUSE_REVOCATION_GLOBALE_RESERVEE })));
        assert_eq!(rgsc_epoques(&st), (0, 0), "rien n'est révoqué");
        assert!(rgsc_traces_globales(&st).is_empty());
        assert_eq!(rgsc_me(addr, &alice, None).await, 200, "alice reste connectée");
    }

    fn rgsc_meta_refuse_l_epoque(st: &AppState) {
        st.db
            .lock()
            .execute_batch(
                "CREATE TRIGGER rgsc_refus_upd BEFORE UPDATE ON meta WHEN NEW.key='session_epoch' BEGIN SELECT RAISE(ABORT,'rgsc refus'); END;
                 CREATE TRIGGER rgsc_refus_ins BEFORE INSERT ON meta WHEN NEW.key='session_epoch' BEGIN SELECT RAISE(ABORT,'rgsc refus'); END;",
            )
            .expect("fixture : meta refuse l'époque globale");
    }

    /// CE QU'IL TIENT : mode 0, par la route (Basic `root`). L'époque globale NON PERSISTÉE (déclencheur
    /// sur `meta`) -> `503`, corps exact `{error: CAUSE_DECONNEXION_GLOBALE_NON_PERSISTEE, id}`, aucun cookie effacé,
    /// époque inchangée en mémoire et sur disque, rien d'inscrit, alice résout. La trace REFUSÉE (déclencheur sur
    /// `ledger`) -> `503` `CAUSE_DECONNEXION_GLOBALE_NON_TRACEE`, l'époque persistée ANNULÉE avec elle. CONTRÔLE POSITIF :
    /// déclencheurs retirés, `200` et l'époque avance.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BA6_RG_200_SUR_NON_PERSISTEE », « BA6_RG_200_SUR_NON_TRACEE » (l'échec servi
    /// en `200`).
    #[tokio::test]
    async fn rgsc_un_echec_de_persistance_ou_de_trace_est_refuse_et_nomme() {
        let (st, _p) = rgsc_mode_0("persistance");
        let addr = router_serve(st.clone()).await;
        let alice = frapper_la_session_du_compte(&st, "rgsc-alice", "editor").expect("fixture : session d'alice");
        let basic = rgsc_basic("root", "rootpw1234567");

        rgsc_meta_refuse_l_epoque(&st);
        let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, Some(&basic), &[], "").await;
        rgsc_cinq_cent_trois(&r, CAUSE_DECONNEXION_GLOBALE_NON_PERSISTEE);
        assert!(!r.cookie_efface(), "aucun cookie effacé sur un refus");
        assert_eq!(rgsc_epoques(&st), (0, 0), "rien n'est révoqué");
        assert!(rgsc_traces_globales(&st).is_empty(), "rien n'est inscrit");
        assert_eq!(rgsc_me(addr, &alice, None).await, 200, "alice reste connectée");
        st.db.lock().execute_batch("DROP TRIGGER rgsc_refus_upd; DROP TRIGGER rgsc_refus_ins;").expect("fixture");

        st.db
            .lock()
            .execute_batch("CREATE TRIGGER rgsc_trace_refusee BEFORE INSERT ON ledger WHEN NEW.kind='auth.deconnexion.globale' BEGIN SELECT RAISE(ABORT,'rgsc trace'); END;")
            .expect("fixture : la trace refusée");
        let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, Some(&basic), &[], "").await;
        rgsc_cinq_cent_trois(&r, CAUSE_DECONNEXION_GLOBALE_NON_TRACEE);
        assert!(!r.cookie_efface(), "aucun cookie effacé sur un refus");
        assert_eq!(rgsc_epoques(&st), (0, 0), "l'époque persistée est annulée avec la trace");
        assert_eq!(rgsc_me(addr, &alice, None).await, 200, "alice reste connectée");
        st.db.lock().execute_batch("DROP TRIGGER rgsc_trace_refusee;").expect("fixture");

        let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, Some(&basic), &[], "").await;
        assert_eq!(r.statut, 200, "contrôle positif : {}", r.texte);
        assert_eq!(rgsc_epoques(&st), (1, 1), "contrôle positif");
    }

    // -------------------------------------------------------------------------------------
    // (2) MODE MULTI-TENANT AVEC PLAN DE CONTRÔLE — DEUX TENANTS RÉELS
    // -------------------------------------------------------------------------------------

    /// Plan de contrôle et DEUX tenants réels créés par la route de création (A : premier administrateur `rgsc-ana` ;
    /// B : `rgsc-ben`) ; `rgsc-ana` éditrice de B aussi ; `rgsc-dan` administrateur du tenant `default` ; `rgsc-sa`
    /// super-administrateur, administrateur de A. Tous à mot de passe de plateforme. La base du tenant `default` est le
    /// FICHIER de `st.db` (comme en production : la poignée du tenant `default` est une seconde connexion à ce fichier).
    pub(super) async fn rgsc_plateforme() -> (AppState, crate::tmp_possede::TmpPossede) {
        let (mut st, dir) = mk_mode1_state();
        let principale = st.db_path.as_ref().clone();
        let conn = open_db(&principale).expect("fixture : base principale");
        conn.execute_batch(include_str!("../../../db/schema.sql")).expect("fixture : schéma");
        assert!(migrate(&conn), "fixture : migrations complètes");
        st.db = Arc::new(Mutex::new(conn));
        st.tenants.default_writer = st.db.clone();
        st.installation_ouverte.store(false, Ordering::SeqCst);
        st.sso_secret = Arc::new(RGSC_SECRET_SSO.into());
        st.rl_auth_max = 1_000_000;
        st.rl_ip_max = 1_000_000;
        st.rl_global_max = 1_000_000;
        for (tenant, admin) in [(RGSC_TENANT_A, "rgsc-ana"), (RGSC_TENANT_B, "rgsc-ben")] {
            let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("rgsc-op")), Json(json!({ "id": tenant, "name": tenant, "admin": admin }))).await;
            assert_eq!(r.status().as_u16(), 201, "fixture : tenant {tenant} créé");
        }
        let plan = st.tenants.control.as_ref().expect("fixture : plan de contrôle");
        for nom in ["rgsc-dan", "rgsc-sa"] {
            ensure_platform_user(plan, nom).expect("fixture : compte de plateforme");
        }
        {
            let c = plan.conn.lock();
            for (nom, tenant, role) in [("rgsc-ana", RGSC_TENANT_B, "editor"), ("rgsc-dan", "default", "admin"), ("rgsc-sa", RGSC_TENANT_A, "admin")] {
                c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) SELECT id,?2,?3 FROM platform_user WHERE name=?1", params![nom, tenant, role]).expect("fixture : droit");
            }
            for nom in ["rgsc-ana", "rgsc-ben", "rgsc-dan", "rgsc-sa"] {
                assert_eq!(c.execute("UPDATE platform_user SET hash=?1 WHERE name=?2", params![hash_pw(RGSC_MOT_DE_PASSE).expect("hachage"), nom]).expect("fixture"), 1, "fixture : {nom}");
            }
            c.execute("UPDATE platform_user SET is_superadmin=1 WHERE name='rgsc-sa'", []).expect("fixture : super-administrateur");
        }
        (st, dir)
    }

    /// Une ligne `user` posée dans la base d'un tenant ; rend son identifiant.
    pub(super) fn rgsc_ligne(st: &AppState, tenant: &str, nom: &str, role: &str, mot: &str) -> i64 {
        let h = st.tenants.handle_for(tenant).unwrap_or_else(|| panic!("fixture : base du tenant {tenant}"));
        let c = h.lock();
        c.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![nom, hash_pw(mot).expect("hachage"), role]).expect("fixture : ligne de tenant");
        c.last_insert_rowid()
    }

    pub(super) fn rgsc_base(st: &AppState, tenant: &str) -> Arc<Mutex<Connection>> {
        st.tenants.handle_for(tenant).unwrap_or_else(|| panic!("fixture : base du tenant {tenant}"))
    }

    fn rgsc_epoque_dans(c: &Connection, nom: &str) -> Option<String> {
        c.query_row("SELECT value FROM meta WHERE key=?1", params![cle_de_l_epoque_du_compte(nom)], |r| r.get(0)).optional().expect("fixture : meta lue")
    }

    pub(super) async fn rgsc_connexion(addr: std::net::SocketAddr, nom: &str) -> String {
        let r = rgsc_envoyer(addr, "POST", "/api/login", None, &[RGSC_JSON], &json!({ "user": nom, "pass": RGSC_MOT_DE_PASSE }).to_string()).await;
        assert_eq!(r.statut, 200, "fixture : {nom} se connecte : {}", r.texte);
        r.cookie_pose().unwrap_or_else(|| panic!("fixture : cookie de {nom} : {}", r.texte))
    }

    /// CE QU'IL TIENT : mode multi-tenant, par la route, sans secret des gestes (la route ne l'exige pas). L'administratrice
    /// d'UN tenant (`rgsc-ana`, A) : `403`, corps exact `{error: CAUSE_REVOCATION_GLOBALE_RESERVEE}`, rien n'est révoqué. Le super-administrateur
    /// (`rgsc-sa`, Basic, membre de A) : `200`, l'époque globale avance, la ligne de registre le nomme, et la session de
    /// `rgsc-ben` (tenant B) tombe. Le même super-administrateur RÉTROGRADÉ dans le plan de contrôle (relu à la requête) :
    /// `403`. Un super-administrateur servi par le SSO d'en-têtes (groupe `admins`) : `200`.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « BA6_RG_MODE1_ROLE » (le mode 1 juge le rôle du tenant, `admin`, au lieu du
    /// super-administrateur — l'administratrice de A révoque les sessions de B).
    #[tokio::test]
    async fn rgsc_mode_1_seul_le_super_administrateur_revoque_globalement() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let ben = rgsc_connexion(addr, "rgsc-ben").await;
        assert_eq!(rgsc_me(addr, &ben, Some(RGSC_TENANT_B)).await, 200, "fixture : ben résout dans B");
        let tenant_a = ("x-plume-tenant", RGSC_TENANT_A);

        let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, Some(&rgsc_basic("rgsc-ana", RGSC_MOT_DE_PASSE)), &[tenant_a], "").await;
        assert_eq!((r.statut, &r.corps), (403, &json!({ "error": CAUSE_REVOCATION_GLOBALE_RESERVEE })), "{}", r.texte);
        assert_eq!(rgsc_epoques(&st), (0, 0), "l'administratrice d'un tenant ne révoque rien");
        assert_eq!(rgsc_me(addr, &ben, Some(RGSC_TENANT_B)).await, 200, "ben reste connecté");

        let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, Some(&rgsc_basic("rgsc-sa", RGSC_MOT_DE_PASSE)), &[tenant_a], "").await;
        assert_eq!((r.statut, &r.corps), (200, &json!({ "ok": true, "portee": "globale" })), "{}", r.texte);
        assert_eq!(rgsc_epoques(&st), (1, 1));
        assert_eq!(rgsc_traces_globales(&st), vec![rgsc_trace_attendue("rgsc-sa", 0)]);
        assert_eq!(rgsc_me(addr, &ben, Some(RGSC_TENANT_B)).await, 401, "la session de ben (autre tenant) est révoquée");

        st.tenants.control.as_ref().expect("plan").conn.lock().execute("UPDATE platform_user SET is_superadmin=0 WHERE name='rgsc-sa'", []).expect("fixture : rétrogradé");
        let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, Some(&rgsc_basic("rgsc-sa", RGSC_MOT_DE_PASSE)), &[tenant_a], "").await;
        assert_eq!((r.statut, &r.corps), (403, &json!({ "error": CAUSE_REVOCATION_GLOBALE_RESERVEE })), "rétrogradé, relu à la requête : {}", r.texte);
        assert_eq!(rgsc_epoques(&st), (1, 1));

        let mut sso = rgsc_sso("rgsc-sso-sa", "admins,plume-rgsca-admin");
        sso.push(tenant_a);
        let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, None, &sso, "").await;
        assert_eq!((r.statut, &r.corps), (200, &json!({ "ok": true, "portee": "globale" })), "{}", r.texte);
        assert_eq!(rgsc_epoques(&st), (2, 2));
        assert_eq!(rgsc_traces_globales(&st), vec![rgsc_trace_attendue("rgsc-sa", 0), rgsc_trace_attendue("rgsc-sso-sa", 1)]);
    }

    /// CE QU'IL TIENT (`P10.24-e`) : mode multi-tenant, deux tenants réels, par la route.
    ///  (a) Les gestes sur des LIGNES HOMONYMES ne révoquent pas le compte de plateforme : `rgsc-ben` (administrateur de
    ///      B) pose un mot de passe sur la ligne `rgsc-ana` de B -> `409`, corps exact ; `rgsc-dan` (administrateur de
    ///      `default`) pose un mot de passe sur la ligne `rgsc-ben` de `default` -> `409`, puis la SUPPRIME -> `200`.
    ///      Après eux : la session d'ana résout dans A, celle de ben dans B ; aucune clé `session_epoch:<nom>` posée, ni
    ///      dans `default` ni dans B ; les hachés des lignes inchangés.
    ///  (b) La déconnexion d'ana révoque le COMPTE, dans ses DEUX tenants : la copie de son cookie rend `401` dans A et
    ///      dans B ; la session de ben résout encore dans B ; l'époque d'ana avance dans la base du compte (`st.db`), la
    ///      base de B n'en porte aucune.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BA6_UU_SANS_REFUS » (le mot de passe de la ligne est posé : `204`, et dans
    /// `default` la session de ben tombe) ; « BA6_UD_EPOQUE_TOUJOURS » (la suppression de la ligne homonyme avance
    /// l'époque du compte de plateforme ben — sa session tombe) ; « BA6_ID_MODE1_SANS_EPOQUE » (la résolution du mode 1
    /// ne juge plus l'époque — la copie du cookie d'ana vaut encore).
    #[tokio::test]
    async fn rgsc_mode_1_deconnexion_par_compte_deux_tenants_et_homonymes() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let ana = rgsc_connexion(addr, "rgsc-ana").await;
        let ben = rgsc_connexion(addr, "rgsc-ben").await;
        for (jeton, tenant) in [(&ana, RGSC_TENANT_A), (&ana, RGSC_TENANT_B), (&ben, RGSC_TENANT_B)] {
            assert_eq!(rgsc_me(addr, jeton, Some(tenant)).await, 200, "fixture : résout dans {tenant}");
        }
        let ligne_ana_b = rgsc_ligne(&st, RGSC_TENANT_B, "rgsc-ana", "editor", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        let ligne_ben_default = rgsc_ligne(&st, "default", "rgsc-ben", "editor", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        let refus = json!({ "error": CAUSE_MOT_DE_PASSE_NON_POSE_IDENTITE_DE_PLATEFORME });
        let neuf = json!({ "password": RGSC_MOT_DE_PASSE_NEUF }).to_string();

        let r = rgsc_envoyer(addr, "POST", &format!("/api/users/{ligne_ana_b}"), Some(&rgsc_basic("rgsc-ben", RGSC_MOT_DE_PASSE)), &[RGSC_JSON, ("x-plume-tenant", RGSC_TENANT_B), RGSC_SECRET], &neuf).await;
        assert_eq!((r.statut, &r.corps), (409, &refus), "B : {}", r.texte);
        let dan = rgsc_basic("rgsc-dan", RGSC_MOT_DE_PASSE);
        let r = rgsc_envoyer(addr, "POST", &format!("/api/users/{ligne_ben_default}"), Some(&dan), &[RGSC_JSON, ("x-plume-tenant", "default"), RGSC_SECRET], &neuf).await;
        assert_eq!((r.statut, &r.corps), (409, &refus), "default : {}", r.texte);
        let h: String = st.db.lock().query_row("SELECT hash FROM user WHERE id=?1", params![ligne_ben_default], |r| r.get(0)).expect("ligne lue");
        assert!(verify_pw(RGSC_MOT_DE_PASSE_DE_LA_LIGNE, &h), "le haché de la ligne de default est inchangé");
        let h: String = rgsc_base(&st, RGSC_TENANT_B).lock().query_row("SELECT hash FROM user WHERE id=?1", params![ligne_ana_b], |r| r.get(0)).expect("ligne lue");
        assert!(verify_pw(RGSC_MOT_DE_PASSE_DE_LA_LIGNE, &h), "le haché de la ligne de B est inchangé");
        let r = rgsc_envoyer(addr, "DELETE", &format!("/api/users/{ligne_ben_default}"), Some(&dan), &[("x-plume-tenant", "default")], "").await;
        assert_eq!(r.statut, 200, "default : la ligne homonyme est supprimée : {}", r.texte);
        assert_eq!(rgsc_compter(&st.db.lock(), "SELECT COUNT(*) FROM user WHERE name=?1", "rgsc-ben"), 0, "fixture : supprimée");
        assert_eq!(rgsc_me(addr, &ana, Some(RGSC_TENANT_A)).await, 200, "ana n'est pas révoquée par un geste sur sa ligne homonyme de B");
        assert_eq!(rgsc_me(addr, &ben, Some(RGSC_TENANT_B)).await, 200, "ben n'est pas révoqué par des gestes sur sa ligne homonyme de default");
        assert_eq!(rgsc_epoque_dans(&st.db.lock(), "rgsc-ben"), None, "aucune époque posée pour ben");
        assert_eq!(rgsc_epoque_dans(&rgsc_base(&st, RGSC_TENANT_B).lock(), "rgsc-ana"), None, "aucune époque posée dans B");

        let copie_d_ana = ana.clone();
        let r = rgsc_envoyer(addr, "POST", "/api/logout", None, &[("Cookie", format!("plume_session={ana}").as_str())], "").await;
        assert_eq!((r.statut, &r.corps), (200, &json!({ "ok": true, "portee": "compte" })), "{}", r.texte);
        for tenant in [RGSC_TENANT_A, RGSC_TENANT_B] {
            assert_eq!(rgsc_me(addr, &copie_d_ana, Some(tenant)).await, 401, "la copie du cookie d'ana ne vaut plus dans {tenant}");
        }
        assert_eq!(rgsc_me(addr, &ben, Some(RGSC_TENANT_B)).await, 200, "ben reste connecté");
        assert_eq!(epoque_du_compte(&st.db.lock(), "rgsc-ana").expect("époque lue"), 1, "l'époque du compte d'ana avance");
        assert_eq!(epoque_du_compte(&st.db.lock(), "rgsc-ben").expect("époque lue"), 0, "pas celle de ben");
        assert_eq!(rgsc_epoque_dans(&rgsc_base(&st, RGSC_TENANT_B).lock(), "rgsc-ana"), None, "l'époque n'est pas portée par la base d'un tenant");
    }

    /// CE QU'IL TIENT (`P10.24-e`, précision du lot 190) : mode multi-tenant avec plan de contrôle, `rgsc-ana` vise SA
    /// ligne dans A (`{password, current, role}`) avec son mot de passe de plateforme, puis avec un mot de passe faux :
    /// `409` les deux fois, corps exact ; rien n'est écrit (haché et rôle de la ligne inchangés), aucun échec compté,
    /// aucune ligne `password` au registre — le mot de passe actuel n'est jugé par AUCUNE résolution. CONTRÔLE POSITIF
    /// (mode multi-tenant SANS plan de contrôle, l'identité est alors la base unique) : un administrateur du SSO
    /// d'en-têtes réinitialise le mot de passe d'alice par la route -> `204`, le nouveau mot de passe est celui de sa
    /// ligne et son époque avance.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BA6_UU_SANS_REFUS » (le mot de passe actuel est jugé par la résolution du mode
    /// zéro : `403` « sans mot de passe local », la ligne de A n'étant pas dans `st.db`) ; « BA6_UU_CONDITION_MULTI » (le
    /// refus pris sur `multi_tenant` : le contrôle positif rend `409`).
    #[tokio::test]
    async fn rgsc_mode_1_le_mot_de_passe_d_une_ligne_de_tenant_n_est_ni_pose_ni_juge() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let ligne = rgsc_ligne(&st, RGSC_TENANT_A, "rgsc-ana", "editor", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        let ana = rgsc_basic("rgsc-ana", RGSC_MOT_DE_PASSE);
        let refus = json!({ "error": CAUSE_MOT_DE_PASSE_NON_POSE_IDENTITE_DE_PLATEFORME });
        let actuels = [RGSC_MOT_DE_PASSE, "ce-n-est-pas-le-mien-rgsc"];
        assert!(actuels.len() >= 2, "plancher");
        for actuel in actuels {
            let corps = json!({ "password": RGSC_MOT_DE_PASSE_NEUF, "current": actuel, "role": "viewer" }).to_string();
            let r = rgsc_envoyer(addr, "POST", &format!("/api/users/{ligne}"), Some(&ana), &[RGSC_JSON, ("x-plume-tenant", RGSC_TENANT_A), RGSC_SECRET], &corps).await;
            assert_eq!((r.statut, &r.corps), (409, &refus), "actuel « {actuel} » : {}", r.texte);
        }
        let (h, role): (String, String) = rgsc_base(&st, RGSC_TENANT_A).lock().query_row("SELECT hash, role FROM user WHERE id=?1", params![ligne], |r| Ok((r.get(0)?, r.get(1)?))).expect("ligne lue");
        assert!(verify_pw(RGSC_MOT_DE_PASSE_DE_LA_LIGNE, &h), "le haché de la ligne est inchangé");
        assert_eq!(role, "editor", "le rôle demandé dans le même corps n'est pas écrit");
        assert_eq!(st.auth_fails.lock().get(&("rgsc-ana".to_string(), "127.0.0.1".to_string())).map_or(0, |f| f.count), 0, "aucun échec compté");
        assert_eq!(rgsc_compter(&st.db.lock(), "SELECT COUNT(*) FROM ledger WHERE kind=?1", "password"), 0, "aucun refus de mot de passe inscrit");

        let (mut degrade, _p) = rgsc_mode_0("degrade");
        degrade.multi_tenant = true;
        assert!(degrade.tenants.control.is_none(), "fixture : aucun plan de contrôle");
        let addr = router_serve(degrade.clone()).await;
        let id_alice: i64 = degrade.db.lock().query_row("SELECT id FROM user WHERE name='rgsc-alice'", [], |r| r.get(0)).expect("fixture");
        let mut sso = rgsc_sso("rgsc-carol", "plume-admin");
        sso.extend([RGSC_JSON, RGSC_SECRET]);
        let r = rgsc_envoyer(addr, "POST", &format!("/api/users/{id_alice}"), None, &sso, &json!({ "password": RGSC_MOT_DE_PASSE_NEUF }).to_string()).await;
        assert_eq!(r.statut, 204, "contrôle positif, sans plan de contrôle : {}", r.texte);
        let h: String = degrade.db.lock().query_row("SELECT hash FROM user WHERE id=?1", params![id_alice], |r| r.get(0)).expect("lu");
        assert!(verify_pw(RGSC_MOT_DE_PASSE_NEUF, &h), "contrôle positif : le mot de passe est posé");
        assert_eq!(epoque_du_compte(&degrade.db.lock(), "rgsc-alice").expect("époque lue"), 1, "contrôle positif : ses sessions sont révoquées");
    }

    /// CE QU'IL TIENT (`P10.24-e`) : mode multi-tenant avec plan de contrôle, `/api/password` au routeur.
    ///  (a) CONTRÔLE POSITIF — l'administrateur de l'assistant `rgsc-wiz` (compte de plateforme homonyme SANS mot de
    ///      passe, droit admin sur A) change le sien par sa crédence d'assistant -> `200`, la crédence est la neuve.
    ///  (b) Le compte de plateforme homonyme reçoit un mot de passe : `rgsc-wiz` s'authentifie par lui et le présente comme
    ///      actuel -> `409`, corps exact `{error: CAUSE_MOT_DE_PASSE_DE_PLATEFORME}` ; la crédence d'assistant reste celle
    ///      de (a).
    ///  (c) `platform_user` illisible, `rgsc-wiz` servi par le SSO d'en-têtes -> `503`, corps exact
    ///      `{error: CAUSE_COMPTE_NON_LU_AU_CHANGEMENT, id}` ; la crédence d'assistant reste celle de (a).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BA6_PP_SANS_PLATEFORME » (la forme d'avant : (b) rend `200` et remplace la
    /// crédence de l'assistant) ; « BA6_PP_NULL_COMPTE » (un compte de plateforme sans mot de passe fait autorité : (a)
    /// rend `409`) ; « BA6_PP_LECTURE_AVALEE » (la lecture ratée vaut l'absence : (c) rend `403`).
    #[tokio::test]
    async fn rgsc_mode_1_le_mot_de_passe_de_l_assistant_et_son_homonyme_de_plateforme() {
        let (st, _dir) = rgsc_plateforme().await;
        *st.admin.lock() = Some(("rgsc-wiz".into(), hash_pw(RGSC_MOT_DE_PASSE).expect("hachage")));
        let plan = st.tenants.control.as_ref().expect("plan");
        ensure_platform_user(plan, "rgsc-wiz").expect("fixture : homonyme de plateforme");
        plan.conn
            .lock()
            .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) SELECT id,?1,'admin' FROM platform_user WHERE name='rgsc-wiz'", params![RGSC_TENANT_A])
            .expect("fixture : droit");
        let addr = router_serve(st.clone()).await;
        let tenant_a = ("x-plume-tenant", RGSC_TENANT_A);
        let assistant = || st.admin.lock().as_ref().map(|(_, h)| h.clone()).expect("crédence d'assistant");

        let corps = json!({ "current": RGSC_MOT_DE_PASSE, "new": RGSC_MOT_DE_PASSE_NEUF }).to_string();
        let r = rgsc_envoyer(addr, "POST", "/api/password", Some(&rgsc_basic("rgsc-wiz", RGSC_MOT_DE_PASSE)), &[RGSC_JSON, tenant_a], &corps).await;
        assert_eq!(r.statut, 200, "(a) contrôle positif : {}", r.texte);
        assert!(verify_pw(RGSC_MOT_DE_PASSE_NEUF, &assistant()), "(a) la crédence d'assistant est la neuve");

        plan.conn
            .lock()
            .execute("UPDATE platform_user SET hash=?1 WHERE name='rgsc-wiz'", params![hash_pw(RGSC_MOT_DE_PASSE_DE_PLATEFORME).expect("hachage")])
            .expect("fixture : mot de passe de plateforme");
        let corps = json!({ "current": RGSC_MOT_DE_PASSE_DE_PLATEFORME, "new": "un-autre-mot-de-passe-rgsc" }).to_string();
        let r = rgsc_envoyer(addr, "POST", "/api/password", Some(&rgsc_basic("rgsc-wiz", RGSC_MOT_DE_PASSE_DE_PLATEFORME)), &[RGSC_JSON, tenant_a], &corps).await;
        assert_eq!((r.statut, &r.corps), (409, &json!({ "error": CAUSE_MOT_DE_PASSE_DE_PLATEFORME })), "(b) : {}", r.texte);
        assert!(verify_pw(RGSC_MOT_DE_PASSE_NEUF, &assistant()), "(b) la crédence d'assistant n'est pas remplacée");

        plan.conn.lock().execute_batch("ALTER TABLE platform_user RENAME TO rgsc_platform_user_cache;").expect("fixture : illisible");
        let mut sso = rgsc_sso("rgsc-wiz", "plume-rgsca-admin");
        sso.extend([RGSC_JSON, tenant_a]);
        let r = rgsc_envoyer(addr, "POST", "/api/password", None, &sso, &json!({ "current": RGSC_MOT_DE_PASSE_NEUF, "new": "encore-un-autre-rgsc-1234" }).to_string()).await;
        plan.conn.lock().execute_batch("ALTER TABLE rgsc_platform_user_cache RENAME TO platform_user;").expect("fixture : remise");
        rgsc_cinq_cent_trois(&r, CAUSE_COMPTE_NON_LU_AU_CHANGEMENT);
        assert!(verify_pw(RGSC_MOT_DE_PASSE_NEUF, &assistant()), "(c) la crédence d'assistant n'est pas remplacée");
    }

    /// CE QU'IL TIENT (`P10.24-e`, précision du lot 192, JOUÉE) : mode multi-tenant avec plan de contrôle,
    /// administrateur de l'assistant `rgsc-wiz`. Dans le tenant `default` (sa base), `rgsc-dan` : rétrograder la ligne
    /// `rgsc-wiz` -> `400` `CAUSE_COMPTE_DE_L_ASSISTANT_NON_RETROGRADABLE_SOUS_PLAN_DE_CONTROLE`, la supprimer -> `400`
    /// `CAUSE_COMPTE_DE_L_ASSISTANT_NON_SUPPRIMABLE_SOUS_PLAN_DE_CONTROLE` (corps exacts ; le remède servi est celui qui
    /// tient sous un plan de contrôle — ses droits de tenant —, jamais « réinitialisez son mot de passe », geste que
    /// `user_update` y refuse en `409`) — sur la forme d'avant, aucun des deux ne jouait (la poignée du tenant `default`
    /// n'est pas `st.db`). MODE 0 : `rgsc-carol` (SSO d'en-têtes) rétrograde puis supprime l'administrateur de l'assistant `rgsc-adm` -> les
    /// causes du mode 0, au remède « réinitialisez son mot de passe ». Dans B, `rgsc-ben` : la rétrogradation de la ligne homonyme
    /// est refusée `409` (rôle d'une ligne de tenant, inerte sous un plan de contrôle) et la ligne se supprime (`200`). MODE 0 (contrôle de la suppression) : `rgsc-carol` supprime alice -> `200`, son époque avance.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BA6_BASE_ASSISTANT_PTR_SEUL » (la forme d'avant : `default` rend `204`/`200`) ;
    /// « BA6_BASE_ASSISTANT_TOUT_TENANT » (la suppression dans B rend `400`) ; « BA6_UD_EPOQUE_JAMAIS » (le mode 0 n'avance plus l'époque) ;
    /// « BA6C_CAUSE_MODE0 » (la forme du lot avant correction : sous un plan de contrôle, le remède impossible) ;
    /// « BA6C_CAUSE_PARTOUT » (le mode 0 reçoit le remède du plan de contrôle).
    #[tokio::test]
    async fn rgsc_mode_1_le_compte_de_l_assistant_est_borne_au_tenant_default() {
        let (st, _dir) = rgsc_plateforme().await;
        *st.admin.lock() = Some(("rgsc-wiz".into(), hash_pw(RGSC_MOT_DE_PASSE).expect("hachage")));
        let addr = router_serve(st.clone()).await;
        let mut ids = Vec::new();
        for tenant in ["default", RGSC_TENANT_B] {
            rgsc_ligne(&st, tenant, "rgsc-autre-admin", "admin", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
            ids.push((tenant, rgsc_ligne(&st, tenant, "rgsc-wiz", "admin", RGSC_MOT_DE_PASSE_DE_LA_LIGNE)));
        }
        let dan = rgsc_basic("rgsc-dan", RGSC_MOT_DE_PASSE);
        let ben = rgsc_basic("rgsc-ben", RGSC_MOT_DE_PASSE);
        let retrograder = json!({ "role": "viewer" }).to_string();
        let (_, id_default) = ids[0];
        let (_, id_b) = ids[1];
        let r = rgsc_envoyer(addr, "POST", &format!("/api/users/{id_default}"), Some(&dan), &[RGSC_JSON, ("x-plume-tenant", "default")], &retrograder).await;
        assert_eq!((r.statut, &r.corps), (400, &json!({ "error": CAUSE_COMPTE_DE_L_ASSISTANT_NON_RETROGRADABLE_SOUS_PLAN_DE_CONTROLE })), "default, rétrogradation : {}", r.texte);
        rgsc_remede_qui_tient_sous_plan_de_controle(&r);
        let r = rgsc_envoyer(addr, "DELETE", &format!("/api/users/{id_default}"), Some(&dan), &[("x-plume-tenant", "default")], "").await;
        assert_eq!((r.statut, &r.corps), (400, &json!({ "error": CAUSE_COMPTE_DE_L_ASSISTANT_NON_SUPPRIMABLE_SOUS_PLAN_DE_CONTROLE })), "default, suppression : {}", r.texte);
        rgsc_remede_qui_tient_sous_plan_de_controle(&r);
        assert_eq!(rgsc_compter(&st.db.lock(), "SELECT COUNT(*) FROM user WHERE name=?1 AND role='admin'", "rgsc-wiz"), 1, "la ligne de default reste administratrice");

        // INVERSÉ par la reprise de la vague BC (`P10.24-e`) : sous un plan de contrôle, le rôle d'une ligne d'un tenant
        // autre que `default` n'est lu par aucune résolution ; sa rétrogradation était servie `204` (ce témoin
        // l'affirmait), elle est refusée `409` `CAUSE_ROLE_NON_CHANGE_IDENTITE_DE_PLATEFORME`, et la ligne reste `admin`.
        let r = rgsc_envoyer(addr, "POST", &format!("/api/users/{id_b}"), Some(&ben), &[RGSC_JSON, ("x-plume-tenant", RGSC_TENANT_B)], &retrograder).await;
        assert_eq!((r.statut, &r.corps), (409, &json!({ "error": CAUSE_ROLE_NON_CHANGE_IDENTITE_DE_PLATEFORME })), "B, rétrogradation de l'homonyme : {}", r.texte);
        assert_eq!(rgsc_compter(&rgsc_base(&st, RGSC_TENANT_B).lock(), "SELECT COUNT(*) FROM user WHERE name=?1 AND role='admin'", "rgsc-wiz"), 1, "B : la ligne homonyme reste admin");
        let r = rgsc_envoyer(addr, "DELETE", &format!("/api/users/{id_b}"), Some(&ben), &[("x-plume-tenant", RGSC_TENANT_B)], "").await;
        assert_eq!(r.statut, 200, "B, suppression de l'homonyme : {}", r.texte);
        assert_eq!(rgsc_compter(&rgsc_base(&st, RGSC_TENANT_B).lock(), "SELECT COUNT(*) FROM user WHERE name=?1", "rgsc-wiz"), 0, "B : supprimée");

        let (st0, _p) = rgsc_mode_0("suppression-mode-0");
        let h_adm: String = st0.db.lock().query_row("SELECT hash FROM user WHERE name='rgsc-adm'", [], |r| r.get(0)).expect("fixture");
        *st0.admin.lock() = Some(("rgsc-adm".into(), h_adm));
        let addr = router_serve(st0.clone()).await;
        let id_adm: i64 = st0.db.lock().query_row("SELECT id FROM user WHERE name='rgsc-adm'", [], |r| r.get(0)).expect("fixture");
        // L'auteur est un administrateur du SSO d'en-têtes : l'administrateur de configuration `root` ne s'authentifie plus
        // une fois l'administrateur de l'assistant posé (mesuré : `401`).
        let mut carol = rgsc_sso("rgsc-carol", "plume-admin");
        carol.push(RGSC_JSON);
        let r = rgsc_envoyer(addr, "POST", &format!("/api/users/{id_adm}"), None, &carol, &retrograder).await;
        assert_eq!((r.statut, &r.corps), (400, &json!({ "error": CAUSE_COMPTE_DE_L_ASSISTANT_NON_RETROGRADABLE })), "mode 0, rétrogradation : {}", r.texte);
        let r = rgsc_envoyer(addr, "DELETE", &format!("/api/users/{id_adm}"), None, &carol, "").await;
        assert_eq!((r.statut, &r.corps), (400, &json!({ "error": CAUSE_COMPTE_DE_L_ASSISTANT_NON_SUPPRIMABLE })), "mode 0, suppression : {}", r.texte);
        for phrase in [CAUSE_COMPTE_DE_L_ASSISTANT_NON_RETROGRADABLE, CAUSE_COMPTE_DE_L_ASSISTANT_NON_SUPPRIMABLE] {
            assert!(phrase.ends_with("Pour lui retirer l'accès, réinitialisez son mot de passe : ses sessions tombent. Rien n'est écrit."), "mode 0 : le remède d'avant, à l'octet : {phrase}");
        }
        let id_alice: i64 = st0.db.lock().query_row("SELECT id FROM user WHERE name='rgsc-alice'", [], |r| r.get(0)).expect("fixture");
        let r = rgsc_envoyer(addr, "DELETE", &format!("/api/users/{id_alice}"), None, &carol, "").await;
        assert_eq!(r.statut, 200, "mode 0 : {}", r.texte);
        assert_eq!(epoque_du_compte(&st0.db.lock(), "rgsc-alice").expect("époque lue"), 1, "mode 0 : l'époque du compte supprimé avance (`P10.24-c`)");
    }

    // -------------------------------------------------------------------------------------
    // (3) CORRECTION APRÈS VÉRIFICATION
    // -------------------------------------------------------------------------------------

    /// Le remède servi sous un plan de contrôle : ses droits de tenant, jamais la réinitialisation que `user_update` y
    /// refuse — lu contre des littéraux du témoin, pas contre la constante.
    fn rgsc_remede_qui_tient_sous_plan_de_controle(r: &RgscReponse) {
        let phrase = r.corps["error"].as_str().unwrap_or_else(|| panic!("phrase servie : {}", r.texte));
        assert!(!phrase.contains("réinitialisez son mot de passe"), "le remède impossible sous un plan de contrôle est servi : {phrase}");
        for f in ["retirez ses droits de tenant", "/api/tenants/{id}/grants", "/api/password", "Rien n'est écrit."] {
            assert!(phrase.contains(f), "« {f} » absent de : {phrase}");
        }
    }

    /// `POST /api/logout` sous la portée `globale`, par le cookie `jeton` seul.
    pub(super) async fn rgsc_deconnexion_globale(addr: std::net::SocketAddr, jeton: &str) -> RgscReponse {
        let cookie = format!("plume_session={jeton}");
        rgsc_envoyer(addr, "POST", "/api/logout", None, &[("Cookie", cookie.as_str()), (PORTEE_DE_LA_DECONNEXION, "globale")], "").await
    }

    /// CE QU'IL TIENT (`P10.31-i`, seconde porte) : mode multi-tenant AVEC plan de contrôle, `POST /api/logout` sous la
    /// portée `globale`, au routeur. `rgsc-sa` se connecte super-administrateur (son jeton porte `admin`), puis est
    /// RÉTROGRADÉ dans le plan de contrôle : sa session reste ouverte (`/api/me` `200` dans A), mais la portée `globale`
    /// rend `403` corps exact `{error: CAUSE_DECONNEXION_GLOBALE_RESERVEE_A_UN_ADMIN}`, aucun cookie effacé, rien de
    /// révoqué ni d'inscrit, la session de ben résout encore. Re-promu : `200`, l'époque globale avance, la ligne de
    /// registre le nomme. L'administratrice d'un tenant (`rgsc-ana`) : `403`. CONTRÔLE POSITIF SANS plan de contrôle
    /// (aucun `platform_user` à relire) : le jeton `admin` d'`rgsc-adm` révoque (`200`), comme avant.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BA6C_LOGOUT_JETON » (la forme d'avant : le rôle porté par le jeton fait foi —
    /// le super-administrateur rétrogradé révoque tout le monde) ; « BA6C_LOGOUT_SANS_PLAN_LIVE » (la relecture appliquée
    /// sans plan de contrôle : le contrôle positif rend `403`).
    #[tokio::test]
    async fn rgsc_mode_1_la_portee_globale_de_la_deconnexion_relit_le_super_administrateur() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let ben = rgsc_connexion(addr, "rgsc-ben").await;
        let sa = rgsc_connexion(addr, "rgsc-sa").await;
        let ana = rgsc_connexion(addr, "rgsc-ana").await;
        let plan = st.tenants.control.as_ref().expect("plan");
        let reserve = json!({ "error": CAUSE_DECONNEXION_GLOBALE_RESERVEE_A_UN_ADMIN });

        let r = rgsc_deconnexion_globale(addr, &ana).await;
        assert_eq!((r.statut, &r.corps), (403, &reserve), "l'administratrice d'un tenant : {}", r.texte);

        plan.conn.lock().execute("UPDATE platform_user SET is_superadmin=0 WHERE name='rgsc-sa'", []).expect("fixture : rétrogradé");
        assert_eq!(rgsc_me(addr, &sa, Some(RGSC_TENANT_A)).await, 200, "fixture : la session de sa reste ouverte");
        let r = rgsc_deconnexion_globale(addr, &sa).await;
        assert_eq!((r.statut, &r.corps), (403, &reserve), "rétrogradé, relu à la requête : {}", r.texte);
        assert!(!r.cookie_efface(), "aucun cookie effacé sur un refus");
        assert_eq!(rgsc_epoques(&st), (0, 0), "rien n'est révoqué");
        assert!(rgsc_traces_globales(&st).is_empty(), "rien n'est inscrit");
        assert_eq!(rgsc_me(addr, &ben, Some(RGSC_TENANT_B)).await, 200, "ben reste connecté");

        plan.conn.lock().execute("UPDATE platform_user SET is_superadmin=1 WHERE name='rgsc-sa'", []).expect("fixture : re-promu");
        let r = rgsc_deconnexion_globale(addr, &sa).await;
        assert_eq!((r.statut, &r.corps), (200, &json!({ "ok": true, "portee": "globale" })), "contrôle positif : {}", r.texte);
        assert_eq!(rgsc_epoques(&st), (1, 1));
        assert_eq!(rgsc_traces_globales(&st), vec![rgsc_trace_attendue("rgsc-sa", 0)]);
        assert_eq!(rgsc_me(addr, &ben, Some(RGSC_TENANT_B)).await, 401, "la session de ben est révoquée");

        let (mut sans_plan, _p) = rgsc_mode_0("logout-sans-plan");
        sans_plan.multi_tenant = true;
        assert!(sans_plan.tenants.control.is_none(), "fixture : aucun plan de contrôle");
        let addr = router_serve(sans_plan.clone()).await;
        let adm = frapper_la_session_du_compte(&sans_plan, "rgsc-adm", "admin").expect("fixture : session d'adm");
        let r = rgsc_deconnexion_globale(addr, &adm).await;
        assert_eq!((r.statut, &r.corps), (200, &json!({ "ok": true, "portee": "globale" })), "sans plan de contrôle, le jeton admin : {}", r.texte);
        assert_eq!(rgsc_epoques(&sans_plan), (1, 1));
    }

    /// CE QU'IL TIENT (`P10.31-i`, réserve réelle du mode multi-tenant, JOUÉE) : `rbac_gate` juge le rôle PAR TENANT avant
    /// le gestionnaire. `rgsc-sv`, super-administrateur de la plateforme, LECTEUR de B : la route sous B rend `403` « lecture
    /// seule (rôle viewer) » ; sous A, dont il n'est pas membre, sans bris de glace : `403` (écriture inter-tenants
    /// interdite) ; sous A avec `X-Plume-Breakglass` : `200`, l'époque avance, la ligne de registre le nomme. Ce qui est
    /// joué ici est ce que dit `CAUSE_REVOCATION_GLOBALE_RESERVEE` : super-administrateur ET administrateur du tenant
    /// choisi, ou bris de glace dans un tenant dont il n'est pas membre.
    #[tokio::test]
    async fn rgsc_mode_1_la_reserve_reelle_du_super_administrateur() {
        let (st, _dir) = rgsc_plateforme().await;
        let plan = st.tenants.control.as_ref().expect("plan");
        ensure_platform_user(plan, "rgsc-sv").expect("fixture : compte de plateforme");
        {
            let c = plan.conn.lock();
            c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) SELECT id,?1,'viewer' FROM platform_user WHERE name='rgsc-sv'", params![RGSC_TENANT_B]).expect("fixture : droit");
            c.execute("UPDATE platform_user SET hash=?1, is_superadmin=1 WHERE name='rgsc-sv'", params![hash_pw(RGSC_MOT_DE_PASSE).expect("hachage")]).expect("fixture");
        }
        let addr = router_serve(st.clone()).await;
        let sv = rgsc_basic("rgsc-sv", RGSC_MOT_DE_PASSE);

        let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, Some(&sv), &[("x-plume-tenant", RGSC_TENANT_B)], "").await;
        assert_eq!((r.statut, &r.corps), (403, &json!("lecture seule (rôle viewer)")), "lecteur de B : {}", r.texte);
        let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, Some(&sv), &[("x-plume-tenant", RGSC_TENANT_A)], "").await;
        assert_eq!(r.statut, 403, "non-membre de A sans bris de glace : {}", r.texte);
        assert!(r.texte.contains("break-glass"), "le refus nomme le bris de glace : {}", r.texte);
        assert_eq!(rgsc_epoques(&st), (0, 0), "rien n'est révoqué");
        assert!(rgsc_traces_globales(&st).is_empty());

        let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, Some(&sv), &[("x-plume-tenant", RGSC_TENANT_A), ("x-plume-breakglass", "incident rgsc")], "").await;
        assert_eq!((r.statut, &r.corps), (200, &json!({ "ok": true, "portee": "globale" })), "bris de glace dans A : {}", r.texte);
        assert_eq!(rgsc_epoques(&st), (1, 1));
        assert_eq!(rgsc_traces_globales(&st), vec![rgsc_trace_attendue("rgsc-sv", 0)]);
    }

    /// CE QU'IL TIENT (`P10.24-e`, création) : mode multi-tenant avec plan de contrôle, `POST /api/users` au routeur.
    /// `rgsc-dan` (administrateur de `default`) puis `rgsc-ben` (administrateur de B) créent `rgsc-neuf` avec le secret des
    /// gestes juste, puis avec un secret FAUX : la connexion de `rgsc-neuf` par ce mot de passe rend `401`, et la création
    /// `409`, corps exact `{error: CAUSE_COMPTE_NON_CREE_IDENTITE_DE_PLATEFORME}` ; aucune ligne `rgsc-neuf` dans
    /// `default` ni dans B, aucune ligne `config.user.create` ni `secret_des_gestes` au registre du tenant visé ni à celui de
    /// `st.db` (le secret n'est pas examiné). CONTRÔLE POSITIF (mode 0) : `root` crée `rgsc-neuf` -> `200`, la ligne existe.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BA6C_UC_SANS_REFUS » (la forme d'avant : `200`, la ligne posée avec son haché,
    /// et la connexion rend quand même `401`) ; « BA6C_UC_REFUS_PARTOUT » (le refus pris en mode 0 : le contrôle positif
    /// rend `409`).
    #[tokio::test]
    async fn rgsc_mode_1_un_compte_ne_se_cree_pas_dans_une_ligne_de_tenant() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let refus = json!({ "error": CAUSE_COMPTE_NON_CREE_IDENTITE_DE_PLATEFORME });
        let corps = json!({ "name": "rgsc-neuf", "password": RGSC_MOT_DE_PASSE_NEUF, "role": "viewer" }).to_string();
        let faux = (ENTETE_DU_SECRET_DES_GESTES, "ce-n-est-pas-le-secret-rgsc");
        for (auteur, tenant) in [("rgsc-dan", "default"), ("rgsc-ben", RGSC_TENANT_B)] {
            for secret in [RGSC_SECRET, faux] {
                let r = rgsc_envoyer(addr, "POST", "/api/users", Some(&rgsc_basic(auteur, RGSC_MOT_DE_PASSE)), &[RGSC_JSON, ("x-plume-tenant", tenant), secret], &corps).await;
                let connexion = rgsc_envoyer(addr, "POST", "/api/login", None, &[RGSC_JSON], &json!({ "user": "rgsc-neuf", "pass": RGSC_MOT_DE_PASSE_NEUF }).to_string()).await;
                assert_eq!(connexion.statut, 401, "{auteur} : le compte d'une ligne de tenant ne se connecte pas : {}", connexion.texte);
                assert_eq!((r.statut, &r.corps), (409, &refus), "{auteur} dans {tenant} ({}) : {}", secret.1, r.texte);
            }
            assert_eq!(rgsc_compter(&rgsc_base(&st, tenant).lock(), "SELECT COUNT(*) FROM user WHERE name=?1", "rgsc-neuf"), 0, "{tenant} : aucune ligne posée");
            // Le registre du tenant VISÉ (celui où la création aurait écrit sa ligne `config.user.create`), et celui de
            // `st.db` (la base du compte) : aucun des deux ne porte la création ni l'examen du secret.
            for kind in ["config.user.create", "secret_des_gestes"] {
                assert_eq!(rgsc_compter(&rgsc_base(&st, tenant).lock(), "SELECT COUNT(*) FROM ledger WHERE kind=?1", kind), 0, "{tenant} : aucune ligne `{kind}` au registre du tenant");
                assert_eq!(rgsc_compter(&st.db.lock(), "SELECT COUNT(*) FROM ledger WHERE kind=?1", kind), 0, "{tenant} : aucune ligne `{kind}` au registre de st.db");
            }
        }

        let (st0, _p) = rgsc_mode_0("creation-mode-0");
        let addr = router_serve(st0.clone()).await;
        let r = rgsc_envoyer(addr, "POST", "/api/users", Some(&rgsc_basic("root", "rootpw1234567")), &[RGSC_JSON, RGSC_SECRET], &corps).await;
        assert_eq!(r.statut, 200, "contrôle positif, mode 0 : {}", r.texte);
        assert_eq!(rgsc_compter(&st0.db.lock(), "SELECT COUNT(*) FROM user WHERE name=?1", "rgsc-neuf"), 1, "contrôle positif : la ligne existe");
    }

    // -------------------------------------------------------------------------------------
    // (4) MODE MULTI-TENANT DÉGRADÉ : `PLUME_MULTI_TENANT=1` ET PLAN DE CONTRÔLE NON INITIALISÉ
    // -------------------------------------------------------------------------------------

    /// Le mode dégradé RÉEL de `server/mod.rs` (initialisation du plan de contrôle échouée : « l'identité retombe sur la base
    /// unique »), fabriqué par l'ÉTAT : la base du mode 0 de ce fichier, `multi_tenant` vrai, aucun plan de contrôle. Le
    /// SSO d'en-têtes y résout les droits par les groupes (`rbac::sso_grants`), et toute base de tenant est `st.db`
    /// (`TenantDbManager::handle_for` sans plan rend l'écrivain par défaut).
    fn rgsc_mode_degrade(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (mut st, p) = rgsc_mode_0(tag);
        st.multi_tenant = true;
        assert!(st.tenants.control.is_none(), "fixture : aucun plan de contrôle");
        assert!(Arc::ptr_eq(&st.tenants.handle_for("default").expect("fixture : base"), &st.db), "fixture : la base du tenant `default` est st.db");
        (st, p)
    }

    /// Le remède du mode 0, lu contre un littéral du témoin : « réinitialisez son mot de passe », jamais les droits de
    /// tenant, dont les routes exigent un plan de contrôle absent ici.
    fn rgsc_remede_du_mode_0(r: &RgscReponse) {
        let phrase = r.corps["error"].as_str().unwrap_or_else(|| panic!("phrase servie : {}", r.texte));
        assert!(phrase.ends_with("Pour lui retirer l'accès, réinitialisez son mot de passe : ses sessions tombent. Rien n'est écrit."), "remède du mode 0 attendu : {phrase}");
        for f in ["/api/tenants/{id}/grants", "retirez ses droits de tenant", "mode multi-tenant"] {
            assert!(!phrase.contains(f), "« {f} » servi sans plan de contrôle : {phrase}");
        }
    }

    /// CE QU'IL TIENT (`P10.24-e`, mode dégradé, par le routeur) : sans plan de contrôle, les comptes sont ceux de la base
    /// unique et les gestes de compte suivent le mode 0, site par site.
    ///  (a) `user_create` : `rgsc-carol` (SSO d'en-têtes, administratrice de `default`) crée `rgsc-neuf` avec le secret des
    ///      gestes -> `200` ; la ligne est dans `st.db` avec son haché, une ligne `config.user.create` au registre, et
    ///      `rgsc-neuf` se connecte par ce mot de passe (`200`, cookie posé) — aucun refus « identité de plateforme ».
    ///  (b) `user_delete` : la session d'alice frappée, `rgsc-carol` supprime alice -> `200` ; l'époque du compte d'alice
    ///      passe de 0 à 1 (sa session est révoquée, `P10.24-c`).
    ///  (c) Le compte de l'assistant (`rgsc-adm`) : rétrogradé -> `400` `CAUSE_COMPTE_DE_L_ASSISTANT_NON_RETROGRADABLE`,
    ///      supprimé -> `400` `CAUSE_COMPTE_DE_L_ASSISTANT_NON_SUPPRIMABLE` (corps exacts, remède du mode 0 lu contre un
    ///      littéral) ; la ligne reste administratrice.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR, chacune remplaçant la condition d'UN site par `st.multi_tenant` :
    /// « BB3_UC_COND_MULTI » (création refusée en `409`) ; « BB3_UD_EPOQUE_COND_MULTI » (époque d'alice laissée à 0) ;
    /// « BB3_UD_CAUSE_COND_MULTI » (suppression : remède du plan de contrôle servi) ; « BB3_UU_CAUSE_COND_MULTI »
    /// (rétrogradation : remède du plan de contrôle servi).
    #[tokio::test]
    async fn rgsc_mode_degrade_les_gestes_de_compte_suivent_le_mode_0() {
        let (st, _p) = rgsc_mode_degrade("degrade-comptes");
        let addr = router_serve(st.clone()).await;
        let mut carol = rgsc_sso("rgsc-carol", "plume-admin");
        carol.push(RGSC_JSON);

        let mut avec_secret = carol.clone();
        avec_secret.push(RGSC_SECRET);
        let corps = json!({ "name": "rgsc-neuf", "password": RGSC_MOT_DE_PASSE_NEUF, "role": "viewer" }).to_string();
        let r = rgsc_envoyer(addr, "POST", "/api/users", None, &avec_secret, &corps).await;
        assert_eq!(r.statut, 200, "(a) création sans plan de contrôle : {}", r.texte);
        let h: String = st.db.lock().query_row("SELECT hash FROM user WHERE name='rgsc-neuf'", [], |r| r.get(0)).expect("(a) la ligne est posée dans st.db");
        assert!(verify_pw(RGSC_MOT_DE_PASSE_NEUF, &h), "(a) son haché est celui du mot de passe demandé");
        assert_eq!(rgsc_compter(&st.db.lock(), "SELECT COUNT(*) FROM ledger WHERE kind=?1", "config.user.create"), 1, "(a) la création est inscrite");
        let connexion = rgsc_envoyer(addr, "POST", "/api/login", None, &[RGSC_JSON], &json!({ "user": "rgsc-neuf", "pass": RGSC_MOT_DE_PASSE_NEUF }).to_string()).await;
        assert_eq!(connexion.statut, 200, "(a) le compte créé se connecte : {}", connexion.texte);
        assert!(connexion.cookie_pose().is_some(), "(a) un cookie de session est posé : {}", connexion.texte);

        frapper_la_session_du_compte(&st, "rgsc-alice", "editor").expect("fixture : session d'alice");
        assert_eq!(epoque_du_compte(&st.db.lock(), "rgsc-alice").expect("époque lue"), 0, "fixture : époque d'alice");
        let id_alice: i64 = st.db.lock().query_row("SELECT id FROM user WHERE name='rgsc-alice'", [], |r| r.get(0)).expect("fixture");
        let r = rgsc_envoyer(addr, "DELETE", &format!("/api/users/{id_alice}"), None, &carol, "").await;
        assert_eq!(r.statut, 200, "(b) suppression sans plan de contrôle : {}", r.texte);
        assert_eq!(epoque_du_compte(&st.db.lock(), "rgsc-alice").expect("époque lue"), 1, "(b) l'époque du compte supprimé avance");

        let h_adm: String = st.db.lock().query_row("SELECT hash FROM user WHERE name='rgsc-adm'", [], |r| r.get(0)).expect("fixture");
        *st.admin.lock() = Some(("rgsc-adm".into(), h_adm));
        let id_adm: i64 = st.db.lock().query_row("SELECT id FROM user WHERE name='rgsc-adm'", [], |r| r.get(0)).expect("fixture");
        let r = rgsc_envoyer(addr, "POST", &format!("/api/users/{id_adm}"), None, &carol, &json!({ "role": "viewer" }).to_string()).await;
        assert_eq!((r.statut, &r.corps), (400, &json!({ "error": CAUSE_COMPTE_DE_L_ASSISTANT_NON_RETROGRADABLE })), "(c) rétrogradation : {}", r.texte);
        rgsc_remede_du_mode_0(&r);
        let r = rgsc_envoyer(addr, "DELETE", &format!("/api/users/{id_adm}"), None, &carol, "").await;
        assert_eq!((r.statut, &r.corps), (400, &json!({ "error": CAUSE_COMPTE_DE_L_ASSISTANT_NON_SUPPRIMABLE })), "(c) suppression : {}", r.texte);
        rgsc_remede_du_mode_0(&r);
        assert_eq!(rgsc_compter(&st.db.lock(), "SELECT COUNT(*) FROM user WHERE name=?1 AND role='admin'", "rgsc-adm"), 1, "(c) la ligne reste administratrice");
    }

    /// CE QU'IL TIENT (`P10.31-i`, mode dégradé, par le routeur) : `revocation_globale_post` juge sur `multi_tenant`, et
    /// non sur le plan de contrôle, À DESSEIN. Sans plan, chaque tenant que les groupes SSO ouvrent EST la base unique
    /// (`handle_for`) : un administrateur de tenant y révoquerait les sessions de tous. `rgsc-carol` (administratrice de
    /// `default` par `plume-admin`, pas super-administratrice) -> `403`, corps exact `{error:
    /// CAUSE_REVOCATION_GLOBALE_RESERVEE}`, rien n'est révoqué ni inscrit ; `rgsc-sso-sa` (groupes `admins,plume-admin`,
    /// super-administrateur) -> `200`, l'époque globale avance (mémoire et disque), la ligne de registre le nomme.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « BB3_RG_COND_PLAN » (la réserve prise sur le plan de contrôle : sans plan,
    /// l'administratrice d'un tenant révoque tout — `200`).
    #[tokio::test]
    async fn rgsc_mode_degrade_la_revocation_globale_reste_au_super_administrateur() {
        let (st, _p) = rgsc_mode_degrade("degrade-revocation");
        let addr = router_serve(st.clone()).await;
        let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, None, &rgsc_sso("rgsc-carol", "plume-admin"), "").await;
        assert_eq!((r.statut, &r.corps), (403, &json!({ "error": CAUSE_REVOCATION_GLOBALE_RESERVEE })), "administratrice de tenant : {}", r.texte);
        assert!(!r.cookie_efface(), "aucun cookie effacé sur un refus");
        assert_eq!(rgsc_epoques(&st), (0, 0), "rien n'est révoqué");
        assert!(rgsc_traces_globales(&st).is_empty(), "rien n'est inscrit");

        let r = rgsc_envoyer(addr, "POST", RGSC_ROUTE, None, &rgsc_sso("rgsc-sso-sa", "admins,plume-admin"), "").await;
        assert_eq!((r.statut, &r.corps), (200, &json!({ "ok": true, "portee": "globale" })), "super-administrateur : {}", r.texte);
        assert_eq!(rgsc_epoques(&st), (1, 1), "l'époque globale avance");
        assert_eq!(rgsc_traces_globales(&st), vec![rgsc_trace_attendue("rgsc-sso-sa", 0)]);
    }
}
