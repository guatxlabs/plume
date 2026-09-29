// =====================================================================================
// `P10.24-m` — LE SECRET DES GESTES : le DROIT ne suffit plus pour créer un compte, promouvoir un administrateur,
//   réinitialiser le mot de passe d'un autre compte, frapper un jeton ou une clé de livraison, poser ou reconfigurer
//   un fournisseur d'identité, poser un droit de tenant ou le premier administrateur d'un tenant. Un secret dédié,
//   dont le démon ne connaît que l'empreinte argon2id (fichier `PLUME_GESTURE_SECRET_FILE`, relu à chaque geste),
//   est exigé AVANT toute écriture, quel que soit le mode d'authentification ; sans fichier, un refus NOMMÉ.
// `P10.28-h` — sous la démonstration publique, un essai Basic FAUX reste un ÉCHEC compté (frein -> 429).
// `P10.29-i` — `poser_l_administrateur` ouvre par la forme commune d'un geste ; `/api/setup` rend un 503 nommé.
// `P10.20-u` — `ref_non_lu_cause` à côté de `ref_non_lu` ; `collectors_etat` sépare `interrompu` et `non_commence`.
//
// CE QUE CE LOT NE TIENT PAS (écrit pour être opposable) :
//   * la console (`web/`) : ni l'invite du secret, ni la lecture de `ref_non_lu_cause` / `collectors_etat` — un autre
//     lot, sur le contrat fixé (en-tête `x-plume-secret-des-gestes`, `cause` ∈ trois clés) ;
//   * la voie cookie n'est pas jouée par le routeur ici (le CSRF en ferait un banc à part) : le jugement vit DANS le
//     gestionnaire, après le garde, donc la méthode d'authentification n'y entre pas — Basic et SSO d'en-têtes le
//     prouvent au routeur ;
//   * les gestes du mode multi-tenant (`grant_set`, `tenant_create` avec `admin`) sont gardés par le même appel, mais
//     leurs témoins de refus ne sont pas écrits ici (mode jamais activé en production) ;
//   * la sous-commande `secret-des-gestes` n'est pas jouée de bout en bout (entrée standard) : son hachage et le
//     jugement de l'empreinte le sont.
// =====================================================================================
mod secret_des_gestes_demonstration_freinee_et_pose_de_l_administrateur {
    use super::*;
    use crate::secret_des_gestes::{
        SecretDesGestesPresente, SourceDuSecretDesGestes, CAUSE_SECRET_DES_GESTES_ABSENT, CAUSE_SECRET_DES_GESTES_FAUX,
        CAUSE_SECRET_DES_GESTES_NON_CONFIGURE, ENTETE_DU_SECRET_DES_GESTES, SECRET_DES_GESTES_DE_TEST,
    };

    const SDG_MOT_DE_PASSE_DE_FIXTURE: &str = "motdepasse12345";
    const SDG_SECRET_SSO: &str = "secret-de-bord-sdg";

    async fn sdg_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| json!({ "_texte": String::from_utf8_lossy(&b) })))
    }

    fn sdg_sans_secret() -> SecretDesGestesPresente {
        SecretDesGestesPresente { valeur: None, ip: "127.0.0.1".into() }
    }

    fn sdg_avec(secret: &str) -> SecretDesGestesPresente {
        SecretDesGestesPresente { valeur: Some(secret.into()), ip: "127.0.0.1".into() }
    }

    fn sdg_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn sdg_id(st: &AppState, nom: &str) -> i64 {
        st.db.lock().query_row("SELECT id FROM user WHERE name=?1", params![nom], |r| r.get(0)).expect("compte de fixture")
    }

    fn sdg_hachage(st: &AppState, nom: &str) -> String {
        st.db.lock().query_row("SELECT hash FROM user WHERE name=?1", params![nom], |r| r.get(0)).expect("compte de fixture")
    }

    async fn sdg_creer(st: &AppState, presente: SecretDesGestesPresente, nom: &str, role: &str) -> (u16, Value) {
        sdg_corps(
            user_create(
                State(st.clone()),
                presente,
                Extension(sp_au("adm", "admin")),
                Json(json!({ "name": nom, "password": format!("{nom}-{}", "m".repeat(PASSWORD_MIN_CHARS)), "role": role })),
            )
            .await,
        )
        .await
    }

    async fn sdg_modifier(st: &AppState, presente: SecretDesGestesPresente, cible: &str, corps: Value) -> (u16, Value) {
        let id = sdg_id(st, cible);
        sdg_corps(
            user_update(
                State(st.clone()),
                presente,
                ConnectInfo("127.0.0.1:45454".parse().expect("adresse de test")),
                Extension(sp_au("adm", "admin")),
                axum::extract::Path(id),
                Json(corps),
            )
            .await,
        )
        .await
    }

    fn sdg_config_oidc() -> Value {
        json!({ "issuer": "https://idp.exemple.invalid", "client_id": "plume", "redirect_uri": "https://plume.exemple.invalid/api/auth/oidc/callback" })
    }

    fn sdg_refus(statut: u16, v: &Value, cause: &str, geste: &str) {
        assert_eq!(statut, 403, "{geste} : 403 attendu, lu {v}");
        assert_eq!(v["cause"], json!(cause), "{geste} : la cause du contrat, lue {v}");
        assert!(v["error"].as_str().is_some_and(|t| !t.is_empty()), "{geste} : une phrase humaine sous `error` : {v}");
    }

    // -------------------------------------------------------------------------------------
    // `P10.24-m` (1) — SANS SECRET CONFIGURÉ, CHAQUE GESTE GARDÉ EST REFUSÉ, NOMMÉ, ET N'ÉCRIT RIEN.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la source non configurée (le cas de TOUT déploiement qui n'a pas posé le fichier) refuse les
    /// sept gestes gardés du mode 0 en 403 `secret_des_gestes_non_configure`, avec une phrase qui dit COMMENT poser le
    /// secret, et RIEN n'est écrit (comptes, rôle, haché, jetons, connecteurs, fournisseurs relus en base). Contrôle
    /// positif : le même état, rétrograder un compte (geste qui n'ouvre rien) passe.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : rendre `Ok(())` dans la branche `Err(raison)` de `exiger_le_secret_des_gestes`
    /// (le repli permissif que la décision refuse) — la création rend 200 et le compte naît.
    #[tokio::test]
    async fn sdg_sans_secret_configure_chaque_geste_garde_est_refuse_nomme_et_n_ecrit_rien() {
        let (mut st, _tmp) = sp_state("sdg-non-configure");
        st.secret_des_gestes = Arc::new(SourceDuSecretDesGestes::NonConfiguree);
        let adm = || Extension(sp_au("adm", "admin"));
        let comptes_avant = sdg_compte(&st, "SELECT COUNT(*) FROM user");
        let hachage_avant = sdg_hachage(&st, "alice");

        let (s, v) = sdg_creer(&st, crate::secret_des_gestes::presente_de_test(), "sdg-x", "admin").await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_NON_CONFIGURE, "création d'un administrateur");
        let phrase = v["error"].as_str().unwrap_or_default();
        assert!(phrase.contains("PLUME_GESTURE_SECRET_FILE") && phrase.contains("secret-des-gestes --generer"), "le refus dit comment poser le secret : {phrase}");
        let (s, v) = sdg_creer(&st, crate::secret_des_gestes::presente_de_test(), "sdg-y", "viewer").await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_NON_CONFIGURE, "création d'un lecteur");
        let (s, v) = sdg_modifier(&st, crate::secret_des_gestes::presente_de_test(), "alice", json!({ "role": "admin" })).await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_NON_CONFIGURE, "promotion");
        let (s, v) = sdg_modifier(&st, crate::secret_des_gestes::presente_de_test(), "alice", json!({ "password": "nouveau-mot-de-passe-long" })).await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_NON_CONFIGURE, "réinitialisation d'un autre compte");
        let (s, v) = sdg_corps(
            token_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), adm(), Json(json!({ "name": "sdg-t", "kind": "agent", "host": "h1" }))).await,
        )
        .await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_NON_CONFIGURE, "frappe d'un jeton");
        let (s, v) = sdg_corps(
            connector_push_source(State(st.clone()), crate::secret_des_gestes::presente_de_test(), adm(), Json(json!({ "preset_id": "aws-cloudtrail" }))).await,
        )
        .await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_NON_CONFIGURE, "clé de livraison");
        let (s, v) = sdg_corps(
            idp_provider_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), adm(), Json(json!({ "name": "sdg-o", "kind": "oidc", "config": sdg_config_oidc() })))
                .await,
        )
        .await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_NON_CONFIGURE, "fournisseur d'identité");

        // ÉTAT RELU : rien n'est écrit.
        assert_eq!(sdg_compte(&st, "SELECT COUNT(*) FROM user"), comptes_avant, "aucun compte créé");
        assert_eq!(sdg_compte(&st, "SELECT COUNT(*) FROM user WHERE name='alice' AND role='editor'"), 1, "alice n'est pas promue");
        assert_eq!(sdg_hachage(&st, "alice"), hachage_avant, "le mot de passe d'alice n'a pas changé");
        assert_eq!(sdg_compte(&st, "SELECT COUNT(*) FROM token"), 0, "aucun jeton ni clé de livraison");
        assert_eq!(sdg_compte(&st, "SELECT COUNT(*) FROM connector"), 0, "aucun connecteur push");
        assert_eq!(sdg_compte(&st, "SELECT COUNT(*) FROM idp_provider"), 0, "aucun fournisseur d'identité");

        // CONTRÔLE POSITIF — un geste qui n'ouvre rien (rétrograder) ne demande pas le secret.
        let (s, v) = sdg_modifier(&st, sdg_sans_secret(), "alice", json!({ "role": "viewer" })).await;
        assert_eq!(s, 204, "rétrograder n'exige pas le secret : {v}");
    }

    // -------------------------------------------------------------------------------------
    // `P10.24-m` (2) — ABSENT, FAUX, BON ; LE FAUX COMPTE AU FREIN ET S'INSCRIT AU REGISTRE AVEC L'AUTEUR.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sans en-tête -> 403 `absent`, rien n'est compté ni écrit ; faux -> 403 `faux`, l'échec compté
    /// au frein du couple (auteur, adresse), une ligne au registre qui nomme l'auteur et NE porte PAS le secret
    /// présenté, rien d'écrit ; bon -> 200 et le compte existe. Puis `lock_threshold` essais faux, et le BON secret
    /// reçoit 429 : le frein mord avant l'examen.
    ///
    /// LES MUTATIONS QUI LE FERAIENT ROUGIR : retirer `auth_record_failure` de la branche du faux (le 429 n'arrive
    /// jamais) ; comparer `secret` à l'empreinte par `==` au lieu de `verify_pw` (le bon secret est refusé).
    #[tokio::test]
    async fn sdg_absent_faux_bon_et_le_faux_compte_au_frein_et_au_registre() {
        let (st, _tmp) = sp_state("sdg-frein");
        let (s, v) = sdg_creer(&st, sdg_sans_secret(), "sdg-a", "admin").await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_ABSENT, "sans en-tête");
        assert!(st.auth_fails.lock().is_empty(), "un en-tête absent n'est pas un essai : rien n'est compté");

        let faux = "ce-n-est-pas-le-bon-secret-sdg";
        let (s, v) = sdg_creer(&st, sdg_avec(faux), "sdg-a", "admin").await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_FAUX, "secret faux");
        assert_eq!(
            st.auth_fails.lock().get(&("<secret-des-gestes:adm>".to_string(), "127.0.0.1".to_string())).map(|f| f.count),
            Some(1),
            "l'échec est compté au frein du couple (auteur, adresse)"
        );
        let traces: Vec<String> = st
            .db
            .lock()
            .prepare("SELECT detail FROM ledger WHERE kind='secret_des_gestes'")
            .and_then(|mut s| s.query_map([], |r| r.get::<_, String>(0))?.collect())
            .expect("registre lisible");
        assert_eq!(traces.len(), 1, "une ligne au registre : {traces:?}");
        assert!(traces[0].contains("'adm'"), "le registre nomme l'auteur : {traces:?}");
        assert!(!traces[0].contains(faux), "le registre ne porte JAMAIS le secret présenté : {traces:?}");
        assert_eq!(sdg_compte(&st, "SELECT COUNT(*) FROM user WHERE name='sdg-a'"), 0, "rien n'est écrit sur un secret faux");

        let (s, v) = sdg_creer(&st, crate::secret_des_gestes::presente_de_test(), "sdg-a", "admin").await;
        assert_eq!(s, 200, "le droit ET le secret : le geste passe ({v})");
        assert_eq!(sdg_compte(&st, "SELECT COUNT(*) FROM user WHERE name='sdg-a' AND role='admin'"), 1);

        for i in 0..st.lock_threshold {
            let (s, v) = sdg_creer(&st, sdg_avec(faux), &format!("sdg-f{i}"), "viewer").await;
            assert_eq!(s, 403, "essai faux {i} : {v}");
        }
        let (s, v) = sdg_creer(&st, crate::secret_des_gestes::presente_de_test(), "sdg-b", "viewer").await;
        assert_eq!(s, 429, "au-delà du seuil, le frein mord — même le bon secret n'est pas examiné : {v}");
        assert_eq!(sdg_compte(&st, "SELECT COUNT(*) FROM user WHERE name='sdg-b'"), 0);
    }

    // -------------------------------------------------------------------------------------
    // `P10.24-m` (3) — CE QUI N'OUVRE RIEN RESTE OUVERT ; CE QUI OUVRE EST GARDÉ, GESTE PAR GESTE.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sans en-tête, la promotion et la réinitialisation d'un autre compte sont refusées (`absent`),
    /// le jeton, la clé de livraison et le fournisseur aussi ; la DÉSACTIVATION seule d'un fournisseur passe (retirer
    /// une voie compromise n'attend pas le secret) mais son ACTIVATION est refusée.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : faire rendre `true` à `est_une_desactivation_seule` (l'activation passe), ou
    /// retirer la condition `mot_de_passe_d_autrui` (la réinitialisation passe sans secret).
    #[tokio::test]
    async fn sdg_chaque_geste_qui_ouvre_est_garde_et_la_desactivation_seule_reste_ouverte() {
        let (st, _tmp) = sp_state("sdg-gestes");
        let adm = || Extension(sp_au("adm", "admin"));
        let (s, v) = sdg_modifier(&st, sdg_sans_secret(), "alice", json!({ "role": "admin" })).await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_ABSENT, "promotion");
        let (s, v) = sdg_modifier(&st, sdg_sans_secret(), "bob", json!({ "password": "nouveau-mot-de-passe-long" })).await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_ABSENT, "réinitialisation d'un autre compte");
        let (s, v) =
            sdg_corps(token_create(State(st.clone()), sdg_sans_secret(), adm(), Json(json!({ "name": "sdg-t", "kind": "datasource" }))).await).await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_ABSENT, "jeton de source de données");
        let (s, v) =
            sdg_corps(connector_push_source(State(st.clone()), sdg_sans_secret(), adm(), Json(json!({ "preset_id": "aws-cloudtrail" }))).await).await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_ABSENT, "clé de livraison");

        let (s, v) = sdg_corps(
            idp_provider_create(
                State(st.clone()),
                crate::secret_des_gestes::presente_de_test(),
                adm(),
                Json(json!({ "name": "sdg-o", "kind": "oidc", "config": sdg_config_oidc(), "enabled": true })),
            )
            .await,
        )
        .await;
        assert_eq!(s, 200, "création avec le secret : {v}");
        let id = v["id"].as_i64().expect("identifiant du fournisseur");
        let (s, v) = sdg_corps(
            idp_provider_update(State(st.clone()), sdg_sans_secret(), adm(), axum::extract::Path(id), Json(json!({ "enabled": false }))).await,
        )
        .await;
        assert_eq!(s, 200, "la désactivation seule reste ouverte sans le secret : {v}");
        let (s, v) = sdg_corps(
            idp_provider_update(State(st.clone()), sdg_sans_secret(), adm(), axum::extract::Path(id), Json(json!({ "enabled": true }))).await,
        )
        .await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_ABSENT, "activation d'un fournisseur");
        let (s, v) = sdg_corps(
            idp_provider_update(State(st.clone()), sdg_sans_secret(), adm(), axum::extract::Path(id), Json(json!({ "enabled": false, "config": sdg_config_oidc() }))).await,
        )
        .await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_ABSENT, "désactivation qui reconfigure");
        assert_eq!(sdg_compte(&st, "SELECT COUNT(*) FROM idp_provider WHERE enabled=0"), 1, "le fournisseur reste désactivé");
    }

    // -------------------------------------------------------------------------------------
    // `P10.24-m` (4) — LE FICHIER EST RELU À CHAQUE GESTE : ROTATION PAR REMPLACEMENT, RETRAIT, CLAIR REFUSÉ.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une source `Fichier` ; l'empreinte de A écrite -> A passe ; le fichier remplacé par l'empreinte
    /// de B -> A est FAUX et B passe, sans redémarrage ; le secret écrit EN CLAIR -> non configuré (jamais comparé tel
    /// quel) ; le fichier retiré -> non configuré.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : lire le fichier une fois (mettre l'empreinte en cache au premier geste) —
    /// A passe encore après la rotation.
    #[tokio::test]
    async fn sdg_le_fichier_est_relu_a_chaque_geste_rotation_retrait_et_clair_refuse() {
        let (mut st, _tmp) = sp_state("sdg-fichier");
        let dossier = crate::tmp_possede::TmpPossede::neuf("sdg-secret");
        let chemin = dossier.sous("secret-des-gestes.phc").as_str().to_string();
        st.secret_des_gestes = Arc::new(SourceDuSecretDesGestes::depuis_la_configuration(&chemin));
        let (a, b) = ("premier-secret-des-gestes-sdg", "second-secret-des-gestes-sdg");
        let ecrire = |contenu: &str| std::fs::write(&chemin, format!("{contenu}\n")).expect("fichier du secret");

        ecrire(&crate::secret_des_gestes::empreinte_du_secret_des_gestes(a).expect("empreinte A"));
        assert_eq!(sdg_creer(&st, sdg_avec(a), "sdg-r1", "viewer").await.0, 200, "A passe");
        ecrire(&crate::secret_des_gestes::empreinte_du_secret_des_gestes(b).expect("empreinte B"));
        let (s, v) = sdg_creer(&st, sdg_avec(a), "sdg-r2", "viewer").await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_FAUX, "A après la rotation");
        assert_eq!(sdg_creer(&st, sdg_avec(b), "sdg-r3", "viewer").await.0, 200, "B passe sans redémarrage");
        ecrire(b);
        let (s, v) = sdg_creer(&st, sdg_avec(b), "sdg-r4", "viewer").await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_NON_CONFIGURE, "secret en clair dans le fichier");
        assert!(v["error"].as_str().unwrap_or_default().contains("argon2id"), "la cause nomme la forme attendue : {v}");
        std::fs::remove_file(&chemin).expect("retrait du fichier");
        let (s, v) = sdg_creer(&st, sdg_avec(b), "sdg-r5", "viewer").await;
        sdg_refus(s, &v, CAUSE_SECRET_DES_GESTES_NON_CONFIGURE, "fichier retiré");
        assert_eq!(sdg_compte(&st, "SELECT COUNT(*) FROM user WHERE name LIKE 'sdg-r%'"), 2, "seuls les deux gestes prouvés ont écrit");
    }

    /// CE QU'IL TIENT : l'empreinte que la sous-commande écrit est de l'argon2id au format PHC que le jugement accepte
    /// et que `verify_pw` vérifie ; une empreinte bcrypt, un clair ou un fichier vide sont refusés.
    #[test]
    fn sdg_l_empreinte_de_la_sous_commande_est_de_l_argon2id_et_seule_acceptee() {
        let e = crate::secret_des_gestes::empreinte_du_secret_des_gestes("un-secret-de-seize-car").expect("empreinte");
        assert!(e.starts_with("$argon2id$"), "{e}");
        assert!(crate::auth::verify_pw("un-secret-de-seize-car", &e));
        let source = |contenu: &str| SourceDuSecretDesGestes::Empreinte(contenu.to_string());
        let (st, _tmp) = sp_state("sdg-empreintes");
        for (contenu, geste) in [
            (bcrypt::hash("un-secret-de-seize-car", 4).expect("bcrypt"), "bcrypt"),
            ("un-secret-de-seize-car".to_string(), "clair"),
            (String::new(), "vide"),
        ] {
            let mut st = st.clone();
            st.secret_des_gestes = Arc::new(source(&contenu));
            let refus = crate::secret_des_gestes::exiger_le_secret_des_gestes(&st, &sdg_avec("un-secret-de-seize-car"), "adm", "témoin");
            assert!(refus.is_err(), "{geste} : refusé");
        }
    }

    // -------------------------------------------------------------------------------------
    // `P10.24-m` (5) — AU ROUTEUR, QUEL QUE SOIT LE MODE D'AUTHENTIFICATION : Basic, SSO d'en-têtes.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : le garde réel devant le gestionnaire réel ; un administrateur Basic puis un administrateur servi
    /// par le SSO d'en-têtes (sans mot de passe local) reçoivent 403 `absent` sans l'en-tête, et créent le compte avec.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : sauter le jugement quand `au.method == "sso"` (le cas que la décision vise :
    /// l'administrateur de production) — la création SSO sans en-tête rend 200.
    #[tokio::test]
    async fn sdg_au_routeur_basic_et_sso_d_en_tetes_exigent_le_secret() {
        let (mut st, _tmp) = sp_state("sdg-routeur");
        st.sso_secret = Arc::new(SDG_SECRET_SSO.into());
        st.user = Arc::new("root-sdg".into());
        st.pass_hash = Arc::new(hash_pw("mot-de-passe-de-configuration-sdg").expect("hachage"));
        let addr = router_serve(st.clone()).await;
        let basic = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("adm:{SDG_MOT_DE_PASSE_DE_FIXTURE}")));
        let corps = |nom: &str| json!({ "name": nom, "password": format!("{nom}-{}", "m".repeat(PASSWORD_MIN_CHARS)), "role": "admin" }).to_string();
        let json_ct = ("Content-Type", "application/json");
        let secret = (ENTETE_DU_SECRET_DES_GESTES, SECRET_DES_GESTES_DE_TEST);

        let (s, texte) = router_probe_envoi(addr, "POST", "/api/users", Some(&basic), &[json_ct], &corps("sdg-basic")).await;
        assert_eq!(s, 403, "Basic sans secret : {texte}");
        assert!(texte.contains(CAUSE_SECRET_DES_GESTES_ABSENT), "{texte}");
        let (s, texte) = router_probe_envoi(addr, "POST", "/api/users", Some(&basic), &[json_ct, secret], &corps("sdg-basic")).await;
        assert_eq!(s, 200, "Basic avec secret : {texte}");

        let sso = [
            json_ct,
            ("x-plume-sso-secret", SDG_SECRET_SSO),
            ("x-authentik-username", "carol-sdg"),
            ("x-authentik-groups", "plume-admin"),
            ("Origin", "http://127.0.0.1"),
        ];
        let (s, texte) = router_probe_envoi(addr, "POST", "/api/users", None, &sso, &corps("sdg-sso")).await;
        assert_eq!(s, 403, "SSO d'en-têtes sans secret : {texte}");
        assert!(texte.contains(CAUSE_SECRET_DES_GESTES_ABSENT), "{texte}");
        let mut avec = sso.to_vec();
        avec.push(secret);
        let (s, texte) = router_probe_envoi(addr, "POST", "/api/users", None, &avec, &corps("sdg-sso")).await;
        assert_eq!(s, 200, "SSO d'en-têtes avec secret : {texte}");
        assert_eq!(sdg_compte(&st, "SELECT COUNT(*) FROM user WHERE name IN ('sdg-basic','sdg-sso')"), 2);
    }

    // -------------------------------------------------------------------------------------
    // `P10.28-h` — SOUS LA DÉMONSTRATION, UN ESSAI BASIC FAUX EST UN ÉCHEC COMPTÉ.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : démonstration active ; un visiteur sans identifiants est servi `demo` (contrôle positif) ;
    /// `lock_threshold` essais Basic faux sur `adm` sont COMPTÉS, et l'essai suivant — même avec le BON mot de passe —
    /// reçoit 429 depuis cette adresse.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : `let identifiants_prouves = ident.is_some();` (la forme d'avant) — chaque essai
    /// faux est servi `demo` et remet le compteur à zéro : 200 à l'infini, jamais 429.
    #[tokio::test]
    async fn dfb_sous_la_demonstration_un_essai_basic_faux_reste_un_echec_compte() {
        let (mut st, _tmp) = sp_state("dfb-demo");
        st.public_demo = true;
        st.user = Arc::new("root-dfb".into());
        st.pass_hash = Arc::new(hash_pw("mot-de-passe-de-configuration-dfb").expect("hachage"));
        let seuil = st.lock_threshold;
        assert!(seuil > 0, "fixture : frein armé");
        let addr = router_serve(st).await;
        let (s, texte) = router_probe_corps(addr, "GET", "/api/me", None, &[]).await;
        assert_eq!(s, 200, "visiteur anonyme servi par la démonstration : {texte}");
        assert!(texte.contains("\"demo\""), "{texte}");
        let faux = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("adm:ce-n-est-pas-lui"));
        let mut premier_429 = None;
        for i in 0..seuil + 1 {
            if router_probe(addr, "GET", "/api/me", Some(&faux)).await == 429 {
                premier_429 = Some(i);
                break;
            }
        }
        assert!(premier_429.is_some(), "des essais faux sous la démonstration finissent par un 429 (seuil {seuil})");
        let vrai = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("adm:{SDG_MOT_DE_PASSE_DE_FIXTURE}")));
        assert_eq!(router_probe(addr, "GET", "/api/me", Some(&vrai)).await, 429, "le couple (compte, adresse) est verrouillé, même pour le bon mot de passe");
    }

    // -------------------------------------------------------------------------------------
    // `P10.29-i` — LA POSE DE L'ADMINISTRATEUR : FORME COMMUNE, REFUS NOMMÉS.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `/api/setup` au routeur ; la table des comptes retirée -> 503 « écriture refusée » nommé ; une
    /// transaction d'un autre geste pendante sur l'écrivain -> 503 « transaction non prise » nommé ; dans les deux cas
    /// rien n'est écrit (`meta.admin_user` absent, aucun administrateur en mémoire). Les deux causes sont distinctes.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `c.unchecked_transaction()` et `server_err(format!(…))` — 500 et une
    /// phrase générique, dans les deux cas.
    #[tokio::test]
    async fn pla_la_pose_de_l_administrateur_refusee_rend_un_503_nomme_par_cause() {
        let (st, _dbp) = onb_state("pla-ecriture");
        st.db.lock().execute_batch("DROP TABLE user").expect("fixture");
        let admin = st.admin.clone();
        let db = st.db.clone();
        let addr = router_serve(st).await;
        let corps = format!(r#"{{"token":"{ONB_TOKEN}","user":"root","password":"motdepasse-tres-long"}}"#);
        let (s, texte) = onb_post(addr, "/api/setup", &corps).await;
        assert_eq!(s, 503, "{texte}");
        assert!(texte.contains("INSTALLATION NON EFFECTUÉE") && texte.contains("écriture"), "cause nommée de l'écriture : {texte}");
        assert!(admin.lock().is_none());
        assert_eq!(db.lock().query_row("SELECT COUNT(*) FROM meta WHERE key='admin_user'", [], |r| r.get::<_, i64>(0)).expect("meta"), 0);

        let (st, _dbp2) = onb_state("pla-begin");
        st.db.lock().execute_batch("BEGIN").expect("transaction étrangère pendante");
        let admin = st.admin.clone();
        let db = st.db.clone();
        let addr = router_serve(st).await;
        let (s, texte) = onb_post(addr, "/api/setup", &corps).await;
        assert_eq!(s, 503, "{texte}");
        assert!(texte.contains("BEGIN refusé"), "cause nommée de la transaction non prise : {texte}");
        assert!(admin.lock().is_none());
        let c = db.lock();
        assert!(!c.is_autocommit(), "la transaction de l'autre geste reste la sienne : ni validée ni annulée ici");
        let _ = c.execute_batch("ROLLBACK");
    }

    // -------------------------------------------------------------------------------------
    // `P10.20-u` — LA CAUSE DE `ref_non_lu`, ET LA FIN NOMMÉE DU RELEVÉ DES COLLECTEURS.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : nominal -> ni `ref_non_lu` ni `ref_non_lu_cause` ; sévérité illisible (BLOB) -> cause
    /// `ligne_illisible` ; table retirée -> cause `table_non_lue`. Les deux causes sont distinctes.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : rendre `REF_NON_LUE_LECTURE_REFUSEE` pour toute erreur dans
    /// `cause_de_ref_non_lue` — les deux voies se confondent.
    #[tokio::test]
    async fn rnc_la_reference_non_lue_porte_sa_cause_stable() {
        let (st, _tmp) = sp_state("rnc-refcase");
        pma_ecrire(&st, "INSERT INTO alert(id,ts,rule,severity,title) VALUES(7,1000,'T1110',3,'bruteforce sur mx1');");
        let cas = pma_dossier_avec_ref(&st, "alert:7");
        let item = pma_item_avec_ref(&st, cas);
        assert_eq!(item.get("ref_non_lu_cause"), None, "rien sur le chemin nominal : {item}");
        pma_ecrire(&st, "UPDATE alert SET severity=x'FF' WHERE id=7;");
        let item = pma_item_avec_ref(&st, cas);
        assert_eq!(item["ref_non_lu"], json!(true), "{item}");
        assert_eq!(item["ref_non_lu_cause"], json!("ligne_illisible"), "{item}");
        pma_retirer_la_table(&st, "alert");
        let item = pma_item_avec_ref(&st, cas);
        assert_eq!(item["ref_non_lu"], json!(true), "{item}");
        assert_eq!(item["ref_non_lu_cause"], json!("table_non_lue"), "{item}");
    }

    /// CE QU'IL TIENT : nominal -> `collectors_etat` nul ; un auto-report dont une colonne ne se décode pas (le parcours
    /// démarre, puis une ligne illisible) -> `interrompu`, AUCUNE ligne rendue — le cas que la console lisait « non
    /// commencé » ; la table retirée -> `non_commence`. `collectors_cause` et `collectors_incomplets` restent servis.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : faire rendre `Some("non_commence")` à `etat()` pour `Interrompu` — le relevé
    /// interrompu sans ligne redevient indiscernable du relevé jamais commencé.
    #[tokio::test]
    async fn rnc_le_releve_des_collecteurs_separe_interrompu_et_non_commence() {
        let (st, _tmp) = sp_state("rnc-collecteurs");
        let adm = sp_au("adm", "admin");
        let (_, lu) = pma_corps(suppressions_get(State(st.clone()), Extension(adm.clone())).await).await;
        assert_eq!(lu["collectors_etat"], Value::Null, "complet : aucune fin nommée : {lu}");
        pma_ecrire(
            &st,
            "INSERT INTO event(ts,source,category,severity,host,message,fields,origin) \
             VALUES(1000,'mail','config',0,'mx1','config du collecteur mail','{}',x'FF');",
        );
        let (_, lu) = pma_corps(suppressions_get(State(st.clone()), Extension(adm.clone())).await).await;
        assert_eq!(lu["collectors"].as_array().map(|a| a.len()), Some(0), "aucune ligne rendue : {lu}");
        assert_eq!(lu["collectors_incomplets"], json!(true), "{lu}");
        assert_eq!(lu["collectors_etat"], json!("interrompu"), "le parcours a démarré : interrompu, pas « non commencé » : {lu}");
        pma_retirer_la_table(&st, "event");
        let (_, lu) = pma_corps(suppressions_get(State(st.clone()), Extension(adm.clone())).await).await;
        assert_eq!(lu["collectors_etat"], json!("non_commence"), "{lu}");
        assert!(lu["collectors_cause"].as_str().is_some_and(|c| !c.is_empty()), "{lu}");
    }
}
