// =====================================================================================
// `P10.30-d` — LES RESTES DE LA FAMILLE : LE FREIN DU SECOND FACTEUR SUR `/metrics`, L'ENTROPIE INDISPONIBLE EN REFUS
// NOMMÉ, LA POSE DE DROIT SANS COMPTE DE PLATEFORME, L'ÉVÉNEMENT DU TENANT DONT LA BASE N'EST PAS SERVIE.
//
// LES DÉFAUTS, RELUS SUR LA BASE AVANT LE CORRECTIF.
//  * `handlers/frein_du_second_facteur.rs` : le déclenchement du frein n'était porté que par l'événement SIEM
//    `lockout` ; aucune série de `/metrics` ne le comptait (`metrics::gather_prom` n'en servait aucune).
//  * `handlers/idp.rs` : `oidc_start`, `mfa_enroll` et `mfa_verify` rendaient `500 « entropie noyau indisponible »`.
//  * `tenants.rs`, `grant_set`, bras `Materialisation` : `500 « échec de matérialisation du compte plateforme »`.
//  * `tenants.rs` : `EvenementDAuditDuTenant::SansBaseServie` n'était avoué par aucun corps — un droit posé ou retiré
//    sur un tenant suspendu rendait un succès nu (le retrait, un 204), et le tenant ne voyait jamais le geste.
//
// LES VOIES D'ÉCHEC : l'entropie coupée sur le fil du témoin (`handlers::idp::crochet_d_entropie`) ; l'`INSERT` de
// `platform_user` refusé par un autorisateur sur la connexion du plan de contrôle ; un tenant SUSPENDU, et un tenant
// dont la clé ne se résout pas (préfixe inconnu, aucune base ouverte) ; l'`INSERT` de `event` refusé par un
// autorisateur pendant que le frein se déclenche.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la création d'un tenant dont la base n'est pas servie juste après son
// provisionnement (elle l'avoue depuis la vague BE, par l'aveu commun de rbac.rs : témoin dans
// `role_de_default_sous_plan_et_aveu_de_la_creation_sans_base.rs`) ; la cause d'un compte de plateforme non établi n'est pas distinguée (perdue dans `ensure_platform_user_conn`) ; ce
// que la console peint de ces corps ; l'enrôlement sans entropie reste un CINQ CENTS (nommé) : son 503 attend une face
// de la console (témoin 109e du harnais), et aucune face existante n'est vraie pour lui.
// =====================================================================================
mod restes_du_frein_de_l_entropie_et_des_tenants {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const RFET_GRAINE: &[u8] = b"rfet-graine-du-temoin";
    const RFET_MOT_DE_PASSE: &str = "motdepasse12345";
    const RFET_SERIE: &str = "plume_frein_du_second_facteur_declenchements_total";
    const RFET_FOURNISSEUR: &str = "rfet-oidc";

    async fn rfet_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    /// Un refus `err_json` en cinq cents : EXACTEMENT `{error, id}`, l'erreur égale à la phrase attendue.
    fn rfet_refus_exact(quoi: &str, statut: u16, corps: &Value, attendu_statut: u16, phrase: &str) {
        assert_eq!(statut, attendu_statut, "{quoi} : statut : {corps}");
        let o = corps.as_object().unwrap_or_else(|| panic!("{quoi} : un objet JSON : {corps}"));
        let mut cles: Vec<&str> = o.keys().map(String::as_str).collect();
        cles.sort_unstable();
        assert_eq!(cles, ["error", "id"], "{quoi} : ensemble EXACT des clés : {corps}");
        assert_eq!(o["error"], json!(phrase), "{quoi} : la phrase nommée, entière : {corps}");
        assert!(o["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
    }

    fn rfet_pair(n: u8) -> std::net::SocketAddr {
        format!("192.0.2.{n}:45454").parse().expect("adresse de test")
    }

    fn rfet_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` ({e})"));
    }

    fn rfet_compter(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` ({e})"))
    }

    fn rfet_poser_la_mfa(st: &AppState, active: bool) -> String {
        let graine = base32_encode(RFET_GRAINE);
        st.db
            .lock()
            .execute(
                "INSERT OR REPLACE INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES('adm',?1,?2,'[]',-1,0,0)",
                params![graine, active as i64],
            )
            .expect("fixture : MFA posée");
        graine
    }

    fn rfet_code(graine: &str) -> String {
        hotp(&base32_decode(graine).expect("graine base32"), (now() / 30) as u64, 6)
    }

    /// Un code à six chiffres qui n'est le code d'AUCUN pas de [pas-3, pas+3].
    fn rfet_code_faux(graine: &str, n: u64) -> String {
        let pas = now() / 30;
        let cle = base32_decode(graine).expect("graine base32");
        let justes: Vec<String> = (-3..=3).map(|d| hotp(&cle, (pas + d) as u64, 6)).collect();
        let mut k = n;
        loop {
            let c = format!("{:06}", k.wrapping_mul(7919).wrapping_add(13) % 1_000_000);
            if !justes.contains(&c) {
                return c;
            }
            k += 1_000_003;
        }
    }

    /// LA VALEUR SERVIE PAR `/metrics` (`gather_prom`, le corps de la route) ; « absente » si la série manque.
    fn rfet_servi() -> String {
        let prom = gather_prom(&test_db(), "/nonexistent-spool", "", &crate::handlers::system::VersionDeSchema::Lue(1), 80);
        if !prom.contains(&format!("\n# TYPE {RFET_SERIE} counter\n")) {
            return "absente".into();
        }
        prom.lines().find_map(|l| l.strip_prefix(&format!("{RFET_SERIE} "))).unwrap_or("sans-valeur").to_string()
    }

    // -------------------------------------------------------------------------------------
    // (1) LE FREIN DU SECOND FACTEUR, COMPTÉ ET SERVI SUR `/metrics`.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, DANS UN PROCESSUS ENFANT (compte exact : aucun voisin de la suite n'y compte), seuil du frein à
    /// deux : la série est servie, déclarée compteur, à 0 au départ ; un premier code faux ne compte rien ; un code
    /// JUSTE présenté à l'essai qui aurait posé le frein ne compte rien ; le second code faux consécutif pose le frein et
    /// compte UN ; l'essai suivant, freiné (429), ne compte rien — à la désactivation, puis à l'activation et à la
    /// connexion (un de plus chacune) ; et l'`INSERT` de l'événement `lockout` refusé par la base, le déclenchement est
    /// compté quand même (la perte de l'événement l'est à part, sous son genre).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `bd3_frein_non_compte` ; `bd3_frein_compte_a_chaque_echec` (le compte sorti du
    /// bras du déclenchement) ; `bd3_frein_compte_si_evenement_ecrit` (compté seulement sur l'événement écrit) ;
    /// `bd3_frein_compte_a_la_reservation` (compté dès que l'essai réservé arme le frein, code juste compris) ;
    /// `bd3_metrique_absente` (la série retirée de `gather_prom`).
    #[tokio::test]
    async fn rfet_frein_declenchements_comptes_exactement_et_servis() {
        const ENFANT: &str = "RFET_FREIN_ENFANT";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les gestionnaires lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _tmp) = sp_state("rfet-frein");
            let mut st = st;
            st.lock_threshold = 2;
            st.lock_base_s = 60;
            let portee = crate::handlers::frein_du_second_facteur::PORTEE_DU_FREIN_DU_SECOND_FACTEUR;
            let mut ip = 10u8;
            let mut lignes: Vec<String> = vec![format!("depart={}", rfet_servi())];
            macro_rules! desactiver {
                ($code:expr) => {{
                    ip += 1;
                    rfet_corps(mfa_disable(State(st.clone()), ConnectInfo(rfet_pair(ip)), Extension(sp_au("adm", "admin")), Json(json!({ "code": $code }))).await).await.0
                }};
            }
            let graine = rfet_poser_la_mfa(&st, true);
            let s = desactiver!(rfet_code_faux(&graine, 1));
            lignes.push(format!("desactivation-faux-1={s}/{}", rfet_servi()));
            let s = desactiver!(rfet_code(&graine));
            lignes.push(format!("desactivation-juste-a-l-essai-arme={s}/{}", rfet_servi()));
            rfet_poser_la_mfa(&st, true);
            let s = desactiver!(rfet_code_faux(&graine, 2));
            lignes.push(format!("desactivation-faux-1={s}/{}", rfet_servi()));
            let s = desactiver!(rfet_code_faux(&graine, 3));
            lignes.push(format!("desactivation-faux-2={s}/{}", rfet_servi()));
            let s = desactiver!(rfet_code_faux(&graine, 4));
            lignes.push(format!("desactivation-freine={s}/{}", rfet_servi()));

            rfet_sql(&st, &format!("DELETE FROM setting WHERE scope='{portee}';"));
            rfet_poser_la_mfa(&st, false);
            for n in 1..=2u64 {
                ip += 1;
                let r = mfa_verify(State(st.clone()), ConnectInfo(rfet_pair(ip)), Extension(sp_au("adm", "admin")), Json(json!({ "code": rfet_code_faux(&graine, 10 + n) }))).await;
                lignes.push(format!("activation-faux-{n}={}/{}", rfet_corps(r).await.0, rfet_servi()));
            }

            rfet_sql(&st, &format!("DELETE FROM setting WHERE scope='{portee}';"));
            rfet_poser_la_mfa(&st, true);
            for n in 1..=2u64 {
                ip += 1;
                let r = login_post(State(st.clone()), ConnectInfo(rfet_pair(ip)), Json(json!({ "user": "adm", "pass": RFET_MOT_DE_PASSE }))).await;
                let (statut, c) = rfet_corps(r).await;
                assert_eq!(statut, 200, "fixture : le mot de passe rend un ticket : {c}");
                let ticket = c["ticket"].as_str().expect("fixture : ticket").to_string();
                let r = login_mfa_post(State(st.clone()), ConnectInfo(rfet_pair(ip)), Json(json!({ "ticket": ticket, "code": rfet_code_faux(&graine, 20 + n) }))).await;
                lignes.push(format!("connexion-faux-{n}={}/{}", rfet_corps(r).await.0, rfet_servi()));
            }

            rfet_sql(&st, &format!("DELETE FROM setting WHERE scope='{portee}';"));
            st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Insert { table_name } if table_name == "event" => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            let s1 = desactiver!(rfet_code_faux(&graine, 31));
            let s2 = desactiver!(rfet_code_faux(&graine, 32));
            st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            let perte = crate::metrics::evenement_d_acces_non_ecrit_de("plume-auth.second-facteur.lockout").map_or(0, |(n, _)| n);
            lignes.push(format!("evenement-refuse={s1},{s2}/{}/perte-lockout={perte}", rfet_servi()));
            println!("RFET-FREIN:{}", lignes.join(";"));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::restes_du_frein_de_l_entropie_et_des_tenants::rfet_frein_declenchements_comptes_exactement_et_servis"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        // Le harnais écrit « test … … » sans retour à la ligne avant la sortie de l'enfant : la marque se cherche DANS la
        // sortie, pas en tête de ligne.
        let ligne = stdout
            .split_once("RFET-FREIN:")
            .and_then(|(_, reste)| reste.lines().next())
            .unwrap_or_else(|| panic!("contrôle : l'enfant a joué : {stdout}\n{stderr}"));
        assert_eq!(
            ligne,
            "depart=0;desactivation-faux-1=401/0;desactivation-juste-a-l-essai-arme=200/0;desactivation-faux-1=401/0;\
             desactivation-faux-2=401/1;desactivation-freine=429/1;activation-faux-1=401/1;activation-faux-2=401/2;\
             connexion-faux-1=401/2;connexion-faux-2=401/3;evenement-refuse=401,401/4/perte-lockout=1",
            "chaque déclenchement compté UNE fois, et seulement lui, servi par `/metrics`"
        );
    }

    // -------------------------------------------------------------------------------------
    // (2) L'ENTROPIE INDISPONIBLE — trois routes, trois refus nommés (deux 503, l'enrôlement sous le cinq cents d'avant).
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : l'entropie coupée, `GET /api/auth/oidc/{name}/start` sur un fournisseur utilisable (points
    /// d'extrémité explicites, aucune découverte) rend 503, corps EXACT `{error: CAUSE_CONNEXION_OIDC_SANS_ENTROPIE, id}`,
    /// sans cookie ni redirection. Contrôle positif : l'entropie rendue, la même demande redirige (302, cookie posé).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `bd3_oidc_500` (la forme d'avant, `500 « entropie noyau indisponible »`).
    #[tokio::test]
    async fn rfet_un_depart_oidc_sans_entropie_est_un_503_nomme_sans_cookie_ni_redirection() {
        let (st, _tmp) = sp_state("rfet-oidc");
        let config = json!({
            "issuer": "https://idp.example", "client_id": "plume", "redirect_uri": "https://plume.example/api/auth/oidc/callback",
            "authorization_endpoint": "https://idp.example/authorize", "token_endpoint": "https://idp.example/token", "jwks_uri": "https://idp.example/jwks",
        });
        st.db
            .lock()
            .execute(
                "INSERT INTO idp_provider(name,kind,enabled,config_json,secret,created,updated) VALUES(?1,'oidc',1,?2,'s',1,1)",
                params![RFET_FOURNISSEUR, config.to_string()],
            )
            .expect("fixture : fournisseur posé");
        let r = {
            let _coupee = crate::handlers::idp::crochet_d_entropie::couper();
            oidc_start(State(st.clone()), axum::extract::Path(RFET_FOURNISSEUR.to_string())).await
        };
        assert!(r.headers().get(header::SET_COOKIE).is_none(), "aucun cookie posé");
        assert!(r.headers().get(header::LOCATION).is_none(), "aucune redirection émise");
        let (statut, corps) = rfet_corps(r).await;
        rfet_refus_exact("oidc_start", statut, &corps, 503, crate::handlers::idp::CAUSE_CONNEXION_OIDC_SANS_ENTROPIE);

        // CONTRÔLE POSITIF — l'entropie rendue.
        let r = oidc_start(State(st.clone()), axum::extract::Path(RFET_FOURNISSEUR.to_string())).await;
        assert_eq!(r.status(), StatusCode::FOUND, "le flux part");
        let loc = r.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        assert!(loc.starts_with("https://idp.example/authorize"), "vers le fournisseur : {loc}");
        assert!(r.headers().get(header::SET_COOKIE).and_then(|v| v.to_str().ok()).is_some_and(|c| c.starts_with("plume_oidc=")), "cookie d'état posé");
    }

    /// CE QU'IL TIENT : l'entropie coupée, `POST /api/mfa/enroll` (mot de passe juste) rend 500, corps EXACT
    /// `{error: CAUSE_ENROLEMENT_SANS_ENTROPIE, id}` ; l'enrôlement en attente garde SA graine (`enabled=0`), et un compte
    /// sans MFA n'en reçoit aucune. Contrôle positif : l'entropie rendue, l'enrôlement sert une graine neuve.
    ///
    /// Un 503 sans face dans la console serait refusé par le témoin 109e : il est tenu ici aussi.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `bd3_enrolement_phrase_d_avant` (la phrase d'avant), `bd3_enrolement_503`.
    #[tokio::test]
    async fn rfet_un_enrolement_sans_entropie_est_un_refus_nomme_et_l_etat_d_avant_reste() {
        let (st, _tmp) = sp_state("rfet-enrolement");
        let graine = rfet_poser_la_mfa(&st, false);
        let enroler = |qui: &'static str| {
            let st = st.clone();
            async move {
                rfet_corps(mfa_enroll(State(st), ConnectInfo(rfet_pair(40)), Extension(sp_au(qui, "admin")), Json(json!({ "password": RFET_MOT_DE_PASSE }))).await).await
            }
        };
        let (s_adm, c_adm, s_bob, c_bob) = {
            let _coupee = crate::handlers::idp::crochet_d_entropie::couper();
            let (s_adm, c_adm) = enroler("adm").await;
            let (s_bob, c_bob) = enroler("bob").await;
            (s_adm, c_adm, s_bob, c_bob)
        };
        rfet_refus_exact("enrôlement en attente", s_adm, &c_adm, 500, crate::handlers::idp::CAUSE_ENROLEMENT_SANS_ENTROPIE);
        rfet_refus_exact("enrôlement sans MFA", s_bob, &c_bob, 500, crate::handlers::idp::CAUSE_ENROLEMENT_SANS_ENTROPIE);
        assert_eq!(
            rfet_compter(&st, &format!("SELECT COUNT(*) FROM user_mfa WHERE user='adm' AND secret='{graine}' AND enabled=0")),
            1,
            "l'enrôlement en attente garde SA graine"
        );
        assert_eq!(rfet_compter(&st, "SELECT COUNT(*) FROM user_mfa WHERE user='bob'"), 0, "aucune graine posée au compte sans MFA");

        // CONTRÔLE POSITIF — l'entropie rendue.
        let (statut, corps) = enroler("adm").await;
        assert_eq!(statut, 200, "{corps}");
        let neuve = corps["secret"].as_str().expect("graine servie").to_string();
        assert_ne!(neuve, graine, "une graine NEUVE");
        assert_eq!(rfet_compter(&st, &format!("SELECT COUNT(*) FROM user_mfa WHERE user='adm' AND secret='{neuve}'")), 1, "et posée");
    }

    /// CE QU'IL TIENT : l'entropie coupée, `POST /api/mfa/verify` avec le code JUSTE d'un enrôlement en attente rend 503,
    /// corps EXACT `{error: CAUSE_MFA_NON_ACTIVEE_SANS_ENTROPIE, id}` ; la MFA reste inactive (`enabled=0`, aucun code de
    /// secours enregistré, pas non consommé), le registre n'atteste aucune activation, et l'essai est rendu au frein
    /// (zéro échec compté). Contrôle positif : l'entropie rendue, le même code active (dix codes de secours servis).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `bd3_activation_500` (la forme d'avant) ; `bd3_activation_sans_rendre`
    /// (l'essai réservé gardé : un échec compté contre un code juste).
    #[tokio::test]
    async fn rfet_une_activation_sans_entropie_est_un_503_nomme_et_rien_n_est_active() {
        let (st, _tmp) = sp_state("rfet-activation");
        let graine = rfet_poser_la_mfa(&st, false);
        let verifier = || {
            let st = st.clone();
            let code = rfet_code(&graine);
            async move { rfet_corps(mfa_verify(State(st), ConnectInfo(rfet_pair(50)), Extension(sp_au("adm", "admin")), Json(json!({ "code": code }))).await).await }
        };
        let (statut, corps) = {
            let _coupee = crate::handlers::idp::crochet_d_entropie::couper();
            verifier().await
        };
        rfet_refus_exact("activation", statut, &corps, 503, crate::handlers::idp::CAUSE_MFA_NON_ACTIVEE_SANS_ENTROPIE);
        assert_eq!(
            rfet_compter(&st, "SELECT COUNT(*) FROM user_mfa WHERE user='adm' AND enabled=0 AND recovery='[]' AND last_step=-1"),
            1,
            "rien d'activé, aucun code de secours enregistré, aucun pas consommé"
        );
        assert_eq!(rfet_compter(&st, "SELECT COUNT(*) FROM ledger WHERE detail LIKE 'MFA TOTP activée%'"), 0, "le registre n'atteste aucune activation");
        assert_eq!(crate::handlers::idp::echecs_consecutifs_du_second_facteur(&st, "adm"), 0, "l'essai est rendu : aucun échec compté");

        // CONTRÔLE POSITIF — l'entropie rendue, le même code.
        let (statut, corps) = verifier().await;
        assert_eq!(statut, 200, "{corps}");
        assert_eq!(corps["recovery_codes"].as_array().map(Vec::len), Some(10), "dix codes de secours servis : {corps}");
        assert_eq!(rfet_compter(&st, "SELECT enabled FROM user_mfa WHERE user='adm'"), 1, "activée");
    }

    // -------------------------------------------------------------------------------------
    // (3) LA POSE DE DROIT SANS COMPTE DE PLATEFORME ÉTABLI — 503 nommé, rien n'a changé, le journal le dit.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, DANS UN PROCESSUS ENFANT (sortie d'erreur lisible) : l'`INSERT` de `platform_user` refusé au plan
    /// de contrôle, la pose d'un droit pour un compte neuf rend 503, corps EXACT `{error: CAUSE_DROIT_NON_POSE, id}` ;
    /// aucun compte, aucun droit, aucun maillon `grant.set` ; la sortie d'erreur porte, ligne ENTIÈRE et seule de son
    /// préfixe, `[tenants] WARN droit NON posé sur '<tenant>' : compte de plateforme ni retrouvé ni créé (cause non
    /// rendue)` — sans le nom du compte. Contrôle positif : l'autorisateur levé, la même pose passe (200).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `bd3_materialisation_500` (la forme d'avant, 500 à phrase fixe) ;
    /// `bd3_materialisation_motif_muet` (la ligne de journal sans son motif).
    #[tokio::test]
    async fn rfet_une_pose_de_droit_sans_compte_de_plateforme_est_un_503_nomme_et_dite() {
        const ENFANT: &str = "RFET_MATERIALISATION_ENFANT";
        const PHASE: &str = "RFET-PHASE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT est lu
        if std::env::var(ENFANT).is_ok() {
            let (st, _dir) = mk_mode1_state();
            let sa = au_super("op-rfet");
            let (statut, v) = rfet_corps(tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Json(json!({ "id": "rfet-mat", "name": "RfetMat" }))).await).await;
            assert_eq!(statut, 201, "fixture : {v}");
            let cp = st.tenants.control.as_ref().expect("fixture : mode 1");
            cp.conn.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Insert { table_name } if table_name == "platform_user" => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            eprintln!("{PHASE}refus");
            let (statut, corps) = rfet_corps(
                grant_set(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Path("rfet-mat".into()), Json(json!({ "user": "erin-rfet", "role": "editor" }))).await,
            )
            .await;
            eprintln!("{PHASE}fin");
            cp.conn.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            let comptes: i64 = cp.conn.lock().query_row("SELECT COUNT(*) FROM platform_user WHERE name='erin-rfet'", [], |r| r.get(0)).expect("lu");
            let maillons: i64 = cp.conn.lock().query_row("SELECT COUNT(*) FROM control_ledger WHERE kind='grant.set'", [], |r| r.get(0)).expect("lu");
            println!("RFET-REFUS:{}", json!({ "statut": statut, "corps": corps, "comptes": comptes, "droits": count_grant(&st, "rfet-mat", "erin-rfet"), "maillons": maillons }));
            let (statut, v) = rfet_corps(
                grant_set(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Path("rfet-mat".into()), Json(json!({ "user": "erin-rfet", "role": "editor" }))).await,
            )
            .await;
            println!("RFET-POSITIF:{}", json!({ "statut": statut, "droits": count_grant(&st, "rfet-mat", "erin-rfet"), "corps": v }));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::restes_du_frein_de_l_entropie_et_des_tenants::rfet_une_pose_de_droit_sans_compte_de_plateforme_est_un_503_nomme_et_dite"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        let marque = |m: &str| -> Value {
            let l = stdout.split_once(m).and_then(|(_, reste)| reste.lines().next()).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}\n{stderr}"));
            serde_json::from_str(l).expect("contrôle : JSON")
        };
        let refus = marque("RFET-REFUS:");
        rfet_refus_exact("pose sans compte", refus["statut"].as_u64().unwrap_or(0) as u16, &refus["corps"], 503, crate::tenants::CAUSE_DROIT_NON_POSE);
        assert_eq!((refus["comptes"].as_i64(), refus["droits"].as_i64(), refus["maillons"].as_i64()), (Some(0), Some(0), Some(0)), "rien n'a changé : {refus}");
        let positif = marque("RFET-POSITIF:");
        assert_eq!((positif["statut"].as_u64(), positif["droits"].as_i64()), (Some(200), Some(1)), "contrôle positif : {positif}");
        let phase = stderr
            .split_once(&format!("{PHASE}refus\n"))
            .and_then(|(_, r)| r.split_once(PHASE))
            .map(|(c, _)| c.to_string())
            .unwrap_or_else(|| panic!("contrôle : phase de refus : {stderr}"));
        let lignes: Vec<&str> = phase.lines().filter(|l| l.starts_with("[tenants]")).collect();
        assert_eq!(
            lignes,
            ["[tenants] WARN droit NON posé sur 'rfet-mat' : compte de plateforme ni retrouvé ni créé (cause non rendue)"],
            "le refus est DIT, ligne entière, sans le nom du compte"
        );
        assert!(!phase.contains("erin-rfet"), "le nom du compte n'apparaît nulle part dans la sortie d'erreur : {phase}");
    }

    // -------------------------------------------------------------------------------------
    // (4) L'ÉVÉNEMENT DU TENANT DONT LA BASE N'EST PAS SERVIE — avoué à côté du succès.
    // -------------------------------------------------------------------------------------

    fn rfet_evenements(st: &AppState, tenant: &str, action: &str) -> i64 {
        let h = st.tenants.handle_for(tenant).expect("fixture : la base du tenant se résout");
        let c = h.lock();
        c.query_row(
            "SELECT COUNT(*) FROM event WHERE source='plume-tenant-admin' AND json_extract(fields,'$.action')=?1",
            params![action],
            |r| r.get(0),
        )
        .expect("fixture : les événements du tenant se lisent")
    }

    /// CE QU'IL TIENT : sur un tenant SUSPENDU (base non servie), la pose d'un droit rend 200, corps EXACT
    /// `{ok, tenant, user, role, evenement_du_tenant_non_ecrit: CAUSE_EVENEMENT_DU_TENANT_SANS_BASE_SERVIE}` ; le retrait
    /// rend 200 (plus le 204 nu), corps EXACT avec `removed` et le même aveu ; la suspension redemandée rend 200 avec
    /// l'aveu ; le droit est posé puis retiré ; réactivé, le tenant n'a ni `grant.set` ni `grant.remove` parmi ses
    /// événements (« même une fois servi de nouveau ») ; un tenant suspendu dont la CLÉ ne se résout pas est réactivé avec
    /// l'aveu. Contrôle positif : tenant servi, la pose n'avoue rien (corps exact) et le retrait est un 204.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `bd3_sans_base_muet_pose`, `bd3_sans_base_muet_retrait`,
    /// `bd3_sans_base_muet_bascule` (l'aveu retiré d'un site) ; `bd3_retrait_204_sans_base` (le retrait rendu en 204) ;
    /// `bd3_sans_base_phrase_de_la_perte` (la phrase de la perte d'écriture servie à la place) ;
    /// `bd3_sans_base_avoue_sur_ecrit` (l'aveu posé sur un événement écrit).
    #[tokio::test]
    async fn rfet_un_evenement_de_tenant_sans_base_servie_est_avoue_a_cote_du_geste_fait() {
        let (st, dir) = mk_mode1_state();
        let sa = au_super("op-rfet");
        let aveu = json!(crate::tenants::CAUSE_EVENEMENT_DU_TENANT_SANS_BASE_SERVIE);
        let (statut, v) = rfet_corps(tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Json(json!({ "id": "rfet-susp", "name": "RfetSusp" }))).await).await;
        assert_eq!(statut, 201, "fixture : {v}");
        let (statut, v) = rfet_corps(tenant_suspend(State(st.clone()), Extension(sa.clone()), Path("rfet-susp".into())).await).await;
        assert_eq!((statut, &v), (200, &json!({ "ok": true, "id": "rfet-susp", "suspended": true })), "fixture : base servie avant la bascule, rien à avouer");

        let (statut, v) = rfet_corps(
            grant_set(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Path("rfet-susp".into()), Json(json!({ "user": "erin-rfet", "role": "editor" }))).await,
        )
        .await;
        assert_eq!(
            (statut, &v),
            (200, &json!({ "ok": true, "tenant": "rfet-susp", "user": "erin-rfet", "role": "editor", "evenement_du_tenant_non_ecrit": aveu })),
            "pose sur un tenant suspendu : le geste fait, l'événement non écrit AVOUÉ"
        );
        assert_eq!(count_grant(&st, "rfet-susp", "erin-rfet"), 1, "le droit est posé");
        let (statut, v) = rfet_corps(grant_delete(State(st.clone()), Extension(sa.clone()), Path(("rfet-susp".into(), "erin-rfet".into()))).await).await;
        assert_eq!(
            (statut, &v),
            (200, &json!({ "ok": true, "tenant": "rfet-susp", "user": "erin-rfet", "removed": true, "evenement_du_tenant_non_ecrit": aveu })),
            "retrait sur un tenant suspendu : un 204 ne peut rien avouer"
        );
        assert_eq!(count_grant(&st, "rfet-susp", "erin-rfet"), 0, "le droit est retiré");
        let (statut, v) = rfet_corps(tenant_suspend(State(st.clone()), Extension(sa.clone()), Path("rfet-susp".into())).await).await;
        assert_eq!(
            (statut, &v),
            (200, &json!({ "ok": true, "id": "rfet-susp", "suspended": true, "evenement_du_tenant_non_ecrit": aveu })),
            "suspension redemandée : la base n'est plus servie, l'événement non écrit est AVOUÉ"
        );

        let (statut, v) = rfet_corps(tenant_unsuspend(State(st.clone()), Extension(sa.clone()), Path("rfet-susp".into())).await).await;
        assert_eq!((statut, &v), (200, &json!({ "ok": true, "id": "rfet-susp", "suspended": false })), "réactivation : base servie, rien à avouer");
        assert_eq!(rfet_evenements(&st, "rfet-susp", "grant.set"), 0, "BASE DU TENANT, servie de nouveau : la pose n'y est pas — c'est ce que l'aveu dit");
        assert_eq!(rfet_evenements(&st, "rfet-susp", "grant.remove"), 0, "BASE DU TENANT, servie de nouveau : le retrait n'y est pas — c'est ce que l'aveu dit");
        assert_eq!(rfet_evenements(&st, "rfet-susp", "tenant.unsuspend"), 1, "fixture : la base réactivée prend ses événements");

        // CONTRÔLE POSITIF — tenant servi : rien d'avoué, le retrait nominal reste un 204.
        let (statut, v) = rfet_corps(
            grant_set(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Path("rfet-susp".into()), Json(json!({ "user": "dave-rfet", "role": "viewer" }))).await,
        )
        .await;
        assert_eq!((statut, &v), (200, &json!({ "ok": true, "tenant": "rfet-susp", "user": "dave-rfet", "role": "viewer" })), "nominal : corps d'avant, à l'octet");
        let r = grant_delete(State(st.clone()), Extension(sa.clone()), Path(("rfet-susp".into(), "dave-rfet".into()))).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT, "nominal : 204 sans corps");

        // UNE CLÉ QUI NE SE RÉSOUT PAS — la réactivation, faite, n'a pas de base où écrire son événement.
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .execute(
                "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('rfet-cle','RfetCle','inconnu:rfet',?1,?2,1)",
                params![dir.sous("rfet-cle.db").as_str(), now()],
            )
            .expect("fixture : tenant à clé non résoluble");
        let (statut, v) = rfet_corps(tenant_unsuspend(State(st.clone()), Extension(sa.clone()), Path("rfet-cle".into())).await).await;
        assert_eq!(
            (statut, &v),
            (200, &json!({ "ok": true, "id": "rfet-cle", "suspended": false, "evenement_du_tenant_non_ecrit": aveu })),
            "réactivation d'un tenant à clé non résoluble : la bascule faite, l'événement non écrit AVOUÉ"
        );
        assert!(!std::path::Path::new(dir.sous("rfet-cle.db").as_str()).exists(), "fixture : aucune base ouverte pour ce tenant");
    }
}
