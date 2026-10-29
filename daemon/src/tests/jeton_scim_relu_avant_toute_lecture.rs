// =====================================================================================
// `P10.34-q` — LE JETON SCIM D'UNE DEMANDE DÉJÀ ADMISE EST RELU AVANT TOUTE LECTURE DU TENANT, ET AVANT LA POSE DE
// L'IDENTITÉ SOUS LE MÊME VERROU.
//
// Un jeton d'un tenant absent, détruit ou recréé est refusé, y compris pour une demande déjà admise : aux lectures
// comme aux écritures.
//
// CE QUI CHANGE (daemon/src/scim.rs, daemon/src/rbac.rs) : `GET /Users`, `GET /Users/{id}` et `PUT active=true` relisent
// le jeton puis lisent sous le MÊME verrou (`scim_lire_pour_la_demande`) ; `PUT active=false` et `DELETE` lisent
// l'existence du membre dans la transaction du déprovisionnement, après la relecture du jeton ; `POST /Users` relit le
// jeton et pose l'identité sous UN verrou (`rbac::poser_l_identite_scim_conn`), le point de course de production
// `scim-jeton-avant-l-identite` précédant ce verrou.
//
// CE QUE CES TÉMOINS TIENNENT, deux tenants réels (fixture de `jeton_scim_relu_a_chaque_ecriture.rs`) :
//  * PAR LE ROUTEUR RÉEL, `PUT active=true` d'un membre puis d'un non-membre, admis avant la destruction et la recréation
//    de A, corps envoyé ensuite : le `401` de l'entrée EN ENTIER (égal à celui d'un jeton inconnu), aucune
//    représentation, rien d'écrit ; contrôles positifs avec le jeton neuf (`200` du membre, `404` du non-membre : le
//    refus cache bien une réponse qui existe) ;
//  * par un contexte fabriqué comme l'entrée le fabrique, admis tant que A existe, joué après la recréation : `GET` d'un
//    membre et d'un non-membre, `GET /Users`, `PUT active=false` et `DELETE` d'un non-membre rendent le `401`, rien
//    d'écrit ; contrôles positifs par le contexte du jeton neuf ;
//  * `POST /Users` SANS groupes, A détruit (seul, puis détruit et recréé avec un jeton neuf) au point de course : le
//    `401`, ni identité, ni provenance, ni ligne de contrôle ; AVEC groupes, A détruit et recréé entre la pose de
//    l'identité et ses droits : le `401`, aucun droit (la relecture de la transaction des droits) ;
//  * le jeton non relu à la lecture (`GET`, `GET /Users`, `PUT active=true`) : le `503` au corps EXACT, rien d'écrit.
//
// MUTANTS (sous `cfg!(test)`, choisis par `VERIF_MUT`, retirés avant le commit), chacun vu ROUGE :
// AY1c_relecture_avant_le_point, AY1c_sans_jeton:scim.user.replace, AY1c_sans_jeton:scim.user.get,
// AY1c_sans_jeton:scim.users.list, AY1c_existence_avant_le_jeton, AY1c_illisible_404 ; et ceux du lot qui restent
// tenus ici : AY1_tx_post_sans_jeton, AY1_tx_deprov_sans_jeton.
//
// LIMITES : la représentation que `POST /Users` sert APRÈS son geste (fait et attesté) est relue sous un verrou distinct ;
// les lignes `[scim]` des `503` ne sont pas capturées ici.
// =====================================================================================
mod jeton_scim_relu_avant_toute_lecture {
    use super::jeton_scim_relu_a_chaque_ecriture::*;
    use super::*;

    const JSRL_PHRASE_NON_RELU: &str = "JETON NON REVÉRIFIÉ : la base du plan de contrôle n'a pas pu relire le jeton SCIM de cette demande au moment de la servir — sa validité n'est ni affirmée ni niée. Rien n'est lu ni écrit par cette étape : aucun droit n'est posé ni retiré, les accès en place restent en place. Rien n'est attesté ; la même demande peut être rejouée telle quelle.";

    fn jsrl_ctx(st: &AppState, jeton: &str) -> ScimCtx {
        scim_authentifier_la_demande(jsre_plan(st), &format!("Bearer {jeton}")).expect("lu").expect("fixture : jeton admis")
    }

    fn jsrl_401() -> (u16, Value) {
        (401, Value::String(JSRE_CORPS_401.to_string()))
    }

    // -------------------------------------------------------------------------------------
    // (1) PAR LE ROUTEUR RÉEL : `PUT active=true`, CORPS ENVOYÉ APRÈS LA RECRÉATION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `PUT /Users/{X}` `{"active":true}` (X administrateur du A recréé) puis `PUT /Users/{W}` (W sans
    /// droit nulle part), admis par l'ancien jeton de A avant sa destruction et sa recréation, corps envoyé ensuite : le
    /// `401` de l'entrée, en entier, égal à celui d'un jeton inconnu ; aucune représentation de X ; rien n'est écrit.
    /// Contrôles positifs avec le jeton neuf : X `200` avec le groupe `admin`, W `404` — les deux réponses que la forme
    /// d'avant servait à l'ancien jeton.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AY1c_sans_jeton:scim.user.replace` (200 avec `admin`, puis 404).
    #[tokio::test]
    async fn jsrl_put_active_true_admis_avant_la_recreation_ne_sert_rien() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let x = jsre_uid(&st, JSRE_X);
        let adresse = router_serve(st.clone()).await;
        let inconnu = jsre_refus_d_un_inconnu(adresse).await;
        let corps = r#"{"active":true}"#;
        let chemin_x = format!("/scim/v2/Users/{x}");
        let chemin_w = format!("/scim/v2/Users/{JSRE_UID_W}");
        let sx = jsre_entetes_admis(&st, adresse, "PUT", &chemin_x, JSRE_JETON_A, corps).await;
        let sw = jsre_entetes_admis(&st, adresse, "PUT", &chemin_w, JSRE_JETON_A, corps).await;
        jsre_detruire_et_recreer_a(&st).await;
        let avant = jsre_instantane(&st);
        let servi_x = jsre_corps_envoye(sx, corps).await;
        let servi_w = jsre_corps_envoye(sw, corps).await;
        assert_eq!(servi_x, inconnu, "membre du A recréé : le 401 de l'entrée, en entier, aucune représentation");
        assert_eq!(servi_w, inconnu, "non-membre : le 401 de l'entrée, jamais le 404 qui dirait son absence du A recréé");
        assert_eq!(jsre_instantane(&st), avant, "rien n'est écrit");

        let (statut, v) = jsre_envoi(adresse, "PUT", &chemin_x, JSRE_JETON_A_RECREE, corps).await;
        assert_eq!(statut, 200, "contrôle positif : le jeton neuf lit X : {v}");
        assert!(v.contains("\"admin\""), "contrôle positif : la représentation porte le rôle de X : {v}");
        let (statut, v) = jsre_envoi(adresse, "PUT", &chemin_w, JSRE_JETON_A_RECREE, corps).await;
        assert_eq!(statut, 404, "contrôle positif : W n'est pas membre du A recréé : {v}");
    }

    // -------------------------------------------------------------------------------------
    // (2) PAR LE CONTEXTE DE L'ENTRÉE : LECTURES ET EXISTENCE DES DÉPROVISIONNEMENTS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un contexte admis par l'ancien jeton de A tant que A existe, joué après la destruction et la
    /// recréation : `GET /Users/{X}` (membre du A recréé), `GET /Users/{W}` (non-membre), `GET /Users`, `PUT active=false`
    /// et `DELETE` de W rendent le `401`, en entier ; rien n'est écrit. Contrôles positifs par le contexte du jeton neuf :
    /// `GET X` `200`, `GET W` `404`, la liste porte X et Y, `PUT active=false` et `DELETE` de W `404`.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AY1c_sans_jeton:scim.user.get` (200 puis 404) ; `AY1c_sans_jeton:scim.users.list`
    /// (200, X et Y listés) ; `AY1c_existence_avant_le_jeton` (404 sur `PUT active=false` et `DELETE`) ;
    /// `AY1_tx_deprov_sans_jeton` (404).
    #[tokio::test]
    async fn jsrl_un_contexte_admis_avant_la_recreation_ne_lit_rien_du_tenant_recree() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let x = jsre_uid(&st, JSRE_X);
        let ancien = jsrl_ctx(&st, JSRE_JETON_A);
        jsre_detruire_et_recreer_a(&st).await;
        let neuf = jsrl_ctx(&st, JSRE_JETON_A_RECREE);
        let avant = jsre_instantane(&st);

        let get_x = jsre_corps(scim_user_get(State(st.clone()), Extension(ancien.clone()), Path(x.clone())).await).await;
        let get_w = jsre_corps(scim_user_get(State(st.clone()), Extension(ancien.clone()), Path(JSRE_UID_W.to_string())).await).await;
        let liste = jsre_corps(scim_users_list(State(st.clone()), Extension(ancien.clone()), axum::extract::Query(HashMap::new())).await).await;
        let put_w = jsre_corps(
            scim_user_replace(State(st.clone()), Extension(ancien.clone()), Path(JSRE_UID_W.to_string()), Json(json!({ "active": false }))).await,
        )
        .await;
        let delete_w = jsre_corps(scim_user_delete(State(st.clone()), Extension(ancien.clone()), Path(JSRE_UID_W.to_string())).await).await;
        assert_eq!(get_x, jsrl_401(), "GET d'un membre du A recréé : le 401, en entier");
        assert_eq!(get_w, jsrl_401(), "GET d'un non-membre : le 401, jamais le 404");
        assert_eq!(liste, jsrl_401(), "GET /Users : le 401, aucune liste du A recréé");
        assert_eq!(put_w, jsrl_401(), "PUT active=false d'un non-membre : le 401, jamais le 404");
        assert_eq!(delete_w, jsrl_401(), "DELETE d'un non-membre : le 401, jamais le 404");
        assert_eq!(jsre_instantane(&st), avant, "rien n'est écrit");

        let (statut, v) = jsre_corps(scim_user_get(State(st.clone()), Extension(neuf.clone()), Path(x.clone())).await).await;
        assert_eq!((statut, v["groups"].clone()), (200, json!([{ "value": "admin", "type": "direct" }])), "contrôle positif : GET X par le jeton neuf");
        let (statut, _) = jsre_corps(scim_user_get(State(st.clone()), Extension(neuf.clone()), Path(JSRE_UID_W.to_string())).await).await;
        assert_eq!(statut, 404, "contrôle positif : W n'est pas membre du A recréé");
        let (statut, v) = jsre_corps(scim_users_list(State(st.clone()), Extension(neuf.clone()), axum::extract::Query(HashMap::new())).await).await;
        let noms: Vec<&str> = v["Resources"].as_array().map(|r| r.iter().filter_map(|u| u["userName"].as_str()).collect()).unwrap_or_default();
        assert_eq!((statut, noms), (200, vec![JSRE_X, JSRE_Y]), "contrôle positif : la liste du A recréé");
        let (statut, _) = jsre_corps(
            scim_user_replace(State(st.clone()), Extension(neuf.clone()), Path(JSRE_UID_W.to_string()), Json(json!({ "active": false }))).await,
        )
        .await;
        assert_eq!(statut, 404, "contrôle positif : PUT active=false d'un non-membre, 404");
        let (statut, _) = jsre_corps(scim_user_delete(State(st.clone()), Extension(neuf.clone()), Path(JSRE_UID_W.to_string())).await).await;
        assert_eq!(statut, 404, "contrôle positif : DELETE d'un non-membre, 404");
        assert_eq!(jsre_instantane(&st), avant, "contrôles positifs : rien n'est écrit (lectures et non-membre)");
    }

    // -------------------------------------------------------------------------------------
    // (3) `POST /Users` SANS GROUPES : LA RELECTURE ET LA POSE SOUS UN SEUL VERROU
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, pour A détruit SEUL puis pour A détruit et recréé avec un jeton neuf, au point de course de
    /// production `scim-jeton-avant-l-identite` : `POST /Users` SANS groupes admis par l'ancien jeton rend le `401`, en
    /// entier ; ni identité au nom demandé, ni provenance sous A, ni ligne `scim.user.provision`. Contrôle positif : le
    /// jeton neuf du A recréé crée l'identité (`201`, provenance A).
    /// LA MUTATION QUI LE FAIT ROUGIR : `AY1c_relecture_avant_le_point` (201, identité de provenance A attestée — la
    /// forme d'avant).
    #[tokio::test]
    async fn jsrl_post_sans_groupes_d_un_tenant_detruit_au_point_de_course_ne_cree_rien() {
        let _env = VERROU_ENV_PROCESSUS.read();
        for recreer in [false, true] {
            let (st, _dir) = jsre_deux_tenants().await;
            let st_course = st.clone();
            crate::handlers::transaction_validee::poser_un_crochet_de_course(&format!("scim-jeton-avant-l-identite:{}", jsre_plan(&st).db_path), move || {
                assert!(tenant_destroy(&st_course.tenants, JSRE_A).is_ok(), "fixture : A détruit pendant la demande");
                if recreer {
                    let chemin = format!("{}.jsrl-course", jsre_plan(&st_course).db_path);
                    assert!(tenant_provision(&st_course.tenants, JSRE_A, JSRE_A, &chemin, "").is_ok(), "fixture : A recréé pendant la demande");
                    jsre_poser_le_jeton(&st_course, JSRE_JETON_A_RECREE, JSRE_A);
                }
            });
            let adresse = router_serve(st.clone()).await;
            let servi = jsre_envoi(adresse, "POST", "/scim/v2/Users", JSRE_JETON_A, r#"{"userName":"jsrl-nu"}"#).await;
            assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM scim_token WHERE hash=?1", &sha256_hex(JSRE_JETON_A.as_bytes())), 0, "fixture ({recreer}) : la course a eu lieu");
            assert_eq!(servi, (401, JSRE_CORPS_401.to_string()), "recréé={recreer} : le 401 de l'entrée, en entier");
            assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM platform_user WHERE name=?1", "jsrl-nu"), 0, "recréé={recreer} : aucune identité");
            assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM scim_provenance WHERE tenant_id=?1", JSRE_A), 0, "recréé={recreer} : aucune provenance sous A");
            assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM control_ledger WHERE kind=?1", "scim.user.provision"), 0, "recréé={recreer} : aucune ligne de contrôle");

            if recreer {
                let (statut, v) = jsre_envoi(adresse, "POST", "/scim/v2/Users", JSRE_JETON_A_RECREE, r#"{"userName":"jsrl-nu"}"#).await;
                assert_eq!(statut, 201, "contrôle positif : le jeton neuf crée l'identité : {v}");
                let uid = jsre_uid(&st, "jsrl-nu");
                assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM scim_provenance WHERE user_id=?1 AND tenant_id='jsre-a'", &uid), 1, "contrôle positif : provenance A");
            }
        }
    }

    /// CE QU'IL TIENT : `POST /Users` de W (sans droit ni provenance, rattachable) avec le groupe `admin`, admis par
    /// l'ancien jeton ; A détruit puis recréé (jeton neuf) au point de course `scim-identite-avant-ses-droits`, après la
    /// pose de l'identité et avant la transaction des droits : le `401`, en entier ; W n'a aucun droit nulle part,
    /// aucune ligne `scim.user.provision`. La relecture d'avant l'identité ne peut pas le voir (A existait) : c'est celle
    /// de la transaction des droits qui tient.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AY1_tx_post_sans_jeton` (201, W administrateur du A recréé).
    #[tokio::test]
    async fn jsrl_post_avec_groupes_detruit_entre_l_identite_et_ses_droits_ne_pose_aucun_droit() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let st_course = st.clone();
        crate::handlers::transaction_validee::poser_un_crochet_de_course(&format!("scim-identite-avant-ses-droits:{}", jsre_plan(&st).db_path), move || {
            assert!(tenant_destroy(&st_course.tenants, JSRE_A).is_ok(), "fixture : A détruit pendant la demande");
            let chemin = format!("{}.jsrl-droits", jsre_plan(&st_course).db_path);
            assert!(tenant_provision(&st_course.tenants, JSRE_A, JSRE_A, &chemin, "").is_ok(), "fixture : A recréé pendant la demande");
            jsre_poser_le_jeton(&st_course, JSRE_JETON_A_RECREE, JSRE_A);
        });
        let adresse = router_serve(st.clone()).await;
        let corps = format!(r#"{{"userName":"{JSRE_W}","groups":[{{"value":"admin"}}]}}"#);
        let servi = jsre_envoi(adresse, "POST", "/scim/v2/Users", JSRE_JETON_A, &corps).await;
        assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM scim_token WHERE hash=?1", &sha256_hex(JSRE_JETON_A_RECREE.as_bytes())), 1, "fixture : la course a eu lieu");
        assert_eq!(servi, (401, JSRE_CORPS_401.to_string()), "le 401 de l'entrée, en entier");
        assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM \"grant\" WHERE user_id=?1", JSRE_UID_W), 0, "W n'a aucun droit nulle part");
        assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM control_ledger WHERE kind=?1", "scim.user.provision"), 0, "aucune ligne de contrôle");
    }

    // -------------------------------------------------------------------------------------
    // (4) LE JETON NON RELU À LA LECTURE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un contexte admis, puis la table des jetons hors d'atteinte : `GET /Users/{X}`, `GET /Users` et
    /// `PUT /Users/{X}` `active=true` rendent le `503` au corps EXACT (ni la représentation ni la liste) ; rien n'est
    /// écrit. Contrôle positif, table remise : `GET X` `200`.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AY1c_sans_jeton:scim.user.get`, `AY1c_sans_jeton:scim.users.list`,
    /// `AY1c_sans_jeton:scim.user.replace` (200 chacune).
    #[tokio::test]
    async fn jsrl_un_jeton_non_relu_a_la_lecture_est_un_503_nomme() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let x = jsre_uid(&st, JSRE_X);
        let ctx = jsrl_ctx(&st, JSRE_JETON_A);
        let attendu = (503u16, json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": JSRL_PHRASE_NON_RELU, "status": "503" }));
        let avant = jsre_instantane(&st);
        jsre_sql(&st, JSRE_JETONS_HORS_D_ATTEINTE);
        let get = jsre_corps(scim_user_get(State(st.clone()), Extension(ctx.clone()), Path(x.clone())).await).await;
        let liste = jsre_corps(scim_users_list(State(st.clone()), Extension(ctx.clone()), axum::extract::Query(HashMap::new())).await).await;
        let put = jsre_corps(scim_user_replace(State(st.clone()), Extension(ctx.clone()), Path(x.clone()), Json(json!({ "active": true }))).await).await;
        jsre_sql(&st, JSRE_JETONS_REMIS);
        assert_eq!(get, attendu, "GET /Users/{{id}} : le 503, EN ENTIER");
        assert_eq!(liste, attendu, "GET /Users : le 503, EN ENTIER");
        assert_eq!(put, attendu, "PUT active=true : le 503, EN ENTIER");
        assert_eq!(jsre_instantane(&st), avant, "rien n'est écrit");
        let (statut, _) = jsre_corps(scim_user_get(State(st.clone()), Extension(ctx.clone()), Path(x.clone())).await).await;
        assert_eq!(statut, 200, "contrôle positif : la table remise, X se lit");
    }
}
