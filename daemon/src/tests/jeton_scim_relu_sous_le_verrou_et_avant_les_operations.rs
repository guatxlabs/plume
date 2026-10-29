// =====================================================================================
// `P10.34-q` — L'ORDRE ET L'ATOMICITÉ DE LA RELECTURE DU JETON SCIM.
//
// Un jeton d'un tenant absent, détruit ou recréé est refusé, y compris pour une demande déjà admise. Les témoins de
// `jeton_scim_relu_a_chaque_ecriture.rs` et `jeton_scim_relu_avant_toute_lecture.rs` tiennent QUE le jeton est relu ;
// ceux-ci tiennent OÙ il l'est (deux tenants réels, fixture de `jeton_scim_relu_a_chaque_ecriture.rs`, routeur réel) :
//  * ORDRE — dans la transaction de `PATCH /Groups`, AVANT toute opération : un `PATCH` admis par l'ancien jeton de A,
//    corps envoyé après la destruction puis la recréation de A, rend le `401` de l'entrée, EN ENTIER, pour un `add` d'un
//    identifiant inconnu comme pour le `remove` du seul administrateur du A recréé ; rien n'est écrit. Contrôles
//    positifs avec le jeton neuf : le `400 noTarget` et le `409` que ces opérations rendent bien ;
//  * ORDRE — dans la transaction des droits de `POST /Users`, AVANT le rattachement et tout droit : un nom NEUF avec un
//    groupe, A détruit puis recréé entre la pose de l'identité et ses droits (point de course
//    `scim-identite-avant-ses-droits`) : le `401`, en entier ; aucun droit, aucune ligne de contrôle ;
//  * ATOMICITÉ — `scim_lire_pour_la_demande` (`GET /Users/{id}`, `GET /Users`, `PUT active=true`) et la pose de
//    l'identité de `POST /Users` relisent le jeton et lisent / posent SOUS LE MÊME VERROU. Le point de course de production
//    (`scim-jeton-relu-avant-la-lecture`, `scim-jeton-relu-avant-l-identite`) est entre la relecture et la lecture /
//    la pose ; le crochet lit `is_locked()` sur le verrou du plan de contrôle et lance la destruction (puis la
//    recréation) de A dans un fil concurrent (modèle `mpra_course`). Verrou tenu : la destruction attend, la demande
//    est servie sur l'état d'avant (la représentation de X administrateur ; l'identité posée PUIS sa provenance scellée
//    par la destruction). Verrou relâché : la destruction passerait en entier avant la lecture ou la pose ;
//  * le journal de contrôle de `PUT active=false` (`scim.user.deprovision`) porte le NOM du membre et son identifiant,
//    ligne entière, et la représentation servie porte le nom.
//
// MUTANTS (sous `cfg!(test)`, choisis par une variable d environnement, retirés avant le commit), chacun vu ROUGE :
// AZ1_V29_patch_jeton_apres_ops, AZ1_V30_post_tx_jeton_apres_rattachement, AZ1_V14_lecture_verrou_scinde (le point
// de course n'est plus atteint), AZ1_V14g_lecture_verrou_scinde_point_entre (le point entre deux verrous),
// AZ1_V25_post_verrou_scinde (idem pour la pose), AZ1_V21_deprov_nom_id.
//
// LIMITES : un témoin de course n'observe que l'intervalle où un point de course est posé. Un verrou scindé AILLEURS
// qu'au point de production (sans point dans l'intervalle) n'est observable par aucun témoin de ce genre.
// =====================================================================================
mod jeton_scim_relu_sous_le_verrou_et_avant_les_operations {
    use super::jeton_scim_relu_a_chaque_ecriture::*;
    use super::*;
    use crate::handlers::transaction_validee::poser_un_crochet_de_course;

    // ---------- le témoin de course (modèle `mpra_course`) ----------

    /// Ce que le crochet a vu (le verrou du plan de contrôle tenu au point de course ?) et le fil du geste concurrent.
    struct JsrvCourse {
        verrou_tenu: Arc<Mutex<Option<bool>>>,
        fil: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
    }

    fn jsrv_course(cle: &str, verrou: Arc<Mutex<Connection>>, concurrent: impl FnOnce() + Send + 'static) -> JsrvCourse {
        let course = JsrvCourse { verrou_tenu: Arc::new(Mutex::new(None)), fil: Arc::new(Mutex::new(None)) };
        let (verrou_tenu, fil) = (course.verrou_tenu.clone(), course.fil.clone());
        poser_un_crochet_de_course(cle, move || {
            let tenu = verrou.is_locked();
            *verrou_tenu.lock() = Some(tenu);
            let concurrent = std::thread::spawn(concurrent);
            if tenu {
                // Le geste tient le verrou : le concurrent l'attend, il est joint après la réponse.
                *fil.lock() = Some(concurrent);
            } else {
                // Le verrou est libre : le concurrent passe EN ENTIER ici, avant la lecture ou la pose.
                concurrent.join().expect("fil concurrent");
            }
        });
        course
    }

    /// Joint le fil concurrent s'il attend encore ; rend ce que le crochet a vu (`None` : point jamais atteint).
    fn jsrv_attendre(course: &JsrvCourse) -> Option<bool> {
        let fil = course.fil.lock().take();
        if let Some(fil) = fil {
            fil.join().expect("fil concurrent");
        }
        *course.verrou_tenu.lock()
    }

    /// Le concurrent : A détruit, puis (si `recreer`) recréé SANS administrateur, avec le jeton neuf.
    fn jsrv_detruire(st: &AppState, recreer: bool, suffixe: &str) -> impl FnOnce() + Send + 'static {
        let st = st.clone();
        let suffixe = suffixe.to_string();
        move || {
            assert!(tenant_destroy(&st.tenants, JSRE_A).is_ok(), "fixture : A détruit pendant la demande");
            if recreer {
                let chemin = format!("{}.{suffixe}", jsre_plan(&st).db_path);
                assert!(tenant_provision(&st.tenants, JSRE_A, JSRE_A, &chemin, "").is_ok(), "fixture : A recréé pendant la demande");
                jsre_poser_le_jeton(&st, JSRE_JETON_A_RECREE, JSRE_A);
            }
        }
    }

    fn jsrv_json(corps: &str) -> Value {
        serde_json::from_str(corps).unwrap_or_else(|_| Value::String(corps.to_string()))
    }

    fn jsrv_jeton_present(st: &AppState, jeton: &str) -> i64 {
        jsre_compter(st, "SELECT COUNT(*) FROM scim_token WHERE hash=?1", &sha256_hex(jeton.as_bytes()))
    }

    // -------------------------------------------------------------------------------------
    // (1) ORDRE : `PATCH /Groups`, LE JETON RELU AVANT TOUTE OPÉRATION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `PATCH /Groups/admin` `add` d'un identifiant que personne ne porte, admis par l'ancien jeton de A,
    /// corps envoyé après la destruction puis la recréation de A : le `401` de l'entrée, en entier ; rien n'est écrit.
    /// Contrôle positif, la même demande avec le jeton neuf : `400` `noTarget` (la réponse que l'ordre inverse servirait).
    /// LA MUTATION QUI LE FAIT ROUGIR : `AZ1_V29_patch_jeton_apres_ops` (relecture après la boucle : `400 noTarget`).
    #[tokio::test]
    async fn jsrv_patch_add_d_un_inconnu_admis_avant_la_recreation_rend_le_401() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let adresse = router_serve(st.clone()).await;
        let corps = r#"{"Operations":[{"op":"add","value":[{"value":"pu_jsrv_jamais_vu"}]}]}"#;
        let s = jsre_entetes_admis(&st, adresse, "PATCH", "/scim/v2/Groups/admin", JSRE_JETON_A, corps).await;
        jsre_detruire_et_recreer_a(&st).await;
        let avant = jsre_instantane(&st);
        let servi = jsre_corps_envoye(s, corps).await;
        assert_eq!(servi, (401, JSRE_CORPS_401.to_string()), "PATCH add d'un inconnu, admis par l'ancien jeton : le 401, en entier");
        assert_eq!(jsre_instantane(&st), avant, "rien n'est écrit");

        let (statut, v) = jsre_envoi(adresse, "PATCH", "/scim/v2/Groups/admin", JSRE_JETON_A_RECREE, corps).await;
        assert_eq!((statut, jsrv_json(&v)["scimType"].clone()), (400, json!("noTarget")), "contrôle positif : le jeton neuf, 400 noTarget : {v}");
        assert_eq!(jsre_instantane(&st), avant, "contrôle positif : rien n'est écrit");
    }

    /// CE QU'IL TIENT : X seul administrateur du A recréé ; `PATCH /Groups/admin` `remove` de X, admis par l'ancien jeton
    /// de A avant la destruction et la recréation, corps envoyé ensuite : le `401`, en entier ; rien n'est écrit (X reste
    /// administrateur). Contrôle positif avec le jeton neuf : le `409` de l'anti-verrouillage.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AZ1_V29_patch_jeton_apres_ops` (`409` dernier administrateur).
    #[tokio::test]
    async fn jsrv_patch_retrait_du_dernier_administrateur_admis_avant_la_recreation_rend_le_401() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let x = jsre_uid(&st, JSRE_X);
        let adresse = router_serve(st.clone()).await;
        let corps = format!(r#"{{"Operations":[{{"op":"remove","path":"members[value eq \"{x}\"]"}}]}}"#);
        let s = jsre_entetes_admis(&st, adresse, "PATCH", "/scim/v2/Groups/admin", JSRE_JETON_A, &corps).await;
        jsre_detruire_et_recreer_a(&st).await;
        jsre_sql(&st, &format!("DELETE FROM \"grant\" WHERE user_id='{JSRE_UID_Y}' AND tenant_id='{JSRE_A}';"));
        assert_eq!(jsre_droits(&st, JSRE_A), vec![format!("{JSRE_X}:admin")], "fixture : X seul administrateur du A recréé");
        let avant = jsre_instantane(&st);
        let servi = jsre_corps_envoye(s, &corps).await;
        assert_eq!(servi, (401, JSRE_CORPS_401.to_string()), "PATCH remove du dernier administrateur, ancien jeton : le 401, en entier");
        assert_eq!(jsre_instantane(&st), avant, "rien n'est écrit");

        let (statut, v) = jsre_envoi(adresse, "PATCH", "/scim/v2/Groups/admin", JSRE_JETON_A_RECREE, &corps).await;
        assert_eq!(statut, 409, "contrôle positif : le jeton neuf, 409 de l'anti-verrouillage : {v}");
        assert_eq!(jsre_droits(&st, JSRE_A), vec![format!("{JSRE_X}:admin")], "contrôle positif : X reste administrateur");
    }

    // -------------------------------------------------------------------------------------
    // (2) ORDRE : DROITS DE `POST /Users`, LE JETON RELU AVANT LE RATTACHEMENT
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `POST /Users` d'un nom NEUF avec le groupe `admin`, admis par l'ancien jeton ; A détruit puis
    /// recréé (jeton neuf) au point de course `scim-identite-avant-ses-droits` : l'identité est posée avec la provenance
    /// de A, que la destruction scelle ; la transaction des droits rend le `401`, en entier ; aucun droit pour ce nom,
    /// aucune ligne `scim.user.provision`.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AZ1_V30_post_tx_jeton_apres_rattachement` (le rattachement jugé d'abord :
    /// `409 uniqueness`).
    #[tokio::test]
    async fn jsrv_post_nom_neuf_detruit_entre_l_identite_et_ses_droits_rend_le_401() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        poser_un_crochet_de_course(&format!("scim-identite-avant-ses-droits:{}", jsre_plan(&st).db_path), jsrv_detruire(&st, true, "jsrv-droits"));
        let adresse = router_serve(st.clone()).await;
        let servi = jsre_envoi(adresse, "POST", "/scim/v2/Users", JSRE_JETON_A, r#"{"userName":"jsrv-neuf","groups":[{"value":"admin"}]}"#).await;
        assert_eq!(jsrv_jeton_present(&st, JSRE_JETON_A_RECREE), 1, "fixture : la course a eu lieu");
        assert_eq!(servi, (401, JSRE_CORPS_401.to_string()), "nom neuf, course entre l'identité et ses droits : le 401, en entier");
        let uid = jsre_uid(&st, "jsrv-neuf");
        assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM \"grant\" WHERE user_id=?1", &uid), 0, "aucun droit pour ce nom");
        assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM control_ledger WHERE kind=?1", "scim.user.provision"), 0, "aucune ligne de contrôle");
    }

    // -------------------------------------------------------------------------------------
    // (3) ATOMICITÉ : LECTURES, LE JETON RELU ET LU SOUS LE MÊME VERROU
    // -------------------------------------------------------------------------------------

    /// La lecture `methode chemin corps` par l'ancien jeton de A, la course posée au point de production
    /// `scim-jeton-relu-avant-la-lecture` (A détruit puis recréé sans administrateur) ; rend ce qui est servi et ce que le
    /// crochet a vu, une fois le concurrent joint (l'appelant juge d'abord ce qui est servi, puis le verrou).
    async fn jsrv_lecture_sous_course(st: &AppState, methode: &str, chemin: &str, corps: &str) -> (u16, Value, Option<bool>) {
        let course = jsrv_course(&format!("scim-jeton-relu-avant-la-lecture:{}", jsre_plan(st).db_path), jsre_plan(st).conn.clone(), jsrv_detruire(st, true, "jsrv-lecture"));
        let adresse = router_serve(st.clone()).await;
        let (statut, v) = jsre_envoi(adresse, methode, chemin, JSRE_JETON_A, corps).await;
        let tenu = jsrv_attendre(&course);
        assert_eq!((jsrv_jeton_present(st, JSRE_JETON_A), jsrv_jeton_present(st, JSRE_JETON_A_RECREE)), (0, 1), "fixture : la course a eu lieu");
        (statut, jsrv_json(&v), tenu)
    }

    fn jsrv_verrou_tenu(tenu: Option<bool>, quoi: &str) {
        assert_eq!(tenu, Some(true), "{quoi} : le point de course est atteint, verrou TENU entre la relecture et la lecture");
    }

    /// CE QU'IL TIENT : `GET /Users/{X}` par l'ancien jeton, destruction et recréation de A au point de course sous le
    /// verrou : la destruction attend, la représentation servie est celle de X administrateur de A (état d'avant), en entier.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AZ1_V14_lecture_verrou_scinde` (point jamais atteint : `None`) ;
    /// `AZ1_V14g_lecture_verrou_scinde_point_entre` (verrou libre, `404` lu sur le A recréé).
    #[tokio::test]
    async fn jsrv_get_d_un_membre_relu_et_lu_sous_le_meme_verrou() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let x = jsre_uid(&st, JSRE_X);
        let (statut, v, tenu) = jsrv_lecture_sous_course(&st, "GET", &format!("/scim/v2/Users/{x}"), "").await;
        let attendu = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "id": x, "userName": JSRE_X, "active": true,
            "groups": [{ "value": "admin", "type": "direct" }], "meta": { "resourceType": "User" }
        });
        assert_eq!((statut, v), (200, attendu), "GET X : la représentation de l'état d'avant la destruction");
        jsrv_verrou_tenu(tenu, "GET /Users/{id}");
    }

    /// CE QU'IL TIENT : `GET /Users` par l'ancien jeton, même course : la liste servie est celle de A d'avant (X seul).
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AZ1_V14_lecture_verrou_scinde`, `AZ1_V14g_lecture_verrou_scinde_point_entre`
    /// (liste vide du A recréé).
    #[tokio::test]
    async fn jsrv_liste_relue_et_lue_sous_le_meme_verrou() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let (statut, v, tenu) = jsrv_lecture_sous_course(&st, "GET", "/scim/v2/Users", "").await;
        let noms: Vec<&str> = v["Resources"].as_array().map(|r| r.iter().filter_map(|u| u["userName"].as_str()).collect()).unwrap_or_default();
        assert_eq!((statut, v["totalResults"].clone(), noms), (200, json!(1), vec![JSRE_X]), "GET /Users : la liste de A d'avant la destruction : {v}");
        jsrv_verrou_tenu(tenu, "GET /Users");
    }

    /// CE QU'IL TIENT : `PUT /Users/{X}` `active=true` par l'ancien jeton, même course : `200`, X administrateur.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AZ1_V14_lecture_verrou_scinde`, `AZ1_V14g_lecture_verrou_scinde_point_entre`
    /// (`404`).
    #[tokio::test]
    async fn jsrv_put_active_true_relu_et_lu_sous_le_meme_verrou() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let x = jsre_uid(&st, JSRE_X);
        let (statut, v, tenu) = jsrv_lecture_sous_course(&st, "PUT", &format!("/scim/v2/Users/{x}"), r#"{"active":true}"#).await;
        assert_eq!((statut, v["userName"].clone(), v["groups"].clone()), (200, json!(JSRE_X), json!([{ "value": "admin", "type": "direct" }])), "PUT active=true : X d'avant la destruction : {v}");
        jsrv_verrou_tenu(tenu, "PUT active=true");
    }

    // -------------------------------------------------------------------------------------
    // (4) ATOMICITÉ : `POST /Users`, LE JETON RELU ET L'IDENTITÉ POSÉE SOUS LE MÊME VERROU
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `POST /Users` SANS groupes par l'ancien jeton ; A détruit (seul) au point de course
    /// `scim-jeton-relu-avant-l-identite`, entre la relecture et la pose : le verrou est TENU, la destruction attend ;
    /// la demande est servie avant elle (`201`), puis la destruction scelle la provenance de l'identité : aucune
    /// provenance ne reste sous l'identifiant de A, absent du catalogue.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AZ1_V25_post_verrou_scinde` (verrou libre : la destruction passe avant la pose,
    /// l'identité garde la provenance de A absent).
    #[tokio::test]
    async fn jsrv_post_relu_et_pose_sous_le_meme_verrou() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let course = jsrv_course(&format!("scim-jeton-relu-avant-l-identite:{}", jsre_plan(&st).db_path), jsre_plan(&st).conn.clone(), jsrv_detruire(&st, false, "jsrv-pose"));
        let adresse = router_serve(st.clone()).await;
        let (statut, v) = jsre_envoi(adresse, "POST", "/scim/v2/Users", JSRE_JETON_A, r#"{"userName":"jsrv-nu"}"#).await;
        let tenu = jsrv_attendre(&course);
        assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM tenant WHERE id=?1", JSRE_A), 0, "fixture : A détruit");
        assert_eq!(statut, 201, "la demande est servie avant la destruction : {v}");
        let uid = jsre_uid(&st, "jsrv-nu");
        assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM scim_provenance WHERE tenant_id=?1", JSRE_A), 0, "aucune provenance sous A absent");
        let provenance: Vec<String> = {
            let c = jsre_plan(&st).conn.lock();
            let mut s = c.prepare("SELECT tenant_id FROM scim_provenance WHERE user_id=?1").expect("fixture");
            let lus = s.query_map(params![uid], |r| r.get::<_, String>(0)).expect("fixture").collect::<Result<Vec<_>, _>>().expect("fixture : lisible");
            lus
        };
        assert_eq!(provenance, vec!["(tenant détruit)".to_string()], "la provenance posée puis scellée par la destruction");
        assert_eq!(tenu, Some(true), "le point de course est atteint, verrou TENU entre la relecture et la pose");
    }

    // -------------------------------------------------------------------------------------
    // (5) LE JOURNAL DE CONTRÔLE DE `PUT active=false`
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : W lecteur de A ; `PUT /Users/{W}` `active=false` par le jeton de A : `200`, la représentation
    /// porte le NOM de W, en entier ; la ligne `scim.user.deprovision` du journal de contrôle, ENTIÈRE (acteur, tenant,
    /// détail), porte le nom et l'identifiant.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AZ1_V21_deprov_nom_id` (l'identifiant à la place du nom).
    #[tokio::test]
    async fn jsrv_put_active_false_nomme_le_membre_au_journal_de_controle() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        jsre_sql(&st, &format!("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES('{JSRE_UID_W}','{JSRE_A}','viewer');"));
        let adresse = router_serve(st.clone()).await;
        let (statut, v) = jsre_envoi(adresse, "PUT", &format!("/scim/v2/Users/{JSRE_UID_W}"), JSRE_JETON_A, r#"{"active":false}"#).await;
        let attendu = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "id": JSRE_UID_W, "userName": JSRE_W, "active": false,
            "groups": [], "meta": { "resourceType": "User" }
        });
        assert_eq!((statut, jsrv_json(&v)), (200, attendu), "PUT active=false : la représentation nomme W");
        let lignes: Vec<(String, String, String)> = {
            let c = jsre_plan(&st).conn.lock();
            let mut s = c.prepare("SELECT actor, tenant, detail FROM control_ledger WHERE kind='scim.user.deprovision' ORDER BY id").expect("fixture");
            let lus = s
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
                .expect("fixture")
                .collect::<Result<Vec<_>, _>>()
                .expect("fixture : lisible");
            lus
        };
        assert_eq!(
            lignes,
            vec![("scim".to_string(), JSRE_A.to_string(), format!("user '{JSRE_W}' (id={JSRE_UID_W}) désactivé -> grants retirés"))],
            "la ligne de contrôle, entière"
        );
        assert_eq!(jsre_droits(&st, JSRE_A), vec![format!("{JSRE_X}:admin")], "les droits de W sont retirés");
    }
}
