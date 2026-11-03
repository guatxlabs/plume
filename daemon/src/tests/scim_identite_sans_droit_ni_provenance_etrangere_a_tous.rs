// =====================================================================================
// `P10.34-h` (décision de l'exploitant du 2026-11-03) — UNE IDENTITÉ SANS DROIT NI PROVENANCE N'EST RATTACHABLE PAR
// AUCUN JETON SCIM.
//
// CE QUI ÉTAIT FAUX (daemon/src/rbac.rs, `lire_le_rattachement_scim`) : une identité de la plateforme qui ne porte de
// droit dans aucun tenant et n'a pas de provenance SCIM — née avant la provenance, par `grant_set` ou par la création
// d'un tenant, ou rendue telle par la destruction du seul tenant où elle avait un droit — tombait dans la dernière
// branche du jugement, RATTACHABLE : `POST /Users` de son nom servait son id à n'importe quel tenant, `PATCH /Groups`
// (ajout, ensemble servi d'un `replace`) lui posait un droit. Désormais rattachable seulement par un droit ici ou la
// provenance de ce tenant ; tout le reste est étranger.
//
// CE QUE CES TÉMOINS TIENNENT, en mode multi-tenant avec DEUX tenants réels (`tenant_create`, bases chiffrées, un jeton
// SCIM chacun), PAR LE ROUTEUR RÉEL (bearer, `auth_guard`) :
//  * vieux (ligne `platform_user` posée à la main, ni droit ni provenance) : pour CHAQUE tenant, `POST /Users` de son nom,
//    sans puis avec `groups`, rend le `409 uniqueness` EN ENTIER, sans son id ; `PATCH /Groups` `add` et `replace path
//    members` rendent le `400 noTarget` d'un id jamais servi, statut et corps à l'octet ; l'état du plan de contrôle
//    (jetons, provenance, droits, identités, catalogue, journal de contrôle) est identique avant et après ; contrôle
//    positif : un nom neuf est créé par le même jeton ;
//  * la SORTIE de cette classe : un droit posé dans A par `grant_set` (super-administrateur, hors SCIM) rend vieux
//    rattachable par A (`PATCH add` `200`, `POST /Users` `201` avec SON id) et étranger pour B (`409`, `noTarget`) ;
//  * orph, né par `grant_set` dans A seulement : rattachable par A ; A détruit (`tenant_destroy`) puis recréé sous le
//    même identifiant avec un jeton neuf : étranger à B ET au A recréé (`409`, `noTarget` sur `add` et `replace`) ;
//  * cas déjà tenus, inchangés : un membre de A porteur aussi d'un droit dans B est rattachable par les deux ; une
//    identité créée par le `POST /Users` de A le reste pour A (rejeu `201` avec son id, `PATCH add` `200`) et est
//    étrangère pour B ;
//  * au point de course de `POST /Users` (jugement fait, droits pas encore écrits), le droit dans A qui rendait mbre
//    rattachable est retiré : le rejugement rend le `409` EN ENTIER, aucun droit écrit, rien au journal de contrôle ;
//    contrôle sans geste concurrent : `201`, son id, son droit.
//
// MUTANTS (sous `cfg!(test)`, choisis par la variable de mutation, retirés avant le commit), chacun vu ROUGE : BL2_RETRO (la
// dernière branche rend de nouveau `Rattachable` à une identité sans droit ni provenance), BL2_POST_SANS_JUGEMENT
// (`POST /Users` sert l'id d'un nom étranger), BL2_POST_SANS_REJUGEMENT (la transaction des droits de `POST /Users` ne
// rejuge plus), BL2_ADD_SANS_JUGEMENT, BL2_REPLACE_SANS_JUGEMENT (l'ajout, l'ensemble servi d'un `replace`, admettent
// toute identité connue de la plateforme), BL2_ICI (le droit ici n'est plus lu), BL2_CREATEUR (la provenance de ce
// tenant n'est plus lue).
//
// CE QU'ILS NE TIENNENT PAS : le mode mono-tenant n'est pas joué ici. Le code le décide ailleurs : `server/mod.rs`
// n'ouvre le plan de contrôle que sous `PLUME_MULTI_TENANT=1` (`control = None` sinon), et `auth.rs` (`auth_guard`)
// comme chaque gestionnaire de `scim.rs` rend `404` sur `/scim/v2/*` quand `control` vaut `None`, avant tout jugement.
// Le SSO n'appelle pas ce jugement (seul `scim.rs` appelle `rattachement_scim_conn` et `poser_l_identite_scim_conn`).
// =====================================================================================
mod scim_identite_sans_droit_ni_provenance_etrangere_a_tous {
    use super::jeton_scim_relu_a_chaque_ecriture::{jsre_corps, jsre_droits, jsre_envoi, jsre_instantane, jsre_plan, jsre_poser_le_jeton, jsre_uid};
    use super::*;
    use crate::handlers::transaction_validee::poser_un_crochet_de_course;

    const SDNP_A: &str = "sdnp-a";
    const SDNP_B: &str = "sdnp-b";
    const SDNP_JETON_A: &str = "sdnp-jeton-de-test-a";
    const SDNP_JETON_A_RECREE: &str = "sdnp-jeton-de-test-a-recree";
    const SDNP_JETON_B: &str = "sdnp-jeton-de-test-b";
    const SDNP_ADMIN_A: &str = "sdnp-adm-a";
    const SDNP_ADMIN_B: &str = "sdnp-adm-b";
    /// Une identité née avant la provenance : ligne `platform_user` sans droit ni provenance.
    const SDNP_VIEUX: &str = "sdnp-vieux";
    const SDNP_UID_VIEUX: &str = "pu_sdnp_vieux";
    /// Un id que la plateforme n'a jamais servi : la référence du `noTarget`.
    const SDNP_INCONNU: &str = "pu_sdnp_jamais_servi";

    /// Le `409 uniqueness`, EN ENTIER, phrase recopiée (jamais lue de la production).
    fn sdnp_unicite() -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "scimType": "uniqueness",
            "detail": "userName déjà pris sur la plateforme par une identité que ce tenant ne peut pas rattacher : l'utilisateur n'est ni créé ni modifié, aucun droit n'est posé",
            "status": "409",
        })
    }

    /// Le `400 noTarget` d'un membre que ce tenant ne connaît pas, EN ENTIER, phrase recopiée.
    fn sdnp_sans_cible() -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "scimType": "noTarget",
            "detail": "opération n°1 : un membre visé n'est pas une identité connue de ce tenant ; la demande est atomique, aucune de ses opérations n'est appliquée",
            "status": "400",
        })
    }

    fn sdnp_groupe(role: &str) -> Value {
        json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "id": role, "displayName": role })
    }

    fn sdnp_json(corps: &str) -> Value {
        serde_json::from_str(corps).unwrap_or_else(|e| panic!("corps JSON ({e}) : {corps}"))
    }

    fn sdnp_ajout(id: &str) -> String {
        json!({ "Operations": [{ "op": "add", "value": [{ "value": id }] }] }).to_string()
    }

    fn sdnp_remplacement(id: &str) -> String {
        json!({ "Operations": [{ "op": "replace", "path": "members", "value": [{ "value": id }] }] }).to_string()
    }

    async fn sdnp_creer_le_tenant(st: &AppState, id: &str, admin: &str) {
        let (statut, v) = jsre_corps(
            tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("sdnp-op")), Json(json!({ "id": id, "name": id, "admin": admin })))
                .await,
        )
        .await;
        assert_eq!(statut, 201, "fixture : tenant {id} créé : {v}");
    }

    /// Le droit posé HORS SCIM, par la route de l'administrateur de la plateforme (`grant_set`, super-administrateur).
    async fn sdnp_grant_set(st: &AppState, tenant: &str, nom: &str, role: &str) {
        let (statut, v) = jsre_corps(
            grant_set(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("sdnp-op")), Path(tenant.into()), Json(json!({ "user": nom, "role": role })))
                .await,
        )
        .await;
        assert_eq!(statut, 200, "fixture : grant_set {nom} {role} dans {tenant} : {v}");
    }

    /// Deux tenants réels, A et B (un administrateur chacun, né par la création du tenant), un jeton SCIM chacun ; vieux,
    /// identité sans droit ni provenance. Le mode installation est fermé (il laisserait passer `/scim/v2/*`).
    async fn sdnp_deux_tenants() -> (AppState, crate::tmp_possede::TmpPossede) {
        let (st, dir) = mk_mode1_state();
        sdnp_creer_le_tenant(&st, SDNP_A, SDNP_ADMIN_A).await;
        sdnp_creer_le_tenant(&st, SDNP_B, SDNP_ADMIN_B).await;
        jsre_poser_le_jeton(&st, SDNP_JETON_A, SDNP_A);
        jsre_poser_le_jeton(&st, SDNP_JETON_B, SDNP_B);
        jsre_plan(&st)
            .conn
            .lock()
            .execute("INSERT INTO platform_user(id,name,hash,is_superadmin,created) VALUES(?1,?2,NULL,0,0)", params![SDNP_UID_VIEUX, SDNP_VIEUX])
            .expect("fixture : identité d'avant la provenance");
        st.installation_ouverte.store(false, std::sync::atomic::Ordering::SeqCst);
        (st, dir)
    }

    fn sdnp_provenance(st: &AppState, uid: &str) -> Option<String> {
        use rusqlite::OptionalExtension as _;
        jsre_plan(st).conn.lock().query_row("SELECT tenant_id FROM scim_provenance WHERE user_id=?1", params![uid], |r| r.get(0)).optional().expect("fixture : lisible")
    }

    fn sdnp_droits_partout(st: &AppState, uid: &str) -> i64 {
        jsre_plan(st).conn.lock().query_row("SELECT COUNT(*) FROM \"grant\" WHERE user_id=?1", params![uid], |r| r.get(0)).expect("fixture : lisible")
    }

    /// Les quatre gestes SCIM qui rattachent, joués par le routeur avec le jeton `jeton` sur l'identité `nom`/`uid`, que
    /// ce tenant ne doit PAS pouvoir rattacher : chacun refusé EN ENTIER (le `noTarget` égal à celui d'un id jamais
    /// servi), rien d'écrit, l'id jamais servi.
    async fn sdnp_tout_refuse(st: &AppState, adresse: std::net::SocketAddr, jeton: &str, quoi: &str, nom: &str, uid: &str) {
        let avant = jsre_instantane(st);
        let posts = [json!({ "userName": nom }).to_string(), json!({ "userName": nom, "groups": [{ "value": "viewer" }] }).to_string()];
        for corps in &posts {
            let (statut, rendu) = jsre_envoi(adresse, "POST", "/scim/v2/Users", jeton, corps).await;
            assert_eq!((statut, sdnp_json(&rendu)), (409, sdnp_unicite()), "{quoi} : POST /Users {corps} : le 409 EN ENTIER");
            assert!(!rendu.contains(uid), "{quoi} : l'id n'est jamais servi : {rendu}");
        }
        for (geste, corps, reference) in [
            ("add", sdnp_ajout(uid), sdnp_ajout(SDNP_INCONNU)),
            ("replace", sdnp_remplacement(uid), sdnp_remplacement(SDNP_INCONNU)),
        ] {
            let inconnu = jsre_envoi(adresse, "PATCH", "/scim/v2/Groups/viewer", jeton, &reference).await;
            assert_eq!((inconnu.0, sdnp_json(&inconnu.1)), (400, sdnp_sans_cible()), "{quoi} : référence {geste} d'un id jamais servi");
            let rendu = jsre_envoi(adresse, "PATCH", "/scim/v2/Groups/viewer", jeton, &corps).await;
            assert_eq!(rendu, inconnu, "{quoi} : PATCH {geste} : le noTarget d'un id jamais servi, statut et corps à l'octet");
        }
        assert_eq!(jsre_instantane(st), avant, "{quoi} : rien n'est écrit (ni identité, ni provenance, ni droit, ni ligne de contrôle)");
    }

    /// CE QU'IL TIENT : vieux (ni droit ni provenance) est étranger à A ET à B, par le routeur : `POST /Users` sans et avec
    /// `groups` = `409` en entier sans son id, `PATCH add` et `replace` = le `noTarget` d'un id jamais servi, rien d'écrit.
    /// Contrôle positif : le jeton de chaque tenant crée un nom neuf (`201`), provenance de ce tenant.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `BL2_RETRO` (`201` avec l'id de vieux) ; `BL2_POST_SANS_JUGEMENT` (`201` sans
    /// `groups`) ; `BL2_ADD_SANS_JUGEMENT` (`add` `200`) ; `BL2_REPLACE_SANS_JUGEMENT` (`replace` `200`).
    #[tokio::test]
    async fn sdnp_sans_droit_ni_provenance_refusee_par_chaque_tenant() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = sdnp_deux_tenants().await;
        let adresse = router_serve(st.clone()).await;
        for (tenant, jeton) in [(SDNP_A, SDNP_JETON_A), (SDNP_B, SDNP_JETON_B)] {
            sdnp_tout_refuse(&st, adresse, jeton, tenant, SDNP_VIEUX, SDNP_UID_VIEUX).await;
            assert_eq!((sdnp_droits_partout(&st, SDNP_UID_VIEUX), sdnp_provenance(&st, SDNP_UID_VIEUX)), (0, None), "{tenant} : vieux reste sans droit ni provenance");
            let neuf = format!("sdnp-neuf-de-{tenant}");
            let (statut, rendu) = jsre_envoi(adresse, "POST", "/scim/v2/Users", jeton, &json!({ "userName": neuf }).to_string()).await;
            assert_eq!(statut, 201, "{tenant} : contrôle positif, un nom neuf est créé : {rendu}");
            assert_eq!(sdnp_provenance(&st, &jsre_uid(&st, &neuf)).as_deref(), Some(tenant), "{tenant} : provenance du tenant appelant");
        }
        let provenances: Vec<String> = jsre_instantane(&st).into_iter().filter(|l| l.starts_with("scim_provenance|")).collect();
        assert_eq!(provenances.len(), 2, "les deux tenants ont été joués, un nom neuf chacun : {provenances:?}");
    }

    /// CE QU'IL TIENT (la sortie de la classe) : `grant_set` pose à vieux un droit `viewer` dans A (hors SCIM). Depuis A,
    /// par le routeur : `PATCH add` au groupe `editor` rend `200` (corps en entier) et son droit ici devient `editor` ;
    /// `POST /Users` de son nom avec `groups` rend `201` avec SON id. Depuis B : tout refusé, rien d'écrit. Avant le
    /// `grant_set`, A le refusait (même chaîne).
    /// LA MUTATION QUI LE FAIT ROUGIR : `BL2_ICI` (le droit ici ignoré : A refuse vieux).
    #[tokio::test]
    async fn sdnp_droit_pose_par_grant_set_rend_membre_de_ce_tenant_seulement() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = sdnp_deux_tenants().await;
        let adresse = router_serve(st.clone()).await;
        sdnp_tout_refuse(&st, adresse, SDNP_JETON_A, "A avant grant_set", SDNP_VIEUX, SDNP_UID_VIEUX).await;
        sdnp_grant_set(&st, SDNP_A, SDNP_VIEUX, "viewer").await;
        assert_eq!(jsre_uid(&st, SDNP_VIEUX), SDNP_UID_VIEUX, "fixture : grant_set a pris l'identité existante");

        sdnp_tout_refuse(&st, adresse, SDNP_JETON_B, "B après grant_set dans A", SDNP_VIEUX, SDNP_UID_VIEUX).await;
        let (statut, rendu) = jsre_envoi(adresse, "PATCH", "/scim/v2/Groups/editor", SDNP_JETON_A, &sdnp_ajout(SDNP_UID_VIEUX)).await;
        assert_eq!((statut, sdnp_json(&rendu)), (200, sdnp_groupe("editor")), "A : PATCH add de vieux");
        assert!(jsre_droits(&st, SDNP_A).contains(&format!("{SDNP_VIEUX}:editor")), "A : vieux est editor");
        let (statut, rendu) = jsre_envoi(adresse, "POST", "/scim/v2/Users", SDNP_JETON_A, &json!({ "userName": SDNP_VIEUX, "groups": [{ "value": "viewer" }] }).to_string()).await;
        assert_eq!(statut, 201, "A : POST /Users de vieux : {rendu}");
        assert_eq!(sdnp_json(&rendu)["id"].as_str(), Some(SDNP_UID_VIEUX), "A : SON id : {rendu}");
        assert!(!jsre_droits(&st, SDNP_B).iter().any(|d| d.starts_with(&format!("{SDNP_VIEUX}:"))), "B : aucun droit de vieux");
    }

    /// CE QU'IL TIENT : orph naît par `grant_set` dans A seulement (aucune provenance) ; A le rattache (`POST /Users` `201`
    /// avec son id). A est détruit, puis recréé sous le même identifiant avec un jeton neuf : orph n'a plus ni droit ni
    /// provenance, il est étranger à B ET au A recréé (`409`, `noTarget` sur `add` et `replace`, rien d'écrit).
    /// LA MUTATION QUI LE FAIT ROUGIR : `BL2_RETRO` (`201` avec l'id d'orph, au A recréé comme à B).
    #[tokio::test]
    async fn sdnp_destruction_d_un_tenant_rend_l_identite_etrangere_a_tous_recree_compris() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = sdnp_deux_tenants().await;
        let adresse = router_serve(st.clone()).await;
        sdnp_grant_set(&st, SDNP_A, "sdnp-orph", "viewer").await;
        let orph = jsre_uid(&st, "sdnp-orph");
        assert_eq!(sdnp_provenance(&st, &orph), None, "fixture : orph sans provenance");
        let (statut, rendu) = jsre_envoi(adresse, "POST", "/scim/v2/Users", SDNP_JETON_A, &json!({ "userName": "sdnp-orph" }).to_string()).await;
        assert_eq!((statut, sdnp_json(&rendu)["id"].as_str()), (201, Some(orph.as_str())), "contrôle : A rattache orph avant sa destruction : {rendu}");

        assert!(tenant_destroy(&st.tenants, SDNP_A).is_ok(), "fixture : A détruit");
        sdnp_creer_le_tenant(&st, SDNP_A, SDNP_ADMIN_A).await;
        jsre_poser_le_jeton(&st, SDNP_JETON_A_RECREE, SDNP_A);
        assert_eq!((sdnp_droits_partout(&st, &orph), sdnp_provenance(&st, &orph)), (0, None), "fixture : orph est sans droit ni provenance");
        for (jeton, quoi) in [(SDNP_JETON_A_RECREE, "A recréé"), (SDNP_JETON_B, "B")] {
            sdnp_tout_refuse(&st, adresse, jeton, quoi, "sdnp-orph", &orph).await;
        }
    }

    /// CE QU'IL TIENT (cas déjà tenus, inchangés) : mbre, membre de A ET de B (deux `grant_set`), est rattachable par les
    /// deux (`POST /Users` `201` avec son id) ; fred, créé par le `POST /Users` de A, l'est pour A (rejeu `201` avec son
    /// id, `PATCH add` `200`) et est étranger pour B ; l'administrateur de B (droit dans B seulement) est étranger pour A.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `BL2_ICI` (mbre refusé) ; `BL2_CREATEUR` (fred refusé par A).
    #[tokio::test]
    async fn sdnp_membre_provenance_et_etrangere_inchanges() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = sdnp_deux_tenants().await;
        let adresse = router_serve(st.clone()).await;
        sdnp_grant_set(&st, SDNP_A, "sdnp-mbre", "viewer").await;
        sdnp_grant_set(&st, SDNP_B, "sdnp-mbre", "viewer").await;
        let mbre = jsre_uid(&st, "sdnp-mbre");
        for jeton in [SDNP_JETON_A, SDNP_JETON_B] {
            let (statut, rendu) = jsre_envoi(adresse, "POST", "/scim/v2/Users", jeton, &json!({ "userName": "sdnp-mbre" }).to_string()).await;
            assert_eq!((statut, sdnp_json(&rendu)["id"].as_str()), (201, Some(mbre.as_str())), "{jeton} : mbre rattachable : {rendu}");
        }

        let (statut, rendu) = jsre_envoi(adresse, "POST", "/scim/v2/Users", SDNP_JETON_A, &json!({ "userName": "sdnp-fred" }).to_string()).await;
        assert_eq!(statut, 201, "fixture : fred créé par A : {rendu}");
        let fred = jsre_uid(&st, "sdnp-fred");
        let (statut, rendu) = jsre_envoi(adresse, "POST", "/scim/v2/Users", SDNP_JETON_A, &json!({ "userName": "sdnp-fred" }).to_string()).await;
        assert_eq!((statut, sdnp_json(&rendu)["id"].as_str()), (201, Some(fred.as_str())), "A : rejeu de fred, son id : {rendu}");
        let (statut, rendu) = jsre_envoi(adresse, "PATCH", "/scim/v2/Groups/viewer", SDNP_JETON_A, &sdnp_ajout(&fred)).await;
        assert_eq!((statut, sdnp_json(&rendu)), (200, sdnp_groupe("viewer")), "A : PATCH add de fred");
        sdnp_tout_refuse(&st, adresse, SDNP_JETON_B, "B sur fred", "sdnp-fred", &fred).await;
        let adm_b = jsre_uid(&st, SDNP_ADMIN_B);
        sdnp_tout_refuse(&st, adresse, SDNP_JETON_A, "A sur l'administrateur de B", SDNP_ADMIN_B, &adm_b).await;
    }

    /// CE QU'IL TIENT : mbre, membre de A par `grant_set` (sans provenance), est jugé rattachable par `POST /Users` de A ;
    /// au point de course (`scim-identite-avant-ses-droits`, verrou relâché, droits pas encore écrits), son droit dans A
    /// est retiré : le rejugement dans la transaction des droits le trouve sans droit ni provenance et rend le `409` EN
    /// ENTIER, sans droit écrit ni ligne de contrôle. Contrôle sur un état neuf, sans geste concurrent : `201`, son id,
    /// son droit `editor`.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `BL2_POST_SANS_REJUGEMENT` et `BL2_RETRO` (`201`, droit `editor` écrit).
    #[tokio::test]
    async fn sdnp_droit_retire_pendant_le_provisionnement_rend_409_sans_rien_ecrire() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let demande = json!({ "userName": "sdnp-mbre", "groups": [{ "value": "editor" }] });
        let (st, _dir) = sdnp_deux_tenants().await;
        sdnp_grant_set(&st, SDNP_A, "sdnp-mbre", "viewer").await;
        let mbre = jsre_uid(&st, "sdnp-mbre");
        let (plan, cible) = (jsre_plan(&st).clone(), mbre.clone());
        poser_un_crochet_de_course(&format!("scim-identite-avant-ses-droits:{}", jsre_plan(&st).db_path), move || {
            let n = plan.conn.lock().execute("DELETE FROM \"grant\" WHERE user_id=?1 AND tenant_id=?2", params![cible, SDNP_A]).expect("crochet : droit retiré");
            assert_eq!(n, 1, "crochet : un droit retiré");
        });
        let (statut, rendu) = jsre_corps(scim_user_create(State(st.clone()), Extension(ScimCtx { tenant: SDNP_A.into() }), Json(demande.clone())).await).await;
        let apres = jsre_instantane(&st);
        assert_eq!((statut, rendu.clone()), (409, sdnp_unicite()), "le 409 EN ENTIER");
        assert!(!rendu.to_string().contains(&mbre), "l'id n'est pas servi : {rendu}");
        assert_eq!(sdnp_droits_partout(&st, &mbre), 0, "aucun droit écrit");
        assert!(!apres.iter().any(|l| l.contains("|scim.user.provision|")), "rien n'est attesté : {apres:?}");

        let (st, _dir2) = sdnp_deux_tenants().await;
        sdnp_grant_set(&st, SDNP_A, "sdnp-mbre", "viewer").await;
        let mbre = jsre_uid(&st, "sdnp-mbre");
        let (statut, rendu) = jsre_corps(scim_user_create(State(st.clone()), Extension(ScimCtx { tenant: SDNP_A.into() }), Json(demande)).await).await;
        assert_eq!((statut, rendu["id"].as_str()), (201, Some(mbre.as_str())), "contrôle sans geste concurrent : {rendu}");
        assert!(jsre_droits(&st, SDNP_A).contains(&"sdnp-mbre:editor".to_string()), "contrôle : son droit editor");
    }
}
