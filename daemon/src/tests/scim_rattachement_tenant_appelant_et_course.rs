// =====================================================================================
// `P10.34-h` (correction) — CE QUE LES TÉMOINS `sret_` NE TENAIENT PAS.
//
// CE QUI ÉTAIT FAUX OU NON TÉMOIGNÉ (mesuré par un vérificateur indépendant sur 509eeb92) :
//  * l'écriture de l'identité refusée APRÈS celle de sa provenance : rendre ce refus sans effet laissait les témoins
//    verts, alors que `POST /Users` rendait alors `201` avec l'id d'une identité inexistante, écrivait un droit
//    fantôme et l'attestait au journal de contrôle ;
//  * une identité créée par le `POST /Users` du tenant appelant et à qui un droit a été posé depuis dans un AUTRE
//    tenant (hors SCIM, `grant_set`) était déclarée étrangère : `PATCH add` rendait `noTarget` et `POST /Users` `409`,
//    contre l'ATTENDU (« provisionnée par le tenant appelant ») ; le droit ailleurs était jugé avant la provenance ;
//  * `POST /Users` jugeait le rattachement sous un verrou puis écrivait les droits sous un autre, sans rejuger : un
//    `PATCH add` d'un autre tenant intercalé sur une identité sans droit ni provenance laissait des droits dans deux
//    tenants, ce qu'aucun ordre en série n'autorise.
//
// CE QUE CES TÉMOINS TIENNENT, en mode multi-tenant avec DEUX tenants réels (catalogués) :
//  * identité refusée après sa provenance : `500` EN ENTIER, avec et sans `groups`, aucune identité, aucun droit,
//    rien au journal, une ligne de provenance inerte sur un id jamais servi ;
//  * gina (provenance du tenant 1, droit posé dans le tenant 2) : rattachable par le tenant 1 (`PATCH add` `200`,
//    `POST /Users` `201` avec son id) ; bert (droit dans le tenant 2 seulement, sans provenance) reste étranger ;
//  * au point de course de `POST /Users` (`point_de_course`, entre le jugement et la transaction des droits) : un droit
//    posé ailleurs rend `409` sans rien écrire ici ; l'identité supprimée rend `500` sans droit fantôme ; la relecture
//    ratée rend le `503` nommé sans droit, et le rejeu aboutit.
//
// MUTANTS (VERIF_MUT sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : AV1C_identite_refusee_avalee,
// AV1C_ordre_ancien, AV1C_sans_rejugement, AV1C_rejugement_illisible_admis, AV1C_identite_disparue_admise ; et
// AV1C_demande_non_atomique pour `saon_un_inconnu_dans_une_demande_mixte_defait_la_demande_entiere`.
//
// CE QU'ILS NE TIENNENT PAS : une identité sans aucun droit ni provenance (née avant la provenance, ou déprovisionnée
// partout) reste rattachable par tout tenant SCIM (rétrocompat, `sret_compte_d_avant_la_provenance_admis`) ; sans
// `groups`, `POST /Users` n'écrit aucun droit et ne rejuge donc rien après son premier jugement. Le temps de réponse
// n'est pas mesuré.
// =====================================================================================
mod scim_rattachement_tenant_appelant_et_course {
    use super::*;
    use crate::handlers::transaction_validee::poser_un_crochet_de_course;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const SRTC_TENANT: &str = "srtc-t1";
    const SRTC_AUTRE_TENANT: &str = "srtc-t2";
    const SRTC_INCONNU: &str = "pu_srtc_qui_n_existe_pas";

    struct SrtcIds {
        bert_ailleurs: String,
        vieux_sans_provenance: String,
    }

    /// Le `409 uniqueness`, EN ENTIER, phrase recopiée (jamais lue de la production).
    fn srtc_unicite() -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "scimType": "uniqueness",
            "detail": "userName déjà pris sur la plateforme par une identité que ce tenant ne peut pas rattacher : l'utilisateur n'est ni créé ni modifié, aucun droit n'est posé",
            "status": "409",
        })
    }

    /// Le `500` d'une identité non créée, EN ENTIER.
    fn srtc_non_creee() -> Value {
        json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": "création platform_user échouée", "status": "500" })
    }

    /// Le `503` d'une lecture ratée de l'utilisateur, EN ENTIER, phrase recopiée.
    fn srtc_illisible() -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": "UTILISATEUR ILLISIBLE : la base du plan de contrôle n'a pas pu lire l'utilisateur visé — ni sa présence ni son absence n'est affirmée, et rien n'est modifié. La même demande peut être rejouée telle quelle.",
            "status": "503",
        })
    }

    fn srtc_groupe(role: &str) -> Value {
        json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "id": role, "displayName": role })
    }

    /// Deux tenants catalogués. anne admin ICI ; bert editor dans l'AUTRE tenant seulement ; vieux posé par
    /// `ensure_platform_user` (aucune provenance), sans droit.
    fn srtc_etat() -> (AppState, crate::tmp_possede::TmpDb, SrtcIds) {
        let (cp, tmp) = mk_test_control();
        for (id, nom) in [(SRTC_TENANT, "SRTC1"), (SRTC_AUTRE_TENANT, "SRTC2")] {
            cp.conn
                .lock()
                .execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,?2,'','sans-base',?3,0)", params![id, nom, now()])
                .expect("fixture : tenant catalogué");
        }
        let anne = ensure_platform_user(&cp, "srtc-anne").expect("fixture");
        let bert_ailleurs = ensure_platform_user(&cp, "srtc-bert").expect("fixture");
        let vieux_sans_provenance = ensure_platform_user(&cp, "srtc-vieux").expect("fixture");
        for (id, tenant, role) in [(&anne, SRTC_TENANT, "admin"), (&bert_ailleurs, SRTC_AUTRE_TENANT, "editor")] {
            cp.conn.lock().execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3)", params![id, tenant, role]).expect("fixture : droit");
        }
        let st = tenant_test_state("admins", "editors", "supers", Some(cp));
        (st, tmp, SrtcIds { bert_ailleurs, vieux_sans_provenance })
    }

    fn srtc_plan(st: &AppState) -> &ControlPlane {
        st.tenants.control.as_ref().expect("fixture : mode 1")
    }

    /// La clé du point de course de `POST /Users` pour la base de contrôle de CET état (deux témoins parallèles ont
    /// deux bases, donc deux clés).
    fn srtc_cle_de_course(st: &AppState) -> String {
        format!("scim-identite-avant-ses-droits:{}", srtc_plan(st).db_path)
    }

    async fn srtc_brut(r: Response) -> (StatusCode, String) {
        let statut = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, String::from_utf8(b.to_vec()).expect("corps UTF-8"))
    }

    async fn srtc_post(st: &AppState, tenant: &str, corps: Value) -> (StatusCode, String) {
        srtc_brut(scim_user_create(State(st.clone()), Extension(ScimCtx { tenant: tenant.into() }), Json(corps)).await).await
    }

    async fn srtc_patch(st: &AppState, tenant: &str, role: &str, corps: Value) -> (StatusCode, String) {
        srtc_brut(scim_group_patch(State(st.clone()), Extension(ScimCtx { tenant: tenant.into() }), Path(role.to_string()), Json(corps)).await).await
    }

    fn srtc_json(corps: &str) -> Value {
        serde_json::from_str(corps).unwrap_or_else(|e| panic!("corps JSON ({e}) : {corps}"))
    }

    fn srtc_ajout(id: &str) -> Value {
        json!({ "Operations": [{ "op": "add", "value": [{ "value": id }] }] })
    }

    fn srtc_lignes(st: &AppState, sql: &str) -> Vec<String> {
        let c = srtc_plan(st).conn.lock();
        let mut s = c.prepare(sql).expect("fixture");
        let lus = s.query_map([], |r| r.get::<_, String>(0)).expect("fixture").collect::<Result<Vec<_>, _>>().expect("fixture : lisible");
        lus
    }

    fn srtc_droits(st: &AppState) -> Vec<String> {
        srtc_lignes(st, "SELECT user_id || '|' || tenant_id || '|' || role FROM \"grant\" ORDER BY 1")
    }

    fn srtc_droits_de(st: &AppState, id: &str) -> Vec<(String, String)> {
        srtc_droits(st)
            .into_iter()
            .filter_map(|l| {
                let p: Vec<&str> = l.split('|').collect();
                (p[0] == id).then(|| (p[1].to_string(), p[2].to_string()))
            })
            .collect()
    }

    fn srtc_identites(st: &AppState) -> Vec<String> {
        srtc_lignes(st, "SELECT id || '|' || name FROM platform_user ORDER BY 1")
    }

    fn srtc_provenances(st: &AppState) -> Vec<String> {
        srtc_lignes(st, "SELECT user_id || '|' || tenant_id FROM scim_provenance ORDER BY 1")
    }

    fn srtc_maillons(st: &AppState) -> Vec<String> {
        srtc_lignes(st, "SELECT kind || '|' || detail FROM control_ledger WHERE kind IN ('scim.user.provision','scim.group.patch') ORDER BY 1")
    }

    fn srtc_lever(st: &AppState) {
        srtc_plan(st).conn.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// CE QU'IL TIENT : l'écriture de l'IDENTITÉ refusée (autorisateur sur `INSERT platform_user`), celle de sa
    /// provenance acceptée. `POST /Users` d'un nom neuf, SANS puis AVEC `groups` : le `500` EN ENTIER ; aucune identité
    /// créée, aucun droit écrit, rien au journal de contrôle ; une seule ligne de provenance de plus, celle du tenant
    /// appelant, sur un id que la plateforme ne porte pas et que la réponse ne sert pas (inerte).
    /// LA MUTATION QUI LE FAIT ROUGIR : `AV1C_identite_refusee_avalee` (le refus de l'`INSERT platform_user` rendu sans
    /// effet : `201` avec l'id d'une identité inexistante, le maillon écrit, et avec `groups` un droit fantôme).
    #[tokio::test]
    async fn srtc_identite_refusee_apres_sa_provenance_rend_500_sans_rien_d_utilisable() {
        let (st, _tmp, _ids) = srtc_etat();
        let cas = vec![
            ("sans groups", json!({ "userName": "srtc-refusee-a" })),
            ("avec groups", json!({ "userName": "srtc-refusee-b", "groups": [{ "value": "viewer" }] })),
        ];
        assert!(cas.len() >= 2, "plancher : deux demandes");
        for (quoi, corps) in cas {
            let (droits, identites, provenances, maillons) = (srtc_droits(&st), srtc_identites(&st), srtc_provenances(&st), srtc_maillons(&st));
            srtc_plan(&st).conn.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Insert { table_name: "platform_user" } => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            let (statut, rendu) = srtc_post(&st, SRTC_TENANT, corps).await;
            srtc_lever(&st);
            assert_eq!((statut, srtc_json(&rendu)), (StatusCode::INTERNAL_SERVER_ERROR, srtc_non_creee()), "{quoi} : le 500 EN ENTIER");
            assert_eq!(srtc_identites(&st), identites, "{quoi} : aucune identité créée");
            assert_eq!(srtc_droits(&st), droits, "{quoi} : aucun droit écrit");
            assert_eq!(srtc_maillons(&st), maillons, "{quoi} : rien n'est attesté");
            let neuves: Vec<String> = srtc_provenances(&st).into_iter().filter(|p| !provenances.contains(p)).collect();
            assert_eq!(neuves.len(), 1, "{quoi} : une seule ligne de provenance de plus : {neuves:?}");
            let (id, tenant) = neuves[0].split_once('|').expect("ligne de provenance");
            assert_eq!(tenant, SRTC_TENANT, "{quoi} : la provenance est le tenant appelant");
            assert!(!srtc_identites(&st).iter().any(|l| l.starts_with(&format!("{id}|"))), "{quoi} : id jamais porté par la plateforme");
            assert!(!rendu.contains(id), "{quoi} : id jamais servi : {rendu}");
        }
    }

    /// CE QU'IL TIENT : gina est créée par le `POST /Users` du tenant 1 (provenance du tenant 1), puis reçoit un droit
    /// dans le tenant 2 posé hors SCIM (la ligne que `grant_set` écrit). Depuis le tenant 1, elle reste rattachable :
    /// `PATCH add` rend `200` (corps EN ENTIER) et pose son droit ICI ; sur un état neuf, le rejeu de son `POST /Users`
    /// avec `groups` rend `201` avec SON id. Son droit dans le tenant 2 est intact. Contrôle : bert (droit dans le tenant
    /// 2 seulement, sans provenance) reste étranger au tenant 1 (`noTarget` d'un inconnu, `409`).
    /// LA MUTATION QUI LE FAIT ROUGIR : `AV1C_ordre_ancien` (le droit ailleurs jugé avant la provenance : `noTarget`
    /// et `409` pour gina).
    #[tokio::test]
    async fn srtc_identite_provisionnee_ici_reste_rattachable_avec_un_droit_ailleurs() {
        async fn gina(st: &AppState) -> String {
            let (statut, corps) = srtc_post(st, SRTC_TENANT, json!({ "userName": "srtc-gina" })).await;
            assert_eq!(statut, StatusCode::CREATED, "fixture : gina créée par le tenant 1 : {corps}");
            let id = srtc_json(&corps)["id"].as_str().expect("id servi").to_string();
            srtc_plan(st)
                .conn
                .lock()
                .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'viewer')", params![id, SRTC_AUTRE_TENANT])
                .expect("fixture : droit posé hors SCIM dans le tenant 2");
            assert_eq!(srtc_provenances(st), vec![format!("{id}|{SRTC_TENANT}")], "fixture : provenance du tenant 1");
            id
        }
        let (st, _tmp, ids) = srtc_etat();
        let id = gina(&st).await;
        let (statut, corps) = srtc_patch(&st, SRTC_TENANT, "editor", srtc_ajout(&id)).await;
        assert_eq!((statut, srtc_json(&corps)), (StatusCode::OK, srtc_groupe("editor")), "PATCH add de gina");
        assert_eq!(
            srtc_droits_de(&st, &id),
            vec![(SRTC_TENANT.to_string(), "editor".to_string()), (SRTC_AUTRE_TENANT.to_string(), "viewer".to_string())]
        );
        let inconnu = srtc_patch(&st, SRTC_TENANT, "editor", srtc_ajout(SRTC_INCONNU)).await;
        assert_eq!(inconnu.0, StatusCode::BAD_REQUEST, "contrôle : l'inconnu : {inconnu:?}");
        assert_eq!(srtc_patch(&st, SRTC_TENANT, "editor", srtc_ajout(&ids.bert_ailleurs)).await, inconnu, "contrôle : bert reste étranger");

        let (st, _tmp2, _ids) = srtc_etat();
        let id = gina(&st).await;
        let (statut, corps) = srtc_post(&st, SRTC_TENANT, json!({ "userName": "srtc-gina", "groups": [{ "value": "viewer" }] })).await;
        assert_eq!(statut, StatusCode::CREATED, "rejeu du POST de gina : {corps}");
        let v = srtc_json(&corps);
        assert_eq!((v["id"].as_str(), v["groups"].clone()), (Some(id.as_str()), json!([{ "value": "viewer", "type": "direct" }])), "{corps}");
        assert_eq!(
            srtc_droits_de(&st, &id),
            vec![(SRTC_TENANT.to_string(), "viewer".to_string()), (SRTC_AUTRE_TENANT.to_string(), "viewer".to_string())]
        );
        let (statut, corps) = srtc_post(&st, SRTC_TENANT, json!({ "userName": "srtc-bert", "groups": [{ "value": "viewer" }] })).await;
        assert_eq!((statut, srtc_json(&corps)), (StatusCode::CONFLICT, srtc_unicite()), "contrôle : bert");
    }

    /// CE QU'IL TIENT : au point de course de `POST /Users` (jugement fait, verrou relâché, droits pas encore écrits),
    /// un geste concurrent pose à vieux (sans droit ni provenance, donc jugé rattachable) un droit dans le tenant 2 —
    /// ce qu'un `PATCH add` du tenant 2 écrit. Le `POST /Users` du tenant 1 avec `groups` rend alors le `409` EN ENTIER,
    /// sans l'id de vieux : vieux n'a que son droit du tenant 2, rien au journal. Contrôle sur un état neuf, sans geste
    /// concurrent : `201`, son id, son droit ici.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AV1C_sans_rejugement` (`201`, droits dans les deux tenants).
    #[tokio::test]
    async fn srtc_droit_pose_ailleurs_pendant_le_provisionnement_rend_409_sans_rien_ecrire() {
        let (st, _tmp, ids) = srtc_etat();
        let (plan, vieux) = (srtc_plan(&st).clone(), ids.vieux_sans_provenance.clone());
        poser_un_crochet_de_course(&srtc_cle_de_course(&st), move || {
            plan.conn
                .lock()
                .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'editor')", params![vieux, SRTC_AUTRE_TENANT])
                .expect("crochet : droit posé par le tenant 2");
        });
        let maillons = srtc_maillons(&st);
        let (statut, corps) = srtc_post(&st, SRTC_TENANT, json!({ "userName": "srtc-vieux", "groups": [{ "value": "viewer" }] })).await;
        assert_eq!((statut, srtc_json(&corps)), (StatusCode::CONFLICT, srtc_unicite()), "le 409 EN ENTIER");
        assert!(!corps.contains(&ids.vieux_sans_provenance), "l'id n'est pas servi : {corps}");
        assert_eq!(srtc_droits_de(&st, &ids.vieux_sans_provenance), vec![(SRTC_AUTRE_TENANT.to_string(), "editor".to_string())], "rien ici");
        assert_eq!(srtc_maillons(&st), maillons, "rien n'est attesté");

        let (st, _tmp2, ids) = srtc_etat();
        let (statut, corps) = srtc_post(&st, SRTC_TENANT, json!({ "userName": "srtc-vieux", "groups": [{ "value": "viewer" }] })).await;
        assert_eq!(statut, StatusCode::CREATED, "contrôle sans geste concurrent : {corps}");
        assert_eq!(srtc_json(&corps)["id"].as_str(), Some(ids.vieux_sans_provenance.as_str()), "{corps}");
        assert_eq!(srtc_droits_de(&st, &ids.vieux_sans_provenance), vec![(SRTC_TENANT.to_string(), "viewer".to_string())]);
    }

    /// CE QU'IL TIENT : au point de course, l'identité servie est supprimée (geste d'un administrateur) : le `500` EN
    /// ENTIER, aucun droit fantôme écrit, rien au journal.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AV1C_identite_disparue_admise` (l'identité absente admise : droit fantôme).
    #[tokio::test]
    async fn srtc_identite_supprimee_pendant_le_provisionnement_rend_500_sans_droit_fantome() {
        let (st, _tmp, ids) = srtc_etat();
        let (plan, vieux) = (srtc_plan(&st).clone(), ids.vieux_sans_provenance.clone());
        poser_un_crochet_de_course(&srtc_cle_de_course(&st), move || {
            let n = plan.conn.lock().execute("DELETE FROM platform_user WHERE id=?1", params![vieux]).expect("crochet : identité supprimée");
            assert_eq!(n, 1, "crochet : une identité supprimée");
        });
        let (droits, maillons) = (srtc_droits(&st), srtc_maillons(&st));
        let (statut, corps) = srtc_post(&st, SRTC_TENANT, json!({ "userName": "srtc-vieux", "groups": [{ "value": "viewer" }] })).await;
        assert_eq!((statut, srtc_json(&corps)), (StatusCode::INTERNAL_SERVER_ERROR, srtc_non_creee()), "le 500 EN ENTIER");
        assert_eq!(srtc_droits(&st), droits, "aucun droit fantôme");
        assert_eq!(srtc_maillons(&st), maillons, "rien n'est attesté");
    }

    /// CE QU'IL TIENT : au point de course, la lecture de la provenance devient illisible (autorisateur) : le rejugement
    /// rend le `503` EN ENTIER, aucun droit écrit, rien au journal. La lecture revenue, le rejeu de la même demande rend
    /// `201` avec le même id et le droit ici.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AV1C_rejugement_illisible_admis` (la lecture ratée admise : `201`).
    #[tokio::test]
    async fn srtc_rejugement_illisible_rend_503_puis_le_rejeu_aboutit() {
        let (st, _tmp, _ids) = srtc_etat();
        let plan = srtc_plan(&st).clone();
        poser_un_crochet_de_course(&srtc_cle_de_course(&st), move || {
            plan.conn.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Read { table_name: "scim_provenance", .. } => Authorization::Deny,
                _ => Authorization::Allow,
            }));
        });
        let (droits, maillons) = (srtc_droits(&st), srtc_maillons(&st));
        let demande = json!({ "userName": "srtc-neuve", "groups": [{ "value": "viewer" }] });
        let (statut, corps) = srtc_post(&st, SRTC_TENANT, demande.clone()).await;
        srtc_lever(&st);
        assert_eq!((statut, srtc_json(&corps)), (StatusCode::SERVICE_UNAVAILABLE, srtc_illisible()), "le 503 EN ENTIER");
        assert_eq!(srtc_droits(&st), droits, "aucun droit écrit");
        assert_eq!(srtc_maillons(&st), maillons, "rien n'est attesté");
        let creee = srtc_identites(&st).into_iter().find(|l| l.ends_with("|srtc-neuve")).expect("l'identité reste créée, comme sous un droit refusé");
        let id = creee.split_once('|').expect("ligne").0.to_string();
        let (statut, corps) = srtc_post(&st, SRTC_TENANT, demande).await;
        assert_eq!(statut, StatusCode::CREATED, "rejeu : {corps}");
        assert_eq!(srtc_json(&corps)["id"].as_str(), Some(id.as_str()), "le même id");
        assert_eq!(srtc_droits_de(&st, &id), vec![(SRTC_TENANT.to_string(), "viewer".to_string())]);
    }
}
