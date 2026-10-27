// =====================================================================================
// `P10.34-h` — UN JETON SCIM D'UN TENANT NE RATTACHE JAMAIS UN COMPTE D'UN AUTRE TENANT (décision de l'exploitant,
// 2026-10-26 ; l'oracle par `userName` qui en découle est ACCEPTÉ).
//
// CE QUI ÉTAIT FAUX (mesuré sur 5100db29, témoins inversés dans `scim_ajout_de_groupe_sans_oracle_par_nom.rs`) :
// `PATCH /Groups` (ajout, ensemble servi d'un `replace`) jugeait l'identité sur `platform_user`, global : toute identité
// connue de la plateforme recevait un droit dans le tenant appelant ; `POST /Users` retrouvait par son nom (`UNIQUE` sur
// toute la plateforme, `ensure_platform_user`) le compte d'un autre tenant, servait son id et lui posait les `groups`
// demandés. Un compte sans aucun droit, créé par le SCIM d'un autre tenant, était rattachable par tous.
//
// CE QUE CES TÉMOINS TIENNENT, en mode multi-tenant avec DEUX tenants réels (catalogués) et des identités de chaque
// classe : bert (droit dans l'autre tenant seulement), eve (créée par le `POST /Users` de l'autre tenant, sans droit),
// fred (créé par le `POST /Users` du tenant appelant, sans droit), dora (droit ici ET ailleurs), vieux (né avant la
// provenance, sans droit nulle part) :
//  * `POST /Users` (avec et sans `groups`) d'un nom étranger : `409 uniqueness` EN ENTIER, sans l'id, rien d'écrit ;
//  * `PATCH add` et `replace` d'un id étranger : le `noTarget` d'un id inconnu, à l'octet, rien d'écrit ;
//  * fred, dora, vieux et un nom neuf : admis (`201`, `200`), droit posé ICI seulement ;
//  * chaque lecture rendue illisible SEULE (`platform_user`, `"grant"`, `scim_provenance`) : `503` nommé, rien d'écrit ;
//  * la provenance écrite AVANT l'identité, et ses deux lignes de journal neuves, capturées en sous-processus ;
//  * la table de provenance posée par `migrate_control`, idempotente.
//
// MUTANTS (VERIF_MUT sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : AV1_ici_ignore, AV1_ailleurs_ignore,
// AV1_provenance_ignoree, AV1_provenance_tous, AV1_sans_provenance_refuse, AV1_patch_ancien, AV1_post_ancien,
// AV1_post_sans_provenance, AV1_ordre, AV1_illisible_absent, AV1_journal_creation_muet, AV1_journal_migration_muet,
// AV1_genre_illisible, AV1_migration_absente.
//
// LIMITES ASSUMÉES : une identité née avant la provenance (ou par `grant_set` / création de tenant) et sans aucun droit
// reste rattachable par tout tenant (rétrocompat : rien ne dit à qui elle appartient) et n'est pas revendiquée par un
// `POST /Users` ; un `userName` pris hors du tenant se lit au `409` (oracle par nom accepté) ; une identité créée par un
// tenant puis sans droit le reste à lui seul, même si ce tenant disparaît. Le temps de réponse n'est pas mesuré.
// =====================================================================================
mod scim_rattachement_entre_tenants_refuse {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const SRET_TENANT: &str = "sret-t1";
    const SRET_AUTRE_TENANT: &str = "sret-t2";
    const SRET_INCONNU: &str = "pu_sret_qui_n_existe_pas";

    struct SretIds {
        anne: String,
        dora_deux_tenants: String,
        bert_ailleurs: String,
        eve_creee_ailleurs: String,
        fred_cree_ici: String,
        vieux_sans_provenance: String,
    }

    /// Le `409 uniqueness`, EN ENTIER, phrase recopiée (jamais lue de la production).
    fn sret_unicite() -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "scimType": "uniqueness",
            "detail": "userName déjà pris sur la plateforme par une identité que ce tenant ne peut pas rattacher : l'utilisateur n'est ni créé ni modifié, aucun droit n'est posé",
            "status": "409",
        })
    }

    /// Le `503` d'une lecture ratée de l'utilisateur, EN ENTIER, phrase recopiée.
    fn sret_illisible() -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": "UTILISATEUR ILLISIBLE : la base du plan de contrôle n'a pas pu lire l'utilisateur visé — ni sa présence ni son absence n'est affirmée, et rien n'est modifié. La même demande peut être rejouée telle quelle.",
            "status": "503",
        })
    }

    fn sret_groupe(role: &str) -> Value {
        json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "id": role, "displayName": role })
    }

    async fn sret_brut(r: Response) -> (StatusCode, String) {
        let statut = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, String::from_utf8(b.to_vec()).expect("corps UTF-8"))
    }

    async fn sret_post(st: &AppState, tenant: &str, corps: Value) -> (StatusCode, String) {
        sret_brut(scim_user_create(State(st.clone()), Extension(ScimCtx { tenant: tenant.into() }), Json(corps)).await).await
    }

    async fn sret_patch(st: &AppState, tenant: &str, role: &str, corps: Value) -> (StatusCode, String) {
        sret_brut(scim_group_patch(State(st.clone()), Extension(ScimCtx { tenant: tenant.into() }), Path(role.to_string()), Json(corps)).await).await
    }

    fn sret_id_servi(corps: &str) -> String {
        serde_json::from_str::<Value>(corps).expect("corps JSON")["id"].as_str().expect("id servi").to_string()
    }

    /// Deux tenants catalogués. anne admin ICI ; dora editor ICI et viewer ailleurs ; bert editor ailleurs seulement ;
    /// eve créée par le `POST /Users` de l'AUTRE tenant, sans groupe ; fred créé par le `POST /Users` de CE tenant, sans
    /// groupe ; vieux posé par `ensure_platform_user` (aucune provenance), sans droit.
    async fn sret_etat() -> (AppState, crate::tmp_possede::TmpDb, SretIds) {
        let (cp, tmp) = mk_test_control();
        for (id, nom) in [(SRET_TENANT, "SRET1"), (SRET_AUTRE_TENANT, "SRET2")] {
            cp.conn
                .lock()
                .execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,?2,'','sans-base',?3,0)", params![id, nom, now()])
                .expect("fixture : tenant catalogué");
        }
        let anne = ensure_platform_user(&cp, "sret-anne").expect("fixture");
        let dora_deux_tenants = ensure_platform_user(&cp, "sret-dora").expect("fixture");
        let bert_ailleurs = ensure_platform_user(&cp, "sret-bert").expect("fixture");
        let vieux_sans_provenance = ensure_platform_user(&cp, "sret-vieux").expect("fixture");
        for (id, tenant, role) in [
            (&anne, SRET_TENANT, "admin"),
            (&dora_deux_tenants, SRET_TENANT, "editor"),
            (&dora_deux_tenants, SRET_AUTRE_TENANT, "viewer"),
            (&bert_ailleurs, SRET_AUTRE_TENANT, "editor"),
        ] {
            cp.conn.lock().execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3)", params![id, tenant, role]).expect("fixture : droit");
        }
        let st = tenant_test_state("admins", "editors", "supers", Some(cp));
        let (statut, corps) = sret_post(&st, SRET_AUTRE_TENANT, json!({ "userName": "sret-eve" })).await;
        assert_eq!(statut, StatusCode::CREATED, "fixture : eve créée par l'autre tenant : {corps}");
        let eve_creee_ailleurs = sret_id_servi(&corps);
        let (statut, corps) = sret_post(&st, SRET_TENANT, json!({ "userName": "sret-fred" })).await;
        assert_eq!(statut, StatusCode::CREATED, "fixture : fred créé par ce tenant : {corps}");
        let fred_cree_ici = sret_id_servi(&corps);
        (st, tmp, SretIds { anne, dora_deux_tenants, bert_ailleurs, eve_creee_ailleurs, fred_cree_ici, vieux_sans_provenance })
    }

    fn sret_plan(st: &AppState) -> &ControlPlane {
        st.tenants.control.as_ref().expect("fixture : mode 1")
    }

    fn sret_droits(st: &AppState) -> Vec<(String, String, String)> {
        let c = sret_plan(st).conn.lock();
        let mut s = c.prepare("SELECT user_id, tenant_id, role FROM \"grant\" ORDER BY user_id, tenant_id, role").expect("fixture");
        let lus = s
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
            .expect("fixture")
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture : droits lisibles");
        lus
    }

    fn sret_droits_de(st: &AppState, id: &str) -> Vec<(String, String)> {
        sret_droits(st).into_iter().filter(|(u, _, _)| u == id).map(|(_, t, r)| (t, r)).collect()
    }

    fn sret_identites(st: &AppState) -> Vec<(String, String)> {
        let c = sret_plan(st).conn.lock();
        let mut s = c.prepare("SELECT id, name FROM platform_user ORDER BY id").expect("fixture");
        let lus = s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).expect("fixture").collect::<Result<Vec<_>, _>>().expect("fixture");
        lus
    }

    fn sret_provenance(st: &AppState, id: &str) -> Option<String> {
        use rusqlite::OptionalExtension as _;
        sret_plan(st)
            .conn
            .lock()
            .query_row("SELECT tenant_id FROM scim_provenance WHERE user_id=?1", params![id], |r| r.get(0))
            .optional()
            .expect("fixture : provenance lisible")
    }

    fn sret_maillons(st: &AppState) -> i64 {
        sret_plan(st)
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM control_ledger WHERE kind IN ('scim.user.provision','scim.group.patch')", [], |r| r.get(0))
            .expect("fixture")
    }

    fn sret_ajout(id: &str) -> Value {
        json!({ "Operations": [{ "op": "add", "value": [{ "value": id }] }] })
    }

    fn sret_remplacement(id: &str) -> Value {
        json!({ "Operations": [{ "op": "replace", "path": "members", "value": [{ "value": id }] }] })
    }

    /// CE QU'IL TIENT : depuis le tenant 1, `POST /Users` du nom de bert (droit ailleurs seulement) et du nom d'eve
    /// (créée par le SCIM de l'autre tenant, sans droit), AVEC et SANS `groups` : `409 uniqueness` EN ENTIER, à l'octet
    /// pour les quatre — la réponse ne dit ni pourquoi ni où ; jamais l'id du compte ; aucune identité créée, aucun droit
    /// écrit, rien au journal.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AV1_post_ancien` (`201`, id de bert servi et droit posé) ;
    /// `AV1_ailleurs_ignore` (bert `201`) ; `AV1_provenance_ignoree` et `AV1_post_sans_provenance` (eve `201`).
    #[tokio::test]
    async fn sret_post_d_un_nom_etranger_rend_409_avec_et_sans_groupes() {
        let (st, _tmp, ids) = sret_etat().await;
        let cas = vec![
            ("bert avec groups", ids.bert_ailleurs.clone(), json!({ "userName": "sret-bert", "groups": [{ "value": "viewer" }] })),
            ("bert sans groups", ids.bert_ailleurs.clone(), json!({ "userName": "sret-bert" })),
            ("eve avec groups", ids.eve_creee_ailleurs.clone(), json!({ "userName": "sret-eve", "groups": [{ "value": "viewer" }] })),
            ("eve sans groups", ids.eve_creee_ailleurs.clone(), json!({ "userName": "sret-eve" })),
        ];
        assert!(cas.len() >= 4, "plancher : quatre demandes");
        let (droits, identites, maillons) = (sret_droits(&st), sret_identites(&st), sret_maillons(&st));
        for (quoi, id, corps) in cas {
            let (statut, rendu) = sret_post(&st, SRET_TENANT, corps).await;
            assert_eq!(statut, StatusCode::CONFLICT, "{quoi} : {rendu}");
            assert_eq!(serde_json::from_str::<Value>(&rendu).expect("corps JSON"), sret_unicite(), "{quoi} : le 409 EN ENTIER");
            assert!(!rendu.contains(&id), "{quoi} : l'id du compte étranger n'est jamais servi : {rendu}");
            assert_eq!(sret_droits(&st), droits, "{quoi} : aucun droit écrit");
            assert_eq!(sret_identites(&st), identites, "{quoi} : aucune identité créée");
            assert_eq!(sret_maillons(&st), maillons, "{quoi} : rien n'est attesté");
        }
    }

    /// CE QU'IL TIENT : depuis le tenant 1, `PATCH add` et `replace path members` de l'id de bert et de l'id d'eve rendent
    /// le `400 noTarget` d'un id INCONNU, statut et corps à l'octet ; aucun droit écrit ni retiré (le `replace` refusé ne
    /// retire pas dora), rien au journal.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AV1_patch_ancien` (`200` pour les deux) ; `AV1_ailleurs_ignore` (bert) ;
    /// `AV1_provenance_ignoree`, `AV1_post_sans_provenance` (eve).
    #[tokio::test]
    async fn sret_patch_add_et_replace_d_un_compte_etranger_rendent_le_no_target_d_un_inconnu() {
        let (st, _tmp, ids) = sret_etat().await;
        let (droits, maillons) = (sret_droits(&st), sret_maillons(&st));
        let formes: Vec<(&str, fn(&str) -> Value)> = vec![("add", sret_ajout), ("replace", sret_remplacement)];
        assert!(formes.len() >= 2, "plancher : deux formes");
        let etrangers = vec![("bert", ids.bert_ailleurs.clone()), ("eve", ids.eve_creee_ailleurs.clone())];
        assert!(etrangers.len() >= 2, "plancher : deux comptes étrangers");
        for (forme, corps_de) in formes {
            let inconnu = sret_patch(&st, SRET_TENANT, "editor", corps_de(SRET_INCONNU)).await;
            assert_eq!(inconnu.0, StatusCode::BAD_REQUEST, "contrôle {forme} : l'inconnu : {inconnu:?}");
            for (qui, id) in &etrangers {
                let rendu = sret_patch(&st, SRET_TENANT, "editor", corps_de(id)).await;
                assert_eq!(rendu, inconnu, "{forme} {qui} : la réponse d'un inconnu, à l'octet");
                assert_eq!(sret_droits(&st), droits, "{forme} {qui} : rien n'est écrit ni retiré");
                assert_eq!(sret_maillons(&st), maillons, "{forme} {qui} : rien n'est attesté");
            }
        }
    }

    /// CE QU'IL TIENT : la chaîne d'un ATTAQUANT qui tient le jeton du tenant 1. Il essaie le nom de bert : `409`, pas
    /// d'id. Il crée un nom neuf : `201` et un id. Il rejoue l'ajout avec l'id de bert (lu ailleurs) puis avec un id
    /// jamais servi : même statut, même corps. Son nom neuf s'ajoute (`200`). À la fin, bert et eve n'ont aucun droit dans
    /// le tenant 1 ; seul le nom neuf en a un.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AV1_post_ancien`, `AV1_patch_ancien`.
    #[tokio::test]
    async fn sret_chaine_d_un_attaquant_ne_rattache_rien() {
        let (st, _tmp, ids) = sret_etat().await;
        let (statut, corps) = sret_post(&st, SRET_TENANT, json!({ "userName": "sret-bert", "groups": [{ "value": "editor" }] })).await;
        assert_eq!((statut, serde_json::from_str::<Value>(&corps).expect("JSON")), (StatusCode::CONFLICT, sret_unicite()), "{corps}");
        let (statut, corps) = sret_post(&st, SRET_TENANT, json!({ "userName": "sret-attaquant" })).await;
        assert_eq!(statut, StatusCode::CREATED, "{corps}");
        let a_lui = sret_id_servi(&corps);
        assert_eq!(sret_provenance(&st, &a_lui), Some(SRET_TENANT.to_string()), "la provenance du nom neuf est le tenant appelant");
        let par_l_id = sret_patch(&st, SRET_TENANT, "editor", sret_ajout(&ids.bert_ailleurs)).await;
        let jamais_servi = sret_patch(&st, SRET_TENANT, "editor", sret_ajout(SRET_INCONNU)).await;
        assert_eq!(par_l_id, jamais_servi, "id étranger et id jamais servi : même réponse");
        let (statut, corps) = sret_patch(&st, SRET_TENANT, "editor", sret_ajout(&a_lui)).await;
        assert_eq!((statut, serde_json::from_str::<Value>(&corps).expect("JSON")), (StatusCode::OK, sret_groupe("editor")), "{corps}");
        assert_eq!(sret_droits_de(&st, &ids.bert_ailleurs), vec![(SRET_AUTRE_TENANT.to_string(), "editor".to_string())], "bert : rien ici");
        assert!(sret_droits_de(&st, &ids.eve_creee_ailleurs).is_empty(), "eve : aucun droit");
        assert_eq!(sret_droits_de(&st, &a_lui), vec![(SRET_TENANT.to_string(), "editor".to_string())], "le nom neuf : son droit ici");
    }

    /// CE QU'IL TIENT : fred, créé par le `POST /Users` du tenant 1 SANS groupe, porte la provenance du tenant 1 ; il
    /// s'ajoute par `PATCH add` (`200`, droit ICI), par `replace` (sur un état neuf, `200`), et le rejeu de son `POST`
    /// avec `groups` le retrouve (`201`, même id, droit posé ICI). Depuis l'AUTRE tenant, fred (qui porte alors un droit
    /// ici) est étranger (`409`).
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AV1_provenance_tous` (toute provenance refusée : fred `noTarget`) ;
    /// `AV1_post_sans_provenance` (provenance absente) ; `AV1_post_ancien`. `AV1_provenance_ignoree` est rougi par les
    /// témoins d'eve (`sret_post_…`, `sret_patch_…`), pas par celui-ci.
    #[tokio::test]
    async fn sret_compte_neuf_du_tenant_appelant_admis() {
        let (st, _tmp, ids) = sret_etat().await;
        assert_eq!(sret_provenance(&st, &ids.fred_cree_ici), Some(SRET_TENANT.to_string()), "provenance écrite par le POST du tenant 1");
        assert_eq!(sret_provenance(&st, &ids.eve_creee_ailleurs), Some(SRET_AUTRE_TENANT.to_string()), "provenance écrite par le POST du tenant 2");
        let (statut, corps) = sret_patch(&st, SRET_TENANT, "editor", sret_ajout(&ids.fred_cree_ici)).await;
        assert_eq!((statut, serde_json::from_str::<Value>(&corps).expect("JSON")), (StatusCode::OK, sret_groupe("editor")), "add : {corps}");
        assert_eq!(sret_droits_de(&st, &ids.fred_cree_ici), vec![(SRET_TENANT.to_string(), "editor".to_string())]);

        let (st, _tmp2, ids) = sret_etat().await;
        let (statut, corps) = sret_patch(&st, SRET_TENANT, "viewer", sret_remplacement(&ids.fred_cree_ici)).await;
        assert_eq!((statut, serde_json::from_str::<Value>(&corps).expect("JSON")), (StatusCode::OK, sret_groupe("viewer")), "replace : {corps}");
        assert_eq!(sret_droits_de(&st, &ids.fred_cree_ici), vec![(SRET_TENANT.to_string(), "viewer".to_string())]);

        let (st, _tmp3, ids) = sret_etat().await;
        let (statut, corps) = sret_post(&st, SRET_TENANT, json!({ "userName": "sret-fred", "groups": [{ "value": "viewer" }] })).await;
        assert_eq!(statut, StatusCode::CREATED, "rejeu du POST : {corps}");
        let v: Value = serde_json::from_str(&corps).expect("JSON");
        assert_eq!((v["id"].as_str(), v["groups"].clone()), (Some(ids.fred_cree_ici.as_str()), json!([{ "value": "viewer", "type": "direct" }])), "{corps}");
        let (statut, corps) = sret_post(&st, SRET_AUTRE_TENANT, json!({ "userName": "sret-fred" })).await;
        assert_eq!((statut, serde_json::from_str::<Value>(&corps).expect("JSON")), (StatusCode::CONFLICT, sret_unicite()), "depuis l'autre tenant : {corps}");
    }

    /// CE QU'IL TIENT : dora porte un droit ICI et un dans l'autre tenant. Depuis le tenant 1, `POST /Users` de son nom
    /// avec `groups` rend `201` et SON id (rôle posé ici), `PATCH add` rend `200` ; depuis l'autre tenant aussi
    /// (`replace`, `200`). Ses droits dans les deux tenants restent les siens.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AV1_ici_ignore` (le droit ici n'est plus lu : dora, porteuse d'un droit
    /// ailleurs, devient étrangère — `409` et `noTarget`).
    #[tokio::test]
    async fn sret_compte_deja_membre_admis_meme_avec_un_droit_ailleurs() {
        let (st, _tmp, ids) = sret_etat().await;
        let (statut, corps) = sret_post(&st, SRET_TENANT, json!({ "userName": "sret-dora", "groups": [{ "value": "viewer" }] })).await;
        assert_eq!(statut, StatusCode::CREATED, "{corps}");
        assert_eq!(sret_id_servi(&corps), ids.dora_deux_tenants, "son id");
        let (statut, corps) = sret_patch(&st, SRET_TENANT, "editor", sret_ajout(&ids.dora_deux_tenants)).await;
        assert_eq!((statut, serde_json::from_str::<Value>(&corps).expect("JSON")), (StatusCode::OK, sret_groupe("editor")), "{corps}");
        let (statut, corps) = sret_patch(&st, SRET_AUTRE_TENANT, "viewer", sret_remplacement(&ids.dora_deux_tenants)).await;
        assert_eq!((statut, serde_json::from_str::<Value>(&corps).expect("JSON")), (StatusCode::OK, sret_groupe("viewer")), "{corps}");
        assert_eq!(
            sret_droits_de(&st, &ids.dora_deux_tenants),
            vec![(SRET_TENANT.to_string(), "editor".to_string()), (SRET_AUTRE_TENANT.to_string(), "viewer".to_string())]
        );
        assert_eq!(sret_droits_de(&st, &ids.anne), vec![(SRET_TENANT.to_string(), "admin".to_string())], "anne intacte");
    }

    /// CE QU'IL TIENT (rétrocompat, limite assumée) : vieux, né avant la provenance et sans droit nulle part, s'ajoute
    /// depuis le tenant 1 (`200`), et sur un état neuf le `POST /Users` de son nom depuis l'autre tenant le retrouve
    /// (`201`, son id) ; aucune provenance n'est revendiquée pour lui.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AV1_sans_provenance_refuse` (`noTarget`, `409`).
    #[tokio::test]
    async fn sret_compte_d_avant_la_provenance_admis() {
        let (st, _tmp, ids) = sret_etat().await;
        let (statut, corps) = sret_patch(&st, SRET_TENANT, "viewer", sret_ajout(&ids.vieux_sans_provenance)).await;
        assert_eq!((statut, serde_json::from_str::<Value>(&corps).expect("JSON")), (StatusCode::OK, sret_groupe("viewer")), "{corps}");
        assert_eq!(sret_droits_de(&st, &ids.vieux_sans_provenance), vec![(SRET_TENANT.to_string(), "viewer".to_string())]);
        let (st, _tmp2, ids) = sret_etat().await;
        let (statut, corps) = sret_post(&st, SRET_AUTRE_TENANT, json!({ "userName": "sret-vieux" })).await;
        assert_eq!(statut, StatusCode::CREATED, "{corps}");
        assert_eq!(sret_id_servi(&corps), ids.vieux_sans_provenance, "son id");
        assert_eq!(sret_provenance(&st, &ids.vieux_sans_provenance), None, "aucune provenance revendiquée");
    }

    fn sret_refuser_la_lecture(st: &AppState, table: &'static str) {
        sret_plan(st).conn.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == table => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn sret_lever(st: &AppState) {
        sret_plan(st).conn.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// CE QU'IL TIENT : chaque lecture du rattachement rendue illisible SEULE (`platform_user`, `"grant"`,
    /// `scim_provenance`) : `POST /Users` d'un nom étranger, `POST /Users` d'un nom neuf et `PATCH add` de fred rendent le
    /// `503` EN ENTIER — jamais un `201`, un `409` ni un `noTarget` ; aucune identité créée, aucun droit écrit. La lecture
    /// revenue, le nom neuf est créé (contrôle positif).
    /// LA MUTATION QUI LE FAIT ROUGIR : `AV1_illisible_absent` (la lecture ratée du nom prise pour une absence : le nom
    /// neuf est créé, `201`).
    #[tokio::test]
    async fn sret_chaque_lecture_ratee_du_rattachement_rend_503() {
        let (st, _tmp, ids) = sret_etat().await;
        let (droits, identites) = (sret_droits(&st), sret_identites(&st));
        let tables = vec!["platform_user", "grant", "scim_provenance"];
        assert!(tables.len() >= 3, "plancher : trois tables");
        for table in tables {
            let gestes = vec![("POST étranger", 0), ("POST neuf", 1), ("PATCH add", 2)];
            assert!(gestes.len() >= 3, "plancher : trois gestes");
            for (quoi, geste) in gestes {
                sret_refuser_la_lecture(&st, table);
                let (statut, corps) = match geste {
                    0 => sret_post(&st, SRET_TENANT, json!({ "userName": "sret-bert" })).await,
                    1 => sret_post(&st, SRET_TENANT, json!({ "userName": "sret-neuf" })).await,
                    _ => sret_patch(&st, SRET_TENANT, "viewer", sret_ajout(&ids.fred_cree_ici)).await,
                };
                sret_lever(&st);
                assert_eq!(statut, StatusCode::SERVICE_UNAVAILABLE, "{table} / {quoi} : {corps}");
                assert_eq!(serde_json::from_str::<Value>(&corps).expect("JSON"), sret_illisible(), "{table} / {quoi} : le 503 EN ENTIER");
                assert_eq!(sret_identites(&st), identites, "{table} / {quoi} : aucune identité créée");
                assert_eq!(sret_droits(&st), droits, "{table} / {quoi} : aucun droit écrit");
            }
        }
        let (statut, corps) = sret_post(&st, SRET_TENANT, json!({ "userName": "sret-neuf" })).await;
        assert_eq!(statut, StatusCode::CREATED, "contrôle positif : {corps}");
    }

    /// CE QU'IL TIENT : `migrate_control` pose `scim_provenance(user_id, tenant_id, created)` et se rejoue sans erreur.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AV1_migration_absente`.
    #[test]
    fn sret_migration_de_controle_pose_la_provenance_idempotente() {
        let conn = rusqlite::Connection::open_in_memory().expect("base en mémoire");
        migrate_control(&conn);
        migrate_control(&conn);
        let mut s = conn.prepare("SELECT name FROM pragma_table_info('scim_provenance') ORDER BY cid").expect("pragma");
        let colonnes = s.query_map([], |r| r.get::<_, String>(0)).expect("pragma").collect::<Result<Vec<_>, _>>().expect("pragma");
        assert_eq!(colonnes, vec!["user_id".to_string(), "tenant_id".to_string(), "created".to_string()]);
    }

    /// CE QU'IL TIENT, lu sur le stderr d'un sous-processus, lignes ENTIÈRES par égalité :
    ///  * l'écriture de la provenance refusée (autorisateur sur `INSERT scim_provenance`) : `POST /Users` d'un nom neuf
    ///    rend le `500` EN ENTIER, AUCUNE identité de ce nom n'existe (la provenance s'écrit AVANT l'identité), et la
    ///    ligne `[scim]` dit l'identité non créée avec la cause du moteur ;
    ///  * la lecture de la provenance refusée : la ligne `[scim]` du `503` nomme le geste `scim.user.provision` ;
    ///  * la table de provenance non créable (base en lecture seule) : la ligne `[rbac]` le dit.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AV1_ordre` (identité écrite avant sa provenance : elle existe, sans
    /// provenance) ; `AV1_journal_creation_muet` ; `AV1_genre_illisible` ; `AV1_journal_migration_muet`.
    #[tokio::test]
    async fn sret_provenance_refusee_rien_n_est_cree_et_les_lignes_le_disent() {
        const ENFANT: &str = "SRET_ENFANT_JOURNAL";
        const PHASE: &str = "SRET-PHASE:";
        const NOM: &str = "sret-sans-provenance";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT est lu dans l environnement, comme le choix du mutant
        if std::env::var(ENFANT).is_ok() {
            let (st, _tmp, _ids) = sret_etat().await;
            let refuser_l_ecriture = || {
                sret_plan(&st).conn.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Insert { table_name: "scim_provenance" } => Authorization::Deny,
                    _ => Authorization::Allow,
                }))
            };
            refuser_l_ecriture();
            let cause_ecriture = sret_plan(&st)
                .conn
                .lock()
                .execute("INSERT INTO scim_provenance(user_id,tenant_id,created) VALUES('x','y',0)", [])
                .expect_err("fixture : écriture de la provenance refusée")
                .to_string();
            eprintln!("{PHASE}creation");
            let (statut, corps) = sret_post(&st, SRET_TENANT, json!({ "userName": NOM })).await;
            sret_lever(&st);
            let du_nom: i64 = sret_plan(&st).conn.lock().query_row("SELECT COUNT(*) FROM platform_user WHERE name=?1", params![NOM], |r| r.get(0)).expect("lu");
            sret_refuser_la_lecture(&st, "scim_provenance");
            let cause_lecture = sret_plan(&st)
                .conn
                .lock()
                .query_row("SELECT tenant_id FROM scim_provenance", [], |r| r.get::<_, String>(0))
                .expect_err("fixture : lecture refusée")
                .to_string();
            eprintln!("{PHASE}illisible");
            let (statut_illisible, _) = sret_post(&st, SRET_TENANT, json!({ "userName": NOM })).await;
            sret_lever(&st);
            let lecture_seule = rusqlite::Connection::open_in_memory().expect("base en mémoire");
            lecture_seule.execute_batch("PRAGMA query_only=ON;").expect("lecture seule");
            let cause_migration = lecture_seule
                .execute_batch("CREATE TABLE IF NOT EXISTS scim_provenance(user_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, created INTEGER);")
                .expect_err("fixture : création refusée")
                .to_string();
            eprintln!("{PHASE}migration");
            migrate_control_provenance_scim(&lecture_seule);
            eprintln!("{PHASE}fin");
            println!(
                "SRET-SORTIE:{}",
                json!({ "statut": statut.as_u16(), "corps": corps, "du_nom": du_nom, "illisible": statut_illisible.as_u16(),
                        "cause_ecriture": cause_ecriture, "cause_lecture": cause_lecture, "cause_migration": cause_migration })
            );
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::scim_rattachement_entre_tenants_refuse::sret_provenance_refusee_rien_n_est_cree_et_les_lignes_le_disent"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let reste = stdout.split_once("SRET-SORTIE:").unwrap_or_else(|| panic!("contrôle : sortie : {stdout}")).1;
        let s: Value = serde_json::from_str(reste.lines().next().unwrap_or("")).unwrap_or_else(|e| panic!("contrôle : JSON ({e}) : {stdout}"));
        let phase = |nom: &str, prefixe: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with(prefixe)).map(str::to_string).collect()
        };
        let cause = |cle: &str| -> String {
            let c = s[cle].as_str().unwrap_or_else(|| panic!("contrôle : {cle} : {s}")).to_string();
            assert!(!c.is_empty(), "contrôle : {cle} lue");
            c
        };
        assert_eq!(s["statut"], json!(500), "{s}");
        assert_eq!(
            serde_json::from_str::<Value>(s["corps"].as_str().expect("corps")).expect("JSON"),
            json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": "création platform_user échouée", "status": "500" }),
            "le 500 EN ENTIER : {s}"
        );
        assert_eq!(s["du_nom"], json!(0), "aucune identité sans provenance : {s}");
        assert_eq!(
            phase("creation", "[scim]"),
            vec![format!("[scim] WARN geste 'scim.user.provision' : identité NON créée (500), rien n'est attesté : {}", cause("cause_ecriture"))],
            "la ligne ENTIÈRE : {stderr}"
        );
        assert_eq!(s["illisible"], json!(503), "{s}");
        assert_eq!(
            phase("illisible", "[scim]"),
            vec![format!("[scim] WARN geste 'scim.user.provision' refusé en 503, rien n'est attesté : {}", cause("cause_lecture"))],
            "la ligne ENTIÈRE : {stderr}"
        );
        assert_eq!(
            phase("migration", "[rbac]"),
            vec![format!("[rbac] WARN table de provenance SCIM non créée : les gestes SCIM qui la lisent refuseront : {}", cause("cause_migration"))],
            "la ligne ENTIÈRE : {stderr}"
        );
        assert!(!stderr.contains(NOM), "le nom de l'utilisateur n'apparaît dans aucune ligne : {stderr}");
    }
}
