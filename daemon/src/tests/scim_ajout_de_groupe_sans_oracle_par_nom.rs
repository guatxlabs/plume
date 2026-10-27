// =====================================================================================
// `P10.34-a` (reste : l'AJOUT) — UN AJOUT SCIM DE GROUPE NE DIT PAS SI UN `userName` PORTE UN DROIT DANS UN AUTRE
// TENANT. `P10.31-u` (reste, `tenants.rs`) — la ligne du droit non lu au retrait ne nomme plus le compte.
//
// CE QUI ÉTAIT FAUX DANS LA PREMIÈRE FORME DE CE LOT (139acc05, mesuré par un vérificateur indépendant). Elle
// refusait à l'ajout (`400 noTarget`) un id qui porte un droit dans un AUTRE tenant seulement, « comme un inconnu ».
// Or `POST /Users` est idempotent par nom (`ensure_platform_user`) et SERT l'id du compte existant : la chaîne
// `POST /Users {userName}` puis `PATCH add` rendait `400` pour un nom qui a un droit ailleurs et `200` pour un nom
// neuf — un oracle d'existence entre tenants NEUF, par `userName` (devinable, souvent une adresse mail), là où
// 8639270b n'opposait que des ids opaques. Elle cassait aussi le flux standard (`groups` est en lecture seule,
// RFC 7643 §4.1.2 : `POST /Users` puis `PATCH /Groups`) pour toute identité partagée entre deux tenants.
//
// LA FORME DE LA VAGUE AJ (décision de l'orchestrateur, RENVERSÉE depuis par `P10.34-h`, voir plus bas). L'ajout
// restait jugé sur `platform_user` : toute identité connue de la plateforme s'ajoutait, et la chaîne rendait la même
// réponse pour un nom partagé et pour un nom neuf — au prix d'un rattachement entre tenants. Ce qui en reste tenu ici :
// une inconnue rend `noTarget`, une ligne `"grant"` sans identité ne vaut jamais membre, une lecture ratée rend le
// `503` `CAUSE_SCIM_UTILISATEUR_ILLISIBLE`. `grant_delete` : phrase FIXE `droit d'un compte (identifiant non lu)` (le
// compte n'est pas relu), sans le tenant ; statut et corps inchangés.
//
// MUTANTS DE LA VAGUE AJ (posés le temps de la preuve, retirés avant le commit), chacun vu ROUGE alors :
// `AJ2C_refus_ailleurs` (le jugement de 139acc05 : un droit ailleurs seulement refusé — c'est désormais la forme
// voulue), `AJ2C_tout_admis` (un inconnu admis : droit fantôme),
// `AJ2C_fantome_admis` (une ligne `"grant"` sans identité vaut membre), `AJ2C_lecture_absente` (une lecture ratée
// servie comme une absence), `AJ2C_T807_nom` (la ligne d'avant, qui nomme le compte et le tenant).
//
// `P10.34-h` — LA DÉCISION EST RENVERSÉE (décision de l'exploitant, 2026-10-26) : un jeton SCIM d'un tenant ne
// rattache JAMAIS un compte d'un autre tenant, et l'oracle par `userName` qui en découle est ACCEPTÉ. TROIS TÉMOINS
// DE CE FICHIER AFFIRMAIENT L'ANCIEN COMPORTEMENT ET SONT INVERSÉS NOMMÉMENT, UN QUATRIÈME EST AJUSTÉ :
//  * `saon_chaine_post_puis_patch_meme_reponse_nom_partage_et_nom_neuf` (la chaîne rendait la même réponse à l'octet
//    et rattachait bert) devient `saon_chaine_post_puis_patch_nom_pris_ailleurs_rend_409_et_no_target` : `POST /Users`
//    du nom de bert rend `409 uniqueness` sans son id, le `PATCH add` de son id rend le `noTarget` d'un inconnu, bert
//    n'a rien ici ; le nom neuf garde `201` puis `200` ;
//  * `saon_un_id_d_un_autre_tenant_s_ajoute_un_inconnu_rend_no_target` devient
//    `saon_un_id_d_un_autre_tenant_rend_le_no_target_d_un_inconnu_sous_les_cinq_formes` ;
//  * `saon_la_reponse_ne_depend_pas_du_tenant_ou_le_compte_a_un_droit` devient
//    `saon_depuis_un_autre_tenant_l_id_repond_comme_un_inconnu` ;
//  * `saon_un_inconnu_dans_une_demande_mixte_defait_la_demande_entiere` : bert y étant désormais refusé dès
//    l'opération n°1, l'inconnu n'aurait plus été atteint ; l'opération n°1 ajoute donc carl (membre du tenant, qui
//    change de rôle : une écriture réelle), et le refus de l'inconnu, n°2, doit la défaire. La phrase du `noTarget`
//    dit « connue de ce tenant » (elle couvre l'inconnu ET l'étranger). Les autres branches (provenance, `POST` sans groupe, lectures ratées, journal) :
//    `scim_rattachement_entre_tenants_refuse.rs`. Un id jamais servi et un id étranger répondent pareil ; le temps
//    de réponse n'est pas mesuré.
// =====================================================================================
mod scim_ajout_de_groupe_sans_oracle_par_nom {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const SAON_TENANT: &str = "saon-t1";
    const SAON_AUTRE_TENANT: &str = "saon-t2";
    const SAON_INCONNU: &str = "pu_saon_qui_n_existe_pas";
    const SAON_FANTOME: &str = "pu_saon_fantome";

    struct SaonIds {
        anne: String,
        carl: String,
        dora_deux_tenants: String,
        bert_ailleurs: String,
    }

    /// Deux tenants catalogués. anne admin et carl editor ICI ; dora editor ICI et viewer dans l'AUTRE tenant ; bert
    /// editor dans l'AUTRE tenant seulement.
    fn saon_etat() -> (AppState, crate::tmp_possede::TmpDb, SaonIds) {
        let (cp, tmp) = mk_test_control();
        for (id, nom) in [(SAON_TENANT, "SAON1"), (SAON_AUTRE_TENANT, "SAON2")] {
            cp.conn
                .lock()
                .execute(
                    "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,?2,'','sans-base',?3,0)",
                    params![id, nom, now()],
                )
                .expect("fixture : tenant catalogué");
        }
        let anne = ensure_platform_user(&cp, "saon-anne").expect("fixture : utilisateur créé");
        let carl = ensure_platform_user(&cp, "saon-carl").expect("fixture : utilisateur créé");
        let dora_deux_tenants = ensure_platform_user(&cp, "saon-dora").expect("fixture : utilisateur créé");
        let bert_ailleurs = ensure_platform_user(&cp, "saon-bert").expect("fixture : utilisateur créé");
        for (id, tenant, role) in [
            (&anne, SAON_TENANT, "admin"),
            (&carl, SAON_TENANT, "editor"),
            (&dora_deux_tenants, SAON_TENANT, "editor"),
            (&dora_deux_tenants, SAON_AUTRE_TENANT, "viewer"),
            (&bert_ailleurs, SAON_AUTRE_TENANT, "editor"),
        ] {
            cp.conn
                .lock()
                .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3)", params![id, tenant, role])
                .expect("fixture : droit posé");
        }
        (tenant_test_state("admins", "editors", "supers", Some(cp)), tmp, SaonIds { anne, carl, dora_deux_tenants, bert_ailleurs })
    }

    fn saon_plan(st: &AppState) -> &ControlPlane {
        st.tenants.control.as_ref().expect("fixture : mode 1")
    }

    /// TOUS les droits de la plateforme, bruts (sans jointure) : `(user_id, tenant, rôle)`.
    fn saon_droits(st: &AppState) -> Vec<(String, String, String)> {
        let c = saon_plan(st).conn.lock();
        let mut s = c.prepare("SELECT user_id, tenant_id, role FROM \"grant\" ORDER BY user_id, tenant_id, role").expect("fixture : droits");
        let lus = s
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
            .expect("fixture : droits")
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture : droits lisibles");
        lus
    }

    fn saon_droits_de(st: &AppState, id: &str) -> Vec<(String, String)> {
        saon_droits(st).into_iter().filter(|(u, _, _)| u == id).map(|(_, t, r)| (t, r)).collect()
    }

    fn saon_maillons(st: &AppState) -> Vec<String> {
        let c = saon_plan(st).conn.lock();
        let mut s = c.prepare("SELECT detail FROM control_ledger WHERE kind='scim.group.patch' ORDER BY id").expect("fixture : journal");
        let lus = s.query_map([], |r| r.get::<_, String>(0)).expect("fixture : journal").collect::<Result<Vec<_>, _>>().expect("fixture : journal lisible");
        lus
    }

    async fn saon_brut(r: Response) -> (StatusCode, String) {
        let statut = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, String::from_utf8(b.to_vec()).expect("corps UTF-8"))
    }

    /// PATCH du groupe `role` depuis `tenant` : statut et corps BRUT (octets), pour comparer à l'octet.
    async fn saon_patch_depuis(st: &AppState, tenant: &str, role: &str, corps: Value) -> (StatusCode, String) {
        let ctx = ScimCtx { tenant: tenant.into() };
        saon_brut(scim_group_patch(State(st.clone()), Extension(ctx), Path(role.to_string()), Json(corps)).await).await
    }

    async fn saon_patch(st: &AppState, role: &str, corps: Value) -> (StatusCode, String) {
        saon_patch_depuis(st, SAON_TENANT, role, corps).await
    }

    fn saon_ajout(id: &str) -> Value {
        json!({ "Operations": [{ "op": "add", "value": [{ "value": id }] }] })
    }

    /// Le `400 noTarget` d'un membre inconnu, EN ENTIER (opération n°1).
    fn saon_no_target() -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "scimType": "noTarget",
            "detail": "opération n°1 : un membre visé n'est pas une identité connue de ce tenant ; la demande est atomique, aucune de ses opérations n'est appliquée",
            "status": "400",
        })
    }

    /// Le corps du `200` d'un PATCH du groupe `role`, EN ENTIER.
    fn saon_groupe(role: &str) -> Value {
        json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "id": role, "displayName": role })
    }

    /// Les cinq formes qui AJOUTENT `id` (l'ensemble servi d'un `replace` s'ajoute).
    fn saon_formes_de_l_ajout(id: &str) -> Vec<(&'static str, Value)> {
        vec![
            ("add value liste", json!({ "op": "add", "value": [{ "value": id }] })),
            ("add path members", json!({ "op": "add", "path": "members", "value": [{ "value": id }] })),
            ("add par filtre", json!({ "op": "add", "path": format!("members[value eq \"{id}\"]") })),
            ("add value objet members", json!({ "op": "add", "value": { "members": [{ "value": id }] } })),
            ("replace path members", json!({ "op": "replace", "path": "members", "value": [{ "value": id }] })),
        ]
    }

    /// Le `409 uniqueness` d'un nom pris hors du tenant, EN ENTIER (phrase recopiée, jamais lue de la production).
    fn saon_unicite() -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "scimType": "uniqueness",
            "detail": "userName déjà pris sur la plateforme par une identité que ce tenant ne peut pas rattacher : l'utilisateur n'est ni créé ni modifié, aucun droit n'est posé",
            "status": "409",
        })
    }

    /// `P10.34-h` — INVERSE NOMMÉ de `saon_chaine_post_puis_patch_meme_reponse_nom_partage_et_nom_neuf` (décision de
    /// l'exploitant, 2026-10-26). CE QU'IL TIENT : depuis le tenant 1, la chaîne `POST /Users {userName}` puis `PATCH
    /// add` joue comme un attaquant. `saon-bert` (droit dans l'autre tenant seulement) : `POST` rend le `409
    /// uniqueness` EN ENTIER, sans l'id de bert ; le `PATCH add` de l'id de bert (lu hors de l'API du tenant 1) rend le
    /// `noTarget` d'un id inconnu, statut et corps à l'octet ; bert n'a aucun droit ici, son droit ailleurs intact ;
    /// aucune identité créée. Le nom neuf : `201` puis `200`, corps du groupe EN ENTIER.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AV1_post_ancien` (`ensure_platform_user` : `201` avec l'id de bert) ;
    /// `AV1_patch_ancien` (jugement sur `platform_user` : `200`, bert rattaché) ; `AV1_ailleurs_ignore`.
    #[tokio::test]
    async fn saon_chaine_post_puis_patch_nom_pris_ailleurs_rend_409_et_no_target() {
        let (st, _tmp, ids) = saon_etat();
        let identites_avant: i64 = saon_plan(&st).conn.lock().query_row("SELECT COUNT(*) FROM platform_user", [], |r| r.get(0)).expect("fixture");
        let ctx = || ScimCtx { tenant: SAON_TENANT.into() };
        let (statut, corps) = saon_brut(scim_user_create(State(st.clone()), Extension(ctx()), Json(json!({ "userName": "saon-bert" }))).await).await;
        assert_eq!(statut, StatusCode::CONFLICT, "POST d'un nom pris ailleurs : {corps}");
        assert_eq!(serde_json::from_str::<Value>(&corps).expect("corps JSON"), saon_unicite(), "le 409 EN ENTIER");
        assert!(!corps.contains(&ids.bert_ailleurs), "l'id du compte étranger n'est jamais servi : {corps}");
        let par_l_id = saon_patch(&st, "editor", saon_ajout(&ids.bert_ailleurs)).await;
        let inconnu = saon_patch(&st, "editor", saon_ajout(SAON_INCONNU)).await;
        assert_eq!(par_l_id.0, StatusCode::BAD_REQUEST, "{par_l_id:?}");
        assert_eq!(par_l_id, inconnu, "l'id étranger répond comme un id jamais servi, à l'octet");
        assert_eq!(saon_droits_de(&st, &ids.bert_ailleurs), vec![(SAON_AUTRE_TENANT.to_string(), "editor".to_string())], "bert n'a rien ici");
        let identites: i64 = saon_plan(&st).conn.lock().query_row("SELECT COUNT(*) FROM platform_user", [], |r| r.get(0)).expect("fixture");
        assert_eq!(identites, identites_avant, "aucune identité créée par le refus");
        let (statut, corps) = saon_brut(scim_user_create(State(st.clone()), Extension(ctx()), Json(json!({ "userName": "saon-neuve" }))).await).await;
        assert_eq!(statut, StatusCode::CREATED, "contrôle : le POST du nom neuf : {corps}");
        let neuve = serde_json::from_str::<Value>(&corps).expect("corps JSON")["id"].as_str().expect("id servi").to_string();
        let (statut, corps) = saon_patch(&st, "editor", saon_ajout(&neuve)).await;
        assert_eq!(statut, StatusCode::OK, "contrôle : le nom neuf s'ajoute : {corps}");
        assert_eq!(serde_json::from_str::<Value>(&corps).expect("corps JSON"), saon_groupe("editor"), "le 200 EN ENTIER");
    }

    /// `P10.34-h` — INVERSE NOMMÉ de `saon_un_id_d_un_autre_tenant_s_ajoute_un_inconnu_rend_no_target`. CE QU'IL
    /// TIENT : sous chacune des cinq formes d'ajout (l'ensemble servi d'un `replace` compris), sur un état neuf, l'id qui
    /// porte un droit dans l'AUTRE tenant seulement rend le `400 noTarget` EN ENTIER, identique à l'octet à celui d'un
    /// id INCONNU ; aucun droit écrit ni retiré nulle part, rien au journal.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AV1_patch_ancien`, `AV1_ailleurs_ignore` (bert `200`).
    #[tokio::test]
    async fn saon_un_id_d_un_autre_tenant_rend_le_no_target_d_un_inconnu_sous_les_cinq_formes() {
        let formes = saon_formes_de_l_ajout(SAON_INCONNU).into_iter().zip(saon_formes_de_l_ajout("<bert>")).collect::<Vec<_>>();
        assert!(formes.len() >= 5, "plancher : les cinq formes d'ajout sont jouées");
        for ((quoi, inconnu), (_, gabarit)) in formes {
            let (st, _tmp, ids) = saon_etat();
            let avant = saon_droits(&st);
            let (statut, corps) = saon_patch(&st, "editor", json!({ "Operations": [inconnu] })).await;
            assert_eq!(statut, StatusCode::BAD_REQUEST, "{quoi} : un inconnu : {corps}");
            assert_eq!(serde_json::from_str::<Value>(&corps).expect("corps JSON"), saon_no_target(), "{quoi} : le noTarget EN ENTIER");
            let ailleurs: Value = serde_json::from_str(&gabarit.to_string().replace("<bert>", &ids.bert_ailleurs)).expect("forme");
            let etranger = saon_patch(&st, "editor", json!({ "Operations": [ailleurs] })).await;
            assert_eq!(etranger, (statut, corps), "{quoi} : l'id d'un autre tenant rend le noTarget de l'inconnu, à l'octet");
            assert_eq!(saon_droits(&st), avant, "{quoi} : rien n'est écrit ni retiré");
            assert!(saon_maillons(&st).is_empty(), "{quoi} : rien n'est attesté");
        }
    }

    /// CE QU'IL TIENT : une demande qui AJOUTE carl (membre du tenant, `editor`) au rôle `viewer` puis un INCONNU est
    /// refusée ENTIÈRE : l'opération n°1 est rattachable et ÉCRIT (carl change de rôle), le refus tombe sur la n°2,
    /// `noTarget` EN ENTIER, et l'écriture de la n°1 est défaite — carl reste `editor`, rien au journal.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AV1C_demande_non_atomique` (chaque opération validée à part : carl reste
    /// `viewer` sous le refus). La forme précédente (bert en n°1, refusé d'emblée) restait verte sous cette mutation.
    #[tokio::test]
    async fn saon_un_inconnu_dans_une_demande_mixte_defait_la_demande_entiere() {
        let (st, _tmp, ids) = saon_etat();
        let avant = saon_droits(&st);
        assert!(avant.contains(&(ids.carl.clone(), SAON_TENANT.to_string(), "editor".to_string())), "fixture : carl editor ici");
        let corps = json!({ "Operations": [
            { "op": "add", "value": [{ "value": ids.carl }] },
            { "op": "add", "value": [{ "value": SAON_INCONNU }] },
        ] });
        let (statut, v) = saon_patch(&st, "viewer", corps).await;
        assert_eq!(statut, StatusCode::BAD_REQUEST, "{v}");
        let mut attendu = saon_no_target();
        attendu["detail"] = json!(
            "opération n°2 : un membre visé n'est pas une identité connue de ce tenant ; la demande est atomique, aucune de ses opérations n'est appliquée"
        );
        assert_eq!(serde_json::from_str::<Value>(&v).expect("corps JSON"), attendu, "le refus EN ENTIER, sur l'opération n°2");
        assert_eq!(saon_droits(&st), avant, "l'écriture de l'opération n°1 est défaite : carl reste editor");
        assert!(saon_maillons(&st).is_empty(), "rien n'est attesté");
    }

    /// CE QU'IL TIENT (le flux de `P10.21-v`) : `POST /Users` SANS groupe crée une identité sans aucun droit ; un
    /// `PATCH add` du même tenant la rend membre (`200`, `+1`, droit relu dans la base brute), le corps EN ENTIER.
    /// Aucun mutant `AJ2C_` ne le vise : il garde ce flux contre tout jugement qui refuserait une identité sans droit
    /// (le mutant `AJ2_orpheline_hors` de 139acc05 le rougissait).
    #[tokio::test]
    async fn saon_une_identite_posee_sans_groupe_s_ajoute_ensuite() {
        let (st, _tmp, ids) = saon_etat();
        let ctx = ScimCtx { tenant: SAON_TENANT.into() };
        let (statut, v) = tok_resp_json(scim_user_create(State(st.clone()), Extension(ctx), Json(json!({ "userName": "saon-neuve" }))).await).await;
        assert_eq!(statut, StatusCode::CREATED, "fixture : identité créée sans groupe : {v}");
        let neuve = v["id"].as_str().expect("fixture : id servi").to_string();
        let (statut, corps) = saon_patch(&st, "viewer", saon_ajout(&neuve)).await;
        assert_eq!(statut, StatusCode::OK, "l'identité sans droit s'ajoute : {corps}");
        assert_eq!(serde_json::from_str::<Value>(&corps).expect("corps JSON"), saon_groupe("viewer"));
        let mut attendus = vec![
            (ids.anne.clone(), SAON_TENANT.to_string(), "admin".to_string()),
            (ids.carl.clone(), SAON_TENANT.to_string(), "editor".to_string()),
            (ids.dora_deux_tenants.clone(), SAON_TENANT.to_string(), "editor".to_string()),
            (ids.dora_deux_tenants.clone(), SAON_AUTRE_TENANT.to_string(), "viewer".to_string()),
            (ids.bert_ailleurs.clone(), SAON_AUTRE_TENANT.to_string(), "editor".to_string()),
            (neuve.clone(), SAON_TENANT.to_string(), "viewer".to_string()),
        ];
        attendus.sort();
        assert_eq!(saon_droits(&st), attendus, "le droit est posé ICI, et seulement lui");
        assert_eq!(saon_maillons(&st), vec!["role 'viewer' +1/-0 membres".to_string()], "l'ajout écrit est compté");
    }

    /// CE QU'IL TIENT : un membre du tenant change de rôle par l'ajout, qu'il porte ou non un droit AILLEURS aussi —
    /// carl (ici seulement) et dora (ici ET dans l'autre tenant) passent `viewer` ici, `200`, `+2` ; le droit de dora
    /// dans l'autre tenant est intact.
    #[tokio::test]
    async fn saon_un_membre_du_tenant_change_de_role_par_l_ajout() {
        let (st, _tmp, ids) = saon_etat();
        let (statut, corps) =
            saon_patch(&st, "viewer", json!({ "Operations": [{ "op": "add", "value": [{ "value": ids.carl }, { "value": ids.dora_deux_tenants }] }] })).await;
        assert_eq!(statut, StatusCode::OK, "{corps}");
        let mut attendus = vec![
            (ids.anne.clone(), SAON_TENANT.to_string(), "admin".to_string()),
            (ids.carl.clone(), SAON_TENANT.to_string(), "viewer".to_string()),
            (ids.dora_deux_tenants.clone(), SAON_TENANT.to_string(), "viewer".to_string()),
            (ids.dora_deux_tenants.clone(), SAON_AUTRE_TENANT.to_string(), "viewer".to_string()),
            (ids.bert_ailleurs.clone(), SAON_AUTRE_TENANT.to_string(), "editor".to_string()),
        ];
        attendus.sort();
        assert_eq!(saon_droits(&st), attendus, "carl et dora passent viewer ICI, le reste intact");
        assert_eq!(saon_maillons(&st), vec!["role 'viewer' +2/-0 membres".to_string()]);
    }

    /// `P10.34-h` — INVERSE NOMMÉ de `saon_la_reponse_ne_depend_pas_du_tenant_ou_le_compte_a_un_droit`, avec les DEUX
    /// tenants réels. CE QU'IL TIENT : depuis son tenant, l'ajout de bert rend `200` (corps du groupe EN ENTIER) ; depuis
    /// l'autre, il rend la réponse d'un id que la plateforme n'a jamais servi, statut et corps à l'octet — l'id ne dit
    /// rien de plus qu'un id inconnu, et bert n'a rien dans le tenant 1.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AV1_patch_ancien`, `AV1_ailleurs_ignore` (`200` depuis le tenant 1).
    #[tokio::test]
    async fn saon_depuis_un_autre_tenant_l_id_repond_comme_un_inconnu() {
        let (st, _tmp, ids) = saon_etat();
        let depuis_le_sien = saon_patch_depuis(&st, SAON_AUTRE_TENANT, "viewer", saon_ajout(&ids.bert_ailleurs)).await;
        assert_eq!(depuis_le_sien.0, StatusCode::OK, "depuis son tenant : {depuis_le_sien:?}");
        assert_eq!(serde_json::from_str::<Value>(&depuis_le_sien.1).expect("corps JSON"), saon_groupe("viewer"));
        let depuis_l_autre = saon_patch(&st, "viewer", saon_ajout(&ids.bert_ailleurs)).await;
        let inconnu = saon_patch(&st, "viewer", saon_ajout(SAON_INCONNU)).await;
        assert_eq!(depuis_l_autre, inconnu, "depuis l'autre tenant : la réponse d'un inconnu, à l'octet");
        assert_eq!(saon_droits_de(&st, &ids.bert_ailleurs), vec![(SAON_AUTRE_TENANT.to_string(), "viewer".to_string())], "bert n'a rien dans le tenant 1");
    }

    /// CE QU'IL TIENT : une ligne `"grant"` qui nomme ICI un id absent de `platform_user` (droit orphelin) ne vaut
    /// jamais « membre » : l'ajout rend le noTarget d'un inconnu à l'octet, la ligne reste telle quelle (rôle non
    /// réécrit), rien au journal.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AJ2C_fantome_admis`, `AJ2C_tout_admis` (`200`, rôle réécrit).
    #[tokio::test]
    async fn saon_un_droit_sans_identite_n_est_jamais_un_membre() {
        let (st, _tmp, _ids) = saon_etat();
        saon_plan(&st)
            .conn
            .lock()
            .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'editor')", params![SAON_FANTOME, SAON_TENANT])
            .expect("fixture : droit sans identité");
        let avant = saon_droits(&st);
        let fantome = saon_patch(&st, "viewer", saon_ajout(SAON_FANTOME)).await;
        let inconnu = saon_patch(&st, "viewer", saon_ajout(SAON_INCONNU)).await;
        assert_eq!(fantome, inconnu, "un droit sans identité rend l'inconnu, à l'octet : {fantome:?}");
        assert_eq!(fantome.0, StatusCode::BAD_REQUEST);
        assert_eq!(saon_droits(&st), avant, "rien n'est réécrit");
        assert!(saon_maillons(&st).is_empty());
    }

    fn saon_refuser_la_lecture(st: &AppState, table: &'static str) {
        saon_plan(st).conn.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == table => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn saon_lever(st: &AppState) {
        saon_plan(st).conn.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// CE QU'IL TIENT : la lecture de `platform_user` refusée, l'ajout d'une identité sans droit, d'un id d'un autre
    /// tenant et d'un inconnu rend le `503` SCIM `CAUSE_SCIM_UTILISATEUR_ILLISIBLE`, corps EN ENTIER — jamais le
    /// `noTarget` d'une absence ; aucun droit écrit, rien au journal. La lecture revenue, l'identité sans droit
    /// s'ajoute (contrôle positif).
    /// LA MUTATION QUI LE FAIT ROUGIR : `AJ2C_lecture_absente` (`400 noTarget`).
    #[tokio::test]
    async fn saon_une_lecture_ratee_a_l_ajout_est_un_503_jamais_un_no_target() {
        let (st, _tmp, ids) = saon_etat();
        let orpheline = ensure_platform_user(saon_plan(&st), "saon-orpheline").expect("fixture : identité sans droit");
        let avant = saon_droits(&st);
        let attendu = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": CAUSE_SCIM_UTILISATEUR_ILLISIBLE,
            "status": "503",
        });
        let cas = [orpheline.as_str(), ids.bert_ailleurs.as_str(), SAON_INCONNU];
        assert!(cas.len() >= 3, "plancher : trois ids");
        for id in cas {
            saon_refuser_la_lecture(&st, "platform_user");
            let (statut, corps) = saon_patch(&st, "viewer", saon_ajout(id)).await;
            saon_lever(&st);
            assert_eq!(statut, StatusCode::SERVICE_UNAVAILABLE, "{id} : {corps}");
            assert_eq!(serde_json::from_str::<Value>(&corps).expect("corps JSON"), attendu, "{id} : le 503 EN ENTIER");
            assert_eq!(saon_droits(&st), avant, "{id} : aucun droit écrit");
        }
        assert!(saon_maillons(&st).is_empty(), "rien n'est attesté");
        let (statut, corps) = saon_patch(&st, "viewer", saon_ajout(&orpheline)).await;
        assert_eq!(statut, StatusCode::OK, "contrôle positif : {corps}");
    }

    /// `P10.31-u` — LA LIGNE DU DROIT NON LU AU RETRAIT, lue sur le stderr d'un sous-processus : ENTIÈRE, par égalité,
    /// la phrase fixe à la place du nom, sans le tenant ; statut et corps du `503` EN ENTIER (cause, identifiant de
    /// corrélation) ; l'accès n'est pas retiré ; ni le nom du compte ni l'id du tenant nulle part dans les lignes
    /// `[tenants]`, et le nom nulle part dans la sortie. Contrôle : le `404` d'un droit absent n'écrit aucune ligne.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AJ2C_T807_nom`.
    #[tokio::test]
    async fn saon_ligne_du_droit_non_lu_au_retrait_sans_nom() {
        const ENFANT: &str = "SAON_ENFANT_JOURNAL";
        const PHASE: &str = "SAON-PHASE:";
        const COMPTE: &str = "saon-compte-nomme";
        const TENANT: &str = "saon-tenant-journal";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT est lu dans l environnement, comme le choix du mutant
        if std::env::var(ENFANT).is_ok() {
            let (st, _dir) = mk_mode1_state();
            let sa = au_super("sa-saon");
            let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Json(json!({ "id": TENANT, "name": "SajtJ" }))).await;
            assert_eq!(r.status(), StatusCode::CREATED, "fixture : tenant");
            let r = grant_set(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Path(TENANT.into()), Json(json!({ "user": COMPTE, "role": "admin" }))).await;
            assert_eq!(r.status().as_u16(), 200, "fixture : droit posé");
            let cp = st.tenants.control.as_ref().expect("mode 1");
            let refuser = || {
                cp.conn.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Read { table_name, .. } if table_name == "grant" => Authorization::Deny,
                    _ => Authorization::Allow,
                }))
            };
            let lever = || cp.conn.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            refuser();
            let cause = cp
                .conn
                .lock()
                .query_row("SELECT g.role FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id WHERE g.tenant_id=?1 AND p.name=?2", params![TENANT, COMPTE], |r| r.get::<_, String>(0))
                .expect_err("fixture : la lecture du droit est refusée")
                .to_string();
            eprintln!("{PHASE}t807");
            let (statut, corps) = tok_resp_json(grant_delete(State(st.clone()), Extension(sa.clone()), Path((TENANT.into(), COMPTE.into()))).await).await;
            lever();
            eprintln!("{PHASE}absent");
            let (statut_absent, _) = tok_resp_json(grant_delete(State(st.clone()), Extension(sa.clone()), Path((TENANT.into(), "saon-personne".into()))).await).await;
            eprintln!("{PHASE}fin");
            let droits: i64 = cp.conn.lock().query_row("SELECT COUNT(*) FROM \"grant\" WHERE tenant_id=?1", params![TENANT], |r| r.get(0)).expect("lu");
            println!("SAON-SORTIE:{}", json!({ "statut": statut.as_u16(), "corps": corps, "absent": statut_absent.as_u16(), "droits": droits, "cause": cause }));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::scim_ajout_de_groupe_sans_oracle_par_nom::saon_ligne_du_droit_non_lu_au_retrait_sans_nom"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let reste = stdout.split_once("SAON-SORTIE:").unwrap_or_else(|| panic!("contrôle : sortie : {stdout}")).1;
        let s: Value = serde_json::from_str(reste.lines().next().unwrap_or("")).unwrap_or_else(|e| panic!("contrôle : JSON ({e}) : {stdout}"));
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.contains("[tenants]")).map(str::to_string).collect()
        };
        let cause = s["cause"].as_str().expect("contrôle : cause du moteur").to_string();
        assert!(!cause.is_empty(), "contrôle : la cause du moteur est lue");
        assert_eq!(
            phase("t807"),
            vec![format!("[tenants] WARN droit d'un compte (identifiant non lu) NON lu au retrait : {cause}")],
            "la ligne ENTIÈRE, sans le nom ni le tenant : {stderr}"
        );
        assert_eq!(s["statut"], json!(503), "{s}");
        let corps = s["corps"].as_object().expect("contrôle : corps objet");
        assert_eq!(corps.keys().map(String::as_str).collect::<Vec<_>>(), vec!["error", "id"], "les clés du 503, exactement : {s}");
        assert_eq!(corps["error"], json!(crate::tenants::CAUSE_DROIT_NON_LU_RETRAIT_NON_FAIT), "{s}");
        assert!(corps["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "identifiant de corrélation servi : {s}");
        assert_eq!(s["droits"], json!(1), "l'accès n'est PAS retiré");
        assert_eq!(s["absent"], json!(404), "contrôle : un droit absent garde son 404");
        assert!(phase("absent").is_empty(), "contrôle : le 404 n'écrit aucune ligne [tenants] : {stderr}");
        for l in phase("t807") {
            assert!(!l.contains(COMPTE) && !l.contains(TENANT), "ni le compte ni le tenant dans la ligne : {l}");
        }
        assert!(!stderr.contains(COMPTE) && !stdout.contains(COMPTE), "le nom du compte n'apparaît nulle part : {stderr}");
    }
}
