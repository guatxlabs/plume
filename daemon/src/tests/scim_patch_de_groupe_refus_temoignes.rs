// =====================================================================================
// `P10.21-v` (reprise) — LES REFUS DU PATCH DE GROUPE SCIM ONT CHACUN LEUR TÉMOIN, et trois trous voisins.
//
// CE QUI ÉTAIT FAUX après la première livraison (mesuré par un vérificateur, mutants verts sur les témoins `pgoj_`) :
//  * la lecture des porteurs du rôle pendant un `replace` (celle qui retire les absents) n'avait aucun témoin de
//    panne : avalée (`unwrap_or_default`), le `replace` rendait `200` sans rien retirer — l'accès restait en place
//    alors que l'IdP le croyait retiré ; et son échec partait sous la cause d'une ÉCRITURE refusée ;
//  * le filtre `members[value eq "id"]` n'éprouvait que l'attribut : `members[value ne "X"]` lu comme `eq` (X retiré
//    au lieu des autres), `emails[value eq "X"]` lu comme `members` (X retiré), en `200` ;
//  * le cas « value non liste » passait par la branche « value requise » : `remove path members value "x"` lu comme
//    sans `value` retirait TOUS les membres du rôle en `200` ;
//  * `path` non texte, `remove` d'un objet sans `members`, `add path members` sans `value`, `value` scalaire sans
//    `path` : quatre refus revendiqués sans témoin ;
//  * un corps sans liste `Operations` (absente, objet, ou `operations` en minuscules — RFC 7643 §2.1 : noms
//    insensibles à la casse) rendait `200` sans rien appliquer ;
//  * un `path` qualifié par l'URN du schéma Group (RFC 7644 §3.10), admis avant (le `path` était ignoré), était
//    refusé en `invalidPath` depuis que le `path` est lu.
//
// MUTATIONS (une compilation, `VERIF_MUT=<nom>`, retirées ensuite) : g8c_porteurs_avales, g8c_cause_fusionnee,
// g8c_filtre_operateur_libre, g8c_filtre_tete_libre, g8c_value_non_liste_absente, g8c_path_non_texte_absent,
// g8c_objet_sans_members_remove_aucun, g8c_add_members_sans_value_aucun, g8c_valeur_scalaire_aucun,
// g8c_operations_non_liste_vide, g8c_operations_casse_stricte, g8c_urn_refuse.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'existence d'un membre est jugée sur `platform_user` GLOBAL — `remove` d'un
// id inconnu rend `400 noTarget`, d'un id d'un autre tenant `200` : un oracle d'existence cross-tenant subsiste
// (ids aléatoires de 24 caractères, valeur faible), à reprendre sous une clé neuve ; les autres URN (extension
// d'entreprise) restent refusées en `invalidPath` ; `Operations: []` reste admis (aucune opération, `200`).
// =====================================================================================
mod scim_patch_de_groupe_refus_temoignes {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const PGRT_TENANT: &str = "pgrt-t1";

    fn pgrt_etat(membres: &[(&str, Option<&str>)]) -> (AppState, crate::tmp_possede::TmpDb, Vec<String>) {
        let (cp, tmp) = mk_test_control();
        cp.conn
            .lock()
            .execute(
                "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,'PGRT','','sans-base',?2,0)",
                params![PGRT_TENANT, now()],
            )
            .expect("fixture : tenant catalogué");
        let mut ids = Vec::new();
        for (nom, role) in membres {
            let id = ensure_platform_user(&cp, nom).expect("fixture : utilisateur créé");
            if let Some(role) = role {
                cp.conn
                    .lock()
                    .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3)", params![id, PGRT_TENANT, role])
                    .expect("fixture : droit posé");
            }
            ids.push(id);
        }
        (tenant_test_state("admins", "editors", "supers", Some(cp)), tmp, ids)
    }

    fn pgrt_plan(st: &AppState) -> &ControlPlane {
        st.tenants.control.as_ref().expect("fixture : mode 1")
    }

    /// L'ÉTAT RELU EN BASE : `(nom, rôle)` du tenant, triés par nom.
    fn pgrt_droits(st: &AppState) -> Vec<(String, String)> {
        let c = pgrt_plan(st).conn.lock();
        let mut s = c
            .prepare("SELECT p.name, g.role FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id WHERE g.tenant_id=?1 ORDER BY p.name")
            .expect("fixture : droits");
        let lus = s
            .query_map(params![PGRT_TENANT], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .expect("fixture : droits")
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture : droits lisibles");
        lus
    }

    fn pgrt_attendus(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(n, r)| (n.to_string(), r.to_string())).collect()
    }

    fn pgrt_maillons(st: &AppState) -> i64 {
        pgrt_plan(st)
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM control_ledger WHERE kind='scim.group.patch'", [], |r| r.get(0))
            .expect("fixture : journal lisible")
    }

    async fn pgrt_patch(st: &AppState, role: &str, corps: Value) -> (StatusCode, Value) {
        let ctx = ScimCtx { tenant: PGRT_TENANT.into() };
        tok_resp_json(scim_group_patch(State(st.clone()), Extension(ctx), Path(role.to_string()), Json(corps)).await).await
    }

    /// Le refus `400` attendu : corps d'erreur SCIM 2.0, `scimType` nommé, état relu INCHANGÉ, rien d'attesté.
    async fn pgrt_refuse(st: &AppState, quoi: &str, corps: Value, scim_type: &str) {
        let avant = pgrt_droits(st);
        let maillons = pgrt_maillons(st);
        let (statut, v) = pgrt_patch(st, "editor", corps).await;
        assert_eq!(statut, StatusCode::BAD_REQUEST, "{quoi} : refusé en 400 : {v}");
        assert_eq!(v["schemas"], json!(["urn:ietf:params:scim:api:messages:2.0:Error"]), "{quoi} : corps d'erreur SCIM : {v}");
        assert_eq!(v["scimType"], json!(scim_type), "{quoi} : scimType nommé : {v}");
        assert_eq!(pgrt_droits(st), avant, "{quoi} : ÉTAT RELU — aucune opération de la demande n'est appliquée");
        assert_eq!(pgrt_maillons(st), maillons, "{quoi} : rien d'attesté");
    }

    /// CE QU'IL TIENT : la lecture des porteurs du rôle refusée par la base (autorisateur qui refuse `grant.user_id`
    /// dans un SELECT) pendant un `replace` rend `503` sous SA cause, rien retiré, rien attesté ; base rendue, le même
    /// `replace` retire les deux porteurs (contrôle positif : le refus vient bien de la lecture).
    /// LES MUTATIONS QUI LE FONT ROUGIR : `g8c_porteurs_avales` (`200`, rien retiré), `g8c_cause_fusionnee`.
    #[tokio::test]
    async fn pgrt_une_lecture_ratee_des_porteurs_refuse_le_remplacement() {
        let (st, _tmp, _ids) = pgrt_etat(&[("pgrt-anne", Some("admin")), ("pgrt-carl", Some("editor")), ("pgrt-dina", Some("editor"))]);
        let avant = pgrt_droits(&st);
        {
            let mut dans_un_select = false;
            pgrt_plan(&st).conn.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Select => {
                    dans_un_select = true;
                    Authorization::Allow
                }
                AuthAction::Insert { .. } | AuthAction::Update { .. } | AuthAction::Delete { .. } => {
                    dans_un_select = false;
                    Authorization::Allow
                }
                AuthAction::Read { table_name, column_name } if dans_un_select && table_name == "grant" && column_name == "user_id" => {
                    Authorization::Deny
                }
                _ => Authorization::Allow,
            }));
        }
        let remplacement = json!({ "Operations": [{ "op": "replace", "path": "members", "value": [] }] });
        let (statut, v) = pgrt_patch(&st, "editor", remplacement.clone()).await;
        pgrt_plan(&st).conn.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(statut, StatusCode::SERVICE_UNAVAILABLE, "lecture des porteurs ratée : refusé, pas servi comme « aucun porteur » : {v}");
        assert!(
            v["detail"].as_str().unwrap_or("").starts_with(CAUSE_SCIM_PORTEURS_DU_ROLE_ILLISIBLES),
            "la cause dit une LECTURE ratée, pas une écriture : {v}"
        );
        assert_eq!(pgrt_droits(&st), avant, "ÉTAT RELU : rien retiré");
        assert_eq!(pgrt_maillons(&st), 0, "rien d'attesté");
        assert!(pgrt_plan(&st).conn.lock().is_autocommit(), "aucune transaction pendante");
        let (statut, v) = pgrt_patch(&st, "editor", remplacement).await;
        assert_eq!(statut, StatusCode::OK, "contrôle positif, base rendue : {v}");
        assert_eq!(pgrt_droits(&st), pgrt_attendus(&[("pgrt-anne", "admin")]), "ÉTAT RELU : les deux porteurs retirés");
    }

    /// CE QU'IL TIENT : chaque forme refusée, après un `add` valide qui n'est PAS appliqué, rend son `400` nommé.
    /// LES MUTATIONS QUI LE FONT ROUGIR (chacune sur sa ligne) : g8c_filtre_operateur_libre, g8c_filtre_tete_libre,
    /// g8c_value_non_liste_absente, g8c_path_non_texte_absent, g8c_objet_sans_members_remove_aucun,
    /// g8c_add_members_sans_value_aucun, g8c_valeur_scalaire_aucun.
    #[tokio::test]
    async fn pgrt_chaque_forme_refusee_a_son_temoin() {
        let (st, _tmp, ids) = pgrt_etat(&[("pgrt-anne", Some("admin")), ("pgrt-bert", None), ("pgrt-carl", Some("editor")), ("pgrt-dina", Some("editor"))]);
        let (bert, carl) = (ids[1].clone(), ids[2].clone());
        let ajout = json!({ "op": "add", "value": [{ "value": bert }] });
        for (quoi, op, scim_type) in [
            ("filtre d'opérateur ne", json!({ "op": "remove", "path": format!("members[value ne \"{carl}\"]") }), "invalidFilter"),
            ("filtre sur un autre attribut que members", json!({ "op": "remove", "path": format!("emails[value eq \"{carl}\"]") }), "invalidFilter"),
            ("remove path members, value scalaire", json!({ "op": "remove", "path": "members", "value": "x" }), "invalidValue"),
            ("path non texte", json!({ "op": "remove", "path": 5, "value": [{ "value": carl }] }), "invalidPath"),
            ("remove d'un objet sans members", json!({ "op": "remove", "value": { "displayName": "x" } }), "noTarget"),
            ("add path members sans value", json!({ "op": "add", "path": "members" }), "invalidValue"),
            ("value scalaire sans path", json!({ "op": "add", "value": "x" }), "invalidValue"),
        ] {
            pgrt_refuse(&st, quoi, json!({ "Operations": [ajout.clone(), op] }), scim_type).await;
        }
        assert_eq!(
            pgrt_droits(&st),
            pgrt_attendus(&[("pgrt-anne", "admin"), ("pgrt-carl", "editor"), ("pgrt-dina", "editor")]),
            "ÉTAT RELU : ni bert ajouté, ni carl ou dina retirés"
        );
    }

    /// CE QU'IL TIENT : un corps sans liste `Operations` (vide, `Operations` objet, `Operations` texte) est refusé en
    /// `400 invalidSyntax` ; le nom `operations` en minuscules est lu (RFC 7643 §2.1), son ajout est APPLIQUÉ.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `g8c_operations_non_liste_vide` (`200`), `g8c_operations_casse_stricte`.
    #[tokio::test]
    async fn pgrt_un_corps_sans_liste_operations_est_refuse() {
        let (st, _tmp, ids) = pgrt_etat(&[("pgrt-anne", Some("admin")), ("pgrt-bert", None)]);
        let bert = ids[1].clone();
        for (quoi, corps) in [
            ("corps vide", json!({})),
            ("Operations objet", json!({ "Operations": { "op": "add", "value": [{ "value": bert }] } })),
            ("Operations texte", json!({ "Operations": "add" })),
        ] {
            pgrt_refuse(&st, quoi, corps, "invalidSyntax").await;
        }
        let (statut, v) = pgrt_patch(&st, "editor", json!({ "operations": [{ "op": "add", "value": [{ "value": bert }] }] })).await;
        assert_eq!(statut, StatusCode::OK, "`operations` en minuscules : {v}");
        assert_eq!(pgrt_droits(&st), pgrt_attendus(&[("pgrt-anne", "admin"), ("pgrt-bert", "editor")]), "ÉTAT RELU : bert ajouté");
    }

    /// CE QU'IL TIENT : un `path` qualifié par l'URN du schéma Group (RFC 7644 §3.10), casse libre, ajoute et retire
    /// comme son attribut nu — y compris sous filtre.
    /// LA MUTATION QUI LE FAIT ROUGIR : `g8c_urn_refuse` (`400 invalidPath`).
    #[tokio::test]
    async fn pgrt_un_path_qualifie_par_l_urn_du_groupe_est_admis() {
        let (st, _tmp, ids) = pgrt_etat(&[("pgrt-anne", Some("admin")), ("pgrt-bert", None), ("pgrt-carl", Some("editor"))]);
        let (bert, carl) = (ids[1].clone(), ids[2].clone());
        let (statut, v) = pgrt_patch(
            &st,
            "editor",
            json!({ "Operations": [
                { "op": "add", "path": "urn:ietf:params:scim:schemas:core:2.0:Group:members", "value": [{ "value": bert }] },
                { "op": "remove", "path": format!("URN:IETF:PARAMS:SCIM:SCHEMAS:CORE:2.0:GROUP:members[value eq \"{carl}\"]") },
            ] }),
        )
        .await;
        assert_eq!(statut, StatusCode::OK, "path qualifié par l'URN : {v}");
        assert_eq!(pgrt_droits(&st), pgrt_attendus(&[("pgrt-anne", "admin"), ("pgrt-bert", "editor")]), "ÉTAT RELU : bert ajouté, carl retiré");
    }
}
