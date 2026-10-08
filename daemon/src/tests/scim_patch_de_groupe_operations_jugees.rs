// =====================================================================================
// `P10.21-v` — LES OPÉRATIONS D'UN PATCH DE GROUPE SCIM SONT JUGÉES (RFC 7644 §3.5.2) : une `op` inconnue, un
// membre inconnu, un `path` inconnu refusent la demande ENTIÈRE en `400` SCIM nommé ; `replace` REMPLACE les
// membres du rôle ; le retrait au format `path: members[value eq "id"]` retire.
//
// LES DÉFAUTS, MESURÉS par mutation (chaque mutant rétablit la forme d'avant sur un point) :
//  * `VERIF_MUT=g8_op_inconnue_ignoree` (le bras `_ => {}`) : une `op` inconnue rend `200` ;
//  * `VERIF_MUT=g8_membre_inconnu_saute` : un membre absent de `platform_user` ne refuse plus rien ;
//  * `VERIF_MUT=g8_replace_comme_add` : `replace` laisse leur droit aux membres absents de l'ensemble servi ;
//  * `VERIF_MUT=g8_path_ignore` (`path` jamais lu) : le retrait par filtre ne retire rien.
//
// CE QUI ÉTAIT FAUX OU INCOMPLET DANS L'ÉNONCÉ : une `op` inconnue SANS membre (`{op:"copy"}`) n'atteignait même
// pas le bras `_ => {}` (la boucle des membres était vide) ; et le trou `path` n'était pas dans la cellule.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le comportement d'un IdP réel face à un `400` (rejeu, alerte) ; les filtres
// SCIM composés (`and`, `or`) — refusés en `invalidFilter`, jamais interprétés ; la base plateforme où un
// `platform_user` existe sans droit dans AUCUN tenant (il reste une cible valide d'`add`, comme avant).
// =====================================================================================
mod scim_patch_de_groupe_operations_jugees {
    use super::*;

    const PGOJ_TENANT: &str = "pgoj-t1";

    fn pgoj_etat(membres: &[(&str, Option<&str>)]) -> (AppState, crate::tmp_possede::TmpDb, Vec<String>) {
        let (cp, tmp) = mk_test_control();
        cp.conn
            .lock()
            .execute(
                "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,'PGOJ','','sans-base',?2,0)",
                params![PGOJ_TENANT, now()],
            )
            .expect("fixture : tenant catalogué");
        let mut ids = Vec::new();
        for (nom, role) in membres {
            let id = ensure_platform_user(&cp, nom).expect("fixture : utilisateur créé");
            if let Some(role) = role {
                cp.conn
                    .lock()
                    .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3)", params![id, PGOJ_TENANT, role])
                    .expect("fixture : droit posé");
            }
            ids.push(id);
        }
        (tenant_test_state("admins", "editors", "supers", Some(cp)), tmp, ids)
    }

    fn pgoj_plan(st: &AppState) -> &ControlPlane {
        st.tenants.control.as_ref().expect("fixture : mode 1")
    }

    /// L'ÉTAT RELU EN BASE : `(nom, rôle)` du tenant, triés par nom.
    fn pgoj_droits(st: &AppState) -> Vec<(String, String)> {
        let c = pgoj_plan(st).conn.lock();
        let mut s = c
            .prepare("SELECT p.name, g.role FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id WHERE g.tenant_id=?1 ORDER BY p.name")
            .expect("fixture : droits");
        let lus = s
            .query_map(params![PGOJ_TENANT], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .expect("fixture : droits")
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture : droits lisibles");
        lus
    }

    fn pgoj_attendus(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(n, r)| (n.to_string(), r.to_string())).collect()
    }

    fn pgoj_maillons(st: &AppState) -> i64 {
        pgoj_plan(st)
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM control_ledger WHERE kind='scim.group.patch'", [], |r| r.get(0))
            .expect("fixture : journal lisible")
    }

    fn pgoj_acces(st: &AppState, nom: &str) -> Result<String, StatusCode> {
        resolve_tenant_access(st, nom, None, false, Some(PGOJ_TENANT), false, None).map(|a| a.role).map_err(|(code, _)| code)
    }

    async fn pgoj_patch(st: &AppState, role: &str, corps: Value) -> (StatusCode, Value) {
        let ctx = ScimCtx { tenant: PGOJ_TENANT.into() };
        tok_resp_json(scim_group_patch(State(st.clone()), Extension(ctx), Path(role.to_string()), Json(corps)).await).await
    }

    /// Le refus `400` attendu : corps d'erreur SCIM 2.0, `scimType` nommé, état relu INCHANGÉ, rien d'attesté.
    async fn pgoj_refuse(st: &AppState, quoi: &str, role: &str, corps: Value, scim_type: &str) {
        let avant = pgoj_droits(st);
        let maillons = pgoj_maillons(st);
        let (statut, v) = pgoj_patch(st, role, corps).await;
        assert_eq!(statut, StatusCode::BAD_REQUEST, "{quoi} : refusé en 400 : {v}");
        assert_eq!(v["schemas"], json!(["urn:ietf:params:scim:api:messages:2.0:Error"]), "{quoi} : corps d'erreur SCIM : {v}");
        assert_eq!(v["scimType"], json!(scim_type), "{quoi} : scimType nommé : {v}");
        assert_eq!(v["status"], json!("400"), "{quoi} : statut dans le corps : {v}");
        assert!(v["detail"].as_str().unwrap_or("").contains("aucune de ses opérations n'est appliquée"), "{quoi} : l'atomicité est dite : {v}");
        assert_eq!(pgoj_droits(st), avant, "{quoi} : ÉTAT RELU — aucune opération de la demande n'est appliquée");
        assert_eq!(pgoj_maillons(st), maillons, "{quoi} : rien d'attesté");
        assert!(pgoj_plan(st).conn.lock().is_autocommit(), "{quoi} : aucune transaction pendante");
    }

    /// CE QU'IL TIENT : une `op` hors add/remove/replace — après un `add` valide, avec ou sans membres — refuse la
    /// demande entière en `400 invalidSyntax`, l'ajout précédent n'est PAS appliqué.
    /// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=g8_op_inconnue_ignoree` — `200`, l'ajout appliqué.
    #[tokio::test]
    async fn pgoj_une_op_inconnue_refuse_la_demande_entiere() {
        let (st, _tmp, ids) = pgoj_etat(&[("pgoj-anne", Some("admin")), ("pgoj-bert", None), ("pgoj-carl", Some("editor"))]);
        let (bert, carl) = (ids[1].clone(), ids[2].clone());
        let ajout = json!({ "op": "add", "value": [{ "value": bert }] });
        pgoj_refuse(&st, "op `move` avec membres", "editor", json!({ "Operations": [ajout.clone(), { "op": "move", "value": [{ "value": carl }] }] }), "invalidSyntax").await;
        pgoj_refuse(&st, "op `copy` sans membre", "editor", json!({ "Operations": [ajout.clone(), { "op": "copy" }] }), "invalidSyntax").await;
        pgoj_refuse(&st, "op absente", "editor", json!({ "Operations": [ajout.clone(), { "value": [{ "value": carl }] }] }), "invalidSyntax").await;
        assert_eq!(pgoj_acces(&st, "pgoj-bert"), Err(StatusCode::FORBIDDEN), "ACCÈS : l'ajout refusé n'a rien donné");
    }

    /// CE QU'IL TIENT : `add` ou `remove` d'une identité inconnue refuse la demande en `400 noTarget`, les
    /// opérations précédentes défaites (l'ajout de B, le retrait de C).
    /// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=g8_membre_inconnu_saute` — plus de `400`.
    #[tokio::test]
    async fn pgoj_un_membre_inconnu_refuse_la_demande_entiere() {
        let (st, _tmp, ids) = pgoj_etat(&[("pgoj-anne", Some("admin")), ("pgoj-bert", None), ("pgoj-carl", Some("editor"))]);
        let (bert, carl) = (ids[1].clone(), ids[2].clone());
        pgoj_refuse(
            &st,
            "add d'un inconnu",
            "editor",
            json!({ "Operations": [{ "op": "add", "value": [{ "value": bert }, { "value": "pgoj-id-qui-n-existe-pas" }] }] }),
            "noTarget",
        )
        .await;
        pgoj_refuse(
            &st,
            "remove d'un inconnu",
            "editor",
            json!({ "Operations": [{ "op": "remove", "value": [{ "value": carl }] }, { "op": "remove", "value": [{ "value": "pgoj-id-qui-n-existe-pas" }] }] }),
            "noTarget",
        )
        .await;
        assert_eq!(pgoj_acces(&st, "pgoj-carl"), Ok("editor".to_string()), "ACCÈS : le retrait défait n'a rien retiré");
    }

    /// CE QU'IL TIENT : `replace` (casse d'Azure, `path: members`) fait de l'ensemble servi les membres du rôle :
    /// l'absent PERD son droit, le nouveau le reçoit, les autres rôles sont intouchés. Sur `admin`, remplacer le
    /// seul administrateur par un autre passe (l'anti-verrouillage juge l'état final) ; remplacer par l'ensemble
    /// vide est refusé `409`, rien d'appliqué.
    /// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=g8_replace_comme_add` — l'absent garde son droit.
    #[tokio::test]
    async fn pgoj_replace_remplace_les_membres_du_role() {
        let (st, _tmp, ids) =
            pgoj_etat(&[("pgoj-anne", Some("admin")), ("pgoj-bert", None), ("pgoj-carl", Some("editor")), ("pgoj-dina", Some("editor"))]);
        let (bert, carl) = (ids[1].clone(), ids[2].clone());
        let (statut, v) = pgoj_patch(&st, "editor", json!({ "Operations": [{ "op": "Replace", "path": "members", "value": [{ "value": bert }, { "value": carl }] }] })).await;
        assert_eq!(statut, StatusCode::OK, "replace conforme : {v}");
        assert_eq!(
            pgoj_droits(&st),
            pgoj_attendus(&[("pgoj-anne", "admin"), ("pgoj-bert", "editor"), ("pgoj-carl", "editor")]),
            "ÉTAT RELU : dina (absente de l'ensemble servi) a perdu `editor`, bert l'a reçu, anne intouchée"
        );
        assert_eq!(pgoj_acces(&st, "pgoj-dina"), Err(StatusCode::FORBIDDEN), "ACCÈS : l'absent n'entre plus");
        assert_eq!(pgoj_maillons(&st), 1, "attesté une fois");
        // Sur `admin` : remplacer anne (seule administratrice) par bert garde un administrateur.
        let (statut, v) = pgoj_patch(&st, "admin", json!({ "Operations": [{ "op": "replace", "value": [{ "value": bert }] }] })).await;
        assert_eq!(statut, StatusCode::OK, "replace de l'administrateur par un autre : {v}");
        assert_eq!(pgoj_droits(&st), pgoj_attendus(&[("pgoj-bert", "admin"), ("pgoj-carl", "editor")]), "ÉTAT RELU : bert administrateur, anne retirée");
        // L'ensemble vide viderait le tenant de ses administrateurs : 409, rien d'appliqué.
        let avant = pgoj_droits(&st);
        let (statut, v) = pgoj_patch(
            &st,
            "admin",
            json!({ "Operations": [{ "op": "add", "value": [{ "value": carl }] }, { "op": "replace", "path": "members", "value": [] }] }),
        )
        .await;
        assert_eq!(statut, StatusCode::CONFLICT, "replace par l'ensemble vide : anti-verrouillage : {v}");
        assert_eq!(pgoj_droits(&st), avant, "ÉTAT RELU : l'ajout de carl est défait avec le reste");
    }

    /// CE QU'IL TIENT : `remove` au format RFC 7644 `path: members[value eq "id"]` sans `value` (la forme émise par
    /// les fournisseurs d'identité usuels) RETIRE ; les mots-clés sans égard à la casse ; `add` par filtre ajoute ;
    /// `remove` de `path: members` sans `value` retire TOUS les membres du rôle.
    /// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=g8_path_ignore` — rien n'est retiré.
    #[tokio::test]
    async fn pgoj_un_retrait_par_filtre_de_path_retire() {
        let (st, _tmp, ids) =
            pgoj_etat(&[("pgoj-anne", Some("admin")), ("pgoj-bert", None), ("pgoj-carl", Some("editor")), ("pgoj-dina", Some("editor"))]);
        let (bert, carl) = (ids[1].clone(), ids[2].clone());
        let (statut, v) = pgoj_patch(&st, "editor", json!({ "Operations": [{ "op": "remove", "path": format!("members[value eq \"{carl}\"]") }] })).await;
        assert_eq!(statut, StatusCode::OK, "retrait par filtre : {v}");
        assert_eq!(pgoj_droits(&st), pgoj_attendus(&[("pgoj-anne", "admin"), ("pgoj-dina", "editor")]), "ÉTAT RELU : carl retiré");
        assert_eq!(pgoj_acces(&st, "pgoj-carl"), Err(StatusCode::FORBIDDEN), "ACCÈS : carl n'entre plus");
        let (statut, v) = pgoj_patch(&st, "editor", json!({ "Operations": [{ "op": "Add", "path": format!("Members[Value EQ \"{bert}\"]") }] })).await;
        assert_eq!(statut, StatusCode::OK, "ajout par filtre (casse libre) : {v}");
        assert_eq!(
            pgoj_droits(&st),
            pgoj_attendus(&[("pgoj-anne", "admin"), ("pgoj-bert", "editor"), ("pgoj-dina", "editor")]),
            "ÉTAT RELU : bert ajouté"
        );
        let (statut, v) = pgoj_patch(&st, "editor", json!({ "Operations": [{ "op": "remove", "path": "members" }] })).await;
        assert_eq!(statut, StatusCode::OK, "retrait de tous les membres : {v}");
        assert_eq!(pgoj_droits(&st), pgoj_attendus(&[("pgoj-anne", "admin")]), "ÉTAT RELU : plus aucun `editor`");
    }

    /// CE QU'IL TIENT — LES FORMES ADMISES, et L'INVERSE : la forme d'avant (`path` absent, `value` liste) rend
    /// `200` et les mêmes lignes ; `path: members` ; `value: {members: […]}` ; un renommage (`displayName`, par
    /// `path` ou par objet) est accepté sans rien écrire. LES FORMES REFUSÉES, chacune après un `add` valide qui
    /// n'est pas appliqué : `path` inconnu, filtre autre que `value eq`, `replace` filtré, membre sans `value`,
    /// `value` qui n'est pas une liste, `remove` sans `path` ni `value`.
    #[tokio::test]
    async fn pgoj_formes_admises_et_formes_refusees() {
        let (st, _tmp, ids) = pgoj_etat(&[("pgoj-anne", Some("admin")), ("pgoj-bert", None), ("pgoj-carl", None), ("pgoj-dina", None)]);
        let (bert, carl, dina) = (ids[1].clone(), ids[2].clone(), ids[3].clone());
        for (quoi, corps) in [
            ("forme d'avant", json!({ "Operations": [{ "op": "add", "value": [{ "value": bert }] }] })),
            ("path members (Azure AD)", json!({ "Operations": [{ "op": "Add", "path": "members", "value": [{ "value": carl, "display": "c" }] }] })),
            ("value objet members (RFC §3.5.2.1)", json!({ "Operations": [{ "op": "add", "value": { "members": [{ "value": dina }] } }] })),
            ("renommage par path", json!({ "Operations": [{ "op": "replace", "path": "displayName", "value": "Éditeurs" }] })),
            ("renommage par objet (Okta)", json!({ "Operations": [{ "op": "replace", "value": { "id": "editor", "displayName": "Éditeurs" } }] })),
        ] {
            let (statut, v) = pgoj_patch(&st, "editor", corps).await;
            assert_eq!(statut, StatusCode::OK, "{quoi} : forme admise : {v}");
        }
        assert_eq!(
            pgoj_droits(&st),
            pgoj_attendus(&[("pgoj-anne", "admin"), ("pgoj-bert", "editor"), ("pgoj-carl", "editor"), ("pgoj-dina", "editor")]),
            "ÉTAT RELU : trois ajouts, les renommages n'écrivent rien"
        );
        let (st, _tmp2, ids) = pgoj_etat(&[("pgoj-anne", Some("admin")), ("pgoj-bert", None), ("pgoj-carl", Some("editor"))]);
        let (bert, carl) = (ids[1].clone(), ids[2].clone());
        let ajout = json!({ "op": "add", "value": [{ "value": bert }] });
        for (quoi, op, scim_type) in [
            ("path inconnu", json!({ "op": "remove", "path": "memberz", "value": [{ "value": carl }] }), "invalidPath"),
            ("filtre autre que value eq", json!({ "op": "remove", "path": "members[display eq \"c\"]" }), "invalidFilter"),
            ("filtre composé", json!({ "op": "remove", "path": format!("members[value eq \"{carl}\" or value eq \"x\"]") }), "invalidFilter"),
            ("replace filtré", json!({ "op": "replace", "path": format!("members[value eq \"{carl}\"]"), "value": [] }), "invalidPath"),
            ("membre sans value", json!({ "op": "remove", "value": [{ "display": "c" }] }), "invalidValue"),
            ("value non liste", json!({ "op": "add", "path": "members", "value": "x" }), "invalidValue"),
            ("remove sans path ni value", json!({ "op": "remove" }), "noTarget"),
        ] {
            pgoj_refuse(&st, quoi, "editor", json!({ "Operations": [ajout.clone(), op] }), scim_type).await;
        }
    }
}
