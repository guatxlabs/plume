// =====================================================================================
// `P10.21-v` (seconde reprise) — LES COMPTES ET LES TOLÉRANCES DU PATCH DE GROUPE SCIM ONT LEUR TÉMOIN.
//
// CE QUI ÉTAIT FAUX après la reprise (mesuré par un vérificateur, mutants verts sur les témoins `pgoj_`/`pgrt_`) :
//  * les retraits d'un `replace` (porteurs absents de l'ensemble servi) n'avaient aucun témoin de COMPTE : non
//    ajoutés à `removed`, le journal de contrôle attestait « -0 » pendant qu'un membre perdait son accès ;
//  * la garde du `]` final du filtre n'avait aucun témoin : ignorée, `remove members[value eq "X"].display` (retrait
//    d'un SOUS-attribut, RFC 7644 §3.5.2.2) retirait X en `200`, et `add` sur le même path lui donnait le rôle ;
//  * `path = externalId` (« accepté, ignoré ») n'était éprouvé que pour `displayName` : refusé, la synchro d'un IdP qui
//    le pousse échouait en boucle sans qu'aucun test ne le voie ;
//  * quatre tolérances sans témoin : `value: null` vaut une value absente, un `path` entouré d'espaces est lu, un
//    filtre sans guillemets et un filtre d'id vide sont `invalidFilter` (pas un membre lu, pas `noTarget`).
//  * `P10.21-r` (hérité, corps déplacé tel quel) : la lecture ratée de la garde anti-verrouillage de l'AJOUT (qui
//    rétrograderait le dernier administrateur) n'avait aucun témoin — avalée, la garde s'ouvrait.
//
// MUTATIONS (une compilation, `VERIF_MUT=<nom>`, retirées ensuite) : g8d_remplacer_retrait_non_compte,
// g8d_filtre_crochet_final_libre, g8d_externalid_refuse, g8d_value_null_non_filtre, g8d_path_non_rogne,
// g8d_filtre_sans_guillemets, g8d_filtre_id_vide_admis, g8d_ajout_garde_err_avalee.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'oracle d'existence cross-tenant (`noTarget` sur `platform_user` global)
// reste ouvert ; le détail du journal n'est relu que sur le `replace` et le `remove` sans value, pas sur chaque forme ;
// la lecture ratée de la garde d'ajout n'est éprouvée que sur sa PREMIÈRE lecture (le droit actuel du membre), pas sur
// le compte des administrateurs effectifs.
// =====================================================================================
mod scim_patch_de_groupe_tolerances_temoignees {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const PGTT_TENANT: &str = "pgtt-t1";

    fn pgtt_etat(membres: &[(&str, Option<&str>)]) -> (AppState, crate::tmp_possede::TmpDb, Vec<String>) {
        let (cp, tmp) = mk_test_control();
        cp.conn
            .lock()
            .execute(
                "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,'PGTT','','sans-base',?2,0)",
                params![PGTT_TENANT, now()],
            )
            .expect("fixture : tenant catalogué");
        let mut ids = Vec::new();
        for (nom, role) in membres {
            let id = ensure_platform_user(&cp, nom).expect("fixture : utilisateur créé");
            if let Some(role) = role {
                cp.conn
                    .lock()
                    .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3)", params![id, PGTT_TENANT, role])
                    .expect("fixture : droit posé");
            }
            ids.push(id);
        }
        (tenant_test_state("admins", "editors", "supers", Some(cp)), tmp, ids)
    }

    fn pgtt_plan(st: &AppState) -> &ControlPlane {
        st.tenants.control.as_ref().expect("fixture : mode 1")
    }

    /// L'ÉTAT RELU EN BASE : `(nom, rôle)` du tenant, triés par nom.
    fn pgtt_droits(st: &AppState) -> Vec<(String, String)> {
        let c = pgtt_plan(st).conn.lock();
        let mut s = c
            .prepare("SELECT p.name, g.role FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id WHERE g.tenant_id=?1 ORDER BY p.name")
            .expect("fixture : droits");
        let lus = s
            .query_map(params![PGTT_TENANT], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .expect("fixture : droits")
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture : droits lisibles");
        lus
    }

    fn pgtt_attendus(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(n, r)| (n.to_string(), r.to_string())).collect()
    }

    /// Le DÉTAIL des maillons `scim.group.patch` du journal de contrôle, dans l'ordre d'écriture.
    fn pgtt_maillons(st: &AppState) -> Vec<String> {
        let c = pgtt_plan(st).conn.lock();
        let mut s = c.prepare("SELECT detail FROM control_ledger WHERE kind='scim.group.patch' ORDER BY id").expect("fixture : journal");
        let lus = s.query_map([], |r| r.get(0)).expect("fixture : journal").collect::<Result<Vec<String>, _>>().expect("fixture : journal lisible");
        lus
    }

    async fn pgtt_patch(st: &AppState, role: &str, corps: Value) -> (StatusCode, Value) {
        let ctx = ScimCtx { tenant: PGTT_TENANT.into() };
        tok_resp_json(scim_group_patch(State(st.clone()), Extension(ctx), Path(role.to_string()), Json(corps)).await).await
    }

    /// CE QU'IL TIENT : un `replace` compte au journal ses ajouts ET ses retraits (porteurs absents de l'ensemble
    /// servi) ; un `remove path members` sans value compte chaque porteur retiré. État relu à chaque pas.
    /// LA MUTATION QUI LE FAIT ROUGIR : `g8d_remplacer_retrait_non_compte` (« +2/-0 » et « +0/-0 »).
    #[tokio::test]
    async fn pgtt_un_remplacement_compte_ses_retraits_au_journal() {
        let (st, _tmp, ids) = pgtt_etat(&[("pgtt-anne", Some("admin")), ("pgtt-bert", None), ("pgtt-carl", Some("editor")), ("pgtt-dina", Some("editor"))]);
        let (bert, carl) = (ids[1].clone(), ids[2].clone());
        let (statut, v) = pgtt_patch(&st, "editor", json!({ "Operations": [{ "op": "replace", "path": "members", "value": [{ "value": bert }, { "value": carl }] }] })).await;
        assert_eq!(statut, StatusCode::OK, "replace : {v}");
        assert_eq!(
            pgtt_droits(&st),
            pgtt_attendus(&[("pgtt-anne", "admin"), ("pgtt-bert", "editor"), ("pgtt-carl", "editor")]),
            "ÉTAT RELU : bert ajouté, dina retirée"
        );
        let (statut, v) = pgtt_patch(&st, "editor", json!({ "Operations": [{ "op": "remove", "path": "members" }] })).await;
        assert_eq!(statut, StatusCode::OK, "remove sans value : {v}");
        assert_eq!(pgtt_droits(&st), pgtt_attendus(&[("pgtt-anne", "admin")]), "ÉTAT RELU : bert et carl retirés");
        assert_eq!(
            pgtt_maillons(&st),
            vec!["role 'editor' +2/-1 membres".to_string(), "role 'editor' +0/-2 membres".to_string()],
            "le journal compte chaque retrait du remplacement"
        );
    }

    /// CE QU'IL TIENT : un filtre mal formé est `400 invalidFilter`, état relu inchangé, rien d'attesté — sous-attribut
    /// après le `]` (en `remove` comme en `add`), id sans guillemets, id vide.
    /// LES MUTATIONS QUI LE FONT ROUGIR (chacune sur sa ligne) : `g8d_filtre_crochet_final_libre` (`200`, carl retiré,
    /// bert promu), `g8d_filtre_sans_guillemets` (`200`, carl retiré), `g8d_filtre_id_vide_admis` (`noTarget`).
    #[tokio::test]
    async fn pgtt_un_filtre_mal_forme_est_refuse() {
        let (st, _tmp, ids) = pgtt_etat(&[("pgtt-anne", Some("admin")), ("pgtt-bert", None), ("pgtt-carl", Some("editor"))]);
        let (bert, carl) = (ids[1].clone(), ids[2].clone());
        let avant = pgtt_droits(&st);
        for (quoi, op, path) in [
            ("remove d'un sous-attribut après le filtre", "remove", format!("members[value eq \"{carl}\"].display")),
            ("add d'un sous-attribut après le filtre", "add", format!("members[value eq \"{bert}\"].display")),
            ("id sans guillemets", "remove", format!("members[value eq {carl}]")),
            ("id vide", "remove", "members[value eq \"\"]".to_string()),
        ] {
            let (statut, v) = pgtt_patch(&st, "editor", json!({ "Operations": [{ "op": op, "path": path }] })).await;
            assert_eq!(statut, StatusCode::BAD_REQUEST, "{quoi} : refusé en 400 : {v}");
            assert_eq!(v["scimType"], json!("invalidFilter"), "{quoi} : scimType nommé : {v}");
            assert_eq!(pgtt_droits(&st), avant, "{quoi} : ÉTAT RELU inchangé");
        }
        assert!(pgtt_maillons(&st).is_empty(), "rien d'attesté");
    }

    /// CE QU'IL TIENT : `path = externalId` comme `displayName` est admis et ignoré (`200`, aucun droit touché) — la
    /// synchro d'un IdP qui pousse l'un ou l'autre n'échoue pas.
    /// LA MUTATION QUI LE FAIT ROUGIR : `g8d_externalid_refuse` (`400 invalidPath`).
    #[tokio::test]
    async fn pgtt_un_path_external_id_est_admis_et_ignore() {
        let (st, _tmp, _ids) = pgtt_etat(&[("pgtt-anne", Some("admin")), ("pgtt-carl", Some("editor"))]);
        let avant = pgtt_droits(&st);
        for path in ["externalId", "EXTERNALID", "displayName"] {
            let (statut, v) = pgtt_patch(&st, "editor", json!({ "Operations": [{ "op": "replace", "path": path, "value": "x" }] })).await;
            assert_eq!(statut, StatusCode::OK, "path {path} : {v}");
            assert_eq!(pgtt_droits(&st), avant, "path {path} : ÉTAT RELU inchangé");
        }
    }

    /// CE QU'IL TIENT : `value: null` vaut une value absente (`remove path members` retire tous les porteurs) ; un
    /// `path` entouré d'espaces est lu comme l'attribut nu.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `g8d_value_null_non_filtre` (`400 invalidValue`), `g8d_path_non_rogne`
    /// (`400 invalidPath`).
    #[tokio::test]
    async fn pgtt_value_nulle_et_path_entoure_d_espaces_sont_lus() {
        let (st, _tmp, ids) = pgtt_etat(&[("pgtt-anne", Some("admin")), ("pgtt-bert", None), ("pgtt-carl", Some("editor"))]);
        let bert = ids[1].clone();
        let (statut, v) = pgtt_patch(&st, "editor", json!({ "Operations": [{ "op": "add", "path": " members ", "value": [{ "value": bert }] }] })).await;
        assert_eq!(statut, StatusCode::OK, "path entouré d'espaces : {v}");
        assert_eq!(
            pgtt_droits(&st),
            pgtt_attendus(&[("pgtt-anne", "admin"), ("pgtt-bert", "editor"), ("pgtt-carl", "editor")]),
            "ÉTAT RELU : bert ajouté"
        );
        let (statut, v) = pgtt_patch(&st, "editor", json!({ "Operations": [{ "op": "remove", "path": "members", "value": null }] })).await;
        assert_eq!(statut, StatusCode::OK, "value null : {v}");
        assert_eq!(pgtt_droits(&st), pgtt_attendus(&[("pgtt-anne", "admin")]), "ÉTAT RELU : bert et carl retirés");
    }

    /// `P10.21-r` (hérité) — CE QU'IL TIENT : la lecture du droit actuel du membre refusée par la base (autorisateur qui
    /// refuse `grant.role` dans un SELECT) pendant l'AJOUT du seul administrateur à `editor` rend `503` sous la cause
    /// « dernier administrateur non établi », rien écrit ni attesté ; base rendue, le même ajout est refusé en `409`
    /// (contrôle positif : la garde lit bien, le `503` vient de la lecture).
    /// LA MUTATION QUI LE FAIT ROUGIR : `g8d_ajout_garde_err_avalee` (`200`, le tenant perd son administrateur).
    #[tokio::test]
    async fn pgtt_une_lecture_ratee_de_la_garde_d_ajout_refuse() {
        let (st, _tmp, ids) = pgtt_etat(&[("pgtt-anne", Some("admin")), ("pgtt-carl", Some("editor"))]);
        let anne = ids[0].clone();
        let avant = pgtt_droits(&st);
        {
            let mut dans_un_select = false;
            pgtt_plan(&st).conn.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Select => {
                    dans_un_select = true;
                    Authorization::Allow
                }
                AuthAction::Insert { .. } | AuthAction::Update { .. } | AuthAction::Delete { .. } => {
                    dans_un_select = false;
                    Authorization::Allow
                }
                AuthAction::Read { table_name, column_name } if dans_un_select && table_name == "grant" && column_name == "role" => {
                    Authorization::Deny
                }
                _ => Authorization::Allow,
            }));
        }
        let ajout = json!({ "Operations": [{ "op": "add", "path": "members", "value": [{ "value": anne }] }] });
        let (statut, v) = pgtt_patch(&st, "editor", ajout.clone()).await;
        pgtt_plan(&st).conn.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(statut, StatusCode::SERVICE_UNAVAILABLE, "garde d'ajout illisible : refusé, pas ouverte : {v}");
        assert!(
            v["detail"].as_str().unwrap_or("").starts_with(CAUSE_SCIM_DERNIER_ADMINISTRATEUR_NON_ETABLI),
            "la cause dit l'anti-verrouillage non établi : {v}"
        );
        assert_eq!(pgtt_droits(&st), avant, "ÉTAT RELU : anne reste administratrice");
        assert!(pgtt_maillons(&st).is_empty(), "rien d'attesté");
        assert!(pgtt_plan(&st).conn.lock().is_autocommit(), "aucune transaction pendante");
        let (statut, v) = pgtt_patch(&st, "editor", ajout).await;
        assert_eq!(statut, StatusCode::CONFLICT, "contrôle positif, base rendue : la garde lit et refuse : {v}");
        assert_eq!(pgtt_droits(&st), avant, "ÉTAT RELU : anne reste administratrice");
    }
}
