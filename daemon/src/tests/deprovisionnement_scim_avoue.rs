// =====================================================================================
// `P10.21-l` — UN DÉPROVISIONNEMENT SCIM QUE LA BASE REFUSE EST REFUSÉ À L'IdP, ET RIEN NE L'ATTESTE.
//
// LE DÉFAUT, MESURÉ AVANT TOUT CORRECTIF. `scim_user_replace` (`active=false`) et `scim_user_delete`
// retiraient les droits de l'utilisateur sous `let _ =`, posaient la ligne `scim.user.deprovision` au
// journal de contrôle et répondaient au fournisseur d'identité par un succès (`200` et `204`) : sur une
// base qui refusait l'écriture, l'accès restait en place — `resolve_tenant_access`, relu à chaque
// requête, le servait encore — pendant que le journal et l'IdP le disaient retiré. L'IdP ne rejoue pas
// un succès. Deux sites que la clé ne nommait pas portent le même défaut : le retrait d'un membre par
// `PATCH /Groups` (`unwrap_or(0)`, puis `200` et `scim.group.patch`) et la LECTURE d'existence des deux
// déprovisionnements (`.ok()` / `.is_err()`), qui servait une lecture ratée comme un `404` — lu par un
// IdP, sur un DELETE, comme « déjà déprovisionné ».
//
// LES DEUX VOIES D'ÉCHEC : une VUE TEMPORAIRE de même nom posée par-dessus `"grant"` renommée (la
// lecture passe, l'écriture tombe), et la TABLE RETIRÉE (la lecture tombe d'abord).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une base réellement en lecture seule (le chemin refusé est le
// même) ; la course « présent à la lecture, absent à l'écriture » (le `404` sans trace qui la couvre
// n'est pas fabriqué ici) ; le rejeu effectif par un fournisseur d'identité réel ; et la lecture de
// l'anti-lockout (`scim_would_orphan_last_admin`), qui lisait un échec comme « pas administrateur » —
// tenue depuis par `P10.21-o` (témoins `pafv_`).
// =====================================================================================
mod deprovisionnement_scim_avoue {
    use super::*;

    const DSA_TENANT: &str = "dsa-t1";

    /// Un plan de contrôle avec le tenant catalogué (sans lui, `resolve_tenant_access` ne résout rien et
    /// la mesure de l'accès serait vide), et un utilisateur porteur d'un droit `editor`.
    fn dsa_etat_avec_membre(nom: &str) -> (AppState, crate::tmp_possede::TmpDb, String) {
        let (cp, tmp) = mk_test_control();
        let id = ensure_platform_user(&cp, nom).expect("fixture : utilisateur créé");
        {
            let c = cp.conn.lock();
            c.execute(
                "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,'DSA','','sans-base',?2,0)",
                params![DSA_TENANT, now()],
            )
            .expect("fixture : tenant catalogué");
            c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'editor')", params![id, DSA_TENANT])
                .expect("fixture : droit posé");
        }
        (tenant_test_state("admins", "editors", "supers", Some(cp)), tmp, id)
    }

    fn dsa_plan(st: &AppState) -> &ControlPlane {
        st.tenants.control.as_ref().expect("fixture : mode 1")
    }

    fn dsa_executer(st: &AppState, sql: &str) {
        dsa_plan(st).conn.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn dsa_compter(st: &AppState, sql: &str, id: &str) -> i64 {
        dsa_plan(st).conn.lock().query_row(sql, params![id], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn dsa_maillons(st: &AppState, genre: &str) -> i64 {
        dsa_plan(st)
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM control_ledger WHERE kind=?1", params![genre], |r| r.get(0))
            .expect("fixture : le journal de contrôle se lit")
    }

    /// L'ACCÈS TEL QUE LE SERT `auth_guard` à chaque requête (identité Basic ou cookie, mode 1).
    fn dsa_acces(st: &AppState, nom: &str) -> Result<String, StatusCode> {
        resolve_tenant_access(st, nom, None, false, Some(DSA_TENANT), false, None).map(|a| a.role).map_err(|(code, _)| code)
    }

    /// Les voies d'échec : (nom, pose, remise, table où relire les droits pendant la panne).
    fn dsa_voies() -> [(&'static str, &'static str, &'static str, &'static str); 2] {
        [
            (
                "vue temporaire",
                "ALTER TABLE \"grant\" RENAME TO grant_source; CREATE TEMP VIEW \"grant\" AS SELECT * FROM grant_source;",
                "DROP VIEW \"grant\"; ALTER TABLE grant_source RENAME TO \"grant\";",
                "grant_source",
            ),
            (
                "table retirée",
                "ALTER TABLE \"grant\" RENAME TO grant_hors_d_atteinte;",
                "ALTER TABLE grant_hors_d_atteinte RENAME TO \"grant\";",
                "grant_hors_d_atteinte",
            ),
        ]
    }

    /// Le refus attendu : `503`, corps d'erreur SCIM 2.0, cause nommée en tête — jamais un succès, jamais
    /// le `404` qu'un IdP lit comme « déjà retiré ».
    fn dsa_refus_scim(quoi: &str, statut: StatusCode, v: &Value, cause: &str) {
        assert_eq!(statut, StatusCode::SERVICE_UNAVAILABLE, "{quoi} : un geste que la base n'a pas pris est REFUSÉ : {v}");
        assert_eq!(v["schemas"], json!(["urn:ietf:params:scim:api:messages:2.0:Error"]), "{quoi} : corps d'erreur SCIM : {v}");
        assert_eq!(v["status"], json!("503"), "{quoi} : statut porté dans le corps (RFC 7644 §3.12) : {v}");
        let detail = v["detail"].as_str().unwrap_or("");
        assert!(detail.starts_with(cause), "{quoi} : la cause est nommée : {v}");
        assert!(!detail.contains("grant_"), "{quoi} : la cause du moteur ne part pas chez l'IdP : {v}");
    }

    fn dsa_cause_attendue(voie: &str, cause_d_ecriture: &'static str) -> &'static str {
        if voie == "table retirée" { CAUSE_SCIM_UTILISATEUR_ILLISIBLE } else { cause_d_ecriture }
    }

    // -------------------------------------------------------------------------------------
    // (1) PUT `active=false` et DELETE — les deux déprovisionnements.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, pour CHACUN des deux gestes et CHACUNE des deux voies : la réponse est un `503` SCIM
    /// (la vue : cause d'écriture ; la table retirée : cause de lecture, plus le `404` d'avant) ; le droit
    /// est TOUJOURS en base (relu dans la table déplacée) ; aucun `scim.user.deprovision` n'entre au
    /// journal de contrôle ; et, la panne levée, l'accès est TOUJOURS servi par `resolve_tenant_access` —
    /// la mesure de ce qu'un succès d'avant cachait. Contrôle positif : la même demande retire le droit,
    /// pose UN maillon, répond `200` (`active: false`) ou `204`, et l'accès tombe en `403`.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : remettre `let _ =` sur l'un des deux `DELETE` (un succès et un
    /// maillon sur un accès en place) ; remettre `.ok()` sur la lecture d'existence (un `404` pour un
    /// utilisateur présent, sous la table retirée).
    #[tokio::test]
    async fn dsa_un_deprovisionnement_que_la_base_refuse_est_refuse_et_l_acces_reste_dit() {
        for geste in ["PUT active=false", "DELETE"] {
            let nom = if geste == "DELETE" { "dsa-del" } else { "dsa-put" };
            let (st, _tmp, id) = dsa_etat_avec_membre(nom);
            let ctx = ScimCtx { tenant: DSA_TENANT.into() };
            let jouer = |st: AppState, ctx: ScimCtx, id: String| async move {
                if geste == "DELETE" {
                    tok_resp_json(scim_user_delete(State(st), Extension(ctx), Path(id)).await).await
                } else {
                    tok_resp_json(scim_user_replace(State(st), Extension(ctx), Path(id), Json(json!({ "active": false }))).await).await
                }
            };
            assert_eq!(dsa_acces(&st, nom), Ok("editor".to_string()), "fixture ({geste}) : l'accès est servi");

            for (voie, pose, remise, table) in dsa_voies() {
                dsa_executer(&st, pose);
                let (statut, v) = jouer(st.clone(), ctx.clone(), id.clone()).await;
                let droits = dsa_compter(&st, &format!("SELECT COUNT(*) FROM {table} WHERE user_id=?1"), &id);
                dsa_executer(&st, remise);
                dsa_refus_scim(&format!("{geste} ({voie})"), statut, &v, dsa_cause_attendue(voie, CAUSE_SCIM_RETRAIT_DES_DROITS_NON_ECRIT));
                assert_eq!(droits, 1, "ÉTAT RELU ({geste}, {voie}) : le droit est toujours en base");
                assert_eq!(dsa_maillons(&st, "scim.user.deprovision"), 0, "JOURNAL ({geste}, {voie}) : aucun déprovisionnement attesté");
                assert_eq!(dsa_acces(&st, nom), Ok("editor".to_string()), "ACCÈS ({geste}, {voie}) : toujours servi — le refus le dit");
            }

            // CONTRÔLE POSITIF — la même demande, base saine.
            let (statut, v) = jouer(st.clone(), ctx.clone(), id.clone()).await;
            if geste == "DELETE" {
                assert_eq!(statut, StatusCode::NO_CONTENT, "{geste} : 204 nu");
            } else {
                assert_eq!((statut, v["active"].clone()), (StatusCode::OK, json!(false)), "{geste} : {v}");
            }
            assert_eq!(dsa_compter(&st, "SELECT COUNT(*) FROM \"grant\" WHERE user_id=?1", &id), 0, "{geste} : le droit est retiré");
            assert_eq!(dsa_maillons(&st, "scim.user.deprovision"), 1, "{geste} : et le journal l'atteste une fois");
            assert_eq!(dsa_acces(&st, nom), Err(StatusCode::FORBIDDEN), "{geste} : l'accès tombe à la requête suivante");
        }
    }

    // -------------------------------------------------------------------------------------
    // (2) L'IDEMPOTENCE — un utilisateur déjà déprovisionné se dit par le 404 de la RFC 7644 §3.6.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : après un DELETE réussi, rejouer le DELETE et le PUT `active=false` rend `404` au
    /// format SCIM (RFC 7644 §3.6 : toute opération sur une ressource supprimée) — ni `503`, ni succès — et
    /// aucun second maillon n'entre.
    #[tokio::test]
    async fn dsa_un_utilisateur_deja_deprovisionne_rend_le_404_du_protocole_sans_trace() {
        let (st, _tmp, id) = dsa_etat_avec_membre("dsa-idem");
        let ctx = ScimCtx { tenant: DSA_TENANT.into() };
        let r = scim_user_delete(State(st.clone()), Extension(ctx.clone()), Path(id.clone())).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT, "fixture : premier déprovisionnement");
        let (statut, v) = tok_resp_json(scim_user_delete(State(st.clone()), Extension(ctx.clone()), Path(id.clone())).await).await;
        assert_eq!((statut, v["status"].clone()), (StatusCode::NOT_FOUND, json!("404")), "DELETE rejoué : {v}");
        let (statut, v) =
            tok_resp_json(scim_user_replace(State(st.clone()), Extension(ctx.clone()), Path(id.clone()), Json(json!({ "active": false }))).await).await;
        assert_eq!((statut, v["status"].clone()), (StatusCode::NOT_FOUND, json!("404")), "PUT rejoué : {v}");
        assert_eq!(dsa_maillons(&st, "scim.user.deprovision"), 1, "aucun second maillon");
    }

    // -------------------------------------------------------------------------------------
    // (3) PATCH /Groups — le retrait d'un membre.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, sous les deux voies : `op=remove` d'un membre `editor` rend un `503` SCIM, le droit
    /// est toujours en base, aucun `scim.group.patch` n'entre, l'accès est toujours servi. Contrôle positif :
    /// le membre retiré, `-1` au journal, l'accès tombe ; un second retrait (déjà absent) rend `200` et `-0`.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : remettre `.unwrap_or(0)` sur le `DELETE` — `200` et un maillon
    /// `-0 membres` sur un accès en place.
    #[tokio::test]
    async fn dsa_un_retrait_de_membre_que_la_base_refuse_est_refuse() {
        let (st, _tmp, id) = dsa_etat_avec_membre("dsa-grp");
        let ctx = ScimCtx { tenant: DSA_TENANT.into() };
        let corps = json!({ "Operations": [{ "op": "remove", "value": [{ "value": id }] }] });
        let jouer = |st: AppState| {
            let (ctx, corps) = (ctx.clone(), corps.clone());
            async move { tok_resp_json(scim_group_patch(State(st), Extension(ctx), Path("editor".to_string()), Json(corps)).await).await }
        };
        for (voie, pose, remise, table) in dsa_voies() {
            dsa_executer(&st, pose);
            let (statut, v) = jouer(st.clone()).await;
            let droits = dsa_compter(&st, &format!("SELECT COUNT(*) FROM {table} WHERE user_id=?1"), &id);
            dsa_executer(&st, remise);
            dsa_refus_scim(&format!("PATCH remove ({voie})"), statut, &v, CAUSE_SCIM_OPERATION_DE_GROUPE_NON_ECRITE);
            assert_eq!(droits, 1, "ÉTAT RELU ({voie}) : le membre porte toujours son droit");
            assert_eq!(dsa_maillons(&st, "scim.group.patch"), 0, "JOURNAL ({voie}) : aucun retrait attesté");
            assert_eq!(dsa_acces(&st, "dsa-grp"), Ok("editor".to_string()), "ACCÈS ({voie}) : toujours servi");
        }
        let (statut, v) = jouer(st.clone()).await;
        assert_eq!(statut, StatusCode::OK, "{v}");
        assert_eq!(dsa_compter(&st, "SELECT COUNT(*) FROM \"grant\" WHERE user_id=?1", &id), 0, "le membre est retiré");
        assert_eq!(dsa_acces(&st, "dsa-grp"), Err(StatusCode::FORBIDDEN), "l'accès tombe");
        let (statut, _v) = jouer(st.clone()).await;
        assert_eq!(statut, StatusCode::OK, "un membre déjà absent n'est pas un échec");
        let details: Vec<String> = {
            let c = dsa_plan(&st).conn.lock();
            let mut s = c.prepare("SELECT detail FROM control_ledger WHERE kind='scim.group.patch' ORDER BY id").expect("journal");
            s.query_map([], |r| r.get(0)).expect("journal").collect::<Result<_, _>>().expect("journal lisible")
        };
        assert_eq!(details, vec!["role 'editor' +0/-1 membres".to_string(), "role 'editor' +0/-0 membres".to_string()], "chaque retrait est compté tel qu'écrit");
    }

    // -------------------------------------------------------------------------------------
    // (4) LE PROVISIONNEMENT — un droit demandé n'est attesté que s'il est écrit.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, sous la vue temporaire : `POST /Users` avec un groupe et `PATCH /Groups op=add`
    /// rendent un `503` SCIM (droits demandés non écrits) ; aucun droit n'est posé ; ni
    /// `scim.user.provision` ni `scim.group.patch` n'entrent. Côté accès, l'échec est fail-closed (aucun
    /// accès n'est donné) : ce qui était faux était la TRACE et la réponse. Contrôle positif : les deux
    /// gestes posent le droit et l'attestent.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : remettre `let _ =` sur l'un des deux `INSERT` — `201`/`200` et un
    /// maillon qui nomme un droit absent.
    #[tokio::test]
    async fn dsa_un_droit_demande_que_la_base_refuse_n_est_ni_atteste_ni_confirme() {
        let (st, _tmp, _id) = dsa_etat_avec_membre("dsa-autre");
        let ctx = ScimCtx { tenant: DSA_TENANT.into() };
        let (pose, remise) = (dsa_voies()[0].1, dsa_voies()[0].2);
        let nouvel = ensure_platform_user(dsa_plan(&st), "dsa-ajout").expect("fixture");

        dsa_executer(&st, pose);
        let (statut, v) = tok_resp_json(
            scim_user_create(State(st.clone()), Extension(ctx.clone()), Json(json!({ "userName": "dsa-neuf", "groups": [{ "value": "viewer" }] }))).await,
        )
        .await;
        dsa_refus_scim("POST /Users", statut, &v, CAUSE_SCIM_DROITS_DEMANDES_NON_ECRITS);
        let (statut, v) = tok_resp_json(
            scim_group_patch(
                State(st.clone()),
                Extension(ctx.clone()),
                Path("viewer".to_string()),
                Json(json!({ "Operations": [{ "op": "add", "value": [{ "value": nouvel }] }] })),
            )
            .await,
        )
        .await;
        dsa_refus_scim("PATCH add", statut, &v, CAUSE_SCIM_OPERATION_DE_GROUPE_NON_ECRITE);
        dsa_executer(&st, remise);
        assert_eq!(dsa_compter(&st, "SELECT COUNT(*) FROM \"grant\" WHERE role=?1", "viewer"), 0, "ÉTAT RELU : aucun droit posé");
        assert_eq!((dsa_maillons(&st, "scim.user.provision"), dsa_maillons(&st, "scim.group.patch")), (0, 0), "JOURNAL : rien d'attesté");

        // CONTRÔLE POSITIF — base saine.
        let (statut, v) = tok_resp_json(
            scim_user_create(State(st.clone()), Extension(ctx.clone()), Json(json!({ "userName": "dsa-neuf", "groups": [{ "value": "viewer" }] }))).await,
        )
        .await;
        assert_eq!((statut, v["active"].clone()), (StatusCode::CREATED, json!(true)), "{v}");
        let (statut, _v) = tok_resp_json(
            scim_group_patch(
                State(st.clone()),
                Extension(ctx.clone()),
                Path("viewer".to_string()),
                Json(json!({ "Operations": [{ "op": "add", "value": [{ "value": nouvel }] }] })),
            )
            .await,
        )
        .await;
        assert_eq!(statut, StatusCode::OK);
        assert_eq!(dsa_compter(&st, "SELECT COUNT(*) FROM \"grant\" WHERE role=?1", "viewer"), 2, "les deux droits sont posés");
        assert_eq!((dsa_maillons(&st, "scim.user.provision"), dsa_maillons(&st, "scim.group.patch")), (1, 1), "et attestés");
    }

    // -------------------------------------------------------------------------------------
    // (5) UNE LECTURE RATÉE N'EST PAS UNE ABSENCE — les deux lectures qu'aucune voie ci-dessus n'atteint.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `"grant"` retirée, `GET /Users/{id}` rend un `503` SCIM (plus le `404` d'un
    /// utilisateur « introuvable ») ; `platform_user` retirée, `PATCH op=remove` rend un `503` SCIM (le
    /// membre illisible était SAUTÉ, et la demande répondait `200`), le droit reste, aucun
    /// `scim.group.patch` n'entre.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `Err(_) => 404` sur la lecture du GET ; `Err(_) => continue` sur
    /// la lecture du membre.
    #[tokio::test]
    async fn dsa_une_lecture_ratee_n_est_pas_servie_comme_une_absence() {
        let (st, _tmp, id) = dsa_etat_avec_membre("dsa-lec");
        let ctx = ScimCtx { tenant: DSA_TENANT.into() };

        dsa_executer(&st, dsa_voies()[1].1);
        let (statut, v) = tok_resp_json(scim_user_get(State(st.clone()), Extension(ctx.clone()), Path(id.clone())).await).await;
        dsa_executer(&st, dsa_voies()[1].2);
        dsa_refus_scim("GET (table des droits retirée)", statut, &v, CAUSE_SCIM_UTILISATEUR_ILLISIBLE);

        dsa_executer(&st, "ALTER TABLE platform_user RENAME TO platform_user_hors_d_atteinte;");
        let (statut, v) = tok_resp_json(
            scim_group_patch(
                State(st.clone()),
                Extension(ctx.clone()),
                Path("editor".to_string()),
                Json(json!({ "Operations": [{ "op": "remove", "value": [{ "value": id }] }] })),
            )
            .await,
        )
        .await;
        dsa_executer(&st, "ALTER TABLE platform_user_hors_d_atteinte RENAME TO platform_user;");
        dsa_refus_scim("PATCH remove (identités retirées)", statut, &v, CAUSE_SCIM_UTILISATEUR_ILLISIBLE);
        assert_eq!(dsa_compter(&st, "SELECT COUNT(*) FROM \"grant\" WHERE user_id=?1", &id), 1, "ÉTAT RELU : le droit est toujours là");
        assert_eq!(dsa_maillons(&st, "scim.group.patch"), 0, "JOURNAL : rien d'attesté");

        // CONTRÔLE POSITIF — base saine : le GET sert l'utilisateur.
        let (statut, v) = tok_resp_json(scim_user_get(State(st.clone()), Extension(ctx.clone()), Path(id.clone())).await).await;
        assert_eq!((statut, v["userName"].clone()), (StatusCode::OK, json!("dsa-lec")), "{v}");
    }
}
