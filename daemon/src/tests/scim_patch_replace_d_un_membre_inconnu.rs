// =====================================================================================
// `P10.21-v` (correction) — UN `replace` QUI VISE UNE IDENTITÉ INCONNUE REFUSE LA DEMANDE en `400 noTarget`.
//
// CE QUI MANQUAIT : les témoins `pgoj_`/`pgrt_`/`pgtt_` tenaient le `noTarget` pour `add` et `remove` seulement.
// Le contrôle d'existence sauté pour le seul geste Remplacer les laissait verts, et la table `grant` n'a pas de
// clé étrangère sur `user_id` : le mutant écrivait un droit fantôme et répondait `200`.
//
// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=V2_remplacer_non_verifie` (un `continue` pour Remplacer avant le
// `SELECT 1 FROM platform_user`) — `200`, la ligne fantôme écrite dans `grant`.
//
// CE QU'IL NE TIENT PAS : l'oracle d'existence cross-tenant (une identité connue de la plateforme mais sans droit
// dans ce tenant est une cible valide d'ajout, une inconnue rend `noTarget`) — reste de `P10.34-a` ; le RETRAIT d'un
// absent est un no-op identique (témoins `psoe_`).
// =====================================================================================
mod scim_patch_replace_d_un_membre_inconnu {
    use super::*;

    const PRMI_TENANT: &str = "prmi-t1";
    const PRMI_INCONNU: &str = "prmi-id-qui-n-existe-pas";

    fn prmi_etat() -> (AppState, crate::tmp_possede::TmpDb, String, String) {
        // anne admin, bert editor ; carl connu de la plateforme, sans droit (cible du contrôle positif).
        let (cp, tmp) = mk_test_control();
        cp.conn
            .lock()
            .execute(
                "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,'PRMI','','sans-base',?2,0)",
                params![PRMI_TENANT, now()],
            )
            .expect("fixture : tenant catalogué");
        let anne = ensure_platform_user(&cp, "prmi-anne").expect("fixture : utilisateur créé");
        let bert = ensure_platform_user(&cp, "prmi-bert").expect("fixture : utilisateur créé");
        let carl = ensure_platform_user(&cp, "prmi-carl").expect("fixture : utilisateur créé");
        for (id, role) in [(&anne, "admin"), (&bert, "editor")] {
            cp.conn
                .lock()
                .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3)", params![id, PRMI_TENANT, role])
                .expect("fixture : droit posé");
        }
        (tenant_test_state("admins", "editors", "supers", Some(cp)), tmp, carl, bert)
    }

    /// L'ÉTAT RELU EN BASE, SANS jointure sur `platform_user` (une ligne fantôme doit se voir) : `(user_id, rôle)`.
    fn prmi_droits_bruts(st: &AppState) -> Vec<(String, String)> {
        let c = st.tenants.control.as_ref().expect("fixture : mode 1").conn.lock();
        let mut s = c.prepare("SELECT user_id, role FROM \"grant\" WHERE tenant_id=?1 ORDER BY user_id, role").expect("fixture : droits");
        let lus = s
            .query_map(params![PRMI_TENANT], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .expect("fixture : droits")
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture : droits lisibles");
        lus
    }

    fn prmi_maillons(st: &AppState) -> i64 {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM control_ledger WHERE kind='scim.group.patch'", [], |r| r.get(0))
            .expect("fixture : journal lisible")
    }

    async fn prmi_patch(st: &AppState, corps: Value) -> (StatusCode, Value) {
        let ctx = ScimCtx { tenant: PRMI_TENANT.into() };
        tok_resp_json(scim_group_patch(State(st.clone()), Extension(ctx), Path("editor".to_string()), Json(corps)).await).await
    }

    /// CE QU'IL TIENT : `replace path members` avec un id inconnu (seul, puis à côté d'un connu) rend `400 noTarget`,
    /// AUCUN droit écrit (état brut relu inchangé, aucune ligne pour l'inconnu), rien d'attesté ; contrôle positif :
    /// le même `replace` d'un id connu rend `200` et l'état relu suit.
    #[tokio::test]
    async fn prmi_replace_d_un_membre_inconnu_refuse_sans_droit_fantome() {
        let (st, _tmp, carl, bert) = prmi_etat();
        let avant = prmi_droits_bruts(&st);
        let maillons = prmi_maillons(&st);
        for (quoi, valeurs) in [("inconnu seul", json!([{ "value": PRMI_INCONNU }])), ("inconnu à côté d'un connu", json!([{ "value": carl }, { "value": PRMI_INCONNU }]))] {
            let (statut, v) = prmi_patch(&st, json!({ "Operations": [{ "op": "replace", "path": "members", "value": valeurs }] })).await;
            assert_eq!(statut, StatusCode::BAD_REQUEST, "{quoi} : replace d'un inconnu refusé en 400 : {v}");
            assert_eq!(v["scimType"], json!("noTarget"), "{quoi} : scimType noTarget : {v}");
            let apres = prmi_droits_bruts(&st);
            assert!(!apres.iter().any(|(u, _)| u == PRMI_INCONNU), "{quoi} : AUCUN droit fantôme écrit : {apres:?}");
            assert_eq!(apres, avant, "{quoi} : ÉTAT RELU inchangé");
            assert_eq!(prmi_maillons(&st), maillons, "{quoi} : rien d'attesté");
        }
        // contrôle positif : un replace d'un id CONNU passe et remplace (carl entre, bert sort du rôle editor).
        let (statut, v) = prmi_patch(&st, json!({ "Operations": [{ "op": "replace", "path": "members", "value": [{ "value": carl }] }] })).await;
        assert_eq!(statut, StatusCode::OK, "replace d'un id connu : {v}");
        let apres = prmi_droits_bruts(&st);
        assert!(apres.contains(&(carl.clone(), "editor".to_string())), "carl porte editor : {apres:?}");
        assert!(!apres.contains(&(bert.clone(), "editor".to_string())), "bert ne porte plus editor : {apres:?}");
    }
}
