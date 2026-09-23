// =====================================================================================
// `P10.21-g` — UNE ÉCRITURE DU PLAN DE CONTRÔLE SE COMPTE AVANT QU'UNE LIGNE DE CONTRÔLE NE L'ATTESTE,
// ET UN ACCÈS OPÉRATEUR DONT LA TRACE MANQUE EST COMPTÉ.
//
// LE DÉFAUT, MESURÉ AVANT TOUT CORRECTIF. La bascule de suspension d'un tenant (`UPDATE tenant`), le
// retrait d'un droit (`DELETE FROM "grant"`), la pose d'un rôle composable (`INSERT … ON CONFLICT`) et le
// premier administrateur d'un tenant neuf (`INSERT OR REPLACE INTO "grant"`) s'écrivaient sous `let _ =` ;
// le retrait d'un rôle, sous `unwrap_or(0)`. Chacun posait ensuite au journal de contrôle une ligne qui
// ATTESTAIT l'écriture, et la réponse confirmait le geste : un tenant restait actif, un accès restait en
// place, un rôle n'existait pas, pendant que la trace tamper-evident disait le contraire. Le retrait de
// rôle refusé rendait « rôle introuvable » pour un rôle toujours en place.
//
// CE QUE LA GARDE DES ÉCRITURES AVALÉES NE VOYAIT PAS, ET POURQUOI — la raison n'était pas celle que la
// clé donne. Ajouter `control_ledger_append` à son vocabulaire de fait ne fait entrer AUCUN des cinq
// sites de la clé ; le seul site neuf est `scim.rs::scim_user_replace`. Trois des cinq (suspension,
// retrait de droit, pose de rôle) écrivent dans un bloc NU de verrou (`{ let conn = cp.conn.lock(); … }`)
// et posent leur ligne de contrôle APRÈS l'accolade fermante, dans le parent, où le critère de portée
// cessait de chercher ; le premier administrateur écrit dans un `if let` et la ligne vit dans l'ancêtre ;
// l'accès opérateur pose sa ligne AVANT l'écriture qu'il perd. La garde apprend qu'un bloc NU se
// traverse (il retombe toujours dans son parent) : les trois entrent, plus `role_delete` que l'énoncé ne
// nommait pas, plus deux gestes SCIM.
//
// LA VOIE D'ÉCHEC : une VUE TEMPORAIRE de même nom posée par-dessus la table renommée. La LECTURE
// préalable du geste (existence du tenant, du droit) passe ; seule l'ÉCRITURE tombe. Là où le geste n'a
// pas de lecture préalable, la TABLE RETIRÉE est jouée aussi.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ils éprouvent un objet non modifiable, pas une base réellement en
// lecture seule (le chemin refusé est le même) ; la table retirée n'est PAS jouée sur la suspension ni sur
// le retrait de droit, parce que leur lecture préalable tombe d'abord et rend « inconnu » — une lecture
// ratée servie comme une absence, hors de cette clé ; ils ne jugent pas ce que la console peint des refus
// neufs ; et l'événement de tenant (`audit_tenant_event`) avale toujours son `INSERT`.
// =====================================================================================
mod ecritures_de_controle_comptees {
    use super::*;

    fn ecc_plan_de_controle(st: &AppState, sql: &str) {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .execute_batch(sql)
            .unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ecc_compte_de_controle(st: &AppState, sql: &str) -> i64 {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .query_row(sql, [], |r| r.get(0))
            .unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn ecc_maillons(st: &AppState, genre: &str) -> i64 {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM control_ledger WHERE kind=?1", params![genre], |r| r.get(0))
            .expect("fixture : le journal de contrôle se lit")
    }

    fn ecc_super_admin() -> AuthUser {
        AuthUser {
            name: "op-ecc".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: true,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    /// La vue temporaire par-dessus la table renommée, et son retrait.
    fn ecc_vue_sur(table: &str) -> String {
        format!("ALTER TABLE \"{table}\" RENAME TO \"{table}_source\"; CREATE TEMP VIEW \"{table}\" AS SELECT * FROM \"{table}_source\";")
    }
    fn ecc_vue_retiree(table: &str) -> String {
        format!("DROP VIEW \"{table}\"; ALTER TABLE \"{table}_source\" RENAME TO \"{table}\";")
    }

    fn ecc_refus(quoi: &str, statut: u16, v: &Value, cause: &str) {
        assert_eq!(statut, 503, "{quoi} : l'écriture refusée est un REFUS, jamais un succès : {v}");
        let phrase = v.get("error").and_then(|x| x.as_str()).unwrap_or("");
        assert!(phrase.starts_with(cause), "{quoi} : le refus NOMME sa cause : {v}");
    }

    fn ecc_evenements_de_tenant(st: &AppState, tenant: &str, action: &str) -> i64 {
        let h = st.tenants.handle_for(tenant).expect("fixture : la base du tenant se résout");
        let c = h.lock();
        c.query_row(
            "SELECT COUNT(*) FROM event WHERE source='plume-tenant-admin' AND json_extract(fields,'$.action')=?1",
            params![action],
            |r| r.get(0),
        )
        .expect("fixture : les événements du tenant se lisent")
    }

    // -------------------------------------------------------------------------------------
    // (1) LA SUSPENSION — la bascule écrite, ou rien n'est posé nulle part.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sous la vue temporaire sur `tenant`, `POST /api/tenants/{id}/suspend` rend un 503
    /// nommé ; le tenant n'est PAS suspendu (relu dans la table source) ; aucun `tenant.suspend` n'entre
    /// au journal de contrôle ; aucun événement « suspendu » n'entre dans la base du tenant — celui-là
    /// était écrit AVANT la bascule. Contrôle positif : la vue retirée, la MÊME demande suspend, un
    /// maillon et un événement entrent ; la réactivation aussi.
    ///
    /// CE QU'IL NE TIENT PAS : la table retirée (la lecture d'existence tombe d'abord, hors clé).
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute("UPDATE tenant …")` — le geste
    /// repasse pour fait, un maillon `tenant.suspend` entre sur un tenant actif.
    #[tokio::test]
    async fn ecc_une_suspension_que_la_base_refuse_est_refusee_et_rien_ne_l_atteste() {
        let (st, _dir) = mk_mode1_state();
        let sa = ecc_super_admin();
        let (statut, v) =
            pb_json(tenant_create(State(st.clone()), Extension(sa.clone()), Json(json!({ "id": "ecc-susp", "name": "EccSusp" }))).await).await;
        assert_eq!(statut, 201, "{v}");

        ecc_plan_de_controle(&st, &ecc_vue_sur("tenant"));
        let (statut, v) = pb_json(tenant_suspend(State(st.clone()), Extension(sa.clone()), Path("ecc-susp".into())).await).await;
        ecc_refus("tenant.suspend", statut, &v, CAUSE_BASCULE_DE_SUSPENSION_NON_ECRITE);
        assert_eq!(
            ecc_compte_de_controle(&st, "SELECT suspended FROM tenant_source WHERE id='ecc-susp'"), 0,
            "ÉTAT RELU : le tenant n'est pas suspendu"
        );
        assert_eq!(ecc_maillons(&st, "tenant.suspend"), 0, "JOURNAL DE CONTRÔLE : aucune suspension n'est attestée");
        ecc_plan_de_controle(&st, &ecc_vue_retiree("tenant"));
        assert_eq!(
            ecc_evenements_de_tenant(&st, "ecc-susp", "tenant.suspend"), 0,
            "BASE DU TENANT : aucun événement « suspendu » sur une bascule refusée"
        );

        // CONTRÔLE POSITIF — la vue retirée, la même demande suspend, et les deux traces l'attestent.
        let (statut, v) = pb_json(tenant_suspend(State(st.clone()), Extension(sa.clone()), Path("ecc-susp".into())).await).await;
        assert_eq!((statut, v.get("suspended").and_then(|x| x.as_bool())), (200, Some(true)), "{v}");
        assert_eq!(ecc_compte_de_controle(&st, "SELECT suspended FROM tenant WHERE id='ecc-susp'"), 1, "le tenant est suspendu");
        assert_eq!(ecc_maillons(&st, "tenant.suspend"), 1, "et le journal l'atteste une fois");
        let (statut, v) = pb_json(tenant_unsuspend(State(st.clone()), Extension(sa.clone()), Path("ecc-susp".into())).await).await;
        assert_eq!(statut, 200, "{v}");
        assert_eq!(ecc_evenements_de_tenant(&st, "ecc-susp", "tenant.suspend"), 1, "l'événement de suspension, pris par la poignée d'avant la bascule");
        assert_eq!(ecc_evenements_de_tenant(&st, "ecc-susp", "tenant.unsuspend"), 1, "et celui de la réactivation");
    }

    // -------------------------------------------------------------------------------------
    // (2) LE RETRAIT DE DROIT — l'accès retiré, ou le refus le dit en tête.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sous la vue temporaire sur `"grant"`, `DELETE /api/tenants/{id}/grants/{user}`
    /// rend un 503 dont la phrase dit que l'ACCÈS EST TOUJOURS EN PLACE ; le droit existe encore (relu) ;
    /// aucun `grant.remove` au journal de contrôle ni dans la base du tenant. Contrôle positif : la vue
    /// retirée, la même demande retire (204 nu), le droit disparaît, un maillon entre.
    ///
    /// CE QU'IL NE TIENT PAS : la table retirée (la lecture préalable tombe d'abord, hors clé).
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ =` sur le `DELETE` — un 204 « retiré » est
    /// rendu sur un accès toujours en place, et le journal l'atteste.
    #[tokio::test]
    async fn ecc_un_retrait_de_droit_que_la_base_refuse_laisse_l_acces_et_le_dit() {
        let (st, _dir) = mk_mode1_state();
        let sa = ecc_super_admin();
        assert_eq!(
            tenant_create(State(st.clone()), Extension(sa.clone()), Json(json!({ "id": "ecc-droit", "name": "EccDroit" }))).await.status(),
            StatusCode::CREATED
        );
        let (statut, v) = pb_json(
            grant_set(State(st.clone()), Extension(sa.clone()), Path("ecc-droit".into()), Json(json!({ "user": "erin", "role": "editor" }))).await,
        )
        .await;
        assert_eq!(statut, 200, "fixture : {v}");

        ecc_plan_de_controle(&st, &ecc_vue_sur("grant"));
        let (statut, v) =
            pb_json(grant_delete(State(st.clone()), Extension(sa.clone()), Path(("ecc-droit".into(), "erin".into()))).await).await;
        ecc_refus("grant.remove", statut, &v, CAUSE_RETRAIT_DE_DROIT_NON_ECRIT);
        assert_eq!(count_grant(&st, "ecc-droit", "erin"), 1, "ÉTAT RELU : l'accès est toujours en place");
        assert_eq!(ecc_maillons(&st, "grant.remove"), 0, "JOURNAL DE CONTRÔLE : aucun retrait n'est attesté");
        assert_eq!(ecc_evenements_de_tenant(&st, "ecc-droit", "grant.remove"), 0, "BASE DU TENANT : aucun retrait n'y est dit");

        // CONTRÔLE POSITIF — la vue retirée, le même retrait passe, 204 nu, et il est attesté.
        ecc_plan_de_controle(&st, &ecc_vue_retiree("grant"));
        let r = grant_delete(State(st.clone()), Extension(sa.clone()), Path(("ecc-droit".into(), "erin".into()))).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT, "le chemin nominal reste un 204 sans corps");
        assert_eq!(count_grant(&st, "ecc-droit", "erin"), 0, "l'accès est retiré");
        assert_eq!(ecc_maillons(&st, "grant.remove"), 1, "et le journal l'atteste");
        assert_eq!(ecc_evenements_de_tenant(&st, "ecc-droit", "grant.remove"), 1, "et le tenant le lit");
    }

    // -------------------------------------------------------------------------------------
    // (3) LES RÔLES COMPOSABLES — pose et retrait, deux voies d'échec chacun.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sous la vue temporaire sur `role_def`, puis sous la table RETIRÉE, `POST
    /// /api/roles` rend un 503 `CAUSE_ROLE_NON_ECRIT` et `DELETE /api/roles/{name}` un 503
    /// `CAUSE_RETRAIT_DE_ROLE_NON_ECRIT` — plus le 404 « rôle introuvable » d'avant ; aucun `role.upsert`
    /// ni `role.delete` au journal de contrôle ; le rôle existant garde sa définition (relue). Contrôle
    /// positif : la table remise, la pose et le retrait passent et entrent au journal ; un rôle absent
    /// rend toujours son 404.
    ///
    /// CE QU'IL NE TIENT PAS : le cache des rôles n'est pas relu (il n'est pas rechargé sur un refus).
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ =` sur l'`INSERT`, ou `unwrap_or(0)` sur le
    /// `DELETE` — le premier rend `ok` et atteste un rôle absent, le second rend un 404 pour un rôle
    /// présent.
    #[tokio::test]
    async fn ecc_un_role_que_la_base_refuse_n_est_ni_servi_ni_atteste() {
        let _roles = CUSTOM_ROLES_TEST_LOCK.lock();
        let (st, _dir) = mk_mode1_state();
        let sa = ecc_super_admin();
        let (statut, v) = pb_json(
            role_create(State(st.clone()), Extension(sa.clone()), Json(json!({ "name": "ecc-role", "base_role": "viewer" }))).await,
        )
        .await;
        assert_eq!(statut, 200, "fixture : {v}");
        let (poses, retraits) = (ecc_maillons(&st, "role.upsert"), ecc_maillons(&st, "role.delete"));

        for (voie, pose, remise) in [
            ("vue temporaire", ecc_vue_sur("role_def"), ecc_vue_retiree("role_def")),
            (
                "table retirée",
                "ALTER TABLE role_def RENAME TO role_def_hors_d_atteinte;".to_string(),
                "ALTER TABLE role_def_hors_d_atteinte RENAME TO role_def;".to_string(),
            ),
        ] {
            ecc_plan_de_controle(&st, &pose);
            let (statut, v) = pb_json(
                role_create(State(st.clone()), Extension(sa.clone()), Json(json!({ "name": "ecc-role", "base_role": "editor" }))).await,
            )
            .await;
            ecc_refus(&format!("role.upsert ({voie})"), statut, &v, CAUSE_ROLE_NON_ECRIT);
            let (statut, v) = pb_json(role_delete(State(st.clone()), Extension(sa.clone()), Path("ecc-role".into())).await).await;
            ecc_refus(&format!("role.delete ({voie})"), statut, &v, CAUSE_RETRAIT_DE_ROLE_NON_ECRIT);
            ecc_plan_de_controle(&st, &remise);
            assert_eq!(
                ecc_compte_de_controle(&st, "SELECT COUNT(*) FROM role_def WHERE name='ecc-role' AND base_role='viewer'"), 1,
                "ÉTAT RELU ({voie}) : le rôle est toujours là, avec sa définition d'avant"
            );
            assert_eq!(
                (ecc_maillons(&st, "role.upsert"), ecc_maillons(&st, "role.delete")), (poses, retraits),
                "JOURNAL DE CONTRÔLE ({voie}) : ni pose ni retrait attestés"
            );
        }

        // CONTRÔLE POSITIF — la table remise, pose et retrait passent, un absent reste un 404.
        let (statut, v) = pb_json(
            role_create(State(st.clone()), Extension(sa.clone()), Json(json!({ "name": "ecc-role", "base_role": "editor" }))).await,
        )
        .await;
        assert_eq!(statut, 200, "{v}");
        let (statut, v) = pb_json(role_delete(State(st.clone()), Extension(sa.clone()), Path("ecc-role".into())).await).await;
        assert_eq!(statut, 200, "{v}");
        assert_eq!((ecc_maillons(&st, "role.upsert"), ecc_maillons(&st, "role.delete")), (poses + 1, retraits + 1));
        let (statut, _v) = pb_json(role_delete(State(st.clone()), Extension(sa.clone()), Path("ecc-role".into())).await).await;
        assert_eq!(statut, 404, "« introuvable » reste l'absence, et seulement elle");
    }

    // -------------------------------------------------------------------------------------
    // (4) LE PREMIER ADMINISTRATEUR — le tenant créé, l'administrateur demandé nommé seulement s'il est posé.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sous la vue temporaire sur `"grant"`, puis sous la table retirée, `POST
    /// /api/tenants` avec `admin` rend 201 (le tenant EXISTE), `first_admin: null` et l'aveu
    /// `premier_administrateur_non_pose` ; aucun droit n'est écrit ; la ligne `tenant.create` du journal
    /// de contrôle ne nomme aucun administrateur et porte `first_admin_non_pose`. Un nom invalide suit la
    /// même voie (il était ignoré sans un mot). Contrôle positif : la table remise, l'administrateur est
    /// posé, nommé, sans aveu, et le détail de contrôle ne porte pas la clé neuve.
    ///
    /// CE QU'IL NE TIENT PAS : ce que la console peint de l'aveu.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ =` sur l'`INSERT OR REPLACE` suivi de
    /// `Pose(…)` — la réponse et le journal nomment un administrateur qui n'existe pas.
    #[tokio::test]
    async fn ecc_un_premier_administrateur_que_la_base_refuse_n_est_pas_nomme() {
        let (st, _dir) = mk_mode1_state();
        let sa = ecc_super_admin();
        let detail_de = |st: &AppState, tenant: &str| -> Value {
            let texte: String = st.tenants.control.as_ref().expect("mode 1").conn.lock()
                .query_row("SELECT detail FROM control_ledger WHERE kind='tenant.create' AND tenant=?1", params![tenant], |r| r.get(0))
                .expect("la création est au journal de contrôle");
            serde_json::from_str(&texte).expect("le détail est du JSON")
        };
        for (voie, pose, remise, tenant) in [
            ("vue temporaire", ecc_vue_sur("grant"), ecc_vue_retiree("grant"), "ecc-adm-vue"),
            (
                "table retirée",
                "ALTER TABLE \"grant\" RENAME TO grant_hors_d_atteinte;".to_string(),
                "ALTER TABLE grant_hors_d_atteinte RENAME TO \"grant\";".to_string(),
                "ecc-adm-sans",
            ),
        ] {
            ecc_plan_de_controle(&st, &pose);
            let (statut, v) = pb_json(
                tenant_create(State(st.clone()), Extension(sa.clone()), Json(json!({ "id": tenant, "name": tenant, "admin": "frank" }))).await,
            )
            .await;
            ecc_plan_de_controle(&st, &remise);
            assert_eq!(statut, 201, "{voie} : le tenant EST créé : {v}");
            assert!(v.get("first_admin").is_some_and(Value::is_null), "{voie} : aucun administrateur n'est nommé : {v}");
            let aveu = v.get(CLE_PREMIER_ADMINISTRATEUR_NON_POSE).and_then(|x| x.as_str()).unwrap_or("");
            assert!(aveu.starts_with(CAUSE_PREMIER_ADMINISTRATEUR_NON_POSE), "{voie} : la réponse DIT le manque : {v}");
            assert_eq!(count_grant(&st, tenant, "frank"), 0, "ÉTAT RELU ({voie}) : aucun droit n'est écrit");
            let detail = detail_de(&st, tenant);
            assert!(detail["first_admin"].is_null(), "JOURNAL DE CONTRÔLE ({voie}) : aucun administrateur attesté : {detail}");
            assert_eq!(detail["first_admin_non_pose"], json!(true), "et le manque y est écrit : {detail}");
        }

        // UN NOM INVALIDE — ignoré sans un mot jusque-là, il suit la même voie.
        let (statut, v) = pb_json(
            tenant_create(State(st.clone()), Extension(sa.clone()), Json(json!({ "id": "ecc-adm-nom", "name": "n", "admin": "pas un nom" }))).await,
        )
        .await;
        assert_eq!(statut, 201, "{v}");
        assert!(v.get(CLE_PREMIER_ADMINISTRATEUR_NON_POSE).is_some(), "le nom invalide est dit : {v}");

        // CONTRÔLE POSITIF — la table en place : posé, nommé, sans aveu, détail de contrôle inchangé.
        let (statut, v) = pb_json(
            tenant_create(State(st.clone()), Extension(sa.clone()), Json(json!({ "id": "ecc-adm-ok", "name": "ok", "admin": "frank" }))).await,
        )
        .await;
        assert_eq!(statut, 201, "{v}");
        assert_eq!(v.get("first_admin").and_then(|x| x.as_str()), Some("frank"), "{v}");
        assert!(v.get(CLE_PREMIER_ADMINISTRATEUR_NON_POSE).is_none(), "le chemin nominal n'avoue rien : {v}");
        assert_eq!(count_grant(&st, "ecc-adm-ok", "frank"), 1, "le droit est écrit");
        let detail = detail_de(&st, "ecc-adm-ok");
        assert_eq!(detail["first_admin"], json!("frank"));
        assert!(detail.get("first_admin_non_pose").is_none(), "le détail nominal est celui d'avant : {detail}");
    }

    // -------------------------------------------------------------------------------------
    // (5) L'ACCÈS OPÉRATEUR CROSS-TENANT — l'accès a lieu, la perte de sa trace est COMPTÉE.
    // -------------------------------------------------------------------------------------

    fn ecc_perdus(trace: &str) -> u64 {
        crate::metrics::acces_operateur_non_trace_de(trace).map(|(n, _)| n).unwrap_or(0)
    }

    /// CE QU'IL TIENT, trace par trace :
    ///  - l'ÉVÉNEMENT du tenant visité, sous la vue temporaire sur `event` : une lecture cross-tenant monte
    ///    `tenant.plume-operator-access.read`, aucune ligne n'entre ; une SECONDE lecture dans la fenêtre
    ///    de debounce RÉESSAIE (compteur +1 encore) ; la vue retirée, une troisième lecture ÉCRIT
    ///    l'événement — sans l'oubli de la fenêtre, elle aurait été débouncée et le tenant n'aurait rien vu ;
    ///  - le même événement sous la table retirée, en break-glass : `….write` monte ;
    ///  - le MAILLON de contrôle, sous la vue temporaire sur `control_ledger` : `control_ledger.superadmin.write`
    ///    monte, et l'événement du tenant, lui, est écrit ;
    ///  - aucune cause publiée ne porte le compte, le tenant ni la raison ; l'exposition est servie par
    ///    `/api/metrics` et inscrite pour Prometheus.
    /// Contrôle positif en tête : sur des bases saines, les deux traces entrent et aucun compteur ne bouge.
    ///
    /// CE QU'IL NE TIENT PAS : le compteur est global au processus (égalités sous l'hypothèse qu'aucun
    /// autre témoin ne perd une trace d'accès opérateur, aucun ne le fait) ; le refus d'un accès dont
    /// AUCUNE trace n'entre est tenu ailleurs (`acces_operateur_sans_trace_refuse.rs`, `P10.21-p`) — ici
    /// chaque accès garde au moins une trace, et l'issue le dit.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ =` sur l'`INSERT` de l'événement — la perte
    /// redevient muette ; ou retirer l'oubli de la fenêtre — la troisième lecture n'écrit rien.
    #[test]
    fn ecc_un_acces_operateur_dont_la_trace_manque_est_compte_sans_identite() {
        let _verrou = acces_operateur_sans_trace_refuse::VERROU_DES_TRACES_D_ACCES_OPERATEUR.lock();
        let (cp, _cptmp) = mk_test_control();
        let chemin = mk_tmp_path("ecc-visite.db");
        {
            let c = cp.conn.lock();
            c.execute(
                "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('ecc-visite','V','',?1,?2,0)",
                params![chemin.as_str(), now()],
            )
            .expect("fixture : tenant visité catalogué");
        }
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
        let base_du_tenant = st.tenants.handle_for("ecc-visite").expect("fixture : la base du tenant se résout");
        {
            let c = base_du_tenant.lock();
            c.execute_batch(include_str!("../../../db/schema.sql")).expect("fixture : schéma");
            let _ = migrate(&c);
        }
        let evenements = |table: &str| -> i64 {
            base_du_tenant
                .lock()
                .query_row(&format!("SELECT COUNT(*) FROM {table} WHERE source='plume-operator-access'"), [], |r| r.get(0))
                .expect("fixture : les événements se lisent")
        };
        let traces = [
            TRACE_OPERATEUR_CONTROLE_LECTURE,
            TRACE_OPERATEUR_CONTROLE_ECRITURE,
            TRACE_OPERATEUR_TENANT_LECTURE,
            TRACE_OPERATEUR_TENANT_ECRITURE,
        ];
        let avant: Vec<u64> = traces.iter().map(|t| ecc_perdus(t)).collect();
        let delta = |i: usize| ecc_perdus(traces[i]) - avant[i];

        // CONTRÔLE POSITIF — bases saines : un maillon et un événement, aucun compteur ne bouge. Un autre
        // opérateur que celui des lectures ci-dessous : un break-glass arme la fenêtre de debounce de son
        // couple, et la première lecture de ce couple serait débouncée sans rien tenter.
        assert!(matches!(emit_operator_access(&st, "op-ecc-positif", "ecc-visite", true, Some("incident-ecc")), TraceDAccesOperateur::AuMoinsUneTrace), "une trace au moins porte cet accès");
        assert_eq!(evenements("event"), 1, "l'événement break-glass est écrit");
        assert_eq!(ecc_maillons(&st, "superadmin.write"), 1, "le maillon est écrit");
        assert_eq!((0..4).map(delta).sum::<u64>(), 0, "une trace écrite n'est pas comptée comme perdue");

        // L'ÉVÉNEMENT DU TENANT, VUE TEMPORAIRE — lecture refusée, puis réessai dans la fenêtre.
        base_du_tenant.lock().execute_batch(&ecc_vue_sur("event")).expect("fixture : vue posée");
        assert!(matches!(emit_operator_access(&st, "op-ecc", "ecc-visite", false, None), TraceDAccesOperateur::AuMoinsUneTrace), "une trace au moins porte cet accès");
        assert_eq!(delta(2), 1, "la lecture dont l'événement est refusé est COMPTÉE");
        assert!(matches!(emit_operator_access(&st, "op-ecc", "ecc-visite", false, None), TraceDAccesOperateur::AuMoinsUneTrace), "une trace au moins porte cet accès");
        assert_eq!(delta(2), 2, "la fenêtre de debounce est OUBLIÉE sur une perte : la lecture suivante réessaie");
        assert_eq!(evenements("event_source"), 1, "AUCUNE ligne de lecture n'est entrée");
        base_du_tenant.lock().execute_batch(&ecc_vue_retiree("event")).expect("fixture : vue retirée");
        assert!(matches!(emit_operator_access(&st, "op-ecc", "ecc-visite", false, None), TraceDAccesOperateur::AuMoinsUneTrace), "une trace au moins porte cet accès");
        assert_eq!(evenements("event"), 2, "la lecture suivante ÉCRIT : le tenant voit la consultation");
        assert_eq!(delta(2), 2, "et rien de plus n'est compté");
        assert_eq!(ecc_maillons(&st, "superadmin.read"), 3, "le journal de contrôle, lui, a pris les trois lectures");

        // L'ÉVÉNEMENT DU TENANT, TABLE RETIRÉE — break-glass.
        base_du_tenant.lock().execute_batch("ALTER TABLE event RENAME TO event_hors_d_atteinte;").expect("fixture : table retirée");
        assert!(matches!(emit_operator_access(&st, "op-ecc", "ecc-visite", true, Some("incident-ecc")), TraceDAccesOperateur::AuMoinsUneTrace), "une trace au moins porte cet accès");
        assert_eq!(delta(3), 1, "le break-glass dont l'événement est perdu est COMPTÉ");
        base_du_tenant.lock().execute_batch("ALTER TABLE event_hors_d_atteinte RENAME TO event;").expect("fixture : table remise");

        // LE MAILLON DE CONTRÔLE, VUE TEMPORAIRE — break-glass : le maillon manque, l'événement entre.
        ecc_plan_de_controle(&st, &ecc_vue_sur("control_ledger"));
        assert!(matches!(emit_operator_access(&st, "op-ecc", "ecc-visite", true, Some("incident-ecc")), TraceDAccesOperateur::AuMoinsUneTrace), "une trace au moins porte cet accès");
        ecc_plan_de_controle(&st, &ecc_vue_retiree("control_ledger"));
        assert_eq!(delta(1), 1, "le maillon break-glass non inscrit est COMPTÉ");
        assert_eq!(ecc_maillons(&st, "superadmin.write"), 2, "fixture : deux maillons sur trois break-glass");
        assert_eq!(evenements("event"), 3, "l'événement du tenant, lui, est écrit");
        assert_eq!(delta(0), 0, "aucune lecture n'a perdu son maillon");

        for trace in &traces[1..] {
            let (_, cause) = crate::metrics::acces_operateur_non_trace_de(trace).expect("la trace est publiée");
            assert!(!cause.is_empty(), "{trace} : la cause du moteur est portée");
            assert!(
                !cause.contains("op-ecc") && !cause.contains("ecc-visite") && !cause.contains("incident-ecc"),
                "{trace} : l'aveu ne porte NI le compte, NI le tenant, NI la raison : {cause}"
            );
        }

        // L'EXPOSITION — `/api/metrics` sert le total et la ventilation ; la série Prometheus est inscrite.
        let m = crate::gather_json(&st.db.lock(), "/spool", "ecc-acces", &crate::handlers::system::VersionDeSchema::Lue(0), 80);
        assert!(m["ingest"]["acces_operateur_non_traces_total"].as_u64().unwrap_or(0) >= 4, "le total est publié : {}", m["ingest"]);
        assert!(
            m["ingest"]["acces_operateur_non_traces"][TRACE_OPERATEUR_TENANT_LECTURE]["n"].as_u64().unwrap_or(0) >= 2,
            "la ventilation par trace est publiée : {}", m["ingest"]
        );
        assert!(
            include_str!("../metrics.rs").contains("\"plume_acces_operateur_non_traces_total\""),
            "la série Prometheus est inscrite"
        );
    }
}
