// =====================================================================================
// `P10.20-b` (quatre sites) — UN PLAFOND NON LU N'EST PAS UN PLAFOND À ZÉRO.
//
// Quatre lectures de ligne unique faisaient disparaître une garde quand la lecture ratait :
//  * `incidents.rs::create_custom_runbook` et `clone_runbook` — `COUNT(*) … .unwrap_or(0)` : le plafond anti-abus
//    `RUNBOOK_MAX_CUSTOM` cessait d'exister, et l'écriture suivait ;
//  * `saved_queries.rs::count_for_owner` — même forme : le plafond per-user des requêtes sauvegardées s'effaçait ;
//  * `datamodels.rs::object_delete` — `has_children … .unwrap_or(false)` : la suppression d'un objet PARENT passait
//    la garde qui protège la hiérarchie.
//
// LE GESTE QUI FAIT RATER UNE SEULE LECTURE : un autorisateur SQLite posé sur l'écrivain partagé refuse la lecture
// d'UNE colonne (`runbook.managed`, `saved_query.owner`, `data_model_object.parent_id`) — celle que seule la sonde
// du plafond lit. L'écriture qui suit (INSERT, DELETE par `id`) ne lit pas cette colonne : sur la forme d'avant, elle
// passait. Chaque témoin juge le refus (503, cause nommée), l'absence d'écriture relue après levée de l'autorisateur,
// puis un contrôle POSITIF : levé, la garde réelle répond (400 quota/parent, 409 plafond).
//
// LES MUTATIONS QUI LES FONT ROUGIR (`VERIF_MUT`, sous `cfg!(test)`, retirées avant le commit) : `b7_create`,
// `b7_clone` (le compte de runbooks retombe à 0), `b7_statut` (le refus du plafond non lu rendu en 400), `b7_sq`
// (le compte de requêtes retombe à 0), `b7_dm` (la sonde d'enfants retombe à `false`).
//
// CE QU'ILS NE TIENNENT PAS : les autres lectures absorbées de `P10.20-b` (dont `attach_runbook`, `P10.22-q`, et
// `unique_custom_key`, appelée sur le même chemin) ; le mode multi-tenant ; la face console (aucun module de `web/`
// ne lit encore ces causes) ; une lecture qui rate par verrou ou E/S réelle plutôt que par autorisateur.
// =====================================================================================
mod plafond_non_lu_n_est_pas_un_plafond_a_zero {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// Refuse sur l'écrivain partagé la lecture d'UNE colonne d'UNE table ; tout le reste passe.
    fn pnl_refuser_la_lecture(st: &AppState, table: &'static str, colonne: &'static str) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == table && column_name == colonne => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn pnl_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    async fn pnl_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
        (statut, corps)
    }

    fn pnl_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn pnl_erreur(corps: &Value) -> String {
        corps["error"].as_str().unwrap_or_default().to_string()
    }

    /// Remplit le quota de runbooks custom (`RUNBOOK_MAX_CUSTOM` = 200) ; rend l'id du premier.
    fn pnl_remplir_les_runbooks(st: &AppState) -> i64 {
        let c = st.db.lock();
        let mut premier = 0;
        for i in 0..200 {
            c.execute(
                "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES(?1,?2,'*','','',0,1,0)",
                params![format!("custom-pnl-{i}"), format!("pnl-{i}")],
            ).expect("fixture : runbook custom écrit");
            if i == 0 { premier = c.last_insert_rowid(); }
        }
        premier
    }

    const PNL_CUSTOMS: &str = "SELECT COUNT(*) FROM runbook WHERE managed=0";

    /// CE QU'IL TIENT : quota de runbooks custom atteint et compte NON LU -> la création rend 503 avec
    /// `CAUSE_QUOTA_DE_RUNBOOKS_NON_LU` en tête, et aucun runbook n'est écrit ; levé, le quota répond 400.
    /// MUTATIONS : `b7_create`, `b7_statut`.
    #[tokio::test]
    async fn pnl_creation_de_runbook_plafond_non_lu_refuse_en_503() {
        let (st, _p) = sp_state("pnl-rb-creation");
        let adm = sp_au("adm", "admin");
        pnl_remplir_les_runbooks(&st);
        let corps_rb = json!({ "name": "pnl-de-trop", "match_kind": "*", "steps": [{ "phase": "triage", "title": "regarder", "step_kind": "manual" }] });

        pnl_refuser_la_lecture(&st, "runbook", "managed");
        let r = runbook_create(State(st.clone()), Extension(adm.clone()), Json(corps_rb.clone())).await;
        pnl_lever(&st);
        let (statut, corps) = pnl_corps(r).await;
        assert_eq!(statut, 503, "plafond non lu : 503, jamais un plafond à zéro : {corps}");
        assert!(pnl_erreur(&corps).starts_with(CAUSE_QUOTA_DE_RUNBOOKS_NON_LU), "cause nommée : {corps}");
        assert_eq!(pnl_compte(&st, PNL_CUSTOMS), 200, "aucun runbook écrit au-delà du plafond");

        let (statut, corps) = pnl_corps(runbook_create(State(st.clone()), Extension(adm.clone()), Json(corps_rb)).await).await;
        assert_eq!(statut, 400, "contrôle positif : levé, le quota répond : {corps}");
        assert!(pnl_erreur(&corps).contains("quota de runbooks custom atteint"), "{corps}");
    }

    /// CE QU'IL TIENT : même jugement pour le clonage. MUTATIONS : `b7_clone`, `b7_statut`.
    #[tokio::test]
    async fn pnl_clonage_de_runbook_plafond_non_lu_refuse_en_503() {
        let (st, _p) = sp_state("pnl-rb-clonage");
        let adm = sp_au("adm", "admin");
        let source = pnl_remplir_les_runbooks(&st);

        pnl_refuser_la_lecture(&st, "runbook", "managed");
        let r = runbook_clone_handler(State(st.clone()), Extension(adm.clone()), Path(source), Json(json!({ "name": "pnl-copie" }))).await;
        pnl_lever(&st);
        let (statut, corps) = pnl_corps(r).await;
        assert_eq!(statut, 503, "plafond non lu : 503 : {corps}");
        assert!(pnl_erreur(&corps).starts_with(CAUSE_QUOTA_DE_RUNBOOKS_NON_LU), "cause nommée : {corps}");
        assert_eq!(pnl_compte(&st, PNL_CUSTOMS), 200, "aucune copie écrite au-delà du plafond");

        let r = runbook_clone_handler(State(st.clone()), Extension(adm.clone()), Path(source), Json(json!({ "name": "pnl-copie" }))).await;
        let (statut, corps) = pnl_corps(r).await;
        assert_eq!(statut, 400, "contrôle positif : levé, le quota répond : {corps}");
        assert!(pnl_erreur(&corps).contains("quota de runbooks custom atteint"), "{corps}");
    }

    /// CE QU'IL TIENT : le cœur garde sa signature `Result<i64, String>` et rend la cause en tête, sans rien écrire.
    /// MUTATIONS : `b7_create`, `b7_clone`.
    #[test]
    fn pnl_coeurs_de_runbook_rendent_la_cause_sans_ecrire() {
        let (st, _p) = sp_state("pnl-rb-coeurs");
        let source = pnl_remplir_les_runbooks(&st);
        pnl_refuser_la_lecture(&st, "runbook", "managed");
        let (cree, clone): (Result<i64, String>, Result<i64, String>) = {
            let c = st.db.lock();
            (create_custom_runbook(&c, "pnl-coeur", "*", "", "", &[], true), clone_runbook(&c, source, Some("pnl-coeur-copie")))
        };
        pnl_lever(&st);
        assert!(matches!(&cree, Err(e) if e.starts_with(CAUSE_QUOTA_DE_RUNBOOKS_NON_LU)), "création : {cree:?}");
        assert!(matches!(&clone, Err(e) if e.starts_with(CAUSE_QUOTA_DE_RUNBOOKS_NON_LU)), "clonage : {clone:?}");
        assert_eq!(pnl_compte(&st, PNL_CUSTOMS), 200, "rien d'écrit");
    }

    /// CE QU'IL TIENT : plafond per-user atteint et compte NON LU -> 503 avec
    /// `CAUSE_PLAFOND_DE_REQUETES_SAUVEGARDEES_NON_LU`, aucune requête écrite ; levé, le plafond répond 409.
    /// MUTATION : `b7_sq`.
    #[tokio::test]
    async fn pnl_requete_sauvegardee_plafond_non_lu_refuse_en_503() {
        let (st, _p) = sp_state("pnl-sq");
        let alice = sp_au("alice", "editor");
        {
            let c = st.db.lock();
            for i in 0..crate::handlers::saved_queries::SAVED_QUERY_MAX_PER_USER {
                c.execute("INSERT INTO saved_query(owner,name,soql) VALUES('alice',?1,'search *')", params![format!("pnl-{i}")])
                    .expect("fixture : requête écrite");
            }
        }
        let a_alice = "SELECT COUNT(*) FROM saved_query WHERE owner='alice'";

        pnl_refuser_la_lecture(&st, "saved_query", "owner");
        let r = saved_query_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "pnl-de-trop", "soql": "search *" }))).await;
        pnl_lever(&st);
        let (statut, corps) = pnl_corps(r).await;
        assert_eq!(statut, 503, "plafond non lu : 503 : {corps}");
        assert_eq!(corps["error"], json!(crate::handlers::saved_queries::CAUSE_PLAFOND_DE_REQUETES_SAUVEGARDEES_NON_LU), "cause nommée : {corps}");
        assert_eq!(pnl_compte(&st, a_alice), 200, "aucune requête écrite au-delà du plafond");

        let r = saved_query_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "pnl-de-trop", "soql": "search *" }))).await;
        let (statut, corps) = pnl_corps(r).await;
        assert_eq!(statut, 409, "contrôle positif : levé, le plafond répond : {corps}");
    }

    /// CE QU'IL TIENT : sonde d'enfants NON LUE -> la suppression d'un objet parent rend 503 avec
    /// `CAUSE_ENFANTS_DE_L_OBJET_NON_LUS`, et le parent est toujours là ; levé, la garde de hiérarchie répond 400.
    /// MUTATION : `b7_dm`.
    #[tokio::test]
    async fn pnl_suppression_d_objet_sonde_d_enfants_non_lue_refuse_en_503() {
        let (st, _p) = sp_state("pnl-dm");
        let adm = sp_au("adm", "admin");
        let parent = {
            let c = st.db.lock();
            c.execute("INSERT INTO data_model_object(model_id,name) VALUES(1,'pnl-parent')", []).expect("fixture : parent");
            let parent = c.last_insert_rowid();
            c.execute("INSERT INTO data_model_object(model_id,name,parent_id) VALUES(1,'pnl-enfant',?1)", params![parent]).expect("fixture : enfant");
            parent
        };
        let present = format!("SELECT COUNT(*) FROM data_model_object WHERE id={parent}");

        pnl_refuser_la_lecture(&st, "data_model_object", "parent_id");
        let r = object_delete(State(st.clone()), Extension(adm.clone()), Path(parent)).await;
        pnl_lever(&st);
        let (statut, corps) = pnl_corps(r).await;
        assert_eq!(statut, 503, "sonde non lue : 503, jamais « aucun enfant » : {corps}");
        assert!(pnl_erreur(&corps).starts_with(CAUSE_ENFANTS_DE_L_OBJET_NON_LUS), "cause nommée : {corps}");
        assert_eq!(pnl_compte(&st, &present), 1, "le parent est toujours là");

        let (statut, corps) = pnl_corps(object_delete(State(st.clone()), Extension(adm.clone()), Path(parent)).await).await;
        assert_eq!(statut, 400, "contrôle positif : levé, la garde de hiérarchie répond : {corps}");
        assert_eq!(pnl_compte(&st, &present), 1, "le parent est toujours là");
    }
}
