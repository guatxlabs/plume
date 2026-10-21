// =====================================================================================
// `P10.25-r` (volet servi) — `/api/tokens` DIT L'AUTEUR D'UN JETON ET LA MARQUE DE SA SUPPRESSION.
//
// LE DÉFAUT, MESURÉ AVANT LE CORRECTIF : `tokens_list` lisait `id,name,kind,host,created,last_used,role,connector_id`
// — ni `created_by` ni `created_by_deleted_at` (colonnes v123, `P10.24-w`). Un jeton conservé au secret connu d'un
// compte supprimé était donc indiscernable, dans l'inventaire, d'un jeton ordinaire.
//
// DÉCISION (la plus sûre) : on SERT les deux champs ; rien n'est révoqué, aucun droit ne change. `created_by` NULL =
// auteur non établi (ligne de commande, jeton antérieur sans trace rattachable).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le relevé en production des jetons laissés avant v123 ; la face console
// (`web/`, autre session) ; le mode multi-tenant (la route y est refusée en 501).
// =====================================================================================
mod jetons_servent_leur_auteur_et_sa_suppression {
    use super::*;

    const JSAS_SECRET_SSO: &str = "secret-de-bord-jsas";
    const JSAS_ADMIN_DE_CONFIGURATION: &str = "root-jsas";

    fn jsas_mot(marque: &str) -> String {
        format!("jsas-{marque}-{}", "m".repeat(PASSWORD_MIN_CHARS))
    }

    async fn jsas_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
        (statut, corps)
    }

    fn jsas_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (mut st, p) = sp_state(tag);
        st.sso_secret = Arc::new(JSAS_SECRET_SSO.into());
        st.user = Arc::new(JSAS_ADMIN_DE_CONFIGURATION.into());
        st.pass_hash = Arc::new(hash_pw(&jsas_mot("configuration")).expect("hachage"));
        (st, p)
    }

    async fn jsas_liste(st: &AppState) -> Value {
        let (s, c) = jsas_corps(tokens_list(State(st.clone()), Extension(sp_au("adm", "admin"))).await).await;
        assert_eq!(s, 200, "{c}");
        c
    }

    fn jsas_ligne<'a>(corps: &'a Value, nom: &str) -> &'a Value {
        corps["tokens"].as_array().expect("liste des jetons").iter().find(|t| t["name"] == nom).unwrap_or_else(|| panic!("`{nom}` listé : {corps}"))
    }

    /// CE QU'IL TIENT : `zoe` frappe un jeton d'agent (servi une fois, donc CONSERVÉ à sa suppression) ; la ligne de
    /// commande frappe un jeton (auteur non établi). Avant la suppression : `created_by` = `zoe`, `created_by_deleted_at`
    /// null (clé PRÉSENTE) ; le jeton de la ligne de commande : les deux null. Après la suppression de `zoe` :
    /// `created_by` intact, `created_by_deleted_at` = l'instant posé en base. Le jeton de la ligne de commande : inchangé.
    ///
    /// MUTATIONS QUI LE FONT ROUGIR (dans `tokens_list`, `handlers/tokens.rs`) : retirer `created_by` du SELECT et de
    /// l'objet servi ; servir `created_by_deleted_at` à `null` au lieu de la colonne 9.
    #[tokio::test]
    async fn jsas_la_liste_sert_l_auteur_et_la_marque_de_suppression() {
        let (st, _p) = jsas_etat("jsas-servi");
        let (s, c) = jsas_corps(
            user_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sp_au("adm", "admin")), Json(json!({ "name": "zoe", "password": jsas_mot("zoe"), "role": "admin" }))).await,
        )
        .await;
        assert_eq!(s, 200, "fixture : compte créé : {c}");
        let (s, c) = jsas_corps(
            token_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sp_au("zoe", "admin")), Json(json!({ "name": "ag-jsas", "kind": "agent", "host": "h-jsas" }))).await,
        )
        .await;
        assert_eq!(s, 200, "fixture : jeton frappé : {c}");
        let agent = c["token"].as_str().expect("fixture : secret montré").to_string();
        let cli = "j".repeat(64);
        inserer_jeton(&st.db.lock(), "cli-jsas", &sha256_hex(cli.as_bytes()), None, None, &PorteeJeton::Machine("h-cli-jsas".into()))
            .expect("fixture : jeton de la ligne de commande");
        // Servi une fois : conservé (marqué) à la suppression, pas révoqué.
        let req = Request::builder().uri("/api/ingest").header("authorization", format!("Bearer {agent}")).body(axum::body::Body::empty()).expect("requête");
        assert_eq!(resolve_identity(&st, &req).0, Some(("h-jsas".into(), "agent".into())), "fixture : jeton servi");

        let avant = jsas_liste(&st).await;
        let ag = jsas_ligne(&avant, "ag-jsas");
        assert_eq!(ag["created_by"], json!("zoe"), "l'auteur est servi : {avant}");
        assert!(ag.get("created_by_deleted_at").is_some_and(Value::is_null), "auteur vivant : marque présente et null : {avant}");
        let cl = jsas_ligne(&avant, "cli-jsas");
        assert!(cl.get("created_by").is_some_and(Value::is_null), "auteur non établi : null : {avant}");
        assert!(cl.get("created_by_deleted_at").is_some_and(Value::is_null), "{avant}");

        let id: i64 = st.db.lock().query_row("SELECT id FROM user WHERE name='zoe'", [], |r| r.get(0)).expect("fixture : id");
        let (s, c) = jsas_corps(user_delete(State(st.clone()), Extension(sp_au("adm", "admin")), axum::extract::Path(id)).await).await;
        assert_eq!(s, 200, "fixture : suppression : {c}");
        let marque: i64 = st
            .db
            .lock()
            .query_row("SELECT created_by_deleted_at FROM token WHERE name='ag-jsas'", [], |r| r.get(0))
            .expect("fixture : jeton conservé et marqué");

        let apres = jsas_liste(&st).await;
        assert!(apres.get("error").is_none(), "inventaire lu : {apres}");
        let ag = jsas_ligne(&apres, "ag-jsas");
        assert_eq!(ag["created_by"], json!("zoe"), "l'attestation n'est pas réécrite : {apres}");
        assert_eq!(ag["created_by_deleted_at"], json!(marque), "la marque de suppression est servie : {apres}");
        let cl = jsas_ligne(&apres, "cli-jsas");
        assert!(cl["created_by"].is_null() && cl["created_by_deleted_at"].is_null(), "{apres}");
    }

    /// CE QU'IL TIENT : le parcours reste SOLDÉ EN BLOC avec les colonnes neuves — un `created_by` illisible (BLOB)
    /// rend la liste avouée (`error`, tableau vide), jamais servie amputée de la ligne.
    #[tokio::test]
    async fn jsas_un_auteur_illisible_rend_la_liste_avouee() {
        let (st, _p) = jsas_etat("jsas-illisible");
        st.db
            .lock()
            .execute_batch(
                "INSERT INTO token(name,token_hash,created,kind,created_by) VALUES('a-jsas','h1',10,'agent','zoe');\
                 INSERT INTO token(name,token_hash,created,kind,created_by) VALUES('b-jsas','h2',20,'agent',x'FF');",
            )
            .expect("fixture");
        let corps = jsas_liste(&st).await;
        assert!(corps.get("error").is_some(), "une ligne illisible avoue la liste : {corps}");
        assert_eq!(corps["tokens"].as_array().map(Vec::len), Some(0), "{corps}");
    }

    /// CE QU'IL TIENT : une MARQUE DE SUPPRESSION illisible (texte dans `created_by_deleted_at`, colonne INTEGER) rend
    /// la liste avouée (`error`, tableau vide). Lue « au mieux », elle sortirait `null` : le jeton d'un auteur SUPPRIMÉ
    /// passerait pour celui d'un auteur vivant.
    ///
    /// MUTATION QUI LE FAIT ROUGIR : dans `tokens_list`, `r.get::<_, Option<i64>>(9)?` remplacé par
    /// `r.get::<_, Option<i64>>(9).ok().flatten()` (erreur de lecture avalée) — les deux témoins précédents restent verts.
    #[tokio::test]
    async fn jsas_une_marque_illisible_rend_la_liste_avouee() {
        let (st, _p) = jsas_etat("jsas-marque-illisible");
        st.db
            .lock()
            .execute_batch(
                "INSERT INTO token(name,token_hash,created,kind,created_by) VALUES('a-jsas','h1',10,'agent','zoe');\
                 INSERT INTO token(name,token_hash,created,kind,created_by,created_by_deleted_at) VALUES('b-jsas','h2',20,'agent','zoe','pas-une-date');",
            )
            .expect("fixture");
        let typee: String = st.db.lock().query_row("SELECT typeof(created_by_deleted_at) FROM token WHERE name='b-jsas'", [], |r| r.get(0)).expect("fixture : type");
        assert_eq!(typee, "text", "fixture : la marque est bien illisible en entier");
        let corps = jsas_liste(&st).await;
        assert!(corps.get("error").is_some(), "une marque illisible avoue la liste : {corps}");
        assert_eq!(corps["tokens"].as_array().map(Vec::len), Some(0), "{corps}");
    }
}
