// =====================================================================================
// `P10.20-l` (sites de la famille dans handlers/dashboards.rs et handlers/dash_ergonomics.rs) et `P10.33-l` (reste :
// la lecture `is_soql` de `library_panel_update`) — UNE LECTURE RATÉE D'UN TABLEAU DE BORD N'EST PAS UNE ABSENCE.
//
// LE DÉFAUT, MESURÉ SUR f0df6162 AVANT LE CORRECTIF. Six gestes lisaient leur ligne par
// `match … { Ok(x) => …, Err(_) => 404 }` : `library_panel_update` (le mode de requête qui arme le garde-fou editor ->
// SQL brut), `snapshot_create` (le tableau de bord à capturer, corps texte « dashboard introuvable »), `snapshot_delete`
// (l'auteur de l'instantané, avant le 403 de propriétaire), `dash_delete`, `panel_delete` et `view_delete` (le
// propriétaire ou le tableau de bord porteur, avant le 403 ou la suppression). Une ligne qui existe mais ne se lit pas
// se disait introuvable.
//
// LE CORRECTIF (décision par défaut de la vague AE). Trois issues par `.optional()` : lue, le geste suit ; absente, le
// 404 d'avant à l'identique (corps compris) ; lecture ratée, 503 — RIEN n'est écrit, capturé, délié ni supprimé, aucun
// 403 n'est décidé, la cause du moteur au journal seul. Corps nommé là où la route rend une `Response`
// (`CAUSE_PANNEAU_DE_BIBLIOTHEQUE_INCHANGE_NON_LU`, `CAUSE_INSTANTANE_NON_CREE_TABLEAU_DE_BORD_NON_LU`,
// `CAUSE_INSTANTANE_NON_SUPPRIME_NON_LU`, `CAUSE_PANNEAU_NON_SUPPRIME_NON_LU` — `panel_delete` passe de `StatusCode` à
// `Response`, son seul appelant étant le routeur) ; 503 SANS CORPS pour `dash_delete` et `view_delete`, dont la
// signature `StatusCode` est gardée parce que leurs appelants de test vivent hors du périmètre du lot.
// INVERSÉ PAR LA VAGUE AF (`P10.20-l`) : `dash_delete` et `view_delete` rendent une `Response`, et leur 503 de lecture
// ratée porte `CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME_NON_LU` / `CAUSE_VUE_NON_SUPPRIMEE_NON_LUE` en corps, avec
// l'identifiant de corrélation — les deux témoins et le journal ci-dessous qui affirmaient le 503 NU l'affirment désormais
// NOMMÉ, en entier ; leurs écritures sont jugées par `ecritures_des_retraits_de_tableaux_de_bord_jugees.rs`.
//
// LA PANNE ÉPROUVÉE : la colonne lue stockée en BLOB (la ligne existe, sa conversion échoue) ; la ligne de journal lue
// sur le stderr d'un sous-processus.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit), par lecture L ∈ {BIB, CAPT, REVOC, DASH, PANEL, VUE} :
// `AE4_<L>_LECTURE_EN_404` (la forme d'avant), `AE4_<L>_ABSENT_EN_503`, `AE4_<L>_LECTURE_FAIT_LE_GESTE` (une lecture
// ratée qui suppose une valeur et poursuit), `AE4_<L>_SANS_JOURNAL`, `AE4_<L>_JOURNAL_SUFFIXE` (« par <compte> » ajouté
// à la ligne) ; pour les quatre corps nommés (BIB, CAPT, REVOC, PANEL) `AE4_<L>_CAUSE_EXPOSEE` ; `AE4_PANEL_DROIT_RETIRE`
// (le refus de droit de `panel_delete` laissé passer).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ce que la console peint (web/ hors périmètre ; les retraits d'un tableau de
// bord et d'un panneau passent par `peindreLeRefusDUnGeste`, qui lit un 503 nommé en « refus nommé » et un 503 nu en
// « refus sans cause », la suppression d'une vue par `motDuRefusServeurDeVue` ; aucun écran n'appelle la modification
// d'un panneau de bibliothèque ni la révocation d'un instantané) ; une lecture ratée par verrou ou table retirée (la
// conversion suffit à atteindre le bras) ; `snapshot_get`, `library_panel_delete` (`is_err`) et `dash_editable`
// (`Err(_) => false`, lu par `panel_delete` après la lecture corrigée : un porteur lu dont le droit ne se lit pas rend
// encore 403) gardent leur confusion — hors du lot ; les écritures de `dash_delete`, `panel_delete` et `view_delete`
// restent en `let _` (un DELETE refusé rend 204) ; le détachement d'un panneau sans effet n'est pas refusé (`P10.33-l`).
// =====================================================================================
mod lecture_ratee_des_tableaux_de_bord_jamais_404 {
    use super::*;

    /// Ce que rusqlite écrit quand une colonne n'a pas le type demandé : la cause du moteur d'une lecture ratée.
    const AE4_MOTEUR: &str = "Invalid column type";
    const AE4_ABSENT: i64 = 987_654;
    const AE4_JETON: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn ae4_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ae4_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn ae4_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn ae4_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    /// Un 503 nommé, EN ENTIER : exactement les clés `error` et `id`, l'erreur égale à la phrase attendue, l'identifiant
    /// de corrélation, et aucune trace de la cause du moteur.
    fn ae4_juger_503(quoi: &str, (statut, corps, v): &(u16, String, Value), phrase: &str) {
        assert_eq!(*statut, 503, "{quoi} : une lecture ratée n'est ni une absence (404) ni un refus de droit (403) : {corps}");
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"], "{quoi} : exactement `error` et `id` : {corps}");
        assert_eq!(v["error"], json!(phrase), "{quoi} : la phrase nommée, seule : {corps}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
        assert!(!corps.contains(AE4_MOTEUR) && !corps.contains("Blob") && !corps.contains("COALESCE"), "{quoi} : la cause du moteur ne sort pas : {corps}");
    }

    /// Un tableau de bord d'alice ; rend son identifiant.
    fn ae4_tableau(st: &AppState, nom: &str, visibilite: &str) -> i64 {
        ae4_sql(st, &format!("INSERT INTO dashboard(name,created,owner,visibility) VALUES('{nom}',1000,'alice','{visibilite}');"));
        ae4_compte(st, "SELECT MAX(id) FROM dashboard")
    }

    /// Un panneau dans le tableau de bord `did`, avec une ligne de cache ; rend son identifiant.
    fn ae4_panneau(st: &AppState, did: i64, bibliotheque: Option<i64>) -> i64 {
        let lib = bibliotheque.map_or("NULL".to_string(), |l| l.to_string());
        ae4_sql(st, &format!("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,library_panel_id) VALUES({did},'p','search source=web | table message',1,'table',{lib});"));
        let pid = ae4_compte(st, "SELECT MAX(id) FROM panel");
        ae4_sql(st, &format!("INSERT INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES({pid},'r','fp',1,'{{}}');"));
        pid
    }

    /// Une définition PARTAGÉE d'alice, créée par le handler réel (titre « avant »), et un panneau qui la référence avec
    /// sa ligne de cache. Rend (définition, panneau).
    async fn ae4_definition(st: &AppState) -> (i64, i64) {
        let (statut, corps, v) = ae4_reponse(
            library_panel_create(State(st.clone()), Extension(sp_au("alice", "editor")), Json(json!({ "name": "def-ae4", "title": "avant", "query": "search source=web | table message" }))).await,
        )
        .await;
        assert_eq!(statut, 200, "fixture : la définition est créée : {corps}");
        let lib = v["id"].as_i64().expect("fixture : identifiant servi");
        let did = ae4_tableau(st, "d-ae4-bib", "shared");
        (lib, ae4_panneau(st, did, Some(lib)))
    }

    fn ae4_instantane(st: &AppState) -> i64 {
        ae4_sql(st, &format!("INSERT INTO dashboard_snapshot(dashboard_id,name,token,data,created,created_by,role_at_capture) VALUES(1,'i','{AE4_JETON}','{{}}',1000,'alice','editor');"));
        ae4_compte(st, "SELECT MAX(id) FROM dashboard_snapshot")
    }

    /// Une vue privée d'alice et un tableau de bord rangé dedans ; rend (vue, tableau).
    fn ae4_vue(st: &AppState) -> (i64, i64) {
        ae4_sql(st, "INSERT INTO view(name,owner,visibility) VALUES('v-ae4','alice','private');");
        let vue = ae4_compte(st, "SELECT MAX(id) FROM view");
        let did = ae4_tableau(st, "d-ae4-vue", "private");
        ae4_sql(st, &format!("UPDATE dashboard SET view_id={vue} WHERE id={did};"));
        (vue, did)
    }

    async fn ae4_modifier(st: &AppState, qui: &AuthUser, lib: i64, corps: Value) -> (u16, String, Value) {
        ae4_reponse(library_panel_update(State(st.clone()), Extension(qui.clone()), Path(lib), Json(corps)).await).await
    }

    async fn ae4_capturer(st: &AppState, qui: &AuthUser, did: i64) -> (u16, String, Value) {
        ae4_reponse(snapshot_create(State(st.clone()), Extension(qui.clone()), Json(json!({ "dashboard_id": did, "from": 0, "to": 100, "name": "i-ae4" }))).await).await
    }

    async fn ae4_revoquer(st: &AppState, qui: &AuthUser, sid: i64) -> (u16, String, Value) {
        ae4_reponse(snapshot_delete(State(st.clone()), Extension(qui.clone()), Path(sid)).await).await
    }

    async fn ae4_retirer_le_panneau(st: &AppState, qui: &AuthUser, pid: i64) -> (u16, String, Value) {
        ae4_reponse(panel_delete(State(st.clone()), Extension(qui.clone()), Path(pid)).await).await
    }

    /// CE QU'IL TIENT (modification d'un panneau de bibliothèque, lecture `is_soql`) : absent, `404` sans corps ; mode de
    /// requête illisible, `503` nommé `CAUSE_PANNEAU_DE_BIBLIOTHEQUE_INCHANGE_NON_LU` en entier, pour l'editor
    /// propriétaire (corps SANS `is_soql` : le garde-fou n'est pas ouvert par une valeur supposée) comme pour l'admin —
    /// titre, visibilité et mode d'avant, cache du référent non purgé, transaction fermée. Contrôle : mode relisible, la
    /// même modification est écrite (`204`).
    /// MUTATIONS : `AE4_BIB_LECTURE_EN_404`, `AE4_BIB_ABSENT_EN_503`, `AE4_BIB_CAUSE_EXPOSEE`, `AE4_BIB_LECTURE_FAIT_LE_GESTE`.
    #[tokio::test]
    async fn ae4_modification_d_un_panneau_de_bibliotheque_mode_illisible_jamais_404_rien_n_est_ecrit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("ae4-bib");
        let (alice, adm) = (sp_au("alice", "editor"), sp_au("adm", "admin"));
        let (statut, corps, _) = ae4_modifier(&st, &alice, AE4_ABSENT, json!({ "title": "x" })).await;
        assert_eq!((statut, corps.as_str()), (404, ""), "contrôle : l'absence établie reste le 404 d'avant, sans corps");

        let (lib, pid) = ae4_definition(&st).await;
        ae4_sql(&st, &format!("UPDATE library_panel SET is_soql=X'00' WHERE id={lib};"));
        for (qui, au) in [("editor propriétaire", &alice), ("admin", &adm)] {
            let r = ae4_modifier(&st, au, lib, json!({ "title": "apres", "visibility": "private" })).await;
            ae4_juger_503(&format!("mode illisible ({qui})"), &r, CAUSE_PANNEAU_DE_BIBLIOTHEQUE_INCHANGE_NON_LU);
            assert_eq!(ae4_texte(&st, &format!("SELECT title FROM library_panel WHERE id={lib}")), "avant", "{qui} : rien n'est écrit");
            assert_eq!(ae4_texte(&st, &format!("SELECT visibility FROM library_panel WHERE id={lib}")), "shared", "{qui} : la définition reste partagée");
            assert_eq!(ae4_texte(&st, &format!("SELECT typeof(is_soql) FROM library_panel WHERE id={lib}")), "blob", "{qui} : le mode n'est pas réécrit");
            assert_eq!(ae4_compte(&st, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={pid}")), 1, "{qui} : le cache du référent n'est pas purgé");
            assert!(st.db.lock().is_autocommit(), "{qui} : aucune transaction pendante");
        }

        ae4_sql(&st, &format!("UPDATE library_panel SET is_soql=1 WHERE id={lib};"));
        let (statut, corps, _) = ae4_modifier(&st, &alice, lib, json!({ "title": "apres", "visibility": "private" })).await;
        assert_eq!(statut, 204, "contrôle : mode relisible, la modification est écrite : {corps}");
        assert_eq!(ae4_texte(&st, &format!("SELECT title FROM library_panel WHERE id={lib}")), "apres");
    }

    /// CE QU'IL TIENT (création d'un instantané) : absent, `404` « dashboard introuvable » exactement ; tableau de bord
    /// illisible, `503` nommé `CAUSE_INSTANTANE_NON_CREE_TABLEAU_DE_BORD_NON_LU` en entier, aucun instantané écrit, pour
    /// l'editor propriétaire comme pour l'admin. Contrôle : nom relisible, l'instantané est créé (`200`, jeton servi).
    /// MUTATIONS : `AE4_CAPT_LECTURE_EN_404`, `AE4_CAPT_ABSENT_EN_503`, `AE4_CAPT_CAUSE_EXPOSEE`, `AE4_CAPT_LECTURE_FAIT_LE_GESTE`.
    #[tokio::test]
    async fn ae4_instantane_d_un_tableau_de_bord_illisible_jamais_404_rien_n_est_capture() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (configuration, masques)
        let (st, _p) = sp_state("ae4-capt");
        let (alice, adm) = (sp_au("alice", "editor"), sp_au("adm", "admin"));
        let (statut, corps, _) = ae4_capturer(&st, &alice, AE4_ABSENT).await;
        assert_eq!((statut, corps.as_str()), (404, "dashboard introuvable"), "contrôle : l'absence établie reste le 404 d'avant, corps compris");

        let did = ae4_tableau(&st, "d-ae4-capt", "shared");
        ae4_sql(&st, &format!("UPDATE dashboard SET name=X'00' WHERE id={did};"));
        for (qui, au) in [("editor propriétaire", &alice), ("admin", &adm)] {
            let r = ae4_capturer(&st, au, did).await;
            ae4_juger_503(&format!("tableau illisible ({qui})"), &r, CAUSE_INSTANTANE_NON_CREE_TABLEAU_DE_BORD_NON_LU);
            assert_eq!(ae4_compte(&st, "SELECT COUNT(*) FROM dashboard_snapshot"), 0, "{qui} : rien n'est capturé ni partagé");
        }

        ae4_sql(&st, &format!("UPDATE dashboard SET name='d-ae4-capt' WHERE id={did};"));
        let (statut, corps, v) = ae4_capturer(&st, &alice, did).await;
        assert_eq!(statut, 200, "contrôle : nom relisible, l'instantané est créé : {corps}");
        assert!(v["token"].as_str().is_some_and(|t| t.len() == 64), "contrôle : jeton servi : {corps}");
        assert_eq!(ae4_compte(&st, "SELECT COUNT(*) FROM dashboard_snapshot"), 1);
    }

    /// CE QU'IL TIENT (révocation d'un instantané) : absent, `404` sans corps ; auteur illisible, `503` nommé
    /// `CAUSE_INSTANTANE_NON_SUPPRIME_NON_LU` en entier pour l'auteur, l'admin ET un tiers — ni `403` ni révocation sur un
    /// auteur non lu ; l'instantané reste. Contrôle : auteur relisible, le tiers reçoit `403`, l'auteur révoque (`204`).
    /// MUTATIONS : `AE4_REVOC_LECTURE_EN_404`, `AE4_REVOC_ABSENT_EN_503`, `AE4_REVOC_CAUSE_EXPOSEE`, `AE4_REVOC_LECTURE_FAIT_LE_GESTE`.
    #[tokio::test]
    async fn ae4_revocation_d_un_instantane_auteur_illisible_jamais_404_ni_403_rien_n_est_supprime() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("ae4-revoc");
        let (alice, bob, adm) = (sp_au("alice", "editor"), sp_au("bob", "editor"), sp_au("adm", "admin"));
        let (statut, corps, _) = ae4_revoquer(&st, &alice, AE4_ABSENT).await;
        assert_eq!((statut, corps.as_str()), (404, ""), "contrôle : l'absence établie reste le 404 d'avant, sans corps");

        let sid = ae4_instantane(&st);
        ae4_sql(&st, &format!("UPDATE dashboard_snapshot SET created_by=X'00' WHERE id={sid};"));
        for (qui, au) in [("auteur", &alice), ("admin", &adm), ("tiers", &bob)] {
            let r = ae4_revoquer(&st, au, sid).await;
            ae4_juger_503(&format!("auteur illisible ({qui})"), &r, CAUSE_INSTANTANE_NON_SUPPRIME_NON_LU);
            assert_eq!(ae4_compte(&st, &format!("SELECT COUNT(*) FROM dashboard_snapshot WHERE id={sid}")), 1, "{qui} : l'instantané reste");
        }

        ae4_sql(&st, &format!("UPDATE dashboard_snapshot SET created_by='alice' WHERE id={sid};"));
        assert_eq!(ae4_revoquer(&st, &bob, sid).await.0, 403, "contrôle : auteur relisible, le tiers est refusé");
        assert_eq!(ae4_revoquer(&st, &alice, sid).await.0, 204, "contrôle : l'auteur révoque");
        assert_eq!(ae4_compte(&st, &format!("SELECT COUNT(*) FROM dashboard_snapshot WHERE id={sid}")), 0);
    }

    /// CE QU'IL TIENT (suppression d'un tableau de bord) : absent, `404` sans corps ; propriétaire illisible, `503` nommé
    /// `CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME_NON_LU` en entier (vague AF : il était NU) pour la propriétaire et l'admin — ni `403` ni suppression ; le tableau et son panneau
    /// restent. Contrôle : propriétaire relisible, un tiers reçoit `403`, la propriétaire supprime (`204`).
    /// MUTATIONS : `AE4_DASH_LECTURE_EN_404`, `AE4_DASH_ABSENT_EN_503`, `AE4_DASH_LECTURE_FAIT_LE_GESTE`.
    #[tokio::test]
    async fn ae4_suppression_d_un_tableau_de_bord_proprietaire_illisible_jamais_404_ni_403_rien_n_est_supprime() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("ae4-dash");
        let (alice, bob, adm) = (sp_au("alice", "editor"), sp_au("bob", "editor"), sp_au("adm", "admin"));
        let (statut, corps, _) = ae4_reponse(dash_delete(State(st.clone()), Extension(alice.clone()), Path(AE4_ABSENT)).await).await;
        assert_eq!((statut, corps.as_str()), (404, ""), "contrôle : l'absence établie reste le 404 d'avant, sans corps");

        let did = ae4_tableau(&st, "d-ae4-dash", "shared");
        let pid = ae4_panneau(&st, did, None);
        ae4_sql(&st, &format!("UPDATE dashboard SET owner=X'00' WHERE id={did};"));
        for (qui, au) in [("propriétaire", &alice), ("admin", &adm)] {
            // INVERSÉ (vague AF) : le 503 était nu, il porte sa cause nommée.
            let r = ae4_reponse(dash_delete(State(st.clone()), Extension(au.clone()), Path(did)).await).await;
            ae4_juger_503(&format!("propriétaire illisible ({qui})"), &r, CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME_NON_LU);
            assert_eq!(ae4_compte(&st, &format!("SELECT COUNT(*) FROM dashboard WHERE id={did}")), 1, "{qui} : le tableau reste");
            assert_eq!(ae4_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE id={pid}")), 1, "{qui} : son panneau reste");
        }

        ae4_sql(&st, &format!("UPDATE dashboard SET owner='alice' WHERE id={did};"));
        let (statut, corps, _) = ae4_reponse(dash_delete(State(st.clone()), Extension(bob.clone()), Path(did)).await).await;
        assert_eq!((statut, corps.as_str()), (403, ""), "contrôle : un tiers est refusé, sans corps");
        assert_eq!(dash_delete(State(st.clone()), Extension(alice.clone()), Path(did)).await.status(), StatusCode::NO_CONTENT, "contrôle : la propriétaire supprime");
        assert_eq!(ae4_compte(&st, &format!("SELECT COUNT(*) FROM dashboard WHERE id={did}")), 0);
    }

    /// CE QU'IL TIENT (suppression d'un panneau) : absent, `404` sans corps ; tableau porteur illisible, `503` nommé
    /// `CAUSE_PANNEAU_NON_SUPPRIME_NON_LU` en entier pour la propriétaire et l'admin — ni `403` ni suppression ; le panneau
    /// et son cache restent. Contrôle : porteur relisible, un editor tiers sur le tableau PRIVÉ d'alice reçoit `403` sans
    /// corps et le panneau comme son cache restent (le bras de droit réécrit par le passage à `Response`) ; la propriétaire
    /// supprime (`204`), le cache est purgé.
    /// MUTATIONS : `AE4_PANEL_LECTURE_EN_404`, `AE4_PANEL_ABSENT_EN_503`, `AE4_PANEL_CAUSE_EXPOSEE`, `AE4_PANEL_LECTURE_FAIT_LE_GESTE`,
    /// `AE4_PANEL_DROIT_RETIRE` (le bras `Ok(Some(_)) => 403` laissé passer).
    #[tokio::test]
    async fn ae4_suppression_d_un_panneau_porteur_illisible_jamais_404_ni_403_rien_n_est_supprime() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("ae4-panel");
        let (alice, bob, adm) = (sp_au("alice", "editor"), sp_au("bob", "editor"), sp_au("adm", "admin"));
        let (statut, corps, _) = ae4_retirer_le_panneau(&st, &alice, AE4_ABSENT).await;
        assert_eq!((statut, corps.as_str()), (404, ""), "contrôle : l'absence établie reste le 404 d'avant, sans corps");

        let did = ae4_tableau(&st, "d-ae4-panel", "private");
        let pid = ae4_panneau(&st, did, None);
        ae4_sql(&st, &format!("UPDATE panel SET dashboard_id=X'00' WHERE id={pid};"));
        for (qui, au) in [("propriétaire", &alice), ("admin", &adm)] {
            let r = ae4_retirer_le_panneau(&st, au, pid).await;
            ae4_juger_503(&format!("porteur illisible ({qui})"), &r, CAUSE_PANNEAU_NON_SUPPRIME_NON_LU);
            assert_eq!(ae4_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE id={pid}")), 1, "{qui} : le panneau reste");
            assert_eq!(ae4_compte(&st, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={pid}")), 1, "{qui} : son cache reste");
        }

        ae4_sql(&st, &format!("UPDATE panel SET dashboard_id={did} WHERE id={pid};"));
        let (statut, corps, _) = ae4_retirer_le_panneau(&st, &bob, pid).await;
        assert_eq!((statut, corps.as_str()), (403, ""), "contrôle : porteur relisible et privé d'alice, l'editor tiers est refusé sans corps");
        assert_eq!(ae4_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE id={pid}")), 1, "contrôle : refusé, le panneau reste");
        assert_eq!(ae4_compte(&st, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={pid}")), 1, "contrôle : refusé, son cache reste");
        let (statut, corps, _) = ae4_retirer_le_panneau(&st, &alice, pid).await;
        assert_eq!(statut, 204, "contrôle : porteur relisible, la propriétaire supprime : {corps}");
        assert_eq!(ae4_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE id={pid}")), 0);
        assert_eq!(ae4_compte(&st, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={pid}")), 0, "contrôle : un succès purge le cache");
    }

    /// CE QU'IL TIENT (suppression d'une vue) : absent, `404` sans corps ; propriétaire illisible, `503` nommé
    /// `CAUSE_VUE_NON_SUPPRIMEE_NON_LUE` en entier (vague AF : il était NU) pour la propriétaire et l'admin — ni `403` ni suppression ; la vue reste, le tableau qui y est
    /// rangé n'est pas délié. Contrôle : propriétaire relisible, un tiers reçoit `403`, la propriétaire supprime (`204`) et
    /// le tableau est délié.
    /// MUTATIONS : `AE4_VUE_LECTURE_EN_404`, `AE4_VUE_ABSENT_EN_503`, `AE4_VUE_LECTURE_FAIT_LE_GESTE`.
    #[tokio::test]
    async fn ae4_suppression_d_une_vue_proprietaire_illisible_jamais_404_ni_403_rien_n_est_delie() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("ae4-vue");
        let (alice, bob, adm) = (sp_au("alice", "editor"), sp_au("bob", "editor"), sp_au("adm", "admin"));
        let (statut, corps, _) = ae4_reponse(view_delete(State(st.clone()), Extension(alice.clone()), Path(AE4_ABSENT)).await).await;
        assert_eq!((statut, corps.as_str()), (404, ""), "contrôle : l'absence établie reste le 404 d'avant, sans corps");

        let (vue, did) = ae4_vue(&st);
        ae4_sql(&st, &format!("UPDATE view SET owner=X'00' WHERE id={vue};"));
        for (qui, au) in [("propriétaire", &alice), ("admin", &adm)] {
            // INVERSÉ (vague AF) : le 503 était nu, il porte sa cause nommée.
            let r = ae4_reponse(view_delete(State(st.clone()), Extension(au.clone()), Path(vue)).await).await;
            ae4_juger_503(&format!("propriétaire illisible ({qui})"), &r, CAUSE_VUE_NON_SUPPRIMEE_NON_LUE);
            assert_eq!(ae4_compte(&st, &format!("SELECT COUNT(*) FROM view WHERE id={vue}")), 1, "{qui} : la vue reste");
            assert_eq!(ae4_compte(&st, &format!("SELECT COALESCE(view_id,0) FROM dashboard WHERE id={did}")), vue, "{qui} : le tableau n'est pas délié");
        }

        ae4_sql(&st, &format!("UPDATE view SET owner='alice' WHERE id={vue};"));
        let (statut, corps, _) = ae4_reponse(view_delete(State(st.clone()), Extension(bob.clone()), Path(vue)).await).await;
        assert_eq!((statut, corps.as_str()), (403, ""), "contrôle : un tiers est refusé, sans corps");
        assert_eq!(view_delete(State(st.clone()), Extension(alice.clone()), Path(vue)).await.status(), StatusCode::NO_CONTENT, "contrôle : la propriétaire supprime");
        assert_eq!(ae4_compte(&st, &format!("SELECT COUNT(*) FROM view WHERE id={vue}")), 0);
        assert_eq!(ae4_compte(&st, &format!("SELECT COALESCE(view_id,0) FROM dashboard WHERE id={did}")), 0, "contrôle : le tableau est délié");
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus : chaque lecture ratée écrit UNE ligne
    /// `[dashboards] WARN <objet> #<id> NON lu(e) pour <geste>, rien n'est … : <cause du moteur>` — avec l'identifiant de
    /// corrélation servi pour les six corps nommés (quatre avant la vague AF) ; les six absences et une révocation nominale n'en écrivent aucune.
    /// Chaque ligne est comparée EN ENTIER : un suffixe ajouté (nom du compte, texte de la requête) rougit.
    /// MUTATIONS : `AE4_<L>_SANS_JOURNAL` et `AE4_<L>_JOURNAL_SUFFIXE` pour L ∈ {BIB, CAPT, REVOC, DASH, PANEL, VUE}.
    #[tokio::test]
    async fn ae4_lignes_de_journal_des_lectures_ratees() {
        const ENFANT: &str = "AE4_ENFANT_JOURNAL";
        const PHASE: &str = "AE4-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
            let (st, _p) = sp_state("ae4-journal");
            let adm = sp_au("adm", "admin");
            eprintln!("{PHASE}bib");
            let (lib, _) = ae4_definition(&st).await;
            ae4_sql(&st, &format!("UPDATE library_panel SET is_soql=X'00' WHERE id={lib};"));
            let r = ae4_modifier(&st, &adm, lib, json!({ "title": "apres" })).await;
            println!("AE4-STATUT-BIB:{}:{lib}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}capt");
            let did = ae4_tableau(&st, "d-ae4-journal", "shared");
            ae4_sql(&st, &format!("UPDATE dashboard SET name=X'00' WHERE id={did};"));
            let r = ae4_capturer(&st, &adm, did).await;
            println!("AE4-STATUT-CAPT:{}:{did}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}revoc");
            let sid = ae4_instantane(&st);
            ae4_sql(&st, &format!("UPDATE dashboard_snapshot SET created_by=X'00' WHERE id={sid};"));
            let r = ae4_revoquer(&st, &adm, sid).await;
            println!("AE4-STATUT-REVOC:{}:{sid}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}panel");
            let pdid = ae4_tableau(&st, "d-ae4-journal-panel", "shared");
            let pid = ae4_panneau(&st, pdid, None);
            ae4_sql(&st, &format!("UPDATE panel SET dashboard_id=X'00' WHERE id={pid};"));
            let r = ae4_retirer_le_panneau(&st, &adm, pid).await;
            println!("AE4-STATUT-PANEL:{}:{pid}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}dash");
            let ddid = ae4_tableau(&st, "d-ae4-journal-dash", "shared");
            ae4_sql(&st, &format!("UPDATE dashboard SET owner=X'00' WHERE id={ddid};"));
            let r = ae4_reponse(dash_delete(State(st.clone()), Extension(adm.clone()), Path(ddid)).await).await;
            println!("AE4-STATUT-DASH:{}:{ddid}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}vue");
            let (vue, _) = ae4_vue(&st);
            ae4_sql(&st, &format!("UPDATE view SET owner=X'00' WHERE id={vue};"));
            let r = ae4_reponse(view_delete(State(st.clone()), Extension(adm.clone()), Path(vue)).await).await;
            println!("AE4-STATUT-VUE:{}:{vue}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}calme");
            let (st, _p) = sp_state("ae4-journal-calme");
            let a = ae4_modifier(&st, &adm, AE4_ABSENT, json!({ "title": "x" })).await.0;
            let b = ae4_capturer(&st, &adm, AE4_ABSENT).await.0;
            let c = ae4_revoquer(&st, &adm, AE4_ABSENT).await.0;
            let d = ae4_retirer_le_panneau(&st, &adm, AE4_ABSENT).await.0;
            let e = dash_delete(State(st.clone()), Extension(adm.clone()), Path(AE4_ABSENT)).await.status().as_u16();
            let f = view_delete(State(st.clone()), Extension(adm.clone()), Path(AE4_ABSENT)).await.status().as_u16();
            let sid = ae4_instantane(&st);
            let g = ae4_revoquer(&st, &adm, sid).await.0;
            println!("AE4-STATUT-CALME:{a}:{b}:{c}:{d}:{e}:{f}:{g}");
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::lecture_ratee_des_tableaux_de_bord_jamais_404::ae4_lignes_de_journal_des_lectures_ratees",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> Vec<String> {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").split(':').map(str::to_string).collect()
        };
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[dashboards] ")).map(str::to_string).collect()
        };
        // La cause du moteur telle que rusqlite l'écrit pour la colonne lue stockée en BLOB : la ligne est jugée EN ENTIER,
        // un suffixe (nom du compte, requête, corps) ne passe pas.
        let moteur = |colonne: &str| format!("{AE4_MOTEUR} Blob at index: 0, name: {colonne}");
        // (phase, marque, tête attendue jusqu'à la parenthèse de corrélation, colonne lue)
        let nommees = [
            ("bib", "AE4-STATUT-BIB:", "[dashboards] WARN panneau de bibliothèque #{} NON lu pour la modification, rien n'est écrit (", "COALESCE(is_soql,1)"),
            ("capt", "AE4-STATUT-CAPT:", "[dashboards] WARN tableau de bord #{} NON lu pour l'instantané, rien n'est capturé (", "name"),
            ("revoc", "AE4-STATUT-REVOC:", "[dashboards] WARN instantané #{} NON lu pour la révocation, rien n'est supprimé (", "COALESCE(created_by,'')"),
            ("panel", "AE4-STATUT-PANEL:", "[dashboards] WARN panneau #{} NON lu pour la suppression, rien n'est supprimé (", "dashboard_id"),
            // INVERSÉ (vague AF) : ces deux lectures avaient un 503 NU et une ligne sans identifiant de corrélation.
            ("dash", "AE4-STATUT-DASH:", "[dashboards] WARN tableau de bord #{} NON lu pour la suppression, rien n'est supprimé (", "COALESCE(owner,'')"),
            ("vue", "AE4-STATUT-VUE:", "[dashboards] WARN vue #{} NON lue pour la suppression, rien n'est délié ni supprimé (", "COALESCE(owner,'')"),
        ];
        assert!(nommees.len() >= 6, "plancher : les six lectures à corps nommé");
        for (nom, m, tete, colonne) in &nommees {
            let st = marque(m);
            assert_eq!(st[0], "503", "contrôle : phase {nom}, lecture ratée servie 503 : {st:?}");
            assert!(st[2].starts_with("plume-e"), "contrôle : phase {nom}, identifiant servi : {st:?}");
            let attendue = format!("{}{}) : {}", tete.replace("{}", &st[1]), st[2], moteur(colonne));
            let lignes = phase(nom);
            assert_eq!(lignes, [attendue], "phase {nom} : une ligne et une seule, en entier (sujet, corrélation servie, cause du moteur)");
        }
        assert_eq!(marque("AE4-STATUT-CALME:"), ["404", "404", "404", "404", "404", "404", "204"], "contrôle : six absences et une révocation nominale");
        assert!(phase("calme").is_empty(), "les absences et le nominal n'écrivent aucune ligne : {:?}", phase("calme"));
    }
}
