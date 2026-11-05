// =====================================================================================
// `P11.25-f` (suite) — CE QUE L'APPELANT NE VOIT PAS EST INCONNU POUR LUI, AUX GESTES DES VUES COMME AU
// RATTACHEMENT D'UN TABLEAU ; ET LA JOINTURE A SON INDEX PAR TABLEAU.
//
// CE QUE CES TÉMOINS TIENNENT :
//   * `DELETE /api/views/{id}/dashboards/{dashboard_id}` : un tableau privé d'un autre compte rangé dans la vue de
//     l'appelant rend la réponse d'un rattachement absent (404, même corps qu'un tableau absent ou non rangé) et rien
//     n'est écrit (ni la jointure, ni `dashboard.view_id`) ; l'administrateur, qui le lit, le retire ;
//   * `GET /api/dashboards?view=<id>` : une vue que l'appelant ne voit pas rend le corps ENTIER d'une vue qu'aucun
//     identifiant ne désigne (les seuls tableaux de toutes les vues), par le gestionnaire et par la route au rôle le
//     plus faible ; `?view=none` rend un tableau dont les seuls rattachements sont à des vues qu'il ne voit pas ; chaque
//     membre du périmètre (administrateur, vue commune, vue de l'appelant) a son cas, dans les deux filtres ;
//   * `PUT /api/dashboards/{id}` et `POST /api/dashboards` : un `view_id` qui ne désigne aucune vue que l'appelant voit
//     (absente ou privée d'autrui, même corps) est refusé en 404 nommé, rien du corps n'est écrit ; une vue commune, la
//     sienne, et pour l'administrateur la vue privée d'autrui, s'écrivent ; la vue illisible -> 503 nommé ;
//   * v125 pose `view_dashboard_par_tableau` sur une base v124, la garde au second passage, et la pose sur une base
//     neuve ; le plan d'une lecture par tableau l'emprunte.
//
// CE QU'ILS NE TIENNENT PAS : ce que la console peint de ces réponses (aucun volet console ici) ; la ligne de journal
// du 503 de lecture (`WARN vue #… NON lue pour y ranger un tableau de bord`), non capturée.
//
// MUTATIONS (posées sous `cfg!(test)` le temps de la vérification, puis retirées) : chaque témoin nomme les siennes.
// =====================================================================================
mod vues_non_visibles_traitees_comme_inconnues {
    use super::*;

    const BU2_ABSENT: &str = "RATTACHEMENT ABSENT : ce tableau de bord n'est pas rangé dans cette vue — rien n'est retiré.";
    const BU2_VUE_DU_TABLEAU_INCONNUE: &str =
        "VUE INCONNUE : aucune vue que vous voyez ne porte l'identifiant `view_id` demandé — rien n'est écrit, rien du corps n'est appliqué.";
    const BU2_VUE_DU_TABLEAU_NON_LUE: &str = "VUE NON LUE : la base n'a pas rendu la vue `view_id` demandée — ce n'est PAS une absence, c'est une lecture qui n'a pas eu lieu, et la vue n'est pas jugée. RIEN n'est écrit, rien du corps n'est appliqué. Réessayez ; si le refus persiste, la table des vues est illisible.";

    /// Une expression qui échoue à l'évaluation (« integer overflow ») : une colonne d'une vue temporaire qui la porte
    /// rend illisible la lecture qui la touche.
    const BU2_DEBORDE: &str = "abs(-9223372036854775807 - 1)";
    /// Un identifiant qu'aucune vue ni aucun tableau ne porte.
    const BU2_ABSENT_ID: i64 = 999_999;

    fn bu2_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(&format!("bu2-{tag}"));
        bu2_ecrire(&st, "DELETE FROM panel; DELETE FROM dashboard; DELETE FROM view_dashboard; DELETE FROM view;");
        (st, p)
    }

    fn bu2_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn bu2_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn bu2_vue(st: &AppState, nom: &str, owner: &str, vis: &str) -> i64 {
        let c = st.db.lock();
        c.execute("INSERT INTO view(name,owner,visibility) VALUES(?1,?2,?3)", params![nom, owner, vis]).expect("fixture : vue");
        c.last_insert_rowid()
    }

    fn bu2_tableau(st: &AppState, nom: &str, owner: &str, vis: &str, vue: Option<i64>) -> i64 {
        let c = st.db.lock();
        c.execute(
            "INSERT INTO dashboard(name,created,owner,visibility,view_id,cols,height,collapsed) VALUES(?1,1000,?2,?3,?4,1,0,0)",
            params![nom, owner, vis, vue],
        )
        .expect("fixture : tableau");
        c.last_insert_rowid()
    }

    fn bu2_rattacher(st: &AppState, vue: i64, tableau: i64) {
        st.db.lock().execute("INSERT INTO view_dashboard(view_id,dashboard_id) VALUES(?1,?2)", params![vue, tableau]).expect("fixture : rattachement");
    }

    fn bu2_rattachements(st: &AppState) -> Vec<(i64, i64)> {
        let c = st.db.lock();
        let mut s = c.prepare("SELECT view_id,dashboard_id FROM view_dashboard ORDER BY view_id,dashboard_id").unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    /// (nom, vue principale) du tableau.
    fn bu2_ligne(st: &AppState, tableau: i64) -> (String, Option<i64>) {
        st.db.lock().query_row("SELECT name,view_id FROM dashboard WHERE id=?1", params![tableau], |r| Ok((r.get(0)?, r.get(1)?))).unwrap()
    }

    async fn bu2_liste(st: &AppState, au: &AuthUser, vue: &str) -> (u16, Value) {
        let q: HashMap<String, String> = [("view".to_string(), vue.to_string())].into_iter().collect();
        let r = dash_list(State(st.clone()), Extension(au.clone()), Query(q)).await;
        (r.1.as_u16(), r.0)
    }

    async fn bu2_ids(st: &AppState, au: &AuthUser, vue: &str) -> Vec<i64> {
        let (code, v) = bu2_liste(st, au, vue).await;
        assert_eq!(code, 200, "liste de {} sous ?view={vue} : {v}", au.name);
        v["dashboards"].as_array().unwrap_or_else(|| panic!("une liste est servie : {v}")).iter().map(|d| d["id"].as_i64().unwrap()).collect()
    }

    async fn bu2_retirer(st: &AppState, au: &AuthUser, vue: i64, tableau: i64) -> (u16, Value) {
        pb_json(view_dashboard_remove(State(st.clone()), Extension(au.clone()), Path((vue, tableau))).await).await
    }

    async fn bu2_modifier(st: &AppState, au: &AuthUser, tableau: i64, corps: Value) -> (u16, Value) {
        pb_json(dash_update(State(st.clone()), Extension(au.clone()), Path(tableau), Json(corps)).await).await
    }

    async fn bu2_creer(st: &AppState, au: &AuthUser, corps: Value) -> (u16, Value) {
        pb_json(dash_create(State(st.clone()), Extension(au.clone()), Json(corps)).await).await
    }

    fn bu2_rendre_illisible(st: &AppState, table: &str, colonnes: &str) {
        bu2_ecrire(st, &format!("ALTER TABLE \"{table}\" RENAME TO \"{table}_source\"; CREATE TEMP VIEW \"{table}\" AS SELECT {colonnes} FROM \"{table}_source\";"));
    }

    fn bu2_rendre_lisible(st: &AppState, table: &str) {
        bu2_ecrire(st, &format!("DROP VIEW \"{table}\"; ALTER TABLE \"{table}_source\" RENAME TO \"{table}\";"));
    }

    /// Un 503 d'`err_json` : la phrase exacte et un identifiant de corrélation, rien d'autre.
    fn bu2_cinq_cent_trois(code: u16, corps: &Value, phrase: &str) {
        assert_eq!(code, 503, "503 attendu : {corps}");
        assert_eq!(corps["error"], json!(phrase), "phrase exacte : {corps}");
        assert!(corps["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "identifiant de corrélation servi : {corps}");
        assert_eq!(corps.as_object().map(|o| o.len()), Some(2), "ni plus ni moins que `error` et `id` : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (1) retrait d'un rattachement : un tableau illisible est un rattachement absent
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : le tableau PRIVÉ de bob, rangé par bob dans la vue d'alice (vue principale, donc rattaché), est
    /// pour alice un rattachement absent : 404 au corps identique à celui d'un tableau lisible non rangé et d'un
    /// identifiant qu'aucun tableau ne porte ; ni la jointure ni sa vue principale ne bougent. Contrôle : l'administrateur,
    /// qui le lit, le retire (204), et la vue principale est vidée. MUTATION : `BU2_RETRAIT_SANS_LISIBLE` (204 pour alice,
    /// le rattachement et la vue principale de bob effacés).
    #[tokio::test]
    async fn bu2_retirer_un_tableau_prive_d_autrui_vaut_un_rattachement_absent() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = bu2_etat("retrait-illisible");
        let (alice, adm) = (sp_au("alice", "editor"), sp_au("adm", "admin"));
        let v = bu2_vue(&st, "V d'alice", "alice", "shared");
        let prive = bu2_tableau(&st, "Privé de bob", "bob", "private", Some(v));
        let lisible = bu2_tableau(&st, "Commun non rangé", "", "shared", None);
        assert_eq!(bu2_rattachements(&st), vec![(v, prive)], "fixture : le privé de bob est rangé dans la vue d'alice");
        let attendu = (404, json!({ "error": BU2_ABSENT }));
        assert_eq!(bu2_retirer(&st, &alice, v, lisible).await, attendu, "contrôle : lisible, non rangé");
        assert_eq!(bu2_retirer(&st, &alice, v, BU2_ABSENT_ID).await, attendu, "contrôle : aucun tableau sous cet identifiant");
        assert_eq!(bu2_retirer(&st, &alice, v, prive).await, attendu, "le privé d'autrui a la réponse d'un absent");
        assert_eq!(bu2_rattachements(&st), vec![(v, prive)], "la jointure n'est pas écrite");
        assert_eq!(bu2_ligne(&st, prive), ("Privé de bob".to_string(), Some(v)), "la vue principale n'est pas vidée");
        let (code, corps) = bu2_retirer(&st, &adm, v, prive).await;
        assert_eq!(code, 204, "l'administrateur le lit et le retire : {corps}");
        assert_eq!((bu2_rattachements(&st), bu2_ligne(&st, prive).1), (vec![], None));
    }

    // -------------------------------------------------------------------------------------
    // (2) dash_list : une vue invisible est une vue inconnue
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : trois vues (privée d'alice PA, commune de bob S, privée de bob PB), un tableau commun rangé dans
    /// chacune, un de toutes les vues (T), un sans vue (N). Pour alice, `?view=PB` rend le corps ENTIER de `?view=999999`
    /// (T seul, `total` 1) ; S et PA rendent leur tableau ; `none` rend N et le tableau rangé dans PB seulement. Pour bob
    /// et l'administrateur, le symétrique. MUTATIONS : `BU2_VUE_SANS_PERIMETRE`, `BU2_VUE_SANS_ADMIN`,
    /// `BU2_VUE_SANS_COMMUNE`, `BU2_VUE_SANS_PROPRIO`, `BU2_AUCUNE_SANS_PERIMETRE`, `BU2_AUCUNE_SANS_ADMIN`,
    /// `BU2_AUCUNE_SANS_COMMUNE`, `BU2_AUCUNE_SANS_PROPRIO`.
    #[tokio::test]
    async fn bu2_liste_sous_une_vue_invisible_vaut_une_vue_inconnue() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = bu2_etat("liste-invisible");
        let (alice, bob, adm) = (sp_au("alice", "editor"), sp_au("bob", "editor"), sp_au("adm", "admin"));
        let pa = bu2_vue(&st, "Privée d'alice", "alice", "private");
        let s = bu2_vue(&st, "Commune de bob", "bob", "shared");
        let pb = bu2_vue(&st, "Privée de bob", "bob", "private");
        let c_pa = bu2_tableau(&st, "Dans PA", "", "shared", None);
        bu2_rattacher(&st, pa, c_pa);
        let c_s = bu2_tableau(&st, "Dans S", "", "shared", None);
        bu2_rattacher(&st, s, c_s);
        let c_pb = bu2_tableau(&st, "Dans PB", "", "shared", None);
        bu2_rattacher(&st, pb, c_pb);
        let t = bu2_tableau(&st, "Toutes", "", "shared", None);
        bu2_ecrire(&st, &format!("UPDATE dashboard SET all_views=1 WHERE id={t}"));
        let n = bu2_tableau(&st, "Sans vue", "", "shared", None);
        // La vue invisible a le corps ENTIER de la vue absente.
        let invisible = bu2_liste(&st, &alice, &pb.to_string()).await;
        let absente = bu2_liste(&st, &alice, &BU2_ABSENT_ID.to_string()).await;
        assert_eq!(absente.0, 200, "fixture : une vue absente rend 200 : {}", absente.1);
        assert_eq!(absente.1["total"], json!(1), "fixture : sous une vue absente, T seul : {}", absente.1);
        assert_eq!(invisible, absente, "la vue privée de bob a, pour alice, le corps d'une vue absente");
        // Alice.
        assert_eq!(bu2_ids(&st, &alice, &s.to_string()).await, vec![c_s, t], "alice voit la vue commune de bob");
        assert_eq!(bu2_ids(&st, &alice, &pa.to_string()).await, vec![c_pa, t], "alice voit sa vue privée");
        assert_eq!(bu2_ids(&st, &alice, "none").await, vec![c_pb, n], "alice : rangé dans PB seulement = sans vue");
        // Bob.
        assert_eq!(bu2_ids(&st, &bob, &pb.to_string()).await, vec![c_pb, t], "bob voit sa vue privée");
        assert_eq!(bu2_ids(&st, &bob, &pa.to_string()).await, vec![t], "bob ne voit pas la vue privée d'alice");
        assert_eq!(bu2_ids(&st, &bob, "none").await, vec![c_pa, n], "bob : rangé dans PA seulement = sans vue");
        // L'administrateur voit tout.
        assert_eq!(bu2_ids(&st, &adm, &pb.to_string()).await, vec![c_pb, t]);
        assert_eq!(bu2_ids(&st, &adm, &pa.to_string()).await, vec![c_pa, t]);
        assert_eq!(bu2_ids(&st, &adm, "none").await, vec![n], "l'administrateur : seul N est sans vue");
    }

    /// CE QU'IL TIENT : par la ROUTE, au rôle le plus faible admis (viewer), `GET /api/dashboards?view=<vue privée d'un
    /// autre compte>` rend le statut et le corps entier de `?view=999999` : le tableau commun rangé dans la vue privée
    /// n'est pas servi. Contrôle : sans filtre, ce tableau est servi au même lecteur. MUTATION : `BU2_VUE_SANS_PERIMETRE`.
    #[tokio::test]
    async fn bu2_liste_par_la_route_une_vue_privee_d_autrui_vaut_une_vue_absente() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = router_test_state("bu2-route-vue-invisible");
        let (pv, d) = {
            let c = st.db.lock();
            c.execute("INSERT INTO view(name,owner,visibility) VALUES('Privée de bob','bob','private')", []).unwrap();
            let pv = c.last_insert_rowid();
            c.execute("INSERT INTO dashboard(name,created,owner,visibility,view_id,cols,height,collapsed) VALUES('Commun',1000,'','shared',?1,1,0,0)", params![pv]).unwrap();
            (pv, c.last_insert_rowid())
        };
        let addr = router_serve(st.clone()).await;
        let corps_de = |texte: &str| -> Value {
            let corps = texte.split_once("\r\n\r\n").map(|(_, c)| c).unwrap_or("");
            match (corps.find('{'), corps.rfind('}')) {
                (Some(a), Some(b)) if a < b => serde_json::from_str(&corps[a..=b]).unwrap_or_else(|_| json!({ "_texte": texte })),
                _ => json!({ "_texte": texte }),
            }
        };
        let (code, texte) = router_probe_envoi(addr, "GET", "/api/dashboards", Some(&viewer_authz()), &[], "").await;
        assert_eq!(code, 200, "{texte}");
        assert!(corps_de(&texte)["dashboards"].as_array().is_some_and(|l| l.iter().any(|x| x["id"] == json!(d))), "contrôle : servi sans filtre : {texte}");
        let (code_p, texte_p) = router_probe_envoi(addr, "GET", &format!("/api/dashboards?view={pv}"), Some(&viewer_authz()), &[], "").await;
        let (code_a, texte_a) = router_probe_envoi(addr, "GET", &format!("/api/dashboards?view={BU2_ABSENT_ID}"), Some(&viewer_authz()), &[], "").await;
        assert_eq!(
            (code_p, corps_de(&texte_p)),
            (200, json!({ "dashboards": [], "me": "vwr", "role": "viewer", "total": 0, "limit": null, "offset": 0 })),
            "la vue privée d'autrui : corps entier"
        );
        assert_eq!((code_p, corps_de(&texte_p)), (code_a, corps_de(&texte_a)), "identique à une vue absente");
    }

    // -------------------------------------------------------------------------------------
    // (3) `view_id` d'une modification ou d'une création : une vue invisible est une vue inconnue
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : alice range son tableau par `view_id` : la vue privée de bob et un identifiant absent rendent le
    /// MÊME 404 nommé, et le nom envoyé dans le même corps n'est pas écrit (ni vue principale, ni jointure) ; la vue
    /// commune de bob et sa propre vue privée s'écrivent (204) ; l'administrateur range dans la vue privée de bob (204) ;
    /// `view_id: null` reste admis. MUTATIONS : `BU2_MAJ_VUE_SANS_CONTROLE`, `BU2_VUE_VISIBLE_SANS_ADMIN`,
    /// `BU2_VUE_VISIBLE_SANS_COMMUNE`, `BU2_VUE_VISIBLE_SANS_PROPRIO`.
    #[tokio::test]
    async fn bu2_modifier_vers_une_vue_invisible_est_refuse_rien_n_est_ecrit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = bu2_etat("maj-vue-invisible");
        let (alice, adm) = (sp_au("alice", "editor"), sp_au("adm", "admin"));
        let pa = bu2_vue(&st, "Privée d'alice", "alice", "private");
        let s = bu2_vue(&st, "Commune de bob", "bob", "shared");
        let pb = bu2_vue(&st, "Privée de bob", "bob", "private");
        let d = bu2_tableau(&st, "avant", "alice", "shared", None);
        let attendu = (404, json!({ "error": BU2_VUE_DU_TABLEAU_INCONNUE }));
        assert_eq!(bu2_modifier(&st, &alice, d, json!({ "name": "après", "view_id": pb })).await, attendu, "vue privée de bob");
        assert_eq!(bu2_modifier(&st, &alice, d, json!({ "name": "après", "view_id": BU2_ABSENT_ID })).await, attendu, "vue absente");
        assert_eq!((bu2_ligne(&st, d), bu2_rattachements(&st)), (("avant".to_string(), None), vec![]), "rien du corps n'est écrit");
        let (code, corps) = bu2_modifier(&st, &alice, d, json!({ "view_id": s })).await;
        assert_eq!(code, 204, "la vue commune de bob : {corps}");
        assert_eq!(bu2_ligne(&st, d).1, Some(s));
        let (code, corps) = bu2_modifier(&st, &alice, d, json!({ "view_id": pa })).await;
        assert_eq!(code, 204, "sa propre vue privée : {corps}");
        assert_eq!(bu2_ligne(&st, d).1, Some(pa));
        let (code, corps) = bu2_modifier(&st, &adm, d, json!({ "view_id": pb })).await;
        assert_eq!(code, 204, "l'administrateur voit la vue privée de bob : {corps}");
        assert_eq!((bu2_ligne(&st, d).1, bu2_rattachements(&st)), (Some(pb), vec![(pb, d)]));
        let (code, corps) = bu2_modifier(&st, &alice, d, json!({ "view_id": null })).await;
        assert_eq!(code, 204, "view_id: null reste admis : {corps}");
        assert_eq!(bu2_ligne(&st, d).1, None);
    }

    /// CE QU'IL TIENT : alice crée un tableau rangé dans la vue privée de bob, puis sous un identifiant absent : même 404
    /// nommé, aucune ligne créée ; dans la vue commune de bob, 200 et rattaché par la jointure. MUTATION :
    /// `BU2_CREATION_VUE_SANS_CONTROLE`.
    #[tokio::test]
    async fn bu2_creer_dans_une_vue_invisible_est_refuse_rien_n_est_cree() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = bu2_etat("creation-vue-invisible");
        let alice = sp_au("alice", "editor");
        let s = bu2_vue(&st, "Commune de bob", "bob", "shared");
        let pb = bu2_vue(&st, "Privée de bob", "bob", "private");
        let attendu = (404, json!({ "error": BU2_VUE_DU_TABLEAU_INCONNUE }));
        assert_eq!(bu2_creer(&st, &alice, json!({ "name": "X", "visibility": "shared", "view_id": pb })).await, attendu, "vue privée de bob");
        assert_eq!(bu2_creer(&st, &alice, json!({ "name": "X", "visibility": "shared", "view_id": BU2_ABSENT_ID })).await, attendu, "vue absente");
        assert_eq!((bu2_entier(&st, "SELECT COUNT(*) FROM dashboard"), bu2_rattachements(&st)), (0, vec![]), "rien n'est créé");
        let (code, corps) = bu2_creer(&st, &alice, json!({ "name": "X", "visibility": "shared", "view_id": s })).await;
        assert_eq!(code, 200, "la vue commune de bob : {corps}");
        let id = corps["id"].as_i64().unwrap();
        assert_eq!(bu2_rattachements(&st), vec![(s, id)]);
    }

    /// CE QU'IL TIENT : la vue visée illisible -> 503 nommé (corps exact), à la modification (le nom n'est pas écrit) et
    /// à la création (aucune ligne) ; jamais le 404 d'une vue inconnue. MUTATION : `BU2_VUE_ILLISIBLE_INCONNUE`.
    #[tokio::test]
    async fn bu2_vue_du_tableau_illisible_503_rien_n_est_ecrit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = bu2_etat("vue-du-tableau-illisible");
        let alice = sp_au("alice", "editor");
        let pb = bu2_vue(&st, "Privée de bob", "bob", "private");
        let d = bu2_tableau(&st, "avant", "alice", "shared", None);
        bu2_rendre_illisible(&st, "view", &format!("id, name, owner, {BU2_DEBORDE} AS visibility, created"));
        let (c1, b1) = bu2_modifier(&st, &alice, d, json!({ "name": "après", "view_id": pb })).await;
        let (c2, b2) = bu2_creer(&st, &alice, json!({ "name": "X", "visibility": "shared", "view_id": pb })).await;
        bu2_rendre_lisible(&st, "view");
        bu2_cinq_cent_trois(c1, &b1, BU2_VUE_DU_TABLEAU_NON_LUE);
        bu2_cinq_cent_trois(c2, &b2, BU2_VUE_DU_TABLEAU_NON_LUE);
        assert!(st.db.lock().is_autocommit(), "transaction close");
        assert_eq!((bu2_ligne(&st, d), bu2_entier(&st, "SELECT COUNT(*) FROM dashboard")), (("avant".to_string(), None), 1), "rien n'est écrit");
    }

    // -------------------------------------------------------------------------------------
    // (4) v125 : l'index par tableau
    // -------------------------------------------------------------------------------------

    fn bu2_index_par_tableau(st: &AppState) -> i64 {
        bu2_entier(
            st,
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='view_dashboard_par_tableau' AND tbl_name='view_dashboard' \
             AND sql LIKE '%view_dashboard(dashboard_id)%'",
        )
    }

    /// CE QU'IL TIENT : une base v124 (sans jointure) migrée à v125 porte `view_dashboard_par_tableau` sur
    /// `view_dashboard(dashboard_id)` ; un second passage (base rendue à 124) le garde, un seul ; une base neuve le
    /// porte ; le plan de « les vues de ce tableau » l'emprunte. MUTATION : `BU2_SANS_INDEX`.
    #[tokio::test]
    async fn bu2_v125_pose_l_index_des_rattachements_par_tableau() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // la migration lit l'environnement
        let (neuve, _pn) = bu2_etat("index-neuve");
        assert_eq!(bu2_index_par_tableau(&neuve), 1, "base neuve : l'index est posé");
        let (st, _p) = bu2_etat("index-v124");
        bu2_ecrire(
            &st,
            "DROP TRIGGER IF EXISTS view_dashboard_suit_l_insertion; DROP TRIGGER IF EXISTS view_dashboard_suit_la_vue_principale; \
             DROP TRIGGER IF EXISTS view_dashboard_suit_l_effacement; DROP TABLE view_dashboard; ALTER TABLE dashboard DROP COLUMN all_views; \
             UPDATE meta SET value='124' WHERE key='schema_version';",
        );
        assert_eq!(bu2_entier(&st, "SELECT COUNT(*) FROM sqlite_master WHERE name='view_dashboard_par_tableau'"), 0, "fixture : base v124 sans index");
        assert!(migrate(&st.db.lock()), "v125 passe");
        assert_eq!(read_schema_version(&st.db.lock()), 125);
        assert_eq!(bu2_index_par_tableau(&st), 1, "v125 pose l'index");
        bu2_ecrire(&st, "UPDATE meta SET value='124' WHERE key='schema_version';");
        assert!(migrate(&st.db.lock()), "le second passage aboutit");
        assert_eq!(bu2_entier(&st, "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND tbl_name='view_dashboard' AND name='view_dashboard_par_tableau'"), 1, "un seul, gardé");
        let plan: Vec<String> = {
            let c = st.db.lock();
            let mut s = c.prepare("EXPLAIN QUERY PLAN SELECT view_id FROM view_dashboard WHERE dashboard_id=?1").unwrap();
            s.query_map(params![1], |r| r.get::<_, String>(3)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
        };
        assert!(plan.iter().any(|l| l.contains("view_dashboard_par_tableau")), "la lecture par tableau emprunte l'index : {plan:?}");
    }
}
