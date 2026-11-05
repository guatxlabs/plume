// =====================================================================================
// `P11.25-f` (troisième passe) — UN RATTACHEMENT POSÉ PAR LA ROUTE N'EST PAS UNE VUE PRINCIPALE, ET UNE VUE QUE
// L'APPELANT NE VOIT PAS RÉPOND COMME UNE VUE ABSENTE.
//
// CE QUE CES TÉMOINS TIENNENT :
//   * `view_dashboard.explicite` (v125) : un rattachement posé par `POST /api/views/{B}/dashboards` survit au passage
//     de la vue principale par B (A -> B -> A, nulle -> B -> nulle) ; une ligne qui n'existait que comme vue
//     principale est relevée à explicite par la même route (servie sous `already_present`) et survit ensuite ; les
//     déclencheurs ne posent que des lignes à 0 (un déplacement sans la route ne laisse rien derrière lui) ; v125
//     remplit les lignes migrées depuis `dashboard.view_id` à 0 et ajoute la colonne à une jointure née sans elle ;
//     le relèvement refusé (ignoré ou annulé par la base) -> 503 nommé, tout ou rien ;
//   * `DELETE /api/views/{id}/dashboards/{dashboard_id}` retire la ligne QUELLE QUE SOIT SON ORIGINE (principale,
//     explicite, ou les deux) et vide la vue principale quand c'était elle ; un rattachement explicite à une vue
//     secondaire se retire sans toucher la principale ;
//   * `POST` et `DELETE` des rattachements : une vue privée d'un autre compte rend le statut ET le corps d'une vue
//     absente (404 nommé), rien n'est écrit ni retiré ; une vue visible dont l'appelant n'est pas propriétaire (commune
//     d'un autre compte, ou semée sans propriétaire) se complète et se vide de ses tableaux qu'il peut modifier (porte
//     alignée sur `dash_update` `view_id` ; la forme d'avant rendait 403) ; chaque membre du périmètre de visibilité
//     (administrateur, vue commune, vue de l'appelant) a son cas ; par le gestionnaire et par le routeur réel ;
//   * `GET /api/dashboards` : `view_id` d'une vue que l'appelant ne voit pas (ou qu'aucune vue ne porte) est servi
//     nul, comme `view_ids` la tait ; chaque membre du périmètre a son cas ; par le gestionnaire et par la route au
//     rôle le plus faible (corps entier de l'entrée).
//
// CE QU'ILS NE TIENNENT PAS : ce que la console peint de ces réponses (aucun volet console ici) ; `view_update`,
// `view_delete` (403 sur une vue privée d'autrui, préexistants). `dash_get` masque désormais `view_id` comme
// `dash_list` : témoins dans portes_des_rattachements_alignees_et_vue_masquee.rs.
//
// MUTATIONS (`VERIF_MUT=<nom>`, posées sous `cfg!(test)` le temps de la vérification puis retirées) : chaque
// témoin nomme les siennes.
// =====================================================================================
mod rattachement_explicite_et_vue_invisible_sans_oracle {
    use super::*;

    const BV2_VUE_INCONNUE: &str = "VUE INCONNUE : aucune vue que vous voyez ne porte cet identifiant — rien n'est rattaché ni retiré.";
    const BV2_INCHANGES: &str = "RATTACHEMENTS INCHANGÉS : la base n'a pas pris l'écriture d'un rattachement ou son effacement, et la transaction est annulée — la vue garde exactement ses rattachements d'avant (tout ou rien). Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
    /// Un identifiant qu'aucune vue ne porte.
    const BV2_ABSENTE: i64 = 999_999;

    fn bv2_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(&format!("bv2-{tag}"));
        bv2_ecrire(&st, "DELETE FROM panel; DELETE FROM dashboard; DELETE FROM view_dashboard; DELETE FROM view;");
        (st, p)
    }

    fn bv2_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn bv2_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn bv2_vue(st: &AppState, nom: &str, owner: &str, vis: &str) -> i64 {
        let c = st.db.lock();
        c.execute("INSERT INTO view(name,owner,visibility) VALUES(?1,?2,?3)", params![nom, owner, vis]).expect("fixture : vue");
        c.last_insert_rowid()
    }

    fn bv2_tableau(st: &AppState, nom: &str, vue: Option<i64>) -> i64 {
        let c = st.db.lock();
        c.execute(
            "INSERT INTO dashboard(name,created,owner,visibility,view_id,cols,height,collapsed) VALUES(?1,1000,'','shared',?2,1,0,0)",
            params![nom, vue],
        )
        .expect("fixture : tableau");
        c.last_insert_rowid()
    }

    /// Les rattachements avec leur origine : `(vue, tableau, explicite)`.
    fn bv2_lignes(st: &AppState) -> Vec<(i64, i64, i64)> {
        let c = st.db.lock();
        let mut s = c.prepare("SELECT view_id,dashboard_id,explicite FROM view_dashboard ORDER BY view_id,dashboard_id").unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    fn bv2_principale(st: &AppState, tableau: i64) -> Option<i64> {
        st.db.lock().query_row("SELECT view_id FROM dashboard WHERE id=?1", params![tableau], |r| r.get(0)).unwrap()
    }

    async fn bv2_ajouter(st: &AppState, au: &AuthUser, vue: i64, ids: &[i64]) -> (u16, Value) {
        pb_json(view_dashboards_add(State(st.clone()), Extension(au.clone()), Path(vue), Json(json!({ "dashboard_ids": ids }))).await).await
    }

    async fn bv2_retirer(st: &AppState, au: &AuthUser, vue: i64, tableau: i64) -> (u16, Value) {
        pb_json(view_dashboard_remove(State(st.clone()), Extension(au.clone()), Path((vue, tableau))).await).await
    }

    async fn bv2_vue_principale_vers(st: &AppState, au: &AuthUser, tableau: i64, vue: Value) {
        let r = dash_update(State(st.clone()), Extension(au.clone()), Path(tableau), Json(json!({ "view_id": vue }))).await;
        assert_eq!(r.status().as_u16(), 204, "fixture : la vue principale de #{tableau} passe à {vue}");
    }

    /// Les tableaux servis sous `?view=<vue>` (vu par l'administrateur, qui voit toutes les vues).
    async fn bv2_sous(st: &AppState, vue: &str) -> Vec<i64> {
        let q: HashMap<String, String> = [("view".to_string(), vue.to_string())].into_iter().collect();
        let r = dash_list(State(st.clone()), Extension(sp_au("adm", "admin")), Query(q)).await;
        assert_eq!(r.1.as_u16(), 200, "liste sous ?view={vue} : {}", r.0);
        r.0["dashboards"].as_array().unwrap_or_else(|| panic!("{}", r.0)).iter().map(|d| d["id"].as_i64().unwrap()).collect()
    }

    /// `view_id` servi par `dash_list` pour chaque tableau, vu par `au`.
    async fn bv2_view_id_servi(st: &AppState, au: &AuthUser) -> Vec<(i64, Value)> {
        let r = dash_list(State(st.clone()), Extension(au.clone()), Query(HashMap::new())).await;
        assert_eq!(r.1.as_u16(), 200, "{}", r.0);
        r.0["dashboards"].as_array().unwrap_or_else(|| panic!("{}", r.0)).iter().map(|d| (d["id"].as_i64().unwrap(), d["view_id"].clone())).collect()
    }

    // -------------------------------------------------------------------------------------
    // (1) l'origine d'un rattachement
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : les deux séquences de la sonde de l'avis. D, vue principale A, rangé dans B par la route
    /// (ligne explicite) ; la vue principale passe A -> B -> A : (B, D) reste, servi sous B. E sans vue, rangé dans B par
    /// la route ; nulle -> B -> nulle : (B, E) reste. MUTATIONS : `BV2_DEPLACEMENT_EFFACE_L_EXPLICITE` (le déclencheur
    /// efface sans regarder l'origine), `BV2_AJOUT_SANS_EXPLICITE` (la route pose une ligne à 0).
    #[tokio::test]
    async fn bv2_rattachement_pose_par_la_route_survit_au_passage_de_la_vue_principale() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l\'environnement
        let (st, _p) = bv2_etat("passage");
        let alice = sp_au("alice", "editor");
        let a = bv2_vue(&st, "A", "alice", "shared");
        let b = bv2_vue(&st, "B", "alice", "shared");
        let d = bv2_tableau(&st, "D", Some(a));
        let e = bv2_tableau(&st, "E", None);
        assert_eq!(bv2_ajouter(&st, &alice, b, &[d, e]).await, (200, json!({ "added": [d, e], "already_present": [] })));
        assert_eq!(bv2_lignes(&st), vec![(a, d, 0), (b, d, 1), (b, e, 1)], "la route pose des lignes explicites");
        bv2_vue_principale_vers(&st, &alice, d, json!(b)).await;
        bv2_vue_principale_vers(&st, &alice, d, json!(a)).await;
        bv2_vue_principale_vers(&st, &alice, e, json!(b)).await;
        bv2_vue_principale_vers(&st, &alice, e, Value::Null).await;
        assert_eq!(bv2_lignes(&st), vec![(a, d, 0), (b, d, 1), (b, e, 1)], "A -> B -> A et nulle -> B -> nulle gardent (B, D) et (B, E)");
        assert_eq!((bv2_principale(&st, d), bv2_principale(&st, e)), (Some(a), None));
        assert_eq!(bv2_sous(&st, &b.to_string()).await, vec![d, e], "servis sous B");
    }

    /// CE QU'IL TIENT : D n'est dans B que comme vue principale (ligne à 0) ; la route le confirme dans B -> 200,
    /// `already_present`, la ligne passe à 1 ; la vue principale part vers A : (B, D) reste. MUTATION :
    /// `BV2_AJOUT_SANS_CONFIRMER`.
    #[tokio::test]
    async fn bv2_confirmer_une_vue_principale_la_rend_explicite() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l\'environnement
        let (st, _p) = bv2_etat("confirmer");
        let alice = sp_au("alice", "editor");
        let a = bv2_vue(&st, "A", "alice", "shared");
        let b = bv2_vue(&st, "B", "alice", "shared");
        let d = bv2_tableau(&st, "D", Some(b));
        assert_eq!(bv2_lignes(&st), vec![(b, d, 0)], "fixture : vue principale seule");
        assert_eq!(bv2_ajouter(&st, &alice, b, &[d]).await, (200, json!({ "added": [], "already_present": [d] })));
        assert_eq!(bv2_lignes(&st), vec![(b, d, 1)], "relevée à explicite");
        bv2_vue_principale_vers(&st, &alice, d, json!(a)).await;
        assert_eq!(bv2_lignes(&st), vec![(a, d, 0), (b, d, 1)], "le rattachement confirmé survit au déplacement");
    }

    /// CE QU'IL TIENT : le relèvement d'une ligne principale ignoré par la base (zéro ligne), puis refusé (ABORT) ->
    /// 503 nommé, corps exact, et le rattachement neuf de la même demande est annulé (tout ou rien) : la ligne reste à
    /// 0, aucune ligne neuve. MUTATIONS : `BV2_CONFIRMATION_SANS_COMPTE` (zéro ligne admis),
    /// `BV2_CONFIRMATION_AVALEE` (l'issue du relèvement jetée).
    #[tokio::test]
    async fn bv2_confirmation_refusee_rien_n_est_ecrit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l\'environnement
        let (st, _p) = bv2_etat("confirmer-refus");
        let alice = sp_au("alice", "editor");
        let b = bv2_vue(&st, "B", "alice", "shared");
        let d = bv2_tableau(&st, "D", Some(b));
        let e = bv2_tableau(&st, "E", None);
        bv2_ecrire(&st, "CREATE TEMP TRIGGER bv2_refus BEFORE UPDATE ON main.view_dashboard BEGIN SELECT RAISE(IGNORE); END;");
        let (code, corps) = bv2_ajouter(&st, &alice, b, &[e, d]).await;
        bv2_ecrire(&st, "DROP TRIGGER bv2_refus;");
        bv2_cinq_cent_trois_inchanges(code, &corps, "ignoré");
        assert_eq!(bv2_lignes(&st), vec![(b, d, 0)], "relèvement ignoré : rien n'est écrit, E n'est pas rattaché");
        bv2_ecrire(&st, "CREATE TEMP TRIGGER bv2_refus BEFORE UPDATE ON main.view_dashboard BEGIN SELECT RAISE(ABORT, 'refus de témoin'); END;");
        let (code, corps) = bv2_ajouter(&st, &alice, b, &[e, d]).await;
        bv2_ecrire(&st, "DROP TRIGGER bv2_refus;");
        bv2_cinq_cent_trois_inchanges(code, &corps, "refusé");
        assert_eq!(bv2_lignes(&st), vec![(b, d, 0)], "relèvement refusé : rien n'est écrit, E n'est pas rattaché");
    }

    /// Le 503 d'un relèvement refusé : la phrase exacte et un identifiant de corrélation, rien d'autre.
    fn bv2_cinq_cent_trois_inchanges(code: u16, corps: &Value, cas: &str) {
        assert_eq!(code, 503, "relèvement {cas} : {corps}");
        assert_eq!(corps["error"], json!(BV2_INCHANGES), "relèvement {cas} : phrase exacte");
        assert!(corps["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "relèvement {cas} : identifiant de corrélation : {corps}");
        assert_eq!(corps.as_object().map(|o| o.len()), Some(2), "relèvement {cas} : `error` et `id` seuls : {corps}");
    }

    /// CE QU'IL TIENT : les déclencheurs ne posent que des lignes à 0 : D créé par la route de création dans A puis
    /// déplacé vers B ne reste pas dans A, puis vers nulle ne reste nulle part ; E sans vue, nulle -> B -> nulle, ne
    /// laisse rien. MUTATIONS : `BV2_INSERTION_POSE_EXPLICITE`, `BV2_DEPLACEMENT_POSE_EXPLICITE`.
    #[tokio::test]
    async fn bv2_deplacement_sans_la_route_ne_laisse_rien() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l\'environnement
        let (st, _p) = bv2_etat("sans-route");
        let alice = sp_au("alice", "editor");
        let a = bv2_vue(&st, "A", "alice", "shared");
        let b = bv2_vue(&st, "B", "alice", "shared");
        let (code, cree) = pb_json(dash_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "D", "visibility": "shared", "view_id": a }))).await).await;
        assert_eq!(code, 200, "{cree}");
        let d = cree["id"].as_i64().unwrap();
        assert_eq!(bv2_lignes(&st), vec![(a, d, 0)], "la création pose une ligne principale");
        bv2_vue_principale_vers(&st, &alice, d, json!(b)).await;
        assert_eq!(bv2_lignes(&st), vec![(b, d, 0)], "déplacée : rien ne reste dans A");
        bv2_vue_principale_vers(&st, &alice, d, Value::Null).await;
        let e = bv2_tableau(&st, "E", None);
        bv2_vue_principale_vers(&st, &alice, e, json!(b)).await;
        assert_eq!(bv2_lignes(&st), vec![(b, e, 0)]);
        bv2_vue_principale_vers(&st, &alice, e, Value::Null).await;
        assert_eq!(bv2_lignes(&st), Vec::<(i64, i64, i64)>::new(), "nulle -> B -> nulle sans la route : rien ne reste");
    }

    /// CE QU'IL TIENT : une base v124 (D rangé dans B par `view_id`) migre à v125 avec la ligne (B, D) à 0 : c'est une
    /// vue principale, et la déplacer vers A ne la laisse pas dans B. Une jointure née sans la colonne (passage
    /// antérieur) la reçoit, ses lignes à 0. MUTATIONS : `BV2_V125_REMPLI_EXPLICITE`, `BV2_V125_SANS_COLONNE_TARDIVE`.
    #[tokio::test]
    async fn bv2_v125_remplit_les_vues_principales_a_zero() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l\'environnement
        let (st, _p) = bv2_etat("v124");
        let vers_v124 = "DROP TRIGGER IF EXISTS view_dashboard_suit_l_insertion; DROP TRIGGER IF EXISTS view_dashboard_suit_la_vue_principale; \
             DROP TRIGGER IF EXISTS view_dashboard_suit_l_effacement; DROP TABLE view_dashboard; ALTER TABLE dashboard DROP COLUMN all_views; \
             UPDATE meta SET value='124' WHERE key='schema_version';";
        bv2_ecrire(&st, vers_v124);
        let a = bv2_vue(&st, "A", "", "shared");
        let b = bv2_vue(&st, "B", "", "shared");
        let d = bv2_tableau(&st, "D", Some(b));
        assert!(migrate(&st.db.lock()), "v125 passe");
        assert_eq!(bv2_lignes(&st), vec![(b, d, 0)], "la ligne migrée est une vue principale");
        bv2_vue_principale_vers(&st, &sp_au("adm", "admin"), d, json!(a)).await;
        assert_eq!(bv2_lignes(&st), vec![(a, d, 0)], "déplacée, elle quitte B");
        // Une jointure née sans `explicite` (un passage antérieur de la migration).
        bv2_ecrire(&st, vers_v124);
        bv2_ecrire(&st, &format!("CREATE TABLE view_dashboard(view_id INTEGER NOT NULL, dashboard_id INTEGER NOT NULL, PRIMARY KEY(view_id, dashboard_id)); INSERT INTO view_dashboard VALUES({b},{d});"));
        assert!(migrate(&st.db.lock()), "v125 passe sur une jointure sans la colonne");
        assert_eq!(bv2_entier(&st, "SELECT COUNT(*) FROM pragma_table_info('view_dashboard') WHERE name='explicite'"), 1, "la colonne est ajoutée");
        assert_eq!(bv2_lignes(&st), vec![(a, d, 0), (b, d, 0)], "ses lignes valent 0");
    }

    // -------------------------------------------------------------------------------------
    // (2) le retrait explicite
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la sémantique du retrait. D est dans B comme vue principale ET explicite : DELETE -> 204, la
    /// ligne part, la vue principale est vidée, D n'est plus servi sous B mais sous `none`. E, vue principale seule
    /// dans B : DELETE -> 204, idem. F, vue principale A et explicite dans B : DELETE (B, F) -> 204, A reste.
    /// MUTATIONS : `BV2_RETRAIT_RABAISSE_LA_PRINCIPALE` (le retrait d'une ligne principale ne fait que la rabaisser à
    /// 0), `BV2_RETRAIT_EXPLICITE_SEUL` (le retrait n'efface que les lignes explicites).
    #[tokio::test]
    async fn bv2_retrait_explicite_retire_la_ligne_meme_principale() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l\'environnement
        let (st, _p) = bv2_etat("retrait");
        let alice = sp_au("alice", "editor");
        let a = bv2_vue(&st, "A", "alice", "shared");
        let b = bv2_vue(&st, "B", "alice", "shared");
        let d = bv2_tableau(&st, "D", Some(b));
        let e = bv2_tableau(&st, "E", Some(b));
        let f = bv2_tableau(&st, "F", Some(a));
        assert_eq!(bv2_ajouter(&st, &alice, b, &[d, f]).await, (200, json!({ "added": [f], "already_present": [d] })));
        assert_eq!(bv2_lignes(&st), vec![(a, f, 0), (b, d, 1), (b, e, 0), (b, f, 1)], "fixture");
        assert_eq!(bv2_retirer(&st, &alice, b, d).await.0, 204);
        assert_eq!((bv2_lignes(&st), bv2_principale(&st, d)), (vec![(a, f, 0), (b, e, 0), (b, f, 1)], None), "principale et explicite : la ligne part, la principale est vidée");
        assert_eq!(bv2_retirer(&st, &alice, b, e).await.0, 204);
        assert_eq!((bv2_lignes(&st), bv2_principale(&st, e)), (vec![(a, f, 0), (b, f, 1)], None), "principale seule : idem");
        assert_eq!(bv2_retirer(&st, &alice, b, f).await.0, 204);
        assert_eq!((bv2_lignes(&st), bv2_principale(&st, f)), (vec![(a, f, 0)], Some(a)), "explicite hors principale : la principale reste");
        assert_eq!(bv2_sous(&st, &b.to_string()).await, Vec::<i64>::new(), "plus rien sous B");
        assert_eq!(bv2_sous(&st, "none").await, vec![d, e], "D et E n'ont plus de vue");
    }

    // -------------------------------------------------------------------------------------
    // (3) une vue invisible est une vue absente
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : alice, sur la vue PRIVÉE de bob : POST et DELETE rendent exactement la réponse d'une vue
    /// absente (404, corps entier), rien n'est rattaché ni retiré. INVERSÉ (porte alignée sur `dash_update` `view_id`) :
    /// sur la vue COMMUNE de bob et sur une vue semée (sans propriétaire), qu'elle voit sans en être propriétaire, elle
    /// rattache D (commun) — 200 — et retire R (commun) — 204 ; la forme d'avant rendait 403. Sur SA vue privée : 200.
    /// L'administrateur, sur la vue privée de bob : 200. MUTATIONS : `BV2_PORTE_INVISIBLE_403` (la forme d'avant),
    /// `BV2_PORTE_SANS_ADMIN`, `BV2_PORTE_SANS_COMMUNE`, `BV2_PORTE_SANS_PROPRIO`, `BX2_PORTE_PROPRIETAIRE`.
    #[tokio::test]
    async fn bv2_portes_des_rattachements_vue_invisible_comme_absente() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l\'environnement
        let (st, _p) = bv2_etat("portes");
        let (alice, adm) = (sp_au("alice", "editor"), sp_au("adm", "admin"));
        let pb = bv2_vue(&st, "privée de bob", "bob", "private");
        let sb = bv2_vue(&st, "commune de bob", "bob", "shared");
        let semee = bv2_vue(&st, "semée", "", "shared");
        let pa = bv2_vue(&st, "privée d'alice", "alice", "private");
        let d = bv2_tableau(&st, "D", None);
        let r = bv2_tableau(&st, "R", None);
        bv2_ecrire(&st, &format!("INSERT INTO view_dashboard(view_id,dashboard_id,explicite) VALUES({pb},{r},1),({sb},{r},1),({semee},{r},1)"));
        let absente = (404, json!({ "error": BV2_VUE_INCONNUE }));
        assert_eq!(bv2_ajouter(&st, &alice, BV2_ABSENTE, &[d]).await, absente, "fixture : la réponse d'une vue absente");
        assert_eq!(bv2_retirer(&st, &alice, BV2_ABSENTE, r).await, absente, "fixture : la réponse d'une vue absente");
        assert_eq!(bv2_ajouter(&st, &alice, pb, &[d]).await, absente, "POST, vue privée d'autrui = vue absente");
        assert_eq!(bv2_retirer(&st, &alice, pb, r).await, absente, "DELETE, vue privée d'autrui = vue absente");
        let avant = vec![(pb, r, 1), (sb, r, 1), (semee, r, 1)];
        assert_eq!(bv2_lignes(&st), avant, "rien n'est rattaché ni retiré");
        let ajoute = (200, json!({ "added": [d], "already_present": [] }));
        assert_eq!(bv2_ajouter(&st, &alice, sb, &[d]).await, ajoute, "POST, vue commune de bob : visible, D modifiable");
        assert_eq!(bv2_retirer(&st, &alice, sb, r).await.0, 204, "DELETE, vue commune de bob : visible, R modifiable");
        assert_eq!(bv2_ajouter(&st, &alice, semee, &[d]).await, ajoute, "POST, vue semée : visible, D modifiable");
        assert_eq!(bv2_retirer(&st, &alice, semee, r).await.0, 204, "DELETE, vue semée : visible, R modifiable");
        assert_eq!(bv2_ajouter(&st, &alice, pa, &[d]).await, ajoute, "sa vue privée");
        assert_eq!(bv2_ajouter(&st, &adm, pb, &[d]).await, ajoute, "l'administrateur voit tout");
        assert_eq!(bv2_lignes(&st), vec![(pb, d, 1), (pb, r, 1), (sb, d, 1), (semee, d, 1), (pa, d, 1)]);
    }

    /// CE QU'IL TIENT : `dash_list` sert `view_id` nul quand la vue principale est une vue que l'appelant ne voit pas,
    /// ou qu'aucune vue ne porte : alice ne reçoit pas la vue privée de bob, reçoit la commune de bob et la sienne ; bob
    /// reçoit la sienne, pas celle d'alice ; l'administrateur toutes, sauf l'identifiant qu'aucune vue ne porte.
    /// MUTATIONS : `BV2_VIEW_ID_BRUT` (la forme d'avant), `BV2_VIEW_ID_SANS_ADMIN`, `BV2_VIEW_ID_SANS_COMMUNE`,
    /// `BV2_VIEW_ID_SANS_PROPRIO`.
    #[tokio::test]
    async fn bv2_liste_view_id_d_une_vue_invisible_est_nul() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l\'environnement
        let (st, _p) = bv2_etat("liste-view-id");
        let pb = bv2_vue(&st, "privée de bob", "bob", "private");
        let sb = bv2_vue(&st, "commune de bob", "bob", "shared");
        let pa = bv2_vue(&st, "privée d'alice", "alice", "private");
        let dpb = bv2_tableau(&st, "Dpb", Some(pb));
        let dsb = bv2_tableau(&st, "Dsb", Some(sb));
        let dpa = bv2_tableau(&st, "Dpa", Some(pa));
        let dn = bv2_tableau(&st, "Dn", None);
        let dx = bv2_tableau(&st, "Dx", Some(BV2_ABSENTE));
        let n = Value::Null;
        assert_eq!(
            bv2_view_id_servi(&st, &sp_au("alice", "editor")).await,
            vec![(dpb, n.clone()), (dsb, json!(sb)), (dpa, json!(pa)), (dn, n.clone()), (dx, n.clone())],
            "alice"
        );
        assert_eq!(
            bv2_view_id_servi(&st, &sp_au("bob", "editor")).await,
            vec![(dpb, json!(pb)), (dsb, json!(sb)), (dpa, n.clone()), (dn, n.clone()), (dx, n.clone())],
            "bob"
        );
        assert_eq!(
            bv2_view_id_servi(&st, &sp_au("adm", "admin")).await,
            vec![(dpb, json!(pb)), (dsb, json!(sb)), (dpa, json!(pa)), (dn, n.clone()), (dx, n)],
            "l'administrateur"
        );
    }

    /// CE QU'IL TIENT : par le ROUTEUR réel. Le lecteur (rôle le plus faible admis à la liste) reçoit l'entrée ENTIÈRE
    /// d'un tableau commun dont la vue principale est la vue privée d'un autre compte, `view_id` nul et `view_ids`
    /// vides. Un éditeur, sur cette vue privée : POST et DELETE rendent le statut et le corps d'une vue absente, et
    /// rien n'est écrit ni retiré. MUTATIONS : `BV2_VIEW_ID_BRUT`, `BV2_PORTE_INVISIBLE_403`.
    #[tokio::test]
    async fn bv2_par_la_route_une_vue_invisible_est_absente() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l\'environnement
        let (st, _p) = router_test_state("bv2-route");
        let (privee, d) = {
            let c = st.db.lock();
            c.execute("INSERT INTO user(name,hash,role) VALUES('edt',?1,'editor')", params![hash_pw("editorpw12345").unwrap()]).unwrap();
            c.execute("INSERT INTO view(name,owner,visibility) VALUES('Privée d''autrui','autre','private')", []).unwrap();
            let privee = c.last_insert_rowid();
            c.execute("INSERT INTO dashboard(name,created,owner,visibility,view_id,cols,height,collapsed,position) VALUES('Commun',1000,'','shared',?1,1,0,0,7)", params![privee]).unwrap();
            (privee, c.last_insert_rowid())
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
        let liste = corps_de(&texte);
        let entree = liste["dashboards"].as_array().and_then(|l| l.iter().find(|x| x["id"] == json!(d)).cloned());
        assert_eq!(
            entree,
            Some(json!({
                "id": d, "name": "Commun", "owner": "", "visibility": "shared", "view_id": null, "panels": 0,
                "cols": 1, "height": 0, "collapsed": false, "position": 7, "editable": true,
                "all_views": false, "view_ids": []
            })),
            "entrée entière : {liste}"
        );
        let editeur = format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "edt:editorpw12345"));
        let en_json = [("Content-Type", "application/json")];
        let demande = format!("{{\"dashboard_ids\":[{d}]}}");
        let (c_abs, t_abs) = router_probe_envoi(addr, "POST", &format!("/api/views/{BV2_ABSENTE}/dashboards"), Some(&editeur), &en_json, &demande).await;
        let (c_inv, t_inv) = router_probe_envoi(addr, "POST", &format!("/api/views/{privee}/dashboards"), Some(&editeur), &en_json, &demande).await;
        assert_eq!((c_abs, corps_de(&t_abs)), (404, json!({ "error": BV2_VUE_INCONNUE })), "fixture : vue absente");
        assert_eq!((c_inv, corps_de(&t_inv)), (c_abs, corps_de(&t_abs)), "POST : vue invisible = vue absente");
        let (c_abs, t_abs) = router_probe_envoi(addr, "DELETE", &format!("/api/views/{BV2_ABSENTE}/dashboards/{d}"), Some(&editeur), &[], "").await;
        let (c_inv, t_inv) = router_probe_envoi(addr, "DELETE", &format!("/api/views/{privee}/dashboards/{d}"), Some(&editeur), &[], "").await;
        assert_eq!((c_abs, corps_de(&t_abs)), (404, json!({ "error": BV2_VUE_INCONNUE })), "fixture : vue absente");
        assert_eq!((c_inv, corps_de(&t_inv)), (c_abs, corps_de(&t_abs)), "DELETE : vue invisible = vue absente");
        assert_eq!(
            bv2_entier(&st, &format!("SELECT COUNT(*) FROM view_dashboard WHERE view_id={privee} AND dashboard_id={d} AND explicite=0")),
            1,
            "la ligne principale reste, non relevée"
        );
        assert_eq!(bv2_entier(&st, &format!("SELECT COUNT(*) FROM view_dashboard WHERE dashboard_id={d}")), 1);
    }
}
