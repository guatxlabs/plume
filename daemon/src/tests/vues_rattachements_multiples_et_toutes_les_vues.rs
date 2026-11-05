// =====================================================================================
// `P11.25-f` — UN TABLEAU DE BORD SE RANGE DANS PLUSIEURS VUES ; « TOUTES LES VUES » EST UN CHOIX
// DÉCLARÉ ; UNE VUE EXISTANTE SE COMPLÈTE AU LIEU D'ÊTRE DOUBLÉE ; LA LISTE SE PAGINE.
//
// CE QUE CES TÉMOINS TIENNENT :
//   * v125 sur une base v124 : `view_dashboard` remplie depuis `dashboard.view_id`, `all_views` à 0 partout — un
//     tableau sans vue n'était servi sous AUCUNE vue (`?view=<id>` filtrait `view_id = <id>`) et ne l'est toujours
//     pas ; des vues homonymes ne font pas échouer la migration ; un second passage ne retire rien ; base neuve :
//     les tableaux semés sont rattachés par la jointure (déclencheur sur `view_id`) ;
//   * les trois déclencheurs (insertion, déplacement de la vue principale, effacement : un rowid réutilisé
//     n'hérite de rien) ;
//   * `dash_list` : `?view=<id>` lit la jointure et `all_views`, `?view=none` les deux aussi ; `total` juste sur
//     une page pleine et sur une page vide ; borne refusée à 101 et à 0, admise à 100 ; filtre et décalage
//     invalides refusés ; la forme servie par la route au rôle le plus faible ;
//   * `all_views` à la création et à la modification, refus nommé de toute autre valeur ;
//   * le doublon de vue : 409 avec l'identifiant de l'existante, dans le périmètre de ce que le créateur voit,
//     jugé sous le verrou d'écriture (point de course entre le jugement et l'insertion) ; lecture, BEGIN et
//     COMMIT refusés ;
//   * `POST /api/views/{id}/dashboards` (ajout partiel, déjà présent, inconnu ou privé d'autrui : 404 sans
//     écriture, tout ou rien, corps invalide, borne, porte de la vue, lectures et écritures refusées) et
//     `DELETE /api/views/{id}/dashboards/{dashboard_id}` (vue principale vidée, absence lue) ;
//   * `view_delete` nettoie la jointure ; le décompte de `views_list` la lit ; la porte de partage d'une vue la lit ;
//   * (seconde passe) un tableau COMMUN rangé hors vue principale ne retient pas le partage ; retirer une vue
//     secondaire garde la vue principale ; les deux routes de rattachement passent par le routeur réel (porte de rôle
//     editor+) ; `view_ids` borné aux vues que l'appelant voit ; un renommage vers un homonyme visible -> 409.
//
// CE QU'ILS NE TIENNENT PAS : ce que la console peint de ces routes (aucun volet console dans ce lot) ; une base
// réellement en lecture seule (les écritures refusées sont jouées par déclencheurs et autorisateur).
//
// MUTATIONS (`VERIF_MUT=<nom>`, posées sous `cfg!(test)` le temps de la vérification puis retirées) : chaque
// témoin nomme les siennes.
// =====================================================================================
mod vues_rattachements_multiples_et_toutes_les_vues {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const BT2_TOUTES_LES_VUES_INVALIDE: &str = "« TOUTES LES VUES » INVALIDE : `all_views` vaut true ou false — rien n'est écrit.";
    const BT2_FILTRE_INVALIDE: &str = "FILTRE DE VUE INVALIDE : `view` vaut l'identifiant entier d'une vue ou `none` — rien n'est servi.";
    const BT2_DECALAGE_INVALIDE: &str = "DÉCALAGE INVALIDE : `offset` vaut un entier positif ou nul — rien n'est servi.";
    const BT2_LIMITE_HORS_BORNE: &str = "LIMITE HORS BORNE : `limit` vaut un entier de 1 à 100 — une page plus grande n'est pas servie tronquée, elle est refusée ; demandez la suite par `offset`.";
    const BT2_VUE_DEJA_EXISTANTE: &str = "VUE DÉJÀ EXISTANTE : une vue de ce nom existe déjà parmi celles que vous voyez — rien n'est créé. Complétez-la (POST /api/views/{id}/dashboards) ou choisissez un autre nom.";
    const BT2_HOMONYMES_NON_LUS: &str = "VUE NON CRÉÉE : la base n'a pas rendu les vues de ce nom — ce n'est PAS « aucune vue de ce nom », c'est une lecture qui n'a pas eu lieu, et le doublon n'est pas jugé. RIEN n'est créé. Réessayez ; si le refus persiste, la table des vues est illisible.";
    const BT2_VUE_NON_VALIDEE: &str = "VUE NON CRÉÉE : la base n'a pas validé la transaction (COMMIT refusé) et l'a annulée — la vue n'existe pas et AUCUN identifiant n'est rendu. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
    const BT2_VUE_BEGIN: &str = "VUE NON CRÉÉE : la base n'a pas pris la transaction de la création (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur l'écrivain) — RIEN n'est écrit. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";
    const BT2_VUE_INCONNUE: &str = "VUE INCONNUE : aucune vue que vous voyez ne porte cet identifiant — rien n'est rattaché ni retiré.";
    const BT2_TABLEAUX_INCONNUS: &str = "TABLEAU DE BORD INCONNU : au moins un identifiant demandé ne désigne aucun tableau de bord que vous voyez — RIEN n'est rattaché, aucun des autres non plus (tout ou rien).";
    const BT2_ABSENT: &str = "RATTACHEMENT ABSENT : ce tableau de bord n'est pas rangé dans cette vue — rien n'est retiré.";
    const BT2_CORPS_INVALIDE: &str = "CORPS INVALIDE : `dashboard_ids` vaut un tableau d'identifiants entiers de tableaux de bord — rien n'est rattaché.";
    const BT2_TROP: &str = "TROP DE RATTACHEMENTS : au plus 100 identifiants par demande — rien n'est rattaché ; envoyez la suite dans une autre demande.";
    const BT2_NON_LUS: &str = "RATTACHEMENTS INCHANGÉS : la base n'a pas rendu la vue, les tableaux de bord demandés ou leurs rattachements — ce n'est PAS une absence, c'est une lecture qui n'a pas eu lieu, et ni le droit ni la présence ne sont jugés. RIEN n'est rattaché ni retiré. Réessayez ; si le refus persiste, la table des vues ou des tableaux de bord est illisible.";
    const BT2_INCHANGES: &str = "RATTACHEMENTS INCHANGÉS : la base n'a pas pris l'écriture d'un rattachement ou son effacement, et la transaction est annulée — la vue garde exactement ses rattachements d'avant (tout ou rien). Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
    const BT2_INCHANGES_BEGIN: &str = "RATTACHEMENTS INCHANGÉS : la base n'a pas pris la transaction du geste (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur l'écrivain) — RIEN n'est écrit. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";
    const BT2_INCHANGES_COMMIT: &str = "RATTACHEMENTS INCHANGÉS : la base n'a pas validé la transaction (COMMIT refusé) et l'a annulée — la vue garde exactement ses rattachements d'avant. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
    const BT2_VUE_NON_SUPPRIMEE: &str = "VUE NON SUPPRIMÉE : la base n'a pas pris l'effacement de la vue ou le détachement de ses tableaux de bord, ou n'a effacé aucune vue, et la transaction est annulée — la vue existe toujours et les tableaux de bord qui y sont rangés y restent rattachés. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";

    /// Une expression qui échoue à l'évaluation (« integer overflow ») : une colonne d'une vue temporaire qui la
    /// porte rend illisible la lecture qui la touche, et elle seule.
    const BT2_DEBORDE: &str = "abs(-9223372036854775807 - 1)";

    /// Base migrée de `sp_state` (alice et bob `editor`, adm `admin`), vidée des vues et tableaux que la chaîne pose.
    fn bt2_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(&format!("bt2-{tag}"));
        bt2_ecrire(&st, "DELETE FROM panel; DELETE FROM dashboard; DELETE FROM view_dashboard; DELETE FROM view;");
        (st, p)
    }

    fn bt2_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn bt2_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn bt2_a_froid(p: &crate::tmp_possede::TmpDb, sql: &str) -> i64 {
        let c = open_db(p.as_str()).expect("relecture à froid");
        c.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture à froid de `{sql}` ({e})"))
    }

    fn bt2_vue(st: &AppState, nom: &str, owner: &str, vis: &str) -> i64 {
        let c = st.db.lock();
        c.execute("INSERT INTO view(name,owner,visibility) VALUES(?1,?2,?3)", params![nom, owner, vis]).expect("fixture : vue");
        c.last_insert_rowid()
    }

    fn bt2_tableau(st: &AppState, nom: &str, owner: &str, vis: &str, vue: Option<i64>) -> i64 {
        let c = st.db.lock();
        c.execute(
            "INSERT INTO dashboard(name,created,owner,visibility,view_id,cols,height,collapsed) VALUES(?1,1000,?2,?3,?4,1,0,0)",
            params![nom, owner, vis, vue],
        )
        .expect("fixture : tableau");
        c.last_insert_rowid()
    }

    fn bt2_rattacher(st: &AppState, vue: i64, tableau: i64) {
        st.db.lock().execute("INSERT INTO view_dashboard(view_id,dashboard_id) VALUES(?1,?2)", params![vue, tableau]).expect("fixture : rattachement");
    }

    fn bt2_rattachements(st: &AppState) -> Vec<(i64, i64)> {
        let c = st.db.lock();
        let mut s = c.prepare("SELECT view_id,dashboard_id FROM view_dashboard ORDER BY view_id,dashboard_id").unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    fn bt2_vue_principale(st: &AppState, tableau: i64) -> Option<i64> {
        st.db.lock().query_row("SELECT view_id FROM dashboard WHERE id=?1", params![tableau], |r| r.get(0)).unwrap()
    }

    fn bt2_toutes(st: &AppState, tableau: i64) -> i64 {
        st.db.lock().query_row("SELECT all_views FROM dashboard WHERE id=?1", params![tableau], |r| r.get(0)).unwrap()
    }

    async fn bt2_liste(st: &AppState, au: &AuthUser, q: &[(&str, &str)]) -> (u16, Value) {
        let q: HashMap<String, String> = q.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let r = dash_list(State(st.clone()), Extension(au.clone()), Query(q)).await;
        (r.1.as_u16(), r.0)
    }

    fn bt2_ids(v: &Value) -> Vec<i64> {
        v["dashboards"].as_array().unwrap_or_else(|| panic!("une liste est servie : {v}")).iter().map(|d| d["id"].as_i64().unwrap()).collect()
    }

    async fn bt2_ids_sous(st: &AppState, vue: &str) -> Vec<i64> {
        let (code, v) = bt2_liste(st, &sp_au("adm", "admin"), &[("view", vue)]).await;
        assert_eq!(code, 200, "liste sous ?view={vue} : {v}");
        bt2_ids(&v)
    }

    fn bt2_rendre_illisible(st: &AppState, table: &str, colonnes: &str) {
        bt2_ecrire(st, &format!("ALTER TABLE \"{table}\" RENAME TO \"{table}_source\"; CREATE TEMP VIEW \"{table}\" AS SELECT {colonnes} FROM \"{table}_source\";"));
    }

    fn bt2_rendre_lisible(st: &AppState, table: &str) {
        bt2_ecrire(st, &format!("DROP VIEW \"{table}\"; ALTER TABLE \"{table}_source\" RENAME TO \"{table}\";"));
    }

    fn bt2_refuser_le_commit(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn bt2_lever_l_autorisateur(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// Un 503 d'`err_json` : la phrase exacte et un identifiant de corrélation, rien d'autre.
    fn bt2_cinq_cent_trois(code: u16, corps: &Value, phrase: &str) {
        assert_eq!(code, 503, "503 attendu : {corps}");
        assert_eq!(corps["error"], json!(phrase), "phrase exacte : {corps}");
        assert!(corps["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "identifiant de corrélation servi : {corps}");
        assert_eq!(corps.as_object().map(|o| o.len()), Some(2), "ni plus ni moins que `error` et `id` : {corps}");
    }

    async fn bt2_ajouter(st: &AppState, au: &AuthUser, vue: i64, corps: Value) -> (u16, Value) {
        pb_json(view_dashboards_add(State(st.clone()), Extension(au.clone()), Path(vue), Json(corps)).await).await
    }

    async fn bt2_retirer(st: &AppState, au: &AuthUser, vue: i64, tableau: i64) -> (u16, Value) {
        pb_json(view_dashboard_remove(State(st.clone()), Extension(au.clone()), Path((vue, tableau))).await).await
    }

    async fn bt2_creer_vue(st: &AppState, au: &AuthUser, nom: &str, vis: &str) -> (u16, Value) {
        pb_json(view_create(State(st.clone()), Extension(au.clone()), Json(json!({ "name": nom, "visibility": vis }))).await).await
    }

    /// Une base v124 : celle de ce binaire, privée des objets que v125 pose, estampillée 124.
    fn bt2_vers_v124(st: &AppState) {
        bt2_ecrire(
            st,
            "DROP TRIGGER IF EXISTS view_dashboard_suit_l_insertion; DROP TRIGGER IF EXISTS view_dashboard_suit_la_vue_principale; \
             DROP TRIGGER IF EXISTS view_dashboard_suit_l_effacement; DROP TABLE view_dashboard; ALTER TABLE dashboard DROP COLUMN all_views; \
             UPDATE meta SET value='124' WHERE key='schema_version';",
        );
    }

    fn bt2_declencheurs(st: &AppState) -> i64 {
        bt2_entier(
            st,
            "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name IN \
             ('view_dashboard_suit_l_insertion','view_dashboard_suit_la_vue_principale','view_dashboard_suit_l_effacement')",
        )
    }

    // -------------------------------------------------------------------------------------
    // (1) v125
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une base v124 (deux vues HOMONYMES, un tableau rangé par `view_id`, un sans vue, un dans une
    /// autre vue) migre à v125 ; la jointure porte exactement les deux rattachements de `view_id` ; `all_views` vaut 0
    /// partout ; les trois déclencheurs existent ; les deux homonymes restent ; et le tableau sans vue n'est servi que
    /// sans filtre et sous `?view=none`, jamais sous une vue — comme `?view=<id>` (filtre `view_id = <id>`) le servait
    /// en v124. MUTATIONS : `BT2_V125_TOUTES_LES_VUES` (la forme annoncée : sans vue -> all_views = 1 ; le tableau
    /// apparaît sous la vue et sort de `none`), `BT2_V125_SANS_REMPLISSAGE`.
    #[tokio::test]
    async fn bt2_v124_migree_jointure_remplie_et_un_tableau_sans_vue_reste_hors_des_vues() {
        let (st, _p) = bt2_etat("v124");
        bt2_vers_v124(&st);
        let v1 = bt2_vue(&st, "Sécurité", "", "shared");
        let v2 = bt2_vue(&st, "Sécurité", "", "shared");
        let v3 = bt2_vue(&st, "Infra", "", "shared");
        let d1 = bt2_tableau(&st, "D1", "", "shared", Some(v1));
        let d2 = bt2_tableau(&st, "D2 sans vue", "", "shared", None);
        let d3 = bt2_tableau(&st, "D3", "", "shared", Some(v3));
        assert!(migrate(&st.db.lock()), "v125 passe malgré deux vues homonymes");
        assert_eq!(read_schema_version(&st.db.lock()), 125);
        assert_eq!(bt2_rattachements(&st), vec![(v1, d1), (v3, d3)], "la jointure porte les rattachements de view_id, et eux seuls");
        assert_eq!((bt2_toutes(&st, d1), bt2_toutes(&st, d2), bt2_toutes(&st, d3)), (0, 0, 0), "all_views vaut 0 partout");
        assert_eq!(bt2_declencheurs(&st), 3, "les trois déclencheurs sont posés");
        assert_eq!(bt2_entier(&st, "SELECT COUNT(*) FROM view WHERE name='Sécurité'"), 2, "les homonymes restent");
        assert_eq!(bt2_ids_sous(&st, &v1.to_string()).await, vec![d1], "sous la vue : son tableau, pas celui sans vue");
        assert_eq!(bt2_ids_sous(&st, &v2.to_string()).await, Vec::<i64>::new(), "la vue homonyme vide reste vide");
        assert_eq!(bt2_ids_sous(&st, "none").await, vec![d2], "sans vue : le tableau sans vue");
        let (_, tous) = bt2_liste(&st, &sp_au("adm", "admin"), &[]).await;
        assert_eq!(bt2_ids(&tous), vec![d1, d2, d3], "sans filtre : tous");
    }

    /// CE QU'IL TIENT : un second passage de v125 (base rendue à 124) ne retire rien : un rattachement posé après le
    /// premier (hors `view_id`) et un `all_views` posé à 1 survivent ; les déclencheurs restent trois.
    /// MUTATION : `BT2_V125_RECONSTRUIT` (la jointure reconstruite depuis `view_id`).
    #[tokio::test]
    async fn bt2_second_passage_de_v125_ne_retire_rien() {
        let (st, _p) = bt2_etat("v125-bis");
        bt2_vers_v124(&st);
        let v1 = bt2_vue(&st, "V1", "", "shared");
        let v2 = bt2_vue(&st, "V2", "", "shared");
        let d1 = bt2_tableau(&st, "D1", "", "shared", Some(v1));
        let d2 = bt2_tableau(&st, "D2", "", "shared", None);
        assert!(migrate(&st.db.lock()));
        bt2_rattacher(&st, v2, d2);
        bt2_ecrire(&st, &format!("UPDATE dashboard SET all_views=1 WHERE id={d1}; UPDATE meta SET value='124' WHERE key='schema_version';"));
        assert!(migrate(&st.db.lock()), "le second passage aboutit");
        assert_eq!(read_schema_version(&st.db.lock()), 125);
        assert_eq!(bt2_rattachements(&st), vec![(v1, d1), (v2, d2)], "le rattachement posé entre les deux passages reste");
        assert_eq!(bt2_toutes(&st, d1), 1, "all_views posé entre les deux passages reste");
        assert_eq!(bt2_declencheurs(&st), 3);
    }

    /// CE QU'IL TIENT : base neuve — le tableau semé par le semeur de production (qui écrit `view_id` par un UPDATE)
    /// est rattaché par la jointure à sa vue, servi sous elle, `all_views` à 0. MUTATION : `BT2_SANS_DECL_VUE_PRINCIPALE`.
    #[tokio::test]
    async fn bt2_base_neuve_le_tableau_seme_est_rattache_par_la_jointure() {
        let (st, _p) = bt2_etat("neuve");
        seed_default_dashboard(&st.db.lock());
        let (did, vid): (i64, i64) = st
            .db
            .lock()
            .query_row("SELECT id, view_id FROM dashboard WHERE view_id IS NOT NULL ORDER BY id LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("fixture : le semeur a rangé un tableau dans une vue");
        assert!(bt2_rattachements(&st).contains(&(vid, did)), "le rattachement du semis est dans la jointure");
        assert_eq!(
            bt2_entier(&st, "SELECT COUNT(*) FROM dashboard d WHERE d.view_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM view_dashboard vd WHERE vd.view_id=d.view_id AND vd.dashboard_id=d.id)"),
            0,
            "chaque vue principale semée est dans la jointure"
        );
        assert_eq!(bt2_toutes(&st, did), 0);
        assert_eq!(bt2_ids_sous(&st, &vid.to_string()).await, vec![did]);
    }

    // -------------------------------------------------------------------------------------
    // (2) déclencheurs, création, modification
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `POST /api/dashboards` avec `view_id` rattache par la jointure, `all_views` 0 par défaut (le
    /// tableau n'est pas servi sous une autre vue) ; `all_views: true` le sert sous toute vue et le sort de `none` ;
    /// `all_views: false` reste 0. MUTATIONS : `BT2_SANS_DECL_INSERTION`, `BT2_CREATION_TOUTES_IGNOREE`,
    /// `BT2_CREATION_PAR_DEFAUT_VRAI`.
    #[tokio::test]
    async fn bt2_creation_rattache_par_la_jointure_et_toutes_les_vues_se_demande() {
        let (st, _p) = bt2_etat("creation");
        let au = sp_au("alice", "editor");
        let v1 = bt2_vue(&st, "V1", "", "shared");
        let v2 = bt2_vue(&st, "V2", "", "shared");
        let creer = |corps: Value| {
            let (st, au) = (st.clone(), au.clone());
            async move { pb_json(dash_create(State(st), Extension(au), Json(corps)).await).await }
        };
        let (code, a) = creer(json!({ "name": "A", "visibility": "shared", "view_id": v1 })).await;
        assert_eq!(code, 200, "{a}");
        let a = a["id"].as_i64().unwrap();
        assert_eq!(bt2_rattachements(&st), vec![(v1, a)], "la création rattache par la jointure");
        assert_eq!(bt2_toutes(&st, a), 0, "all_views absent : 0");
        let (code, b) = creer(json!({ "name": "B", "visibility": "shared", "all_views": true })).await;
        assert_eq!(code, 200, "{b}");
        let b = b["id"].as_i64().unwrap();
        assert_eq!(bt2_toutes(&st, b), 1);
        let (_, c) = creer(json!({ "name": "C", "visibility": "shared", "all_views": false })).await;
        let c = c["id"].as_i64().unwrap();
        assert_eq!(bt2_toutes(&st, c), 0);
        assert_eq!(bt2_ids_sous(&st, &v2.to_string()).await, vec![b], "sous une autre vue : seulement celui de toutes les vues");
        assert_eq!(bt2_ids_sous(&st, &v1.to_string()).await, vec![a, b]);
        assert_eq!(bt2_ids_sous(&st, "none").await, vec![c], "none : ni rattaché ni de toutes les vues");
    }

    /// CE QU'IL TIENT : `all_views` hors booléen (chaîne, nombre, `null`) est refusé en 400, corps exact, à la création
    /// (aucune ligne) et à la modification (le nom envoyé avec n'est pas écrit) ; `true` puis `false` s'écrivent.
    /// MUTATIONS : `BT2_TOUTES_LES_VUES_LAXISTE`, `BT2_CREATION_SANS_JUGEMENT`, `BT2_MAJ_SANS_JUGEMENT`,
    /// `BT2_MAJ_TOUTES_IGNOREE`.
    #[tokio::test]
    async fn bt2_toutes_les_vues_hors_booleen_refusee_rien_n_est_ecrit() {
        let (st, _p) = bt2_etat("toutes-invalide");
        let au = sp_au("alice", "editor");
        let attendu = json!({ "error": BT2_TOUTES_LES_VUES_INVALIDE });
        let creer = |v: Value| {
            let (st, au) = (st.clone(), au.clone());
            async move { pb_json(dash_create(State(st), Extension(au), Json(json!({ "name": "X", "all_views": v }))).await).await }
        };
        assert_eq!(creer(json!("oui")).await, (400, attendu.clone()), "création, chaîne");
        assert_eq!(creer(json!(1)).await, (400, attendu.clone()), "création, nombre");
        assert_eq!(creer(Value::Null).await, (400, attendu.clone()), "création, null");
        assert_eq!(bt2_entier(&st, "SELECT COUNT(*) FROM dashboard"), 0, "aucune création");
        let d = bt2_tableau(&st, "avant", "alice", "shared", None);
        let modifier = |v: Value| {
            let (st, au) = (st.clone(), au.clone());
            async move { pb_json(dash_update(State(st), Extension(au), Path(d), Json(json!({ "name": "après", "all_views": v }))).await).await }
        };
        assert_eq!(modifier(json!("oui")).await, (400, attendu.clone()), "modification, chaîne");
        assert_eq!(modifier(json!(1)).await, (400, attendu.clone()), "modification, nombre");
        assert_eq!(modifier(Value::Null).await, (400, attendu.clone()), "modification, null");
        assert_eq!(bt2_entier(&st, &format!("SELECT COUNT(*) FROM dashboard WHERE id={d} AND name='avant'")), 1, "le nom n'est pas écrit");
        let r = dash_update(State(st.clone()), Extension(au.clone()), Path(d), Json(json!({ "all_views": true }))).await;
        assert_eq!(r.status().as_u16(), 204);
        assert_eq!(bt2_toutes(&st, d), 1, "true s'écrit");
        let r = dash_update(State(st.clone()), Extension(au.clone()), Path(d), Json(json!({ "all_views": false }))).await;
        assert_eq!(r.status().as_u16(), 204);
        assert_eq!(bt2_toutes(&st, d), 0, "false s'écrit");
    }

    /// CE QU'IL TIENT : écrire `view_id` DÉPLACE la vue principale : l'ancien rattachement part, le nouveau arrive, le
    /// rattachement posé hors `view_id` reste ; `view_id: null` retire la principale seule. MUTATIONS :
    /// `BT2_DEPLACEMENT_GARDE_L_ANCIEN`, `BT2_SANS_DECL_VUE_PRINCIPALE`.
    #[tokio::test]
    async fn bt2_ecrire_la_vue_principale_deplace_et_garde_les_autres_rattachements() {
        let (st, _p) = bt2_etat("deplacement");
        let au = sp_au("alice", "editor");
        let (v1, v2, v3) = (bt2_vue(&st, "V1", "", "shared"), bt2_vue(&st, "V2", "", "shared"), bt2_vue(&st, "V3", "", "shared"));
        let d = bt2_tableau(&st, "D", "alice", "shared", Some(v1));
        bt2_rattacher(&st, v3, d);
        let r = dash_update(State(st.clone()), Extension(au.clone()), Path(d), Json(json!({ "view_id": v2 }))).await;
        assert_eq!(r.status().as_u16(), 204);
        assert_eq!(bt2_rattachements(&st), vec![(v2, d), (v3, d)]);
        let r = dash_update(State(st.clone()), Extension(au.clone()), Path(d), Json(json!({ "view_id": null }))).await;
        assert_eq!(r.status().as_u16(), 204);
        assert_eq!(bt2_rattachements(&st), vec![(v3, d)]);
    }

    /// CE QU'IL TIENT : un tableau effacé emporte ses rattachements ; le tableau créé ensuite sous le MÊME rowid
    /// (constat de fixture, relu) n'est rangé dans aucune vue. MUTATION : `BT2_SANS_DECL_EFFACEMENT`.
    #[tokio::test]
    async fn bt2_un_tableau_efface_emporte_ses_rattachements() {
        let (st, _p) = bt2_etat("effacement");
        let au = sp_au("alice", "editor");
        let (v1, v2) = (bt2_vue(&st, "V1", "", "shared"), bt2_vue(&st, "V2", "", "shared"));
        let d = bt2_tableau(&st, "D", "alice", "shared", Some(v1));
        bt2_rattacher(&st, v2, d);
        let r = dash_delete(State(st.clone()), Extension(au.clone()), Path(d)).await;
        assert_eq!(r.status().as_u16(), 204);
        assert_eq!(bt2_rattachements(&st), Vec::<(i64, i64)>::new(), "plus aucun rattachement");
        let (_, neuf) = pb_json(dash_create(State(st.clone()), Extension(au.clone()), Json(json!({ "name": "neuf", "visibility": "shared" }))).await).await;
        assert_eq!(neuf["id"].as_i64(), Some(d), "fixture : le rowid est réutilisé");
        assert_eq!(bt2_ids_sous(&st, &v2.to_string()).await, Vec::<i64>::new(), "le neuf n'hérite d'aucune vue");
    }

    // -------------------------------------------------------------------------------------
    // (3) dash_list
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `?view=<id>` rend les tableaux rattachés par la jointure (même sans `view_id`) et ceux de toutes
    /// les vues ; `?view=none` rend ceux qui n'ont ni rattachement ni `all_views` (un tableau rattaché sans `view_id`
    /// n'y est pas) ; chaque ligne porte `all_views` et `view_ids` (triés). MUTATIONS : `BT2_FILTRE_SANS_TOUTES`,
    /// `BT2_FILTRE_VUE_PAR_COLONNE`, `BT2_AUCUNE_SANS_TOUTES`, `BT2_AUCUNE_PAR_COLONNE`, `BT2_VIEW_IDS_VIDE`,
    /// `BT2_TOUTES_LUE_FAUX`.
    #[tokio::test]
    async fn bt2_filtre_de_vue_lit_la_jointure_et_toutes_les_vues() {
        let (st, _p) = bt2_etat("filtre");
        let (v1, v2) = (bt2_vue(&st, "V1", "", "shared"), bt2_vue(&st, "V2", "", "shared"));
        let a = bt2_tableau(&st, "A", "", "shared", Some(v1));
        let b = bt2_tableau(&st, "B", "", "shared", None);
        bt2_rattacher(&st, v1, b);
        let c = bt2_tableau(&st, "C", "", "shared", None);
        bt2_ecrire(&st, &format!("UPDATE dashboard SET all_views=1 WHERE id={c}"));
        let e = bt2_tableau(&st, "E", "", "shared", None);
        let f = bt2_tableau(&st, "F", "", "shared", Some(v2));
        bt2_rattacher(&st, v1, f);
        assert_eq!(bt2_ids_sous(&st, &v1.to_string()).await, vec![a, b, c, f]);
        assert_eq!(bt2_ids_sous(&st, &v2.to_string()).await, vec![c, f]);
        assert_eq!(bt2_ids_sous(&st, "none").await, vec![e]);
        let (_, v) = bt2_liste(&st, &sp_au("adm", "admin"), &[("view", &v1.to_string())]).await;
        let lignes: Vec<(i64, Value, Value, Value)> = v["dashboards"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| (d["id"].as_i64().unwrap(), d["view_id"].clone(), d["all_views"].clone(), d["view_ids"].clone()))
            .collect();
        assert_eq!(
            lignes,
            vec![
                (a, json!(v1), json!(false), json!([v1])),
                (b, Value::Null, json!(false), json!([v1])),
                (c, Value::Null, json!(true), json!([])),
                (f, json!(v2), json!(false), json!([v1, v2])),
            ]
        );
    }

    /// CE QU'IL TIENT : sans `limit`, la liste entière (`limit` nul, `offset` 0) ; une page pleine porte le total du
    /// filtre (pas sa longueur), sous la même visibilité (le tableau privé d'alice n'est pas compté pour bob) ; une page
    /// vide aussi, sans aucune ligne de tableau ; la borne est admise à 100, refusée à 101 et à 0 ; `limit`, `offset` et
    /// `view` invalides refusés, corps exacts. MUTATIONS : `BT2_TOTAL_DE_LA_PAGE`, `BT2_PAGE_VIDE_SANS_TOTAL`,
    /// `BT2_PAGE_VIDE_LIGNE`, `BT2_TOTAL_SANS_FILTRE`, `BT2_BORNE_TRONQUE`, `BT2_BORNE_PLUS_UN`, `BT2_BORNE_MOINS_UN`,
    /// `BT2_BORNE_ZERO`, `BT2_OFFSET_LAXISTE`, `BT2_VUE_LAXISTE`.
    #[tokio::test]
    async fn bt2_pagination_total_juste_et_borne_refusee() {
        let (st, _p) = bt2_etat("page");
        let bob = sp_au("bob", "editor");
        let ids: Vec<i64> = (1..=5).map(|i| bt2_tableau(&st, &format!("P{i}"), "", "shared", None)).collect();
        bt2_tableau(&st, "privé d'alice", "alice", "private", None);
        let (code, v) = bt2_liste(&st, &bob, &[]).await;
        assert_eq!(code, 200);
        assert_eq!((bt2_ids(&v), v["total"].clone(), v["limit"].clone(), v["offset"].clone()), (ids.clone(), json!(5), Value::Null, json!(0)));
        let (_, v) = bt2_liste(&st, &bob, &[("limit", "2")]).await;
        assert_eq!((bt2_ids(&v), v["total"].clone(), v["limit"].clone(), v["offset"].clone()), (ids[..2].to_vec(), json!(5), json!(2), json!(0)));
        let (_, v) = bt2_liste(&st, &bob, &[("limit", "2"), ("offset", "4")]).await;
        assert_eq!((bt2_ids(&v), v["total"].clone(), v["offset"].clone()), (ids[4..].to_vec(), json!(5), json!(4)));
        let (code, v) = bt2_liste(&st, &bob, &[("offset", "10")]).await;
        assert_eq!((code, bt2_ids(&v), v["total"].clone()), (200, Vec::<i64>::new(), json!(5)), "page vide : le total reste celui du filtre");
        let (code, v) = bt2_liste(&st, &bob, &[("limit", "100")]).await;
        assert_eq!((code, v["limit"].clone(), bt2_ids(&v)), (200, json!(100), ids.clone()), "la borne est admise");
        assert_eq!(bt2_liste(&st, &bob, &[("limit", "101")]).await, (400, json!({ "error": BT2_LIMITE_HORS_BORNE })), "limit=101");
        assert_eq!(bt2_liste(&st, &bob, &[("limit", "0")]).await, (400, json!({ "error": BT2_LIMITE_HORS_BORNE })), "limit=0");
        assert_eq!(bt2_liste(&st, &bob, &[("limit", "deux")]).await, (400, json!({ "error": BT2_LIMITE_HORS_BORNE })), "limit=deux");
        assert_eq!(bt2_liste(&st, &bob, &[("offset", "-1")]).await, (400, json!({ "error": BT2_DECALAGE_INVALIDE })), "offset=-1");
        assert_eq!(bt2_liste(&st, &bob, &[("view", "toutes")]).await, (400, json!({ "error": BT2_FILTRE_INVALIDE })), "view=toutes");
    }

    /// CE QU'IL TIENT : par la ROUTE, au rôle le plus faible admis (viewer), la page sous une vue sert le corps exact
    /// (lignes, `me`, `role`, `total`, `limit`, `offset`) ; une limite hors borne y est un 400 au corps exact.
    /// MUTATION : `BT2_STATUT_PERDU` (le 400 servi en 200).
    #[tokio::test]
    async fn bt2_page_par_la_route_au_role_le_plus_faible() {
        let (st, _p) = router_test_state("bt2-route-liste");
        let (v, d1, d2) = {
            let c = st.db.lock();
            c.execute("INSERT INTO view(name,owner,visibility) VALUES('Route','','shared')", []).unwrap();
            let v = c.last_insert_rowid();
            c.execute("INSERT INTO dashboard(name,created,owner,visibility,view_id,cols,height,collapsed,position) VALUES('R1',1000,'','shared',?1,1,0,0,1)", params![v]).unwrap();
            let d1 = c.last_insert_rowid();
            c.execute("INSERT INTO dashboard(name,created,owner,visibility,view_id,cols,height,collapsed,position) VALUES('R2',1000,'','shared',?1,2,30,1,2)", params![v]).unwrap();
            (v, d1, c.last_insert_rowid())
        };
        let addr = router_serve(st.clone()).await;
        // Le corps JSON, entre la première accolade après les en-têtes et la dernière (un découpage en morceaux
        // l'encadrerait de tailles hexadécimales).
        let corps_de = |texte: &str| -> Value {
            let corps = texte.split_once("\r\n\r\n").map(|(_, c)| c).unwrap_or("");
            match (corps.find('{'), corps.rfind('}')) {
                (Some(a), Some(b)) if a < b => serde_json::from_str(&corps[a..=b]).unwrap_or_else(|_| json!({ "_texte": texte })),
                _ => json!({ "_texte": texte }),
            }
        };
        let (code, texte) = router_probe_envoi(addr, "GET", &format!("/api/dashboards?view={v}&limit=1&offset=1"), Some(&viewer_authz()), &[], "").await;
        assert_eq!(code, 200, "{texte}");
        assert_eq!(
            corps_de(&texte),
            json!({
                "dashboards": [{
                    "id": d2, "name": "R2", "owner": "", "visibility": "shared", "view_id": v, "panels": 0,
                    "cols": 2, "height": 30, "collapsed": true, "position": 2, "editable": true,
                    "all_views": false, "view_ids": [v]
                }],
                "me": "vwr", "role": "viewer", "total": 2, "limit": 1, "offset": 1
            }),
            "corps entier ({d1} est en première page)"
        );
        let (code, texte) = router_probe_envoi(addr, "GET", "/api/dashboards?limit=101", Some(&viewer_authz()), &[], "").await;
        assert_eq!((code, corps_de(&texte)), (400, json!({ "error": BT2_LIMITE_HORS_BORNE })));
    }

    // -------------------------------------------------------------------------------------
    // (4) doublon de vue
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : le doublon se juge sur les vues que le créateur VOIT : une vue commune homonyme -> 409, corps
    /// exact avec l'identifiant ; la vue privée d'alice n'est pas un doublon pour bob (200, aucun identifiant d'autrui
    /// servi) ; l'est pour l'administrateur (409, la plus ancienne) et pour alice. MUTATIONS : `BT2_DOUBLON_IGNORE`,
    /// `BT2_DOUBLON_GLOBAL`, `BT2_DOUBLON_SANS_ADMIN`, `BT2_DOUBLON_SANS_PROPRIETAIRE`.
    #[tokio::test]
    async fn bt2_doublon_de_vue_409_dans_le_perimetre_du_createur() {
        let (st, _p) = bt2_etat("doublon");
        let (alice, bob, adm) = (sp_au("alice", "editor"), sp_au("bob", "editor"), sp_au("adm", "admin"));
        let (code, e) = bt2_creer_vue(&st, &alice, "Équipe", "shared").await;
        assert_eq!(code, 200, "{e}");
        let e = e["id"].as_i64().unwrap();
        let (code, corps) = bt2_creer_vue(&st, &bob, "Équipe", "shared").await;
        assert_eq!((code, corps), (409, json!({ "error": BT2_VUE_DEJA_EXISTANTE, "view_id": e })));
        assert_eq!(bt2_entier(&st, "SELECT COUNT(*) FROM view WHERE name='Équipe'"), 1);
        let (_, p) = bt2_creer_vue(&st, &alice, "Perso", "private").await;
        let p = p["id"].as_i64().unwrap();
        let (code, corps) = bt2_creer_vue(&st, &bob, "Perso", "private").await;
        assert_eq!(code, 200, "la vue privée d'alice n'est pas un doublon pour bob : {corps}");
        assert_ne!(corps["id"].as_i64(), Some(p));
        let (code, corps) = bt2_creer_vue(&st, &adm, "Perso", "shared").await;
        assert_eq!((code, corps), (409, json!({ "error": BT2_VUE_DEJA_EXISTANTE, "view_id": p })), "l'administrateur voit tout");
        let (code, corps) = bt2_creer_vue(&st, &alice, "Perso", "shared").await;
        assert_eq!((code, corps), (409, json!({ "error": BT2_VUE_DEJA_EXISTANTE, "view_id": p })), "alice voit la sienne");
        assert_eq!(bt2_entier(&st, "SELECT COUNT(*) FROM view WHERE name='Perso'"), 2);
    }

    /// CE QU'IL TIENT : au point de course posé ENTRE le jugement du doublon et l'insertion, l'écrivain est TENU ; la
    /// création concurrente du même nom attend, puis rend 409 avec l'identifiant de la vue posée ; une seule vue.
    /// MUTATION : `BT2_DOUBLON_HORS_VERROU` (jugement sous un premier verrou, insertion sous un second).
    #[tokio::test]
    async fn bt2_le_doublon_se_juge_sous_le_verrou_d_ecriture() {
        let (st, _p) = bt2_etat("course");
        let cle = format!("vue-jugee-avant-son-insertion:{}", st.db_path.as_str());
        let verrou_tenu: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
        let fil: Arc<Mutex<Option<std::thread::JoinHandle<(u16, Value)>>>> = Arc::new(Mutex::new(None));
        let issue: Arc<Mutex<Option<(u16, Value)>>> = Arc::new(Mutex::new(None));
        let (vt, fl, is, st2, db) = (verrou_tenu.clone(), fil.clone(), issue.clone(), st.clone(), st.db.clone());
        crate::handlers::transaction_validee::poser_un_crochet_de_course(&cle, move || {
            let tenu = db.is_locked();
            *vt.lock() = Some(tenu);
            let concurrent = std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime de fil").block_on(async move {
                    pb_json(view_create(State(st2), Extension(sp_au("bob", "editor")), Json(json!({ "name": "Course", "visibility": "shared" }))).await).await
                })
            });
            if tenu {
                *fl.lock() = Some(concurrent);
            } else {
                *is.lock() = Some(concurrent.join().expect("fil concurrent"));
            }
        });
        let (code, corps) = bt2_creer_vue(&st, &sp_au("alice", "editor"), "Course", "shared").await;
        let attente = fil.lock().take();
        if let Some(h) = attente {
            *issue.lock() = Some(h.join().expect("fil concurrent"));
        }
        assert_eq!(code, 200, "{corps}");
        let id = corps["id"].as_i64().unwrap();
        assert_eq!(*verrou_tenu.lock(), Some(true), "l'écrivain est tenu entre le jugement et l'insertion");
        assert_eq!(issue.lock().clone(), Some((409, json!({ "error": BT2_VUE_DEJA_EXISTANTE, "view_id": id }))), "le concurrent voit la vue posée");
        assert_eq!(bt2_entier(&st, "SELECT COUNT(*) FROM view WHERE name='Course'"), 1);
    }

    /// CE QU'IL TIENT : la recherche des homonymes illisible -> 503 nommé (corps exact), rien n'est créé.
    /// MUTATION : `BT2_HOMONYMES_ILLISIBLES_ABSENTS` (lecture ratée prise pour « aucun homonyme » : le refus servi
    /// devient celui de l'insertion).
    #[tokio::test]
    async fn bt2_homonymes_non_lus_rien_n_est_cree() {
        let (st, _p) = bt2_etat("homonymes-illisibles");
        bt2_vue(&st, "Ancienne", "alice", "shared");
        bt2_rendre_illisible(&st, "view", &format!("id, {BT2_DEBORDE} AS name, owner, visibility, created"));
        let (code, corps) = bt2_creer_vue(&st, &sp_au("alice", "editor"), "X", "shared").await;
        bt2_cinq_cent_trois(code, &corps, BT2_HOMONYMES_NON_LUS);
        bt2_rendre_lisible(&st, "view");
        assert_eq!(bt2_entier(&st, "SELECT COUNT(*) FROM view"), 1, "rien n'est créé");
    }

    /// CE QU'IL TIENT : COMMIT refusé -> 503 nommé (corps exact), aucun identifiant, rien à froid, transaction close ;
    /// levé, la création aboutit. MUTATION : `BT2_COMMIT_IGNORE`.
    #[tokio::test]
    async fn bt2_creation_de_vue_commit_refuse_aucun_identifiant() {
        let (st, p) = bt2_etat("vue-commit");
        bt2_refuser_le_commit(&st);
        let (code, corps) = bt2_creer_vue(&st, &sp_au("alice", "editor"), "Validée ?", "shared").await;
        bt2_lever_l_autorisateur(&st);
        bt2_cinq_cent_trois(code, &corps, BT2_VUE_NON_VALIDEE);
        assert!(st.db.lock().is_autocommit(), "transaction close");
        assert_eq!(bt2_a_froid(&p, "SELECT COUNT(*) FROM view"), 0);
        let (code, _) = bt2_creer_vue(&st, &sp_au("alice", "editor"), "Validée ?", "shared").await;
        assert_eq!(code, 200);
    }

    /// CE QU'IL TIENT : BEGIN refusé (transaction étrangère pendante sur l'écrivain) -> 503 nommé, corps exact, pour la
    /// création d'une vue, l'ajout et le retrait de rattachements ; rien n'est écrit. MUTATIONS : `BT2_BEGIN_PHRASE`,
    /// `BT2_AJOUT_BEGIN_PHRASE`, `BT2_RETRAIT_BEGIN_PHRASE`.
    #[tokio::test]
    async fn bt2_begin_refuse_sur_les_trois_gestes() {
        let (st, _p) = bt2_etat("begin");
        let alice = sp_au("alice", "editor");
        let v = bt2_vue(&st, "V", "alice", "shared");
        let d = bt2_tableau(&st, "D", "alice", "shared", Some(v));
        let d2 = bt2_tableau(&st, "D2", "alice", "shared", None);
        bt2_ecrire(&st, "BEGIN");
        let (c1, b1) = bt2_creer_vue(&st, &alice, "Neuve", "shared").await;
        let (c2, b2) = bt2_ajouter(&st, &alice, v, json!({ "dashboard_ids": [d2] })).await;
        let (c3, b3) = bt2_retirer(&st, &alice, v, d).await;
        bt2_ecrire(&st, "ROLLBACK");
        bt2_cinq_cent_trois(c1, &b1, BT2_VUE_BEGIN);
        bt2_cinq_cent_trois(c2, &b2, BT2_INCHANGES_BEGIN);
        bt2_cinq_cent_trois(c3, &b3, BT2_INCHANGES_BEGIN);
        assert_eq!(bt2_entier(&st, "SELECT COUNT(*) FROM view"), 1);
        assert_eq!(bt2_rattachements(&st), vec![(v, d)]);
    }

    // -------------------------------------------------------------------------------------
    // (5) compléter une vue
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la demande [D1, D2, D3, D1] (D2 déjà rangé, D1 privé d'alice) rend 200 au corps exact,
    /// dans l'ordre, doublon de la demande retiré ; la vue principale de D1 et D3 n'est pas écrite ; la même demande
    /// rejouée n'ajoute rien. MUTATIONS : `BT2_AJOUT_SANS_DEDOUBLONNER`, `BT2_DEJA_COMPTE_AJOUTE`,
    /// `BT2_AJOUT_ECRIT_LA_VUE_PRINCIPALE`.
    #[tokio::test]
    async fn bt2_completer_une_vue_n_ajoute_que_les_manquants() {
        let (st, _p) = bt2_etat("completer");
        let alice = sp_au("alice", "editor");
        let v = bt2_vue(&st, "V", "alice", "shared");
        let d1 = bt2_tableau(&st, "D1", "alice", "private", None);
        let d2 = bt2_tableau(&st, "D2", "", "shared", None);
        let d3 = bt2_tableau(&st, "D3", "", "shared", None);
        bt2_rattacher(&st, v, d2);
        let (code, corps) = bt2_ajouter(&st, &alice, v, json!({ "dashboard_ids": [d1, d2, d3, d1] })).await;
        assert_eq!((code, corps), (200, json!({ "added": [d1, d3], "already_present": [d2] })));
        assert_eq!(bt2_rattachements(&st), vec![(v, d1), (v, d2), (v, d3)]);
        assert_eq!((bt2_vue_principale(&st, d1), bt2_vue_principale(&st, d3)), (None, None), "la vue principale ne change pas");
        let (code, corps) = bt2_ajouter(&st, &alice, v, json!({ "dashboard_ids": [d1, d2, d3] })).await;
        assert_eq!((code, corps), (200, json!({ "added": [], "already_present": [d1, d2, d3] })), "idempotent");
    }

    /// CE QU'IL TIENT : deux inconnus encadrant un connu -> 404 au corps exact qui les nomme TOUS, et le connu n'est
    /// pas rattaché (tout ou rien) ; le tableau privé de bob, demandé par alice, a la même réponse qu'un absent (pas
    /// d'oracle d'existence). MUTATIONS : `BT2_PREMIER_INCONNU_SEUL`, `BT2_INCONNU_ECRIT_LES_AUTRES`,
    /// `BT2_PRIVE_D_AUTRUI_ADMIS`.
    #[tokio::test]
    async fn bt2_completer_un_inconnu_404_rien_n_est_ecrit() {
        let (st, _p) = bt2_etat("inconnu");
        let alice = sp_au("alice", "editor");
        let v = bt2_vue(&st, "V", "alice", "shared");
        let d3 = bt2_tableau(&st, "D3", "", "shared", None);
        let de_bob = bt2_tableau(&st, "privé de bob", "bob", "private", None);
        let (code, corps) = bt2_ajouter(&st, &alice, v, json!({ "dashboard_ids": [999_998, d3, 999_999] })).await;
        assert_eq!((code, corps), (404, json!({ "error": BT2_TABLEAUX_INCONNUS, "dashboard_ids": [999_998, 999_999] })));
        let (code, corps) = bt2_ajouter(&st, &alice, v, json!({ "dashboard_ids": [d3, de_bob] })).await;
        assert_eq!((code, corps), (404, json!({ "error": BT2_TABLEAUX_INCONNUS, "dashboard_ids": [de_bob] })), "privé d'autrui = inconnu");
        assert_eq!(bt2_rattachements(&st), Vec::<(i64, i64)>::new(), "rien n'est écrit");
    }

    /// CE QU'IL TIENT : vue inconnue -> 404 nommé ; corps absent, élément non entier -> 400 exact sans écriture ; 101
    /// identifiants -> 400 exact, 100 passent la borne (jugés ensuite : inconnus, 404). INVERSÉ (porte alignée sur
    /// celle de `dash_update` `view_id`) : bob, qui n'est pas propriétaire de la vue commune d'alice mais la VOIT et peut
    /// modifier D3 (commun), la complète (200) — la forme d'avant rendait 403 (« modifier une vue est un geste de
    /// propriétaire »). MUTATIONS : `BT2_VUE_INCONNUE_MUETTE`, `BX2_PORTE_PROPRIETAIRE` (la porte d'avant : 403 pour
    /// bob), `BT2_ELEMENT_LAXISTE`, `BT2_TROP_PLUS_UN`, `BT2_TROP_MOINS_UN`.
    #[tokio::test]
    async fn bt2_completer_porte_et_corps() {
        let (st, _p) = bt2_etat("porte");
        let (alice, bob) = (sp_au("alice", "editor"), sp_au("bob", "editor"));
        let v = bt2_vue(&st, "V", "alice", "shared");
        let d3 = bt2_tableau(&st, "D3", "", "shared", None);
        let (code, corps) = bt2_ajouter(&st, &alice, 999_999, json!({ "dashboard_ids": [d3] })).await;
        assert_eq!((code, corps), (404, json!({ "error": BT2_VUE_INCONNUE })));
        let (code, corps) = bt2_ajouter(&st, &bob, v, json!({ "dashboard_ids": [d3] })).await;
        assert_eq!((code, corps), (200, json!({ "added": [d3], "already_present": [] })), "bob voit la vue et peut modifier D3");
        bt2_ecrire(&st, "DELETE FROM view_dashboard;");
        let (code, corps) = bt2_ajouter(&st, &alice, v, json!({})).await;
        assert_eq!((code, corps), (400, json!({ "error": BT2_CORPS_INVALIDE })));
        let (code, corps) = bt2_ajouter(&st, &alice, v, json!({ "dashboard_ids": [d3, "x"] })).await;
        assert_eq!((code, corps), (400, json!({ "error": BT2_CORPS_INVALIDE })));
        let cent_un: Vec<i64> = (0..101).map(|i| 900_000 + i).collect();
        let (code, corps) = bt2_ajouter(&st, &alice, v, json!({ "dashboard_ids": cent_un })).await;
        assert_eq!((code, corps), (400, json!({ "error": BT2_TROP })));
        let cent: Vec<i64> = (0..100).map(|i| 900_000 + i).collect();
        let (code, corps) = bt2_ajouter(&st, &alice, v, json!({ "dashboard_ids": cent.clone() })).await;
        assert_eq!((code, corps), (404, json!({ "error": BT2_TABLEAUX_INCONNUS, "dashboard_ids": cent })), "cent passent la borne");
        assert_eq!(bt2_rattachements(&st), Vec::<(i64, i64)>::new());
    }

    /// CE QU'IL TIENT : la visibilité de la vue illisible (la porte ne lit plus son propriétaire, et `visibility` est lue
    /// avant lui), puis la ligne d'un tableau demandé illisible -> 503 nommé (corps exact) dans les deux cas, ni 404 ni
    /// écriture. MUTATIONS : `BT2_PORTE_ILLISIBLE_ABSENTE`,
    /// `BT2_LECTURE_RATEE_INCONNUE`.
    #[tokio::test]
    async fn bt2_completer_lectures_non_faites() {
        let (st, _p) = bt2_etat("completer-illisible");
        let alice = sp_au("alice", "editor");
        let v = bt2_vue(&st, "V", "alice", "shared");
        let d3 = bt2_tableau(&st, "D3", "", "shared", None);
        bt2_rendre_illisible(&st, "view", &format!("id, name, owner, {BT2_DEBORDE} AS visibility, created"));
        let (code, corps) = bt2_ajouter(&st, &alice, v, json!({ "dashboard_ids": [d3] })).await;
        bt2_rendre_lisible(&st, "view");
        bt2_cinq_cent_trois(code, &corps, BT2_NON_LUS);
        bt2_rendre_illisible(&st, "dashboard", &format!("id, name, {BT2_DEBORDE} AS owner, visibility, view_id, all_views"));
        let (code, corps) = bt2_ajouter(&st, &alice, v, json!({ "dashboard_ids": [d3] })).await;
        bt2_rendre_lisible(&st, "dashboard");
        bt2_cinq_cent_trois(code, &corps, BT2_NON_LUS);
        assert_eq!(bt2_rattachements(&st), Vec::<(i64, i64)>::new());
    }

    /// CE QU'IL TIENT : l'écriture du SECOND rattachement refusée (le premier déjà écrit) -> 503 nommé et le premier
    /// est annulé (tout ou rien) ; une écriture ignorée (zéro ligne) aussi ; COMMIT refusé -> 503 nommé, rien à
    /// froid. MUTATIONS : `BT2_ECRITURE_SANS_ANNULER`, `BT2_AJOUT_COMMIT_IGNORE`.
    #[tokio::test]
    async fn bt2_completer_ecritures_refusees_tout_ou_rien() {
        let (st, p) = bt2_etat("completer-ecriture");
        let alice = sp_au("alice", "editor");
        let v = bt2_vue(&st, "V", "alice", "shared");
        let d1 = bt2_tableau(&st, "D1", "", "shared", None);
        let d3 = bt2_tableau(&st, "D3", "", "shared", None);
        bt2_ecrire(&st, &format!("CREATE TEMP TRIGGER bt2_refus BEFORE INSERT ON main.view_dashboard WHEN NEW.dashboard_id={d3} BEGIN SELECT RAISE(ABORT, 'refus de témoin'); END;"));
        let (code, corps) = bt2_ajouter(&st, &alice, v, json!({ "dashboard_ids": [d1, d3] })).await;
        bt2_ecrire(&st, "DROP TRIGGER bt2_refus;");
        bt2_cinq_cent_trois(code, &corps, BT2_INCHANGES);
        assert_eq!(bt2_rattachements(&st), Vec::<(i64, i64)>::new(), "le premier rattachement est annulé");
        bt2_ecrire(&st, "CREATE TEMP TRIGGER bt2_ignore BEFORE INSERT ON main.view_dashboard BEGIN SELECT RAISE(IGNORE); END;");
        let (code, corps) = bt2_ajouter(&st, &alice, v, json!({ "dashboard_ids": [d1] })).await;
        bt2_ecrire(&st, "DROP TRIGGER bt2_ignore;");
        bt2_cinq_cent_trois(code, &corps, BT2_INCHANGES);
        bt2_refuser_le_commit(&st);
        let (code, corps) = bt2_ajouter(&st, &alice, v, json!({ "dashboard_ids": [d1] })).await;
        bt2_lever_l_autorisateur(&st);
        bt2_cinq_cent_trois(code, &corps, BT2_INCHANGES_COMMIT);
        assert_eq!(bt2_a_froid(&p, "SELECT COUNT(*) FROM view_dashboard"), 0, "rien à froid");
    }

    // -------------------------------------------------------------------------------------
    // (6) retirer un rattachement
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : retirer un rattachement hors vue principale (204) ; retirer la vue principale la vide (204,
    /// `view_id` nul) ; retirer un absent -> 404 nommé ; vue inconnue -> 404 nommé. INVERSÉ (porte alignée sur celle de
    /// `dash_update` `view_id`) : bob, non propriétaire de la vue commune d'alice, y retire D2 (commun, qu'il peut
    /// modifier) — 204 ; la forme d'avant rendait 403.
    /// MUTATIONS : `BT2_RETRAIT_GARDE_LA_PRINCIPALE`, `BT2_ABSENT_204`, `BX2_PORTE_PROPRIETAIRE`.
    #[tokio::test]
    async fn bt2_retirer_un_rattachement() {
        let (st, _p) = bt2_etat("retirer");
        let (alice, bob) = (sp_au("alice", "editor"), sp_au("bob", "editor"));
        let v = bt2_vue(&st, "V", "alice", "shared");
        let d1 = bt2_tableau(&st, "D1", "", "shared", Some(v));
        let d2 = bt2_tableau(&st, "D2", "", "shared", None);
        bt2_rattacher(&st, v, d2);
        let (code, corps) = bt2_retirer(&st, &bob, v, d2).await;
        assert_eq!(code, 204, "bob voit la vue et peut modifier D2 : {corps}");
        assert_eq!(bt2_rattachements(&st), vec![(v, d1)]);
        let (code, _) = bt2_retirer(&st, &alice, v, d1).await;
        assert_eq!(code, 204);
        assert_eq!((bt2_rattachements(&st), bt2_vue_principale(&st, d1)), (vec![], None), "la vue principale est vidée");
        let (code, corps) = bt2_retirer(&st, &alice, v, d2).await;
        assert_eq!((code, corps), (404, json!({ "error": BT2_ABSENT })));
        let (code, corps) = bt2_retirer(&st, &alice, 999_999, d2).await;
        assert_eq!((code, corps), (404, json!({ "error": BT2_VUE_INCONNUE })));
    }

    /// CE QU'IL TIENT : présence illisible -> 503 nommé (pas « absent ») ; effacement ignoré (zéro ligne) -> 503 et le
    /// rattachement reste ; détachement de la vue principale refusé -> 503 et l'effacement est annulé ; COMMIT refusé
    /// -> 503, le rattachement reste à froid. MUTATIONS : `BT2_PRESENCE_ILLISIBLE_ABSENTE`,
    /// `BT2_RETRAIT_EFFACEMENT_SANS_COMPTE`, `BT2_RETRAIT_SANS_ANNULER`, `BT2_RETRAIT_COMMIT_IGNORE`.
    #[tokio::test]
    async fn bt2_retirer_refus_et_lectures() {
        let (st, p) = bt2_etat("retirer-refus");
        let alice = sp_au("alice", "editor");
        let v = bt2_vue(&st, "V", "alice", "shared");
        let d1 = bt2_tableau(&st, "D1", "", "shared", Some(v));
        bt2_rendre_illisible(&st, "view_dashboard", &format!("{BT2_DEBORDE} AS view_id, dashboard_id"));
        let (code, corps) = bt2_retirer(&st, &alice, v, d1).await;
        bt2_rendre_lisible(&st, "view_dashboard");
        bt2_cinq_cent_trois(code, &corps, BT2_NON_LUS);
        bt2_ecrire(&st, "CREATE TEMP TRIGGER bt2_ignore BEFORE DELETE ON main.view_dashboard BEGIN SELECT RAISE(IGNORE); END;");
        let (code, corps) = bt2_retirer(&st, &alice, v, d1).await;
        bt2_ecrire(&st, "DROP TRIGGER bt2_ignore;");
        bt2_cinq_cent_trois(code, &corps, BT2_INCHANGES);
        bt2_ecrire(&st, "CREATE TEMP TRIGGER bt2_refus BEFORE UPDATE ON main.dashboard BEGIN SELECT RAISE(ABORT, 'refus de témoin'); END;");
        let (code, corps) = bt2_retirer(&st, &alice, v, d1).await;
        bt2_ecrire(&st, "DROP TRIGGER bt2_refus;");
        bt2_cinq_cent_trois(code, &corps, BT2_INCHANGES);
        assert_eq!((bt2_rattachements(&st), bt2_vue_principale(&st, d1)), (vec![(v, d1)], Some(v)), "rien n'a bougé");
        bt2_refuser_le_commit(&st);
        let (code, corps) = bt2_retirer(&st, &alice, v, d1).await;
        bt2_lever_l_autorisateur(&st);
        bt2_cinq_cent_trois(code, &corps, BT2_INCHANGES_COMMIT);
        assert_eq!(bt2_a_froid(&p, &format!("SELECT COUNT(*) FROM view_dashboard WHERE view_id={v} AND dashboard_id={d1}")), 1);
    }

    // -------------------------------------------------------------------------------------
    // (7) suppression d'une vue, décompte, porte de partage
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : supprimer une vue retire ses rattachements (principal et hors `view_id`) ; la vue créée ensuite
    /// sous le MÊME rowid (constat relu) est vide ; un retrait des rattachements refusé -> 503 nommé, la vue reste.
    /// MUTATIONS : `BT2_VUE_EFFACEE_GARDE_LA_JOINTURE`, `BT2_VUE_EFFACEE_ERREUR_AVALEE`.
    #[tokio::test]
    async fn bt2_suppression_de_vue_nettoie_la_jointure() {
        let (st, _p) = bt2_etat("vue-effacee");
        let alice = sp_au("alice", "editor");
        let w = bt2_vue(&st, "W", "alice", "shared");
        let d0 = bt2_tableau(&st, "D0", "", "shared", None);
        bt2_rattacher(&st, w, d0);
        bt2_ecrire(&st, &format!("CREATE TEMP TRIGGER bt2_refus BEFORE DELETE ON main.view_dashboard WHEN OLD.view_id={w} BEGIN SELECT RAISE(ABORT, 'refus de témoin'); END;"));
        let (code, corps) = pb_json(view_delete(State(st.clone()), Extension(alice.clone()), Path(w)).await).await;
        bt2_ecrire(&st, "DROP TRIGGER bt2_refus;");
        bt2_cinq_cent_trois(code, &corps, BT2_VUE_NON_SUPPRIMEE);
        assert_eq!(bt2_entier(&st, &format!("SELECT COUNT(*) FROM view WHERE id={w}")), 1, "la vue reste");
        let v = bt2_vue(&st, "V", "alice", "shared");
        let d1 = bt2_tableau(&st, "D1", "", "shared", Some(v));
        let d2 = bt2_tableau(&st, "D2", "", "shared", None);
        bt2_rattacher(&st, v, d2);
        let r = view_delete(State(st.clone()), Extension(alice.clone()), Path(v)).await;
        assert_eq!(r.status().as_u16(), 204);
        assert_eq!(bt2_rattachements(&st), vec![(w, d0)], "les rattachements de la vue supprimée sont partis");
        assert_eq!(bt2_vue_principale(&st, d1), None);
        let (_, neuve) = bt2_creer_vue(&st, &alice, "Neuve", "shared").await;
        assert_eq!(neuve["id"].as_i64(), Some(v), "fixture : le rowid est réutilisé");
        assert_eq!(bt2_ids_sous(&st, &v.to_string()).await, Vec::<i64>::new(), "la vue neuve n'hérite de rien");
    }

    /// CE QU'IL TIENT : le décompte de `views_list` compte les rattachements de la jointure (principal et hors
    /// `view_id`), pas un tableau de toutes les vues. MUTATION : `BT2_DECOMPTE_PAR_COLONNE`.
    #[tokio::test]
    async fn bt2_decompte_des_vues_lit_la_jointure() {
        let (st, _p) = bt2_etat("decompte");
        let v = bt2_vue(&st, "V", "", "shared");
        bt2_tableau(&st, "D1", "", "shared", Some(v));
        let d2 = bt2_tableau(&st, "D2", "", "shared", None);
        bt2_rattacher(&st, v, d2);
        let c = bt2_tableau(&st, "C", "", "shared", None);
        bt2_ecrire(&st, &format!("UPDATE dashboard SET all_views=1 WHERE id={c}"));
        let Json(corps) = views_list(State(st.clone()), Extension(sp_au("adm", "admin"))).await;
        let vues = corps["views"].as_array().unwrap_or_else(|| panic!("{corps}"));
        assert_eq!(vues.iter().map(|x| (x["id"].as_i64().unwrap(), x["dashboards"].as_i64().unwrap())).collect::<Vec<_>>(), vec![(v, 2)]);
    }

    /// CE QU'IL TIENT : la porte de partage d'une vue est retenue par un tableau privé rangé hors vue principale
    /// (phrase exacte qui le nomme) ; avec un second privé rangé par `view_id`, la phrase nomme celui-ci et compte
    /// l'autre ; un seul privé par `view_id` n'est pas compté deux fois ; un privé de toutes les vues ne retient pas.
    /// MUTATIONS : `BT2_PARTAGE_SANS_JOINTURE`, `BT2_PARTAGE_SANS_SOMME`, `BT2_PARTAGE_DOUBLE_COMPTE`,
    /// `BT2_PARTAGE_TOUTES_RETIENT`.
    #[tokio::test]
    async fn bt2_partage_d_une_vue_retenu_par_un_rattachement_prive() {
        let (st, _p) = bt2_etat("partage");
        let alice = sp_au("alice", "editor");
        let partager = |vue: i64| {
            let (st, au) = (st.clone(), alice.clone());
            async move { pb_json(view_update(State(st), Extension(au), Path(vue), Json(json!({ "visibility": "shared" }))).await).await }
        };
        let z = bt2_vue(&st, "Z", "alice", "private");
        let toutes = bt2_tableau(&st, "Toutes", "alice", "private", None);
        bt2_ecrire(&st, &format!("UPDATE dashboard SET all_views=1 WHERE id={toutes}"));
        let (code, corps) = partager(z).await;
        assert_eq!(code, 204, "un privé de toutes les vues ne retient pas : {corps}");
        let v = bt2_vue(&st, "V", "alice", "private");
        let d = bt2_tableau(&st, "Hors principale", "alice", "private", None);
        bt2_rattacher(&st, v, d);
        let (code, corps) = partager(v).await;
        assert_eq!(
            (code, corps),
            (409, json!({ "_texte": format!("Partage refusé : le tableau de bord « Hors principale » (n° {d}, à alice) est privé. Partagez d'abord cet élément, ou retirez-le, puis partagez la vue.") }))
        );
        let w = bt2_vue(&st, "W", "alice", "private");
        let p = bt2_tableau(&st, "Principal", "alice", "private", Some(w));
        let (code, corps) = partager(w).await;
        assert_eq!(
            (code, corps),
            (409, json!({ "_texte": format!("Partage refusé : le tableau de bord « Principal » (n° {p}, à alice) est privé. Partagez d'abord cet élément, ou retirez-le, puis partagez la vue.") })),
            "un seul élément, compté une fois"
        );
        bt2_rattacher(&st, w, d);
        let (code, corps) = partager(w).await;
        assert_eq!(
            (code, corps),
            (409, json!({ "_texte": format!("Partage refusé : le tableau de bord « Principal » (n° {p}, à alice) est privé — et 1 autre(s) élément(s) le retiennent aussi. Partagez d'abord cet élément, ou retirez-le, puis partagez la vue.") }))
        );
    }

    /// CE QU'IL TIENT : le compte des rattachements hors vue principale illisible -> 503 nommé ; le compte lu mais la
    /// ligne du premier illisible -> 503 nommé ; jamais 204. MUTATIONS : `BT2_PARTAGE_JOINTURE_ILLISIBLE_RIEN`,
    /// `BT2_PREMIER_ILLISIBLE_RIEN`.
    #[tokio::test]
    async fn bt2_partage_lectures_non_faites() {
        let (st, _p) = bt2_etat("partage-illisible");
        let alice = sp_au("alice", "editor");
        let v = bt2_vue(&st, "V", "alice", "private");
        let d = bt2_tableau(&st, "Hors principale", "alice", "private", None);
        bt2_rattacher(&st, v, d);
        let attendu = (503, json!(crate::handlers::panneau_resolu::CAUSE_ELEMENTS_RETENANT_NON_LUS));
        bt2_rendre_illisible(&st, "view_dashboard", &format!("{BT2_DEBORDE} AS view_id, dashboard_id"));
        let (code, corps) = pb_json(view_update(State(st.clone()), Extension(alice.clone()), Path(v), Json(json!({ "visibility": "shared" }))).await).await;
        bt2_rendre_lisible(&st, "view_dashboard");
        assert_eq!((code, corps["error"].clone()), attendu.clone(), "compte illisible");
        bt2_rendre_illisible(
            &st,
            "dashboard",
            &format!("id, CASE WHEN COALESCE(visibility,'shared')<>'shared' THEN {BT2_DEBORDE} ELSE name END AS name, owner, visibility, view_id, all_views"),
        );
        let (code, corps) = pb_json(view_update(State(st.clone()), Extension(alice.clone()), Path(v), Json(json!({ "visibility": "shared" }))).await).await;
        bt2_rendre_lisible(&st, "dashboard");
        assert_eq!((code, corps["error"].clone()), attendu, "première ligne illisible");
        assert_eq!(bt2_entier(&st, &format!("SELECT COUNT(*) FROM view WHERE id={v} AND visibility='private'")), 1, "rien n'est écrit");
    }

    // -------------------------------------------------------------------------------------
    // (8) seconde passe : visibilité de la porte de partage, retrait d'une vue secondaire, routes par le routeur,
    //     `view_ids` borné au périmètre de l'appelant, renommage vers un homonyme
    // -------------------------------------------------------------------------------------

    const BT2C_RENOMMEE_VERS_UNE_EXISTANTE: &str = "VUE DÉJÀ EXISTANTE : une autre vue de ce nom existe déjà parmi celles que vous voyez — rien n'est renommé, rien du corps n'est appliqué. Complétez-la (POST /api/views/{id}/dashboards) ou choisissez un autre nom.";
    const BT2C_HOMONYMES_NON_LUS: &str = "VUE INCHANGÉE : la base n'a pas rendu les vues de ce nom — ce n'est PAS « aucune vue de ce nom », c'est une lecture qui n'a pas eu lieu, et le doublon n'est pas jugé. RIEN n'est renommé ni partagé. Réessayez ; si le refus persiste, la table des vues est illisible.";

    fn bt2c_phrase_de_partage(nom: &str, n: i64) -> Value {
        json!({ "_texte": format!("Partage refusé : le tableau de bord « {nom} » (n° {n}, à alice) est privé. Partagez d'abord cet élément, ou retirez-le, puis partagez la vue.") })
    }

    fn bt2c_vue_lue(st: &AppState, vue: i64) -> (String, String) {
        st.db.lock().query_row("SELECT name,visibility FROM view WHERE id=?1", params![vue], |r| Ok((r.get(0)?, r.get(1)?))).unwrap()
    }

    /// CE QU'IL TIENT : un tableau COMMUN rangé dans la vue hors vue principale ne retient pas son partage (204) ; à
    /// côté d'un privé de rowid plus grand, c'est le privé qui est nommé, seul ; à côté d'un privé principal, il n'est pas
    /// compté. MUTATIONS : `BT2C_COMPTE_SANS_VIS` (le compte de la jointure sans filtre de visibilité : 503 puis « 1
    /// autre(s) »), `BT2C_PREMIER_SANS_VIS` (le premier élément sans filtre : le commun est nommé).
    #[tokio::test]
    async fn bt2c_partage_un_tableau_commun_rattache_ne_retient_pas() {
        let (st, _p) = bt2_etat("partage-commun");
        let alice = sp_au("alice", "editor");
        let partager = |vue: i64| {
            let (st, au) = (st.clone(), alice.clone());
            async move { pb_json(view_update(State(st), Extension(au), Path(vue), Json(json!({ "visibility": "shared" }))).await).await }
        };
        let v = bt2_vue(&st, "V", "alice", "private");
        let c = bt2_tableau(&st, "Commun", "bob", "shared", None);
        bt2_rattacher(&st, v, c);
        let (code, corps) = partager(v).await;
        assert_eq!(code, 204, "un commun rattaché ne retient pas : {corps}");
        assert_eq!(bt2c_vue_lue(&st, v).1, "shared");
        let w = bt2_vue(&st, "W", "alice", "private");
        let c2 = bt2_tableau(&st, "Commun 2", "bob", "shared", None);
        let p = bt2_tableau(&st, "Privé", "alice", "private", None);
        assert!(c2 < p, "fixture : le commun a le plus petit rowid");
        bt2_rattacher(&st, w, c2);
        bt2_rattacher(&st, w, p);
        assert_eq!(partager(w).await, (409, bt2c_phrase_de_partage("Privé", p)), "le privé est nommé, seul");
        let x = bt2_vue(&st, "X", "alice", "private");
        let pp = bt2_tableau(&st, "Principal privé", "alice", "private", Some(x));
        let c3 = bt2_tableau(&st, "Commun 3", "bob", "shared", None);
        bt2_rattacher(&st, x, c3);
        assert_eq!(partager(x).await, (409, bt2c_phrase_de_partage("Principal privé", pp)), "le commun n'est pas compté");
    }

    /// CE QU'IL TIENT : retirer une vue SECONDAIRE d'un tableau qui a une autre vue principale (204) laisse la vue
    /// principale et son rattachement en place. MUTATION : `BT2C_RETRAIT_SANS_CONDITION` (`AND view_id=?2` retiré : la
    /// vue principale est vidée, et le déclencheur emporte son rattachement).
    #[tokio::test]
    async fn bt2c_retirer_une_vue_secondaire_garde_la_vue_principale() {
        let (st, _p) = bt2_etat("retirer-secondaire");
        let alice = sp_au("alice", "editor");
        let v1 = bt2_vue(&st, "V1", "alice", "shared");
        let v2 = bt2_vue(&st, "V2", "alice", "shared");
        let d = bt2_tableau(&st, "D", "", "shared", Some(v1));
        bt2_rattacher(&st, v2, d);
        assert_eq!(bt2_rattachements(&st), vec![(v1, d), (v2, d)], "fixture");
        let (code, corps) = bt2_retirer(&st, &alice, v2, d).await;
        assert_eq!(code, 204, "{corps}");
        assert_eq!((bt2_rattachements(&st), bt2_vue_principale(&st, d)), (vec![(v1, d)], Some(v1)), "la vue principale reste");
    }

    /// CE QU'IL TIENT : `POST /api/views/{id}/dashboards` et `DELETE /api/views/{id}/dashboards/{dashboard_id}` sont
    /// servis par le ROUTEUR réel (authentification, porte de rôle, gestionnaire) : un lecteur est refusé (403) sur une
    /// vue qu'il possède pourtant, rien n'est écrit ni retiré ; un éditeur propriétaire rattache (200, `added`) puis
    /// retire (204). MUTATIONS : `BT2C_SANS_ROUTE_AJOUT`, `BT2C_SANS_ROUTE_RETRAIT` (chemin non enregistré),
    /// `BT2C_SANS_PORTE_EDITOR` (le préfixe `/api/views/` admis au lecteur).
    #[tokio::test]
    async fn bt2c_routes_de_rattachement_servies_par_le_routeur_a_l_editeur() {
        let (st, _p) = router_test_state("bt2c-routes");
        let (vv, ve, d) = {
            let c = st.db.lock();
            c.execute("INSERT INTO user(name,hash,role) VALUES('edt',?1,'editor')", params![hash_pw("editorpw12345").unwrap()]).unwrap();
            c.execute("INSERT INTO view(name,owner,visibility) VALUES('Du lecteur','vwr','private')", []).unwrap();
            let vv = c.last_insert_rowid();
            c.execute("INSERT INTO view(name,owner,visibility) VALUES('De l''éditeur','edt','private')", []).unwrap();
            let ve = c.last_insert_rowid();
            c.execute("INSERT INTO dashboard(name,created,owner,visibility,cols,height,collapsed) VALUES('Commun',1000,'','shared',1,0,0)", []).unwrap();
            (vv, ve, c.last_insert_rowid())
        };
        let addr = router_serve(st.clone()).await;
        let editeur = format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "edt:editorpw12345"));
        let en_json = [("Content-Type", "application/json")];
        let corps = format!("{{\"dashboard_ids\":[{d}]}}");
        let present = |v: i64| bt2_entier(&st, &format!("SELECT COUNT(*) FROM view_dashboard WHERE view_id={v} AND dashboard_id={d}"));
        let (code, texte) = router_probe_envoi(addr, "POST", &format!("/api/views/{vv}/dashboards"), Some(&viewer_authz()), &en_json, &corps).await;
        assert_eq!(code, 403, "le lecteur est refusé par la porte de rôle : {texte}");
        assert_eq!(present(vv), 0, "rien n'est rattaché");
        bt2_rattacher(&st, vv, d);
        let (code, texte) = router_probe_envoi(addr, "DELETE", &format!("/api/views/{vv}/dashboards/{d}"), Some(&viewer_authz()), &[], "").await;
        assert_eq!(code, 403, "le lecteur est refusé par la porte de rôle : {texte}");
        assert_eq!(present(vv), 1, "rien n'est retiré");
        let (code, texte) = router_probe_envoi(addr, "POST", &format!("/api/views/{ve}/dashboards"), Some(&editeur), &en_json, &corps).await;
        assert_eq!(code, 200, "{texte}");
        assert!(texte.contains(&format!("\"added\":[{d}]")), "{texte}");
        assert_eq!(present(ve), 1, "rattaché par la route");
        let (code, texte) = router_probe_envoi(addr, "DELETE", &format!("/api/views/{ve}/dashboards/{d}"), Some(&editeur), &[], "").await;
        assert_eq!(code, 204, "{texte}");
        assert_eq!(present(ve), 0, "retiré par la route");
    }

    /// CE QU'IL TIENT : `view_ids` ne sert que les vues que l'appelant voit (périmètre de `views_list`) : bob ne reçoit
    /// pas la vue privée d'alice, alice pas celle de bob, l'administrateur les trois. MUTATION :
    /// `BT2C_VIEW_IDS_SANS_PERIMETRE`.
    #[tokio::test]
    async fn bt2c_view_ids_ne_sert_que_les_vues_que_l_appelant_voit() {
        let (st, _p) = bt2_etat("view-ids-perimetre");
        let pa = bt2_vue(&st, "Privée d'alice", "alice", "private");
        let s = bt2_vue(&st, "Commune", "bob", "shared");
        let pb = bt2_vue(&st, "Privée de bob", "bob", "private");
        let d = bt2_tableau(&st, "D", "", "shared", None);
        for v in [pa, s, pb] {
            bt2_rattacher(&st, v, d);
        }
        let mut vus = Vec::new();
        for au in [sp_au("bob", "editor"), sp_au("alice", "editor"), sp_au("adm", "admin")] {
            let (code, v) = bt2_liste(&st, &au, &[]).await;
            assert_eq!((code, bt2_ids(&v)), (200, vec![d]), "{v}");
            vus.push(v["dashboards"][0]["view_ids"].clone());
        }
        assert_eq!(vus, vec![json!([s, pb]), json!([pa, s]), json!([pa, s, pb])]);
    }

    /// CE QU'IL TIENT : renommer une vue vers le nom d'une AUTRE vue que le renommeur voit -> 409 avec l'identifiant de
    /// l'existante, rien du corps appliqué (ni nom ni partage) ; son propre nom n'est pas un doublon (204) ; la vue privée
    /// d'autrui ne l'est pas non plus (204), elle l'est pour l'administrateur (409) ; la recherche illisible -> 503
    /// nommé, rien n'est renommé. MUTATIONS : `BT2C_RENOMMAGE_SANS_RECHERCHE`, `BT2C_RENOMMAGE_INCLUT_SOI`,
    /// `BT2C_RENOMMAGE_GLOBAL`, `BT2C_RENOMMAGE_ILLISIBLE_RIEN`.
    #[tokio::test]
    async fn bt2c_renommer_vers_une_vue_existante_est_refuse() {
        let (st, _p) = bt2_etat("renommage");
        let (alice, adm) = (sp_au("alice", "editor"), sp_au("adm", "admin"));
        let modifier = |vue: i64, au: &AuthUser, corps: Value| {
            let (st, au) = (st.clone(), au.clone());
            async move { pb_json(view_update(State(st), Extension(au), Path(vue), Json(corps)).await).await }
        };
        let a = bt2_vue(&st, "A", "alice", "shared");
        let b = bt2_vue(&st, "B", "alice", "private");
        let pb = bt2_vue(&st, "Privée de bob", "bob", "private");
        assert_eq!(
            modifier(b, &alice, json!({ "name": "A", "visibility": "shared" })).await,
            (409, json!({ "error": BT2C_RENOMMEE_VERS_UNE_EXISTANTE, "view_id": a }))
        );
        assert_eq!(bt2c_vue_lue(&st, b), ("B".to_string(), "private".to_string()), "rien du corps n'est appliqué");
        let (code, corps) = modifier(b, &alice, json!({ "name": "B" })).await;
        assert_eq!(code, 204, "son propre nom n'est pas un doublon : {corps}");
        assert_eq!(
            modifier(a, &adm, json!({ "name": "Privée de bob" })).await,
            (409, json!({ "error": BT2C_RENOMMEE_VERS_UNE_EXISTANTE, "view_id": pb })),
            "l'administrateur voit la vue privée de bob"
        );
        let (code, corps) = modifier(b, &alice, json!({ "name": "Privée de bob" })).await;
        assert_eq!(code, 204, "la vue privée de bob n'est pas dans le périmètre d'alice : {corps}");
        assert_eq!(bt2c_vue_lue(&st, b).0, "Privée de bob");
        bt2_rendre_illisible(&st, "view", &format!("id, CASE WHEN id={b} THEN name ELSE {BT2_DEBORDE} END AS name, owner, visibility, created"));
        let (code, corps) = modifier(b, &alice, json!({ "name": "Z" })).await;
        bt2_rendre_lisible(&st, "view");
        bt2_cinq_cent_trois(code, &corps, BT2C_HOMONYMES_NON_LUS);
        assert_eq!(bt2c_vue_lue(&st, b).0, "Privée de bob", "rien n'est renommé");
    }
}
