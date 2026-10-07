// =====================================================================================
// `P10.20-w` (rang QUATRE) — UNE CRÉATION NE SERT UN IDENTIFIANT QUE SUR UNE LIGNE ÉCRITE.
//
// CE QUE CES TÉMOINS TIENNENT. Les six créations du rang quatre — tableau de bord, panneau, vue,
// panneau de bibliothèque, liste de lecture, instantané — avalaient leur `INSERT` puis servaient
// `last_insert_rowid()`. La garde de forme `check_a_swallowed_write_is_never_affirmed_as_a_fact.py`
// constate que la forme a disparu des sources ; elle ne prouve pas qu'une réponse RÉELLE refuse. Ces
// témoins jouent chaque route sur une table rendue non modifiable (vue temporaire posée sur la
// connexion d'écriture : la lecture passe, l'écriture échoue), APRÈS avoir amorcé la connexion avec
// des maillons de registre — l'identifiant que l'ancienne forme servait était celui du DERNIER de ces
// maillons. Chaque témoin porte son CONTRÔLE POSITIF : la vue retirée, la même route sert
// l'identifiant de la ligne ÉCRITE, relu par la clé.
//
// CE QU'ILS NE TIENNENT PAS : une base réellement en lecture seule (seulement un objet non
// modifiable, même chemin de code) ; ce que la console PEINT de ces refus (`P10.21-d`) ; la voie
// « plusieurs lignes écrites » (aucune forme d'insertion de ces routes ne peut en écrire plus
// d'une ; le bras `Ok(n)` est jugé sur `n = 0`, joué sur les SIX sites par un déclencheur
// `RAISE(IGNORE)` dans `isc_juger`). L'absence de ligne sous la vue non modifiable est un constat
// sur la FIXTURE (c'est la vue qui refuse l'écriture), pas une affirmation du correctif.
// =====================================================================================
mod identifiant_servi_sur_une_ligne_ecrite {
    use super::*;

    fn isc_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        sp_state(&format!("isc-{tag}"))
    }

    fn isc_admin() -> AuthUser {
        sp_au("adm", "admin")
    }

    fn isc_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn isc_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// Après cet appel, `last_insert_rowid()` sur la connexion du gestionnaire désigne un maillon du
    /// REGISTRE : c'est l'identifiant que l'ancienne forme servait comme numéro d'objet.
    fn isc_amorcer_la_connexion(st: &AppState) {
        let conn = st.db.lock();
        for i in 0..3 {
            ledger_append(&conn, "temoin.amorce", &format!("amorce {i}"));
        }
    }

    fn isc_rendre_non_modifiable(st: &AppState, table: &str) {
        isc_ecrire(
            st,
            &format!("ALTER TABLE \"{table}\" RENAME TO \"{table}_source\"; CREATE TEMP VIEW \"{table}\" AS SELECT * FROM \"{table}_source\";"),
        );
    }

    fn isc_rendre_modifiable(st: &AppState, table: &str) {
        isc_ecrire(st, &format!("DROP VIEW \"{table}\"; ALTER TABLE \"{table}_source\" RENAME TO \"{table}\";"));
    }

    /// L'identifiant NUMÉRIQUE servi. Le `id` d'un 5xx d'`err_json` est une chaîne de corrélation.
    fn isc_identifiant_servi(v: &Value) -> Option<i64> {
        v.get("id").and_then(|x| x.as_i64())
    }

    fn isc_dashboard(st: &AppState) -> i64 {
        isc_ecrire(st, "INSERT INTO dashboard(name,created,visibility,owner) VALUES('D de témoin',1000,'shared','adm');");
        isc_compte(st, "SELECT MAX(id) FROM dashboard")
    }

    /// Refus commun : 503, cause nommée par son préfixe (et, si donnée, par `detail`), aucun
    /// identifiant numérique, aucun jeton.
    fn isc_refus_nomme(table: &str, voie: &str, statut: u16, refus: &Value, detail: Option<&str>) {
        assert_eq!(statut, 503, "`{table}` ({voie}) : la route REFUSE au lieu de servir un identifiant : {refus}");
        let cause = refus["error"].as_str().unwrap_or("");
        assert!(cause.starts_with(crate::handlers::dashboards::CAUSE_OBJET_NON_CREE), "`{table}` ({voie}) : le refus NOMME sa cause : {refus}");
        if let Some(d) = detail {
            assert!(cause.contains(d), "`{table}` ({voie}) : la cause dit `{d}` : {refus}");
        }
        assert_eq!(
            isc_identifiant_servi(refus), None,
            "`{table}` ({voie}) : AUCUN identifiant n'est servi — celui de l'ancienne forme désignait un maillon du REGISTRE : {refus}"
        );
        assert_eq!(refus.get("token"), None, "`{table}` ({voie}) : aucun jeton de partage n'est servi : {refus}");
    }

    /// LE JUGEMENT COMMUN. `creer` joue la route ; `table` est la table de l'objet. Trois phases :
    /// (1) table non modifiable (bras `Err`) ; (2) insertion qui « réussit » sans poser de ligne,
    /// déclencheur `RAISE(IGNORE)` (bras `Ok(n)`, n = 0) ; (3) contrôle positif (200, identifiant =
    /// celui de la ligne écrite). Les deux refus : 503 nommé, aucun identifiant, registre inchangé.
    async fn isc_juger<F, Fut>(st: &AppState, table: &str, creer: F) -> Value
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Response>,
    {
        isc_amorcer_la_connexion(st);
        let lignes_avant = isc_compte(st, &format!("SELECT COUNT(*) FROM \"{table}\""));
        isc_rendre_non_modifiable(st, table);
        let registre_avant = isc_compte(st, "SELECT COUNT(*) FROM ledger");

        let (statut, refus) = pb_json(creer().await).await;
        isc_refus_nomme(table, "non modifiable", statut, &refus, None);
        assert_eq!(isc_compte(st, "SELECT COUNT(*) FROM ledger"), registre_avant, "rien n'entre au registre");
        // Constat de FIXTURE (la vue refuse l'écriture), pas une affirmation du correctif.
        assert_eq!(isc_compte(st, &format!("SELECT COUNT(*) FROM \"{table}_source\"")), lignes_avant, "fixture : la vue a refusé l'écriture");
        isc_rendre_modifiable(st, table);

        // ZÉRO LIGNE ÉCRITE — l'`INSERT` « réussit » (Ok(0)) ; `last_insert_rowid()` désigne encore
        // un maillon du registre. Une route qui servirait l'identifiant sans compter les lignes
        // rendrait 200 avec ce numéro emprunté.
        isc_amorcer_la_connexion(st);
        isc_ecrire(st, &format!("CREATE TEMP TRIGGER isc_ignorer BEFORE INSERT ON main.\"{table}\" BEGIN SELECT RAISE(IGNORE); END;"));
        let registre_avant = isc_compte(st, "SELECT COUNT(*) FROM ledger");
        let (statut, refus) = pb_json(creer().await).await;
        isc_refus_nomme(table, "zéro ligne écrite", statut, &refus, Some("0 ligne(s) écrite(s) au lieu d'une"));
        assert_eq!(isc_compte(st, "SELECT COUNT(*) FROM ledger"), registre_avant, "`{table}` (zéro ligne) : rien n'entre au registre");
        isc_ecrire(st, "DROP TRIGGER isc_ignorer;");

        // CONTRÔLE POSITIF — le refus n'est pas inconditionnel, et l'identifiant servi est celui de la
        // ligne ÉCRITE, jamais celui d'une autre table.
        isc_amorcer_la_connexion(st);
        let (statut, pose) = pb_json(creer().await).await;
        assert_eq!(statut, 200, "contrôle positif : la création aboutit : {pose}");
        let servi = isc_identifiant_servi(&pose).unwrap_or_else(|| panic!("un identifiant numérique est servi : {pose}"));
        assert_eq!(servi, isc_compte(st, &format!("SELECT MAX(id) FROM \"{table}\"")), "l'identifiant servi est celui de la ligne écrite");
        assert_eq!(isc_compte(st, &format!("SELECT COUNT(*) FROM \"{table}\"")), lignes_avant + 1, "UNE ligne écrite");
        pose
    }

    /// CE QU'IL TIENT : `POST /api/dashboards` sur `dashboard` non modifiable rend 503 nommé sans
    /// identifiant. MUTATION : `VERIF_MUT=B6_DASH` (le bras `Err` sert `last_insert_rowid()`) -> 200
    /// avec l'identifiant du dernier maillon de registre, l'assert du statut tombe.
    #[tokio::test]
    async fn isc_un_tableau_de_bord_non_ecrit_ne_sert_aucun_identifiant() {
        let (st, _tmp) = isc_etat("dash");
        let au = isc_admin();
        isc_juger(&st, "dashboard", || dash_create(State(st.clone()), Extension(au.clone()), Json(json!({ "name": "à moi", "visibility": "private" })))).await;
    }

    /// CE QU'IL TIENT : une insertion qui « réussit » sans poser de ligne (déclencheur `RAISE(IGNORE)`)
    /// n'est pas une création : 503 nommé, aucun identifiant — le `Ok(0)` laissait l'identifiant d'une
    /// autre table sur la connexion. MUTATION : `VERIF_MUT=B6_DASH_ZERO` -> 200 avec ce numéro emprunté.
    #[tokio::test]
    async fn isc_une_insertion_ignoree_ne_sert_aucun_identifiant() {
        let (st, _tmp) = isc_etat("dash-zero");
        isc_amorcer_la_connexion(&st);
        isc_ecrire(&st, "CREATE TEMP TRIGGER isc_ignorer BEFORE INSERT ON main.dashboard BEGIN SELECT RAISE(IGNORE); END;");
        let avant = isc_compte(&st, "SELECT COUNT(*) FROM dashboard");
        let (statut, refus) = pb_json(dash_create(State(st.clone()), Extension(isc_admin()), Json(json!({ "name": "ignoré" }))).await).await;
        isc_refus_nomme("dashboard", "insertion ignorée", statut, &refus, Some("0 ligne(s) écrite(s) au lieu d'une"));
        assert_eq!(isc_compte(&st, "SELECT COUNT(*) FROM dashboard"), avant, "aucune ligne");
        isc_ecrire(&st, "DROP TRIGGER isc_ignorer;");
        let (statut, pose) = pb_json(dash_create(State(st.clone()), Extension(isc_admin()), Json(json!({ "name": "posé" }))).await).await;
        assert_eq!(statut, 200, "contrôle positif : {pose}");
        assert_eq!(isc_identifiant_servi(&pose), Some(isc_compte(&st, "SELECT id FROM dashboard WHERE name='posé'")));
    }

    /// MUTATION : `VERIF_MUT=B6_PANEL` -> 200 avec un identifiant emprunté.
    #[tokio::test]
    async fn isc_un_panneau_non_ecrit_ne_sert_aucun_identifiant() {
        let (st, _tmp) = isc_etat("panel");
        let au = isc_admin();
        let did = isc_dashboard(&st);
        isc_juger(&st, "panel", || {
            panel_create(
                State(st.clone()),
                Extension(au.clone()),
                Json(json!({ "dashboard_id": did, "title": "p", "query": "search source=web | table message", "is_soql": true })),
            )
        })
        .await;
    }

    /// MUTATION : `VERIF_MUT=B6_VIEW` -> 200 avec un identifiant emprunté.
    #[tokio::test]
    async fn isc_une_vue_non_ecrite_ne_sert_aucun_identifiant() {
        let (st, _tmp) = isc_etat("view");
        let au = isc_admin();
        isc_juger(&st, "view", || view_create(State(st.clone()), Extension(au.clone()), Json(json!({ "name": "ma vue" })))).await;
    }

    /// MUTATION : `VERIF_MUT=B6_LIB` -> 200 avec un identifiant emprunté.
    #[tokio::test]
    async fn isc_un_panneau_de_bibliotheque_non_ecrit_ne_sert_aucun_identifiant() {
        let (st, _tmp) = isc_etat("lib");
        let au = isc_admin();
        isc_juger(&st, "library_panel", || {
            library_panel_create(State(st.clone()), Extension(au.clone()), Json(json!({ "name": "réutilisable", "query": "search source=web | table message" })))
        })
        .await;
    }

    /// MUTATION : `VERIF_MUT=B6_PLAYLIST` -> 200 avec un identifiant emprunté.
    #[tokio::test]
    async fn isc_une_liste_de_lecture_non_ecrite_ne_sert_aucun_identifiant() {
        let (st, _tmp) = isc_etat("playlist");
        let au = isc_admin();
        isc_juger(&st, "playlist", || playlist_create(State(st.clone()), Extension(au.clone()), Json(json!({ "name": "mur" })))).await;
    }

    /// CE QU'IL TIENT EN PLUS : ni identifiant NI jeton de partage — le jeton servi par l'ancienne
    /// forme était un lien qui ne menait à rien. MUTATION : `VERIF_MUT=B6_SNAP` -> 200, identifiant et
    /// jeton servis.
    #[tokio::test]
    async fn isc_un_instantane_non_ecrit_ne_sert_ni_identifiant_ni_jeton() {
        let (st, _tmp) = isc_etat("snap");
        let au = isc_admin();
        let did = isc_dashboard(&st);
        isc_ecrire(
            &st,
            &format!("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,visibility) VALUES({did},'p','search source=web | table message',1,'table',0,'shared');"),
        );
        let pose = isc_juger(&st, "dashboard_snapshot", || {
            snapshot_create(State(st.clone()), Extension(au.clone()), Json(json!({ "dashboard_id": did, "from": 0, "to": 0, "name": "i" })))
        })
        .await;
        assert_eq!(pose["token"].as_str().map(str::len), Some(64), "contrôle positif : un jeton est rendu : {pose}");
    }
}
