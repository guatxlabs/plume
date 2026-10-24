// =====================================================================================
// `P10.20-l` (vague AJ : `dash_get`, `panel_access`, `read_panel_cost`, `panel_cache_ttl` dans handlers/dashboards.rs ;
// `cloner_le_runbook`, `unique_custom_key` dans handlers/incidents.rs) — SIX LECTURES D'UNE LIGNE EN TROIS ISSUES.
//
// LE DÉFAUT, MESURÉ SUR 8639270b AVANT LE CORRECTIF. `dash_get` lisait le tableau de bord par `.ok()` et servait 404
// « dashboard introuvable » sur une lecture ratée ; `panel_access` lisait le panneau et son tableau par `.ok()?` et
// `panel_data` servait 403 « panneau inaccessible » (un refus de droit inventé) ; `read_panel_cost` rendait une lecture
// ratée comme « jamais mesuré » sans un mot ; `panel_cache_ttl` retombait en silence sur le TTL global (un TTL par
// panneau posé à 0 ou plus court se perdait) ; `cloner_le_runbook` servait 400 « runbook source introuvable » sur une
// lecture ratée de la source ; `unique_custom_key` lisait une lecture ratée comme « clé libre » (`while … .is_ok()`).
//
// LE CORRECTIF. Trois issues par `.optional()`. Absences : le 404, le 403 et le 400 d'avant, corps compris. Lectures
// ratées : 503 nommé (`CAUSE_TABLEAU_DE_BORD_NON_LU`, `CAUSE_PANNEAU_NON_LU`, `CAUSE_RUNBOOK_NON_CLONE_SOURCE_NON_LUE`,
// `CAUSE_CLE_DE_RUNBOOK_NON_LUE`), rien n'est servi, exécuté ni écrit ; le coût non lu sert le panneau comme jamais
// mesuré (comportement d'avant : chauffe quand il est cacheable) avec une ligne fixe ; le TTL non lu vaut 0 (cache coupé
// pour ce panneau, fail-closed) avec une ligne fixe.
// CE QUI ÉTAIT FAUX DANS L'ÉNONCÉ : « read_panel_cost rend None = LIVE » — depuis FIX #5c un panneau jamais mesuré
// part en SWR/chauffe quand il est cacheable (dashboards.rs, `unknown`) ; le témoin du coût le montre (`warming`).
//
// LA PANNE ÉPROUVÉE : la colonne lue stockée en BLOB (la ligne existe, sa conversion échoue), et pour la clé de runbook
// la colonne `key` renommée (seule la lecture d'occupation échoue, le compte du plafond et la source restent lisibles).
// Les lignes de journal sont lues sur le stderr d'un sous-processus et comparées EN ENTIER ; la cause du moteur attendue
// est RE-PRODUITE par la même requête sur la même base (jamais recopiée).
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : DASH_LECTURE_EN_404, DASH_ABSENT_EN_503,
// DASH_CAUSE_EXPOSEE, DASH_SANS_JOURNAL, DASH_JOURNAL_SUFFIXE ; PANEL_PANNEAU_EN_NONE, PANEL_TABLEAU_EN_NONE,
// PANEL_ABSENT_EN_503, PANEL_REFUS_DROIT_RETIRE, PANEL_DATA_LECTURE_EN_403, PANEL_DATA_SANS_JOURNAL,
// PANEL_DATA_JOURNAL_SUFFIXE ; COUT_ERR_EN_NONE, COUT_NON_LU_EN_MESURE, COUT_SANS_JOURNAL, COUT_JOURNAL_SUFFIXE ;
// TTL_LU_EN_GLOBAL, TTL_NULL_EN_ZERO, TTL_ABSENT_EN_ZERO, TTL_NON_LU_EN_GLOBAL, TTL_SANS_JOURNAL, TTL_JOURNAL_SUFFIXE ;
// CLONE_LECTURE_EN_400, CLONE_ABSENT_EN_503, CLONE_VARIANTE_LIGNE ; CLE_NON_LUE_LIBRE, CLE_VARIANTE_LIGNE,
// CLE_LIBRE_EN_REFUS, CLE_PRISE_EN_LIBRE.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ce que la console peint (web/ hors périmètre : le 503 de `dash_get` passe par le
// `catch` de `loadPanelsInto`, celui de `panel_data` par `refusDUneLectureServie`, ceux des runbooks par
// `peindreLeRefusDUnGeste` — lus, non joués) ; `DefinitionExecutee::courante` (`panneau_resolu.rs`, première lecture de
// `panel_access` ; en trois issues depuis la vague AK, témoins `ak1_`) ; une lecture ratée par verrou ou table retirée (la conversion suffit à
// atteindre le bras) ; le mode multi-tenant.
// =====================================================================================
mod lectures_des_panneaux_et_cles_de_runbook_en_trois_issues {
    use super::*;

    const AJ4_ABSENT: i64 = 987_655;
    const AJ4_TTL_GLOBAL: i64 = 60;

    fn aj4_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn aj4_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn aj4_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    /// Un 503 nommé, EN ENTIER : exactement `error` et `id`, la phrase attendue, l'identifiant de corrélation, aucune
    /// trace de la cause du moteur.
    fn aj4_juger_503(quoi: &str, (statut, corps, v): &(u16, String, Value), phrase: &str) {
        assert_eq!(*statut, 503, "{quoi} : une lecture ratée n'est ni une absence ni un refus de droit : {corps}");
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"], "{quoi} : exactement `error` et `id` : {corps}");
        assert_eq!(v["error"], json!(phrase), "{quoi} : la phrase nommée, seule : {corps}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
        assert!(!corps.contains("Invalid column type") && !corps.contains("Blob") && !corps.contains("no such column"), "{quoi} : la cause du moteur ne sort pas : {corps}");
    }

    fn aj4_tableau(st: &AppState, nom: &str, visibilite: &str) -> i64 {
        aj4_sql(st, &format!("INSERT INTO dashboard(name,created,owner,visibility) VALUES('{nom}',1000,'alice','{visibilite}');"));
        aj4_compte(st, "SELECT MAX(id) FROM dashboard")
    }

    /// Un panneau SQL sain (`SELECT 1 AS un`, is_soql=0) dans le tableau `did` ; rend son identifiant.
    fn aj4_panneau(st: &AppState, did: i64) -> i64 {
        aj4_sql(st, &format!("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES({did},'p','SELECT 1 AS un',0,'table');"));
        aj4_compte(st, "SELECT MAX(id) FROM panel")
    }

    fn aj4_q() -> Query<HashMap<String, String>> {
        Query(HashMap::from([("from".to_string(), (now() - 86_400).to_string()), ("to".to_string(), "0".to_string())]))
    }

    async fn aj4_fiche(st: &AppState, qui: &AuthUser, did: i64) -> (u16, String, Value) {
        aj4_reponse(dash_get(State(st.clone()), Extension(qui.clone()), Path(did)).await).await
    }

    async fn aj4_donnees(st: &AppState, qui: &AuthUser, pid: i64) -> (u16, String, Value) {
        aj4_reponse(panel_data(State(st.clone()), Extension(qui.clone()), Path(pid), aj4_q()).await).await
    }

    fn aj4_runbook(nom: &str) -> Value {
        json!({ "name": nom, "match_kind": "*", "steps": [{ "phase": "triage", "title": "regarder", "step_kind": "manual" }] })
    }

    async fn aj4_creer(st: &AppState, nom: &str) -> (u16, String, Value) {
        aj4_reponse(runbook_create(State(st.clone()), Extension(sp_au("adm", "admin")), Json(aj4_runbook(nom))).await).await
    }

    async fn aj4_cloner(st: &AppState, src: i64, nom: &str) -> (u16, String, Value) {
        aj4_reponse(runbook_clone_handler(State(st.clone()), Extension(sp_au("adm", "admin")), Path(src), Json(json!({ "name": nom }))).await).await
    }

    fn aj4_traces_runbook(st: &AppState) -> i64 {
        aj4_compte(st, "SELECT COUNT(*) FROM ledger WHERE kind LIKE 'config.runbook%'")
    }

    /// CE QU'IL TIENT (`dash_get`) : absent, `404` « dashboard introuvable » exactement ; lu, `200` avec son nom, et le
    /// tableau PRIVÉ d'alice reste `403` pour bob (le refus établi) ; nom illisible, `503` `CAUSE_TABLEAU_DE_BORD_NON_LU`
    /// en entier pour la propriétaire, l'admin et bob — aucun `403` décidé sur une lecture ratée, même pour le privé.
    /// MUTATIONS : DASH_LECTURE_EN_404, DASH_ABSENT_EN_503, DASH_CAUSE_EXPOSEE.
    #[tokio::test]
    async fn aj4_fiche_d_un_tableau_de_bord_illisible_jamais_404_ni_403() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("aj4-dash");
        let (alice, bob, adm) = (sp_au("alice", "editor"), sp_au("bob", "editor"), sp_au("adm", "admin"));
        let (statut, corps, _) = aj4_fiche(&st, &alice, AJ4_ABSENT).await;
        assert_eq!((statut, corps.as_str()), (404, "dashboard introuvable"), "absence établie : le 404 d'avant, corps compris");

        let partage = aj4_tableau(&st, "d-aj4-partage", "shared");
        let prive = aj4_tableau(&st, "d-aj4-prive", "private");
        let (statut, corps, v) = aj4_fiche(&st, &bob, partage).await;
        assert_eq!((statut, v["name"].clone()), (200, json!("d-aj4-partage")), "contrôle : lu, servi : {corps}");
        let (statut, corps, _) = aj4_fiche(&st, &bob, prive).await;
        assert_eq!(statut, 403, "contrôle : le privé d'alice reste refusé à bob quand il est lu : {corps}");

        aj4_sql(&st, &format!("UPDATE dashboard SET name=X'00' WHERE id IN ({partage},{prive});"));
        let cas = [("propriétaire", &alice, partage), ("admin", &adm, partage), ("bob, partagé", &bob, partage), ("bob, privé", &bob, prive)];
        assert!(cas.len() >= 4, "plancher : quatre lectures ratées");
        for (qui, au, did) in cas {
            let r = aj4_fiche(&st, au, did).await;
            aj4_juger_503(&format!("tableau illisible ({qui})"), &r, CAUSE_TABLEAU_DE_BORD_NON_LU);
        }
    }

    /// CE QU'IL TIENT (`panel_access` par `panel_data`) : panneau absent et panneau dont le tableau porteur est absent,
    /// `403` « panneau inaccessible » exactement ;
    /// panneau privé d'alice dans un tableau privé, `403` pour bob (refus établi, rien n'est armé) ; panneau lu, `200` ;
    /// ligne du PANNEAU illisible (`window_s`) ou ligne du TABLEAU illisible (`owner`), `503` `CAUSE_PANNEAU_NON_LU` en
    /// entier — aucun rafraîchissement armé, aucun cache écrit.
    /// MUTATIONS : PANEL_PANNEAU_EN_NONE, PANEL_TABLEAU_EN_NONE, PANEL_ABSENT_EN_503, PANEL_REFUS_DROIT_RETIRE,
    /// PANEL_DATA_LECTURE_EN_403.
    #[tokio::test]
    async fn aj4_donnees_d_un_panneau_illisible_jamais_403() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("aj4-panel");
        let (bob, adm) = (sp_au("bob", "editor"), sp_au("adm", "admin"));
        let (statut, _, v) = aj4_donnees(&st, &adm, AJ4_ABSENT).await;
        assert_eq!((statut, v), (403, json!({ "error": "panneau inaccessible" })), "absence établie : le 403 d'avant, corps compris");

        let orphelin = aj4_panneau(&st, AJ4_ABSENT);
        let (statut, _, v) = aj4_donnees(&st, &adm, orphelin).await;
        assert_eq!((statut, v), (403, json!({ "error": "panneau inaccessible" })), "tableau porteur absent : le 403 d'avant, corps compris");

        let prive = aj4_tableau(&st, "d-aj4-panel-prive", "private");
        let pid_prive = aj4_panneau(&st, prive);
        let (statut, _, v) = aj4_donnees(&st, &bob, pid_prive).await;
        assert_eq!((statut, v), (403, json!({ "error": "panneau inaccessible" })), "refus établi : le privé d'alice reste refusé à bob");

        let partage = aj4_tableau(&st, "d-aj4-panel", "shared");
        let pid = aj4_panneau(&st, partage);
        let (statut, corps, _) = aj4_donnees(&st, &bob, pid).await;
        assert_eq!(statut, 200, "contrôle : panneau lu, servi : {corps}");
        for _ in 0..20_000 {
            if st.panel_refresh_inflight.lock().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }

        let pid_panne = aj4_panneau(&st, partage);
        let tableau_panne = aj4_tableau(&st, "d-aj4-panel-tableau", "shared");
        let pid_tableau = aj4_panneau(&st, tableau_panne);
        aj4_sql(&st, &format!("UPDATE panel SET window_s=X'00' WHERE id={pid_panne}; UPDATE dashboard SET owner=X'00' WHERE id={tableau_panne};"));
        let cas = [("panneau illisible", pid_panne), ("tableau illisible", pid_tableau)];
        assert!(cas.len() >= 2, "plancher : les deux lectures de la porte");
        for (quoi, p) in cas {
            for (qui, au) in [("bob", &bob), ("admin", &adm)] {
                let r = aj4_donnees(&st, au, p).await;
                aj4_juger_503(&format!("{quoi} ({qui})"), &r, CAUSE_PANNEAU_NON_LU);
                assert!(st.panel_refresh_inflight.lock().is_empty(), "{quoi} ({qui}) : aucun rafraîchissement armé");
                assert_eq!(aj4_compte(&st, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={p}")), 0, "{quoi} ({qui}) : rien n'est mis en cache");
            }
        }
    }

    /// CE QU'IL TIENT (`panel_cache_ttl`, appel réel) : TTL posé à 7, rendu 7 ; colonne NULL, le global ; panneau absent,
    /// le global ; colonne illisible, `0` (cache coupé pour ce panneau) — le global choisi (60) diffère des deux.
    /// MUTATIONS : TTL_LU_EN_GLOBAL, TTL_NULL_EN_ZERO, TTL_ABSENT_EN_ZERO, TTL_NON_LU_EN_GLOBAL.
    #[test]
    fn aj4_ttl_du_cache_en_trois_issues_non_lu_coupe_le_cache() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = sp_state("aj4-ttl");
        let did = aj4_tableau(&st, "d-aj4-ttl", "shared");
        let (pose, nul, panne) = (aj4_panneau(&st, did), aj4_panneau(&st, did), aj4_panneau(&st, did));
        aj4_sql(&st, &format!("UPDATE panel SET panel_cache_ttl_s=7 WHERE id={pose}; UPDATE panel SET panel_cache_ttl_s=X'00' WHERE id={panne};"));
        let conn = st.db.lock();
        assert_eq!(panel_cache_ttl(&conn, pose, AJ4_TTL_GLOBAL), 7, "lu : le TTL du panneau");
        assert_eq!(panel_cache_ttl(&conn, nul, AJ4_TTL_GLOBAL), AJ4_TTL_GLOBAL, "NULL : le global");
        assert_eq!(panel_cache_ttl(&conn, AJ4_ABSENT, AJ4_TTL_GLOBAL), AJ4_TTL_GLOBAL, "absent : le global (comme avant)");
        assert_eq!(panel_cache_ttl(&conn, panne, AJ4_TTL_GLOBAL), 0, "non lu : cache coupé, jamais le global");
    }

    /// CE QU'IL TIENT (`read_panel_cost`, appel réel, puis `panel_data`) : coût mesuré, `Ok(Some(12.5))` ; aucun coût,
    /// `Ok(None)` ; coût illisible, `Err` — et `panel_data` sert ce panneau comme JAMAIS MESURÉ (comportement d'avant :
    /// `200` avec `warming: true`, une mesure armée), pas en exécution directe sur un coût supposé.
    /// MUTATIONS : COUT_ERR_EN_NONE, COUT_NON_LU_EN_MESURE.
    #[tokio::test]
    async fn aj4_cout_d_un_panneau_en_trois_issues_non_lu_servi_comme_jamais_mesure() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = sp_state("aj4-cout");
        let did = aj4_tableau(&st, "d-aj4-cout", "shared");
        let pid = aj4_panneau(&st, did);
        let fp = query_fingerprint("SELECT 1 AS un", false);
        {
            let conn = st.db.lock();
            assert_eq!(read_panel_cost(&conn, pid, &fp).expect("aucun coût : lecture faite"), None, "aucun coût : Ok(None)");
            record_panel_cost(&conn, pid, &fp, 12.5, now());
            assert_eq!(read_panel_cost(&conn, pid, &fp).expect("coût lu"), Some(12.5), "coût mesuré : Ok(Some)");
            conn.execute("UPDATE panel_cost SET cost_ms=X'00' WHERE panel_id=?1", params![pid]).unwrap();
            assert!(read_panel_cost(&conn, pid, &fp).is_err(), "coût illisible : Err, jamais « jamais mesuré »");
        }
        let (statut, corps, v) = aj4_donnees(&st, &sp_au("adm", "admin"), pid).await;
        assert_eq!((statut, v["warming"].clone()), (200, json!(true)), "coût non lu : servi comme jamais mesuré (chauffe), pas en direct : {corps}");
        for _ in 0..20_000 {
            if st.panel_refresh_inflight.lock().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }

    /// CE QU'IL TIENT (clonage, `cloner_le_runbook` par la route) : source absente, `400` « runbook source introuvable »
    /// exactement ; source illisible (`description`), `503` `CAUSE_RUNBOOK_NON_CLONE_SOURCE_NON_LUE` en entier — aucun
    /// runbook copié, aucune trace ; contrôle : source relisible, la copie est écrite (`200`).
    /// MUTATIONS : CLONE_LECTURE_EN_400, CLONE_ABSENT_EN_503, CLONE_VARIANTE_LIGNE.
    #[tokio::test]
    async fn aj4_clonage_d_un_runbook_source_illisible_jamais_400() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = sp_state("aj4-clone");
        let (statut, _, v) = aj4_cloner(&st, AJ4_ABSENT, "copie").await;
        assert_eq!((statut, v), (400, json!({ "error": "runbook source introuvable" })), "absence établie : le 400 d'avant, à l'octet");
        let (statut, corps, v) = aj4_creer(&st, "aj4 source").await;
        assert_eq!(statut, 200, "fixture : source créée : {corps}");
        let src = v["id"].as_i64().expect("fixture : identifiant");
        let (avant, traces) = (aj4_compte(&st, "SELECT COUNT(*) FROM runbook"), aj4_traces_runbook(&st));
        aj4_sql(&st, &format!("UPDATE runbook SET description=X'00' WHERE id={src};"));
        let r = aj4_cloner(&st, src, "copie").await;
        aj4_juger_503("source illisible", &r, crate::handlers::incidents::CAUSE_RUNBOOK_NON_CLONE_SOURCE_NON_LUE);
        assert_eq!(aj4_compte(&st, "SELECT COUNT(*) FROM runbook"), avant, "aucune copie écrite");
        assert_eq!(aj4_traces_runbook(&st), traces, "aucune trace écrite");
        assert!(st.db.lock().is_autocommit(), "aucune transaction pendante");
        aj4_sql(&st, &format!("UPDATE runbook SET description='' WHERE id={src};"));
        let (statut, corps, v) = aj4_cloner(&st, src, "copie").await;
        assert_eq!((statut, v.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>())), (200, Some(vec!["id".to_string()])), "contrôle : source relisible, copie écrite : {corps}");
        assert_eq!(aj4_compte(&st, "SELECT COUNT(*) FROM runbook"), avant + 1);
    }

    /// CE QU'IL TIENT (`unique_custom_key`, par la création et le clonage) : clé libre, `custom-aj4-cle` ; clé prise, la
    /// suivante (`custom-aj4-cle-1`, puis `-2` par le clonage) ; colonne `key` renommée (seule la lecture d'occupation
    /// échoue), `503` `CAUSE_CLE_DE_RUNBOOK_NON_LUE` en entier à la création comme au clonage — aucun runbook écrit,
    /// aucune trace.
    /// MUTATIONS : CLE_NON_LUE_LIBRE, CLE_VARIANTE_LIGNE, CLE_LIBRE_EN_REFUS, CLE_PRISE_EN_LIBRE.
    #[tokio::test]
    async fn aj4_cle_de_runbook_non_lue_n_est_pas_une_cle_libre() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = sp_state("aj4-cle");
        let mut ids = Vec::new();
        for _ in 0..2 {
            let (statut, corps, v) = aj4_creer(&st, "aj4 cle").await;
            assert_eq!(statut, 200, "création : {corps}");
            ids.push(v["id"].as_i64().expect("identifiant"));
        }
        let (statut, corps, v) = aj4_cloner(&st, ids[0], "aj4 cle").await;
        assert_eq!(statut, 200, "clonage : {corps}");
        ids.push(v["id"].as_i64().expect("identifiant"));
        let cles: Vec<String> = ids
            .iter()
            .map(|i| st.db.lock().query_row("SELECT key FROM runbook WHERE id=?1", params![i], |r| r.get(0)).expect("clé lue"))
            .collect();
        assert_eq!(cles, ["custom-aj4-cle", "custom-aj4-cle-1", "custom-aj4-cle-2"], "libre, puis prise -> la suivante");

        let (avant, traces) = (aj4_compte(&st, "SELECT COUNT(*) FROM runbook"), aj4_traces_runbook(&st));
        aj4_sql(&st, "ALTER TABLE runbook RENAME COLUMN key TO cle_renommee_aj4;");
        let r = aj4_creer(&st, "aj4 autre").await;
        aj4_juger_503("création, clé non lue", &r, crate::handlers::incidents::CAUSE_CLE_DE_RUNBOOK_NON_LUE);
        let r = aj4_cloner(&st, ids[0], "aj4 autre").await;
        aj4_juger_503("clonage, clé non lue", &r, crate::handlers::incidents::CAUSE_CLE_DE_RUNBOOK_NON_LUE);
        assert_eq!(aj4_compte(&st, "SELECT COUNT(*) FROM runbook"), avant, "aucun runbook écrit");
        assert_eq!(aj4_traces_runbook(&st), traces, "aucune trace écrite");
        assert!(st.db.lock().is_autocommit(), "aucune transaction pendante");
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus et comparées EN ENTIER : `dash_get` et `panel_data`
    /// écrivent `[dashboards] WARN … NON lu …, rien n'est servi (<corrélation>) : <cause du moteur>` ; le coût et le TTL
    /// non lus leur ligne fixe (sans cause du moteur) ; le clonage et la création la ligne `[runbooks] WARN …` de
    /// `refus_d_ecriture_de_runbook` avec la phrase et la cause. Les absences et le nominal n'écrivent rien.
    /// MUTATIONS : DASH_SANS_JOURNAL, DASH_JOURNAL_SUFFIXE, PANEL_DATA_SANS_JOURNAL, PANEL_DATA_JOURNAL_SUFFIXE,
    /// COUT_SANS_JOURNAL, COUT_JOURNAL_SUFFIXE, TTL_SANS_JOURNAL, TTL_JOURNAL_SUFFIXE (et les variantes de runbook, dont la
    /// phrase change la ligne).
    #[tokio::test]
    async fn aj4_lignes_de_journal_des_lectures_ratees() {
        const ENFANT: &str = "AJ4_ENFANT_JOURNAL";
        const PHASE: &str = "AJ4-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
            let (st, _p) = sp_state("aj4-journal");
            let adm = sp_au("adm", "admin");
            eprintln!("{PHASE}dash");
            let did = aj4_tableau(&st, "d-aj4-journal", "shared");
            aj4_sql(&st, &format!("UPDATE dashboard SET name=X'00' WHERE id={did};"));
            let r = aj4_fiche(&st, &adm, did).await;
            let moteur = st
                .db
                .lock()
                .query_row("SELECT name,COALESCE(owner,''),COALESCE(visibility,'shared'),view_id FROM dashboard WHERE id=?1", params![did], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<i64>>(3)?))
                })
                .expect_err("rejouée")
                .to_string();
            println!("AJ4-STATUT-DASH\t{}\t{did}\t{}\t{moteur}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}panel");
            let pdid = aj4_tableau(&st, "d-aj4-journal-panel", "shared");
            let pid = aj4_panneau(&st, pdid);
            aj4_sql(&st, &format!("UPDATE panel SET window_s=X'00' WHERE id={pid};"));
            let r = aj4_donnees(&st, &adm, pid).await;
            let moteur = st
                .db
                .lock()
                .query_row("SELECT dashboard_id,window_s,COALESCE(visibility,'shared') FROM panel WHERE id=?1", params![pid], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?))
                })
                .expect_err("rejouée")
                .to_string();
            println!("AJ4-STATUT-PANEL\t{}\t{pid}\t{}\t{moteur}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}cout");
            let cdid = aj4_tableau(&st, "d-aj4-journal-cout", "shared");
            let cpid = aj4_panneau(&st, cdid);
            aj4_sql(&st, &format!("INSERT INTO panel_cost(panel_id,query_fp,cost_ms,measured_at) VALUES({cpid},'{}',X'00',1);", query_fingerprint("SELECT 1 AS un", false)));
            let r = aj4_donnees(&st, &adm, cpid).await;
            for _ in 0..20_000 {
                if st.panel_refresh_inflight.lock().is_empty() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            println!("AJ4-STATUT-COUT\t{}\t{cpid}", r.0);
            eprintln!("{PHASE}ttl");
            let tpid = aj4_panneau(&st, cdid);
            aj4_sql(&st, &format!("UPDATE panel SET panel_cache_ttl_s=X'00' WHERE id={tpid};"));
            let ttl = panel_cache_ttl(&st.db.lock(), tpid, AJ4_TTL_GLOBAL);
            println!("AJ4-STATUT-TTL\t{ttl}\t{tpid}");
            eprintln!("{PHASE}clone");
            let (_, _, v) = aj4_creer(&st, "aj4 journal").await;
            let src = v["id"].as_i64().unwrap_or(0);
            aj4_sql(&st, &format!("UPDATE runbook SET description=X'00' WHERE id={src};"));
            let r = aj4_cloner(&st, src, "copie").await;
            let moteur = st
                .db
                .lock()
                .query_row("SELECT name,match_kind,match_key,description FROM runbook WHERE id=?1", params![src], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?))
                })
                .expect_err("rejouée")
                .to_string();
            println!("AJ4-STATUT-CLONE\t{}\t{src}\t{}\t{moteur}", r.0, r.2["id"].as_str().unwrap_or(""));
            aj4_sql(&st, &format!("UPDATE runbook SET description='' WHERE id={src};"));
            eprintln!("{PHASE}cle");
            aj4_sql(&st, "ALTER TABLE runbook RENAME COLUMN key TO cle_renommee_aj4;");
            let r = aj4_creer(&st, "aj4 autre").await;
            let moteur = st.db.lock().query_row("SELECT 1 FROM runbook WHERE key=?1", params!["custom-aj4-autre"], |_| Ok(())).expect_err("rejouée").to_string();
            println!("AJ4-STATUT-CLE\t{}\t0\t{}\t{moteur}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}calme");
            let (st, _p) = sp_state("aj4-journal-calme");
            let a = aj4_fiche(&st, &adm, AJ4_ABSENT).await.0;
            let b = aj4_donnees(&st, &adm, AJ4_ABSENT).await.0;
            let c = aj4_cloner(&st, AJ4_ABSENT, "copie").await.0;
            let cdid = aj4_tableau(&st, "d-aj4-calme", "shared");
            let cpid = aj4_panneau(&st, cdid);
            let d = panel_cache_ttl(&st.db.lock(), AJ4_ABSENT, AJ4_TTL_GLOBAL);
            let e = aj4_fiche(&st, &adm, cdid).await.0;
            let f = aj4_creer(&st, "aj4 calme").await.0;
            let g = aj4_donnees(&st, &adm, cpid).await.0;
            for _ in 0..20_000 {
                if st.panel_refresh_inflight.lock().is_empty() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            println!("AJ4-STATUT-CALME\t{a}\t{b}\t{c}\t{d}\t{e}\t{f}\t{g}");
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::lectures_des_panneaux_et_cles_de_runbook_en_trois_issues::aj4_lignes_de_journal_des_lectures_ratees",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> Vec<String> {
            let reste = stdout.split_once(&format!("{m}\t")).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").split('\t').map(str::to_string).collect()
        };
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[dashboards] ") || l.starts_with("[runbooks] ")).map(str::to_string).collect()
        };
        let inc_clone = crate::handlers::incidents::CAUSE_RUNBOOK_NON_CLONE_SOURCE_NON_LUE;
        let inc_cle = crate::handlers::incidents::CAUSE_CLE_DE_RUNBOOK_NON_LUE;
        // (phase, marque, ligne attendue en fonction de [statut, id, corrélation, cause du moteur])
        type Attendue = fn(&[String], &str, &str) -> String;
        let nommees: [(&str, &str, Attendue); 4] = [
            ("dash", "AJ4-STATUT-DASH", |m, _, _| format!("[dashboards] WARN tableau de bord #{} NON lu pour la lecture, rien n'est servi ({}) : {}", m[1], m[2], m[3])),
            ("panel", "AJ4-STATUT-PANEL", |m, _, _| format!("[dashboards] WARN panneau #{} NON lu pour l'exécution, rien n'est servi ({}) : {}", m[1], m[2], m[3])),
            ("clone", "AJ4-STATUT-CLONE", |m, c, _| format!("[runbooks] WARN clonage d'un runbook refusée, rien n'est écrit ({}) : {c} ({})", m[2], m[3])),
            ("cle", "AJ4-STATUT-CLE", |m, _, k| format!("[runbooks] WARN création d'un runbook refusée, rien n'est écrit ({}) : {k} ({})", m[2], m[3])),
        ];
        assert!(nommees.len() >= 4, "plancher : quatre lectures ratées à 503 nommé");
        for (nom, m, attendue) in &nommees {
            let st = marque(m);
            assert_eq!(st[0], "503", "contrôle : phase {nom}, 503 : {st:?}");
            assert!(st[2].starts_with("plume-e"), "contrôle : phase {nom}, identifiant servi : {st:?}");
            assert!(!st[3].is_empty(), "contrôle : phase {nom}, cause du moteur rejouée : {st:?}");
            assert_eq!(phase(nom), [attendue(&st, inc_clone, inc_cle)], "phase {nom} : une ligne et une seule, en entier");
        }
        let cout = marque("AJ4-STATUT-COUT");
        assert_eq!(cout[0], "200", "contrôle : coût non lu, panneau servi : {cout:?}");
        assert_eq!(phase("cout"), [format!("[dashboards] WARN panneau #{} : coût non lu, le panneau est servi comme jamais mesuré", cout[1])], "coût non lu : la ligne fixe, en entier");
        let ttl = marque("AJ4-STATUT-TTL");
        assert_eq!(ttl[0], "0", "contrôle : TTL non lu = cache coupé : {ttl:?}");
        assert_eq!(phase("ttl"), [format!("[dashboards] WARN panneau #{} : TTL du cache non lu, cache coupé pour ce panneau", ttl[1])], "TTL non lu : la ligne fixe, en entier");
        assert_eq!(
            marque("AJ4-STATUT-CALME"),
            ["404", "403", "400", AJ4_TTL_GLOBAL.to_string().as_str(), "200", "200", "200"],
            "contrôle : trois absences, un TTL absent, trois nominaux"
        );
        assert!(phase("calme").is_empty(), "les absences et le nominal n'écrivent aucune ligne : {:?}", phase("calme"));
    }
}
