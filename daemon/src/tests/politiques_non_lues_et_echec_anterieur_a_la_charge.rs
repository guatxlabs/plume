// =====================================================================================================
// `P10.5-p`, `P10.32-o` — UNE POLITIQUE PAR INDEX NON LUE NE FABRIQUE PAS UN HORIZON MESURÉ ; UN ÉCHEC PLUS ANCIEN
// QUE LA CHARGE UTILE EN CACHE N'Y EST PAS JOINT.
//
// LES DÉFAUTS (lus sur les branches reprises des vagues AV) :
//  * l'horizon des panneaux (`handlers/panneau_avoue.rs`) lisait les politiques par le lecteur de la PURGE
//    (`rollups::load_index_policies`), qui rend une liste vide sur un énoncé refusé et écarte une ligne illisible : une
//    lecture ratée publiait la rétention globale comme horizon MESURÉ ;
//  * plusieurs branches de l'horizon n'avaient pas de témoin capable de rougir : `/api/query` en SQL brut par un admin
//    borné à un environnement, la borne de la plus courte fenêtre par la globale et la famille hors politique dans la
//    voie froide ;
//  * `dashboards::joindre_l_echec_a_la_charge_valide` joignait l'aveu à toute charge valide, y compris une charge
//    CALCULÉE APRÈS la tentative (succès concurrent : `now_s` est pris avant l'exécution) ; les bras « aucune charge » et
//    « non jointe » du journal du pré-chauffage n'étaient jugés que sur une classe dont la nature égale le texte.
//
// DÉSORMAIS : `rollups::lire_les_politiques_d_index` rend `Err` sur un énoncé refusé (table présente) ou une ligne
// illisible, une liste vide sur une table absente RELEVÉE ; l'horizon (chemin chaud, voie froide, cache re-servi) dit
// alors « non mesuré » (`NOTICE_POLITIQUE_PAR_INDEX_NON_LUE`) ; la purge garde son repli (lignes lisibles gardées). Une
// charge calculée après la tentative n'est pas touchée (`PlusRecenteQueLaTentative`), à la demande comme au
// pré-chauffage, et le journal le dit.
//
// MUTANTS (variable de mutation sous `cfg!(test)`, retirés du source avant le commit), chacun vu ROUGE :
//  AW1_LIGNE_ECARTEE, AW1_NON_LUE_GLOBALE : (1) ; AW1_ABSENCE_NON_RELEVEE : (2) ; AW1_ABSENTE_REFUSEE : (3) ;
//  AW1_PURGE_STRICTE : (4) ; AW1_RESTAMP_NON_LUE : (5) ; AW1_QUERY_ENV_SQL_BRUT : (6) ; AW1_PLUS_RECENTE_JOINTE : (7),
//  (8) ; AW1_PLUS_RECENTE_ECRASE : (7), (10) ; AW1_PLUS_RECENTE_LARGE : (9) ; AW1_AUCUNE_TEXTE_BRUT,
//  AW1_NON_JOINTE_TEXTE_BRUT, AW1_PLUS_RECENTE_TEXTE_BRUT : (10) ; sous `cold_tier` : AW1_FROID_NON_LUE_IGNOREE : (11) ;
//  AW1_FROID_MIN_GLOBALE : (12) ; AW1_FROID_TOUTES_FAMILLES : (13).
// =====================================================================================================

mod aw1_politiques_non_lues_et_echec_anterieur {
    use super::*;
    use crate::query_exec::panne_de_test_au_coeur::{demander, encore_demandee, retirer, PanneAuCoeur};

    const AW1_JOUR: i64 = 86_400;
    const AW1_GXQL: &str = "search source=web | table message";
    const AW1_RAISON_RETENTION: &str = "retention_floor";
    const AW1_RAISON_NON_MESURE: &str = "horizon_non_mesure";
    const AW1_NOTICE_DEHORS: &str = "PORTÉE INCOMPLÈTE : la fenêtre demandée descend SOUS l'horizon de conservation : sous lui, la rétention peut avoir supprimé les lignes, et ce panneau n'est assuré d'en voir aucune. La part antérieure à cet horizon est hors de portée — un creux ou une courbe qui s'y arrête n'établit donc PAS une absence. Ce n'est pas non plus l'affirmation qu'il manque quelque chose : sur une base plus jeune que cet horizon, il se peut que rien n'ait jamais été supprimé.";
    const AW1_NOTICE_DEDANS: &str = "la fenêtre demandée tient AU-DESSUS de l'horizon de conservation : sous lui, la rétention peut avoir supprimé les lignes, et ce panneau n'est assuré d'en voir aucune : rien n'est resté dehors de ce fait.";
    /// L'aveu neuf, recopié (jamais lu depuis la production).
    const AW1_NOTICE_NON_LUE: &str = "l'horizon de conservation de ce panneau n'est PAS établi : les politiques de rétention par environnement n'ont pas pu être lues, et aucune fenêtre n'est calculée sur la seule rétention globale. Cette réponse ne dit RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";
    /// La phrase servie d'une erreur du support (`CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE`), lue par son nom : le témoin
    /// juge que l'aveu n'est PAS joint, pas sa phrase.
    const AW1_NATURE_DU_SUPPORT: &str = "aw1 nature du support";
    const AW1_TEXTE_DU_SUPPORT: &str = "aw1 texte du moteur, chemin de la base";
    const AW1_SQL_REGEXP: &str = "SELECT message FROM event WHERE message REGEXP 'aw1'";
    const AW1_REFUS_DU_CACHE: &str = "aw1 refus du cache";

    fn aw1_mesure(depuis: i64, calcule_a: i64, horizon_ts: i64, dehors: bool) -> Value {
        json!({
            "searched_from": depuis,
            "calcule_a": calcule_a,
            "horizon_ts": horizon_ts,
            "older_outside_window": dehors,
            "reason": AW1_RAISON_RETENTION,
            "notice": if dehors { AW1_NOTICE_DEHORS } else { AW1_NOTICE_DEDANS },
        })
    }

    fn aw1_non_lue(depuis: i64, calcule_a: i64) -> Value {
        json!({ "searched_from": depuis, "calcule_a": calcule_a, "reason": AW1_RAISON_NON_MESURE, "notice": AW1_NOTICE_NON_LUE })
    }

    fn aw1_calcule_a(cov: &Value) -> i64 {
        cov["calcule_a"].as_i64().unwrap_or_else(|| panic!("instant du calcul non publié : {cov}"))
    }

    /// Base migrée, un admin, un panneau GXQL au coût mesuré bas (chemin LIVE de `panel_data`), globale à trente jours.
    fn aw1_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, i64) {
        aw1_etat_avec(tag, |_| {})
    }

    /// `aw1_etat`, la table des politiques ajustée AVANT que l'état (et son pool de lecture) n'existe : aucune connexion
    /// ne garde un schéma d'avant l'ajustement.
    fn aw1_etat_avec(tag: &str, ajuster: impl FnOnce(&Connection)) -> (AppState, crate::tmp_possede::TmpDb, i64) {
        let path = ff_tmp_path(tag);
        let id = {
            let conn = open_db(&path).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : migrations complètes");
            conn.execute("INSERT INTO user(name,hash,role) VALUES('adm',?1,'admin')", params![hash_pw("adminpw12345").unwrap()]).unwrap();
            conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('d-aw1','adm','private')", []).unwrap();
            let did = conn.last_insert_rowid();
            conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'p',?2,1,'table')", params![did, AW1_GXQL]).unwrap();
            let id = conn.last_insert_rowid();
            conn.execute(
                "INSERT OR REPLACE INTO panel_cost(panel_id,query_fp,cost_ms,measured_at) VALUES(?1,?2,1.0,?3)",
                params![id, query_fingerprint(AW1_GXQL, true), now()],
            )
            .unwrap();
            aw1_reglage(&conn, "retention_days", "30");
            ajuster(&conn);
            id
        };
        (ds_file_state(&path), path, id)
    }

    fn aw1_reglage(conn: &Connection, cle: &str, valeur: &str) {
        conn.execute("INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global',?1,?2)", params![cle, valeur]).expect("fixture : réglage posé");
    }

    /// Une ligne de politique, chaque colonne passée telle quelle (une valeur illisible reste illisible : TEXT non
    /// numérique dans une colonne INTEGER, BLOB).
    fn aw1_ligne(conn: &Connection, nom: rusqlite::types::Value, jours: rusqlite::types::Value, lignes: rusqlite::types::Value, octets: rusqlite::types::Value) {
        conn.execute("INSERT INTO index_policy(name,retention_days,max_rows,max_bytes,enabled) VALUES(?1,?2,?3,?4,1)", params![nom, jours, lignes, octets])
            .expect("fixture : ligne de politique");
    }

    fn aw1_lisible(conn: &Connection, nom: &str, jours: i64) {
        use rusqlite::types::Value as V;
        aw1_ligne(conn, V::Text(nom.into()), V::Integer(jours), V::Integer(0), V::Integer(0));
    }

    /// Les quatre façons de rendre UNE ligne illisible, une colonne à la fois (chaque lecture de colonne seule).
    fn aw1_illisibles(nom: &str) -> Vec<(&'static str, [rusqlite::types::Value; 4])> {
        use rusqlite::types::Value as V;
        vec![
            ("nom en BLOB", [V::Blob(nom.as_bytes().to_vec()), V::Integer(10), V::Integer(0), V::Integer(0)]),
            ("durée non entière", [V::Text(nom.into()), V::Text("dix".into()), V::Integer(0), V::Integer(0)]),
            ("plafond de lignes en BLOB", [V::Text(nom.into()), V::Integer(10), V::Blob(vec![0]), V::Integer(0)]),
            ("plafond d'octets non entier", [V::Text(nom.into()), V::Integer(10), V::Integer(0), V::Text("beaucoup".into())]),
        ]
    }

    /// Une ligne illisible EN TÊTE et une AU MILIEU (colonne `rang` d'`aw1_illisibles`), des lignes lisibles derrière
    /// chacune : `stage` à dix jours, `prod` à vingt.
    fn aw1_politiques_avec_illisibles(conn: &Connection, rang: usize) {
        let [a, b, c, d] = aw1_illisibles("tete").swap_remove(rang).1;
        aw1_ligne(conn, a, b, c, d);
        aw1_lisible(conn, "stage", 10);
        let [a, b, c, d] = aw1_illisibles("milieu").swap_remove(rang).1;
        aw1_ligne(conn, a, b, c, d);
        aw1_lisible(conn, "prod", 20);
    }

    fn aw1_admin(env: Option<&str>) -> AuthUser {
        AuthUser {
            name: "adm".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: env.map(str::to_string),
        }
    }

    async fn aw1_par_la_route(st: &AppState, id: i64, env: Option<&str>, depuis: i64) -> Value {
        let q = Query(HashMap::from([("from".to_string(), depuis.to_string()), ("to".to_string(), "0".to_string())]));
        let r = panel_data(State(st.clone()), Extension(aw1_admin(env)), Path(id), q).await;
        let code = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        let v: Value = serde_json::from_slice(&b).expect("réponse JSON");
        assert_eq!(code, 200, "contrôle : panneau servi : {v}");
        assert!(v.get("warming").is_none(), "contrôle : chemin LIVE, pas une chauffe : {v}");
        v["stats"]["coverage"].clone()
    }

    /// (1) PAR LA ROUTE : une ligne de politique illisible (chaque colonne, une à la fois ; en tête et au milieu, des
    /// lignes lisibles derrière) rend l'horizon NON MESURÉ, environnement déterminé ou non — jamais la globale ni la
    /// politique lisible de `stage` publiées comme mesurées. Contrôle : sans les lignes illisibles, `stage` à dix jours.
    /// MUTANTS : AW1_LIGNE_ECARTEE (lignes illisibles sautées : `stage` mesuré à dix jours), AW1_NON_LUE_GLOBALE (lecture
    /// ratée prise pour la globale).
    #[tokio::test]
    async fn aw1_politique_illisible_par_la_route_horizon_non_mesure() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let depuis = now() - 25 * AW1_JOUR;
        let (st, _p, id) = aw1_etat("aw1-illisible-controle");
        {
            let c = st.db.lock();
            aw1_lisible(&c, "stage", 10);
            aw1_lisible(&c, "prod", 20);
        }
        let cov = aw1_par_la_route(&st, id, Some("stage"), depuis).await;
        let a = aw1_calcule_a(&cov);
        assert_eq!(cov, aw1_mesure(depuis, a, a - 10 * AW1_JOUR, true), "contrôle : politique lisible de stage");
        let cas = aw1_illisibles("x");
        assert!(cas.len() >= 4, "plancher : quatre colonnes rendues illisibles");
        let mut joues = 0;
        for (rang, (colonne, _)) in cas.iter().enumerate() {
            let (st, _p, id) = aw1_etat(&format!("aw1-illisible-{rang}"));
            aw1_politiques_avec_illisibles(&st.db.lock(), rang);
            for env in [Some("stage"), None] {
                let cov = aw1_par_la_route(&st, id, env, depuis).await;
                let a = aw1_calcule_a(&cov);
                assert_eq!(cov, aw1_non_lue(depuis, a), "{colonne}, {env:?} : politiques non lues, horizon non mesuré");
                joues += 1;
            }
        }
        assert_eq!(joues, 2 * cas.len(), "contrôle : chaque colonne, deux environnements");
    }

    /// (2) ÉNONCÉ REFUSÉ SUR UNE TABLE PRÉSENTE (colonne de durée absente) : horizon non mesuré. MUTANT :
    /// AW1_ABSENCE_NON_RELEVEE (tout refus d'énoncé pris pour une table absente : la globale publiée comme mesurée).
    #[tokio::test]
    async fn aw1_table_des_politiques_illisible_horizon_non_mesure() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, id) = aw1_etat_avec("aw1-schema", |c| {
            c.execute_batch("DROP TABLE index_policy; CREATE TABLE index_policy(id INTEGER PRIMARY KEY, name TEXT, enabled INTEGER); INSERT INTO index_policy(name,enabled) VALUES('stage',1);")
                .expect("fixture : table au schéma amputé");
        });
        let depuis = now() - 25 * AW1_JOUR;
        let cov = aw1_par_la_route(&st, id, Some("stage"), depuis).await;
        let a = aw1_calcule_a(&cov);
        assert_eq!(cov, aw1_non_lue(depuis, a), "énoncé refusé : horizon non mesuré");
    }

    /// (3) TABLE ABSENTE (base d'avant les politiques) : aucune politique, comme la purge la voit — la globale, MESURÉE.
    /// MUTANT : AW1_ABSENTE_REFUSEE (absence prise pour une lecture ratée).
    #[tokio::test]
    async fn aw1_table_des_politiques_absente_horizon_a_la_globale() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, id) = aw1_etat_avec("aw1-absente", |c| c.execute_batch("DROP TABLE index_policy;").expect("fixture : table retirée"));
        let depuis = now() - 25 * AW1_JOUR;
        let cov = aw1_par_la_route(&st, id, Some("stage"), depuis).await;
        let a = aw1_calcule_a(&cov);
        assert_eq!(cov, aw1_mesure(depuis, a, a - 30 * AW1_JOUR, false), "table absente : la globale, mesurée");
        assert!(crate::rollups::lire_les_politiques_d_index(&st.db.lock()).expect("table absente : lue").is_empty(), "aucune politique");
    }

    /// (4) LA PURGE GARDE SON REPLI : le lecteur de `retention_run` (`load_index_policies`) écarte les lignes illisibles
    /// (en tête, au milieu) et garde les lisibles derrière elles ; le lecteur de l'horizon, sur la même table, rend `Err`.
    /// MUTANT : AW1_PURGE_STRICTE (la purge prend le lecteur strict : plus aucune politique, `stage` et `prod` purgés à
    /// la globale).
    #[test]
    fn aw1_la_purge_garde_les_politiques_lisibles() {
        let cas = aw1_illisibles("x");
        assert!(cas.len() >= 4, "plancher : quatre colonnes rendues illisibles");
        let mut joues = 0;
        for (rang, (colonne, _)) in cas.iter().enumerate() {
            let (st, _p, _) = aw1_etat(&format!("aw1-purge-{rang}"));
            let c = st.db.lock();
            aw1_politiques_avec_illisibles(&c, rang);
            let lues: Vec<(String, i64)> = load_index_policies(&c).into_iter().map(|p| (p.name, p.retention_days)).collect();
            assert_eq!(lues, vec![("stage".to_string(), 10), ("prod".to_string(), 20)], "{colonne} : la purge garde les lignes lisibles");
            assert!(crate::rollups::lire_les_politiques_d_index(&c).is_err(), "{colonne} : le lecteur de l'horizon rend la lecture non faite");
            joues += 1;
        }
        assert_eq!(joues, cas.len(), "contrôle : chaque colonne");
    }

    /// (5) CACHE RE-SERVI : un horizon écrit politiques lisibles n'est plus re-servi quand elles ne le sont plus ; la
    /// couverture servie est non mesurée sur la fenêtre et l'instant STOCKÉS. MUTANT : AW1_RESTAMP_NON_LUE.
    #[test]
    fn aw1_cache_re_servi_politiques_non_lues() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, p, _) = aw1_etat("aw1-cache");
        aw1_lisible(&st.db.lock(), "stage", 10);
        let depuis = now() - 25 * AW1_JOUR;
        let pc = panneau_avoue::compile_panneau_avoue(AW1_GXQL, true, depuis, 0, Some("stage")).expect("compilé");
        let stocke = panneau_avoue::horizon(p.as_str(), &HashMap::new(), &pc, depuis);
        let a = aw1_calcule_a(&stocke);
        assert_eq!(stocke, aw1_mesure(depuis, a, a - 10 * AW1_JOUR, true), "contrôle : écrit politiques lisibles");
        aw1_lisible(&st.db.lock(), "prod", 20);
        {
            use rusqlite::types::Value as V;
            aw1_ligne(&st.db.lock(), V::Text("milieu".into()), V::Text("dix".into()), V::Integer(0), V::Integer(0));
        }
        let mut v = json!({ "columns": [], "rows": [], "stats": { "coverage": stocke } });
        panneau_avoue::cache_reestamper(&mut v, p.as_str(), &HashMap::new(), Some(&pc), a, a + 5);
        assert_eq!(v["stats"]["coverage"], aw1_non_lue(depuis, a), "re-servi : non mesuré, fenêtre et instant stockés");
    }

    /// (6) `/api/query` EN SQL BRUT PAR UN ADMIN BORNÉ À `stage` (politique de soixante jours, globale à trente) : le SQL
    /// brut ne filtre aucun environnement, l'horizon est la plus courte (trente), jamais les soixante de `stage` — un
    /// aveu optimiste de trente jours. Contrôle : le même admin en GXQL lit `stage`, soixante. MUTANT :
    /// AW1_QUERY_ENV_SQL_BRUT (`environnement_lu` tenu pour GXQL).
    #[tokio::test]
    async fn aw1_api_query_sql_brut_d_un_admin_borne_prend_la_plus_courte() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, _) = aw1_etat("aw1-api-query-brut");
        aw1_lisible(&st.db.lock(), "stage", 60);
        let depuis = now() - 45 * AW1_JOUR;
        let cas = [
            ("sql", json!({ "sql": "SELECT ts FROM event WHERE ts >= __FROM__", "from": depuis }), 30, true),
            ("soql", json!({ "soql": AW1_GXQL, "from": depuis }), 60, false),
        ];
        let mut joues = 0;
        for (nom, corps, jours, dehors) in cas {
            let r = crate::handlers::query::query(State(st.clone()), Extension(aw1_admin(Some("stage"))), Json(corps)).await;
            let code = r.status().as_u16();
            let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
            let v: Value = serde_json::from_slice(&b).expect("réponse JSON");
            assert_eq!(code, 200, "contrôle ({nom}) : requête servie : {v}");
            let cov = v["stats"]["coverage"].clone();
            let a = aw1_calcule_a(&cov);
            assert_eq!(cov, aw1_mesure(depuis, a, a - jours * AW1_JOUR, dehors), "{nom} : {jours} jours");
            joues += 1;
        }
        assert_eq!(joues, 2, "contrôle : SQL brut et GXQL");
    }

    // ---------------------------------------------------------------------------------
    // Une charge utile calculée APRÈS la tentative en échec.
    // ---------------------------------------------------------------------------------

    fn aw1_support() -> crate::query_exec::EchecDeRequete {
        crate::query_exec::EchecDeRequete::Support { nature: AW1_NATURE_DU_SUPPORT.into(), texte: AW1_TEXTE_DU_SUPPORT.into() }
    }

    fn aw1_charge() -> String {
        json!({ "columns": ["a"], "rows": [[42]] }).to_string()
    }

    /// (7) À LA DEMANDE, PAR LE POINT D'ENTRÉE DE LA TÂCHE (`consigner_l_issue_du_rafraichissement`) : une charge valide
    /// calculée APRÈS l'instant de la tentative reste à l'octet et à son instant (ni aveu joint, ni corps d'échec écrit
    /// par-dessus). Contrôle : la même charge calculée AVANT reçoit l'aveu. MUTANTS : AW1_PLUS_RECENTE_JOINTE (aveu
    /// joint à la charge plus récente), AW1_PLUS_RECENTE_ECRASE (corps d'échec écrit par-dessus).
    #[test]
    fn aw1_a_la_demande_une_charge_plus_recente_que_la_tentative_reste_a_l_octet() {
        let _env = VERROU_ENV_PROCESSUS.read(); // panel_serve_cfg_de lit load_config()
        let mut joues = 0;
        for (nom, decalage, jointe) in [("plus-recente", 3_600, false), ("anterieure", -5, true)] {
            let (st, dbp, _g, panne, _s) = t3c_state(&format!("aw1-demande-{nom}"));
            let from = t3c_from();
            let (rk, fp, _) = t3c_cle(&st, panne, from);
            let (ttl_global, _) = panel_serve_cfg_de(&load_config());
            let tentative = now();
            panneau_avoue::cache_ecrire(&st.db.lock(), panne, &rk, &fp, tentative + decalage, &aw1_charge());
            consigner_l_issue_du_rafraichissement(&st.db, "default", panne, &rk, &fp, tentative, from, ttl_global, Ok(Err(aw1_support())));
            let (payload, calcule_a) = panneau_avoue::cache_lire(&st.db.lock(), panne, &rk, &fp).expect("ligne de cache");
            assert_eq!(calcule_a, tentative + decalage, "({nom}) instant de calcul inchangé : {payload}");
            if jointe {
                let v: Value = serde_json::from_str(&payload).unwrap();
                assert_eq!(v["stats"]["rafraichissement_en_echec"]["echoue_a"], json!(tentative), "contrôle ({nom}) : l'aveu est joint : {payload}");
            } else {
                assert_eq!(payload, aw1_charge(), "({nom}) charge calculée après la tentative : à l'octet");
            }
            ff_rm(&dbp);
            joues += 1;
        }
        assert_eq!(joues, 2, "contrôle : plus récente et antérieure");
    }

    /// Une base de panneaux de la vague T avec un event et un panneau dont l'énoncé appelle `regexp` (les pannes du
    /// support passent par cette UDF) ; le cache des autres panneaux est coupé : le pré-chauffage n'exécute que celui-ci.
    fn aw1_seul_panneau_regexp(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, i64) {
        let (st, dbp, _g, _panne, _s) = t3c_state(tag);
        let id = {
            let conn = st.db.lock();
            conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'aw1','sshd',1,'m')", params![now()]).unwrap();
            let did: i64 = conn.query_row("SELECT MIN(id) FROM dashboard", [], |r| r.get(0)).unwrap();
            conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'aw1',?2,0,'table')", params![did, AW1_SQL_REGEXP]).unwrap();
            let id = conn.last_insert_rowid();
            conn.execute("UPDATE panel SET panel_cache_ttl_s=0 WHERE id<>?1", params![id]).unwrap();
            id
        };
        (st, dbp, id)
    }

    /// (8) AU PRÉ-CHAUFFAGE (`cache_refresh_all_panels`, panne du support armée au cœur) : une charge valide calculée
    /// APRÈS l'instant du tick reste à l'octet et à son instant. Contrôle : calculée avant, elle reçoit l'aveu. MUTANT :
    /// AW1_PLUS_RECENTE_JOINTE.
    #[test]
    fn aw1_au_pre_chauffage_une_charge_plus_recente_que_la_tentative_reste_a_l_octet() {
        let _env = VERROU_ENV_PROCESSUS.read(); // cache_refresh_all_panels lit load_config()
        let mut joues = 0;
        for (nom, decalage, jointe) in [("plus-recente", 3_600, false), ("anterieure", -3_600, true)] {
            let (st, dbp, id) = aw1_seul_panneau_regexp(&format!("aw1-prechauffe-{nom}"));
            let from = t3c_from();
            let (rk, fp, _) = t3c_cle(&st, id, from);
            let calcule = now() + decalage;
            panneau_avoue::cache_ecrire(&st.db.lock(), id, &rk, &fp, calcule, &aw1_charge());
            demander(dbp.as_str(), PanneAuCoeur::ErreurDuSupport);
            crate::rollups::cache_refresh_all_panels(&st.db, dbp.as_str(), &st.refresh_sem);
            let servie = !encore_demandee(dbp.as_str());
            retirer(dbp.as_str());
            assert!(servie, "prémisse ({nom}) : la panne a servi au pré-chauffage");
            let (payload, calcule_a) = panneau_avoue::cache_lire(&st.db.lock(), id, &rk, &fp).expect("ligne de cache");
            assert_eq!(calcule_a, calcule, "({nom}) instant de calcul inchangé : {payload}");
            if jointe {
                let v: Value = serde_json::from_str(&payload).unwrap();
                assert!(v["stats"]["rafraichissement_en_echec"].is_object(), "contrôle ({nom}) : l'aveu est joint : {payload}");
            } else {
                assert_eq!(payload, aw1_charge(), "({nom}) charge calculée après le tick : à l'octet");
            }
            ff_rm(&dbp);
            joues += 1;
        }
        assert_eq!(joues, 2, "contrôle : plus récente et antérieure");
    }

    /// (9) LE BORD : une charge calculée À L'INSTANT de la tentative (`echoue_a == calcule_a`) reçoit l'aveu ; une seconde
    /// plus tard, non. MUTANT : AW1_PLUS_RECENTE_LARGE (égalité tenue pour plus récente).
    #[test]
    fn aw1_une_charge_calculee_a_l_instant_de_la_tentative_recoit_l_aveu() {
        let (st, dbp, _g, panne, _s) = t3c_state("aw1-bord");
        let from = t3c_from();
        let (rk, fp, _) = t3c_cle(&st, panne, from);
        let t: i64 = now();
        let echec = crate::handlers::dashboards::EchecMisEnCache::de_la_requete(aw1_support());
        let mut joues = 0;
        for (calcule, jointe) in [(t, true), (t + 1, false)] {
            let conn = st.db.lock();
            panneau_avoue::cache_ecrire(&conn, panne, &rk, &fp, calcule, &aw1_charge());
            let issue = crate::handlers::dashboards::joindre_l_echec_a_la_charge_valide(&conn, panne, &rk, &fp, t, &echec);
            let (payload, _) = panneau_avoue::cache_lire(&conn, panne, &rk, &fp).expect("ligne de cache");
            if jointe {
                assert!(matches!(issue, crate::handlers::dashboards::IssueDeLaChargeValide::Jointe), "calculée à l'instant de la tentative : jointe");
                let v: Value = serde_json::from_str(&payload).unwrap();
                assert_eq!(v["stats"]["rafraichissement_en_echec"]["echoue_a"], json!(t), "aveu à l'instant de la tentative : {payload}");
            } else {
                assert!(
                    matches!(issue, crate::handlers::dashboards::IssueDeLaChargeValide::PlusRecenteQueLaTentative),
                    "calculée une seconde après : plus récente"
                );
                assert_eq!(payload, aw1_charge(), "plus récente : à l'octet");
            }
            joues += 1;
        }
        assert_eq!(joues, 2, "contrôle : le bord et la seconde suivante");
        ff_rm(&dbp);
    }

    /// (10) LES LIGNES DE JOURNAL, ENTIÈRES, sur la classe du SUPPORT (sa nature n'est pas le texte du moteur, qui peut
    /// citer le chemin de la base) : pré-chauffage sans charge valide (« aucune »), écriture de l'aveu refusée (« non
    /// jointe »), charge calculée après le tick (« plus récente ») ; à la demande, charge calculée après la tentative.
    /// MUTANTS : AW1_AUCUNE_TEXTE_BRUT, AW1_NON_JOINTE_TEXTE_BRUT, AW1_PLUS_RECENTE_TEXTE_BRUT (texte du moteur au
    /// journal du bras), AW1_PLUS_RECENTE_ECRASE (à la demande : corps d'échec écrit, autre ligne).
    #[test]
    fn aw1_lignes_de_journal_des_bras_du_pre_chauffage_et_de_la_charge_plus_recente() {
        let _env = VERROU_ENV_PROCESSUS.read(); // cache_refresh_all_panels et panel_serve_cfg_de lisent load_config()
        const ENFANT: &str = "AW1_ENFANT_JOURNAL_DES_BRAS";
        const PHASE: &str = "AW1-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let from = t3c_from();
            {
                let (_st, dbp, _id) = aw1_seul_panneau_regexp("aw1-j-sonde");
                let pc = panneau_avoue::compile_panneau_avoue(AW1_SQL_REGEXP, false, from, 0, None).unwrap();
                demander(dbp.as_str(), PanneAuCoeur::ErreurDuSupport);
                let e = crate::query_exec::en_classant(|| panneau_avoue::executer(dbp.as_str(), &HashMap::new(), pc, from)).unwrap_err();
                retirer(dbp.as_str());
                eprintln!("AW1-TEXTE:{}", e.texte());
                eprintln!("AW1-NATURE:{}", crate::handlers::dashboards::EchecMisEnCache::de_la_requete(e).au_journal());
                ff_rm(&dbp);
            }
            for nom in ["aucune", "refus", "plus-recente"] {
                let (st, dbp, id) = aw1_seul_panneau_regexp(&format!("aw1-j-{nom}"));
                let (rk, fp, _) = t3c_cle(&st, id, from);
                match nom {
                    "refus" => {
                        panneau_avoue::cache_ecrire(&st.db.lock(), id, &rk, &fp, now() - 3_600, &aw1_charge());
                        st.db
                            .lock()
                            .execute_batch(&format!("CREATE TRIGGER aw1_refus BEFORE INSERT ON panel_cache BEGIN SELECT RAISE(ABORT,'{AW1_REFUS_DU_CACHE}'); END;"))
                            .unwrap();
                    }
                    "plus-recente" => panneau_avoue::cache_ecrire(&st.db.lock(), id, &rk, &fp, now() + 3_600, &aw1_charge()),
                    _ => {}
                }
                eprintln!("AW1-ID-{nom}:{id}");
                eprintln!("{PHASE}{nom}");
                demander(dbp.as_str(), PanneAuCoeur::ErreurDuSupport);
                crate::rollups::cache_refresh_all_panels(&st.db, dbp.as_str(), &st.refresh_sem);
                println!("AW1-SERVIE-{nom}:{}", !encore_demandee(dbp.as_str()));
                retirer(dbp.as_str());
                ff_rm(&dbp);
            }
            {
                let nom = "demande-plus-recente";
                let (st, dbp, _g, panne, _s) = t3c_state(&format!("aw1-j-{nom}"));
                let (rk, fp, _) = t3c_cle(&st, panne, from);
                let (ttl_global, _) = panel_serve_cfg_de(&load_config());
                let tentative = now();
                panneau_avoue::cache_ecrire(&st.db.lock(), panne, &rk, &fp, tentative + 3_600, &aw1_charge());
                eprintln!("AW1-ID-{nom}:{panne}");
                eprintln!("{PHASE}{nom}");
                consigner_l_issue_du_rafraichissement(&st.db, "default", panne, &rk, &fp, tentative, from, ttl_global, Ok(Err(aw1_support())));
                ff_rm(&dbp);
            }
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::aw1_politiques_non_lues_et_echec_anterieur::aw1_lignes_de_journal_des_bras_du_pre_chauffage_et_de_la_charge_plus_recente",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let mut premisses = 0;
        for nom in ["aucune", "refus", "plus-recente"] {
            let m = format!("AW1-SERVIE-{nom}:true");
            assert!(stdout.lines().any(|l| l.ends_with(&m)), "prémisse : la panne a servi ({nom}) : {stdout}");
            premisses += 1;
        }
        assert_eq!(premisses, 3, "les trois prémisses jugées");
        let lire = |marque: &str| -> String {
            stderr.lines().find_map(|l| l.strip_prefix(marque)).unwrap_or_else(|| panic!("contrôle : {marque} : {stderr}")).to_string()
        };
        let nature = lire("AW1-NATURE:");
        let texte = lire("AW1-TEXTE:");
        assert_ne!(nature, texte, "prémisse : pour le support, la nature n'est pas le texte du moteur");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            let id = lire(&format!("AW1-ID-{nom}:"));
            corps
                .lines()
                .filter(|l| l.starts_with(&format!("[panel] WARN rafraîchissement du panneau {id} ")) || l.starts_with(&format!("[cache] WARN pré-chauffage du panneau {id} ")))
                .map(str::to_string)
                .collect()
        };
        let cache = |nom: &str, suite: &str| -> String {
            format!("[cache] WARN pré-chauffage du panneau {} en échec ({nature}) — {suite}", lire(&format!("AW1-ID-{nom}:")))
        };
        let attendus: [(&str, String); 4] = [
            ("aucune", cache("aucune", "rien d'écrit, le chemin à la demande retentera")),
            ("refus", cache("refus", &format!("charge utile précédente conservée, échec NON joint au corps servi ({AW1_REFUS_DU_CACHE})"))),
            ("plus-recente", cache("plus-recente", "charge utile calculée après cette tentative conservée, rien d'écrit")),
            (
                "demande-plus-recente",
                format!(
                    "[panel] WARN rafraîchissement du panneau {} en échec ({AW1_NATURE_DU_SUPPORT}) — /api/panels/{{id}}/data, tenant 'default' — charge utile calculée après cette tentative conservée, rien d'écrit",
                    lire("AW1-ID-demande-plus-recente:")
                ),
            ),
        ];
        let mut fautes = Vec::new();
        for (nom, ligne) in &attendus {
            let vu = phase(nom);
            if vu != vec![ligne.clone()] {
                fautes.push(format!("phase {nom} : attendu [{ligne}], vu {vu:?}"));
            }
        }
        assert_eq!(attendus.len(), 4, "plancher : quatre lignes attendues");
        assert!(fautes.is_empty(), "une ligne ENTIÈRE par bras :\n{}\n{stderr}", fautes.join("\n"));
    }

    /// LA VOIE FROIDE DE `/api/query` (`horizon_de_la_voie_froide_lue`), sous le tier froid actif.
    #[cfg(feature = "cold_tier")]
    mod froid {
        use super::*;

        fn aw1_froid(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, HashMap<String, String>) {
            let (st, base) = router_test_state(tag);
            let mut conf: HashMap<String, String> = HashMap::new();
            conf.insert("PLUME_COLD_HOT_WINDOW_DAYS".to_string(), "2".to_string());
            conf.insert("PLUME_COLD_TIER".to_string(), "1".to_string());
            aw1_reglage(&st.db.lock(), "retention_days", "30");
            (st, base, conf)
        }

        const AW1_MAINTENANT: i64 = 1_800_000_000;

        fn aw1_frontiere() -> i64 {
            (AW1_MAINTENANT.div_euclid(AW1_JOUR) - 2) * AW1_JOUR
        }

        /// (11) POLITIQUES NON LUES (une ligne illisible en tête, une au milieu) : non mesuré, pour le pré-agrégé ET pour
        /// `event` (le lecteur froid lit les politiques par le lecteur de la purge, qui avale un refus) ; une famille hors
        /// politique seule (`metric`) reste mesurée. MUTANT : AW1_FROID_NON_LUE_IGNOREE (le pré-agrégé prend l'aveu de
        /// l'environnement non déterminé, `event` est mesuré).
        #[test]
        fn aw1_froid_politiques_non_lues_non_mesure() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
            let (st, base, conf) = aw1_froid("aw1-froid-non-lue");
            {
                let c = st.db.lock();
                aw1_politiques_avec_illisibles(&c, 1);
                aw1_reglage(&c, "metric_raw_hours", "48");
            }
            let depuis = AW1_MAINTENANT - 25 * AW1_JOUR;
            let mut joues = 0;
            for sql in ["SELECT bucket FROM event_rollup WHERE bucket >= 0", "SELECT ts FROM event"] {
                for env in [Some("stage"), None] {
                    let cov = panneau_avoue::horizon_de_la_voie_froide_lue(base.as_str(), &conf, sql, depuis, AW1_MAINTENANT, aw1_frontiere(), env);
                    assert_eq!(cov, aw1_non_lue(depuis, AW1_MAINTENANT), "{sql}, {env:?} : politiques non lues, non mesuré");
                    joues += 1;
                }
            }
            assert_eq!(joues, 4, "contrôle : deux familles, deux environnements");
            let cov = panneau_avoue::horizon_de_la_voie_froide_lue(base.as_str(), &conf, "SELECT ts FROM metric", depuis, AW1_MAINTENANT, aw1_frontiere(), Some("stage"));
            assert_eq!(cov, aw1_mesure(depuis, AW1_MAINTENANT, AW1_MAINTENANT - 48 * 3_600, true), "contrôle : metric hors politique, mesurée");
        }

        /// (12) PRÉ-AGRÉGÉ, ENVIRONNEMENT NON DÉTERMINÉ, SEULE POLITIQUE PLUS LONGUE que la globale (soixante contre
        /// trente) : la plus courte d'elle et de la globale, trente — jamais soixante. MUTANT : AW1_FROID_MIN_GLOBALE.
        #[test]
        fn aw1_froid_la_plus_courte_est_bornee_par_la_globale() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
            let (st, base, conf) = aw1_froid("aw1-froid-plus-courte");
            aw1_lisible(&st.db.lock(), "stage", 60);
            let depuis = AW1_MAINTENANT - 45 * AW1_JOUR;
            let cov = panneau_avoue::horizon_de_la_voie_froide_lue(
                base.as_str(), &conf, "SELECT bucket FROM event_rollup WHERE bucket >= 0", depuis, AW1_MAINTENANT, aw1_frontiere(), None,
            );
            assert_eq!(cov, aw1_mesure(depuis, AW1_MAINTENANT, AW1_MAINTENANT - 30 * AW1_JOUR, true), "la plus courte, bornée par la globale");
        }

        /// (13) UNE FAMILLE HORS POLITIQUE LISIBLE GARDE SA RÉTENTION dans la voie froide : `event_rollup` et `metric`,
        /// `stage` à dix jours, `metric` à quarante-huit heures : l'horizon est celui de `metric`, jamais la durée de la
        /// politique appliquée à `metric`. MUTANT : AW1_FROID_TOUTES_FAMILLES.
        #[test]
        fn aw1_froid_famille_hors_politique_garde_sa_retention() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
            let (st, base, conf) = aw1_froid("aw1-froid-hors-politique");
            {
                let c = st.db.lock();
                aw1_lisible(&c, "stage", 10);
                aw1_reglage(&c, "metric_raw_hours", "48");
            }
            let depuis = AW1_MAINTENANT - 20 * AW1_JOUR;
            let cov = panneau_avoue::horizon_de_la_voie_froide_lue(
                base.as_str(), &conf, "SELECT r.bucket FROM event_rollup r JOIN metric m ON 1=1", depuis, AW1_MAINTENANT, aw1_frontiere(), Some("stage"),
            );
            assert_eq!(cov, aw1_mesure(depuis, AW1_MAINTENANT, AW1_MAINTENANT - 48 * 3_600, true), "metric : quarante-huit heures");
        }
    }
}
