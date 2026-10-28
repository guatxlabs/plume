// =====================================================================================================
// L'HORIZON D'UN PANNEAU SUIT LES POLITIQUES PAR INDEX (`handlers/panneau_avoue.rs`).
//
// LE DÉFAUT. L'horizon publié dans `stats.coverage` prenait la rétention GLOBALE (`retention_days`) pour
// `event`, `event_rollup` et `event_dim_rollup`, et ne lisait jamais `index_policy` — alors que la purge
// (`retention_prune_table`, `rollups.rs`) coupe un environnement doté d'une politique à SA fenêtre et
// l'exclut de la purge globale. Un panneau filtré sur un environnement à politique courte recevait un
// horizon plus profond que ce qui est gardé : un certificat de complétude faux.
//
// CE QUI EST TENU. Environnement déterminé (GXQL compilé avec un environnement non vide) : la politique de
// cet environnement remplace la globale, qu'elle soit plus courte OU plus longue (la purge globale exclut
// cet environnement : la plus longue est la vraie). Environnement non déterminé (aucun, vide, SQL opaque) :
// la plus courte des fenêtres (politiques et globale), comme la lecture froide sans index nommé ; un
// plafond qui tourne et peut couper `event` : NON MESURÉ, notice nommée. Plafond de lignes ou d'octets
// sur l'environnement lu et `event` lu : NON MESURÉ, notice nommée — SAUF sous le tier froid actif, où
// `retention_run` ne joue jamais les plafonds (`plafonds_d_index_actifs`). Aucune politique : l'aveu
// d'avant. `/api/query` (chemin chaud) passe l'environnement qu'il a compilé. Le cache re-servi ne garde
// pas un horizon que la politique rend désormais non dérivable, et laisse intact un corps sans horizon.
// Mutations : AV3_* (une par branche), jouées une par une.
// =====================================================================================================

mod av3_politiques_par_index {
    use super::*;

    const AV3_JOUR: i64 = 86_400;
    const AV3_GXQL: &str = "search source=web | table message";
    const AV3_SQL_EVENT_OPAQUE: &str = "SELECT ts FROM event WHERE ts >= __FROM__";
    const AV3_RAISON_RETENTION: &str = "retention_floor";
    const AV3_RAISON_NON_MESURE: &str = "horizon_non_mesure";
    /// Les phrases de `notice_d_horizon` (raison de rétention), recopiées.
    const AV3_NOTICE_DEHORS: &str = "PORTÉE INCOMPLÈTE : la fenêtre demandée descend SOUS l'horizon de conservation : sous lui, la rétention peut avoir supprimé les lignes, et ce panneau n'est assuré d'en voir aucune. La part antérieure à cet horizon est hors de portée — un creux ou une courbe qui s'y arrête n'établit donc PAS une absence. Ce n'est pas non plus l'affirmation qu'il manque quelque chose : sur une base plus jeune que cet horizon, il se peut que rien n'ait jamais été supprimé.";
    const AV3_NOTICE_DEDANS: &str = "la fenêtre demandée tient AU-DESSUS de l'horizon de conservation : sous lui, la rétention peut avoir supprimé les lignes, et ce panneau n'est assuré d'en voir aucune : rien n'est resté dehors de ce fait.";
    /// Les deux aveux neufs, recopiés (jamais lus depuis la production).
    const AV3_NOTICE_ENV: &str = "l'horizon de conservation de ce panneau n'est PAS établi : un plafond de lignes ou d'octets propre à un environnement est actif, et l'environnement que ce panneau lit n'est pas déterminé — aucune fenêtre de rétention n'est donc un plancher sûr pour ce qu'il lit. Cette réponse ne dit RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";
    const AV3_NOTICE_PLAFOND: &str = "l'horizon de conservation de ce panneau n'est PAS établi : l'environnement qu'il lit porte un plafond de lignes ou d'octets, qui supprime les événements les plus anciens au-delà du plafond, plus récents peut-être que toute fenêtre de rétention. Cette réponse ne dit RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";

    fn av3_notice_reglage_non_lu(cle: &str) -> String {
        format!(
            "l'horizon de conservation de ce panneau n'est PAS établi : le réglage de rétention écrit `{cle}` n'a pas pu être lu (valeur non entière, ou lecture refusée), et aucun horizon n'est calculé sur l'environnement ou le défaut. Cette réponse ne dit donc RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas."
        )
    }

    /// L'aveu d'un horizon mesuré, objet ENTIER.
    fn av3_mesure(depuis: i64, calcule_a: i64, horizon_ts: i64, dehors: bool) -> Value {
        json!({
            "searched_from": depuis,
            "calcule_a": calcule_a,
            "horizon_ts": horizon_ts,
            "older_outside_window": dehors,
            "reason": AV3_RAISON_RETENTION,
            "notice": if dehors { AV3_NOTICE_DEHORS } else { AV3_NOTICE_DEDANS },
        })
    }

    /// L'aveu d'un horizon non mesuré par une politique, objet ENTIER.
    fn av3_non_mesure(depuis: i64, calcule_a: i64, notice: &str) -> Value {
        json!({ "searched_from": depuis, "calcule_a": calcule_a, "reason": AV3_RAISON_NON_MESURE, "notice": notice })
    }

    fn av3_calcule_a(cov: &Value) -> i64 {
        cov["calcule_a"].as_i64().unwrap_or_else(|| panic!("instant du calcul non publié : {cov}"))
    }

    /// Base migrée, un admin `adm`, un tableau privé et un panneau GXQL au coût mesuré bas (chemin LIVE de
    /// `panel_data`, qui exécute par `panneau_avoue::executer`).
    fn av3_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, i64) {
        let path = ff_tmp_path(tag);
        let id = {
            let conn = open_db(&path).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : migrations complètes");
            conn.execute("INSERT INTO user(name,hash,role) VALUES('adm',?1,'admin')", params![hash_pw("adminpw12345").unwrap()]).unwrap();
            conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('d-av3','adm','private')", []).unwrap();
            let did = conn.last_insert_rowid();
            conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'p',?2,1,'table')", params![did, AV3_GXQL]).unwrap();
            let id = conn.last_insert_rowid();
            conn.execute(
                "INSERT OR REPLACE INTO panel_cost(panel_id,query_fp,cost_ms,measured_at) VALUES(?1,?2,1.0,?3)",
                params![id, query_fingerprint(AV3_GXQL, true), now()],
            )
            .unwrap();
            av3_reglage(&conn, "retention_days", "30");
            id
        };
        let st = ds_file_state(&path);
        (st, path, id)
    }

    fn av3_reglage(conn: &Connection, cle: &str, valeur: &str) {
        conn.execute("INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global',?1,?2)", params![cle, valeur]).expect("fixture : réglage posé");
    }

    fn av3_politique(conn: &Connection, nom: &str, jours: i64, max_rows: i64, max_bytes: i64) {
        conn.execute(
            "INSERT INTO index_policy(name,retention_days,max_rows,max_bytes,enabled) VALUES(?1,?2,?3,?4,1)",
            params![nom, jours, max_rows, max_bytes],
        )
        .expect("fixture : politique par index");
    }

    fn av3_admin(env: Option<&str>) -> AuthUser {
        AuthUser {
            name: "adm".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: env.map(str::to_string),
        }
    }

    /// `panel_data` (le gestionnaire réel) : statut et `stats.coverage`.
    async fn av3_par_la_route(st: &AppState, id: i64, env: Option<&str>, depuis: i64) -> Value {
        let q = Query(HashMap::from([("from".to_string(), depuis.to_string()), ("to".to_string(), "0".to_string())]));
        let r = panel_data(State(st.clone()), Extension(av3_admin(env)), Path(id), q).await;
        let code = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        let v: Value = serde_json::from_slice(&b).expect("réponse JSON");
        assert_eq!(code, 200, "contrôle : panneau servi : {v}");
        assert!(v.get("warming").is_none(), "contrôle : chemin LIVE (coût mesuré), pas une chauffe : {v}");
        v["stats"]["coverage"].clone()
    }

    /// `executer` (le seul consommateur de production d'un panneau compilé).
    fn av3_executer(path: &str, query: &str, is_soql: bool, env: Option<&str>, depuis: i64) -> Value {
        let pc = panneau_avoue::compile_panneau_avoue(query, is_soql, depuis, 0, env).expect("panneau compilé");
        panneau_avoue::executer(path, &HashMap::new(), pc, depuis).expect("panneau exécuté")["stats"]["coverage"].clone()
    }

    /// (1) PAR LA ROUTE : politique de dix jours sur `stage`, globale à trente. Panneau filtré `stage` : horizon de dix
    /// jours (fenêtre de vingt : dehors). Environnement non déterminé : la plus courte, dix jours. Environnement `prod`
    /// (sans politique) : la globale. MUTANTS : AV3_ENV_IGNORE, AV3_POLITIQUE_IGNOREE, AV3_PROPRE_GLOBALE,
    /// AV3_INDETERMINE_GLOBALE, AV3_AUTRE_ENV.
    #[tokio::test]
    async fn av3_politique_de_dix_jours_sur_stage_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, id) = av3_etat("av3-route-stage");
        av3_politique(&st.db.lock(), "stage", 10, 0, 0);
        let depuis = now() - 20 * AV3_JOUR;
        let cov = av3_par_la_route(&st, id, Some("stage"), depuis).await;
        let a = av3_calcule_a(&cov);
        assert_eq!(cov, av3_mesure(depuis, a, a - 10 * AV3_JOUR, true), "stage : la politique de dix jours, pas la globale");
        let cov = av3_par_la_route(&st, id, None, depuis).await;
        let a = av3_calcule_a(&cov);
        assert_eq!(cov, av3_mesure(depuis, a, a - 10 * AV3_JOUR, true), "environnement non déterminé : la plus courte");
        let cov = av3_par_la_route(&st, id, Some("prod"), depuis).await;
        let a = av3_calcule_a(&cov);
        assert_eq!(cov, av3_mesure(depuis, a, a - 30 * AV3_JOUR, false), "prod sans politique : la globale");
    }

    /// (2) SANS POLITIQUE : l'aveu d'avant, à l'octet, quel que soit l'environnement. MUTANT : AV3_SANS_POLITIQUE_MUET.
    #[tokio::test]
    async fn av3_sans_politique_l_aveu_d_avant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, id) = av3_etat("av3-sans-politique");
        let depuis = now() - 20 * AV3_JOUR;
        let mut joues = 0;
        for env in [Some("stage"), None] {
            let cov = av3_par_la_route(&st, id, env, depuis).await;
            let a = av3_calcule_a(&cov);
            assert_eq!(cov, av3_mesure(depuis, a, a - 30 * AV3_JOUR, false), "{env:?} : la globale, aveu d'avant");
            joues += 1;
        }
        assert_eq!(joues, 2, "contrôle : deux environnements");
    }

    /// (3) POLITIQUE PLUS LONGUE QUE LA GLOBALE (soixante jours contre trente) : l'horizon est celui de la politique,
    /// PLUS PROFOND que la globale — la purge globale exclut `stage` (`retention_prune_table`, `NOT IN`), ses lignes
    /// restent jusqu'à soixante jours. Fenêtre de quarante-cinq : dedans. MUTANT : AV3_PROPRE_GLOBALE.
    #[tokio::test]
    async fn av3_politique_plus_longue_que_la_globale() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, id) = av3_etat("av3-plus-longue");
        av3_politique(&st.db.lock(), "stage", 60, 0, 0);
        let depuis = now() - 45 * AV3_JOUR;
        let cov = av3_par_la_route(&st, id, Some("stage"), depuis).await;
        let a = av3_calcule_a(&cov);
        assert_eq!(cov, av3_mesure(depuis, a, a - 60 * AV3_JOUR, false), "stage : soixante jours");
    }

    /// (4) POLITIQUE SANS DURÉE NI PLAFOND (`retention_days = 0` : hérite de la globale) : la globale, déterminé ou non.
    /// MUTANTS : AV3_ZERO_PROPRE, AV3_ZERO_INDETERMINE.
    #[tokio::test]
    async fn av3_politique_sans_duree_ni_plafond() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, id) = av3_etat("av3-zero");
        av3_politique(&st.db.lock(), "stage", 0, 0, 0);
        let depuis = now() - 20 * AV3_JOUR;
        let mut joues = 0;
        for env in [Some("stage"), None] {
            let cov = av3_par_la_route(&st, id, env, depuis).await;
            let a = av3_calcule_a(&cov);
            assert_eq!(cov, av3_mesure(depuis, a, a - 30 * AV3_JOUR, false), "{env:?} : politique sans durée = globale");
            joues += 1;
        }
        assert_eq!(joues, 2, "contrôle : deux environnements");
    }

    /// (5) PLAFOND sur l'environnement lu, `event` lu : non mesuré (plafond). Plafond seul (sans durée) et environnement
    /// non déterminé : non mesuré (environnement). MUTANT : AV3_PLAFOND_IGNORE.
    #[tokio::test]
    async fn av3_plafond_sur_l_environnement_lu() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, id) = av3_etat("av3-plafond");
        av3_politique(&st.db.lock(), "stage", 10, 1000, 0);
        let depuis = now() - 20 * AV3_JOUR;
        let cov = av3_par_la_route(&st, id, Some("stage"), depuis).await;
        let a = av3_calcule_a(&cov);
        assert_eq!(cov, av3_non_mesure(depuis, a, AV3_NOTICE_PLAFOND), "stage plafonné : non mesuré");
        let (st, _p, id) = av3_etat("av3-plafond-seul");
        av3_politique(&st.db.lock(), "stage", 0, 0, 1_000_000);
        let cov = av3_par_la_route(&st, id, None, depuis).await;
        let a = av3_calcule_a(&cov);
        assert_eq!(cov, av3_non_mesure(depuis, a, AV3_NOTICE_ENV), "plafond seul, environnement non déterminé : non mesuré");
    }

    /// (6) PLAFOND SANS `event` LU (pré-agrégé seul) : le plafond ne coupe que `event`, la durée de la politique vaut.
    /// MUTANT : AV3_PLAFOND_PARTOUT.
    #[test]
    fn av3_plafond_ignore_sur_le_pre_agrege() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, p, _) = av3_etat("av3-plafond-rollup");
        av3_politique(&st.db.lock(), "stage", 10, 1000, 0);
        let maintenant: i64 = 1_800_000_000;
        let depuis = maintenant - 20 * AV3_JOUR;
        let (cov, _) = panneau_avoue::horizon_et_frontiere_selon_l_index(
            p.as_str(), &HashMap::new(), "SELECT bucket FROM event_rollup WHERE bucket >= 0", Some("stage"), depuis, maintenant,
        );
        assert_eq!(cov, av3_mesure(depuis, maintenant, maintenant - 10 * AV3_JOUR, true), "pré-agrégé : la durée de la politique");
    }

    /// (7) SQL OPAQUE avec un environnement d'appelant : rien ne le filtre, donc non déterminé — la plus courte (`prod`,
    /// dix jours, sous la globale de trente et la politique de soixante de `stage`). GXQL avec un environnement VIDE :
    /// aucun filtre injecté, donc non déterminé — la plus courte encore (avant, la fixture n'avait que la politique de
    /// soixante : la plus courte valait la globale, comme un vide tenu pour déterminé, et le témoin ne pouvait pas
    /// rougir). Le vide n'atteint pas `environnement_lu` par une route (commentaire au site) : c'est le contrat de
    /// l'appel direct qui est tenu. MUTANTS : AV3_OPAQUE_ENV, AV3_ENV_VIDE, AW1_ENV_VIDE_DETERMINE.
    #[test]
    fn av3_opaque_et_environnement_vide_ne_sont_pas_determines() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, p, _) = av3_etat("av3-opaque");
        {
            let c = st.db.lock();
            av3_politique(&c, "stage", 60, 0, 0);
            av3_politique(&c, "prod", 10, 0, 0);
        }
        let depuis = now() - 45 * AV3_JOUR;
        let cov = av3_executer(p.as_str(), AV3_SQL_EVENT_OPAQUE, false, Some("stage"), depuis);
        let a = av3_calcule_a(&cov);
        assert_eq!(cov, av3_mesure(depuis, a, a - 10 * AV3_JOUR, true), "SQL opaque : non déterminé, la plus courte");
        let cov = av3_executer(p.as_str(), AV3_GXQL, true, Some(""), depuis);
        let a = av3_calcule_a(&cov);
        assert_eq!(cov, av3_mesure(depuis, a, a - 10 * AV3_JOUR, true), "environnement vide : non déterminé, la plus courte");
        let cov = av3_executer(p.as_str(), AV3_GXQL, true, Some("stage"), depuis);
        let a = av3_calcule_a(&cov);
        assert_eq!(cov, av3_mesure(depuis, a, a - 60 * AV3_JOUR, false), "contrôle : GXQL filtré stage");
    }

    /// (8) PORTE MASQUÉE : un GXQL masqué compilé avec `stage` lit `stage`. MUTANT : AV3_MASQUE_ENV.
    #[test]
    fn av3_porte_masquee_garde_l_environnement() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, p, _) = av3_etat("av3-masque");
        av3_politique(&st.db.lock(), "stage", 60, 0, 0);
        let depuis = now() - 45 * AV3_JOUR;
        let masques = guatx_core::soql::FieldMaskSet::new();
        let pc = panneau_avoue::compile_panneau_avoue_masque(AV3_GXQL, true, depuis, 0, Some("stage"), &masques).expect("compilé");
        let cov = panneau_avoue::executer(p.as_str(), &HashMap::new(), pc, depuis).expect("exécuté")["stats"]["coverage"].clone();
        let a = av3_calcule_a(&cov);
        assert_eq!(cov, av3_mesure(depuis, a, a - 60 * AV3_JOUR, false), "porte masquée : la politique de stage");
    }

    /// (9) UNE FAMILLE HORS POLITIQUE GARDE SA RÉTENTION : `event` et `metric` nommés, `stage` à dix jours, `metric` à
    /// quarante-huit heures : l'horizon est celui de `metric` (le plus haut), jamais la durée de la politique appliquée
    /// à `metric`. MUTANT : AV3_TOUTES_CLES.
    #[test]
    fn av3_famille_hors_politique_garde_sa_retention() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, p, _) = av3_etat("av3-hors-politique");
        {
            let c = st.db.lock();
            av3_politique(&c, "stage", 10, 0, 0);
            av3_reglage(&c, "metric_raw_hours", "48");
        }
        let maintenant: i64 = 1_800_000_000;
        let depuis = maintenant - 20 * AV3_JOUR;
        let (cov, _) = panneau_avoue::horizon_et_frontiere_selon_l_index(
            p.as_str(), &HashMap::new(), "SELECT e.ts FROM event e JOIN metric m ON 1=1", Some("stage"), depuis, maintenant,
        );
        assert_eq!(cov, av3_mesure(depuis, maintenant, maintenant - 48 * 3_600, true), "metric : quarante-huit heures");
    }

    /// (10) RÉGLAGE ILLISIBLE ET POLITIQUE MUETTE DANS LE MÊME CALCUL : le réglage non lu l'emporte (la purge saute alors
    /// la famille). Les DEUX causes sont présentes : un plafond qui tourne, environnement non déterminé, `event` lu
    /// (`EnvironnementNonDetermine`), et `alert_days` illisible. Avant, la politique était de durée seule (la plus courte,
    /// aucune notice de politique) : l'ordre n'était jamais joué (vérification de la vague AV, mutant V23 vert). MUTANTS :
    /// AV3_PRIORITE_REGLAGE, AW1_ORDRE_MUETTE_AVANT.
    #[test]
    fn av3_reglage_illisible_l_emporte_sur_la_politique() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, p, _) = av3_etat("av3-priorite");
        {
            let c = st.db.lock();
            av3_politique(&c, "stage", 10, 1000, 0);
            av3_reglage(&c, "alert_days", "trente");
        }
        let depuis = now() - 20 * AV3_JOUR;
        let cov = av3_executer(p.as_str(), "SELECT a.ts FROM alert a JOIN event e ON 1=1 WHERE a.ts>=__FROM__", false, None, depuis);
        assert_eq!(
            cov,
            json!({ "searched_from": depuis, "calcule_a": av3_calcule_a(&cov), "reason": AV3_RAISON_NON_MESURE, "reglage_non_lu": "alert_days",
                    "notice": av3_notice_reglage_non_lu("alert_days") }),
            "réglage illisible : son aveu, pas celui de la politique"
        );
    }

    /// (11) CACHE RE-SERVI : un horizon écrit sans politique n'est plus re-servi quand une politique le rend non dérivable
    /// (plafond et environnement non déterminé, puis plafond sur l'environnement lu). MUTANTS : AV3_RESTAMP_ENV,
    /// AV3_RESTAMP_PLAFOND.
    #[test]
    fn av3_cache_re_servi_suit_la_politique() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut joues = 0;
        for (tag, env, plafond, notice) in [("av3-cache-env", None, 1000, AV3_NOTICE_ENV), ("av3-cache-plafond", Some("stage"), 1000, AV3_NOTICE_PLAFOND)] {
            let (st, p, _) = av3_etat(tag);
            let depuis = now() - 20 * AV3_JOUR;
            let pc = panneau_avoue::compile_panneau_avoue(AV3_GXQL, true, depuis, 0, env).expect("compilé");
            let stocke = panneau_avoue::horizon(p.as_str(), &HashMap::new(), &pc, depuis);
            let a = av3_calcule_a(&stocke);
            assert_eq!(stocke, av3_mesure(depuis, a, a - 30 * AV3_JOUR, false), "{tag} : contrôle, écrit sans politique");
            av3_politique(&st.db.lock(), "stage", 10, plafond, 0);
            let mut v = json!({ "columns": [], "rows": [], "stats": { "coverage": stocke } });
            panneau_avoue::cache_reestamper(&mut v, p.as_str(), &HashMap::new(), Some(&pc), a, a + 5);
            assert_eq!(v["stats"]["coverage"], av3_non_mesure(depuis, a, notice), "{tag} : re-servi non mesuré");
            joues += 1;
        }
        assert_eq!(joues, 2, "contrôle : deux causes");
    }

    /// (15) UN CORPS D'ÉCHEC EN CACHE (`calcul_echoue`, sans horizon) N'EST PAS RÉ-ESTAMPÉ quand une politique rend
    /// l'horizon non dérivable : il garde sa raison et sa phrase, et `error` sa cause. MUTANT : AV3C_RESTAMP_ECHEC.
    #[test]
    fn av3_corps_d_echec_en_cache_garde_sa_raison() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, p, _) = av3_etat("av3-cache-echec");
        av3_politique(&st.db.lock(), "stage", 10, 1000, 0);
        let depuis = now() - 20 * AV3_JOUR;
        let a = now();
        let pc = panneau_avoue::compile_panneau_avoue(AV3_GXQL, true, depuis, 0, Some("stage")).expect("compilé");
        let echec = panneau_avoue::corps_d_echec("moteur indisponible", depuis, a);
        assert_eq!(echec["stats"]["coverage"]["reason"], json!("calcul_echoue"), "contrôle : corps d'échec");
        assert!(echec["stats"]["coverage"].get("horizon_ts").is_none(), "contrôle : sans horizon");
        let mut v = echec.clone();
        panneau_avoue::cache_reestamper(&mut v, p.as_str(), &HashMap::new(), Some(&pc), a, a + 5);
        assert_eq!(v, echec, "corps d'échec re-servi : intact");
    }

    /// (16) LA ROUTE DE PRÉ-AGRÉGAT D'UN PANNEAU (`search | stats count by source`, la forme de tous les panneaux livrés)
    /// lit l'environnement compilé : `stage` à soixante jours (globale à trente), l'horizon est soixante jours, pas la
    /// plus courte. MUTANT : AV3C_ROUTE_ENV.
    #[test]
    fn av3_route_de_pre_agregat_garde_l_environnement() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, p, _) = av3_etat("av3-route-preagrege");
        av3_politique(&st.db.lock(), "stage", 60, 0, 0);
        let depuis = now() - 45 * AV3_JOUR;
        let pc = panneau_avoue::compile_panneau_avoue("search | stats count by source", true, depuis, 0, Some("stage")).expect("compilé");
        assert!(pc.sql_de_test().contains("event_rollup"), "contrôle : routé vers le pré-agrégé : {}", pc.sql_de_test());
        let cov = panneau_avoue::horizon(p.as_str(), &HashMap::new(), &pc, depuis);
        let a = av3_calcule_a(&cov);
        assert_eq!(cov, av3_mesure(depuis, a, a - 60 * AV3_JOUR, false), "pré-agrégé routé, stage : soixante jours");
    }

    /// (17) `/api/query`, CHEMIN CHAUD, PAR LE GESTIONNAIRE RÉEL : un GXQL compilé pour `stage` (politique de soixante
    /// jours, globale à trente) publie soixante jours ; sans environnement, la plus courte (trente). MUTANT :
    /// AV3C_QUERY_ENV.
    #[tokio::test]
    async fn av3_api_query_chemin_chaud_passe_l_environnement() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, _) = av3_etat("av3-api-query");
        av3_politique(&st.db.lock(), "stage", 60, 0, 0);
        let depuis = now() - 45 * AV3_JOUR;
        let mut joues = 0;
        for (env, jours, dehors) in [(Some("stage"), 60, false), (None, 30, true)] {
            let r = crate::handlers::query::query(State(st.clone()), Extension(av3_admin(env)), Json(json!({ "soql": AV3_GXQL, "from": depuis }))).await;
            let code = r.status().as_u16();
            let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
            let v: Value = serde_json::from_slice(&b).expect("réponse JSON");
            assert_eq!(code, 200, "contrôle : requête servie : {v}");
            let cov = v["stats"]["coverage"].clone();
            let a = av3_calcule_a(&cov);
            assert_eq!(cov, av3_mesure(depuis, a, a - jours * AV3_JOUR, dehors), "{env:?} : {jours} jours");
            joues += 1;
        }
        assert_eq!(joues, 2, "contrôle : deux environnements");
    }

    /// LA VOIE FROIDE DE `/api/query` (`horizon_de_la_voie_froide_lue`) et le chemin chaud SOUS LE TIER FROID ACTIF
    /// (`PLUME_COLD_TIER=1`, seul état où la voie froide existe) : les pré-agrégés suivent la politique, `event` suit déjà
    /// les politiques par le lecteur froid, et aucun plafond ne rend l'horizon non mesuré — `retention_run` ne les joue
    /// pas sous le tier froid.
    #[cfg(feature = "cold_tier")]
    mod froid {
        use super::*;

        /// La base (fichier temporaire possédé, retiré à la chute) est rendue avec l'état : le témoin la garde vivante.
        fn av3_froid(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, HashMap<String, String>) {
            let (st, base) = router_test_state(tag);
            let mut conf: HashMap<String, String> = HashMap::new();
            conf.insert("PLUME_COLD_HOT_WINDOW_DAYS".to_string(), "2".to_string());
            conf.insert("PLUME_COLD_TIER".to_string(), "1".to_string());
            av3_reglage(&st.db.lock(), "retention_days", "30");
            (st, base, conf)
        }

        const AV3_SQL_ROLLUP: &str = "SELECT bucket FROM event_rollup WHERE bucket >= 0";
        const AV3_SQL_EVENT_METRIC: &str = "SELECT e.ts FROM event e JOIN metric m ON 1=1";

        /// (12) Pré-agrégé, `stage` déterminé : soixante jours (globale à trente, `prod` à dix) ; non déterminé, ou
        /// environnement vide passé tel quel : la plus courte, dix (`prod`). Le plafond de `stage` n'y change rien
        /// (pré-agrégé, tier froid).
        /// MUTANTS : AV3_FROID_ROLLUP_GLOBAL, AV3_FROID_INDETERMINE, AV3C_FROID_ENV_VIDE, AV3C_FROID_PLAFOND_MORD.
        #[test]
        fn av3_froid_pre_agrege_suit_la_politique() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
            let (st, base, conf) = av3_froid("av3-froid-rollup");
            {
                let c = st.db.lock();
                av3_politique(&c, "stage", 60, 1000, 1_000_000);
                av3_politique(&c, "prod", 10, 0, 0);
            }
            let maintenant: i64 = 1_800_000_000;
            let frontiere = (maintenant.div_euclid(AV3_JOUR) - 2) * AV3_JOUR;
            let depuis = maintenant - 45 * AV3_JOUR;
            let cov = panneau_avoue::horizon_de_la_voie_froide_lue(base.as_str(), &conf, AV3_SQL_ROLLUP, depuis, maintenant, frontiere, Some("stage"));
            assert_eq!(cov, av3_mesure(depuis, maintenant, maintenant - 60 * AV3_JOUR, false), "stage : soixante jours");
            let mut joues = 0;
            for env in [None, Some("")] {
                let cov = panneau_avoue::horizon_de_la_voie_froide_lue(base.as_str(), &conf, AV3_SQL_ROLLUP, depuis, maintenant, frontiere, env);
                assert_eq!(cov, av3_mesure(depuis, maintenant, maintenant - 10 * AV3_JOUR, true), "{env:?} : la plus courte");
                joues += 1;
            }
            assert_eq!(joues, 2, "contrôle : deux environnements non déterminés");
        }

        /// (13) `event` lu par la voie froide : des plafonds (lignes sur `stage`, octets sur `prod`) ne changent rien à
        /// l'horizon du lecteur froid, environnement déterminé ou non. MUTANT : AV3C_FROID_PLAFOND_REVENU.
        #[test]
        fn av3_froid_plafond_sur_event_ne_tourne_pas() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
            let maintenant: i64 = 1_800_000_000;
            let frontiere = (maintenant.div_euclid(AV3_JOUR) - 2) * AV3_JOUR;
            let depuis = frontiere - 10 * AV3_JOUR;
            let sql = "SELECT ts FROM event";
            let (st, base, conf) = av3_froid("av3-froid-plafond");
            let mut joues = 0;
            for env in [Some("stage"), None] {
                let avant = panneau_avoue::horizon_de_la_voie_froide_lue(base.as_str(), &conf, sql, depuis, maintenant, frontiere, env);
                assert!(avant["horizon_ts"].is_i64(), "contrôle : horizon d'avant mesuré : {avant}");
                {
                    let c = st.db.lock();
                    av3_politique(&c, "stage", 0, 1000, 0);
                    av3_politique(&c, "prod", 0, 0, 1_000_000);
                }
                let cov = panneau_avoue::horizon_de_la_voie_froide_lue(base.as_str(), &conf, sql, depuis, maintenant, frontiere, env);
                assert_eq!(cov, avant, "{env:?} : plafonds sous le tier froid, l'horizon du lecteur froid");
                st.db.lock().execute("DELETE FROM index_policy", []).expect("fixture : politiques retirées");
                joues += 1;
            }
            assert_eq!(joues, 2, "contrôle : deux environnements");
        }

        /// (18) CHEMIN CHAUD DU PANNEAU SOUS LE TIER FROID ACTIF : un plafond sur `stage` ne rend pas l'horizon non mesuré
        /// (même aveu que la politique sans plafond) ; sans `PLUME_COLD_TIER=1`, le même plafond le rend non mesuré.
        /// MUTANT : AV3C_PLAFONDS_TOUJOURS_ACTIFS.
        #[test]
        fn av3_froid_chemin_chaud_plafond_inactif() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
            let (st, base, conf) = av3_froid("av3-froid-chaud");
            let maintenant: i64 = 1_800_000_000;
            let depuis = maintenant - 20 * AV3_JOUR;
            let sql = "SELECT ts FROM event WHERE env_id = 'stage'";
            av3_politique(&st.db.lock(), "stage", 10, 0, 0);
            let (sans_plafond, _) = panneau_avoue::horizon_et_frontiere_selon_l_index(base.as_str(), &conf, sql, Some("stage"), depuis, maintenant);
            assert!(sans_plafond["horizon_ts"].is_i64(), "contrôle : horizon mesuré : {sans_plafond}");
            st.db.lock().execute("UPDATE index_policy SET max_rows=1000 WHERE name='stage'", []).expect("fixture : plafond posé");
            let (cov, _) = panneau_avoue::horizon_et_frontiere_selon_l_index(base.as_str(), &conf, sql, Some("stage"), depuis, maintenant);
            assert_eq!(cov, sans_plafond, "tier froid actif : le plafond ne tourne pas");
            let mut tiede = conf.clone();
            tiede.remove("PLUME_COLD_TIER");
            let (cov, _) = panneau_avoue::horizon_et_frontiere_selon_l_index(base.as_str(), &tiede, sql, Some("stage"), depuis, maintenant);
            assert_eq!(cov, av3_non_mesure(depuis, maintenant, AV3_NOTICE_PLAFOND), "contrôle : tier froid éteint, le plafond tourne");
        }

        /// (14) Réglage illisible (`metric_raw_hours`) ET politiques non lues (une ligne illisible) dans le même calcul : le
        /// réglage non lu l'emporte. Avant, la seconde cause était un plafond, qui ne rend jamais la voie froide muette
        /// (`politique_lue(.., false)`) : la branche n'était pas jouée et le témoin ne pouvait pas rougir (vérification de
        /// la vague AV). MUTANTS : AV3_FROID_PRIORITE, AW1_FROID_ORDRE.
        #[test]
        fn av3_froid_reglage_illisible_l_emporte() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
            let (st, base, conf) = av3_froid("av3-froid-priorite");
            {
                let c = st.db.lock();
                av3_politique(&c, "stage", 0, 1000, 0);
                c.execute("INSERT INTO index_policy(name,retention_days,max_rows,max_bytes,enabled) VALUES('prod','dix',0,0,1)", [])
                    .expect("fixture : politique illisible");
                av3_reglage(&c, "metric_raw_hours", "quarante");
            }
            let maintenant: i64 = 1_800_000_000;
            let frontiere = (maintenant.div_euclid(AV3_JOUR) - 2) * AV3_JOUR;
            let depuis = maintenant - 20 * AV3_JOUR;
            let cov = panneau_avoue::horizon_de_la_voie_froide_lue(base.as_str(), &conf, AV3_SQL_EVENT_METRIC, depuis, maintenant, frontiere, Some("stage"));
            assert_eq!(
                cov,
                json!({ "searched_from": depuis, "calcule_a": maintenant, "reason": AV3_RAISON_NON_MESURE, "reglage_non_lu": "metric_raw_hours",
                        "notice": av3_notice_reglage_non_lu("metric_raw_hours") }),
                "réglage illisible : son aveu"
            );
        }
    }
}
