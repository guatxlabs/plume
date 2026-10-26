// =====================================================================================
// `P10.20-b` (restes de la vague AQ : lectures de `retention_effective` HORS de la passe), `P10.28-l` (deux lectures
// ratées prises pour une absence : `maintenance.rs`, `seeds.rs`).
//
// LES DÉFAUTS, LUS SUR f5d7008c :
//  * `retention_settings_put` (admin_ui.rs) : l'ancienne valeur lue par `setting_days`, qui jette l'illisible et rend le
//    repli env/conf/défaut. Une ligne écrite illisible (BLOB, « 365.0 ») dont la nouvelle valeur ÉGALAIT ce repli était
//    classée no-op (`if n == cur { continue }`) : la réparation demandée n'était pas écrite, la purge restait suspendue
//    sur la famille ; sinon l'audit inscrivait le repli comme « ancienne valeur » (`"old": cur`) ;
//  * `retention_preview` : `current` et `destructive` calculés sur le repli ; le registre des exclusions (planchers de
//    rétention, `effective`) et `GET /api/index-policies` (`global_retention_days`) servaient le repli comme valeur ;
//  * l'horizon des panneaux (`panneau_avoue.rs`) : une famille illisible donnait un plancher calculé sur le repli ; sous
//    le tier froid, la frontière (horizon et `stats.cold`) aussi ; la recherche (`search.rs`) aussi ;
//  * `reparse_lower_bound` (aging.rs), la bannière du tier froid, la sonde `cold-aging-plan` : fenêtre chaude,
//    rétention cold et bande calculées sur le repli ;
//  * `ensure_rollup_srcip_host_panels` (maintenance.rs) : `Err(_) => return` sur la lecture du tableau rapide, retour
//    muet ; le drapeau des semis (`PointDeReprise::deja_seme`, seeds.rs) et celui de la démonstration lus par
//    `.is_ok()` : une lecture ratée valait absence et le semis était rejoué.
//
// DÉSORMAIS (décisions de l'orchestrateur, vague AR) : `retention_effective_lue` (main.rs) rend la valeur ou la cause ;
// le PUT ÉCRIT toujours sur une ligne illisible et l'audite « (ancienne valeur non lue) », sans nombre ni « destructif »,
// et sert `ancienne_valeur_non_lue` ; une valeur LUE égale reste un no-op (200 `changed: 0`) ; aperçu, registre et
// politiques d'index servent `null` et la cause ; l'horizon dit « non établi » (`reglage_non_lu`) ; sous le tier froid,
// aucune frontière, le reparse REFUSÉ en 503 nommé, la bannière dit « NON LUES », la sonde refuse de publier un plan ;
// le tableau rapide et les drapeaux de semis sont lus en trois issues (non lu : rien n'est écrit, c'est dit, et compté
// pour les semis comptés).
//
// LES VOIES D'ÉCHEC FABRIQUÉES : valeur `setting` posée en BLOB ou en texte « 365.0 » sur UNE clé à la fois ;
// autorisateur SQLite refusant la lecture de `dashboard.name` ou de `meta.key` seule ; la table `index_policy` renommée
// (bras d'échec de l'inventaire). Journal lu sur le stderr d'un sous-processus, lignes ENTIÈRES.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : `query.rs` (vers :1177 et :1976) et `datamodels.rs` (vers :551) lisent encore la
// frontière froide par `retention_effective` (hors de ce lot) ; une réponse de panneau servie depuis le cache garde
// l'horizon mesuré à l'écriture quand le réglage devient illisible ensuite (`horizon_perime` ne se pose pas) ; la
// console (`web/index_policies.js`) affiche `global_retention_days: null` comme un nombre (zone d'une autre session).
//
// LES MUTATIONS QUI LES FONT ROUGIR (variable de mutation sous `cfg!(test)`, retirées du source avant le commit) : voir chaque
// témoin (`AR1_*`).
// =====================================================================================
mod retention_lue_hors_de_la_passe {
    use super::*;
    use crate::comptes_de_transaction::compte_des_temoins;
    use axum::response::IntoResponse;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// Les deux formes d'une valeur écrite illisible : un BLOB (la ligne EXISTE, `get::<String>` échoue) et un texte
    /// présent mais non entier (jamais arrondi, leçon AQ).
    const AR1_ILLISIBLES: [&str; 2] = ["BLOB", "365.0"];
    const AR1_CLE: &str = "retention_days";

    fn ar1_valeur(forme: &str) -> rusqlite::types::Value {
        match forme {
            "BLOB" => rusqlite::types::Value::Blob(vec![0]),
            texte => rusqlite::types::Value::Text(texte.to_string()),
        }
    }

    fn ar1_pose(conn: &Connection, cle: &str, valeur: rusqlite::types::Value) {
        conn.execute("INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global',?1,?2)", params![cle, valeur]).expect("réglage posé");
    }

    async fn ar1_corps(r: Response) -> (StatusCode, Value) {
        let code = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (code, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    fn ar1_admin() -> AuthUser {
        sp_au("adm", "admin")
    }

    /// Le repli env/conf/défaut que la forme d'avant aurait servi pour `retention_days` (même chaîne que les routes).
    fn ar1_repli(conn: &Connection) -> i64 {
        crate::retention_effective(conn, &load_config(), AR1_CLE)
    }

    fn ar1_dernier_audit(conn: &Connection) -> (String, i64, String, Value) {
        let detail: String = conn
            .query_row("SELECT detail FROM ledger WHERE kind='config.retention.retention_days' ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .expect("une trace au registre");
        let (sev, msg, fields): (i64, String, String) = conn
            .query_row(
                "SELECT severity, message, fields FROM event WHERE source='plume-config' AND message LIKE 'rétention retention_days:%' ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("un événement d'audit");
        (detail, sev, msg, serde_json::from_str(&fields).expect("champs JSON"))
    }

    fn ar1_traces(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind='config.retention.retention_days'", [], |r| r.get(0)).expect("traces")
    }

    /// (a) PUT SUR UNE LIGNE ILLISIBLE, VALEUR ÉGALE AU REPLI : écrite, auditée « (ancienne valeur non lue) » sans nombre
    /// ni « destructif », sévérité haute, `ancienne_valeur_non_lue` servi ; la ligne devient lisible et vaut la valeur.
    /// MUTANTS : `AR1_PUT_REPLI` (ancienne valeur = repli : no-op, rien n'est écrit), `AR1_PUT_AUDIT_REPLI` (écrite,
    /// mais l'audit inscrit le repli), `AR1_PUT_SANS_CHAMP` (corps sans `ancienne_valeur_non_lue`).
    #[tokio::test]
    async fn ar1_put_sur_ligne_illisible_ecrit_la_valeur_egale_au_repli_et_l_audite_sans_nombre() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        for forme in table_declaree!(AR1_ILLISIBLES) {
            let (st, _p) = sp_state(&format!("ar1-put-{}", forme.replace('.', "-")));
            let repli = {
                let conn = st.db.lock();
                ar1_pose(&conn, AR1_CLE, ar1_valeur(forme));
                ar1_repli(&conn)
            };
            let (code, corps) =
                ar1_corps(retention_settings_put(State(st.clone()), Extension(ar1_admin()), Json(json!({ "retention_days": repli }))).await.into_response()).await;
            assert_eq!(code, StatusCode::OK, "{forme} : {corps}");
            assert_eq!(
                corps,
                json!({ "ok": true, "changed": 1, "applied": { "retention_days": repli }, "ancienne_valeur_non_lue": ["retention_days"] }),
                "{forme} : la valeur égale au repli est ÉCRITE et la réparation dite"
            );
            let conn = st.db.lock();
            let ecrite: String =
                conn.query_row("SELECT value FROM setting WHERE scope='global' AND key=?1", params![AR1_CLE], |r| r.get(0)).expect("ligne réparée lisible");
            assert_eq!(ecrite, repli.to_string(), "{forme} : la ligne porte la valeur demandée");
            let (detail, sev, msg, champs) = ar1_dernier_audit(&conn);
            let ancienne = crate::handlers::admin_ui::ANCIENNE_VALEUR_DE_RETENTION_NON_LUE;
            assert_eq!(detail, format!("{ancienne}->{repli} par adm"), "{forme} : registre");
            assert_eq!(msg, format!("rétention retention_days: {ancienne}->{repli} par adm"), "{forme} : message");
            assert_eq!(sev, 3, "{forme} : une baisse ne peut pas être exclue : sévérité haute");
            assert_eq!(
                champs,
                json!({ "key": "retention_days", "old": null, "old_non_lue": true, "new": repli, "actor": "adm", "destructive": null }),
                "{forme} : aucun nombre inventé, « destructif » non affirmé"
            );
        }
    }

    /// (b) CONTRÔLE POSITIF — ligne LISIBLE : valeur égale = no-op à l'octet d'avant (aucune trace) ; valeur différente =
    /// l'audit d'avant (ancienne valeur LUE, destructif calculé). MUTANT : `AR1_PUT_TOUJOURS` (écrit aussi l'égale lue).
    #[tokio::test]
    async fn ar1_put_sur_ligne_lisible_garde_le_no_op_et_l_audit_d_avant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = sp_state("ar1-put-lisible");
        {
            let conn = st.db.lock();
            ar1_pose(&conn, AR1_CLE, rusqlite::types::Value::Text("40".into()));
        }
        let avant = ar1_traces(&st.db.lock());
        let (code, corps) = ar1_corps(retention_settings_put(State(st.clone()), Extension(ar1_admin()), Json(json!({ "retention_days": 40 }))).await.into_response()).await;
        assert_eq!((code, corps.clone()), (StatusCode::OK, json!({ "ok": true, "changed": 0, "applied": {} })), "valeur LUE égale : no-op");
        assert_eq!(ar1_traces(&st.db.lock()), avant, "no-op : aucune trace");
        let (code, corps) = ar1_corps(retention_settings_put(State(st.clone()), Extension(ar1_admin()), Json(json!({ "retention_days": 35 }))).await.into_response()).await;
        assert_eq!((code, corps), (StatusCode::OK, json!({ "ok": true, "changed": 1, "applied": { "retention_days": 35 } })), "valeur lue différente");
        let (detail, sev, _, champs) = ar1_dernier_audit(&st.db.lock());
        assert_eq!((detail.as_str(), sev), ("40->35 par adm", 3), "l'audit d'avant : ancienne valeur lue, baisse = sévérité haute");
        assert_eq!(champs, json!({ "key": "retention_days", "old": 40, "new": 35, "actor": "adm", "destructive": true }));
    }

    /// (c) APERÇU — ligne illisible : `current` et `destructive` à `null`, `current_non_lu` nommé, corps ENTIER ; ligne
    /// lisible : le corps d'avant. MUTANTS : `AR1_PREVIEW_REPLI` (current = repli), `AR1_PREVIEW_SANS_CAUSE`.
    #[tokio::test]
    async fn ar1_apercu_sur_ligne_illisible_ne_compare_pas_au_repli() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut q = HashMap::new();
        q.insert("key".to_string(), AR1_CLE.to_string());
        q.insert("value".to_string(), "100".to_string());
        for forme in table_declaree!(AR1_ILLISIBLES) {
            let (st, _p) = sp_state(&format!("ar1-apercu-{}", forme.replace('.', "-")));
            ar1_pose(&st.db.lock(), AR1_CLE, ar1_valeur(forme));
            let (code, corps) = ar1_corps(retention_preview(State(st.clone()), Extension(ar1_admin()), Query(q.clone())).await.into_response()).await;
            assert_eq!(code, StatusCode::OK);
            assert_eq!(
                corps,
                json!({
                    "ok": true, "key": "retention_days", "unit": "days", "current": null, "new": 100, "destructive": null,
                    "deleted": 0, "deleted_kind": "events", "oldest": null, "approx": true,
                    "current_non_lu": crate::handlers::admin_ui::CAUSE_VALEUR_DE_RETENTION_EN_VIGUEUR_NON_LUE,
                }),
                "{forme} : corps entier"
            );
        }
        let (st, _p) = sp_state("ar1-apercu-lisible");
        ar1_pose(&st.db.lock(), AR1_CLE, rusqlite::types::Value::Text("40".into()));
        let (_, corps) = ar1_corps(retention_preview(State(st.clone()), Extension(ar1_admin()), Query(q.clone())).await.into_response()).await;
        assert_eq!(
            corps,
            json!({ "ok": true, "key": "retention_days", "unit": "days", "current": 40, "new": 100, "destructive": false,
                    "deleted": 0, "deleted_kind": "events", "oldest": null, "approx": true }),
            "contrôle : le corps d'avant"
        );
    }

    fn ar1_planchers(corps: &Value) -> Vec<Value> {
        let entree = corps["daemon"].as_array().expect("registre du démon").iter().find(|e| e["name"] == json!("retention_floors")).cloned().expect("planchers");
        entree["detail"]["fields"].as_array().expect("champs").clone()
    }

    fn ar1_plancher_attendu(cle: &str, effective: Option<i64>) -> Value {
        let (k, env_key, d, floor, ceil) = crate::RETENTION_FIELDS.into_iter().find(|f| f.0 == cle).expect("clé connue");
        let tables: Vec<&str> =
            crate::handlers::panneau_avoue::FAMILLES_DE_RETENTION.iter().filter(|(_, c, _)| *c == k).map(|(t, _, _)| *t).collect();
        match effective {
            Some(e) => json!({ "key": k, "effective": e, "floor": floor, "ceil": ceil, "default": d, "env": env_key, "tables": tables }),
            None => json!({ "key": k, "effective": null, "effective_non_lue": crate::handlers::admin_ui::CAUSE_VALEUR_DE_RETENTION_EN_VIGUEUR_NON_LUE,
                            "floor": floor, "ceil": ceil, "default": d, "env": env_key, "tables": tables }),
        }
    }

    /// (d) REGISTRE DES EXCLUSIONS (`GET /api/suppressions`) — l'entrée illisible : `effective: null` + cause ; une autre
    /// clé lisible garde sa valeur. MUTANT : `AR1_PLANCHERS_REPLI`.
    #[tokio::test]
    async fn ar1_planchers_du_registre_sans_repli_sur_l_entree_illisible() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        for forme in table_declaree!(AR1_ILLISIBLES) {
            let (st, _p) = sp_state(&format!("ar1-planchers-{}", forme.replace('.', "-")));
            {
                let conn = st.db.lock();
                ar1_pose(&conn, AR1_CLE, ar1_valeur(forme));
                ar1_pose(&conn, "snapshot_days", rusqlite::types::Value::Text("45".into()));
            }
            let (_, corps) = ar1_corps(crate::handlers::admin_ui::suppressions_get(State(st.clone()), Extension(ar1_admin())).await).await;
            let champs = ar1_planchers(&corps);
            assert!(champs.len() >= 5, "INSTRUMENT MUET : {} plancher(s) servis", champs.len());
            let par_cle = |cle: &str| champs.iter().find(|c| c["key"] == json!(cle)).cloned().unwrap_or(Value::Null);
            assert_eq!(par_cle(AR1_CLE), ar1_plancher_attendu(AR1_CLE, None), "{forme} : entrée illisible");
            assert_eq!(par_cle("snapshot_days"), ar1_plancher_attendu("snapshot_days", Some(45)), "{forme} : contrôle, clé lisible");
        }
    }

    /// (e) `GET /api/index-policies` — rétention globale illisible : `null` + `global_retention_non_lue`, dans le bras
    /// nominal ET dans le bras de l'inventaire non lu ; lisible : le corps d'avant, sans la clé. MUTANTS :
    /// `AR1_INDEX_REPLI`, `AR1_INDEX_ERR_SANS_CAUSE`.
    #[tokio::test]
    async fn ar1_politiques_d_index_rendent_la_retention_globale_non_lue() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let cause = crate::handlers::admin_ui::CAUSE_VALEUR_DE_RETENTION_EN_VIGUEUR_NON_LUE;
        for forme in table_declaree!(AR1_ILLISIBLES) {
            let (st, _p) = sp_state(&format!("ar1-index-{}", forme.replace('.', "-")));
            ar1_pose(&st.db.lock(), AR1_CLE, ar1_valeur(forme));
            let (code, corps) = ar1_corps(crate::handlers::index_policies::index_policies_list(State(st.clone()), Extension(ar1_admin())).await).await;
            assert_eq!(code, StatusCode::OK);
            let mut cles: Vec<&String> = corps.as_object().map(|o| o.keys().collect()).unwrap_or_default();
            cles.sort();
            assert_eq!(cles, vec!["bounds", "global_retention_days", "global_retention_non_lue", "indexes", "ok"], "{forme} : clés du corps : {corps}");
            assert_eq!(corps["ok"], json!(true), "{forme}");
            assert_eq!(corps["global_retention_days"], Value::Null, "{forme} : aucune valeur de repli");
            assert_eq!(corps["global_retention_non_lue"], json!(cause), "{forme} : la cause");
            assert_eq!(corps["bounds"], json!({ "retention_days": { "min_when_set": 7, "max": 3650, "inherit": 0 } }), "{forme}");
            assert!(corps["indexes"].is_array(), "{forme}");
            st.db.lock().execute_batch("ALTER TABLE index_policy RENAME TO index_policy_hors_d_atteinte;").expect("inventaire rendu illisible");
            let (_, corps) = ar1_corps(crate::handlers::index_policies::index_policies_list(State(st.clone()), Extension(ar1_admin())).await).await;
            let attendu = crate::handlers::liste_bornee::corps_de_liste_illisible(
                json!({ "ok": false, "global_retention_days": null, "global_retention_non_lue": cause,
                        "bounds": { "retention_days": { "min_when_set": 7, "max": 3650, "inherit": 0 } } }),
                "indexes",
            );
            assert_eq!(corps, attendu, "{forme} : bras de l'inventaire non lu, corps entier");
        }
        let (st, _p) = sp_state("ar1-index-lisible");
        ar1_pose(&st.db.lock(), AR1_CLE, rusqlite::types::Value::Text("40".into()));
        let (_, corps) = ar1_corps(crate::handlers::index_policies::index_policies_list(State(st.clone()), Extension(ar1_admin())).await).await;
        let mut cles: Vec<&String> = corps.as_object().map(|o| o.keys().collect()).unwrap_or_default();
            cles.sort();
        assert_eq!(cles, vec!["bounds", "global_retention_days", "indexes", "ok"], "contrôle : les clés d'avant : {corps}");
        assert_eq!(corps["global_retention_days"], json!(40), "contrôle : la valeur lue");
    }

    fn ar1_notice_non_etablie(cle: &str) -> String {
        format!(
            "l'horizon de conservation de ce panneau n'est PAS établi : le réglage de rétention écrit `{cle}` n'a pas pu \
             être lu (valeur non entière, ou lecture refusée), et aucun horizon n'est calculé sur l'environnement ou le \
             défaut. Cette réponse ne dit donc RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas."
        )
    }

    /// (f) HORIZON D'UN PANNEAU (`executer`, le point d'entrée des réponses de panneau) — la famille illisible SEULE,
    /// sur un SQL qui nomme deux familles (`alert` illisible, `event` lisible) : aucun horizon, `reglage_non_lu`, notice
    /// « non établi », couverture ENTIÈRE ; contrôle lisible : horizon publié. MUTANTS : `AR1_HORIZON_REPLI` (la famille
    /// illisible lue au repli), `AR1_HORIZON_SAUTE` (la famille illisible sautée : l'horizon d'`event` publié).
    #[tokio::test]
    async fn ar1_horizon_non_etabli_sur_une_famille_illisible() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let conf: HashMap<String, String> = HashMap::new();
        let from = now() - 200 * 86_400;
        let sql = "SELECT a.ts FROM alert a JOIN event e ON 1=1 WHERE a.ts>=__FROM__";
        for forme in table_declaree!(AR1_ILLISIBLES) {
            let (st, p) = sp_state(&format!("ar1-horizon-{}", forme.replace('.', "-")));
            {
                let conn = st.db.lock();
                ar1_pose(&conn, "alert_days", ar1_valeur(forme));
                ar1_pose(&conn, AR1_CLE, rusqlite::types::Value::Text("30".into()));
            }
            let pc = crate::handlers::panneau_avoue::compile_panneau_avoue(sql, false, from, 0, None).expect("panneau compilé");
            let v = crate::handlers::panneau_avoue::executer(p.as_str(), &conf, pc, from).expect("panneau exécuté");
            let cov = v["stats"]["coverage"].clone();
            let calcule_a = cov["calcule_a"].as_i64().expect("instant du calcul publié");
            assert_eq!(
                cov,
                json!({ "searched_from": from, "calcule_a": calcule_a, "reason": "horizon_non_mesure", "reglage_non_lu": "alert_days",
                        "notice": ar1_notice_non_etablie("alert_days") }),
                "{forme} : couverture entière, aucun horizon fabriqué"
            );
        }
        let (st, p) = sp_state("ar1-horizon-lisible");
        {
            let conn = st.db.lock();
            ar1_pose(&conn, "alert_days", rusqlite::types::Value::Text("90".into()));
            ar1_pose(&conn, AR1_CLE, rusqlite::types::Value::Text("30".into()));
        }
        let pc = crate::handlers::panneau_avoue::compile_panneau_avoue(sql, false, from, 0, None).expect("panneau compilé");
        let v = crate::handlers::panneau_avoue::executer(p.as_str(), &conf, pc, from).expect("panneau exécuté");
        assert_eq!(v["stats"]["coverage"]["reason"], json!("retention_floor"), "contrôle : horizon publié : {v}");
        assert!(v["stats"]["coverage"]["horizon_ts"].is_i64(), "contrôle : horizon_ts publié");
        assert!(v["stats"]["coverage"].get("reglage_non_lu").is_none(), "contrôle : rien à avouer");
    }

    fn ar1_tableau_rapide_sans_panneaux(conn: &Connection) {
        seed_rollup_dashboard(conn);
        conn.execute(
            "DELETE FROM panel WHERE title IN ('Sévérité >=3 par src_ip','Volume par host') AND dashboard_id=(SELECT id FROM dashboard WHERE name='Vue d''ensemble (rapide)')",
            [],
        )
        .expect("panneaux rapides retirés");
    }

    fn ar1_panneaux_rapides(conn: &Connection) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM panel WHERE title IN ('Sévérité >=3 par src_ip','Volume par host') AND dashboard_id=(SELECT id FROM dashboard WHERE name='Vue d''ensemble (rapide)')",
            [],
            |r| r.get(0),
        )
        .expect("panneaux rapides")
    }

    /// Les deux titres comptés sur TOUS les tableaux : « rien n'est écrit » se juge partout, pas seulement sur le tableau
    /// rapide (un repli sur un autre tableau, `SELECT MIN(id) FROM dashboard`, y écrirait les deux panneaux).
    fn ar1_panneaux_rapides_partout(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM panel WHERE title IN ('Sévérité >=3 par src_ip','Volume par host')", [], |r| r.get(0))
            .expect("panneaux des deux titres, tous tableaux")
    }

    /// Plancher du témoin : un AUTRE tableau que le rapide existe, sans quoi un repli n'aurait nulle part où écrire.
    fn ar1_autres_tableaux(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM dashboard WHERE name<>'Vue d''ensemble (rapide)'", [], |r| r.get(0)).expect("autres tableaux")
    }

    fn ar1_refuser_la_lecture(conn: &Connection, table: &'static str, colonne: &'static str) {
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == table && column_name == colonne => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn ar1_rendre_la_main(conn: &Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// (g) `ensure_rollup_srcip_host_panels` — le tableau rapide NON LU : aucun panneau des deux titres écrit, sur AUCUN
    /// tableau (compte avant/après sur tous) ; lu : les deux écrits une fois, sur le rapide seul (contrôle). La ligne
    /// `[seed]` est jugée en sous-processus (k). MUTANT : `AR1_REPLI_MIN_ID` (repli sur `SELECT MIN(id) FROM dashboard`).
    #[test]
    fn ar1_tableau_rapide_non_lu_rien_n_est_ecrit_puis_repris() {
        let conn = test_db();
        ar1_tableau_rapide_sans_panneaux(&conn);
        assert!(ar1_autres_tableaux(&conn) >= 1, "plancher : un autre tableau existe (un repli aurait où écrire)");
        let partout_avant = ar1_panneaux_rapides_partout(&conn);
        ar1_refuser_la_lecture(&conn, "dashboard", "name");
        ensure_rollup_srcip_host_panels(&conn);
        ar1_rendre_la_main(&conn);
        assert_eq!(ar1_panneaux_rapides(&conn), 0, "tableau non lu : rien n'est écrit");
        assert_eq!(ar1_panneaux_rapides_partout(&conn), partout_avant, "tableau non lu : rien n'est écrit sur AUCUN tableau");
        ensure_rollup_srcip_host_panels(&conn);
        ensure_rollup_srcip_host_panels(&conn);
        assert_eq!(ar1_panneaux_rapides(&conn), 2, "contrôle : lu, les deux panneaux une fois");
        assert_eq!(ar1_panneaux_rapides_partout(&conn), partout_avant + 2, "contrôle : les deux, sur le tableau rapide seul");
    }

    const AR1_SECURITE: &str = "Sécurité & détection";

    /// Une base SUR DISQUE : les comptes des témoins sont rangés par chemin de base (une base en mémoire n'en a pas).
    fn ar1_base_sur_disque(tag: &str) -> (crate::tmp_possede::TmpPossede, Connection) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let conn = open_db(&p).expect("base sur disque");
        conn.execute_batch(include_str!("../../../db/schema.sql")).expect("schéma");
        assert!(migrate(&conn), "la chaîne de migrations doit aller au bout");
        (tmp, conn)
    }

    fn ar1_tableaux(conn: &Connection, nom: &str) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM dashboard WHERE name=?1", params![nom], |r| r.get(0)).expect("tableaux")
    }

    fn ar1_compte_presence_non_lue(conn: &Connection) -> u64 {
        compte_des_temoins(
            conn,
            &format!("geste de fond non validé seed : {} : {}", crate::seeds::GESTE_TABLEAU_SEME_SOUS_DRAPEAU, crate::seeds::ETAPE_PRESENCE_NON_LUE),
        )
    }

    fn ar1_sans_securite(conn: &Connection) {
        conn.execute("DELETE FROM panel WHERE dashboard_id IN (SELECT id FROM dashboard WHERE name=?1)", params![AR1_SECURITE]).expect("panneaux retirés");
        conn.execute("DELETE FROM dashboard WHERE name=?1", params![AR1_SECURITE]).expect("tableau retiré");
        conn.execute("DELETE FROM meta WHERE key='seeded_security'", []).expect("drapeau retiré");
    }

    fn ar1_sans_velero(conn: &Connection) {
        conn.execute("DELETE FROM rule WHERE name='Backup Velero en échec'", []).expect("règle retirée");
        conn.execute("DELETE FROM meta WHERE key='seeded_velero_rule'", []).expect("drapeau retiré");
    }

    fn ar1_regles_velero(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM rule WHERE name='Backup Velero en échec'", [], |r| r.get(0)).expect("règles")
    }

    /// (h) DRAPEAU DE SEMIS NON LU (`meta.key` refusée seule) — tableau sous drapeau : rien n'est écrit, compté UNE fois
    /// sous « présence non lue » ; règle sous drapeau : rien n'est écrit ; lu : semés une fois (contrôle), drapeau posé
    /// = pas de second semis. MUTANT : `AR1_DRAPEAU_IS_OK` (la forme d'avant : lecture ratée = absence).
    #[test]
    fn ar1_drapeau_de_semis_non_lu_rien_n_est_ecrit_et_compte() {
        let (_tmp, conn) = ar1_base_sur_disque("ar1-drapeau");
        ar1_sans_securite(&conn);
        ar1_sans_velero(&conn);
        let avant = ar1_compte_presence_non_lue(&conn);
        ar1_refuser_la_lecture(&conn, "meta", "key");
        crate::seeds::seed_security_dashboard(&conn);
        crate::seeds::seed_velero_rule(&conn);
        ar1_rendre_la_main(&conn);
        assert_eq!(ar1_tableaux(&conn, AR1_SECURITE), 0, "drapeau non lu : aucun tableau");
        assert_eq!(ar1_regles_velero(&conn), 0, "drapeau non lu : aucune règle");
        assert_eq!(ar1_compte_presence_non_lue(&conn) - avant, 1, "le tableau sous drapeau est compté une fois sous « présence non lue »");
        crate::seeds::seed_security_dashboard(&conn);
        crate::seeds::seed_velero_rule(&conn);
        crate::seeds::seed_security_dashboard(&conn);
        crate::seeds::seed_velero_rule(&conn);
        assert_eq!((ar1_tableaux(&conn, AR1_SECURITE), ar1_regles_velero(&conn)), (1, 1), "contrôle : semés une fois");
        assert_eq!(ar1_compte_presence_non_lue(&conn) - avant, 1, "contrôle : rien de plus compté au nominal");
    }

    fn ar1_evenements_de_demo(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM event WHERE host='demo-host'", [], |r| r.get(0)).expect("événements de démo")
    }

    /// (i) DRAPEAU DE LA DÉMONSTRATION NON LU — rien n'est écrit ; lu : semée une fois. MUTANT : `AR1_DEMO_IS_OK`.
    #[test]
    fn ar1_drapeau_de_demonstration_non_lu_rien_n_est_ecrit() {
        let conn = test_db();
        conn.execute("DELETE FROM meta WHERE key='seeded_demo'", []).expect("drapeau retiré");
        ar1_refuser_la_lecture(&conn, "meta", "key");
        crate::seeds::semer_la_demonstration(&conn);
        ar1_rendre_la_main(&conn);
        assert_eq!(ar1_evenements_de_demo(&conn), 0, "drapeau non lu : aucune donnée de démo");
        crate::seeds::semer_la_demonstration(&conn);
        let semes = ar1_evenements_de_demo(&conn);
        assert!(semes > 0, "contrôle : semée");
        crate::seeds::semer_la_demonstration(&conn);
        assert_eq!(ar1_evenements_de_demo(&conn), semes, "contrôle : drapeau posé, pas de second semis");
    }

    /// (k) LES LIGNES DE JOURNAL, ENTIÈRES, EN SOUS-PROCESSUS : tableau rapide non lu (une ligne, aucune au nominal ni pour
    /// un tableau ABSENT) ; drapeaux non lus (tableau sous drapeau, règle) ; démonstration non lue, puis semée (ligne
    /// d'avant). MUTANTS : `AR1_MAINT_MUET` (retour muet), `AR1_DRAPEAU_IS_OK`, `AR1_DEMO_IS_OK`, `AR1_REPLI_MIN_ID`
    /// (repli sur un autre tableau : l'enfant panique, il ne sort plus en 0).
    #[test]
    fn ar1_lignes_de_journal_entieres_en_sous_processus() {
        const ENFANT: &str = "AR1_ENFANT_JOURNAL";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            let conn = test_db();
            println!("AR1-ENFANT-A-JOUE");
            ar1_tableau_rapide_sans_panneaux(&conn);
            let partout_avant = ar1_panneaux_rapides_partout(&conn);
            ar1_refuser_la_lecture(&conn, "dashboard", "name");
            ensure_rollup_srcip_host_panels(&conn);
            ar1_rendre_la_main(&conn);
            assert_eq!(ar1_panneaux_rapides_partout(&conn), partout_avant, "enfant : tableau non lu, rien n'est écrit sur aucun tableau");
            ensure_rollup_srcip_host_panels(&conn);
            // Tableau ABSENT (install pré-semis) : le silence d'avant.
            conn.execute("DELETE FROM panel WHERE dashboard_id=(SELECT id FROM dashboard WHERE name='Vue d''ensemble (rapide)')", []).expect("panneaux");
            conn.execute("DELETE FROM dashboard WHERE name='Vue d''ensemble (rapide)'", []).expect("tableau rapide retiré");
            ensure_rollup_srcip_host_panels(&conn);
            ar1_sans_securite(&conn);
            ar1_sans_velero(&conn);
            conn.execute("DELETE FROM meta WHERE key='seeded_demo'", []).expect("drapeau retiré");
            ar1_refuser_la_lecture(&conn, "meta", "key");
            crate::seeds::seed_security_dashboard(&conn);
            crate::seeds::seed_velero_rule(&conn);
            crate::seeds::semer_la_demonstration(&conn);
            ar1_rendre_la_main(&conn);
            crate::seeds::seed_security_dashboard(&conn);
            crate::seeds::seed_velero_rule(&conn);
            crate::seeds::semer_la_demonstration(&conn);
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::retention_lue_hors_de_la_passe::ar1_lignes_de_journal_entieres_en_sous_processus"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("AR1-ENFANT-A-JOUE"), "contrôle : l'enfant a vraiment joué : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let lues: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("[seed] panneaux rapides") || l.starts_with("[seed] `seeded_security`") || l.starts_with("[seed] `seeded_velero_rule`") || l.starts_with("[demo] "))
            .collect();
        let refus = "access to meta.key is prohibited";
        let attendues: Vec<String> = vec![
            "[seed] panneaux rapides de « Vue d'ensemble (rapide) » NON vérifiés : le tableau n'a pas pu être lu (access to dashboard.name is prohibited) — rien n'est écrit, retenté au prochain démarrage".to_string(),
            format!("[seed] `seeded_security` NON semé : sa présence n'a pas pu être lue ({refus}) — rien n'est écrit, le semis sera retenté au prochain démarrage"),
            format!("[seed] `seeded_velero_rule` NON semé : sa présence n'a pas pu être lue ({refus}) — rien n'est écrit, le semis sera retenté au prochain démarrage"),
            format!("[demo] données de démo NON semées : le drapeau `seeded_demo` n'a pas pu être lu ({refus}) — rien n'est écrit, le semis sera retenté au prochain démarrage"),
            "[demo] données de démo seedées (PLUME_DEMO=1) — désactive PLUME_DEMO en prod".to_string(),
        ];
        assert_eq!(lues, attendues, "lignes entières, dans l'ordre, aucune au nominal :\n{stderr}");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // TIER FROID (`--features cold_tier`)
    // ---------------------------------------------------------------------------------------------------------------

    #[cfg(feature = "cold_tier")]
    struct Ar1Froid {
        racine: crate::tmp_possede::TmpPossede,
    }

    #[cfg(feature = "cold_tier")]
    impl Ar1Froid {
        /// Pose le tier froid dans l'environnement du processus (les routes lisent `load_config()`).
        fn poser() -> Self {
            let d = crate::tmp_possede::TmpPossede::neuf("ar1-froid");
            std::env::set_var("PLUME_COLD_TIER", "1");
            std::env::set_var("PLUME_COLD_DIR", d.to_string_lossy().to_string());
            Ar1Froid { racine: d }
        }

        fn conf(&self) -> HashMap<String, String> {
            ar1_conf_froide(&self.racine)
        }
    }

    /// La configuration du tier froid SANS toucher l'environnement du processus (fonctions qui prennent `conf`).
    #[cfg(feature = "cold_tier")]
    fn ar1_conf_froide(racine: &crate::tmp_possede::TmpPossede) -> HashMap<String, String> {
        let mut c = HashMap::new();
        c.insert("PLUME_COLD_TIER".to_string(), "1".to_string());
        c.insert("PLUME_COLD_DIR".to_string(), racine.to_string_lossy().to_string());
        c
    }

    #[cfg(feature = "cold_tier")]
    impl Drop for Ar1Froid {
        fn drop(&mut self) {
            std::env::remove_var("PLUME_COLD_TIER");
            std::env::remove_var("PLUME_COLD_DIR");
        }
    }

    /// La cause que `setting_days_lu` rend pour cette forme (sondée, jamais recopiée).
    #[cfg(feature = "cold_tier")]
    fn ar1_moteur(conn: &Connection) -> String {
        crate::setting_days_lu(conn, &HashMap::new(), AR1_CLE, "PLUME_RETENTION_DAYS", 30, 7, 3650).2.expect("prémisse : réglage illisible")
    }

    /// (l) FRONTIÈRE FROIDE D'UN PANNEAU — `retention_days` illisible, fenêtre sous la frontière : aucune frontière rendue,
    /// donc aucun `stats.cold` affirmé sur un repli ; l'horizon dit « non établi ». Contrôle lisible : `stats.cold` posé.
    /// MUTANT : `AR1_BORNE_FROIDE_REPLI`.
    #[cfg(feature = "cold_tier")]
    #[test]
    fn ar1_froid_aucune_frontiere_sur_un_reglage_illisible() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let froid = Ar1Froid::poser();
        let from = now() - 400 * 86_400;
        let sql = "SELECT ts FROM event WHERE ts>=__FROM__";
        for forme in table_declaree!(AR1_ILLISIBLES) {
            let (st, p) = sp_state(&format!("ar1-frontiere-{}", forme.replace('.', "-")));
            ar1_pose(&st.db.lock(), AR1_CLE, ar1_valeur(forme));
            let (cov, frontiere) = crate::handlers::panneau_avoue::horizon_et_frontiere_du_sql(p.as_str(), &froid.conf(), &crate::handlers::panneau_avoue::compile_panneau_avoue(sql, false, from, 0, None).expect("compilé").sql_de_test().to_string(), from, now());
            assert_eq!(frontiere, None, "{forme} : aucune frontière fabriquée");
            assert_eq!(cov["reglage_non_lu"], json!(AR1_CLE), "{forme} : {cov}");
            let pc = crate::handlers::panneau_avoue::compile_panneau_avoue(sql, false, from, 0, None).expect("compilé");
            let v = crate::handlers::panneau_avoue::executer(p.as_str(), &froid.conf(), pc, from).expect("exécuté");
            assert!(v["stats"].get("cold").is_none(), "{forme} : aucune bande froide affirmée : {v}");
        }
        let (st, p) = sp_state("ar1-frontiere-lisible");
        ar1_pose(&st.db.lock(), AR1_CLE, rusqlite::types::Value::Text("30".into()));
        let pc = crate::handlers::panneau_avoue::compile_panneau_avoue(sql, false, from, 0, None).expect("compilé");
        let v = crate::handlers::panneau_avoue::executer(p.as_str(), &froid.conf(), pc, from).expect("exécuté");
        assert!(v["stats"]["cold"].is_object(), "contrôle : réglage lisible, la bande froide est dite : {v}");
    }

    /// (m) RECHERCHE (`GET /api/search`) — `retention_days` illisible : la couverture froide « NON ÉTABLIE » sans
    /// frontière ; lisible et sans jour scellé : aucune note (comportement d'avant). MUTANT : `AR1_SEARCH_REPLI`.
    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn ar1_froid_recherche_sans_frontiere_sur_un_reglage_illisible() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _froid = Ar1Froid::poser();
        let mut q = HashMap::new();
        q.insert("q".to_string(), "source:sshd".to_string());
        for forme in table_declaree!(AR1_ILLISIBLES) {
            let (st, _p) = sp_state(&format!("ar1-recherche-{}", forme.replace('.', "-")));
            ar1_pose(&st.db.lock(), AR1_CLE, ar1_valeur(forme));
            let corps = crate::handlers::search::search(State(st.clone()), Extension(ar1_admin()), Query(q.clone())).await.0;
            assert_eq!(corps["coverage"], crate::handlers::search::couverture_froide_sans_reglage_lu(), "{forme} : {corps}");
        }
        let (st, _p) = sp_state("ar1-recherche-lisible");
        ar1_pose(&st.db.lock(), AR1_CLE, rusqlite::types::Value::Text("30".into()));
        let corps = crate::handlers::search::search(State(st.clone()), Extension(ar1_admin()), Query(q.clone())).await.0;
        assert!(corps.get("coverage").is_none(), "contrôle : aucun jour scellé, aucune note : {corps}");
    }

    /// (n) REPARSE (`POST /api/parsers/reparse`) — `retention_days` illisible, tier froid actif : 503, corps ENTIER
    /// (`error` = la cause nommée, `id`) ; lisible : 200. MUTANT : `AR1_REPARSE_REPLI`.
    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn ar1_froid_reparse_refuse_sur_un_reglage_illisible() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _froid = Ar1Froid::poser();
        for forme in table_declaree!(AR1_ILLISIBLES) {
            let (st, _p) = sp_state(&format!("ar1-reparse-{}", forme.replace('.', "-")));
            let cause = {
                let conn = st.db.lock();
                ar1_pose(&conn, AR1_CLE, ar1_valeur(forme));
                crate::cold_store::reparse_lower_bound(&conn, &load_config(), now(), 0).expect_err("prémisse : la borne est refusée")
            };
            let (code, corps) = ar1_corps(crate::handlers::detection::parser_reparse(State(st.clone()), Extension(ar1_admin()), Json(json!({}))).await).await;
            assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "{forme} : {corps}");
            let mut cles: Vec<&String> = corps.as_object().map(|o| o.keys().collect()).unwrap_or_default();
            cles.sort();
            assert_eq!(cles, vec!["error", "id"], "{forme} : corps entier : {corps}");
            assert_eq!(corps["error"], json!(cause), "{forme} : la cause nommée, jamais le texte du moteur");
            assert!(cause.starts_with("REPARSE REFUSÉ : le réglage de rétention écrit"), "{forme} : {cause}");
            assert!(corps["id"].as_str().unwrap_or("").starts_with("plume-e"), "{forme} : identifiant de corrélation : {corps}");
        }
        let (st, _p) = sp_state("ar1-reparse-lisible");
        ar1_pose(&st.db.lock(), AR1_CLE, rusqlite::types::Value::Text("30".into()));
        let (code, corps) = ar1_corps(crate::handlers::detection::parser_reparse(State(st.clone()), Extension(ar1_admin()), Json(json!({}))).await).await;
        assert_eq!(code, StatusCode::OK, "contrôle : réglage lisible, le reparse a lieu : {corps}");
    }

    /// (o) BANNIÈRE ET SONDE — `retention_days` illisible : la bannière dit « NON LUES » (aucun nombre), la sonde
    /// `cold-aging-plan` refuse de publier un plan, cause entière ; lisible : bannière `Actif`, plan publié. MUTANTS :
    /// `AR1_BANNIERE_REPLI`, `AR1_SONDE_REPLI`.
    #[cfg(feature = "cold_tier")]
    #[test]
    fn ar1_froid_banniere_et_sonde_sans_repli() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let racine_froide = crate::tmp_possede::TmpPossede::neuf("ar1-froid-conf");
        let conf = ar1_conf_froide(&racine_froide);
        for forme in table_declaree!(AR1_ILLISIBLES) {
            let (st, p) = sp_state(&format!("ar1-banniere-{}", forme.replace('.', "-")));
            let conn = st.db.lock();
            ar1_pose(&conn, AR1_CLE, ar1_valeur(forme));
            let banniere = crate::cold_banniere::banniere(crate::cold_banniere::etat(&conn, &conf, p.as_str()));
            let racine = crate::cold_store::cold_root(&conf, p.as_str());
            let attendue = format!(
                "tier froid ACTIF — racine {}, fenêtre chaude et rétention cold NON LUES : le réglage de rétention écrit \
                 (`retention_days`) n'a pas pu être lu, aucune des deux n'est annoncée (jamais le repli env/défaut) et la \
                 passe de vieillissement saute tant qu'il n'est pas réécrit, {}",
                racine.display(),
                crate::cold_banniere::inventaire(&racine, 10_000).phrase()
            );
            assert_eq!(banniere, attendue, "{forme} : bannière entière");
            let moteur = ar1_moteur(&conn);
            drop(conn);
            let plan = crate::cold_store::cold_aging_plan(&conf, p.as_str());
            assert_eq!(
                plan,
                Err(format!(
                    "réglage de rétention `retention_days` écrit NON LU ({moteur}) : la passe de vieillissement saute ce tour, \
                     jamais sur le repli env/défaut — AUCUN plan n'est publié (il décrirait un travail qui n'a pas lieu). \
                     Réécrire le réglage (PUT /api/retention), puis relancer."
                )),
                "{forme} : aucun plan sur le repli"
            );
        }
        let (st, p) = sp_state("ar1-banniere-lisible");
        let conn = st.db.lock();
        ar1_pose(&conn, AR1_CLE, rusqlite::types::Value::Text("30".into()));
        let banniere = crate::cold_banniere::banniere(crate::cold_banniere::etat(&conn, &conf, p.as_str()));
        assert!(banniere.contains("fenêtre chaude ") && banniere.contains(" j (au-delà"), "contrôle : bannière Actif : {banniere}");
        drop(conn);
        assert!(crate::cold_store::cold_aging_plan(&conf, p.as_str()).is_ok(), "contrôle : plan publié");
    }

    /// (p) LA LIGNE `[reparse] WARN`, ENTIÈRE, EN SOUS-PROCESSUS — cause du moteur sondée dans l'enfant ; aucune ligne pour
    /// un réglage lisible. MUTANT : `AR1_REPARSE_MUET`.
    #[cfg(feature = "cold_tier")]
    #[test]
    fn ar1_froid_ligne_du_reparse_refuse_en_sous_processus() {
        const ENFANT: &str = "AR1_ENFANT_REPARSE";
        const MOTEUR: &str = "AR1-MOTEUR:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            let racine_froide = crate::tmp_possede::TmpPossede::neuf("ar1-froid-enfant");
            let conf = ar1_conf_froide(&racine_froide);
            let conn = test_db();
            ar1_pose(&conn, AR1_CLE, rusqlite::types::Value::Text("30".into()));
            assert!(crate::cold_store::reparse_lower_bound(&conn, &conf, now(), 0).is_ok(), "enfant : lisible, borne rendue");
            ar1_pose(&conn, AR1_CLE, ar1_valeur("BLOB"));
            println!("{MOTEUR}{}", ar1_moteur(&conn));
            assert!(crate::cold_store::reparse_lower_bound(&conn, &conf, now(), 0).is_err(), "enfant : illisible, refus");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::retention_lue_hors_de_la_passe::ar1_froid_ligne_du_reparse_refuse_en_sous_processus"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let moteur = stdout.lines().find_map(|l| l.split_once(MOTEUR).map(|(_, r)| r)).expect("cause du moteur sondée dans l'enfant").to_string();
        let lues: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[reparse] ")).collect();
        assert_eq!(
            lues,
            vec![format!("[reparse] WARN reparse REFUSÉ : le réglage `retention_days` écrit n'a pas pu être lu ({moteur}) — aucun event n'est lu ni modifié")],
            "une ligne entière, aucune pour le réglage lisible :\n{stderr}"
        );
    }
}
