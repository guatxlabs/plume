// =====================================================================================
// `P10.20-l` (tranche de la vague AL) — L'OVERRIDE ADMIN DES EXCLUSIONS D'AFFICHAGE confondait « aucune ligne » et
// « lecture qui n'a pas eu lieu ».
//
// LE DÉFAUT, MESURÉ SUR 831785a9 AVANT LE CORRECTIF. `excl_display_csv` (`dashboards.rs`) lisait l'override par
// `.ok().map(trim).unwrap_or_else(cfg env)` : une lecture ratée retombait EN SILENCE sur la valeur du déploiement
// (les variables d'environnement des exclusions opérateur et self). Ses quatre consommateurs en faisaient un fait :
//   * `excl_clauses_refresh` (boot et après chaque édition) chargeait les clauses de l'environnement dans le cache des
//     panneaux, à la place de celles de l'administrateur ;
//   * `apply_display_excl_edit` inscrivait au registre d'audit la valeur de l'environnement comme ANCIENNE valeur
//     (lecture avant l'écriture) ou comme NOUVELLE (relecture après), et validait ;
//   * `daemon_excl_registry` servait à l'exploitant la valeur de l'environnement comme « valeur active ».
//
// LE CORRECTIF. `excl_display_csv` rend `rusqlite::Result<String>` par `.optional()` : ligne lue = l'override ; ligne
// absente = l'environnement (comme avant, à l'octet) ; lecture ratée = `Err`. `ExclClauses::resolve` propage.
//   * Rafraîchissement (boot) : `Err` = cache d'avant GARDÉ (au boot : les clauses de l'environnement) + ligne WARN.
//   * Édition : les lectures se font DANS la transaction ; non lue = `ROLLBACK`, 503
//     `CAUSE_EXCLUSION_D_AFFICHAGE_INCHANGEE_NON_LUE`, rien d'écrit, ligne WARN avec le champ. Les clauses posées dans le
//     cache après le `COMMIT` sont celles relues dans la transaction (plus de relecture après validation).
//   * Registre : `value` = `PHRASE_OVERRIDE_D_AFFICHAGE_NON_LU`, `detail.override_non_lu` = la même phrase, aucune
//     clause servie, `editable: false` ; cause du moteur au journal seul.
//
// LES PANNES ÉPROUVÉES : autorisateur SQLite qui refuse la lecture de `setting.value` (toujours, seulement avant
// l'écriture du geste, seulement après elle, seulement après le `COMMIT`) ; valeur d'override en BLOB (forme
// inconnue) sur UNE seule des deux lignes, pour que chaque lecture se témoigne seule. Lignes de journal lues sur le
// stderr d'un sous-processus, ENTIÈRES, par égalité ; corps de la route comparés EN ENTIER.
//
// MUTANTS (posés le temps de la preuve sous `cfg!(test)` par la variable de mutation, retirés avant le commit), chacun vu ROUGE :
// `AL2_CSV_ABSENT` (la forme d'avant : lecture ratée = absence), `AL2_REFRESH_REPLI` (le cache prend l'environnement),
// `AL2_REFRESH_SANS_JOURNAL`, `AL2_EDIT_OLD_REPLI`, `AL2_EDIT_NEW_REPLI` (l'environnement pris pour l'ancienne ou la
// nouvelle valeur), `AL2_EDIT_SANS_ROLLBACK`, `AL2_EDIT_SANS_JOURNAL`, `AL2_EDIT_CAUSE_COMMIT` (la lecture ratée servie
// sous la cause du COMMIT refusé), `AL2_PUT_SANS_CACHE` (le cache non posé après validation), `AL2_REG_REPLI`,
// `AL2_REG_SANS_DETAIL`, `AL2_REG_SANS_JOURNAL`. Puis, après le vérificateur : `V_RES_OP`, `V_RES_SELF`, `V_EDIT_OP`,
// `V_EDIT_SELF` (une seule lecture retombe sur l'environnement), `V_EDIT_NEW_SELF`, `V_EDIT_CLAUSES_SELF`,
// `V_PUT_REFRESH` (le rafraîchissement remis après la validation), `V_REG_EDITABLE` (l'entrée non lue reste éditable).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la console (`web/suppressions.js`) n'est pas jouée — elle peint `value` tel quel,
// la cause neuve en refus nommé, et n'ouvre l'édition que sous `editable` ; le registre est plateforme (base `st.db`),
// aucun second tenant n'est en jeu.
// =====================================================================================
mod exclusions_d_affichage_lues_en_trois_issues {
    use super::*;
    use crate::handlers::admin_ui::{
        apply_display_excl_edit, daemon_excl_registry, suppressions_put, CAUSE_EXCLUSION_D_AFFICHAGE_INCHANGEE_NON_LUE,
        PHRASE_OVERRIDE_D_AFFICHAGE_NON_LU,
    };
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const AL2_OVERRIDE_OP: &str = "198.51.100.4";
    const AL2_OVERRIDE_SELF: &str = "al2.example.org";
    const AL2_ENV_OP: &str = "192.0.2.10";
    const AL2_NEUF: &str = "203.0.113.9";
    const AL2_NEUF_SELF: &str = "neuf.al2.example.org";
    const AL2_ENV_SELF: &str = "env.al2.example.net";
    const AL2_CLE_ENV_OP: &str = "PLUME_OPERATOR_IPS";
    const AL2_CLE_ENV_SELF: &str = "PLUME_SELF_HOSTS";

    #[derive(Clone, Copy)]
    enum Quand {
        Toujours,
        AvantLEcriture,
        ApresLEcriture,
        ApresLeCommit,
    }

    /// Refuse la lecture de `setting.value` sur cette connexion : toujours, seulement tant que le geste n'a pas écrit
    /// `setting` (INSERT ou DELETE préparé), seulement après, ou seulement après le `COMMIT` préparé (rusqlite rend
    /// `COMMIT`/`END` sous `TransactionOperation::Unknown` : il ne nomme que BEGIN, RELEASE et ROLLBACK).
    fn al2_refuser(conn: &Connection, quand: Quand) {
        let mut ecrit = false;
        let mut valide = false;
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } | AuthAction::Delete { table_name } if table_name == "setting" => {
                ecrit = true;
                Authorization::Allow
            }
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => {
                valide = true;
                Authorization::Allow
            }
            AuthAction::Read { table_name, column_name } if table_name == "setting" && column_name == "value" => {
                let refuse = match quand {
                    Quand::Toujours => true,
                    Quand::AvantLEcriture => !ecrit,
                    Quand::ApresLEcriture => ecrit,
                    Quand::ApresLeCommit => valide,
                };
                if refuse { Authorization::Deny } else { Authorization::Allow }
            }
            _ => Authorization::Allow,
        }));
    }

    fn al2_lever(conn: &Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn al2_override(conn: &Connection, cle: &str, valeur: &str) {
        conn.execute(
            "INSERT INTO setting(scope,key,value,updated,updated_by) VALUES('global',?1,?2,0,'al2') \
             ON CONFLICT(scope,key) DO UPDATE SET value=?2",
            params![cle, valeur],
        )
        .expect("fixture : override posé");
    }

    fn al2_entier(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn al2_texte(conn: &Connection, sql: &str) -> String {
        conn.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn al2_reponse(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = if b.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()))
        };
        (statut, corps)
    }

    /// L'entrée ENTIÈRE du registre qu'on attend pour une exclusion d'affichage, lue ou non lue (non lue : pas
    /// éditable).
    fn al2_entree_attendue(nom: &str, valeur: Option<&str>) -> Value {
        let (label, scope, champ, source, edit_key) = if nom == "operator_excl" {
            (
                "Exclusion opérateur (__OPERATOR_EXCL__)",
                "panneaux menace externe (web top-clients/4xx, Cloudflare 25-29, banpass)",
                "src_ip",
                "ExclClauses / PLUME_OPERATOR_IPS (override setting excl_operator_ips)",
                "operator",
            )
        } else {
            (
                "Exclusion self/vhost (__SELF_EXCL__)",
                "mêmes panneaux menace externe (vhost self)",
                "vhost",
                "ExclClauses / PLUME_SELF_HOSTS (override setting excl_self_hosts)",
                "self",
            )
        };
        let (value, detail) = match valeur {
            Some(csv) => {
                let (sql, soql) = ExclClauses::build(champ, csv);
                (json!(csv), json!({ "field": champ, "sql": sql, "soql": soql, "substituted_in": "la compilation des panneaux", "never_in": "les règles de détection" }))
            }
            None => (
                json!(PHRASE_OVERRIDE_D_AFFICHAGE_NON_LU),
                json!({ "field": champ, "override_non_lu": PHRASE_OVERRIDE_D_AFFICHAGE_NON_LU, "substituted_in": "la compilation des panneaux", "never_in": "les règles de détection" }),
            ),
        };
        json!({
            "name": nom, "label": label, "scope": scope, "type": "display-only", "value": value, "detail": detail,
            "source": source, "editable": valeur.is_some(), "edit_key": edit_key, "guarantee": "collecte/règles NON modifiées",
        })
    }

    fn al2_entree(daemon: &Value, nom: &str) -> Value {
        daemon
            .as_array()
            .unwrap_or_else(|| panic!("registre : tableau : {daemon}"))
            .iter()
            .find(|e| e["name"] == nom)
            .cloned()
            .unwrap_or_else(|| panic!("registre : entrée {nom} : {daemon}"))
    }

    /// TROIS ISSUES AU SITE MÊME : override lu (taillé), ligne absente = l'environnement, lecture refusée = `Err`, valeur
    /// d'une forme inconnue (BLOB) = `Err` ; `ExclClauses::resolve` propage. MUTATION : `AL2_CSV_ABSENT`.
    #[test]
    fn al2_le_csv_de_l_override_a_trois_issues() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // `cfg` lit l'environnement
        let conn = test_db();
        let conf: HashMap<String, String> = [(AL2_CLE_ENV_OP.to_string(), AL2_ENV_OP.to_string())].into_iter().collect();
        let lire = |conn: &Connection| excl_display_csv(conn, &conf, EXCL_OP_SETTING, AL2_CLE_ENV_OP, PLUME_OPERATOR_IPS_DEFAULT);
        assert_eq!(lire(&conn).expect("absente : lue"), AL2_ENV_OP, "ligne absente : le repli sur l'environnement, comme avant");
        al2_override(&conn, EXCL_OP_SETTING, &format!("  {AL2_OVERRIDE_OP} "));
        assert_eq!(lire(&conn).expect("présente : lue"), AL2_OVERRIDE_OP, "override lu, taillé");
        al2_refuser(&conn, Quand::Toujours);
        assert!(lire(&conn).is_err(), "lecture refusée : `Err`, jamais l'environnement : {:?}", lire(&conn));
        assert!(ExclClauses::resolve(&conn, &conf).is_err(), "resolve propage la lecture refusée");
        al2_lever(&conn);
        conn.execute("UPDATE setting SET value=X'00FF' WHERE scope='global' AND key=?1", params![EXCL_OP_SETTING]).expect("fixture : BLOB");
        assert!(lire(&conn).is_err(), "valeur d'une forme inconnue : `Err`, jamais l'environnement : {:?}", lire(&conn));
    }

    /// JOUÉ DANS UN SOUS-PROCESSUS (le cache des panneaux est global au processus, et le stderr est lu) : le
    /// rafraîchissement du boot, l'édition et le registre, chacun sous lecture refusée puis rétablie.
    /// MUTATIONS : toutes celles de l'en-tête sauf `AL2_CSV_ABSENT` seule (qu'il rougit aussi).
    #[tokio::test]
    async fn al2_cache_edition_et_registre_n_inventent_jamais_le_repli() {
        const ENFANT: &str = "AL2_ENFANT_JOURNAL";
        const PHASE: &str = "AL2-PHASE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les gestionnaires lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _tmp) = sp_state("al2-exclusions");
            let db = st.db.clone();
            let conf: HashMap<String, String> = HashMap::new();
            let adm = sp_au("adm", "admin");
            let cache_op = || excl_clauses_cell().read().op_sql.clone();
            let mut sortie = serde_json::Map::new();
            {
                let conn = db.lock();
                al2_override(&conn, EXCL_OP_SETTING, AL2_OVERRIDE_OP);
                al2_override(&conn, EXCL_SELF_SETTING, AL2_OVERRIDE_SELF);
                al2_refuser(&conn, Quand::Toujours);
                let cause = conn
                    .query_row("SELECT value FROM setting WHERE scope='global' AND key='excl_operator_ips'", [], |_| Ok(()))
                    .expect_err("fixture : lecture refusée")
                    .to_string();
                sortie.insert("cause".into(), json!(cause));
                al2_lever(&conn);
            }

            // ---- Rafraîchissement du BOOT : override présent mais illisible -> le cache de l'environnement est gardé.
            eprintln!("{PHASE}boot");
            {
                let conn = db.lock();
                al2_refuser(&conn, Quand::Toujours);
                excl_clauses_refresh(&conn, &conf);
                al2_lever(&conn);
            }
            sortie.insert("boot".into(), json!(cache_op()));
            eprintln!("{PHASE}lu");
            excl_clauses_refresh(&db.lock(), &conf);
            sortie.insert("lu".into(), json!(cache_op()));
            eprintln!("{PHASE}garde");
            {
                let conn = db.lock();
                al2_refuser(&conn, Quand::Toujours);
                excl_clauses_refresh(&conn, &conf);
                al2_lever(&conn);
            }
            sortie.insert("garde".into(), json!(cache_op()));

            // ---- Édition : lecture refusée avant, puis après l'écriture ; set et clear.
            let etat = |conn: &Connection| -> Value {
                json!([
                    conn.is_autocommit(),
                    al2_texte(conn, "SELECT value FROM setting WHERE scope='global' AND key='excl_operator_ips'"),
                    al2_entier(conn, "SELECT COUNT(*) FROM ledger WHERE kind LIKE 'config.suppression.%'"),
                    al2_entier(conn, "SELECT COUNT(*) FROM event WHERE source='plume-config' AND message LIKE '%exclusion d''affichage%'"),
                ])
            };
            for (nom, action, quand) in [
                ("edit_avant", "set_operator_excl", Quand::AvantLEcriture),
                ("edit_apres", "set_operator_excl", Quand::ApresLEcriture),
                ("clear_apres", "clear_operator_excl", Quand::ApresLEcriture),
            ] {
                eprintln!("{PHASE}{nom}");
                let conn = db.lock();
                al2_refuser(&conn, quand);
                let r = apply_display_excl_edit(&conn, &conf, action, AL2_NEUF, "adm");
                al2_lever(&conn);
                let issue = match r {
                    Ok((field, old, new, _)) => json!({ "ok": [field, old, new] }),
                    Err((code, msg)) => json!({ "err": [code.as_u16(), msg] }),
                };
                sortie.insert(nom.into(), json!([issue, etat(&conn)]));
                if !conn.is_autocommit() {
                    conn.execute_batch("ROLLBACK").expect("nettoyage : transaction laissée ouverte");
                }
            }
            sortie.insert("cache_apres_refus".into(), json!(cache_op()));

            // ---- Édition levée, par le gestionnaire : 200, le cache porte les clauses relues dans la transaction.
            eprintln!("{PHASE}edit_ok");
            let r = al2_reponse(
                suppressions_put(State(st.clone()), Extension(adm.clone()), Json(json!({ "action": "set_operator_excl", "value": AL2_NEUF }))).await,
            )
            .await;
            let conn = db.lock();
            sortie.insert("edit_ok".into(), json!([r, etat(&conn), cache_op(),
                al2_texte(&conn, "SELECT detail FROM ledger WHERE kind='config.suppression.operator' ORDER BY id DESC LIMIT 1")]));

            // ---- Registre : lecture refusée puis rétablie.
            eprintln!("{PHASE}registre");
            al2_refuser(&conn, Quand::Toujours);
            let reg: Vec<Value> = daemon_excl_registry(&conn, &conf).iter().map(|e| e.to_json()).collect();
            al2_lever(&conn);
            sortie.insert("registre".into(), json!(reg));
            eprintln!("{PHASE}registre_lu");
            let reg: Vec<Value> = daemon_excl_registry(&conn, &conf).iter().map(|e| e.to_json()).collect();
            sortie.insert("registre_lu".into(), json!(reg));
            eprintln!("{PHASE}fin");
            println!("AL2-SORTIE:{}", Value::Object(sortie));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::exclusions_d_affichage_lues_en_trois_issues::al2_cache_edition_et_registre_n_inventent_jamais_le_repli"])
            .env(ENFANT, "1")
            .env(AL2_CLE_ENV_OP, AL2_ENV_OP)
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let reste = stdout.split_once("AL2-SORTIE:").unwrap_or_else(|| panic!("contrôle : sortie : {stdout}")).1;
        let s: Value = serde_json::from_str(reste.lines().next().unwrap_or("")).unwrap_or_else(|e| panic!("contrôle : JSON ({e}) : {stdout}"));
        let cause = s["cause"].as_str().unwrap_or_else(|| panic!("contrôle : cause : {s}")).to_string();
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[exclusion]") || l.starts_with("[suppressions]")).map(str::to_string).collect()
        };
        let aucune: Vec<String> = Vec::new();
        let op_sql = |csv: &str| ExclClauses::build("src_ip", csv).0;
        let ligne_du_cache = format!("[exclusion] WARN override d'affichage NON lu : les panneaux gardent les clauses d'avant, jamais le repli sur l'environnement ({cause})");

        // ---- Cache : boot = l'environnement gardé ; lu = l'override ; refusé ensuite = l'override GARDÉ, pas l'env.
        assert_eq!(s["boot"], json!(op_sql(AL2_ENV_OP)), "boot, override illisible : le cache de l'environnement est gardé");
        assert_eq!(phase("boot"), [ligne_du_cache.clone()], "boot : la ligne ENTIÈRE");
        assert_eq!(s["lu"], json!(op_sql(AL2_OVERRIDE_OP)), "override lu : le cache le porte");
        assert_eq!(phase("lu"), aucune, "lecture réussie : aucune ligne");
        assert_eq!(s["garde"], json!(op_sql(AL2_OVERRIDE_OP)), "override illisible : le cache d'avant est GARDÉ, jamais l'environnement");
        assert_eq!(phase("garde"), [ligne_du_cache], "rafraîchissement refusé : la ligne ENTIÈRE");

        // ---- Édition refusée : 503 nommé, transaction fermée, rien d'écrit, aucune trace, ligne ENTIÈRE.
        let refus = json!({ "err": [503, CAUSE_EXCLUSION_D_AFFICHAGE_INCHANGEE_NON_LUE] });
        let rien = json!([true, AL2_OVERRIDE_OP, 0, 0]);
        let ligne_d_edition = format!("[suppressions] WARN exclusion d'affichage operator NON lue : transaction annulée, aucune modification ({cause})");
        assert_eq!(s["edit_avant"], json!([refus, rien]), "ancienne valeur non lue : 503 nommé, rien d'écrit ni tracé");
        assert_eq!(phase("edit_avant"), [ligne_d_edition.clone()]);
        assert_eq!(s["edit_apres"], json!([refus, rien]), "nouvelle valeur non relue : 503 nommé, l'écriture annulée");
        assert_eq!(phase("edit_apres"), [ligne_d_edition.clone()]);
        assert_eq!(s["clear_apres"], json!([refus, rien]), "effacement non relu : 503 nommé, la ligne reste");
        assert_eq!(phase("clear_apres"), [ligne_d_edition]);
        assert_eq!(s["cache_apres_refus"], json!(op_sql(AL2_OVERRIDE_OP)), "aucune édition refusée ne touche au cache");

        // ---- Édition levée : 200 à l'octet, une trace avec l'override pour ancienne valeur, le cache posé.
        let ok = &s["edit_ok"];
        assert_eq!(ok[0], json!([200, { "ok": true, "field": "operator", "old": AL2_OVERRIDE_OP, "new": AL2_NEUF }]), "édition levée : {ok}");
        assert_eq!(ok[1], json!([true, AL2_NEUF, 1, 1]), "une trace, un événement, la valeur écrite : {ok}");
        assert_eq!(ok[2], json!(op_sql(AL2_NEUF)), "le cache porte les clauses relues dans la transaction : {ok}");
        assert_eq!(ok[3], json!(format!("exclusion affichage operator: [{AL2_OVERRIDE_OP}]->[{AL2_NEUF}] par adm")), "la trace porte l'override, jamais l'environnement");
        assert_eq!(phase("edit_ok"), aucune);

        // ---- Registre : non lu = la phrase fixe, sans clause ; lu = la valeur et ses clauses.
        let reg = &s["registre"];
        assert_eq!(al2_entree(reg, "operator_excl"), al2_entree_attendue("operator_excl", None), "registre, override non lu");
        assert_eq!(al2_entree(reg, "self_excl"), al2_entree_attendue("self_excl", None), "registre, override non lu");
        assert_eq!(phase("registre"), [
            format!("[suppressions] WARN override d'affichage operator_excl NON lu pour le registre ({cause})"),
            format!("[suppressions] WARN override d'affichage self_excl NON lu pour le registre ({cause})"),
        ]);
        let reg = &s["registre_lu"];
        assert_eq!(al2_entree(reg, "operator_excl"), al2_entree_attendue("operator_excl", Some(AL2_NEUF)), "registre lu");
        assert_eq!(al2_entree(reg, "self_excl"), al2_entree_attendue("self_excl", Some(AL2_OVERRIDE_SELF)), "registre lu");
        assert_eq!(phase("registre_lu"), aucune);
    }

    /// PAR LE ROUTEUR RÉEL, jeton administrateur (le seul rôle admis sur `/api/suppressions`) : sous lecture refusée de
    /// l'override, GET sert les deux entrées ENTIÈRES avec la phrase fixe, PUT rend le 503 nommé `{error, id}` et
    /// n'écrit rien ; rétablie, GET sert l'override et ses clauses. MUTATIONS : `AL2_REG_REPLI`, `AL2_REG_SANS_DETAIL`,
    /// `AL2_CSV_ABSENT`, `AL2_EDIT_CAUSE_COMMIT`.
    #[tokio::test]
    async fn al2_la_route_sert_l_aveu_et_refuse_l_edition() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _p) = router_test_state("al2-routeur");
        let db = st.db.clone();
        {
            let conn = db.lock();
            al2_override(&conn, EXCL_OP_SETTING, AL2_OVERRIDE_OP);
            al2_override(&conn, EXCL_SELF_SETTING, AL2_OVERRIDE_SELF);
        }
        let addr = router_serve(st).await;
        let admin = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("root:rootpw1234567"));
        let envoyer = |methode: &'static str, corps: String| {
            let admin = admin.clone();
            async move {
                let (code, brut) = router_probe_envoi(addr, methode, "/api/suppressions", Some(&admin), &[("Content-Type", "application/json")], &corps).await;
                let corps = brut.split_once("\r\n\r\n").map(|(_, c)| c.to_string()).unwrap_or_default();
                let objet = match (corps.find('{'), corps.rfind('}')) {
                    (Some(a), Some(b)) if a < b => corps[a..=b].to_string(),
                    _ => corps.clone(),
                };
                (code, serde_json::from_str::<Value>(&objet).unwrap_or(Value::String(corps)))
            }
        };
        al2_refuser(&db.lock(), Quand::Toujours);
        let (code, corps) = envoyer("GET", String::new()).await;
        assert_eq!(code, 200, "GET sous lecture refusée : {corps}");
        assert_eq!(al2_entree(&corps["daemon"], "operator_excl"), al2_entree_attendue("operator_excl", None), "route : opérateur non lu");
        assert_eq!(al2_entree(&corps["daemon"], "self_excl"), al2_entree_attendue("self_excl", None), "route : self non lu");
        let (code, corps) = envoyer("PUT", json!({ "action": "set_operator_excl", "value": AL2_NEUF }).to_string()).await;
        assert_eq!(code, 503, "PUT sous lecture refusée : {corps}");
        let o = corps.as_object().unwrap_or_else(|| panic!("PUT : corps JSON objet : {corps}"));
        let mut cles: Vec<&str> = o.keys().map(String::as_str).collect();
        cles.sort_unstable();
        assert_eq!(cles, ["error", "id"], "PUT : ensemble exact des clés : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_EXCLUSION_D_AFFICHAGE_INCHANGEE_NON_LUE), "PUT : la phrase seule : {corps}");
        assert!(corps["id"].as_str().is_some_and(|s| s.starts_with("plume-e")), "PUT : identifiant : {corps}");
        al2_lever(&db.lock());
        {
            let conn = db.lock();
            assert_eq!(al2_texte(&conn, "SELECT value FROM setting WHERE scope='global' AND key='excl_operator_ips'"), AL2_OVERRIDE_OP, "rien d'écrit");
            assert_eq!(al2_entier(&conn, "SELECT COUNT(*) FROM ledger WHERE kind LIKE 'config.suppression.%'"), 0, "aucune trace");
        }
        let (code, corps) = envoyer("GET", String::new()).await;
        assert_eq!(code, 200, "GET rétabli : {corps}");
        assert_eq!(al2_entree(&corps["daemon"], "operator_excl"), al2_entree_attendue("operator_excl", Some(AL2_OVERRIDE_OP)), "route : opérateur lu");
        assert_eq!(al2_entree(&corps["daemon"], "self_excl"), al2_entree_attendue("self_excl", Some(AL2_OVERRIDE_SELF)), "route : self lu");
    }

    /// Une SEULE ligne d'override illisible (sa valeur en BLOB, forme inconnue), l'autre lisible : la panne propre à une
    /// ligne, que l'autorisateur (colonne entière) ne sait pas poser.
    fn al2_une_ligne_illisible(conn: &Connection, illisible: &str) {
        al2_override(conn, EXCL_OP_SETTING, AL2_OVERRIDE_OP);
        al2_override(conn, EXCL_SELF_SETTING, AL2_OVERRIDE_SELF);
        conn.execute("UPDATE setting SET value=X'00FF' WHERE scope='global' AND key=?1", params![illisible]).expect("fixture : BLOB");
    }

    /// L'état que l'édition refusée ne doit pas changer : transaction fermée, les deux lignes (type et octets), aucune
    /// trace ni événement.
    fn al2_etat_des_deux_lignes(conn: &Connection) -> Value {
        json!([
            conn.is_autocommit(),
            al2_texte(conn, "SELECT typeof(value) || ':' || hex(value) FROM setting WHERE scope='global' AND key='excl_operator_ips'"),
            al2_texte(conn, "SELECT typeof(value) || ':' || hex(value) FROM setting WHERE scope='global' AND key='excl_self_hosts'"),
            al2_entier(conn, "SELECT COUNT(*) FROM ledger WHERE kind LIKE 'config.suppression.%'"),
            al2_entier(conn, "SELECT COUNT(*) FROM event WHERE source='plume-config' AND message LIKE '%exclusion d''affichage%'"),
        ])
    }

    fn al2_hex_texte(v: &str) -> String {
        format!("text:{}", v.bytes().map(|b| format!("{b:02X}")).collect::<String>())
    }

    /// CHAQUE LECTURE SE TÉMOIGNE SEULE : la ligne opérateur illisible SEULE, puis la ligne self SEULE. `resolve` rend
    /// `Err` dans les deux cas (jamais l'environnement pour la ligne en panne) ; l'édition de l'AUTRE exclusion, dont la
    /// lecture d'avant l'écriture réussit, bute sur la relecture de la ligne en panne dans la transaction : 503 nommé,
    /// rien d'écrit. Contrôle : la ligne saine se lit. MUTATIONS : `V_RES_OP`, `V_RES_SELF` (une lecture de `resolve`
    /// retombe sur l'environnement), `V_EDIT_OP`, `V_EDIT_SELF` (une relecture de l'édition retombe sur lui).
    #[test]
    fn al2_chaque_lecture_se_temoigne_seule() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // `cfg` lit l'environnement
        let conn = test_db();
        let conf: HashMap<String, String> = [(AL2_CLE_ENV_OP, AL2_ENV_OP), (AL2_CLE_ENV_SELF, AL2_ENV_SELF)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let refus: Result<(String, String, String), (u16, String)> = Err((503, CAUSE_EXCLUSION_D_AFFICHAGE_INCHANGEE_NON_LUE.to_string()));
        let editer = |conn: &Connection, action: &str, valeur: &str| {
            apply_display_excl_edit(conn, &conf, action, valeur, "adm")
                .map(|(field, old, new, _)| (field.to_string(), old, new))
                .map_err(|(code, msg)| (code.as_u16(), msg))
        };

        // ---- La ligne OPÉRATEUR seule illisible.
        al2_une_ligne_illisible(&conn, EXCL_OP_SETTING);
        let r = ExclClauses::resolve(&conn, &conf);
        assert!(r.is_err(), "opérateur seul illisible : resolve rend Err, jamais l'environnement : {r:?}");
        assert_eq!(
            excl_display_csv(&conn, &conf, EXCL_SELF_SETTING, AL2_CLE_ENV_SELF, PLUME_SELF_HOSTS_DEFAULT).expect("contrôle : self se lit"),
            AL2_OVERRIDE_SELF,
            "contrôle : la panne est propre à la ligne opérateur"
        );
        let avant = json!([true, "blob:00FF", al2_hex_texte(AL2_OVERRIDE_SELF), 0, 0]);
        assert_eq!(al2_etat_des_deux_lignes(&conn), avant, "fixture");
        assert_eq!(editer(&conn, "set_self_excl", AL2_NEUF_SELF), refus, "édition de self, opérateur non relu : 503 nommé");
        assert_eq!(al2_etat_des_deux_lignes(&conn), avant, "édition de self refusée : rien d'écrit ni tracé, transaction fermée");

        // ---- La ligne SELF seule illisible.
        al2_une_ligne_illisible(&conn, EXCL_SELF_SETTING);
        let r = ExclClauses::resolve(&conn, &conf);
        assert!(r.is_err(), "self seul illisible : resolve rend Err, jamais l'environnement : {r:?}");
        assert_eq!(
            excl_display_csv(&conn, &conf, EXCL_OP_SETTING, AL2_CLE_ENV_OP, PLUME_OPERATOR_IPS_DEFAULT).expect("contrôle : l'opérateur se lit"),
            AL2_OVERRIDE_OP,
            "contrôle : la panne est propre à la ligne self"
        );
        let avant = json!([true, al2_hex_texte(AL2_OVERRIDE_OP), "blob:00FF", 0, 0]);
        assert_eq!(al2_etat_des_deux_lignes(&conn), avant, "fixture");
        assert_eq!(editer(&conn, "set_operator_excl", AL2_NEUF), refus, "édition de l'opérateur, self non relu : 503 nommé");
        assert_eq!(al2_etat_des_deux_lignes(&conn), avant, "édition de l'opérateur refusée : rien d'écrit ni tracé, transaction fermée");

        // ---- Contrôle : les deux lisibles, les deux éditions passent.
        al2_override(&conn, EXCL_SELF_SETTING, AL2_OVERRIDE_SELF);
        assert_eq!(editer(&conn, "set_self_excl", AL2_NEUF_SELF), Ok(("self".to_string(), AL2_OVERRIDE_SELF.to_string(), AL2_NEUF_SELF.to_string())), "contrôle");
        assert_eq!(editer(&conn, "set_operator_excl", AL2_NEUF), Ok(("operator".to_string(), AL2_OVERRIDE_OP.to_string(), AL2_NEUF.to_string())), "contrôle");
    }

    /// JOUÉ DANS UN SOUS-PROCESSUS (cache global, stderr lu) : PAR LE GESTIONNAIRE, la lecture de `setting` refusée
    /// APRÈS le `COMMIT`. Le 200 et la trace d'audit portent la nouvelle valeur de l'exclusion éditée (self, puis
    /// opérateur) ; le cache porte les clauses relues DANS la transaction, les deux exclusions (celle qu'on n'édite pas
    /// comprise) ; aucune ligne de journal (aucune relecture après validation). Contrôle : l'autorisateur refuse bien
    /// après le geste. MUTATIONS : `V_EDIT_NEW_SELF` (le « new » de self pris sur l'opérateur), `V_EDIT_CLAUSES_SELF`
    /// (clauses posées sans le self), `V_PUT_REFRESH` (le rafraîchissement remis après la validation : il bute, garde le
    /// cache d'avant et le dit).
    #[tokio::test]
    async fn al2_la_route_pose_les_clauses_relues_dans_la_transaction() {
        const ENFANT: &str = "AL2_ENFANT_APRES_COMMIT";
        const PHASE: &str = "AL2-PHASE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les gestionnaires lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _tmp) = sp_state("al2-apres-commit");
            let db = st.db.clone();
            let conf: HashMap<String, String> = HashMap::new();
            let adm = sp_au("adm", "admin");
            let cache = || {
                let c = excl_clauses_cell().read();
                json!([c.op_sql, c.op_soql, c.self_sql, c.self_soql])
            };
            let mut sortie = serde_json::Map::new();
            {
                let conn = db.lock();
                al2_override(&conn, EXCL_OP_SETTING, AL2_OVERRIDE_OP);
                al2_override(&conn, EXCL_SELF_SETTING, AL2_OVERRIDE_SELF);
                excl_clauses_refresh(&conn, &conf);
            }
            sortie.insert("depart".into(), cache());
            for (nom, action, valeur, kind) in [
                ("put_self", "set_self_excl", AL2_NEUF_SELF, "config.suppression.self"),
                ("put_op", "set_operator_excl", AL2_NEUF, "config.suppression.operator"),
            ] {
                eprintln!("{PHASE}{nom}");
                al2_refuser(&db.lock(), Quand::ApresLeCommit);
                let r = al2_reponse(
                    suppressions_put(State(st.clone()), Extension(adm.clone()), Json(json!({ "action": action, "value": valeur }))).await,
                )
                .await;
                let conn = db.lock();
                let arme = conn
                    .query_row("SELECT value FROM setting WHERE scope='global' AND key='excl_self_hosts'", [], |_| Ok(()))
                    .is_err();
                al2_lever(&conn);
                let trace = al2_texte(&conn, &format!("SELECT detail FROM ledger WHERE kind='{kind}' ORDER BY id DESC LIMIT 1"));
                sortie.insert(nom.into(), json!([r, cache(), trace, arme]));
            }
            eprintln!("{PHASE}fin");
            println!("AL2-SORTIE:{}", Value::Object(sortie));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::exclusions_d_affichage_lues_en_trois_issues::al2_la_route_pose_les_clauses_relues_dans_la_transaction"])
            .env(ENFANT, "1")
            .env(AL2_CLE_ENV_OP, AL2_ENV_OP)
            .env(AL2_CLE_ENV_SELF, AL2_ENV_SELF)
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let reste = stdout.split_once("AL2-SORTIE:").unwrap_or_else(|| panic!("contrôle : sortie : {stdout}")).1;
        let s: Value = serde_json::from_str(reste.lines().next().unwrap_or("")).unwrap_or_else(|e| panic!("contrôle : JSON ({e}) : {stdout}"));
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[exclusion]") || l.starts_with("[suppressions]")).map(str::to_string).collect()
        };
        let aucune: Vec<String> = Vec::new();
        let clauses = |op: &str, slf: &str| {
            let c = ExclClauses::depuis_les_csv(op, slf);
            json!([c.op_sql, c.op_soql, c.self_sql, c.self_soql])
        };
        assert_eq!(s["depart"], clauses(AL2_OVERRIDE_OP, AL2_OVERRIDE_SELF), "fixture : le cache porte les deux overrides");

        let p = &s["put_self"];
        assert_eq!(p[0], json!([200, { "ok": true, "field": "self", "old": AL2_OVERRIDE_SELF, "new": AL2_NEUF_SELF }]), "édition de self : le 200 porte le nouveau self : {p}");
        assert_eq!(p[1], clauses(AL2_OVERRIDE_OP, AL2_NEUF_SELF), "édition de self : le cache porte les clauses relues dans la transaction : {p}");
        assert_eq!(p[2], json!(format!("exclusion affichage self: [{AL2_OVERRIDE_SELF}]->[{AL2_NEUF_SELF}] par adm")), "la trace porte le nouveau self : {p}");
        assert_eq!(p[3], json!(true), "contrôle : la lecture de setting est refusée après le COMMIT : {p}");
        assert_eq!(phase("put_self"), aucune, "aucune relecture après la validation, aucune ligne");

        let p = &s["put_op"];
        assert_eq!(p[0], json!([200, { "ok": true, "field": "operator", "old": AL2_OVERRIDE_OP, "new": AL2_NEUF }]), "édition de l'opérateur : {p}");
        assert_eq!(p[1], clauses(AL2_NEUF, AL2_NEUF_SELF), "édition de l'opérateur : le cache garde l'exclusion self relue : {p}");
        assert_eq!(p[2], json!(format!("exclusion affichage operator: [{AL2_OVERRIDE_OP}]->[{AL2_NEUF}] par adm")), "la trace : {p}");
        assert_eq!(p[3], json!(true), "contrôle : refus armé après le COMMIT : {p}");
        assert_eq!(phase("put_op"), aucune, "aucune relecture après la validation, aucune ligne");
    }
}
