// =====================================================================================
// `P10.29-l` (restes AM : `cases.rs` vers :1278, `datasource.rs` vers :490 et :533-534, `alerts.rs` vers :136 et :404) —
// LE TEXTE DU MOTEUR NE PART PLUS DANS LA CRÉATION D'UN DOSSIER, L'UNION DES CLÉS DE LABELS, LES VALEURS D'UN LABEL ET
// LE TOTAL DES LISTES D'ALERTES.
//
// LE DÉFAUT, MESURÉ SUR 60841412 AVANT LE CORRECTIF :
// - `case_create` : `sla_due_non_lu` = `{CAUSE_ECHEANCE_DU_DOSSIER_CREE_NON_RELUE} ({e})` — le texte rusqlite (« access to
//   incident.sla_due is prohibited », nom de colonne) dans le corps 200 servi à un éditeur ;
// - `prom_labels` : `warnings` = « échantillon de labels NON LU : {e} » — le texte de `run_query_ex` (« no such table:
//   metric », ou le refus d'ouverture de la base) dans le corps 200 servi à un lecteur ;
// - `alerts_query_page` / `alert_groups_query_page` : `TotalDeListe::NonEtabli(e.to_string())`, servi sous
//   `total_error` (« total NON ÉTABLI : not authorized to use function: COUNT in SELECT COUNT(DISTINCT alert.rule) FROM alert
//   WHERE alert.status=? at offset 7 — … », énoncé interne compris) dans le corps 200 de `/api/alerts` et `/api/alerts/groups` ;
// - `prom_label_values` (via `prom_distinct_col`) : le 400 servait `error` = le texte de `run_query_ex` (« no such table:
//   metric ») à un lecteur.
//
// LE REMÈDE : une phrase fixe par cause dans le corps (statut et forme inchangés) ; le texte du moteur part à une ligne
// `[cases] WARN` (avec le numéro du dossier), `[datasource] WARN` (objet visé, libellé fixe, et tenant) ou `[alerts] WARN`
// (liste visée et tenant). Le total distingue deux causes par le CODE du moteur : `SQLITE_INTERRUPT` seul est une
// interruption (garde de budget ou annulation) ; toute autre erreur (E/S, base corrompue, verrou, mémoire, refus) est un
// refus de la base. La fonction de page ne connaît pas le tenant : le gestionnaire écrit la ligne (`journaliser`).
//
// LES TÉMOINS :
// (1) `an2_corps_servis_par_la_route` (routeur réel, mode 0, éditeur pour la création, lecteur sinon) : chaque corps
//     d'aveu comparé À L'OCTET ; contrôles positifs : création nominale sans aveu, union et valeurs nominales, totaux ;
// (2) `an2_journal_des_aveux` : la même partie en sous-processus, lignes `[cases]`, `[datasource]`, `[alerts]` EN ENTIER ;
// (3) `an2_compte_non_etabli_selon_le_code_du_moteur` : appel direct de `TotalDeListe::non_etabli` avec des erreurs
//     `SqliteFailure` fabriquées (IOERR, CORRUPT, BUSY, NOMEM, READONLY : refus ; INTERRUPT : interruption) — le refus
//     joué par la route sort à la préparation (`SqlInputError`) et ne tranche pas entre « tout `SqliteFailure` » et le
//     seul code d'interruption ;
// (4) `an2_tache_des_labels_interrompue` : `union_des_cles_de_labels` (la fonction que `prom_labels` appelle) reçoit un
//     `JoinError` FABRIQUÉ par une tâche bloquante qui panique ; phrase, clés et ligne de journal comparées en entier ;
// (5) `an2_deux_tenants` : DEUX tenants réels (mode 1), gestionnaires appelés au rôle lecteur : la base refusée chez l'un
//     rend la phrase fixe et une ligne qui nomme CE tenant, pendant que l'autre est servi par SA base ; puis l'inverse.
//     `case_create` n'y est pas : sa ligne `[cases] WARN` nomme le dossier, et l'autorisateur qui refuse l'échéance se
//     pose sur l'écrivain du tenant exactement comme en mode 0 (rien de propre au tenant à éprouver dans ce bras).
// Pannes : autorisateur SQLite refusant la LECTURE de la seule colonne `incident.sla_due` (connexion d'écriture) ; table
// `metric` renommée ; autorisateur posé sur une connexion de lecture DÉPOSÉE dans le pool de la base, qui refuse la
// SEULE PREMIÈRE autorisation de la fonction `count` (le compte est le premier énoncé de la route ; la page de groupes,
// qui compte aussi, passe ensuite). Le pool est global et borné (éviction LRU entre bases) : le témoin rejoue la requête
// tant que la connexion armée n'a pas servi, et son refus joué est l'instrument qui dit qu'elle a servi.
// Le bras « interrompu » du total est aussi tenu par `total_dalertes_non_etabli_avoue.rs` (tir du rappel de progression).
//
// MUTANTS JOUÉS (par `VERIF_MUT`, retirés avant le commit), un par site, par bras et par ligne de journal : voir le
// rapport du lot (`AN2_NE_TOUT_SQLITE`, `AN2_TACHE_TEXTE`, `AN2_TACHE_MUET`, `AN2_VALEURS_TEXTE`, `AN2_VALEURS_MUET`,
// `AN2_OBJET_HOST`, `AN2_OBJET_JSON`, `AN2_TENANT_FIXE_LABELS`, `AN2_TENANT_FIXE_ALERTES`, ...).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la console (aucun écran ne lit `sla_due_non_lu`, ni le `total_error` de
// `/api/alerts`) ; les `{cause}` de `FinDeParcours::cause()` servis par `corps_de_liste_d_alertes`,
// `corps_de_liste_de_groupes` et les deux autres corps d'`alerts.rs` (hors de ce lot) ; `SERVIES137` ; le `total_error`
// de `/api/query` (contrat `P10.7-g`) ; le 400 de `prom_run` (`datasource.rs`, `Ok(Err(e)) => prom_err(e)`) qui exécute
// le sélecteur de l'appelant ; le bras `JoinError` de `prom_distinct_col`, déjà à phrase fixe (« exécution échouée »).
// =====================================================================================
mod texte_du_moteur_hors_des_corps_de_succes {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicBool, Ordering};

    const AN2_ENFANT: &str = "AN2_ENFANT_JOURNAL";
    const AN2_RENDU: &str = "AN2-RENDU:";
    const AN2_FIN: &str = "AN2-FIN:";
    const AN2_MDP_EDITEUR: &str = "editeur-an2-0123456789";
    /// Au plus autant de requêtes pour que la connexion armée serve la route (le pool global peut l'évincer).
    const AN2_ESSAIS: usize = 40;
    /// Les issues jouées, dans l'ordre.
    const AN2_ORDRE: [&str; 12] = [
        "cree_nominale", "cree_echeance_non_relue", "labels_nominal", "valeurs_nominal", "labels_non_lus",
        "valeurs_name_non_lues", "valeurs_host_non_lues", "valeurs_json_non_lues",
        "alertes_nominal", "alertes_total_refuse", "groupes_nominal", "groupes_total_refuse",
    ];
    /// Le tenant de l'appelant en mode 0 (l'identité résolue par le routeur).
    const AN2_TENANT_MODE_0: &str = "default";
    /// Ce que le moteur dit des trois pannes : aucun corps ne doit le porter.
    const AN2_MOTEUR_ECHEANCE: &str = "access to incident.sla_due is prohibited";
    const AN2_MOTEUR_LABELS: &str = "no such table: metric";
    const AN2_MOTEUR_COMPTE: &str = "not authorized";
    /// MESURÉ (première exécution de ce témoin) : le refus de l'autorisateur cite l'énoncé ENTIER — c'est ce texte que
    /// `total_error` servait à un lecteur avant le correctif. Il reste au journal (énoncé interne, valeurs liées en `?`).
    const AN2_MOTEUR_COMPTE_LISTE: &str = "not authorized to use function: COUNT in SELECT COUNT(*) FROM alert at offset 7";
    const AN2_MOTEUR_COMPTE_GROUPES: &str =
        "not authorized to use function: COUNT in SELECT COUNT(DISTINCT alert.rule) FROM alert WHERE alert.status=? at offset 7";

    struct An2Jeu {
        rendus: Vec<(&'static str, u16, String)>,
        dossier: i64,
    }

    fn an2_editeur() -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("edt:{AN2_MDP_EDITEUR}")))
    }

    fn an2_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
    }

    async fn an2_envoi(addr: std::net::SocketAddr, methode: &str, chemin: &str, authz: &str, corps: &str) -> (u16, String) {
        let (code, brut) = router_probe_envoi(addr, methode, chemin, Some(authz), &[("Content-Type", "application/json")], corps).await;
        let (tete, corps) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {chemin} : {brut}"));
        let corps = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(corps.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {chemin}"))).expect("corps UTF-8")
        } else {
            corps.to_string()
        };
        (code, corps)
    }

    /// Dépose dans le pool de `chemin` une connexion de lecture dont l'autorisateur refuse la SEULE PREMIÈRE autorisation
    /// de `count`, après avoir vidé les connexions au repos de cette base (la connexion armée est la seule à prendre).
    /// Le drapeau rendu dit si le refus a été joué.
    fn an2_armer_le_refus_du_compte(chemin: &str) -> Arc<AtomicBool> {
        while crate::query_exec::connexions_de_lecture_au_repos(chemin) > 0 {
            drop(crate::query_exec::read_conn_get(chemin).expect("fixture : connexion au repos"));
        }
        let conn = crate::query_exec::read_conn_get(chemin).expect("fixture : connexion de lecture");
        let joue = Arc::new(AtomicBool::new(false));
        let drapeau = joue.clone();
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Function { function_name } if function_name.eq_ignore_ascii_case("count") && !drapeau.swap(true, Ordering::SeqCst) => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        crate::query_exec::read_conn_put(chemin, conn);
        joue
    }

    async fn an2_compte_refuse(addr: std::net::SocketAddr, chemin_base: &str, route: &str) -> (u16, String) {
        for _ in 0..AN2_ESSAIS {
            let joue = an2_armer_le_refus_du_compte(chemin_base);
            let rendu = an2_envoi(addr, "GET", route, &viewer_authz(), "").await;
            if joue.load(Ordering::SeqCst) {
                return rendu;
            }
        }
        panic!("instrument : la connexion armée n'a servi {route} en aucun des {AN2_ESSAIS} essais — le témoin ne conclut pas");
    }

    async fn an2_jouer() -> An2Jeu {
        let mut rendus: Vec<(&'static str, u16, String)> = Vec::new();
        let (st, base) = router_test_state("an2-routes");
        let chemin = base.as_str().to_string();
        an2_sql(&st, "DELETE FROM incident; DELETE FROM sla_policy; DELETE FROM alert;");
        st.db
            .lock()
            .execute("INSERT INTO user(name,hash,role) VALUES('edt',?1,'editor')", params![hash_pw(AN2_MDP_EDITEUR).unwrap()])
            .expect("fixture : compte éditeur");
        an2_sql(
            &st,
            "INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources) VALUES(1000,'rule.an2a',2,'Alerte AN2 A','','new','T1046','');
             INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources) VALUES(1001,'rule.an2b',3,'Alerte AN2 B','','new','T1046','');",
        );
        let addr = router_serve(st.clone()).await;
        let editeur = an2_editeur();

        // ---- création d'un dossier ----
        let (s, c) = an2_envoi(addr, "POST", "/api/cases", &editeur, r#"{"title":"Nominal","priority":2}"#).await;
        rendus.push(("cree_nominale", s, c));
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "incident", column_name: "sla_due" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (s, c) = an2_envoi(addr, "POST", "/api/cases", &editeur, r#"{"title":"Echeance","priority":2}"#).await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        let dossier = serde_json::from_str::<Value>(&c).ok().and_then(|v| v["id"].as_i64()).unwrap_or(0);
        rendus.push(("cree_echeance_non_relue", s, c));

        // ---- union des clés de labels ----
        let (s, c) = an2_envoi(addr, "GET", "/api/v1/labels", &viewer_authz(), "").await;
        rendus.push(("labels_nominal", s, c));
        let (s, c) = an2_envoi(addr, "GET", "/api/v1/label/__name__/values", &viewer_authz(), "").await;
        rendus.push(("valeurs_nominal", s, c));
        an2_sql(&st, "ALTER TABLE metric RENAME TO metric_hors_d_atteinte_an2;");
        let (s, c) = an2_envoi(addr, "GET", "/api/v1/labels", &viewer_authz(), "").await;
        rendus.push(("labels_non_lus", s, c));
        // Les trois énoncés de `prom_label_values` (noms de métriques, colonne `host`, clé JSON) : trois objets au journal.
        let (s, c) = an2_envoi(addr, "GET", "/api/v1/label/__name__/values", &viewer_authz(), "").await;
        rendus.push(("valeurs_name_non_lues", s, c));
        let (s, c) = an2_envoi(addr, "GET", "/api/v1/label/host/values", &viewer_authz(), "").await;
        rendus.push(("valeurs_host_non_lues", s, c));
        let (s, c) = an2_envoi(addr, "GET", "/api/v1/label/job_an2/values", &viewer_authz(), "").await;
        rendus.push(("valeurs_json_non_lues", s, c));
        an2_sql(&st, "ALTER TABLE metric_hors_d_atteinte_an2 RENAME TO metric;");

        // ---- total des listes d'alertes ----
        let (s, c) = an2_envoi(addr, "GET", "/api/alerts?status=all", &viewer_authz(), "").await;
        rendus.push(("alertes_nominal", s, c));
        let (s, c) = an2_compte_refuse(addr, &chemin, "/api/alerts?status=all").await;
        rendus.push(("alertes_total_refuse", s, c));
        let (s, c) = an2_envoi(addr, "GET", "/api/alerts/groups?group=rule", &viewer_authz(), "").await;
        rendus.push(("groupes_nominal", s, c));
        let (s, c) = an2_compte_refuse(addr, &chemin, "/api/alerts/groups?group=rule").await;
        rendus.push(("groupes_total_refuse", s, c));
        An2Jeu { rendus, dossier }
    }

    fn an2_total_refuse() -> String {
        format!(
            "total NON ÉTABLI : {} — la page est servie, la population de la liste ne l'est pas",
            crate::handlers::alerts::TOTAL_D_ALERTES_REFUSE_PAR_LA_BASE
        )
    }

    /// (1) LES CORPS SERVIS : chaque aveu comparé à l'octet, chaque contrôle positif en entier.
    #[tokio::test]
    async fn an2_corps_servis_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let jeu = an2_jouer().await;
        let issues: Vec<&str> = jeu.rendus.iter().map(|(i, _, _)| *i).collect();
        assert_eq!(issues, AN2_ORDRE.to_vec(), "chaque issue est jouée une fois, dans l'ordre");
        let rendu = |issue: &str| -> (u16, String) {
            jeu.rendus.iter().find(|(i, _, _)| *i == issue).map(|(_, s, c)| (*s, c.clone())).unwrap_or_else(|| panic!("issue {issue} jouée"))
        };
        let mut manquent: Vec<String> = Vec::new();
        let mut juger = |issue: &str, attendu: (u16, String)| {
            let lu = rendu(issue);
            if lu != attendu {
                manquent.push(format!("{issue} : attendu {} {}\n    lu {} {}", attendu.0, attendu.1, lu.0, lu.1));
            }
        };

        // Création : le nominal sans aveu, l'échéance non relue servie `null` avec la phrase SEULE.
        let (s, c) = rendu("cree_nominale");
        let nominal: Value = serde_json::from_str(&c).unwrap_or(Value::Null);
        let id_nominal = nominal["id"].as_i64().unwrap_or(0);
        assert!(s == 200 && id_nominal > 0 && nominal["sla_due"].is_i64(), "contrôle : création nominale servie avec son échéance : {s} {c}");
        juger(
            "cree_nominale",
            (200, json!({ "id": id_nominal, "status": "new", "priority": 2, "priority_label": priority_label(2), "sla_due": nominal["sla_due"].clone() }).to_string()),
        );
        assert!(jeu.dossier > id_nominal, "contrôle : le second dossier est créé et servi avec son identifiant ({})", jeu.dossier);
        let mut aveu = json!({ "id": jeu.dossier, "status": "new", "priority": 2, "priority_label": priority_label(2), "sla_due": null });
        aveu["sla_due_non_lu"] = json!(CAUSE_ECHEANCE_DU_DOSSIER_CREE_NON_RELUE);
        juger("cree_echeance_non_relue", (200, aveu.to_string()));

        // Labels : l'union nominale sans avertissement, l'échantillon non lu dit par la phrase fixe.
        let (s, c) = rendu("labels_nominal");
        let v: Value = serde_json::from_str(&c).unwrap_or(Value::Null);
        assert!(s == 200 && v == json!({ "status": "success", "data": ["__name__", "host"] }), "contrôle : union nominale sans avertissement : {s} {c}");
        juger("valeurs_nominal", (200, json!({ "status": "success", "data": [] }).to_string()));
        let valeurs_refusees =
            (400, json!({ "status": "error", "errorType": "bad_data", "error": crate::handlers::datasource::VALEURS_DE_LABEL_NON_LUES }).to_string());
        juger("valeurs_name_non_lues", valeurs_refusees.clone());
        juger("valeurs_host_non_lues", valeurs_refusees.clone());
        juger("valeurs_json_non_lues", valeurs_refusees);
        juger(
            "labels_non_lus",
            (
                200,
                json!({
                    "status": "success",
                    "data": ["__name__", "host"],
                    "warnings": [format!(
                        "{} — seules les clés fixes (__name__, host) sont servies, l'union des clés n'est pas établie",
                        crate::handlers::datasource::ECHANTILLON_DE_LABELS_NON_LU
                    )]
                })
                .to_string(),
            ),
        );

        // Alertes : le corps refusé est le corps nominal, `total` à `null` et `total_error` à la phrase fixe.
        let refus_attendu = |nominale: &str| -> (u16, String) {
            let (s, c) = rendu(nominale);
            let mut attendu: Value = serde_json::from_str(&c).unwrap_or(Value::Null);
            assert!(s == 200 && attendu["total"] == json!(2) && attendu.get("total_error").is_none() && attendu.get("error").is_none(), "contrôle : {nominale} compté, sans aveu : {s} {c}");
            attendu["total"] = Value::Null;
            attendu["total_error"] = json!(an2_total_refuse());
            (200, attendu.to_string())
        };
        juger("alertes_total_refuse", refus_attendu("alertes_nominal"));
        juger("groupes_total_refuse", refus_attendu("groupes_nominal"));

        // Aucun texte du moteur dans aucun corps.
        for (issue, _, brut) in &jeu.rendus {
            for trace in [AN2_MOTEUR_ECHEANCE, AN2_MOTEUR_LABELS, AN2_MOTEUR_COMPTE, "sla_due is", "no such table", "prohibited", "COUNT(", "offset 7"] {
                if brut.contains(trace) {
                    manquent.push(format!("{issue} : le corps porte « {trace} » : {brut}"));
                }
            }
        }
        assert!(manquent.is_empty(), "corps mal servis :\n{}", manquent.join("\n"));
    }

    /// (2) LE JOURNAL : les lignes `[cases] WARN`, `[datasource] WARN` et `[alerts] WARN`, EN ENTIER.
    #[tokio::test]
    async fn an2_journal_des_aveux() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        if std::env::var(AN2_ENFANT).is_ok() {
            let jeu = an2_jouer().await;
            for (issue, statut, _) in &jeu.rendus {
                println!("{AN2_RENDU} {issue} {statut}");
            }
            println!("{AN2_FIN} {} {}", jeu.rendus.len(), jeu.dossier);
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::texte_du_moteur_hors_des_corps_de_succes::an2_journal_des_aveux"])
            .env(AN2_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let (joues, dossier) = stdout
            .lines()
            .find_map(|l| l.split_once(AN2_FIN))
            .and_then(|(_, v)| v.trim().split_once(' ').map(|(a, b)| (a.parse::<usize>().unwrap_or(0), b.trim().parse::<i64>().unwrap_or(0))))
            .unwrap_or_else(|| panic!("contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}"));
        assert_eq!(joues, AN2_ORDRE.len(), "contrôle : toutes les issues jouées par l'enfant : {stdout}");
        assert!(dossier > 0, "contrôle : le dossier à l'échéance non relue est créé : {stdout}");
        assert_eq!(stdout.lines().filter(|l| l.contains(AN2_RENDU)).count(), AN2_ORDRE.len(), "contrôle : une ligne par issue : {stdout}");
        let journal: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("[cases] WARN") || l.starts_with("[datasource] WARN") || l.starts_with("[alerts] WARN"))
            .collect();
        assert_eq!(
            journal,
            vec![
                format!("[cases] WARN échéance du dossier #{dossier} non relue : {AN2_MOTEUR_ECHEANCE}"),
                format!("[datasource] WARN échantillon de labels non lu (tenant '{AN2_TENANT_MODE_0}') : {AN2_MOTEUR_LABELS}"),
                format!("[datasource] WARN valeurs distinctes de __name__ non lues (tenant '{AN2_TENANT_MODE_0}') : {AN2_MOTEUR_LABELS}"),
                format!("[datasource] WARN valeurs distinctes de host non lues (tenant '{AN2_TENANT_MODE_0}') : {AN2_MOTEUR_LABELS}"),
                format!("[datasource] WARN valeurs distinctes d'un label JSON non lues (tenant '{AN2_TENANT_MODE_0}') : {AN2_MOTEUR_LABELS}"),
                format!("[alerts] WARN total de la liste d'alertes non établi (tenant '{AN2_TENANT_MODE_0}') : {AN2_MOTEUR_COMPTE_LISTE}"),
                format!("[alerts] WARN total de la liste de groupes par rule non établi (tenant '{AN2_TENANT_MODE_0}') : {AN2_MOTEUR_COMPTE_GROUPES}"),
            ],
            "une ligne EXACTE par aveu, le texte du moteur au journal seul :\n{stderr}"
        );
    }

    /// (3) LE CLASSEMENT D'UN COMPTE RATÉ PAR LE CODE DU MOTEUR — appel direct de `TotalDeListe::non_etabli`, la fonction
    /// que les deux pages appellent. Seul `SQLITE_INTERRUPT` est une interruption : une erreur d'E/S, une base corrompue,
    /// un verrou, un manque de mémoire, une base en lecture seule ou une absence de ligne sont des refus de la base.
    #[test]
    fn an2_compte_non_etabli_selon_le_code_du_moteur() {
        use crate::handlers::alerts::{TotalDeListe, TOTAL_D_ALERTES_INTERROMPU, TOTAL_D_ALERTES_REFUSE_PAR_LA_BASE};
        let echec = |code: std::ffi::c_int| rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), Some(format!("moteur an2 {code}")));
        let phrase = |e: rusqlite::Error| match TotalDeListe::non_etabli("de la liste d'alertes", &e) {
            TotalDeListe::NonEtabli(c) => c.phrase,
            autre => panic!("un compte raté est NON ÉTABLI, jamais {autre:?}"),
        };
        let lus = vec![
            ("IOERR", phrase(echec(rusqlite::ffi::SQLITE_IOERR))),
            ("IOERR_READ", phrase(echec(rusqlite::ffi::SQLITE_IOERR_READ))),
            ("CORRUPT", phrase(echec(rusqlite::ffi::SQLITE_CORRUPT))),
            ("BUSY", phrase(echec(rusqlite::ffi::SQLITE_BUSY))),
            ("NOMEM", phrase(echec(rusqlite::ffi::SQLITE_NOMEM))),
            ("READONLY", phrase(echec(rusqlite::ffi::SQLITE_READONLY))),
            ("SANS_LIGNE", phrase(rusqlite::Error::QueryReturnedNoRows)),
            ("INTERRUPT", phrase(echec(rusqlite::ffi::SQLITE_INTERRUPT))),
        ];
        assert_eq!(
            lus,
            vec![
                ("IOERR", TOTAL_D_ALERTES_REFUSE_PAR_LA_BASE),
                ("IOERR_READ", TOTAL_D_ALERTES_REFUSE_PAR_LA_BASE),
                ("CORRUPT", TOTAL_D_ALERTES_REFUSE_PAR_LA_BASE),
                ("BUSY", TOTAL_D_ALERTES_REFUSE_PAR_LA_BASE),
                ("NOMEM", TOTAL_D_ALERTES_REFUSE_PAR_LA_BASE),
                ("READONLY", TOTAL_D_ALERTES_REFUSE_PAR_LA_BASE),
                ("SANS_LIGNE", TOTAL_D_ALERTES_REFUSE_PAR_LA_BASE),
                ("INTERRUPT", TOTAL_D_ALERTES_INTERROMPU),
            ],
            "seul le code d'interruption se dit « interrompu » ; toute autre erreur du moteur est un refus de la base"
        );
    }

    const AN2_ENFANT_TACHE: &str = "AN2_ENFANT_TACHE";
    const AN2_TENANT_TACHE: &str = "an2-tache";

    /// (4) LA TÂCHE DE LECTURE DE L'ÉCHANTILLON QUI NE SE TERMINE PAS : un `JoinError` FABRIQUÉ par une vraie tâche
    /// bloquante qui panique, remis à `union_des_cles_de_labels` (la fonction que `prom_labels` appelle sur l'issue de sa
    /// tâche). L'enfant rend la phrase, les clés et le drapeau ; le parent compare tout, et la ligne de journal EN ENTIER.
    #[tokio::test]
    async fn an2_tache_des_labels_interrompue() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // l'enfant est désigné par l'environnement
        if std::env::var(AN2_ENFANT_TACHE).is_ok() {
            let issue = tokio::task::spawn_blocking(|| -> Result<(Vec<Value>, bool), String> { panic!("an2 lecture de l'échantillon interrompue") }).await;
            let sortie = issue.as_ref().err().map(|e| e.to_string()).unwrap_or_default();
            let (cles, coupe, phrase) = crate::handlers::datasource::union_des_cles_de_labels(issue, AN2_TENANT_TACHE);
            println!("{AN2_RENDU}{}", json!({ "sortie": sortie, "cles": cles, "coupe": coupe, "phrase": phrase }));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::texte_du_moteur_hors_des_corps_de_succes::an2_tache_des_labels_interrompue"])
            .env(AN2_ENFANT_TACHE, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let rendu: Value = stdout
            .lines()
            .find_map(|l| l.split_once(AN2_RENDU))
            .and_then(|(_, v)| serde_json::from_str(v).ok())
            .unwrap_or_else(|| panic!("contrôle : l'enfant a rendu son issue : {stdout}\n{stderr}"));
        let tache = rendu["sortie"].as_str().unwrap_or("").to_string();
        assert!(tache.contains("panicked"), "contrôle : l'issue remise est bien la panique d'une tâche : {rendu}");
        assert_eq!(
            rendu,
            json!({
                "sortie": tache,
                "cles": ["__name__", "host"],
                "coupe": false,
                "phrase": crate::handlers::datasource::ECHANTILLON_DE_LABELS_TACHE_INTERROMPUE,
            }),
            "les clés fixes seules, aucune coupe prétendue, la phrase fixe de la tâche (sans sa sortie)"
        );
        let journal: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[datasource] WARN")).collect();
        assert_eq!(
            journal,
            vec![format!("[datasource] WARN échantillon de labels non lu (tenant '{AN2_TENANT_TACHE}') : la tâche ne s'est pas terminée : {tache}")],
            "une ligne EXACTE, la sortie de la tâche au journal seul :\n{stderr}"
        );
    }

    const AN2_ENFANT_DEUX: &str = "AN2_ENFANT_DEUX_TENANTS";
    const AN2_ALPHA: &str = "an2-alpha";
    const AN2_BETA: &str = "an2-beta";

    fn an2_lecteur(tenant: &str) -> AuthUser {
        AuthUser { name: "lecteur-an2".into(), role: "viewer".into(), tenant: tenant.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }

    async fn an2_rendu(r: Response) -> (u16, String) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, String::from_utf8_lossy(&b).into_owned())
    }

    /// Crée le tenant `t` (vraie route de création), sème un point de métrique (clé de label `cle`) et `alertes` alertes
    /// dans SA base, et rend le chemin de cette base.
    async fn an2_creer_le_tenant(st: &AppState, t: &str, metrique: &str, cle: &str, alertes: i64) -> String {
        let (statut, corps) = an2_rendu(
            tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-an2")), Json(json!({ "id": t, "name": t }))).await,
        )
        .await;
        assert_eq!(statut, 201, "contrôle : tenant {t} créé : {corps}");
        assert!(st.tenants.tenant_available(t), "contrôle : tenant {t} résolu pour le pool de lecture");
        let h = st.tenants.handle_for(t).expect("contrôle : base du tenant");
        {
            let c = h.lock();
            c.execute("INSERT INTO metric(ts,name,labels,value,host) VALUES(?1,?2,?3,1.0,'h-an2')", params![now(), metrique, format!("{{\"{cle}\":\"v\"}}")])
                .expect("fixture : point de métrique");
            for i in 0..alertes {
                c.execute(
                    "INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources) VALUES(?1,?2,2,'Alerte AN2','','new','T1046','')",
                    params![1000 + i, format!("rule.{t}.{i}")],
                )
                .expect("fixture : alerte");
            }
        }
        st.tenants.ready_db_path(t).expect("contrôle : chemin de la base du tenant")
    }

    fn an2_metric_hors_d_atteinte(st: &AppState, t: &str, retiree: bool) {
        let sql = if retiree { "ALTER TABLE metric RENAME TO metric_hors_d_atteinte_an2;" } else { "ALTER TABLE metric_hors_d_atteinte_an2 RENAME TO metric;" };
        st.tenants.handle_for(t).expect("contrôle : base du tenant").lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` chez {t} ({e})"));
    }

    async fn an2_labels_et_valeurs(st: &AppState, phase: &str, t: &str, rendus: &mut Vec<(String, u16, String)>) {
        let (s, c) = an2_rendu(crate::handlers::datasource::prom_labels(State(st.clone()), Extension(an2_lecteur(t))).await).await;
        rendus.push((format!("{phase}:labels:{t}"), s, c));
        let (s, c) = an2_rendu(
            crate::handlers::datasource::prom_label_values(State(st.clone()), Extension(an2_lecteur(t)), Path("__name__".to_string()), axum::extract::Query(HashMap::new()))
                .await,
        )
        .await;
        rendus.push((format!("{phase}:valeurs:{t}"), s, c));
    }

    async fn an2_alertes(st: &AppState, t: &str) -> (u16, String) {
        let q: HashMap<String, String> = HashMap::from([("status".to_string(), "all".to_string())]);
        an2_rendu(crate::handlers::alerts::alerts(State(st.clone()), Extension(an2_lecteur(t)), axum::extract::Query(q)).await).await
    }

    async fn an2_alertes_compte_refuse(st: &AppState, t: &str, chemin: &str) -> (u16, String) {
        for _ in 0..AN2_ESSAIS {
            let joue = an2_armer_le_refus_du_compte(chemin);
            let rendu = an2_alertes(st, t).await;
            if joue.load(Ordering::SeqCst) {
                return rendu;
            }
        }
        panic!("instrument : la connexion armée n'a servi les alertes de {t} en aucun des {AN2_ESSAIS} essais — le témoin ne conclut pas");
    }

    async fn an2_jouer_deux_tenants() -> Vec<(String, u16, String)> {
        let (st, _dir) = mk_mode1_state();
        let alpha = an2_creer_le_tenant(&st, AN2_ALPHA, "metrique_alpha", "cle_alpha", 1).await;
        let beta = an2_creer_le_tenant(&st, AN2_BETA, "metrique_beta", "cle_beta", 2).await;
        assert_ne!(alpha, beta, "contrôle : deux bases distinctes");
        let mut rendus: Vec<(String, u16, String)> = Vec::new();
        an2_labels_et_valeurs(&st, "nominal", AN2_ALPHA, &mut rendus).await;
        an2_labels_et_valeurs(&st, "nominal", AN2_BETA, &mut rendus).await;
        // alpha refusée, beta servie par SA base ; puis l'inverse.
        an2_metric_hors_d_atteinte(&st, AN2_ALPHA, true);
        an2_labels_et_valeurs(&st, "alpha_refusee", AN2_ALPHA, &mut rendus).await;
        an2_labels_et_valeurs(&st, "alpha_refusee", AN2_BETA, &mut rendus).await;
        an2_metric_hors_d_atteinte(&st, AN2_ALPHA, false);
        an2_metric_hors_d_atteinte(&st, AN2_BETA, true);
        an2_labels_et_valeurs(&st, "beta_refusee", AN2_BETA, &mut rendus).await;
        an2_labels_et_valeurs(&st, "beta_refusee", AN2_ALPHA, &mut rendus).await;
        an2_metric_hors_d_atteinte(&st, AN2_BETA, false);
        // Le compte des alertes : nominal chez les deux, puis refusé chez l'un pendant que l'autre est compté.
        let (s, c) = an2_alertes(&st, AN2_ALPHA).await;
        rendus.push((format!("nominal:alertes:{AN2_ALPHA}"), s, c));
        let (s, c) = an2_alertes(&st, AN2_BETA).await;
        rendus.push((format!("nominal:alertes:{AN2_BETA}"), s, c));
        let (s, c) = an2_alertes_compte_refuse(&st, AN2_ALPHA, &alpha).await;
        rendus.push((format!("alpha_refusee:alertes:{AN2_ALPHA}"), s, c));
        let (s, c) = an2_alertes(&st, AN2_BETA).await;
        rendus.push((format!("alpha_refusee:alertes:{AN2_BETA}"), s, c));
        let (s, c) = an2_alertes_compte_refuse(&st, AN2_BETA, &beta).await;
        rendus.push((format!("beta_refusee:alertes:{AN2_BETA}"), s, c));
        let (s, c) = an2_alertes(&st, AN2_ALPHA).await;
        rendus.push((format!("beta_refusee:alertes:{AN2_ALPHA}"), s, c));
        rendus
    }

    /// (5) DEUX TENANTS RÉELS (mode 1) : la base refusée chez l'un rend la phrase fixe et une ligne de journal qui nomme
    /// CE tenant ; l'autre est servi par SA base (ses clés, sa métrique, son compte) ; puis l'inverse. Corps à l'octet,
    /// lignes en entier, dans l'ordre.
    #[tokio::test]
    async fn an2_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        if std::env::var(AN2_ENFANT_DEUX).is_ok() {
            let rendus = an2_jouer_deux_tenants().await;
            for (issue, statut, corps) in &rendus {
                println!("{AN2_RENDU}{}", json!([issue, statut, corps]));
            }
            println!("{AN2_FIN} {}", rendus.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::texte_du_moteur_hors_des_corps_de_succes::an2_deux_tenants"])
            .env(AN2_ENFANT_DEUX, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let rendus: Vec<(String, u16, String)> = stdout
            .lines()
            .filter_map(|l| l.split_once(AN2_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : ligne de rendu lisible ({e}) : {v}")))
            .collect();
        assert!(stdout.contains(&format!("{AN2_FIN} 18")), "contrôle : l'enfant a joué ses dix-huit issues : {stdout}\n{stderr}");
        let rendu = |issue: String| -> (u16, String) {
            rendus.iter().find(|(i, _, _)| *i == issue).map(|(_, s, c)| (*s, c.clone())).unwrap_or_else(|| panic!("issue {issue} jouée : {stdout}"))
        };
        let union = |cle: &str| (200, json!({ "status": "success", "data": ["__name__", cle, "host"] }).to_string());
        let metriques = |m: &str| (200, json!({ "status": "success", "data": [m] }).to_string());
        let union_non_lue = (
            200,
            json!({
                "status": "success",
                "data": ["__name__", "host"],
                "warnings": [format!(
                    "{} — seules les clés fixes (__name__, host) sont servies, l'union des clés n'est pas établie",
                    crate::handlers::datasource::ECHANTILLON_DE_LABELS_NON_LU
                )]
            })
            .to_string(),
        );
        let valeurs_non_lues = (400, json!({ "status": "error", "errorType": "bad_data", "error": crate::handlers::datasource::VALEURS_DE_LABEL_NON_LUES }).to_string());
        let compte = |t: &str, n: i64| -> (u16, String) {
            let (s, c) = rendu(format!("nominal:alertes:{t}"));
            let v: Value = serde_json::from_str(&c).unwrap_or(Value::Null);
            assert!(s == 200 && v["total"] == json!(n) && v.get("total_error").is_none(), "contrôle : {t} compte SES {n} alertes : {s} {c}");
            (s, c)
        };
        let compte_refuse = |t: &str, n: i64| -> (u16, String) {
            let mut v: Value = serde_json::from_str(&compte(t, n).1).unwrap_or(Value::Null);
            v["total"] = Value::Null;
            v["total_error"] = json!(an2_total_refuse());
            (200, v.to_string())
        };
        let lus: Vec<(String, u16, String)> = rendus.clone();
        let attendus: Vec<(String, u16, String)> = vec![
            ("nominal:labels:an2-alpha", union("cle_alpha")),
            ("nominal:valeurs:an2-alpha", metriques("metrique_alpha")),
            ("nominal:labels:an2-beta", union("cle_beta")),
            ("nominal:valeurs:an2-beta", metriques("metrique_beta")),
            ("alpha_refusee:labels:an2-alpha", union_non_lue.clone()),
            ("alpha_refusee:valeurs:an2-alpha", valeurs_non_lues.clone()),
            ("alpha_refusee:labels:an2-beta", union("cle_beta")),
            ("alpha_refusee:valeurs:an2-beta", metriques("metrique_beta")),
            ("beta_refusee:labels:an2-beta", union_non_lue.clone()),
            ("beta_refusee:valeurs:an2-beta", valeurs_non_lues.clone()),
            ("beta_refusee:labels:an2-alpha", union("cle_alpha")),
            ("beta_refusee:valeurs:an2-alpha", metriques("metrique_alpha")),
            ("nominal:alertes:an2-alpha", compte(AN2_ALPHA, 1)),
            ("nominal:alertes:an2-beta", compte(AN2_BETA, 2)),
            ("alpha_refusee:alertes:an2-alpha", compte_refuse(AN2_ALPHA, 1)),
            ("alpha_refusee:alertes:an2-beta", compte(AN2_BETA, 2)),
            ("beta_refusee:alertes:an2-beta", compte_refuse(AN2_BETA, 2)),
            ("beta_refusee:alertes:an2-alpha", compte(AN2_ALPHA, 1)),
        ]
        .into_iter()
        .map(|(i, (s, c))| (i.to_string(), s, c))
        .collect();
        assert_eq!(lus, attendus, "chaque tenant servi par SA base, la phrase fixe chez le seul tenant refusé");
        let journal: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[datasource] WARN") || l.starts_with("[alerts] WARN")).collect();
        assert_eq!(
            journal,
            vec![
                format!("[datasource] WARN échantillon de labels non lu (tenant '{AN2_ALPHA}') : {AN2_MOTEUR_LABELS}"),
                format!("[datasource] WARN valeurs distinctes de __name__ non lues (tenant '{AN2_ALPHA}') : {AN2_MOTEUR_LABELS}"),
                format!("[datasource] WARN échantillon de labels non lu (tenant '{AN2_BETA}') : {AN2_MOTEUR_LABELS}"),
                format!("[datasource] WARN valeurs distinctes de __name__ non lues (tenant '{AN2_BETA}') : {AN2_MOTEUR_LABELS}"),
                format!("[alerts] WARN total de la liste d'alertes non établi (tenant '{AN2_ALPHA}') : {AN2_MOTEUR_COMPTE_LISTE}"),
                format!("[alerts] WARN total de la liste d'alertes non établi (tenant '{AN2_BETA}') : {AN2_MOTEUR_COMPTE_LISTE}"),
            ],
            "une ligne EXACTE par aveu, qui nomme le tenant refusé :\n{stderr}"
        );
    }
}
