// =====================================================================================
// `P10.29-l` (vague BE) — LE TEXTE DU MOTEUR HORS DES RIPOSTES, DE LA FICHE DE RISQUE ET DES ESSAIS DE DÉTECTION.
//
// LE DÉFAUT, RELU SUR d68c32e5 :
//  - `handlers/actions.rs` : les quatre 503 nommés de `action_result`, `action_approve` (lecture, écriture) et
//    `action_cancel` servaient `format!("{CAUSE_X} ({e})")`, `e` étant l'erreur du moteur (type d'une valeur illisible,
//    nom de table, message d'un déclencheur) ;
//  - `handlers/rba.rs` : `/api/risk/entity/{t}/{e}` (rôle lecteur) servait le texte du moteur dans `summary_error`,
//    `timeline_error` et `contributions_error` ;
//  - `handlers/detection.rs` : le 503 de `parser_reparse` servait `prepare: <texte du moteur>`, et `/api/rule-test`
//    (rôle éditeur) servait le texte de `run_query` tel quel sous `error` (refus de l'autorisateur, erreur d'E/S).
// Les numéros « 97, 101 à 103, 127 » que citait le reste de la clé sont ceux des instruments du harnais console qui
// épinglent ces formes, pas des numéros de ligne.
//
// CE QUE CES TÉMOINS JUGENT :
// (1) `be6_par_la_route_corps_entiers` — par le routeur réel (mode 0), jeton du rôle le plus faible admis par route
//     (administrateur pour les ripostes et le reparse, jeton d'agent lié à l'hôte pour le verdict, lecteur pour la fiche
//     de risque, éditeur pour l'essai) : chaque corps de refus ENTIER (ensemble exact des clés, valeur exacte de la
//     cause comparée à une constante du test), aucun octet de la réponse ne porte le texte du moteur ; l'essai de règle
//     sous chacune des quatre classes (support, occupée, produit, moteur) armées au cœur d'exécution ; contrôles
//     positifs (approbation, annulation et verdict pris, fiche servie sans aveu, aperçu du reparse, valeur de l'essai).
// (2) `be6_deux_tenants_journal_entier` — DEUX tenants réels (mode 1), gestionnaires appelés au rôle le plus faible,
//     en sous-processus : une ligne `[actions]`, `[rba]`, `[reparse]` ou `[detection]` par refus, ÉGALE à la ligne
//     attendue, dans l'ordre, nommant le tenant de l'APPELANT ; le texte du moteur rendu par `{:?}` (le message du
//     déclencheur porte un retour à la ligne, un retour chariot et un guillemet : la ligne reste une) ; aucune ligne
//     pour la phrase du produit ; la ligne de l'essai porte la nature (code SQLite), jamais le texte.
//
// MUTATIONS (jouées sous la variable de mutation, retirées du source) : `BE6_A1` à `BE6_A4` (chaque site de riposte sert de nouveau
// le texte du moteur), `BE6_R1` à `BE6_R3` (chaque aveu de la fiche de risque), `BE6_J_MUET`, `BE6_J_TENANT`,
// `BE6_J_ECHAP` (aide de journal muette, tenant figé, texte non échappé), `BE6_D_PREP` et `BE6_D_PREP_MUET` (reparse),
// `BE6_D_TEXTE`, `BE6_D_PRODUIT`, `BE6_D_SUPPORT`, `BE6_D_OCCUPEE`, `BE6_D_MOTEUR`, `BE6_D_TENANT` (essai de règle).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la ligne de journal d'une riposte ne porte pas l'identifiant de corrélation du
// 503 (la forme `err_json(…)` que lisent les instruments 101 et 103 du harnais console le tire après la ligne ; la
// riposte est nommée par son numéro) ; le NUL n'est pas joué (un message de déclencheur ne le porte pas), seuls le
// retour à la ligne, le retour chariot et le guillemet le sont ; l'essai de règle garde son deux cents `{error, sql}`.
// =====================================================================================
mod be6_texte_du_moteur_hors_des_ripostes_du_risque_et_des_essais {
    use super::*;
    use crate::handlers::actions::{
        CAUSE_ANNULATION_NON_ENREGISTREE, CAUSE_APPROBATION_NON_ENREGISTREE, CAUSE_RESULTAT_NON_ENREGISTRE, CAUSE_RIPOSTE_NON_LUE,
    };
    use crate::handlers::query::{CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE, CAUSE_REQUETE_NON_SERVIE_BASE_OCCUPEE, REQUETE_REJETEE_PAR_LE_MOTEUR};
    use crate::query_exec::panne_de_test_au_coeur::{demander, encore_demandee, retirer, PanneAuCoeur};
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// La phrase servie entre parenthèses à la place du texte du moteur (littéral, jamais la constante de production).
    const BE6_CAUSE_AU_JOURNAL: &str = "la cause rendue par la base est au journal du démon";
    /// La phrase du 503 du reparse non préparé (littéral).
    const BE6_REPARSE_NON_PREPARE: &str = "REPARSE NON COMMENCÉ : la base a refusé de préparer le parcours des events — \
         rien n'a été lu ni écrit. Relancez le reparse ; si le refus persiste, la cause rendue par la base est au journal du démon.";
    /// Le message du déclencheur qui refuse toute mise à jour d'une riposte : il porte les caractères qui forgeraient une
    /// ligne de journal (retour à la ligne, retour chariot, guillemet).
    const BE6_MESSAGE_DU_DECLENCHEUR: &str = "be6 refus\nligne forgée\r\"guillemet\"";
    const BE6_JETON_D_AGENT: &str = "be6-jeton-de-l-agent-lie";
    const BE6_HOTE: &str = "hote-be6";
    const BE6_MDP_EDITEUR: &str = "editeur-be6-12345";
    const BE6_SOQL: &str = "search source=be6 message=~\"be6\" | stats count";
    const BE6_ENFANT: &str = "BE6_ENFANT_DEUX_TENANTS";
    const BE6_FIN: &str = "BE6-FIN:";
    const BE6_ALPHA: &str = "be6-alpha";
    const BE6_BETA: &str = "be6-beta";

    // ── instruments ──────────────────────────────────────────────────────────────────────────────────────────────

    /// Les ripostes, la fiche de risque et l'event de la fixture, sur une base donnée (mode 0 ou base d'un tenant).
    fn be6_semer(conn: &Connection) {
        let t = now() - 60;
        conn.execute_batch(&format!(
            "DELETE FROM action;\
             INSERT INTO action(id,ts,kind,target,status,dry_run,host) VALUES(4100,1000,'kill_pid','4242','pending',1,'');\
             INSERT INTO action(id,ts,kind,target,status,dry_run,host) VALUES(4101,1000,'kill_pid','4243','pending',1,'');\
             INSERT INTO action(id,ts,kind,target,status,dry_run,host) VALUES(4102,1000,'kill_pid','4244','pending',1,'');\
             INSERT INTO action(id,ts,kind,target,status,dry_run,host) VALUES(4103,1000,'kill_pid','4245','pending',1,'');\
             INSERT INTO action(id,ts,kind,target,status,dry_run,host) VALUES(4104,1000,'ban_ip','203.0.113.70','approved',0,'{BE6_HOTE}');\
             INSERT INTO action(id,ts,kind,target,status,dry_run,host) VALUES(4105,1000,'ban_ip','203.0.113.71','approved',0,'{BE6_HOTE}');\
             UPDATE action SET target=x'FF' WHERE id=4101;\
             INSERT INTO risk_rollup(entity_type,entity,score,contrib,distinct_tactics,tactics,max_severity,first_ts,last_ts) \
               VALUES('host','be6-h',10,1,1,'TA0001',2,{t},{t});\
             INSERT INTO risk_event(ts,entity_type,entity,risk_score,source,reason) VALUES({t},'host','be6-h',10,'rule','be6');\
             INSERT INTO event(ts,source,severity,message,host) VALUES({t},'be6',1,'be6-sonde','be6-h');"
        ))
        .expect("fixture : semis");
    }

    fn be6_sql(conn: &Connection, sql: &str) {
        conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    /// Le déclencheur qui refuse toute mise à jour d'une riposte, avec `BE6_MESSAGE_DU_DECLENCHEUR`.
    fn be6_poser_le_declencheur(conn: &Connection) {
        be6_sql(
            conn,
            &format!(
                "CREATE TRIGGER be6_refus BEFORE UPDATE ON action BEGIN SELECT RAISE(ABORT, '{}'); END;",
                BE6_MESSAGE_DU_DECLENCHEUR.replace('\'', "''")
            ),
        );
    }

    fn be6_casser_la_fiche(conn: &Connection) {
        be6_sql(conn, "UPDATE risk_rollup SET score=x'FF' WHERE entity='be6-h'; ALTER TABLE risk_event RENAME TO be6_risk_event_a_l_ecart;");
    }

    fn be6_reparer_la_fiche(conn: &Connection) {
        be6_sql(conn, "UPDATE risk_rollup SET score=10 WHERE entity='be6-h'; ALTER TABLE be6_risk_event_a_l_ecart RENAME TO risk_event;");
    }

    /// Le texte que rend la lecture d'une colonne `nom` BLOB à l'index `index` (reproduit en mémoire, même mappeur).
    fn be6_texte_du_blob(index: usize, nom: &str) -> String {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        let colonnes: Vec<String> = (0..=index).map(|i| if i == index { nom.to_string() } else { format!("c{i}") }).collect();
        c.execute_batch(&format!("CREATE TABLE t({}); INSERT INTO t({}) VALUES({}x'FF');", colonnes.join(","), colonnes.join(","), "'x',".repeat(index)))
            .expect("instrument : table");
        c.query_row(&format!("SELECT {} FROM t", colonnes.join(",")), [], |r| {
            for i in 0..index {
                r.get::<_, String>(i)?;
            }
            r.get::<_, i64>(index)
        })
        .err()
        .expect("instrument : la lecture du BLOB échoue")
        .to_string()
    }

    /// La nature qu'un échec laisse au journal de l'essai : son code SQLite, jamais son message.
    fn be6_nature(e: &rusqlite::Error) -> String {
        match e {
            rusqlite::Error::SqliteFailure(f, _) => format!("code SQLite {} ({:?})", f.extended_code, f.code),
            autre => panic!("instrument : erreur sans code SQLite : {autre}"),
        }
    }

    /// L'erreur que rend au pas une fonction scalaire qui échoue sous le code `code` (reproduit en mémoire).
    fn be6_erreur_au_pas(code: i32) -> rusqlite::Error {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        c.create_scalar_function("be6_erreur", 1, rusqlite::functions::FunctionFlags::SQLITE_UTF8, |ctx| -> rusqlite::Result<i64> {
            Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(ctx.get::<i32>(0)?), None))
        })
        .expect("instrument : fonction d'erreur");
        c.query_row(&format!("SELECT be6_erreur({code})"), [], |r| r.get::<_, i64>(0)).err().expect("instrument : l'erreur est rendue au pas")
    }

    /// Le refus que la panne `RefusDeLAutorisateur` fait rendre (lecture d'`event.message`), reproduit en mémoire.
    fn be6_refus_de_l_autorisateur() -> rusqlite::Error {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        c.execute_batch("CREATE TABLE event(message TEXT);").expect("instrument : table");
        c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "event" && column_name == "message" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        c.prepare("SELECT message FROM event").err().expect("instrument : le refus a lieu")
    }

    fn be6_vider_le_pool(chemin: &str) {
        while crate::query_exec::connexions_de_lecture_au_repos(chemin) > 0 {
            drop(crate::query_exec::read_conn_get(chemin).expect("fixture : connexion au repos"));
        }
    }

    fn be6_corps_de_l_essai() -> Value {
        json!({ "query": BE6_SOQL, "is_soql": true, "op": ">", "threshold": 0.0, "window_s": 3600 })
    }

    /// Les quatre classes de l'essai : (issue, panne, phrase servie sous `error`).
    fn be6_classes_de_l_essai() -> Vec<(&'static str, PanneAuCoeur, String)> {
        vec![
            ("support", PanneAuCoeur::ErreurDuSupport, CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE.to_string()),
            ("occupee", PanneAuCoeur::BaseOccupee, CAUSE_REQUETE_NON_SERVIE_BASE_OCCUPEE.to_string()),
            ("produit", PanneAuCoeur::Interruption, format!("requête interrompue (budget {} s dépassé)", crate::query_exec::query_budget_ms() / 1000)),
            ("moteur", PanneAuCoeur::RefusDeLAutorisateur, REQUETE_REJETEE_PAR_LE_MOTEUR.to_string()),
        ]
    }

    fn be6_cles(v: &Value) -> Vec<String> {
        let mut c: Vec<String> = v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        c.sort();
        c
    }

    /// Un 503 `{error, id}` exactement, la cause exacte, un identifiant de corrélation.
    fn be6_refus_503(contexte: &str, (code, corps, brut): &(u16, Value, String), cause: &str) {
        assert_eq!(*code, 503, "{contexte} : statut : {brut}");
        assert_eq!(be6_cles(corps), vec!["error", "id"], "{contexte} : exactement `error` et `id` : {brut}");
        assert_eq!(corps["error"], json!(cause), "{contexte} : la cause exacte : {brut}");
        assert!(corps["id"].as_str().unwrap_or("").starts_with("plume-e"), "{contexte} : identifiant de corrélation : {brut}");
    }

    /// Une requête à travers le routeur réel : statut, corps JSON (corps `chunked` recollé), réponse brute.
    async fn be6_envoyer(addr: std::net::SocketAddr, methode: &str, chemin: &str, authz: &str, corps: &str) -> (u16, Value, String) {
        let entetes = [("Content-Type", "application/json")];
        let (code, brut) = router_probe_envoi(addr, methode, chemin, Some(authz), &entetes, corps).await;
        let (tete, c) = brut.split_once("\r\n\r\n").unwrap_or(("", ""));
        let octets: Vec<u8> = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            shell_decouper(c.as_bytes()).unwrap_or_else(|| panic!("trame chunked incomplète : {brut}"))
        } else {
            c.as_bytes().to_vec()
        };
        let texte = String::from_utf8_lossy(&octets).into_owned();
        (code, serde_json::from_str(&texte).unwrap_or(Value::Null), brut)
    }

    /// Aucun octet de la réponse ne porte un des textes du moteur que la fixture fait rendre.
    fn be6_sans_texte_du_moteur(contexte: &str, brut: &str) {
        for texte in ["Invalid column type", "Blob", "no such table", "be6 refus", "ligne forgée", "prohibited", "not authorized", "disk I/O", "locked", "prepare:"] {
            assert!(!brut.contains(texte), "{contexte} : la réponse porte le texte du moteur « {texte} » : {brut}");
        }
    }

    // ── (1) PAR LA ROUTE ─────────────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn be6_par_la_route_corps_entiers() {
        let _env = VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent leur configuration
        let (st, _base) = router_test_state("be6-route");
        {
            let conn = st.db.lock();
            be6_semer(&conn);
            conn.execute("INSERT INTO user(name,hash,role) VALUES('edt-be6',?1,'editor')", params![hash_pw(BE6_MDP_EDITEUR).unwrap()])
                .expect("fixture : compte éditeur");
            conn.execute(
                "INSERT INTO token(name,token_hash,created,host) VALUES('agent-be6',?1,?2,?3)",
                params![sha256_hex(BE6_JETON_D_AGENT.as_bytes()), now(), BE6_HOTE],
            )
            .expect("fixture : jeton d'agent");
        }
        let chemin = st.db_path.as_ref().clone();
        let addr = router_serve(st.clone()).await;
        let b64 = |s: &str| format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(s));
        let admin = b64("root:rootpw1234567");
        let editeur = b64(&format!("edt-be6:{BE6_MDP_EDITEUR}"));
        let lecteur = viewer_authz();
        let agent = format!("Bearer {BE6_JETON_D_AGENT}");
        let verdict = |id: i64| json!({ "id": id, "status": "done", "result": "ok" }).to_string();

        // RIPOSTES — contrôle positif : une riposte lue s'approuve.
        let r = be6_envoyer(addr, "POST", "/api/actions/4100/approve", &admin, "").await;
        assert_eq!(r.0, 204, "contrôle : l'approbation nominale passe : {}", r.2);
        // Lecture non faite (cible BLOB).
        let r = be6_envoyer(addr, "POST", "/api/actions/4101/approve", &admin, "").await;
        be6_refus_503("approbation, relecture", &r, &format!("{CAUSE_RIPOSTE_NON_LUE} ({BE6_CAUSE_AU_JOURNAL})"));
        be6_sans_texte_du_moteur("approbation, relecture", &r.2);
        // Écritures refusées par le déclencheur.
        be6_poser_le_declencheur(&st.db.lock());
        let r = be6_envoyer(addr, "POST", "/api/actions/4102/approve", &admin, "").await;
        be6_refus_503("approbation, écriture", &r, &format!("{CAUSE_APPROBATION_NON_ENREGISTREE} ({BE6_CAUSE_AU_JOURNAL})"));
        be6_sans_texte_du_moteur("approbation, écriture", &r.2);
        let r = be6_envoyer(addr, "POST", "/api/actions/4103/cancel", &admin, "").await;
        be6_refus_503("annulation", &r, &format!("{CAUSE_ANNULATION_NON_ENREGISTREE} ({BE6_CAUSE_AU_JOURNAL})"));
        be6_sans_texte_du_moteur("annulation", &r.2);
        let r = be6_envoyer(addr, "POST", "/api/actions/result", &agent, &verdict(4104)).await;
        be6_refus_503("verdict de l'agent", &r, &format!("{CAUSE_RESULTAT_NON_ENREGISTRE} ({BE6_CAUSE_AU_JOURNAL})"));
        be6_sans_texte_du_moteur("verdict de l'agent", &r.2);
        // Contrôles positifs, déclencheur retiré : annulation et verdict pris.
        be6_sql(&st.db.lock(), "DROP TRIGGER be6_refus;");
        let r = be6_envoyer(addr, "POST", "/api/actions/4103/cancel", &admin, "").await;
        assert_eq!(r.0, 204, "contrôle : l'annulation nominale passe : {}", r.2);
        let r = be6_envoyer(addr, "POST", "/api/actions/result", &agent, &verdict(4105)).await;
        assert_eq!((r.0, r.1.clone()), (200, json!({ "ok": true })), "contrôle : le verdict nominal est pris : {}", r.2);

        // FICHE DE RISQUE — contrôle positif, puis les trois aveux.
        let r = be6_envoyer(addr, "GET", "/api/risk/entity/host/be6-h", &lecteur, "").await;
        assert_eq!(r.0, 200, "contrôle : fiche servie : {}", r.2);
        assert!(r.1["summary"].is_object() && r.1.get("summary_error").is_none() && r.1.get("timeline_error").is_none() && r.1.get("contributions_error").is_none(), "contrôle : fiche sans aveu : {}", r.2);
        be6_casser_la_fiche(&st.db.lock());
        let r = be6_envoyer(addr, "GET", "/api/risk/entity/host/be6-h", &lecteur, "").await;
        be6_reparer_la_fiche(&st.db.lock());
        assert_eq!(r.0, 200, "fiche : un deux cents qui avoue : {}", r.2);
        assert_eq!(
            r.1,
            json!({
                "entity_type": "host", "entity": "be6-h", "summary": null, "timeline": null, "contributions": null,
                "summary_error": format!("synthèse de risque NON LUE : {BE6_CAUSE_AU_JOURNAL} — ce n'est PAS « aucun risque cumulé » pour cette entité"),
                "timeline_error": format!("ligne de temps du risque NON LUE : {BE6_CAUSE_AU_JOURNAL}"),
                "contributions_error": format!("contributions du risque NON LUES : {BE6_CAUSE_AU_JOURNAL}"),
                "lecture_non_faite": true,
            }),
            "fiche : corps entier : {}",
            r.2
        );
        be6_sans_texte_du_moteur("fiche de risque", &r.2);

        // REPARSE — contrôle positif, puis la préparation refusée.
        let r = be6_envoyer(addr, "POST", "/api/parsers/reparse", &admin, &json!({ "dry_run": true }).to_string()).await;
        assert_eq!(r.0, 200, "contrôle : aperçu du reparse servi : {}", r.2);
        be6_sql(&st.db.lock(), "ALTER TABLE event RENAME TO be6_event_a_l_ecart;");
        let r = be6_envoyer(addr, "POST", "/api/parsers/reparse", &admin, &json!({ "dry_run": true }).to_string()).await;
        be6_sql(&st.db.lock(), "ALTER TABLE be6_event_a_l_ecart RENAME TO event;");
        be6_refus_503("reparse non préparé", &r, BE6_REPARSE_NON_PREPARE);
        be6_sans_texte_du_moteur("reparse non préparé", &r.2);

        // ESSAI DE RÈGLE — contrôle positif, puis une panne par classe, armée au cœur d'exécution.
        let r = be6_envoyer(addr, "POST", "/api/rule-test", &editeur, &be6_corps_de_l_essai().to_string()).await;
        assert_eq!(r.0, 200, "contrôle : essai nominal : {}", r.2);
        assert_eq!(r.1["value"].as_f64(), Some(1.0), "contrôle : l'event semé est compté : {}", r.2);
        let classes = be6_classes_de_l_essai();
        assert!(classes.len() >= 4, "plancher : quatre classes");
        for (issue, panne, phrase) in classes {
            be6_vider_le_pool(&chemin);
            demander(&chemin, panne);
            let r = be6_envoyer(addr, "POST", "/api/rule-test", &editeur, &be6_corps_de_l_essai().to_string()).await;
            let armee = !encore_demandee(&chemin);
            retirer(&chemin);
            be6_vider_le_pool(&chemin);
            assert!(armee, "{issue} : la panne a servi (sinon ce témoin ne conclut pas)");
            assert_eq!(r.0, 200, "{issue} : l'essai garde son deux cents formé : {}", r.2);
            assert_eq!(be6_cles(&r.1), vec!["error", "sql"], "{issue} : exactement `error` et `sql` : {}", r.2);
            assert_eq!(r.1["error"], json!(phrase), "{issue} : la phrase de la classe : {}", r.2);
            assert!(r.1["sql"].is_string(), "{issue} : le SQL compilé reste servi : {}", r.2);
            be6_sans_texte_du_moteur(issue, &r.2);
        }
    }

    // ── (2) DEUX TENANTS, LE JOURNAL ────────────────────────────────────────────────────────────────────────────

    fn be6_au(role: &str, nom: &str, tenant: &str) -> AuthUser {
        AuthUser { name: nom.into(), role: role.into(), tenant: tenant.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }

    async fn be6_statut(r: Response) -> u16 {
        r.status().as_u16()
    }

    /// Joue, sur le tenant `t`, chaque refus de ce lot ; rend le nombre de refus joués.
    async fn be6_jouer_sur(st: &AppState, t: &str, chemin: &str) -> usize {
        let h = st.tenants.handle_for(t).expect("contrôle : base du tenant");
        let admin = be6_au("admin", "adm-be6", t);
        let mut joues = 0usize;
        assert_eq!(be6_statut(action_approve(State(st.clone()), Extension(admin.clone()), Path(4101)).await).await, 503, "{t} : relecture refusée");
        joues += 1;
        be6_poser_le_declencheur(&h.lock());
        assert_eq!(be6_statut(action_approve(State(st.clone()), Extension(admin.clone()), Path(4102)).await).await, 503, "{t} : approbation refusée");
        assert_eq!(be6_statut(action_cancel(State(st.clone()), Extension(admin.clone()), Path(4103)).await).await, 503, "{t} : annulation refusée");
        let agent = be6_au("agent", BE6_HOTE, t);
        let r = action_result(State(st.clone()), Extension(agent), Json(json!({ "id": 4104, "status": "done", "result": "ok" }))).await;
        assert_eq!(be6_statut(r).await, 503, "{t} : verdict refusé");
        joues += 3;
        be6_sql(&h.lock(), "DROP TRIGGER be6_refus;");
        be6_casser_la_fiche(&h.lock());
        let fiche = risk_entity_timeline(State(st.clone()), Extension(be6_au("viewer", "lec-be6", t)), Path(("host".to_string(), "be6-h".to_string()))).await;
        be6_reparer_la_fiche(&h.lock());
        assert_eq!(fiche.0["lecture_non_faite"], json!(true), "{t} : fiche qui avoue");
        joues += 3;
        be6_sql(&h.lock(), "ALTER TABLE event RENAME TO be6_event_a_l_ecart;");
        let r = parser_reparse(State(st.clone()), Extension(admin.clone()), Json(json!({ "dry_run": true }))).await;
        be6_sql(&h.lock(), "ALTER TABLE be6_event_a_l_ecart RENAME TO event;");
        assert_eq!(be6_statut(r).await, 503, "{t} : reparse non préparé");
        joues += 1;
        for (issue, panne, _) in be6_classes_de_l_essai() {
            be6_vider_le_pool(chemin);
            demander(chemin, panne);
            let r = rule_test_adhoc(State(st.clone()), Extension(be6_au("editor", "edt-be6", t)), Json(be6_corps_de_l_essai())).await;
            let armee = !encore_demandee(chemin);
            retirer(chemin);
            be6_vider_le_pool(chemin);
            assert!(armee, "{t}/{issue} : la panne a servi");
            assert_eq!(be6_statut(r).await, 200, "{t}/{issue} : essai formé");
            joues += 1;
        }
        joues
    }

    /// Les lignes attendues pour le tenant `t`, dans l'ordre de `be6_jouer_sur`.
    fn be6_lignes_attendues(t: &str) -> Vec<String> {
        let declencheur = format!("{BE6_MESSAGE_DU_DECLENCHEUR:?}");
        let table_risque = format!("{:?}", "no such table: risk_event");
        vec![
            format!("[actions] WARN riposte #4101 NON relue, rien n'est approuvé (tenant '{t}') : {:?}", be6_texte_du_blob(1, "target")),
            format!("[actions] WARN approbation de la riposte #4102 NON écrite (tenant '{t}') : {declencheur}"),
            format!("[actions] WARN annulation de la riposte #4103 NON écrite (tenant '{t}') : {declencheur}"),
            format!("[actions] WARN verdict de l'agent NON écrit, riposte #4104 restée ouverte (tenant '{t}') : {declencheur}"),
            format!("[rba] WARN synthèse de risque NON LUE (tenant '{t}') : {:?}", be6_texte_du_blob(0, "score")),
            format!("[rba] WARN ligne de temps du risque NON LUE (tenant '{t}') : {table_risque}"),
            format!("[rba] WARN contributions du risque NON LUES (tenant '{t}') : {table_risque}"),
            format!("[reparse] WARN parcours des events NON préparé, rien n'est lu ni écrit (tenant '{t}') : {:?}", "no such table: event"),
            format!(
                "[detection] WARN essai de règle non exécuté, erreur du support de la base (/api/rule-test, tenant '{t}') : {}",
                be6_nature(&be6_erreur_au_pas(rusqlite::ffi::SQLITE_IOERR_READ))
            ),
            format!(
                "[detection] WARN essai de règle non exécuté, base occupée (/api/rule-test, tenant '{t}') : {}",
                be6_nature(&be6_erreur_au_pas(rusqlite::ffi::SQLITE_BUSY))
            ),
            format!(
                "[detection] WARN essai de règle non exécuté, requête rejetée par le moteur (/api/rule-test, tenant '{t}') : {}",
                be6_nature(&be6_refus_de_l_autorisateur())
            ),
        ]
    }

    /// Les lignes de journal de ce lot, et elles seules.
    fn be6_journal(stderr: &str) -> Vec<String> {
        let prefixes = ["[actions] WARN ", "[rba] WARN ", "[reparse] WARN ", "[detection] WARN essai de règle"];
        // Une ligne forgée (retour à la ligne non échappé) commencerait par un morceau du message : elle est gardée aussi.
        stderr
            .lines()
            .filter(|l| prefixes.iter().any(|p| l.starts_with(p)) || l.starts_with("ligne forgée") || l.contains("\"guillemet\""))
            .map(str::to_string)
            .collect()
    }

    #[tokio::test]
    async fn be6_deux_tenants_journal_entier() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(BE6_ENFANT).is_ok() {
            let (st, _dir) = mk_mode1_state();
            let mut chemins = Vec::new();
            for t in [BE6_ALPHA, BE6_BETA] {
                let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-be6")), Json(json!({ "id": t, "name": t }))).await;
                assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
                be6_semer(&st.tenants.handle_for(t).expect("contrôle : base du tenant").lock());
                chemins.push(st.tenants.ready_db_path(t).expect("contrôle : chemin de la base du tenant"));
            }
            assert_ne!(chemins[0], chemins[1], "contrôle : deux bases distinctes");
            let mut joues = be6_jouer_sur(&st, BE6_ALPHA, &chemins[0]).await;
            joues += be6_jouer_sur(&st, BE6_BETA, &chemins[1]).await;
            println!("{BE6_FIN} {joues}");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::be6_texte_du_moteur_hors_des_ripostes_du_risque_et_des_essais::be6_deux_tenants_journal_entier",
            ])
            .env(BE6_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(&format!("{BE6_FIN} 24")), "contrôle : douze refus joués par tenant : {stdout}\n{stderr}");
        let mut attendu = be6_lignes_attendues(BE6_ALPHA);
        attendu.extend(be6_lignes_attendues(BE6_BETA));
        assert!(attendu.len() >= 22, "plancher : onze lignes par tenant ({})", attendu.len());
        assert_eq!(be6_journal(&stderr), attendu, "une ligne EXACTE par refus, tenant de l'appelant, aucune pour la phrase du produit :\n{stderr}");
    }
}
