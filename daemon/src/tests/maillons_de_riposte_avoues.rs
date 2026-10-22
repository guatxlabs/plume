// =====================================================================================
// `P10.31-u` (reste : les appels nus de `ledger_append` dans `handlers/actions.rs`) —
// UN MAILLON DE RIPOSTE QUI N'EST PAS ENTRÉ AU REGISTRE SE DIT, ET IL N'ANNULE RIEN.
//
// LE DÉFAUT, MESURÉ SUR aa19c5fa AVANT LE CORRECTIF. Onze appels de `ledger_append` posaient leur maillon
// sans lire l'issue : le verdict d'agent (`action_result`, `action.remote`, puis `{"ok": true}`), le
// miroir HTTP de l'approbation (`netban.forme`, `netban.plafond`, `netban.non-arme`), celui du responder
// (les trois mêmes, dans `miroir_http_du_responder`), le ban manuel refusé (`netban_add` : plafond et
// pose non écrite) et les deux verdicts du responder qui ne clôturent pas (`action.exec.verdict-non-ecrit`,
// `action.exec.verdict-conserve`/`-non-relu`). Pour la plupart, ce maillon EST la seule trace d'un ban
// perdu ou refusé. CE QUE L'ÉNONCÉ AVAIT DE TROP : « sans aveu ». La primitive (`ledger.rs`) écrit déjà
// `[ledger] WARN maillon '<genre>' NON inscrit …` sur la sortie d'erreur, mais par son seul genre :
// rien ne disait quelle action, et la réponse au verdict d'agent affirmait `ok: true` sans réserve.
//
// LE CORRECTIF (décision par défaut de la vague AC). Chaque maillon est lu (`cause_de_non_inscription`) ;
// manquant, il écrit une ligne `[<sujet>] WARN <geste> : le registre n'a PAS pris le maillon `<genre>`
// (<cause du moteur>)` qui porte l'identifiant de l'action (ou le geste, pour un ban manuel) et JAMAIS la
// cible. Rien n'est annulé. Sur le succès servi d'`action_result`, `registre_sans_maillon` s'ajoute à
// `ok: true` ; les refus déjà servis (503, 507) et les 204 de l'approbation ne changent pas ; le
// responder rend la ligne de son miroir à `respond_run`, qui l'émet comme l'aveu de la levée.
//
// LES PANNES ÉPROUVÉES : déclencheurs `RAISE(ABORT)` sur `BEFORE INSERT ON ledger` filtrés par genre, sur
// `BEFORE INSERT ON net_ban` (pose non écrite) et `BEFORE UPDATE ON action` (clôture refusée) ;
// `RAISE(IGNORE)` sur la clôture pour le verdict conservé ; le store live rempli pour le plafond. Les
// lignes de journal sont lues sur le stderr d'un sous-processus ; `respond_run` y est joué de bout en bout
// (plateforme `generic-appliance`, gabarit `true {pid}` : aucune commande système réelle).
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : `AC1_REMOTE_JETE`, `AC1_REMOTE_SANS_CLE`,
// `AC1_REMOTE_SANS_JOURNAL`, `AC1_REMOTE_CLE_SANS_PANNE`, `AC1_APPROVE_FORME`, `AC1_APPROVE_PLAFOND`,
// `AC1_APPROVE_NON_ARME`, `AC1_RESPONDER_FORME`, `AC1_RESPONDER_PLAFOND`, `AC1_RESPONDER_NON_ARME`,
// `AC1_NETBAN_PLAFOND`, `AC1_NETBAN_NON_ARME`, `AC1_RESPONDER_VERDICT_NON_ECRIT`,
// `AC1_RESPONDER_VERDICT_CONSERVE` ; puis, après la première vérification : `AC1C_NN_CLE` (une clé de trop
// sur le 503 de `netban_add`), `AC1C_GENRE_NON_RELU`, `AC1C_GESTE_DISPARUE`, `AC1C_GESTE_NON_RELU`.
//
// LES TROIS ISSUES DU VERDICT CONSERVÉ SONT JOUÉES : relu (`RAISE(IGNORE)`), ligne disparue (le déclencheur
// de clôture supprime la ligne avant d'ignorer l'écriture) et relecture ratée (il y pose un blob dans
// `status`, que la relecture typée en `String` refuse) ; chacune dit au journal ce qui s'est passé.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la console n'affiche pas `registre_sans_maillon` (la route du
// verdict d'agent n'est lue que par l'agent, qui ne lit que `ok`).
// =====================================================================================
mod maillons_de_riposte_avoues {
    use super::*;

    const AC1_MOTEUR_REGISTRE: &str = "registre hors d atteinte (temoin AC1)";
    const AC1_MOTEUR_POSE: &str = "pose refusee (temoin AC1)";
    const AC1_MOTEUR_CLOTURE: &str = "cloture refusee (temoin AC1)";
    const AC1_TETE_DE_LIGNE: &str = "le registre n'a PAS pris le maillon";

    fn ac1_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("ac1-{tag}"));
        ac1_base(&chemin);
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn ac1_base(chemin: &str) {
        let conn = open_db(chemin).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture `P10.31-u` : la chaîne de migrations doit aller au bout");
        conn.execute("DELETE FROM action", []).unwrap();
        conn.execute("DELETE FROM net_ban", []).unwrap();
    }

    fn ac1_admin() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn ac1_agent() -> AuthUser {
        AuthUser {
            name: "hote-ac1".into(), role: "agent".into(), tenant: "default".into(), is_superadmin: false,
            method: "token".into(), csrf: String::new(), env: None,
        }
    }

    fn ac1_sql(conn: &Connection, sql: &str) {
        conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ac1_compte(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn ac1_riposte(conn: &Connection, kind: &str, target: &str, statut: &str, hote: &str) -> i64 {
        conn.execute(
            "INSERT INTO action(ts,kind,target,status,dry_run,host) VALUES(1000,?1,?2,?3,0,?4)",
            params![kind, target, statut, hote],
        )
        .expect("fixture : la riposte s'insère");
        conn.last_insert_rowid()
    }

    /// Le registre refuse le maillon de CE genre, et lui seul.
    fn ac1_registre_refuse(conn: &Connection, genre: &str) {
        ac1_sql(
            conn,
            &format!(
                "CREATE TRIGGER ac1_registre_refuse BEFORE INSERT ON ledger WHEN NEW.kind='{genre}' \
                 BEGIN SELECT RAISE(ABORT, '{AC1_MOTEUR_REGISTRE}'); END;"
            ),
        );
    }

    fn ac1_registre_repare(conn: &Connection) {
        ac1_sql(conn, "DROP TRIGGER IF EXISTS ac1_registre_refuse;");
    }

    fn ac1_pose_refusee(conn: &Connection) {
        ac1_sql(
            conn,
            &format!("CREATE TRIGGER ac1_pose_refusee BEFORE INSERT ON net_ban BEGIN SELECT RAISE(ABORT, '{AC1_MOTEUR_POSE}'); END;"),
        );
    }

    fn ac1_store_plein() {
        let mut c = netban_cache().write();
        c.clear();
        for i in 0..NETBAN_CACHE_CAP {
            c.insert(format!("2001:db8::{i:x}"), None);
        }
    }

    fn ac1_ligne(sujet: &str, geste: &str, genre: &str, cause: &str) -> String {
        format!("[{sujet}] WARN {geste} : {AC1_TETE_DE_LIGNE} `{genre}` ({cause})")
    }

    /// Les clés d'un corps JSON, triées : un corps de refus se juge en entier, pas clé par clé.
    fn ac1_cles(v: &Value) -> Vec<String> {
        let mut cles: Vec<String> = v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        cles.sort();
        cles
    }

    async fn ac1_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    async fn ac1_verdict(st: &AppState, id: i64) -> (u16, String, Value) {
        ac1_reponse(action_result(State(st.clone()), Extension(ac1_agent()), Json(json!({ "id": id, "status": "done", "result": "ok" }))).await).await
    }

    async fn ac1_approuver(st: &AppState, id: i64) -> (u16, String, Value) {
        ac1_reponse(action_approve(State(st.clone()), Extension(ac1_admin()), Path(id)).await).await
    }

    async fn ac1_ban_manuel(st: &AppState, ip: &str) -> (u16, String, Value) {
        ac1_reponse(netban_add(State(st.clone()), Extension(ac1_admin()), Json(json!({ "ip": ip, "ttl_s": 600 }))).await).await
    }

    /// CE QU'IL TIENT : le verdict d'agent écrit dont le maillon `action.remote` n'est pas entré rend 200
    /// `{ok: true, registre_sans_maillon: CAUSE_GESTE_SANS_TRACE (<moteur>)}` — deux clés exactement, sans
    /// l'hôte —, la riposte est bien close (`done`, horodatée) et rien n'est au registre. Contrôles : le
    /// verdict nominal rend `{"ok":true}` octet pour octet avec son maillon, l'absence rend `{"ok":false}`.
    /// MUTATIONS : `AC1_REMOTE_JETE`, `AC1_REMOTE_SANS_CLE`, `AC1_REMOTE_CLE_SANS_PANNE`.
    #[tokio::test]
    async fn ac1_verdict_d_agent_sans_maillon_avoue_a_cote_de_ok() {
        let (st, _tmp) = ac1_etat("verdict-agent");
        let (sans_trace, nominal) = {
            let conn = st.db.lock();
            (ac1_riposte(&conn, "ban_ip", "203.0.113.41", "approved", "hote-ac1"), ac1_riposte(&conn, "ban_ip", "203.0.113.42", "approved", "hote-ac1"))
        };
        ac1_registre_refuse(&st.db.lock(), "action.remote");
        let (statut, corps, v) = ac1_verdict(&st, sans_trace).await;
        assert_eq!(statut, 200, "le verdict est écrit : un succès, jamais un refus : {corps}");
        assert_eq!(v["ok"], json!(true), "`ok` reste vrai, l'agent passe à la suivante : {corps}");
        let aveu = v[CLE_REGISTRE_SANS_MAILLON].as_str().unwrap_or_else(|| panic!("l'aveu du maillon manquant est servi : {corps}"));
        assert_eq!(aveu, format!("{CAUSE_GESTE_SANS_TRACE} ({AC1_MOTEUR_REGISTRE})"), "phrase partagée et cause du moteur");
        assert_eq!(v.as_object().map(|o| o.len()), Some(2), "deux clés, rien d'autre : {corps}");
        assert!(!corps.contains("hote-ac1") && !corps.contains("203.0.113"), "ni l'hôte ni la cible : {corps}");
        {
            let conn = st.db.lock();
            assert_eq!(
                ac1_compte(&conn, &format!("SELECT COUNT(*) FROM action WHERE id={sans_trace} AND status='done' AND done_ts IS NOT NULL")),
                1,
                "le verdict n'est pas annulé"
            );
            assert_eq!(ac1_compte(&conn, "SELECT COUNT(*) FROM ledger WHERE kind='action.remote'"), 0, "fixture : le maillon a bien manqué");
        }
        ac1_registre_repare(&st.db.lock());
        let (statut, corps, _) = ac1_verdict(&st, nominal).await;
        assert_eq!((statut, corps.as_str()), (200, r#"{"ok":true}"#), "nominal : corps d'avant, octet pour octet");
        assert_eq!(ac1_compte(&st.db.lock(), "SELECT COUNT(*) FROM ledger WHERE kind='action.remote'"), 1, "nominal : le maillon est entré");
        let (statut, corps, _) = ac1_verdict(&st, nominal).await;
        assert_eq!((statut, corps.as_str()), (200, r#"{"ok":false}"#), "riposte déjà close : l'absence d'avant");
    }

    /// CE QU'IL TIENT : sur l'approbation, un maillon de miroir manquant ne change pas la réponse — 204
    /// pour la cible inanalysable et pour le plafond, 503 `CAUSE_BAN_NON_ARME (<moteur de la pose>)` exact
    /// et sans `registre_sans_maillon` pour la pose non écrite —, et la riposte reste `approved`. Sur
    /// `netban_add`, le 507 du plafond et le 503 de la pose non écrite gardent leur corps exact. Chaque refus
    /// est jugé en entier : exactement `{error, id}` (l'identifiant de `err_json`), rien d'autre.
    /// MUTATION : `AC1C_NN_CLE`.
    #[tokio::test]
    async fn ac1_un_maillon_de_miroir_manquant_ne_change_aucune_reponse() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        crate::ledger::declarer_la_liste_pour_ce_temoin();
        netban_cache().write().clear();
        let (st, _tmp) = ac1_etat("reponses");
        let (forme, plafond, non_arme) = {
            let conn = st.db.lock();
            (
                ac1_riposte(&conn, "ban_ip", "pas-une-adresse", "pending", ""),
                ac1_riposte(&conn, "ban_ip", "203.0.113.43", "pending", ""),
                ac1_riposte(&conn, "ban_ip", "203.0.113.44", "pending", ""),
            )
        };
        ac1_registre_refuse(&st.db.lock(), "netban.forme");
        let (statut, corps, _) = ac1_approuver(&st, forme).await;
        assert_eq!((statut, corps.as_str()), (204, ""), "cible inanalysable : le 204 d'avant");
        ac1_registre_repare(&st.db.lock());
        ac1_registre_refuse(&st.db.lock(), "netban.plafond");
        ac1_store_plein();
        let (statut, corps, _) = ac1_approuver(&st, plafond).await;
        assert_eq!((statut, corps.as_str()), (204, ""), "plafond : le 204 d'avant");
        let (statut, corps, v) = ac1_ban_manuel(&st, "203.0.113.45").await;
        assert_eq!(statut, 507, "ban manuel sur store plein : le 507 d'avant : {corps}");
        assert_eq!(
            v["error"].as_str(),
            Some(format!("store de bans plein ({NETBAN_CACHE_CAP} IP) — libérer par DELETE /api/netban/{{ip}}, ou bloquer en amont (pare-feu/CDN)").as_str()),
            "le corps du 507 ne change pas : {corps}"
        );
        assert_eq!(ac1_cles(&v), ["error", "id"], "le 507 entier, sans l'aveu : {corps}");
        netban_cache().write().clear();
        ac1_registre_repare(&st.db.lock());
        ac1_registre_refuse(&st.db.lock(), "netban.non-arme");
        ac1_pose_refusee(&st.db.lock());
        let (statut, corps, v) = ac1_approuver(&st, non_arme).await;
        assert_eq!(statut, 503, "pose non écrite : le 503 d'avant : {corps}");
        assert_eq!(v["error"].as_str(), Some(format!("{CAUSE_BAN_NON_ARME} ({AC1_MOTEUR_POSE})").as_str()), "corps exact : {corps}");
        assert_eq!(ac1_cles(&v), ["error", "id"], "le 503 de l'approbation entier, sans l'aveu : {corps}");
        let (statut, corps, v) = ac1_ban_manuel(&st, "203.0.113.46").await;
        assert_eq!(statut, 503, "ban manuel non écrit : le 503 d'avant : {corps}");
        assert_eq!(v["error"].as_str(), Some(format!("{CAUSE_BAN_NON_ARME} ({AC1_MOTEUR_POSE})").as_str()), "corps exact : {corps}");
        assert_eq!(ac1_cles(&v), ["error", "id"], "le 503 du ban manuel entier, sans l'aveu : {corps}");
        let conn = st.db.lock();
        assert_eq!(
            ac1_compte(&conn, &format!("SELECT COUNT(*) FROM action WHERE id IN ({forme},{plafond},{non_arme}) AND status='approved'")),
            3,
            "aucune approbation n'est annulée"
        );
        assert_eq!(
            ac1_compte(&conn, "SELECT COUNT(*) FROM ledger WHERE kind IN ('netban.forme','netban.plafond','netban.non-arme')"),
            0,
            "fixture : les trois maillons ont bien manqué"
        );
        drop(conn);
        netban_cache().write().clear();
    }

    /// CE QU'IL TIENT : le miroir du responder REND la ligne d'un maillon manquant (cible inanalysable,
    /// plafond, pose non écrite), avec l'identifiant de l'action et la cause du moteur, sans la cible ;
    /// `respond_run` l'émet par le câblage tenu dans `levee_de_ban_issue_consommee`. Contrôles : maillon
    /// entré -> `None`. MUTATIONS : `AC1_RESPONDER_FORME`, `AC1_RESPONDER_PLAFOND`, `AC1_RESPONDER_NON_ARME`.
    #[test]
    fn ac1_le_miroir_du_responder_rend_la_ligne_d_un_maillon_manquant() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let (st, _tmp) = ac1_etat("miroir-responder");
        let miroir = |target: &str| miroir_http_du_responder(&st.db.lock(), 31, "ban_ip", target, "done", false);

        assert_eq!(miroir("pas-une-adresse"), None, "contrôle : maillon `netban.forme` entré, rien à dire");
        ac1_registre_refuse(&st.db.lock(), "netban.forme");
        assert_eq!(
            miroir("pas-une-adresse"),
            Some(ac1_ligne("responder", "action 31 exécutée : cible inanalysable, aucun miroir HTTP", "netban.forme", AC1_MOTEUR_REGISTRE))
        );
        ac1_registre_repare(&st.db.lock());

        ac1_store_plein();
        assert_eq!(miroir("203.0.113.47"), None, "contrôle : maillon `netban.plafond` entré");
        ac1_registre_refuse(&st.db.lock(), "netban.plafond");
        assert_eq!(
            miroir("203.0.113.48"),
            Some(ac1_ligne("responder", "action 31 exécutée : miroir HTTP refusé par le plafond", "netban.plafond", AC1_MOTEUR_REGISTRE))
        );
        ac1_registre_repare(&st.db.lock());
        netban_cache().write().clear();

        ac1_pose_refusee(&st.db.lock());
        assert_eq!(miroir("203.0.113.49"), None, "contrôle : maillon `netban.non-arme` entré");
        ac1_registre_refuse(&st.db.lock(), "netban.non-arme");
        let ligne = miroir("203.0.113.50");
        assert_eq!(ligne, Some(ac1_ligne("responder", "action 31 exécutée : miroir HTTP NON armé", "netban.non-arme", AC1_MOTEUR_REGISTRE)));
        assert!(!ligne.unwrap_or_default().contains("203.0.113"), "jamais la cible");
        let conn = st.db.lock();
        assert_eq!(ac1_compte(&conn, "SELECT COUNT(*) FROM ledger WHERE kind='netban.forme'"), 1, "seul le contrôle est entré");
        assert_eq!(ac1_compte(&conn, "SELECT COUNT(*) FROM ledger WHERE kind='netban.plafond'"), 1, "seul le contrôle est entré");
        assert_eq!(ac1_compte(&conn, "SELECT COUNT(*) FROM ledger WHERE kind='netban.non-arme'"), 1, "seul le contrôle est entré");
        drop(conn);
        netban_cache().write().clear();
    }

    // ── LES LIGNES DE JOURNAL, LUES SUR LE STDERR D'UN SOUS-PROCESSUS ────────────────────────────────

    const AC1_ENFANT: &str = "AC1_ENFANT_JOURNAL";
    const AC1_PHASE: &str = "AC1-PHASE:";

    /// Une phase par site HTTP ; `panne` = le registre refuse le maillon du site. Statut et identifiant sur stdout.
    async fn ac1_jouer_les_sites_http(panne: bool, suffixe: &str) {
        let refuser = |conn: &Connection, genre: &str| if panne { ac1_registre_refuse(conn, genre) };

        eprintln!("{AC1_PHASE}remote{suffixe}");
        let (st, _tmp) = ac1_etat("journal-remote");
        let id = ac1_riposte(&st.db.lock(), "ban_ip", "203.0.113.51", "approved", "hote-ac1");
        refuser(&st.db.lock(), "action.remote");
        println!("AC1-ID:remote{suffixe}:{}:{id}", ac1_verdict(&st, id).await.0);

        eprintln!("{AC1_PHASE}approve-forme{suffixe}");
        let (st, _tmp) = ac1_etat("journal-forme");
        let id = ac1_riposte(&st.db.lock(), "ban_ip", "pas-une-adresse", "pending", "");
        refuser(&st.db.lock(), "netban.forme");
        println!("AC1-ID:approve-forme{suffixe}:{}:{id}", ac1_approuver(&st, id).await.0);

        eprintln!("{AC1_PHASE}approve-plafond{suffixe}");
        let (st, _tmp) = ac1_etat("journal-plafond");
        let id = ac1_riposte(&st.db.lock(), "ban_ip", "203.0.113.52", "pending", "");
        refuser(&st.db.lock(), "netban.plafond");
        ac1_store_plein();
        println!("AC1-ID:approve-plafond{suffixe}:{}:{id}", ac1_approuver(&st, id).await.0);

        eprintln!("{AC1_PHASE}netban-plafond{suffixe}");
        println!("AC1-ID:netban-plafond{suffixe}:{}:0", ac1_ban_manuel(&st, "203.0.113.53").await.0);
        netban_cache().write().clear();

        eprintln!("{AC1_PHASE}approve-non-arme{suffixe}");
        let (st, _tmp) = ac1_etat("journal-non-arme");
        let id = ac1_riposte(&st.db.lock(), "ban_ip", "203.0.113.54", "pending", "");
        refuser(&st.db.lock(), "netban.non-arme");
        ac1_pose_refusee(&st.db.lock());
        println!("AC1-ID:approve-non-arme{suffixe}:{}:{id}", ac1_approuver(&st, id).await.0);

        eprintln!("{AC1_PHASE}netban-non-arme{suffixe}");
        println!("AC1-ID:netban-non-arme{suffixe}:{}:0", ac1_ban_manuel(&st, "203.0.113.55").await.0);
    }

    /// Les verdicts du responder qui ne clôturent pas (clôture refusée, puis les trois issues du verdict
    /// conservé), joués par `respond_run` sur la base `PLUME_DB`.
    fn ac1_jouer_le_responder(panne: bool, suffixe: &str) {
        use rusqlite::OptionalExtension as _;
        let base = std::env::var("PLUME_DB").expect("l'enfant reçoit sa base");
        let conn = open_db(&base).expect("fixture : la base du responder s'ouvre");
        // Le statut tel qu'il est : texte, sinon son type (`blob`), et `absente` si la ligne n'est plus là.
        let statut_de = |id: i64| -> String {
            conn.query_row(
                "SELECT CASE typeof(status) WHEN 'text' THEN status ELSE typeof(status) END FROM action WHERE id=?1",
                params![id],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .expect("fixture : le statut se lit")
            .unwrap_or_else(|| "absente".to_string())
        };

        eprintln!("{AC1_PHASE}responder-non-ecrit{suffixe}");
        let id = ac1_riposte(&conn, "kill_pid", "4242", "approved", "");
        ac1_sql(
            &conn,
            &format!(
                "CREATE TRIGGER ac1_cloture BEFORE UPDATE ON action WHEN NEW.status IN ('done','failed') \
                 BEGIN SELECT RAISE(ABORT, '{AC1_MOTEUR_CLOTURE}'); END;"
            ),
        );
        if panne { ac1_registre_refuse(&conn, "action.exec.verdict-non-ecrit"); }
        respond_run();
        let statut: String = conn.query_row("SELECT status FROM action WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        println!("AC1-ID:responder-non-ecrit{suffixe}:{statut}:{id}");
        ac1_sql(&conn, "DROP TRIGGER ac1_cloture;");
        ac1_registre_repare(&conn);
        conn.execute("UPDATE action SET status='failed' WHERE id=?1", params![id]).unwrap();

        eprintln!("{AC1_PHASE}responder-conserve{suffixe}");
        let id = ac1_riposte(&conn, "kill_pid", "4243", "approved", "");
        ac1_sql(
            &conn,
            "CREATE TRIGGER ac1_cloture BEFORE UPDATE ON action WHEN NEW.status IN ('done','failed') \
             BEGIN SELECT RAISE(IGNORE); END;",
        );
        if panne { ac1_registre_refuse(&conn, "action.exec.verdict-conserve"); }
        respond_run();
        println!("AC1-ID:responder-conserve{suffixe}:{}:{id}", statut_de(id));
        ac1_sql(&conn, "DROP TRIGGER ac1_cloture;");
        ac1_registre_repare(&conn);
        conn.execute("UPDATE action SET status='failed' WHERE id=?1", params![id]).unwrap();

        // La ligne disparaît entre la clôture et sa relecture : le déclencheur la supprime puis ignore l'écriture.
        eprintln!("{AC1_PHASE}responder-disparue{suffixe}");
        let id = ac1_riposte(&conn, "kill_pid", "4244", "approved", "");
        ac1_sql(
            &conn,
            "CREATE TRIGGER ac1_cloture BEFORE UPDATE ON action WHEN NEW.status IN ('done','failed') \
             BEGIN DELETE FROM action WHERE id=OLD.id; SELECT RAISE(IGNORE); END;",
        );
        if panne { ac1_registre_refuse(&conn, "action.exec.verdict-conserve"); }
        respond_run();
        println!("AC1-ID:responder-disparue{suffixe}:{}:{id}", statut_de(id));
        ac1_sql(&conn, "DROP TRIGGER ac1_cloture;");
        ac1_registre_repare(&conn);

        // La relecture échoue : le déclencheur pose un blob dans `status` puis ignore l'écriture ; la
        // relecture typée en `String` le refuse (`NonRelu`).
        eprintln!("{AC1_PHASE}responder-non-relu{suffixe}");
        let id = ac1_riposte(&conn, "kill_pid", "4245", "approved", "");
        ac1_sql(
            &conn,
            "CREATE TRIGGER ac1_cloture BEFORE UPDATE ON action WHEN NEW.status IN ('done','failed') \
             BEGIN UPDATE action SET status=X'00' WHERE id=OLD.id; SELECT RAISE(IGNORE); END;",
        );
        if panne { ac1_registre_refuse(&conn, "action.exec.verdict-non-relu"); }
        respond_run();
        println!("AC1-ID:responder-non-relu{suffixe}:{}:{id}", statut_de(id));
        ac1_sql(&conn, "DROP TRIGGER ac1_cloture;");
        ac1_registre_repare(&conn);
        conn.execute("UPDATE action SET status='failed' WHERE id=?1", params![id]).unwrap();
    }

    /// LES LIGNES DE JOURNAL des onze sites (et des trois issues du verdict conservé), lues sur le stderr d'un sous-processus : chaque maillon refusé
    /// écrit UNE ligne `[<sujet>] WARN <geste> : le registre n'a PAS pris le maillon `<genre>` (<moteur>)`
    /// qui porte l'identifiant de l'action et jamais la cible ; les mêmes sites, registre sain, n'écrivent
    /// AUCUNE ligne de ce genre. Les statuts servis sont ceux d'avant (200, 204, 507, 503) ; le responder
    /// laisse `approved` sur la clôture refusée (le tour suivant la reprendra). MUTATIONS : `AC1_REMOTE_JETE`,
    /// `AC1_REMOTE_SANS_JOURNAL`, `AC1_APPROVE_FORME`, `AC1_APPROVE_PLAFOND`, `AC1_APPROVE_NON_ARME`,
    /// `AC1_NETBAN_PLAFOND`, `AC1_NETBAN_NON_ARME`, `AC1_RESPONDER_VERDICT_NON_ECRIT`,
    /// `AC1_RESPONDER_VERDICT_CONSERVE`, `AC1C_GENRE_NON_RELU`, `AC1C_GESTE_DISPARUE`, `AC1C_GESTE_NON_RELU`.
    #[tokio::test]
    async fn ac1_lignes_de_journal_des_maillons_de_riposte_manquants() {
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(AC1_ENFANT).is_ok() {
            let _g = NETBAN_TEST_LOCK.lock();
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            netban_cache().write().clear();
            ac1_jouer_les_sites_http(true, "").await;
            ac1_jouer_le_responder(true, "");
            ac1_jouer_les_sites_http(false, "-calme").await;
            ac1_jouer_le_responder(false, "-calme");
            eprintln!("{AC1_PHASE}fin");
            return;
        }
        let base = crate::tmp_possede::TmpDb::neuf("ac1-journal-responder");
        ac1_base(&base);
        let sans_conf = format!("{}.aucune.conf", &*base);
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::maillons_de_riposte_avoues::ac1_lignes_de_journal_des_maillons_de_riposte_manquants",
            ])
            .env(AC1_ENFANT, "1")
            .env("PLUME_DB", &*base)
            .env("PLUME_CONFIG", &sans_conf)
            .env("PLUME_NETBAN_FROM_ACTIONS", "1")
            .env("PLUME_EXEC_PLATFORM", "generic-appliance")
            .env("PLUME_EXEC_GENERIC_KILL_PID", "true {pid}")
            .env("PLUME_HOST_LABEL", "hote-ac1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        // `AC1-ID:<phase>:<statut>:<id>` -> (statut, id).
        let marque = |phase: &str| -> (String, String) {
            let reste = stdout.split_once(&format!("AC1-ID:{phase}:")).unwrap_or_else(|| panic!("contrôle : {phase} : {stdout}")).1;
            let ligne = reste.lines().next().unwrap_or("");
            let (statut, id) = ligne.split_once(':').unwrap_or((ligne, ""));
            (statut.to_string(), id.to_string())
        };
        let lignes = |phase: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{AC1_PHASE}{phase}\n")).unwrap_or_else(|| panic!("contrôle : phase {phase} : {stderr}")).1;
            let corps = debut.split_once(AC1_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.contains(" WARN ") && l.contains(AC1_TETE_DE_LIGNE)).map(str::to_string).collect()
        };
        let attendus: [(&str, &str, &str, &str, &str); 10] = [
            ("remote", "200", "actions", "action {id} : verdict `done` de l'agent écrit", "action.remote"),
            ("approve-forme", "204", "actions", "action {id} approuvée : cible inanalysable, aucun miroir HTTP", "netban.forme"),
            ("approve-plafond", "204", "actions", "action {id} approuvée : miroir HTTP refusé par le plafond", "netban.plafond"),
            ("netban-plafond", "507", "netban", "ban manuel refusé par le plafond", "netban.plafond"),
            ("approve-non-arme", "503", "actions", "action {id} approuvée : miroir HTTP NON armé", "netban.non-arme"),
            ("netban-non-arme", "503", "netban", "ban manuel NON armé", "netban.non-arme"),
            ("responder-non-ecrit", "approved", "responder", "action {id} exécutée, verdict NON écrit", "action.exec.verdict-non-ecrit"),
            // Le verdict conservé est celui relu : `approved` (`RAISE(IGNORE)` n'a rien écrit).
            ("responder-conserve", "approved", "responder", "action {id} exécutée, verdict d'un autre acteur conservé", "action.exec.verdict-conserve"),
            // Chaque issue du verdict conservé dit ce qui s'est passé, pas « verdict conservé ».
            ("responder-disparue", "absente", "responder", "action {id} exécutée, ligne d'action disparue avant la relecture du verdict", "action.exec.verdict-conserve"),
            ("responder-non-relu", "blob", "responder", "action {id} exécutée, verdict conservé NON relu", "action.exec.verdict-non-relu"),
        ];
        for (phase, statut_attendu, sujet, geste, genre) in attendus {
            let (statut, id) = marque(phase);
            assert_eq!(statut, statut_attendu, "phase {phase} : la réponse d'avant");
            let vues = lignes(phase);
            assert_eq!(vues.len(), 1, "phase {phase} : une ligne et une seule : {vues:?}\n{stderr}");
            assert_eq!(vues[0], ac1_ligne(sujet, &geste.replace("{id}", &id), genre, AC1_MOTEUR_REGISTRE), "phase {phase} : sujet, action et cause du moteur");
            assert!(!vues[0].contains("203.0.113") && !vues[0].contains("pas-une-adresse") && !vues[0].contains("424"), "phase {phase} : jamais la cible : {}", vues[0]);
            let (statut_calme, _) = marque(&format!("{phase}-calme"));
            assert_eq!(statut_calme, statut_attendu, "phase {phase}-calme : la même réponse, registre sain");
            assert!(lignes(&format!("{phase}-calme")).is_empty(), "phase {phase}-calme : aucune ligne de maillon manquant, registre sain");
        }
    }
}
