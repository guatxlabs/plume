// =====================================================================================
// `P10.29-l` (vague BF) — LE TEXTE DU MOTEUR HORS DES BANS, DE LA MISE EN FILE ET DU TOTAL ; LA LIGNE `[query]` SANS
// L'ÉNONCÉ ; LE TENANT SUR LES LIGNES `[purge]`.
//
// LE DÉFAUT, RELU SUR b29051c4 :
//  - `handlers/actions.rs` : trois 503 servaient `format!("{CAUSE_X} ({cause})")`, `cause` étant le texte du moteur :
//    `action_create` (`RiposteMiseEnFile::NonEcrite`, `mise_en_file_de_riposte.rs:87`), le ban de `action_approve` et
//    `netban_add` (`PoseDeBan::NonEcrit`, `auth.rs:780`) ;
//  - `handlers/query.rs` : `total_lu` servait sous `total_error`, au rôle lecteur, le texte de `run_query_ex` (refus
//    de l'autorisateur, erreur d'E/S) et l'affichage d'une tâche interrompue ; la ligne `[query] WARN` du refus du
//    moteur portait ce texte, qui cite l'énoncé (donc peut nommer une valeur cherchée) ;
//  - `handlers/purge.rs` : la ligne `[<id>] [purge] WARN` ne nommait pas le tenant (la fabrique ne le recevait pas),
//    et rien ne reliait la ligne `[<id>] [purge] ERREUR` d'une transaction restée ouverte au tenant.
//
// CE QUE CES TÉMOINS JUGENT :
// (1) `bf3_ripostes_par_la_route_corps_entiers` — routeur réel, administrateur (rôle seul admis par les trois routes) :
//     corps de refus ENTIER (`{error, id}`, cause exacte avec la phrase fixe littérale entre parenthèses), aucun octet
//     du message du déclencheur dans la réponse ; contrôles positifs (riposte posée, ban approuvé, ban manuel posé).
// (2) `bf3_total_par_la_route_corps_entiers` — routeur réel, LECTEUR : `count_only` sous trois classes (support, base
//     occupée, refus du moteur) armées sur la connexion de lecture du pool, corps entier (clés exactes, `total` à -1,
//     `total_error` à la phrase littérale) ; la voie paginée (page et compte concurrents) avec le seul comptage en
//     échec sous les MÊMES trois classes (agrégat `count` remplacé par une fonction dont la fin rend `SQLITE_IOERR_READ`
//     ou `SQLITE_BUSY`, fonction `count` déniée pour le moteur, sur les deux connexions armées), la page servie ;
//     contrôles positifs (compte seul et compte de la page lus, sans aveu).
// (3) `bf3_tache_de_comptage_interrompue` — `total_lu` sur une tâche qui panique (message secret) et une tâche annulée :
//     phrase fixe, le message de la panique absent. Appel direct : aucune route ne provoque une panique de la tâche.
// (4) `bf3_deux_tenants_journal_entier` — DEUX tenants réels (mode 1), en sous-processus : chaque ligne `[actions]`,
//     `[netban]`, `[query]` et `[purge]` ÉGALE à la ligne attendue, dans l'ordre, nommant le tenant de l'APPELANT ; le
//     texte du moteur des ripostes rendu par `{:?}` (le message porte un retour à la ligne, un retour chariot et un
//     guillemet) ; les lignes du total et du refus du moteur ne portent que la nature (code SQLite) ; aucune ligne pour
//     la phrase du produit (interruption), dont le corps est jugé ici (appel du gestionnaire) ; la ligne `[purge]
//     ERREUR` est jugée par son préfixe (identifiant servi), et la ligne qui la relie au tenant en entier.
// (5) `bf3_le_refus_du_compilateur_peut_citer_le_corps_d_une_macro` — ce que `docs/GXQL.md` dit maintenant du refus
//     du compilateur : après détente, le message cite un mot du corps de la macro, absent de la requête.
// (6) `bf3_connexion_armee_par_l_instrument_fermee_au_retour` — l'instrument `query_exec::panne_de_test_au_coeur` ne
//     remet pas au pool la connexion qu'il arme : la page échoue, aucune connexion au repos, le comptage qui suit lit
//     sur une connexion neuve ; contrôle : une connexion saine tenue pendant qu'une autre est armée hors du pool est
//     remise. Sans quoi le comptage de la voie paginée reprenait la connexion armée de la page (rouge intermittent des
//     témoins `ar2_` sur une ligne `[query] WARN total non établi` en trop, à coup sûr sous `BF3_C_RETARD`).
// (`texte_du_moteur_hors_des_panneaux_et_des_sources_de_donnees.rs`, `as1_ligne_prom`) — inversé nommément : la ligne
//     `[datasource] WARN série rejetée par le moteur` ne porte que la nature.
//
// MUTATIONS (jouées sous la variable de mutation, retirées du source) : `BF3_A_FILE_FUITE`, `BF3_A_FILE_MUET`,
// `BF3_A_FILE_TENANT`, `BF3_A_BAN_FUITE`, `BF3_A_BAN_MUET`, `BF3_A_BAN_TENANT`, `BF3_A_NET_FUITE`, `BF3_A_NET_MUET`,
// `BF3_A_NET_TENANT` (ripostes) ; `BF3_T_MOTEUR`, `BF3_T_SUPPORT`, `BF3_T_OCCUPEE`, `BF3_T_PRODUIT`, `BF3_T_JOIN`,
// `BF3_T_JOIN_FIN`, `BF3_T_MUET`, `BF3_T_NATURE`, `BF3_T_SITE_SEUL`, `BF3_T_SITE_PAGE`, `BF3_T_TENANT_SEUL`,
// `BF3_T_TENANT_PAGE` (total) ; `BF3_Q_TEXTE` (ligne du moteur) ; `BF3_P_LIGNE`, `BF3_P_PLAN`, `BF3_P_APPLY`,
// `BF3_P_LIAISON`, `BF3_P_LIAISON_TENANT` (purge) ; `BF3_T_PAGE_CLASSE` (voie paginée : support et base occupée
// fondus dans le moteur) ; `BF3_I_REMISE` (connexion armée remise au pool) ; `BF3_D_TEXTE` (texte du moteur à la ligne
// `[datasource]`). `BF3_C_RETARD` n'est pas une mutation mais une contrainte : le comptage de la voie paginée retardé de
// 300 ms, sous laquelle les témoins `ar2_` restent verts, et rougissent avec `BF3_I_REMISE`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la classe « produit » du total n'est jugée que par l'appel du gestionnaire (le
// rappel de progression armé sur le pool interromprait aussi les lectures de l'authentification du routeur) ; la ligne
// `[purge] ERREUR` elle-même ne nomme pas le tenant (`purge::annuler_la_purge` ne le reçoit pas), elle est reliée par
// l'identifiant ; le registre `netban.non-arme` garde le texte du moteur (lu par l'administrateur seul, `/api/ledger`).
// RESTES NOMMÉS, hors de ce lot : la cause au journal d'un échec de panneau (`dashboards::EchecMisEnCache`, classe
// « moteur », `au_journal: texte`) garde le texte du moteur, qui peut citer l'énoncé compilé de la requête ENREGISTRÉE
// du panneau ; elle sert les lignes `[panel]` (`dashboards.rs`), `[cache]` (`rollups.rs`) et `[dashboards]`
// (`dash_ergonomics.rs`), que huit fichiers de témoins jugent texte compris ; et les lignes `[panel]` et `[cache]` ne
// nomment toujours pas le tenant partout (reste de la vague BE).
// =====================================================================================
mod bf3_texte_du_moteur_hors_des_bans_du_total_et_tenant_de_la_purge {
    use super::*;
    use crate::handlers::actions::{CAUSE_BAN_NON_ARME, CAUSE_RIPOSTE_NON_MISE_EN_FILE};
    use crate::handlers::query::total_lu;
    use crate::query_exec::EchecDeRequete;
    use guatx_core::soql::{KnowledgeSet, Schema};
    use rusqlite::functions::FunctionFlags;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    /// La phrase servie entre parenthèses à la place du texte du moteur (littéral, jamais la constante de production).
    const BF3_CAUSE_AU_JOURNAL: &str = "la cause rendue par la base est au journal du démon";
    /// Les phrases du total non établi, écrites ICI.
    const BF3_TOTAL_ILLISIBLE: &str =
        "total NON ÉTABLI : la base n'a pas pu être lue (erreur du support) — « -1 » n'est pas un compte ; l'exploitant en trouve le code au journal.";
    const BF3_TOTAL_OCCUPEE: &str =
        "total NON ÉTABLI : la base est occupée (verrou tenu par une autre opération) — « -1 » n'est pas un compte ; réessayez dans un instant.";
    const BF3_TOTAL_MOTEUR: &str =
        "total NON ÉTABLI : le moteur a refusé le comptage — « -1 » n'est pas un compte ; l'exploitant en trouve le code au journal.";
    const BF3_TOTAL_TACHE: &str = "total NON ÉTABLI : la tâche de comptage ne s'est pas terminée — « -1 » n'est pas un compte";
    /// Le message des déclencheurs de riposte : il porte les caractères qui forgeraient une ligne de journal.
    const BF3_MESSAGE: &str = "bf3 refus\nligne forgée\r\"guillemet\"";
    /// Le message du déclencheur qui refuse la suppression de la purge.
    const BF3_MESSAGE_PURGE: &str = "bf3-purge-refus";
    const BF3_PANIQUE: &str = "bf3 panique au message secret";
    const BF3_SOQL: &str = "search source=bf3 message=~\"bf3\"";
    const BF3_ENFANT: &str = "BF3_ENFANT_DEUX_TENANTS";
    const BF3_NETBAN_DES_RIPOSTES: &str = "PLUME_NETBAN_FROM_ACTIONS";
    const BF3_VAL: &str = "BF3-VAL:";
    const BF3_FIN: &str = "BF3-FIN:";
    const BF3_ALPHA: &str = "bf3-alpha";
    const BF3_BETA: &str = "bf3-beta";

    // ── instruments ──────────────────────────────────────────────────────────────────────────────────────────────

    /// Une panne posée sur une connexion de lecture déposée au pool.
    #[derive(Clone, Copy, Debug)]
    enum Bf3Panne {
        /// L'UDF `regexp` rend une erreur d'E/S (`SQLITE_IOERR_READ`).
        Support,
        /// L'UDF `regexp` rend `SQLITE_BUSY`.
        Occupee,
        /// L'autorisateur refuse la lecture d'`event.message`.
        LectureDuMessage,
        /// L'autorisateur refuse la fonction `count` (seul le comptage l'appelle).
        FonctionCount,
        /// La fonction d'agrégat `count` (zéro argument : `COUNT(*)`) remplacée par une fonction dont la fin rend une
        /// erreur d'E/S (`SQLITE_IOERR_READ`) : seul le comptage échoue, sous la classe « support ».
        CompteSupport,
        /// Même remplacement, la fin rend `SQLITE_BUSY` : seul le comptage échoue, sous la classe « base occupée ».
        CompteOccupee,
        /// Le rappel de progression interrompt tout énoncé.
        Interruption,
    }

    /// L'agrégat `count` dont la fin rend le code `0` (sans message : un message rabattrait le code sur `SQLITE_ERROR`).
    struct Bf3CompteEnPanne(i32);

    impl rusqlite::functions::Aggregate<i64, i64> for Bf3CompteEnPanne {
        fn init(&self, _: &mut rusqlite::functions::Context<'_>) -> rusqlite::Result<i64> {
            Ok(0)
        }
        fn step(&self, _: &mut rusqlite::functions::Context<'_>, n: &mut i64) -> rusqlite::Result<()> {
            *n += 1;
            Ok(())
        }
        fn finalize(&self, _: &mut rusqlite::functions::Context<'_>, _: Option<i64>) -> rusqlite::Result<i64> {
            Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(self.0), None))
        }
    }

    fn bf3_poser(conn: &Connection, panne: Bf3Panne) {
        let utf8 = FunctionFlags::SQLITE_UTF8;
        match panne {
            Bf3Panne::Support => conn
                .create_scalar_function("regexp", 2, utf8, |_ctx| -> rusqlite::Result<bool> {
                    Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR_READ), None))
                })
                .expect("fixture : regexp en panne d'E/S"),
            Bf3Panne::Occupee => conn
                .create_scalar_function("regexp", 2, utf8, |_ctx| -> rusqlite::Result<bool> {
                    Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY), None))
                })
                .expect("fixture : regexp occupée"),
            Bf3Panne::LectureDuMessage => conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Read { table_name, column_name } if table_name == "event" && column_name == "message" => Authorization::Deny,
                _ => Authorization::Allow,
            })),
            Bf3Panne::FonctionCount => conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Function { function_name } if function_name.eq_ignore_ascii_case("count") => Authorization::Deny,
                _ => Authorization::Allow,
            })),
            Bf3Panne::CompteSupport => conn
                .create_aggregate_function("count", 0, utf8, Bf3CompteEnPanne(rusqlite::ffi::SQLITE_IOERR_READ))
                .expect("fixture : count en panne d'E/S"),
            Bf3Panne::CompteOccupee => conn
                .create_aggregate_function("count", 0, utf8, Bf3CompteEnPanne(rusqlite::ffi::SQLITE_BUSY))
                .expect("fixture : count occupée"),
            Bf3Panne::Interruption => conn.progress_handler(1, Some(|| true)),
        }
    }

    fn bf3_vider_le_pool(chemin: &str) {
        while crate::query_exec::connexions_de_lecture_au_repos(chemin) > 0 {
            drop(crate::query_exec::read_conn_get(chemin).expect("fixture : connexion au repos"));
        }
    }

    /// Dépose `n` connexions de lecture armées de `panne` dans le pool vidé de `chemin`.
    fn bf3_armer_le_pool(chemin: &str, panne: Bf3Panne, n: usize) {
        bf3_vider_le_pool(chemin);
        let conns: Vec<Connection> = (0..n).map(|_| crate::query_exec::read_conn_get(chemin).expect("fixture : connexion de lecture")).collect();
        for c in conns {
            bf3_poser(&c, panne);
            crate::query_exec::read_conn_put(chemin, c);
        }
        assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(chemin), n, "fixture : {n} connexion(s) armée(s) au repos");
    }

    /// La nature qu'un échec laisse au journal : son code SQLite (celui d'un échec ou d'une erreur de saisie).
    fn bf3_nature(e: &rusqlite::Error) -> String {
        let f = e
            .sqlite_error()
            .map(|f| (f.extended_code, f.code))
            .or_else(|| std::error::Error::source(e).and_then(|s| s.downcast_ref::<rusqlite::ffi::Error>()).map(|f| (f.extended_code, f.code)))
            .unwrap_or_else(|| panic!("instrument : erreur sans code SQLite : {e}"));
        format!("code SQLite {} ({:?})", f.0, f.1)
    }

    /// L'erreur que la panne `panne` fait rendre, REPRODUITE en mémoire (même mécanisme).
    fn bf3_erreur_de(panne: Bf3Panne) -> rusqlite::Error {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        c.execute_batch("CREATE TABLE event(message TEXT); INSERT INTO event VALUES('bf3');").expect("instrument : table");
        bf3_poser(&c, panne);
        match panne {
            Bf3Panne::Support | Bf3Panne::Occupee => {
                c.query_row("SELECT regexp('bf3', message) FROM event", [], |r| r.get::<_, bool>(0)).err().expect("instrument : regexp échoue")
            }
            Bf3Panne::LectureDuMessage => c.prepare("SELECT message FROM event").err().expect("instrument : lecture refusée"),
            Bf3Panne::FonctionCount => c.prepare("SELECT COUNT(*) FROM event").err().expect("instrument : count refusée"),
            Bf3Panne::CompteSupport | Bf3Panne::CompteOccupee => {
                c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get::<_, i64>(0)).err().expect("instrument : count échoue")
            }
            Bf3Panne::Interruption => panic!("instrument : l'interruption est une phrase du produit, sans nature"),
        }
    }

    fn bf3_declencheur(conn: &Connection, nom: &str, quand: &str, message: &str) {
        conn.execute_batch(&format!("CREATE TRIGGER {nom} {quand} BEGIN SELECT RAISE(ABORT, '{}'); END;", message.replace('\'', "''")))
            .unwrap_or_else(|e| panic!("fixture : déclencheur {nom} ({e})"));
    }

    /// Les ripostes de la fixture : deux bans à approuver (5100 nominal, 5101 refusé).
    fn bf3_semer_les_ripostes(conn: &Connection) {
        conn.execute_batch(
            "INSERT INTO action(id,ts,kind,target,status,dry_run,host) VALUES(5100,1000,'ban_ip','203.0.113.79','pending',0,'');\
             INSERT INTO action(id,ts,kind,target,status,dry_run,host) VALUES(5101,1000,'ban_ip','203.0.113.80','pending',0,'');",
        )
        .expect("fixture : ripostes");
    }

    fn bf3_semer_l_evenement(conn: &Connection) {
        conn.execute("INSERT INTO event(ts,source,severity,message,host) VALUES(?1,'bf3',1,'bf3-sonde','bf3-h')", params![now() - 60])
            .expect("fixture : événement");
    }

    fn bf3_corps_de_riposte() -> Value {
        json!({ "kind": "kill_pid", "target": "4242", "dry_run": true })
    }

    fn bf3_corps_de_requete(compte_seul: bool, page: bool) -> Value {
        let mut b = json!({ "soql": BF3_SOQL, "from": now() - 3600, "to": now() + 60 });
        if compte_seul {
            b["count_only"] = json!(true);
        }
        if page {
            b["limit"] = json!(10);
        }
        b
    }

    fn bf3_cles(v: &Value) -> Vec<String> {
        let mut c: Vec<String> = v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        c.sort();
        c
    }

    /// Un 503 `{error, id}` exactement, la cause exacte, un identifiant de corrélation.
    fn bf3_refus_503(contexte: &str, (code, corps, brut): &(u16, Value, String), cause: &str) {
        assert_eq!(*code, 503, "{contexte} : statut : {brut}");
        assert_eq!(bf3_cles(corps), vec!["error", "id"], "{contexte} : exactement `error` et `id` : {brut}");
        assert_eq!(corps["error"], json!(cause), "{contexte} : la cause exacte : {brut}");
        assert!(corps["id"].as_str().unwrap_or("").starts_with("plume-e"), "{contexte} : identifiant de corrélation : {brut}");
    }

    /// Une requête à travers le routeur réel : statut, corps JSON (corps `chunked` recollé), réponse brute.
    async fn bf3_envoyer(addr: std::net::SocketAddr, methode: &str, chemin: &str, authz: &str, corps: &str) -> (u16, Value, String) {
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
    fn bf3_sans_texte_du_moteur(contexte: &str, brut: &str) {
        for texte in ["bf3 refus", "ligne forgée", "guillemet", "disk I/O", "locked", "prohibited", "not authorized", "code SQLite", "event.message"] {
            assert!(!brut.contains(texte), "{contexte} : la réponse porte le texte du moteur « {texte} » : {brut}");
        }
    }

    fn bf3_admin_authz() -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("root:rootpw1234567"))
    }

    // ── (1) RIPOSTES, PAR LA ROUTE ───────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn bf3_ripostes_par_la_route_corps_entiers() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf(BF3_NETBAN_DES_RIPOSTES, "1");
        let _g = NETBAN_TEST_LOCK.lock();
        crate::ledger::declarer_la_liste_pour_ce_temoin();
        netban_cache().write().clear();
        let (st, _base) = router_test_state("bf3-ripostes");
        bf3_semer_les_ripostes(&st.db.lock());
        let addr = router_serve(st.clone()).await;
        let admin = bf3_admin_authz();

        // Contrôles positifs : la riposte se pose, le ban s'approuve, le ban manuel se pose.
        let r = bf3_envoyer(addr, "POST", "/api/actions", &admin, &bf3_corps_de_riposte().to_string()).await;
        assert_eq!(r.0, 200, "contrôle : riposte posée : {}", r.2);
        assert!(r.1["id"].as_i64().unwrap_or(0) > 0, "contrôle : identifiant servi : {}", r.2);
        let r = bf3_envoyer(addr, "POST", "/api/actions/5100/approve", &admin, "").await;
        assert_eq!(r.0, 204, "contrôle : ban approuvé : {}", r.2);
        let r = bf3_envoyer(addr, "POST", "/api/netban", &admin, &json!({ "ip": "203.0.113.82", "ttl_s": 600 }).to_string()).await;
        assert_eq!((r.0, r.1["ok"].clone()), (200, json!(true)), "contrôle : ban manuel posé : {}", r.2);

        // Mise en file refusée par le déclencheur.
        bf3_declencheur(&st.db.lock(), "bf3_file", "BEFORE INSERT ON action", BF3_MESSAGE);
        let r = bf3_envoyer(addr, "POST", "/api/actions", &admin, &bf3_corps_de_riposte().to_string()).await;
        bf3_refus_503("mise en file", &r, &format!("{CAUSE_RIPOSTE_NON_MISE_EN_FILE} ({BF3_CAUSE_AU_JOURNAL})"));
        bf3_sans_texte_du_moteur("mise en file", &r.2);

        // Ban de l'approbation et ban manuel refusés par le déclencheur.
        bf3_declencheur(&st.db.lock(), "bf3_ban", "BEFORE INSERT ON net_ban", BF3_MESSAGE);
        let r = bf3_envoyer(addr, "POST", "/api/actions/5101/approve", &admin, "").await;
        bf3_refus_503("ban de l'approbation", &r, &format!("{CAUSE_BAN_NON_ARME} ({BF3_CAUSE_AU_JOURNAL})"));
        bf3_sans_texte_du_moteur("ban de l'approbation", &r.2);
        let r = bf3_envoyer(addr, "POST", "/api/netban", &admin, &json!({ "ip": "203.0.113.83", "ttl_s": 600 }).to_string()).await;
        bf3_refus_503("ban manuel", &r, &format!("{CAUSE_BAN_NON_ARME} ({BF3_CAUSE_AU_JOURNAL})"));
        bf3_sans_texte_du_moteur("ban manuel", &r.2);
        netban_cache().write().clear();
    }

    // ── (2) TOTAL, PAR LA ROUTE ──────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn bf3_total_par_la_route_corps_entiers() {
        let _env = VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent leur configuration
        let (st, _base) = router_test_state("bf3-total");
        bf3_semer_l_evenement(&st.db.lock());
        let chemin = st.db_path.as_ref().clone();
        let addr = router_serve(st.clone()).await;
        let lecteur = viewer_authz();

        // Contrôle positif : le compte est lu, sans aveu.
        let r = bf3_envoyer(addr, "POST", "/api/query", &lecteur, &bf3_corps_de_requete(true, false).to_string()).await;
        assert_eq!(r.0, 200, "contrôle : compte servi : {}", r.2);
        assert_eq!((r.1["total"].clone(), r.1.get("total_error").is_none()), (json!(1), true), "contrôle : compte lu : {}", r.2);

        for (classe, panne, phrase) in [
            ("support", Bf3Panne::Support, BF3_TOTAL_ILLISIBLE),
            ("occupee", Bf3Panne::Occupee, BF3_TOTAL_OCCUPEE),
            ("moteur", Bf3Panne::LectureDuMessage, BF3_TOTAL_MOTEUR),
        ] {
            bf3_armer_le_pool(&chemin, panne, 1);
            let r = bf3_envoyer(addr, "POST", "/api/query", &lecteur, &bf3_corps_de_requete(true, false).to_string()).await;
            bf3_vider_le_pool(&chemin);
            assert_eq!(r.0, 200, "{classe} : le compte seul garde son deux cents : {}", r.2);
            assert_eq!(bf3_cles(&r.1), vec!["count_only", "stats", "total", "total_error"], "{classe} : clés exactes : {}", r.2);
            assert_eq!(r.1["count_only"], json!(true), "{classe} : {}", r.2);
            assert_eq!(r.1["total"], json!(-1), "{classe} : « -1 » reste le mot du contrat : {}", r.2);
            assert_eq!(r.1["total_error"], json!(phrase), "{classe} : la phrase de la classe : {}", r.2);
            bf3_sans_texte_du_moteur(classe, &r.2);
        }

        // Voie paginée : page et compte concurrents. Contrôle positif : la page et son compte, sans aveu.
        bf3_vider_le_pool(&chemin);
        let r = bf3_envoyer(addr, "POST", "/api/query", &lecteur, &bf3_corps_de_requete(false, true).to_string()).await;
        assert_eq!(r.0, 200, "contrôle : page servie : {}", r.2);
        assert_eq!((r.1["total"].clone(), r.1.get("total_error").is_none()), (json!(1), true), "contrôle : compte de la page lu : {}", r.2);
        // Seul le comptage échoue, sous chacune des trois classes : la fonction `count` n'est appelée que par lui
        // (agrégat remplacé pour le support et la base occupée, refusé par l'autorisateur pour le moteur), armée sur
        // les deux connexions que la page et le comptage prennent.
        for (classe, panne, phrase) in [
            ("support", Bf3Panne::CompteSupport, BF3_TOTAL_ILLISIBLE),
            ("occupee", Bf3Panne::CompteOccupee, BF3_TOTAL_OCCUPEE),
            ("moteur", Bf3Panne::FonctionCount, BF3_TOTAL_MOTEUR),
        ] {
            bf3_armer_le_pool(&chemin, panne, 2);
            let r = bf3_envoyer(addr, "POST", "/api/query", &lecteur, &bf3_corps_de_requete(false, true).to_string()).await;
            bf3_vider_le_pool(&chemin);
            assert_eq!(r.0, 200, "page/{classe} : servie : {}", r.2);
            assert_eq!(r.1["rows"].as_array().map(|a| a.len()), Some(1), "page/{classe} : la ligne semée est servie : {}", r.2);
            assert_eq!(r.1["total"], json!(-1), "page/{classe} : total non établi : {}", r.2);
            assert_eq!(r.1["total_error"], json!(phrase), "page/{classe} : la phrase de la classe : {}", r.2);
            assert!(r.1.get("total_capped").is_none(), "page/{classe} : pas de plafond annoncé : {}", r.2);
            bf3_sans_texte_du_moteur(&format!("page/{classe}"), &r.2);
        }
    }

    // ── (6) L'INSTRUMENT DU CŒUR NE REMET PAS AU POOL LA CONNEXION QU'IL ARME ────────────────────────────────────

    #[tokio::test]
    async fn bf3_connexion_armee_par_l_instrument_fermee_au_retour() {
        use crate::query_exec::panne_de_test_au_coeur::{demander, encore_demandee, retirer, PanneAuCoeur};
        let _env = VERROU_ENV_PROCESSUS.read(); // le cœur lit son plafond de lignes dans l'environnement
        let (st, _base) = router_test_state("bf3-instrument");
        bf3_semer_l_evenement(&st.db.lock());
        let chemin = st.db_path.as_ref().clone();
        let compte = "SELECT COUNT(*) AS n FROM (SELECT 1 FROM (SELECT message FROM event WHERE source='bf3') LIMIT 10001)";
        let n_lu = |v: &Value| v["rows"][0][0].as_i64();

        // La page : la connexion du pool est armée (lecture d'`event.message` refusée), la page échoue.
        bf3_vider_le_pool(&chemin);
        demander(&chemin, PanneAuCoeur::RefusDeLAutorisateur);
        let page = crate::query_exec::run_query_ex(&chemin, "SELECT message FROM event WHERE source='bf3'", 5_000, None);
        let servie = !encore_demandee(&chemin);
        retirer(&chemin);
        assert!(servie, "contrôle : la panne a armé la connexion de la page");
        assert!(page.is_err(), "contrôle : la page échoue sur la connexion armée : {page:?}");
        assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(&chemin), 0, "la connexion armée n'est pas remise au pool");
        // Le comptage qui suit prend une connexion neuve : il lit.
        let total = crate::query_exec::run_query_ex(&chemin, compte, 5_000, None);
        assert_eq!(total.as_ref().ok().and_then(n_lu), Some(1), "le comptage suivant ne reprend pas la connexion armée : {total:?}");
        assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(&chemin), 1, "contrôle : la connexion saine du comptage est remise");

        // Contrôle : une connexion SAINE tenue pendant qu'une autre est armée hors du pool est remise au pool.
        bf3_vider_le_pool(&chemin);
        let saine = crate::query_exec::read_conn_get(&chemin).expect("fixture : connexion saine");
        let hors_du_pool = crate::query_exec::read_conn_get(&chemin).expect("fixture : connexion hors du pool");
        demander(&chemin, PanneAuCoeur::RefusDeLAutorisateur);
        let armee = crate::query_exec::run_on_conn(&hors_du_pool, &chemin, "SELECT message FROM event", 5_000, None);
        retirer(&chemin);
        assert!(armee.is_err(), "contrôle : la connexion hors du pool est armée : {armee:?}");
        drop(hors_du_pool);
        crate::query_exec::read_conn_put(&chemin, saine);
        assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(&chemin), 1, "la connexion saine est remise au pool");
        let total = crate::query_exec::run_query_ex(&chemin, compte, 5_000, None);
        assert_eq!(total.as_ref().ok().and_then(n_lu), Some(1), "contrôle : la connexion remise lit : {total:?}");
        bf3_vider_le_pool(&chemin);
    }

    // ── (3) TÂCHE DE COMPTAGE INTERROMPUE ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn bf3_tache_de_comptage_interrompue() {
        let panique = tokio::task::spawn_blocking(|| -> Result<Value, EchecDeRequete> { panic!("{BF3_PANIQUE}") }).await;
        assert!(panique.as_ref().err().map(|e| e.is_panic()).unwrap_or(false), "contrôle : la tâche a paniqué");
        let (n, cause) = total_lu(panique, "/api/query", "default");
        assert_eq!((n, cause.as_deref()), (-1, Some(BF3_TOTAL_TACHE)), "panique : phrase fixe");
        assert!(!cause.unwrap_or_default().contains(BF3_PANIQUE), "panique : le message n'est pas servi");
        let tache = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok::<Value, EchecDeRequete>(json!({}))
        });
        tache.abort();
        let annulee = tache.await;
        assert!(annulee.as_ref().err().map(|e| e.is_cancelled()).unwrap_or(false), "contrôle : la tâche est annulée");
        let (n, cause) = total_lu(annulee, "/api/query", "default");
        assert_eq!((n, cause.as_deref()), (-1, Some(BF3_TOTAL_TACHE)), "annulation : phrase fixe");
    }

    // ── (4) DEUX TENANTS, LE JOURNAL ─────────────────────────────────────────────────────────────────────────────

    fn bf3_au(role: &str, nom: &str, tenant: &str) -> AuthUser {
        AuthUser { name: nom.into(), role: role.into(), tenant: tenant.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }

    async fn bf3_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&octets).unwrap_or(Value::Null))
    }

    /// Le compte de `/api/query` sous `panne` (n connexions armées), par le gestionnaire, au rôle lecteur.
    async fn bf3_requete_en_panne(st: &AppState, t: &str, chemin: &str, panne: Bf3Panne, n: usize, corps: Value) -> (u16, Value) {
        bf3_armer_le_pool(chemin, panne, n);
        let r = bf3_corps(crate::handlers::query::query(State(st.clone()), Extension(bf3_au("viewer", "lec-bf3", t)), Json(corps)).await).await;
        bf3_vider_le_pool(chemin);
        r
    }

    fn bf3_valeur(t: &str, cle: &str, valeur: &str) {
        println!("{BF3_VAL}{t}:{cle}:{valeur}");
    }

    /// Joue, sur le tenant `t`, chaque geste de ce lot ; rend le nombre de gestes joués.
    async fn bf3_jouer_sur(st: &AppState, t: &str, chemin: &str) -> usize {
        let h = st.tenants.handle_for(t).expect("contrôle : base du tenant");
        let admin = bf3_au("admin", "adm-bf3", t);
        let mut joues = 0usize;
        // RIPOSTES.
        bf3_declencheur(&h.lock(), "bf3_file", "BEFORE INSERT ON action", BF3_MESSAGE);
        bf3_declencheur(&h.lock(), "bf3_ban", "BEFORE INSERT ON net_ban", BF3_MESSAGE);
        let (s, _) = bf3_corps(action_create(State(st.clone()), Extension(admin.clone()), Json(bf3_corps_de_riposte())).await).await;
        assert_eq!(s, 503, "{t} : mise en file refusée");
        let (s, _) = bf3_corps(action_approve(State(st.clone()), Extension(admin.clone()), Path(5101)).await).await;
        assert_eq!(s, 503, "{t} : ban de l'approbation refusé");
        let (s, _) = bf3_corps(netban_add(State(st.clone()), Extension(admin.clone()), Json(json!({ "ip": "203.0.113.84", "ttl_s": 600 }))).await).await;
        assert_eq!(s, 503, "{t} : ban manuel refusé");
        joues += 3;
        // TOTAL : trois classes journalisées, la phrase du produit sans ligne.
        for (classe, panne) in [("support", Bf3Panne::Support), ("occupee", Bf3Panne::Occupee), ("moteur", Bf3Panne::LectureDuMessage)] {
            let (s, v) = bf3_requete_en_panne(st, t, chemin, panne, 1, bf3_corps_de_requete(true, false)).await;
            assert_eq!((s, v["total"].clone()), (200, json!(-1)), "{t}/{classe} : total non établi : {v}");
            joues += 1;
        }
        // L'interruption arrête TOUT énoncé, y compris la lecture de l'horizon de conservation, qui prend la première
        // connexion du pool avant le comptage (et la ferme : elle revient armée) : une seconde connexion armée est celle
        // que le comptage prend.
        let (s, v) = bf3_requete_en_panne(st, t, chemin, Bf3Panne::Interruption, 2, bf3_corps_de_requete(true, false)).await;
        let produit = format!(
            "total NON ÉTABLI : requête interrompue (budget {} s dépassé) — « -1 » n'est pas un compte",
            crate::query_exec::query_budget_ms() / 1000
        );
        assert_eq!((s, v["total"].clone(), v["total_error"].clone()), (200, json!(-1), json!(produit)), "{t} : la phrase du produit, à l'octet : {v}");
        joues += 1;
        let (s, v) = bf3_requete_en_panne(st, t, chemin, Bf3Panne::FonctionCount, 2, bf3_corps_de_requete(false, true)).await;
        assert_eq!((s, v["total"].clone(), v["total_error"].clone()), (200, json!(-1), json!(BF3_TOTAL_MOTEUR)), "{t} : page, comptage refusé : {v}");
        joues += 1;
        // LIGNE DU REFUS DU MOTEUR (requête non paginée).
        let (s, v) = bf3_requete_en_panne(st, t, chemin, Bf3Panne::LectureDuMessage, 1, bf3_corps_de_requete(false, false)).await;
        assert_eq!(s, 400, "{t} : requête rejetée : {v}");
        joues += 1;
        // TÂCHE DE COMPTAGE INTERROMPUE.
        let panique = tokio::task::spawn_blocking(|| -> Result<Value, EchecDeRequete> { panic!("{BF3_PANIQUE}") }).await;
        assert_eq!(total_lu(panique, "/api/query", t).0, -1, "{t} : panique");
        let tache = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok::<Value, EchecDeRequete>(json!({}))
        });
        tache.abort();
        assert_eq!(total_lu(tache.await, "/api/query", t).0, -1, "{t} : annulation");
        joues += 2;
        // PURGE : lecture non faite (plan), refus de la base (apply), transaction restée ouverte (apply).
        with_write(st, &admin, |c| {
            c.execute(
                "INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
                 VALUES(X'FFFE','','flux-a',0,0,1,0,'admin')",
                [],
            )
            .expect("fixture : rétention au nom illisible")
        });
        let cause_du_hold = match with_write(st, &admin, |c| purge_plan(c, pcr_scope())) {
            Err(PurgeRefusal::LegalHoldUnread(texte)) => texte,
            Err(e) => panic!("{t} : précondition : `legal_hold_unread` attendu, rendu `{e}`"),
            Ok(_) => panic!("{t} : précondition : la rétention illisible refuse le plan"),
        };
        bf3_valeur(t, "hold", &format!("{cause_du_hold:?}"));
        let (s, corps) = pcr_plan(st, &admin).await;
        assert_eq!((s, corps["refusal"].clone()), (500, json!("legal_hold_unread")), "{t} : plan refusé : {corps}");
        bf3_valeur(t, "id-plan", corps["id"].as_str().unwrap_or_default());
        with_write(st, &admin, |c| c.execute_batch("DELETE FROM legal_hold;").expect("fixture : rétention retirée"));
        let (s, plan) = pcr_plan(st, &admin).await;
        assert_eq!(s, 200, "{t} : plan servi : {plan}");
        let jeton = plan["token"].as_str().expect("jeton servi").to_string();
        bf3_declencheur(&h.lock(), "bf3_purge", "BEFORE DELETE ON event", BF3_MESSAGE_PURGE);
        let texte_db = match with_write(st, &admin, |c| purge_confirm_and_apply(c, pcr_scope(), &jeton, "api:adm-bf3", "témoin bf3")) {
            Err(PurgeRefusal::Db(texte)) => texte,
            Err(e) => panic!("{t} : précondition : `db` attendu, rendu `{e}`"),
            Ok(_) => panic!("{t} : précondition : la suppression refusée refuse la purge"),
        };
        bf3_valeur(t, "db", &format!("{texte_db:?}"));
        let (s, corps) = pcr_apply(st, &admin, &jeton).await;
        assert_eq!((s, corps["refusal"].clone()), (500, json!("db")), "{t} : apply refusé : {corps}");
        bf3_valeur(t, "id-db", corps["id"].as_str().unwrap_or_default());
        with_write(st, &admin, |c| {
            c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Transaction { operation: TransactionOperation::Rollback } => Authorization::Deny,
                _ => Authorization::Allow,
            }))
        });
        let (s, corps) = pcr_apply(st, &admin, &jeton).await;
        with_write(st, &admin, |c| {
            c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            if !c.is_autocommit() {
                c.execute_batch("ROLLBACK").expect("annulation à la main, autorisateur retiré");
            }
        });
        assert_eq!((s, corps["refusal"].clone()), (500, json!("transaction_left_open")), "{t} : transaction restée ouverte : {corps}");
        bf3_valeur(t, "id-ouverte", corps["id"].as_str().unwrap_or_default());
        joues += 3;
        joues
    }

    /// Les lignes attendues pour le tenant `t`, dans l'ordre de `bf3_jouer_sur`.
    fn bf3_lignes_attendues(t: &str, val: &dyn Fn(&str) -> String) -> Vec<String> {
        let message = format!("{BF3_MESSAGE:?}");
        let nature = |p: Bf3Panne| bf3_nature(&bf3_erreur_de(p));
        vec![
            format!("[actions] WARN riposte NON mise en file, aucune ligne écrite (tenant '{t}') : {message}"),
            format!("[actions] WARN ban de la riposte #5101 NON armé (tenant '{t}') : {message}"),
            format!("[netban] WARN ban manuel NON armé (tenant '{t}') : {message}"),
            format!("[query] WARN total non établi, erreur du support de la base (/api/query, tenant '{t}') : {}", nature(Bf3Panne::Support)),
            format!("[query] WARN total non établi, base occupée (/api/query, tenant '{t}') : {}", nature(Bf3Panne::Occupee)),
            format!("[query] WARN total non établi, comptage rejeté par le moteur (/api/query, tenant '{t}') : {}", nature(Bf3Panne::LectureDuMessage)),
            format!("[query] WARN total non établi, comptage rejeté par le moteur (/api/query, tenant '{t}') : {}", nature(Bf3Panne::FonctionCount)),
            format!("[query] WARN requête rejetée par le moteur (/api/query, tenant '{t}') : {}", nature(Bf3Panne::LectureDuMessage)),
            format!("[query] WARN total non établi, tâche de comptage interrompue (/api/query, tenant '{t}') : panique"),
            format!("[query] WARN total non établi, tâche de comptage interrompue (/api/query, tenant '{t}') : annulation"),
            format!("[{}] [purge] WARN refus servi, lecture de la base non faite (legal_hold_unread), tenant '{t}' : {}", val("id-plan"), val("hold")),
            format!("[{}] [purge] WARN refus servi, refus de la base (db), tenant '{t}' : {}", val("id-db"), val("db")),
            format!("[{}] [purge] ERREUR", val("id-ouverte")),
            format!("[{}] [purge] WARN refus servi, transaction restée ouverte, tenant '{t}'", val("id-ouverte")),
        ]
    }

    /// Les lignes de journal de ce lot, et elles seules ; une ligne `[purge] ERREUR` réduite à son préfixe.
    fn bf3_journal(stderr: &str) -> Vec<String> {
        let prefixes = ["[actions] WARN ", "[netban] WARN ", "[query] WARN "];
        stderr
            .lines()
            .filter_map(|l| {
                // Une ligne forgée (retour à la ligne non échappé) commencerait par un morceau du message : gardée aussi.
                if prefixes.iter().any(|p| l.starts_with(p)) || l.starts_with("ligne forgée") || l.contains("\"guillemet\"") {
                    return Some(l.to_string());
                }
                if let Some(i) = l.find("] [purge] ERREUR") {
                    return Some(l[..i + "] [purge] ERREUR".len()].to_string());
                }
                l.contains("] [purge] ").then(|| l.to_string())
            })
            .collect()
    }

    #[tokio::test]
    async fn bf3_deux_tenants_journal_entier() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(BF3_ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            let _ouverte = porte_de_purge_de_temoin::ouvrir();
            let (st, _dir) = mk_mode1_state();
            let mut chemins = Vec::new();
            for t in [BF3_ALPHA, BF3_BETA] {
                let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-bf3")), Json(json!({ "id": t, "name": t }))).await;
                assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
                {
                    let h = st.tenants.handle_for(t).expect("contrôle : base du tenant");
                    let c = h.lock();
                    bf3_semer_les_ripostes(&c);
                    bf3_semer_l_evenement(&c);
                    pcr_semer(&c);
                }
                chemins.push(st.tenants.ready_db_path(t).expect("contrôle : chemin de la base du tenant"));
            }
            assert_ne!(chemins[0], chemins[1], "contrôle : deux bases distinctes");
            let mut joues = bf3_jouer_sur(&st, BF3_ALPHA, &chemins[0]).await;
            joues += bf3_jouer_sur(&st, BF3_BETA, &chemins[1]).await;
            netban_cache().write().clear();
            println!("{BF3_FIN} {joues}");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::bf3_texte_du_moteur_hors_des_bans_du_total_et_tenant_de_la_purge::bf3_deux_tenants_journal_entier",
            ])
            .env(BF3_ENFANT, "1")
            .env(BF3_NETBAN_DES_RIPOSTES, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(&format!("{BF3_FIN} 28")), "contrôle : quatorze gestes joués par tenant : {stdout}\n{stderr}");
        let valeur_de = |t: &str| {
            let stdout = stdout.clone();
            let t = t.to_string();
            move |cle: &str| -> String {
                let tete = format!("{BF3_VAL}{t}:{cle}:");
                stdout
                    .lines()
                    // La première valeur suit, sur la même ligne, l'en-tête que `libtest` écrit pour le test.
                    .find_map(|l| l.split_once(tete.as_str()).map(|(_, v)| v.to_string()))
                    .unwrap_or_else(|| panic!("contrôle : valeur {t}/{cle} rendue par l'enfant : {stdout}"))
            }
        };
        let mut attendu = bf3_lignes_attendues(BF3_ALPHA, &valeur_de(BF3_ALPHA));
        attendu.extend(bf3_lignes_attendues(BF3_BETA, &valeur_de(BF3_BETA)));
        assert_eq!(bf3_journal(&stderr), attendu, "une ligne EXACTE par geste, tenant de l'appelant, aucune pour la phrase du produit :\n{stderr}");
    }

    // ── (5) LE REFUS DU COMPILATEUR ET LE CORPS D'UNE MACRO ──────────────────────────────────────────────────────

    #[test]
    fn bf3_le_refus_du_compilateur_peut_citer_le_corps_d_une_macro() {
        const REQUETE: &str = "search x `bf3m`";
        const MOT_DU_CORPS: &str = "bf3commandeducorps";
        let mut savoir = KnowledgeSet::new();
        savoir.add_macro("bf3m", vec![], format!("| {MOT_DU_CORPS}"));
        let refus = guatx_core::soql::to_sql(REQUETE, 0, 0, &Schema::events().with_knowledge(savoir)).err().expect("la commande du corps est refusée");
        assert!(!REQUETE.contains(MOT_DU_CORPS), "contrôle : le mot n'est pas dans la requête de l'appelant");
        assert!(refus.contains(MOT_DU_CORPS), "le refus cite le corps de la macro, détendu avant l'analyse : {refus}");
        let sans_macro = guatx_core::soql::to_sql(REQUETE, 0, 0, &Schema::events()).err().unwrap_or_default();
        assert!(!sans_macro.contains(MOT_DU_CORPS), "contrôle : sans la macro, le mot n'apparaît pas : {sans_macro}");
    }
}
