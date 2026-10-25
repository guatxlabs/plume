// =====================================================================================
// `P10.29-l` (vague AQ) — LE TEXTE DU MOTEUR NE PART PLUS AU CLIENT DANS `compliance.rs`, `search.rs`, `system.rs` ET
// `fleet.rs`.
//
// LE DÉFAUT, LU SUR a759d83d AVANT LE CORRECTIF :
//  * `/api/compliance/posture` et `/api/compliance/report` (tout lecteur) servaient `CAUSE_POSTURE_NON_LUE` ou
//    `CAUSE_ANCRAGE_NON_LU` suivie du texte du moteur : `e.to_string()` de rusqlite (« access to ledger.hash is
//    prohibited », « no such table: event »), la chaîne d'erreur de `run_query`, le refus du compilateur, le texte d'un
//    `JoinError`, et « règles mappées NON LUES : … ({e}) » ;
//  * `/api/search` servait « le moteur de recherche a REFUSÉ cette requête … : {e} » — le message de l'UDF `regexp` (qui
//    cite le motif soumis), de FTS5, ou la colonne refusée par l'autorisateur ;
//  * `/healthz` (SANS authentification), `/metrics`, `/api/system/metrics` et le paquet de diagnostic servaient « La
//    lecture a échoué : {e}. » sous `schema_version_non_etablie` ; `/api/bulletin` « La lecture a échoué : {e}. » et
//    « La ligne existe et ne se décode pas : {e}. » ;
//  * `/api/fleet` servait « SANTÉ DU PIPELINE NON LUE … Cause : {e} » sous `pipeline_fresh_non_lu` et `non_lus`.
//
// LE REMÈDE : la conformité sert la classe de la fin (`FIN_DE_PARCOURS_INTERROMPUE` / `FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE`
// d'`alerts.rs`) ou la phrase fixe du site (`REQUETE_DE_POSTURE_NON_COMPILEE`, `REGLES_MAPPEES_NON_LUES`,
// `TACHE_DE_LECTURE_EN_ECHEC`), le moteur à une ligne `[compliance] WARN` qui nomme la lecture et le tenant ; la recherche
// sert `RECHERCHE_REJETEE` (l'interruption garde sa phrase), le journal `[search] WARN` ne porte que la NATURE de
// l'erreur (code SQLite, par liste blanche), jamais son message ; la version de schéma et le bulletin servent leurs
// sous-phrases sans `{e}`, le moteur à `[system] WARN` (base opérateur, tenant, ou paquet de diagnostic) ; la flotte sert
// la constante seule, le moteur à `[fleet] WARN` avec le tenant.
//
// LES TÉMOINS :
// (1) `aq1_routes_corps_et_journal` : routeur réel en sous-processus, jeton lecteur (`/healthz` sans jeton, le paquet de
//     diagnostic en administrateur), chaque site ATTEIGNABLE : refusée et interrompue pour la posture, les quatre
//     lectures de l'ancrage, la recherche structurée et la recherche plein-texte (préparation refusée, collecte
//     interrompue, sur chacune des deux branches) ; règles mappées ; compilation refusée par un filtre de champ ; motif
//     invalide ; ligne non décodée ; version de schéma et bulletin illisibles ; bulletin indécodable ; santé du pipeline
//     refusée. Corps entiers, aucune trace du moteur dans la réponse (en-têtes compris), puis les lignes de journal EN
//     ENTIER, dans l'ordre. Le tenant y vaut `default` (mode 0) : ce témoin ne distingue pas le tenant de l'appelant ;
// (2) `aq1_deux_tenants` : DEUX tenants réels (mode 1), gestionnaires appelés au rôle lecteur, sur CHAQUE site qui
//     journalise le tenant (posture, règles mappées, compte, tête de chaîne, dernier point, premier maillon, compilation,
//     recherche structurée refusée et interrompue, recherche plein-texte refusée et interrompue, version de schéma,
//     bulletin illisible et indécodable, flotte) : la ligne nomme CELUI de l'appelant, l'autre tenant restant servi par
//     SA base ;
// (3) `aq1_sites_hors_d_atteinte` : les deux `JoinError` de la conformité (tâche bloquante qui panique, sans panne
//     atteignable) tenus par la ligne ENTIÈRE du source ; les deux `Err` de `query_map` de la recherche (liaison de
//     paramètres fixes, sans pas d'exécution) tenus par leur commentaire et leur ligne ;
// (4) `aq1_phrases_fixes` : chaque phrase à son littéral, et distinctes.
// Pannes : une connexion de lecture DÉPOSÉE dans le pool de la base, armée d'un autorisateur qui refuse la SEULE
// première lecture d'une colonne (ou de la table, colonne vide, pour `COUNT(*)`), ou qui arme un rappel de progression
// interrompant le SEUL énoncé qui lit cette colonne. Le drapeau levé par la panne dit qu'elle a servi ; sinon la requête
// est rejouée. Les textes attendus au journal sont REPRODUITS sur une connexion en mémoire (même refus, même motif),
// jamais recopiés.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la couverture froide de la recherche (`search.rs`, `cold_coverage_unread`, sous
// `cold_tier`) sert encore `({e})` ; la revalidation en fond de la flotte (cache périmé) ne journalise pas un échec qu'elle
// ne sert pas ; la ligne de la version de schéma du paquet de diagnostic ne nomme pas le tenant (la fonction pure ne le
// connaît pas).
// =====================================================================================
mod aq1_conformite_recherche_systeme_flotte {
    use super::*;
    use crate::handlers::alerts::{FIN_DE_PARCOURS_INTERROMPUE, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE};
    use crate::handlers::compliance::{
        CAUSE_ANCRAGE_NON_LU, CAUSE_POSTURE_NON_LUE, REGLES_MAPPEES_NON_LUES, REQUETE_DE_POSTURE_NON_COMPILEE, TACHE_DE_LECTURE_EN_ECHEC,
    };
    use crate::handlers::fleet::CAUSE_SANTE_DU_PIPELINE_NON_LUE;
    use crate::handlers::search::RECHERCHE_REJETEE;
    use crate::handlers::system::{
        CAUSE_BULLETIN_NON_ETABLI, CAUSE_VERSION_DE_SCHEMA_NON_ETABLIE, CLE_BULLETIN_NON_ETABLI, CLE_VERSION_DE_SCHEMA_NON_ETABLIE,
    };
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicBool, Ordering};

    const AQ1_ENFANT: &str = "AQ1_ENFANT_ROUTES";
    const AQ1_ENFANT_DEUX: &str = "AQ1_ENFANT_DEUX_TENANTS";
    const AQ1_RENDU: &str = "AQ1-RENDU:";
    const AQ1_FIN: &str = "AQ1-FIN:";
    /// Au plus autant de requêtes pour que la connexion armée serve la route (le pool global peut l'évincer).
    const AQ1_ESSAIS: usize = 40;
    const AQ1_ADMIN: &str = "root:rootpw1234567";
    const AQ1_TENANT_MODE_0: &str = "default";
    const AQ1_ALPHA: &str = "aq1-alpha";
    const AQ1_BETA: &str = "aq1-beta";
    const POSTURE: &str = "/api/compliance/posture";
    const RAPPORT: &str = "/api/compliance/report";
    const RECHERCHE: &str = "/api/search?q=host%3Aaq1-h";
    /// Un terme SANS champ : la barre prend la branche plein-texte (MATCH), qui lit aussi `event.src_ip`.
    const TERME_PLEIN_TEXTE: &str = "aq1sonde";
    const RECHERCHE_PLEIN_TEXTE: &str = "/api/search?q=aq1sonde";
    /// Ce qu'aucune réponse ne doit porter, en-têtes compris : les textes que le moteur, le compilateur, le décodeur ou
    /// `run_query` écrivent pour les pannes jouées ici.
    const TRACES_DU_MOTEUR: [&str; 10] = [
        "prohibited", "not authorized", "interrupted", "Invalid column", "expected value", "regex parse",
        "requête interrompue", "filtrage interdit", "no such", "code SQLite",
    ];

    /// Ce qui arme la connexion déposée : le refus de la première lecture d'UNE colonne (colonne vide : la table lue
    /// par `COUNT(*)`), ou l'interruption du seul énoncé qui la lit.
    #[derive(Clone, Copy)]
    enum Aq1Panne {
        Refus(&'static str, &'static str),
        Coupe(&'static str, &'static str),
    }

    /// Dépose dans le pool de `chemin` une connexion de lecture armée de `panne`, après avoir vidé les connexions au
    /// repos de cette base (la connexion armée est la seule à prendre). Le drapeau rendu dit si la panne a été jouée.
    fn aq1_armer(chemin: &str, panne: Aq1Panne) -> Arc<AtomicBool> {
        while crate::query_exec::connexions_de_lecture_au_repos(chemin) > 0 {
            drop(crate::query_exec::read_conn_get(chemin).expect("fixture : connexion au repos"));
        }
        let conn = crate::query_exec::read_conn_get(chemin).expect("fixture : connexion de lecture");
        let joue = Arc::new(AtomicBool::new(false));
        match panne {
            Aq1Panne::Refus(table, colonne) => {
                let drapeau = joue.clone();
                conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Read { table_name, column_name } if table_name == table && column_name == colonne && !drapeau.swap(true, Ordering::SeqCst) => {
                        Authorization::Deny
                    }
                    _ => Authorization::Allow,
                }));
            }
            Aq1Panne::Coupe(table, colonne) => {
                let vise = Arc::new(AtomicBool::new(false));
                let (armee, deja) = (vise.clone(), joue.clone());
                conn.authorizer(Some(move |ctx: AuthContext<'_>| {
                    match ctx.action {
                        AuthAction::Read { table_name, column_name } if table_name == table && column_name == colonne && !deja.load(Ordering::SeqCst) => {
                            armee.store(true, Ordering::SeqCst)
                        }
                        _ => {}
                    }
                    Authorization::Allow
                }));
                let drapeau = joue.clone();
                conn.progress_handler(1, Some(move || vise.swap(false, Ordering::SeqCst) && !drapeau.swap(true, Ordering::SeqCst)));
            }
        }
        crate::query_exec::read_conn_put(chemin, conn);
        joue
    }

    /// Rejoue `appel` jusqu'à ce que la connexion armée ait servi (`avant` est rejoué à chaque essai : vider un cache).
    async fn aq1_en_panne<T, F, Fut>(chemin: &str, panne: Aq1Panne, avant: &dyn Fn(), appel: F) -> T
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        for _ in 0..AQ1_ESSAIS {
            avant();
            let joue = aq1_armer(chemin, panne);
            let rendu = appel().await;
            if joue.load(Ordering::SeqCst) {
                return rendu;
            }
        }
        panic!("instrument : la connexion armée n'a servi en aucun des {AQ1_ESSAIS} essais — le témoin ne conclut pas");
    }

    /// GET par le routeur réel : (statut, corps, réponse brute en-têtes compris).
    async fn aq1_envoi(addr: std::net::SocketAddr, chemin: &str, authz: Option<&str>) -> (u16, String, String) {
        let (code, brut) = router_probe_envoi(addr, "GET", chemin, authz, &[], "").await;
        let (tete, corps) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {chemin} : {brut}"));
        let corps = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(corps.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {chemin}"))).expect("corps UTF-8")
        } else {
            corps.to_string()
        };
        (code, corps, brut)
    }

    /// Le texte que le moteur écrit quand l'autorisateur refuse la lecture de `table.colonne` (colonne vide : la table
    /// lue par `COUNT(*)`), REPRODUIT sur une connexion en mémoire.
    fn aq1_refus(table: &'static str, colonne: &'static str) -> rusqlite::Error {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        let col = if colonne.is_empty() { "x" } else { colonne };
        c.execute_batch(&format!("CREATE TABLE {table}({col});")).expect("instrument : table");
        c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == table && column_name == colonne => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let sql = if colonne.is_empty() { format!("SELECT COUNT(*) FROM {table}") } else { format!("SELECT {colonne} FROM {table}") };
        let refus = c.prepare(&sql).err();
        refus.unwrap_or_else(|| panic!("instrument : le refus de {table}.{colonne} n'a pas eu lieu"))
    }

    /// Le refus que l'UDF `regexp` lève pour le motif `(`, REPRODUIT sur une connexion qui porte les mêmes UDF.
    fn aq1_erreur_du_motif() -> rusqlite::Error {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        crate::query_exec::install_query_udfs(&c);
        c.execute_batch("CREATE TABLE t(m TEXT); INSERT INTO t VALUES('x');").expect("instrument : table");
        let refus = c
            .prepare("SELECT m FROM t WHERE m REGEXP '('")
            .and_then(|mut s| s.query_map([], |r| r.get::<_, String>(0)).and_then(|lignes| lignes.collect::<rusqlite::Result<Vec<String>>>()))
            .err();
        refus.expect("instrument : le motif invalide est refusé par le moteur")
    }

    /// La NATURE qu'un refus de la recherche laisse au journal : son code SQLite, jamais son message.
    fn aq1_nature(e: &rusqlite::Error) -> String {
        match e {
            rusqlite::Error::SqliteFailure(f, _) => format!("code SQLite {} ({:?})", f.extended_code, f.code),
            autre => panic!("instrument : erreur sans code SQLite : {autre}"),
        }
    }

    /// Le texte de rusqlite pour une colonne `value` qui porte un BLOB lue en TEXT.
    fn aq1_texte_du_blob() -> String {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        let refus = c.query_row("SELECT x'FF' AS value", [], |r| r.get::<_, String>(0)).err();
        refus.map(|e| e.to_string()).expect("instrument : un BLOB ne se lit pas en TEXT")
    }

    fn aq1_texte_du_decodage() -> String {
        serde_json::from_str::<Value>("pas-du-json").err().map(|e| e.to_string()).expect("instrument : « pas-du-json » ne se décode pas")
    }

    /// La phrase de l'interruption de la recherche, écrite ici EN ENTIER (pas tirée de `search_engine_error` : un
    /// mutant qui confondrait les deux classes y changerait aussi l'attendu).
    fn aq1_recherche_interrompue() -> String {
        format!(
            "recherche INTERROMPUE : le budget de lecture de {} ms a été dépassé — ce n'est PAS « aucun résultat », la \
             recherche n'est pas allée au bout. Resserrez la fenêtre (`from`/`to`) ou ajoutez un filtre structuré (`host:`, \
             `source:`, `severity:`) ; pour une exploration délibérément longue, passez par /api/query (budget interactif \
             séparé).",
            READ_WATCHDOG_BUDGET_MS
        )
    }

    fn aq1_avec(mut v: Value, cle: &str, valeur: Value) -> Value {
        v[cle] = valeur;
        v
    }

    fn aq1_sans_stats(mut v: Value) -> Value {
        if let Some(o) = v.as_object_mut() {
            o.remove("stats");
        }
        v
    }

    fn aq1_cles(v: &Value) -> Vec<String> {
        let mut c: Vec<String> = v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        c.sort();
        c
    }

    fn aq1_semer_la_posture(chemin: &str) {
        let conn = open_db(chemin).expect("fixture : base");
        let mk = |ctrl: &str, res: &str| {
            json!({ "agent": { "name": "h1" }, "data": { "sca": { "type": "check", "policy": "CIS",
                "check": { "id": ctrl, "title": "t", "result": res, "compliance": [ { "pci_dss": ["8.7"] } ] } } } })
        };
        ingest_wazuh(&conn, chemin, "aq1-1", mk("1", "failed"));
        ingest_wazuh(&conn, chemin, "aq1-2", mk("2", "passed"));
        conn.execute_batch(
            "UPDATE rule SET compliance=NULL;
             INSERT INTO event(ts,source,severity,message,host,src_ip) VALUES(1000,'aq1',1,'m-aq1','aq1-h',NULL);
             INSERT INTO event(ts,source,severity,message,host,src_ip) VALUES(1001,'aq1',1,'m-blob','aq1-blob',x'FF');",
        )
        .expect("fixture : règles sans cadre, deux événements dont un à src_ip illisible");
    }

    type Aq1Rendus = Vec<(String, u16, String, String)>;

    fn aq1_garder(rendus: &mut Aq1Rendus, issue: &str, (code, corps, brut): (u16, String, String)) {
        rendus.push((issue.to_string(), code, corps, brut));
    }

    /// La partie jouée par l'enfant (mode 0) : chaque issue, dans l'ordre ; les attendus qui dépendent de la fixture
    /// (fenêtre de la recherche, refus du compilateur) sont rendus sous `attendu:`.
    async fn aq1_jouer_routes() -> Aq1Rendus {
        let mut rendus: Aq1Rendus = Vec::new();
        let (st, _base) = router_test_state("aq1-routes");
        let chemin = st.db_path.as_ref().clone();
        aq1_semer_la_posture(&chemin);
        rendus.push(("attendu:fenetre".into(), 0, st.search_limit_default.to_string(), String::new()));
        let ecrivain = st.db.clone();
        let addr = router_serve(st.clone()).await;
        let lecteur = viewer_authz();
        let v = Some(lecteur.as_str());
        let admin = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(AQ1_ADMIN));
        let rien = || {};

        aq1_garder(&mut rendus, "posture_nominale", aq1_envoi(addr, POSTURE, v).await);
        aq1_garder(&mut rendus, "posture_refusee", aq1_en_panne(&chemin, Aq1Panne::Refus("event", "category"), &rien, || aq1_envoi(addr, POSTURE, v)).await);
        aq1_garder(&mut rendus, "posture_coupee", aq1_en_panne(&chemin, Aq1Panne::Coupe("event", "category"), &rien, || aq1_envoi(addr, POSTURE, v)).await);
        aq1_garder(&mut rendus, "regles_refusees", aq1_en_panne(&chemin, Aq1Panne::Refus("rule", "compliance"), &rien, || aq1_envoi(addr, POSTURE, v)).await);
        aq1_garder(&mut rendus, "rapport_nominal", aq1_envoi(addr, RAPPORT, v).await);
        for (issue, panne) in [
            ("compte_refuse", Aq1Panne::Refus("ledger", "")),
            ("compte_coupe", Aq1Panne::Coupe("ledger", "")),
            ("tete_refusee", Aq1Panne::Refus("ledger", "hash")),
            ("tete_coupee", Aq1Panne::Coupe("ledger", "hash")),
            ("point_refuse", Aq1Panne::Refus("checkpoint", "ts")),
            ("point_coupe", Aq1Panne::Coupe("checkpoint", "ts")),
            ("maillon_refuse", Aq1Panne::Refus("ledger", "ts")),
            ("maillon_coupe", Aq1Panne::Coupe("ledger", "ts")),
        ] {
            aq1_garder(&mut rendus, issue, aq1_en_panne(&chemin, panne, &rien, || aq1_envoi(addr, RAPPORT, v)).await);
        }
        aq1_garder(&mut rendus, "recherche_nominale", aq1_envoi(addr, RECHERCHE, v).await);
        aq1_garder(&mut rendus, "recherche_refusee", aq1_en_panne(&chemin, Aq1Panne::Refus("event", "src_ip"), &rien, || aq1_envoi(addr, RECHERCHE, v)).await);
        aq1_garder(&mut rendus, "recherche_coupee", aq1_en_panne(&chemin, Aq1Panne::Coupe("event", "src_ip"), &rien, || aq1_envoi(addr, RECHERCHE, v)).await);
        aq1_garder(&mut rendus, "recherche_motif", aq1_envoi(addr, "/api/search?q=regex%3D%28", v).await);
        aq1_garder(&mut rendus, "recherche_ligne", aq1_envoi(addr, "/api/search?q=host%3Aaq1-blob", v).await);
        aq1_garder(&mut rendus, "plein_texte_nominal", aq1_envoi(addr, RECHERCHE_PLEIN_TEXTE, v).await);
        aq1_garder(&mut rendus, "plein_texte_refuse", aq1_en_panne(&chemin, Aq1Panne::Refus("event", "src_ip"), &rien, || aq1_envoi(addr, RECHERCHE_PLEIN_TEXTE, v)).await);
        aq1_garder(&mut rendus, "plein_texte_coupe", aq1_en_panne(&chemin, Aq1Panne::Coupe("event", "src_ip"), &rien, || aq1_envoi(addr, RECHERCHE_PLEIN_TEXTE, v)).await);

        aq1_garder(&mut rendus, "sonde_nominale", aq1_envoi(addr, "/healthz", None).await);
        let version: String = ecrivain
            .lock()
            .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0))
            .expect("fixture : version de schéma lue");
        ecrivain.lock().execute("UPDATE meta SET value=x'FF' WHERE key='schema_version'", []).expect("fixture : version illisible");
        aq1_garder(&mut rendus, "sonde_illisible", aq1_envoi(addr, "/healthz", None).await);
        aq1_garder(&mut rendus, "metriques_illisibles", aq1_envoi(addr, "/metrics", v).await);
        aq1_garder(&mut rendus, "ecran_illisible", aq1_envoi(addr, "/api/system/metrics", v).await);
        aq1_garder(&mut rendus, "diagnostic_illisible", aq1_envoi(addr, "/api/system/diag", Some(admin.as_str())).await);
        ecrivain.lock().execute("UPDATE meta SET value=?1 WHERE key='schema_version'", params![version]).expect("fixture : version rétablie");

        aq1_garder(&mut rendus, "bulletin_nominal", aq1_envoi(addr, "/api/bulletin", v).await);
        ecrivain
            .lock()
            .execute("INSERT INTO setting(scope,key,value,updated,updated_by) VALUES('global','bulletin',x'FF',1,'aq1')", [])
            .expect("fixture : bulletin illisible");
        aq1_garder(&mut rendus, "bulletin_illisible", aq1_envoi(addr, "/api/bulletin", v).await);
        ecrivain.lock().execute("UPDATE setting SET value='pas-du-json' WHERE key='bulletin'", []).expect("fixture : bulletin indécodable");
        aq1_garder(&mut rendus, "bulletin_indecodable", aq1_envoi(addr, "/api/bulletin", v).await);
        ecrivain.lock().execute("DELETE FROM setting WHERE key='bulletin'", []).expect("fixture : bulletin retiré");

        let vider = || {
            crate::handlers::fleet::fleet_map().lock().remove(&chemin);
        };
        aq1_garder(&mut rendus, "flotte_refusee", aq1_en_panne(&chemin, Aq1Panne::Refus("metric", "ts"), &vider, || aq1_envoi(addr, "/api/fleet", v)).await);
        vider();
        aq1_garder(&mut rendus, "flotte_nominale", aq1_envoi(addr, "/api/fleet", v).await);

        // LA COMPILATION REFUSÉE : un filtre de champ masque `category` pour tout rôle, sur une base à part (le registre
        // des filtres est rangé par chemin de base).
        let (st_b, _base_b) = router_test_state("aq1-compilation");
        let chemin_b = st_b.db_path.as_ref().clone();
        {
            let conn = open_db(&chemin_b).expect("fixture : base du filtre");
            conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('aq1','category','mask','')", []).expect("fixture : filtre de champ");
            field_filters_reload(&conn, &chemin_b);
        }
        let refus_du_compilateur = soql_to_sql_masked_x(
            &crate::handlers::compliance::compliance_posture_soql(),
            0,
            0,
            None,
            &effective_masks(&chemin_b, "viewer", AQ1_TENANT_MODE_0, None),
        )
        .err()
        .unwrap_or_default();
        rendus.push(("attendu:compilation".into(), 0, refus_du_compilateur, String::new()));
        let addr_b = router_serve(st_b.clone()).await;
        aq1_garder(&mut rendus, "posture_non_compilee", aq1_envoi(addr_b, POSTURE, v).await);
        rendus
    }

    /// (1) LES ROUTES : corps entiers par issue, aucune trace du moteur dans la réponse, puis le journal EN ENTIER.
    #[tokio::test]
    async fn aq1_routes_corps_et_journal() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        if std::env::var(AQ1_ENFANT).is_ok() {
            let rendus = aq1_jouer_routes().await;
            for (issue, code, corps, brut) in &rendus {
                println!("{AQ1_RENDU}{}", json!([issue, code, corps, brut]));
            }
            println!("{AQ1_FIN} {}", rendus.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::aq1_conformite_recherche_systeme_flotte::aq1_routes_corps_et_journal"])
            .env(AQ1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let tous: Vec<(String, u16, String, String)> = stdout
            .lines()
            .filter_map(|l| l.split_once(AQ1_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : ligne de rendu lisible ({e}) : {v}")))
            .collect();
        assert!(stdout.contains(&format!("{AQ1_FIN} 34")), "contrôle : l'enfant a joué ses trente-deux issues et rendu ses deux attendus : {stdout}\n{stderr}");
        assert_eq!(tous.len(), 34, "contrôle : une ligne par issue : {stdout}");
        let rendu = |issue: &str| -> (u16, Value, String) {
            let (_, code, corps, brut) = tous.iter().find(|(i, ..)| i == issue).unwrap_or_else(|| panic!("contrôle : {issue} rendu par l'enfant"));
            (*code, serde_json::from_str(corps).unwrap_or(Value::Null), brut.clone())
        };
        let attendu = |cle: &str| -> String { tous.iter().find(|(i, ..)| i == cle).map(|(_, _, c, _)| c.clone()).unwrap_or_else(|| panic!("contrôle : {cle}")) };

        // LA RÉPONSE NE PORTE AUCUN TEXTE DU MOTEUR, en-têtes compris, sur AUCUNE issue.
        let servis: Vec<&(String, u16, String, String)> = tous.iter().filter(|(i, ..)| !i.starts_with("attendu:")).collect();
        assert!(servis.len() >= 32, "plancher : trente-deux issues jouées par la route ({})", servis.len());
        for (issue, _, _, brut) in &servis {
            for trace in TRACES_DU_MOTEUR {
                assert!(!brut.contains(trace), "{issue} : la réponse porte « {trace} » : {brut}");
            }
        }

        // ---- CONFORMITÉ : POSTURE ----
        let (s, nominale, _) = rendu("posture_nominale");
        assert!(
            s == 200 && nominale["summary"].as_array().map(|a| !a.is_empty()).unwrap_or(false) && nominale.get("error").is_none(),
            "contrôle : la posture nominale est lue (un cadre au moins) et n'avoue rien : {nominale}"
        );
        let cadres = nominale["frameworks"].clone();
        let posture_vide = |classe: &str| {
            json!({ "framework": null, "since": 0, "summary": [], "truncated": false, "frameworks": cadres.clone(),
                    "error": format!("{CAUSE_POSTURE_NON_LUE}{classe}") })
        };
        assert_eq!(rendu("posture_refusee").1, posture_vide(FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE), "posture refusée : la classe du refus");
        assert_eq!(rendu("posture_coupee").1, posture_vide(FIN_DE_PARCOURS_INTERROMPUE), "posture coupée : la classe de l'interruption");
        assert_eq!(
            rendu("regles_refusees").1,
            aq1_avec(nominale.clone(), "error", json!(format!("{CAUSE_POSTURE_NON_LUE}{REGLES_MAPPEES_NON_LUES}"))),
            "règles mappées refusées : la posture lue reste servie, la phrase fixe s'ajoute"
        );
        assert_eq!(
            rendu("posture_non_compilee").1,
            json!({ "framework": null, "controls": [], "rules": [], "totals": {}, "frameworks": cadres.clone(),
                    "error": format!("{CAUSE_POSTURE_NON_LUE}{REQUETE_DE_POSTURE_NON_COMPILEE}") }),
            "compilation refusée : la forme vide et la phrase fixe"
        );
        assert_eq!(rendu("posture_non_compilee").0, 200);

        // ---- CONFORMITÉ : ANCRAGE ----
        let (s, rapport, _) = rendu("rapport_nominal");
        let preuve = rapport["evidence"].clone();
        assert!(s == 200 && preuve.get("error").is_none() && preuve["ledger_entries"].is_i64(), "contrôle : ancrage nominal lu : {rapport}");
        assert_eq!(rapport["posture"], nominale, "contrôle : le rapport porte la posture lue");
        let (n, tete, point) = (preuve["ledger_entries"].clone(), preuve["ledger_head"].clone(), preuve["last_checkpoint_ts"].clone());
        let ancrage = |base: Value, classe: &str| aq1_avec(base, "error", json!(format!("{CAUSE_ANCRAGE_NON_LU}{classe}")));
        let lus_ancrage: Vec<(&str, Value)> = ["compte_refuse", "compte_coupe", "tete_refusee", "tete_coupee", "point_refuse", "point_coupe", "maillon_refuse", "maillon_coupe"]
            .iter()
            .map(|i| {
                let (s, v, _) = rendu(*i);
                assert_eq!(s, 200, "{i} : statut");
                assert_eq!(aq1_cles(&v), aq1_cles(&rapport), "{i} : les clés du rapport sont intactes");
                assert_eq!(v["posture"], nominale, "{i} : la posture, lue, n'est pas accusée");
                (*i, v["evidence"].clone())
            })
            .collect();
        let (r, c) = (FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE, FIN_DE_PARCOURS_INTERROMPUE);
        assert_eq!(
            lus_ancrage,
            vec![
                ("compte_refuse", ancrage(json!({}), r)),
                ("compte_coupe", ancrage(json!({}), c)),
                ("tete_refusee", ancrage(json!({ "ledger_entries": n }), r)),
                ("tete_coupee", ancrage(json!({ "ledger_entries": n }), c)),
                ("point_refuse", ancrage(json!({ "ledger_entries": n, "ledger_head": tete }), r)),
                ("point_coupe", ancrage(json!({ "ledger_entries": n, "ledger_head": tete }), c)),
                ("maillon_refuse", ancrage(json!({ "ledger_entries": n, "ledger_head": tete, "last_checkpoint_ts": point }), r)),
                ("maillon_coupe", ancrage(json!({ "ledger_entries": n, "ledger_head": tete, "last_checkpoint_ts": point }), c)),
            ],
            "chaque lecture de l'ancrage : ce qui a été lu avant elle, et la classe de sa fin"
        );

        // ---- RECHERCHE ----
        let fenetre: i64 = attendu("attendu:fenetre").parse().expect("contrôle : fenêtre de la recherche");
        let (s, nominale_r, _) = rendu("recherche_nominale");
        assert!(s == 200 && nominale_r.get("stats").is_some(), "contrôle : la recherche publie son découpage : {nominale_r}");
        assert_eq!(
            aq1_sans_stats(nominale_r),
            json!({ "results": [{ "ts": 1000, "source": "aq1", "severity": 1, "message": "m-aq1", "host": "aq1-h", "src_ip": null }],
                    "served": 1, "window": fenetre, "truncated": false }),
            "contrôle : la recherche nominale à l'octet"
        );
        let rejet = json!({ "results": [], "error": RECHERCHE_REJETEE });
        for issue in ["recherche_refusee", "recherche_motif", "recherche_ligne", "plein_texte_refuse"] {
            let (s, v, _) = rendu(issue);
            assert!(s == 200 && v.get("stats").is_some(), "{issue} : statut et découpage : {v}");
            assert_eq!(aq1_sans_stats(v), rejet, "{issue} : la phrase fixe du refus, jamais le message du moteur");
        }
        for issue in ["recherche_coupee", "plein_texte_coupe"] {
            let (s, v, _) = rendu(issue);
            assert_eq!((s, aq1_sans_stats(v)), (200, json!({ "results": [], "error": aq1_recherche_interrompue() })), "{issue} : la phrase de l'interruption");
        }
        // CONTRÔLE DE BRANCHE : la forme servie à vide par la branche structurée sans filtre est `{ "results": [] }` seul ;
        // `served`/`window`/`truncated` disent que le MATCH plein-texte a été exécuté jusqu'au bout.
        let (s, v, _) = rendu("plein_texte_nominal");
        assert_eq!(
            (s, aq1_sans_stats(v)),
            (200, json!({ "results": [], "served": 0, "window": fenetre, "truncated": false })),
            "contrôle : la recherche plein-texte nominale, exécutée, sans erreur"
        );
        assert_ne!(aq1_recherche_interrompue(), RECHERCHE_REJETEE, "deux classes, deux phrases");

        // ---- SYSTÈME ----
        let version = env!("CARGO_PKG_VERSION");
        assert_eq!(rendu("sonde_nominale").1, json!({ "ok": true, "version": version, "schema": CODE_SCHEMA_MAX }), "contrôle : sonde nominale");
        let aveu_schema = format!("{CAUSE_VERSION_DE_SCHEMA_NON_ETABLIE} La lecture a échoué.");
        let (s, sonde, _) = rendu("sonde_illisible");
        assert_eq!(s, 200, "la sonde de vivacité reste verte");
        assert_eq!(
            sonde,
            json!({ "ok": true, "version": version, "schema": null, CLE_VERSION_DE_SCHEMA_NON_ETABLIE: aveu_schema }),
            "sonde SANS authentification : la phrase fixe, jamais le texte du moteur"
        );
        let (s, _, brut) = rendu("metriques_illisibles");
        assert!(s == 200 && brut.contains("schema=\"non_etablie\""), "/metrics : l'étiquette n'affirme aucune version : {brut}");
        for issue in ["ecran_illisible", "diagnostic_illisible"] {
            let (s, v, _) = rendu(issue);
            assert_eq!(s, 200, "{issue} : statut");
            assert_eq!(
                (v["schema_version"].clone(), v[CLE_VERSION_DE_SCHEMA_NON_ETABLIE].clone()),
                (Value::Null, json!(aveu_schema)),
                "{issue} : `null` et la phrase fixe"
            );
        }
        assert_eq!(rendu("bulletin_nominal").1, json!({ "bulletin": null }), "contrôle : aucun bandeau");
        assert_eq!(
            rendu("bulletin_illisible").1,
            json!({ "bulletin": null, CLE_BULLETIN_NON_ETABLI: format!("{CAUSE_BULLETIN_NON_ETABLI} La lecture a échoué.") }),
            "bulletin illisible : la sous-phrase de la lecture, sans le moteur"
        );
        assert_eq!(
            rendu("bulletin_indecodable").1,
            json!({ "bulletin": null, CLE_BULLETIN_NON_ETABLI: format!("{CAUSE_BULLETIN_NON_ETABLI} La ligne existe et ne se décode pas.") }),
            "bulletin indécodable : la sous-phrase du décodage, sans le décodeur"
        );

        // ---- FLOTTE ----
        let (s, flotte, _) = rendu("flotte_refusee");
        assert_eq!(s, 200);
        assert_eq!(
            aq1_cles(&flotte),
            vec!["hosts", "non_lus", "now", "pipeline_fresh", "pipeline_fresh_non_lu", "repartition", "total"],
            "flotte : l'inventaire reste servi, sans `error` : {flotte}"
        );
        assert_eq!(
            (flotte["pipeline_fresh"].clone(), flotte["pipeline_fresh_non_lu"].clone(), flotte["non_lus"].clone()),
            (Value::Null, json!(CAUSE_SANTE_DU_PIPELINE_NON_LUE), json!([CAUSE_SANTE_DU_PIPELINE_NON_LUE])),
            "flotte : la constante seule, sur ses deux clés"
        );
        let (s, flotte, _) = rendu("flotte_nominale");
        assert!(
            s == 200 && flotte["pipeline_fresh"].is_boolean() && flotte.get("pipeline_fresh_non_lu").is_none() && flotte.get("non_lus").is_none(),
            "contrôle : flotte nominale, santé lue : {flotte}"
        );

        // ---- LE JOURNAL, EN ENTIER, DANS L'ORDRE ----
        let t = AQ1_TENANT_MODE_0;
        let coupe_execution = format!("requête interrompue (budget {} s dépassé)", crate::query_exec::query_budget_ms() / 1000);
        let blob = aq1_texte_du_blob();
        let lecture = |quoi: &str, moteur: String| format!("[compliance] WARN lecture {quoi} non faite (tenant '{t}') : {moteur}");
        let interruption = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERRUPT), None);
        let journal: Vec<&str> = stderr
            .lines()
            .filter(|l| ["[compliance] WARN", "[search] WARN", "[system] WARN", "[fleet] WARN"].iter().any(|p| l.starts_with(p)))
            .collect();
        assert_eq!(
            journal,
            vec![
                lecture("de la posture", aq1_refus("event", "category").to_string()),
                lecture("de la posture", coupe_execution),
                lecture("des règles mappées", aq1_refus("rule", "compliance").to_string()),
                lecture("du compte du journal d'intégrité", aq1_refus("ledger", "").to_string()),
                lecture("du compte du journal d'intégrité", "interrupted".to_string()),
                lecture("de la tête de chaîne", aq1_refus("ledger", "hash").to_string()),
                lecture("de la tête de chaîne", "interrupted".to_string()),
                lecture("du dernier point de contrôle", aq1_refus("checkpoint", "ts").to_string()),
                lecture("du dernier point de contrôle", "interrupted".to_string()),
                lecture("du premier maillon", aq1_refus("ledger", "ts").to_string()),
                lecture("du premier maillon", "interrupted".to_string()),
                format!("[search] WARN recherche rejetée par le moteur (tenant '{t}') : {}", aq1_nature(&aq1_refus("event", "src_ip"))),
                format!("[search] WARN recherche interrompue (tenant '{t}') : {}", aq1_nature(&interruption)),
                format!("[search] WARN recherche rejetée par le moteur (tenant '{t}') : {}", aq1_nature(&aq1_erreur_du_motif())),
                format!("[search] WARN recherche rejetée par le moteur (tenant '{t}') : erreur hors du code SQLite (ligne non décodée)"),
                format!("[search] WARN recherche rejetée par le moteur (tenant '{t}') : {}", aq1_nature(&aq1_refus("event", "src_ip"))),
                format!("[search] WARN recherche interrompue (tenant '{t}') : {}", aq1_nature(&interruption)),
                format!("[system] WARN version de schéma non lue (base opérateur) : {blob}"),
                format!("[system] WARN version de schéma non lue (base opérateur) : {blob}"),
                format!("[system] WARN version de schéma non lue (tenant '{t}') : {blob}"),
                format!("[system] WARN version de schéma non lue (base du paquet de diagnostic) : {blob}"),
                format!("[system] WARN bulletin non lu (tenant '{t}') : {blob}"),
                format!("[system] WARN bulletin non décodé (tenant '{t}') : {}", aq1_texte_du_decodage()),
                format!("[fleet] WARN santé du pipeline non lue (tenant '{t}') : {}", aq1_refus("metric", "ts")),
                lecture("de la posture (compilation)", attendu("attendu:compilation")),
            ],
            "une ligne EXACTE par lecture ratée, le texte du moteur au journal seul (la recherche : sa nature), aucune pour une issue nominale :\n{stderr}"
        );
        assert!(!attendu("attendu:compilation").is_empty(), "contrôle : le filtre de champ refuse bien la compilation");
    }

    fn aq1_lecteur(tenant: &str) -> AuthUser {
        AuthUser { name: "lecteur-aq1".into(), role: "viewer".into(), tenant: tenant.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }

    /// Crée le tenant `t` (vraie route de création), retire les cadres de ses règles, et rend le chemin de SA base.
    async fn aq1_creer_le_tenant(st: &AppState, t: &str) -> String {
        let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-aq1")), Json(json!({ "id": t, "name": t }))).await;
        assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
        assert!(st.tenants.tenant_available(t), "contrôle : tenant {t} résolu pour le pool de lecture");
        st.tenants.handle_for(t).expect("contrôle : base du tenant").lock().execute_batch("UPDATE rule SET compliance=NULL;").expect("fixture : règles sans cadre");
        st.tenants.ready_db_path(t).expect("contrôle : chemin de la base du tenant")
    }

    async fn aq1_posture(st: &AppState, t: &str) -> Value {
        compliance_posture(State(st.clone()), Extension(aq1_lecteur(t)), axum::extract::Query(HashMap::new())).await.0
    }

    async fn aq1_ancrage(st: &AppState, t: &str) -> Value {
        compliance_report(State(st.clone()), Extension(aq1_lecteur(t)), axum::extract::Query(HashMap::new())).await.0["evidence"].clone()
    }

    async fn aq1_recherche(st: &AppState, t: &str, texte: &str) -> Value {
        let q: HashMap<String, String> = HashMap::from([("q".to_string(), texte.to_string())]);
        aq1_sans_stats(crate::handlers::search::search(State(st.clone()), Extension(aq1_lecteur(t)), axum::extract::Query(q)).await.0)
    }

    async fn aq1_ecran(st: &AppState, t: &str) -> Value {
        let v = system_metrics(State(st.clone()), Extension(aq1_lecteur(t))).await.0;
        json!([v["schema_version"].clone(), v.get(CLE_VERSION_DE_SCHEMA_NON_ETABLIE).cloned()])
    }

    async fn aq1_bulletin(st: &AppState, t: &str) -> Value {
        bulletin_get(State(st.clone()), Extension(aq1_lecteur(t))).await.0
    }

    async fn aq1_flotte(st: &AppState, t: &str) -> Value {
        let v = crate::handlers::fleet::fleet(State(st.clone()), Extension(aq1_lecteur(t)), axum::extract::Query(HashMap::new())).await.0;
        json!([v["pipeline_fresh"].clone(), v.get("pipeline_fresh_non_lu").cloned(), v.get("non_lus").cloned()])
    }

    /// L'ancrage réduit à ce qui ne dépend pas de la base : ses clés et son aveu.
    fn aq1_cles_et_erreur(v: Value) -> Value {
        json!([aq1_cles(&v), v["error"].clone()])
    }

    fn aq1_ecrire(st: &AppState, t: &str, sql: &str) {
        st.tenants.handle_for(t).expect("contrôle : base du tenant").lock().execute_batch(sql).expect("fixture : écriture dans la base du tenant");
    }

    async fn aq1_jouer_deux_tenants() -> Vec<(String, Value)> {
        let (st, _dir) = mk_mode1_state();
        let alpha = aq1_creer_le_tenant(&st, AQ1_ALPHA).await;
        let beta = aq1_creer_le_tenant(&st, AQ1_BETA).await;
        assert_ne!(alpha, beta, "contrôle : deux bases distinctes");
        let mut rendus: Vec<(String, Value)> = Vec::new();
        let rien = || {};
        let refus_posture = Aq1Panne::Refus("event", "category");
        rendus.push(("posture_refusee:alpha".into(), aq1_en_panne(&alpha, refus_posture, &rien, || aq1_posture(&st, AQ1_ALPHA)).await));
        rendus.push(("posture_nominale:beta".into(), aq1_posture(&st, AQ1_BETA).await));
        rendus.push(("posture_refusee:beta".into(), aq1_en_panne(&beta, refus_posture, &rien, || aq1_posture(&st, AQ1_BETA)).await));
        rendus.push(("posture_nominale:alpha".into(), aq1_posture(&st, AQ1_ALPHA).await));
        let refus_compte = Aq1Panne::Refus("ledger", "");
        rendus.push(("compte_refuse:alpha".into(), aq1_en_panne(&alpha, refus_compte, &rien, || aq1_ancrage(&st, AQ1_ALPHA)).await));
        rendus.push(("compte_refuse:beta".into(), aq1_en_panne(&beta, refus_compte, &rien, || aq1_ancrage(&st, AQ1_BETA)).await));
        let refus_recherche = Aq1Panne::Refus("event", "src_ip");
        rendus.push(("recherche_refusee:alpha".into(), aq1_en_panne(&alpha, refus_recherche, &rien, || aq1_recherche(&st, AQ1_ALPHA, "host:aq1-h")).await));
        rendus.push(("recherche_refusee:beta".into(), aq1_en_panne(&beta, refus_recherche, &rien, || aq1_recherche(&st, AQ1_BETA, "host:aq1-h")).await));

        // LES AUTRES SITES QUI JOURNALISENT LE TENANT, en alternant l'appelant (l'autre tenant reste muet au journal).
        rendus.push(("regles_refusees:alpha".into(), aq1_en_panne(&alpha, Aq1Panne::Refus("rule", "compliance"), &rien, || aq1_posture(&st, AQ1_ALPHA)).await));
        rendus.push(("tete_refusee:beta".into(), aq1_cles_et_erreur(aq1_en_panne(&beta, Aq1Panne::Refus("ledger", "hash"), &rien, || aq1_ancrage(&st, AQ1_BETA)).await)));
        rendus.push(("point_refuse:alpha".into(), aq1_cles_et_erreur(aq1_en_panne(&alpha, Aq1Panne::Refus("checkpoint", "ts"), &rien, || aq1_ancrage(&st, AQ1_ALPHA)).await)));
        rendus.push(("maillon_refuse:beta".into(), aq1_cles_et_erreur(aq1_en_panne(&beta, Aq1Panne::Refus("ledger", "ts"), &rien, || aq1_ancrage(&st, AQ1_BETA)).await)));
        let evenement = "INSERT INTO event(ts,source,severity,message,host,src_ip) VALUES(1000,'aq1',1,'m-aq1','aq1-h',NULL);";
        aq1_ecrire(&st, AQ1_ALPHA, evenement);
        aq1_ecrire(&st, AQ1_BETA, evenement);
        let coupe_recherche = Aq1Panne::Coupe("event", "src_ip");
        rendus.push(("recherche_coupee:alpha".into(), aq1_en_panne(&alpha, coupe_recherche, &rien, || aq1_recherche(&st, AQ1_ALPHA, "host:aq1-h")).await));
        rendus.push(("plein_texte_refuse:beta".into(), aq1_en_panne(&beta, refus_recherche, &rien, || aq1_recherche(&st, AQ1_BETA, TERME_PLEIN_TEXTE)).await));
        rendus.push(("plein_texte_coupe:alpha".into(), aq1_en_panne(&alpha, coupe_recherche, &rien, || aq1_recherche(&st, AQ1_ALPHA, TERME_PLEIN_TEXTE)).await));

        let illisible = "UPDATE meta SET value=x'FF' WHERE key='schema_version';";
        let lisible = format!("UPDATE meta SET value='{CODE_SCHEMA_MAX}' WHERE key='schema_version';");
        aq1_ecrire(&st, AQ1_ALPHA, illisible);
        rendus.push(("ecran_illisible:alpha".into(), aq1_ecran(&st, AQ1_ALPHA).await));
        rendus.push(("ecran_lu:beta".into(), aq1_ecran(&st, AQ1_BETA).await));
        aq1_ecrire(&st, AQ1_ALPHA, &lisible);
        aq1_ecrire(&st, AQ1_BETA, illisible);
        rendus.push(("ecran_illisible:beta".into(), aq1_ecran(&st, AQ1_BETA).await));
        rendus.push(("ecran_lu:alpha".into(), aq1_ecran(&st, AQ1_ALPHA).await));
        aq1_ecrire(&st, AQ1_BETA, &lisible);

        aq1_ecrire(&st, AQ1_ALPHA, "INSERT INTO setting(scope,key,value,updated,updated_by) VALUES('global','bulletin',x'FF',1,'aq1');");
        aq1_ecrire(&st, AQ1_BETA, "INSERT INTO setting(scope,key,value,updated,updated_by) VALUES('global','bulletin','pas-du-json',1,'aq1');");
        rendus.push(("bulletin_illisible:alpha".into(), aq1_bulletin(&st, AQ1_ALPHA).await));
        rendus.push(("bulletin_indecodable:beta".into(), aq1_bulletin(&st, AQ1_BETA).await));

        let vider_alpha = || {
            crate::handlers::fleet::fleet_map().lock().remove(&alpha);
        };
        let vider_beta = || {
            crate::handlers::fleet::fleet_map().lock().remove(&beta);
        };
        let refus_flotte = Aq1Panne::Refus("metric", "ts");
        rendus.push(("flotte_refusee:alpha".into(), aq1_en_panne(&alpha, refus_flotte, &vider_alpha, || aq1_flotte(&st, AQ1_ALPHA)).await));
        rendus.push(("flotte_refusee:beta".into(), aq1_en_panne(&beta, refus_flotte, &vider_beta, || aq1_flotte(&st, AQ1_BETA)).await));

        {
            // La base d'un tenant est chiffrée par SA clé : la fixture passe par sa poignée, pas par un `open_db` nu.
            let h = st.tenants.handle_for(AQ1_ALPHA).expect("contrôle : base d'alpha");
            let conn = h.lock();
            conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('aq1','category','mask','')", []).expect("fixture : filtre de champ");
            field_filters_reload(&conn, &alpha);
        }
        let refus_du_compilateur = soql_to_sql_masked_x(
            &crate::handlers::compliance::compliance_posture_soql(),
            0,
            0,
            None,
            &effective_masks(&alpha, "viewer", AQ1_ALPHA, None),
        )
        .err()
        .unwrap_or_default();
        rendus.push(("attendu:compilation".into(), json!(refus_du_compilateur)));
        rendus.push(("posture_non_compilee:alpha".into(), aq1_posture(&st, AQ1_ALPHA).await));
        rendus.push(("posture_nominale_hors_filtre:beta".into(), aq1_posture(&st, AQ1_BETA).await));
        rendus
    }

    /// (2) DEUX TENANTS RÉELS (mode 1) : chaque ligne qui nomme un tenant nomme celui de l'appelant ; l'autre tenant est
    /// servi par SA base. Corps des issues jouées, lignes en entier, dans l'ordre.
    #[tokio::test]
    async fn aq1_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        if std::env::var(AQ1_ENFANT_DEUX).is_ok() {
            let rendus = aq1_jouer_deux_tenants().await;
            for (issue, corps) in &rendus {
                println!("{AQ1_RENDU}{}", json!([issue, corps]));
            }
            println!("{AQ1_FIN} {}", rendus.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::aq1_conformite_recherche_systeme_flotte::aq1_deux_tenants"])
            .env(AQ1_ENFANT_DEUX, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(&format!("{AQ1_FIN} 26")), "contrôle : l'enfant a joué ses vingt-cinq issues et rendu son attendu : {stdout}\n{stderr}");
        let tous: Vec<(String, Value)> = stdout
            .lines()
            .filter_map(|l| l.split_once(AQ1_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : ligne de rendu lisible ({e}) : {v}")))
            .collect();
        let corps = |cle: &str| -> Value { tous.iter().find(|(i, _)| i == cle).map(|(_, c)| c.clone()).unwrap_or_else(|| panic!("contrôle : {cle} rendu par l'enfant")) };
        let erreur = |cle: &str| corps(cle).get("error").cloned();
        let posture = |classe: &str| Some(json!(format!("{CAUSE_POSTURE_NON_LUE}{classe}")));
        let aveu_schema = json!(format!("{CAUSE_VERSION_DE_SCHEMA_NON_ETABLIE} La lecture a échoué."));
        let flotte = json!([null, CAUSE_SANTE_DU_PIPELINE_NON_LUE, [CAUSE_SANTE_DU_PIPELINE_NON_LUE]]);
        let lus: Vec<(&str, Value)> = vec![
            ("posture_refusee:alpha", json!(erreur("posture_refusee:alpha"))),
            ("posture_nominale:beta", json!(erreur("posture_nominale:beta"))),
            ("posture_refusee:beta", json!(erreur("posture_refusee:beta"))),
            ("posture_nominale:alpha", json!(erreur("posture_nominale:alpha"))),
            ("compte_refuse:alpha", corps("compte_refuse:alpha")),
            ("compte_refuse:beta", corps("compte_refuse:beta")),
            ("recherche_refusee:alpha", corps("recherche_refusee:alpha")),
            ("recherche_refusee:beta", corps("recherche_refusee:beta")),
            ("regles_refusees:alpha", json!(erreur("regles_refusees:alpha"))),
            ("tete_refusee:beta", corps("tete_refusee:beta")),
            ("point_refuse:alpha", corps("point_refuse:alpha")),
            ("maillon_refuse:beta", corps("maillon_refuse:beta")),
            ("recherche_coupee:alpha", corps("recherche_coupee:alpha")),
            ("plein_texte_refuse:beta", corps("plein_texte_refuse:beta")),
            ("plein_texte_coupe:alpha", corps("plein_texte_coupe:alpha")),
            ("ecran_illisible:alpha", corps("ecran_illisible:alpha")),
            ("ecran_lu:beta", corps("ecran_lu:beta")),
            ("ecran_illisible:beta", corps("ecran_illisible:beta")),
            ("ecran_lu:alpha", corps("ecran_lu:alpha")),
            ("bulletin_illisible:alpha", corps("bulletin_illisible:alpha")),
            ("bulletin_indecodable:beta", corps("bulletin_indecodable:beta")),
            ("flotte_refusee:alpha", corps("flotte_refusee:alpha")),
            ("flotte_refusee:beta", corps("flotte_refusee:beta")),
            ("posture_non_compilee:alpha", json!(erreur("posture_non_compilee:alpha"))),
            ("posture_nominale_hors_filtre:beta", json!(erreur("posture_nominale_hors_filtre:beta"))),
        ];
        let ancrage = json!({ "error": format!("{CAUSE_ANCRAGE_NON_LU}{FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE}") });
        let rejet = json!({ "results": [], "error": RECHERCHE_REJETEE });
        let interrompue = json!({ "results": [], "error": aq1_recherche_interrompue() });
        let aveu_ancrage = json!(format!("{CAUSE_ANCRAGE_NON_LU}{FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE}"));
        assert_eq!(
            lus,
            vec![
                ("posture_refusee:alpha", json!(posture(FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE))),
                ("posture_nominale:beta", Value::Null),
                ("posture_refusee:beta", json!(posture(FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE))),
                ("posture_nominale:alpha", Value::Null),
                ("compte_refuse:alpha", ancrage.clone()),
                ("compte_refuse:beta", ancrage),
                ("recherche_refusee:alpha", rejet.clone()),
                ("recherche_refusee:beta", rejet.clone()),
                ("regles_refusees:alpha", json!(posture(REGLES_MAPPEES_NON_LUES))),
                ("tete_refusee:beta", json!([["error", "ledger_entries"], aveu_ancrage.clone()])),
                ("point_refuse:alpha", json!([["error", "ledger_entries", "ledger_head"], aveu_ancrage.clone()])),
                ("maillon_refuse:beta", json!([["error", "last_checkpoint_ts", "ledger_entries", "ledger_head"], aveu_ancrage])),
                ("recherche_coupee:alpha", interrompue.clone()),
                ("plein_texte_refuse:beta", rejet),
                ("plein_texte_coupe:alpha", interrompue),
                ("ecran_illisible:alpha", json!([null, aveu_schema.clone()])),
                ("ecran_lu:beta", json!([CODE_SCHEMA_MAX, null])),
                ("ecran_illisible:beta", json!([null, aveu_schema])),
                ("ecran_lu:alpha", json!([CODE_SCHEMA_MAX, null])),
                ("bulletin_illisible:alpha", json!({ "bulletin": null, CLE_BULLETIN_NON_ETABLI: format!("{CAUSE_BULLETIN_NON_ETABLI} La lecture a échoué.") })),
                ("bulletin_indecodable:beta", json!({ "bulletin": null, CLE_BULLETIN_NON_ETABLI: format!("{CAUSE_BULLETIN_NON_ETABLI} La ligne existe et ne se décode pas.") })),
                ("flotte_refusee:alpha", flotte.clone()),
                ("flotte_refusee:beta", flotte),
                ("posture_non_compilee:alpha", json!(posture(REQUETE_DE_POSTURE_NON_COMPILEE))),
                ("posture_nominale_hors_filtre:beta", Value::Null),
            ],
            "le tenant refusé sert la phrase fixe, l'autre est servi par SA base"
        );
        let blob = aq1_texte_du_blob();
        let (a, b) = (AQ1_ALPHA, AQ1_BETA);
        let interruption = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERRUPT), None);
        let journal: Vec<&str> = stderr
            .lines()
            .filter(|l| ["[compliance] WARN", "[search] WARN", "[system] WARN", "[fleet] WARN"].iter().any(|p| l.starts_with(p)))
            .collect();
        let compilation = corps("attendu:compilation").as_str().unwrap_or_default().to_string();
        assert!(!compilation.is_empty(), "contrôle : le filtre de champ d'alpha refuse la compilation");
        assert_eq!(
            journal,
            vec![
                format!("[compliance] WARN lecture de la posture non faite (tenant '{a}') : {}", aq1_refus("event", "category")),
                format!("[compliance] WARN lecture de la posture non faite (tenant '{b}') : {}", aq1_refus("event", "category")),
                format!("[compliance] WARN lecture du compte du journal d'intégrité non faite (tenant '{a}') : {}", aq1_refus("ledger", "")),
                format!("[compliance] WARN lecture du compte du journal d'intégrité non faite (tenant '{b}') : {}", aq1_refus("ledger", "")),
                format!("[search] WARN recherche rejetée par le moteur (tenant '{a}') : {}", aq1_nature(&aq1_refus("event", "src_ip"))),
                format!("[search] WARN recherche rejetée par le moteur (tenant '{b}') : {}", aq1_nature(&aq1_refus("event", "src_ip"))),
                format!("[compliance] WARN lecture des règles mappées non faite (tenant '{a}') : {}", aq1_refus("rule", "compliance")),
                format!("[compliance] WARN lecture de la tête de chaîne non faite (tenant '{b}') : {}", aq1_refus("ledger", "hash")),
                format!("[compliance] WARN lecture du dernier point de contrôle non faite (tenant '{a}') : {}", aq1_refus("checkpoint", "ts")),
                format!("[compliance] WARN lecture du premier maillon non faite (tenant '{b}') : {}", aq1_refus("ledger", "ts")),
                format!("[search] WARN recherche interrompue (tenant '{a}') : {}", aq1_nature(&interruption)),
                format!("[search] WARN recherche rejetée par le moteur (tenant '{b}') : {}", aq1_nature(&aq1_refus("event", "src_ip"))),
                format!("[search] WARN recherche interrompue (tenant '{a}') : {}", aq1_nature(&interruption)),
                format!("[system] WARN version de schéma non lue (tenant '{a}') : {blob}"),
                format!("[system] WARN version de schéma non lue (tenant '{b}') : {blob}"),
                format!("[system] WARN bulletin non lu (tenant '{a}') : {blob}"),
                format!("[system] WARN bulletin non décodé (tenant '{b}') : {}", aq1_texte_du_decodage()),
                format!("[fleet] WARN santé du pipeline non lue (tenant '{a}') : {}", aq1_refus("metric", "ts")),
                format!("[fleet] WARN santé du pipeline non lue (tenant '{b}') : {}", aq1_refus("metric", "ts")),
                format!("[compliance] WARN lecture de la posture (compilation) non faite (tenant '{a}') : {compilation}"),
            ],
            "une ligne EXACTE par refus, qui nomme le tenant de l'appelant :\n{stderr}"
        );
    }

    /// (3) LES DEUX SITES HORS D'ATTEINTE — la tâche bloquante qui panique (`JoinError`) : aucune panne ne s'y joue par la
    /// route. La ligne ENTIÈRE est comparée, une fois chacune : la phrase fixe, le texte du `JoinError` au journal seul.
    #[test]
    fn aq1_sites_hors_d_atteinte() {
        let src = include_str!("../handlers/compliance.rs");
        let posture = "    .unwrap_or_else(|e| (std::collections::BTreeMap::new(), std::collections::BTreeMap::new(), 0, Some(lecture_non_faite(\"de la posture (tâche)\", &au.tenant, TACHE_DE_LECTURE_EN_ECHEC, &e.to_string()))));\n";
        let ancrage = "    .unwrap_or_else(|e| corps_de_lecture_non_faite(json!({}), CAUSE_ANCRAGE_NON_LU, lecture_non_faite(\"de l'ancrage (tâche)\", &au.tenant, TACHE_DE_LECTURE_EN_ECHEC, &e.to_string())));\n";
        assert_eq!(src.matches(posture).count(), 1, "la tâche de la posture : la phrase fixe, une fois");
        assert_eq!(src.matches(ancrage).count(), 1, "la tâche de l'ancrage : la phrase fixe, une fois");
        assert_eq!(src.matches(".unwrap_or_else(|e|").count(), 2, "contrôle : deux `JoinError` dans le module, ni plus ni moins");

        // LES DEUX `Err` DE `query_map` DE LA RECHERCHE : liaison de paramètres fixes, sans pas d'exécution. Le commentaire
        // qui dit pourquoi ET la ligne qui sert la phrase fixe sous le tenant de l'appelant, ensemble, deux fois.
        let src = include_str!("../handlers/search.rs");
        let site = "                    Err(e) => return with_coverage(search_engine_error(&e, &tenant)),";
        let tenu = [
            "                    // HORS D'ATTEINTE : `query_map` ne fait que LIER les paramètres (rusqlite 0.31, `Statement::query`), sans",
            "                    // aucun pas d'exécution ; leur nombre est fixé par l'énoncé, la seule chaîne liée vient d'une URL bornée",
            "                    // bien en deçà de SQLITE_LIMIT_LENGTH (non abaissé ici). Tenu par la lecture du source (témoins `aq1_`).",
            site,
            "",
        ]
        .join("\n");
        assert_eq!(src.matches(tenu.as_str()).count(), 2, "les deux `query_map` : le commentaire et la phrase fixe sous le tenant de l'appelant");
        assert_eq!(src.matches(&format!("{site}\n")).count(), 4, "contrôle : quatre sites de cette forme (deux préparations témoignées par la route, deux `query_map`)");
    }

    /// (4) LES PHRASES FIXES : chacune à son littéral, et distinctes (les attendus des autres témoins sont construits sur
    /// ces mêmes symboles : un texte commun n'y rougirait pas).
    #[test]
    fn aq1_phrases_fixes() {
        assert_eq!(REQUETE_DE_POSTURE_NON_COMPILEE, "la requête de posture n'a pas été compilée pour ce rôle");
        assert_eq!(REGLES_MAPPEES_NON_LUES, "règles mappées NON LUES : la lecture de `rule` a échoué — une carte vide serait un repli, pas une mesure");
        assert_eq!(TACHE_DE_LECTURE_EN_ECHEC, "la tâche de lecture a échoué (panique ou annulation du pool bloquant)");
        assert_eq!(RECHERCHE_REJETEE, "le moteur de recherche a REFUSÉ cette requête (ce n'est pas « aucun résultat ») : motif rejeté par le moteur de recherche");
        let phrases = [REQUETE_DE_POSTURE_NON_COMPILEE, REGLES_MAPPEES_NON_LUES, TACHE_DE_LECTURE_EN_ECHEC, FIN_DE_PARCOURS_INTERROMPUE, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE];
        let distinctes: std::collections::BTreeSet<&str> = phrases.iter().copied().collect();
        assert_eq!(distinctes.len(), 5, "cinq phrases de conformité, cinq textes");
    }
}
