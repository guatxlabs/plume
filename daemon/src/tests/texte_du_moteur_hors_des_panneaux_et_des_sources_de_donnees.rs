// =====================================================================================
// `P10.29-l` (vague AS) — LE TEXTE DU MOTEUR NE PART PLUS AU CLIENT PAR LES PANNEAUX NI PAR LES SOURCES DE DONNÉES.
//
// LE DÉFAUT, LU SUR 5c7b6de8 AVANT LE CORRECTIF :
//  * `handlers/dashboards.rs` — le rafraîchissement de fond d'un panneau en échec écrivait `corps_d_echec(cause)` dans
//    `panel_cache`, `error` = texte du moteur ; le HIT le servait en 200 à TOUT lecteur du panneau (le cache est
//    rôle-agnostique et persistant). Les trois voies d'exécution directe (live avec permis, live sans permis, masquée)
//    servaient `bad_req(e)`, `e` = texte du moteur ;
//  * `handlers/datasource.rs` — `/api/ds/query` servait `bad_req(e)` où `e` mêlait le texte du compilateur et celui du
//    moteur ; `/api/v1/query`, `/api/v1/query_range` et `/api/v1/series` servaient `prom_err(e)`, texte du moteur ;
//  * `handlers/dash_ergonomics.rs` — `capture_dashboard_data` figeait le texte du moteur (`"error": e`) dans l'instantané,
//    servi tel quel par `snapshot_get` à tout détenteur du jeton.
// Au rôle lecteur, le refus de l'autorisateur citait la colonne lue, une E/S ratée se lisait comme une faute de la
// requête, et une base occupée comme un rejet.
//
// LE REMÈDE : la classe est relue sur le fil qui exécute (`query_exec::en_classant`) ; les voies directes et
// `/api/ds/query` servent `refus_de_requete` (503 nommés pour le support et la base occupée, phrase du produit à
// l'octet, `REQUETE_REJETEE_PAR_LE_MOTEUR` sinon) ; le refus du COMPILATEUR reste servi à l'octet en 400 ; les routes
// Prometheus gardent leur forme `{status, errorType, error}` (503 `unavailable` avec `id` pour le support et la base
// occupée) ; le corps d'échec mis en cache porte la phrase de la classe et la classe sous `classe_d_echec`, retirée au
// HIT ; un corps d'échec écrit par une version antérieure (sans classe) n'est plus servi : il est traité comme une
// absence et recalculé. Le moteur part au journal avec la route et le tenant de l'appelant. L'instantané fige la même
// phrase et la classe (retirée au service) ; un instantané figé par une version antérieure ne sert plus son `error`.
//
// LES TÉMOINS :
// (1) `as1_routes_par_le_routeur` : routeur réel en sous-processus, jeton lecteur, mode 0. Chaque site — panneau live,
//     panneau live sans permis (lane saturée, cache coupé), panneau masqué (règle de masque du lecteur), panneau en
//     SWR (rafraîchissement en échec puis deux HIT), `/api/ds/query` en GET et en POST, les trois routes Prometheus —
//     nominal puis par classe (support, base occupée, produit, moteur) ; refus du compilateur à l'octet (live, masqué,
//     GET et POST de `/api/ds/query`) ; ligne `panel_cache` à l'ANCIENNE forme insérée à la main : jamais servie, le
//     panneau est recalculé ; ligne à la forme COURANTE insérée à la main : servie, classe retirée. Corps entiers,
//     aucune trace du moteur dans la réponse (en-têtes compris) ni dans `panel_cache`, journal comparé ligne à ligne ;
// (2) `as1_deux_tenants` : mode 1, DEUX tenants réels, gestionnaires appelés au rôle lecteur, chaque site et les
//     classes support, base occupée et moteur pour chacun des deux tenants : la ligne nomme CELUI de l'appelant,
//     l'autre tenant reste servi par sa base ;
// (3) `as1_chaque_geste_du_journal_porte_la_route_et_le_tenant` : les quatre gestes d'un rafraîchissement en échec
//     (cache coupé, charge conservée, corps NON écrit, corps écrit), ligne entière ;
// (4) `as1_corps_d_echec_a_classe_inconnue_traite_comme_l_ancienne_forme` : classe forgée hors liste -> MISS, recalcul ;
// (5) `as1_instantanes` : capture puis `snapshot_get`, chaque classe, ligne de journal entière ; instantané antérieur ;
// (6) `as1_ds_soql_exec_n_existe_que_dans_les_tests` : `#[cfg(test)]`, aucun `allow(dead_code)`.
// Pannes : `query_exec::panne_de_test_au_coeur` (UDF `regexp` ou autorisateur armés au cœur) pour les panneaux et
// `/api/ds/query` ; pour les routes Prometheus, dont l'énoncé n'appelle pas `regexp`, une connexion de lecture armée
// à la main puis rendue au pool (`json_extract` remplacée, autorisateur qui refuse `metric.labels`).
//
// MUTANTS DE LA CORRECTION (VERIF_MUT, retirés avant le commit), chacun vu ROUGE sur son témoin : AS2_JOURNAL_COUPE,
// AS2_JOURNAL_CONSERVE, AS2_JOURNAL_NON_ECRIT (préfixe d'avant le lot) -> (3) ; AS2_CLASSE_TOUTE (présence de la classe
// sans appartenance) -> (4) ; AS2_INST_TEXTE, AS2_INST_TENANT, AS2_INST_FILTRE, AS2_INST_TOUTE_CLASSE,
// AS2_INST_CLASSE_SERVIE, AS2_INST_COMPILATION_SANS_CLASSE -> (5) ; `#[allow(dead_code)]` remis sur `ds_soql_exec` -> (6).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une voie froide (aucune ici) ; la ligne `[query] WARN` peut citer l'énoncé
// (reste nommé par la vague AR) ; un instantané stocké n'est pas réécrit (le filtre est au service) ; une charge utile
// illisible en cache (`Err(_) => false`) reste servie telle quelle, comme avant le lot.
// =====================================================================================
mod as1_texte_du_moteur_hors_des_panneaux_et_des_sources {
    use super::*;
    use crate::handlers::query::{
        CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE as ILLISIBLE, CAUSE_REQUETE_NON_SERVIE_BASE_OCCUPEE as OCCUPEE, REQUETE_REJETEE_PAR_LE_MOTEUR as REJETEE,
    };
    use crate::query_exec::panne_de_test_au_coeur::{demander, encore_demandee, retirer, PanneAuCoeur};
    use rusqlite::functions::FunctionFlags;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const AS1_ENFANT_ROUTEUR: &str = "AS1_ENFANT_ROUTEUR";
    const AS1_ENFANT_DEUX: &str = "AS1_ENFANT_DEUX_TENANTS";
    const AS1_ATTENDU: &str = "AS1-ATTENDU:";
    const AS1_FIN: &str = "AS1-FIN:";
    const AS1_ALPHA: &str = "as1-alpha";
    const AS1_BETA: &str = "as1-beta";
    /// La route des données d'un panneau, écrite ici (et non empruntée à la production) : un témoin qui lirait la
    /// constante ne verrait pas qu'elle change.
    const AS1_ROUTE_PANNEAU: &str = "/api/panels/{id}/data";
    const AS1_SQL_EN_PANNE: &str = "SELECT message FROM event WHERE message REGEXP 'as1'";
    const AS1_SQL_SAIN: &str = "SELECT 1 AS un";
    const AS1_GXQL_REFUSE: &str = "search source=as1 | inputlookup secret";
    const AS1_GXQL_MASQUE: &str = "search src_user=as1-alice | table host";
    const AS1_SOQL: &str = "search source=as1 message=~\"as1\"";
    const AS1_PROM: &str = "as1_metric{k=\"v\"}";
    /// Un `error` mis en cache par une version antérieure : le refus de l'autorisateur, qui cite l'énoncé.
    const AS1_TEXTE_ANCIEN: &str = "not authorized to use function: COUNT in SELECT COUNT(DISTINCT message) FROM event WHERE src_user='as1-secret'";
    /// Ce qu'aucune réponse refusée ni aucune ligne `panel_cache` ne doit porter : textes et natures du moteur joués ici.
    const TRACES_DU_MOTEUR: [&str; 11] = [
        "prohibited", "disk I/O", "code SQLite", "SQLITE", "event.message", "metric.labels", "panne de test", "not authorized", "as1-secret",
        "database is locked", "REGEXP",
    ];
    const CLASSES: [&str; 4] = ["support", "occupee", "produit", "moteur"];
    const CLASSES_DU_JOURNAL: [&str; 3] = ["support", "occupee", "moteur"];
    const ROUTES_PROM: [&str; 3] = ["/api/v1/query_range", "/api/v1/query", "/api/v1/series"];

    #[derive(Clone, Copy)]
    struct As1Panneaux {
        live: i64,
        sans_permis: i64,
        masque: i64,
        swr: i64,
        refuse_live: i64,
        refuse_masque: i64,
        ancien: i64,
        nouveau: i64,
    }

    fn as1_semer(conn: &Connection, maintenant: i64) -> As1Panneaux {
        conn.execute(
            "INSERT INTO event(ts,source,severity,message,host,src_ip) VALUES(?1,'as1',1,'as1-sonde','as1-h',NULL)",
            params![maintenant - 60],
        )
        .expect("fixture : événement");
        conn.execute(
            "INSERT INTO metric(ts,name,labels,value,host) VALUES(?1,'as1_metric','{\"k\":\"v\"}',1.0,'as1-h')",
            params![maintenant - 60],
        )
        .expect("fixture : métrique");
        conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('as1','root','shared')", []).expect("fixture : tableau");
        let did = conn.last_insert_rowid();
        let panneau = |q: &str, soql: i64| -> i64 {
            conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'as1',?2,?3,'table')", params![did, q, soql])
                .expect("fixture : panneau");
            conn.last_insert_rowid()
        };
        let p = As1Panneaux {
            live: panneau(AS1_SQL_EN_PANNE, 0),
            sans_permis: panneau(AS1_SQL_EN_PANNE, 0),
            masque: panneau(AS1_SQL_EN_PANNE, 0),
            swr: panneau(AS1_SQL_EN_PANNE, 0),
            refuse_live: panneau(AS1_GXQL_REFUSE, 1),
            refuse_masque: panneau(AS1_GXQL_MASQUE, 1),
            ancien: panneau(AS1_SQL_SAIN, 0),
            nouveau: panneau(AS1_SQL_SAIN, 0),
        };
        // Cache coupé pour ce panneau : la branche « cache off ET lane saturée » exécute sans permis.
        conn.execute("UPDATE panel SET panel_cache_ttl_s=0 WHERE id=?1", params![p.sans_permis]).expect("fixture : ttl nul");
        // Coût CONNU et léger : voie live (le coût inconnu part en SWR).
        record_panel_cost(conn, p.live, &query_fingerprint(AS1_SQL_EN_PANNE, false), 1.0, maintenant);
        record_panel_cost(conn, p.refuse_live, &query_fingerprint(AS1_GXQL_REFUSE, true), 1.0, maintenant);
        p
    }

    fn as1_masquer(conn: &Connection, chemin: &str) {
        conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('as1','src_user','mask','viewer')", []).expect("fixture : masque");
        field_filters_reload(conn, chemin);
    }

    fn as1_vider_le_pool(chemin: &str) {
        while crate::query_exec::connexions_de_lecture_au_repos(chemin) > 0 {
            drop(crate::query_exec::read_conn_get(chemin).expect("fixture : connexion au repos"));
        }
    }

    fn as1_panne(classe: &str) -> PanneAuCoeur {
        match classe {
            "support" => PanneAuCoeur::ErreurDuSupport,
            "occupee" => PanneAuCoeur::BaseOccupee,
            "produit" => PanneAuCoeur::Interruption,
            "moteur" => PanneAuCoeur::RefusDeLAutorisateur,
            autre => panic!("instrument : classe inconnue {autre}"),
        }
    }

    /// Arme UNE connexion de lecture de `chemin` pour une route Prometheus (énoncé sur `metric`, sans `regexp`) et la
    /// rend au pool : la lecture suivante de cette base la prend. Le produit passe par la panne au cœur (interruption).
    fn as1_armer_prom(chemin: &str, classe: &str) {
        as1_vider_le_pool(chemin);
        if classe == "produit" {
            demander(chemin, PanneAuCoeur::Interruption);
            return;
        }
        let c = crate::query_exec::read_conn_get(chemin).expect("instrument : connexion de lecture");
        let utf8 = FunctionFlags::SQLITE_UTF8;
        match classe {
            "support" | "occupee" => {
                let code = if classe == "support" { rusqlite::ffi::SQLITE_IOERR_READ } else { rusqlite::ffi::SQLITE_BUSY };
                c.create_scalar_function("json_extract", 2, utf8, move |_ctx| -> rusqlite::Result<String> {
                    Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None))
                })
                .expect("instrument : json_extract remplacée");
            }
            "moteur" => {
                c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Read { table_name, column_name } if table_name == "metric" && column_name == "labels" => Authorization::Deny,
                    _ => Authorization::Allow,
                }));
            }
            autre => panic!("instrument : classe inconnue {autre}"),
        }
        crate::query_exec::read_conn_put(chemin, c);
    }

    /// Après une route Prometheus armée : la panne a servi (interruption consommée, ou connexion armée sortie du pool
    /// puis rendue — elle est fermée ici avec les autres).
    fn as1_desarmer_prom(chemin: &str, classe: &str) -> bool {
        let servie = if classe == "produit" { !encore_demandee(chemin) } else { true };
        retirer(chemin);
        as1_vider_le_pool(chemin);
        servie
    }

    // ---------- reproductions en mémoire : natures et textes que le journal doit porter ----------

    fn as1_nature(e: &rusqlite::Error) -> String {
        match e {
            rusqlite::Error::SqliteFailure(f, _) => format!("code SQLite {} ({:?})", f.extended_code, f.code),
            autre => panic!("instrument : erreur sans code SQLite : {autre}"),
        }
    }

    fn as1_erreur_de_code(code: i32) -> rusqlite::Error {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        c.create_scalar_function("as1_erreur", 1, FunctionFlags::SQLITE_UTF8, |ctx| -> rusqlite::Result<i64> {
            Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(ctx.get::<i32>(0)?), None))
        })
        .expect("instrument : fonction d'erreur");
        c.query_row(&format!("SELECT as1_erreur({code})"), [], |r| r.get::<_, i64>(0)).err().expect("instrument : l'erreur est rendue au pas")
    }

    fn as1_refus_de_lecture(table: &'static str, colonne: &'static str) -> rusqlite::Error {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        c.execute_batch(&format!("CREATE TABLE {table}({colonne} TEXT);")).expect("instrument : table");
        c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == table && column_name == colonne => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        c.prepare(&format!("SELECT {colonne} FROM {table}")).err().expect("instrument : le refus a lieu")
    }

    fn as1_nature_support() -> String {
        as1_nature(&as1_erreur_de_code(rusqlite::ffi::SQLITE_IOERR_READ))
    }

    fn as1_nature_occupee() -> String {
        as1_nature(&as1_erreur_de_code(rusqlite::ffi::SQLITE_BUSY))
    }

    fn as1_phrase_du_budget() -> String {
        format!("requête interrompue (budget {} s dépassé)", crate::query_exec::query_budget_ms() / 1000)
    }

    fn as1_ligne_query(classe: &str, route: &str, tenant: &str, id: &str) -> String {
        match classe {
            "support" => format!("[query] WARN requête non servie, erreur du support de la base ({route}, tenant '{tenant}', {id}) : {}", as1_nature_support()),
            "occupee" => format!("[query] WARN requête non servie, base occupée ({route}, tenant '{tenant}', {id}) : {}", as1_nature_occupee()),
            "moteur" => {
                let e = as1_refus_de_lecture("event", "message");
                format!("[query] WARN requête rejetée par le moteur ({route}, tenant '{tenant}') : {} : {:?}", as1_nature(&e), e.to_string())
            }
            autre => panic!("instrument : aucune ligne pour {autre}"),
        }
    }

    fn as1_ligne_prom(classe: &str, route: &str, tenant: &str, id: &str) -> String {
        match classe {
            "support" => format!("[datasource] WARN série non servie, erreur du support de la base ({route}, tenant '{tenant}', {id}) : {}", as1_nature_support()),
            "occupee" => format!("[datasource] WARN série non servie, base occupée ({route}, tenant '{tenant}', {id}) : {}", as1_nature_occupee()),
            "moteur" => {
                let e = as1_refus_de_lecture("metric", "labels");
                format!("[datasource] WARN série rejetée par le moteur ({route}, tenant '{tenant}') : {} : {:?}", as1_nature(&e), e.to_string())
            }
            autre => panic!("instrument : aucune ligne pour {autre}"),
        }
    }

    /// La ligne `[panel]` d'un rafraîchissement en échec dont le corps est écrit : la cause (nature seule pour le
    /// support et la base occupée, phrase du produit, texte du moteur), la route, le tenant de l'appelant, le geste.
    fn as1_ligne_panel(classe: &str, panneau: i64, tenant: &str) -> String {
        let cause = as1_cause(classe);
        format!(
            "[panel] WARN rafraîchissement du panneau {panneau} en échec ({cause}) — {AS1_ROUTE_PANNEAU}, tenant '{tenant}' — corps d'échec servi, nouvelle tentative à l'expiration du cache"
        )
    }

    /// La cause qu'une ligne de journal porte pour un panneau armé (`as1_panne`) : la nature seule pour le support et la
    /// base occupée, la phrase du produit, le texte du moteur.
    fn as1_cause(classe: &str) -> String {
        match classe {
            "support" => as1_nature_support(),
            "occupee" => as1_nature_occupee(),
            "produit" => as1_phrase_du_budget(),
            "moteur" => as1_refus_de_lecture("event", "message").to_string(),
            autre => panic!("instrument : classe inconnue {autre}"),
        }
    }

    fn as1_phrase(classe: &str) -> String {
        match classe {
            "support" => ILLISIBLE.to_string(),
            "occupee" => OCCUPEE.to_string(),
            "produit" => as1_phrase_du_budget(),
            "moteur" => REJETEE.to_string(),
            autre => panic!("instrument : classe inconnue {autre}"),
        }
    }

    // ---------- jugement des corps ----------

    fn as1_json(corps: &str) -> Value {
        serde_json::from_str(corps).unwrap_or_else(|_| json!({ "_texte": corps }))
    }

    fn as1_cles(v: &Value) -> Vec<String> {
        let mut c: Vec<String> = v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        c.sort();
        c
    }

    fn as1_sans_trace(contexte: &str, brut: &str) {
        for trace in TRACES_DU_MOTEUR {
            assert!(!brut.contains(trace), "{contexte} : la réponse porte « {trace} » : {brut}");
        }
    }

    /// Le refus d'une route JSON (`refus_de_requete`) pour une classe : 503 `{error, id}` (rend l'identifiant) ou 400
    /// `{error}` exactement.
    fn as1_juger_refus(contexte: &str, classe: &str, code: u16, corps: &str) -> Option<String> {
        let v = as1_json(corps);
        match classe {
            "support" | "occupee" => {
                assert_eq!(code, 503, "{contexte} : statut ; corps {corps}");
                assert_eq!(as1_cles(&v), vec!["error", "id"], "{contexte} : exactement `error` et `id` : {corps}");
                assert_eq!(v["error"], json!(as1_phrase(classe)), "{contexte} : la phrase fixe de la classe");
                let id = v["id"].as_str().unwrap_or_default().to_string();
                assert!(id.starts_with("plume-e"), "{contexte} : identifiant de corrélation : {corps}");
                Some(id)
            }
            _ => {
                assert_eq!((code, v), (400, json!({ "error": as1_phrase(classe) })), "{contexte} : 400 et la phrase de la classe, à l'octet");
                None
            }
        }
    }

    /// Le refus d'une route Prometheus : forme `{status, errorType, error}` gardée, `id` en plus pour un 503.
    fn as1_juger_prom(contexte: &str, classe: &str, code: u16, corps: &str) -> Option<String> {
        let v = as1_json(corps);
        match classe {
            "support" | "occupee" => {
                assert_eq!(code, 503, "{contexte} : statut ; corps {corps}");
                assert_eq!(as1_cles(&v), vec!["error", "errorType", "id", "status"], "{contexte} : forme Prometheus et identifiant : {corps}");
                assert_eq!(
                    (v["status"].clone(), v["errorType"].clone(), v["error"].clone()),
                    (json!("error"), json!("unavailable"), json!(as1_phrase(classe))),
                    "{contexte} : statut, type et phrase fixe"
                );
                let id = v["id"].as_str().unwrap_or_default().to_string();
                assert!(id.starts_with("plume-e"), "{contexte} : identifiant de corrélation : {corps}");
                Some(id)
            }
            _ => {
                assert_eq!(
                    (code, v),
                    (400, json!({ "status": "error", "errorType": "bad_data", "error": as1_phrase(classe) })),
                    "{contexte} : 400 Prometheus, la phrase de la classe à l'octet"
                );
                None
            }
        }
    }

    /// Le corps d'échec servi au HIT : `{columns, error, rows, stats}` exactement, la phrase de la classe, aucune ligne.
    fn as1_juger_hit(contexte: &str, classe: &str, code: u16, corps: &str) {
        let v = as1_json(corps);
        assert_eq!(code, 200, "{contexte} : statut ; corps {corps}");
        assert_eq!(as1_cles(&v), vec!["columns", "error", "rows", "stats"], "{contexte} : la forme d'avant, sans `warming` ni classe : {corps}");
        assert_eq!(v["error"], json!(as1_phrase(classe)), "{contexte} : la phrase de la classe");
        assert_eq!((v["columns"].clone(), v["rows"].clone()), (json!([]), json!([])), "{contexte} : aucune ligne inventée");
        assert_eq!(v["stats"]["coverage"]["reason"], json!(crate::handlers::panneau_avoue::RAISON_CALCUL_ECHOUE), "{contexte} : l'aveu de l'échec");
    }

    fn as1_payload_du_cache(conn: &Connection, panneau: i64) -> Vec<String> {
        let mut stmt = conn.prepare("SELECT payload FROM panel_cache WHERE panel_id=?1").expect("lecture du cache");
        stmt.query_map(params![panneau], |r| r.get::<_, String>(0)).expect("lecture du cache").collect::<rusqlite::Result<Vec<_>>>().expect("lignes du cache")
    }

    fn as1_encoder(s: &str) -> String {
        s.bytes().map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
    }

    fn as1_chemin_prom(route: &str, maintenant: i64) -> String {
        let q = as1_encoder(AS1_PROM);
        match route {
            "/api/v1/query_range" => format!("{route}?query={q}&start={}&end={}", maintenant - 3600, maintenant + 60),
            "/api/v1/query" => format!("{route}?query={q}&time={maintenant}"),
            "/api/v1/series" => format!("{route}?match%5B%5D={q}&start={}&end={}", maintenant - 3600, maintenant + 60),
            autre => panic!("instrument : route {autre}"),
        }
    }

    fn as1_prom_nominal(contexte: &str, route: &str, code: u16, corps: &str) {
        let v = as1_json(corps);
        assert_eq!((code, v["status"].clone()), (200, json!("success")), "{contexte} : nominal servi : {corps}");
        let n = if route == "/api/v1/series" { v["data"].as_array().map(|a| a.len()) } else { v["data"]["result"].as_array().map(|a| a.len()) };
        assert_eq!(n, Some(1), "{contexte} : la série semée est rendue : {corps}");
    }

    // ---------- le routeur réel, mode 0 ----------

    async fn as1_envoi(addr: std::net::SocketAddr, methode: &str, chemin: &str, corps: Option<&Value>) -> (u16, String, String) {
        let entetes = [("Content-Type", "application/json")];
        let texte = corps.map(|c| c.to_string()).unwrap_or_default();
        let (code, brut) = router_probe_envoi(addr, methode, chemin, Some(&viewer_authz()), &entetes, &texte).await;
        let (tete, c) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {chemin} : {brut}"));
        let c = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(c.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {chemin}"))).expect("corps UTF-8")
        } else {
            c.to_string()
        };
        (code, c, brut)
    }

    fn as1_chemin_panneau(id: i64, depuis: i64) -> String {
        format!("/api/panels/{id}/data?from={depuis}&to=0")
    }

    /// `/api/ds/query` : (méthode, chemin, corps) pour une forme d'appel.
    fn as1_ds(forme: &str, soql: &str, depuis: i64, jusqua: i64) -> (&'static str, String, Option<Value>) {
        if forme == "get" {
            ("GET", format!("/api/ds/query?soql={}&from={depuis}&to={jusqua}", as1_encoder(soql)), None)
        } else {
            ("POST", "/api/ds/query".to_string(), Some(json!({ "soql": soql, "from": depuis, "to": jusqua, "format": "table" })))
        }
    }

    fn as1_ds_nominal(contexte: &str, forme: &str, code: u16, corps: &str) {
        let v = as1_json(corps);
        assert_eq!(code, 200, "{contexte} : nominal servi : {corps}");
        let n = if forme == "get" { v.as_array().map(|a| a.len()) } else { v["rows"].as_array().map(|a| a.len()) };
        assert_eq!(n, Some(1), "{contexte} : la ligne semée est rendue : {corps}");
    }

    async fn as1_jouer_le_routeur() -> Vec<String> {
        let (st, _base) = router_test_state("as1-routeur");
        let chemin = st.db_path.as_ref().clone();
        let maintenant = now();
        let depuis = maintenant - 86_400;
        let p = as1_semer(&st.db.lock(), maintenant);
        let addr = router_serve(st.clone()).await;
        let mut attendus: Vec<String> = Vec::new();

        // CONTRÔLES DU CHEMIN : chaque site rend la ligne semée.
        let (c, b, _) = as1_envoi(addr, "GET", &as1_chemin_panneau(p.live, depuis), None).await;
        assert_eq!((c, as1_json(&b)["rows"].clone()), (200, json!([["as1-sonde"]])), "contrôle : panneau live nominal : {b}");
        {
            let lane = st.refresh_sem.clone();
            let n = lane.available_permits() as u32;
            let _saturee = lane.try_acquire_many_owned(n).expect("contrôle : lane de rafraîchissement saturée");
            let (c, b, _) = as1_envoi(addr, "GET", &as1_chemin_panneau(p.sans_permis, depuis), None).await;
            assert_eq!((c, as1_json(&b)["rows"].clone()), (200, json!([["as1-sonde"]])), "contrôle : panneau sans permis nominal : {b}");
        }
        for forme in ["get", "post"] {
            let (m, ch, corps) = as1_ds(forme, AS1_SOQL, maintenant - 3600, maintenant + 60);
            let (c, b, _) = as1_envoi(addr, m, &ch, corps.as_ref()).await;
            as1_ds_nominal(&format!("ds {forme}"), forme, c, &b);
        }
        for route in ROUTES_PROM {
            let (c, b, _) = as1_envoi(addr, "GET", &as1_chemin_prom(route, maintenant), None).await;
            as1_prom_nominal(route, route, c, &b);
        }

        // LE REFUS DU COMPILATEUR : la requête de l'appelant, son texte à l'octet en 400, jamais sous « moteur ».
        let refus = crate::handlers::panneau_avoue::compile_panneau_avoue(AS1_GXQL_REFUSE, true, depuis, 0, None).err().expect("précondition : GXQL refusé");
        let (c, b, _) = as1_envoi(addr, "GET", &as1_chemin_panneau(p.refuse_live, depuis), None).await;
        assert_eq!((c, as1_json(&b)), (400, json!({ "error": refus })), "panneau live : le refus du compilateur à l'octet");
        for forme in ["get", "post"] {
            let refus = soql_to_sql_masked_x(AS1_GXQL_REFUSE, maintenant - 3600, maintenant + 60, None, &guatx_core::soql::FieldMaskSet::new())
                .err()
                .expect("précondition : GXQL refusé");
            let (m, ch, corps) = as1_ds(forme, AS1_GXQL_REFUSE, maintenant - 3600, maintenant + 60);
            let (c, b, _) = as1_envoi(addr, m, &ch, corps.as_ref()).await;
            assert_eq!((c, as1_json(&b)), (400, json!({ "error": refus })), "ds {forme} : le refus du compilateur à l'octet, jamais REQUETE_REJETEE_PAR_LE_MOTEUR");
        }

        // VOIE LIVE, AVEC PERMIS.
        for classe in CLASSES {
            as1_vider_le_pool(&chemin);
            demander(&chemin, as1_panne(classe));
            let (c, b, brut) = as1_envoi(addr, "GET", &as1_chemin_panneau(p.live, depuis), None).await;
            assert!(!encore_demandee(&chemin), "contrôle : live/{classe} : la panne a servi");
            as1_vider_le_pool(&chemin);
            as1_sans_trace(&format!("live/{classe}"), &brut);
            let id = as1_juger_refus(&format!("live/{classe}"), classe, c, &b);
            if classe != "produit" {
                attendus.push(as1_ligne_query(classe, AS1_ROUTE_PANNEAU, "default", &id.unwrap_or_default()));
            }
        }

        // VOIE LIVE SANS PERMIS (cache coupé pour ce panneau, lane saturée).
        for classe in CLASSES {
            let lane = st.refresh_sem.clone();
            let n = lane.available_permits() as u32;
            let saturee = lane.try_acquire_many_owned(n).expect("contrôle : lane saturée");
            as1_vider_le_pool(&chemin);
            demander(&chemin, as1_panne(classe));
            let (c, b, brut) = as1_envoi(addr, "GET", &as1_chemin_panneau(p.sans_permis, depuis), None).await;
            drop(saturee);
            assert!(!encore_demandee(&chemin), "contrôle : sans_permis/{classe} : la panne a servi");
            as1_vider_le_pool(&chemin);
            as1_sans_trace(&format!("sans_permis/{classe}"), &brut);
            let id = as1_juger_refus(&format!("sans_permis/{classe}"), classe, c, &b);
            if classe != "produit" {
                attendus.push(as1_ligne_query(classe, AS1_ROUTE_PANNEAU, "default", &id.unwrap_or_default()));
            }
        }

        // `/api/ds/query`, GET ET POST.
        for forme in ["get", "post"] {
            for classe in CLASSES {
                let (m, ch, corps) = as1_ds(forme, AS1_SOQL, maintenant - 3600, maintenant + 60);
                as1_vider_le_pool(&chemin);
                demander(&chemin, as1_panne(classe));
                let (c, b, brut) = as1_envoi(addr, m, &ch, corps.as_ref()).await;
                assert!(!encore_demandee(&chemin), "contrôle : ds {forme}/{classe} : la panne a servi");
                as1_vider_le_pool(&chemin);
                as1_sans_trace(&format!("ds {forme}/{classe}"), &brut);
                let id = as1_juger_refus(&format!("ds {forme}/{classe}"), classe, c, &b);
                if classe != "produit" {
                    attendus.push(as1_ligne_query(classe, "/api/ds/query", "default", &id.unwrap_or_default()));
                }
            }
        }

        // LES TROIS ROUTES PROMETHEUS.
        for route in ROUTES_PROM {
            for classe in CLASSES {
                as1_armer_prom(&chemin, classe);
                let (c, b, brut) = as1_envoi(addr, "GET", &as1_chemin_prom(route, maintenant), None).await;
                assert!(as1_desarmer_prom(&chemin, classe), "contrôle : {route}/{classe} : la panne a servi");
                as1_sans_trace(&format!("{route}/{classe}"), &brut);
                let id = as1_juger_prom(&format!("{route}/{classe}"), classe, c, &b);
                if classe != "produit" {
                    attendus.push(as1_ligne_prom(classe, route, "default", &id.unwrap_or_default()));
                }
            }
        }

        // SWR : RAFRAÎCHISSEMENT EN ÉCHEC, PUIS DEUX HIT. Le cache du panneau est vidé entre deux classes.
        for classe in CLASSES {
            crate::handlers::panneau_avoue::cache_invalider_panneau(&st.db.lock(), p.swr);
            as1_vider_le_pool(&chemin);
            demander(&chemin, as1_panne(classe));
            let (c, b, _) = as1_envoi(addr, "GET", &as1_chemin_panneau(p.swr, depuis), None).await;
            assert_eq!((c, as1_json(&b)["warming"].clone()), (200, json!(true)), "contrôle : swr/{classe} : 1re interrogation en chauffe : {b}");
            t3c_attendre_la_tache(&st).await;
            assert!(!encore_demandee(&chemin), "contrôle : swr/{classe} : la panne a servi au rafraîchissement");
            as1_vider_le_pool(&chemin);
            let lignes = as1_payload_du_cache(&st.db.lock(), p.swr);
            assert_eq!(lignes.len(), 1, "swr/{classe} : un corps d'échec écrit : {lignes:?}");
            for trace in TRACES_DU_MOTEUR {
                assert!(!lignes[0].contains(trace), "swr/{classe} : `panel_cache` porte « {trace} » : {}", lignes[0]);
            }
            assert_eq!(as1_json(&lignes[0])[MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC], json!(classe), "swr/{classe} : la classe écrite avec le corps");
            let (c2, b2, brut2) = as1_envoi(addr, "GET", &as1_chemin_panneau(p.swr, depuis), None).await;
            let (c3, b3, _) = as1_envoi(addr, "GET", &as1_chemin_panneau(p.swr, depuis), None).await;
            assert!(t3c_rien_en_vol(&st), "swr/{classe} : un échec frais n'arme rien");
            as1_sans_trace(&format!("swr/{classe}"), &brut2);
            as1_juger_hit(&format!("swr/{classe} HIT 1"), classe, c2, &b2);
            as1_juger_hit(&format!("swr/{classe} HIT 2"), classe, c3, &b3);
            assert_eq!(as1_json(&b2), as1_json(&b3), "swr/{classe} : les deux HIT servent le même corps");
            attendus.push(as1_ligne_panel(classe, p.swr, "default"));
        }

        // UNE LIGNE `panel_cache` À L'ANCIENNE FORME (texte du moteur, sans classe), INSÉRÉE À LA MAIN : jamais servie.
        let rk = env_range_key(None, &cache_range_key(depuis, 0, now()));
        {
            let conn = st.db.lock();
            let ancien = json!({ "columns": [], "rows": [], "error": AS1_TEXTE_ANCIEN, "stats": { "coverage": { "reason": "calcul_echoue" } } });
            crate::handlers::panneau_avoue::cache_ecrire(&conn, p.ancien, &rk, &query_fingerprint(AS1_SQL_SAIN, false), now(), &ancien.to_string());
        }
        let (c, b, brut) = as1_envoi(addr, "GET", &as1_chemin_panneau(p.ancien, depuis), None).await;
        as1_sans_trace("ancien", &brut);
        assert!(!brut.contains("COUNT(DISTINCT"), "ancien : le texte mis en cache n'est pas servi : {brut}");
        assert_eq!((c, as1_json(&b)["warming"].clone()), (200, json!(true)), "ancien : traité comme une absence (chauffe) : {b}");
        t3c_attendre_la_tache(&st).await;
        let lignes = as1_payload_du_cache(&st.db.lock(), p.ancien);
        assert_eq!(lignes.len(), 1, "ancien : une ligne : {lignes:?}");
        assert_eq!(as1_json(&lignes[0])["rows"], json!([[1]]), "ancien : recalculé, le résultat remplace l'ancien corps : {}", lignes[0]);
        let (c, b, _) = as1_envoi(addr, "GET", &as1_chemin_panneau(p.ancien, depuis), None).await;
        assert_eq!((c, as1_json(&b)["rows"].clone()), (200, json!([[1]])), "ancien : le panneau est servi : {b}");

        // CONTRE-ÉPREUVE : une ligne À LA FORME COURANTE (classe écrite) est servie au HIT, classe retirée.
        {
            let conn = st.db.lock();
            let mut courant = crate::handlers::panneau_avoue::corps_d_echec(REJETEE, depuis, now());
            courant[MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC] = json!("moteur");
            crate::handlers::panneau_avoue::cache_ecrire(&conn, p.nouveau, &rk, &query_fingerprint(AS1_SQL_SAIN, false), now(), &courant.to_string());
        }
        let (c, b, _) = as1_envoi(addr, "GET", &as1_chemin_panneau(p.nouveau, depuis), None).await;
        assert!(t3c_rien_en_vol(&st), "nouveau : un corps courant frais n'arme rien");
        as1_juger_hit("nouveau", "moteur", c, &b);

        // VOIE MASQUÉE (règle de masque du lecteur) : nominal, refus du compilateur, puis chaque classe.
        as1_masquer(&st.db.lock(), &chemin);
        let (c, b, _) = as1_envoi(addr, "GET", &as1_chemin_panneau(p.masque, depuis), None).await;
        assert_eq!((c, as1_json(&b)["rows"].clone()), (200, json!([["as1-sonde"]])), "contrôle : panneau masqué nominal : {b}");
        let masques = effective_masks(&chemin, "viewer", "default", None);
        assert!(!masques.is_empty(), "contrôle : le lecteur a un masque actif");
        let refus = crate::handlers::panneau_avoue::compile_panneau_avoue_masque(AS1_GXQL_MASQUE, true, depuis, 0, None, &masques)
            .err()
            .expect("précondition : filtre sur un champ masqué refusé");
        let (c, b, _) = as1_envoi(addr, "GET", &as1_chemin_panneau(p.refuse_masque, depuis), None).await;
        assert_eq!((c, as1_json(&b)), (400, json!({ "error": refus })), "panneau masqué : le refus du compilateur à l'octet");
        for classe in CLASSES {
            as1_vider_le_pool(&chemin);
            demander(&chemin, as1_panne(classe));
            let (c, b, brut) = as1_envoi(addr, "GET", &as1_chemin_panneau(p.masque, depuis), None).await;
            assert!(!encore_demandee(&chemin), "contrôle : masque/{classe} : la panne a servi");
            as1_vider_le_pool(&chemin);
            as1_sans_trace(&format!("masque/{classe}"), &brut);
            let id = as1_juger_refus(&format!("masque/{classe}"), classe, c, &b);
            if classe != "produit" {
                attendus.push(as1_ligne_query(classe, AS1_ROUTE_PANNEAU, "default", &id.unwrap_or_default()));
            }
        }
        attendus
    }

    fn as1_journal(stderr: &str) -> Vec<String> {
        stderr
            .lines()
            .filter(|l| l.starts_with("[query] ") || l.starts_with("[panel] ") || l.starts_with("[datasource] "))
            .map(str::to_string)
            .collect()
    }

    fn as1_attendus(stdout: &str) -> Vec<String> {
        // `split_once` et non `strip_prefix` : libtest écrit « test … ... » sans fin de ligne avant la première sortie.
        stdout.lines().filter_map(|l| l.split_once(AS1_ATTENDU)).map(|(_, v)| v.to_string()).collect()
    }

    /// (1) CHAQUE SITE PAR LE ROUTEUR RÉEL, AU RÔLE LECTEUR.
    #[tokio::test]
    async fn as1_routes_par_le_routeur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        if std::env::var(AS1_ENFANT_ROUTEUR).is_ok() {
            let attendus = as1_jouer_le_routeur().await;
            for l in &attendus {
                println!("{AS1_ATTENDU}{l}");
            }
            println!("{AS1_FIN} {}", attendus.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .env(AS1_ENFANT_ROUTEUR, "1")
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::as1_texte_du_moteur_hors_des_panneaux_et_des_sources::as1_routes_par_le_routeur"])
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant juge chaque corps et sort en 0 : {stdout}\n{stderr}");
        // live 3, sans permis 3, ds 2 x 3, Prometheus 3 x 3, SWR 4, masqué 3.
        assert!(stdout.contains(&format!("{AS1_FIN} 28")), "contrôle : vingt-huit refus au journal attendus : {stdout}\n{stderr}");
        let attendus = as1_attendus(&stdout);
        assert!(attendus.len() >= 28, "plancher : vingt-huit lignes attendues ({})", attendus.len());
        assert_eq!(as1_journal(&stderr), attendus, "une ligne EXACTE par refus du support, de la base occupée et du moteur, et par corps d'échec écrit :\n{stderr}");
    }

    // ---------- mode 1 : deux tenants réels, gestionnaires appelés au rôle lecteur ----------

    fn as1_lecteur(tenant: &str) -> AuthUser {
        AuthUser { name: "lecteur-as1".into(), role: "viewer".into(), tenant: tenant.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }

    async fn as1_creer_le_tenant(st: &AppState, t: &str, maintenant: i64) -> (String, As1Panneaux) {
        let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-as1")), Json(json!({ "id": t, "name": t }))).await;
        assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
        let p = as1_semer(&st.tenants.handle_for(t).expect("contrôle : base du tenant").lock(), maintenant);
        (st.tenants.ready_db_path(t).expect("contrôle : chemin de la base du tenant"), p)
    }

    async fn as1_corps(r: Response) -> (u16, String) {
        let code = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (code, String::from_utf8_lossy(&b).into_owned())
    }

    fn as1_requete(paires: &[(&str, String)]) -> Query<HashMap<String, String>> {
        Query(paires.iter().map(|(k, v)| (k.to_string(), v.clone())).collect())
    }

    async fn as1_appel(st: &AppState, site: &str, t: &str, p: &As1Panneaux, maintenant: i64) -> (u16, String) {
        let au = as1_lecteur(t);
        let depuis = maintenant - 86_400;
        let panneau = |id: i64| (Path(id), as1_requete(&[("from", depuis.to_string()), ("to", "0".to_string())]));
        let r = match site {
            "live" => {
                let (pa, q) = panneau(p.live);
                panel_data(State(st.clone()), Extension(au), pa, q).await
            }
            "sans_permis" => {
                let (pa, q) = panneau(p.sans_permis);
                panel_data(State(st.clone()), Extension(au), pa, q).await
            }
            "masque" => {
                let (pa, q) = panneau(p.masque);
                panel_data(State(st.clone()), Extension(au), pa, q).await
            }
            "swr" => {
                let (pa, q) = panneau(p.swr);
                panel_data(State(st.clone()), Extension(au), pa, q).await
            }
            "ds_get" => {
                let q = as1_requete(&[("soql", AS1_SOQL.to_string()), ("from", (maintenant - 3600).to_string()), ("to", (maintenant + 60).to_string())]);
                ds_query_get(State(st.clone()), Extension(au), q).await
            }
            "ds_post" => {
                let corps = json!({ "soql": AS1_SOQL, "from": maintenant - 3600, "to": maintenant + 60, "format": "table" });
                ds_query_post(State(st.clone()), Extension(au), Json(corps)).await
            }
            "/api/v1/query_range" => {
                let q = as1_requete(&[("query", AS1_PROM.to_string()), ("start", (maintenant - 3600).to_string()), ("end", (maintenant + 60).to_string())]);
                prom_query_range(State(st.clone()), Extension(au), q).await
            }
            "/api/v1/query" => {
                let q = as1_requete(&[("query", AS1_PROM.to_string()), ("time", maintenant.to_string())]);
                prom_query(State(st.clone()), Extension(au), q).await
            }
            "/api/v1/series" => {
                let q = as1_requete(&[("match[]", AS1_PROM.to_string()), ("start", (maintenant - 3600).to_string()), ("end", (maintenant + 60).to_string())]);
                prom_series(State(st.clone()), Extension(au), q).await
            }
            autre => panic!("instrument : site {autre}"),
        };
        as1_corps(r).await
    }

    fn as1_route_du_site(site: &str) -> &str {
        match site {
            "live" | "sans_permis" | "masque" | "swr" => AS1_ROUTE_PANNEAU,
            "ds_get" | "ds_post" => "/api/ds/query",
            route => route,
        }
    }

    /// Joue un site armé pour `appelant` et rend les lignes attendues ; l'autre tenant est servi par sa base.
    async fn as1_jouer_un_site_arme(
        st: &AppState, site: &str, classe: &str, appelant: (&str, &str, &As1Panneaux), autre: (&str, &str, &As1Panneaux), maintenant: i64,
    ) -> Vec<String> {
        let (t, chemin, p) = appelant;
        let contexte = format!("{site}/{classe}/{t}");
        let prom = site.starts_with("/api/v1/");
        let mut attendus = Vec::new();
        let saturee = if site == "sans_permis" {
            let lane = st.refresh_sem.clone();
            let n = lane.available_permits() as u32;
            Some(lane.try_acquire_many_owned(n).expect("contrôle : lane saturée"))
        } else {
            None
        };
        if site == "swr" {
            crate::handlers::panneau_avoue::cache_invalider_panneau(&st.tenants.handle_for(t).expect("base du tenant").lock(), p.swr);
        }
        if prom {
            as1_armer_prom(chemin, classe);
        } else {
            as1_vider_le_pool(chemin);
            demander(chemin, as1_panne(classe));
        }
        let (c, b) = as1_appel(st, site, t, p, maintenant).await;
        drop(saturee);
        if site == "swr" {
            assert_eq!((c, as1_json(&b)["warming"].clone()), (200, json!(true)), "contrôle : {contexte} : chauffe : {b}");
            t3c_attendre_la_tache(st).await;
        }
        if prom {
            assert!(as1_desarmer_prom(chemin, classe), "contrôle : {contexte} : la panne a servi");
        } else {
            assert!(!encore_demandee(chemin), "contrôle : {contexte} : la panne a servi");
            retirer(chemin);
            as1_vider_le_pool(chemin);
        }
        if site == "swr" {
            let (c, b) = as1_appel(st, site, t, p, maintenant).await;
            as1_sans_trace(&contexte, &b);
            as1_juger_hit(&contexte, classe, c, &b);
            attendus.push(as1_ligne_panel(classe, p.swr, t));
        } else if prom {
            as1_sans_trace(&contexte, &b);
            let id = as1_juger_prom(&contexte, classe, c, &b).unwrap_or_default();
            attendus.push(as1_ligne_prom(classe, site, t, &id));
        } else {
            as1_sans_trace(&contexte, &b);
            let id = as1_juger_refus(&contexte, classe, c, &b).unwrap_or_default();
            attendus.push(as1_ligne_query(classe, as1_route_du_site(site), t, &id));
        }
        // L'AUTRE TENANT, SANS PANNE : servi par sa base (le SWR, qui chaufferait, n'est pas rejoué).
        let (t_autre, chemin_autre, p_autre) = autre;
        if site != "swr" {
            let (c, b) = as1_appel(st, site, t_autre, p_autre, maintenant).await;
            assert!(!encore_demandee(chemin_autre), "contrôle : aucune panne demandée sur l'autre base");
            assert_eq!(c, 200, "{contexte} : l'autre tenant ({t_autre}) reste servi par sa base : {b}");
        }
        attendus
    }

    async fn as1_jouer_deux_tenants() -> Vec<String> {
        let (st, _dir) = mk_mode1_state();
        let maintenant = now();
        let (alpha, pa) = as1_creer_le_tenant(&st, AS1_ALPHA, maintenant).await;
        let (beta, pb) = as1_creer_le_tenant(&st, AS1_BETA, maintenant).await;
        assert_ne!(alpha, beta, "contrôle : deux bases distinctes");
        let a = (AS1_ALPHA, alpha.as_str(), &pa);
        let b = (AS1_BETA, beta.as_str(), &pb);
        let mut attendus = Vec::new();
        let sites = ["live", "sans_permis", "swr", "ds_get", "ds_post", ROUTES_PROM[0], ROUTES_PROM[1], ROUTES_PROM[2]];
        assert!(sites.len() >= 8, "plancher : huit sites");
        for site in sites {
            for classe in CLASSES_DU_JOURNAL {
                attendus.extend(as1_jouer_un_site_arme(&st, site, classe, a, b, maintenant).await);
                attendus.extend(as1_jouer_un_site_arme(&st, site, classe, b, a, maintenant).await);
            }
        }
        // LA VOIE MASQUÉE : la règle de masque posée dans les DEUX bases (chacune la sienne).
        for (t, chemin) in [(AS1_ALPHA, alpha.as_str()), (AS1_BETA, beta.as_str())] {
            as1_masquer(&st.tenants.handle_for(t).expect("base du tenant").lock(), chemin);
            assert!(!effective_masks(chemin, "viewer", t, None).is_empty(), "contrôle : masque actif pour le lecteur de {t}");
        }
        for classe in CLASSES_DU_JOURNAL {
            attendus.extend(as1_jouer_un_site_arme(&st, "masque", classe, a, b, maintenant).await);
            attendus.extend(as1_jouer_un_site_arme(&st, "masque", classe, b, a, maintenant).await);
        }
        attendus
    }

    /// (2) DEUX TENANTS RÉELS, SITE PAR SITE : la ligne nomme le tenant de l'appelant.
    #[tokio::test]
    async fn as1_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(AS1_ENFANT_DEUX).is_ok() {
            let attendus = as1_jouer_deux_tenants().await;
            for l in &attendus {
                println!("{AS1_ATTENDU}{l}");
            }
            println!("{AS1_FIN} {}", attendus.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .env(AS1_ENFANT_DEUX, "1")
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::as1_texte_du_moteur_hors_des_panneaux_et_des_sources::as1_deux_tenants"])
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant juge chaque corps et sort en 0 : {stdout}\n{stderr}");
        // neuf sites (masqué compris), trois classes, deux tenants.
        assert!(stdout.contains(&format!("{AS1_FIN} 54")), "contrôle : cinquante-quatre refus au journal attendus : {stdout}\n{stderr}");
        let attendus = as1_attendus(&stdout);
        assert!(attendus.len() >= 54, "plancher : cinquante-quatre lignes attendues ({})", attendus.len());
        assert!(attendus.iter().any(|l| l.contains(&format!("tenant '{AS1_ALPHA}'"))) && attendus.iter().any(|l| l.contains(&format!("tenant '{AS1_BETA}'"))), "contrôle : les deux tenants sont nommés");
        assert_eq!(as1_journal(&stderr), attendus, "chaque ligne nomme le tenant de l'appelant, site par site :\n{stderr}");
    }

    // ---------- (3) les quatre gestes du journal d'un rafraîchissement en échec ----------

    const AS1_ENFANT_GESTES: &str = "AS1_ENFANT_GESTES_DU_JOURNAL";
    const AS1_TENANT_DES_GESTES: &str = "as1-gestes";
    const AS1_TEXTE_DU_GESTE: &str = "as1 texte du moteur pour les gestes";

    /// Ré-exécute `nom` dans un sous-processus (journal entier capturé) et rend (stdout, stderr) d'un enfant sorti en 0.
    fn as1_rejouer_en_enfant(mut enfant: std::process::Command, nom: &str) -> (String, String) {
        let sortie = enfant
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("tests::as1_texte_du_moteur_hors_des_panneaux_et_des_sources::{nom}")])
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant juge chaque corps et sort en 0 : {stdout}\n{stderr}");
        (stdout, stderr)
    }

    /// (3) CHAQUE GESTE DE `memoriser_l_echec_du_rafraichissement` — cache coupé, charge utile conservée, corps NON
    /// écrit, corps écrit — porte la route et le tenant de l'appelant : ligne entière comparée, geste par geste.
    #[tokio::test]
    async fn as1_chaque_geste_du_journal_porte_la_route_et_le_tenant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(AS1_ENFANT_GESTES).is_ok() {
            let from = t3c_from();
            let (ttl_global, _) = panel_serve_cfg_de(&load_config());
            let mut attendus = Vec::new();
            for geste in ["coupe", "conserve", "non_ecrit", "ecrit"] {
                let (st, dbp, _g, panne, _s) = t3c_state(&format!("as1-geste-{geste}"));
                let (rk, fp, _) = t3c_cle(&st, panne, from);
                let fin = match geste {
                    "coupe" => {
                        st.db.lock().execute("UPDATE panel SET panel_cache_ttl_s=0 WHERE id=?1", params![panne]).expect("fixture : cache coupé");
                        "cache des panneaux coupé, rien d'écrit".to_string()
                    }
                    "conserve" => {
                        crate::handlers::panneau_avoue::cache_ecrire(&st.db.lock(), panne, &rk, &fp, now() - 5, &json!({ "columns": ["a"], "rows": [[42]] }).to_string());
                        "charge utile précédente conservée (périmée), nouvelle tentative à la prochaine interrogation".to_string()
                    }
                    "non_ecrit" => {
                        st.db
                            .lock()
                            .execute_batch("CREATE TRIGGER as1_refus BEFORE INSERT ON panel_cache BEGIN SELECT RAISE(ABORT,'as1 refus du cache'); END;")
                            .expect("fixture : écriture refusée");
                        "corps d'échec NON ÉCRIT (as1 refus du cache), le panneau reste sans charge utile".to_string()
                    }
                    _ => "corps d'échec servi, nouvelle tentative à l'expiration du cache".to_string(),
                };
                let echec = crate::query_exec::EchecDeRequete::Moteur { nature: "as1 nature".into(), texte: AS1_TEXTE_DU_GESTE.into() };
                consigner_l_issue_du_rafraichissement(&st.db, AS1_TENANT_DES_GESTES, panne, &rk, &fp, now(), from, ttl_global, Ok(Err(echec)));
                let ecrit = crate::handlers::panneau_avoue::cache_lire(&st.db.lock(), panne, &rk, &fp);
                match geste {
                    "coupe" | "non_ecrit" => assert!(ecrit.is_none(), "contrôle : {geste} : rien d'écrit"),
                    "conserve" => assert_eq!(as1_json(&ecrit.expect("contrôle : charge conservée").0)["rows"], json!([[42]]), "contrôle : conservée"),
                    _ => assert_eq!(as1_json(&ecrit.expect("contrôle : corps écrit").0)["error"], json!(REJETEE), "contrôle : corps écrit"),
                }
                attendus.push(format!(
                    "[panel] WARN rafraîchissement du panneau {panne} en échec ({AS1_TEXTE_DU_GESTE}) — {AS1_ROUTE_PANNEAU}, tenant '{AS1_TENANT_DES_GESTES}' — {fin}"
                ));
                ff_rm(&dbp);
            }
            for l in &attendus {
                println!("{AS1_ATTENDU}{l}");
            }
            println!("{AS1_FIN} {}", attendus.len());
            return;
        }
        // Protocole à deux bras : le test relance SON binaire (`current_exe()`) avec `AS1_ENFANT_GESTES` (`.env(`) ; le bras
        // de l'enfant ci-dessus émet ses lignes attendues et sort, ce bras-ci les juge.
        let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        enfant.env(AS1_ENFANT_GESTES, "1");
        let (stdout, stderr) = as1_rejouer_en_enfant(enfant, "as1_chaque_geste_du_journal_porte_la_route_et_le_tenant");
        assert!(stdout.contains(&format!("{AS1_FIN} 4")), "contrôle : quatre gestes : {stdout}\n{stderr}");
        let attendus = as1_attendus(&stdout);
        assert_eq!(attendus.len(), 4, "plancher : quatre lignes attendues");
        assert_eq!(as1_journal(&stderr), attendus, "une ligne EXACTE par geste, route et tenant compris :\n{stderr}");
    }

    // ---------- (4) un corps d'échec à classe INCONNUE est traité comme l'ancienne forme ----------

    /// (4) Un corps d'échec mis en cache dont `classe_d_echec` n'est pas une classe écrite par la version courante (forgé
    /// à la main) n'est pas servi : MISS (`warming`), puis recalcul. Contre-épreuve d'abord (le coût est encore inconnu,
    /// le panneau passe donc en SWR) : une classe reconnue est servie au HIT, classe retirée.
    #[tokio::test]
    async fn as1_corps_d_echec_a_classe_inconnue_traite_comme_l_ancienne_forme() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let from = t3c_from();
        let (st, dbp, _g, _panne, sain) = t3c_state("as1-classe-inconnue");
        let (rk, fp, ttl) = t3c_cle(&st, sain, from);
        assert!(ttl > 0, "contrôle : cache actif");
        let corps = |classe: &str, error: &str| {
            let mut v = crate::handlers::panneau_avoue::corps_d_echec(error, from, now());
            v[MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC] = json!(classe);
            v.to_string()
        };
        crate::handlers::panneau_avoue::cache_ecrire(&st.db.lock(), sain, &rk, &fp, now(), &corps("moteur", REJETEE));
        let (c, b) = as1_corps(panel_data(State(st.clone()), Extension(t3c_admin()), Path(sain), t3c_q(from)).await).await;
        assert!(t3c_rien_en_vol(&st), "contre-épreuve : un corps courant frais n'arme rien");
        as1_juger_hit("classe reconnue", "moteur", c, &b);

        crate::handlers::panneau_avoue::cache_ecrire(&st.db.lock(), sain, &rk, &fp, now(), &corps("as1-classe-inconnue", AS1_TEXTE_ANCIEN));
        let (c, b) = as1_corps(panel_data(State(st.clone()), Extension(t3c_admin()), Path(sain), t3c_q(from)).await).await;
        as1_sans_trace("classe inconnue", &b);
        assert!(!b.contains("COUNT(DISTINCT"), "classe inconnue : le texte mis en cache n'est pas servi : {b}");
        assert_eq!((c, as1_json(&b)["warming"].clone()), (200, json!(true)), "classe inconnue : traitée comme une absence (chauffe) : {b}");
        t3c_attendre_la_tache(&st).await;
        let lignes = as1_payload_du_cache(&st.db.lock(), sain);
        assert_eq!(lignes.len(), 1, "classe inconnue : une ligne : {lignes:?}");
        assert_eq!(as1_json(&lignes[0])["rows"], json!([[1]]), "classe inconnue : recalculé, le résultat remplace le corps forgé : {}", lignes[0]);
        ff_rm(&dbp);
    }

    // ---------- (5) instantanés : capture d'un panneau en échec, puis service par jeton ----------

    const AS1_ENFANT_INSTANTANES: &str = "AS1_ENFANT_INSTANTANES";
    /// La route de création d'un instantané, écrite ici (et non empruntée à la production).
    const AS1_ROUTE_INSTANTANE: &str = "/api/dashboard-snapshots";
    /// La phrase servie pour un panneau en échec figé par une version antérieure, écrite ici à l'octet.
    const AS1_PHRASE_INSTANTANE_ANTERIEUR: &str =
        "calcul du panneau en échec à la capture — cause non servie : cet instantané a été figé par une version antérieure";

    async fn as1_lire_l_instantane(st: &AppState, t: &str, jeton: &str) -> Value {
        let (c, b) = as1_corps(snapshot_get(State(st.clone()), Extension(as1_lecteur(t)), Path(jeton.to_string())).await).await;
        assert_eq!(c, 200, "contrôle : instantané servi par son jeton : {b}");
        as1_json(&b)
    }

    async fn as1_jouer_les_instantanes() -> Vec<String> {
        let (st, _dir) = mk_mode1_state();
        let maintenant = now();
        let (chemin, _p) = as1_creer_le_tenant(&st, AS1_ALPHA, maintenant).await;
        let did = {
            let h = st.tenants.handle_for(AS1_ALPHA).expect("base du tenant");
            let conn = h.lock();
            conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('as1-capture','root','shared')", []).expect("fixture : tableau");
            let did = conn.last_insert_rowid();
            for (titre, q, soql) in [("as1-calcul", AS1_SQL_EN_PANNE, 0), ("as1-compilation", AS1_GXQL_REFUSE, 1)] {
                conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,?2,?3,?4,'table')", params![did, titre, q, soql])
                    .expect("fixture : panneau");
            }
            did
        };
        let refus_du_compilateur = match crate::handlers::panneau_avoue::compile_panneau_avoue(AS1_GXQL_REFUSE, true, 0, 0, None) {
            Err(e) => e,
            Ok(_) => panic!("contrôle : le compilateur refuse {AS1_GXQL_REFUSE}"),
        };
        let compilation = json!({ "title": "as1-compilation", "viz": "table", "error": refus_du_compilateur });
        let au = as1_lecteur(AS1_ALPHA);
        let capturer = |st: AppState, au: AuthUser| async move {
            let (c, b) = as1_corps(snapshot_create(State(st), Extension(au), Json(json!({ "dashboard_id": did }))).await).await;
            assert_eq!(c, 200, "contrôle : instantané créé : {b}");
            as1_sans_trace("création", &b);
            as1_json(&b)["token"].as_str().expect("contrôle : jeton").to_string()
        };
        let mut attendus = Vec::new();

        // NOMINAL : les lignes du panneau, le refus du compilateur à l'octet.
        let jeton = capturer(st.clone(), au.clone()).await;
        let v = as1_lire_l_instantane(&st, AS1_ALPHA, &jeton).await;
        // (la création du tenant journalise un événement qui nomme `as1-alpha` : la sonde est l'une des lignes.)
        let lignes = v["data"]["panels"][0]["rows"].as_array().cloned().unwrap_or_default();
        assert!(lignes.contains(&json!(["as1-sonde"])), "contrôle : capture nominale : {v}");
        assert_eq!(v["data"]["panels"][1], compilation, "le refus du compilateur figé à l'octet, classe retirée : {v}");

        // PAR CLASSE : la phrase de la classe à l'octet, rien du moteur — ni servi, ni stocké.
        for classe in CLASSES {
            let contexte = format!("instantané/{classe}");
            as1_vider_le_pool(&chemin);
            demander(&chemin, as1_panne(classe));
            let jeton = capturer(st.clone(), au.clone()).await;
            assert!(!encore_demandee(&chemin), "contrôle : {contexte} : la panne a servi");
            retirer(&chemin);
            as1_vider_le_pool(&chemin);
            let v = as1_lire_l_instantane(&st, AS1_ALPHA, &jeton).await;
            let panneau = &v["data"]["panels"][0];
            as1_sans_trace(&contexte, &panneau.to_string());
            assert_eq!(*panneau, json!({ "title": "as1-calcul", "viz": "table", "error": as1_phrase(classe) }), "{contexte} : exactement la phrase de la classe : {v}");
            assert_eq!(v["data"]["panels"][1], compilation, "{contexte} : le refus du compilateur reste à l'octet");
            let stocke: String = st
                .tenants
                .handle_for(AS1_ALPHA)
                .expect("base du tenant")
                .lock()
                .query_row("SELECT data FROM dashboard_snapshot WHERE token=?1", params![jeton], |r| r.get(0))
                .expect("contrôle : instantané stocké");
            let stocke = as1_json(&stocke)["panels"][0].clone();
            as1_sans_trace(&format!("{contexte} (stocké)"), &stocke.to_string());
            assert_eq!(stocke[MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC], json!(classe), "{contexte} : la classe est rangée avec la phrase : {stocke}");
            attendus.push(format!(
                "[dashboards] WARN instantané du tableau de bord #{did} : panneau en échec à la capture ({}) — {AS1_ROUTE_INSTANTANE}, tenant '{AS1_ALPHA}' — phrase de la classe figée",
                as1_cause(classe)
            ));
        }

        // UN INSTANTANÉ DÉJÀ STOCKÉ À L'ANCIENNE FORME (texte du moteur, sans classe ou classe inconnue) : son texte
        // n'est plus servi ; un panneau à la forme courante l'est, classe retirée ; un panneau en succès est intact.
        let ancien_jeton = "a1".repeat(32);
        let sain = json!({ "title": "as1-sain", "viz": "table", "columns": ["un"], "rows": [[1]], "stats": {} });
        let data = json!({ "dashboard_id": did, "name": "as1", "captured_at": 0, "panels": [
            { "title": "as1-a", "viz": "table", "error": AS1_TEXTE_ANCIEN },
            { "title": "as1-b", "viz": "table", "error": AS1_TEXTE_ANCIEN, MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC: "as1-classe-inconnue" },
            { "title": "as1-c", "viz": "table", "error": REJETEE, MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC: "moteur" },
            sain.clone(),
        ] });
        st.tenants
            .handle_for(AS1_ALPHA)
            .expect("base du tenant")
            .lock()
            .execute(
                "INSERT INTO dashboard_snapshot(dashboard_id,name,token,data,created,created_by,role_at_capture) VALUES(?1,'as1',?2,?3,?4,'root','admin')",
                params![did, ancien_jeton, data.to_string(), maintenant],
            )
            .expect("fixture : instantané à l'ancienne forme");
        let v = as1_lire_l_instantane(&st, AS1_ALPHA, &ancien_jeton).await;
        as1_sans_trace("instantané antérieur", &v.to_string());
        assert_eq!(
            v["data"]["panels"],
            json!([
                { "title": "as1-a", "viz": "table", "error": AS1_PHRASE_INSTANTANE_ANTERIEUR },
                { "title": "as1-b", "viz": "table", "error": AS1_PHRASE_INSTANTANE_ANTERIEUR },
                { "title": "as1-c", "viz": "table", "error": REJETEE },
                sain,
            ]),
            "instantané antérieur : texte du moteur remplacé, forme courante servie sans classe, succès intact : {v}"
        );
        attendus
    }

    /// (5) CAPTURE D'UN PANNEAU EN ÉCHEC PUIS SERVICE PAR JETON (mode 1, tenant réel, rôle lecteur) : chaque classe,
    /// la phrase à l'octet, la ligne de journal entière avec la route et le tenant du créateur ; instantané antérieur.
    #[tokio::test]
    async fn as1_instantanes() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(AS1_ENFANT_INSTANTANES).is_ok() {
            let attendus = as1_jouer_les_instantanes().await;
            for l in &attendus {
                println!("{AS1_ATTENDU}{l}");
            }
            println!("{AS1_FIN} {}", attendus.len());
            return;
        }
        // Protocole à deux bras : le test relance SON binaire (`current_exe()`) avec `AS1_ENFANT_INSTANTANES` (`.env(`) ; le bras
        // de l'enfant ci-dessus émet ses lignes attendues et sort, ce bras-ci les juge.
        let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        enfant.env(AS1_ENFANT_INSTANTANES, "1");
        let (stdout, stderr) = as1_rejouer_en_enfant(enfant, "as1_instantanes");
        assert!(stdout.contains(&format!("{AS1_FIN} 4")), "contrôle : quatre captures en échec : {stdout}\n{stderr}");
        let attendus = as1_attendus(&stdout);
        assert_eq!(attendus.len(), 4, "plancher : quatre lignes attendues");
        let journal: Vec<String> = stderr
            .lines()
            .filter(|l| l.starts_with("[dashboards] ") || l.starts_with("[query] ") || l.starts_with("[panel] "))
            .map(str::to_string)
            .collect();
        assert_eq!(journal, attendus, "une ligne EXACTE par panneau en échec à la capture :\n{stderr}");
    }

    // ---------- (6) `ds_soql_exec` n'existe que dans les tests ----------

    /// (6) `ds_soql_exec` (texte du compilateur et du moteur mêlés) n'est compilée que pour les tests : aucune voie de
    /// production ne peut la reprendre. Lu sur la source : l'attribut qui la précède est `#[cfg(test)]`, et le module
    /// ne tait aucun code mort.
    #[test]
    fn as1_ds_soql_exec_n_existe_que_dans_les_tests() {
        let source = include_str!("../handlers/datasource.rs");
        let lignes: Vec<&str> = source.lines().collect();
        let pos = lignes.iter().position(|l| l.starts_with("pub(crate) fn ds_soql_exec(")).expect("contrôle : la fonction existe");
        assert_eq!(lignes[pos - 1].trim(), "#[cfg(test)]", "l'attribut qui précède `ds_soql_exec`");
        assert!(!source.contains("allow(dead_code)"), "datasource.rs ne tait aucun code mort");
    }
}
