// =====================================================================================
// `P10.20-b` (vague AS : derniers sites du démon) et `P10.29-l` (texte du moteur servi par le pivot et les jeux de
// données).
//
// LES DÉFAUTS, LUS SUR 5c7b6de8 AVANT LE CORRECTIF :
//  * `handlers/query.rs` (`/api/query` vers :1240, `/api/export` vers :2045) et `handlers/datamodels.rs` (pivot et jeux
//    de données vers :551) lisaient la frontière froide par `retention_effective`, qui jette le troisième champ de
//    `setting_days_lu` : un réglage `retention_days` écrit et illisible (BLOB, « 365.0 ») fabriquait la frontière sur le
//    repli env/défaut. La requête et l'export servaient alors l'union chaud∪froid bornée par un nombre que l'admin n'a
//    pas écrit, et l'aveu de bande froide du pivot (`aveu_de_bande_froide`) affirmait cette frontière comme un fait ;
//  * `handlers/datamodels.rs` vers :574 (`run_generated_soql`) : `Ok(Err(e)) => bad_req(e)`, le texte du moteur servi
//    au rôle lecteur (refus de l'autorisateur, motif de l'UDF `regexp`) et une erreur d'E/S servie en 400 ;
//  * `seeds.rs` vers :1720 (`seed_env_notifier`) : l'existant lu par `.ok()` — une lecture refusée valait absence et
//    l'INSERT posait un SECOND canal `ntfy (env)` (aucun UNIQUE sur `notifier.name`) ; UPDATE et INSERT en `let _` ;
//  * `handlers/rba.rs` vers :116 (`ti_risk_contribution`) : le booléen de `risk_event_insert` jeté, une contribution
//    de risque threat-intel refusée se perdait sans trace.
//
// DÉSORMAIS (décision de l'orchestrateur, vague AS) : frontière lue par `retention_effective_lue` ; illisible, la
// réponse est CHAUDE seule et le dit — `/api/query` (compte seul, keyset chaud, page, requête entière) et le pivot
// posent `stats.cold` = `aveu_de_bande_froide_frontiere_non_lue(route)` (`served_from: "hot"`, `aveu` « frontière non
// lue », `reason: "cold_coverage_unread"`, la clé non lue, JAMAIS de `boundary_ts`) ; l'export est marqué incomplet
// d'ampleur inconnue (`x-plume-truncated: 1`, nom `-TRONQUE-ampleur-inconnue`) et nomme la cause
// (`x-plume-cold-coverage: cold_coverage_unread`). Le pivot classe l'échec comme `/api/query` (`en_classant`,
// `refus_de_requete`). Le canal `ntfy (env)` est lu en trois issues, chaque écriture refusée ou sans effet est dite.
// La contribution threat-intel refusée écrit une ligne `[risk] WARN` fixe, qui dit l'état RELU de la transaction
// englobante (ouverte, annulée par le moteur, absente) au lieu d'affirmer qu'elle n'est pas annulée. Sur un export
// à frontière non lue, aucun écart top-N n'est chiffré (la sonde ne voit que la part chaude). `retention_effective` et `setting_days`
// sont retirées (plus d'appelant de production) ; `risk_event_insert` ne sert plus que les témoins (`#[cfg(test)]`).
//
// LES TÉMOINS :
// (1) `as2_pivot_et_jeu_de_donnees_classent_l_echec_par_la_route` : routeur réel en sous-processus, jeton lecteur,
//     `POST /api/pivot/run` et `POST /api/datasets/{id}/run`, nominal puis une panne par classe (support, base occupée,
//     produit, moteur) ; corps entiers, aucune trace du moteur dans la réponse brute, journal `[query]` ENTIER ;
// (2) `as2_pivot_et_jeu_de_donnees_deux_tenants` : mode 1, deux tenants réels, chaque site, chaque classe pour chacun
//     des deux tenants : la ligne nomme celui de l'appelant, l'autre reste servi ;
// (3) `as2_canal_ntfy_en_trois_issues_sans_doublon` : sous-processus ; absent, présent, non lu (avec et sans ligne
//     existante), UPDATE refusé et sans effet, INSERT refusé et sans effet ; comptes des lignes `notifier` avant/après,
//     lignes `[seed]` ENTIÈRES (aucune ne porte l'URL) ;
// (4) `as2_contribution_threat_intel_refusee_est_dite` : sous-processus ; écrite, déjà posée, refusée par
//     `RAISE(ABORT)` dans une transaction qui reste validée, par `RAISE(ROLLBACK)` (le moteur annule la transaction),
//     hors transaction ; trois lignes `[risk]` entières ;
// (5) `cold_tier` — `as2_froid_requete_export_et_pivot_sans_frontiere_par_la_route` : routeur réel, jeton lecteur,
//     fenêtre profonde, les sept sites, BLOB et « 365.0 » ; l'aveu comparé à des LITTÉRAUX (`served_from: "hot"`,
//     raison, clé, phrase, aucun `boundary_ts`) ; contrôle lisible : frontière établie ;
// (6) `cold_tier` — `as2_froid_deux_tenants` : mode 1, deux tenants réels, l'un illisible l'autre lisible puis
//     l'inverse, les sept sites : l'aveu suit la base de l'appelant ;
// (7) `cold_tier` — `as2_froid_export_pre_agrege_sans_nombre_fabrique` : export servi par la route pré-agrégée chaude
//     (plafond top-N mordant, 32 écartés) ; contrôle lisible : `-TRONQUE-32-lignes-manquantes` ; illisible : nom
//     `-TRONQUE-ampleur-inconnue`, aucun `x-plume-truncated-ecartes`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le compte seul (`count_only`) d'une requête dont la frontière EST lue ne dit
// toujours rien du froid (comportement d'avant, hors de ce lot) ; la console ne lit pas encore `x-plume-cold-coverage`
// (elle lit `x-plume-truncated`). L'appel de `ti_risk_contribution` depuis l'ingestion (`ingest/mod.rs`) n'est pas joué
// de bout en bout : le témoin (4) appelle la fonction dans une transaction ; une annulation par le moteur y est DITE,
// mais l'ingestion continue le lot sans relire l'état (hors de ce lot). `SQLITE_FULL`/`IOERR`/`NOMEM` ne sont pas
// provoqués : `RAISE(ROLLBACK)` joue le même effet (transaction annulée par le moteur), seul reproductible à coup sûr.
//
// LES MUTATIONS QUI LES FONT ROUGIR (variable `VERIF_MUT` sous `cfg!(test)`, retirées du source avant le commit) :
//  * (1) : `AS2_P_MOTEUR` (texte du moteur servi) ; (1)(5) : `AS2_P_ROUTE` (le jeu de données se dit pivot) ;
//  * (5) : `AS2_Q_REPLI`, `AS2_Q_AVEU_COMPTE`, `AS2_Q_AVEU_KEYSET`, `AS2_Q_AVEU_PAGE`, `AS2_Q_AVEU_PLEIN`,
//    `AS2_X_REPLI`, `AS2_X_NON_TRONQUE`, `AS2_X_SANS_ENTETE`, `AS2_P_REPLI`, `AS2_P_SANS_AVEU`,
//    `AS2_P_CONTENU_SERVI` (`served_from: "hot+cold"`, phrase vide), `AS2_P_CONTENU_FRONTIERE` (`boundary_ts: 0`) ;
//    (6) les mêmes ; (7) : `AS2_X_ECARTES` (l'écart de la part chaude chiffré dans le nom et l'en-tête) ;
//  * (3) : `AS2_S_OK` (lecture ratée = absence : second canal), `AS2_S_LECTURE_MUETTE`, `AS2_S_MAJ_REFUS_MUET`,
//    `AS2_S_MAJ_VIDE_MUET`, `AS2_S_INS_REFUS_MUET`, `AS2_S_INS_VIDE_MUET` ;
//  * (4) : `AS2_R_MUET`, `AS2_R_TX_FIGEE` (une transaction annulée par le moteur dite « ouverte »).
// =====================================================================================
mod as2_frontiere_froide_non_lue_et_ecritures_avouees {
    use super::*;
    use crate::handlers::query::{CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE, CAUSE_REQUETE_NON_SERVIE_BASE_OCCUPEE, REQUETE_REJETEE_PAR_LE_MOTEUR};
    use crate::query_exec::panne_de_test_au_coeur::{demander, encore_demandee, retirer, PanneAuCoeur};
    use rusqlite::functions::FunctionFlags;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const AS2_RENDU: &str = "AS2-RENDU:";
    const AS2_FIN: &str = "AS2-FIN:";
    const AS2_ALPHA: &str = "as2-alpha";
    const AS2_BETA: &str = "as2-beta";
    const AS2_ROUTE_PIVOT: &str = "/api/pivot/run";
    const AS2_ROUTE_JEU: &str = "/api/datasets/{id}/run";
    /// Les deux sites de `run_generated_soql` : (nom, route servie, route nommée au journal).
    const AS2_SITES_ENGENDRES: [(&str, &str, &str); 2] = [("pivot", "/api/pivot/run", AS2_ROUTE_PIVOT), ("jeu", "/api/datasets/1/run", AS2_ROUTE_JEU)];
    /// Ce qu'aucune réponse refusée ne doit porter, en-têtes compris : les textes et natures du moteur joués ici.
    const TRACES_DU_MOTEUR: [&str; 8] = ["prohibited", "disk I/O", "code SQLite", "SQLITE", "event.message", "panne de test", "not authorized", "regexp"];

    type As2Rendus = Vec<(String, String, u16, String, String)>;

    // ---------------------------------------------------------------------------------------------------------------
    // FIXTURES COMMUNES
    // ---------------------------------------------------------------------------------------------------------------

    /// Un événement chaud, un modèle de données à un objet (contrainte qui lit `message` par `regexp`) et un jeu de
    /// données de la même requête : le pivot (`object_id` 1) et le jeu de données (`id` 1) exécutent le même GXQL.
    fn as2_semer(conn: &Connection, ts: i64) {
        conn.execute("INSERT INTO event(ts,source,severity,message,host,src_ip) VALUES(?1,'as2',1,'as2-sonde','as2-h',NULL)", params![ts])
            .expect("fixture : événement");
        conn.execute("INSERT INTO data_model(id,name,enabled) VALUES(1,'as2',1)", []).expect("fixture : modèle");
        conn.execute(
            "INSERT INTO data_model_object(id,model_id,name,parent_id,constraint_soql,enabled) VALUES(1,1,'as2',NULL,'source=as2 message=~\"as2\"',1)",
            [],
        )
        .expect("fixture : objet");
        conn.execute("INSERT INTO dataset(id,name,kind,soql,enabled) VALUES(1,'as2','search','search source=as2 message=~\"as2\" | stats count',1)", [])
            .expect("fixture : jeu de données");
    }

    fn as2_corps_engendre(site: &str, depuis: i64, jusqua: i64) -> Value {
        match site {
            "pivot" => json!({ "object_id": 1, "stats": [{ "func": "count" }], "from": depuis, "to": jusqua }),
            _ => json!({ "from": depuis, "to": jusqua }),
        }
    }

    /// Les connexions au repos de la base sont fermées : une connexion armée ne sert jamais deux fois.
    fn as2_vider_le_pool(chemin: &str) {
        while crate::query_exec::connexions_de_lecture_au_repos(chemin) > 0 {
            drop(crate::query_exec::read_conn_get(chemin).expect("fixture : connexion au repos"));
        }
    }

    /// POST par le routeur réel : (statut, corps décodé, réponse brute en-têtes compris).
    async fn as2_envoi(addr: std::net::SocketAddr, route: &str, authz: &str, corps: &Value) -> (u16, String, String) {
        let entetes = [("Content-Type", "application/json")];
        let (code, brut) = router_probe_envoi(addr, "POST", route, Some(authz), &entetes, &corps.to_string()).await;
        let (tete, c) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {route} : {brut}"));
        let c = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(c.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {route}"))).expect("corps UTF-8")
        } else {
            c.to_string()
        };
        (code, c, brut)
    }

    /// La valeur d'un en-tête de la réponse brute (nom comparé sans casse), ou `None`.
    #[cfg(feature = "cold_tier")]
    fn as2_entete(brut: &str, nom: &str) -> Option<String> {
        let tete = brut.split_once("\r\n\r\n").map(|(t, _)| t).unwrap_or(brut);
        tete.lines().skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim().eq_ignore_ascii_case(nom)).then(|| v.trim().to_string())
        })
    }

    fn as2_lancer_l_enfant(mut enfant: std::process::Command, test: &str) -> (String, String) {
        let sortie = enfant.args(["--exact", "--nocapture", "--test-threads=1", test]).output().expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        (stdout, stderr)
    }

    fn as2_lire_les_rendus(stdout: &str) -> As2Rendus {
        stdout
            .lines()
            .filter_map(|l| l.split_once(AS2_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : ligne de rendu lisible ({e}) : {v}")))
            .collect()
    }

    fn as2_imprimer(rendus: &As2Rendus) {
        for r in rendus {
            println!("{AS2_RENDU}{}", json!([r.0, r.1, r.2, r.3, r.4]));
        }
        println!("{AS2_FIN} {}", rendus.len());
    }

    fn as2_nature(e: &rusqlite::Error) -> String {
        match e {
            rusqlite::Error::SqliteFailure(f, _) => format!("code SQLite {} ({:?})", f.extended_code, f.code),
            autre => panic!("instrument : erreur sans code SQLite : {autre}"),
        }
    }

    fn as2_fonction_d_erreur(c: &Connection) {
        c.create_scalar_function("as2_erreur", 1, FunctionFlags::SQLITE_UTF8, |ctx| -> rusqlite::Result<i64> {
            Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(ctx.get::<i32>(0)?), None))
        })
        .expect("instrument : fonction d'erreur");
    }

    /// L'erreur que la panne rend au pas pour ce code (E/S ou base occupée), REPRODUITE en mémoire.
    fn as2_erreur_au_pas(code: i32) -> rusqlite::Error {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        as2_fonction_d_erreur(&c);
        c.query_row(&format!("SELECT as2_erreur({code})"), [], |r| r.get::<_, i64>(0)).err().expect("instrument : l'erreur est rendue au pas")
    }

    /// Le refus que la panne `RefusDeLAutorisateur` fait rendre (lecture d'`event.message`), REPRODUIT en mémoire.
    fn as2_refus_de_message() -> rusqlite::Error {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        c.execute_batch("CREATE TABLE event(message TEXT);").expect("instrument : table");
        c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "event" && column_name == "message" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        c.prepare("SELECT message FROM event").err().expect("instrument : le refus de event.message a lieu")
    }

    fn as2_ligne_support(route: &str, tenant: &str, id: &str) -> String {
        format!(
            "[query] WARN requête non servie, erreur du support de la base ({route}, tenant '{tenant}', {id}) : {}",
            as2_nature(&as2_erreur_au_pas(rusqlite::ffi::SQLITE_IOERR_READ))
        )
    }

    fn as2_ligne_occupee(route: &str, tenant: &str, id: &str) -> String {
        format!("[query] WARN requête non servie, base occupée ({route}, tenant '{tenant}', {id}) : {}", as2_nature(&as2_erreur_au_pas(rusqlite::ffi::SQLITE_BUSY)))
    }

    fn as2_ligne_moteur(route: &str, tenant: &str) -> String {
        let e = as2_refus_de_message();
        format!("[query] WARN requête rejetée par le moteur ({route}, tenant '{tenant}') : {} : {:?}", as2_nature(&e), e.to_string())
    }

    /// Un 503 nommé : `{error, id}` EXACTEMENT, la phrase attendue, et l'identifiant rendu.
    fn as2_juger_503(contexte: &str, code: u16, corps: &str, cause: &str) -> String {
        let v: Value = serde_json::from_str(corps).unwrap_or(Value::Null);
        assert_eq!(code, 503, "{contexte} : statut : {corps}");
        let mut cles: Vec<&String> = v.as_object().map(|o| o.keys().collect()).unwrap_or_default();
        cles.sort();
        assert_eq!(cles, vec!["error", "id"], "{contexte} : exactement `error` et `id` : {v}");
        assert_eq!(v["error"], json!(cause), "{contexte} : la phrase fixe");
        let id = v["id"].as_str().unwrap_or_default().to_string();
        assert!(id.starts_with("plume-e"), "{contexte} : identifiant de corrélation : {v}");
        id
    }

    fn as2_journal_query(stderr: &str) -> Vec<String> {
        stderr.lines().filter(|l| l.starts_with("[query] ")).map(str::to_string).collect()
    }

    fn as2_lecteur(tenant: &str) -> AuthUser {
        AuthUser { name: "lecteur-as2".into(), role: "viewer".into(), tenant: tenant.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }

    async fn as2_creer_le_tenant(st: &AppState, t: &str, ts: i64) -> String {
        let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-as2")), Json(json!({ "id": t, "name": t }))).await;
        assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
        assert!(st.tenants.tenant_available(t), "contrôle : tenant {t} résolu pour le pool de lecture");
        as2_semer(&st.tenants.handle_for(t).expect("contrôle : base du tenant").lock(), ts);
        st.tenants.ready_db_path(t).expect("contrôle : chemin de la base du tenant")
    }

    /// Un site engendré appelé par son gestionnaire, au rôle lecteur du tenant `t`.
    async fn as2_appel_engendre(st: &AppState, site: &str, t: &str, corps: Value) -> (u16, String) {
        let r = match site {
            "pivot" => crate::handlers::datamodels::pivot_run(State(st.clone()), Extension(as2_lecteur(t)), Json(corps)).await,
            _ => crate::handlers::datamodels::dataset_run(State(st.clone()), Extension(as2_lecteur(t)), Path(1), Json(corps)).await,
        };
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, String::from_utf8_lossy(&b).into_owned())
    }

    // ---------------------------------------------------------------------------------------------------------------
    // (1) LE PIVOT ET LE JEU DE DONNÉES CLASSENT L'ÉCHEC — `P10.29-l`
    // ---------------------------------------------------------------------------------------------------------------

    const AS2_ENFANT_ENGENDRES: &str = "AS2_ENFANT_ENGENDRES";

    async fn as2_jouer_les_sites_engendres() -> As2Rendus {
        let (st, _base) = router_test_state("as2-engendres");
        let chemin = st.db_path.as_ref().clone();
        let maintenant = now();
        as2_semer(&st.db.lock(), maintenant - 60);
        let addr = router_serve(st.clone()).await;
        let lecteur = viewer_authz();
        let mut rendus: As2Rendus = Vec::new();
        for (site, route, _) in AS2_SITES_ENGENDRES {
            let corps = as2_corps_engendre(site, maintenant - 3600, maintenant + 3600);
            let (c, b, brut) = as2_envoi(addr, route, &lecteur, &corps).await;
            rendus.push((site.into(), "nominal".into(), c, b, brut));
            for (issue, panne) in [
                ("support", PanneAuCoeur::ErreurDuSupport),
                ("occupee", PanneAuCoeur::BaseOccupee),
                ("produit", PanneAuCoeur::Interruption),
                ("moteur", PanneAuCoeur::RefusDeLAutorisateur),
            ] {
                as2_vider_le_pool(&chemin);
                demander(&chemin, panne);
                let (c, b, brut) = as2_envoi(addr, route, &lecteur, &corps).await;
                let issue = if encore_demandee(&chemin) {
                    retirer(&chemin);
                    format!("{issue}:panne_non_armee")
                } else {
                    issue.to_string()
                };
                as2_vider_le_pool(&chemin);
                rendus.push((site.into(), issue, c, b, brut));
            }
        }
        rendus
    }

    /// (1) PAR LA ROUTE, AU RÔLE LECTEUR : nominal, puis support (503), base occupée (503), produit (400 à l'octet),
    /// moteur (400 à phrase fixe) ; journal `[query]` ENTIER, route nommée. MUTANTS : `AS2_P_MOTEUR`, `AS2_P_ROUTE`.
    #[tokio::test]
    async fn as2_pivot_et_jeu_de_donnees_classent_l_echec_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(AS2_ENFANT_ENGENDRES).is_ok() {
            as2_imprimer(&as2_jouer_les_sites_engendres().await);
            return;
        }
        let (stdout, stderr) = as2_lancer_l_enfant(
            {
                let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
                enfant.env(AS2_ENFANT_ENGENDRES, "1");
                enfant
            },
            "tests::as2_frontiere_froide_non_lue_et_ecritures_avouees::as2_pivot_et_jeu_de_donnees_classent_l_echec_par_la_route",
        );
        let rendus = as2_lire_les_rendus(&stdout);
        assert!(stdout.contains(&format!("{AS2_FIN} 10")), "contrôle : deux sites, cinq issues chacun : {stdout}\n{stderr}");
        assert!(rendus.len() >= 10, "plancher : dix issues rendues ({})", rendus.len());
        let rendu = |site: &str, issue: &str| -> (u16, String, String) {
            let r = rendus.iter().find(|r| r.0 == site && r.1 == issue).unwrap_or_else(|| panic!("contrôle : {site}/{issue} joué, panne armée : {rendus:?}"));
            (r.2, r.3.clone(), r.4.clone())
        };
        let budget = crate::query_exec::query_budget_interactive_ms();
        let mut attendu: Vec<String> = Vec::new();
        for (site, _, route_du_journal) in AS2_SITES_ENGENDRES {
            let (c, b, _) = rendu(site, "nominal");
            assert_eq!(c, 200, "contrôle : {site} nominal servi : {b}");
            let v: Value = serde_json::from_str(&b).expect("contrôle : réponse JSON");
            assert_eq!(v["rows"], json!([[1]]), "contrôle : {site} compte la ligne semée : {b}");
            for issue in ["support", "occupee", "produit", "moteur"] {
                let (_, _, brut) = rendu(site, issue);
                for trace in TRACES_DU_MOTEUR {
                    assert!(!brut.contains(trace), "{site}/{issue} : la réponse porte « {trace} » : {brut}");
                }
            }
            let (c, b, _) = rendu(site, "support");
            let id = as2_juger_503(&format!("{site}/support"), c, &b, CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE);
            attendu.push(as2_ligne_support(route_du_journal, "default", &id));
            let (c, b, _) = rendu(site, "occupee");
            let id = as2_juger_503(&format!("{site}/occupee"), c, &b, CAUSE_REQUETE_NON_SERVIE_BASE_OCCUPEE);
            attendu.push(as2_ligne_occupee(route_du_journal, "default", &id));
            let (c, b, _) = rendu(site, "produit");
            assert_eq!(
                (c, serde_json::from_str::<Value>(&b).unwrap_or(Value::Null)),
                (400, json!({ "error": format!("requête interrompue (budget {} s dépassé)", budget / 1000) })),
                "{site}/produit : la phrase du produit à l'octet, en 400"
            );
            let (c, b, _) = rendu(site, "moteur");
            assert_eq!(
                (c, serde_json::from_str::<Value>(&b).unwrap_or(Value::Null)),
                (400, json!({ "error": REQUETE_REJETEE_PAR_LE_MOTEUR })),
                "{site}/moteur : la phrase fixe, jamais le texte du moteur"
            );
            attendu.push(as2_ligne_moteur(route_du_journal, "default"));
        }
        assert_eq!(as2_journal_query(&stderr), attendu, "une ligne [query] EXACTE par refus du support, de la base occupée et du moteur :\n{stderr}");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // (2) DEUX TENANTS RÉELS, SITE PAR SITE — `P10.29-l`
    // ---------------------------------------------------------------------------------------------------------------

    const AS2_ENFANT_DEUX: &str = "AS2_ENFANT_DEUX_TENANTS";

    /// (2) La ligne nomme le tenant de l'appelant sur CHAQUE site et chaque classe ; l'autre tenant reste servi.
    #[tokio::test]
    async fn as2_pivot_et_jeu_de_donnees_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(AS2_ENFANT_DEUX).is_ok() {
            let (st, _dir) = mk_mode1_state();
            let maintenant = now();
            let alpha = as2_creer_le_tenant(&st, AS2_ALPHA, maintenant - 60).await;
            let beta = as2_creer_le_tenant(&st, AS2_BETA, maintenant - 60).await;
            assert_ne!(alpha, beta, "contrôle : deux bases distinctes");
            let mut rendus: As2Rendus = Vec::new();
            for (site, _, _) in AS2_SITES_ENGENDRES {
                let corps = as2_corps_engendre(site, maintenant - 3600, maintenant + 3600);
                for (issue, panne, appelant, chemin, autre, chemin_autre) in [
                    ("support", PanneAuCoeur::ErreurDuSupport, AS2_ALPHA, &alpha, AS2_BETA, &beta),
                    ("support", PanneAuCoeur::ErreurDuSupport, AS2_BETA, &beta, AS2_ALPHA, &alpha),
                    ("occupee", PanneAuCoeur::BaseOccupee, AS2_ALPHA, &alpha, AS2_BETA, &beta),
                    ("occupee", PanneAuCoeur::BaseOccupee, AS2_BETA, &beta, AS2_ALPHA, &alpha),
                    ("moteur", PanneAuCoeur::RefusDeLAutorisateur, AS2_BETA, &beta, AS2_ALPHA, &alpha),
                    ("moteur", PanneAuCoeur::RefusDeLAutorisateur, AS2_ALPHA, &alpha, AS2_BETA, &beta),
                ] {
                    as2_vider_le_pool(chemin);
                    demander(chemin, panne);
                    let (c, b) = as2_appel_engendre(&st, site, appelant, corps.clone()).await;
                    let servie = !encore_demandee(chemin);
                    retirer(chemin);
                    as2_vider_le_pool(chemin);
                    rendus.push((site.into(), format!("{issue}:{appelant}:{}", if servie { "armee" } else { "non_armee" }), c, b, String::new()));
                    let (c, b) = as2_appel_engendre(&st, site, autre, corps.clone()).await;
                    assert!(!encore_demandee(chemin_autre), "contrôle : aucune panne demandée sur l'autre base");
                    rendus.push((site.into(), format!("nominal:{autre}"), c, b, String::new()));
                }
            }
            as2_imprimer(&rendus);
            return;
        }
        let (stdout, stderr) = as2_lancer_l_enfant(
            {
                let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
                enfant.env(AS2_ENFANT_DEUX, "1");
                enfant
            },
            "tests::as2_frontiere_froide_non_lue_et_ecritures_avouees::as2_pivot_et_jeu_de_donnees_deux_tenants",
        );
        let rendus = as2_lire_les_rendus(&stdout);
        assert!(stdout.contains(&format!("{AS2_FIN} 24")), "contrôle : deux sites, douze appels chacun : {stdout}\n{stderr}");
        assert!(rendus.len() >= 24, "plancher : vingt-quatre appels rendus ({})", rendus.len());
        let mut attendu: Vec<String> = Vec::new();
        for (site, issue, code, corps, _) in &rendus {
            let route = AS2_SITES_ENGENDRES.iter().find(|s| s.0 == site.as_str()).map(|s| s.2).expect("site connu");
            let morceaux: Vec<&str> = issue.split(':').collect();
            match morceaux.as_slice() {
                ["nominal", t] => {
                    assert_eq!(*code, 200, "{site} : l'autre tenant ({t}) reste servi par sa base : {corps}");
                    assert_eq!(serde_json::from_str::<Value>(corps).unwrap_or(Value::Null)["rows"], json!([[1]]), "{site}/{t} : sa ligne");
                }
                ["support", t, "armee"] => {
                    let id = as2_juger_503(&format!("{site}/support/{t}"), *code, corps, CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE);
                    attendu.push(as2_ligne_support(route, t, &id));
                }
                ["occupee", t, "armee"] => {
                    let id = as2_juger_503(&format!("{site}/occupee/{t}"), *code, corps, CAUSE_REQUETE_NON_SERVIE_BASE_OCCUPEE);
                    attendu.push(as2_ligne_occupee(route, t, &id));
                }
                ["moteur", t, "armee"] => {
                    assert_eq!(
                        (*code, serde_json::from_str::<Value>(corps).unwrap_or(Value::Null)),
                        (400, json!({ "error": REQUETE_REJETEE_PAR_LE_MOTEUR })),
                        "{site}/moteur/{t} : la phrase fixe"
                    );
                    attendu.push(as2_ligne_moteur(route, t));
                }
                autre => panic!("contrôle : panne armée à chaque appel : {site} {autre:?}"),
            }
        }
        assert_eq!(attendu.len(), 12, "contrôle : douze refus attendus au journal");
        assert_eq!(as2_journal_query(&stderr), attendu, "chaque ligne [query] nomme le tenant de l'appelant, site par site :\n{stderr}");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // (3) LE CANAL `ntfy (env)` EN TROIS ISSUES — `P10.20-b`
    // ---------------------------------------------------------------------------------------------------------------

    const AS2_ENFANT_NTFY: &str = "AS2_ENFANT_CANAL_NTFY";
    const AS2_URL_A: &str = "http://192.0.2.10/as2-a";
    const AS2_URL_B: &str = "http://192.0.2.11/as2-b";

    fn as2_conf_ntfy(url: &str) -> HashMap<String, String> {
        let mut c = HashMap::new();
        c.insert("PLUME_NOTIFY_NTFY_URL".to_string(), url.to_string());
        c
    }

    fn as2_canaux(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM notifier", [], |r| r.get(0)).expect("compte des canaux")
    }

    fn as2_canaux_env(conn: &Connection) -> Vec<String> {
        let mut s = conn.prepare("SELECT url FROM notifier WHERE name='ntfy (env)' ORDER BY id").expect("lecture des canaux env");
        let urls: Vec<String> = s.query_map([], |r| r.get(0)).expect("parcours").collect::<rusqlite::Result<_>>().expect("lignes");
        urls
    }

    fn as2_refuser_l_identifiant(conn: &Connection) {
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "notifier" && column_name == "id" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn as2_rendre_la_main(conn: &Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// Une base où le canal `ntfy (env)` existe (URL A) — ou non.
    fn as2_base_ntfy(avec_canal: bool) -> Connection {
        let conn = test_db();
        if avec_canal {
            crate::seeds::seed_env_notifier(&conn, &as2_conf_ntfy(AS2_URL_A));
            assert_eq!(as2_canaux_env(&conn), vec![AS2_URL_A.to_string()], "fixture : un canal env, URL A");
        }
        conn
    }

    /// (3) SOUS-PROCESSUS : chaque issue, comptes avant/après, lignes `[seed]` entières et dans l'ordre (aucune pour les
    /// trois succès ni pour l'URL vide). MUTANTS : `AS2_S_OK`, `AS2_S_LECTURE_MUETTE`, `AS2_S_MAJ_REFUS_MUET`,
    /// `AS2_S_MAJ_VIDE_MUET`, `AS2_S_INS_REFUS_MUET`, `AS2_S_INS_VIDE_MUET`.
    #[test]
    fn as2_canal_ntfy_en_trois_issues_sans_doublon() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // `cfg` lit l'environnement avant la carte
        if std::env::var(AS2_ENFANT_NTFY).is_ok() {
            println!("AS2-ENFANT-NTFY-A-JOUE");
            assert!(std::env::var("PLUME_NOTIFY_NTFY_URL").is_err(), "prémisse : l'URL vient de la carte, pas de l'environnement");
            // Absent : INSERT (succès, muet).
            let conn = as2_base_ntfy(false);
            let avant = as2_canaux(&conn);
            crate::seeds::seed_env_notifier(&conn, &as2_conf_ntfy(AS2_URL_A));
            assert_eq!(as2_canaux(&conn), avant + 1, "absent : un canal posé");
            assert_eq!(as2_canaux_env(&conn), vec![AS2_URL_A.to_string()], "absent : URL A");
            // Présent : UPDATE (succès, muet).
            let avant = as2_canaux(&conn);
            crate::seeds::seed_env_notifier(&conn, &as2_conf_ntfy(AS2_URL_B));
            assert_eq!(as2_canaux(&conn), avant, "présent : aucun canal de plus");
            assert_eq!(as2_canaux_env(&conn), vec![AS2_URL_B.to_string()], "présent : l'URL mise à jour");
            // URL vide : rien (muet).
            crate::seeds::seed_env_notifier(&conn, &as2_conf_ntfy(""));
            assert_eq!(as2_canaux_env(&conn), vec![AS2_URL_B.to_string()], "URL vide : rien ne bouge");
            // Présent, NON LU : rien n'est écrit, aucun second canal.
            let avant = as2_canaux(&conn);
            as2_refuser_l_identifiant(&conn);
            crate::seeds::seed_env_notifier(&conn, &as2_conf_ntfy(AS2_URL_A));
            as2_rendre_la_main(&conn);
            assert_eq!(as2_canaux(&conn), avant, "présent non lu : aucun second canal");
            assert_eq!(as2_canaux_env(&conn), vec![AS2_URL_B.to_string()], "présent non lu : la ligne existante intacte");
            // Absent, NON LU : rien n'est écrit.
            let conn = as2_base_ntfy(false);
            let avant = as2_canaux(&conn);
            as2_refuser_l_identifiant(&conn);
            crate::seeds::seed_env_notifier(&conn, &as2_conf_ntfy(AS2_URL_A));
            as2_rendre_la_main(&conn);
            assert_eq!(as2_canaux(&conn), avant, "absent non lu : rien n'est écrit");
            // UPDATE refusé, puis sans effet.
            let conn = as2_base_ntfy(true);
            let avant = as2_canaux(&conn);
            conn.execute_batch("CREATE TRIGGER as2_maj BEFORE UPDATE ON notifier BEGIN SELECT RAISE(ABORT, 'as2-maj-refusee'); END;").expect("déclencheur");
            crate::seeds::seed_env_notifier(&conn, &as2_conf_ntfy(AS2_URL_B));
            conn.execute_batch("DROP TRIGGER as2_maj; CREATE TRIGGER as2_maj BEFORE UPDATE ON notifier BEGIN SELECT RAISE(IGNORE); END;").expect("déclencheur");
            crate::seeds::seed_env_notifier(&conn, &as2_conf_ntfy(AS2_URL_B));
            assert_eq!(as2_canaux(&conn), avant, "UPDATE refusé ou sans effet : aucun canal de plus");
            assert_eq!(as2_canaux_env(&conn), vec![AS2_URL_A.to_string()], "UPDATE refusé ou sans effet : l'URL d'avant");
            // INSERT refusé, puis sans effet.
            let conn = as2_base_ntfy(false);
            let avant = as2_canaux(&conn);
            conn.execute_batch("CREATE TRIGGER as2_ins BEFORE INSERT ON notifier BEGIN SELECT RAISE(ABORT, 'as2-insertion-refusee'); END;").expect("déclencheur");
            crate::seeds::seed_env_notifier(&conn, &as2_conf_ntfy(AS2_URL_A));
            conn.execute_batch("DROP TRIGGER as2_ins; CREATE TRIGGER as2_ins BEFORE INSERT ON notifier BEGIN SELECT RAISE(IGNORE); END;").expect("déclencheur");
            crate::seeds::seed_env_notifier(&conn, &as2_conf_ntfy(AS2_URL_A));
            assert_eq!(as2_canaux(&conn), avant, "INSERT refusé ou sans effet : aucun canal");
            return;
        }
        let (stdout, stderr) = as2_lancer_l_enfant(
            {
                let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
                enfant.env(AS2_ENFANT_NTFY, "1");
                enfant
            },
            "tests::as2_frontiere_froide_non_lue_et_ecritures_avouees::as2_canal_ntfy_en_trois_issues_sans_doublon",
        );
        assert!(stdout.contains("AS2-ENFANT-NTFY-A-JOUE"), "contrôle : l'enfant a vraiment joué : {stdout}\n{stderr}");
        let lues: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[seed] canal `ntfy (env)`")).collect();
        let lecture = "[seed] canal `ntfy (env)` NON semé : sa présence n'a pas pu être lue (access to notifier.id is prohibited) — rien n'est écrit \
                       (aucun second canal), retenté au prochain démarrage";
        let attendues: Vec<String> = vec![
            lecture.to_string(),
            lecture.to_string(),
            "[seed] canal `ntfy (env)` NON mis à jour : écriture refusée (as2-maj-refusee) — le canal garde sa configuration précédente, retenté au prochain démarrage".to_string(),
            "[seed] canal `ntfy (env)` NON mis à jour : écriture sans effet (0 ligne au lieu d'une) — le canal garde sa configuration précédente, retenté au prochain démarrage".to_string(),
            "[seed] canal `ntfy (env)` NON semé : écriture refusée (as2-insertion-refusee) — aucun canal n'est créé, retenté au prochain démarrage".to_string(),
            "[seed] canal `ntfy (env)` NON semé : écriture sans effet (0 ligne au lieu d'une) — aucun canal n'est créé, retenté au prochain démarrage".to_string(),
        ];
        assert_eq!(lues, attendues, "lignes entières, dans l'ordre, aucune pour les succès :\n{stderr}");
        for l in stderr.lines() {
            assert!(!l.contains("192.0.2."), "aucune ligne ne porte l'URL du canal : {l}");
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // (4) LA CONTRIBUTION THREAT-INTEL REFUSÉE EST DITE — `P10.20-b`
    // ---------------------------------------------------------------------------------------------------------------

    const AS2_ENFANT_RISQUE: &str = "AS2_ENFANT_RISQUE_TI";

    fn as2_contributions_ti(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM risk_event WHERE source='ti'", [], |r| r.get(0)).expect("compte des contributions")
    }

    /// La ligne `[risk]` attendue pour un refus : la cause du moteur, puis l'état de la transaction englobante RELU.
    fn as2_ligne_risque(cause: &str, transaction: &str) -> String {
        format!("[risk] WARN contribution de risque threat-intel NON écrite : refusée par le moteur ({cause}) — l'entité ne reçoit pas ce score ; {transaction}")
    }

    /// (4) SOUS-PROCESSUS : écrite, déjà posée (même bucket) muettes ; refusée par un `RAISE(ABORT)` dans la transaction
    /// du lot : aucune ligne, la transaction reste ouverte ET validable, la ligne le dit ; refusée par un
    /// `RAISE(ROLLBACK)` : le moteur annule lui-même la transaction (l'événement du lot disparaît), la ligne dit
    /// « ANNULÉE » et non « ouverte » ; refusée hors de toute transaction : la ligne le dit. Trois lignes `[risk]`
    /// entières, dans l'ordre (ni entité ni source du flux). MUTANTS : `AS2_R_MUET`, `AS2_R_TX_FIGEE`.
    #[test]
    fn as2_contribution_threat_intel_refusee_est_dite() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // `load_config` lit l'environnement
        if std::env::var(AS2_ENFANT_RISQUE).is_ok() {
            println!("AS2-ENFANT-RISQUE-A-JOUE");
            let conn = test_db();
            let ts = now();
            let hit = |entite: &str| crate::handlers::threat_intel::TiHit { entity_type: "ip".into(), entity: entite.into(), severity: 3, source: "as2-flux".into() };
            let evenements = |source: &str| -> i64 { conn.query_row("SELECT COUNT(*) FROM event WHERE source=?1", params![source], |r| r.get(0)).expect("compte") };
            // (a) refus d'énoncé : la transaction du lot reste ouverte.
            let tx = conn.unchecked_transaction().expect("transaction du lot");
            tx.execute("INSERT INTO event(ts,source,severity,message,host,src_ip) VALUES(?1,'as2-ti',1,'as2','h',NULL)", params![ts]).expect("événement du lot");
            crate::handlers::rba::ti_risk_contribution(&tx, &hit("192.0.2.10"), ts, "prod");
            assert_eq!(as2_contributions_ti(&tx), 1, "écrite");
            crate::handlers::rba::ti_risk_contribution(&tx, &hit("192.0.2.10"), ts, "prod");
            assert_eq!(as2_contributions_ti(&tx), 1, "déjà posée : dédup du bucket");
            tx.execute_batch("CREATE TRIGGER as2_risque BEFORE INSERT ON risk_event BEGIN SELECT RAISE(ABORT, 'as2-risque-refuse'); END;").expect("déclencheur");
            crate::handlers::rba::ti_risk_contribution(&tx, &hit("192.0.2.11"), ts, "prod");
            assert_eq!(as2_contributions_ti(&tx), 1, "refusée : aucune ligne");
            assert!(!conn.is_autocommit(), "contrôle : la transaction du lot est encore ouverte après un refus d'énoncé");
            tx.commit().expect("la transaction du lot reste validable");
            assert_eq!(evenements("as2-ti"), 1, "l'événement du lot reste écrit");
            // (b) le moteur annule la transaction de lui-même.
            conn.execute_batch(
                "DROP TRIGGER as2_risque; CREATE TRIGGER as2_risque_annule BEFORE INSERT ON risk_event BEGIN SELECT RAISE(ROLLBACK, 'as2-risque-annule'); END;",
            )
            .expect("déclencheur d'annulation");
            let tx = conn.unchecked_transaction().expect("transaction du second lot");
            tx.execute("INSERT INTO event(ts,source,severity,message,host,src_ip) VALUES(?1,'as2-ti-annule',1,'as2','h',NULL)", params![ts])
                .expect("événement du second lot");
            crate::handlers::rba::ti_risk_contribution(&tx, &hit("192.0.2.12"), ts, "prod");
            assert!(conn.is_autocommit(), "contrôle : le moteur a bien annulé la transaction englobante");
            drop(tx);
            assert_eq!(evenements("as2-ti-annule"), 0, "contrôle : l'événement du second lot est parti avec l'annulation");
            assert_eq!(as2_contributions_ti(&conn), 1, "refusée : aucune ligne");
            // (c) hors de toute transaction.
            crate::handlers::rba::ti_risk_contribution(&conn, &hit("192.0.2.13"), ts, "prod");
            assert_eq!(as2_contributions_ti(&conn), 1, "refusée hors transaction : aucune ligne");
            return;
        }
        let (stdout, stderr) = as2_lancer_l_enfant(
            {
                let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
                enfant.env(AS2_ENFANT_RISQUE, "1");
                enfant
            },
            "tests::as2_frontiere_froide_non_lue_et_ecritures_avouees::as2_contribution_threat_intel_refusee_est_dite",
        );
        assert!(stdout.contains("AS2-ENFANT-RISQUE-A-JOUE"), "contrôle : l'enfant a vraiment joué : {stdout}\n{stderr}");
        let lues: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[risk] ")).collect();
        assert_eq!(
            lues,
            vec![
                as2_ligne_risque("as2-risque-refuse", "la transaction englobante reste ouverte"),
                as2_ligne_risque("as2-risque-annule", "la transaction englobante a été ANNULÉE par le moteur"),
                as2_ligne_risque("as2-risque-annule", "aucune transaction englobante"),
            ],
            "trois lignes entières, aucune pour l'écrite ni la déjà posée :\n{stderr}"
        );
    }

    // ---------------------------------------------------------------------------------------------------------------
    // TIER FROID (`--features cold_tier`) — LA FRONTIÈRE NON LUE N'EST JAMAIS FABRIQUÉE
    // ---------------------------------------------------------------------------------------------------------------

    /// Les deux formes d'une valeur écrite illisible : un BLOB et un texte présent mais non entier.
    #[cfg(feature = "cold_tier")]
    const AS2_ILLISIBLES: [&str; 2] = ["BLOB", "365.0"];
    #[cfg(feature = "cold_tier")]
    const AS2_SOQL: &str = "search source=as2";
    /// Les sept sites qui lisent la frontière : (nom, route).
    #[cfg(feature = "cold_tier")]
    const AS2_SITES_FROIDS: [(&str, &str); 7] = [
        ("compte", "/api/query"),
        ("keyset", "/api/query"),
        ("page", "/api/query"),
        ("plein", "/api/query"),
        ("export", "/api/export"),
        ("pivot", "/api/pivot/run"),
        ("jeu", "/api/datasets/1/run"),
    ];

    #[cfg(feature = "cold_tier")]
    fn as2_valeur(forme: &str) -> rusqlite::types::Value {
        match forme {
            "BLOB" => rusqlite::types::Value::Blob(vec![0]),
            texte => rusqlite::types::Value::Text(texte.to_string()),
        }
    }

    #[cfg(feature = "cold_tier")]
    fn as2_pose(conn: &Connection, valeur: rusqlite::types::Value) {
        conn.execute("INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global','retention_days',?1)", params![valeur]).expect("réglage posé");
    }

    #[cfg(feature = "cold_tier")]
    fn as2_corps_froid(site: &str, depuis: i64, jusqua: i64) -> Value {
        match site {
            "compte" => json!({ "soql": AS2_SOQL, "from": depuis, "to": jusqua, "count_only": true }),
            "keyset" => json!({ "soql": AS2_SOQL, "from": depuis, "to": jusqua, "limit": 10, "keyset": true }),
            "page" => json!({ "soql": AS2_SOQL, "from": depuis, "to": jusqua, "limit": 10 }),
            "plein" => json!({ "soql": AS2_SOQL, "from": depuis, "to": jusqua }),
            "export" => json!({ "soql": AS2_SOQL, "from": depuis, "to": jusqua, "format": "json" }),
            autre => as2_corps_engendre(autre, depuis, jusqua),
        }
    }

    /// L'aveu attendu pour ce site, ÉCRIT EN LITTÉRAUX (jamais relu de la fonction de production) : `served_from: "hot"`
    /// (que `web/viz.js` `coldShareBadge` lit pour peindre « bande non lue » ; `"hot+cold"` y peindrait « froid : rien
    /// de vieilli »), `reason`, la clé non lue, la phrase entière qui nomme la route qui sert, et AUCUN `boundary_ts`
    /// (une frontière que la console afficherait). MUTANTS : `AS2_P_CONTENU_SERVI`, `AS2_P_CONTENU_FRONTIERE`.
    #[cfg(feature = "cold_tier")]
    fn as2_aveu_attendu(site: &str) -> Value {
        let chemin = match site {
            "pivot" => "/api/pivot/run",
            "jeu" => "/api/datasets/{id}/run",
            _ => "/api/query",
        };
        json!({
            "served_from": "hot",
            "reason": "cold_coverage_unread",
            "reglage_non_lu": "retention_days",
            "aveu": format!(
                "bande froide NON établie, frontière non lue : le réglage de rétention écrit (`retention_days`) n'a pas pu être lu, aucune frontière n'est calculée sur un repli ; ce chemin ({chemin}) n'a lu que la fenêtre chaude, des lignes plus anciennes existent peut-être dans le tier froid et ne sont pas comptées"
            ),
        })
    }

    /// Pose le tier froid dans l'environnement (les routes lisent `load_config()`) et le retire à la chute, panic
    /// compris, avec la clé enregistrée pour la base.
    #[cfg(feature = "cold_tier")]
    struct As2Froid(Option<String>);

    #[cfg(feature = "cold_tier")]
    const AS2_VARIABLES_FROIDES: [(&str, &str); 3] = [("PLUME_COLD_TIER", "1"), ("PLUME_COLD_HOT_WINDOW_DAYS", "2"), ("PLUME_COLD_VECTORIZED", "0")];

    #[cfg(feature = "cold_tier")]
    impl As2Froid {
        fn poser(chemin_cle: Option<String>) -> Self {
            std::env::remove_var("PLUME_COLD_DIR");
            for (k, v) in AS2_VARIABLES_FROIDES {
                std::env::set_var(k, v);
            }
            As2Froid(chemin_cle)
        }
    }

    #[cfg(feature = "cold_tier")]
    impl Drop for As2Froid {
        fn drop(&mut self) {
            for (k, _) in AS2_VARIABLES_FROIDES {
                std::env::remove_var(k);
            }
            if let Some(c) = &self.0 {
                crate::crypto::unregister_db_key(c);
            }
        }
    }

    /// Ce qu'un site sert, jugé : (statut, corps JSON pour les routes JSON, en-têtes utiles pour l'export).
    #[cfg(feature = "cold_tier")]
    struct As2Servi {
        code: u16,
        corps: Value,
        tronque: Option<String>,
        couverture: Option<String>,
        disposition: Option<String>,
    }

    #[cfg(feature = "cold_tier")]
    fn as2_juger_illisible(contexte: &str, site: &str, s: &As2Servi) {
        assert_eq!(s.code, 200, "{contexte} : réponse chaude servie : {}", s.corps);
        match site {
            "export" => {
                assert_eq!(s.corps.as_array().map(|a| a.len()), Some(1), "{contexte} : la ligne chaude exportée : {}", s.corps);
                assert_eq!(s.tronque.as_deref(), Some("1"), "{contexte} : le fichier est dit incomplet");
                assert_eq!(s.couverture.as_deref(), Some("cold_coverage_unread"), "{contexte} : la cause est nommée");
                assert!(
                    s.disposition.as_deref().unwrap_or("").ends_with("-TRONQUE-ampleur-inconnue.json\""),
                    "{contexte} : le nom du fichier porte l'aveu : {:?}",
                    s.disposition
                );
            }
            _ => {
                assert_eq!(s.corps["stats"]["cold"], as2_aveu_attendu(site), "{contexte} : l'aveu de frontière non lue, entier : {}", s.corps);
                assert!(s.corps["stats"]["cold"].get("boundary_ts").is_none(), "{contexte} : aucune frontière publiée : {}", s.corps);
                assert_eq!(s.corps["stats"]["cold"]["served_from"], json!("hot"), "{contexte} : servi du chaud seul : {}", s.corps);
                match site {
                    "compte" => assert_eq!(s.corps["total"], json!(1), "{contexte} : le compte chaud : {}", s.corps),
                    "pivot" | "jeu" => assert_eq!(s.corps["rows"], json!([[1]]), "{contexte} : le compte chaud : {}", s.corps),
                    _ => assert_eq!(s.corps["rows"].as_array().map(|a| a.len()), Some(1), "{contexte} : la ligne chaude : {}", s.corps),
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // (5) PAR LA ROUTE, FENÊTRE PROFONDE
    // ---------------------------------------------------------------------------------------------------------------

    /// La clé de la base de la fixture (même valeur que le banc froid de `aveu_de_part_froide_sur_la_route.rs`) : la
    /// route, et l'union froide qu'elle ouvre sur un réglage lisible, la retrouvent par le registre par chemin.
    #[cfg(feature = "cold_tier")]
    const AS2_CLE_DE_LA_FIXTURE: &str = "plume-cold-route-test-key-do-not-use-in-prod-0000";

    #[cfg(feature = "cold_tier")]
    async fn as2_servir_par_la_route(addr: std::net::SocketAddr, site: &str, route: &str, corps: &Value) -> As2Servi {
        let (code, b, brut) = as2_envoi(addr, route, &viewer_authz(), corps).await;
        As2Servi {
            code,
            corps: serde_json::from_str(&b).unwrap_or(Value::Null),
            tronque: (site == "export").then(|| as2_entete(&brut, "x-plume-truncated")).flatten(),
            couverture: as2_entete(&brut, "x-plume-cold-coverage"),
            disposition: (site == "export").then(|| as2_entete(&brut, "content-disposition")).flatten(),
        }
    }

    /// (5) `retention_days` illisible (BLOB, « 365.0 »), fenêtre bien plus ancienne que toute frontière : chaque site
    /// sert la part chaude et l'aveu ENTIER, jamais une frontière ; contrôle lisible : frontière établie (`boundary_ts`)
    /// sur les six sites qui la publient, aucun en-tête d'aveu sur l'export. MUTANTS : `AS2_Q_REPLI`,
    /// `AS2_Q_AVEU_COMPTE`, `AS2_Q_AVEU_KEYSET`, `AS2_Q_AVEU_PAGE`, `AS2_Q_AVEU_PLEIN`, `AS2_X_REPLI`,
    /// `AS2_X_NON_TRONQUE`, `AS2_X_SANS_ENTETE`, `AS2_P_REPLI`, `AS2_P_SANS_AVEU`, `AS2_P_ROUTE`.
    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn as2_froid_requete_export_et_pivot_sans_frontiere_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write(); // l'environnement du tier froid est posé ici
        let maintenant = now();
        let depuis = maintenant - 400 * 86_400;
        for &forme in table_declaree!(AS2_ILLISIBLES) {
            let (st, base) = router_test_state_avec(&format!("as2-froid-{}", forme.replace('.', "-")), Some(AS2_CLE_DE_LA_FIXTURE));
            let _froid = As2Froid::poser(Some(base.as_str().to_string()));
            {
                let c = st.db.lock();
                as2_semer(&c, maintenant - 60);
                as2_pose(&c, as2_valeur(forme));
            }
            let addr = router_serve(st.clone()).await;
            for &(site, route) in table_declaree!(AS2_SITES_FROIDS) {
                let s = as2_servir_par_la_route(addr, site, route, &as2_corps_froid(site, depuis, maintenant + 3600)).await;
                as2_juger_illisible(&format!("{forme}/{site}"), site, &s);
            }
        }
        let (st, base) = router_test_state_avec("as2-froid-lisible", Some(AS2_CLE_DE_LA_FIXTURE));
        let _froid = As2Froid::poser(Some(base.as_str().to_string()));
        {
            let c = st.db.lock();
            as2_semer(&c, maintenant - 60);
            as2_pose(&c, rusqlite::types::Value::Text("30".into()));
        }
        let addr = router_serve(st.clone()).await;
        for &(site, route) in table_declaree!(AS2_SITES_FROIDS) {
            let s = as2_servir_par_la_route(addr, site, route, &as2_corps_froid(site, depuis, maintenant + 3600)).await;
            assert_eq!(s.code, 200, "contrôle lisible/{site} : servi : {}", s.corps);
            assert_eq!(s.couverture, None, "contrôle lisible/{site} : aucun en-tête d'aveu");
            match site {
                "export" => assert_eq!(s.tronque.as_deref(), Some("0"), "contrôle lisible : l'export n'est pas dit incomplet"),
                "compte" => assert!(s.corps["stats"].get("cold").is_none(), "contrôle lisible : le compte seul ne dit rien du froid (d'avant) : {}", s.corps),
                _ => {
                    assert!(s.corps["stats"]["cold"]["boundary_ts"].is_i64(), "contrôle lisible/{site} : la frontière est établie : {}", s.corps);
                    assert!(s.corps["stats"]["cold"].get("reason").is_none(), "contrôle lisible/{site} : aucun aveu de frontière non lue : {}", s.corps);
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // (6) DEUX TENANTS RÉELS
    // ---------------------------------------------------------------------------------------------------------------

    #[cfg(feature = "cold_tier")]
    async fn as2_servir_par_le_gestionnaire(st: &AppState, site: &str, t: &str, corps: Value) -> As2Servi {
        let r = match site {
            "export" => crate::handlers::query::export(State(st.clone()), Extension(as2_lecteur(t)), Json(corps)).await,
            "pivot" | "jeu" => {
                let (code, b) = as2_appel_engendre(st, site, t, corps).await;
                return As2Servi { code, corps: serde_json::from_str(&b).unwrap_or(Value::Null), tronque: None, couverture: None, disposition: None };
            }
            _ => crate::handlers::query::query(State(st.clone()), Extension(as2_lecteur(t)), Json(corps)).await,
        };
        let code = r.status().as_u16();
        let entete = |nom: &str| r.headers().get(nom).and_then(|v| v.to_str().ok()).map(str::to_string);
        let (tronque, couverture, disposition) = (entete("x-plume-truncated"), entete("x-plume-cold-coverage"), entete("content-disposition"));
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        As2Servi { code, corps: serde_json::from_slice(&b).unwrap_or(Value::Null), tronque, couverture, disposition }
    }

    /// (6) MODE 1, DEUX TENANTS : l'un illisible (BLOB puis « 365.0 »), l'autre lisible, puis l'inverse ; même corps,
    /// fenêtre chaude (un réglage lisible n'atteint pas le froid) : l'aveu suit la base de l'appelant, sur chaque site.
    /// MUTANTS : ceux de (5) qui retirent l'aveu ou rendent le repli.
    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn as2_froid_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _froid = As2Froid::poser(None);
        let (st, _dir) = mk_mode1_state();
        let maintenant = now();
        as2_creer_le_tenant(&st, AS2_ALPHA, maintenant - 60).await;
        as2_creer_le_tenant(&st, AS2_BETA, maintenant - 60).await;
        let poser = |t: &str, v: rusqlite::types::Value| as2_pose(&st.tenants.handle_for(t).expect("base du tenant").lock(), v);
        for (illisible, lisible, forme) in [(AS2_ALPHA, AS2_BETA, "BLOB"), (AS2_BETA, AS2_ALPHA, "365.0")] {
            poser(illisible, as2_valeur(forme));
            poser(lisible, rusqlite::types::Value::Text("30".into()));
            for &(site, _) in table_declaree!(AS2_SITES_FROIDS) {
                let corps = as2_corps_froid(site, maintenant - 3600, maintenant + 3600);
                let s = as2_servir_par_le_gestionnaire(&st, site, illisible, corps.clone()).await;
                as2_juger_illisible(&format!("{illisible}/{forme}/{site}"), site, &s);
                let s = as2_servir_par_le_gestionnaire(&st, site, lisible, corps).await;
                assert_eq!(s.code, 200, "{lisible}/{site} : servi : {}", s.corps);
                assert_eq!(s.couverture, None, "{lisible}/{site} : aucun en-tête d'aveu");
                if site == "export" {
                    assert_eq!(s.tronque.as_deref(), Some("0"), "{lisible} : l'export n'est pas dit incomplet");
                } else {
                    assert!(s.corps["stats"].get("cold").is_none(), "{lisible}/{site} : fenêtre chaude, aucun aveu froid : {}", s.corps);
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // (7) EXPORT SERVI PAR LA ROUTE PRÉ-AGRÉGÉE : AUCUN NOMBRE FABRIQUÉ
    // ---------------------------------------------------------------------------------------------------------------

    /// (7) `search source=web | stats count by status`, 37 valeurs distinctes dans le seau courant, plafond top-N à 5 :
    /// l'export passe par la route pré-agrégée CHAUDE, dont la sonde chiffre 32 lignes écartées. CONTRÔLE lisible : le
    /// nom porte `-TRONQUE-32-lignes-manquantes` et `x-plume-truncated-ecartes: 32` (la route et sa sonde ont bien
    /// servi). Illisible (BLOB, « 365.0 ») : la part froide est d'ampleur inconnue, donc NI le nom NI l'en-tête ne
    /// portent 32 — nom `-TRONQUE-ampleur-inconnue`, aucun `x-plume-truncated-ecartes`, la cause nommée. MUTANT :
    /// `AS2_X_ECARTES`.
    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn as2_froid_export_pre_agrege_sans_nombre_fabrique() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write(); // tier froid et plafond top-N posés ici
        let maintenant = now();
        let seau = (maintenant / 3600) * 3600;
        let corps = json!({ "soql": "search source=web | stats count by status", "from": maintenant - 3600, "to": maintenant + 3600, "format": "json" });
        for forme in ["lisible", "BLOB", "365.0"] {
            let (st, base) = router_test_state_avec(&format!("as2-export-topn-{}", forme.replace('.', "-")), Some(AS2_CLE_DE_LA_FIXTURE));
            let _froid = As2Froid::poser(Some(base.as_str().to_string()));
            {
                let c = st.db.lock();
                for i in 0..37 {
                    c.execute(
                        "INSERT INTO event(ts,source,fields,dedup) VALUES(?1,'web',?2,?3)",
                        params![seau + 61, format!("{{\"status\":\"v{i}\"}}"), format!("as2-topn-{i}")],
                    )
                    .expect("fixture : événement");
                }
                std::env::set_var("PLUME_ROLLUP_DIM_TOPN", "5");
                rollup_events(&c);
                std::env::remove_var("PLUME_ROLLUP_DIM_TOPN");
                let valeur = if forme == "lisible" { rusqlite::types::Value::Text("30".into()) } else { as2_valeur(forme) };
                as2_pose(&c, valeur);
            }
            let addr = router_serve(st.clone()).await;
            let (code, b, brut) = as2_envoi(addr, "/api/export", &viewer_authz(), &corps).await;
            assert_eq!(code, 200, "{forme} : export servi : {b}");
            let lignes = serde_json::from_str::<Value>(&b).ok().and_then(|v| v.as_array().map(|a| a.len()));
            assert_eq!(lignes, Some(5), "{forme} : les cinq valeurs gardées par le plafond : {b}");
            assert_eq!(as2_entete(&brut, "x-plume-truncated").as_deref(), Some("1"), "{forme} : le fichier est dit incomplet");
            let nom = as2_entete(&brut, "content-disposition").unwrap_or_default();
            if forme == "lisible" {
                assert!(nom.ends_with("-TRONQUE-32-lignes-manquantes.json\""), "contrôle : la route pré-agrégée a chiffré sa part : {nom}");
                assert_eq!(as2_entete(&brut, "x-plume-truncated-ecartes").as_deref(), Some("32"), "contrôle : l'ampleur chiffrée publiée");
                assert_eq!(as2_entete(&brut, "x-plume-cold-coverage"), None, "contrôle : aucun aveu de frontière non lue");
            } else {
                assert!(nom.ends_with("-TRONQUE-ampleur-inconnue.json\""), "{forme} : aucun nombre dans le nom, l'ampleur est inconnue : {nom}");
                assert_eq!(as2_entete(&brut, "x-plume-truncated-ecartes"), None, "{forme} : aucun écart chiffré sur la seule part chaude");
                assert_eq!(as2_entete(&brut, "x-plume-cold-coverage").as_deref(), Some("cold_coverage_unread"), "{forme} : la cause est nommée");
            }
        }
    }
}
