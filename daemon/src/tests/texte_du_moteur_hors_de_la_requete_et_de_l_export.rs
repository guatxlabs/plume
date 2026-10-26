// =====================================================================================
// `P10.29-l` (vague AR) — LE TEXTE DU MOTEUR NE PART PLUS AU CLIENT PAR `/api/query` NI PAR `/api/export`.
//
// LE DÉFAUT, LU SUR f5d7008c AVANT LE CORRECTIF : les neuf sites qui rendent l'échec de `run_query_ex` (ou d'une voie
// froide qui l'emprunte) servaient `bad_req(e)` — `handlers/query.rs`, keyset chaud, page offset, requête non
// paginée, export, et sous `cold_tier` keyset froid, voie vectorisée, union chaud∪froid, export froid et export
// chaud. Au rôle lecteur : le refus de l'autorisateur (« access to event.message is prohibited », qui cite aussi
// l'énoncé quand il porte sur une fonction), le message de l'UDF `regexp` (le motif soumis), le chemin d'un fichier
// froid, et une erreur d'E/S servie en 400 comme une faute de l'analyste. Un dixième site, le keyset VECTORISÉ du
// tier froid (`cold_keyset_vectorized_page`, armé par défaut), servait le même texte dans un 500 (`server_err`),
// préfixé « hot keyset (fail-closed, cohérence espace-id): ».
//
// LE REMÈDE : la CLASSE est décidée au producteur (`query_exec`, par le code rusqlite) et relue par la route
// (`query_exec::en_classant`, sur le fil de la tâche bloquante) ; `refus_de_requete` sert un 503 à phrase fixe pour
// le support, un 503 à phrase fixe distincte pour une base occupée (`SQLITE_BUSY`, `SQLITE_LOCKED`), la phrase du
// produit à l'octet (refus d'un motif par `regex_de_requete` compris), une phrase fixe pour tout autre texte du
// moteur, et le moteur, le support et la base occupée partent à une ligne `[query] WARN` qui nomme la route et le
// tenant de l'appelant. `run_query_ex` rend le même texte qu'avant à ses autres appelants.
//
// LES TÉMOINS :
// (1) `ar2_routes_chaudes_corps_et_journal` : routeur réel en sous-processus, jeton lecteur, les quatre sites du
//     build par défaut (keyset chaud, page offset, non paginé, export), chacun nominal puis par classe — support
//     (UDF `regexp` qui rend SQLITE_IOERR_READ au pas), base occupée (UDF `regexp` qui rend SQLITE_BUSY), produit
//     (interruption au premier pas : budget de temps ; motif trop long ; motif invalide), moteur (autorisateur qui
//     refuse `event.message`). Corps entiers, aucun texte du moteur dans la réponse (en-têtes compris), journal
//     `[query]` EN ENTIER ;
// (2) `ar2_deux_tenants` : mode 1, DEUX tenants réels, gestionnaires appelés au rôle lecteur, sur CHAQUE site, les
//     classes support, base occupée et moteur pour chacun des deux tenants : la ligne nomme CELUI de l'appelant,
//     l'autre tenant reste servi par sa base ;
// (3) `ar2_routes_froides_corps_et_journal` (`cold_tier`, voie vectorisée DÉSARMÉE) : union, keyset froid, export
//     froid, chacun nominal puis par classe (moteur : UDF qui rend un message d'erreur) ; l'export chaud compilé
//     sous `cold_tier` est le site joué par (1) dans ce build ;
// (3b) `ar2_voies_vectorisees_armees` (`cold_tier`, voie vectorisée ARMÉE, comme en production) : le keyset
//     vectorisé (`served_from` « hot+cold-vectorized-keyset », part chaude armée) et la fusion vectorisée
//     (« cold-vectorized-merge », part chaude `hot_partial` armée), chacun nominal puis support, base occupée,
//     produit et moteur ; puis la part froide du keyset vectorisé rendue illisible (fichiers froids écrasés) :
//     400 à phrase fixe, texte de la lecture froide au journal seulement ;
// (4) témoins du producteur : chaque classe par son code (`ar2_classes_au_producteur`, base occupée et motifs
//     refusés compris, note du motif remise à zéro et retenue à texte égal), l'ouverture ratée
//     (`ar2_ouverture_ratee_est_du_support`), la note du fil (`ar2_en_classant_ne_retient_que_sa_note`), l'égalité
//     de `code_du_support` avec le classeur privé de `sqlite_plafond` (`ar2_code_du_support_egale_celui_du_journal`) ;
// (5) `ar2_sites_tenus_par_le_source` : chaque site, bloc ENTIER, et le compte exact des formes, en complément des
//     témoins comportementaux ; (6) `ar2_phrases_fixes`.
// Pannes : `query_exec::panne_de_test_au_coeur`, qui arme UNE fois la connexion d'exécution de la base visée au
// point de passage (`run_on_conn`), compte de pagination épargné ; la demande retirée dit qu'elle a servi.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la voie vectorisée pur-froide (`cold_vectorized_try`) n'a pas de connexion
// SQLite à armer — son échec n'a pas de classe notée et sort en phrase fixe (bloc tenu par (5)) ; une erreur de
// l'hydratation froide (fichier corrompu) est rangée « moteur » (400) et non « support » (503) : sa classe se décide
// dans `cold_store`, hors de ce lot.
// =====================================================================================
mod ar2_texte_du_moteur_hors_de_la_requete {
    use super::*;
    use crate::handlers::query::{CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE, CAUSE_REQUETE_NON_SERVIE_BASE_OCCUPEE, REQUETE_REJETEE_PAR_LE_MOTEUR};
    use crate::regex_de_requete::{compiler_motif, LONGUEUR_MAX_DU_MOTIF, MESSAGE_MOTIF_TROP_LONG};
    #[cfg(feature = "cold_tier")]
    use crate::query_exec::panne_de_test_au_coeur::MESSAGE_DE_LA_PANNE_DU_MOTEUR;
    use crate::query_exec::panne_de_test_au_coeur::{demander, encore_demandee, retirer, PanneAuCoeur};
    use crate::query_exec::{en_classant, EchecDeRequete, NATURE_HORS_DU_COEUR};
    use rusqlite::functions::FunctionFlags;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const AR2_ENFANT: &str = "AR2_ENFANT_ROUTES_CHAUDES";
    const AR2_ENFANT_DEUX: &str = "AR2_ENFANT_DEUX_TENANTS";
    const AR2_ENFANT_CODES: &str = "AR2_ENFANT_CODES";
    const AR2_RENDU: &str = "AR2-RENDU:";
    const AR2_FIN: &str = "AR2-FIN:";
    const AR2_CODE: &str = "AR2-CODE";
    const AR2_ALPHA: &str = "ar2-alpha";
    const AR2_BETA: &str = "ar2-beta";
    const AR2_SOQL: &str = "search source=ar2 message=~\"ar2\"";
    /// Un motif que la bibliothèque `regex` refuse (groupe non fermé) : la saisie de l'analyste, refusée par le démon.
    const AR2_MOTIF_INVALIDE: &str = "ar2(";
    /// Ce qu'aucune réponse refusée ne doit porter, en-têtes compris : les textes et natures du moteur joués ici.
    const TRACES_DU_MOTEUR: [&str; 8] = ["prohibited", "disk I/O", "code SQLite", "SQLITE", "event.message", "panne de test", "not authorized", "regexp"];
    /// Les quatre sites du build par défaut : (nom, route, corps de requête au-delà de soql/from/to).
    const AR2_SITES_CHAUDS: [(&str, &str); 4] =
        [("keyset_chaud", "/api/query"), ("page_offset", "/api/query"), ("non_pagine", "/api/query"), ("export", "/api/export")];

    fn ar2_corps(site: &str, soql: &str, depuis: i64, jusqua: i64) -> Value {
        let mut b = json!({ "soql": soql, "from": depuis, "to": jusqua });
        match site {
            "keyset_chaud" | "keyset_froid" => {
                b["limit"] = json!(10);
                b["keyset"] = json!(true);
            }
            "page_offset" => b["limit"] = json!(10),
            "export" | "export_froid" => b["format"] = json!("json"),
            _ => {}
        }
        b
    }

    fn ar2_route(site: &str) -> &'static str {
        if site.starts_with("export") {
            "/api/export"
        } else {
            "/api/query"
        }
    }

    /// Les connexions au repos de la base sont fermées : une connexion armée ne sert jamais deux fois.
    fn ar2_vider_le_pool(chemin: &str) {
        while crate::query_exec::connexions_de_lecture_au_repos(chemin) > 0 {
            drop(crate::query_exec::read_conn_get(chemin).expect("fixture : connexion au repos"));
        }
    }

    /// POST par le routeur réel : (statut, corps, réponse brute en-têtes compris).
    async fn ar2_envoi(addr: std::net::SocketAddr, route: &str, authz: &str, corps: &Value) -> (u16, String, String) {
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

    /// La nature qu'un échec laisse au journal : son code SQLite, jamais son message.
    fn ar2_nature(e: &rusqlite::Error) -> String {
        match e {
            rusqlite::Error::SqliteFailure(f, _) => format!("code SQLite {} ({:?})", f.extended_code, f.code),
            autre => panic!("instrument : erreur sans code SQLite : {autre}"),
        }
    }

    /// Une fonction scalaire qui rend, au pas, le code passé en argument (sans message : le code reste le sien).
    fn ar2_fonction_d_erreur(c: &Connection) {
        c.create_scalar_function("ar2_erreur", 1, FunctionFlags::SQLITE_UTF8, |ctx| -> rusqlite::Result<i64> {
            Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(ctx.get::<i32>(0)?), None))
        })
        .expect("instrument : fonction d'erreur");
    }

    /// L'erreur d'E/S que la panne `ErreurDuSupport` fait rendre au pas, REPRODUITE en mémoire.
    fn ar2_erreur_d_e_s() -> rusqlite::Error {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        ar2_fonction_d_erreur(&c);
        let e = c.query_row(&format!("SELECT ar2_erreur({})", rusqlite::ffi::SQLITE_IOERR_READ), [], |r| r.get::<_, i64>(0)).err();
        e.expect("instrument : l'erreur d'E/S est rendue au pas")
    }

    /// Le refus que la panne `RefusDeLAutorisateur` fait rendre (lecture d'`event.message`), REPRODUIT en mémoire.
    fn ar2_refus_de_message() -> rusqlite::Error {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        c.execute_batch("CREATE TABLE event(message TEXT);").expect("instrument : table");
        c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "event" && column_name == "message" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        c.prepare("SELECT message FROM event").err().expect("instrument : le refus de event.message a lieu")
    }

    /// L'erreur que la panne `ErreurDuMoteur` fait rendre au pas (UDF qui écrit un message), REPRODUITE en mémoire.
    #[cfg(feature = "cold_tier")]
    fn ar2_erreur_de_l_udf() -> rusqlite::Error {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        c.create_scalar_function("ar2_udf", 0, FunctionFlags::SQLITE_UTF8, |_ctx| -> rusqlite::Result<i64> {
            Err(rusqlite::Error::UserFunctionError(MESSAGE_DE_LA_PANNE_DU_MOTEUR.into()))
        })
        .expect("instrument : udf");
        c.query_row("SELECT ar2_udf()", [], |r| r.get::<_, i64>(0)).err().expect("instrument : l'UDF échoue")
    }

    /// La ligne du support : la nature et l'identifiant servi, jamais le texte (une ouverture ratée y citerait le chemin).
    fn ar2_ligne_support(route: &str, tenant: &str, id: &str) -> String {
        format!("[query] WARN requête non servie, erreur du support de la base ({route}, tenant '{tenant}', {id}) : {}", ar2_nature(&ar2_erreur_d_e_s()))
    }

    /// L'erreur que la panne `BaseOccupee` fait rendre au pas, REPRODUITE en mémoire.
    fn ar2_erreur_occupee() -> rusqlite::Error {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        ar2_fonction_d_erreur(&c);
        let e = c.query_row(&format!("SELECT ar2_erreur({})", rusqlite::ffi::SQLITE_BUSY), [], |r| r.get::<_, i64>(0)).err();
        e.expect("instrument : la base occupée est rendue au pas")
    }

    /// La ligne de la base occupée : la nature et l'identifiant servi, jamais le texte.
    fn ar2_ligne_occupee(route: &str, tenant: &str, id: &str) -> String {
        format!("[query] WARN requête non servie, base occupée ({route}, tenant '{tenant}', {id}) : {}", ar2_nature(&ar2_erreur_occupee()))
    }

    /// Les deux saisies de motif refusées par le démon, et la phrase exacte que chacune doit rendre.
    fn ar2_motifs_refuses() -> [(&'static str, String, String); 2] {
        let long = "a".repeat(LONGUEUR_MAX_DU_MOTIF + 1);
        let phrase_invalide = compiler_motif(AR2_MOTIF_INVALIDE).err().expect("instrument : motif invalide refusé").en_erreur_udf().to_string();
        [
            ("motif_long", format!("search source=ar2 message=~\"{long}\""), MESSAGE_MOTIF_TROP_LONG.to_string()),
            ("motif_invalide", format!("search source=ar2 message=~\"{AR2_MOTIF_INVALIDE}\""), phrase_invalide),
        ]
    }

    fn ar2_ligne_moteur(route: &str, tenant: &str, e: &rusqlite::Error) -> String {
        format!("[query] WARN requête rejetée par le moteur ({route}, tenant '{tenant}') : {} : {:?}", ar2_nature(e), e.to_string())
    }

    fn ar2_semer(conn: &Connection, ts: i64) {
        conn.execute(
            "INSERT INTO event(ts,source,severity,message,host,src_ip) VALUES(?1,'ar2',1,'ar2-sonde','ar2-h',NULL)",
            params![ts],
        )
        .expect("fixture : événement");
    }

    type Ar2Rendus = Vec<(String, String, u16, String, String)>;

    /// La partie jouée par l'enfant (mode 0) : chaque site, nominal puis une panne par classe.
    async fn ar2_jouer_routes_chaudes() -> Ar2Rendus {
        let (st, _base) = router_test_state("ar2-routes");
        let chemin = st.db_path.as_ref().clone();
        let maintenant = now();
        ar2_semer(&st.db.lock(), maintenant - 60);
        let addr = router_serve(st.clone()).await;
        let lecteur = viewer_authz();
        let mut rendus: Ar2Rendus = Vec::new();
        for (site, route) in AR2_SITES_CHAUDS {
            let corps = ar2_corps(site, AR2_SOQL, maintenant - 3600, maintenant + 3600);
            let (c, b, brut) = ar2_envoi(addr, route, &lecteur, &corps).await;
            rendus.push((site.into(), "nominal".into(), c, b, brut));
            for (issue, soql, _) in ar2_motifs_refuses() {
                let (c, b, brut) = ar2_envoi(addr, route, &lecteur, &ar2_corps(site, &soql, maintenant - 3600, maintenant + 3600)).await;
                rendus.push((site.into(), issue.into(), c, b, brut));
            }
            for (issue, panne) in [
                ("support", PanneAuCoeur::ErreurDuSupport),
                ("occupee", PanneAuCoeur::BaseOccupee),
                ("produit", PanneAuCoeur::Interruption),
                ("moteur", PanneAuCoeur::RefusDeLAutorisateur),
            ] {
                ar2_vider_le_pool(&chemin);
                demander(&chemin, panne);
                let (c, b, brut) = ar2_envoi(addr, route, &lecteur, &corps).await;
                let issue = if encore_demandee(&chemin) {
                    retirer(&chemin);
                    format!("{issue}:panne_non_armee")
                } else {
                    issue.to_string()
                };
                ar2_vider_le_pool(&chemin);
                rendus.push((site.into(), issue, c, b, brut));
            }
        }
        rendus
    }

    fn ar2_lire_les_rendus(stdout: &str) -> Ar2Rendus {
        stdout
            .lines()
            .filter_map(|l| l.split_once(AR2_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : ligne de rendu lisible ({e}) : {v}")))
            .collect()
    }

    /// Le bras du parent : `enfant` est la commande que le TEST a construite (binaire courant et variable du bras
    /// de l'enfant posés dans son propre corps, protocole de ré-exécution) ; elle est jouée sur ce seul test.
    fn ar2_lancer_l_enfant(mut enfant: std::process::Command, test: &str) -> (String, String) {
        let sortie = enfant.args(["--exact", "--nocapture", "--test-threads=1", test]).output().expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        (stdout, stderr)
    }

    fn ar2_journal(stderr: &str) -> Vec<String> {
        stderr.lines().filter(|l| l.starts_with("[query] ")).map(str::to_string).collect()
    }

    fn ar2_phrase_du_budget(budget_ms: u64) -> String {
        format!("requête interrompue (budget {} s dépassé)", budget_ms / 1000)
    }

    /// Le refus du support : 503, `{error, id}` exactement, la phrase fixe, et l'identifiant rendu.
    fn ar2_refus_du_support(contexte: &str, code: u16, corps: &str) -> String {
        let v: Value = serde_json::from_str(corps).unwrap_or(Value::Null);
        assert_eq!(code, 503, "{contexte} : statut du support");
        let mut cles: Vec<&String> = v.as_object().map(|o| o.keys().collect()).unwrap_or_default();
        cles.sort();
        assert_eq!(cles, vec!["error", "id"], "{contexte} : exactement `error` et `id` : {v}");
        assert_eq!(v["error"], json!(CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE), "{contexte} : la phrase fixe du support");
        let id = v["id"].as_str().unwrap_or_default().to_string();
        assert!(id.starts_with("plume-e"), "{contexte} : identifiant de corrélation : {v}");
        id
    }

    /// Le refus de la base occupée : 503, `{error, id}` exactement, SA phrase fixe, et l'identifiant rendu.
    fn ar2_refus_occupee(contexte: &str, code: u16, corps: &str) -> String {
        let v: Value = serde_json::from_str(corps).unwrap_or(Value::Null);
        assert_eq!(code, 503, "{contexte} : statut de la base occupée");
        let mut cles: Vec<&String> = v.as_object().map(|o| o.keys().collect()).unwrap_or_default();
        cles.sort();
        assert_eq!(cles, vec!["error", "id"], "{contexte} : exactement `error` et `id` : {v}");
        assert_eq!(v["error"], json!(CAUSE_REQUETE_NON_SERVIE_BASE_OCCUPEE), "{contexte} : la phrase fixe de la base occupée");
        let id = v["id"].as_str().unwrap_or_default().to_string();
        assert!(id.starts_with("plume-e"), "{contexte} : identifiant de corrélation : {v}");
        id
    }

    /// (1) LES QUATRE SITES DU BUILD PAR DÉFAUT, PAR LA ROUTE, AU RÔLE LECTEUR.
    #[tokio::test]
    async fn ar2_routes_chaudes_corps_et_journal() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        if std::env::var(AR2_ENFANT).is_ok() {
            let rendus = ar2_jouer_routes_chaudes().await;
            for r in &rendus {
                println!("{AR2_RENDU}{}", json!([r.0, r.1, r.2, r.3, r.4]));
            }
            println!("{AR2_FIN} {}", rendus.len());
            return;
        }
        let (stdout, stderr) = ar2_lancer_l_enfant(
            {
                let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
                enfant.env(AR2_ENFANT, "1");
                enfant
            },
            "tests::ar2_texte_du_moteur_hors_de_la_requete::ar2_routes_chaudes_corps_et_journal",
        );
        let rendus = ar2_lire_les_rendus(&stdout);
        assert!(stdout.contains(&format!("{AR2_FIN} 28")), "contrôle : quatre sites, sept issues chacun : {stdout}\n{stderr}");
        assert!(rendus.len() >= 28, "plancher : vingt-huit issues rendues ({})", rendus.len());
        let rendu = |site: &str, issue: &str| -> (u16, String, String) {
            let r = rendus.iter().find(|r| r.0 == site && r.1 == issue).unwrap_or_else(|| panic!("contrôle : {site}/{issue} joué, panne armée : {rendus:?}"));
            (r.2, r.3.clone(), r.4.clone())
        };
        let refus_moteur = ar2_refus_de_message();
        let mut attendu_journal: Vec<String> = Vec::new();
        for (site, route) in AR2_SITES_CHAUDS {
            // CONTRÔLE DU CHEMIN : le nominal prouve le site que le corps fait prendre.
            let (c, b, _) = rendu(site, "nominal");
            assert_eq!(c, 200, "contrôle : {site} nominal servi : {b}");
            if route == "/api/export" {
                let v: Value = serde_json::from_str(&b).expect("contrôle : export JSON");
                assert_eq!(v.as_array().map(|a| a.len()), Some(1), "contrôle : l'export rend la ligne semée : {b}");
            } else {
                let v: Value = serde_json::from_str(&b).expect("contrôle : réponse JSON");
                assert_eq!(v["rows"].as_array().map(|a| a.len()), Some(1), "contrôle : {site} rend la ligne semée : {b}");
                let marque = match site {
                    "keyset_chaud" => v.get("has_more").is_some() && v.get("total").is_none(),
                    "page_offset" => v.get("total").is_some() && v.get("has_more").is_none(),
                    _ => v.get("total").is_none() && v.get("has_more").is_none(),
                };
                assert!(marque, "contrôle : {site} est servi par sa voie (keyset : has_more ; offset : total ; sinon ni l'un ni l'autre) : {b}");
            }
            for issue in ["support", "occupee", "produit", "moteur"] {
                let (_, _, brut) = rendu(site, issue);
                for trace in TRACES_DU_MOTEUR {
                    assert!(!brut.contains(trace), "{site}/{issue} : la réponse porte « {trace} » : {brut}");
                }
            }
            // LE MOTIF REFUSÉ EST UNE PHRASE DU DÉMON, servie à l'octet (sans ligne au journal).
            for (issue, _, phrase) in ar2_motifs_refuses() {
                let (c, b, _) = rendu(site, issue);
                assert_eq!(
                    (c, serde_json::from_str::<Value>(&b).unwrap_or(Value::Null)),
                    (400, json!({ "error": phrase })),
                    "{site}/{issue} : la phrase du démon sur la saisie de l'analyste, à l'octet"
                );
            }
            let (c, b, _) = rendu(site, "support");
            let id = ar2_refus_du_support(&format!("{site}/support"), c, &b);
            attendu_journal.push(ar2_ligne_support(route, "default", &id));
            let (c, b, _) = rendu(site, "occupee");
            let id = ar2_refus_occupee(&format!("{site}/occupee"), c, &b);
            attendu_journal.push(ar2_ligne_occupee(route, "default", &id));
            let budget = if route == "/api/export" { crate::query_exec::query_budget_interactive_ms() } else { crate::query_exec::query_budget_ms() };
            let (c, b, _) = rendu(site, "produit");
            assert_eq!(
                (c, serde_json::from_str::<Value>(&b).unwrap_or(Value::Null)),
                (400, json!({ "error": ar2_phrase_du_budget(budget) })),
                "{site}/produit : la phrase du produit à l'octet, en 400"
            );
            let (c, b, _) = rendu(site, "moteur");
            assert_eq!(
                (c, serde_json::from_str::<Value>(&b).unwrap_or(Value::Null)),
                (400, json!({ "error": REQUETE_REJETEE_PAR_LE_MOTEUR })),
                "{site}/moteur : la phrase fixe, jamais le texte du moteur"
            );
            attendu_journal.push(ar2_ligne_moteur(route, "default", &refus_moteur));
        }
        assert_eq!(ar2_journal(&stderr), attendu_journal, "une ligne [query] EXACTE par refus du support, de la base occupée et du moteur, aucune pour le produit ni le nominal :\n{stderr}");
    }

    fn ar2_lecteur(tenant: &str) -> AuthUser {
        AuthUser { name: "lecteur-ar2".into(), role: "viewer".into(), tenant: tenant.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }

    async fn ar2_creer_le_tenant(st: &AppState, t: &str, ts: i64) -> String {
        let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-ar2")), Json(json!({ "id": t, "name": t }))).await;
        assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
        assert!(st.tenants.tenant_available(t), "contrôle : tenant {t} résolu pour le pool de lecture");
        ar2_semer(&st.tenants.handle_for(t).expect("contrôle : base du tenant").lock(), ts);
        st.tenants.ready_db_path(t).expect("contrôle : chemin de la base du tenant")
    }

    async fn ar2_appel(st: &AppState, site: &str, t: &str, corps: Value) -> (u16, String) {
        let r = if site == "export" {
            crate::handlers::query::export(State(st.clone()), Extension(ar2_lecteur(t)), Json(corps)).await
        } else {
            crate::handlers::query::query(State(st.clone()), Extension(ar2_lecteur(t)), Json(corps)).await
        };
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, String::from_utf8_lossy(&b).into_owned())
    }

    /// (2) DEUX TENANTS RÉELS, SITE PAR SITE : la ligne nomme le tenant de l'appelant.
    #[tokio::test]
    async fn ar2_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(AR2_ENFANT_DEUX).is_ok() {
            let (st, _dir) = mk_mode1_state();
            let maintenant = now();
            let alpha = ar2_creer_le_tenant(&st, AR2_ALPHA, maintenant - 60).await;
            let beta = ar2_creer_le_tenant(&st, AR2_BETA, maintenant - 60).await;
            assert_ne!(alpha, beta, "contrôle : deux bases distinctes");
            let mut rendus: Ar2Rendus = Vec::new();
            for (site, _) in AR2_SITES_CHAUDS {
                let corps = ar2_corps(site, AR2_SOQL, maintenant - 3600, maintenant + 3600);
                for (issue, panne, appelant, chemin, autre, chemin_autre) in [
                    ("support", PanneAuCoeur::ErreurDuSupport, AR2_ALPHA, &alpha, AR2_BETA, &beta),
                    ("support", PanneAuCoeur::ErreurDuSupport, AR2_BETA, &beta, AR2_ALPHA, &alpha),
                    ("occupee", PanneAuCoeur::BaseOccupee, AR2_ALPHA, &alpha, AR2_BETA, &beta),
                    ("occupee", PanneAuCoeur::BaseOccupee, AR2_BETA, &beta, AR2_ALPHA, &alpha),
                    ("moteur", PanneAuCoeur::RefusDeLAutorisateur, AR2_BETA, &beta, AR2_ALPHA, &alpha),
                    ("moteur", PanneAuCoeur::RefusDeLAutorisateur, AR2_ALPHA, &alpha, AR2_BETA, &beta),
                ] {
                    ar2_vider_le_pool(chemin);
                    demander(chemin, panne);
                    let (c, b) = ar2_appel(&st, site, appelant, corps.clone()).await;
                    let servie = !encore_demandee(chemin);
                    retirer(chemin);
                    ar2_vider_le_pool(chemin);
                    rendus.push((site.into(), format!("{issue}:{appelant}:{}", if servie { "armee" } else { "non_armee" }), c, b, String::new()));
                    let (c, b) = ar2_appel(&st, site, autre, corps.clone()).await;
                    assert!(!encore_demandee(chemin_autre), "contrôle : aucune panne demandée sur l'autre base");
                    rendus.push((site.into(), format!("nominal:{autre}"), c, b, String::new()));
                }
            }
            for r in &rendus {
                println!("{AR2_RENDU}{}", json!([r.0, r.1, r.2, r.3, r.4]));
            }
            println!("{AR2_FIN} {}", rendus.len());
            return;
        }
        let (stdout, stderr) = ar2_lancer_l_enfant(
            {
                let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
                enfant.env(AR2_ENFANT_DEUX, "1");
                enfant
            },
            "tests::ar2_texte_du_moteur_hors_de_la_requete::ar2_deux_tenants",
        );
        let rendus = ar2_lire_les_rendus(&stdout);
        assert!(stdout.contains(&format!("{AR2_FIN} 48")), "contrôle : quatre sites, douze appels chacun : {stdout}\n{stderr}");
        assert!(rendus.len() >= 48, "plancher : quarante-huit appels rendus ({})", rendus.len());
        let refus_moteur = ar2_refus_de_message();
        let mut attendu: Vec<String> = Vec::new();
        for (site, issue, code, corps, _) in &rendus {
            let route = ar2_route(site);
            let morceaux: Vec<&str> = issue.split(':').collect();
            match morceaux.as_slice() {
                ["nominal", t] => assert_eq!(*code, 200, "{site} : l'autre tenant ({t}) reste servi par sa base : {corps}"),
                ["support", t, "armee"] => {
                    let id = ar2_refus_du_support(&format!("{site}/support/{t}"), *code, corps);
                    attendu.push(ar2_ligne_support(route, t, &id));
                }
                ["occupee", t, "armee"] => {
                    let id = ar2_refus_occupee(&format!("{site}/occupee/{t}"), *code, corps);
                    attendu.push(ar2_ligne_occupee(route, t, &id));
                }
                ["moteur", t, "armee"] => {
                    assert_eq!(
                        (*code, serde_json::from_str::<Value>(corps).unwrap_or(Value::Null)),
                        (400, json!({ "error": REQUETE_REJETEE_PAR_LE_MOTEUR })),
                        "{site}/moteur/{t} : la phrase fixe"
                    );
                    attendu.push(ar2_ligne_moteur(route, t, &refus_moteur));
                }
                autre => panic!("contrôle : panne armée à chaque appel : {site} {autre:?}"),
            }
        }
        assert_eq!(attendu.len(), 24, "contrôle : vingt-quatre refus attendus au journal");
        assert_eq!(ar2_journal(&stderr), attendu, "chaque ligne [query] nomme le tenant de l'appelant, site par site :\n{stderr}");
    }

    /// (3) LES SITES FROIDS PAR LA ROUTE : union chaud∪froid, keyset froid, export froid.
    #[cfg(feature = "cold_tier")]
    const AR2_ENFANT_FROID: &str = "AR2_ENFANT_ROUTES_FROIDES";

    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn ar2_routes_froides_corps_et_journal() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write(); // le banc froid pose l'environnement
        if std::env::var(AR2_ENFANT_FROID).is_ok() {
            let banc = BancFroidSurLaRoute::monter("ar2-froid", false).await;
            banc.vieillir();
            let soql = "search source=froid message=~\"ligne\"";
            let mut rendus: Ar2Rendus = Vec::new();
            for site in ["union_froide", "keyset_froid", "export_froid"] {
                let corps = ar2_corps(site, soql, banc.base_froide - 60, banc.maintenant + 60);
                let route = ar2_route(site);
                let (c, b, brut) = ar2_envoi(banc.addr, route, &banc.authz, &corps).await;
                rendus.push((site.into(), "nominal".into(), c, b, brut));
                for (issue, panne) in [
                    ("support", PanneAuCoeur::ErreurDuSupport),
                    ("produit", PanneAuCoeur::Interruption),
                    ("moteur", PanneAuCoeur::ErreurDuMoteur),
                ] {
                    ar2_vider_le_pool(&banc.chemin_base);
                    demander(&banc.chemin_base, panne);
                    let (c, b, brut) = ar2_envoi(banc.addr, route, &banc.authz, &corps).await;
                    let issue = if encore_demandee(&banc.chemin_base) {
                        retirer(&banc.chemin_base);
                        format!("{issue}:panne_non_armee")
                    } else {
                        issue.to_string()
                    };
                    ar2_vider_le_pool(&banc.chemin_base);
                    rendus.push((site.into(), issue, c, b, brut));
                }
            }
            for r in &rendus {
                println!("{AR2_RENDU}{}", json!([r.0, r.1, r.2, r.3, r.4]));
            }
            println!("{AR2_FIN} {}", rendus.len());
            return;
        }
        let (stdout, stderr) = ar2_lancer_l_enfant(
            {
                let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
                enfant.env(AR2_ENFANT_FROID, "1");
                enfant
            },
            "tests::ar2_texte_du_moteur_hors_de_la_requete::ar2_routes_froides_corps_et_journal",
        );
        let rendus = ar2_lire_les_rendus(&stdout);
        assert!(stdout.contains(&format!("{AR2_FIN} 12")), "contrôle : trois sites froids, quatre issues chacun : {stdout}\n{stderr}");
        assert!(rendus.len() >= 12, "plancher : douze issues rendues ({})", rendus.len());
        let rendu = |site: &str, issue: &str| -> (u16, String, String) {
            let r = rendus.iter().find(|r| r.0 == site && r.1 == issue).unwrap_or_else(|| panic!("contrôle : {site}/{issue} joué, panne armée : {rendus:?}"));
            (r.2, r.3.clone(), r.4.clone())
        };
        let erreur_udf = ar2_erreur_de_l_udf();
        let mut attendu_journal: Vec<String> = Vec::new();
        for site in ["union_froide", "keyset_froid", "export_froid"] {
            let route = ar2_route(site);
            let (c, b, _) = rendu(site, "nominal");
            assert_eq!(c, 200, "contrôle : {site} nominal servi : {b}");
            if route == "/api/query" {
                let v: Value = serde_json::from_str(&b).expect("contrôle : réponse JSON");
                assert!(v["stats"].get("cold").is_some(), "contrôle : {site} est servi par l'union chaud∪froid : {b}");
            }
            for issue in ["support", "produit", "moteur"] {
                let (_, _, brut) = rendu(site, issue);
                for trace in TRACES_DU_MOTEUR {
                    assert!(!brut.contains(trace), "{site}/{issue} : la réponse porte « {trace} » : {brut}");
                }
            }
            let (c, b, _) = rendu(site, "support");
            let id = ar2_refus_du_support(&format!("{site}/support"), c, &b);
            attendu_journal.push(ar2_ligne_support(route, "default", &id));
            let budget = if route == "/api/export" { crate::query_exec::query_budget_interactive_ms() } else { crate::query_exec::query_budget_ms() };
            let (c, b, _) = rendu(site, "produit");
            assert_eq!(
                (c, serde_json::from_str::<Value>(&b).unwrap_or(Value::Null)),
                (400, json!({ "error": ar2_phrase_du_budget(budget) })),
                "{site}/produit : la phrase du produit à l'octet"
            );
            let (c, b, _) = rendu(site, "moteur");
            assert_eq!(
                (c, serde_json::from_str::<Value>(&b).unwrap_or(Value::Null)),
                (400, json!({ "error": REQUETE_REJETEE_PAR_LE_MOTEUR })),
                "{site}/moteur : la phrase fixe"
            );
            attendu_journal.push(ar2_ligne_moteur(route, "default", &erreur_udf));
        }
        assert_eq!(ar2_journal(&stderr), attendu_journal, "les sites froids journalisent comme les chauds :\n{stderr}");
    }

    /// (3b) LES VOIES VECTORISÉES ARMÉES (le défaut de production, `PLUME_COLD_VECTORIZED=1`).
    #[cfg(feature = "cold_tier")]
    const AR2_ENFANT_VECTORISE: &str = "AR2_ENFANT_VOIES_VECTORISEES";
    #[cfg(feature = "cold_tier")]
    const AR2_TEXTE_FROID: &str = "AR2-TEXTE-FROID:";
    #[cfg(feature = "cold_tier")]
    const AR2_SOQL_FROID: &str = "search source=froid message=~\"ligne\"";
    #[cfg(feature = "cold_tier")]
    const AR2_SOQL_FROID_COMPTE: &str = "search source=froid message=~\"ligne\" | stats count";

    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn ar2_voies_vectorisees_armees() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write(); // le banc froid pose l'environnement
        if std::env::var(AR2_ENFANT_VECTORISE).is_ok() {
            let banc = BancFroidSurLaRoute::monter("ar2-vectorise", true).await;
            banc.vieillir();
            let (depuis, jusqua) = (banc.base_froide - 60, banc.maintenant + 60);
            let mut rendus: Ar2Rendus = Vec::new();
            let mut frontiere: Option<i64> = None;
            for (site, corps) in [
                ("keyset_vectorise", json!({ "soql": AR2_SOQL_FROID, "from": depuis, "to": jusqua, "limit": 10, "keyset": true })),
                ("merge_vectorise", json!({ "soql": AR2_SOQL_FROID_COMPTE, "from": depuis, "to": jusqua })),
            ] {
                let (c, b, brut) = ar2_envoi(banc.addr, "/api/query", &banc.authz, &corps).await;
                if site == "keyset_vectorise" {
                    frontiere = serde_json::from_str::<Value>(&b).ok().and_then(|v| v["stats"]["cold"]["boundary_ts"].as_i64());
                }
                rendus.push((site.into(), "nominal".into(), c, b, brut));
                for (issue, panne) in [
                    ("support", PanneAuCoeur::ErreurDuSupport),
                    ("occupee", PanneAuCoeur::BaseOccupee),
                    ("produit", PanneAuCoeur::Interruption),
                    ("moteur", PanneAuCoeur::ErreurDuMoteur),
                ] {
                    ar2_vider_le_pool(&banc.chemin_base);
                    demander(&banc.chemin_base, panne);
                    let (c, b, brut) = ar2_envoi(banc.addr, "/api/query", &banc.authz, &corps).await;
                    let issue = if encore_demandee(&banc.chemin_base) {
                        retirer(&banc.chemin_base);
                        format!("{issue}:panne_non_armee")
                    } else {
                        issue.to_string()
                    };
                    ar2_vider_le_pool(&banc.chemin_base);
                    rendus.push((site.into(), issue, c, b, brut));
                }
            }
            // LA PART FROIDE DU KEYSET VECTORISÉ RENDUE ILLISIBLE : chaque fichier sous la racine froide est écrasé
            // (fichiers de la fixture, jamais la base vivante). Le texte que la lecture froide rend est relevé au
            // producteur, par l'appel que la page fait (`cold_keyset_page`), pour juger la ligne du journal entière.
            let mut a_ecraser = vec![std::path::PathBuf::from(format!("{}.cold", banc.chemin_base))];
            let mut ecrases = 0;
            while let Some(d) = a_ecraser.pop() {
                for entree in std::fs::read_dir(&d).expect("fixture : racine froide lisible") {
                    let chemin = entree.expect("fixture : entrée de la racine froide lisible").path();
                    if chemin.is_dir() {
                        a_ecraser.push(chemin);
                    } else {
                        let taille = std::fs::metadata(&chemin).expect("fixture : taille du fichier froid").len() as usize;
                        std::fs::write(&chemin, vec![0x5a_u8; taille.max(64)]).expect("fixture : fichier froid écrasé");
                        ecrases += 1;
                    }
                }
            }
            println!("{AR2_TEXTE_FROID}{}", json!({ "ecrases": ecrases, "frontiere": frontiere }));
            let corps = json!({ "soql": AR2_SOQL_FROID, "from": depuis, "to": jusqua, "limit": 10, "keyset": true });
            let (c, b, brut) = ar2_envoi(banc.addr, "/api/query", &banc.authz, &corps).await;
            rendus.push(("keyset_vectorise".into(), "froid_illisible".into(), c, b, brut));
            let texte = frontiere.and_then(|f| {
                crate::cold_store::cold_keyset_page(&banc.chemin_base, &banc.conf, None, depuis, jusqua, f, AR2_SOQL_FROID, true, None, 9, &[]).err()
            });
            println!("{AR2_TEXTE_FROID}{}", json!({ "texte": texte }));
            for r in &rendus {
                println!("{AR2_RENDU}{}", json!([r.0, r.1, r.2, r.3, r.4]));
            }
            println!("{AR2_FIN} {}", rendus.len());
            return;
        }
        let (stdout, stderr) = ar2_lancer_l_enfant(
            {
                let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
                enfant.env(AR2_ENFANT_VECTORISE, "1");
                enfant
            },
            "tests::ar2_texte_du_moteur_hors_de_la_requete::ar2_voies_vectorisees_armees",
        );
        let rendus = ar2_lire_les_rendus(&stdout);
        assert!(stdout.contains(&format!("{AR2_FIN} 11")), "contrôle : deux voies, cinq issues chacune, plus la part froide illisible : {stdout}\n{stderr}");
        assert!(rendus.len() >= 11, "plancher : onze issues rendues ({})", rendus.len());
        let rendu = |site: &str, issue: &str| -> (u16, String, String) {
            let r = rendus.iter().find(|r| r.0 == site && r.1 == issue).unwrap_or_else(|| panic!("contrôle : {site}/{issue} joué, panne armée : {rendus:?}"));
            (r.2, r.3.clone(), r.4.clone())
        };
        let releves: Vec<Value> = stdout.lines().filter_map(|l| l.split_once(AR2_TEXTE_FROID)).map(|(_, v)| serde_json::from_str(v).expect("contrôle : relevé lisible")).collect();
        assert_eq!(releves.len(), 2, "contrôle : deux relevés de la part froide : {stdout}");
        assert!(releves[0]["ecrases"].as_i64().unwrap_or(0) >= 1, "contrôle : au moins un fichier froid écrasé : {}", releves[0]);
        assert!(releves[0]["frontiere"].as_i64().is_some(), "contrôle : la frontière lue sur la page nominale : {}", releves[0]);
        let texte_froid = releves[1]["texte"].as_str().unwrap_or_else(|| panic!("contrôle : la lecture froide échoue au producteur : {}", releves[1])).to_string();
        let erreur_udf = ar2_erreur_de_l_udf();
        let mut attendu_journal: Vec<String> = Vec::new();
        for (site, voie, ou) in [("keyset_vectorise", "hot+cold-vectorized-keyset", "cold"), ("merge_vectorise", "cold-vectorized-merge", "")] {
            // CONTRÔLE DU CHEMIN : la page nominale est servie par la voie vectorisée visée.
            let (c, b, _) = rendu(site, "nominal");
            assert_eq!(c, 200, "contrôle : {site} nominal servi : {b}");
            let v: Value = serde_json::from_str(&b).expect("contrôle : réponse JSON");
            let servie = if ou.is_empty() { v["stats"]["served_from"].clone() } else { v["stats"][ou]["served_from"].clone() };
            assert_eq!(servie, json!(voie), "contrôle : {site} est servi par la voie vectorisée armée : {b}");
            for issue in ["support", "occupee", "produit", "moteur"] {
                let (_, _, brut) = rendu(site, issue);
                for trace in TRACES_DU_MOTEUR.iter().chain(["hot keyset"].iter()) {
                    assert!(!brut.contains(trace), "{site}/{issue} : la réponse porte « {trace} » : {brut}");
                }
            }
            let (c, b, _) = rendu(site, "support");
            let id = ar2_refus_du_support(&format!("{site}/support"), c, &b);
            attendu_journal.push(ar2_ligne_support("/api/query", "default", &id));
            let (c, b, _) = rendu(site, "occupee");
            let id = ar2_refus_occupee(&format!("{site}/occupee"), c, &b);
            attendu_journal.push(ar2_ligne_occupee("/api/query", "default", &id));
            let (c, b, _) = rendu(site, "produit");
            assert_eq!(
                (c, serde_json::from_str::<Value>(&b).unwrap_or(Value::Null)),
                (400, json!({ "error": ar2_phrase_du_budget(crate::query_exec::query_budget_ms()) })),
                "{site}/produit : la phrase du produit à l'octet"
            );
            let (c, b, _) = rendu(site, "moteur");
            assert_eq!(
                (c, serde_json::from_str::<Value>(&b).unwrap_or(Value::Null)),
                (400, json!({ "error": REQUETE_REJETEE_PAR_LE_MOTEUR })),
                "{site}/moteur : la phrase fixe, jamais un 500 qui porte le texte"
            );
            attendu_journal.push(ar2_ligne_moteur("/api/query", "default", &erreur_udf));
        }
        let (c, b, brut) = rendu("keyset_vectorise", "froid_illisible");
        assert_eq!(
            (c, serde_json::from_str::<Value>(&b).unwrap_or(Value::Null)),
            (400, json!({ "error": REQUETE_REJETEE_PAR_LE_MOTEUR })),
            "keyset_vectorise/froid_illisible : la phrase fixe, jamais le texte de la lecture froide"
        );
        assert!(!brut.contains(&texte_froid), "keyset_vectorise/froid_illisible : la réponse porte le texte de la lecture froide : {brut}");
        attendu_journal.push(format!("[query] WARN requête rejetée par le moteur (/api/query, tenant 'default') : {NATURE_HORS_DU_COEUR} : {texte_froid:?}"));
        assert_eq!(ar2_journal(&stderr), attendu_journal, "les voies vectorisées journalisent comme les autres sites :\n{stderr}");
    }

    /// Exécute `sql` sur `c` par `run_on_conn`, classé, et rend aussi le texte NON classé d'un second appel.
    fn ar2_classer(c: &Connection, sql: &str) -> (EchecDeRequete, String) {
        let classe = en_classant(|| crate::query_exec::run_on_conn(c, ":memory:ar2-classes", sql, 600_000, None)).expect_err("l'exécution échoue");
        let texte = crate::query_exec::run_on_conn(c, ":memory:ar2-classes", sql, 600_000, None).expect_err("l'exécution échoue");
        (classe, texte)
    }

    /// (4a) CHAQUE CLASSE PAR SON CODE, AU PRODUCTEUR, ET LE TEXTE D'AVANT POUR LES AUTRES APPELANTS.
    #[test]
    fn ar2_classes_au_producteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // le refus mémoire lit le plafond dans l'environnement
        let c = Connection::open_in_memory().expect("base d'épreuve");
        ar2_fonction_d_erreur(&c);
        let supports = [
            rusqlite::ffi::SQLITE_IOERR_READ,
            rusqlite::ffi::SQLITE_CORRUPT,
            rusqlite::ffi::SQLITE_FULL,
            rusqlite::ffi::SQLITE_CANTOPEN,
            rusqlite::ffi::SQLITE_NOTADB,
            rusqlite::ffi::SQLITE_PROTOCOL,
        ];
        let mut vus = 0;
        for code in supports {
            let (classe, texte) = ar2_classer(&c, &format!("SELECT ar2_erreur({code})"));
            let e = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
            match &classe {
                EchecDeRequete::Support { nature, texte: t } => {
                    assert_eq!(nature, &ar2_nature(&e), "nature du code {code}");
                    assert_eq!(t, &texte, "le texte d'avant, inchangé, code {code}");
                }
                autre => panic!("le code {code} accuse le support : {autre:?}"),
            }
            vus += 1;
        }
        assert_eq!(vus, 6, "plancher : les six codes du support joués");
        // `P10.29-l` (vague AR, correction) — INVERSÉ : BUSY était classé moteur (« syntaxe, champ, motif ou accès
        // rejeté »). Une base occupée n'est ni une faute de la requête ni une panne du support : classe à part, par
        // le code primaire (codes étendus compris).
        let occupees = [rusqlite::ffi::SQLITE_BUSY, rusqlite::ffi::SQLITE_LOCKED, rusqlite::ffi::SQLITE_BUSY_SNAPSHOT, rusqlite::ffi::SQLITE_LOCKED_SHAREDCACHE];
        let mut vus = 0;
        for code in occupees {
            let (classe, texte) = ar2_classer(&c, &format!("SELECT ar2_erreur({code})"));
            let e = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
            assert_eq!(classe, EchecDeRequete::Occupee { nature: ar2_nature(&e), texte }, "le code {code} dit une base occupée");
            vus += 1;
        }
        assert_eq!(vus, 4, "plancher : les quatre codes d'une base occupée joués");
        // Un code ni du support ni d'une base occupée reste du moteur : syntaxe, type incompatible, valeur trop grosse.
        for code in [rusqlite::ffi::SQLITE_MISMATCH, rusqlite::ffi::SQLITE_TOOBIG] {
            let (classe, texte) = ar2_classer(&c, &format!("SELECT ar2_erreur({code})"));
            let e = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
            assert_eq!(classe, EchecDeRequete::Moteur { nature: ar2_nature(&e), texte }, "le code {code} reste du moteur");
        }
        let (classe, texte) = ar2_classer(&c, "SELEC 1");
        assert!(matches!(&classe, EchecDeRequete::Moteur { nature, texte: t } if nature.starts_with("code SQLite 1 ") && t == &texte), "syntaxe : moteur : {classe:?}");
        // Le produit : refus mémoire (IOERR_NOMEM converti en SQLITE_NOMEM par SQLite), lecture seule, budget.
        let (classe, texte) = ar2_classer(&c, &format!("SELECT ar2_erreur({})", rusqlite::ffi::SQLITE_IOERR_NOMEM));
        assert!(
            matches!(&classe, EchecDeRequete::Produit(p) if p == &texte && (p.contains("budget mémoire dépassé") || p.contains("mémoire épuisée"))),
            "refus mémoire : produit : {classe:?}"
        );
        let (classe, _) = ar2_classer(&c, "CREATE TABLE ar2_t(a)");
        assert_eq!(classe, EchecDeRequete::Produit("seules les requêtes en lecture (SELECT/WITH) sont autorisées".into()), "lecture seule : produit");
        c.progress_handler(1, Some(|| true));
        let classe = en_classant(|| crate::query_exec::run_on_conn(&c, ":memory:ar2-classes", "SELECT 1", 7_000, None)).expect_err("interrompue");
        c.progress_handler(1, None::<fn() -> bool>);
        assert_eq!(classe, EchecDeRequete::Produit(ar2_phrase_du_budget(7_000)), "interruption : produit (budget)");
    }

    /// (4a') LE MOTIF REFUSÉ PAR LE DÉMON EST DU PRODUIT, PAR LA NOTE DE L'UDF : la phrase exacte, remise à zéro à chaque
    /// énoncé, retenue seulement à texte égal ; la même phrase écrite par une autre UDF reste du moteur.
    #[test]
    fn ar2_motif_refuse_au_producteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let c = Connection::open_in_memory().expect("base d'épreuve");
        crate::query_exec::install_query_udfs(&c);
        let long = "a".repeat(LONGUEUR_MAX_DU_MOTIF + 1);
        let (classe, texte) = ar2_classer(&c, &format!("SELECT regexp('{long}', 'x')"));
        assert_eq!((classe, texte), (EchecDeRequete::Produit(MESSAGE_MOTIF_TROP_LONG.into()), MESSAGE_MOTIF_TROP_LONG.to_string()), "motif trop long : produit, texte d'avant");
        let invalide = compiler_motif(AR2_MOTIF_INVALIDE).err().expect("instrument : motif invalide").en_erreur_udf().to_string();
        let (classe, texte) = ar2_classer(&c, &format!("SELECT regexp('{AR2_MOTIF_INVALIDE}', 'x')"));
        assert_eq!((classe, texte), (EchecDeRequete::Produit(invalide.clone()), invalide), "motif invalide : produit, texte d'avant");
        // Une autre UDF qui écrit LA MÊME phrase sans passer par le refus du motif.
        let imitation = Connection::open_in_memory().expect("base d'épreuve");
        imitation
            .create_scalar_function("ar2_imite", 0, FunctionFlags::SQLITE_UTF8, |_ctx| -> rusqlite::Result<i64> {
                Err(rusqlite::Error::UserFunctionError(MESSAGE_MOTIF_TROP_LONG.into()))
            })
            .expect("instrument : udf");
        // Note LAISSÉE hors de `run_on_conn` sur ce fil (UDF jouée directement) : la remise à zéro de l'énoncé suivant
        // l'efface, l'imitation reste du moteur.
        assert!(c.query_row(&format!("SELECT regexp('{long}', 'x')"), [], |r| r.get::<_, i64>(0)).is_err(), "contrôle : refus joué hors du cœur");
        let (classe, _) = ar2_classer(&imitation, "SELECT ar2_imite()");
        assert!(matches!(&classe, EchecDeRequete::Moteur { texte, .. } if texte == MESSAGE_MOTIF_TROP_LONG), "note d'un énoncé précédent : moteur : {classe:?}");
        // Note posée, échec d'un AUTRE texte : la note n'est pas retenue.
        assert!(c.query_row(&format!("SELECT regexp('{long}', 'x')"), [], |r| r.get::<_, i64>(0)).is_err(), "contrôle : refus joué hors du cœur");
        let autre = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR), Some("ar2-autre-texte".into()));
        assert!(matches!(EchecDeRequete::du_moteur(&autre), EchecDeRequete::Moteur { texte, .. } if texte == "ar2-autre-texte"), "texte différent de la note : moteur");
    }

    /// (4b) L'OUVERTURE RATÉE EST DU SUPPORT : le point d'entrée que la route appelle (`run_query_ex`).
    #[test]
    fn ar2_ouverture_ratee_est_du_support() {
        let dir = crate::tmp_possede::TmpPossede::neuf("ar2-ouverture");
        let absente = dir.sous("absente.db").as_str().to_string();
        let texte = crate::query_exec::run_query_ex(&absente, "SELECT 1", 2_000, None).expect_err("base absente");
        let classe = en_classant(|| crate::query_exec::run_query_ex(&absente, "SELECT 1", 2_000, None)).expect_err("base absente");
        let attendu = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN), None);
        assert_eq!(classe, EchecDeRequete::Support { nature: ar2_nature(&attendu), texte: texte.clone() }, "ouverture : support, texte d'avant");
        assert!(texte.starts_with("unable to open database file"), "le texte d'avant pour les autres appelants : {texte}");
    }

    /// (4c) LA NOTE DU FIL : effacée avant l'appel, retenue seulement si son texte est celui de l'échec rendu.
    #[test]
    fn ar2_en_classant_ne_retient_que_sa_note() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let c = Connection::open_in_memory().expect("base d'épreuve");
        ar2_fonction_d_erreur(&c);
        let io = format!("SELECT ar2_erreur({})", rusqlite::ffi::SQLITE_IOERR_READ);
        assert_eq!(en_classant(|| Ok::<i64, String>(7)), Ok(7), "succès rendu tel quel");
        // Aucune note : un échec d'ailleurs est du moteur, hors du cœur.
        assert_eq!(
            en_classant(|| Err::<(), String>("ar2-ailleurs".into())),
            Err(EchecDeRequete::Moteur { nature: NATURE_HORS_DU_COEUR.into(), texte: "ar2-ailleurs".into() }),
            "échec sans note"
        );
        // Une note LAISSÉE par un appel précédent sur ce fil ne classe pas l'échec suivant, même de même texte.
        let texte_io = crate::query_exec::run_on_conn(&c, ":memory:ar2-note", &io, 600_000, None).expect_err("E/S");
        assert_eq!(
            en_classant(|| Err::<(), String>(texte_io.clone())),
            Err(EchecDeRequete::Moteur { nature: NATURE_HORS_DU_COEUR.into(), texte: texte_io.clone() }),
            "la note d'avant l'appel est effacée"
        );
        // Une note posée pendant l'appel mais d'un autre texte que l'échec rendu n'est pas retenue.
        let classe = en_classant(|| {
            let _ = crate::query_exec::run_on_conn(&c, ":memory:ar2-note", &io, 600_000, None);
            Err::<(), String>("ar2-autre-producteur".into())
        });
        assert_eq!(classe, Err(EchecDeRequete::Moteur { nature: NATURE_HORS_DU_COEUR.into(), texte: "ar2-autre-producteur".into() }), "texte différent : hors du cœur");
        // Contrôle : la note de l'appel lui-même est retenue.
        assert!(matches!(en_classant(|| crate::query_exec::run_on_conn(&c, ":memory:ar2-note", &io, 600_000, None)), Err(EchecDeRequete::Support { .. })), "contrôle : la note de l'appel classe");
    }

    /// (4d) `code_du_support` EST LE CLASSEUR DU JOURNAL : pour chaque code primaire, la ligne `[sqlite] erreur du
    /// support` que `sqlite_plafond::message_erreur` écrit (classeur privé) et `code_du_support` disent la même chose.
    #[test]
    fn ar2_code_du_support_egale_celui_du_journal() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(AR2_ENFANT_CODES).is_ok() {
            for code in 1..=28 {
                eprintln!("{AR2_CODE} {code}");
                let _ = crate::sqlite_plafond::message_erreur(&rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None));
            }
            return;
        }
        let (_, stderr) = ar2_lancer_l_enfant(
            {
                let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
                enfant.env(AR2_ENFANT_CODES, "1");
                enfant
            },
            "tests::ar2_texte_du_moteur_hors_de_la_requete::ar2_code_du_support_egale_celui_du_journal",
        );
        let mut courant: Option<i32> = None;
        let mut joues: Vec<i32> = Vec::new();
        let mut du_journal: Vec<i32> = Vec::new();
        for l in stderr.lines() {
            if let Some(n) = l.strip_prefix(&format!("{AR2_CODE} ")) {
                let n: i32 = n.trim().parse().expect("contrôle : code lisible");
                joues.push(n);
                courant = Some(n);
            } else if l.starts_with("[sqlite] erreur du support de la base") {
                du_journal.push(courant.expect("contrôle : une ligne du support suit un code joué"));
            }
        }
        assert!(joues.len() >= 28, "plancher : vingt-huit codes joués par l'enfant ({})", joues.len());
        let du_classeur: Vec<i32> = joues.iter().copied().filter(|n| crate::query_exec::code_du_support(rusqlite::ffi::Error::new(*n).code)).collect();
        assert!(!du_journal.is_empty(), "contrôle : le journal accuse au moins un code");
        assert_eq!(du_classeur, du_journal, "code_du_support et le classeur privé de sqlite_plafond disent le même ensemble");
    }

    /// Les blocs de la voie vectorisée, du keyset vectorisé et de la page offset, comparés EN ENTIER.
    const AR2_BLOCS: [&str; 6] = [
        "        match crate::query_exec::en_classant(|| run_query_ex(db_path, &hot_page, budget_ms, qid)) {",
        "            Err(e) => return Err(IssueKeysetVectorise::Erreur(e)),",
        "                        Ok(Err(IssueKeysetVectorise::Erreur(e))) => return refus_de_requete(e, \"/api/query\", &au.tenant),",
        "                let res = tokio::task::spawn_blocking(move || {
                    crate::query_exec::en_classant(|| {
                        if pure_cold {
                            crate::cold_store::cold_vectorized_try(&dbp, &conf, env_s.as_deref(), from, to, boundary, &rsoql, true, budget_ms, &preds)
                        } else {
                            crate::cold_store::cold_vectorized_merge_try(&dbp, &conf, env_s.as_deref(), from, to, boundary, &rsoql, true, budget_ms, qidv.as_deref(), &preds)
                        }
                    })
                })
                .await;
                match res {",
        "                    Ok(Ok(None)) => { /* non vectorisable / non routable -> fallback cold_union_query ci-dessous */ }
                    Ok(Err(e)) => return refus_de_requete(e, \"/api/query\", &au.tenant), // corruption cold -> fail-closed (comme l'oracle)
                    Err(_) => return server_err(\"exécution échouée\"),",
        "        let page_fut = tokio::task::spawn_blocking(move || crate::query_exec::en_classant(|| run_query_ex(&db_path, &off_page, budget_ms, qid2.as_deref())));",
    ];
    const AR2_REFUS_QUERY: &str = "refus_de_requete(e, \"/api/query\", &au.tenant)";
    const AR2_REFUS_EXPORT: &str = "refus_de_requete(e, \"/api/export\", &au.tenant)";

    /// Les fautes du source de `handlers/query.rs` : un bloc absent ou doublé, un compte de site qui n'est pas le
    /// sien, un `bad_req(e)` hors des deux refus du COMPILATEUR GXQL (bras ajouté avant l'appel compris).
    fn ar2_fautes_du_source(src: &str) -> Vec<String> {
        let mut fautes = Vec::new();
        for (k, b) in AR2_BLOCS.iter().enumerate() {
            if src.matches(b).count() != 1 {
                fautes.push(format!("bloc {k} absent ou doublé"));
            }
        }
        for (forme, attendu) in [(AR2_REFUS_QUERY, 7), (AR2_REFUS_EXPORT, 3), ("crate::query_exec::en_classant(", 11)] {
            let n = src.matches(forme).count();
            if n != attendu {
                fautes.push(format!("{forme} : {n} au lieu de {attendu}"));
            }
        }
        let nus: Vec<&str> = src.lines().filter(|l| l.contains("bad_req(e)") && !l.trim_start().starts_with("//")).map(str::trim).collect();
        if nus != vec!["Err(e) => return bad_req(e),", "Err(e) => return bad_req(e),"] {
            fautes.push(format!("`bad_req(e)` hors des deux refus du compilateur : {nus:?}"));
        }
        fautes
    }

    /// (5) CHAQUE SITE, ET LE COMPTE EXACT DES FORMES (en complément des témoins comportementaux), avec les contrôles
    /// HOSTILES de l'instrument : chacun des dix sites rendu à `bad_req(e)`, l'exécution vectorisée non classée, un
    /// bras `bad_req(e)` ajouté avant celui de la voie vectorisée.
    #[test]
    fn ar2_sites_tenus_par_le_source() {
        let src = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers/query.rs")).expect("handlers/query.rs lisible");
        assert_eq!(ar2_fautes_du_source(&src), Vec::<String>::new(), "le source livré");
        let mut hostiles = 0;
        for forme in [AR2_REFUS_QUERY, AR2_REFUS_EXPORT] {
            let sites: Vec<usize> = src.match_indices(forme).map(|(i, _)| i).collect();
            for i in sites {
                let mut m = src.clone();
                m.replace_range(i..i + forme.len(), "bad_req(e)");
                assert!(!ar2_fautes_du_source(&m).is_empty(), "l'instrument ne voit pas le site rendu à `bad_req(e)` (octet {i})");
                hostiles += 1;
            }
        }
        assert_eq!(hostiles, 10, "plancher : les dix sites rendus un par un");
        let sans_classe = src.replacen("                    crate::query_exec::en_classant(|| {\n                        if pure_cold {", "                    (|| {\n                        if pure_cold {", 1);
        assert_ne!(sans_classe, src, "contrôle : la forme vectorisée existe");
        assert!(!ar2_fautes_du_source(&sans_classe).is_empty(), "l'instrument ne voit pas la voie vectorisée non classée");
        let bras_avant = src.replacen(
            "                    Ok(Ok(None)) => { /* non vectorisable",
            "                    Ok(Err(e)) if from > 0 => return bad_req(e),\n                    Ok(Ok(None)) => { /* non vectorisable",
            1,
        );
        assert_ne!(bras_avant, src, "contrôle : la forme du bras existe");
        assert!(!ar2_fautes_du_source(&bras_avant).is_empty(), "l'instrument ne voit pas un bras `bad_req(e)` ajouté avant");
    }

    /// (6) LES PHRASES FIXES : distinctes, sans mot que la console lirait comme annulation ou budget.
    #[test]
    fn ar2_phrases_fixes() {
        let phrases = [CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE, CAUSE_REQUETE_NON_SERVIE_BASE_OCCUPEE, REQUETE_REJETEE_PAR_LE_MOTEUR];
        for (i, a) in phrases.iter().enumerate() {
            for b in &phrases[i + 1..] {
                assert_ne!(a, b, "trois classes, trois phrases");
            }
        }
        for p in phrases {
            for mot in ["budget", "annulée", "interrompue", "SQLite", "prohibited"] {
                assert!(!p.contains(mot), "« {mot} » dans une phrase fixe : {p}");
            }
        }
        assert!(CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE.starts_with("REQUÊTE NON SERVIE : "), "ouverture du 503");
        assert!(CAUSE_REQUETE_NON_SERVIE_BASE_OCCUPEE.starts_with("REQUÊTE NON SERVIE : "), "ouverture du 503 de la base occupée");
    }
}
