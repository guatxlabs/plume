// =====================================================================================
// `P10.32-r` (vague AZ, reprise après vérification) — UN EXPORT DONT LA FENÊTRE EST ENTIÈREMENT FROIDE, COUPÉ À SA
// BORNE, LE DIT ; LE REFUS D'UN AGRÉGAT FROID TRONQUÉ SOUS UN EXPORT NOMME LA BORNE DE L'EXPORT.
// `P10.29-w` (restes) — UNE BASE PRISE PENDANT LE MONTAGE DE L'UNION (préparation de l'insertion, vue d'union) EST
// SERVIE « OCCUPÉE », JAMAIS « ILLISIBLE ».
//
// LES DÉFAUTS, MESURÉS PAR LE VÉRIFICATEUR SUR 3903eb8e (profil `cold_tier`) :
//  * 120 lignes froides, aucune chaude dans la fenêtre, PLUME_QUERY_MAX=50, PLUME_EXPORT_MAX=100 : 100 lignes,
//    `x-plume-truncated: 1`, mais AUCUN `x-plume-export-borne`. L'hydratation froide était plafonnée à la borne
//    (`cold_store::reader::cold_hydrate_row_cap` = plafond du fil) : l'union portait exactement 100 lignes, le cœur ne
//    voyait jamais la ligne sonde du `LIMIT borne+1`, et `borne_de_l_export_touchee` restait faux. Remède :
//    `query_exec::plafond_d_hydratation_froide_de_ce_fil` hydrate la borne PLUS UNE ligne sous un export ;
//  * `search source=froid | stats count` exporté sous les mêmes réglages : 422 dont le message disait
//    « plafond RAM PLUME_QUERY_MAX=100 » alors que la variable valait 50 (`cold_store/exactness.rs`). Remède :
//    `TruncatedAggregate::sous_la_borne_de_l_export`, posé par la route d'export, le message nomme sa borne.
//
// `P10.29-w` : `cold_store/reader.rs` laissait sur `pe` (servi « illisible ») la préparation de l'insertion dans la table
// temporaire et la vue d'union, « faute de témoin déterministe ». Mesuré ici : ces énoncés n'écrivent que la base
// TEMPORAIRE et ne prennent aucun verrou sur la base partagée. Un écrivain qui prend la base en verrou EXCLUSIF au point
// exact de chacune de ces étapes (crochet de test `query_exec::crochet_de_l_union_froide`, base passée en journal de
// rollback, où ce verrou bloque tout lecteur, ce que la sonde constate) ne les fait pas échouer : l'union se
// monte, la requête de l'appelant rencontre le verrou, le cœur la classe `Occupee`, la route sert le 503 de la base
// OCCUPÉE. Les sites sont donc dits HORS D'ATTEINTE au site (`reader.rs`, étape (4)), sans changement de leur `pe`.
// (Vague BA : après la vue, le premier énoncé qui lit `main` n'est pas la requête de l'appelant mais la lecture du sel
// par `install_fmask_udf` ; son journal sous ce verrou est jugé par `occupee_n_est_pas_illisible_ba3.rs`.)
//
// MUTANTS (variable VERIF_MUT sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE :
//  AZ3_SONDE_FROIDE (hydratation sous un export plafonnée à la borne, sans la ligne sonde) (1) ;
//  AZ3_SONDE_PARTOUT (la ligne sonde ajoutée aussi hors d'un export) (1) ;
//  AZ3_MSG_QUERY_MAX (le message ignore la borne de l'export) (2) ;
//  AZ3_SANS_BORNE_NOMMEE (la route d'export ne pose pas sa borne sur le refus) (2) ;
//  AZ3W_INSERT_LIT_MAIN, AZ3W_VUE_LIT_MAIN (un énoncé sur `main` sous `pe` au point de l'étape : servi illisible) (3).
//
// CE QUE CES TÉMOINS NE TENAIENT PAS (reste de `P10.29-w`, repris en vague BA par `occupee_n_est_pas_illisible_ba3.rs`) :
// une occupation pendant la lecture du réglage de rétention (`HorizonDeLecture::lire`, `cold_store/reader.rs`, par
// `retention_effective_lue`, texte sans code) était servie « illisible ».
// =====================================================================================
#[cfg(feature = "cold_tier")]
mod az3_export_froid_coupe_a_sa_borne_et_union_occupee {
    use super::*;
    use crate::query_exec::crochet_de_l_union_froide::{armer, desarmer, Etape};

    const AZ3_LEVIERS: [&str; 2] = ["PLUME_QUERY_MAX", "PLUME_EXPORT_MAX"];
    const AZ3_ENTETE_BORNE: &str = "x-plume-export-borne";
    const AZ3_CAUSE_OCCUPEE: &str = "REQUÊTE NON SERVIE : la base est occupée (verrou tenu par une autre opération) — ce n'est PAS un résultat vide, et rien n'est rendu. Réessayez dans un instant.";
    const AZ3_PLAFOND_DE_L_EXPORT_100: &str = "(plafond de l'export : sa borne de 100 lignes (PLUME_EXPORT_MAX, ou le `limit` de la demande s'il est plus petit) et une ligne de plus qui détecte la coupure, soit 101 lignes, au-dessus de PLUME_QUERY_MAX)";

    /// Pose les leviers et remet l'état d'avant à la sortie (l'appelant tient `VERROU_ENV_PROCESSUS.write()`).
    struct Az3Env(Vec<(&'static str, Option<String>)>);
    impl Az3Env {
        fn poser(valeurs: &[(&'static str, &str)]) -> Self {
            let avant = AZ3_LEVIERS.iter().map(|k| (*k, std::env::var(k).ok())).collect();
            for k in AZ3_LEVIERS {
                std::env::remove_var(k);
            }
            for (k, v) in valeurs {
                std::env::set_var(k, v);
            }
            Az3Env(avant)
        }
    }
    impl Drop for Az3Env {
        fn drop(&mut self) {
            for (k, v) in &self.0 {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    /// Retire un crochet resté armé (témoin qui panique avant de passer l'étape) : il ne vise que son chemin, mais
    /// un crochet laissé là ne doit pas survivre au témoin.
    struct Az3Desarme;
    impl Drop for Az3Desarme {
        fn drop(&mut self) {
            desarmer();
        }
    }

    struct Az3Servi {
        code: u16,
        corps: Value,
        brut: String,
    }
    impl Az3Servi {
        fn entete(&self, nom: &str) -> Option<String> {
            let tete = self.brut.split_once("\r\n\r\n").map(|(t, _)| t).unwrap_or(&self.brut);
            tete.lines().skip(1).find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().eq_ignore_ascii_case(nom).then(|| v.trim().to_string())
            })
        }
        fn lignes(&self) -> usize {
            self.corps.as_array().unwrap_or_else(|| panic!("tableau attendu : {}", self.resume())).len()
        }
        fn resume(&self) -> String {
            format!(
                "code={} lignes={:?} tronque={:?} borne={:?} nom={:?} corps={}",
                self.code,
                self.corps.as_array().map(|a| a.len()),
                self.entete("x-plume-truncated"),
                self.entete(AZ3_ENTETE_BORNE),
                self.entete("content-disposition"),
                if self.corps.is_array() { String::from("[…]") } else { self.corps.to_string() }
            )
        }
    }

    /// POST par le routeur réel ; corps JSON décodé (chunked compris), réponse brute gardée.
    async fn az3_envoyer(addr: std::net::SocketAddr, route: &str, authz: &str, corps: &Value) -> Az3Servi {
        let entetes = [("Content-Type", "application/json")];
        let (code, brut) = router_probe_envoi(addr, "POST", route, Some(authz), &entetes, &corps.to_string()).await;
        let (tete, c) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière : {brut}"));
        let c = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(c.as_bytes()).unwrap_or_else(|| panic!("trame chunked : {brut}"))).expect("corps UTF-8")
        } else {
            c.to_string()
        };
        Az3Servi { code, corps: serde_json::from_str(&c).unwrap_or(Value::Null), brut }
    }

    /// Fenêtre ENTIÈREMENT froide : les 120 lignes vieillies, ni la ligne chaude du banc, ni rien au-dessus.
    fn az3_corps_pur_froid(banc: &BancFroidSurLaRoute, soql: &str) -> Value {
        json!({ "soql": soql, "from": banc.base_froide - 60, "to": banc.base_froide + LIGNES_FROIDES * 60, "format": "json" })
    }

    /// (1) EXPORT D'UNE FENÊTRE ENTIÈREMENT FROIDE, PLUME_QUERY_MAX=50 :
    ///   borne 100 (120 froides) -> 100 lignes, coupé, `x-plume-export-borne: 100`, nom `-TRONQUE-` ;
    ///   borne 119 (une seule ligne de trop) -> 119 lignes, borne 119 dite ;
    ///   borne 120 (exactement les lignes froides) -> 120 lignes, rien n'est dit coupé, aucun en-tête de borne ;
    ///   `/api/query` de la même fenêtre : la recopie froide reste à PLUME_QUERY_MAX=50 (`stats.cold.rows_hydrated`).
    /// MUTANTS : AZ3_SONDE_FROIDE (borne 100 et 119), AZ3_SONDE_PARTOUT (`/api/query`).
    #[tokio::test]
    async fn az3_export_entierement_froid_coupe_a_sa_borne_le_dit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _leviers = Az3Env::poser(&[("PLUME_QUERY_MAX", "50"), ("PLUME_EXPORT_MAX", "100")]);
        let banc = BancFroidSurLaRoute::monter("az3-pur-froid", false).await;
        banc.vieillir();
        let corps = az3_corps_pur_froid(&banc, "search source=froid");

        let s = az3_envoyer(banc.addr, "/api/export", &banc.authz, &corps).await;
        assert_eq!(s.code, 200, "borne 100 : servi : {}", s.resume());
        assert_eq!(s.lignes(), 100, "borne 100 : la borne, pas PLUME_QUERY_MAX=50 ni les 120 froides : {}", s.resume());
        assert_eq!(s.entete("x-plume-truncated").as_deref(), Some("1"), "borne 100 : coupé : {}", s.resume());
        assert!(s.entete("content-disposition").unwrap_or_default().contains("-TRONQUE-"), "borne 100 : nom de fichier tronqué : {}", s.resume());
        assert_eq!(s.entete(AZ3_ENTETE_BORNE).as_deref(), Some("100"), "borne 100 : fenêtre entièrement froide coupée à sa borne, borne dite : {}", s.resume());

        std::env::set_var("PLUME_EXPORT_MAX", "119");
        let s = az3_envoyer(banc.addr, "/api/export", &banc.authz, &corps).await;
        assert_eq!(s.code, 200, "borne 119 : servi : {}", s.resume());
        assert_eq!(s.lignes(), 119, "borne 119 : {}", s.resume());
        assert_eq!(s.entete("x-plume-truncated").as_deref(), Some("1"), "borne 119 : une ligne de trop, coupé : {}", s.resume());
        assert_eq!(s.entete(AZ3_ENTETE_BORNE).as_deref(), Some("119"), "borne 119 : borne dite : {}", s.resume());

        std::env::set_var("PLUME_EXPORT_MAX", "120");
        let s = az3_envoyer(banc.addr, "/api/export", &banc.authz, &corps).await;
        assert_eq!(s.code, 200, "borne 120 : servi : {}", s.resume());
        assert_eq!(s.lignes(), 120, "borne 120 : toutes les froides : {}", s.resume());
        assert_eq!(s.entete("x-plume-truncated").as_deref(), Some("0"), "borne 120 : la ligne sonde ne fait pas dire coupé un export complet : {}", s.resume());
        assert_eq!(s.entete(AZ3_ENTETE_BORNE), None, "borne 120 : borne non touchée : {}", s.resume());

        let (code, v) = banc.interroger("search source=froid", banc.base_froide - 60, banc.base_froide + LIGNES_FROIDES * 60).await;
        assert_eq!(code, 200, "/api/query : servi : {v}");
        assert_eq!(v["stats"]["cold"]["rows_hydrated"], json!(50), "/api/query : la recopie froide reste à PLUME_QUERY_MAX, sans ligne sonde : {}", v["stats"]);
        assert_eq!(v["stats"]["truncated"], json!(true), "/api/query : coupé à 50 : {}", v["stats"]);
    }

    /// (2) AGRÉGAT FROID TRONQUÉ SOUS UN EXPORT, PLUME_QUERY_MAX=50, PLUME_EXPORT_MAX=100 : 422, corps ENTIER (cinq clés),
    /// `cold_row_cap` et `cold_rows_hydrated` = 101 (borne et ligne sonde), message qui nomme la borne de l'export et
    /// jamais `PLUME_QUERY_MAX=`. MUTANTS : AZ3_MSG_QUERY_MAX, AZ3_SANS_BORNE_NOMMEE.
    #[tokio::test]
    async fn az3_refus_d_agregat_froid_sous_export_nomme_la_borne() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _leviers = Az3Env::poser(&[("PLUME_QUERY_MAX", "50"), ("PLUME_EXPORT_MAX", "100")]);
        let banc = BancFroidSurLaRoute::monter("az3-agregat-froid", false).await;
        banc.vieillir();
        let corps = json!({ "soql": "search source=froid | stats count", "from": banc.base_froide - 60, "to": banc.maintenant + 60, "format": "json" });
        let s = az3_envoyer(banc.addr, "/api/export", &banc.authz, &corps).await;
        assert_eq!(s.code, 422, "refus d'un agrégat sur une recopie tronquée : {}", s.resume());
        let mut cles: Vec<&String> = s.corps.as_object().map(|o| o.keys().collect()).unwrap_or_default();
        cles.sort();
        assert_eq!(cles, vec!["cold_row_cap", "cold_rows_hydrated", "error", "reason", "truncated"], "corps entier : {}", s.resume());
        assert_eq!(s.corps["reason"], json!("cold_truncated_aggregate"), "{}", s.resume());
        assert_eq!(s.corps["truncated"], json!(true), "{}", s.resume());
        assert_eq!(s.corps["cold_row_cap"], json!(101), "plafond froid = borne de l'export et ligne sonde : {}", s.resume());
        assert_eq!(s.corps["cold_rows_hydrated"], json!(101), "{}", s.resume());
        let message = s.corps["error"].as_str().unwrap_or_default();
        assert!(message.contains(AZ3_PLAFOND_DE_L_EXPORT_100), "le message nomme la borne de l'export : {message}");
        assert!(!message.contains("PLUME_QUERY_MAX="), "le message n'attribue plus le plafond à PLUME_QUERY_MAX : {message}");
    }

    /// (3) `P10.29-w` — UN ÉCRIVAIN PREND LA BASE EN VERROU EXCLUSIF AU POINT EXACT DE L'ÉTAPE (avant la préparation de
    /// l'insertion dans la table temporaire, puis avant la vue d'union), base en journal de rollback. Pour chaque étape :
    /// le crochet est passé, le verrou est pris et une sonde le voit (BUSY), l'export d'une fenêtre entièrement froide
    /// sert le 503 OCCUPÉE `{error, id}` exactement ; contrôle : le verrou rendu, le même export est servi (200, 120).
    /// MUTANTS : AZ3W_INSERT_LIT_MAIN, AZ3W_VUE_LIT_MAIN.
    #[tokio::test]
    async fn az3w_base_prise_pendant_le_montage_de_l_union_est_servie_occupee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _leviers = Az3Env::poser(&[]);
        // Les deux étapes sont écrites dans la boucle même (vague BA : le plancher sur ce tableau littéral et le compte
        // d'une boucle sans `continue` étaient vrais par construction, retirés).
        for (etape, etiquette) in [(Etape::AvantLInsertion, "az3w-insertion"), (Etape::AvantLaVue, "az3w-vue")] {
            let banc = BancFroidSurLaRoute::monter(etiquette, false).await;
            banc.vieillir();
            let chemin = banc.chemin_base.clone();
            assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(&chemin), 0, "{etiquette} : instrument : aucune connexion de lecture ouverte");
            let mode: String = banc.st.db.lock().query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0)).expect("fixture : mode de journal");
            assert_eq!(mode, "delete", "{etiquette} : instrument : base passée en journal de rollback");

            let constats: std::sync::Arc<parking_lot::Mutex<Vec<String>>> = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
            let _desarme = Az3Desarme;
            {
                let db = banc.st.db.clone();
                let chemin_sonde = chemin.clone();
                let constats = constats.clone();
                armer(
                    &chemin,
                    etape,
                    Box::new(move || {
                        let pris = db
                            .lock()
                            .execute_batch("BEGIN EXCLUSIVE; INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global','az3w-verrou','1');");
                        constats.lock().push(match pris {
                            Ok(()) => "verrou pris".to_string(),
                            Err(e) => format!("verrou NON pris : {e}"),
                        });
                        let sonde = Connection::open_with_flags(&chemin_sonde, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).expect("instrument : sonde ouverte");
                        crate::crypto::apply_key_for(&sonde, &chemin_sonde);
                        let _ = sonde.busy_timeout(std::time::Duration::ZERO);
                        let lu = sonde.query_row("SELECT COUNT(*) FROM event", [], |r| r.get::<_, i64>(0));
                        constats.lock().push(match lu.as_ref().err().and_then(|e| e.sqlite_error_code()) {
                            Some(rusqlite::ErrorCode::DatabaseBusy) => "sonde occupée".to_string(),
                            _ => format!("sonde NON occupée : {lu:?}"),
                        });
                    }),
                );
            }
            let corps = az3_corps_pur_froid(&banc, "search source=froid");
            let s = az3_envoyer(banc.addr, "/api/export", &banc.authz, &corps).await;
            banc.st.db.lock().execute_batch("ROLLBACK;").expect("fixture : verrou rendu");
            assert!(!desarmer(), "{etiquette} : le crochet de l'étape a été passé");
            assert_eq!(*constats.lock(), vec!["verrou pris".to_string(), "sonde occupée".to_string()], "{etiquette} : instrument : la base était prise au point de l'étape");
            assert_eq!(s.code, 503, "{etiquette} : base prise pendant le montage : 503 : {}", s.resume());
            let mut cles: Vec<&String> = s.corps.as_object().map(|o| o.keys().collect()).unwrap_or_default();
            cles.sort();
            assert_eq!(cles, vec!["error", "id"], "{etiquette} : exactement `error` et `id` : {}", s.resume());
            assert_eq!(s.corps["error"], json!(AZ3_CAUSE_OCCUPEE), "{etiquette} : la base OCCUPÉE, jamais illisible : {}", s.resume());
            assert!(s.corps["id"].as_str().unwrap_or_default().starts_with("plume-e"), "{etiquette} : identifiant de corrélation : {}", s.resume());

            let c = az3_envoyer(banc.addr, "/api/export", &banc.authz, &corps).await;
            assert_eq!(c.code, 200, "{etiquette} : contrôle, verrou rendu : servi : {}", c.resume());
            assert_eq!(c.lignes(), LIGNES_FROIDES as usize, "{etiquette} : contrôle : toutes les froides : {}", c.resume());
        }
    }
}
