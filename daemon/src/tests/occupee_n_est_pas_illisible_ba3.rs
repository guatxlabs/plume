// =====================================================================================
// `P10.29-w`, `P10.33-r`, `P10.32-r` (vague BA) — UNE BASE OCCUPÉE N'EST NI UN SEL ILLISIBLE NI UNE RÉTENTION
// ILLISIBLE ; LE REFUS D'UN EXPORT DONT LA BORNE ÉGALE PLUME_QUERY_MAX NE DIT PAS « AU-DESSUS » ; MESURE MÉMOIRE D'UN
// EXPORT FROID À SA BORNE PAR DÉFAUT.
//
// LES DÉFAUTS, RELEVÉS PAR LE VÉRIFICATEUR DE LA VAGUE AZ (f4f3f827) ET RE-MESURÉS ICI :
//  * `install_fmask_udf` (`query_exec.rs`) lisait le sel par `read_field_mask_salt`, qui rend un texte sans code :
//    sous le verrou d'un autre écrivain, la lecture échouait en BUSY et le journal disait « sel de hachage ILLISIBLE …
//    database is locked [code étendu 5] ». Sur la connexion d'union froide c'est le premier énoncé qui lit `main` après
//    la vue (`reader.rs`, étape (7)). Remède : l'installation passe par `relire_le_sel_sur`, qui garde le code ; une
//    base occupée a sa ligne (« NON LU, base OCCUPÉE »), une interruption aussi ; la relecture à l'appel, sous une base
//    occupée, fait échouer l'instruction sous le code d'occupation (classée `Occupee`), plus sous un message ;
//  * `HorizonDeLecture::lire` (`cold_store/reader.rs`) : `retention_effective_lue` rend un texte sans code, une base
//    occupée y devenait `HORIZON_FROID_NON_LU`, servi « illisible » sur les quatre voies froides (union, vectorisée,
//    fusion, keyset colonnaire). Remède : la lecture se fait sous un point de sauvegarde dont le premier énoncé est une
//    sonde du schéma, notée `Occupee` par son code ; la lecture de `main` est ensuite tenue jusqu'à la libération ;
//  * `cold_store/exactness.rs` : `PLUME_QUERY_MAX` égal à la borne plus une ligne, le 422 disait la borne « au-dessus
//    de PLUME_QUERY_MAX ». Remède : le cas d'égalité nomme les deux.
//
// MUTANTS (variable VERIF_MUT sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE :
//  BA3_CLASSE_SANS_CODE (l'occupation n'est plus reconnue par le code dans `relire_le_sel_sur`) : (1), (3) ;
//  BA3_RELECTURE_PAR_MESSAGE (relecture occupée rendue par un message, forme d'avant) : (1) ;
//  BA3_INSTALL_INTERROMPUE_MUETTE (l'interruption de l'installation sans ligne) : (1) ;
//  BA3_HORIZON_SANS_SONDE (ni point de sauvegarde ni sonde, forme d'avant) : (2a), (2b), (2c), (2d), une par voie ;
//  BA3_HORIZON_LIBERE_APRES_LA_SONDE (le point de sauvegarde libéré juste après la sonde) : (4a) ;
//  BA3C_RELEASE_AVANT_POLITIQUES (libéré après le réglage, avant la fenêtre chaude et les politiques) : (4b) ;
//  BA3_MESSAGE_SANS_EGALITE (le bras d'égalité retiré) : (5).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'occupation est fabriquée par une connexion du même processus en journal de
// rollback (en WAL, un lecteur ne rencontre pas le verrou d'un écrivain) ; la libération ratée du point de sauvegarde est
// dite HORS D'ATTEINTE au site, sans témoin ; `relire_le_sel_sur` n'est joué que sous BUSY (LOCKED y est hors
// d'atteinte : aucun cache partagé ; le classement commun `code_de_base_occupee` est jugé par les témoins `au1_`). La
// couverture (`handlers/panneau_avoue.rs`), qui rangeait un échec de l'horizon sous « retention_days », le range par sa
// classe depuis la vague BB ; elle est jugée à l'appelant réel par `couverture_froide_sous_base_prise_bc2.rs`. La
// mesure (6) compte ce que SQLite alloue, pas la mémoire Rust du corps rendu.
// =====================================================================================
#[cfg(test)]
mod ba3_occupee_n_est_pas_illisible {
    use super::*;

    const BA3_SEL: &str = "sel-ba3-epreuve";
    const BA3_ENFANT_SEL: &str = "BA3_ENFANT_SEL_OCCUPE";
    const BA3_LIGNE_INSTALL_OCCUPEE: &str = "[field_filter] sel de hachage NON LU, base OCCUPÉE sur cette connexion : database is locked [code étendu 5] — plume_fmask_hash le relira à chaque appel";
    const BA3_LIGNE_RELECTURE_OCCUPEE: &str = "[field_filter] sel de hachage NON LU à la relecture, base OCCUPÉE : database is locked [code étendu 5] — HASH refusé pour cette instruction";
    const BA3_LIGNE_INSTALL_INTERROMPUE: &str = "[field_filter] sel de hachage NON LU, lecture interrompue sur cette connexion — plume_fmask_hash le relira à chaque appel";

    /// Les lignes du journal du sel, dans l'ordre.
    fn ba3_lignes_du_sel(stderr: &str) -> Vec<String> {
        stderr.lines().filter(|l| l.starts_with("[field_filter] sel de hachage")).map(str::to_string).collect()
    }

    /// (1) LE SEL SOUS UNE BASE OCCUPÉE, À L'INSTALLATION ET À LA RELECTURE, ET L'INSTALLATION INTERROMPUE. Base en journal
    /// de rollback ; une seconde connexion tient le verrou EXCLUSIF ; le lecteur attend zéro. Lu sur le stderr d'un
    /// sous-processus : une ligne « NON LU, base OCCUPÉE » à l'installation, une à la relecture (et l'instruction échoue
    /// sous le code d'occupation), jamais « ILLISIBLE » ; verrou rendu, le HASH réussit sur la même connexion (contrôle) ;
    /// une installation interrompue a sa propre ligne.
    /// MUTANTS : BA3_CLASSE_SANS_CODE, BA3_RELECTURE_PAR_MESSAGE, BA3_INSTALL_INTERROMPUE_MUETTE.
    #[test]
    fn ba3_sel_sous_base_occupee_n_est_pas_dit_illisible() {
        if std::env::var(BA3_ENFANT_SEL).is_ok() {
            let base = crate::tmp_possede::TmpDb::neuf("ba3-sel-occupe");
            let chemin = base.as_str().to_string();
            let ecrivain = Connection::open(&chemin).expect("fixture : écrivain");
            ecrivain
                .execute_batch(&format!(
                    "PRAGMA journal_mode=DELETE; CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT); INSERT INTO meta VALUES('field_mask_salt','{BA3_SEL}');"
                ))
                .expect("fixture : base et sel");
            let lecteur = Connection::open_with_flags(&chemin, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).expect("fixture : lecteur");
            lecteur.busy_timeout(std::time::Duration::ZERO).expect("fixture : attente nulle");
            ecrivain.execute_batch("BEGIN EXCLUSIVE;").expect("fixture : verrou exclusif");
            crate::query_exec::install_fmask_udf(&lecteur);
            let sous_verrou = lecteur.query_row("SELECT plume_fmask_hash('alice')", [], |r| r.get::<_, String>(0));
            // Une ligne à elle : libtest a déjà écrit « test … ... » sans fin de ligne.
            println!("\nBA3-RELECTURE-CODE: {:?}", sous_verrou.as_ref().err().and_then(|e| e.sqlite_error_code()));
            ecrivain.execute_batch("ROLLBACK;").expect("fixture : verrou rendu");
            let apres = lecteur.query_row("SELECT plume_fmask_hash('alice')", [], |r| r.get::<_, String>(0));
            println!("BA3-APRES: {apres:?}");
            let interrompu = Connection::open_with_flags(&chemin, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).expect("fixture : lecteur interrompu");
            let lu: i64 = interrompu.query_row("SELECT count(*) FROM meta", [], |r| r.get(0)).expect("fixture : schéma chargé");
            println!("BA3-SCHEMA: {lu}");
            interrompu.progress_handler(1, Some(|| true));
            crate::query_exec::install_fmask_udf(&interrompu);
            interrompu.progress_handler(0, None::<fn() -> bool>);
            println!("BA3-ENFANT-A-JOUE");
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::ba3_occupee_n_est_pas_illisible::ba3_sel_sous_base_occupee_n_est_pas_dit_illisible"])
            .env(BA3_ENFANT_SEL, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("BA3-ENFANT-A-JOUE"), "contrôle : l'enfant a joué : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert_eq!(
            ba3_lignes_du_sel(&stderr),
            vec![BA3_LIGNE_INSTALL_OCCUPEE.to_string(), BA3_LIGNE_RELECTURE_OCCUPEE.to_string(), BA3_LIGNE_INSTALL_INTERROMPUE.to_string()],
            "une ligne par issue, occupée jamais dite illisible :\n{stderr}"
        );
        assert!(
            stdout.lines().any(|l| l == "BA3-RELECTURE-CODE: Some(DatabaseBusy)"),
            "la relecture sous une base occupée fait échouer l'instruction sous le code d'occupation : {stdout}"
        );
        let attendu = format!("BA3-APRES: Ok({:?})", crate::fmask_hash(BA3_SEL, "alice"));
        assert!(stdout.lines().any(|l| l == attendu), "contrôle : verrou rendu, le HASH réussit sur la même connexion ({attendu}) : {stdout}");
    }

    #[cfg(feature = "cold_tier")]
    mod ba3_voies_froides {
        use super::*;
        use crate::query_exec::crochet_de_l_union_froide::{armer, desarmer, Etape};

        const BA3_LEVIERS: [&str; 2] = ["PLUME_QUERY_MAX", "PLUME_EXPORT_MAX"];
        const BA3_CAUSE_OCCUPEE: &str = "REQUÊTE NON SERVIE : la base est occupée (verrou tenu par une autre opération) — ce n'est PAS un résultat vide, et rien n'est rendu. Réessayez dans un instant.";
        const BA3_ENFANT_UNION: &str = "BA3_ENFANT_UNION_SEL_OCCUPE";

        /// Pose les leviers et remet l'état d'avant à la sortie (l'appelant tient `VERROU_ENV_PROCESSUS.write()`).
        struct Ba3Env(Vec<(&'static str, Option<String>)>);
        impl Ba3Env {
            fn poser(valeurs: &[(&'static str, &str)]) -> Self {
                let avant = BA3_LEVIERS.iter().map(|k| (*k, std::env::var(k).ok())).collect();
                for k in BA3_LEVIERS {
                    std::env::remove_var(k);
                }
                for (k, v) in valeurs {
                    std::env::set_var(k, v);
                }
                Ba3Env(avant)
            }
        }
        impl Drop for Ba3Env {
            fn drop(&mut self) {
                for (k, v) in &self.0 {
                    match v {
                        Some(v) => std::env::set_var(k, v),
                        None => std::env::remove_var(k),
                    }
                }
            }
        }

        /// Retire un crochet resté armé (témoin qui panique avant l'étape).
        struct Ba3Desarme;
        impl Drop for Ba3Desarme {
            fn drop(&mut self) {
                desarmer();
            }
        }

        struct Ba3Servi {
            code: u16,
            corps: Value,
            brut: String,
        }
        impl Ba3Servi {
            fn entete(&self, nom: &str) -> Option<String> {
                let tete = self.brut.split_once("\r\n\r\n").map(|(t, _)| t).unwrap_or(&self.brut);
                tete.lines().skip(1).find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.trim().eq_ignore_ascii_case(nom).then(|| v.trim().to_string())
                })
            }
            fn resume(&self) -> String {
                let corps = if self.corps.is_array() { format!("[{} lignes]", self.corps.as_array().map_or(0, |a| a.len())) } else { self.corps.to_string() };
                format!("code={} borne={:?} corps={corps}", self.code, self.entete("x-plume-export-borne"))
            }
            /// Le refus de la base OCCUPÉE, corps entier : exactement `error` (la phrase) et `id`.
            fn est_le_refus_occupee(&self, etiquette: &str) {
                assert_eq!(self.code, 503, "{etiquette} : 503 : {}", self.resume());
                let mut cles: Vec<&String> = self.corps.as_object().map(|o| o.keys().collect()).unwrap_or_default();
                cles.sort();
                assert_eq!(cles, vec!["error", "id"], "{etiquette} : exactement `error` et `id` : {}", self.resume());
                assert_eq!(self.corps["error"], json!(BA3_CAUSE_OCCUPEE), "{etiquette} : la base OCCUPÉE, jamais illisible : {}", self.resume());
                assert!(self.corps["id"].as_str().unwrap_or_default().starts_with("plume-e"), "{etiquette} : identifiant de corrélation : {}", self.resume());
            }
        }

        /// POST par le routeur réel ; corps JSON décodé (chunked compris), réponse brute gardée.
        async fn ba3_envoyer(addr: std::net::SocketAddr, route: &str, authz: &str, corps: &Value) -> Ba3Servi {
            let entetes = [("Content-Type", "application/json")];
            let (code, brut) = router_probe_envoi(addr, "POST", route, Some(authz), &entetes, &corps.to_string()).await;
            let (tete, c) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière : {brut}"));
            let c = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
                String::from_utf8(shell_decouper(c.as_bytes()).unwrap_or_else(|| panic!("trame chunked : {brut}"))).expect("corps UTF-8")
            } else {
                c.to_string()
            };
            Ba3Servi { code, corps: serde_json::from_str(&c).unwrap_or(Value::Null), brut }
        }

        /// Le chemin de la base tel que SQLite le nomme (`sqlite3_db_filename`) : celui que `HorizonDeLecture::lire`
        /// passe au crochet.
        fn ba3_chemin_sqlite(banc: &BancFroidSurLaRoute) -> String {
            banc.st.db.lock().path().expect("instrument : chemin de la base").to_string()
        }

        /// Passe la base du banc en journal de rollback (aucune connexion de lecture ouverte : sinon la bascule échoue).
        fn ba3_journal_de_rollback(banc: &BancFroidSurLaRoute, etiquette: &str) {
            assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(&banc.chemin_base), 0, "{etiquette} : instrument : aucune connexion de lecture ouverte");
            let mode: String = banc.st.db.lock().query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0)).expect("fixture : mode de journal");
            assert_eq!(mode, "delete", "{etiquette} : instrument : base passée en journal de rollback");
        }

        /// Arme, à `etape` sur la base du banc, un écrivain qui prend la base en verrou EXCLUSIF (l'écrivain du banc, qui
        /// garde sa transaction ouverte) et une sonde qui constate que la base est prise. Rend les constats.
        fn ba3_armer_le_verrou(banc: &BancFroidSurLaRoute, chemin_du_crochet: &str, etape: Etape) -> std::sync::Arc<parking_lot::Mutex<Vec<String>>> {
            let constats: std::sync::Arc<parking_lot::Mutex<Vec<String>>> = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
            let db = banc.st.db.clone();
            let chemin_sonde = banc.chemin_base.clone();
            let c = constats.clone();
            armer(
                chemin_du_crochet,
                etape,
                Box::new(move || {
                    let pris = db.lock().execute_batch("BEGIN EXCLUSIVE; INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global','ba3-verrou','1');");
                    c.lock().push(match pris {
                        Ok(()) => "verrou pris".to_string(),
                        Err(e) => format!("verrou NON pris : {e}"),
                    });
                    let sonde = Connection::open_with_flags(&chemin_sonde, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).expect("instrument : sonde ouverte");
                    crate::crypto::apply_key_for(&sonde, &chemin_sonde);
                    let _ = sonde.busy_timeout(std::time::Duration::ZERO);
                    let lu = sonde.query_row("SELECT COUNT(*) FROM event", [], |r| r.get::<_, i64>(0));
                    c.lock().push(match lu.as_ref().err().and_then(|e| e.sqlite_error_code()) {
                        Some(rusqlite::ErrorCode::DatabaseBusy) => "sonde occupée".to_string(),
                        _ => format!("sonde NON occupée : {lu:?}"),
                    });
                }),
            );
            constats
        }

        /// (2) `P10.29-w` — UNE BASE PRISE AU MOMENT DE LIRE L'HORIZON DE RÉTENTION EST SERVIE « OCCUPÉE », VOIE PAR VOIE.
        /// Un banc neuf en journal de rollback, un écrivain prend la base en verrou EXCLUSIF dans `HorizonDeLecture::lire`,
        /// avant sa lecture ; la route sert le 503 OCCUPÉE, corps entier ; contrôle : verrou rendu, la même demande est
        /// servie (200). MUTANT : BA3_HORIZON_SANS_SONDE (le réglage de rétention lu le premier : 503 illisible).
        async fn ba3_horizon_sous_base_occupee(etiquette: &str, vectorise: bool, demande: fn(&BancFroidSurLaRoute) -> Value) {
            let _leviers = Ba3Env::poser(&[]);
            let banc = BancFroidSurLaRoute::monter(etiquette, vectorise).await;
            banc.vieillir();
            ba3_journal_de_rollback(&banc, etiquette);
            let chemin = ba3_chemin_sqlite(&banc);
            let _desarme = Ba3Desarme;
            let constats = ba3_armer_le_verrou(&banc, &chemin, Etape::AvantLaPriseDeLHorizon);
            let corps = demande(&banc);
            let s = ba3_envoyer(banc.addr, "/api/query", &banc.authz, &corps).await;
            banc.st.db.lock().execute_batch("ROLLBACK;").expect("fixture : verrou rendu");
            assert!(!desarmer(), "{etiquette} : la lecture de l'horizon a été atteinte (crochet passé) : {}", s.resume());
            assert_eq!(*constats.lock(), vec!["verrou pris".to_string(), "sonde occupée".to_string()], "{etiquette} : instrument : la base était prise avant l'horizon");
            s.est_le_refus_occupee(etiquette);
            let c = ba3_envoyer(banc.addr, "/api/query", &banc.authz, &corps).await;
            assert_eq!(c.code, 200, "{etiquette} : contrôle, verrou rendu : servi : {}", c.resume());
        }

        /// (2a) Union chaud∪froid (voie vectorisée désarmée), fenêtre chevauchante.
        #[tokio::test]
        async fn ba3_horizon_occupe_voie_union() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            ba3_horizon_sous_base_occupee("ba3h-union", false, |b| json!({ "soql": "search source=froid", "from": b.base_froide - 60, "to": b.maintenant + 60 })).await;
        }

        /// (2b) Voie vectorisée pur-froid (`cold_vectorized_try`).
        #[tokio::test]
        async fn ba3_horizon_occupe_voie_vectorisee() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            ba3_horizon_sous_base_occupee("ba3h-vectorisee", true, |b| {
                json!({ "soql": "search source=froid | stats count by host", "from": b.base_froide - 60, "to": b.base_froide + LIGNES_FROIDES * 60 })
            })
            .await;
        }

        /// (2c) Fusion chaud∪froid vectorisée (`cold_vectorized_merge_try`), fenêtre chevauchante.
        #[tokio::test]
        async fn ba3_horizon_occupe_voie_fusion() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            ba3_horizon_sous_base_occupee("ba3h-fusion", true, |b| json!({ "soql": "search source=froid | stats count by host", "from": b.base_froide - 60, "to": b.maintenant + 60 })).await;
        }

        /// (2d) Keyset colonnaire (`cold_keyset_page`).
        #[tokio::test]
        async fn ba3_horizon_occupe_voie_keyset() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            ba3_horizon_sous_base_occupee("ba3h-keyset", true, |b| {
                json!({ "soql": "search source=froid", "keyset": true, "limit": 10, "from": b.base_froide - 60, "to": b.maintenant + 60 })
            })
            .await;
        }

        /// (3) `P10.29-w` / `P10.33-r` — APRÈS LA VUE D'UNION, LE SEL LU SOUS UNE BASE PRISE EST DIT « NON LU, base
        /// OCCUPÉE », JAMAIS « ILLISIBLE ». Un écrivain prend la base en verrou EXCLUSIF juste avant la vue d'union (journal
        /// de rollback) ; l'export d'une fenêtre entièrement froide sert le 503 OCCUPÉE ; le stderr du sous-processus porte
        /// la ligne d'installation du sel de la connexion d'union, une seule, sous la classe occupée.
        /// MUTANT : BA3_CLASSE_SANS_CODE (« ILLISIBLE … database is locked »).
        #[tokio::test]
        async fn ba3_sel_de_l_union_sous_base_occupee_dit_occupee() {
            if std::env::var(BA3_ENFANT_UNION).is_ok() {
                let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
                let _leviers = Ba3Env::poser(&[]);
                let banc = BancFroidSurLaRoute::monter("ba3-sel-union", false).await;
                banc.vieillir();
                ba3_journal_de_rollback(&banc, "ba3-sel-union");
                let _desarme = Ba3Desarme;
                let constats = ba3_armer_le_verrou(&banc, &banc.chemin_base, Etape::AvantLaVue);
                let corps = json!({ "soql": "search source=froid", "from": banc.base_froide - 60, "to": banc.base_froide + LIGNES_FROIDES * 60, "format": "json" });
                let s = ba3_envoyer(banc.addr, "/api/export", &banc.authz, &corps).await;
                banc.st.db.lock().execute_batch("ROLLBACK;").expect("fixture : verrou rendu");
                assert!(!desarmer(), "le crochet de la vue a été passé");
                assert_eq!(*constats.lock(), vec!["verrou pris".to_string(), "sonde occupée".to_string()], "instrument : la base était prise avant la vue");
                s.est_le_refus_occupee("ba3-sel-union");
                println!("BA3-UNION-A-JOUE");
                return;
            }
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
            let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
                .args([
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                    "tests::ba3_occupee_n_est_pas_illisible::ba3_voies_froides::ba3_sel_de_l_union_sous_base_occupee_dit_occupee",
                ])
                .env(BA3_ENFANT_UNION, "1")
                .output()
                .expect("ré-exécution du binaire de test");
            let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
            assert!(stdout.contains("BA3-UNION-A-JOUE"), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
            assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
            assert_eq!(
                ba3_lignes_du_sel(&stderr),
                vec![BA3_LIGNE_INSTALL_OCCUPEE.to_string()],
                "le sel de la connexion d'union, lu sous la base prise, est dit OCCUPÉE, jamais ILLISIBLE :\n{stderr}"
            );
        }

        /// (4) `P10.29-w` — LA LECTURE DE `main` EST TENUE DE LA SONDE À LA FIN DE L'HORIZON. À `etape`, un écrivain neuf
        /// (attente nulle) tente le verrou EXCLUSIF : il lui est refusé, la lecture de l'horizon tient, la route sert la
        /// fenêtre (200, les 120 lignes froides hydratées).
        async fn ba3_horizon_tenu_a(etiquette: &str, etape: Etape) {
            let _leviers = Ba3Env::poser(&[]);
            let banc = BancFroidSurLaRoute::monter(etiquette, false).await;
            banc.vieillir();
            ba3_journal_de_rollback(&banc, etiquette);
            let chemin = ba3_chemin_sqlite(&banc);
            let constats: std::sync::Arc<parking_lot::Mutex<Vec<String>>> = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
            let tenu: std::sync::Arc<parking_lot::Mutex<Option<Connection>>> = std::sync::Arc::new(parking_lot::Mutex::new(None));
            let _desarme = Ba3Desarme;
            {
                let c = constats.clone();
                let t = tenu.clone();
                let chemin_ecrivain = banc.chemin_base.clone();
                armer(
                    &chemin,
                    etape,
                    Box::new(move || {
                        let ecrivain = Connection::open(&chemin_ecrivain).expect("instrument : écrivain neuf");
                        crate::crypto::apply_key_for(&ecrivain, &chemin_ecrivain);
                        let _ = ecrivain.busy_timeout(std::time::Duration::ZERO);
                        match ecrivain.execute_batch("BEGIN EXCLUSIVE;") {
                            Ok(()) => {
                                c.lock().push("verrou pris".to_string());
                                *t.lock() = Some(ecrivain);
                            }
                            Err(e) => c.lock().push(match e.sqlite_error_code() {
                                Some(rusqlite::ErrorCode::DatabaseBusy) => "verrou refusé".to_string(),
                                _ => format!("verrou NON tenté : {e}"),
                            }),
                        }
                    }),
                );
            }
            let (code, v) = banc.interroger("search source=froid", banc.base_froide - 60, banc.maintenant + 60).await;
            if let Some(ecrivain) = tenu.lock().take() {
                ecrivain.execute_batch("ROLLBACK;").expect("fixture : verrou rendu");
            }
            assert!(!desarmer(), "{etiquette} : le crochet {etape:?} a été passé");
            assert_eq!(*constats.lock(), vec!["verrou refusé".to_string()], "{etiquette} : la lecture de l'horizon tient la base contre un écrivain à {etape:?} : {v}");
            assert_eq!(code, 200, "{etiquette} : la fenêtre est servie : {v}");
            assert_eq!(v["stats"]["cold"]["rows_hydrated"], json!(LIGNES_FROIDES), "{etiquette} : les lignes froides hydratées : {}", v["stats"]);
        }

        /// (4a) Juste après la sonde, avant le réglage.
        /// MUTANT : BA3_HORIZON_LIBERE_APRES_LA_SONDE (l'écrivain prend le verrou, le réglage rencontre la base prise : 503).
        #[tokio::test]
        async fn ba3_horizon_tient_sa_lecture_de_la_sonde_a_la_fin() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            ba3_horizon_tenu_a("ba3-horizon-tenu", Etape::ApresLaPriseDeLHorizon).await;
        }

        /// (4b) Après la fenêtre chaude et les politiques, juste avant la libération : une libération anticipée (après le
        /// réglage, avant `cold_hot_window_days` et `Bande::calculer`) laisserait `load_index_policies` rencontrer la base
        /// prise et rendre, sans rien dire, des politiques vides.
        /// MUTANT : BA3C_RELEASE_AVANT_POLITIQUES (l'écrivain prend le verrou : « verrou pris »).
        #[tokio::test]
        async fn ba3_horizon_tient_sa_lecture_jusqu_a_la_liberation() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            ba3_horizon_tenu_a("ba3-horizon-tenu-fin", Etape::AvantLaLiberationDeLHorizon).await;
        }

        /// (5) `P10.32-r` — `PLUME_QUERY_MAX=50`, `PLUME_EXPORT_MAX=49` : la borne plus une ligne ÉGALE `PLUME_QUERY_MAX`.
        /// Agrégat froid sur 120 lignes exporté : 422, corps entier, `cold_row_cap` 50, message qui nomme les deux plafonds
        /// égaux, jamais « au-dessus de PLUME_QUERY_MAX ».
        /// MUTANT : BA3_MESSAGE_SANS_EGALITE.
        #[tokio::test]
        async fn ba3_refus_quand_la_borne_egale_plume_query_max() {
            const BA3_PLAFOND_EGAL: &str = "(plafond de l'export : sa borne de 49 lignes (PLUME_EXPORT_MAX, ou le `limit` de la demande s'il est plus petit) et une ligne de plus qui détecte la coupure, soit 50 lignes, ÉGAL à PLUME_QUERY_MAX=50 : relever l'un ou l'autre élargit la lecture)";
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            let _leviers = Ba3Env::poser(&[("PLUME_QUERY_MAX", "50"), ("PLUME_EXPORT_MAX", "49")]);
            let banc = BancFroidSurLaRoute::monter("ba3-borne-egale", false).await;
            banc.vieillir();
            let corps = json!({ "soql": "search source=froid | stats count", "from": banc.base_froide - 60, "to": banc.base_froide + LIGNES_FROIDES * 60, "format": "json" });
            let s = ba3_envoyer(banc.addr, "/api/export", &banc.authz, &corps).await;
            assert_eq!(s.code, 422, "agrégat sur une recopie tronquée : {}", s.resume());
            let mut cles: Vec<&String> = s.corps.as_object().map(|o| o.keys().collect()).unwrap_or_default();
            cles.sort();
            assert_eq!(cles, vec!["cold_row_cap", "cold_rows_hydrated", "error", "reason", "truncated"], "corps entier : {}", s.resume());
            assert_eq!(s.corps["reason"], json!("cold_truncated_aggregate"), "{}", s.resume());
            assert_eq!(s.corps["cold_row_cap"], json!(50), "{}", s.resume());
            let message = s.corps["error"].as_str().unwrap_or_default();
            assert!(message.contains(BA3_PLAFOND_EGAL), "le message nomme les deux plafonds égaux : {message}");
            assert!(!message.contains("au-dessus de"), "aucun des deux n'est au-dessus de l'autre : {message}");
        }

        /// (6) MESURE — UN EXPORT AUX RÉGLAGES PAR DÉFAUT D'UNE FENÊTRE ENTIÈREMENT FROIDE DE PLUS DE 50 001 LIGNES : la
        /// borne (50 000) plus la ligne sonde sont recopiées dans la table TEMP (en mémoire au défaut). Ce que SQLite
        /// alloue de plus pendant l'export (`sqlite3_memory_highwater` remis au niveau courant juste avant) est comparé au
        /// plafond dur appliqué (`PRAGMA hard_heap_limit`) : trois exports concurrents (sémaphore des requêtes) doivent
        /// tenir dessous. Aucune borne de durée. Le chiffre est imprimé (`BA3-MESURE`).
        #[tokio::test]
        async fn ba3_mesure_memoire_d_un_export_froid_a_sa_borne_par_defaut() {
            const BA3_LIGNES: i64 = 50_100;
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            let _leviers = Ba3Env::poser(&[]);
            let cle = "plume-cold-route-test-key-do-not-use-in-prod-0000";
            let poses: [(&'static str, &str); 3] = [("PLUME_COLD_TIER", "1"), ("PLUME_COLD_HOT_WINDOW_DAYS", "2"), ("PLUME_COLD_VECTORIZED", "0")];
            std::env::remove_var("PLUME_COLD_DIR");
            for (k, v) in poses {
                std::env::set_var(k, v);
            }
            let conf: HashMap<String, String> = poses.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            let (st, base) = router_test_state_avec("ba3-mesure", Some(cle));
            let chemin = base.as_str().to_string();
            let _nettoyage = PoseDEnvironnement(poses.iter().map(|(k, _)| *k).collect(), chemin.clone());
            let minuit = now().div_euclid(JOUR) * JOUR;
            let base_froide = minuit - 8 * JOUR;
            {
                let c = st.db.lock();
                let tx = c.unchecked_transaction().unwrap();
                for i in 0..BA3_LIGNES {
                    // Lignes représentatives : un message et des champs de la taille d'un journal d'accès web.
                    tx.execute(
                        "INSERT INTO event(ts,severity,source,category,host,src_ip,dst_ip,url,xff,dedup,engagement_id,origin,env_id,message,fields) \
                         VALUES(?1,3,'froid','web','web-01.exemple.test','192.0.2.17','198.51.100.4',?2,'',?3,'','','prod',?4,?5)",
                        params![
                            base_froide + i,
                            format!("/api/v1/ressources/{i}?page=2&tri=date"),
                            format!("froid-{i}"),
                            format!("GET /api/v1/ressources/{i}?page=2&tri=date HTTP/1.1 200 {} \"-\" \"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0\"", 1000 + i % 9000),
                            format!("{{\"status\":200,\"bytes\":{},\"method\":\"GET\",\"ua\":\"Mozilla/5.0 (X11; Linux x86_64)\",\"referer\":\"https://exemple.test/accueil\",\"latence_ms\":{}}}", 1000 + i % 9000, i % 700),
                        ],
                    )
                    .unwrap();
                }
                // Une ligne chaude APRÈS : le vieillissement diffère le jour qui détient la fin du compteur de rowid.
                tx.execute(
                    "INSERT INTO event(ts,severity,source,category,host,src_ip,dst_ip,url,xff,dedup,engagement_id,origin,env_id,message,fields) \
                     VALUES(?1,1,'froid','test','h-froid','','','','','ba3-chaude','','','prod','ligne chaude','{}')",
                    params![now() - 60],
                )
                .unwrap();
                tx.commit().unwrap();
            }
            crate::cold_store::cold_age_run(&st.db, &chemin, &conf, minuit, 30);
            let restantes: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM event WHERE ts < ?1", params![minuit - 2 * JOUR], |r| r.get(0)).unwrap();
            assert_eq!(restantes, 0, "instrument : le vieillissement a déplacé les lignes froides");
            let plafond: i64 = st.db.lock().query_row("PRAGMA hard_heap_limit", [], |r| r.get(0)).expect("plafond dur relu");
            let addr = router_serve(st.clone()).await;
            let corps = json!({ "soql": "search source=froid", "from": base_froide - 60, "to": base_froide + BA3_LIGNES, "format": "json" });
            // SAFETY : fonctions de statut de SQLite, sans pointeur ; la remise du pic est de processus.
            let avant = unsafe {
                rusqlite::ffi::sqlite3_memory_highwater(1);
                rusqlite::ffi::sqlite3_memory_used()
            };
            // La sonde ne lit que les premiers 64 Kio : les en-têtes (`x-plume-rows`, `x-plume-export-borne`) partent
            // après l'exécution SQLite complète, le corps n'est pas décodé.
            let (code, brut) = router_probe_envoi(addr, "POST", "/api/export", Some(&viewer_authz()), &[("Content-Type", "application/json")], &corps.to_string()).await;
            let s = Ba3Servi { code, corps: Value::Null, brut };
            let pic = unsafe { rusqlite::ffi::sqlite3_memory_highwater(0) };
            let delta = pic - avant;
            println!("BA3-MESURE: lignes_froides={BA3_LIGNES} code={} borne={:?} avant={avant} pic={pic} delta={delta} plafond={plafond} trois_exports={}", s.code, s.entete("x-plume-export-borne"), 3 * delta);
            assert_eq!(s.code, 200, "export servi : {}", s.resume());
            assert_eq!(s.entete("x-plume-rows").as_deref(), Some("50000"), "la borne par défaut : {}", s.resume());
            assert_eq!(s.entete("x-plume-export-borne").as_deref(), Some("50000"), "coupé à sa borne (la ligne sonde a été recopiée) : {}", s.resume());
            assert!(delta > 0, "instrument : l'export alloue dans SQLite (delta={delta})");
            assert!(plafond > 0, "instrument : plafond dur appliqué ({plafond})");
            assert!(3 * delta < plafond, "trois exports concurrents tiennent sous le plafond dur : delta={delta}, plafond={plafond}");
        }
    }
}
