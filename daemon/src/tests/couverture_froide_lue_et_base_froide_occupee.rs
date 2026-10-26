// =====================================================================================
// `P10.34-n`, `P10.29-w` et `P10.20-b` (voie froide de `/api/query`) — LA COUVERTURE D'UNE VOIE QUI A LU LE FROID EST
// CELLE DE LA RÉTENTION FROIDE ; UNE BASE FROIDE OCCUPÉE EST SERVIE « OCCUPÉE » ; LE PLUS VIEUX JOUR SCELLÉ ET LA LISTE
// DES ENVIRONNEMENTS SCELLÉS NON LUS SONT DES ERREURS, PAS UNE FENÊTRE VIDE.
//
// LES DÉFAUTS, LUS SUR ac4ca5cd AVANT LE CORRECTIF :
//  * `handlers/query.rs` (vers :1451) : `couverture` est calculée AVANT l'aiguillage par `panneau_avoue::horizon_du_sql`,
//    qui prend pour horizon de `event` la frontière chaude (`cold_boundary`) et dit « ce panneau n'a aucun chemin pour
//    les lire » ; elle était posée telle quelle sur les quatre sorties froides (keyset colonnaire, keyset de l'oracle,
//    vectorisées, union), alors que `stats.cold.served_from` disait le froid lu ;
//  * `query_exec::en_classant_la_voie_froide` range au support toute erreur froide sans note ; aucun producteur froid ne
//    notait l'occupation (`cold_store::pe` perd le code) : une base occupée était servie en 503 « illisible » ;
//  * `cold_store/reader.rs` (vers :1149) et `planner.rs` (vers :781, :978, :1788) : `MIN(day)` lu par
//    `.ok().flatten().map(..).unwrap_or(hi)` — une lecture ratée posait `lo = hi`, une fenêtre froide d'une seconde servie
//    comme la réponse d'une fenêtre « tout » ; `distinct_seal_envs` (vers :1013) : `if let Ok(..)` puis `rows.flatten()`,
//    un environnement illisible était sauté sans un mot.
//
// LES TÉMOINS (profil `cold_tier` sauf (9)) :
// (1) `au1_chaque_voie_froide_lue_porte_l_horizon_de_la_retention_froide` : routeur réel, jeton lecteur, sept voies
//     (keyset colonnaire, fusion vectorisée, pur-froid vectorisé, union paginée voie armée ; keyset de l'oracle, union
//     paginée, union entière voie désarmée), trois fenêtres (dans la rétention froide, dessous, non bornée), `coverage`
//     comparé EN ENTIER à un objet littéral ;
// (2) `au1_page_colonnaire_sans_froid_garde_sa_couverture` : page que la part chaude remplit seule : couverture d'avant
//     à l'octet (frontière chaude, `cold_boundary`) ;
// (3) `au1_couverture_froide_suit_les_politiques_par_index` : politique `prod` à dix jours ; lecteur sans index (route),
//     index `prod` et index sans politique (gestionnaire, jeton à index) ;
// (3b) `au1_couverture_froide_par_index_sur_chaque_voie` : politique `staging` à dix jours, lignes dans `prod` ; sur
//     chacune des six voies (quatre armées, deux désarmées), l'index `prod` reçoit trente jours et la route sans index
//     dix : chaque site passe l'index de l'appelant ;
// (4) `au1_couverture_froide_deux_tenants` : mode 1, deux tenants réels aux rétentions différentes ;
// (5) `au1_plus_ancien_jour_illisible_sert_le_503_illisible` : `day` rendu BLOB, fenêtre non bornée, quatre voies (une
//     par site de lecture du plus vieux jour) : 503 `{error, id}` exactement ;
// (6) `au1_environnement_scelle_illisible_sert_le_503_illisible` : une ligne de sceau à `env_id` BLOB, quatre voies (les
//     trois sites de la liste des environnements), dont la page 2 d'un parcours colonnaire (garde mono-environnement) ;
// (7) `au1_table_des_sceaux_absente_reste_aucun_froid` : base jamais vieillie, quatre voies, deux fenêtres : 200 ;
// (8) `au1_base_froide_occupee_sert_le_503_occupee` : un écrivain tient la base en verrou exclusif ; les quatre
//     producteurs froids, fenêtre non bornée puis bornée, par le classeur et `refus_de_requete` que la route appelle —
//     la route ne peut pas l'atteindre : ses lectures chaudes d'avant l'aiguillage (frontière, couverture) rencontrent
//     le même verrou et servent DÉJÀ la base occupée par la voie chaude ;
// (9) `au1_texte_de_la_voie_froide_ne_note_que_l_occupation` : occupée, verrouillée (chacune avec son texte SQLite),
//     corrompue, E/S portant le texte de l'occupation, ligne illisible ;
// (10) `au1_horizon_froid_direct` : portée non dérivable (à l'octet de l'horizon du panneau), famille chaude plus haute,
//     réglage non lu (event, puis autre famille), pool non pris.
//
// LES MUTATIONS QUI LES FONT ROUGIR (posées sous `cfg!(test)` par une variable de mutation, retirées du source avant le commit) :
// `AU1_HORIZON_FRONTIERE` (1)(3)(4)(10) ; `AU1_SITE_COLONNAIRE`, `AU1_SITE_ORACLE`, `AU1_SITE_VECTORISE`, `AU1_SITE_UNION`
// (1) ; `AU1_PAGE_TOUJOURS_LUE` (2) ; `AU1_SANS_POLITIQUES`, `AU1_ENV_IGNORE` (3) ; `AU1_ENV_NONE_ORACLE` (3)(3b) ;
// `AU1_ENV_NONE_COLONNAIRE`, `AU1_ENV_NONE_VECTORISE`, `AU1_ENV_NONE_UNION` (3b) ; `AU1_TENANT_DEFAUT` (4) ;
// `AU1_MIN_OK`, `AU1_MIN_READER`, `AU1_MIN_781`, `AU1_MIN_978`, `AU1_MIN_1788` (5) ; `AU1_DISTINCT_FLATTEN`,
// `AU1_DISTINCT_READER`, `AU1_DISTINCT_PLAN`, `AU1_DISTINCT_MONO` (6) ; `AU1_ABSENTE_MIN_ERR`, `AU1_ABSENTE_DISTINCT_ERR`
// (7) ; `AU1_OCCUPEE_JAMAIS` (8)(9), `AU1_DDL_PE` (8) ; `AU1_OCCUPEE_POUR_TOUT` (5)(6)(9) ; `AU1_OCCUPEE_PAR_TEXTE` (9) ;
// `AU1_SANS_DELEGATION`, `AU1_MIN_DES_PLANCHERS`, `AU1_NON_LU_IGNORE` (10).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la base occupée n'est jouée qu'au PREMIER énoncé de chaque producteur ; une
// occupation qui surviendrait entre deux énoncés d'une même connexion de l'union (préparation de l'insertion dans la
// table temporaire, vue d'union) reste sur `cold_store::pe` et servie « illisible », faute de témoin déterministe sans
// point d'arrêt dans le code ; une occupation pendant la lecture du réglage de rétention (`HorizonDeLecture::lire`, qui
// lit par `retention_effective_lue`, texte sans code, premier énoncé des voies à index, à fenêtre bornée, vectorisées
// et colonnaire) reste servie « illisible » ; la voie d'union dont le SQL ne lit pas le froid (base `metric`) garde sa
// couverture, mais les deux couvertures y sont égales (aucune famille froide nommée), ce qui rend ce cas inobservable.
// =====================================================================================
mod au1_couverture_froide_et_base_froide_occupee {
    use super::*;
    use crate::query_exec::{en_classant_la_voie_froide, texte_de_la_voie_froide, EchecDeRequete};

    /// `query_exec::NATURE_DE_LA_LECTURE_FROIDE`, recopiée.
    const AU1_NATURE_DE_LA_LECTURE_FROIDE: &str =
        "lecture du tier froid non faite (ouverture, horizon de lecture, hydratation ou décodage d'un fichier), hors du cœur d'exécution";

    /// (9) L'ASSISTANT NE NOTE QUE L'OCCUPATION, PAR LE CODE : `SQLITE_BUSY` et `SQLITE_LOCKED` gardent leur classe à
    /// travers le classeur froid, chacun avec le texte que SQLite lui donne (`sqlite3ErrStr` : « database is locked »
    /// pour BUSY, « database table is locked » pour LOCKED) ; une base corrompue, une ligne illisible, et un code non
    /// occupé qui porterait le texte de BUSY restent du support : la classe ne se lit pas sur le texte.
    #[test]
    fn au1_texte_de_la_voie_froide_ne_note_que_l_occupation() {
        let echec = |code: i32, texte: &str| rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), Some(texte.to_string()));
        let cas: Vec<(&str, rusqlite::Error, bool)> = vec![
            ("SQLITE_BUSY", echec(rusqlite::ffi::SQLITE_BUSY, "database is locked"), true),
            ("SQLITE_LOCKED", echec(rusqlite::ffi::SQLITE_LOCKED, "database table is locked"), true),
            ("SQLITE_CORRUPT", rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT), None), false),
            ("SQLITE_IOERR au texte de BUSY", echec(rusqlite::ffi::SQLITE_IOERR, "database is locked"), false),
            ("ligne illisible", rusqlite::Error::InvalidColumnType(0, "day".to_string(), rusqlite::types::Type::Blob), false),
        ];
        assert!(cas.len() >= 5, "plancher : cinq cas");
        let mut joues = 0;
        for (nom, e, occupe) in cas {
            let texte_attendu = e.to_string();
            let nature_attendue = e.sqlite_error().map(|f| format!("code SQLite {} ({:?})", f.extended_code, f.code));
            match en_classant_la_voie_froide(|| Err::<(), String>(texte_de_la_voie_froide(e))) {
                Err(EchecDeRequete::Occupee { nature, texte }) => {
                    assert!(occupe, "{nom} : classé occupé alors que ce n'est pas une occupation");
                    assert_eq!(Some(nature), nature_attendue, "{nom} : la nature est le code SQLite");
                    assert_eq!(texte, texte_attendu, "{nom} : le texte est celui de l'erreur");
                }
                Err(EchecDeRequete::Support { nature, texte }) => {
                    assert!(!occupe, "{nom} : une base occupée servie « illisible »");
                    assert_eq!(nature, AU1_NATURE_DE_LA_LECTURE_FROIDE, "{nom} : nature de la lecture froide");
                    assert_eq!(texte, texte_attendu, "{nom} : le texte est celui de l'erreur");
                }
                autre => panic!("{nom} : classe inattendue {:?}", autre.err().map(|e| e.texte().to_string())),
            }
            joues += 1;
        }
        assert_eq!(joues, 5, "contrôle : cinq cas joués");
    }

    #[cfg(feature = "cold_tier")]
    mod froid {
        use super::*;
        use crate::handlers::query::refus_de_requete;

        const AU1_JOUR: i64 = 86_400;
        const AU1_SOQL: &str = "search source=froid";
        const AU1_SOQL_COMPTE: &str = "search source=froid | stats count";
        const AU1_SOQL_PAR_MESSAGE: &str = "search source=froid | stats count by message";
        const AU1_RAISON_RETENTION: &str = "retention_floor";
        const AU1_RAISON_NON_BORNEE: &str = "fenetre_non_bornee";
        const AU1_RAISON_COLD: &str = "cold_boundary";
        const AU1_RAISON_NON_MESURE: &str = "horizon_non_mesure";
        /// Les phrases d'horizon (`notice_d_horizon`, `handlers/panneau_avoue.rs`), recopiées.
        const AU1_NOTICE_RETENTION_DEHORS: &str = "PORTÉE INCOMPLÈTE : la fenêtre demandée descend SOUS l'horizon de conservation : sous lui, la rétention peut avoir supprimé les lignes, et ce panneau n'est assuré d'en voir aucune. La part antérieure à cet horizon est hors de portée — un creux ou une courbe qui s'y arrête n'établit donc PAS une absence. Ce n'est pas non plus l'affirmation qu'il manque quelque chose : sur une base plus jeune que cet horizon, il se peut que rien n'ait jamais été supprimé.";
        const AU1_NOTICE_RETENTION_DEDANS: &str = "la fenêtre demandée tient AU-DESSUS de l'horizon de conservation : sous lui, la rétention peut avoir supprimé les lignes, et ce panneau n'est assuré d'en voir aucune : rien n'est resté dehors de ce fait.";
        const AU1_NOTICE_RETENTION_NON_BORNEE: &str = "fenêtre non bornée : tout ce que la base porte encore a été cherché. l'horizon de conservation : sous lui, la rétention peut avoir supprimé les lignes, et ce panneau n'est assuré d'en voir aucune — ce panneau ne voit rien au-delà, quelle que soit la fenêtre demandée.";
        const AU1_NOTICE_FROID_DEHORS: &str = "PORTÉE INCOMPLÈTE : la fenêtre demandée descend SOUS la frontière du vieillissement froid : sous elle, les lignes ont quitté la base vive et ce panneau n'a aucun chemin pour les lire. La part antérieure à cet horizon est hors de portée — un creux ou une courbe qui s'y arrête n'établit donc PAS une absence. Ce n'est pas non plus l'affirmation qu'il manque quelque chose : sur une base plus jeune que cet horizon, il se peut que rien n'ait jamais été supprimé.";
        const AU1_NOTICE_FROID_NON_BORNEE: &str = "fenêtre non bornée : tout ce que la base porte encore a été cherché. la frontière du vieillissement froid : sous elle, les lignes ont quitté la base vive et ce panneau n'a aucun chemin pour les lire — ce panneau ne voit rien au-delà, quelle que soit la fenêtre demandée.";
        /// Les deux aveux d'un horizon non mesuré (`panneau_avoue.rs`), recopiés.
        const AU1_NOTICE_POOL: &str = "le pool de lecture n'a pas pu être pris ; l'horizon n'a PAS été mesuré. Cette réponse ne dit donc RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";
        fn au1_notice_reglage_non_lu(cle: &str) -> String {
            format!(
                "l'horizon de conservation de ce panneau n'est PAS établi : le réglage de rétention écrit `{cle}` n'a pas pu être lu (valeur non entière, ou lecture refusée), et aucun horizon n'est calculé sur l'environnement ou le défaut. Cette réponse ne dit donc RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas."
            )
        }
        /// `CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE` et `CAUSE_REQUETE_NON_SERVIE_BASE_OCCUPEE` (`handlers/query.rs`), recopiées.
        const AU1_CAUSE_ILLISIBLE: &str = "REQUÊTE NON SERVIE : la base n'a pas pu être lue (erreur du support : entrée-sortie, disque, fichier illisible ou corrompu) — ce n'est PAS un résultat vide, et rien n'est rendu. Réessayez ; si le refus persiste, la base est illisible : l'exploitant en trouve le code au journal.";
        const AU1_CAUSE_OCCUPEE: &str = "REQUÊTE NON SERVIE : la base est occupée (verrou tenu par une autre opération) — ce n'est PAS un résultat vide, et rien n'est rendu. Réessayez dans un instant.";

        /// L'aveu d'horizon attendu, objet ENTIER.
        fn au1_couverture(depuis: i64, calcule_a: i64, horizon_ts: i64, dehors: bool, raison: &str, notice: &str) -> Value {
            json!({
                "searched_from": depuis,
                "calcule_a": calcule_a,
                "horizon_ts": horizon_ts,
                "older_outside_window": dehors,
                "reason": raison,
                "notice": notice,
            })
        }

        fn au1_poser_reglage(conn: &Connection, cle: &str, valeur: &str) {
            conn.execute("INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global',?1,?2)", params![cle, valeur]).expect("fixture : réglage posé");
        }

        /// POST `/api/query` par le routeur réel : statut et corps décodé (trames recollées).
        async fn au1_envoi(addr: std::net::SocketAddr, authz: &str, corps: &Value) -> (u16, Value) {
            let entetes = [("Content-Type", "application/json")];
            let (code, brut) = router_probe_envoi(addr, "POST", "/api/query", Some(authz), &entetes, &corps.to_string()).await;
            let (tete, c) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière : {brut}"));
            let octets: Vec<u8> = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
                shell_decouper(c.as_bytes()).unwrap_or_else(|| panic!("trame chunked : {brut}"))
            } else {
                c.as_bytes().to_vec()
            };
            let v: Value = serde_json::from_slice(&octets).unwrap_or_else(|e| panic!("réponse illisible ({e}) : {brut}"));
            (code, v)
        }

        /// Appel DIRECT du gestionnaire (identité choisie : index, tenant).
        async fn au1_direct(st: &AppState, au: AuthUser, corps: &Value) -> (u16, Value) {
            let r = crate::handlers::query::query(State(st.clone()), Extension(au), Json(corps.clone())).await;
            let code = r.status().as_u16();
            let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
            (code, serde_json::from_slice(&b).expect("réponse JSON"))
        }

        fn au1_lecteur(tenant: &str, env: Option<&str>) -> AuthUser {
            AuthUser { name: "lecteur-au1".into(), role: "viewer".into(), tenant: tenant.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: env.map(str::to_string) }
        }

        /// La provenance publiée par la voie (vectorisées : `stats.served_from` ; autres : `stats.cold.served_from`).
        fn au1_provenance(voie: &str, v: &Value) -> Value {
            if voie.starts_with("cold-vectorized") {
                v["stats"]["served_from"].clone()
            } else {
                v["stats"]["cold"]["served_from"].clone()
            }
        }

        /// Le 503 nommé : `{error, id}` exactement, la phrase attendue, un identifiant de corrélation.
        fn au1_refus(contexte: &str, code: u16, v: &Value, cause: &str) {
            assert_eq!(code, 503, "{contexte} : statut 503 : {v}");
            let mut cles: Vec<&String> = v.as_object().map(|o| o.keys().collect()).unwrap_or_default();
            cles.sort();
            assert_eq!(cles, vec!["error", "id"], "{contexte} : exactement `error` et `id` : {v}");
            assert_eq!(v["error"], json!(cause), "{contexte} : la phrase");
            assert!(v["id"].as_str().unwrap_or_default().starts_with("plume-e"), "{contexte} : identifiant de corrélation : {v}");
        }

        /// Les quatre voies d'un banc ARMÉ, chacune lisant un site distinct du plus vieux jour / des environnements :
        /// (nom, corps, provenance attendue au nominal).
        fn au1_voies_armees(banc: &BancFroidSurLaRoute, depuis: i64) -> Vec<(&'static str, Value, &'static str)> {
            let frontiere = banc.minuit - 2 * AU1_JOUR;
            let jusqua = banc.maintenant + 60;
            vec![
                ("keyset colonnaire", json!({ "soql": AU1_SOQL, "from": depuis, "to": jusqua, "limit": 10, "keyset": true }), "hot+cold-vectorized-keyset"),
                ("fusion vectorisée", json!({ "soql": AU1_SOQL_COMPTE, "from": depuis, "to": jusqua }), "cold-vectorized-merge"),
                ("pur-froid vectorisé", json!({ "soql": AU1_SOQL_COMPTE, "from": depuis, "to": frontiere - 1 }), "cold-vectorized"),
                ("union paginée", json!({ "soql": AU1_SOQL, "from": depuis, "to": jusqua, "limit": 10 }), "hot+cold"),
            ]
        }

        /// (1) CHAQUE VOIE QUI A LU LE FROID, PAR LA ROUTE, AU RÔLE LECTEUR : l'horizon est le premier jour servi par la
        /// rétention froide (trente jours ; fenêtre chaude du banc : deux jours, donc `frontière + 2 j - 30 j`).
        #[tokio::test]
        async fn au1_chaque_voie_froide_lue_porte_l_horizon_de_la_retention_froide() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write(); // le banc froid pose l'environnement
            let mut joues = 0;
            for vectorise in [true, false] {
                let banc = BancFroidSurLaRoute::monter(if vectorise { "au1-cov-armee" } else { "au1-cov-desarmee" }, vectorise).await;
                banc.vieillir();
                au1_poser_reglage(&banc.st.db.lock(), "retention_days", "30");
                let frontiere = banc.minuit - 2 * AU1_JOUR;
                let horizon = frontiere + 2 * AU1_JOUR - 30 * AU1_JOUR;
                let fenetres = [("dans la rétention froide", banc.base_froide - 60), ("sous la rétention froide", frontiere - 40 * AU1_JOUR), ("non bornée", 0)];
                for (fenetre, depuis) in fenetres {
                    let voies: Vec<(&str, Value, &str)> = if vectorise {
                        au1_voies_armees(&banc, depuis)
                    } else {
                        let jusqua = banc.maintenant + 60;
                        vec![
                            ("keyset de l'oracle", json!({ "soql": AU1_SOQL, "from": depuis, "to": jusqua, "limit": 10, "keyset": true }), "hot+cold"),
                            ("union paginée", json!({ "soql": AU1_SOQL, "from": depuis, "to": jusqua, "limit": 10 }), "hot+cold"),
                            ("union entière", json!({ "soql": AU1_SOQL_PAR_MESSAGE, "from": depuis, "to": jusqua }), "hot+cold"),
                        ]
                    };
                    assert!(voies.len() >= 3, "plancher : au moins trois voies par banc");
                    for (voie, corps, provenance) in voies {
                        let (code, v) = au1_envoi(banc.addr, &banc.authz, &corps).await;
                        assert_eq!(code, 200, "contrôle : {voie} {fenetre} servi : {v}");
                        assert_eq!(au1_provenance(provenance, &v), json!(provenance), "contrôle : {voie} est servi par la voie visée : {v}");
                        assert_eq!(v["stats"]["cold"]["boundary_ts"], json!(frontiere), "contrôle : frontière du banc : {v}");
                        let calcule_a = v["stats"]["coverage"]["calcule_a"].as_i64().unwrap_or_else(|| panic!("{voie} {fenetre} : pas de `stats.coverage` : {v}"));
                        let attendu = match depuis {
                            0 => au1_couverture(0, calcule_a, horizon, false, AU1_RAISON_NON_BORNEE, AU1_NOTICE_RETENTION_NON_BORNEE),
                            d if d < horizon => au1_couverture(d, calcule_a, horizon, true, AU1_RAISON_RETENTION, AU1_NOTICE_RETENTION_DEHORS),
                            d => au1_couverture(d, calcule_a, horizon, false, AU1_RAISON_RETENTION, AU1_NOTICE_RETENTION_DEDANS),
                        };
                        assert_eq!(v["stats"]["coverage"], attendu, "{voie} {fenetre} : l'horizon de la rétention froide, objet entier");
                        joues += 1;
                    }
                }
            }
            assert_eq!(joues, 21, "contrôle : sept voies, trois fenêtres");
        }

        /// (2) UNE PAGE COLONNAIRE QUE LA PART CHAUDE REMPLIT SEULE N'A PAS LU LE FROID : sa couverture est celle d'avant,
        /// à l'octet (frontière chaude, « aucun chemin »).
        #[tokio::test]
        async fn au1_page_colonnaire_sans_froid_garde_sa_couverture() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            let banc = BancFroidSurLaRoute::monter("au1-cov-sans-froid", true).await;
            banc.vieillir();
            au1_poser_reglage(&banc.st.db.lock(), "retention_days", "30");
            let frontiere = banc.minuit - 2 * AU1_JOUR;
            let mut joues = 0;
            for depuis in [banc.base_froide - 60, 0] {
                let corps = json!({ "soql": AU1_SOQL, "from": depuis, "to": banc.maintenant + 60, "limit": 1, "keyset": true });
                let (code, v) = au1_envoi(banc.addr, &banc.authz, &corps).await;
                assert_eq!(code, 200, "contrôle : page servie : {v}");
                assert_eq!(v["stats"]["cold"]["served_from"], json!("hot-vectorized-keyset"), "contrôle : la part chaude remplit la page : {v}");
                let calcule_a = v["stats"]["coverage"]["calcule_a"].as_i64().unwrap_or_else(|| panic!("pas de `stats.coverage` : {v}"));
                let attendu = if depuis > 0 {
                    au1_couverture(depuis, calcule_a, frontiere, true, AU1_RAISON_COLD, AU1_NOTICE_FROID_DEHORS)
                } else {
                    au1_couverture(0, calcule_a, frontiere, false, AU1_RAISON_NON_BORNEE, AU1_NOTICE_FROID_NON_BORNEE)
                };
                assert_eq!(v["stats"]["coverage"], attendu, "depuis {depuis} : la couverture d'avant, objet entier");
                joues += 1;
            }
            assert_eq!(joues, 2, "contrôle : deux fenêtres");
        }

        /// (3) L'HORIZON FROID EST CELUI DE L'INDEX : politique `prod` à dix jours. Sans index nommé (route, lecteur), la
        /// lecture hydrate chaque index et l'horizon est le plus tardif (dix jours) ; l'index `prod` : dix jours ; un index
        /// sans politique : la bande globale (trente jours).
        #[tokio::test]
        async fn au1_couverture_froide_suit_les_politiques_par_index() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            let banc = BancFroidSurLaRoute::monter("au1-cov-politiques", false).await;
            banc.vieillir();
            {
                let c = banc.st.db.lock();
                au1_poser_reglage(&c, "retention_days", "30");
                c.execute("INSERT INTO index_policy(name,retention_days,enabled) VALUES('prod',10,1)", []).expect("fixture : politique par index");
            }
            let frontiere = banc.minuit - 2 * AU1_JOUR;
            let depuis = frontiere - 15 * AU1_JOUR;
            let corps = json!({ "soql": AU1_SOQL, "from": depuis, "to": banc.maintenant + 60, "limit": 10, "keyset": true });
            let mut rendus: Vec<(&str, u16, Value, i64)> = Vec::new();
            let (code, v) = au1_envoi(banc.addr, &banc.authz, &corps).await;
            rendus.push(("lecteur sans index (route)", code, v, 10));
            let (code, v) = au1_direct(&banc.st, au1_lecteur("default", Some("prod")), &corps).await;
            rendus.push(("index prod", code, v, 10));
            let (code, v) = au1_direct(&banc.st, au1_lecteur("default", Some("staging")), &corps).await;
            rendus.push(("index sans politique", code, v, 30));
            assert!(rendus.len() >= 3, "plancher : trois identités");
            for (qui, code, v, jours) in &rendus {
                assert_eq!(*code, 200, "contrôle : {qui} servi : {v}");
                assert_eq!(v["stats"]["cold"]["served_from"], json!("hot+cold"), "contrôle : {qui} lit le froid : {v}");
                let calcule_a = v["stats"]["coverage"]["calcule_a"].as_i64().unwrap_or_else(|| panic!("{qui} : pas de `stats.coverage` : {v}"));
                let horizon = frontiere + 2 * AU1_JOUR - jours * AU1_JOUR;
                let (dehors, notice) = if depuis < horizon { (true, AU1_NOTICE_RETENTION_DEHORS) } else { (false, AU1_NOTICE_RETENTION_DEDANS) };
                assert_eq!(*jours == 10, dehors, "contrôle : la fenêtre sépare les deux horizons");
                assert_eq!(v["stats"]["coverage"], au1_couverture(depuis, calcule_a, horizon, dehors, AU1_RAISON_RETENTION, notice), "{qui} : horizon de {jours} jours");
            }
        }

        /// (3b) L'INDEX DE L'APPELANT EST PASSÉ À L'HORIZON SUR CHAQUE VOIE QUI A LU LE FROID : politique à dix jours sur
        /// `staging`, bande globale à trente jours, lignes dans `prod`. L'index `prod` (gestionnaire, jeton à index) : trente
        /// jours ; sans index (route, lecteur) : le plus tardif de la portée, dix jours. Voies armées (keyset colonnaire,
        /// fusion et pur-froid vectorisés, union paginée) puis désarmées (keyset de l'oracle, union paginée) : une voie qui
        /// perdrait l'index donnerait dix jours à l'index `prod`.
        #[tokio::test]
        async fn au1_couverture_froide_par_index_sur_chaque_voie() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            let mut joues = 0;
            for vectorise in [true, false] {
                let banc = BancFroidSurLaRoute::monter(if vectorise { "au1-index-armee" } else { "au1-index-desarmee" }, vectorise).await;
                banc.vieillir();
                {
                    let c = banc.st.db.lock();
                    au1_poser_reglage(&c, "retention_days", "30");
                    c.execute("INSERT INTO index_policy(name,retention_days,enabled) VALUES('staging',10,1)", []).expect("fixture : politique par index");
                }
                let frontiere = banc.minuit - 2 * AU1_JOUR;
                let depuis = frontiere - 15 * AU1_JOUR;
                let voies: Vec<(&str, Value, &str)> = if vectorise {
                    au1_voies_armees(&banc, depuis)
                } else {
                    let jusqua = banc.maintenant + 60;
                    vec![
                        ("keyset de l'oracle", json!({ "soql": AU1_SOQL, "from": depuis, "to": jusqua, "limit": 10, "keyset": true }), "hot+cold"),
                        ("union paginée", json!({ "soql": AU1_SOQL, "from": depuis, "to": jusqua, "limit": 10 }), "hot+cold"),
                    ]
                };
                assert!(voies.len() >= 2, "plancher : deux voies par banc");
                for (voie, corps, provenance) in voies {
                    let (code, v) = au1_envoi(banc.addr, &banc.authz, &corps).await;
                    let par_route = ("sans index (route)", code, v, 10_i64);
                    let (code, v) = au1_direct(&banc.st, au1_lecteur("default", Some("prod")), &corps).await;
                    let par_index = ("index prod", code, v, 30_i64);
                    for (qui, code, v, jours) in [par_route, par_index] {
                        assert_eq!(code, 200, "contrôle : {voie}, {qui} servi : {v}");
                        assert_eq!(au1_provenance(provenance, &v), json!(provenance), "contrôle : {voie}, {qui} est servi par la voie visée : {v}");
                        let calcule_a = v["stats"]["coverage"]["calcule_a"].as_i64().unwrap_or_else(|| panic!("{voie}, {qui} : pas de `stats.coverage` : {v}"));
                        let horizon = frontiere + 2 * AU1_JOUR - jours * AU1_JOUR;
                        let (dehors, notice) = if depuis < horizon { (true, AU1_NOTICE_RETENTION_DEHORS) } else { (false, AU1_NOTICE_RETENTION_DEDANS) };
                        assert_eq!(jours == 10, dehors, "contrôle : la fenêtre sépare les deux horizons");
                        assert_eq!(
                            v["stats"]["coverage"],
                            au1_couverture(depuis, calcule_a, horizon, dehors, AU1_RAISON_RETENTION, notice),
                            "{voie}, {qui} : horizon de {jours} jours"
                        );
                        joues += 1;
                    }
                }
            }
            assert_eq!(joues, 12, "contrôle : six voies, deux identités");
        }

        /// Retire à la chute les variables posées par le témoin (4), panic compris.
        struct Au1EnvironnementPose(Vec<&'static str>);
        impl Drop for Au1EnvironnementPose {
            fn drop(&mut self) {
                for k in &self.0 {
                    std::env::remove_var(k);
                }
            }
        }

        /// (4) DEUX TENANTS RÉELS (mode 1), RÉTENTIONS DIFFÉRENTES, MÊME FENÊTRE, voie de l'oracle : l'horizon froid est
        /// mesuré sur la base de l'appelant (aucun fichier froid n'est requis : le SQL lit le bras froid, vide).
        #[tokio::test]
        async fn au1_couverture_froide_deux_tenants() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            let poses: [(&'static str, &str); 3] = [("PLUME_COLD_TIER", "1"), ("PLUME_COLD_HOT_WINDOW_DAYS", "2"), ("PLUME_COLD_VECTORIZED", "0")];
            std::env::remove_var("PLUME_COLD_DIR");
            for (k, v) in poses {
                std::env::set_var(k, v);
            }
            let _nettoyage = Au1EnvironnementPose(poses.iter().map(|(k, _)| *k).collect());
            let (st, _dir) = mk_mode1_state();
            let maintenant = now();
            let tenants = [("au1-alpha", 30_i64), ("au1-beta", 20_i64)];
            for (t, jours) in tenants {
                let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-au1")), Json(json!({ "id": t, "name": t }))).await;
                assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
                let base = st.tenants.handle_for(t).expect("contrôle : base du tenant");
                au1_poser_reglage(&base.lock(), "retention_days", &jours.to_string());
            }
            let depuis = maintenant - 25 * AU1_JOUR;
            let corps = json!({ "soql": AU1_SOQL, "from": depuis, "to": maintenant + 60, "limit": 10, "keyset": true });
            let mut joues = 0;
            for (t, jours) in tenants {
                let (code, v) = au1_direct(&st, au1_lecteur(t, None), &corps).await;
                assert_eq!(code, 200, "contrôle : {t} servi : {v}");
                assert_eq!(v["stats"]["cold"]["served_from"], json!("hot+cold"), "contrôle : {t} lit le froid : {v}");
                let frontiere = v["stats"]["cold"]["boundary_ts"].as_i64().unwrap_or_else(|| panic!("contrôle : frontière publiée : {v}"));
                let calcule_a = v["stats"]["coverage"]["calcule_a"].as_i64().unwrap_or_else(|| panic!("{t} : pas de `stats.coverage` : {v}"));
                let horizon = frontiere + 2 * AU1_JOUR - jours * AU1_JOUR;
                let (dehors, notice) = if jours == 20 { (true, AU1_NOTICE_RETENTION_DEHORS) } else { (false, AU1_NOTICE_RETENTION_DEDANS) };
                assert_eq!(v["stats"]["coverage"], au1_couverture(depuis, calcule_a, horizon, dehors, AU1_RAISON_RETENTION, notice), "{t} : horizon sur la base de l'appelant ({jours} j)");
                joues += 1;
            }
            assert_eq!(joues, 2, "contrôle : deux tenants");
        }

        /// (5) LE PLUS VIEUX JOUR SCELLÉ ILLISIBLE (toutes les lignes à `day` BLOB : `MIN` rend un BLOB), FENÊTRE NON
        /// BORNÉE : chacune des quatre voies lit un site distinct (union : `reader`, keyset colonnaire : traversée,
        /// fusion et pur-froid : leurs bornes) et sert le 503 de la base illisible — avant, `lo = hi` et un 200.
        #[tokio::test]
        async fn au1_plus_ancien_jour_illisible_sert_le_503_illisible() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            let banc = BancFroidSurLaRoute::monter("au1-min-illisible", true).await;
            banc.vieillir();
            let voies = au1_voies_armees(&banc, 0);
            assert!(voies.len() >= 4, "plancher : quatre voies");
            for (voie, corps, provenance) in &voies {
                let (code, v) = au1_envoi(banc.addr, &banc.authz, corps).await;
                assert_eq!(code, 200, "contrôle : {voie} nominal : {v}");
                assert_eq!(au1_provenance(provenance, &v), json!(provenance), "contrôle : {voie} est servi par la voie visée : {v}");
            }
            let n = banc.st.db.lock().execute("UPDATE cold_seal SET day = CAST(day AS BLOB)", []).expect("fixture : jours rendus illisibles");
            assert!(n >= 1, "contrôle : au moins un sceau rendu illisible");
            let mut joues = 0;
            for (voie, corps, _) in &voies {
                let (code, v) = au1_envoi(banc.addr, &banc.authz, corps).await;
                au1_refus(voie, code, &v, AU1_CAUSE_ILLISIBLE);
                joues += 1;
            }
            assert_eq!(joues, 4, "contrôle : quatre voies jouées");
        }

        /// (6) UNE LIGNE DE SCEAU À `env_id` ILLISIBLE (BLOB), cinq jours en arrière, fenêtre bornée : la liste des
        /// environnements n'est pas lue ; trois sites (union : `reader` ; fusion et pur-froid : le plan de balayage ; page 2
        /// d'un parcours colonnaire : la garde mono-environnement, seule à voir ce jour au-dessus du curseur) — avant,
        /// `rows.flatten()` sautait la ligne et la réponse était servie comme complète.
        #[tokio::test]
        async fn au1_environnement_scelle_illisible_sert_le_503_illisible() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            let banc = BancFroidSurLaRoute::monter("au1-env-illisible", true).await;
            banc.vieillir();
            let depuis = banc.base_froide - 60;
            let mut voies = au1_voies_armees(&banc, depuis);
            // La page 2 du parcours colonnaire : son curseur est sous la frontière, au jour des lignes froides ; la garde
            // mono-environnement juge la fenêtre de la TRAVERSÉE, le plan de balayage celle de la page (sous le curseur).
            let (code, page1) = au1_envoi(banc.addr, &banc.authz, &voies[0].1).await;
            assert_eq!(code, 200, "contrôle : page 1 servie : {page1}");
            let curseur = page1["next_cursor"].clone();
            assert!(curseur["espace"].is_string() && curseur["ts"].as_i64().unwrap_or(i64::MAX) < banc.minuit - 2 * AU1_JOUR, "contrôle : curseur colonnaire sous la frontière : {page1}");
            voies.push((
                "page 2 colonnaire",
                json!({ "soql": AU1_SOQL, "from": depuis, "to": banc.maintenant + 60, "limit": 10, "keyset": true, "cursor": curseur }),
                "hot+cold-vectorized-keyset",
            ));
            assert!(voies.len() >= 5, "plancher : cinq voies");
            for (voie, corps, provenance) in &voies {
                let (code, v) = au1_envoi(banc.addr, &banc.authz, corps).await;
                assert_eq!(code, 200, "contrôle : {voie} nominal : {v}");
                assert_eq!(au1_provenance(provenance, &v), json!(provenance), "contrôle : {voie} est servi par la voie visée : {v}");
            }
            let jour = (banc.minuit - 5 * AU1_JOUR).div_euclid(AU1_JOUR);
            let ts = banc.minuit - 5 * AU1_JOUR + 60;
            banc.st
                .db
                .lock()
                .execute(
                    "INSERT INTO cold_seal(env_id,day,seq,expected_rows,sealed_ts,max_id,ts_min,ts_max,lo_ts,lo_id,hi_id) \
                     VALUES(CAST('staging' AS BLOB),?1,0,1,?2,0,?2,?2,?2,0,0)",
                    params![jour, ts],
                )
                .expect("fixture : sceau à environnement illisible");
            let mut joues = 0;
            for (voie, corps, _) in &voies {
                let (code, v) = au1_envoi(banc.addr, &banc.authz, corps).await;
                au1_refus(voie, code, &v, AU1_CAUSE_ILLISIBLE);
                joues += 1;
            }
            assert_eq!(joues, 5, "contrôle : cinq voies jouées");
        }

        /// (7) BASE JAMAIS VIEILLIE : la table des sceaux n'existe pas. C'est « aucun froid », pas une lecture ratée : les
        /// quatre voies, fenêtre non bornée (plus vieux jour puis environnements) et bornée (environnements), servent 200.
        #[tokio::test]
        async fn au1_table_des_sceaux_absente_reste_aucun_froid() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            let banc = BancFroidSurLaRoute::monter("au1-sans-sceaux", true).await;
            let tables: i64 = banc
                .st
                .db
                .lock()
                .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cold_seal'", [], |r| r.get(0))
                .expect("contrôle : catalogue lisible");
            assert_eq!(tables, 0, "contrôle : une base jamais vieillie ne porte pas la table des sceaux");
            let mut joues = 0;
            for depuis in [0, banc.base_froide - 60] {
                let voies = au1_voies_armees(&banc, depuis);
                assert!(voies.len() >= 4, "plancher : quatre voies");
                for (voie, corps, provenance) in &voies {
                    let (code, v) = au1_envoi(banc.addr, &banc.authz, corps).await;
                    assert_eq!(code, 200, "{voie} depuis {depuis} : aucun froid n'est pas une base illisible : {v}");
                    assert_eq!(au1_provenance(provenance, &v), json!(provenance), "contrôle : {voie} est servi par la voie visée : {v}");
                    joues += 1;
                }
            }
            assert_eq!(joues, 8, "contrôle : quatre voies, deux fenêtres");
        }

        /// (8) UN ÉCRIVAIN TIENT LA BASE EN VERROU EXCLUSIF : chaque producteur froid, fenêtre non bornée (plus vieux
        /// jour) puis bornée (table temporaire de l'union, liste des environnements), classé par le classeur que la route
        /// appelle puis servi par `refus_de_requete` : 503 de la base OCCUPÉE, `{error, id}` exactement.
        #[tokio::test]
        async fn au1_base_froide_occupee_sert_le_503_occupee() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            let banc = BancFroidSurLaRoute::monter("au1-occupee", true).await;
            banc.vieillir();
            let frontiere = banc.minuit - 2 * AU1_JOUR;
            let jusqua = banc.maintenant + 60;
            let chemin = banc.chemin_base.clone();
            // L'ÉCRIVAIN QUI TIENT LE VERROU est la connexion d'écriture du banc. En WAL, toute connexion ouverte garde un
            // verrou partagé sur le fichier de base : le verrou exclusif n'est obtenu que par la SEULE connexion ouverte
            // (aucune lecture du pool n'a encore eu lieu sur ce chemin), et tout lecteur qui ouvre ensuite reçoit
            // `SQLITE_BUSY` au terme de son délai d'attente.
            assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(&chemin), 0, "instrument : aucune connexion de lecture ouverte sur la base");
            let verrou = banc.st.db.lock();
            verrou
                .execute_batch("PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global','au1-verrou','1');")
                .expect("fixture : verrou exclusif pris");
            {
                let sonde = Connection::open_with_flags(&chemin, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).expect("instrument : sonde ouverte");
                crate::crypto::apply_key_for(&sonde, &chemin);
                let lu = sonde.query_row("SELECT COUNT(*) FROM event", [], |r| r.get::<_, i64>(0));
                assert!(
                    matches!(lu.as_ref().err().and_then(|e| e.sqlite_error_code()), Some(rusqlite::ErrorCode::DatabaseBusy)),
                    "instrument : la base doit être OCCUPÉE pour tout autre lecteur : {lu:?}"
                );
            }
            let conf = banc.conf.clone();
            let mut rendus: Vec<(String, Result<(), EchecDeRequete>)> = Vec::new();
            for depuis in [0, banc.base_froide - 60] {
                let sql = soql_to_sql_x(AU1_SOQL, depuis, jusqua, None).expect("contrôle : GXQL compilé");
                rendus.push((
                    format!("union depuis {depuis}"),
                    en_classant_la_voie_froide(|| crate::cold_store::cold_union_query(&chemin, &conf, None, depuis, jusqua, frontiere, &sql, None, 60_000, None, &[]).map(|_| ())),
                ));
                rendus.push((
                    format!("pur-froid depuis {depuis}"),
                    en_classant_la_voie_froide(|| crate::cold_store::cold_vectorized_try(&chemin, &conf, None, depuis, frontiere - 1, frontiere, AU1_SOQL_COMPTE, true, 60_000, &[]).map(|_| ())),
                ));
                rendus.push((
                    format!("fusion depuis {depuis}"),
                    en_classant_la_voie_froide(|| {
                        crate::cold_store::cold_vectorized_merge_try(&chemin, &conf, None, depuis, jusqua, frontiere, AU1_SOQL_COMPTE, true, 60_000, None, &[]).map(|_| ())
                    }),
                ));
                rendus.push((
                    format!("keyset colonnaire depuis {depuis}"),
                    en_classant_la_voie_froide(|| crate::cold_store::cold_keyset_page(&chemin, &conf, None, depuis, jusqua, frontiere, AU1_SOQL, true, None, 10, &[]).map(|_| ())),
                ));
            }
            verrou.execute_batch("ROLLBACK; PRAGMA locking_mode=NORMAL;").expect("fixture : verrou rendu");
            drop(verrou);
            assert!(rendus.len() >= 8, "plancher : quatre producteurs, deux fenêtres");
            let mut joues = 0;
            for (quoi, issue) in rendus {
                let echec = match issue {
                    Err(e) => e,
                    Ok(()) => panic!("{quoi} : servi sur une base occupée"),
                };
                let r = refus_de_requete(echec, "/api/query", "default");
                let code = r.status().as_u16();
                let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
                let v: Value = serde_json::from_slice(&b).expect("refus JSON");
                au1_refus(&quoi, code, &v, AU1_CAUSE_OCCUPEE);
                joues += 1;
            }
            assert_eq!(joues, 8, "contrôle : huit lectures jouées");
        }

        /// (10) LA FONCTION D'HORIZON FROID, APPELÉE DIRECTEMENT (bras qu'aucune voie de la route n'atteint seule).
        #[tokio::test]
        async fn au1_horizon_froid_direct() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les réglages lisent l'environnement en repli
            let (st, base) = router_test_state("au1-horizon-direct");
            let chemin = base.as_str().to_string();
            let mut conf: HashMap<String, String> = HashMap::new();
            conf.insert("PLUME_COLD_HOT_WINDOW_DAYS".to_string(), "2".to_string());
            let maintenant: i64 = 1_800_000_000;
            let frontiere = (maintenant.div_euclid(AU1_JOUR) - 2) * AU1_JOUR;
            let horizon_froid = frontiere + 2 * AU1_JOUR - 30 * AU1_JOUR;
            let depuis = frontiere - 10 * AU1_JOUR;
            {
                let c = st.db.lock();
                au1_poser_reglage(&c, "retention_days", "30");
                au1_poser_reglage(&c, "metric_raw_hours", "48");
            }
            let mut joues = 0;
            // (a) Aucune famille nommée : l'aveu de l'horizon du panneau, à l'octet.
            let sql_sans = "SELECT ip FROM banned_ip";
            assert_eq!(
                crate::panneau_avoue::horizon_de_la_voie_froide_lue(&chemin, &conf, sql_sans, depuis, maintenant, frontiere, None),
                crate::panneau_avoue::horizon_du_sql(&chemin, &conf, sql_sans, depuis, maintenant),
                "portée non dérivable : l'aveu du panneau"
            );
            assert_eq!(crate::panneau_avoue::horizon_du_sql(&chemin, &conf, sql_sans, depuis, maintenant)["reason"], json!("portee_non_derivable"), "contrôle");
            joues += 1;
            // (b) `event` seul : l'horizon froid ; `event` et `metric` : le plancher chaud de `metric` (48 h) est plus haut.
            let sql_event = "SELECT ts FROM event";
            assert_eq!(
                crate::panneau_avoue::horizon_de_la_voie_froide_lue(&chemin, &conf, sql_event, depuis, maintenant, frontiere, None),
                au1_couverture(depuis, maintenant, horizon_froid, false, AU1_RAISON_RETENTION, AU1_NOTICE_RETENTION_DEDANS),
                "event seul : horizon de la rétention froide"
            );
            joues += 1;
            let sql_deux = "SELECT ts FROM event UNION ALL SELECT ts FROM metric";
            let plancher_metric = maintenant - 48 * 3_600;
            assert_eq!(
                crate::panneau_avoue::horizon_de_la_voie_froide_lue(&chemin, &conf, sql_deux, depuis, maintenant, frontiere, None),
                au1_couverture(depuis, maintenant, plancher_metric, true, AU1_RAISON_RETENTION, AU1_NOTICE_RETENTION_DEHORS),
                "event et metric : le plus haut des planchers"
            );
            joues += 1;
            // (c) Réglage non lu : celui de `event` (horizon froid), puis celui d'une autre famille.
            au1_poser_reglage(&st.db.lock(), "retention_days", "365.0");
            assert_eq!(
                crate::panneau_avoue::horizon_de_la_voie_froide_lue(&chemin, &conf, sql_event, depuis, maintenant, frontiere, None),
                json!({ "searched_from": depuis, "calcule_a": maintenant, "reason": AU1_RAISON_NON_MESURE, "reglage_non_lu": "retention_days", "notice": au1_notice_reglage_non_lu("retention_days") }),
                "rétention froide non lue"
            );
            joues += 1;
            {
                let c = st.db.lock();
                au1_poser_reglage(&c, "retention_days", "30");
                au1_poser_reglage(&c, "metric_raw_hours", "quarante-huit");
            }
            assert_eq!(
                crate::panneau_avoue::horizon_de_la_voie_froide_lue(&chemin, &conf, sql_deux, depuis, maintenant, frontiere, None),
                json!({ "searched_from": depuis, "calcule_a": maintenant, "reason": AU1_RAISON_NON_MESURE, "reglage_non_lu": "metric_raw_hours", "notice": au1_notice_reglage_non_lu("metric_raw_hours") }),
                "réglage d'une autre famille non lu"
            );
            joues += 1;
            // (d) Pool non pris : base inexistante.
            let absente = format!("{chemin}.au1-absente/plume.db");
            assert_eq!(
                crate::panneau_avoue::horizon_de_la_voie_froide_lue(&absente, &conf, sql_event, depuis, maintenant, frontiere, None),
                json!({ "searched_from": depuis, "calcule_a": maintenant, "reason": AU1_RAISON_NON_MESURE, "notice": AU1_NOTICE_POOL }),
                "pool non pris"
            );
            joues += 1;
            assert_eq!(joues, 6, "contrôle : six bras joués");
        }
    }
}
