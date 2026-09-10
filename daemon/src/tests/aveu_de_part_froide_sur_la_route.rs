    // `P10.5-k` (2026-09-10) — L'AVEU DE PART FROIDE EST EXERCÉ LÀ OÙ IL EST SERVI : SUR LA RÉPONSE
    // ENTIÈRE DE LA ROUTE.
    //
    // La décision qui produit l'aveu (`ColdUnionMeta::provenance`, dérivée de `parts_lues`) était
    // testée là où elle vit ; aucun témoin ne montait le routeur réel avec le tier froid ALLUMÉ et du
    // froid SEMÉ, si bien qu'un lot pouvait poser ou déplacer `stats.cold` sans qu'aucune exécution n'ait
    // lu ce que le client reçoit. Ce témoin fait les trois choses que la clé demandait : il allume le tier
    // froid par l'environnement (la seule voie que la route lit, `load_config` ne prenant rien de l'état),
    // il vieillit des événements dans la bande froide par le vieillissement RÉEL, et il interroge
    // `POST /api/query` à travers les six couches du routeur, par la fabrique que d'autres familles
    // emploient déjà.
    //
    // TROIS LECTURES, DEUX SENS — ET DEUX MESURES QUI ONT CORRIGÉ L'ÉNONCÉ. (1) AVANT vieillissement,
    // fenêtre franchissant la frontière : la provenance dit DÉJÀ `hot+cold`, avec ZÉRO fichier lu et ZÉRO
    // ligne hydratée — elle dit ce que le SQL a PU lire (les deux bras, le froid étant vide), pas ce qu'il
    // a lu ; ce qui distingue « le froid n'a rien » de « le froid a servi » est le compte de fichiers et de
    // lignes, publié à côté. ET LA ZONE GRISE QUE LA DOCTRINE DU LECTEUR NOMME (« l'aging en RETARD »)
    // EST MESURÉE À LA ROUTE : l'union prend le chaud à `ts >= B` et le froid à `ts < B`, si bien qu'une
    // journée passée sous la frontière mais PAS ENCORE vieillie n'est servie par AUCUN bras — la route rend
    // la seule ligne chaude, 1 au lieu de 121, en disant `hot+cold`. C'est un compromis documenté et
    // signalé par le dead-man's-switch du vieillissement, borné à l'intervalle entre le franchissement de
    // minuit et la passe suivante ; ce témoin le mesure pour qu'il ne soit pas confondu avec une perte
    // silencieuse : le jour où ce compte devient 121, le compromis a été fermé et la cellule doit le dire.
    // (2) APRÈS vieillissement, même fenêtre : `hot+cold`, au moins un fichier lu, autant de lignes
    // hydratées que de lignes vieillies, et le compte est celui de TOUTES les lignes — les 120 ont changé
    // de bras et sont revenues. (3) Fenêtre entièrement chaude : aucun aveu de part froide — la route ne
    // parle du froid que quand la fenêtre l'atteint.
    //
    // CE QUE CE TÉMOIN NE TIENT PAS, DIT PLUTÔT QUE TU : la voie vectorisée (`PLUME_COLD_VECTORIZED=0`
    // ici), qui écrit sa provenance en dur hors du point unique ; la route `/api/search`, dont l'aveu est
    // d'une autre famille (`coverage.reason`) ; et la troncature, que la fixture n'atteint pas (cent
    // vingt lignes, sous tout plafond).
    /// LE BANC FROID SUR LA ROUTE, partagé par les témoins de ce fichier : le tier froid posé par
    /// l'ENVIRONNEMENT (la seule voie que la route lit), la clé de la base posée dans le REGISTRE PAR
    /// TENANT et jamais dans l'environnement, cent vingt lignes huit jours en arrière et une ligne chaude,
    /// le routeur réel servi sur l'adresse de bouclage. Le vieillissement est un geste séparé
    /// (`vieillir`) : un témoin lit avant et après.
    ///
    /// POURQUOI LA CLÉ NE PASSE PAS PAR L'ENVIRONNEMENT, MESURÉ le 2026-09-10 : `open_db` lit la clé globale
    /// (environnement puis fichier de configuration), donc une clé posée là, même sous le verrou en
    /// écriture, s'applique à TOUTE base ouverte par un témoin voisin qui ne tient pas le verrou en lecture
    /// — quatre témoins étrangers ont rougi en une suite (« file is not a database », un 401 de routeur, un
    /// inventaire vide). Le registre est indexé par le chemin de la base : il n'atteint que celle-ci.
    #[cfg(feature = "cold_tier")]
    struct BancFroidSurLaRoute {
        st: AppState,
        _base: crate::tmp_possede::TmpDb,
        _nettoyage: PoseDEnvironnement,
        chemin_base: String,
        conf: HashMap<String, String>,
        maintenant: i64,
        minuit: i64,
        base_froide: i64,
        addr: std::net::SocketAddr,
        authz: String,
    }

    /// Retire à la chute les variables posées ET la clé enregistrée pour le chemin, panic compris : un
    /// témoin qui laisserait le tier froid allumé ou une clé dans le registre changerait le verdict du suivant.
    #[cfg(feature = "cold_tier")]
    struct PoseDEnvironnement(Vec<&'static str>, String);
    #[cfg(feature = "cold_tier")]
    impl Drop for PoseDEnvironnement {
        fn drop(&mut self) {
            for k in &self.0 {
                std::env::remove_var(k);
            }
            crate::crypto::unregister_db_key(&self.1);
        }
    }

    #[cfg(feature = "cold_tier")]
    const JOUR: i64 = 86_400;
    #[cfg(feature = "cold_tier")]
    const LIGNES_FROIDES: i64 = 120;

    #[cfg(feature = "cold_tier")]
    impl BancFroidSurLaRoute {
        /// `vectorise` : arme ou désarme la voie vectorisée (`PLUME_COLD_VECTORIZED`). L'appelant tient le
        /// verrou d'environnement en écriture.
        async fn monter(etiquette: &str, vectorise: bool) -> Self {
            let cle = "plume-cold-route-test-key-do-not-use-in-prod-0000";
            let poses: [(&'static str, &str); 3] = [
                ("PLUME_COLD_TIER", "1"),
                ("PLUME_COLD_HOT_WINDOW_DAYS", "2"),
                ("PLUME_COLD_VECTORIZED", if vectorise { "1" } else { "0" }),
            ];
            // `PLUME_COLD_DIR` volontairement ABSENT : la racine froide dérive du chemin de la base, donc vit
            // dans le répertoire possédé par la fixture et disparaît avec lui.
            std::env::remove_var("PLUME_COLD_DIR");
            for (k, v) in poses {
                std::env::set_var(k, v);
            }
            let mut conf: HashMap<String, String> = HashMap::new();
            for (k, v) in poses {
                conf.insert(k.to_string(), v.to_string());
            }
            // La base est chiffrée par une clé ENREGISTRÉE POUR SON CHEMIN : la fixture, la route et le
            // vieillissement (`cold_base_secret` lit le registre en premier) la partagent sans qu'elle
            // touche l'environnement ni la carte de configuration.
            let (st, base) = router_test_state_avec(etiquette, Some(cle));
            let chemin_base = base.as_str().to_string();
            let nettoyage = PoseDEnvironnement(poses.iter().map(|(k, _)| *k).collect(), chemin_base.clone());
            let maintenant = now();
            let minuit = maintenant.div_euclid(JOUR) * JOUR;
            let base_froide = minuit - 8 * JOUR;
            {
                let c = st.db.lock();
                let tx = c.unchecked_transaction().unwrap();
                for i in 0..LIGNES_FROIDES {
                    tx.execute(
                        "INSERT INTO event(ts,severity,source,category,host,src_ip,dst_ip,url,xff,dedup,engagement_id,origin,env_id,message,fields) \
                         VALUES(?1,1,'froid','test','h-froid','','','','',?2,'','','prod','ligne froide','{}')",
                        params![base_froide + i * 60, format!("froid-{i}")],
                    )
                    .unwrap();
                }
                tx.execute(
                    "INSERT INTO event(ts,severity,source,category,host,src_ip,dst_ip,url,xff,dedup,engagement_id,origin,env_id,message,fields) \
                     VALUES(?1,1,'froid','test','h-froid','','','','','froid-chaud','','','prod','ligne chaude','{}')",
                    params![maintenant - 60],
                )
                .unwrap();
                tx.commit().unwrap();
            }
            let addr = router_serve(st.clone()).await;
            Self { st, _base: base, _nettoyage: nettoyage, chemin_base, conf, maintenant, minuit, base_froide, addr, authz: viewer_authz() }
        }

        /// Le vieillissement RÉEL, puis la preuve qu'il a déplacé les lignes : la table chaude ne porte plus
        /// la journée froide, et la racine froide dérivée porte au moins un fichier.
        fn vieillir(&self) {
            crate::cold_store::cold_age_run(&self.st.db, &self.chemin_base, &self.conf, self.minuit, 30);
            let restantes: i64 = self
                .st
                .db
                .lock()
                .query_row("SELECT COUNT(*) FROM event WHERE ts < ?1", params![self.minuit - 2 * JOUR], |r| r.get(0))
                .unwrap();
            assert_eq!(restantes, 0, "instrument : le vieillissement n'a pas déplacé la journée froide hors de la table chaude");
            let racine_froide = std::path::PathBuf::from(format!("{}.cold", self.chemin_base));
            let fichiers = std::fs::read_dir(&racine_froide).map(|d| d.count()).unwrap_or(0);
            assert!(fichiers >= 1, "instrument : aucune entrée sous la racine froide dérivée {}", racine_froide.display());
        }

        /// Une requête par la route, à travers les six couches, et la réponse ENTIÈRE décodée (le routeur
        /// sert ce corps en `Transfer-Encoding: chunked` : les trames sont recollées par l'aide que la
        /// fermeture du shell emploie déjà, jamais devinées).
        async fn interroger(&self, soql: &str, depuis: i64, jusqua: i64) -> (u16, Value) {
            let corps = format!("{{\"soql\":\"{soql}\",\"from\":{depuis},\"to\":{jusqua}}}");
            let entetes = [("Content-Type", "application/json")];
            let (code, texte) = router_probe_envoi(self.addr, "POST", "/api/query", Some(&self.authz), &entetes, &corps).await;
            let (en_tete, corps_http) = texte.split_once("\r\n\r\n").unwrap_or(("", ""));
            let octets: Vec<u8> = if en_tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
                shell_decouper(corps_http.as_bytes()).unwrap_or_else(|| panic!("trame chunked incomplète — code {code}, texte : {texte}"))
            } else {
                corps_http.as_bytes().to_vec()
            };
            let v: Value = serde_json::from_slice(&octets).unwrap_or_else(|e| panic!("réponse de route illisible ({e}) — code {code}, texte : {texte}"));
            (code, v)
        }
    }

    /// `P10.5-g` (b) — UN CURSEUR MARQUÉ PAR LA VOIE COLONNAIRE MAIS REMONTÉ AU-DESSUS DE LA FRONTIÈRE EST REFUSÉ
    /// EN 422 NOMMÉ, jamais en erreur serveur retriable : la cause est déterministe (la frontière a reculé sous un
    /// curseur déjà émis, cas ordinaire d'une fenêtre chaude élargie), et le client doit reprendre sans curseur.
    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn p10_5g_un_curseur_marque_remonte_au_dessus_de_la_frontiere_est_refuse_nomme() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let banc = BancFroidSurLaRoute::monter("curseur-marque-remonte", true).await;
        banc.vieillir();
        // Fenêtre chevauchante, curseur CHAUD (au-dessus de la frontière) portant la marque colonnaire.
        let corps = format!(
            "{{\"soql\":\"search source=froid\",\"keyset\":true,\"limit\":10,\"from\":{},\"to\":{},\"cursor\":{{\"ts\":{},\"id\":1,\"espace\":\"{}\"}}}}",
            banc.base_froide - 60, banc.maintenant + 60, banc.maintenant, crate::ESPACE_ID_COLD_VECTORISE
        );
        let entetes = [("Content-Type", "application/json")];
        let (code, texte) = router_probe_envoi(banc.addr, "POST", "/api/query", Some(&banc.authz), &entetes, &corps).await;
        assert_eq!(code, 422, "un curseur marqué remonté au-dessus de la frontière est un refus DÉTERMINISTE, pas une erreur serveur retriable : {texte}");
        assert!(texte.contains("cold_cursor_marque_au_dessus_de_la_frontiere"), "le refus nomme sa cause machine : {texte}");
        assert!(texte.contains("\"restart_without_cursor\":true"), "le refus porte l'ordre de reprendre sans curseur : {texte}");
    }

    /// La somme de la dernière colonne des lignes servies : le compte d'une agrégation.
    #[cfg(feature = "cold_tier")]
    fn compte_servi(v: &Value) -> i64 {
        v["rows"]
            .as_array()
            .map(|rows| rows.iter().filter_map(|r| r.as_array()).filter_map(|r| r.last()).filter_map(|x| x.as_i64()).sum())
            .unwrap_or(-1)
    }

    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn l_aveu_de_part_froide_est_servi_sur_la_reponse_entiere_de_la_route() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let banc = BancFroidSurLaRoute::monter("aveu-part-froide", false).await;
        // `count by message` : une dimension qu'aucun pré-agrégé ne porte, donc la route pré-agrégée ne peut
        // pas effacer la frontière froide — c'est le chemin brut, celui qui publie l'aveu, qui sert.
        let soql = "search source=froid | stats count by message";
        let (depuis, jusqua) = (banc.base_froide - 60, banc.maintenant + 60);

        // (1) AVANT VIEILLISSEMENT : la fenêtre franchit la frontière, le bras froid est lisible mais VIDE —
        //     la provenance dit `hot+cold`, et les comptes disent que rien n'y a été lu.
        let (code1, v1) = banc.interroger(soql, depuis, jusqua).await;
        assert_eq!(code1, 200, "CONTRÔLE : la route doit servir la fenêtre large avant vieillissement : {v1}");
        assert_eq!(
            v1["stats"]["cold"]["served_from"].as_str(),
            Some("hot+cold"),
            "avant vieillissement, la provenance dit ce que le SQL a PU lire — les deux bras : {}",
            v1["stats"]
        );
        assert_eq!(v1["stats"]["cold"]["files_read"].as_i64(), Some(0), "avant vieillissement, aucun fichier froid n'existe : {}", v1["stats"]["cold"]);
        assert_eq!(v1["stats"]["cold"]["rows_hydrated"].as_i64(), Some(0), "avant vieillissement, aucune ligne froide n'est hydratée : {}", v1["stats"]["cold"]);
        // ZONE GRISE MESURÉE (compromis documenté dans `cold_store/reader.rs`, « l'aging en retard ») : les
        // lignes sous la frontière, encore dans la table chaude, ne sont servies par aucun bras.
        assert_eq!(
            compte_servi(&v1),
            1,
            "avant vieillissement, l'union ne lit le chaud qu'à partir de la frontière : seule la ligne chaude est servie. \
             Si ce compte vaut {}, la zone grise « aging en retard » a été FERMÉE — mettre à jour la cellule P10.5-k. Lignes : {}",
            LIGNES_FROIDES + 1,
            v1["rows"]
        );

        banc.vieillir();

        // (2) APRÈS VIEILLISSEMENT : même fenêtre, l'aveu dit `hot+cold`, un fichier est lu, le compte est entier.
        let (code2, v2) = banc.interroger(soql, depuis, jusqua).await;
        assert_eq!(code2, 200, "la route doit servir la fenêtre large après vieillissement : {v2}");
        assert_eq!(
            v2["stats"]["cold"]["served_from"].as_str(),
            Some("hot+cold"),
            "après vieillissement, l'aveu servi au client doit dire que le bras froid a été lu : {}",
            v2["stats"]
        );
        assert!(
            v2["stats"]["cold"]["files_read"].as_i64().unwrap_or(0) >= 1,
            "l'aveu doit compter au moins un fichier froid lu : {}",
            v2["stats"]["cold"]
        );
        assert!(
            v2["stats"]["cold"]["rows_hydrated"].as_i64().unwrap_or(0) >= LIGNES_FROIDES,
            "l'aveu doit compter au moins autant de lignes hydratées que de lignes vieillies : {}",
            v2["stats"]["cold"]
        );
        assert!(v2["stats"]["cold"]["boundary_ts"].as_i64().is_some(), "l'aveu doit porter la frontière : {}", v2["stats"]["cold"]);
        assert_eq!(
            compte_servi(&v2),
            LIGNES_FROIDES + 1,
            "après vieillissement, la route doit servir TOUTES les lignes — les 120 vieillies par le bras froid, la chaude par le chaud : {}",
            v2["rows"]
        );

        // (3) FENÊTRE ENTIÈREMENT CHAUDE : aucun aveu de part froide, et le compte est celui du chaud seul.
        let (code3, v3) = banc.interroger(soql, banc.maintenant - JOUR, banc.maintenant + 60).await;
        assert_eq!(code3, 200, "la route doit servir la fenêtre chaude : {v3}");
        assert!(
            v3["stats"]["cold"].is_null(),
            "sur une fenêtre qui n'atteint pas la frontière, la route ne doit rien dire du froid : {}",
            v3["stats"]
        );
        assert_eq!(compte_servi(&v3), 1, "la fenêtre chaude ne compte que la ligne chaude : {}", v3["rows"]);
    }

    // `P10.5-n` (2026-09-10) — LE TROISIÈME SITE D'AVEU, LA VOIE VECTORISÉE, NOMME SES DEUX VALEURS SUR LA
    // ROUTE. La cellule comptait trois sites qui écrivent `served_from` et deux témoins comportementaux :
    // le troisième site — l'agrégat froid vectorisé, `cold-vectorized` sur une fenêtre purement froide,
    // `cold-vectorized-merge` sur une fenêtre chevauchante — n'avait aucun témoin qui nomme ses valeurs,
    // et la garde de source qui tient les deux autres n'ancre pas sa forme (il écrit l'aveu en ligne). La
    // propriété était tenue par le CODE, défaisable sans qu'aucune garde ne rougisse. Ce témoin la tient
    // par la ROUTE : la voie est armée, une agrégation vectorisable (`stats count`) est servie sur les deux
    // fenêtres, et les deux aveux — `stats.served_from` et `stats.cold.served_from` — portent la valeur de
    // la voie, avec la frontière et le compte juste. Témoin négatif : la même agrégation sur une fenêtre
    // entièrement chaude ne porte aucune de ces deux valeurs.
    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn l_aveu_de_la_voie_vectorisee_nomme_ses_deux_valeurs_sur_la_route() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let banc = BancFroidSurLaRoute::monter("aveu-voie-vectorisee", true).await;
        banc.vieillir();
        let soql = "search source=froid | stats count";

        // (1) FENÊTRE PUREMENT FROIDE (`0 < to < B`) : les noyaux seuls, `cold-vectorized`, et les 120 lignes.
        let (code1, v1) = banc.interroger(soql, banc.base_froide - 60, banc.base_froide + LIGNES_FROIDES * 60 + 60).await;
        assert_eq!(code1, 200, "la route doit servir la fenêtre purement froide : {v1}");
        assert_eq!(v1["stats"]["served_from"].as_str(), Some("cold-vectorized"), "la voie des noyaux doit se nommer dans `stats.served_from` : {}", v1["stats"]);
        assert_eq!(v1["stats"]["cold"]["served_from"].as_str(), Some("cold-vectorized"), "et dans l'aveu de part froide : {}", v1["stats"]["cold"]);
        assert!(v1["stats"]["cold"]["boundary_ts"].as_i64().is_some(), "l'aveu de la voie porte la frontière : {}", v1["stats"]["cold"]);
        assert_eq!(compte_servi(&v1), LIGNES_FROIDES, "la fenêtre purement froide compte les lignes vieillies, et elles seules : {}", v1["rows"]);
        // `P10.5-o` — le drapeau de troncature de la voie porte son ORIGINE : un compte sur tous les fichiers est
        // complet par construction, et se dit comme tel — pas comme une mesure qui n'a pas eu lieu.
        assert_eq!(v1["stats"]["truncated"].as_bool(), Some(false), "{}", v1["stats"]);
        assert_eq!(v1["stats"]["truncated_origin"].as_str(), Some("complete_par_construction"), "l'origine du drapeau est publiée : {}", v1["stats"]);

        // (2) FENÊTRE CHEVAUCHANTE (`from < B <= to`) : la fusion, `cold-vectorized-merge`, et toutes les lignes.
        let (code2, v2) = banc.interroger(soql, banc.base_froide - 60, banc.maintenant + 60).await;
        assert_eq!(code2, 200, "la route doit servir la fenêtre chevauchante : {v2}");
        assert_eq!(v2["stats"]["served_from"].as_str(), Some("cold-vectorized-merge"), "la fusion doit se nommer dans `stats.served_from` : {}", v2["stats"]);
        assert_eq!(v2["stats"]["cold"]["served_from"].as_str(), Some("cold-vectorized-merge"), "et dans l'aveu de part froide : {}", v2["stats"]["cold"]);
        assert_eq!(compte_servi(&v2), LIGNES_FROIDES + 1, "la fenêtre chevauchante compte les lignes des deux bras : {}", v2["rows"]);
        assert_eq!(v2["stats"]["truncated_origin"].as_str(), Some("complete_par_construction"), "la fusion de deux comptes est complète par construction : {}", v2["stats"]);

        // (3) TÉMOIN NÉGATIF : une fenêtre entièrement chaude ne porte aucune des deux valeurs de la voie.
        let (code3, v3) = banc.interroger(soql, banc.maintenant - JOUR, banc.maintenant + 60).await;
        assert_eq!(code3, 200, "la route doit servir la fenêtre chaude : {v3}");
        let voie = v3["stats"]["served_from"].as_str().unwrap_or("");
        assert!(!voie.starts_with("cold-vectorized"), "une fenêtre chaude ne doit pas se dire servie par la voie froide : {}", v3["stats"]);
        assert!(v3["stats"]["cold"].is_null(), "une fenêtre chaude ne porte aucun aveu de part froide : {}", v3["stats"]);
        assert_eq!(compte_servi(&v3), 1, "la fenêtre chaude ne compte que la ligne chaude : {}", v3["rows"]);
    }
