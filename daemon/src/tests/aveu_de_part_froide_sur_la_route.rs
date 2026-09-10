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
    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn l_aveu_de_part_froide_est_servi_sur_la_reponse_entiere_de_la_route() {
        let _env = VERROU_ENV_PROCESSUS.write();
        struct EnvPose(Vec<&'static str>);
        impl Drop for EnvPose {
            fn drop(&mut self) {
                for k in &self.0 {
                    std::env::remove_var(k);
                }
            }
        }
        let cle = "plume-cold-route-test-key-do-not-use-in-prod-0000";
        let poses: [(&'static str, &str); 4] = [
            ("PLUME_COLD_TIER", "1"),
            ("PLUME_COLD_HOT_WINDOW_DAYS", "2"),
            ("PLUME_DB_KEY", cle),
            ("PLUME_COLD_VECTORIZED", "0"),
        ];
        // `PLUME_COLD_DIR` volontairement ABSENT : la racine froide dérive du chemin de la base, donc vit
        // dans le répertoire possédé par la fixture et disparaît avec lui.
        std::env::remove_var("PLUME_COLD_DIR");
        for (k, v) in poses {
            std::env::set_var(k, v);
        }
        let _nettoyage = EnvPose(poses.iter().map(|(k, _)| *k).collect());
        let mut conf: HashMap<String, String> = HashMap::new();
        for (k, v) in poses {
            conf.insert(k.to_string(), v.to_string());
        }

        // La base est ouverte APRÈS la pose de la clé : toutes ses ouvertures, fixture et route, la partagent.
        let (st, base_possedee) = router_test_state("aveu-part-froide");
        let chemin_base = base_possedee.as_str().to_string();
        let jour = 86_400i64;
        let maintenant = now();
        let minuit = maintenant.div_euclid(jour) * jour;
        let base_froide = minuit - 8 * jour;
        const LIGNES_FROIDES: i64 = 120;
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
        let authz = viewer_authz();
        let entetes = [("Content-Type", "application/json")];
        // `count by message` : une dimension qu'aucun pré-agrégé ne porte, donc la route pré-agrégée ne peut
        // pas effacer la frontière froide — c'est le chemin brut, celui qui publie l'aveu, qui sert.
        let interroger = |depuis: i64, jusqua: i64| {
            let corps = format!("{{\"soql\":\"search source=froid | stats count by message\",\"from\":{depuis},\"to\":{jusqua}}}");
            let authz = authz.clone();
            async move {
                let (code, texte) = router_probe_envoi(addr, "POST", "/api/query", Some(&authz), &entetes, &corps).await;
                let (en_tete, corps_http) = texte.split_once("\r\n\r\n").unwrap_or(("", ""));
                // Le routeur sert ce corps en `Transfer-Encoding: chunked` : les trames sont recollées par
                // l'aide que la fermeture du shell emploie déjà, jamais devinées.
                let octets: Vec<u8> = if en_tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
                    shell_decouper(corps_http.as_bytes()).unwrap_or_else(|| panic!("trame chunked incomplète — code {code}, texte : {texte}"))
                } else {
                    corps_http.as_bytes().to_vec()
                };
                let v: Value = serde_json::from_slice(&octets).unwrap_or_else(|e| {
                    panic!("réponse de route illisible ({e}) — code {code}, texte : {texte}")
                });
                (code, v)
            }
        };
        let compte = |v: &Value| -> i64 {
            v["rows"]
                .as_array()
                .map(|rows| rows.iter().filter_map(|r| r.as_array()).filter_map(|r| r.last()).filter_map(|x| x.as_i64()).sum())
                .unwrap_or(-1)
        };

        // (1) AVANT VIEILLISSEMENT : la fenêtre franchit la frontière, le bras froid est lisible mais VIDE —
        //     la provenance dit `hot+cold`, et les comptes disent que rien n'y a été lu.
        let (code1, v1) = interroger(base_froide - 60, maintenant + 60).await;
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
            compte(&v1),
            1,
            "avant vieillissement, l'union ne lit le chaud qu'à partir de la frontière : seule la ligne chaude est servie. \
             Si ce compte vaut {}, la zone grise « aging en retard » a été FERMÉE — mettre à jour la cellule P10.5-k. Lignes : {}",
            LIGNES_FROIDES + 1,
            v1["rows"]
        );

        // LE VIEILLISSEMENT RÉEL, puis la preuve qu'il a déplacé les lignes : la table chaude ne porte plus
        // la journée froide, et la racine froide dérivée porte au moins un fichier.
        crate::cold_store::cold_age_run(&st.db, &chemin_base, &conf, minuit, 30);
        let restantes: i64 = st
            .db
            .lock()
            .query_row("SELECT COUNT(*) FROM event WHERE ts < ?1", params![minuit - 2 * jour], |r| r.get(0))
            .unwrap();
        assert_eq!(restantes, 0, "instrument : le vieillissement n'a pas déplacé la journée froide hors de la table chaude");
        let racine_froide = std::path::PathBuf::from(format!("{chemin_base}.cold"));
        let fichiers = std::fs::read_dir(&racine_froide).map(|d| d.count()).unwrap_or(0);
        assert!(fichiers >= 1, "instrument : aucune entrée sous la racine froide dérivée {}", racine_froide.display());

        // (2) APRÈS VIEILLISSEMENT : même fenêtre, l'aveu dit `hot+cold`, un fichier est lu, le compte est inchangé.
        let (code2, v2) = interroger(base_froide - 60, maintenant + 60).await;
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
            compte(&v2),
            LIGNES_FROIDES + 1,
            "après vieillissement, la route doit servir TOUTES les lignes — les 120 vieillies par le bras froid, la chaude par le chaud : {}",
            v2["rows"]
        );

        // (3) FENÊTRE ENTIÈREMENT CHAUDE : aucun aveu de part froide, et le compte est celui du chaud seul.
        let (code3, v3) = interroger(maintenant - jour, maintenant + 60).await;
        assert_eq!(code3, 200, "la route doit servir la fenêtre chaude : {v3}");
        assert!(
            v3["stats"]["cold"].is_null(),
            "sur une fenêtre qui n'atteint pas la frontière, la route ne doit rien dire du froid : {}",
            v3["stats"]
        );
        assert_eq!(compte(&v3), 1, "la fenêtre chaude ne compte que la ligne chaude : {}", v3["rows"]);
    }
