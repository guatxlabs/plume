// =====================================================================================
// `P7.20-a` (correction après vérification) — UNE CIBLE DE CONFIGURATION N'EST ADMISE QUE POUR LA LIGNE QUI LA PORTE
// ENCORE, ET L'INSCRIPTION SUIT L'ÉCRITURE.
//
// (1) Une ligne de surcouche réécrite par l'API (route de modification), ou un identifiant repris par une ligne créée
//     par l'API après une suppression, ne garde AUCUNE origine de configuration : l'inscription date du chargement des
//     surcouches (démarrage), elle n'est rendue que si la ligne qui émet porte encore exactement les cibles inscrites
//     (`ssrf_cibles_de_l_objet_inchange`, daemon/src/ledger.rs). Sonde du vérificateur : un connecteur modifié par
//     l'API vers une URL publique dont la réponse renvoie vers l'ancienne cible privée l'atteignait.
// (2) Une écriture de surcouche refusée (insertion ou mise à jour) n'inscrit rien, ni sous son identifiant, ni sous celui
//     d'une autre ligne (`last_insert_rowid()` de la ligne précédente).
// (3) Une destination syslog écrite sous une forme non normale (`TCP://hôte:port/…`) est inscrite sous la forme
//     d'émission `tcp://hôte:port`, celle que l'envoi présente à la garde.
// (4) Chaque genre de canal qui émet vers une URL (ntfy — dont le canal semé par `PLUME_NOTIFY_NTFY_URL` —, slack, email,
//     générique) est jugé par la vraie chaîne d'envoi avec SES cibles : la surcouche part (faux `curl` appelé), son
//     jumeau de l'API, même URL et autre identifiant, est refusé avant `curl`.
// (5) Une destination et un connecteur de surcouche rechargés (second chargement : la ligne existe, chemin de MISE À
//     JOUR, celui de tout démarrage après le premier) sont inscrits sous l'identifiant de la ligne mise à jour, et leur
//     envoi part vers les cibles du fichier modifié.
// (6) L'inventaire du démarrage juge une surcouche de connecteur comme l'envoi (requête admise sur la base des pages,
//     cible exacte du point de jeton) : il ne la dit pas refusée ; il dit ses jumeaux de l'API.
// (7) L'essai d'un connecteur (`connector_test`) juge la ligne qu'il lit : réécrite en base, elle perd l'inscription.
//
// Les sous-processus arment le témoin d'égress (armé pour tout le processus) et règlent l'environnement ; la garde y
// tourne au défaut (aucun `PLUME_*`, fichier de configuration absent).
//
// MUTANTS JOUÉS (posés sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : M_INCHANGE_IGNORE (inscription
// rendue quelle que soit la ligne) ; M_POLL_INSCRIPTION_BRUTE (poll manuel jugé avec l'inscription brute) ;
// M_INSCRIT_REFUS_CANAL, M_INSCRIT_REFUS_DESTINATION, M_INSCRIT_REFUS_CONNECTEUR (écriture refusée inscrite) ;
// M_SYSLOG_BRUT (endpoint syslog inscrit tel quel) ; M_NTFY_SANS_CIBLES, M_SLACK_SANS_CIBLES, M_EMAIL_SANS_CIBLES,
// M_GENERIQUE_SANS_CIBLES (branche de `notify_send_pour_l_objet` jugée sans les cibles du canal) ; BA1_MAJ_DEST,
// BA1_MAJ_CONN (mise à jour inscrite sous l'identifiant d'insertion, une famille à la fois) ; BA1_INV_LUE_FAUX,
// BA1_INV_LUE_VRAI (requête admise forcée à la lecture de l'inventaire), BA1_INV_LIGNE_FAUX, BA1_INV_LIGNE_VRAI (forcée
// dans les cibles de la ligne comparées à l'inscription) ; BA1_ESSAI_BRUT (essai jugé avec l'inscription brute).
// =====================================================================================
mod cibles_de_configuration_fideles_a_la_ligne_qui_emet {
    use super::*;
    use crate::ledger::{ssrf_cibles_de_l_objet, CibleDeConfiguration, FamilleDeSurcouche};

    const MODULE: &str = "tests::cibles_de_configuration_fideles_a_la_ligne_qui_emet::";
    const ENFANT: &str = "P720A_ENFANT_LIGNE_QUI_EMET";
    const FIN: &str = "P720A-LIGNE-QUI-EMET-A-JOUE";
    const CONNECTEUR_PRIVE: &str = "http://10.0.0.15/api";
    const PAGE_SUIVANTE_PRIVEE: &str = "http://10.0.0.15/api?p=2";
    const FLUX_PUBLIC: &str = "https://192.0.2.10/feed";
    const FLUX_PUBLIC_RECREE: &str = "https://192.0.2.11/feed";
    const SYSLOG_NON_NORMAL: &str = "TCP://10.0.0.21:6514/p720a";
    const SYSLOG_D_EMISSION: &str = "tcp://10.0.0.21:6514";
    const NTFY_SEME: &str = "http://10.0.0.40:8080/p720a-env";
    const NTFY_DE_SURCOUCHE: &str = "http://10.0.0.36/p720a";
    const SLACK_DE_SURCOUCHE: &str = "http://10.0.0.37/hooks/p720a";
    const EMAIL_DE_SURCOUCHE: &str = "smtp://10.0.0.38:25";
    const GENERIQUE_DE_SURCOUCHE: &str = "http://10.0.0.39/generique";
    const VARIABLE_SLACK: &str = "P720A_LQE_WEBHOOK_SLACK";
    /// Un faux `curl` : il note chaque appel et réussit (aucun réseau).
    const FAUX_CURL: &str = "#!/bin/sh\necho appel >> \"$P720A_LQE_BAC/appels\"\ncat > /dev/null\nexit 0\n";

    /// La valeur de la ligne `CLE:valeur` de l'enfant, présente une seule fois.
    fn lu(stdout: &str, cle: &str) -> String {
        let prefixe = format!("{cle}:");
        let trouves: Vec<&str> = stdout.lines().filter_map(|l| l.strip_prefix(prefixe.as_str())).collect();
        assert_eq!(trouves.len(), 1, "une seule ligne {cle} : {stdout}");
        trouves[0].to_string()
    }

    fn id_de(c: &Connection, table: &str, nom: &str) -> i64 {
        c.query_row(&format!("SELECT id FROM {table} WHERE name=?1"), params![nom], |r| r.get(0)).expect("id lisible")
    }

    /// Prépare la ré-exécution de `test` sur une commande que le test a construite DANS SON CORPS : arguments, puis
    /// environnement `PLUME_*` vidé et `PLUME_CONFIG` vers un fichier absent. L'appelant pose ensuite `ENFANT` et ses
    /// propres variables.
    fn preparer_l_enfant(commande: &mut std::process::Command, test: &str) {
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}{test}"));
        for (nom, _) in std::env::vars_os() {
            if nom.to_string_lossy().starts_with("PLUME_") {
                commande.env_remove(&nom);
            }
        }
        commande.env("PLUME_CONFIG", "/nonexistent");
    }

    /// Lance l'enfant ; rend (sortie standard, sortie d'erreur), après avoir vérifié qu'il a joué jusqu'au bout.
    fn sorties_de_l_enfant(mut commande: std::process::Command) -> (String, String) {
        let sortie = commande.output().expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains(FIN), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        (stdout, stderr)
    }

    fn vus_texte() -> Vec<String> {
        crate::ledger::temoin_de_l_egress::vus().into_iter().map(|(m, u)| format!("{m} {u}")).collect()
    }

    /// Le témoin répond : la page publique annonce une suite vers l'ancienne cible privée ; tout le reste, vide.
    fn repondre(_methode: &str, url: &str) -> Result<HttpResp, String> {
        let corps = if url.starts_with("https://192.0.2.") {
            format!(r#"{{"items":[],"next":"{PAGE_SUIVANTE_PRIVEE}"}}"#)
        } else {
            r#"{"items":[]}"#.to_string()
        };
        Ok(crate::ledger::temoin_de_l_egress::reponse(200, &[], &corps))
    }

    fn config_publique(url: &str) -> Value {
        json!({ "url": url, "records_path": "items", "field_map": { "message": "msg" },
                "pagination": { "kind": "link_header", "next_path": "next" } })
    }

    // ------------------------------------------------------------------ (1) ligne réécrite ou identifiant repris

    /// Un connecteur de surcouche vers une adresse privée est admis (contrôle) ; réécrit par l'API vers une URL publique
    /// dont la réponse renvoie vers l'ancienne cible, il ne l'atteint plus ; supprimé puis recréé par l'API sous le même
    /// identifiant, non plus — au poll manuel comme au passage de fond.
    #[test]
    fn p720a_une_ligne_reecrite_ou_reprise_par_l_api_perd_l_origine_de_configuration() {
        if std::env::var(ENFANT).is_ok() {
            println!();
            let (st, base) = router_test_state("p720a-lqe-reecrite");
            let dossier = crate::tmp_possede::TmpPossede::neuf("p720a-lqe-reecrite");
            let d = dossier.join("connectors");
            std::fs::create_dir_all(&d).expect("dossier de surcouche");
            std::fs::write(d.join("k.json"), json!({ "name": "p720a-lqe-k", "type": "http_pull", "enabled": true,
                "config": { "url": CONNECTEUR_PRIVE, "records_path": "items", "field_map": { "message": "msg" } } }).to_string())
                .expect("surcouche");
            let id = {
                let c = open_db(&base).expect("base");
                let k = crate::overlays_oac::load_overlay_connectors(&c, &d);
                assert_eq!(k.charges, 1, "contrôle : la surcouche est posée");
                id_de(&c, "connector", "p720a-lqe-k")
            };
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
            let poll = |id: i64| {
                let arme = crate::ledger::temoin_de_l_egress::armer(repondre);
                rt.block_on(async {
                    let _ = crate::handlers::connectors::connector_poll(State(st.clone()), Extension(ergo_au("admin")), Path(id)).await;
                });
                let vus = vus_texte();
                drop(arme);
                vus.join(" | ")
            };
            println!("P720A-LQE-AVANT:{}", poll(id));
            let maj = rt.block_on(async {
                crate::handlers::connectors::connector_update(State(st.clone()), Extension(ergo_au("admin")), Path(id),
                    Json(json!({ "config": config_publique(FLUX_PUBLIC) }))).await.status().as_u16()
            });
            println!("P720A-LQE-MAJ:{maj}");
            println!("P720A-LQE-APRES-MAJ:{}", poll(id));
            let suppression = rt.block_on(async {
                crate::handlers::connectors::connector_delete(State(st.clone()), Extension(ergo_au("admin")), Path(id)).await.status().as_u16()
            });
            println!("P720A-LQE-SUPPRESSION:{suppression}");
            let creation = rt.block_on(async {
                let r = crate::handlers::connectors::connector_create(State(st.clone()), Extension(ergo_au("admin")),
                    Json(json!({ "name": "p720a-lqe-recree", "type": "http_pull", "enabled": true, "config": config_publique(FLUX_PUBLIC_RECREE) }))).await;
                let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps");
                serde_json::from_slice::<Value>(&b).ok().and_then(|v| v.get("id").and_then(|x| x.as_i64()))
            });
            println!("P720A-LQE-MEME-ID:{}", creation == Some(id));
            println!("P720A-LQE-REPRIS-POLL:{}", poll(id));
            st.db.lock().execute("UPDATE connector SET last_run=0 WHERE id=?1", params![id]).expect("connecteur dû");
            let arme = crate::ledger::temoin_de_l_egress::armer(repondre);
            let _ = run_due_connectors(&st.db, &base.to_string());
            println!("P720A-LQE-REPRIS-FOND:{}", vus_texte().join(" | "));
            drop(arme);
            println!("{FIN}");
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        preparer_l_enfant(&mut commande, "p720a_une_ligne_reecrite_ou_reprise_par_l_api_perd_l_origine_de_configuration");
        commande.env(ENFANT, "1");
        let (s, _) = sorties_de_l_enfant(commande);
        assert_eq!(lu(&s, "P720A-LQE-AVANT"), format!("GET {CONNECTEUR_PRIVE}"), "contrôle : la surcouche atteint sa cible privée");
        assert_eq!(lu(&s, "P720A-LQE-MAJ"), "200", "contrôle : la modification par l'API est prise");
        assert_eq!(lu(&s, "P720A-LQE-APRES-MAJ"), format!("GET {FLUX_PUBLIC}"),
            "ligne réécrite par l'API : la page suivante vers l'ancienne cible privée est refusée avant le réseau");
        assert_eq!(lu(&s, "P720A-LQE-SUPPRESSION"), "204", "contrôle : la suppression est prise");
        assert_eq!(lu(&s, "P720A-LQE-MEME-ID"), "true", "prémisse : la ligne créée par l'API reprend l'identifiant");
        assert_eq!(lu(&s, "P720A-LQE-REPRIS-POLL"), format!("GET {FLUX_PUBLIC_RECREE}"), "identifiant repris : poll manuel refusé vers l'ancienne cible");
        assert_eq!(lu(&s, "P720A-LQE-REPRIS-FOND"), format!("GET {FLUX_PUBLIC_RECREE}"), "identifiant repris : passage de fond refusé vers l'ancienne cible");
    }

    /// Le cœur, sans réseau : l'inscription n'est rendue que pour la ligne qui porte exactement ses cibles.
    #[test]
    fn p720a_l_inscription_n_est_rendue_qu_a_la_ligne_qui_la_porte() {
        use crate::ledger::{remplacer_les_cibles_de_surcouche, ssrf_cibles_de_l_objet_inchange};
        let base = "p720a-lqe-coeur-base-de-temoin";
        let base_des_pages = CibleDeConfiguration::suivie_d_une_requete(CONNECTEUR_PRIVE);
        let jeton = CibleDeConfiguration::exacte("http://10.0.0.17/oauth/jeton");
        remplacer_les_cibles_de_surcouche(base, FamilleDeSurcouche::Connecteurs, vec![(3, base_des_pages.clone()), (3, jeton.clone())]);
        let inscrites = vec![base_des_pages.clone(), jeton.clone()];
        assert_eq!(ssrf_cibles_de_l_objet_inchange(base, FamilleDeSurcouche::Connecteurs, 3, &[jeton.clone(), base_des_pages.clone()]), inscrites, "mêmes cibles, autre ordre : rendues");
        assert_eq!(ssrf_cibles_de_l_objet_inchange(base, FamilleDeSurcouche::Connecteurs, 3, &[base_des_pages.clone()]), Vec::<CibleDeConfiguration>::new(), "une cible en moins : rien");
        assert_eq!(ssrf_cibles_de_l_objet_inchange(base, FamilleDeSurcouche::Connecteurs, 3,
            &[base_des_pages.clone(), jeton.clone(), CibleDeConfiguration::exacte(FLUX_PUBLIC)]), Vec::<CibleDeConfiguration>::new(), "une cible en plus : rien");
        assert_eq!(ssrf_cibles_de_l_objet_inchange(base, FamilleDeSurcouche::Connecteurs, 3,
            &[CibleDeConfiguration::exacte(CONNECTEUR_PRIVE), jeton.clone()]), Vec::<CibleDeConfiguration>::new(), "même URL, sans la requête admise : rien");
        assert_eq!(ssrf_cibles_de_l_objet_inchange(base, FamilleDeSurcouche::Connecteurs, 4, &inscrites), Vec::<CibleDeConfiguration>::new(), "autre identifiant : rien");
        assert_eq!(ssrf_cibles_de_l_objet_inchange(base, FamilleDeSurcouche::Connecteurs, 3, &[]), Vec::<CibleDeConfiguration>::new(), "ligne sans cible : rien");
        remplacer_les_cibles_de_surcouche(base, FamilleDeSurcouche::Connecteurs, Vec::new());
        assert_eq!(ssrf_cibles_de_l_objet_inchange(base, FamilleDeSurcouche::Connecteurs, 3, &inscrites), Vec::<CibleDeConfiguration>::new(), "rien d'inscrit : rien");
    }

    // ------------------------------------------------------------------ (2) écriture refusée : rien d'inscrit

    /// Par famille : une surcouche écrite (contrôle : ses cibles inscrites sous son identifiant), puis une insertion
    /// refusée et une mise à jour refusée. Rien n'est inscrit pour elles, ni sous l'identifiant de la ligne écrite juste
    /// avant (celui que `last_insert_rowid()` rend encore), ni sous celui de la ligne dont la mise à jour est refusée.
    #[test]
    fn p720a_une_ecriture_de_surcouche_refusee_n_inscrit_rien() {
        let (_st, base) = router_test_state("p720a-lqe-refus");
        let c = open_db(&base).expect("base");
        let base_s = crate::ledger::base_de(&c);
        let dossier = crate::tmp_possede::TmpPossede::neuf("p720a-lqe-refus");
        for sous in ["notifiers", "destinations", "connectors"] {
            std::fs::create_dir_all(dossier.join(sous)).expect("dossier");
        }
        let ecrire = |sous: &str, fichier: &str, v: Value| std::fs::write(dossier.join(sous).join(fichier), v.to_string()).expect("surcouche");
        let carte = json!({ "message": "msg" });
        ecrire("notifiers", "a.json", json!({ "name": "p720a-lqe-canal", "kind": "webhook", "url": "http://10.0.0.51/a" }));
        ecrire("notifiers", "b.json", json!({ "name": "p720a-lqe-canal-insertion-refusee", "kind": "webhook", "url": "http://10.0.0.52/refus" }));
        ecrire("notifiers", "c.json", json!({ "name": "p720a-lqe-canal-maj-refusee", "kind": "webhook", "url": "http://10.0.0.53/neuve" }));
        ecrire("destinations", "a.json", json!({ "name": "p720a-lqe-dest", "type": "webhook", "endpoint": "http://10.0.0.54/a" }));
        ecrire("destinations", "b.json", json!({ "name": "p720a-lqe-dest-insertion-refusee", "type": "webhook", "endpoint": "http://10.0.0.55/refus" }));
        ecrire("destinations", "c.json", json!({ "name": "p720a-lqe-dest-maj-refusee", "type": "webhook", "endpoint": "http://10.0.0.56/neuve" }));
        ecrire("connectors", "a.json", json!({ "name": "p720a-lqe-conn", "type": "http_pull",
            "config": { "url": "http://10.0.0.57/a", "records_path": "items", "field_map": carte } }));
        ecrire("connectors", "b.json", json!({ "name": "p720a-lqe-conn-insertion-refusee", "type": "http_pull",
            "config": { "url": "http://10.0.0.58/refus", "records_path": "items", "field_map": carte } }));
        ecrire("connectors", "c.json", json!({ "name": "p720a-lqe-conn-maj-refusee", "type": "http_pull",
            "config": { "url": "http://10.0.0.59/neuve", "records_path": "items", "field_map": carte } }));
        // Les lignes déjà posées par une surcouche (managed=1) dont la mise à jour sera refusée.
        c.execute_batch(
            "INSERT INTO notifier(name,kind,enabled,url,min_severity,config,managed) VALUES('p720a-lqe-canal-maj-refusee','webhook',1,'http://10.0.0.60/ancienne',2,'{}',1); \
             INSERT INTO destination(type,name,enabled,endpoint,config,filter,batch_max,interval_s,managed,created) \
               VALUES('webhook','p720a-lqe-dest-maj-refusee',0,'http://10.0.0.61/ancienne','{}','{}',500,30,1,0); \
             INSERT INTO connector(type,name,enabled,config_json,secret,interval_s,env_id,managed,created) \
               VALUES('http_pull','p720a-lqe-conn-maj-refusee',0,'{}','',300,'prod',1,0); \
             CREATE TEMP TRIGGER p720a_lqe_n_i BEFORE INSERT ON main.notifier WHEN NEW.name='p720a-lqe-canal-insertion-refusee' BEGIN SELECT RAISE(ABORT, 'p720a : écriture refusée'); END; \
             CREATE TEMP TRIGGER p720a_lqe_n_u BEFORE UPDATE ON main.notifier WHEN NEW.name='p720a-lqe-canal-maj-refusee' BEGIN SELECT RAISE(ABORT, 'p720a : écriture refusée'); END; \
             CREATE TEMP TRIGGER p720a_lqe_d_i BEFORE INSERT ON main.destination WHEN NEW.name='p720a-lqe-dest-insertion-refusee' BEGIN SELECT RAISE(ABORT, 'p720a : écriture refusée'); END; \
             CREATE TEMP TRIGGER p720a_lqe_d_u BEFORE UPDATE ON main.destination WHEN NEW.name='p720a-lqe-dest-maj-refusee' BEGIN SELECT RAISE(ABORT, 'p720a : écriture refusée'); END; \
             CREATE TEMP TRIGGER p720a_lqe_c_i BEFORE INSERT ON main.connector WHEN NEW.name='p720a-lqe-conn-insertion-refusee' BEGIN SELECT RAISE(ABORT, 'p720a : écriture refusée'); END; \
             CREATE TEMP TRIGGER p720a_lqe_c_u BEFORE UPDATE ON main.connector WHEN NEW.name='p720a-lqe-conn-maj-refusee' BEGIN SELECT RAISE(ABORT, 'p720a : écriture refusée'); END;",
        )
        .expect("fixtures");
        let n = crate::overlays_oac::load_overlay_notifiers(&c, &dossier.join("notifiers"));
        let d = crate::overlays_oac::load_overlay_destinations(&c, &dossier.join("destinations"));
        let k = crate::overlays_oac::load_overlay_connectors(&c, &dossier.join("connectors"));
        assert_eq!((n.charges, d.charges, k.charges), (1, 1, 1), "contrôle : une écriture prise par famille, deux refusées");
        assert_eq!((n.ignores, d.ignores, k.ignores), (2, 2, 2));
        for (famille, table, ecrite, cible_ecrite, refusees) in [
            (FamilleDeSurcouche::Canaux, "notifier", "p720a-lqe-canal", CibleDeConfiguration::exacte("http://10.0.0.51/a"), "p720a-lqe-canal-maj-refusee"),
            (FamilleDeSurcouche::Destinations, "destination", "p720a-lqe-dest", CibleDeConfiguration::exacte("http://10.0.0.54/a"), "p720a-lqe-dest-maj-refusee"),
            (FamilleDeSurcouche::Connecteurs, "connector", "p720a-lqe-conn", CibleDeConfiguration::suivie_d_une_requete("http://10.0.0.57/a"), "p720a-lqe-conn-maj-refusee"),
        ] {
            let id_ecrite = id_de(&c, table, ecrite);
            let id_maj_refusee = id_de(&c, table, refusees);
            assert_eq!(ssrf_cibles_de_l_objet(&base_s, famille, id_ecrite), vec![cible_ecrite], "{table} : la ligne écrite, ses seules cibles");
            assert_eq!(ssrf_cibles_de_l_objet(&base_s, famille, id_maj_refusee), Vec::<CibleDeConfiguration>::new(), "{table} : mise à jour refusée, rien d'inscrit");
            let max: i64 = c.query_row(&format!("SELECT COALESCE(MAX(id),0) FROM {table}"), [], |r| r.get(0)).expect("max");
            for id in 0..=max + 1 {
                if id == id_ecrite {
                    continue;
                }
                assert_eq!(ssrf_cibles_de_l_objet(&base_s, famille, id), Vec::<CibleDeConfiguration>::new(), "{table} #{id} : rien d'inscrit");
            }
        }
    }

    // ------------------------------------------------------------------ (3) syslog inscrit sous sa forme d'émission

    /// Une destination syslog de surcouche écrite `TCP://hôte:port/chemin` est inscrite `tcp://hôte:port` et son envoi
    /// part ; son jumeau de l'API (même endpoint, autre identifiant) est refusé.
    #[test]
    fn p720a_un_syslog_de_surcouche_est_inscrit_sous_sa_forme_d_emission() {
        if std::env::var(ENFANT).is_ok() {
            println!();
            let (st, base) = router_test_state("p720a-lqe-syslog");
            let dossier = crate::tmp_possede::TmpPossede::neuf("p720a-lqe-syslog");
            let d = dossier.join("destinations");
            std::fs::create_dir_all(&d).expect("dossier");
            std::fs::write(d.join("s.json"), json!({ "name": "p720a-lqe-syslog", "type": "syslog", "enabled": true, "endpoint": SYSLOG_NON_NORMAL }).to_string())
                .expect("surcouche");
            {
                let c = open_db(&base).expect("base");
                let chargement = crate::overlays_oac::load_overlay_destinations(&c, &d);
                println!("P720A-LQE-SYSLOG-POSES:{}", chargement.charges);
                let id = id_de(&c, "destination", "p720a-lqe-syslog");
                let inscrites: Vec<String> = ssrf_cibles_de_l_objet(&crate::ledger::base_de(&c), FamilleDeSurcouche::Destinations, id).into_iter().map(|x| x.url).collect();
                println!("P720A-LQE-SYSLOG-INSCRITES:{}", inscrites.join(" | "));
                c.execute_batch(
                    "INSERT INTO destination(id,type,name,enabled,endpoint,config,filter,batch_max,interval_s) \
                       SELECT 351,type,'p720a-lqe-syslog-jumeau',1,endpoint,config,filter,batch_max,interval_s FROM destination WHERE name='p720a-lqe-syslog';",
                )
                .expect("jumeau de l'API");
                c.execute("INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,'p720a','auth',3,'h1','m')", params![now()]).expect("événement");
            }
            let arme = crate::ledger::temoin_de_l_egress::armer(|_m, _u| Ok(crate::ledger::temoin_de_l_egress::reponse(200, &[], "")));
            let _ = run_due_destinations(&st.db, &base.to_string());
            println!("P720A-LQE-SYSLOG-VUS:{}", vus_texte().join(" | "));
            drop(arme);
            let c = st.db.lock();
            for nom in ["p720a-lqe-syslog", "p720a-lqe-syslog-jumeau"] {
                let e: String = c.query_row("SELECT COALESCE(last_error,'ok') FROM destination WHERE name=?1", params![nom], |r| r.get(0)).expect("état");
                println!("P720A-LQE-ETAT-{nom}:{}", if e == "ok" { "ok" } else if e.contains("adresse privée") { "refus-prive" } else { "autre" });
            }
            println!("{FIN}");
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        preparer_l_enfant(&mut commande, "p720a_un_syslog_de_surcouche_est_inscrit_sous_sa_forme_d_emission");
        commande.env(ENFANT, "1");
        let (s, _) = sorties_de_l_enfant(commande);
        assert_eq!(lu(&s, "P720A-LQE-SYSLOG-POSES"), "1", "contrôle : la forme non normale est admise à l'écriture");
        assert_eq!(lu(&s, "P720A-LQE-SYSLOG-INSCRITES"), SYSLOG_D_EMISSION, "inscrite sous la forme d'émission");
        assert_eq!(lu(&s, "P720A-LQE-SYSLOG-VUS"), format!("TCP {SYSLOG_D_EMISSION}"), "la surcouche part, une fois ; son jumeau non");
        assert_eq!(lu(&s, "P720A-LQE-ETAT-p720a-lqe-syslog"), "ok");
        assert_eq!(lu(&s, "P720A-LQE-ETAT-p720a-lqe-syslog-jumeau"), "refus-prive", "contrôle : le jumeau de l'API est refusé pour son adresse privée");
    }

    // ------------------------------------------------------------------ (4) chaque genre de canal, par la vraie chaîne

    /// Essai (route) de chaque canal de configuration — le ntfy semé par `PLUME_NOTIFY_NTFY_URL`, un ntfy, un slack, un
    /// email et un générique écrits en surcouche — puis de son jumeau de l'API. Le compte d'appels du faux `curl` est
    /// relevé après chaque essai.
    #[test]
    fn p720a_chaque_genre_de_canal_est_juge_avec_les_cibles_de_son_canal() {
        if std::env::var(ENFANT).is_ok() {
            println!();
            let bac = std::path::PathBuf::from(std::env::var("P720A_LQE_BAC").expect("bac du faux curl"));
            let racine = std::path::PathBuf::from(std::env::var("P720A_LQE_SURCOUCHES").expect("dossier des surcouches"));
            let (st, base) = router_test_state("p720a-lqe-genres");
            let ids: Vec<(String, i64)> = {
                let c = open_db(&base).expect("base");
                let conf = load_config();
                seed_env_notifier(&c, &conf);
                crate::overlays_oac::inscrire_le_canal_de_l_environnement(&c, &conf);
                let n = crate::overlays_oac::load_overlay_notifiers(&c, &racine);
                println!("P720A-LQE-CANAUX-POSES:{}", n.charges);
                let mut ids = Vec::new();
                for (cle, nom, jumeau) in [
                    ("SEME", "ntfy (env)", 241i64), ("NTFY", "p720a-lqe-ntfy", 242), ("SLACK", "p720a-lqe-slack", 243),
                    ("EMAIL", "p720a-lqe-email", 244), ("GENERIQUE", "p720a-lqe-generique", 245),
                ] {
                    c.execute(
                        "INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) SELECT ?1,'p720a-lqe-jumeau-'||?1,kind,1,url,0,config FROM notifier WHERE name=?2",
                        params![jumeau, nom],
                    )
                    .expect("jumeau de l'API");
                    ids.push((cle.to_string(), id_de(&c, "notifier", nom)));
                    ids.push((format!("JUMEAU-{cle}"), jumeau));
                }
                ids
            };
            let appels = || std::fs::read_to_string(bac.join("appels")).map(|t| t.lines().count()).unwrap_or(0);
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
            rt.block_on(async {
                for (cle, id) in &ids {
                    let r = notifier_test(State(st.clone()), Extension(ergo_au("admin")), Path(*id)).await;
                    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps");
                    let ok = serde_json::from_slice::<Value>(&b).ok().and_then(|v| v.get("ok").and_then(|x| x.as_bool()));
                    println!("P720A-LQE-ESSAI-{cle}:{ok:?}/{}", appels());
                }
            });
            println!("{FIN}");
            return;
        }
        let dossier = crate::tmp_possede::TmpPossede::neuf("p720a-lqe-genres");
        let bac = dossier.join("bac");
        std::fs::create_dir_all(&bac).expect("bac du faux curl");
        let faux = bac.join("curl");
        std::fs::write(&faux, FAUX_CURL).expect("faux curl");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&faux, std::fs::Permissions::from_mode(0o755)).expect("faux curl exécutable");
        }
        let surcouches = dossier.join("notifiers");
        std::fs::create_dir_all(&surcouches).expect("dossier des canaux");
        let ecrire = |fichier: &str, v: Value| std::fs::write(surcouches.join(fichier), v.to_string()).expect("surcouche");
        ecrire("ntfy.json", json!({ "name": "p720a-lqe-ntfy", "kind": "ntfy", "url": NTFY_DE_SURCOUCHE }));
        ecrire("slack.json", json!({ "name": "p720a-lqe-slack", "kind": "slack", "config": { "webhook_url": format!("env:{VARIABLE_SLACK}") } }));
        ecrire("email.json", json!({ "name": "p720a-lqe-email", "kind": "email", "url": EMAIL_DE_SURCOUCHE,
            "config": { "from": "plume@exemple.test", "to": "soc@exemple.test" } }));
        ecrire("generique.json", json!({ "name": "p720a-lqe-generique", "kind": "generic", "url": GENERIQUE_DE_SURCOUCHE }));
        let chemin_systeme = std::env::var("PATH").unwrap_or_default();
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        preparer_l_enfant(&mut commande, "p720a_chaque_genre_de_canal_est_juge_avec_les_cibles_de_son_canal");
        commande
            .env(ENFANT, "1")
            .env("P720A_LQE_BAC", &bac)
            .env("P720A_LQE_SURCOUCHES", &surcouches)
            .env(VARIABLE_SLACK, SLACK_DE_SURCOUCHE)
            .env("PLUME_NOTIFY_NTFY_URL", NTFY_SEME)
            .env("PATH", format!("{}:{chemin_systeme}", bac.display()));
        let (s, _) = sorties_de_l_enfant(commande);
        assert_eq!(lu(&s, "P720A-LQE-CANAUX-POSES"), "4", "contrôle : les quatre surcouches sont posées");
        let mut attendu = 0;
        for cle in ["SEME", "NTFY", "SLACK", "EMAIL", "GENERIQUE"] {
            attendu += 1;
            assert_eq!(lu(&s, &format!("P720A-LQE-ESSAI-{cle}")), format!("Some(true)/{attendu}"), "{cle} : le canal de configuration part (curl appelé)");
            assert_eq!(lu(&s, &format!("P720A-LQE-ESSAI-JUMEAU-{cle}")), format!("Some(false)/{attendu}"), "{cle} : son jumeau de l'API est refusé avant curl");
        }
    }

    // ------------------------------------------------------------------ (5) surcouche rechargée : chemin de mise à jour

    const DEST_AVANT: &str = "http://10.0.0.71/in";
    const DEST_APRES: &str = "http://10.0.0.74/in";
    const CONN_AVANT: &str = "http://10.0.0.72/api";
    const CONN_APRES: &str = "http://10.0.0.75/api";

    /// Les cibles inscrites pour un objet, `url|requête admise`, jointes.
    fn inscrites_texte(base: &str, famille: FamilleDeSurcouche, id: i64) -> String {
        ssrf_cibles_de_l_objet(base, famille, id).into_iter().map(|x| format!("{}|{}", x.url, x.requete_admise)).collect::<Vec<_>>().join(" ; ")
    }

    /// Une destination et un connecteur de surcouche chargés DEUX fois, le fichier modifié entre les deux chargements :
    /// le second prend le chemin de MISE À JOUR (la ligne existe déjà, celui de tout démarrage après le premier). Les
    /// cibles de la ligne mise à jour sont inscrites sous SON identifiant, et l'envoi part vers elles — au passage de
    /// fond des destinations, au poll manuel et au passage de fond des connecteurs.
    #[test]
    fn p720a_une_surcouche_rechargee_est_inscrite_sous_la_ligne_mise_a_jour() {
        if std::env::var(ENFANT).is_ok() {
            println!();
            let (st, base) = router_test_state("p720a-lqe-recharge");
            let dossier = crate::tmp_possede::TmpPossede::neuf("p720a-lqe-recharge");
            let (dd, dk) = (dossier.join("destinations"), dossier.join("connectors"));
            std::fs::create_dir_all(&dd).expect("dossier");
            std::fs::create_dir_all(&dk).expect("dossier");
            let ecrire = |dest: &str, conn: &str| {
                std::fs::write(dd.join("w.json"), json!({ "name": "p720a-lqe-dest-rechargee", "type": "webhook", "enabled": true, "endpoint": dest }).to_string())
                    .expect("surcouche");
                std::fs::write(dk.join("k.json"), json!({ "name": "p720a-lqe-conn-recharge", "type": "http_pull", "enabled": true,
                    "config": { "url": conn, "records_path": "items", "field_map": { "message": "msg" } } }).to_string())
                    .expect("surcouche");
            };
            let id_k = {
                let c = open_db(&base).expect("base");
                ecrire(DEST_AVANT, CONN_AVANT);
                let (d1, k1) = (crate::overlays_oac::load_overlay_destinations(&c, &dd), crate::overlays_oac::load_overlay_connectors(&c, &dk));
                let avant = (id_de(&c, "destination", "p720a-lqe-dest-rechargee"), id_de(&c, "connector", "p720a-lqe-conn-recharge"));
                ecrire(DEST_APRES, CONN_APRES);
                let (d2, k2) = (crate::overlays_oac::load_overlay_destinations(&c, &dd), crate::overlays_oac::load_overlay_connectors(&c, &dk));
                let apres = (id_de(&c, "destination", "p720a-lqe-dest-rechargee"), id_de(&c, "connector", "p720a-lqe-conn-recharge"));
                println!("P720A-LQE-RECHARGE-POSES:{}/{} puis {}/{}", d1.charges, k1.charges, d2.charges, k2.charges);
                println!("P720A-LQE-RECHARGE-MEMES-LIGNES:{}", avant == apres);
                let lignes: i64 = c.query_row("SELECT (SELECT COUNT(*) FROM destination) + (SELECT COUNT(*) FROM connector)", [], |r| r.get(0)).expect("compte");
                println!("P720A-LQE-RECHARGE-LIGNES:{lignes}");
                let base_s = crate::ledger::base_de(&c);
                println!("P720A-LQE-RECHARGE-INSCRITE-DEST:{}", inscrites_texte(&base_s, FamilleDeSurcouche::Destinations, apres.0));
                println!("P720A-LQE-RECHARGE-INSCRITE-CONN:{}", inscrites_texte(&base_s, FamilleDeSurcouche::Connecteurs, apres.1));
                c.execute("INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,'p720a','auth',3,'h1','m')", params![now()]).expect("événement");
                apres.1
            };
            let arme = crate::ledger::temoin_de_l_egress::armer(repondre);
            let _ = run_due_destinations(&st.db, &base.to_string());
            println!("P720A-LQE-RECHARGE-ENVOI-DEST:{}", vus_texte().join(" | "));
            drop(arme);
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
            let arme = crate::ledger::temoin_de_l_egress::armer(repondre);
            rt.block_on(async {
                let _ = crate::handlers::connectors::connector_poll(State(st.clone()), Extension(ergo_au("admin")), Path(id_k)).await;
            });
            println!("P720A-LQE-RECHARGE-POLL:{}", vus_texte().join(" | "));
            drop(arme);
            st.db.lock().execute("UPDATE connector SET last_run=0 WHERE id=?1", params![id_k]).expect("connecteur dû");
            let arme = crate::ledger::temoin_de_l_egress::armer(repondre);
            let _ = run_due_connectors(&st.db, &base.to_string());
            println!("P720A-LQE-RECHARGE-FOND-CONN:{}", vus_texte().join(" | "));
            drop(arme);
            println!("{FIN}");
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        preparer_l_enfant(&mut commande, "p720a_une_surcouche_rechargee_est_inscrite_sous_la_ligne_mise_a_jour");
        commande.env(ENFANT, "1");
        let (s, _) = sorties_de_l_enfant(commande);
        assert_eq!(lu(&s, "P720A-LQE-RECHARGE-POSES"), "1/1 puis 1/1", "contrôle : chaque chargement écrit la destination et le connecteur");
        assert_eq!(lu(&s, "P720A-LQE-RECHARGE-MEMES-LIGNES"), "true", "prémisse : le second chargement met à jour les lignes du premier");
        assert_eq!(lu(&s, "P720A-LQE-RECHARGE-LIGNES"), "2", "prémisse : aucune ligne insérée au second chargement");
        assert_eq!(lu(&s, "P720A-LQE-RECHARGE-INSCRITE-DEST"), format!("{DEST_APRES}|false"), "destination mise à jour : inscrite sous son identifiant");
        assert_eq!(lu(&s, "P720A-LQE-RECHARGE-INSCRITE-CONN"), format!("{CONN_APRES}|true"), "connecteur mis à jour : inscrit sous son identifiant");
        assert_eq!(lu(&s, "P720A-LQE-RECHARGE-ENVOI-DEST"), format!("POST {DEST_APRES}"), "destination mise à jour : l'envoi de fond part");
        assert_eq!(lu(&s, "P720A-LQE-RECHARGE-POLL"), format!("GET {CONN_APRES}"), "connecteur mis à jour : le poll manuel part");
        assert_eq!(lu(&s, "P720A-LQE-RECHARGE-FOND-CONN"), format!("GET {CONN_APRES}"), "connecteur mis à jour : le passage de fond part");
    }

    // ------------------------------------------------------------------ (6) inventaire du démarrage, surcouches comprises

    const LEVIERS: &str = "PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse privée";
    const LIGNE_POLITIQUE_PAR_DEFAUT: &str = "[ssrf] adresses privées (10/8, 172.16/12, 192.168/16) : REFUSÉES pour un \
canal, une destination ou un connecteur saisi par l'API ; ADMISES pour le canal semé par PLUME_NOTIFY_NTFY_URL (son URL \
exacte), les objets écrits en surcouche config.d (leurs propres cibles) et les fournisseurs d'identité et d'IA (réservés \
à l'administrateur) — PLUME_SSRF_BLOCK_PRIVATE=0 les admet partout, =1 les refuse partout, PLUME_SSRF_ALLOW exempte un \
hôte ou un CIDR";

    fn ligne_d_inventaire(genre: &str, id: i64, champ: &str, hote: &str) -> String {
        format!("[ssrf] cible privée refusée à l'envoi : {genre} #{id} ({champ}) vers l'hôte {hote:?} — {LEVIERS}")
    }

    /// Le point d'entrée du démarrage (`dire_l_egress_au_demarrage`) sur une destination (cible exacte) et deux
    /// connecteurs de surcouche — un http_pull (base des pages suivie d'une requête) et un defender (point de jeton exact
    /// ET base Graph suivie d'une requête) —, plus le jumeau de l'API de chacun (même configuration, autre identifiant).
    /// L'inventaire juge chaque cible comme l'envoi : les surcouches ne sont pas dites, leurs jumeaux le sont. Lignes
    /// ENTIÈRES, lues sur la sortie d'erreur de l'enfant.
    #[test]
    fn p720a_l_inventaire_du_demarrage_juge_les_surcouches_comme_l_envoi() {
        if std::env::var(ENFANT).is_ok() {
            println!();
            let c = test_db();
            let dossier = crate::tmp_possede::TmpPossede::neuf("p720a-lqe-inventaire");
            let (dd, dk) = (dossier.join("destinations"), dossier.join("connectors"));
            std::fs::create_dir_all(&dd).expect("dossier");
            std::fs::create_dir_all(&dk).expect("dossier");
            std::fs::write(dd.join("w.json"), json!({ "name": "p720a-lqe-inv-dest", "type": "webhook", "enabled": true, "endpoint": "http://10.0.0.81/in" }).to_string())
                .expect("surcouche");
            std::fs::write(dk.join("a.json"), json!({ "name": "p720a-lqe-inv-http", "type": "http_pull", "enabled": true,
                "config": { "url": "http://10.0.0.82/api", "records_path": "items", "field_map": { "message": "msg" } } }).to_string())
                .expect("surcouche");
            std::fs::write(dk.join("b.json"), json!({ "name": "p720a-lqe-inv-defender", "type": "defender", "enabled": true,
                "config": { "azure_tenant": "t-1", "client_id": "c-1", "login_host": "10.0.0.83", "graph_host": "10.0.0.84" } }).to_string())
                .expect("surcouche");
            let d = crate::overlays_oac::load_overlay_destinations(&c, &dd);
            let k = crate::overlays_oac::load_overlay_connectors(&c, &dk);
            println!("P720A-LQE-INVENTAIRE-POSES:{}/{}", d.charges, k.charges);
            c.execute_batch(
                "INSERT INTO destination(id,type,name,enabled,endpoint,config,filter,batch_max,interval_s) \
                   SELECT 251,type,'p720a-lqe-inv-jumeau-dest',1,endpoint,config,filter,batch_max,interval_s FROM destination WHERE name='p720a-lqe-inv-dest'; \
                 INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) \
                   SELECT 261,type,'p720a-lqe-inv-jumeau-http',1,config_json,secret,interval_s,env_id FROM connector WHERE name='p720a-lqe-inv-http'; \
                 INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) \
                   SELECT 262,type,'p720a-lqe-inv-jumeau-defender',1,config_json,secret,interval_s,env_id FROM connector WHERE name='p720a-lqe-inv-defender';",
            )
            .expect("jumeaux de l'API");
            crate::overlays_oac::dire_l_egress_au_demarrage(&c).join().expect("fil de l'inventaire");
            println!("{FIN}");
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        preparer_l_enfant(&mut commande, "p720a_l_inventaire_du_demarrage_juge_les_surcouches_comme_l_envoi");
        commande.env(ENFANT, "1");
        let (s, stderr) = sorties_de_l_enfant(commande);
        assert_eq!(lu(&s, "P720A-LQE-INVENTAIRE-POSES"), "1/2", "contrôle : les trois surcouches sont posées");
        let lignes: Vec<String> = stderr.lines().filter(|l| l.starts_with("[ssrf]")).map(str::to_string).collect();
        assert_eq!(
            lignes,
            vec![
                LIGNE_POLITIQUE_PAR_DEFAUT.to_string(),
                ligne_d_inventaire("destination", 251, "endpoint", "10.0.0.81"),
                ligne_d_inventaire("connecteur", 261, "url", "10.0.0.82"),
                ligne_d_inventaire("connecteur", 262, "login_host", "10.0.0.83"),
                ligne_d_inventaire("connecteur", 262, "graph_host", "10.0.0.84"),
            ],
            "le démarrage : les surcouches ne sont pas dites, leurs jumeaux de l'API le sont"
        );
    }

    // ------------------------------------------------------------------ (7) essai d'un connecteur : la ligne lue

    const CONN_ESSAYE: &str = "http://10.0.0.76/api";

    /// L'essai (route `connector_test`) d'un connecteur de surcouche part vers sa cible privée (contrôle). Sa ligne
    /// réécrite en base — même URL, un point de jeton ajouté (`auth.kind` à `none` : aucun jeton n'est demandé) — ne
    /// porte plus exactement les cibles inscrites : l'essai est refusé avant le réseau.
    #[test]
    fn p720a_l_essai_d_un_connecteur_juge_la_ligne_qu_il_lit() {
        if std::env::var(ENFANT).is_ok() {
            println!();
            let (st, base) = router_test_state("p720a-lqe-essai");
            let dossier = crate::tmp_possede::TmpPossede::neuf("p720a-lqe-essai");
            let d = dossier.join("connectors");
            std::fs::create_dir_all(&d).expect("dossier");
            std::fs::write(d.join("k.json"), json!({ "name": "p720a-lqe-essai", "type": "http_pull", "enabled": true,
                "config": { "url": CONN_ESSAYE, "records_path": "items", "field_map": { "message": "msg" } } }).to_string())
                .expect("surcouche");
            let id = {
                let c = open_db(&base).expect("base");
                assert_eq!(crate::overlays_oac::load_overlay_connectors(&c, &d).charges, 1, "contrôle : la surcouche est posée");
                id_de(&c, "connector", "p720a-lqe-essai")
            };
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
            let essai = |id: i64| {
                let arme = crate::ledger::temoin_de_l_egress::armer(repondre);
                let ok = rt.block_on(async {
                    let r = crate::handlers::connectors::connector_test(State(st.clone()), Extension(ergo_au("admin")), Path(id)).await;
                    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps");
                    serde_json::from_slice::<Value>(&b).ok().and_then(|v| v.get("ok").and_then(|x| x.as_bool()))
                });
                let vus = vus_texte();
                drop(arme);
                format!("{ok:?}/{}", vus.join(" | "))
            };
            println!("P720A-LQE-ESSAI-AVANT:{}", essai(id));
            let reecrite = json!({ "url": CONN_ESSAYE, "records_path": "items", "field_map": { "message": "msg" },
                "auth": { "kind": "none", "token_url": "https://192.0.2.12/jeton" } });
            st.db.lock().execute("UPDATE connector SET config_json=?1 WHERE id=?2", params![reecrite.to_string(), id]).expect("ligne réécrite");
            println!("P720A-LQE-ESSAI-APRES:{}", essai(id));
            println!("{FIN}");
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        preparer_l_enfant(&mut commande, "p720a_l_essai_d_un_connecteur_juge_la_ligne_qu_il_lit");
        commande.env(ENFANT, "1");
        let (s, _) = sorties_de_l_enfant(commande);
        assert_eq!(lu(&s, "P720A-LQE-ESSAI-AVANT"), format!("Some(true)/GET {CONN_ESSAYE}"), "contrôle : l'essai de la surcouche part");
        assert_eq!(lu(&s, "P720A-LQE-ESSAI-APRES"), "Some(false)/", "ligne réécrite : l'essai est refusé avant le réseau");
    }
}
