    // ================================================================================================
    // S7 — UNE ALERTE QUI NE DÉSIGNE PAS SA CAUSE FAIT REFAIRE LE TRAVAIL QU'ELLE PRÉTEND ÉPARGNER.
    //
    // CE QUI ÉTAIT CASSÉ. La pastille d'une source bascule sur `active_alerts > 0` (web/freshness.js), et
    // le daemon calculait ce compteur en cherchant des jetons `source=<nom>` DANS LE TEXTE de la requête
    // de la règle, recopié dans `alert.detail`. Une règle volontairement GÉNÉRIQUE — celle que le principe
    // vendor-agnostic du projet demande d'écrire — n'en porte aucun : l'alerte partait, GLOBALE, et aucune
    // source ne basculait. L'exploitant apprenait que « quelque chose » ne remonte plus et devait chercher
    // QUOI à la main.
    //
    // CE QUE CES TESTS PROUVENT, ET DANS QUEL ORDRE :
    //   1. L'AMPLEUR, dérivée du contenu LIVRÉ (jamais énumérée à la main) : combien de règles livrées le
    //      texte sait nommer, combien il ne sait pas, et le fait que les 23 capteurs n'étaient PAS
    //      nommables du tout par cette voie.
    //   2. LA MUTATION, deux fois et dans les deux sens : une source muette -> SA pastille bascule et
    //      AUCUNE autre ; deux sources muettes -> DEUX pastilles. Un test qui vérifierait seulement
    //      « une alerte est levée » reproduirait exactement le défaut.
    //   3. CE QUE ÇA NE CASSE PAS : l'alerte globale (même compte, même titre, même détail, même clé de
    //      dédup), et les alertes ANTÉRIEURES à la migration, qui retombent sur le texte à l'identique.
    //   4. L'INCONNU NOMMÉ : une source non déterminable le DIT (et se compte à part) au lieu de
    //      retomber en silence sur l'état global.
    // ================================================================================================

    /// Base sur DISQUE : `run_due_rules` et `compute_freshness` ouvrent une connexion de LECTURE sur le
    /// chemin (pool read-only), donc une base en mémoire ne traverserait pas le vrai chemin.
    fn imp_base_disque(tag: &str) -> (crate::tmp_possede::TmpPossede, String) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&w), "la chaîne de migrations doit aller au bout");
        }
        (tmp, p)
    }

    /// `n` events d'une source, le plus récent à `now - age`. Trois au minimum : `compute_freshness`
    /// écarte les feeds à moins de 3 events (`HAVING SUM(n)>=3`, anti-artefact one-shot).
    fn imp_flux(c: &Connection, source: &str, category: &str, age: i64, n: i64) {
        for i in 0..n {
            c.execute(
                "INSERT INTO event(ts,host,source,category,severity,message,dedup) VALUES(?1,'srv01',?2,?3,1,'m',?4)",
                params![now() - age - i, source, category, format!("{source}-{category}-{i}-{age}")],
            )
            .unwrap();
        }
    }

    /// L'AVEU d'un capteur : « je ne peux pas collecter » (`category=config`, `fields.collect_status=
    /// unavailable`), la forme EXACTE que pose `plume_unavailable` dans `collectors/lib.sh` et que la
    /// règle livrée `de-collector-unavailable.json` recherche.
    fn imp_aveu_indisponible(c: &Connection, source: &str) {
        c.execute(
            "INSERT INTO event(ts,host,source,category,severity,message,fields,dedup) \
             VALUES(?1,'srv01',?2,'config',2,'collecte impossible','{\"collect_status\":\"unavailable\"}',?3)",
            params![now() - 30, source, format!("{source}-unavail")],
        )
        .unwrap();
    }

    /// `active_alerts` du feed `name` tel que /api/freshness le rend. `None` = le feed n'existe pas.
    fn imp_alertes_du_feed(v: &Value, name: &str) -> Option<i64> {
        v["feeds"].as_array()?.iter().find(|f| f["name"] == name).and_then(|f| f["active_alerts"].as_i64())
    }

    /// La règle livrée `de-collector-unavailable.json`, posée DUE (last_run NULL) et ACTIVE.
    fn imp_pose_la_regle_generique(c: &Connection) {
        c.execute(
            "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed) \
             VALUES('Catalogue — Couverture: un capteur déclare ne PAS pouvoir collecter',1,\
                    'search category=config collect_status=unavailable | stats count',1,'>',0.0,2,600,7200,'T1562.001',1)",
            [],
        )
        .unwrap();
    }

    // ---------------------------------------------------------------------------------------------
    // (1) L'AMPLEUR — DÉRIVÉE DU CONTENU LIVRÉ
    // ---------------------------------------------------------------------------------------------

    /// COMBIEN DE RÈGLES LIVRÉES LE TEXTE SAIT NOMMER, ET COMBIEN IL NE SAIT PAS. Le corpus n'est PAS
    /// énuméré ici : il est BALAYÉ dans `config.d/rules/**` (l'overlay livré, celui que le loader pose),
    /// et chaque requête passe par `extract_query_sources` — le mécanisme HISTORIQUE lui-même. Ce test
    /// mesure donc l'ANGLE MORT du mécanisme avec le mécanisme, ce qui est la seule façon d'être sûr que
    /// le chiffre décrit le code livré et pas une lecture à la main.
    ///
    /// MESURÉ le 2026-08-20 : 47 règles livrées, 36 portant un jeton `source=`, 11 n'en portant AUCUN —
    /// dont 4 ACTIVES par défaut. Les 11 sont exactement les règles NORMALISÉES CIM (`search
    /// category=firewall …`, `search category=config collect_status=unavailable …`) : le mécanisme textuel
    /// punit précisément les règles que le principe vendor-agnostic du projet demande d'écrire.
    ///
    /// LES BORNES SONT ASSERTÉES, PAS LES TOTAUX. Un total figé casserait au premier ajout de règle et
    /// serait « corrigé » sans être lu ; ce qui doit tenir, c'est que la FAMILLE existe (au moins une
    /// règle générique, et au moins une ACTIVE) — le jour où elle disparaît, ce test le dit, et c'est une
    /// information, pas une panne.
    #[test]
    fn imputation_ampleur_du_contenu_livre() {
        fn balaye(dir: &std::path::Path, out: &mut Vec<(String, String, bool)>) {
            let Ok(rd) = std::fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    balaye(&p, out);
                } else if p.extension().and_then(|x| x.to_str()) == Some("json") {
                    let Ok(txt) = std::fs::read_to_string(&p) else { continue };
                    let Ok(v) = serde_json::from_str::<Value>(&txt) else { continue };
                    let Some(q) = v["query"].as_str() else { continue };
                    out.push((
                        p.file_name().unwrap().to_string_lossy().to_string(),
                        q.to_string(),
                        v["enabled"].as_bool().unwrap_or(false),
                    ));
                }
            }
        }
        let racine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../config.d/rules");
        let mut regles = Vec::new();
        balaye(&racine, &mut regles);
        assert!(regles.len() >= 40, "corpus de règles livrées introuvable ou tronqué : {}", regles.len());
        let nommables = regles.iter().filter(|(_, q, _)| !extract_query_sources(q).is_empty()).count();
        let muettes: Vec<&(String, String, bool)> =
            regles.iter().filter(|(_, q, _)| extract_query_sources(q).is_empty()).collect();
        let muettes_actives = muettes.iter().filter(|(_, _, on)| *on).count();
        assert!(
            !muettes.is_empty(),
            "aucune règle livrée n'est générique : la famille S7 aurait disparu, ce qui mérite d'être lu \
             ({} règles, {nommables} nommables par le texte)",
            regles.len()
        );
        assert!(
            muettes_actives >= 1,
            "les règles génériques existent mais aucune n'est ACTIVE : l'écart ne serait plus qu'une \
             question de bibliothèque ({} générique(s) trouvée(s))",
            muettes.len()
        );
        assert!(
            muettes.iter().any(|(f, _, _)| f == "de-collector-unavailable.json"),
            "la règle de capteur indisponible n'est plus dans le corpus générique : {:?}",
            muettes.iter().map(|(f, _, _)| f).collect::<Vec<_>>()
        );
    }

    /// L'AUTRE MOITIÉ DE L'AMPLEUR : les 23 CAPTEURS. Le `detail` d'une alerte de capteur muet est une
    /// PHRASE (« aucune donnée depuis N min ») — elle ne porte aucun jeton `source=`, donc AUCUN des 23
    /// n'était imputable par la voie textuelle. Ce test le montre par le mécanisme (contrôle NÉGATIF) et
    /// montre, par le même balayage, que le descripteur TYPÉ de chaque sonde, lui, sait répondre.
    ///
    /// GARDE DÉRIVÉE, jamais une liste : elle porte sur TOUTE entrée de `COLLECTORS`, donc une 24ᵉ ajoutée
    /// demain est couverte sans que personne ne rouvre ce fichier. Et l'unique sonde qui ne PEUT pas
    /// nommer son feed (les métriques, dont le feed est nommé dynamiquement « métriques · N séries ») est
    /// comptée séparément : c'est un aveu, pas un oubli.
    #[test]
    fn imputation_les_capteurs_ne_sont_pas_nommables_par_le_texte_mais_par_leur_sonde() {
        let detail_type = "aucune donnée depuis 12 min — machines en retard : srv01 (12 min)";
        assert!(
            extract_query_sources(detail_type).is_empty(),
            "CONTRÔLE NÉGATIF : le détail d'une alerte de capteur muet ne porte aucun jeton `source=`"
        );
        let mut nommes = 0usize;
        let mut indeterminables = 0usize;
        for (id, _label, _iv, sonde, _eb) in COLLECTORS.iter() {
            let imp = imputer_alerte_de_capteur(sonde);
            assert!(!imp.is_empty(), "capteur `{id}` : la sonde n'impute rien du tout");
            if imp.iter().any(|s| s == SOURCE_INDETERMINABLE) {
                indeterminables += 1;
            } else {
                nommes += 1;
            }
        }
        assert_eq!(
            indeterminables, 1,
            "une seule sonde ne peut pas nommer son feed (les métriques) ; si ce chiffre monte, une sonde \
             a été ajoutée sans savoir à quoi elle s'impute"
        );
        assert_eq!(nommes + indeterminables, COLLECTORS.len(), "tous les capteurs sont couverts");
    }

    // ---------------------------------------------------------------------------------------------
    // (2) LA PREUVE PAR MUTATION — L'ÉTAT DE LA SOURCE FAUTIVE, ET SEULEMENT LE SIEN
    // ---------------------------------------------------------------------------------------------

    /// MUTATION A — UN capteur devient muet. SA source bascule ; les autres NON.
    ///
    /// Le battement de santé de `crowdsec` est vieux de 1 h (tolérance : 5 x 300 s = 25 min) pendant que
    /// `ufw` bat encore et que `web` alimente le pipeline. AVANT : `active_alerts` valait 0 pour TOUT le
    /// monde, y compris pour crowdsec — l'alerte existait et ne désignait personne. Le contrôle NÉGATIF
    /// est fait ICI, sur l'alerte réellement écrite : son `detail` ne contient aucun jeton `source=`,
    /// donc la voie textuelle ne pouvait rien en tirer.
    #[test]
    fn imputation_un_capteur_muet_bascule_sa_source_et_seulement_elle() {
        let (_tmp, p) = imp_base_disque("imps7a");
        {
            let w = Connection::open(&p).unwrap();
            imp_flux(&w, "crowdsec", "health", 3600, 4); // MUET : > 5 x 300 s
            imp_flux(&w, "ufw", "health", 20, 4); // bat encore
            imp_flux(&w, "web", "web", 10, 4); // garde le pipeline frais
            rollup_events(&w);
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        check_heartbeats(&db);
        let (regles, detail, sources): (Vec<String>, String, String) = {
            let c = db.lock();
            let mut s = c.prepare("SELECT rule FROM alert WHERE rule LIKE 'heartbeat.%' ORDER BY rule").unwrap();
            let r: Vec<String> = s.query_map([], |x| x.get::<_, String>(0)).unwrap().flatten().collect();
            drop(s);
            let (d, so): (String, String) = c
                .query_row(
                    "SELECT COALESCE(detail,''), COALESCE(sources,'') FROM alert WHERE rule='heartbeat.crowdsec-health'",
                    [],
                    |x| Ok((x.get(0)?, x.get(1)?)),
                )
                .unwrap();
            (r, d, so)
        };
        assert_eq!(regles, vec!["heartbeat.crowdsec-health"], "un seul capteur est muet");
        assert!(
            extract_query_sources(&detail).is_empty(),
            "CONTRÔLE NÉGATIF sur l'alerte RÉELLE : le texte ne sait pas la nommer ({detail})"
        );
        assert_eq!(imputation_decoder(&sources), vec!["crowdsec".to_string()], "la DONNÉE la nomme");
        let v = compute_freshness(&p, None);
        assert_eq!(imp_alertes_du_feed(&v, "crowdsec"), Some(1), "LA source fautive bascule");
        assert_eq!(imp_alertes_du_feed(&v, "ufw"), Some(0), "la source saine ne bascule PAS");
        assert_eq!(imp_alertes_du_feed(&v, "web"), Some(0), "la source saine ne bascule PAS");
        assert_eq!(v["unattributed_alerts"], 0, "rien n'est resté orphelin");
    }

    /// TÉMOIN INVERSE de la mutation A — DEUX capteurs muets, DEUX pastilles. Ce n'est pas la même
    /// affirmation que « une source bascule » : un mécanisme qui imputerait tout à la PREMIÈRE source
    /// trouvée passerait le test précédent et échouerait ici.
    #[test]
    fn imputation_deux_capteurs_muets_font_basculer_deux_sources() {
        let (_tmp, p) = imp_base_disque("imps7b");
        {
            let w = Connection::open(&p).unwrap();
            imp_flux(&w, "crowdsec", "health", 3600, 4); // MUET
            imp_flux(&w, "ufw", "health", 3600, 4); // MUET aussi
            imp_flux(&w, "web", "web", 10, 4); // garde le pipeline frais
            rollup_events(&w);
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        check_heartbeats(&db);
        let regles: Vec<String> = {
            let c = db.lock();
            let mut s = c.prepare("SELECT rule FROM alert WHERE rule LIKE 'heartbeat.%' ORDER BY rule").unwrap();
            s.query_map([], |x| x.get::<_, String>(0)).unwrap().flatten().collect()
        };
        assert_eq!(regles, vec!["heartbeat.crowdsec-health", "heartbeat.ufw-health"], "deux capteurs muets");
        let v = compute_freshness(&p, None);
        assert_eq!(imp_alertes_du_feed(&v, "crowdsec"), Some(1), "la 1re bascule");
        assert_eq!(imp_alertes_du_feed(&v, "ufw"), Some(1), "la 2de bascule AUSSI (pas une alerte globale de plus)");
        assert_eq!(imp_alertes_du_feed(&v, "web"), Some(0), "la source saine ne bascule pas");
    }

    /// MUTATION B — LE CAS S7 LUI-MÊME : la RÈGLE générique livrée. `search category=config
    /// collect_status=unavailable | stats count` ne nomme aucune source ; l'événement qui la fait tirer,
    /// lui, porte `source='auditd'` DANS SA COLONNE. C'est ce champ que l'imputation lit désormais.
    #[test]
    fn imputation_regle_generique_bascule_la_source_qui_a_avoue() {
        let (_tmp, p) = imp_base_disque("imps7c");
        {
            let w = Connection::open(&p).unwrap();
            imp_pose_la_regle_generique(&w);
            imp_flux(&w, "auditd", "exec", 20, 4);
            imp_flux(&w, "web", "web", 10, 4);
            imp_aveu_indisponible(&w, "auditd");
            rollup_events(&w);
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_due_rules(&db, &p);
        let (n, detail, sources): (i64, String, String) = {
            let c = db.lock();
            let n: i64 = c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
            let (d, s): (String, String) = c
                .query_row("SELECT COALESCE(detail,''), COALESCE(sources,'') FROM alert", [], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap();
            (n, d, s)
        };
        assert_eq!(n, 1, "UNE alerte (globale), comme avant : rien n'a été multiplié");
        assert!(
            extract_query_sources(&detail).is_empty(),
            "CONTRÔLE NÉGATIF : le texte de la règle ne nomme aucune source ({detail})"
        );
        assert_eq!(imputation_decoder(&sources), vec!["auditd".to_string()], "la colonne `source` la nomme");
        let v = compute_freshness(&p, None);
        assert_eq!(imp_alertes_du_feed(&v, "auditd"), Some(1), "la source qui a avoué bascule");
        assert_eq!(imp_alertes_du_feed(&v, "web"), Some(0), "l'autre source ne bascule PAS");
    }

    /// TÉMOIN INVERSE de la mutation B — DEUX capteurs avouent, DEUX pastilles basculent, sous UNE SEULE
    /// alerte globale. C'est le point qui distingue « imputer » de « dupliquer l'alerte » : le compte
    /// d'alertes ne bouge pas, ce sont les états de source qui bougent.
    #[test]
    fn imputation_deux_aveux_font_basculer_deux_sources_sous_une_seule_alerte() {
        let (_tmp, p) = imp_base_disque("imps7d");
        {
            let w = Connection::open(&p).unwrap();
            imp_pose_la_regle_generique(&w);
            imp_flux(&w, "auditd", "exec", 20, 4);
            imp_flux(&w, "integrity", "integrity", 20, 4);
            imp_flux(&w, "web", "web", 10, 4);
            imp_aveu_indisponible(&w, "auditd");
            imp_aveu_indisponible(&w, "integrity");
            rollup_events(&w);
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_due_rules(&db, &p);
        let (n, sources): (i64, String) = {
            let c = db.lock();
            let n: i64 = c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
            let s: String = c.query_row("SELECT COALESCE(sources,'') FROM alert", [], |r| r.get(0)).unwrap();
            (n, s)
        };
        assert_eq!(n, 1, "TOUJOURS une seule alerte globale — l'imputation n'en fabrique pas");
        let mut imp = imputation_decoder(&sources);
        imp.sort();
        assert_eq!(imp, vec!["auditd".to_string(), "integrity".to_string()], "les DEUX sources sont nommées");
        let v = compute_freshness(&p, None);
        assert_eq!(imp_alertes_du_feed(&v, "auditd"), Some(1), "la 1re bascule");
        assert_eq!(imp_alertes_du_feed(&v, "integrity"), Some(1), "la 2de bascule AUSSI");
        assert_eq!(imp_alertes_du_feed(&v, "web"), Some(0), "la source saine ne bascule pas");
    }

    // ---------------------------------------------------------------------------------------------
    // (3) CE QUE ÇA NE CASSE PAS
    // ---------------------------------------------------------------------------------------------

    /// L'ALERTE GLOBALE EST INTACTE. Des exploitants s'en servent : elle garde son compte, son titre, sa
    /// sévérité, son `detail` (la requête de la règle, sur laquelle repose le drill « voir les événements
    /// déclencheurs ») et sa clé de dédup. Ce qu'elle GAGNE est une colonne. Ce test le dit champ par
    /// champ, parce qu'une régression de forme d'alerte ne se verrait nulle part ailleurs.
    #[test]
    fn imputation_ne_cree_ni_ne_retitre_aucune_alerte() {
        let (_tmp, p) = imp_base_disque("imps7e");
        {
            let w = Connection::open(&p).unwrap();
            imp_pose_la_regle_generique(&w);
            imp_flux(&w, "auditd", "exec", 20, 4);
            imp_aveu_indisponible(&w, "auditd");
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        run_due_rules(&db, &p);
        run_due_rules(&db, &p); // 2e tour : l'épisode est DÉJÀ ouvert (INSERT OR IGNORE no-op)
        let c = db.lock();
        let n: i64 = c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
        let (rule, sev, title, detail, dedup, mitre): (String, i64, String, String, String, String) = c
            .query_row(
                "SELECT rule,severity,COALESCE(title,''),COALESCE(detail,''),COALESCE(dedup,''),COALESCE(mitre,'') FROM alert",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!(n, 1, "UNE alerte, deux tours plus tard : la dédup tient toujours");
        assert!(rule.starts_with("rule."), "la règle porte toujours son identifiant : {rule}");
        assert_eq!(sev, 2, "sévérité inchangée");
        assert!(title.contains("Catalogue"), "titre inchangé : {title}");
        assert_eq!(detail, "search category=config collect_status=unavailable | stats count", "detail = requête de la règle, INCHANGÉ");
        assert!(dedup.starts_with("rule-"), "clé de dédup inchangée : {dedup}");
        assert_eq!(mitre, "T1562.001", "MITRE hérité, inchangé");
    }

    /// LES ALERTES D'AVANT LA MIGRATION. `sources=''` signifie « levée par un binaire antérieur » : le
    /// lecteur DOIT retomber sur l'extraction textuelle, sinon la mise à jour effacerait des pastilles
    /// déjà justes. On pose une alerte à la main dans l'ancienne forme et on vérifie que le feed qu'elle
    /// nommait dans son texte bascule toujours.
    #[test]
    fn imputation_alerte_anterieure_retombe_sur_le_texte() {
        let (_tmp, p) = imp_base_disque("imps7f");
        {
            let w = Connection::open(&p).unwrap();
            imp_flux(&w, "web", "web", 10, 4);
            rollup_events(&w);
            w.execute(
                "INSERT INTO alert(ts,rule,severity,title,detail,dedup) \
                 VALUES(?1,'rule.99',3,'ancienne','search source=web status>=500 | stats count','rule-99')",
                params![now() - 60],
            )
            .unwrap();
            let vide: String = w.query_row("SELECT sources FROM alert", [], |r| r.get(0)).unwrap();
            assert_eq!(vide, "", "la colonne v115 vaut bien '' pour une alerte posée sans elle");
        }
        let v = compute_freshness(&p, None);
        assert_eq!(imp_alertes_du_feed(&v, "web"), Some(1), "le repli textuel imputait, et impute toujours");
        assert_eq!(v["unattributed_alerts"], 0, "une alerte que le texte sait nommer n'est pas orpheline");
    }

    // ---------------------------------------------------------------------------------------------
    // (4) L'INCONNU NOMMÉ
    // ---------------------------------------------------------------------------------------------

    /// UNE SOURCE QU'ON NE SAIT PAS NOMMER LE DIT. Le capteur de métriques est muet ; son feed est nommé
    /// DYNAMIQUEMENT par la fraîcheur (« métriques · N séries »), donc il n'existe aucun nom stable à
    /// imputer. L'alerte porte alors l'inconnu NOMMÉ, elle est COMPTÉE à part (`unattributed_alerts`), et
    /// surtout elle n'accuse AUCUNE source au hasard — ce qui serait pire que de ne rien dire.
    #[test]
    fn imputation_source_non_determinable_est_nommee_pas_silencieuse() {
        let (_tmp, p) = imp_base_disque("imps7g");
        {
            let w = Connection::open(&p).unwrap();
            imp_flux(&w, "web", "web", 10, 4); // pipeline frais + un feed qui ne doit PAS être accusé
            // métrique VIEILLE : capteur `resources`, intervalle 60 s -> muet au-delà de 5 x 60 s.
            w.execute("INSERT INTO metric(ts,host,name,value) VALUES(?1,'srv01','cpu',1.0)", params![now() - 400]).unwrap();
            rollup_events(&w);
        }
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        check_heartbeats(&db);
        let (regles, sources): (Vec<String>, String) = {
            let c = db.lock();
            let mut s = c.prepare("SELECT rule FROM alert WHERE rule LIKE 'heartbeat.%' ORDER BY rule").unwrap();
            let r: Vec<String> = s.query_map([], |x| x.get::<_, String>(0)).unwrap().flatten().collect();
            drop(s);
            let so: String = c
                .query_row("SELECT COALESCE(sources,'') FROM alert WHERE rule='heartbeat.resources'", [], |x| x.get(0))
                .unwrap();
            (r, so)
        };
        assert_eq!(regles, vec!["heartbeat.resources"], "seul le capteur de métriques est muet");
        assert_eq!(sources, SOURCE_INDETERMINABLE, "l'alerte DIT qu'elle ne sait pas nommer sa source");
        let v = compute_freshness(&p, None);
        assert_eq!(v["unattributed_alerts"], 1, "l'orpheline est COMPTÉE, pas diluée");
        assert_eq!(imp_alertes_du_feed(&v, "web"), Some(0), "et elle n'accuse personne au hasard");
    }

    /// LA FORME STOCKÉE. Le vide devient l'inconnu NOMMÉ (jamais la chaîne vide, qui signifie « alerte
    /// d'avant la migration » et déclencherait le repli textuel en silence), les doublons fusionnent,
    /// l'ordre d'arrivée est préservé, et le plafond DIT qu'il a mordu au lieu de tronquer sans un mot.
    #[test]
    fn imputation_forme_stockee_ne_perd_rien_en_silence() {
        assert_eq!(imputation_encoder(&[]), SOURCE_INDETERMINABLE, "vide -> inconnu NOMMÉ, jamais ''");
        assert_eq!(imputation_encoder(&["".to_string()]), SOURCE_INDETERMINABLE, "un nom vide est un inconnu");
        let deux = imputation_encoder(&["auditd".into(), "web".into(), "auditd".into()]);
        assert_eq!(imputation_decoder(&deux), vec!["auditd".to_string(), "web".to_string()], "dédup, ordre préservé");
        assert!(imputation_decoder("").is_empty(), "'' = alerte d'avant la migration -> le lecteur replie");
        let beaucoup: Vec<String> = (0..64).map(|i| format!("src{i}")).collect();
        let borne = imputation_decoder(&imputation_encoder(&beaucoup));
        assert!(borne.len() <= 32, "la liste est BORNÉE ({} noms)", borne.len());
        assert!(
            borne.contains(&SOURCE_INDETERMINABLE.to_string()),
            "quand le plafond mord, la liste DIT qu'elle est tronquée"
        );
    }

    /// GARDE DÉRIVÉE — AUCUN PRODUCTEUR D'ALERTE NE REJOINT LA LISTE EN SILENCE. Le périmètre est QUATRE
    /// producteurs sur onze ; les sept autres retombent volontairement sur le chemin textuel, à
    /// l'identique. Ce qui doit tenir, ce n'est pas ce partage — c'est qu'il soit un CHOIX à chaque fois.
    ///
    /// LE QUATRIÈME (P3.9-a) est l'alerte de DÉTECTION AVEUGLE : elle se rapporte à une RÈGLE qui ne
    /// peut plus être évaluée, et à aucun feed — elle impute à l'inconnu NOMMÉ, pour la même raison que
    /// la flotte. Cette garde l'a arrêtée à son tour, et c'est ici que son choix est dit.
    ///
    /// LE TROISIÈME, AJOUTÉ PAR P3.2-a, EST CELUI QUI PROUVE QUE LA GARDE SERT. La sonde de flotte
    /// (`verifier_flotte_muette`) a été écrite sans penser à l'imputation ; ce test l'a arrêtée. Elle
    /// impute — mais à l'INCONNU NOMMÉ, et c'est le choix qu'elle DIT ici : son alerte se rapporte à des
    /// HÔTES et à aucun feed. Lui attribuer une source ferait basculer la pastille d'une source qui n'a
    /// rien fait ; laisser la colonne VIDE la ferait retomber en silence sur l'extraction textuelle.
    ///
    /// Le corpus n'est pas énuméré : il est LU DANS LA SOURCE (`daemon/src/**/*.rs`, tests exclus), site
    /// par site, en découpant la liste de colonnes de chaque `INSERT … INTO alert(…)`. Un huitième
    /// producteur ajouté demain fait échouer ce test, et son auteur doit alors dire lequel des deux
    /// chemins il prend. Une garde qui aurait ÉNUMÉRÉ les sept n'aurait rien dit du huitième.
    #[test]
    fn imputation_tout_producteur_d_alerte_declare_son_choix() {
        fn balaye(dir: &std::path::Path, out: &mut Vec<(String, bool)>) {
            let Ok(rd) = std::fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                let nom = p.file_name().unwrap_or_default().to_string_lossy().to_string();
                if p.is_dir() {
                    if nom != "tests" {
                        balaye(&p, out);
                    }
                } else if nom.ends_with(".rs") && nom != "tests.rs" {
                    let Ok(t) = std::fs::read_to_string(&p) else { continue };
                    let mut i = 0usize;
                    while let Some(k) = t[i..].find("INTO alert(") {
                        let deb = i + k + "INTO alert(".len();
                        let Some(fin) = t[deb..].find(')') else { break };
                        // La liste de colonnes peut être coupée par une continuation de chaîne Rust
                        // (`\` + saut de ligne) : on retire tout blanc et toute barre oblique inverse.
                        let cols: String =
                            t[deb..deb + fin].chars().filter(|c| !c.is_whitespace() && *c != '\\').collect();
                        out.push((format!("{}", p.display()), cols.split(',').any(|c| c == "sources")));
                        i = deb + fin;
                    }
                }
            }
        }
        let racine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sites = Vec::new();
        balaye(&racine, &mut sites);
        let imputent: Vec<&(String, bool)> = sites.iter().filter(|(_, ok)| *ok).collect();
        assert_eq!(
            sites.len(),
            11,
            "le nombre de producteurs d'alerte a bougé ({} trouvés) : chaque producteur doit dire s'il \
             impute depuis la DONNÉE (colonne `sources`) ou s'il retombe sur le texte de la règle. \
             Sites : {:?}",
            sites.len(),
            sites
        );
        assert_eq!(
            imputent.len(),
            4,
            "le partage a bougé : {} producteur(s) imputent depuis la donnée. Si c'est voulu, le bandeau \
             de daemon/src/imputation.rs doit le dire aussi. Sites : {:?}",
            imputent.len(),
            imputent
        );
        assert!(
            imputent.iter().any(|(f, _)| f.ends_with("detection.rs")),
            "l'ordonnanceur de règles impute : {imputent:?}"
        );
        assert!(
            imputent.iter().any(|(f, _)| f.ends_with("detection_aveugle.rs")),
            "l'alerte de détection aveugle impute (à l'inconnu NOMMÉ : une règle éteinte n'accuse aucun feed) : {imputent:?}"
        );
        assert!(
            imputent.iter().filter(|(f, _)| f.ends_with("freshness.rs")).count() == 2,
            "les DEUX dead-man's-switches de `freshness.rs` imputent — celui des CAPTEURS (au feed de sa \
             sonde) et celui de la FLOTTE (à l'inconnu NOMMÉ : une alerte d'hôtes ne se rapporte à aucun \
             feed) : {imputent:?}"
        );
    }
