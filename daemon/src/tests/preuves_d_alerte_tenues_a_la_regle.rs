// =====================================================================================
// `P11.25-g` — LES PREUVES D'UNE ALERTE RESTENT CELLES DE LA RÈGLE QUI L'A LEVÉE.
//
// Les preuves de la règle « attaquant actif non banni » listent les adresses que son nombre compte. Ce fichier tient
// ce que les témoins de `preuves_d_alerte_attaquant_actif_non_banni.rs` ne tenaient pas :
//   (a) une modification de la requête de la règle par l'administrateur (`POST /api/rules/{id}`) retire sa requête de
//       preuves : l'alerte suivante n'en porte aucune, plutôt que des adresses que la règle ne compte plus ; une
//       modification du seuil et de la sévérité seuls la garde ;
//   (b) les bords de la population : une adresse à exactement 20 réponses (le plancher, non comptée) et une à 21
//       (comptée), des défis cloudflare dont l'action n'est pas `challenged` (non comptés), de l'activité hors de la
//       fenêtre (non comptée) ; le nombre de la règle égale le nombre de preuves, lignes exactes ;
//   (c) un filtre de champs sur `status` ou sur `action` (les champs dont dépend le compte par adresse) retient les
//       preuves, comme un filtre sur `src_ip` ;
//   (d) une règle sans fenêtre (`window_s` = 0) dit `from` = 0, quelle que soit l'issue ;
//   (e) une règle livrée renommée par l'exploitant (requête exacte) ne reçoit pas la requête de preuves en v126 ;
//   (f) les preuves sont lues une fois par LEVÉE : un épisode déjà ouvert ne les relit pas ; un épisode résolu entre
//       la sélection et l'écriture lève quand même son alerte (sans preuves) ; une nouvelle levée les relit ;
//   (g) le bord de statut de la branche web : des réponses 302 et 399 ne sont ni comptées ni prouvées, une réponse
//       400 l'est ; lignes exactes, nombre de la règle == nombre de preuves ;
//   (h) des événements à adresse vide (web et cloudflare) ne sont ni comptés ni prouvés ;
//   (i) une règle qui déclare des preuves et ne tire pas ne les lit pas (compteur de lectures inchangé sur un tick où
//       elle est évaluée) ; la même, quand elle tire, les lit une fois ;
//   (j) la ligne de journal de (f), écrite quand une alerte part sans preuves parce que son épisode était ouvert à la
//       sélection, capturée ENTIÈRE dans un sous-processus (crochet `AVANT_LES_ECRITURES_DU_TICK`) ; aucune ligne à la
//       levée ordinaire ni sur l'épisode ouvert qui suit ;
//   (k) un overlay `config.d` (`rules/*.json`, `sigma/*.json`) qui réimpose la règle livrée sous son nom change sa
//       requête et sa nature : la requête de preuves est retirée au chargement réel, l'alerte suivante ne porte aucune
//       preuve et son tick n'écrit aucune ligne WARN ; une réimposition à requête et nature identiques la garde, une
//       requête changée la retire. Le prédicat est celui de (a) (`preuves_d_alerte`, partagé par les trois gestes).
//
// MUTANTS JOUÉS (variable d environnement de mutation, retirés avant le commit) : CC1R_PREUVES_GARDEES (a) ;
// CC1R_FENETRE0, CC1R_PLANCHER20, CC1R_ACTION (b) ; CC1R_MASQUE_SRCIP (c) ; CC1R_FROM0 (d) ; CC1R_NOM (e) ;
// CC1R_RELIT_OUVERT (f) ; CC1C_POP_300 (statut >=300 dans la requête de preuves jouée) (g) ; CC1C_IP_VIDE_WEB,
// CC1C_IP_VIDE_CF (condition d'adresse non vide retirée d'une branche) (h) ; CC1C_LIT_SANS_TIR (filtre de tir retiré
// de la phase 2 ter) (i) ; CC1C_LOG_OUVERT (ligne retirée) (j) ; CC1C_JSON_SANS, CC1C_SIGMA_SANS (prédicat retiré
// d'une réimposition), CC1C_JSON_TOUJOURS_NULL, CC1C_SIGMA_TOUJOURS_NULL (preuves retirées même à l'identique) (k) ;
// CC1C_RU_SANS (prédicat retiré de `rule_update`) (a).
// =====================================================================================
mod preuves_d_alerte_tenues_a_la_regle {
    use super::*;
    use crate::mesure_environnement::Mesure;

    const CC1R_NOM_V52: &str = "Attaquant actif NON banni (web 4xx / CF challenged sans mitigation)";

    fn cc1r_preparer(p: &str) {
        let w = open_db(p).unwrap();
        w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&w), "fixture : la chaîne de migrations va au bout");
        crate::seeds::seed_detection_rules(&w);
        w.execute("UPDATE rule SET enabled = (name = ?1)", params![CC1R_NOM_V52]).unwrap();
    }

    fn cc1r_base(tag: &str) -> crate::tmp_possede::TmpDb {
        let p = crate::tmp_possede::TmpDb::neuf(&format!("cc1r-{tag}"));
        cc1r_preparer(p.as_str());
        p
    }

    /// `n` événements par (adresse, genre, âge en secondes) : `web` = réponse 404, `web_<statut>` = réponse de ce statut,
    /// `cloudflare` = défi `challenged`, `cloudflare_block` = action `block` (non comptée par la règle).
    fn cc1r_evenements(p: &str, lots: &[(&str, &str, usize, i64)]) {
        let w = open_db(p).unwrap();
        let maintenant = now();
        for (ip, genre, n, age) in lots {
            let (source, fields) = match *genre {
                "web" => ("web", "{\"status\":\"404\"}".to_string()),
                "cloudflare" => ("cloudflare", "{\"action\":\"challenged\"}".to_string()),
                "cloudflare_block" => ("cloudflare", "{\"action\":\"block\"}".to_string()),
                autre => match autre.strip_prefix("web_") {
                    Some(statut) => ("web", format!("{{\"status\":\"{statut}\"}}")),
                    None => panic!("genre de fixture inconnu : {autre}"),
                },
            };
            for i in 0..*n {
                w.execute(
                    "INSERT INTO event(ts,source,severity,src_ip,fields,dedup) VALUES(?1,?2,2,?3,?4,?5)",
                    params![maintenant - age, source, ip, fields, format!("cc1r-{ip}-{genre}-{age}-{i}")],
                )
                .unwrap();
            }
        }
    }

    /// Trois adresses comptées, dans la fenêtre.
    fn cc1r_trois_comptees(p: &str) {
        cc1r_evenements(p, &[("198.51.100.20", "cloudflare", 40, 60), ("203.0.113.10", "web", 30, 60), ("192.0.2.30", "web", 25, 60)]);
    }

    fn cc1r_tick(p: &str) -> crate::bilan_de_tick::BilanDeTick {
        let db = Arc::new(Mutex::new(open_db(p).unwrap()));
        run_due_rules(&db, p)
    }

    fn cc1r_id(p: &str) -> i64 {
        open_db(p).unwrap().query_row("SELECT id FROM rule WHERE name=?1", params![CC1R_NOM_V52], |r| r.get(0)).unwrap()
    }

    fn cc1r_requete_de_preuves(p: &str, id: i64) -> Option<String> {
        open_db(p).unwrap().query_row("SELECT evidence_query FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap()
    }

    /// (valeur, preuves écrites) de l'alerte OUVERTE de la règle `id` (celle qui porte sa clé).
    fn cc1r_alerte_ouverte(p: &str, id: i64) -> (Option<f64>, Option<String>) {
        open_db(p)
            .unwrap()
            .query_row("SELECT current_value,evidence FROM alert WHERE dedup=?1", params![format!("rule-{id}")], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
    }

    fn cc1r_json(s: &str) -> Value {
        serde_json::from_str(s).unwrap_or_else(|e| panic!("preuves écrites en JSON : {e} : {s}"))
    }

    fn cc1r_admin() -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("root:rootpw1234567"))
    }

    fn cc1r_corps_json(reponse: &str) -> Value {
        let corps = reponse.split_once("\r\n\r\n").map(|(_, c)| c.to_string()).unwrap_or_default();
        let objet = match (corps.find('{'), corps.rfind('}')) {
            (Some(a), Some(b)) if a < b => corps[a..=b].to_string(),
            _ => corps.clone(),
        };
        serde_json::from_str(&objet).unwrap_or_else(|e| panic!("corps JSON : {e} : {reponse}"))
    }

    // ------------------------------------------------------------------------------------------------------- (a)

    #[tokio::test]
    async fn cc1r_requete_modifiee_par_l_admin_retire_les_preuves_seuil_seul_les_garde() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, dbp) = router_test_state("cc1r-edition");
        {
            let w = open_db(dbp.as_str()).unwrap();
            crate::seeds::seed_detection_rules(&w);
            w.execute("UPDATE rule SET enabled = (name = ?1)", params![CC1R_NOM_V52]).unwrap();
        }
        cc1r_trois_comptees(dbp.as_str());
        let id = cc1r_id(dbp.as_str());
        assert_eq!(cc1r_requete_de_preuves(dbp.as_str(), id).as_deref(), Some(crate::seeds::ATTACKER_UNMITIGATED_EVIDENCE_SQL), "fixture : posée");
        let addr = router_serve(st).await;
        let json_ct = [("Content-Type", "application/json")];
        // Seuil et sévérité seuls : la population ne change pas, la requête de preuves reste.
        let (code, reponse) = router_probe_envoi(addr, "POST", &format!("/api/rules/{id}"), Some(&cc1r_admin()), &json_ct, r#"{"threshold":0.0,"severity":4}"#).await;
        assert_eq!(code, 200, "{reponse}");
        assert_eq!(cc1r_requete_de_preuves(dbp.as_str(), id).as_deref(), Some(crate::seeds::ATTACKER_UNMITIGATED_EVIDENCE_SQL), "seuil seul : la requête de preuves reste");
        // La requête renvoyée À L'IDENTIQUE (enregistrement d'un formulaire) : elle reste aussi.
        let meme = serde_json::to_string(&json!({ "query": crate::seeds::ATTACKER_UNMITIGATED_RULE_SQL, "is_soql": false })).unwrap();
        let (code, reponse) = router_probe_envoi(addr, "POST", &format!("/api/rules/{id}"), Some(&cc1r_admin()), &json_ct, &meme).await;
        assert_eq!(code, 200, "{reponse}");
        assert!(cc1r_requete_de_preuves(dbp.as_str(), id).is_some(), "requête et nature inchangées : la requête de preuves reste");
        // Le plancher passé à 35 : la règle ne compte plus que 198.51.100.20 (40 défis).
        let q35 = crate::seeds::ATTACKER_UNMITIGATED_RULE_SQL.replace("activite > 20", "activite > 35");
        assert_ne!(q35, crate::seeds::ATTACKER_UNMITIGATED_RULE_SQL, "fixture : la requête change");
        let corps = serde_json::to_string(&json!({ "query": q35, "threshold": 0.0 })).unwrap();
        let (code, reponse) = router_probe_envoi(addr, "POST", &format!("/api/rules/{id}"), Some(&cc1r_admin()), &json_ct, &corps).await;
        assert_eq!(code, 200, "{}", cc1r_corps_json(&reponse));
        assert_eq!(cc1r_requete_de_preuves(dbp.as_str(), id), None, "requête modifiée : la requête de preuves est retirée");
        assert_eq!(cc1r_tick(dbp.as_str()), Mesure::Lue(0));
        let (valeur, preuves) = cc1r_alerte_ouverte(dbp.as_str(), id);
        assert_eq!(valeur, Some(1.0), "fixture : la règle modifiée compte une adresse");
        assert_eq!(preuves, None, "aucune preuve plutôt que des adresses que la règle ne compte pas");
    }

    // ------------------------------------------------------------------------------------------------------- (b)

    #[test]
    fn cc1r_preuves_bornees_a_la_fenetre_au_plancher_et_a_l_action() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let p = cc1r_base("bords");
        cc1r_evenements(
            p.as_str(),
            &[
                ("198.51.100.30", "web", 30, 60),
                ("192.0.2.41", "cloudflare", 25, 60),
                ("203.0.113.21", "web", 21, 60),
                // Non comptées : exactement au plancher, défis bloqués, activité hors de la fenêtre (3600 s).
                ("203.0.113.20", "web", 20, 60),
                ("192.0.2.40", "cloudflare_block", 30, 60),
                ("198.51.100.7", "web", 40, 7200),
            ],
        );
        let id = cc1r_id(p.as_str());
        assert_eq!(cc1r_tick(p.as_str()), Mesure::Lue(0));
        let (valeur, preuves) = cc1r_alerte_ouverte(p.as_str(), id);
        assert_eq!(valeur, Some(3.0), "la règle compte 198.51.100.30, 192.0.2.41 et 203.0.113.21");
        let preuves = cc1r_json(&preuves.expect("l'alerte porte ses preuves"));
        assert_eq!(
            preuves["rows"],
            json!([["198.51.100.30", 30, 30, 0], ["192.0.2.41", 25, 0, 25], ["203.0.113.21", 21, 21, 0]]),
            "les adresses comptées, et elles seules : {preuves}"
        );
        assert_eq!(preuves["total"].as_f64(), valeur, "nombre de la règle == nombre de preuves");
        let texte = preuves.to_string();
        for absente in ["203.0.113.20", "192.0.2.40", "198.51.100.7"] {
            assert!(!texte.contains(absente), "{absente} n'est pas comptée par la règle, elle n'est pas une preuve");
        }
    }

    // ------------------------------------------------------------------------------------------------------- (c)

    #[tokio::test]
    async fn cc1r_filtre_sur_status_ou_action_retient_les_preuves() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, dbp) = router_test_state("cc1r-masque");
        {
            let w = open_db(dbp.as_str()).unwrap();
            crate::seeds::seed_detection_rules(&w);
            w.execute("UPDATE rule SET enabled = (name = ?1)", params![CC1R_NOM_V52]).unwrap();
        }
        cc1r_trois_comptees(dbp.as_str());
        let id = cc1r_id(dbp.as_str());
        assert_eq!(cc1r_tick(dbp.as_str()), Mesure::Lue(0));
        let addr = router_serve(st).await;
        let evidence_servie = |reponse: &str| -> Value {
            let corps = cc1r_corps_json(reponse);
            corps["alerts"]
                .as_array()
                .unwrap_or_else(|| panic!("liste d'alertes : {corps}"))
                .iter()
                .find(|a| a["rule"] == json!(format!("rule.{id}")))
                .map(|a| a["evidence"].clone())
                .unwrap_or_else(|| panic!("alerte de rule.{id} servie : {corps}"))
        };
        let (code, reponse) = router_probe_corps(addr, "GET", "/api/alerts", Some(&viewer_authz()), &[]).await;
        assert_eq!(code, 200, "{reponse}");
        assert_eq!(evidence_servie(&reponse)["state"], json!("established"), "contrôle : sans filtre, servies");
        for champ in ["status", "action"] {
            {
                let w = open_db(dbp.as_str()).unwrap();
                w.execute("DELETE FROM field_filter", []).unwrap();
                w.execute("INSERT INTO field_filter(name,field,action,role) VALUES('cc1r',?1,'mask','')", params![champ]).unwrap();
                field_filters_reload(&w, dbp.as_str());
            }
            let (code, reponse) = router_probe_corps(addr, "GET", "/api/alerts", Some(&viewer_authz()), &[]).await;
            assert_eq!(code, 200, "{reponse}");
            assert_eq!(evidence_servie(&reponse)["state"], json!("withheld"), "filtre sur `{champ}` : les preuves en dépendent, retenues");
            assert!(!reponse.contains("198.51.100.20"), "filtre sur `{champ}` : aucune adresse des preuves");
        }
        crate::field_filter::field_filters_forget(dbp.as_str());
    }

    // ------------------------------------------------------------------------------------------------------- (d)

    #[test]
    fn cc1r_regle_sans_fenetre_dit_from_zero() {
        use crate::preuves_d_alerte::{Preuves, PreuvesDatees};
        for preuves in [
            Preuves::Etablies { colonnes: vec![json!("src_ip")], lignes: vec![json!(["192.0.2.1"])], total_exact: true },
            Preuves::SansLigne { colonnes: vec![json!("src_ip")] },
            Preuves::NonEtablies { cause: crate::detection_aveugle::CAUSE_ERREUR_REQUETE },
        ] {
            let j = PreuvesDatees { instant: 10_000, window_s: 0, preuves: preuves.clone() }.en_json();
            assert_eq!((j["at"].clone(), j["from"].clone(), j["window_s"].clone()), (json!(10_000), json!(0), json!(0)), "{preuves:?}");
        }
    }

    // ------------------------------------------------------------------------------------------------------- (e)

    #[test]
    fn cc1r_regle_livree_renommee_ne_recoit_pas_la_requete_de_preuves() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let p = cc1r_base("renommee");
        let id = cc1r_id(p.as_str());
        let w = open_db(p.as_str()).unwrap();
        w.execute_batch("ALTER TABLE rule DROP COLUMN evidence_query; ALTER TABLE alert DROP COLUMN evidence; UPDATE meta SET value='125' WHERE key='schema_version';").unwrap();
        w.execute("UPDATE rule SET name='cc1r règle renommée par l''exploitant' WHERE id=?1", params![id]).unwrap();
        let (q, is_soql): (String, i64) = w.query_row("SELECT query,is_soql FROM rule WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((q.as_str(), is_soql), (crate::seeds::ATTACKER_UNMITIGATED_RULE_SQL, 0), "fixture : seul le nom change");
        assert!(migrate(&w), "v126 passe");
        assert_eq!(cc1r_requete_de_preuves(p.as_str(), id), None, "règle renommée : aucune requête de preuves posée");
    }

    // ------------------------------------------------------------------------------------------------------- (f)

    fn cc1r_lectures() -> u32 {
        crate::preuves_d_alerte::LECTURES_DE_PREUVES.with(|n| n.get())
    }

    fn cc1r_resoudre_avant_les_ecritures(db: &Arc<Mutex<Connection>>) {
        db.lock().execute("UPDATE alert SET status='resolved', dedup=NULL WHERE dedup LIKE 'rule-%'", []).unwrap();
    }

    #[test]
    fn cc1r_preuves_lues_une_fois_par_levee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        struct Remise;
        impl Drop for Remise {
            fn drop(&mut self) {
                crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(crate::handlers::detection::sans_crochet));
            }
        }
        let _remise = Remise;
        let p = cc1r_base("une-lecture");
        cc1r_trois_comptees(p.as_str());
        let id = cc1r_id(p.as_str());
        let redue = || open_db(p.as_str()).unwrap().execute_batch("UPDATE rule SET last_run=NULL;").unwrap();
        let depart = cc1r_lectures();
        assert_eq!(cc1r_tick(p.as_str()), Mesure::Lue(0));
        assert_eq!(cc1r_lectures() - depart, 1, "la levée lit les preuves");
        let (_, premieres) = cc1r_alerte_ouverte(p.as_str(), id);
        assert!(premieres.is_some(), "fixture : l'alerte levée porte ses preuves");
        // Épisode ouvert : la règle tire encore, rien n'est relu, rien n'est réécrit.
        redue();
        assert_eq!(cc1r_tick(p.as_str()), Mesure::Lue(0));
        assert_eq!(cc1r_lectures() - depart, 1, "épisode ouvert : les preuves ne sont pas relues");
        assert_eq!(cc1r_alerte_ouverte(p.as_str(), id).1, premieres, "épisode ouvert : preuves inchangées");
        // L'épisode est résolu entre la sélection et l'écriture : l'alerte est levée quand même, sans preuves.
        crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(cc1r_resoudre_avant_les_ecritures));
        redue();
        assert_eq!(cc1r_tick(p.as_str()), Mesure::Lue(0));
        crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(crate::handlers::detection::sans_crochet));
        assert_eq!(cc1r_lectures() - depart, 1, "épisode ouvert à la sélection : non relues");
        let (valeur, preuves) = cc1r_alerte_ouverte(p.as_str(), id);
        assert_eq!((valeur, preuves), (Some(3.0), None), "l'alerte n'est jamais retenue faute de preuves");
        // Une levée neuve (épisode résolu avant la sélection) relit.
        open_db(p.as_str()).unwrap().execute("UPDATE alert SET status='resolved', dedup=NULL WHERE dedup=?1", params![format!("rule-{id}")]).unwrap();
        redue();
        assert_eq!(cc1r_tick(p.as_str()), Mesure::Lue(0));
        assert_eq!(cc1r_lectures() - depart, 2, "levée neuve : relues");
        let (_, neuves) = cc1r_alerte_ouverte(p.as_str(), id);
        assert_eq!(cc1r_json(&neuves.expect("levée neuve : preuves écrites"))["total"], json!(3));
    }

    // ------------------------------------------------------------------------------------------------------- (g)

    /// Les bords de statut de la branche web : une réponse 400 est comptée, des 302 et des 399 ne le sont pas, ni par la
    /// règle ni par ses preuves.
    #[test]
    fn cc1r_bord_de_statut_300_et_399_ni_comptes_ni_prouves_400_compte() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let p = cc1r_base("statut");
        cc1r_evenements(
            p.as_str(),
            &[
                ("203.0.113.10", "web", 30, 60),
                ("198.51.100.40", "web_400", 25, 60),
                ("192.0.2.30", "web", 22, 60),
                // Non comptées : redirections (3xx) et le dernier statut sous 400.
                ("198.51.100.99", "web_302", 30, 60),
                ("198.51.100.98", "web_399", 30, 60),
            ],
        );
        let id = cc1r_id(p.as_str());
        assert_eq!(cc1r_tick(p.as_str()), Mesure::Lue(0));
        let (valeur, preuves) = cc1r_alerte_ouverte(p.as_str(), id);
        assert_eq!(valeur, Some(3.0), "la règle compte 203.0.113.10, 198.51.100.40 et 192.0.2.30");
        let preuves = cc1r_json(&preuves.expect("l'alerte porte ses preuves"));
        assert_eq!(
            preuves["rows"],
            json!([["203.0.113.10", 30, 30, 0], ["198.51.100.40", 25, 25, 0], ["192.0.2.30", 22, 22, 0]]),
            "les adresses comptées, et elles seules : {preuves}"
        );
        assert_eq!(preuves["total"].as_f64(), valeur, "nombre de la règle == nombre de preuves");
    }

    // ------------------------------------------------------------------------------------------------------- (h)

    /// Des événements à adresse vide, web comme cloudflare, au-dessus du plancher : ni comptés ni prouvés.
    #[test]
    fn cc1r_adresse_vide_ni_comptee_ni_prouvee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let p = cc1r_base("adresse-vide");
        cc1r_trois_comptees(p.as_str());
        cc1r_evenements(p.as_str(), &[("", "web", 30, 60), ("", "cloudflare", 30, 60)]);
        let id = cc1r_id(p.as_str());
        assert_eq!(cc1r_tick(p.as_str()), Mesure::Lue(0));
        let (valeur, preuves) = cc1r_alerte_ouverte(p.as_str(), id);
        assert_eq!(valeur, Some(3.0), "l'adresse vide n'est pas comptée par la règle");
        let preuves = cc1r_json(&preuves.expect("l'alerte porte ses preuves"));
        assert_eq!(
            preuves["rows"],
            json!([["198.51.100.20", 40, 0, 40], ["203.0.113.10", 30, 30, 0], ["192.0.2.30", 25, 25, 0]]),
            "aucune ligne pour l'adresse vide : {preuves}"
        );
        assert_eq!(preuves["total"].as_f64(), valeur, "nombre de la règle == nombre de preuves");
    }

    // ------------------------------------------------------------------------------------------------------- (i)

    /// Une règle qui déclare des preuves et ne tire pas ne les lit pas ; la même, quand elle tire, les lit une fois.
    #[test]
    fn cc1r_regle_qui_ne_tire_pas_ne_lit_pas_ses_preuves() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let p = cc1r_base("sans-tir");
        cc1r_evenements(p.as_str(), &[("198.51.100.20", "web", 30, 60)]);
        let id = cc1r_id(p.as_str());
        assert!(cc1r_requete_de_preuves(p.as_str(), id).is_some(), "fixture : la règle déclare des preuves");
        let depart = cc1r_lectures();
        assert_eq!(cc1r_tick(p.as_str()), Mesure::Lue(0));
        let derniere: Option<f64> = open_db(p.as_str()).unwrap().query_row("SELECT last_value FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        assert_eq!(derniere, Some(1.0), "fixture : la règle est évaluée à ce tick (une adresse, sous son seuil)");
        let alertes: i64 = open_db(p.as_str()).unwrap().query_row("SELECT COUNT(*) FROM alert WHERE rule=?1", params![format!("rule.{id}")], |r| r.get(0)).unwrap();
        assert_eq!(alertes, 0, "fixture : la règle ne tire pas");
        assert_eq!(cc1r_lectures() - depart, 0, "aucune lecture de preuves sans tir");
        // Contre-épreuve : deux adresses de plus, la règle tire et lit.
        cc1r_evenements(p.as_str(), &[("203.0.113.10", "web", 30, 60), ("192.0.2.30", "web", 25, 60)]);
        open_db(p.as_str()).unwrap().execute_batch("UPDATE rule SET last_run=NULL;").unwrap();
        assert_eq!(cc1r_tick(p.as_str()), Mesure::Lue(0));
        assert_eq!(cc1r_lectures() - depart, 1, "la levée lit les preuves");
        assert_eq!(cc1r_alerte_ouverte(p.as_str(), id).0, Some(3.0));
    }

    // ------------------------------------------------------------------------------------------------------- (j)

    const CC1R_SEPARATEUR_LEVEE: &str = "CC1R-ENFANT-LEVEE-FAITE";
    const CC1R_SEPARATEUR_COURSE: &str = "CC1R-ENFANT-COURSE-FAITE";
    const CC1R_SEPARATEUR_FIN: &str = "CC1R-ENFANT-FIN";

    /// LA LIGNE DE JOURNAL d'une alerte levée sans preuves parce que son épisode était ouvert à la sélection, ENTIÈRE,
    /// lue sur le stderr d'un sous-processus : une à cette levée, aucune à la levée ordinaire qui précède (preuves
    /// lues), aucune sur l'épisode ouvert qui suit (aucune alerte levée).
    #[test]
    fn cc1r_alerte_levee_sans_preuves_episode_ouvert_ecrit_sa_ligne_entiere() {
        const ENFANT: &str = "CC1R_ENFANT_JOURNAL_EPISODE";
        if std::env::var(ENFANT).is_ok() {
            struct Remise;
            impl Drop for Remise {
                fn drop(&mut self) {
                    crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(crate::handlers::detection::sans_crochet));
                }
            }
            let _remise = Remise;
            let p = cc1r_base("journal-episode-enfant");
            cc1r_trois_comptees(p.as_str());
            let id = cc1r_id(p.as_str());
            println!("CC1R-ENFANT-REGLE={id}");
            let redue = || open_db(p.as_str()).unwrap().execute_batch("UPDATE rule SET last_run=NULL;").unwrap();
            assert_eq!(cc1r_tick(p.as_str()), Mesure::Lue(0));
            assert!(cc1r_alerte_ouverte(p.as_str(), id).1.is_some(), "levée ordinaire : preuves écrites");
            eprintln!("{CC1R_SEPARATEUR_LEVEE}");
            crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(cc1r_resoudre_avant_les_ecritures));
            redue();
            assert_eq!(cc1r_tick(p.as_str()), Mesure::Lue(0));
            crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(crate::handlers::detection::sans_crochet));
            assert_eq!(cc1r_alerte_ouverte(p.as_str(), id), (Some(3.0), None), "levée après la course : sans preuves");
            eprintln!("{CC1R_SEPARATEUR_COURSE}");
            redue();
            assert_eq!(cc1r_tick(p.as_str()), Mesure::Lue(0));
            eprintln!("{CC1R_SEPARATEUR_FIN}");
            println!("CC1R-ENFANT-A-JOUE");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::preuves_d_alerte_tenues_a_la_regle::cc1r_alerte_levee_sans_preuves_episode_ouvert_ecrit_sa_ligne_entiere",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("CC1R-ENFANT-A-JOUE"), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let id: i64 = stdout
            .lines()
            .find_map(|l| l.split("CC1R-ENFANT-REGLE=").nth(1))
            .expect("l'enfant nomme sa règle")
            .trim()
            .parse()
            .unwrap();
        let (levee, reste) = stderr.split_once(CC1R_SEPARATEUR_LEVEE).expect("premier séparateur");
        let (course, reste) = reste.split_once(CC1R_SEPARATEUR_COURSE).expect("deuxième séparateur");
        let (episode, _) = reste.split_once(CC1R_SEPARATEUR_FIN).expect("troisième séparateur");
        let aveux = |bloc: &str| -> Vec<String> { bloc.lines().filter(|l| l.contains("sans ses preuves")).map(str::to_string).collect() };
        assert_eq!(aveux(levee), Vec::<String>::new(), "levée ordinaire, preuves lues : aucune ligne : {stderr}");
        assert_eq!(
            aveux(course),
            vec![format!("[detection] WARN règle #{id} : l'alerte de son tir est levée sans ses preuves — son épisode était ouvert quand le tick a choisi de ne pas les lire")],
            "une ligne entière à la levée sans preuves : {stderr}"
        );
        assert_eq!(aveux(episode), Vec::<String>::new(), "épisode ouvert, aucune alerte levée : aucune ligne : {stderr}");
    }

    // ------------------------------------------------------------------------------------------------------- (k)

    /// Un fichier d'overlay qui réimpose la règle livrée sous son nom : `rules/*.json` (requête GXQL) ou `sigma/*.json`.
    fn cc1r_overlay_de_la_regle_livree(genre: &str, dossier: &std::path::Path) {
        let contenu = match genre {
            "json" => json!({ "name": CC1R_NOM_V52, "query": "search source=web | stats count", "is_soql": true, "op": ">", "threshold": 0.0,
                              "severity": 3, "interval_s": 300, "window_s": 3600, "mitre": "T1595" }),
            "sigma" => json!({ "title": CC1R_NOM_V52, "logsource": { "category": "firewall" },
                               "detection": { "selection": { "action": "deny" }, "condition": "selection" }, "level": "medium" }),
            autre => panic!("genre d'overlay inconnu : {autre}"),
        };
        std::fs::write(dossier.join("cc1r-regle-livree.json"), contenu.to_string()).unwrap();
    }

    fn cc1r_charger(genre: &str, conn: &Connection, dossier: &std::path::Path) -> u32 {
        match genre {
            "json" => crate::overlays::load_overlay_rules(conn, dossier).charges,
            "sigma" => crate::overlays::load_overlay_sigma(conn, dossier).charges,
            autre => panic!("genre d'overlay inconnu : {autre}"),
        }
    }

    const CC1R_SEPARATEUR_TICK: &str = "CC1R-ENFANT-TICK-OVERLAY";
    const CC1R_SEPARATEUR_TICK_FIN: &str = "CC1R-ENFANT-TICK-OVERLAY-FIN";

    /// Un overlay (JSON, puis Sigma) qui réimpose la règle livrée sous son nom change sa requête et sa nature : la requête
    /// de preuves est retirée au chargement, l'alerte suivante ne porte aucune preuve, et aucune ligne de journal ne dit
    /// des preuves ratées. Jugé dans un sous-processus pour lire le journal du tick, ligne par ligne.
    #[test]
    fn cc1r_overlay_qui_reimpose_la_regle_livree_retire_ses_preuves_sans_journal() {
        const ENFANT: &str = "CC1R_ENFANT_OVERLAY";
        if std::env::var(ENFANT).is_ok() {
            for genre in ["json", "sigma"] {
                let p = cc1r_base(&format!("overlay-{genre}-enfant"));
                cc1r_trois_comptees(p.as_str());
                let id = cc1r_id(p.as_str());
                assert!(cc1r_requete_de_preuves(p.as_str(), id).is_some(), "fixture : la règle livrée déclare ses preuves");
                let dossier = crate::tmp_possede::TmpPossede::neuf(&format!("cc1r-overlay-{genre}"));
                cc1r_overlay_de_la_regle_livree(genre, &dossier);
                let charges = cc1r_charger(genre, &open_db(p.as_str()).unwrap(), &dossier);
                let (is_soql, managed): (i64, i64) =
                    open_db(p.as_str()).unwrap().query_row("SELECT is_soql,managed FROM rule WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
                let posee = cc1r_requete_de_preuves(p.as_str(), id).is_some();
                // Seuil sous zéro : la règle réimposée tire quelle que soit sa valeur.
                open_db(p.as_str()).unwrap().execute("UPDATE rule SET enabled=1, threshold=-1.0 WHERE id=?1", params![id]).unwrap();
                eprintln!("{CC1R_SEPARATEUR_TICK}-{genre}");
                let bilan = cc1r_tick(p.as_str());
                eprintln!("{CC1R_SEPARATEUR_TICK_FIN}-{genre}");
                let (valeur, preuves) = cc1r_alerte_ouverte(p.as_str(), id);
                println!(
                    "CC1R-ENFANT-{genre}=charges:{charges} is_soql:{is_soql} managed:{managed} requete_de_preuves:{posee} bilan:{bilan:?} alerte:{} preuves:{}",
                    valeur.is_some(),
                    preuves.is_some()
                );
            }
            println!("CC1R-ENFANT-A-JOUE");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::preuves_d_alerte_tenues_a_la_regle::cc1r_overlay_qui_reimpose_la_regle_livree_retire_ses_preuves_sans_journal",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("CC1R-ENFANT-A-JOUE"), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        // Le journal d'abord (chaque cas), puis l'état : une requête de preuves gardée se voit au journal du tick.
        for genre in ["json", "sigma"] {
            let debut = format!("{CC1R_SEPARATEUR_TICK}-{genre}\n");
            let fin = format!("{CC1R_SEPARATEUR_TICK_FIN}-{genre}");
            let (_, reste) = stderr.split_once(&debut).unwrap_or_else(|| panic!("séparateur {genre} : {stderr}"));
            let (tick, _) = reste.split_once(&fin).unwrap_or_else(|| panic!("séparateur de fin {genre} : {stderr}"));
            let alertes: Vec<&str> = tick.lines().filter(|l| l.contains("WARN")).collect();
            assert_eq!(alertes, Vec::<&str>::new(), "overlay {genre} : aucune ligne WARN au tick qui lève l'alerte : {stderr}");
        }
        for genre in ["json", "sigma"] {
            let lu = stdout
                .lines()
                .find_map(|l| l.split(&format!("CC1R-ENFANT-{genre}=")).nth(1))
                .unwrap_or_else(|| panic!("l'enfant rend le cas {genre} : {stdout}"));
            assert_eq!(
                lu.trim(),
                format!("charges:1 is_soql:1 managed:1 requete_de_preuves:false bilan:{:?} alerte:true preuves:false", Mesure::Lue(0)),
                "overlay {genre} : réimposé, requête de preuves retirée, alerte levée sans preuves"
            );
        }
    }

    /// La réimposition À L'IDENTIQUE (même requête GXQL, même nature) d'une règle d'overlay garde sa requête de preuves ;
    /// le même fichier dont la requête change la retire. Pour `rules/*.json` et pour `sigma/*.json`.
    #[test]
    fn cc1r_overlay_reimpose_a_l_identique_garde_les_preuves_requete_changee_les_retire() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        const NOM: &str = "cc1r règle d'overlay";
        const PREUVES_POSEES: &str = "search source=web | stats count by src_ip";
        for genre in ["json", "sigma"] {
            let p = cc1r_base(&format!("overlay-identique-{genre}"));
            let dossier = crate::tmp_possede::TmpPossede::neuf(&format!("cc1r-identique-{genre}"));
            let ecrire = |selection: &str, requete: &str| {
                let contenu = match genre {
                    "json" => json!({ "name": NOM, "query": requete, "is_soql": true, "op": ">", "threshold": 0.0, "severity": 3,
                                      "interval_s": 300, "window_s": 3600, "mitre": "T1595" }),
                    _ => json!({ "title": NOM, "logsource": { "category": "firewall" },
                                 "detection": { "selection": { "action": selection }, "condition": "selection" }, "level": "medium" }),
                };
                std::fs::write(dossier.join("cc1r-overlay.json"), contenu.to_string()).unwrap();
            };
            ecrire("deny", "search source=web | stats count");
            assert_eq!(cc1r_charger(genre, &open_db(p.as_str()).unwrap(), &dossier), 1, "{genre} : première pose");
            let id: i64 = open_db(p.as_str()).unwrap().query_row("SELECT id FROM rule WHERE name=?1", params![NOM], |r| r.get(0)).unwrap();
            open_db(p.as_str()).unwrap().execute("UPDATE rule SET evidence_query=?1 WHERE id=?2", params![PREUVES_POSEES, id]).unwrap();
            let requete_avant: String = open_db(p.as_str()).unwrap().query_row("SELECT query FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap();
            assert_eq!(cc1r_charger(genre, &open_db(p.as_str()).unwrap(), &dossier), 1, "{genre} : réimposition identique chargée");
            let requete_apres: String = open_db(p.as_str()).unwrap().query_row("SELECT query FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap();
            assert_eq!(requete_apres, requete_avant, "fixture {genre} : même requête réimposée");
            assert_eq!(cc1r_requete_de_preuves(p.as_str(), id).as_deref(), Some(PREUVES_POSEES), "{genre} : réimposition identique, preuves gardées");
            ecrire("block", "search source=web status>=500 | stats count");
            assert_eq!(cc1r_charger(genre, &open_db(p.as_str()).unwrap(), &dossier), 1, "{genre} : réimposition changée chargée");
            let requete_changee: String = open_db(p.as_str()).unwrap().query_row("SELECT query FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap();
            assert_ne!(requete_changee, requete_avant, "fixture {genre} : la requête change");
            assert_eq!(cc1r_requete_de_preuves(p.as_str(), id), None, "{genre} : requête changée, preuves retirées");
        }
    }
}
