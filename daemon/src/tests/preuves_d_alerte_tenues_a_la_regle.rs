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
//       la sélection et l'écriture lève quand même son alerte (sans preuves) ; une nouvelle levée les relit.
//
// MUTANTS JOUÉS (variable d environnement de mutation, retirés avant le commit) : CC1R_PREUVES_GARDEES (a) ;
// CC1R_FENETRE0, CC1R_PLANCHER20, CC1R_ACTION (b) ; CC1R_MASQUE_SRCIP (c) ; CC1R_FROM0 (d) ; CC1R_NOM (e) ;
// CC1R_RELIT_OUVERT (f).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la ligne de journal de (f), écrite quand une alerte part sans preuves parce que
// son épisode était ouvert à la sélection, n'est pas capturée (seule l'alerte levée, sans preuves, est jugée).
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

    /// `n` événements par (adresse, genre, âge en secondes) : `web` = réponse 404, `cloudflare` = défi `challenged`,
    /// `cloudflare_block` = action `block` (non comptée par la règle).
    fn cc1r_evenements(p: &str, lots: &[(&str, &str, usize, i64)]) {
        let w = open_db(p).unwrap();
        let maintenant = now();
        for (ip, genre, n, age) in lots {
            let (source, fields) = match *genre {
                "web" => ("web", "{\"status\":\"404\"}"),
                "cloudflare" => ("cloudflare", "{\"action\":\"challenged\"}"),
                "cloudflare_block" => ("cloudflare", "{\"action\":\"block\"}"),
                autre => panic!("genre de fixture inconnu : {autre}"),
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
}
