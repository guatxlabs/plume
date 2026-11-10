// =====================================================================================
// `P11.25-g` — L'ALERTE « ATTAQUANT ACTIF NON BANNI » PORTE SES PREUVES : les adresses que son nombre compte, leur
// activité sur la fenêtre et leur part par source, lues à l'instant de la levée, servies sous `evidence` par
// `GET /api/alerts`.
//
// VU sur 80a7936d : la règle v52 (SQL natif d'agrégat, `seeds.rs`) est servie par `run_due_rules` (aucun réglage de
// throttle ni de fenêtre de suppression : `run_advanced_rules` l'exclut), dont l'`INSERT` n'écrivait que le titre
// « nom : valeur > seuil » et le texte de la requête ; la ligne servie par `/api/alerts` ne portait aucune adresse.
//
// TENU ICI, par l'ordonnanceur réel puis par la route (jeton viewer, le rôle le plus faible admis) :
//   (1) jeu fixe (adresses RFC 5737 et une privée, une adresse bannie, une sous le plancher) : la règle compte 3,
//       l'alerte porte exactement ces 3 adresses, leur activité et leur part web / cloudflare, triées par activité
//       décroissante, l'instant de la levée et la fenêtre ; aucune exclusion (la privée y est), la bannie absente ;
//       nombre de la règle == nombre de preuves ; requête, seuil et fenêtre de la règle inchangés ;
//   (2) la coupe à la borne, dite (total lu, servies, `truncated`) : par l'ordonnanceur au-delà de la borne, et aux
//       trois bords sur l'objet écrit ; le plafond de lecture qui coupe avant (`total_exact` faux) ;
//   (3) preuves non établies (lecture ratée, compilation refusée) : l'alerte existe, cause du vocabulaire fermé, ni
//       texte du moteur ni requête ; la ligne de journal capturée ENTIÈRE dans un sous-processus, une seule par levée,
//       aucune sur un épisode déjà ouvert ni pour « aucune ligne » ;
//   (4) aucune ligne : issue distincte, sa phrase ;
//   (5) les preuves ne sont pas réécrites au tick suivant (épisode ouvert, activité changée) ;
//   (6) une autre règle sans requête de preuves : sa ligne servie est celle d'avant, à l'octet (aucune clé neuve) ;
//   (7) migration v126 jouée deux fois sur une base au schéma 125 (idempotente), règle modifiée par l'exploitant non
//       récrite, requête de preuves posée par l'exploitant non écrasée, base neuve semée identique à une base migrée ;
//   (8) deux bases de tenant : chacune ses propres adresses ;
//   (9) un filtre de champs actif pour l'appelant : preuves retenues, dit ;
//  (10) ce que lit l'envoi des notifications (titre, détail, sévérité, hôte, technique) est identique, preuves ou pas ;
//  (11) des preuves illisibles en base : dites illisibles, jamais le texte stocké.
//
// MUTANTS JOUÉS (variable d environnement de mutation, retirés avant le commit) : CC1_PRIVEES (adresses privées retirées des preuves) (1) ;
// CC1_BANNIE (anti-jointure retirée de la requête de preuves posée) (1) ; CC1_COUPE_TAIE (total ramené aux servies,
// coupe tue) (2) ; CC1_MASQUE_ALERTE (pas d'alerte quand les preuves ratent) (3) ; CC1_REECRIT_AU_TICK (preuves
// réécrites au rafraîchissement) (5) ; CC1_RECRIT_MODIFIEE (pose sans la garde de la requête livrée) (7) ;
// CC1_REGLE_COMPTE (la règle évaluée sur sa requête de preuves) (1) ; CC1_CAUSE_MOTEUR (texte du moteur pour cause)
// (3) ; CC1_JOURNAL_MUET (ligne de journal retirée) (3) ; CC1_SERVI_NUL (clé `evidence` nulle servie pour toute
// alerte) (6) ; CC1_MASQUES_IGNORES (preuves servies sous un filtre de champs) (9) ; CC1_SEMIS_SANS_PREUVES (le semis
// ne pose pas la requête de preuves) (7).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'instant `at` est `now_ts` du tick, la variable même que l'`INSERT` écrit dans
// `alert.ts` (égalité jugée en (1)) ; une variante qui ancrerait les preuves à l'instant de leur lecture ne diffère que
// si la lecture franchit une seconde, ce qu'aucun témoin déterministe ne fabrique ici. La cause `budget_depasse` et
// la cause `evaluateur_en_panne` ne sont pas fabriquées (la seconde n'existe pas pour les preuves : lecture sur le fil
// de l'ordonnanceur, sans fil d'évaluation).
// =====================================================================================
mod preuves_d_alerte_attaquant_actif_non_banni {
    use super::*;
    use crate::mesure_environnement::Mesure;

    const CC1_NOM_V52: &str = "Attaquant actif NON banni (web 4xx / CF challenged sans mitigation)";
    const CC1_PHRASE_ETABLIES: &str = "Preuves établies à l'instant où l'alerte a été levée (at), sur la fenêtre de la règle : toutes les lignes lues sont servies. Fait daté : elles ne sont pas réécrites aux tirs suivants.";
    const CC1_PHRASE_COUPEES: &str = "Preuves établies à l'instant où l'alerte a été levée (at), sur la fenêtre de la règle, COUPÉES : served lignes servies sur total lues (total_exact faux : au moins autant, le plafond de lecture a coupé avant). Fait daté : elles ne sont pas réécrites aux tirs suivants.";
    const CC1_PHRASE_SANS_LIGNE: &str = "Aucune ligne de preuve à l'instant où l'alerte a été levée (at) : la lecture a réussi et n'a rien rendu, l'activité comptée par la règle a cessé entre son évaluation et cette lecture. Fait daté : elles ne sont pas réécrites aux tirs suivants.";
    const CC1_PHRASE_NON_ETABLIES: &str = "Preuves NON ÉTABLIES : leur lecture a échoué à l'instant où l'alerte a été levée (at), pour la cause dite. L'alerte est levée quand même. Fait daté : elles ne sont pas réécrites aux tirs suivants.";
    const CC1_PHRASE_RETENUES: &str = "Preuves retenues : un filtre de champs est actif pour votre rôle, et les preuves, lues sans masque par l'ordonnanceur, ne peuvent pas être masquées après coup.";
    const CC1_PHRASE_ILLISIBLES: &str = "Preuves écrites sur l'alerte mais illisibles en base : rien n'en est servi.";
    const CC1_BORNE: usize = 50;
    const CC1_TABLE_ABSENTE: &str = "SELECT src_ip FROM table_absente_du_temoin_cc1";

    fn cc1_ecrire(p: &str, sql: &str) {
        let w = open_db(p).unwrap();
        w.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    /// Base migrée puis semée comme une base neuve ; seule la règle v52 reste active.
    fn cc1_preparer(p: &str) {
        let w = open_db(p).unwrap();
        w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&w), "fixture : la chaîne de migrations va au bout");
        crate::seeds::seed_detection_rules(&w);
        w.execute("UPDATE rule SET enabled = (name = ?1)", params![CC1_NOM_V52]).unwrap();
    }

    fn cc1_base(tag: &str) -> crate::tmp_possede::TmpDb {
        let p = crate::tmp_possede::TmpDb::neuf(&format!("cc1-{tag}"));
        cc1_preparer(p.as_str());
        p
    }

    /// `n` événements par (adresse, genre) : `web` = réponse 404, `web200` = réponse 200 (non comptée),
    /// `cloudflare` = défi du pare-feu applicatif.
    fn cc1_evenements(p: &str, lots: &[(&str, &str, usize)]) {
        let w = open_db(p).unwrap();
        let t = now() - 60;
        for (ip, genre, n) in lots {
            let (source, fields) = match *genre {
                "web" => ("web", "{\"status\":\"404\"}"),
                "web200" => ("web", "{\"status\":\"200\"}"),
                "cloudflare" => ("cloudflare", "{\"action\":\"challenged\"}"),
                autre => panic!("genre de fixture inconnu : {autre}"),
            };
            for i in 0..*n {
                w.execute(
                    "INSERT INTO event(ts,source,severity,src_ip,fields,dedup) VALUES(?1,?2,2,?3,?4,?5)",
                    params![t, source, ip, fields, format!("cc1-{ip}-{genre}-{i}")],
                )
                .unwrap();
            }
        }
    }

    /// Le jeu fixe : trois adresses comptées (dont une privée), une bannie, une sous le plancher, du trafic 200.
    fn cc1_jeu_fixe(p: &str) {
        cc1_evenements(
            p,
            &[
                ("198.51.100.20", "cloudflare", 40),
                ("198.51.100.20", "web", 5),
                ("203.0.113.10", "web", 30),
                ("203.0.113.10", "web200", 100),
                ("10.1.2.3", "web", 25),
                ("192.0.2.66", "web", 50),
                ("192.0.2.7", "web", 10),
            ],
        );
        let t = now() - 60;
        open_db(p)
            .unwrap()
            .execute("INSERT INTO banned_ip(src_ip,source,label,first_seen,last_seen) VALUES('192.0.2.66','crowdsec','temoin',?1,?1)", params![t])
            .unwrap();
    }

    fn cc1_preuves_attendues_du_jeu_fixe(at: i64) -> Value {
        json!({
            "state": "established", "phrase": CC1_PHRASE_ETABLIES,
            "at": at, "from": at - 3600, "window_s": 3600,
            "columns": ["src_ip", "activite", "web", "cloudflare"],
            "rows": [["198.51.100.20", 45, 5, 40], ["203.0.113.10", 30, 30, 0], ["10.1.2.3", 25, 25, 0]],
            "total": 3, "total_exact": true, "served": 3, "truncated": false,
        })
    }

    fn cc1_tick(p: &str) -> crate::bilan_de_tick::BilanDeTick {
        let db = Arc::new(Mutex::new(open_db(p).unwrap()));
        run_due_rules(&db, p)
    }

    fn cc1_id(p: &str, nom: &str) -> i64 {
        open_db(p).unwrap().query_row("SELECT id FROM rule WHERE name=?1", params![nom], |r| r.get(0)).unwrap()
    }

    /// (ts, valeur, preuves écrites) de l'alerte de la règle `id`.
    fn cc1_alerte(p: &str, id: i64) -> (i64, Option<f64>, Option<String>) {
        open_db(p)
            .unwrap()
            .query_row("SELECT ts,current_value,evidence FROM alert WHERE rule=?1", params![format!("rule.{id}")], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
    }

    fn cc1_json(s: &str) -> Value {
        serde_json::from_str(s).unwrap_or_else(|e| panic!("preuves écrites en JSON : {e} : {s}"))
    }

    fn cc1_regle_sql(p: &str, nom: &str, query: &str, is_soql: i64, evidence: Option<&str>) -> i64 {
        let w = open_db(p).unwrap();
        w.execute(
            "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,evidence_query) VALUES(?1,1,?2,?3,'>',0.0,3,300,3600,'T1595',?4)",
            params![nom, query, is_soql, evidence],
        )
        .unwrap();
        w.last_insert_rowid()
    }

    fn cc1_corps(reponse: &str) -> Value {
        let (entetes, brut) = reponse.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse sans corps : {reponse}"));
        // Corps en morceaux (`Transfer-Encoding: chunked`) : taille hexadécimale, CRLF, morceau, CRLF ; 0 termine.
        let corps = if entetes.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            let mut reste = brut.as_bytes();
            let mut corps: Vec<u8> = Vec::new();
            loop {
                let fin = reste.windows(2).position(|w| w == b"\r\n").unwrap_or_else(|| panic!("morceau sans taille : {brut}"));
                let taille = String::from_utf8_lossy(&reste[..fin]).trim().to_string();
                let n = usize::from_str_radix(&taille, 16).unwrap_or_else(|e| panic!("taille de morceau : {e} : {brut}"));
                if n == 0 {
                    break;
                }
                corps.extend_from_slice(&reste[fin + 2..fin + 2 + n]);
                reste = &reste[fin + 2 + n + 2..];
            }
            String::from_utf8_lossy(&corps).into_owned()
        } else {
            brut.to_string()
        };
        serde_json::from_str(&corps).unwrap_or_else(|e| panic!("corps JSON : {e} : {corps}"))
    }

    fn cc1_alerte_servie(corps: &Value, id: i64) -> Value {
        corps["alerts"]
            .as_array()
            .unwrap_or_else(|| panic!("liste d'alertes : {corps}"))
            .iter()
            .find(|a| a["rule"] == json!(format!("rule.{id}")))
            .cloned()
            .unwrap_or_else(|| panic!("alerte de rule.{id} servie : {corps}"))
    }

    // ------------------------------------------------------------------------------------------------------- (1)

    #[test]
    fn cc1_regle_livree_tire_et_son_alerte_porte_les_adresses_comptees() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let p = cc1_base("jeu-fixe");
        cc1_jeu_fixe(p.as_str());
        let id = cc1_id(p.as_str(), CC1_NOM_V52);
        // La règle livrée est intacte : requête, nature, seuil, fenêtre ; et sa requête de preuves est posée.
        let (q, is_soql, op, seuil, fenetre, preuves_q): (String, i64, String, f64, i64, Option<String>) = open_db(p.as_str())
            .unwrap()
            .query_row("SELECT query,is_soql,op,threshold,window_s,evidence_query FROM rule WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
            .unwrap();
        assert_eq!((q.as_str(), is_soql, op.as_str(), seuil, fenetre), (crate::seeds::ATTACKER_UNMITIGATED_RULE_SQL, 0, ">", 2.0, 3600), "la règle livrée ne change pas");
        assert_eq!(preuves_q.as_deref(), Some(crate::seeds::ATTACKER_UNMITIGATED_EVIDENCE_SQL), "sa requête de preuves est posée");
        let avant = now();
        assert_eq!(cc1_tick(p.as_str()), Mesure::Lue(0), "rien d'abandonné");
        let apres = now();
        let (ts, valeur, preuves) = cc1_alerte(p.as_str(), id);
        assert_eq!(valeur, Some(3.0), "la règle compte trois adresses : 198.51.100.20, 203.0.113.10, 10.1.2.3");
        assert!(ts >= avant && ts <= apres, "l'alerte est levée par ce tick");
        let preuves = cc1_json(&preuves.expect("l'alerte porte ses preuves"));
        assert_eq!(preuves, cc1_preuves_attendues_du_jeu_fixe(ts), "adresses, activité, sources, instant de la levée et fenêtre");
        assert_eq!(preuves["total"].as_f64(), valeur, "nombre de la règle == nombre de preuves (rien n'est coupé)");
        let texte = preuves.to_string();
        assert!(texte.contains("\"10.1.2.3\""), "aucune exclusion : l'adresse privée est une preuve");
        assert!(!texte.contains("192.0.2.66"), "l'adresse bannie n'est ni comptée ni prouvée");
        assert!(!texte.contains("192.0.2.7"), "l'adresse sous le plancher n'est ni comptée ni prouvée");
    }

    // ------------------------------------------------------------------------------------------------------- (2)

    #[test]
    fn cc1_coupe_au_dela_de_la_borne_dite_par_l_ordonnanceur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let p = cc1_base("coupe");
        // Une adresse de plus que la borne, activités distinctes (21 + i) pour un ordre total.
        let ips: Vec<String> = (1..=CC1_BORNE + 1).map(|i| format!("198.51.100.{i}")).collect();
        let lots: Vec<(&str, &str, usize)> = ips.iter().enumerate().map(|(i, ip)| (ip.as_str(), "web", 22 + i)).collect();
        assert!(lots.len() > CC1_BORNE, "plancher : plus d'adresses que la borne");
        cc1_evenements(p.as_str(), &lots);
        let id = cc1_id(p.as_str(), CC1_NOM_V52);
        assert_eq!(cc1_tick(p.as_str()), Mesure::Lue(0));
        let (_, valeur, preuves) = cc1_alerte(p.as_str(), id);
        let preuves = cc1_json(&preuves.unwrap());
        assert_eq!(valeur, Some((CC1_BORNE + 1) as f64), "la règle compte toutes les adresses");
        assert_eq!(preuves["total"], json!(CC1_BORNE + 1), "le total lu est dit : {preuves}");
        assert_eq!(preuves["served"], json!(CC1_BORNE));
        assert_eq!(preuves["truncated"], json!(true));
        assert_eq!(preuves["total_exact"], json!(true));
        assert_eq!(preuves["phrase"], json!(CC1_PHRASE_COUPEES));
        let lignes = preuves["rows"].as_array().unwrap();
        assert_eq!(lignes.len(), CC1_BORNE, "la borne est appliquée");
        assert_eq!(lignes[0], json!([format!("198.51.100.{}", CC1_BORNE + 1), 22 + CC1_BORNE, 22 + CC1_BORNE, 0]), "activité décroissante : la plus active en tête");
        assert_eq!(lignes[CC1_BORNE - 1], json!(["198.51.100.2", 23, 23, 0]), "la dernière servie");
        assert!(!preuves.to_string().contains("\"198.51.100.1\""), "la moins active est coupée");
    }

    /// Les trois bords de la borne sur l'objet écrit (borne - 1, borne, borne + 1).
    #[test]
    fn cc1_coupe_aux_trois_bords_de_la_borne() {
        use crate::preuves_d_alerte::{Preuves, PreuvesDatees};
        for (n, servies, coupees, phrase) in [
            (CC1_BORNE - 1, CC1_BORNE - 1, false, CC1_PHRASE_ETABLIES),
            (CC1_BORNE, CC1_BORNE, false, CC1_PHRASE_ETABLIES),
            (CC1_BORNE + 1, CC1_BORNE, true, CC1_PHRASE_COUPEES),
        ] {
            let lignes: Vec<Value> = (0..n).map(|i| json!([format!("192.0.2.{}", i % 250), n - i])).collect();
            let d = PreuvesDatees { instant: 10_000, window_s: 3600, preuves: Preuves::Etablies { colonnes: vec![json!("src_ip"), json!("activite")], lignes: lignes.clone(), total_exact: true } };
            let j = d.en_json();
            assert_eq!(
                (j["total"].clone(), j["served"].clone(), j["truncated"].clone(), j["phrase"].clone()),
                (json!(n), json!(servies), json!(coupees), json!(phrase)),
                "bord {n}"
            );
            assert_eq!(j["rows"], json!(lignes[..servies]), "bord {n} : les premières lignes, dans l'ordre lu");
            assert_eq!((j["at"].clone(), j["from"].clone()), (json!(10_000), json!(10_000 - 3600)));
        }
    }

    /// Le plafond de lecture (`PLUME_QUERY_MAX`) coupe avant la borne : `total_exact` faux, la coupe est dite.
    #[test]
    fn cc1_plafond_de_lecture_dit_un_total_minore() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let avant = std::env::var("PLUME_QUERY_MAX").ok();
        struct Remise(Option<String>);
        impl Drop for Remise {
            fn drop(&mut self) {
                match &self.0 {
                    Some(v) => std::env::set_var("PLUME_QUERY_MAX", v),
                    None => std::env::remove_var("PLUME_QUERY_MAX"),
                }
            }
        }
        let _remise = Remise(avant);
        let p = cc1_base("plafond");
        cc1_jeu_fixe(p.as_str());
        std::env::set_var("PLUME_QUERY_MAX", "2");
        let d = crate::preuves_d_alerte::lire_les_preuves(p.as_str(), crate::seeds::ATTACKER_UNMITIGATED_EVIDENCE_SQL, false, 3600, now());
        let j = d.en_json();
        assert_eq!(j["state"], json!("established"));
        assert_eq!((j["total"].clone(), j["served"].clone(), j["total_exact"].clone(), j["truncated"].clone()), (json!(2), json!(2), json!(false), json!(true)), "{j}");
        assert_eq!(j["phrase"], json!(CC1_PHRASE_COUPEES));
        std::env::remove_var("PLUME_QUERY_MAX");
        let j = crate::preuves_d_alerte::lire_les_preuves(p.as_str(), crate::seeds::ATTACKER_UNMITIGATED_EVIDENCE_SQL, false, 3600, now()).en_json();
        assert_eq!((j["total"].clone(), j["total_exact"].clone(), j["truncated"].clone()), (json!(3), json!(true), json!(false)), "sans plafond : exact, entier");
    }

    // ------------------------------------------------------------------------------------------------------- (3) (4)

    /// Une règle SQL qui tire et dont la requête de preuves ne se lit pas ; une règle GXQL dont la requête de preuves ne
    /// compile pas ; une règle dont les preuves ne rendent aucune ligne.
    fn cc1_trois_regles(p: &str) -> (i64, i64, i64) {
        open_db(p).unwrap().execute("UPDATE rule SET enabled=0", []).unwrap();
        cc1_evenements(p, &[("192.0.2.1", "web", 3)]);
        let lecture = cc1_regle_sql(p, "cc1 preuves illisibles", "SELECT COUNT(*) FROM event WHERE source='web'", 0, Some(CC1_TABLE_ABSENTE));
        let compil = cc1_regle_sql(p, "cc1 preuves non compilables", "search source=web | stats count", 1, Some("search source=web | verbe_inconnu_du_temoin_cc1"));
        let vide = cc1_regle_sql(p, "cc1 preuves sans ligne", "SELECT COUNT(*) FROM event WHERE source='web'", 0, Some("SELECT src_ip FROM event WHERE 0"));
        (lecture, compil, vide)
    }

    #[test]
    fn cc1_preuves_non_etablies_l_alerte_part_avec_une_cause_fermee_et_aucune_ligne_dite() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let p = cc1_base("non-etablies");
        let (lecture, compil, vide) = cc1_trois_regles(p.as_str());
        assert_eq!(cc1_tick(p.as_str()), Mesure::Lue(0), "des preuves non établies ne sont pas un abandon : la règle est évaluée et son alerte écrite");
        for (id, cause) in [(lecture, "erreur_requete"), (compil, "compilation_refusee")] {
            let (ts, valeur, preuves) = cc1_alerte(p.as_str(), id);
            assert!(valeur.is_some_and(|v| v > 0.0), "l'alerte existe et porte la valeur de la règle");
            let ecrites = preuves.expect("les preuves sont dites");
            assert_eq!(
                cc1_json(&ecrites),
                json!({ "state": "not_established", "phrase": CC1_PHRASE_NON_ETABLIES, "at": ts, "from": ts - 3600, "window_s": 3600, "cause": cause }),
                "règle #{id} : corps entier"
            );
            for interdit in ["table_absente", "verbe_inconnu", "no such", "SELECT", "search"] {
                assert!(!ecrites.contains(interdit), "ni texte du moteur ni requête : « {interdit} » dans {ecrites}");
            }
        }
        let (ts, _, preuves) = cc1_alerte(p.as_str(), vide);
        assert_eq!(
            cc1_json(&preuves.unwrap()),
            json!({ "state": "no_rows", "phrase": CC1_PHRASE_SANS_LIGNE, "at": ts, "from": ts - 3600, "window_s": 3600,
                    "columns": ["src_ip"], "rows": [], "total": 0, "total_exact": true, "served": 0, "truncated": false }),
            "aucune ligne : issue distincte"
        );
    }

    const CC1_SEPARATEUR_EPISODE: &str = "CC1-ENFANT-EPISODE-OUVERT";
    const CC1_SEPARATEUR_FIN: &str = "CC1-ENFANT-FIN";

    /// LA LIGNE DE JOURNAL d'une alerte levée sans ses preuves, ENTIÈRE, lue sur le stderr d'un sous-processus : une
    /// par alerte levée dont les preuves ne sont pas établies, aucune pour « aucune ligne », aucune sur l'épisode ouvert
    /// (tick suivant : aucune alerte levée).
    #[test]
    fn cc1_preuves_non_etablies_ecrivent_leur_ligne_de_journal_entiere() {
        const ENFANT: &str = "CC1_ENFANT_JOURNAL";
        if std::env::var(ENFANT).is_ok() {
            let p = cc1_base("journal-enfant");
            let (lecture, compil, vide) = cc1_trois_regles(p.as_str());
            println!("CC1-ENFANT-REGLES={lecture},{compil},{vide}");
            assert_eq!(cc1_tick(p.as_str()), Mesure::Lue(0));
            eprintln!("{CC1_SEPARATEUR_EPISODE}");
            cc1_ecrire(p.as_str(), "UPDATE rule SET last_run=NULL;");
            assert_eq!(cc1_tick(p.as_str()), Mesure::Lue(0));
            eprintln!("{CC1_SEPARATEUR_FIN}");
            println!("CC1-ENFANT-A-JOUE");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::preuves_d_alerte_attaquant_actif_non_banni::cc1_preuves_non_etablies_ecrivent_leur_ligne_de_journal_entiere",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("CC1-ENFANT-A-JOUE"), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let ids: Vec<i64> = stdout
            .lines()
            .find_map(|l| l.split("CC1-ENFANT-REGLES=").nth(1))
            .expect("l'enfant nomme ses règles")
            .trim()
            .split(',')
            .map(|s| s.parse().unwrap())
            .collect();
        let (levee, reste) = stderr.split_once(CC1_SEPARATEUR_EPISODE).expect("premier séparateur");
        let (episode, _) = reste.split_once(CC1_SEPARATEUR_FIN).expect("second séparateur");
        let aveux = |bloc: &str| -> Vec<String> { bloc.lines().filter(|l| l.contains("sans ses preuves")).map(str::to_string).collect() };
        let mut attendues = vec![
            format!("[detection] WARN règle #{} : l'alerte de son tir est levée sans ses preuves — leur lecture a échoué (cause erreur_requete) ; elles sont dites non établies sur l'alerte", ids[0]),
            format!("[detection] WARN règle #{} : l'alerte de son tir est levée sans ses preuves — leur lecture a échoué (cause compilation_refusee) ; elles sont dites non établies sur l'alerte", ids[1]),
        ];
        let mut lues = aveux(levee);
        lues.sort();
        attendues.sort();
        assert_eq!(lues, attendues, "une ligne entière par alerte levée sans preuves, aucune pour « aucune ligne » (#{}) : {stderr}", ids[2]);
        assert_eq!(aveux(episode), Vec::<String>::new(), "épisode ouvert, aucune alerte levée : aucune ligne : {stderr}");
    }

    // ------------------------------------------------------------------------------------------------------- (5)

    #[test]
    fn cc1_preuves_non_reecrites_au_tick_suivant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let p = cc1_base("non-reecrites");
        cc1_jeu_fixe(p.as_str());
        let id = cc1_id(p.as_str(), CC1_NOM_V52);
        assert_eq!(cc1_tick(p.as_str()), Mesure::Lue(0));
        let (ts, _, premieres) = cc1_alerte(p.as_str(), id);
        let premieres = premieres.unwrap();
        assert_eq!(cc1_json(&premieres), cc1_preuves_attendues_du_jeu_fixe(ts), "fixture : les preuves de la levée");
        // L'activité change : une quatrième adresse franchit le plancher. La règle redue rafraîchit l'épisode ouvert.
        cc1_evenements(p.as_str(), &[("203.0.113.99", "web", 60)]);
        cc1_ecrire(p.as_str(), "UPDATE rule SET last_run=NULL;");
        assert_eq!(cc1_tick(p.as_str()), Mesure::Lue(0));
        let (_, valeur, secondes) = cc1_alerte(p.as_str(), id);
        assert_eq!(valeur, Some(4.0), "fixture : l'épisode ouvert est rafraîchi à la nouvelle valeur");
        assert_eq!(secondes.as_deref(), Some(premieres.as_str()), "les preuves restent celles de la levée, à l'octet");
    }

    // ------------------------------------------------------------------------------------------------------- (1) (6) par la route

    #[tokio::test]
    async fn cc1_par_la_route_viewer_lit_les_preuves_et_une_autre_regle_reste_a_l_octet() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, dbp) = router_test_state("cc1-route");
        {
            let w = open_db(dbp.as_str()).unwrap();
            crate::seeds::seed_detection_rules(&w);
            w.execute("UPDATE rule SET enabled = (name = ?1)", params![CC1_NOM_V52]).unwrap();
        }
        cc1_jeu_fixe(dbp.as_str());
        let autre = cc1_regle_sql(dbp.as_str(), "cc1 autre règle", "search source=web | stats count", 1, None);
        let id = cc1_id(dbp.as_str(), CC1_NOM_V52);
        assert_eq!(cc1_tick(dbp.as_str()), Mesure::Lue(0));
        let (ts, _, ecrites) = cc1_alerte(dbp.as_str(), id);
        let addr = router_serve(st).await;
        let (code, reponse) = router_probe_corps(addr, "GET", "/api/alerts", Some(&viewer_authz()), &[]).await;
        assert_eq!(code, 200, "{reponse}");
        let corps = cc1_corps(&reponse);
        let servie = cc1_alerte_servie(&corps, id);
        assert_eq!(servie["evidence"], cc1_preuves_attendues_du_jeu_fixe(ts), "le viewer lit les preuves sous `evidence`");
        assert_eq!(servie["evidence"], cc1_json(&ecrites.unwrap()), "servies telles qu'écrites à la levée");
        // L'autre règle : la ligne d'avant, à l'octet (ensemble de clés et valeurs, sérialisation canonique).
        let ligne = cc1_alerte_servie(&corps, autre);
        let (aid, ats, titre, detail, valeur, sources, ouverte): (i64, i64, String, String, f64, String, i64) = open_db(dbp.as_str())
            .unwrap()
            .query_row(
                "SELECT id,ts,title,detail,current_value,sources,COALESCE(opened_at,ts) FROM alert WHERE rule=?1",
                params![format!("rule.{autre}")],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
            )
            .unwrap();
        let attendue = json!({
            "id": aid, "ts": ats, "rule": format!("rule.{autre}"), "severity": 3, "title": titre, "status": "new",
            "detail": detail, "case_id": null, "mitre": "T1595", "window_s": 3600,
            "search_link": { "query": "search source=web", "is_soql": true, "from": ats - 3600, "to": ats },
            "acked_at": 0, "acked_by": "", "opened_at": ouverte, "value": valeur, "basis": "regle", "basis_ref": "",
            "sources": sources, "host": null,
        });
        assert_eq!(serde_json::to_string(&ligne).unwrap(), serde_json::to_string(&attendue).unwrap(), "ligne d'une alerte sans preuves : celle d'avant");
        assert!(ligne.get("evidence").is_none(), "aucune clé `evidence` pour une alerte sans preuves");
    }

    // ------------------------------------------------------------------------------------------------------- (9) (11)

    #[tokio::test]
    async fn cc1_filtre_de_champs_actif_preuves_retenues_et_preuves_illisibles_dites() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, dbp) = router_test_state("cc1-masque");
        {
            let w = open_db(dbp.as_str()).unwrap();
            crate::seeds::seed_detection_rules(&w);
            w.execute("UPDATE rule SET enabled = (name = ?1)", params![CC1_NOM_V52]).unwrap();
        }
        cc1_jeu_fixe(dbp.as_str());
        let id = cc1_id(dbp.as_str(), CC1_NOM_V52);
        assert_eq!(cc1_tick(dbp.as_str()), Mesure::Lue(0));
        let (ts, _, _) = cc1_alerte(dbp.as_str(), id);
        // Deux alertes aux preuves illisibles : du texte, et du JSON qui n'est pas un objet.
        cc1_ecrire(
            dbp.as_str(),
            "INSERT INTO alert(ts,rule,severity,title,detail,evidence) VALUES(1,'rule.illisible-texte',2,'t','d','pas du json 203.0.113.250'); \
             INSERT INTO alert(ts,rule,severity,title,detail,evidence) VALUES(2,'rule.illisible-tableau',2,'t','d','[\"203.0.113.251\"]'); \
             INSERT INTO alert(ts,rule,severity,title,detail) VALUES(3,'rule.sans-preuves',2,'t','d');",
        );
        let addr = router_serve(st).await;
        let (code, reponse) = router_probe_corps(addr, "GET", "/api/alerts", Some(&viewer_authz()), &[]).await;
        assert_eq!(code, 200, "{reponse}");
        let corps = cc1_corps(&reponse);
        assert_eq!(cc1_alerte_servie(&corps, id)["evidence"], cc1_preuves_attendues_du_jeu_fixe(ts), "contrôle : sans filtre, servies");
        for regle in ["rule.illisible-texte", "rule.illisible-tableau"] {
            let a = corps["alerts"].as_array().unwrap().iter().find(|a| a["rule"] == json!(regle)).cloned().unwrap();
            assert_eq!(a["evidence"], json!({ "state": "unreadable", "phrase": CC1_PHRASE_ILLISIBLES }), "{regle}");
        }
        assert!(!reponse.contains("203.0.113.25"), "le texte stocké illisible n'est jamais servi");
        {
            let w = open_db(dbp.as_str()).unwrap();
            w.execute("INSERT INTO field_filter(name,field,action,role) VALUES('cc1','src_ip','mask','')", []).unwrap();
            field_filters_reload(&w, dbp.as_str());
        }
        let (code, reponse) = router_probe_corps(addr, "GET", "/api/alerts", Some(&viewer_authz()), &[]).await;
        assert_eq!(code, 200, "{reponse}");
        let corps = cc1_corps(&reponse);
        assert_eq!(cc1_alerte_servie(&corps, id)["evidence"], json!({ "state": "withheld", "phrase": CC1_PHRASE_RETENUES }), "filtre actif : retenues");
        assert!(!reponse.contains("198.51.100.20"), "aucune adresse des preuves sous un filtre actif");
        let sans = corps["alerts"].as_array().unwrap().iter().find(|a| a["rule"] == json!("rule.sans-preuves")).cloned().unwrap();
        assert!(sans.get("evidence").is_none(), "filtre actif : une alerte sans preuves ne gagne pas de clé `evidence` : {sans}");
        crate::field_filter::field_filters_forget(dbp.as_str());
    }

    // ------------------------------------------------------------------------------------------------------- (7)

    fn cc1_vers_125(p: &str) {
        cc1_ecrire(p, "ALTER TABLE rule DROP COLUMN evidence_query; ALTER TABLE alert DROP COLUMN evidence; UPDATE meta SET value='125' WHERE key='schema_version';");
    }

    fn cc1_regle_v52(p: &str) -> (String, String, i64, String, f64, i64, i64, Option<String>) {
        open_db(p)
            .unwrap()
            .query_row(
                "SELECT name,query,is_soql,op,threshold,interval_s,window_s,evidence_query FROM rule WHERE name=?1",
                params![CC1_NOM_V52],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
            )
            .unwrap()
    }

    fn cc1_colonnes_neuves(p: &str) -> Vec<(String, String, String)> {
        open_db(p)
            .unwrap()
            .prepare("SELECT 'rule', name, type FROM pragma_table_info('rule') WHERE name='evidence_query' UNION ALL SELECT 'alert', name, type FROM pragma_table_info('alert') WHERE name='evidence'")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    #[test]
    fn cc1_migration_v126_idempotente_respecte_l_exploitant_et_rejoint_la_base_neuve() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let neuve = cc1_base("neuve");
        assert!(read_schema_version(&open_db(neuve.as_str()).unwrap()) >= 126, "la base neuve porte au moins v126");
        // Base au schéma 125, règle livrée intacte : v126 pose les colonnes et la requête de preuves.
        let migree = cc1_base("migree");
        cc1_vers_125(migree.as_str());
        assert_eq!(cc1_colonnes_neuves(migree.as_str()), Vec::<(String, String, String)>::new(), "fixture : base 125 sans les colonnes");
        assert!(migrate(&open_db(migree.as_str()).unwrap()), "v126 passe");
        assert!(read_schema_version(&open_db(migree.as_str()).unwrap()) >= 126, "la base migrée porte au moins v126");
        assert_eq!(cc1_regle_v52(migree.as_str()), cc1_regle_v52(neuve.as_str()), "base neuve semée == base migrée (règle v52)");
        assert_eq!(cc1_colonnes_neuves(migree.as_str()), cc1_colonnes_neuves(neuve.as_str()), "mêmes colonnes neuves");
        assert_eq!(cc1_colonnes_neuves(neuve.as_str()).len(), 2);
        // Second passage : rien ne bouge, et une requête de preuves posée par l'exploitant entre les deux reste.
        cc1_ecrire(migree.as_str(), "UPDATE meta SET value='125' WHERE key='schema_version';");
        assert!(migrate(&open_db(migree.as_str()).unwrap()), "second passage : aboutit");
        assert_eq!(cc1_regle_v52(migree.as_str()), cc1_regle_v52(neuve.as_str()), "second passage : inchangée");
        open_db(migree.as_str()).unwrap().execute("UPDATE rule SET evidence_query='SELECT 1' WHERE name=?1", params![CC1_NOM_V52]).unwrap();
        cc1_ecrire(migree.as_str(), "UPDATE meta SET value='125' WHERE key='schema_version';");
        assert!(migrate(&open_db(migree.as_str()).unwrap()), "troisième passage : aboutit");
        assert_eq!(cc1_regle_v52(migree.as_str()).7.as_deref(), Some("SELECT 1"), "la requête de preuves de l'exploitant n'est pas écrasée");
        // Base 125 dont l'exploitant a modifié la règle : v126 ne la récrit pas.
        let modifiee = cc1_base("modifiee");
        cc1_vers_125(modifiee.as_str());
        let q = crate::seeds::ATTACKER_UNMITIGATED_RULE_SQL.replace("activite > 20", "activite > 30");
        assert_ne!(q, crate::seeds::ATTACKER_UNMITIGATED_RULE_SQL, "fixture : la requête est modifiée");
        open_db(modifiee.as_str()).unwrap().execute("UPDATE rule SET query=?1 WHERE name=?2", params![q, CC1_NOM_V52]).unwrap();
        assert!(migrate(&open_db(modifiee.as_str()).unwrap()), "v126 passe");
        let (_, query, ..) = cc1_regle_v52(modifiee.as_str());
        assert_eq!(query, q, "la requête de l'exploitant reste");
        assert_eq!(cc1_regle_v52(modifiee.as_str()).7, None, "aucune requête de preuves posée sur une règle modifiée");
    }

    // ------------------------------------------------------------------------------------------------------- (8)

    #[test]
    fn cc1_deux_bases_de_tenant_chacune_ses_preuves() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let a = cc1_base("tenant-a");
        let b = cc1_base("tenant-b");
        cc1_evenements(a.as_str(), &[("203.0.113.1", "web", 30), ("203.0.113.2", "web", 31), ("203.0.113.3", "web", 32)]);
        cc1_evenements(b.as_str(), &[("198.51.100.1", "cloudflare", 30), ("198.51.100.2", "cloudflare", 31), ("10.9.9.9", "cloudflare", 32)]);
        assert_eq!(cc1_tick(a.as_str()), Mesure::Lue(0));
        assert_eq!(cc1_tick(b.as_str()), Mesure::Lue(0));
        let ips = |p: &str| -> Vec<Value> {
            let (_, _, e) = cc1_alerte(p, cc1_id(p, CC1_NOM_V52));
            cc1_json(&e.unwrap())["rows"].as_array().unwrap().iter().map(|l| l[0].clone()).collect()
        };
        assert_eq!(ips(a.as_str()), vec![json!("203.0.113.3"), json!("203.0.113.2"), json!("203.0.113.1")], "tenant A : ses adresses");
        assert_eq!(ips(b.as_str()), vec![json!("10.9.9.9"), json!("198.51.100.2"), json!("198.51.100.1")], "tenant B : ses adresses");
    }

    // ------------------------------------------------------------------------------------------------------- (10)

    /// Ce que l'envoi des notifications lit d'une alerte (`dispatch_notifications`) : titre, détail, sévérité, hôte,
    /// technique, famille. Identique, que la règle porte une requête de preuves ou non (l'état d'avant ce lot).
    #[test]
    fn cc1_ce_que_lit_l_envoi_des_notifications_ne_change_pas() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let lire = |p: &str| -> (i64, String, String, String, String, String) {
            open_db(p)
                .unwrap()
                .query_row(
                    "SELECT severity,title,detail,COALESCE(host,''),COALESCE(mitre,''),COALESCE(rule,'') FROM alert WHERE notified=0",
                    [],
                    |r| Ok((r.get(0)?, r.get::<_, Option<String>>(1)?.unwrap_or_default(), r.get::<_, Option<String>>(2)?.unwrap_or_default(), r.get(3)?, r.get(4)?, r.get(5)?)),
                )
                .unwrap()
        };
        let avec = cc1_base("notif-avec");
        cc1_jeu_fixe(avec.as_str());
        let sans = cc1_base("notif-sans");
        cc1_jeu_fixe(sans.as_str());
        open_db(sans.as_str()).unwrap().execute("UPDATE rule SET evidence_query=NULL", []).unwrap();
        assert_eq!(cc1_tick(avec.as_str()), Mesure::Lue(0));
        assert_eq!(cc1_tick(sans.as_str()), Mesure::Lue(0));
        assert!(cc1_alerte(avec.as_str(), cc1_id(avec.as_str(), CC1_NOM_V52)).2.is_some(), "fixture : l'une porte des preuves");
        assert!(cc1_alerte(sans.as_str(), cc1_id(sans.as_str(), CC1_NOM_V52)).2.is_none(), "fixture : l'autre non (état d'avant)");
        let (lu_avec, lu_sans) = (lire(avec.as_str()), lire(sans.as_str()));
        assert_eq!(lu_avec, lu_sans, "ce que lit l'envoi : identique");
        assert_eq!(lu_avec.1, format!("{CC1_NOM_V52} : 3 > 2"), "titre « nom : valeur > seuil »");
        assert_eq!(lu_avec.2, crate::seeds::ATTACKER_UNMITIGATED_RULE_SQL, "détail : la requête de la règle");
        let corps = |l: &(i64, String, String, String, String, String)| serde_json::to_string(&crate::handlers::alerting::slack_payload(l.0, &l.1, &l.2, &l.3, 1_000)).unwrap();
        assert_eq!(corps(&lu_avec), corps(&lu_sans), "corps de notification identique à l'octet");
        assert!(!corps(&lu_avec).contains("198.51.100.20"), "aucune adresse des preuves dans le corps d'une notification");
    }
}
