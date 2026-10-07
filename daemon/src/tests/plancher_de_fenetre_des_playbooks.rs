// =====================================================================================
// `P10.21-e` — LA FENÊTRE DE DÉDUPLICATION D'UN PLAYBOOK A UN PLANCHER.
//
// LE DÉFAUT. La seule garde contre une SECONDE riposte (et un second armement) pour la même cible,
// quand la règle d'un playbook reste vraie d'un passage à l'autre, est la déduplication de
// `run_playbooks`, qui ne regarde que les ripostes des `window_s` dernières secondes. Rien ne
// bornait `window_s` à l'enregistrement : un playbook à `window_s` plus court que l'écart entre deux
// de ses passages reposait une riposte à chaque passage.
//
// LA PRÉMISSE, CORRIGÉE. L'écart minimal entre deux passages est `interval_s` (sélection
// `now - last_run >= interval_s`), et au moins un tour d'ordonnanceur (`TOUR_DE_DETECTION_S`) : le
// tour ne borne pas seulement les `interval_s <= 0`, il borne tout `interval_s` inférieur au tour.
// Plancher retenu : `window_s >= max(interval_s, TOUR_DE_DETECTION_S)`.
//
// L'ÉCART RÉEL. Il dépasse l'écart minimal d'à peu près la durée d'un tour (le sommeil de la boucle
// est placé après le travail), et aucune marge fixe ne le borne : la déduplication remonte donc
// jusqu'au passage précédent (`debut_de_la_deduplication_du_playbook`), bornée pour qu'un passage
// très ancien (démon arrêté, playbook rallumé) ne retienne pas une riposte due. Témoins (4) et (5).
//
// L'ARMEMENT. Une ligne sous le plancher peut être armée par d'autres voies que la création et la
// modification de sa cadence : case « Activée », bascule de la ligne, fichier `config.d` coupé puis
// dérogation d'activation réappliquée au démarrage. Les deux gestes de l'API qui arment sont jugés
// (témoin 9) ; et la déduplication plancher sa fenêtre nominale à l'exécution, ce qui couvre toutes
// les voies, y compris celle du démarrage (témoin 8).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : rien n'est jugé côté console (la cause servie sur la liste
// n'est peinte par aucun module de `web/`) ; un tour plus long que `max(window_s, interval_s, 20)
// + max(interval_s, 20)` sort de la borne et retombe sur la fenêtre nominale ; la cadence de la
// boucle est gardée par une lecture de SOURCE (témoin 7), pas par une mesure du temps ; une ligne
// armée sous le plancher par la dérogation du démarrage garde sa fenêtre de REQUÊTE courte (les
// événements tombés entre deux passages ne sont vus par aucun) — seule sa déduplication est planchée,
// et rien ne refuse cette réactivation au démarrage.
// =====================================================================================
mod plancher_de_fenetre_des_playbooks {
    use super::*;
    use crate::handlers::playbooks::{debut_de_la_deduplication_du_playbook, juger_le_plancher_de_fenetre_du_playbook, run_playbooks, TOUR_DE_DETECTION_S};

    fn pfp_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("pfp-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.21-e` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM playbook", []).unwrap();
            conn.execute("DELETE FROM action", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn pfp_admin() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn pfp_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn pfp_phrase(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    const PFP_REQUETE: &str = "search source=auth outcome=fail | stats count by src_ip";

    // -------------------------------------------------------------------------------------
    // (1) LA FONCTION PURE — le plancher et les termes de son refus.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sous `max(interval_s, tour)` la fenêtre est refusée, et la phrase cite
    /// `window_s`, `interval_s`, le plancher et un levier ; à l'égalité elle passe ; un `interval_s`
    /// nul, négatif ou inférieur au tour ne fait pas descendre le plancher sous le tour.
    /// LA MUTATION QUI LE FAIT ROUGIR : faire rendre `Ok` au juge sans condition (plancher retiré).
    #[test]
    fn pfp_le_plancher_vaut_le_plus_grand_de_l_intervalle_et_du_tour() {
        let tour = TOUR_DE_DETECTION_S as i64;
        assert_eq!(tour, 20, "la cadence déclarée de l'ordonnanceur");
        assert!(juger_le_plancher_de_fenetre_du_playbook(300, 300).is_ok(), "égalité : admise");
        assert!(juger_le_plancher_de_fenetre_du_playbook(3600, 300).is_ok(), "les valeurs par défaut sont au-dessus");
        assert!(juger_le_plancher_de_fenetre_du_playbook(tour, 0).is_ok(), "intervalle nul : plancher = un tour");
        let refus = juger_le_plancher_de_fenetre_du_playbook(299, 300).expect_err("une seconde sous l'intervalle : refusée");
        for terme in ["window_s = 299 s", "interval_s = 300 s", "plancher = 300 s", "Levier", "ramenez interval_s à 299 s",
                      "fenêtre de la requête de détection", "élargit d'autant la recherche"] {
            assert!(refus.contains(terme), "le refus doit citer « {terme} » : {refus}");
        }
        for (fenetre, intervalle) in [(10, 0), (10, -5), (19, 5)] {
            let refus = juger_le_plancher_de_fenetre_du_playbook(fenetre, intervalle)
                .expect_err("sous le tour : refusée, quel que soit l'intervalle");
            assert!(refus.contains("plancher = 20 s"), "le tour borne l'intervalle {intervalle} : {refus}");
            assert!(refus.contains("portez window_s à au moins 20 s"), "seul levier utile sous le tour : {refus}");
        }
    }

    // -------------------------------------------------------------------------------------
    // (2) LA CRÉATION — refusée sous le plancher, rien d'écrit.
    // -------------------------------------------------------------------------------------

    #[tokio::test]
    async fn pfp_la_creation_sous_le_plancher_est_refusee_sans_rien_ecrire() {
        let (st, _tmp) = pfp_etat("creation");
        let (code, v) = pb_json(playbook_create(State(st.clone()), Extension(pfp_admin()),
            Json(json!({ "name": "pfp-court", "query": PFP_REQUETE, "action_kind": "ban_ip", "window_s": 60, "interval_s": 300 }))).await).await;
        assert_eq!(code, 400, "fenêtre 60 s, intervalle 300 s : refus ({v})");
        assert!(pfp_phrase(&v).contains("window_s = 60 s"), "refus nommé : {v}");
        assert_eq!(pfp_compte(&st, "SELECT COUNT(*) FROM playbook"), 0, "rien n'est écrit");
        // CONTRÔLE POSITIF : la même création, fenêtre égale à l'intervalle, passe.
        let (code, v) = pb_json(playbook_create(State(st.clone()), Extension(pfp_admin()),
            Json(json!({ "name": "pfp-egal", "query": PFP_REQUETE, "action_kind": "ban_ip", "window_s": 300, "interval_s": 300 }))).await).await;
        assert_eq!(code, 200, "au plancher : admise ({v})");
        assert_eq!(pfp_compte(&st, "SELECT COUNT(*) FROM playbook"), 1);
    }

    // -------------------------------------------------------------------------------------
    // (3) LA MODIFICATION — une ligne déjà sous le plancher reste désactivable.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une ligne posée sous le plancher AVANT lui est signalée par la liste sans être
    /// modifiée ; elle se désactive et se renomme (la requête ne touche ni `window_s` ni `interval_s`) ;
    /// toucher l'un des deux juge les valeurs EFFECTIVES (l'autre lu sur la ligne) ; la remonter au
    /// plancher passe et éteint le signalement.
    #[tokio::test]
    async fn pfp_une_ligne_sous_le_plancher_reste_desactivable_et_n_est_que_signalee() {
        let (st, _tmp) = pfp_etat("modification");
        st.db.lock().execute(
            "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,created_by_role) VALUES('pfp-ancien',1,?1,1,'ban_ip',300,5,2,'admin')",
            params![PFP_REQUETE],
        ).unwrap();
        let id: i64 = pfp_compte(&st, "SELECT id FROM playbook WHERE name='pfp-ancien'");

        let liste = playbooks_list(State(st.clone()), Extension(pfp_admin())).await.0;
        let ligne = &liste["playbooks"][0];
        assert_eq!(ligne["fenetre_sous_le_plancher"], json!(true), "ligne sous le plancher SIGNALÉE : {ligne}");
        assert!(ligne["cause_fenetre_sous_le_plancher"].as_str().unwrap_or("").contains("window_s = 5 s"), "{ligne}");
        assert_eq!(ligne["window_s"], json!(5), "la valeur enregistrée n'est pas modifiée par la lecture");

        let (code, v) = pb_json(playbook_update(State(st.clone()), Extension(pfp_admin()), Path(id), Json(json!({ "enabled": false }))).await).await;
        assert_eq!(code, 200, "désactiver un playbook sous le plancher doit rester possible ({v})");
        assert_eq!(pfp_compte(&st, "SELECT enabled FROM playbook WHERE name='pfp-ancien'"), 0, "désactivé");
        let (code, v) = pb_json(playbook_update(State(st.clone()), Extension(pfp_admin()), Path(id), Json(json!({ "name": "pfp-renomme" }))).await).await;
        assert_eq!(code, 200, "renommer aussi ({v})");

        // LE FORMULAIRE DE LA CONSOLE renvoie `window_s` et `interval_s` à chaque enregistrement : les
        // renvoyer INCHANGÉS n'est pas toucher la cadence (mutation `cadence_portee` : 400).
        let (code, v) = pb_json(playbook_update(State(st.clone()), Extension(pfp_admin()), Path(id),
            Json(json!({ "name": "pfp-formulaire", "window_s": 5, "interval_s": 300, "enabled": false }))).await).await;
        assert_eq!(code, 200, "corps du formulaire, cadence inchangée : admis sous le plancher ({v})");
        assert_eq!(pfp_compte(&st, "SELECT COUNT(*) FROM playbook WHERE name='pfp-formulaire'"), 1, "renommé par le formulaire");

        let (code, v) = pb_json(playbook_update(State(st.clone()), Extension(pfp_admin()), Path(id), Json(json!({ "window_s": 10 }))).await).await;
        assert_eq!(code, 400, "fenêtre 10 s contre l'intervalle 300 s LU SUR LA LIGNE : refus ({v})");
        assert!(pfp_phrase(&v).contains("interval_s = 300 s"), "valeurs effectives citées : {v}");
        let (code, v) = pb_json(playbook_update(State(st.clone()), Extension(pfp_admin()), Path(id), Json(json!({ "interval_s": 5 }))).await).await;
        assert_eq!(code, 400, "intervalle 5 s contre la fenêtre 5 s de la ligne : sous le tour, refus ({v})");
        assert_eq!(pfp_compte(&st, &format!("SELECT window_s FROM playbook WHERE id={id}")), 5, "refus : rien d'écrit");

        let (code, v) = pb_json(playbook_update(State(st.clone()), Extension(pfp_admin()), Path(id), Json(json!({ "window_s": 300 }))).await).await;
        assert_eq!(code, 200, "remontée au plancher : admise ({v})");

        // LA SECONDE VOIE DU LEVIER — « ramenez interval_s à W s au plus » : l'intervalle ENVOYÉ est jugé,
        // pas celui de la ligne (mutation `intervalle_de_la_ligne` : 400 contre l'intervalle 300 lu).
        st.db.lock().execute(
            "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,created_by_role) VALUES('pfp-voie2',1,?1,1,'ban_ip',300,60,2,'admin')",
            params![PFP_REQUETE],
        ).unwrap();
        let id2: i64 = pfp_compte(&st, "SELECT id FROM playbook WHERE name='pfp-voie2'");
        let (code, v) = pb_json(playbook_update(State(st.clone()), Extension(pfp_admin()), Path(id2), Json(json!({ "interval_s": 60 }))).await).await;
        assert_eq!(code, 200, "intervalle ramené à la fenêtre de 60 s : admis ({v})");
        assert_eq!(pfp_compte(&st, &format!("SELECT interval_s FROM playbook WHERE id={id2}")), 60, "écrit");
        let liste = playbooks_list(State(st.clone()), Extension(pfp_admin())).await.0;
        assert_eq!(liste["playbooks"][0]["fenetre_sous_le_plancher"], json!(false), "plus signalée");
        assert_eq!(liste["playbooks"][0]["cause_fenetre_sous_le_plancher"], Value::Null);
        assert_eq!(liste["playbooks"][1]["fenetre_sous_le_plancher"], json!(false), "seconde voie : plus signalée");
    }

    // -------------------------------------------------------------------------------------
    // (4) DEUX PASSAGES DE `run_playbooks` SUR UNE RÈGLE ENCORE VRAIE.
    // -------------------------------------------------------------------------------------

    /// Une base avec UN playbook `ban_ip` dû dont la requête rend toujours la même cible.
    fn pfp_base_de_playbook(tag: &str, interval_s: i64, window_s: i64) -> (Arc<Mutex<Connection>>, String, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("pfp-{tag}"));
        let p = chemin.to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.21-e` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM action", []).unwrap();
            conn.execute("DELETE FROM playbook", []).unwrap();
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('plume_mode','observe')", []).unwrap();
            conn.execute(
                "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,last_run,created_by_role) \
                 VALUES('pfp-pb',1,'SELECT ''203.0.113.70''',0,'ban_ip',?1,?2,0,NULL,'admin')",
                params![interval_s, window_s],
            ).unwrap();
        }
        (db, p, chemin)
    }

    fn pfp_compte_sur(db: &Arc<Mutex<Connection>>, sql: &str) -> i64 {
        db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    /// Joue deux passages séparés de `ecart` secondes : le premier, puis le passage du temps simulé
    /// en reculant d'autant le marqueur `last_run` et l'horodatage des ripostes, puis le second.
    fn pfp_deux_passages(db: &Arc<Mutex<Connection>>, p: &str, ecart: i64) -> i64 {
        pfp_deux_passages_decales(db, p, ecart, ecart)
    }

    /// Variante : le marqueur recule de `ecart_marqueur`, la riposte de `ecart_riposte` (une riposte
    /// posée par un autre chemin, plus récente que le passage précédent).
    fn pfp_deux_passages_decales(db: &Arc<Mutex<Connection>>, p: &str, ecart_marqueur: i64, ecart_riposte: i64) -> i64 {
        use crate::mesure_environnement::Mesure;
        crate::ledger::declarer_la_liste_pour_ce_temoin(); // `P4.7-e` : ce témoin pose une riposte de ban, il déclare sa population
        assert_eq!(run_playbooks(db, p), Mesure::Lue(0), "premier passage : rien d'abandonné");
        assert_eq!(pfp_compte_sur(db, "SELECT COUNT(*) FROM action"), 1, "la première riposte est posée");
        db.lock().execute_batch(&format!("UPDATE playbook SET last_run=last_run-{ecart_marqueur}; UPDATE action SET ts=ts-{ecart_riposte};")).unwrap();
        let marqueur_recule = pfp_compte_sur(db, "SELECT last_run FROM playbook");
        assert_eq!(run_playbooks(db, p), Mesure::Lue(0), "second passage : rien d'abandonné");
        assert!(pfp_compte_sur(db, "SELECT last_run FROM playbook") >= marqueur_recule + ecart_marqueur,
            "le second passage a bien eu lieu : marqueur reposé à l'heure courante");
        pfp_compte_sur(db, "SELECT COUNT(*) FROM action WHERE target='203.0.113.70'")
    }

    /// CE QU'IL TIENT : quand la fenêtre couvre l'écart entre deux passages, le second passage ne pose
    /// PAS de seconde riposte ; et même une ligne posée sous le plancher AVANT lui (fenêtre 60 s,
    /// intervalle 300 s) ne re-pose rien au passage suivant : la déduplication remonte au passage
    /// précédent. LA MUTATION QUI LE FAIT ROUGIR : `extension_retiree` (fenêtre nominale seule : 2).
    #[test]
    fn pfp_deux_passages_ne_posent_qu_une_riposte_quand_la_fenetre_couvre_l_intervalle() {
        let (db, p, _tmp) = pfp_base_de_playbook("deux-passages", 300, 302);
        assert_eq!(pfp_deux_passages(&db, &p, 300), 1, "fenêtre ≥ intervalle : une seule riposte sur deux passages");

        let (db, p, _tmp2) = pfp_base_de_playbook("fenetre-courte", 300, 60);
        assert_eq!(pfp_deux_passages(&db, &p, 300), 1,
            "ligne d'avant le plancher, fenêtre 60 s : la riposte du passage précédent est vue quand même");
    }

    // -------------------------------------------------------------------------------------
    // (5) L'ÉCART RÉEL — il dépasse l'intervalle, la déduplication le couvre.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : au plancher exact (`window_s == interval_s`, la valeur que le levier propose),
    /// un écart réel qui dépasse l'intervalle d'une seconde, puis d'un tour entier plus dix-neuf
    /// secondes de travail, ne laisse partir AUCUNE seconde riposte.
    /// LA MUTATION QUI LE FAIT ROUGIR : `extension_retiree` (2 ripostes dès 301 s).
    #[test]
    fn pfp_au_plancher_exact_le_depassement_du_tour_ne_laisse_partir_aucune_seconde_riposte() {
        assert!(juger_le_plancher_de_fenetre_du_playbook(300, 300).is_ok(), "ce playbook est admis par le plancher");
        for ecart in [301, 300 + TOUR_DE_DETECTION_S as i64 + 19] {
            let (db, p, _tmp) = pfp_base_de_playbook(&format!("plancher-exact-{ecart}"), 300, 300);
            assert_eq!(pfp_deux_passages(&db, &p, ecart), 1, "écart réel {ecart} s : la riposte d'avant est vue");
        }
    }

    /// CE QU'IL TIENT : la remontée est BORNÉE. Un passage précédent très ancien (démon arrêté) ne
    /// retient pas une riposte due : une riposte d'il y a 5 000 s, hors fenêtre, ne bloque pas la
    /// suivante quand le marqueur date de 10 000 s. La fonction pure rend aussi ses trois régimes.
    /// LA MUTATION QUI LE FAIT ROUGIR : `borne_retiree` (la riposte périmée est comptée : 1).
    #[test]
    fn pfp_la_remontee_au_passage_precedent_est_bornee() {
        let (db, p, _tmp) = pfp_base_de_playbook("borne", 300, 300);
        assert_eq!(pfp_deux_passages_decales(&db, &p, 10_000, 5_000), 2, "passage d'avant trop ancien : fenêtre nominale, riposte due posée");
        assert_eq!(debut_de_la_deduplication_du_playbook(10_000, 300, 300, None), 9_700, "premier passage : nominal");
        assert_eq!(debut_de_la_deduplication_du_playbook(10_000, 300, 300, Some(9_661)), 9_661, "passage d'avant dans la borne : remontée");
        assert_eq!(debut_de_la_deduplication_du_playbook(10_000, 300, 300, Some(9_399)), 9_700, "au-delà de la borne : nominal");
        assert_eq!(debut_de_la_deduplication_du_playbook(10_000, 3600, 300, Some(9_700)), 6_400, "passage d'avant récent : nominal");
    }

    // -------------------------------------------------------------------------------------
    // (6) L'IMPORT D'OVERLAY — un fichier sous le plancher est ignoré, compté.
    // -------------------------------------------------------------------------------------

    #[test]
    fn pfp_un_overlay_sous_le_plancher_est_ignore_et_compte() {
        let chemin = crate::tmp_possede::TmpDb::neuf("pfp-overlay");
        let conn = open_db(&chemin).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture `P10.21-e` : la chaîne de migrations doit aller au bout");
        conn.execute("DELETE FROM playbook", []).unwrap();
        let dossier = crate::tmp_possede::TmpPossede::neuf("pfp-overlay-d");
        std::fs::write(dossier.join("court.json"), json!({ "name": "pfp-ov-court", "query": PFP_REQUETE, "action_kind": "ban_ip", "interval_s": 300, "window_s": 30 }).to_string()).unwrap();
        std::fs::write(dossier.join("sain.json"), json!({ "name": "pfp-ov-sain", "query": PFP_REQUETE, "action_kind": "ban_ip", "interval_s": 300, "window_s": 600 }).to_string()).unwrap();
        // Un fichier qui COUPE le playbook passe sous le plancher : il n'arme rien, et l'ignorer laisserait
        // allumée la ligne qu'il existe pour couper (mutation `overlay_coupe_ignore` : (1, 2)).
        std::fs::write(dossier.join("coupe.json"), json!({ "name": "pfp-ov-coupe", "query": PFP_REQUETE, "action_kind": "ban_ip", "interval_s": 300, "window_s": 30, "enabled": false }).to_string()).unwrap();
        let ch = crate::overlays::load_overlay_playbooks(&conn, &dossier);
        assert_eq!((ch.charges, ch.ignores), (2, 1), "deux chargés (sain, coupé), un ignoré (actif sous le plancher)");
        let noms: Vec<(String, i64)> = conn.prepare("SELECT name, enabled FROM playbook ORDER BY name").unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(noms, vec![("pfp-ov-coupe".to_string(), 0), ("pfp-ov-sain".to_string(), 1)],
            "le fichier actif sous le plancher n'est pas posé ; le fichier coupé l'est, éteint");
    }

    // -------------------------------------------------------------------------------------
    // (7) LA CADENCE DÉCLARÉE UNE FOIS EST CELLE QUE LA BOUCLE DORT.
    // -------------------------------------------------------------------------------------

    /// Juge le corps de `spawn_rule_scheduler` : un seul sommeil, et c'est `TOUR_DE_DETECTION_S`.
    fn pfp_juger_la_cadence_de_la_boucle(source: &str) -> Result<(), String> {
        let debut = source.find("fn spawn_rule_scheduler(").ok_or("spawn_rule_scheduler introuvable")?;
        let reste = &source[debut..];
        // Le corps finit à la première accolade fermante en colonne zéro (l'item suivant peut être un
        // `pub(crate) fn` : chercher « \nfn » engloberait la fonction d'après).
        let fin = reste.find("\n}\n").map(|i| i + 2).unwrap_or(reste.len());
        let corps = &reste[..fin];
        let sommeils = corps.matches("sleep(").count();
        if sommeils != 1 {
            return Err(format!("{sommeils} sommeil(s) dans spawn_rule_scheduler, un seul attendu"));
        }
        if !corps.contains("sleep(Duration::from_secs(crate::handlers::playbooks::TOUR_DE_DETECTION_S))") {
            return Err("le sommeil de spawn_rule_scheduler ne lit pas TOUR_DE_DETECTION_S".into());
        }
        Ok(())
    }

    /// CE QU'IL TIENT : la boucle de règles dort `TOUR_DE_DETECTION_S` et rien d'autre ; si sa cadence
    /// change sans la constante, le plancher et la borne de déduplication deviennent faux sans bruit.
    /// Épreuve négative jouée à chaque exécution : un sommeil de 40 s en dur est refusé.
    /// LA MUTATION QUI LE FAIT ROUGIR : remplacer ce sommeil par `from_secs(40)` dans `boucles_de_fond.rs`.
    #[test]
    fn pfp_la_boucle_de_regles_dort_la_cadence_declaree() {
        let reelle = include_str!("../server/boucles_de_fond.rs");
        let fabriquee = reelle.replace("sleep(Duration::from_secs(crate::handlers::playbooks::TOUR_DE_DETECTION_S))", "sleep(Duration::from_secs(40))");
        assert!(pfp_juger_la_cadence_de_la_boucle(&fabriquee).is_err(), "épreuve : un sommeil en dur doit être refusé");
        assert_eq!(pfp_juger_la_cadence_de_la_boucle(reelle), Ok(()));
    }

    // -------------------------------------------------------------------------------------
    // (8) LA DÉDUPLICATION À L'EXÉCUTION — planchée, bornée à l'égalité, saturée, appelée dans l'ordre.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, sur la fonction pure : la fenêtre nominale vaut au moins `max(interval_s, tour)`
    /// même pour une ligne sous le plancher ; un passage précédent EXACTEMENT sur la borne remonte ;
    /// des valeurs extrêmes admises par le juge (`i64::MAX`) ne débordent pas.
    /// MUTATIONS QUI LE FONT ROUGIR : `plancher_runtime_retire` (9 995), `borne_stricte` (9 700),
    /// `sub_simple` (débordement : panique en profil de test).
    #[test]
    fn pfp_la_deduplication_plancher_sa_fenetre_et_ne_deborde_pas() {
        assert_eq!(debut_de_la_deduplication_du_playbook(10_000, 5, 300, None), 9_700, "ligne sous le plancher : fenêtre nominale planchée à l'intervalle");
        assert_eq!(debut_de_la_deduplication_du_playbook(10_000, 5, 0, None), 9_980, "intervalle nul : planchée au tour");
        assert_eq!(debut_de_la_deduplication_du_playbook(10_000, 300, 300, Some(9_400)), 9_400, "passage précédent sur la borne : remontée");
        let extreme = std::panic::catch_unwind(|| debut_de_la_deduplication_du_playbook(1_700_000_000, i64::MAX, i64::MAX, Some(1_699_999_000)));
        assert_eq!(extreme.ok(), Some(1_700_000_000 - i64::MAX), "valeurs extrêmes admises par le juge : pas de débordement");
    }

    /// CE QU'IL TIENT, sur `run_playbooks` : (a) une ligne ARMÉE sous le plancher (fenêtre 5 s, intervalle
    /// 300 s — l'état que laisse la dérogation du démarrage) ne repose pas de riposte au passage suivant,
    /// écart réel 321 s ; (b) aux valeurs par défaut (fenêtre 3 600 s, intervalle 300 s), une riposte de
    /// 1 000 s est vue, et un passage précédent de 5 000 s hors borne ne retient pas une riposte due : ce
    /// cas distingue l'ordre des arguments à l'appel.
    /// MUTATIONS QUI LE FONT ROUGIR : `plancher_runtime_retire` (a : 2), `args_inverses` (b : 1 au lieu de 2).
    #[test]
    fn pfp_run_playbooks_plancher_la_deduplication_et_passe_ses_arguments_dans_l_ordre() {
        let (db, p, _tmp) = pfp_base_de_playbook("arme-sous-plancher", 300, 5);
        assert_eq!(pfp_deux_passages(&db, &p, 321), 1, "ligne armée sous le plancher : une seule riposte sur deux passages");

        let (db, p, _tmp2) = pfp_base_de_playbook("defauts-recente", 300, 3600);
        assert_eq!(pfp_deux_passages_decales(&db, &p, 300, 1_000), 1, "défauts : la riposte de 1 000 s est dans la fenêtre");

        let (db, p, _tmp3) = pfp_base_de_playbook("defauts-borne", 300, 3600);
        assert_eq!(pfp_deux_passages_decales(&db, &p, 5_000, 5_000), 2,
            "défauts : passage précédent à 5 000 s, au-delà de la borne (3 600 + 300) : la riposte due est posée");
    }

    // -------------------------------------------------------------------------------------
    // (9) ARMER UNE LIGNE SOUS LE PLANCHER PAR L'API — refusé, la couper reste admis.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la bascule de la ligne (`/playbooks/{id}/enabled`) et la case « Activée » du
    /// formulaire refusent d'ARMER une ligne éteinte sous le plancher (400 nommé, rien d'écrit) ; la
    /// couper passe ; renvoyer `enabled:true` sur une ligne déjà armée n'arme rien et passe ; une ligne
    /// au plancher s'arme.
    /// MUTATIONS QUI LE FONT ROUGIR : `bascule_non_jugee` (200 à la bascule), `armement_non_juge` (200 au formulaire).
    #[tokio::test]
    async fn pfp_armer_une_ligne_sous_le_plancher_est_refuse() {
        let (st, _tmp) = pfp_etat("armement");
        {
            let c = st.db.lock();
            c.execute("INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,created_by_role) VALUES('pfp-eteint',0,?1,1,'ban_ip',300,5,2,'admin')", params![PFP_REQUETE]).unwrap();
            c.execute("INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,created_by_role) VALUES('pfp-arme',1,?1,1,'ban_ip',300,5,2,'admin')", params![PFP_REQUETE]).unwrap();
            c.execute("INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,created_by_role) VALUES('pfp-sain',0,?1,1,'ban_ip',300,300,2,'admin')", params![PFP_REQUETE]).unwrap();
        }
        let id_de = |n: &str| pfp_compte(&st, &format!("SELECT id FROM playbook WHERE name='{n}'"));
        let (eteint, arme, sain) = (id_de("pfp-eteint"), id_de("pfp-arme"), id_de("pfp-sain"));
        let bascule = |id: i64, en: bool| crate::handlers::detection::playbook_set_enabled(State(st.clone()), Extension(pfp_admin()), Path(id), Json(json!({ "enabled": en })));

        let (code, v) = pb_json(bascule(eteint, true).await).await;
        assert_eq!(code, 400, "bascule : armer sous le plancher est refusé ({v})");
        assert!(pfp_phrase(&v).contains("window_s = 5 s"), "refus nommé : {v}");
        assert_eq!(pfp_compte(&st, &format!("SELECT enabled FROM playbook WHERE id={eteint}")), 0, "rien d'écrit");

        let (code, v) = pb_json(playbook_update(State(st.clone()), Extension(pfp_admin()), Path(eteint), Json(json!({ "enabled": true }))).await).await;
        assert_eq!(code, 400, "formulaire : armer sous le plancher est refusé ({v})");
        assert_eq!(pfp_compte(&st, &format!("SELECT enabled FROM playbook WHERE id={eteint}")), 0, "rien d'écrit");

        let (code, v) = pb_json(bascule(arme, false).await).await;
        assert_eq!(code, 200, "couper une ligne sous le plancher reste admis ({v})");
        let (code, v) = pb_json(playbook_update(State(st.clone()), Extension(pfp_admin()), Path(eteint),
            Json(json!({ "name": "pfp-eteint-2", "window_s": 5, "interval_s": 300, "enabled": false }))).await).await;
        assert_eq!(code, 200, "formulaire qui garde la ligne éteinte : admis ({v})");
        st.db.lock().execute(&format!("UPDATE playbook SET enabled=1 WHERE id={arme}"), []).unwrap();
        let (code, v) = pb_json(playbook_update(State(st.clone()), Extension(pfp_admin()), Path(arme),
            Json(json!({ "name": "pfp-arme-2", "window_s": 5, "interval_s": 300, "enabled": true }))).await).await;
        assert_eq!(code, 200, "formulaire sur une ligne DÉJÀ armée : enabled inchangé, admis ({v})");

        let (code, v) = pb_json(bascule(sain, true).await).await;
        assert_eq!(code, 200, "contrôle positif : une ligne au plancher s'arme ({v})");
        assert_eq!(pfp_compte(&st, &format!("SELECT enabled FROM playbook WHERE id={sain}")), 1);
    }
}
