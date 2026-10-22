// =====================================================================================
// `P10.33-j` (reste) — LA RÉSOLUTION ET LE RAFRAÎCHISSEMENT D'UNE ALERTE DE SANTÉ SONT ÉCRITS, OU LE REFUS SE COMPTE.
//
// VU (re-mesuré au commit de départ aa5556fd) : les INSERT d'alerte des dead-man's-switch étaient déjà comptés
// (vague T), mais leurs UPDATE restaient en `let _` — résolution du capteur muet (`handlers/freshness.rs`, bras
// « de nouveau actif »), résolution de l'épisode de flotte précédent (`verifier_flotte_muette`), résolution du
// magasin de secrets (`sonde_du_magasin_de_secrets.rs`, `Sert`), et les rafraîchissements d'imputation ou de texte
// (capteur muet, magasin, alerte de cécité de `detection_aveugle::consigner_abandon`). Une résolution refusée
// laissait l'alerte ouverte ET sa clé de dédup tenue : le prochain épisode aurait été avalé par l'INSERT OR IGNORE,
// et le tick rendait `Lue(0)`, un tick calme.
//
// CE QUE CES TÉMOINS JOUENT : un déclencheur `RAISE(ABORT)` sur `UPDATE` de `alert` (et sur `INSERT` pour les
// doubles refus), l'épisode ouvert par un premier tick sans panne, puis le tick qui doit résoudre ou rafraîchir ;
// le compte rendu (`Lue(n)`), l'alerte restée ouverte, la résolution au tick sans panne, et la ligne de journal lue
// sur le stderr d'un sous-processus (sujet + cause du moteur, ni hôte ni détail). Hôtes de test : noms fictifs.
// Décision par défaut AB2 : UN abandon par alerte (INSERT et rafraîchissement de la même alerte refusés = un) ;
// l'épisode de flotte précédent et l'épisode courant sont deux alertes (deux refus = deux) ; le rafraîchissement
// de l'alerte de cécité est DIT sans être recompté (l'ordonnanceur compte déjà cet abandon de règle — témoin au tick).
// Correction AB2 : une base qui refuse TOUTE écriture (lecture seule) refuse chaque résolution de capteur même sur
// zéro ligne : le COMPTE reste un par capteur (ce n'est pas un tick calme), le JOURNAL les agrège en UNE ligne par
// tick (nombre + première cause). La ligne de résolution de flotte est jugée aussi avec des hôtes muets (ensemble
// changé), là où un nom de machine pourrait fuir.
// =====================================================================================
mod resolutions_et_imputations_de_sante_comptees {
    use super::*;
    use crate::detection_aveugle::{cle_dedup, consigner_abandon, seuil_d_abandons_consecutifs, AbandonDEvaluation};
    use crate::mesure_environnement::Mesure;
    use crate::sonde_du_magasin_de_secrets::{
        verifier_le_magasin_de_secrets, DEDUP_MAGASIN, FENETRE_DE_JUGEMENT_S, SERIE_MAGASINS_NON_PRETS,
        SERIE_MAGASINS_TOTAL,
    };

    const AB2_CAUSE: &str = "mise a jour refusee par le temoin ab2";
    const AB2_REFUS_UPDATE: &str = "CREATE TRIGGER ab2_refus_update BEFORE UPDATE ON alert \
                                    BEGIN SELECT RAISE(ABORT,'mise a jour refusee par le temoin ab2'); END;";
    const AB2_REFUS_SOURCES: &str = "CREATE TRIGGER ab2_refus_update BEFORE UPDATE OF sources ON alert \
                                     BEGIN SELECT RAISE(ABORT,'mise a jour refusee par le temoin ab2'); END;";
    const AB2_REFUS_INSERT: &str = "CREATE TRIGGER ab2_refus_insert BEFORE INSERT ON alert \
                                    BEGIN SELECT RAISE(ABORT,'insertion refusee par le temoin ab2'); END;";
    const AB2_SANS_REFUS: &str = "DROP TRIGGER IF EXISTS ab2_refus_update; DROP TRIGGER IF EXISTS ab2_refus_insert;";
    /// Instant fixe pour le magasin (la sonde reçoit l'instant en argument).
    const AB2_NOW: i64 = 1_750_000_000;
    const AB2_INTERVALLE_S: i64 = 600;

    fn ab2_n(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    /// (statut, dédup) de l'alerte d'une famille, la plus ancienne d'abord.
    fn ab2_alertes(conn: &Connection, regle: &str) -> Vec<(String, Option<String>)> {
        let mut st = conn.prepare("SELECT status, dedup FROM alert WHERE rule=?1 ORDER BY id").unwrap();
        st.query_map(params![regle], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
    }

    /// Le pare-feu muet depuis deux heures, puis un premier tick sans panne qui ouvre l'épisode.
    fn ab2_capteur_muet_ouvert() -> Arc<Mutex<Connection>> {
        let conn = test_db();
        conn.execute(
            "INSERT INTO snapshot(ts,host,kind,data) VALUES(?1,'hote-ab2-pare-feu','firewall','{}')",
            params![now() - 7200],
        )
        .unwrap();
        let db = Arc::new(Mutex::new(conn));
        assert_eq!(check_heartbeats(&db), Mesure::Lue(0), "contrôle : premier tick sans panne");
        assert_eq!(ab2_alertes(&db.lock(), "heartbeat.firewall"), vec![("new".into(), Some("hb-firewall".into()))]);
        db
    }

    /// Le pare-feu reparle.
    fn ab2_capteur_reparle(db: &Arc<Mutex<Connection>>) {
        db.lock()
            .execute(
                "INSERT INTO snapshot(ts,host,kind,data) VALUES(?1,'hote-ab2-pare-feu','firewall','{}')",
                params![now()],
            )
            .unwrap();
    }

    /// Un parc par le vrai chemin (`metric` -> plancher -> rollup) ; seule la sonde `resources` s'anime.
    fn ab2_parc(conn: &Connection, hotes: &[(&str, i64)]) {
        let mut plancher = i64::MAX;
        for (hote, ts) in hotes {
            conn.execute("INSERT INTO metric(ts,name,labels,value,host) VALUES(?1,'cpu','{}',1.0,?2)", params![ts, hote])
                .unwrap();
            plancher = plancher.min(*ts);
        }
        note_host_backfill_floor(conn, plancher);
        rollup_hosts(conn);
    }

    /// Trois machines fictives, une muette, et un premier tick sans panne qui ouvre l'épisode de flotte.
    fn ab2_flotte_ouverte() -> Arc<Mutex<Connection>> {
        let conn = test_db();
        let t = now();
        ab2_parc(&conn, &[("hote-ab2-vivant", t - 60), ("hote-ab2-second", t - 60), ("hote-ab2-muet", t - 7200)]);
        let db = Arc::new(Mutex::new(conn));
        assert_eq!(check_heartbeats(&db), Mesure::Lue(0), "contrôle : premier tick sans panne");
        let a = ab2_alertes(&db.lock(), "heartbeat.flotte-hotes-muets");
        assert_eq!(a.len(), 1, "contrôle : un épisode de flotte ouvert");
        assert_eq!(a[0].0, "new");
        db
    }

    fn ab2_hote(db: &Arc<Mutex<Connection>>, hote: &str, last_ts: i64) {
        db.lock().execute("UPDATE host_rollup SET last_ts=?1 WHERE host=?2", params![last_ts, hote]).unwrap();
    }

    fn ab2_releve(conn: &Connection, ts: i64, non_prets: f64, total: f64) {
        for (serie, v) in [(SERIE_MAGASINS_NON_PRETS, non_prets), (SERIE_MAGASINS_TOTAL, total)] {
            conn.execute("INSERT INTO metric(ts,name,labels,value) VALUES(?1,?2,'{}',?3)", params![ts, serie, v]).unwrap();
        }
    }

    /// Six relevés unanimes « un magasin sur trois pas prêt », puis l'épisode ouvert sans panne.
    fn ab2_magasin_ouvert() -> Connection {
        let conn = test_db();
        for i in 0..6i64 {
            ab2_releve(&conn, AB2_NOW - (FENETRE_DE_JUGEMENT_S / 4) + i * 60, 1.0, 3.0);
        }
        assert_eq!(verifier_le_magasin_de_secrets(&conn, AB2_NOW), Mesure::Lue(0), "contrôle : épisode ouvert sans panne");
        assert_eq!(ab2_magasin(&conn).0, "new");
        conn
    }

    /// (statut, dédup, ts) de l'alerte du magasin (une seule par construction des témoins).
    fn ab2_magasin(conn: &Connection) -> (String, Option<String>, i64) {
        assert_eq!(ab2_n(conn, "SELECT COUNT(*) FROM alert"), 1, "contrôle : une seule alerte, celle du magasin");
        conn.query_row("SELECT status, dedup, ts FROM alert", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap()
    }

    // ------------------------------------------------------------------ capteur muet

    #[test]
    fn ab2_capteur_resolution_refusee_comptee_alerte_ouverte_puis_resolue() {
        let db = ab2_capteur_muet_ouvert();
        ab2_capteur_reparle(&db);
        db.lock().execute_batch(AB2_REFUS_UPDATE).unwrap();
        assert_eq!(check_heartbeats(&db), Mesure::Lue(1), "résolution refusée : UN abandon, jamais un tick calme");
        assert_eq!(
            ab2_alertes(&db.lock(), "heartbeat.firewall"),
            vec![("new".into(), Some("hb-firewall".into()))],
            "contrôle : l'alerte est restée ouverte, sa clé tenue"
        );
        db.lock().execute_batch(AB2_SANS_REFUS).unwrap();
        assert_eq!(check_heartbeats(&db), Mesure::Lue(0), "tick sans panne : aucun abandon");
        assert_eq!(ab2_alertes(&db.lock(), "heartbeat.firewall"), vec![("resolved".into(), None)], "résolue, clé libérée");
        assert_eq!(check_heartbeats(&db), Mesure::Lue(0), "rien d'ouvert : la résolution sur zéro ligne n'est pas un refus");
    }

    #[test]
    fn ab2_capteur_imputation_refusee_comptee() {
        let db = ab2_capteur_muet_ouvert();
        db.lock().execute_batch(AB2_REFUS_SOURCES).unwrap();
        assert_eq!(check_heartbeats(&db), Mesure::Lue(1), "épisode ouvert, imputation refusée : UN abandon");
        assert_eq!(ab2_n(&db.lock(), "SELECT COUNT(*) FROM alert"), 1, "contrôle : toujours un seul épisode");
        db.lock().execute_batch(AB2_SANS_REFUS).unwrap();
        assert_eq!(check_heartbeats(&db), Mesure::Lue(0), "tick sans panne : l'imputation est rafraîchie sans abandon");
    }

    /// L'INSERT et le rafraîchissement portent la MÊME alerte : deux refus sur elle = UN abandon.
    #[test]
    fn ab2_capteur_insert_et_imputation_refuses_un_seul_abandon() {
        let db = ab2_capteur_muet_ouvert();
        db.lock().execute_batch(AB2_REFUS_INSERT).unwrap();
        db.lock().execute_batch(AB2_REFUS_SOURCES).unwrap();
        assert_eq!(check_heartbeats(&db), Mesure::Lue(1), "une alerte, deux refus : un abandon, jamais deux");
        db.lock().execute_batch(AB2_SANS_REFUS).unwrap();
        assert_eq!(check_heartbeats(&db), Mesure::Lue(0), "contre-épreuve sans panne");
    }

    // ------------------------------------------------------------------ flotte muette

    #[test]
    fn ab2_flotte_resolution_refusee_comptee_alerte_ouverte_puis_resolue() {
        let db = ab2_flotte_ouverte();
        ab2_hote(&db, "hote-ab2-muet", now() - 60);
        db.lock().execute_batch(AB2_REFUS_UPDATE).unwrap();
        assert_eq!(check_heartbeats(&db), Mesure::Lue(1), "parc revenu, résolution refusée : UN abandon");
        let a = ab2_alertes(&db.lock(), "heartbeat.flotte-hotes-muets");
        assert_eq!((a.len(), a[0].0.as_str()), (1, "new"), "contrôle : l'épisode est resté ouvert");
        assert!(a[0].1.is_some(), "contrôle : sa clé est tenue");
        db.lock().execute_batch(AB2_SANS_REFUS).unwrap();
        assert_eq!(check_heartbeats(&db), Mesure::Lue(0), "tick sans panne : aucun abandon");
        assert_eq!(ab2_alertes(&db.lock(), "heartbeat.flotte-hotes-muets"), vec![("resolved".into(), None)]);
    }

    /// Ensemble CHANGÉ : la résolution de l'épisode précédent est refusée, le nouvel épisode s'écrit -> `Lue(1)`.
    #[test]
    fn ab2_flotte_ensemble_change_resolution_refusee_nouvel_episode_ecrit() {
        let db = ab2_flotte_ouverte();
        ab2_hote(&db, "hote-ab2-second", now() - 7200);
        db.lock().execute_batch(AB2_REFUS_UPDATE).unwrap();
        assert_eq!(check_heartbeats(&db), Mesure::Lue(1), "épisode précédent non résolu : UN abandon, même si le neuf s'écrit");
        let a = ab2_alertes(&db.lock(), "heartbeat.flotte-hotes-muets");
        assert_eq!(a.len(), 2, "contrôle : le nouvel épisode est écrit");
        assert!(a.iter().all(|(s, _)| s == "new"), "contrôle : l'ancien est resté ouvert : {a:?}");
        db.lock().execute_batch(AB2_SANS_REFUS).unwrap();
        assert_eq!(check_heartbeats(&db), Mesure::Lue(0), "tick sans panne");
        let a = ab2_alertes(&db.lock(), "heartbeat.flotte-hotes-muets");
        assert_eq!(a[0], ("resolved".into(), None), "l'ancien est résolu au tick sans panne");
        assert_eq!(a[1].0, "new");
    }

    /// Ensemble CHANGÉ, résolution ET nouvel épisode refusés : deux alertes, deux abandons.
    #[test]
    fn ab2_flotte_resolution_et_nouvel_episode_refuses_deux_abandons() {
        let db = ab2_flotte_ouverte();
        ab2_hote(&db, "hote-ab2-second", now() - 7200);
        db.lock().execute_batch(AB2_REFUS_UPDATE).unwrap();
        db.lock().execute_batch(AB2_REFUS_INSERT).unwrap();
        assert_eq!(check_heartbeats(&db), Mesure::Lue(2), "deux alertes distinctes refusées : deux abandons");
        assert_eq!(ab2_alertes(&db.lock(), "heartbeat.flotte-hotes-muets").len(), 1, "contrôle : rien d'écrit");
    }

    /// Base en LECTURE SEULE, rien d'ouvert : chaque résolution (23 capteurs + flotte) est refusée -> un abandon chacune.
    #[test]
    fn ab2_base_en_lecture_seule_chaque_resolution_refusee_comptee() {
        let db = Arc::new(Mutex::new(test_db()));
        assert_eq!(check_heartbeats(&db), Mesure::Lue(0), "contrôle : base vide, rien d'ouvert, aucun abandon");
        db.lock().execute_batch("PRAGMA query_only=1").unwrap();
        let attendu = u32::try_from(COLLECTORS.len()).unwrap() + 1;
        assert_eq!(check_heartbeats(&db), Mesure::Lue(attendu), "lecture seule : un abandon par résolution refusée, jamais agrégé");
        db.lock().execute_batch("PRAGMA query_only=0").unwrap();
        assert_eq!(check_heartbeats(&db), Mesure::Lue(0), "contre-épreuve : base de nouveau inscriptible");
        assert_eq!(ab2_n(&db.lock(), "SELECT COUNT(*) FROM alert"), 0, "contrôle : aucune alerte");
    }

    // ------------------------------------------------------------------ magasin de secrets

    #[test]
    fn ab2_magasin_resolution_refusee_comptee_alerte_ouverte_puis_resolue() {
        let conn = ab2_magasin_ouvert();
        ab2_releve(&conn, AB2_NOW + 300, 0.0, 3.0);
        conn.execute_batch(AB2_REFUS_UPDATE).unwrap();
        assert_eq!(verifier_le_magasin_de_secrets(&conn, AB2_NOW + 300), Mesure::Lue(1), "résolution refusée : UN abandon");
        let (s, d, _) = ab2_magasin(&conn);
        assert_eq!((s.as_str(), d.as_deref()), ("new", Some(DEDUP_MAGASIN)), "contrôle : ouverte, clé tenue");
        conn.execute_batch(AB2_SANS_REFUS).unwrap();
        assert_eq!(verifier_le_magasin_de_secrets(&conn, AB2_NOW + 300), Mesure::Lue(0), "sans panne : aucun abandon");
        let (s, d, _) = ab2_magasin(&conn);
        assert_eq!((s.as_str(), d), ("resolved", None), "résolue, clé libérée");
    }

    #[test]
    fn ab2_magasin_rafraichissement_refuse_compte() {
        let conn = ab2_magasin_ouvert();
        conn.execute_batch(AB2_REFUS_UPDATE).unwrap();
        assert_eq!(verifier_le_magasin_de_secrets(&conn, AB2_NOW + 300), Mesure::Lue(1), "texte non rafraîchi : UN abandon");
        assert_eq!(ab2_magasin(&conn).2, AB2_NOW, "contrôle : l'horodatage est celui d'avant");
        conn.execute_batch(AB2_SANS_REFUS).unwrap();
        assert_eq!(verifier_le_magasin_de_secrets(&conn, AB2_NOW + 300), Mesure::Lue(0), "sans panne : aucun abandon");
        assert_eq!(ab2_magasin(&conn).2, AB2_NOW + 300, "contre-épreuve : rafraîchi");
    }

    #[test]
    fn ab2_magasin_insert_et_rafraichissement_refuses_un_seul_abandon() {
        let conn = ab2_magasin_ouvert();
        conn.execute_batch(AB2_REFUS_INSERT).unwrap();
        conn.execute_batch(AB2_REFUS_UPDATE).unwrap();
        assert_eq!(verifier_le_magasin_de_secrets(&conn, AB2_NOW + 300), Mesure::Lue(1), "une alerte, deux refus : un abandon");
    }

    // ------------------------------------------------------------------ alerte de cécité

    /// Le rafraîchissement refusé ne change pas `alerte_posee` (l'alerte est ouverte) ni le texte d'avant.
    #[test]
    fn ab2_cecite_rafraichissement_refuse_alerte_toujours_posee() {
        let conn = test_db();
        conn.execute(
            "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) VALUES('ab2-aveugle',1,'SELECT 1',0,'>',1,3,?1,3600)",
            params![AB2_INTERVALLE_S],
        )
        .unwrap();
        let id = conn.last_insert_rowid();
        let seuil = i64::from(seuil_d_abandons_consecutifs(AB2_INTERVALLE_S));
        conn.execute("UPDATE rule SET abandons_consecutifs=?1 WHERE id=?2", params![seuil - 1, id]).unwrap();
        let abandon = AbandonDEvaluation::compilation_refusee("x");
        assert!(consigner_abandon(&conn, id, "ab2-aveugle", 3, now(), &abandon).unwrap().alerte_posee, "contrôle : posée");
        let titre_avant: String =
            conn.query_row("SELECT title FROM alert WHERE dedup=?1", params![cle_dedup(id)], |r| r.get(0)).unwrap();
        conn.execute_batch(AB2_REFUS_UPDATE).unwrap();
        let r = consigner_abandon(&conn, id, "ab2-aveugle", 3, now(), &abandon).unwrap();
        assert!(r.alerte_posee, "rafraîchissement refusé : l'alerte de cécité reste ouverte, posée");
        assert_eq!(i64::from(r.consecutifs), seuil + 1, "contrôle : le compte a avancé");
        let titre: String =
            conn.query_row("SELECT title FROM alert WHERE dedup=?1", params![cle_dedup(id)], |r| r.get(0)).unwrap();
        assert_eq!(titre, titre_avant, "contrôle : le texte est celui d'avant");
    }

    /// AU TICK (`run_due_rules`) : la règle abandonnée dont le rafraîchissement de l'alerte de cécité est refusé compte
    /// UN abandon — ni deux (recompté), ni zéro ; l'alerte reste ouverte sous son texte et son horodatage d'avant.
    #[test]
    fn ab2_cecite_rafraichissement_refuse_un_abandon_au_tick() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("ab2-cecite-tick");
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        let id = {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn));
            conn.execute("DELETE FROM rule", []).unwrap();
            conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) \
                 VALUES('ab2-cecite-tick',1,'search | stats count by | where',1,'>',0,2,?1,3600)",
                params![AB2_INTERVALLE_S],
            )
            .unwrap();
            conn.last_insert_rowid()
        };
        let seuil = i64::from(seuil_d_abandons_consecutifs(AB2_INTERVALLE_S));
        db.lock().execute("UPDATE rule SET abandons_consecutifs=?1 WHERE id=?2", params![seuil - 1, id]).unwrap();
        assert_eq!(run_due_rules(&db, &p), Mesure::Lue(1), "contrôle : une règle abandonnée, l'alerte de cécité posée");
        let ouverte = |conn: &Connection| -> (String, i64) {
            conn.query_row(
                "SELECT title, ts FROM alert WHERE dedup=?1 AND status IN ('new','ack')",
                params![cle_dedup(id)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
        };
        // L'alerte vieillie, la règle de nouveau due, et tout UPDATE d'alerte refusé.
        db.lock().execute("UPDATE alert SET ts=ts-1000 WHERE dedup=?1", params![cle_dedup(id)]).unwrap();
        let avant = ouverte(&db.lock());
        db.lock().execute("UPDATE rule SET last_run=NULL WHERE id=?1", params![id]).unwrap();
        db.lock().execute_batch(AB2_REFUS_UPDATE).unwrap();
        assert_eq!(run_due_rules(&db, &p), Mesure::Lue(1), "rafraîchissement refusé : la règle compte UN abandon, pas deux");
        assert_eq!(ouverte(&db.lock()), avant, "contrôle : l'alerte reste ouverte sous son texte et son horodatage d'avant");
        let n: i64 = db.lock().query_row("SELECT abandons_consecutifs FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        assert_eq!(n, seuil + 1, "contrôle : le compte consécutif a avancé");
        db.lock().execute_batch(AB2_SANS_REFUS).unwrap();
        db.lock().execute("UPDATE rule SET last_run=NULL WHERE id=?1", params![id]).unwrap();
        assert_eq!(run_due_rules(&db, &p), Mesure::Lue(1), "contre-épreuve sans panne : toujours UN abandon");
        assert!(ouverte(&db.lock()).1 > avant.1, "contre-épreuve : l'horodatage est rafraîchi");
    }

    // ------------------------------------------------------------------ journal

    /// Les LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus : une ligne par refus, qui nomme le sujet et porte
    /// la cause du moteur — jamais un nom d'hôte, un nom de règle ni le détail d'une alerte ; aucune au nominal.
    #[test]
    fn ab2_lignes_de_journal_sujet_et_cause_sans_hote_ni_detail() {
        const ENFANT: &str = "AB2_ENFANT_JOURNAL";
        const PHASE: &str = "AB2-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            eprintln!("{PHASE}capteur-resolution");
            let db = ab2_capteur_muet_ouvert();
            ab2_capteur_reparle(&db);
            db.lock().execute_batch(AB2_REFUS_UPDATE).unwrap();
            println!("AB2-BILAN-CAPTEUR-RESOLUTION:{:?}", check_heartbeats(&db));
            eprintln!("{PHASE}capteur-imputation");
            let db = ab2_capteur_muet_ouvert();
            db.lock().execute_batch(AB2_REFUS_SOURCES).unwrap();
            println!("AB2-BILAN-CAPTEUR-IMPUTATION:{:?}", check_heartbeats(&db));
            eprintln!("{PHASE}capteur-double");
            let db = ab2_capteur_muet_ouvert();
            db.lock().execute_batch(AB2_REFUS_INSERT).unwrap();
            db.lock().execute_batch(AB2_REFUS_SOURCES).unwrap();
            println!("AB2-BILAN-CAPTEUR-DOUBLE:{:?}", check_heartbeats(&db));
            eprintln!("{PHASE}flotte-resolution");
            let db = ab2_flotte_ouverte();
            ab2_hote(&db, "hote-ab2-muet", now() - 60);
            db.lock().execute_batch(AB2_REFUS_UPDATE).unwrap();
            println!("AB2-BILAN-FLOTTE-RESOLUTION:{:?}", check_heartbeats(&db));
            eprintln!("{PHASE}flotte-ensemble-change");
            let db = ab2_flotte_ouverte();
            ab2_hote(&db, "hote-ab2-second", now() - 7200);
            db.lock().execute_batch(AB2_REFUS_UPDATE).unwrap();
            println!("AB2-BILAN-FLOTTE-ENSEMBLE-CHANGE:{:?}", check_heartbeats(&db));
            eprintln!("{PHASE}lecture-seule");
            let db = Arc::new(Mutex::new(test_db()));
            db.lock().execute_batch("PRAGMA query_only=1").unwrap();
            println!("AB2-BILAN-LECTURE-SEULE:{:?}", check_heartbeats(&db));
            eprintln!("{PHASE}magasin-resolution");
            let conn = ab2_magasin_ouvert();
            ab2_releve(&conn, AB2_NOW + 300, 0.0, 3.0);
            conn.execute_batch(AB2_REFUS_UPDATE).unwrap();
            println!("AB2-BILAN-MAGASIN-RESOLUTION:{:?}", verifier_le_magasin_de_secrets(&conn, AB2_NOW + 300));
            eprintln!("{PHASE}magasin-rafraichissement");
            let conn = ab2_magasin_ouvert();
            conn.execute_batch(AB2_REFUS_UPDATE).unwrap();
            println!("AB2-BILAN-MAGASIN-RAFRAICHISSEMENT:{:?}", verifier_le_magasin_de_secrets(&conn, AB2_NOW + 300));
            eprintln!("{PHASE}cecite");
            let conn = test_db();
            conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) VALUES('ab2-aveugle',1,'SELECT 1',0,'>',1,3,?1,3600)",
                params![AB2_INTERVALLE_S],
            )
            .unwrap();
            let id = conn.last_insert_rowid();
            let seuil = i64::from(seuil_d_abandons_consecutifs(AB2_INTERVALLE_S));
            conn.execute("UPDATE rule SET abandons_consecutifs=?1 WHERE id=?2", params![seuil - 1, id]).unwrap();
            let abandon = AbandonDEvaluation::compilation_refusee("x");
            let _premier = consigner_abandon(&conn, id, "ab2-aveugle", 3, now(), &abandon);
            conn.execute_batch(AB2_REFUS_UPDATE).unwrap();
            println!("AB2-CECITE-ID:{id}");
            println!("AB2-BILAN-CECITE:{:?}", consigner_abandon(&conn, id, "ab2-aveugle", 3, now(), &abandon).map(|r| r.alerte_posee));
            eprintln!("{PHASE}nominal");
            let db = ab2_capteur_muet_ouvert();
            ab2_capteur_reparle(&db);
            println!("AB2-BILAN-NOMINAL-CAPTEUR:{:?}", check_heartbeats(&db));
            let db = ab2_flotte_ouverte();
            ab2_hote(&db, "hote-ab2-muet", now() - 60);
            println!("AB2-BILAN-NOMINAL-FLOTTE:{:?}", check_heartbeats(&db));
            let conn = ab2_magasin_ouvert();
            println!("AB2-BILAN-NOMINAL-MAGASIN:{:?}", verifier_le_magasin_de_secrets(&conn, AB2_NOW + 300));
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::resolutions_et_imputations_de_sante_comptees::ab2_lignes_de_journal_sujet_et_cause_sans_hote_ni_detail",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        for (marque, attendu) in [
            ("AB2-BILAN-CAPTEUR-RESOLUTION:", "Lue(1)"),
            ("AB2-BILAN-CAPTEUR-IMPUTATION:", "Lue(1)"),
            ("AB2-BILAN-CAPTEUR-DOUBLE:", "Lue(1)"),
            ("AB2-BILAN-FLOTTE-RESOLUTION:", "Lue(1)"),
            ("AB2-BILAN-FLOTTE-ENSEMBLE-CHANGE:", "Lue(1)"),
            ("AB2-BILAN-LECTURE-SEULE:", format!("Lue({})", COLLECTORS.len() + 1).as_str()),
            ("AB2-BILAN-MAGASIN-RESOLUTION:", "Lue(1)"),
            ("AB2-BILAN-MAGASIN-RAFRAICHISSEMENT:", "Lue(1)"),
            ("AB2-BILAN-CECITE:", "Some(true)"),
            ("AB2-BILAN-NOMINAL-CAPTEUR:", "Lue(0)"),
            ("AB2-BILAN-NOMINAL-FLOTTE:", "Lue(0)"),
            ("AB2-BILAN-NOMINAL-MAGASIN:", "Lue(0)"),
        ] {
            assert!(stdout.contains(&format!("{marque}{attendu}")), "contrôle : bilan {marque}{attendu} : {stdout}");
        }
        let id_cecite: String = stdout
            .lines()
            .find_map(|l| l.strip_prefix("AB2-CECITE-ID:"))
            .expect("contrôle : identifiant de la règle")
            .to_string();
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[plume]") || l.starts_with("[detection]")).map(str::to_string).collect()
        };
        // Les lignes d'AVEU (refus) d'une phase ; les autres lignes du journal ne sont jugées que sur ce qu'elles taisent.
        let refus = |nom: &str| -> Vec<String> {
            phase(nom)
                .into_iter()
                .filter(|l| ["NON ÉCRITE", "NON RÉSOLU", "NON RAFRAÎCHI", "n'a pas pu être rafraîchi"].iter().any(|m| l.contains(m)))
                .collect()
        };
        let debut_cecite = format!("[detection] WARN règle #{id_cecite} : le texte de son alerte de cécité n'a pas pu être rafraîchi");
        for (nom, debut) in [
            ("capteur-resolution", "[plume] battement de cœur : 1 alerte(s) « capteur muet » NON RÉSOLUE(S) ce tick (première cause : "),
            ("capteur-imputation", "[plume] battement de cœur : imputation de l'alerte « capteur muet » du capteur firewall NON RAFRAÎCHIE"),
            ("flotte-resolution", "[plume] battement de cœur : épisode « flotte muette » précédent NON RÉSOLU"),
            ("flotte-ensemble-change", "[plume] battement de cœur : épisode « flotte muette » précédent NON RÉSOLU"),
            ("magasin-resolution", "[plume] magasin de secrets : alerte NON RÉSOLUE"),
            ("magasin-rafraichissement", "[plume] magasin de secrets : texte de l'alerte NON RAFRAÎCHI"),
            ("cecite", debut_cecite.as_str()),
        ] {
            let lignes = refus(nom);
            assert_eq!(lignes.len(), 1, "phase {nom} : une ligne et une seule pour le refus : {lignes:?}");
            assert!(lignes[0].starts_with(debut), "phase {nom} : le sujet nommé : {}", lignes[0]);
            assert!(lignes[0].contains(AB2_CAUSE), "phase {nom} : la cause du moteur : {}", lignes[0]);
        }
        // Base en lecture seule : 23 résolutions de capteur refusées = UNE ligne agrégée (nombre + première cause), puis
        // la ligne de la flotte ; jamais une ligne par capteur.
        let lecture_seule = refus("lecture-seule");
        assert_eq!(lecture_seule.len(), 2, "lecture-seule : une ligne agrégée pour les capteurs, une pour la flotte : {lecture_seule:?}");
        let debut_agrege = format!("[plume] battement de cœur : {} alerte(s) « capteur muet » NON RÉSOLUE(S) ce tick (première cause : ", COLLECTORS.len());
        assert!(lecture_seule[0].starts_with(&debut_agrege), "lecture-seule : nombre et sujet : {}", lecture_seule[0]);
        assert!(lecture_seule[0].contains("readonly"), "lecture-seule : la cause du moteur : {}", lecture_seule[0]);
        assert!(lecture_seule[1].starts_with("[plume] battement de cœur : épisode « flotte muette » précédent NON RÉSOLU"), "{lecture_seule:?}");
        assert!(phase("lecture-seule").iter().all(|l| !l.contains("du capteur")), "lecture-seule : aucun capteur nommé : {:?}", phase("lecture-seule"));
        // Le double refus d'une même alerte : les DEUX écritures sont refusées (deux lignes), le compte reste UN (bilan).
        let double = refus("capteur-double");
        assert_eq!(double.len(), 2, "capteur-double : l'INSERT ET l'imputation refusés, chacun dit : {double:?}");
        assert!(double[0].contains("NON ÉCRITE") && double[0].contains("insertion refusee par le temoin ab2"), "{double:?}");
        assert!(double[1].contains("NON RAFRAÎCHIE") && double[1].contains(AB2_CAUSE), "{double:?}");
        for nom in [
            "capteur-resolution",
            "capteur-imputation",
            "capteur-double",
            "flotte-resolution",
            "flotte-ensemble-change",
            "lecture-seule",
            "magasin-resolution",
            "magasin-rafraichissement",
            "cecite",
        ] {
            for l in phase(nom) {
                for interdit in [
                    "hote-ab2",
                    "ab2-aveugle",
                    "aucune donnée depuis",
                    "machines en retard",
                    "Hôtes muets",
                    "rotation des clés",
                    "magasin(s) de secrets",
                    "fois de suite",
                    "Dernière cause",
                ] {
                    assert!(!l.contains(interdit), "phase {nom} : ni hôte, ni règle, ni détail ({interdit}) : {l}");
                }
            }
        }
        assert!(refus("nominal").is_empty(), "chemin nominal sans aveu : {:?}", phase("nominal"));
    }
}
