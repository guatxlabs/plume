// =====================================================================================
// `P10.20-w` (queue des écritures non scrutées) — LA MARQUE D'ENVOI EST ÉCRITE, OU L'ÉCHEC SE COMPTE.
//
// VU (re-mesuré au commit de départ) : deux sorties posaient leur marque d'envoi en `let _ =` APRÈS un
// envoi réussi — le filigrane d'une destination (`forward_one_destination`) et le marqueur `notified`
// d'une alerte (`dispatch_notifications`). Refusée, la marque ne bougeait pas : le MÊME lot repartait
// vers le puits externe à chaque tick (bilan `Lue(0)`), les mêmes vingt alertes repartaient à chaque
// tour, sans aucun aveu.
//
// CE QUE CES TÉMOINS JOUENT : un déclencheur `RAISE(ABORT)` sur la colonne de la marque, un transport
// simulé (aucun réseau) ou un canal `lookup` (aucun réseau), et la contre-épreuve nominale.
// =====================================================================================
mod marques_d_envoi_ecrites_ou_avouees {
    use super::*;
    use crate::handlers::destinations::{forward_one_destination, Wire};
    use crate::handlers::notifiers::dispatch_notifications;
    use crate::mesure_environnement::Mesure;

    fn mew_base_destination() -> (Arc<Mutex<Connection>>, i64) {
        let conn = test_db();
        for i in 0..3 {
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,message,src_ip) VALUES(?1,'p1020w','auth',3,?2,'192.0.2.10')",
                params![now(), format!("m{i}")],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO destination(id,type,name,enabled,endpoint,watermark) VALUES(7,'webhook','D',1,'https://198.51.100.20/in',0)",
            [],
        )
        .unwrap();
        let max_id: i64 = conn.query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap();
        (Arc::new(Mutex::new(conn)), max_id)
    }

    fn mew_filigrane(db: &Arc<Mutex<Connection>>) -> i64 {
        db.lock().query_row("SELECT watermark FROM destination WHERE id=7", [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn p10_20w_filigrane_refuse_apres_envoi_reussi_compte_un_abandon() {
        let (db, _) = mew_base_destination();
        db.lock()
            .execute_batch(
                "CREATE TRIGGER mew_refus BEFORE UPDATE OF watermark ON destination \
                 BEGIN SELECT RAISE(ABORT,'filigrane refuse par le temoin'); END;",
            )
            .unwrap();
        let envois = std::cell::Cell::new(0u32);
        let ok_tx = |_w: &Wire| { envois.set(envois.get() + 1); Ok::<u16, String>(200) };
        let b = forward_one_destination(&db, 7, "webhook", "https://198.51.100.20/in", "{}", "{}", 500, 0, now(), &ok_tx);
        assert_eq!(envois.get(), 1, "le lot est bien parti vers le puits");
        assert_eq!(b, Mesure::Lue(1), "filigrane refusé après envoi : la destination compte UN abandon");
        assert_eq!(mew_filigrane(&db), 0, "le filigrane n'a pas bougé");
    }

    #[test]
    fn p10_20w_filigrane_sans_effet_compte_un_abandon() {
        // Écriture qui réussit sans toucher de ligne (ici : la destination n'existe pas) — même verdict.
        let (db, _) = mew_base_destination();
        let ok_tx = |_w: &Wire| Ok::<u16, String>(200);
        let b = forward_one_destination(&db, 99, "webhook", "https://198.51.100.20/in", "{}", "{}", 500, 0, now(), &ok_tx);
        assert_eq!(b, Mesure::Lue(1), "zéro ligne écrite n'est pas un filigrane avancé");
    }

    #[test]
    fn p10_20w_filigrane_nominal_avance_sans_abandon() {
        let (db, max_id) = mew_base_destination();
        let ok_tx = |_w: &Wire| Ok::<u16, String>(200);
        let b = forward_one_destination(&db, 7, "webhook", "https://198.51.100.20/in", "{}", "{}", 500, 0, now(), &ok_tx);
        assert_eq!(b, Mesure::Lue(0), "chemin nominal : aucun abandon");
        assert_eq!(mew_filigrane(&db), max_id, "le filigrane avance au dernier événement transmis");
    }

    fn mew_base_notifications() -> Arc<Mutex<Connection>> {
        let conn = test_db();
        conn.execute_batch("DELETE FROM alert; DELETE FROM notifier; DELETE FROM lookup_kv WHERE name='mew_s8';").unwrap();
        let t = now();
        for i in 0..3i64 {
            conn.execute(
                "INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources,host) VALUES(?1,'r.mew',3,'A','','new','','',?2)",
                params![t + i, format!("192.0.2.{}", 30 + i)],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('L','lookup',1,'',0,'{\"lookup\":\"mew_s8\",\"key_field\":\"host\"}')",
            [],
        )
        .unwrap();
        Arc::new(Mutex::new(conn))
    }

    fn mew_traitees(db: &Arc<Mutex<Connection>>) -> i64 {
        db.lock().query_row("SELECT COUNT(*) FROM lookup_kv WHERE name='mew_s8'", [], |r| r.get(0)).unwrap()
    }

    /// Refus (`RAISE(ABORT)`) PUIS écriture sans effet (`RAISE(IGNORE)`, `Ok(0)`) enchaînés dans UN SEUL test : le
    /// compte `dispatch_marqueur` est une statique de processus, deux tests parallèles qui assertent chacun `avant+N`
    /// se marcheraient dessus. Aucun autre test ne compte sous ce nom dans ce processus (les témoins `aw6_` le font dans
    /// un sous-processus).
    ///
    /// INVERSÉ par `P10.33-h` (vague AW) : ce témoin affirmait « au premier marqueur refusé, le tour s'arrête : UNE seule
    /// alerte traitée » — l'alerte était envoyée AVANT son marqueur, puis renvoyée à chaque tour. Le marqueur est
    /// désormais écrit avant tout envoi : refusé, RIEN ne part pour l'alerte, le refus est compté pour CHACUNE, et les
    /// suivantes sont tentées (ici toutes refusées par le même déclencheur).
    #[test]
    fn p10_20w_marqueur_refuse_ou_sans_effet_rien_ne_part_et_chaque_alerte_est_comptee() {
        let db = mew_base_notifications();
        db.lock()
            .execute_batch(
                "CREATE TRIGGER mew_refus_notif BEFORE UPDATE OF notified ON alert \
                 BEGIN SELECT RAISE(ABORT,'marqueur refuse par le temoin'); END;",
            )
            .unwrap();
        let avant = crate::metrics::tick_aveugle_de("dispatch_marqueur").map(|(n, _)| n).unwrap_or(0);
        dispatch_notifications(&db);
        assert_eq!(mew_traitees(&db), 0, "marqueur refusé : rien n'est envoyé, pour aucune des trois alertes");
        let (n, cause) = crate::metrics::tick_aveugle_de("dispatch_marqueur").expect("le refus est compté sous son nom");
        assert_eq!(n, avant + 3, "un compte par alerte dont le marqueur est refusé, les trois sont tentées");
        assert!(cause.contains("marqueur refuse par le temoin"), "la cause est celle du moteur : {cause}");

        // Second cas : l'UPDATE réussit sans toucher de ligne. Si `Ok(0)` valait nominal, les trois alertes partiraient.
        db.lock()
            .execute_batch(
                "DROP TRIGGER mew_refus_notif; CREATE TRIGGER mew_muet_notif BEFORE UPDATE OF notified ON alert \
                 BEGIN SELECT RAISE(IGNORE); END;",
            )
            .unwrap();
        dispatch_notifications(&db);
        assert_eq!(mew_traitees(&db), 0, "marqueur sans effet : rien n'est envoyé non plus");
        let (n2, cause2) = crate::metrics::tick_aveugle_de("dispatch_marqueur").expect("compté sous son nom");
        assert_eq!(n2, avant + 6, "les marqueurs sans effet sont comptés eux aussi, un par alerte");
        assert!(cause2.contains("0 ligne(s)"), "la cause dit zéro ligne écrite : {cause2}");
        let non_marquees: i64 =
            db.lock().query_row("SELECT COUNT(*) FROM alert WHERE rule='r.mew' AND notified=0", [], |r| r.get(0)).unwrap();
        assert_eq!(non_marquees, 3, "contrôle : aucun marqueur n'a été posé");
    }

    /// La LIGNE DE JOURNAL, lue sur le stderr d'un sous-processus : filigrane refusé -> identifiant + cause du moteur,
    /// ni l'endpoint (qui peut porter une crédence) ni un événement ; zéro ligne -> identifiant + « 0 ligne(s) » ;
    /// chemin nominal muet. Marqueur refusé -> une ligne par alerte, « rien n'est envoyé pour elle » (INVERSÉ par
    /// `P10.33-h`, vague AW : la ligne disait « traitée (envoyée ou silencée) », le marqueur précédant désormais l'envoi).
    #[test]
    fn p10_20w_ligne_de_journal_cause_et_identifiant_sans_endpoint() {
        const ENFANT: &str = "MEW_S8_ENFANT_JOURNAL";
        const PHASE: &str = "MEW-S8-PHASE:";
        const ENDPOINT: &str = "https://mew:credence-s8@198.51.100.20/in";
        if std::env::var(ENFANT).is_ok() {
            let ok_tx = |_w: &Wire| Ok::<u16, String>(200);
            eprintln!("{PHASE}refus");
            let (db, _) = mew_base_destination();
            db.lock()
                .execute_batch(
                    "CREATE TRIGGER mew_refus BEFORE UPDATE OF watermark ON destination \
                     BEGIN SELECT RAISE(ABORT,'filigrane refuse par le temoin'); END;",
                )
                .unwrap();
            println!("MEW-BILAN-REFUS:{:?}", forward_one_destination(&db, 7, "webhook", ENDPOINT, "{}", "{}", 500, 0, now(), &ok_tx));
            eprintln!("{PHASE}muet");
            let (db, _) = mew_base_destination();
            println!("MEW-BILAN-MUET:{:?}", forward_one_destination(&db, 99, "webhook", ENDPOINT, "{}", "{}", 500, 0, now(), &ok_tx));
            eprintln!("{PHASE}nominal");
            let (db, _) = mew_base_destination();
            println!("MEW-BILAN-NOMINAL:{:?}", forward_one_destination(&db, 7, "webhook", ENDPOINT, "{}", "{}", 500, 0, now(), &ok_tx));
            eprintln!("{PHASE}marqueur");
            let db = mew_base_notifications();
            db.lock()
                .execute_batch(
                    "CREATE TRIGGER mew_refus_notif BEFORE UPDATE OF notified ON alert \
                     BEGIN SELECT RAISE(ABORT,'marqueur refuse par le temoin'); END;",
                )
                .unwrap();
            dispatch_notifications(&db);
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::marques_d_envoi_ecrites_ou_avouees::p10_20w_ligne_de_journal_cause_et_identifiant_sans_endpoint",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[plume]")).map(str::to_string).collect()
        };
        for (marque, attendu) in [("MEW-BILAN-REFUS:", "Lue(1)"), ("MEW-BILAN-MUET:", "Lue(1)"), ("MEW-BILAN-NOMINAL:", "Lue(0)")] {
            assert!(stdout.contains(&format!("{marque}{attendu}")), "contrôle : bilan {marque}{attendu} : {stdout}");
        }
        let refus = phase("refus");
        assert_eq!(refus.len(), 1, "une ligne et une seule pour le filigrane refusé : {refus:?}");
        let l = &refus[0];
        assert!(l.starts_with("[plume] destination 7 :"), "l'identifiant de la destination : {l}");
        assert!(l.contains("filigrane NON ÉCRIT"), "le geste nommé : {l}");
        assert!(l.contains("filigrane refuse par le temoin"), "la cause du moteur : {l}");
        let muet = phase("muet");
        assert_eq!(muet.len(), 1, "une ligne et une seule pour zéro ligne écrite : {muet:?}");
        assert!(muet[0].starts_with("[plume] destination 99 :") && muet[0].contains("0 ligne(s)"), "identifiant et zéro ligne : {}", muet[0]);
        for l in refus.iter().chain(&muet) {
            assert!(!l.contains("198.51.100.20") && !l.contains("credence-s8"), "jamais l'endpoint (ni sa crédence) : {l}");
            assert!(!l.contains("p1020w") && !l.contains("192.0.2.10"), "jamais un événement : {l}");
        }
        assert!(phase("nominal").is_empty(), "chemin nominal muet : {:?}", phase("nominal"));
        let marqueur = phase("marqueur");
        let dispatch: Vec<&String> = marqueur.iter().filter(|l| l.starts_with("[plume] dispatch :")).collect();
        assert_eq!(dispatch.len(), 3, "une ligne par alerte dont le marqueur est refusé : {marqueur:?}");
        for l in &dispatch {
            assert!(l.contains("marqueur `notified` NON ÉCRIT, rien n'est envoyé pour elle ce tour-ci"), "rien n'est parti : {l}");
            assert!(!l.contains("traitée (envoyée ou silencée)"), "l'ancienne phrase ne revient pas : {l}");
        }
    }

    #[test]
    fn p10_20w_marqueur_nominal_traite_les_trois_alertes() {
        let db = mew_base_notifications();
        dispatch_notifications(&db);
        assert_eq!(mew_traitees(&db), 3, "nominal : les trois alertes sont traitées");
        let marquees: i64 = db.lock().query_row("SELECT COUNT(*) FROM alert WHERE rule='r.mew' AND notified=1", [], |r| r.get(0)).unwrap();
        assert_eq!(marquees, 3, "nominal : les trois marqueurs sont écrits");
    }
}
