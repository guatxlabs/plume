// =====================================================================================
// `P10.33-h` (restes) — UN ENVOI REFUSÉ N'EST PAS UN SUCCÈS, UN FILIGRANE REFUSÉ NE LAISSE PAS LA DESTINATION DUE
// EN SILENCE.
//
// VU (re-mesuré au commit de départ 7c167699) :
// (a) `deliver_report` écrivait `last_ok`, `last_count` et `last_error = NULL` APRÈS l'envoi sans regarder ce
//     que l'envoi rendait : un notificateur qui refuse (`false`) laissait un « dernier succès » et effaçait
//     l'erreur précédente ;
// (b) `forward_one_destination`, filigrane refusé après un envoi réussi : journal + `Lue(1)`, mais l'UNIQUE
//     UPDATE refusé portait aussi `last_run` et `last_error` — la destination restait due à chaque tick (le même
//     lot repartait) sans rien dire à la console.
//
// CE QUE CES TÉMOINS JOUENT : le point d'entrée du tick des rapports (`run_due_reports`) et `deliver_report`,
// un notificateur intercepté sur le fil courant (`temoin_d_envoi`, aucun réseau) ; `forward_one_destination` avec
// un transport simulé (aucun réseau) et un `now_ts` FIXE (aucune horloge) ; des déclencheurs `RAISE(ABORT)` ; la
// ligne de journal lue sur le stderr d'un sous-processus.
// CE QU'ILS NE TIENNENT PAS : la période du tick du planificateur ; une politique de relivraison (hors lot).
// =====================================================================================
mod envoi_refuse_et_filigrane_refuse_avoues {
    use super::*;
    use crate::handlers::destinations::{forward_one_destination, Wire, FILIGRANE_NON_ECRIT_APRES_ENVOI};
    use crate::handlers::scheduled_reports::{
        deliver_report, run_due_reports, temoin_d_envoi, IssueDuRapport, ENVOI_REFUSE_PAR_LE_NOTIFICATEUR,
    };
    use crate::mesure_environnement::Mesure;

    const ERF_HOTE_NOTIFICATEUR: &str = "198.51.100.41";
    const ERF_URL: &str = "https://erf:credence-v6@198.51.100.41/hook";
    const ERF_ENDPOINT: &str = "https://erf:credence-v6@198.51.100.42/in";
    const ERF_NOW: i64 = 1_700_000_000;

    /// Base sur disque (le rendu passe par le pool de lecture du chemin) : un événement, un dataset, un notificateur
    /// d'un genre inconnu, un rapport dû. Un succès ANCIEN est posé (`last_ok`, `last_count`) : un envoi refusé ne
    /// doit pas le remplacer.
    fn erf_rapport(tag: &str) -> (crate::tmp_possede::TmpDb, Arc<Mutex<Connection>>, i64) {
        let path = crate::tmp_possede::TmpDb::neuf(&format!("erf-{tag}"));
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        conn.execute(
            "INSERT INTO event(ts,source,category,severity,host,message,src_ip) VALUES(?1,'erf','auth',3,'h1','contenu erf','192.0.2.21')",
            params![now()],
        )
        .unwrap();
        conn.execute("INSERT INTO dataset(id,name,soql) VALUES(51,'erf-ds','search | table message')", []).unwrap();
        conn.execute(
            "INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) VALUES(52,'erf-n','temoin-v6',1,?1,0,'{}')",
            params![ERF_URL],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO scheduled_report(id,name,dataset_id,notifier_id,interval_s,last_ok,last_count) VALUES(53,'erf-rapport',51,52,3600,111,7)",
            [],
        )
        .unwrap();
        (path, Arc::new(Mutex::new(conn)), 53)
    }

    fn erf_etat(db: &Arc<Mutex<Connection>>, id: i64) -> (i64, i64, Option<String>, i64) {
        db.lock()
            .query_row("SELECT last_run,last_ok,last_error,last_count FROM scheduled_report WHERE id=?1", params![id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap()
    }

    #[test]
    fn p10_33h_envoi_refuse_ni_last_ok_ni_last_count_last_error_pose() {
        let (path, db, id) = erf_rapport("refuse");
        temoin_d_envoi::poser(|_k, _t, _d| false);
        let b = run_due_reports(&db, &path);
        temoin_d_envoi::retirer();
        assert_eq!(b, Mesure::Lue(0), "envoi refusé, statut écrit : pas un abandon");
        let (last_run, last_ok, last_error, last_count) = erf_etat(&db, id);
        assert!(last_run > 0, "la marque d'échéance est écrite : {last_run}");
        assert_eq!(last_ok, 111, "un envoi refusé n'écrit pas de « dernier succès »");
        assert_eq!(last_count, 7, "un envoi refusé ne remplace pas le compte du dernier succès");
        assert_eq!(last_error.as_deref(), Some(ENVOI_REFUSE_PAR_LE_NOTIFICATEUR), "l'erreur dit le refus, par sa constante");
        let e = last_error.unwrap_or_default();
        assert!(!e.contains(ERF_HOTE_NOTIFICATEUR) && !e.contains("credence-v6"), "jamais l'URL du notificateur : {e}");
        assert!(!e.contains("contenu erf"), "jamais le contenu : {e}");
    }

    #[test]
    fn p10_33h_envoi_refuse_issue_delivered_faux_statut_ecrit() {
        let (path, db, id) = erf_rapport("issue");
        temoin_d_envoi::poser(|_k, _t, _d| false);
        let issue = deliver_report(&db, &path, id);
        temoin_d_envoi::retirer();
        assert!(
            matches!(issue, Ok(IssueDuRapport::Envoye { count, delivered: false, statut_ecrit: true }) if count >= 1),
            "envoi refusé, aveu écrit : forme de l'issue inchangée, delivered faux, statut écrit : {issue:?}"
        );
    }

    #[test]
    fn p10_33h_envoi_reussi_inchange_efface_l_erreur() {
        let (path, db, id) = erf_rapport("reussi");
        db.lock().execute("UPDATE scheduled_report SET last_error='erreur ancienne v6' WHERE id=?1", params![id]).unwrap();
        temoin_d_envoi::poser(|_k, _t, _d| true);
        let b = run_due_reports(&db, &path);
        temoin_d_envoi::retirer();
        assert_eq!(b, Mesure::Lue(0));
        let (last_run, last_ok, last_error, last_count) = erf_etat(&db, id);
        assert!(last_run > 0 && last_ok == last_run, "succès : last_ok écrit : {last_run} {last_ok}");
        assert_eq!(last_error, None, "succès : l'erreur ancienne est effacée");
        assert!(last_count >= 1, "succès : le compte du rapport : {last_count}");
    }

    #[test]
    fn p10_33h_envoi_refuse_et_last_error_refuse_compte_un_abandon() {
        let (path, db, id) = erf_rapport("erreur-refusee");
        db.lock()
            .execute_batch(
                "CREATE TRIGGER erf_err BEFORE UPDATE OF last_error ON scheduled_report \
                 BEGIN SELECT RAISE(ABORT,'erreur refusee par le temoin v6'); END;",
            )
            .unwrap();
        temoin_d_envoi::poser(|_k, _t, _d| false);
        let b = run_due_reports(&db, &path);
        temoin_d_envoi::retirer();
        assert_eq!(b, Mesure::Lue(1), "envoi refusé dont l'aveu est refusé : compté");
        let (_, last_ok, _, last_count) = erf_etat(&db, id);
        assert_eq!((last_ok, last_count), (111, 7), "contrôle : le dernier succès n'a pas bougé");
    }

    /// Destination 8 : deux événements, filigrane à 0, un succès ANCIEN posé (`last_ok` = 111, `last_count` = 7) : la
    /// console affiche « ok <âge de last_ok> », un filigrane refusé ne doit pas le rajeunir.
    fn erf_destination() -> Arc<Mutex<Connection>> {
        let conn = test_db();
        for i in 0..2 {
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,message,src_ip) VALUES(?1,'erf-d','auth',3,?2,'192.0.2.22')",
                params![now(), format!("d{i}")],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO destination(id,type,name,enabled,endpoint,watermark,interval_s,last_ok,last_count) VALUES(8,'webhook','D',1,?1,0,30,111,7)",
            params![ERF_ENDPOINT],
        )
        .unwrap();
        Arc::new(Mutex::new(conn))
    }

    fn erf_dest_etat(db: &Arc<Mutex<Connection>>) -> (i64, Option<i64>, Option<String>, i64) {
        db.lock()
            .query_row("SELECT watermark,last_run,last_error,error_count FROM destination WHERE id=8", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap()
    }

    const ERF_REFUS_FILIGRANE: &str = "CREATE TRIGGER erf_filigrane BEFORE UPDATE OF watermark ON destination \
         BEGIN SELECT RAISE(ABORT,'filigrane refuse par le temoin v6'); END;";
    fn erf_dest_succes(db: &Arc<Mutex<Connection>>) -> (Option<i64>, i64) {
        db.lock().query_row("SELECT last_ok,last_count FROM destination WHERE id=8", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap()
    }

    /// Filigrane refusé SANS erreur : le premier UPDATE réussit et n'écrit rien (`Ok(0)`).
    const ERF_IGNORE_FILIGRANE: &str = "CREATE TRIGGER erf_ignore_filigrane BEFORE UPDATE OF watermark ON destination \
         BEGIN SELECT RAISE(IGNORE); END;";
    /// Tout UPDATE de la destination réussit et n'écrit rien : la seconde écriture rend `Ok(0)` elle aussi.
    const ERF_IGNORE_TOUT: &str = "CREATE TRIGGER erf_ignore_tout BEFORE UPDATE ON destination \
         BEGIN SELECT RAISE(IGNORE); END;";
    const ERF_REFUS_TOUT: &str = "CREATE TRIGGER erf_tout BEFORE UPDATE ON destination \
         BEGIN SELECT RAISE(ABORT,'tout refuse par le temoin v6'); END;";

    #[test]
    fn p10_33h_filigrane_refuse_pose_last_run_et_last_error() {
        let db = erf_destination();
        db.lock().execute_batch(ERF_REFUS_FILIGRANE).unwrap();
        let envois = std::cell::Cell::new(0u32);
        let ok_tx = |_w: &Wire| { envois.set(envois.get() + 1); Ok::<u16, String>(200) };
        let b = forward_one_destination(&db, 8, "webhook", ERF_ENDPOINT, "{}", "{}", 500, 0, ERF_NOW, &ok_tx);
        assert_eq!(envois.get(), 1, "contrôle : le lot est parti");
        assert_eq!(b, Mesure::Lue(1), "filigrane refusé : toujours compté");
        let (watermark, last_run, last_error, error_count) = erf_dest_etat(&db);
        assert_eq!(watermark, 0, "contrôle : le filigrane n'a pas bougé");
        assert_eq!(last_run, Some(ERF_NOW), "l'échéance est posée : la destination n'est plus due à chaque tick");
        assert_eq!(last_error.as_deref(), Some(FILIGRANE_NON_ECRIT_APRES_ENVOI), "la console lit l'aveu, par sa constante");
        assert_eq!(error_count, 1, "l'aveu se compte");
        assert_eq!(erf_dest_succes(&db), (Some(111), 7), "la seconde écriture ne rajeunit ni last_ok ni last_count");
        let e = last_error.unwrap_or_default();
        assert!(!e.contains("198.51.100.42") && !e.contains("credence-v6"), "jamais l'endpoint : {e}");
        assert!(!e.contains("erf-d") && !e.contains("192.0.2.22"), "jamais un événement : {e}");
    }

    /// Le premier UPDATE réussit SANS effet (`Ok(0)`, déclencheur `RAISE(IGNORE)` sur le filigrane) : c'est le même
    /// défaut qu'un refus (la destination resterait due à chaque tick), la seconde écriture a lieu aussi.
    #[test]
    fn p10_33h_filigrane_sans_effet_pose_last_run_et_last_error() {
        let db = erf_destination();
        db.lock().execute_batch(ERF_IGNORE_FILIGRANE).unwrap();
        let ok_tx = |_w: &Wire| Ok::<u16, String>(200);
        let b = forward_one_destination(&db, 8, "webhook", ERF_ENDPOINT, "{}", "{}", 500, 0, ERF_NOW, &ok_tx);
        assert_eq!(b, Mesure::Lue(1), "filigrane sans effet : compté");
        let (watermark, last_run, last_error, error_count) = erf_dest_etat(&db);
        assert_eq!(watermark, 0, "contrôle : le filigrane n'a pas bougé");
        assert_eq!(last_run, Some(ERF_NOW), "l'échéance est posée aussi quand le premier UPDATE n'a rien écrit");
        assert_eq!(last_error.as_deref(), Some(FILIGRANE_NON_ECRIT_APRES_ENVOI), "l'aveu, par sa constante");
        assert_eq!(error_count, 1, "l'aveu se compte");
        assert_eq!(erf_dest_succes(&db), (Some(111), 7), "contrôle : le dernier succès n'a pas bougé");
    }

    #[test]
    fn p10_33h_tout_update_refuse_journal_seul_lue_un() {
        let db = erf_destination();
        db.lock().execute_batch(ERF_REFUS_TOUT).unwrap();
        let ok_tx = |_w: &Wire| Ok::<u16, String>(200);
        let b = forward_one_destination(&db, 8, "webhook", ERF_ENDPOINT, "{}", "{}", 500, 0, ERF_NOW, &ok_tx);
        assert_eq!(b, Mesure::Lue(1), "tout refusé : compté");
        let (watermark, last_run, last_error, error_count) = erf_dest_etat(&db);
        assert_eq!((watermark, last_run, last_error, error_count), (0, None, None, 0), "contrôle : rien n'est écrit");
    }

    /// La LIGNE DE JOURNAL, sur le stderr d'un sous-processus : une seule ligne par refus ; elle dit si la seconde
    /// écriture (échéance + aveu) a tenu ou si elle a refusé à son tour, avec la cause du moteur ; jamais l'endpoint.
    #[test]
    fn p10_33h_ligne_de_journal_dit_la_seconde_ecriture() {
        const ENFANT: &str = "ERF_V6_ENFANT_JOURNAL";
        const PHASE: &str = "ERF-V6-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let ok_tx = |_w: &Wire| Ok::<u16, String>(200);
            eprintln!("{PHASE}filigrane");
            let db = erf_destination();
            db.lock().execute_batch(ERF_REFUS_FILIGRANE).unwrap();
            println!("ERF-BILAN-FILIGRANE:{:?}", forward_one_destination(&db, 8, "webhook", ERF_ENDPOINT, "{}", "{}", 500, 0, ERF_NOW, &ok_tx));
            eprintln!("{PHASE}tout");
            let db = erf_destination();
            db.lock().execute_batch(ERF_REFUS_TOUT).unwrap();
            println!("ERF-BILAN-TOUT:{:?}", forward_one_destination(&db, 8, "webhook", ERF_ENDPOINT, "{}", "{}", 500, 0, ERF_NOW, &ok_tx));
            eprintln!("{PHASE}ignore-tout");
            let db = erf_destination();
            db.lock().execute_batch(ERF_IGNORE_TOUT).unwrap();
            println!("ERF-BILAN-IGNORE:{:?}", forward_one_destination(&db, 8, "webhook", ERF_ENDPOINT, "{}", "{}", 500, 0, ERF_NOW, &ok_tx));
            eprintln!("{PHASE}rapport-refuse");
            let (path, db, _id) = erf_rapport("journal-refuse");
            db.lock()
                .execute_batch("CREATE TRIGGER erf_j_err BEFORE UPDATE OF last_error ON scheduled_report BEGIN SELECT RAISE(ABORT,'erreur refusee par le temoin v6'); END;")
                .unwrap();
            temoin_d_envoi::poser(|_k, _t, _d| false);
            println!("ERF-BILAN-RAPPORT-REFUSE:{:?}", run_due_reports(&db, &path));
            temoin_d_envoi::retirer();
            eprintln!("{PHASE}rapport-reussi");
            let (path, db, _id) = erf_rapport("journal-reussi");
            db.lock()
                .execute_batch("CREATE TRIGGER erf_j_ok BEFORE UPDATE OF last_ok ON scheduled_report BEGIN SELECT RAISE(ABORT,'succes refuse par le temoin v6'); END;")
                .unwrap();
            temoin_d_envoi::poser(|_k, _t, _d| true);
            println!("ERF-BILAN-RAPPORT-REUSSI:{:?}", run_due_reports(&db, &path));
            temoin_d_envoi::retirer();
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::envoi_refuse_et_filigrane_refuse_avoues::p10_33h_ligne_de_journal_dit_la_seconde_ecriture",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains("ERF-BILAN-FILIGRANE:Lue(1)") && stdout.contains("ERF-BILAN-TOUT:Lue(1)"), "contrôle : bilans : {stdout}");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[plume]")).map(str::to_string).collect()
        };
        let filigrane = phase("filigrane");
        assert_eq!(filigrane.len(), 1, "une ligne : {filigrane:?}");
        assert!(filigrane[0].starts_with("[plume] destination 8 :"), "{}", filigrane[0]);
        assert!(filigrane[0].contains("filigrane refuse par le temoin v6"), "la cause du moteur : {}", filigrane[0]);
        assert!(filigrane[0].contains("last_run et last_error écrits"), "la seconde écriture a tenu, dit : {}", filigrane[0]);
        let tout = phase("tout");
        assert_eq!(tout.len(), 1, "une ligne et une seule, même quand la seconde écriture refuse : {tout:?}");
        assert!(tout[0].contains("NON ÉCRITS non plus"), "le second refus est dit : {}", tout[0]);
        assert!(!tout[0].contains("last_run et last_error écrits"), "jamais une écriture prétendue : {}", tout[0]);
        // Les deux UPDATE refusent sous le MÊME message : la cause doit paraître deux fois, une par écriture
        // (vérification finale de la vague V, mutant MD6B : la cause de la seconde retirée restait verte).
        assert_eq!(tout[0].matches("tout refuse par le temoin v6").count(), 2, "la cause du moteur, pour chaque écriture : {}", tout[0]);
        // Seconde écriture SANS effet (`Ok(0)`) : elle n'a rien écrit, la ligne ne doit pas prétendre le contraire.
        assert!(stdout.contains("ERF-BILAN-IGNORE:Lue(1)"), "contrôle : bilan : {stdout}");
        let ignore = phase("ignore-tout");
        assert_eq!(ignore.len(), 1, "une ligne : {ignore:?}");
        assert!(ignore[0].contains("NON ÉCRITS non plus"), "la seconde écriture sans effet est dite : {}", ignore[0]);
        assert!(!ignore[0].contains("last_run et last_error écrits"), "jamais une écriture prétendue : {}", ignore[0]);
        assert_eq!(ignore[0].matches("0 ligne(s) écrite(s) au lieu d'une").count(), 2, "les deux écritures, chacune son compte : {}", ignore[0]);
        // Rapport : la ligne nomme les colonnes que l'écriture refusée portait, selon que l'envoi a été refusé ou non.
        assert!(stdout.contains("ERF-BILAN-RAPPORT-REFUSE:Lue(1)") && stdout.contains("ERF-BILAN-RAPPORT-REUSSI:Lue(1)"), "contrôle : bilans : {stdout}");
        let rapport = |nom: &str| -> String {
            let l: Vec<String> = phase(nom).into_iter().filter(|l| l.starts_with("[plume] rapport planifié 53 :")).collect();
            assert_eq!(l.len(), 1, "une ligne pour le rapport 53 ({nom}) : {l:?}");
            l[0].clone()
        };
        let refuse = rapport("rapport-refuse");
        assert!(refuse.contains("envoi refusé par le notificateur, et last_error NON ÉCRIT"), "envoi refusé : last_error nommé : {refuse}");
        assert!(!refuse.contains("last_ok"), "envoi refusé : last_ok n'était pas écrit, la ligne ne le nomme pas : {refuse}");
        assert!(refuse.contains("erreur refusee par le temoin v6"), "la cause du moteur : {refuse}");
        assert!(!refuse.contains(ERF_HOTE_NOTIFICATEUR) && !refuse.contains("credence-v6"), "jamais l'URL : {refuse}");
        let reussi = rapport("rapport-reussi");
        assert!(reussi.contains("statut d'envoi (last_ok, last_count) NON ÉCRIT"), "envoi livré : last_ok nommé : {reussi}");
        assert!(!reussi.contains("envoi refusé"), "envoi livré : jamais dit refusé : {reussi}");
        assert!(reussi.contains("succes refuse par le temoin v6"), "la cause du moteur : {reussi}");
        for l in filigrane.iter().chain(&tout).chain(&ignore) {
            assert!(!l.contains("198.51.100.42") && !l.contains("credence-v6"), "jamais l'endpoint : {l}");
        }
    }
}
