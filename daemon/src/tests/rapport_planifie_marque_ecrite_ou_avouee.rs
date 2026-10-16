// =====================================================================================
// `P10.20-w` (rapports planifiés, famille de `P10.33-h`) — LA MARQUE D'ÉCHÉANCE EST ÉCRITE AVANT L'ENVOI, OU
// LE RAPPORT N'EST PAS ENVOYÉ.
//
// VU (re-mesuré au commit de départ) : `deliver_report` envoyait le rapport au notificateur PUIS posait
// `last_run` en `let _ =`. Refusée, la marque ne bougeait pas : l'échéance (`?1 - last_run >= interval_s`) restait
// vraie et le MÊME rapport masqué repartait vers le notificateur tiers à chaque tick, bilan `Lue(0)`, sans
// `last_error`. Le chemin d'échec et le bras panic de `run_due_reports` avalaient de même leur écriture.
//
// CE QUE CES TÉMOINS JOUENT : le point d'entrée du tick (`run_due_reports`), un notificateur intercepté sur le
// fil courant (`temoin_d_envoi`, aucun réseau), des déclencheurs `RAISE(ABORT)` / `RAISE(IGNORE)` sur la colonne
// visée, et la ligne de journal lue sur le stderr d'un sous-processus.
// =====================================================================================
mod rapport_planifie_marque_ecrite_ou_avouee {
    use super::*;
    use crate::handlers::scheduled_reports::{run_due_reports, temoin_d_envoi};
    use crate::mesure_environnement::Mesure;
    use std::cell::Cell;
    use std::rc::Rc;

    const RPM_NOM: &str = "rpm-rapport-confidentiel";
    const RPM_URL: &str = "https://rpm:credence-u6@198.51.100.40/hook";
    const RPM_GXQL_VALIDE: &str = "search | table message";
    const RPM_GXQL_CASSE: &str = "search | where (((";

    /// Base sur disque (le rendu passe par le pool de lecture du chemin) : un événement, un dataset, un notificateur
    /// d'un genre inconnu (aucun réseau même sans intercepteur), un rapport dû (`last_run = 0`, intervalle d'une heure).
    fn rpm_base(tag: &str, gxql: &str) -> (crate::tmp_possede::TmpDb, Arc<Mutex<Connection>>, i64) {
        let (path, conn, id) = rpm_base_nue(tag, gxql);
        (path, Arc::new(Mutex::new(conn)), id)
    }

    fn rpm_base_nue(tag: &str, gxql: &str) -> (crate::tmp_possede::TmpDb, Connection, i64) {
        let path = crate::tmp_possede::TmpDb::neuf(&format!("rpm-{tag}"));
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        conn.execute(
            "INSERT INTO event(ts,source,category,severity,host,message,src_ip) VALUES(?1,'rpm','auth',3,'h1','contenu du rapport','192.0.2.11')",
            params![now()],
        )
        .unwrap();
        conn.execute("INSERT INTO dataset(id,name,soql) VALUES(41,'rpm-ds',?1)", params![gxql]).unwrap();
        conn.execute(
            "INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) VALUES(42,'rpm-n','temoin-u6',1,?1,0,'{}')",
            params![RPM_URL],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO scheduled_report(id,name,dataset_id,notifier_id,interval_s) VALUES(43,?1,41,42,3600)",
            params![RPM_NOM],
        )
        .unwrap();
        (path, conn, 43)
    }

    /// Pose un intercepteur qui compte les envois du fil courant et rend « livré ».
    fn rpm_compter_les_envois() -> Rc<Cell<u32>> {
        let n = Rc::new(Cell::new(0u32));
        let m = n.clone();
        temoin_d_envoi::poser(move |_k, _t, _d| { m.set(m.get() + 1); true });
        n
    }

    fn rpm_etat(db: &Arc<Mutex<Connection>>, id: i64) -> (i64, i64, Option<String>, i64) {
        db.lock()
            .query_row("SELECT last_run,last_ok,last_error,last_count FROM scheduled_report WHERE id=?1", params![id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap()
    }

    #[test]
    fn p10_20w_marque_refusee_aucun_envoi_compte_et_toujours_du() {
        let (path, db, id) = rpm_base("refus", RPM_GXQL_VALIDE);
        db.lock()
            .execute_batch(
                "CREATE TRIGGER rpm_refus BEFORE UPDATE OF last_run ON scheduled_report \
                 BEGIN SELECT RAISE(ABORT,'marque refusee par le temoin u6'); END;",
            )
            .unwrap();
        let envois = rpm_compter_les_envois();
        let b1 = run_due_reports(&db, &path);
        assert_eq!(envois.get(), 0, "marque refusée : AUCUN envoi vers le notificateur");
        assert_eq!(b1, Mesure::Lue(1), "marque refusée : le rapport est compté abandonné au bilan");
        let b2 = run_due_reports(&db, &path);
        assert_eq!(envois.get(), 0, "deuxième tick, marque toujours refusée : toujours zéro envoi");
        assert_eq!(b2, Mesure::Lue(1), "le rapport reste dû et se recompte");
        temoin_d_envoi::retirer();
        assert_eq!(rpm_etat(&db, id).0, 0, "contrôle : last_run n'a pas bougé");
    }

    #[test]
    fn p10_20w_marque_sans_effet_vaut_refus() {
        let (path, db, _) = rpm_base("muet", RPM_GXQL_VALIDE);
        db.lock()
            .execute_batch("CREATE TRIGGER rpm_muet BEFORE UPDATE OF last_run ON scheduled_report BEGIN SELECT RAISE(IGNORE); END;")
            .unwrap();
        let envois = rpm_compter_les_envois();
        let b = run_due_reports(&db, &path);
        temoin_d_envoi::retirer();
        assert_eq!(envois.get(), 0, "zéro ligne écrite n'est pas une marque posée : aucun envoi");
        assert_eq!(b, Mesure::Lue(1), "marque sans effet comptée abandonnée");
    }

    #[test]
    fn p10_20w_nominal_un_envoi_marque_ecrite_pas_de_reenvoi_avant_l_intervalle() {
        let (path, db, id) = rpm_base("nominal", RPM_GXQL_VALIDE);
        // Une erreur ANCIENNE : un succès doit l'effacer, sinon elle resterait affichée après l'envoi réussi.
        db.lock().execute("UPDATE scheduled_report SET last_error='erreur ancienne u6' WHERE id=?1", params![id]).unwrap();
        // Ce que reçoit le point d'envoi : genre du notificateur, titre, détail rendu.
        let recu: Rc<std::cell::RefCell<Vec<(String, String, String)>>> = Rc::default();
        let r2 = recu.clone();
        temoin_d_envoi::poser(move |k, t, d| { r2.borrow_mut().push((k.into(), t.into(), d.into())); true });
        let b1 = run_due_reports(&db, &path);
        assert_eq!(recu.borrow().len(), 1, "un envoi");
        {
            let r = recu.borrow();
            let (k, t, d) = &r[0];
            assert_eq!(k, "temoin-u6", "le genre du notificateur");
            assert!(t.contains(RPM_NOM), "le titre nomme le rapport : {t}");
            assert!(d.contains("contenu du rapport") && d.contains("1 ligne(s)"), "le détail rendu est transmis : {d:?}");
        }
        assert_eq!(b1, Mesure::Lue(0), "nominal : aucun abandon");
        let (last_run, last_ok, last_error, last_count) = rpm_etat(&db, id);
        assert!(last_run > 0 && last_ok == last_run, "marque et statut écrits : {last_run} {last_ok}");
        assert_eq!(last_error, None, "le succès efface l'erreur ancienne");
        assert!(last_count >= 1, "le compte rapporté est écrit : {last_count}");
        let b2 = run_due_reports(&db, &path);
        temoin_d_envoi::retirer();
        assert_eq!(recu.borrow().len(), 1, "tick suivant avant l'intervalle : pas de ré-envoi");
        assert_eq!(b2, Mesure::Lue(0));
    }

    #[test]
    fn p10_20w_statut_refuse_apres_envoi_compte_sans_second_envoi() {
        let (path, db, id) = rpm_base("statut", RPM_GXQL_VALIDE);
        db.lock()
            .execute_batch(
                "CREATE TRIGGER rpm_statut BEFORE UPDATE OF last_ok ON scheduled_report \
                 BEGIN SELECT RAISE(ABORT,'statut refuse par le temoin u6'); END;",
            )
            .unwrap();
        let envois = rpm_compter_les_envois();
        let b1 = run_due_reports(&db, &path);
        assert_eq!(envois.get(), 1, "l'envoi a eu lieu, la marque était posée");
        assert_eq!(b1, Mesure::Lue(1), "statut d'après envoi refusé : compté");
        assert!(rpm_etat(&db, id).0 > 0, "la marque d'échéance est écrite");
        let b2 = run_due_reports(&db, &path);
        temoin_d_envoi::retirer();
        assert_eq!(envois.get(), 1, "aucun second envoi : la marque d'avant envoi tient l'échéance");
        assert_eq!(b2, Mesure::Lue(0));
    }

    #[test]
    fn p10_20w_echec_de_livraison_ecrit_last_error_ou_se_compte() {
        let (path, db, id) = rpm_base("echec", RPM_GXQL_CASSE);
        assert!(
            crate::handlers::scheduled_reports::render_report_detail(&path, RPM_NOM, "viewer", "", RPM_GXQL_CASSE).is_err(),
            "contrôle : le GXQL de la fixture est refusé"
        );
        let envois = rpm_compter_les_envois();
        let b = run_due_reports(&db, &path);
        assert_eq!(envois.get(), 0, "échec d'exécution : aucun envoi");
        assert_eq!(b, Mesure::Lue(0), "échec consigné : pas un abandon");
        let (last_run, _, last_error, _) = rpm_etat(&db, id);
        assert!(last_run > 0 && last_error.is_some(), "last_run et last_error écrits : {last_run} {last_error:?}");

        // Le même échec, consignation refusée : compté.
        let (path2, db2, _) = rpm_base("echec-refus", RPM_GXQL_CASSE);
        db2.lock()
            .execute_batch(
                "CREATE TRIGGER rpm_err BEFORE UPDATE OF last_error ON scheduled_report \
                 BEGIN SELECT RAISE(ABORT,'erreur refusee par le temoin u6'); END;",
            )
            .unwrap();
        let b2 = run_due_reports(&db2, &path2);
        temoin_d_envoi::retirer();
        assert_eq!(envois.get(), 0);
        assert_eq!(b2, Mesure::Lue(1), "échec non consigné : compté abandonné");
    }

    #[test]
    fn p10_20w_panic_capture_marque_comptee() {
        let (path, db, id) = rpm_base("panic", RPM_GXQL_VALIDE);
        temoin_d_envoi::poser(|_k, _t, _d| panic!("panic du temoin u6"));
        let b = run_due_reports(&db, &path);
        assert_eq!(b, Mesure::Lue(1), "panic capturé : compté");
        let (last_run, _, last_error, _) = rpm_etat(&db, id);
        assert!(last_run > 0, "marque d'échéance écrite");
        assert_eq!(last_error.as_deref(), Some("panic interne du rapport (capturé)"));

        // Panic dont la consignation est refusée : le bilan additionne les deux pertes.
        let (path2, db2, _) = rpm_base("panic-refus", RPM_GXQL_VALIDE);
        db2.lock()
            .execute_batch(
                "CREATE TRIGGER rpm_err BEFORE UPDATE OF last_error ON scheduled_report \
                 BEGIN SELECT RAISE(ABORT,'erreur refusee par le temoin u6'); END;",
            )
            .unwrap();
        let b2 = run_due_reports(&db2, &path2);
        temoin_d_envoi::retirer();
        assert_eq!(b2, Mesure::Lue(2), "panic + consignation refusée : deux abandons");
    }

    /// La route manuelle POST /api/scheduled-reports/{id}/run, jouée par son gestionnaire : sa réponse DIT si la
    /// marque d'échéance et le statut sont écrits. `deliver_report` tourne dans `spawn_blocking` (autre fil) : le
    /// témoin d'envoi n'y est pas posé, le notificateur `temoin-u6` (genre inconnu) rend `false` sans réseau.
    async fn rpm_run(tag: &str, gxql: &str, declencheur: Option<&str>) -> (StatusCode, Value, (i64, i64, Option<String>, i64)) {
        use axum::response::IntoResponse;
        let (path, conn, id) = rpm_base_nue(tag, gxql);
        if let Some(sql) = declencheur {
            conn.execute_batch(sql).unwrap();
        }
        let st = ds_file_state_sur(&path, conn);
        let au = AuthUser {
            name: "rpm-editeur".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        };
        let r = crate::handlers::scheduled_reports::report_run_now(State(st.clone()), Extension(au), axum::extract::Path(id))
            .await
            .into_response();
        let code = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps: Value = serde_json::from_slice(&b).unwrap_or(Value::Null);
        let etat = rpm_etat(&st.db, id);
        drop(path);
        (code, corps, etat)
    }

    const RPM_REFUS_MARQUE: &str = "CREATE TRIGGER rpm_refus BEFORE UPDATE OF last_run ON scheduled_report \
         BEGIN SELECT RAISE(ABORT,'marque refusee par le temoin u6'); END;";
    const RPM_REFUS_STATUT: &str = "CREATE TRIGGER rpm_statut BEFORE UPDATE OF last_ok ON scheduled_report \
         BEGIN SELECT RAISE(ABORT,'statut refuse par le temoin u6'); END;";
    const RPM_REFUS_ERREUR: &str = "CREATE TRIGGER rpm_err BEFORE UPDATE OF last_error ON scheduled_report \
         BEGIN SELECT RAISE(ABORT,'erreur refusee par le temoin u6'); END;";

    #[tokio::test]
    async fn p10_20w_run_envoye_dit_marque_et_statut_ecrits() {
        let (code, c, (last_run, last_ok, _, _)) = rpm_run("run-ok", RPM_GXQL_VALIDE, None).await;
        assert_eq!(code, StatusCode::OK, "{c}");
        assert_eq!(c["ok"], json!(true), "{c}");
        assert_eq!(c["marque_ecrite"], json!(true), "{c}");
        assert_eq!(c["statut_ecrit"], json!(true), "{c}");
        assert_eq!(c["delivered"], json!(false), "notificateur inconnu : livraison rendue false, dite telle quelle : {c}");
        assert!(c["rows"].as_i64().unwrap_or(0) >= 1, "{c}");
        assert!(last_run > 0 && last_ok == last_run, "marque et statut écrits : {last_run} {last_ok}");

        let (code, c, (last_run, last_ok, _, _)) = rpm_run("run-statut", RPM_GXQL_VALIDE, Some(RPM_REFUS_STATUT)).await;
        assert_eq!(code, StatusCode::OK, "l'envoi a eu lieu : {c}");
        assert_eq!(c["marque_ecrite"], json!(true), "{c}");
        assert_eq!(c["statut_ecrit"], json!(false), "statut refusé : dit dans la réponse : {c}");
        assert!(last_run > 0 && last_ok == 0, "contrôle : marque écrite, statut non : {last_run} {last_ok}");
    }

    #[tokio::test]
    async fn p10_20w_run_marque_refusee_est_une_erreur_serveur_jamais_un_ok() {
        let (code, c, (last_run, _, _, _)) = rpm_run("run-refus", RPM_GXQL_VALIDE, Some(RPM_REFUS_MARQUE)).await;
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR, "{c}");
        assert!(c.get("ok").is_none(), "jamais un « ok » : {c}");
        assert_eq!(c["marque_ecrite"], json!(false), "{c}");
        assert_eq!(c["delivered"], json!(false), "{c}");
        assert!(c["error"].as_str().unwrap_or("").contains("aucun envoi"), "{c}");
        assert_eq!(last_run, 0, "contrôle : marque non écrite");
    }

    #[tokio::test]
    async fn p10_20w_run_echec_dit_si_l_erreur_est_consignee() {
        let (code, c, (last_run, _, last_error, _)) = rpm_run("run-echec", RPM_GXQL_CASSE, None).await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{c}");
        assert_eq!(c["marque_ecrite"], json!(true), "échec consigné : {c}");
        assert!(c["error"].as_str().map(|e| !e.is_empty()).unwrap_or(false), "la cause est rendue : {c}");
        assert!(last_run > 0 && last_error.is_some(), "contrôle : {last_run} {last_error:?}");

        let (code, c, (last_run, _, _, _)) = rpm_run("run-echec-refus", RPM_GXQL_CASSE, Some(RPM_REFUS_ERREUR)).await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{c}");
        assert_eq!(c["marque_ecrite"], json!(false), "consignation refusée : dite : {c}");
        assert_eq!(last_run, 0, "contrôle : rien d'écrit");
    }

    /// La LIGNE DE JOURNAL, lue sur le stderr d'un sous-processus : marque refusée -> identifiant du rapport, geste
    /// nommé, cause du moteur ; jamais le nom du rapport, l'endpoint du notificateur (qui porte une crédence) ni le
    /// contenu. Chemin nominal : aucune ligne.
    #[test]
    fn p10_20w_ligne_de_journal_identifiant_et_cause_sans_nom_ni_endpoint() {
        const ENFANT: &str = "RPM_U6_ENFANT_JOURNAL";
        const PHASE: &str = "RPM-U6-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            eprintln!("{PHASE}refus");
            let (path, db, _) = rpm_base("journal-refus", RPM_GXQL_VALIDE);
            db.lock()
                .execute_batch(
                    "CREATE TRIGGER rpm_refus BEFORE UPDATE OF last_run ON scheduled_report \
                     BEGIN SELECT RAISE(ABORT,'marque refusee par le temoin u6'); END;",
                )
                .unwrap();
            println!("RPM-BILAN-REFUS:{:?}", run_due_reports(&db, &path));
            eprintln!("{PHASE}nominal");
            let (path, db, _) = rpm_base("journal-nominal", RPM_GXQL_VALIDE);
            println!("RPM-BILAN-NOMINAL:{:?}", run_due_reports(&db, &path));
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::rapport_planifie_marque_ecrite_ou_avouee::p10_20w_ligne_de_journal_identifiant_et_cause_sans_nom_ni_endpoint",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains("RPM-BILAN-REFUS:Lue(1)"), "contrôle : bilan du refus : {stdout}");
        assert!(stdout.contains("RPM-BILAN-NOMINAL:Lue(0)"), "contrôle : bilan nominal : {stdout}");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[plume]")).map(str::to_string).collect()
        };
        let refus = phase("refus");
        assert_eq!(refus.len(), 1, "une ligne et une seule pour la marque refusée : {refus:?}");
        let l = &refus[0];
        assert!(l.starts_with("[plume] rapport planifié 43 :"), "l'identifiant du rapport : {l}");
        assert!(l.contains("marque d'échéance NON ÉCRITE"), "le geste nommé : {l}");
        assert!(l.contains("aucun envoi"), "la conséquence dite : {l}");
        assert!(l.contains("marque refusee par le temoin u6"), "la cause du moteur : {l}");
        assert!(!l.contains(RPM_NOM), "jamais le nom du rapport : {l}");
        assert!(!l.contains("198.51.100.40") && !l.contains("credence-u6"), "jamais l'endpoint : {l}");
        assert!(!l.contains("contenu du rapport"), "jamais le contenu : {l}");
        assert!(phase("nominal").is_empty(), "chemin nominal muet : {:?}", phase("nominal"));
    }
}
