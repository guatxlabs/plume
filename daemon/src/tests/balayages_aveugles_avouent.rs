// =====================================================================================
// `P10.7-f` (lot 106) — UN BALAYAGE DE FOND NE TRAVAILLE PLUS SUR UNE LISTE RACCOURCIE EN SILENCE.
//
// Les balayages périodiques lisaient leur liste de travail par `query_map(..).flatten()` : une ligne en
// erreur disparaissait et le tour s'exécutait sur une liste plus courte, indiscernable d'une liste complète
// (`P10.7-f`, la forme la plus grave de la famille). Deux voies réelles produisent cette ligne en erreur :
// l'interruption d'un énoncé en cours (budget), et « no such table » rendu au PREMIER pas d'une connexion
// dont le cache de schéma est périmé (`P10.7-z`). Ces témoins jouent l'interruption sans chronomètre
// (rappel de progression) et la table hors d'atteinte ; la propriété est l'AVEU compté par balayage — un
// tour qui ne fait rien sans le dire est exactement le défaut.
// =====================================================================================

/// Coupe le PREMIER énoncé qui avance, une seule fois : le rappel rend `true` au premier appel, puis `false`.
fn p10_7f_couper_le_premier_enonce(conn: &Connection) {
    let premier = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    conn.progress_handler(1, Some(move || premier.swap(false, std::sync::atomic::Ordering::SeqCst)));
}
fn p10_7f_ne_plus_couper(conn: &Connection) {
    conn.progress_handler(1, None::<fn() -> bool>);
}

#[test]
fn p10_7f_un_balayage_d_engagements_interrompu_ne_fait_rien_et_le_compte() {
    let conn = test_db();
    let avant = crate::metrics::tick_aveugle_de("engagement_expire_active").map(|(n, _)| n).unwrap_or(0);
    conn.execute(
        "INSERT INTO engagement(id,name,box,scope,window_start,window_end,status,created) VALUES('e-aveugle','n','whitebox','[\"198.51.100.0/24\"]',0,?1,'active',?2)",
        params![now() - 100, now() - 200],
    )
    .unwrap();
    p10_7f_couper_le_premier_enonce(&conn);
    let n = expire_due_engagements_conn(&conn, now());
    p10_7f_ne_plus_couper(&conn);
    assert_eq!(n, 0, "un balayage dont la liste n'a pas été lue ne touche à rien");
    assert_eq!(
        conn.query_row::<String, _, _>("SELECT status FROM engagement WHERE id='e-aveugle'", [], |r| r.get(0)).unwrap(),
        "active",
        "l'engagement échu reste tel quel : le tour n'a pas travaillé sur une liste amputée"
    );
    let (compte, cause) = crate::metrics::tick_aveugle_de("engagement_expire_active").expect("le balayage aveugle est COMPTÉ, sous son nom");
    assert_eq!(compte, avant + 1, "un tour aveugle = un compte de plus");
    assert!(cause.contains("interrupt"), "la cause est celle du moteur (interruption), pas une phrase inventée : {cause}");
    let n = expire_due_engagements_conn(&conn, now());
    assert_eq!(n, 1, "le tour suivant relit et fait le travail");
    assert_eq!(crate::metrics::tick_aveugle_de("engagement_expire_active").map(|(n, _)| n), Some(avant + 1), "un tour lu ne compte rien");
}

#[test]
fn p10_7f_le_balayage_des_echeances_sla_hors_d_atteinte_est_compte_et_ne_marque_rien() {
    let conn = test_db();
    let avant = crate::metrics::tick_aveugle_de("sla_multilevel").map(|(n, _)| n).unwrap_or(0);
    conn.execute("INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,600,1,0,'root',0)", []).unwrap();
    let id = case_create_row(&conn, "alice", "Crit", 4, "", None, 1);
    conn.execute("UPDATE incident SET ack_due=?1, resolve_due=?1 WHERE id=?2", params![now() - 10, id]).unwrap();
    // La table des notificateurs hors d'atteinte : la liste des dépassements se lit, celle des canaux non.
    conn.execute_batch("ALTER TABLE notifier RENAME TO notifier_hors_d_atteinte;").unwrap();
    let db = Arc::new(Mutex::new(conn));
    sla_multilevel_tick(&db);
    {
        let c = db.lock();
        let (ab, rb): (i64, i64) = c.query_row("SELECT ack_breached, resolve_breached FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((ab, rb), (0, 0), "rien n'est marqué tant que la liste des canaux n'a pas été lue : le tour est refusé en bloc");
        let (compte, cause) = crate::metrics::tick_aveugle_de("sla_multilevel").expect("le balayage aveugle est COMPTÉ, sous son nom");
        assert_eq!(compte, avant + 1);
        assert!(cause.contains("no such table"), "la cause est celle du moteur : {cause}");
        c.execute_batch("ALTER TABLE notifier_hors_d_atteinte RENAME TO notifier;").unwrap();
    }
    sla_multilevel_tick(&db);
    let c = db.lock();
    let (ab, rb): (i64, i64) = c.query_row("SELECT ack_breached, resolve_breached FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!((ab, rb), (1, 1), "la table revenue, le tour suivant marque les deux dépassements");
    assert_eq!(crate::metrics::tick_aveugle_de("sla_multilevel").map(|(n, _)| n), Some(avant + 1), "un tour lu ne compte rien");
}

#[test]
fn p10_7f_un_runbook_dont_les_etapes_ne_sont_pas_lues_n_est_pas_attache_ampute() {
    let conn = test_db();
    seed_runbooks(&conn);
    let id = case_create_row(&conn, "a", "exploit", 4, "", None, 2);
    link_alert(&conn, id, "T1190", Some("web-1"));
    let rb = pick_runbook_id(&conn, Some("initial-access"), None).unwrap();
    let etapes_attendues: i64 = conn.query_row("SELECT COUNT(*) FROM runbook_step WHERE runbook_id=?1", params![rb], |r| r.get(0)).unwrap();
    assert!(etapes_attendues >= 4, "instrument : le runbook livré a des étapes");
    // La table des ÉTAPES hors d'atteinte : `attach_runbook` lit d'abord l'existence de l'incident, la
    // progression et le runbook (query_row) — toutes passent — et seule la lecture des étapes échoue, ce qui
    // est exactement la ligne en erreur que le bloc doit refuser au lieu d'attacher un runbook amputé. (Une
    // interruption par rappel de progression frapperait la PREMIÈRE requête, celle de l'incident, pas celle-ci.)
    conn.execute_batch("ALTER TABLE runbook_step RENAME TO runbook_step_hors_d_atteinte;").unwrap();
    let refus = attach_runbook(&conn, id, rb, "bob", &PrefillTargets::default())
        .expect_err("une lecture d'étapes ratée est un REFUS, jamais un runbook amputé");
    assert!(refus.contains("étapes du runbook NON LUES"), "le refus nomme ce qui n'a pas été lu : {refus}");
    let ecrites: i64 = conn.query_row("SELECT COUNT(*) FROM case_step WHERE incident_id=?1", params![id], |r| r.get(0)).unwrap();
    assert_eq!(ecrites, 0, "aucune étape n'est instanciée sur une lecture refusée");
    conn.execute_batch("ALTER TABLE runbook_step_hors_d_atteinte RENAME TO runbook_step;").unwrap();
    let n = attach_runbook(&conn, id, rb, "bob", &PrefillTargets::default()).expect("la table revenue, le runbook s'attache");
    assert_eq!(n, etapes_attendues, "toutes les étapes, pas une de moins");
}
