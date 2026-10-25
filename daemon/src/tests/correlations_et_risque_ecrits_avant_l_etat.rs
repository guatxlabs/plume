// =====================================================================================
// `P10.20-b` / `P10.32-x` (jumeau de `run_advanced_rules`) — CORRÉLATIONS, VOIE RISQUE ET OBSERVATIONS DES LIGNES DE BASE,
// RÈGLES DE RISQUE : CE QUE LE MOTEUR REFUSE D'ÉCRIRE NE LAISSE PLUS DERRIÈRE LUI L'ÉTAT QUI LE TAIT.
//
// VU sur `a759d83d` : `run_correlations` posait `last_run` EN TÊTE (`let _`), avalait l'INSERT de l'alerte d'une séquence
// appariée (`let _`), son rafraîchissement et la résolution des groupes retombés (`let _`, jouée même si l'alerte avait été
// refusée), puis `last_fired` affirmait un tir (`let _`) ; en mode risque, `risk_event_insert` rendait `false` pour
// « déjà posée » (`Ok(0)`) comme pour « refusée » (`Err`) et le résultat était jeté. `run_baselines` jetait de même la
// contribution de risque (voie risque) et l'INSERT des observations du bucket avant d'avancer `last_bucket` (observations
// manquantes aux z-scores suivants). `run_risk_rules` jetait l'issue de chaque contribution et avançait `last_run` de
// toutes les règles évaluées. Rien n'était compté ni dit.
//
// ATTENDU, tenu ici (refus fabriqués par des déclencheurs `RAISE(ABORT)` : l'`OR IGNORE` de l'INSERT ne les absorbe pas) :
//   * corrélation : DEUX corrélations, refus sur la PREMIÈRE, la suivante est écrite (alerte, résolution, `last_fired`,
//     `last_run`) ; la refusée n'écrit ni la résolution de ses groupes retombés, ni `last_fired`, ni `last_run`, et compte
//     UN abandon (deux alertes refusées = un abandon) ; trigger levé, le tick suivant écrit l'alerte et avance l'état ;
//     refus PARTIEL puis reprise : l'alerte déjà entrée est écartée par la dédup (`Ok(0)`), ce qui vaut entrée (`Lue(0)`) ;
//     `last_fired`, `last_run`, la résolution refusés : dits et comptés (un abandon, même pour deux refus) ; le
//     rafraîchissement refusé d'une alerte entrée : dit, pas compté, état avancé ; replanification après une évaluation
//     ratée refusée : dite, pas recomptée ;
//   * corrélation de risque : même chose avec la contribution (deux corrélations, la seconde en mode alerte écrite) ;
//   * ligne de base : contribution de risque ou observation refusée -> bucket non marqué, `last_run` au pas de reprise,
//     un abandon, reprise qui écrit ; refus partiel de contribution puis reprise : la dédup vaut entrée ; `last_bucket`
//     ou `last_run` refusé : dit et compté une fois par ligne de base, et pas du tout pour une ligne de base déjà comptée
//     (évaluation ratée, ligne indécodable, au-delà du plafond) ;
//   * corrélation de risque dont `last_run`/`last_fired` est refusé APRÈS des contributions entrées : un abandon ; groupes
//     ouverts illisibles : un abandon par corrélation (zéro, un ou deux groupes illisibles -> 0, 1, 1), jamais résolus ;
//     séquence cassée : `last_fired` reste nul (modes alerte et risque), il est posé quand elle tire ;
//   * `risk_event_contribuer` rend `Ecrite`, `DejaPosee` (dédup) ou `Refusee` ; `risk_event_insert` rend `false` pour les
//     deux dernières ;
//   * règle de risque : DEUX règles, refus sur la PREMIÈRE, la seconde contribue et avance `last_run` ; la refusée garde
//     `last_run`, compte UN abandon (deux contributions refusées = un) ; trigger levé, elle contribue ; la dédup vaut
//     entrée ;
//   * chaque ligne de journal neuve est lue ENTIÈRE sur le stderr d'un sous-processus, une seule par corrélation ou par
//     règle refusée ; le nominal n'en écrit aucune ;
//   * contrôle positif : écriture réussie -> mêmes lignes, `last_run` et `last_fired` à l'heure du tour, `Lue(0)`.
//
// MUTANTS JOUÉS (retirés avant le commit), chacun rouge sur son témoin : AQ3_ALERTE_CORR_MUETTE,
// AQ3_LAST_RUN_AVANT, AQ3_RESOLUTION_SUR_ECHEC, AQ3_CORR_COMPTE_PAR_ALERTE, AQ3_OK0_CORR, AQ3_RAFRAICHI_MUET,
// AQ3_RAFRAICHI_COMPTE, AQ3_RESOLUTION_MUETTE, AQ3_LAST_FIRED_MUET, AQ3_LAST_RUN_MUET, AQ3_REPLANIF_MUETTE,
// AQ3_CONTRIB_CORR_MUETTE, AQ3_OK0_RISQUE, AQ3_CONTRIB_BL_MUETTE, AQ3_OBS_MUETTE, AQ3_BUCKET_MUET, AQ3_BL_LAST_RUN_MUET,
// AQ3_BL_COMPTE_DOUBLE, AQ3_RISQUE_LAST_RUN_INCOND, AQ3_RISQUE_COMPTE_PAR_CONTRIBUTION ; puis AQ3C_ETAT_RISQUE_IGNORE,
// AQ3C_OPEN_LIGNE_MUETTE, AQ3C_OPEN_PAR_LIGNE, AQ3C_A_TIRE_TOUJOURS, AQ3C_BL_RECOMPTE_OK, AQ3C_BL_RECOMPTE_INDECODABLE,
// AQ3C_BL_RECOMPTE_PLAFOND, AQ3C_RBA_OK0_ECRITE, AQ3C_INSERT_BOOL_DEJA.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : un refus par verrou, disque plein ou interruption (même `Err`, non fabriqué) ;
// l'absence de pas de reprise d'une corrélation ou d'une règle de risque refusée (réévaluée et dite à chaque tick tant que
// le refus dure) ; l'écriture du pas de reprise d'une ligne de base et celle de `last_run` d'une règle de risque (`let _`,
// sens bruyant : nouvel essai dès le tour suivant) ; la contribution threat-intel de l'ingestion (`ti_risk_contribution`,
// hors des voies planifiées) ; le contrat de `Mesure::Lue` (`bilan_de_tick.rs`).
// =====================================================================================
mod correlations_et_risque_ecrits_avant_l_etat {
    use super::*;
    use crate::mesure_environnement::Mesure;

    const CREA_CAUSE: &str = "écriture refusée par le témoin";
    const CREA_IP_A: &str = "192.0.2.10";
    const CREA_IP_B: &str = "192.0.2.20";
    /// Fenêtre des corrélations et des règles de risque : le bucket de dédup du risque (`now / window_s`) ne change pas
    /// entre deux tours d'un même témoin, la dédup est donc réellement jouée.
    const CREA_FENETRE_S: i64 = 1_000_000_000;

    /// Un déclencheur `RAISE(ABORT)` nommé `nom`, `moment` (« BEFORE INSERT », « BEFORE UPDATE ») sur `table`, sous la
    /// condition `quand` (vide : toujours).
    fn crea_refus(nom: &str, moment: &str, table: &str, quand: &str) -> String {
        let quand = if quand.is_empty() { String::new() } else { format!(" WHEN {quand}") };
        format!("CREATE TRIGGER {nom} {moment} ON {table}{quand} BEGIN SELECT RAISE(ABORT, '{CREA_CAUSE}'); END;")
    }

    fn crea_ecrire(p: &str, sql: &str) {
        let w = open_db(p).unwrap();
        w.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn crea_base(tag: &str) -> (crate::tmp_possede::TmpPossede, String) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(&format!("crea-{tag}"));
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let w = Connection::open(&p).unwrap();
        w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&w), "fixture : la chaîne de migrations doit aller au bout");
        (tmp, p)
    }

    // ---------------------------------------------------------------- corrélations

    const CREA_ETAPES: &str = r#"[{"name":"echec auth","query":"search source=auth outcome=fail","min_count":3},{"name":"succes","query":"search source=auth outcome=success","min_count":1}]"#;

    /// Une corrélation par entrée de `risques` (0 = mode alerte, sinon score du mode risque), ids 1, 2… dans l'ordre, et
    /// la séquence complète (trois échecs puis un succès) pour chaque IP de `ips`.
    fn crea_base_correlations(tag: &str, risques: &[i64], ips: &[&str]) -> (crate::tmp_possede::TmpPossede, String) {
        let (tmp, p) = crea_base(tag);
        let w = open_db(&p).unwrap();
        for (k, risque) in risques.iter().enumerate() {
            w.execute(
                "INSERT INTO correlation(name,enabled,key_field,entity_type,steps,window_s,interval_s,severity,mitre,risk_score,managed) \
                 VALUES(?1,1,'src_ip','ip',?2,?3,300,4,'T1110',?4,2)",
                params![format!("séquence {}", k + 1), CREA_ETAPES, CREA_FENETRE_S, risque],
            ).unwrap();
        }
        let base = now() - 100;
        for ip in ips {
            for i in 0..3 {
                w.execute("INSERT INTO event(ts,source,src_ip,fields,dedup) VALUES(?1,'auth',?2,'{\"outcome\":\"fail\"}',?3)", params![base + i, ip, format!("f-{ip}-{i}")]).unwrap();
            }
            w.execute("INSERT INTO event(ts,source,src_ip,fields,dedup) VALUES(?1,'auth',?2,'{\"outcome\":\"success\"}',?3)", params![base + 30, ip, format!("s-{ip}")]).unwrap();
        }
        (tmp, p)
    }

    /// Un groupe ouvert (alerte `new`) de la corrélation `cid` pour une entité qui ne matche plus : la résolution le fermera.
    fn crea_groupe_retombe(p: &str, cid: i64) {
        crea_ecrire(p, &format!(
            "INSERT INTO alert(ts,rule,severity,title,detail,dedup,status,mitre) VALUES({},'corr.{cid}',4,'retombé {cid}','x','corr-{cid}-198.51.100.7','new','T1110');",
            now() - 50
        ));
    }

    fn crea_tour_correlations(p: &str) -> crate::bilan_de_tick::BilanDeTick {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // la concurrence de détection se lit dans l'environnement
        let db = Arc::new(Mutex::new(open_db(p).unwrap()));
        run_correlations(&db, p)
    }

    /// (id, last_run posé, last_fired posé) de chaque corrélation, par id.
    fn crea_etat_correlations(p: &str) -> Vec<(i64, bool, bool)> {
        open_db(p).unwrap()
            .prepare("SELECT id, last_run IS NOT NULL, last_fired IS NOT NULL FROM correlation ORDER BY id").unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap()
            .collect::<Result<_, _>>().unwrap()
    }

    /// (règle, titre, dédup ou vide, statut) de chaque alerte, par id.
    fn crea_alertes(p: &str) -> Vec<(String, String, String, String)> {
        open_db(p).unwrap()
            .prepare("SELECT rule, CASE WHEN rule LIKE 'corr.%' AND title LIKE 'retombé%' THEN title ELSE '' END, COALESCE(dedup,''), status FROM alert ORDER BY id").unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap()
            .collect::<Result<_, _>>().unwrap()
    }

    fn crea_a(rule: &str, titre: &str, dedup: &str, statut: &str) -> (String, String, String, String) {
        (rule.to_string(), titre.to_string(), dedup.to_string(), statut.to_string())
    }

    #[test]
    fn p10_20b_correlation_controle_positif_alerte_ecrite_groupe_retombe_resolu_et_etat_avance() {
        let (_t, p) = crea_base_correlations("corr-ok", &[0], &[CREA_IP_A]);
        crea_groupe_retombe(&p, 1);
        let avant = now();
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(0), "nominal : rien d'abandonné");
        assert_eq!(
            crea_alertes(&p),
            vec![crea_a("corr.1", "retombé 1", "", "resolved"), crea_a("corr.1", "", "corr-1-192.0.2.10", "new")],
            "nominal : le groupe retombé est résolu, l'alerte de la séquence appariée est écrite"
        );
        let (lr, lf): (i64, i64) = open_db(&p).unwrap().query_row("SELECT last_run, last_fired FROM correlation", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert!(lr >= avant && lf == lr, "nominal : last_run et last_fired à l'heure du tour (lus {lr}, {lf} ; tour à {avant})");
    }

    #[test]
    fn p10_20b_deux_correlations_refus_sur_la_premiere_la_suivante_ecrite_puis_la_refusee_entre_au_tick_suivant() {
        let (_t, p) = crea_base_correlations("corr-deux", &[0, 0], &[CREA_IP_A]);
        crea_groupe_retombe(&p, 1);
        crea_groupe_retombe(&p, 2);
        crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE INSERT", "alert", "NEW.rule='corr.1'"));
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "une corrélation dont l'alerte est refusée : un abandon");
        assert_eq!(
            crea_alertes(&p),
            vec![
                crea_a("corr.1", "retombé 1", "corr-1-198.51.100.7", "new"),
                crea_a("corr.2", "retombé 2", "", "resolved"),
                crea_a("corr.2", "", "corr-2-192.0.2.10", "new"),
            ],
            "la refusée ne résout pas son groupe retombé ; la suivante écrit son alerte et résout le sien"
        );
        assert_eq!(
            crea_etat_correlations(&p),
            vec![(1, false, false), (2, true, true)],
            "la refusée n'écrit ni last_run ni last_fired ; la suivante avance les deux"
        );
        crea_ecrire(&p, "DROP TRIGGER crea_refus;");
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(0), "trigger levé : rien d'abandonné");
        assert_eq!(
            crea_alertes(&p),
            vec![
                crea_a("corr.1", "retombé 1", "", "resolved"),
                crea_a("corr.2", "retombé 2", "", "resolved"),
                crea_a("corr.2", "", "corr-2-192.0.2.10", "new"),
                crea_a("corr.1", "", "corr-1-192.0.2.10", "new"),
            ],
            "au tick suivant (sans remise à zéro par la fixture), l'alerte refusée entre et le groupe retombé est résolu"
        );
        assert_eq!(crea_etat_correlations(&p), vec![(1, true, true), (2, true, true)]);
    }

    #[test]
    fn p10_20b_correlation_deux_alertes_refusees_un_abandon_puis_refus_partiel_et_la_dedup_vaut_entree() {
        let (_t, p) = crea_base_correlations("corr-partiel", &[0], &[CREA_IP_A, CREA_IP_B]);
        crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE INSERT", "alert", ""));
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "deux alertes refusées d'UNE corrélation : un abandon");
        assert_eq!(crea_alertes(&p), Vec::<(String, String, String, String)>::new(), "fixture : les deux alertes refusées");
        assert_eq!(crea_etat_correlations(&p), vec![(1, false, false)]);
        crea_ecrire(&p, &format!("DROP TRIGGER crea_refus; {}", crea_refus("crea_refus", "BEFORE INSERT", "alert", "NEW.dedup='corr-1-192.0.2.20'")));
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "refus partiel : un abandon");
        assert_eq!(crea_alertes(&p), vec![crea_a("corr.1", "", "corr-1-192.0.2.10", "new")], "refus partiel : l'une entre, l'autre est refusée");
        assert_eq!(crea_etat_correlations(&p), vec![(1, false, false)], "refus partiel : ni last_run ni last_fired");
        crea_ecrire(&p, "DROP TRIGGER crea_refus;");
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(0), "reprise : l'alerte encore ouverte écartée par la dédup vaut entrée");
        let mut alertes = crea_alertes(&p);
        alertes.sort();
        assert_eq!(
            alertes,
            vec![crea_a("corr.1", "", "corr-1-192.0.2.10", "new"), crea_a("corr.1", "", "corr-1-192.0.2.20", "new")],
            "reprise : la refusée entre, l'entrée n'est pas doublée"
        );
        assert_eq!(crea_etat_correlations(&p), vec![(1, true, true)], "reprise : l'état avance");
    }

    /// Une corrélation qui tire, l'état refusé par `refus` : compté une fois, l'alerte entrée, seule l'écriture refusée
    /// manque (`etat` attendu : last_run posé, last_fired posé).
    fn crea_etat_refuse(tag: &str, refus: &str, etat: (bool, bool)) {
        let (_t, p) = crea_base_correlations(tag, &[0], &[CREA_IP_A]);
        crea_ecrire(&p, refus);
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "{tag} : l'état refusé est compté, une fois");
        assert_eq!(crea_alertes(&p), vec![crea_a("corr.1", "", "corr-1-192.0.2.10", "new")], "{tag} : l'alerte est entrée");
        assert_eq!(crea_etat_correlations(&p), vec![(1, etat.0, etat.1)], "{tag} : seule l'écriture refusée manque");
    }

    #[test]
    fn p10_20b_correlation_last_fired_last_run_ou_resolution_refuses_sont_comptes_une_fois() {
        // (a) last_fired refusé ; (b) last_run refusé ; (c) les deux : un abandon ; (d) résolution refusée.
        crea_etat_refuse("corr-lf", &crea_refus("crea_refus", "BEFORE UPDATE", "correlation", "NEW.last_fired IS NOT OLD.last_fired"), (true, false));
        crea_etat_refuse("corr-lr", &crea_refus("crea_refus", "BEFORE UPDATE", "correlation", "NEW.last_run IS NOT OLD.last_run"), (false, true));
        crea_etat_refuse("corr-deux-etats", &crea_refus("crea_refus", "BEFORE UPDATE", "correlation", ""), (false, false));
        let (_t, p) = crea_base_correlations("corr-resolution", &[0], &[CREA_IP_A]);
        crea_groupe_retombe(&p, 1);
        crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE UPDATE", "alert", "NEW.status='resolved'"));
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "résolution refusée : comptée");
        assert_eq!(
            crea_alertes(&p),
            vec![crea_a("corr.1", "retombé 1", "corr-1-198.51.100.7", "new"), crea_a("corr.1", "", "corr-1-192.0.2.10", "new")],
            "résolution refusée : le groupe reste ouvert, l'alerte est entrée"
        );
        assert_eq!(crea_etat_correlations(&p), vec![(1, true, true)], "résolution refusée : l'état avance");
    }

    #[test]
    fn p10_20b_correlation_insert_ignore_par_le_moteur_rend_ok0_et_vaut_entree() {
        // `RAISE(IGNORE)` fait rendre `Ok(0)` à l'INSERT, comme la dédup : ce n'est pas un refus, l'état avance.
        let (_t, p) = crea_base_correlations("corr-ignore", &[0], &[CREA_IP_A]);
        crea_ecrire(&p, "CREATE TRIGGER crea_ignore BEFORE INSERT ON alert BEGIN SELECT RAISE(IGNORE); END;");
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(0), "Ok(0) : entrée, pas un abandon");
        assert_eq!(crea_alertes(&p), Vec::<(String, String, String, String)>::new(), "fixture : l'INSERT est écarté sans erreur");
        assert_eq!(crea_etat_correlations(&p), vec![(1, true, true)], "Ok(0) : last_run et last_fired écrits");
    }

    #[test]
    fn p10_20b_correlation_rafraichissement_refuse_n_est_pas_un_abandon_et_l_etat_avance() {
        let (_t, p) = crea_base_correlations("corr-rafraichi", &[0], &[CREA_IP_A]);
        crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE UPDATE", "alert", "NEW.status = OLD.status"));
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(0), "rafraîchissement refusé d'une alerte entrée : pas un abandon");
        assert_eq!(crea_alertes(&p), vec![crea_a("corr.1", "", "corr-1-192.0.2.10", "new")]);
        assert_eq!(crea_etat_correlations(&p), vec![(1, true, true)], "rafraîchissement refusé : l'état avance");
    }

    #[test]
    fn p10_20b_correlation_evaluation_ratee_replanification_refusee_comptee_une_fois() {
        // Colonne de clé absente de la projection : évaluation ratée (le témoin d'avant, `scheduled_run_correlations_
        // eval_failure_fail_closed`, garde l'avancée de `last_run` quand elle est écrite).
        let (_t, p) = crea_base_correlations("corr-eval", &[0], &[CREA_IP_A]);
        crea_ecrire(&p, &format!("UPDATE correlation SET key_field='colonne_absente'; {}", crea_refus("crea_refus", "BEFORE UPDATE", "correlation", "")));
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "évaluation ratée dont la replanification est refusée : un abandon, pas deux");
        assert_eq!(crea_etat_correlations(&p), vec![(1, false, false)]);
    }

    #[test]
    fn p10_20b_correlation_de_risque_refusee_sur_la_premiere_la_suivante_ecrite_puis_contribution_au_tick_suivant() {
        let (_t, p) = crea_base_correlations("corr-risque", &[30, 0], &[CREA_IP_A]);
        crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE INSERT", "risk_event", ""));
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "contribution refusée : un abandon");
        let contributions = |p: &str| -> Vec<(String, i64, String)> {
            open_db(p).unwrap().prepare("SELECT source, rule_id, entity FROM risk_event ORDER BY id").unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().collect::<Result<_, _>>().unwrap()
        };
        assert_eq!(contributions(&p), Vec::<(String, i64, String)>::new(), "fixture : la contribution est refusée");
        assert_eq!(crea_alertes(&p), vec![crea_a("corr.2", "", "corr-2-192.0.2.10", "new")], "la suivante (mode alerte) est écrite");
        assert_eq!(crea_etat_correlations(&p), vec![(1, false, false), (2, true, true)], "la refusée garde son état ; la suivante avance");
        crea_ecrire(&p, "DROP TRIGGER crea_refus;");
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(0));
        assert_eq!(contributions(&p), vec![("correlation".to_string(), 1, CREA_IP_A.to_string())], "au tick suivant, la contribution entre");
        assert_eq!(crea_etat_correlations(&p), vec![(1, true, true), (2, true, true)]);
    }

    #[test]
    fn p10_20b_correlation_de_risque_deux_refus_un_abandon_puis_refus_partiel_et_la_dedup_vaut_entree() {
        let (_t, p) = crea_base_correlations("corr-risque-partiel", &[30], &[CREA_IP_A, CREA_IP_B]);
        crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE INSERT", "risk_event", ""));
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "deux contributions refusées d'UNE corrélation : un abandon");
        crea_ecrire(&p, &format!("DROP TRIGGER crea_refus; {}", crea_refus("crea_refus", "BEFORE INSERT", "risk_event", "NEW.entity='192.0.2.20'")));
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "refus partiel : un abandon");
        assert_eq!(crea_etat_correlations(&p), vec![(1, false, false)], "refus partiel : ni last_run ni last_fired");
        crea_ecrire(&p, "DROP TRIGGER crea_refus;");
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(0), "reprise : la contribution déjà posée vaut entrée");
        let entites: Vec<String> = open_db(&p).unwrap().prepare("SELECT entity FROM risk_event ORDER BY entity").unwrap()
            .query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
        assert_eq!(entites, vec![CREA_IP_A.to_string(), CREA_IP_B.to_string()], "reprise : la refusée entre, l'entrée n'est pas doublée");
        assert_eq!(crea_etat_correlations(&p), vec![(1, true, true)]);
    }

    // ---------------------------------------------------------------- lignes de base

    /// Heure FIXE des ticks : 1800 s après le début d'une heure (même construction que `alertes_ecrites_avant_d_avancer_l_etat`).
    const CREA_T0: i64 = 488_889 * 3600 + 1800;
    const CREA_CLOS: i64 = CREA_T0 / 3600 - 1;

    /// Une ligne de base due (interval_s = bucket_s = 3600), score de risque `risque` (0 = alerte discrète), historique bas
    /// et pic de soixante événements au bucket clos pour chaque hôte de `hotes`.
    fn crea_base_ligne(tag: &str, risque: i64, hotes: &[&str]) -> (crate::tmp_possede::TmpPossede, String) {
        let (tmp, p) = crea_base(tag);
        let w = open_db(&p).unwrap();
        w.execute(
            "INSERT INTO ueba_baseline(name,enabled,query,is_soql,entity_type,entity_field,value_field,bucket_s,min_samples,z_threshold,window_s,interval_s,severity,mitre,risk_score,managed) \
             VALUES('volume auth par hôte',1,'search source=auth | stats count by host',1,'host','host','',3600,5,3.0,604800,3600,3,'T1110',?1,2)",
            params![risque],
        ).unwrap();
        for h in hotes {
            for (k, v) in [4.0, 5.0, 6.0, 5.0, 4.0, 6.0, 5.0, 4.0, 6.0, 5.0].iter().enumerate() {
                w.execute(
                    "INSERT INTO ueba_baseline_obs(baseline_id,entity_type,entity,bucket,value,env_id) VALUES(1,'host',?1,?2,?3,'prod')",
                    params![h, CREA_CLOS - 1 - (k as i64), v],
                ).unwrap();
            }
            for i in 0..60 {
                w.execute("INSERT INTO event(ts,source,host,fields,dedup) VALUES(?1,'auth',?2,'{}',?3)", params![CREA_CLOS * 3600 + 10, h, format!("p{h}{i}")]).unwrap();
            }
        }
        (tmp, p)
    }

    /// Un tick de `run_baselines` à l'heure FIXÉE `t` puis (bilan, last_bucket, last_run).
    fn crea_tick_ligne(p: &str, t: i64) -> (crate::bilan_de_tick::BilanDeTick, Option<i64>, Option<i64>) {
        use crate::handlers::detection_advanced::horloge_fixee_des_lignes_de_base as horloge;
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // la concurrence de détection se lit dans l'environnement
        let db = Arc::new(Mutex::new(open_db(p).unwrap()));
        horloge::fixer(Some(t));
        let bilan = run_baselines(&db, p);
        horloge::fixer(None);
        let c = db.lock();
        let (lb, lr) = c.query_row("SELECT last_bucket, last_run FROM ueba_baseline", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        (bilan, lb, lr)
    }

    fn crea_compte(p: &str, sql: &str) -> i64 {
        open_db(p).unwrap().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    const CREA_REPRISE: i64 = CREA_T0 - (3600 - REPRISE_LIGNE_DE_BASE_S);

    #[test]
    fn p10_20b_ligne_de_base_de_risque_contribution_refusee_bucket_inchange_puis_reprise_ecrit() {
        let (_t, p) = crea_base_ligne("bl-risque", 20, &["h1"]);
        crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE INSERT", "risk_event", ""));
        assert_eq!(crea_tick_ligne(&p, CREA_T0), (Mesure::Lue(1), None, Some(CREA_REPRISE)), "contribution refusée : bucket non marqué, pas de reprise, un abandon");
        assert_eq!(crea_compte(&p, "SELECT COUNT(*) FROM risk_event"), 0, "fixture : contribution refusée");
        crea_ecrire(&p, "DROP TRIGGER crea_refus;");
        assert_eq!(crea_tick_ligne(&p, CREA_T0 + REPRISE_LIGNE_DE_BASE_S), (Mesure::Lue(0), Some(CREA_CLOS), Some(CREA_T0 + REPRISE_LIGNE_DE_BASE_S)));
        let dedup: String = open_db(&p).unwrap().query_row("SELECT dedup FROM risk_event", [], |r| r.get(0)).unwrap();
        assert_eq!(dedup, format!("risk:baseline1:h1:{CREA_CLOS}"), "au pas de reprise, la contribution du bucket raté entre");
    }

    #[test]
    fn p10_20b_ligne_de_base_de_risque_refus_partiel_puis_reprise_la_dedup_vaut_entree() {
        let (_t, p) = crea_base_ligne("bl-risque-partiel", 20, &["h1", "h2"]);
        crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE INSERT", "risk_event", "NEW.entity='h2'"));
        assert_eq!(crea_tick_ligne(&p, CREA_T0), (Mesure::Lue(1), None, Some(CREA_REPRISE)), "refus partiel : un abandon, bucket non marqué");
        assert_eq!(crea_compte(&p, "SELECT COUNT(*) FROM risk_event"), 1, "fixture : h1 entre, h2 refusée");
        crea_ecrire(&p, "DROP TRIGGER crea_refus;");
        assert_eq!(
            crea_tick_ligne(&p, CREA_T0 + REPRISE_LIGNE_DE_BASE_S),
            (Mesure::Lue(0), Some(CREA_CLOS), Some(CREA_T0 + REPRISE_LIGNE_DE_BASE_S)),
            "reprise : la contribution de h1 écartée par la dédup vaut entrée"
        );
        assert_eq!(crea_compte(&p, "SELECT COUNT(*) FROM risk_event"), 2, "reprise : h2 entre, h1 n'est pas doublée");
    }

    #[test]
    fn p10_20b_ligne_de_base_observation_refusee_bucket_inchange_puis_reprise_ecrit_l_observation() {
        let (_t, p) = crea_base_ligne("bl-obs", 0, &["h1"]);
        crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE INSERT", "ueba_baseline_obs", ""));
        let obs = format!("SELECT COUNT(*) FROM ueba_baseline_obs WHERE bucket={CREA_CLOS}");
        assert_eq!(crea_tick_ligne(&p, CREA_T0), (Mesure::Lue(1), None, Some(CREA_REPRISE)), "observation refusée : bucket non marqué, pas de reprise, un abandon");
        assert_eq!((crea_compte(&p, &obs), crea_compte(&p, "SELECT COUNT(*) FROM alert")), (0, 1), "observation refusée, l'anomalie est écrite");
        crea_ecrire(&p, "DROP TRIGGER crea_refus;");
        assert_eq!(crea_tick_ligne(&p, CREA_T0 + REPRISE_LIGNE_DE_BASE_S), (Mesure::Lue(0), Some(CREA_CLOS), Some(CREA_T0 + REPRISE_LIGNE_DE_BASE_S)));
        assert_eq!((crea_compte(&p, &obs), crea_compte(&p, "SELECT COUNT(*) FROM alert")), (1, 1), "reprise : l'observation entre, l'anomalie n'est pas doublée");
    }

    #[test]
    fn p10_20b_ligne_de_base_last_bucket_ou_last_run_refuses_comptes_une_fois() {
        let (_t, p) = crea_base_ligne("bl-bucket", 0, &["h1"]);
        crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE UPDATE", "ueba_baseline", "NEW.last_bucket IS NOT OLD.last_bucket"));
        assert_eq!(crea_tick_ligne(&p, CREA_T0), (Mesure::Lue(1), None, Some(CREA_T0)), "last_bucket refusé : compté, last_run avancé");
        let (_t2, p2) = crea_base_ligne("bl-last-run", 0, &["h1"]);
        crea_ecrire(&p2, &crea_refus("crea_refus", "BEFORE UPDATE", "ueba_baseline", "NEW.last_run IS NOT OLD.last_run"));
        assert_eq!(crea_tick_ligne(&p2, CREA_T0), (Mesure::Lue(1), Some(CREA_CLOS), None), "last_run refusé : compté, bucket marqué");
        let (_t3, p3) = crea_base_ligne("bl-deux-etats", 0, &["h1"]);
        crea_ecrire(&p3, &crea_refus("crea_refus", "BEFORE UPDATE", "ueba_baseline", ""));
        assert_eq!(crea_tick_ligne(&p3, CREA_T0), (Mesure::Lue(1), None, None), "les deux refusés : un abandon pour la ligne de base");
    }

    // ---------------------------------------------------------------- règles de risque

    /// `regles` règles de risque (ids 1, 2…), même requête, et un événement web par IP de `ips`.
    fn crea_base_regles(tag: &str, regles: usize, ips: &[&str]) -> (crate::tmp_possede::TmpPossede, String) {
        let (tmp, p) = crea_base(tag);
        let w = open_db(&p).unwrap();
        for k in 0..regles {
            w.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,risk_score,risk_entity_type,risk_entity_field) \
                 VALUES(?1,1,'search source=web | stats count by src_ip',1,'>',0,3,300,?2,'T1046',25,'ip','src_ip')",
                params![format!("scanners {}", k + 1), CREA_FENETRE_S],
            ).unwrap();
        }
        for ip in ips {
            w.execute("INSERT INTO event(ts,source,severity,message,src_ip,dedup) VALUES(?1,'web',3,'m',?2,?3)", params![now() - 5, ip, format!("w-{ip}")]).unwrap();
        }
        (tmp, p)
    }

    fn crea_tour_regles(p: &str) -> crate::bilan_de_tick::BilanDeTick {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // le budget de requête se lit dans l'environnement
        let db = Arc::new(Mutex::new(open_db(p).unwrap()));
        run_risk_rules(&db, p)
    }

    /// (id, last_run posé, contributions de la règle) par id.
    fn crea_etat_regles(p: &str) -> Vec<(i64, bool, i64)> {
        open_db(p).unwrap()
            .prepare("SELECT id, last_run IS NOT NULL, (SELECT COUNT(*) FROM risk_event e WHERE e.rule_id=rule.id AND e.source='rule') FROM rule ORDER BY id").unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap()
            .collect::<Result<_, _>>().unwrap()
    }

    #[test]
    fn p10_20b_deux_regles_de_risque_refus_sur_la_premiere_la_suivante_contribue_puis_la_refusee_au_tick_suivant() {
        let (_t, p) = crea_base_regles("rr-deux", 2, &[CREA_IP_A]);
        crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE INSERT", "risk_event", "NEW.rule_id=1"));
        assert_eq!(crea_tour_regles(&p), Mesure::Lue(1), "une règle dont la contribution est refusée : un abandon");
        assert_eq!(crea_etat_regles(&p), vec![(1, false, 0), (2, true, 1)], "la refusée garde last_run ; la suivante contribue et avance");
        crea_ecrire(&p, "DROP TRIGGER crea_refus;");
        assert_eq!(crea_tour_regles(&p), Mesure::Lue(0), "trigger levé : rien d'abandonné");
        assert_eq!(crea_etat_regles(&p), vec![(1, true, 1), (2, true, 1)], "au tick suivant, la refusée contribue et avance");
    }

    #[test]
    fn p10_20b_regle_de_risque_deux_refus_un_abandon_et_la_dedup_vaut_entree() {
        let (_t, p) = crea_base_regles("rr-partiel", 1, &[CREA_IP_A, CREA_IP_B]);
        crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE INSERT", "risk_event", ""));
        assert_eq!(crea_tour_regles(&p), Mesure::Lue(1), "deux contributions refusées d'UNE règle : un abandon");
        assert_eq!(crea_etat_regles(&p), vec![(1, false, 0)]);
        crea_ecrire(&p, "DROP TRIGGER crea_refus;");
        assert_eq!(crea_tour_regles(&p), Mesure::Lue(0));
        assert_eq!(crea_etat_regles(&p), vec![(1, true, 2)], "trigger levé : les deux contributions entrent");
        crea_ecrire(&p, "UPDATE rule SET last_run=NULL;");
        assert_eq!(crea_tour_regles(&p), Mesure::Lue(0), "règle redue, même bucket : les contributions déjà posées valent entrée");
        assert_eq!(crea_etat_regles(&p), vec![(1, true, 2)], "dédup : rien de doublé, last_run avancé");
    }

    // ---------------------------------------------------------------- compléments : état du mode risque, groupes illisibles,
    // garde du tir, lignes de base déjà comptées, issues d'une contribution

    #[test]
    fn p10_20b_correlation_de_risque_etat_refuse_apres_contributions_entrees_compte_un_abandon() {
        // (refus, état attendu : last_run posé, last_fired posé)
        for (tag, quand, etat) in [
            ("corr-risque-etats", "", (false, false)),
            ("corr-risque-lf", "NEW.last_fired IS NOT OLD.last_fired", (true, false)),
            ("corr-risque-lr", "NEW.last_run IS NOT OLD.last_run", (false, true)),
        ] {
            let (_t, p) = crea_base_correlations(tag, &[30], &[CREA_IP_A, CREA_IP_B]);
            crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE UPDATE", "correlation", quand));
            assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "{tag} : contributions entrées puis état refusé : un abandon");
            assert_eq!(crea_compte(&p, "SELECT COUNT(*) FROM risk_event WHERE source='correlation' AND rule_id=1"), 2, "{tag} : les deux contributions sont entrées");
            assert_eq!(crea_etat_correlations(&p), vec![(1, etat.0, etat.1)], "{tag} : seule l'écriture refusée manque");
        }
    }

    /// Une alerte ouverte de la corrélation 1 dont la dédup est un BLOB : `LIKE 'corr-1-%'` la retient, son décodage en
    /// texte échoue (groupe ouvert illisible).
    fn crea_groupe_illisible(p: &str, entite: &str) {
        crea_ecrire(p, &format!(
            "INSERT INTO alert(ts,rule,severity,title,detail,dedup,status,mitre) VALUES({},'corr.1',4,'illisible','x',CAST('corr-1-{entite}' AS BLOB),'new','T1110');",
            now() - 50
        ));
    }

    #[test]
    fn p10_20b_correlation_groupes_ouverts_illisibles_un_abandon_par_correlation() {
        for (tag, illisibles, attendu) in [("corr-illisible-0", 0usize, 0u32), ("corr-illisible-1", 1, 1), ("corr-illisible-2", 2, 1)] {
            let (_t, p) = crea_base_correlations(tag, &[0], &[CREA_IP_A]);
            for k in 0..illisibles {
                crea_groupe_illisible(&p, &format!("198.51.100.{}", 7 + k));
            }
            assert_eq!(
                crea_compte(&p, "SELECT COUNT(*) FROM alert WHERE dedup LIKE 'corr-1-%'"),
                illisibles as i64,
                "{tag} : fixture, la lecture des groupes ouverts retient les dédups BLOB"
            );
            assert_eq!(crea_tour_correlations(&p), Mesure::Lue(attendu), "{tag} : {illisibles} groupe(s) illisible(s) -> {attendu} abandon(s), un par corrélation");
            assert_eq!(
                crea_compte(&p, "SELECT COUNT(*) FROM alert WHERE typeof(dedup)='blob' AND status='new'"),
                illisibles as i64,
                "{tag} : un groupe illisible n'est pas résolu (fail-closed)"
            );
            assert_eq!(crea_compte(&p, "SELECT COUNT(*) FROM alert WHERE dedup='corr-1-192.0.2.10' AND status='new'"), 1, "{tag} : l'alerte de la séquence est entrée");
            assert_eq!(crea_etat_correlations(&p), vec![(1, true, true)], "{tag} : l'état avance");
        }
    }

    #[test]
    fn p10_20b_correlation_sequence_cassee_ne_pose_pas_last_fired_celle_qui_tire_le_pose() {
        // Mode alerte (1) et mode risque (2), trois échecs SANS succès : la séquence n'est pas appariée.
        let (_t, p) = crea_base_correlations("corr-cassee", &[0, 30], &[]);
        let base = now() - 100;
        for i in 0..3 {
            crea_ecrire(&p, &format!("INSERT INTO event(ts,source,src_ip,fields,dedup) VALUES({},'auth','{CREA_IP_A}','{{\"outcome\":\"fail\"}}','f-{i}');", base + i));
        }
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(0), "séquence cassée : rien d'abandonné");
        assert_eq!((crea_compte(&p, "SELECT COUNT(*) FROM alert"), crea_compte(&p, "SELECT COUNT(*) FROM risk_event")), (0, 0), "fixture : aucun tir");
        assert_eq!(crea_etat_correlations(&p), vec![(1, true, false), (2, true, false)], "séquence cassée : last_run posé, last_fired reste nul");
        crea_ecrire(&p, &format!("INSERT INTO event(ts,source,src_ip,fields,dedup) VALUES({},'auth','{CREA_IP_A}','{{\"outcome\":\"success\"}}','s'); UPDATE correlation SET last_run=NULL;", base + 30));
        assert_eq!(crea_tour_correlations(&p), Mesure::Lue(0), "séquence complétée : rien d'abandonné");
        assert_eq!((crea_compte(&p, "SELECT COUNT(*) FROM alert"), crea_compte(&p, "SELECT COUNT(*) FROM risk_event")), (1, 1), "fixture : les deux tirent");
        assert_eq!(crea_etat_correlations(&p), vec![(1, true, true), (2, true, true)], "celle qui tire pose last_fired");
    }

    #[test]
    fn p10_20b_ligne_de_base_deja_comptee_n_est_pas_recomptee_quand_son_last_run_est_refuse() {
        let refus = crea_refus("crea_refus", "BEFORE UPDATE", "ueba_baseline", "");
        // (a) évaluation ratée (colonne d'entité absente du résultat) puis last_run refusé : un abandon.
        let (_t, p) = crea_base_ligne("bl-eval-lr", 0, &["h1"]);
        crea_ecrire(&p, &format!("UPDATE ueba_baseline SET entity_field='colonne_absente'; {refus}"));
        assert_eq!(crea_tick_ligne(&p, CREA_T0), (Mesure::Lue(1), None, None), "évaluation ratée puis last_run refusé : un abandon, pas deux");
        // (b) ligne indécodable (nom BLOB) puis last_run refusé : un abandon.
        let (_t, p) = crea_base_ligne("bl-indecodable-lr", 0, &["h1"]);
        crea_ecrire(&p, &format!("UPDATE ueba_baseline SET name=CAST('volume' AS BLOB); {refus}"));
        assert_eq!(crea_tick_ligne(&p, CREA_T0), (Mesure::Lue(1), None, None), "ligne indécodable puis last_run refusé : un abandon, pas deux");
        // (c) plafond + 1 lignes de base en échec d'évaluation, last_run refusé : une par ligne de base, au-delà du plafond comprise.
        let cap = {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
            detect_concurrency().saturating_mul(4).max(4)
        };
        let (_t, p) = crea_base_ligne("bl-plafond-lr", 0, &["h1"]);
        for k in 1..=cap {
            crea_ecrire(&p, &format!(
                "INSERT INTO ueba_baseline(name,enabled,query,is_soql,entity_type,entity_field,value_field,bucket_s,min_samples,z_threshold,window_s,interval_s,severity,mitre,risk_score,managed) \
                 SELECT name||' {k}',enabled,query,is_soql,entity_type,entity_field,value_field,bucket_s,min_samples,z_threshold,window_s,interval_s,severity,mitre,risk_score,managed FROM ueba_baseline WHERE id=1;"
            ));
        }
        crea_ecrire(&p, &format!("UPDATE ueba_baseline SET entity_field='colonne_absente'; {refus}"));
        assert_eq!(crea_compte(&p, "SELECT COUNT(*) FROM ueba_baseline"), cap as i64 + 1, "fixture : plafond + 1 lignes de base");
        assert_eq!(crea_tick_ligne(&p, CREA_T0).0, Mesure::Lue(cap as u32 + 1), "plafond {cap} + 1 : une par ligne de base, aucune recomptée");
        assert_eq!(crea_compte(&p, "SELECT COUNT(*) FROM ueba_baseline WHERE last_run IS NOT NULL"), 0, "fixture : tous les last_run refusés");
    }

    #[test]
    fn p10_20b_contribution_de_risque_trois_issues_et_booleen_du_wrapper() {
        let (_t, p) = crea_base("rba-issues");
        let c = open_db(&p).unwrap();
        let contribuer = |dedup: &str| risk_event_contribuer(&c, 1_000, "ip", CREA_IP_A, 10, "correlation", Some(1), "r", "", 3, "prod", Some(dedup));
        let inserer = |dedup: &str| risk_event_insert(&c, 1_000, "ip", CREA_IP_A, 10, "correlation", Some(1), "r", "", 3, "prod", Some(dedup));
        let issue = contribuer("d1");
        assert!(matches!(issue, IssueDeLaContribution::Ecrite), "insertion : Ecrite (lu {issue:?})");
        let issue = contribuer("d1");
        assert!(matches!(issue, IssueDeLaContribution::DejaPosee), "Ok(0) de la dédup : DejaPosee (lu {issue:?})");
        assert!(inserer("d2"), "wrapper : une ligne écrite -> true");
        assert!(!inserer("d2"), "wrapper : déjà posée -> false");
        c.execute_batch(&crea_refus("crea_refus", "BEFORE INSERT", "risk_event", "")).unwrap();
        let issue = contribuer("d3");
        assert!(matches!(issue, IssueDeLaContribution::Refusee(_)), "refus du moteur : Refusee (lu {issue:?})");
        assert!(!inserer("d4"), "wrapper : refusée -> false");
        assert_eq!(crea_compte(&p, "SELECT COUNT(*) FROM risk_event"), 2, "fixture : d1 et d2 seules entrées");
    }

    // ---------------------------------------------------------------- lignes de journal

    const CREA_SEPARATEUR: &str = "CREA-ENFANT-SEPARATEUR";

    /// Les refus sont DITS, une ligne par corrélation ou par règle refusée. L'enfant (variable `CREA_ENFANT`) joue une
    /// base par cas, séparées sur le même flux par `CREA-ENFANT-SEPARATEUR <cas>` ; le parent lit les lignes
    /// `[detection] WARN` de chaque bloc et les compare ENTIÈRES (égalité) à l'attendu ; le dernier bloc (nominal) n'en
    /// a aucune.
    #[test]
    fn p10_20b_les_refus_des_correlations_lignes_de_base_et_regles_de_risque_sont_dits_sur_stderr() {
        const ENFANT: &str = "CREA_ENFANT";
        if std::env::var(ENFANT).is_ok() {
            let sep = |cas: &str| eprintln!("{CREA_SEPARATEUR} {cas}");
            sep("alerte");
            let (_t, p) = crea_base_correlations("j-alerte", &[0], &[CREA_IP_A, CREA_IP_B]);
            crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE INSERT", "alert", ""));
            assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "contrôle enfant");
            sep("contribution");
            let (_t, p) = crea_base_correlations("j-contrib", &[30], &[CREA_IP_A, CREA_IP_B]);
            crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE INSERT", "risk_event", ""));
            assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "contrôle enfant");
            sep("rafraichissement");
            let (_t, p) = crea_base_correlations("j-rafraichi", &[0], &[CREA_IP_A]);
            crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE UPDATE", "alert", "NEW.status = OLD.status"));
            assert_eq!(crea_tour_correlations(&p), Mesure::Lue(0), "contrôle enfant");
            sep("resolution");
            let (_t, p) = crea_base_correlations("j-resolution", &[0], &[CREA_IP_A]);
            crea_groupe_retombe(&p, 1);
            crea_ecrire(&p, &format!(
                "INSERT INTO alert(ts,rule,severity,title,detail,dedup,status,mitre) VALUES({},'corr.1',4,'retombé 1','x','corr-1-198.51.100.8','new','T1110'); {}",
                now() - 50,
                crea_refus("crea_refus", "BEFORE UPDATE", "alert", "NEW.status='resolved'")
            ));
            assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "contrôle enfant");
            sep("last_fired");
            let (_t, p) = crea_base_correlations("j-lf", &[0], &[CREA_IP_A]);
            crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE UPDATE", "correlation", "NEW.last_fired IS NOT OLD.last_fired"));
            assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "contrôle enfant");
            sep("last_run");
            let (_t, p) = crea_base_correlations("j-lr", &[0], &[CREA_IP_A]);
            crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE UPDATE", "correlation", "NEW.last_run IS NOT OLD.last_run"));
            assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "contrôle enfant");
            sep("replanification");
            let (_t, p) = crea_base_correlations("j-eval", &[0], &[CREA_IP_A]);
            crea_ecrire(&p, &format!("UPDATE correlation SET key_field='colonne_absente'; {}", crea_refus("crea_refus", "BEFORE UPDATE", "correlation", "")));
            assert_eq!(crea_tour_correlations(&p), Mesure::Lue(1), "contrôle enfant");
            sep("observation");
            let (_t, p) = crea_base_ligne("j-obs", 0, &["h1", "h2"]);
            crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE INSERT", "ueba_baseline_obs", ""));
            assert_eq!(crea_tick_ligne(&p, CREA_T0).0, Mesure::Lue(1), "contrôle enfant");
            sep("contribution_ligne_de_base");
            let (_t, p) = crea_base_ligne("j-bl-risque", 20, &["h1"]);
            crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE INSERT", "risk_event", ""));
            assert_eq!(crea_tick_ligne(&p, CREA_T0).0, Mesure::Lue(1), "contrôle enfant");
            sep("last_bucket");
            let (_t, p) = crea_base_ligne("j-bucket", 0, &["h1"]);
            crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE UPDATE", "ueba_baseline", "NEW.last_bucket IS NOT OLD.last_bucket"));
            assert_eq!(crea_tick_ligne(&p, CREA_T0).0, Mesure::Lue(1), "contrôle enfant");
            sep("last_run_ligne_de_base");
            let (_t, p) = crea_base_ligne("j-bl-lr", 0, &["h1"]);
            crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE UPDATE", "ueba_baseline", "NEW.last_run IS NOT OLD.last_run"));
            assert_eq!(crea_tick_ligne(&p, CREA_T0).0, Mesure::Lue(1), "contrôle enfant");
            sep("regle_de_risque");
            let (_t, p) = crea_base_regles("j-rr", 1, &[CREA_IP_A, CREA_IP_B]);
            crea_ecrire(&p, &crea_refus("crea_refus", "BEFORE INSERT", "risk_event", ""));
            assert_eq!(crea_tour_regles(&p), Mesure::Lue(1), "contrôle enfant");
            sep("nominal");
            let (_t, p) = crea_base_correlations("j-nominal", &[0, 30], &[CREA_IP_A]);
            crea_groupe_retombe(&p, 1);
            assert_eq!(crea_tour_correlations(&p), Mesure::Lue(0), "contrôle enfant");
            let (_t, p) = crea_base_ligne("j-nominal-bl", 20, &["h1"]);
            assert_eq!(crea_tick_ligne(&p, CREA_T0), (Mesure::Lue(0), Some(CREA_CLOS), Some(CREA_T0)), "contrôle enfant");
            let (_t, p) = crea_base_regles("j-nominal-rr", 1, &[CREA_IP_A]);
            assert_eq!(crea_tour_regles(&p), Mesure::Lue(0), "contrôle enfant");
            sep("fin");
            println!("CREA-ENFANT-A-JOUE");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::correlations_et_risque_ecrits_avant_l_etat::p10_20b_les_refus_des_correlations_lignes_de_base_et_regles_de_risque_sont_dits_sur_stderr",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("CREA-ENFANT-A-JOUE"), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        // Découpe du stderr par cas : chaque séparateur ouvre le bloc du cas qu'il nomme.
        let mut blocs: Vec<(String, Vec<String>)> = Vec::new();
        for ligne in stderr.lines() {
            if let Some(cas) = ligne.strip_prefix(&format!("{CREA_SEPARATEUR} ")) {
                blocs.push((cas.to_string(), Vec::new()));
            } else if ligne.starts_with("[detection] WARN") {
                let dernier = blocs.last_mut().unwrap_or_else(|| panic!("ligne avant le premier séparateur : {ligne}"));
                dernier.1.push(ligne.to_string());
            }
        }
        let corr = |suite: &str| format!("[detection] WARN corrélation #1 : {suite}");
        let bl = |suite: &str| format!("[detection] WARN ligne de base #1 : {suite}");
        let reprise = format!("bucket non marqué traité, réévalué au pas de reprise (au plus {REPRISE_LIGNE_DE_BASE_S} s, borné par interval_s)");
        let attendu: Vec<(&str, Vec<String>)> = vec![
            ("alerte", vec![corr(&format!("une alerte n'a pas pu être écrite ({CREA_CAUSE}) — ni la résolution de ses groupes, ni last_fired, ni last_run ne sont posés : la corrélation est due dès le tick suivant"))]),
            ("contribution", vec![corr(&format!("une contribution de risque n'a pas pu être écrite ({CREA_CAUSE}) — ni last_fired ni last_run ne sont posés : la corrélation est due dès le tick suivant"))]),
            ("rafraichissement", vec![corr(&format!("une alerte entrée n'a pas pu être rafraîchie ({CREA_CAUSE}) — elle garde son heure et son détail d'avant"))]),
            ("resolution", vec![corr(&format!("un groupe ouvert retombé n'a pas pu être résolu ({CREA_CAUSE}) — il reste ouvert"))]),
            ("last_fired", vec![corr(&format!("son dernier tir n'a pas pu être écrit ({CREA_CAUSE}) — last_fired reste celui d'avant"))]),
            ("last_run", vec![corr(&format!("son évaluation n'a pas pu être écrite ({CREA_CAUSE}) — last_run reste celui d'avant, la corrélation est due dès le tick suivant"))]),
            ("replanification", vec![corr(&format!("sa replanification après une évaluation ratée n'a pas pu être écrite ({CREA_CAUSE}) — elle est due dès le tick suivant"))]),
            ("observation", vec![bl(&format!("une observation du bucket {CREA_CLOS} n'a pas pu être écrite ({CREA_CAUSE}) — {reprise}"))]),
            ("contribution_ligne_de_base", vec![bl(&format!("une contribution de risque n'a pas pu être écrite ({CREA_CAUSE}) — bucket {CREA_CLOS} non marqué traité, réévalué au pas de reprise (au plus {REPRISE_LIGNE_DE_BASE_S} s, borné par interval_s)"))]),
            ("last_bucket", vec![bl(&format!("le bucket {CREA_CLOS} traité n'a pas pu être marqué ({CREA_CAUSE}) — last_bucket reste celui d'avant"))]),
            ("last_run_ligne_de_base", vec![bl(&format!("son évaluation n'a pas pu être écrite ({CREA_CAUSE}) — last_run reste celui d'avant, la ligne de base est due dès le tick suivant"))]),
            ("regle_de_risque", vec![format!("[detection] WARN règle de risque #1 : une contribution de risque n'a pas pu être écrite ({CREA_CAUSE}) — last_run n'avance pas, la règle est due dès le tick suivant")]),
            ("nominal", vec![]),
            ("fin", vec![]),
        ];
        let attendu: Vec<(String, Vec<String>)> = attendu.into_iter().map(|(c, l)| (c.to_string(), l)).collect();
        assert_eq!(blocs, attendu, "chaque refus a sa ligne entière, une seule par corrélation, ligne de base ou règle ; le nominal n'en a aucune\n{stderr}");
    }
}
