// =====================================================================================
// `P10.32-x` (reste : le jumeau `run_advanced_rules`) — L'ÉTAT D'UNE RÈGLE AVANCÉE N'AVANCE QU'APRÈS SES ALERTES.
//
// VU sur `7ecbec19` (`handlers/alerting.rs`) : `run_advanced_rules` posait `last_run`/`last_value` en `let _` AVANT
// d'écrire ses alertes. Une alerte refusée par le moteur laissait donc la règle avancée : plus due avant `interval_s`,
// la détection restait muette tout ce temps (seul le compte d'abandon en gardait une trace). Même défaut, avalé en
// `let _` : la replanification d'une règle abandonnée, la résolution et la purge du throttle sous le seuil, le throttle
// d'une alerte entrée, `last_fired`.
//
// ATTENDU, tenu ici (refus fabriqués par des triggers `RAISE(ABORT)`) : une alerte refusée laisse `last_run` et
// `last_value` d'avant, la règle se rejoue au tick SUIVANT sans qu'on la redue à la main ; cas mixte (une alerte
// entrée, une refusée) : l'état n'avance pas, le tick suivant fait entrer la refusée et mute l'entrée ; toutes les
// alertes écrites ou toutes les unités muettes : l'état avance comme avant. Chaque écriture refusée (état au tir,
// `last_fired`, état sous le seuil, résolution, purge du throttle) est COMPTÉE — une règle, un abandon, même pour
// trois refus — et dite au journal. Le throttle refusé d'une alerte ENTRÉE est dit, PAS compté (sens bruyant, comme sa
// lecture ratée : `alertes_ecrites_avant_d_avancer_l_etat` juge déjà qu'un throttle en vue illisible n'est pas un
// abandon). Les lignes sont lues sur le stderr d'un sous-processus (le binaire de test rejoué), dont celle de la
// replanification refusée d'une règle abandonnée, qui n'est pas recomptée.
//
// REPRISE APRÈS VÉRIFICATION : deux refus AU TIR (état ET `last_fired`) comptent pour une règle ; la règle dont les
// LIGNES ne s'évaluent pas après un scalaire lu (`run_query_ex` en erreur, fabriqué par le crochet du fil appelant
// `avant_la_preparation_de_ce_fil` : la table `event` est retirée entre le scalaire et les lignes) est replanifiée,
// donc pas réévaluée au tick suivant ; les lignes de journal de la résolution refusée, de la purge refusée, de
// `last_fired` refusé et de la replanification refusée après une COMPILATION refusée sont lues sur stderr.
//
// MUTANTS JOUÉS (variable de mutation sous cfg!(test), retirés avant le commit) : x_etat_avant_les_alertes, x_etat_si_une_entree,
// x_etat_jamais_ecrit_au_tir, x_etat_refus_non_compte, x_throttle_refus_muet, x_last_fired_refus_non_compte,
// x_etat_sous_seuil_non_compte, x_resolution_non_comptee, x_purge_non_comptee, x_compte_par_ecriture_sous_seuil,
// x_etat_refus_muet, x_replanification_muette — chacun rouge sur son témoin. Reprise : aa4_last_fired_compte_en_plus,
// aa4_lignes_ratees_sans_replanif, aa4_resolution_muette, aa4_purge_muette, aa4_last_fired_muet,
// aa4_compil_replanif_muette — chacun rouge sur son témoin.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : un refus par verrou, disque plein ou interruption (même `Err`,
// non fabriqué) ; un refus durable, qui fait réévaluer la règle et écrire une ligne de journal à chaque tick (pas de
// pas de reprise, comme le jumeau `run_due_rules`).
// =====================================================================================
mod regle_avancee_etat_apres_ses_alertes {
    use super::*;
    use crate::mesure_environnement::Mesure;

    const EAA_REQUETE: &str = "search source=web status>=500 | stats count by src_ip | where count > 10";
    const EAA_REFUS_ALERTE: &str = "CREATE TRIGGER eaa_refus BEFORE INSERT ON alert BEGIN SELECT RAISE(ABORT, 'alerte refusée par le témoin'); END;";
    const EAA_REFUS_ALERTE_8888: &str = "CREATE TRIGGER eaa_refus BEFORE INSERT ON alert WHEN NEW.src_ip='8.8.8.8' BEGIN SELECT RAISE(ABORT, 'alerte refusée par le témoin'); END;";
    const EAA_REFUS_ETAT: &str = "CREATE TRIGGER eaa_refus_etat BEFORE UPDATE OF last_run ON rule BEGIN SELECT RAISE(ABORT, 'état refusé par le témoin'); END;";
    const EAA_REFUS_THROTTLE: &str = "CREATE TRIGGER eaa_refus_throttle BEFORE INSERT ON alert_throttle BEGIN SELECT RAISE(ABORT, 'throttle refusé par le témoin'); END;";
    const EAA_REFUS_LAST_FIRED: &str = "CREATE TRIGGER eaa_refus_tir BEFORE UPDATE OF last_fired ON rule BEGIN SELECT RAISE(ABORT, 'tir refusé par le témoin'); END;";
    const EAA_REFUS_RESOLUTION: &str = "CREATE TRIGGER eaa_refus_resolution BEFORE UPDATE ON alert BEGIN SELECT RAISE(ABORT, 'résolution refusée par le témoin'); END;";
    const EAA_REFUS_PURGE: &str = "CREATE TRIGGER eaa_refus_purge BEFORE DELETE ON alert_throttle BEGIN SELECT RAISE(ABORT, 'purge refusée par le témoin'); END;";

    fn eaa_ecrire(p: &str, sql: &str) {
        let w = open_db(p).unwrap();
        w.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    /// Une règle avancée throttlée par `src_ip` (requête `query`, GXQL si `is_soql`), et 24 événements web en erreur
    /// pour chaque IP de `ips`. Rend (tmp, chemin).
    fn eaa_base(tag: &str, ips: &[&str], query: &str, is_soql: bool) -> (crate::tmp_possede::TmpPossede, String) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(&format!("eaa-{tag}"));
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let t = now() - 10;
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&w), "fixture : la chaîne de migrations doit aller au bout");
            w.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed,throttle_field) \
                 VALUES('exploit web par IP',1,?1,?2,'>',0.0,4,300,600,'T1190',2,'src_ip')",
                params![query, is_soql as i64],
            ).unwrap();
            for ip in ips {
                for i in 0..24 {
                    w.execute(
                        "INSERT INTO event(ts,source,severity,src_ip,fields,dedup) VALUES(?1,'web',4,?2,'{\"status\":\"500\"}',?3)",
                        params![t, ip, format!("eaa-{ip}-{i}")],
                    ).unwrap();
                }
            }
        }
        (tmp, p)
    }

    /// Ce que le témoin lit après un tour.
    struct EaaTour {
        bilan: crate::bilan_de_tick::BilanDeTick,
        alertes: i64,
        ouvertes: i64,
        throttles: i64,
        last_run: Option<i64>,
        last_value: Option<f64>,
    }

    /// Un tour de `run_advanced_rules` (le point d'entrée appelé par la boucle de fond), puis ce qu'il a laissé.
    fn eaa_tour(p: &str) -> EaaTour {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // le budget de requête se lit dans l'environnement
        let db = Arc::new(Mutex::new(open_db(p).unwrap()));
        let bilan = run_advanced_rules(&db, p);
        let c = db.lock();
        let (last_run, last_value) = c
            .query_row("SELECT last_run, last_value FROM rule", [], |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, Option<f64>>(1)?)))
            .unwrap();
        EaaTour {
            bilan,
            alertes: c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap(),
            ouvertes: c.query_row("SELECT COUNT(*) FROM alert WHERE status IN ('new','ack')", [], |r| r.get(0)).unwrap(),
            throttles: c.query_row("SELECT COUNT(*) FROM alert_throttle", [], |r| r.get(0)).unwrap(),
            last_run,
            last_value,
        }
    }

    // ---------------------------------------------------------------- au tir : l'état après les alertes

    #[test]
    fn p10_32x_alerte_refusee_laisse_last_run_et_last_value_et_la_regle_se_rejoue_au_tick_suivant() {
        let (_t, p) = eaa_base("refus", &["9.9.9.9"], EAA_REQUETE, true);
        eaa_ecrire(&p, EAA_REFUS_ALERTE);
        let tour = eaa_tour(&p);
        assert_eq!(tour.alertes, 0, "fixture : le trigger a refusé l'alerte");
        assert_eq!(tour.bilan, Mesure::Lue(1), "alerte refusée : un abandon compté");
        assert_eq!((tour.last_run, tour.last_value), (None, None), "alerte refusée : last_run et last_value restent ceux d'avant (la règle n'est pas avancée)");
        // Le trigger retiré, AUCUNE remise à zéro de last_run : la règle est encore due et son alerte entre.
        eaa_ecrire(&p, "DROP TRIGGER eaa_refus;");
        let tour = eaa_tour(&p);
        assert_eq!(tour.alertes, 1, "tick suivant : la règle restée due fait entrer son alerte");
        assert_eq!(tour.bilan, Mesure::Lue(0));
        assert!(tour.last_run.is_some() && tour.last_value.is_some(), "alerte entrée : l'état avance");
    }

    #[test]
    fn p10_32x_cas_mixte_l_etat_n_avance_pas_et_le_tick_suivant_fait_entrer_la_refusee() {
        let (_t, p) = eaa_base("mixte", &["9.9.9.9", "8.8.8.8"], EAA_REQUETE, true);
        eaa_ecrire(&p, EAA_REFUS_ALERTE_8888);
        let tour = eaa_tour(&p);
        assert_eq!((tour.alertes, tour.throttles), (1, 1), "fixture : 9.9.9.9 entrée avec son throttle, 8.8.8.8 refusée");
        assert_eq!(tour.bilan, Mesure::Lue(1));
        assert_eq!(tour.last_run, None, "une alerte refusée suffit : last_run n'avance pas, même si une autre est entrée");
        eaa_ecrire(&p, "DROP TRIGGER eaa_refus;");
        let tour = eaa_tour(&p);
        let c = open_db(&p).unwrap();
        let ips: Vec<String> = c.prepare("SELECT src_ip FROM alert ORDER BY src_ip").unwrap()
            .query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
        assert_eq!(ips, vec!["8.8.8.8".to_string(), "9.9.9.9".to_string()], "tick suivant : la refusée entre, l'entrée n'est pas doublée (throttle)");
        assert_eq!(tour.bilan, Mesure::Lue(0));
        assert!(tour.last_run.is_some(), "toutes les alertes entrées : l'état avance");
    }

    #[test]
    fn p10_32x_controle_negatif_alerte_ecrite_ou_unites_muettes_l_etat_avance() {
        let (_t, p) = eaa_base("nominal", &["9.9.9.9"], EAA_REQUETE, true);
        let avant = now();
        let tour = eaa_tour(&p);
        assert_eq!((tour.alertes, tour.bilan), (1, Mesure::Lue(0)), "nominal : une alerte, rien d'abandonné");
        assert!(tour.last_run.is_some_and(|t| t >= avant), "nominal : last_run posé à l'heure du tour ({:?})", tour.last_run);
        assert!(tour.last_value.is_some(), "nominal : last_value posé");
        // Redue, l'unité muette par la fenêtre de suppression : aucun refus, l'état avance comme avant.
        eaa_ecrire(&p, "UPDATE rule SET last_run=NULL, last_value=NULL;");
        let tour = eaa_tour(&p);
        assert_eq!((tour.alertes, tour.bilan), (1, Mesure::Lue(0)), "fixture : l'unité est muette");
        assert!(tour.last_run.is_some() && tour.last_value.is_some(), "unités muettes, aucun refus : l'état avance");
    }

    #[test]
    fn p10_32x_etat_refuse_apres_une_alerte_ecrite_est_compte() {
        let (_t, p) = eaa_base("etat-refuse", &["9.9.9.9"], EAA_REQUETE, true);
        eaa_ecrire(&p, EAA_REFUS_ETAT);
        let tour = eaa_tour(&p);
        assert_eq!(tour.alertes, 1, "l'alerte est entrée");
        assert_eq!(tour.last_run, None, "fixture : l'état a été refusé");
        assert_eq!(tour.bilan, Mesure::Lue(1), "état refusé : compté (une règle, un abandon)");
    }

    #[test]
    fn p10_32x_throttle_refuse_d_une_alerte_entree_n_est_pas_un_abandon_et_l_etat_avance() {
        let (_t, p) = eaa_base("throttle-refuse", &["9.9.9.9"], EAA_REQUETE, true);
        eaa_ecrire(&p, EAA_REFUS_THROTTLE);
        let tour = eaa_tour(&p);
        assert_eq!((tour.alertes, tour.throttles), (1, 0), "fixture : l'alerte est entrée, son throttle refusé");
        assert_eq!(tour.bilan, Mesure::Lue(0), "throttle refusé d'une alerte entrée : dit au journal, pas un abandon (sens bruyant)");
        assert!(tour.last_run.is_some(), "l'alerte existe : l'état avance (le refus est bruyant, pas aveugle)");
    }

    #[test]
    fn p10_32x_last_fired_refuse_est_compte() {
        let (_t, p) = eaa_base("tir-refuse", &["9.9.9.9"], EAA_REQUETE, true);
        eaa_ecrire(&p, EAA_REFUS_LAST_FIRED);
        let tour = eaa_tour(&p);
        let last_fired: Option<i64> = open_db(&p).unwrap().query_row("SELECT last_fired FROM rule", [], |r| r.get(0)).unwrap();
        assert_eq!((tour.alertes, last_fired), (1, None), "fixture : alerte entrée, last_fired refusé");
        assert_eq!(tour.bilan, Mesure::Lue(1), "last_fired refusé : compté");
    }

    #[test]
    fn p10_32x_etat_et_last_fired_refuses_au_tir_comptent_pour_une_regle() {
        let (_t, p) = eaa_base("tir-deux-refus", &["9.9.9.9"], EAA_REQUETE, true);
        eaa_ecrire(&p, &format!("{EAA_REFUS_ETAT}{EAA_REFUS_LAST_FIRED}"));
        let tour = eaa_tour(&p);
        let last_fired: Option<i64> = open_db(&p).unwrap().query_row("SELECT last_fired FROM rule", [], |r| r.get(0)).unwrap();
        assert_eq!((tour.alertes, tour.last_run, last_fired), (1, None, None), "fixture : alerte entrée, état ET last_fired refusés");
        assert_eq!(tour.bilan, Mesure::Lue(1), "deux refus d'UNE règle au tir : un seul abandon");
    }

    // ---------------------------------------------------------------- les lignes ratées après un scalaire lu

    /// Retire le crochet du fil appelant, même si le témoin panique.
    struct EaaRetirerLeCrochet;
    impl Drop for EaaRetirerLeCrochet {
        fn drop(&mut self) {
            crate::query_exec::avant_la_preparation_de_ce_fil(None);
        }
    }

    /// Le scalaire est lu, puis l'évaluation des LIGNES échoue (`run_query_ex` en erreur) : la règle est comptée ET
    /// replanifiée — elle n'est ni réévaluée ni recomptée au tick suivant, avant son `interval_s`.
    #[test]
    fn p10_32x_lignes_ratees_apres_un_scalaire_lu_la_regle_est_replanifiee() {
        let (_t, p) = eaa_base("lignes-ratees", &["9.9.9.9"], EAA_REQUETE, true);
        let preparations = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let _retrait = EaaRetirerLeCrochet;
        {
            let (preparations, p) = (preparations.clone(), p.clone());
            // Le crochet tourne sur le fil appelant avant chaque préparation : la première (le scalaire) passe, la
            // seconde (les lignes) trouve la table `event` retirée par une autre connexion.
            crate::query_exec::avant_la_preparation_de_ce_fil(Some(Box::new(move || {
                if preparations.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                    open_db(&p).unwrap().execute_batch("DROP TABLE event;").expect("fixture : retrait de la table event");
                }
            })));
        }
        let avant = now();
        let tour = eaa_tour(&p);
        crate::query_exec::avant_la_preparation_de_ce_fil(None);
        assert_eq!(preparations.load(std::sync::atomic::Ordering::SeqCst), 2, "instrument : deux préparations, le scalaire puis les lignes");
        assert_eq!(tour.alertes, 0, "fixture : les lignes n'ont pas été lues, aucune unité fabriquée");
        assert_eq!(tour.bilan, Mesure::Lue(1), "lignes ratées : un abandon compté");
        assert!(tour.last_run.is_some_and(|t| t >= avant), "lignes ratées : la règle est replanifiée (last_run posé : {:?})", tour.last_run);
        assert!(tour.last_value.is_some(), "lignes ratées : last_value posé avec la replanification, comme avant");
        let tour = eaa_tour(&p);
        assert_eq!(tour.bilan, Mesure::Lue(0), "replanifiée : la règle n'est ni réévaluée ni recomptée au tick suivant");
    }

    // ---------------------------------------------------------------- sous le seuil : état, résolution, purge

    /// Une règle qui a tiré (alerte ouverte, throttle posé), puis revenue sous le seuil et redue ; `refus` posé ensuite.
    fn eaa_sous_seuil(tag: &str, refus: &str) -> (crate::tmp_possede::TmpPossede, String, EaaTour) {
        let (t, p) = eaa_base(tag, &["9.9.9.9"], EAA_REQUETE, true);
        let tir = eaa_tour(&p);
        assert_eq!((tir.ouvertes, tir.throttles), (1, 1), "fixture : alerte ouverte et throttle posé");
        eaa_ecrire(&p, "UPDATE rule SET threshold=1000000.0, last_run=NULL, last_value=NULL;");
        eaa_ecrire(&p, refus);
        let tour = eaa_tour(&p);
        (t, p, tour)
    }

    #[test]
    fn p10_32x_sous_le_seuil_controle_negatif_resolue_purgee_etat_avance() {
        let (_t, _p, tour) = eaa_sous_seuil("seuil-ok", "");
        assert_eq!(tour.bilan, Mesure::Lue(0));
        assert_eq!((tour.ouvertes, tour.throttles), (0, 0), "nominal : alerte résolue, throttle purgé");
        assert!(tour.last_run.is_some() && tour.last_value.is_some(), "nominal : état avancé");
    }

    #[test]
    fn p10_32x_sous_le_seuil_resolution_refusee_est_comptee() {
        let (_t, _p, tour) = eaa_sous_seuil("seuil-resolution", EAA_REFUS_RESOLUTION);
        assert_eq!(tour.ouvertes, 1, "fixture : la résolution a été refusée");
        assert_eq!(tour.bilan, Mesure::Lue(1), "résolution refusée : comptée");
    }

    #[test]
    fn p10_32x_sous_le_seuil_purge_du_throttle_refusee_est_comptee() {
        let (_t, _p, tour) = eaa_sous_seuil("seuil-purge", EAA_REFUS_PURGE);
        assert_eq!((tour.ouvertes, tour.throttles), (0, 1), "fixture : alerte résolue, purge refusée");
        assert_eq!(tour.bilan, Mesure::Lue(1), "purge refusée : comptée");
    }

    #[test]
    fn p10_32x_sous_le_seuil_etat_refuse_est_compte() {
        let (_t, _p, tour) = eaa_sous_seuil("seuil-etat", EAA_REFUS_ETAT);
        assert_eq!((tour.last_run, tour.ouvertes), (None, 0), "fixture : état refusé, alerte résolue quand même");
        assert_eq!(tour.bilan, Mesure::Lue(1), "état refusé sous le seuil : compté");
    }

    #[test]
    fn p10_32x_sous_le_seuil_trois_refus_comptent_pour_une_regle() {
        let refus = format!("{EAA_REFUS_ETAT}{EAA_REFUS_RESOLUTION}{EAA_REFUS_PURGE}");
        let (_t, _p, tour) = eaa_sous_seuil("seuil-trois", &refus);
        assert_eq!((tour.last_run, tour.ouvertes, tour.throttles), (None, 1, 1), "fixture : les trois écritures refusées");
        assert_eq!(tour.bilan, Mesure::Lue(1), "trois refus d'UNE règle : un seul abandon");
    }

    // ---------------------------------------------------------------- les lignes de journal, lues sur stderr

    const EAA_SEP_1: &str = "EAA-ENFANT-SEPARATEUR-ETAT";
    const EAA_SEP_2: &str = "EAA-ENFANT-SEPARATEUR-REPLANIFICATION";
    const EAA_SEP_THROTTLE: &str = "EAA-ENFANT-SEPARATEUR-THROTTLE";
    const EAA_SEP_3: &str = "EAA-ENFANT-SEPARATEUR-NOMINAL";
    const EAA_PREFIXE: &str = "[alerting] WARN règle avancée #";

    /// Les refus sont DITS. L'enfant (variable `EAA_ENFANT`) joue cinq bases séparées sur le même flux : (1) alerte
    /// refusée ; (2) état refusé après une alerte écrite ; (3) règle abandonnée (requête brute sur une table absente)
    /// dont la replanification est refusée — un seul abandon ; (4) throttle refusé d'une alerte entrée — aucun abandon ;
    /// (5) nominal. Le parent lit : une ligne par refus, qui dit le refus (et la suite) ; aucune ligne pour le nominal.
    #[test]
    fn p10_32x_les_refus_sont_dits_sur_stderr_et_le_nominal_ne_dit_rien() {
        const ENFANT: &str = "EAA_ENFANT";
        if std::env::var(ENFANT).is_ok() {
            let (_t1, p1) = eaa_base("stderr-alerte", &["9.9.9.9"], EAA_REQUETE, true);
            eaa_ecrire(&p1, EAA_REFUS_ALERTE);
            assert_eq!(eaa_tour(&p1).bilan, Mesure::Lue(1), "contrôle enfant : alerte refusée");
            eprintln!("{EAA_SEP_1}");
            let (_t2, p2) = eaa_base("stderr-etat", &["9.9.9.9"], EAA_REQUETE, true);
            eaa_ecrire(&p2, EAA_REFUS_ETAT);
            assert_eq!(eaa_tour(&p2).alertes, 1, "contrôle enfant : alerte écrite, état refusé");
            eprintln!("{EAA_SEP_2}");
            let (_t3, p3) = eaa_base("stderr-replanif", &["9.9.9.9"], "SELECT COUNT(*) FROM table_absente_du_temoin", false);
            eaa_ecrire(&p3, EAA_REFUS_ETAT);
            let tour = eaa_tour(&p3);
            assert_eq!((tour.bilan, tour.last_run), (Mesure::Lue(1), None), "contrôle enfant : abandon compté une fois, replanification refusée");
            eprintln!("{EAA_SEP_THROTTLE}");
            let (_t5, p5) = eaa_base("stderr-throttle", &["9.9.9.9"], EAA_REQUETE, true);
            eaa_ecrire(&p5, EAA_REFUS_THROTTLE);
            assert_eq!(eaa_tour(&p5).bilan, Mesure::Lue(0), "contrôle enfant : throttle refusé, pas un abandon");
            eprintln!("{EAA_SEP_3}");
            let (_t4, p4) = eaa_base("stderr-nominal", &["9.9.9.9"], EAA_REQUETE, true);
            assert_eq!(eaa_tour(&p4).bilan, Mesure::Lue(0), "contrôle enfant : nominal");
            println!("EAA-ENFANT-A-JOUE");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::regle_avancee_etat_apres_ses_alertes::p10_32x_les_refus_sont_dits_sur_stderr_et_le_nominal_ne_dit_rien",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("EAA-ENFANT-A-JOUE"), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let (alerte, reste) = stderr.split_once(EAA_SEP_1).expect("contrôle : premier séparateur sur stderr");
        let (etat, reste) = reste.split_once(EAA_SEP_2).expect("contrôle : deuxième séparateur sur stderr");
        let (replanif, reste) = reste.split_once(EAA_SEP_THROTTLE).expect("contrôle : troisième séparateur sur stderr");
        let (throttle, nominal) = reste.split_once(EAA_SEP_3).expect("contrôle : quatrième séparateur sur stderr");
        let lignes = |bloc: &str| -> Vec<String> { bloc.lines().filter(|l| l.starts_with(EAA_PREFIXE)).map(str::to_string).collect() };
        let l = lignes(alerte);
        assert_eq!(l.len(), 1, "alerte refusée : une ligne : {stderr}");
        assert!(l[0].contains("l'alerte d'une unité n'a pas pu être écrite") && l[0].contains("la règle est due dès le tick suivant"), "la ligne dit le refus et la suite : {}", l[0]);
        let l = lignes(etat);
        assert_eq!(l.len(), 1, "état refusé : une ligne : {stderr}");
        assert!(l[0].contains("son évaluation n'a pas pu être écrite") && l[0].contains("la règle est due dès le tick suivant"), "la ligne dit le refus et la suite : {}", l[0]);
        let l = lignes(replanif);
        assert_eq!(l.len(), 1, "replanification refusée : une ligne : {stderr}");
        assert!(l[0].contains("sa replanification après abandon n'a pas pu être écrite"), "la ligne dit le refus : {}", l[0]);
        let l = lignes(throttle);
        assert_eq!(l.len(), 1, "throttle refusé : une ligne : {stderr}");
        assert!(l[0].contains("le throttle d'une unité dont l'alerte est entrée n'a pas pu être écrit"), "la ligne dit le refus : {}", l[0]);
        assert_eq!(lignes(nominal), Vec::<String>::new(), "nominal : aucune ligne : {stderr}");
    }

    const EAA_SEP_RESOLUTION: &str = "EAA-ENFANT-SEPARATEUR-RESOLUTION";
    const EAA_SEP_PURGE: &str = "EAA-ENFANT-SEPARATEUR-PURGE";
    const EAA_SEP_COMPILATION: &str = "EAA-ENFANT-SEPARATEUR-COMPILATION";
    /// Une requête GXQL qui ne compile pas : une macro que le compilateur fermé ne connaît pas.
    const EAA_REQUETE_QUI_NE_COMPILE_PAS: &str = "`macro_inexistante_eaa`";

    /// Les AUTRES refus sont DITS. L'enfant (variable `EAA_ENFANT_RESTE`) joue quatre bases séparées sur le même flux :
    /// (1) `last_fired` refusé après une alerte entrée ; (2) résolution refusée sous le seuil ; (3) purge du throttle
    /// refusée sous le seuil ; (4) règle GXQL dont la COMPILATION est refusée, et sa replanification refusée — un seul
    /// abandon. Le parent lit, dans chaque bloc, UNE ligne qui dit CE refus-là.
    #[test]
    fn p10_32x_les_refus_de_tir_de_resolution_de_purge_et_de_replanification_sont_dits_sur_stderr() {
        const ENFANT: &str = "EAA_ENFANT_RESTE";
        if std::env::var(ENFANT).is_ok() {
            let (_t1, p1) = eaa_base("stderr-tir", &["9.9.9.9"], EAA_REQUETE, true);
            eaa_ecrire(&p1, EAA_REFUS_LAST_FIRED);
            let tour = eaa_tour(&p1);
            assert_eq!((tour.alertes, tour.bilan), (1, Mesure::Lue(1)), "contrôle enfant : alerte entrée, last_fired refusé");
            eprintln!("{EAA_SEP_RESOLUTION}");
            let (_t2, _p2, tour) = eaa_sous_seuil("stderr-resolution", EAA_REFUS_RESOLUTION);
            assert_eq!((tour.ouvertes, tour.bilan), (1, Mesure::Lue(1)), "contrôle enfant : résolution refusée");
            eprintln!("{EAA_SEP_PURGE}");
            let (_t3, _p3, tour) = eaa_sous_seuil("stderr-purge", EAA_REFUS_PURGE);
            assert_eq!((tour.throttles, tour.bilan), (1, Mesure::Lue(1)), "contrôle enfant : purge refusée");
            eprintln!("{EAA_SEP_COMPILATION}");
            assert!(
                crate::handlers::detection::rule_sql(EAA_REQUETE_QUI_NE_COMPILE_PAS, true, 600).is_err(),
                "contrôle enfant : la requête ne compile pas"
            );
            let (_t4, p4) = eaa_base("stderr-compilation", &["9.9.9.9"], EAA_REQUETE_QUI_NE_COMPILE_PAS, true);
            eaa_ecrire(&p4, EAA_REFUS_ETAT);
            let tour = eaa_tour(&p4);
            assert_eq!((tour.bilan, tour.last_run), (Mesure::Lue(1), None), "contrôle enfant : compilation refusée comptée une fois, replanification refusée");
            println!("EAA-ENFANT-RESTE-A-JOUE");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::regle_avancee_etat_apres_ses_alertes::p10_32x_les_refus_de_tir_de_resolution_de_purge_et_de_replanification_sont_dits_sur_stderr",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("EAA-ENFANT-RESTE-A-JOUE"), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let (tir, reste) = stderr.split_once(EAA_SEP_RESOLUTION).expect("contrôle : premier séparateur sur stderr");
        let (resolution, reste) = reste.split_once(EAA_SEP_PURGE).expect("contrôle : deuxième séparateur sur stderr");
        let (purge, compilation) = reste.split_once(EAA_SEP_COMPILATION).expect("contrôle : troisième séparateur sur stderr");
        let lignes = |bloc: &str| -> Vec<String> { bloc.lines().filter(|l| l.starts_with(EAA_PREFIXE)).map(str::to_string).collect() };
        for (nom, bloc, attendu) in [
            ("last_fired refusé", tir, "son dernier tir n'a pas pu être écrit"),
            ("résolution refusée", resolution, "ses alertes ouvertes n'ont pas pu être résolues"),
            ("purge refusée", purge, "son throttle n'a pas pu être purgé"),
            ("replanification refusée après une compilation refusée", compilation, "sa replanification après abandon n'a pas pu être écrite"),
        ] {
            let l = lignes(bloc);
            assert_eq!(l.len(), 1, "{nom} : une ligne : {stderr}");
            assert!(l[0].contains(attendu), "{nom} : la ligne dit le refus : {}", l[0]);
        }
    }
}
