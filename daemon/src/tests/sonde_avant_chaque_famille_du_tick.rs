// =====================================================================================
// `P10.31-j` — LA SONDE D'ORPHELINE EST REPRISE AVANT CHAQUE FAMILLE DU TICK DE DÉTECTION. Mesuré le 2026-10-24 sur
// 831785a9 : `tick_de_detection_d_un_tenant` sondait l'écrivain UNE fois en tête, puis enchaînait règles avancées,
// risque, corrélations, lignes de base, playbooks, battements, notifications, escalades, SLA et engagements sans
// jamais sonder de nouveau ; seule `run_due_rules` refaisait la sonde avant ses écritures. Chaque famille rend le
// verrou en sortant : une orpheline laissée entre deux familles recevait les écritures de toutes les suivantes
// (visibles de l'écrivain seul, perdues au redémarrage). Décision d'Hugo (2026-09-29) : le tick se déclare aveugle,
// n'évalue et n'écrit plus rien, et n'annule pas la transaction.
//
// LE TÉMOIN : le crochet `AVANT_LA_FAMILLE_DU_TICK` note les changements de l'écrivain devant chaque famille et ouvre
// l'orpheline devant la famille visée. La FIXTURE donne à CHAQUE famille quelque chose à écrire (le contrôle positif le
// mesure famille par famille) : « aucun changement après l'orpheline » n'est donc vacant pour aucune. Une famille qui
// écrit par sa PROPRE transaction (escalade, SLA, engagements) ne change rien dans l'orpheline mais y voit son `BEGIN`
// refusé, compté par base : on relit ces refus. Le rafraîchissement du périmètre n'écrit rien : on relit la carte qu'il
// remplit. Et l'orpheline (intacte, vue une seule fois), le bilan (aveugle, famille nommée).
// =====================================================================================
mod sonde_avant_chaque_famille_du_tick {
    use super::*;
    use crate::bilan_de_tick::{BilanDuPlanificateur, BOUCLE_REGLES, CAUSE_TRANSACTION_ORPHELINE};
    use crate::mesure_environnement::{Mesure, CAUSE_SOURCE_ILLISIBLE};
    use crate::server::boucles_de_fond::crochets_de_la_sonde_par_famille::{sans_crochet_de_famille, AVANT_LA_FAMILLE_DU_TICK, FAMILLES_ADMISES_PAR_LA_SONDE};
    use crate::server::boucles_de_fond::{les_regles_ont_deja_declare_l_orpheline, tick_de_detection_d_un_tenant};

    /// Les familles sondées hors mode engagement, dans l'ordre du tick.
    const SAFT_FAMILLES: &[&str] = &[
        "règles avancées",
        "règles de risque",
        "corrélations",
        "lignes de base",
        "playbooks",
        "battements des capteurs",
        "notifications",
        "escalade des dossiers en retard",
        "SLA multi-niveau",
    ];
    /// Les deux familles sondées sous le mode engagement, après les précédentes.
    const SAFT_FAMILLES_ENGAGEMENT: &[&str] = &["expiration des engagements", "rafraîchissement du périmètre des engagements"];
    /// Les journaux des familles qui écrivent par leur propre transaction : escalade (`cases`), SLA (`caseops`),
    /// expiration des engagements (`engagement`). Un `BEGIN` refusé y est compté par base et par cause.
    const SAFT_JOURNAUX_A_TRANSACTION: &[&str] = &["cases", "caseops", "engagement"];

    thread_local! {
        static SAFT_CIBLE: std::cell::Cell<&'static str> = const { std::cell::Cell::new("") };
        /// `total_changes()` de l'écrivain juste après l'ouverture de l'orpheline (`None` : jamais ouverte).
        static SAFT_INJECTION: std::cell::Cell<Option<i64>> = const { std::cell::Cell::new(None) };
        /// (famille, `total_changes()` de l'écrivain) noté devant chaque sonde, dans l'ordre.
        static SAFT_MARQUES: std::cell::RefCell<Vec<(&'static str, i64)>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    fn saft_changements(c: &Connection) -> i64 {
        c.query_row("SELECT total_changes()", [], |r| r.get(0)).unwrap()
    }

    fn saft_ouvrir_l_orpheline(c: &Connection) {
        c.execute_batch("BEGIN IMMEDIATE; INSERT INTO meta(key,value) VALUES('saft','1');").expect("fixture : transaction laissée ouverte");
        SAFT_INJECTION.with(|i| i.set(Some(saft_changements(c))));
    }

    /// Le crochet de famille : note les changements devant chaque famille ; devant la famille visée, ouvre l'orpheline.
    fn saft_crochet_de_famille(db: &Arc<Mutex<Connection>>, famille: &'static str) {
        let c = db.lock();
        SAFT_MARQUES.with(|m| m.borrow_mut().push((famille, saft_changements(&c))));
        if famille == SAFT_CIBLE.with(|c| c.get()) {
            saft_ouvrir_l_orpheline(&c);
        }
    }

    /// Le crochet de `run_due_rules` (entre son évaluation et ses écritures) : ouvre l'orpheline là.
    fn saft_orpheline_pendant_les_regles(db: &Arc<Mutex<Connection>>) {
        saft_ouvrir_l_orpheline(&db.lock());
    }

    /// Une base où CHAQUE famille du tick a quelque chose à écrire : `last_run` des règles avancées et de risque, d'une
    /// corrélation, d'une ligne de base et d'un playbook ; une alerte « capteur muet » ouverte pour un capteur jamais vu
    /// (résolue par les battements, puis marquée notifiée) ; un dossier dont l'échéance et l'échéance d'acquittement sont
    /// passées, avec une politique SLA de sa priorité (escalade, puis dépassement d'acquittement) ; un engagement actif
    /// dont la fenêtre est écoulée (expiré) et un autre dans sa fenêtre (chargé dans la carte du périmètre).
    fn saft_base(tag: &str) -> (crate::tmp_possede::TmpPossede, String, Arc<Mutex<Connection>>) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn));
            conn.execute("DELETE FROM rule", []).unwrap();
            conn.execute("DELETE FROM alert", []).unwrap();
            let maintenant = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) \
                 VALUES('saft',1,'search source=saft | stats count',1,'>',0,2,0,3600)",
                [],
            )
            .unwrap();
            // Évaluée par `run_advanced_rules` (fenêtre de suppression) : écrit son `last_run`.
            conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,suppress_window_s) \
                 VALUES('saft-avancee',1,'search source=saft | stats count',1,'>',0,2,0,3600,600)",
                [],
            )
            .unwrap();
            // Évaluée par `run_risk_rules` (risk_score>0) : avance son `last_run` qu'elle contribue ou non.
            conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,risk_score,risk_entity_type,risk_entity_field) \
                 VALUES('saft-risque',1,'search source=saft | stats count by source',1,'>',0,2,0,3600,5,'host','source')",
                [],
            )
            .unwrap();
            conn.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'saft','auth',1,'échec')", params![maintenant])
                .unwrap();
            // `run_correlations` : `last_run` avance même quand l'évaluation échoue (étapes vides).
            conn.execute("INSERT INTO correlation(name,enabled,steps,interval_s) VALUES('saft',1,'[]',300)", []).unwrap();
            // `run_baselines` : `last_run` avance pour toute ligne de base due.
            conn.execute(
                "INSERT INTO ueba_baseline(name,enabled,query,entity_field,value_field) VALUES('saft',1,'search source=saft | stats count by host','host','count')",
                [],
            )
            .unwrap();
            // `run_playbooks` : le marqueur de passage est écrit avant tout.
            conn.execute(
                "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s) VALUES('saft',1,'search source=saft | stats count',1,'ban_ip',300,3600)",
                [],
            )
            .unwrap();
            // `check_heartbeats` : le capteur `firewall` n'a jamais rien envoyé (aucun instantané) — son épisode ouvert est
            // résolu. `dispatch_notifications` marque ensuite cette alerte notifiée (aucun canal : rien n'est envoyé).
            conn.execute(
                "INSERT INTO alert(ts,rule,severity,title,detail,dedup) VALUES(?1,'heartbeat.firewall',2,'Capteur muet : firewall','saft','hb-firewall')",
                params![maintenant],
            )
            .unwrap();
            // `escalate_overdue_cases` (échéance passée) puis `sla_multilevel_tick` (acquittement dû, politique P2).
            conn.execute(
                "INSERT INTO incident(ts,updated,title,status,priority,sla_due,ack_due) VALUES(?1,?1,'saft','open',2,?2,?2)",
                params![maintenant - 7200, maintenant - 60],
            )
            .unwrap();
            conn.execute("INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled) VALUES('saft',2,60,3600,1)", []).unwrap();
            // Mode engagement seulement : l'un expire, l'autre est chargé dans la carte du périmètre.
            conn.execute(
                "INSERT INTO engagement(id,name,scope,window_start,window_end,status) VALUES('saft-expire','saft','[\"192.0.2.0/24\"]',?1,?2,'active')",
                params![maintenant - 7200, maintenant - 60],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO engagement(id,name,scope,window_start,window_end,status) VALUES('saft-actif','saft','[\"198.51.100.0/24\"]',?1,?2,'active')",
                params![maintenant - 60, maintenant + 3600],
            )
            .unwrap();
        }
        (tmp, p, db)
    }

    fn saft_last_run_pose(c: &Connection, regle: &str) -> bool {
        c.query_row("SELECT last_run IS NOT NULL FROM rule WHERE name=?1", params![regle], |r| r.get(0)).unwrap()
    }

    /// Les `BEGIN` refusés comptés sur cette base par les familles à transaction, toutes causes confondues.
    fn saft_begins_refuses(c: &Connection) -> u64 {
        let mut n = 0;
        for journal in table_declaree!(SAFT_JOURNAUX_A_TRANSACTION) {
            for cause in crate::comptes_de_transaction::CauseDuBeginRefuse::TOUTES {
                n += crate::comptes_de_transaction::compte_des_temoins(c, &format!("begin refusé {journal} {}", cause.etiquette()));
            }
        }
        n
    }

    /// Ce qu'un tick a laissé, lu sur l'écrivain AVANT de fermer l'orpheline.
    struct SaftIssue {
        bilan: crate::bilan_de_tick::BilanDeTick,
        admises: Vec<&'static str>,
        marques: Vec<(&'static str, i64)>,
        injection: Option<i64>,
        changements: i64,
        autocommit: bool,
        marque: i64,
        orphelines_vues: u64,
        begins_refuses: u64,
        /// Les engagements que la carte du périmètre porte pour cette base (`None` : aucune entrée).
        perimetre: Option<Vec<String>>,
        avancee: bool,
        risque: bool,
    }

    /// Joue UN tick, l'orpheline ouverte devant `cible` (`""` : jamais), puis ferme l'orpheline.
    fn saft_jouer(db: &Arc<Mutex<Connection>>, p: &str, cible: &'static str) -> SaftIssue {
        SAFT_CIBLE.with(|c| c.set(cible));
        SAFT_INJECTION.with(|i| i.set(None));
        SAFT_MARQUES.with(|m| m.borrow_mut().clear());
        FAMILLES_ADMISES_PAR_LA_SONDE.with(|v| v.borrow_mut().clear());
        AVANT_LA_FAMILLE_DU_TICK.with(|h| h.set(saft_crochet_de_famille));
        let bilan = tick_de_detection_d_un_tenant(db, p).bilan_de_tick();
        AVANT_LA_FAMILLE_DU_TICK.with(|h| h.set(sans_crochet_de_famille));
        let admises = FAMILLES_ADMISES_PAR_LA_SONDE.with(|v| v.borrow().clone());
        let marques = SAFT_MARQUES.with(|m| m.borrow().clone());
        let perimetre = crate::handlers::engagement::engagement_scope_map()
            .write()
            .remove(p)
            .map(|v| v.into_iter().map(|e| e.engagement_id).collect());
        let issue = {
            let c = db.lock();
            SaftIssue {
                bilan,
                admises,
                marques,
                injection: SAFT_INJECTION.with(|i| i.get()),
                changements: saft_changements(&c),
                autocommit: c.is_autocommit(),
                marque: c.query_row("SELECT COUNT(*) FROM meta WHERE key='saft'", [], |r| r.get(0)).unwrap(),
                orphelines_vues: crate::comptes_de_transaction::compte_des_temoins(&c, "orpheline vue"),
                begins_refuses: saft_begins_refuses(&c),
                perimetre,
                avancee: saft_last_run_pose(&c, "saft-avancee"),
                risque: saft_last_run_pose(&c, "saft-risque"),
            }
        };
        if !issue.autocommit {
            db.lock().execute_batch("ROLLBACK").expect("fixture : fermeture de l'orpheline");
        }
        issue
    }

    /// Les écritures de chaque famille admise : changements de l'écrivain entre sa marque et la suivante (la dernière :
    /// jusqu'à la fin du tick).
    fn saft_ecritures_par_famille(issue: &SaftIssue) -> Vec<(&'static str, i64)> {
        issue
            .marques
            .iter()
            .enumerate()
            .map(|(i, (famille, avant))| (*famille, issue.marques.get(i + 1).map(|m| m.1).unwrap_or(issue.changements) - avant))
            .collect()
    }

    /// Le bilan d'un tick arrêté par UNE orpheline vue devant `famille` : la famille nommée, puis le compte des
    /// abandons des familles qui ont tourné avant elle — un entier, et rien d'autre après.
    fn saft_juger_le_bilan(famille: &str, bilan: &crate::bilan_de_tick::BilanDeTick) {
        match bilan {
            Mesure::Illisible { detail, .. } => {
                let tete = format!(
                    "1 famille(s) aveugle(s) ce tick — {famille} : aveugle, l'écrivain porte une transaction orpheline \
                     ({CAUSE_TRANSACTION_ORPHELINE}) — rien n'est évalué ni écrit par {famille} ce tick, la transaction n'est \
                     pas annulée ; abandons comptés par ailleurs : "
                );
                let reste = detail.strip_prefix(tete.as_str()).unwrap_or_else(|| panic!("orpheline devant « {famille} » : bilan inattendu : {detail}"));
                assert!(!reste.is_empty() && reste.bytes().all(|o| o.is_ascii_digit()), "orpheline devant « {famille} » : bilan inattendu : {detail}");
            }
            Mesure::Lue(n) => panic!("orpheline devant « {famille} » : le tick se dit lu ({n} abandon(s))"),
        }
    }

    /// Les assertions communes à une orpheline ouverte devant `familles[k]`.
    fn saft_juger_l_orpheline(familles: &[&'static str], k: usize, issue: &SaftIssue) {
        let cible = familles[k];
        saft_juger_le_bilan(cible, &issue.bilan);
        assert_eq!(issue.admises, familles[..k].to_vec(), "orpheline devant « {cible} » : seules les familles d'avant ont tourné");
        let injection = issue.injection.unwrap_or_else(|| panic!("instrument : le crochet ne s'est pas déclenché devant « {cible} »"));
        assert_eq!(issue.changements, injection, "orpheline devant « {cible} » : aucune écriture de l'écrivain après l'orpheline");
        assert_eq!(issue.begins_refuses, 0, "orpheline devant « {cible} » : aucune famille à transaction n'a tenté d'écrire dans l'orpheline");
        assert_eq!(issue.perimetre, None, "orpheline devant « {cible} » : le périmètre n'a pas été rafraîchi");
        assert!(!issue.autocommit, "orpheline devant « {cible} » : la transaction est toujours ouverte");
        assert_eq!(issue.marque, 1, "orpheline devant « {cible} » : c'est la même orpheline, ni annulée ni remplacée");
        assert_eq!(issue.orphelines_vues, 1, "orpheline devant « {cible} » : vue une seule fois, le tick s'arrête là");
    }

    /// CE QU'IL TIENT : pour CHAQUE famille hors mode engagement, une orpheline ouverte juste devant elle arrête le tick :
    /// ni elle ni aucune suivante n'est admise, l'écrivain n'écrit plus rien, aucune famille à transaction n'y voit son
    /// `BEGIN` refusé, l'orpheline reste ouverte et intacte, le bilan nomme cette famille, et le tick aveugle est compté
    /// sous `regles` avec la cause de l'orpheline. Les règles avancées et de risque n'écrivent leur `last_run` que si
    /// l'orpheline est ouverte APRÈS elles.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer la sonde devant une famille (`sans_sonde:<jeton>`) ; ignorer l'arrêt
    /// après l'aveu devant une famille (`ignore:<jeton>`), y compris la DERNIÈRE (`ignore:SLA` : le SLA voit son `BEGIN`
    /// refusé dans l'orpheline).
    #[test]
    fn saft_une_orpheline_devant_chaque_famille_arrete_le_tick_sans_ecrire() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        set_engagement_mode(false);
        for (k, cible) in table_declaree!(SAFT_FAMILLES).iter().enumerate() {
            let (_tmp, p, db) = saft_base(&format!("saft-famille-{k}"));
            let avant = crate::metrics::tick_aveugle_de(BOUCLE_REGLES).map(|(n, _)| n).unwrap_or(0);
            let issue = saft_jouer(&db, &p, cible);
            saft_juger_l_orpheline(SAFT_FAMILLES, k, &issue);
            let (n, cause) = crate::metrics::tick_aveugle_de(BOUCLE_REGLES).expect("le tick aveugle est compté sous `regles`");
            assert!(n > avant, "orpheline devant « {cible} » : le compteur des ticks aveugles monte ({avant} -> {n})");
            assert_eq!(cause, CAUSE_TRANSACTION_ORPHELINE);
            assert_eq!(issue.avancee, k > 0, "orpheline devant « {cible} » : `last_run` de la règle avancée");
            assert_eq!(issue.risque, k > 1, "orpheline devant « {cible} » : `last_run` de la règle de risque");
        }
    }

    /// CONTRÔLE POSITIF, hors mode engagement : sans orpheline, la sonde admet les neuf familles et aucune des deux
    /// familles d'engagement (leurs sondes sont sous le drapeau), le tick est lu, et CHAQUE famille écrit au moins une
    /// ligne sur l'écrivain dans cette fixture — la dernière (SLA) comprise : l'égalité « aucun changement après
    /// l'orpheline » des témoins ci-dessus n'est vacante pour aucune famille.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : sonder hors du drapeau ; retirer la politique SLA de la fixture
    /// (`sans_politique_sla` : le SLA n'écrit plus rien) ; tenir le bilan des règles pour un aveu d'orpheline
    /// (`regles_toujours`).
    #[test]
    fn saft_sans_orpheline_chaque_famille_passe_et_ecrit() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        set_engagement_mode(false);
        let (_tmp, p, db) = saft_base("saft-sain");
        let issue = saft_jouer(&db, &p, "");
        assert!(matches!(issue.bilan, Mesure::Lue(_)), "écrivain sain : tick lu : {:?}", issue.bilan);
        assert_eq!(issue.admises, SAFT_FAMILLES.to_vec(), "mode engagement éteint : les neuf familles, pas celles d'engagement");
        let ecritures = saft_ecritures_par_famille(&issue);
        assert_eq!(ecritures.iter().map(|e| e.0).collect::<Vec<_>>(), SAFT_FAMILLES.to_vec(), "une marque devant chaque famille sondée");
        for (famille, n) in &ecritures {
            assert!(*n > 0, "fixture : « {famille} » n'écrit rien ({n} changement) — l'égalité des témoins serait vacante pour elle : {ecritures:?}");
        }
        assert_eq!(issue.injection, None);
        assert!(issue.autocommit && issue.marque == 0 && issue.orphelines_vues == 0 && issue.begins_refuses == 0);
        assert_eq!(issue.perimetre, None, "mode engagement éteint : aucun périmètre chargé");
        assert!(issue.avancee && issue.risque, "les deux règles ont écrit leur last_run");
        let froid = open_db(&p).unwrap();
        assert!(saft_last_run_pose(&froid, "saft-avancee") && saft_last_run_pose(&froid, "saft-risque"), "et c'est validé, vu à froid");
    }

    /// Remet le mode engagement éteint même si le témoin panique.
    struct SaftModeEngagement;
    impl Drop for SaftModeEngagement {
        fn drop(&mut self) {
            set_engagement_mode(false);
        }
    }

    /// CE QU'IL TIENT : sous le mode engagement, sans orpheline, les onze familles passent, chacune des dix premières
    /// écrit (l'expiration expire l'engagement échu), et le rafraîchissement — qui n'écrit rien — charge dans la carte du
    /// périmètre l'engagement dans sa fenêtre ; puis une orpheline devant l'une des deux familles d'engagement arrête le
    /// tick là, comme pour les autres, et la carte du périmètre reste vide pour cette base : le rafraîchissement n'a pas
    /// lu l'orpheline.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `sans_sonde:expiration`, `sans_sonde:rafra`, `ignore:expiration`,
    /// `ignore:rafra` (la DERNIÈRE famille : la carte du périmètre se remplit).
    #[test]
    fn saft_sous_le_mode_engagement_les_deux_familles_d_engagement_sont_sondees() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        let _remise = SaftModeEngagement;
        set_engagement_mode(true);
        let toutes: Vec<&'static str> = SAFT_FAMILLES.iter().chain(SAFT_FAMILLES_ENGAGEMENT).copied().collect();
        let (_tmp, p, db) = saft_base("saft-engagement-sain");
        let saine = saft_jouer(&db, &p, "");
        assert!(matches!(saine.bilan, Mesure::Lue(_)), "écrivain sain : tick lu : {:?}", saine.bilan);
        assert_eq!(saine.admises, toutes, "mode engagement : les onze familles passent la sonde");
        let ecritures = saft_ecritures_par_famille(&saine);
        assert_eq!(ecritures.iter().map(|e| e.0).collect::<Vec<_>>(), toutes, "une marque devant chaque famille sondée");
        for (famille, n) in &ecritures[..ecritures.len() - 1] {
            assert!(*n > 0, "fixture : « {famille} » n'écrit rien ({n} changement) — l'égalité des témoins serait vacante pour elle : {ecritures:?}");
        }
        assert_eq!(saine.perimetre, Some(vec!["saft-actif".to_string()]), "le rafraîchissement a chargé l'engagement dans sa fenêtre");
        let statut: String = open_db(&p).unwrap().query_row("SELECT status FROM engagement WHERE id='saft-expire'", [], |r| r.get(0)).unwrap();
        assert_eq!(statut, "expired", "l'expiration a écrit, vu à froid");
        for (k, cible) in toutes.iter().enumerate().skip(SAFT_FAMILLES.len()) {
            let (_tmp, p, db) = saft_base(&format!("saft-engagement-{k}"));
            let issue = saft_jouer(&db, &p, cible);
            saft_juger_l_orpheline(&toutes, k, &issue);
        }
    }

    /// CE QU'IL TIENT : une orpheline laissée PENDANT l'évaluation des règles est vue par la sonde de `run_due_rules`
    /// d'avant ses écritures, qui déclare le tick aveugle ; le tick s'arrête LÀ : aucune famille suivante n'est sondée
    /// (aucune marque du crochet de famille) ni admise, l'orpheline est vue UNE fois (une ligne de journal : la note
    /// « orpheline vue » est posée par la même sonde que la ligne), le bilan nomme les seules règles (« 1 famille(s) »),
    /// rien n'est écrit, l'orpheline reste intacte.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `double_compte` (le tick ne s'arrête plus après l'aveu des règles : la sonde
    /// des règles avancées revoit l'orpheline, deux notes, « 2 famille(s) »).
    #[test]
    fn saft_une_orpheline_vue_par_les_regles_arrete_le_tick_sans_second_compte() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        set_engagement_mode(false);
        let (_tmp, p, db) = saft_base("saft-regles");
        crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(saft_orpheline_pendant_les_regles));
        let issue = saft_jouer(&db, &p, "");
        crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(crate::handlers::detection::sans_crochet));
        saft_juger_le_bilan("règles", &issue.bilan);
        assert_eq!(issue.marques, Vec::<(&str, i64)>::new(), "aucune famille suivante n'est sondée");
        assert_eq!(issue.admises, Vec::<&str>::new(), "aucune famille suivante n'est admise");
        let injection = issue.injection.expect("instrument : le crochet des règles ne s'est pas déclenché");
        assert_eq!(issue.changements, injection, "rien n'est écrit après l'orpheline");
        assert_eq!(issue.orphelines_vues, 1, "l'orpheline est vue une seule fois");
        assert_eq!((issue.autocommit, issue.marque), (false, 1), "l'orpheline est intacte");
        assert!(!issue.avancee && !issue.risque, "ni règle avancée ni règle de risque évaluées");
    }

    /// CE QU'IL TIENT : l'arrêt après les règles ne vaut que pour l'AVEU de l'orpheline. Un bilan lu, ou aveugle pour une
    /// autre cause (liste des règles illisible), ne l'arrête pas ; le bilan qui porte le tick aveugle par orpheline des
    /// règles l'arrête.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `toute_cecite` (toute cécité des règles arrête le tick).
    #[test]
    fn saft_seul_l_aveu_d_orpheline_des_regles_arrete_le_tick() {
        let mut lu = BilanDuPlanificateur::default();
        lu.absorber(Mesure::Lue(2));
        assert!(!les_regles_ont_deja_declare_l_orpheline(&lu), "bilan lu");
        let mut liste = BilanDuPlanificateur::default();
        liste.absorber(crate::bilan_de_tick::tick_aveugle("règles", &rusqlite::Error::QueryReturnedNoRows));
        assert!(matches!(liste.bilan_de_tick(), Mesure::Illisible { cause, .. } if cause == CAUSE_SOURCE_ILLISIBLE), "fixture : bilan aveugle");
        assert!(!les_regles_ont_deja_declare_l_orpheline(&liste), "cécité d'une autre cause");
        let mut aveu = BilanDuPlanificateur::default();
        aveu.absorber(crate::bilan_de_tick::tick_aveugle_par_transaction_orpheline(BOUCLE_REGLES, "règles"));
        assert!(les_regles_ont_deja_declare_l_orpheline(&aveu), "aveu de l'orpheline par les règles");
    }

    /// Le corps de `tick_de_detection_d_un_tenant` APRÈS `run_due_rules` (qui porte ses propres sondes), jusqu'à la fin
    /// de la fonction.
    fn saft_corps_apres_les_regles(src: &str) -> &str {
        let debut = src.find("pub(crate) fn tick_de_detection_d_un_tenant(").expect("instrument : le tick a été renommé");
        let regles = "b.absorber(run_due_rules(handle, db_path));";
        let apres = debut + src[debut..].find(regles).expect("instrument : `run_due_rules` n'est plus appelée par le tick") + regles.len();
        let fin = apres + src[apres..].find("\n}\n").expect("instrument : fin du tick introuvable");
        &src[apres..fin]
    }

    /// LECTURE DU SOURCE (complément des témoins d'exécution, pour la famille de DEMAIN) : rend (les familles sondées,
    /// dans l'ordre ; les appels de famille qu'aucune sonde ne précède). Un appel de famille est une ligne de code qui
    /// finit par `);` — `let` compris (`let _ = run_x(…);`, `let n = run_x(…);`) — et n'est ni une sonde ni la prise du
    /// verrou (`let c = handle.lock();`) ; il consomme la sonde qui le précède.
    fn saft_sondes_et_familles_non_sondees(corps: &str) -> (Vec<String>, Vec<String>) {
        let mut sondees = Vec::new();
        let mut non_sondees = Vec::new();
        let mut sonde_en_attente = false;
        for ligne in corps.lines() {
            let code = ligne.split(" //").next().unwrap_or("").trim();
            if code.is_empty() || code.starts_with("//") {
                continue;
            }
            let prise_du_verrou = code.starts_with("let ") && code.ends_with("= handle.lock();");
            if let Some(reste) = code.strip_prefix("if orpheline_avant_la_famille(handle, \"") {
                sondees.push(reste.split('"').next().unwrap_or("").to_string());
                sonde_en_attente = true;
            } else if code.ends_with(");") && !prise_du_verrou {
                if !sonde_en_attente {
                    non_sondees.push(code.to_string());
                }
                sonde_en_attente = false;
            }
        }
        (sondees, non_sondees)
    }

    /// CE QU'IL TIENT : dans le source du tick, CHAQUE appel de famille après `run_due_rules` est précédé de sa sonde,
    /// et les familles sondées sont exactement, dans l'ordre, celles que les témoins d'exécution jouent — une famille
    /// ajoutée demain sans sonde, ou sans témoin, rougit ici. L'instrument est éprouvé sur quatre corps FABRIQUÉS à
    /// partir du vrai : une sonde retirée (devant les playbooks), une famille neuve sans sonde sous trois formes (appel
    /// nu, `let _ =`, `let n =`) ; chacune est accusée, et la ligne fautive est nommée.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `let_ignore` (les lignes `let` ne sont plus lues comme des appels de famille).
    #[test]
    fn saft_chaque_famille_du_tick_est_precedee_de_sa_sonde() {
        let corps = saft_corps_apres_les_regles(include_str!("../server/boucles_de_fond.rs"));
        let (sondees, non_sondees) = saft_sondes_et_familles_non_sondees(corps);
        let attendues: Vec<String> = SAFT_FAMILLES.iter().chain(SAFT_FAMILLES_ENGAGEMENT).map(|f| f.to_string()).collect();
        assert!(sondees.len() >= 11, "plancher : {} sonde(s) lue(s) dans le tick, onze attendues — la lecture est cassée", sondees.len());
        assert_eq!(sondees, attendues, "les familles sondées du tick sont celles que les témoins jouent, dans l'ordre");
        assert!(non_sondees.is_empty(), "appel(s) de famille sans sonde devant : {non_sondees:?}");

        let sonde_playbooks = "    if orpheline_avant_la_famille(handle, \"playbooks\", &mut b) { return b; }\n";
        assert!(corps.contains(sonde_playbooks), "instrument : la sonde des playbooks n'a plus cette forme");
        let (_, retiree) = saft_sondes_et_familles_non_sondees(&corps.replacen(sonde_playbooks, "", 1));
        assert_eq!(retiree, vec!["b.absorber(run_playbooks(handle, db_path));".to_string()], "une sonde retirée est accusée");

        let notifications = "    if orpheline_avant_la_famille(handle, \"notifications\", &mut b) { return b; }\n";
        assert!(corps.contains(notifications), "instrument : la sonde des notifications n'a plus cette forme");
        for neuve in [
            "b.absorber(run_famille_neuve(handle, db_path));",
            "let _ = run_famille_neuve(handle, db_path);",
            "let n = run_famille_neuve(handle, db_path);",
        ] {
            let (_, ajoutee) = saft_sondes_et_familles_non_sondees(&corps.replacen(notifications, &format!("    {neuve}\n{notifications}"), 1));
            assert_eq!(ajoutee, vec![neuve.to_string()], "une famille neuve sans sonde est accusée : {neuve}");
        }
    }
}
