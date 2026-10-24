// =====================================================================================
// `P10.31-j` (restes) — LA SONDE D'ORPHELINE EST REPRISE AVANT LES ÉCRITURES DES CINQ FAMILLES QUI ÉVALUENT HORS DU
// VERROU. Mesuré le 2026-10-24 sur 583aa34b : règles avancées (`alerting.rs`, cinq reprises de verrou qui écrivent :
// replanification après compilation refusée, après évaluation ratée, retour sous le seuil, état après lignes non lues,
// alertes et état), risque (`rba.rs`, phase 3), corrélations et lignes de base (`detection_advanced.rs`, phase 3) et
// playbooks (`playbooks.rs`, marqueur après compilation refusée, marqueur et ripostes) évaluaient hors du verrou puis le
// reprenaient pour ÉCRIRE sans sonder : une orpheline laissée pendant l'évaluation recevait ces écritures (visibles de
// l'écrivain seul, perdues au redémarrage). Seule `run_due_rules` re-sondait. Et une famille qui se serait déclarée
// aveugle aurait laissé le tick re-sonder la MÊME orpheline devant la famille suivante (double compte).
//
// LE TÉMOIN : le crochet `AVANT_LES_ECRITURES_DE_LA_FAMILLE` (appelé juste avant chaque reprise de verrou qui écrit,
// avec la famille et le site) note les changements de l'écrivain et ouvre l'orpheline devant le site visé. Chaque site
// a son témoin SEUL, avec son contrôle positif (même fixture sans orpheline : le site est atteint et la famille ÉCRIT
// après lui, donc « aucun changement après l'orpheline » n'est vacant). Les cinq familles sont aussi jouées par le TICK
// (`tick_de_detection_d_un_tenant`) : bilan « 1 famille(s) » nommant la famille, orpheline vue une seule fois, aucune
// famille suivante admise. Enfin la sonde de PHASE 1 de `run_due_rules` a son témoin propre : une orpheline ouverte
// avant l'appel arrête la règle AVANT l'évaluation (le crochet des écritures des règles n'est jamais atteint), là où la
// sonde de phase 3 seule laissait tout évaluer avant de le dire.
//
// MUTANTS JOUÉS (variable de mutation sous cfg!(test), retirés avant le commit), chacun rouge sur son témoin :
// AM3_ALERTING_COMPILATION, AM3_ALERTING_EVALUATION, AM3_ALERTING_SOUS_SEUIL, AM3_ALERTING_LIGNES, AM3_ALERTING_TIR,
// AM3_RBA, AM3_CORR, AM3_BASE, AM3_PB_COMPILATION, AM3_PB_RIPOSTES (la sonde du site retirée : verrou pris nu, crochet
// gardé) ; AM3_DC_AVANCEES, AM3_DC_RISQUE, AM3_DC_CORR, AM3_DC_BASE, AM3_DC_PB (l'arrêt après l'aveu de la famille
// retiré dans le tick : la sonde de la famille suivante revoit l'orpheline) ; AM3_PHASE1 (la sonde de phase 1 de
// `run_due_rules` retirée).
//
// LE SECOND TOUR DE BOUCLE. Règles avancées et playbooks reprennent le verrou à CHAQUE tour de leur boucle : les témoins
// `saef_second_tour_*` (deux règles, ou deux playbooks, par la même reprise) ouvrent l'orpheline à la SECONDE visite de
// la reprise visée — un témoin par reprise des deux familles, les cinq d'`alerting.rs` et les deux de `playbooks.rs`. Le
// risque, les corrélations et les lignes de base n'ont qu'une reprise, hors de toute boucle. Mutants joués, chacun
// rouge sur son témoin du second tour et vert sur ceux du premier : ONCE_AC, ONCE_AE, ONCE_AS, ONCE_AL, ONCE_AT,
// ONCE_PC, ONCE_PR (la reprise sondée à sa première visite seulement : verrou pris nu ensuite, crochet gardé) ;
// ONCE_AV_PARTAGE et ONCE_PB_PARTAGE (une seule sonde par appel de la famille, toutes reprises confondues).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le compteur GLOBAL des ticks aveugles est lu « monte » et non « +1 ». Il n'est
// pas isolable : `TICKS_AVEUGLES` est un compte de processus par balayage (ni par tenant ni par base), et les autres
// témoins qui versent sous `regles` (`tick_aveugle_sur_transaction_orpheline.rs`, `sonde_avant_chaque_famille_du_tick.rs`)
// ne prennent aucun verrou commun avec ceux-ci sous `cargo test` (fils parallèles). Un double compte qui ne passerait
// que par ce compteur resterait donc vert ; l'exactitude est tenue par la note « orpheline vue » de CETTE base (une
// seule) et par le bilan (« 1 famille(s) »). La phrase du bilan reste celle de
// `tick_aveugle_par_transaction_orpheline` (« rien n'est évalué ni écrit par <famille> ») alors qu'à ces sites
// l'évaluation a eu lieu et qu'un tour de boucle précédent a pu écrire (validé, hors de toute orpheline). Et la cause
// servie reste `CAUSE_SOURCE_ILLISIBLE` : aucune cause dédiée à l'orpheline n'est traduite par la console.
// =====================================================================================
mod sonde_avant_les_ecritures_des_familles {
    use super::*;
    use crate::bilan_de_tick::{BOUCLE_REGLES, CAUSE_TRANSACTION_ORPHELINE};
    use crate::handlers::alerting::{
        SITE_ALERTES_ET_ETAT, SITE_ETAT_APRES_LIGNES_NON_LUES, SITE_REPLANIFICATION_APRES_COMPILATION_REFUSEE,
        SITE_REPLANIFICATION_APRES_EVALUATION_RATEE, SITE_RETOUR_SOUS_LE_SEUIL,
    };
    use crate::handlers::detection_advanced::{SITE_ECRITURES_DES_CORRELATIONS, SITE_ECRITURES_DES_LIGNES_DE_BASE};
    use crate::handlers::playbooks::{SITE_MARQUEUR_APRES_COMPILATION_REFUSEE, SITE_MARQUEUR_ET_RIPOSTES};
    use crate::handlers::rba::SITE_CONTRIBUTIONS_ET_ETAT_DU_RISQUE;
    use crate::mesure_environnement::{Mesure, CAUSE_SOURCE_ILLISIBLE};
    use crate::server::boucles_de_fond::crochets_de_la_sonde_par_famille::{
        sans_crochet_d_ecritures, AVANT_LES_ECRITURES_DE_LA_FAMILLE, FAMILLES_ADMISES_PAR_LA_SONDE,
    };

    /// Une requête GXQL que le compilateur refuse (macro inconnue).
    const SAEF_REQUETE_QUI_NE_COMPILE_PAS: &str = "`macro_inexistante_saef`";
    /// Une requête SQL brute qui compile (aucune compilation) mais dont l'évaluation échoue (table absente).
    const SAEF_REQUETE_QUI_ECHOUE: &str = "SELECT COUNT(*) FROM table_absente_saef";
    /// Une requête GXQL qui rend le nombre d'événements de la fixture (un scalaire > 0).
    const SAEF_REQUETE_QUI_COMPTE: &str = "search source=saef | stats count";

    thread_local! {
        /// (famille, site) devant lequel le crochet ouvre l'orpheline ; ("", "") : jamais.
        static SAEF_CIBLE: std::cell::Cell<(&'static str, &'static str)> = const { std::cell::Cell::new(("", "")) };
        /// `total_changes()` de l'écrivain juste après l'ouverture de l'orpheline (`None` : jamais ouverte).
        static SAEF_INJECTION: std::cell::Cell<Option<i64>> = const { std::cell::Cell::new(None) };
        /// (famille, site, `total_changes()` de l'écrivain) noté à chaque reprise de verrou qui écrit, dans l'ordre.
        static SAEF_SITES: std::cell::RefCell<Vec<(&'static str, &'static str, i64)>> = const { std::cell::RefCell::new(Vec::new()) };
        /// Appels du crochet des écritures de `run_due_rules` (phase 3).
        static SAEF_PHASE_TROIS_ATTEINTE: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        /// Visites de la reprise visée (`SAEF_CIBLE`) par le crochet du SECOND tour.
        static SAEF_VISITES_DE_LA_CIBLE: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    fn saef_changements(c: &Connection) -> i64 {
        c.query_row("SELECT total_changes()", [], |r| r.get(0)).unwrap()
    }

    fn saef_ouvrir_l_orpheline(c: &Connection) {
        c.execute_batch("BEGIN IMMEDIATE; INSERT INTO meta(key,value) VALUES('saef','1');").expect("fixture : transaction laissée ouverte");
        SAEF_INJECTION.with(|i| i.set(Some(saef_changements(c))));
    }

    /// Le crochet des reprises de verrou qui écrivent : note le site et les changements ; devant la cible, ouvre l'orpheline.
    fn saef_crochet(db: &Arc<Mutex<Connection>>, famille: &'static str, site: &'static str) {
        let c = db.lock();
        SAEF_SITES.with(|s| s.borrow_mut().push((famille, site, saef_changements(&c))));
        if (famille, site) == SAEF_CIBLE.with(|c| c.get()) && SAEF_INJECTION.with(|i| i.get()).is_none() {
            saef_ouvrir_l_orpheline(&c);
        }
    }

    /// Le crochet du SECOND tour : note le site et les changements comme `saef_crochet`, mais n'ouvre l'orpheline qu'à la
    /// DEUXIÈME visite de la reprise visée — le premier tour de boucle est passé par elle et a écrit, hors de toute orpheline.
    fn saef_crochet_du_second_tour(db: &Arc<Mutex<Connection>>, famille: &'static str, site: &'static str) {
        let c = db.lock();
        SAEF_SITES.with(|s| s.borrow_mut().push((famille, site, saef_changements(&c))));
        if (famille, site) == SAEF_CIBLE.with(|c| c.get()) {
            let visite = SAEF_VISITES_DE_LA_CIBLE.with(|n| {
                n.set(n.get() + 1);
                n.get()
            });
            if visite == 2 && SAEF_INJECTION.with(|i| i.get()).is_none() {
                saef_ouvrir_l_orpheline(&c);
            }
        }
    }

    /// Le crochet des écritures de `run_due_rules` : compte ses appels.
    fn saef_noter_la_phase_trois(_db: &Arc<Mutex<Connection>>) {
        SAEF_PHASE_TROIS_ATTEINTE.with(|n| n.set(n.get() + 1));
    }

    /// Une base migrée, sans règle, alerte, corrélation, ligne de base ni playbook, avec trois événements `saef` récents.
    fn saef_base(tag: &str) -> (crate::tmp_possede::TmpPossede, String, Arc<Mutex<Connection>>) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute_batch("DELETE FROM rule; DELETE FROM alert; DELETE FROM correlation; DELETE FROM ueba_baseline; DELETE FROM playbook;")
                .unwrap();
            let maintenant = now();
            for i in 0..3 {
                conn.execute(
                    "INSERT INTO event(ts,source,category,severity,message,src_ip,host,dedup) VALUES(?1,'saef','auth',1,'échec','192.0.2.10','h1',?2)",
                    params![maintenant - 10, format!("saef-{i}")],
                )
                .unwrap();
            }
        }
        (tmp, p, db)
    }

    /// Une règle avancée (fenêtre de suppression 600 s, throttle par `src_ip` si `throttle`), due.
    fn saef_regle_avancee(db: &Arc<Mutex<Connection>>, query: &str, is_soql: bool, threshold: f64, throttle: bool) {
        db.lock()
            .execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,suppress_window_s,throttle_field) \
                 VALUES('saef-avancee',1,?1,?2,'>',?3,2,0,3600,600,?4)",
                params![query, is_soql as i64, threshold, if throttle { "src_ip" } else { "" }],
            )
            .unwrap();
    }

    fn saef_regle_de_risque(db: &Arc<Mutex<Connection>>) {
        db.lock()
            .execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,risk_score,risk_entity_type,risk_entity_field) \
                 VALUES('saef-risque',1,'search source=saef | stats count by source',1,'>',0,2,0,3600,5,'host','source')",
                [],
            )
            .unwrap();
    }

    /// Étapes vides : l'évaluation échoue, `last_run` avance quand même (une écriture après la reprise).
    fn saef_correlation(db: &Arc<Mutex<Connection>>) {
        db.lock().execute("INSERT INTO correlation(name,enabled,steps,interval_s) VALUES('saef',1,'[]',300)", []).unwrap();
    }

    fn saef_ligne_de_base(db: &Arc<Mutex<Connection>>) {
        db.lock()
            .execute(
                "INSERT INTO ueba_baseline(name,enabled,query,entity_field,value_field) VALUES('saef',1,'search source=saef | stats count by host','host','count')",
                [],
            )
            .unwrap();
    }

    fn saef_playbook(db: &Arc<Mutex<Connection>>, query: &str) {
        db.lock()
            .execute(
                "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s) VALUES('saef',1,?1,1,'ban_ip',300,3600)",
                params![query],
            )
            .unwrap();
    }

    /// Ce qu'une famille (ou un tick) a laissé, lu sur l'écrivain AVANT de fermer l'orpheline.
    struct SaefIssue {
        bilan: crate::bilan_de_tick::BilanDeTick,
        sites: Vec<(&'static str, &'static str, i64)>,
        admises: Vec<&'static str>,
        injection: Option<i64>,
        changements: i64,
        autocommit: bool,
        marque: i64,
        orphelines_vues: u64,
        compteur_avant: u64,
        compteur_apres: Option<(u64, String)>,
    }

    /// Joue `jouer` (la famille, ou le tick), l'orpheline ouverte devant `cible` à sa PREMIÈRE visite, puis ferme l'orpheline.
    fn saef_jouer(
        db: &Arc<Mutex<Connection>>,
        cible: (&'static str, &'static str),
        jouer: impl FnOnce() -> crate::bilan_de_tick::BilanDeTick,
    ) -> SaefIssue {
        saef_jouer_avec(db, cible, saef_crochet, jouer)
    }

    /// Joue `jouer` sous le crochet des écritures `crochet` (qui décide à quelle visite de `cible` il ouvre l'orpheline),
    /// puis ferme l'orpheline.
    fn saef_jouer_avec(
        db: &Arc<Mutex<Connection>>,
        cible: (&'static str, &'static str),
        crochet: fn(&Arc<Mutex<Connection>>, &'static str, &'static str),
        jouer: impl FnOnce() -> crate::bilan_de_tick::BilanDeTick,
    ) -> SaefIssue {
        SAEF_CIBLE.with(|c| c.set(cible));
        SAEF_INJECTION.with(|i| i.set(None));
        SAEF_SITES.with(|s| s.borrow_mut().clear());
        SAEF_VISITES_DE_LA_CIBLE.with(|n| n.set(0));
        FAMILLES_ADMISES_PAR_LA_SONDE.with(|v| v.borrow_mut().clear());
        let compteur_avant = crate::metrics::tick_aveugle_de(BOUCLE_REGLES).map(|(n, _)| n).unwrap_or(0);
        AVANT_LES_ECRITURES_DE_LA_FAMILLE.with(|h| h.set(crochet));
        let bilan = jouer();
        AVANT_LES_ECRITURES_DE_LA_FAMILLE.with(|h| h.set(sans_crochet_d_ecritures));
        let compteur_apres = crate::metrics::tick_aveugle_de(BOUCLE_REGLES);
        let issue = {
            let c = db.lock();
            SaefIssue {
                bilan,
                sites: SAEF_SITES.with(|s| s.borrow().clone()),
                admises: FAMILLES_ADMISES_PAR_LA_SONDE.with(|v| v.borrow().clone()),
                injection: SAEF_INJECTION.with(|i| i.get()),
                changements: saef_changements(&c),
                autocommit: c.is_autocommit(),
                marque: c.query_row("SELECT COUNT(*) FROM meta WHERE key='saef'", [], |r| r.get(0)).unwrap(),
                orphelines_vues: crate::comptes_de_transaction::compte_des_temoins(&c, "orpheline vue"),
                compteur_avant,
                compteur_apres,
            }
        };
        if !issue.autocommit {
            db.lock().execute_batch("ROLLBACK").expect("fixture : fermeture de l'orpheline");
        }
        issue
    }

    /// Le détail exact du tick aveugle d'une famille.
    fn saef_detail(famille: &str) -> String {
        format!(
            "{famille} : aveugle, l'écrivain porte une transaction orpheline ({CAUSE_TRANSACTION_ORPHELINE}) — rien n'est \
             évalué ni écrit par {famille} ce tick, la transaction n'est pas annulée"
        )
    }

    /// Les assertions communes d'une orpheline ouverte devant (famille, site), quel que soit l'appelant.
    fn saef_juger_l_orpheline(famille: &'static str, site: &'static str, issue: &SaefIssue) {
        let vus: Vec<(&str, &str)> = issue.sites.iter().map(|s| (s.0, s.1)).collect();
        assert_eq!(vus.last(), Some(&(famille, site)), "la dernière reprise de verrou atteinte est celle visée : {vus:?}");
        let injection = issue.injection.unwrap_or_else(|| panic!("instrument : le crochet ne s'est pas déclenché devant « {famille} / {site} »"));
        assert_eq!(issue.changements, injection, "« {famille} / {site} » : aucune écriture de l'écrivain après l'orpheline");
        assert!(!issue.autocommit, "« {famille} / {site} » : la transaction est toujours ouverte");
        assert_eq!(issue.marque, 1, "« {famille} / {site} » : c'est la même orpheline, ni annulée ni remplacée");
        assert_eq!(issue.orphelines_vues, 1, "« {famille} / {site} » : l'orpheline est vue une seule fois");
        let (n, cause) = issue.compteur_apres.clone().expect("le tick aveugle est compté sous `regles`");
        assert!(n > issue.compteur_avant, "« {famille} / {site} » : le compteur des ticks aveugles monte ({} -> {n})", issue.compteur_avant);
        assert_eq!(cause, CAUSE_TRANSACTION_ORPHELINE);
    }

    /// Une famille jouée SEULE, l'orpheline ouverte devant (famille, site) : bilan aveugle exact, rien d'écrit après.
    fn saef_juger_la_famille_aveugle(famille: &'static str, site: &'static str, issue: &SaefIssue) {
        assert_eq!(
            issue.bilan,
            Mesure::Illisible { cause: CAUSE_SOURCE_ILLISIBLE, detail: saef_detail(famille) },
            "« {famille} / {site} » : la famille se déclare aveugle, nommée"
        );
        saef_juger_l_orpheline(famille, site, issue);
    }

    /// CONTRÔLE POSITIF d'un site : sans orpheline, la reprise visée est atteinte (une fois, dernière), la famille ÉCRIT
    /// après elle (l'égalité du témoin n'est pas vacante), rien n'est vu, le bilan est lu.
    fn saef_juger_le_site_sain(famille: &'static str, site: &'static str, issue: &SaefIssue) {
        assert!(matches!(issue.bilan, Mesure::Lue(_)), "« {famille} / {site} » sans orpheline : bilan lu : {:?}", issue.bilan);
        let (f, s, avant) = *issue.sites.last().unwrap_or_else(|| panic!("fixture : aucune reprise de verrou atteinte pour « {famille} / {site} »"));
        assert_eq!((f, s), (famille, site), "fixture : la dernière reprise atteinte est celle visée : {:?}", issue.sites);
        assert!(issue.changements > avant, "fixture : « {famille} / {site} » n'écrit rien après la reprise — le témoin serait vacant");
        assert_eq!(issue.injection, None);
        assert!(issue.autocommit && issue.marque == 0 && issue.orphelines_vues == 0);
    }

    /// Joue une famille directement deux fois — base saine, puis base neuve avec l'orpheline devant le site — et juge.
    fn saef_site(
        tag: &str,
        famille: &'static str,
        site: &'static str,
        preparer: impl Fn(&Arc<Mutex<Connection>>),
        famille_fn: fn(&Arc<Mutex<Connection>>, &str) -> crate::bilan_de_tick::BilanDeTick,
    ) {
        let (_t1, p1, db1) = saef_base(&format!("saef-{tag}-sain"));
        preparer(&db1);
        let sain = saef_jouer(&db1, ("", ""), || famille_fn(&db1, &p1));
        saef_juger_le_site_sain(famille, site, &sain);
        let (_t2, p2, db2) = saef_base(&format!("saef-{tag}-orpheline"));
        preparer(&db2);
        let issue = saef_jouer(&db2, (famille, site), || famille_fn(&db2, &p2));
        saef_juger_la_famille_aveugle(famille, site, &issue);
    }

    /// Retire le crochet des préparations même si le témoin panique.
    struct SaefRetirerLeCrochetDePreparation;
    impl Drop for SaefRetirerLeCrochetDePreparation {
        fn drop(&mut self) {
            crate::query_exec::avant_la_preparation_de_ce_fil(None);
        }
    }

    // ---------------------------------------------------------------- règles avancées (`alerting.rs`)

    /// CE QU'IL TIENT : une orpheline ouverte après la compilation refusée d'une règle avancée, avant sa replanification,
    /// est vue : la famille se déclare aveugle, `last_run` n'est pas écrit dans l'orpheline. Contrôle positif : sans
    /// orpheline, la replanification écrit.
    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_ALERTING_COMPILATION.
    #[test]
    fn saef_regles_avancees_replanification_apres_compilation_refusee() {
        assert!(crate::handlers::detection::rule_sql(SAEF_REQUETE_QUI_NE_COMPILE_PAS, true, 3600).is_err(), "fixture : la requête ne compile pas");
        saef_site(
            "av-compil",
            "règles avancées",
            SITE_REPLANIFICATION_APRES_COMPILATION_REFUSEE,
            |db| saef_regle_avancee(db, SAEF_REQUETE_QUI_NE_COMPILE_PAS, true, 0.0, false),
            crate::handlers::alerting::run_advanced_rules,
        );
    }

    /// CE QU'IL TIENT : même chose après une évaluation ratée (SQL brut sur une table absente).
    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_ALERTING_EVALUATION.
    #[test]
    fn saef_regles_avancees_replanification_apres_evaluation_ratee() {
        saef_site(
            "av-eval",
            "règles avancées",
            SITE_REPLANIFICATION_APRES_EVALUATION_RATEE,
            |db| saef_regle_avancee(db, SAEF_REQUETE_QUI_ECHOUE, false, 0.0, false),
            crate::handlers::alerting::run_advanced_rules,
        );
    }

    /// CE QU'IL TIENT : même chose au retour sous le seuil (état, résolution, purge du throttle).
    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_ALERTING_SOUS_SEUIL.
    #[test]
    fn saef_regles_avancees_retour_sous_le_seuil() {
        saef_site(
            "av-seuil",
            "règles avancées",
            SITE_RETOUR_SOUS_LE_SEUIL,
            |db| saef_regle_avancee(db, SAEF_REQUETE_QUI_COMPTE, true, 1000.0, false),
            crate::handlers::alerting::run_advanced_rules,
        );
    }

    /// CE QU'IL TIENT : même chose quand le scalaire est lu puis que les LIGNES ne s'évaluent pas (`run_query_ex` en
    /// erreur, fabriqué par le crochet du fil appelant : la table `event` est retirée entre les deux préparations) —
    /// l'état écrit à cette reprise n'entre pas dans l'orpheline.
    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_ALERTING_LIGNES.
    #[test]
    fn saef_regles_avancees_etat_apres_lignes_non_lues() {
        let _retrait = SaefRetirerLeCrochetDePreparation;
        saef_site(
            "av-lignes",
            "règles avancées",
            SITE_ETAT_APRES_LIGNES_NON_LUES,
            |db| saef_regle_avancee(db, "search source=saef | stats count by src_ip", true, 0.0, true),
            |db, p| {
                let preparations = Arc::new(std::sync::atomic::AtomicU32::new(0));
                let (compte, chemin) = (preparations.clone(), p.to_string());
                crate::query_exec::avant_la_preparation_de_ce_fil(Some(Box::new(move || {
                    if compte.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                        open_db(&chemin).unwrap().execute_batch("DROP TABLE event;").expect("fixture : retrait de la table event");
                    }
                })));
                let bilan = crate::handlers::alerting::run_advanced_rules(db, p);
                crate::query_exec::avant_la_preparation_de_ce_fil(None);
                assert_eq!(preparations.load(std::sync::atomic::Ordering::SeqCst), 2, "instrument : le scalaire puis les lignes");
                bilan
            },
        );
    }

    /// CE QU'IL TIENT : même chose au tir (alertes, throttle, état, `last_fired`) : aucune alerte dans l'orpheline.
    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_ALERTING_TIR.
    #[test]
    fn saef_regles_avancees_alertes_et_etat() {
        saef_site(
            "av-tir",
            "règles avancées",
            SITE_ALERTES_ET_ETAT,
            |db| saef_regle_avancee(db, SAEF_REQUETE_QUI_COMPTE, true, 0.0, false),
            crate::handlers::alerting::run_advanced_rules,
        );
    }

    // ---------------------------------------------------------------- risque, corrélations, lignes de base, playbooks

    /// CE QU'IL TIENT : une orpheline ouverte après l'évaluation des règles de risque, avant la phase 3 : ni contribution
    /// ni `last_run` dans l'orpheline, la famille se déclare aveugle.
    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_RBA.
    #[test]
    fn saef_regles_de_risque_phase_trois() {
        saef_site("risque", "règles de risque", SITE_CONTRIBUTIONS_ET_ETAT_DU_RISQUE, saef_regle_de_risque, crate::handlers::rba::run_risk_rules);
    }

    /// CE QU'IL TIENT : même chose pour les corrélations (phase 3 après l'évaluation en fils).
    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_CORR.
    #[test]
    fn saef_correlations_phase_trois() {
        saef_site("corr", "corrélations", SITE_ECRITURES_DES_CORRELATIONS, saef_correlation, crate::handlers::detection_advanced::run_correlations);
    }

    /// CE QU'IL TIENT : même chose pour les lignes de base (phase 3, après le verrou de l'évaluation rendu).
    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_BASE.
    #[test]
    fn saef_lignes_de_base_phase_trois() {
        saef_site("base", "lignes de base", SITE_ECRITURES_DES_LIGNES_DE_BASE, saef_ligne_de_base, crate::handlers::detection_advanced::run_baselines);
    }

    /// CE QU'IL TIENT : une orpheline ouverte après la compilation refusée d'un playbook, avant son marqueur de passage :
    /// le marqueur n'entre pas dans l'orpheline, la famille se déclare aveugle.
    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_PB_COMPILATION.
    #[test]
    fn saef_playbooks_marqueur_apres_compilation_refusee() {
        saef_site(
            "pb-compil",
            "playbooks",
            SITE_MARQUEUR_APRES_COMPILATION_REFUSEE,
            |db| saef_playbook(db, SAEF_REQUETE_QUI_NE_COMPILE_PAS),
            crate::handlers::playbooks::run_playbooks,
        );
    }

    /// CE QU'IL TIENT : une orpheline ouverte après la sélection des cibles, avant le marqueur et les ripostes : rien
    /// n'entre dans l'orpheline, la famille se déclare aveugle.
    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_PB_RIPOSTES.
    #[test]
    fn saef_playbooks_marqueur_et_ripostes() {
        saef_site("pb-ripostes", "playbooks", SITE_MARQUEUR_ET_RIPOSTES, |db| saef_playbook(db, SAEF_REQUETE_QUI_COMPTE), crate::handlers::playbooks::run_playbooks);
    }

    // ---------------------------------------------------------------- le SECOND tour de boucle (règles avancées, playbooks)

    /// Ce qu'un tour de boucle écrit à la reprise visée et qui reste, compté après la fermeture de l'orpheline.
    const SAEF_REGLES_ECRITES: &str = "SELECT COUNT(*) FROM rule WHERE last_run IS NOT NULL";
    const SAEF_ALERTES_ECRITES: &str = "SELECT COUNT(*) FROM alert";
    const SAEF_PLAYBOOKS_MARQUES: &str = "SELECT COUNT(*) FROM playbook WHERE last_run IS NOT NULL";

    fn saef_compter(db: &Arc<Mutex<Connection>>, sql: &str) -> i64 {
        db.lock().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    /// Joue une famille dont la fixture porte DEUX éléments dus (deux règles avancées, ou deux playbooks) qui passent par
    /// la MÊME reprise de verrou :
    /// - CONTRÔLE POSITIF, base saine : la reprise visée est visitée deux fois et seule, chaque tour écrit (`ecrit_par_tour`
    ///   vaut 2) et l'écrivain change après la seconde visite (l'égalité du témoin n'est pas vacante au second tour) ;
    /// - base neuve, l'orpheline ouverte à la SECONDE visite : la famille se déclare aveugle, nommée ; rien n'entre dans
    ///   l'orpheline ; ce que le premier tour a écrit reste (validé, hors de toute orpheline : `ecrit_par_tour` vaut 1 une
    ///   fois l'orpheline annulée par la fixture). Une sonde faite au premier tour seulement laisse écrire le second.
    fn saef_second_tour(
        tag: &str,
        famille: &'static str,
        site: &'static str,
        preparer: impl Fn(&Arc<Mutex<Connection>>),
        ecrit_par_tour: &str,
        famille_fn: fn(&Arc<Mutex<Connection>>, &str) -> crate::bilan_de_tick::BilanDeTick,
    ) {
        let (_t1, p1, db1) = saef_base(&format!("saef-{tag}-2t-sain"));
        preparer(&db1);
        preparer(&db1);
        let sain = saef_jouer_avec(&db1, ("", ""), saef_crochet_du_second_tour, || famille_fn(&db1, &p1));
        assert!(matches!(sain.bilan, Mesure::Lue(_)), "« {famille} / {site} » sans orpheline, deux tours : bilan lu : {:?}", sain.bilan);
        let vus: Vec<(&str, &str)> = sain.sites.iter().map(|s| (s.0, s.1)).collect();
        assert_eq!(vus, vec![(famille, site), (famille, site)], "fixture : deux tours, tous deux par « {famille} / {site} »");
        assert!(sain.changements > sain.sites[1].2, "fixture : le second tour n'écrit rien après sa reprise — le témoin serait vacant");
        assert_eq!(saef_compter(&db1, ecrit_par_tour), 2, "fixture : chaque tour écrit ({ecrit_par_tour})");
        assert!(sain.injection.is_none() && sain.autocommit && sain.orphelines_vues == 0);

        let (_t2, p2, db2) = saef_base(&format!("saef-{tag}-2t-orpheline"));
        preparer(&db2);
        preparer(&db2);
        let issue = saef_jouer_avec(&db2, (famille, site), saef_crochet_du_second_tour, || famille_fn(&db2, &p2));
        let vus: Vec<(&str, &str)> = issue.sites.iter().map(|s| (s.0, s.1)).collect();
        assert_eq!(vus, vec![(famille, site), (famille, site)], "« {famille} / {site} » : deux tours, l'orpheline ouverte au second");
        assert!(issue.sites[1].2 > issue.sites[0].2, "« {famille} / {site} » : le premier tour a écrit avant l'orpheline");
        saef_juger_la_famille_aveugle(famille, site, &issue);
        assert_eq!(
            saef_compter(&db2, ecrit_par_tour),
            1,
            "« {famille} / {site} » : ce que le premier tour a écrit reste, rien du second ({ecrit_par_tour})"
        );
    }

    /// CE QU'IL TIENT : au SECOND tour, l'orpheline ouverte après la compilation refusée de la seconde règle avancée est
    /// vue : rien n'est replanifié dans l'orpheline, la replanification du premier tour reste.
    /// LES MUTATIONS QUI LE FONT ROUGIR : ONCE_AC, ONCE_AV_PARTAGE.
    #[test]
    fn saef_second_tour_regles_avancees_replanification_apres_compilation_refusee() {
        saef_second_tour(
            "av-compil",
            "règles avancées",
            SITE_REPLANIFICATION_APRES_COMPILATION_REFUSEE,
            |db| saef_regle_avancee(db, SAEF_REQUETE_QUI_NE_COMPILE_PAS, true, 0.0, false),
            SAEF_REGLES_ECRITES,
            crate::handlers::alerting::run_advanced_rules,
        );
    }

    /// CE QU'IL TIENT : même chose au second tour après une évaluation ratée.
    /// LES MUTATIONS QUI LE FONT ROUGIR : ONCE_AE, ONCE_AV_PARTAGE.
    #[test]
    fn saef_second_tour_regles_avancees_replanification_apres_evaluation_ratee() {
        saef_second_tour(
            "av-eval",
            "règles avancées",
            SITE_REPLANIFICATION_APRES_EVALUATION_RATEE,
            |db| saef_regle_avancee(db, SAEF_REQUETE_QUI_ECHOUE, false, 0.0, false),
            SAEF_REGLES_ECRITES,
            crate::handlers::alerting::run_advanced_rules,
        );
    }

    /// CE QU'IL TIENT : même chose au second tour revenu sous le seuil (l'état du premier tour reste).
    /// LES MUTATIONS QUI LE FONT ROUGIR : ONCE_AS, ONCE_AV_PARTAGE.
    #[test]
    fn saef_second_tour_regles_avancees_retour_sous_le_seuil() {
        saef_second_tour(
            "av-seuil",
            "règles avancées",
            SITE_RETOUR_SOUS_LE_SEUIL,
            |db| saef_regle_avancee(db, SAEF_REQUETE_QUI_COMPTE, true, 1000.0, false),
            SAEF_REGLES_ECRITES,
            crate::handlers::alerting::run_advanced_rules,
        );
    }

    /// CE QU'IL TIENT : même chose au second tour dont les LIGNES ne s'évaluent pas. Le crochet du fil appelant écarte
    /// la table `event` (renommée) avant les lignes de chaque tour et la rend avant le scalaire du second : quatre
    /// préparations, scalaire lu puis lignes en erreur à chaque tour.
    /// LES MUTATIONS QUI LE FONT ROUGIR : ONCE_AL, ONCE_AV_PARTAGE.
    #[test]
    fn saef_second_tour_regles_avancees_etat_apres_lignes_non_lues() {
        let _retrait = SaefRetirerLeCrochetDePreparation;
        saef_second_tour(
            "av-lignes",
            "règles avancées",
            SITE_ETAT_APRES_LIGNES_NON_LUES,
            |db| saef_regle_avancee(db, "search source=saef | stats count by src_ip", true, 0.0, true),
            SAEF_REGLES_ECRITES,
            |db, p| {
                let preparations = Arc::new(std::sync::atomic::AtomicU32::new(0));
                let (compte, chemin) = (preparations.clone(), p.to_string());
                crate::query_exec::avant_la_preparation_de_ce_fil(Some(Box::new(move || {
                    let ddl = match compte.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                        1 | 3 => "ALTER TABLE event RENAME TO saef_event_ecartee;",
                        2 => "ALTER TABLE saef_event_ecartee RENAME TO event;",
                        _ => return,
                    };
                    open_db(&chemin).unwrap().execute_batch(ddl).expect("fixture : table event écartée puis rendue");
                })));
                let bilan = crate::handlers::alerting::run_advanced_rules(db, p);
                crate::query_exec::avant_la_preparation_de_ce_fil(None);
                assert_eq!(preparations.load(std::sync::atomic::Ordering::SeqCst), 4, "instrument : scalaire puis lignes, deux tours");
                bilan
            },
        );
    }

    /// CE QU'IL TIENT : même chose au tir du second tour : l'alerte du premier tour reste, aucune du second n'entre dans
    /// l'orpheline.
    /// LES MUTATIONS QUI LE FONT ROUGIR : ONCE_AT, ONCE_AV_PARTAGE.
    #[test]
    fn saef_second_tour_regles_avancees_alertes_et_etat() {
        saef_second_tour(
            "av-tir",
            "règles avancées",
            SITE_ALERTES_ET_ETAT,
            |db| saef_regle_avancee(db, SAEF_REQUETE_QUI_COMPTE, true, 0.0, false),
            SAEF_ALERTES_ECRITES,
            crate::handlers::alerting::run_advanced_rules,
        );
    }

    /// CE QU'IL TIENT : au second tour, l'orpheline ouverte après la compilation refusée du second playbook est vue : son
    /// marqueur n'entre pas dans l'orpheline, celui du premier reste.
    /// LES MUTATIONS QUI LE FONT ROUGIR : ONCE_PC, ONCE_PB_PARTAGE.
    #[test]
    fn saef_second_tour_playbooks_marqueur_apres_compilation_refusee() {
        saef_second_tour(
            "pb-compil",
            "playbooks",
            SITE_MARQUEUR_APRES_COMPILATION_REFUSEE,
            |db| saef_playbook(db, SAEF_REQUETE_QUI_NE_COMPILE_PAS),
            SAEF_PLAYBOOKS_MARQUES,
            crate::handlers::playbooks::run_playbooks,
        );
    }

    /// CE QU'IL TIENT : au second tour, l'orpheline ouverte après la sélection des cibles du second playbook est vue : ni
    /// marqueur ni riposte dans l'orpheline, le marqueur du premier reste.
    /// LES MUTATIONS QUI LE FONT ROUGIR : ONCE_PR, ONCE_PB_PARTAGE.
    #[test]
    fn saef_second_tour_playbooks_marqueur_et_ripostes() {
        saef_second_tour(
            "pb-ripostes",
            "playbooks",
            SITE_MARQUEUR_ET_RIPOSTES,
            |db| saef_playbook(db, SAEF_REQUETE_QUI_COMPTE),
            SAEF_PLAYBOOKS_MARQUES,
            crate::handlers::playbooks::run_playbooks,
        );
    }

    // ---------------------------------------------------------------- par le tick : un seul compte, rien après

    /// Les familles du tick sondées avant chacune (`orpheline_avant_la_famille`), dans l'ordre, jusqu'aux playbooks.
    const SAEF_FAMILLES_DU_TICK: [&str; 5] = ["règles avancées", "règles de risque", "corrélations", "lignes de base", "playbooks"];

    /// Une base où chacune des cinq familles atteint sa reprise de verrou principale et écrit.
    fn saef_base_du_tick(tag: &str) -> (crate::tmp_possede::TmpPossede, String, Arc<Mutex<Connection>>) {
        let (tmp, p, db) = saef_base(tag);
        saef_regle_avancee(&db, SAEF_REQUETE_QUI_COMPTE, true, 0.0, false);
        saef_regle_de_risque(&db);
        saef_correlation(&db);
        saef_ligne_de_base(&db);
        saef_playbook(&db, SAEF_REQUETE_QUI_COMPTE);
        (tmp, p, db)
    }

    /// Joue le tick, l'orpheline ouverte devant (famille, site) — la famille de rang `k` du tick — et juge : le bilan dit
    /// « 1 famille(s) » nommant cette famille, l'orpheline est vue une fois (aucune sonde suivante ne la revoit), seules
    /// les familles jusqu'à elle ont été admises, rien n'est écrit après l'orpheline.
    fn saef_tick(k: usize, site: &'static str) {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        set_engagement_mode(false);
        let famille = SAEF_FAMILLES_DU_TICK[k];
        let (_t, p, db) = saef_base_du_tick(&format!("saef-tick-{k}"));
        let issue = saef_jouer(&db, (famille, site), || crate::server::boucles_de_fond::tick_de_detection_d_un_tenant(&db, &p).bilan_de_tick());
        match &issue.bilan {
            Mesure::Illisible { cause, detail } => {
                assert_eq!(*cause, CAUSE_SOURCE_ILLISIBLE);
                let tete = format!("1 famille(s) aveugle(s) ce tick — {} ; abandons comptés par ailleurs : ", saef_detail(famille));
                let reste = detail.strip_prefix(tete.as_str()).unwrap_or_else(|| panic!("« {famille} » par le tick : bilan inattendu : {detail}"));
                assert!(!reste.is_empty() && reste.bytes().all(|o| o.is_ascii_digit()), "« {famille} » par le tick : bilan inattendu : {detail}");
            }
            Mesure::Lue(n) => panic!("« {famille} » par le tick : le tick se dit lu ({n} abandon(s))"),
        }
        assert_eq!(issue.admises, SAEF_FAMILLES_DU_TICK[..=k].to_vec(), "« {famille} » par le tick : aucune famille suivante admise");
        saef_juger_l_orpheline(famille, site, &issue);
    }

    /// CONTRÔLE POSITIF du tick : sans orpheline, les cinq reprises principales sont atteintes dans l'ordre et chacune
    /// écrit après elle — les témoins par le tick ci-dessous ne sont vacants pour aucune famille.
    #[test]
    fn saef_tick_sans_orpheline_chaque_famille_atteint_sa_reprise_et_ecrit() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        set_engagement_mode(false);
        let (_t, p, db) = saef_base_du_tick("saef-tick-sain");
        let issue = saef_jouer(&db, ("", ""), || crate::server::boucles_de_fond::tick_de_detection_d_un_tenant(&db, &p).bilan_de_tick());
        assert!(matches!(issue.bilan, Mesure::Lue(_)), "écrivain sain : tick lu : {:?}", issue.bilan);
        let vus: Vec<(&str, &str)> = issue.sites.iter().map(|s| (s.0, s.1)).collect();
        assert_eq!(
            vus,
            vec![
                ("règles avancées", SITE_ALERTES_ET_ETAT),
                ("règles de risque", SITE_CONTRIBUTIONS_ET_ETAT_DU_RISQUE),
                ("corrélations", SITE_ECRITURES_DES_CORRELATIONS),
                ("lignes de base", SITE_ECRITURES_DES_LIGNES_DE_BASE),
                ("playbooks", SITE_MARQUEUR_ET_RIPOSTES),
            ],
            "fixture : chaque famille atteint sa reprise principale, une fois"
        );
        for (i, (famille, site, avant)) in issue.sites.iter().enumerate() {
            let apres = issue.sites.get(i + 1).map(|s| s.2).unwrap_or(issue.changements);
            assert!(apres > *avant, "fixture : « {famille} / {site} » n'écrit rien après sa reprise — le témoin par le tick serait vacant");
        }
        assert!(issue.autocommit && issue.orphelines_vues == 0);
    }

    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_DC_AVANCEES (et AM3_ALERTING_TIR).
    #[test]
    fn saef_tick_orpheline_aux_ecritures_des_regles_avancees_un_seul_compte() {
        saef_tick(0, SITE_ALERTES_ET_ETAT);
    }

    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_DC_RISQUE (et AM3_RBA).
    #[test]
    fn saef_tick_orpheline_aux_ecritures_du_risque_un_seul_compte() {
        saef_tick(1, SITE_CONTRIBUTIONS_ET_ETAT_DU_RISQUE);
    }

    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_DC_CORR (et AM3_CORR).
    #[test]
    fn saef_tick_orpheline_aux_ecritures_des_correlations_un_seul_compte() {
        saef_tick(2, SITE_ECRITURES_DES_CORRELATIONS);
    }

    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_DC_BASE (et AM3_BASE).
    #[test]
    fn saef_tick_orpheline_aux_ecritures_des_lignes_de_base_un_seul_compte() {
        saef_tick(3, SITE_ECRITURES_DES_LIGNES_DE_BASE);
    }

    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_DC_PB (et AM3_PB_RIPOSTES).
    #[test]
    fn saef_tick_orpheline_aux_ecritures_des_playbooks_un_seul_compte() {
        saef_tick(4, SITE_MARQUEUR_ET_RIPOSTES);
    }

    // ---------------------------------------------------------------- la sonde de phase 1 de `run_due_rules`

    /// CE QU'IL TIENT : une orpheline ouverte AVANT l'appel de `run_due_rules` est vue par sa sonde de PHASE 1 : la règle
    /// n'est pas évaluée — le crochet des écritures (entre évaluation et phase 3) n'est jamais atteint —, le bilan nomme
    /// les règles, rien n'est écrit, l'orpheline est vue une fois et reste intacte. La sonde de phase 3 seule rendrait le
    /// même bilan APRÈS avoir tout évalué : seul le crochet les distingue. Contrôle positif : sans orpheline, le crochet
    /// est atteint une fois et l'alerte est écrite.
    /// LA MUTATION QUI LE FAIT ROUGIR : AM3_PHASE1.
    #[test]
    fn saef_la_sonde_de_phase_un_de_run_due_rules_arrete_avant_l_evaluation() {
        let regle = |db: &Arc<Mutex<Connection>>| {
            db.lock()
                .execute(
                    "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) VALUES('saef',1,?1,1,'>',0,2,0,3600)",
                    params![SAEF_REQUETE_QUI_COMPTE],
                )
                .unwrap();
        };
        let jouer = |db: &Arc<Mutex<Connection>>, p: &str| {
            SAEF_PHASE_TROIS_ATTEINTE.with(|n| n.set(0));
            crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(saef_noter_la_phase_trois));
            let bilan = crate::handlers::detection::run_due_rules(db, p);
            crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(crate::handlers::detection::sans_crochet));
            (bilan, SAEF_PHASE_TROIS_ATTEINTE.with(|n| n.get()))
        };
        let (_t1, p1, db1) = saef_base("saef-phase1-sain");
        regle(&db1);
        let (bilan, atteinte) = jouer(&db1, &p1);
        assert!(matches!(bilan, Mesure::Lue(_)), "sans orpheline : règle évaluée, bilan lu : {bilan:?}");
        assert_eq!(atteinte, 1, "sans orpheline : le crochet des écritures est atteint une fois");
        let alertes: i64 = db1.lock().query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
        assert!(alertes >= 1, "sans orpheline : l'alerte est écrite ({alertes})");

        let (_t2, p2, db2) = saef_base("saef-phase1-orpheline");
        regle(&db2);
        let injection = {
            let c = db2.lock();
            saef_ouvrir_l_orpheline(&c);
            saef_changements(&c)
        };
        let (bilan, atteinte) = jouer(&db2, &p2);
        let (changements, autocommit, marque, vues) = {
            let c = db2.lock();
            (
                saef_changements(&c),
                c.is_autocommit(),
                c.query_row("SELECT COUNT(*) FROM meta WHERE key='saef'", [], |r| r.get::<_, i64>(0)).unwrap(),
                crate::comptes_de_transaction::compte_des_temoins(&c, "orpheline vue"),
            )
        };
        if !autocommit {
            db2.lock().execute_batch("ROLLBACK").expect("fixture : fermeture de l'orpheline");
        }
        assert_eq!(bilan, Mesure::Illisible { cause: CAUSE_SOURCE_ILLISIBLE, detail: saef_detail("règles") }, "les règles se déclarent aveugles");
        assert_eq!(atteinte, 0, "la sonde de phase 1 arrête AVANT l'évaluation : le crochet des écritures n'est pas atteint");
        assert_eq!(changements, injection, "rien n'est écrit après l'orpheline");
        assert_eq!((autocommit, marque, vues), (false, 1, 1), "l'orpheline est intacte et vue une fois");
    }
}
