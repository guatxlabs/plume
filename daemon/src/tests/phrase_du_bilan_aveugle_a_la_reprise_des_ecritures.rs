// =====================================================================================
// `P10.31-j` (reste de la vague AM) — LE BILAN D'UN TICK AVEUGLE DIT CE QUI S'EST PASSÉ À LA REPRISE DES ÉCRITURES.
// Mesuré le 2026-10-25 sur 60841412 : un seul constructeur, `tick_aveugle_par_transaction_orpheline`, servait la phrase
// « rien n'est évalué ni écrit par <famille> ce tick » aux six sites qui voient l'orpheline. Elle est vraie devant une
// famille (tête du tick, `orpheline_avant_la_famille`, phase 1 de `run_due_rules`) ; fausse aux deux sites où la sonde
// est reprise APRÈS la compilation ou l'évaluation — `ecrivain_sonde_avant_les_ecritures` (dix reprises de cinq familles)
// et la phase 3 de `run_due_rules` —, où un tour de boucle ou une famille d'avant a pu écrire, validé.
//
// CE QUE CES TÉMOINS TIENNENT, chacun par égalité de la ligne ENTIÈRE (littéral recopié ici, pas reconstruit depuis le
// démon) :
//   * le premier constructeur rend sa phrase d'origine à l'octet ; le second rend la phrase de la reprise, sous la même
//     cause publiée (`source_illisible`) et en gardant la sous-chaîne « (cause nommée) » que lit
//     `les_regles_ont_deja_declare_l_orpheline` ;
//   * la phase 3 de `run_due_rules`, jouée seule puis par le tick (le tick s'arrête derrière elle sans re-sonder : un
//     seul compte) ;
//   * TÉMOINS NÉGATIFS : la tête du tick, la sonde avant une famille et la phase 1 de `run_due_rules` gardent la phrase
//     d'origine ;
//   * le compte PAR FIL des ticks aveugles (`metrics::ticks_aveugles_de_ce_fil`) monte de UN exactement à chaque aveu —
//     le tick joué ici tourne sur le fil du témoin : la sonde et le crochet local au fil sont dans le même appel.
// Les dix reprises de `ecrivain_sonde_avant_les_ecritures`, au premier ET au second tour de boucle, sont jugées par
// `sonde_avant_les_ecritures_des_familles.rs` (inversé dans la même vague : `saef_detail`, compte par fil « +1 »).
//
// MUTANTS JOUÉS (variable de mutation sous cfg!(test), retirés avant le commit), chacun rouge sur ses témoins :
// AN4_ANCIEN_ECRITURES (l'ancien constructeur aux dix reprises : témoins `saef_` des sites et du tick),
// AN4_ANCIEN_REGLES_PHASE3, AN4_NEUF_TETE, AN4_NEUF_AVANT_FAMILLE, AN4_NEUF_PHASE1 (le mauvais constructeur à un
// site), AN4_PREMIER_CHANGE (la phrase d'origine retouchée), AN4_SANS_COMPTE (le second constructeur ne compte plus),
// AN4_SANS_SOUS_CHAINE (la sous-chaîne « (cause) » perdue : le tick re-sonde, double compte), AN4_COMPTE_DOUBLE et
// AN4_FIL_MUET (le compte par fil faussé).
//
// CE QU'ILS NE TIENNENT PAS : la cause servie reste `CAUSE_SOURCE_ILLISIBLE` (ensemble fermé de cinq) ; aucune cause
// dédiée à l'orpheline n'est traduite par la console (`web/system.js`). Le compte de PROCESSUS (`TICKS_AVEUGLES`) reste
// lu « monte » : les témoins parallèles de `cargo test` le font bouger ensemble.
// =====================================================================================
mod phrase_du_bilan_aveugle_a_la_reprise_des_ecritures {
    use super::*;
    use crate::bilan_de_tick::{BOUCLE_REGLES, CAUSE_TRANSACTION_ORPHELINE};
    use crate::mesure_environnement::{Mesure, CAUSE_SOURCE_ILLISIBLE};
    use crate::server::boucles_de_fond::crochets_de_la_sonde_par_famille::{sans_crochet_de_famille, AVANT_LA_FAMILLE_DU_TICK};

    /// La phrase d'origine, recopiée : vraie AVANT toute évaluation.
    const PBAR_AVANT_TETE: &str = " : aveugle, l'écrivain porte une transaction orpheline (transaction_orpheline_sur_l_ecrivain) — rien n'est évalué ni écrit par ";
    const PBAR_AVANT_QUEUE: &str = " ce tick, la transaction n'est pas annulée";
    /// La phrase de la reprise, recopiée : vraie APRÈS la compilation ou l'évaluation.
    const PBAR_REPRISE_TETE: &str = " : aveugle, l'écrivain porte une transaction orpheline (transaction_orpheline_sur_l_ecrivain) — vue en reprenant le verrou pour écrire, après la compilation ou l'évaluation : rien n'est écrit par ";
    const PBAR_REPRISE_QUEUE: &str = " à cette reprise, ce qu'une reprise précédente de ce tick a écrit reste écrit, la transaction n'est pas annulée";

    fn pbar_avant(famille: &str) -> String {
        format!("{famille}{PBAR_AVANT_TETE}{famille}{PBAR_AVANT_QUEUE}")
    }

    fn pbar_reprise(famille: &str) -> String {
        format!("{famille}{PBAR_REPRISE_TETE}{famille}{PBAR_REPRISE_QUEUE}")
    }

    fn pbar_fil() -> u64 {
        crate::metrics::ticks_aveugles_de_ce_fil::compte(BOUCLE_REGLES, CAUSE_TRANSACTION_ORPHELINE)
    }

    fn pbar_changements(c: &Connection) -> i64 {
        c.query_row("SELECT total_changes()", [], |r| r.get(0)).unwrap()
    }

    thread_local! {
        /// `total_changes()` de l'écrivain juste après l'ouverture de l'orpheline (`None` : jamais ouverte).
        static PBAR_INJECTION: std::cell::Cell<Option<i64>> = const { std::cell::Cell::new(None) };
    }

    fn pbar_ouvrir_l_orpheline(c: &Connection) {
        c.execute_batch("BEGIN IMMEDIATE; INSERT INTO meta(key,value) VALUES('pbar','1');").expect("fixture : transaction laissée ouverte");
        PBAR_INJECTION.with(|i| i.set(Some(pbar_changements(c))));
    }

    /// Le crochet des écritures de `run_due_rules` : ouvre l'orpheline entre l'évaluation et la phase 3.
    fn pbar_orpheline_avant_les_ecritures_des_regles(db: &Arc<Mutex<Connection>>) {
        pbar_ouvrir_l_orpheline(&db.lock());
    }

    /// Le crochet avant la sonde d'une famille du tick : ouvre l'orpheline devant les règles avancées.
    fn pbar_orpheline_devant_les_regles_avancees(db: &Arc<Mutex<Connection>>, famille: &'static str) {
        if famille == "règles avancées" {
            pbar_ouvrir_l_orpheline(&db.lock());
        }
    }

    /// Une base migrée, une seule règle due (qui compile et s'évalue), trois événements `pbar` récents.
    fn pbar_base(tag: &str) -> (crate::tmp_possede::TmpPossede, String, Arc<Mutex<Connection>>) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute_batch("DELETE FROM rule; DELETE FROM alert; DELETE FROM correlation; DELETE FROM ueba_baseline; DELETE FROM playbook;")
                .unwrap();
            conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) \
                 VALUES('pbar',1,'search source=pbar | stats count',1,'>',0,2,0,3600)",
                [],
            )
            .unwrap();
            let maintenant = now();
            for i in 0..3 {
                conn.execute(
                    "INSERT INTO event(ts,source,category,severity,message,src_ip,host,dedup) VALUES(?1,'pbar','auth',1,'échec','192.0.2.20','h1',?2)",
                    params![maintenant - 10, format!("pbar-{i}")],
                )
                .unwrap();
            }
        }
        (tmp, p, db)
    }

    /// Ce que l'écrivain porte après l'appel : (changements, autocommit, marque de l'orpheline, orphelines vues) ; ferme
    /// l'orpheline si elle est ouverte.
    fn pbar_relever_puis_fermer(db: &Arc<Mutex<Connection>>) -> (i64, bool, i64, u64) {
        let releve = {
            let c = db.lock();
            (
                pbar_changements(&c),
                c.is_autocommit(),
                c.query_row("SELECT COUNT(*) FROM meta WHERE key='pbar'", [], |r| r.get::<_, i64>(0)).unwrap(),
                crate::comptes_de_transaction::compte_des_temoins(&c, "orpheline vue"),
            )
        };
        if !releve.1 {
            db.lock().execute_batch("ROLLBACK").expect("fixture : fermeture de l'orpheline");
        }
        releve
    }

    /// Le bilan d'un tick arrêté par UNE orpheline : « 1 famille(s) », le détail attendu, puis un compte d'abandons
    /// entier et rien d'autre.
    fn pbar_juger_le_bilan_du_tick(bilan: &crate::bilan_de_tick::BilanDeTick, detail_attendu: &str) {
        match bilan {
            Mesure::Illisible { cause, detail } => {
                assert_eq!(*cause, CAUSE_SOURCE_ILLISIBLE);
                let tete = format!("1 famille(s) aveugle(s) ce tick — {detail_attendu} ; abandons comptés par ailleurs : ");
                let reste = detail.strip_prefix(tete.as_str()).unwrap_or_else(|| panic!("bilan du tick inattendu : {detail}"));
                assert!(!reste.is_empty() && reste.bytes().all(|o| o.is_ascii_digit()), "bilan du tick inattendu : {detail}");
            }
            Mesure::Lue(n) => panic!("le tick se dit lu ({n} abandon(s))"),
        }
    }

    // ---------------------------------------------------------------- les deux constructeurs

    /// CE QU'IL TIENT : le premier constructeur rend la phrase d'origine à l'octet, sous `source_illisible`, et compte UN
    /// tick aveugle sur ce fil sous la cause de l'orpheline.
    /// LA MUTATION QUI LE FAIT ROUGIR : AN4_PREMIER_CHANGE (et AN4_FIL_MUET, AN4_COMPTE_DOUBLE).
    #[test]
    fn pbar_le_premier_constructeur_garde_la_phrase_d_origine() {
        let avant = pbar_fil();
        let b = crate::bilan_de_tick::tick_aveugle_par_transaction_orpheline(BOUCLE_REGLES, "famille-pbar");
        assert_eq!(
            b,
            Mesure::Illisible {
                cause: CAUSE_SOURCE_ILLISIBLE,
                detail: "famille-pbar : aveugle, l'écrivain porte une transaction orpheline (transaction_orpheline_sur_l_ecrivain) — \
                         rien n'est évalué ni écrit par famille-pbar ce tick, la transaction n'est pas annulée"
                    .to_string(),
            }
        );
        assert_eq!(pbar_fil(), avant + 1, "un tick aveugle compté sur ce fil");
    }

    /// CE QU'IL TIENT : le second constructeur rend la phrase de la reprise à l'octet, sous `source_illisible`, compte UN
    /// tick aveugle sur ce fil, garde le préfixe « famille : aveugle, » et la sous-chaîne que lit
    /// `les_regles_ont_deja_declare_l_orpheline` (qui le reconnaît une fois absorbé).
    /// LES MUTATIONS QUI LE FONT ROUGIR : AN4_SANS_COMPTE, AN4_SANS_SOUS_CHAINE, AN4_COMPTE_DOUBLE, AN4_FIL_MUET.
    #[test]
    fn pbar_le_second_constructeur_dit_la_reprise() {
        let avant = pbar_fil();
        let b = crate::bilan_de_tick::tick_aveugle_par_transaction_orpheline_aux_ecritures(BOUCLE_REGLES, "famille-pbar");
        assert_eq!(pbar_fil(), avant + 1, "un tick aveugle compté sur ce fil");
        assert_eq!(
            b,
            Mesure::Illisible {
                cause: CAUSE_SOURCE_ILLISIBLE,
                detail: "famille-pbar : aveugle, l'écrivain porte une transaction orpheline (transaction_orpheline_sur_l_ecrivain) — \
                         vue en reprenant le verrou pour écrire, après la compilation ou l'évaluation : rien n'est écrit par \
                         famille-pbar à cette reprise, ce qu'une reprise précédente de ce tick a écrit reste écrit, la \
                         transaction n'est pas annulée"
                    .to_string(),
            }
        );
        assert_eq!(b, Mesure::Illisible { cause: CAUSE_SOURCE_ILLISIBLE, detail: pbar_reprise("famille-pbar") }, "instrument : `pbar_reprise`");
        let mut planificateur = crate::bilan_de_tick::BilanDuPlanificateur::default();
        planificateur.absorber(b);
        assert!(
            crate::server::boucles_de_fond::les_regles_ont_deja_declare_l_orpheline(&planificateur),
            "l'aveu de la reprise est reconnu : le tick s'arrête derrière lui sans re-sonder"
        );
    }

    // ---------------------------------------------------------------- la phase 3 de `run_due_rules`

    /// CE QU'IL TIENT : une orpheline ouverte entre l'évaluation des règles et leur phase 3 rend le bilan de la REPRISE,
    /// nommant les règles, à l'octet ; un tick compté sur ce fil ; rien d'écrit après l'orpheline ; orpheline intacte et
    /// vue une fois.
    /// LA MUTATION QUI LE FAIT ROUGIR : AN4_ANCIEN_REGLES_PHASE3.
    #[test]
    fn pbar_run_due_rules_phase_trois_dit_la_reprise() {
        let (_t, p, db) = pbar_base("pbar-phase3");
        PBAR_INJECTION.with(|i| i.set(None));
        let avant = pbar_fil();
        crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(pbar_orpheline_avant_les_ecritures_des_regles));
        let bilan = crate::handlers::detection::run_due_rules(&db, &p);
        crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(crate::handlers::detection::sans_crochet));
        let fil = pbar_fil();
        let (changements, autocommit, marque, vues) = pbar_relever_puis_fermer(&db);
        let injection = PBAR_INJECTION.with(|i| i.get()).expect("instrument : le crochet des écritures des règles n'a pas ouvert l'orpheline");
        assert_eq!(bilan, Mesure::Illisible { cause: CAUSE_SOURCE_ILLISIBLE, detail: pbar_reprise("règles") }, "phase 3 : la phrase de la reprise");
        assert_eq!(fil, avant + 1, "un tick aveugle compté sur ce fil");
        assert_eq!(changements, injection, "rien n'est écrit après l'orpheline");
        assert_eq!((autocommit, marque, vues), (false, 1, 1), "l'orpheline est intacte et vue une fois");
    }

    /// CE QU'IL TIENT : la même orpheline, jouée par le TICK : le bilan dit « 1 famille(s) » et la phrase de la reprise
    /// des règles, le tick s'arrête derrière elle (aucune famille admise par la sonde suivante, un seul tick compté sur ce
    /// fil, orpheline vue une fois).
    /// LES MUTATIONS QUI LE FONT ROUGIR : AN4_ANCIEN_REGLES_PHASE3, AN4_SANS_SOUS_CHAINE (le tick re-sonde : deux comptes).
    #[test]
    fn pbar_par_le_tick_la_phase_trois_des_regles_dit_la_reprise_un_seul_compte() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        set_engagement_mode(false);
        let (_t, p, db) = pbar_base("pbar-tick-phase3");
        let avant = pbar_fil();
        crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(pbar_orpheline_avant_les_ecritures_des_regles));
        let bilan = crate::server::boucles_de_fond::tick_de_detection_d_un_tenant(&db, &p).bilan_de_tick();
        crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(crate::handlers::detection::sans_crochet));
        let fil = pbar_fil();
        let (_, autocommit, marque, vues) = pbar_relever_puis_fermer(&db);
        pbar_juger_le_bilan_du_tick(&bilan, &pbar_reprise("règles"));
        assert_eq!(fil, avant + 1, "UN tick aveugle compté sur ce fil : le tick ne re-sonde pas");
        assert_eq!((autocommit, marque, vues), (false, 1, 1), "l'orpheline est intacte et vue une fois");
    }

    // ---------------------------------------------------------------- témoins négatifs : AVANT la famille, l'ancienne phrase

    /// CE QU'IL TIENT : une orpheline déjà ouverte au début du tick est vue par la sonde de TÊTE : phrase d'origine, à
    /// l'octet, nommant tout le tick ; un seul compte sur ce fil.
    /// LA MUTATION QUI LE FAIT ROUGIR : AN4_NEUF_TETE.
    #[test]
    fn pbar_la_tete_du_tick_garde_la_phrase_d_origine() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        set_engagement_mode(false);
        let (_t, p, db) = pbar_base("pbar-tete");
        pbar_ouvrir_l_orpheline(&db.lock());
        let avant = pbar_fil();
        let bilan = crate::server::boucles_de_fond::tick_de_detection_d_un_tenant(&db, &p).bilan_de_tick();
        let fil = pbar_fil();
        let (_, autocommit, marque, vues) = pbar_relever_puis_fermer(&db);
        pbar_juger_le_bilan_du_tick(&bilan, &pbar_avant("tick de détection (toutes les familles)"));
        assert_eq!(fil, avant + 1, "un tick aveugle compté sur ce fil");
        assert_eq!((autocommit, marque, vues), (false, 1, 1));
    }

    /// CE QU'IL TIENT : une orpheline ouverte entre les règles et la sonde des règles avancées est vue AVANT la famille
    /// (`orpheline_avant_la_famille`) : phrase d'origine nommant les règles avancées, à l'octet ; un seul compte.
    /// LA MUTATION QUI LE FAIT ROUGIR : AN4_NEUF_AVANT_FAMILLE.
    #[test]
    fn pbar_la_sonde_avant_une_famille_garde_la_phrase_d_origine() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        set_engagement_mode(false);
        let (_t, p, db) = pbar_base("pbar-avant-famille");
        let avant = pbar_fil();
        AVANT_LA_FAMILLE_DU_TICK.with(|h| h.set(pbar_orpheline_devant_les_regles_avancees));
        let bilan = crate::server::boucles_de_fond::tick_de_detection_d_un_tenant(&db, &p).bilan_de_tick();
        AVANT_LA_FAMILLE_DU_TICK.with(|h| h.set(sans_crochet_de_famille));
        let fil = pbar_fil();
        let (_, autocommit, marque, vues) = pbar_relever_puis_fermer(&db);
        pbar_juger_le_bilan_du_tick(&bilan, &pbar_avant("règles avancées"));
        assert_eq!(fil, avant + 1, "un tick aveugle compté sur ce fil");
        assert_eq!((autocommit, marque, vues), (false, 1, 1));
        let alertes: i64 = open_db(&p).unwrap().query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
        assert!(alertes >= 1, "contrôle : les règles ont tourné et écrit AVANT l'orpheline ({alertes})");
    }

    /// CE QU'IL TIENT : une orpheline ouverte avant `run_due_rules` est vue par sa sonde de PHASE 1, avant toute
    /// évaluation : phrase d'origine nommant les règles, à l'octet ; un seul compte.
    /// LA MUTATION QUI LE FAIT ROUGIR : AN4_NEUF_PHASE1.
    #[test]
    fn pbar_la_phase_un_de_run_due_rules_garde_la_phrase_d_origine() {
        let (_t, p, db) = pbar_base("pbar-phase1");
        pbar_ouvrir_l_orpheline(&db.lock());
        let avant = pbar_fil();
        let bilan = crate::handlers::detection::run_due_rules(&db, &p);
        let fil = pbar_fil();
        let (_, autocommit, marque, vues) = pbar_relever_puis_fermer(&db);
        assert_eq!(bilan, Mesure::Illisible { cause: CAUSE_SOURCE_ILLISIBLE, detail: pbar_avant("règles") });
        assert_eq!(fil, avant + 1, "un tick aveugle compté sur ce fil");
        assert_eq!((autocommit, marque, vues), (false, 1, 1));
    }
}
