// =====================================================================================
// `P10.27-h` — UN `BEGIN` REFUSÉ EST COMPTÉ, PAR CAUSE ET PAR JOURNAL, ET SERVI SOUS `/metrics`.
// `P10.26-d` — LE GESTE DÛ D'UNE PASSE DE FOND QUE LA BASE N'A PAS VALIDÉ EST COMPTÉ ET SERVI.
// `P10.27-y` — LE COMPTE DE LA SONDE DES TRANSACTIONS ORPHELINES EST SERVI SOUS `/metrics`.
//
// LES DÉFAUTS, RE-MESURÉS AVANT TOUT CORRECTIF le 2026-09-29 : `metrics.rs` ne portait aucune série ni clé JSON sur ces
// trois faits ; `dire_la_transaction_non_ouverte`, `tracer_apres_coup`, les balayages du cycle de vie des engagements et
// les deux plis de `rollup_hosts` ne faisaient que journaliser ; le compte de la sonde n'avait qu'un lecteur
// `#[cfg(test)]`. Chaque témoin ci-dessous rougit sur la forme d'avant (sa mutation est nommée dans son commentaire).
//
// LES ÉNONCÉS SOUS-COMPTAIENT, ET LE PÉRIMÈTRE RETENU EST ÉCRIT ICI. `P10.26-d` ne visait que les balayages d'engagement :
// les deux plis de `rollup_hosts` (définitif, rattrapage) ne faisaient eux aussi que journaliser un refus, et un `BEGIN`
// refusé dans un balayage n'était pas compté non plus — les trois étapes (`BEGIN`, écriture, `COMMIT`) sont comptées.
// `P10.27-h` : le compteur posé dans `dire_la_transaction_non_ouverte` couvre l'entonnoir (`ouvrir_sa_transaction` et ses
// formes, les deux gardes du spool) ; `tracer_apres_coup`, les balayages d'engagement, la purge confirmée, l'attache
// d'un runbook et les semis refusaient leur `BEGIN` ailleurs — ils sont comptés aussi.
//
// L'INSTRUMENT : les compteurs sont de PROCESSUS et la suite tourne en parallèle ; chaque témoin juge donc le compte
// noté PAR BASE (`compte_des_temoins`, inerte hors `cfg(test)`), ce qui rend jugeables les égalités strictes — y compris
// « rien n'est compté ». Les valeurs SERVIES (`/api/system/metrics`, la route qui sert `gather_json` ; `/metrics`) sont
// jugées de deux façons : EXACTEMENT sous une clé propre au témoin (journaux `rtcm-*`, geste `rtcm : geste témoin`), que
// personne d'autre ne fait monter ; encadrées sous une clé partagée (totaux, causes, gestes réels), qui ne peut que monter.
//
// REPRISE APRÈS VÉRIFICATION (2026-09-30) — la première forme laissait survivre cinq mutations : le rattrapage de
// `rollup_hosts` refusé à l'écriture ou au `COMMIT` avalé ; la ventilation SERVIE par journal envoyée toute sous
// `(autres)` ou laissée à zéro ; la PREMIÈRE cause d'un geste gardée au lieu de la dernière ; le compte de la sonde servi
// comme une présence (0/1). Chacune rougit désormais son témoin (nommée dans son commentaire). La cause `hors_verrou`
// s'y ajoute : un refus du moteur sur un écrivain libre qui n'est pas un verrou tombait sous `verrou`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le mode multi-tenant (le compte est de processus, tous tenants confondus — c'est
// écrit dans le `# HELP`) ; une base réellement en lecture seule ou un disque plein (la cause `hors_verrou` est fabriquée
// par un autorisateur qui refuse le `BEGIN`, même classe de code, sans toucher au système de fichiers) ; les sites hors
// du compte (migrations, instantané de lecture de la ventilation, sauvegarde en flux, scellement du tier froid) ; le
// panneau Système de la console ne lit pas ces clés.
// =====================================================================================
mod refus_de_transaction_comptes_sous_metrics {
    use super::*;
    use crate::comptes_de_transaction::{compte_des_temoins, compter_un_geste_de_fond_non_valide};
    use crate::handlers::transaction_validee::{
        ouvrir_le_garde_du_geste, ouvrir_sa_transaction, signaler_une_transaction_ouverte_hors_de_tout_geste, tracer_apres_coup,
        transactions_ouvertes_hors_de_tout_geste,
    };
    use crate::metrics::{entree_sous_plafond, CLE_DES_AUTRES};
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const RTCM_SPOOL: &str = "/nonexistent-spool";

    fn rtcm_json(st: &AppState) -> Value {
        crate::gather_json(&st.db.lock(), RTCM_SPOOL, "", &crate::handlers::system::VersionDeSchema::Lue(1), 80)
    }

    fn rtcm_prom(st: &AppState) -> String {
        crate::gather_prom(&st.db.lock(), RTCM_SPOOL, "", &crate::handlers::system::VersionDeSchema::Lue(1), 80)
    }

    /// La valeur d'un échantillon Prometheus (`nom` porte ses étiquettes), ou `None` s'il n'est pas servi.
    fn rtcm_echantillon(prom: &str, nom: &str) -> Option<u64> {
        prom.lines().find_map(|l| l.strip_prefix(nom).and_then(|reste| reste.strip_prefix(' ')).and_then(|v| v.trim().parse().ok()))
    }

    fn rtcm_compte(st: &AppState, quoi: &str) -> u64 {
        compte_des_temoins(&st.db.lock(), quoi)
    }

    /// Ouvre la transaction d'un AUTRE geste sur l'écrivain et la laisse pendante (l'état qu'un `COMMIT` refusé puis
    /// ignoré laisserait) : c'est la condition d'un `BEGIN` refusé pour transaction étrangère, pas le défaut sous témoin.
    fn rtcm_transaction_etrangere(st: &AppState) {
        st.db.lock().execute_batch("BEGIN IMMEDIATE; INSERT INTO meta(key,value) VALUES('rtcm-etrangere','1');").expect("fixture : transaction étrangère");
    }

    fn rtcm_fermer_l_etrangere(st: &AppState) {
        st.db.lock().execute_batch("ROLLBACK").expect("fixture : la transaction étrangère est fermée par son geste");
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.27-h` — L'ENTONNOIR : PAR CAUSE, PAR JOURNAL, ET RIEN QUAND LE `BEGIN` EST PRIS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, DANS LES DEUX SENS : un `BEGIN` pris n'est pas compté ; un `BEGIN` refusé sur un écrivain qui porte
    /// la transaction d'un autre geste est compté sous `transaction_etrangere` et sous son journal (par
    /// `ouvrir_sa_transaction` et par `ouvrir_le_garde_du_geste`), jamais sous `verrou` ; refusé parce qu'une AUTRE
    /// connexion tient le verrou d'écriture (écrivain libre, `SQLITE_BUSY`), il est compté sous `verrou` ; refusé par le
    /// moteur sur un écrivain libre pour une autre raison qu'un verrou (autorisateur, `SQLITE_AUTH`), sous `hors_verrou`
    /// — chacun sous sa seule cause. Les trois causes sont servies par `/api/system/metrics` (`transactions`) et par
    /// `/metrics` (`plume_transaction_begin_refuses_total{cause}`, compteur), le total égal à leur somme ; la ventilation
    /// SERVIE par journal porte exactement les refus de ce témoin sous ses journaux `rtcm-*`, et rien sous un journal dont
    /// le `BEGIN` a été pris.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer `compter_un_begin_refuse` de `dire_la_transaction_non_ouverte` (la forme
    /// d'avant) ; inverser deux causes dans `CauseDuBeginRefuse::du_refus`, ou y ranger tout écrivain libre sous `verrou`
    /// (la première forme) ; retirer la boucle de l'exposition Prometheus par cause ; dans `compter_un_begin_refuse`,
    /// ventiler sous `CLE_DES_AUTRES` au lieu du journal (mutation A2 de la vérification) ou n'y rien ajouter (`+= 0`).
    #[test]
    fn rtcm_un_begin_refuse_est_compte_sous_sa_cause_et_son_journal() {
        let (st, p) = sp_state("rtcm-entonnoir");

        // NÉGATIF — écrivain libre, `BEGIN` pris : rien n'est compté.
        {
            let c = st.db.lock();
            ouvrir_sa_transaction(&c, "rtcm-libre", "témoin").expect("écrivain libre : le BEGIN est pris");
            c.execute_batch("ROLLBACK").expect("fixture : fermeture");
        }
        assert_eq!(rtcm_compte(&st, "begin refusé rtcm-libre verrou"), 0, "un BEGIN pris n'est pas compté (verrou)");
        assert_eq!(rtcm_compte(&st, "begin refusé rtcm-libre transaction_etrangere"), 0, "ni sous l'autre cause");

        // TRANSACTION ÉTRANGÈRE — refusé par l'entonnoir et par le garde.
        rtcm_transaction_etrangere(&st);
        let refus_entonnoir = ouvrir_sa_transaction(&st.db.lock(), "rtcm-etrangere", "témoin").is_err();
        let refus_garde = ouvrir_le_garde_du_geste(&st.db.lock(), "rtcm-garde", "témoin", "rtcm : non pris").is_err();
        rtcm_fermer_l_etrangere(&st);
        assert!(refus_entonnoir && refus_garde, "fixture : les deux BEGIN sont refusés");
        assert_eq!(rtcm_compte(&st, "begin refusé rtcm-etrangere transaction_etrangere"), 1, "compté sous sa cause et son journal");
        assert_eq!(rtcm_compte(&st, "begin refusé rtcm-etrangere verrou"), 0, "et pas sous le verrou");
        assert_eq!(rtcm_compte(&st, "begin refusé rtcm-garde transaction_etrangere"), 1, "le garde `Txn` est compté aussi");

        // VERROU — une autre connexion tient le verrou d'écriture ; l'écrivain, libre, n'attend pas.
        let autre = open_db(p.as_str()).expect("fixture : seconde connexion");
        autre.execute_batch("BEGIN IMMEDIATE").expect("fixture : la seconde connexion prend le verrou d'écriture");
        let (refuse, libre_apres) = {
            let c = st.db.lock();
            c.busy_timeout(std::time::Duration::ZERO).expect("fixture : sans attente");
            let refuse = ouvrir_sa_transaction(&c, "rtcm-verrou", "témoin").is_err();
            c.busy_timeout(std::time::Duration::from_secs(5)).expect("fixture : attente rétablie");
            (refuse, c.is_autocommit())
        };
        autre.execute_batch("ROLLBACK").expect("fixture : verrou rendu");
        assert!(refuse && libre_apres, "fixture : BEGIN refusé par le verrou, écrivain resté libre");
        assert_eq!(rtcm_compte(&st, "begin refusé rtcm-verrou verrou"), 1, "compté sous le verrou");
        assert_eq!(rtcm_compte(&st, "begin refusé rtcm-verrou transaction_etrangere"), 0, "et pas sous la transaction étrangère");
        assert_eq!(rtcm_compte(&st, "begin refusé rtcm-verrou hors_verrou"), 0, "ni hors verrou");

        // HORS VERROU — l'écrivain est libre et le moteur refuse le `BEGIN` pour une autre raison qu'un verrou. Fabriqué par
        // un autorisateur qui refuse l'ouverture d'une transaction (`SQLITE_AUTH`) : un refus qui ne passe pas avec le temps,
        // comme une base en lecture seule ou un disque plein, sans toucher au système de fichiers.
        let (refuse, libre_apres) = {
            let c = st.db.lock();
            c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Transaction { operation: TransactionOperation::Begin } => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            let refuse = ouvrir_sa_transaction(&c, "rtcm-hors-verrou", "témoin").is_err();
            c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            (refuse, c.is_autocommit())
        };
        assert!(refuse && libre_apres, "fixture : BEGIN refusé par l'autorisateur, écrivain resté libre");
        assert_eq!(rtcm_compte(&st, "begin refusé rtcm-hors-verrou hors_verrou"), 1, "compté hors verrou");
        assert_eq!(rtcm_compte(&st, "begin refusé rtcm-hors-verrou verrou"), 0, "et pas sous le verrou : il ne passera pas");
        assert_eq!(rtcm_compte(&st, "begin refusé rtcm-hors-verrou transaction_etrangere"), 0, "ni sous la transaction étrangère");

        // EXPOSITION — `/api/system/metrics`, puis `/metrics`. Totaux et causes sont partagés par la suite parallèle :
        // encadrés, jamais égalés.
        let m = rtcm_json(&st);
        let t = &m["transactions"];
        let verrou = t["begin_refuses_par_cause"]["verrou"].as_u64().expect("cause `verrou` servie");
        let etrangere = t["begin_refuses_par_cause"]["transaction_etrangere"].as_u64().expect("cause `transaction_etrangere` servie");
        let hors_verrou = t["begin_refuses_par_cause"]["hors_verrou"].as_u64().expect("cause `hors_verrou` servie");
        assert!(verrou >= 1 && etrangere >= 2 && hors_verrou >= 1, "les refus de ce témoin sont dans les comptes servis : {t}");
        assert_eq!(t["begin_refuses_total"].as_u64(), Some(verrou + etrangere + hors_verrou), "le total est la somme des causes : {t}");
        // LA VENTILATION SERVIE PAR JOURNAL — les journaux `rtcm-*` n'appartiennent qu'à ce témoin : leurs valeurs servies
        // sont jugées EXACTEMENT. Le plafond (64) est au-dessus des quarante-six journaux littéraux du code (compté le
        // 2026-09-30) : aucun journal de ce témoin ne peut être rangé sous `(autres)` par le reste de la suite.
        let par_journal = &t["begin_refuses_par_journal"];
        let servi = |sous_verrou: u64, sous_etrangere: u64, sous_hors_verrou: u64| {
            json!({ "verrou": sous_verrou, "transaction_etrangere": sous_etrangere, "hors_verrou": sous_hors_verrou })
        };
        assert_eq!(par_journal["rtcm-etrangere"], servi(0, 1, 0), "servi sous son journal et sa cause : {par_journal}");
        assert_eq!(par_journal["rtcm-garde"], servi(0, 1, 0), "le garde `Txn` aussi : {par_journal}");
        assert_eq!(par_journal["rtcm-verrou"], servi(1, 0, 0), "le verrou sous le sien : {par_journal}");
        assert_eq!(par_journal["rtcm-hors-verrou"], servi(0, 0, 1), "le refus hors verrou sous le sien : {par_journal}");
        assert!(par_journal.get("rtcm-libre").is_none(), "un journal dont le BEGIN a été pris n'est pas ventilé : {par_journal}");
        let prom = rtcm_prom(&st);
        assert!(prom.contains("# TYPE plume_transaction_begin_refuses_total counter\n"), "la série est un compteur");
        let p_verrou = rtcm_echantillon(&prom, "plume_transaction_begin_refuses_total{cause=\"verrou\"}").expect("échantillon `verrou` servi");
        let p_etrangere =
            rtcm_echantillon(&prom, "plume_transaction_begin_refuses_total{cause=\"transaction_etrangere\"}").expect("échantillon `transaction_etrangere` servi");
        let p_hors_verrou =
            rtcm_echantillon(&prom, "plume_transaction_begin_refuses_total{cause=\"hors_verrou\"}").expect("échantillon `hors_verrou` servi");
        assert!(
            p_verrou >= verrou && p_etrangere >= etrangere && p_hors_verrou >= hors_verrou,
            "/metrics sert les mêmes compteurs que /api/system/metrics"
        );
        let aide = prom.lines().find(|l| l.starts_with("# HELP plume_transaction_begin_refuses_total ")).expect("la série est documentée");
        assert!(aide.contains("/api/system/metrics") && !aide.contains("/api/metrics"), "le # HELP renvoie à la route qui sert le JSON : {aide}");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.27-h` — LES `BEGIN` REFUSÉS HORS DE L'ENTONNOIR SONT COMPTÉS AUSSI
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sur un écrivain qui porte une transaction étrangère, la trace d'après coup (`tracer_apres_coup`),
    /// le semis de démonstration, le semis d'un tableau de bord sous son drapeau, la purge confirmée et l'attache d'un
    /// runbook refusent leur `BEGIN` — chacun est compté, une fois, sous son journal et sous `transaction_etrangere`, et
    /// rien n'est écrit. Contrôle négatif : la même trace, sur un écrivain libre, est écrite et n'est pas comptée.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer le compte de `tracer_apres_coup`, de `semer_la_demonstration`, de
    /// `semer_sous_son_drapeau`, de `purge_apply` ou de `attach_runbook` — son journal reste à zéro.
    #[test]
    fn rtcm_les_begin_refuses_hors_de_l_entonnoir_sont_comptes() {
        let (st, _p) = sp_state("rtcm-hors-entonnoir");
        let t0 = now();
        let (incident, runbook) = {
            let c = st.db.lock();
            c.execute(
                "INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id) \
                 VALUES(?1,'rtcm-purge','test',1,'à purger','h1','prod','','')",
                params![t0 - 60],
            )
            .expect("fixture : événement purgeable");
            let incident = dossier_seme(&c, "adm", "rtcm incident", 2, "", None, 2);
            c.execute(
                "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) \
                 VALUES('rtcm-runbook','rtcm','*','','',0,1,1000)",
                [],
            )
            .expect("fixture : runbook");
            let runbook = c.last_insert_rowid();
            c.execute(
                "INSERT INTO runbook_step(runbook_id,ordinal,phase,title) VALUES(?1,1,'triage','rtcm étape')",
                params![runbook],
            )
            .expect("fixture : étape");
            c.execute("DELETE FROM meta WHERE key IN ('seeded_default','seeded_demo')", []).expect("fixture : semis à faire");
            (incident, runbook)
        };
        let perimetre = || {
            purge_scope_from_args(&[("source".to_string(), "rtcm-purge".to_string())], &(t0 - 3600).to_string(), &t0.to_string(), t0)
                .expect("fixture : périmètre de purge")
        };
        let jeton = purge_plan(&st.db.lock(), perimetre()).expect("fixture : plan de purge").digest().to_string();

        // NÉGATIF — écrivain libre : la trace est écrite, rien n'est compté.
        let libre = tracer_apres_coup(&st.db.lock(), "rtcm-trace", "témoin", "rtcm : trace", || Ok(()));
        assert!(libre.is_ok(), "écrivain libre : la trace est écrite");
        assert_eq!(rtcm_compte(&st, "begin refusé rtcm-trace transaction_etrangere"), 0, "un BEGIN pris n'est pas compté");

        rtcm_transaction_etrangere(&st);
        let trace = tracer_apres_coup(&st.db.lock(), "rtcm-trace", "témoin", "rtcm : trace", || Ok(()));
        semer_la_demonstration(&st.db.lock());
        seed_default_dashboard(&st.db.lock());
        let purge =purge_confirm_and_apply(&st.db.lock(), perimetre(), &jeton, "rtcm", "témoin");
        let attache = crate::handlers::incidents::attach_runbook(&st.db.lock(), incident, runbook, "adm", &Default::default());
        rtcm_fermer_l_etrangere(&st);

        assert_eq!(trace, Err("rtcm : trace"), "la trace n'est pas écrite");
        assert!(purge.is_err(), "la purge n'a pas lieu");
        assert!(attache.is_err(), "l'attache n'a pas lieu");
        for journal in ["rtcm-trace", "demo", "seed", "purge", "runbooks"] {
            assert_eq!(rtcm_compte(&st, &format!("begin refusé {journal} transaction_etrangere")), 1, "`{journal}` : le BEGIN refusé est compté");
            assert_eq!(rtcm_compte(&st, &format!("begin refusé {journal} verrou")), 0, "`{journal}` : sous sa seule cause");
        }
        let c = st.db.lock();
        let lit = |sql: &str| -> i64 { c.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("`{sql}` ({e})")) };
        assert_eq!(lit("SELECT COUNT(*) FROM event WHERE source='rtcm-purge'"), 1, "rien n'est purgé");
        assert_eq!(lit("SELECT COUNT(*) FROM case_step"), 0, "aucune étape n'est attachée");
        assert_eq!(lit("SELECT COUNT(*) FROM meta WHERE key IN ('seeded_demo','seeded_default')"), 0, "rien n'est semé");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.26-d` — LES BALAYAGES DU CYCLE DE VIE DES ENGAGEMENTS : TROIS ÉTAPES, TROIS GESTES
    // -------------------------------------------------------------------------------------

    fn rtcm_engagements(st: &AppState, t: i64) {
        let c = st.db.lock();
        c.execute("DELETE FROM engagement", []).expect("fixture : table vide");
        for (id, statut, debut, fin) in [
            ("eng_rtcm_a", "active", t - 7200, t - 10),
            ("eng_rtcm_b", "active", t - 7200, t - 5),
            ("eng_rtcm_c", "scheduled", t - 10, t + 3600),
            ("eng_rtcm_d", "scheduled", t - 7200, t - 20),
        ] {
            c.execute(
                "INSERT INTO engagement(id,name,box,scope,window_start,window_end,status,created) VALUES(?1,?1,'greybox','[\"192.0.2.0/24\"]',?2,?3,?4,?2)",
                params![id, debut, fin, statut],
            )
            .expect("fixture : engagement");
        }
    }

    /// Les trois gestes du balayage, sous l'étape `etape`.
    fn rtcm_gestes_du_cycle(st: &AppState, etape: &str) -> [u64; 3] {
        ["expiration", "activation", "expiration sans activation"]
            .map(|geste| rtcm_compte(st, &format!("geste de fond non validé engagement : {geste} : {etape}")))
    }

    /// CE QU'IL TIENT : deux engagements actifs échus, un planifié qui s'ouvre, un planifié échu sans activation. `COMMIT`
    /// refusé : chaque geste est compté sous « COMMIT refusé » (2, 1, 1) ; `UPDATE engagement` refusé : sous « écriture
    /// refusée » (2, 1, 1) ; transaction étrangère : sous « BEGIN refusé » (2, 1, 1), et les quatre `BEGIN` refusés sont
    /// comptés comme tels. Contrôle négatif : levés, le balayage suivant fait les quatre gestes et ne compte AUCUN refus
    /// de plus. Servi : `/api/system/metrics` `scheduler.gestes_de_fond_non_valides` (par geste, dernière cause avec son étape)
    /// et `/metrics` `plume_scheduler_gestes_de_fond_non_valides_total` (compteur).
    ///
    /// LA DERNIÈRE CAUSE SERVIE EST CELLE DU DERNIER REFUS : la clé d'un geste réel (`engagement : expiration`) est
    /// partagée avec les témoins de `P10.25-e`, qui la font monter en parallèle — sa dernière cause n'y est jugée que sur
    /// son étape. Elle est jugée EXACTEMENT sous une clé propre au témoin (`rtcm : geste témoin`), refusée deux fois de
    /// suite pour deux causes différentes, par la même fonction que les balayages.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer le compte de `dire_un_geste_du_cycle_non_pris` (la forme d'avant) ;
    /// retirer `compter_un_begin_refuse` de `dire_un_begin_du_cycle_refuse` ; compter aussi le geste VALIDÉ ; retirer
    /// `poser_les_gestes_de_fond_non_valides` de `gather_json` ; garder la PREMIÈRE cause dans
    /// `consigner_avec_sa_derniere_cause` (mutation B3 de la vérification : `if e.1.is_empty() { e.1 = cause; }`).
    #[test]
    fn rtcm_un_geste_de_balayage_non_valide_est_compte_sous_son_etape() {
        let (st, _p) = sp_state("rtcm-balayages");
        let t = now();
        let balayer = |st: &AppState| {
            let c = st.db.lock();
            let expires = expire_due_engagements_conn(&c, t);
            let (actives, expires_planifies) = activate_due_engagements_conn(&c, t);
            (expires, actives, expires_planifies)
        };

        // `COMMIT` refusé.
        rtcm_engagements(&st, t);
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let fait = balayer(&st);
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(fait, (0, 0, 0), "fixture : aucun geste n'est fait");
        assert_eq!(rtcm_gestes_du_cycle(&st, "COMMIT refusé"), [2, 1, 1], "chaque COMMIT refusé est compté, par geste");

        // Écriture refusée.
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Update { table_name: "engagement", .. } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let fait = balayer(&st);
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(fait, (0, 0, 0), "fixture : aucun geste n'est fait");
        assert_eq!(rtcm_gestes_du_cycle(&st, "écriture refusée"), [2, 1, 1], "chaque écriture refusée est comptée, par geste");

        // `BEGIN` refusé (transaction étrangère).
        rtcm_transaction_etrangere(&st);
        let fait = balayer(&st);
        rtcm_fermer_l_etrangere(&st);
        assert_eq!(fait, (0, 0, 0), "fixture : aucun geste n'est fait");
        assert_eq!(rtcm_gestes_du_cycle(&st, "BEGIN refusé"), [2, 1, 1], "chaque BEGIN refusé est compté, par geste");
        assert_eq!(rtcm_compte(&st, "begin refusé engagement transaction_etrangere"), 4, "et comme BEGIN refusé (`P10.27-h`)");

        // NÉGATIF — levés : les quatre gestes sont faits, aucun refus de plus.
        let fait = balayer(&st);
        assert_eq!(fait, (2, 1, 1), "le balayage suivant fait les quatre gestes");
        for etape in ["COMMIT refusé", "écriture refusée", "BEGIN refusé"] {
            assert_eq!(rtcm_gestes_du_cycle(&st, etape), [2, 1, 1], "un geste validé n'est pas compté ({etape})");
        }

        // EXPOSITION.
        let m = rtcm_json(&st);
        let s = &m["scheduler"];
        let expiration = &s["gestes_de_fond_non_valides"]["engagement : expiration"];
        assert!(expiration["n"].as_u64().unwrap_or(0) >= 6, "le geste est servi avec son compte : {s}");
        let cause = expiration["derniere_cause"].as_str().unwrap_or("");
        assert!(
            ["COMMIT refusé : ", "écriture refusée : ", "BEGIN refusé : "].iter().any(|e| cause.starts_with(e)),
            "la dernière cause porte son étape : {cause}"
        );
        let total = s["gestes_de_fond_non_valides_total"].as_u64().expect("total servi");
        assert!(total >= 12, "le total est servi : {s}");
        // LA DERNIÈRE CAUSE, SOUS UNE CLÉ PROPRE AU TÉMOIN : deux refus successifs, deux causes réelles du moteur.
        {
            let c = st.db.lock();
            let premier = c.execute_batch("SELECT * FROM rtcm_table_absente_premiere").expect_err("fixture : premier refus");
            let dernier = c.execute_batch("SELECT * FROM rtcm_table_absente_derniere").expect_err("fixture : dernier refus");
            compter_un_geste_de_fond_non_valide(&c, "rtcm", "geste témoin", "BEGIN refusé", &premier);
            compter_un_geste_de_fond_non_valide(&c, "rtcm", "geste témoin", "COMMIT refusé", &dernier);
        }
        let temoin = rtcm_json(&st)["scheduler"]["gestes_de_fond_non_valides"]["rtcm : geste témoin"].clone();
        assert_eq!(temoin["n"].as_u64(), Some(2), "le geste du témoin est servi avec son compte exact : {temoin}");
        assert_eq!(
            temoin["derniere_cause"].as_str(),
            Some("COMMIT refusé : no such table: rtcm_table_absente_derniere"),
            "la dernière cause servie est celle du DERNIER refus, avec son étape"
        );
        let prom = rtcm_prom(&st);
        assert!(prom.contains("# TYPE plume_scheduler_gestes_de_fond_non_valides_total counter\n"), "la série est un compteur");
        assert!(
            rtcm_echantillon(&prom, "plume_scheduler_gestes_de_fond_non_valides_total").unwrap_or(0) >= total,
            "/metrics sert le même compteur que /api/system/metrics"
        );
        let aide = prom.lines().find(|l| l.starts_with("# HELP plume_scheduler_gestes_de_fond_non_valides_total ")).expect("la série est documentée");
        assert!(aide.contains("/api/system/metrics") && !aide.contains("/api/metrics"), "le # HELP renvoie à la route qui sert le JSON : {aide}");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.26-d` — LES DEUX PLIS DE `rollup_hosts`
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : pli définitif ouvert (watermark retiré) — refusé par une transaction étrangère, il est compté
    /// sous « BEGIN refusé » (et son `BEGIN` comme tel, journal `rollup`) ; `COMMIT` refusé : sous « COMMIT refusé » ;
    /// `INSERT` du watermark refusé : sous « écriture refusée ». Rattrapage ouvert (watermark dans le futur, plancher à 0),
    /// aux MÊMES trois étapes : transaction étrangère, « BEGIN refusé » ; `COMMIT` refusé, « COMMIT refusé » ; `INSERT` du
    /// plancher refusé, « écriture refusée » — et le plancher reste à 0 après chacun. Contrôle négatif : levés, les deux
    /// plis passent et rien de plus n'est compté.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer le compte de la branche `BEGIN` du pli définitif, de celle du
    /// rattrapage, ou de `dire_un_pli_non_valide` ; intervertir les deux étapes de `valider_ou_annuler_sa_transaction` ;
    /// avaler la branche d'erreur du rattrapage (mutation B2 de la vérification :
    /// `let _ = valider_ou_annuler_sa_transaction(conn, done);`).
    #[test]
    fn rtcm_un_pli_de_rollup_hosts_non_valide_est_compte_sous_son_etape() {
        let (st, _p) = sp_state("rtcm-plis");
        let pli = |etape: &str| rtcm_compte(&st, &format!("geste de fond non validé rollup : pli définitif de l'inventaire de flotte : {etape}"));
        let rattrapage = |etape: &str| rtcm_compte(&st, &format!("geste de fond non validé rollup : rattrapage de l'inventaire de flotte : {etape}"));
        let ouvrir_le_pli = |st: &AppState| {
            st.db.lock().execute("DELETE FROM meta WHERE key='host_rollup_wm'", []).expect("fixture : watermark retiré, le pli s'ouvre");
        };
        let refuser = |st: &AppState, refus: fn(&AuthAction<'_>) -> bool| {
            st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| if refus(&ctx.action) { Authorization::Deny } else { Authorization::Allow }));
        };
        let lever = |st: &AppState| st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);

        ouvrir_le_pli(&st);
        rtcm_transaction_etrangere(&st);
        rollup_hosts(&st.db.lock());
        rtcm_fermer_l_etrangere(&st);
        assert_eq!(pli("BEGIN refusé"), 1, "le pli refusé à son BEGIN est compté");
        assert_eq!(rtcm_compte(&st, "begin refusé rollup transaction_etrangere"), 1, "et son BEGIN comme tel");

        ouvrir_le_pli(&st);
        refuser(&st, |a| matches!(a, AuthAction::Transaction { operation: TransactionOperation::Unknown }));
        rollup_hosts(&st.db.lock());
        lever(&st);
        assert_eq!(pli("COMMIT refusé"), 1, "le pli refusé à son COMMIT est compté");

        ouvrir_le_pli(&st);
        refuser(&st, |a| matches!(a, AuthAction::Insert { table_name: "meta" }));
        rollup_hosts(&st.db.lock());
        lever(&st);
        assert_eq!(pli("écriture refusée"), 1, "le pli refusé à son écriture est compté");

        {
            let c = st.db.lock();
            c.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('host_rollup_wm',?1)", params![(now() + 10 * 86400).to_string()]).expect("fixture : watermark futur");
            c.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('host_rollup_backfill_floor','0')", []).expect("fixture : plancher noté");
        }
        let plancher = |st: &AppState| -> String {
            st.db.lock().query_row("SELECT value FROM meta WHERE key='host_rollup_backfill_floor'", [], |r| r.get(0)).expect("plancher")
        };
        rtcm_transaction_etrangere(&st);
        rollup_hosts(&st.db.lock());
        rtcm_fermer_l_etrangere(&st);
        assert_eq!(rattrapage("BEGIN refusé"), 1, "le rattrapage refusé à son BEGIN est compté");
        assert_eq!(plancher(&st), "0", "fixture : le rattrapage n'a pas eu lieu");

        refuser(&st, |a| matches!(a, AuthAction::Transaction { operation: TransactionOperation::Unknown }));
        rollup_hosts(&st.db.lock());
        lever(&st);
        assert_eq!(plancher(&st), "0", "fixture : le COMMIT du rattrapage a été refusé");
        assert_eq!(rattrapage("COMMIT refusé"), 1, "le rattrapage refusé à son COMMIT est compté");

        refuser(&st, |a| matches!(a, AuthAction::Insert { table_name: "meta" }));
        rollup_hosts(&st.db.lock());
        lever(&st);
        assert_eq!(plancher(&st), "0", "fixture : l'écriture du plancher a été refusée");
        assert_eq!(rattrapage("écriture refusée"), 1, "le rattrapage refusé à son écriture est compté");

        // NÉGATIF — levés : rattrapage puis pli définitif passent, rien de plus n'est compté.
        rollup_hosts(&st.db.lock());
        ouvrir_le_pli(&st);
        rollup_hosts(&st.db.lock());
        assert_ne!(plancher(&st), "0", "fixture : le rattrapage a eu lieu");
        assert!(st.db.lock().query_row("SELECT 1 FROM meta WHERE key='host_rollup_wm'", [], |_| Ok(())).is_ok(), "fixture : le pli a eu lieu");
        assert_eq!(
            [pli("BEGIN refusé"), pli("COMMIT refusé"), pli("écriture refusée")],
            [1, 1, 1],
            "un pli définitif validé n'est pas compté"
        );
        assert_eq!(
            [rattrapage("BEGIN refusé"), rattrapage("COMMIT refusé"), rattrapage("écriture refusée")],
            [1, 1, 1],
            "un rattrapage validé n'est pas compté"
        );
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.27-y` — LA SONDE DES TRANSACTIONS ORPHELINES, SERVIE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : écrivain en autocommit, la sonde ne compte rien ; une transaction laissée ouverte, DEUX ticks de
    /// détection la voient et la comptent chacun — la série est un COMPTE de passages, pas une présence. Le compte de
    /// processus est servi par `/api/system/metrics` (`transactions.orphelines_vues_total`, encadré par deux lectures du
    /// compteur, qui vaut au moins deux par construction du témoin) et par `/metrics`
    /// (`plume_transactions_orphelines_vues_total`, compteur, dont le `# HELP` dit qu'il est de processus tous tenants
    /// confondus, que la sonde ne ferme pas la transaction, et sur quoi alerter).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : servir un autre compte (ou zéro) sous `orphelines_vues_total` ; le servir comme
    /// une présence (mutation C2 de la vérification : `u64::from(transactions_ouvertes_hors_de_tout_geste() > 0)` — rouge
    /// même seul, puisque le témoin fait deux passages) ; retirer la série de `gather_prom` ; remettre `#[cfg(test)]` sur
    /// le lecteur (ne compile plus).
    #[test]
    fn rtcm_les_transactions_orphelines_vues_par_la_sonde_sont_servies() {
        let (st, p) = sp_state("rtcm-orpheline");
        assert!(!signaler_une_transaction_ouverte_hors_de_tout_geste(&st.db.lock(), "témoin"), "négatif : écrivain en autocommit");
        assert_eq!(rtcm_compte(&st, "orpheline vue"), 0, "rien n'est compté");

        st.db.lock().execute_batch("BEGIN IMMEDIATE; INSERT INTO meta(key,value) VALUES('rtcm-orpheline','1');").expect("fixture : transaction laissée ouverte");
        let _ = run_due_rules(&st.db, p.as_str());
        let _ = run_due_rules(&st.db, p.as_str());
        let avant = transactions_ouvertes_hors_de_tout_geste();
        let m = rtcm_json(&st);
        let apres = transactions_ouvertes_hors_de_tout_geste();
        let prom = rtcm_prom(&st);
        let apres_prom = transactions_ouvertes_hors_de_tout_geste();
        st.db.lock().execute_batch("ROLLBACK").expect("fixture : fermeture");

        assert_eq!(rtcm_compte(&st, "orpheline vue"), 2, "chaque tick de détection a vu et compté la transaction orpheline");
        let servi = m["transactions"]["orphelines_vues_total"].as_u64().expect("compte servi par /api/system/metrics");
        assert!(
            avant >= 2 && avant <= servi && servi <= apres,
            "/api/system/metrics sert le COMPTE de la sonde, pas sa présence : {avant} <= {servi} <= {apres}"
        );
        assert!(prom.contains("# TYPE plume_transactions_orphelines_vues_total counter\n"), "la série est un compteur");
        let aide = prom.lines().find(|l| l.starts_with("# HELP plume_transactions_orphelines_vues_total ")).expect("la série est documentée");
        assert!(aide.contains("tous tenants") && aide.contains("ne la ferme pas") && aide.contains("alerter"), "le # HELP documente la série : {aide}");
        let servi_prom = rtcm_echantillon(&prom, "plume_transactions_orphelines_vues_total").expect("échantillon servi par /metrics");
        assert!(apres <= servi_prom && servi_prom <= apres_prom, "/metrics sert le compte de la sonde : {apres} <= {servi_prom} <= {apres_prom}");
    }

    // -------------------------------------------------------------------------------------
    // (6) LA VENTILATION PAR JOURNAL EST BORNÉE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sous un plafond de deux, deux journaux ont chacun leur entrée, un journal existant continue de
    /// monter, et un troisième tombe sous `(autres)` sans créer d'entrée — le compte n'est jamais perdu.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer le test du plafond dans `entree_sous_plafond`.
    #[test]
    fn rtcm_la_ventilation_par_journal_est_bornee() {
        let mut v: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
        for journal in ["a", "b", "a", "c", "d"] {
            *entree_sous_plafond(&mut v, journal, 2) += 1;
        }
        assert_eq!(v.get("a"), Some(&2), "un journal déjà ventilé continue de monter");
        assert_eq!(v.get("b"), Some(&1));
        assert_eq!(v.get(CLE_DES_AUTRES), Some(&2), "au-delà du plafond, le compte va sous `(autres)`");
        assert_eq!(v.len(), 3, "et aucune entrée neuve n'est créée : {v:?}");
    }
}
