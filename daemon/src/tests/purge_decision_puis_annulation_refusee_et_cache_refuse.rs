// =====================================================================================
// `P10.29-l` / `P10.32-o` — UNE DÉCISION DE LA PURGE DONT L'ANNULATION EST REFUSÉE GARDE SON CODE ; LE VIDAGE DU CACHE
// RENDU EST LU PAR LA PURGE ; UNE LECTURE DE LIGNE DE CACHE REFUSÉE N'EST PLUS TUE COMME UNE ABSENCE.
//
// LES DÉFAUTS, RELUS SUR 092aade9 :
//  - `purge.rs::annuler_la_purge` rend `TransactionLeftOpen { id, etape }` quel que soit l'échec d'origine ; la route
//    (`handlers/purge.rs::statut_du_refus_de_purge`, bras `TransactionLeftOpen` du groupe 500, et
//    `purge_refusal_response`, corps `transaction_left_open`) servait donc 500 « la base a refusé l'opération » après une
//    DÉCISION du produit (`count_mismatch`, `stale_token`, `cold_tier`, `cited_by_case`, `fts_desync`) : le code de la
//    décision et le 409 étaient perdus ;
//  - `purge_delete_rows` appelait `panneau_avoue::cache_vider`, `execute(..).unwrap_or(0)` : un vidage REFUSÉ (c'est une
//    écriture, `DELETE FROM panel_cache`, pas une lecture comme le disait l'énoncé) rendait « 0 entrée vidée » et la
//    purge était validée avec des charges utiles qui portent le contenu purgé ;
//  - `panneau_avoue::cache_lire` finissait par `.ok()` : une lecture refusée ou une ligne illisible était une absence,
//    sans compte ni journal.
//
// CE QUE CES TÉMOINS JUGENT :
//  - par la ROUTE `purge_apply_route` (porte de témoin ouverte, compte admin), ROLLBACK refusé par un autorisateur, pour
//    quatre décisions provoquées DANS la transaction par un déclencheur : `count_mismatch` (une ligne ignorée par
//    `RAISE(IGNORE)`), `stale_token` (une ligne du périmètre change de source à l'inscription au registre : même compte,
//    autre ventilation), `cold_tier` (sceau posé à l'inscription), `cited_by_case` (citation posée à l'inscription) : 409,
//    corps ENTIER `{ok:false, refusal:<code>, message:<phrase écrite ici>, annulation_refusee:true, id}`, connexion
//    restée en transaction (fait constaté) ; registre et events intacts après fermeture à la main en DÉCOULENT (cohérence
//    de la fixture, pas un témoin distinct) ;
//  - `fts_desync` par `purge_apply` en appel direct (le déclencheur `event_ad` retiré entre confirmation et exécution :
//    un DDL ne se pose pas depuis un déclencheur), corps servi par `purge_refusal_response` ;
//  - contrôle : même `count_mismatch`, ROLLBACK pris -> 409 au corps d'avant (`Display` entier, phrase écrite ici) ;
//  - la LOI des codes : `match` EXHAUSTIF écrit ici (`dar_loi_attendue`, sans bras par défaut : une variante neuve ne
//    compile pas sans être classée), chaque forme jugée présente face à `purge::est_une_decision` (seule source, elle
//    aussi exhaustive : la liste de chaînes `est_une_decision_du_produit` et le bras `_ => CONFLICT` ont disparu) et au
//    409 ; puis la réponse servie par étape pour une `TransactionLeftOpen` construite dans le test (le classement fait
//    par `annuler_la_purge` est jugé par `purge_classement_de_l_annulation_et_site_de_la_cli.rs`) ;
//  - la ligne `[purge] ERREUR` (détail de la décision, sous l'identifiant servi) et la ligne `[purge] WARN` du cache non
//    vidé, ENTIÈRES, dans un sous-processus ;
//  - cache non vidé : déclencheur qui refuse le DELETE de `panel_cache` -> 500 `db` au corps entier, events, registre et
//    cache intacts ; contrôle positif : sans déclencheur, `panel_cache_cleared` = 1 et la purge est validée ;
//  - `cache_lire_dit` dans un sous-processus (compte de PRODUCTION `lectures_de_cache_refusees`, un enfant neuf part de
//    zéro) : absence -> `Absente` sans compte ; ligne valide -> `Lue` ; ligne illisible (BLOB) -> `Illisible`, compté ;
//    lecture refusée par l'autorisateur -> `NonLue`, compté ; absence relue après -> rien de plus ; aucune ligne de
//    journal (chaque appelant dit la sienne : `cache_non_lu_ne_remplace_pas_la_charge_valide.rs`).
// MUTANTS JOUÉS (`VERIF_MUT` sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : `DEC_STATUT` (décision servie
// en 500), `DEC_CORPS` (corps `transaction_left_open` d'avant), `DEC_DRAPEAU` (`annulation_refusee:false`),
// `DEC_SANS_<code>` pour chacun des six codes (code retiré de la loi), `DISPLAY_ANCIEN` (« Transaction ANNULÉE en entier »),
// `VIDER_AVALE` (vidage refusé rendu 0), `LIRE_MUET` (lecture refusée tue), `LIRE_SANS_COMPTE`, `LIRE_SANS_JOURNAL`,
// `LIRE_COMPTE_ABSENCE` (l'absence comptée). Correction après vérification : `DEC_DEFAUT_409` (bras par défaut de
// `statut_du_refus_de_purge` remis en 409), `DEC_LOI_COUNT` (`count_mismatch` sorti de `purge::est_une_decision`),
// `DEC_ANNULER_SANS_DECISION` (`annuler_la_purge` pose `decision: false`), `LIRE_ILLISIBLE_NON_LUE`.
// CE QUE CES TÉMOINS NE TIENNENT PAS : la console ne lit pas `stats.rafraichissement_en_echec` (web/, hors de ce lot) ;
// `legal_hold` n'atteint pas l'annulation (rendu par le seul plan, hors transaction) : sa ligne n'est jugée que par la loi
// des codes ; les lignes `[purge]` ne nomment pas le tenant (`purge_apply` ne le reçoit pas) ; le compte de
// `cache_lire_dit` n'est pas servi sous `/api/system/metrics`.
// =====================================================================================
mod purge_decision_puis_annulation_refusee_et_cache_refuse {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    /// Phrase attendue pour une décision dont l'annulation est refusée, écrite ICI.
    const DAR_PHRASE_DECISION: &str = "REFUS — l'état lu s'oppose à la purge (code `refusal`), puis la base a refusé \
         l'annulation de la transaction : la purge n'est pas validée, mais la transaction reste ouverte jusqu'à sa \
         fermeture ou au redémarrage du démon : un geste qui ouvre sa propre transaction est refusé, une écriture faite \
         sans transaction propre y est prise puis perdue à la fermeture. Le détail de la décision et la cause du refus \
         d'annulation sont écrits au journal du démon, sous l'identifiant servi.";

    /// Phrase attendue pour `transaction_left_open` (étape non décidée), écrite ICI.
    const DAR_PHRASE_RESTEE_OUVERTE: &str = "REFUS — la base a refusé l'opération, puis l'annulation de la transaction : \
         la purge n'est pas validée, mais la transaction reste ouverte jusqu'à sa fermeture ou au redémarrage du démon : \
         un geste qui ouvre sa propre transaction est refusé, une écriture faite sans transaction propre y est prise puis \
         perdue à la fermeture. La cause est écrite au journal du démon, sous l'identifiant servi.";

    /// Phrase attendue pour `db`, écrite ICI.
    const DAR_PHRASE_DB: &str = "REFUS — la base a refusé l'opération : la purge n'est pas faite, aucune ligne \
         supprimée. La cause est écrite au journal du démon, sous l'identifiant servi.";

    /// `Display` attendu de `count_mismatch` sur la fixture (6 inscrites, 5 supprimées), écrit ICI.
    const DAR_DISPLAY_COUNT: &str = "REFUS — INCOHÉRENCE registre/base : 6 ligne(s) inscrite(s), 5 supprimée(s). Rien \
         n'est validé, inscription au registre comprise (le registre ne peut pas affirmer autre chose que la réalité).";

    /// Déclencheur : la PREMIÈRE ligne du périmètre n'est pas supprimée (`RAISE(IGNORE)`) -> 5 supprimées sur 6 inscrites.
    const DAR_IGNORE_UNE: &str = "CREATE TRIGGER dar_ignore BEFORE DELETE ON event \
         WHEN OLD.id = (SELECT MIN(id) FROM event WHERE origin='') BEGIN SELECT RAISE(IGNORE); END;";

    fn dar_a_l_inscription(corps: &str) -> String {
        format!("CREATE TRIGGER dar_inscription AFTER INSERT ON ledger WHEN NEW.kind = '{PURGE_LEDGER_KIND}' BEGIN {corps} END;")
    }

    fn dar_refuser_le_rollback(st: &AppState, au: &AuthUser) {
        with_write(st, au, |c| {
            c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Transaction { operation: TransactionOperation::Rollback } => Authorization::Deny,
                _ => Authorization::Allow,
            }))
        });
    }

    fn dar_fermer_a_la_main(st: &AppState, au: &AuthUser) {
        with_write(st, au, |c| {
            c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            if !c.is_autocommit() {
                c.execute_batch("ROLLBACK").expect("annulation à la main, autorisateur retiré");
            }
        });
    }

    fn dar_id(corps: &Value) -> String {
        let id = corps["id"].as_str().unwrap_or_else(|| panic!("`id` de corrélation servi : {corps}")).to_string();
        let n = id.strip_prefix(&format!("plume-e{}-", std::process::id())).unwrap_or_else(|| panic!("forme de `{id}`"));
        assert!(!n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()), "forme de `{id}`");
        id
    }

    async fn dar_jeton(st: &AppState, au: &AuthUser) -> String {
        let (statut, plan) = pcr_plan(st, au).await;
        assert_eq!(statut, 200, "précondition : plan servi : {plan}");
        plan["token"].as_str().expect("jeton servi").to_string()
    }

    /// Joue une décision provoquée par `fixture` (posée APRÈS le plan), ROLLBACK refusé, par la route ; juge 409 et corps
    /// entier, connexion restée en transaction, puis registre et events intacts après fermeture à la main.
    async fn dar_jouer_decision(tag: &str, avant_plan: &str, fixture: &str, code: &str) {
        let (st, _p) = pcr_etat(tag);
        let au = pcr_admin();
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        if !avant_plan.is_empty() {
            pcr_ecrire(&st, &au, avant_plan);
        }
        let jeton = dar_jeton(&st, &au).await;
        let registre = with_write(&st, &au, |c| pcr_registre(c));
        pcr_ecrire(&st, &au, fixture);
        dar_refuser_le_rollback(&st, &au);
        let (statut, corps) = pcr_apply(&st, &au, &jeton).await;
        let autocommit = with_write(&st, &au, |c| c.is_autocommit());
        dar_fermer_a_la_main(&st, &au);
        assert_eq!(statut, 409, "{code} : la décision garde son 409 : {corps}");
        let id = dar_id(&corps);
        assert_eq!(
            corps,
            json!({ "ok": false, "refusal": code, "message": DAR_PHRASE_DECISION, "annulation_refusee": true, "id": id }),
            "{code} : corps entier"
        );
        assert!(!autocommit, "{code} : fait constaté, la connexion est restée en transaction");
        // Cohérence de la fixture, PAS un témoin distinct : la connexion étant restée en transaction (assertion ci-dessus),
        // le ROLLBACK à la main de `dar_fermer_a_la_main` annule tout ; registre et events intacts en découlent.
        assert_eq!(with_write(&st, &au, |c| pcr_registre(c)), registre, "{code} : registre inchangé");
        assert_eq!(pcr_events_servis(&st, &au), 6, "{code} : events intacts");
    }

    #[tokio::test]
    async fn dar_count_mismatch_annulation_refusee_garde_409() {
        dar_jouer_decision("dar-count", "", DAR_IGNORE_UNE, "count_mismatch").await;
    }

    #[tokio::test]
    async fn dar_stale_token_annulation_refusee_garde_409() {
        let fixture = dar_a_l_inscription(
            "UPDATE event SET source='flux-c' WHERE id = (SELECT MIN(id) FROM event WHERE origin='');",
        );
        dar_jouer_decision("dar-stale", "", &fixture, "stale_token").await;
    }

    #[tokio::test]
    async fn dar_cold_tier_annulation_refusee_garde_409() {
        let creer = "CREATE TABLE IF NOT EXISTS cold_seal(env_id TEXT NOT NULL, day INTEGER NOT NULL, seq INTEGER NOT NULL, \
           expected_rows INTEGER NOT NULL, sealed_ts INTEGER NOT NULL, purged INTEGER NOT NULL DEFAULT 0, \
           max_id INTEGER NOT NULL, ts_min INTEGER NOT NULL, ts_max INTEGER NOT NULL, lo_ts INTEGER NOT NULL, \
           lo_id INTEGER NOT NULL, hi_id INTEGER NOT NULL, last_file INTEGER NOT NULL DEFAULT 0, \
           PRIMARY KEY(env_id,day,seq));";
        let fixture = dar_a_l_inscription("INSERT INTO cold_seal VALUES('prod',1,0,6,0,1,99,1000,1005,1000,1,99,1);");
        dar_jouer_decision("dar-cold", creer, &fixture, "cold_tier").await;
    }

    #[tokio::test]
    async fn dar_cited_by_case_annulation_refusee_garde_409() {
        let fixture = dar_a_l_inscription(
            "INSERT INTO incident_item(incident_id,ts,kind,author,body,ref) \
             SELECT 1,0,'event','adm','','event:' || MIN(id) FROM event WHERE origin='';",
        );
        dar_jouer_decision("dar-cited", "", &fixture, "cited_by_case").await;
    }

    /// `fts_desync` : le déclencheur `event_ad` retiré entre la confirmation et l'exécution (appel direct de
    /// `purge_apply`), ROLLBACK refusé ; le corps est celui que la route sert (`purge_refusal_response`).
    #[tokio::test]
    async fn dar_fts_desync_annulation_refusee_garde_409() {
        let (st, _p) = pcr_etat("dar-fts");
        let au = pcr_admin();
        let confirme = with_write(&st, &au, |c| pcr_confirmer(c).0);
        pcr_ecrire(&st, &au, "DROP TRIGGER event_ad;");
        dar_refuser_le_rollback(&st, &au);
        let r = with_write(&st, &au, |c| purge_apply(c, confirme));
        let autocommit = with_write(&st, &au, |c| c.is_autocommit());
        dar_fermer_a_la_main(&st, &au);
        let e = match r {
            Err(e @ PurgeRefusal::TransactionLeftOpen { .. }) => e,
            Err(e) => panic!("transaction_left_open attendu, rendu `{e}`"),
            Ok(_) => panic!("le déclencheur `event_ad` est retiré : refus attendu"),
        };
        assert!(!autocommit, "fait constaté : la connexion est restée en transaction");
        let (statut, corps) = pcr_lire(purge_refusal_response(e)).await;
        assert_eq!(statut, 409, "fts_desync garde son 409 : {corps}");
        let id = dar_id(&corps);
        assert_eq!(
            corps,
            json!({ "ok": false, "refusal": "fts_desync", "message": DAR_PHRASE_DECISION, "annulation_refusee": true, "id": id }),
            "corps entier"
        );
    }

    /// Contrôle : même décision, ROLLBACK PRIS -> 409 au corps d'avant, `Display` entier, connexion en autocommit.
    #[tokio::test]
    async fn dar_count_mismatch_annulation_prise_sert_le_corps_d_avant() {
        let (st, _p) = pcr_etat("dar-count-pris");
        let au = pcr_admin();
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        let jeton = dar_jeton(&st, &au).await;
        pcr_ecrire(&st, &au, DAR_IGNORE_UNE);
        let (statut, corps) = pcr_apply(&st, &au, &jeton).await;
        assert_eq!(statut, 409, "{corps}");
        assert_eq!(corps, json!({ "ok": false, "refusal": "count_mismatch", "message": DAR_DISPLAY_COUNT }), "corps entier");
        assert!(with_write(&st, &au, |c| c.is_autocommit()), "ROLLBACK pris");
        assert_eq!(pcr_events_servis(&st, &au), 6, "events intacts");
    }

    /// LA LOI ATTENDUE, écrite ICI par un `match` EXHAUSTIF sans bras par défaut (modèle : `prs_chaque_refus_est_servi_avec_sa_nature`) :
    /// une variante neuve de `PurgeRefusal` ne compile pas tant qu'elle n'est pas classée ici. Rend (rang de la forme, décision).
    fn dar_loi_attendue(v: &PurgeRefusal) -> (u8, bool) {
        match v {
            PurgeRefusal::LegalHold(_) => (0, true),
            PurgeRefusal::ColdTier { .. } => (1, true),
            PurgeRefusal::CitedByCase { .. } => (2, true),
            PurgeRefusal::FtsDesync => (3, true),
            PurgeRefusal::StaleToken { .. } => (4, true),
            PurgeRefusal::CountMismatch { .. } => (5, true),
            PurgeRefusal::LegalHoldUndetermined => (6, false),
            PurgeRefusal::LegalHoldUnread(_) => (7, false),
            PurgeRefusal::ReasonRequired => (8, false),
            PurgeRefusal::PlanRowUnread { .. } => (9, false),
            PurgeRefusal::TransactionNotOpened => (10, false),
            PurgeRefusal::Db(_) => (11, false),
            PurgeRefusal::TransactionLeftOpen { decision: true, .. } => (12, true),
            PurgeRefusal::TransactionLeftOpen { decision: false, .. } => (13, false),
        }
    }

    /// LA LOI DES CODES : chaque forme (les quatorze rangs de `dar_loi_attendue`, jugés présents, pas comptés) face à
    /// `purge::est_une_decision` et au statut servi ; puis, pour chaque variante d'origine, la réponse servie pour une
    /// `TransactionLeftOpen` construite ICI (étape = code d'origine, décision lue par `est_une_decision`) : la boucle juge
    /// la réponse par étape, pas le classement fait par `annuler_la_purge` (jugé, pour une lecture non faite dans la
    /// transaction, par `purge_classement_de_l_annulation_et_site_de_la_cli.rs`).
    #[tokio::test]
    async fn dar_loi_des_codes_et_reponse_par_etape() {
        let origines: Vec<PurgeRefusal> = vec![
            PurgeRefusal::LegalHold(vec!["h".into()]),
            PurgeRefusal::ColdTier { files: 1, days: 1 },
            PurgeRefusal::CitedByCase { ids: vec![1], total: 1 },
            PurgeRefusal::FtsDesync,
            PurgeRefusal::StaleToken { expected: "a".into(), got: "b".into() },
            PurgeRefusal::CountMismatch { declared: 2, deleted: 1 },
            PurgeRefusal::LegalHoldUndetermined,
            PurgeRefusal::LegalHoldUnread("x".into()),
            PurgeRefusal::ReasonRequired,
            PurgeRefusal::PlanRowUnread { site: "sources", cause: "x".into() },
            PurgeRefusal::TransactionNotOpened,
            PurgeRefusal::Db("x".into()),
        ];
        let mut formes: Vec<PurgeRefusal> = origines.clone();
        formes.push(PurgeRefusal::TransactionLeftOpen { id: "x".into(), etape: "count_mismatch", decision: true });
        formes.push(PurgeRefusal::TransactionLeftOpen { id: "x".into(), etape: "db", decision: false });
        let rangs: std::collections::BTreeSet<u8> = formes.iter().map(|v| dar_loi_attendue(v).0).collect();
        assert_eq!(rangs, (0u8..14).collect(), "chaque forme de la loi attendue est jugée");
        for v in &formes {
            let (_, attendu) = dar_loi_attendue(v);
            assert_eq!(crate::purge::est_une_decision(v), attendu, "loi de `{}`", purge_refusal_code(v));
            let statut = crate::handlers::purge::statut_du_refus_de_purge(v).as_u16();
            if attendu {
                assert_eq!(statut, 409, "décision `{}` en 409", purge_refusal_code(v));
            } else {
                assert_ne!(statut, 409, "`{}` n'est pas une décision : jamais 409", purge_refusal_code(v));
            }
        }
        for origine in &origines {
            let (_, attendu) = dar_loi_attendue(origine);
            let etape = purge_refusal_code(origine);
            let restee = PurgeRefusal::TransactionLeftOpen { id: "dar-id".into(), etape, decision: crate::purge::est_une_decision(origine) };
            let (statut, corps) = pcr_lire(purge_refusal_response(restee)).await;
            if attendu {
                assert_eq!(statut, 409, "étape `{etape}` : {corps}");
                assert_eq!(
                    corps,
                    json!({ "ok": false, "refusal": etape, "message": DAR_PHRASE_DECISION, "annulation_refusee": true, "id": "dar-id" }),
                    "étape `{etape}` : corps entier"
                );
            } else {
                assert_eq!(statut, 500, "étape `{etape}` : {corps}");
                assert_eq!(
                    corps,
                    json!({ "ok": false, "refusal": "transaction_left_open", "message": DAR_PHRASE_RESTEE_OUVERTE, "id": "dar-id" }),
                    "étape `{etape}` : corps entier"
                );
            }
        }
        // `COMMIT refusé` : étape hors des codes, origine `db` (`purge_apply`) -> 500.
        let (statut, _) = pcr_lire(purge_refusal_response(PurgeRefusal::TransactionLeftOpen {
            id: "dar-id".into(),
            etape: "COMMIT refusé",
            decision: false,
        }))
        .await;
        assert_eq!(statut, 500, "COMMIT refusé");
    }

    fn dar_poser_une_ligne_de_cache(st: &AppState, au: &AuthUser) {
        pcr_ecrire(st, au, "INSERT INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(77,'rk','fp',1,'{}');");
    }

    fn dar_lignes_de_cache(st: &AppState, au: &AuthUser) -> i64 {
        with_write(st, au, |c| c.query_row("SELECT COUNT(*) FROM panel_cache", [], |r| r.get(0)).expect("compte du cache"))
    }

    /// Le vidage du cache rendu REFUSÉ fait refuser la purge (`db`), rien n'est validé ; contrôle positif sans refus.
    #[tokio::test]
    async fn dar_cache_non_vide_refuse_la_purge() {
        let (st, _p) = pcr_etat("dar-cache");
        let au = pcr_admin();
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        dar_poser_une_ligne_de_cache(&st, &au);
        let jeton = dar_jeton(&st, &au).await;
        let registre = with_write(&st, &au, |c| pcr_registre(c));
        pcr_ecrire(&st, &au, "CREATE TRIGGER dar_cache BEFORE DELETE ON panel_cache BEGIN SELECT RAISE(ABORT, 'dar-cache'); END;");
        let (statut, corps) = pcr_apply(&st, &au, &jeton).await;
        assert_eq!(statut, 500, "{corps}");
        let id = dar_id(&corps);
        assert_eq!(corps, json!({ "ok": false, "refusal": "db", "message": DAR_PHRASE_DB, "id": id }), "corps entier");
        assert_eq!(pcr_events_servis(&st, &au), 6, "events intacts");
        assert_eq!(with_write(&st, &au, |c| pcr_registre(c)), registre, "registre inchangé");
        assert_eq!(dar_lignes_de_cache(&st, &au), 1, "cache intact");
        // Contrôle positif : déclencheur retiré, la purge est validée et dit l'entrée vidée.
        pcr_ecrire(&st, &au, "DROP TRIGGER dar_cache;");
        let jeton = dar_jeton(&st, &au).await;
        let (statut, recu) = pcr_apply(&st, &au, &jeton).await;
        assert_eq!(statut, 200, "{recu}");
        assert_eq!(recu["panel_cache_cleared"], json!(1), "une entrée vidée : {recu}");
        assert_eq!(dar_lignes_de_cache(&st, &au), 0, "cache vidé");
        assert_eq!(pcr_events_servis(&st, &au), 0, "events purgés");
    }

    /// LES LIGNES DE JOURNAL, dans un sous-processus : `[purge] ERREUR` d'une décision dont l'annulation est refusée
    /// (détail de la décision, rang n° 1) et `[purge] WARN` du cache non vidé, ENTIÈRES, sous leurs identifiants servis.
    #[tokio::test]
    async fn dar_lignes_de_journal_de_la_purge_entieres() {
        const ENFANT: &str = "DAR_ENFANT_JOURNAL_PURGE";
        if std::env::var(ENFANT).is_ok() {
            let (st, _p) = pcr_etat("dar-journal");
            let au = pcr_admin();
            let _ouverte = porte_de_purge_de_temoin::ouvrir();
            dar_poser_une_ligne_de_cache(&st, &au);
            let jeton = dar_jeton(&st, &au).await;
            pcr_ecrire(&st, &au, DAR_IGNORE_UNE);
            dar_refuser_le_rollback(&st, &au);
            eprintln!("DAR-DEBUT");
            let (_, corps) = pcr_apply(&st, &au, &jeton).await;
            dar_fermer_a_la_main(&st, &au);
            pcr_ecrire(&st, &au, "DROP TRIGGER dar_ignore; CREATE TRIGGER dar_cache BEFORE DELETE ON panel_cache BEGIN SELECT RAISE(ABORT, 'dar-cache'); END;");
            let jeton = dar_jeton(&st, &au).await;
            let (_, corps2) = pcr_apply(&st, &au, &jeton).await;
            eprintln!("DAR-FIN");
            println!("DAR-ID:{}", corps["id"].as_str().unwrap_or_default());
            println!("DAR-ID2:{}", corps2["id"].as_str().unwrap_or_default());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::purge_decision_puis_annulation_refusee_et_cache_refuse::dar_lignes_de_journal_de_la_purge_entieres",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let lire = |cle: &str| stdout.split_once(cle).map(|(_, r)| r.lines().next().unwrap_or("")).unwrap_or("").to_string();
        let (id, id2) = (lire("DAR-ID:"), lire("DAR-ID2:"));
        assert!(id.starts_with("plume-e") && id2.starts_with("plume-e") && id != id2, "contrôle : deux `id` servis : {stdout}");
        let fenetre = stderr
            .split_once("DAR-DEBUT")
            .and_then(|(_, r)| r.split_once("DAR-FIN"))
            .map(|(c, _)| c)
            .unwrap_or_else(|| panic!("contrôle : fenêtre de journal : {stderr}"));
        let lignes: Vec<&str> = fenetre.lines().filter(|l| l.contains("[purge]")).collect();
        let erreur = format!(
            "[{id}] [purge] ERREUR purge confirmée : transaction toujours OUVERTE après « count_mismatch » puis un ROLLBACK \
             refusé (\"not authorized\") ; refus d'origine : \"{DAR_DISPLAY_COUNT}\" — rien n'est validé, l'écrivain reste en \
             transaction jusqu'à sa fermeture (BEGIN refusés, écritures sans BEGIN prises puis perdues ; ROLLBACK de purge \
             refusé n° 1 depuis le démarrage)"
        );
        let warn = format!(
            "[{id2}] [purge] WARN refus servi, refus de la base (db) : \"cache de panneaux NON VIDÉ (dar-cache [code étendu \
             1811]) — ses charges utiles portent le contenu purgé, purge refusée\""
        );
        assert_eq!(lignes, vec![erreur.as_str(), warn.as_str()], "deux lignes [purge], entières : {fenetre}");
    }

    /// `cache_lire_dit` : absence, ligne valide, ligne illisible, lecture refusée ; compte de PRODUCTION, dans un
    /// sous-processus (le compte est par processus). Aucune ligne de journal ICI : chaque appelant dit à SA ligne ce qu'il
    /// fait de l'issue (`cache_non_lu_ne_remplace_pas_la_charge_valide.rs`).
    #[test]
    fn dar_cache_lire_distingue_le_refus_de_l_absence() {
        const ENFANT: &str = "DAR_ENFANT_CACHE_LIRE";
        if std::env::var(ENFANT).is_ok() {
            let c = test_db();
            c.execute_batch(
                "INSERT INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(7,'rk','fp',100,'{\"rows\":[]}'); \
                 INSERT INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(8,'rk','fp',100,X'00');",
            )
            .expect("fixture");
            let mut comptes = vec![panneau_avoue::lectures_de_cache_refusees()];
            eprintln!("DAR-DEBUT");
            let absent = panneau_avoue::cache_lire_dit(&c, 9, "rk", "fp");
            comptes.push(panneau_avoue::lectures_de_cache_refusees());
            let valide = panneau_avoue::cache_lire_dit(&c, 7, "rk", "fp");
            comptes.push(panneau_avoue::lectures_de_cache_refusees());
            let illisible = panneau_avoue::cache_lire_dit(&c, 8, "rk", "fp");
            comptes.push(panneau_avoue::lectures_de_cache_refusees());
            c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Read { table_name: "panel_cache", column_name: "payload" } => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            let refusee = panneau_avoue::cache_lire_dit(&c, 7, "rk", "fp");
            comptes.push(panneau_avoue::lectures_de_cache_refusees());
            c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            let absent2 = panneau_avoue::cache_lire_dit(&c, 9, "rk", "fp");
            comptes.push(panneau_avoue::lectures_de_cache_refusees());
            eprintln!("DAR-FIN");
            println!("DAR-ISSUES:{:?}|{:?}|{:?}|{:?}|{:?}", absent, valide, illisible, refusee, absent2);
            println!("DAR-COMPTES:{comptes:?}");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::purge_decision_puis_annulation_refusee_et_cache_refuse::dar_cache_lire_distingue_le_refus_de_l_absence",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let issues = stdout.split_once("DAR-ISSUES:").map(|(_, r)| r.lines().next().unwrap_or("")).unwrap_or("");
        assert_eq!(
            issues,
            "Absente|Lue(\"{\\\"rows\\\":[]}\", 100)|Illisible(\"Invalid column type Blob at index: 0, name: payload \
             (lecture de cache ratée n° 1 depuis le démarrage)\")|NonLue(\"access to panel_cache.payload is prohibited \
             [code étendu 23] (lecture de cache ratée n° 2 depuis le démarrage)\")|Absente",
            "issues : absence, valide, illisible, refusée, absence : {stdout}"
        );
        assert!(stdout.contains("DAR-COMPTES:[0, 0, 0, 1, 2, 2]"), "compte de production : {stdout}");
        let fenetre = stderr
            .split_once("DAR-DEBUT")
            .and_then(|(_, r)| r.split_once("DAR-FIN"))
            .map(|(c, _)| c)
            .unwrap_or_else(|| panic!("contrôle : fenêtre de journal : {stderr}"));
        let lignes: Vec<&str> = fenetre.lines().filter(|l| l.contains("[panel]")).collect();
        assert!(lignes.is_empty(), "`cache_lire_dit` n'écrit aucune ligne, ses appelants la disent : {fenetre}");
    }
}
