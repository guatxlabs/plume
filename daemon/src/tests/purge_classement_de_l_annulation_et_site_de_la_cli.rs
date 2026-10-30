// =====================================================================================
// `P10.29-l` — UNE LECTURE NON FAITE DANS LA TRANSACTION DE LA PURGE, SUIVIE D'UN ROLLBACK REFUSÉ, N'EST PAS UNE DÉCISION ;
// ET LA CLI DE PURGE SERT, À SON SITE, LE CODE QUE SERT LA ROUTE.
//
// LES DÉFAUTS, RELEVÉS PAR LE VÉRIFICATEUR SUR 7e40a9b2 :
//  (1) `purge.rs::annuler_la_purge` classe l'échec d'origine (`est_une_decision`) ; ce classement n'était témoigné que
//      pour les décisions et pour `db`. Le mutant `!matches!(origine, PurgeRefusal::Db(_))` restait vert : avec lui, une
//      LECTURE NON FAITE levée dans la transaction (rétention légale indéterminable relue par `hold_guard`, ligne citée
//      non lue par `cited_by_case`) puis un ROLLBACK refusé étaient servis en 409 « l'état lu s'oppose à la purge » ;
//  (2) aucun témoin n'atteignait le site de la CLI (`purge_cli`, branche `--json`) : seul l'assistant
//      `purge_refusal_cli_json` était jugé, et l'ancien corps remis au site restait vert.
//
// LE CORRECTIF : (2) la fin de `purge_cli` (simulation, confirmation, exécution, rendu, code de sortie) est sortie dans
// `purge::purge_cli_sur`, sur une connexion déjà ouverte par la porte ; `purge_cli` écrit ses deux sorties telles quelles
// et sort avec son code. Ces témoins l'appellent sur une base de test, ROLLBACK refusé par un autorisateur.
//
// CE QUE CES TÉMOINS JUGENT :
//  - `legal_hold_undetermined` relu DANS la transaction (lecture de `legal_hold` refusée APRÈS l'inscription au registre,
//    donc ni le plan ni la re-simulation ne la voient), ROLLBACK refusé : par la ROUTE `purge_apply_route`, 500 au corps
//    ENTIER `transaction_left_open` ; en appel direct de `purge_apply`, `TransactionLeftOpen { etape, decision: false }` ;
//  - `plan_row_unread` levé DANS la transaction (citation posée après la confirmation, lecture de la liste des events
//    cités interrompue au pas par le gestionnaire de progression), ROLLBACK refusé : variante et corps servi (500) ;
//  - `legal_hold_unread` n'est PAS levé dans la transaction : `holds_covering` n'est appelé que par `purge_plan`, hors
//    transaction (la relecture de `purge_delete_rows` passe par `hold_guard`) ; l'énoncé qui le citait parmi les lectures
//    de la transaction ne tenait pas ;
//  - le site de la CLI (`purge_cli_sur`) : décision puis ROLLBACK refusé en `--json` (code de la décision, `id`,
//    `annulation_refusee`, sortie 3) ; lecture non faite puis ROLLBACK refusé en `--json` (`transaction_left_open`, `id`,
//    sans `annulation_refusee`) et en texte (le `Display` entier sur la sortie d'erreur, sortie 3) ; succès (simulation
//    et exécution, JSON et texte : sortie 0, rien sur la sortie d'erreur).
// MUTANTS JOUÉS (`VERIF_MUT` sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : `BB1_DECISION`
// (`annuler_la_purge` classe par `!matches!(origine, PurgeRefusal::Db(_))`), `BB1_CLI` (l'ancien corps
// `{ok, refusal: purge_refusal_code(&e), message}` remis au site), `BB1_CODE` (refus rendu en sortie 1), `BB1_TEXTE`
// (refus en texte rendu muet).
// CE QUE CES TÉMOINS NE TIENNENT PAS : `purge_cli` lui-même (lecture des arguments, porte de la base, écriture des deux
// sorties, `exit`). Il est EXÉCUTÉ par `main` en sous-processus, arguments après `--`, dans
// purge_cli_executee_en_sous_processus.rs (refus ordinaire `stale_token`, JSON et texte, simulation, et décision
// `count_mismatch` puis ROLLBACK refusé, l'enfant posant lui-même son autorisateur par `sqlite3_auto_extension`).
// =====================================================================================
mod purge_classement_de_l_annulation_et_site_de_la_cli {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// Phrase servie par la route pour `transaction_left_open` (étape non décidée), écrite ICI.
    const BB1_PHRASE_RESTEE_OUVERTE: &str = "REFUS — la base a refusé l'opération, puis l'annulation de la transaction : \
         la purge n'est pas validée, mais la transaction reste ouverte jusqu'à sa fermeture ou au redémarrage du démon : \
         un geste qui ouvre sa propre transaction est refusé, une écriture faite sans transaction propre y est prise puis \
         perdue à la fermeture. La cause est écrite au journal du démon, sous l'identifiant servi.";

    /// `Display` de `TransactionLeftOpen` (ce que la CLI rend), écrit ICI ; `<ETAPE>` et `<ID>` sont remplacés.
    const BB1_DISPLAY_RESTEE_OUVERTE: &str = "REFUS — PURGE NON VALIDÉE, TRANSACTION RESTÉE OUVERTE : <ETAPE>, puis la \
         base a refusé le ROLLBACK qui devait l'annuler. Rien n'est validé, mais la connexion reste en transaction jusqu'à \
         sa fermeture ou à la fin du processus (fin de la CLI, redémarrage du démon) : un geste qui ouvre sa propre \
         transaction est refusé, une écriture faite sans transaction propre y est prise puis perdue à la fermeture. Les \
         causes sont écrites au journal sous l'identifiant <ID>.";

    /// Déclencheur : la PREMIÈRE ligne du périmètre n'est pas supprimée -> `count_mismatch` (décision) dans la transaction.
    const BB1_IGNORE_UNE: &str = "CREATE TRIGGER bb1_ignore BEFORE DELETE ON event \
         WHEN OLD.id = (SELECT MIN(id) FROM event WHERE origin='') BEGIN SELECT RAISE(IGNORE); END;";

    /// Une citation d'un event du périmètre par un case.
    const BB1_CITATION: &str = "INSERT INTO incident_item(incident_id,ts,kind,author,body,ref) \
         SELECT 1,0,'event','adm','','event:' || MIN(id) FROM event WHERE origin='';";

    /// Ce que l'autorisateur fait échouer, en plus du ROLLBACK (toujours refusé).
    #[derive(Clone, Copy, PartialEq)]
    enum Echec {
        /// Rien d'autre : seule l'annulation est refusée.
        RollbackSeul,
        /// Toute lecture de `legal_hold` APRÈS l'inscription au registre (donc dans la transaction) : `hold_guard` rend
        /// `legal_hold_undetermined`.
        HoldDansLaTransaction,
        /// Le DEUXIÈME énoncé qui lit `incident_item` après l'inscription (la liste des events cités de
        /// `cited_by_case`, après son compte) est interrompu à son premier pas : `plan_row_unread`.
        LigneCiteeDansLaTransaction,
    }

    fn bb1_armer(c: &Connection, echec: Echec) {
        let interrompre = Arc::new(AtomicBool::new(false));
        let pour_le_moteur = interrompre.clone();
        c.progress_handler(1, Some(move || pour_le_moteur.swap(false, Ordering::SeqCst)));
        let (mut inscrit, mut selects, mut dernier_lisant, mut lisants) = (false, 0u32, 0u32, 0u32);
        c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Rollback } => Authorization::Deny,
            AuthAction::Insert { table_name } if table_name == "ledger" => {
                inscrit = true;
                Authorization::Allow
            }
            AuthAction::Select if inscrit => {
                selects += 1;
                Authorization::Allow
            }
            AuthAction::Read { table_name, .. }
                if inscrit && echec == Echec::HoldDansLaTransaction && table_name == "legal_hold" =>
            {
                Authorization::Deny
            }
            AuthAction::Read { table_name, .. }
                if inscrit && echec == Echec::LigneCiteeDansLaTransaction && table_name == "incident_item" =>
            {
                if selects != dernier_lisant {
                    dernier_lisant = selects;
                    lisants += 1;
                    if lisants == 2 {
                        interrompre.store(true, Ordering::SeqCst);
                    }
                }
                Authorization::Allow
            }
            _ => Authorization::Allow,
        }));
    }

    /// Retire autorisateur et gestionnaire ; rend l'état constaté (autocommit ?) AVANT la fermeture à la main.
    fn bb1_desarmer(c: &Connection) -> bool {
        let autocommit = c.is_autocommit();
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        c.progress_handler(1, None::<fn() -> bool>);
        if !autocommit {
            c.execute_batch("ROLLBACK").expect("annulation à la main, autorisateur retiré");
        }
        autocommit
    }

    fn bb1_id(id: &str) -> String {
        let n = id.strip_prefix(&format!("plume-e{}-", std::process::id())).unwrap_or_else(|| panic!("forme de `{id}`"));
        assert!(!n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()), "forme de `{id}`");
        id.to_string()
    }

    fn bb1_display(etape: &str, id: &str) -> String {
        BB1_DISPLAY_RESTEE_OUVERTE.replace("<ETAPE>", etape).replace("<ID>", id)
    }

    /// Exige `TransactionLeftOpen { etape, decision: false }` et rend son identifiant.
    fn bb1_restee_ouverte_sans_decision(r: &Result<PurgeReceipt, PurgeRefusal>, etape_attendue: &str) -> String {
        match r {
            Err(PurgeRefusal::TransactionLeftOpen { id, etape, decision }) => {
                assert_eq!(*etape, etape_attendue, "étape nommée");
                assert!(!*decision, "`{etape}` est une lecture non faite, pas une décision du produit");
                bb1_id(id)
            }
            Err(e) => panic!("transaction_left_open attendu, rendu `{}` : {e}", purge_refusal_code(e)),
            Ok(_) => panic!("refus attendu"),
        }
    }

    async fn bb1_corps_servi(e: PurgeRefusal, id: &str) {
        let (statut, corps) = pcr_lire(purge_refusal_response(e)).await;
        assert_eq!(statut, 500, "lecture non faite puis ROLLBACK refusé : jamais 409 : {corps}");
        assert_eq!(
            corps,
            json!({ "ok": false, "refusal": "transaction_left_open", "message": BB1_PHRASE_RESTEE_OUVERTE, "id": id }),
            "corps entier"
        );
    }

    // ── (1) LE CLASSEMENT DANS `annuler_la_purge` ────────────────────────────────────────────

    /// Par la ROUTE : la rétention légale devient indéterminable APRÈS l'inscription au registre (dans la transaction),
    /// ROLLBACK refusé -> 500 `transaction_left_open`, corps entier, connexion restée en transaction.
    #[tokio::test]
    async fn bb1_hold_indetermine_dans_la_transaction_route_500() {
        let (st, _p) = pcr_etat("bb1-hold-route");
        let au = pcr_admin();
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        let (statut, plan) = pcr_plan(&st, &au).await;
        assert_eq!(statut, 200, "précondition : plan servi : {plan}");
        let jeton = plan["token"].as_str().expect("jeton servi").to_string();
        let registre = with_write(&st, &au, |c| pcr_registre(c));
        with_write(&st, &au, |c| bb1_armer(c, Echec::HoldDansLaTransaction));
        let (statut, corps) = pcr_apply(&st, &au, &jeton).await;
        let autocommit = with_write(&st, &au, |c| bb1_desarmer(c));
        assert!(!autocommit, "fait constaté : la connexion est restée en transaction : {corps}");
        assert_eq!(statut, 500, "une lecture non faite n'est pas servie en 409 : {corps}");
        let id = bb1_id(corps["id"].as_str().unwrap_or_else(|| panic!("`id` servi : {corps}")));
        assert_eq!(
            corps,
            json!({ "ok": false, "refusal": "transaction_left_open", "message": BB1_PHRASE_RESTEE_OUVERTE, "id": id }),
            "corps entier"
        );
        assert_eq!(with_write(&st, &au, |c| pcr_registre(c)), registre, "registre inchangé après fermeture");
        assert_eq!(pcr_events_servis(&st, &au), 6, "events intacts");
    }

    /// En appel direct : la variante porte l'étape `legal_hold_undetermined` et `decision: false`.
    #[tokio::test]
    async fn bb1_hold_indetermine_dans_la_transaction_variante() {
        let c = pcr_base();
        let (confirme, _) = pcr_confirmer(&c);
        bb1_armer(&c, Echec::HoldDansLaTransaction);
        let r = purge_apply(&c, confirme);
        let autocommit = bb1_desarmer(&c);
        assert!(!autocommit, "fait constaté : la connexion est restée en transaction");
        let id = bb1_restee_ouverte_sans_decision(&r, "legal_hold_undetermined");
        bb1_corps_servi(r.err().unwrap(), &id).await;
        assert_eq!(pcr_events(&c), 6, "events intacts");
    }

    /// La liste des events cités, relue dans la transaction, n'est pas lue (premier pas interrompu) : `plan_row_unread`, puis
    /// ROLLBACK refusé -> `decision: false`, 500.
    #[tokio::test]
    async fn bb1_ligne_citee_non_lue_dans_la_transaction_variante() {
        let c = pcr_base();
        let (confirme, _) = pcr_confirmer(&c);
        c.execute_batch(BB1_CITATION).expect("citation posée après la confirmation");
        bb1_armer(&c, Echec::LigneCiteeDansLaTransaction);
        let r = purge_apply(&c, confirme);
        let autocommit = bb1_desarmer(&c);
        assert!(!autocommit, "fait constaté : la connexion est restée en transaction");
        let id = bb1_restee_ouverte_sans_decision(&r, "plan_row_unread");
        bb1_corps_servi(r.err().unwrap(), &id).await;
        assert_eq!(pcr_events(&c), 6, "events intacts");
    }

    // ── (2) LE SITE DE LA CLI ────────────────────────────────────────────────────────────────

    fn bb1_jeton(c: &Connection) -> String {
        purge_plan(c, pcr_scope()).expect("plan nominal").digest().to_string()
    }

    /// Une seule ligne JSON sur la sortie standard, rien sur la sortie d'erreur, sortie 3.
    fn bb1_refus_json(s: &crate::purge::SortieDeLaPurgeCli) -> Value {
        assert_eq!(s.code, 3, "un refus sort en 3 : {}", s.stdout);
        assert!(s.stderr.is_empty(), "rien sur la sortie d'erreur en --json : {}", s.stderr);
        let ligne = s.stdout.strip_suffix('\n').unwrap_or_else(|| panic!("une ligne terminée : {:?}", s.stdout));
        assert!(!ligne.contains('\n'), "une seule ligne : {:?}", s.stdout);
        serde_json::from_str(ligne).unwrap_or_else(|e| panic!("JSON lisible ({e}) : {ligne}"))
    }

    /// Décision (`count_mismatch`) puis ROLLBACK refusé, `--json` : le code de la décision, `annulation_refusee`, `id`.
    #[test]
    fn bb1_cli_decision_puis_annulation_refusee_json() {
        let c = pcr_base();
        let jeton = bb1_jeton(&c);
        c.execute_batch(BB1_IGNORE_UNE).expect("déclencheur posé après le plan");
        bb1_armer(&c, Echec::RollbackSeul);
        let s = crate::purge::purge_cli_sur(&c, pcr_scope(), Some(&jeton), "témoin P10.29-l", "cli:t", true);
        let autocommit = bb1_desarmer(&c);
        assert!(!autocommit, "fait constaté : la connexion est restée en transaction");
        let corps = bb1_refus_json(&s);
        let id = bb1_id(corps["id"].as_str().unwrap_or_else(|| panic!("`id` rendu : {corps}")));
        assert_eq!(
            corps,
            json!({
                "ok": false, "refusal": "count_mismatch", "message": bb1_display("count_mismatch", &id),
                "id": id, "annulation_refusee": true
            }),
            "corps entier de la CLI"
        );
        assert_eq!(pcr_events(&c), 6, "events intacts");
    }

    /// Lecture non faite dans la transaction puis ROLLBACK refusé, `--json` : `transaction_left_open`, `id`, sans
    /// `annulation_refusee`.
    #[test]
    fn bb1_cli_lecture_non_faite_puis_annulation_refusee_json() {
        let c = pcr_base();
        let jeton = bb1_jeton(&c);
        bb1_armer(&c, Echec::HoldDansLaTransaction);
        let s = crate::purge::purge_cli_sur(&c, pcr_scope(), Some(&jeton), "témoin P10.29-l", "cli:t", true);
        let autocommit = bb1_desarmer(&c);
        assert!(!autocommit, "fait constaté : la connexion est restée en transaction");
        let corps = bb1_refus_json(&s);
        let id = bb1_id(corps["id"].as_str().unwrap_or_else(|| panic!("`id` rendu : {corps}")));
        assert_eq!(
            corps,
            json!({
                "ok": false, "refusal": "transaction_left_open",
                "message": bb1_display("legal_hold_undetermined", &id), "id": id
            }),
            "corps entier de la CLI"
        );
    }

    /// Même refus en texte : le `Display` entier sur la sortie d'erreur, rien sur la sortie standard, sortie 3.
    #[test]
    fn bb1_cli_lecture_non_faite_puis_annulation_refusee_texte() {
        let c = pcr_base();
        let jeton = bb1_jeton(&c);
        bb1_armer(&c, Echec::HoldDansLaTransaction);
        let s = crate::purge::purge_cli_sur(&c, pcr_scope(), Some(&jeton), "témoin P10.29-l", "cli:t", false);
        let autocommit = bb1_desarmer(&c);
        assert!(!autocommit, "fait constaté : la connexion est restée en transaction");
        assert_eq!(s.code, 3, "un refus sort en 3 : {}", s.stderr);
        assert!(s.stdout.is_empty(), "rien sur la sortie standard : {}", s.stdout);
        let ligne = s.stderr.strip_suffix('\n').unwrap_or_else(|| panic!("une ligne terminée : {:?}", s.stderr));
        let id = ligne.rsplit("l'identifiant ").next().and_then(|r| r.strip_suffix('.')).unwrap_or_default();
        let id = bb1_id(id);
        assert_eq!(ligne, bb1_display("legal_hold_undetermined", &id), "Display entier");
    }

    /// Succès : simulation puis exécution, en JSON et en texte : sortie 0, rien sur la sortie d'erreur.
    #[test]
    fn bb1_cli_succes_simulation_et_execution() {
        let c = pcr_base();
        let sim = crate::purge::purge_cli_sur(&c, pcr_scope(), None, "", "cli:t", false);
        assert_eq!((sim.code, sim.stderr.as_str()), (0, ""), "simulation en texte");
        assert!(sim.stdout.starts_with("SIMULATION DE PURGE (aucune ligne supprimée)\n"), "{}", sim.stdout);
        let sim = crate::purge::purge_cli_sur(&c, pcr_scope(), None, "", "cli:t", true);
        assert_eq!((sim.code, sim.stderr.as_str()), (0, ""), "simulation en JSON");
        let plan: Value = serde_json::from_str(sim.stdout.strip_suffix('\n').expect("ligne terminée")).expect("JSON");
        let jeton = plan["token"].as_str().expect("jeton rendu").to_string();
        assert_eq!(pcr_events(&c), 6, "la simulation n'écrit rien");
        let fait = crate::purge::purge_cli_sur(&c, pcr_scope(), Some(&jeton), "témoin P10.29-l", "cli:t", true);
        assert_eq!((fait.code, fait.stderr.as_str()), (0, ""), "exécution en JSON : {}", fait.stdout);
        let recu: Value = serde_json::from_str(fait.stdout.strip_suffix('\n').expect("ligne terminée")).expect("JSON");
        assert_eq!((recu["ok"].clone(), recu["rows_deleted"].clone()), (json!(true), json!(6)), "{recu}");
        assert_eq!(pcr_events(&c), 0, "purge faite");
        let b = pcr_base();
        let fait = crate::purge::purge_cli_sur(&b, pcr_scope(), Some(&bb1_jeton(&b)), "témoin P10.29-l", "cli:t", false);
        assert_eq!((fait.code, fait.stderr.as_str()), (0, ""), "exécution en texte : {}", fait.stdout);
        assert!(!fait.stdout.is_empty(), "le reçu est rendu en texte");
        assert_eq!(pcr_events(&b), 0, "purge faite");
    }
}
