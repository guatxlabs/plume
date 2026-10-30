// =====================================================================================
// `P10.29-l` (tranche purge) — UN `ROLLBACK` REFUSÉ APRÈS L'EXÉCUTION REFUSÉE D'UNE PURGE EST LU, DIT ET COMPTÉ.
//
// LE DÉFAUT, RELU SUR e66bb760 (`purge.rs::purge_apply`) : après un `COMMIT` refusé et après un refus de
// `purge_delete_rows`, l'annulation s'écrivait `let _ = conn.execute_batch("ROLLBACK")`. Un `ROLLBACK` refusé laissait la
// connexion de l'écrivain EN TRANSACTION, sans un mot au journal ni un compte, et la route servait `db` « aucune ligne
// supprimée » — la phrase d'un refus proprement annulé — sur un écrivain bloqué.
//
// CE QUE CES TÉMOINS JUGENT, par la ROUTE `purge_apply_route` entière (porte de témoin ouverte sur ce fil, compte admin) :
//  - DELETE refusé par un déclencheur (`RAISE(ABORT)`) puis `ROLLBACK` refusé par un autorisateur : 500, corps ENTIER
//    `{ok:false, refusal:"transaction_left_open", message:<phrase écrite ici>, id}`, ni le texte du déclencheur ni celui
//    de l'autorisateur dans le corps, refus compté UNE fois sur la base, la connexion reste en transaction (fait constaté,
//    `is_autocommit`) ; après coup, autorisateur retiré et annulation faite à la main, le
//    registre est intact (les events le sont par construction, le déclencheur refusant tout DELETE) ;
//  - `COMMIT` refusé (clé étrangère DIFFÉRÉE violée) puis `ROLLBACK` refusé : même réponse, étape « COMMIT refusé »
//    et `Display` ENTIER (la phrase que la CLI écrit) en appel direct, compté une fois. « Rien n'a été validé » n'y est
//    PAS jugé : la clé différée violée rend tout `COMMIT` impossible, l'assertion serait vraie quel que soit le code ;
//  - contrôle positif : DELETE refusé, `ROLLBACK` pris -> `db` servi comme avant, rien compté, connexion en autocommit ;
//  - bras « refus sans information » : le déclencheur lève `RAISE(ROLLBACK)` (le moteur annule lui-même) et
//    l'autorisateur refuse aussi le `ROLLBACK` -> la connexion est en autocommit, donc `db` servi, rien compté ;
//  - la ligne de journal ET le compte de PRODUCTION `ROLLBACKS_DE_PURGE_REFUSES`, capturés dans un SOUS-PROCESSUS (le
//    compte est par processus : un enfant neuf part de zéro) qui joue quatre purges refusées — restée ouverte, ROLLBACK
//    pris, moteur qui annule lui-même avec ROLLBACK refusé, restée ouverte : deux lignes `[purge] ERREUR`, comparées
//    ENTIÈRES, chacune sous son identifiant servi, rangs « n° 1 » puis « n° 2 ». Le rang est la valeur du compte de
//    production (sa seule lecture par le démon, il n'est pas servi sous `/api/system/metrics`) : figé, monté sur un
//    ROLLBACK pris ou sur une connexion revenue en autocommit, il rougit. Le « compté une fois » des témoins en
//    processus lit le miroir par connexion `noter_pour_les_temoins` (le compte de processus y est partagé entre fils) ;
//    le quatrième refus, qui passe son `BEGIN` après la fermeture à la main, montre aussi que la transaction laissée
//    ouverte ne bloque que jusqu'à sa fermeture ;
//  - en appel direct, la connexion revenue en autocommit rend le refus D'ORIGINE (cause comprise), et la phrase dit vrai
//    sur l'écrivain resté en transaction : `BEGIN` refusé, écriture sans `BEGIN` acceptée puis perdue à la fermeture.
// MUTANTS JOUÉS (variable de mutation sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : `AW8_ROLLBACK_MUET` (refus du
// ROLLBACK jeté après un refus d'exécution), `AW8_COMMIT_MUET` (même chose après un COMMIT refusé), `AW8_SANS_COMPTE`,
// `AW8_COMPTE_SUR_ERR` (tout ROLLBACK en erreur pris pour une transaction restée ouverte), `AW8_SANS_JOURNAL`,
// `AW8_ID_DIFFERENT` (la réponse tire un identifiant neuf), `AW8_PHRASE_DB` (la variante servie sous la phrase de `db`),
// `AW8_STATUT_503` ; puis, à la reprise (une compilation), `AX5_RANG_FIGE` (le rang lu sans incrémenter le compte de
// processus), `AX5_COMPTE_AVANT_OK` (compté avant de lire le ROLLBACK), `AX5_COMPTE_AVANT_AUTOCOMMIT` (compté avant de
// relire l'autocommit), `AX5_DISPLAY` (la variante affichée sous la phrase de `db`) et `AX5_PHRASE_ANCIENNE` (la phrase
// servie « jusqu'au redémarrage du démon ») ; puis, à la correction, `M_AUTOCOMMIT_CAUSE_PERDUE` (connexion revenue en
// autocommit : le refus du ROLLBACK rendu à la place du refus d'origine — le corps servi est le même, seul le `Display`
// le montre), `AX5B_PHRASE_REFUSEES` et `AX5B_DISPLAY_ANCIEN` (phrase servie / `Display` qui affirment « les écritures
// suivantes sont refusées », faux pour une écriture sans BEGIN, constaté par `prrc_ecriture_sans_begin_prise_puis_perdue`).
// CE QUE CES TÉMOINS NE TIENNENT PAS : la ligne `[purge]` ne nomme pas le tenant (`purge_apply` ne le reçoit pas,
// l'identifiant relie la ligne au ticket) ; le compte de processus (`ROLLBACKS_DE_PURGE_REFUSES`, son rang est sur la ligne
// `[purge]`) n'est pas servi sous `/api/system/metrics` (fichiers de métriques hors de cette tranche) ; la CLI n'est pas
// relancée en sous-processus : le `Display` qu'elle écrit (même variante) est jugé ENTIER en appel direct, et la CLI ne
// fait que l'écrire (`purge.rs`, fin de la sous-commande `purge` : `eprintln!("{e}")`, ou `e.to_string()` en JSON).
// =====================================================================================
mod purge_rollback_refuse_dit_et_compte {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    /// Phrase attendue pour `transaction_left_open`, écrite ICI (pas relue dans la constante de production).
    const PRRC_PHRASE_RESTEE_OUVERTE: &str = "REFUS — la base a refusé l'opération, puis l'annulation de la transaction : \
         la purge n'est pas validée, mais la transaction reste ouverte jusqu'à sa fermeture ou au redémarrage du démon : \
         un geste qui ouvre sa propre transaction est refusé, une écriture faite sans transaction propre y est prise puis \
         perdue à la fermeture. La cause est écrite au journal du démon, sous l'identifiant servi.";

    /// Phrase attendue pour `db`, écrite ICI.
    const PRRC_PHRASE_DB: &str = "REFUS — la base a refusé l'opération : la purge n'est pas faite, aucune ligne \
         supprimée. La cause est écrite au journal du démon, sous l'identifiant servi.";

    const PRRC_COMPTE: &str = "rollback de purge refusé";

    fn prrc_refuser_le_rollback(st: &AppState, au: &AuthUser) {
        with_write(st, au, |c| {
            c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Transaction { operation: TransactionOperation::Rollback } => Authorization::Deny,
                _ => Authorization::Allow,
            }))
        });
    }

    /// Retire l'autorisateur et ferme à la main ce que la purge a laissé ouvert (fin de témoin).
    fn prrc_fermer_a_la_main(st: &AppState, au: &AuthUser) {
        with_write(st, au, |c| {
            c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            if !c.is_autocommit() {
                c.execute_batch("ROLLBACK").expect("annulation à la main, autorisateur retiré");
            }
        });
    }

    fn prrc_compte(st: &AppState, au: &AuthUser) -> u64 {
        with_write(st, au, |c| crate::comptes_de_transaction::compte_des_temoins(c, PRRC_COMPTE))
    }

    fn prrc_juger_l_identifiant(corps: &Value) -> String {
        let id = corps["id"].as_str().unwrap_or_else(|| panic!("`id` de corrélation servi : {corps}")).to_string();
        let n = id.strip_prefix(&format!("plume-e{}-", std::process::id())).unwrap_or_else(|| panic!("forme de `{id}`"));
        assert!(!n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()), "forme de `{id}`");
        id
    }

    /// Juge la réponse servie quand la transaction est restée ouverte : 500, corps ENTIER, aucun texte du moteur.
    fn prrc_juger_restee_ouverte(statut: u16, corps: &Value, moteurs: &[&str]) -> String {
        assert_eq!(statut, 500, "transaction restée ouverte servie en 500 : {corps}");
        let id = prrc_juger_l_identifiant(corps);
        assert_eq!(
            corps,
            &json!({ "ok": false, "refusal": "transaction_left_open", "message": PRRC_PHRASE_RESTEE_OUVERTE, "id": id }),
            "corps entier"
        );
        for m in moteurs {
            assert!(!corps.to_string().contains(m), "le texte du moteur `{m}` hors du corps : {corps}");
        }
        id
    }

    fn prrc_juger_db(statut: u16, corps: &Value) {
        assert_eq!(statut, 500, "`db` servi en 500 : {corps}");
        let id = prrc_juger_l_identifiant(corps);
        assert_eq!(corps, &json!({ "ok": false, "refusal": "db", "message": PRRC_PHRASE_DB, "id": id }), "corps entier de `db`");
    }

    async fn prrc_jeton(st: &AppState, au: &AuthUser) -> String {
        let (statut, plan) = pcr_plan(st, au).await;
        assert_eq!(statut, 200, "précondition : plan servi : {plan}");
        plan["token"].as_str().expect("jeton servi").to_string()
    }

    fn prrc_poser_la_cle_differee(st: &AppState, au: &AuthUser) {
        pcr_ecrire(
            st,
            au,
            "PRAGMA foreign_keys=ON; \
             CREATE TABLE prrc_enfant(e INTEGER REFERENCES event(id) DEFERRABLE INITIALLY DEFERRED); \
             INSERT INTO prrc_enfant SELECT id FROM event WHERE origin='' LIMIT 1;",
        );
    }

    /// DELETE refusé par le déclencheur, puis ROLLBACK refusé : variante nommée, compte, connexion restée en transaction.
    #[tokio::test]
    async fn prrc_delete_refuse_puis_rollback_refuse_par_la_route() {
        let (st, _p) = pcr_etat("prrc-delete");
        let au = pcr_admin();
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        let jeton = prrc_jeton(&st, &au).await;
        let registre = with_write(&st, &au, |c| pcr_registre(c));
        pcr_ecrire(&st, &au, "CREATE TRIGGER prrc_refus BEFORE DELETE ON event BEGIN SELECT RAISE(ABORT, 'prrc-moteur'); END;");
        prrc_refuser_le_rollback(&st, &au);
        let (statut, corps) = pcr_apply(&st, &au, &jeton).await;
        prrc_juger_restee_ouverte(statut, &corps, &["prrc-moteur", "not authorized"]);
        assert_eq!(prrc_compte(&st, &au), 1, "le ROLLBACK refusé est compté une fois");
        assert!(!with_write(&st, &au, |c| c.is_autocommit()), "fait constaté : la connexion est restée en transaction");
        prrc_fermer_a_la_main(&st, &au);
        // Seul le registre est jugé : les events sont intacts par construction (le déclencheur refuse tout DELETE).
        assert_eq!(with_write(&st, &au, |c| pcr_registre(c)), registre, "registre inchangé");
    }

    /// Le COMMIT refusé, puis le ROLLBACK refusé : l'étape est « COMMIT refusé » (appel direct), compté une fois.
    #[test]
    fn prrc_commit_refuse_puis_rollback_refuse_nomme_l_etape() {
        let (st, _p) = pcr_etat("prrc-commit-direct");
        let au = pcr_admin();
        prrc_poser_la_cle_differee(&st, &au);
        let plan = with_write(&st, &au, |c| purge_plan(c, pcr_scope()).expect("plan nominal"));
        let jeton = plan.digest().to_string();
        prrc_refuser_le_rollback(&st, &au);
        let r = with_write(&st, &au, |c| purge_confirm_and_apply(c, pcr_scope(), &jeton, "t", "témoin P10.29-l"));
        let e = match r {
            Err(e @ PurgeRefusal::TransactionLeftOpen { .. }) => e,
            Err(e) => panic!("transaction_left_open attendu après un COMMIT refusé, rendu `{e}`"),
            Ok(_) => panic!("la clé différée violée refuse le COMMIT"),
        };
        let PurgeRefusal::TransactionLeftOpen { id, etape, .. } = &e else { unreachable!() };
        assert_eq!(*etape, "COMMIT refusé");
        // Le `Display` est ce que la CLI écrit (sortie d'erreur et champ `message` du JSON) : phrase ENTIÈRE, écrite ICI.
        assert_eq!(
            e.to_string(),
            format!(
                "REFUS — PURGE NON VALIDÉE, TRANSACTION RESTÉE OUVERTE : COMMIT refusé, puis la base a refusé le ROLLBACK \
                 qui devait l'annuler. Rien n'est validé, mais la connexion reste en transaction jusqu'à sa fermeture \
                 ou à la fin du processus (fin de la CLI, redémarrage du démon) : un geste qui ouvre sa propre \
                 transaction est refusé, une écriture faite sans transaction propre y est prise puis perdue à la \
                 fermeture. Les causes sont écrites au journal sous l'identifiant {id}."
            ),
            "phrase servie à la CLI"
        );
        assert_eq!(prrc_compte(&st, &au), 1, "compté une fois");
        prrc_fermer_a_la_main(&st, &au);
    }

    /// Le COMMIT refusé puis le ROLLBACK refusé, par la ROUTE : corps entier.
    #[tokio::test]
    async fn prrc_commit_refuse_puis_rollback_refuse_par_la_route() {
        let (st, _p) = pcr_etat("prrc-commit");
        let au = pcr_admin();
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        prrc_poser_la_cle_differee(&st, &au);
        let jeton = prrc_jeton(&st, &au).await;
        prrc_refuser_le_rollback(&st, &au);
        let (statut, corps) = pcr_apply(&st, &au, &jeton).await;
        prrc_juger_restee_ouverte(statut, &corps, &["FOREIGN KEY", "not authorized"]);
        assert_eq!(prrc_compte(&st, &au), 1, "compté une fois");
        assert!(!with_write(&st, &au, |c| c.is_autocommit()), "fait constaté : la connexion est restée en transaction");
        prrc_fermer_a_la_main(&st, &au);
    }

    /// Contrôle positif : le ROLLBACK est pris -> `db` comme avant, rien compté, connexion en autocommit.
    #[tokio::test]
    async fn prrc_rollback_pris_sert_db_et_ne_compte_rien() {
        let (st, _p) = pcr_etat("prrc-pris");
        let au = pcr_admin();
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        let jeton = prrc_jeton(&st, &au).await;
        pcr_ecrire(&st, &au, "CREATE TRIGGER prrc_refus BEFORE DELETE ON event BEGIN SELECT RAISE(ABORT, 'prrc-moteur'); END;");
        let (statut, corps) = pcr_apply(&st, &au, &jeton).await;
        prrc_juger_db(statut, &corps);
        assert_eq!(prrc_compte(&st, &au), 0, "rien compté : le ROLLBACK est pris");
        assert!(with_write(&st, &au, |c| c.is_autocommit()), "connexion revenue en autocommit");
    }

    /// Le moteur a annulé lui-même (`RAISE(ROLLBACK)`) et le ROLLBACK de la purge est refusé : la connexion est en
    /// autocommit, ce refus n'est pas une information -> `db`, rien compté.
    #[tokio::test]
    async fn prrc_rollback_refuse_sans_transaction_ouverte_n_est_pas_compte() {
        let (st, _p) = pcr_etat("prrc-deja-annulee");
        let au = pcr_admin();
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        let jeton = prrc_jeton(&st, &au).await;
        pcr_ecrire(&st, &au, "CREATE TRIGGER prrc_refus BEFORE DELETE ON event BEGIN SELECT RAISE(ROLLBACK, 'prrc-moteur'); END;");
        prrc_refuser_le_rollback(&st, &au);
        let (statut, corps) = pcr_apply(&st, &au, &jeton).await;
        let autocommit = with_write(&st, &au, |c| c.is_autocommit());
        prrc_fermer_a_la_main(&st, &au);
        prrc_juger_db(statut, &corps);
        assert!(autocommit, "contrôle : le moteur a annulé la transaction lui-même");
        assert_eq!(prrc_compte(&st, &au), 0, "rien compté : aucune transaction n'est restée ouverte");
    }

    /// Le moteur a annulé lui-même et le ROLLBACK de la purge est refusé : c'est le refus D'ORIGINE qui sort, sa cause
    /// comprise (le `Display` que la CLI écrit et que la ligne `WARN` de la route recopie), pas le refus du ROLLBACK. Le
    /// corps servi (`db`, phrase fixe) ne le distingue pas : seul le `Display` en appel direct le peut. Le ROLLBACK pris
    /// est joué en contrôle, sur la même forme.
    #[test]
    fn prrc_moteur_qui_annule_rend_la_cause_d_origine() {
        let (st, _p) = pcr_etat("prrc-cause-origine");
        let au = pcr_admin();
        let jouer = |declencheur: &str, refuser: bool| -> (String, bool) {
            pcr_ecrire(&st, &au, &format!("DROP TRIGGER IF EXISTS prrc_refus; {declencheur}"));
            let plan = with_write(&st, &au, |c| purge_plan(c, pcr_scope()).expect("plan nominal"));
            let jeton = plan.digest().to_string();
            if refuser {
                prrc_refuser_le_rollback(&st, &au);
            }
            let r = with_write(&st, &au, |c| purge_confirm_and_apply(c, pcr_scope(), &jeton, "t", "témoin P10.29-l"));
            let autocommit = with_write(&st, &au, |c| c.is_autocommit());
            prrc_fermer_a_la_main(&st, &au);
            match r {
                Err(e @ PurgeRefusal::Db(_)) => (e.to_string(), autocommit),
                Err(e) => panic!("`db` attendu, rendu `{e}`"),
                Ok(_) => panic!("le déclencheur refuse le DELETE"),
            }
        };
        let (pris, autocommit_pris) =
            jouer("CREATE TRIGGER prrc_refus BEFORE DELETE ON event BEGIN SELECT RAISE(ABORT, 'prrc-moteur'); END;", false);
        assert!(autocommit_pris, "contrôle : ROLLBACK pris");
        assert_eq!(pris, "REFUS — base : prrc-moteur (aucune ligne supprimée)", "contrôle : ROLLBACK pris, cause d'origine");
        let (annule, autocommit) =
            jouer("CREATE TRIGGER prrc_refus BEFORE DELETE ON event BEGIN SELECT RAISE(ROLLBACK, 'prrc-origine'); END;", true);
        assert!(autocommit, "contrôle : le moteur a annulé la transaction lui-même");
        assert_eq!(
            annule, "REFUS — base : prrc-origine (aucune ligne supprimée)",
            "le refus d'origine sort tel quel, pas celui du ROLLBACK"
        );
        assert_eq!(prrc_compte(&st, &au), 0, "rien compté");
    }

    /// CE QUE DIT LA PHRASE de `transaction_left_open`, constaté : sur l'écrivain resté en transaction, un geste qui ouvre
    /// sa transaction (`ouvrir_sa_transaction`, `BEGIN IMMEDIATE`) est refusé, mais une écriture sans `BEGIN` est ACCEPTÉE
    /// dans la transaction pendante, puis perdue quand on la ferme. « Les écritures suivantes sont refusées » serait faux.
    #[test]
    fn prrc_ecriture_sans_begin_prise_puis_perdue() {
        let (st, _p) = pcr_etat("prrc-ecriture-perdue");
        let au = pcr_admin();
        pcr_ecrire(&st, &au, "CREATE TABLE prrc_t(v INTEGER); CREATE TRIGGER prrc_refus BEFORE DELETE ON event BEGIN SELECT RAISE(ABORT, 'prrc-moteur'); END;");
        let plan = with_write(&st, &au, |c| purge_plan(c, pcr_scope()).expect("plan nominal"));
        let jeton = plan.digest().to_string();
        prrc_refuser_le_rollback(&st, &au);
        let r = with_write(&st, &au, |c| purge_confirm_and_apply(c, pcr_scope(), &jeton, "t", "témoin P10.29-l"));
        assert!(matches!(r, Err(PurgeRefusal::TransactionLeftOpen { .. })), "précondition : transaction restée ouverte");
        let (insere, begin_refuse) = with_write(&st, &au, |c| {
            let insere = c.execute("INSERT INTO prrc_t VALUES (1)", []);
            let begin = crate::handlers::transaction_validee::ouvrir_sa_transaction(c, "purge", "témoin P10.29-l");
            (insere.map_err(|e| e.to_string()), begin.is_err())
        });
        assert_eq!(insere, Ok(1), "l'écriture sans BEGIN est acceptée dans la transaction pendante");
        assert!(begin_refuse, "un geste qui ouvre sa transaction est refusé");
        prrc_fermer_a_la_main(&st, &au);
        let n: i64 = with_write(&st, &au, |c| c.query_row("SELECT COUNT(*) FROM prrc_t", [], |r| r.get(0)).expect("compte"));
        assert_eq!(n, 0, "l'écriture acceptée est perdue à la fermeture");
    }

    /// LA LIGNE DE JOURNAL ET LE COMPTE DE PRODUCTION, capturés dans un sous-processus : quatre purges refusées, deux
    /// lignes ERREUR ENTIÈRES sous leurs identifiants servis, rangs 1 puis 2.
    #[tokio::test]
    async fn prrc_ligne_de_journal_entiere_sous_l_identifiant_servi() {
        const ENFANT: &str = "PRRC_ENFANT_JOURNAL";
        if std::env::var(ENFANT).is_ok() {
            let (st, _p) = pcr_etat("prrc-journal");
            let au = pcr_admin();
            let _ouverte = porte_de_purge_de_temoin::ouvrir();
            let jeton = prrc_jeton(&st, &au).await;
            pcr_ecrire(&st, &au, "CREATE TRIGGER prrc_refus BEFORE DELETE ON event BEGIN SELECT RAISE(ABORT, 'prrc-moteur'); END;");
            prrc_refuser_le_rollback(&st, &au);
            eprintln!("PRRC-DEBUT");
            // 1. ROLLBACK refusé, transaction restée ouverte : compté (n° 1).
            let (_, corps) = pcr_apply(&st, &au, &jeton).await;
            prrc_fermer_a_la_main(&st, &au);
            // 2. ROLLBACK pris (autorisateur retiré) : `db`, ni ligne ni compte.
            let jeton = prrc_jeton(&st, &au).await;
            let (_, corps_pris) = pcr_apply(&st, &au, &jeton).await;
            // 3. Le moteur annule lui-même (`RAISE(ROLLBACK)`), le ROLLBACK de la purge est refusé : `db`, ni ligne ni compte.
            pcr_ecrire(&st, &au, "DROP TRIGGER prrc_refus; CREATE TRIGGER prrc_refus BEFORE DELETE ON event BEGIN SELECT RAISE(ROLLBACK, 'prrc-moteur'); END;");
            let jeton = prrc_jeton(&st, &au).await;
            prrc_refuser_le_rollback(&st, &au);
            let (_, corps_annule) = pcr_apply(&st, &au, &jeton).await;
            prrc_fermer_a_la_main(&st, &au);
            // 4. De nouveau restée ouverte : le compte de processus MONTE (n° 2), les cas 2 et 3 n'y ont rien ajouté.
            pcr_ecrire(&st, &au, "DROP TRIGGER prrc_refus; CREATE TRIGGER prrc_refus BEFORE DELETE ON event BEGIN SELECT RAISE(ABORT, 'prrc-moteur'); END;");
            let jeton = prrc_jeton(&st, &au).await;
            prrc_refuser_le_rollback(&st, &au);
            let (_, corps2) = pcr_apply(&st, &au, &jeton).await;
            eprintln!("PRRC-FIN");
            prrc_fermer_a_la_main(&st, &au);
            println!("PRRC-ID:{}", corps["id"].as_str().unwrap_or_default());
            println!("PRRC-ID2:{}", corps2["id"].as_str().unwrap_or_default());
            println!("PRRC-REFUS-INTERMEDIAIRES:{},{}", corps_pris["refusal"], corps_annule["refusal"]);
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::purge_rollback_refuse_dit_et_compte::prrc_ligne_de_journal_entiere_sous_l_identifiant_servi",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let id = stdout.split_once("PRRC-ID:").map(|(_, r)| r.lines().next().unwrap_or("")).unwrap_or("").to_string();
        let id2 = stdout.split_once("PRRC-ID2:").map(|(_, r)| r.lines().next().unwrap_or("")).unwrap_or("").to_string();
        assert!(id.starts_with("plume-e") && id2.starts_with("plume-e") && id != id2, "contrôle : deux `id` servis : {stdout}");
        assert!(
            stdout.contains("PRRC-REFUS-INTERMEDIAIRES:\"db\",\"db\""),
            "contrôle : les deux refus intermédiaires (ROLLBACK pris, moteur qui annule) servent `db` : {stdout}"
        );
        let fenetre = stderr
            .split_once("PRRC-DEBUT")
            .and_then(|(_, r)| r.split_once("PRRC-FIN"))
            .map(|(c, _)| c)
            .unwrap_or_else(|| panic!("contrôle : fenêtre de journal : {stderr}"));
        // Les deux refus intermédiaires écrivent leur ligne `[purge] WARN` (refus `db` servi) : seules les lignes ERREUR comptent.
        let lignes: Vec<&str> = fenetre.lines().filter(|l| l.contains("[purge] ERREUR")).collect();
        let attendu = |id: &str, rang: u32| {
            format!(
                "[{id}] [purge] ERREUR purge confirmée : transaction toujours OUVERTE après « db » puis un ROLLBACK refusé \
                 (\"not authorized\") ; refus d'origine : \"REFUS — base : prrc-moteur (aucune ligne supprimée)\" — rien \
                 n'est validé, l'écrivain reste en transaction jusqu'à sa fermeture (BEGIN refusés, écritures sans BEGIN \
                 prises puis perdues ; ROLLBACK de purge refusé n° {rang} depuis le démarrage)"
            )
        };
        let (l1, l2) = (attendu(&id, 1), attendu(&id2, 2));
        // Le rang écrit est la valeur du compte de PRODUCTION `ROLLBACKS_DE_PURGE_REFUSES` (seule lecture qu'en fait le
        // démon) : il MONTE d'un refus resté ouvert au suivant (n° 1 puis n° 2), et les deux cas intermédiaires (ROLLBACK
        // pris, ROLLBACK refusé sur une connexion revenue en autocommit) n'y ajoutent rien.
        assert_eq!(lignes, vec![l1.as_str(), l2.as_str()], "deux lignes ERREUR, entières, rangs 1 puis 2 : {fenetre}");
    }
}
