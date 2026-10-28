// =====================================================================================
// `P10.7-r` (suite, vague AW) — LE MAILLON DU JOURNAL DE CONTRÔLE ET SON POINT DE CONTRÔLE SONT ÉCRITS ENSEMBLE OU PAS
// DU TOUT ; `verify-control` NE VÉRIFIE JAMAIS LA BASE À LA PLACE D'UNE COPIE DEMANDÉE ; L'OUVERTURE DU PLAN DE CONTRÔLE
// (`scim-token`) NE RÉSOUT PLUS LA CLÉ DU REGISTRE.
//
// L'ÉNONCÉ, RE-MESURÉ SUR LA BASE e66bb760 (lecture du code, puis témoins sous mutants qui rejouent la forme d'avant) :
//  - `control_ledger_append` écrivait le maillon en autocommit, puis son point dans un second énoncé : un arrêt entre
//    les deux, ou un point refusé, laissait un maillon sans point — la vérification restait en 2 pour toujours, et ce 2
//    permanent noyait celui qui signale une réécriture blanchie (mutant `jcma_release_apres_insert` : la forme d'avant) ;
//  - `commande_verify_control` lisait `--export` par `flag_val` : `--export` nu rendait « absent », `--export --prev h`
//    prenait `--prev` pour le fichier, un chemin nu était ignoré — la BASE était vérifiée et la sortie pouvait être 0 ;
//  - `init_control_plane` appelait `ledger::ledger_key`, que la sous-commande `scim-token` empruntait donc aussi.
//
// CE QUE CES TÉMOINS TIENNENT :
//  (1) un ARRÊT DU PROCESSUS entre le maillon et son point (un sous-processus qui sort du déclencheur du point) ne
//      laisse ni l'un ni l'autre, et la base rouverte se vérifie en 0 ;
//  (2) un point refusé ou ignoré par la base annule le maillon (cause nommée), et la chaîne reste ancrée ensuite ;
//      sans clé de signature, le maillon reste écrit sans point (décision inchangée) ;
//  (3) une transaction déjà ouverte sur la connexion : le point de reprise s'y imbrique, ne la valide pas, et une
//      annulation n'efface que le maillon refusé ;
//  (4) chaque issue (point refusé, point ignoré, validation refusée, ouverture refusée, annulation refusée, maillon
//      ignoré par la base : 0 ligne écrite) dit sa ligne ENTIÈRE sur le stderr d'un sous-processus, le chemin nominal
//      reste muet ;
//  (5) le geste servi par la route (`role_create`) porte `registre_sans_maillon`, corps à l'octet ;
//  (6) `verify-control` : chaque forme d'argument non comprise sort en 2 avec l'usage et sa raison, sans rien vérifier ;
//      les formes valides vérifient ce qu'elles nomment ;
//  (7) `init_control_plane` ne résout ni n'arme la clé du registre (stderr d'un sous-processus, aucun point posé) ; le
//      serveur l'arme après l'ouverture (texte du bras lu) ; `scim-token` n'arme donc pas : son bras ne fait que passer
//      par l'ouverture (lien lu sur le texte, déjà vrai avant le lot — c'est l'ouverture qui est témoignée).
//
// CE QU'ILS NE TIENNENT PAS : le binaire n'est pas lancé (les fonctions qu'il appelle le sont, ses bras sont lus sur le
// texte) ; l'emplacement historique de la clé (`/data/`, `/var/lib/plume/db/`) n'est pas écrit par un test — c'est la
// RÉSOLUTION de la clé par l'ouverture qui est témoignée absente, donc toute génération.
// =====================================================================================
mod journal_de_controle_maillon_et_point_atomiques {
    use super::*;
    use rusqlite::functions::FunctionFlags;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const JCMA_CLE: [u8; 32] = [37u8; 32];
    const JCMA_POINT: &str = "maillon_du_journal_de_controle";
    const JCMA_CAUSE_POINT: &str = "le point de contrôle signé du maillon n'a pas été posé : le maillon est annulé avec lui";
    const JCMA_TRACE_MANQUANTE: &str = "TRACE MANQUANTE : le geste d'administration a bien eu lieu, mais le journal du plan de contrôle n'a pas pris la ligne qui l'atteste — ce changement restera sans preuve d'audit, et la vérification de la chaîne ne signalera pas ce trou. Refaire le geste ne le comble pas : signalez-le.";
    const JCMA_CODE_D_ARRET: i32 = 86;
    const JCMA_USAGE: &str = "usage : plume-daemon verify-control [--export <fichier> [--prev <hash>]]";

    fn jcma_cle() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&JCMA_CLE)
    }

    fn jcma_epinglee() -> [u8; 32] {
        jcma_cle().verifying_key().to_bytes()
    }

    fn jcma_ok(n: usize) -> String {
        format!("control_ledger OK : {n} entrée(s) chaînées intègres, chaîne lue entièrement ; tête ancrée, {n} point(s) de contrôle signés par la clé épinglée")
    }

    /// Un plan de contrôle en mode 1 au journal VIERGE, sa clé de signature armée ou non.
    fn jcma_etat(signe: bool) -> (AppState, crate::tmp_possede::TmpDb) {
        let (cp, tmp) = mk_test_control();
        cp.conn.lock().execute_batch("DELETE FROM control_ledger; DELETE FROM control_checkpoint;").expect("fixture : journal vierge");
        crate::rbac::armer_la_signature_du_journal_de_controle(cp.db_path.as_str(), if signe { Some(jcma_cle()) } else { None });
        (tenant_test_state("jcma-adm", "jcma-edi", "jcma-sa", Some(cp)), tmp)
    }

    fn jcma_sql(st: &AppState, sql: &str) {
        st.tenants.control.as_ref().expect("mode 1").conn.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture `{sql}` : {e}"));
    }

    /// (maillons, points) du plan de contrôle.
    fn jcma_etat_du_journal(conn: &Connection) -> (i64, i64) {
        let maillons = conn.query_row("SELECT COUNT(*) FROM control_ledger", [], |r| r.get(0)).expect("compte des maillons");
        let points = conn.query_row("SELECT COUNT(*) FROM control_checkpoint", [], |r| r.get(0)).expect("compte des points");
        (maillons, points)
    }

    fn jcma_journal(st: &AppState) -> (i64, i64) {
        jcma_etat_du_journal(&st.tenants.control.as_ref().expect("mode 1").conn.lock())
    }

    fn jcma_verdict(st: &AppState) -> (i32, String) {
        crate::rbac::verdict_de_verify_control(&st.tenants.control.as_ref().expect("mode 1").conn.lock(), Some(&jcma_epinglee()))
    }

    /// `None` = inscrit ; sinon la cause.
    fn jcma_append(st: &AppState, kind: &str) -> Option<String> {
        control_ledger_append(st, kind, "sa-jcma-acteur", "tenant-jcma-cible", "raison-jcma-detail").cause_de_non_inscription().map(str::to_string)
    }

    // -------------------------------------------------------------------------------------
    // (1) UN ARRÊT DU PROCESSUS ENTRE LE MAILLON ET SON POINT
    // -------------------------------------------------------------------------------------

    /// Un sous-processus écrit un maillon nominal, puis un second dont le point de contrôle déclenche une fonction qui
    /// TERMINE le processus (`std::process::exit`) — après l'`INSERT` du maillon, pendant celui du point, sans rien
    /// fermer. La base rouverte par le parent ne porte que le premier maillon et son point, et se vérifie en 0. La forme
    /// d'avant (maillon validé seul, mutant `jcma_release_apres_insert`) y laissait deux maillons pour un point : 2.
    #[test]
    fn jcma_un_arret_entre_le_maillon_et_son_point_ne_laisse_ni_l_un_ni_l_autre() {
        let _env = VERROU_ENV_PROCESSUS.read();
        const ENFANT: &str = "JCMA_ENFANT_ARRET";
        if let Ok(chemin) = std::env::var(ENFANT) {
            let cp = mk_control_at(&chemin);
            cp.conn.lock().execute_batch("PRAGMA journal_mode=WAL;").expect("enfant : WAL, comme `init_control_plane`");
            crate::rbac::armer_la_signature_du_journal_de_controle(&chemin, Some(jcma_cle()));
            let st = tenant_test_state("jcma-adm", "jcma-edi", "jcma-sa", Some(cp));
            println!("JCMA-PREMIER:{}", jcma_append(&st, "jcma.avant").is_none());
            {
                let c = st.tenants.control.as_ref().expect("mode 1").conn.lock();
                c.create_scalar_function("jcma_arret", 0, FunctionFlags::SQLITE_UTF8, |_| -> rusqlite::Result<i64> {
                    println!("JCMA-ARRET-DANS-LE-POINT");
                    std::process::exit(JCMA_CODE_D_ARRET)
                })
                .expect("enfant : fonction d'arrêt");
                c.execute_batch("CREATE TRIGGER jcma_arret BEFORE INSERT ON control_checkpoint BEGIN SELECT jcma_arret(); END;").expect("enfant : déclencheur");
            }
            let issue = jcma_append(&st, "jcma.arret");
            println!("JCMA-APRES-L-ARRET:{issue:?}");
            return;
        }
        let dossier = crate::tmp_possede::TmpPossede::neuf("jcma-arret");
        let chemin = dossier.sous("plume-control.db").as_str().to_owned();
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::journal_de_controle_maillon_et_point_atomiques::jcma_un_arret_entre_le_maillon_et_son_point_ne_laisse_ni_l_un_ni_l_autre",
            ])
            .env(ENFANT, &chemin)
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        assert_eq!(sortie.status.code(), Some(JCMA_CODE_D_ARRET), "l'enfant s'arrête dans le déclencheur du point : {stdout}");
        let jetons: Vec<&str> = stdout.split(['\n', ' ']).collect();
        assert!(jetons.contains(&"JCMA-PREMIER:true"), "contrôle : le premier maillon est inscrit : {stdout}");
        assert!(jetons.contains(&"JCMA-ARRET-DANS-LE-POINT"), "instrument : l'arrêt a lieu PENDANT l'écriture du point : {stdout}");
        assert!(!stdout.contains("JCMA-APRES-L-ARRET"), "l'append interrompu ne rend jamais la main : {stdout}");
        let c = crate::db_open::open_db_keyed_without_schema_contract(&chemin, None).expect("la base rouverte");
        assert_eq!(jcma_etat_du_journal(&c), (1, 1), "ni le maillon interrompu ni son point : seul le premier, avec le sien");
        assert_eq!(crate::rbac::verdict_de_verify_control(&c, Some(&jcma_epinglee())), (0, jcma_ok(1)), "la base rouverte reste ancrée");
    }

    // -------------------------------------------------------------------------------------
    // (2) LE POINT REFUSÉ OU IGNORÉ ANNULE LE MAILLON ; SANS CLÉ, LE MAILLON RESTE SANS POINT
    // -------------------------------------------------------------------------------------

    #[test]
    fn jcma_un_point_refuse_ou_ignore_annule_son_maillon() {
        let (st, _t) = jcma_etat(true);
        assert_eq!(jcma_append(&st, "jcma.avant"), None, "contrôle : un maillon nominal");
        jcma_sql(&st, "CREATE TRIGGER jcma_refus BEFORE INSERT ON control_checkpoint BEGIN SELECT RAISE(ABORT, 'jcma refus du point'); END;");
        assert_eq!(jcma_append(&st, "jcma.refus").as_deref(), Some(JCMA_CAUSE_POINT), "point refusé : maillon annulé, cause nommée");
        assert_eq!(jcma_journal(&st), (1, 1), "le maillon refusé n'est pas resté");
        jcma_sql(&st, "DROP TRIGGER jcma_refus; CREATE TRIGGER jcma_ignore BEFORE INSERT ON control_checkpoint BEGIN SELECT RAISE(IGNORE); END;");
        assert_eq!(jcma_append(&st, "jcma.ignore").as_deref(), Some(JCMA_CAUSE_POINT), "point ignoré (aucune ligne) : même issue");
        assert_eq!(jcma_journal(&st), (1, 1));
        jcma_sql(&st, "DROP TRIGGER jcma_ignore;");
        assert_eq!(jcma_append(&st, "jcma.apres"), None, "contrôle positif : le refus n'est pas inconditionnel");
        assert_eq!(jcma_journal(&st), (2, 2));
        assert_eq!(jcma_verdict(&st), (0, jcma_ok(2)), "la chaîne reste ancrée : aucun maillon sans point ne la tient en 2");
    }

    /// Décision inchangée de `P10.7-r` : un plan de contrôle sans clé de signature garde son journal — le maillon est
    /// inscrit, sans point.
    #[test]
    fn jcma_sans_cle_le_maillon_reste_ecrit_sans_point() {
        let (st, _t) = jcma_etat(false);
        assert_eq!(jcma_append(&st, "jcma.sans_cle"), None);
        assert_eq!(jcma_journal(&st), (1, 0));
    }

    // -------------------------------------------------------------------------------------
    // (3) UNE TRANSACTION DÉJÀ OUVERTE SUR LA CONNEXION
    // -------------------------------------------------------------------------------------

    #[test]
    fn jcma_le_point_de_reprise_s_imbrique_dans_une_transaction_ouverte() {
        let (st, _t) = jcma_etat(true);
        jcma_sql(&st, "BEGIN IMMEDIATE");
        assert_eq!(jcma_append(&st, "jcma.dans"), None, "le maillon s'écrit dans la transaction englobante");
        assert!(!st.tenants.control.as_ref().expect("mode 1").conn.lock().is_autocommit(), "le point de reprise ne valide pas la transaction englobante");
        jcma_sql(&st, "ROLLBACK");
        assert_eq!(jcma_journal(&st), (0, 0), "la transaction englobante décide : annulée, ni maillon ni point");

        jcma_sql(&st, "BEGIN IMMEDIATE");
        assert_eq!(jcma_append(&st, "jcma.garde"), None);
        jcma_sql(&st, "CREATE TRIGGER jcma_refus BEFORE INSERT ON control_checkpoint BEGIN SELECT RAISE(ABORT, 'jcma refus du point'); END;");
        assert_eq!(jcma_append(&st, "jcma.refus").as_deref(), Some(JCMA_CAUSE_POINT));
        jcma_sql(&st, "DROP TRIGGER jcma_refus; COMMIT");
        assert_eq!(jcma_journal(&st), (1, 1), "l'annulation n'a effacé que le maillon refusé, pas la transaction englobante");
        assert_eq!(jcma_verdict(&st), (0, jcma_ok(1)));
    }

    // -------------------------------------------------------------------------------------
    // (4) CHAQUE ISSUE DIT SA LIGNE, LUE ENTIÈRE SUR LE STDERR D'UN SOUS-PROCESSUS
    // -------------------------------------------------------------------------------------

    #[test]
    fn jcma_chaque_issue_dit_sa_ligne() {
        let _env = VERROU_ENV_PROCESSUS.read();
        const ENFANT: &str = "JCMA_ENFANT_LIGNES";
        if std::env::var(ENFANT).is_ok() {
            let (st, _t) = jcma_etat(true);
            let conn = || st.tenants.control.as_ref().expect("mode 1").conn.lock();
            let issue = |kind: &str| {
                let i = jcma_append(&st, kind);
                println!("JCMA-ISSUE-{kind}:{}", i.as_deref().unwrap_or("INSCRIT").replace(' ', "_"));
            };
            let etat = |kind: &str| {
                let (m, p) = jcma_journal(&st);
                println!("JCMA-ETAT-{kind}:{m}/{p}");
            };
            jcma_sql(&st, "CREATE TRIGGER jcma_refus BEFORE INSERT ON control_checkpoint BEGIN SELECT RAISE(ABORT, 'jcma refus du point'); END;");
            issue("jcma.refus");
            etat("jcma.refus");
            jcma_sql(&st, "DROP TRIGGER jcma_refus; CREATE TRIGGER jcma_ignore BEFORE INSERT ON control_checkpoint BEGIN SELECT RAISE(IGNORE); END;");
            issue("jcma.ignore");
            etat("jcma.ignore");
            jcma_sql(&st, "DROP TRIGGER jcma_ignore;");
            // La VALIDATION refusée une fois : l'annulation (`ROLLBACK TO` puis le second `RELEASE`) passe.
            let refus_joue = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let marque = refus_joue.clone();
            conn().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Savepoint { operation: TransactionOperation::Release, savepoint_name }
                    if savepoint_name == JCMA_POINT && !marque.swap(true, std::sync::atomic::Ordering::SeqCst) =>
                {
                    Authorization::Deny
                }
                _ => Authorization::Allow,
            }));
            issue("jcma.validation");
            println!("JCMA-REFUS-DE-VALIDATION-JOUE:{}", refus_joue.load(std::sync::atomic::Ordering::SeqCst));
            println!("JCMA-FERME-jcma.validation:{}", conn().is_autocommit());
            etat("jcma.validation");
            // L'OUVERTURE refusée.
            conn().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Savepoint { operation: TransactionOperation::Begin, savepoint_name } if savepoint_name == JCMA_POINT => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            issue("jcma.ouverture");
            etat("jcma.ouverture");
            // L'ANNULATION refusée (point refusé, puis `ROLLBACK TO` refusé) : le point de reprise reste ouvert, l'enfant
            // le ferme.
            jcma_sql(&st, "CREATE TRIGGER jcma_refus BEFORE INSERT ON control_checkpoint BEGIN SELECT RAISE(ABORT, 'jcma refus du point'); END;");
            conn().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Savepoint { operation: TransactionOperation::Rollback, savepoint_name } if savepoint_name == JCMA_POINT => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            issue("jcma.annulation");
            conn().authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
            println!("JCMA-FERME-jcma.annulation:{}", conn().is_autocommit());
            jcma_sql(&st, &format!("ROLLBACK TO {JCMA_POINT}; RELEASE {JCMA_POINT}; DROP TRIGGER jcma_refus;"));
            etat("jcma.annulation");
            issue("jcma.nominal");
            etat("jcma.nominal");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::journal_de_controle_maillon_et_point_atomiques::jcma_chaque_issue_dit_sa_ligne"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let jetons: Vec<&str> = stdout.split(['\n', ' ']).collect();
        let point = JCMA_CAUSE_POINT.replace(' ', "_");
        let non_ecrit = "l'écriture_du_maillon_n'a_pas_eu_lieu";
        let attendus = [
            format!("JCMA-ISSUE-jcma.refus:{point}"),
            "JCMA-ETAT-jcma.refus:0/0".to_string(),
            format!("JCMA-ISSUE-jcma.ignore:{point}"),
            "JCMA-ETAT-jcma.ignore:0/0".to_string(),
            format!("JCMA-ISSUE-jcma.validation:{non_ecrit}"),
            "JCMA-REFUS-DE-VALIDATION-JOUE:true".to_string(),
            "JCMA-FERME-jcma.validation:true".to_string(),
            "JCMA-ETAT-jcma.validation:0/0".to_string(),
            format!("JCMA-ISSUE-jcma.ouverture:{non_ecrit}"),
            "JCMA-ETAT-jcma.ouverture:0/0".to_string(),
            format!("JCMA-ISSUE-jcma.annulation:{point}"),
            "JCMA-FERME-jcma.annulation:false".to_string(),
            "JCMA-ETAT-jcma.annulation:0/0".to_string(),
            "JCMA-ISSUE-jcma.nominal:INSCRIT".to_string(),
            "JCMA-ETAT-jcma.nominal:1/1".to_string(),
        ];
        for attendu in &attendus {
            assert!(jetons.contains(&attendu.as_str()), "{attendu} : {stdout}");
        }
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[control_ledger] WARN")).collect();
        assert_eq!(
            lignes,
            vec![
                "[control_ledger] WARN maillon 'jcma.refus' NON inscrit : son point de contrôle n'a pas été posé (l'écriture n'a pas eu lieu (jcma refus du point)) — le maillon est annulé avec lui",
                "[control_ledger] WARN maillon 'jcma.ignore' NON inscrit : son point de contrôle n'a pas été posé (0 ligne(s) écrite(s) au lieu d'une) — le maillon est annulé avec lui",
                "[control_ledger] WARN maillon 'jcma.validation' NON inscrit : la transaction qui porte le maillon et son point de contrôle n'a pas été validée (not authorized) — ni l'un ni l'autre n'est écrit",
                "[control_ledger] WARN maillon 'jcma.ouverture' NON inscrit : la transaction qui doit porter le maillon et son point de contrôle ne s'ouvre pas (not authorized)",
                "[control_ledger] WARN maillon 'jcma.annulation' NON inscrit : son point de contrôle n'a pas été posé (l'écriture n'a pas eu lieu (jcma refus du point)) — le maillon est annulé avec lui — ANNULATION REFUSÉE (not authorized) : le point de reprise maillon_du_journal_de_controle reste ouvert",
            ],
            "cinq lignes entières, aucune pour le chemin nominal, ni acteur, ni cible, ni détail : {stderr}"
        );
    }

    /// L'`INSERT` DU MAILLON QUI N'ÉCRIT AUCUNE LIGNE (déclencheur `RAISE(IGNORE)` sur `control_ledger`) : le bras du
    /// compte inattendu, désormais sous le point de reprise. La cause est le compte, le journal reste vierge, le point
    /// de reprise est refermé (la connexion revient en autocommit), la ligne de stderr est celle d'avant le lot, à
    /// l'octet ; une fois le déclencheur retiré, un maillon nominal s'inscrit avec son point et la chaîne se vérifie
    /// en 0. Mutant `jcma_compte_permissif` (le compte inattendu validé comme une inscription) : rouge.
    #[test]
    fn jcma_un_maillon_que_la_base_ignore_dit_son_compte() {
        let _env = VERROU_ENV_PROCESSUS.read();
        const ENFANT: &str = "JCMA_ENFANT_COMPTE";
        if std::env::var(ENFANT).is_ok() {
            let (st, _t) = jcma_etat(true);
            let rendre = |kind: &str| {
                let issue = jcma_append(&st, kind);
                println!("JCMA-ISSUE-{kind}:{}", issue.as_deref().unwrap_or("INSCRIT").replace(' ', "_"));
                let (m, p) = jcma_journal(&st);
                println!("JCMA-ETAT-{kind}:{m}/{p}");
                println!("JCMA-FERME-{kind}:{}", st.tenants.control.as_ref().expect("mode 1").conn.lock().is_autocommit());
            };
            jcma_sql(&st, "CREATE TRIGGER jcma_ignore_maillon BEFORE INSERT ON control_ledger BEGIN SELECT RAISE(IGNORE); END;");
            rendre("jcma.compte");
            jcma_sql(&st, "DROP TRIGGER jcma_ignore_maillon;");
            rendre("jcma.nominal");
            println!("JCMA-VERDICT:{}", jcma_verdict(&st).0);
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::journal_de_controle_maillon_et_point_atomiques::jcma_un_maillon_que_la_base_ignore_dit_son_compte"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let jetons: Vec<&str> = stdout.split(['\n', ' ']).collect();
        for attendu in [
            "JCMA-ISSUE-jcma.compte:0_ligne(s)_écrite(s)_au_lieu_d'une",
            "JCMA-ETAT-jcma.compte:0/0",
            "JCMA-FERME-jcma.compte:true",
            "JCMA-ISSUE-jcma.nominal:INSCRIT",
            "JCMA-ETAT-jcma.nominal:1/1",
            "JCMA-FERME-jcma.nominal:true",
            "JCMA-VERDICT:0",
        ] {
            assert!(jetons.contains(&attendu), "{attendu} : {stdout}");
        }
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[control_ledger] WARN")).collect();
        assert_eq!(
            lignes,
            vec!["[control_ledger] WARN maillon 'jcma.compte' NON inscrit : 0 ligne(s) écrite(s) au lieu d'une"],
            "une ligne entière pour le compte, aucune pour le maillon nominal : {stderr}"
        );
    }

    // -------------------------------------------------------------------------------------
    // (5) PAR LA ROUTE : LE GESTE SERVI PORTE `registre_sans_maillon`
    // -------------------------------------------------------------------------------------

    #[tokio::test]
    async fn jcma_le_geste_dont_le_point_est_refuse_porte_son_aveu() {
        let _roles = CUSTOM_ROLES_TEST_LOCK.lock();
        let (st, _dir) = mk_mode1_state();
        let cp = st.tenants.control.as_ref().expect("mode 1").clone();
        crate::rbac::armer_la_signature_du_journal_de_controle(cp.db_path.as_str(), Some(jcma_cle()));
        let sa = AuthUser { name: "op-jcma".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: true, method: "basic".into(), csrf: String::new(), env: None };
        let avant = jcma_etat_du_journal(&cp.conn.lock());
        jcma_sql(&st, "CREATE TRIGGER jcma_refus BEFORE INSERT ON control_checkpoint BEGIN SELECT RAISE(ABORT, 'jcma refus du point'); END;");
        let (statut, v) = pb_json(role_create(State(st.clone()), Extension(sa.clone()), Json(json!({ "name": "jcma-role", "base_role": "viewer" }))).await).await;
        assert_eq!(statut, 200, "le rôle EST créé : {v}");
        assert_eq!(
            v,
            json!({ "ok": true, "name": "jcma-role", "base_role": "viewer", "deny_perms": [], "registre_sans_maillon": format!("{JCMA_TRACE_MANQUANTE} ({JCMA_CAUSE_POINT})") }),
            "corps entier : le succès et l'aveu du maillon annulé"
        );
        assert_eq!(jcma_etat_du_journal(&cp.conn.lock()), avant, "ni maillon ni point");
        jcma_sql(&st, "DROP TRIGGER jcma_refus;");
        let (statut, v) = pb_json(role_create(State(st.clone()), Extension(sa), Json(json!({ "name": "jcma-role-2", "base_role": "viewer" }))).await).await;
        assert_eq!((statut, v), (200, json!({ "ok": true, "name": "jcma-role-2", "base_role": "viewer", "deny_perms": [] })), "contrôle positif : aucun aveu");
        assert_eq!(jcma_etat_du_journal(&cp.conn.lock()), (avant.0 + 1, avant.1 + 1), "le maillon et son point");
    }

    // -------------------------------------------------------------------------------------
    // (6) `verify-control` : LES ARGUMENTS NON COMPRIS SORTENT EN 2 AVEC L'USAGE
    // -------------------------------------------------------------------------------------

    fn jcma_args(reste: &[&str]) -> Vec<String> {
        ["plume-daemon", "verify-control"].iter().chain(reste.iter()).map(|s| s.to_string()).collect()
    }

    fn jcma_refus(raison: &str) -> (i32, String) {
        (2, format!("{JCMA_USAGE} — {raison} : aucun verdict"))
    }

    /// La base et la copie se vérifient toutes deux en 0 : une forme non comprise qui retomberait sur l'une ou l'autre
    /// sortirait en 0 au lieu de 2.
    #[test]
    fn jcma_verify_control_refuse_les_arguments_non_compris() {
        let (st, base) = jcma_etat(true);
        assert_eq!(jcma_append(&st, "jcma.copie1"), None, "fixture");
        assert_eq!(jcma_append(&st, "jcma.copie2"), None, "fixture");
        let dossier = crate::tmp_possede::TmpPossede::neuf("jcma-args");
        let copie = dossier.sous("copie.jsonl").as_str().to_owned();
        let autre = dossier.sous("autre.jsonl").as_str().to_owned();
        let (lignes, _, _) = crate::governance::control_ledger_export_lines_ancree(&st.tenants.control.as_ref().expect("mode 1").conn.lock(), 0, 0).expect("fixture : export");
        std::fs::write(&copie, lignes.join("\n")).expect("fixture : copie");
        let pin = jcma_epinglee();
        let jouer = |reste: &[&str]| crate::rbac::commande_verify_control(&jcma_args(reste), base.as_str(), None, Some(&pin));
        let copie_ok = "export OK : 2 entrée(s) chaînées intègres, chaîne lue entièrement ; tête ancrée, 2 point(s) de contrôle signés par la clé épinglée".to_string();

        // Contrôles positifs : la base, la copie, `--prev` (vide = origine) avant ou après `--export`.
        assert_eq!(jouer(&[]), (0, jcma_ok(2)), "la base");
        assert_eq!(jouer(&["--export", copie.as_str()]), (0, copie_ok.clone()), "la copie");
        assert_eq!(jouer(&["--prev", "", "--export", copie.as_str()]), (0, copie_ok.clone()), "l'ordre des drapeaux est libre");
        assert_eq!(
            crate::rbac::lire_la_cible_de_verify_control(&jcma_args(&["--prev", "H", "--export", "F"])),
            Ok(crate::rbac::CibleDeVerifyControl::Copie { fichier: "F".to_string(), prev: "H".to_string() })
        );
        assert_eq!(crate::rbac::lire_la_cible_de_verify_control(&jcma_args(&[])), Ok(crate::rbac::CibleDeVerifyControl::Base));

        // Les quatre formes de l'énoncé.
        assert_eq!(jouer(&["--export"]), jcma_refus("« --export » attend un fichier"), "`--export` nu");
        assert_eq!(jouer(&["--export", "--prev", "abc"]), jcma_refus("« --export » attend un fichier"), "`--export` suivi d'un drapeau");
        assert_eq!(jouer(&[copie.as_str()]), jcma_refus(&format!("argument non compris « {copie} »")), "un chemin nu sans `--export`");
        assert_eq!(jouer(&["--export", copie.as_str(), "--prev"]), jcma_refus("« --prev » attend un hachage"), "`--prev` sans valeur");
        // Et leurs voisines.
        assert_eq!(jouer(&["--prev"]), jcma_refus("« --prev » attend un hachage"), "`--prev` nu, seul");
        assert_eq!(jouer(&["--export", copie.as_str(), "--prev", "--export"]), jcma_refus("« --prev » attend un hachage"), "`--prev` suivi d'un drapeau");
        assert_eq!(jouer(&["--prev", "abc"]), jcma_refus("« --prev » ne s'emploie qu'avec « --export »"), "`--prev` sans `--export`");
        assert_eq!(jouer(&["--export", copie.as_str(), "--export", autre.as_str()]), jcma_refus("« --export » donné deux fois"), "drapeau répété");
        assert_eq!(jouer(&["--verbose"]), jcma_refus("argument non compris « --verbose »"), "drapeau inconnu");
    }

    // -------------------------------------------------------------------------------------
    // (7) L'OUVERTURE NE RÉSOUT PAS LA CLÉ ; LE SERVEUR L'ARME APRÈS ELLE ; `scim-token` NE L'ARME PAS
    // -------------------------------------------------------------------------------------

    /// La clé du registre est posée à un chemin que `PLUME_LEDGER_KEY_PATH` désigne : `init_control_plane` seul n'arme
    /// rien (aucun point posé), `armer_la_signature_du_plan_de_controle` arme la clé lue à ce chemin.
    #[test]
    fn jcma_l_ouverture_n_arme_pas_la_signature_le_serveur_si() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let dossier = crate::tmp_possede::TmpPossede::neuf("jcma-init");
        let fichier_de_cle = dossier.sous("signature.key").as_str().to_owned();
        std::fs::write(&fichier_de_cle, hex_encode(&JCMA_CLE)).expect("fixture : clé du registre");
        let base = dossier.sous("plume.db").as_str().to_owned();
        let conf: HashMap<String, String> = [("PLUME_LEDGER_KEY_PATH".to_string(), fichier_de_cle)].into_iter().collect();
        let cp = init_control_plane(&conf, &base).expect("plan de contrôle");
        let st = tenant_test_state("jcma-adm", "jcma-edi", "jcma-sa", Some(cp.clone()));
        assert_eq!(jcma_append(&st, "jcma.ouvert"), None);
        assert_eq!(jcma_journal(&st), (1, 0), "l'ouverture seule n'arme aucune clé : maillon sans point");
        crate::state::armer_la_signature_du_plan_de_controle(&conf, &cp);
        assert_eq!(jcma_append(&st, "jcma.arme"), None);
        let pubkey: String = cp.conn.lock().query_row("SELECT pubkey FROM control_checkpoint", [], |r| r.get(0)).expect("un point signé");
        assert_eq!(pubkey, hex_encode(&jcma_epinglee()), "armé par le serveur : signé par la clé lue au chemin du registre");
    }

    /// L'OUVERTURE NE RÉSOUT PAS LA CLÉ — donc ne peut pas l'engendrer. Un chemin de clé ABSENT (non historique) fait
    /// dire à `ledger::ledger_key` « clé ABSENTE » sur stderr : un sous-processus qui n'ouvre que le plan de contrôle
    /// (ce que fait `scim-token`) n'imprime aucune ligne `[ledger]` ; celui qui arme ensuite la signature l'imprime,
    /// entière (contrôle positif de l'instrument).
    #[test]
    fn jcma_l_ouverture_ne_resout_pas_la_cle_du_registre() {
        let _env = VERROU_ENV_PROCESSUS.read();
        const ENFANT: &str = "JCMA_ENFANT_OUVERTURE";
        if let Ok(geste) = std::env::var(ENFANT) {
            let dossier = crate::tmp_possede::TmpPossede::neuf("jcma-ouverture");
            let absente = dossier.sous("absente.key").as_str().to_owned();
            println!("JCMA-CHEMIN:{absente}");
            let conf: HashMap<String, String> = [("PLUME_LEDGER_KEY_PATH".to_string(), absente)].into_iter().collect();
            let cp = init_control_plane(&conf, dossier.sous("plume.db").as_str()).expect("enfant : plan de contrôle");
            if geste == "armer" {
                crate::state::armer_la_signature_du_plan_de_controle(&conf, &cp);
            }
            return;
        }
        let jouer = |geste: &str| {
            let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
                .args(["--exact", "--nocapture", "--test-threads=1", "tests::journal_de_controle_maillon_et_point_atomiques::jcma_l_ouverture_ne_resout_pas_la_cle_du_registre"])
                .env(ENFANT, geste)
                .output()
                .expect("ré-exécution du binaire de test");
            let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
            assert_eq!(sortie.status.code(), Some(0), "{geste} : {stdout}\n{stderr}");
            let chemin = stdout.split(['\n', ' ']).find_map(|t| t.strip_prefix("JCMA-CHEMIN:")).expect("le chemin de l'enfant").to_string();
            let lignes: Vec<String> = stderr.lines().filter(|l| l.starts_with("[ledger]")).map(str::to_string).collect();
            (chemin, lignes)
        };
        let (_, lignes) = jouer("ouvrir");
        assert_eq!(lignes, Vec::<String>::new(), "l'ouverture seule ne résout pas la clé du registre");
        let (chemin, lignes) = jouer("armer");
        assert_eq!(
            lignes,
            vec![format!("[ledger] clé ABSENTE à '{chemin}' — chemin NON-legacy (Secret escrow attendu) : REFUS de générer une nouvelle clé (fail-closed). Checkpoints NON signés jusqu'à provisionnement. NE PAS régénérer : une clé divergente romprait EN SILENCE la continuité de vérification.")],
            "contrôle positif : l'armement par le serveur résout la clé, et l'instrument le voit"
        );
    }

    /// Le bras du serveur, lu sur le texte : la signature est armée dans le bras `Ok(cp)` de `init_control_plane`, une
    /// seule fois dans le serveur. Témoin de TEXTE : il ne lance pas le serveur.
    ///
    /// `scim-token` : ce test ne tient que le LIEN — son bras ouvre le plan de contrôle par `init_control_plane` et
    /// n'appelle pas l'armement lui-même. Ce lien était déjà vrai avant `P10.7-r` (l'armement passait alors PAR
    /// l'ouverture) : il ne témoigne pas du changement. Que l'ouverture n'arme plus rien est tenu par
    /// `jcma_l_ouverture_ne_resout_pas_la_cle_du_registre` et `jcma_l_ouverture_n_arme_pas_la_signature_le_serveur_si`,
    /// qui rougissent sous le mutant `jcma_init_arme` (l'ouverture réarme).
    #[test]
    fn jcma_le_serveur_arme_la_signature_scim_token_non() {
        let appel = "                crate::state::armer_la_signature_du_plan_de_controle(&conf, &cp);\n";
        let serveur = include_str!("../server/mod.rs");
        let debut = "        match init_control_plane(&conf, &db_path) {\n            Ok(cp) => {\n";
        assert_eq!(serveur.matches(debut).count(), 1, "un seul bras d'ouverture du plan de contrôle dans le serveur");
        let bras = &serveur[serveur.find(debut).expect("bras") + debut.len()..];
        assert!(
            bras.starts_with(&format!(
                "                // `P10.7-r` — la signature des points de contrôle est armée ICI, par le serveur qui écrit au journal de\n\
                 \x20               // contrôle, et non par l'ouverture (que la sous-commande `scim-token` emprunte aussi).\n{appel}"
            )),
            "l'armement est le premier geste du bras Ok(cp) : {}",
            &bras[..bras.len().min(400)]
        );
        assert_eq!(serveur.matches("armer_la_signature_du_plan_de_controle(").count(), 1, "une seule fois dans le serveur");
        let main = include_str!("../main.rs");
        let debut_scim = "    if args.get(1).map(String::as_str) == Some(\"scim-token\") {\n";
        let scim = &main[main.find(debut_scim).expect("bras scim-token")..];
        let scim = &scim[..scim.find("\n    }\n").expect("fin du bras scim-token")];
        assert!(
            scim.contains("init_control_plane(&conf, &db_path)") && !scim.contains("armer_la_signature"),
            "lien : scim-token passe par l'ouverture et n'appelle pas l'armement lui-même : {scim}"
        );
    }
}
