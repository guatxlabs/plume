// =====================================================================================
// `P10.29-l` — `purge_cli` EXÉCUTÉE PAR `main` EN SOUS-PROCESSUS : LES DEUX SORTIES À LEUR PLACE, LE CODE DE SORTIE EXACT,
// ET LA DÉCISION SUIVIE D'UN ROLLBACK REFUSÉ, REJOUÉE DANS L'ENFANT.
//
// LE DÉFAUT, RELEVÉ PAR LE VÉRIFICATEUR SUR f4f8e0a5 : la fin de `purge_cli` (écrire `stdout` puis `stderr` de
// `purge_cli_sur`, puis `exit(code)`) n'était exécutée par aucun témoin. Deux mutants restaient verts : refus rendu en
// sortie 0 (pas d'`exit`) et sorties standard et d'erreur inversées. L'en-tête de
// purge_classement_de_l_annulation_et_site_de_la_cli.rs disait ce chemin intestable (« libtest refuse ses
// arguments ») : faux, sous_commandes_executees_sur_base_absente.rs lance déjà `main` -> `purge_cli` en
// sous-processus, arguments placés après `--`.
// REPRISE (vérificateur sur d79d340a) : `current_exe()` et `.env(` vivaient dans une aide ; la garde
// check_a_test_that_declines_to_conclude_says_so.py ne reconnaît le protocole de ré-exécution que dans le CORPS du
// test, et lisait donc le `return` du bras enfant comme une sortie muette. Chaque test construit maintenant SA
// commande (`Command::new(std::env::current_exe()…)` puis `.env(…)`) ; l'aide reçoit la commande déjà construite.
//
// CE QUE CES TÉMOINS JUGENT, sur une base NÉE PAR LA PORTE avec sa clé (`PLUME_DB_KEY` passée à l'enfant) :
//  - refus ordinaire en `--json` (jeton faux -> `stale_token`) : sortie 3 ; le corps JSON (`ok:false`,
//    `refusal:"stale_token"`, le jeton fourni cité) est sur la sortie STANDARD et sur aucune ligne de la sortie d'erreur ;
//  - le même refus en texte : sortie 3 ; la phrase « CONFIRMATION CADUQUE » sur la sortie d'ERREUR, pas sur la standard ;
//  - simulation en `--json` (contrôle du chemin heureux) : sortie 0, le plan JSON sur la sortie standard ;
//  - DÉCISION (`count_mismatch`, déclencheur `RAISE(IGNORE)` sur la première ligne du périmètre) PUIS ROLLBACK REFUSÉ,
//    dans l'enfant, en `--json` : sortie 3, corps ENTIER sur la sortie standard (`refusal:"count_mismatch"`, le
//    `Display` de `TransactionLeftOpen`, `id` de la forme `plume-e<pid de l'enfant>-<n>`, `annulation_refusee:true`),
//    UNE ligne `[<id>] [purge] ERREUR` sur la sortie d'erreur sous le même identifiant, et les events intacts une fois
//    l'enfant sorti. Le ROLLBACK est refusé par un autorisateur que l'ENFANT pose sur chaque connexion qu'il ouvre
//    (`sqlite3_auto_extension`, appelé dans le bras enfant avant `crate::main()`) : aucun crochet de production.
// MUTANTS JOUÉS (`VERIF_MUT` sous `cfg!(test)` dans `purge_cli`, retirés avant le commit), chacun vu ROUGE :
// `BB1C_EXIT0` (refus rendu en sortie 0, sans `exit`), `BB1C_INVERSE` (sortie standard et sortie d'erreur inversées) ;
// et dans `annuler_la_purge`, `BC1_SANS_DECISION` (pose `decision: false`) : dans ce fichier, seul le quatrième témoin
// rougit (avec, ailleurs, `bb1_cli_decision_puis_annulation_refusee_json`, au site `purge_cli_sur`).
// =====================================================================================
mod purge_cli_executee_en_sous_processus {
    use super::*;
    use std::os::raw::{c_char, c_int, c_void};

    const BB1C_ENFANT: &str = "P1029L_BB1C_ENFANT_MAIN";
    const BB1C_MARQUE_ENFANT: &str = "P1029L-BB1C-ENFANT-APPELLE-MAIN";
    const BB1C_CLE: &str = "cle-de-temoin-bb1c-purge";
    const BB1C_JETON_FAUX: &str = "jeton-bb1c-faux";
    const BB1C_SOURCE: &str = "flux-bb1c";
    /// Phrase du `Display` de `StaleToken`, écrite ICI.
    const BB1C_CADUQUE: &str = "REFUS — CONFIRMATION CADUQUE";
    /// `Display` de `TransactionLeftOpen` (ce que la CLI rend), écrit ICI ; `<ETAPE>` et `<ID>` sont remplacés.
    const BB1C_DISPLAY_RESTEE_OUVERTE: &str = "REFUS — PURGE NON VALIDÉE, TRANSACTION RESTÉE OUVERTE : <ETAPE>, puis la \
         base a refusé le ROLLBACK qui devait l'annuler. Rien n'est validé, mais la connexion reste en transaction jusqu'à \
         sa fermeture ou à la fin du processus (fin de la CLI, redémarrage du démon) : un geste qui ouvre sa propre \
         transaction est refusé, une écriture faite sans transaction propre y est prise puis perdue à la fermeture. Les \
         causes sont écrites au journal sous l'identifiant <ID>.";
    /// Déclencheur : la PREMIÈRE ligne du périmètre n'est pas supprimée -> `count_mismatch` (décision) dans la transaction.
    const BB1C_IGNORE_UNE: &str = "CREATE TRIGGER bb1c_ignore BEFORE DELETE ON event \
         WHEN OLD.id = (SELECT MIN(id) FROM event WHERE source='flux-bb1c') BEGIN SELECT RAISE(IGNORE); END;";

    /// Une base NÉE PAR LA PORTE avec sa clé, dans un répertoire possédé ; rend le répertoire et le chemin de la base.
    fn bb1c_base() -> (crate::tmp_possede::TmpPossede, String) {
        let tmp = crate::tmp_possede::TmpPossede::neuf("p1029l-bb1c-purge");
        let base = tmp.racine().chemin().join("nee.db").to_string_lossy().into_owned();
        drop(crate::db_open::PreparedDb::open_keyed(&base, Some(BB1C_CLE)).expect("naissance par la porte avec la clé"));
        (tmp, base)
    }

    fn bb1c_ouvrir(base: &str) -> Connection {
        crate::db_open::PreparedDb::open_keyed(base, Some(BB1C_CLE)).expect("réouverture par la porte").into_connection()
    }

    fn bb1c_perimetre() -> PurgeScope {
        let v = vec![("source".to_string(), BB1C_SOURCE.to_string())];
        purge_scope_from_args(&v, "0", "2000", now()).expect("périmètre valide")
    }

    fn bb1c_events(base: &str) -> i64 {
        bb1c_ouvrir(base)
            .query_row("SELECT COUNT(*) FROM event WHERE source=?1", params![BB1C_SOURCE], |r| r.get(0))
            .expect("compte des events du périmètre")
    }

    /// Lance l'enfant (commande DÉJÀ construite par le test, binaire et marqueur d'enfant posés) : `purge` puis le
    /// périmètre et `extra` après `--`. Rend (pid de l'enfant, code de sortie, sortie standard, sortie d'erreur).
    fn bb1c_executer(
        mut enfant: std::process::Command,
        nom_du_test: &str,
        tmp: &crate::tmp_possede::TmpPossede,
        base: &str,
        extra: &[&str],
    ) -> (u32, i32, String, String) {
        let chemin = format!("tests::purge_cli_executee_en_sous_processus::{nom_du_test}");
        let mut args: Vec<&str> =
            vec!["purge", "--exact", "--nocapture", "--test-threads=1", chemin.as_str(), "--", "--source", BB1C_SOURCE];
        args.extend_from_slice(&["--since", "0", "--until", "2000"]);
        args.extend_from_slice(extra);
        let lance = enfant
            .args(&args)
            .env("PLUME_DB", base)
            .env("PLUME_CONFIG", tmp.racine().chemin().join("aucune.conf"))
            .env("PLUME_DB_KEY", BB1C_CLE)
            .env_remove("PLUME_DB_KEY_FILE")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("ré-exécution du binaire de test");
        let pid = lance.id();
        let sortie = lance.wait_with_output().expect("sorties de l'enfant");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stderr.contains(BB1C_MARQUE_ENFANT), "contrôle : l'enfant a atteint `main` : {stdout}\n{stderr}");
        (pid, sortie.status.code().unwrap_or(-1), stdout, stderr)
    }

    /// Le corps JSON de refus : la fin d'une ligne (libtest écrit « test … » devant, sur la même ligne) qui se lit
    /// comme un objet à `ok:false`.
    fn bb1c_refus_json(flux: &str) -> Option<serde_json::Value> {
        flux.lines()
            .filter_map(|l| l.find('{').map(|i| &l[i..]))
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok())
            .find(|v| v.get("ok") == Some(&serde_json::json!(false)))
    }

    /// Autorisateur C posé par l'ENFANT : refuse tout `ROLLBACK`, laisse passer le reste.
    unsafe extern "C" fn bb1c_refuser_le_rollback(
        _: *mut c_void,
        action: c_int,
        operation: *const c_char,
        _: *const c_char,
        _: *const c_char,
        _: *const c_char,
    ) -> c_int {
        if action == rusqlite::ffi::SQLITE_TRANSACTION
            && !operation.is_null()
            && std::ffi::CStr::from_ptr(operation).to_bytes() == b"ROLLBACK"
        {
            return rusqlite::ffi::SQLITE_DENY;
        }
        rusqlite::ffi::SQLITE_OK
    }

    /// Point d'entrée d'extension automatique : pose l'autorisateur sur chaque connexion que l'enfant ouvre.
    unsafe extern "C" fn bb1c_poser_l_autorisateur(
        db: *mut rusqlite::ffi::sqlite3,
        _: *mut *const c_char,
        _: *const rusqlite::ffi::sqlite3_api_routines,
    ) -> c_int {
        rusqlite::ffi::sqlite3_set_authorizer(db, Some(bb1c_refuser_le_rollback), std::ptr::null_mut())
    }

    #[test]
    fn p10_29l_purge_cli_refus_json_sort_3_corps_sur_la_sortie_standard() {
        if std::env::var_os(BB1C_ENFANT).is_some() {
            eprintln!("{BB1C_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _env = VERROU_ENV_PROCESSUS.read();
        let (tmp, base) = bb1c_base();
        let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        enfant.env(BB1C_ENFANT, "1");
        let (_, code, stdout, stderr) = bb1c_executer(
            enfant,
            "p10_29l_purge_cli_refus_json_sort_3_corps_sur_la_sortie_standard",
            &tmp,
            &base,
            &["--json", "--confirm", BB1C_JETON_FAUX, "--reason", "temoin bb1c"],
        );
        assert_eq!(code, 3, "refus en --json : sortie 3 :\n{stdout}\n{stderr}");
        let corps = bb1c_refus_json(&stdout).unwrap_or_else(|| panic!("corps JSON de refus sur la sortie STANDARD :\n{stdout}\n{stderr}"));
        assert_eq!(corps["refusal"], "stale_token", "code servi : {corps}");
        let message = corps["message"].as_str().unwrap_or_default();
        assert!(message.starts_with(BB1C_CADUQUE) && message.contains(BB1C_JETON_FAUX), "message du refus : {corps}");
        assert!(bb1c_refus_json(&stderr).is_none(), "aucun corps JSON sur la sortie d'erreur :\n{stderr}");
    }

    #[test]
    fn p10_29l_purge_cli_refus_texte_sort_3_phrase_sur_la_sortie_d_erreur() {
        if std::env::var_os(BB1C_ENFANT).is_some() {
            eprintln!("{BB1C_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _env = VERROU_ENV_PROCESSUS.read();
        let (tmp, base) = bb1c_base();
        let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        enfant.env(BB1C_ENFANT, "1");
        let (_, code, stdout, stderr) = bb1c_executer(
            enfant,
            "p10_29l_purge_cli_refus_texte_sort_3_phrase_sur_la_sortie_d_erreur",
            &tmp,
            &base,
            &["--confirm", BB1C_JETON_FAUX, "--reason", "temoin bb1c"],
        );
        assert_eq!(code, 3, "refus en texte : sortie 3 :\n{stdout}\n{stderr}");
        assert!(
            stderr.lines().any(|l| l.starts_with(BB1C_CADUQUE) && l.contains(BB1C_JETON_FAUX)),
            "la phrase du refus est sur la sortie d'ERREUR :\n{stderr}"
        );
        assert!(!stdout.contains(BB1C_CADUQUE), "rien du refus sur la sortie standard :\n{stdout}");
    }

    #[test]
    fn p10_29l_purge_cli_simulation_json_sort_0_plan_sur_la_sortie_standard() {
        if std::env::var_os(BB1C_ENFANT).is_some() {
            eprintln!("{BB1C_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _env = VERROU_ENV_PROCESSUS.read();
        let (tmp, base) = bb1c_base();
        let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        enfant.env(BB1C_ENFANT, "1");
        let (_, code, stdout, stderr) = bb1c_executer(
            enfant,
            "p10_29l_purge_cli_simulation_json_sort_0_plan_sur_la_sortie_standard",
            &tmp,
            &base,
            &["--json"],
        );
        assert_eq!(code, 0, "simulation : sortie 0 :\n{stdout}\n{stderr}");
        assert!(stdout.contains("\"token\""), "le plan JSON (jeton de confirmation) est sur la sortie standard :\n{stdout}");
        assert!(!stderr.contains("\"token\""), "rien du plan sur la sortie d'erreur :\n{stderr}");
    }

    /// Décision (`count_mismatch`) puis ROLLBACK refusé DANS L'ENFANT, `--json` : sortie 3, corps entier sur la sortie
    /// standard, une ligne `[<id>] [purge] ERREUR` sur la sortie d'erreur, events intacts.
    #[test]
    fn p10_29l_purge_cli_decision_puis_rollback_refuse_sort_3_corps_entier_et_ligne_de_journal() {
        if std::env::var_os(BB1C_ENFANT).is_some() {
            eprintln!("{BB1C_MARQUE_ENFANT}");
            // SAFETY : point d'entrée de la signature attendue par `sqlite3_auto_extension`, posé avant toute ouverture
            // de connexion dans ce processus enfant.
            let pose = unsafe { rusqlite::ffi::sqlite3_auto_extension(Some(bb1c_poser_l_autorisateur)) };
            assert_eq!(pose, rusqlite::ffi::SQLITE_OK, "extension automatique posée dans l'enfant");
            crate::main();
            return;
        }
        let _env = VERROU_ENV_PROCESSUS.read();
        let (tmp, base) = bb1c_base();
        let jeton = {
            let c = bb1c_ouvrir(&base);
            for i in 0..4 {
                c.execute(
                    "INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id) \
                     VALUES(?1,?2,'test',1,'preuve','h1','prod','','')",
                    params![1_000 + i, BB1C_SOURCE],
                )
                .expect("event du périmètre");
            }
            let jeton = purge_plan(&c, bb1c_perimetre()).expect("plan nominal").digest().to_string();
            c.execute_batch(BB1C_IGNORE_UNE).expect("déclencheur posé après le plan");
            jeton
        };
        assert_eq!(bb1c_events(&base), 4, "contrôle : quatre events dans le périmètre");
        let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        enfant.env(BB1C_ENFANT, "1");
        let (pid, code, stdout, stderr) = bb1c_executer(
            enfant,
            "p10_29l_purge_cli_decision_puis_rollback_refuse_sort_3_corps_entier_et_ligne_de_journal",
            &tmp,
            &base,
            &["--json", "--confirm", jeton.as_str(), "--reason", "temoin bc1"],
        );
        assert_eq!(code, 3, "décision puis ROLLBACK refusé : sortie 3 :\n{stdout}\n{stderr}");
        let corps = bb1c_refus_json(&stdout)
            .unwrap_or_else(|| panic!("corps JSON de refus sur la sortie STANDARD :\n{stdout}\n{stderr}"));
        let id = corps["id"].as_str().unwrap_or_else(|| panic!("`id` rendu : {corps}")).to_string();
        let rang = id.strip_prefix(&format!("plume-e{pid}-")).unwrap_or_else(|| panic!("`id` de l'enfant {pid} : {id}"));
        assert!(!rang.is_empty() && rang.bytes().all(|b| b.is_ascii_digit()), "forme de `{id}`");
        let display = BB1C_DISPLAY_RESTEE_OUVERTE.replace("<ETAPE>", "count_mismatch").replace("<ID>", &id);
        assert_eq!(
            corps,
            serde_json::json!({
                "ok": false, "refusal": "count_mismatch", "message": display,
                "id": id, "annulation_refusee": true
            }),
            "corps entier rendu par l'enfant"
        );
        let prefixe = format!("[{id}] [purge] ERREUR ");
        assert_eq!(
            stderr.lines().filter(|l| l.starts_with(&prefixe)).count(),
            1,
            "une ligne de journal sous l'identifiant servi, sur la sortie d'erreur :\n{stderr}"
        );
        assert!(bb1c_refus_json(&stderr).is_none(), "aucun corps JSON sur la sortie d'erreur :\n{stderr}");
        assert_eq!(bb1c_events(&base), 4, "events intacts : rien n'est validé, l'enfant sorti");
    }
}
