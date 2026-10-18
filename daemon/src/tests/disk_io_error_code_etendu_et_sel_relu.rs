// ================================================================================================
// P10.33-r — LE CODE ÉTENDU D'UNE ERREUR SQLITE SE DIT AU JOURNAL, `SQLITE_IOERR_NOMEM` EST DÉJÀ UN
// REFUS MÉMOIRE, ET LE SEL DE MASQUAGE SE RELIT À LA DEMANDE
// ================================================================================================
// Relevé sur un pod neuf : « disk I/O error » dans les premières minutes (sel de masquage illisible,
// pré-chauffages, plein texte), puis plus rien. Ce qui a été lu, joué et changé :
//
//   · LE CODE ÉTENDU N'ÉTAIT DIT NULLE PART. « disk I/O error » est le texte de toute la famille
//     `SQLITE_IOERR` (`IOERR_READ`, `IOERR_SHMSIZE`, `IOERR_SHMMAP`, `IOERR_LOCK`…) ;
//     `read_field_mask_salt` rendait `e.to_string()`, et les deux journaux du sel le recopiaient.
//     `decrire_l_erreur` ajoute le code étendu (nommé dans la famille d'E/S), et `message_erreur`
//     journalise les erreurs du SUPPORT de la base (E/S, ouverture, disque plein, corruption, verrou),
//     jamais celles de la requête ;
//   · `install_fmask_udf` lisait le sel UNE fois : un échec transitoire figeait le refus de tout HASH
//     pour la vie de la connexion, et les connexions vivent dans `READ_POOL`. Le sel est relu à chaque
//     appel tant qu'il n'est pas établi, seul le succès est gardé.
//
// CE QUI ÉTAIT FAUX DANS L'ÉNONCÉ ET LA CONSIGNE :
//   · L'HYPOTHÈSE « `SQLITE_IOERR_NOMEM` sort en "disk I/O error", que le classeur ne reconnaît pas ».
//     SQLite convertit ce code en `SQLITE_NOMEM` à la frontière de l'API : l'abandon de l'instruction
//     appelle `sqlite3OomFault` pour `IOERR_NOMEM`, puis `apiHandleError` (dans `sqlite3ApiExit`, que
//     traversent `sqlite3_step`, `sqlite3_prepare*` et l'ouverture) rend `SQLITE_NOMEM` et pose
//     « out of memory ». Joué ci-dessous : une fonction scalaire qui rend `IOERR_NOMEM` au pas fait
//     sortir du pas le code étendu 7, et `run_on_conn` rend le refus mémoire avec le classeur INCHANGÉ.
//     Le classeur n'est donc PAS étendu (une branche sur 3082 serait morte) ; et le « disk I/O error »
//     relevé en prod n'est PAS un manque de mémoire : c'est un autre code de la famille, que le
//     journal dira désormais ;
//   · LA VOIE `Context::get_connection` pour relire le sel. En rusqlite 0.31, la `ConnectionRef`
//     rendue, en tombant, passe par `InnerConnection::close`, qui appelle `remove_hooks()` avant de
//     tester `owned` (`inner_connection.rs`, `hooks.rs`) : elle efface l'authorizer DENY et le rappel
//     de progression de la connexion du pool. Le témoin du sel relu juge donc AUSSI qu'un authorizer
//     posé avant la relecture refuse toujours après (mutant `get_connection`).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS :
//   · `SQLITE_IOERR_NOMEM` est FABRIQUÉ par une fonction scalaire : le refus d'allocation de
//     `unixShmMap` sous la limite de tas (de PROCESSUS) n'est pas provoqué ; la conversion jugée est
//     celle du chemin d'abandon du VDBE, les autres chemins (`sqlite3_prepare*`, ouverture) sont lus,
//     pas joués ;
//   · puisque SQLite écrase `IOERR_NOMEM` en `SQLITE_NOMEM`, le journal ne distingue pas un refus
//     d'allocation de la couche d'E/S d'un refus du VDBE (seul un rappel `SQLITE_CONFIG_LOG`, non
//     posé, verrait le code d'origine) ;
//   · le sel « transitoirement illisible » est simulé par un authorizer qui refuse la lecture de
//     `meta.value`, pas par une erreur d'E/S ; l'erreur d'E/S (`IOERR_SHMSIZE`) et l'interruption de la
//     relecture sont FABRIQUÉES par une vue temporaire `meta` dont `value` appelle une fonction qui rend
//     ce code au pas, pas par le volume ni par le rappel de progression ;
//   · la fermeture refusée (`SQLITE_BUSY`) juge qu'aucune instruction de relecture ne reste en suspens
//     après les chemins joués (succès, échec au pas) ; l'échec à la préparation laisse `st` nul.

#[cfg(test)]
mod disk_io_error_code_etendu_et_sel_relu {
    use rusqlite::functions::FunctionFlags;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use rusqlite::Connection;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    /// `SQLITE_IOERR_SHMSIZE` = `SQLITE_IOERR | (19 << 8)` : même famille, autre cause.
    const IOERR_SHMSIZE: i32 = 4874;
    const SEL_D_EPREUVE: &str = "sel-d-epreuve-v1";

    fn echec(code: i32, texte: Option<&str>) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), texte.map(str::to_string))
    }

    /// Les cinq classes d'erreur du SUPPORT hors famille d'E/S, avec le texte du moteur pour chacune.
    const CLASSES_DU_SUPPORT_HORS_E_S: [(i32, &str); 5] = [
        (rusqlite::ffi::SQLITE_CANTOPEN, "unable to open database file"),
        (rusqlite::ffi::SQLITE_FULL, "database or disk is full"),
        (rusqlite::ffi::SQLITE_CORRUPT, "database disk image is malformed"),
        (rusqlite::ffi::SQLITE_NOTADB, "file is not a database"),
        (rusqlite::ffi::SQLITE_PROTOCOL, "locking protocol"),
    ];

    /// Une fonction scalaire qui rend, au PAS, l'erreur dont le code est son argument (sans message : un
    /// message ferait rabattre le code sur SQLITE_ERROR, `sqlite3_result_error`).
    fn poser_la_fonction_d_erreur(c: &Connection) {
        c.create_scalar_function("v1_erreur_d_e_s", 1, FunctionFlags::SQLITE_UTF8, |ctx| -> rusqlite::Result<i64> {
            Err(echec(ctx.get::<i32>(0)?, None))
        })
        .unwrap();
    }

    /// Une base dont `meta` est une vue TEMPORAIRE : lire `value` appelle la fonction d'erreur avec `code`.
    fn base_dont_le_sel_rend(code: i32) -> Connection {
        let c = Connection::open_in_memory().expect("base d'épreuve");
        poser_la_fonction_d_erreur(&c);
        c.execute_batch(&format!(
            "CREATE TEMP VIEW meta AS SELECT 'field_mask_salt' AS key, v1_erreur_d_e_s({code}) AS value;"
        ))
        .expect("vue d'épreuve");
        c
    }

    /// Toute instruction préparée par le démon sur la connexion est finalisée : `sqlite3_close` rend
    /// `SQLITE_BUSY` tant qu'une instruction reste en suspens, et le `Drop` de rusqlite l'ignorerait.
    fn fermer_sans_instruction_en_suspens(c: Connection) {
        if let Err((_, e)) = c.close() {
            panic!("une instruction de relecture n'a pas été finalisée (la connexion refuse de se fermer) : {e}");
        }
    }

    fn est_un_refus_memoire(m: &str) -> bool {
        m.contains("budget mémoire dépassé") || m.contains("mémoire épuisée")
    }

    /// Une base de lecture minimale : `meta` avec un sel, et une table `secret` que l'authorizer refuse.
    fn base_avec_sel() -> Connection {
        let c = Connection::open_in_memory().expect("base d'épreuve");
        c.execute_batch(&format!(
            "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT); \
             INSERT INTO meta VALUES('field_mask_salt','{SEL_D_EPREUVE}'); \
             CREATE TABLE secret(x TEXT); INSERT INTO secret VALUES('s');"
        ))
        .expect("schéma d'épreuve");
        c
    }

    /// Authorizer : refuse la lecture de `meta.value` tant que `refuser_le_sel` est vrai (compte chaque
    /// demande de lecture de cette colonne), et refuse TOUJOURS `secret`.
    fn poser_l_authorizer(c: &Connection, refuser_le_sel: Arc<AtomicBool>, lectures_du_sel: Arc<AtomicUsize>) {
        c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "meta" && column_name == "value" => {
                lectures_du_sel.fetch_add(1, Ordering::SeqCst);
                if refuser_le_sel.load(Ordering::SeqCst) {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }
            AuthAction::Read { table_name, .. } if table_name == "secret" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// (1) LES ERREURS D'E/S NE SONT PAS DES REFUS MÉMOIRE, AU POINT D'ENTRÉE `message_erreur` :
    /// `SQLITE_IOERR` nu et `IOERR_SHMSIZE` (même code primaire que `IOERR_NOMEM`), et `SQLITE_BUSY`
    /// portant le texte « out of memory », sortent TELS QUELS — le classeur lit le code, jamais le texte,
    /// jamais toute la famille `SystemIoFailure`.
    ///
    /// MUTATION : `tout_ioerr` (toute la famille d'E/S classée manque de mémoire) -> ROUGE.
    #[test]
    fn les_erreurs_d_e_s_ne_sont_pas_des_refus_memoire() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // un refus lirait le plafond dans l'environnement
        for intact in [
            echec(rusqlite::ffi::SQLITE_IOERR, Some("disk I/O error")),
            echec(IOERR_SHMSIZE, Some("disk I/O error")),
            echec(rusqlite::ffi::SQLITE_BUSY, Some("out of memory")),
        ] {
            assert_eq!(
                crate::sqlite_plafond::message_erreur(&intact),
                intact.to_string(),
                "une erreur d'E/S n'est pas un refus mémoire : {intact:?}"
            );
        }
    }

    /// (1 bis) RÉFUTATION, DE BOUT EN BOUT À TRAVERS `run_on_conn` : une fonction scalaire rend
    /// `SQLITE_IOERR_NOMEM` au PAS. Le pas rend le code étendu `SQLITE_NOMEM` (7) et « out of memory »
    /// (SQLite a converti), et `run_on_conn` rend le refus mémoire avec le classeur d'avant. Contrôle
    /// négatif : `IOERR_SHMSIZE` au pas garde son code et ressort en texte du moteur.
    ///
    /// MUTATIONS : `nomem_retire` (classeur qui ne reconnaît plus `SQLITE_NOMEM`) -> ROUGE : c'est bien
    /// par la conversion en `SQLITE_NOMEM` que `IOERR_NOMEM` est reconnu ; `tout_ioerr` -> contrôle
    /// négatif ROUGE.
    #[test]
    fn un_ioerr_nomem_au_pas_sort_en_sqlite_nomem_et_en_refus_memoire() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let c = Connection::open_in_memory().unwrap();
        poser_la_fonction_d_erreur(&c);
        let sql_nomem = format!("SELECT v1_erreur_d_e_s({})", rusqlite::ffi::SQLITE_IOERR_NOMEM);
        match c.query_row(&sql_nomem, [], |r| r.get::<_, i64>(0)) {
            Err(rusqlite::Error::SqliteFailure(f, Some(m)))
                if f.extended_code == rusqlite::ffi::SQLITE_NOMEM && m == "out of memory" => {}
            autre => panic!("SQLite devait convertir IOERR_NOMEM en SQLITE_NOMEM « out of memory » : {autre:?}"),
        }
        let err = crate::query_exec::run_on_conn(&c, ":memory:v1-ioerr-nomem", &sql_nomem, 600_000, None)
            .expect_err("le pas échoue");
        assert!(est_un_refus_memoire(&err), "IOERR_NOMEM au pas doit sortir en refus mémoire : {err}");

        let sql_shm = format!("SELECT v1_erreur_d_e_s({IOERR_SHMSIZE})");
        match c.query_row(&sql_shm, [], |r| r.get::<_, i64>(0)) {
            Err(rusqlite::Error::SqliteFailure(f, _)) if f.extended_code == IOERR_SHMSIZE => {}
            autre => panic!("instrument : IOERR_SHMSIZE garde son code étendu au pas : {autre:?}"),
        }
        let err = crate::query_exec::run_on_conn(&c, ":memory:v1-ioerr-shmsize", &sql_shm, 600_000, None)
            .expect_err("le pas échoue");
        assert!(!est_un_refus_memoire(&err), "IOERR_SHMSIZE n'est pas un manque de mémoire : {err}");
        assert!(err.contains("disk I/O error"), "le texte du moteur sort tel quel : {err}");
    }

    /// (2) LA DESCRIPTION, PAR VALEUR. Nom lisible dans la famille d'E/S, le nombre seul ailleurs ou pour
    /// un rang inconnu, le texte seul pour une erreur sans code. Et `read_field_mask_salt` garde le code.
    ///
    /// MUTATION : `code_absent` (la description réduite au texte du moteur) -> ROUGE.
    #[test]
    fn la_description_porte_le_code_etendu() {
        use crate::sqlite_plafond::decrire_l_erreur;
        assert_eq!(
            decrire_l_erreur(&echec(rusqlite::ffi::SQLITE_IOERR_NOMEM, Some("disk I/O error"))),
            "disk I/O error [SQLITE_IOERR_NOMEM, code étendu 3082]"
        );
        assert_eq!(
            decrire_l_erreur(&echec(IOERR_SHMSIZE, Some("disk I/O error"))),
            "disk I/O error [SQLITE_IOERR_SHMSIZE, code étendu 4874]"
        );
        assert_eq!(
            decrire_l_erreur(&echec(rusqlite::ffi::SQLITE_IOERR, Some("disk I/O error"))),
            "disk I/O error [SQLITE_IOERR, code étendu 10]"
        );
        assert_eq!(
            decrire_l_erreur(&echec(rusqlite::ffi::SQLITE_IOERR | (60 << 8), Some("disk I/O error"))),
            "disk I/O error [code étendu 15370]"
        );
        assert_eq!(
            decrire_l_erreur(&echec(rusqlite::ffi::SQLITE_BUSY, Some("database is locked"))),
            "database is locked [code étendu 5]"
        );
        assert_eq!(decrire_l_erreur(&rusqlite::Error::QueryReturnedNoRows), "Query returned no rows");

        let c = base_avec_sel();
        poser_l_authorizer(&c, Arc::new(AtomicBool::new(true)), Arc::new(AtomicUsize::new(0)));
        assert_eq!(
            crate::read_field_mask_salt(&c),
            Err("access to meta.value is prohibited [code étendu 23]".to_string()),
            "la lecture ratée du sel garde son code"
        );
    }

    /// (2 bis) LA LIGNE DE JOURNAL, LUE SUR LE STDERR D'UN SOUS-PROCESSUS. L'enfant passe à
    /// `message_erreur` une erreur du SUPPORT (`IOERR_SHMSIZE`) et une erreur de REQUÊTE (colonne
    /// inconnue), puis installe le HASH sur une connexion dont le sel est illisible.
    ///
    /// Les cinq autres classes du support (ouverture, disque plein, corruption, fichier qui n'est pas une
    /// base, protocole de verrou) ont chacune leur ligne ; et l'échec d'une relecture à la demande du sel
    /// a la sienne.
    ///
    /// MUTATIONS : `code_absent` -> la ligne `[sqlite]` et la ligne du sel perdent le code : ROUGE ;
    /// `journal_tout` (toute erreur SQLite journalisée) -> la colonne inconnue apparaît : ROUGE ;
    /// `journal_ioerr_seul` (classeur réduit à la famille d'E/S) -> cinq lignes manquent : ROUGE ;
    /// `relecture_muette` (échec de relecture rendu au client seulement) -> ROUGE.
    #[test]
    fn le_journal_dit_le_code_etendu_des_erreurs_du_support() {
        const ENFANT: &str = "V1_JOURNAL_DU_CODE_ETENDU_ENFANT";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            println!("V1-ENFANT-A-JOUE");
            let _ = crate::sqlite_plafond::message_erreur(&echec(IOERR_SHMSIZE, Some("disk I/O error")));
            for (code, texte) in CLASSES_DU_SUPPORT_HORS_E_S {
                let _ = crate::sqlite_plafond::message_erreur(&echec(code, Some(texte)));
            }
            let _ = crate::sqlite_plafond::message_erreur(&echec(1, Some("no such column: v1_colonne_inconnue")));
            let c = base_avec_sel();
            poser_l_authorizer(&c, Arc::new(AtomicBool::new(true)), Arc::new(AtomicUsize::new(0)));
            crate::query_exec::install_fmask_udf(&c);
            // La relecture à la demande échoue aussi : elle se dit au journal de l'hôte.
            let _ = c.query_row("SELECT plume_fmask_hash('alice')", [], |r| r.get::<_, String>(0));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::disk_io_error_code_etendu_et_sel_relu::le_journal_dit_le_code_etendu_des_erreurs_du_support",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("V1-ENFANT-A-JOUE"), "contrôle : l'enfant a vraiment joué : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let du_support: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[sqlite] ")).collect();
        let mut attendu = vec![
            "[sqlite] erreur du support de la base : disk I/O error [SQLITE_IOERR_SHMSIZE, code étendu 4874]".to_string(),
        ];
        attendu.extend(
            CLASSES_DU_SUPPORT_HORS_E_S
                .iter()
                .map(|(code, texte)| format!("[sqlite] erreur du support de la base : {texte} [code étendu {code}]")),
        );
        assert_eq!(
            du_support, attendu,
            "une ligne par erreur du support (les six classes), avec son code étendu, aucune pour la requête : {stderr}"
        );
        assert!(!stderr.contains("v1_colonne_inconnue"), "une erreur de requête ne va pas au journal d'hôte : {stderr}");
        assert!(
            stderr.lines().any(|l| l.starts_with(
                "[field_filter] sel de hachage ILLISIBLE sur cette connexion : access to meta.value is prohibited [code étendu 23] — "
            )),
            "le journal du sel illisible porte le code étendu : {stderr}"
        );
        assert!(
            stderr.lines().any(|l| l.starts_with(
                "[field_filter] sel de hachage ILLISIBLE à la relecture : access to meta.value is prohibited [code étendu 23] — "
            )),
            "l'échec de la relecture à la demande va AUSSI au journal de l'hôte, avec son code : {stderr}"
        );
    }

    /// (3) LE SEL TRANSITOIREMENT ILLISIBLE NE FIGE PLUS LE REFUS. Sel refusé à l'installation : HASH
    /// échoue (nommant le sel et le code) ; lecture rendue : HASH RÉUSSIT sur la MÊME connexion, avec le
    /// hash du sel, en UNE relecture pour trois lignes ; l'authorizer refuse toujours `secret` après la
    /// relecture ; le sel effacé APRÈS le succès, le hash ne change pas (cache du succès).
    ///
    /// MUTATIONS : `refus_en_cache` (forme d'avant) -> la réussite attendue est un refus : ROUGE ;
    /// `succes_non_cache` -> trois relectures, puis refus une fois le sel effacé : ROUGE ;
    /// `get_connection` (la voie de la consigne) -> l'authorizer est effacé par la relecture : ROUGE ;
    /// `finalize_retire` (l'instruction de relecture n'est pas finalisée après le pas) -> la connexion
    /// refuse de se fermer (`SQLITE_BUSY`, instruction en suspens) : ROUGE.
    #[test]
    fn un_sel_transitoirement_illisible_est_relu_et_seul_le_succes_est_garde() {
        let c = base_avec_sel();
        let refuser_le_sel = Arc::new(AtomicBool::new(true));
        let lectures = Arc::new(AtomicUsize::new(0));
        poser_l_authorizer(&c, refuser_le_sel.clone(), lectures.clone());
        crate::query_exec::install_fmask_udf(&c);
        const TROIS: &str = "SELECT plume_fmask_hash(v) FROM (SELECT 'alice' AS v UNION ALL SELECT 'bob' UNION ALL SELECT 'carol')";
        let hacher = |c: &Connection| -> rusqlite::Result<Vec<String>> {
            let mut st = c.prepare(TROIS)?;
            let lignes = st.query_map([], |r| r.get::<_, String>(0))?;
            lignes.collect()
        };

        let avant = lectures.load(Ordering::SeqCst);
        let e = hacher(&c).expect_err("sel toujours refusé : HASH refuse").to_string();
        assert!(e.contains("sel") && e.contains("code étendu 23"), "le refus nomme le sel et le code : {e}");
        assert_eq!(lectures.load(Ordering::SeqCst) - avant, 1, "une seule relecture : le premier échec arrête l'instruction");

        refuser_le_sel.store(false, Ordering::SeqCst);
        let attendu: Vec<String> = ["alice", "bob", "carol"].iter().map(|v| crate::fmask_hash(SEL_D_EPREUVE, v)).collect();
        let avant = lectures.load(Ordering::SeqCst);
        assert_eq!(hacher(&c).expect("lecture rendue : HASH réussit sur la même connexion"), attendu);
        assert_eq!(lectures.load(Ordering::SeqCst) - avant, 1, "une relecture pour trois lignes, puis le cache");

        match c.query_row("SELECT x FROM secret", [], |r| r.get::<_, String>(0)) {
            Err(e) if e.to_string().contains("prohibited") => {}
            autre => panic!("la relecture du sel ne doit pas effacer l'authorizer de la connexion : {autre:?}"),
        }

        c.execute("DELETE FROM meta WHERE key='field_mask_salt'", []).expect("effacement du sel");
        assert_eq!(crate::read_field_mask_salt(&c), Ok(None), "contrôle : sel effacé");
        assert_eq!(hacher(&c).expect("sel établi : le cache sert"), attendu, "corrélation préservée");
        fermer_sans_instruction_en_suspens(c);
    }

    /// (4) LE CODE ÉTENDU SURVIT À LA RELECTURE À LA DEMANDE. `meta` est une vue temporaire dont `value`
    /// rend `IOERR_SHMSIZE` au pas : un code étendu qui NE VAUT PAS son code primaire (4874 contre 10), le
    /// cas même que la clé veut voir. Le refus de HASH dit le nom et le nombre ; puis la connexion se ferme
    /// (l'instruction de relecture est finalisée aussi sur le chemin d'échec du pas).
    ///
    /// MUTATIONS : `code_primaire` (la relecture ne garde que `rc & 0xff`) -> « code étendu 10 » : ROUGE ;
    /// `finalize_retire` -> la connexion refuse de se fermer : ROUGE.
    #[test]
    fn la_relecture_du_sel_garde_le_code_etendu_qui_ne_vaut_pas_son_primaire() {
        let c = base_dont_le_sel_rend(IOERR_SHMSIZE);
        assert_eq!(
            crate::read_field_mask_salt(&c),
            Err("disk I/O error [SQLITE_IOERR_SHMSIZE, code étendu 4874]".to_string()),
            "instrument : la vue rend IOERR_SHMSIZE à la lecture du sel"
        );
        crate::query_exec::install_fmask_udf(&c);
        let e = c
            .query_row("SELECT plume_fmask_hash('alice')", [], |r| r.get::<_, String>(0))
            .expect_err("sel illisible : HASH refuse")
            .to_string();
        assert!(
            e.contains("illisible") && e.contains("[SQLITE_IOERR_SHMSIZE, code étendu 4874]"),
            "le refus de la relecture porte le code étendu, pas le primaire : {e}"
        );
        fermer_sans_instruction_en_suspens(c);
    }

    /// (5) UNE INTERRUPTION PENDANT LA RELECTURE EST CLASSÉE COMME INTERRUPTION. La relecture imbriquée
    /// voit le même rappel de progression que l'instruction externe : une annulation, le budget ou le quota
    /// de déversement peut l'arrêter. Simulée par la vue dont `value` rend `SQLITE_INTERRUPT` au pas :
    /// l'instruction externe échoue en `SQLITE_INTERRUPT`, et `run_on_conn` (point d'entrée) rend le
    /// dépassement de budget, pas « sel illisible : interrupted ».
    ///
    /// MUTATION : `interruption_illisible` (l'interruption rendue comme lecture ratée) -> ROUGE.
    #[test]
    fn une_interruption_pendant_la_relecture_est_classee_comme_interruption() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let c = base_dont_le_sel_rend(rusqlite::ffi::SQLITE_INTERRUPT);
        crate::query_exec::install_fmask_udf(&c);
        match c.query_row("SELECT plume_fmask_hash('alice')", [], |r| r.get::<_, String>(0)) {
            Err(rusqlite::Error::SqliteFailure(f, _)) if f.code == rusqlite::ErrorCode::OperationInterrupted => {}
            autre => panic!("l'instruction externe échoue sous le code d'interruption : {autre:?}"),
        }
        let err = crate::query_exec::run_on_conn(&c, ":memory:v1-relecture-interrompue", "SELECT plume_fmask_hash('alice')", 600_000, None)
            .expect_err("la relecture est interrompue");
        assert_eq!(err, "requête interrompue (budget 600 s dépassé)", "classée comme interruption : {err}");
        fermer_sans_instruction_en_suspens(c);
    }
}
