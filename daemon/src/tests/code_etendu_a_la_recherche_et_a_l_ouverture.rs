// ================================================================================================
// P10.33-r — LE CODE ÉTENDU D'UNE ERREUR DU SUPPORT SE DIT AUSSI À `/api/search` ET À L'OUVERTURE
// D'UNE CONNEXION DE LECTURE
// ================================================================================================
// Ce qui a été lu et changé :
//
//   · `/api/search` : `search_engine_error` (handlers/search.rs) écrit `[search] WARN … : code SQLite N (Classe)`,
//     où N est DÉJÀ le code étendu, en nombre ; il n'écrivait ni le NOM du code (`SQLITE_IOERR_SHMMAP`) ni la ligne
//     `[sqlite] erreur du support de la base` que `message_erreur` écrit ailleurs. Elle l'écrit désormais, par le
//     même assistant (`sqlite_plafond::journaliser_si_erreur_du_support`), pour les seules classes du support ; le
//     corps rendu au client ne change pas (phrase fixe `RECHERCHE_REJETEE`, recopiée ici en littéral) ;
//   · l'ouverture d'une connexion de lecture (`query_exec::read_conn_open`) : l'échec n'allait PAS au journal par
//     `read_with` ni `read_with_watchdog` (qui le remplacent par leur défaut, query_exec.rs `Err(_) => default`) ;
//     par `run_query_ex` (`read_conn_get(db_path)?`), il remontait et `[query] WARN` en disait la nature, mais
//     avec le seul code PRIMAIRE. Car rusqlite n'en connaissait que le code PRIMAIRE —
//     `sqlite3_open_v2` masque par `errMask` = 0xff tant que les codes étendus ne sont pas allumés, ce que rusqlite
//     ne fait qu'après l'ouverture (`openDatabase` de sqlite3.c ; `InnerConnection::open_with_flags`). L'ouverture
//     passe `SQLITE_OPEN_EXRESCODE` et l'échec part au journal par la même ligne, SANS le texte : rusqlite y colle le
//     CHEMIN de la base (« unable to open database file: <chemin> »).
//
// CE QUI ÉTAIT FAUX DANS L'ÉNONCÉ : « `/api/search` ne dit pas le code étendu » — il le disait en nombre dans
// `[search] WARN` ; ce qui manquait était son nom et la ligne `[sqlite]` commune. Et « l'ouverture ne dit pas le code
// étendu » : elle ne POUVAIT pas le dire sans `SQLITE_OPEN_EXRESCODE`, le code étendu n'atteignant pas rusqlite.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS :
//   · les pannes sont FABRIQUÉES, aucun volume réel : l'erreur d'E/S de la recherche vient d'une fonction `regexp`
//     substituée sur la connexion du pool, qui rend le code au pas ; celle de l'ouverture, d'un VFS par défaut
//     substitué DANS UN SOUS-PROCESSUS, dont `xOpen` rend le code pour un seul nom de fichier ;
//   · la cause vue en prod (« disk I/O error » au démarrage d'un pod) n'est PAS établie ici : elle reste à LIRE dans
//     ces lignes après déploiement ;
//   · un échec d'ouverture hors des classes du support ne part PAS à la ligne `[sqlite]` — c'est JOUÉ ici : le VFS
//     substitué rend aussi `SQLITE_NOMEM` et `SQLITE_PERM` pour deux autres noms, et aucune ligne n'est écrite (le
//     classeur est celui de `message_erreur`, inchangé ; mémoire et E/S restent distinguées) ;
//   · SEULE l'ouverture du POOL DE LECTURE passe `SQLITE_OPEN_EXRESCODE` et se journalise. L'écrivain
//     (`db_open.rs`, `Connection::open`) et les autres ouvertures en lecture seule (`rollups.rs`, `ledger.rs`,
//     `integrity_check.rs`, `main.rs`) rendent toujours le code PRIMAIRE seul ;
//   · HORS LOT, antérieur : le TEXTE que `read_conn_open` rend à l'appelant porte le chemin de la base pour
//     `CANTOPEN` (« unable to open database file: <chemin> ») et pour `NOMEM` (le chemin seul : SQLite n'a pas rendu
//     de poignée) ; il est épinglé tel quel ci-dessous, constaté et non corrigé, et n'a pas été suivi jusqu'au client.

#[cfg(test)]
mod ay4_code_etendu_recherche_ouverture {
    use super::*;
    use rusqlite::functions::FunctionFlags;
    use std::ffi::CStr;
    use std::os::raw::{c_char, c_int};
    use std::sync::atomic::{AtomicBool, Ordering};

    const AY4_ENFANT_ROUTE: &str = "AY4_ENFANT_ROUTE";
    const AY4_ENFANT_OUVERTURE: &str = "AY4_ENFANT_OUVERTURE";
    const AY4_RENDU: &str = "AY4-RENDU:";
    const AY4_FIN: &str = "AY4-FIN:";
    const AY4_ESSAIS: usize = 40;
    /// La phrase servie pour un refus du moteur, ÉCRITE ICI (jamais tirée de la production).
    const PHRASE_DU_REFUS: &str =
        "le moteur de recherche a REFUSÉ cette requête (ce n'est pas « aucun résultat ») : motif rejeté par le moteur de recherche";
    /// `SQLITE_IOERR | (2 << 8)`.
    const IOERR_READ: i32 = 266;
    /// Le seul nom de fichier dont le VFS substitué refuse l'ouverture.
    const MARQUE_DU_VFS: &[u8] = b"ay4-ouverture-en-panne";
    /// Les deux noms dont le VFS substitué refuse l'ouverture HORS des classes du support.
    const MARQUE_NOMEM: &[u8] = b"ay4-ouverture-sans-memoire";
    const MARQUE_PERM: &[u8] = b"ay4-ouverture-sans-droit";
    const NOM_DU_VFS: &[u8] = b"ay4-vfs-en-panne\0";

    type XOpen = unsafe extern "C" fn(*mut rusqlite::ffi::sqlite3_vfs, *const c_char, *mut rusqlite::ffi::sqlite3_file, c_int, *mut c_int) -> c_int;
    static XOPEN_D_ORIGINE: std::sync::OnceLock<XOpen> = std::sync::OnceLock::new();

    unsafe extern "C" fn ay4_xopen(
        vfs: *mut rusqlite::ffi::sqlite3_vfs,
        nom: *const c_char,
        fichier: *mut rusqlite::ffi::sqlite3_file,
        drapeaux: c_int,
        sortie: *mut c_int,
    ) -> c_int {
        let porte = |marque: &[u8]| !nom.is_null() && CStr::from_ptr(nom).to_bytes().windows(marque.len()).any(|w| w == marque);
        if porte(MARQUE_DU_VFS) {
            return rusqlite::ffi::SQLITE_IOERR_SHMMAP;
        }
        if porte(MARQUE_NOMEM) {
            return rusqlite::ffi::SQLITE_NOMEM;
        }
        if porte(MARQUE_PERM) {
            return rusqlite::ffi::SQLITE_PERM;
        }
        let origine = XOPEN_D_ORIGINE.get().expect("instrument : xOpen d'origine gardé");
        origine(vfs, nom, fichier, drapeaux, sortie)
    }

    /// Pose, comme VFS PAR DÉFAUT du processus, une copie du VFS d'origine dont seul `xOpen` change. N'est appelée que
    /// dans l'enfant : le processus de la suite garde son VFS.
    fn poser_le_vfs_en_panne() {
        unsafe {
            let defaut = rusqlite::ffi::sqlite3_vfs_find(std::ptr::null());
            assert!(!defaut.is_null(), "instrument : VFS par défaut trouvé");
            let mut copie: rusqlite::ffi::sqlite3_vfs = *defaut;
            let _ = XOPEN_D_ORIGINE.set(copie.xOpen.expect("instrument : xOpen du VFS d'origine"));
            copie.xOpen = Some(ay4_xopen);
            copie.zName = NOM_DU_VFS.as_ptr() as *const c_char;
            copie.pNext = std::ptr::null_mut();
            let rc = rusqlite::ffi::sqlite3_vfs_register(Box::into_raw(Box::new(copie)), 1);
            assert_eq!(rc, rusqlite::ffi::SQLITE_OK, "instrument : VFS substitué enregistré");
        }
    }

    /// Dépose dans le pool de `chemin` UNE connexion de lecture dont `regexp` rend `code` au pas (sans message, pour que le
    /// code ne retombe pas sur SQLITE_ERROR), après avoir vidé les connexions au repos. Le drapeau dit si elle a servi.
    fn armer(chemin: &str, code: i32) -> Arc<AtomicBool> {
        vider_le_pool(chemin);
        let conn = crate::query_exec::read_conn_get(chemin).expect("fixture : connexion de lecture");
        let joue = Arc::new(AtomicBool::new(false));
        let drapeau = joue.clone();
        conn.create_scalar_function("regexp", 2, FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC, move |_ctx| -> rusqlite::Result<bool> {
            drapeau.store(true, Ordering::SeqCst);
            Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None))
        })
        .expect("fixture : regexp substituée");
        crate::query_exec::read_conn_put(chemin, conn);
        joue
    }

    fn vider_le_pool(chemin: &str) {
        while crate::query_exec::connexions_de_lecture_au_repos(chemin) > 0 {
            drop(crate::query_exec::read_conn_get(chemin).expect("fixture : connexion au repos"));
        }
    }

    async fn envoi(addr: std::net::SocketAddr, chemin: &str, authz: &str) -> (u16, Value) {
        let (code, brut) = router_probe_envoi(addr, "GET", chemin, Some(authz), &[], "").await;
        let (tete, corps) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {chemin} : {brut}"));
        let corps = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(corps.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {chemin}"))).expect("corps UTF-8")
        } else {
            corps.to_string()
        };
        let mut v: Value = serde_json::from_str(&corps).unwrap_or(Value::Null);
        if let Some(o) = v.as_object_mut() {
            o.remove("stats");
        }
        (code, v)
    }

    async fn en_panne(addr: std::net::SocketAddr, base: &str, code: i32, requete: &str, authz: &str) -> (u16, Value) {
        for _ in 0..AY4_ESSAIS {
            let joue = armer(base, code);
            let rendu = envoi(addr, requete, authz).await;
            if joue.load(Ordering::SeqCst) {
                vider_le_pool(base);
                return rendu;
            }
        }
        panic!("instrument : la connexion armée n'a servi en aucun des {AY4_ESSAIS} essais — le témoin ne conclut pas");
    }

    /// La NATURE qu'écrit `[search] WARN` pour le motif `(` refusé par l'UDF `regexp`, reproduite sur une connexion en
    /// mémoire qui porte les mêmes UDF.
    fn nature_du_motif_refuse() -> String {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        crate::query_exec::install_query_udfs(&c);
        let e = c.query_row("SELECT 'x' REGEXP '('", [], |r| r.get::<_, bool>(0)).expect_err("instrument : motif refusé");
        match &e {
            rusqlite::Error::SqliteFailure(f, _) => format!("code SQLite {} ({:?})", f.extended_code, f.code),
            autre => panic!("instrument : erreur sans code SQLite : {autre}"),
        }
    }

    /// (1) PAR LA ROUTE, SUR LES DEUX BRANCHES DE LA BARRE. Une erreur d'E/S au pas (branche structurée :
    /// `IOERR_SHMMAP` ; branche plein-texte : `IOERR_READ`) écrit la ligne `[sqlite]` avec le NOM du code étendu, juste
    /// avant `[search] WARN` inchangée, et le corps reste la phrase fixe à l'octet ; un motif refusé (erreur de la
    /// requête) n'écrit AUCUNE ligne `[sqlite]` ; une recherche nominale non plus.
    ///
    /// MUTATIONS : `AY4_RECHERCHE_MUETTE` (l'appel retiré de `search_engine_error`) -> les deux lignes `[sqlite]`
    /// manquent : ROUGE ; `AY4_TOUT_JOURNAL` (classeur court-circuité) -> le motif refusé écrit une ligne : ROUGE.
    #[tokio::test]
    async fn la_recherche_dit_le_code_etendu_d_une_erreur_du_support() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        if std::env::var(AY4_ENFANT_ROUTE).is_ok() {
            let (st, _base) = router_test_state("ay4-recherche");
            let chemin = st.db_path.as_ref().clone();
            open_db(&chemin)
                .expect("fixture : base")
                .execute_batch("INSERT INTO event(ts,source,severity,message,host,src_ip) VALUES(1000,'ay4',1,'ay4sonde present','ay4-h',NULL);")
                .expect("fixture : un événement");
            let addr = router_serve(st.clone()).await;
            let lecteur = viewer_authz();
            let mut rendus: Vec<(String, u16, Value)> = Vec::new();
            let (c, v) = envoi(addr, "/api/search?q=host%3Aay4-h%20regex%3Dsonde", &lecteur).await;
            rendus.push(("nominale".into(), c, v));
            let (c, v) = en_panne(addr, &chemin, rusqlite::ffi::SQLITE_IOERR_SHMMAP, "/api/search?q=host%3Aay4-h%20regex%3Dsonde", &lecteur).await;
            rendus.push(("structuree".into(), c, v));
            let (c, v) = en_panne(addr, &chemin, IOERR_READ, "/api/search?q=ay4sonde%20regex%3Dsonde", &lecteur).await;
            rendus.push(("plein_texte".into(), c, v));
            vider_le_pool(&chemin);
            let (c, v) = envoi(addr, "/api/search?q=regex%3D%28", &lecteur).await;
            rendus.push(("motif".into(), c, v));
            for (issue, code, corps) in &rendus {
                println!("{AY4_RENDU}{}", json!([issue, code, corps]));
            }
            println!("{AY4_FIN} {}", rendus.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ay4_code_etendu_recherche_ouverture::la_recherche_dit_le_code_etendu_d_une_erreur_du_support",
            ])
            .env(AY4_ENFANT_ROUTE, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(&format!("{AY4_FIN} 4")), "contrôle : l'enfant a joué ses quatre issues : {stdout}\n{stderr}");
        let rendus: Vec<(String, u16, Value)> = stdout
            .lines()
            .filter_map(|l| l.split_once(AY4_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : ligne de rendu lisible ({e}) : {v}")))
            .collect();
        assert_eq!(rendus.len(), 4, "contrôle : une ligne par issue : {stdout}");
        let rendu = |issue: &str| rendus.iter().find(|(i, ..)| i == issue).map(|(_, c, v)| (*c, v.clone())).unwrap_or_else(|| panic!("{issue} rendu"));
        let (c, nominale) = rendu("nominale");
        assert_eq!(
            (c, nominale["results"].as_array().map(Vec::len), nominale.get("error").cloned()),
            (200, Some(1), None),
            "contrôle : la recherche nominale lit l'événement (la regexp d'origine est en place) : {nominale}"
        );
        let refus = json!({ "results": [], "error": PHRASE_DU_REFUS });
        for issue in ["structuree", "plein_texte", "motif"] {
            assert_eq!(rendu(issue), (200, refus.clone()), "{issue} : le corps servi reste la phrase fixe, à l'octet");
        }
        let journal: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[sqlite] ") || l.starts_with("[search] WARN")).collect();
        assert_eq!(
            journal,
            vec![
                "[sqlite] erreur du support de la base : disk I/O error [SQLITE_IOERR_SHMMAP, code étendu 5386]".to_string(),
                "[search] WARN recherche rejetée par le moteur (tenant 'default') : code SQLite 5386 (SystemIoFailure)".to_string(),
                "[sqlite] erreur du support de la base : disk I/O error [SQLITE_IOERR_READ, code étendu 266]".to_string(),
                "[search] WARN recherche rejetée par le moteur (tenant 'default') : code SQLite 266 (SystemIoFailure)".to_string(),
                format!("[search] WARN recherche rejetée par le moteur (tenant 'default') : {}", nature_du_motif_refuse()),
            ],
            "le journal ENTIER de la recherche : une ligne [sqlite] par erreur du support, aucune pour la requête : {stderr}"
        );
    }

    /// (2) L'OUVERTURE D'UNE CONNEXION DE LECTURE (`read_conn_get` sur un pool vide, donc `read_conn_open`), dans un
    /// sous-processus dont le VFS par défaut refuse l'ouverture d'un seul nom par `SQLITE_IOERR_SHMMAP`, puis sur un
    /// chemin dont le répertoire n'existe pas (`SQLITE_CANTOPEN` réel), puis sur un chemin qui porte un octet nul (erreur
    /// sans code SQLite), puis sur deux noms dont le VFS refuse l'ouverture par `SQLITE_NOMEM` et `SQLITE_PERM` (hors
    /// des classes du support : AUCUNE ligne `[sqlite]`). Chaque échec du support écrit UNE ligne `[sqlite]` avec son code étendu et sans le chemin ;
    /// le texte rendu à l'appelant est celui d'avant, à l'octet.
    ///
    /// MUTATIONS : `AY4_SANS_EXRESCODE` (drapeau retiré) -> `[SQLITE_IOERR, code étendu 10]` : ROUGE ;
    /// `AY4_CHEMIN_GARDE` (texte du refus gardé) -> le chemin entre au journal : ROUGE ; `AY4_OUVERTURE_MUETTE` (aucune
    /// ligne à l'ouverture) -> ROUGE ; `AY4_OUVERTURE_SANS_CLASSE` (ligne écrite pour toute `SqliteFailure`) -> la
    /// mémoire et le droit sont dits « erreur du support » : ROUGE.
    #[test]
    fn l_ouverture_dit_le_code_etendu_sans_le_chemin() {
        const ABSENT: &str = "ay4-repertoire-absent";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(AY4_ENFANT_OUVERTURE).is_ok() {
            let dossier = crate::tmp_possede::TmpPossede::neuf("ay4-ouverture");
            poser_le_vfs_en_panne();
            let en_panne = dossier.sous("ay4-ouverture-en-panne.db");
            let absent = dossier.sous(&format!("{ABSENT}/ay4.db"));
            let sans_memoire = dossier.sous("ay4-ouverture-sans-memoire.db");
            let sans_droit = dossier.sous("ay4-ouverture-sans-droit.db");
            for (issue, chemin) in [
                ("vfs", en_panne.as_str().to_string()),
                ("absent", absent.as_str().to_string()),
                ("nul", "ay4\0nul.db".to_string()),
                ("nomem", sans_memoire.as_str().to_string()),
                ("perm", sans_droit.as_str().to_string()),
            ] {
                let texte = crate::query_exec::read_conn_get(&chemin).err().unwrap_or_else(|| panic!("instrument : {issue} ouvert"));
                let texte = texte.replace(dossier.racine().as_str(), "<dossier>");
                println!("{AY4_RENDU}{}", json!([issue, texte]));
            }
            println!("{AY4_FIN} 5");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::ay4_code_etendu_recherche_ouverture::l_ouverture_dit_le_code_etendu_sans_le_chemin"])
            .env(AY4_ENFANT_OUVERTURE, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(&format!("{AY4_FIN} 5")), "contrôle : l'enfant a joué ses cinq ouvertures : {stdout}\n{stderr}");
        let rendus: Vec<(String, String)> = stdout
            .lines()
            .filter_map(|l| l.split_once(AY4_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : ligne de rendu lisible ({e}) : {v}")))
            .collect();
        assert_eq!(
            rendus,
            vec![
                ("vfs".to_string(), "disk I/O error".to_string()),
                ("absent".to_string(), format!("unable to open database file: <dossier>/{ABSENT}/ay4.db")),
                ("nul".to_string(), "nul byte found in provided data at position: 3".to_string()),
                // HORS LOT, constaté : sans poignée, rusqlite rend le CHEMIN comme texte (cf. l'en-tête).
                ("nomem".to_string(), "<dossier>/ay4-ouverture-sans-memoire.db".to_string()),
                ("perm".to_string(), "access permission denied".to_string()),
            ],
            "le texte rendu à l'appelant est celui d'avant, à l'octet"
        );
        let journal: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[sqlite] ")).collect();
        assert_eq!(
            journal,
            vec![
                "[sqlite] erreur du support de la base : Error code 5386: I/O error within the xShmMap method (trying to map a shared-memory segment into process address space) [SQLITE_IOERR_SHMMAP, code étendu 5386]",
                "[sqlite] erreur du support de la base : Error code 14: Unable to open the database file [code étendu 14]",
            ],
            "une ligne par échec d'ouverture du support, avec son code étendu ; rien pour l'erreur sans code, ni pour la mémoire ou le droit : {stderr}"
        );
        assert!(!stderr.contains(ABSENT), "le chemin de la base n'entre pas au journal : {stderr}");
    }
}
