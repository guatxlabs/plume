// =====================================================================================
// TROIS SECRETS ÉCRITS PAR LE DÉMARRAGE NAISSENT EN 0600, SYNCHRONISÉS, ET UNE ÉCRITURE REFUSÉE EST DITE.
//
// VU (re-mesuré sur 53488460) : la clé de signature du registre (`ledger.rs`, `ledger_key_load`, branche legacy
// `allow_generate`), la clé qui signe les cookies (`session.rs`, `load_session_secret`) et le jeton qui ouvre le compte
// administrateur (`server/mod.rs`, `installation_au_demarrage`, `setup-token.txt`) étaient écrits par
// `let _ = std::fs::write(…)` (droits de l'umask, 0644 sous umask 022) puis `let _ = set_permissions(0o600)`. Fenêtre où
// le fichier est lisible par autrui ; écriture refusée avalée (une clé du registre non persistée signait quand même,
// clé divergente au démarrage suivant) ; aucun `sync_all` (une coupure laissait un fichier vide, refusé pour toujours).
//
// LES TÉMOINS visent les trois fonctions que le démarrage appelle. La fenêtre est rendue OBSERVABLE sans course : un
// enfant (le binaire de test relancé) pose umask 022, `RLIMIT_CORE` 0, `RLIMIT_FSIZE` 0 et `SIGXFSZ` par défaut, de sorte
// que le noyau le TUE à la première écriture dans le fichier, juste après sa création. Les droits relus ensuite sont
// ceux que le fichier avait pendant toute la fenêtre : 0600 si le mode est posé à la création, 0644 sous l'ancien geste
// (écrire puis changer les droits). Même enfant avec `SIGXFSZ` ignoré : l'écriture rend EFBIG, comme un disque plein.
// L'écriture refusée par une entrée devenue RÉPERTOIRE ne dépend pas de root. Les lignes dites se lisent sur le stderr
// de l'enfant, ligne entière.
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit), chacun vu ROUGE : AT3_POSE_MODE_644, AT3_POSE_INACHEVE_GARDE,
// AT3_LEDGER_ECRIRE_PUIS_CHMOD, AT3_LEDGER_CLE_NON_ECRITE_RENDUE, AT3_LEDGER_REFUS_MUET, AT3_SESSION_VIDE_GARDE,
// AT3_SESSION_ECRASE, AT3_SESSION_ECRIRE_PUIS_CHMOD, AT3_SESSION_REFUS_MUET, AT3_JETON_TEMPORAIRE_PERIME_GARDE,
// AT3_JETON_TEMPORAIRE_REFUS_TU, AT3_JETON_TEMPORAIRE_LAISSE, AT3_JETON_ECRIRE_PUIS_CHMOD, AT3_JETON_LIGNE_MUETTE,
// AT3_FERMEE_TEMPORAIRE_GARDE.
//
// CORRECTION APRÈS VÉRIFICATION. La clé de session gardée en mémoire est jugée DISTINCTE d'un démarrage à l'autre et
// jamais nulle ; une entrée non UTF-8 (illisible sans être un répertoire) n'est écrasée ni pour le registre ni pour la
// session ; le jeton remplace l'ancien `setup-token.txt` par un NOUVEL inode. Côté session, un contenu LU qui n'est pas
// une clé (« \n » seul, clé tronquée, « pas-une-cle ») est de nouveau REMPLACÉ, comme sur 53488460, mais par un
// temporaire 0600 renommé dessus, et c'est dit. Mutants joués, chacun vu ROUGE : AT3C_SESSION_CLE_CONSTANTE,
// AT3C_LEDGER_ILLISIBLE_ECRASE, AT3C_SESSION_ILLISIBLE_ECRASE, AT3C_REMPLACER_EN_PLACE, AT3C_SESSION_INVALIDE_GARDE,
// AT3C_SESSION_TRONQUEE_GARDE, AT3C_SESSION_FS_WRITE, AT3C_SESSION_REMPLACEE_MUETTE, AT3C_SESSION_REMPLACEMENT_MUET.
//
// INVERSÉ (vague AU) : les deux lignes « gardée EN MÉMOIRE » nomment désormais la voie du fichier monté en lecture seule
// au lieu de la variable ; témoins de la provenance dans cle_de_session_montee_et_provenance_dite.rs.
// =====================================================================================

mod secrets_poses_en_0600_des_la_creation {
    use super::*;
    use crate::server::installation_au_demarrage;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// La variable qui fait d'un témoin l'enfant qu'il relance : `<cas>|<répertoire>`.
    const ENFANT: &str = "AT3_ENFANT";
    /// Ce que l'enfant imprime de son issue sur stdout.
    const MARQUE: &str = "AT3-ISSUE:";
    /// Le chemin du module des témoins, pour relancer un témoin par son nom exact.
    const MODULE: &str = "tests::secrets_poses_en_0600_des_la_creation::";
    /// Le temporaire du jeton d'installation, écrit ici en littéral (le témoin ne relit pas la production).
    const TEMPORAIRE_DU_JETON: &str = "setup-token.txt.en-cours";
    /// Le temporaire de la clé de session, en littéral pour la même raison.
    const TEMPORAIRE_DE_SESSION: &str = "session.key.en-cours";
    /// Des octets qu'aucune lecture UTF-8 n'accepte : l'entrée est un fichier, mais illisible comme texte.
    const NON_UTF8: [u8; 4] = [0xff, 0xfe, 0x00, 0x80];
    const JETON: &str = "setup-token.txt";
    /// Le haché de fixture de l'administrateur de l'assistant (la fonction jugée le recharge sans le vérifier).
    const HACHE_DE_FIXTURE: &str = "hache-de-fixture-at3";

    /// Dans l'enfant : le répertoire du cas `cas`, sinon `None` (on est le parent).
    fn repertoire_de_l_enfant(cas: &str) -> Option<String> {
        let v = std::env::var(ENFANT).ok()?;
        let (c, dir) = v.split_once('|')?;
        (c == cas).then(|| dir.to_string())
    }

    /// Dans l'enfant : umask 022, aucun fichier de vidage, et la taille de fichier bornée à 0. `tuer` : `SIGXFSZ` par
    /// défaut (le noyau tue à la première écriture), sinon ignoré (l'écriture rend EFBIG).
    fn borner_l_enfant(tuer: bool) {
        // SAFETY: appels système sans pointeur conservé ; l'enfant ne joue que ce témoin, sur un seul fil.
        unsafe {
            libc::umask(0o022);
            let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            assert_eq!(libc::getrlimit(libc::RLIMIT_CORE, &mut lim), 0);
            assert_eq!(libc::setrlimit(libc::RLIMIT_CORE, &libc::rlimit { rlim_cur: 0, rlim_max: lim.rlim_max }), 0);
            libc::signal(libc::SIGXFSZ, if tuer { libc::SIG_DFL } else { libc::SIG_IGN });
            assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut lim), 0);
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &libc::rlimit { rlim_cur: 0, rlim_max: lim.rlim_max }), 0);
        }
    }

    /// Les entrées d'un répertoire, triées : (nom, droits, est un répertoire, taille). Droits et taille d'un répertoire
    /// valent 0 (ses droits viennent de l'umask du processus de test, que le témoin ne fixe pas).
    fn entrees(dir: &std::path::Path) -> Vec<(String, u32, bool, u64)> {
        let mut v: Vec<_> = std::fs::read_dir(dir)
            .expect("lecture du répertoire du témoin")
            .map(|e| {
                let e = e.expect("entrée");
                let m = std::fs::symlink_metadata(e.path()).expect("stat");
                let (droits, taille) = if m.is_dir() { (0, 0) } else { (m.permissions().mode() & 0o777, m.len()) };
                (e.file_name().to_string_lossy().into_owned(), droits, m.is_dir(), taille)
            })
            .collect();
        v.sort();
        v
    }

    fn issues(sortie: &std::process::Output) -> Vec<String> {
        String::from_utf8_lossy(&sortie.stdout).lines().filter_map(|l| l.split_once(MARQUE).map(|(_, v)| v.to_string())).collect()
    }

    fn lignes(sortie: &std::process::Output, prefixe: &str) -> Vec<String> {
        String::from_utf8_lossy(&sortie.stderr).lines().filter(|l| l.starts_with(prefixe)).map(str::to_string).collect()
    }

    fn tout(sortie: &std::process::Output) -> String {
        format!("stdout : {}\nstderr : {}", String::from_utf8_lossy(&sortie.stdout), String::from_utf8_lossy(&sortie.stderr))
    }

    /// L'enfant est mort de la borne de taille, à l'écriture, sans avoir rendu d'issue.
    fn tue_a_l_ecriture(sortie: &std::process::Output) {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(sortie.status.signal(), Some(libc::SIGXFSZ), "contrôle : l'enfant meurt de SIGXFSZ à l'écriture ; {}", tout(sortie));
        assert!(issues(sortie).is_empty(), "contrôle : l'enfant n'a rien rendu ; {}", tout(sortie));
    }

    /// L'enfant a joué jusqu'au bout et sort en 0.
    fn joue_jusqu_au_bout(sortie: &std::process::Output) {
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 ; {}", tout(sortie));
    }

    fn conf_de_session(chemin: &str) -> std::collections::HashMap<String, String> {
        std::collections::HashMap::from([("PLUME_SESSION_KEY".to_string(), chemin.to_string())])
    }

    /// Instrument : le témoin d'une clé de session ne conclut rien si l'environnement en pose une.
    fn environnement_sans_cle_de_session() {
        assert!(std::env::var("PLUME_SESSION_SECRET").is_err() && std::env::var("PLUME_SESSION_KEY").is_err()
            && std::env::var("PLUME_SESSION_SECRET_FILE").is_err() && std::env::var("PLUME_SESSION_SECRET_REF").is_err(),
            "instrument : l'environnement pose une clé de session, ce témoin REFUSE DE CONCLURE");
    }

    // ---------------------------------------------------------------- la fenêtre de création (enfant tué)

    /// Registre : tué à l'écriture, la clé engendrée existe déjà, vide, en 0600 — jamais 0644.
    #[test]
    fn at3_cle_du_registre_tuee_a_l_ecriture_est_deja_en_0600() {
        if let Some(dir) = repertoire_de_l_enfant("registre-tue") {
            borner_l_enfant(true);
            let k = ledger_key_load(&format!("{dir}/ledger.key"), true);
            println!("{MARQUE}{}", k.is_some());
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-registre-tue");
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}at3_cle_du_registre_tuee_a_l_ecriture_est_deja_en_0600")])
            .env(ENFANT, format!("registre-tue|{tmp}"))
            .output()
            .expect("relance du binaire de test");
        tue_a_l_ecriture(&sortie);
        assert_eq!(entrees(&tmp), vec![("ledger.key".to_string(), 0o600, false, 0)], "{}", tout(&sortie));
    }

    /// Session : même fenêtre, même verdict.
    #[test]
    fn at3_cle_de_session_tuee_a_l_ecriture_est_deja_en_0600() {
        if let Some(dir) = repertoire_de_l_enfant("session-tue") {
            borner_l_enfant(true);
            let k = load_session_secret(&conf_de_session(&format!("{dir}/session.key")));
            println!("{MARQUE}{}", k.len());
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-session-tue");
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}at3_cle_de_session_tuee_a_l_ecriture_est_deja_en_0600")])
            .env(ENFANT, format!("session-tue|{tmp}"))
            .env_remove("PLUME_SESSION_SECRET")
            .env_remove("PLUME_SESSION_KEY")
            .env_remove("PLUME_SESSION_SECRET_FILE")
            .env_remove("PLUME_SESSION_SECRET_REF")
            .output()
            .expect("relance du binaire de test");
        tue_a_l_ecriture(&sortie);
        assert_eq!(entrees(&tmp), vec![("session.key".to_string(), 0o600, false, 0)], "{}", tout(&sortie));
    }

    /// Jeton : tué à l'écriture, seul le temporaire existe, en 0600 ; `setup-token.txt` n'a jamais existé lisible.
    #[test]
    fn at3_jeton_tue_a_l_ecriture_n_existe_qu_en_0600() {
        if let Some(dir) = repertoire_de_l_enfant("jeton-tue") {
            let c = test_db();
            borner_l_enfant(true);
            let issue = installation_au_demarrage(&c, &format!("{dir}/plume.db"), false);
            println!("{MARQUE}{}", issue.is_ok());
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-jeton-tue");
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}at3_jeton_tue_a_l_ecriture_n_existe_qu_en_0600")])
            .env(ENFANT, format!("jeton-tue|{tmp}"))
            .output()
            .expect("relance du binaire de test");
        tue_a_l_ecriture(&sortie);
        assert_eq!(entrees(&tmp), vec![(TEMPORAIRE_DU_JETON.to_string(), 0o600, false, 0)], "{}", tout(&sortie));
    }

    // ---------------------------------------------------------------- registre : écriture refusée

    /// Disque plein (EFBIG) : le fichier créé puis inachevé est RETIRÉ, la clé n'est PAS utilisée, et c'est dit.
    #[test]
    fn at3_cle_du_registre_non_ecrite_disque_plein_n_est_pas_utilisee() {
        if let Some(dir) = repertoire_de_l_enfant("registre-plein") {
            borner_l_enfant(false);
            let k = ledger_key_load(&format!("{dir}/ledger.key"), true);
            println!("{MARQUE}{}", k.is_some());
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-registre-plein");
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}at3_cle_du_registre_non_ecrite_disque_plein_n_est_pas_utilisee")])
            .env(ENFANT, format!("registre-plein|{tmp}"))
            .output()
            .expect("relance du binaire de test");
        joue_jusqu_au_bout(&sortie);
        let p = format!("{tmp}/ledger.key");
        assert_eq!(issues(&sortie), vec!["false"], "aucune clé rendue ; {}", tout(&sortie));
        assert_eq!(entrees(&tmp), Vec::<(String, u32, bool, u64)>::new(), "le fichier inachevé est retiré ; {}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[ledger]"), vec![format!(
            "[ledger] clé NON écrite à '{p}' (écriture de {p} : File too large (os error 27) ; le fichier inachevé a été \
             retiré) : la clé engendrée N'EST PAS utilisée — le démarrage suivant ne la relirait pas et les checkpoints \
             qu'elle aurait signés seraient invérifiables. Checkpoints NON signés jusqu'à ce que cet emplacement accepte la clé."
        )], "{}", tout(&sortie));
    }

    /// L'entrée est un répertoire : création refusée, clé non utilisée, dit ; le répertoire est intact.
    #[test]
    fn at3_cle_du_registre_sur_un_repertoire_n_est_pas_utilisee() {
        if let Some(dir) = repertoire_de_l_enfant("registre-repertoire") {
            let k = ledger_key_load(&format!("{dir}/ledger.key"), true);
            println!("{MARQUE}{}", k.is_some());
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-registre-repertoire");
        let p = format!("{tmp}/ledger.key");
        std::fs::create_dir(&p).expect("fixture : l'entrée est un répertoire");
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}at3_cle_du_registre_sur_un_repertoire_n_est_pas_utilisee")])
            .env(ENFANT, format!("registre-repertoire|{tmp}"))
            .output()
            .expect("relance du binaire de test");
        joue_jusqu_au_bout(&sortie);
        assert_eq!(issues(&sortie), vec!["false"], "aucune clé rendue ; {}", tout(&sortie));
        assert_eq!(entrees(&tmp), vec![("ledger.key".to_string(), 0, true, 0)], "{}", tout(&sortie));
        assert!(std::fs::read_dir(&p).expect("répertoire").next().is_none(), "le répertoire reste vide");
        assert_eq!(lignes(&sortie, "[ledger]"), vec![format!(
            "[ledger] clé NON écrite à '{p}' (création de {p} impossible (File exists (os error 17))) : la clé engendrée \
             N'EST PAS utilisée — le démarrage suivant ne la relirait pas et les checkpoints qu'elle aurait signés seraient \
             invérifiables. Checkpoints NON signés jusqu'à ce que cet emplacement accepte la clé."
        )], "{}", tout(&sortie));
    }

    // ---------------------------------------------------------------- registre : chemins inchangés et nominal

    /// Nominal : clé engendrée, posée en 0600, relue identique ; un fichier VIDE ou non vide invalide n'est jamais
    /// réécrit (fail-closed inchangé).
    #[test]
    fn at3_cle_du_registre_posee_relue_et_jamais_reecrite() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-registre-nominal");
        let p = format!("{tmp}/ledger.key");
        let k = ledger_key_load(&p, true).expect("chemin legacy absent : clé engendrée");
        assert_eq!(std::fs::metadata(&p).expect("stat").permissions().mode() & 0o777, 0o600, "clé en 0600");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), hex_encode(k.to_bytes().as_slice()), "le fichier porte la clé rendue");
        let relue = ledger_key_load(&p, true).expect("relecture");
        assert_eq!(relue.to_bytes(), k.to_bytes(), "relue identique");

        let vide = format!("{tmp}/ledger-vide.key");
        std::fs::write(&vide, "").unwrap();
        assert!(ledger_key_load(&vide, true).is_none(), "fichier vide : fail-closed");
        assert_eq!(std::fs::read_to_string(&vide).unwrap(), "", "fichier vide jamais réécrit");
        let invalide = format!("{tmp}/ledger-invalide.key");
        std::fs::write(&invalide, "pas-une-cle").unwrap();
        assert!(ledger_key_load(&invalide, true).is_none(), "fichier invalide : fail-closed");
        assert_eq!(std::fs::read_to_string(&invalide).unwrap(), "pas-une-cle", "fichier invalide jamais réécrit");
    }

    // ---------------------------------------------------------------- session

    /// Nominal : clé engendrée, posée en 0600, relue identique au démarrage suivant.
    #[test]
    fn at3_cle_de_session_posee_en_0600_et_relue() {
        let _env = VERROU_ENV_PROCESSUS.read();
        environnement_sans_cle_de_session();
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-session-nominal");
        let p = format!("{tmp}/session.key");
        let k = load_session_secret(&conf_de_session(&p));
        assert_eq!(k.len(), 32);
        assert_eq!(std::fs::metadata(&p).expect("stat").permissions().mode() & 0o777, 0o600, "clé en 0600");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), hex_encode(&k), "le fichier porte la clé rendue");
        assert_eq!(load_session_secret(&conf_de_session(&p)), k, "relue identique");
    }

    /// Fichier VIDE : remplacé par une clé neuve en 0600, comme avant (il n'a jamais porté de clé).
    #[test]
    fn at3_cle_de_session_vide_est_remplacee() {
        let _env = VERROU_ENV_PROCESSUS.read();
        environnement_sans_cle_de_session();
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-session-vide");
        let p = format!("{tmp}/session.key");
        std::fs::write(&p, "").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let k = load_session_secret(&conf_de_session(&p));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), hex_encode(&k), "le fichier vide porte maintenant la clé rendue");
        assert_eq!(std::fs::metadata(&p).expect("stat").permissions().mode() & 0o777, 0o600, "clé en 0600");
    }

    /// Contenus LUS qui ne sont pas une clé (texte, « \n » seul, clé tronquée à 31 octets, hex de longueur impaire) :
    /// chacun est REMPLACÉ par la clé rendue, en 0600, par un NOUVEL inode (jamais réécrit en place), sans temporaire.
    #[test]
    fn at3_cle_de_session_lue_invalide_est_remplacee_par_un_nouvel_inode() {
        let _env = VERROU_ENV_PROCESSUS.read();
        environnement_sans_cle_de_session();
        let cle_de_31_octets = "ab".repeat(31);
        let hex_impair = "ab".repeat(31) + "a";
        for (i, contenu) in ["pas-une-cle", "\n", cle_de_31_octets.as_str(), hex_impair.as_str()].into_iter().enumerate() {
            let tmp = crate::tmp_possede::TmpPossede::neuf(&format!("at3-session-invalide-{i}"));
            let p = format!("{tmp}/session.key");
            std::fs::write(&p, contenu).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            let ancien = std::fs::metadata(&p).unwrap().ino();
            let k = load_session_secret(&conf_de_session(&p));
            assert_eq!(k.len(), 32, "{contenu:?} : clé de 32 octets rendue");
            assert_eq!(std::fs::read_to_string(&p).unwrap(), hex_encode(&k), "{contenu:?} : le fichier porte la clé rendue");
            assert_ne!(std::fs::metadata(&p).unwrap().ino(), ancien, "{contenu:?} : nouvel inode, pas réécrit en place");
            assert_eq!(entrees(&tmp), vec![("session.key".to_string(), 0o600, false, 64)],
                "{contenu:?} : clé en 0600, aucun temporaire");
            assert_eq!(load_session_secret(&conf_de_session(&p)), k, "{contenu:?} : relue identique au démarrage suivant");
        }
    }

    /// « \n » seul : remplacé, et c'est DIT, ligne entière.
    #[test]
    fn at3_cle_de_session_blanche_remplacee_est_dite() {
        if let Some(dir) = repertoire_de_l_enfant("session-blanche") {
            let _env = VERROU_ENV_PROCESSUS.read();
            let k = load_session_secret(&conf_de_session(&format!("{dir}/session.key")));
            println!("{MARQUE}{}", hex_encode(&k));
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-session-blanche");
        let p = format!("{tmp}/session.key");
        std::fs::write(&p, "\n").unwrap();
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}at3_cle_de_session_blanche_remplacee_est_dite")])
            .env(ENFANT, format!("session-blanche|{tmp}"))
            .env_remove("PLUME_SESSION_SECRET")
            .env_remove("PLUME_SESSION_KEY")
            .env_remove("PLUME_SESSION_SECRET_FILE")
            .env_remove("PLUME_SESSION_SECRET_REF")
            .output()
            .expect("relance du binaire de test");
        joue_jusqu_au_bout(&sortie);
        assert_eq!(issues(&sortie), vec![std::fs::read_to_string(&p).unwrap()], "le fichier porte la clé rendue ; {}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[session]"), vec![format!(
            "[session] clé de signature à '{p}' invalide (vide, hex invalide ou moins de 32 octets) : REMPLACÉE par une clé \
             neuve en 0600 — les sessions ouvertes avant ce démarrage sont perdues."
        )], "{}", tout(&sortie));
    }

    /// « \n » seul mais le temporaire résiste (répertoire) : rien n'est écrasé, clé gardée en mémoire, et c'est DIT.
    #[test]
    fn at3_cle_de_session_invalide_non_remplacee_est_gardee_en_memoire_et_dite() {
        if let Some(dir) = repertoire_de_l_enfant("session-non-remplacee") {
            let _env = VERROU_ENV_PROCESSUS.read();
            let k = load_session_secret(&conf_de_session(&format!("{dir}/session.key")));
            println!("{MARQUE}{}", k.len());
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-session-non-remplacee");
        let p = format!("{tmp}/session.key");
        std::fs::write(&p, "\n").unwrap();
        std::fs::create_dir(format!("{tmp}/{TEMPORAIRE_DE_SESSION}")).expect("fixture : le temporaire est un répertoire");
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}at3_cle_de_session_invalide_non_remplacee_est_gardee_en_memoire_et_dite")])
            .env(ENFANT, format!("session-non-remplacee|{tmp}"))
            .env_remove("PLUME_SESSION_SECRET")
            .env_remove("PLUME_SESSION_KEY")
            .env_remove("PLUME_SESSION_SECRET_FILE")
            .env_remove("PLUME_SESSION_SECRET_REF")
            .output()
            .expect("relance du binaire de test");
        joue_jusqu_au_bout(&sortie);
        assert_eq!(issues(&sortie), vec!["32"], "clé de 32 octets rendue ; {}", tout(&sortie));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "\n", "rien n'est écrasé");
        assert_eq!(lignes(&sortie, "[session]"), vec![format!(
            "[session] clé de signature à '{p}' invalide et NON remplacée (temporaire {p}.en-cours non retiré (Is a directory \
             (os error 21))) : la clé neuve est gardée EN MÉMOIRE — les sessions ouvertes ne survivront pas au prochain \
             redémarrage. Rends l'emplacement inscriptible, ou monte-la en fichier en lecture seule par PLUME_SESSION_SECRET_FILE."
        )], "{}", tout(&sortie));
    }

    /// Entrée NON UTF-8 (un fichier qu'on ne peut pas lire comme texte) : jamais écrasée, octets intacts ; la clé
    /// gardée en mémoire est engendrée à chaque démarrage — deux appels, deux clés distinctes, jamais nulles.
    #[test]
    fn at3_cle_de_session_illisible_jamais_ecrasee_et_cle_en_memoire_engendree() {
        let _env = VERROU_ENV_PROCESSUS.read();
        environnement_sans_cle_de_session();
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-session-illisible");
        let p = format!("{tmp}/session.key");
        std::fs::write(&p, NON_UTF8).unwrap();
        let a = load_session_secret(&conf_de_session(&p));
        let b = load_session_secret(&conf_de_session(&p));
        assert_eq!(std::fs::read(&p).unwrap(), NON_UTF8.to_vec(), "entrée illisible jamais écrasée");
        assert_eq!((a.len(), b.len()), (32, 32), "clés de 32 octets rendues");
        assert_ne!(a, b, "deux démarrages sans écriture : deux clés engendrées distinctes");
        assert!(a != vec![0u8; 32] && b != vec![0u8; 32], "jamais une clé nulle");
        let noms: Vec<String> = entrees(&tmp).into_iter().map(|(n, ..)| n).collect();
        assert_eq!(noms, vec!["session.key".to_string()], "aucun temporaire");
    }

    /// Registre, entrée NON UTF-8, génération autorisée : aucune clé rendue, octets intacts (53488460 l'écrasait).
    #[test]
    fn at3_cle_du_registre_illisible_jamais_ecrasee() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-registre-illisible");
        let p = format!("{tmp}/ledger.key");
        std::fs::write(&p, NON_UTF8).unwrap();
        assert!(ledger_key_load(&p, true).is_none(), "clé illisible : aucune clé rendue");
        assert_eq!(std::fs::read(&p).unwrap(), NON_UTF8.to_vec(), "entrée illisible jamais écrasée");
    }

    /// L'entrée est un répertoire : la clé est gardée en mémoire et c'est DIT, ligne entière.
    #[test]
    fn at3_cle_de_session_non_ecrite_est_gardee_en_memoire_et_dite() {
        if let Some(dir) = repertoire_de_l_enfant("session-repertoire") {
            let _env = VERROU_ENV_PROCESSUS.read();
            let k = load_session_secret(&conf_de_session(&format!("{dir}/session.key")));
            println!("{MARQUE}{}", k.len());
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-session-repertoire");
        let p = format!("{tmp}/session.key");
        std::fs::create_dir(&p).expect("fixture : l'entrée est un répertoire");
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}at3_cle_de_session_non_ecrite_est_gardee_en_memoire_et_dite")])
            .env(ENFANT, format!("session-repertoire|{tmp}"))
            .env_remove("PLUME_SESSION_SECRET")
            .env_remove("PLUME_SESSION_KEY")
            .env_remove("PLUME_SESSION_SECRET_FILE")
            .env_remove("PLUME_SESSION_SECRET_REF")
            .output()
            .expect("relance du binaire de test");
        joue_jusqu_au_bout(&sortie);
        assert_eq!(issues(&sortie), vec!["32"], "clé de 32 octets rendue ; {}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[session]"), vec![format!(
            "[session] clé de signature NON écrite (création de {p} impossible (File exists (os error 17))) : elle est \
             gardée EN MÉMOIRE — les sessions ouvertes ne survivront pas au prochain redémarrage. Une entrée présente qu'on \
             ne peut pas lire n'est jamais écrasée : retire-la ou rends l'emplacement inscriptible, ou monte-la en fichier en \
             lecture seule par PLUME_SESSION_SECRET_FILE."
        )], "{}", tout(&sortie));
    }

    // ---------------------------------------------------------------- jeton d'installation

    /// Un temporaire périmé et un ancien `setup-token.txt` aux droits larges sont remplacés : jeton publié en 0600,
    /// aucun temporaire ne reste.
    #[test]
    fn at3_jeton_publie_remplace_le_perime_et_l_ancien() {
        let c = test_db();
        let db = crate::tmp_possede::TmpDb::neuf("at3-jeton-perime");
        let dir = std::path::Path::new(db.as_str()).parent().expect("répertoire").to_path_buf();
        for nom in [JETON, TEMPORAIRE_DU_JETON] {
            std::fs::write(dir.join(nom), "ancien").unwrap();
            std::fs::set_permissions(dir.join(nom), std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let ancien = std::fs::metadata(dir.join(JETON)).unwrap().ino();
        let issue = installation_au_demarrage(&c, db.as_str(), false).expect("lisible");
        assert!(issue.ouverte && !issue.jeton.is_empty(), "installation ouverte, jeton fabriqué");
        assert_eq!(std::fs::read_to_string(dir.join(JETON)).unwrap(), issue.jeton, "le jeton neuf est publié");
        assert_ne!(std::fs::metadata(dir.join(JETON)).unwrap().ino(), ancien, "l'ancien est REMPLACÉ (nouvel inode), pas réécrit en place");
        assert_eq!(entrees(&dir), vec![(JETON.to_string(), 0o600, false, issue.jeton.len() as u64)], "seul le jeton, en 0600");
    }

    /// `setup-token.txt` est un répertoire : le rename est refusé, le temporaire retiré, et la ligne qui annonce le
    /// jeton dit qu'il n'est PAS sur le disque.
    #[test]
    fn at3_jeton_non_publie_est_dit_sur_sa_ligne() {
        if let Some(dir) = repertoire_de_l_enfant("jeton-repertoire") {
            let c = test_db();
            let issue = installation_au_demarrage(&c, &format!("{dir}/plume.db"), false).expect("lisible");
            println!("{MARQUE}{}:{}", issue.ouverte, issue.jeton.len());
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-jeton-repertoire");
        let tp = format!("{tmp}/{JETON}");
        std::fs::create_dir(&tp).expect("fixture : l'entrée est un répertoire");
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}at3_jeton_non_publie_est_dit_sur_sa_ligne")])
            .env(ENFANT, format!("jeton-repertoire|{tmp}"))
            .output()
            .expect("relance du binaire de test");
        joue_jusqu_au_bout(&sortie);
        assert_eq!(issues(&sortie), vec!["true:36"], "installation ouverte, jeton fabriqué ; {}", tout(&sortie));
        assert_eq!(entrees(&tmp), vec![(JETON.to_string(), 0, true, 0)], "aucun temporaire ne reste ; {}", tout(&sortie));
        assert_eq!(lignes(&sortie, "  ("), vec![format!(
            "  (NON écrit sur le disque : publication de {tp} impossible (Is a directory (os error 21)) ; temporaire retiré \
             — ce journal en est la seule copie)"
        )], "{}", tout(&sortie));
    }

    /// Le temporaire est un répertoire : son retrait est refusé, rien n'est écrit, et c'est dit sur la même ligne.
    #[test]
    fn at3_jeton_dont_le_temporaire_resiste_est_dit_sur_sa_ligne() {
        if let Some(dir) = repertoire_de_l_enfant("jeton-temporaire") {
            let c = test_db();
            let issue = installation_au_demarrage(&c, &format!("{dir}/plume.db"), false).expect("lisible");
            println!("{MARQUE}{}:{}", issue.ouverte, issue.jeton.len());
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-jeton-temporaire");
        let en_cours = format!("{tmp}/{TEMPORAIRE_DU_JETON}");
        std::fs::create_dir(&en_cours).expect("fixture : le temporaire est un répertoire");
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}at3_jeton_dont_le_temporaire_resiste_est_dit_sur_sa_ligne")])
            .env(ENFANT, format!("jeton-temporaire|{tmp}"))
            .output()
            .expect("relance du binaire de test");
        joue_jusqu_au_bout(&sortie);
        assert_eq!(issues(&sortie), vec!["true:36"], "{}", tout(&sortie));
        assert_eq!(entrees(&tmp), vec![(TEMPORAIRE_DU_JETON.to_string(), 0, true, 0)], "aucun jeton écrit ; {}", tout(&sortie));
        assert_eq!(lignes(&sortie, "  ("), vec![format!(
            "  (NON écrit sur le disque : temporaire {en_cours} non retiré (Is a directory (os error 21)) — ce journal en \
             est la seule copie)"
        )], "{}", tout(&sortie));
    }

    /// Installation FERMÉE : `setup-token.txt` ET son temporaire résiduels sont effacés, chacun dit.
    #[test]
    fn at3_installation_fermee_efface_aussi_le_temporaire() {
        if let Some(dir) = repertoire_de_l_enfant("fermee") {
            let c = test_db();
            c.execute("INSERT INTO user(name,hash,role) VALUES('wiz',?1,'admin')", params![HACHE_DE_FIXTURE]).expect("fixture : compte");
            c.execute("INSERT INTO meta(key,value) VALUES('admin_user','wiz') ON CONFLICT(key) DO UPDATE SET value='wiz'", [])
                .expect("fixture : meta.admin_user");
            let issue = installation_au_demarrage(&c, &format!("{dir}/plume.db"), false).expect("lisible");
            println!("{MARQUE}{}", issue.ouverte);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("at3-fermee");
        for nom in [JETON, TEMPORAIRE_DU_JETON] {
            std::fs::write(tmp.join(nom), "residu").unwrap();
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}at3_installation_fermee_efface_aussi_le_temporaire")])
            .env(ENFANT, format!("fermee|{tmp}"))
            .output()
            .expect("relance du binaire de test");
        joue_jusqu_au_bout(&sortie);
        assert_eq!(issues(&sortie), vec!["false"], "installation fermée ; {}", tout(&sortie));
        assert_eq!(entrees(&tmp), Vec::<(String, u32, bool, u64)>::new(), "les deux résidus sont effacés ; {}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[setup]"), vec![
            format!("[setup] token d'installation résiduel effacé ({tmp}/{JETON})"),
            format!("[setup] token d'installation résiduel effacé ({tmp}/{TEMPORAIRE_DU_JETON})"),
        ], "{}", tout(&sortie));
    }
}
