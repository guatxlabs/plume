// `P10.33-v` ET `P10.33-g` — UNE SOUS-COMMANDE NE CRÉE PAS LA BASE ET NE DÉLIE PAS SES COMPAGNONS
// ================================================================================================
// `P10.33-v` (clé neuve) : `plume-daemon integrity-check [--full] [<chemin>]`. Aucune sous-commande ne
// jugeait la structure SQLite de la base vivante. Le module `integrity_check` rend un verdict à trois
// sorties (0 sain, 1 corrompu, 2 aucun verdict) en lecture seule, l'état des fichiers lu par `stat`
// seul (leçon `P10.33-u` : aucun second descripteur sur la base), et choisit son ouverture sur les
// compagnons AVANT d'ouvrir : vivante si `-wal` et `-shm` existent, immuable si aucun n'existe (une
// ouverture ordinaire, même en lecture seule, créerait `-wal` et `-shm` sur une base WAL fermée
// proprement), refus si un seul existe ou si un `-journal` chaud est là.
//
// TÉMOINS (module `integrity_check_sur_base_vivante_ou_hors_ligne`) : le verdict pur sur de vrais
// fichiers (vide, saine en rapide et en complet, page écrasée, page 1 écrasée, sous clé avec le HMAC,
// clé fausse, journal chaud, WAL fermé proprement, compagnon seul) ; puis `main` en sous-processus :
// base absente (2, rien créé), page écrasée par chemin explicite (1), base WAL tenue par la porte
// (0, la porte relit sa ligne, le verdict voit les pages du WAL), WAL laissé par un écrivain mort
// (0, `-wal`/`-shm` toujours là : c'est CE témoin qui tient « ne délie rien »), base chiffrée sous la
// clé du démon (0, clé appliquée, HMAC contrôlé), drapeau inconnu avant le chemin et second chemin
// (exactement 2, aucune ligne JSON, la base de la configuration n'est pas jugée). Enfin : page libre
// abîmée sous clé (structure « ok », HMAC en défaut, 1), base occupée par un écrivain WAL exclusif
// (2, « base occupée »), et un nom qui porte `#`, `?` ou `%` (le fichier nommé est jugé, pas le
// chemin tronqué ou décodé où vit une base saine). L'enfant reçoit les arguments de la sous-commande
// par `P1033V_ARGUMENTS_DE_L_ENFANT` (`cfg(test)` seul) : libtest refuserait `-full` en argument.
//
// MUTANTS JOUÉS (par variable d'environnement, retirés avant le commit) : ic_full_ignore, ic_vide_ok,
// ic_full_rapide, ic_lignes_ignorees, ic_corrompu_en_refus, ic_corrompu_en_refus_4, ic_cle_ignoree, ic_sans_cipher,
// ic_notadb_corrompu, ic_journal_ignore, ic_jamais_immuable, ic_compagnon_seul_ouvert,
// ic_absente_sans_garde, ic_toujours_immuable, ic_lecture_ecriture, ic_main_sans_cle, ic_hmac_ignore,
// ic_busy_corrompu, ic_drapeau_ignore, ic_args_err0, ic_u_diese, ic_u_question, ic_u_pourcent ; pour `P10.33-g` : g_retention, g_fts, g_sigma (la sous-commande ouvre la base par la porte AVANT sa garde).
//
// CE QUE CE FICHIER NE TIENT PAS : `-shm` sans droit d'écriture ; la sortie 78 d'integrity-check
// (fichier de clé illisible : la couche pure `db_key_from_file` a ses témoins dans `sec.rs`, le
// `exit(78)` lui-même n'est pas joué sous cette sous-commande) ; la course entre le `stat` et
// l'ouverture vivante ; un écrivain en mode journal de retour arrière qui écrirait pendant une
// ouverture immuable. Pour `P10.33-g` : `purge`, le signal après sauvegarde et `restore-drill record`
// restent tenus par le balayage de source seul ; la propriété root d'un fichier créé sous `sudo`
// n'est pas testable sans root.
mod integrity_check_sur_base_vivante_ou_hors_ligne {
    use super::*;
    use crate::integrity_check::{analyser_les_arguments, verifier, Arguments, Mode, CODE_CORROMPU, CODE_REFUS, CODE_SAIN};

    const IC_ENFANT: &str = "P1033V_ENFANT_MAIN";
    const IC_MARQUE_ENFANT: &str = "P1033V-ENFANT-APPELLE-MAIN";
    const IC_ECRIVAIN: &str = "P1033V_ENFANT_ECRIVAIN";
    /// Lue par `integrity_check::arguments_a_analyser` sous `cfg(test)` seulement.
    const IC_ARGUMENTS: &str = "P1033V_ARGUMENTS_DE_L_ENFANT";
    const CLE_DU_TEMOIN: &str = "temoin-p1033v";
    const AUTRE_CLE: &str = "autre-p1033v";

    fn existe(p: &str) -> bool {
        std::path::Path::new(p).exists()
    }

    /// Une table de soixante lignes d'un kilo-octet : une quinzaine de pages feuilles sous une racine
    /// intérieure (page 2), aucune page libre.
    fn remplir(c: &rusqlite::Connection) {
        c.execute_batch(
            "CREATE TABLE ic_t(x BLOB); \
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<60) \
             INSERT INTO ic_t SELECT randomblob(1000) FROM n;",
        )
        .expect("fixture : remplissage");
    }

    /// Base en mode journal par défaut (DELETE), fermée : aucun compagnon. Rend la taille de page.
    fn base_saine(chemin: &str, cle: Option<&str>) -> usize {
        let c = rusqlite::Connection::open(chemin).expect("fixture : ouverture");
        crate::db_open::appliquer_une_cle_explicite(&c, cle).expect("fixture : clé");
        remplir(&c);
        let ps: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0)).expect("fixture : page_size");
        ps as usize
    }

    /// Base en mode WAL fermée proprement : la dernière connexion a fait son checkpoint et délié
    /// `-wal` et `-shm`, l'en-tête dit toujours WAL.
    fn base_wal_fermee(chemin: &str) {
        let c = rusqlite::Connection::open(chemin).expect("fixture : ouverture");
        let mode: String = c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).expect("fixture : WAL");
        assert_eq!(mode, "wal", "fixture : la base passe en WAL");
        remplir(&c);
        drop(c);
        assert!(!existe(&format!("{chemin}-wal")) && !existe(&format!("{chemin}-shm")), "fixture : WAL fermé proprement, sans compagnon");
    }

    /// Remplit d'octets 0xFF la plage `[debut, fin)` du fichier (aucune connexion ouverte dessus).
    fn ecraser(chemin: &str, debut: usize, fin: usize) {
        let mut octets = std::fs::read(chemin).expect("fixture : lecture");
        assert!(fin <= octets.len(), "fixture : la plage existe ({fin} > {})", octets.len());
        for o in &mut octets[debut..fin] {
            *o = 0xFF;
        }
        std::fs::write(chemin, &octets).expect("fixture : écriture");
    }

    /// L'`argv` que l'enfant analyse, en tableau JSON : `plume-daemon integrity-check <suite>`.
    fn argv_de_l_enfant(suite: &[&str]) -> String {
        let mut v = vec!["plume-daemon", "integrity-check"];
        v.extend_from_slice(suite);
        serde_json::to_string(&v).expect("tableau JSON")
    }

    fn cause(v: &crate::integrity_check::Verdict) -> String {
        v.rapport["cause"].as_str().unwrap_or("").to_string()
    }

    /// La ligne JSON de l'enfant (stdout porte aussi l'en-tête de libtest).
    fn rapport_de(sortie: &std::process::Output) -> serde_json::Value {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stderr.contains(IC_MARQUE_ENFANT), "contrôle : l'enfant a atteint `main` : {stdout}\n{stderr}");
        // libtest écrit « test <nom> ... » sans fin de ligne avant la sortie du test : l'objet suit sur la même ligne.
        let ligne = stdout
            .lines()
            .find_map(|l| l.find("{\"").map(|i| &l[i..]))
            .unwrap_or_else(|| panic!("aucune ligne JSON sur stdout : {stdout}\n{stderr}"));
        serde_json::from_str(ligne).unwrap_or_else(|e| panic!("JSON illisible ({e}) : {ligne}"))
    }

    // ── LE VERDICT PUR ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn p10_33v_les_arguments_full_et_chemin_dans_les_deux_ordres() {
        let a = |v: &[&str]| analyser_les_arguments(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(a(&["d", "integrity-check"]).unwrap(), Arguments { mode: Mode::Rapide, chemin: None });
        assert_eq!(a(&["d", "integrity-check", "--full"]).unwrap(), Arguments { mode: Mode::Complet, chemin: None });
        let complet = Arguments { mode: Mode::Complet, chemin: Some("/b.db".into()) };
        assert_eq!(a(&["d", "integrity-check", "--full", "/b.db"]).unwrap(), complet);
        assert_eq!(a(&["d", "integrity-check", "/b.db", "--full"]).unwrap(), complet);
        for inconnu in [&["-full", "/b.db"][..], &["/b.db", "--exact"], &["--ful"], &["--help"]] {
            let mut v = vec!["d", "integrity-check"];
            v.extend_from_slice(inconnu);
            let e = a(&v).expect_err("un drapeau inconnu est refusé, jamais ignoré");
            assert!(e.contains("drapeau inconnu"), "{e}");
        }
        assert!(a(&["d", "integrity-check", "/a.db", "/b.db"]).is_err(), "un second chemin est une erreur, pas un argument ignoré");
    }

    #[test]
    fn p10_33v_fichier_vide_refus_de_conclure() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-vide");
        let base = _tmp.sous("vide.db").chemin().to_string_lossy().into_owned();
        std::fs::write(&base, b"").unwrap();
        let v = verifier(&base, Mode::Rapide, None);
        assert_eq!(v.code, CODE_REFUS, "fichier vide : quick_check y rendrait « ok », le verdict est un refus : {}", v.rapport);
        assert!(cause(&v).contains("fichier vide"), "{}", v.rapport);
        assert!(!existe(&format!("{base}-wal")) && !existe(&format!("{base}-shm")));
    }

    #[test]
    fn p10_33v_base_saine_rend_0_en_rapide_et_en_complet_sans_rien_creer() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-saine");
        let base = _tmp.sous("saine.db").chemin().to_string_lossy().into_owned();
        base_saine(&base, None);
        let v = verifier(&base, Mode::Rapide, None);
        assert_eq!(v.code, CODE_SAIN, "{}", v.rapport);
        assert_eq!(v.rapport["verdict"], "sain");
        assert_eq!(v.rapport["pragma"], "quick_check");
        assert_eq!(v.rapport["lignes"], serde_json::json!(["ok"]));
        assert_eq!(v.rapport["ouverture"], "immuable", "aucun compagnon : ouverture immuable");
        assert_eq!(v.rapport["cle_appliquee"], false);
        assert!(v.rapport["cipher_integrity_check"].is_null(), "sans clé, aucun contrôle du HMAC n'est annoncé");
        let v = verifier(&base, Mode::Complet, None);
        assert_eq!(v.code, CODE_SAIN, "{}", v.rapport);
        assert_eq!(v.rapport["pragma"], "integrity_check", "--full joue integrity_check");
        for suffixe in ["-wal", "-shm", "-journal"] {
            assert!(!existe(&format!("{base}{suffixe}")), "aucun {suffixe} créé");
        }
    }

    #[test]
    fn p10_33v_page_ecrasee_rend_1_avec_les_lignes_du_moteur() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-page");
        let base = _tmp.sous("corrompue.db").chemin().to_string_lossy().into_owned();
        let ps = base_saine(&base, None);
        let pages = std::fs::metadata(&base).unwrap().len() as usize / ps;
        assert!(pages >= 10, "fixture : la table occupe des pages feuilles ({pages} pages)");
        ecraser(&base, 5 * ps, 6 * ps); // page 6, une feuille de `ic_t`
        for mode in [Mode::Rapide, Mode::Complet] {
            let v = verifier(&base, mode, None);
            assert_eq!(v.code, CODE_CORROMPU, "{mode:?} : {}", v.rapport);
            assert_eq!(v.rapport["verdict"], "corrompu");
            let lignes = v.rapport["lignes"].as_array().cloned().unwrap_or_default();
            assert!(!lignes.is_empty() && lignes != vec![serde_json::json!("ok")], "les défauts du moteur sont rendus : {}", v.rapport);
        }
    }

    /// Un défaut que seul le contrôle de structure voit (aucune lecture de table ne le rencontre) : le
    /// compte de pages libres de l'en-tête (octets 36..40) falsifié sur une base sans page libre. Le
    /// moteur rend une ligne de défaut et aucune erreur : le verdict « corrompu » vient des LIGNES.
    #[test]
    fn p10_33v_compte_de_pages_libres_falsifie_rend_1_par_les_lignes() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-freelist");
        let base = _tmp.sous("freelist.db").chemin().to_string_lossy().into_owned();
        base_saine(&base, None);
        let mut octets = std::fs::read(&base).unwrap();
        assert_eq!(&octets[32..40], &[0u8; 8], "fixture : aucune page libre");
        octets[36..40].copy_from_slice(&5u32.to_be_bytes());
        std::fs::write(&base, &octets).unwrap();
        for mode in [Mode::Rapide, Mode::Complet] {
            let v = verifier(&base, mode, None);
            assert_eq!(v.code, CODE_CORROMPU, "{mode:?} : {}", v.rapport);
            assert!(cause(&v).contains("rend des défauts"), "le verdict vient des lignes, pas d'une erreur : {}", v.rapport);
            let lignes = v.rapport["lignes"].as_array().cloned().unwrap_or_default();
            assert!(!lignes.is_empty() && lignes != vec![serde_json::json!("ok")], "{}", v.rapport);
        }
    }

    #[test]
    fn p10_33v_page_1_ecrasee_sqlite_corrupt_rend_1() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-page1");
        let base = _tmp.sous("schema.db").chemin().to_string_lossy().into_owned();
        let ps = base_saine(&base, None);
        ecraser(&base, 100, ps); // l'en-tête de fichier intact, l'arbre de `sqlite_master` abîmé
        let v = verifier(&base, Mode::Rapide, None);
        assert_eq!(v.code, CODE_CORROMPU, "SQLITE_CORRUPT à la lecture du schéma est un fait : {}", v.rapport);
        assert!(cause(&v).contains("SQLITE_CORRUPT"), "{}", v.rapport);
    }

    #[test]
    fn p10_33v_sous_cle_le_hmac_est_controle_et_une_cle_fausse_refuse() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-cle");
        let base = _tmp.sous("chiffree.db").chemin().to_string_lossy().into_owned();
        base_saine(&base, Some(CLE_DU_TEMOIN));
        let tete = std::fs::read(&base).unwrap();
        assert_ne!(&tete[..16], b"SQLite format 3\0", "fixture : la base est chiffrée");
        let v = verifier(&base, Mode::Rapide, Some(CLE_DU_TEMOIN));
        assert_eq!(v.code, CODE_SAIN, "{}", v.rapport);
        assert_eq!(v.rapport["cle_appliquee"], true);
        assert_eq!(v.rapport["cipher_integrity_check"], serde_json::json!([]), "le HMAC de chaque page est contrôlé, aucun défaut : {}", v.rapport);
        for cle in [Some(AUTRE_CLE), None] {
            let v = verifier(&base, Mode::Rapide, cle);
            assert_eq!(v.code, CODE_REFUS, "clé {cle:?} : aucun verdict, jamais « corrompu » : {}", v.rapport);
            assert!(cause(&v).contains("clé fausse ou en-tête illisible"), "{}", v.rapport);
        }
    }

    #[test]
    fn p10_33v_journal_chaud_refuse_sans_ouvrir() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-journal");
        let base = _tmp.sous("journal.db").chemin().to_string_lossy().into_owned();
        base_saine(&base, None);
        std::fs::write(format!("{base}-journal"), [0u8; 512]).unwrap();
        let v = verifier(&base, Mode::Rapide, None);
        assert_eq!(v.code, CODE_REFUS, "{}", v.rapport);
        assert!(cause(&v).contains("-journal non vide"), "{}", v.rapport);
    }

    #[test]
    fn p10_33v_base_wal_fermee_proprement_ouverte_immuable_sans_creer_wal_ni_shm() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-walferme");
        let base = _tmp.sous("wal.db").chemin().to_string_lossy().into_owned();
        base_wal_fermee(&base);
        let v = verifier(&base, Mode::Rapide, None);
        assert!(!existe(&format!("{base}-wal")), "integrity-check a CRÉÉ un -wal à côté d'une base fermée : {}", v.rapport);
        assert!(!existe(&format!("{base}-shm")), "integrity-check a CRÉÉ un -shm à côté d'une base fermée : {}", v.rapport);
        assert_eq!(v.code, CODE_SAIN, "{}", v.rapport);
        assert_eq!(v.rapport["ouverture"], "immuable");
    }

    #[test]
    fn p10_33v_un_compagnon_seul_refuse_et_l_autre_n_est_pas_cree() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-compagnon");
        let base = _tmp.sous("wal.db").chemin().to_string_lossy().into_owned();
        base_wal_fermee(&base);
        let (wal, shm) = (format!("{base}-wal"), format!("{base}-shm"));
        std::fs::write(&wal, b"").unwrap();
        let v = verifier(&base, Mode::Rapide, None);
        assert_eq!(v.code, CODE_REFUS, "{}", v.rapport);
        assert!(cause(&v).contains("-wal présent sans -shm"), "{}", v.rapport);
        assert!(!existe(&shm), "le -shm manquant n'est pas créé");
        std::fs::remove_file(&wal).unwrap();
        std::fs::write(&shm, b"").unwrap();
        let v = verifier(&base, Mode::Rapide, None);
        assert_eq!(v.code, CODE_REFUS, "{}", v.rapport);
        assert!(cause(&v).contains("-shm présent sans -wal"), "{}", v.rapport);
        assert!(!existe(&wal), "le -wal manquant n'est pas créé");
    }

    // ── LE POINT D'ENTRÉE : `main` EN SOUS-PROCESSUS ────────────────────────────────────────────
    // Les arguments libres de l'enfant (`integrity-check`, le chemin) sont aussi des filtres de libtest :
    // avec `--exact`, seul le test nommé joue. Les clés ambiantes sont retirées de l'environnement de
    // l'enfant : les bases du témoin sont en clair.

    #[test]
    fn p10_33v_integrity_check_sur_base_absente_sort_2_et_ne_cree_rien() {
        if std::env::var_os(IC_ENFANT).is_some() {
            eprintln!("{IC_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-absente");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("absente.db").to_string_lossy().into_owned();
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "integrity-check",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::integrity_check_sur_base_vivante_ou_hors_ligne::p10_33v_integrity_check_sur_base_absente_sort_2_et_ne_cree_rien",
            ])
            .env(IC_ENFANT, "1")
            .env(IC_ARGUMENTS, argv_de_l_enfant(&[]))
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .env_remove("PLUME_DB_KEY")
            .env_remove("PLUME_DB_KEY_FILE")
            .env_remove(crate::crypto::CLE_DB_KEY_AUTO_PATH)
            .output()
            .expect("ré-exécution du binaire de test");
        let r = rapport_de(&sortie);
        assert_eq!(sortie.status.code(), Some(CODE_REFUS), "base absente : aucun verdict : {r}");
        assert_eq!(r["verdict"], "refus");
        assert_eq!(r["base"], serde_json::json!(base), "la base de la configuration est celle jugée");
        assert!(r["cause"].as_str().unwrap_or("").contains("base absente"), "{r}");
        let restes: Vec<String> = std::fs::read_dir(&dir)
            .expect("répertoire lisible")
            .map(|e| e.expect("entrée lisible").file_name().to_string_lossy().into_owned())
            .collect();
        assert!(restes.is_empty(), "integrity-check ne crée RIEN (ni base, ni -wal, ni -shm) : {restes:?}");
    }

    #[test]
    fn p10_33v_integrity_check_sur_page_ecrasee_par_chemin_sort_1() {
        if std::env::var_os(IC_ENFANT).is_some() {
            eprintln!("{IC_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-chemin");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("corrompue.db").to_string_lossy().into_owned();
        let autre = dir.join("configuree.db").to_string_lossy().into_owned();
        let ps = base_saine(&base, None);
        ecraser(&base, 5 * ps, 6 * ps);
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "integrity-check",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::integrity_check_sur_base_vivante_ou_hors_ligne::p10_33v_integrity_check_sur_page_ecrasee_par_chemin_sort_1",
            ])
            .env(IC_ENFANT, "1")
            .env(IC_ARGUMENTS, argv_de_l_enfant(&[base.as_str()]))
            .env("PLUME_DB", &autre)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .env_remove("PLUME_DB_KEY")
            .env_remove("PLUME_DB_KEY_FILE")
            .env_remove(crate::crypto::CLE_DB_KEY_AUTO_PATH)
            .output()
            .expect("ré-exécution du binaire de test");
        let r = rapport_de(&sortie);
        assert_eq!(sortie.status.code(), Some(CODE_CORROMPU), "page écrasée : corrompu : {r}");
        assert_eq!(r["verdict"], "corrompu");
        assert_eq!(r["base"], serde_json::json!(base), "le chemin donné est celui jugé, pas la base de la configuration");
        assert!(!existe(&autre), "la base de la configuration n'est pas créée");
    }

    /// La scène de `P10.33-u` : la porte tient la base en WAL et y a écrit ; integrity-check, dans un
    /// autre processus, ouvre et ferme. Après : la porte relit sa ligne, et le verdict a porté sur l'état
    /// servi (pages du WAL comprises), pas sur le seul fichier principal. CE TÉMOIN NE TIENT PAS « ne
    /// délie rien » : la porte garde son verrou partagé, aucune fermeture de l'enfant ne pourrait délier
    /// `-wal`/`-shm` ici, même en lecture-écriture. C'est le témoin de l'écrivain mort qui le tient.
    #[test]
    fn p10_33v_integrity_check_a_cote_de_la_porte_juge_le_wal_et_la_porte_relit() {
        if std::env::var_os(IC_ENFANT).is_some() {
            eprintln!("{IC_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _env = VERROU_ENV_PROCESSUS.read();
        if db_key().is_some() {
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "p10_33v_integrity_check_a_cote_de_la_porte_juge_le_wal_et_la_porte_relit",
                "la configuration ambiante porte une clé at-rest : la porte chiffrerait la base du témoin, que \
                 l'enfant (sans clé) ne pourrait pas lire ; la scène n'a PAS été jouée sur cette machine.",
            );
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-porte");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("plume.db").to_string_lossy().into_owned();
        let (wal, shm) = (format!("{base}-wal"), format!("{base}-shm"));

        drop(crate::db_open::PreparedDb::open(&base).expect("naissance par la porte"));
        {
            let c = rusqlite::Connection::open(&base).unwrap();
            let mode: String = c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).unwrap();
            assert_eq!(mode, "wal", "fixture : la base est en WAL, comme en production");
        }
        let db = crate::db_open::PreparedDb::open(&base).expect("la porte ouvre");
        db.execute_batch(
            "CREATE TABLE p1033v_temoin(x INTEGER, y BLOB); \
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<40) \
             INSERT INTO p1033v_temoin SELECT 1033, randomblob(2000) FROM n;",
        )
        .unwrap();
        assert!(existe(&wal) && existe(&shm), "fixture : -wal et -shm existent");
        let pages_servies: i64 = db.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();

        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "integrity-check",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::integrity_check_sur_base_vivante_ou_hors_ligne::p10_33v_integrity_check_a_cote_de_la_porte_juge_le_wal_et_la_porte_relit",
            ])
            .env(IC_ENFANT, "1")
            .env(IC_ARGUMENTS, argv_de_l_enfant(&[]))
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .env_remove("PLUME_DB_KEY")
            .env_remove("PLUME_DB_KEY_FILE")
            .env_remove(crate::crypto::CLE_DB_KEY_AUTO_PATH)
            .output()
            .expect("ré-exécution du binaire de test");
        let r = rapport_de(&sortie);
        assert_eq!(r["pages"], serde_json::json!(pages_servies), "le verdict porte sur l'état servi, pages du WAL comprises : {r}");
        assert_eq!(sortie.status.code(), Some(CODE_SAIN), "{r}");
        assert_eq!(r["ouverture"], "vivante", "{r}");

        let n: i64 = db.query_row("SELECT count(*) FROM p1033v_temoin WHERE x = 1033", [], |r| r.get(0)).expect("la porte relit ses lignes");
        assert_eq!(n, 40);
    }

    /// `-wal` et `-shm` laissés par un écrivain mort (sorti sans fermer), sans aucun détenteur : une
    /// ouverture en lecture-écriture, dernière connexion, ferait son checkpoint et les DÉLIERAIT à la
    /// fermeture. integrity-check les laisse, et la ligne de l'écrivain se relit ensuite.
    #[test]
    fn p10_33v_integrity_check_sur_wal_laisse_par_un_ecrivain_mort_ne_delie_rien() {
        if let Ok(base) = std::env::var(IC_ECRIVAIN) {
            let c = rusqlite::Connection::open(&base).expect("écrivain : ouverture");
            let mode: String = c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).expect("écrivain : WAL");
            assert_eq!(mode, "wal");
            c.execute_batch("CREATE TABLE p1033v_mort(x INTEGER); INSERT INTO p1033v_mort VALUES (1033);").expect("écrivain : écriture");
            // Sortie SANS fermer la connexion : ni checkpoint ni suppression des compagnons.
            std::process::exit(0);
        }
        if std::env::var_os(IC_ENFANT).is_some() {
            eprintln!("{IC_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        const NOM: &str = "tests::integrity_check_sur_base_vivante_ou_hors_ligne::p10_33v_integrity_check_sur_wal_laisse_par_un_ecrivain_mort_ne_delie_rien";
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-mort");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("plume.db").to_string_lossy().into_owned();
        let (wal, shm) = (format!("{base}-wal"), format!("{base}-shm"));
        let ecrivain = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", NOM])
            .env(IC_ECRIVAIN, &base)
            .output()
            .expect("écrivain lancé");
        assert!(ecrivain.status.success(), "écrivain : {}", String::from_utf8_lossy(&ecrivain.stderr));
        assert!(existe(&wal) && existe(&shm), "fixture : l'écrivain mort laisse -wal et -shm");
        assert!(std::fs::metadata(&wal).unwrap().len() > 0, "fixture : sa ligne n'est que dans le -wal");

        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["integrity-check", "--exact", "--nocapture", "--test-threads=1", NOM])
            .env(IC_ENFANT, "1")
            .env(IC_ARGUMENTS, argv_de_l_enfant(&[]))
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .env_remove("PLUME_DB_KEY")
            .env_remove("PLUME_DB_KEY_FILE")
            .env_remove(crate::crypto::CLE_DB_KEY_AUTO_PATH)
            .output()
            .expect("ré-exécution du binaire de test");
        let r = rapport_de(&sortie);
        assert_eq!(sortie.status.code(), Some(CODE_SAIN), "{r}");
        assert_eq!(r["ouverture"], "vivante", "{r}");
        assert!(existe(&wal), "integrity-check a DÉLIÉ le -wal laissé par l'écrivain");
        assert!(existe(&shm), "integrity-check a DÉLIÉ le -shm laissé par l'écrivain");
        let c = rusqlite::Connection::open(&base).unwrap();
        let x: i64 = c.query_row("SELECT x FROM p1033v_mort", [], |r| r.get(0)).expect("la ligne de l'écrivain se relit");
        assert_eq!(x, 1033);
    }

    // ── LES TROIS BRANCHES QUE LA PREMIÈRE VERSION NE TENAIT PAS (relevées par la vérification) ────
    // La clé du démon transmise par `main` (le cas de production), le HMAC en défaut sous une
    // structure saine (seul `cipher_integrity_check` le voit), et la base occupée (refus, jamais
    // « corrompu »).

    /// Le délai d'attente de verrou du témoin de la base occupée : le refus doit venir de
    /// `SQLITE_BUSY`, pas de cinq secondes d'attente par étape.
    const ATTENTE_DU_TEMOIN: std::time::Duration = std::time::Duration::from_millis(100);

    /// Le cas de production : base SQLCipher, clé dans l'environnement du démon. `main` doit appliquer
    /// la clé que le démon appliquerait (`db_key()`) : sans elle, la réponse serait toujours 2.
    #[test]
    fn p10_33v_integrity_check_applique_la_cle_du_demon_et_sort_0() {
        if std::env::var_os(IC_ENFANT).is_some() {
            eprintln!("{IC_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-cle-main");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("chiffree.db").to_string_lossy().into_owned();
        base_saine(&base, Some(CLE_DU_TEMOIN));
        let tete = std::fs::read(&base).unwrap();
        assert_ne!(&tete[..16], b"SQLite format 3\0", "fixture : la base est chiffrée");
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "integrity-check",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::integrity_check_sur_base_vivante_ou_hors_ligne::p10_33v_integrity_check_applique_la_cle_du_demon_et_sort_0",
            ])
            .env(IC_ENFANT, "1")
            .env(IC_ARGUMENTS, argv_de_l_enfant(&[]))
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .env(crate::crypto::CLE_DB_KEY, CLE_DU_TEMOIN)
            .env_remove(crate::crypto::CLE_DB_KEY_FILE)
            .env_remove(crate::crypto::CLE_DB_KEY_AUTO_PATH)
            .output()
            .expect("ré-exécution du binaire de test");
        let r = rapport_de(&sortie);
        assert_eq!(r["cle_appliquee"], true, "main transmet la clé du démon : {r}");
        assert_eq!(sortie.status.code(), Some(CODE_SAIN), "base chiffrée saine sous la clé du démon : {r}");
        assert_eq!(r["cipher_integrity_check"], serde_json::json!([]), "le HMAC est contrôlé sous la clé du démon : {r}");
        assert_eq!(r["base"], serde_json::json!(base));
    }

    // ── LES ARGUMENTS : UN ARGUMENT INCONNU SORT EN 2, SANS JUGER LA BASE DE LA CONFIGURATION ─────
    // Avant : l'analyse s'arrêtait au premier drapeau autre que `--full`, et `-full /copie.db` jugeait
    // `PLUME_DB` (la base vivante), qui pouvait sortir en 0. Ici `PLUME_DB` est une base SAINE : un
    // drapeau ignoré rendrait 0 et une ligne JSON ; le refus rend exactement 2, sans ligne JSON.

    /// L'enfant d'un témoin d'arguments : `main` sur `suite`, la base de la configuration saine. La
    /// ré-exécution (`current_exe()` et `.env(IC_ENFANT, …)`) est écrite dans le corps de chaque test,
    /// comme le veut la garde du canal de refus ; cette aide ne fait que compléter l'environnement.
    fn enfant_sur_des_arguments(mut enfant: std::process::Command, nom: &str, suite: &[&str], dir: &std::path::Path, base_configuree: &str) -> std::process::Output {
        enfant
            .args(["integrity-check", "--exact", "--nocapture", "--test-threads=1", nom])
            .env(IC_ARGUMENTS, argv_de_l_enfant(suite))
            .env("PLUME_DB", base_configuree)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .env_remove("PLUME_DB_KEY")
            .env_remove("PLUME_DB_KEY_FILE")
            .env_remove(crate::crypto::CLE_DB_KEY_AUTO_PATH)
            .output()
            .expect("ré-exécution du binaire de test")
    }

    /// Le refus d'arguments : sortie exactement 2, le message nommé sur stderr, aucune ligne JSON
    /// (aucune base n'a été jugée, la base de la configuration non plus).
    fn juger_le_refus_d_arguments(sortie: &std::process::Output, message: &str) {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stderr.contains(IC_MARQUE_ENFANT), "contrôle : l'enfant a atteint `main` : {stdout}\n{stderr}");
        assert!(!stdout.contains("{\""), "aucune base n'est jugée sur un argument refusé (la base de la configuration non plus) : {stdout}");
        assert_eq!(sortie.status.code(), Some(CODE_REFUS), "un argument refusé sort exactement en 2 : {stdout}\n{stderr}");
        assert!(stderr.contains(message), "le refus est nommé (« {message} ») : {stderr}");
    }

    #[test]
    fn p10_33v_integrity_check_drapeau_inconnu_avant_le_chemin_sort_2_sans_juger_la_base_configuree() {
        if std::env::var_os(IC_ENFANT).is_some() {
            eprintln!("{IC_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-drapeau");
        let dir = _tmp.racine().chemin().to_path_buf();
        let vivante = dir.join("vivante.db").to_string_lossy().into_owned();
        let copie = dir.join("copie.db").to_string_lossy().into_owned();
        base_saine(&vivante, None);
        base_saine(&copie, None);
        let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        enfant.env(IC_ENFANT, "1");
        let sortie = enfant_sur_des_arguments(
            enfant,
            "tests::integrity_check_sur_base_vivante_ou_hors_ligne::p10_33v_integrity_check_drapeau_inconnu_avant_le_chemin_sort_2_sans_juger_la_base_configuree",
            &["-full", copie.as_str()],
            &dir,
            &vivante,
        );
        juger_le_refus_d_arguments(&sortie, "drapeau inconnu « -full »");
    }

    #[test]
    fn p10_33v_integrity_check_deux_chemins_sort_2_sans_rien_juger() {
        if std::env::var_os(IC_ENFANT).is_some() {
            eprintln!("{IC_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-deux-chemins");
        let dir = _tmp.racine().chemin().to_path_buf();
        let (a, b) = (dir.join("a.db").to_string_lossy().into_owned(), dir.join("b.db").to_string_lossy().into_owned());
        base_saine(&a, None);
        base_saine(&b, None);
        let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        enfant.env(IC_ENFANT, "1");
        let sortie = enfant_sur_des_arguments(
            enfant,
            "tests::integrity_check_sur_base_vivante_ou_hors_ligne::p10_33v_integrity_check_deux_chemins_sort_2_sans_rien_juger",
            &[a.as_str(), b.as_str()],
            &dir,
            &a,
        );
        juger_le_refus_d_arguments(&sortie, "en trop");
    }

    /// `uri_immuable` échappe `#`, `?` et `%`. Sans l'échappement, `x#y.db` ouvrirait `x` (le reste est
    /// un fragment d'URI), `p?q.db` ouvrirait `p` (le reste est la requête), `m%41.db` ouvrirait `mA.db`
    /// (décodage). Chaque leurre est une base SAINE ; le fichier nommé a une page écrasée : seul le bon
    /// fichier rend 1.
    #[test]
    fn p10_33v_un_nom_avec_diese_question_ou_pourcent_est_le_fichier_juge_pas_le_chemin_tronque() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-uri");
        let dir = _tmp.racine().chemin().to_path_buf();
        for (nom, leurre) in [("x#y.db", "x"), ("p?q.db", "p"), ("m%41.db", "mA.db")] {
            let base = dir.join(nom).to_string_lossy().into_owned();
            let leurre = dir.join(leurre).to_string_lossy().into_owned();
            base_saine(&leurre, None);
            let ps = base_saine(&base, None);
            ecraser(&base, 5 * ps, 6 * ps);
            assert_eq!(verifier(&leurre, Mode::Rapide, None).code, CODE_SAIN, "fixture : le leurre de « {nom} » est sain");
            let v = verifier(&base, Mode::Rapide, None);
            assert_eq!(v.rapport["ouverture"], "immuable", "« {nom} » : la voie de l'URI : {}", v.rapport);
            assert_eq!(v.code, CODE_CORROMPU, "« {nom} » : le fichier nommé est jugé, pas son leurre tronqué ou décodé : {}", v.rapport);
        }
    }

    /// Une page LIBRE abîmée d'une base chiffrée : `quick_check` ne lit pas le contenu d'une page libre
    /// (il rend « ok »), seul `cipher_integrity_check` voit le HMAC en défaut. Le verdict est 1.
    #[test]
    fn p10_33v_hmac_d_une_page_libre_abimee_sous_structure_saine_rend_1() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-hmac");
        let base = _tmp.sous("libre.db").chemin().to_string_lossy().into_owned();
        let (ps, libres) = {
            let c = rusqlite::Connection::open(&base).expect("fixture : ouverture");
            crate::db_open::appliquer_une_cle_explicite(&c, Some(CLE_DU_TEMOIN)).expect("fixture : clé");
            remplir(&c);
            c.execute_batch("DELETE FROM ic_t;").expect("fixture : DELETE");
            let ps: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0)).expect("fixture : page_size");
            let fl: i64 = c.query_row("PRAGMA freelist_count", [], |r| r.get(0)).expect("fixture : freelist_count");
            (ps as usize, fl)
        };
        assert!(libres >= 5, "fixture : le DELETE laisse des pages libres ({libres})");
        let mut octets = std::fs::read(&base).expect("fixture : lecture");
        let n = octets.len();
        for o in &mut octets[n - ps + 100..n - ps + 200] {
            *o ^= 0xFF;
        }
        std::fs::write(&base, &octets).expect("fixture : écriture");
        let v = verifier(&base, Mode::Rapide, Some(CLE_DU_TEMOIN));
        assert_eq!(v.rapport["lignes"], serde_json::json!(["ok"]), "contrôle : la structure est saine, quick_check ne lit pas la page libre : {}", v.rapport);
        let defauts = v.rapport["cipher_integrity_check"].as_array().map(Vec::len).unwrap_or(0);
        assert!(defauts > 0, "cipher_integrity_check signale la page abîmée : {}", v.rapport);
        assert_eq!(v.code, CODE_CORROMPU, "un HMAC en défaut est un fait de corruption : {}", v.rapport);
        assert!(cause(&v).contains("cipher_integrity_check"), "{}", v.rapport);
    }

    /// Base occupée : un écrivain WAL en `locking_mode=EXCLUSIVE` tient une transaction EXCLUSIVE,
    /// `-wal` et `-shm` présents (ouverture vivante). `SQLITE_BUSY` est un refus de conclure, jamais
    /// une fausse alerte de corruption ; les compagnons de l'écrivain restent en place.
    #[test]
    fn p10_33v_base_occupee_rend_2_jamais_corrompu() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033v-occupee");
        let base = _tmp.sous("occupee.db").chemin().to_string_lossy().into_owned();
        let w = rusqlite::Connection::open(&base).expect("fixture : ouverture de l'écrivain");
        let m: String = w.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).expect("fixture : WAL");
        assert_eq!(m, "wal", "fixture : la base passe en WAL");
        remplir(&w);
        w.execute_batch("PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; INSERT INTO ic_t VALUES (x'00');")
            .expect("fixture : transaction exclusive");
        let (wal, shm) = (format!("{base}-wal"), format!("{base}-shm"));
        assert!(existe(&wal) && existe(&shm), "fixture : -wal et -shm présents (ouverture vivante)");
        let v = crate::integrity_check::verifier_avec_attente(&base, Mode::Rapide, None, ATTENTE_DU_TEMOIN);
        assert_eq!(v.rapport["ouverture"], "vivante", "{}", v.rapport);
        assert_eq!(v.code, CODE_REFUS, "base occupée : aucun verdict, jamais « corrompu » : {}", v.rapport);
        assert!(cause(&v).contains("base occupée"), "{}", v.rapport);
        assert!(existe(&wal) && existe(&shm), "les compagnons de l'écrivain restent en place");
        w.execute_batch("COMMIT;").expect("l'écrivain termine sa transaction");
        drop(w);
    }
}

// `P10.33-g` (restes) — TROIS SOUS-COMMANDES DE PLUS EXÉCUTÉES SUR UNE BASE ABSENTE : `retention`,
// `fts-compact` et `sigma-import` (hors `--dry-run`) n'étaient tenues que par le balayage de source.
// Même harnais que `token` et `respond` : `main` en sous-processus, code 1, la phrase du refus suivie
// de celle du site sur stderr, et rien de créé dans le répertoire de la base.
mod refus_de_base_absente_executes {
    use super::*;

    const G_ENFANT: &str = "P1033G_ENFANT_MAIN_EXECUTE";
    const G_MARQUE_ENFANT: &str = "P1033G-ENFANT-EXECUTE-APPELLE-MAIN";

    fn juger_le_refus(geste: &str, phrase_du_site: &str, sortie: &std::process::Output, dir: &std::path::Path, base: &str) {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stderr.contains(G_MARQUE_ENFANT), "contrôle : l'enfant a atteint `main` : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(1), "base absente : `{geste}` sort en 1 : {stdout}\n{stderr}");
        let restes: Vec<String> = std::fs::read_dir(dir)
            .expect("répertoire de la base lisible")
            .map(|e| e.expect("entrée lisible").file_name().to_string_lossy().into_owned())
            .collect();
        assert!(restes.is_empty(), "base absente : `{geste}` ne crée RIEN (ni base en clair, ni -wal, ni -shm) : {restes:?}\n{stderr}");
        let refus = refuser_une_base_absente(base, geste).expect_err("contrôle : la base est toujours absente");
        let attendu = format!("{refus} — {phrase_du_site}");
        assert!(stderr.lines().any(|l| l == attendu), "le refus est DIT sur stderr :\nattendu : {attendu}\nstderr :\n{stderr}");
    }

    #[test]
    fn p10_33g_retention_sur_une_base_absente_refuse_le_dit_et_ne_cree_rien() {
        if std::env::var_os(G_ENFANT).is_some() {
            eprintln!("{G_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033g-retention");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("absente.db").to_string_lossy().into_owned();
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "retention",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::refus_de_base_absente_executes::p10_33g_retention_sur_une_base_absente_refuse_le_dit_et_ne_cree_rien",
            ])
            .env(G_ENFANT, "1")
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .output()
            .expect("ré-exécution du binaire de test");
        juger_le_refus("retention", "AUCUNE rétention appliquée. Arrêt propre.", &sortie, &dir, &base);
    }

    #[test]
    fn p10_33g_fts_compact_sur_une_base_absente_refuse_le_dit_et_ne_cree_rien() {
        if std::env::var_os(G_ENFANT).is_some() {
            eprintln!("{G_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033g-fts");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("absente.db").to_string_lossy().into_owned();
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "fts-compact",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::refus_de_base_absente_executes::p10_33g_fts_compact_sur_une_base_absente_refuse_le_dit_et_ne_cree_rien",
            ])
            .env(G_ENFANT, "1")
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .output()
            .expect("ré-exécution du binaire de test");
        juger_le_refus("fts-compact", "AUCUNE compaction appliquée. Arrêt propre.", &sortie, &dir, &base);
    }

    #[test]
    fn p10_33g_sigma_import_sur_une_base_absente_refuse_le_dit_et_ne_cree_rien() {
        if std::env::var_os(G_ENFANT).is_some() {
            eprintln!("{G_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033g-sigma");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("absente.db").to_string_lossy().into_owned();
        // La règle vit HORS du répertoire de la base : celui-ci doit rester vide.
        let _regles = crate::tmp_possede::TmpPossede::neuf("p1033g-sigma-regles");
        let regle = _regles.sous("regle.yml").chemin().to_string_lossy().into_owned();
        std::fs::write(&regle, "title: p1033g\nlogsource:\n  product: linux\ndetection:\n  sel:\n    a: b\n  condition: sel\n").unwrap();
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "sigma-import",
                regle.as_str(),
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::refus_de_base_absente_executes::p10_33g_sigma_import_sur_une_base_absente_refuse_le_dit_et_ne_cree_rien",
            ])
            .env(G_ENFANT, "1")
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .output()
            .expect("ré-exécution du binaire de test");
        juger_le_refus("sigma-import", "AUCUNE règle importée. Arrêt propre.", &sortie, &dir, &base);
    }
}
