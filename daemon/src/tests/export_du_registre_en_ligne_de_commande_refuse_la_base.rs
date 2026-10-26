// `P10.33-w` (reste du 2026-10-18) — `ledger-export --out` DE LA LIGNE DE COMMANDE N'ÉCRIT JAMAIS DANS LA BASE VIVANTE.
//
// VU (re-mesuré par ces témoins avant le correctif, mutant `ar4_none_sans_refus`) : `ledger_sink_write("file", cible, ..,
// None)`, le chemin de `main` (bras `ledger-export`), ouvrait la cible en création-ajout sans aucune vérification. `--out`
// égal à `plume.db`, à un compagnon, à la base du plan de contrôle, ou à un lien (dur ou symbolique) vers l'un d'eux,
// ajoutait du JSONL au fichier de base.
//
// TENU : `refuser_une_cible_libre_sur_la_base_vivante` (`governance.rs`), appelée par la branche `None` ; signature de
// `ledger_sink_write` inchangée, `main.rs` inchangé (refus sur stderr, sortie 2). Comparaison par `stat` (périphérique,
// inode), sans ouvrir : le lien symbolique est refusé par l'inode de ce qu'il vise, pas par `O_NOFOLLOW`. Une cible pas
// encore là, au bout de ses liens, au nom d'un fichier de base DANS le répertoire de la base, est refusée aussi. Un chemin
// libre hors base reste accepté, y compris dans le répertoire de la base (`tests/governance.rs`, « CLI opérateur (None) »).
//
// MUTANTS JOUÉS (sous cfg!(test), par variable de mutation, retirés avant le commit) : `ar4_none_sans_refus` (la branche `None` ne
// refuse plus), `ar4_par_chemin` (même fichier jugé par égalité de chemin au lieu de l'inode), `ar4_sans_nom_absent`
// (une cible absente n'est plus jugée), `ar4_sans_resolution` (les liens pendants ne sont plus suivis),
// `ar4_sans_controle` (la base du plan de contrôle n'est plus comparée). Puis, sur les mutants d'un vérificateur restés
// verts, cinq témoins ajoutés : `VA2` (destination d'un lien relatif prise telle quelle), `VA3` (un seul saut de lien
// suivi), `VA5` (sans repli sur le répertoire courant pour une cible sans répertoire), `VA7` (une base `PLUME_DB` sans
// répertoire n'est plus comparée), `VA9` (répertoire d'une cible absente comparé par chemin au lieu de l'inode).
mod export_du_registre_en_ligne_de_commande_refuse_la_base {
    use super::*;

    const OCTETS_DE_LA_BASE: &[u8] = b"SQLite format 3\0-base-factice-du-temoin-ar4";
    const OCTETS_DU_COMPAGNON: &[u8] = b"compagnon-factice-du-temoin-ar4";

    /// Base factice dans son répertoire et un répertoire séparé. Les fichiers de base ne sont jamais ouverts par le
    /// démon : le témoin les lit lui-même (ce ne sont pas des bases SQLite) pour comparer à l'octet.
    struct Scene {
        _dossier_de_base: crate::tmp_possede::TmpPossede,
        _separe: crate::tmp_possede::TmpPossede,
        base: std::path::PathBuf,
        dossier: std::path::PathBuf,
        separe: std::path::PathBuf,
    }

    fn scene(nom: &str) -> Scene {
        let dossier_de_base = crate::tmp_possede::TmpPossede::neuf(&format!("ar4-{nom}-base"));
        let separe = crate::tmp_possede::TmpPossede::neuf(&format!("ar4-{nom}-separe"));
        let base = dossier_de_base.join("plume.db");
        std::fs::write(&base, OCTETS_DE_LA_BASE).expect("base factice");
        let dossier = dossier_de_base.to_path_buf();
        let separe_chemin = separe.to_path_buf();
        Scene { _dossier_de_base: dossier_de_base, _separe: separe, base, dossier, separe: separe_chemin }
    }

    fn ecrire(cible: &std::path::Path) -> Result<(), String> {
        ledger_sink_write("file", &cible.to_string_lossy(), &["{\"ar4\":1}".to_string()], None)
    }

    fn refus_present(nom: &str) -> String {
        format!("{REFUS_PUITS_SUR_LA_BASE_VIVANTE} : {CIBLE_LIBRE_EST_UN_FICHIER_DE_BASE} {nom} ; écrire l'export ailleurs")
    }

    fn refus_absent(nom: &str) -> String {
        format!("{REFUS_PUITS_SUR_LA_BASE_VIVANTE} : {CIBLE_LIBRE_CREERAIT_UN_FICHIER_DE_BASE} {nom} ; écrire l'export ailleurs")
    }

    fn octets(p: &std::path::Path) -> Vec<u8> {
        std::fs::read(p).unwrap_or_else(|e| panic!("lecture de {} : {e}", p.display()))
    }

    /// La base nommée par son chemin, puis chacun de ses compagnons présents (`-wal`, `-shm`, `-journal`) : refusés,
    /// refus entier, fichier inchangé à l'octet.
    #[test]
    fn p1033w_cli_la_base_et_ses_compagnons_par_leur_chemin_sont_refuses() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let s = scene("chemin");
        let _db = ReglageBackupPose::neuf("PLUME_DB", &s.base.to_string_lossy());
        let _ctl = ReglageBackupPose::retire("PLUME_CONTROL_DB");
        assert_eq!(ecrire(&s.base), Err(refus_present("plume.db")), "--out = la base");
        assert_eq!(octets(&s.base), OCTETS_DE_LA_BASE, "la base n'a pas bougé d'un octet");
        let wal = s.dossier.join("plume.db-wal");
        let shm = s.dossier.join("plume.db-shm");
        let journal = s.dossier.join("plume.db-journal");
        std::fs::write(&wal, OCTETS_DU_COMPAGNON).expect("-wal factice");
        std::fs::write(&shm, OCTETS_DU_COMPAGNON).expect("-shm factice");
        std::fs::write(&journal, OCTETS_DU_COMPAGNON).expect("-journal factice");
        assert_eq!(ecrire(&wal), Err(refus_present("plume.db-wal")), "--out = le -wal");
        assert_eq!(ecrire(&shm), Err(refus_present("plume.db-shm")), "--out = le -shm");
        assert_eq!(ecrire(&journal), Err(refus_present("plume.db-journal")), "--out = le -journal");
        assert_eq!(octets(&wal), OCTETS_DU_COMPAGNON, "le -wal n'a pas bougé d'un octet");
        assert_eq!(octets(&shm), OCTETS_DU_COMPAGNON, "le -shm n'a pas bougé d'un octet");
        assert_eq!(octets(&journal), OCTETS_DU_COMPAGNON, "le -journal n'a pas bougé d'un octet");
        assert_eq!(octets(&s.base), OCTETS_DE_LA_BASE, "la base n'a pas bougé d'un octet");
    }

    /// Lien DUR au nom neutre, dans un répertoire séparé : seul l'inode le relie à la base (le mutant `ar4_par_chemin`
    /// l'accepte). Refusé, la base inchangée.
    #[test]
    fn p1033w_cli_un_lien_dur_vers_la_base_est_refuse_par_l_inode() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let s = scene("lien-dur");
        let _db = ReglageBackupPose::neuf("PLUME_DB", &s.base.to_string_lossy());
        let _ctl = ReglageBackupPose::retire("PLUME_CONTROL_DB");
        let lien = s.separe.join("copie.jsonl");
        std::fs::hard_link(&s.base, &lien).expect("lien dur vers la base factice (même système de fichiers)");
        assert_eq!(ecrire(&lien), Err(refus_present("plume.db")), "--out = lien dur vers la base");
        assert_eq!(octets(&s.base), OCTETS_DE_LA_BASE, "la base n'a pas bougé d'un octet");
    }

    /// Lien SYMBOLIQUE au nom neutre, dans un répertoire séparé, vers le `-wal` présent : refusé par l'inode de ce qu'il
    /// vise ; le compagnon inchangé, le lien toujours un lien.
    #[test]
    fn p1033w_cli_un_lien_symbolique_vers_un_compagnon_est_refuse() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let s = scene("lien-symb");
        let _db = ReglageBackupPose::neuf("PLUME_DB", &s.base.to_string_lossy());
        let _ctl = ReglageBackupPose::retire("PLUME_CONTROL_DB");
        let wal = s.dossier.join("plume.db-wal");
        std::fs::write(&wal, OCTETS_DU_COMPAGNON).expect("-wal factice");
        let lien = s.separe.join("export.jsonl");
        std::os::unix::fs::symlink(&wal, &lien).expect("lien symbolique vers le -wal");
        assert_eq!(ecrire(&lien), Err(refus_present("plume.db-wal")), "--out = lien symbolique vers le -wal");
        assert_eq!(octets(&wal), OCTETS_DU_COMPAGNON, "le -wal n'a pas bougé d'un octet");
        assert!(std::fs::symlink_metadata(&lien).expect("lien").file_type().is_symlink(), "le lien est resté un lien");
    }

    /// La base du plan de contrôle (défaut : `plume-control.db` à côté de `PLUME_DB`) : refusée, inchangée.
    #[test]
    fn p1033w_cli_la_base_du_plan_de_controle_est_refusee() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let s = scene("controle");
        let _db = ReglageBackupPose::neuf("PLUME_DB", &s.base.to_string_lossy());
        let _ctl = ReglageBackupPose::retire("PLUME_CONTROL_DB");
        let controle = s.dossier.join("plume-control.db");
        std::fs::write(&controle, OCTETS_DE_LA_BASE).expect("base du plan de contrôle factice");
        let lien = s.separe.join("controle.jsonl");
        std::fs::hard_link(&controle, &lien).expect("lien dur vers la base du plan de contrôle");
        assert_eq!(ecrire(&controle), Err(refus_present("plume-control.db")), "--out = base du plan de contrôle");
        assert_eq!(ecrire(&lien), Err(refus_present("plume-control.db")), "--out = lien dur vers la base du plan de contrôle");
        assert_eq!(octets(&controle), OCTETS_DE_LA_BASE, "la base du plan de contrôle n'a pas bougé d'un octet");
    }

    /// Une cible ABSENTE au nom d'un compagnon dans le répertoire de la base (base fermée : ni `-journal` ni `-wal`) :
    /// refusée, rien n'est créé ; et un lien PENDANT au nom neutre qui y mène, aussi.
    #[test]
    fn p1033w_cli_un_compagnon_absent_n_est_pas_cree_meme_par_un_lien_pendant() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let s = scene("absent");
        let _db = ReglageBackupPose::neuf("PLUME_DB", &s.base.to_string_lossy());
        let _ctl = ReglageBackupPose::retire("PLUME_CONTROL_DB");
        let journal = s.dossier.join("plume.db-journal");
        assert_eq!(ecrire(&journal), Err(refus_absent("plume.db-journal")), "--out = -journal absent");
        assert!(std::fs::symlink_metadata(&journal).is_err(), "le -journal a été créé malgré le refus");
        let wal = s.dossier.join("plume.db-wal");
        let pendant = s.separe.join("pendant.jsonl");
        std::os::unix::fs::symlink(&wal, &pendant).expect("lien pendant vers le -wal absent");
        assert_eq!(ecrire(&pendant), Err(refus_absent("plume.db-wal")), "--out = lien pendant vers le -wal absent");
        assert!(std::fs::symlink_metadata(&wal).is_err(), "le -wal a été créé au bout du lien malgré le refus");
        assert_eq!(octets(&s.base), OCTETS_DE_LA_BASE, "la base n'a pas bougé d'un octet");
    }

    /// CONTRÔLE POSITIF : le chemin libre reste libre. Hors base : un fichier neuf dans un répertoire séparé, un fichier
    /// au nom neutre DANS le répertoire de la base (aucun confinement de répertoire sur la ligne de commande), un fichier
    /// nommé `plume.db` dans un autre répertoire (le nom seul ne refuse pas) : écrits, avec la ligne.
    #[test]
    fn p1033w_cli_un_chemin_libre_hors_base_reste_accepte() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let s = scene("libre");
        let _db = ReglageBackupPose::neuf("PLUME_DB", &s.base.to_string_lossy());
        let _ctl = ReglageBackupPose::retire("PLUME_CONTROL_DB");
        let accepte = |cible: std::path::PathBuf| {
            assert_eq!(ecrire(&cible), Ok(()), "chemin libre refusé : {}", cible.display());
            assert_eq!(octets(&cible), b"{\"ar4\":1}\n", "la ligne est écrite dans {}", cible.display());
        };
        accepte(s.separe.join("export.jsonl"));
        accepte(s.dossier.join("export.jsonl"));
        accepte(s.separe.join("plume.db"));
        assert_eq!(octets(&s.base), OCTETS_DE_LA_BASE, "la base n'a pas bougé d'un octet");
    }

    /// Lien symbolique RELATIF (`rel.jsonl -> plume.db-wal`, contenu sans répertoire) vers le `-wal` présent : la
    /// destination se lit depuis le répertoire du lien, pas depuis le répertoire courant. Refusé, le `-wal` inchangé.
    /// Mutant `VA2` (destination prise telle quelle) : accepté, le JSONL s'ajoute au `-wal`.
    #[test]
    fn p1033w_cli_un_lien_symbolique_relatif_vers_un_compagnon_est_refuse() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let s = scene("lien-relatif");
        let _db = ReglageBackupPose::neuf("PLUME_DB", &s.base.to_string_lossy());
        let _ctl = ReglageBackupPose::retire("PLUME_CONTROL_DB");
        let wal = s.dossier.join("plume.db-wal");
        std::fs::write(&wal, OCTETS_DU_COMPAGNON).expect("-wal factice");
        let lien = s.dossier.join("rel.jsonl");
        std::os::unix::fs::symlink("plume.db-wal", &lien).expect("lien symbolique relatif vers le -wal");
        assert_eq!(ecrire(&lien), Err(refus_present("plume.db-wal")), "--out = lien relatif vers le -wal");
        assert_eq!(octets(&wal), OCTETS_DU_COMPAGNON, "le -wal n'a pas bougé d'un octet");
        assert_eq!(octets(&s.base), OCTETS_DE_LA_BASE, "la base n'a pas bougé d'un octet");
    }

    /// CHAÎNE de deux liens PENDANTS (`a.jsonl -> b.jsonl -> <dossier>/plume.db-wal` absent) : suivie jusqu'au bout,
    /// refusée, rien n'est créé. Mutant `VA3` (un seul saut suivi) : accepté, le `-wal` naît au bout de la chaîne.
    #[test]
    fn p1033w_cli_une_chaine_de_deux_liens_pendants_vers_un_compagnon_est_refusee() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let s = scene("chaine");
        let _db = ReglageBackupPose::neuf("PLUME_DB", &s.base.to_string_lossy());
        let _ctl = ReglageBackupPose::retire("PLUME_CONTROL_DB");
        let wal = s.dossier.join("plume.db-wal");
        let b = s.separe.join("b.jsonl");
        let a = s.separe.join("a.jsonl");
        std::os::unix::fs::symlink(&wal, &b).expect("lien pendant b -> -wal absent");
        std::os::unix::fs::symlink(&b, &a).expect("lien a -> b");
        assert_eq!(ecrire(&a), Err(refus_absent("plume.db-wal")), "--out = chaîne de deux liens pendants vers le -wal");
        assert!(std::fs::symlink_metadata(&wal).is_err(), "le -wal a été créé au bout de la chaîne malgré le refus");
        assert_eq!(octets(&s.base), OCTETS_DE_LA_BASE, "la base n'a pas bougé d'un octet");
    }

    /// Compagnon ABSENT atteint par un LIEN DE RÉPERTOIRE (`<separe>/vers-la-base -> <dossier>`, puis
    /// `<separe>/vers-la-base/plume.db-journal`) : le chemin littéral du répertoire diffère, son inode est celui du
    /// répertoire de la base. Refusé, rien n'est créé. Mutant `VA9` (répertoires comparés par chemin) : accepté, créé.
    #[test]
    fn p1033w_cli_un_compagnon_absent_par_un_lien_de_repertoire_est_refuse() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let s = scene("lien-de-repertoire");
        let _db = ReglageBackupPose::neuf("PLUME_DB", &s.base.to_string_lossy());
        let _ctl = ReglageBackupPose::retire("PLUME_CONTROL_DB");
        let vers = s.separe.join("vers-la-base");
        std::os::unix::fs::symlink(&s.dossier, &vers).expect("lien de répertoire vers le répertoire de la base");
        assert_eq!(
            ecrire(&vers.join("plume.db-journal")),
            Err(refus_absent("plume.db-journal")),
            "--out = -journal absent par un lien de répertoire"
        );
        assert!(std::fs::symlink_metadata(s.dossier.join("plume.db-journal")).is_err(), "le -journal a été créé malgré le refus");
        assert_eq!(octets(&s.base), OCTETS_DE_LA_BASE, "la base n'a pas bougé d'un octet");
    }

    // ── RÉPERTOIRE COURANT : chemins sans répertoire, EN SOUS-PROCESSUS (le répertoire courant est global au processus ;
    // l'enfant le reçoit par `Command::current_dir`, le parent ne le change jamais) ──────────────────────────────────────

    const AR4_CWD_ENFANT: &str = "AR4_ENFANT_CIBLE_RELATIVE";
    const AR4_CWD_CIBLE: &str = "AR4_ENFANT_CIBLE";
    const AR4_CWD_ISSUE: &str = "AR4-ENFANT-ISSUE";

    /// `VA5` : `cd <dossier de la base>` puis `--out plume.db-journal` (nom nu, absent) : le répertoire de la cible est
    /// le répertoire courant, celui de la base ; refusé, rien n'est créé. `VA7` : `PLUME_DB=plume.db` (sans répertoire,
    /// lu depuis le répertoire courant) et `--out` = la base par son chemin absolu : refusé, la base inchangée. Contrôle
    /// positif : nom nu neutre (`export.jsonl`) dans le même répertoire courant, écrit avec la ligne.
    #[test]
    fn p1033w_cli_les_chemins_sans_repertoire_se_jugent_depuis_le_repertoire_courant() {
        if std::env::var_os(AR4_CWD_ENFANT).is_some() {
            let cible = std::env::var(AR4_CWD_CIBLE).expect("cible de l'enfant");
            let issue = ecrire(std::path::Path::new(&cible));
            eprintln!("{AR4_CWD_ISSUE} {issue:?}");
            return;
        }
        // L'enfant hérite de l'environnement du parent : lu sous le verrou, jamais pendant qu'un autre témoin le pose.
        let _env = VERROU_ENV_PROCESSUS.read();
        let tmp = crate::tmp_possede::TmpPossede::neuf("ar4-cwd");
        let dossier = tmp.to_path_buf();
        let base = dossier.join("plume.db");
        std::fs::write(&base, OCTETS_DE_LA_BASE).expect("base factice");
        let jouer = |plume_db: &str, cible: &str| -> (Vec<String>, String) {
            let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
                .args([
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                    "tests::export_du_registre_en_ligne_de_commande_refuse_la_base::p1033w_cli_les_chemins_sans_repertoire_se_jugent_depuis_le_repertoire_courant",
                ])
                .current_dir(&dossier)
                .env(AR4_CWD_ENFANT, "1")
                .env(AR4_CWD_CIBLE, cible)
                .env("PLUME_DB", plume_db)
                .env("PLUME_CONFIG", dossier.join("aucune.conf"))
                .env_remove("PLUME_CONTROL_DB")
                .output()
                .expect("ré-exécution du binaire de test");
            let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
            assert!(sortie.status.success(), "l'enfant a fini sans panique : {stderr}");
            let lignes = stderr.lines().filter(|l| l.starts_with(AR4_CWD_ISSUE)).map(str::to_string).collect();
            (lignes, stderr)
        };
        let issue = |r: Result<(), String>| vec![format!("{AR4_CWD_ISSUE} {r:?}")];
        let base_s = base.to_string_lossy().into_owned();

        let (lignes, stderr) = jouer(&base_s, "plume.db-journal");
        assert_eq!(lignes, issue(Err(refus_absent("plume.db-journal"))), "VA5 : nom nu -journal absent : {stderr}");
        assert!(std::fs::symlink_metadata(dossier.join("plume.db-journal")).is_err(), "le -journal a été créé malgré le refus");

        let (lignes, stderr) = jouer("plume.db", &base_s);
        assert_eq!(lignes, issue(Err(refus_present("plume.db"))), "VA7 : PLUME_DB sans répertoire, --out = la base : {stderr}");
        assert_eq!(octets(&base), OCTETS_DE_LA_BASE, "la base n'a pas bougé d'un octet");

        let (lignes, stderr) = jouer("plume.db", "export.jsonl");
        assert_eq!(lignes, issue(Ok(())), "contrôle : nom nu neutre accepté : {stderr}");
        assert_eq!(octets(&dossier.join("export.jsonl")), b"{\"ar4\":1}\n", "la ligne est écrite dans export.jsonl");
        assert_eq!(octets(&base), OCTETS_DE_LA_BASE, "la base n'a pas bougé d'un octet");
    }

    // ── LE POINT D'ENTRÉE : `main` (bras `ledger-export`) EN SOUS-PROCESSUS, SUR UNE BASE FABRIQUÉE ─────────────────────
    // `--out <chemin>` suit `--` : libtest le lit comme un filtre libre (avec `--exact`, seul ce test joue), `main` le lit
    // par `flag_val`.

    const AR4_ENFANT: &str = "AR4_ENFANT_MAIN_LEDGER_EXPORT";
    const AR4_MARQUE_ENFANT: &str = "AR4-ENFANT-APPELLE-MAIN";

    #[test]
    fn p1033w_cli_ledger_export_sur_la_base_sort_2_avec_la_ligne_entiere() {
        if std::env::var_os(AR4_ENFANT).is_some() {
            eprintln!("{AR4_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("ar4-main");
        let dossier = tmp.to_path_buf();
        let base = dossier.join("plume.db");
        let base_s = base.to_string_lossy().into_owned();
        // La base fabriquée : la base complète des tests (schéma et migrations), trois maillons écrits par
        // `ledger_append`, copiée en clair dans un fichier par `VACUUM INTO` ; aucune connexion ne la tient ensuite.
        let dernier_hash: String = {
            let c = test_db();
            assert!(ledger_append(&c, "test.ar4", "maillon 0").cause_de_non_inscription().is_none(), "fixture : maillon 0");
            assert!(ledger_append(&c, "test.ar4", "maillon 1").cause_de_non_inscription().is_none(), "fixture : maillon 1");
            assert!(ledger_append(&c, "test.ar4", "maillon 2").cause_de_non_inscription().is_none(), "fixture : maillon 2");
            c.execute("VACUUM INTO ?1", [&base_s]).expect("fixture : base fabriquée sur disque");
            c.query_row("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).expect("fixture : dernier hachage")
        };
        let jouer = |out: &std::path::Path| -> (Option<i32>, Vec<String>, String) {
            let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
                .args([
                    "ledger-export",
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                    "tests::export_du_registre_en_ligne_de_commande_refuse_la_base::p1033w_cli_ledger_export_sur_la_base_sort_2_avec_la_ligne_entiere",
                    "--",
                    "--out",
                ])
                .arg(out)
                .env(AR4_ENFANT, "1")
                .env("PLUME_DB", &base_s)
                .env("PLUME_CONFIG", dossier.join("aucune.conf"))
                .env_remove("PLUME_CONTROL_DB")
                .env_remove("PLUME_DB_KEY")
                .env_remove("PLUME_DB_KEY_FILE")
                .env_remove(crate::crypto::CLE_DB_KEY_AUTO_PATH)
                .output()
                .expect("ré-exécution du binaire de test");
            let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
            assert!(stderr.contains(AR4_MARQUE_ENFANT), "contrôle : l'enfant a atteint `main` : {stderr}");
            let lignes = stderr.lines().filter(|l| l.starts_with("ledger-export")).map(str::to_string).collect();
            (sortie.status.code(), lignes, stderr)
        };

        let avant = octets(&base);
        let (code, lignes, stderr) = jouer(&base);
        assert_eq!(lignes, vec![format!("ledger-export: {}", refus_present("plume.db"))], "ligne de refus entière : {stderr}");
        assert_eq!(code, Some(2), "--out = la base : sortie 2 : {stderr}");
        assert_eq!(octets(&base), avant, "la base fabriquée n'a pas bougé d'un octet");

        // Contre-épreuve : même base, chemin libre à côté -> sortie 0, les trois maillons écrits, ligne de succès entière.
        let libre = dossier.join("export.jsonl");
        let (code, lignes, stderr) = jouer(&libre);
        assert_eq!(
            lignes,
            vec![format!("ledger-export : 3 entrées -> {} (last_id=3, last_hash={dernier_hash})", libre.display())],
            "ligne de succès entière : {stderr}"
        );
        assert_eq!(code, Some(0), "chemin libre : sortie 0 : {stderr}");
        assert_eq!(String::from_utf8_lossy(&octets(&libre)).lines().count(), 3, "les trois maillons sont dans la copie");
    }
}
