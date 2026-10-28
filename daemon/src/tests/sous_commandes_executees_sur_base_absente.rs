// `P10.33-g` (restes) — DEUX GESTES EXÉCUTABLES JOUÉS SUR UNE BASE ABSENTE, ET LE SIGNAL APRÈS SAUVEGARDE
// ===================================================================================================
// `purge` (purge.rs, `purge_cli`, sortie 2) et `restore-drill record` (main.rs, sortie 1) n'étaient
// tenues que par le balayage de source (sous_commandes_refusent_une_base_absente.rs ②), qui lit la
// FORME du refus et non son effet. Elles sont ici EXÉCUTÉES par `main` en sous-processus, comme
// `token`, `respond` (même fichier ④), `retention`, `fts-compact` et `sigma-import`
// (sous_commandes_ne_creent_ni_ne_delient_la_base.rs) : code de sortie exact, ligne de refus EXACTE
// sur stderr (phrase de l'aide puis phrase du site, littérale ici), répertoire de la base resté vide.
//
// Deux obstacles levés sans toucher la production :
// - `purge` exige `--since`, `--until` et un identifiant, que libtest refuserait comme options : ils
//   passent après `--`, où libtest ne lit plus que des filtres (aucun test ne porte ces noms avec
//   `--exact`) et où `purge_cli` les trouve par position (`flag`) ;
// - `restore-drill record` lit une attestation sur stdin et la juge AVANT la garde : l'enfant en reçoit
//   une VALIDE (contrôle positif : `depuis_texte` l'accepte), sinon il sortirait en 1 pour une autre
//   cause et la ligne exacte le distinguerait.
//
// Aucune assertion « pas de succès annoncé » : le code de sortie exact et le répertoire resté vide
// attrapent déjà toute régression qui irait jusqu'au succès (une phrase de succès propre à un seul geste
// ne tiendrait sur rien pour l'autre).
//
// MUTANTS JOUÉS (variable de mutation sous cfg!(test), posés dans la production le temps de l'épreuve puis
// retirés) : AW7_PURGE_PORTE (purge_cli ouvre la porte AVANT `refuser_une_base_absente` : la base naît
// en clair et la garde la voit existante) et AW7_DRILL_PORTE (même geste dans `restore-drill record`).
// Chacun rougit son témoin.
//
// ③ LE SIGNAL DE POSTURE APRÈS `backup --compress` (main.rs, garde `refuser_une_base_absente` avant
// `PreparedDb::open`). Jusqu'à `P10.34-r`, ce témoin la faisait REFUSER sur une base absente : avec
// `PLUME_DB_KEY` posée, `backup_compressed` aboutissait sur une base absente (fichier de 0 octet laissé
// derrière, archive d'une base vide annoncée réussie), puis la garde du signal refusait. Ce succès était
// le défaut de `P10.34-r` : la garde d'ENTRÉE de `backup` refuse désormais une base absente avant toute
// sauvegarde (témoin : sauvegarde_sur_base_absente_et_base_pleine_dites.rs), et la garde du signal ne
// refuse plus que si la base disparaît PENDANT la sauvegarde — une course sans témoin déterministe.
// REPOINTÉ : la garde du signal reste EXÉCUTÉE, dans son sens passant, sur une base NÉE PAR LA PORTE AVEC
// LA CLÉ (`PreparedDb::open_keyed`, schéma complet, chiffrée) : la sauvegarde aboutit (code 0, archive
// écrite), la garde laisse passer, et le signal de posture symétrique est ÉCRIT dans la base (une ligne
// `plume-backup-symmetric-*`, zéro avant), sans la ligne « signal de posture NON émis ». Mutant
// AX6_SIGNAL_REFUSE (le passage après la garde coupé, ce que produirait une garde qui refuse une base
// existante) : rouge.
//
// LIMITE ASSUMÉE : la propriété root d'un fichier créé par une CLI lancée sous `sudo` n'est pas
// témoignable sans root.
mod sous_commandes_executees_sur_base_absente {
    use super::*;

    const AW7_ENFANT: &str = "P1033G_AW7_ENFANT_MAIN";
    const AW7_MARQUE_ENFANT: &str = "P1033G-AW7-ENFANT-APPELLE-MAIN";

    /// Phrases du site, LITTÉRALES (jamais relues dans la production).
    const PHRASE_PURGE: &str = "AUCUNE purge appliquée. Arrêt propre.";
    const PHRASE_DRILL: &str = "attestation NON enregistrée.";

    /// Attestation valide : chiffrement connu, tables et lignes non nulles, horodatage plausible.
    const ATTESTATION_JSON: &str = r#"{"ts":1700000000,"archive":"plume-aw7.tar.zst.age","archive_octets":4096,"chiffrement":"symmetric","tables":3,"lignes":42}"#;

    fn juger_le_refus(
        geste: &str,
        code: i32,
        phrase_du_site: &str,
        sortie: &std::process::Output,
        dir: &std::path::Path,
        base: &str,
    ) {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stderr.contains(AW7_MARQUE_ENFANT), "contrôle : l'enfant a atteint `main` : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(code), "base absente : `{geste}` sort en {code} : {stdout}\n{stderr}");
        let restes: Vec<String> = std::fs::read_dir(dir)
            .expect("répertoire de la base lisible")
            .map(|e| e.expect("entrée lisible").file_name().to_string_lossy().into_owned())
            .collect();
        assert!(restes.is_empty(), "base absente : `{geste}` ne crée RIEN (ni base en clair, ni -wal, ni -shm) : {restes:?}\n{stderr}");
        let refus = refuser_une_base_absente(base, geste).expect_err("contrôle : la base est toujours absente");
        let attendu = format!("{refus} — {phrase_du_site}");
        assert!(
            stderr.lines().any(|l| l == attendu),
            "le refus est DIT sur stderr, ligne entière :\nattendu : {attendu}\nstderr :\n{stderr}"
        );
    }

    #[test]
    fn p10_33g_purge_sur_une_base_absente_sort_2_le_dit_et_ne_cree_rien() {
        if std::env::var_os(AW7_ENFANT).is_some() {
            eprintln!("{AW7_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        // Contrôle positif : le périmètre passé à l'enfant est VALIDE, sinon il sortirait en 2 avant la
        // garde (même code, autre ligne).
        let sel = vec![("source".to_string(), "flux-aw7".to_string())];
        assert!(purge_scope_from_args(&sel, "-2d", "-1h", now()).is_ok(), "contrôle : périmètre de purge valide");
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033g-aw7-purge");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("absente.db").to_string_lossy().into_owned();
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "purge",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::sous_commandes_executees_sur_base_absente::p10_33g_purge_sur_une_base_absente_sort_2_le_dit_et_ne_cree_rien",
                "--",
                "--source",
                "flux-aw7",
                "--since",
                "-2d",
                "--until",
                "-1h",
            ])
            .env(AW7_ENFANT, "1")
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .stdin(std::process::Stdio::null())
            .output()
            .expect("ré-exécution du binaire de test");
        juger_le_refus("purge", 2, PHRASE_PURGE, &sortie, &dir, &base);
    }

    #[test]
    fn p10_33g_restore_drill_record_sur_une_base_absente_sort_1_le_dit_et_ne_cree_rien() {
        if std::env::var_os(AW7_ENFANT).is_some() {
            eprintln!("{AW7_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let attestation = format!("{} {ATTESTATION_JSON}\n", crate::exercice_de_restauration::PREFIXE_ATTESTATION);
        // Contrôle positif : l'attestation est acceptée, le refus vu plus bas est donc celui de la garde.
        assert!(
            crate::exercice_de_restauration::Exercice::depuis_texte(&attestation).is_ok(),
            "contrôle : attestation valide"
        );
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033g-aw7-drill");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("absente.db").to_string_lossy().into_owned();
        let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "restore-drill",
                "record",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::sous_commandes_executees_sur_base_absente::p10_33g_restore_drill_record_sur_une_base_absente_sort_1_le_dit_et_ne_cree_rien",
            ])
            .env(AW7_ENFANT, "1")
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("ré-exécution du binaire de test");
        {
            use std::io::Write;
            let mut entree = enfant.stdin.take().expect("stdin de l'enfant");
            entree.write_all(attestation.as_bytes()).expect("attestation écrite sur stdin");
        }
        let sortie = enfant.wait_with_output().expect("sortie de l'enfant");
        juger_le_refus("restore-drill record", 1, PHRASE_DRILL, &sortie, &dir, &base);
    }
    #[test]
    fn p10_33g_signal_apres_backup_compress_sur_une_base_nee_par_la_porte_est_emis() {
        if std::env::var_os(AW7_ENFANT).is_some() {
            eprintln!("{AW7_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _env = VERROU_ENV_PROCESSUS.read();
        const CLE_DE_LA_BASE: &str = "cle-de-temoin-ax6-base-nee";
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033g-ax6-backup");
        let dir = _tmp.racine().chemin().to_path_buf();
        let _tmp_dest = crate::tmp_possede::TmpPossede::neuf("p1033g-ax6-backup-dest");
        let dir_dest = _tmp_dest.racine().chemin().to_path_buf();
        let base = dir.join("nee.db").to_string_lossy().into_owned();
        let dest = dir_dest.join("archive.age").to_string_lossy().into_owned();
        let symetriques = || -> i64 {
            crate::db_open::PreparedDb::open_keyed(&base, Some(CLE_DE_LA_BASE))
                .expect("la base née s'ouvre avec sa clé")
                .into_connection()
                .query_row("SELECT COUNT(*) FROM event WHERE dedup LIKE '%plume-backup-symmetric-%'", [], |r| r.get(0))
                .expect("compte des signaux de posture")
        };
        // La base naît par la porte, AVEC la clé : schéma complet, chiffrée.
        drop(crate::db_open::PreparedDb::open_keyed(&base, Some(CLE_DE_LA_BASE)).expect("naissance par la porte avec la clé"));
        assert!(refuser_une_base_absente(&base, "contrôle").is_ok(), "contrôle : la base née n'est pas absente");
        assert_eq!(symetriques(), 0, "contrôle : aucun signal de posture avant la sauvegarde");
        // `--compress` passe après `--` (libtest le refuserait comme option) ; `main` le trouve partout.
        // La destination est le premier argument positionnel après `backup` ; libtest la lit comme un
        // filtre de plus, sans effet avec `--exact`.
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "backup",
                dest.as_str(),
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::sous_commandes_executees_sur_base_absente::p10_33g_signal_apres_backup_compress_sur_une_base_nee_par_la_porte_est_emis",
                "--",
                "--compress",
            ])
            .env(AW7_ENFANT, "1")
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .env("PLUME_DB_KEY", CLE_DE_LA_BASE)
            .env_remove("PLUME_DB_KEY_FILE")
            .env_remove("PLUME_BACKUP_AGE_RECIPIENT")
            .env_remove("PLUME_BACKUP_REQUIRE_ASYMMETRIC")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stderr.contains(AW7_MARQUE_ENFANT), "contrôle : l'enfant a atteint `main` : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "sauvegarde d'une base née : sortie 0 : {stdout}\n{stderr}");
        // Contrôle : la sauvegarde a bien abouti, la garde du signal a donc été ATTEINTE.
        assert!(stdout.contains("backup (compressé+chiffré) ->"), "contrôle : la sauvegarde a abouti : {stdout}\n{stderr}");
        assert!(std::path::Path::new(&dest).is_file(), "contrôle : l'archive est écrite");
        assert!(
            !stderr.lines().any(|l| l.contains("signal de posture NON émis")),
            "base née : la garde du signal laisse passer, aucun refus dit : {stderr}"
        );
        assert_eq!(symetriques(), 1, "la garde a laissé passer : le signal de posture symétrique est ÉCRIT : {stderr}");
    }
}
