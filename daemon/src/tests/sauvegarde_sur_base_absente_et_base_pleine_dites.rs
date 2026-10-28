// =====================================================================================
// `P10.34-r` — `backup` SUR UNE BASE ABSENTE REFUSE ET NE CRÉE RIEN ; `P10.7-r` (reste de la vague AW) — UNE BASE
// PLEINE OU UN `RAISE(ROLLBACK)` : LA LIGNE DE L'ANNULATION DIT L'ÉTAT RELU, PAS UN POINT DE REPRISE « RESTÉ OUVERT ».
//
// L'ÉNONCÉ, RE-MESURÉ SUR LA BASE 309315de :
//  - `backup --compress` (et le mode historique `backup`, même bras de `main`) ouvrait le chemin de la base sans garde :
//    sur une base absente, un fichier de 0 octet restait au chemin de la base et la sortie 0 annonçait réussie
//    l'archive d'une base vide (mutant AX6_BACKUP_PORTE : la garde d'entrée sautée, la forme d'avant) ;
//  - `control_ledger_append` : quand la base annule elle-même toute la transaction (base pleine, `RAISE(ROLLBACK)`),
//    `ROLLBACK TO` échoue en « no such savepoint » et la ligne disait « ANNULATION REFUSÉE … reste ouvert », alors que
//    la connexion est revenue en autocommit (mutant AX6_SANS_RELECTURE : l'état non relu, la forme d'avant).
//
// CE QUE CES TÉMOINS TIENNENT :
//  (1) `backup --compress` (clé posée : la sauvegarde aboutissait) et `backup` (mode historique) sur une base absente,
//      exécutés par `main` en sous-processus : sortie 1, ligne de refus EXACTE (phrase de l'aide puis phrase du site,
//      littérale ici), répertoire de la base resté VIDE, aucune archive écrite ;
//  (2) base pleine (`max_page_count` à la taille courante, détail volumineux) : l'issue servie est la cause du maillon
//      non écrit, l'état reste 1/1, la connexion est en autocommit, et la ligne ENTIÈRE dit la transaction annulée par
//      la base ; même chose sous une transaction ENGLOBANTE ouverte par l'appelant (son écriture est annulée avec elle :
//      « englobante comprise » est mesuré, pas supposé) ; même chose pour un `RAISE(ROLLBACK)` du point de contrôle ;
//      le plafond levé, un maillon nominal s'inscrit avec son point (2/2) et la chaîne se vérifie en 0.
//  Le bras « point de reprise resté ouvert » (autorisateur qui refuse `ROLLBACK TO`, connexion hors autocommit) reste
//  témoigné par `jcma_chaque_issue_dit_sa_ligne` ; mutant AX6_RELECTURE_TOUJOURS (le bras neuf pris sans relire) : rouge.
// =====================================================================================
mod sauvegarde_sur_base_absente_et_base_pleine_dites {
    use super::*;

    const AX6_ENFANT: &str = "P1034R_AX6_ENFANT_MAIN";
    const AX6_MARQUE_ENFANT: &str = "P1034R-AX6-ENFANT-APPELLE-MAIN";
    /// Phrase du site, LITTÉRALE (jamais relue dans la production).
    const PHRASE_BACKUP: &str = "AUCUNE sauvegarde produite. Arrêt propre.";
    const CLE_DE_TEMOIN: &str = "cle-de-temoin-ax6-sauvegarde";

    fn ax6_juger_le_refus(mode: &str, sortie: &std::process::Output, dir: &std::path::Path, base: &str, dest: &str) {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stderr.contains(AX6_MARQUE_ENFANT), "contrôle : l'enfant a atteint `main` : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(1), "base absente : `{mode}` sort en 1 : {stdout}\n{stderr}");
        let restes: Vec<String> = std::fs::read_dir(dir)
            .expect("répertoire de la base lisible")
            .map(|e| e.expect("entrée lisible").file_name().to_string_lossy().into_owned())
            .collect();
        assert!(restes.is_empty(), "base absente : `{mode}` ne crée RIEN (ni base de 0 octet, ni -wal, ni -shm) : {restes:?}\n{stderr}");
        assert!(!std::path::Path::new(dest).exists(), "base absente : `{mode}` n'écrit aucune archive : {stdout}\n{stderr}");
        let refus = refuser_une_base_absente(base, "backup").expect_err("contrôle : la base est toujours absente");
        let attendu = format!("{refus} — {PHRASE_BACKUP}");
        assert!(
            stderr.lines().any(|l| l == attendu),
            "le refus est DIT sur stderr, ligne entière :\nattendu : {attendu}\nstderr :\n{stderr}"
        );
        assert!(
            !stdout.contains("backup ->") && !stdout.contains("backup (compressé+chiffré) ->"),
            "aucune sauvegarde annoncée sur stdout : {stdout}"
        );
    }

    // -------------------------------------------------------------------------------------
    // (1) `backup` SUR UNE BASE ABSENTE
    // -------------------------------------------------------------------------------------

    #[test]
    fn p10_34r_backup_compress_sur_une_base_absente_sort_1_le_dit_et_ne_cree_rien() {
        if std::env::var_os(AX6_ENFANT).is_some() {
            eprintln!("{AX6_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1034r-ax6-compress");
        let dir = _tmp.racine().chemin().to_path_buf();
        let _tmp_dest = crate::tmp_possede::TmpPossede::neuf("p1034r-ax6-compress-dest");
        let dest = _tmp_dest.racine().chemin().join("archive.age").to_string_lossy().into_owned();
        let base = dir.join("absente.db").to_string_lossy().into_owned();
        // `--compress` passe après `--` (libtest le refuserait comme option) ; la destination est le premier argument
        // positionnel après `backup`, lu par libtest comme un filtre de plus, sans effet avec `--exact`. La clé est
        // POSÉE : c'est le cas où la sauvegarde aboutissait sur une base absente.
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "backup",
                dest.as_str(),
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::sauvegarde_sur_base_absente_et_base_pleine_dites::p10_34r_backup_compress_sur_une_base_absente_sort_1_le_dit_et_ne_cree_rien",
                "--",
                "--compress",
            ])
            .env(AX6_ENFANT, "1")
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .env("PLUME_DB_KEY", CLE_DE_TEMOIN)
            .env_remove("PLUME_DB_KEY_FILE")
            .env_remove("PLUME_BACKUP_AGE_RECIPIENT")
            .env_remove("PLUME_BACKUP_REQUIRE_ASYMMETRIC")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("ré-exécution du binaire de test");
        ax6_juger_le_refus("backup --compress", &sortie, &dir, &base, &dest);
    }

    #[test]
    fn p10_34r_backup_historique_sur_une_base_absente_sort_1_le_dit_et_ne_cree_rien() {
        if std::env::var_os(AX6_ENFANT).is_some() {
            eprintln!("{AX6_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1034r-ax6-historique");
        let dir = _tmp.racine().chemin().to_path_buf();
        let _tmp_dest = crate::tmp_possede::TmpPossede::neuf("p1034r-ax6-historique-dest");
        let dest = _tmp_dest.racine().chemin().join("copie.bak").to_string_lossy().into_owned();
        let base = dir.join("absente.db").to_string_lossy().into_owned();
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "backup",
                dest.as_str(),
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::sauvegarde_sur_base_absente_et_base_pleine_dites::p10_34r_backup_historique_sur_une_base_absente_sort_1_le_dit_et_ne_cree_rien",
            ])
            .env(AX6_ENFANT, "1")
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .env("PLUME_DB_KEY", CLE_DE_TEMOIN)
            .env_remove("PLUME_DB_KEY_FILE")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("ré-exécution du binaire de test");
        ax6_juger_le_refus("backup", &sortie, &dir, &base, &dest);
    }

    // -------------------------------------------------------------------------------------
    // (2) BASE PLEINE, TRANSACTION ENGLOBANTE, `RAISE(ROLLBACK)` : LA LIGNE DIT L'ÉTAT RELU
    // -------------------------------------------------------------------------------------

    const AX6_CLE: [u8; 32] = [43u8; 32];
    const AX6_CAUSE_NON_ECRIT: &str = "l'écriture du maillon n'a pas eu lieu";
    const AX6_CAUSE_POINT: &str = "le point de contrôle signé du maillon n'a pas été posé : le maillon est annulé avec lui";
    const AX6_LIGNE_PLEIN: &str = "[control_ledger] WARN maillon 'ax6.plein' NON inscrit : l'écriture n'a pas eu lieu (database or disk is full) — la base a déjà annulé toute la transaction (englobante comprise) : ni le maillon ni son point ne sont écrits, aucun point de reprise ne reste ouvert";
    const AX6_LIGNE_ENGLOBANTE: &str = "[control_ledger] WARN maillon 'ax6.englobante' NON inscrit : l'écriture n'a pas eu lieu (database or disk is full) — la base a déjà annulé toute la transaction (englobante comprise) : ni le maillon ni son point ne sont écrits, aucun point de reprise ne reste ouvert";
    const AX6_LIGNE_ROLLBACK: &str = "[control_ledger] WARN maillon 'ax6.rollback' NON inscrit : son point de contrôle n'a pas été posé (l'écriture n'a pas eu lieu (ax6 rollback du point)) — le maillon est annulé avec lui — la base a déjà annulé toute la transaction (englobante comprise) : ni le maillon ni son point ne sont écrits, aucun point de reprise ne reste ouvert";

    fn ax6_etat() -> (AppState, crate::tmp_possede::TmpDb) {
        let (cp, tmp) = mk_test_control();
        cp.conn.lock().execute_batch("DELETE FROM control_ledger; DELETE FROM control_checkpoint;").expect("fixture : journal vierge");
        crate::rbac::armer_la_signature_du_journal_de_controle(cp.db_path.as_str(), Some(ed25519_dalek::SigningKey::from_bytes(&AX6_CLE)));
        (tenant_test_state("ax6-adm", "ax6-edi", "ax6-sa", Some(cp)), tmp)
    }

    #[test]
    fn p10_7r_base_pleine_ou_transaction_annulee_par_la_base_la_ligne_dit_l_etat_relu() {
        let _env = VERROU_ENV_PROCESSUS.read();
        const ENFANT: &str = "P107R_AX6_ENFANT_PLEIN";
        if std::env::var(ENFANT).is_ok() {
            let (st, _t) = ax6_etat();
            let conn = || st.tenants.control.as_ref().expect("mode 1").conn.lock();
            let sql = |s: &str| conn().execute_batch(s).unwrap_or_else(|e| panic!("fixture `{s}` : {e}"));
            let etat = |kind: &str| {
                let c = conn();
                let m: i64 = c.query_row("SELECT COUNT(*) FROM control_ledger", [], |r| r.get(0)).expect("compte des maillons");
                let p: i64 = c.query_row("SELECT COUNT(*) FROM control_checkpoint", [], |r| r.get(0)).expect("compte des points");
                println!("AX6-ETAT-{kind}:{m}/{p}");
                println!("AX6-FERME-{kind}:{}", c.is_autocommit());
            };
            let rendre = |kind: &str, detail: &str| {
                let issue = control_ledger_append(&st, kind, "sa-ax6-acteur", "tenant-ax6-cible", detail);
                println!("AX6-ISSUE-{kind}:{}", issue.cause_de_non_inscription().unwrap_or("INSCRIT").replace(' ', "_"));
                etat(kind);
            };
            let gros = "x".repeat(200_000);
            rendre("ax6.nominal", "raison-ax6");
            sql("CREATE TABLE ax6_englobante(x INTEGER);");
            // Base pleine : le plafond de pages posé à la taille courante, puis un détail qui exige des pages neuves.
            {
                let c = conn();
                let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0)).expect("page_count");
                c.execute_batch(&format!("PRAGMA max_page_count = {pages};")).expect("plafond de pages");
            }
            rendre("ax6.plein", &gros);
            // Sous une transaction ENGLOBANTE de l'appelant, qui a déjà écrit (une petite ligne : aucune page neuve).
            sql("BEGIN; INSERT INTO ax6_englobante VALUES (1);");
            rendre("ax6.englobante", &gros);
            let survivantes: i64 = conn().query_row("SELECT COUNT(*) FROM ax6_englobante", [], |r| r.get(0)).expect("compte englobante");
            println!("AX6-ENGLOBANTE-SURVIVANTES:{survivantes}");
            // Le plafond levé : un maillon nominal s'inscrit avec son point, la chaîne se vérifie.
            sql("PRAGMA max_page_count = 1073741823;");
            rendre("ax6.apres", "raison-ax6");
            let epinglee = ed25519_dalek::SigningKey::from_bytes(&AX6_CLE).verifying_key().to_bytes();
            println!("AX6-VERDICT:{}", crate::rbac::verdict_de_verify_control(&conn(), Some(&epinglee)).0);
            // `RAISE(ROLLBACK)` du point de contrôle : la base annule toute la transaction.
            sql("CREATE TRIGGER ax6_rollback BEFORE INSERT ON control_checkpoint BEGIN SELECT RAISE(ROLLBACK, 'ax6 rollback du point'); END;");
            rendre("ax6.rollback", "raison-ax6");
            sql("DROP TRIGGER ax6_rollback;");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::sauvegarde_sur_base_absente_et_base_pleine_dites::p10_7r_base_pleine_ou_transaction_annulee_par_la_base_la_ligne_dit_l_etat_relu",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let jetons: Vec<&str> = stdout.split(['\n', ' ']).collect();
        let non_ecrit = AX6_CAUSE_NON_ECRIT.replace(' ', "_");
        let point = AX6_CAUSE_POINT.replace(' ', "_");
        let attendus = [
            "AX6-ISSUE-ax6.nominal:INSCRIT".to_string(),
            "AX6-ETAT-ax6.nominal:1/1".to_string(),
            "AX6-FERME-ax6.nominal:true".to_string(),
            format!("AX6-ISSUE-ax6.plein:{non_ecrit}"),
            "AX6-ETAT-ax6.plein:1/1".to_string(),
            "AX6-FERME-ax6.plein:true".to_string(),
            format!("AX6-ISSUE-ax6.englobante:{non_ecrit}"),
            "AX6-ETAT-ax6.englobante:1/1".to_string(),
            "AX6-FERME-ax6.englobante:true".to_string(),
            "AX6-ENGLOBANTE-SURVIVANTES:0".to_string(),
            "AX6-ISSUE-ax6.apres:INSCRIT".to_string(),
            "AX6-ETAT-ax6.apres:2/2".to_string(),
            "AX6-VERDICT:0".to_string(),
            format!("AX6-ISSUE-ax6.rollback:{point}"),
            "AX6-ETAT-ax6.rollback:2/2".to_string(),
            "AX6-FERME-ax6.rollback:true".to_string(),
        ];
        for attendu in &attendus {
            assert!(jetons.contains(&attendu.as_str()), "{attendu} : {stdout}\n{stderr}");
        }
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[control_ledger] WARN")).collect();
        assert_eq!(
            lignes,
            vec![AX6_LIGNE_PLEIN, AX6_LIGNE_ENGLOBANTE, AX6_LIGNE_ROLLBACK],
            "trois lignes entières, l'état relu (autocommit), aucune pour les maillons nominaux : {stderr}"
        );
    }
}
