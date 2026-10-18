// `P10.33-w` (seconde relecture) — LA VALIDATION D'UNE CIBLE DE PUITS `file` NE LÂCHE PAS LES VERROUS DE LA BASE, ET LE
// RÉPERTOIRE D'UN `PLUME_DB` RELATIF SANS DOSSIER EST LE RÉPERTOIRE COURANT.
//
// 1. `refuser_une_cible_sur_la_base_vivante` lit la base et ses compagnons par `std::fs::metadata` (stat, aucun
//    descripteur). Ouvrir puis fermer un descripteur sur la base depuis le processus qui la tient lâcherait TOUS ses
//    verrous POSIX (`P10.33-u`) : un autre processus qui ferme la base se croirait seul et délierait `-wal` et `-shm`.
//    Le témoin rejoue la scène à DEUX processus (patron de `porte_ne_lache_pas_les_verrous_du_wal.rs`) : la porte tient
//    la base en WAL, la validation tourne sur des cibles EXISTANTES (la boucle du lien dur s'exécute), puis un enfant
//    ouvre et ferme la base ; `-wal` et `-shm` doivent survivre.
// 2. `PLUME_DB=plume.db` (relatif, sans répertoire) : le répertoire de la base est « . ». Une cible posée dans le
//    répertoire courant est refusée par la branche répertoire ; une cible dans une racine séparée passe.
//
// MUTANTS JOUÉS (sous cfg!(test), par VERIF_MUT, retirés avant le commit) : `w_ouvre_le_compagnon` (la boucle du lien
// dur fait `File::open(..).metadata()`) -> témoin 1 rouge ; `w_dossier_relatif_ignore` (le repli « . » remplacé par un
// répertoire qui n'existe pas : branches répertoire et lien dur muettes) -> témoin 2 rouge.
mod puits_du_registre_garde_les_verrous_de_la_base {
    use super::*;

    const P1033W_ENFANT: &str = "P1033W_ENFANT_BASE";

    #[test]
    fn p1033w_valider_une_cible_existante_ne_lache_pas_les_verrous_de_la_base() {
        if let Ok(base) = std::env::var(P1033W_ENFANT) {
            // L'ENFANT : le geste du sidecar — ouvrir, lire, fermer.
            let c = rusqlite::Connection::open(&base).expect("enfant : ouverture");
            let n: i64 = c.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0)).expect("enfant : lecture");
            assert!(n > 0, "enfant : la base a un schéma");
            drop(c);
            return;
        }
        let _env = VERROU_ENV_PROCESSUS.write();
        if db_key().is_some() || base_en_clair_declaree(&load_config()) {
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "p1033w_valider_une_cible_existante_ne_lache_pas_les_verrous_de_la_base",
                "la configuration ambiante porte une clé at-rest ou déclare le clair voulu : la porte sans clé n'a PAS \
                 été ouverte, la validation n'a pas été jugée contre une base tenue en WAL sur cette machine.",
            );
            return;
        }
        let dossier_de_base = crate::tmp_possede::TmpPossede::neuf("p1033w-verrous");
        let racine_separee = crate::tmp_possede::TmpPossede::neuf("p1033w-verrous-racine");
        let base = dossier_de_base.join("plume.db").to_string_lossy().into_owned();
        let wal = format!("{base}-wal");
        let shm = format!("{base}-shm");
        drop(crate::db_open::PreparedDb::open(&base).expect("naissance par la porte"));
        {
            let c = rusqlite::Connection::open(&base).unwrap();
            let mode: String = c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).unwrap();
            assert_eq!(mode, "wal", "fixture : la base est en WAL, comme en production");
        }
        let db = crate::db_open::PreparedDb::open(&base).expect("la porte ouvre");
        db.execute_batch("CREATE TABLE p1033w_temoin(x INTEGER); INSERT INTO p1033w_temoin VALUES (1033);").unwrap();
        assert!(std::path::Path::new(&wal).exists() && std::path::Path::new(&shm).exists(), "fixture : -wal et -shm existent");

        let _db = ReglageBackupPose::neuf("PLUME_DB", &base);
        let _ctl = ReglageBackupPose::retire("PLUME_CONTROL_DB");
        let racine = racine_separee.to_path_buf();
        // Cible EXISTANTE neutre : acceptée, après avoir comparé son inode à la base et à ses compagnons.
        let neutre = racine.join("neutre.jsonl");
        std::fs::write(&neutre, b"").expect("cible neutre");
        assert!(ledger_file_target_validate(&racine, &neutre.to_string_lossy()).is_ok(), "contrôle : cible neutre acceptée");
        // Cible EXISTANTE liée en dur à la base : refusée par la boucle du lien dur.
        let lien = racine.join("lien.jsonl");
        std::fs::hard_link(&base, &lien).expect("lien dur vers la base");
        match ledger_file_target_validate(&racine, &lien.to_string_lossy()) {
            Ok(p) => panic!("lien dur vers la base ACCEPTÉ ({})", p.display()),
            Err(e) => assert!(e.starts_with(REFUS_PUITS_SUR_LA_BASE_VIVANTE) && e.contains("lien dur"), "refus inattendu : {e}"),
        }
        std::fs::remove_file(&lien).expect("retrait du lien");

        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::puits_du_registre_garde_les_verrous_de_la_base::p1033w_valider_une_cible_existante_ne_lache_pas_les_verrous_de_la_base",
            ])
            .env(P1033W_ENFANT, &base)
            .output()
            .expect("enfant lancé");
        assert!(sortie.status.success(), "l'enfant a ouvert, lu et fermé : {}", String::from_utf8_lossy(&sortie.stderr));
        assert!(std::path::Path::new(&wal).exists(), "la validation a lâché les verrous : l'enfant a DÉLIÉ le -wal tenu par la porte");
        assert!(std::path::Path::new(&shm).exists(), "la validation a lâché les verrous : l'enfant a DÉLIÉ le -shm tenu par la porte");
        let x: i64 = db.query_row("SELECT x FROM p1033w_temoin", [], |r| r.get(0)).expect("la porte relit sa ligne");
        assert_eq!(x, 1033);
    }

    #[test]
    fn p1033w_plume_db_relatif_sans_dossier_refuse_le_repertoire_courant() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _db = ReglageBackupPose::neuf("PLUME_DB", "plume.db");
        let _ctl = ReglageBackupPose::retire("PLUME_CONTROL_DB");
        let courant = std::env::current_dir().expect("répertoire courant").canonicalize().expect("canonique");
        // Cible INEXISTANTE (rien n'est créé dans le répertoire courant), nom neutre : seule la branche répertoire
        // peut la refuser.
        let cible = courant.join("p1033w-cible-voisine-de-la-base-relative.jsonl");
        assert!(!cible.exists(), "fixture : la cible n'existe pas");
        match ledger_file_target_validate(&courant, &cible.to_string_lossy()) {
            Ok(p) => panic!("PLUME_DB=plume.db : cible du répertoire courant ACCEPTÉE ({}) — le repli « . » est ignoré", p.display()),
            Err(e) => assert!(
                e.starts_with(REFUS_PUITS_SUR_LA_BASE_VIVANTE) && e.contains("répertoire"),
                "refus inattendu : {e}"
            ),
        }
        // Contre-épreuve : même PLUME_DB, racine séparée -> acceptée (le refus vient bien du répertoire).
        let separee = crate::tmp_possede::TmpPossede::neuf("p1033w-relatif-racine");
        let racine = separee.to_path_buf();
        assert!(
            ledger_file_target_validate(&racine, &racine.join("audit.jsonl").to_string_lossy()).is_ok(),
            "contre-épreuve : cible hors du répertoire courant refusée"
        );
    }
}
