// `P10.33-u` — LA PORTE NE ROUVRE JAMAIS LE FICHIER DE BASE : SES VERROUS POSIX TIENNENT
// ================================================================================================
// LE DÉFAUT, MESURÉ EN PRODUCTION LE 2026-10-18 (pod f2631ec). `open_with_prelude` appelait l'aveu de
// la base en clair, qui lisait les seize premiers octets par `std::fs::File::open(plume.db)` puis
// fermait ce descripteur. Sémantique POSIX : fermer UN descripteur d'un inode lâche TOUS les verrous
// `fcntl` du processus sur cet inode. SQLite n'en sait rien et croit garder son SHARED. Le sidecar de
// sauvegarde (un AUTRE processus), en fermant sa connexion, a obtenu l'EXCLUSIVE, s'est cru seul,
// a fait son checkpoint et a DÉLIÉ `-wal` et `-shm` sous le démon : une partie du pool est restée sur
// le WAL délié, une autre est née sur un WAL neuf sans les pages de l'ancien
// (45 lectures SQLITE_IOERR_SHORT_READ, code étendu 522, en vingt minutes).
//
// LE TÉMOIN rejoue la scène à DEUX PROCESSUS, parce que la propriété n'existe qu'entre processus :
// le parent ouvre par la porte (`PreparedDb::open`), garde la connexion et écrit dans le WAL ; un
// ENFANT (ce binaire de test, relancé) ouvre la même base et la ferme. Le parent exige ensuite que
// `-wal` et `-shm` existent toujours et que sa ligne se relise.
//
// MUTANT JOUÉ (retiré du source avant le commit) : `fd_rouvert` — un `std::fs::File::open(path)` lâché
// juste après l'aveu dans `open_with_prelude` -> rouge (l'enfant délie `-wal`).
//
// CE QUE CE FICHIER NE TIENT PAS : il ne juge que la PORTE de l'environnement (`open_with_prelude`) ;
// les autres ouvertures brutes du produit sont relues par l'audit consigné sous `P10.33-u`.
mod porte_ne_lache_pas_les_verrous_du_wal {
    use super::*;

    const P1033U_ENFANT: &str = "P1033U_ENFANT_BASE";

    #[test]
    fn p10_33u_un_autre_processus_qui_ferme_la_base_ne_delie_pas_le_wal_de_la_porte() {
        if let Ok(base) = std::env::var(P1033U_ENFANT) {
            // L'ENFANT : la sous-commande du sidecar, réduite à son geste — ouvrir, lire, fermer.
            let c = rusqlite::Connection::open(&base).expect("enfant : ouverture");
            let n: i64 = c.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0)).expect("enfant : lecture");
            assert!(n > 0, "enfant : la base a un schéma");
            drop(c);
            return;
        }
        let _env = VERROU_ENV_PROCESSUS.read();
        if db_key().is_some() || base_en_clair_declaree(&load_config()) {
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "p10_33u_un_autre_processus_qui_ferme_la_base_ne_delie_pas_le_wal_de_la_porte",
                "la configuration ambiante porte une clé at-rest ou déclare le clair voulu : la porte \
                 sans clé (le chemin qui rouvrait le fichier) n'a PAS été exercée sur cette machine.",
            );
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033u-verrous");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("plume.db").to_string_lossy().into_owned();
        let wal = format!("{base}-wal");
        let shm = format!("{base}-shm");

        drop(crate::db_open::PreparedDb::open(&base).expect("naissance par la porte"));
        {
            let c = rusqlite::Connection::open(&base).unwrap();
            let mode: String = c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).unwrap();
            assert_eq!(mode, "wal", "fixture : la base est en WAL, comme en production");
        }

        let db = crate::db_open::PreparedDb::open(&base).expect("la porte ouvre");
        db.execute_batch("CREATE TABLE p1033u_temoin(x INTEGER); INSERT INTO p1033u_temoin VALUES (1033);").unwrap();
        assert!(std::path::Path::new(&wal).exists() && std::path::Path::new(&shm).exists(), "fixture : -wal et -shm existent");

        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::porte_ne_lache_pas_les_verrous_du_wal::p10_33u_un_autre_processus_qui_ferme_la_base_ne_delie_pas_le_wal_de_la_porte",
            ])
            .env(P1033U_ENFANT, &base)
            .output()
            .expect("enfant lancé");
        assert!(sortie.status.success(), "l'enfant a ouvert, lu et fermé : {}", String::from_utf8_lossy(&sortie.stderr));

        assert!(std::path::Path::new(&wal).exists(), "un autre processus a fermé la base et a DÉLIÉ le -wal tenu par la porte");
        assert!(std::path::Path::new(&shm).exists(), "un autre processus a fermé la base et a DÉLIÉ le -shm tenu par la porte");
        let x: i64 = db.query_row("SELECT x FROM p1033u_temoin", [], |r| r.get(0)).expect("la porte relit sa ligne");
        assert_eq!(x, 1033);
    }
}
