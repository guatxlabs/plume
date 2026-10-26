// =====================================================================================
// INTÉGRITÉ DE LA RESTAURATION ET DE LA SAUVEGARDE MANUELLE (`backup/dump_restauration.rs`, `backup/mod.rs`) —
// LA DESTINATION N'EST TOUCHÉE QU'UNE FOIS LE NOUVEAU CONTENU COMPLET.
//
// LES DÉFAUTS, LUS SUR f5d7008c :
//  * `restore_compressed` effaçait la destination ET ses compagnons `-wal`/`-shm` AVANT de lire le flux jusqu'à sa
//    sentinelle (B1) ou avant le `sqlcipher_export` (legacy). Un flux tronqué, une sentinelle absente, un `COMMIT`
//    refusé ou un export refusé rendait une erreur APRÈS l'effacement : avec `restore <src> --force`, dont la
//    destination par défaut est `PLUME_DB`, la base saine était perdue ;
//  * `backup_compressed` effaçait la destination avant d'avoir une archive neuve (B1 et legacy), puis l'effaçait encore
//    sur échec : rejouée sous un nom fixe, une sauvegarde ratée détruisait la dernière bonne archive ;
//  * une destination de sauvegarde qui désignait la base vivante (le fichier, un lien dur, un compagnon) n'était pas
//    refusée : la base était effacée sous la connexion qui la lisait.
//
// DÉSORMAIS : la restauration s'écrit dans `<dest>.restauration-en-cours`, la sauvegarde dans
// `<dest>.sauvegarde-en-cours` (même répertoire) ; la destination n'est remplacée que par UN `rename` une fois le
// contenu complet (sentinelle et `COMMIT` jugés pour la restauration, compagnons `-wal`/`-shm`/`-journal` retirés juste
// avant ; archive vidée et synchronisée, erreurs jugées, pour la sauvegarde).
// Toute erreur retire le temporaire et laisse la destination identique octet pour octet. Une destination de
// sauvegarde qui désigne la base vivante est refusée par `stat` (périphérique + inode) ou par son nom dans le même
// répertoire canonique, sans ouvrir aucun fichier de la base.
//
// LES VOIES D'ÉCHEC FABRIQUÉES : archive `.age` coupée en son milieu (vraie sauvegarde B1) ; dump B1 forgé sans
// sentinelle, avec une sentinelle fausse, ou dont le post-DDL valide déjà la transaction (le `COMMIT` final est alors
// refusé par le moteur) ; fichier SQLite en clair dont une table porte une collation inconnue (l'export la refuse
// après avoir créé la table précédente dans la base attachée) ; destination qui est un répertoire non vide (le
// `rename` final est refusé) ; destinataire age invalide (la sauvegarde échoue après la création de son fichier) ;
// journal CHAUD d'une ancienne base en mode rollback posé à côté de la destination ; limite de taille de fichier
// (`RLIMIT_FSIZE`, dans un sous-processus) posée pendant la sauvegarde, que seul le dernier vidage de l'archive franchit.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : un échec du `rename` de la restauration survient APRÈS le retrait des
// compagnons `-wal`/`-shm`/`-journal` de la destination (le fichier principal reste, ses compagnons non) — l'ordre
// est choisi pour qu'un arrêt brutal entre les deux ne laisse jamais la base restaurée à côté du WAL ou du journal de
// l'ancienne ; deux sauvegardes concurrentes vers la même destination partagent le même temporaire ; le `sync_all`
// de l'archive avant son `rename` (sa durabilité ne se voit qu'après une coupure de courant).
// =====================================================================================

mod restauration_et_sauvegarde_ecrites_a_cote {
    use super::*;
    use crate::backup::{SUFFIXE_RESTAURATION_EN_COURS, SUFFIXE_SAUVEGARDE_EN_COURS};

    const CLE: &str = "ar3-cle-de-test-de-restauration";

    fn chemin(racine: &std::path::Path, nom: &str) -> String {
        racine.join(nom).to_string_lossy().into_owned()
    }

    fn existe(p: &str) -> bool {
        std::path::Path::new(p).exists()
    }

    /// Base SQLCipher à une ligne `valeur` dans `t(v)`.
    fn base_avec(chemin: &str, valeur: &str) {
        let c = open_db_keyed(chemin, Some(CLE)).unwrap();
        c.execute_batch("CREATE TABLE t(v TEXT);").unwrap();
        c.execute("INSERT INTO t VALUES(?1)", [valeur]).unwrap();
    }

    /// La valeur de `t`, lue avec la clé : la base est lisible ET porte ce contenu.
    fn valeur_de(chemin: &str) -> String {
        let c = open_db_keyed(chemin, Some(CLE)).unwrap();
        c.query_row("SELECT v FROM t", [], |r| r.get(0)).expect("base lisible avec la clé")
    }

    /// age(zstd(charge)) chiffré à la passphrase `CLE` — la même enveloppe que `backup_compressed`.
    fn archive_de(charge: &[u8], chemin: &str) {
        use std::io::Write;
        let out = std::fs::File::create(chemin).unwrap();
        let w = crate::backup::backup_encryptor(CLE, None).unwrap().wrap_output(out).unwrap();
        let mut z = zstd::Encoder::new(w, 3).unwrap();
        z.write_all(charge).unwrap();
        z.finish().unwrap().finish().unwrap();
    }

    fn ecrire_u32(v: &mut Vec<u8>, n: u32) {
        v.extend_from_slice(&n.to_le_bytes());
    }
    fn ecrire_str(v: &mut Vec<u8>, s: &str) {
        ecrire_u32(v, s.len() as u32);
        v.extend_from_slice(s.as_bytes());
    }

    /// Dump B1 forgé : une table `t(v)` portant la ligne 'restauree', les instructions de post-DDL `post`, puis la
    /// sentinelle si elle est donnée (`None` : le flux s'arrête juste avant elle).
    fn dump_b1(post: &[&str], sentinelle: Option<u8>) -> Vec<u8> {
        let mut v = b"PLUMEDUMP1\n".to_vec();
        ecrire_u32(&mut v, 1);
        ecrire_str(&mut v, "CREATE TABLE t(v TEXT)");
        ecrire_u32(&mut v, 1);
        ecrire_str(&mut v, "t");
        v.extend_from_slice(&1u16.to_le_bytes());
        ecrire_str(&mut v, "INSERT INTO t (v) VALUES (?)");
        v.push(1); // ligne présente
        v.push(3); // TEXT
        ecrire_str(&mut v, "restauree");
        v.push(0); // fin de table
        ecrire_u32(&mut v, 0); // sqlite_sequence
        ecrire_u32(&mut v, post.len() as u32);
        for sql in post {
            v.push(1);
            ecrire_str(&mut v, sql);
        }
        if let Some(s) = sentinelle {
            v.push(s);
        }
        v
    }

    /// Les octets de la destination et de ses deux compagnons, tels qu'ils sont avant la restauration.
    struct Instantane {
        base: Vec<u8>,
        wal: Vec<u8>,
        shm: Vec<u8>,
    }

    /// Destination saine : une base SQLCipher portant 'ancienne', et deux compagnons `-wal`/`-shm` présents.
    fn destination_saine(dest: &str) -> Instantane {
        base_avec(dest, "ancienne");
        std::fs::write(format!("{dest}-wal"), b"compagnon -wal de l'ancienne base").unwrap();
        std::fs::write(format!("{dest}-shm"), b"compagnon -shm de l'ancienne base").unwrap();
        Instantane {
            base: std::fs::read(dest).unwrap(),
            wal: std::fs::read(format!("{dest}-wal")).unwrap(),
            shm: std::fs::read(format!("{dest}-shm")).unwrap(),
        }
    }

    /// La destination est identique octet pour octet (fichier et compagnons), et aucun temporaire ne reste.
    fn assert_intacte(dest: &str, avant: &Instantane, cas: &str) {
        assert!(std::fs::read(dest).unwrap() == avant.base, "{cas} : la base de destination a changé");
        assert!(std::fs::read(format!("{dest}-wal")).unwrap() == avant.wal, "{cas} : le compagnon -wal a changé");
        assert!(std::fs::read(format!("{dest}-shm")).unwrap() == avant.shm, "{cas} : le compagnon -shm a changé");
        let en_cours = format!("{dest}{SUFFIXE_RESTAURATION_EN_COURS}");
        assert!(!existe(&en_cours), "{cas} : le temporaire {en_cours} est resté");
        assert!(!existe(&format!("{en_cours}-journal")), "{cas} : le journal du temporaire est resté");
        assert_eq!(valeur_de(dest), "ancienne", "{cas} : la base de destination n'est plus lisible telle qu'elle était");
    }

    fn suffixe_intacte(dest: &str) -> String {
        format!(" — la destination {dest} est INTACTE : la restauration s'écrivait dans {dest}{SUFFIXE_RESTAURATION_EN_COURS}, qui a été retiré.")
    }

    /// Une vraie sauvegarde B1 assez grosse pour s'étendre sur plusieurs blocs age (64 Kio), coupée en son milieu :
    /// la tête (marqueur compris) se déchiffre, la suite manque. C'est le flux tronqué d'un transfert interrompu.
    #[test]
    fn ar3_archive_coupee_en_son_milieu_laisse_la_destination_intacte() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-coupee");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "src.db");
        {
            let c = open_db_keyed(&src, Some(CLE)).unwrap();
            c.execute_batch("CREATE TABLE t(v TEXT); CREATE TABLE b(x BLOB); INSERT INTO t VALUES('neuve');").unwrap();
            let mut etat: u64 = 0x9E37_79B9_7F4A_7C15;
            for _ in 0..384 {
                let mut blob = vec![0u8; 1024];
                for o in blob.iter_mut() {
                    etat ^= etat << 13;
                    etat ^= etat >> 7;
                    etat ^= etat << 17;
                    *o = (etat >> 24) as u8;
                }
                c.execute("INSERT INTO b VALUES(?1)", [blob]).unwrap();
            }
        }
        let archive = chemin(&racine, "complete.age");
        backup_compressed(&src, &archive, Some(CLE), None).expect("sauvegarde B1");
        assert!(backup_payload_head(&archive, CLE).starts_with(b"PLUMEDUMP1\n"), "la fixture doit emprunter le chemin B1");
        let octets = std::fs::read(&archive).unwrap();
        assert!(octets.len() > 3 * 65_536, "la fixture doit couvrir plusieurs blocs age ({} o)", octets.len());
        let coupee = chemin(&racine, "coupee.age");
        std::fs::write(&coupee, &octets[..octets.len() / 2]).unwrap();

        let dest = chemin(&racine, "plume.db");
        let avant = destination_saine(&dest);
        let err = restore_compressed(&coupee, &dest, Some(CLE), true, None).expect_err("un flux coupé doit être refusé");
        assert!(err.ends_with(&suffixe_intacte(&dest)), "le refus dit que la destination est intacte : {err}");
        assert_intacte(&dest, &avant, "archive coupée");
    }

    /// Le dump s'arrête juste avant sa sentinelle : tout le reste a été rejoué dans le temporaire.
    #[test]
    fn ar3_dump_sans_sentinelle_laisse_la_destination_intacte() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-sans-sentinelle");
        let racine = _tmp.racine().chemin().to_path_buf();
        let archive = chemin(&racine, "sans-sentinelle.age");
        archive_de(&dump_b1(&[], None), &archive);
        let dest = chemin(&racine, "plume.db");
        let avant = destination_saine(&dest);
        let err = restore_compressed(&archive, &dest, Some(CLE), true, None).expect_err("sentinelle manquante");
        assert_eq!(err, format!("restore : lecture sentinelle : failed to fill whole buffer{}", suffixe_intacte(&dest)));
        assert_intacte(&dest, &avant, "sans sentinelle");
    }

    #[test]
    fn ar3_sentinelle_fausse_laisse_la_destination_intacte() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-sentinelle-fausse");
        let racine = _tmp.racine().chemin().to_path_buf();
        let archive = chemin(&racine, "sentinelle-fausse.age");
        archive_de(&dump_b1(&[], Some(0x00)), &archive);
        let dest = chemin(&racine, "plume.db");
        let avant = destination_saine(&dest);
        let err = restore_compressed(&archive, &dest, Some(CLE), true, None).expect_err("sentinelle fausse");
        assert_eq!(err, format!("restore : sentinelle de fin absente (0x00) — dump tronqué/corrompu{}", suffixe_intacte(&dest)));
        assert_intacte(&dest, &avant, "sentinelle fausse");
    }

    /// Le post-DDL valide la transaction lui-même : le `COMMIT` final de `restore_stream` est refusé par le moteur.
    #[test]
    fn ar3_commit_refuse_laisse_la_destination_intacte() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-commit");
        let racine = _tmp.racine().chemin().to_path_buf();
        let archive = chemin(&racine, "commit-refuse.age");
        archive_de(&dump_b1(&["COMMIT"], Some(0xFF)), &archive);
        let dest = chemin(&racine, "plume.db");
        let avant = destination_saine(&dest);
        let err = restore_compressed(&archive, &dest, Some(CLE), true, None).expect_err("COMMIT refusé");
        assert!(err.starts_with("commit restore : "), "le refus vient du COMMIT final : {err}");
        assert!(err.ends_with(&suffixe_intacte(&dest)), "le refus dit que la destination est intacte : {err}");
        assert_intacte(&dest, &avant, "COMMIT refusé");
    }

    /// Chemin legacy : le fichier SQLite en clair porte une première table saine, puis une table dont la collation
    /// est inconnue. L'export crée la première dans la base attachée (le temporaire existe), puis refuse la seconde.
    #[test]
    fn ar3_legacy_refuse_au_sqlcipher_export_laisse_la_destination_intacte() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-legacy-refuse");
        let racine = _tmp.racine().chemin().to_path_buf();
        let clair = chemin(&racine, "clair.db");
        {
            let c = open_db_keyed(&clair, None).unwrap();
            c.execute_batch(
                "CREATE TABLE t(v TEXT); INSERT INTO t VALUES('legacy');
                 CREATE TABLE u(w TEXT); INSERT INTO u VALUES('x');
                 PRAGMA writable_schema=ON;
                 UPDATE sqlite_master SET sql='CREATE TABLE u(w TEXT COLLATE collation_inconnue_ar3)' WHERE name='u';
                 PRAGMA writable_schema=OFF;").unwrap();
        }
        let archive = chemin(&racine, "legacy-refuse.age");
        archive_de(&std::fs::read(&clair).unwrap(), &archive);
        let dest = chemin(&racine, "plume.db");
        let avant = destination_saine(&dest);
        let err = restore_compressed(&archive, &dest, Some(CLE), true, None).expect_err("export refusé");
        assert!(err.starts_with("re-chiffrement (sqlcipher_export) : "), "le refus vient de l'export : {err}");
        assert!(err.ends_with(&suffixe_intacte(&dest)), "le refus dit que la destination est intacte : {err}");
        assert_intacte(&dest, &avant, "legacy refusé à l'export");
    }

    /// Succès B1 : la base restaurée prend la place de la destination par un `rename` (un lien dur vers l'ancienne
    /// base garde l'ancien contenu : rien n'a été réécrit en place), les compagnons de l'ancienne base sont retirés,
    /// aucun temporaire ne reste, et la base se lit avec la clé.
    #[test]
    fn ar3_succes_b1_publie_par_rename_et_retire_les_compagnons() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-succes-b1");
        let racine = _tmp.racine().chemin().to_path_buf();
        let archive = chemin(&racine, "valide.age");
        archive_de(&dump_b1(&[], Some(0xFF)), &archive);
        let dest = chemin(&racine, "plume.db");
        let avant = destination_saine(&dest);
        let lien = chemin(&racine, "ancienne-par-lien-dur.db");
        std::fs::hard_link(&dest, &lien).unwrap();

        restore_compressed(&archive, &dest, Some(CLE), true, None).expect("restauration valide");
        assert!(!existe(&format!("{dest}-wal")), "le compagnon -wal de l'ancienne base doit être retiré");
        assert!(!existe(&format!("{dest}-shm")), "le compagnon -shm de l'ancienne base doit être retiré");
        assert!(!existe(&format!("{dest}{SUFFIXE_RESTAURATION_EN_COURS}")), "aucun temporaire ne reste");
        assert!(std::fs::read(&lien).unwrap() == avant.base,
            "le lien dur garde l'ancien contenu : la destination a été remplacée par rename, pas réécrite en place");
        assert_eq!(valeur_de(&dest), "restauree", "la base restaurée se lit avec la clé");
    }

    /// Un temporaire laissé par une tentative précédente (arrêt brutal) est retiré avant de commencer : sans ce
    /// retrait, SQLCipher l'ouvrirait comme une base et la restauration échouerait.
    #[test]
    fn ar3_un_temporaire_residuel_est_retire_avant_de_commencer() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-residu");
        let racine = _tmp.racine().chemin().to_path_buf();
        let archive = chemin(&racine, "valide.age");
        archive_de(&dump_b1(&[], Some(0xFF)), &archive);
        let dest = chemin(&racine, "plume.db");
        let en_cours = format!("{dest}{SUFFIXE_RESTAURATION_EN_COURS}");
        std::fs::write(&en_cours, vec![0x5Au8; 8192]).unwrap();

        restore_compressed(&archive, &dest, Some(CLE), false, None).expect("restauration malgré le résidu");
        assert!(!existe(&en_cours), "le résidu ne reste pas");
        assert_eq!(valeur_de(&dest), "restauree");
    }

    /// Succès legacy : même publication (compagnons retirés, aucun temporaire), base re-chiffrée lisible avec la clé.
    #[test]
    fn ar3_succes_legacy_publie_la_base_rechiffree() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-succes-legacy");
        let racine = _tmp.racine().chemin().to_path_buf();
        let clair = chemin(&racine, "clair.db");
        {
            let c = open_db_keyed(&clair, None).unwrap();
            c.execute_batch("CREATE TABLE t(v TEXT); INSERT INTO t VALUES('legacy');").unwrap();
        }
        let archive = chemin(&racine, "legacy.age");
        archive_de(&std::fs::read(&clair).unwrap(), &archive);
        let dest = chemin(&racine, "plume.db");
        destination_saine(&dest);

        restore_compressed(&archive, &dest, Some(CLE), true, None).expect("restauration legacy");
        assert!(!existe(&format!("{dest}-wal")), "le compagnon -wal de l'ancienne base doit être retiré");
        assert!(!existe(&format!("{dest}-shm")), "le compagnon -shm de l'ancienne base doit être retiré");
        assert!(!existe(&format!("{dest}{SUFFIXE_RESTAURATION_EN_COURS}")), "aucun temporaire ne reste");
        assert_eq!(valeur_de(&dest), "legacy", "la base re-chiffrée se lit avec la clé");
    }

    /// Le `rename` final refusé (la destination est un répertoire non vide) : le temporaire est retiré, le
    /// répertoire n'est pas touché, et le refus le dit.
    #[test]
    fn ar3_rename_de_restauration_refuse_retire_le_temporaire() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-rename-restauration");
        let racine = _tmp.racine().chemin().to_path_buf();
        let archive = chemin(&racine, "valide.age");
        archive_de(&dump_b1(&[], Some(0xFF)), &archive);
        let dest = chemin(&racine, "repertoire");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(format!("{dest}/garde"), b"contenu").unwrap();
        // Les compagnons de l'ancienne base, posés à côté : leur retrait PRÉCÈDE le `rename`, ils ont donc disparu
        // même quand ce `rename` est refusé (l'ordre inverse les laisserait, et c'est ce que le refus affirme).
        let wal = format!("{dest}-wal");
        let shm = format!("{dest}-shm");
        let journal = format!("{dest}-journal");
        std::fs::write(&wal, b"compagnon -wal de l'ancienne base").unwrap();
        std::fs::write(&shm, b"compagnon -shm de l'ancienne base").unwrap();
        std::fs::write(&journal, b"compagnon -journal de l'ancienne base").unwrap();

        let err = restore_compressed(&archive, &dest, Some(CLE), true, None).expect_err("rename refusé");
        let en_cours = format!("{dest}{SUFFIXE_RESTAURATION_EN_COURS}");
        let tete = format!("restore : la base restaurée n'a pas pu prendre la place de {dest} (");
        let queue = format!(") ; le temporaire {en_cours} a été retiré. {dest} n'a pas été remplacée, mais ses compagnons -wal, -shm et -journal avaient déjà été retirés.");
        assert!(err.starts_with(&tete) && err.ends_with(&queue), "refus du rename : {err}");
        assert!(!existe(&en_cours), "le temporaire ne reste pas");
        assert_eq!(std::fs::read(format!("{dest}/garde")).unwrap(), b"contenu");
        assert!(!existe(&wal), "le compagnon -wal est retiré AVANT le rename, refusé ou non");
        assert!(!existe(&shm), "le compagnon -shm est retiré AVANT le rename, refusé ou non");
        assert!(!existe(&journal), "le compagnon -journal est retiré AVANT le rename, refusé ou non");
    }

    /// La destination porte le journal CHAUD d'une ancienne base en mode rollback (arrêt brutal en pleine transaction :
    /// la base modifiée en place et son `-journal`). La base restaurée, COMPLÈTE, prend sa place par `rename` : si ce
    /// journal restait à côté, SQLite le rejouerait sur elle dès la première ouverture, et on relirait l'ancien contenu
    /// sans aucun signal. Le journal est retiré avec les autres compagnons, et la base relue est celle de l'archive.
    #[test]
    fn ar3_journal_chaud_de_l_ancienne_base_n_est_pas_rejoue_sur_la_restauree() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-journal-chaud");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "src.db");
        base_avec(&src, "restauree");
        let archive = chemin(&racine, "archive.age");
        backup_compressed(&src, &archive, Some(CLE), None).expect("archive");

        let ancienne = chemin(&racine, "ancienne.db");
        {
            let c = open_db_keyed(&ancienne, Some(CLE)).unwrap();
            c.execute_batch(
                "PRAGMA journal_mode=DELETE; CREATE TABLE t(v TEXT); INSERT INTO t VALUES('ancienne');
                 CREATE TABLE f(x BLOB);
                 WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<3000) INSERT INTO f SELECT randomblob(300) FROM n;").unwrap();
        }
        let dest = chemin(&racine, "plume.db");
        let journal = format!("{dest}-journal");
        {
            let c = open_db_keyed(&ancienne, Some(CLE)).unwrap();
            // Cache minuscule : la transaction déborde et écrit ses pages DANS la base, le journal garde les anciennes.
            c.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA cache_size=10; BEGIN; UPDATE t SET v='modifiee'; UPDATE f SET x=randomblob(300);").unwrap();
            let j = format!("{ancienne}-journal");
            assert!(existe(&j), "contrôle : le journal de la transaction en cours existe");
            std::fs::copy(&ancienne, &dest).unwrap();
            std::fs::copy(&j, &journal).unwrap();
            c.execute_batch("ROLLBACK").unwrap();
        }
        assert!(std::fs::metadata(&journal).unwrap().len() > 0, "contrôle : journal chaud posé à côté de la destination");

        restore_compressed(&archive, &dest, Some(CLE), true, None).expect("restauration valide");
        // Relevé AVANT la lecture : une ouverture qui rejoue le journal l'efface ensuite.
        let journal_reste = existe(&journal);
        assert_eq!(valeur_de(&dest), "restauree",
            "la base relue doit être celle de l'archive, pas l'ancienne rejouée (journal de l'ancienne base resté : {journal_reste})");
        assert!(!journal_reste, "le journal de l'ancienne base est retiré avant la publication");
    }

    // ── SAUVEGARDE ────────────────────────────────────────────────────────────────────────────────

    /// La cause d'une sauvegarde qui devait être refusée (`BackupStats` n'implémente pas `Debug`).
    fn refus_de_sauvegarde(r: Result<crate::backup::BackupStats, String>, cas: &str) -> String {
        match r {
            Ok(_) => panic!("{cas} : la sauvegarde devait être refusée, elle a abouti"),
            Err(e) => e,
        }
    }

    /// Base source SQLCipher `<racine>/plume.db` portant `valeur`.
    fn source(racine: &std::path::Path, valeur: &str) -> String {
        let src = chemin(racine, "plume.db");
        base_avec(&src, valeur);
        src
    }

    /// La sauvegarde B1 échoue APRÈS avoir créé son fichier (destinataire age invalide) : la dernière bonne archive
    /// reste identique et restaurable, et aucun temporaire ne reste.
    #[test]
    fn ar3_sauvegarde_ratee_laisse_la_derniere_bonne_archive() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-sauvegarde-ratee");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = source(&racine, "v1");
        let dest = chemin(&racine, "nom-fixe.db.age");
        backup_compressed(&src, &dest, Some(CLE), None).expect("première sauvegarde");
        let bonne = std::fs::read(&dest).unwrap();

        let err = refus_de_sauvegarde(backup_compressed(&src, &dest, Some(CLE), Some("age1-pas-une-cle-publique")), "destinataire invalide");
        assert!(err.starts_with("destinataire age invalide (clé publique age1... attendue) : "), "cause : {err}");
        assert!(std::fs::read(&dest).unwrap() == bonne, "la dernière bonne archive doit rester identique");
        assert!(!existe(&format!("{dest}{SUFFIXE_SAUVEGARDE_EN_COURS}")), "aucun temporaire ne reste");
        let restauree = chemin(&racine, "restauree.db");
        restore_compressed(&dest, &restauree, Some(CLE), false, None).expect("la dernière bonne archive reste restaurable");
        assert_eq!(valeur_de(&restauree), "v1");
    }

    /// Même échec sur le chemin legacy forcé (`backup/mod.rs`) : il effaçait la destination puis en créait une vide.
    #[test]
    fn ar3_sauvegarde_legacy_ratee_laisse_la_derniere_bonne_archive() {
        let _reglages = VERROU_ENV_PROCESSUS.write(); // ce test POSE un réglage
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-sauvegarde-legacy-ratee");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = source(&racine, "v1");
        let dest = chemin(&racine, "nom-fixe.db.age");
        backup_compressed(&src, &dest, Some(CLE), None).expect("première sauvegarde");
        let bonne = std::fs::read(&dest).unwrap();

        let err = {
            let _force = ReglageBackupPose::neuf(crate::backup::CLE_BACKUP_FORCE_PLAINTEXT_EXPORT, "1");
            refus_de_sauvegarde(backup_compressed(&src, &dest, Some(CLE), Some("age1-pas-une-cle-publique")), "destinataire invalide")
        };
        assert!(err.starts_with("destinataire age invalide (clé publique age1... attendue) : "), "cause : {err}");
        assert!(std::fs::read(&dest).unwrap() == bonne, "la dernière bonne archive doit rester identique (chemin legacy)");
        let mut restant: Vec<String> = std::fs::read_dir(&racine).unwrap()
            .flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        restant.sort();
        assert_eq!(restant, vec!["nom-fixe.db.age".to_string(), "plume.db".to_string()],
            "ni temporaire de sauvegarde ni clair ne restent");
    }

    /// Succès : l'archive neuve prend la place de l'ancienne par un `rename` (le lien dur vers l'ancienne archive
    /// garde son contenu), aucun temporaire ne reste. La destination est `<base>.age`, la destination par défaut de
    /// `backup --compress` : à côté de la base, sous un autre nom, elle n'est PAS refusée.
    #[test]
    fn ar3_sauvegarde_reussie_publie_par_rename() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-sauvegarde-reussie");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = source(&racine, "v1");
        let dest = format!("{src}.age");
        backup_compressed(&src, &dest, Some(CLE), None).expect("première sauvegarde");
        let ancienne = std::fs::read(&dest).unwrap();
        let lien = chemin(&racine, "ancienne-archive-par-lien-dur.age");
        std::fs::hard_link(&dest, &lien).unwrap();
        open_db_keyed(&src, Some(CLE)).unwrap().execute("UPDATE t SET v='v2'", []).unwrap();

        backup_compressed(&src, &dest, Some(CLE), None).expect("seconde sauvegarde vers <base>.age");
        assert!(!existe(&format!("{dest}{SUFFIXE_SAUVEGARDE_EN_COURS}")), "aucun temporaire ne reste");
        assert!(std::fs::read(&lien).unwrap() == ancienne,
            "le lien dur garde l'ancienne archive : la destination a été remplacée par rename, pas réécrite en place");
        let restauree = chemin(&racine, "restauree.db");
        restore_compressed(&dest, &restauree, Some(CLE), false, None).expect("archive neuve restaurable");
        assert_eq!(valeur_de(&restauree), "v2");
    }

    /// Le `rename` de publication refusé (destination = répertoire non vide) : temporaire retiré, refus dit.
    #[test]
    fn ar3_rename_de_sauvegarde_refuse_retire_le_temporaire() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-rename-sauvegarde");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = source(&racine, "v1");
        let dest = chemin(&racine, "repertoire");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(format!("{dest}/garde"), b"contenu").unwrap();

        let err = refus_de_sauvegarde(backup_compressed(&src, &dest, Some(CLE), None), "rename refusé");
        let en_cours = format!("{dest}{SUFFIXE_SAUVEGARDE_EN_COURS}");
        let tete = format!("backup : l'archive complète n'a pas pu prendre la place de {dest} (");
        let queue = format!(") ; le temporaire {en_cours} a été retiré et {dest} n'a pas été remplacée.");
        assert!(err.starts_with(&tete) && err.ends_with(&queue), "refus du rename : {err}");
        assert!(!existe(&en_cours), "le temporaire ne reste pas");
        assert_eq!(std::fs::read(format!("{dest}/garde")).unwrap(), b"contenu");
    }

    fn refus_base_vivante(dest: &str, quoi: &str) -> String {
        format!("backup REFUSÉ : la destination {dest} désigne {quoi} — y écrire l'archive détruirait la base. \
                 Choisissez un chemin hors de la base et de ses compagnons (-wal, -shm, -journal).")
    }

    /// Une destination qui désigne la base vivante est refusée avant tout geste : la base elle-même, un lien dur
    /// (même inode sous un autre nom : seul `stat` le voit), et chacun des trois compagnons sous son nom, absents du
    /// disque (seule la comparaison des noms les voit). La base reste identique et aucun temporaire n'est créé.
    #[test]
    fn ar3_destination_qui_designe_la_base_vivante_est_refusee() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-base-vivante");
        let racine = _tmp.racine().chemin().to_path_buf();
        let db = source(&racine, "vivante");
        let avant = std::fs::read(&db).unwrap();

        let err = refus_de_sauvegarde(backup_compressed(&db, &db, Some(CLE), None), "la base elle-même");
        assert_eq!(err, refus_base_vivante(&db, "la base vivante elle-même"));

        let lien = chemin(&racine, "autre-nom-meme-inode.db");
        std::fs::hard_link(&db, &lien).unwrap();
        let err = refus_de_sauvegarde(backup_compressed(&db, &lien, Some(CLE), None), "lien dur vers la base");
        assert_eq!(err, refus_base_vivante(&lien, "la base vivante elle-même"));

        let wal = format!("{db}-wal");
        assert!(!existe(&wal), "le compagnon -wal est absent : seul son nom peut le désigner");
        let err = refus_de_sauvegarde(backup_compressed(&db, &wal, Some(CLE), None), "compagnon -wal");
        assert_eq!(err, refus_base_vivante(&wal, "le compagnon -wal de la base vivante"));

        let shm = format!("{db}-shm");
        let err = refus_de_sauvegarde(backup_compressed(&db, &shm, Some(CLE), None), "compagnon -shm");
        assert_eq!(err, refus_base_vivante(&shm, "le compagnon -shm de la base vivante"));

        let journal = format!("{db}-journal");
        let err = refus_de_sauvegarde(backup_compressed(&db, &journal, Some(CLE), None), "compagnon -journal");
        assert_eq!(err, refus_base_vivante(&journal, "le compagnon -journal de la base vivante"));

        assert!(std::fs::read(&db).unwrap() == avant, "la base vivante n'a pas changé");
        assert!(std::fs::read(&lien).unwrap() == avant, "le lien dur n'a pas changé");
        let mut restant: Vec<String> = std::fs::read_dir(&racine).unwrap()
            .flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        restant.sort();
        assert_eq!(restant, vec!["autre-nom-meme-inode.db".to_string(), "plume.db".to_string()],
            "aucun compagnon ni temporaire n'a été créé");
    }

    /// Un compagnon ABSENT désigné par un chemin écrit autrement : par `sous/..`, et par un lien symbolique vers le
    /// répertoire de la base. `stat` ne le voit pas (il n'existe pas) ; seule la comparaison des répertoires RENDUS
    /// CANONIQUES le reconnaît. Sans elle, l'archive serait publiée sous le nom `plume.db-journal`, à côté de la base.
    #[test]
    fn ar3_compagnon_absent_ecrit_autrement_est_refuse() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-compagnon-canonique");
        let racine = _tmp.racine().chemin().to_path_buf();
        let db = source(&racine, "vivante");
        std::fs::create_dir(racine.join("sous")).unwrap();
        std::os::unix::fs::symlink(&racine, racine.join("sous").join("lien-vers-la-racine")).unwrap();
        let par_point_point = format!("{}/sous/../plume.db-journal", racine.display());
        let par_lien = format!("{}/sous/lien-vers-la-racine/plume.db-journal", racine.display());
        let refuse = |dest: &str| {
            assert!(!existe(dest), "contrôle : le compagnon -journal est absent ({dest})");
            let err = refus_de_sauvegarde(backup_compressed(&db, dest, Some(CLE), None), dest);
            assert_eq!(err, refus_base_vivante(dest, "le compagnon -journal de la base vivante"));
        };
        refuse(&par_point_point);
        refuse(&par_lien);
        assert!(!existe(&format!("{db}-journal")), "aucune archive n'a été publiée sous le nom du compagnon");
        let mut restant: Vec<String> = std::fs::read_dir(&racine).unwrap()
            .flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        restant.sort();
        assert_eq!(restant, vec!["plume.db".to_string(), "sous".to_string()], "aucun temporaire n'a été créé");
    }

    // ── VIDAGE FINAL DE L'ARCHIVE ─────────────────────────────────────────────────────────────────

    /// Variable qui fait jouer à un test son rôle d'ENFANT (valeur `b1` ou `legacy`) : la limite de taille de fichier
    /// est un attribut du PROCESSUS, elle se pose dans un sous-processus pour ne gêner aucun autre test.
    const ENFANT_VIDAGE: &str = "AR3_ENFANT_VIDAGE_FINAL";
    const MARQUE_VIDAGE: &str = "AR3-VIDAGE:";
    /// Au-dessus de la première archive (une ligne), sous la seconde (64 Kio aléatoires, incompressibles).
    const LIMITE_DE_TAILLE: u64 = 16_384;

    /// L'ENFANT. Une première sauvegarde (sans limite) donne la dernière bonne archive ; la base reçoit 64 Kio
    /// aléatoires ; la seconde sauvegarde vise le même nom. Un guetteur pose `RLIMIT_FSIZE` dès que le temporaire
    /// `<dest>.sauvegarde-en-cours` existe : tout ce qui précède (le clair du legacy compris) s'écrit sans limite, et
    /// l'archive, plus petite que le tampon d'1 Mio, n'atteint le fichier qu'à son DERNIER vidage, qui franchit la
    /// limite. Le facteur scrypt relevé (16) élargit la fenêtre entre la création du temporaire et ce vidage. Un essai
    /// où la limite est arrivée trop tard (archive publiée au-delà de la limite) n'éprouve rien : il est rejoué.
    fn sonder_le_vidage_final_dans_l_enfant(legacy: bool) {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let _reglages = VERROU_ENV_PROCESSUS.write(); // l'enfant POSE des réglages
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ar3-vidage-final");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = source(&racine, "v1");
        let _force = legacy.then(|| ReglageBackupPose::neuf(crate::backup::CLE_BACKUP_FORCE_PLAINTEXT_EXPORT, "1"));
        let dest = chemin(&racine, "nom-fixe.db.age");
        backup_compressed(&src, &dest, Some(CLE), None).expect("première sauvegarde");
        let bonne = std::fs::read(&dest).unwrap();
        assert!((bonne.len() as u64) < LIMITE_DE_TAILLE, "contrôle : la première archive tient sous la limite ({} o)", bonne.len());
        {
            let c = open_db_keyed(&src, Some(CLE)).unwrap();
            let mut etat: u64 = 0x1234_5678_9ABC_DEF1;
            let mut blob = vec![0u8; 65_536];
            for o in blob.iter_mut() {
                etat ^= etat << 13;
                etat ^= etat >> 7;
                etat ^= etat << 17;
                *o = (etat >> 24) as u8;
            }
            c.execute_batch("CREATE TABLE b(x BLOB);").unwrap();
            c.execute("INSERT INTO b VALUES(?1)", [blob]).unwrap();
        }
        let _lent = ReglageBackupPose::neuf(crate::backup::CLE_BACKUP_SCRYPT_LOG_N, "16");
        let en_cours = format!("{dest}{SUFFIXE_SAUVEGARDE_EN_COURS}");
        let mut sans_limite = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: appels système sans pointeur conservé ; l'enfant ne joue que ce test.
        unsafe {
            assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut sans_limite), 0);
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN); // l'écriture rend EFBIG au lieu de tuer le processus
        }
        let essais_max = 40;
        for essai in 1..=essais_max {
            let arreter = Arc::new(AtomicBool::new(false));
            let posee = Arc::new(AtomicBool::new(false));
            let guetteur = {
                let (arreter, posee, en_cours) = (arreter.clone(), posee.clone(), en_cours.clone());
                std::thread::spawn(move || {
                    while !arreter.load(Ordering::SeqCst) {
                        if std::path::Path::new(&en_cours).exists() {
                            let limite = libc::rlimit { rlim_cur: LIMITE_DE_TAILLE, rlim_max: sans_limite.rlim_max };
                            // SAFETY: appel système sans pointeur conservé.
                            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limite) }, 0);
                            posee.store(true, Ordering::SeqCst);
                            return;
                        }
                        std::thread::sleep(std::time::Duration::from_micros(50));
                    }
                })
            };
            let r = backup_compressed(&src, &dest, Some(CLE), None);
            arreter.store(true, Ordering::SeqCst);
            guetteur.join().unwrap();
            // SAFETY: appel système sans pointeur conservé.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &sans_limite) }, 0);
            let apres = std::fs::read(&dest).unwrap();
            let limite_trop_tard = r.is_ok() && apres.len() as u64 > LIMITE_DE_TAILLE;
            if !posee.load(Ordering::SeqCst) || limite_trop_tard {
                eprintln!("essai {essai} non probant (limite posée : {}, archive {} o)", posee.load(Ordering::SeqCst), apres.len());
                continue;
            }
            let issue = match &r { Ok(_) => "Ok".to_string(), Err(e) => e.clone() };
            let restauree = chemin(&racine, &format!("restauree-{essai}.db"));
            let relue = match restore_compressed(&dest, &restauree, Some(CLE), false, None) {
                Ok(()) => valeur_de(&restauree),
                Err(e) => format!("non restaurable ({e})"),
            };
            println!("{MARQUE_VIDAGE}{issue}|derniere bonne intacte={}|temporaire reste={}|relue={relue}", apres == bonne, existe(&en_cours));
            return;
        }
        println!("{MARQUE_VIDAGE}aucun essai probant sur {essais_max}");
    }

    /// Le verdict de l'enfant : la sauvegarde rend l'échec du dernier vidage (EFBIG, comme le rendrait ENOSPC), la
    /// dernière bonne archive reste identique à l'octet et restaurable, et aucun temporaire ne reste.
    fn juger_le_vidage_final(sortie: &std::process::Output) {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        // La marque suit le « test … ... » de libtest sur la même ligne : on la cherche, pas en tête de ligne.
        let verdict: Vec<&str> = stdout.lines().filter_map(|l| l.split_once(MARQUE_VIDAGE).map(|(_, v)| v)).collect();
        assert_eq!(verdict, vec!["vidage final de l'archive : File too large (os error 27)|derniere bonne intacte=true|temporaire reste=false|relue=v1"],
            "verdict de l'enfant : {stdout}\n{stderr}");
    }

    /// Chemin B1 (`backup/dump_restauration.rs`).
    #[test]
    fn ar3_vidage_final_refuse_b1_laisse_la_derniere_bonne_archive() {
        if std::env::var(ENFANT_VIDAGE).as_deref() == Ok("b1") {
            sonder_le_vidage_final_dans_l_enfant(false);
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1",
                   "tests::restauration_et_sauvegarde_ecrites_a_cote::ar3_vidage_final_refuse_b1_laisse_la_derniere_bonne_archive"])
            .env(ENFANT_VIDAGE, "b1")
            .output()
            .expect("ré-exécution du binaire de test");
        juger_le_vidage_final(&sortie);
    }

    /// Chemin legacy forcé (`backup/mod.rs`, `backup_compressed_legacy`).
    #[test]
    fn ar3_vidage_final_refuse_legacy_laisse_la_derniere_bonne_archive() {
        if std::env::var(ENFANT_VIDAGE).as_deref() == Ok("legacy") {
            sonder_le_vidage_final_dans_l_enfant(true);
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1",
                   "tests::restauration_et_sauvegarde_ecrites_a_cote::ar3_vidage_final_refuse_legacy_laisse_la_derniere_bonne_archive"])
            .env(ENFANT_VIDAGE, "legacy")
            .output()
            .expect("ré-exécution du binaire de test");
        juger_le_vidage_final(&sortie);
    }
}
