    // ============================================================================================
    // SAUVEGARDE STREAMING — LE CLAIR SUR DISQUE : ce que le chemin par défaut achète, et comment
    // on le MESURE plutôt que de l'affirmer.
    // --------------------------------------------------------------------------------------------
    // Le chemin par DÉFAUT de `backup_compressed` sérialise un dump typé directement dans
    // zstd -> age -> `.age`, sans jamais matérialiser la base en clair. Le chemin HISTORIQUE
    // (`sqlcipher_export`, encore emprunté en repli et via `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT=1`)
    // pose au contraire une copie déchiffrée de tout le SOC dans le répertoire de staging le temps
    // du cycle. Les quatre tests de ce module éprouvent CETTE différence :
    //   - `..._leaves_the_staging_dir_empty_under_watch`      : surveillance CONTINUE, avec contrôle
    //   - `..._survives_an_unusable_staging_dir`              : la même garde SANS COURSE
    //   - `..._carries_multi_mib_blobs_within_a_bounded_memory_delta` : la RAM sous une ligne énorme
    //   - `..._is_smaller_than_the_plaintext_export_on_the_same_db`   : taille et temps, deux formats
    // La FIDÉLITÉ du dump (types, BLOB, FTS, sqlite_sequence) et le REPLI sur schéma non représentable
    // sont éprouvés ailleurs, par `backup_b1_parity_roundtrip` et
    // `backup_b1_falls_back_to_legacy_for_contentless_fts`.
    //
    // Comme `backup_retention_adverse.rs`, ce module s'appuie sur les helpers partagés du module de
    // tests (`open_db_keyed`, `backup_compressed`, `restore_compressed`, `migrate`,
    // `backup_payload_head`) : tous les fichiers de `tests/` sont inclus dans le MÊME module.
    //
    // AUCUN de ces tests ne pose `PLUME_BACKUP_STAGING_DIR`, et c'est délibéré : ils s'appuient sur la
    // résolution PAR DÉFAUT du staging (le répertoire de `dest`), qui est celle des déploiements
    // host/Docker — et ils ne peuvent donc pas faire rougir `f2_staging_dir_default_is_dest_parent`,
    // qui lit précisément l'ABSENCE de cette variable.
    // ============================================================================================

    /// Sérialise les tests qui posent `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT` (env PROCESS-global, lu à
    /// chaque backup). Cette variable n'est touchée QUE par ce module -> le verrou suffit.
    static BACKUP_PATH_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    /// Base SQLCipher au SCHÉMA RÉEL de plume (`db/schema.sql` + toute la chaîne de migrations, donc la
    /// FTS5 à contenu externe `event_fts` et ses déclencheurs) peuplée de `n` événements. C'est la base
    /// dont on veut prouver quelque chose : une fixture au schéma inventé ne dirait rien du chemin pris
    /// en production.
    fn bkst_seed_real_schema_db(path: &str, key: &str, n: i64) {
        let conn = open_db_keyed(path, Some(key)).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        conn.execute_batch("BEGIN;").unwrap();
        for i in 0..n {
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,host,message,fields) \
                 VALUES(?1,'sshd','auth',3,?2,?3,'{\"user\":\"root\",\"port\":22}')",
                params![1_700_000_000i64 + i, format!("host-{}", i % 64),
                        format!("failed password for invalid user u{i} from 10.0.{}.{} port {}", i % 251, i % 253, 1024 + (i % 40000))],
            ).unwrap();
        }
        conn.execute_batch("COMMIT;").unwrap();
    }

    /// SONDE DU RÉPERTOIRE DE STAGING — échantillonne `dir` en boucle SERRÉE depuis un fil dédié pendant
    /// que `body` s'exécute, et retient tout nom de fichier vu AU MOINS UNE FOIS. Renvoie
    /// `(retour de body, noms vus triés, nombre d'échantillons)`. Le nombre d'échantillons est rendu
    /// EXPRÈS : sans lui, « aucun nom vu » se lit « je n'ai pas mesuré » aussi bien que « c'est propre ».
    ///
    /// LIMITE ASSUMÉE : c'est un ÉCHANTILLONNAGE, pas une interception. Un fichier créé PUIS effacé entre
    /// deux lectures de répertoire passerait inaperçu. Deux choses bornent ce trou : (1) la boucle ne dort
    /// jamais — des centaines de milliers de lectures par sauvegarde, mesurées et assertées — alors que le
    /// clair du chemin historique vit pendant TOUTE la durée du dump, pas un instant ; (2) le test jumeau
    /// `backup_streaming_survives_an_unusable_staging_dir` ferme le trou PAR CONSTRUCTION, sans course :
    /// le staging y est rendu inaccessible en écriture, donc rien n'y est créable, même fugacement.
    fn bkst_watch_dir<T>(dir: &std::path::Path, body: impl FnOnce() -> T) -> (T, Vec<String>, u64) {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::sync::Arc;
        let stop = Arc::new(AtomicBool::new(false));
        let samples = Arc::new(AtomicU64::new(0));
        let seen: Arc<parking_lot::Mutex<std::collections::BTreeSet<String>>> = Arc::new(parking_lot::Mutex::new(Default::default()));
        let h = {
            let (d, stop, samples, seen) = (dir.to_path_buf(), stop.clone(), samples.clone(), seen.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(rd) = std::fs::read_dir(&d) {
                        for e in rd.flatten() { seen.lock().insert(e.file_name().to_string_lossy().into_owned()); }
                    }
                    samples.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        let out = body();
        stop.store(true, Ordering::Relaxed);
        h.join().unwrap();
        let names: Vec<String> = seen.lock().iter().cloned().collect();
        (out, names, samples.load(Ordering::Relaxed))
    }

    /// LA GARDE QUE LA SAUVEGARDE STREAMING ACHÈTE : pendant TOUTE la sauvegarde d'une base au SCHÉMA RÉEL
    /// de plume, RIEN n'apparaît dans le répertoire de staging à part le fichier de destination lui-même —
    /// surveillé en continu depuis un fil. (Le staging est ici le répertoire de `dest`, la résolution par
    /// défaut ; c'est pourquoi la destination fait partie de ce qui est légitimement vu.)
    ///
    /// Le test porte SON PROPRE CONTRÔLE, et c'est lui qui valide l'instrument : la même sonde, sur la même
    /// base, avec `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT=1` (chemin historique), DOIT voir apparaître un
    /// `.plain.tmp.`. Une sonde qui ne voit jamais rien, même quand le clair est là, ne prouverait rien du
    /// cas nominal.
    #[test]
    fn backup_streaming_leaves_the_staging_dir_empty_under_watch() {
        let _env = BACKUP_PATH_ENV_LOCK.lock();
        let _tmpg = crate::tmp_possede::TmpPossede::neuf("bkst-watch");
        let root = _tmpg.racine().chemin().to_path_buf();
        let key = "staging-watch-passphrase";
        let src = root.join("src.db").to_string_lossy().into_owned();
        bkst_seed_real_schema_db(&src, key, 20_000);

        // --- (1) CHEMIN PAR DÉFAUT (streaming) : rien d'autre que la destination ne doit apparaître. ---
        let d_stream = root.join("sortie-streaming");
        std::fs::create_dir_all(&d_stream).unwrap();
        let dest = d_stream.join("plume-x.db.age").to_string_lossy().into_owned();
        let (res, seen, samples) = bkst_watch_dir(&d_stream, || backup_compressed(&src, &dest, Some(key), None));
        let st = res.expect("sauvegarde streaming OK");
        eprintln!("[staging-watch] streaming : {samples} échantillons, noms vus = {seen:?}");
        // ce que le cycle DÉCLARE doit coïncider avec ce que la sonde OBSERVE — sinon le log opérateur ment.
        assert!(!st.wrote_plaintext_to_disk, "le cycle streaming ne doit PAS se déclarer écrivain de clair");
        assert!(samples >= 200, "la sonde doit avoir RÉELLEMENT échantillonné (n={samples}) — sinon « rien vu » ne veut rien dire");
        assert_eq!(seen, vec!["plume-x.db.age".to_string()],
            "seul le fichier de destination doit apparaître pendant la sauvegarde streaming ; vu : {seen:?}");
        // et le chemin effectivement pris sur le SCHÉMA RÉEL est bien le dump streaming (pas le repli).
        assert!(backup_payload_head(&dest, key).starts_with(b"PLUMEDUMP1\n"),
            "sur le schéma RÉEL de plume (event_fts à contenu externe), le chemin pris doit être le streaming");

        // --- (2) CONTRÔLE — VALIDATION DE L'INSTRUMENT : le chemin historique, lui, DOIT être vu. -------
        let d_hist = root.join("sortie-historique");
        std::fs::create_dir_all(&d_hist).unwrap();
        let dest_hist = d_hist.join("plume-x.db.age").to_string_lossy().into_owned();
        std::env::set_var("PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT", "1");
        let (res2, seen2, samples2) = bkst_watch_dir(&d_hist, || backup_compressed(&src, &dest_hist, Some(key), None));
        std::env::remove_var("PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT");
        let st2 = res2.expect("sauvegarde historique OK");
        eprintln!("[staging-watch] historique : {samples2} échantillons, noms vus = {seen2:?}");
        assert!(st2.wrote_plaintext_to_disk, "le cycle historique DOIT se déclarer écrivain de clair");
        assert!(seen2.iter().any(|n| n.contains(".plain.tmp.")),
            "l'instrument est INVALIDE s'il ne voit pas le clair du chemin historique ; vu : {seen2:?}");
        assert!(backup_payload_head(&dest_hist, key).starts_with(b"SQLite format 3"),
            "le chemin forcé produit bien l'ancien format (copie SQLite complète)");
        // à la SORTIE, le garde RAII a effacé ce clair : il ne reste que la destination.
        let restant: Vec<String> = std::fs::read_dir(&d_hist).unwrap()
            .flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(restant, vec!["plume-x.db.age".to_string()],
            "le garde RAII doit avoir effacé le clair du chemin historique à la sortie ; reste : {restant:?}");
    }

    /// LA MÊME GARDE, SANS COURSE — par CONSTRUCTION plutôt que par échantillonnage. Le répertoire de
    /// staging est rendu NON-INSCRIPTIBLE (mode 0555) : plus AUCUN fichier neuf n'y est créable, même une
    /// nanoseconde. Seule la destination, PRÉ-CRÉÉE, reste ouvrable en écriture (droit porté par le
    /// FICHIER, pas par le répertoire) — c'est ce qui isole la propriété testée : « aucun fichier NOUVEAU ».
    /// La sauvegarde streaming réussit quand même et se restaure fidèlement -> elle n'a donc créé aucun
    /// clair. Le contrôle inverse (chemin historique forcé) ÉCHOUE dans la même configuration : lui, il lui
    /// FAUT créer son temporaire. C'est la différence entre « on n'a rien vu » et « rien ne pouvait exister ».
    #[test]
    fn backup_streaming_survives_an_unusable_staging_dir() {
        use std::os::unix::fs::PermissionsExt;
        let _env = BACKUP_PATH_ENV_LOCK.lock();
        let _tmpg = crate::tmp_possede::TmpPossede::neuf("bkst-ro");
        let root = _tmpg.racine().chemin().to_path_buf();
        let key = "staging-non-inscriptible-passphrase";
        let src = root.join("src.db").to_string_lossy().into_owned();
        bkst_seed_real_schema_db(&src, key, 500);
        let orig_events: i64 = {
            let c = open_db_keyed(&src, Some(key)).unwrap();
            c.query_row("SELECT count(*) FROM event", [], |r| r.get(0)).unwrap()
        };

        let stage = root.join("staging-non-inscriptible");
        std::fs::create_dir_all(&stage).unwrap();
        let dest = stage.join("plume-x.db.age").to_string_lossy().into_owned();
        let dest_hist = stage.join("plume-historique.db.age").to_string_lossy().into_owned();
        // les DEUX destinations sont pré-créées : le contrôle doit échouer sur SON TEMPORAIRE, pas sur sa
        // destination — sinon il ne prouverait rien de plus que « le répertoire est en lecture seule ».
        std::fs::write(&dest, b"").unwrap();
        std::fs::write(&dest_hist, b"").unwrap();
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o555)).unwrap();

        // (1) STREAMING : réussit, et la restauration rend la base à l'identique.
        let st = backup_compressed(&src, &dest, Some(key), None).expect("le streaming ne crée aucun fichier dans le staging");
        assert!(!st.wrote_plaintext_to_disk, "aucun clair déclaré");
        let restored = root.join("restored.db").to_string_lossy().into_owned(); // HORS du staging
        restore_compressed(&dest, &restored, Some(key), true, None).expect("restauration OK");
        {
            let c = open_db_keyed(&restored, Some(key)).unwrap();
            let n: i64 = c.query_row("SELECT count(*) FROM event", [], |r| r.get(0)).unwrap();
            assert_eq!(n, orig_events, "base restaurée complète alors qu'aucun fichier neuf n'était créable dans le staging");
        }
        // le staging ne contient QUE les deux destinations pré-créées : rien n'y est né.
        let mut restant: Vec<String> = std::fs::read_dir(&stage).unwrap()
            .flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        restant.sort();
        assert_eq!(restant, vec!["plume-historique.db.age".to_string(), "plume-x.db.age".to_string()],
            "aucun fichier NOUVEAU dans le staging ; trouvé : {restant:?}");

        // (2) CONTRÔLE : le chemin historique, lui, ÉCHOUE — il ne peut pas créer son clair.
        std::env::set_var("PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT", "1");
        let hist = backup_compressed(&src, &dest_hist, Some(key), None);
        std::env::remove_var("PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT");
        assert!(hist.is_err(),
            "le chemin historique DOIT échouer quand son temporaire n'est pas créable — sinon le test ne prouve rien du streaming");

        // rend le répertoire effaçable par le garde de la fixture (Drop de TmpPossede).
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Pages résidentes du processus (RSS, en octets) lues dans `/proc/self/statm` — 2e champ × taille de
    /// page. Sans dépendance. `None` hors Linux/procfs indisponible (l'appelant dégrade alors le test en
    /// vérification de FIDÉLITÉ seule plutôt que de mentir sur une mesure absente).
    fn bkst_rss_bytes() -> Option<u64> {
        let s = std::fs::read_to_string("/proc/self/statm").ok()?;
        let resident: u64 = s.split_whitespace().nth(1)?.parse().ok()?;
        Some(resident * 4096) // taille de page = 4 KiB sur les cibles supportées
    }

    /// UNE LIGNE ÉNORME NE DOIT PAS FAIRE ENFLER LA MÉMOIRE. 16 BLOB de 4 Mio (64 Mio de charge utile)
    /// traversent le dump : on échantillonne le RSS PENDANT la sauvegarde et on exige que le PIC reste
    /// très en dessous de la charge — si le code accumulait la base, la table, ou une chaîne qui grandit,
    /// le delta vaudrait au moins les 64 Mio. On vérifie en plus que les octets ressortent EXACTS.
    ///
    /// CE QUE LA MESURE NE DIT PAS : le RSS est PROCESS-global et la suite tourne en parallèle — le delta
    /// mesuré MAJORE donc la consommation réelle de la sauvegarde (bruit des tests voisins inclus). Le seuil
    /// est choisi en conséquence : il discrimine « une ligne à la fois » de « toute la base », pas « 8 Mio »
    /// de « 12 Mio ». Le PLANCHER structurel reste une ligne + les tampons : `write_value_ref` écrit la
    /// cellule empruntée au pager SQLite sans la copier, et rien n'est retenu d'une ligne à l'autre.
    #[test]
    fn backup_streaming_carries_multi_mib_blobs_within_a_bounded_memory_delta() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::sync::Arc;
        const BLOB: usize = 4 << 20;   // 4 Mio par ligne
        const ROWS: usize = 16;        // 64 Mio de charge utile
        let _tmpg = crate::tmp_possede::TmpPossede::neuf("bkst-blob");
        let root = _tmpg.racine().chemin().to_path_buf();
        let key = "gros-blob-passphrase";
        let src = root.join("src.db").to_string_lossy().into_owned();
        let dest = root.join("bk.age").to_string_lossy().into_owned();
        let restored = root.join("restored.db").to_string_lossy().into_owned();

        // Contenu compressible mais NON trivial (motif dépendant de la ligne) -> zstd rapide, octets distincts.
        let mk_blob = |k: usize| -> Vec<u8> {
            let pat: Vec<u8> = (0..256u32).map(|b| (b as u8) ^ (k as u8)).collect();
            pat.iter().cycle().take(BLOB).copied().collect()
        };
        let mut orig_sums: Vec<u64> = Vec::new();
        {
            let w = open_db_keyed(&src, Some(key)).unwrap();
            w.execute_batch("CREATE TABLE gros(id INTEGER PRIMARY KEY, charge BLOB NOT NULL);").unwrap();
            for k in 0..ROWS {
                let b = mk_blob(k);
                orig_sums.push(b.iter().fold(0u64, |a, &x| a.wrapping_mul(31).wrapping_add(x as u64)));
                w.execute("INSERT INTO gros(id,charge) VALUES(?,?)", params![k as i64, b]).unwrap();
            }
        }

        // Sonde RSS : PIC observé pendant la sauvegarde (référence prise juste avant, base fermée).
        let base_rss = bkst_rss_bytes();
        let peak = Arc::new(AtomicU64::new(base_rss.unwrap_or(0)));
        let stop = Arc::new(AtomicBool::new(false));
        let h = {
            let (peak, stop) = (peak.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if let Some(r) = bkst_rss_bytes() { peak.fetch_max(r, Ordering::Relaxed); }
                }
            })
        };
        let stats = backup_compressed(&src, &dest, Some(key), None).expect("sauvegarde des gros BLOB OK");
        stop.store(true, Ordering::Relaxed);
        h.join().unwrap();

        assert!(stats.plaintext_bytes as usize >= BLOB * ROWS,
            "le dump doit avoir réellement transporté les {} Mio (mesuré : {} o)", (BLOB * ROWS) >> 20, stats.plaintext_bytes);
        if let Some(base) = base_rss {
            let delta = peak.load(Ordering::Relaxed).saturating_sub(base);
            eprintln!("[gros-blob] charge={} Mio  dump={} o  dest={} o  pic RSS - référence = {} Mio",
                (BLOB * ROWS) >> 20, stats.plaintext_bytes, stats.dest_bytes, delta >> 20);
            assert!(delta < (BLOB * ROWS / 2) as u64,
                "le pic RSS ({} Mio au-dessus de la référence) doit rester très inférieur à la charge de {} Mio — \
                 accumuler la base ou la table coûterait au moins autant",
                delta >> 20, (BLOB * ROWS) >> 20);
        } else {
            eprintln!("[gros-blob] /proc/self/statm indisponible : mesure mémoire NON faite (fidélité seule)");
        }

        // FIDÉLITÉ : les octets ressortent EXACTS après restauration.
        restore_compressed(&dest, &restored, Some(key), true, None).expect("restauration des gros BLOB OK");
        let c = open_db_keyed(&restored, Some(key)).unwrap();
        let mut stmt = c.prepare("SELECT id, charge FROM gros ORDER BY id").unwrap();
        let got: Vec<(i64, u64)> = stmt.query_map([], |r| {
            let b: Vec<u8> = r.get(1)?;
            Ok((r.get::<_, i64>(0)?, b.iter().fold(0u64, |a, &x| a.wrapping_mul(31).wrapping_add(x as u64))))
        }).unwrap().map(|x| x.unwrap()).collect();
        assert_eq!(got.len(), ROWS, "toutes les lignes restaurées");
        for (k, (id, sum)) in got.iter().enumerate() {
            assert_eq!(*id, k as i64, "rowid préservé");
            assert_eq!(*sum, orig_sums[k], "les {} Mio de la ligne {k} ressortent octet pour octet", BLOB >> 20);
        }
    }

    /// CE QUE LE DUMP N'EMPORTE PAS, MESURÉ — sur la MÊME base au schéma RÉEL de plume, on produit les
    /// DEUX formats et on compare taille du `.age` ET durée de restauration. Le dump streaming n'emporte
    /// ni les index ni les tables shadow FTS5 : il est plus PETIT, et la restauration repaie ce gain en
    /// RECONSTRUISANT ces index. Le test verrouille le sens de l'échange (streaming plus petit) et IMPRIME
    /// les deux durées — c'est de ces chiffres que vient le tableau de l'en-tête de `backup.rs`.
    #[test]
    fn backup_streaming_is_smaller_than_the_plaintext_export_on_the_same_db() {
        let _env = BACKUP_PATH_ENV_LOCK.lock();
        let _tmpg = crate::tmp_possede::TmpPossede::neuf("bkst-taille");
        let root = _tmpg.racine().chemin().to_path_buf();
        let key = "taille-comparee-passphrase";
        let src = root.join("src.db").to_string_lossy().into_owned();
        bkst_seed_real_schema_db(&src, key, 20_000);
        let src_bytes = std::fs::metadata(&src).map(|m| m.len()).unwrap_or(0);

        let dest_stream = root.join("bk-stream.age").to_string_lossy().into_owned();
        let dest_hist = root.join("bk-historique.age").to_string_lossy().into_owned();
        let re_stream = root.join("re-stream.db").to_string_lossy().into_owned();
        let re_hist = root.join("re-historique.db").to_string_lossy().into_owned();

        let st_stream = backup_compressed(&src, &dest_stream, Some(key), None).expect("sauvegarde streaming OK");
        assert!(backup_payload_head(&dest_stream, key).starts_with(b"PLUMEDUMP1\n"), "format streaming attendu");
        assert!(!st_stream.wrote_plaintext_to_disk, "le streaming n'écrit aucun clair");

        std::env::set_var("PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT", "1");
        let st_hist = backup_compressed(&src, &dest_hist, Some(key), None).expect("sauvegarde historique OK");
        std::env::remove_var("PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT");
        assert!(backup_payload_head(&dest_hist, key).starts_with(b"SQLite format 3"), "format historique attendu");
        assert!(st_hist.wrote_plaintext_to_disk, "le chemin historique écrit bien un clair");

        let t0 = std::time::Instant::now();
        restore_compressed(&dest_stream, &re_stream, Some(key), true, None).expect("restauration streaming OK");
        let ms_stream = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        restore_compressed(&dest_hist, &re_hist, Some(key), true, None).expect("restauration historique OK");
        let ms_hist = t1.elapsed().as_millis();

        eprintln!(
            "[taille-comparee] base={src_bytes} o | streaming: charge={} o dest={} o restore={ms_stream} ms | \
             historique: charge={} o dest={} o restore={ms_hist} ms",
            st_stream.plaintext_bytes, st_stream.dest_bytes, st_hist.plaintext_bytes, st_hist.dest_bytes);

        // L'échange, dans son sens : le dump n'emporte ni index ni shadow FTS -> `.age` PLUS PETIT.
        assert!(st_stream.dest_bytes < st_hist.dest_bytes,
            "le dump streaming ({} o) doit être plus petit que la copie SQLite complète ({} o)",
            st_stream.dest_bytes, st_hist.dest_bytes);

        // ...et les DEUX restaurations rendent la MÊME base utile (même nombre de lignes, FTS requêtable).
        for (label, path) in [("streaming", &re_stream), ("historique", &re_hist)] {
            let c = open_db_keyed(path, Some(key)).unwrap();
            let n: i64 = c.query_row("SELECT count(*) FROM event", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 20_000, "restauration {label} : tous les événements");
            let f: i64 = c.query_row("SELECT count(*) FROM event_fts WHERE event_fts MATCH 'password'", [], |r| r.get(0)).unwrap();
            assert_eq!(f, 20_000, "restauration {label} : l'index FTS5 est présent et requêtable");
        }
    }
