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
    //   - `..._peak_live_heap_follows_row_width_not_row_count` : le dump est O(la ligne), pas O(la table)
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

    /// Base à LIGNES LARGES : `lignes` lignes portant chacune UNE cellule BLOB de `octets_par_cellule`
    /// octets. Motif dépendant de la ligne -> contenu compressible (zstd rapide) mais DISTINCT d'une ligne
    /// à l'autre, donc une restauration infidèle se voit. Renvoie l'empreinte de chaque ligne.
    fn bkst_seed_lignes_larges(path: &str, key: &str, lignes: usize, octets_par_cellule: usize) -> Vec<u64> {
        let empreinte = |b: &[u8]| b.iter().fold(0u64, |a, &x| a.wrapping_mul(31).wrapping_add(x as u64));
        let mut sommes = Vec::with_capacity(lignes);
        let w = open_db_keyed(path, Some(key)).unwrap();
        w.execute_batch("CREATE TABLE gros(id INTEGER PRIMARY KEY, charge BLOB NOT NULL);").unwrap();
        for k in 0..lignes {
            let motif: Vec<u8> = (0..256u32).map(|b| (b as u8) ^ (k as u8)).collect();
            let b: Vec<u8> = motif.iter().cycle().take(octets_par_cellule).copied().collect();
            sommes.push(empreinte(&b));
            w.execute("INSERT INTO gros(id,charge) VALUES(?,?)", params![k as i64, b]).unwrap();
        }
        sommes
    }

    /// LE DUMP EST O(LA LIGNE), PAS O(LA TABLE) — et c'est CETTE propriété-là qui tient la contrainte dure
    /// de 2 Gio, pas un chiffre de mémoire.
    ///
    /// COMMENT ON LA PROUVE. On sauvegarde DEUX bases de MÊME LARGEUR de ligne (cellule de 4 Mio) et de
    /// NOMBRE de lignes différent (2 puis 16), et on exige que le PIC DE TAS VIVANT du fil ne BOUGE PAS.
    /// C'est une PROPRIÉTÉ (invariance en N), pas un seuil : la valeur du pic n'a pas à être devinée, seule
    /// sa STABILITÉ compte. Un code qui accumulerait la table écarterait les deux pics d'exactement la
    /// charge ajoutée — 56 Mio ici, presque trois ordres de grandeur au-dessus de la marge admise.
    ///
    /// POURQUOI PAS LE RSS. Le RSS est PROCESS-global : mesuré depuis un test qui tourne EN PARALLÈLE des
    /// 948 autres, il compte les allocations des voisins et son verdict dépend du nombre de cœurs, de
    /// l'ordonnancement et de l'allocateur. C'est ce qui a fait REFUSER un build de production le
    /// 2026-08-08 (+247 Mio observés pour 64 Mio de charge) alors que rien du chemin testé n'avait changé.
    /// L'instrument d'ici (`crate::tas_du_fil`) compte les octets Rust alloués moins libérés PAR CE FIL :
    /// un entier, insensible aux voisins, qui rend le même verdict partout.
    ///
    /// LA BORNE CONNUE, QUI RESTE. Le pic par ligne est intrinsèquement O(la plus grosse CELLULE) : côté
    /// restore, `rd_bytes` alloue la valeur entière, donc une cellule de 1 Gio coûte 1 Gio. Ce test ne
    /// prétend PAS l'exclure — il fait varier N à largeur CONSTANTE, donc il sépare exactement O(cellule),
    /// qu'on assume, de O(table), qu'on refuse.
    ///
    /// L'AUTRE TERME, CELUI QUI A FAIT ROUGIR LA PORTE — le KDF, pas le dump. Sur le chemin par
    /// PASSPHRASE, `age` choisit le facteur de travail scrypt par un ÉTALONNAGE AU CHRONO à CHAQUE
    /// sauvegarde (`target_scrypt_work_factor`, age 0.11 : viser ~1 s de CPU) et scrypt alloue
    /// 128·r·2^log_n octets, r=8 chez age (`primitives::scrypt` -> `ScryptParams::new(log_n, 8, 1, 32)`),
    /// soit 2^(10+log_n). MESURÉ le 2026-08-08 sur cette machine, six sauvegardes de
    /// suite : log_n a valu 13 PUIS 14 sans que rien change, soit un pic de tas de 9 439 995 o puis
    /// 17 828 603 o — un écart de 8 Mio dû au SEUL KDF, sur la MÊME base et le MÊME code. Ce qui suit
    /// est alors DÉDUIT, pas mesuré ici : le seuil de l'ancien test valait 32 Mio (charge/2), donc
    /// TOUTE machine assez rapide pour choisir log_n >= 16 le faisait rougir à coup sûr, sans qu'aucune
    /// ligne ne change ; age lui-même donne 18 comme « ~1 s sur une machine moderne », soit 256 Mio —
    /// l'ordre de grandeur des « +247 Mio » qui ont fait refuser 8618753. Ce terme est CONSTANT en N —
    /// il ne dit RIEN du streaming — mais il est ALÉATOIRE, donc
    /// l'invariance se mesure avec un DESTINATAIRE age asymétrique (x25519, pas de KDF). Le chemin de
    /// dump est le MÊME dans les deux modes : seul l'enveloppement de la clé de fichier change. Le bloc
    /// « LE TERME KDF, NOMMÉ » ci-dessous le mesure quand même, sur le chemin par défaut, en LISANT
    /// log_n dans l'en-tête du fichier produit — donc sans rien deviner.
    ///
    /// CE QUE L'INSTRUMENT NE VOIT PAS : les `malloc` du C lié. Le tampon de ligne du pager SQLite — donc
    /// la cellule qu'emprunte `ValueRef` — et les tampons internes de zstd ne sont pas du tas Rust. Une
    /// accumulation écrite en Rust (tampon qui grandit, lignes retenues, dump matérialisé avant écriture)
    /// est vue ; une accumulation qu'on délèguerait à SQLite (un `group_concat` dans le SELECT du plan)
    /// ne le serait pas.
    #[test]
    fn backup_streaming_peak_live_heap_follows_row_width_not_row_count() {
        // LARGEUR de ligne, CONSTANTE entre les deux mesures — et plus grande que TOUS les tampons de la
        // chaîne (BufWriter 1 Mio, chunks age 64 Kio, fenêtre zstd) : une ligne ne peut pas s'y cacher.
        const CELLULE: usize = 4 << 20;
        const PEU: usize = 2;        //  8 Mio de charge
        const BEAUCOUP: usize = 16;  // 64 Mio de charge — 8x plus de LIGNES, MÊME largeur
        // Marge admise sur l'INVARIANCE. Elle n'est pas devinée : l'écart MESURÉ entre les deux pics vaut
        // 368 o, et les DEUX pics sont sortis BIT-À-BIT identiques (1 147 968 o / 1 147 600 o) sur dix
        // exécutions du 2026-08-08 — cinq machine au repos, cinq sous douze boucles CPU. La MÊME charge
        // faisait pourtant passer le facteur scrypt de log_n=14 à log_n=12, soit 12 Mio de moins sur le
        // pic du chemin par défaut : c'est très exactement la sensibilité que cette mesure-ci n'a pas.
        // 64 Kio est 178x l'écart observé, et 900x SOUS les (BEAUCOUP-PEU)*CELLULE = 56 Mio qu'une
        // accumulation de la table produirait.
        const MARGE: u64 = 64 << 10;

        // LE VERROU, QUE LA VERSION RSS DE CE TEST N'AVAIT PAS : `backup_compressed` LIT
        // `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT` (env PROCESS-global) et trois tests de ce module le POSENT.
        // Sans le verrou, un voisin peut faire prendre à CETTE sauvegarde le chemin HISTORIQUE au milieu de
        // la mesure — un deuxième canal de non-déterminisme, indépendant du RSS.
        let _env = BACKUP_PATH_ENV_LOCK.lock();
        let _tmpg = crate::tmp_possede::TmpPossede::neuf("bkst-largeur");
        let root = _tmpg.racine().chemin().to_path_buf();
        let key = "largeur-de-ligne-passphrase";
        let src_peu = root.join("peu.db").to_string_lossy().into_owned();
        let src_beaucoup = root.join("beaucoup.db").to_string_lossy().into_owned();
        let dest_peu = root.join("peu.age").to_string_lossy().into_owned();
        let dest_beaucoup = root.join("beaucoup.age").to_string_lossy().into_owned();
        let restored = root.join("restored.db").to_string_lossy().into_owned();
        let sommes_peu = bkst_seed_lignes_larges(&src_peu, key, PEU, CELLULE);
        bkst_seed_lignes_larges(&src_beaucoup, key, BEAUCOUP, CELLULE);

        // DESTINATAIRE asymétrique jetable : supprime le terme KDF aléatoire de la mesure (cf. en-tête).
        let identite = age::x25519::Identity::generate();
        let destinataire = identite.to_public().to_string();

        // --- LA MESURE : le pic de tas VIVANT pendant chaque sauvegarde, sur le fil du test. -------------
        let (r_peu, pic_peu) = crate::tas_du_fil::pic_vivant_pendant(
            || backup_compressed(&src_peu, &dest_peu, Some(key), Some(&destinataire)));
        let st_peu = r_peu.expect("sauvegarde OK (peu de lignes)");
        let (r_beaucoup, pic_beaucoup) = crate::tas_du_fil::pic_vivant_pendant(
            || backup_compressed(&src_beaucoup, &dest_beaucoup, Some(key), Some(&destinataire)));
        let st_beaucoup = r_beaucoup.expect("sauvegarde OK (beaucoup de lignes)");
        eprintln!("[largeur-de-ligne] cellule={} Mio | {PEU} lignes : charge={} Mio dump={} o pic tas={} o \
                   | {BEAUCOUP} lignes : charge={} Mio dump={} o pic tas={} o",
            CELLULE >> 20, (PEU * CELLULE) >> 20, st_peu.plaintext_bytes, pic_peu,
            (BEAUCOUP * CELLULE) >> 20, st_beaucoup.plaintext_bytes, pic_beaucoup);

        // LE CHEMIN PRIS EST BIEN CELUI QU'ON MESURE : le streaming, jamais le repli historique (qui, lui,
        // matérialise la base en clair et n'a pas du tout le même profil mémoire).
        assert!(!st_peu.wrote_plaintext_to_disk && !st_beaucoup.wrote_plaintext_to_disk,
            "les deux mesures doivent porter sur le chemin STREAMING, pas sur le repli historique");
        // les deux dumps ont RÉELLEMENT transporté leur charge (sinon on comparerait deux non-événements).
        assert!(st_peu.plaintext_bytes as usize >= PEU * CELLULE,
            "le dump de {PEU} lignes doit transporter {} o (mesuré : {} o)", PEU * CELLULE, st_peu.plaintext_bytes);
        assert!(st_beaucoup.plaintext_bytes as usize >= BEAUCOUP * CELLULE,
            "le dump de {BEAUCOUP} lignes doit transporter {} o (mesuré : {} o)", BEAUCOUP * CELLULE, st_beaucoup.plaintext_bytes);

        // LA SONDE A BIEN VU CETTE SAUVEGARDE : le BufWriter de sortie (`BACKUP_BUF` = 1 Mio) est une
        // allocation Rust vivante pendant tout le dump. Un pic en dessous voudrait dire qu'on n'a rien mesuré.
        assert!(pic_peu >= BACKUP_BUF as u64 && pic_beaucoup >= BACKUP_BUF as u64,
            "la sonde doit avoir vu la sauvegarde allouer (au moins le tampon de sortie de {} o) ; pics = {pic_peu} o / {pic_beaucoup} o",
            BACKUP_BUF);

        // --- LA PROPRIÉTÉ : 8x plus de lignes, MÊME pic. -------------------------------------------------
        let ecart = pic_beaucoup.abs_diff(pic_peu);
        assert!(ecart <= MARGE,
            "le pic de tas doit suivre la LARGEUR de ligne, pas leur NOMBRE : {PEU} lignes -> {pic_peu} o, \
             {BEAUCOUP} lignes -> {pic_beaucoup} o (écart {ecart} o > marge {MARGE} o). Accumuler la table \
             aurait écarté les deux pics de {} o",
            (BEAUCOUP - PEU) * CELLULE);

        // --- CONTRÔLE — VALIDATION DE L'INSTRUMENT : la MÊME sonde, sur le MÊME fil, autour d'un code qui
        // accumule VOLONTAIREMENT N x CELLULE octets. Elle DOIT le voir, et le voir GRANDIR avec N. Sans ce
        // contrôle, « le pic n'a pas bougé » se lirait « la sonde est aveugle » aussi bien que « ça streame ».
        let accumule = |n: usize| -> usize {
            let retenu: Vec<Vec<u8>> = (0..n).map(|k| vec![k as u8; CELLULE]).collect();
            retenu.iter().map(|v| v.len()).sum()
        };
        let (octets_temoin, pic_temoin_peu) = crate::tas_du_fil::pic_vivant_pendant(|| accumule(PEU));
        assert_eq!(octets_temoin, PEU * CELLULE, "le témoin doit avoir retenu ce qu'il annonce");
        let (_, pic_temoin_beaucoup) = crate::tas_du_fil::pic_vivant_pendant(|| accumule(BEAUCOUP));
        let croissance_temoin = pic_temoin_beaucoup.saturating_sub(pic_temoin_peu);
        eprintln!("[largeur-de-ligne] témoin qui ACCUMULE : {PEU} lignes -> {pic_temoin_peu} o, \
                   {BEAUCOUP} lignes -> {pic_temoin_beaucoup} o (croissance {croissance_temoin} o)");
        assert!(croissance_temoin >= ((BEAUCOUP - PEU) * CELLULE) as u64,
            "l'instrument est INVALIDE s'il ne voit pas une accumulation délibérée : {PEU} -> {pic_temoin_peu} o, \
             {BEAUCOUP} -> {pic_temoin_beaucoup} o, croissance {croissance_temoin} o < {} o attendus",
            (BEAUCOUP - PEU) * CELLULE);

        // --- LE TERME KDF, NOMMÉ — la MÊME base, le chemin PAR DÉFAUT (passphrase). Le pic y grossit du
        // tampon scrypt, dont la taille est ANNONCÉE par l'en-tête age du fichier qu'on vient de produire
        // (`-> scrypt <sel> <log_n>`) : on ne devine rien, on lit. C'est ce terme — pas le dump — que la
        // mesure de RSS d'avant prenait pour une fuite du streaming.
        let dest_kdf = root.join("kdf.age").to_string_lossy().into_owned();
        let (r_kdf, pic_kdf) = crate::tas_du_fil::pic_vivant_pendant(
            || backup_compressed(&src_peu, &dest_kdf, Some(key), None));
        r_kdf.expect("sauvegarde OK (chemin par défaut, passphrase)");
        let tete = std::fs::read(&dest_kdf).expect("relecture de l'en-tête age");
        let log_n: u32 = String::from_utf8_lossy(&tete[..128.min(tete.len())])
            .lines().find_map(|l| l.strip_prefix("-> scrypt ").and_then(|a| a.split_whitespace().nth(1)).and_then(|n| n.parse().ok()))
            .expect("le chemin par défaut doit produire une strophe scrypt annonçant son log_n");
        let tampon_scrypt: u64 = 1u64 << (10 + log_n); // 128 · r(=8) · 2^log_n
        eprintln!("[largeur-de-ligne] KDF du chemin par défaut : log_n={log_n} -> tampon scrypt {tampon_scrypt} o ; \
                   pic tas={pic_kdf} o (contre {pic_peu} o pour la MÊME base avec un destinataire asymétrique)");
        assert!(pic_kdf >= tampon_scrypt,
            "le chemin par passphrase doit allouer AU MOINS le tampon scrypt que son propre en-tête annonce \
             (log_n={log_n} -> {tampon_scrypt} o) ; pic mesuré {pic_kdf} o");

        // --- FIDÉLITÉ : les octets ressortent EXACTS après restauration. ---------------------------------
        restore_compressed(&dest_peu, &restored, Some(key), true, Some(&identite)).expect("restauration OK");
        let c = open_db_keyed(&restored, Some(key)).unwrap();
        let mut stmt = c.prepare("SELECT id, charge FROM gros ORDER BY id").unwrap();
        let got: Vec<(i64, u64)> = stmt.query_map([], |r| {
            let b: Vec<u8> = r.get(1)?;
            Ok((r.get::<_, i64>(0)?, b.iter().fold(0u64, |a, &x| a.wrapping_mul(31).wrapping_add(x as u64))))
        }).unwrap().map(|x| x.unwrap()).collect();
        assert_eq!(got.len(), PEU, "toutes les lignes restaurées");
        for (k, (id, somme)) in got.iter().enumerate() {
            assert_eq!(*id, k as i64, "rowid préservé");
            assert_eq!(*somme, sommes_peu[k], "les {} Mio de la ligne {k} ressortent octet pour octet", CELLULE >> 20);
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
