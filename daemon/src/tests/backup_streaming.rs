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

    // LE VERROU DES RÉGLAGES DE SAUVEGARDE vit désormais dans `common.rs` (`BACKUP_ENV_LOCK`), avec le
    // garde RAII `ReglageBackupPose` qui restaure la valeur antérieure même sous panic. Il y a été déplacé
    // parce que l'énoncé « cette variable n'est touchée QUE par ce module » était FAUX de deux manières :
    // `PLUME_BACKUP_REQUIRE_ASYMMETRIC` est posée par un test de `detection.rs`, et une douzaine de tests
    // d'autres fichiers déclenchent une sauvegarde — donc LISENT ces réglages — sans prendre le verrou.
    // Un verrou local à ce fichier ne pouvait pas porter une propriété qui est celle du binaire entier.
    //
    // `PLUME_BACKUP_SCRYPT_LOG_N` n'est toujours posée par AUCUN test, et c'est délibéré : la décision
    // qu'elle pilote est une fonction PURE (`scrypt_log_n_depuis`) qu'on éprouve en lui passant la chaîne.
    // Poser la vraie variable aurait imposé son facteur de travail à la trentaine de tests voisins qui
    // sauvegardent par passphrase — jusqu'à 1 073 741 824 octets de scrypt chacun. Une borne ne s'éprouve
    // pas en armant la bombe.

    /// Le `log_n` ANNONCÉ par la strophe `-> scrypt <sel> <log_n>` de l'en-tête age d'un fichier.
    /// `None` s'il n'y a pas de strophe scrypt (cas d'un fichier chiffré à un destinataire x25519) :
    /// c'est ce `None` qui sert de TÉMOIN NÉGATIF — un lecteur qui rendrait toujours une valeur ne
    /// prouverait rien. L'en-tête age v1 est du texte ASCII en tête de fichier, donc 512 octets suffisent
    /// très largement (la strophe est en 2ᵉ ligne).
    fn bkst_log_n_annonce(chemin: &str) -> Option<u32> {
        let octets = std::fs::read(chemin).expect("relecture de l'en-tête age");
        String::from_utf8_lossy(&octets[..512.min(octets.len())])
            .lines()
            .find_map(|l| l.strip_prefix("-> scrypt ").and_then(|a| a.split_whitespace().nth(1)).and_then(|n| n.parse().ok()))
    }

    /// Réécrit le `log_n` de la strophe scrypt d'un `.age` EXISTANT, sans rien rechiffrer. Sert à
    /// FABRIQUER un fichier qui EXIGE un facteur de travail donné pour un coût nul : `age` compare
    /// `log_n` au plafond de l'identité AVANT d'exécuter le moindre tour de scrypt
    /// (`age-0.11.3/src/scrypt.rs`, le `if log_n > self.max_work_factor` précède l'appel à `scrypt`).
    /// Produire pour de vrai un fichier à log_n=21 coûterait 2 Gio et des minutes ; le forger coûte un
    /// `replace`. Le fichier résultant est évidemment INDÉCHIFFRABLE (la clé dérivée ne correspondra
    /// plus) — c'est sans importance : on n'éprouve que la borne, et le témoin ci-dessous montre
    /// justement qu'un log_n SOUS le plafond échoue d'une AUTRE manière.
    fn bkst_forge_log_n(source: &str, dest: &str, nouveau_log_n: u32) {
        let octets = std::fs::read(source).expect("lecture du backup source");
        let tete_len = 512.min(octets.len());
        let tete = String::from_utf8_lossy(&octets[..tete_len]).into_owned();
        let ligne = tete.lines().find(|l| l.starts_with("-> scrypt "))
            .expect("le fichier source doit porter une strophe scrypt").to_string();
        let sel = ligne.split_whitespace().nth(2).expect("sel de la strophe").to_string();
        let remplacee = format!("-> scrypt {sel} {nouveau_log_n}");
        let mut sortie = tete.replacen(&ligne, &remplacee, 1).into_bytes();
        sortie.extend_from_slice(&octets[tete_len..]);
        std::fs::write(dest, &sortie).expect("écriture du backup forgé");
        assert_eq!(bkst_log_n_annonce(dest), Some(nouveau_log_n),
            "la forge doit avoir réellement changé le log_n annoncé (sinon le test ne mesure rien)");
    }

    /// Base SQLCipher MINUSCULE (une table, une ligne) : de quoi produire un `.age` valide sans payer
    /// une seconde de dump. Les tests de KDF n'éprouvent que l'enveloppe, jamais la charge.
    fn bkst_seed_minuscule(path: &str, key: &str) {
        let w = open_db_keyed(path, Some(key)).unwrap();
        w.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT NOT NULL);").unwrap();
        w.execute("INSERT INTO t(id,v) VALUES(1,'kdf')", []).unwrap();
    }

    /// LE FACTEUR DE TRAVAIL SCRYPT ÉCRIT EST FIXE, BORNÉ, ET NE DÉPEND PLUS DE LA MACHINE (P8.6-b).
    ///
    /// CE QU'IL Y AVAIT AVANT, MESURÉ LE 2026-08-09 sur cette machine (12 cœurs), en appelant trois fois
    /// de suite `age::Encryptor::with_user_passphrase` et en RELISANT le `log_n` de l'en-tête produit :
    ///     profil `debug`   (= ce que compile `cargo test`) : 13, 14, 14   ->   8 Mio /  16 Mio
    ///     profil `release` (= LA PRODUCTION)               : 19, 19, 20   -> 512 Mio / 1024 Mio
    /// Le même code, la même machine, la même base : le tampon scrypt variait d'un facteur 128 selon le
    /// profil de compilation, et d'un facteur 2 d'un appel à l'autre. Sous un budget de 2 Gio, le chemin
    /// par DÉFAUT pouvait donc réclamer LA MOITIÉ DU BUDGET sur un coup de dé.
    ///
    /// CE QUE CE TEST VERROUILLE : le `.age` produit annonce TOUJOURS le même facteur, ce facteur est
    /// celui que le code déclare, et son tampon tient sous une borne écrite EN DUR ICI (donc relever la
    /// constante sans relire ce raisonnement fait ROUGIR ce test — la borne n'est pas dérivée de la
    /// constante qu'elle surveille).
    ///
    /// VALIDATION DE L'INSTRUMENT, dans les deux sens :
    ///   - TÉMOIN POSITIF : le lecteur de strophe voit AUSSI le facteur d'un fichier qu'on n'a pas
    ///     produit — celui qu'`age` choisit tout seul — et on l'IMPRIME (sans l'asserter : c'est
    ///     précisément la valeur non déterministe que le correctif retire) ;
    ///   - TÉMOIN NÉGATIF : sur un backup chiffré à un destinataire x25519, il n'y a AUCUNE strophe
    ///     scrypt et le lecteur rend `None`. Un lecteur qui rendrait toujours quelque chose ne prouverait
    ///     rien.
    ///
    /// CE TEST NE POSE AUCUNE VARIABLE D'ENVIRONNEMENT, et c'est la leçon du 2026-08-08 appliquée en
    /// amont : il compare le facteur observé à ce que le résolveur DÉCIDE ici et maintenant
    /// (`backup_scrypt_log_n()`), et vérifie SÉPARÉMENT, par la fonction PURE, que le défaut vaut bien
    /// 12. Un opérateur qui aurait posé `PLUME_BACKUP_SCRYPT_LOG_N` dans son shell ne le fait donc pas
    /// rougir à tort — et surtout, aucun voisin ne se voit imposer un facteur de travail par ce test.
    #[test]
    fn le_facteur_scrypt_ecrit_est_fixe_borne_et_independant_de_la_machine() {
        let _reglages = BACKUP_ENV_LOCK.read(); // sauvegarde -> LIT les réglages posés par d'autres tests
        let _tmpg = crate::tmp_possede::TmpPossede::neuf("bkst-kdf-fixe");
        let root = _tmpg.racine().chemin().to_path_buf();
        let key = "facteur-scrypt-fixe-passphrase";
        let src = root.join("src.db").to_string_lossy().into_owned();
        bkst_seed_minuscule(&src, key);

        // --- LA PROPRIÉTÉ : trois sauvegardes, trois fois le MÊME facteur, et c'est le nôtre. ---------
        let mut vus = Vec::new();
        for i in 0..3 {
            let dest = root.join(format!("bk-{i}.age")).to_string_lossy().into_owned();
            backup_compressed(&src, &dest, Some(key), None).expect("sauvegarde par passphrase OK");
            vus.push(bkst_log_n_annonce(&dest).expect("le chemin par passphrase doit produire une strophe scrypt"));
        }
        eprintln!("[kdf-fixe] log_n annoncés par trois sauvegardes consécutives : {vus:?} \
                   (tampon {} o chacun)", crate::backup::scrypt_tampon_octets(vus[0] as u8));
        assert!(vus.iter().all(|n| *n == vus[0]),
            "le facteur écrit doit être le MÊME à chaque sauvegarde ; observé {vus:?}");
        assert_eq!(vus[0], crate::backup::backup_scrypt_log_n() as u32,
            "le facteur écrit doit être celui que le résolveur DÉCIDE ({}) ; observé {}",
            crate::backup::backup_scrypt_log_n(), vus[0]);
        // ...et le DÉFAUT (réglage absent) est 12 — établi par la fonction PURE, sans toucher à l'env.
        assert_eq!(crate::backup::scrypt_log_n_depuis(""), crate::backup::BACKUP_SCRYPT_LOG_N_DEFAUT);
        assert_eq!(crate::backup::BACKUP_SCRYPT_LOG_N_DEFAUT, 12,
            "le défaut du chemin par passphrase doit rester 12 (cf. section « FACTEUR DE TRAVAIL SCRYPT »)");

        // --- LA BORNE, ÉCRITE EN DUR (pas dérivée de la constante surveillée) : 4 194 304 octets, soit
        // 0,2 % du budget de 2 Gio, contre les 1 073 741 824 o (50 % du budget) mesurés avant. Relever
        // `BACKUP_SCRYPT_LOG_N_DEFAUT` fait rougir ICI, en nommant les deux nombres.
        let tampon = crate::backup::scrypt_tampon_octets(crate::backup::BACKUP_SCRYPT_LOG_N_DEFAUT);
        assert_eq!(tampon, 4_194_304,
            "le tampon scrypt par défaut doit valoir 4 194 304 o (log_n=12) ; il vaut {tampon} o \
             (log_n={}) — si c'est voulu, c'est le raisonnement de la section « FACTEUR DE TRAVAIL \
             SCRYPT » de backup.rs qu'il faut rouvrir, pas ce nombre qu'il faut suivre",
            crate::backup::BACKUP_SCRYPT_LOG_N_DEFAUT);

        // --- TÉMOIN POSITIF de l'instrument : il lit aussi un facteur qu'on n'a PAS écrit. ------------
        let temoin = root.join("temoin-age.age").to_string_lossy().into_owned();
        {
            let e = age::Encryptor::with_user_passphrase(age::secrecy::SecretString::from(key.to_string()));
            let f = std::fs::File::create(&temoin).unwrap();
            let mut w = e.wrap_output(f).unwrap();
            std::io::Write::write_all(&mut w, b"charge").unwrap();
            w.finish().unwrap();
        }
        let calibre = bkst_log_n_annonce(&temoin)
            .expect("l'instrument doit voir la strophe scrypt d'un fichier produit par le défaut d'age");
        eprintln!("[kdf-fixe] TÉMOIN — `age` livré à lui-même a choisi log_n={calibre} sur CE binaire \
                   (tampon {} o). C'est cette valeur-là qui n'est plus utilisée.",
                  crate::backup::scrypt_tampon_octets(calibre as u8));

        // --- TÉMOIN NÉGATIF : pas de strophe scrypt du tout sur le chemin asymétrique. ----------------
        let identite = age::x25519::Identity::generate();
        let asym = root.join("bk-asym.age").to_string_lossy().into_owned();
        backup_compressed(&src, &asym, Some(key), Some(&identite.to_public().to_string()))
            .expect("sauvegarde asymétrique OK");
        assert_eq!(bkst_log_n_annonce(&asym), None,
            "un backup à destinataire x25519 n'a AUCUNE strophe scrypt : l'instrument doit rendre None \
             (sinon il rend n'importe quoi et les assertions ci-dessus ne valent rien)");
    }

    /// LE PLAFOND DE LECTURE EST FIXE, IL COUVRE L'HISTORIQUE, ET IL REFUSE EN LE DISANT (P8.6-b).
    ///
    /// POURQUOI UN PLAFOND FIXE. `age::scrypt::Identity::new` pose `target_scrypt_work_factor() + 4`,
    /// c'est-à-dire un plafond RECALCULÉ AU CHRONO sur la machine qui déchiffre. La restaurabilité d'un
    /// backup dépendait donc de la machine du DR : produit en release sur ce poste (log_n=20 mesuré), il
    /// aurait été REFUSÉ par un binaire debug du même poste (target=13 -> plafond 17).
    ///
    /// CE QUE CE TEST VERROUILLE :
    ///   1. le plafond couvre TOUT ce que le défaut au chrono a pu écrire avant le correctif — 18 documenté
    ///      par age pour « une machine moderne », 19 et 20 MESURÉS ici en release le 2026-08-09 ;
    ///   2. il refuse ce qui ne tient pas dans le budget (log_n=21 -> 2 147 483 648 o = le budget entier) ;
    ///   3. quand il refuse, il DIT quoi : le facteur exigé, son prix en octets, le plafond et son prix.
    ///      Sans cela, un DR reçoit « passphrase incorrecte ? » pour une passphrase parfaitement bonne.
    ///
    /// LE TÉMOIN QUI EMPÊCHE DE SE MENTIR : le même fichier forgé à un log_n SOUS le plafond échoue lui
    /// aussi (la clé dérivée ne correspond plus), mais d'une AUTRE manière — sans le mot « plafonne ».
    /// Sans ce témoin, « ça échoue » se lirait « la borne a mordu » aussi bien que « la forge casse tout ».
    #[test]
    fn le_plafond_scrypt_de_lecture_est_fixe_couvre_l_historique_et_refuse_au_dela() {
        let _reglages = BACKUP_ENV_LOCK.read(); // `backup_compressed` LIT les réglages portés par l'env
        use crate::backup::{scrypt_tampon_octets, BACKUP_SCRYPT_MAX_LOG_N};

        // (1) LA COUVERTURE HISTORIQUE, en dur : abaisser le plafond sous 20 rendrait illisibles des
        //     backups que plume a réellement produits.
        assert!(BACKUP_SCRYPT_MAX_LOG_N >= 20,
            "le plafond de lecture ({BACKUP_SCRYPT_MAX_LOG_N}) doit couvrir les facteurs que le défaut au \
             chrono produisait : 18 documenté par age, 19 et 20 MESURÉS en release le 2026-08-09. \
             L'abaisser rend des backups légitimes indéchiffrables — c'est une perte de données.");
        // (2) ...et le budget, en dur aussi : à 21 le tampon vaut à lui seul les 2 Gio du démon.
        assert!(scrypt_tampon_octets(BACKUP_SCRYPT_MAX_LOG_N) <= 1_073_741_824,
            "le plafond de lecture ({BACKUP_SCRYPT_MAX_LOG_N} -> {} o) doit rester sous 1 073 741 824 o : \
             au cran suivant, le KDF seul consomme le budget de 2 Gio et un fichier hostile devient un OOM",
            scrypt_tampon_octets(BACKUP_SCRYPT_MAX_LOG_N));

        // (3) LE REFUS, ET CE QU'IL DIT.
        let _tmpg = crate::tmp_possede::TmpPossede::neuf("bkst-kdf-plafond");
        let root = _tmpg.racine().chemin().to_path_buf();
        let key = "plafond-scrypt-passphrase";
        let src = root.join("src.db").to_string_lossy().into_owned();
        bkst_seed_minuscule(&src, key);
        let bon = root.join("bon.age").to_string_lossy().into_owned();
        backup_compressed(&src, &bon, Some(key), None).expect("sauvegarde par passphrase OK");

        let au_dela = (BACKUP_SCRYPT_MAX_LOG_N as u32) + 1;
        let forge_haut = root.join("forge-haut.age").to_string_lossy().into_owned();
        bkst_forge_log_n(&bon, &forge_haut, au_dela);
        let dest_db = root.join("restaure.db").to_string_lossy().into_owned();
        let err_haut = restore_compressed(&forge_haut, &dest_db, Some(key), true, None)
            .expect_err("un backup exigeant plus que le plafond doit être REFUSÉ");
        eprintln!("[kdf-plafond] refus à log_n={au_dela} : {err_haut}");
        for attendu in [&format!("log_n={au_dela}"), &scrypt_tampon_octets(au_dela as u8).to_string(),
                        &format!("log_n={BACKUP_SCRYPT_MAX_LOG_N}"), &"passphrase n'est PAS en cause".to_string()] {
            assert!(err_haut.contains(attendu.as_str()),
                "le refus doit contenir {attendu:?} — il dit : {err_haut}");
        }

        // (4) LE TÉMOIN : SOUS le plafond, la forge échoue AUTREMENT (pas sur la borne). 13 est choisi
        //     parce qu'il coûte ~1 s en debug (8 Mio) : le test paie un vrai tour de scrypt pour prouver
        //     que la borne a bien été FRANCHIE, et pas seulement que le fichier est cassé.
        let forge_bas = root.join("forge-bas.age").to_string_lossy().into_owned();
        bkst_forge_log_n(&bon, &forge_bas, 13);
        let err_bas = restore_compressed(&forge_bas, &dest_db, Some(key), true, None)
            .expect_err("un fichier forgé reste indéchiffrable : la clé dérivée ne correspond plus");
        eprintln!("[kdf-plafond] TÉMOIN — échec à log_n=13 (sous le plafond) : {err_bas}");
        assert!(!err_bas.contains("plume plafonne"),
            "à log_n=13 la borne n'a PAS mordu : l'échec doit venir du déchiffrement, pas du plafond. \
             Il dit : {err_bas}");
    }

    /// LE FACTEUR EST RÉGLABLE, ET LES RÉGLAGES ABSURDES SONT REFUSÉS EN LE DISANT.
    ///
    /// `PLUME_BACKUP_SCRYPT_LOG_N` existe pour l'opérateur qui SAIT que sa `PLUME_DB_KEY` est un mot de
    /// passe tapé par un humain et veut racheter de l'étirement. Il est borné des DEUX côtés : en bas par
    /// le point de départ de l'étalonnage d'age (10), en haut par ce que plume sait relire
    /// (`BACKUP_SCRYPT_MAX_LOG_N`) — sinon plume écrirait un fichier qu'il refuserait lui-même.
    /// Une valeur hors bornes n'est pas silencieusement écrêtée : elle est IGNORÉE et DITE.
    ///
    /// Test PUR au sens FORT : il n'exécute aucun scrypt **et ne touche à AUCUNE variable
    /// d'environnement**. Ce second point est la leçon du 2026-08-08 (P8.6-a) appliquée en amont —
    /// poser `PLUME_BACKUP_SCRYPT_LOG_N=20` pour éprouver la borne haute l'aurait posé pour TOUT le
    /// processus, et la trentaine de tests voisins qui sauvegardent par passphrase sans verrou auraient
    /// payé un scrypt de 1 073 741 824 octets. La décision est PURE, donc elle se lit sans rien poser.
    #[test]
    fn le_facteur_scrypt_est_reglable_et_ses_bornes_sont_dites() {
        use crate::backup::{scrypt_log_n_depuis, scrypt_tampon_octets,
                            BACKUP_SCRYPT_LOG_N_DEFAUT, BACKUP_SCRYPT_MAX_LOG_N, BACKUP_SCRYPT_MIN_LOG_N};
        let defaut = BACKUP_SCRYPT_LOG_N_DEFAUT;

        assert_eq!(scrypt_log_n_depuis(""), defaut, "absente -> le défaut");
        assert_eq!(scrypt_log_n_depuis("  "), defaut, "vide/espaces -> le défaut");
        assert_eq!(scrypt_log_n_depuis(" 14 "), 14, "les espaces autour d'une valeur valide sont tolérés");

        // ACCEPTÉES : les deux bornes elles-mêmes, et une valeur intermédiaire. Les bornes sont INCLUSES —
        // un test qui n'éprouverait que l'intérieur laisserait passer un `<` mis pour un `<=`.
        for n in [BACKUP_SCRYPT_MIN_LOG_N, defaut + 1, BACKUP_SCRYPT_MAX_LOG_N] {
            assert_eq!(scrypt_log_n_depuis(&n.to_string()), n,
                "log_n={n} est dans [{BACKUP_SCRYPT_MIN_LOG_N}, {BACKUP_SCRYPT_MAX_LOG_N}] : il doit être retenu");
        }
        // REFUSÉES : sous le plancher, au-dessus du plafond, non numérique. Toutes -> le défaut.
        for brut in [(BACKUP_SCRYPT_MIN_LOG_N - 1).to_string(), (BACKUP_SCRYPT_MAX_LOG_N + 1).to_string(),
                     "0".to_string(), "63".to_string(), "quatorze".to_string(), "12.5".to_string(),
                     "-1".to_string(), "999".to_string()] {
            assert_eq!(scrypt_log_n_depuis(&brut), defaut,
                "PLUME_BACKUP_SCRYPT_LOG_N={brut:?} est hors bornes ou illisible : le défaut doit rester");
        }
        // JAMAIS plume n'écrit ce qu'il refuserait de relire : la borne haute du réglage EST le plafond
        // de lecture. Sans cette égalité, un opérateur pourrait produire des archives illisibles.
        assert_eq!(scrypt_log_n_depuis(&BACKUP_SCRYPT_MAX_LOG_N.to_string()), BACKUP_SCRYPT_MAX_LOG_N);
        assert_eq!(scrypt_log_n_depuis(&(BACKUP_SCRYPT_MAX_LOG_N + 1).to_string()), defaut);

        // Le calcul du tampon est celui d'age (128·r·2^log_n, r=8), pas une approximation : il porte les
        // chiffres que les messages de refus impriment.
        assert_eq!(scrypt_tampon_octets(10), 1_048_576);
        assert_eq!(scrypt_tampon_octets(12), 4_194_304);
        assert_eq!(scrypt_tampon_octets(20), 1_073_741_824);
        // ...et il est TOTAL : `age` accepte log_n jusqu'à 63 dans une strophe, et 2^(10+54) ne tient
        // plus dans un u64. C'est précisément la valeur la plus hostile qui atteint le message de refus :
        // il doit la chiffrer, pas paniquer dessus. (Défaut trouvé par ce test avant d'être corrigé.)
        assert_eq!(scrypt_tampon_octets(53), 1u64 << 63, "dernière valeur représentable");
        assert_eq!(scrypt_tampon_octets(54), u64::MAX, "au-delà : saturation, jamais de débordement");
        assert_eq!(scrypt_tampon_octets(63), u64::MAX, "le maximum qu'une strophe age puisse annoncer");
    }

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
        let _reglages = BACKUP_ENV_LOCK.write(); // ce test POSE un réglage -> exclut les lecteurs
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
        let (res2, seen2, samples2) = {
            let _force = ReglageBackupPose::neuf(crate::backup::CLE_BACKUP_FORCE_PLAINTEXT_EXPORT, "1");
            bkst_watch_dir(&d_hist, || backup_compressed(&src, &dest_hist, Some(key), None))
        };
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
        let _reglages = BACKUP_ENV_LOCK.write(); // ce test POSE un réglage -> exclut les lecteurs
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
        let hist = {
            let _force = ReglageBackupPose::neuf(crate::backup::CLE_BACKUP_FORCE_PLAINTEXT_EXPORT, "1");
            backup_compressed(&src, &dest_hist, Some(key), None)
        };
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
        // la mesure — un deuxième canal de non-déterminisme, indépendant du RSS. Ce test ne POSE rien : il
        // lui suffit d'exclure les poseurs, donc la LECTURE.
        let _reglages = BACKUP_ENV_LOCK.read();
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
        let _reglages = BACKUP_ENV_LOCK.write(); // ce test POSE un réglage -> exclut les lecteurs
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

        let st_hist = {
            let _force = ReglageBackupPose::neuf(crate::backup::CLE_BACKUP_FORCE_PLAINTEXT_EXPORT, "1");
            backup_compressed(&src, &dest_hist, Some(key), None).expect("sauvegarde historique OK")
        };
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

    // ============================================================================================
    // LA GARDE QUI EMPÊCHE LA RÉCIDIVE — DÉRIVÉE DES SOURCES, JAMAIS UNE LISTE.
    // --------------------------------------------------------------------------------------------
    // Le verrou `BACKUP_ENV_LOCK` ne vaut que si TOUS ceux qui lisent les réglages le prennent. Tant
    // que cette obligation n'était qu'une phrase de commentaire, elle a été manquée par douze tests
    // répartis dans trois fichiers, et le prix s'est payé en rougeurs INTERMITTENTES (mesuré le
    // 2026-08-19 : 2 exécutions sur 5 du binaire filtré `backup`, alors que chacun des tests concernés
    // passait SEUL). Le test ci-dessous relit les sources et refuse qu'un test déclenche une
    // sauvegarde sans prendre le verrou.
    // ============================================================================================

    /// GARDE DÉRIVÉE : aucun `#[test]` ne déclenche une sauvegarde sans prendre `BACKUP_ENV_LOCK`.
    ///
    /// Rien n'est énuméré. Les DÉCLENCHEURS sont dérivés des sources de PRODUCTION : `backup_compressed`
    /// (la fonction qui relit les réglages) plus toute fonction de production qui l'appelle — c'est ce
    /// second terme qui fait apparaître `scheduled_backup_cycle`, par lequel trois tests de
    /// `backup_retention_adverse.rs` sauvegardent sans jamais écrire le mot `backup_compressed`. Une
    /// simple recherche textuelle du nom de la fonction les aurait laissés passer.
    ///
    /// L'INSTRUMENT EST VALIDÉ AVANT DE CONCLURE, dans les deux sens :
    ///   - il doit avoir TROUVÉ des tests déclencheurs (sinon « aucune infraction » ne dit rien) ;
    ///   - il doit avoir dérivé `scheduled_backup_cycle` (sinon la dérivation est inerte) ;
    ///   - le même prédicat doit ACCUSER un corps synthétique sans verrou et ACQUITTER le même corps
    ///     avec — un prédicat qui n'accuse jamais rien serait vert pour de mauvaises raisons.
    #[test]
    fn aucune_sauvegarde_de_test_ne_lit_les_reglages_sans_le_verrou() {
        use crate::db_open::door_tests::{rs_files, sans_commentaire};
        use std::path::PathBuf;

        const VERROU: &str = "BACKUP_ENV_LOCK";
        const RACINE: &str = "backup_compressed"; // la fonction qui RELIT les réglages, à chaque appel

        /// Un en-tête de fonction d'indentation 0 (production) ou 4 (module de tests), avec sa VISIBILITÉ.
        /// Plus profond (méthode d'`impl`, fonction imbriquée) -> pas une frontière : le corps courant
        /// l'absorbe. La visibilité n'est pas un détail : une fonction PRIVÉE de son module ne peut pas
        /// être appelée depuis un test, donc elle ne peut pas être un déclencheur. C'est ce qui écarte
        /// `fn main` — que la dérivation trouve (il sauvegarde), mais qu'aucun test ne peut appeler —
        /// sans avoir à l'exclure nommément.
        fn nom_de_fn(l: &str) -> Option<(bool, String)> {
            let indent = l.len() - l.trim_start().len();
            if indent != 0 && indent != 4 { return None; }
            let t0 = l.trim_start();
            let (publique, apres) = match t0.strip_prefix("pub") {
                Some(r) => {
                    let r = if r.starts_with('(') { &r[r.find(')')? + 1..] } else { r };
                    (true, r.trim_start())
                }
                None => (false, t0),
            };
            let reste = apres.strip_prefix("fn ").or_else(|| apres.strip_prefix("async fn "))?;
            let nom: String = reste.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            (!nom.is_empty()).then_some((publique, nom))
        }

        /// Découpe un fichier en unités (nom, appelable de l'extérieur, porte `#[test]`, corps).
        fn unites(src: &str) -> Vec<(String, bool, bool, String)> {
            let mut out: Vec<(String, bool, bool, String)> = Vec::new();
            let mut marque_test = false;
            for l in src.lines() {
                let t = l.trim_start();
                if let Some((publique, nom)) = nom_de_fn(l) {
                    out.push((nom, publique, marque_test, String::new()));
                    marque_test = false;
                } else if t.starts_with("#[") {
                    // `#[test]` ET `#[tokio::test]` ; `#[cfg(test)]` finit par `test)]` -> exclu.
                    marque_test |= t.trim_end().ends_with("test]");
                } else if !t.is_empty() && !t.starts_with("///") && !t.starts_with("//") {
                    marque_test = false; // une ligne ordinaire referme la fenêtre d'attributs
                }
                if let Some(u) = out.last_mut() { u.3.push_str(l); u.3.push('\n'); }
            }
            out
        }

        /// APPEL de `nom`, pas simple occurrence : le caractère qui précède ne doit pas être un
        /// caractère de nom (sinon `domain(` compterait pour un appel à `main`), et les commentaires
        /// sont retirés ligne à ligne.
        fn appelle(corps: &str, nom: &str) -> bool {
            let motif = format!("{nom}(");
            corps.lines().map(sans_commentaire).any(|l| {
                l.match_indices(&motif).any(|(i, _)| {
                    !l[..i].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_')
                })
            })
        }

        let racine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        rs_files(&racine, &mut fichiers);
        let dossier_tests = racine.join("tests");

        // --- (1) LES DÉCLENCHEURS, DÉRIVÉS DE LA PRODUCTION -------------------------------------
        let mut declencheurs: Vec<String> = vec![RACINE.to_string()];
        for f in fichiers.iter().filter(|f| !f.starts_with(&dossier_tests)) {
            let src = std::fs::read_to_string(f).unwrap();
            for (nom, publique, _, corps) in unites(&src) {
                if publique && nom != RACINE && appelle(&corps, RACINE) && !declencheurs.contains(&nom) {
                    declencheurs.push(nom);
                }
            }
        }
        declencheurs.sort();
        eprintln!("[verrou-reglages-backup] déclencheurs dérivés de la production : {declencheurs:?}");
        assert!(declencheurs.iter().any(|d| d == "scheduled_backup_cycle"),
            "la dérivation est INERTE : elle n'a pas retrouvé `scheduled_backup_cycle`, par lequel des tests \
             sauvegardent sans nommer `{RACINE}`. Une garde qui ne dérive plus rien ne garde plus rien.");
        assert!(!declencheurs.iter().any(|d| d == "main"),
            "`fn main` sauvegarde aussi, mais il est PRIVÉ : aucun test ne peut l'appeler. Le laisser \
             entrer accuse à tort tout test dont un message d'assertion mentionne `main()` — mesuré une \
             fois sur `misc.rs`, avant que le filtre de visibilité n'existe.");

        // --- (2) LES TESTS QUI DÉCLENCHENT UNE SAUVEGARDE, ET CE QU'ILS PRENNENT ------------------
        let (mut gardes, mut nus) = (Vec::<String>::new(), Vec::<String>::new());
        for f in fichiers.iter().filter(|f| f.starts_with(&dossier_tests)) {
            let src = std::fs::read_to_string(f).unwrap();
            for (nom, _, est_test, corps) in unites(&src) {
                if !est_test || nom == "aucune_sauvegarde_de_test_ne_lit_les_reglages_sans_le_verrou" { continue; }
                if !declencheurs.iter().any(|d| appelle(&corps, d)) { continue; }
                let ou = format!("{}::{nom}", f.file_name().unwrap().to_string_lossy());
                if corps.contains(VERROU) { gardes.push(ou) } else { nus.push(ou) }
            }
        }

        // --- (3) VALIDATION DE L'INSTRUMENT, puis seulement la propriété -------------------------
        eprintln!("[verrou-reglages-backup] tests qui déclenchent une sauvegarde : {} gardés, {} nus",
            gardes.len(), nus.len());
        assert!(gardes.len() >= 15,
            "l'instrument n'a trouvé que {} test(s) gardé(s) : il ne voit plus les corps de test, et son \
             « aucune infraction » ne prouverait rien (mesuré le 2026-08-19 : 20)", gardes.len());
        let temoin_nu = "    fn t() { scheduled_backup_cycle(a, b, 1, None, None); }";
        let temoin_garde = "    fn t() { let _g = BACKUP_ENV_LOCK.read(); scheduled_backup_cycle(a, b, 1, None, None); }";
        assert!(declencheurs.iter().any(|d| appelle(temoin_nu, d)) && !temoin_nu.contains(VERROU),
            "le prédicat n'ACCUSE pas un corps synthétique qui sauvegarde sans verrou : il n'accuserait rien");
        assert!(declencheurs.iter().any(|d| appelle(temoin_garde, d)) && temoin_garde.contains(VERROU),
            "le prédicat n'ACQUITTE pas un corps synthétique qui prend le verrou : il accuserait tout");
        assert!(!appelle("    let d = domain(x);", "main"),
            "`domain(` ne doit pas compter pour un appel à `main` : la borne de mot est ce qui rend le \
             prédicat utilisable sur des noms courts");

        assert!(nus.is_empty(),
            "ces tests déclenchent une sauvegarde SANS prendre `{VERROU}` :\n  {}\n\
             `backup_compressed` RELIT `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT` et \
             `PLUME_BACKUP_REQUIRE_ASYMMETRIC` dans l'environnement PROCESS-global à chaque appel, et des \
             voisins les POSENT : sans le verrou, la sauvegarde mesurée ici peut prendre le chemin \
             HISTORIQUE, ou être REFUSÉE, à cause d'un test qui tourne à côté. Ajouter \
             `let _reglages = {VERROU}.read();` en tête (ou `.write()` si le test POSE un réglage).",
            nus.join("\n  "));
    }
