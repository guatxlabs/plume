    // ============================================================================================
    // TESTS ADVERSES — SCHEDULER DE BACKUP NATIF + RÉTENTION KEEP-N (data-availability-critical).
    // Cible : server::scheduled_backup_cycle / spawn_backup_scheduler / spawn_autovacuum_loop
    //         + backup::backup_keep_recent_plan / fmt_backup_ts / parse_backup_ts / classify_backup_name.
    // Objectif : prouver qu'aucun backup VALIDE n'est supprimé/corrompu et que l'off-by-default est inerte.
    // Ces tests COMPLÈTENT (ne dupliquent pas) native_* déjà présents : ils poussent les BORDS.
    // Réutilise les helpers de detection.rs (même module `tests`) : gfs_reg/gfs_fmt_ts/gfs_premig,
    // mk_tmp_path, bytes_contain, open_db_keyed, backup_compressed, restore_compressed.
    // ============================================================================================

    /// VECTEUR 1 — ORDRE CHRONOLOGIQUE aux BORDS (fin d'année, fin de mois, minuit, seconde-collision).
    /// Le tri de la rétention DOIT être chronologique (TS parsé), pas un artefact lexical. On mélange
    /// des instants qui traversent 2025->2026 et janvier->février, plus deux noms qui parsent au MÊME
    /// instant (seconde intercalaire `...5960Z` == `...0000Z` de la minute suivante). KEEP=1 doit garder
    /// le VRAI plus récent (2026-02-01T00:00:00Z) et ne JAMAIS supprimer un instant plus récent qu'un gardé.
    #[test]
    fn adverse_keep_recent_chronology_at_boundaries() {
        let d = |y: i64, mo: i64, dd: i64, h: i64, mi: i64, s: i64| crate::backup::days_from_civil(y, mo, dd) * 86400 + h * 3600 + mi * 60 + s;
        // instants, du plus VIEUX au plus RÉCENT (vérité terrain).
        let ordered = [
            d(2025, 12, 31, 23, 59, 59), // avant-dernier de 2025
            d(2026,  1,  1,  0,  0,  0), // minuit changement d'année
            d(2026,  1,  1,  0,  0,  1),
            d(2026,  1, 31, 23, 59, 59), // fin janvier
            d(2026,  2,  1,  0,  0,  0), // 1er février = LE PLUS RÉCENT
        ];
        // sanité : la vérité terrain est bien strictement croissante.
        for w in ordered.windows(2) { assert!(w[0] < w[1], "instants de référence croissants"); }
        // noms mélangés (ordre d'entrée volontairement chaotique) — lexical != insertion.
        let mut names: Vec<String> = ordered.iter().map(|&s| gfs_reg(s)).collect();
        names.rotate_left(2);
        names.swap(0, 3);

        let newest = gfs_reg(*ordered.last().unwrap());
        // KEEP=1 : seul le plus récent survit ; tous les autres réguliers sont supprimés.
        let plan = crate::backup::backup_keep_recent_plan(&names, 1);
        assert_eq!(plan.len(), ordered.len() - 1, "KEEP=1 -> supprime tous sauf 1");
        assert!(!plan.contains(&newest), "le PLUS RÉCENT (2026-02-01) n'est JAMAIS supprimé");
        // KEEP=3 : garde les 3 plus récents (02-01, 01-31, 01-01T00:00:01), supprime les 2 plus vieux.
        let plan3 = crate::backup::backup_keep_recent_plan(&names, 3);
        let del3: std::collections::HashSet<&String> = plan3.iter().collect();
        assert_eq!(plan3.len(), 2, "KEEP=3 sur 5 -> 2 supprimés");
        for &keep_s in &ordered[2..] {
            assert!(!del3.contains(&gfs_reg(keep_s)), "un des 3 plus récents ne doit PAS être supprimé");
        }
        for &del_s in &ordered[..2] {
            assert!(del3.contains(&gfs_reg(del_s)), "les 2 plus vieux doivent être supprimés");
        }

        // COLLISION de seconde : `...T115960Z` (leap second) et `...T120000Z` parsent au MÊME instant.
        let leap = "plume-20260101T115960Z.db.age".to_string();
        let plain = "plume-20260101T120000Z.db.age".to_string();
        assert_eq!(crate::backup::parse_backup_ts("20260101T115960Z"),
                   crate::backup::parse_backup_ts("20260101T120000Z"),
                   "leap-second et minute suivante = même instant Unix");
        let older = gfs_reg(d(2026, 1, 1, 11, 0, 0));
        let coll = vec![leap.clone(), plain.clone(), older.clone()];
        // KEEP=1 : tie-break DÉTERMINISTE par nom ; supprime 2, garde 1 ; jamais > keep gardés, jamais < keep.
        let pc = crate::backup::backup_keep_recent_plan(&coll, 1);
        assert_eq!(pc.len(), 2, "3 réguliers, KEEP=1 -> 2 supprimés (collision incluse)");
        assert!(pc.contains(&older), "le plus vieux est toujours supprimé");
        // idempotence : rejouer le plan donne le même résultat.
        assert_eq!(crate::backup::backup_keep_recent_plan(&coll, 1), pc, "plan déterministe");
    }

    /// VECTEUR 1 bis — `keep` == nombre de réguliers EN PRÉSENCE de bruit (tmp/garbage/premigrate).
    /// Le dénominateur du KEEP-N est le nombre de RÉGULIERS SEULS : les non-parseables et premigrate ne
    /// doivent NI gonfler NI réduire ce compte. keep==nbRéguliers -> AUCUNE suppression même noyé de bruit.
    #[test]
    fn adverse_keep_equals_regular_count_ignores_noise() {
        let base = crate::backup::days_from_civil(2026, 3, 10) * 86400;
        let regs: Vec<String> = (0..3).map(|i| gfs_reg(base + i * 3600)).collect();
        let mut names = regs.clone();
        names.push(".plume-20260310T090000Z.db.age.tmp.4242".into()); // temp en vol (rename pas encore fait)
        names.push("plume-20260310T090000Z.db.age.tmp.4242".into());  // variante suffixe .tmp
        names.push("random.bin".into());
        names.push(gfs_premig("deadbeef", base + 99 * 3600));
        names.push("plume-NOTATIMESTAMP.db.age".into()); // TS non parseable -> Unparseable
        // keep == 3 == nb de réguliers -> RIEN supprimé (le bruit ne compte pas comme régulier).
        assert!(crate::backup::backup_keep_recent_plan(&names, 3).is_empty(),
            "keep == nb de réguliers -> aucune suppression, le bruit ne gonfle pas le compte");
        // keep == 2 -> exactement 1 régulier (le plus vieux) supprimé ; le bruit reste intact.
        let plan = crate::backup::backup_keep_recent_plan(&names, 2);
        assert_eq!(plan, vec![regs[0].clone()], "seul le plus vieux RÉGULIER est supprimé, jamais le bruit");
    }

    /// VECTEUR 2 — Un `.tmp` (backup EN COURS d'écriture / crashé avant rename) et un `premigrate` PRÉSENTS
    /// dans DEST ne doivent JAMAIS être ni comptés ni supprimés par un VRAI cycle de rétention, et le cycle
    /// PUBLIE par rename atomique (aucun `.tmp` de CE cycle ne subsiste). Prune APRÈS rename (le neuf compte).
    #[test]
    fn adverse_cycle_never_prunes_inflight_tmp_or_premigrate() {
        let _reglages = VERROU_ENV_PROCESSUS.read(); // `scheduled_backup_cycle` -> `backup_compressed` LIT les réglages
        let key = "adverse-inflight-tmp-passphrase";
        let src = mk_tmp_path("adv-tmp-src.db");
        let dest_dir = mk_tmp_path("adv-tmp-dest");
        std::fs::create_dir_all(&dest_dir).unwrap();
        {
            let c = open_db_keyed(&src, Some(key)).unwrap();
            c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&c);
            c.execute("INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,'sshd','auth',3,'h','m','{}')",
                params![now()]).unwrap();
        }
        // SEED : 4 vieux réguliers (2019) + un .tmp EN VOL + un premigrate + un fichier étranger.
        let old_base = crate::backup::days_from_civil(2019, 5, 1) * 86400;
        let old_regs: Vec<String> = (0..4).map(|i| format!("plume-{}.db.age", crate::backup::fmt_backup_ts(old_base + i * 3600))).collect();
        for n in &old_regs { std::fs::write(format!("{dest_dir}/{n}"), b"OLD").unwrap(); }
        let inflight_tmp = format!(".plume-{}.db.age.tmp.9999", crate::backup::fmt_backup_ts(old_base + 100 * 3600));
        std::fs::write(format!("{dest_dir}/{inflight_tmp}"), b"PARTIAL-DO-NOT-TOUCH").unwrap();
        let premig = gfs_premig("cafe1234", old_base + 50 * 3600);
        std::fs::write(format!("{dest_dir}/{premig}"), b"PREMIGRATE").unwrap();
        std::fs::write(format!("{dest_dir}/notes.txt"), b"foreign").unwrap();

        // CYCLE KEEP=1 : écrit un backup FRAIS (TS ~aujourd'hui) puis prune.
        crate::server::scheduled_backup_cycle(&src, &dest_dir, 1, Some(key), None);

        let entries: Vec<String> = std::fs::read_dir(&dest_dir).unwrap()
            .filter_map(|e| e.ok()).filter_map(|e| e.file_name().into_string().ok()).collect();
        // (a) le .tmp EN VOL, le premigrate et le fichier étranger SURVIVENT toujours.
        assert!(entries.contains(&inflight_tmp), "le .tmp en vol n'est JAMAIS pruné : {entries:?}");
        assert!(entries.contains(&premig), "le premigrate n'est JAMAIS pruné : {entries:?}");
        assert!(entries.contains(&"notes.txt".to_string()), "un fichier étranger n'est jamais touché");
        // (b) aucun .tmp de CE cycle (rename atomique publié).
        let this_cycle_tmp: Vec<&String> = entries.iter().filter(|n| n.contains(".tmp.") && *n != &inflight_tmp).collect();
        assert!(this_cycle_tmp.is_empty(), "aucun .tmp résiduel de ce cycle (rename atomique) : {entries:?}");
        // (c) rétention KEEP=1 : sur 4 vieux + 1 neuf = 5 réguliers -> il reste EXACTEMENT 1 régulier canonique.
        let canon: Vec<&String> = entries.iter().filter(|n| n.starts_with("plume-") && n.ends_with(".db.age")).collect();
        assert_eq!(canon.len(), 1, "KEEP=1 -> 1 seul régulier survit : {entries:?}");
        // (d) le survivant est le FRAIS (pas un 2019) et il est RESTAURABLE À L'IDENTIQUE.
        let fresh = canon[0];
        assert!(!fresh.contains("20190501") && !fresh.starts_with("plume-2019"), "le survivant est le backup FRAIS : {fresh}");
        let restored = mk_tmp_path("adv-tmp-restored.db");
        restore_compressed(&format!("{dest_dir}/{fresh}"), &restored, Some(key), true, None).expect("le backup frais est restaurable");
        {
            let r = open_db_keyed(&restored, Some(key)).unwrap();
            assert_eq!(r.query_row("SELECT COUNT(*) FROM event", [], |x| x.get::<_, i64>(0)).unwrap(), 1, "contenu fidèle");
        }
        for f in [&src, &restored] { for e in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{f}{e}")); } }
        let _ = std::fs::remove_dir_all(&dest_dir);
    }

    /// VECTEUR 2/3 — SÛRETÉ CRITIQUE : si le backup ÉCHOUE (clé fausse), la rétention ne DOIT PAS s'exécuter
    /// (l'ordre backup->rename->prune l'exige). Sinon un cycle qui n'a produit AUCUN nouveau backup pourrait
    /// quand même supprimer d'anciens backups valides -> perte nette. On seed des backups valides, on lance
    /// un cycle avec une MAUVAISE clé -> tout doit rester intact, aucun nouveau backup, aucun prune.
    #[test]
    fn adverse_failed_backup_does_not_prune_existing() {
        let _reglages = VERROU_ENV_PROCESSUS.read(); // `scheduled_backup_cycle` -> `backup_compressed` LIT les réglages
        let good = "the-real-passphrase";
        let wrong = "the-WRONG-passphrase";
        let src = mk_tmp_path("adv-fail-src.db");
        let dest_dir = mk_tmp_path("adv-fail-dest");
        std::fs::create_dir_all(&dest_dir).unwrap();
        {
            let c = open_db_keyed(&src, Some(good)).unwrap();
            c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&c);
        }
        // seed : 5 vieux réguliers valides.
        let old_base = crate::backup::days_from_civil(2021, 1, 1) * 86400;
        let seeded: Vec<String> = (0..5).map(|i| format!("plume-{}.db.age", crate::backup::fmt_backup_ts(old_base + i * 3600))).collect();
        for n in &seeded { std::fs::write(format!("{dest_dir}/{n}"), b"VALID-SEED").unwrap(); }

        // cycle avec la MAUVAISE clé -> backup_compressed échoue AVANT tout rename/prune.
        crate::server::scheduled_backup_cycle(&src, &dest_dir, 1, Some(wrong), None);

        let entries: Vec<String> = std::fs::read_dir(&dest_dir).unwrap()
            .filter_map(|e| e.ok()).filter_map(|e| e.file_name().into_string().ok()).collect();
        // TOUS les seeds valides sont TOUJOURS là (aucune rétention sur backup échoué).
        for n in &seeded { assert!(entries.contains(n), "backup échoué : les backups valides existants ne sont PAS supprimés ({n}) : {entries:?}"); }
        // aucun nouveau backup canonique, aucun .tmp résiduel.
        assert!(!entries.iter().any(|n| n.contains(".tmp.")), "aucun .tmp orphelin après échec : {entries:?}");
        assert_eq!(entries.len(), seeded.len(), "exactement les seeds, rien de plus/moins : {entries:?}");

        // idem si la SOURCE est introuvable (open échoue) -> pas de prune.
        crate::server::scheduled_backup_cycle("/nonexistent/nope.db", &dest_dir, 1, Some(good), None);
        let entries2: Vec<String> = std::fs::read_dir(&dest_dir).unwrap()
            .filter_map(|e| e.ok()).filter_map(|e| e.file_name().into_string().ok()).collect();
        assert_eq!(entries2.len(), seeded.len(), "source absente : aucun prune, seeds intacts : {entries2:?}");

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir_all(&dest_dir);
    }

    /// VECTEUR 4 — OFF-BY-DEFAULT ROBUSTE : une valeur EXPLICITE invalide/vide/0/négative de
    /// PLUME_BACKUP_INTERVAL (et PLUME_AUTOVACUUM_INTERVAL) doit DÉSACTIVER (return immédiat) — jamais
    /// crasher, jamais spawner, jamais créer de répertoire. Le test complète native_ops_off_by_default
    /// (qui ne couvre que l'ABSENCE de la var) en passant des valeurs pathologiques via le conf map.
    #[test]
    fn adverse_off_by_default_pathological_values() {
        // pré-condition : ces vars ne sont pas dans l'ENV réel (cfg lit env AVANT le conf map).
        assert!(std::env::var("PLUME_BACKUP_INTERVAL").is_err(), "PLUME_BACKUP_INTERVAL non posé en env");
        assert!(std::env::var("PLUME_AUTOVACUUM_INTERVAL").is_err(), "PLUME_AUTOVACUUM_INTERVAL non posé en env");
        for bad in ["0", "", "  ", "abc", "-5", "0x10", "12.5", "9999999999999999999999"] {
            let dest = mk_tmp_path(&format!("adv-off-{}", bad.len()));
            let mut conf = std::collections::HashMap::new();
            conf.insert("PLUME_BACKUP_INTERVAL".to_string(), bad.to_string());
            conf.insert("PLUME_AUTOVACUUM_INTERVAL".to_string(), bad.to_string());
            conf.insert("PLUME_BACKUP_DEST".to_string(), dest.as_str().to_string());
            let src_off = mk_tmp_path("adv-off-src");
            crate::server::spawn_backup_scheduler(conf.clone(), src_off.as_str().to_string());
            let dummy = std::sync::Arc::new(parking_lot::Mutex::new(rusqlite::Connection::open_in_memory().unwrap()));
            crate::server::spawn_autovacuum_loop(conf, dummy);
            std::thread::sleep(std::time::Duration::from_millis(60));
            assert!(!std::path::Path::new(&dest).exists(),
                "valeur d'intervalle invalide ({bad:?}) -> scheduler DÉSACTIVÉ, aucun répertoire créé ({dest})");
        }
    }

    /// VECTEUR 4 bis — UNE DESTINATION OBJET QU'ON NE PEUT PAS HONORER NE DOIT JAMAIS DEVENIR UNE
    /// ÉCRITURE LOCALE. C'est le défaut que ce vecteur rend impossible : un exploitant qui écrit
    /// `PLUME_BACKUP_DEST=s3://…` croit ses sauvegardes HORS du nœud. Si le binaire ne sait pas les y
    /// mettre, la seule issue acceptable est l'arrêt de l'ordonnanceur — pas un répertoire local
    /// silencieusement rempli sous un nom de destination distante, qui ferait croire à un escrow
    /// inexistant jusqu'au jour du sinistre.
    ///
    /// LE TEST VAUT DANS LES DEUX PROFILS, et c'est délibéré — il n'a AUCUN `cfg` :
    ///   · sans la feature `s3_backup`, le module de dépôt n'existe pas dans ce binaire et la
    ///     destination est refusée à la lecture de la configuration ;
    ///   · avec la feature, elle est refusée par la résolution (aucun service objet n'est configuré
    ///     ici, et un `_ENDPOINT` ne se devine pas).
    /// Deux causes, une seule conséquence observable — c'est ELLE qui est le contrat, et c'est elle
    /// que ce test fixe. Il est donc aussi la preuve, exécutée par la suite PAR DÉFAUT, que la
    /// fonctionnalité éteinte ne change pas le comportement.
    #[test]
    fn adverse_destination_objet_non_honorable_ne_devient_jamais_une_ecriture_locale() {
        assert!(std::env::var("PLUME_BACKUP_S3_ENDPOINT").is_err(),
            "aucun service objet ne doit être configuré dans l'environnement de test");
        for dest in ["s3://sauvegardes", "s3://sauvegardes/plume/noeud-1", "s3://X", "s3://"] {
            // Le répertoire par défaut du scheduler est `<dossier de la base>/backups` : s'il apparaît,
            // c'est qu'une écriture locale a eu lieu sous un nom de destination distante.
            let src = mk_tmp_path("adv-objet-src");
            let local = std::path::Path::new(src.as_str()).parent().unwrap().join("backups");
            assert!(!local.exists(), "pré-condition : le répertoire local n'existe pas encore");
            let mut conf = std::collections::HashMap::new();
            conf.insert("PLUME_BACKUP_INTERVAL".to_string(), "1".to_string()); // ACTIF, donc rien ne masque le refus
            conf.insert("PLUME_BACKUP_ON_START".to_string(), "1".to_string());
            conf.insert("PLUME_BACKUP_DEST".to_string(), dest.to_string());
            crate::server::spawn_backup_scheduler(conf, src.as_str().to_string());
            std::thread::sleep(std::time::Duration::from_millis(60));
            assert!(!local.exists(),
                "destination objet {dest:?} non honorable -> AUCUNE écriture locale ne doit apparaître ({})",
                local.display());
        }
        // TÉMOIN POSITIF de l'instrument : la MÊME mécanique, avec une destination LOCALE, crée bien le
        // répertoire. Sans lui, les quatre assertions ci-dessus seraient satisfaites par un scheduler qui
        // ne ferait jamais rien, et ce vecteur ne prouverait rien du tout.
        let src = mk_tmp_path("adv-objet-temoin");
        let dest_local = mk_tmp_path("adv-objet-dest");
        let mut conf = std::collections::HashMap::new();
        conf.insert("PLUME_BACKUP_INTERVAL".to_string(), "1".to_string());
        conf.insert("PLUME_BACKUP_DEST".to_string(), dest_local.as_str().to_string());
        crate::server::spawn_backup_scheduler(conf, src.as_str().to_string());
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(std::path::Path::new(dest_local.as_str()).exists(),
            "témoin positif : une destination LOCALE fait bien créer le répertoire — sinon l'instrument \
             ne distingue pas « refusé » de « rien ne tourne »");
    }

    /// VECTEUR 6 — fmt_backup_ts est l'INVERSE EXACT de parse_backup_ts sur des dates DURES : epoch 0,
    /// AVANT l'epoch (négatif), fin d'année/mois à 23:59:59, années bissextiles (dont séculaires : 2000
    /// bissextile, 1900 NON), et un BALAYAGE dense. Prouve aussi que le nom trie lexicalement ==
    /// chronologiquement (invariant dont dépend la rétention) sur un set MÉLANGÉ.
    #[test]
    fn adverse_fmt_parse_roundtrip_hard_dates_and_sort() {
        let d = |y: i64, mo: i64, dd: i64, h: i64, mi: i64, s: i64| crate::backup::days_from_civil(y, mo, dd) * 86400 + h * 3600 + mi * 60 + s;
        let cases = [
            d(1970, 1, 1, 0, 0, 0),      // epoch 0
            d(1969, 12, 31, 23, 59, 59), // -1 s (négatif)
            d(1900, 2, 28, 23, 59, 59),  // 1900 NON bissextile (séculaire)
            d(1904, 2, 29, 12, 0, 0),    // bissextile
            d(2000, 2, 29, 0, 0, 0),     // séculaire bissextile
            d(2024, 2, 29, 23, 59, 59),
            d(2025, 12, 31, 23, 59, 59), // fin d'année
            d(2026, 1, 1, 0, 0, 0),      // début d'année, minuit
            d(2026, 2, 28, 23, 59, 59),
            d(2026, 3, 1, 0, 0, 0),      // sortie de février non-bissextile
            d(9999, 12, 31, 23, 59, 59), // futur lointain (4 chiffres d'année = borne du format)
            d(1583, 1, 1, 0, 0, 0),      // grégorien proleptique lointain
        ];
        for &secs in &cases {
            let ts = crate::backup::fmt_backup_ts(secs);
            assert_eq!(ts.len(), crate::backup::BACKUP_TS_LEN, "TS de 16 chars pour {ts}");
            assert_eq!(crate::backup::parse_backup_ts(&ts), Some(secs), "round-trip EXACT pour {ts} ({secs})");
            assert_eq!(ts, gfs_fmt_ts(secs), "fmt == `date -u +%Y%m%dT%H%M%SZ` pour {secs}");
        }
        // BALAYAGE dense : ~50k instants espacés d'un nombre premier de secondes -> couvre heures/jours/mois.
        let start = d(2020, 1, 1, 0, 0, 0);
        for k in 0..50_000i64 {
            let secs = start + k * 3607; // 3607 = premier -> désaligne les frontières
            let ts = crate::backup::fmt_backup_ts(secs);
            assert_eq!(crate::backup::parse_backup_ts(&ts), Some(secs), "balayage : round-trip {ts}");
        }
        // INVARIANT DE TRI : pour des noms BIEN FORMÉS, tri lexical du nom == tri chronologique du TS.
        // (fmt produit un champ largeur-fixe zéro-paddé -> la rétention peut trier par TS parsé sans piège.)
        let mut mixed: Vec<(i64, String)> = cases.iter().map(|&s| (s, gfs_reg(s))).collect();
        let mut by_name = mixed.clone();
        by_name.sort_by(|a, b| a.1.cmp(&b.1));      // tri lexical du NOM
        mixed.sort_by_key(|x| x.0);                  // tri chronologique du TS
        assert_eq!(by_name.iter().map(|x| x.0).collect::<Vec<_>>(),
                   mixed.iter().map(|x| x.0).collect::<Vec<_>>(),
                   "tri lexical du nom == tri chronologique (invariant de rétention)");
    }

    /// VECTEUR 6 bis — parse_backup_ts REJETTE les TS malformés -> `classify_backup_name` = Unparseable
    /// -> la rétention ne les compte ni ne les supprime JAMAIS (fail-safe sur nom ambigu).
    #[test]
    fn adverse_parse_rejects_malformed_ts_stays_kept() {
        for bad in [
            "",                    // vide
            "20260101T120000",     // Z manquant (15)
            "20260101X120000Z",    // séparateur T faux
            "20260101T120000z",    // z minuscule
            "2026-01-01T12:00:00Z",// tirets/deux-points (mauvaise longueur)
            "20261301T120000Z",    // mois 13
            "20260132T120000Z",    // jour 32
            "20260100T120000Z",    // jour 0
            "20260101T240000Z",    // heure 24
            "20260101T126000Z",    // minute 60
            "20260101T120061Z",    // seconde 61
            "2026010AT120000Z",    // chiffre non-ASCII
            "202601011200000Z",    // 17 chars
        ] {
            assert_eq!(crate::backup::parse_backup_ts(bad), None, "TS malformé rejeté : {bad:?}");
            let name = format!("plume-{bad}.db.age");
            assert_eq!(crate::backup::classify_backup_name(&name), crate::backup::ParsedBackup::Unparseable,
                "nom à TS malformé -> Unparseable (jamais supprimé) : {name}");
            // et la rétention ne le supprime jamais, même avec un vrai backup récent à côté.
            let recent = gfs_reg(crate::backup::days_from_civil(2099, 1, 1) * 86400);
            let names = vec![name.clone(), recent.clone()];
            let plan = crate::backup::backup_keep_recent_plan(&names, 1);
            assert!(!plan.contains(&name), "un nom Unparseable n'est JAMAIS dans le plan de suppression : {name}");
        }
    }

    /// VECTEUR 1 — GARDE-FOU CLOCK-SKEW (fix appliqué). La rétention trie « le plus récent » par le TS du
    /// NOM. Un objet FUTUR-daté déjà présent (NTP reculé, ou import d'un hôte à horloge rapide) a un TS plus
    /// grand -> le backup FRAIS de ce cycle (TS plus petit) serait pruné avec KEEP petit = perte du snapshot
    /// le plus à jour. FIX : `scheduled_backup_cycle` exclut le fichier écrit CE cycle du set de prune ->
    /// il n'est JAMAIS supprimé, quoi qu'en dise le plan. Ce test VÉRIFIE le garde-fou (le frais survit).
    #[test]
    fn adverse_clock_skew_never_prunes_just_written_fresh_backup() {
        let _reglages = VERROU_ENV_PROCESSUS.read(); // `scheduled_backup_cycle` -> `backup_compressed` LIT les réglages
        let key = "adverse-clock-skew-passphrase";
        let src = mk_tmp_path("adv-skew-src.db");
        let dest_dir = mk_tmp_path("adv-skew-dest");
        std::fs::create_dir_all(&dest_dir).unwrap();
        {
            let c = open_db_keyed(&src, Some(key)).unwrap();
            c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&c);
            c.execute("INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,'sshd','auth',3,'h','fresh','{}')",
                params![now()]).unwrap();
        }
        // objet FUTUR-DATÉ déjà présent (TS de l'an 2099) — contenu bidon/obsolète.
        let future_name = format!("plume-{}.db.age", crate::backup::fmt_backup_ts(crate::backup::days_from_civil(2099, 1, 1) * 86400));
        std::fs::write(format!("{dest_dir}/{future_name}"), b"STALE-FUTURE-DATED").unwrap();

        // CYCLE KEEP=1 : produit un backup FRAIS (TS ~aujourd'hui < 2099) puis prune.
        crate::server::scheduled_backup_cycle(&src, &dest_dir, 1, Some(key), None);

        let entries: Vec<String> = std::fs::read_dir(&dest_dir).unwrap()
            .filter_map(|e| e.ok()).filter_map(|e| e.file_name().into_string().ok()).collect();
        let canon: Vec<&String> = entries.iter().filter(|n| n.starts_with("plume-") && n.ends_with(".db.age")).collect();
        // GARDE-FOU VÉRIFIÉ : le backup FRAIS de ce cycle SURVIT (jamais pruné), MÊME si le plan KEEP=1 aurait
        // voulu le supprimer au profit du futur-daté (TS max). Les DEUX restent -> zéro perte du snapshot frais.
        let fresh_present = canon.iter().any(|n| *n != &future_name);
        assert!(fresh_present,
            "GARDE-FOU : le backup FRAIS écrit ce cycle DOIT survivre au clock-skew (jamais pruné). canon={canon:?}");
        assert!(canon.iter().any(|n| *n == &future_name),
            "le futur-daté (TS max) reste le KEEP-1 nominal");
        assert_eq!(canon.len(), 2, "futur-daté (KEEP-1) + frais protégé = 2 ; le frais n'est pas supprimé");
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir_all(&dest_dir);
    }
