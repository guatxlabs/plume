    // ============================================================================================
    // P8.25-a + P8.26-a — LES SIGNAUX DE POSTURE SUIVENT L'ARCHIVE, SUR LE CHEMIN NATIF AUSSI.
    // --------------------------------------------------------------------------------------------
    // Deux signaux SOC non purgeables n'avaient qu'un appelant, la sous-commande `backup` : « sauvegarde
    // symétrique : aucun destinataire d'escrow » (P8.25-a) et « restauration non éprouvée » (P8.3-a, le
    // trou jumeau : P8.26-a). Le cycle NATIF (`server::scheduled_backup_cycle`), celui que
    // `deploy/k3s.yaml` active, publiait des archives déchiffrables par le nœud, jamais restaurées,
    // avec pour seul témoin une ligne sur la sortie d'erreur. Trois témoins par signal ci-dessous,
    // puis UNE garde DÉRIVÉE de ce qui écrit l'archive et de ce qui signale — jamais une liste.
    //
    // Chaque témoin relit la base SOURCE après le cycle : c'est là que les signaux s'écrivent (le
    // cycle n'a pas d'autre base), et l'archive, prise AVANT eux, n'en porte pas la trace.
    // ============================================================================================

    /// Une base plume chiffrée, au contrat, sans aucun événement de posture.
    fn base_source_au_contrat(dir: &crate::tmp_possede::TmpPossede, key: &str) -> String {
        let src = dir.sous("source.db").as_str().to_owned();
        let c = open_db_keyed(&src, Some(key)).unwrap();
        c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&c);
        c.execute("INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,'sshd','auth',3,'h','m','{}')",
            params![now()]).unwrap();
        src
    }

    /// Les signaux d'une famille présents dans la base : (nombre, nombre que la purge de rétention
    /// AURAIT le droit d'effacer). Le second terme est ce que « non purgeable » veut dire, lu sur le
    /// prédicat de production et non sur une phrase.
    fn signaux(src: &str, key: &str, famille: &str) -> (i64, i64) {
        signaux_cle(src, Some(key), famille)
    }
    /// MÊME lecture, clé OPTIONNELLE : le cas `P9.4-b` porte sur une base EN CLAIR (`PLUME_DB_KEY`
    /// vide, ce que livrent `docker-compose.yml` et `deploy/k3s.yaml`), qui s'ouvre SANS clé.
    fn signaux_cle(src: &str, key: Option<&str>, famille: &str) -> (i64, i64) {
        let c = open_db_keyed(src, key).unwrap();
        let ou = format!("source='plume-config' AND category='health' AND {famille}");
        let n: i64 = c.query_row(&format!("SELECT COUNT(*) FROM event WHERE {ou}"), [], |r| r.get(0)).unwrap();
        let purgeables: i64 = c.query_row(
            &format!("SELECT COUNT(*) FROM event WHERE {ou} AND {}", crate::rollups::RETENTION_NONPURGE), [], |r| r.get(0)).unwrap();
        (n, purgeables)
    }
    /// P8.25-a — la posture « symétrique ».
    fn signaux_de_posture(src: &str, key: &str) -> (i64, i64) {
        signaux(src, key, "fields LIKE '%no-age-recipient%'")
    }
    /// P8.26-a — l'exercice de restauration dû, tel que `signal_exercice_du` le marque dans ses
    /// `fields` (`restore_drill` = l'état), tout état confondu. Pas sur `dedup` : la clé STOCKÉE est
    /// cloisonnée par hôte (`dedup_scoped_by_host`), un motif ancré sur la clé de l'émetteur ne trouverait
    /// jamais rien — et le témoin (a) rendrait « aucun signal » pour la mauvaise raison.
    const FAMILLE_EXERCICE: &str = "fields LIKE '%\"restore_drill\":%'";
    fn signaux_d_exercice(src: &str, key: &str) -> (i64, i64) {
        signaux(src, key, FAMILLE_EXERCICE)
    }
    /// L'état d'exercice que porte le DERNIER signal d'exercice (`fields.restore_drill`), s'il y en a un.
    fn etat_du_dernier_signal_d_exercice(src: &str, key: &str) -> Option<String> {
        let c = open_db_keyed(src, Some(key)).unwrap();
        c.query_row(&format!("SELECT json_extract(fields,'$.restore_drill') FROM event WHERE {FAMILLE_EXERCICE} ORDER BY id DESC LIMIT 1"),
            [], |r| r.get(0)).ok()
    }
    /// Un exercice de restauration enregistré À L'INSTANT sur la base source, sur le mode donné.
    fn enregistrer_un_exercice_frais(src: &str, key: &str, chiffrement: crate::backup::BackupKind) {
        let c = open_db_keyed(src, Some(key)).unwrap();
        let ex = crate::exercice_de_restauration::Exercice {
            ts: now(), archive: "plume-exercice.db.age".into(), archive_octets: 4096, chiffrement, tables: 3, lignes: 12,
        };
        crate::exercice_de_restauration::enregistrer(&c, &ex, now()).expect("enregistrement de l'exercice");
    }

    fn archives_publiees(dest: &str) -> Vec<String> {
        std::fs::read_dir(dest).unwrap().filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with("plume-") && n.ends_with(".db.age")).collect()
    }

    /// (a) Le cycle natif SANS destinataire publie une archive ET écrit le signal — un seul, non
    /// purgeable, dédupliqué à l'heure (un second cycle dans la même heure n'en ajoute pas).
    #[test]
    fn le_cycle_natif_sans_destinataire_emet_le_signal_de_posture() {
        let _reglages = BACKUP_ENV_LOCK.read(); // `scheduled_backup_cycle` -> `backup_compressed` LIT les réglages
        let dir = crate::tmp_possede::TmpPossede::neuf("p825-sym");
        let key = "p825-cle-symetrique";
        let src = base_source_au_contrat(&dir, key);
        let dest = dir.sous("backups").as_str().to_owned();
        std::fs::create_dir_all(&dest).unwrap();
        assert_eq!(signaux_de_posture(&src, key), (0, 0), "TÉMOIN : aucun signal avant le cycle");

        let seau_avant = now() / 3600; // le seau de dédup est l'heure (cf. `emit_backup_symmetric_signal`)
        let publie = crate::server::scheduled_backup_cycle(&src, &dest, 4, Some(key), None);
        assert!(publie.is_some(), "le cycle doit avoir publié une archive");
        assert_eq!(archives_publiees(&dest).len(), 1);
        assert_eq!(signaux_de_posture(&src, key), (1, 0),
            "archive symétrique publiée -> UN signal de posture, que la rétention n'a pas le droit d'effacer");

        // Dédup horaire : le cycle suivant, dans la même heure, n'ajoute pas de second signal. Si l'heure a
        // tourné entre les deux cycles, un second signal est légitime : l'attente est bornée par les seaux
        // traversés, pas figée à 1 (sinon le test rougirait quelques secondes par heure).
        std::thread::sleep(std::time::Duration::from_millis(1100)); // un nom d'archive à la seconde
        let publie2 = crate::server::scheduled_backup_cycle(&src, &dest, 4, Some(key), None);
        assert!(publie2.is_some() && publie2 != publie, "second cycle : une seconde archive, un autre nom");
        let seau_apres = now() / 3600;
        let n = signaux_de_posture(&src, key).0;
        if seau_avant == seau_apres {
            assert_eq!(n, 1, "même heure -> toujours un seul signal (dédup)");
        } else {
            assert!((1..=2).contains(&n), "heure tournée entre les cycles -> un ou deux signaux, jamais plus : {n}");
        }
    }

    /// (b) Le témoin inverse : AVEC destinataire, l'archive est publiée et AUCUN signal de posture
    /// symétrique n'est écrit. Un appel inconditionnel du signal rougit ici. (Le signal d'EXERCICE,
    /// lui, ne regarde pas le destinataire : son témoin inverse est un exercice frais, plus bas.)
    #[test]
    fn le_cycle_natif_avec_destinataire_n_emet_aucun_signal_de_posture() {
        let _reglages = BACKUP_ENV_LOCK.read(); // `scheduled_backup_cycle` -> `backup_compressed` LIT les réglages
        let dir = crate::tmp_possede::TmpPossede::neuf("p825-asym");
        let key = "p825-cle-asymetrique";
        let src = base_source_au_contrat(&dir, key);
        let dest = dir.sous("backups").as_str().to_owned();
        std::fs::create_dir_all(&dest).unwrap();
        let destinataire = age::x25519::Identity::generate().to_public().to_string();

        let publie = crate::server::scheduled_backup_cycle(&src, &dest, 4, Some(key), Some(&destinataire));
        assert!(publie.is_some(), "le cycle doit avoir publié une archive");
        assert_eq!(archives_publiees(&dest).len(), 1);
        assert_eq!(signaux_de_posture(&src, key), (0, 0), "destinataire présent -> posture saine, AUCUN signal");
    }

    /// (c) Un cycle qui ÉCHOUE n'avoue aucune posture D'ARCHIVE : on ne signale pas le chiffrement ni
    /// l'éprouvé d'une sauvegarde qui n'existe pas. Ce qu'un tel cycle dit désormais, il le dit dans SA
    /// famille — le signal `P9.4-b` « aucune archive publiée », dont les témoins suivent ce bloc.
    /// Deux échecs distincts, parce qu'ils n'ont pas le même point de sortie : la sauvegarde
    /// refusée (clé fausse : `backup_compressed` rend Err), et la sauvegarde PRODUITE mais jamais
    /// PUBLIÉE (le rename échoue : le chemin final est un répertoire). Un signal posé sur le `Ok` de
    /// `backup_compressed`, avant le rename, passerait le premier et rougirait au second.
    #[test]
    fn un_cycle_natif_qui_echoue_n_avoue_aucune_posture_d_archive() {
        let _reglages = BACKUP_ENV_LOCK.read(); // `scheduled_backup_cycle` -> `backup_compressed` LIT les réglages
        let dir = crate::tmp_possede::TmpPossede::neuf("p825-echec");
        let key = "p825-la-bonne-cle";
        let src = base_source_au_contrat(&dir, key);
        let dest = dir.sous("backups").as_str().to_owned();
        std::fs::create_dir_all(&dest).unwrap();

        // Échec 1 : clé fausse -> `backup_compressed` refuse, rien n'est publié.
        let publie = crate::server::scheduled_backup_cycle(&src, &dest, 4, Some("p825-la-MAUVAISE-cle"), None);
        assert!(publie.is_none() && archives_publiees(&dest).is_empty(), "clé fausse : aucune archive");
        assert_eq!((signaux_de_posture(&src, key), signaux_d_exercice(&src, key)), ((0, 0), (0, 0)),
            "sauvegarde refusée -> aucun signal, ni de posture ni d'exercice (P8.26-a)");

        // Échec 2 : le nom canonique est OCCUPÉ par un répertoire non vide -> le rename échoue, le
        // cycle abandonne. Le nom porte l'instant de DÉBUT du cycle (à la seconde) : on occupe la
        // seconde courante et les deux suivantes.
        let t = now();
        for s in t..t + 3 {
            let occupe = format!("{dest}/plume-{}.db.age/occupe", crate::backup::fmt_backup_ts(s));
            std::fs::create_dir_all(&occupe).unwrap();
        }
        let publie = crate::server::scheduled_backup_cycle(&src, &dest, 4, Some(key), None);
        assert!(publie.is_none(), "rename impossible : le cycle n'a rien publié");
        assert!(!std::fs::read_dir(&dest).unwrap().filter_map(|e| e.ok()).any(|e| e.path().is_file()),
            "rename impossible : ni archive ni temporaire ne subsiste");
        assert_eq!((signaux_de_posture(&src, key), signaux_d_exercice(&src, key)), ((0, 0), (0, 0)),
            "sauvegarde produite mais JAMAIS publiée -> aucun signal, ni de posture ni d'exercice (ils ne partent qu'après le rename, sur UNE porte — P8.26-a)");
    }

    /// P8.26-a (a) — Le cycle natif publie une archive sur une installation où AUCUN exercice de
    /// restauration n'a jamais été enregistré : le signal « restauration non éprouvée » est écrit — un
    /// seul, non purgeable, dédupliqué au JOUR (un second cycle le même jour n'en ajoute pas). La
    /// condition n'est PAS le destinataire : une archive qui part vers un séquestre et que personne n'a
    /// jamais restaurée est tout aussi non éprouvée, et reçoit le même signal.
    #[test]
    fn le_cycle_natif_sans_exercice_enregistre_emet_le_signal_d_exercice_du() {
        let _reglages = BACKUP_ENV_LOCK.read(); // `scheduled_backup_cycle` -> `backup_compressed` LIT les réglages
        let dir = crate::tmp_possede::TmpPossede::neuf("p826-jamais");
        let key = "p826-cle-jamais";
        let src = base_source_au_contrat(&dir, key);
        let dest = dir.sous("backups").as_str().to_owned();
        std::fs::create_dir_all(&dest).unwrap();
        assert_eq!(signaux_d_exercice(&src, key), (0, 0), "TÉMOIN : aucun signal avant le cycle");

        let jour_avant = now() / 86_400; // le seau de dédup est le JOUR (cf. `signal_exercice_du`)
        let publie = crate::server::scheduled_backup_cycle(&src, &dest, 4, Some(key), None);
        assert!(publie.is_some(), "le cycle doit avoir publié une archive");
        assert_eq!(archives_publiees(&dest).len(), 1);
        assert_eq!(signaux_d_exercice(&src, key), (1, 0),
            "archive publiée sans exercice enregistré -> UN signal d'exercice dû, que la rétention n'a pas le droit d'effacer");
        assert_eq!(etat_du_dernier_signal_d_exercice(&src, key).as_deref(), Some("jamais"), "le signal dit QUEL défaut : jamais éprouvée");

        // Dédup quotidienne : le cycle suivant, le même jour, n'ajoute rien. Si le jour a tourné entre les
        // deux cycles, un second signal est légitime : borné par les seaux traversés, pas figé à 1.
        std::thread::sleep(std::time::Duration::from_millis(1100)); // un nom d'archive à la seconde
        let publie2 = crate::server::scheduled_backup_cycle(&src, &dest, 4, Some(key), None);
        assert!(publie2.is_some() && publie2 != publie, "second cycle : une seconde archive, un autre nom");
        let n = signaux_d_exercice(&src, key).0;
        if jour_avant == now() / 86_400 {
            assert_eq!(n, 1, "même jour -> toujours un seul signal d'exercice (dédup)");
        } else {
            assert!((1..=2).contains(&n), "jour tourné entre les cycles -> un ou deux signaux, jamais plus : {n}");
        }

        // Le témoin qui sépare CE signal de celui de P8.25-a : AVEC destinataire, la posture est saine
        // (aucun signal symétrique) mais la restauration reste non éprouvée (un signal d'exercice).
        let dir2 = crate::tmp_possede::TmpPossede::neuf("p826-jamais-asym");
        let src2 = base_source_au_contrat(&dir2, key);
        let dest2 = dir2.sous("backups").as_str().to_owned();
        std::fs::create_dir_all(&dest2).unwrap();
        let destinataire = age::x25519::Identity::generate().to_public().to_string();
        assert!(crate::server::scheduled_backup_cycle(&src2, &dest2, 4, Some(key), Some(&destinataire)).is_some());
        assert_eq!(signaux_de_posture(&src2, key), (0, 0), "destinataire présent -> posture saine");
        assert_eq!(signaux_d_exercice(&src2, key), (1, 0), "…mais jamais restaurée -> le signal d'exercice part quand même");
    }

    /// P8.26-a (b) — Le témoin inverse : un exercice FRAIS est enregistré, sur le mode de l'archive qui
    /// va partir ; le cycle publie et AUCUN signal d'exercice n'est écrit (la posture symétrique, elle,
    /// l'est : la porte a bien été ouverte). Un appel qui émettrait sans lire l'état rougit ici. Puis la
    /// seconde moitié de la condition : le MÊME exercice, symétrique, ne clôt rien si l'archive part vers
    /// un séquestre — le chemin de reprise réel n'a pas été éprouvé, le signal le dit par son état. C'est
    /// ce qui prouve que `escrow_asymetrique` est dérivé du destinataire de l'archive, pas figé.
    #[test]
    fn le_cycle_natif_apres_un_exercice_frais_n_emet_aucun_signal_d_exercice() {
        let _reglages = BACKUP_ENV_LOCK.read(); // `scheduled_backup_cycle` -> `backup_compressed` LIT les réglages
        let dir = crate::tmp_possede::TmpPossede::neuf("p826-frais");
        let key = "p826-cle-frais";
        let src = base_source_au_contrat(&dir, key);
        let dest = dir.sous("backups").as_str().to_owned();
        std::fs::create_dir_all(&dest).unwrap();
        enregistrer_un_exercice_frais(&src, key, crate::backup::BackupKind::Symmetric);

        let publie = crate::server::scheduled_backup_cycle(&src, &dest, 4, Some(key), None);
        assert!(publie.is_some(), "le cycle doit avoir publié une archive");
        assert_eq!(archives_publiees(&dest).len(), 1);
        assert_eq!(signaux_de_posture(&src, key), (1, 0), "la porte a été ouverte : la posture symétrique est signalée");
        assert_eq!(signaux_d_exercice(&src, key), (0, 0), "exercice frais sur le mode de l'archive -> AUCUN signal d'exercice");

        // Même exercice (symétrique), mais l'archive suivante part vers un destinataire : le chemin qui
        // servira au sinistre — l'identité d'escrow — n'a jamais servi. Le signal part, et nomme cet état.
        std::thread::sleep(std::time::Duration::from_millis(1100)); // un nom d'archive à la seconde
        let destinataire = age::x25519::Identity::generate().to_public().to_string();
        assert!(crate::server::scheduled_backup_cycle(&src, &dest, 4, Some(key), Some(&destinataire)).is_some());
        assert_eq!(signaux_d_exercice(&src, key), (1, 0), "exercice symétrique, archive vers un séquestre -> un signal");
        assert_eq!(etat_du_dernier_signal_d_exercice(&src, key).as_deref(), Some("mode_non_eprouve"),
            "le signal dit que c'est le MODE qui n'est pas éprouvé, pas l'âge");
    }

    /// GARDE DÉRIVÉE : tout chemin de production qui ÉCRIT une archive (appelle `backup_compressed`)
    /// atteint TOUS les signaux de posture — directement, ou par une fonction de production qui les
    /// émet. Rien n'est énuméré, ni d'un côté ni de l'autre : les ÉCRIVAINS sont dérivés des appelants
    /// de `backup_compressed` ; les SIGNAUX sont les fonctions libres de production dont le nom commence
    /// par `signal_` et qu'aucune autre d'entre elles n'appelle — la RACINE conditionnelle, celle qui
    /// décide depuis la connexion seule (`signal_exercice_du` reçoit son état de son appelant : un chemin
    /// qui l'appellerait directement DICTERAIT l'état au lieu de le lire, et ne serait pas acquitté ;
    /// `emit_backup_symmetric_signal` émet sans regarder le destinataire, même raison). Pour chaque
    /// signal, les ÉMETTEURS sont le point fixe de ses appelants, et chaque écrivain doit en être.
    ///
    /// L'INSTRUMENT EST VALIDÉ AVANT DE CONCLURE : au moins DEUX signaux dérivés (la posture symétrique
    /// de P8.25-a et l'exercice de restauration de P8.26-a — sous ce plancher, un signal a été renommé
    /// hors de la dérivation et la garde refuse de conclure plutôt que d'acquitter sur moins), au moins
    /// deux écrivains trouvés (la sous-commande et le cycle natif, les deux chemins connus), un corps
    /// synthétique qui écrit sans émettre est ACCUSÉ pour chaque signal, le même corps qui émet tous
    /// les signaux est ACQUITTÉ, et un corps qui ne nomme l'écrivain qu'en commentaire n'est pas un
    /// écrivain.
    #[test]
    fn toute_ecriture_d_archive_en_production_emet_tous_les_signaux_de_posture() {
        use crate::db_open::door_tests::{rs_files, sans_commentaire};
        const ECRIVAIN: &str = "backup_compressed";
        const PREFIXE_SIGNAL: &str = "signal_";

        /// Les unités d'indentation 0 d'un fichier de production : (nom, corps SANS sa ligne d'en-tête).
        fn unites(src: &str) -> Vec<(String, String)> {
            let mut out: Vec<(String, String)> = Vec::new();
            for l in src.lines() {
                let t = l.trim_start();
                let en_tete = l.len() == t.len() && ["fn ", "pub fn ", "pub(crate) fn ", "async fn ", "pub(crate) async fn "]
                    .iter().any(|p| t.starts_with(p));
                if en_tete {
                    let nom: String = t[t.find("fn ").unwrap() + 3..].chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    out.push((nom, String::new()));
                } else if let Some(u) = out.last_mut() { u.1.push_str(l); u.1.push('\n'); }
            }
            out
        }
        /// APPEL de la fonction LIBRE `nom` : borne de mot à gauche, et pas un appel de MÉTHODE (`next.run(`
        /// dans chaque middleware ferait entrer `server::run` dans le point fixe, puis tout ce qui l'appelle).
        /// Commentaires retirés ligne à ligne.
        fn appelle(corps: &str, nom: &str) -> bool {
            let motif = format!("{nom}(");
            corps.lines().map(sans_commentaire).any(|l| l.match_indices(&motif)
                .any(|(i, _)| !l[..i].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '.')))
        }
        /// Le point fixe des appelants de `racine` parmi `production` — ce qui « émet » ce signal.
        fn emetteurs_de(production: &[(String, String, String)], racine: &str) -> Vec<String> {
            let mut emetteurs = vec![racine.to_string()];
            loop {
                let avant = emetteurs.len();
                for (_, nom, corps) in production {
                    if !emetteurs.contains(nom) && emetteurs.iter().any(|e| appelle(corps, e)) { emetteurs.push(nom.clone()); }
                }
                if emetteurs.len() == avant { return emetteurs; }
            }
        }

        let racine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        rs_files(&racine, &mut fichiers);
        // Production = hors `src/tests/` et hors les `tests.rs` de module (cold_store en porte un).
        let production: Vec<(String, String, String)> = fichiers.iter()
            .filter(|f| !f.starts_with(racine.join("tests")) && f.file_name().is_some_and(|n| n != "tests.rs"))
            .flat_map(|f| {
                let nom_fichier = f.file_name().unwrap().to_string_lossy().into_owned();
                unites(&std::fs::read_to_string(f).unwrap()).into_iter().map(move |(n, c)| (nom_fichier.clone(), n, c))
            }).collect();

        // Les SIGNAUX DE POSTURE : les `signal_*` de production qu'aucun autre `signal_*` n'appelle.
        let candidats: Vec<&(String, String, String)> = production.iter().filter(|(_, nom, _)| nom.starts_with(PREFIXE_SIGNAL)).collect();
        let signaux: Vec<String> = candidats.iter()
            .filter(|(_, nom, _)| !candidats.iter().any(|(_, autre, corps)| autre != nom && appelle(corps, nom)))
            .map(|(_, nom, _)| nom.clone()).collect();
        // Pour chaque signal, ses émetteurs ; puis les ÉCRIVAINS (qui appelle `backup_compressed`, hors
        // elle-même) et, pour chacun, les signaux qu'il N'ATTEINT PAS.
        let emetteurs: Vec<(String, Vec<String>)> = signaux.iter().map(|s| (s.clone(), emetteurs_de(&production, s))).collect();
        let manquants = |corps: &str| -> Vec<String> {
            emetteurs.iter().filter(|(_, em)| !em.iter().any(|e| appelle(corps, e))).map(|(s, _)| s.clone()).collect()
        };
        let ecrivains: Vec<(String, String, Vec<String>)> = production.iter()
            .filter(|(_, nom, corps)| nom != ECRIVAIN && appelle(corps, ECRIVAIN))
            .map(|(f, nom, corps)| (f.clone(), nom.clone(), manquants(corps)))
            .collect();
        eprintln!("[posture-sauvegarde] signaux dérivés : {signaux:?} ; émetteurs : {emetteurs:?} ; écrivains (signaux manquants) : {ecrivains:?}");

        // Validation de l'instrument, puis la propriété.
        assert!(signaux.len() >= 2, "l'instrument ne dérive que {} signal(aux) de posture ({signaux:?}) : un signal a été renommé hors du préfixe `{PREFIXE_SIGNAL}` ou la dérivation ne lit plus les corps (attendus : la posture symétrique et l'exercice de restauration) — la garde REFUSE de conclure sur moins", signaux.len());
        assert!(ecrivains.len() >= 2, "l'instrument ne trouve que {} écrivain(s) d'archive : il ne lit plus les corps (attendus : la sous-commande `backup` et `scheduled_backup_cycle`)", ecrivains.len());
        assert!(ecrivains.iter().any(|(_, n, _)| n == "scheduled_backup_cycle"), "la dérivation n'a pas retrouvé le cycle natif : elle est inerte");
        // Les témoins sont ASSEMBLÉS : une chaîne littérale qui nommerait l'écrivain ferait passer ce test
        // pour un test qui sauvegarde aux yeux de la garde du verrou (elle ne dépouille pas les chaînes).
        let nu = format!("    let st = {ECRIVAIN}(a, b, k, r)?;\n");
        // Le témoin d'acquittement nomme les RACINES dérivées, pas une fonction de production qui les
        // regroupe : sinon une mutation de production ferait échouer l'INSTRUMENT, avec le mauvais
        // diagnostic, au lieu de la propriété.
        let garde = signaux.iter().fold(nu.clone(), |acc, s| format!("{acc}    {s}(&conn, r, now());\n"));
        let prose = format!("    // {ECRIVAIN}(a, b, k, r) — en commentaire seulement\n");
        assert!(appelle(&nu, ECRIVAIN) && manquants(&nu).len() == signaux.len(), "le prédicat n'ACCUSE pas un écrivain muet pour CHAQUE signal : {:?}", manquants(&nu));
        assert!(manquants(&garde).is_empty(), "le prédicat n'ACQUITTE pas un écrivain qui émet tous les signaux : il accuserait tout ({:?})", manquants(&garde));
        for s in &signaux {
            let partiel = format!("{nu}    {s}(&conn, r, now());\n");
            assert_eq!(manquants(&partiel).len(), signaux.len() - 1, "un écrivain qui n'émet QUE `{s}` doit être accusé pour chacun des autres signaux");
        }
        assert!(!appelle(&prose, ECRIVAIN), "un commentaire qui nomme l'écrivain ne doit pas compter pour une écriture");
        assert!(!appelle("    next.run(req).await", "run") && appelle("    server::run(conf)", "run"),
            "un appel de MÉTHODE ne doit pas compter pour un appel de la fonction libre homonyme");
        for (s, em) in &emetteurs {
            assert!(em.len() <= 12,
                "le point fixe des émetteurs de `{s}` a enflé ({}) : {em:?} — un nom court y entre par homonymie, et tout écrivain qui l'appellerait serait acquitté à tort", em.len());
        }

        let muets: Vec<String> = ecrivains.iter().filter(|(_, _, m)| !m.is_empty())
            .map(|(f, n, m)| format!("{f}::{n} n'atteint pas : {}", m.join(", "))).collect();
        assert!(muets.is_empty(),
            "ces chemins de production ÉCRIVENT une archive sans émettre tous les signaux de posture :\n  {}\n\
             Une archive publiée sans ces signaux est, selon le signal manquant, déchiffrable par le nœud (P8.25-a) ou \
             jamais restaurée (P8.26-a) avec, pour seul témoin, une ligne de journal — les deux trous fermés sur le cycle natif.", muets.join("\n  "));
    }

    // ============================================================================================
    // P9.4-b — UN CYCLE QUI NE PRODUIT RIEN LE DIT ; UN CYCLE QUI PRODUIT NE DIT RIEN.
    // --------------------------------------------------------------------------------------------
    // LE DÉFAUT, MESURÉ SUR LES SOURCES le 2026-08-25. La branche de SUCCÈS du cycle natif lève deux
    // signaux de posture NON PURGEABLES (les témoins (a) à (d) ci-dessus). Sa branche d'ÉCHEC écrivait
    // UNE ligne sur la sortie d'erreur et rendait la main. Or `backup_compressed` REFUSE dès sa
    // première instruction quand la clé de base est vide, et les deux déploiements conteneurisés
    // ARMENT ce cycle en livrant `PLUME_DB_KEY` VIDE : à intervalle régulier un cycle partait,
    // échouait, et AUCUNE archive n'était jamais écrite — sans qu'aucune surface ne le dise.
    //
    // LES DEUX TÉMOINS, ET LE SECOND EST LE CŒUR. (1) un cycle SANS CLÉ ne publie rien et le signal
    // PART, non purgeable, dédupliqué à l'heure, son étape prise dans un ensemble FERMÉ et sa cause
    // NOMMANT la clé requise ; (2) un cycle qui PUBLIE n'émet AUCUN signal de cette famille — et le
    // témoin croisé (la posture symétrique, elle, est bien écrite) prouve que ce silence est une
    // décision et non une base qu'on n'aurait pas su ouvrir. Sans (2), une version qui crierait
    // TOUJOURS passerait (1) sans rien prouver.
    //
    // PUIS UNE GARDE DÉRIVÉE DU CORPS DU CYCLE : chaque sortie « aucune archive » de
    // `scheduled_backup_cycle` émet. Rien n'est énuméré — un TROISIÈME point de sortie ajouté demain
    // est contrôlé d'office.
    // ============================================================================================

    /// Une base plume EN CLAIR (aucune clé) au contrat : EXACTEMENT ce que livrent `docker-compose.yml`
    /// et `deploy/k3s.yaml` par défaut (`PLUME_DB_KEY` vide -> `db_key()` rend `None`). C'est la base
    /// sur laquelle le cycle natif tourne dans ces deux déploiements.
    fn base_source_en_clair(dir: &crate::tmp_possede::TmpPossede) -> String {
        let src = dir.sous("source.db").as_str().to_owned();
        let c = open_db_keyed(&src, None).unwrap();
        c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&c);
        c.execute("INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,'sshd','auth',3,'h','m','{}')",
            params![now()]).unwrap();
        src
    }

    /// P9.4-b — la famille « ce cycle n'a publié AUCUNE archive », telle que l'émetteur la marque dans
    /// ses `fields`. Pas sur `dedup` : la clé STOCKÉE est cloisonnée par hôte (`dedup_scoped_by_host`),
    /// un motif ancré dessus ne trouverait jamais rien et le témoin rendrait « aucun signal » pour la
    /// mauvaise raison — la même faute que celle déjà relevée sur la famille EXERCICE.
    const FAMILLE_SANS_ARCHIVE: &str = "fields LIKE '%\"backup_cycle\":\"no_archive\"%'";
    fn signaux_sans_archive(src: &str, key: Option<&str>) -> (i64, i64) {
        signaux_cle(src, key, FAMILLE_SANS_ARCHIVE)
    }
    /// L'ÉTAPE et la CAUSE que porte le DERNIER signal « aucune archive », s'il y en a un.
    fn etape_et_cause_du_dernier_signal_sans_archive(src: &str, key: Option<&str>) -> Option<(String, String)> {
        let c = open_db_keyed(src, key).unwrap();
        c.query_row(
            &format!("SELECT json_extract(fields,'$.step'), json_extract(fields,'$.cause') FROM event \
                      WHERE {FAMILLE_SANS_ARCHIVE} ORDER BY id DESC LIMIT 1"),
            [], |r| Ok((r.get(0)?, r.get(1)?))).ok()
    }

    /// P9.4-b (1) — LE CAS DU DÉPLOIEMENT CONTENEUR/CLUSTER, JOUÉ : base EN CLAIR, cycle armé, aucune
    /// clé. La sauvegarde compressée refuse, RIEN n'est écrit dans la destination — pas même un
    /// temporaire — et le cycle l'écrit dans la base, une fois, non purgeable, avec l'étape et la cause.
    #[test]
    fn le_cycle_natif_sans_cle_ne_publie_rien_et_le_dit() {
        let _reglages = BACKUP_ENV_LOCK.read(); // `scheduled_backup_cycle` -> `backup_compressed` LIT les réglages
        let dir = crate::tmp_possede::TmpPossede::neuf("p94b-sans-cle");
        let src = base_source_en_clair(&dir);
        let dest = dir.sous("backups").as_str().to_owned();
        std::fs::create_dir_all(&dest).unwrap();
        assert_eq!(signaux_sans_archive(&src, None), (0, 0), "TÉMOIN : aucun signal avant le cycle");

        let seau_avant = now() / 3600; // le seau de dédup est l'heure (cf. `emit_backup_cycle_failed_signal`)
        let publie = crate::server::scheduled_backup_cycle(&src, &dest, 24, None, None);
        assert!(publie.is_none(), "sans clé, la sauvegarde compressée REFUSE : ce cycle ne publie rien");
        assert!(archives_publiees(&dest).is_empty(), "aucune archive ne doit exister");
        assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 0,
            "la destination doit rester VIDE — pas même un temporaire : c'est ce que l'exploitant y trouve");
        assert_eq!(signaux_sans_archive(&src, None), (1, 0),
            "cycle sans archive -> UN signal, que la rétention n'a pas le droit d'effacer");

        let (etape, cause) = etape_et_cause_du_dernier_signal_sans_archive(&src, None).expect("le signal doit porter son étape et sa cause");
        assert!(crate::backup::CAUSES_DE_CYCLE_SANS_ARCHIVE.contains(&etape.as_str()),
            "l'étape `{etape}` sort de l'ensemble FERMÉ {:?} : la cardinalité de l'étiquette n'est plus bornée",
            crate::backup::CAUSES_DE_CYCLE_SANS_ARCHIVE);
        assert_eq!(etape, crate::backup::CYCLE_SANS_ARCHIVE_SAUVEGARDE_REFUSEE, "la sauvegarde a été REFUSÉE, pas produite-puis-perdue");
        assert!(cause.contains("PLUME_DB_KEY"),
            "la cause doit NOMMER la clé requise — sans elle, l'exploitant lit « échec » sans savoir quoi poser : {cause}");

        // DÉDUP HORAIRE : le cycle suivant, dans la même heure, n'ajoute pas de second signal — sinon un
        // `PLUME_BACKUP_INTERVAL` bas noierait l'exploitant sous le même fait. Si l'heure a tourné entre
        // les deux, un second signal est légitime : l'attente est bornée par les seaux traversés.
        std::thread::sleep(std::time::Duration::from_millis(1100)); // un nom d'archive à la seconde
        assert!(crate::server::scheduled_backup_cycle(&src, &dest, 24, None, None).is_none(), "second cycle : toujours rien");
        let n = signaux_sans_archive(&src, None).0;
        if seau_avant == now() / 3600 {
            assert_eq!(n, 1, "même heure -> toujours un seul signal (dédup)");
        } else {
            assert!((1..=2).contains(&n), "heure tournée entre les cycles -> un ou deux signaux, jamais plus : {n}");
        }
    }

    /// P9.4-b (2) — LE TÉMOIN INVERSE, ET C'EST LUI QUI REND LE PREMIER OPPOSABLE : un cycle qui PUBLIE
    /// n'émet AUCUN signal de cette famille. Le témoin CROISÉ, dans le même corps, interdit de lire ce
    /// silence comme une cécité : la posture symétrique, elle, EST écrite sur la même base par le même
    /// cycle — la porte a donc bien été ouverte, et l'absence du signal `P9.4-b` est une décision.
    #[test]
    fn un_cycle_natif_qui_publie_n_emet_aucun_signal_de_cycle_sans_archive() {
        let _reglages = BACKUP_ENV_LOCK.read(); // `scheduled_backup_cycle` -> `backup_compressed` LIT les réglages
        let dir = crate::tmp_possede::TmpPossede::neuf("p94b-publie");
        let key = "p94b-la-bonne-cle";
        let src = base_source_au_contrat(&dir, key);
        let dest = dir.sous("backups").as_str().to_owned();
        std::fs::create_dir_all(&dest).unwrap();

        let publie = crate::server::scheduled_backup_cycle(&src, &dest, 24, Some(key), None);
        assert!(publie.is_some(), "le cycle doit avoir publié une archive");
        assert_eq!(archives_publiees(&dest).len(), 1);
        assert_eq!(signaux_sans_archive(&src, Some(key)), (0, 0),
            "une archive A ÉTÉ publiée -> AUCUN signal « aucune archive ». Une version qui crierait à chaque cycle rougit ici");
        assert_eq!(signaux_de_posture(&src, key), (1, 0),
            "TÉMOIN CROISÉ : la posture symétrique EST écrite sur cette base par ce cycle — le silence ci-dessus n'est pas une base qu'on n'a pas su ouvrir");
    }

    /// P9.4-b (3) — LE SECOND POINT DE SORTIE SANS ARCHIVE, et il n'a pas la même étape : la sauvegarde
    /// est PRODUITE dans le temporaire mais jamais PUBLIÉE (le nom canonique est occupé par un
    /// répertoire -> le rename échoue). Rien n'est servi, rien n'est prunable ; le cycle le dit avec
    /// l'étape `publication_impossible`, distincte du refus. Une étiquette unique fondrait les deux
    /// causes, qui n'appellent pas le même geste.
    #[test]
    fn un_cycle_natif_qui_ne_publie_pas_son_temporaire_le_dit_avec_sa_propre_etape() {
        let _reglages = BACKUP_ENV_LOCK.read(); // `scheduled_backup_cycle` -> `backup_compressed` LIT les réglages
        let dir = crate::tmp_possede::TmpPossede::neuf("p94b-rename");
        let key = "p94b-cle-rename";
        let src = base_source_au_contrat(&dir, key);
        let dest = dir.sous("backups").as_str().to_owned();
        std::fs::create_dir_all(&dest).unwrap();

        // Le nom porte l'instant de DÉBUT du cycle (à la seconde) : on occupe la seconde courante et les
        // deux suivantes par un répertoire NON VIDE, que `rename` ne peut pas écraser.
        let t = now();
        for s in t..t + 3 {
            let occupe = format!("{dest}/plume-{}.db.age/occupe", crate::backup::fmt_backup_ts(s));
            std::fs::create_dir_all(&occupe).unwrap();
        }
        assert!(crate::server::scheduled_backup_cycle(&src, &dest, 24, Some(key), None).is_none(), "rename impossible : rien n'est publié");
        assert_eq!(signaux_sans_archive(&src, Some(key)), (1, 0), "cycle sans archive -> UN signal non purgeable");
        let (etape, cause) = etape_et_cause_du_dernier_signal_sans_archive(&src, Some(key)).expect("étape et cause dues");
        assert_eq!(etape, crate::backup::CYCLE_SANS_ARCHIVE_PUBLICATION_IMPOSSIBLE,
            "produite-mais-jamais-publiée n'est pas un refus : l'étape doit les distinguer");
        assert!(cause.contains("rename"), "la cause doit dire ce qui a échoué : {cause}");
        // Et les DEUX familles d'archive publiée restent muettes : rien n'a été publié.
        assert_eq!((signaux_de_posture(&src, key), signaux_d_exercice(&src, key)), ((0, 0), (0, 0)),
            "aucune archive publiée -> aucune posture d'archive avouée");
    }

    /// P9.4-b (4) — GARDE DÉRIVÉE DU CORPS DU CYCLE : CHAQUE sortie « aucune archive » de
    /// `scheduled_backup_cycle` émet le signal. Rien n'est énuméré — la population est faite des
    /// `return None` du corps LIVRÉ, commentaires retirés ; un TROISIÈME point de sortie ajouté demain
    /// est contrôlé sans être nommé ici.
    ///
    /// L'INSTRUMENT EST VALIDÉ AVANT DE CONCLURE : un plancher sur le nombre de sorties réellement
    /// LUES (sous lui, c'est la lecture qui est cassée et la garde REFUSE de conclure plutôt que de
    /// rendre vert en étant aveugle), un corps synthétique qui sort sans émettre est ACCUSÉ, le même
    /// corps qui émet est ACQUITTÉ, et un corps qui ne nomme l'émission qu'en COMMENTAIRE est accusé.
    #[test]
    fn toute_sortie_sans_archive_du_cycle_natif_emet_le_signal() {
        use crate::db_open::door_tests::sans_commentaire;
        const EMETTEUR: &str = "signaler_qu_aucune_archive_n_a_ete_publiee";
        const SORTIE: &str = "return None;";
        /// Sous ce nombre de sorties réellement lues, c'est l'instrument qui est cassé.
        const PLANCHER_SORTIES: usize = 2;

        /// Les sorties « aucune archive » qui n'émettent PAS : pour chaque `return None;` du corps, les
        /// lignes qui le précèdent DANS SON BLOC (jusqu'à l'accolade ouvrante la plus proche) doivent
        /// nommer l'émetteur. Rend (sorties lues, numéros de ligne fautifs).
        fn sorties_muettes(corps: &str) -> (usize, Vec<usize>) {
            let lignes: Vec<String> = corps.lines().map(|l| sans_commentaire(l).to_string()).collect();
            let (mut vues, mut muettes) = (0usize, Vec::new());
            for (i, l) in lignes.iter().enumerate() {
                if !l.contains(SORTIE) { continue; }
                vues += 1;
                // remonte jusqu'à l'ouverture du bloc qui porte cette sortie (ou le début du corps)
                // Un APPEL, pas une MENTION : `let _ = (X, signaler_qu_...)` nomme l'émetteur sans
                // l'exécuter, et acquittait à tort — mesuré en MUTANT ce module le 2026-08-25.
                let mut emet = false;
                for j in (0..i).rev() {
                    if lignes[j].contains(&format!("{EMETTEUR}(")) { emet = true; break; }
                    if lignes[j].trim_end().ends_with('{') { break; }
                }
                if !emet { muettes.push(i + 1); }
            }
            (vues, muettes)
        }

        // Témoins de la lecture, dans les DEUX sens, avant de juger le corps livré.
        let muet = "    match x {\n        Err(e) => {\n            eprintln!(\"{e}\");\n            return None;\n        }\n    }\n";
        let garde = format!("    match x {{\n        Err(e) => {{\n            eprintln!(\"{{e}}\");\n            {EMETTEUR}(db, key, ETAPE, &e);\n            return None;\n        }}\n    }}\n");
        let prose = format!("    match x {{\n        Err(e) => {{\n            // {EMETTEUR}(db, key, ETAPE, &e) — en commentaire seulement\n            return None;\n        }}\n    }}\n");
        assert_eq!(sorties_muettes(muet), (1, vec![4]), "la lecture n'ACCUSE pas une sortie muette");
        assert_eq!(sorties_muettes(&garde).1, Vec::<usize>::new(), "la lecture n'ACQUITTE pas une sortie qui émet");
        assert_eq!(sorties_muettes(&prose).1, vec![4], "une émission écrite en COMMENTAIRE ne doit pas acquitter");
        // MESURÉ le 2026-08-25 en mutant le module : la première version de cette lecture cherchait le
        // NOM de l'émetteur, et `let _ = (ETAPE, signaler_…);` l'acquittait sans rien exécuter — un
        // correctif dégénéré serait passé. Un appel se distingue d'une mention par sa parenthèse.
        let mention = format!("    match x {{\n        Err(e) => {{\n            let _ = (ETAPE, {EMETTEUR});\n            return None;\n        }}\n    }}\n");
        assert_eq!(sorties_muettes(&mention).1, vec![4], "une MENTION de l'émetteur, sans appel, ne doit pas acquitter");

        let fichier = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/server/sauvegarde_planifiee.rs");
        let source = std::fs::read_to_string(&fichier).expect("le module de l'ordonnanceur doit être lisible");
        let debut = source.find("pub(crate) fn scheduled_backup_cycle").expect("INSTRUMENT : le cycle n'est plus dans ce module");
        // BORNÉ à l'accolade fermante d'indentation 0 : sans cette borne, une fonction écrite APRÈS le
        // cycle verrait ses propres `return None` jugés par cette garde, avec le mauvais diagnostic.
        let fin = source[debut..].find("\n}\n").map(|i| debut + i).unwrap_or(source.len());
        let corps = &source[debut..fin];
        let (vues, muettes) = sorties_muettes(corps);
        eprintln!("[p94b] {vues} sortie(s) `{SORTIE}` lue(s) dans le cycle natif ; muettes : {muettes:?}");
        assert!(vues >= PLANCHER_SORTIES,
            "{vues} sortie(s) `{SORTIE}` lue(s) dans `scheduled_backup_cycle`, plancher {PLANCHER_SORTIES} : la lecture est cassée, la garde REFUSE de conclure");
        assert!(muettes.is_empty(),
            "ces sorties du cycle natif rendent la main SANS ARCHIVE et SANS SIGNAL (lignes {muettes:?} du corps lu) : \
             un cycle qui ne produit rien redeviendrait invisible, comme il l'était avant P9.4-b — l'exploitant \
             croirait disposer de la rétention annoncée à côté et n'aurait AUCUNE archive.");
    }
