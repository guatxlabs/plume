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
        let c = open_db_keyed(src, Some(key)).unwrap();
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

    /// (c) Un cycle qui ÉCHOUE n'avoue aucune posture : on ne signale pas une sauvegarde qui n'existe
    /// pas. Deux échecs distincts, parce qu'ils n'ont pas le même point de sortie : la sauvegarde
    /// refusée (clé fausse : `backup_compressed` rend Err), et la sauvegarde PRODUITE mais jamais
    /// PUBLIÉE (le rename échoue : le chemin final est un répertoire). Un signal posé sur le `Ok` de
    /// `backup_compressed`, avant le rename, passerait le premier et rougirait au second.
    #[test]
    fn un_cycle_natif_qui_echoue_n_emet_aucun_signal() {
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
