    // ============================================================================================
    // P8.25-a — LE SIGNAL DE POSTURE SUIT L'ARCHIVE, SUR LE CHEMIN NATIF AUSSI.
    // --------------------------------------------------------------------------------------------
    // Le signal SOC non purgeable « sauvegarde symétrique : aucun destinataire d'escrow » n'avait qu'un
    // appelant, la sous-commande `backup`. Le cycle NATIF (`server::scheduled_backup_cycle`), celui que
    // `deploy/k3s.yaml` active, publiait des archives déchiffrables par le nœud avec pour seul témoin
    // une ligne sur la sortie d'erreur. Trois témoins ci-dessous, puis une garde DÉRIVÉE de ce qui
    // écrit l'archive — jamais une liste de fonctions.
    //
    // Chaque témoin relit la base SOURCE après le cycle : c'est là que le signal s'écrit (le cycle
    // n'a pas d'autre base), et l'archive, prise AVANT le signal, n'en porte pas la trace.
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

    /// Les signaux de posture « symétrique » présents dans la base : (nombre, nombre que la purge
    /// de rétention AURAIT le droit d'effacer). Le second terme est ce que « non purgeable » veut
    /// dire, lu sur le prédicat de production et non sur une phrase.
    fn signaux_de_posture(src: &str, key: &str) -> (i64, i64) {
        let c = open_db_keyed(src, Some(key)).unwrap();
        let ou = "source='plume-config' AND category='health' AND fields LIKE '%no-age-recipient%'";
        let n: i64 = c.query_row(&format!("SELECT COUNT(*) FROM event WHERE {ou}"), [], |r| r.get(0)).unwrap();
        let purgeables: i64 = c.query_row(
            &format!("SELECT COUNT(*) FROM event WHERE {ou} AND {}", crate::rollups::RETENTION_NONPURGE), [], |r| r.get(0)).unwrap();
        (n, purgeables)
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

    /// (b) Le témoin inverse : AVEC destinataire, l'archive est publiée et AUCUN signal n'est écrit.
    /// Un appel inconditionnel du signal rougit ici.
    #[test]
    fn le_cycle_natif_avec_destinataire_n_emet_aucun_signal() {
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
        assert_eq!(signaux_de_posture(&src, key), (0, 0), "sauvegarde refusée -> aucun signal");

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
        assert_eq!(signaux_de_posture(&src, key), (0, 0),
            "sauvegarde produite mais JAMAIS publiée -> aucun signal (il ne part qu'après le rename)");
    }

    /// GARDE DÉRIVÉE : tout chemin de production qui ÉCRIT une archive (appelle `backup_compressed`)
    /// émet aussi le signal de posture — directement, ou par une fonction de production qui l'émet.
    /// Rien n'est énuméré : les ÉCRIVAINS sont dérivés des appelants de `backup_compressed`, les
    /// ÉMETTEURS sont le point fixe des appelants de `signal_backup_symmetric_if_needed`. Le signal
    /// conditionnel est la racine, pas `emit_backup_symmetric_signal` : un chemin qui émettrait sans
    /// regarder le destinataire ne serait pas un appelant acquitté.
    ///
    /// L'INSTRUMENT EST VALIDÉ AVANT DE CONCLURE : au moins deux écrivains trouvés (la sous-commande
    /// et le cycle natif, les deux chemins connus), un corps synthétique qui écrit sans émettre est
    /// ACCUSÉ, le même corps qui émet est ACQUITTÉ, et un corps qui ne nomme l'écrivain qu'en
    /// commentaire n'est pas un écrivain.
    #[test]
    fn toute_ecriture_d_archive_en_production_emet_le_signal_de_posture() {
        use crate::db_open::door_tests::{rs_files, sans_commentaire};
        const ECRIVAIN: &str = "backup_compressed";
        const SIGNAL: &str = "signal_backup_symmetric_if_needed";

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

        // Les ÉMETTEURS : point fixe des appelants du signal conditionnel.
        let mut emetteurs = vec![SIGNAL.to_string()];
        loop {
            let avant = emetteurs.len();
            for (_, nom, corps) in &production {
                if !emetteurs.contains(nom) && emetteurs.iter().any(|e| appelle(corps, e)) { emetteurs.push(nom.clone()); }
            }
            if emetteurs.len() == avant { break; }
        }
        // Les ÉCRIVAINS : qui appelle `backup_compressed` (hors elle-même).
        let ecrivains: Vec<(String, String, bool)> = production.iter()
            .filter(|(_, nom, corps)| nom != ECRIVAIN && appelle(corps, ECRIVAIN))
            .map(|(f, nom, corps)| (f.clone(), nom.clone(), emetteurs.iter().any(|e| appelle(corps, e))))
            .collect();
        eprintln!("[posture-sauvegarde] émetteurs dérivés : {emetteurs:?} ; écrivains : {ecrivains:?}");

        // Validation de l'instrument, puis la propriété.
        assert!(ecrivains.len() >= 2, "l'instrument ne trouve que {} écrivain(s) d'archive : il ne lit plus les corps (attendus : la sous-commande `backup` et `scheduled_backup_cycle`)", ecrivains.len());
        assert!(ecrivains.iter().any(|(_, n, _)| n == "scheduled_backup_cycle"), "la dérivation n'a pas retrouvé le cycle natif : elle est inerte");
        // Les témoins sont ASSEMBLÉS : une chaîne littérale qui nommerait l'écrivain ferait passer ce test
        // pour un test qui sauvegarde aux yeux de la garde du verrou (elle ne dépouille pas les chaînes).
        let nu = format!("    let st = {ECRIVAIN}(a, b, k, r)?;\n");
        // Le témoin d'acquittement nomme la RACINE, pas une fonction dérivée : sinon une mutation de
        // production ferait échouer l'INSTRUMENT, avec le mauvais diagnostic, au lieu de la propriété.
        let garde = format!("    let st = {ECRIVAIN}(a, b, k, r)?;\n    {SIGNAL}(&conn, r, now());\n");
        let prose = format!("    // {ECRIVAIN}(a, b, k, r) — en commentaire seulement\n");
        assert!(appelle(&nu, ECRIVAIN) && !emetteurs.iter().any(|e| appelle(&nu, e)), "le prédicat n'ACCUSE pas un écrivain muet");
        assert!(emetteurs.iter().any(|e| appelle(&garde, e)), "le prédicat n'ACQUITTE pas un écrivain qui émet : il accuserait tout");
        assert!(!appelle(&prose, ECRIVAIN), "un commentaire qui nomme l'écrivain ne doit pas compter pour une écriture");
        assert!(!appelle("    next.run(req).await", "run") && appelle("    server::run(conf)", "run"),
            "un appel de MÉTHODE ne doit pas compter pour un appel de la fonction libre homonyme");
        assert!(emetteurs.len() <= 12,
            "le point fixe des émetteurs a enflé ({}) : {emetteurs:?} — un nom court y entre par homonymie, et tout écrivain qui l'appellerait serait acquitté à tort", emetteurs.len());

        let muets: Vec<String> = ecrivains.iter().filter(|(_, _, emet)| !emet).map(|(f, n, _)| format!("{f}::{n}")).collect();
        assert!(muets.is_empty(),
            "ces chemins de production ÉCRIVENT une archive sans émettre le signal de posture :\n  {}\n\
             Une archive symétrique publiée sans `{SIGNAL}` est déchiffrable par le nœud avec, pour seul témoin, \
             une ligne de journal — le trou que P8.25-a a fermé sur le cycle natif.", muets.join("\n  "));
    }
