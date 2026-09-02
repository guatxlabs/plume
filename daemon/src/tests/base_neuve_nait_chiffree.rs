// `P9.6-a` — UNE BASE NEUVE NAÎT CHIFFRÉE ; UNE BASE EXISTANTE N'EST JAMAIS TOUCHÉE PAR UN DÉMARRAGE
// ================================================================================================
// CE QUE CE LOT FABRIQUE, ET QUI N'EXISTAIT PAS. Avant lui, perdre un fichier de clé n'avait AUCUN
// effet sur un déploiement livré tel quel : il n'y en avait pas. Après lui, perdre la clé d'une base
// chiffrée, c'est perdre le SOC entier et toutes ses archives, définitivement. Le lot crée donc une
// nouvelle façon de tout perdre, et la moitié la plus importante du travail est que cette clé et sa
// mise à l'abri soient IMPOSSIBLES à manquer.
//
// LE TÉMOIN QUI COMPTE LE PLUS EST LE DEUXIÈME, et il est écrit en premier dans l'ordre de lecture :
// une base EXISTANTE, au démarrage, ne bouge pas d'un octet. Se tromper dans l'autre sens — laisser
// une base neuve en clair — est le défaut d'avant, sans aggravation. Se tromper dans CE sens-là
// engendrerait une clé pour une base qui n'en a pas.
//
// AUCUN ÉTAT DE PROCESSUS N'EST TOUCHÉ PAR CE FICHIER pour les chemins injectables : la
// configuration est une `HashMap` passée en argument, comme `P8.7-b` l'a rendu possible après avoir
// mesuré que `PLUME_CONFIG` posé sous verrou faisait rougir deux tests d'incidents sans rapport. Les
// tests qui exercent la SAUVEGARDE prennent le verrou partagé des réglages, parce que
// `backup_compressed` relit, lui, des réglages ambiants.

    /// L'en-tête d'un fichier SQLite NON chiffré. SQLCipher chiffre la page 1 en entier, en-tête
    /// compris : sa présence est la preuve DIRECTE, sur le disque, que la base est en clair.
    const ENTETE_EN_CLAIR: &[u8; 16] = b"SQLite format 3\0";

    fn conf96(paires: &[(&str, &str)]) -> HashMap<String, String> {
        paires.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// Les octets ENTIERS d'un fichier — la valeur dont les témoins de non-régression mesurent
    /// l'immobilité. On ne compare pas une taille ni une date : on compare le contenu.
    fn octets(chemin: &std::path::Path) -> Vec<u8> {
        std::fs::read(chemin).expect("lecture du fichier")
    }

    /// Base plume EN CLAIR au SCHÉMA RÉEL (schema.sql + toute la chaîne de migrations), portant `n`
    /// events et une entrée de journal inaltérable. C'est la forme exacte d'une base de production
    /// restée en clair — celle que la conversion doit savoir traiter.
    fn base_plume_en_clair(chemin: &str, n: i64) {
        let conn = open_db_keyed(chemin, None).expect("création de la base en clair");
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        conn.execute_batch("BEGIN;").unwrap();
        for i in 0..n {
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,host,message,fields) \
                 VALUES(?1,'sshd','auth',3,'hote-a',?2,'{}')",
                params![now(), format!("MARQUEUR_P96A tentative n={i}")],
            )
            .unwrap();
        }
        conn.execute_batch("COMMIT;").unwrap();
        ledger_append(&conn, "test.fixture", "entrée de journal inaltérable posée par la fixture");
    }

    // ── ① LA TABLE DE DÉCISION, EXHAUSTIVE ET PURE ────────────────────────────────────────────────

    /// TOUTES les combinaisons, y compris celles qui ne devraient pas exister — un `match` qui
    /// laisserait un cas hors de son intention rendrait ici une décision qu'on n'a pas voulue. La
    /// propriété défendue est écrite comme une INVARIANTE et non comme une liste : `EngendrerLaCleAuto`
    /// ne sort JAMAIS d'un état autre que `Neuve`, ni en présence de la moindre clé.
    #[test]
    fn p96a_la_table_de_decision_ne_peut_pas_se_tromper_dans_le_sens_dangereux() {
        let verdicts = [
            None,
            Some(DbProbe::Fresh),
            Some(DbProbe::OpensWithKey),
            Some(DbProbe::Plaintext),
            Some(DbProbe::WrongKeyOrCorrupt),
            Some(DbProbe::Unopenable),
            Some(DbProbe::Locked),
        ];
        let etats = [
            EtatDuFichierDeBase::Neuve,
            EtatDuFichierDeBase::Existante,
            EtatDuFichierDeBase::Indecidable,
        ];
        let mut engendrements = 0usize;
        for explicite in [false, true] {
            for auto in [false, true] {
                for v in verdicts {
                    for e in etats {
                        let d = decision_at_rest(explicite, auto, v, e);
                        if d == DecisionAtRest::EngendrerLaCleAuto {
                            engendrements += 1;
                            assert_eq!(e, EtatDuFichierDeBase::Neuve,
                                "LE SENS DANGEREUX : une clé serait engendrée sur un état {e:?}");
                            assert!(!explicite && !auto,
                                "une clé serait engendrée alors qu'il en existe déjà une (explicite={explicite}, auto={auto})");
                        }
                        // Une base EXISTANTE sans aucune clé ne produit RIEN, jamais : c'est le témoin
                        // qui compte le plus, exprimé sur la décision avant de l'être sur les octets.
                        if !explicite && !auto && e == EtatDuFichierDeBase::Existante {
                            assert_eq!(d, DecisionAtRest::RienAFaire, "base existante, aucune clé -> RIEN");
                        }
                    }
                }
            }
        }
        assert!(engendrements > 0, "ANTI-FAUX-VERT : aucun engendrement n'a été atteint, la table ne prouve rien");

        // Les quatre issues NOMMÉES, une par une — un refus qui se confondrait avec un autre serait
        // illisible en exploitation, et c'est le message que l'exploitant a sous les yeux.
        assert_eq!(decision_at_rest(false, false, None, EtatDuFichierDeBase::Neuve), DecisionAtRest::EngendrerLaCleAuto);
        assert_eq!(decision_at_rest(true, false, Some(DbProbe::Plaintext), EtatDuFichierDeBase::Existante),
            DecisionAtRest::RefusConversionRequise, "clé EXPLICITE + base en clair -> refus qui nomme le geste");
        assert_eq!(decision_at_rest(false, true, Some(DbProbe::Plaintext), EtatDuFichierDeBase::Existante),
            DecisionAtRest::RefusCleAutoOrpheline, "clé AUTO orpheline -> refus DISTINCT (la cause n'est pas la même)");
        assert_eq!(decision_at_rest(true, false, Some(DbProbe::WrongKeyOrCorrupt), EtatDuFichierDeBase::Existante),
            DecisionAtRest::RefusCleQuiNOuvrePasLaBase, "comportement historique conservé");
        for v in [DbProbe::Fresh, DbProbe::OpensWithKey, DbProbe::Unopenable, DbProbe::Locked] {
            assert_eq!(decision_at_rest(true, false, Some(v), EtatDuFichierDeBase::Existante), DecisionAtRest::RienAFaire,
                "{v:?} : le démarrage continue, exactement comme avant ce lot");
        }
    }

    /// LA PROPRIÉTÉ « BASE NEUVE » EXIGE DEUX ABSENCES INDÉPENDANTES, et toute incertitude ne conclut
    /// pas. Mesuré sur de VRAIS fichiers : c'est la seule façon de savoir ce que `metadata` rend.
    #[test]
    fn p96a_l_etat_du_fichier_de_base_exige_deux_absences() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p96a-etat");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let p = |n: &str| dir.join(n).to_string_lossy().into_owned();

        let absent = p("absente.db");
        assert_eq!(etat_du_fichier_de_base(&absent), EtatDuFichierDeBase::Neuve, "fichier absent");

        let vide = p("vide.db");
        std::fs::write(&vide, b"").unwrap();
        assert_eq!(etat_du_fichier_de_base(&vide), EtatDuFichierDeBase::Neuve, "fichier de 0 octet");

        // LE SECOND TÉMOIN : un fichier principal VIDE mais un WAL qui porte des octets. Un seul
        // regard sur le fichier principal aurait dit « neuve » et engendré une clé.
        std::fs::write(format!("{vide}-wal"), b"des octets qui prouvent que quelque chose a vecu ici").unwrap();
        assert_eq!(etat_du_fichier_de_base(&vide), EtatDuFichierDeBase::Existante,
            "LE SENS DANGEREUX : un WAL non vide interdit de conclure à une base neuve");
        std::fs::remove_file(format!("{vide}-wal")).unwrap();
        assert_eq!(etat_du_fichier_de_base(&vide), EtatDuFichierDeBase::Neuve, "témoin inverse : WAL retiré -> neuve");

        let pleine = p("pleine.db");
        base_plume_en_clair(&pleine, 3);
        assert_eq!(etat_du_fichier_de_base(&pleine), EtatDuFichierDeBase::Existante, "base réelle");

        // UNE MESURE QUI ÉCHOUE NE REND PAS LE VERDICT LE PLUS RASSURANT (`S32`) : un composant de
        // chemin qui n'est pas un répertoire fait échouer `metadata` autrement que par « absent ».
        let sous_un_fichier = format!("{pleine}/impossible.db");
        assert_eq!(etat_du_fichier_de_base(&sous_un_fichier), EtatDuFichierDeBase::Indecidable,
            "chemin dont un composant n'est pas un répertoire -> on ne conclut PAS");
    }

    // ── ② LES TROIS MUTATIONS, SUR DE VRAIS FICHIERS ──────────────────────────────────────────────

    /// LE TÉMOIN QUI COMPTE LE PLUS. Une base EXISTANTE en clair, aucune clé configurée : le
    /// démarrage ne doit RIEN écrire. La valeur mesurée est l'ENSEMBLE des octets de la base, pas sa
    /// taille — et l'absence du fichier de clé, qui est la seule chose que ce lot pourrait créer.
    ///
    /// LA MUTATION EST DANS LE MÊME TEST, ET C'EST CE QUI LE REND CONCLUANT : la MÊME configuration,
    /// la MÊME fonction, sur une base ABSENTE, engendre la clé. Une version qui n'engendrerait jamais
    /// rien passerait la première moitié et rougirait la seconde.
    #[test]
    fn p96a_une_base_existante_en_clair_n_est_pas_touchee_par_un_demarrage() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p96a-immobile");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let p = |n: &str| dir.join(n).to_string_lossy().into_owned();

        let existante = p("existante.db");
        base_plume_en_clair(&existante, 25);
        let cle_attendue = format!("{existante}.key");
        let conf = conf96(&[("PLUME_DB", existante.as_str())]);

        let avant = octets(std::path::Path::new(&existante));
        assert_eq!(&avant[..16], ENTETE_EN_CLAIR, "état de départ : la base est EN CLAIR");

        // Plusieurs démarrages : ce n'est pas le premier qui compte, c'est qu'AUCUN ne touche rien.
        for tour in 1..=3 {
            ensure_encrypted(&conf, &existante);
            assert_eq!(octets(std::path::Path::new(&existante)), avant,
                "RÉGRESSION `P9.6-a` (tour {tour}) : le démarrage a MODIFIÉ une base existante. C'est la \
                 porte à sens unique que ce lot ferme — une conversion ne se déclenche jamais toute seule.");
            assert!(!std::path::Path::new(&cle_attendue).exists(),
                "RÉGRESSION (tour {tour}) : une clé a été ENGENDRÉE pour une base qui existait déjà — elle \
                 ne lui appartient pas, et le démarrage suivant lui opposerait un PRAGMA key qu'elle ne \
                 comprend pas");
            for compagnon in ["-wal", "-shm", ".plaintext.bak", ".conversion-en-cours", ".avant-chiffrement"] {
                assert!(!std::path::Path::new(&format!("{existante}{compagnon}")).exists(),
                    "RÉGRESSION (tour {tour}) : le démarrage a créé `{compagnon}`");
            }
        }

        // Le chemin de clé EXPLICITEMENT posé ne change rien : ce levier ne CRÉE rien par lui-même.
        let ailleurs = p("cle-posee-ailleurs.key");
        let conf_levier = conf96(&[("PLUME_DB", existante.as_str()), ("PLUME_DB_KEY_AUTO_PATH", ailleurs.as_str())]);
        ensure_encrypted(&conf_levier, &existante);
        assert_eq!(octets(std::path::Path::new(&existante)), avant, "levier posé : la base ne bouge toujours pas");
        assert!(!std::path::Path::new(&ailleurs).exists(),
            "poser PLUME_DB_KEY_AUTO_PATH sur un déploiement EN SERVICE ne doit engendrer AUCUNE clé");

        // ── LA MUTATION : MÊME configuration, base ABSENTE -> la clé EST engendrée. ────────────────
        let neuve = p("neuve.db");
        let conf_neuve = conf96(&[("PLUME_DB", neuve.as_str())]);
        ensure_encrypted(&conf_neuve, &neuve);
        assert!(std::path::Path::new(&format!("{neuve}.key")).exists(),
            "ANTI-FAUX-VERT : si rien n'est jamais engendré, l'immobilité prouvée plus haut ne prouve rien");
    }

    /// UNE BASE ABSENTE NAÎT CHIFFRÉE, ET SA CLÉ EST POSÉE EN 0600 — droits RELUS, pas seulement
    /// demandés. La preuve du chiffrement est faite sur les OCTETS du fichier, comme `P8.7-b`.
    #[test]
    fn p96a_une_base_absente_nait_chiffree_et_sa_cle_est_en_0600() {
        use std::os::unix::fs::PermissionsExt;
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p96a-naissance");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("neuve.db").to_string_lossy().into_owned();
        let chemin_cle = dir.join("at-rest.key").to_string_lossy().into_owned();
        let conf = conf96(&[("PLUME_DB", base.as_str()), ("PLUME_DB_KEY_AUTO_PATH", chemin_cle.as_str())]);

        assert!(!std::path::Path::new(&base).exists(), "état de départ : la base n'existe pas");
        ensure_encrypted(&conf, &base);

        let cle = cle_auto_lire(&chemin_cle).expect("la clé doit avoir été engendrée et être relisible");
        assert_eq!(cle.len(), 64, "256 bits d'aléa, en hexadécimal : {}", cle.len());
        assert!(cle.chars().all(|c| c.is_ascii_hexdigit()), "la clé est de l'hexadécimal");
        let mode = std::fs::metadata(&chemin_cle).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "les droits sont RELUS, pas seulement demandés : {mode:o}");

        // Le chemin résolu est celui que `db_key()` emploie : la même expression, sur la même conf.
        assert_eq!(cle_auto_chemin(&conf), chemin_cle, "le levier gagne sur le chemin dérivé");
        let conf_derivee = conf96(&[("PLUME_DB", base.as_str())]);
        assert_eq!(cle_auto_chemin(&conf_derivee), format!("{base}.key"), "levier vide -> chemin DÉRIVÉ de PLUME_DB");

        // LA BASE NAÎT CHIFFRÉE — mesuré sur les octets, avec son témoin négatif juste après.
        {
            let c = open_db_keyed(&base, Some(&cle)).unwrap();
            c.execute_batch("CREATE TABLE t(x TEXT); INSERT INTO t VALUES('valeur-p96a');").unwrap();
        }
        let tete = octets(std::path::Path::new(&base));
        assert_ne!(&tete[..16], ENTETE_EN_CLAIR,
            "RÉGRESSION `P9.6-a` : une base NEUVE porte encore `SQLite format 3\\0` — un `sqlite3` nu y \
             relirait les messages d'événement");
        assert_eq!(probe_db(&base, &cle), DbProbe::OpensWithKey,
            "…et ce n'est pas « illisible », c'est CHIFFRÉ AVEC CETTE CLÉ");

        // TÉMOIN NÉGATIF : la même fabrication SANS clé donne bien l'en-tête en clair — sans quoi
        // l'assertion ci-dessus passerait sur n'importe quel fichier.
        let temoin = dir.join("temoin-en-clair.db").to_string_lossy().into_owned();
        {
            let c = open_db_keyed(&temoin, None).unwrap();
            c.execute_batch("CREATE TABLE t(x TEXT); INSERT INTO t VALUES('valeur-p96a');").unwrap();
        }
        assert_eq!(&octets(std::path::Path::new(&temoin))[..16], ENTETE_EN_CLAIR,
            "témoin négatif : sans clé, l'en-tête SQLite est bien là (l'instrument voit ce qu'il prétend voir)");
    }

    /// UNE BASE DÉJÀ CHIFFRÉE NE BOUGE PAS NON PLUS — troisième mutation, et la seule qui exerce le
    /// chemin `OpensWithKey` de bout en bout sur un vrai fichier.
    #[test]
    fn p96a_une_base_deja_chiffree_n_est_pas_touchee() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p96a-deja");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("chiffree.db").to_string_lossy().into_owned();
        let cle = "cle-explicite-p96a-jamais-persistee";
        {
            let c = open_db_keyed(&base, Some(cle)).unwrap();
            c.execute_batch("CREATE TABLE t(x TEXT); INSERT INTO t VALUES('deja-chiffree');").unwrap();
        }
        let conf = conf96(&[("PLUME_DB", base.as_str()), ("PLUME_DB_KEY", cle)]);
        let avant = octets(std::path::Path::new(&base));
        ensure_encrypted(&conf, &base);
        assert_eq!(octets(std::path::Path::new(&base)), avant, "base déjà chiffrée : aucun octet ne change");
        assert!(!std::path::Path::new(&format!("{base}.key")).exists(),
            "aucune clé auto n'est engendrée quand une clé explicite gagne");
    }

    /// LA CLÉ N'EST JAMAIS RÉÉCRITE — ni par-dessus une clé existante, ni par-dessus un fichier VIDE
    /// (secret monté non peuplé). C'est la règle de `ledger_key_load`, et c'est aussi ce qui rend
    /// inoffensive la course entre deux démarrages simultanés.
    #[test]
    fn p96a_une_cle_auto_n_est_jamais_reecrite() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p96a-jamais-reecrite");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let chemin = dir.join("k.key").to_string_lossy().into_owned();

        let premiere = cle_auto_engendrer(&chemin).expect("première pose");
        let echec = cle_auto_engendrer(&chemin).expect_err("une clé existante n'est JAMAIS écrasée");
        assert!(echec.contains(&chemin), "l'échec nomme le fichier : {echec}");
        assert_eq!(cle_auto_lire(&chemin).as_deref(), Some(premiere.as_str()),
            "la clé d'origine est intacte — l'écraser romprait la lecture de la base qu'elle chiffre");

        // Fichier PRÉSENT mais VIDE : `cle_auto_lire` rend None (« aucune clé »), et la pose REFUSE.
        let vide = dir.join("vide.key").to_string_lossy().into_owned();
        std::fs::write(&vide, b"   \n").unwrap();
        assert_eq!(cle_auto_lire(&vide), None, "une clé vide vaut « aucune clé »");
        assert!(cle_auto_engendrer(&vide).is_err(), "fail-closed : on ne réécrit PAS par-dessus un fichier vide");

        // La lecture retire les espaces : une clé restaurée depuis un séquestre avec `echo` s'ouvre.
        let restauree = dir.join("restauree.key").to_string_lossy().into_owned();
        std::fs::write(&restauree, format!("{premiere}\n")).unwrap();
        assert_eq!(cle_auto_lire(&restauree).as_deref(), Some(premiere.as_str()),
            "le geste de reprise le plus banal (`echo \"$CLE\" > fichier`) doit rendre la MÊME clé");
    }

    /// SANS FICHIER DE CLÉ, `db_key()` REND CE QU'ELLE RENDAIT — c'est l'invariant de toute
    /// installation antérieure à ce lot, et il se mesure sans toucher un seul état de processus.
    #[test]
    fn p96a_sans_fichier_de_cle_la_resolution_ambiante_est_inchangee() {
        assert!(
            std::env::var("PLUME_DB_KEY").map(|v| v.is_empty()).unwrap_or(true)
                && std::env::var("PLUME_DB_KEY_FILE").map(|v| v.is_empty()).unwrap_or(true),
            "ce test EXIGE un environnement muet sur la clé"
        );
        let conf = conf96(&[("PLUME_DB", "/var/lib/plume/db/plume.db")]);
        let chemin = cle_auto_chemin(&conf);
        if !std::path::Path::new(&chemin).exists() {
            assert_eq!(db_key(), None,
                "aucune clé nulle part et aucun fichier de clé -> `None`, exactement comme avant `P9.6-a`");
        } else {
            // `P11.23-e` — LE CHEMIN MUET DE CE TEST, ET IL N'A PAS DE `return` POUR LE TRAHIR.
            // Sur une machine où le fichier de clé auto EXISTE (un hôte qui a déjà fait tourner le
            // démon), la seule assertion qui porte l'invariant annoncé — « sans fichier de clé, la
            // résolution rend ce qu'elle rendait » — est SAUTÉE, et le test reste vert sur les deux
            // qui l'encadrent. Le refus part par le canal plutôt que d'échouer : ce fichier
            // appartient à la machine, pas au test, et un rouge y serait inrefermable.
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "p96a_sans_fichier_de_cle_la_resolution_ambiante_est_inchangee",
                &format!(
                    "le fichier de clé auto « {chemin} » EXISTE sur cette machine : l'invariant \
                     « aucune clé nulle part -> `None` » n'a PAS été exercé. Rejouer sur un hôte \
                     qui n'a jamais démarré le démon, ou après avoir retiré ce fichier."
                ),
            );
        }
        assert_eq!(cle_auto_lire("/chemin/qui/n/existe/pas/du/tout.key"), None);
    }

    /// LES TROIS PROVENANCES DONNENT CHACUNE UNE CLÉ, ET LE TABLEAU QUI LES DÉCLARE DIT VRAI.
    ///
    /// POURQUOI CE TEST EXISTE PLUTÔT QU'UNE SIMPLE CONSTANTE. `CLES_QUI_DONNENT_UNE_CLE_DE_BASE`
    /// n'est lue par AUCUN chemin d'exécution : c'est la garde de CI
    /// `check_a_deployment_never_arms_a_task_it_cannot_run.py` qui en DÉRIVE sa classe d'équivalence,
    /// pour savoir qu'un manifeste satisfait la précondition de la sauvegarde compressée. Un tableau
    /// que seul un script Python lit finirait supprimé comme du code mort, et la garde deviendrait
    /// muette sans que rien ne rougisse. Ce test le RELIE au comportement qu'il annonce : chacun des
    /// trois noms, SEUL, doit rendre une clé.
    #[test]
    fn p96a_chacune_des_trois_provenances_donne_une_cle() {
        assert!(
            std::env::var("PLUME_DB_KEY").map(|v| v.is_empty()).unwrap_or(true)
                && std::env::var("PLUME_DB_KEY_FILE").map(|v| v.is_empty()).unwrap_or(true),
            "ce test EXIGE un environnement muet sur la clé (l'environnement gagne sur la carte injectée)"
        );
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p96a-provenances");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("b.db").to_string_lossy().into_owned();

        assert_eq!(CLES_QUI_DONNENT_UNE_CLE_DE_BASE.len(), 3, "trois provenances, pas une de plus");
        for nom in CLES_QUI_DONNENT_UNE_CLE_DE_BASE {
            let obtenue: Option<String> = match nom {
                n if n == CLE_DB_KEY => db_key_depuis(&conf96(&[(CLE_DB_KEY, "par-la-passphrase")])),
                n if n == CLE_DB_KEY_FILE => {
                    let f = dir.join("fournie.key").to_string_lossy().into_owned();
                    std::fs::write(&f, b"par-le-fichier-monte").unwrap();
                    db_key_depuis(&conf96(&[(CLE_DB_KEY_FILE, f.as_str())]))
                }
                n if n == CLE_DB_KEY_AUTO_PATH => {
                    let a = dir.join("engendree.key").to_string_lossy().into_owned();
                    let conf = conf96(&[("PLUME_DB", base.as_str()), (CLE_DB_KEY_AUTO_PATH, a.as_str())]);
                    assert_eq!(db_key_depuis(&conf), None, "cette provenance N'EST PAS une clé explicite");
                    ensure_encrypted(&conf, &base); // base absente -> la clé est engendrée
                    cle_auto_lire(&cle_auto_chemin(&conf))
                }
                autre => panic!("provenance `{autre}` déclarée mais non éprouvée ici — le tableau a changé"),
            };
            assert!(obtenue.is_some_and(|k| !k.is_empty()), "`{nom}`, seul, doit rendre une clé non vide");
        }
    }

    // ── ③ CE QUE L'EXPLOITANT APPREND, ET PAR QUEL MÉCANISME ──────────────────────────────────────

    /// LE SIGNAL DE POSTURE EST NON PURGEABLE — prouvé par le PRÉDICAT DE PURGE DU PRODUIT, pas par
    /// une liste de sources recopiée ici : une ligne qui ne satisfait PAS `RETENTION_NONPURGE` est une
    /// ligne que la rétention emporterait. Et il est dédupliqué à l'HEURE, comme tous ses jumeaux.
    #[test]
    fn p96a_le_signal_de_cle_non_mise_a_l_abri_est_non_purgeable_et_dedupe_a_l_heure() {
        let conn = test_db();
        let t0 = 1_800_000_000i64;
        assert!(emit_cle_auto_sans_abri(&conn, t0, "/data/plume-at-rest.key"), "premier signal écrit");
        assert!(!emit_cle_auto_sans_abri(&conn, t0 + 60, "/data/plume-at-rest.key"),
            "même heure -> dédupliqué (un crashloop ne doit pas tempêter)");
        assert!(emit_cle_auto_sans_abri(&conn, t0 + 3600, "/data/plume-at-rest.key"), "heure suivante -> un signal");

        let purgeables: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM event WHERE message LIKE 'CLÉ AT-REST NON MISE%' AND {RETENTION_NONPURGE}"),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(purgeables, 0,
            "un exploitant pourrait EFFACER l'avertissement qui dit qu'il va tout perdre — c'est \
             exactement ce qu'une ligne de journal permettait, et c'est ce que ce signal ferme");
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM event WHERE message LIKE 'CLÉ AT-REST NON MISE%'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(total, 2, "ANTI-FAUX-VERT : le prédicat de non-purge doit porter sur des lignes qui EXISTENT");

        let (sev, src, org): (i64, String, String) = conn
            .query_row(
                "SELECT severity, source, origin FROM event WHERE message LIKE 'CLÉ AT-REST NON MISE%' LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((sev, src.as_str(), org.as_str()), (4, "plume-config", "daemon"),
            "jumeau EXACT des autres signaux de posture non purgeables du dépôt");
        let msg: String = conn
            .query_row("SELECT message FROM event WHERE message LIKE 'CLÉ AT-REST NON MISE%' LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert!(msg.contains("DÉFINITIVEMENT") && msg.contains(CLE_DB_KEY_ESCROWED),
            "le message doit dire ce qui est perdu ET comment acquitter : {msg}");
        assert!(msg.contains("DÉCLARATION"),
            "…et ce que l'acquittement VAUT : un acquittement qui se ferait passer pour une preuve serait \
             pire que pas d'acquittement du tout");
    }

    /// LA CONDITION D'ÉMISSION, DANS LES QUATRE SENS. Un signal qui partirait toujours n'apprendrait
    /// rien et serait débranché ; un signal qui ne partirait jamais laisserait l'oubli invisible.
    #[test]
    fn p96a_le_signal_ne_part_que_sous_une_cle_engendree_non_acquittee() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p96a-signal");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("b.db").to_string_lossy().into_owned();
        let chemin = dir.join("k.key").to_string_lossy().into_owned();
        let base_conf: Vec<(&str, &str)> = vec![("PLUME_DB", base.as_str()), ("PLUME_DB_KEY_AUTO_PATH", chemin.as_str())];

        // (a) aucun fichier de clé -> RIEN (le cas de toute installation antérieure).
        assert_eq!(cle_auto_a_signaler(&conf96(&base_conf)), None, "pas de clé engendrée -> aucun signal");

        // (b) clé engendrée, aucun acquittement -> ON CRIE.
        cle_auto_engendrer(&chemin).unwrap();
        assert_eq!(cle_auto_a_signaler(&conf96(&base_conf)).as_deref(), Some(chemin.as_str()),
            "clé engendrée et rien qui atteste sa mise à l'abri -> signal, et il NOMME le fichier");

        // (c) acquittement posé -> silence. Toutes les formes du drapeau, une seule grammaire.
        for oui in ["1", "true", "YES", "on"] {
            let mut c = base_conf.clone();
            c.push((CLE_DB_KEY_ESCROWED, oui));
            assert_eq!(cle_auto_a_signaler(&conf96(&c)), None, "acquitté par `{oui}` -> silence");
        }
        for non in ["", "0", "peut-être"] {
            let mut c = base_conf.clone();
            c.push((CLE_DB_KEY_ESCROWED, non));
            assert!(cle_auto_a_signaler(&conf96(&c)).is_some(), "`{non}` n'acquitte rien");
        }

        // (d) clé EXPLICITE -> RIEN : elle vient d'ailleurs, le produit ne l'a pas fabriquée.
        let mut c = base_conf.clone();
        c.push(("PLUME_DB_KEY", "une-cle-apportee-par-l-exploitant"));
        assert_eq!(cle_auto_a_signaler(&conf96(&c)), None, "clé explicite -> le produit n'a rien à acquitter");

        // L'ANNONCE DE NAISSANCE dit les trois choses qu'on ne peut pas deviner.
        let annonce = annonce_cle_engendree(&chemin, &base);
        assert!(annonce.contains(&chemin), "l'annonce nomme le fichier");
        assert!(annonce.contains("NE PROTÈGE PAS"), "…et ce contre quoi le chiffrement ne protège pas");
        assert!(annonce.contains(CLE_DB_KEY_ESCROWED), "…et comment acquitter");
        assert!(!annonce.contains(&cle_auto_lire(&chemin).unwrap()),
            "AUCUNE valeur de clé ne doit figurer dans une ligne de journal");
    }

    // ── ④ LE GESTE EXPLICITE DE CONVERSION ────────────────────────────────────────────────────────

    /// LA PLACE EST CONTRÔLÉE AVANT, ET UNE MESURE ABSENTE VAUT REFUS. La dissymétrie avec la garde
    /// d'ingest (`ingest_disk_reject`, fail-OPEN) est le point : un ingest refusé à tort coûte un
    /// réessai, une conversion lancée sans savoir coûte la base.
    #[test]
    fn p96a_la_place_est_controlee_avant_et_une_mesure_absente_vaut_refus() {
        let gio = 1024u64 * 1024 * 1024;
        assert_eq!(place_requise_octets(10 * gio), 24 * gio, "une seconde base, l'archive, et la base jetable");
        assert!(verdict_de_place(gio, Some(3 * gio)).is_ok(), "de la place -> on part");
        let court = verdict_de_place(10 * gio, Some(gio)).expect_err("place insuffisante -> refus");
        assert!(court.contains("1024 Mo libres") && court.contains("24576 Mo requis"),
            "le refus DIT combien il en faut et combien il y en a : {court}");
        let aveugle = verdict_de_place(gio, None).expect_err("mesure indisponible -> refus, pas fail-open");
        assert!(aveugle.contains("NON MESURABLE"), "{aveugle}");
    }

    /// LE GESTE REFUSE DE PARTIR TANT QUE SES PRÉCONDITIONS NE SONT PAS RÉUNIES — et, à chaque refus,
    /// la base n'a pas bougé d'un octet.
    #[test]
    fn p96a_la_conversion_refuse_sans_cle_et_sans_acquittement() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p96a-refus");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("plume.db").to_string_lossy().into_owned();
        base_plume_en_clair(&base, 10);
        let avant = octets(std::path::Path::new(&base));
        let cle = "cle-de-conversion-p96a";

        let sans_cle = convertir_la_base_au_repos(&conf96(&[("PLUME_DB", base.as_str())]), &base)
            .expect_err("aucune clé -> refus");
        assert!(sans_cle.contains(CLE_DB_KEY_FILE) && sans_cle.contains(CLE_DB_KEY),
            "le refus NOMME les leviers à poser : {sans_cle}");

        let sans_ack = convertir_la_base_au_repos(&conf96(&[("PLUME_DB", base.as_str()), ("PLUME_DB_KEY", cle)]), &base)
            .expect_err("clé posée mais mise à l'abri non acquittée -> refus");
        assert!(sans_ack.contains(CLE_DB_KEY_ESCROWED), "le refus nomme l'acquittement : {sans_ack}");
        assert!(sans_ack.contains("DÉFINITIVEMENT"),
            "…et dit POURQUOI : convertir vers une clé que personne n'a mise à l'abri fabrique la perte totale");

        assert_eq!(octets(std::path::Path::new(&base)), avant, "aucun refus n'a touché la base");
        for suffixe in [".conversion-en-cours", ".avant-chiffrement", ".key"] {
            assert!(!std::path::Path::new(&format!("{base}{suffixe}")).exists(), "aucun résidu `{suffixe}`");
        }
    }

    /// LE GESTE, DE BOUT EN BOUT. Il prouve l'équivalence, produit une archive VÉRIFIÉE PAR
    /// RESTAURATION, bascule, s'inscrit au journal inaltérable, et n'est plus réversible. Puis il est
    /// IDEMPOTENT : le relancer ne fait rien.
    #[test]
    fn p96a_la_conversion_prouve_l_equivalence_puis_bascule_et_s_inscrit_au_journal() {
        let _reglages = VERROU_ENV_PROCESSUS.read(); // la sauvegarde RELIT des réglages que d'autres tests POSENT
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p96a-conversion");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("plume.db").to_string_lossy().into_owned();
        let dest = dir.join("backups").to_string_lossy().into_owned();
        const N: i64 = 120;
        base_plume_en_clair(&base, N);
        let cle = "cle-de-conversion-p96a-jamais-persistee";
        let conf = conf96(&[
            ("PLUME_DB", base.as_str()),
            ("PLUME_DB_KEY", cle),
            (CLE_DB_KEY_ESCROWED, "1"),
            ("PLUME_BACKUP_DEST", dest.as_str()),
        ]);

        let avant = octets(std::path::Path::new(&base));
        assert_eq!(&avant[..16], ENTETE_EN_CLAIR, "état de départ : la base est EN CLAIR");
        let (ledger_avant, events_avant) = {
            let c = open_db_keyed(&base, None).unwrap();
            let l: i64 = c.query_row("SELECT COUNT(*) FROM ledger", [], |r| r.get(0)).unwrap();
            let e: i64 = c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
            (l, e)
        };
        assert_eq!(events_avant, N, "pré-condition : la base porte {N} events");

        let issue = convertir_la_base_au_repos(&conf, &base).expect("la conversion doit aboutir");
        let rapport = match issue {
            IssueConversion::Convertie(r) => r,
            autre => panic!("attendu : une conversion (obtenu {autre:?})"),
        };
        assert!(rapport.objets_de_schema > 20, "le schéma réel porte des dizaines d'objets : {}", rapport.objets_de_schema);
        assert!(rapport.tables > 5, "les tables de données sont comparées : {}", rapport.tables);
        assert!(rapport.lignes >= N, "les lignes sont comptées : {}", rapport.lignes);
        assert_eq!(rapport.entrees_ledger as i64, ledger_avant, "la chaîne du journal inaltérable est REVÉRIFIÉE");
        assert_eq!(rapport.lignes_restaurees, rapport.lignes,
            "le compte de l'archive RESTAURÉE et celui de la copie doivent s'accorder");

        // LA BASE EST CHIFFRÉE — sur les octets.
        let apres = octets(std::path::Path::new(&base));
        assert_ne!(&apres[..16], ENTETE_EN_CLAIR, "RÉGRESSION : la base porte encore `SQLite format 3\\0`");
        assert_eq!(probe_db(&base, cle), DbProbe::OpensWithKey, "…et elle s'ouvre AVEC la clé");

        // LE CONTENU EST LE MÊME, table par table, et la conversion s'est INSCRITE au journal.
        {
            let c = open_db_keyed(&base, Some(cle)).unwrap();
            let e: i64 = c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
            // CE QUE LA CONVERSION AJOUTE, ET RIEN D'AUTRE. L'équivalence est prouvée AVANT la
            // publication de l'archive ; après elle, le geste consigne ce que cette archive IMPLIQUE,
            // exactement comme le cycle natif. Une seule ligne : la posture SYMÉTRIQUE (aucun
            // destinataire d'escrow n'est configuré ici, l'archive est donc déchiffrable par la
            // machine — et le produit le DIT au lieu de le laisser deviner).
            assert_eq!(e, events_avant + 1, "aucun event perdu, et UNE seule ligne ajoutée");
            let symetrique: i64 = c
                .query_row("SELECT COUNT(*) FROM event WHERE dedup LIKE '%plume-backup-symmetric-%'", [], |r| r.get(0))
                .unwrap();
            assert_eq!(symetrique, 1, "la ligne ajoutée est la posture symétrique de l'archive publiée");
            // …ET LE SIGNAL « RESTAURATION JAMAIS ÉPROUVÉE » SE TAIT, parce que ce geste VIENT de
            // l'éprouver : il a restauré l'archive dans une base jetable et en a recompté les lignes.
            // L'émettre ici serait un énoncé FAUX — et c'est le signal lui-même qui décide, sur
            // l'attestation consignée, pas une condition écrite à la main.
            let drill: i64 = c
                .query_row("SELECT COUNT(*) FROM event WHERE dedup LIKE '%plume-restore-drill-%'", [], |r| r.get(0))
                .unwrap();
            assert_eq!(drill, 0, "un exercice VENANT d'avoir lieu ne doit pas être annoncé comme dû");
            let dernier = crate::exercice_de_restauration::dernier_exercice(&c)
                .expect("la restauration menée par le geste est CONSIGNÉE, pas seulement effectuée");
            assert_eq!(dernier.archive, rapport.archive, "l'attestation nomme l'archive réellement exercée");
            assert_eq!(dernier.lignes, rapport.lignes_restaurees, "…et les lignes réellement revenues");
            let l: i64 = c.query_row("SELECT COUNT(*) FROM ledger", [], |r| r.get(0)).unwrap();
            assert_eq!(l, ledger_avant + 1, "la conversion s'inscrit ELLE-MÊME au journal inaltérable");
            let detail: String = c
                .query_row("SELECT detail FROM ledger WHERE kind='at_rest.converted'", [], |r| r.get(0))
                .expect("l'entrée de conversion existe et porte son genre");
            assert!(detail.contains("objets de schéma comparés") && detail.contains("entrées de journal revérifiées"),
                "la trace dit CE QUI a été vérifié, pas seulement que ça a eu lieu : {detail}");
            // La chaîne reste vérifiable APRÈS la conversion ET après sa propre inscription.
            let (n, _, _, rupture) = verify_ledger_conn(&c, None).expect("chaîne relisible");
            assert_eq!(rupture, None, "aucune rupture de chaîne après conversion ({n} entrées)");
        }

        // L'ARCHIVE DE SÉCURITÉ EXISTE, sous son nom CANONIQUE, et elle se vérifie encore.
        let archives: Vec<String> = std::fs::read_dir(&dest).unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        assert_eq!(archives, vec![rapport.archive.clone()],
            "une seule archive, sous le nom canonique que la rétention sait élaguer");
        assert!(rapport.archive.starts_with("plume-") && rapport.archive.ends_with(".db.age"),
            "nom canonique : {}", rapport.archive);
        let chemin_archive = std::path::Path::new(&dest).join(&rapport.archive);
        let (genre, contenu) = verify_backup(&chemin_archive.to_string_lossy(), Some(cle), None)
            .expect("l'archive publiée reste vérifiable");
        assert_eq!(genre, BackupKind::Symmetric, "sans destinataire age, l'archive est symétrique — et c'est DIT");
        assert_eq!(contenu.expect("vérification COMPLÈTE").lignes, rapport.lignes_restaurees);

        // AUCUNE COPIE EN CLAIR NE RESTE, et aucun état intermédiaire non plus.
        for suffixe in [".conversion-en-cours", ".avant-chiffrement", ".plaintext.bak", "-wal", "-shm"] {
            assert!(!std::path::Path::new(&format!("{base}{suffixe}")).exists(),
                "résidu `{suffixe}` : le chiffrement at-rest serait cosmétique");
        }

        // IDEMPOTENCE : relancer le geste ne fait RIEN.
        let octets_apres = octets(std::path::Path::new(&base));
        assert_eq!(convertir_la_base_au_repos(&conf, &base).expect("second passage"), IssueConversion::DejaChiffree);
        assert_eq!(octets(std::path::Path::new(&base)), octets_apres, "le second passage ne touche rien");
    }

    /// UN ÉCHEC EN COURS DE ROUTE LAISSE L'ORIGINAL INTACT ET AUCUN ÉTAT DÉMARRABLE À MOITIÉ. La
    /// mutation porte sur l'étape de SAUVEGARDE — celle qui vient APRÈS l'export et la preuve
    /// d'équivalence, donc celle qui a le plus à laisser derrière elle.
    #[test]
    fn p96a_un_echec_de_sauvegarde_laisse_l_original_intact_et_retire_la_copie() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p96a-echec");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("plume.db").to_string_lossy().into_owned();
        base_plume_en_clair(&base, 20);
        let avant = octets(std::path::Path::new(&base));
        let cle = "cle-p96a-echec";

        // La destination de sauvegarde est un FICHIER, pas un répertoire : `create_dir_all` échoue,
        // et l'échec survient APRÈS que la copie chiffrée a été écrite et prouvée équivalente.
        let obstacle = dir.join("obstacle").to_string_lossy().into_owned();
        std::fs::write(&obstacle, b"je ne suis pas un repertoire").unwrap();
        let conf = conf96(&[
            ("PLUME_DB", base.as_str()),
            ("PLUME_DB_KEY", cle),
            (CLE_DB_KEY_ESCROWED, "1"),
            ("PLUME_BACKUP_DEST", obstacle.as_str()),
        ]);

        let echec = convertir_la_base_au_repos(&conf, &base).expect_err("sans archive vérifiée, on ne bascule PAS");
        assert!(echec.contains("INTACT"), "le message dit dans quel état est la base : {echec}");
        assert_eq!(octets(std::path::Path::new(&base)), avant,
            "l'original n'a pas bougé d'un octet — et il DÉMARRE encore, exactement comme avant le geste");
        assert_eq!(&octets(std::path::Path::new(&base))[..16], ENTETE_EN_CLAIR, "il est toujours EN CLAIR");
        for suffixe in [".conversion-en-cours", ".avant-chiffrement"] {
            assert!(!std::path::Path::new(&format!("{base}{suffixe}")).exists(),
                "AUCUN état intermédiaire ne subsiste (`{suffixe}`)");
        }
        // Et une destination distante est refusée AVANT d'écrire quoi que ce soit : la précondition
        // exige une archive que CE processus puisse restaurer pour la vérifier.
        let distante = conf96(&[
            ("PLUME_DB", base.as_str()),
            ("PLUME_DB_KEY", cle),
            (CLE_DB_KEY_ESCROWED, "1"),
            ("PLUME_BACKUP_DEST", "s3://un-seau/plume"),
        ]);
        let refus = convertir_la_base_au_repos(&distante, &base).expect_err("destination distante -> refus");
        assert!(refus.contains("répertoire LOCAL"), "{refus}");
        assert_eq!(octets(std::path::Path::new(&base)), avant, "toujours intacte");
    }
