// `S32` — UNE MESURE D'ENVIRONNEMENT QUI ÉCHOUE NE REND PAS LA VALEUR LA PLUS RASSURANTE.
//
// CE QUE CES TESTS PROUVENT, ET POURQUOI IL EN FAUT DEUX POUR CHAQUE PROPRIÉTÉ.
//
//   ① SENS « ILLISIBLE » — une source retirée doit produire le verdict `illisible`, une cause nommée,
//      et AUCUN nombre. C'est le défaut d'origine : `/proc` muet publiait `(0 s, 0 octet)` et un
//      répertoire de spool disparu publiait « 0 fichier en attente ». Les deux valeurs les plus calmes
//      de leur série, indiscernables d'un vrai repos.
//   ② SENS « LU, VALEUR ZÉRO » — une source PRÉSENTE dont la valeur vaut réellement zéro doit produire
//      le verdict `lu` et le nombre 0. Sans ce second témoin, une fonction qui rendrait TOUJOURS
//      « illisible » passerait le premier test sans rien prouver — et elle serait un défaut symétrique,
//      exactement aussi grave : elle ferait disparaître une file réellement vide.
//   Chaque propriété est donc tenue par une PAIRE, et les paires sont nommées comme telles.
//
// CE QUI REND CES TESTS INDÉPENDANTS DE LA MACHINE QUI LES EXÉCUTE. Aucune fonction exercée ici ne
// nomme `/proc`, ne lit `sysconf` ni ne dépend d'un répertoire du système : la racine, la fréquence
// d'horloge et la taille de page arrivent en paramètre, et les arborescences sont fabriquées dans un
// temporaire POSSÉDÉ. Le même verdict tombe donc sur un hôte sans `/proc`, sur un hôte dont `/proc`
// répond parfaitement, et dans un conteneur — ce qu'un test qui aurait lu le vrai `/proc` de la
// machine de test n'aurait su faire dans aucun de ces trois cas.
//
// LES CAUSES QUI DEMANDENT UNE ERREUR SYSTÈME QU'UN TEST NE PEUT PAS FABRIQUER DE FAÇON PORTABLE
// (accès refusé : un processus privilégié lit un répertoire en mode 000, donc l'instrument mentirait
// selon qui exécute la suite) sont exercées sur la TRADUCTION elle-même, `cause_io`, avec des erreurs
// construites à la main. La traduction a un seul auteur : la garder, c'est garder tous ses appelants.

#[cfg(test)]
mod mesure_environnement_tests {
    use crate::mesure_environnement::*;
    use crate::metrics::{component_health, gather_json, gather_prom};
    use crate::tmp_possede::TmpPossede;
    use crate::{migrate, now};
    use rusqlite::Connection;

    /// La forme réelle de `/proc/<pid>/stat`, avec ce qui la rend piégeuse : le champ `comm` contient
    /// des espaces ET des parenthèses. Les champs sont posés pour que `utime`=100 et `stime`=50.
    /// `ticks` permet de fabriquer le témoin « vraiment zéro ».
    fn stat_fabrique(utime: u64, stime: u64) -> String {
        let mut champs = vec!["4242".to_string(), "(pl u me (x))".to_string(), "S".to_string()];
        // Après `comm` : index 0 = state. utime -> index 11, stime -> index 12.
        for i in 1..=12 {
            champs.push(match i {
                11 => utime.to_string(),
                12 => stime.to_string(),
                _ => "0".to_string(),
            });
        }
        champs.join(" ")
    }

    fn statm_fabrique(pages_residentes: u64) -> String {
        format!("1000 {pages_residentes} 12 1 0 300 0")
    }

    fn arbre_proc(tmp: &TmpPossede, stat: &str, statm: &str) -> std::path::PathBuf {
        let racine = tmp.join("proc");
        std::fs::create_dir_all(racine.join("self")).unwrap();
        std::fs::write(racine.join("self").join("stat"), stat).unwrap();
        std::fs::write(racine.join("self").join("statm"), statm).unwrap();
        racine
    }

    fn base_en_memoire() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&c);
        c
    }

    // =============================================================================================
    // LA PROFONDEUR DE LA FILE D'INGEST — LA PAIRE
    // =============================================================================================

    /// ① Le répertoire de spool a disparu : le verdict est `illisible`, la cause est `source_absente`,
    /// et il N'Y A PAS de nombre. C'est le défaut nommé par la clé : « un répertoire disparu se lisait
    /// comme une file vide ».
    #[test]
    fn une_file_dont_le_repertoire_est_absent_est_illisible_et_ne_rend_aucun_nombre() {
        let tmp = TmpPossede::neuf("s32-file-absente");
        let jamais_cree = tmp.join("spool-qui-n-existe-pas");
        let m = profondeur_file_depuis(&jamais_cree);
        assert_eq!(m.verdict(), VERDICT_ILLISIBLE, "un répertoire absent n'est pas une file vide");
        assert_eq!(m.cause(), CAUSE_SOURCE_ABSENTE, "la cause NOMME ce qui manque : {:?}", m.cause());
        assert!(m.valeur().is_none(), "aucun nombre publiable : une file non lue n'a pas de profondeur");
        assert!(
            m.detail().unwrap_or_default().contains("spool-qui-n-existe-pas"),
            "l'aveu porte le chemin tenté, sinon il ne se répare pas : {:?}",
            m.detail()
        );
    }

    /// ② LE SECOND TÉMOIN, INDISPENSABLE. Un répertoire qui EXISTE et ne contient rien est une file
    /// réellement vide : le verdict est `lu` et la valeur est 0. Sans ce test, une fonction qui
    /// rendrait toujours `illisible` passerait le précédent — et ferait disparaître de la supervision
    /// toutes les files réellement vides, c'est-à-dire le cas nominal.
    #[test]
    fn une_file_vide_mais_lisible_rend_un_vrai_zero() {
        let tmp = TmpPossede::neuf("s32-file-vide");
        let m = profondeur_file_depuis(&tmp);
        assert_eq!(m.verdict(), VERDICT_LU, "un répertoire présent et vide EST une mesure");
        assert_eq!(m.cause(), CAUSE_AUCUNE, "une mesure prise n'a pas de cause de trou");
        assert_eq!(m.valeur(), Some(&0), "zéro fichier en attente — et c'est un vrai zéro");
        assert!(m.detail().is_none(), "aucun détail d'échec quand il n'y a pas d'échec");
    }

    /// La profondeur compte ce que le consommateur du spool consommerait, et rien d'autre.
    #[test]
    fn la_profondeur_compte_les_enveloppes_et_ignore_les_temporaires() {
        let tmp = TmpPossede::neuf("s32-file-compte");
        for nom in ["a.json", "b.ndjson", ".c.json", "d.txt", ".tmp"] {
            std::fs::write(tmp.join(nom), b"{}").unwrap();
        }
        assert_eq!(profondeur_file_depuis(&tmp).valeur(), Some(&2), "seuls `a.json` et `b.ndjson` comptent");
        assert!(entree_de_spool_comptee("x.json") && entree_de_spool_comptee("x.ndjson"));
        assert!(!entree_de_spool_comptee(".x.json"), "un temporaire en cours d'écriture n'est pas en attente");
        assert!(!entree_de_spool_comptee("x.txt"));
    }

    // =============================================================================================
    // LE COUPLE PROCESSEUR / MÉMOIRE — LA PAIRE
    // =============================================================================================

    /// ① `/proc` injoignable : verdict `illisible`, cause `source_absente`, aucun nombre. Avant ce lot,
    /// l'appelant dépliait la lecture sur `(0.0, 0)` — « aucun temps processeur, aucune mémoire
    /// résidente », les deux valeurs les plus calmes de la série.
    #[test]
    fn un_proc_injoignable_est_illisible_et_ne_publie_ni_processeur_ni_memoire() {
        let tmp = TmpPossede::neuf("s32-proc-absent");
        let m = cpu_rss_depuis(&tmp.join("proc-inexistant"), 100.0, 4096);
        assert_eq!(m.verdict(), VERDICT_ILLISIBLE);
        assert_eq!(m.cause(), CAUSE_SOURCE_ABSENTE);
        assert!(m.valeur().is_none(), "ni temps processeur ni mémoire résidente ne sont publiables");
    }

    /// ② LE SECOND TÉMOIN. Un processus qui vient de démarrer a RÉELLEMENT consommé zéro tick et peut
    /// avoir zéro page résidente comptée : la source est lue, la valeur est zéro, et le verdict le dit.
    /// C'est le cas qu'une fonction toujours-`illisible` détruirait.
    #[test]
    fn un_proc_lisible_dont_la_valeur_est_nulle_rend_lu_et_zero() {
        let tmp = TmpPossede::neuf("s32-proc-zero");
        let racine = arbre_proc(&tmp, &stat_fabrique(0, 0), &statm_fabrique(0));
        let m = cpu_rss_depuis(&racine, 100.0, 4096);
        assert_eq!(m.verdict(), VERDICT_LU, "la source est là et elle dit zéro : c'est une MESURE");
        assert_eq!(m.cause(), CAUSE_AUCUNE);
        assert_eq!(m.valeur(), Some(&(0.0, 0)), "un vrai zéro se publie, contrairement à un trou");
    }

    /// Le décodage lui-même, sur la forme piégeuse (`comm` avec espaces et parenthèses) et avec des
    /// constantes d'hôte EXPLICITES : le résultat ne dépend d'aucune propriété de la machine de test.
    #[test]
    fn le_decodage_du_couple_processeur_memoire_est_pur_et_independant_de_l_hote() {
        let m = cpu_rss_depuis_textes(&stat_fabrique(100, 50), &statm_fabrique(3), 100.0, 4096);
        assert_eq!(m.valeur(), Some(&(1.5, 12288)), "(100+50)/100 Hz = 1,5 s ; 3 pages x 4096 = 12288 o");
        // La MÊME entrée sous d'autres constantes d'hôte rend un autre nombre — donc les constantes
        // sont bien celles qu'on passe, jamais celles de la machine qui exécute la suite.
        let m = cpu_rss_depuis_textes(&stat_fabrique(100, 50), &statm_fabrique(3), 1000.0, 16384);
        assert_eq!(m.valeur(), Some(&(0.15, 49152)));
    }

    /// UNE SOURCE PRÉSENTE MAIS INCOMPRISE N'EST PAS UNE SOURCE ABSENTE, ET SURTOUT PAS UN ZÉRO. C'est
    /// la forme que `S28` avait vue se perdre : un fichier lisible dont le format a changé était ignoré
    /// en silence, et l'appelant concluait comme si rien n'existait.
    #[test]
    fn une_forme_non_reconnue_se_nomme_au_lieu_de_se_taire() {
        let tronque = cpu_rss_depuis_textes("4242 (plume) S 1 2 3", &statm_fabrique(3), 100.0, 4096);
        assert_eq!(tronque.cause(), CAUSE_FORME_INCONNUE, "moins de 15 champs après `comm`");
        assert!(tronque.valeur().is_none());

        let sans_parenthese = cpu_rss_depuis_textes("4242 plume S", &statm_fabrique(3), 100.0, 4096);
        assert_eq!(sans_parenthese.cause(), CAUSE_FORME_INCONNUE);

        let statm_court = cpu_rss_depuis_textes(&stat_fabrique(1, 1), "1000", 100.0, 4096);
        assert_eq!(statm_court.cause(), CAUSE_FORME_INCONNUE, "pages résidentes absentes");

        // Une constante d'hôte non renseignée n'est PAS remplacée par une valeur d'usage : publier un
        // temps processeur calculé sur une fréquence supposée serait prétendre la mesure qui manque.
        let sans_horloge = cpu_rss_depuis_textes(&stat_fabrique(100, 50), &statm_fabrique(3), 0.0, 4096);
        assert_eq!(sans_horloge.cause(), CAUSE_FORME_INCONNUE);
        assert!(sans_horloge.valeur().is_none(), "aucun nombre inventé faute d'horloge");
    }

    // =============================================================================================
    // LA TAILLE DE LA BASE — L'ASYMÉTRIE ENTRE LES DEUX FICHIERS
    // =============================================================================================

    /// ② Le journal d'écriture ABSENT est un VRAI ZÉRO (hors mode WAL, ou après un point de reprise qui
    /// l'a retiré) : la taille reste LUE. L'erreur symétrique — traiter cette absence en panne — ferait
    /// disparaître la taille de la base dans un état parfaitement normal.
    #[test]
    fn une_base_sans_journal_reste_lue_le_journal_absent_valant_un_vrai_zero() {
        let tmp = TmpPossede::neuf("s32-base-sans-journal");
        let base = tmp.join("plume.db");
        std::fs::write(&base, vec![0u8; 4096]).unwrap();
        let m = taille_base_depuis(&base);
        assert_eq!(m.verdict(), VERDICT_LU);
        assert_eq!(m.valeur(), Some(&4096), "4096 octets de base + 0 octet de journal absent");

        std::fs::write(tmp.join("plume.db-wal"), vec![0u8; 1024]).unwrap();
        assert_eq!(taille_base_depuis(&base).valeur(), Some(&5120), "le journal présent s'ajoute");
    }

    /// ① Le fichier principal injoignable est une ANOMALIE : rendre zéro annoncerait une base VIDE au
    /// moment où elle est en fait introuvable.
    #[test]
    fn une_base_introuvable_est_illisible_et_non_une_base_vide() {
        let tmp = TmpPossede::neuf("s32-base-absente");
        let m = taille_base_depuis(&tmp.join("jamais-creee.db"));
        assert_eq!(m.verdict(), VERDICT_ILLISIBLE);
        assert_eq!(m.cause(), CAUSE_SOURCE_ABSENTE);
        assert!(m.valeur().is_none());
    }

    /// Aucune base configurée n'est PAS une mesure ratée : c'est une absence de sujet. Le distinguer
    /// évite de crier « source illisible » sur un déploiement qui n'a simplement pas de chemin de base.
    #[test]
    fn aucun_chemin_de_base_est_une_absence_de_sujet_pas_un_echec_de_mesure() {
        let m = taille_base_depuis(std::path::Path::new(""));
        assert_eq!(m.verdict(), VERDICT_LU);
        assert_eq!(m.valeur(), Some(&0));
    }

    // =============================================================================================
    // LA TRADUCTION DES ERREURS SYSTÈME — UN SEUL AUTEUR, DONC UNE SEULE GARDE
    // =============================================================================================

    /// Les trois familles d'échec système ne se confondent pas : une source absente se répare en
    /// recréant un répertoire, un accès refusé en corrigeant des droits ou un profil de confinement,
    /// une erreur d'entrée-sortie ni l'un ni l'autre. Exercée sur des erreurs CONSTRUITES : le cas
    /// « accès refusé » n'est pas fabricable de façon portable (un processus privilégié lit un
    /// répertoire en mode 000), et un test qui dépendrait de qui l'exécute ne prouverait rien.
    #[test]
    fn la_cause_est_derivee_de_l_erreur_systeme_et_les_familles_ne_se_confondent_pas() {
        use std::io::{Error, ErrorKind};
        assert_eq!(cause_io(&Error::from(ErrorKind::NotFound)), CAUSE_SOURCE_ABSENTE);
        assert_eq!(cause_io(&Error::from(ErrorKind::PermissionDenied)), CAUSE_SOURCE_REFUSEE);
        assert_eq!(cause_io(&Error::from(ErrorKind::Other)), CAUSE_SOURCE_ILLISIBLE);
        assert_eq!(cause_io(&Error::from(ErrorKind::InvalidData)), CAUSE_SOURCE_ILLISIBLE);
    }

    /// LA CARDINALITÉ EST BORNÉE, ET SON PIRE CAS EST ÉCRIT. L'étiquette `cause` ne prend ses valeurs
    /// que dans `CAUSES` : cinq clés, fermées. Chaque jauge `…_lisible` vaut donc AU PLUS 5 séries de
    /// sortie sur toute la vie d'un déploiement, et UNE SEULE par scrape puisque les cas sont
    /// exclusifs. Aucune cause ne porte de chemin ni de message système — ceux-là n'ont pas de borne
    /// et vivent dans le détail JSON, jamais dans une étiquette.
    #[test]
    fn la_cardinalite_des_causes_est_bornee_et_aucune_cause_ne_porte_de_texte_libre() {
        assert_eq!(CAUSES.len(), 5, "l'ensemble des causes est FERMÉ");
        let uniques: std::collections::BTreeSet<&str> = CAUSES.iter().copied().collect();
        assert_eq!(uniques.len(), CAUSES.len(), "aucune clé en double");
        for c in CAUSES {
            assert!(!c.is_empty() && c.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_'),
                "une clé d'étiquette est un mot stable, sans espace ni ponctuation : {c:?}");
        }
        // Une seule série émise par jauge, quel que soit le verdict.
        let sortie = exposition_prom_lisible("plume_x_lisible", "la chose", VERDICT_ILLISIBLE, CAUSE_SOURCE_ABSENTE);
        assert_eq!(sortie.matches("plume_x_lisible{").count(), 1);
        assert!(sortie.contains("plume_x_lisible{cause=\"source_absente\"} 0"), "{sortie}");
        let sortie = exposition_prom_lisible("plume_x_lisible", "la chose", VERDICT_LU, CAUSE_AUCUNE);
        assert!(sortie.contains("plume_x_lisible{cause=\"aucune\"} 1"), "{sortie}");
    }

    // =============================================================================================
    // CE QUE LE CONSOMMATEUR VOIT — LA PREUVE QUI COMPTE
    // =============================================================================================

    /// ① SUR `/metrics` : la série de VALEUR disparaît et l'indicateur de lisibilité prend sa place,
    /// avec sa cause. Une série absente est un premier concept côté Prometheus (ce dépôt s'en sert
    /// déjà : l'âge d'un exercice de restauration jamais fait est ABSENT plutôt que zéro) ; ce qu'elle
    /// ne sait pas dire — « la lecture a échoué » plutôt que « le scrape n'a pas eu lieu » — est
    /// exactement ce que la jauge ajoute.
    #[test]
    fn une_file_illisible_retire_sa_serie_de_metrics_et_leve_l_indicateur() {
        let tmp = TmpPossede::neuf("s32-prom-illisible");
        let absent = tmp.join("spool-absent");
        let c = base_en_memoire();
        let prom = gather_prom(&c, absent.to_str().unwrap(), "", 1, 80);
        assert!(!prom.contains("plume_spool_queue_files"),
            "la profondeur de file est ABSENTE, jamais publiée à zéro : {prom}");
        assert!(prom.contains("plume_spool_queue_lisible{cause=\"source_absente\"} 0"),
            "l'indicateur NOMME la panne de mesure : {prom}");
    }

    /// ② LE SECOND TÉMOIN SUR LA MÊME SURFACE : une file réellement vide publie bien `0`, avec
    /// l'indicateur à 1. C'est ce test qui interdit de « corriger » le précédent en retirant la série
    /// dans tous les cas.
    #[test]
    fn une_file_vide_publie_bien_zero_sur_metrics_avec_l_indicateur_leve() {
        let tmp = TmpPossede::neuf("s32-prom-vide");
        let c = base_en_memoire();
        let prom = gather_prom(&c, tmp.to_str().unwrap(), "", 1, 80);
        assert!(prom.contains("plume_spool_queue_files 0"), "un vrai zéro se publie : {prom}");
        assert!(prom.contains("plume_spool_queue_lisible{cause=\"aucune\"} 1"), "{prom}");
    }

    /// La même paire sur le JSON du panneau : le nombre est ABSENT quand il n'a pas été lu, PRÉSENT
    /// (et nul) quand il l'a été. Le panneau lit ce champ-là ; s'il trouvait zéro dans les deux cas, le
    /// correctif serait annulé côté client.
    #[test]
    fn le_json_du_panneau_omet_le_nombre_non_lu_et_publie_le_vrai_zero() {
        let c = base_en_memoire();
        let tmp = TmpPossede::neuf("s32-json");
        let vide = gather_json(&c, tmp.to_str().unwrap(), "", 1, 80);
        assert_eq!(vide.pointer("/ingest/queue_depth").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(vide.pointer("/ingest/queue_depth_verdict").and_then(|v| v.as_str()), Some(VERDICT_LU));

        let absent = tmp.join("spool-absent");
        let illisible = gather_json(&c, absent.to_str().unwrap(), "", 1, 80);
        assert!(illisible.pointer("/ingest/queue_depth").is_none(),
            "aucun nombre : le champ est ABSENT, pas à zéro");
        assert_eq!(illisible.pointer("/ingest/queue_depth_verdict").and_then(|v| v.as_str()), Some(VERDICT_ILLISIBLE));
        assert_eq!(illisible.pointer("/ingest/queue_depth_cause").and_then(|v| v.as_str()), Some(CAUSE_SOURCE_ABSENTE));
        assert!(illisible.pointer("/ingest/queue_depth_detail").and_then(|v| v.as_str()).unwrap_or_default().contains("spool-absent"),
            "le détail libre porte le chemin — il n'est JAMAIS une étiquette de série");
    }

    /// LA SURFACE LA PLUS GRAVE : la santé par composant, dont la pastille alimente
    /// `plume_component_up` ET la posture globale. Une file illisible ne peut pas y être VERTE — sinon
    /// une panne d'observabilité se lit comme une bonne nouvelle. Ce n'est pas rouge non plus : la voie
    /// d'ingest HTTP peut parfaitement continuer de servir.
    #[test]
    fn une_file_illisible_ne_peut_pas_rendre_le_composant_ingest_vert() {
        let c = base_en_memoire();
        c.execute(
            "INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'sshd','auth',1,'x')",
            rusqlite::params![now()],
        )
        .unwrap();
        let tmp = TmpPossede::neuf("s32-sante");

        // ② Témoin inverse D'ABORD : la MÊME base, avec un spool présent et vide, reste VERTE. Sans
        // lui, rendre tout jaune passerait le test suivant sans rien prouver.
        let sains = component_health(&c, tmp.to_str().unwrap(), "", 80);
        let ingest_sain = sains.iter().find(|v| v["component"] == "ingest").unwrap();
        assert_eq!(ingest_sain["state"], "green", "spool vide + données fraîches -> vert : {ingest_sain}");
        assert_eq!(ingest_sain["queue_depth"], 0, "et le vrai zéro est publié");

        // ① La même base, spool retiré : le composant n'est plus vert et le détail NOMME la cause.
        let absent = tmp.join("spool-absent");
        let comps = component_health(&c, absent.to_str().unwrap(), "", 80);
        let ingest = comps.iter().find(|v| v["component"] == "ingest").unwrap();
        assert_ne!(ingest["state"], "green", "une file non lue n'est pas une file saine : {ingest}");
        assert_eq!(ingest["state"], "yellow", "jaune, pas rouge : la voie HTTP peut encore servir");
        assert!(ingest["detail"].as_str().unwrap_or_default().contains("NON LISIBLE"),
            "le détail dit ce qui manque : {ingest}");
        assert!(ingest.get("queue_depth").is_none(), "et il n'y a AUCUN nombre à lire : {ingest}");
        assert_eq!(ingest["queue_depth_cause"], CAUSE_SOURCE_ABSENTE);
    }

    // =============================================================================================
    // LA MÊME FIGURE SUR LA SONDE DE CHIFFREMENT AU REPOS — ET C'EST LA PLUS PARLANTE DES TROIS
    // =============================================================================================

    /// LA SONDE QUI CLASSE LA BASE AVANT OUVERTURE rendait `Fresh` — le verdict le plus rassurant de
    /// son type — dès que l'interrogation du fichier échouait pour un motif AUTRE que l'absence.
    /// L'exploitant lisait « aucune base existante : elle sera créée chiffrée d'office » alors qu'une
    /// base est peut-être là, intacte, et seulement injoignable. La variante juste existait déjà :
    /// `Unopenable`, « présente mais non ouvrable : elle ne sera PAS touchée ».
    ///
    /// L'INSTRUMENT EST VALIDÉ AVANT D'ÊTRE CRU, et il est choisi pour être INDÉPENDANT DE QUI EXÉCUTE
    /// LA SUITE : un chemin dont un composant intermédiaire est un FICHIER ORDINAIRE échoue à
    /// l'interrogation sur tout Linux, privilégié ou non — là où un répertoire en mode 000 se laisse
    /// traverser par un processus privilégié et ferait passer le test selon la machine.
    #[test]
    fn une_base_non_interrogeable_n_est_pas_une_base_absente() {
        use crate::crypto::{probe_db, DbProbe};
        let tmp = TmpPossede::neuf("s32-sonde-repos");
        let barrage = tmp.join("ceci-est-un-fichier");
        std::fs::write(&barrage, b"x").unwrap();
        let sous_le_barrage = barrage.join("plume.db");

        // VALIDATION DE L'INSTRUMENT : l'échec doit exister, et ne doit PAS être « absent ».
        let echec = std::fs::metadata(&sous_le_barrage).expect_err("l'instrument doit produire un échec");
        assert_ne!(echec.kind(), std::io::ErrorKind::NotFound,
            "l'instrument doit produire un échec AUTRE que l'absence, sinon il ne prouve rien : {echec}");

        // ① La sonde n'invente pas « base neuve » à partir d'une interrogation impossible.
        assert_eq!(probe_db(sous_le_barrage.to_str().unwrap(), "peu-importe"), DbProbe::Unopenable,
            "une base non interrogeable n'est pas une base absente");

        // ② TÉMOIN INVERSE, indispensable : un fichier réellement ABSENT reste `Fresh`. Sans lui, une
        // sonde qui rendrait toujours `Unopenable` passerait le test précédent — et ferait échouer
        // toute première installation, qui n'a légitimement aucune base.
        assert_eq!(probe_db(tmp.join("jamais-creee.db").to_str().unwrap(), "peu-importe"), DbProbe::Fresh,
            "un fichier absent EST une lecture réussie dont le résultat est « rien »");
    }

    /// LE COUPLE PROCESSEUR/MÉMOIRE SUR `/metrics`, dans le sens qui est vérifiable partout : sur un
    /// hôte dont `/proc` répond, les deux séries sont publiées ET l'indicateur vaut 1. La paire
    /// complète du couple est tenue par les tests paramétrés plus haut — ceux-là jouent l'échec sans
    /// avoir à retirer `/proc` à la machine qui exécute la suite, ce qu'aucun test ne peut faire.
    #[test]
    fn l_indicateur_du_couple_processeur_memoire_accompagne_toujours_ses_series() {
        let c = base_en_memoire();
        let tmp = TmpPossede::neuf("s32-prom-proc");
        let prom = gather_prom(&c, tmp.to_str().unwrap(), "", 1, 80);
        assert_eq!(prom.matches("plume_process_mesure_lisible{").count(), 1,
            "l'indicateur est publié dans les DEUX cas — une jauge absente quand tout va bien ne se \
             distinguerait pas d'un scrape manqué : {prom}");
        let lu = prom.contains("plume_process_mesure_lisible{cause=\"aucune\"} 1");
        assert_eq!(
            lu,
            prom.contains("plume_process_cpu_seconds_total") && prom.contains("plume_process_resident_memory_bytes"),
            "les deux séries de valeur sont présentes SI ET SEULEMENT SI la mesure a été lue : {prom}"
        );
    }

    // =============================================================================================
    // `S33` — L'IDENTITÉ DE L'HÔTE, QUI DÉCIDE QUELLES ACTIONS DE RÉPONSE S'EXÉCUTENT ICI
    // =============================================================================================
    //
    // POURQUOI CETTE MESURE-LÀ EST TRAITÉE À PART DES SÉRIES. Les autres nourrissent un graphique :
    // une valeur perdue y est un trou. Celle-ci choisit un COMPORTEMENT. Le repli d'origine rendait
    // `localhost` quand la source n'était pas lisible, et un nom d'hôte plausible ment mieux qu'un
    // zéro — il est indiscernable d'une lecture réussie, y compris pour qui relit le code.

    /// ① SENS « ILLISIBLE ». Aucune des deux sources ne porte d'identité -> verdict `illisible`,
    /// cause nommée, et AUCUN nom. Les deux formes d'échec sont distinguées, parce qu'elles ne se
    /// réparent pas pareil : un fichier ABSENT se crée, un fichier VIDE s'écrit.
    #[test]
    fn une_identite_d_hote_qu_on_ne_sait_pas_lire_n_est_pas_remplacee_par_un_nom_plausible() {
        let tmp = TmpPossede::neuf("s33-identite-illisible");

        let absent = identite_hote_depuis(&tmp.join("pas-de-fichier"), None);
        assert_eq!(absent.verdict(), VERDICT_ILLISIBLE, "source absente et aucun repli : rien n'a été lu");
        assert_eq!(absent.cause(), CAUSE_SOURCE_ABSENTE);
        assert_eq!(absent.valeur(), None, "aucun nom ne doit sortir d'une lecture qui a échoué");

        let vide = tmp.join("hostname-vide");
        std::fs::write(&vide, "   \n").unwrap();
        let m = identite_hote_depuis(&vide, None);
        assert_eq!(m.verdict(), VERDICT_ILLISIBLE, "un fichier lu qui ne porte aucun nom n'est pas une identité");
        assert_eq!(m.cause(), CAUSE_FORME_INCONNUE,
            "lu mais incompréhensible : la cause n'est PAS `source_absente`, et la distinction décide du geste de réparation");
        assert_eq!(m.valeur(), None);

        // La variable de repli vide ne sauve pas davantage : elle ne porte pas d'identité non plus.
        assert_eq!(identite_hote_depuis(&vide, Some("   ")).verdict(), VERDICT_ILLISIBLE);
    }

    /// ② SENS « LU ». C'est le témoin sans lequel tout le reste ne prouverait rien : une fonction qui
    /// rendrait TOUJOURS `illisible` passerait le test ① sans difficulté, et elle serait le défaut
    /// symétrique — elle empêcherait tout hôte d'exécuter la moindre action ciblée. La précédence
    /// (fichier d'abord, variable ensuite) est celle d'avant, et elle est vérifiée telle quelle.
    #[test]
    fn une_identite_d_hote_reellement_lisible_est_lue_et_la_precedence_est_conservee() {
        let tmp = TmpPossede::neuf("s33-identite-lue");
        let f = tmp.join("hostname");
        std::fs::write(&f, "cible-a\n").unwrap();

        let m = identite_hote_depuis(&f, None);
        assert_eq!(m.verdict(), VERDICT_LU);
        assert_eq!(m.cause(), CAUSE_AUCUNE);
        assert_eq!(m.valeur().map(String::as_str), Some("cible-a"), "le nom est rendu tel quel, sans blancs");

        assert_eq!(identite_hote_depuis(&f, Some("cible-b")).valeur().map(String::as_str), Some("cible-a"),
            "le FICHIER prime sur la variable : la précédence livrée n'est pas modifiée par ce lot");
        assert_eq!(identite_hote_depuis(&tmp.join("absent"), Some("cible-b")).valeur().map(String::as_str), Some("cible-b"),
            "la variable sert bien de repli quand le fichier n'est pas là");
    }

    /// CE QUE LE CONSOMMATEUR FAIT DE L'UN ET DE L'AUTRE — la propriété qui compte vraiment, jouée sur
    /// le PRÉDICAT que le responder exécute, et non sur une paraphrase de ce prédicat.
    ///
    /// TROIS ACTIONS APPROUVÉES : une non ciblée, une ciblée sur cette machine, une ciblée sur une
    /// machine qui s'appelle `localhost`. Identité LUE -> les deux premières sont réclamées, jamais la
    /// troisième. Identité ILLISIBLE -> SEULE la non ciblée l'est : l'ancienne forme, elle, repliait
    /// sur `localhost` et exécutait donc ICI une action destinée à une AUTRE machine, pendant que
    /// celle qui visait celle-ci dormait indéfiniment.
    #[test]
    fn une_identite_illisible_ne_reclame_plus_aucune_action_ciblee() {
        let c = base_en_memoire();
        c.execute_batch(
            "INSERT INTO action(ts,kind,target,status,host,dry_run) VALUES
               (1,'ban_ip','1.2.3.4','approved',NULL,1),
               (1,'ban_ip','1.2.3.5','approved','cible-a',1),
               (1,'ban_ip','1.2.3.6','approved','localhost',1);",
        )
        .unwrap();
        // L'ÉNONCÉ EXERCÉ EST CELUI DU PRODUIT, jamais une recopie : `ACTIONS_A_RECLAMER_ICI` est la
        // constante que `respond_run` prépare, et le couple (identité, lue) sort de la fonction que
        // `respond_run` appelle. Une paraphrase resterait VERTE le jour où la production changerait —
        // c'est-à-dire exactement le jour où l'on aurait besoin qu'elle rougisse.
        let reclamees = |etiquette: &str, mesure: Mesure<String>| -> Vec<String> {
            let (me, lue) = crate::handlers::actions::identite_pour_reclamation(etiquette, mesure);
            let mut st = c.prepare(crate::handlers::actions::ACTIONS_A_RECLAMER_ICI).unwrap();
            let mut v: Vec<String> = st
                .query_map(rusqlite::params![me, i64::from(lue)], |r| r.get::<_, String>(2))
                .unwrap()
                .flatten()
                .collect();
            v.sort();
            v
        };
        let illisible = || Mesure::Illisible {
            cause: CAUSE_SOURCE_ABSENTE,
            detail: "aucune des deux sources ne porte d'identité".into(),
        };

        assert_eq!(
            reclamees("", Mesure::Lue("cible-a".into())),
            vec!["1.2.3.4", "1.2.3.5"],
            "identité LUE : la non ciblée et celle qui vise cette machine — jamais celle d'une autre"
        );
        assert_eq!(
            reclamees("", illisible()),
            vec!["1.2.3.4"],
            "identité ILLISIBLE : seules les actions non ciblées, qui disent « n'importe quel hôte ». \
             Le repli `localhost` d'avant aurait ajouté 1.2.3.6 — une action appliquée au mauvais hôte, \
             et il aurait en même temps laissé dormir celle qui visait le vrai nom de cette machine."
        );
        assert_eq!(
            reclamees("localhost", illisible()),
            vec!["1.2.3.4", "1.2.3.6"],
            "TÉMOIN INVERSE : une étiquette POSÉE par l'exploitant est une décision, pas une lecture — \
             elle réclame donc bien ses actions ciblées, mesure en échec ou non. Sans ce témoin, une \
             version qui ne réclamerait JAMAIS rien de ciblé passerait le témoin précédent sans rien prouver."
        );
    }

    /// L'INDICATEUR ACCOMPAGNE LA DÉCISION, comme il accompagne les séries : la jauge est publiée dans
    /// les DEUX cas (une jauge absente quand tout va bien ne se distinguerait pas d'un scrape manqué),
    /// et la VALEUR — le nom de la machine — n'y figure jamais : ce n'est pas un nombre, et l'emporter
    /// en étiquette ferait de chaque hôte une série de plus.
    #[test]
    fn l_indicateur_de_l_identite_d_hote_porte_le_verdict_et_jamais_le_nom() {
        let c = base_en_memoire();
        let tmp = TmpPossede::neuf("s33-prom-identite");
        let prom = gather_prom(&c, tmp.to_str().unwrap(), "", 1, 80);
        assert_eq!(prom.matches("plume_host_identity_lisible{").count(), 1,
            "l'indicateur est publié dans les deux cas : {prom}");
        assert!(!prom.contains("plume_host_identity_lisible{host="),
            "le nom d'hôte ne part JAMAIS en étiquette : {prom}");
        let j = gather_json(&c, tmp.to_str().unwrap(), "", 1, 80);
        let hote = j.get("host").and_then(|h| h.as_object()).expect("l'objet `host` est publié");
        assert!(hote.contains_key("identity_verdict") && hote.contains_key("identity_cause"),
            "le verdict et sa cause sont là : {hote:?}");
        assert!(!hote.contains_key("identity"),
            "la VALEUR n'est pas publiée — seul son verdict l'est : {hote:?}");
    }
}
