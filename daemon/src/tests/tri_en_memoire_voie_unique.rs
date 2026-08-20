// S26 — CE QUE LE MOTEUR FAIT D'UN TRI EST LU, PAS SUPPOSÉ ; ET AUCUNE CONNEXION N'ÉCHAPPE À CE RÉGLAGE
// ================================================================================================
// LE DÉFAUT QUE CES TESTS FERMENT, ET POURQUOI IL EST LE PLUS GRAVE DE SA FAMILLE. SQLCipher chiffre les
// PAGES de la base ; il ne chiffre PAS les fichiers temporaires de SQLite. Un tri qui déverse écrit donc
// des VALEURS D'ÉVÉNEMENT EN CLAIR hors du chiffrement au repos — mesuré le 2026-08-04 : 323 occurrences
// lisibles de deux aiguilles du jeu de test dans 16 Mio lus, contrôle négatif à 0. C'est pour cette
// raison que le déversement est OPT-IN et jamais activé par défaut, et toute la garantie du défaut tient
// à une seule phrase : « une connexion qui ne dit rien trie en mémoire ».
//
// Cette phrase était un COMMENTAIRE. Elle décrit une propriété de la LIAISON SQLite — qui ne pose
// `SQLITE_TEMP_STORE=2` que dans la branche SQLCipher de sa compilation — et rien ne la relisait. Une
// version future livrant `=1` aurait fait déverser en clair toute connexion muette, pendant que la
// bannière aurait continué d'annoncer « déversement DÉSACTIVÉ ». Une bannière qui annonce l'inverse de
// ce qui se passe est pire qu'une bannière absente.
//
// POURQUOI `PRAGMA temp_store` NE SUFFIT PAS — le piège qui rendrait une « lecture » aussi fausse que
// l'affirmation qu'elle remplace. Ce pragma rend le réglage LOCAL de la connexion, et sur une connexion
// muette il vaut 0 : la MÊME valeur, que le tri finisse en mémoire ou sur le disque. La décision est
// prise par `sqlite3TempInMemory`, qui CROISE ce 0 avec la valeur COMPILÉE — laquelle ne se lit que dans
// `PRAGMA compile_options`. Un test qui se contenterait de lire `temp_store` serait vert dans les deux
// mondes.
//
// CE QUE CHAQUE TEST PROUVE :
//   ① la valeur compilée est LUE sur le moteur réel, et le verdict bascule quand le réglage change ;
//   ② la table de SQLite est reproduite à l'identique, y compris la ligne qui décrit le monde dangereux ;
//   ③ la bannière dit ce qui est MESURÉ — et change de phrase quand la mesure change ;
//   ④ le refus se déclenche sur la valeur dangereuse et RESTE MUET sur la valeur sûre ;
//   ⑤ aucune connexion de production sur un FICHIER ne s'ouvre hors de la voie qui pose ces réglages.

#[cfg(test)]
mod tri_en_memoire_voie_unique_tests {
    use crate::sqlite_plafond::{
        armer, banniere, constat_de_tri, lire_tri, refus_de_demarrage_pour, tri_dune_connexion_nue,
        tri_en_memoire, tri_pour, Deversement, Tri,
    };

    /// ① LA VALEUR COMPILÉE EST LUE SUR LE MOTEUR, ET LE VERDICT SUIT — AVEC SON TÉMOIN NÉGATIF.
    ///
    /// La sonde est NUE (aucun réglage posé) : c'est le cas dont dépend toute la garantie. Elle vérifie
    /// d'abord que le réglage local vaut bien 0 — un instrument qui n'est pas nu ne mesure pas le
    /// silence — puis que le moteur NOMME sa valeur compilée. La construction livrée porte
    /// `TEMP_STORE=2` : c'est ce que le commentaire affirmait, et c'est maintenant ce qui est LU.
    ///
    /// MUTATION, SUR LE MOTEUR RÉEL ET NON SUR UNE CONSTANTE : la même connexion à laquelle on pose
    /// `temp_store=FILE` bascule sur `SurDisque`. Sans ce second verdict, ce test ne prouverait pas que
    /// la lecture DÉPEND de quoi que ce soit.
    #[test]
    fn la_valeur_compilee_du_moteur_est_lue_et_non_supposee() {
        let nue = tri_dune_connexion_nue();
        let compile = match &nue {
            Tri::EnMemoire { compile, local } => {
                assert_eq!(*local, 0, "la sonde doit être NUE pour mesurer le SILENCE");
                *compile
            }
            autre => panic!(
                "une connexion qui ne dit RIEN doit trier en MÉMOIRE dans cette construction — lu : {}",
                constat_de_tri(autre)
            ),
        };
        assert_eq!(
            compile, 2,
            "la liaison SQLCipher livre SQLITE_TEMP_STORE=2 ; toute autre valeur change la garantie de \
             confidentialité du défaut et doit être VUE, pas héritée en silence"
        );

        // TÉMOIN NÉGATIF, sur le MÊME moteur : un réglage explicite qui fait déverser doit être LU comme
        // tel. Une lecture qui rendrait toujours `EnMemoire` ne prouverait rien.
        let c = rusqlite::Connection::open_in_memory().expect("connexion mémoire");
        c.execute_batch("PRAGMA temp_store=FILE;").expect("réglage explicite");
        match lire_tri(&c) {
            Tri::SurDisque { compile: k, local } => {
                assert_eq!((k, local), (compile, 1), "le réglage local LU doit être celui qui a été posé");
            }
            autre => panic!("`temp_store=FILE` doit être lu comme un déversement — lu : {}", constat_de_tri(&autre)),
        }
    }

    /// ② LA TABLE DE SQLITE, REPRODUITE À L'IDENTIQUE. `sqlite3TempInMemory` croise la valeur compilée
    /// et le réglage local ; la recopier de mémoire au lieu de la lire est exactement la faute que ce lot
    /// corrige. La ligne qui compte est `(compile=1, local=0)` : c'est le monde qu'une future version de
    /// la liaison livrerait, et le seul où le SILENCE déverse.
    #[test]
    fn la_table_de_sqlite_est_reproduite_a_lidentique() {
        // compile=1 (défaut de SQLite) : seul un MEMORY explicite sauve.
        assert!(!tri_en_memoire(1, 0), "LE CAS DANGEREUX : compilé à 1, le silence DÉVERSE");
        assert!(!tri_en_memoire(1, 1));
        assert!(tri_en_memoire(1, 2));
        // compile=2 (ce que la liaison SQLCipher livre) : seul un FILE explicite déverse.
        assert!(tri_en_memoire(2, 0), "compilé à 2, le silence trie en mémoire");
        assert!(!tri_en_memoire(2, 1));
        assert!(tri_en_memoire(2, 2));
        // compile=3 : jamais de fichier temporaire, le réglage local ne peut rien y faire.
        assert!(tri_en_memoire(3, 0) && tri_en_memoire(3, 1) && tri_en_memoire(3, 2));
        // hors bornes : SQLite rend 0 -> fichier, TOUJOURS. Fail-closed, pas fail-silent.
        assert!(!tri_en_memoire(0, 2) && !tri_en_memoire(9, 2));
        // ET L'IGNORANCE NE SE DÉGUISE PAS : sans valeur compilée, aucun verdict n'est rendu.
        assert!(matches!(tri_pour(None, Some(2)), Tri::Illisible(_)), "pas de valeur compilée = pas de verdict");
        assert!(matches!(tri_pour(Some(2), None), Tri::Illisible(_)), "pas de réglage local = pas de verdict");
    }

    /// ③ LA BANNIÈRE DIT CE QUI EST MESURÉ. C'est LE défaut que S26 nomme : sous la valeur dangereuse,
    /// l'ancienne bannière aurait continué d'annoncer « aucune valeur d'événement en clair » pendant que
    /// des valeurs seraient parties en clair. Les DEUX sens sont exigés — une bannière qui crierait
    /// toujours ne prouverait rien non plus.
    #[test]
    fn la_banniere_dit_ce_qui_est_mesure_pas_ce_qui_est_promis() {
        let sure = banniere(Deversement::Desactive, Tri::EnMemoire { compile: 2, local: 0 });
        assert!(sure.contains("MESURÉ"), "la garantie doit être présentée comme une MESURE : {sure}");
        assert!(sure.contains("TEMP_STORE=2"), "et les chiffres LUS doivent y être : {sure}");
        assert!(sure.contains("Aucune valeur d'événement en clair"), "{sure}");

        // LE MONDE DANGEREUX EST DÉRIVÉ, JAMAIS CONSTRUIT À LA MAIN : `tri_pour(Some(1), Some(0))` est
        // ce que rendrait une liaison livrant `SQLITE_TEMP_STORE=1` sur une connexion muette. Un premier
        // jet posait `Tri::EnMemoire { compile: 1, .. }` — une valeur que la table de SQLite ne peut PAS
        // produire, donc un test qui aurait prouvé quelque chose sur un monde inexistant.
        let dangereuse = banniere(Deversement::Desactive, tri_pour(Some(1), Some(0)));
        // Le MÊME mode, la MÊME bannière : c'est la MESURE qui a changé.
        assert!(
            !dangereuse.contains("Aucune valeur d'événement en clair"),
            "sous la valeur compilée dangereuse, la bannière ne doit PLUS promettre la confidentialité : {dangereuse}"
        );
        assert!(
            dangereuse.contains("EN CLAIR") && dangereuse.contains("MESURE DIT AUTRE CHOSE"),
            "elle doit annoncer le risque RÉEL, et dire que c'est la mesure qui parle : {dangereuse}"
        );

        // Et l'ignorance s'avoue, au lieu de se taire.
        let muette = banniere(Deversement::Desactive, Tri::Illisible("compile_options muet".into()));
        assert!(muette.contains("N'EST PAS LISIBLE"), "{muette}");
        assert!(!muette.contains("Aucune valeur d'événement en clair"), "{muette}");
    }

    /// ④ LE REFUS SE DÉCLENCHE SUR LA VALEUR DANGEREUSE, ET RESTE MUET SUR LA VALEUR SÛRE. Une garde qui
    /// refuse toujours n'est pas une garde, c'est une panne — d'où le témoin positif ET le négatif.
    ///
    /// LA DISSYMÉTRIE EST DÉLIBÉRÉE : un déversement DEMANDÉ et non obtenu coûte une requête qui échoue,
    /// un déversement OBTENU sans avoir été demandé coûte la confidentialité. Seule la seconde direction
    /// arrête le processus.
    #[test]
    fn le_refus_se_declenche_sur_la_valeur_dangereuse_et_pas_sur_la_sure() {
        let sur = Tri::EnMemoire { compile: 2, local: 0 };
        assert!(refus_de_demarrage_pour(&sur, false).is_none(), "la valeur sûre ne doit RIEN déclencher");

        let dangereux = tri_pour(Some(1), Some(0)); // le monde qu'une future liaison livrerait
        let refus = refus_de_demarrage_pour(&dangereux, false).expect("la valeur dangereuse doit REFUSER");
        assert!(refus.contains("REFUS DE DÉMARRER"), "{refus}");
        assert!(refus.contains("EN CLAIR"), "le refus doit dire CE QUI FUIT : {refus}");
        assert!(
            refus.contains("SQLITE_TEMP_STORE=2") && refus.contains("PLUME_SQLITE_DEVERSEMENT=1"),
            "et les DEUX sorties : reconstruire le moteur, ou prendre l'échange explicitement : {refus}"
        );

        // L'OPT-IN N'EST PAS UN DÉFAUT : qui a demandé le déversement l'obtient, sans refus.
        assert!(refus_de_demarrage_pour(&Tri::SurDisque { compile: 2, local: 1 }, true).is_none());
        // L'ignorance est traitée comme le danger — fail-closed.
        assert!(refus_de_demarrage_pour(&Tri::Illisible("x".into()), false).is_some());
    }

    /// ⑤-a LA VOIE UNIQUE POSE ET RELIT, SUR UNE VRAIE BASE FICHIER. `armer` ne se contente pas
    /// d'envoyer le batch : il RELIT ce que la connexion en a fait. Un batch refusé — le cas que
    /// `let _ = execute_batch(...)` avalait sur tous les sites — ne peut plus passer pour un succès.
    ///
    /// MUTATION : forcer `temp_store=FILE` APRÈS l'armement fait basculer la relecture sur `SurDisque`.
    #[test]
    fn la_voie_unique_pose_et_relit_sur_une_vraie_base() {
        let coffre = crate::tmp_possede::TmpDb::neuf("tri-voie-unique");
        let c = rusqlite::Connection::open(coffre.as_str()).expect("base temporaire");
        match armer(&c) {
            Tri::EnMemoire { local, .. } => assert_eq!(local, 2, "l'armement pose `temp_store=MEMORY` (2), et on le RELIT"),
            autre => panic!("l'armement doit rendre un tri en mémoire — lu : {}", constat_de_tri(&autre)),
        }
        c.execute_batch("PRAGMA temp_store=FILE;").expect("mutation du réglage");
        assert!(
            matches!(lire_tri(&c), Tri::SurDisque { .. }),
            "la relecture doit SUIVRE le réglage réel, sinon elle ne lit rien"
        );
    }

    // ── ⑤-b LA GARDE DÉRIVÉE : AUCUNE CONNEXION HORS VOIE ────────────────────────────────────────
    // Même forme que `checkpoint_wal_passe_par_la_voie_unique` (P10.17-a) : on n'ÉNUMÈRE pas les sites,
    // on parcourt les sources, on dérive les fichiers de TEST depuis les déclarations `#[cfg(test)] mod
    // x;`, on retire les modules `#[cfg(test)]` internes et les COMMENTAIRES, et on refuse TOUT site
    // restant. Un fichier ajouté demain est couvert le jour où il est ajouté.

    use crate::db_open::door_tests::{est_test, fichiers_de_test, rs_files, texte_de_production};
    use std::path::PathBuf;

    /// Le fichier autorisé à ouvrir SANS armer sur la ligne même : la PORTE arme ses deux ouvertures
    /// nues, donc tous ses appelants avec elles.
    const LA_PORTE: &str = "db_open.rs";
    /// La règle est la PROXIMITÉ, pas le flot de données : un chemin qui ouvrirait ici et armerait très
    /// loin échoue, et c'est voulu — on préfère un refus bruyant à une connexion dont le tri n'est borné
    /// que par la valeur compilée du moteur.
    const FENETRE: usize = 15;

    /// Cette ligne obtient-elle une connexion rusqlite sur un FICHIER ? Dérivé de ce qui rend un trieur
    /// dépendant de la valeur compilée : l'ouverture elle-même.
    ///   - toutes les formes de `Connection::open*`, lecture seule COMPRISE — un `SELECT … ORDER BY`
    ///     trie exactement comme une écriture, la lecture seule ne protège de rien ici ;
    ///   - PAS `open_in_memory` : il n'y a pas de fichier de base, et la sonde de S26 en est une ;
    ///   - PAS un `Connection` qualifié par un AUTRE moteur (`duckdb::`) ; renommer `rusqlite` pour se
    ///     glisser dans cette exclusion est traité comme une ouverture.
    fn ouvre_une_connexion_sur_fichier(l: &str) -> bool {
        if l.contains("use rusqlite::Connection as") || l.contains("use rusqlite as") {
            return true;
        }
        match l.find("Connection::open") {
            None => false,
            Some(pos) => {
                if l[pos..].starts_with("Connection::open_in_memory") {
                    return false;
                }
                match l[..pos].rfind("::") {
                    Some(fin) if fin + 2 == pos => {
                        let debut = l[..fin].rfind(|c: char| !c.is_alphanumeric() && c != '_').map_or(0, |i| i + 1);
                        &l[debut..fin] == "rusqlite"
                    }
                    _ => true,
                }
            }
        }
    }

    #[test]
    fn toute_connexion_sur_fichier_est_armee() {
        let racine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        rs_files(&racine, &mut fichiers);
        assert!(fichiers.len() > 20, "précondition : le scanner a trouvé les sources ({})", fichiers.len());
        let marques = fichiers_de_test(&fichiers);

        let (mut ouvertures, mut hors_voie) = (0usize, Vec::<String>::new());
        let mut la_porte_arme = 0usize;
        for f in &fichiers {
            if est_test(f, &marques) {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap();
            let lignes = texte_de_production(f, &src);
            let porte = f.file_name().is_some_and(|n| n == LA_PORTE);
            for (i, (n, l)) in lignes.iter().enumerate() {
                if porte && l.contains("sqlite_plafond::armer(") {
                    la_porte_arme += 1;
                }
                if !ouvre_une_connexion_sur_fichier(l) {
                    continue;
                }
                ouvertures += 1;
                let arme = porte
                    || lignes[i..lignes.len().min(i + FENETRE)]
                        .iter()
                        .any(|(_, s)| s.contains("sqlite_plafond::armer("));
                if !arme {
                    hors_voie.push(format!("{}:{n}: {}", f.display(), l.trim()));
                }
            }
        }

        // ANTI-FAUX-VERT, DEUX FOIS. Si le scanner ne voyait plus aucune ouverture, ou si la porte
        // cessait d'armer les siennes, cette garde rendrait VERT en ne gardant plus rien — et c'est
        // précisément l'exemption qu'elle accorde à la porte qui le permettrait.
        assert!(ouvertures >= 8, "précondition : le scanner voit les ouvertures de production ({ouvertures})");
        assert_eq!(
            la_porte_arme, 2,
            "la porte doit armer ses DEUX ouvertures nues (`raw_env`, `raw_keyed`) : c'est ce qui couvre \
             tous ses appelants, et donc ce qui justifie l'exemption accordée à {LA_PORTE}"
        );
        assert!(
            hors_voie.is_empty(),
            "connexion(s) ouverte(s) HORS de la voie qui pose les réglages de tri :\n  {}\n\
             Une connexion qui ne pose rien hérite du réglage COMPILÉ du moteur ; si celui-ci change, ses \
             tris déversent des VALEURS D'ÉVÉNEMENT EN CLAIR hors de la base SQLCipher. Appeler \
             `sqlite_plafond::armer(&conn)` à l'ouverture, ou passer par la porte `db_open`.",
            hors_voie.join("\n  ")
        );
    }

    /// LE SCANNER EST MESURÉ, sinon il pourrait être vert en ne voyant rien. On lui donne les formes
    /// qu'il DOIT attraper et celles qu'il doit laisser passer — dont la lecture seule, que la garde
    /// précédente (bornée aux ouvertures `SQLITE_OPEN_READ_ONLY`) traitait à part et que celle-ci couvre
    /// au même titre : un tri de lecture écrit les mêmes octets en clair qu'un tri d'écriture.
    #[test]
    fn le_scanner_de_voie_unique_attrape_ce_quil_annonce() {
        for attrape in [
            "    let conn = Connection::open(&path)?;",
            "let c = rusqlite::Connection::open(p).unwrap();",
            "let conn = Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;",
            "let conn = Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;",
            "use rusqlite::Connection as C;",
        ] {
            assert!(ouvre_une_connexion_sur_fichier(attrape), "doit être attrapé : {attrape}");
        }
        for laisse in [
            "let conn = Connection::open_in_memory()?;",
            "let conn = duckdb::Connection::open(db_path).map_err(be)?;",
            "let db = PreparedDb::open(&db_path)?;",
            "    let _ = sqlite_plafond::armer(&conn);",
        ] {
            assert!(!ouvre_une_connexion_sur_fichier(laisse), "ne doit PAS être attrapé : {laisse}");
        }
    }
}
