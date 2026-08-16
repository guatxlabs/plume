// P10.17-a — GARDE : `wal_checkpoint` N'EXISTE QU'À UN SEUL ENDROIT DU CODE DE PRODUCTION.
//
// LE DÉFAUT QU'ELLE FERME. `PRAGMA wal_checkpoint(TRUNCATE)` ne rend pas son verdict par un
// code d'erreur mais par une LIGNE `(busy, log, checkpointed)`. `execute_batch` ne lit aucune
// ligne : il rend `Ok(())` que la troncature ait eu lieu OU qu'un lecteur l'ait refusée. Les
// CINQ sites de production appelaient `execute_batch` et jetaient tous ce `Ok` — le démon
// croyait tronquer son WAL après backup, fusion de rollups, démarrage, arrêt et bascule
// SQLCipher, sans jamais distinguer « tronqué » de « refusé ».
//
// POURQUOI UNE GARDE ET NON CINQ CORRECTIFS. Corriger cinq appels laisse le sixième, écrit
// demain, aveugle — et il le serait en silence, comme les cinq précédents. Ici la couverture
// est acquise par CONSTRUCTION : le PRAGMA ne peut plus apparaître hors de
// `db_open::checkpoint_wal_tronque`, qui LIT sa ligne.
//
// CE QUE LE PÉRIMÈTRE EXCLUT, ET POURQUOI C'EST DÉLIBÉRÉ :
//   * les fichiers de TEST (`est_test`) — un test a le droit d'appeler le PRAGMA nu ;
//   * les modules `#[cfg(test)]` INTERNES à un fichier de production — c'est
//     `texte_de_production` qui les retire. `migrate.rs` en contient deux occurrences, dans
//     le module de test ouvert ligne 5137. **Mon premier comptage annonçait 7 sites de
//     production ; il y en a 5.** J'avais compté sur un `grep` brut, qui ne sait pas ce
//     qu'est un module de test ;
//   * les COMMENTAIRES (`sans_commentaire`) — `rollups.rs` explique dans un commentaire
//     pourquoi son ordre d'opérations précède « le `wal_checkpoint(TRUNCATE)` du bloc
//     suivant ». Une garde qui compterait ce texte interdirait d'écrire POURQUOI elle
//     existe : faute commise le matin même sur une autre garde, dont le témoin négatif
//     matchait le commentaire qui le justifiait.
//
// CE QU'ELLE NE PROUVE PAS : que la voie unique lit CORRECTEMENT la ligne. C'est
// `le_checkpoint_rend_un_verdict_lisible` qui l'exerce, sur une vraie base.

#[cfg(test)]
mod checkpoint_wal_voie_unique_tests {
    use crate::db_open::door_tests::{
        est_test, fichiers_de_test, rs_files, sans_commentaire, texte_de_production,
    };
    use std::path::PathBuf;

    /// Le SEUL fichier autorisé à nommer le PRAGMA — celui qui en lit le résultat.
    const VOIE_UNIQUE: &str = "db_open.rs";

    #[test]
    fn checkpoint_wal_passe_par_la_voie_unique() {
        let racine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        rs_files(&racine, &mut fichiers);
        let marques = fichiers_de_test(&fichiers);

        let (mut hors_voie, mut vu_dans_la_voie) = (Vec::<String>::new(), false);
        for f in &fichiers {
            if est_test(f, &marques) {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap();
            let porte = texte_de_production(f, &src)
                .into_iter()
                .any(|(_, l)| sans_commentaire(&l).contains("wal_checkpoint"));
            if !porte {
                continue;
            }
            if f.file_name().is_some_and(|n| n == VOIE_UNIQUE) {
                vu_dans_la_voie = true;
            } else {
                hors_voie.push(f.display().to_string());
            }
        }

        // PRÉCONDITION : si la voie unique ne portait plus le PRAGMA, la garde deviendrait
        // vide et rendrait VERT pour de mauvaises raisons. On refuse de conclure — c'est le
        // défaut « l'instrument ne peut pas trouver » que cette campagne poursuit ailleurs.
        assert!(
            vu_dans_la_voie,
            "`wal_checkpoint` a disparu de {VOIE_UNIQUE} : la garde ne garde plus rien, \
             elle ne doit donc pas rendre VERT"
        );
        assert!(
            hors_voie.is_empty(),
            "`PRAGMA wal_checkpoint` appelé HORS de la voie unique ({VOIE_UNIQUE}) :\n  {}\n\
             Un appel direct ne LIT PAS la ligne (busy, log, checkpointed) : il rend Ok(()) \
             même quand la troncature a été REFUSÉE. Passer par \
             `db_open::checkpoint_wal_tronque(conn, \"<contexte>\")`.",
            hors_voie.join("\n  ")
        );
    }

    /// La voie unique rend-elle un verdict LISIBLE sur une vraie base ? Sans ce test, la
    /// garde ci-dessus prouverait seulement que personne n'appelle le PRAGMA ailleurs — pas
    /// que l'unique appelant en fait quelque chose.
    #[test]
    fn le_checkpoint_rend_un_verdict_lisible() {
        use crate::db_open::{checkpoint_wal_tronque, Checkpoint};
        // TEMPORAIRE POSSÉDÉ, et c'est la garde de BUILD qui me l'a appris : mon premier jet
        // appelait `std::env::temp_dir()` et `garde_temporaire_possede` a FAIT ÉCHOUER la
        // compilation. Elle avait raison — SQLite crée deux sidecars (`-wal`, `-shm`) que
        // personne ne nomme, et c'était 90 % de la fuite mesurée le 2026-08-03.
        let coffre = crate::tmp_possede::TmpDb::neuf("checkpoint-wal");
        let c = rusqlite::Connection::open(coffre.as_str()).expect("base temporaire");
        c.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE t(x); INSERT INTO t VALUES(1);")
            .expect("schéma");

        // CAS NOMINAL : aucun lecteur concurrent -> la troncature a lieu, et on le SAIT.
        let v = checkpoint_wal_tronque(&c, "test");
        assert!(v.a_tronque(), "sans lecteur concurrent, le checkpoint doit TRONQUER — obtenu {v:?}");

        // TÉMOIN NÉGATIF, ET IL A TROUVÉ UN VRAI TROU. Sur une base HORS mode WAL, SQLite
        // rend `busy=0` et `log = checkpointed = -1`. Mon premier jet tombait dans la
        // branche nominale et annonçait « tronqué » avec `pages: -1` — un succès pour une
        // opération qui n'a PAS eu lieu, c'est-à-dire exactement le défaut que cette voie
        // existe pour fermer. Sans ce témoin, la fonction aurait remplacé un mensonge
        // (`Ok(())` aveugle) par un autre, mieux habillé.
        let sans_wal = rusqlite::Connection::open_in_memory().expect("mémoire");
        sans_wal.execute_batch("PRAGMA journal_mode=DELETE;").expect("mode journal");
        let v2 = checkpoint_wal_tronque(&sans_wal, "test-sans-wal");
        assert!(
            matches!(v2, Checkpoint::Impossible(_)),
            "hors mode WAL, il n'y a RIEN à tronquer : le verdict doit le NOMMER, \
             pas rendre un succès — obtenu {v2:?}"
        );
        assert!(!v2.a_tronque(), "hors mode WAL, `a_tronque` doit être faux — obtenu {v2:?}");
    }
}
