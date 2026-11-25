// =====================================================================================
// RESTAURATION : CE QU'UN MODULE FAIT À SA CRÉATION EST REJOUÉ AU FORMAT ANCIEN, ET LES GARDES QUE L'ARCHIVE NE PEUT
// PLUS ATTEINDRE GARDENT LEUR TÉMOIN (`backup/restauration_liste_fermee.rs` : `juger_le_schema_du_format_ancien`,
// `admettre`, `action_interne_d_un_module`, `crochets_de_restauration` ; `backup/dump_restauration.rs` :
// `restore_stream`, `restore_compressed`).
//
// LE DÉFAUT, LU SUR ecc5b404 : au format ancien, une ligne de table virtuelle n'était que PRÉPARÉE sur le brouillon
// (module, classe d'instruction, arguments) ; ce que le module fait en s'exécutant, que le format courant juge sous la
// liste, n'était pas rejoué, et les tables fantômes du fichier étaient jugées comme des tables quelconques puis
// rejouées par l'export. Une FTS4 qui relit sa table de contenu à sa création (refusée au format courant), une table
// sous un nom fantôme que le module ne crée pas, une table fantôme absente ou réécrite (contrainte qui bornerait les
// écritures du module) : la base était publiée.
//
// DÉSORMAIS : la création d'une table virtuelle est EXÉCUTÉE sur le brouillon, sous la liste ; le module y crée ses
// tables fantômes, et celles du fichier (une table rejouée nommée `<vt>_<suffixe>` d'une table virtuelle du fichier)
// ne sont plus créées comme des tables : l'ensemble de leurs noms et de leurs textes doit être EXACTEMENT celui que le
// module a créé. Tout écart refuse sous « format ancien », phrase fixe, avant l'export et avant toute publication.
//
// LES DEUX GARDES DE LA RECONSTRUCTION PLEIN TEXTE (lecture de la seule table de contenu créée par la restauration ;
// fonctions des seuls modules) ne sont plus atteintes par une archive depuis que les arguments d'une table virtuelle
// sont jugés à sa création. Elles restent une défense en profondeur ; leur témoin passe par le crochet de test
// `crochets_de_restauration::sans_jugement_des_arguments`, qui retire ce jugement sur le fil du témoin.
//
// L'ÉCRITURE D'UN COMPTEUR REFUSÉE PAR LE MOTEUR : témoin léger par le crochet `crochets_de_restauration::
// sur_la_connexion`, qui abaisse la longueur maximale d'une valeur sur la connexion de restauration ; un nom de
// compteur plus long rend la phase et le code SQLite (`SQLITE_TOOBIG`), jamais ce nom.
// =====================================================================================

mod cj2_restauration_creation_rejouee_et_gardes_de_profondeur {
    use super::*;
    use crate::backup::{crochets_de_restauration, SUFFIXE_RESTAURATION_EN_COURS};

    const CLE: &str = "cj2-cle-de-test-de-restauration";

    // Les phrases attendues, écrites ici en toutes lettres (jamais relues de la production).
    const CLASSE: &str = "classe d'instruction hors de la liste de la phase";
    const FANTOME: &str = "tables fantômes autres que celles que le module crée";
    const OPTION: &str = "argument de table virtuelle hors de ce que l'écrivain émet";

    fn chemin(racine: &std::path::Path, nom: &str) -> String {
        racine.join(nom).to_string_lossy().into_owned()
    }

    /// age(zstd(charge)) chiffré à la passphrase `CLE` — la même enveloppe que `backup_compressed`.
    fn archive_de(charge: &[u8], chemin: &str) {
        use std::io::Write;
        let out = std::fs::File::create(chemin).unwrap();
        let w = crate::backup::backup_encryptor(CLE, None).unwrap().wrap_output(out).unwrap();
        let mut z = zstd::Encoder::new(w, 3).unwrap();
        z.write_all(charge).unwrap();
        z.finish().unwrap().finish().unwrap();
    }

    fn contenu(racine: &std::path::Path) -> Vec<String> {
        let mut noms: Vec<String> = std::fs::read_dir(racine).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        noms.sort();
        noms
    }

    fn lignes_de(c: &rusqlite::Connection, sql: &str) -> Vec<String> {
        let mut s = c.prepare(sql).unwrap();
        let n = s.column_count();
        let mut lignes: Vec<String> = s
            .query_map([], |r| Ok((0..n).map(|i| format!("{:?}", r.get::<_, rusqlite::types::Value>(i).unwrap())).collect::<Vec<_>>().join("|")))
            .unwrap()
            .map(|l| l.unwrap())
            .collect();
        lignes.sort();
        lignes
    }

    fn suffixe_intacte(dest: &str) -> String {
        format!(" — la destination {dest} est INTACTE : la restauration s'écrivait dans {dest}{SUFFIXE_RESTAURATION_EN_COURS}, qui a été retiré.")
    }

    fn hors_liste(phase: &'static str, cause: &'static str) -> impl Fn(&str) -> String {
        move |dest| format!("restore : phase {phase} : instruction hors liste ({cause}){}", suffixe_intacte(dest))
    }

    /// LE TÉMOIN DE REFUS, deux fois. (1) Destination ABSENTE : la restauration échoue avec exactement `attendue(dest)`,
    /// et seul `archive.age` reste (rien de publié, ni temporaire ni clair). (2) Destination SAINE avec ses compagnons
    /// `-wal` et `-shm`, restaurée avec `--force` : même refus, base et compagnons identiques à l'octet, rien d'autre ne
    /// reste.
    fn refusee(cas: &str, charge: &[u8], attendue: impl Fn(&str) -> String) {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        {
            let _tmp = crate::tmp_possede::TmpPossede::neuf(&format!("{cas}-sans-dest"));
            let racine = _tmp.racine().chemin().to_path_buf();
            archive_de(charge, &chemin(&racine, "archive.age"));
            let dest = chemin(&racine, "plume.db");
            let err = restore_compressed(&chemin(&racine, "archive.age"), &dest, Some(CLE), false, None).expect_err(cas);
            assert_eq!(err, attendue(&dest), "{cas} (sans destination)");
            assert_eq!(contenu(&racine), vec!["archive.age".to_string()], "{cas} : ni destination publiée, ni temporaire, ni clair");
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf(cas);
        let racine = _tmp.racine().chemin().to_path_buf();
        archive_de(charge, &chemin(&racine, "archive.age"));
        let dest = chemin(&racine, "plume.db");
        {
            let c = open_db_keyed(&dest, Some(CLE)).unwrap();
            c.execute_batch("CREATE TABLE t(v TEXT); INSERT INTO t VALUES('ancienne');").unwrap();
        }
        std::fs::write(format!("{dest}-wal"), b"compagnon -wal de l'ancienne base").unwrap();
        std::fs::write(format!("{dest}-shm"), b"compagnon -shm de l'ancienne base").unwrap();
        let avant: Vec<Vec<u8>> = ["", "-wal", "-shm"].iter().map(|s| std::fs::read(format!("{dest}{s}")).unwrap()).collect();
        let err = restore_compressed(&chemin(&racine, "archive.age"), &dest, Some(CLE), true, None).expect_err(cas);
        assert_eq!(err, attendue(&dest), "{cas}");
        let apres: Vec<Vec<u8>> = ["", "-wal", "-shm"].iter().map(|s| std::fs::read(format!("{dest}{s}")).unwrap()).collect();
        assert!(apres == avant, "{cas} : la destination ou un compagnon a changé");
        assert_eq!(contenu(&racine), vec!["archive.age", "plume.db", "plume.db-shm", "plume.db-wal"], "{cas} : rien d'autre ne reste");
    }

    /// Restaure `charge` sur une destination absente ; rend la connexion à la base publiée.
    fn admise(cas: &str, racine: &std::path::Path, charge: &[u8]) -> rusqlite::Connection {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        archive_de(charge, &chemin(racine, "archive.age"));
        let dest = chemin(racine, "plume.db");
        restore_compressed(&chemin(racine, "archive.age"), &dest, Some(CLE), false, None).unwrap_or_else(|e| panic!("{cas} : {e}"));
        open_db_keyed(&dest, Some(CLE)).unwrap()
    }

    // ── FORMAT ANCIEN ───────────────────────────────────────────────────────────────────────────────

    /// Une base SQLite EN CLAIR portant `t(v)` et sa ligne 'legacy', puis `ddl` ; rend ses octets (la charge d'une archive
    /// au format ancien). Le fichier est retiré.
    fn clair(racine: &std::path::Path, ddl: &str) -> Vec<u8> {
        let p = chemin(racine, "clair-de-fixture.db");
        {
            let c = open_db_keyed(&p, None).unwrap();
            c.execute_batch("CREATE TABLE t(v TEXT); INSERT INTO t VALUES('legacy');").unwrap();
            c.execute_batch(ddl).unwrap();
        }
        let octets = std::fs::read(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        octets
    }

    fn ancien_refuse(cas: &str, ddl: &str, cause: &'static str) {
        let _tmp = crate::tmp_possede::TmpPossede::neuf(&format!("{cas}-fixture"));
        let charge = clair(_tmp.racine().chemin(), ddl);
        refusee(cas, &charge, hors_liste("format ancien", cause));
    }

    /// LE MODULE RELIT SA TABLE DE CONTENU À SA CRÉATION : une FTS4 sans colonne déclarée prend celles de `t`. Ses
    /// arguments sont admis (`content='t'`, une table du fichier) ; au format courant, la lecture de `t` pendant la
    /// création est refusée par la liste (`restauration_format_ancien_liste_fermee.rs`, cd1-b-p-autoriseur). Au format
    /// ancien, la ligne n'était que préparée : la base était publiée.
    #[test]
    fn ancien_une_fts4_qui_relit_sa_table_de_contenu_a_la_creation_est_refusee() {
        ancien_refuse("cj2-a-fts4-sans-colonne", "CREATE VIRTUAL TABLE f USING fts4(content='t');", CLASSE);
    }

    /// UNE TABLE SOUS UN NOM FANTÔME QUE LE MODULE NE CRÉE PAS : une FTS5 à contenu externe n'a pas de `f_content`.
    /// L'écrivain n'émet jamais de table de cette forme (`collect_dump_plan` les écarte) ; elle était rejouée.
    #[test]
    fn ancien_une_table_sous_un_nom_fantome_que_le_module_ne_cree_pas_est_refusee() {
        ancien_refuse("cj2-a-fantome-en-trop", "CREATE VIRTUAL TABLE f USING fts5(v, content='t'); CREATE TABLE f_content(x);", FANTOME);
    }

    /// UNE TABLE FANTÔME ABSENTE : le module crée `f_docsize`, le fichier ne la porte plus.
    #[test]
    fn ancien_une_table_fantome_absente_est_refusee() {
        ancien_refuse("cj2-a-fantome-absente", "CREATE VIRTUAL TABLE f USING fts5(v, content='t'); DROP TABLE f_docsize;", FANTOME);
    }

    /// UNE TABLE FANTÔME RÉÉCRITE : même nom, même colonnes, une contrainte en plus (sans fonction, donc admise par la
    /// phase des tables) qui refuserait au module ses écritures à venir. Elle était rejouée par l'export ; son texte
    /// n'est pas celui que le module écrit.
    #[test]
    fn ancien_une_table_fantome_reecrite_est_refusee() {
        ancien_refuse(
            "cj2-a-fantome-reecrite",
            "CREATE VIRTUAL TABLE f USING fts5(v, content='t'); PRAGMA writable_schema=ON; \
             UPDATE sqlite_master SET sql = 'CREATE TABLE ''f_data''(id INTEGER PRIMARY KEY, block BLOB, CHECK (id < 1000))' \
             WHERE name = 'f_data'; PRAGMA writable_schema=OFF;",
            FANTOME,
        );
    }

    /// Restaure l'archive au format ancien qui porte `ddl` ; la base publiée porte le schéma du fichier à l'identique
    /// (tables fantômes comprises). Rend la connexion à la base publiée.
    fn ancien_admis_comme_la_source(cas: &str, racine: &std::path::Path, ddl: &str) -> rusqlite::Connection {
        let source = {
            let p = chemin(racine, "source.db");
            let c = open_db_keyed(&p, None).unwrap();
            c.execute_batch("CREATE TABLE t(v TEXT); INSERT INTO t VALUES('legacy');").unwrap();
            c.execute_batch(ddl).unwrap();
            let schema = lignes_de(&c, "SELECT type, name, sql FROM sqlite_master");
            drop(c);
            std::fs::remove_file(&p).unwrap();
            schema
        };
        let charge = clair(racine, ddl);
        let c = admise(cas, racine, &charge);
        assert_eq!(lignes_de(&c, "SELECT type, name, sql FROM sqlite_master"), source, "{cas} : schéma publié");
        c
    }

    /// LE CONTRÔLE : une FTS4 et une FTS5 à contenu externe, reconstruites, se restaurent ; la base publiée porte le
    /// schéma du fichier à l'identique (tables fantômes comprises) et chaque table virtuelle répond.
    #[test]
    fn ancien_une_fts4_et_une_fts5_admises_se_restaurent_avec_leurs_tables_fantomes() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cj2-a-admis");
        let racine = _tmp.racine().chemin().to_path_buf();
        let c = ancien_admis_comme_la_source(
            "cj2-a-admis",
            &racine,
            "CREATE VIRTUAL TABLE f4 USING fts4(v, content='t'); INSERT INTO f4(f4) VALUES('rebuild'); \
             CREATE VIRTUAL TABLE e USING fts5(v, content='t', content_rowid='rowid'); INSERT INTO e(e) VALUES('rebuild');",
        );
        let fantomes = lignes_de(&c, "SELECT name FROM sqlite_master WHERE name GLOB 'f4_*' OR name GLOB 'e_*'");
        let attendues = ["e_config", "e_data", "e_docsize", "e_idx", "f4_docsize", "f4_segdir", "f4_segments", "f4_stat"];
        assert_eq!(fantomes, attendues.iter().map(|n| format!("Text({n:?})")).collect::<Vec<_>>(), "tables fantômes publiées");
        assert_eq!(lignes_de(&c, "SELECT rowid FROM e WHERE e MATCH 'legacy'"), vec!["Integer(1)".to_string()], "e répond");
        assert_eq!(lignes_de(&c, "SELECT rowid FROM f4 WHERE f4 MATCH 'legacy'"), vec!["Integer(1)".to_string()], "f4 répond");
    }

    /// UN NOM DE LA FORME `<x>_<suffixe>` N'EST UNE TABLE FANTÔME QUE SI `x` EST UNE TABLE VIRTUELLE DU FICHIER ET SI LA
    /// LIGNE EST UNE TABLE REJOUÉE : `t_data` (`t` est une table ordinaire), `w_idx` (`w` est une vue) restent des tables
    /// jugées et rejouées ; le déclencheur `f_config` (à côté de la FTS5 `f`) n'est pas une table. L'archive se restaure.
    #[test]
    fn ancien_un_nom_de_forme_fantome_hors_d_une_table_virtuelle_reste_une_ligne_ordinaire() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cj2-a-nom-ordinaire");
        let racine = _tmp.racine().chemin().to_path_buf();
        ancien_admis_comme_la_source(
            "cj2-a-nom-ordinaire",
            &racine,
            "CREATE TABLE t_data(x); CREATE VIEW w AS SELECT v FROM t; CREATE TABLE w_idx(x); \
             CREATE VIRTUAL TABLE f USING fts5(v, content='t'); CREATE TRIGGER f_config AFTER INSERT ON t BEGIN SELECT 1; END;",
        );
    }

    // ── FORMAT COURANT : DUMPS FORGÉS ───────────────────────────────────────────────────────────────

    fn ecrire_u32(v: &mut Vec<u8>, n: u32) {
        v.extend_from_slice(&n.to_le_bytes());
    }
    fn ecrire_str(v: &mut Vec<u8>, s: &str) {
        ecrire_u32(v, s.len() as u32);
        v.extend_from_slice(s.as_bytes());
    }

    enum Post {
        Sql(&'static str),
        Reconstruire(&'static str),
    }

    /// Un dump B1 forgé au format de `dump_stream` : la table `table` (colonnes `id`, `v`) et sa ligne (1, 'restauree') au
    /// texte d'insertion de l'écrivain, les compteurs `compteurs`, puis `post`.
    fn dump(table: &str, compteurs: &[(&str, i64)], post: &[Post]) -> Vec<u8> {
        let mut v = b"PLUMEDUMP1\n".to_vec();
        ecrire_u32(&mut v, 1);
        ecrire_str(&mut v, table);
        ecrire_u32(&mut v, 1);
        ecrire_str(&mut v, "t");
        v.extend_from_slice(&2u16.to_le_bytes());
        ecrire_str(&mut v, "INSERT INTO \"t\" (\"id\", \"v\") VALUES (?, ?)");
        v.push(1);
        v.push(1);
        v.extend_from_slice(&1i64.to_le_bytes());
        v.push(3);
        ecrire_str(&mut v, "restauree");
        v.push(0);
        ecrire_u32(&mut v, compteurs.len() as u32);
        for (nom, seq) in compteurs {
            ecrire_str(&mut v, nom);
            v.extend_from_slice(&seq.to_le_bytes());
        }
        ecrire_u32(&mut v, post.len() as u32);
        for p in post {
            match p {
                Post::Sql(sql) => {
                    v.push(1);
                    ecrire_str(&mut v, sql);
                }
                Post::Reconstruire(nom) => {
                    v.push(2);
                    ecrire_str(&mut v, nom);
                }
            }
        }
        v.push(0xFF);
        v
    }

    const TABLE: &str = "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)";

    // ── LES DEUX GARDES DE LA RECONSTRUCTION FTS ────────────────────────────────────────────────────

    /// GARDE DE LECTURE : pendant la reconstruction, le module ne relit qu'une table créée par la section 1. Sans le
    /// crochet, l'archive est refusée plus tôt, sur son argument `content=` (le jugement qui rend la garde inatteignable) ;
    /// avec lui, la reconstruction relit `sqlite_master` et la garde refuse.
    #[test]
    fn garde_de_lecture_de_la_reconstruction_refuse_une_table_non_restauree() {
        let charge = dump(TABLE, &[], &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(name, content='sqlite_master')"), Post::Reconstruire("f")]);
        refusee("cj2-r-lecture-jugee", &charge, hors_liste("post-DDL", OPTION));
        let _arme = crochets_de_restauration::sans_jugement_des_arguments();
        refusee("cj2-r-lecture", &charge, hors_liste("reconstruction FTS", CLASSE));
    }

    /// GARDE DES FONCTIONS : pendant la reconstruction, le module n'appelle que `max` et `coalesce`. Une FTS4 créée avec
    /// `compress=`/`uncompress=` y fait appeler `hex`, nommée par l'archive : sans le crochet, refusée sur son argument ;
    /// avec lui, la garde refuse l'appel.
    #[test]
    fn garde_des_fonctions_de_la_reconstruction_refuse_une_fonction_nommee_par_l_archive() {
        let charge = dump(TABLE, &[], &[Post::Sql("CREATE VIRTUAL TABLE f USING fts4(v, compress=hex, uncompress=hex)"), Post::Reconstruire("f")]);
        refusee("cj2-r-fonction-jugee", &charge, hors_liste("post-DDL", OPTION));
        let _arme = crochets_de_restauration::sans_jugement_des_arguments();
        refusee("cj2-r-fonction", &charge, hors_liste("reconstruction FTS", CLASSE));
    }

    /// LE CONTRÔLE DU CROCHET : une archive conforme (FTS5 et FTS4 à contenu externe, reconstruites) se restaure avec le
    /// crochet armé ; chaque refus ci-dessus vient donc de la garde, pas du crochet.
    #[test]
    fn sans_jugement_des_arguments_une_archive_conforme_se_restaure() {
        let _arme = crochets_de_restauration::sans_jugement_des_arguments();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cj2-r-conforme");
        let racine = _tmp.racine().chemin().to_path_buf();
        let charge = dump(
            TABLE,
            &[],
            &[
                Post::Sql("CREATE VIRTUAL TABLE e USING fts5(v, content='t', content_rowid='id')"),
                Post::Sql("CREATE VIRTUAL TABLE f USING fts4(v, content='t')"),
                Post::Reconstruire("e"),
                Post::Reconstruire("f"),
            ],
        );
        let c = admise("cj2-r-conforme", &racine, &charge);
        assert_eq!(lignes_de(&c, "SELECT rowid FROM e WHERE e MATCH 'restauree'"), vec!["Integer(1)".to_string()]);
        assert_eq!(lignes_de(&c, "SELECT rowid FROM f WHERE f MATCH 'restauree'"), vec!["Integer(1)".to_string()]);
    }

    // ── L'ÉCRITURE D'UN COMPTEUR ────────────────────────────────────────────────────────────────────

    const AUTOINCREMENT: &str = "CREATE TABLE t(id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)";

    /// La longueur maximale d'une valeur posée sur la connexion de restauration : assez pour le schéma et la ligne du dump
    /// forgé, moins que le nom de compteur du témoin.
    const LONGUEUR_MAXIMALE: i32 = 256;

    fn abaisser_la_longueur_maximale() -> crochets_de_restauration::Arme {
        crochets_de_restauration::sur_la_connexion(|c| {
            // SAFETY : la poignée vit autant que `c`, que la restauration garde ouverte pendant l'appel.
            unsafe {
                rusqlite::ffi::sqlite3_limit(c.handle(), rusqlite::ffi::SQLITE_LIMIT_LENGTH, LONGUEUR_MAXIMALE);
            }
        })
    }

    /// L'ÉCRITURE D'UN COMPTEUR REFUSÉE PAR LE MOTEUR : un nom de compteur plus long que la longueur maximale du moteur
    /// (`SQLITE_TOOBIG`, code 18). Le refus nomme la phase des compteurs et le code, jamais ce nom ; rien n'est publié.
    #[test]
    fn l_ecriture_d_un_compteur_refusee_par_le_moteur_rend_la_phase_et_son_code() {
        let nom = "compteur-".repeat(40);
        assert!(nom.len() > LONGUEUR_MAXIMALE as usize, "contrôle : le nom dépasse la longueur maximale");
        let charge = dump(AUTOINCREMENT, &[(nom.as_str(), 5)], &[]);
        let _arme = abaisser_la_longueur_maximale();
        refusee("cj2-c-compteur", &charge, |dest| {
            format!("restore : phase compteurs : refusée par le moteur (code 18){}", suffixe_intacte(dest))
        });
    }

    /// LE CONTRÔLE : la même archive avec un nom court, sous la même longueur maximale, se restaure et la base publiée
    /// porte le compteur de l'archive (et non celui que le moteur a posé pendant les données).
    #[test]
    fn sous_la_meme_longueur_maximale_un_compteur_court_s_ecrit() {
        let _arme = abaisser_la_longueur_maximale();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cj2-c-compteur-court");
        let racine = _tmp.racine().chemin().to_path_buf();
        let c = admise("cj2-c-compteur-court", &racine, &dump(AUTOINCREMENT, &[("t", 5)], &[]));
        assert_eq!(lignes_de(&c, "SELECT name, seq FROM sqlite_sequence"), vec!["Text(\"t\")|Integer(5)".to_string()]);
    }
}
