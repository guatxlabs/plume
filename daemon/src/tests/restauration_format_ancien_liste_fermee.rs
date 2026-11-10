// =====================================================================================
// LE FORMAT ANCIEN SUIT LA LISTE FERMÉE DU FORMAT COURANT, ET UN REFUS DU MOTEUR NE RECOPIE PLUS SON TEXTE
// (`backup/restauration_liste_fermee.rs` : `juger_le_schema_du_format_ancien`, `refusee_par_le_moteur_sous`,
// `ListeFermee::executer_une_chaine` ; `backup/dump_restauration.rs` : `restore_compressed`, `restore_stream`).
//
// LES DÉFAUTS, LUS SUR 7e605d1f :
//  * une archive au format ancien (fichier SQLite en clair) était recopiée par `sqlcipher_export` sans aucun jugement :
//    les tables et les index du fichier étaient rejoués, ses vues, déclencheurs et tables virtuelles recopiés tels
//    quels dans le schéma de la base restaurée ;
//  * une chaîne de l'archive que la liste admet mais que le moteur refuse rendait le texte du moteur, qui peut citer un
//    morceau de la chaîne lue (« table t already exists in CREATE TABLE t(v TEXT) at offset 13 »).
//
// DÉSORMAIS : chaque ligne de schéma du fichier est jugée AVANT l'export sur un brouillon armé de la même liste (table
// rejouée sous la phase des tables, toute autre ligne sous celle du post-DDL ; seules les trois tables du moteur, à leur
// texte exact, sont exemptées) ; un refus nomme la phase « format ancien », la destination n'est pas publiée, une
// destination existante reste identique à l'octet, et ni le temporaire de restauration ni le fichier en clair ne
// restent. Une erreur du moteur née d'une chaîne ou d'une valeur de l'archive rend la phase, « refusée par le moteur »
// et le code d'erreur SQLite étendu, à chaque phase où une chaîne de l'archive est préparée ou exécutée ; un refus du
// moteur pendant le jugement du format ancien nomme « format ancien », et un refus de l'autoriseur pendant l'exécution
// reste le refus nommé, distinct de celui du moteur.
//
// LES ARCHIVES ADMISES sont de vraies sauvegardes (`backup_compressed`) : une base au schéma complet de la tête dont le
// filtre de champs plein texte (table virtuelle sans contenu) fait prendre le format ancien à l'écrivain. Les archives
// REFUSÉES portent chacune UNE ligne banale qu'aucune base du démon ne porte : table virtuelle d'un module que
// l'écrivain n'émet pas, index ou contrainte qui appelle une fonction hors des ensembles nommés.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'échec à l'EXÉCUTION d'une création de table admise (phase des tables), ni celui
// de l'écriture d'un compteur (`insert seq`), tous deux rendus par phase et code SQLite : les chemins connus qui les font
// échouer (une valeur lue de l'ordre de la limite de longueur du moteur, une panne du support ou de la mémoire) n'ont
// pas de témoin léger.
// =====================================================================================

mod restauration_format_ancien_liste_fermee {
    use super::*;
    use crate::backup::SUFFIXE_RESTAURATION_EN_COURS;

    const CLE: &str = "cd1-cle-de-test-de-restauration";

    // Les phrases attendues, écrites ici en toutes lettres (jamais relues de la production).
    const HORS_LISTE_ANCIEN: &str =
        "restore : phase format ancien : instruction hors liste (classe d'instruction hors de la liste de la phase)";

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

    fn suffixe_intacte(dest: &str) -> String {
        format!(" — la destination {dest} est INTACTE : la restauration s'écrivait dans {dest}{SUFFIXE_RESTAURATION_EN_COURS}, qui a été retiré.")
    }

    /// Les noms du répertoire, triés.
    fn contenu(racine: &std::path::Path) -> Vec<String> {
        let mut noms: Vec<String> = std::fs::read_dir(racine).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        noms.sort();
        noms
    }

    /// Une base SQLite EN CLAIR à `chemin`, portant `t(v)` et sa ligne 'legacy', puis `ddl` ; rend ses octets (la charge
    /// d'une archive au format ancien). Le fichier est retiré : seule l'archive reste dans le répertoire.
    fn clair(chemin: &str, ddl: &str) -> Vec<u8> {
        {
            let c = open_db_keyed(chemin, None).unwrap();
            c.execute_batch("CREATE TABLE t(v TEXT); INSERT INTO t VALUES('legacy');").unwrap();
            c.execute_batch(ddl).unwrap();
        }
        let octets = std::fs::read(chemin).unwrap();
        std::fs::remove_file(chemin).unwrap();
        octets
    }

    /// LE TÉMOIN DE REFUS, deux fois. (1) Destination ABSENTE : la restauration échoue avec exactement `attendue(dest)`,
    /// rien n'est publié, et seul `archive.age` reste (ni temporaire de restauration, ni fichier en clair). (2) Destination
    /// SAINE avec ses compagnons : même refus, base et compagnons identiques à l'octet, et rien d'autre ne reste.
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

    fn hors_liste_ancien(dest: &str) -> String {
        format!("{HORS_LISTE_ANCIEN}{}", suffixe_intacte(dest))
    }

    // ── FORMAT ANCIEN : REFUS ───────────────────────────────────────────────────────────────────────

    /// Une table virtuelle d'un module que l'écrivain n'émet pas (`fts5vocab`, présent dans le moteur), à côté d'une FTS5
    /// admise : l'export la recopiait telle quelle, le jugement la refuse.
    #[test]
    fn format_ancien_une_table_virtuelle_d_un_module_non_emis_est_refusee_avant_toute_publication() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cd1-a-module-fixture");
        let charge = clair(
            &chemin(_tmp.racine().chemin(), "clair.db"),
            "CREATE VIRTUAL TABLE f USING fts5(v, content='t'); CREATE VIRTUAL TABLE w USING fts5vocab(f, row);",
        );
        refusee("cd1-a-module", &charge, hors_liste_ancien);
    }

    /// Un index qui appelle une fonction hors de celles des index du démon (`json_extract`) : l'export le rejouait.
    #[test]
    fn format_ancien_un_index_qui_appelle_une_fonction_hors_liste_est_refuse() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cd1-a-index-fixture");
        let charge = clair(&chemin(_tmp.racine().chemin(), "clair.db"), "CREATE INDEX i ON t(upper(v));");
        refusee("cd1-a-index", &charge, hors_liste_ancien);
    }

    /// Une table dont la contrainte appelle une fonction : la phase des tables n'admet aucune fonction.
    #[test]
    fn format_ancien_une_contrainte_qui_appelle_une_fonction_est_refusee() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cd1-a-check-fixture");
        let charge = clair(&chemin(_tmp.racine().chemin(), "clair.db"), "CREATE TABLE c(v TEXT CHECK (length(v) < 9));");
        refusee("cd1-a-check", &charge, hors_liste_ancien);
    }

    /// Une table du moteur n'est exemptée qu'à son texte EXACT : `sqlite_stat1` (créée par `ANALYZE`) dont le texte porte
    /// une colonne de plus est jugée comme une création de table, et le moteur refuse ce nom réservé avant toute action.
    #[test]
    fn format_ancien_une_table_du_moteur_n_est_exemptee_qu_a_son_texte_exact() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cd1-a-stat1-fixture");
        let charge = clair(
            &chemin(_tmp.racine().chemin(), "clair.db"),
            "CREATE INDEX i ON t(v); ANALYZE;
             PRAGMA writable_schema=ON;
             UPDATE sqlite_master SET sql='CREATE TABLE sqlite_stat1(tbl,idx,stat,note)' WHERE name='sqlite_stat1';
             PRAGMA writable_schema=OFF;",
        );
        refusee("cd1-a-stat1", &charge, hors_liste_ancien);
    }

    /// UNE COLLATION INCONNUE N'ARRÊTE PAS LE JUGEMENT : la colonne qui la nomme précède une contrainte qui appelle une
    /// fonction ; sans la collation du brouillon, la préparation s'arrêterait à la collation et la contrainte ne serait
    /// jamais jugée (le refus serait alors celui du moteur, code 257). Le jugement précède l'export : joué après, l'export
    /// refuserait d'abord la collation. Le texte est posé par `writable_schema` : la collation n'existe pas quand le
    /// fichier est relu.
    #[test]
    fn format_ancien_une_collation_inconnue_n_arrete_pas_le_jugement() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cd1-a-collation-fixture");
        let charge = clair(
            &chemin(_tmp.racine().chemin(), "clair.db"),
            "CREATE TABLE u(w TEXT, x TEXT);
             PRAGMA writable_schema=ON;
             UPDATE sqlite_master SET sql='CREATE TABLE u(w TEXT COLLATE collation_inconnue_cd1, x TEXT CHECK (length(x) < 9))' WHERE name='u';
             PRAGMA writable_schema=OFF;",
        );
        refusee("cd1-a-collation", &charge, hors_liste_ancien);
    }

    /// LA COLLATION INCONNUE SEULE passe le jugement (ce n'est pas une classe d'instruction) et l'export la refuse comme
    /// avant ; l'erreur de l'export rend son code (celui que rend la fonction d'export, 1), sans le texte du moteur qui
    /// nommait la collation lue dans le fichier.
    #[test]
    fn format_ancien_un_refus_de_l_export_rend_son_code_sans_son_texte() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cd1-b-export-fixture");
        let charge = clair(
            &chemin(_tmp.racine().chemin(), "clair.db"),
            "CREATE TABLE u(w TEXT);
             PRAGMA writable_schema=ON;
             UPDATE sqlite_master SET sql='CREATE TABLE u(w TEXT COLLATE collation_inconnue_cd1)' WHERE name='u';
             PRAGMA writable_schema=OFF;",
        );
        refusee("cd1-b-export", &charge, |dest| {
            format!("re-chiffrement (sqlcipher_export) : phase format ancien : refusée par le moteur (code 1){}", suffixe_intacte(dest))
        });
    }

    /// Un fichier qui porte l'en-tête SQLite mais pas une base : la lecture de son schéma rend son code (26, « pas une
    /// base »), sans le texte du moteur.
    #[test]
    fn format_ancien_un_fichier_illisible_rend_son_code_sans_son_texte() {
        let mut charge = b"SQLite format 3\0".to_vec();
        charge.extend(std::iter::repeat(0x5Au8).take(4096 - 16));
        refusee("cd1-b-illisible", &charge, |dest| {
            format!("plaintext illisible (passphrase invalide ?) : phase format ancien : refusée par le moteur (code 26){}", suffixe_intacte(dest))
        });
    }

    /// Un `sql` de schéma qui n'est pas un texte UTF-8 (un octet 0xFF dans la chaîne d'une vue, posé par
    /// `writable_schema`) : le moteur relit le fichier, la bibliothèque ne lit pas ce texte ; refus sans code inventé.
    #[test]
    fn format_ancien_un_schema_qui_n_est_pas_de_l_utf8_est_refuse_sans_code() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cd1-b-utf8-fixture");
        let charge = clair(
            &chemin(_tmp.racine().chemin(), "clair.db"),
            "CREATE VIEW w AS SELECT 'ab' AS v;
             PRAGMA writable_schema=ON;
             UPDATE sqlite_master SET sql = CAST(CAST('CREATE VIEW w AS SELECT ''a' AS BLOB) || x'ff' || CAST('b'' AS v' AS BLOB) AS TEXT) WHERE name='w';
             PRAGMA writable_schema=OFF;",
        );
        refusee("cd1-b-utf8", &charge, |dest| {
            format!("restore : phase format ancien : refusée sans code d'erreur SQLite{}", suffixe_intacte(dest))
        });
    }

    /// UN REFUS DU MOTEUR PENDANT LE JUGEMENT est servi sous « format ancien », jamais sous la phase de la liste qui
    /// jugeait la ligne. Une table dont la contrainte cite une colonne absente (jugée sous la phase des tables) : le
    /// moteur relit le fichier sans résoudre ce nom, la préparation sur le brouillon le refuse (code 1). Le texte est
    /// posé par `writable_schema`.
    #[test]
    fn format_ancien_un_refus_du_moteur_sur_une_table_est_servi_sous_le_format_ancien() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cd1-b-moteur-table-fixture");
        let charge = clair(
            &chemin(_tmp.racine().chemin(), "clair.db"),
            "CREATE TABLE c(v TEXT);
             PRAGMA writable_schema=ON;
             UPDATE sqlite_master SET sql='CREATE TABLE c(v TEXT CHECK (w > 0))' WHERE name='c';
             PRAGMA writable_schema=OFF;",
        );
        refusee("cd1-b-moteur-table", &charge, moteur("format ancien", 1));
    }

    /// Même refus pour une ligne jugée sous la phase du post-DDL : un index qui appelle une fonction que le moteur ne
    /// connaît pas.
    #[test]
    fn format_ancien_un_refus_du_moteur_sur_un_index_est_servi_sous_le_format_ancien() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cd1-b-moteur-index-fixture");
        let charge = clair(
            &chemin(_tmp.racine().chemin(), "clair.db"),
            "CREATE INDEX i ON t(v);
             PRAGMA writable_schema=ON;
             UPDATE sqlite_master SET sql='CREATE INDEX i ON t(fonction_inconnue_cd1(v))' WHERE name='i';
             PRAGMA writable_schema=OFF;",
        );
        refusee("cd1-b-moteur-index", &charge, moteur("format ancien", 1));
    }

    // ── FORMAT ANCIEN : ADMIS ───────────────────────────────────────────────────────────────────────

    /// Une ligne relue, valeurs typées, rendue comparable.
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

    /// Restaure `archive` vers une destination neuve et compare à la source `src` (clé `cle`, `None` = en clair) :
    /// schéma entier, et lignes de chaque table qui porte des lignes (tables du moteur et tables fantômes comprises).
    fn restauree_comme_la_source(cas: &str, racine: &std::path::Path, archive: &str, src: &rusqlite::Connection) -> rusqlite::Connection {
        let dest = chemin(racine, "plume.db");
        restore_compressed(archive, &dest, Some(CLE), false, None).unwrap_or_else(|e| panic!("{cas} : {e}"));
        let dst = open_db_keyed(&dest, Some(CLE)).unwrap();
        let schema = "SELECT type, name, tbl_name, sql FROM sqlite_master";
        assert_eq!(lignes_de(&dst, schema), lignes_de(src, schema), "{cas} : schéma restauré = schéma de la source");
        let tables: Vec<String> = {
            let mut s = src.prepare("SELECT name FROM sqlite_master WHERE type='table' AND rootpage > 0 ORDER BY name").unwrap();
            s.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect()
        };
        for t in &tables {
            let sql = format!("SELECT * FROM \"{t}\"");
            assert_eq!(lignes_de(&dst, &sql), lignes_de(src, &sql), "{cas} : lignes de {t}");
        }
        dst
    }

    /// ALLER-RETOUR ANCIEN DU SCHÉMA COMPLET DE LA TÊTE. Une base de la tête (schéma de base puis toutes les migrations,
    /// dont `ANALYZE` : `sqlite_stat1` et `sqlite_stat4`), avec le filtre de champs plein texte (table virtuelle FTS5 sans
    /// contenu et ses déclencheurs, dont le corps appelle `json_valid`, `group_concat` et `json_each`) qui fait prendre le
    /// format ancien à l'écrivain réel, les index de champ chaud (`json_extract`), des compteurs AUTOINCREMENT, et une vue
    /// portant un déclencheur `INSTEAD OF` (la vue est créée sur le brouillon avant les déclencheurs). La restauration
    /// aboutit, le schéma et chaque table sont ceux de la source, et les deux FTS répondent.
    #[test]
    fn aller_retour_ancien_du_schema_complet_de_la_tete() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cd1-tete");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "src.db");
        {
            let c = open_db_keyed(&src, Some(CLE)).unwrap();
            c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&c);
            let mut conf = std::collections::HashMap::new();
            conf.insert("PLUME_FTS_FIELDS".to_string(), "1".to_string());
            let _ = crate::maintenance::reconcile_index_state(&c, &conf);
            for champ in crate::soql_glue::HOT_FIELDS {
                c.execute(
                    &format!(
                        "CREATE INDEX IF NOT EXISTS idx_ev_f_{champ} ON event(json_extract(fields,'$.{champ}')) \
                         WHERE json_extract(fields,'$.{champ}') IS NOT NULL"
                    ),
                    [],
                ).unwrap();
            }
            for i in 0..40i64 {
                c.execute(
                    "INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,'sshd','auth',3,?2,?3,?4)",
                    params![
                        1_700_000_000i64 + i,
                        format!("hote-{}", i % 4),
                        format!("refus du mot de passe pour alice numero {i}"),
                        format!("{{\"user\":\"bob{}\",\"action\":\"login\"}}", i % 3)
                    ],
                ).unwrap();
            }
            c.execute("INSERT INTO legal_hold(name, reason) VALUES('conservation-a', 'enquete')", []).unwrap();
            c.execute("INSERT INTO legal_hold(name, reason) VALUES('conservation-b', 'enquete')", []).unwrap();
            c.execute("DELETE FROM legal_hold WHERE name='conservation-b'", []).unwrap();
            c.execute_batch(
                "CREATE VIEW vue_des_refus AS SELECT id, host, message FROM event WHERE severity >= 3;
                 CREATE TRIGGER vue_des_refus_sans_ecriture INSTEAD OF DELETE ON vue_des_refus BEGIN SELECT 1; END;",
            ).unwrap();
        }
        let src_c = open_db_keyed(&src, Some(CLE)).unwrap();
        let compte = |filtre: &str| -> i64 {
            src_c.query_row(&format!("SELECT count(*) FROM sqlite_master WHERE {filtre}"), [], |r| r.get(0)).unwrap()
        };
        assert_eq!(compte("name IN ('sqlite_stat1','sqlite_stat4','sqlite_sequence')"), 3, "contrôle : les trois tables du moteur");
        assert_eq!(compte("name = 'event_fields_fts' AND sql LIKE '%content=''''%'"), 1, "contrôle : FTS5 sans contenu");
        assert!(compte("type='trigger' AND sql LIKE '%json_each%'") >= 2, "contrôle : déclencheurs du filtre de champs");
        assert_eq!(compte("type='index' AND sql LIKE '%json_extract%'"), crate::soql_glue::HOT_FIELDS.len() as i64, "contrôle : index de champ chaud");
        assert_eq!(compte("type='trigger' AND sql LIKE '%INSTEAD OF%'"), 1, "contrôle : déclencheur INSTEAD OF sur la vue");

        let archive = chemin(&racine, "archive.age");
        backup_compressed(&src, &archive, Some(CLE), None).expect("sauvegarde");
        assert!(backup_payload_head(&archive, CLE).starts_with(b"SQLite format 3\0"), "la fixture doit emprunter le format ancien");
        let dst = restauree_comme_la_source("cd1-tete", &racine, &archive, &src_c);
        let fts = "SELECT rowid FROM event_fts WHERE event_fts MATCH 'alice'";
        assert_eq!(lignes_de(&dst, fts).len(), 40, "event_fts répond");
        let champs = "SELECT rowid FROM event_fields_fts WHERE event_fields_fts MATCH 'bob1'";
        assert!(!lignes_de(&src_c, champs).is_empty(), "contrôle : le filtre de champs indexe la source");
        assert_eq!(lignes_de(&dst, champs), lignes_de(&src_c, champs), "event_fields_fts répond comme la source");
    }

    /// LA MESURE QUI CHOISIT LE MÉCANISME : un autoriseur posé sur la connexion qui joue `sqlcipher_export` voit les
    /// créations de tables et d'index du fichier, mais jamais celles de ses vues, déclencheurs et tables virtuelles,
    /// recopiés par une écriture brute de `sqlite_master` ; d'où le jugement du schéma AVANT l'export, sur un brouillon.
    #[test]
    fn l_export_ne_montre_ni_vue_ni_declencheur_ni_table_virtuelle_a_un_autoriseur() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cd1-mesure-export");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "clair.db");
        let c = open_db_keyed(&src, None).unwrap();
        c.execute_batch(
            "CREATE TABLE t(v TEXT); INSERT INTO t VALUES('a'); CREATE INDEX i ON t(v); CREATE VIEW w AS SELECT v FROM t;
             CREATE TRIGGER g AFTER INSERT ON t BEGIN SELECT 1; END; CREATE VIRTUAL TABLE f USING fts5(v, content='t');",
        ).unwrap();
        let vues = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let pour_l_autoriseur = vues.clone();
        c.authorizer(Some(move |ctx: rusqlite::hooks::AuthContext<'_>| {
            use rusqlite::hooks::AuthAction as A;
            let nom = match ctx.action {
                A::CreateTable { .. } => "table",
                A::CreateIndex { .. } => "index",
                A::CreateView { .. } => "vue",
                A::CreateTrigger { .. } => "declencheur",
                A::CreateVtable { .. } => "table virtuelle",
                _ => "",
            };
            if !nom.is_empty() {
                pour_l_autoriseur.lock().unwrap().push(nom.to_string());
            }
            rusqlite::hooks::Authorization::Allow
        }));
        let dest = chemin(&racine, "dest.db");
        c.execute_batch(&format!("ATTACH DATABASE '{dest}' AS enc KEY 'k'; SELECT sqlcipher_export('enc'); DETACH DATABASE enc;")).unwrap();
        let vues = vues.lock().unwrap().clone();
        assert!(vues.iter().any(|v| v == "table") && vues.iter().any(|v| v == "index"), "contrôle : tables et index vus : {vues:?}");
        for classe in ["vue", "declencheur", "table virtuelle"] {
            assert!(!vues.iter().any(|v| v == classe), "{classe} vue par l'autoriseur de l'export : {vues:?}");
        }
        let d = open_db_keyed(&dest, Some("k")).unwrap();
        assert_eq!(d.query_row("SELECT count(*) FROM sqlite_master WHERE name IN ('w','g','f')", [], |r| r.get::<_, i64>(0)).unwrap(), 3,
            "les trois objets sont pourtant recopiés");
    }

    // ── FORMAT COURANT : REFUS DU MOTEUR, PHASE PAR PHASE ───────────────────────────────────────────

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

    /// Un dump B1 forgé (format de `dump_stream`) : tables, UNE table de données `t` (insertion, lignes TEXT d'une
    /// valeur), compteurs, post-DDL.
    struct Dump {
        tables: Vec<&'static str>,
        insertion: &'static str,
        lignes: Vec<&'static str>,
        compteurs: Vec<(&'static str, i64)>,
        post: Vec<Post>,
    }

    impl Dump {
        fn conforme() -> Dump {
            Dump { tables: vec!["CREATE TABLE t(v TEXT)"], insertion: "INSERT INTO t (v) VALUES (?)", lignes: vec!["restauree"], compteurs: vec![], post: vec![] }
        }

        fn octets(&self) -> Vec<u8> {
            let mut v = b"PLUMEDUMP1\n".to_vec();
            ecrire_u32(&mut v, self.tables.len() as u32);
            for sql in &self.tables {
                ecrire_str(&mut v, sql);
            }
            ecrire_u32(&mut v, 1);
            ecrire_str(&mut v, "t");
            v.extend_from_slice(&1u16.to_le_bytes());
            ecrire_str(&mut v, self.insertion);
            for valeur in &self.lignes {
                v.push(1);
                v.push(3);
                ecrire_str(&mut v, valeur);
            }
            v.push(0);
            ecrire_u32(&mut v, self.compteurs.len() as u32);
            for (nom, seq) in &self.compteurs {
                ecrire_str(&mut v, nom);
                v.extend_from_slice(&seq.to_le_bytes());
            }
            ecrire_u32(&mut v, self.post.len() as u32);
            for p in &self.post {
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
    }

    fn moteur(phase: &'static str, code: i32) -> impl Fn(&str) -> String {
        move |dest| format!("restore : phase {phase} : refusée par le moteur (code {code}){}", suffixe_intacte(dest))
    }

    /// Le dump forgé de base est admis : chaque refus ci-dessous vient de la ligne qui le modifie.
    #[test]
    fn courant_le_dump_forge_de_base_est_admis() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cd1-b-conforme");
        let racine = _tmp.racine().chemin().to_path_buf();
        archive_de(&Dump::conforme().octets(), &chemin(&racine, "archive.age"));
        let dest = chemin(&racine, "plume.db");
        restore_compressed(&chemin(&racine, "archive.age"), &dest, Some(CLE), false, None).expect("dump conforme");
        let c = open_db_keyed(&dest, Some(CLE)).unwrap();
        assert_eq!(lignes_de(&c, "SELECT v FROM t"), vec!["Text(\"restauree\")".to_string()]);
    }

    /// Insertion, PRÉPARATION : une colonne que la table n'a pas (la tête est comptée avant que le moteur ne refuse).
    #[test]
    fn courant_insertion_refusee_a_la_preparation_rend_son_code() {
        let mut d = Dump::conforme();
        d.insertion = "INSERT INTO t (absente) VALUES (?)";
        refusee("cd1-b-i-prep", &d.octets(), moteur("insertion", 1));
    }

    /// Insertion, EXÉCUTION : une valeur de l'archive viole l'unicité que porte la table (le texte du moteur nommait
    /// `t.v`) : code étendu 2067.
    #[test]
    fn courant_insertion_refusee_a_l_execution_rend_son_code() {
        let mut d = Dump::conforme();
        d.tables = vec!["CREATE TABLE t(v TEXT UNIQUE)"];
        d.lignes = vec!["double", "double"];
        refusee("cd1-b-i-exec", &d.octets(), moteur("insertion", 2067));
    }

    /// Insertion, EXÉCUTION SANS CODE : `RETURNING` (admis par l'autoriseur) fait rendre une ligne, que la bibliothèque
    /// refuse elle-même ; aucun code SQLite n'est inventé.
    #[test]
    fn courant_insertion_refusee_hors_du_moteur_le_dit_sans_code() {
        let mut d = Dump::conforme();
        d.insertion = "INSERT INTO t (v) VALUES (?) RETURNING 1";
        refusee("cd1-b-i-sans-code", &d.octets(), |dest| {
            format!("restore : phase insertion : refusée sans code d'erreur SQLite{}", suffixe_intacte(dest))
        });
    }

    /// Compteurs : l'archive annonce un compteur sans avoir créé de table AUTOINCREMENT (pas de `sqlite_sequence`).
    #[test]
    fn courant_compteurs_refuses_par_le_moteur_rendent_leur_code() {
        let mut d = Dump::conforme();
        d.compteurs = vec![("t", 5)];
        refusee("cd1-b-compteurs", &d.octets(), moteur("compteurs", 1));
    }

    /// Post-DDL, PRÉPARATION : une vue du nom d'une table déjà créée (la tête est comptée avant le refus du moteur).
    #[test]
    fn courant_post_ddl_refuse_a_la_preparation_rend_son_code() {
        let mut d = Dump::conforme();
        d.post = vec![Post::Sql("CREATE VIEW t AS SELECT 1")];
        refusee("cd1-b-p-prep", &d.octets(), moteur("post-DDL", 1));
    }

    /// Post-DDL, EXÉCUTION : un index unique sur des lignes en double (le texte du moteur nommait `t.v`).
    #[test]
    fn courant_post_ddl_refuse_a_l_execution_rend_son_code() {
        let mut d = Dump::conforme();
        d.lignes = vec!["double", "double"];
        d.post = vec![Post::Sql("CREATE UNIQUE INDEX u ON t(v)")];
        refusee("cd1-b-p-exec", &d.octets(), moteur("post-DDL", 2067));
    }

    /// Post-DDL, REFUS DE L'AUTORISEUR PENDANT L'EXÉCUTION : une FTS4 sur la table de contenu `t` sans colonne déclarée
    /// relit `t` à sa création, lecture que la liste n'admet pas ; l'exécution échoue (code 23 côté moteur) et le refus
    /// rendu est le refus nommé, pas celui du moteur.
    #[test]
    fn courant_post_ddl_refuse_par_l_autoriseur_a_l_execution_rend_le_refus_nomme() {
        let mut d = Dump::conforme();
        d.post = vec![Post::Sql("CREATE VIRTUAL TABLE f USING fts4(content='t')")];
        refusee("cd1-b-p-autoriseur", &d.octets(), |dest| {
            format!(
                "restore : phase post-DDL : instruction hors liste (classe d'instruction hors de la liste de la phase){}",
                suffixe_intacte(dest)
            )
        });
    }

    /// Reconstruction FTS : une FTS5 sans contenu ne se reconstruit pas ; le module refuse.
    #[test]
    fn courant_reconstruction_refusee_par_le_moteur_rend_son_code() {
        let mut d = Dump::conforme();
        d.post = vec![Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content='')"), Post::Reconstruire("f")];
        refusee("cd1-b-reconstruction", &d.octets(), moteur("reconstruction FTS", 1));
    }

    /// Validation : un module FTS4 vide au `COMMIT` les termes de sa reconstruction dans `f_segdir`, où un index (admis :
    /// `json_extract`, sur la table fantôme) lit la racine binaire du segment comme du JSON ; le moteur refuse l'écriture,
    /// donc le `COMMIT`.
    #[test]
    fn courant_validation_refusee_par_le_moteur_rend_son_code() {
        let mut d = Dump::conforme();
        d.post = vec![
            Post::Sql("CREATE VIRTUAL TABLE f USING fts4(v, content='t')"),
            Post::Sql("CREATE INDEX j ON f_segdir(json_extract(root, '$.a'))"),
            Post::Reconstruire("f"),
        ];
        refusee("cd1-b-validation", &d.octets(), moteur("validation", 1));
    }
}
