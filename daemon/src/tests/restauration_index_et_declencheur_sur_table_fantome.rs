// =====================================================================================
// RESTAURATION : AUCUN INDEX NI AUCUN DÉCLENCHEUR SUR UNE TABLE FANTÔME, DANS LES DEUX FORMATS
// (`backup/restauration_liste_fermee.rs` : `admettre`, `ListeFermee::preparer_une_chaine_de_l_archive`,
// `juger_le_schema_du_format_ancien` ; `backup/dump_restauration.rs` : `restore_stream`, `restore_compressed`).
//
// LE DÉFAUT, LU SUR 79268e80 : une table fantôme du fichier (`<vt>_<suffixe>`) devait déjà être exactement celle que
// le module crée, nom et texte ; mais une instruction de l'archive qui crée un INDEX ou un DÉCLENCHEUR dont la cible
// est une table fantôme était admise, au format ancien (jugée sous la phase post-DDL sur le brouillon) comme dans la
// section post-DDL du format courant, et la base était publiée. Le module écrit lui-même dans ses tables fantômes, sur
// la connexion du démon et sans autoriseur, à chaque écriture dans la table virtuelle : un index `UNIQUE` y borne ou
// refuse ces écritures, un déclencheur y fait jouer son corps (la mesure ci-dessous le montre sans restauration).
//
// DÉSORMAIS : l'autoriseur refuse, sous la phase post-DDL, la création d'un index (hors index automatique d'une
// contrainte, que seul le moteur nomme) ou d'un déclencheur dont la CIBLE, telle que le moteur la passe à l'autoriseur,
// est une table fantôme d'une table virtuelle créée par cette restauration ; le refus nomme sa cause
// (`index ou déclencheur posé sur une table fantôme`), avant toute publication, destination absente ou intacte à
// l'octet. Le format ancien emprunte le même autoriseur sur son brouillon, son refus nomme « format ancien ».
//
// PLANCHER NOMMÉ (un témoin par suffixe n'est pas demandé) : les tables fantômes que FTS5 et FTS4 à contenu externe
// créent, relevées sur le moteur et comparées à leur liste nommée (`f_config`, `f_data`, `f_docsize`, `f_idx` ;
// `f4_docsize`, `f4_segdir`, `f4_segments`, `f4_stat`) ; un index et un déclencheur sur CHACUNE, dans chaque format.
//
// LA CIBLE EST CELLE QUE LE MOTEUR CONNAÎT : une autre casse, un nom qualifié par sa base ou entre guillemets dans le
// texte de l'archive désignent la même table fantôme et sont refusés de même, dans les deux formats.
//
// AUCUN OBJET DE L'ARCHIVE NE PREND LE NOM D'UNE TABLE FANTÔME (`<vt>_<suffixe>`), QUEL QUE SOIT SON GENRE : table,
// vue, index nommé, table virtuelle. Casse ASCII ignorée des deux côtés, comme le moteur résout les noms. Créé AVANT la
// table virtuelle, l'objet fait refuser la création de celle-ci : FTS4 crée `<vt>_stat` par `CREATE TABLE IF NOT EXISTS`
// et adoptait une table, une vue ou une table virtuelle déjà là, avec ce qui y était posé (la mesure d'une vue adoptée
// le montre sans restauration). Créé APRÈS, il est refusé à sa propre création. Dans les deux cas par la liste, sous la
// cause `objet au nom d'une table fantôme d'une table virtuelle`, avant toute publication. Deux cas sont arrêtés par le
// MOTEUR, qui cherche le nom avant de montrer la création à l'autoriseur : un index ou une table virtuelle créés après
// la table virtuelle sous le nom d'une table fantôme qu'elle a créée (refus hors classe, chaîne sans tête), témoignés
// pour FTS5, FTS4 et FTS3 dans les deux formats (au format courant, le refus du moteur seul en contrôle). Au format
// ancien, une table au nom exact d'une table fantôme est une table fantôme du fichier, comparée à celles que le module
// crée (`tables fantômes autres que celles que le module crée`). Un déclencheur NOMMÉ comme une table fantôme ne prend pas ce
// nom (les déclencheurs ont leur propre espace de noms) et n'est pas refusé par ces règles sur une table ordinaire, dans
// les deux ordres et les deux formats. L'écrivain rejoue comme table ordinaire une table adoptée dont le nom ne diffère de celui d'une table
// fantôme que par la casse : la restauration de son archive est refusée.
//
// LE CORPS des déclencheurs et des vues est jugé par une autre règle (`restauration_corps_des_declencheurs_et_des_vues.rs` :
// seuls ceux que le démon crée sont admis). Les contrôles d'ici qui restaurent un déclencheur de fixture sur une table
// ordinaire lèvent ce seul jugement (`crochets_de_restauration::sans_jugement_des_declencheurs_et_des_vues`).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les LIGNES des tables fantômes du format ancien (données recopiées par l'export,
// non jugées).
// =====================================================================================

mod cj8_restauration_index_et_declencheur_sur_table_fantome {
    use super::*;
    use crate::backup::SUFFIXE_RESTAURATION_EN_COURS;

    const CLE: &str = "cj8-cle-de-test-de-restauration";

    // Les phrases attendues, écrites ici en toutes lettres (jamais relues de la production).
    const SUR_UNE_FANTOME: &str = "index ou déclencheur posé sur une table fantôme";
    const CLASSE: &str = "classe d'instruction hors de la liste de la phase";

    const TABLE: &str = "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)";
    const FTS5: &str = "CREATE VIRTUAL TABLE f USING fts5(v, content='t', content_rowid='id')";
    const FTS4: &str = "CREATE VIRTUAL TABLE f4 USING fts4(v, content='t')";

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
            let err = restore_compressed(&chemin(&racine, "archive.age"), &dest, Some(CLE), false, None)
                .expect_err(&format!("{cas} : l'archive a été restaurée et publiée"));
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
        let err = restore_compressed(&chemin(&racine, "archive.age"), &dest, Some(CLE), true, None)
            .expect_err(&format!("{cas} : l'archive a été restaurée et publiée par-dessus la destination"));
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

    // ── LE PLANCHER : LES TABLES FANTÔMES QUE LE MODULE CRÉE ───────────────────────────────────────────

    /// Les tables fantômes que crée `creation` (une table virtuelle `vt` à contenu externe sur `t`), relevées sur le
    /// moteur, avec la première colonne de chacune : (nom, colonne), par nom.
    fn tables_fantomes_creees_par(creation: &str, vt: &str) -> Vec<(String, String)> {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(&format!("{TABLE}; {creation};")).unwrap();
        let noms: Vec<String> = {
            let mut s = c.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name GLOB ?1 ORDER BY name").unwrap();
            s.query_map([format!("{vt}_*")], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect()
        };
        noms.into_iter()
            .map(|nom| {
                let colonne: String = c.query_row("SELECT name FROM pragma_table_info(?1) ORDER BY cid LIMIT 1", [&nom], |r| r.get(0)).unwrap();
                (nom, colonne)
            })
            .collect()
    }

    /// Les cas du plancher : pour FTS5 et FTS4, chaque table fantôme que le module crée, comparée d'abord à sa liste
    /// NOMMÉE ; rend (création, nom de la table virtuelle, table fantôme, sa première colonne).
    fn plancher() -> Vec<(&'static str, &'static str, String, String)> {
        let mut cas = Vec::new();
        for (creation, vt, nommees) in [
            (FTS5, "f", ["f_config", "f_data", "f_docsize", "f_idx"]),
            (FTS4, "f4", ["f4_docsize", "f4_segdir", "f4_segments", "f4_stat"]),
        ] {
            let relevees = tables_fantomes_creees_par(creation, vt);
            let noms: Vec<&str> = relevees.iter().map(|(n, _)| n.as_str()).collect();
            assert_eq!(noms, nommees, "plancher : les tables fantômes que crée {vt}, relevées sur le moteur");
            cas.extend(relevees.into_iter().map(|(n, col)| (creation, vt, n, col)));
        }
        cas
    }

    fn index_sur(table: &str, colonne: &str) -> String {
        format!("CREATE INDEX cj8_index ON \"{table}\"(\"{colonne}\")")
    }

    fn declencheur_sur(table: &str) -> String {
        format!("CREATE TRIGGER cj8_declencheur AFTER INSERT ON \"{table}\" BEGIN SELECT 1; END")
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
        Sql(String),
        Reconstruire(&'static str),
    }

    fn sql(s: &str) -> Post {
        Post::Sql(s.to_string())
    }

    /// Un dump B1 forgé au format de `dump_stream` : la table `t` (colonnes `id`, `v`) et sa ligne (1, 'restauree') au
    /// texte d'insertion de l'écrivain, aucun compteur, puis `post`.
    fn dump(post: &[Post]) -> Vec<u8> {
        dump_avec(&[], post)
    }

    /// Le même dump, la section 1 portant en plus les tables `en_plus` (sans ligne), après `t`.
    fn dump_avec(en_plus: &[&str], post: &[Post]) -> Vec<u8> {
        let mut v = b"PLUMEDUMP1\n".to_vec();
        ecrire_u32(&mut v, 1 + en_plus.len() as u32);
        ecrire_str(&mut v, TABLE);
        for creation in en_plus {
            ecrire_str(&mut v, creation);
        }
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
        ecrire_u32(&mut v, 0);
        ecrire_u32(&mut v, post.len() as u32);
        for p in post {
            match p {
                Post::Sql(s) => {
                    v.push(1);
                    ecrire_str(&mut v, s);
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

    /// Dans l'ordre de l'écrivain : la table virtuelle, sa reconstruction, puis l'instruction `objet`.
    fn courant_apres(creation: &str, vt: &'static str, objet: &str) -> Vec<u8> {
        dump(&[sql(creation), Post::Reconstruire(vt), sql(objet)])
    }

    /// LA MESURE DU CONSTAT, FORMAT COURANT : un index `UNIQUE` puis un déclencheur posés sur `f_data`, à la place de
    /// l'écrivain (après la table virtuelle et sa reconstruction). Ils étaient admis et la base publiée.
    #[test]
    fn courant_un_index_unique_ou_un_declencheur_sur_une_table_fantome_est_refuse() {
        refusee(
            "cj8-c-index-unique",
            &courant_apres(FTS5, "f", "CREATE UNIQUE INDEX f_borne ON f_data(block)"),
            hors_liste("post-DDL", SUR_UNE_FANTOME),
        );
        refusee(
            "cj8-c-declencheur",
            &courant_apres(FTS5, "f", "CREATE TRIGGER f_ecrit AFTER INSERT ON f_data BEGIN DELETE FROM t; END"),
            hors_liste("post-DDL", SUR_UNE_FANTOME),
        );
    }

    /// LE PLANCHER, FORMAT COURANT : un index puis un déclencheur sur chaque table fantôme que FTS5 et FTS4 créent.
    #[test]
    fn courant_un_index_ou_un_declencheur_sur_chaque_table_fantome_est_refuse() {
        for (creation, vt, table, colonne) in plancher() {
            refusee(&format!("cj8-c-index-{table}"), &courant_apres(creation, vt, &index_sur(&table, &colonne)), hors_liste("post-DDL", SUR_UNE_FANTOME));
            refusee(&format!("cj8-c-declencheur-{table}"), &courant_apres(creation, vt, &declencheur_sur(&table)), hors_liste("post-DDL", SUR_UNE_FANTOME));
        }
    }

    /// LES GARDES QU'UN TEL OBJET ÉTAIT SEUL À ATTEINDRE : les dumps des trois témoins devenus une défense en profondeur
    /// (`restauration_liste_fermee_des_instructions.rs`, `un_declencheur_ne_joue_jamais_pendant_la_restauration` et
    /// `le_commit_refuse_par_la_liste_laisse_la_destination_intacte` ; `restauration_format_ancien_liste_fermee.rs`,
    /// `courant_validation_refusee_par_le_moteur_rend_son_code`) sont, sans le crochet qui lève la règle, refusés dès la
    /// création de leur déclencheur ou de leur index, avant la reconstruction et avant le `COMMIT`.
    #[test]
    fn sans_le_crochet_les_chemins_des_gardes_profondes_sont_refuses_a_la_creation() {
        let cas = [
            ("cj8-c-profonde-declencheur", FTS5, "f", "CREATE TRIGGER g AFTER INSERT ON f_data BEGIN SELECT 1; END"),
            ("cj8-c-profonde-commit", FTS4, "f4", "CREATE TRIGGER g AFTER INSERT ON f4_segdir BEGIN SELECT 1; END"),
            ("cj8-c-profonde-moteur", FTS4, "f4", "CREATE INDEX j ON f4_segdir(json_extract(root, '$.a'))"),
        ];
        for (nom, creation, vt, objet) in cas {
            refusee(nom, &dump(&[sql(creation), sql(objet), Post::Reconstruire(vt)]), hors_liste("post-DDL", SUR_UNE_FANTOME));
        }
    }

    /// LE CONTRÔLE, FORMAT COURANT : à côté des mêmes tables virtuelles, un index `UNIQUE` et un déclencheur sur la table
    /// ordinaire `t` (le déclencheur porte même le nom d'une table fantôme) se restaurent ; chaque table virtuelle répond.
    #[test]
    fn courant_un_index_et_un_declencheur_sur_une_table_ordinaire_se_restaurent() {
        // Le corps de ce déclencheur n'est pas celui d'un déclencheur que le démon crée : refusé par ailleurs (P10.34-t,
        // `restauration_corps_des_declencheurs_et_des_vues.rs`). Ce témoin d'une autre règle lève ce seul jugement.
        let _corps = crate::backup::crochets_de_restauration::sans_jugement_des_declencheurs_et_des_vues();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cj8-c-controle");
        let racine = _tmp.racine().chemin().to_path_buf();
        let charge = dump(&[
            sql(FTS5),
            sql(FTS4),
            Post::Reconstruire("f"),
            Post::Reconstruire("f4"),
            sql("CREATE UNIQUE INDEX t_v ON t(v)"),
            sql("CREATE TRIGGER f_data AFTER INSERT ON t BEGIN SELECT 1; END"),
        ]);
        let c = admise("cj8-c-controle", &racine, &charge);
        assert_eq!(
            lignes_de(&c, "SELECT type, name, tbl_name FROM sqlite_master WHERE type IN ('index', 'trigger') AND sql IS NOT NULL"),
            vec!["Text(\"index\")|Text(\"t_v\")|Text(\"t\")".to_string(), "Text(\"trigger\")|Text(\"f_data\")|Text(\"t\")".to_string()],
        );
        assert_eq!(lignes_de(&c, "SELECT rowid FROM f WHERE f MATCH 'restauree'"), vec!["Integer(1)".to_string()], "f répond");
        assert_eq!(lignes_de(&c, "SELECT rowid FROM f4 WHERE f4 MATCH 'restauree'"), vec!["Integer(1)".to_string()], "f4 répond");
    }

    /// UNE VUE AU NOM D'UNE TABLE FANTÔME ATTENDUE, FORMAT COURANT, refusée par la liste sous la cause nommée dans les
    /// deux ordres : dans l'ordre de l'écrivain (vues en dernier), à sa création, l'autoriseur en voyant le nom avant que
    /// le moteur ne le cherche ; posée AVANT la table virtuelle, à la création de celle-ci. Le moteur, lui, refusait les
    /// deux sous son code (le nom pris, puis le module qui ne peut plus créer `f_data`).
    #[test]
    fn courant_une_vue_au_nom_d_une_table_fantome_est_refusee_dans_les_deux_ordres() {
        let vue = "CREATE VIEW f_data AS SELECT v FROM t";
        refusee("cj8-c-vue-apres", &courant_apres(FTS5, "f", vue), hors_liste("post-DDL", NOMMEE));
        refusee("cj8-c-vue-avant", &dump(&[sql(vue), sql(FTS5), Post::Reconstruire("f")]), hors_liste("post-DDL", NOMMEE));
    }

    /// UN INDEX AU NOM D'UNE TABLE FANTÔME ATTENDUE, FORMAT COURANT (sa cible est la table ordinaire `t`). Après la table
    /// virtuelle, le moteur arrête la préparation sur le nom pris avant de montrer la création à l'autoriseur, et la
    /// chaîne, sans tête, est refusée hors classe ; avant elle, la liste refuse la création de la table virtuelle sous la
    /// cause nommée.
    #[test]
    fn courant_un_index_au_nom_d_une_table_fantome_est_refuse_dans_les_deux_ordres() {
        let index = "CREATE INDEX f_data ON t(v)";
        refusee("cj8-c-index-nomme-apres", &courant_apres(FTS5, "f", index), hors_liste("post-DDL", CLASSE));
        refusee("cj8-c-index-nomme-avant", &dump(&[sql(index), sql(FTS5), Post::Reconstruire("f")]), hors_liste("post-DDL", NOMMEE));
    }

    /// Une autre écriture de la cible, que le moteur résout vers la même table fantôme : casse, base nommée, guillemets.
    const CIBLES_ECRITES_AUTREMENT: [&str; 2] = [
        "CREATE INDEX main.cj8_index ON F_DATA(block)",
        "CREATE TRIGGER cj8_declencheur AFTER INSERT ON \"F_Data\" BEGIN SELECT 1; END",
    ];

    /// LA CIBLE TELLE QUE LE MOTEUR LA CONNAÎT, FORMAT COURANT : chaque écriture de `CIBLES_ECRITES_AUTREMENT` est refusée
    /// sous la cause des tables fantômes.
    #[test]
    fn courant_la_cible_ecrite_autrement_est_refusee() {
        for (i, objet) in CIBLES_ECRITES_AUTREMENT.iter().enumerate() {
            refusee(&format!("cj8-c-cible-ecrite-{i}"), &courant_apres(FTS5, "f", objet), hors_liste("post-DDL", SUR_UNE_FANTOME));
        }
    }

    // ── UNE TABLE ORDINAIRE AU NOM D'UNE TABLE FANTÔME, CRÉÉE AVANT LA TABLE VIRTUELLE ─────────────────

    const NOMMEE: &str = "objet au nom d'une table fantôme d'une table virtuelle";

    /// `f4_stat`, au texte que FTS4 lui donne quand il la crée (`CREATE TABLE IF NOT EXISTS`), en table ordinaire.
    const STAT_ORDINAIRE: &str = "CREATE TABLE f4_stat(id INTEGER PRIMARY KEY, value BLOB)";

    /// LE CONTOURNEMENT PAR L'ORDRE, FORMAT COURANT : `f4_stat` créée en section 1 comme table ordinaire, un déclencheur
    /// posé dessus AVANT la création de `f4` (aucune table virtuelle n'existe encore : la cible n'est pas une table
    /// fantôme), puis `f4`, dont le module adopte la table avec son déclencheur. Sans reconstruction, rien ne fait jouer le
    /// déclencheur pendant la restauration : la base était publiée. La création de `f4` est refusée sous sa cause.
    #[test]
    fn courant_un_declencheur_pose_avant_la_table_virtuelle_sur_sa_future_table_fantome_est_refuse() {
        let charge = dump_avec(&[STAT_ORDINAIRE], &[sql("CREATE TRIGGER g AFTER INSERT ON f4_stat BEGIN DELETE FROM t; END"), sql(FTS4)]);
        refusee("cj8-c-adoptee-declencheur", &charge, hors_liste("post-DDL", NOMMEE));
    }

    /// Le même ordre avec un index `UNIQUE`, et la reconstruction : la base était publiée avec l'index sur `f4_stat`.
    #[test]
    fn courant_un_index_pose_avant_la_table_virtuelle_sur_sa_future_table_fantome_est_refuse() {
        let charge = dump_avec(&[STAT_ORDINAIRE], &[sql("CREATE UNIQUE INDEX u ON f4_stat(value)"), sql(FTS4), Post::Reconstruire("f4")]);
        refusee("cj8-c-adoptee-index", &charge, hors_liste("post-DDL", NOMMEE));
    }

    /// La table seule, sans objet posé dessus : adoptée, elle porterait les lignes de l'archive dans les statistiques du
    /// module.
    #[test]
    fn courant_une_table_ordinaire_au_nom_d_une_table_fantome_seule_est_refusee() {
        let charge = dump_avec(&[STAT_ORDINAIRE], &[sql(FTS4), Post::Reconstruire("f4")]);
        refusee("cj8-c-adoptee-seule", &charge, hors_liste("post-DDL", NOMMEE));
    }

    /// Une autre casse, déclencheur APRÈS la table virtuelle : le moteur passe à l'autoriseur le nom de la table adoptée,
    /// `F4_Stat`, qui n'est pas au texte d'une table fantôme ; sans reconstruction (dont l'écriture du module dans
    /// `F4_Stat` était refusée), la base était publiée. La règle compare les noms sans la casse ASCII, comme le moteur.
    #[test]
    fn courant_une_table_ordinaire_au_nom_d_une_table_fantome_dans_une_autre_casse_est_refusee() {
        let charge = dump_avec(
            &["CREATE TABLE F4_Stat(id INTEGER PRIMARY KEY, value BLOB)"],
            &[sql(FTS4), sql("CREATE TRIGGER g AFTER INSERT ON F4_Stat BEGIN DELETE FROM t; END")],
        );
        refusee("cj8-c-adoptee-casse", &charge, hors_liste("post-DDL", NOMMEE));
    }

    /// FTS5 crée ses tables fantômes sans `IF NOT EXISTS` : le moteur refusait déjà la création ; la règle la refuse
    /// avant lui, sous sa cause.
    #[test]
    fn courant_une_table_ordinaire_au_nom_d_une_table_fantome_fts5_est_refusee() {
        let charge = dump_avec(&["CREATE TABLE f_config(k PRIMARY KEY, v) WITHOUT ROWID"], &[sql(FTS5), Post::Reconstruire("f")]);
        refusee("cj8-c-adoptee-fts5", &charge, hors_liste("post-DDL", NOMMEE));
    }

    /// LE CONTRÔLE : des tables ordinaires dont le nom n'est pas celui d'une table fantôme de `f4` (`f4_autre`, suffixe
    /// que l'écrivain ne tient pas pour fantôme ; `t_stat`, table fantôme d'une table virtuelle qui n'existe pas), avec un
    /// déclencheur, se restaurent à côté de `f4`, qui répond.
    #[test]
    fn courant_une_table_ordinaire_au_nom_voisin_se_restaure_a_cote_de_la_table_virtuelle() {
        // Le corps de ce déclencheur n'est pas celui d'un déclencheur que le démon crée : refusé par ailleurs (P10.34-t,
        // `restauration_corps_des_declencheurs_et_des_vues.rs`). Ce témoin d'une autre règle lève ce seul jugement.
        let _corps = crate::backup::crochets_de_restauration::sans_jugement_des_declencheurs_et_des_vues();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cj8-c-voisine");
        let racine = _tmp.racine().chemin().to_path_buf();
        let charge = dump_avec(
            &["CREATE TABLE f4_autre(id INTEGER PRIMARY KEY, value BLOB)", "CREATE TABLE t_stat(id INTEGER PRIMARY KEY, value BLOB)"],
            &[sql("CREATE TRIGGER g AFTER INSERT ON t_stat BEGIN SELECT 1; END"), sql(FTS4), Post::Reconstruire("f4")],
        );
        let c = admise("cj8-c-voisine", &racine, &charge);
        assert_eq!(
            lignes_de(&c, "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('f4_autre', 't_stat', 'f4_stat')"),
            vec!["Text(\"f4_autre\")".to_string(), "Text(\"f4_stat\")".to_string(), "Text(\"t_stat\")".to_string()],
        );
        assert_eq!(lignes_de(&c, "SELECT rowid FROM f4 WHERE f4 MATCH 'restauree'"), vec!["Integer(1)".to_string()], "f4 répond");
    }

    /// LE CROCHET QUI LÈVE LA RÈGLE SE DÉSARME EN SORTIE DE PORTÉE : armé, il laisse passer un déclencheur sur `f_config`
    /// (base publiée, déclencheur en place) ; sa garde sortie de portée, le même dump est refusé sur le même fil.
    #[test]
    fn le_crochet_qui_leve_la_regle_se_desarme_en_sortie_de_portee() {
        let charge = courant_apres(FTS5, "f", &declencheur_sur("f_config"));
        {
            let _arme = crate::backup::crochets_de_restauration::sans_refus_sur_les_tables_fantomes();
            let _tmp = crate::tmp_possede::TmpPossede::neuf("cj8-c-crochet-arme");
            let racine = _tmp.racine().chemin().to_path_buf();
            let c = admise("cj8-c-crochet-arme", &racine, &charge);
            assert_eq!(
                lignes_de(&c, "SELECT name, tbl_name FROM sqlite_master WHERE type = 'trigger'"),
                vec!["Text(\"cj8_declencheur\")|Text(\"f_config\")".to_string()],
                "contrôle : le crochet armé lève la règle",
            );
        }
        refusee("cj8-c-crochet-desarme", &charge, hors_liste("post-DDL", SUR_UNE_FANTOME));
    }

    // ── FORMAT ANCIEN ───────────────────────────────────────────────────────────────────────────────

    /// Une base SQLite EN CLAIR portant `t` et sa ligne (1, 'legacy'), puis `ddl` ; rend ses octets (la charge d'une
    /// archive au format ancien). Le fichier est retiré.
    fn clair(racine: &std::path::Path, ddl: &str) -> Vec<u8> {
        let p = chemin(racine, "clair-de-fixture.db");
        {
            let c = open_db_keyed(&p, None).unwrap();
            c.execute_batch(&format!("{TABLE}; INSERT INTO t VALUES(1, 'legacy');")).unwrap();
            c.execute_batch(ddl).unwrap();
        }
        let octets = std::fs::read(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        octets
    }

    /// Dans l'ordre d'une base vivante : la table virtuelle, sa reconstruction, puis `objet`.
    fn ancien_apres(racine: &std::path::Path, creation: &str, vt: &str, objet: &str) -> Vec<u8> {
        clair(racine, &format!("{creation}; INSERT INTO {vt}({vt}) VALUES('rebuild'); {objet};"))
    }

    /// LA MESURE DU CONSTAT, FORMAT ANCIEN : le même index `UNIQUE` puis le même déclencheur sur `f_data`, dans le
    /// fichier. Jugés sous la phase post-DDL sur le brouillon, ils étaient admis, recopiés par l'export, et la base
    /// publiée.
    #[test]
    fn ancien_un_index_unique_ou_un_declencheur_sur_une_table_fantome_est_refuse() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cj8-a-mesure-fixture");
        let racine = _tmp.racine().chemin().to_path_buf();
        refusee(
            "cj8-a-index-unique",
            &ancien_apres(&racine, FTS5, "f", "CREATE UNIQUE INDEX f_borne ON f_data(block)"),
            hors_liste("format ancien", SUR_UNE_FANTOME),
        );
        refusee(
            "cj8-a-declencheur",
            &ancien_apres(&racine, FTS5, "f", "CREATE TRIGGER f_ecrit AFTER INSERT ON f_data BEGIN DELETE FROM t; END"),
            hors_liste("format ancien", SUR_UNE_FANTOME),
        );
    }

    /// LE PLANCHER, FORMAT ANCIEN : un index puis un déclencheur sur chaque table fantôme que FTS5 et FTS4 créent.
    #[test]
    fn ancien_un_index_ou_un_declencheur_sur_chaque_table_fantome_est_refuse() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cj8-a-plancher-fixture");
        let racine = _tmp.racine().chemin().to_path_buf();
        for (creation, vt, table, colonne) in plancher() {
            refusee(
                &format!("cj8-a-index-{table}"),
                &ancien_apres(&racine, creation, vt, &index_sur(&table, &colonne)),
                hors_liste("format ancien", SUR_UNE_FANTOME),
            );
            refusee(
                &format!("cj8-a-declencheur-{table}"),
                &ancien_apres(&racine, creation, vt, &declencheur_sur(&table)),
                hors_liste("format ancien", SUR_UNE_FANTOME),
            );
        }
    }

    /// LA CIBLE TELLE QUE LE MOTEUR LA CONNAÎT, FORMAT ANCIEN : le fichier garde le texte écrit autrement, le brouillon le
    /// résout vers la table fantôme.
    #[test]
    fn ancien_la_cible_ecrite_autrement_est_refusee() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cj8-a-cible-fixture");
        let racine = _tmp.racine().chemin().to_path_buf();
        for (i, objet) in CIBLES_ECRITES_AUTREMENT.iter().enumerate() {
            refusee(&format!("cj8-a-cible-ecrite-{i}"), &ancien_apres(&racine, FTS5, "f", objet), hors_liste("format ancien", SUR_UNE_FANTOME));
        }
    }

    /// LE CONTRÔLE, FORMAT ANCIEN : les mêmes tables virtuelles avec un index `UNIQUE` et un déclencheur sur la table
    /// ordinaire `t` se restaurent ; la base publiée porte le schéma du fichier à l'identique et chaque table virtuelle
    /// répond.
    #[test]
    fn ancien_un_index_et_un_declencheur_sur_une_table_ordinaire_se_restaurent() {
        // Le corps de ce déclencheur n'est pas celui d'un déclencheur que le démon crée : refusé par ailleurs (P10.34-t,
        // `restauration_corps_des_declencheurs_et_des_vues.rs`). Ce témoin d'une autre règle lève ce seul jugement.
        let _corps = crate::backup::crochets_de_restauration::sans_jugement_des_declencheurs_et_des_vues();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cj8-a-controle");
        let racine = _tmp.racine().chemin().to_path_buf();
        let ddl = format!(
            "{FTS5}; INSERT INTO f(f) VALUES('rebuild'); {FTS4}; INSERT INTO f4(f4) VALUES('rebuild'); \
             CREATE UNIQUE INDEX t_v ON t(v); CREATE TRIGGER f_data AFTER INSERT ON t BEGIN SELECT 1; END;"
        );
        let charge = clair(&racine, &ddl);
        let source = {
            let p = chemin(&racine, "source.db");
            let c = open_db_keyed(&p, None).unwrap();
            c.execute_batch(&format!("{TABLE}; INSERT INTO t VALUES(1, 'legacy'); {ddl}")).unwrap();
            let schema = lignes_de(&c, "SELECT type, name, tbl_name, sql FROM sqlite_master");
            drop(c);
            std::fs::remove_file(&p).unwrap();
            schema
        };
        let c = admise("cj8-a-controle", &racine, &charge);
        assert_eq!(lignes_de(&c, "SELECT type, name, tbl_name, sql FROM sqlite_master"), source, "schéma publié");
        assert_eq!(lignes_de(&c, "SELECT rowid FROM f WHERE f MATCH 'legacy'"), vec!["Integer(1)".to_string()], "f répond");
        assert_eq!(lignes_de(&c, "SELECT rowid FROM f4 WHERE f4 MATCH 'legacy'"), vec!["Integer(1)".to_string()], "f4 répond");
    }

    /// UNE VUE AU NOM D'UNE TABLE FANTÔME ATTENDUE, FORMAT ANCIEN : la ligne de `f_data` réécrite en vue dans le fichier,
    /// après la table virtuelle. Les vues sont créées sur le brouillon avant les tables virtuelles ; la liste refuse la
    /// création de la table virtuelle sous la cause nommée et « format ancien », avant l'export (le moteur la refusait sous
    /// son code, le module ne pouvant plus créer `f_data`).
    #[test]
    fn ancien_une_vue_au_nom_d_une_table_fantome_est_refusee() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cj8-a-vue-fixture");
        let racine = _tmp.racine().chemin().to_path_buf();
        let charge = ancien_apres(
            &racine,
            FTS5,
            "f",
            "PRAGMA writable_schema=ON; \
             UPDATE sqlite_master SET type = 'view', rootpage = 0, sql = 'CREATE VIEW f_data AS SELECT v FROM t' WHERE name = 'f_data'; \
             PRAGMA writable_schema=OFF",
        );
        refusee("cj8-a-vue", &charge, hors_liste("format ancien", NOMMEE));
    }

    /// UNE TABLE ORDINAIRE AU NOM D'UNE TABLE FANTÔME DANS UNE AUTRE CASSE, FORMAT ANCIEN : le fichier porte `F4_STAT`,
    /// que FTS4 a adoptée comme sa table `f4_stat` (contrôle relevé sur le moteur), et un déclencheur dessus. La ligne
    /// n'est pas une table fantôme du fichier au texte exact : elle est rejouée comme table ordinaire, et la création de
    /// `f4` sur le brouillon est refusée sous sa cause, avant l'export.
    #[test]
    fn ancien_une_table_ordinaire_au_nom_d_une_table_fantome_dans_une_autre_casse_est_refusee() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cj8-a-adoptee-fixture");
        let racine = _tmp.racine().chemin().to_path_buf();
        let ddl = format!(
            "CREATE TABLE F4_STAT(id INTEGER PRIMARY KEY, value BLOB); {FTS4}; INSERT INTO f4(f4) VALUES('rebuild'); \
             CREATE TRIGGER g AFTER INSERT ON F4_STAT BEGIN DELETE FROM t; END;"
        );
        let adoptee = {
            let c = rusqlite::Connection::open_in_memory().unwrap();
            c.execute_batch(&format!("{TABLE}; {ddl}")).unwrap();
            lignes_de(&c, "SELECT name FROM sqlite_master WHERE type = 'table' AND lower(name) GLOB 'f4_*'")
        };
        assert_eq!(
            adoptee,
            ["F4_STAT", "f4_docsize", "f4_segdir", "f4_segments"].iter().map(|n| format!("Text({n:?})")).collect::<Vec<_>>(),
            "contrôle : FTS4 adopte F4_STAT et ne crée pas f4_stat",
        );
        refusee("cj8-a-adoptee-casse", &clair(&racine, &ddl), hors_liste("format ancien", NOMMEE));
    }

    // ── LES MESURES ─────────────────────────────────────────────────────────────────────────────────

    /// CE QU'UN DÉCLENCHEUR POSÉ SUR UNE TABLE FANTÔME FAIT JOUER, sans restauration : sur une connexion sans autoriseur
    /// (celle du démon après la restauration), une écriture dans la table virtuelle fait écrire le module dans sa table
    /// fantôme, et le corps du déclencheur joue, ici une écriture dans une autre table de la base. Le moteur embarqué ne
    /// l'interdit qu'en mode défensif (`SQLITE_DBCONFIG_DEFENSIVE`), que le démon ne pose pas.
    #[test]
    fn mesure_un_declencheur_sur_une_table_fantome_joue_quand_le_module_ecrit() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(&format!(
            "{TABLE}; {FTS5}; CREATE TABLE journal(n INTEGER); \
             CREATE TRIGGER f_ecrit AFTER INSERT ON f_data BEGIN INSERT INTO journal VALUES(new.id); END;"
        ))
        .unwrap();
        let avant: i64 = c.query_row("SELECT count(*) FROM journal", [], |r| r.get(0)).unwrap();
        c.execute_batch("INSERT INTO t VALUES(1, 'alpha'); INSERT INTO f(rowid, v) VALUES(1, 'alpha');").unwrap();
        let apres: i64 = c.query_row("SELECT count(*) FROM journal", [], |r| r.get(0)).unwrap();
        assert_eq!(avant, 0, "contrôle : rien avant l'écriture");
        assert!(apres > 0, "l'écriture du module dans f_data fait jouer le déclencheur");
    }

    /// L'ÉCRIVAIN N'ÉMET JAMAIS UNE TELLE LIGNE pour une base du démon : la tête (schéma de base, toutes les migrations,
    /// filtre de champs plein texte en place, index de champ chaud) ne porte aucun index ni déclencheur dont la cible est
    /// une table fantôme de l'une de ses tables virtuelles. Les allers-retours au schéma complet de la tête, dans les deux
    /// formats, restent ceux des témoins existants (`restauration_liste_fermee_des_instructions.rs`,
    /// `restauration_format_ancien_liste_fermee.rs`).
    #[test]
    fn mesure_la_tete_ne_porte_aucun_index_ni_declencheur_sur_une_table_fantome() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cj8-tete");
        let racine = _tmp.racine().chemin().to_path_buf();
        let c = open_db_keyed(&chemin(&racine, "src.db"), Some(CLE)).unwrap();
        c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&c), "fixture : migrations complètes");
        let mut conf = std::collections::HashMap::new();
        conf.insert("PLUME_FTS_FIELDS".to_string(), "1".to_string());
        let cr = crate::maintenance::reconcile_index_state(&c, &conf);
        assert_eq!((cr.lectures_non_faites, cr.ecritures_refusees), (0, 0), "fixture : entretien des index sans échec ({:?})", cr.lignes);
        for champ in crate::soql_glue::HOT_FIELDS {
            c.execute(
                &format!(
                    "CREATE INDEX IF NOT EXISTS idx_ev_f_{champ} ON event(json_extract(fields,'$.{champ}')) \
                     WHERE json_extract(fields,'$.{champ}') IS NOT NULL"
                ),
                [],
            )
            .unwrap();
        }
        let virtuelles = lignes_de(&c, "SELECT name FROM sqlite_master WHERE type = 'table' AND sql LIKE 'CREATE VIRTUAL TABLE%'");
        assert_eq!(virtuelles, vec!["Text(\"event_fields_fts\")".to_string(), "Text(\"event_fts\")".to_string()], "contrôle : tables virtuelles de la tête");
        let fantome = "EXISTS (SELECT 1 FROM sqlite_master v WHERE v.type = 'table' AND v.sql LIKE 'CREATE VIRTUAL TABLE%' AND {col} GLOB v.name || '_*')";
        let fantomes = lignes_de(&c, &format!("SELECT name FROM sqlite_master m WHERE m.type = 'table' AND {}", fantome.replace("{col}", "m.name")));
        assert!(fantomes.len() >= 8, "contrôle : les tables fantômes des deux tables virtuelles sont relues ({fantomes:?})");
        let declencheurs: i64 = c.query_row("SELECT count(*) FROM sqlite_master WHERE type = 'trigger'", [], |r| r.get(0)).unwrap();
        let index: i64 = c.query_row("SELECT count(*) FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL", [], |r| r.get(0)).unwrap();
        assert!(declencheurs >= 2 && index >= crate::soql_glue::HOT_FIELDS.len() as i64, "contrôle : la tête porte des déclencheurs et des index");
        let sur_une_fantome = lignes_de(
            &c,
            &format!("SELECT type, name, tbl_name FROM sqlite_master m WHERE m.type IN ('index', 'trigger') AND m.sql IS NOT NULL AND {}", fantome.replace("{col}", "m.tbl_name")),
        );
        assert!(sur_une_fantome.is_empty(), "un index ou un déclencheur de la tête vise une table fantôme : {sur_une_fantome:?}");
    }

    // =================================================================================================
    // AUCUN OBJET DE L'ARCHIVE NE PREND LE NOM D'UNE TABLE FANTÔME, QUEL QUE SOIT SON GENRE, DANS LES DEUX ORDRES ET
    // LES DEUX FORMATS (`admettre`, `nom_dans_l_espace_des_tables`, `designe_une_table_fantome_de`).
    // =================================================================================================
    mod cj9_objet_au_nom_d_une_table_fantome {
        use super::*;

        const FTS3: &str = "CREATE VIRTUAL TABLE f3 USING fts3(v, content='t')";
        const TABLES_FANTOMES_AUTRES: &str = "tables fantômes autres que celles que le module crée";

        /// Les modules émis : (création, nom de la table virtuelle, une table fantôme que le module CRÉE, un nom
        /// `<vt>_<suffixe>` de l'écrivain que ce module à contenu externe NE crée PAS).
        fn modules() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
            vec![(FTS5, "f", "f_data", "f_content"), (FTS4, "f4", "f4_stat", "f4_content"), (FTS3, "f3", "f3_segments", "f3_stat")]
        }

        /// Les créations d'un objet de chaque genre de l'espace de noms des tables sous le nom `nom` : (genre, chaîne).
        /// La table virtuelle est une FTS4 à contenu externe sur `t`, que la liste admet.
        fn objets_nommes(nom: &str) -> Vec<(&'static str, String)> {
            vec![
                ("table", format!("CREATE TABLE {nom}(id INTEGER PRIMARY KEY, value BLOB)")),
                ("vue", format!("CREATE VIEW {nom} AS SELECT 1 AS id, x'00' AS value")),
                ("index", format!("CREATE INDEX {nom} ON t(v)")),
                ("table virtuelle", format!("CREATE VIRTUAL TABLE {nom} USING fts4(v, content='t')")),
            ]
        }

        /// LE CODE QUE REND LE MOTEUR SEUL (connexion sans autoriseur) sur `sequence`, jouée après la table `t`.
        fn code_du_moteur_seul(sequence: &str) -> i32 {
            let c = rusqlite::Connection::open_in_memory().unwrap();
            match c.execute_batch(&format!("{TABLE}; {sequence}")) {
                Err(rusqlite::Error::SqliteFailure(e, _)) | Err(rusqlite::Error::SqlInputError { error: e, .. }) => e.extended_code,
                autre => panic!("le moteur seul n'a pas refusé « {sequence} » : {autre:?}"),
            }
        }

        // ── LES MESURES DU CONSTAT ──────────────────────────────────────────────────────────────────

        /// CE QUE FAIT UNE VUE ADOPTÉE, sans restauration : FTS4 crée `<vt>_stat` par `CREATE TABLE IF NOT EXISTS` et
        /// adopte une VUE déjà là sous ce nom ; une écriture dans la table virtuelle fait alors jouer le corps du
        /// déclencheur `INSTEAD OF` posé sur la vue, ici l'effacement d'une autre table de la base.
        #[test]
        fn mesure_une_vue_adoptee_par_fts4_fait_jouer_son_declencheur_a_l_ecriture_du_module() {
            let c = rusqlite::Connection::open_in_memory().unwrap();
            c.execute_batch(&format!(
                "{TABLE}; INSERT INTO t VALUES(1, 'alpha'); \
                 CREATE VIEW f4_stat AS SELECT 1 AS id, x'00' AS value; \
                 CREATE TRIGGER g INSTEAD OF INSERT ON f4_stat BEGIN DELETE FROM t; END; {FTS4};"
            ))
            .unwrap();
            let genre: String = c.query_row("SELECT type FROM sqlite_master WHERE name = 'f4_stat'", [], |r| r.get(0)).unwrap();
            assert_eq!(genre, "view", "contrôle : FTS4 a adopté la vue, aucune table f4_stat n'a été créée");
            let avant: i64 = c.query_row("SELECT count(*) FROM t", [], |r| r.get(0)).unwrap();
            c.execute_batch("INSERT INTO f4(docid, v) VALUES(2, 'beta');").unwrap();
            let apres: i64 = c.query_row("SELECT count(*) FROM t", [], |r| r.get(0)).unwrap();
            assert_eq!((avant, apres), (1, 0), "l'écriture du module dans f4_stat fait jouer le déclencheur de la vue");
        }

        /// LA MESURE, FORMAT COURANT : une vue `f4_stat` et un déclencheur `INSTEAD OF` dessus, posés avant `f4`.
        /// Refusée à la création de `f4`, sous sa cause, avant toute publication.
        #[test]
        fn courant_une_vue_posee_avant_fts4_au_nom_de_sa_table_stat_est_refusee() {
            let charge = dump(&[
                sql("CREATE VIEW f4_stat AS SELECT 1 AS id, x'00' AS value"),
                sql("CREATE TRIGGER g INSTEAD OF INSERT ON f4_stat BEGIN DELETE FROM t; END"),
                sql(FTS4),
            ]);
            refusee("cj9-c-vue-adoptee", &charge, hors_liste("post-DDL", NOMMEE));
        }

        /// LA MESURE, FORMAT ANCIEN : le même fichier, écrit par le moteur (qui y a fait adopter la vue par FTS4).
        /// Refusé à la création de `f4` sur le brouillon, avant l'export.
        #[test]
        fn ancien_une_vue_posee_avant_fts4_au_nom_de_sa_table_stat_est_refusee() {
            let _tmp = crate::tmp_possede::TmpPossede::neuf("cj9-a-vue-adoptee-fixture");
            let racine = _tmp.racine().chemin().to_path_buf();
            let charge = clair(
                &racine,
                &format!(
                    "CREATE VIEW f4_stat AS SELECT 1 AS id, x'00' AS value; \
                     CREATE TRIGGER g INSTEAD OF INSERT ON f4_stat BEGIN DELETE FROM t; END; {FTS4};"
                ),
            );
            refusee("cj9-a-vue-adoptee", &charge, hors_liste("format ancien", NOMMEE));
        }

        /// L'ÉCRIVAIN ET UNE AUTRE CASSE : une base où FTS4 a adopté la table `F4_Stat` comme sa table `f4_stat`.
        /// `collect_dump_plan` ne la reconnaît pas pour fantôme (son jeu de noms compare la casse) et la rejoue comme table
        /// ordinaire : la restauration de cette archive du format courant est refusée sous la cause nommée. Contrôle : la
        /// même base sans cette table se restaure.
        #[test]
        fn mesure_l_ecrivain_rejoue_une_table_adoptee_sous_une_autre_casse_et_sa_restauration_est_refusee() {
            let _reglages = VERROU_ENV_PROCESSUS.read();
            let _tmp = crate::tmp_possede::TmpPossede::neuf("cj9-ecrivain-casse");
            let racine = _tmp.racine().chemin().to_path_buf();
            for (nom, avant) in [("controle", ""), ("casse", "CREATE TABLE F4_Stat(id INTEGER PRIMARY KEY, value BLOB);")] {
                let src = chemin(&racine, &format!("{nom}-src.db"));
                {
                    let c = open_db_keyed(&src, Some(CLE)).unwrap();
                    c.execute_batch(&format!("{TABLE}; INSERT INTO t VALUES(1, 'ecrite'); {avant} {FTS4}; INSERT INTO f4(f4) VALUES('rebuild');"))
                        .unwrap();
                }
                let archive = chemin(&racine, &format!("{nom}.age"));
                backup_compressed(&src, &archive, Some(CLE), None).expect("sauvegarde");
                let dest = chemin(&racine, &format!("{nom}-dest.db"));
                let issue = restore_compressed(&archive, &dest, Some(CLE), false, None);
                if nom == "controle" {
                    assert_eq!(issue, Ok(()), "contrôle : la base sans F4_Stat se restaure");
                } else {
                    assert_eq!(issue, Err(hors_liste("post-DDL", NOMMEE)(&dest)), "la table F4_Stat rejouée fait refuser f4");
                }
            }
        }

        // ── FORMAT COURANT ──────────────────────────────────────────────────────────────────────────

        /// AVANT LA TABLE VIRTUELLE, FORMAT COURANT, PAR LA LISTE : pour chaque module émis, un objet de chaque genre
        /// (table de la section 1, vue, index, table virtuelle) au nom d'une table fantôme que le module crée est refusé
        /// à la création de la table virtuelle, sous la cause nommée.
        #[test]
        fn courant_un_objet_de_chaque_genre_cree_avant_la_table_virtuelle_est_refuse_par_la_liste() {
            for (creation, vt, cree, _) in modules() {
                for (genre, objet) in objets_nommes(cree) {
                    let charge = if genre == "table" { dump_avec(&[objet.as_str()], &[sql(creation)]) } else { dump(&[sql(&objet), sql(creation)]) };
                    refusee(&format!("cj9-c-avant-{vt}-{}", genre.replace(' ', "-")), &charge, hors_liste("post-DDL", NOMMEE));
                }
            }
        }

        /// APRÈS LA TABLE VIRTUELLE, FORMAT COURANT, PAR LA LISTE : une vue ou une table (dans la section post-DDL) au
        /// nom d'une table fantôme que le module a créée, et un objet de chaque genre au nom `<vt>_<suffixe>` que ce
        /// module ne crée pas, sont refusés à leur création sous la cause nommée. L'autoriseur voit le nom d'une vue ou
        /// d'une table avant que le moteur ne cherche s'il est pris.
        #[test]
        fn courant_un_objet_cree_apres_la_table_virtuelle_est_refuse_par_la_liste() {
            for (creation, vt, cree, non_cree) in modules() {
                let mut cas: Vec<(String, String)> =
                    objets_nommes(cree).into_iter().filter(|(g, _)| *g == "table" || *g == "vue").map(|(g, o)| (format!("cree-{g}"), o)).collect();
                cas.extend(objets_nommes(non_cree).into_iter().map(|(g, o)| (format!("non-cree-{g}"), o)));
                for (nom, objet) in cas {
                    refusee(
                        &format!("cj9-c-apres-{vt}-{}", nom.replace(' ', "-")),
                        &courant_apres(creation, vt, &objet),
                        hors_liste("post-DDL", NOMMEE),
                    );
                }
            }
        }

        /// APRÈS LA TABLE VIRTUELLE, FORMAT COURANT, PAR LE MOTEUR : un INDEX ou une TABLE VIRTUELLE au nom d'une table
        /// fantôme que le module a créée. Le moteur cherche le nom avant de montrer la création à l'autoriseur
        /// (`sqlite3CreateIndex` ; `sqlite3StartTable`, l'autorisation d'une table virtuelle ne venant qu'après, dans
        /// `sqlite3VtabBeginParse`) : la chaîne n'a pas de tête et la liste la refuse comme hors classe. Le contrôle joue
        /// la même suite sur le moteur seul, qui la refuse (code 1). Pour chaque module émis.
        #[test]
        fn courant_un_index_ou_une_table_virtuelle_apres_elle_au_nom_d_une_table_fantome_creee_est_arrete_par_le_moteur() {
            for (creation, vt, cree, _) in modules() {
                for (genre, objet) in objets_nommes(cree).into_iter().filter(|(g, _)| *g == "index" || *g == "table virtuelle") {
                    assert_eq!(code_du_moteur_seul(&format!("{creation}; {objet};")), 1, "contrôle : le moteur seul refuse {genre} {cree}");
                    refusee(&format!("cj9-c-moteur-{vt}-{}", genre.replace(' ', "-")), &courant_apres(creation, vt, &objet), hors_liste("post-DDL", CLASSE));
                }
            }
        }

        /// LA CASSE IGNORÉE DES DEUX CÔTÉS, FORMAT COURANT, dans les deux ordres : table virtuelle `F4` en majuscules et
        /// vue en minuscules, puis l'inverse ; avant (`f4_stat`, que FTS4 adopterait) et après (`f4_content`, que le
        /// moteur ne refuse pas). Chacun est refusé sous la cause nommée.
        #[test]
        fn courant_la_casse_est_ignoree_sur_le_nom_de_la_table_virtuelle_et_sur_celui_de_l_objet() {
            let majuscule = "CREATE VIRTUAL TABLE F4 USING fts4(v, content='t')";
            let cas = [
                ("vt-maj-avant", dump(&[sql("CREATE VIEW f4_stat AS SELECT 1 AS id, x'00' AS value"), sql(majuscule)])),
                ("objet-maj-avant", dump(&[sql("CREATE VIEW F4_STAT AS SELECT 1 AS id, x'00' AS value"), sql(FTS4)])),
                ("vt-maj-apres", dump(&[sql(majuscule), Post::Reconstruire("F4"), sql("CREATE VIEW f4_content AS SELECT 1 AS id")])),
                ("objet-maj-apres", courant_apres(FTS4, "f4", "CREATE VIEW F4_CONTENT AS SELECT 1 AS id")),
            ];
            for (nom, charge) in cas {
                refusee(&format!("cj9-c-casse-{nom}"), &charge, hors_liste("post-DDL", NOMMEE));
            }
        }

        /// LE DÉCLENCHEUR A SON PROPRE ESPACE DE NOMS : un déclencheur nommé comme une table fantôme, avant comme après
        /// la table virtuelle, ne prend pas ce nom ; il est admis sur la table ordinaire `t`, le module crée sa table
        /// sous ce nom, et chaque table virtuelle répond.
        #[test]
        fn courant_un_declencheur_au_nom_d_une_table_fantome_garde_son_espace_de_noms_et_se_restaure() {
            // Le corps de ce déclencheur n'est pas celui d'un déclencheur que le démon crée : refusé par ailleurs (P10.34-t,
            // `restauration_corps_des_declencheurs_et_des_vues.rs`). Ce témoin d'une autre règle lève ce seul jugement.
            let _corps = crate::backup::crochets_de_restauration::sans_jugement_des_declencheurs_et_des_vues();
            let _tmp = crate::tmp_possede::TmpPossede::neuf("cj9-c-declencheur-nomme");
            let racine = _tmp.racine().chemin().to_path_buf();
            let charge = dump(&[
                sql("CREATE TRIGGER f4_stat AFTER INSERT ON t BEGIN SELECT 1; END"),
                sql(FTS4),
                sql(FTS5),
                Post::Reconstruire("f4"),
                Post::Reconstruire("f"),
                sql("CREATE TRIGGER f_data AFTER INSERT ON t BEGIN SELECT 1; END"),
            ]);
            let c = admise("cj9-c-declencheur-nomme", &racine, &charge);
            assert_eq!(
                lignes_de(&c, "SELECT type, name, tbl_name FROM sqlite_master WHERE name IN ('f4_stat', 'f_data')"),
                vec![
                    "Text(\"table\")|Text(\"f4_stat\")|Text(\"f4_stat\")".to_string(),
                    "Text(\"table\")|Text(\"f_data\")|Text(\"f_data\")".to_string(),
                    "Text(\"trigger\")|Text(\"f4_stat\")|Text(\"t\")".to_string(),
                    "Text(\"trigger\")|Text(\"f_data\")|Text(\"t\")".to_string(),
                ],
            );
            assert_eq!(lignes_de(&c, "SELECT rowid FROM f4 WHERE f4 MATCH 'restauree'"), vec!["Integer(1)".to_string()], "f4 répond");
            assert_eq!(lignes_de(&c, "SELECT rowid FROM f WHERE f MATCH 'restauree'"), vec!["Integer(1)".to_string()], "f répond");
        }

        // ── FORMAT ANCIEN ───────────────────────────────────────────────────────────────────────────

        /// AVANT LA TABLE VIRTUELLE DANS LE FICHIER, FORMAT ANCIEN, PAR LA LISTE : chaque fichier est écrit par le moteur.
        /// Une vue, un index, une table virtuelle au nom `<vt>_content` (que le module à contenu externe ne crée pas, de
        /// sorte que le moteur les laisse coexister), pour FTS5 et FTS4, et une table virtuelle `f4_stat` que FTS4 adopte
        /// comme sa table de statistiques : refusés à la création de la table virtuelle sur le brouillon, avant l'export.
        #[test]
        fn ancien_un_objet_de_chaque_genre_ecrit_avant_la_table_virtuelle_est_refuse_par_la_liste() {
            let _tmp = crate::tmp_possede::TmpPossede::neuf("cj9-a-avant-fixture");
            let racine = _tmp.racine().chemin().to_path_buf();
            let mut cas: Vec<(String, String)> = Vec::new();
            for (creation, vt, _, non_cree) in modules() {
                for (genre, objet) in objets_nommes(non_cree).into_iter().filter(|(g, _)| *g != "table") {
                    cas.push((format!("{vt}-{}", genre.replace(' ', "-")), format!("{objet}; {creation};")));
                }
            }
            cas.push(("f4-vt-adoptee".to_string(), format!("CREATE VIRTUAL TABLE f4_stat USING fts4(v, content='t'); {FTS4};")));
            for (nom, ddl) in cas {
                refusee(&format!("cj9-a-avant-{nom}"), &clair(&racine, &ddl), hors_liste("format ancien", NOMMEE));
            }
        }

        /// APRÈS LA TABLE VIRTUELLE DANS LE FICHIER, FORMAT ANCIEN, PAR LA LISTE : un objet de chaque genre écrit par le
        /// moteur après elle sous un nom `<vt>_<suffixe>` que le module ne crée pas, pour FTS5, FTS4 et FTS3. La vue (que
        /// le brouillon crée avant les tables virtuelles), la table dans une autre casse (rejouée comme table ordinaire,
        /// avant elles) sont refusées à la création de la table virtuelle ; l'index et la table virtuelle (jugés dans
        /// l'ordre du fichier) à leur propre création ; tous sous la cause nommée. La table au nom exact est une table
        /// fantôme du fichier, que le module ne crée pas : la comparaison des tables fantômes la refuse sous sa cause.
        #[test]
        fn ancien_un_objet_de_chaque_genre_ecrit_apres_la_table_virtuelle_est_refuse_par_la_liste() {
            let _tmp = crate::tmp_possede::TmpPossede::neuf("cj9-a-apres-fixture");
            let racine = _tmp.racine().chemin().to_path_buf();
            for (creation, vt, _, non_cree) in modules() {
                let mut cas: Vec<(String, String, &'static str)> = objets_nommes(non_cree)
                    .into_iter()
                    .filter(|(g, _)| *g != "table")
                    .map(|(g, o)| (g.replace(' ', "-"), o, NOMMEE))
                    .collect();
                cas.push(("table-casse".to_string(), format!("CREATE TABLE {}(id INTEGER PRIMARY KEY, value BLOB)", non_cree.to_ascii_uppercase()), NOMMEE));
                cas.push(("table-exacte".to_string(), format!("CREATE TABLE {non_cree}(id INTEGER PRIMARY KEY, value BLOB)"), TABLES_FANTOMES_AUTRES));
                for (nom, objet, cause) in cas {
                    refusee(&format!("cj9-a-apres-{vt}-{nom}"), &clair(&racine, &format!("{creation}; {objet};")), hors_liste("format ancien", cause));
                }
            }
        }

        /// APRÈS LA TABLE VIRTUELLE DANS LE FICHIER, FORMAT ANCIEN, PAR LE MOTEUR : un index ou une table virtuelle au nom
        /// d'une table fantôme que le module crée. Le moteur ne laisse pas écrire un tel fichier : il est retouché par
        /// `writable_schema` (un objet `zz` créé après la table virtuelle prend ce nom et ce texte ; pour la table
        /// virtuelle, la ligne de la table fantôme est retirée d'abord, deux tables du même nom ne se relisant pas). Sur
        /// le brouillon, où le module vient de créer sa table, le moteur arrête la préparation sur le nom pris avant de
        /// montrer la création à l'autoriseur : refus hors classe sous « format ancien ». Pour chaque module émis.
        #[test]
        fn ancien_un_index_ou_une_table_virtuelle_apres_elle_au_nom_d_une_table_fantome_creee_est_arrete_par_le_moteur() {
            let _tmp = crate::tmp_possede::TmpPossede::neuf("cj9-a-moteur-fixture");
            let racine = _tmp.racine().chemin().to_path_buf();
            for (creation, vt, cree, _) in modules() {
                let index = format!(
                    "{creation}; CREATE INDEX zz ON t(v); PRAGMA writable_schema=ON; \
                     UPDATE sqlite_master SET name = '{cree}', sql = 'CREATE INDEX {cree} ON t(v)' WHERE name = 'zz'; \
                     PRAGMA writable_schema=OFF;"
                );
                let virtuelle = format!(
                    "{creation}; CREATE VIRTUAL TABLE zz USING fts4(v, content='t'); PRAGMA writable_schema=ON; \
                     DELETE FROM sqlite_master WHERE type = 'table' AND name = '{cree}'; \
                     UPDATE sqlite_master SET name = '{cree}', tbl_name = '{cree}', \
                     sql = 'CREATE VIRTUAL TABLE {cree} USING fts4(v, content=''t'')' WHERE name = 'zz'; \
                     PRAGMA writable_schema=OFF;"
                );
                for (genre, ddl) in [("index", index), ("table-virtuelle", virtuelle)] {
                    let charge = clair(&racine, &ddl);
                    let schema = {
                        let p = chemin(&racine, "relu.db");
                        std::fs::write(&p, &charge).unwrap();
                        let c = open_db_keyed(&p, None).unwrap();
                        let lu = lignes_de(&c, &format!("SELECT type FROM sqlite_master WHERE name = '{cree}'"));
                        drop(c);
                        std::fs::remove_file(&p).unwrap();
                        lu
                    };
                    let attendu = if genre == "index" { vec!["Text(\"index\")", "Text(\"table\")"] } else { vec!["Text(\"table\")"] };
                    assert_eq!(schema, attendu, "contrôle : le fichier retouché se relit avec {genre} {cree}");
                    refusee(&format!("cj9-a-moteur-{vt}-{genre}"), &charge, hors_liste("format ancien", CLASSE));
                }
            }
        }

        /// LA CASSE IGNORÉE DES DEUX CÔTÉS, FORMAT ANCIEN : table virtuelle `F4` et vue `f4_stat` (adoptée), puis table
        /// virtuelle `f4` et vue `F4_STAT` (adoptée), fichiers écrits par le moteur.
        #[test]
        fn ancien_la_casse_est_ignoree_sur_le_nom_de_la_table_virtuelle_et_sur_celui_de_l_objet() {
            let _tmp = crate::tmp_possede::TmpPossede::neuf("cj9-a-casse-fixture");
            let racine = _tmp.racine().chemin().to_path_buf();
            let cas = [
                ("vt-maj", "CREATE VIEW f4_stat AS SELECT 1 AS id, x'00' AS value; CREATE VIRTUAL TABLE F4 USING fts4(v, content='t');".to_string()),
                ("objet-maj", format!("CREATE VIEW F4_STAT AS SELECT 1 AS id, x'00' AS value; {FTS4};")),
            ];
            for (nom, ddl) in cas {
                refusee(&format!("cj9-a-casse-{nom}"), &clair(&racine, &ddl), hors_liste("format ancien", NOMMEE));
            }
        }

        /// LE DÉCLENCHEUR, FORMAT ANCIEN : nommé comme une table fantôme, avant et après la table virtuelle dans le
        /// fichier ; admis, la base publiée porte le schéma du fichier et la table virtuelle répond.
        #[test]
        fn ancien_un_declencheur_au_nom_d_une_table_fantome_garde_son_espace_de_noms_et_se_restaure() {
            // Le corps de ce déclencheur n'est pas celui d'un déclencheur que le démon crée : refusé par ailleurs (P10.34-t,
            // `restauration_corps_des_declencheurs_et_des_vues.rs`). Ce témoin d'une autre règle lève ce seul jugement.
            let _corps = crate::backup::crochets_de_restauration::sans_jugement_des_declencheurs_et_des_vues();
            let _tmp = crate::tmp_possede::TmpPossede::neuf("cj9-a-declencheur-nomme");
            let racine = _tmp.racine().chemin().to_path_buf();
            let ddl = format!(
                "CREATE TRIGGER f4_stat AFTER INSERT ON t BEGIN SELECT 1; END; {FTS4}; INSERT INTO f4(f4) VALUES('rebuild'); \
                 CREATE TRIGGER f4_segdir AFTER INSERT ON t BEGIN SELECT 1; END;"
            );
            let c = admise("cj9-a-declencheur-nomme", &racine, &clair(&racine, &ddl));
            assert_eq!(
                lignes_de(&c, "SELECT type, name, tbl_name FROM sqlite_master WHERE name IN ('f4_stat', 'f4_segdir')"),
                vec![
                    "Text(\"table\")|Text(\"f4_segdir\")|Text(\"f4_segdir\")".to_string(),
                    "Text(\"table\")|Text(\"f4_stat\")|Text(\"f4_stat\")".to_string(),
                    "Text(\"trigger\")|Text(\"f4_segdir\")|Text(\"t\")".to_string(),
                    "Text(\"trigger\")|Text(\"f4_stat\")|Text(\"t\")".to_string(),
                ],
            );
            assert_eq!(lignes_de(&c, "SELECT rowid FROM f4 WHERE f4 MATCH 'legacy'"), vec!["Integer(1)".to_string()], "f4 répond");
        }
    }
}
