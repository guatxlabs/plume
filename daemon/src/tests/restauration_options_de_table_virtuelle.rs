// =====================================================================================
// UNE TABLE VIRTUELLE D'UNE ARCHIVE EST JUGÉE SUR SES ARGUMENTS, DANS LES DEUX FORMATS, AVANT QUE LE MOTEUR NE LA JOUE
// (`backup/restauration_liste_fermee.rs` : `ListeFermee::preparer_une_chaine_de_l_archive`,
// `arguments_decoupes_par_le_moteur`, `argument_admis` ; `backup/dump_restauration.rs` : `restore_stream`,
// `restore_compressed`).
//
// LE DÉFAUT, LU SUR 2b9eff27 : l'autoriseur ne voit d'une création de table virtuelle que son nom et son MODULE
// (`SQLITE_CREATE_VTABLE`, les arguments n'y passent pas). Le format courant jugeait en plus ce que le module fait en
// s'exécutant ; le format ancien ne préparait la ligne que sur un brouillon, et l'export la recopiait telle quelle,
// relue par le module à la première ouverture. Une archive d'un module admis portait donc les options qu'elle voulait :
// un découpeur choisi (`tokenize='porter'`), une table de contenu que la restauration n'a pas créée
// (`content='sqlite_master'`), des fonctions que le module appellera à chaque écriture (`compress=hex`), une casse ou un
// espacement que l'écrivain n'émet pas ; la destination était publiée.
//
// DÉSORMAIS : les arguments, tels que le moteur les découpe, sont jugés un par un, chacun ENTIER (casse et espaces
// compris), contre ce que l'écrivain émet : nom de colonne nu ; `content='<table>'` d'une table créée par cette
// restauration ; pour FTS5 seulement, `content_rowid='<colonne>'` et les trois options du filtre de champs plein texte.
// Tout autre argument refuse la restauration sous la phase de la chaîne (« post-DDL », « format ancien ») avec une
// phrase fixe, sans texte de l'archive ni du moteur, avant toute publication : une destination existante reste
// identique à l'octet, une destination absente n'est pas créée.
//
// LES ARCHIVES ADMISES : de vraies sauvegardes du schéma complet de la tête, dans les deux formats (la liste des tables
// virtuelles qu'elles portent est relevée ici, au texte exact), et des archives forgées qui portent chaque forme admise.
// Les archives REFUSÉES portent chacune UNE forme qu'aucune base du démon ne porte.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'écriture d'un compteur (section 3) qui échouerait à l'exécution. Elle ne touche
// que le cache de pages (aucune contrainte, aucun index ni déclencheur n'est permis sur `sqlite_sequence`), donc seules
// une valeur d'au moins la longueur maximale du moteur ou une allocation refusée la font échouer ; aucune des deux ne se
// provoque sans un volume réel ou un plafond de mémoire du processus entier.
// =====================================================================================

mod ci6_restauration_options_de_table_virtuelle {
    use super::*;
    use crate::backup::SUFFIXE_RESTAURATION_EN_COURS;

    const CLE: &str = "ci6-cle-de-test-de-restauration";

    // Les phrases attendues, écrites ici en toutes lettres (jamais relues de la production).
    const OPTION: &str = "argument de table virtuelle hors de ce que l'écrivain émet";
    const CLASSE: &str = "classe d'instruction hors de la liste de la phase";
    const PLUSIEURS: &str = "plus d'une instruction dans la chaîne";

    /// Le découpeur du filtre de champs plein texte, au texte exact du démon (`maintenance::FTS_FIELDS_VTABLE_DDL`).
    const DECOUPEUR_DU_DEMON: &str = "tokenize=\"unicode61 remove_diacritics 2 tokenchars '_-.:/@'\"";

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

    /// La charge entière d'une archive (déchiffrée, décompressée).
    fn charge_de(archive: &str) -> Vec<u8> {
        use std::io::Read;
        let f = std::fs::File::open(archive).unwrap();
        let dec = age::Decryptor::new_buffered(std::io::BufReader::new(f)).unwrap();
        let id = age::scrypt::Identity::new(age::secrecy::SecretString::from(CLE.to_string()));
        let reader = dec.decrypt(std::iter::once(&id as &dyn age::Identity)).unwrap();
        let mut v = Vec::new();
        zstd::Decoder::new(reader).unwrap().read_to_end(&mut v).unwrap();
        v
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

    /// Un dump B1 forgé au format de `dump_stream` : la table `t(id INTEGER PRIMARY KEY, v TEXT)` et sa ligne
    /// (1, 'restauree') au texte d'insertion de l'écrivain, aucun compteur, puis `post`.
    fn dump(post: &[Post]) -> Vec<u8> {
        let mut v = b"PLUMEDUMP1\n".to_vec();
        ecrire_u32(&mut v, 1);
        ecrire_str(&mut v, "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)");
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

    fn suffixe_intacte(dest: &str) -> String {
        format!(" — la destination {dest} est INTACTE : la restauration s'écrivait dans {dest}{SUFFIXE_RESTAURATION_EN_COURS}, qui a été retiré.")
    }

    /// Le refus attendu, en entier.
    fn refus_attendu(phase: &str, cause: &str, dest: &str) -> String {
        format!("restore : phase {phase} : instruction hors liste ({cause}){}", suffixe_intacte(dest))
    }

    /// LE TÉMOIN DE REFUS, deux fois. (1) Destination ABSENTE : la restauration échoue avec exactement le refus attendu, et
    /// seul `archive.age` reste (rien de publié, ni temporaire ni clair). (2) Destination SAINE avec ses compagnons `-wal`
    /// et `-shm`, restaurée avec `--force` : même refus, base et compagnons identiques à l'octet, rien d'autre ne reste.
    fn refusee(cas: &str, charge: &[u8], phase: &str, cause: &str) {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        {
            let _tmp = crate::tmp_possede::TmpPossede::neuf(&format!("{cas}-sans-dest"));
            let racine = _tmp.racine().chemin().to_path_buf();
            archive_de(charge, &chemin(&racine, "archive.age"));
            let dest = chemin(&racine, "plume.db");
            let err = restore_compressed(&chemin(&racine, "archive.age"), &dest, Some(CLE), false, None).expect_err(cas);
            assert_eq!(err, refus_attendu(phase, cause, &dest), "{cas} (sans destination)");
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
        assert_eq!(err, refus_attendu(phase, cause, &dest), "{cas}");
        let apres: Vec<Vec<u8>> = ["", "-wal", "-shm"].iter().map(|s| std::fs::read(format!("{dest}{s}")).unwrap()).collect();
        assert!(apres == avant, "{cas} : la destination ou un compagnon a changé");
        assert_eq!(contenu(&racine), vec!["archive.age", "plume.db", "plume.db-shm", "plume.db-wal"], "{cas} : rien d'autre ne reste");
    }

    /// Un dump B1 forgé dont le post-DDL est `post`, refusé sous la phase post-DDL.
    fn courant_refuse(cas: &str, post: &[Post], cause: &str) {
        refusee(cas, &dump(post), "post-DDL", cause);
    }

    /// Une archive au format ancien portant `ddl`, refusée sous la phase « format ancien ».
    fn ancien_refuse(cas: &str, ddl: &str, cause: &str) {
        let _tmp = crate::tmp_possede::TmpPossede::neuf(&format!("{cas}-fixture"));
        let charge = clair(_tmp.racine().chemin(), ddl);
        refusee(cas, &charge, "format ancien", cause);
    }

    /// Restaure `charge` sur une destination absente ; rend la connexion à la base publiée.
    fn admise(cas: &str, racine: &std::path::Path, charge: &[u8]) -> rusqlite::Connection {
        archive_de(charge, &chemin(racine, "archive.age"));
        let dest = chemin(racine, "plume.db");
        restore_compressed(&chemin(racine, "archive.age"), &dest, Some(CLE), false, None).unwrap_or_else(|e| panic!("{cas} : {e}"));
        open_db_keyed(&dest, Some(CLE)).unwrap()
    }

    fn tables_virtuelles(c: &rusqlite::Connection) -> Vec<String> {
        lignes_de(c, "SELECT name, sql FROM sqlite_master WHERE sql LIKE 'CREATE VIRTUAL TABLE%'")
    }

    // ── FORMAT COURANT : REFUS ──────────────────────────────────────────────────────────────────────

    /// Un module que l'écrivain n'émet pas (`fts5vocab`, présent dans le moteur) reste refusé par l'autoriseur.
    #[test]
    fn courant_un_module_hors_liste_est_refuse() {
        courant_refuse("ci6-c-module", &[Post::Sql("CREATE VIRTUAL TABLE w USING fts5vocab(t, row)")], CLASSE);
    }

    /// Module admis, découpeur que l'écrivain n'émet pas : la base était publiée avec ce découpeur.
    #[test]
    fn courant_un_decoupeur_hors_liste_est_refuse() {
        courant_refuse("ci6-c-decoupeur", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content='t', tokenize='porter')")], OPTION);
    }

    /// Module admis, fonctions nommées par l'archive (`compress=`/`uncompress=`), sans reconstruction : le module ne les
    /// appelle pas pendant la restauration, la base était publiée et les aurait appelées à chaque écriture.
    #[test]
    fn courant_des_fonctions_nommees_par_l_archive_sont_refusees_sans_reconstruction() {
        courant_refuse("ci6-c-compress", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts4(v, compress=hex, uncompress=hex)")], OPTION);
    }

    /// Une table de contenu que la restauration n'a pas créée (`sqlite_master`), sans reconstruction.
    #[test]
    fn courant_une_table_de_contenu_non_creee_est_refusee() {
        courant_refuse("ci6-c-contenu", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content='sqlite_master')")], OPTION);
    }

    /// `content_rowid` ne nomme qu'une colonne nue.
    #[test]
    fn courant_un_content_rowid_qui_n_est_pas_un_nom_nu_est_refuse() {
        courant_refuse("ci6-c-rowid", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content='t', content_rowid='id + 0')")], OPTION);
    }

    /// LE PREMIER CARACTÈRE D'UN NOM NU : une lettre ou `_`. Le reste de ces valeurs est fait de caractères admis ; seul
    /// le premier les sort de ce que l'écrivain émet, et le module ne vérifie pas la colonne à la création.
    #[test]
    fn courant_un_content_rowid_dont_seul_le_premier_caractere_est_hors_liste_est_refuse() {
        courant_refuse("ci6-c-rowid-dollar", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content='t', content_rowid='$id')")], OPTION);
        courant_refuse("ci6-c-rowid-chiffre", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content='t', content_rowid='1id')")], OPTION);
    }

    /// UN NOM NU N'EST JAMAIS VIDE : `content_rowid=''` a la forme `<clé>'<valeur>'` et ne porte aucun caractère hors
    /// liste, mais l'écrivain n'émet pas de colonne sans nom. Un juge qui admettrait la chaîne vide publierait cette base.
    #[test]
    fn courant_un_content_rowid_vide_est_refuse() {
        courant_refuse("ci6-c-rowid-vide", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content='t', content_rowid='')")], OPTION);
    }

    /// `EXPLAIN CREATE VIRTUAL TABLE` a la tête `CreateVtable` que la liste admet ; sur la base jetable, l'instruction rend
    /// le programme sans l'exécuter, l'espion n'est pas appelé, aucun argument n'est relevé : le jugement reste fermé et
    /// refuse sous sa cause, avant que le moteur ne voie l'instruction sur la connexion de la restauration.
    #[test]
    fn courant_une_creation_sous_explain_n_a_aucun_argument_releve_et_est_refusee() {
        courant_refuse("ci6-c-explain", &[Post::Sql("EXPLAIN CREATE VIRTUAL TABLE f USING fts5(v, tokenize='porter')")], OPTION);
    }

    /// UNE OPTION ADMISE ÉCRITE AUTREMENT EST JUGÉE SUR SON TEXTE ENTIER : le moteur lit ces quatre formes comme
    /// `content='t'`, l'écrivain n'en émet aucune.
    #[test]
    fn courant_une_option_admise_dans_une_autre_casse_ou_un_autre_espacement_est_refusee() {
        courant_refuse("ci6-c-casse", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, CONTENT='t')")], OPTION);
        courant_refuse("ci6-c-espace-avant", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content ='t')")], OPTION);
        courant_refuse("ci6-c-espace-apres", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content= 't')")], OPTION);
        courant_refuse("ci6-c-guillemets", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content=\"t\")")], OPTION);
    }

    /// LA DONNÉE ENTIÈRE, JAMAIS UN PRÉFIXE NI UN SUFFIXE : un préfixe admis prolongé, le découpeur du démon précédé d'un
    /// autre.
    #[test]
    fn courant_une_option_fixe_prolongee_ou_precedee_est_refusee() {
        courant_refuse("ci6-c-prefixe", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content='', prefix='2 3 4')")], OPTION);
        courant_refuse(
            "ci6-c-decoupeur-precede",
            &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content='', tokenize=\"porter unicode61 remove_diacritics 2 tokenchars '_-.:/@'\")")],
            OPTION,
        );
    }

    /// UNE OPTION FIXE N'EST COMPARÉE NI PAR SON DÉBUT NI PAR SA FIN. `content=''''` commence par l'option admise
    /// `content=''` et nomme pour table de contenu une table appelée `'`, que la restauration n'a pas créée ;
    /// `xprefix='2 3'` finit par l'option admise `prefix='2 3'`. Une comparaison par préfixe admettrait la première, une
    /// comparaison par suffixe la seconde : chacune est refusée, seule, à côté d'arguments tous admis.
    #[test]
    fn courant_une_option_fixe_n_est_admise_ni_par_son_debut_ni_par_sa_fin() {
        courant_refuse("ci6-c-option-debut", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content='''')")], OPTION);
        courant_refuse("ci6-c-option-fin", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content='t', xprefix='2 3')")], OPTION);
    }

    /// Les options de FTS5 ne sont admises que pour FTS5 : une FTS4 sans contenu, que l'écrivain n'émet pas.
    #[test]
    fn courant_une_option_de_fts5_sur_fts4_est_refusee() {
        courant_refuse("ci6-c-fts4-sans-contenu", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts4(v, content='')")], OPTION);
    }

    /// Une colonne n'est qu'un nom nu : une colonne typée est hors de ce que l'écrivain émet.
    #[test]
    fn courant_une_colonne_typee_est_refusee() {
        courant_refuse("ci6-c-colonne-typee", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts4(v TEXT, content='t')")], OPTION);
    }

    /// L'ORDRE DES REFUS : une seconde instruction derrière une table virtuelle hors liste garde sa cause.
    #[test]
    fn courant_une_seconde_instruction_garde_sa_cause_devant_un_argument_hors_liste() {
        courant_refuse("ci6-c-ordre", &[Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, tokenize='porter'); DROP TABLE t")], PLUSIEURS);
    }

    // ── FORMAT COURANT : ADMIS ──────────────────────────────────────────────────────────────────────

    /// CHAQUE FORME ADMISE, dans un dump forgé : colonnes nues, contenu externe d'une table créée et `content_rowid`
    /// (reconstruite, elle répond), les trois options du filtre de champs, FTS4 et FTS3 à contenu externe. La base est
    /// publiée et porte chaque table virtuelle à son texte exact.
    #[test]
    fn courant_chaque_forme_admise_se_restaure() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ci6-c-admis");
        let racine = _tmp.racine().chemin().to_path_buf();
        let charge = dump(&[
            Post::Sql("CREATE VIRTUAL TABLE e USING fts5(v, content='t', content_rowid='id')"),
            Post::Reconstruire("e"),
            Post::Sql(
                "CREATE VIRTUAL TABLE g USING fts5(v, content='', tokenize=\"unicode61 remove_diacritics 2 tokenchars '_-.:/@'\", prefix='2 3')",
            ),
            Post::Sql("CREATE VIRTUAL TABLE f4 USING fts4(v, content='t')"),
            Post::Sql("CREATE VIRTUAL TABLE f3 USING fts3(v, content='t')"),
        ]);
        let c = admise("ci6-c-admis", &racine, &charge);
        assert_eq!(
            tables_virtuelles(&c),
            vec![
                "Text(\"e\")|Text(\"CREATE VIRTUAL TABLE e USING fts5(v, content='t', content_rowid='id')\")".to_string(),
                "Text(\"f3\")|Text(\"CREATE VIRTUAL TABLE f3 USING fts3(v, content='t')\")".to_string(),
                "Text(\"f4\")|Text(\"CREATE VIRTUAL TABLE f4 USING fts4(v, content='t')\")".to_string(),
                format!("Text(\"g\")|Text(\"CREATE VIRTUAL TABLE g USING fts5(v, content='', {}, prefix='2 3')\")", DECOUPEUR_DU_DEMON.replace('"', "\\\"")),
            ],
        );
        assert_eq!(lignes_de(&c, "SELECT rowid FROM e WHERE e MATCH 'restauree'"), vec!["Integer(1)".to_string()], "e reconstruite répond");
    }

    // ── FORMAT ANCIEN ───────────────────────────────────────────────────────────────────────────────

    /// LE FORMAT ANCIEN NE JUGEAIT LA LIGNE QU'À LA PRÉPARATION : l'autoriseur n'y voit que le module ; le module ne
    /// s'exécute pas sur le brouillon et l'export recopie la ligne telle quelle. Une FTS4 qui fait appeler `hex` à chaque
    /// écriture était publiée ; elle est désormais refusée avant l'export.
    #[test]
    fn ancien_des_fonctions_nommees_par_l_archive_sont_refusees() {
        ancien_refuse("ci6-a-compress", "CREATE VIRTUAL TABLE f USING fts4(v, compress=hex, uncompress=hex);", OPTION);
    }

    #[test]
    fn ancien_un_decoupeur_hors_liste_est_refuse() {
        ancien_refuse("ci6-a-decoupeur", "CREATE VIRTUAL TABLE f USING fts5(v, content='t', tokenize='porter');", OPTION);
    }

    #[test]
    fn ancien_une_table_de_contenu_non_creee_est_refusee() {
        ancien_refuse("ci6-a-contenu", "CREATE VIRTUAL TABLE f USING fts5(v, content='sqlite_master');", OPTION);
    }

    /// UNE VALEUR QUI PORTE UNE APOSTROPHE N'EST PAS JUGÉE SUR SON TEXTE BRUT : la table `a''b` est créée par l'archive,
    /// mais le module lit `content='a''b'` déquoté, `a'b`, une table que la restauration n'a pas créée. L'écrivain n'émet
    /// aucun nom portant une apostrophe : la valeur est refusée.
    #[test]
    fn ancien_une_table_de_contenu_dont_le_nom_porte_une_apostrophe_est_refusee() {
        ancien_refuse("ci6-a-apostrophe", "CREATE TABLE \"a''b\"(v); CREATE VIRTUAL TABLE f USING fts5(v, content='a''b');", OPTION);
    }

    /// Le format ancien juge la même donnée entière : l'option admise `content=''` prolongée d'une apostrophe doublée.
    #[test]
    fn ancien_une_option_fixe_prolongee_est_refusee() {
        ancien_refuse("ci6-a-option-debut", "CREATE VIRTUAL TABLE f USING fts5(v, content='''');", OPTION);
    }

    #[test]
    fn ancien_une_option_admise_dans_une_autre_casse_est_refusee() {
        ancien_refuse("ci6-a-casse", "CREATE VIRTUAL TABLE f USING fts5(v, CONTENT='t');", OPTION);
        ancien_refuse("ci6-a-espace", "CREATE VIRTUAL TABLE f USING fts5(v, content = 't');", OPTION);
    }

    #[test]
    fn ancien_un_module_hors_liste_est_refuse() {
        ancien_refuse(
            "ci6-a-module",
            "CREATE VIRTUAL TABLE f USING fts5(v, content='t'); CREATE VIRTUAL TABLE w USING fts5vocab(f, row);",
            CLASSE,
        );
    }

    /// Les formes admises au format ancien : les options du filtre de champs, un contenu externe et son `content_rowid`.
    #[test]
    fn ancien_chaque_forme_admise_se_restaure() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ci6-a-admis");
        let racine = _tmp.racine().chemin().to_path_buf();
        let ddl = format!(
            "CREATE VIRTUAL TABLE e USING fts5(v, content='t', content_rowid='rowid'); \
             CREATE VIRTUAL TABLE g USING fts5(v, content='', {DECOUPEUR_DU_DEMON}, prefix='2 3');"
        );
        let charge = clair(&racine, &ddl);
        let c = admise("ci6-a-admis", &racine, &charge);
        assert_eq!(
            tables_virtuelles(&c),
            vec![
                "Text(\"e\")|Text(\"CREATE VIRTUAL TABLE e USING fts5(v, content='t', content_rowid='rowid')\")".to_string(),
                format!("Text(\"g\")|Text(\"CREATE VIRTUAL TABLE g USING fts5(v, content='', {}, prefix='2 3')\")", DECOUPEUR_DU_DEMON.replace('"', "\\\"")),
            ],
        );
    }

    // ── LA MESURE : CE QUE L'ÉCRIVAIN ÉMET POUR UNE BASE AU SCHÉMA COMPLET DE LA TÊTE ─────────────────

    /// Une base de la tête : schéma de base puis toutes les migrations, index de champ chaud, quelques événements ; avec
    /// `champs`, le filtre de champs plein texte (table virtuelle sans contenu), qui fait prendre le format ancien.
    fn base_de_la_tete(src: &str, champs: bool) {
        let c = open_db_keyed(src, Some(CLE)).unwrap();
        c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&c);
        if champs {
            let mut conf = std::collections::HashMap::new();
            conf.insert("PLUME_FTS_FIELDS".to_string(), "1".to_string());
            let _ = crate::maintenance::reconcile_index_state(&c, &conf);
        }
        for champ in crate::soql_glue::HOT_FIELDS {
            c.execute(
                &format!(
                    "CREATE INDEX IF NOT EXISTS idx_ev_f_{champ} ON event(json_extract(fields,'$.{champ}')) \
                     WHERE json_extract(fields,'$.{champ}') IS NOT NULL"
                ),
                [],
            ).unwrap();
        }
        for i in 0..8i64 {
            c.execute(
                "INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,'sshd','auth',3,'hote',?2,?3)",
                params![1_700_000_000i64 + i, format!("refus pour alice numero {i}"), format!("{{\"user\":\"bob{i}\"}}")],
            ).unwrap();
        }
    }

    /// Les chaînes de post-DDL d'un dump B1 (charge entière, marqueur compris), lues au format de `dump_stream`.
    fn post_ddl_du_dump(charge: &[u8]) -> Vec<String> {
        let mut p = 11usize;
        let u32_ = |p: &mut usize| -> usize {
            let n = u32::from_le_bytes(charge[*p..*p + 4].try_into().unwrap()) as usize;
            *p += 4;
            n
        };
        let str_ = |p: &mut usize| -> String {
            let n = u32_(p);
            let s = String::from_utf8(charge[*p..*p + n].to_vec()).unwrap();
            *p += n;
            s
        };
        assert_eq!(&charge[..11], b"PLUMEDUMP1\n", "contrôle : dump B1");
        for _ in 0..u32_(&mut p) {
            str_(&mut p);
        }
        for _ in 0..u32_(&mut p) {
            str_(&mut p);
            let ncols = u16::from_le_bytes(charge[p..p + 2].try_into().unwrap()) as usize;
            p += 2;
            str_(&mut p);
            loop {
                let tag = charge[p];
                p += 1;
                if tag == 0 {
                    break;
                }
                for _ in 0..ncols {
                    let classe = charge[p];
                    p += 1;
                    match classe {
                        0 => {}
                        1 | 2 => p += 8,
                        3 | 4 => {
                            str_bytes(charge, &mut p);
                        }
                        autre => panic!("classe de valeur inattendue {autre}"),
                    }
                }
            }
        }
        for _ in 0..u32_(&mut p) {
            str_(&mut p);
            p += 8;
        }
        let mut post = Vec::new();
        for _ in 0..u32_(&mut p) {
            let tag = charge[p];
            p += 1;
            let s = str_(&mut p);
            if tag == 1 {
                post.push(s);
            }
        }
        assert_eq!(&charge[p..], &[0xFF], "contrôle : sentinelle de fin, rien derrière");
        post
    }

    fn str_bytes(charge: &[u8], p: &mut usize) {
        let n = u32::from_le_bytes(charge[*p..*p + 4].try_into().unwrap()) as usize;
        *p += 4 + n;
    }

    /// LA TABLE VIRTUELLE QUE L'ÉCRIVAIN ÉMET AU FORMAT COURANT, relevée sur une vraie sauvegarde du schéma complet de la
    /// tête : `event_fts` seule, à ce texte exact ; la sauvegarde se restaure et `event_fts` reconstruite répond.
    #[test]
    fn mesure_la_table_virtuelle_d_un_dump_reel_du_format_courant() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ci6-mesure-courant");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "src.db");
        base_de_la_tete(&src, false);
        let archive = chemin(&racine, "source.age");
        backup_compressed(&src, &archive, Some(CLE), None).expect("sauvegarde");
        let charge = charge_de(&archive);
        let vt: Vec<String> = post_ddl_du_dump(&charge).into_iter().filter(|s| s.starts_with("CREATE VIRTUAL TABLE")).collect();
        assert_eq!(
            vt,
            vec!["CREATE VIRTUAL TABLE event_fts USING fts5(\n  message, source, category, content='event', content_rowid='id'\n)".to_string()],
        );
        let dest = chemin(&racine, "plume.db");
        restore_compressed(&archive, &dest, Some(CLE), false, None).expect("la sauvegarde réelle se restaure");
        let c = open_db_keyed(&dest, Some(CLE)).unwrap();
        assert_eq!(lignes_de(&c, "SELECT rowid FROM event_fts WHERE event_fts MATCH 'alice'").len(), 8, "event_fts répond");
    }

    /// LES TABLES VIRTUELLES QUE L'ÉCRIVAIN ÉMET AU FORMAT ANCIEN, relevées sur une vraie sauvegarde du schéma complet de
    /// la tête avec le filtre de champs : `event_fields_fts` et `event_fts`, à ce texte exact ; la sauvegarde se restaure.
    #[test]
    fn mesure_les_tables_virtuelles_d_un_export_reel_du_format_ancien() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ci6-mesure-ancien");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "src.db");
        base_de_la_tete(&src, true);
        let archive = chemin(&racine, "source.age");
        backup_compressed(&src, &archive, Some(CLE), None).expect("sauvegarde");
        let charge = charge_de(&archive);
        assert!(charge.starts_with(b"SQLite format 3\0"), "contrôle : la fixture emprunte le format ancien");
        let releve = chemin(&racine, "releve.db");
        std::fs::write(&releve, &charge).unwrap();
        let vt = {
            let c = open_db_keyed(&releve, None).unwrap();
            lignes_de(&c, "SELECT sql FROM sqlite_master WHERE sql LIKE 'CREATE VIRTUAL TABLE%'")
        };
        std::fs::remove_file(&releve).unwrap();
        assert_eq!(
            vt,
            vec![
                format!("Text(\"CREATE VIRTUAL TABLE event_fields_fts USING fts5(v, content='', {}, prefix='2 3')\")", DECOUPEUR_DU_DEMON.replace('"', "\\\"")),
                "Text(\"CREATE VIRTUAL TABLE event_fts USING fts5(\\n  message, source, category, content='event', content_rowid='id'\\n)\")".to_string(),
            ],
        );
        let dest = chemin(&racine, "plume.db");
        restore_compressed(&archive, &dest, Some(CLE), false, None).expect("la sauvegarde réelle se restaure");
        let c = open_db_keyed(&dest, Some(CLE)).unwrap();
        assert_eq!(lignes_de(&c, "SELECT rowid FROM event_fts WHERE event_fts MATCH 'alice'").len(), 8, "event_fts répond");
        assert_eq!(lignes_de(&c, "SELECT rowid FROM event_fields_fts WHERE event_fields_fts MATCH 'bob3'").len(), 1, "event_fields_fts répond");
    }
}
