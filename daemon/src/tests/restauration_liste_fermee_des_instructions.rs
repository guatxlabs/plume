// =====================================================================================
// LA RESTAURATION N'ACCEPTE QUE LES FORMES D'INSTRUCTION QUE L'ÉCRIVAIN DU DUMP ÉMET
// (`backup/restauration_liste_fermee.rs`, `backup/dump_restauration.rs::restore_stream`).
//
// LE DÉFAUT, LU SUR af7be360 : `restore_stream` passait au moteur, par `execute_batch`, trois familles de chaînes lues
// dans l'archive (création de tables ; texte d'insertion par table ; index, déclencheurs, vues et tables virtuelles)
// sans vérifier qu'elles avaient la forme que l'écrivain émet, et `execute_batch` jouait TOUTES les instructions d'une
// chaîne.
//
// DÉSORMAIS : autoriseur à refus par défaut, réglé par phase ; une instruction et une tête par chaîne (le moteur dit où
// finit la première) ; insertion dans la seule table annoncée, créée par la section 1, toutes les valeurs de la ligne
// liées par des paramètres anonymes ; table virtuelle des seuls modules FTS3/FTS4/FTS5 ; reconstruction FTS d'une
// table virtuelle créée par cette restauration seulement. Un refus fait échouer la restauration entière, dit la phase
// et la cause dans un vocabulaire fermé, ne recopie ni le texte du dump ni celui du moteur, et laisse la destination
// intacte à l'octet (ou absente si elle l'était).
//
// LES DUMPS DE REFUS sont forgés dans le test (même format que l'écrivain) ; les dumps ADMIS sont de vraies sauvegardes
// (`backup_compressed`) : schéma complet de la tête plus une vue (la tête n'en a pas), les index de champ chaud que la
// production crée en tâche de fond (`json_extract`, expression et clause `WHERE`), un compteur AUTOINCREMENT, et les
// trois modules FTS.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une valeur écrite en dur dans le texte d'insertion à côté des paramètres
// (`VALUES (?, 5)` avec une colonne de plus) ou une opération sur des paramètres (`?+?`) n'est vue ni par l'autoriseur
// ni par le compte des paramètres ; elle n'apporte rien que les valeurs liées, choisies par la même archive, n'apportent
// déjà. La comparer au texte exact de l'écrivain refuserait les dumps forgés des témoins existants
// (`INSERT INTO t (v) VALUES (?)`, restauration_et_sauvegarde_ecrites_a_cote.rs).
// =====================================================================================

mod restauration_liste_fermee_des_instructions {
    use super::*;
    use crate::backup::SUFFIXE_RESTAURATION_EN_COURS;

    const CLE: &str = "cc6b-cle-de-test-de-restauration";

    // Les phrases attendues, écrites ici en toutes lettres (jamais relues de la production).
    const CLASSE: &str = "classe d'instruction hors de la liste de la phase";
    const PLUSIEURS: &str = "plus d'une instruction dans la chaîne";
    const HORS_FORME: &str = "insertion qui ne lie pas exactement les valeurs de la ligne";
    const NON_CREEE: &str = "table non créée par cette restauration";

    fn chemin(racine: &std::path::Path, nom: &str) -> String {
        racine.join(nom).to_string_lossy().into_owned()
    }

    fn existe(p: &str) -> bool {
        std::path::Path::new(p).exists()
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

    fn ecrire_u32(v: &mut Vec<u8>, n: u32) {
        v.extend_from_slice(&n.to_le_bytes());
    }
    fn ecrire_str(v: &mut Vec<u8>, s: &str) {
        ecrire_u32(v, s.len() as u32);
        v.extend_from_slice(s.as_bytes());
    }

    struct Donnees {
        nom: String,
        ncols: u16,
        insertion: String,
        lignes: Vec<Vec<&'static str>>,
    }

    enum Post {
        Sql(&'static str),
        Reconstruire(&'static str),
    }

    /// Un dump B1 forgé, section par section (format de `dump_stream`). Les valeurs sont des TEXT.
    struct Dump {
        tables: Vec<&'static str>,
        donnees: Vec<Donnees>,
        compteurs: Vec<(&'static str, i64)>,
        post: Vec<Post>,
    }

    impl Dump {
        /// Le dump que tout témoin modifie : une table `t(v)` et sa ligne 'restauree', aucun compteur, aucun post-DDL.
        fn conforme() -> Dump {
            Dump {
                tables: vec!["CREATE TABLE t(v TEXT)"],
                donnees: vec![Donnees { nom: "t".into(), ncols: 1, insertion: "INSERT INTO t (v) VALUES (?)".into(), lignes: vec![vec!["restauree"]] }],
                compteurs: vec![],
                post: vec![],
            }
        }

        /// Le même dump, dont le texte d'insertion de `t` est `insertion`.
        fn avec_insertion(insertion: &str) -> Dump {
            let mut d = Dump::conforme();
            d.donnees[0].insertion = insertion.into();
            d
        }

        fn octets(&self) -> Vec<u8> {
            let mut v = b"PLUMEDUMP1\n".to_vec();
            ecrire_u32(&mut v, self.tables.len() as u32);
            for sql in &self.tables {
                ecrire_str(&mut v, sql);
            }
            ecrire_u32(&mut v, self.donnees.len() as u32);
            for d in &self.donnees {
                ecrire_str(&mut v, &d.nom);
                v.extend_from_slice(&d.ncols.to_le_bytes());
                ecrire_str(&mut v, &d.insertion);
                for ligne in &d.lignes {
                    v.push(1);
                    for valeur in ligne {
                        v.push(3);
                        ecrire_str(&mut v, valeur);
                    }
                }
                v.push(0);
            }
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

    /// Destination saine : une base SQLCipher portant 'ancienne' dans `t(v)`, et deux compagnons `-wal`/`-shm`.
    struct Instantane {
        base: Vec<u8>,
        wal: Vec<u8>,
        shm: Vec<u8>,
    }

    fn destination_saine(dest: &str) -> Instantane {
        {
            let c = open_db_keyed(dest, Some(CLE)).unwrap();
            c.execute_batch("CREATE TABLE t(v TEXT); INSERT INTO t VALUES('ancienne');").unwrap();
        }
        std::fs::write(format!("{dest}-wal"), b"compagnon -wal de l'ancienne base").unwrap();
        std::fs::write(format!("{dest}-shm"), b"compagnon -shm de l'ancienne base").unwrap();
        Instantane {
            base: std::fs::read(dest).unwrap(),
            wal: std::fs::read(format!("{dest}-wal")).unwrap(),
            shm: std::fs::read(format!("{dest}-shm")).unwrap(),
        }
    }

    fn suffixe_intacte(dest: &str) -> String {
        format!(" — la destination {dest} est INTACTE : la restauration s'écrivait dans {dest}{SUFFIXE_RESTAURATION_EN_COURS}, qui a été retiré.")
    }

    /// Le refus attendu, en entier : phase, cause, puis la phrase de destination intacte.
    fn refus_attendu(phase: &str, cause: &str, dest: &str) -> String {
        format!("restore : phase {phase} : instruction hors liste ({cause}){}", suffixe_intacte(dest))
    }

    /// LE TÉMOIN DE REFUS. Le dump est restauré sur une destination saine : la restauration échoue avec exactement le
    /// refus nommé (donc sans le texte du dump ni celui du moteur), la destination et ses compagnons sont identiques à
    /// l'octet, et aucun temporaire ne reste.
    fn refusee(cas: &str, dump: &Dump, phase: &str, cause: &str) {
        echoue_destination_intacte(cas, dump, |dest| refus_attendu(phase, cause, dest));
    }

    /// Le dump est restauré sur une destination saine : la restauration échoue avec EXACTEMENT `attendue(dest)`, la
    /// destination et ses compagnons sont identiques à l'octet, et aucun temporaire ne reste.
    fn echoue_destination_intacte(cas: &str, dump: &Dump, attendue: impl FnOnce(&str) -> String) {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf(cas);
        let racine = _tmp.racine().chemin().to_path_buf();
        let archive = chemin(&racine, "archive.age");
        archive_de(&dump.octets(), &archive);
        let dest = chemin(&racine, "plume.db");
        let avant = destination_saine(&dest);
        let err = restore_compressed(&archive, &dest, Some(CLE), true, None).expect_err(cas);
        assert_eq!(err, attendue(&dest), "{cas}");
        assert!(std::fs::read(&dest).unwrap() == avant.base, "{cas} : la base de destination a changé");
        assert!(std::fs::read(format!("{dest}-wal")).unwrap() == avant.wal, "{cas} : le compagnon -wal a changé");
        assert!(std::fs::read(format!("{dest}-shm")).unwrap() == avant.shm, "{cas} : le compagnon -shm a changé");
        let en_cours = format!("{dest}{SUFFIXE_RESTAURATION_EN_COURS}");
        for sfx in ["", "-journal", "-wal", "-shm"] {
            assert!(!existe(&format!("{en_cours}{sfx}")), "{cas} : le temporaire {en_cours}{sfx} est resté");
        }
        let c = open_db_keyed(&dest, Some(CLE)).unwrap();
        let v: String = c.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "ancienne", "{cas} : la destination ne se relit plus telle qu'elle était");
    }

    /// Le dump est restauré vers une destination ABSENTE : refus nommé, la destination n'est pas publiée, aucun
    /// temporaire ne reste.
    fn refusee_sans_destination(cas: &str, dump: &Dump, phase: &str, cause: &str) {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf(cas);
        let racine = _tmp.racine().chemin().to_path_buf();
        let archive = chemin(&racine, "archive.age");
        archive_de(&dump.octets(), &archive);
        let dest = chemin(&racine, "plume.db");
        let err = restore_compressed(&archive, &dest, Some(CLE), false, None).expect_err(cas);
        assert_eq!(err, refus_attendu(phase, cause, &dest), "{cas}");
        let mut restant: Vec<String> = std::fs::read_dir(&racine).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        restant.sort();
        assert_eq!(restant, vec!["archive.age".to_string()], "{cas} : ni destination publiée ni temporaire");
    }

    /// Le dump est admis : la restauration aboutit et `t` porte les valeurs attendues.
    fn admise(cas: &str, dump: &Dump, attendues: &[&str]) {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf(cas);
        let racine = _tmp.racine().chemin().to_path_buf();
        let archive = chemin(&racine, "archive.age");
        archive_de(&dump.octets(), &archive);
        let dest = chemin(&racine, "plume.db");
        restore_compressed(&archive, &dest, Some(CLE), false, None).unwrap_or_else(|e| panic!("{cas} : {e}"));
        let c = open_db_keyed(&dest, Some(CLE)).unwrap();
        let mut s = c.prepare("SELECT v FROM t ORDER BY rowid").unwrap();
        let lues: Vec<String> = s.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(lues, attendues, "{cas}");
    }

    // ── CONTRÔLES POSITIFS DES DUMPS FORGÉS ─────────────────────────────────────────────────────────

    /// Le dump forgé de base est admis (sans quoi chaque refus ci-dessous pourrait venir d'ailleurs), et un point-virgule
    /// final suivi d'un commentaire n'est pas une seconde instruction.
    #[test]
    fn une_chaine_conforme_est_admise_meme_suivie_d_un_point_virgule_et_d_un_commentaire() {
        admise("cc6b-conforme", &Dump::conforme(), &["restauree"]);
        let mut d = Dump::conforme();
        d.tables[0] = "CREATE TABLE t(v TEXT); -- fin de la chaîne";
        d.donnees[0].insertion = "INSERT INTO t (v) VALUES (?);  ".into();
        admise("cc6b-conforme-queue-vide", &d, &["restauree"]);
    }

    // ── PHASE TABLES ────────────────────────────────────────────────────────────────────────────────

    fn tables_plus(sql: &'static str) -> Dump {
        let mut d = Dump::conforme();
        d.tables.push(sql);
        d
    }

    #[test]
    fn tables_une_lecture_est_hors_liste() {
        refusee("cc6b-t-lecture", &tables_plus("SELECT v FROM t"), "tables", CLASSE);
    }

    #[test]
    fn tables_une_suppression_de_table_est_hors_liste() {
        refusee("cc6b-t-drop", &tables_plus("DROP TABLE t"), "tables", CLASSE);
    }

    #[test]
    fn tables_un_reglage_est_hors_liste() {
        refusee("cc6b-t-pragma", &tables_plus("PRAGMA user_version = 7"), "tables", CLASSE);
    }

    /// Une création de table qui LIT (une tête admise, plus une lecture) : la lecture refuse la chaîne.
    #[test]
    fn tables_une_creation_qui_lit_est_hors_liste() {
        refusee("cc6b-t-as-select", &tables_plus("CREATE TABLE x AS SELECT 1 AS v"), "tables", CLASSE);
    }

    /// Une autre base que la principale : la base temporaire.
    #[test]
    fn tables_une_table_temporaire_est_hors_liste() {
        refusee("cc6b-t-temp", &tables_plus("CREATE TEMP TABLE x(v)"), "tables", CLASSE);
    }

    /// Une écriture du schéma SANS création : l'écriture de `sqlite_master` n'est admise qu'avec une création ; sans tête,
    /// la chaîne est hors liste (et le refus ne passe pas le texte du moteur, qui l'aurait refusée de lui-même).
    #[test]
    fn tables_une_ecriture_du_schema_sans_creation_est_hors_liste() {
        refusee("cc6b-t-schema", &tables_plus("INSERT INTO sqlite_master VALUES('table','x','x',0,'CREATE TABLE x(v)')"), "tables", CLASSE);
    }

    #[test]
    fn tables_une_chaine_sans_instruction_est_hors_liste() {
        refusee("cc6b-t-vide", &tables_plus("  -- rien"), "tables", CLASSE);
    }

    /// UNE CHAÎNE QUE LA LISTE ADMET MAIS QUE LE MOTEUR REFUSE rend le refus du moteur : la phase, « refusée par le
    /// moteur » et le code d'erreur SQLite, et non le refus nommé (la liste ne juge que la forme, pas la validité) ni le
    /// texte du moteur, qui citait la chaîne lue (« table t already exists in CREATE TABLE t(v TEXT) at offset 13 »).
    /// Ici une création de table admise (une tête, aucune action hors liste) d'une table que la section 1 a déjà créée,
    /// refusée à la préparation. INVERSÉ (vague CD) : ce témoin s'appelait
    /// `tables_une_chaine_admise_que_le_moteur_refuse_garde_le_message_d_avant` et affirmait le message d'avant.
    #[test]
    fn tables_une_chaine_admise_que_le_moteur_refuse_rend_son_code_sans_son_texte() {
        let d = tables_plus("CREATE TABLE t(v TEXT)");
        echoue_destination_intacte("cc6b-t-moteur", &d, |dest| {
            format!("restore : phase tables : refusée par le moteur (code 1){}", suffixe_intacte(dest))
        });
    }

    #[test]
    fn tables_deux_instructions_dans_une_chaine_sont_refusees() {
        let mut d = Dump::conforme();
        d.tables[0] = "CREATE TABLE t(v TEXT); CREATE TABLE u(v TEXT)";
        refusee("cc6b-t-deux", &d, "tables", PLUSIEURS);
        refusee_sans_destination("cc6b-t-deux-sans-dest", &d, "tables", PLUSIEURS);
    }

    // ── PHASE INSERTION ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn insertion_une_lecture_est_hors_liste() {
        refusee("cc6b-i-lecture", &Dump::avec_insertion("SELECT v FROM t"), "insertion", CLASSE);
    }

    #[test]
    fn insertion_une_suppression_est_hors_liste() {
        refusee("cc6b-i-delete", &Dump::avec_insertion("DELETE FROM t"), "insertion", CLASSE);
    }

    #[test]
    fn insertion_un_reglage_est_hors_liste() {
        refusee("cc6b-i-pragma", &Dump::avec_insertion("PRAGMA user_version = 7"), "insertion", CLASSE);
    }

    /// La section annonce `t`, le texte insère dans `u` (créée elle aussi par la section 1).
    #[test]
    fn insertion_dans_une_autre_table_que_celle_annoncee_est_refusee() {
        let mut d = Dump::avec_insertion("INSERT INTO u (v) VALUES (?)");
        d.tables.push("CREATE TABLE u(v TEXT)");
        refusee("cc6b-i-autre-table", &d, "insertion", CLASSE);
    }

    /// Une insertion dont la valeur vient d'une lecture (une tête admise, plus une lecture).
    #[test]
    fn insertion_d_une_valeur_lue_est_hors_liste() {
        refusee("cc6b-i-select", &Dump::avec_insertion("INSERT INTO t (v) SELECT ?"), "insertion", CLASSE);
    }

    #[test]
    fn insertion_qui_appelle_une_fonction_est_hors_liste() {
        refusee("cc6b-i-fonction", &Dump::avec_insertion("INSERT INTO t (v) VALUES (upper(?))"), "insertion", CLASSE);
    }

    /// Une valeur écrite dans le texte au lieu d'être liée : aucun paramètre pour la valeur lue de la ligne.
    #[test]
    fn insertion_d_une_valeur_ecrite_dans_le_texte_est_refusee() {
        refusee("cc6b-i-litterale", &Dump::avec_insertion("INSERT INTO t (v) VALUES ('ecrite')"), "insertion", HORS_FORME);
    }

    /// Un paramètre numéroté (`?1`) : l'écrivain n'émet que des paramètres anonymes.
    #[test]
    fn insertion_par_parametre_numerote_est_refusee() {
        refusee("cc6b-i-numerote", &Dump::avec_insertion("INSERT INTO t (v) VALUES (?1)"), "insertion", HORS_FORME);
    }

    /// PLUS DE PARAMÈTRES QUE DE VALEURS PAR LIGNE : la section annonce une valeur par ligne, le texte en lie deux. Refus
    /// nommé avant toute ligne, et non l'erreur du moteur au premier `execute`.
    #[test]
    fn insertion_qui_porte_plus_de_parametres_que_de_valeurs_est_refusee() {
        let mut d = Dump::avec_insertion("INSERT INTO t (v, w) VALUES (?, ?)");
        d.tables[0] = "CREATE TABLE t(v TEXT, w TEXT)";
        refusee("cc6b-i-trop-de-parametres", &d, "insertion", HORS_FORME);
    }

    /// Le même texte sur une table SANS ligne : aucun `execute` ne le jugerait, le compte des paramètres seul le refuse.
    #[test]
    fn insertion_qui_porte_plus_de_parametres_que_de_valeurs_est_refusee_meme_sans_ligne() {
        let mut d = Dump::avec_insertion("INSERT INTO t (v, w) VALUES (?, ?)");
        d.tables[0] = "CREATE TABLE t(v TEXT, w TEXT)";
        d.donnees[0].lignes.clear();
        refusee("cc6b-i-trop-de-parametres-sans-ligne", &d, "insertion", HORS_FORME);
        refusee_sans_destination("cc6b-i-trop-de-parametres-sans-ligne-sans-dest", &d, "insertion", HORS_FORME);
    }

    /// La section annonce `sqlite_sequence`, que la section 1 ne crée pas (le moteur la crée pour la table
    /// AUTOINCREMENT) : un compteur ne s'écrit que par la section 3.
    #[test]
    fn insertion_dans_une_table_que_la_section_1_n_a_pas_creee_est_refusee() {
        let d = Dump {
            tables: vec!["CREATE TABLE t(v TEXT)", "CREATE TABLE s(id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)"],
            donnees: vec![Donnees {
                nom: "sqlite_sequence".into(),
                ncols: 2,
                insertion: "INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)".into(),
                lignes: vec![vec!["s", "999"]],
            }],
            compteurs: vec![],
            post: vec![],
        };
        refusee("cc6b-i-non-creee", &d, "insertion", NON_CREEE);
    }

    #[test]
    fn insertion_deux_instructions_sont_refusees() {
        refusee("cc6b-i-deux", &Dump::avec_insertion("INSERT INTO t (v) VALUES (?); DELETE FROM t"), "insertion", PLUSIEURS);
    }

    // ── PHASE POST-DDL ──────────────────────────────────────────────────────────────────────────────

    fn post(etapes: Vec<Post>) -> Dump {
        let mut d = Dump::conforme();
        d.post = etapes;
        d
    }

    #[test]
    fn post_ddl_une_lecture_est_hors_liste() {
        refusee("cc6b-p-lecture", &post(vec![Post::Sql("SELECT v FROM t")]), "post-DDL", CLASSE);
    }

    #[test]
    fn post_ddl_une_suppression_de_table_est_hors_liste() {
        refusee("cc6b-p-drop", &post(vec![Post::Sql("DROP TABLE t")]), "post-DDL", CLASSE);
    }

    #[test]
    fn post_ddl_un_reglage_est_hors_liste() {
        refusee("cc6b-p-pragma", &post(vec![Post::Sql("PRAGMA foreign_keys = ON")]), "post-DDL", CLASSE);
    }

    #[test]
    fn post_ddl_une_table_ordinaire_est_hors_liste() {
        refusee("cc6b-p-table", &post(vec![Post::Sql("CREATE TABLE x(v)")]), "post-DDL", CLASSE);
    }

    /// Un index qui appelle une fonction (une tête admise, plus un appel de fonction) : l'ensemble des fonctions admises
    /// est vide.
    #[test]
    fn post_ddl_un_index_qui_appelle_une_fonction_est_hors_liste() {
        refusee("cc6b-p-index-fonction", &post(vec![Post::Sql("CREATE INDEX i ON t(upper(v))")]), "post-DDL", CLASSE);
    }

    /// `coalesce` n'est admise que comme fonction d'un module FTS3/FTS4, une fois une table virtuelle créée : dans un
    /// index d'un dump sans table virtuelle, elle est hors liste.
    #[test]
    fn post_ddl_une_fonction_des_modules_avant_toute_table_virtuelle_est_hors_liste() {
        refusee("cc6b-p-coalesce", &post(vec![Post::Sql("CREATE INDEX i ON t(coalesce(v, ''))")]), "post-DDL", CLASSE);
    }

    /// UNE TABLE VIRTUELLE CRÉÉE N'OUVRE PAS LA LISTE DES FONCTIONS À L'ARCHIVE. L'écrivain émet les tables virtuelles
    /// AVANT les index : c'est l'état où un vrai dump de la tête crée ses index. Une fonction hors de celles des index du
    /// démon y reste hors liste.
    #[test]
    fn post_ddl_un_index_qui_appelle_une_fonction_apres_une_table_virtuelle_est_hors_liste() {
        let d = post(vec![
            Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content='t')"),
            Post::Sql("CREATE INDEX i ON t(upper(v))"),
        ]);
        refusee("cc6b-p-fts5-index-fonction", &d, "post-DDL", CLASSE);
    }

    /// `coalesce` est appelée par un module FTS4 quand il prépare SES instructions, à l'exécution ; une chaîne de l'archive
    /// qui l'appelle, même une fois la table FTS4 créée, reste hors liste.
    #[test]
    fn post_ddl_une_fonction_des_modules_dans_un_index_apres_une_table_virtuelle_est_hors_liste() {
        let d = post(vec![
            Post::Sql("CREATE VIRTUAL TABLE f USING fts4(v, content='t')"),
            Post::Sql("CREATE INDEX i ON t(coalesce(v, ''))"),
        ]);
        refusee("cc6b-p-fts4-coalesce", &d, "post-DDL", CLASSE);
    }

    /// `json_extract` n'est admise que dans un index de la section 4 : dans le texte d'insertion, elle est hors liste.
    #[test]
    fn insertion_qui_appelle_la_fonction_des_index_est_hors_liste() {
        refusee("cc6b-i-json", &Dump::avec_insertion("INSERT INTO t (v) VALUES (json_extract(?, '$.a'))"), "insertion", CLASSE);
    }

    /// La forme des index de champ chaud (`json_extract` dans l'expression, et dans la clause `WHERE` d'un index partiel)
    /// est admise, après une table virtuelle comme sans elle.
    #[test]
    fn post_ddl_les_index_qui_appellent_json_extract_sont_admis() {
        let json = "{\"a\":\"restauree\"}";
        let mut d = post(vec![
            Post::Sql("CREATE INDEX i ON t(json_extract(v, '$.a'))"),
            Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content='t')"),
            Post::Sql("CREATE INDEX j ON t(json_extract(v, '$.a')) WHERE json_extract(v, '$.a') IS NOT NULL"),
        ]);
        d.donnees[0].lignes = vec![vec![json]];
        admise("cc6b-p-json", &d, &[json]);
    }

    /// `fts5vocab` existe dans le moteur, mais l'écrivain n'émet que FTS3, FTS4 et FTS5.
    #[test]
    fn post_ddl_une_table_virtuelle_d_un_module_que_l_ecrivain_n_emet_pas_est_refusee() {
        refusee("cc6b-p-module", &post(vec![Post::Sql("CREATE VIRTUAL TABLE w USING fts5vocab(t, row)")]), "post-DDL", CLASSE);
    }

    #[test]
    fn post_ddl_deux_instructions_sont_refusees() {
        refusee("cc6b-p-deux", &post(vec![Post::Sql("CREATE INDEX i ON t(v); DROP TABLE t")]), "post-DDL", PLUSIEURS);
        refusee_sans_destination("cc6b-p-deux-sans-dest", &post(vec![Post::Sql("CREATE INDEX i ON t(v); DROP TABLE t")]), "post-DDL", PLUSIEURS);
    }

    /// Un déclencheur posé sur une table fantôme joue quand le module y écrit pendant la reconstruction : une action
    /// portée par un déclencheur n'est pas dans la liste (aucun déclencheur ne joue pendant une restauration conforme).
    #[test]
    fn un_declencheur_ne_joue_jamais_pendant_la_restauration() {
        let d = post(vec![
            Post::Sql("CREATE VIRTUAL TABLE f USING fts5(v, content='t')"),
            Post::Sql("CREATE TRIGGER g AFTER INSERT ON f_data BEGIN SELECT 1; END"),
            Post::Reconstruire("f"),
        ]);
        refusee("cc6b-p-declencheur", &d, "reconstruction FTS", CLASSE);
    }

    /// LE `COMMIT` FINAL REFUSÉ, CHEMIN QUI RESTE ATTEIGNABLE : un module FTS4 vide au `COMMIT` les termes de sa
    /// reconstruction dans `f_segdir`, où un déclencheur l'attend ; l'action du déclencheur est hors liste, le `COMMIT`
    /// échoue avec le refus nommé de la phase de validation, et la destination reste intacte.
    #[test]
    fn le_commit_refuse_par_la_liste_laisse_la_destination_intacte() {
        let d = post(vec![
            Post::Sql("CREATE VIRTUAL TABLE f USING fts4(v, content='t')"),
            Post::Sql("CREATE TRIGGER g AFTER INSERT ON f_segdir BEGIN SELECT 1; END"),
            Post::Reconstruire("f"),
        ]);
        refusee("cc6b-v-commit", &d, "validation", CLASSE);
    }

    // ── PHASE RECONSTRUCTION FTS ────────────────────────────────────────────────────────────────────

    /// `t` existe (section 1) mais n'est pas une table virtuelle créée par la section 4.
    #[test]
    fn reconstruction_d_une_table_que_la_restauration_n_a_pas_creee_est_refusee() {
        refusee("cc6b-r-non-creee", &post(vec![Post::Reconstruire("t")]), "reconstruction FTS", NON_CREEE);
    }

    /// Une FTS créée par la section 4 dont le contenu serait une table que la section 1 n'a pas créée : la lecture du
    /// module pendant la reconstruction est hors liste.
    #[test]
    fn reconstruction_qui_lit_une_table_hors_de_la_restauration_est_hors_liste() {
        let d = post(vec![
            Post::Sql("CREATE VIRTUAL TABLE f USING fts5(name, content='sqlite_master')"),
            Post::Reconstruire("f"),
        ]);
        refusee("cc6b-r-contenu-etranger", &d, "reconstruction FTS", CLASSE);
    }

    /// LES FONCTIONS QU'UN MODULE APPELLE SONT CELLES DE LA LISTE, MÊME QUAND L'ARCHIVE CHOISIT SES OPTIONS. L'écrivain
    /// n'émet que des tables FTS à contenu externe ; une FTS4 créée par l'archive avec `compress=`/`uncompress=` fait
    /// appeler au module, pendant la reconstruction, la fonction que l'archive a nommée (`hex`), hors de celles que les
    /// modules appellent d'eux-mêmes (`max`, `coalesce`). L'option n'est pas jugée par lecture du texte : c'est
    /// l'autoriseur qui refuse l'appel.
    #[test]
    fn reconstruction_d_une_fts4_qui_fait_appeler_une_fonction_hors_liste_au_module_est_refusee() {
        let d = post(vec![
            Post::Sql("CREATE VIRTUAL TABLE f USING fts4(v, compress=hex, uncompress=hex)"),
            Post::Reconstruire("f"),
        ]);
        refusee_sans_destination("cc6b-r-fonction-du-module-sans-dest", &d, "reconstruction FTS", CLASSE);
        refusee("cc6b-r-fonction-du-module", &d, "reconstruction FTS", CLASSE);
    }

    // ── DUMPS RÉELS ─────────────────────────────────────────────────────────────────────────────────

    /// Les trois modules que l'écrivain émet (`fts_external_content`), chacun à contenu externe, l'un écrit en capitales :
    /// une vraie sauvegarde B1 se restaure, chaque table virtuelle reconstruite répond, et les tables fantômes de FTS4
    /// reconstruites sont celles de la source à l'octet (le module lit la taille de page pour tailler ses blocs : assez de
    /// termes pour couvrir plusieurs blocs).
    #[test]
    fn les_modules_fts3_fts4_et_fts5_que_l_ecrivain_emet_se_restaurent() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cc6b-modules");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "src.db");
        {
            let c = open_db_keyed(&src, Some(CLE)).unwrap();
            c.execute_batch(
                "CREATE TABLE t(v TEXT); INSERT INTO t VALUES('alpha'); INSERT INTO t VALUES('beta');
                 CREATE VIRTUAL TABLE f3 USING fts3(v, content='t');
                 CREATE VIRTUAL TABLE f4 USING FTS4(v, content='t');
                 CREATE VIRTUAL TABLE f5 USING fts5(v, content='t');
                 WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<400)
                 INSERT INTO t SELECT 'terme' || i || ' mot' || (i * 7919 % 1000) FROM n;
                 INSERT INTO f3(f3) VALUES('rebuild'); INSERT INTO f4(f4) VALUES('rebuild'); INSERT INTO f5(f5) VALUES('rebuild');").unwrap();
        }
        let archive = chemin(&racine, "archive.age");
        backup_compressed(&src, &archive, Some(CLE), None).expect("sauvegarde");
        assert!(backup_payload_head(&archive, CLE).starts_with(b"PLUMEDUMP1\n"), "la fixture doit emprunter le chemin B1");
        let dest = chemin(&racine, "plume.db");
        restore_compressed(&archive, &dest, Some(CLE), false, None).expect("les trois modules se restaurent");
        let src_c = open_db_keyed(&src, Some(CLE)).unwrap();
        let dst_c = open_db_keyed(&dest, Some(CLE)).unwrap();
        let trouves = |c: &rusqlite::Connection, vt: &str| -> i64 {
            c.query_row(&format!("SELECT count(*) FROM {vt} WHERE {vt} MATCH 'beta'"), [], |r| r.get(0)).unwrap()
        };
        for vt in ["f4", "f5"] {
            assert_eq!(trouves(&dst_c, vt), trouves(&src_c, vt), "{vt} reconstruite répond comme la source");
        }
        // FTS4 et FTS5 lisent `t` : la reconstruction retrouve la ligne.
        assert_eq!((trouves(&dst_c, "f4"), trouves(&dst_c, "f5")), (1, 1), "FTS4 et FTS5 reconstruites depuis t");
        // FTS3 ne connaît pas l'option `content` (elle y devient une colonne) : son contenu est interne et vide, une
        // recherche n'y prouverait rien. Ce qui se prouve : sa table et ses tables fantômes, créées par le module pendant
        // la restauration, sont celles de la source.
        let f3 = "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name = 'f3' OR name LIKE 'f3\\_%' ESCAPE '\\'";
        assert!(lignes_de(&src_c, f3).len() >= 4, "contrôle : FTS3 et ses tables fantômes au catalogue de la source");
        assert_eq!(lignes_de(&dst_c, f3), lignes_de(&src_c, f3), "FTS3 et ses tables fantômes recréées comme la source");
        let blocs = "SELECT blockid, hex(block) FROM f4_segments";
        assert!(lignes_de(&src_c, blocs).len() >= 2, "contrôle : les termes de FTS4 couvrent plusieurs blocs");
        assert_eq!(lignes_de(&dst_c, blocs), lignes_de(&src_c, blocs), "blocs de FTS4 identiques à ceux de la source");
        let segments = "SELECT level, idx, start_block, leaves_end_block, end_block, hex(root) FROM f4_segdir";
        assert_eq!(lignes_de(&dst_c, segments), lignes_de(&src_c, segments), "segments de FTS4 identiques à ceux de la source");
    }

    /// LES INDEX DE CHAMP CHAUD QUE LA PRODUCTION CRÉE PAR DÉFAUT (`PLUME_EXPRINDEX=1`) : une base de la tête, passée par
    /// la vraie passe de fond (`maintenance::reconcile_expr_indexes_background`), se sauvegarde et se restaure ; le schéma
    /// relu est le même, et une requête sur un champ chaud rend les mêmes lignes. Sous levier éteint (régime de CI), la
    /// passe ne crée rien : le témoin pose alors la même forme lui-même, pour ne jamais conclure sur une base sans eux.
    #[test]
    fn les_index_de_champ_chaud_de_la_production_se_restaurent() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cc6b-champ-chaud");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "src.db");
        {
            let c = open_db_keyed(&src, Some(CLE)).unwrap();
            c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&c);
            for i in 0..30i64 {
                let fields = if i % 3 == 0 { "{}".to_string() } else { format!("{{\"user\":\"alice{}\",\"action\":\"login\"}}", i % 2) };
                c.execute(
                    "INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,'sshd','auth',3,'hote',?2,?3)",
                    params![1_700_000_000i64 + i, format!("connexion {i}"), fields],
                ).unwrap();
            }
            let db = std::sync::Arc::new(parking_lot::Mutex::new(c));
            let _ = crate::maintenance::reconcile_expr_indexes_background(&db);
            let c = db.lock();
            for champ in crate::soql_glue::HOT_FIELDS {
                c.execute(
                    &format!(
                        "CREATE INDEX IF NOT EXISTS idx_ev_f_{champ} ON event(json_extract(fields,'$.{champ}')) \
                         WHERE json_extract(fields,'$.{champ}') IS NOT NULL"
                    ),
                    [],
                ).unwrap();
            }
        }
        let src_c = open_db_keyed(&src, Some(CLE)).unwrap();
        let index_json = "SELECT name, sql FROM sqlite_master WHERE type='index' AND sql LIKE '%json_extract%WHERE%json_extract%'";
        assert_eq!(lignes_de(&src_c, index_json).len(), crate::soql_glue::HOT_FIELDS.len(), "contrôle : un index partiel par champ chaud");

        let archive = chemin(&racine, "archive.age");
        backup_compressed(&src, &archive, Some(CLE), None).expect("sauvegarde");
        assert!(backup_payload_head(&archive, CLE).starts_with(b"PLUMEDUMP1\n"), "la fixture doit emprunter le chemin B1");
        let dest = chemin(&racine, "plume.db");
        restore_compressed(&archive, &dest, Some(CLE), false, None).expect("les index de champ chaud se restaurent sous la liste");
        let dst_c = open_db_keyed(&dest, Some(CLE)).unwrap();
        let schema = "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_stat%'";
        assert_eq!(lignes_de(&dst_c, schema), lignes_de(&src_c, schema), "le schéma restauré est celui de la source");
        let requete = "SELECT id FROM event WHERE json_extract(fields,'$.user') = 'alice1'";
        assert!(!lignes_de(&src_c, requete).is_empty(), "contrôle : le champ chaud est porté par des événements");
        assert_eq!(lignes_de(&dst_c, requete), lignes_de(&src_c, requete), "une requête sur un champ chaud rend les mêmes lignes");
    }

    /// LES COMPTEURS AUTOINCREMENT, UNE LIGNE PAR TABLE : le moteur pose un compteur pendant la section 2, la section 3 le
    /// remplace par celui de l'archive (supérieur ici au plus grand identifiant restant). Un retrait refusé laisserait les
    /// deux.
    #[test]
    fn les_compteurs_autoincrement_sont_ceux_de_la_source_une_ligne_par_table() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cc6b-compteurs");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "src.db");
        {
            let c = open_db_keyed(&src, Some(CLE)).unwrap();
            c.execute_batch(
                "CREATE TABLE s(id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT);
                 INSERT INTO s(v) VALUES('a'); INSERT INTO s(v) VALUES('b'); INSERT INTO s(v) VALUES('c');
                 DELETE FROM s WHERE id > 1;").unwrap();
        }
        let src_c = open_db_keyed(&src, Some(CLE)).unwrap();
        let compteurs = "SELECT name, seq FROM sqlite_sequence";
        assert_eq!(lignes_de(&src_c, compteurs), vec!["Text(\"s\")|Integer(3)".to_string()], "contrôle : compteur de la source");
        let archive = chemin(&racine, "archive.age");
        backup_compressed(&src, &archive, Some(CLE), None).expect("sauvegarde");
        assert!(backup_payload_head(&archive, CLE).starts_with(b"PLUMEDUMP1\n"), "la fixture doit emprunter le chemin B1");
        let dest = chemin(&racine, "plume.db");
        restore_compressed(&archive, &dest, Some(CLE), false, None).expect("le compteur se restaure");
        let dst_c = open_db_keyed(&dest, Some(CLE)).unwrap();
        assert_eq!(lignes_de(&dst_c, compteurs), lignes_de(&src_c, compteurs), "un compteur par table, celui de la source");
    }

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

    /// ALLER-RETOUR DU SCHÉMA COMPLET DE LA TÊTE (schéma de base puis toutes les migrations : FTS5 à contenu externe,
    /// déclencheurs, index partiels, tables AUTOINCREMENT), plus une vue, que la tête n'a pas et que l'écrivain émet :
    /// la restauration aboutit, le schéma relu est le même, chaque table ordinaire porte les mêmes lignes, les compteurs
    /// AUTOINCREMENT sont les mêmes, et la FTS reconstruite répond. Un refus ici voudrait dire que la liste est fausse.
    #[test]
    fn aller_retour_du_schema_complet_de_la_tete() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cc6b-tete");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "src.db");
        {
            let c = open_db_keyed(&src, Some(CLE)).unwrap();
            c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&c);
            for i in 0..40i64 {
                c.execute(
                    "INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,'sshd','auth',3,?2,?3,'{}')",
                    params![1_700_000_000i64 + i, format!("hote-{}", i % 4), format!("refus du mot de passe pour alice numero {i}")],
                ).unwrap();
            }
            c.execute("INSERT INTO legal_hold(name, reason) VALUES('conservation-a', 'enquete')", []).unwrap();
            c.execute("INSERT INTO legal_hold(name, reason) VALUES('conservation-b', 'enquete')", []).unwrap();
            c.execute("DELETE FROM legal_hold WHERE name='conservation-b'", []).unwrap();
            c.execute_batch("CREATE VIEW vue_des_refus AS SELECT id, host, message FROM event WHERE severity >= 3;").unwrap();
        }
        let src_c = open_db_keyed(&src, Some(CLE)).unwrap();
        let compte = |ty: &str, filtre: &str| -> i64 {
            src_c.query_row(&format!("SELECT count(*) FROM sqlite_master WHERE type='{ty}' {filtre}"), [], |r| r.get(0)).unwrap()
        };
        assert!(compte("table", "AND sql LIKE 'CREATE VIRTUAL TABLE%'") >= 1, "contrôle : la tête porte une table virtuelle FTS");
        assert!(compte("trigger", "") >= 1, "contrôle : la tête porte des déclencheurs");
        assert!(compte("index", "AND sql LIKE '% WHERE %'") >= 1, "contrôle : la tête porte des index partiels");
        assert!(compte("index", "AND sql IS NULL") >= 1, "contrôle : la tête porte des index automatiques de contrainte");
        assert!(compte("view", "") >= 1, "contrôle : la fixture porte une vue");
        assert!(lignes_de(&src_c, "SELECT name, seq FROM sqlite_sequence").len() >= 1, "contrôle : la tête porte des compteurs AUTOINCREMENT");

        let archive = chemin(&racine, "archive.age");
        backup_compressed(&src, &archive, Some(CLE), None).expect("sauvegarde");
        assert!(backup_payload_head(&archive, CLE).starts_with(b"PLUMEDUMP1\n"), "la fixture doit emprunter le chemin B1");
        let dest = chemin(&racine, "plume.db");
        restore_compressed(&archive, &dest, Some(CLE), false, None).expect("le schéma complet de la tête se restaure sous la liste");
        let dst_c = open_db_keyed(&dest, Some(CLE)).unwrap();

        let schema = "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_stat%'";
        assert_eq!(lignes_de(&dst_c, schema), lignes_de(&src_c, schema), "le schéma restauré est celui de la source");
        let ordinaires: Vec<String> = {
            let mut s = src_c.prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND sql NOT LIKE 'CREATE VIRTUAL TABLE%' AND name NOT LIKE 'sqlite_%' \
                 AND name NOT LIKE 'event_fts_%' ORDER BY name").unwrap();
            s.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect()
        };
        assert!(ordinaires.iter().any(|t| t == "event") && ordinaires.iter().any(|t| t == "legal_hold"), "contrôle : tables relues");
        for t in &ordinaires {
            let sql = format!("SELECT * FROM \"{t}\"");
            assert_eq!(lignes_de(&dst_c, &sql), lignes_de(&src_c, &sql), "lignes de {t}");
        }
        let n_events: i64 = src_c.query_row("SELECT count(*) FROM event", [], |r| r.get(0)).unwrap();
        assert!(n_events >= 40, "contrôle : événements semés");
        let compteurs = "SELECT name, seq FROM sqlite_sequence";
        assert_eq!(lignes_de(&dst_c, compteurs), lignes_de(&src_c, compteurs), "compteurs AUTOINCREMENT");
        let fts = "SELECT rowid FROM event_fts WHERE event_fts MATCH 'alice'";
        assert_eq!(lignes_de(&dst_c, fts), lignes_de(&src_c, fts), "la FTS reconstruite répond comme la source");
        assert_eq!(lignes_de(&dst_c, fts).len() as i64, n_events, "chaque événement est retrouvé par la FTS");
        let vue = "SELECT * FROM vue_des_refus";
        assert_eq!(lignes_de(&dst_c, vue), lignes_de(&src_c, vue), "la vue restaurée se lit comme la source");
    }
}
