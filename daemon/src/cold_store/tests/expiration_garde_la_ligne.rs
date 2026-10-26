// `P10.34-j` — L'EXPIRATION FROIDE NE SUPPRIME LA LIGNE `cold_seal` QU'AVEC SON FICHIER.
//
// Le défaut : `expire_cold_days` (`cold_store/aging.rs`) journalisait un `remove_file` refusé (autre que
// `NotFound`) puis supprimait QUAND MÊME la ligne `cold_seal` : le fichier restait après sa rétention, sans plus
// rien pour le retrouver ni le purger. Et `all_sealed_files` (`cold_store/seal.rs`) rendait une lecture ratée de
// l'index sous la forme d'un `Vec` vide, c'est-à-dire « rien à expirer ».
//
// Les témoins passent par le POINT D'ENTRÉE (`cold_age_run`, que la passe de rétention appelle) et jugent le
// journal dans un SOUS-PROCESSUS, ligne ENTIÈRE : l'enfant joue le scénario et vérifie l'état (lignes, fichiers),
// le parent relit sa sortie d'erreur. Le refus d'unlink est provoqué SANS dépendre des droits (un test joué en
// root passerait outre un `chmod`) : l'entrée du fichier scellé est un RÉPERTOIRE de même nom, `unlink` rend
// `EISDIR` même en root.
//
// MUTANTS JOUÉS (sous la variable de mutation, retirés avant le commit), chacun vu ROUGE : AS3_LIGNE_SUPPRIMEE (la ligne part malgré
// le refus), AS3_NOTFOUND_ECHEC (un fichier absent compté comme refus), AS3_COMPTE_DOUBLE, AS3_TOTAL_TU,
// AS3_REFUS_TU (ligne par refus retirée), AS3_ENV_TU, AS3_ENV_GARDEE (env_id non conforme : ligne gardée),
// AS3_LECTURE_AVALEE (lecture ratée rendue « rien à expirer », sans mot), AS3_NATURE_MESSAGE (le message du moteur
// au lieu du code), AS3_ILLISIBLES_TUS, AS3_ILLISIBLE_FATALE (une ligne illisible fait échouer toute la lecture),
// AS3_ILLISIBLE_AVALEE (ligne illisible jetée sans compte), AS3_DELETE_TU (suppression refusée muette),
// AS3_ARRET_EN_ILLISIBLE (une erreur du moteur en cours de lecture comptée comme ligne illisible).
// Puis, pour les témoins (6) à (10), chacun vu ROUGE : VB1 (lecture ratée du plan d'escrow -> panique), VB2 (plan
// lisible rendu vide), ENV_TU (refus d'unlink sans `env_id`), UNION_SANS_BORNE (voie d'union sans horizon),
// VEC_SANS_BORNE (voie vectorisée sans horizon), BORD_MOINS / BORD_PLUS (premier jour servi décalé d'un jour),
// SANS_FENETRE (instant de la requête pris à la frontière, sans la fenêtre chaude), ILLISIBLE_REPLI (réglage
// illisible remplacé par le défaut).

use super::*;

const AS3_ENFANT: &str = "PLUME_TEST_AS3_EXPIRATION_ENFANT";
const AS3_SEPARATEUR: &str = "@@as3-tour-suivant@@";
const AS3_PREFIXE: &str = "[cold] expiration";

/// Relance le binaire de test sur UN test, en enfant, et rend ses lignes de journal d'expiration découpées par
/// tour (le séparateur est écrit par l'enfant sur la même sortie d'erreur, donc dans l'ordre).
fn as3_lancer(mut enfant: std::process::Command, test: &str) -> Vec<Vec<String>> {
    let sortie = enfant.args(["--exact", "--nocapture", "--test-threads=1", test]).output().expect("ré-exécution du binaire de test");
    let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
    assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
    assert!(stdout.contains("1 passed"), "contrôle : l'enfant a bien joué le test visé : {stdout}");
    let mut tours: Vec<Vec<String>> = vec![Vec::new()];
    for l in stderr.lines() {
        if l == AS3_SEPARATEUR {
            tours.push(Vec::new());
        } else if l.starts_with(AS3_PREFIXE) {
            tours.last_mut().expect("au moins un tour").push(l.to_string());
        }
    }
    tours
}

fn as3_seal(db: &Arc<Mutex<Connection>>, env: &str, day: i64, seq: i64) {
    let ts = day * SECS_PER_DAY;
    seal_row(db, env, day, seq, 1, 1, 1, ts, ts, i64::MIN, i64::MIN, 1, 1);
}

fn as3_lignes(db: &Arc<Mutex<Connection>>) -> Vec<(String, i64, i64)> {
    let c = db.lock();
    let mut st = c.prepare("SELECT env_id, day, seq FROM cold_seal WHERE typeof(env_id)='text' ORDER BY env_id, day, seq").unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(|r| r.unwrap()).collect()
}

fn as3_nb_lignes(db: &Arc<Mutex<Connection>>) -> i64 {
    db.lock().query_row("SELECT count(*) FROM cold_seal", [], |r| r.get(0)).unwrap()
}

fn as3_fichier(p: &Path) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, b"jour froid de temoin").unwrap();
}

fn as3_tour(db: &Arc<Mutex<Connection>>, cold: &Path) {
    cold_age_run(db, "", &conf_on(cold, HOT_WIN), n_now(), RET_DAYS);
}

/// (1) UN TOUR MIXTE : sur le MÊME jour, un seq refusé (répertoire) et un seq retiré ; un second env_id retiré ; un
/// fichier déjà absent (`NotFound`) ; un env_id non conforme. Seule la ligne refusée reste, le refus est dit et
/// compté UNE fois. Au tour suivant, l'entrée réparée (fichier ordinaire) part avec sa ligne, sans un mot.
#[test]
fn as3_tour_mixte_garde_seulement_la_ligne_refusee() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // la conf ne décide que si l'env ne porte pas la clé
    let d = M - 40; // au-delà de la rétention (30 j) -> expiré
    let d_absent = M - 41;
    if std::env::var(AS3_ENFANT).as_deref() == Ok("tour_mixte") {
        let root = tmp_root("as3-mixte");
        let cold = root.join("cold");
        let db = mkdb(&root);
        let refuse = file_path(&cold, "prod", d, 0);
        std::fs::create_dir_all(&refuse).unwrap(); // un RÉPERTOIRE à la place du fichier : unlink -> EISDIR
        let retire = file_path(&cold, "prod", d, 1);
        as3_fichier(&retire);
        let autre_env = file_path(&cold, "stage", d, 0);
        as3_fichier(&autre_env);
        assert!(!file_path(&cold, "prod", d_absent, 0).exists(), "contrôle : le fichier du jour absent n'existe pas");
        as3_seal(&db, "prod", d, 0);
        as3_seal(&db, "prod", d, 1);
        as3_seal(&db, "stage", d, 0);
        as3_seal(&db, "prod", d_absent, 0);
        as3_seal(&db, "a/b", d, 0);
        assert_eq!(as3_nb_lignes(&db), 5, "contrôle : cinq lignes semées");

        as3_tour(&db, &cold);
        assert_eq!(as3_lignes(&db), vec![("prod".to_string(), d, 0)], "seule la ligne dont le fichier n'a pas pu partir reste");
        assert!(refuse.is_dir(), "l'entrée refusée est toujours là");
        assert!(!retire.exists(), "le seq voisin du même jour est retiré");
        assert!(!autre_env.exists(), "l'autre env_id est retiré");

        // RÉPARATION : l'entrée redevient un fichier ordinaire ; le tour suivant le retire et la ligne part.
        std::fs::remove_dir(&refuse).unwrap();
        as3_fichier(&refuse);
        eprintln!("{AS3_SEPARATEUR}");
        as3_tour(&db, &cold);
        assert_eq!(as3_nb_lignes(&db), 0, "au tour suivant, la ligne gardée part avec son fichier");
        assert!(!refuse.exists(), "au tour suivant, le fichier est retiré");
        return;
    }
    let tours = as3_lancer(
        {
            let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            enfant.env(AS3_ENFANT, "tour_mixte");
            enfant
        },
        "cold_store::tests::expiration_garde_la_ligne::as3_tour_mixte_garde_seulement_la_ligne_refusee",
    );
    assert_eq!(tours.len(), 2, "contrôle : deux tours joués : {tours:?}");
    let j = ymd_from_day(d);
    let mut attendu = vec![
        format!("[cold] expiration prod seq 0 du jour {j} : fichier non retiré (IsADirectory) — ligne cold_seal gardée, retentée au tour suivant"),
        format!("[cold] expiration seq 0 du jour {j} : env_id non conforme, aucun chemin construit — ligne cold_seal retirée sans unlink"),
        "[cold] expiration : 1 fichier(s) non retiré(s) ce tour — lignes cold_seal gardées, retentées au tour suivant".to_string(),
    ];
    let mut obtenu = tours[0].clone();
    attendu.sort();
    obtenu.sort();
    assert_eq!(obtenu, attendu, "premier tour : le refus, l'env_id non conforme et le compte, rien d'autre");
    assert_eq!(
        tours[0].last().map(String::as_str),
        Some("[cold] expiration : 1 fichier(s) non retiré(s) ce tour — lignes cold_seal gardées, retentées au tour suivant"),
        "le compte du tour vient après les refus"
    );
    assert!(tours[1].is_empty(), "tour suivant : fichier réparé retiré, rien à dire : {:?}", tours[1]);
}

/// (2) LECTURE DE L'INDEX RATÉE : l'expiration du tour est sautée et c'est DIT, avec le code SQLite (jamais le
/// message, qui cite l'énoncé). Le fichier au-delà de la rétention reste : rien n'est dit expiré.
#[test]
fn as3_lecture_ratee_de_l_index_saute_l_expiration_et_le_dit() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let d = M - 40;
    if std::env::var(AS3_ENFANT).as_deref() == Ok("lecture_ratee") {
        let root = tmp_root("as3-lecture");
        let cold = root.join("cold");
        let db = mkdb(&root);
        // Un index au schéma inattendu (sans `seq`) : `CREATE TABLE IF NOT EXISTS` le laisse, la lecture des
        // seals est refusée à la préparation.
        db.lock().execute_batch("CREATE TABLE cold_seal(env_id TEXT NOT NULL, day INTEGER NOT NULL)").unwrap();
        db.lock().execute("INSERT INTO cold_seal(env_id, day) VALUES('prod', ?1)", params![d]).unwrap();
        let p = file_path(&cold, "prod", d, 0);
        as3_fichier(&p);
        as3_tour(&db, &cold);
        assert!(p.exists(), "lecture ratée : aucun fichier retiré");
        assert_eq!(as3_nb_lignes(&db), 1, "lecture ratée : aucune ligne retirée");
        return;
    }
    let tours = as3_lancer(
        {
            let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            enfant.env(AS3_ENFANT, "lecture_ratee");
            enfant
        },
        "cold_store::tests::expiration_garde_la_ligne::as3_lecture_ratee_de_l_index_saute_l_expiration_et_le_dit",
    );
    assert_eq!(
        tours,
        vec![vec![
            "[cold] expiration du tour SAUTÉE : index cold_seal non lu (code SQLite 1 (Unknown)) — aucun fichier retiré, rien n'est dit expiré ; retentée au tour suivant"
                .to_string()
        ]],
        "la lecture ratée est dite, ligne entière, une fois"
    );
}

/// (3) UNE LIGNE ILLISIBLE (env_id en BLOB) : comptée et dite, jamais expirée ; la ligne lisible voisine est
/// expirée normalement (une ligne illisible ne fait pas sauter tout le tour).
#[test]
fn as3_ligne_illisible_comptee_et_la_voisine_expiree() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let d = M - 40;
    if std::env::var(AS3_ENFANT).as_deref() == Ok("ligne_illisible") {
        let root = tmp_root("as3-illisible");
        let cold = root.join("cold");
        let db = mkdb(&root);
        let p = file_path(&cold, "prod", d, 0);
        as3_fichier(&p);
        as3_seal(&db, "prod", d, 0);
        db.lock()
            .execute(
                "INSERT INTO cold_seal(env_id,day,seq,expected_rows,sealed_ts,purged,max_id,ts_min,ts_max,lo_ts,lo_id,hi_id,last_file) \
                 VALUES(X'00',?1,1,1,0,1,1,0,0,0,0,1,1)",
                params![d],
            )
            .unwrap();
        assert_eq!(as3_nb_lignes(&db), 2, "contrôle : deux lignes semées");
        as3_tour(&db, &cold);
        assert!(!p.exists(), "la ligne lisible est expirée : son fichier part");
        assert!(as3_lignes(&db).is_empty(), "la ligne lisible part");
        assert_eq!(as3_nb_lignes(&db), 1, "la ligne illisible reste");
        return;
    }
    let tours = as3_lancer(
        {
            let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            enfant.env(AS3_ENFANT, "ligne_illisible");
            enfant
        },
        "cold_store::tests::expiration_garde_la_ligne::as3_ligne_illisible_comptee_et_la_voisine_expiree",
    );
    assert_eq!(
        tours,
        vec![vec!["[cold] expiration : 1 ligne(s) cold_seal illisible(s) — leurs fichiers ne sont pas expirés ce tour".to_string()]],
        "la ligne illisible est comptée et dite, ligne entière"
    );
}

/// (4) SUPPRESSION DE LA LIGNE REFUSÉE (fichier déjà retiré) : dite avec le code SQLite ; au tour suivant le fichier
/// est absent (`NotFound`) et la ligne part, sans un mot.
#[test]
fn as3_suppression_de_ligne_refusee_dite_puis_retentee() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let d = M - 40;
    if std::env::var(AS3_ENFANT).as_deref() == Ok("suppression_refusee") {
        let root = tmp_root("as3-suppression");
        let cold = root.join("cold");
        let db = mkdb(&root);
        let p = file_path(&cold, "prod", d, 0);
        as3_fichier(&p);
        as3_seal(&db, "prod", d, 0);
        db.lock()
            .execute_batch("CREATE TRIGGER as3_refus BEFORE DELETE ON cold_seal BEGIN SELECT RAISE(ABORT, 'refus de temoin'); END")
            .unwrap();
        as3_tour(&db, &cold);
        assert!(!p.exists(), "le fichier est retiré");
        assert_eq!(as3_lignes(&db), vec![("prod".to_string(), d, 0)], "la ligne dont la suppression est refusée reste");
        db.lock().execute_batch("DROP TRIGGER as3_refus").unwrap();
        eprintln!("{AS3_SEPARATEUR}");
        as3_tour(&db, &cold);
        assert_eq!(as3_nb_lignes(&db), 0, "au tour suivant, fichier absent : la ligne part");
        return;
    }
    let tours = as3_lancer(
        {
            let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            enfant.env(AS3_ENFANT, "suppression_refusee");
            enfant
        },
        "cold_store::tests::expiration_garde_la_ligne::as3_suppression_de_ligne_refusee_dite_puis_retentee",
    );
    let j = ymd_from_day(d);
    assert_eq!(
        tours,
        vec![
            vec![format!(
                "[cold] expiration seq 0 du jour {j} : ligne cold_seal non supprimée (code SQLite 1811 (ConstraintViolation)) — retentée au tour suivant"
            )],
            Vec::<String>::new(),
        ],
        "la suppression refusée est dite au premier tour, rien au second"
    );
}

/// (5) UNE ERREUR DU MOTEUR EN COURS DE LECTURE (interruption au premier pas) est une lecture RATÉE, rendue avec
/// son code — jamais une « ligne illisible » suivie d'une liste partielle prise pour complète. Contrôle : la même
/// lecture sans interruption rend les deux lignes, aucune illisible.
#[test]
fn as3_erreur_du_moteur_en_cours_de_lecture_est_une_lecture_ratee() {
    let root = tmp_root("as3-interrompue");
    let db = mkdb(&root);
    as3_seal(&db, "prod", M - 40, 0);
    as3_seal(&db, "prod", M - 40, 1);
    let c = db.lock();
    let lus = all_sealed_files(&c).expect("contrôle : lecture nominale");
    assert_eq!((lus.seals.len(), lus.illisibles), (2, 0), "contrôle : deux lignes lues, aucune illisible");
    c.progress_handler(1, Some(|| true));
    let rendu = all_sealed_files(&c);
    c.progress_handler(1, None::<fn() -> bool>);
    match rendu {
        Err(nature) => assert_eq!(nature, "code SQLite 9 (OperationInterrupted)", "la nature est le code, jamais le message"),
        Ok(lus) => panic!("lecture interrompue rendue comme un fait : {} lue(s), {} illisible(s)", lus.seals.len(), lus.illisibles),
    }
}

/// (6) LE REFUS NOMME SON INDEX : deux index refusés sur le MÊME (jour, seq) donnent deux lignes distinctes, chacune
/// avec son `env_id` — sans lui, les deux refus seraient indiscernables.
#[test]
fn as3_le_refus_d_unlink_nomme_son_index() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let d = M - 40;
    if std::env::var(AS3_ENFANT).as_deref() == Ok("deux_index") {
        let root = tmp_root("as3-deux-index");
        let cold = root.join("cold");
        let db = mkdb(&root);
        for env in ["prod", "stage"] {
            std::fs::create_dir_all(file_path(&cold, env, d, 0)).unwrap(); // unlink -> EISDIR
            as3_seal(&db, env, d, 0);
        }
        as3_tour(&db, &cold);
        assert_eq!(as3_lignes(&db), vec![("prod".to_string(), d, 0), ("stage".to_string(), d, 0)], "les deux lignes restent");
        return;
    }
    let tours = as3_lancer(
        {
            let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            enfant.env(AS3_ENFANT, "deux_index");
            enfant
        },
        "cold_store::tests::expiration_garde_la_ligne::as3_le_refus_d_unlink_nomme_son_index",
    );
    let j = ymd_from_day(d);
    let mut obtenu = tours[0].clone();
    obtenu.sort();
    assert_eq!(
        obtenu,
        vec![
            "[cold] expiration : 2 fichier(s) non retiré(s) ce tour — lignes cold_seal gardées, retentées au tour suivant".to_string(),
            format!("[cold] expiration prod seq 0 du jour {j} : fichier non retiré (IsADirectory) — ligne cold_seal gardée, retentée au tour suivant"),
            format!("[cold] expiration stage seq 0 du jour {j} : fichier non retiré (IsADirectory) — ligne cold_seal gardée, retentée au tour suivant"),
        ],
        "chaque refus nomme son index, le compte vient en plus"
    );
}

/// (7) LE PLAN D'ESCROW SUR UN INDEX NON LU RESTE VIDE, SANS PANIQUE : base sans table `cold_seal` (tier froid jamais
/// allumé) et table au schéma inattendu (sans `seq`). Contrôle : un index lisible rend son fichier.
#[test]
fn as3_plan_d_escrow_sur_index_non_lu_vide_sans_panique() {
    let keys = std::collections::HashSet::new();
    let root = tmp_root("as3-escrow");
    let cold_dir = root.join("cold");
    let cold = cold_dir.as_path();
    let sans_table = Connection::open_in_memory().unwrap();
    assert!(cold_backup_plan(&sans_table, cold, "t", &keys).is_empty(), "base sans cold_seal : plan vide");
    let sans_seq = Connection::open_in_memory().unwrap();
    sans_seq.execute_batch("CREATE TABLE cold_seal(env_id TEXT NOT NULL, day INTEGER NOT NULL); INSERT INTO cold_seal VALUES('prod', 19000)").unwrap();
    assert!(cold_backup_plan(&sans_seq, cold, "t", &keys).is_empty(), "cold_seal sans seq : plan vide");
    let db = mkdb(&root);
    as3_seal(&db, "prod", M - 40, 0);
    as3_fichier(&file_path(cold, "prod", M - 40, 0)); // le plan n'émet que les fichiers présents
    let plan = cold_backup_plan(&db.lock(), cold, "t", &keys);
    assert_eq!(plan.iter().map(|i| i.key.clone()).collect::<Vec<_>>(), vec![format!("cold/t/prod/{}-0000.parquet", ymd_from_day(M - 40))], "contrôle : index lisible");
}

// ---- (8) à (10) : LE LECTEUR FROID NE SERT AUCUN JOUR QUE L'EXPIRATION DIT EXPIRÉ -------------------------------
//
// L'état visé est celui que laisse un unlink refusé : ligne `cold_seal` ET fichier lisible, au-delà de la rétention.
// Il est construit par le vieillissement RÉEL joué vingt jours plus tôt (`n_tot`), sans expiration à l'instant de la
// requête. Rétention 30 j, instant `M` : dernier jour expiré `M-31`, premier jour servi `M-30` (le bord).

const AS3_J_EXPIRE: i64 = M - 40;
const AS3_J_BORD_EXPIRE: i64 = M - 31;
const AS3_J_BORD_SERVI: i64 = M - 30;
const AS3_J_SERVI: i64 = M - 23;
const AS3_JOURS: [i64; 4] = [AS3_J_EXPIRE, AS3_J_BORD_EXPIRE, AS3_J_BORD_SERVI, AS3_J_SERVI];

fn as3_source(day: i64) -> String {
    format!("j{}", M - day)
}

fn as3_ligne(day: i64, i: i64) -> ColdRow {
    let mut r = rich_row(day * SECS_PER_DAY + 100 + i, i);
    r.row.source = as3_source(day);
    r
}

struct As3Froid {
    _root: crate::tmp_possede::TmpPossede,
    db: Arc<Mutex<Connection>>,
    dbp: String,
    conf: HashMap<String, String>,
    b: i64,
}

fn as3_froid(tag: &str) -> As3Froid {
    let root = tmp_root(tag);
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    for day in AS3_JOURS {
        for i in 0..3 {
            insert_event(&db, &as3_ligne(day, i));
        }
    }
    insert_recent_tail_holder(&db);
    let n_tot = (M - 20) * SECS_PER_DAY;
    cold_age_run(&db, &dbp, &conf, n_tot, RET_DAYS);
    for day in AS3_JOURS {
        assert_eq!(count_hot_day(&db, "prod", day), 0, "contrôle : jour {day} vieilli");
        assert!(file_path(&cold_root(&conf, &dbp), "prod", day, 0).is_file(), "contrôle : fichier du jour {day} présent");
    }
    let b = union_boundary(&db, &conf);
    assert_eq!(b, (M - HOT_WIN) * SECS_PER_DAY, "contrôle : frontière de l'instant M");
    As3Froid { _root: root, db, dbp, conf, b }
}

fn as3_compte_oracle(f: &As3Froid, from: i64) -> Vec<(String, i64)> {
    let to = M * SECS_PER_DAY;
    let sql = compile_ev("search | stats count by source", from, to, FieldMaskSet::new());
    let (v, _t, _m) = union_query_oracle(&f.dbp, &f.conf, None, from, to, f.b, &sql, None, 60_000, None, &[]).expect("union");
    count_by_source(&v)
}

/// (8) VOIE D'UNION (`cold_union_query`, celle de `/api/query`) : les jours expirés à ligne gardée ne sont pas servis,
/// fenêtre bornée comme non bornée (borne basse = `MIN(day)` de l'index) ; le bord (`M-30`) et le jour dans la
/// rétention sont servis à l'octet. Puis l'expiration à l'instant `M` retire EXACTEMENT les jours que le lecteur
/// écartait : un seul horizon.
#[test]
fn as3_le_lecteur_froid_ne_sert_pas_un_jour_expire_a_ligne_gardee() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let f = as3_froid("as3-lecteur");
    let attendu = vec![(as3_source(AS3_J_SERVI), 3), (as3_source(AS3_J_BORD_SERVI), 3), ("recent-tail".to_string(), 1)];
    let mut attendu_trie = attendu.clone();
    attendu_trie.sort();
    assert_eq!(as3_compte_oracle(&f, (M - 45) * SECS_PER_DAY), attendu_trie, "fenêtre bornée : jours expirés non servis");
    assert_eq!(as3_compte_oracle(&f, 0), attendu_trie, "fenêtre non bornée : jours expirés non servis");

    // À L'OCTET : chaque ligne servie des jours dans la rétention est celle qui a été écrite, sur les colonnes que
    // `table` rend depuis le schéma natif (`dedup`, absent du schéma GXQL, revient NULL et n'est pas comparé).
    let to = M * SECS_PER_DAY;
    let sql = compile_ev("search | table ts, source, message, fields, host, url, xff", 0, to, FieldMaskSet::new());
    let (v, _t, _m) = union_query_oracle(&f.dbp, &f.conf, None, 0, to, f.b, &sql, None, 60_000, None, &[]).expect("union");
    let colonnes = ["ts", "source", "message", "fields", "host", "url", "xff"];
    let valeurs: Vec<Vec<Value>> = colonnes.iter().map(|c| col_vals(&v, c)).collect();
    let mut servi: Vec<Vec<Value>> = (0..valeurs[0].len())
        .map(|k| valeurs.iter().map(|col| col[k].clone()).collect::<Vec<Value>>())
        .filter(|l| l[1].as_str() != Some("recent-tail"))
        .collect();
    servi.sort_by_key(|l| l[0].as_i64());
    let ecrit: Vec<Vec<Value>> = [AS3_J_BORD_SERVI, AS3_J_SERVI]
        .iter()
        .flat_map(|d| (0..3).map(move |i| as3_ligne(*d, i)))
        .map(|r| {
            vec![
                json!(r.row.ts), json!(r.row.source), json!(r.row.message), json!(r.row.fields), json!(r.row.host),
                json!(r.row.url), json!(r.xff),
            ]
        })
        .collect();
    assert_eq!(servi, ecrit, "jours dans la rétention : servis à l'octet, rien d'autre");

    // UN SEUL HORIZON : l'expiration à l'instant M retire les deux jours écartés, garde le bord et le jour servi.
    cold_age_run(&f.db, &f.dbp, &f.conf, n_now(), RET_DAYS);
    let jours: Vec<i64> = as3_lignes(&f.db).into_iter().map(|(_, d, _)| d).collect();
    assert_eq!(jours, vec![AS3_J_BORD_SERVI, AS3_J_SERVI], "l'expiration retire exactement les jours que le lecteur écartait");
}

/// (9) VOIE VECTORISÉE (`cold_vectorized_try`, armée par défaut) : même horizon — la requête est bien ROUTÉE (sinon
/// le témoin ne prouverait rien) et ne compte ni le jour expiré ni le bord expiré.
#[test]
fn as3_la_voie_vectorisee_ne_sert_pas_un_jour_expire_a_ligne_gardee() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let f = as3_froid("as3-vectorise");
    let routee = cold_vectorized_try(&f.dbp, &f.conf, None, (M - 45) * SECS_PER_DAY, f.b - 1, f.b, "search | stats count by source", true, 60_000, &[])
        .expect("voie vectorisée")
        .expect("contrôle : la requête est routée vers la voie vectorisée");
    let mut attendu = vec![(as3_source(AS3_J_SERVI), 3), (as3_source(AS3_J_BORD_SERVI), 3)];
    attendu.sort();
    assert_eq!(count_by_source(&routee), attendu, "voie vectorisée : jours expirés non servis, bord servi");
}

/// (10) HORIZON ILLISIBLE (réglage `retention_days` écrit, non entier) : la lecture froide est REFUSÉE sur les deux
/// voies, cause fixe ; jamais servie sur un repli. Contrôle : le même réglage lisible sert.
#[test]
fn as3_horizon_de_retention_illisible_refuse_la_lecture_froide() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let f = as3_froid("as3-horizon-illisible");
    f.db.lock().execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','30')", []).unwrap();
    assert_eq!(as3_compte_oracle(&f, 0).len(), 3, "contrôle : réglage lisible, la lecture sert");
    f.db.lock().execute("UPDATE setting SET value='trente' WHERE key='retention_days'", []).unwrap();
    let to = M * SECS_PER_DAY;
    let sql = compile_ev("search | stats count by source", 0, to, FieldMaskSet::new());
    match union_query_oracle(&f.dbp, &f.conf, None, 0, to, f.b, &sql, None, 60_000, None, &[]) {
        Err(e) => assert_eq!(e, HORIZON_FROID_NON_LU, "voie d'union : cause fixe"),
        Ok((v, _, _)) => panic!("voie d'union : servie sur un horizon illisible : {v}"),
    }
    match cold_vectorized_try(&f.dbp, &f.conf, None, (M - 45) * SECS_PER_DAY, f.b - 1, f.b, "search | stats count by source", true, 60_000, &[]) {
        Err(e) => assert_eq!(e, HORIZON_FROID_NON_LU, "voie vectorisée : cause fixe"),
        Ok(v) => panic!("voie vectorisée : servie sur un horizon illisible : {v:?}"),
    }
}
